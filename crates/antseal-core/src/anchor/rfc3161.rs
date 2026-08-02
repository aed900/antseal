//! The RFC 3161 shell, hand-written (task **A5**).
//!
//! # Why this is antseal's code and not a crate's
//!
//! Measured at D60 against the exact pinned closure: there is no `TstInfo`,
//! no `TimeStampReq`, no `MessageImprint` and no `PKIStatusInfo` anywhere in
//! it. `cms 0.3.0-pre.2` stops at RFC 5652 and `x509-cert 0.3.0` at RFC 5280;
//! neither carries an RFC 3161 type and neither offers path validation. The
//! hand-written boundary therefore sits **here**, where no crate exists — not
//! one layer down at RFC 5652, where one does and where hand-rolling would
//! buy ~250 lines of ASN.1 whose correctness antseal would own forever.
//!
//! # Strictness: what comes free and what does not
//!
//! Everything here decodes through `der`'s `Decode::from_der`, whose
//! `SliceReader` fixes `EncodingRules::Der` regardless of the `ber` feature
//! `cms` switches on for the whole graph. That rejects, measured rather than
//! assumed (D60 §2.1): indefinite lengths, non-minimal long-form lengths,
//! redundant INTEGER leading zeros, BER BOOLEANs, constructed OCTET STRINGs,
//! `unused > 7` BIT STRINGs, top-level trailing data, and every non-DER
//! `GeneralizedTime` spelling — fractional seconds, omitted seconds, a
//! numeric offset, a missing `Z`.
//!
//! Three things it does **not** give, all of which this module handles:
//!
//! 1. **`Option<Any>` is greedy.** `der`'s `Option<T>::decode` peeks the tag
//!    and asks `T::can_decode`, and `Any::can_decode` returns `true` for
//!    *every* tag (`der-0.8.1/src/asn1/any.rs:124`). So an untagged
//!    `Option<Any>` OPTIONAL field swallows whatever follows it. D60 §3.1's
//!    proven `PkiStatusInfo` model has exactly that shape —
//!    `status_string: Option<Any>` ahead of `fail_info: Option<BitString>` —
//!    and it ran clean against all nine live responses only because all nine
//!    are `granted` with neither optional field present. On a *rejection*
//!    response, the shape it exists to parse, the `Any` eats the `failInfo`
//!    BIT STRING and `fail_info` silently becomes `None`. Every OPTIONAL
//!    field below is therefore either strongly typed or tag-directed by hand.
//! 2. **DER's DEFAULT rule is not enforced.** `der_derive`'s `default`
//!    attribute expands to `Option::<T>::decode(reader)?.unwrap_or_else(..)`,
//!    which accepts an explicitly encoded default value. X.690 §11.5 forbids
//!    encoding one. `TSTInfo.ordering DEFAULT FALSE` is checked here and
//!    `ESSCertIDv2.hashAlgorithm DEFAULT id-sha256` in [`super::ess`].
//! 3. **Trailing content inside a nested construction is not rejected.**
//!    `Reader::finish` — the only caller of `ErrorKind::TrailingData` on the
//!    happy path — runs at the top level of `from_der` only;
//!    `read_nested`/`resume_nested` restore the outer position without
//!    checking that the inner reader was drained
//!    (`der-0.8.1/src/reader/position.rs:93-97`). Every hand-written
//!    `decode_value` here ends by asserting the reader is drained, and
//!    `tests/der_pin_eval.rs::der_derived_sequences_and_trailing_content`
//!    measures what the *derived* types do so the gap is a recorded
//!    measurement rather than an assumption.
//!
//! # No recursive walker
//!
//! Per D60 §2.4 this module contains no recursive DER traversal. Depth is
//! `der`'s guard — `MAX_DEPTH = 64`, so 63 nested constructions accepted —
//! consumed by name, because a hand-written recursive prescan overflows the
//! stack and **aborts** on hostile input (measured: depth 20 000 in 83 407
//! bytes → `SIGABRT`), which is not catchable and traps on `wasm32`.

use cms::content_info::ContentInfo;
use der::asn1::{GeneralizedTime, Int, ObjectIdentifier, OctetString};
use der::{
    Any, Decode, DecodeValue, Encode, EncodeValue, ErrorKind, Header, Length, Reader, Sequence, Tag,
    TagMode, TagNumber, Writer,
};
use x509_cert::ext::Extensions;
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::spki::AlgorithmIdentifierOwned;

use super::error::{AnchorError, DerSite, der_error};

/// `id-ct-TSTInfo` — RFC 3161 §2.4.2, the only `eContentType` a timestamp
/// token may encapsulate.
pub const ID_CT_TST_INFO: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.1.4");

/// `PKIStatus` values RFC 3161 §2.4.2 defines as carrying a usable token.
const PKI_STATUS_GRANTED: u32 = 0;
/// `grantedWithMods` — the token was issued with modifications.
const PKI_STATUS_GRANTED_WITH_MODS: u32 = 1;

/// The only `TSTInfo.version` RFC 3161 defines.
const TST_INFO_V1: i64 = 1;

// ─── PKIStatusInfo ──────────────────────────────────────────────────────

/// ```text
/// PKIStatusInfo ::= SEQUENCE {
///     status        PKIStatus,
///     statusString  PKIFreeText     OPTIONAL,
///     failInfo      PKIFailureInfo  OPTIONAL }
/// ```
///
/// Hand-decoded rather than derived: both OPTIONAL fields are untagged and
/// `statusString` is the one antseal never reads, so the obvious
/// `Option<Any>` for it would consume `failInfo`. The two are separated by
/// tag (`SEQUENCE` vs `BIT STRING`), which is what makes a tag-directed
/// decode exact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PkiStatusInfo {
    /// `PKIStatus`, an INTEGER. Kept as the decoded integer because the
    /// failure path reports it.
    status: Int,
    /// `PKIFreeText`, a `SEQUENCE OF UTF8String`. Captured for
    /// well-formedness and never read: it is TSA-authored free text and
    /// nothing may branch on it.
    status_string: Option<Any>,
    /// `PKIFailureInfo`, a BIT STRING. Diagnostic only.
    fail_info: Option<der::asn1::BitString>,
}

impl PkiStatusInfo {
    /// The status as a `u32`, or `None` when the encoded value does not fit
    /// one. RFC 3161 defines 0..=5; anything wider is refused as not-granted
    /// rather than decoded into a lie.
    #[must_use]
    pub fn status(&self) -> Option<u32> {
        int_as_u32(&self.status)
    }

    /// Whether the response carries a usable token.
    #[must_use]
    pub fn is_granted(&self) -> bool {
        matches!(
            self.status(),
            Some(PKI_STATUS_GRANTED | PKI_STATUS_GRANTED_WITH_MODS)
        )
    }

    /// The `failInfo` bits, when present. Diagnostic only — no verdict, no
    /// code and no report byte may depend on them.
    #[must_use]
    pub const fn fail_info(&self) -> Option<&der::asn1::BitString> {
        self.fail_info.as_ref()
    }

    /// Whether a `statusString` was present. Diagnostic only.
    #[must_use]
    pub const fn has_status_string(&self) -> bool {
        self.status_string.is_some()
    }
}

impl<'a> DecodeValue<'a> for PkiStatusInfo {
    type Error = der::Error;

    fn decode_value<R: Reader<'a>>(reader: &mut R, _header: Header) -> der::Result<Self> {
        let status = Int::decode(reader)?;
        let status_string = if peek_is(reader, Tag::Sequence)? {
            Some(Any::decode(reader)?)
        } else {
            None
        };
        let fail_info = if peek_is(reader, Tag::BitString)? {
            Some(der::asn1::BitString::decode(reader)?)
        } else {
            None
        };
        finish_nested(reader)?;
        Ok(Self {
            status,
            status_string,
            fail_info,
        })
    }
}

// ─── TimeStampResp ──────────────────────────────────────────────────────

/// ```text
/// TimeStampResp ::= SEQUENCE {
///     status          PKIStatusInfo,
///     timeStampToken  TimeStampToken  OPTIONAL }
/// ```
///
/// `TimeStampToken` is a CMS `ContentInfo` (RFC 3161 §2.4.2), so the shell
/// stops here and `cms` takes over.
#[derive(Debug, Clone, PartialEq, Eq, Sequence)]
pub struct TimeStampResp {
    /// The status block.
    pub status: PkiStatusInfo,
    /// The token, when one was issued.
    #[asn1(optional = "true")]
    pub time_stamp_token: Option<ContentInfo>,
}

impl TimeStampResp {
    /// Parse a `TimeStampResp` from strict DER.
    ///
    /// # Errors
    ///
    /// [`AnchorError::Der`] with the class D60 §7.2 assigns: a BER construct
    /// or a non-canonical encoding gives `anchor-der-not-strict`, an
    /// over-deep document gives `anchor-der-nesting-depth`, anything else
    /// gives `anchor-der-malformed`.
    pub fn parse(bytes: &[u8]) -> Result<Self, AnchorError> {
        Self::from_der(bytes).map_err(|e| der_error(DerSite::Response, e))
    }

    /// The token, if the status grants one.
    ///
    /// # Errors
    ///
    /// [`AnchorError::StatusNotGranted`] when the status is neither
    /// `granted` nor `grantedWithMods`; [`AnchorError::TokenAbsent`] when it
    /// grants but carries no token.
    pub fn granted_token(&self) -> Result<&ContentInfo, AnchorError> {
        if !self.status.is_granted() {
            return Err(AnchorError::StatusNotGranted {
                // `u32::MAX` stands for "wider than RFC 3161's 0..=5", which
                // is itself not-granted; the value is diagnostic only.
                status: self.status.status().unwrap_or(u32::MAX),
            });
        }
        self.time_stamp_token
            .as_ref()
            .ok_or(AnchorError::TokenAbsent)
    }
}

// ─── MessageImprint ─────────────────────────────────────────────────────

/// ```text
/// MessageImprint ::= SEQUENCE {
///     hashAlgorithm  AlgorithmIdentifier,
///     hashedMessage  OCTET STRING }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Sequence)]
pub struct MessageImprint {
    /// The digest algorithm. antseal requires SHA-256 exactly (D60 §3.3):
    /// A4 always requests it and `anchor_digest` is SHA-256.
    pub hash_algorithm: AlgorithmIdentifierOwned,
    /// The digest itself.
    pub hashed_message: OctetString,
}

// ─── Accuracy ───────────────────────────────────────────────────────────

/// ```text
/// Accuracy ::= SEQUENCE {
///     seconds  INTEGER            OPTIONAL,
///     millis   [0] INTEGER (1..999) OPTIONAL,
///     micros   [1] INTEGER (1..999) OPTIONAL }
/// ```
///
/// Present in 4 of the 9 live captures and never read by any rule — parsed
/// rather than captured as an opaque `Any` so that a token carrying garbage
/// here is refused instead of tolerated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Sequence)]
pub struct Accuracy {
    /// Whole seconds.
    #[asn1(optional = "true")]
    pub seconds: Option<u32>,
    /// Milliseconds.
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT", optional = "true")]
    pub millis: Option<u16>,
    /// Microseconds.
    #[asn1(context_specific = "1", tag_mode = "IMPLICIT", optional = "true")]
    pub micros: Option<u16>,
}

// ─── TSTInfo ────────────────────────────────────────────────────────────

/// ```text
/// TSTInfo ::= SEQUENCE {
///     version         INTEGER { v1(1) },
///     policy          TSAPolicyId,
///     messageImprint  MessageImprint,
///     serialNumber    INTEGER,
///     genTime         GeneralizedTime,
///     accuracy        Accuracy                 OPTIONAL,
///     ordering        BOOLEAN            DEFAULT FALSE,
///     nonce           INTEGER                  OPTIONAL,
///     tsa             [0] GeneralName          OPTIONAL,
///     extensions      [1] IMPLICIT Extensions  OPTIONAL }
/// ```
///
/// Hand-decoded for the DEFAULT rule on `ordering`, which no derive
/// enforces, and because `accuracy`/`ordering`/`nonce` are three untagged
/// OPTIONALs in a row — a shape where one `Any` anywhere silently eats the
/// next field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TstInfo {
    version: Int,
    policy: ObjectIdentifier,
    message_imprint: MessageImprint,
    serial_number: Int,
    gen_time: GeneralizedTime,
    accuracy: Option<Accuracy>,
    ordering: bool,
    nonce: Option<Int>,
    tsa: Option<GeneralName>,
    extensions: Option<Extensions>,
}

impl TstInfo {
    /// Parse a `TSTInfo` from strict DER, then check its version.
    ///
    /// # Errors
    ///
    /// [`AnchorError::Der`] for an encoding fault;
    /// [`AnchorError::TstVersionUnsupported`] when `version != 1`.
    pub fn parse(bytes: &[u8]) -> Result<Self, AnchorError> {
        let info = Self::from_der(bytes).map_err(|e| der_error(DerSite::TstInfo, e))?;
        let version = int_as_i64(&info.version).unwrap_or(i64::MIN);
        if version != TST_INFO_V1 {
            // `i64::MIN` is the sentinel for "wider than an i64", which is
            // certainly not 1. Diagnostic payload only.
            return Err(AnchorError::TstVersionUnsupported { version });
        }
        Ok(info)
    }

    /// The TSA policy under which the token was issued.
    #[must_use]
    pub const fn policy(&self) -> ObjectIdentifier {
        self.policy
    }

    /// What the token timestamps.
    #[must_use]
    pub const fn message_imprint(&self) -> &MessageImprint {
        &self.message_imprint
    }

    /// The TSA's serial number for this token. DER INTEGER content octets;
    /// **not** interpreted as a number, because real serials exceed every
    /// integer width (DigiCert's is 17 octets).
    #[must_use]
    pub fn serial_number(&self) -> &[u8] {
        self.serial_number.as_bytes()
    }

    /// The claimed stamping time.
    ///
    /// **Never compare this to a local clock.** A21/A32 own the prohibition
    /// and D60 §5.4 measured why: the D60 capture host's clock ran 129 s
    /// slow, so the obvious `gen_time <= fetch_date` sanity check rejects
    /// every committed fixture. `antseal-core` cannot make the mistake by
    /// construction — it reads no clock and verification time is a parameter
    /// — and this accessor exists so A9 can evaluate the certificate chain
    /// *at* `genTime`, which is the only use it has.
    #[must_use]
    pub const fn gen_time(&self) -> GeneralizedTime {
        self.gen_time
    }

    /// `genTime` as whole seconds since the Unix epoch.
    #[must_use]
    pub fn gen_time_unix(&self) -> u64 {
        self.gen_time.to_unix_duration().as_secs()
    }

    /// The TSA's stated accuracy, when present. OPTIONAL and unused; carried
    /// so a caller can render it, never so a rule can branch on it.
    #[must_use]
    pub const fn accuracy(&self) -> Option<Accuracy> {
        self.accuracy
    }

    /// The `ordering` flag. Present as `TRUE` on FreeTSA; no rule reads it.
    #[must_use]
    pub const fn ordering(&self) -> bool {
        self.ordering
    }

    /// The nonce's DER INTEGER **content octets**, when present.
    ///
    /// Content octets, not the raw draw: A4 emits 8 bytes, or 9 when the
    /// sign prefix was needed, and the caller compares against what A4
    /// emitted (D59 §1). Byte comparison is exact value comparison here
    /// because DER INTEGER encoding is canonical and A5 rejects non-minimal
    /// encodings, so two encodings are equal iff the values are.
    #[must_use]
    pub fn nonce(&self) -> Option<&[u8]> {
        self.nonce.as_ref().map(Int::as_bytes)
    }

    /// The TSA name, when present. Not a trust input: RFC 3161 §2.4.2 makes
    /// it informational and the signer certificate is what identifies the
    /// TSA.
    #[must_use]
    pub const fn tsa(&self) -> Option<&GeneralName> {
        self.tsa.as_ref()
    }

    /// `TSTInfo` extensions, when present.
    ///
    /// **None of the nine live TSAs sends any** (asserted in
    /// `tests/anchor_real_tokens.rs`), so today this is always `None` on real
    /// material. They are parsed for well-formedness and otherwise ignored:
    /// no decision in the register rules on what a *critical* unrecognised
    /// `TSTInfo` extension should mean, and inventing a rule against zero
    /// fixtures is the defect D60 §4 refuses. Recorded as open work rather
    /// than silently decided.
    #[must_use]
    pub const fn extensions(&self) -> Option<&Extensions> {
        self.extensions.as_ref()
    }
}

impl<'a> DecodeValue<'a> for TstInfo {
    type Error = der::Error;

    fn decode_value<R: Reader<'a>>(reader: &mut R, _header: Header) -> der::Result<Self> {
        let version = Int::decode(reader)?;
        let policy = ObjectIdentifier::decode(reader)?;
        let message_imprint = MessageImprint::decode(reader)?;
        let serial_number = Int::decode(reader)?;
        let gen_time = GeneralizedTime::decode(reader)?;

        let accuracy = if peek_is(reader, Tag::Sequence)? {
            Some(Accuracy::decode(reader)?)
        } else {
            None
        };

        // `ordering BOOLEAN DEFAULT FALSE`. X.690 §11.5: a DEFAULT value MUST
        // NOT be encoded in DER, so an explicit FALSE here is a strictness
        // fault, not a redundancy. `der`'s own `default` attribute would have
        // accepted it — it expands to `Option::<T>::decode(..).unwrap_or_else`
        // — which is why this field is decoded by hand.
        let ordering = if peek_is(reader, Tag::Boolean)? {
            if bool::decode(reader)? {
                true
            } else {
                return Err(reader.error(ErrorKind::Noncanonical { tag: Tag::Boolean }));
            }
        } else {
            false
        };

        let nonce = if peek_is(reader, Tag::Integer)? {
            Some(Int::decode(reader)?)
        } else {
            None
        };

        // `tsa [0] GeneralName` is EXPLICIT: `GeneralName` is a CHOICE, so
        // RFC 3161's `[0]` cannot be implicit and `Reader::context_specific`
        // is unusable (its `T: FixedTag` bound is exactly what a CHOICE
        // cannot satisfy). The wrapper is read as an `Any` and its value
        // re-parsed with `from_der`, which validates the inner CHOICE *and*
        // rejects anything after it — a capture-only path would accept junk
        // beside a legitimate GeneralName.
        let tsa = if peek_is(
            reader,
            Tag::ContextSpecific {
                constructed: true,
                number: TAG_TSA,
            },
        )? {
            let wrapper = Any::decode(reader)?;
            Some(GeneralName::from_der(wrapper.value())?)
        } else {
            None
        };

        // `extensions [1] IMPLICIT Extensions`.
        let extensions = reader.context_specific::<Extensions>(TAG_EXTENSIONS, TagMode::Implicit)?;

        finish_nested(reader)?;
        Ok(Self {
            version,
            policy,
            message_imprint,
            serial_number,
            gen_time,
            accuracy,
            ordering,
            nonce,
            tsa,
            extensions,
        })
    }
}

/// `[0]` — `TSTInfo.tsa`.
const TAG_TSA: TagNumber = TagNumber(0);
/// `[1]` — `TSTInfo.extensions`.
const TAG_EXTENSIONS: TagNumber = TagNumber(1);

// ─── encoding ───────────────────────────────────────────────────────────
//
// The two hand-decoded types need `EncodeValue` because `TimeStampResp`
// derives `Sequence`, whose generated encoder requires every field to be
// `Encode`. It is not dead weight: `tests/anchor_caps.rs` builds its
// over-limit fixtures by decoding a real token, mutating the structure and
// re-encoding, which is how a synthetic token stays a *token* rather than a
// blob nothing would have accepted anyway.

impl EncodeValue for PkiStatusInfo {
    fn value_len(&self) -> der::Result<Length> {
        self.status.encoded_len()?
            + self.status_string.encoded_len()?
            + self.fail_info.encoded_len()?
    }

    fn encode_value(&self, writer: &mut impl Writer) -> der::Result<()> {
        self.status.encode(writer)?;
        self.status_string.encode(writer)?;
        self.fail_info.encode(writer)
    }
}

impl<'a> Sequence<'a> for PkiStatusInfo {}

impl EncodeValue for TstInfo {
    fn value_len(&self) -> der::Result<Length> {
        let mut len = self.version.encoded_len()?;
        len = (len + self.policy.encoded_len()?)?;
        len = (len + self.message_imprint.encoded_len()?)?;
        len = (len + self.serial_number.encoded_len()?)?;
        len = (len + self.gen_time.encoded_len()?)?;
        len = (len + self.accuracy.encoded_len()?)?;
        if self.ordering {
            len = (len + true.encoded_len()?)?;
        }
        len = (len + self.nonce.encoded_len()?)?;
        if let Some(tsa) = &self.tsa {
            len = (len + explicit_tsa_len(tsa)?)?;
        }
        if let Some(ext) = &self.extensions {
            len = (len + implicit_extensions_len(ext)?)?;
        }
        Ok(len)
    }

    fn encode_value(&self, writer: &mut impl Writer) -> der::Result<()> {
        self.version.encode(writer)?;
        self.policy.encode(writer)?;
        self.message_imprint.encode(writer)?;
        self.serial_number.encode(writer)?;
        self.gen_time.encode(writer)?;
        self.accuracy.encode(writer)?;
        // DER omits a DEFAULT value: `ordering` is written only when TRUE,
        // which is the same rule the decoder enforces in the other direction.
        if self.ordering {
            true.encode(writer)?;
        }
        self.nonce.encode(writer)?;
        if let Some(tsa) = &self.tsa {
            Header::new(
                Tag::ContextSpecific {
                    constructed: true,
                    number: TAG_TSA,
                },
                tsa.encoded_len()?,
            )
            .encode(writer)?;
            tsa.encode(writer)?;
        }
        if let Some(ext) = &self.extensions {
            let body = ext.value_len()?;
            Header::new(
                Tag::ContextSpecific {
                    constructed: true,
                    number: TAG_EXTENSIONS,
                },
                body,
            )
            .encode(writer)?;
            ext.encode_value(writer)?;
        }
        Ok(())
    }
}

impl<'a> Sequence<'a> for TstInfo {}

/// Encoded length of the EXPLICIT `[0]` wrapper around a `GeneralName`.
fn explicit_tsa_len(tsa: &GeneralName) -> der::Result<Length> {
    let inner = tsa.encoded_len()?;
    Header::new(
        Tag::ContextSpecific {
            constructed: true,
            number: TAG_TSA,
        },
        inner,
    )
    .encoded_len()?
        + inner
}

/// Encoded length of the IMPLICIT `[1]` re-tagging of `Extensions`.
fn implicit_extensions_len(ext: &Extensions) -> der::Result<Length> {
    let body = ext.value_len()?;
    Header::new(
        Tag::ContextSpecific {
            constructed: true,
            number: TAG_EXTENSIONS,
        },
        body,
    )
    .encoded_len()?
        + body
}

// ─── integer helpers ────────────────────────────────────────────────────
//
// `der 0.8.1`'s owned `Int` offers no conversion to a Rust integer — only
// `as_bytes`, the DER content octets. Decoding `PKIStatus`/`TSTInfo.version`
// directly as `u32`/`i64` would instead make an out-of-range value a *decode*
// failure, i.e. `anchor-der-malformed`, which is the wrong statement: an
// INTEGER too wide for a `u32` is perfectly well-formed DER and belongs in
// the semantic error that names the field. These two total functions keep
// that distinction, and the range check itself is the thing being tested.

/// DER INTEGER content octets → `u32`. `None` for negative or out-of-range.
fn int_as_u32(int: &Int) -> Option<u32> {
    let bytes = int.as_bytes();
    // A negative value (high bit of the first octet) is never a status.
    if bytes.first().is_none_or(|b| b & 0x80 != 0) {
        return None;
    }
    // DER emits a single leading zero octet only as a sign prefix.
    let magnitude = if bytes[0] == 0 { &bytes[1..] } else { bytes };
    if magnitude.len() > 4 {
        return None;
    }
    Some(magnitude.iter().fold(0u32, |acc, &b| (acc << 8) | u32::from(b)))
}

/// DER INTEGER content octets → `i64`, sign-extended. `None` when wider than
/// eight octets.
fn int_as_i64(int: &Int) -> Option<i64> {
    let bytes = int.as_bytes();
    if bytes.is_empty() || bytes.len() > 8 {
        return None;
    }
    let seed = if bytes[0] & 0x80 == 0 { 0i64 } else { -1i64 };
    Some(
        bytes
            .iter()
            .fold(seed, |acc, &b| (acc << 8) | i64::from(b)),
    )
}

// ─── shared decode helpers ──────────────────────────────────────────────

/// Is the next TLV's tag exactly `tag`? `false` at end of input.
///
/// This is the tag-directed alternative to an untagged `Option<Any>` field,
/// which `der` would let swallow whatever follows it.
fn peek_is<'a, R: Reader<'a>>(reader: &R, tag: Tag) -> der::Result<bool> {
    if reader.is_finished() {
        return Ok(false);
    }
    Ok(Tag::peek(reader)? == tag)
}

/// Reject content left unread inside a nested construction.
///
/// `der 0.8.1` does not do this for us: `Reader::finish` is called only at
/// the top level of `from_der`, and `read_nested` restores the outer position
/// without checking that the inner reader was drained
/// (`reader/position.rs:93-97`). Without this call every hand-written
/// `decode_value` here would silently accept junk appended inside its own
/// SEQUENCE.
fn finish_nested<'a, R: Reader<'a>>(reader: &mut R) -> der::Result<()> {
    if reader.is_finished() {
        return Ok(());
    }
    let decoded = reader.position();
    let remaining = reader.remaining_len();
    Err(reader.error(ErrorKind::TrailingData { decoded, remaining }))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The OID is the one RFC 3161 §2.4.2 assigns; a typo here would make
    /// every real token fail with `anchor-cms-not-tst-info`, and the
    /// nine-token suite would say so — but it would say so confusingly. This
    /// says it directly.
    #[test]
    fn tst_info_content_type_oid() {
        assert_eq!(ID_CT_TST_INFO.to_string(), "1.2.840.113549.1.9.16.1.4");
    }

    /// The trap D60 §3.1's model would have shipped: a `PKIStatusInfo` that
    /// omits `statusString` and carries `failInfo` — the shape of every
    /// *rejection* response, and the shape none of the nine granted captures
    /// could have exercised.
    ///
    /// `30 08  02 01 02  03 03 00 80 00` = status 2 (rejection), no
    /// statusString, failInfo with `badAlg` set. With `status_string:
    /// Option<Any>` the `Any` consumes the BIT STRING and `fail_info` is
    /// `None`; the assertion below is red in that build.
    #[test]
    fn status_string_absent_does_not_swallow_fail_info() {
        const DER: &[u8] = &[0x30, 0x08, 0x02, 0x01, 0x02, 0x03, 0x03, 0x00, 0x80, 0x00];
        let info = PkiStatusInfo::from_der(DER).expect("well-formed PKIStatusInfo");
        assert_eq!(info.status(), Some(2));
        assert!(!info.has_status_string(), "no statusString was encoded");
        assert!(
            info.fail_info().is_some(),
            "failInfo was swallowed by a greedy Any — the D60 §3.1 model's defect"
        );
    }

    /// The same message with a `statusString` present must still find the
    /// `failInfo`. Without this leg the test above passes on an
    /// implementation that simply never decodes `statusString`.
    #[test]
    fn status_string_present_is_parsed_and_fail_info_still_found() {
        // 30 11  02 01 02  30 07 (0c 05 "wrong")  03 03 00 80 00
        const DER: &[u8] = &[
            0x30, 0x11, 0x02, 0x01, 0x02, 0x30, 0x07, 0x0c, 0x05, b'w', b'r', b'o', b'n', b'g',
            0x03, 0x03, 0x00, 0x80, 0x00,
        ];
        let info = PkiStatusInfo::from_der(DER).expect("well-formed PKIStatusInfo");
        assert_eq!(info.status(), Some(2));
        assert!(info.has_status_string());
        assert!(info.fail_info().is_some());
    }

    /// A status wider than `u32` is refused as not-granted rather than
    /// wrapped into a value that might read as `granted`.
    #[test]
    fn an_oversized_status_is_not_granted() {
        // 30 0b  02 09 00 ff ff ff ff ff ff ff ff   (2^64 - 1)
        const DER: &[u8] = &[
            0x30, 0x0b, 0x02, 0x09, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        ];
        let info = PkiStatusInfo::from_der(DER).expect("well-formed PKIStatusInfo");
        assert_eq!(info.status(), None);
        assert!(!info.is_granted());
    }

    /// X.690 §11.5, which no `der` derive enforces. A `TSTInfo` whose
    /// `ordering` is explicitly `FALSE` is not DER.
    #[test]
    fn an_explicitly_encoded_default_ordering_is_rejected() {
        let der = tst_info_with_ordering(Some(false));
        let err = TstInfo::parse(&der).expect_err("explicit DEFAULT must be refused");
        assert_eq!(err.code(), "anchor-der-not-strict");
    }

    /// The other direction, or the test above proves only that some tokens
    /// fail: `ordering TRUE` is legal (FreeTSA sends it) and `ordering`
    /// absent is legal, and both must parse.
    #[test]
    fn ordering_true_and_ordering_absent_both_parse() {
        let with_true = TstInfo::parse(&tst_info_with_ordering(Some(true)))
            .expect("ordering TRUE is legal DER");
        assert!(with_true.ordering());
        let without =
            TstInfo::parse(&tst_info_with_ordering(None)).expect("absent ordering is legal DER");
        assert!(!without.ordering());
    }

    /// Content appended inside the `TSTInfo` SEQUENCE is rejected. `der`
    /// does not reject it for us (`Reader::finish` runs at the top level
    /// only), so this pins the compensating check in `finish_nested`.
    #[test]
    fn trailing_content_inside_tst_info_is_rejected() {
        let mut der = tst_info_with_ordering(None);
        // Append a NULL inside the SEQUENCE and grow the outer length.
        der.extend_from_slice(&[0x05, 0x00]);
        let body_len = der.len() - 2;
        der[1] = u8::try_from(body_len).expect("fixture body fits one length octet");
        let err = TstInfo::parse(&der).expect_err("junk inside the SEQUENCE must be refused");
        assert_eq!(err.code(), "anchor-der-malformed");
    }

    /// A minimal but real `TSTInfo`, built by hand so the `ordering` field
    /// can be varied. Version 1, policy 1.2.3, SHA-256 imprint over 32 zero
    /// bytes, serial 1, `genTime` in the DER-legal 15-octet form.
    fn tst_info_with_ordering(ordering: Option<bool>) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&[0x02, 0x01, 0x01]); // version 1
        body.extend_from_slice(&[0x06, 0x02, 0x2a, 0x03]); // policy 1.2.3
        // messageImprint: SEQUENCE { AlgorithmIdentifier(sha256, NULL), OCTET STRING(32) }
        body.extend_from_slice(&[0x30, 0x31, 0x30, 0x0d, 0x06, 0x09]);
        body.extend_from_slice(&[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01]);
        body.extend_from_slice(&[0x05, 0x00, 0x04, 0x20]);
        body.extend_from_slice(&[0u8; 32]);
        body.extend_from_slice(&[0x02, 0x01, 0x01]); // serialNumber 1
        body.extend_from_slice(&[0x18, 0x0f]); // GeneralizedTime, 15 octets
        body.extend_from_slice(b"20260802192227Z");
        if let Some(flag) = ordering {
            body.extend_from_slice(&[0x01, 0x01, if flag { 0xff } else { 0x00 }]);
        }
        let mut out = vec![0x30, u8::try_from(body.len()).expect("fixture body < 128 B")];
        out.extend_from_slice(&body);
        out
    }
}
