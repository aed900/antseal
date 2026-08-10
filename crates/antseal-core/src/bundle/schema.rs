//! The v1 `.sealproof` bundle schema (F8): [`BundleV1`] and its section
//! types, with every tier-**`[P]`** and tier-**`[X]`** rule of registry
//! §§7.6–7.14 enforced where a bundle is *created* — which is the same place
//! it is decoded.
//!
//! # What this layer is, and what it deliberately is not
//!
//! This is **layer 1** of the three-layer decode of registry §7.6.3. It
//! answers "is this a well-formed v1 `.sealproof`?" from the bundle's own
//! bytes and nothing else.
//!
//! **D78 (ratified): bundle schema validation never consults the embedded
//! manifest.** Key 1 is an opaque `bstr` here — a borrowed sub-slice handed
//! on to F9's layer 2 — so no presence rule of this module can reach for
//! manifest data. Every rule that genuinely needs both sides is tier `[R]` and
//! belongs to `crate::verify`: which reveal array a unit belongs in, id
//! resolution into the manifest tables, `full_reveal.s_root` presence,
//! leaf-exactness of a GGM cover, the no-ancestor-seed rule, tiling,
//! `true_length` = range width, and partial-reveal isolation (MVP-SPEC.md
//! line 121).
//!
//! Artifact internals are likewise out of scope: `.ots` bytes, DER tokens and
//! certificates, and the receipt payload are opaque [`OpaqueBytes`] this
//! module never parses. The attestation/ops model, CMS/X.509 verification,
//! chain validation against the pinned root store, and every `.ots`/DER size
//! limit are **A's, at M2**.
//!
//! # Construction is validation
//!
//! A schema-invalid [`BundleV1`] cannot exist: every field is private and
//! both construction paths — [`BundleV1::new`] (reveal side) and
//! [`BundleV1::decode`] (verify side) — funnel through the same checks,
//! **including the D10 §1 count and artifact-size caps** (F41: the caps
//! originally ran only at the array/`bstr` heads of the decode path, so
//! the constructors could assemble an anchor set or reveal set whose
//! encoding no v1 decoder accepts — and this doc claimed otherwise). On
//! the decode path the constructor-side cap re-checks can never fire —
//! the walk already enforced them on the claimed counts — so decode
//! precedence and every tamper row are untouched.
//!
//! **The two aggregate byte caps are enforced one layer later** (F53):
//! `MAX_BUNDLE_BYTES` and `MAX_MANIFEST_BYTES` are properties of
//! *encoded* artifacts, invisible to a constructor of parts, so
//! [`encode_bundle`] and
//! [`encode_envelope`](crate::manifest::encode_envelope) check them on
//! the finished bytes with the decode path's own `bundle-too-large` /
//! `manifest-too-large` codes. Per-part caps cannot substitute: 256 OTS
//! anchors of 1 MiB are 256 legal artifacts that sum past the bundle
//! cap. With that, "constructible **and encodable**" equals "decodable"
//! with no residual.
//!
//! Several rules are stronger still — unrepresentable rather than checked:
//!
//! | rule (registry) | how it is enforced |
//! | --- | --- |
//! | anchor kind is positional, never a field (§7.6.2) | two distinct types in two distinct sections; a TSA token cannot be written into the OTS array |
//! | the OTS upgrade group is all-or-nothing (§7.8, D79) | [`OtsUpgrade`] holds all three fields; `Option<OtsUpgrade>` has no "two of three" state |
//! | `anchor_status` is one of seven values (§6.1) | [`AnchorStatus`] is a closed enum |
//! | a node address satisfies `level <= 64`, `index < 2^level` (§5) | [`NodeAddress`] is valid by construction (G8) |
//! | no reveal-shape discriminant exists (§7.6.1, D28 rider 1) | no such field is declared, and `tests/identifier_bans.rs` greps the repo for one |
//!
//! # There is no reveal-shape field, and there must never be one (D28)
//!
//! The bundle carries no `is_full_reveal` / `reveal_mode` / `reveal_shape`
//! discriminant at any level. Reveal shape is **derived** from the signed
//! unit table and the revealed set (D28 rider 1); a declared shape would be a
//! second, *sealer-forgeable* source of truth, and a bundle declaring
//! "partial" while revealing every unit would reintroduce through the wire
//! format exactly the permissive option D28 rejected. A [`FullReveal`] entry
//! is therefore **material, not a claim**: it supplies openings whose
//! presence must *agree* with the independently derived predicate, and R4
//! computes that predicate — this module never does.
//!
//! # Wire integers are `u64`
//!
//! No `usize` appears in any wire-facing type, error payload, or length
//! check, so decode results and error values are identical on wasm32 and on
//! 64-bit natives (the F5 rule, and a precondition for the WASM↔native
//! bit-match requirement).
//!
//! # Secret hygiene (project rule 6)
//!
//! A `.sealproof` carries *disclosed* key material: `k_u` per reveal, `k_m`
//! in the storage record, and the three 16-byte salts. Disclosed is not
//! public-by-accident — those values are held in the crypto layer's
//! redacting, zeroizing newtypes ([`Key32`], [`Salt16`], [`Seed32`]) so a
//! `Debug`-printed bundle cannot dump them into a log, and [`OpaqueBytes`]
//! renders its length rather than its contents. C7's opaque `FileSalt` is
//! deliberately **not** used here — see [`FullReveal`] for why a
//! serializable field must not be the type whose whole purpose is to have no
//! public byte path.

use crate::codec::caps::{MAX_BUNDLE_BYTES, clamped_capacity};
use crate::codec::encode::MapEncoder;
use crate::codec::{
    CanonicalDecoder, CanonicalEncoder, CappedArtifact, DecodeError, EncodeError, encode_item,
};
use crate::content::ggm::NodeAddress;
use crate::crypto::material::{Key32, NodeHash32, Salt16, Seed32};
use crate::format::{SUPPORTED_VERSIONS, V1, VersionDispatch};
use crate::manifest::{ContentAddress, Nonce24};

use super::error::{
    BundleError, BundleListKind, CiphertextDefect, ContainerField, FixedLenField, OpaqueField,
    OrderedList, TupleId,
};
use super::registry::{
    AnchorStatus, BLOCK_HEADER_LEN, BundleMapId, FORMAT_VERSION_V1, KEY_LEN, KeyClass,
    MIN_CIPHERTEXT_LEN, NODE_HASH_LEN, PADDING_BLOCK, SALT_LEN, SEED_LEN, STORAGE_ADDRESS_LEN,
    STORAGE_NONCE_LEN, TX_HASH_LEN, key,
};

// ---------------------------------------------------------------------------
// decode plumbing
// ---------------------------------------------------------------------------

/// Wrap a codec rejection as a bundle-layer (layer 1) failure.
const fn cbor(source: DecodeError) -> BundleError {
    BundleError::Cbor { source }
}

/// The construction-side counterpart of [`decode_section`]'s cap step
/// (F41): reject an already-materialised list longer than its D10 cap,
/// with the same error and payload the decode path reports at the array
/// head. On the decode path this re-check can never fire — the head cap
/// already bounded the element count — so it binds the
/// direct-construction path only.
fn check_section_cap<T>(list: BundleListKind, entries: &[T]) -> Result<(), BundleError> {
    let claimed = entries.len() as u64;
    let cap = list.cap();
    if claimed > cap {
        return Err(BundleError::ListTooLong { list, claimed, cap });
    }
    Ok(())
}

/// The construction-side counterpart of [`decode_opaque`]'s cap step
/// (F41); same error, same payload, same [`OpaqueField::cap`] source as
/// the decode path, so the two sides cannot disagree on a value.
fn check_opaque_cap(field: OpaqueField, bytes: &OpaqueBytes) -> Result<(), BundleError> {
    let len = bytes.len();
    let cap = field.cap();
    if len > cap {
        return Err(BundleError::ArtifactTooLarge { field, len, cap });
    }
    Ok(())
}

/// Classify a decoded map key, converting the two non-assigned bands into
/// their distinct errors (registry §1 rule 4).
fn admit_key(map: BundleMapId, key: u64) -> Result<(), BundleError> {
    match map.classify(key) {
        KeyClass::Assigned => Ok(()),
        KeyClass::Reserved => Err(BundleError::ReservedKey { map, key }),
        KeyClass::Unknown => Err(BundleError::UnknownKey { map, key }),
    }
}

/// A required key that never arrived.
const fn missing(map: BundleMapId, key: u64) -> BundleError {
    BundleError::MissingKey { map, key }
}

/// Reject an assigned-key match arm the classifier already excluded.
/// Unreachable: [`BundleMapId::classify`] returns `Assigned` only for keys the
/// map's decode loop handles. Present so the match is total without a panic
/// path (library code never unwraps).
const fn unhandled_assigned_key(map: BundleMapId, key: u64) -> BundleError {
    BundleError::UnknownKey { map, key }
}

/// Length-checked conversion of a decoded `bstr` into a fixed-size array.
fn fixed<const N: usize>(field: FixedLenField, bytes: &[u8]) -> Result<[u8; N], BundleError> {
    <[u8; N]>::try_from(bytes).map_err(|_| BundleError::WrongLength {
        field,
        // usize -> u64 is lossless on every supported target; wire-facing
        // values are u64 so errors match bit-for-bit on wasm32.
        expected: N as u64,
        got: bytes.len() as u64,
    })
}

/// The cheap parse-time shape gate on a unit ciphertext (registry §2).
///
/// XChaCha20-Poly1305 output = padded plaintext + a 16-byte tag and
/// `padded_length` is a positive multiple of 256 (MVP-SPEC.md line 91), so
/// `len >= 272` and `len ≡ 16 (mod 256)`. **Checked in that order**: a length
/// of 271 violates both, and the fixed order is what lets a tamper row pin
/// one code (D30). The exact `len == padded_length(true_length) + 16` needs
/// the manifest and is R's.
fn check_ciphertext_shape(len: u64) -> Result<(), BundleError> {
    if len < MIN_CIPHERTEXT_LEN {
        return Err(BundleError::CiphertextShape {
            defect: CiphertextDefect::TooShort,
            got: len,
        });
    }
    if len % PADDING_BLOCK != MIN_CIPHERTEXT_LEN % PADDING_BLOCK {
        return Err(BundleError::CiphertextShape {
            defect: CiphertextDefect::BadResidue,
            got: len,
        });
    }
    Ok(())
}

/// Strict ascent over a list's `u64` sort key (registry §8). Strict ascent
/// also rejects duplicates, which is why "two entries for one id" and
/// "entries out of order" share one code per list.
fn check_ascending_ids(
    list: OrderedList,
    ids: impl IntoIterator<Item = u64>,
) -> Result<(), BundleError> {
    let mut previous: Option<u64> = None;
    for id in ids {
        if let Some(prev) = previous
            && prev >= id
        {
            return Err(BundleError::UnsortedList {
                list,
                previous: u128::from(prev),
                found: u128::from(id),
            });
        }
        previous = Some(id);
    }
    Ok(())
}

/// The leaf-interval start of a node address, rescaled to a common depth.
///
/// The true start is `index · 2^(d − level)` for the file's depth `d`, which
/// this layer does not know (`d` comes from the manifest — tier `[R]`).
/// Registry §8 records the way out: rescaling every start by the same
/// positive factor preserves strict order, so comparing
/// `index · 2^(D − level)` for **any** common `D >= max(level)` gives the
/// identical verdict. Computed in `u128` because the bound `2^D <= 2^64` is
/// not a `u64`.
const fn scaled_interval_start(address: NodeAddress, common_depth: u8) -> u128 {
    // `common_depth >= address.level()` at every call site (it is the
    // pairwise maximum), so the shift distance is in `0..=64`.
    (address.index() as u128) << (common_depth - address.level())
}

/// Strict ascent over node-address leaf-interval starts (registry §5/§8).
///
/// Compares each adjacent pair at `D = max(level_a, level_b)`, which is
/// order-equivalent to comparing true starts at the real depth `d >= D`.
/// The reported `previous`/`found` are the values at that pairwise `D`, i.e.
/// diagnostics rather than absolute leaf offsets.
fn check_ascending_addresses(
    list: OrderedList,
    addresses: impl IntoIterator<Item = NodeAddress>,
) -> Result<(), BundleError> {
    let mut previous: Option<NodeAddress> = None;
    for address in addresses {
        if let Some(prev) = previous {
            let common = prev.level().max(address.level());
            let before = scaled_interval_start(prev, common);
            let after = scaled_interval_start(address, common);
            if before >= after {
                return Err(BundleError::UnsortedList {
                    list,
                    previous: before,
                    found: after,
                });
            }
        }
        previous = Some(address);
    }
    Ok(())
}

/// Decode the leading `[level, index]` of a registry §5 tuple into a
/// validity-checked [`NodeAddress`].
///
/// Constructed through G8's [`NodeAddress::try_new`] rather than re-checked
/// inline, so `level <= 64` and `index < 2^level` have exactly one
/// implementation and one error code each (registry §5; D30).
///
/// A wire `level` too large for `u8` saturates to 255 in the error payload.
/// The rejection class is unaffected — 255 > `MAX_LEVEL` = 64, so the same
/// error and the same code result — only the reported number is clamped, and
/// that number is diagnostic, never verdict-bearing.
fn decode_node_address(d: &mut CanonicalDecoder<'_>) -> Result<NodeAddress, BundleError> {
    let level = d.u64().map_err(cbor)?;
    let index = d.u64().map_err(cbor)?;
    let level = u8::try_from(level).unwrap_or(u8::MAX);
    NodeAddress::try_new(level, index).map_err(|source| BundleError::NodeAddress { source })
}

// ---------------------------------------------------------------------------
// opaque payloads
// ---------------------------------------------------------------------------

/// A variable-length byte payload this layer carries but never parses:
/// `.ots` bytes, DER tokens and certificates, the Arbitrum receipt payload,
/// and unit ciphertexts.
///
/// `Debug` renders the **length only**. Two reasons: a rendered bundle must
/// not dump ciphertext or multi-kilobyte DER into a log (project rule 6's
/// discipline applied to disclosed-but-bulky material), and the length is the
/// only property this layer is entitled to have an opinion about.
#[derive(Clone, PartialEq, Eq)]
pub struct OpaqueBytes(Vec<u8>);

impl OpaqueBytes {
    /// Wrap owned bytes.
    #[must_use]
    pub const fn from_vec(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Borrow the payload.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    /// Payload length in bytes (`u64`, never `usize` — wire-facing).
    #[must_use]
    pub fn len(&self) -> u64 {
        self.0.len() as u64
    }

    /// Whether the payload is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl core::fmt::Debug for OpaqueBytes {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "OpaqueBytes({} bytes)", self.len())
    }
}

// ---------------------------------------------------------------------------
// manifest storage record (registry §7.7)
// ---------------------------------------------------------------------------

/// The **manifest's own** storage triple — the address, nonce, and key of the
/// uploaded *encrypted* manifest copy (MVP-SPEC.md line 98: "bytes anchored ≠
/// bytes stored"). Per-unit addresses and nonces live in the manifest unit
/// table, not here.
///
/// Required, not optional, even though no *evidence*-layer check consumes it:
/// an absent record would be a second bundle shape for the same logical
/// content, and the storage-linkage layer must be able to say "this bundle
/// claims persistence and the claim fails" rather than "this bundle said
/// nothing". The evidence verdict never depends on it — that separation is
/// R's, and no wire flag encodes it.
#[derive(Debug)]
pub struct StorageRecord {
    address: ContentAddress,
    nonce: Nonce24,
    k_m: Key32,
}

impl StorageRecord {
    /// Assemble a storage record from already-typed values.
    #[must_use]
    pub const fn new(address: ContentAddress, nonce: Nonce24, k_m: Key32) -> Self {
        Self {
            address,
            nonce,
            k_m,
        }
    }

    /// Autonomi address of the encrypted manifest copy (decision D11).
    #[must_use]
    pub const fn address(&self) -> &ContentAddress {
        &self.address
    }

    /// That copy's XChaCha20-Poly1305 nonce. Manifest AEAD uses **empty
    /// AAD** (spec line 98), so no further binding field is carried.
    #[must_use]
    pub const fn nonce(&self) -> &Nonce24 {
        &self.nonce
    }

    /// `k_m = HKDF(W, "manifest-key")`. Disclosing it costs nothing: the
    /// bundle already embeds the plaintext manifest.
    #[must_use]
    pub const fn k_m(&self) -> &Key32 {
        &self.k_m
    }

    fn decode(d: &mut CanonicalDecoder<'_>) -> Result<Self, BundleError> {
        const MAP: BundleMapId = BundleMapId::StorageRecord;
        let mut reader = d.map().map_err(cbor)?;
        let mut address: Option<ContentAddress> = None;
        let mut nonce: Option<Nonce24> = None;
        let mut k_m: Option<Key32> = None;

        while let Some(k) = reader.next_key(d).map_err(cbor)? {
            admit_key(MAP, k)?;
            match k {
                key::storage_record::ADDRESS => {
                    let bytes = d.bytes().map_err(cbor)?;
                    address = Some(ContentAddress::from_bytes(fixed::<
                        { STORAGE_ADDRESS_LEN as usize },
                    >(
                        FixedLenField::StorageAddress,
                        bytes,
                    )?));
                }
                key::storage_record::NONCE => {
                    let bytes = d.bytes().map_err(cbor)?;
                    nonce = Some(Nonce24::from_bytes(
                        fixed::<{ STORAGE_NONCE_LEN as usize }>(
                            FixedLenField::StorageNonce,
                            bytes,
                        )?,
                    ));
                }
                key::storage_record::K_M => {
                    let bytes = d.bytes().map_err(cbor)?;
                    k_m = Some(Key32::from_bytes(fixed::<{ KEY_LEN as usize }>(
                        FixedLenField::ManifestKey,
                        bytes,
                    )?));
                }
                other => return Err(unhandled_assigned_key(MAP, other)),
            }
        }

        Ok(Self {
            address: address.ok_or(missing(MAP, key::storage_record::ADDRESS))?,
            nonce: nonce.ok_or(missing(MAP, key::storage_record::NONCE))?,
            k_m: k_m.ok_or(missing(MAP, key::storage_record::K_M))?,
        })
    }
}

// ---------------------------------------------------------------------------
// anchor artifacts (registry §§7.8–7.9)
// ---------------------------------------------------------------------------

/// The OTS **upgrade group**: block height, the 80-byte block header, and the
/// fetch date, carried together or not at all (registry §7.8).
///
/// **D79 (ratified): the group is free-standing and all-or-nothing.** Its
/// presence is *never* keyed on the artifact's `status` field — the sealer
/// writes `status`, and the design says a verifier must never trust it, so a
/// parse rule reading it would hand the sealer a lever on the decoder. Two of
/// the three present is a malformed artifact, and holding all three in one
/// struct makes that state unrepresentable rather than merely rejected.
///
/// Anchor *semantics* — what an upgraded OTS attestation proves, and the
/// online gate that promotes it to `proven` — are A's, at M2. This is the
/// shape only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OtsUpgrade {
    block_height: u64,
    block_header: [u8; BLOCK_HEADER_LEN as usize],
    fetch_date: u64,
}

impl OtsUpgrade {
    /// Assemble an upgrade record from already-typed values.
    #[must_use]
    pub const fn new(
        block_height: u64,
        block_header: [u8; BLOCK_HEADER_LEN as usize],
        fetch_date: u64,
    ) -> Self {
        Self {
            block_height,
            block_header,
            fetch_date,
        }
    }

    /// The attested Bitcoin block height.
    #[must_use]
    pub const fn block_height(&self) -> u64 {
        self.block_height
    }

    /// The embedded 80-byte Bitcoin block header (MVP-SPEC.md line 108).
    /// Never parsed here.
    #[must_use]
    pub const fn block_header(&self) -> &[u8; BLOCK_HEADER_LEN as usize] {
        &self.block_header
    }

    /// When the upgrade/header was fetched — POSIX seconds UTC
    /// (registry §3).
    #[must_use]
    pub const fn fetch_date(&self) -> u64 {
        self.fetch_date
    }
}

/// One OpenTimestamps anchor artifact (MVP-SPEC.md lines 108, 112–114).
///
/// **The anchor kind is positional, not a field** (registry §7.6.2): this
/// type only ever appears in bundle key 3, so "a TSA token in the OTS array"
/// is not a representable state needing a checked rule. The cost — a future
/// third anchor kind is a new top-level key rather than a new enum value — is
/// the intended shape, since a new kind arrives with a new artifact schema
/// regardless.
#[derive(Debug)]
pub struct OtsAnchor {
    status: AnchorStatus,
    ots: OpaqueBytes,
    upgrade: Option<OtsUpgrade>,
}

impl OtsAnchor {
    /// Assemble an OTS artifact, under the same D10 byte cap the decode
    /// path enforces (F41 — previously unchecked here, so the seal side
    /// could embed an `.ots` no v1 decoder accepts).
    ///
    /// # Errors
    ///
    /// [`BundleError::ArtifactTooLarge`] — `ots` exceeds
    /// [`OpaqueField::Ots`]'s cap (`bundle-ots-too-large`, as on decode).
    pub fn new(
        status: AnchorStatus,
        ots: OpaqueBytes,
        upgrade: Option<OtsUpgrade>,
    ) -> Result<Self, BundleError> {
        check_opaque_cap(OpaqueField::Ots, &ots)?;
        Ok(Self {
            status,
            ots,
            upgrade,
        })
    }

    /// The **sealer-recorded** status. Never trusted: the verifier derives
    /// its own state from the artifact (spec line 121).
    #[must_use]
    pub const fn status(&self) -> AnchorStatus {
        self.status
    }

    /// The raw `.ots` bytes — opaque here; A parses them at M2, and A owns
    /// their size limits.
    #[must_use]
    pub const fn ots(&self) -> &OpaqueBytes {
        &self.ots
    }

    /// The upgrade group, present iff this anchor has been upgraded to a
    /// Bitcoin attestation (D79).
    #[must_use]
    pub const fn upgrade(&self) -> Option<&OtsUpgrade> {
        self.upgrade.as_ref()
    }

    fn decode(d: &mut CanonicalDecoder<'_>) -> Result<Self, BundleError> {
        const MAP: BundleMapId = BundleMapId::OtsAnchor;
        let mut reader = d.map().map_err(cbor)?;
        let mut status: Option<AnchorStatus> = None;
        let mut ots: Option<OpaqueBytes> = None;
        let mut block_height: Option<u64> = None;
        let mut block_header: Option<[u8; BLOCK_HEADER_LEN as usize]> = None;
        let mut fetch_date: Option<u64> = None;

        while let Some(k) = reader.next_key(d).map_err(cbor)? {
            admit_key(MAP, k)?;
            match k {
                key::ots_anchor::STATUS => status = Some(decode_anchor_status(d)?),
                key::ots_anchor::OTS => ots = Some(decode_opaque(d, OpaqueField::Ots)?),
                key::ots_anchor::BLOCK_HEIGHT => block_height = Some(d.u64().map_err(cbor)?),
                key::ots_anchor::BLOCK_HEADER => {
                    let bytes = d.bytes().map_err(cbor)?;
                    block_header = Some(fixed::<{ BLOCK_HEADER_LEN as usize }>(
                        FixedLenField::BlockHeader,
                        bytes,
                    )?);
                }
                key::ots_anchor::FETCH_DATE => fetch_date = Some(d.u64().map_err(cbor)?),
                other => return Err(unhandled_assigned_key(MAP, other)),
            }
        }

        // D79: all-or-nothing over the three group keys, decided without ever
        // reading `status`. The reported missing key is the lowest-numbered
        // absent one, so the payload is deterministic when two are absent.
        let upgrade = match (block_height, block_header, fetch_date) {
            (None, None, None) => None,
            (Some(height), Some(header), Some(date)) => Some(OtsUpgrade::new(height, header, date)),
            (height, header, _) => {
                let missing_key = if height.is_none() {
                    key::ots_anchor::BLOCK_HEIGHT
                } else if header.is_none() {
                    key::ots_anchor::BLOCK_HEADER
                } else {
                    key::ots_anchor::FETCH_DATE
                };
                return Err(BundleError::OtsUpgradeGroupIncomplete { missing_key });
            }
        };

        Ok(Self {
            status: status.ok_or(missing(MAP, key::ots_anchor::STATUS))?,
            ots: ots.ok_or(missing(MAP, key::ots_anchor::OTS))?,
            upgrade,
        })
    }
}

/// One RFC 3161 TSA anchor artifact (MVP-SPEC.md lines 109, 112–114).
///
/// One artifact per token: "≥ 2 TSAs" means ≥ 2 entries in bundle key 4, not
/// a multi-token artifact. Nothing in the schema requires two — an
/// under-anchored bundle is a *verdict*, not a parse error.
#[derive(Debug)]
pub struct TsaAnchor {
    status: AnchorStatus,
    token: OpaqueBytes,
    intermediates: Vec<OpaqueBytes>,
    fetch_date: u64,
}

impl TsaAnchor {
    /// Assemble a TSA artifact, under the same D10 caps the decode path
    /// enforces (F41), checked in the decode path's key order: token byte
    /// cap, intermediates count cap, then each certificate's byte cap.
    ///
    /// # Errors
    ///
    /// - [`BundleError::ArtifactTooLarge`] — over-cap `token`
    ///   (`bundle-tsa-token-too-large`) or certificate
    ///   (`bundle-cert-too-large`).
    /// - [`BundleError::ListTooLong`] — more than
    ///   [`BundleListKind::Intermediates`]'s cap of certificates
    ///   (`bundle-too-many-intermediates`).
    pub fn new(
        status: AnchorStatus,
        token: OpaqueBytes,
        intermediates: Vec<OpaqueBytes>,
        fetch_date: u64,
    ) -> Result<Self, BundleError> {
        check_opaque_cap(OpaqueField::TsaToken, &token)?;
        check_section_cap(BundleListKind::Intermediates, &intermediates)?;
        for cert in &intermediates {
            check_opaque_cap(OpaqueField::Certificate, cert)?;
        }
        Ok(Self {
            status,
            token,
            intermediates,
            fetch_date,
        })
    }

    /// The **sealer-recorded** status. Never trusted.
    #[must_use]
    pub const fn status(&self) -> AnchorStatus {
        self.status
    }

    /// The DER `TimeStampResp`/token — opaque here; CMS/X.509 parsing and
    /// pinned-root chain validation are A's, at M2.
    #[must_use]
    pub const fn token(&self) -> &OpaqueBytes {
        &self.token
    }

    /// DER intermediate certificates, in the order the TSA supplied them.
    ///
    /// **Intermediates only.** A bundle-supplied chain can never close
    /// against a bundle-supplied root (spec line 109), so no root slot exists
    /// here to be tempted by.
    #[must_use]
    pub fn intermediates(&self) -> &[OpaqueBytes] {
        &self.intermediates
    }

    /// When the token was obtained — POSIX seconds UTC. Always known at
    /// seal, hence required where the OTS counterpart is optional.
    #[must_use]
    pub const fn fetch_date(&self) -> u64 {
        self.fetch_date
    }

    fn decode(d: &mut CanonicalDecoder<'_>) -> Result<Self, BundleError> {
        const MAP: BundleMapId = BundleMapId::TsaAnchor;
        let mut reader = d.map().map_err(cbor)?;
        let mut status: Option<AnchorStatus> = None;
        let mut token: Option<OpaqueBytes> = None;
        let mut intermediates: Option<Vec<OpaqueBytes>> = None;
        let mut fetch_date: Option<u64> = None;

        while let Some(k) = reader.next_key(d).map_err(cbor)? {
            admit_key(MAP, k)?;
            match k {
                key::tsa_anchor::STATUS => status = Some(decode_anchor_status(d)?),
                key::tsa_anchor::TOKEN => token = Some(decode_opaque(d, OpaqueField::TsaToken)?),
                key::tsa_anchor::INTERMEDIATES => {
                    intermediates = Some(decode_section(d, BundleListKind::Intermediates, |d| {
                        decode_opaque(d, OpaqueField::Certificate)
                    })?);
                }
                key::tsa_anchor::FETCH_DATE => fetch_date = Some(d.u64().map_err(cbor)?),
                other => return Err(unhandled_assigned_key(MAP, other)),
            }
        }

        Ok(Self {
            status: status.ok_or(missing(MAP, key::tsa_anchor::STATUS))?,
            token: token.ok_or(missing(MAP, key::tsa_anchor::TOKEN))?,
            intermediates: intermediates.ok_or(missing(MAP, key::tsa_anchor::INTERMEDIATES))?,
            fetch_date: fetch_date.ok_or(missing(MAP, key::tsa_anchor::FETCH_DATE))?,
        })
    }
}

/// Read one `anchor_status` value, rejecting the reserved band.
fn decode_anchor_status(d: &mut CanonicalDecoder<'_>) -> Result<AnchorStatus, BundleError> {
    let raw = d.u64().map_err(cbor)?;
    AnchorStatus::from_wire(raw).ok_or(BundleError::UnknownAnchorStatus { value: raw })
}

// ---------------------------------------------------------------------------
// Arbitrum receipt (registry §7.10)
// ---------------------------------------------------------------------------

/// The opt-in Arbitrum payment receipt (MVP-SPEC.md line 110).
///
/// **Presence is the opt-in.** There is no parse-decidable condition on this
/// section: its presence *is* the sealer's `--include-receipt` choice, so
/// absence is never an error and presence is never required. A verifier must
/// not read anything into either.
///
/// The MVP verdict is fixed and unchangeable by this section — "supporting
/// evidence, no independently proven time" — because no on-chain datum
/// contains `anchor_digest`.
#[derive(Debug)]
pub struct ReceiptRecord {
    tx_hashes: Vec<[u8; TX_HASH_LEN as usize]>,
    block_number: u64,
    payload: OpaqueBytes,
}

impl ReceiptRecord {
    /// Assemble a receipt record: the D10 caps the decode path enforces
    /// (F41), in the decode path's key order, then the one shape rule this
    /// level owns — at least one transaction hash.
    ///
    /// On the decode path ([`Self::decode`] funnels through here) the cap
    /// checks can never fire: the walk already enforced them at the array
    /// head and on the `bstr`. They bind the direct-construction path.
    ///
    /// # Errors
    ///
    /// - [`BundleError::ListTooLong`] — more than
    ///   [`BundleListKind::TxHashes`]'s cap of hashes
    ///   (`bundle-too-many-tx-hashes`, as on decode).
    /// - [`BundleError::ArtifactTooLarge`] — over-cap `payload`
    ///   (`bundle-receipt-payload-too-large`, as on decode).
    /// - [`BundleError::EmptyContainer`] when `tx_hashes` is empty — a
    ///   payment has at least one transaction, so an empty list is
    ///   malformed rather than "no payment".
    pub fn new(
        tx_hashes: Vec<[u8; TX_HASH_LEN as usize]>,
        block_number: u64,
        payload: OpaqueBytes,
    ) -> Result<Self, BundleError> {
        check_section_cap(BundleListKind::TxHashes, &tx_hashes)?;
        check_opaque_cap(OpaqueField::ReceiptPayload, &payload)?;
        if tx_hashes.is_empty() {
            return Err(BundleError::EmptyContainer {
                field: ContainerField::TxHashes,
            });
        }
        Ok(Self {
            tx_hashes,
            block_number,
            payload,
        })
    }

    /// Keccak-256 EVM transaction hashes, in capture order.
    #[must_use]
    pub fn tx_hashes(&self) -> &[[u8; TX_HASH_LEN as usize]] {
        &self.tx_hashes
    }

    /// The payment's Arbitrum One block number.
    #[must_use]
    pub const fn block_number(&self) -> u64 {
        self.block_number
    }

    /// The opaque A/S capture (quote preimages, `proof_bytes`).
    ///
    /// Deliberately outside the wire registry: its internal layout is A/S's
    /// and is *not* a v1 wire format, so changing it is not a
    /// format-version event. Anything the v1.1 verification chain must read
    /// in a version-stable, cross-implementation way goes in the reserved
    /// `chain_inputs` slot instead (registry §7.10 key 3).
    #[must_use]
    pub const fn payload(&self) -> &OpaqueBytes {
        &self.payload
    }

    fn decode(d: &mut CanonicalDecoder<'_>) -> Result<Self, BundleError> {
        const MAP: BundleMapId = BundleMapId::ReceiptRecord;
        let mut reader = d.map().map_err(cbor)?;
        let mut tx_hashes: Option<Vec<[u8; TX_HASH_LEN as usize]>> = None;
        let mut block_number: Option<u64> = None;
        let mut payload: Option<OpaqueBytes> = None;

        while let Some(k) = reader.next_key(d).map_err(cbor)? {
            admit_key(MAP, k)?;
            match k {
                key::receipt::TX_HASHES => {
                    tx_hashes = Some(decode_section(d, BundleListKind::TxHashes, |d| {
                        let bytes = d.bytes().map_err(cbor)?;
                        fixed::<{ TX_HASH_LEN as usize }>(FixedLenField::TxHash, bytes)
                    })?);
                }
                key::receipt::BLOCK_NUMBER => block_number = Some(d.u64().map_err(cbor)?),
                key::receipt::PAYLOAD => {
                    payload = Some(decode_opaque(d, OpaqueField::ReceiptPayload)?);
                }
                other => return Err(unhandled_assigned_key(MAP, other)),
            }
        }

        Self::new(
            tx_hashes.ok_or(missing(MAP, key::receipt::TX_HASHES))?,
            block_number.ok_or(missing(MAP, key::receipt::BLOCK_NUMBER))?,
            payload.ok_or(missing(MAP, key::receipt::PAYLOAD))?,
        )
    }
}

// ---------------------------------------------------------------------------
// GGM cover / boundary path tuples (registry §5)
// ---------------------------------------------------------------------------

/// One disclosed GGM sub-cover seed: `cover_entry = [level, index, seed]`
/// (registry §5, D9 Candidate A).
///
/// The address is explicit on the wire rather than implied by position,
/// deliberately: the verifier MUST recompute the expected leaf-exact cover
/// from `(range, n, d)` and compare **sets**, which is what gives
/// "over-broad cover spanning an unrevealed leaf" and "wrong-position node"
/// distinct, nameable errors instead of one generic root mismatch.
///
/// Leaf-exactness and the no-ancestor-seed rule are **`[R]`** — they need the
/// manifest and G13's cover derivation.
#[derive(Debug)]
pub struct CoverEntry {
    address: NodeAddress,
    seed: Seed32,
}

impl CoverEntry {
    /// Assemble a cover entry from a validated address and a 32-byte seed.
    #[must_use]
    pub const fn new(address: NodeAddress, seed: Seed32) -> Self {
        Self { address, seed }
    }

    /// The node's `(level, index)` address — valid by construction (G8).
    #[must_use]
    pub const fn address(&self) -> NodeAddress {
        self.address
    }

    /// The disclosed covering seed.
    #[must_use]
    pub const fn seed(&self) -> &Seed32 {
        &self.seed
    }

    fn decode(d: &mut CanonicalDecoder<'_>) -> Result<Self, BundleError> {
        let arity = d.array().map_err(cbor)?;
        if arity != TupleId::CoverEntry.arity() {
            return Err(BundleError::WrongTupleArity {
                tuple: TupleId::CoverEntry,
                got: arity,
            });
        }
        let address = decode_node_address(d)?;
        let bytes = d.bytes().map_err(cbor)?;
        let seed = Seed32::from_bytes(fixed::<{ SEED_LEN as usize }>(
            FixedLenField::CoverSeed,
            bytes,
        )?);
        Ok(Self { address, seed })
    }
}

/// One boundary Merkle sibling node: `path_node = [level, index, hash]`
/// (registry §5).
#[derive(Debug)]
pub struct PathNode {
    address: NodeAddress,
    hash: NodeHash32,
}

impl PathNode {
    /// Assemble a path node from a validated address and a 32-byte hash.
    #[must_use]
    pub const fn new(address: NodeAddress, hash: NodeHash32) -> Self {
        Self { address, hash }
    }

    /// The node's `(level, index)` address — valid by construction (G8).
    #[must_use]
    pub const fn address(&self) -> NodeAddress {
        self.address
    }

    /// The sibling node hash.
    #[must_use]
    pub const fn hash(&self) -> &NodeHash32 {
        &self.hash
    }

    fn decode(d: &mut CanonicalDecoder<'_>) -> Result<Self, BundleError> {
        let arity = d.array().map_err(cbor)?;
        if arity != TupleId::PathNode.arity() {
            return Err(BundleError::WrongTupleArity {
                tuple: TupleId::PathNode,
                got: arity,
            });
        }
        let address = decode_node_address(d)?;
        let bytes = d.bytes().map_err(cbor)?;
        let hash = NodeHash32::from_bytes(fixed::<{ NODE_HASH_LEN as usize }>(
            FixedLenField::PathNodeHash,
            bytes,
        )?);
        Ok(Self { address, hash })
    }
}

// ---------------------------------------------------------------------------
// reveals (registry §§7.11–7.12)
// ---------------------------------------------------------------------------

/// One revealed **fine-tree-covered** unit (MVP-SPEC.md lines 96, 112–114):
/// the unit key, the ciphertext, the leaf-exact GGM sub-cover of its leaf
/// range, and the boundary Merkle path up to `fine_root`.
///
/// # No nonce, no AAD (registry §7.6.1)
///
/// Nonces come from the manifest — the single source of truth (spec
/// line 114) — and `AAD = seal_id ‖ LE64(unit_id)` is reconstructed from the
/// manifest and this entry's `unit_id`. A bundle-side nonce would be a
/// second, sealer-controlled AEAD input the verifier could be steered onto,
/// so the field does not exist and `tests/bundle_schema.rs` asserts its
/// absence rather than merely not implementing it.
///
/// # `cover` and `paths` are nested here on purpose
///
/// Because both live *inside* the reveal they belong to, a proof can only
/// speak about the unit whose entry encloses it: "proof reaches outside the
/// revealed set" is **unrepresentable in v1**. That check idles until bundle
/// key 10 (`range_reveals`) is assigned in v1.1, where a range proof may name
/// units by id from a separate section — recorded so it is not deleted as
/// dead code.
///
/// # D75: a full reveal ships covers **and** `s_root`
///
/// `cover` is unconditionally required (tier `[P]`), including for units of a
/// fully revealed file whose [`FullReveal`] entry also carries `s_root`. That
/// keeps bundle schema validation decidable from the bundle alone; the
/// alternative — omitting covers on a full reveal — would make this key's
/// presence depend on the derived full-reveal predicate and so cross into
/// tier `[R]`. On a full reveal the covers leak nothing, since every leaf is
/// disclosed anyway. The consequence is R's: the two routes to `fine_root`
/// must be required to *agree*.
#[derive(Debug)]
pub struct CoveredReveal {
    unit_id: u64,
    k_u: Key32,
    ciphertext: OpaqueBytes,
    cover: Vec<CoverEntry>,
    paths: Vec<PathNode>,
}

impl CoveredReveal {
    /// Assemble a covered reveal: the two D10 count caps the decode path
    /// enforces (F41), in the decode path's key order, then the rules this
    /// level owns — the ciphertext's length shape, a non-empty cover, and
    /// strict ascent of both `cover` and `paths` by leaf-interval start.
    ///
    /// On the decode path ([`Self::decode`] funnels through here) the cap
    /// checks can never fire: [`decode_section`] already enforced them at
    /// the two array heads. They bind the direct-construction path.
    ///
    /// # Errors
    ///
    /// - [`BundleError::ListTooLong`] — over-cap `cover`
    ///   (`bundle-too-many-cover-entries`) or `paths`
    ///   (`bundle-too-many-path-nodes`), as on decode.
    /// - [`BundleError::CiphertextShape`] — the ciphertext is shorter than a
    ///   padding block plus the tag, or not one tag past a whole number of
    ///   blocks (registry §2).
    /// - [`BundleError::EmptyContainer`] — an empty `cover`; a covered unit
    ///   has at least one leaf, and the empty unit is never covered.
    /// - [`BundleError::UnsortedList`] — `cover` or `paths` not strictly
    ///   ascending (registry §8); strict ascent also rejects duplicates.
    pub fn new(
        unit_id: u64,
        k_u: Key32,
        ciphertext: OpaqueBytes,
        cover: Vec<CoverEntry>,
        paths: Vec<PathNode>,
    ) -> Result<Self, BundleError> {
        check_section_cap(BundleListKind::Cover, &cover)?;
        check_section_cap(BundleListKind::Paths, &paths)?;
        check_ciphertext_shape(ciphertext.len())?;
        if cover.is_empty() {
            return Err(BundleError::EmptyContainer {
                field: ContainerField::Cover,
            });
        }
        check_ascending_addresses(OrderedList::Cover, cover.iter().map(CoverEntry::address))?;
        check_ascending_addresses(OrderedList::Paths, paths.iter().map(PathNode::address))?;
        Ok(Self {
            unit_id,
            k_u,
            ciphertext,
            cover,
            paths,
        })
    }

    /// The revealed unit's work-global ordinal. Resolving it into the
    /// manifest unit table is **`[R]`**.
    #[must_use]
    pub const fn unit_id(&self) -> u64 {
        self.unit_id
    }

    /// The disclosed unit key, so the verifier decrypts without ever holding
    /// the master secret `W` (spec line 114).
    #[must_use]
    pub const fn k_u(&self) -> &Key32 {
        &self.k_u
    }

    /// The embedded unit ciphertext.
    #[must_use]
    pub const fn ciphertext(&self) -> &OpaqueBytes {
        &self.ciphertext
    }

    /// The leaf-exact GGM sub-cover of this unit's leaf range.
    #[must_use]
    pub fn cover(&self) -> &[CoverEntry] {
        &self.cover
    }

    /// The boundary Merkle sibling path up to `fine_root`. Empty exactly
    /// when the unit spans the whole `[0, n)` grid — the *exactly* is `[R]`.
    #[must_use]
    pub fn paths(&self) -> &[PathNode] {
        &self.paths
    }

    fn decode(d: &mut CanonicalDecoder<'_>) -> Result<Self, BundleError> {
        const MAP: BundleMapId = BundleMapId::CoveredReveal;
        let mut reader = d.map().map_err(cbor)?;
        let mut unit_id: Option<u64> = None;
        let mut k_u: Option<Key32> = None;
        let mut ciphertext: Option<OpaqueBytes> = None;
        let mut cover: Option<Vec<CoverEntry>> = None;
        let mut paths: Option<Vec<PathNode>> = None;

        while let Some(k) = reader.next_key(d).map_err(cbor)? {
            admit_key(MAP, k)?;
            match k {
                key::covered_reveal::UNIT_ID => unit_id = Some(d.u64().map_err(cbor)?),
                key::covered_reveal::K_U => k_u = Some(decode_unit_key(d)?),
                key::covered_reveal::CIPHERTEXT => {
                    ciphertext = Some(OpaqueBytes::from_vec(d.bytes().map_err(cbor)?.to_vec()));
                }
                key::covered_reveal::COVER => {
                    cover = Some(decode_section(
                        d,
                        BundleListKind::Cover,
                        CoverEntry::decode,
                    )?);
                }
                key::covered_reveal::PATHS => {
                    paths = Some(decode_section(d, BundleListKind::Paths, PathNode::decode)?);
                }
                other => return Err(unhandled_assigned_key(MAP, other)),
            }
        }

        Self::new(
            unit_id.ok_or(missing(MAP, key::covered_reveal::UNIT_ID))?,
            k_u.ok_or(missing(MAP, key::covered_reveal::K_U))?,
            ciphertext.ok_or(missing(MAP, key::covered_reveal::CIPHERTEXT))?,
            cover.ok_or(missing(MAP, key::covered_reveal::COVER))?,
            paths.ok_or(missing(MAP, key::covered_reveal::PATHS))?,
        )
    }
}

/// One revealed **non-covered** unit — a `--no-fine-tree` whole-file unit or
/// a raw mirror (MVP-SPEC.md lines 92, 94, 112–114): the two cases bound by
/// `unit_commit` rather than by `fine_root`.
///
/// A raw-mirror reveal is an ordinary entry here — no mirror flag, no link
/// field: the manifest's `kind` already identifies it (D23), and whether a
/// unit legitimately belongs in *this* section rather than
/// [`CoveredReveal`]'s is **`[R]`** (it depends on the file's
/// `fine_tree_present` and the unit's `kind`).
///
/// Keys 0–2 are deliberately key-aligned with [`CoveredReveal`] so both
/// reveal kinds share one decode prefix: same key numbers, same types, same
/// `[P]` checks, one implementation.
#[derive(Debug)]
pub struct NonCoveredReveal {
    unit_id: u64,
    k_u: Key32,
    ciphertext: OpaqueBytes,
    unit_salt: Salt16,
}

impl NonCoveredReveal {
    /// Assemble a non-covered reveal, checking the ciphertext length shape.
    ///
    /// # Errors
    ///
    /// [`BundleError::CiphertextShape`] — see [`CoveredReveal::new`].
    pub fn new(
        unit_id: u64,
        k_u: Key32,
        ciphertext: OpaqueBytes,
        unit_salt: Salt16,
    ) -> Result<Self, BundleError> {
        check_ciphertext_shape(ciphertext.len())?;
        Ok(Self {
            unit_id,
            k_u,
            ciphertext,
            unit_salt,
        })
    }

    /// The revealed unit's work-global ordinal. Resolution is **`[R]`**.
    #[must_use]
    pub const fn unit_id(&self) -> u64 {
        self.unit_id
    }

    /// The disclosed unit key.
    #[must_use]
    pub const fn k_u(&self) -> &Key32 {
        &self.k_u
    }

    /// The embedded unit ciphertext.
    #[must_use]
    pub const fn ciphertext(&self) -> &OpaqueBytes {
        &self.ciphertext
    }

    /// The salt that opens `unit_commit = SHA-256(0x02 ‖ unit_salt ‖ bytes)`
    /// (spec line 94).
    #[must_use]
    pub const fn unit_salt(&self) -> &Salt16 {
        &self.unit_salt
    }

    fn decode(d: &mut CanonicalDecoder<'_>) -> Result<Self, BundleError> {
        const MAP: BundleMapId = BundleMapId::NonCoveredReveal;
        let mut reader = d.map().map_err(cbor)?;
        let mut unit_id: Option<u64> = None;
        let mut k_u: Option<Key32> = None;
        let mut ciphertext: Option<OpaqueBytes> = None;
        let mut unit_salt: Option<Salt16> = None;

        while let Some(k) = reader.next_key(d).map_err(cbor)? {
            admit_key(MAP, k)?;
            match k {
                key::noncovered_reveal::UNIT_ID => unit_id = Some(d.u64().map_err(cbor)?),
                key::noncovered_reveal::K_U => k_u = Some(decode_unit_key(d)?),
                key::noncovered_reveal::CIPHERTEXT => {
                    ciphertext = Some(OpaqueBytes::from_vec(d.bytes().map_err(cbor)?.to_vec()));
                }
                key::noncovered_reveal::UNIT_SALT => {
                    let bytes = d.bytes().map_err(cbor)?;
                    unit_salt = Some(Salt16::from_bytes(fixed::<{ SALT_LEN as usize }>(
                        FixedLenField::UnitSalt,
                        bytes,
                    )?));
                }
                other => return Err(unhandled_assigned_key(MAP, other)),
            }
        }

        Self::new(
            unit_id.ok_or(missing(MAP, key::noncovered_reveal::UNIT_ID))?,
            k_u.ok_or(missing(MAP, key::noncovered_reveal::K_U))?,
            ciphertext.ok_or(missing(MAP, key::noncovered_reveal::CIPHERTEXT))?,
            unit_salt.ok_or(missing(MAP, key::noncovered_reveal::UNIT_SALT))?,
        )
    }
}

/// Read one disclosed 32-byte unit key. Shared by both reveal sections —
/// their keys 0–2 are key-aligned precisely so this is one implementation
/// (registry §7.12).
fn decode_unit_key(d: &mut CanonicalDecoder<'_>) -> Result<Key32, BundleError> {
    let bytes = d.bytes().map_err(cbor)?;
    Ok(Key32::from_bytes(fixed::<{ KEY_LEN as usize }>(
        FixedLenField::UnitKey,
        bytes,
    )?))
}

// ---------------------------------------------------------------------------
// file-level disclosures (registry §§7.13–7.14)
// ---------------------------------------------------------------------------

/// One **touched** file: its path and the path-only salt that opens
/// `path_commit` (MVP-SPEC.md lines 95, 112–114).
///
/// `path_salt` is independent of `file_salt` precisely so that naming a file
/// never weakens its content commitments; the two must never be merged into
/// one salt field in a future version.
///
/// The path's bytes **as received** are the commitment pre-image
/// (`path_commit = SHA-256(0x05 ‖ path_salt ‖ path_utf8)`). No NFC, no
/// separator rewriting, no case folding is applied: the text canonicalization
/// pipeline governs file *content*, never this field.
#[derive(Debug)]
pub struct TouchedFile {
    file_id: u64,
    path: String,
    path_salt: Salt16,
}

impl TouchedFile {
    /// Assemble a touched-file entry.
    #[must_use]
    pub const fn new(file_id: u64, path: String, path_salt: Salt16) -> Self {
        Self {
            file_id,
            path,
            path_salt,
        }
    }

    /// Index into the manifest's file table; in-range is **`[R]`**.
    #[must_use]
    pub const fn file_id(&self) -> u64 {
        self.file_id
    }

    /// The disclosed path, byte-identical to the commitment pre-image.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// The 16-byte path-only salt.
    #[must_use]
    pub const fn path_salt(&self) -> &Salt16 {
        &self.path_salt
    }

    fn decode(d: &mut CanonicalDecoder<'_>) -> Result<Self, BundleError> {
        const MAP: BundleMapId = BundleMapId::TouchedFile;
        let mut reader = d.map().map_err(cbor)?;
        let mut file_id: Option<u64> = None;
        let mut path: Option<String> = None;
        let mut path_salt: Option<Salt16> = None;

        while let Some(k) = reader.next_key(d).map_err(cbor)? {
            admit_key(MAP, k)?;
            match k {
                key::touched_file::FILE_ID => file_id = Some(d.u64().map_err(cbor)?),
                // UTF-8 validity is F3's native `tstr` check, surfaced as
                // `cbor-invalid-utf8` through the layer-1 wrapper: it is a
                // canonicality property of the encoding, not a schema rule.
                key::touched_file::PATH => path = Some(d.str().map_err(cbor)?.to_owned()),
                key::touched_file::PATH_SALT => {
                    let bytes = d.bytes().map_err(cbor)?;
                    path_salt = Some(Salt16::from_bytes(fixed::<{ SALT_LEN as usize }>(
                        FixedLenField::PathSalt,
                        bytes,
                    )?));
                }
                other => return Err(unhandled_assigned_key(MAP, other)),
            }
        }

        Ok(Self {
            file_id: file_id.ok_or(missing(MAP, key::touched_file::FILE_ID))?,
            path: path.ok_or(missing(MAP, key::touched_file::PATH))?,
            path_salt: path_salt.ok_or(missing(MAP, key::touched_file::PATH_SALT))?,
        })
    }
}

/// One **fully revealed** file's disclosure material: `file_salt`, and
/// `s_root` when the file has a fine tree (MVP-SPEC.md lines 112–114, 121).
///
/// # The entry is material, not a claim (D28)
///
/// Its presence does **not** assert that the file is fully revealed. D28
/// makes the presence rule a biconditional over a predicate derived from the
/// *signed* unit table and the revealed set:
///
/// ```text
/// N(F)     = { unit_id : unit ∈ manifest.units, unit.file_id = F, kind = Normal }
/// R(F)     = N(F) ∩ bundle.revealed
/// full(F) ⟺ N(F) ≠ ∅ ∧ R(F) = N(F)
///
/// a §7.14 entry for F exists  ⟺  full(F)
/// its s_root is present       ⟺  full(F) ∧ F.fine_tree = Present
/// ```
///
/// Every input is either signed manifest data or bundle field presence, but
/// the predicate needs *both* sides — so the whole biconditional is tier
/// **`[R]`** and R4 owns all five of its violation arms. This module supplies
/// the material and checks its shape; it never decides whether the material
/// *should* be here.
///
/// Note the shape consequence: "missing `file_salt`" is realized as a missing
/// **entry**, not as an entry with a missing key, because `file_salt` is
/// required at schema level and this layer rejects an entry without it long
/// before R4 runs. `s_root` is genuinely optional at schema level, so its
/// arms *are* entry-with-key-absent (and entry-with-key-present).
/// # Why the salt is a [`Salt16`] and not C7's opaque `FileSalt`
///
/// `FileSalt` exists to keep a *derived* `file_salt` unreachable as bytes:
/// C7's rule is that
/// [`FullFileRevealDisclosure::file_salt_bytes`](crate::crypto::disclosure::FullFileRevealDisclosure::file_salt_bytes)
/// is **the only public byte path** to one, and reaching it requires the
/// full-reveal witness. A bundle field must be serializable by definition,
/// so storing `FileSalt` here would make `encode_bundle` a second public
/// byte path and quietly demote that rule to a convention.
///
/// Holding [`Salt16`] instead is also the honest description: a salt that
/// has reached a `FullReveal` is *already disclosed* — it either came off
/// the wire or was obtained through the witness-gated accessor, which
/// already yielded raw bytes. R4 wraps it with
/// [`FileSalt::from_disclosed`](crate::crypto::material::FileSalt::from_disclosed)
/// when re-verifying `raw_commit`/`canon_commit`; that is what
/// `from_disclosed` is for.
#[derive(Debug)]
pub struct FullReveal {
    file_id: u64,
    file_salt: Salt16,
    s_root: Option<Seed32>,
}

impl FullReveal {
    /// Assemble a full-reveal entry.
    #[must_use]
    pub const fn new(file_id: u64, file_salt: Salt16, s_root: Option<Seed32>) -> Self {
        Self {
            file_id,
            file_salt,
            s_root,
        }
    }

    /// Index into the manifest's file table; in-range is **`[R]`**. That the
    /// id also appears in `touched_files` is **`[X]`** and checked here.
    #[must_use]
    pub const fn file_id(&self) -> u64 {
        self.file_id
    }

    /// The 16-byte salt that opens `raw_commit`/`canon_commit`, as
    /// disclosed. See the type docs for why this is a [`Salt16`].
    #[must_use]
    pub const fn file_salt(&self) -> &Salt16 {
        &self.file_salt
    }

    /// The disclosed full `[0, n)` GGM cover, when the file has a fine tree.
    ///
    /// Named `disclosed_*` as a reminder that presence is *evidence to be
    /// checked against* the derived predicate, not a declaration to be
    /// believed (D28).
    #[must_use]
    pub const fn disclosed_s_root(&self) -> Option<&Seed32> {
        self.s_root.as_ref()
    }

    fn decode(d: &mut CanonicalDecoder<'_>) -> Result<Self, BundleError> {
        const MAP: BundleMapId = BundleMapId::FullReveal;
        let mut reader = d.map().map_err(cbor)?;
        let mut file_id: Option<u64> = None;
        let mut file_salt: Option<Salt16> = None;
        let mut s_root: Option<Seed32> = None;

        while let Some(k) = reader.next_key(d).map_err(cbor)? {
            admit_key(MAP, k)?;
            match k {
                key::full_reveal::FILE_ID => file_id = Some(d.u64().map_err(cbor)?),
                key::full_reveal::FILE_SALT => {
                    let bytes = d.bytes().map_err(cbor)?;
                    file_salt = Some(Salt16::from_bytes(fixed::<{ SALT_LEN as usize }>(
                        FixedLenField::FileSalt,
                        bytes,
                    )?));
                }
                key::full_reveal::S_ROOT => {
                    let bytes = d.bytes().map_err(cbor)?;
                    s_root = Some(Seed32::from_bytes(fixed::<{ SEED_LEN as usize }>(
                        FixedLenField::SRoot,
                        bytes,
                    )?));
                }
                other => return Err(unhandled_assigned_key(MAP, other)),
            }
        }

        Ok(Self {
            file_id: file_id.ok_or(missing(MAP, key::full_reveal::FILE_ID))?,
            file_salt: file_salt.ok_or(missing(MAP, key::full_reveal::FILE_SALT))?,
            s_root,
        })
    }
}

// ---------------------------------------------------------------------------
// the bundle (registry §7.6)
// ---------------------------------------------------------------------------

/// The unvalidated section set [`BundleV1::new`] consumes.
///
/// A plain parts bag: it holds whatever a builder assembled, and validation
/// happens on the way *out* of it. Splitting the two keeps `BundleV1`'s
/// invariants attached to `BundleV1` alone — there is no way to obtain one
/// except through the checks.
#[derive(Debug)]
pub struct BundleParts<'b> {
    /// The full plaintext manifest **envelope** bytes, exactly as anchored.
    /// Opaque at this layer (D78).
    pub manifest: &'b [u8],
    /// The manifest's own storage triple.
    pub storage_record: StorageRecord,
    /// OTS anchor artifacts. **Empty is legal**: a bundle with no anchors at
    /// all is well-formed, not a schema error.
    ///
    /// Deliberately **not** spelled "UNANCHORED". That word is MVP-SPEC.md
    /// line 137's and it means *zero headline-eligible anchors* — a bundle
    /// carrying one `pending` OTS is UNANCHORED with this array
    /// **non-empty**. Layer 1 cannot decide it (D78; registry §7.6 is tier
    /// [P], *"decidable from the one entry being decoded"*), and the registry
    /// says so itself: *"an under-anchored bundle is a verdict, not a parse
    /// error"* (§7.9). Four senses of the word share this codebase — D98
    /// rider 3c, extended by D108.
    ///
    /// The registry's own `len/shape` cell for this key **does** spell it
    /// (registry §7.6 key 3, and again in the mirror's `notes`), and is
    /// frozen: see `docs/format/frozen-registry-errata.md` for the scope of
    /// that sentence and D108 §3 for why it is not corrected in place.
    pub ots_anchors: Vec<OtsAnchor>,
    /// TSA anchor artifacts; empty is legal, on the same terms.
    pub tsa_anchors: Vec<TsaAnchor>,
    /// The opt-in Arbitrum receipt.
    pub receipt: Option<ReceiptRecord>,
    /// Covered-unit reveals, ascending by `unit_id`.
    pub covered_reveals: Vec<CoveredReveal>,
    /// Non-covered-unit reveals, ascending by `unit_id`.
    pub noncovered_reveals: Vec<NonCoveredReveal>,
    /// Touched-file entries, ascending by `file_id`.
    pub touched_files: Vec<TouchedFile>,
    /// Full-reveal entries, ascending by `file_id`.
    pub full_reveals: Vec<FullReveal>,
}

/// A decoded v1 `.sealproof` bundle — **layer 1 only**.
///
/// Borrows its input for `'b`. The embedded manifest is held as a
/// **sub-slice of the bundle's own bytes**, never a copy: `Manifest<'b>`'s
/// zero-copy guarantee — that the bytes fed to `work_id` and to signature
/// verification are the received ones *by construction* — only holds if the
/// slice really is the bundle's own bytes, and a decode-into-`Vec` step would
/// silently downgrade that guarantee to a convention. [`Self::manifest_bytes`]
/// is also the `anchor_digest` pre-image (spec line 75).
///
/// # Required-may-be-empty everywhere
///
/// Every top-level key is required except the receipt, so one logical bundle
/// has exactly **one** shape: the "nothing revealed, nothing anchored" bundle
/// is all four sections present and empty, not four keys missing. That avoids
/// the absent-vs-empty split that would give one logical bundle two byte
/// encodings.
///
/// # What a bundle deliberately does not carry (registry §7.6.1)
///
/// No per-unit nonce; **no signature container of any kind** — the bundle is
/// unsigned, its authority is the embedded *signed* manifest plus the anchor
/// artifacts, and a bundle signature would invite the verifier to trust the
/// assembler, who is the sealer, who is the adversary; no stored
/// `work_id`/`anchor_digest`/`seal_id`, all three being derived; and no
/// reveal-shape discriminant (D28 rider 1). `tests/bundle_schema.rs` asserts
/// all four absences — an absence nobody tests is an absence that grows back.
#[derive(Debug)]
pub struct BundleV1<'b> {
    manifest: &'b [u8],
    storage_record: StorageRecord,
    ots_anchors: Vec<OtsAnchor>,
    tsa_anchors: Vec<TsaAnchor>,
    receipt: Option<ReceiptRecord>,
    covered_reveals: Vec<CoveredReveal>,
    noncovered_reveals: Vec<NonCoveredReveal>,
    touched_files: Vec<TouchedFile>,
    full_reveals: Vec<FullReveal>,
}

impl<'b> BundleV1<'b> {
    /// Validate a section set into a bundle.
    ///
    /// Checks run in a **fixed order** so a given input always yields the
    /// same rejection: the six D10 section-count caps in section-key order
    /// (F41 — on the decode path these re-checks can never fire, because
    /// [`decode_section`] enforced each at its array head; they bind the
    /// direct-construction path), then the four list-ordering rules in
    /// section-key order, then the two cross-section rules. The ordering
    /// and cross-section rules are tier `[X]` — decidable from the bundle
    /// alone — which is what keeps them out of the verify family under
    /// D78.
    ///
    /// # Errors
    ///
    /// - [`BundleError::ListTooLong`] — a section longer than its D10 cap
    ///   (the same `bundle-too-many-*` codes the decode path reports).
    /// - [`BundleError::UnsortedList`] — a section is not strictly ascending
    ///   by its id (which also rejects a repeated id within one section).
    /// - [`BundleError::UnitRevealedTwice`] — one `unit_id` appears in both
    ///   reveal sections. R's `DuplicateUnitReveal` remains the
    ///   manifest-aware backstop.
    /// - [`BundleError::FullRevealWithoutTouchedFile`] — a full reveal whose
    ///   path was never disclosed.
    pub fn new(parts: BundleParts<'b>) -> Result<Self, BundleError> {
        let BundleParts {
            manifest,
            storage_record,
            ots_anchors,
            tsa_anchors,
            receipt,
            covered_reveals,
            noncovered_reveals,
            touched_files,
            full_reveals,
        } = parts;

        check_section_cap(BundleListKind::OtsAnchors, &ots_anchors)?;
        check_section_cap(BundleListKind::TsaAnchors, &tsa_anchors)?;
        check_section_cap(BundleListKind::CoveredReveals, &covered_reveals)?;
        check_section_cap(BundleListKind::NonCoveredReveals, &noncovered_reveals)?;
        check_section_cap(BundleListKind::TouchedFiles, &touched_files)?;
        check_section_cap(BundleListKind::FullReveals, &full_reveals)?;

        check_ascending_ids(
            OrderedList::CoveredReveals,
            covered_reveals.iter().map(CoveredReveal::unit_id),
        )?;
        check_ascending_ids(
            OrderedList::NonCoveredReveals,
            noncovered_reveals.iter().map(NonCoveredReveal::unit_id),
        )?;
        check_ascending_ids(
            OrderedList::TouchedFiles,
            touched_files.iter().map(TouchedFile::file_id),
        )?;
        check_ascending_ids(
            OrderedList::FullReveals,
            full_reveals.iter().map(FullReveal::file_id),
        )?;

        // Both cross-section rules are single merge scans over sequences
        // the ordering rules above have already proved strictly ascending
        // (R54). The pre-R54 shape rescanned the other section per element
        // — Θ(|noncovered| × |covered|), up to ~2³² steps for two at-cap
        // disjoint reveal sections, all of it inside stage 1 and therefore
        // ahead of any authenticator (2026-07-31 review, U3). The merge
        // walks each outer section in the same ascending order and decides
        // membership exactly where the rescan did, so the first error is
        // byte-for-byte unchanged; ascending outer ids are what let the
        // inner cursor advance monotonically without ever backtracking.
        let mut covered_ids = covered_reveals
            .iter()
            .map(CoveredReveal::unit_id)
            .peekable();
        for reveal in &noncovered_reveals {
            while covered_ids.next_if(|&id| id < reveal.unit_id()).is_some() {}
            if covered_ids.peek() == Some(&reveal.unit_id()) {
                return Err(BundleError::UnitRevealedTwice {
                    unit_id: reveal.unit_id(),
                });
            }
        }
        let mut touched_ids = touched_files.iter().map(TouchedFile::file_id).peekable();
        for full in &full_reveals {
            while touched_ids.next_if(|&id| id < full.file_id()).is_some() {}
            if touched_ids.peek() != Some(&full.file_id()) {
                return Err(BundleError::FullRevealWithoutTouchedFile {
                    file_id: full.file_id(),
                });
            }
        }

        Ok(Self {
            manifest,
            storage_record,
            ots_anchors,
            tsa_anchors,
            receipt,
            covered_reveals,
            noncovered_reveals,
            touched_files,
            full_reveals,
        })
    }

    /// Destructure a validated bundle back into its section set — the exact
    /// inverse of [`Self::new`], and R34's **re-assembly seam**.
    ///
    /// The parts bag holds whatever a builder assembled and validation
    /// happens on the way *out* of it (see [`BundleParts`]); this is the way
    /// back *in*, so a caller can move a whole section between two decoded
    /// bundles — one work's reveals under another work's manifest, one
    /// work's anchors grafted onto another's — and re-encode. That class of
    /// input is what a hostile relay holding two bundles can cheaply
    /// produce, and byte-level mutation reaches it only by luck.
    ///
    /// **Safe by construction, not by care.** Every field moves out
    /// untouched, and the only route back to a `BundleV1` is [`Self::new`],
    /// which re-runs every tier-`[X]` rule. So a recombination either
    /// produces a bundle that decodes, or is refused by the checks this type
    /// already owns — there is no way to manufacture an
    /// invariant-violating `BundleV1` through here.
    #[must_use]
    pub fn into_parts(self) -> BundleParts<'b> {
        BundleParts {
            manifest: self.manifest,
            storage_record: self.storage_record,
            ots_anchors: self.ots_anchors,
            tsa_anchors: self.tsa_anchors,
            receipt: self.receipt,
            covered_reveals: self.covered_reveals,
            noncovered_reveals: self.noncovered_reveals,
            touched_files: self.touched_files,
            full_reveals: self.full_reveals,
        }
    }

    /// The **exact** bytes of the embedded plaintext manifest envelope,
    /// borrowed from the bundle input — the pre-image of `anchor_digest`
    /// (spec line 75) and the input F9's layer 2 decodes.
    ///
    /// Opaque here by D78: this layer never opens it.
    #[must_use]
    pub const fn manifest_bytes(&self) -> &'b [u8] {
        self.manifest
    }

    /// The manifest's storage triple.
    #[must_use]
    pub const fn storage_record(&self) -> &StorageRecord {
        &self.storage_record
    }

    /// OTS anchor artifacts, in the order the bundle carried them (their
    /// order is a builder rule backed by the seal journal, not a parse rule
    /// — registry §8).
    #[must_use]
    pub fn ots_anchors(&self) -> &[OtsAnchor] {
        &self.ots_anchors
    }

    /// TSA anchor artifacts, in wire order.
    #[must_use]
    pub fn tsa_anchors(&self) -> &[TsaAnchor] {
        &self.tsa_anchors
    }

    /// The Arbitrum receipt, if the sealer opted it in. Absence is never an
    /// error and presence is never required.
    #[must_use]
    pub const fn receipt(&self) -> Option<&ReceiptRecord> {
        self.receipt.as_ref()
    }

    /// Covered-unit reveals, strictly ascending by `unit_id`.
    #[must_use]
    pub fn covered_reveals(&self) -> &[CoveredReveal] {
        &self.covered_reveals
    }

    /// Non-covered-unit reveals, strictly ascending by `unit_id`.
    #[must_use]
    pub fn noncovered_reveals(&self) -> &[NonCoveredReveal] {
        &self.noncovered_reveals
    }

    /// Touched-file entries, strictly ascending by `file_id`.
    #[must_use]
    pub fn touched_files(&self) -> &[TouchedFile] {
        &self.touched_files
    }

    /// Full-reveal entries, strictly ascending by `file_id`.
    #[must_use]
    pub fn full_reveals(&self) -> &[FullReveal] {
        &self.full_reveals
    }

    /// Every revealed `unit_id`, in the registry's **canonical concatenation
    /// order**: `covered_reveals` ⧺ `noncovered_reveals`, i.e. section key
    /// order (registry §7.6).
    ///
    /// Recorded there as a registry fact rather than an implementation
    /// accident because R5 populates `BundleView::revealed_unit_ids` from it,
    /// and a first-duplicate report has to be deterministic. The two sections
    /// are disjoint and each strictly ascending, so the concatenation is
    /// duplicate-free — but it is *not* globally sorted, and callers that
    /// need sorted ids must sort.
    #[must_use]
    pub fn revealed_unit_ids(&self) -> Vec<u64> {
        self.covered_reveals
            .iter()
            .map(CoveredReveal::unit_id)
            .chain(
                self.noncovered_reveals
                    .iter()
                    .map(NonCoveredReveal::unit_id),
            )
            .collect()
    }

    /// Decode a bundle **through F10's version dispatch** — layer 1 of three
    /// (registry §7.6.3).
    ///
    /// The discriminant (registry §7.6 key 0) is read first, by
    /// [`crate::format::peek_format_version`], and the matching row of the
    /// `version -> decoder` table runs; a version with no row is
    /// [`BundleError::UnsupportedFormatVersion`] and nothing else. Unlike
    /// the manifest body's, this discriminant is a top-level key of the file
    /// itself, so it is readable from the first bytes — an unsupported
    /// bundle is rejected before any section is walked.
    ///
    /// The embedded manifest is **not** decoded here (D78), and its version
    /// is a separate discriminant with a separate rejection. F9's
    /// `SealProof::decode` composes layers 2 and 3 on top.
    ///
    /// # The size cap runs first (F11 / decision D10 §5)
    ///
    /// `input.len() > MAX_BUNDLE_BYTES` is the **first statement**, before the
    /// version peek and before any decoder is constructed. It is the one O(1)
    /// check in the whole pipeline, so an oversized bundle costs a length
    /// comparison and nothing else — no walk, no AEAD, no hash, no signature.
    /// The precedence is deliberate and pinned by tests: an oversized bundle
    /// that *also* has non-canonical CBOR, or a bad signature, reports
    /// `bundle-too-large`.
    ///
    /// # Errors
    ///
    /// [`BundleError::InputTooLarge`] for an over-cap input;
    /// [`BundleError::UnsupportedFormatVersion`] for a version this build
    /// has no decoder for; otherwise whatever the selected version's decoder
    /// returns — for v1, [`BundleError::Cbor`] for canonicality failures at
    /// this layer plus every `bundle-*` schema class.
    pub fn decode(input: &'b [u8]) -> Result<Self, BundleError> {
        let len = input.len() as u64;
        if len > MAX_BUNDLE_BYTES {
            return Err(BundleError::InputTooLarge {
                len,
                cap: MAX_BUNDLE_BYTES,
            });
        }
        VersionDispatch::v1_only(FORMAT_VERSION_V1, Self::decode_v1).decode(input)
    }

    /// Strict-decode a **v1** bundle.
    ///
    /// Reachable only with a [`V1`] witness, i.e. only from version dispatch
    /// (F10) — so no future version can widen or otherwise disturb this
    /// path. That is the structural half of MVP-SPEC.md line 123.
    ///
    /// Every read goes through the F3 strict reader and every item is read
    /// *typed*, so this pass is simultaneously the canonicality pass; there
    /// is no skipped subtree and no second walk. `finish` rejects trailing
    /// bytes, so [`Self::manifest_bytes`] and the sections together account
    /// for the whole input.
    fn decode_v1(admitted: V1<'b>) -> Result<Self, BundleError> {
        const MAP: BundleMapId = BundleMapId::Bundle;
        let input = admitted.bytes();
        let mut d = CanonicalDecoder::new(input);
        let mut reader = d.map().map_err(cbor)?;

        let mut format_version: Option<u64> = None;
        let mut manifest: Option<&'b [u8]> = None;
        let mut storage_record: Option<StorageRecord> = None;
        let mut ots_anchors: Option<Vec<OtsAnchor>> = None;
        let mut tsa_anchors: Option<Vec<TsaAnchor>> = None;
        let mut receipt: Option<ReceiptRecord> = None;
        let mut covered_reveals: Option<Vec<CoveredReveal>> = None;
        let mut noncovered_reveals: Option<Vec<NonCoveredReveal>> = None;
        let mut touched_files: Option<Vec<TouchedFile>> = None;
        let mut full_reveals: Option<Vec<FullReveal>> = None;

        while let Some(k) = reader.next_key(&mut d).map_err(cbor)? {
            admit_key(MAP, k)?;
            match k {
                key::bundle::FORMAT_VERSION => {
                    let found = d.u64().map_err(cbor)?;
                    // Dispatch already read this value and selected this
                    // decoder for it; re-checking guards against the peek
                    // and the schema pass ever disagreeing (see
                    // `crate::format`).
                    if found != FORMAT_VERSION_V1 {
                        return Err(BundleError::UnsupportedFormatVersion {
                            found,
                            supported: SUPPORTED_VERSIONS,
                        });
                    }
                    format_version = Some(found);
                }
                // The zero-copy seam: a sub-slice of `input`, never a copy.
                key::bundle::MANIFEST => manifest = Some(d.bytes().map_err(cbor)?),
                key::bundle::STORAGE_RECORD => {
                    storage_record = Some(StorageRecord::decode(&mut d)?)
                }
                key::bundle::OTS_ANCHORS => {
                    ots_anchors = Some(decode_section(
                        &mut d,
                        BundleListKind::OtsAnchors,
                        OtsAnchor::decode,
                    )?);
                }
                key::bundle::TSA_ANCHORS => {
                    tsa_anchors = Some(decode_section(
                        &mut d,
                        BundleListKind::TsaAnchors,
                        TsaAnchor::decode,
                    )?);
                }
                key::bundle::RECEIPT => receipt = Some(ReceiptRecord::decode(&mut d)?),
                key::bundle::COVERED_REVEALS => {
                    covered_reveals = Some(decode_section(
                        &mut d,
                        BundleListKind::CoveredReveals,
                        CoveredReveal::decode,
                    )?);
                }
                key::bundle::NONCOVERED_REVEALS => {
                    noncovered_reveals = Some(decode_section(
                        &mut d,
                        BundleListKind::NonCoveredReveals,
                        NonCoveredReveal::decode,
                    )?);
                }
                key::bundle::TOUCHED_FILES => {
                    touched_files = Some(decode_section(
                        &mut d,
                        BundleListKind::TouchedFiles,
                        TouchedFile::decode,
                    )?);
                }
                key::bundle::FULL_REVEALS => {
                    full_reveals = Some(decode_section(
                        &mut d,
                        BundleListKind::FullReveals,
                        FullReveal::decode,
                    )?);
                }
                other => return Err(unhandled_assigned_key(MAP, other)),
            }
        }
        d.finish().map_err(cbor)?;

        // The discriminant must be present. A bundle with no version field
        // is *malformed*, not *unsupported* — F10 keeps the two claims
        // separate, so this stays `bundle-missing-key`.
        format_version.ok_or(missing(MAP, key::bundle::FORMAT_VERSION))?;

        Self::new(BundleParts {
            manifest: manifest.ok_or(missing(MAP, key::bundle::MANIFEST))?,
            storage_record: storage_record.ok_or(missing(MAP, key::bundle::STORAGE_RECORD))?,
            ots_anchors: ots_anchors.ok_or(missing(MAP, key::bundle::OTS_ANCHORS))?,
            tsa_anchors: tsa_anchors.ok_or(missing(MAP, key::bundle::TSA_ANCHORS))?,
            receipt,
            covered_reveals: covered_reveals.ok_or(missing(MAP, key::bundle::COVERED_REVEALS))?,
            noncovered_reveals: noncovered_reveals
                .ok_or(missing(MAP, key::bundle::NONCOVERED_REVEALS))?,
            touched_files: touched_files.ok_or(missing(MAP, key::bundle::TOUCHED_FILES))?,
            full_reveals: full_reveals.ok_or(missing(MAP, key::bundle::FULL_REVEALS))?,
        })
    }
}

/// Decode a definite-length array of entries under F11's cap and clamp
/// (decision D10 §4). **Every** array head in this module goes through here.
///
/// The order is frozen, because it fixes tamper-row precedence:
///
/// 1. `d.array()` — head canonicality, so a non-shortest length head beats
///    every cap code with `cbor-non-shortest-length`;
/// 2. the cap on the **claimed** count, before a single element is read —
///    the rejecting input is an array head and nothing else, so a hostile
///    bundle is refused in O(1) and long before any crypto;
/// 3. `Vec::with_capacity(clamped_capacity::<T>(claimed, d.remaining()))` — by
///    this point `claimed <= cap`, so the allocation is bounded by
///    `min(cap, remaining_input)`. The `::<T>` is load-bearing (F30): the
///    clamp divides the remaining **bytes** by the element width, so the
///    reservation is bounded by the input in bytes and not merely in
///    elements;
/// 4. decode elements (the loop was always bounded by input consumption:
///    each element costs ≥1 byte or errors).
fn decode_section<T>(
    d: &mut CanonicalDecoder<'_>,
    list: BundleListKind,
    mut decode_one: impl FnMut(&mut CanonicalDecoder<'_>) -> Result<T, BundleError>,
) -> Result<Vec<T>, BundleError> {
    let claimed = d.array().map_err(cbor)?;
    let cap = list.cap();
    if claimed > cap {
        return Err(BundleError::ListTooLong { list, claimed, cap });
    }
    let mut out = Vec::with_capacity(clamped_capacity::<T>(claimed, d.remaining()));
    for _ in 0..claimed {
        out.push(decode_one(d)?);
    }
    Ok(out)
}

/// Read an opaque foreign artifact `bstr` under its frozen byte cap
/// (decision D10 §1 rows 16–19).
///
/// The length is checked on the **borrowed** slice, before the one `to_vec`,
/// so an over-cap artifact never drives a copy. F3 has already refused a
/// claimed length exceeding the remaining input, so the borrow itself is
/// bounded by the attacker's own bytes.
fn decode_opaque(
    d: &mut CanonicalDecoder<'_>,
    field: OpaqueField,
) -> Result<OpaqueBytes, BundleError> {
    let bytes = d.bytes().map_err(cbor)?;
    let cap = field.cap();
    let len = bytes.len() as u64;
    if len > cap {
        return Err(BundleError::ArtifactTooLarge { field, len, cap });
    }
    Ok(OpaqueBytes::from_vec(bytes.to_vec()))
}

// ---------------------------------------------------------------------------
// encode (F9)
// ---------------------------------------------------------------------------
//
// Emission goes through F2's closure-scoped builders, so non-canonical
// output is unrepresentable: `MapEncoder` sorts its entries at map close and
// rejects a repeated key, and every length/integer head is shortest-form by
// construction. Call sites still list keys in ascending order — readable, and
// it makes a missing key visible as a gap.
//
// Determinism (F9 accept) is therefore a property of the *section order plus
// the list order*, and every parse-ordered list was already validated
// ascending on the way in. The one unsorted bundle list — the two anchor
// sections — is emitted in the order it was decoded or built, which is
// registry §8's builder rule: "the same logical bundle always produces
// identical bytes" holds **per builder state**, not per logical content. A
// bundle rebuilt from a different anchor capture order is a different byte
// string and neither is wrong.

impl StorageRecord {
    fn encode_into(&self, m: &mut MapEncoder) -> Result<(), EncodeError> {
        m.entry(key::storage_record::ADDRESS, |e| {
            e.bytes(self.address.as_bytes())
        })?;
        m.entry(key::storage_record::NONCE, |e| {
            e.bytes(self.nonce.as_bytes())
        })?;
        m.entry(key::storage_record::K_M, |e| e.bytes(self.k_m.as_bytes()))
    }
}

impl OtsAnchor {
    fn encode_into(&self, m: &mut MapEncoder) -> Result<(), EncodeError> {
        m.entry(key::ots_anchor::STATUS, |e| e.u64(self.status.to_wire()))?;
        m.entry(key::ots_anchor::OTS, |e| e.bytes(self.ots.as_slice()))?;
        // D79: the group is emitted whole or not at all — `Option` is what
        // makes "two of three" unrepresentable on the way out as well as in.
        if let Some(upgrade) = &self.upgrade {
            m.entry(key::ots_anchor::BLOCK_HEIGHT, |e| {
                e.u64(upgrade.block_height())
            })?;
            m.entry(key::ots_anchor::BLOCK_HEADER, |e| {
                e.bytes(upgrade.block_header())
            })?;
            m.entry(key::ots_anchor::FETCH_DATE, |e| e.u64(upgrade.fetch_date()))?;
        }
        Ok(())
    }
}

impl TsaAnchor {
    fn encode_into(&self, m: &mut MapEncoder) -> Result<(), EncodeError> {
        m.entry(key::tsa_anchor::STATUS, |e| e.u64(self.status.to_wire()))?;
        m.entry(key::tsa_anchor::TOKEN, |e| e.bytes(self.token.as_slice()))?;
        m.entry(key::tsa_anchor::INTERMEDIATES, |e| {
            e.array(|a| {
                for cert in &self.intermediates {
                    a.item(|e| e.bytes(cert.as_slice()))?;
                }
                Ok(())
            })
        })?;
        m.entry(key::tsa_anchor::FETCH_DATE, |e| e.u64(self.fetch_date))?;
        Ok(())
    }
}

impl ReceiptRecord {
    fn encode_into(&self, m: &mut MapEncoder) -> Result<(), EncodeError> {
        m.entry(key::receipt::TX_HASHES, |e| {
            e.array(|a| {
                for hash in &self.tx_hashes {
                    a.item(|e| e.bytes(hash))?;
                }
                Ok(())
            })
        })?;
        m.entry(key::receipt::BLOCK_NUMBER, |e| e.u64(self.block_number))?;
        m.entry(key::receipt::PAYLOAD, |e| e.bytes(self.payload.as_slice()))
    }
}

impl CoverEntry {
    fn encode_into(&self, e: &mut CanonicalEncoder) -> Result<(), EncodeError> {
        e.array(|a| {
            a.item(|e| e.u64(u64::from(self.address.level())))?;
            a.item(|e| e.u64(self.address.index()))?;
            a.item(|e| e.bytes(self.seed.as_bytes()))
        })
    }
}

impl PathNode {
    fn encode_into(&self, e: &mut CanonicalEncoder) -> Result<(), EncodeError> {
        e.array(|a| {
            a.item(|e| e.u64(u64::from(self.address.level())))?;
            a.item(|e| e.u64(self.address.index()))?;
            a.item(|e| e.bytes(self.hash.as_bytes()))
        })
    }
}

impl CoveredReveal {
    fn encode_into(&self, m: &mut MapEncoder) -> Result<(), EncodeError> {
        m.entry(key::covered_reveal::UNIT_ID, |e| e.u64(self.unit_id))?;
        m.entry(key::covered_reveal::K_U, |e| e.bytes(self.k_u.as_bytes()))?;
        m.entry(key::covered_reveal::CIPHERTEXT, |e| {
            e.bytes(self.ciphertext.as_slice())
        })?;
        m.entry(key::covered_reveal::COVER, |e| {
            e.array(|a| {
                for entry in &self.cover {
                    a.item(|e| entry.encode_into(e))?;
                }
                Ok(())
            })
        })?;
        m.entry(key::covered_reveal::PATHS, |e| {
            e.array(|a| {
                for node in &self.paths {
                    a.item(|e| node.encode_into(e))?;
                }
                Ok(())
            })
        })
    }
}

impl NonCoveredReveal {
    fn encode_into(&self, m: &mut MapEncoder) -> Result<(), EncodeError> {
        m.entry(key::noncovered_reveal::UNIT_ID, |e| e.u64(self.unit_id))?;
        m.entry(key::noncovered_reveal::K_U, |e| {
            e.bytes(self.k_u.as_bytes())
        })?;
        m.entry(key::noncovered_reveal::CIPHERTEXT, |e| {
            e.bytes(self.ciphertext.as_slice())
        })?;
        m.entry(key::noncovered_reveal::UNIT_SALT, |e| {
            e.bytes(self.unit_salt.as_bytes())
        })
    }
}

impl TouchedFile {
    fn encode_into(&self, m: &mut MapEncoder) -> Result<(), EncodeError> {
        m.entry(key::touched_file::FILE_ID, |e| e.u64(self.file_id))?;
        // The tstr's bytes are the `path_commit` pre-image, so they are
        // emitted exactly as held: no normalization, ever (registry §7.13).
        m.entry(key::touched_file::PATH, |e| e.str(&self.path))?;
        m.entry(key::touched_file::PATH_SALT, |e| {
            e.bytes(self.path_salt.as_bytes())
        })
    }
}

impl FullReveal {
    fn encode_into(&self, m: &mut MapEncoder) -> Result<(), EncodeError> {
        m.entry(key::full_reveal::FILE_ID, |e| e.u64(self.file_id))?;
        m.entry(key::full_reveal::FILE_SALT, |e| {
            e.bytes(self.file_salt.as_bytes())
        })?;
        if let Some(s_root) = &self.s_root {
            m.entry(key::full_reveal::S_ROOT, |e| e.bytes(s_root.as_bytes()))?;
        }
        Ok(())
    }
}

impl BundleV1<'_> {
    fn encode_into(&self, m: &mut MapEncoder) -> Result<(), EncodeError> {
        m.entry(key::bundle::FORMAT_VERSION, |e| e.u64(FORMAT_VERSION_V1))?;
        m.entry(key::bundle::MANIFEST, |e| e.bytes(self.manifest))?;
        m.entry(key::bundle::STORAGE_RECORD, |e| {
            e.map(|sm| self.storage_record.encode_into(sm))
        })?;
        m.entry(key::bundle::OTS_ANCHORS, |e| {
            encode_section(e, &self.ots_anchors, OtsAnchor::encode_into)
        })?;
        m.entry(key::bundle::TSA_ANCHORS, |e| {
            encode_section(e, &self.tsa_anchors, TsaAnchor::encode_into)
        })?;
        if let Some(receipt) = &self.receipt {
            m.entry(key::bundle::RECEIPT, |e| {
                e.map(|rm| receipt.encode_into(rm))
            })?;
        }
        m.entry(key::bundle::COVERED_REVEALS, |e| {
            encode_section(e, &self.covered_reveals, CoveredReveal::encode_into)
        })?;
        m.entry(key::bundle::NONCOVERED_REVEALS, |e| {
            encode_section(e, &self.noncovered_reveals, NonCoveredReveal::encode_into)
        })?;
        m.entry(key::bundle::TOUCHED_FILES, |e| {
            encode_section(e, &self.touched_files, TouchedFile::encode_into)
        })?;
        m.entry(key::bundle::FULL_REVEALS, |e| {
            encode_section(e, &self.full_reveals, FullReveal::encode_into)
        })
    }
}

/// Emit one bundle section as an array of maps, in stored order.
fn encode_section<T>(
    e: &mut CanonicalEncoder,
    entries: &[T],
    encode_one: impl Fn(&T, &mut MapEncoder) -> Result<(), EncodeError>,
) -> Result<(), EncodeError> {
    e.array(|a| {
        for entry in entries {
            a.item(|e| e.map(|m| encode_one(entry, m)))?;
        }
        Ok(())
    })
}

/// Encode a validated bundle to its canonical CBOR bytes — the reveal-side
/// entry point, and the API surface R's M3 bundle builder consumes.
///
/// # Why this borrows where `encode_body` consumes
///
/// [`encode_body`](crate::manifest::encode_body) takes its body **by
/// value** — and `ManifestBodyV1` is not `Clone` outside `test-util`
/// builds — so that no verification path can re-encode a decoded
/// manifest: the manifest's bytes are hashed (`work_id`) and signed, so
/// "the bytes I received" and "the bytes I would produce" must never be
/// confusable.
///
/// A bundle is different, and the difference is structural rather than a
/// relaxation: **nothing hashes or signs a `.sealproof` as a whole**. It is
/// unsigned by design (registry §7.6.1), and the one digest that matters —
/// `anchor_digest` = SHA-256 of the embedded manifest bytes — is taken from
/// [`BundleV1::manifest_bytes`], the received sub-slice, which round-trips
/// through this function untouched. Re-encoding a bundle therefore cannot
/// change what any verdict is computed over, so a borrow is safe and lets a
/// caller re-serialize a decoded bundle (which the round-trip test does).
///
/// # The aggregate size gate (F53)
///
/// This is where `MAX_BUNDLE_BYTES` is enforced on the reveal side — the
/// residual F41 named rather than hid. Every *part* of a bundle is capped
/// at construction, but the caps are per-part: 256 OTS anchors of 1 MiB
/// each are 256 individually legal artifacts that sum past the whole-bundle
/// cap. The sum exists only once the bundle is serialized, so this is the
/// first place it can be seen.
///
/// Re-encoding a *decoded* bundle can never trip it: that bundle's input
/// already passed the identical check as the first statement of
/// [`BundleV1::decode`], and this function reproduces those bytes.
///
/// # Errors
///
/// - [`EncodeError::TooLarge`] — the bundle exceeds
///   [`MAX_BUNDLE_BYTES`](crate::codec::caps::MAX_BUNDLE_BYTES), reported
///   with the decode path's own `bundle-too-large` code.
/// - The three F2 caller-bug variants (duplicate map key, a scope that did
///   not emit exactly one item, a rejecting sink); none is reachable for a
///   validated bundle — the keys are registry constants and every scope
///   emits one item — so those are totality `Err`s, never panic paths.
pub fn encode_bundle(bundle: &BundleV1<'_>) -> Result<Vec<u8>, EncodeError> {
    let encoded = encode_item(|e| e.map(|m| bundle.encode_into(m)))?;
    CappedArtifact::Bundle.gate(&encoded)?;
    Ok(encoded)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **F53**: the encode-side aggregate size gate, at the boundary.
    ///
    /// The lever is the embedded manifest `bstr`, opaque at this layer
    /// (D78) and uncapped here on purpose — the manifest's own cap belongs
    /// to layer 2. Every section is empty and every part is legal; only the
    /// serialization is over. The boundary is hit exactly: for a payload of
    /// 2^16 bytes or more the `bstr` head is five bytes, so bundle length
    /// is affine in payload length and one probe encode fixes the offset.
    ///
    /// One 256 MiB buffer serves both directions (a sub-slice for at-cap,
    /// the whole for cap+1), which is what keeps this affordable; the F15
    /// `bundle-oversized` fixture already allocates the same order.
    ///
    /// Red before the gate landed: the cap+1 bundle encoded fine at
    /// 268 435 457 bytes. Planted-fault direction: delete the
    /// `CappedArtifact::Bundle.gate` line and this goes red again, with
    /// that message.
    #[test]
    fn encode_refuses_a_bundle_one_byte_over_the_aggregate_cap() {
        use crate::codec::CappedArtifact;
        use crate::codec::caps::MAX_BUNDLE_BYTES;

        fn parts(manifest: &[u8]) -> BundleParts<'_> {
            BundleParts {
                manifest,
                storage_record: StorageRecord::new(
                    ContentAddress::from_bytes([0xA0; 32]),
                    Nonce24::from_bytes([0xA1; 24]),
                    Key32::from_bytes([0xA2; 32]),
                ),
                ots_anchors: Vec::new(),
                tsa_anchors: Vec::new(),
                receipt: None,
                covered_reveals: Vec::new(),
                noncovered_reveals: Vec::new(),
                touched_files: Vec::new(),
                full_reveals: Vec::new(),
            }
        }
        fn encode_with(manifest: &[u8]) -> Result<Vec<u8>, EncodeError> {
            encode_bundle(&BundleV1::new(parts(manifest)).expect("sections are empty"))
        }

        const PROBE: usize = 65_536;
        let probe_len = encode_with(&vec![0xA5u8; PROBE])
            .expect("the probe bundle is far under the cap")
            .len() as u64;
        let at_cap_manifest = PROBE as u64 + (MAX_BUNDLE_BYTES - probe_len);

        let manifest = vec![0xA5u8; at_cap_manifest as usize + 1];
        let at_cap = encode_with(&manifest[..at_cap_manifest as usize])
            .expect("a bundle of exactly MAX_BUNDLE_BYTES is admitted");
        assert_eq!(at_cap.len() as u64, MAX_BUNDLE_BYTES);
        drop(at_cap);

        let err = encode_with(&manifest).expect_err("one byte over the cap is refused");
        assert_eq!(
            err,
            EncodeError::TooLarge {
                artifact: CappedArtifact::Bundle,
                len: MAX_BUNDLE_BYTES + 1,
                cap: MAX_BUNDLE_BYTES,
            }
        );

        // The code is the *decode* path's, taken from the decode path's own
        // variant rather than spelled again — so the two can never drift
        // and no code is minted (D30; the universe stays 194).
        assert_eq!(
            err.code(),
            Some(
                BundleError::InputTooLarge {
                    len: MAX_BUNDLE_BYTES + 1,
                    cap: MAX_BUNDLE_BYTES,
                }
                .code()
            )
        );
    }

    fn seed(byte: u8) -> Seed32 {
        Seed32::from_bytes([byte; 32])
    }

    /// F10's cross-parser guard, bundle side: the v1 decoder re-checks the
    /// discriminant dispatch read, so the peek and the schema pass can never
    /// silently disagree about the first key. Only reachable by minting the
    /// witness directly — production code has no such constructor.
    #[test]
    fn the_v1_decoder_rechecks_the_discriminant_dispatch_read() {
        let bundle = encode_item(|e| {
            e.map(|m| {
                m.entry(key::bundle::FORMAT_VERSION, |e| e.u64(2))?;
                m.entry(key::bundle::MANIFEST, |e| e.bytes(&[0u8]))
            })
        })
        .expect("encode");
        assert!(matches!(
            BundleV1::decode_v1(V1::admit_for_test(&bundle)),
            Err(BundleError::UnsupportedFormatVersion { found: 2, .. })
        ));
    }

    fn address(level: u8, index: u64) -> NodeAddress {
        NodeAddress::try_new(level, index).expect("test address is in bounds")
    }

    /// The ciphertext gate's two defects and their **checked order**: a
    /// length that violates both reports `TooShort`, which is what lets a
    /// tamper row pin one code.
    #[test]
    fn ciphertext_shape_gate_has_a_fixed_check_order() {
        assert!(check_ciphertext_shape(272).is_ok());
        assert!(check_ciphertext_shape(272 + 256).is_ok());

        // Violates both rules: 271 < 272, and 271 % 256 == 15.
        let both = check_ciphertext_shape(271).expect_err("must reject");
        assert_eq!(both.code(), "bundle-ciphertext-too-short");

        // Long enough, wrong residue.
        let residue = check_ciphertext_shape(273).expect_err("must reject");
        assert_eq!(residue.code(), "bundle-ciphertext-length-residue");

        // The empty ciphertext is not a special case — it is too short.
        assert_eq!(
            check_ciphertext_shape(0).expect_err("must reject").code(),
            "bundle-ciphertext-too-short"
        );
    }

    /// F41: the D10 caps bind the **direct-construction** path with the
    /// decode path's own codes, so a builder cannot assemble an anchor or
    /// receipt whose encoding no v1 decoder accepts. Planted-fault
    /// direction: neuter `check_section_cap`/`check_opaque_cap` and this
    /// test goes red. At-cap acceptance stays with `tests/parser_caps.rs`.
    #[test]
    fn anchor_and_receipt_construction_enforces_the_decode_side_caps() {
        let over_ots = OpaqueBytes::from_vec(vec![0x4F; (OpaqueField::Ots.cap() + 1) as usize]);
        let err = OtsAnchor::new(AnchorStatus::Pending, over_ots, None).expect_err("over cap");
        assert_eq!(err.code(), "bundle-ots-too-large");

        let over_token =
            OpaqueBytes::from_vec(vec![0x30; (OpaqueField::TsaToken.cap() + 1) as usize]);
        let err =
            TsaAnchor::new(AnchorStatus::Proven, over_token, Vec::new(), 0).expect_err("over cap");
        assert_eq!(err.code(), "bundle-tsa-token-too-large");

        let token = || OpaqueBytes::from_vec(vec![0x30; 8]);
        let too_many = (0..=BundleListKind::Intermediates.cap())
            .map(|_| OpaqueBytes::from_vec(vec![0xC0; 8]))
            .collect();
        let err = TsaAnchor::new(AnchorStatus::Proven, token(), too_many, 0).expect_err("over cap");
        assert_eq!(err.code(), "bundle-too-many-intermediates");

        let big_cert =
            OpaqueBytes::from_vec(vec![0xC0; (OpaqueField::Certificate.cap() + 1) as usize]);
        let err =
            TsaAnchor::new(AnchorStatus::Proven, token(), vec![big_cert], 0).expect_err("over cap");
        assert_eq!(err.code(), "bundle-cert-too-large");

        let payload = || OpaqueBytes::from_vec(vec![1, 2]);
        let hashes = vec![[0xE0; 32]; (BundleListKind::TxHashes.cap() + 1) as usize];
        let err = ReceiptRecord::new(hashes, 0, payload()).expect_err("over cap");
        assert_eq!(err.code(), "bundle-too-many-tx-hashes");

        let big_payload =
            OpaqueBytes::from_vec(vec![1; (OpaqueField::ReceiptPayload.cap() + 1) as usize]);
        let err = ReceiptRecord::new(vec![[0xE0; 32]], 0, big_payload).expect_err("over cap");
        assert_eq!(err.code(), "bundle-receipt-payload-too-large");
    }

    /// F41, reveal tuples: over-cap `cover`/`paths` are refused at
    /// construction with the decode path's codes, ahead of the shape,
    /// emptiness and ascent rules — mirroring decode's total order, where
    /// both caps fire at their array heads before `new` runs.
    #[test]
    fn covered_reveal_construction_enforces_the_cover_and_path_caps() {
        let k = || Key32::from_bytes([0x11; 32]);
        let ct = || OpaqueBytes::from_vec(vec![0x22; 272]);

        // Every entry shares one address, so the ascent rule would also
        // reject these parts — the cap must win, as on decode.
        let over_cover = (0..=BundleListKind::Cover.cap())
            .map(|_| CoverEntry::new(address(1, 0), seed(0x31)))
            .collect();
        let err = CoveredReveal::new(0, k(), ct(), over_cover, Vec::new()).expect_err("over cap");
        assert_eq!(err.code(), "bundle-too-many-cover-entries");

        let one_cover = vec![CoverEntry::new(address(1, 0), seed(0x31))];
        let over_paths = (0..=BundleListKind::Paths.cap())
            .map(|_| PathNode::new(address(1, 0), NodeHash32::from_bytes([0x41; 32])))
            .collect();
        let err = CoveredReveal::new(0, k(), ct(), one_cover, over_paths).expect_err("over cap");
        assert_eq!(err.code(), "bundle-too-many-path-nodes");
    }

    /// F41, bundle sections: an over-cap section is refused at
    /// construction with the decode path's code, ahead of the ordering and
    /// cross-section rules — mirroring decode's total order, where the cap
    /// fires at the section's array head before `new` runs.
    #[test]
    fn bundle_construction_enforces_the_section_caps_ahead_of_ordering_rules() {
        fn empty_parts(manifest: &[u8]) -> BundleParts<'_> {
            BundleParts {
                manifest,
                storage_record: StorageRecord::new(
                    ContentAddress::from_bytes([0xA0; 32]),
                    Nonce24::from_bytes([0xA1; 24]),
                    Key32::from_bytes([0xA2; 32]),
                ),
                ots_anchors: Vec::new(),
                tsa_anchors: Vec::new(),
                receipt: None,
                covered_reveals: Vec::new(),
                noncovered_reveals: Vec::new(),
                touched_files: Vec::new(),
                full_reveals: Vec::new(),
            }
        }
        let manifest = [0xA5u8; 4];

        // Every entry shares file_id 0 and no touched file exists, so the
        // ascent rule *and* the cross-section rule would both reject these
        // parts — the cap must win, as it does on decode.
        let mut parts = empty_parts(&manifest);
        parts.full_reveals = (0..=BundleListKind::FullReveals.cap())
            .map(|_| FullReveal::new(0, Salt16::from_bytes([0x81; 16]), None))
            .collect();
        let err = BundleV1::new(parts).expect_err("over cap");
        assert_eq!(err.code(), "bundle-too-many-full-reveals");

        let mut parts = empty_parts(&manifest);
        parts.ots_anchors = (0..=BundleListKind::OtsAnchors.cap())
            .map(|_| {
                OtsAnchor::new(
                    AnchorStatus::Pending,
                    OpaqueBytes::from_vec(vec![0x4F; 4]),
                    None,
                )
                .expect("tiny anchor is under the caps")
            })
            .collect();
        let err = BundleV1::new(parts).expect_err("over cap");
        assert_eq!(err.code(), "bundle-too-many-ots-anchors");
    }

    /// Strict ascent rejects both a repeat and an inversion, with the same
    /// code per list (registry §8).
    #[test]
    fn id_ascent_rejects_repeats_and_inversions() {
        assert!(check_ascending_ids(OrderedList::TouchedFiles, [0, 1, 7]).is_ok());
        assert!(check_ascending_ids(OrderedList::TouchedFiles, []).is_ok());

        let repeat = check_ascending_ids(OrderedList::TouchedFiles, [1, 1]).expect_err("repeat");
        assert_eq!(repeat.code(), "bundle-unsorted-touched-files");
        let inverted =
            check_ascending_ids(OrderedList::TouchedFiles, [2, 1]).expect_err("inverted");
        // One code per list, so the two failure modes are one tamper row.
        assert_eq!(inverted.code(), repeat.code());
    }

    /// Leaf-interval ordering is decidable **without** the file's depth
    /// `d` (registry §8): comparing at any common `D >= max(level)` gives the
    /// same verdict as comparing true starts.
    #[test]
    fn address_ascent_is_depth_independent() {
        // Depth 3 layout: (2,0) covers [0,2), (3,2) covers [2,3),
        // (2,2) covers [4,6) — ascending.
        let ascending = [address(2, 0), address(3, 2), address(2, 2)];
        assert!(check_ascending_addresses(OrderedList::Cover, ascending).is_ok());

        // The same set with the last two swapped is not.
        let swapped = [address(2, 0), address(2, 2), address(3, 2)];
        let err = check_ascending_addresses(OrderedList::Cover, swapped).expect_err("unsorted");
        assert_eq!(err.code(), "bundle-unsorted-cover");

        // A repeat is an equal start, which strict ascent rejects too.
        let repeat = [address(1, 1), address(1, 1)];
        assert_eq!(
            check_ascending_addresses(OrderedList::Paths, repeat)
                .expect_err("repeat")
                .code(),
            "bundle-unsorted-paths"
        );

        // Deep addresses do not overflow: level 64 with a maximal index is
        // computed in u128 (registry §8).
        let deep = [address(64, u64::MAX - 1), address(64, u64::MAX)];
        assert!(check_ascending_addresses(OrderedList::Cover, deep).is_ok());
    }

    /// The scaled start really is the true start when the common depth is
    /// the tree's depth — the property the pairwise comparison relies on.
    #[test]
    fn scaled_interval_start_matches_the_true_start() {
        // d = 3: (1, 1) covers [4, 8); (3, 5) covers [5, 6).
        assert_eq!(scaled_interval_start(address(1, 1), 3), 4);
        assert_eq!(scaled_interval_start(address(3, 5), 3), 5);
        assert_eq!(scaled_interval_start(address(0, 0), 3), 0);
        // Rescaling by a common factor preserves the comparison.
        assert!(scaled_interval_start(address(1, 1), 3) < scaled_interval_start(address(3, 5), 3));
        assert!(scaled_interval_start(address(1, 1), 1) < scaled_interval_start(address(3, 5), 3));
    }

    /// A covered reveal rejects an empty cover: a covered unit has at least
    /// one leaf, and the empty unit is never covered (registry §7.11).
    #[test]
    fn covered_reveal_rejects_an_empty_cover() {
        let err = CoveredReveal::new(
            0,
            Key32::from_bytes([7; 32]),
            OpaqueBytes::from_vec(vec![0; 272]),
            Vec::new(),
            Vec::new(),
        )
        .expect_err("empty cover");
        assert_eq!(err.code(), "bundle-empty-cover");
    }

    /// `paths` may legitimately be empty (the unit spans the whole grid);
    /// only the *exactly* is R's.
    #[test]
    fn covered_reveal_accepts_empty_paths() {
        let reveal = CoveredReveal::new(
            3,
            Key32::from_bytes([7; 32]),
            OpaqueBytes::from_vec(vec![0; 272]),
            vec![CoverEntry::new(address(0, 0), seed(1))],
            Vec::new(),
        )
        .expect("whole-grid unit");
        assert_eq!(reveal.unit_id(), 3);
        assert!(reveal.paths().is_empty());
        assert_eq!(reveal.cover().len(), 1);
    }

    /// A receipt with no transaction hashes is malformed, not "no payment".
    #[test]
    fn receipt_rejects_an_empty_tx_hash_list() {
        let err = ReceiptRecord::new(Vec::new(), 42, OpaqueBytes::from_vec(vec![1, 2, 3]))
            .expect_err("empty tx_hashes");
        assert_eq!(err.code(), "bundle-empty-tx-hashes");
    }

    /// `OpaqueBytes` renders its length, never its contents (project rule 6
    /// applied to disclosed-but-bulky material).
    #[test]
    fn opaque_bytes_debug_hides_contents() {
        let payload = OpaqueBytes::from_vec(vec![0xAB; 5]);
        assert_eq!(format!("{payload:?}"), "OpaqueBytes(5 bytes)");
        assert_eq!(payload.len(), 5);
        assert!(!payload.is_empty());
        assert!(OpaqueBytes::from_vec(Vec::new()).is_empty());
    }

    /// Disclosed key material never reaches a `Debug` rendering, even when
    /// a whole reveal is printed (project rule 6).
    #[test]
    fn reveal_debug_redacts_disclosed_key_material() {
        let reveal = NonCoveredReveal::new(
            1,
            Key32::from_bytes([0xC1; 32]),
            OpaqueBytes::from_vec(vec![0xC2; 272]),
            Salt16::from_bytes([0xC3; 16]),
        )
        .expect("valid reveal");
        let rendered = format!("{reveal:?}");
        assert!(rendered.contains("<redacted>"), "{rendered}");
        assert!(!rendered.contains("193"), "{rendered}");
        assert!(!rendered.contains("195"), "{rendered}");
    }
}
