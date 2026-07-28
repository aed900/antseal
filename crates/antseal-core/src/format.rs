//! Format versioning (F10): the version discriminant is read **first**, and
//! every schema decoder is reached through a `version -> decoder` table.
//!
//! MVP-SPEC.md line 123 (format stability), line 98 (the manifest body's
//! `format_version` field), line 153 (M0). The wire rows are registry §7.2
//! key 0 (manifest body) and §7.6 key 0 (bundle) —
//! `docs/format/registry-v1.md` and its machine mirror.
//!
//! # The line-123 stability contract (normative)
//!
//! > *every released manifest/bundle format version remains verifiable by
//! > all future CLI and page releases; per-version golden vectors are
//! > retained in CI indefinitely; the hosted page supports all released
//! > versions.*
//!
//! Three obligations follow, and this module exists to make the first two
//! mechanical rather than aspirational:
//!
//! 1. **A released version's byte behaviour never changes.** Not its key
//!    numbers, not its lengths, not its rejection classes. A change to any
//!    of those is a *new version*, never an edit to an old one.
//! 2. **A future release still decodes every older version.** Support is
//!    added by appending a row to the table below, never by widening the v1
//!    decoder to be lenient about something v2 introduced.
//! 3. **The evidence is retained.** Each version's golden vectors live in
//!    `testdata/vectors/v<n>/` and are executed by every future release's
//!    CI — the retention half is Q's (Q6's per-version `FROZEN.sha256`
//!    freeze + must-exist manifest, Q14's freeze gate). See
//!    `testdata/vectors/README.md` and [the index contract](#the-per-version-vector-index).
//!
//! # Why the freeze is structural, not a comment
//!
//! Obligation 1 is easy to state and easy to break: the v1 decoder is
//! ordinary code, and "just make it accept the new optional key too" is a
//! one-line edit that silently re-defines a permanent format. So the v1
//! decode path is fenced behind a **witness type**, [`V1`], in the spirit of
//! `LeafExactCover` (G11), `UnitBinding` (C7) and `SplitEligibleText` (G5):
//!
//! - [`V1`] has a private field and **no public constructor**. The only
//!   place in the crate that mints one is `VersionDispatch::decode`, after
//!   it has read the discriminant and found it equal to 1.
//! - Each per-version decoder entry point takes its own version's witness.
//!   `VersionDispatch`'s row is typed `fn(V1<'b>) -> …`, so a v2 decoder
//!   **cannot** be added as a second row of this table: it takes a `V2`
//!   witness, which is a different type. v2 arrives as its own witness, its
//!   own entry point and its own table — leaving every byte of the v1 path
//!   untouched by construction.
//! - Nothing outside dispatch can call a v1 decoder at all, so "v1's
//!   behaviour" is exactly "what dispatch does with a discriminant of 1".
//!
//! # Dispatch order, and why the body's version is read late
//!
//! The version field sits **inside** the body byte string, so the outer
//! manifest envelope `{0: body, 1: signatures}` must be decoded before the
//! body's discriminant can be read at all. That makes the envelope shape
//! **frozen across every format version** — it is the one map that can never
//! carry a version-specific change, because it is what you must parse in
//! order to find the version. Recorded as a registry fact in
//! `docs/format/registry-v1.md` §7.1 and §9 (F10's note in `tasks/F.md`).
//!
//! The bundle's discriminant, by contrast, is a top-level key of the bundle
//! map itself, so it is readable from the first bytes of the file.
//!
//! # Peek, then decode
//!
//! [`peek_format_version`] is a deliberately tiny second parser: it opens the
//! top-level map, reads the first key, and — only if that key is 0 with an
//! unsigned value — reports the version. It **never** reports an error.
//! Anything it cannot confidently read (not a map, empty map, first key is
//! not 0, value is not an unsigned integer, truncated input) yields `None`,
//! and dispatch hands the input to the v1 decoder so the *authoritative*
//! rejection comes from the real schema pass with its real error code and
//! position. A versionless artifact is therefore `manifest-missing-key` /
//! `bundle-missing-key`, not a version error — malformed and unsupported are
//! different claims.
//!
//! Because canonical CBOR maps have strictly ascending keys (F3), key 0 is
//! first whenever it is present, so the peek reads a constant number of
//! bytes regardless of artifact size — a hostile 100 MB bundle declaring
//! version 7 is rejected after ~4 bytes, with none of F11's per-list caps
//! reached.
//!
//! One F11 cap does run first, and deliberately: D10 §5 makes the O(1)
//! `input.len() > MAX_BUNDLE_BYTES` check the **first statement** of
//! `BundleV1::decode`, ahead of the peek. So an artifact above 256 MiB is
//! `bundle-too-large` even when it declares an unsupported version — the
//! cheapest possible rejection wins, and a v1 verifier has no basis for
//! reading a 300 MiB artifact's version field anyway. Everything under the
//! cap behaves exactly as this section describes.
//!
//! The chosen version's decoder still re-reads and re-checks the
//! discriminant from the same bytes. That is not redundant: it is the guard
//! against this module and the schema module ever disagreeing about what the
//! first key says.
//!
//! # The per-version vector index
//!
//! [`SUPPORTED_VERSIONS`] is the code side; `testdata/vectors/v<n>/INDEX.json`
//! is the data side, and `crates/antseal-core/tests/vector_index.rs` asserts
//! they agree. The index is what downstream vector-landing tasks
//! (F12/F13/G15/R9) register into; its contract is documented in
//! `testdata/vectors/README.md` ("The per-version index").

#![deny(clippy::unwrap_used)]

use core::fmt;

use crate::codec::CanonicalDecoder;

/// Every format version this build can decode, ascending.
///
/// v1 is the sole entry and the only version that has ever been released.
/// A future release appends; it never edits or removes — obligation 2 of the
/// line-123 contract.
pub const SUPPORTED_VERSIONS: &[u64] = &[1];

/// The map key carrying the format discriminant, in **both** versioned
/// top-level maps: the manifest body (registry §7.2) and the bundle
/// (registry §7.6).
///
/// Key 0 is not a coincidence — canonical maps ascend, so key 0 is the
/// first thing on the wire, which is what makes [`peek_format_version`]
/// constant-time.
pub const VERSION_KEY: u64 = 0;

/// Render a supported-version list for an error message.
///
/// Errors carry `&'static [u64]` rather than a pre-rendered string so the
/// *value* stays machine-comparable; this is only for `Display`.
#[must_use]
pub fn supported_versions_str(supported: &[u64]) -> String {
    let mut out = String::new();
    for (i, v) in supported.iter().enumerate() {
        if i > 0 {
            out.push_str(", ");
        }
        let _ = fmt::Write::write_fmt(&mut out, format_args!("v{v}"));
    }
    if out.is_empty() {
        out.push_str("(none)");
    }
    out
}

// ---------------------------------------------------------------------------
// the v1 admission witness
// ---------------------------------------------------------------------------

/// Proof that an artifact's version discriminant was read **before** any
/// schema decode and equals 1.
///
/// Private field, no public constructor: the only production path that mints
/// one is `VersionDispatch::decode`. Holding a `V1` therefore *means*
/// "dispatch selected the v1 decoder for these exact bytes", which is what
/// makes "the v1 path is frozen behind dispatch" a type-system fact rather
/// than a convention (see the module docs).
#[derive(Debug, Clone, Copy)]
pub struct V1<'b> {
    bytes: &'b [u8],
}

impl<'b> V1<'b> {
    /// Mint the witness. Private on purpose — see the type docs.
    const fn admit(bytes: &'b [u8]) -> Self {
        Self { bytes }
    }

    /// Mint a witness in a crate unit test.
    ///
    /// Exists so the "peek and the schema pass disagree" guard inside each
    /// v1 decoder is reachable from a test; production code has no such
    /// constructor.
    #[cfg(test)]
    pub(crate) const fn admit_for_test(bytes: &'b [u8]) -> Self {
        Self::admit(bytes)
    }

    /// The admitted bytes.
    #[must_use]
    pub(crate) const fn bytes(self) -> &'b [u8] {
        self.bytes
    }
}

// ---------------------------------------------------------------------------
// the version -> decoder table
// ---------------------------------------------------------------------------

/// How an error family reports "this build cannot decode that version".
///
/// Implemented by `ManifestError` and `BundleError` so dispatch can be shared
/// while each family keeps its own permanent code (D30/D78: `manifest-` and
/// `bundle-` never merge).
pub(crate) trait VersionRejection {
    /// Build the family's unsupported-version rejection.
    fn unsupported_version(found: u64, supported: &'static [u64]) -> Self;
}

/// A v1 decoder entry point: it consumes the [`V1`] admission witness, so
/// only dispatch can call it and only for bytes whose discriminant read as 1.
///
/// The alias is per-version on purpose — `V2Decoder` would be a *different*
/// alias over a different witness, which is what stops a v2 decoder from ever
/// being installed in a v1 table.
pub(crate) type V1Decoder<'b, T, E> = fn(V1<'b>) -> Result<T, E>;

/// The `version -> decoder` table for one versioned artifact.
///
/// **v1 is the sole row.** The row's type bakes in the [`V1`] witness, so
/// this table is *structurally* incapable of holding a v2 decoder — see the
/// module docs for why that is the point rather than a limitation.
pub(crate) struct VersionDispatch<'b, T, E> {
    /// The one released version and the entry point that decodes it.
    v1: (u64, V1Decoder<'b, T, E>),
}

impl<'b, T, E: VersionRejection> VersionDispatch<'b, T, E> {
    /// Build the table. `version` is the caller's own `FORMAT_VERSION_V1`
    /// constant, so the row is checked against the registry rather than
    /// against a literal repeated here.
    pub(crate) const fn v1_only(version: u64, decode: V1Decoder<'b, T, E>) -> Self {
        Self {
            v1: (version, decode),
        }
    }

    /// Read the discriminant, then decode through the matching row.
    ///
    /// A version with no row is [`VersionRejection::unsupported_version`] and
    /// nothing else — never a canonicality error and never an unknown-key
    /// error, which is F10's whole point: "this artifact is newer than this
    /// verifier" must not be reported as "this artifact is corrupt".
    pub(crate) fn decode(&self, input: &'b [u8]) -> Result<T, E> {
        let (v1_version, v1_decode) = self.v1;
        match peek_format_version(input) {
            // Confidently versioned and we have a row for it.
            Some(found) if found == v1_version => v1_decode(V1::admit(input)),
            // Confidently versioned, no row: the one thing this returns.
            Some(found) => Err(E::unsupported_version(found, SUPPORTED_VERSIONS)),
            // Not confidently versioned. The peek does not invent errors;
            // the real schema pass produces the authoritative one.
            None => v1_decode(V1::admit(input)),
        }
    }
}

/// Read the format discriminant of a versioned top-level map, or `None` if
/// the input does not confidently carry one.
///
/// Never returns an error — see the module docs ("Peek, then decode").
#[must_use]
pub fn peek_format_version(input: &[u8]) -> Option<u64> {
    let mut d = CanonicalDecoder::new(input);
    let mut reader = d.map().ok()?;
    match reader.next_key(&mut d).ok()?? {
        VERSION_KEY => d.u64().ok(),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::encode_item as encode;

    /// A canonical map `{0: version, 1: h'00'}` — the smallest thing shaped
    /// like a versioned artifact.
    fn versioned_map(version: u64) -> Vec<u8> {
        encode(|e| {
            e.map(|m| {
                m.entry(0, |e| e.u64(version))?;
                m.entry(1, |e| e.bytes(&[0u8]))
            })
        })
        .expect("encode")
    }

    #[test]
    fn peek_reads_the_discriminant_of_a_well_formed_map() {
        for v in [0u64, 1, 2, 7, u64::from(u32::MAX), u64::MAX] {
            assert_eq!(
                peek_format_version(&versioned_map(v)),
                Some(v),
                "version {v}"
            );
        }
    }

    /// The peek is *only* a peek: every shape it cannot read confidently is
    /// `None`, never a guess and never an error.
    #[test]
    fn peek_declines_rather_than_guessing() {
        // Not a map at all.
        assert_eq!(peek_format_version(&[0x01]), None);
        // Empty input.
        assert_eq!(peek_format_version(&[]), None);
        // Truncated head.
        assert_eq!(peek_format_version(&[0xa2]), None);
        // Empty map: no key 0.
        let empty = encode(|e| e.map(|_| Ok(()))).expect("encode");
        assert_eq!(peek_format_version(&empty), None);
        // First key is not 0 (canonical order, so key 0 is genuinely absent).
        let no_zero = encode(|e| e.map(|m| m.entry(1, |e| e.u64(1)))).expect("encode");
        assert_eq!(peek_format_version(&no_zero), None);
        // Key 0 present but not an unsigned integer.
        let wrong_type = encode(|e| e.map(|m| m.entry(0, |e| e.str("1")))).expect("encode");
        assert_eq!(peek_format_version(&wrong_type), None);
    }

    /// The peek stops after the first entry, so its cost does not grow with
    /// the artifact — a hostile oversized input declaring an unknown version
    /// is rejected before anything is allocated for it.
    #[test]
    fn peek_is_constant_cost_in_artifact_size() {
        let big = encode(|e| {
            e.map(|m| {
                m.entry(0, |e| e.u64(9))?;
                m.entry(1, |e| e.bytes(&vec![0u8; 1 << 16]))
            })
        })
        .expect("encode");
        assert_eq!(peek_format_version(&big), Some(9));
    }

    // ── the table ───────────────────────────────────────────────────────

    #[derive(Debug, PartialEq, Eq)]
    enum FakeError {
        Unsupported {
            found: u64,
            supported: &'static [u64],
        },
        FromDecoder,
    }

    impl VersionRejection for FakeError {
        fn unsupported_version(found: u64, supported: &'static [u64]) -> Self {
            Self::Unsupported { found, supported }
        }
    }

    fn v1_decoder(input: V1<'_>) -> Result<usize, FakeError> {
        if input.bytes().is_empty() {
            Err(FakeError::FromDecoder)
        } else {
            Ok(input.bytes().len())
        }
    }

    fn table<'b>() -> VersionDispatch<'b, usize, FakeError> {
        VersionDispatch::v1_only(1, v1_decoder)
    }

    #[test]
    fn version_one_reaches_the_v1_row() {
        let bytes = versioned_map(1);
        assert_eq!(table().decode(&bytes), Ok(bytes.len()));
    }

    #[test]
    fn an_unrowed_version_is_the_version_error_and_nothing_else() {
        for found in [0u64, 2, 3, 255, u64::MAX] {
            let bytes = versioned_map(found);
            assert_eq!(
                table().decode(&bytes),
                Err(FakeError::Unsupported {
                    found,
                    supported: SUPPORTED_VERSIONS
                }),
                "version {found}"
            );
        }
    }

    /// An input with no readable discriminant is handed to the v1 decoder so
    /// the authoritative rejection is the schema pass's, not the peek's.
    #[test]
    fn unversionable_input_falls_through_to_the_decoder() {
        assert_eq!(table().decode(&[]), Err(FakeError::FromDecoder));
        let no_zero = encode(|e| e.map(|m| m.entry(1, |e| e.u64(1)))).expect("encode");
        assert_eq!(table().decode(&no_zero), Ok(no_zero.len()));
    }

    #[test]
    fn supported_versions_is_v1_only_and_ascending() {
        assert_eq!(SUPPORTED_VERSIONS, &[1]);
        assert!(SUPPORTED_VERSIONS.windows(2).all(|w| w[0] < w[1]));
    }

    #[test]
    fn supported_versions_render_readably() {
        assert_eq!(supported_versions_str(SUPPORTED_VERSIONS), "v1");
        assert_eq!(supported_versions_str(&[1, 2, 10]), "v1, v2, v10");
        assert_eq!(supported_versions_str(&[]), "(none)");
    }
}
