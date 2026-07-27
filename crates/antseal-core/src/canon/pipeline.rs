//! The canonicalization v1 pipeline (G2): text detection and the canonical
//! rendition transform, version-dispatched through the [`unicode`] registry.
//!
//! [`unicode`]: super::unicode
//!
//! # The frozen pipeline (decision D21; MVP-SPEC.md lines 81–85)
//!
//! A text file's **canonical rendition** is UTF-8, NFC-normalized, LF line
//! endings, no BOM (spec line 83). It is produced by a fixed five-stage
//! pipeline, frozen by decision D21
//! (`docs/decisions/D21-canonicalization-micro-semantics.md`):
//!
//! 1. **Decode** — strict UTF-8 for detected text ([`TextMode::Detected`]);
//!    deterministic lossy U+FFFD replacement for forced text
//!    ([`TextMode::Forced`]; decision D20, below).
//! 2. **Strip ALL leading U+FEFF scalars** — the entire contiguous run of
//!    U+FEFF at position 0 of the *decoded scalar stream*. This is a
//!    deliberate D21 deviation from the common "strip exactly one BOM" rule:
//!    stripping exactly one is not idempotent (`U+FEFF U+FEFF x` would
//!    canonicalize to `U+FEFF x`, which canonicalizes *again* to `x`), and
//!    idempotence is load-bearing for this function (the verifier's
//!    raw-mirror recompute must reproduce seal-time output exactly, spec
//!    line 121). A U+FEFF anywhere after a non-U+FEFF scalar is content and
//!    is preserved.
//! 3. **Line endings, one left-to-right pass** — `CR LF → LF`; a CR whose
//!    *next input scalar* is not LF is lone and becomes LF. Hence
//!    `CR CR LF → LF LF` (the first CR is lone; the second forms a CRLF) —
//!    the pass never re-examines its own output.
//! 4. **NFC** — using the **descriptor-recorded** Unicode version's table
//!    ([`UnicodeVersion::nfc`]), never "latest" (spec line 83; registry G1,
//!    decision D25).
//! 5. **Encode** — UTF-8; no BOM is (re)introduced.
//!
//! **Canonical-form invariant** (D21): the output never begins with U+FEFF,
//! contains no CR, and is NFC under the given version. Canonical output
//! therefore re-canonicalizes to itself byte-identically —
//! `canonicalize(canonicalize(x)) == canonicalize(x)` — in every mode.
//! (Stages 2–4 preserve the invariant jointly: EOL rewriting never moves a
//! U+FEFF to position 0, and NFC can neither create a CR nor a U+FEFF —
//! neither scalar has, or appears in, any canonical decomposition, and
//! canonical reordering only moves scalars with combining class > 0, which
//! CR and U+FEFF are not.)
//!
//! # Text modes and totality (decision D20)
//!
//! Seal-time text **detection is strict UTF-8 validity** ([`is_text`]);
//! `--force-text` (spec line 149) opts an invalid-UTF-8 file into text
//! treatment anyway. Decision D20 (`docs/decisions/D20-force-text.md`)
//! makes forced-text canonicalization **total**: stage 1 decodes with
//! deterministic lossy U+FFFD replacement under the Unicode *substitution
//! of maximal subparts* policy — exactly the documented
//! [`String::from_utf8_lossy`] policy, byte-pinned by this module's KATs
//! (which double as a tripwire should a future toolchain ever alter it:
//! canonical bytes are format consensus, so any drift must fail tests, not
//! ship).
//!
//! Lossy decoding of *valid* UTF-8 is the identity, so **both modes produce
//! byte-identical output for every valid-UTF-8 input**. That is why D20
//! records **no forced-mode flag in the canonicalization descriptor**:
//! `kind = Text` alone determines recompute semantics, and the verifier's
//! raw-mirror recompute (spec line 121) always runs [`TextMode::Forced`] —
//! being total, it can re-derive the canonical rendition from *any*
//! raw-mirror bytes and reproduces the seal-time result whether the sealer
//! detected or forced.
//!
//! [`TextMode::Detected`] exists for seal-time hygiene: the caller asserts
//! it has established validity, so an invalid sequence is a caller bug or a
//! file mutated between detection and canonicalization, and surfaces as the
//! [`CanonicalizeError::InvalidUtf8`] error — never a panic, and never a
//! silent U+FFFD substitution that would corrupt content.
//!
//! # Binary files are not represented here
//!
//! Binary files have **no canonical rendition**; their offsets are raw-byte
//! offsets (spec line 83). There is deliberately no `Binary`/identity mode
//! in [`TextMode`]: minting an "identity rendition" would give the raw byte
//! domain a second name and invite canonical-vs-raw domain confusion in the
//! commitments (`canon_commit` vs `raw_commit`, spec line 95) and in the
//! fine tree's domain choice (spec line 85). The per-file canonicalization
//! descriptor's kind (G4) records text-vs-binary; only text kinds route
//! through this function, and binary files simply never call it.

use std::borrow::Cow;

use super::unicode::{UnicodeVersion, UnicodeVersionError};

/// How raw bytes were established to be text, selecting the stage-1 decode
/// of the canonicalization pipeline (decision D20; module docs).
///
/// On valid UTF-8 the two modes are byte-identical. The distinction only
/// changes what happens to *invalid* UTF-8: `Detected` refuses it (error,
/// not panic), `Forced` replaces it deterministically (total).
///
/// This enum is exhaustive on purpose: D20 froze the mode set (a
/// descriptor-recorded mode flag was explicitly rejected), so a new variant
/// would be a format-level event, not an API addition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TextMode {
    /// The caller established strict UTF-8 validity ([`is_text`]) —
    /// seal-time detected text. Stage 1 decodes strictly; invalid input is
    /// the caller-bug/TOCTOU error [`CanonicalizeError::InvalidUtf8`].
    Detected,
    /// Text by fiat (`--force-text`, spec line 149) — and the mode of
    /// **every verifier-side recompute** (spec line 121), since
    /// `kind = Text` alone determines recompute semantics (D20). Stage 1
    /// decodes lossily: each maximal subpart of an ill-formed sequence
    /// becomes one U+FFFD ([`String::from_utf8_lossy`] policy), making the
    /// transform total over arbitrary bytes.
    Forced,
}

/// A canonical rendition — the output of [`canonicalize_v`], carrying the
/// canonical-form invariant as a type-level witness.
///
/// Invariant (D21, module docs): the bytes are valid UTF-8, contain no CR,
/// do not begin with U+FEFF, and are NFC **under the Unicode version they
/// were produced with**. The value does not carry that version — the
/// per-file canonicalization descriptor is the authoritative record of it
/// (spec line 83) — so equality is plain byte equality.
///
/// There is no public constructor: the only way to obtain one is to run the
/// pipeline. Unit byte offsets into text files index into exactly these
/// bytes ([`Self::len`] is the byte length; spec line 83).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalBytes(String);

impl CanonicalBytes {
    /// The canonical rendition as bytes — the domain of text-file unit
    /// offsets, `canon_commit`, and text fine-tree leaves.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    /// The canonical rendition as text (it is valid UTF-8 by construction).
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consume into the underlying byte vector.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.0.into_bytes()
    }

    /// Byte length of the canonical rendition — the text file's `size`
    /// field / unit-offset domain bound (spec lines 83, 98).
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// `true` for the empty canonical rendition. Reachable from nonempty
    /// input: a file consisting solely of U+FEFF scalars canonicalizes to
    /// zero bytes (stage 2), which downstream handles under the empty-file
    /// rule (spec line 78) with the raw mirror carrying the original bytes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl AsRef<[u8]> for CanonicalBytes {
    fn as_ref(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl AsRef<str> for CanonicalBytes {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// Errors of the canonicalization pipeline.
///
/// Two failure classes, kept distinct because they demand opposite caller
/// reactions: an unknown version means *this verifier is too old* (or the
/// descriptor is malformed) and must never be conflated with an integrity
/// verdict; invalid UTF-8 in detected mode means *the seal-time caller's
/// validity claim was wrong* and the seal must not proceed silently.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum CanonicalizeError {
    /// The version string does not resolve in the Unicode version registry
    /// — surfaced transparently as the registry's own distinct error
    /// ([`UnicodeVersionError::UnknownUnicodeVersion`], G1/D25).
    #[error(transparent)]
    UnknownVersion(#[from] UnicodeVersionError),

    /// [`TextMode::Detected`] requires strictly valid UTF-8, and the input
    /// is not. Carries positions only — never the offending bytes, so
    /// content cannot leak through error messages or logs.
    #[error(
        "input is not valid UTF-8: invalid sequence starting at byte offset \
         {valid_up_to} (detected-text canonicalization is strict; \
         forced-text mode is the total lossy transform)"
    )]
    InvalidUtf8 {
        /// Number of leading input bytes that are valid UTF-8 (the offset
        /// where the first invalid sequence starts), as reported by strict
        /// decoding.
        valid_up_to: usize,
        /// Length in bytes of the invalid sequence at `valid_up_to`:
        /// `Some(1..=3)` for an error mid-stream, `None` when the input
        /// ends with a truncated (possibly still completable) sequence —
        /// mirroring [`std::str::Utf8Error::error_len`].
        error_len: Option<usize>,
    },
}

/// Seal-time text detection: **strict UTF-8 validity** (spec line 83 —
/// "Text files (valid UTF-8, or `--force-text`)").
///
/// This predicate is the *entire* detection rule; there is no heuristic
/// (no NUL-byte scan, no control-character ratio). A file is text iff its
/// bytes are valid UTF-8, or the user forces it.
#[must_use]
pub fn is_text(raw_bytes: &[u8]) -> bool {
    str::from_utf8(raw_bytes).is_ok()
}

/// Canonicalize `raw_bytes` under the canonicalization version named by the
/// descriptor string `version` — the spec's `canonicalize_v` (line 121),
/// where *v* is the per-file descriptor's recorded Unicode version.
///
/// This is the verifier-facing entry point: resolve `version` through the
/// G1 registry, then run the frozen D21 pipeline (module docs). Seal-time
/// code holding a resolved [`UnicodeVersion`] (e.g.
/// [`UnicodeVersion::CURRENT`]) can call [`canonicalize`] directly.
///
/// Pure, deterministic, and panic-free on arbitrary input; total in
/// [`TextMode::Forced`]; idempotent
/// (`canonicalize_v(v, m, out) == out` for any output `out`).
///
/// # Errors
///
/// - [`CanonicalizeError::UnknownVersion`] — `version` is not registered in
///   this build (the registry's distinct "verifier too old" error; never an
///   integrity verdict).
/// - [`CanonicalizeError::InvalidUtf8`] — [`TextMode::Detected`] only:
///   the input is not strictly valid UTF-8.
///
/// # Examples
///
/// ```
/// use antseal_core::canon::{TextMode, UNICODE_17_0_0, canonicalize_v};
///
/// // BOM + CRLF + NFD ("e" + COMBINING ACUTE ACCENT) all normalize away:
/// let raw = b"\xEF\xBB\xBFtitle\r\ncafe\xCC\x81\n";
/// let canonical = canonicalize_v(UNICODE_17_0_0, TextMode::Detected, raw)?;
/// assert_eq!(canonical.as_str(), "title\ncaf\u{00E9}\n");
/// # Ok::<(), antseal_core::canon::CanonicalizeError>(())
/// ```
pub fn canonicalize_v(
    version: &str,
    mode: TextMode,
    raw_bytes: &[u8],
) -> Result<CanonicalBytes, CanonicalizeError> {
    let version = UnicodeVersion::resolve(version)?;
    canonicalize(version, mode, raw_bytes)
}

/// [`canonicalize_v`] with the version already resolved — the pipeline
/// core. Same semantics; the only remaining error is
/// [`CanonicalizeError::InvalidUtf8`] in [`TextMode::Detected`]
/// ([`TextMode::Forced`] is total and cannot fail).
pub fn canonicalize(
    version: UnicodeVersion,
    mode: TextMode,
    raw_bytes: &[u8],
) -> Result<CanonicalBytes, CanonicalizeError> {
    // Stage 1 — decode (strict for detected text, lossy U+FFFD maximal
    // subparts for forced text; D20).
    let decoded: Cow<'_, str> = match mode {
        TextMode::Detected => Cow::Borrowed(str::from_utf8(raw_bytes).map_err(|err| {
            CanonicalizeError::InvalidUtf8 {
                valid_up_to: err.valid_up_to(),
                error_len: err.error_len(),
            }
        })?),
        TextMode::Forced => String::from_utf8_lossy(raw_bytes),
    };

    // Stage 2 — strip ALL leading U+FEFF scalars (the contiguous run at
    // position 0; D21's deliberate strip-all-for-idempotence rule).
    let stripped = decoded.trim_start_matches('\u{FEFF}');

    // Stage 3 — line endings, one pass: CRLF → LF, lone CR → LF.
    let eol_normalized = normalize_eol(stripped);

    // Stage 4 — NFC via the version-selected table (never "latest").
    let nfc = version.nfc(&eol_normalized);

    // Stage 5 — encode UTF-8, no BOM: a Rust `String` is exactly that, and
    // nothing is prepended.
    Ok(CanonicalBytes(nfc))
}

/// Stage 3: one left-to-right pass over the scalar stream mapping
/// `CR LF → LF` and lone `CR → LF` (D21).
///
/// "Lone" is decided by the *next input scalar* only — the pass never
/// re-examines its own output — so `CR CR LF → LF LF`: the first CR sees a
/// CR next (lone → LF), the second CR sees LF next (CRLF pair → LF).
fn normalize_eol(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut scalars = text.chars().peekable();
    while let Some(c) = scalars.next() {
        if c == '\r' {
            if scalars.peek() == Some(&'\n') {
                // CRLF: consume the LF; the pair becomes one LF.
                scalars.next();
            }
            out.push('\n');
        } else {
            out.push(c);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use proptest::test_runner::RngSeed;

    use super::super::unicode::UNICODE_17_0_0;
    use super::*;

    /// Canonicalize under the current (v17) table, panicking on error —
    /// KAT-helper for inputs that must succeed in the given mode.
    fn canon(mode: TextMode, raw: &[u8]) -> CanonicalBytes {
        canonicalize(UnicodeVersion::CURRENT, mode, raw)
            .expect("KAT input must canonicalize in this mode")
    }

    /// Canonicalize a valid-UTF-8 KAT input under BOTH modes, asserting the
    /// D20 mode-agreement property on the way (lossy decode of valid UTF-8
    /// is the identity, so Detected and Forced must agree byte-identically).
    fn canon_both(raw: &[u8]) -> CanonicalBytes {
        let detected = canon(TextMode::Detected, raw);
        let forced = canon(TextMode::Forced, raw);
        assert_eq!(
            detected, forced,
            "modes must agree on valid UTF-8 (D20), input {raw:02X?}"
        );
        detected
    }

    // ---- KATs: leading-BOM handling (D21 stage 2) ----

    #[test]
    fn kat_leading_bom_stripped() {
        // The same input spelled as encoded bytes and as a str literal.
        assert_eq!(canon_both(b"\xEF\xBB\xBFhello").as_bytes(), b"hello");
        assert_eq!(canon_both("\u{FEFF}hello".as_bytes()).as_bytes(), b"hello");
    }

    /// Pins the D21 deviation: ALL leading U+FEFF scalars are stripped, not
    /// exactly one. (Strip-exactly-one would map `FEFF FEFF hi` to
    /// `FEFF hi`, which re-canonicalizes to `hi` — not idempotent.)
    #[test]
    fn kat_all_leading_boms_stripped() {
        assert_eq!(
            canon_both("\u{FEFF}\u{FEFF}hi".as_bytes()).as_bytes(),
            b"hi"
        );
        assert_eq!(
            canon_both("\u{FEFF}\u{FEFF}\u{FEFF}".as_bytes()).as_bytes(),
            b""
        );
        // A BOM-only file has an EMPTY canonical rendition (nonempty raw →
        // empty canonical is reachable; spec line 78's empty rule applies).
        assert_eq!(canon_both("\u{FEFF}".as_bytes()).as_bytes(), b"");
        // The stripped run ends at the first non-U+FEFF scalar; later
        // U+FEFFs are content.
        assert_eq!(
            canon_both("\u{FEFF}\u{FEFF}a\u{FEFF}b".as_bytes()).as_str(),
            "a\u{FEFF}b"
        );
    }

    #[test]
    fn kat_interior_and_trailing_feff_preserved() {
        // Interior and trailing U+FEFF are content, byte-identically kept.
        assert_eq!(canon_both("a\u{FEFF}b".as_bytes()).as_str(), "a\u{FEFF}b");
        assert_eq!(canon_both("a\u{FEFF}".as_bytes()).as_str(), "a\u{FEFF}");
        // Position-0 rule: a U+FEFF at scalar index 1 survives even when
        // the leading CR before it is rewritten by stage 3.
        assert_eq!(canon_both("\r\u{FEFF}x".as_bytes()).as_str(), "\n\u{FEFF}x");
        // A U+FEFF after a (content) replacement char is content too — the
        // leading run is over.
        assert_eq!(
            canon_both("\u{FFFD}\u{FEFF}".as_bytes()).as_str(),
            "\u{FFFD}\u{FEFF}"
        );
    }

    // ---- KATs: line endings (D21 stage 3) ----

    #[test]
    fn kat_crlf_to_lf() {
        assert_eq!(canon_both(b"a\r\nb").as_bytes(), b"a\nb");
        assert_eq!(canon_both(b"a\r\nb\r\n").as_bytes(), b"a\nb\n");
    }

    #[test]
    fn kat_lone_cr_to_lf() {
        assert_eq!(canon_both(b"a\rb").as_bytes(), b"a\nb");
        // A trailing CR is lone by definition (no next scalar).
        assert_eq!(canon_both(b"a\r").as_bytes(), b"a\n");
    }

    /// The frozen one-pass rule: lone-ness is judged against the next INPUT
    /// scalar, so `CR CR LF → LF LF` (D21's worked example).
    #[test]
    fn kat_cr_runs_are_one_pass() {
        assert_eq!(canon_both(b"\r\r\n").as_bytes(), b"\n\n");
        assert_eq!(canon_both(b"a\r\r\nb").as_bytes(), b"a\n\nb");
        assert_eq!(canon_both(b"\r\r\r").as_bytes(), b"\n\n\n");
        assert_eq!(canon_both(b"\r\n\r").as_bytes(), b"\n\n");
        assert_eq!(canon_both(b"\r\n\r\n").as_bytes(), b"\n\n");
    }

    // ---- KATs: NFC (stage 4) ----

    #[test]
    fn kat_nfd_input_becomes_nfc_latin() {
        // e + COMBINING ACUTE ACCENT → é (U+00E9), byte-exact.
        assert_eq!(canon_both("e\u{0301}".as_bytes()).as_bytes(), [0xC3, 0xA9]);
        // A + COMBINING RING ABOVE → Å (U+00C5).
        assert_eq!(canon_both("A\u{030A}".as_bytes()).as_bytes(), [0xC3, 0x85]);
        // Canonical reordering + double composition → ṩ (U+1E69).
        assert_eq!(
            canon_both("s\u{0323}\u{0307}".as_bytes()).as_str(),
            "\u{1E69}"
        );
    }

    #[test]
    fn kat_nfd_input_becomes_nfc_hangul() {
        // Jamo L+V → 가 (U+AC00), byte-exact.
        assert_eq!(
            canon_both("\u{1100}\u{1161}".as_bytes()).as_bytes(),
            [0xEA, 0xB0, 0x80]
        );
        // Jamo L+V+T → 각 (U+AC01).
        assert_eq!(
            canon_both("\u{1100}\u{1161}\u{11A8}".as_bytes()).as_bytes(),
            [0xEA, 0xB0, 0x81]
        );
    }

    // ---- KATs: fixed points, empty input, full pipeline ----

    #[test]
    fn kat_already_canonical_is_byte_identical() {
        // Already-canonical inputs (LF endings, NFC, no leading U+FEFF)
        // must pass through with zero byte drift.
        let fixed_points: &[&str] = &[
            "",
            "hello, world\n",
            "caf\u{00E9}\n",    // precomposed é
            "\u{AC00}\u{AC01}", // precomposed Hangul
            "a\u{FEFF}b",       // interior U+FEFF is content
            "x\u{FFFD}y",       // pre-existing replacement char is content
            "line one\nline two\n",
            "\n",
            "\u{1E69}",    // ṩ, NFC
            "\u{0301}abc", // defective combining sequence is NFC-stable
        ];
        for text in fixed_points {
            assert_eq!(
                canon_both(text.as_bytes()).as_bytes(),
                text.as_bytes(),
                "canonical fixed point drifted: {text:?}"
            );
        }
    }

    #[test]
    fn kat_empty_input() {
        let empty = canon_both(b"");
        assert_eq!(empty.as_bytes(), b"");
        assert!(empty.is_empty());
        assert_eq!(empty.len(), 0);
        // And through the descriptor-string entry point.
        let via_v = canonicalize_v(UNICODE_17_0_0, TextMode::Forced, b"")
            .expect("empty input canonicalizes");
        assert_eq!(via_v, empty);
    }

    /// One input exercising stages 2–4 together, pinning their frozen
    /// order: double BOM, CRLF, the CR-CR-LF run, and NFD composition.
    #[test]
    fn kat_full_pipeline_order() {
        let raw = "\u{FEFF}\u{FEFF}\r\ne\u{0301}\r\r\nB";
        assert_eq!(canon_both(raw.as_bytes()).as_str(), "\n\u{00E9}\n\nB");
    }

    // ---- KATs: forced-text lossy decode (D20) ----

    /// Byte-exact pins of the maximal-subparts U+FFFD policy
    /// ([`String::from_utf8_lossy`]) — the tripwire for any toolchain-level
    /// policy drift. Every row is invalid UTF-8, so each also asserts that
    /// Detected mode errors and that forced output is idempotent.
    #[test]
    fn kat_forced_lossy_maximal_subparts_byte_exact() {
        let kats: &[(&[u8], &str)] = &[
            // Truncated 3-byte sequence at end of input → ONE replacement.
            (b"\xE2\x82", "\u{FFFD}"),
            // Same maximal subpart mid-stream (broken by 'a') → still ONE.
            (b"\xE2\x82abc", "\u{FFFD}abc"),
            // Overlong 2-byte encoding of '/': C0 can never begin a valid
            // sequence, then a stray continuation → TWO replacements.
            (b"\xC0\xAF", "\u{FFFD}\u{FFFD}"),
            // Lone continuation byte.
            (b"\x80", "\u{FFFD}"),
            // Lead byte broken immediately: subparts are F0 and 8C.
            (b"\xF0\x28\x8C\x28", "\u{FFFD}(\u{FFFD}("),
            // Overlong 3-byte encoding: E0 requires A0..=BF next → three.
            (b"\xE0\x80\xAF", "\u{FFFD}\u{FFFD}\u{FFFD}"),
            // CESU-8 surrogate D800: ED requires 80..=9F next → three.
            (b"\xED\xA0\x80", "\u{FFFD}\u{FFFD}\u{FFFD}"),
            // Beyond U+10FFFF: F4 requires 80..=8F next → four.
            (b"\xF4\x90\x80\x80", "\u{FFFD}\u{FFFD}\u{FFFD}\u{FFFD}"),
            // A TRUNCATED BOM is not a BOM: it decodes to U+FFFD, which is
            // content and is NOT stripped.
            (b"\xEF\xBB", "\u{FFFD}"),
            // A real leading BOM is stripped even when followed by garbage.
            (b"\xEF\xBB\xBF\xEF\xBB", "\u{FFFD}"),
            // Truncated 2-byte sequence after valid text.
            (b"caf\xC3", "caf\u{FFFD}"),
        ];
        for (raw, expected) in kats {
            let forced = canon(TextMode::Forced, raw);
            assert_eq!(forced.as_str(), *expected, "input {raw:02X?}");
            // Byte-exactness is str equality, but make the U+FFFD encoding
            // explicit once per row: EF BF BD triples where expected.
            assert_eq!(forced.as_bytes(), expected.as_bytes());
            // Forced output is a fixed point (idempotence on the KATs).
            assert_eq!(canon(TextMode::Forced, forced.as_bytes()), forced);
            // The same bytes in Detected mode are an error, not a panic.
            let err = canonicalize(UnicodeVersion::CURRENT, TextMode::Detected, raw)
                .expect_err("invalid UTF-8 must not pass detected mode");
            assert!(
                matches!(err, CanonicalizeError::InvalidUtf8 { .. }),
                "wrong error class for {raw:02X?}: {err:?}"
            );
        }
        // And the U+FFFD encoding itself, pinned as raw bytes.
        assert_eq!(
            canon(TextMode::Forced, b"\xE2\x82").as_bytes(),
            [0xEF, 0xBF, 0xBD]
        );
    }

    // ---- Mode semantics, errors, registry dispatch ----

    #[test]
    fn kat_modes_agree_on_valid_utf8() {
        // `canon_both` asserts agreement; run it across the interesting
        // valid inputs in one named place (the D20 no-descriptor-flag
        // property: recompute cannot depend on which mode sealed).
        for raw in [
            b"plain ascii".as_slice(),
            b"\xEF\xBB\xBFbom\r\nand crlf",
            "e\u{0301}\r\nNFD line".as_bytes(),
            "\u{FEFF}\u{FEFF}double bom".as_bytes(),
            "\u{FFFD}already replaced".as_bytes(),
            b"",
        ] {
            let _ = canon_both(raw);
        }
    }

    #[test]
    fn detected_mode_rejects_invalid_utf8_without_panicking() {
        // Invalid lead byte at offset 0, mid-stream error.
        let err = canonicalize(UnicodeVersion::CURRENT, TextMode::Detected, b"\xFF")
            .expect_err("0xFF is not UTF-8");
        assert_eq!(
            err,
            CanonicalizeError::InvalidUtf8 {
                valid_up_to: 0,
                error_len: Some(1),
            }
        );
        // Truncated sequence at end of input: error_len is None.
        let err = canonicalize(
            UnicodeVersion::CURRENT,
            TextMode::Detected,
            b"SEALCONTENT\xE2\x82",
        )
        .expect_err("truncated sequence is not UTF-8");
        assert_eq!(
            err,
            CanonicalizeError::InvalidUtf8 {
                valid_up_to: 11,
                error_len: None,
            }
        );
        // The message names the offset but never echoes input bytes.
        let msg = err.to_string();
        assert!(msg.contains("byte offset 11"), "message: {msg}");
        assert!(
            !msg.contains("SEALCONTENT"),
            "error must not echo content: {msg}"
        );
    }

    #[test]
    fn unknown_version_is_the_registrys_distinct_error() {
        let err = canonicalize_v("unicode-99.0.0", TextMode::Forced, b"x")
            .expect_err("unregistered version must not canonicalize");
        match err {
            CanonicalizeError::UnknownVersion(UnicodeVersionError::UnknownUnicodeVersion {
                requested,
            }) => assert_eq!(requested, "unicode-99.0.0"),
            other => panic!("expected the registry's UnknownUnicodeVersion, got {other:?}"),
        }
        // Distinct from the invalid-UTF-8 class even when the input is
        // also invalid: version resolution is checked first.
        let err = canonicalize_v("latest", TextMode::Detected, b"\xFF")
            .expect_err("unregistered version must not canonicalize");
        assert!(matches!(err, CanonicalizeError::UnknownVersion(_)));
    }

    #[test]
    fn canonicalize_v_dispatches_through_the_registry() {
        let raw = "\u{FEFF}via registry\r\ne\u{0301}".as_bytes();
        let via_string = canonicalize_v(UNICODE_17_0_0, TextMode::Detected, raw)
            .expect("frozen descriptor string resolves");
        let via_resolved = canonicalize(UnicodeVersion::CURRENT, TextMode::Detected, raw)
            .expect("current version canonicalizes");
        assert_eq!(via_string, via_resolved);
        assert_eq!(via_string.as_str(), "via registry\n\u{00E9}");
        // CURRENT's descriptor string round-trips through the same path.
        let via_current_str =
            canonicalize_v(UnicodeVersion::CURRENT.as_str(), TextMode::Detected, raw)
                .expect("CURRENT.as_str() resolves");
        assert_eq!(via_current_str, via_resolved);
    }

    #[test]
    fn is_text_is_strict_utf8_validity() {
        // Text.
        assert!(is_text(b""));
        assert!(is_text(b"hello"));
        assert!(is_text(b"\xEF\xBB\xBFbom is text"));
        assert!(is_text("caf\u{00E9} \u{AC00}".as_bytes()));
        // Not text — strict validity, no heuristics.
        assert!(!is_text(b"\xFF"));
        assert!(!is_text(b"caf\xC3"));
        assert!(!is_text(b"\xEF\xBB")); // truncated BOM
        assert!(!is_text(b"\xED\xA0\x80")); // CESU-8 surrogate
        // NUL bytes are valid UTF-8: still text (deliberately no NUL scan).
        assert!(is_text(b"a\x00b"));
    }

    // ---- Property tests (fixed seed; Q3 later centralizes conventions) ----

    /// Scalars that concentrate on the pipeline's hot spots: CR/LF, U+FEFF,
    /// U+FFFD, NFD material (combining marks, singletons, Hangul jamo),
    /// plus arbitrary scalars for breadth.
    fn hotspot_string() -> impl Strategy<Value = String> {
        let scalar = prop_oneof![
            Just('\r'),
            Just('\n'),
            Just('\u{FEFF}'),
            Just('\u{FFFD}'),
            Just('\u{0301}'), // COMBINING ACUTE ACCENT
            Just('\u{030A}'), // COMBINING RING ABOVE
            Just('\u{00E9}'), // é (precomposed)
            Just('\u{212B}'), // ANGSTROM SIGN (NFC singleton)
            Just('\u{1100}'), // Hangul jamo L
            Just('\u{1161}'), // Hangul jamo V
            Just('\u{11A8}'), // Hangul jamo T
            proptest::char::range('a', 'f'),
            any::<char>(),
        ];
        proptest::collection::vec(scalar, 0..=64).prop_map(|scalars| scalars.into_iter().collect())
    }

    /// Arbitrary raw bytes, weighted toward interesting shapes: pure noise,
    /// valid hotspot text, and hotspot text truncated mid-scalar (which
    /// manufactures maximal-subpart boundary cases at the tail).
    fn raw_byte_soup() -> impl Strategy<Value = Vec<u8>> {
        prop_oneof![
            proptest::collection::vec(any::<u8>(), 0..=256),
            hotspot_string().prop_map(String::into_bytes),
            (hotspot_string(), 0usize..=3).prop_map(|(text, cut)| {
                let mut bytes = text.into_bytes();
                let keep = bytes.len().saturating_sub(cut);
                bytes.truncate(keep);
                bytes
            }),
        ]
    }

    proptest! {
        #![proptest_config(ProptestConfig {
            // Deterministic fixed seed per the determinism principle
            // (0xD20D21 — the two decisions this module implements). Q3
            // later centralizes seed/regression-file conventions. 4096
            // cases keeps the three suites' NFC-heavy debug runtime in
            // budget; the KATs above pin every known corner exactly.
            cases: 4096,
            rng_seed: RngSeed::Fixed(0x00D2_0D21),
            .. ProptestConfig::default()
        })]

        /// D20 totality + D21 idempotence + the canonical-form invariant,
        /// over arbitrary bytes in forced-text mode — including the
        /// cross-mode closure: canonical output is valid UTF-8, so
        /// Detected mode must accept it and agree.
        #[test]
        fn forced_mode_is_total_idempotent_and_canonical(raw in raw_byte_soup()) {
            let result = canonicalize(UnicodeVersion::CURRENT, TextMode::Forced, &raw);
            prop_assert!(result.is_ok(), "forced-text canonicalization must be total (D20)");
            let once = result.expect("just asserted Ok");

            // Canonical-form invariant (D21): never begins with U+FEFF,
            // no CR, NFC under the applied version. (The leading-BOM check
            // is hoisted into a binding: `prop_assert!` stringifies its
            // condition into a format string, where `{FEFF}` would read as
            // a capture.)
            let begins_with_feff = once.as_str().starts_with('\u{FEFF}');
            prop_assert!(!begins_with_feff, "canonical output must not begin with U+FEFF");
            prop_assert!(!once.as_str().contains('\r'));
            prop_assert!(unicode_normalization::is_nfc(once.as_str()));

            // Idempotence: canonicalize(canonicalize(x)) == canonicalize(x).
            let twice = canonicalize(UnicodeVersion::CURRENT, TextMode::Forced, once.as_bytes())
                .expect("forced mode is total");
            prop_assert_eq!(&twice, &once);

            // Cross-mode closure on canonical output.
            let detected = canonicalize(UnicodeVersion::CURRENT, TextMode::Detected, once.as_bytes())
                .expect("canonical bytes are valid UTF-8 by construction");
            prop_assert_eq!(&detected, &once);
        }

        /// Detected-text mode over valid UTF-8: succeeds, is idempotent,
        /// and agrees byte-identically with forced mode (the D20
        /// no-descriptor-flag property).
        #[test]
        fn detected_mode_is_idempotent_and_mode_agnostic_on_valid_utf8(text in hotspot_string()) {
            let detected = canonicalize(UnicodeVersion::CURRENT, TextMode::Detected, text.as_bytes())
                .expect("valid UTF-8 must canonicalize in detected mode");
            let forced = canonicalize(UnicodeVersion::CURRENT, TextMode::Forced, text.as_bytes())
                .expect("forced mode is total");
            prop_assert_eq!(&detected, &forced);

            let twice = canonicalize(UnicodeVersion::CURRENT, TextMode::Detected, detected.as_bytes())
                .expect("canonical bytes are valid UTF-8");
            prop_assert_eq!(&twice, &detected);
        }

        /// Detected mode accepts EXACTLY the strictly-valid-UTF-8 inputs
        /// ([`is_text`]), never panics on arbitrary bytes, reports std's
        /// exact error positions on rejection, and agrees with forced mode
        /// whenever it accepts.
        #[test]
        fn detected_mode_accepts_exactly_valid_utf8(raw in raw_byte_soup()) {
            let result = canonicalize(UnicodeVersion::CURRENT, TextMode::Detected, &raw);
            prop_assert_eq!(result.is_ok(), is_text(&raw));
            match result {
                Ok(canonical) => {
                    let forced = canonicalize(UnicodeVersion::CURRENT, TextMode::Forced, &raw)
                        .expect("forced mode is total");
                    prop_assert_eq!(canonical, forced);
                }
                Err(CanonicalizeError::InvalidUtf8 { valid_up_to, error_len }) => {
                    let std_err = str::from_utf8(&raw).expect_err("is_text said invalid");
                    prop_assert_eq!(valid_up_to, std_err.valid_up_to());
                    prop_assert_eq!(error_len, std_err.error_len());
                }
                Err(other) => prop_assert!(false, "unexpected error class: {other}"),
            }
        }
    }
}
