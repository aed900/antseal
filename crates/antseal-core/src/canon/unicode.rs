//! Pinned Unicode/NFC data versions and the version-dispatch registry (G1).
//!
//! Decision record: `docs/decisions/D25-unicode-normalization.md`. The v1
//! table is Unicode **17.0.0**, shipped by `unicode-normalization = "=0.1.25"`
//! and registered under the frozen descriptor string [`UNICODE_17_0_0`]
//! (`"unicode-17.0.0"`).
//!
//! Normative rules this module embodies (MVP-SPEC.md lines 81–83, 123, 153):
//!
//! - The Unicode version is **frozen at seal time** and recorded in the
//!   per-file canonicalization descriptor; verifiers apply exactly the
//!   descriptor-recorded version, **never "latest"** — otherwise an aging
//!   honest bundle would false-positive as tampered once the verifier's
//!   Unicode tables drift.
//! - Future Unicode versions are **added** to this registry; every table
//!   ever shipped is **retained forever** under the format-stability policy
//!   (spec line 123). Removing, renaming, or altering a registered entry is
//!   a format break.
//! - A descriptor string this build does not register resolves to the
//!   distinct [`UnicodeVersionError::UnknownUnicodeVersion`] — meaning "this
//!   bundle needs a newer verifier", which every caller must keep distinct
//!   from any integrity failure.

use core::fmt;

use unicode_normalization::UnicodeNormalization as _;

/// Frozen descriptor version string for the Unicode 17.0.0 tables
/// (format `unicode-<major>.<minor>.<patch>`).
///
/// This exact string is what seal-time code writes into canonicalization
/// descriptors and what [`UnicodeVersion::resolve`] accepts. Its mapping to
/// the pinned crate release (`unicode-normalization = "=0.1.25"`, which
/// ships `UNICODE_VERSION == (17, 0, 0)`) is machine-asserted in this
/// module's tests, per decision D25.
pub const UNICODE_17_0_0: &str = "unicode-17.0.0";

/// Every descriptor version string this build registers, in registration
/// order. Grows append-only (see the module docs on retention).
const REGISTERED: &[&str] = &[UNICODE_17_0_0];

/// Longest prefix of an unregistered version string echoed back in
/// [`UnicodeVersionError::UnknownUnicodeVersion`]. Version strings arrive
/// from adversarial bundles; bounding the echo keeps a hostile
/// megabyte-long "version" from bloating error output, independent of the
/// decode-time size caps the bundle parser will also enforce.
const MAX_ECHO_BYTES: usize = 64;

/// A Unicode data version registered in this build of `antseal-core`,
/// resolved from a canonicalization-descriptor version string.
///
/// Values of this type are proof that the version is registered: every
/// NFC computation is dispatched through a `UnicodeVersion`, so an
/// unregistered version is unrepresentable past [`UnicodeVersion::resolve`].
/// The inner representation is private — new versions are added here
/// without breaking callers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct UnicodeVersion(Table);

/// Which shipped normalization table backs a [`UnicodeVersion`].
///
/// One variant per retained table, forever (format-stability policy,
/// MVP-SPEC.md line 123). Each variant names its exact data source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Table {
    /// Unicode 17.0.0 via the exact pin `unicode-normalization = "=0.1.25"`
    /// (the crate's `UNICODE_VERSION` constant is asserted to equal
    /// `(17, 0, 0)` by this module's tests).
    V17_0_0,
}

impl UnicodeVersion {
    /// The version newly created seals freeze into their canonicalization
    /// descriptors (G4's `describe_file`): currently Unicode 17.0.0.
    ///
    /// **Verification must never use this.** A verifier resolves the
    /// descriptor-recorded string via [`UnicodeVersion::resolve`] — the
    /// spec's "descriptor-recorded version, never latest" rule (line 83).
    pub const CURRENT: Self = Self(Table::V17_0_0);

    /// Resolve a canonicalization-descriptor version string to its
    /// registered normalization table.
    ///
    /// Accepts exactly the strings in the registry (byte-for-byte; no
    /// trimming, no case folding — descriptor strings are frozen bytes).
    ///
    /// # Errors
    ///
    /// [`UnicodeVersionError::UnknownUnicodeVersion`] for any unregistered
    /// string. Callers must surface this as "produced by a newer antseal
    /// than this verifier — upgrade to verify", never as an integrity
    /// failure.
    pub fn resolve(descriptor: &str) -> Result<Self, UnicodeVersionError> {
        match descriptor {
            UNICODE_17_0_0 => Ok(Self(Table::V17_0_0)),
            other => Err(UnicodeVersionError::UnknownUnicodeVersion {
                requested: truncate_for_echo(other),
            }),
        }
    }

    /// The frozen descriptor string for this version — the exact bytes
    /// recorded in manifests (e.g. [`UNICODE_17_0_0`]).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self.0 {
            Table::V17_0_0 => UNICODE_17_0_0,
        }
    }

    /// NFC-normalize `input` using **this version's** table.
    ///
    /// This is the version-dispatched NFC substrate the G2 pipeline
    /// (`canonicalize_v`) calls between EOL normalization and UTF-8
    /// encoding. It is exactly Unicode NFC and nothing else: no BOM
    /// stripping, no line-ending changes — an interior (or even leading)
    /// U+FEFF passes through untouched; handling the *leading* BOM is the
    /// pipeline's job.
    ///
    /// Pure and deterministic: same input and version ⇒ same output bytes,
    /// on every platform and on `wasm32-unknown-unknown` (bit-match with
    /// native is a standing requirement).
    #[must_use]
    pub fn nfc(self, input: &str) -> String {
        match self.0 {
            Table::V17_0_0 => input.nfc().collect(),
        }
    }
}

impl fmt::Display for UnicodeVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Errors of the Unicode version registry.
///
/// This enum is deliberately local to the canonicalization version
/// registry — crypto errors (C's tasks) live in their own enum, and the
/// two must never be merged: "unknown version" is a
/// verifier-too-old/malformed-descriptor condition, not an integrity
/// verdict.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum UnicodeVersionError {
    /// The descriptor names a Unicode version this build does not
    /// register (see [`UnicodeVersion::resolve`]).
    #[error(
        "unknown Unicode normalization version {requested:?} \
         (this build registers: {}); \
         if the bundle is honest it was produced by a newer antseal — \
         upgrade the verifier",
        REGISTERED.join(", ")
    )]
    UnknownUnicodeVersion {
        /// The unregistered version string as received, truncated to at
        /// most `MAX_ECHO_BYTES` (64 bytes, plus a marker) because it is
        /// adversarial input. `{:?}` rendering keeps control characters
        /// escaped in the message.
        requested: String,
    },
}

/// Bound an adversarial string for echoing inside an error message
/// (UTF-8-boundary-safe truncation, with an explicit marker).
fn truncate_for_echo(s: &str) -> String {
    if s.len() <= MAX_ECHO_BYTES {
        return s.to_owned();
    }
    let mut end = MAX_ECHO_BYTES;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}… [truncated; {} bytes total]", &s[..end], s.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// D25's crate-release → Unicode-data-version mapping, machine-checked:
    /// `unicode-normalization = "=0.1.25"` must ship Unicode 17.0.0, and the
    /// frozen descriptor string must spell exactly that version. If a future
    /// pin bump moves the shipped data, this fails before any canonical
    /// byte can drift.
    #[test]
    fn pinned_crate_ships_the_recorded_unicode_data_version() {
        assert_eq!(unicode_normalization::UNICODE_VERSION, (17, 0, 0));
        assert_eq!(UnicodeVersion::CURRENT.as_str(), "unicode-17.0.0");
        assert_eq!(UNICODE_17_0_0, "unicode-17.0.0");
        assert_eq!(REGISTERED, &["unicode-17.0.0"]);
    }

    #[test]
    fn registry_resolves_the_frozen_string() {
        assert_eq!(
            UnicodeVersion::resolve("unicode-17.0.0"),
            Ok(UnicodeVersion::CURRENT)
        );
        // Round-trip: the string a seal records resolves back to the same
        // table.
        assert_eq!(
            UnicodeVersion::resolve(UnicodeVersion::CURRENT.as_str()),
            Ok(UnicodeVersion::CURRENT)
        );
        assert_eq!(UnicodeVersion::CURRENT.to_string(), "unicode-17.0.0");
    }

    #[test]
    fn registry_rejects_unknown_strings_distinctly() {
        // Exact-bytes matching: near-misses (case, whitespace, prefixes)
        // and never-registered versions all yield the distinct
        // UnknownUnicodeVersion error.
        for bad in [
            "",
            "unicode-16.0.0",
            "unicode-18.0.0",
            "unicode-17",
            "unicode-17.0",
            "17.0.0",
            "latest",
            "UNICODE-17.0.0",
            "unicode-17.0.0 ",
            " unicode-17.0.0",
            "unicode-17.0.0\u{0}",
        ] {
            let err =
                UnicodeVersion::resolve(bad).expect_err("unregistered string must not resolve");
            let UnicodeVersionError::UnknownUnicodeVersion { requested } = err;
            assert_eq!(requested, bad, "echo must carry the rejected string");
        }
    }

    #[test]
    fn unknown_version_echo_is_bounded() {
        let hostile = "unicode-".repeat(4096);
        let err =
            UnicodeVersion::resolve(&hostile).expect_err("unregistered string must not resolve");
        let UnicodeVersionError::UnknownUnicodeVersion { requested } = &err;
        assert!(
            requested.len() < 128,
            "echo must be bounded, got {} bytes",
            requested.len()
        );
        assert!(requested.starts_with("unicode-"));
        assert!(requested.contains("[truncated; 32768 bytes total]"));
        // The Display rendering stays bounded and still names the registry.
        let msg = err.to_string();
        assert!(msg.len() < 512);
        assert!(msg.contains("unicode-17.0.0"));
    }

    #[test]
    fn error_display_names_requested_and_registered_versions() {
        let err = UnicodeVersion::resolve("unicode-99.0.0")
            .expect_err("unregistered string must not resolve");
        let msg = err.to_string();
        assert!(msg.contains("\"unicode-99.0.0\""), "message: {msg}");
        assert!(msg.contains("unicode-17.0.0"), "message: {msg}");
    }

    /// NFD → NFC known-answer tests over the v17 table: Latin diacritics,
    /// a compatibility-singleton, canonical reordering + double
    /// composition. These prove the shipped table actually normalizes
    /// (not identity) with the expected answers.
    #[test]
    fn nfc_kats_latin() {
        let v = UnicodeVersion::CURRENT;
        assert_eq!(v.nfc("e\u{0301}"), "\u{00E9}"); // e + COMBINING ACUTE → é
        assert_eq!(v.nfc("A\u{030A}"), "\u{00C5}"); // A + COMBINING RING → Å
        assert_eq!(v.nfc("\u{212B}"), "\u{00C5}"); // ANGSTROM SIGN → Å (singleton)
        assert_eq!(v.nfc("s\u{0323}\u{0307}"), "\u{1E69}"); // ṩ: two compositions
        assert_eq!(v.nfc("s\u{0307}\u{0323}"), "\u{1E69}"); // ṩ: reorder, then compose
    }

    /// Hangul algorithmic composition (L+V and L+V+T jamo → precomposed
    /// syllables).
    #[test]
    fn nfc_kats_hangul() {
        let v = UnicodeVersion::CURRENT;
        assert_eq!(v.nfc("\u{1100}\u{1161}"), "\u{AC00}"); // 가
        assert_eq!(v.nfc("\u{1100}\u{1161}\u{11A8}"), "\u{AC01}"); // 각
    }

    /// NFC itself must preserve U+FEFF wherever it appears — stripping the
    /// single *leading* BOM is the G2 pipeline's job, not the normalizer's
    /// (spec line 83; G2 KAT "interior U+FEFF preserved").
    #[test]
    fn nfc_preserves_u_feff() {
        let v = UnicodeVersion::CURRENT;
        assert_eq!(v.nfc("a\u{FEFF}b"), "a\u{FEFF}b");
        assert_eq!(v.nfc("\u{FEFF}x"), "\u{FEFF}x");
    }

    /// ASCII passes through untouched; every KAT input normalizes
    /// deterministically (same bytes on repeat) and idempotently
    /// (NFC(NFC(x)) == NFC(x)).
    #[test]
    fn nfc_is_deterministic_and_idempotent_on_kats() {
        let v = UnicodeVersion::CURRENT;
        assert_eq!(v.nfc("hello, world\n"), "hello, world\n");
        let inputs = [
            "hello, world\n",
            "e\u{0301}",
            "A\u{030A}",
            "\u{212B}",
            "s\u{0323}\u{0307}",
            "s\u{0307}\u{0323}",
            "\u{1100}\u{1161}",
            "\u{1100}\u{1161}\u{11A8}",
            "a\u{FEFF}b",
            "",
        ];
        for input in inputs {
            let once = v.nfc(input);
            assert_eq!(v.nfc(input), once, "non-deterministic on {input:?}");
            assert_eq!(v.nfc(&once), once, "non-idempotent on {input:?}");
        }
    }
}
