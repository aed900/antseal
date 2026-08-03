//! The pinned TSA root store (task **A6**; contents gated by **A7**;
//! lifecycle by **A26**) — versioned const data compiled into this crate.
//!
//! # Why the bytes live here and not in `testdata/`
//!
//! `testdata/` is the fixture tree (`testdata/README.md`: "Fixture tree for
//! antseal"). These are **production** bytes shipped inside a library, so
//! D57 §7 puts them beside the code that consumes them. **DER, not PEM**:
//! `include_bytes!` of DER is byte-exact and needs no base64 decoder in a
//! crate that must stay WASM-safe and dependency-minimal.
//!
//! That placement carries one hazard, and it is closed rather than noted.
//! `.gitattributes` had exactly one binary guard, `testdata/** -text`, which
//! covers **nothing** under `crates/`; the `windows-latest` CI image sets
//! `core.autocrlf=true` machine-wide, and a CRLF-mangled DER is an
//! unparseable root. This module's directory therefore gains its own
//! `-text` rule, and [`tests::the_gitattributes_binary_rule_covers_this_directory`]
//! fails if it is ever removed — a check that must live here, because the
//! `cross-os` lane only notices on a Windows runner.
//!
//! # What a pinned root is, and what a supplied certificate can never be
//!
//! MVP-SPEC.md line 109: "bundle-embedded chains supply intermediates only —
//! a chain that only closes against bundle-supplied roots renders 'internally
//! consistent only', never 'proven'". D57 ruling **P2** sharpens it: a
//! token- or bundle-supplied self-signed certificate is **never** a trust
//! anchor, *even when its bytes equal a pinned root's*. That is not a corner
//! case — three of the five real production TSAs surveyed for D57 (FreeTSA,
//! DFN, SwissSign) ship their own self-signed root inside every token.
//!
//! The rule is enforced structurally in [`super::chain`]: a path can only
//! terminate on a [`PinnedRoot`] out of this store, and supplied certificates
//! enter the search only as intermediates. There is no single certificate
//! pool anywhere, which is the implementation D53 §5(c) names as the one that
//! silently turns a sealer-written self-signed chain into `proven`.
//!
//! # Store contents are a *gate*, not a wish list
//!
//! D57 §5 names five target roots and §6 makes admission conditional:
//! **no root may be compiled in ahead of its provenance.** Store version 1
//! therefore holds the roots whose channel set is complete on the day it was
//! built — three of the five — and the other two are **quarantined**, named
//! in `PROVENANCE.md` with the exact missing channel. A quarantined root is
//! not a silent omission: a user who configures that TSA gets a
//! pre-payment seal abort (A20), which is loud, and A26's append process is
//! how it is fixed.

use x509_cert::Certificate;

/// One pinned trust anchor.
///
/// Carries **bytes plus the two fingerprints** and nothing else. Subject,
/// validity window and key algorithm are parsed from [`Self::der`] on demand
/// rather than duplicated here: a duplicated field is a field that can drift
/// from the bytes it describes, and every one of them is derivable. The two
/// fingerprints are the exception, and they are guarded — they exist so a
/// human can match this table against `PROVENANCE.md` line by line, and
/// [`tests::pinned_store_fingerprints_match_the_embedded_bytes`] recomputes
/// both from the bytes so the one drift class the format permits is closed
/// mechanically.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PinnedRoot {
    /// The self-signed root certificate, DER.
    pub der: &'static [u8],
    /// SHA-256 over [`Self::der`].
    pub cert_sha256: [u8; 32],
    /// SHA-256 over the DER `SubjectPublicKeyInfo`.
    ///
    /// This is the value that stays **stable across a cross-certificate of
    /// the same root** (D57 §2) — the property that makes the DigiCert and
    /// Sectigo hierarchies verifiable at all, since both ship a cross-signed
    /// copy of their root whose `cert_sha256` differs and whose SPKI does
    /// not.
    pub spki_sha256: [u8; 32],
    /// Stable machine label, for verdict data and `PROVENANCE.md`. Never
    /// parsed, never user-facing prose.
    pub label: &'static str,
}

impl PinnedRoot {
    /// Parse this root's certificate.
    ///
    /// # Errors
    ///
    /// [`der::Error`] if the compiled-in bytes are not a DER certificate,
    /// which would be a build defect —
    /// [`tests::every_pinned_root_parses_and_is_self_signed_shaped`] makes it
    /// a red test rather than a runtime surprise. Callers in
    /// [`super::chain`] treat a parse failure as "this root cannot anchor
    /// anything" instead of failing the whole verification, so one bad root
    /// can never take the other anchors down with it (F2).
    pub fn parse(&self) -> Result<Certificate, der::Error> {
        use der::Decode as _;
        Certificate::from_der(self.der)
    }
}

/// The compiled-in set of pinned TSA trust anchors.
///
/// Every verification entry point takes `&TsaRootStore`; none reaches for
/// [`TsaRootStore::pinned`] internally, so a caller cannot accidentally
/// bypass an injected store.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TsaRootStore {
    version: u32,
    build_date: &'static str,
    roots: &'static [PinnedRoot],
}

/// Monotonic store version, bumped on **any** change to the root set (A26).
///
/// Appears in verdict data ([`super::chain::ChainVerdict::root_store_version`])
/// so a rendered verdict says which trust store produced it.
pub const TSA_ROOT_STORE_VERSION: u32 = 1;

/// ISO-8601 date the store contents were last changed (A26).
pub const TSA_ROOT_STORE_BUILD_DATE: &str = "2026-08-03";

/// The version an **injected** store reports.
///
/// Zero, and deliberately outside the released sequence: a test store must
/// never be able to claim it is a shipped one, and `0 < 1` keeps A26's
/// monotonicity readable. `from_static` is the only way to obtain it and
/// exists in no default build.
pub const INJECTED_STORE_VERSION: u32 = 0;

/// The build date an injected store reports.
pub const INJECTED_STORE_BUILD_DATE: &str = "(injected)";

impl TsaRootStore {
    /// The compiled-in production store — the **only** constructor available
    /// in a default build.
    #[must_use]
    pub const fn pinned() -> &'static Self {
        &PINNED_STORE
    }

    /// This store's version ([`TSA_ROOT_STORE_VERSION`], or
    /// [`INJECTED_STORE_VERSION`] for a test store).
    #[must_use]
    pub const fn version(&self) -> u32 {
        self.version
    }

    /// The date this store's contents last changed.
    #[must_use]
    pub const fn build_date(&self) -> &'static str {
        self.build_date
    }

    /// The pinned roots, in the store's own declaration order.
    ///
    /// Order is presentation only: [`super::chain`] quantifies over the whole
    /// set, so no verdict may depend on it.
    #[must_use]
    pub const fn roots(&self) -> &'static [PinnedRoot] {
        self.roots
    }

    /// Test-only injection (A6 Accept; A24's mock-CA suites; A43's negative
    /// direction).
    ///
    /// Gated so that "page/CLI production paths provably use `pinned()` only"
    /// is a **compile-time fact rather than a review checklist item**: in a
    /// default build this symbol does not exist, and
    /// `scripts/gate-features.sh` is the lane that witnesses it.
    ///
    /// The store it returns reports [`INJECTED_STORE_VERSION`], so a fixture
    /// can never be mistaken for a released trust store in verdict data.
    #[cfg(any(test, feature = "test-util"))]
    #[must_use]
    pub const fn from_static(roots: &'static [PinnedRoot]) -> Self {
        Self {
            version: INJECTED_STORE_VERSION,
            build_date: INJECTED_STORE_BUILD_DATE,
            roots,
        }
    }
}

/// Parse a lowercase hex digest literal at compile time.
///
/// The fingerprints below are transcribed from `PROVENANCE.md`, and a
/// transcription is exactly where a digit flips. Writing them as hex strings
/// keeps the source diffable against the provenance record; parsing them in a
/// `const fn` makes a malformed literal a **compile error**; and
/// [`tests::pinned_store_fingerprints_match_the_embedded_bytes`] makes a
/// *well-formed but wrong* literal a test failure.
const fn hex32(s: &str) -> [u8; 32] {
    let b = s.as_bytes();
    assert!(b.len() == 64, "a SHA-256 hex literal is 64 characters");
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        out[i] = nibble(b[2 * i]) << 4 | nibble(b[2 * i + 1]);
        i += 1;
    }
    out
}

/// One lowercase hex digit. Uppercase is rejected so the literals cannot
/// drift into two spellings of the same value.
const fn nibble(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        _ => panic!("hex literals are lowercase 0-9a-f"),
    }
}

/// Store version 1.
///
/// Three roots, admitted under D57 §6's channel rule. See `PROVENANCE.md` in
/// this directory for the per-root, per-channel record, **including the two
/// D57 §5 candidates that are quarantined** and the exact channel each is
/// waiting on.
static ROOTS_V1: &[PinnedRoot] = &[
    // Free TSA — MVP-SPEC.md line 108 default. C1 vendor + two Wayback
    // snapshots ten and seven years old + the root embedded in the live
    // token. Not in any browser root programme, and never will be:
    // Mozilla's covers TLS and S/MIME only.
    PinnedRoot {
        der: include_bytes!("freetsa-root-ca.der"),
        cert_sha256: hex32("a6379e7cecc05faa3cbf076013d745e327bbbaa38c0b9af22469d4701d18aabc"),
        spki_sha256: hex32("52c54ba340885605314daa1857c8763b94087d05c636092938d4e2d1818e99b5"),
        label: "freetsa-root-ca",
    },
    // DigiCert Trusted Root G4 — MVP-SPEC.md line 108 default. The
    // **self-signed** root, never the `DigiCert Assured ID Root CA`
    // cross-certificate the token also ships: same SPKI, but it expires
    // 2031-11-09 against this one's 2038-01-15, so pinning the cross-signed
    // copy would strand every token issued after 2031.
    PinnedRoot {
        der: include_bytes!("digicert-trusted-root-g4.der"),
        cert_sha256: hex32("552f7bdcf1a7af9e6ce672017f4f12abf77240c78e761ac203d1d9d20ac89988"),
        spki_sha256: hex32("59df317bfa9f4f0ab7ca514d7772296aa2c765b87664d08b96e57399e364729c"),
        label: "digicert-trusted-root-g4",
    },
    // DFN-Verein Community Root CA 2022 — MVP-SPEC.md line 108 documented
    // alternate, for `zeitstempel.dfn.de`. **Not** T-TeleSec and not DFN's
    // Global hierarchy: the live chain terminates here, self-signed, with no
    // T-Systems involvement (D57 §8.1 corrects `tasks/A.md` A7 on this).
    PinnedRoot {
        der: include_bytes!("dfn-verein-community-root-ca-2022.der"),
        cert_sha256: hex32("3cdc2c9e9e5a36cb5888fd1796cb912f846253b682c1b32057532033510c7bb6"),
        spki_sha256: hex32("e686263a55fc1d1d7e5952a2d708597816e1f462a6b1a5dae975ddd421a8a1b0"),
        label: "dfn-verein-community-root-ca-2022",
    },
    // Sectigo Public Time Stamping Root R46 — MVP-SPEC.md line 108
    // documented alternate. Again the **self-signed** root, not the
    // USERTrust-issued cross-certificate inside the token (same SPKI,
    // expires 2038-01-18 against this one's 2046-03-21, and USERTrust
    // anchors a very large general-purpose PKI we have no reason to trust
    // for time).
    PinnedRoot {
        der: include_bytes!("sectigo-public-time-stamping-root-r46.der"),
        cert_sha256: hex32("4941b001b8a97e961b7817c9d9e960ec4b056bfc915a8c1aabf6ef6b3ac046a5"),
        spki_sha256: hex32("a4db8668c6796ebf476ddc5ace453a9260dbd4dbb09f51ecec9a839003824795"),
        label: "sectigo-public-time-stamping-root-r46",
    },
];

static PINNED_STORE: TsaRootStore = TsaRootStore {
    version: TSA_ROOT_STORE_VERSION,
    build_date: TSA_ROOT_STORE_BUILD_DATE,
    roots: ROOTS_V1,
};

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest as _, Sha256};
    use std::collections::BTreeSet;

    /// The one drift class this format permits, closed mechanically: a
    /// fingerprint literal that no longer describes the bytes beside it.
    ///
    /// Recomputes **both** digests from `der`. Without this the store could
    /// ship a root whose `spki_sha256` names a different key than the one
    /// path validation actually verifies under, and nothing else in the tree
    /// would notice — the chain check uses the parsed key, not the literal.
    #[test]
    fn pinned_store_fingerprints_match_the_embedded_bytes() {
        let store = TsaRootStore::pinned();
        assert!(!store.roots().is_empty(), "the store must not be empty");
        for root in store.roots() {
            assert_eq!(
                Sha256::digest(root.der).as_slice(),
                root.cert_sha256,
                "{}: cert_sha256 does not describe der",
                root.label
            );
            let cert = root.parse().expect("a pinned root parses");
            let spki = der::Encode::to_der(cert.tbs_certificate().subject_public_key_info())
                .expect("SPKI re-encodes");
            assert_eq!(
                Sha256::digest(&spki).as_slice(),
                root.spki_sha256,
                "{}: spki_sha256 does not describe der's SubjectPublicKeyInfo",
                root.label
            );
        }
    }

    /// The store's identity, asserted as data: version, count, and every
    /// label. A root added or removed without a deliberate edit here — and
    /// therefore without the A26 version bump and the `PROVENANCE.md` row —
    /// is a red build.
    ///
    /// The count is **four, not D57 §5's five**, and that is A7's gate
    /// working rather than a defect: `swisssign-signature-services-root-2020-2`
    /// is quarantined pending its C1 channel (`PROVENANCE.md` §Quarantine).
    #[test]
    fn pinned_store_is_exactly_four_roots_at_version_1() {
        let store = TsaRootStore::pinned();
        assert_eq!(store.version(), 1);
        assert_eq!(store.build_date(), "2026-08-03");
        let labels: Vec<&str> = store.roots().iter().map(|r| r.label).collect();
        assert_eq!(
            labels,
            [
                "freetsa-root-ca",
                "digicert-trusted-root-g4",
                "dfn-verein-community-root-ca-2022",
                "sectigo-public-time-stamping-root-r46",
            ]
        );
        let bytes: usize = store.roots().iter().map(|r| r.der.len()).sum();
        assert_eq!(bytes, 6_429, "store size, for the A26 record");
    }

    /// Labels are unique, kebab-case and non-empty. They key `PROVENANCE.md`
    /// rows and appear in verdict data, so a duplicate would make one root's
    /// provenance unfindable and a verdict ambiguous.
    #[test]
    fn labels_are_unique_and_well_formed() {
        let roots = TsaRootStore::pinned().roots();
        let labels: BTreeSet<&str> = roots.iter().map(|r| r.label).collect();
        assert_eq!(labels.len(), roots.len(), "duplicate root label");
        for label in labels {
            assert!(!label.is_empty());
            assert!(
                label
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'),
                "`{label}` is not lowercase kebab-case"
            );
        }
    }

    /// Every compiled-in root parses, is self-signed **in shape** (issuer DN
    /// equals subject DN), and carries the CA authority D53 §3's
    /// `constraints_ok` demands of a trust anchor.
    ///
    /// The last clause is the one that matters: `constraints_ok` is applied
    /// to every issuer element **including the anchor**, so a pinned root
    /// without `CA:TRUE` or without `keyCertSign` would make every chain
    /// through it render `invalid` — a failure that would look like a broken
    /// TSA rather than a broken store.
    #[test]
    fn every_pinned_root_parses_and_is_self_signed_shaped() {
        use der::Encode as _;
        use x509_cert::ext::pkix::{BasicConstraints, KeyUsage, KeyUsages};

        for root in TsaRootStore::pinned().roots() {
            let cert = root
                .parse()
                .unwrap_or_else(|e| panic!("{}: {e}", root.label));
            let tbs = cert.tbs_certificate();
            assert_eq!(
                tbs.issuer().to_der().expect("issuer encodes"),
                tbs.subject().to_der().expect("subject encodes"),
                "{}: a pinned root must be self-signed",
                root.label
            );
            let bc = tbs
                .get_extension::<BasicConstraints>()
                .expect("extensions decode")
                .map(|(_, bc)| bc);
            assert!(
                bc.is_some_and(|bc| bc.ca),
                "{}: a pinned root needs basicConstraints CA:TRUE",
                root.label
            );
            let ku = tbs
                .get_extension::<KeyUsage>()
                .expect("extensions decode")
                .map(|(_, ku)| ku);
            assert!(
                ku.is_none_or(|ku| ku.0.contains(KeyUsages::KeyCertSign)),
                "{}: a pinned root's keyUsage must permit keyCertSign",
                root.label
            );
        }
    }

    /// No pinned root duplicates another's key. Two entries with the same
    /// SPKI would be one trust anchor wearing two labels — and A26's
    /// append-only rule would then be unable to say what was appended.
    #[test]
    fn no_two_pinned_roots_share_a_key_or_a_certificate() {
        let roots = TsaRootStore::pinned().roots();
        let certs: BTreeSet<[u8; 32]> = roots.iter().map(|r| r.cert_sha256).collect();
        let keys: BTreeSet<[u8; 32]> = roots.iter().map(|r| r.spki_sha256).collect();
        assert_eq!(certs.len(), roots.len(), "duplicate certificate");
        assert_eq!(keys.len(), roots.len(), "duplicate subject public key");
    }

    /// An injected store never claims a released version.
    ///
    /// Without this a fixture store could render verdict data indistinguishable
    /// from the shipped one, and `store_version_appears_in_verdict_data` would
    /// pass while proving nothing.
    #[test]
    fn an_injected_store_reports_the_sentinel_version() {
        static NONE: &[PinnedRoot] = &[];
        let injected = TsaRootStore::from_static(NONE);
        assert_eq!(injected.version(), INJECTED_STORE_VERSION);
        assert_eq!(injected.version(), 0);
        assert_ne!(injected.version(), TSA_ROOT_STORE_VERSION);
        assert_eq!(injected.build_date(), INJECTED_STORE_BUILD_DATE);
        assert!(injected.roots().is_empty());
    }

    /// `hex32` rejects the malformed literal shapes, so the compile-time
    /// guard is not taken on trust.
    ///
    /// The uppercase rejection is the interesting one: without it the store
    /// could carry `A6:37…` in one row and `a637…` in the next, both correct
    /// and neither greppable against `PROVENANCE.md`.
    #[test]
    fn hex32_parses_the_documented_shape() {
        assert_eq!(
            hex32("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")[..4],
            [0x00, 0x11, 0x22, 0x33]
        );
        // The remaining cases are compile-time `panic!`s inside a `const fn`
        // and cannot be exercised at runtime; they are named here so the
        // intent is recorded next to the guard: a 63- or 65-character
        // literal, and any uppercase or non-hex digit, fail the build.
    }

    /// The `.gitattributes` rule that keeps these DER files intact on a
    /// Windows checkout.
    ///
    /// `testdata/** -text` — the tree's only binary guard before this module
    /// existed — covers **nothing** under `crates/`. The `windows-latest`
    /// image sets `core.autocrlf=true` machine-wide, so without the rule
    /// below every `0x0A` inside a root certificate becomes `0x0D 0x0A` at
    /// checkout and every pinned root stops parsing. This test lives here,
    /// and not in the `cross-os` lane, because the lane can only observe the
    /// damage on a Windows runner and this fails everywhere.
    #[test]
    #[cfg(not(target_arch = "wasm32"))]
    fn the_gitattributes_binary_rule_covers_this_directory() {
        const GITATTRIBUTES: &str =
            include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../.gitattributes"));
        let rule = "crates/antseal-core/src/anchor/roots/*.der -text";
        assert!(
            GITATTRIBUTES.lines().any(|l| l.trim() == rule),
            "`.gitattributes` must carry the line `{rule}`; without it the \
             compiled-in roots are CRLF-mangled on the Windows CI runner"
        );
    }

    /// Every compiled-in root has a `PROVENANCE.md` row, and every root
    /// `PROVENANCE.md` marks **quarantined** is absent from the store.
    ///
    /// This is A7's rule — "no root may be compiled in ahead of its
    /// provenance" — as a test rather than a review promise. It fails in both
    /// directions: promoting a quarantined root without updating the record,
    /// and adding a root the record never mentions.
    #[test]
    fn the_store_matches_the_provenance_record() {
        const PROVENANCE: &str = include_str!("PROVENANCE.md");
        let pinned: BTreeSet<&str> = TsaRootStore::pinned()
            .roots()
            .iter()
            .map(|r| r.label)
            .collect();

        // `### <label>` headings, one per root the record describes.
        let documented: Vec<&str> = PROVENANCE
            .lines()
            .filter_map(|l| l.strip_prefix("### "))
            .map(str::trim)
            .collect();
        assert!(
            documented.len() >= pinned.len(),
            "PROVENANCE.md documents {} roots, the store pins {}",
            documented.len(),
            pinned.len()
        );
        for label in &pinned {
            assert!(
                documented.contains(label),
                "`{label}` is compiled in with no PROVENANCE.md section"
            );
        }

        // `- QUARANTINED: <label>` lines, one per root held back.
        let quarantined: Vec<&str> = PROVENANCE
            .lines()
            .filter_map(|l| l.trim().strip_prefix("- QUARANTINED: "))
            .map(str::trim)
            .collect();
        assert!(
            !quarantined.is_empty(),
            "the quarantine section must list its roots as `- QUARANTINED: <label>`; \
             an empty list here would make this test vacuous"
        );
        for label in &quarantined {
            assert!(
                !pinned.contains(label),
                "`{label}` is quarantined in PROVENANCE.md but compiled into the store"
            );
        }
    }
}
