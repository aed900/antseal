//! **Reverse coverage** (task F23; the A domain appended by **A38**): every
//! code a registered error family can emit is claimed by a tamper row, by a
//! Q7 seed row, or by an entry naming the task that owes it — never by
//! silence.
//!
//! # The direction Q8's registry cannot check
//!
//! `testdata/tamper/MATRIX.json` maps the **spec's** enumeration (MVP-SPEC.md
//! line 168) onto rows. That is the right check for "did we implement the
//! matrix the spec asks for", and it is structurally incapable of catching a
//! code nobody wrote a spec case for. F11 added **eighteen** such codes in one
//! commit — the strongest possible demonstration that the direction is
//! unguarded — and F18 and F20 have since added rows for codes line 168 never
//! names either.
//!
//! R7 closed exactly this gap on R's own unprefixed namespace
//! (`every_unprefixed_verify_code_has_a_row_or_a_named_owner`) and earned
//! itself immediately by surfacing two unowned codes. This module began as
//! the F-side twin, and it is deliberately *data* rather than a bespoke test,
//! so a further family drops in as one more [`CoverageDomain`] rather than a
//! second implementation. F24's `cbor-` sibling did **not** take that route
//! and recorded why (a concurrent lane); **A38's three A-domain families
//! did**, which is the first evidence that the data design pays.
//!
//! # The three ways a code may be accounted for
//!
//! 1. **A row in a lib-side registry slice.** The common case.
//! 2. **A row that lives in an integration target.** Q7's seed rows and
//!    F20's anchor rows are both in `crates/antseal-core/tests/`, which a lib
//!    test cannot see — so they are named in
//!    [`CoverageDomain::claimed_in_integration_target`], and
//!    `tests/tamper_matrix.rs` checks in the other direction that each named
//!    row really exists and really binds that code. Neither half can go stale
//!    without one of the two turning red.
//! 3. **A named owner.** [`CoverageDomain::owed`] pairs the code with the
//!    task that owes it a row. This is the escape hatch R7's design makes
//!    deliberate: landing a code without a row stays possible, but only as a
//!    recorded statement, never as an omission.
//!
//! # What it is not
//!
//! It is not a claim that every code *should* have a row. Several plainly
//! should not — a representative per cap family may be the right cost/benefit
//! (F22's open call), and a code may even be structurally unreachable through
//! any decode surface. The check's claim is narrower and stronger: whichever
//! of those is true, **somebody wrote it down**.

use super::tamper::{ExpectedOutcome, TamperRow};

/// One error family's reverse-coverage accounting.
///
/// The universe is passed in rather than held here because the exemplar
/// sweeps that define it (`bundle::error::all_code_exemplars` and friends)
/// are `#[cfg(test)]`, while this data must stay visible to the integration
/// target that validates half of it.
pub struct CoverageDomain {
    /// The family, for failure messages.
    pub name: &'static str,
    /// The prefix every code in this family carries (contract §2).
    pub prefix: &'static str,
    /// Codes claimed by rows that live in an **integration target**, paired
    /// with the row id, since a lib test cannot see them.
    pub claimed_in_integration_target: &'static [(&'static str, &'static str)],
    /// Codes with no row yet, paired with the task that owes one.
    pub owed: &'static [(&'static str, &'static str)],
}

impl CoverageDomain {
    /// Codes of `universe` that no `rows` entry claims, that no integration
    /// row claims, and that no task is recorded as owing.
    #[must_use]
    pub fn unaccounted(&self, universe: &[&'static str], rows: &[TamperRow]) -> Vec<&'static str> {
        universe
            .iter()
            .copied()
            .filter(|code| !self.is_accounted(code, rows))
            .collect()
    }

    /// Whether one code is claimed by a row, an integration row, or a named
    /// owner.
    #[must_use]
    pub fn is_accounted(&self, code: &'static str, rows: &[TamperRow]) -> bool {
        rows.iter()
            .any(|row| row.expected == ExpectedOutcome::ErrorCode(code))
            || self
                .claimed_in_integration_target
                .iter()
                .any(|(claimed, _)| *claimed == code)
            || self.owed.iter().any(|(owed, _)| *owed == code)
    }
}

/// The domains this check runs over. **F24 appends its `cbor-` domain here**;
/// nothing else needs to change for it. A38 appended the three A-domain
/// families the same way, which is the mechanism working as F23 designed it:
/// a new family costs one `CoverageDomain` const and one entry here.
pub const DOMAINS: &[&CoverageDomain] = &[&BUNDLE, &MANIFEST, &ANCHOR, &ANCHOR_OTS, &ANCHOR_HEADER];

/// F8's `.sealproof` schema family — 47 codes.
pub const BUNDLE: CoverageDomain = CoverageDomain {
    name: "BundleError",
    prefix: "bundle-",
    // F20's rows live in `tests/tamper_rows_anchor/`, because their base is
    // the hand-rolled wire writer — the only route to a shape F8 made
    // unrepresentable in the typed API.
    claimed_in_integration_target: &[
        (
            "bundle-wrong-length-block-header",
            "anchor-schema-short-block-header",
        ),
        ("bundle-wrong-length-tx-hash", "anchor-schema-short-tx-hash"),
        ("bundle-empty-tx-hashes", "anchor-schema-empty-tx-hashes"),
        (
            "bundle-unknown-anchor-status",
            "anchor-schema-unknown-status",
        ),
        (
            "bundle-ots-upgrade-group-incomplete",
            "anchor-schema-partial-upgrade-group",
        ),
    ],
    owed: &[
        ("bundle-missing-key", "F39 — required-key family"),
        ("bundle-wrong-length-k-u", "F39 — fixed-length-field family"),
        ("bundle-wrong-length-k-m", "F39 — fixed-length-field family"),
        (
            "bundle-wrong-length-unit-salt",
            "F39 — fixed-length-field family",
        ),
        (
            "bundle-wrong-length-path-salt",
            "F39 — fixed-length-field family",
        ),
        (
            "bundle-wrong-length-file-salt",
            "F39 — fixed-length-field family",
        ),
        (
            "bundle-wrong-length-s-root",
            "F39 — fixed-length-field family",
        ),
        (
            "bundle-wrong-length-cover-seed",
            "F39 — fixed-length-field family",
        ),
        (
            "bundle-wrong-length-path-node-hash",
            "F39 — fixed-length-field family",
        ),
        (
            "bundle-wrong-length-storage-nonce",
            "F39 — fixed-length-field family",
        ),
        (
            "bundle-wrong-length-storage-address",
            "F39 — fixed-length-field family",
        ),
        ("bundle-empty-cover", "F39 — empty-container family"),
        (
            "bundle-unsorted-covered-reveals",
            "F39 — ordered-list family",
        ),
        (
            "bundle-unsorted-noncovered-reveals",
            "F39 — ordered-list family",
        ),
        ("bundle-unsorted-touched-files", "F39 — ordered-list family"),
        ("bundle-unsorted-full-reveals", "F39 — ordered-list family"),
        ("bundle-unsorted-cover", "F39 — ordered-list family"),
        ("bundle-unsorted-paths", "F39 — ordered-list family"),
        ("bundle-wrong-cover-entry-arity", "F39 — tuple-arity family"),
        ("bundle-wrong-path-node-arity", "F39 — tuple-arity family"),
        (
            "bundle-ciphertext-too-short",
            "F39 — ciphertext-shape family",
        ),
        (
            "bundle-ciphertext-length-residue",
            "F39 — ciphertext-shape family",
        ),
        (
            "bundle-too-many-ots-anchors",
            "F22 — D10 list cap (`ListTooLong`)",
        ),
        (
            "bundle-too-many-tsa-anchors",
            "F22 — D10 list cap (`ListTooLong`)",
        ),
        (
            "bundle-too-many-intermediates",
            "F22 — D10 list cap (`ListTooLong`)",
        ),
        (
            "bundle-too-many-tx-hashes",
            "F22 — D10 list cap (`ListTooLong`)",
        ),
        (
            "bundle-too-many-covered-reveals",
            "F22 — D10 list cap (`ListTooLong`)",
        ),
        (
            "bundle-too-many-noncovered-reveals",
            "F22 — D10 list cap (`ListTooLong`)",
        ),
        (
            "bundle-too-many-cover-entries",
            "F22 — D10 list cap (`ListTooLong`)",
        ),
        (
            "bundle-too-many-path-nodes",
            "F22 — D10 list cap (`ListTooLong`)",
        ),
        (
            "bundle-too-many-touched-files",
            "F22 — D10 list cap (`ListTooLong`)",
        ),
        (
            "bundle-too-many-full-reveals",
            "F22 — D10 list cap (`ListTooLong`)",
        ),
        (
            "bundle-ots-too-large",
            "F22 — D10 opaque-artifact cap (`ArtifactTooLarge`)",
        ),
        (
            "bundle-tsa-token-too-large",
            "F22 — D10 opaque-artifact cap (`ArtifactTooLarge`)",
        ),
        (
            "bundle-cert-too-large",
            "F22 — D10 opaque-artifact cap (`ArtifactTooLarge`)",
        ),
        (
            "bundle-receipt-payload-too-large",
            "F22 — D10 opaque-artifact cap (`ArtifactTooLarge`)",
        ),
        (
            "bundle-unit-revealed-twice",
            "F39 — cross-field consistency family",
        ),
        (
            "bundle-full-reveal-without-touched-file",
            "F39 — cross-field consistency family",
        ),
    ],
};

/// F5's manifest schema family — 48 codes.
pub const MANIFEST: CoverageDomain = CoverageDomain {
    name: "ManifestError",
    prefix: "manifest-",
    // Every manifest row so far is lib-side (F15's and F18's slices).
    claimed_in_integration_target: &[],
    owed: &[
        ("manifest-missing-key", "F39 — required-key family"),
        (
            "manifest-wrong-length-seal-id",
            "F39 — fixed-length-field family",
        ),
        (
            "manifest-wrong-length-path-commit",
            "F39 — fixed-length-field family",
        ),
        (
            "manifest-wrong-length-raw-commit",
            "F39 — fixed-length-field family",
        ),
        (
            "manifest-wrong-length-canon-commit",
            "F39 — fixed-length-field family",
        ),
        (
            "manifest-wrong-length-unit-commit",
            "F39 — fixed-length-field family",
        ),
        (
            "manifest-wrong-length-fine-root",
            "F39 — fixed-length-field family",
        ),
        (
            "manifest-wrong-length-nonce",
            "F39 — fixed-length-field family",
        ),
        (
            "manifest-wrong-length-address",
            "F39 — fixed-length-field family",
        ),
        (
            "manifest-wrong-length-pubkey-ed25519",
            "F39 — fixed-length-field family",
        ),
        (
            "manifest-wrong-length-pubkey-ml-dsa-65",
            "F39 — fixed-length-field family",
        ),
        (
            "manifest-wrong-length-signature-ed25519",
            "F39 — fixed-length-field family",
        ),
        (
            "manifest-wrong-length-signature-ml-dsa-65",
            "F39 — fixed-length-field family",
        ),
        (
            "manifest-unexpected-canon-commit",
            "F39 — conditional-field family (present iff)",
        ),
        (
            "manifest-missing-canon-commit",
            "F39 — conditional-field family (present iff)",
        ),
        (
            "manifest-unexpected-fine-root",
            "F39 — conditional-field family (present iff)",
        ),
        (
            "manifest-missing-fine-root",
            "F39 — conditional-field family (present iff)",
        ),
        (
            "manifest-unexpected-fine-tree-domain",
            "F39 — conditional-field family (present iff)",
        ),
        (
            "manifest-missing-fine-tree-domain",
            "F39 — conditional-field family (present iff)",
        ),
        (
            "manifest-unexpected-unicode-version",
            "F39 — conditional-field family (present iff)",
        ),
        (
            "manifest-missing-unicode-version",
            "F39 — conditional-field family (present iff)",
        ),
        (
            "manifest-unexpected-unit-commit",
            "F39 — conditional-field family (present iff)",
        ),
        (
            "manifest-missing-unit-commit",
            "F39 — conditional-field family (present iff)",
        ),
        ("manifest-empty-files", "F39 — empty-container family"),
        ("manifest-empty-units", "F39 — empty-container family"),
        ("manifest-empty-pubkeys", "F39 — empty-container family"),
        ("manifest-empty-signatures", "F39 — empty-container family"),
        (
            "manifest-empty-normal-units",
            "F22 — D77 §6's mirror-only row (blocked on F25's span primitive)",
        ),
        (
            "manifest-unknown-descriptor-kind",
            "F39 — closed-enum family",
        ),
        (
            "manifest-unknown-fine-tree-domain",
            "F39 — closed-enum family",
        ),
        ("manifest-unknown-unit-kind", "F39 — closed-enum family"),
        (
            "manifest-unknown-fine-tree-flag",
            "F39 — closed-enum family",
        ),
        (
            "manifest-unregistered-alg-sig-policy",
            "F39 — sig-policy/algorithm family",
        ),
        (
            "manifest-duplicate-alg-sig-policy",
            "F39 — sig-policy/algorithm family",
        ),
        (
            "manifest-unregistered-alg-pubkeys",
            "F39 — sig-policy/algorithm family",
        ),
        (
            "manifest-duplicate-alg-pubkeys",
            "F39 — sig-policy/algorithm family",
        ),
        (
            "manifest-unregistered-alg-signatures",
            "F39 — sig-policy/algorithm family",
        ),
        (
            "manifest-duplicate-alg-signatures",
            "F39 — sig-policy/algorithm family",
        ),
        ("manifest-too-many-files", "F22 — D10 input/list cap"),
        ("manifest-too-many-units", "F22 — D10 input/list cap"),
        ("manifest-too-large", "F22 — D10 input/list cap"),
        ("manifest-wrong-range-arity", "F39 — tuple-arity family"),
        (
            "manifest-descriptor-domain-mismatch",
            "F39 — cross-field consistency family",
        ),
        (
            "manifest-sig-policy-empty",
            "F39 — sig-policy/algorithm family",
        ),
        (
            "manifest-unit-id-mismatch",
            "F39 — cross-field consistency family",
        ),
    ],
};

// ─────────────────────────────────────────────────────────────────────
// The A domain (task A38)
// ─────────────────────────────────────────────────────────────────────
//
// **Three families, one prefix.** D91 §6.1 rules that A has exactly one
// namespace, `anchor-`, so all three share [`CoverageDomain::prefix`] and the
// domains are distinguished by `name`. That is why `universe_of` below
// dispatches on the name rather than the prefix: keying a lookup on the
// prefix silently merges two families the moment a domain gains a sibling,
// and the A domain arrived with two siblings at once.
//
// **Nothing here is claimed by a row yet, and that is the honest state.**
// `testdata/tamper/MATRIX.json` pends eight M2 anchor cases and every one is
// owned by A21; none is an implemented `TamperRow`, so
// `claimed_in_integration_target` — which `tests/tamper_matrix.rs` validates
// in the other direction against *live* rows — would be a false claim for all
// three families. Every code is therefore accounted for by a **named owner**,
// which is the third of §4b layer 4's three ways and the one G22's
// `content-canonicalize-invalid-utf8` established.
//
// **What that leaves this check biting on**, since a list of owners could
// otherwise read as a formality: a *new* A code minted without an entry goes
// red, and a code recorded here that no variant emits any more goes red in
// the other direction (`the_coverage_accounting_is_not_stale`). Between them
// they are the reverse-coverage direction §4b layer 4 names and the direction
// D91 §8 found unenforced for this whole domain.
//
// The suites the owner strings refer to, named once here rather than 52
// times: `tests/der_pin_eval.rs` and `tests/anchor_caps.rs` (A5),
// `tests/anchor_real_tokens.rs` (A8, nine real TSA responses),
// `tests/anchor_ots_blast_radius.rs` (A11).

/// A5/A8's RFC 3161 / RFC 5652 / X.509 family — 35 codes, ten of them fixed
/// by resolved decisions (D60 §7.3, D53 §8, D59 §5) and 25 minted by A8's
/// Accept row for outcomes no decision enumerated, reviewed at Q73.
pub const ANCHOR: CoverageDomain = CoverageDomain {
    name: "AnchorError",
    prefix: "anchor-",
    claimed_in_integration_target: &[],
    owed: &[
        (
            "anchor-der-not-strict",
            "A21 - MATRIX.json pending row `anchor-ber-not-der`; `expected` null until Q75",
        ),
        (
            "anchor-der-malformed",
            "A21 - row or recorded non-row; A5's strict-DER suite drives it",
        ),
        (
            "anchor-der-nesting-depth",
            "A21 - row or recorded non-row; A5's strict-DER suite drives it",
        ),
        (
            "anchor-chain-cert-count",
            "A21 - row or recorded non-row; A5's cap suite drives it at cap and cap+1",
        ),
        (
            "anchor-chain-cert-size",
            "A21 - row or recorded non-row; A5's cap suite drives it at cap and cap+1",
        ),
        (
            "anchor-signed-attr-count",
            "A21 - row or recorded non-row; A5's cap suite drives it at cap and cap+1",
        ),
        (
            "anchor-tsa-status-not-granted",
            "A21 - row or recorded non-row; A5's response-envelope suite drives it",
        ),
        (
            "anchor-tsa-token-absent",
            "A21 - row or recorded non-row; A5's response-envelope suite drives it",
        ),
        (
            "anchor-cms-not-signed-data",
            "A21 - row or recorded non-row; A8's CMS suite drives it from real tokens",
        ),
        (
            "anchor-cms-not-tst-info",
            "A21 - row or recorded non-row; A8's CMS suite drives it from real tokens",
        ),
        (
            "anchor-cms-econtent-absent",
            "A21 - row or recorded non-row; A8's CMS suite drives it from real tokens",
        ),
        (
            "anchor-cms-signer-count",
            "A21 - row or recorded non-row; A8's CMS suite drives it from real tokens",
        ),
        (
            "anchor-cms-signed-attrs-absent",
            "A21 - row or recorded non-row; A8's CMS suite drives it from real tokens",
        ),
        (
            "anchor-cms-attr-duplicate",
            "A21 - row or recorded non-row; A8's CMS suite drives it from real tokens",
        ),
        (
            "anchor-cms-attr-not-single-valued",
            "A21 - row or recorded non-row; A8's CMS suite drives it from real tokens",
        ),
        (
            "anchor-cms-content-type-attr-missing",
            "A21 - row or recorded non-row; A8's CMS suite drives it from real tokens",
        ),
        (
            "anchor-cms-content-type-attr-mismatch",
            "A21 - row or recorded non-row; A8's CMS suite drives it from real tokens",
        ),
        (
            "anchor-cms-message-digest-attr-missing",
            "A21 - row or recorded non-row; A8's CMS suite drives it from real tokens",
        ),
        (
            "anchor-cms-message-digest-attr-mismatch",
            "A21 - row or recorded non-row; A8's CMS suite drives it from real tokens",
        ),
        (
            "anchor-cms-signature-invalid",
            "A21 - row or recorded non-row; A8's CMS suite drives it from real tokens",
        ),
        (
            "anchor-cms-signer-id-unsupported",
            "A21 - row or recorded non-row; A8's CMS suite drives it from real tokens",
        ),
        (
            "anchor-signer-cert-not-found",
            "A21 - row or recorded non-row; A8's CMS suite drives it from real tokens",
        ),
        (
            "anchor-esscert-attr-missing",
            "A21 - row or recorded non-row; A8's CMS suite drives it from real tokens",
        ),
        (
            "anchor-esscert-empty",
            "A21 - row or recorded non-row; A8's CMS suite drives it from real tokens",
        ),
        (
            "anchor-esscert-mismatch",
            "A21 - row or recorded non-row; A8's CMS suite drives it from real tokens",
        ),
        (
            "anchor-eku-missing",
            "A21 - row or recorded non-row; A8's CMS suite drives it from real tokens",
        ),
        (
            "anchor-eku-not-critical",
            "A21 - row or recorded non-row; A8's CMS suite drives it from real tokens",
        ),
        (
            "anchor-eku-no-timestamping",
            "A21 - row or recorded non-row; A8's CMS suite drives it from real tokens",
        ),
        (
            "anchor-tst-version-unsupported",
            "A21 - row or recorded non-row; A8's CMS suite drives it from real tokens",
        ),
        (
            "anchor-tsa-imprint-mismatch",
            "A21 - MATRIX.json pending row `anchor-tsa-imprint-mismatch` (D53 S8 row 2)",
        ),
        (
            "anchor-tsa-nonce-mismatch",
            "A10 - owner-backed; NO bundle tamper row is possible (contract S2)",
        ),
        (
            "anchor-digest-alg-unsupported",
            "A21 - row or recorded non-row; A8's CMS suite drives it from real tokens",
        ),
        (
            "anchor-signature-alg-unsupported",
            "A21 - row or recorded non-row; A8's CMS suite drives it from real tokens",
        ),
        (
            "anchor-spki-unsupported",
            "A21 - row or recorded non-row; A8's CMS suite drives it from real tokens",
        ),
        (
            "anchor-key-alg-mismatch",
            "A21 - row or recorded non-row; A8's CMS suite drives it from real tokens",
        ),
    ],
};

/// A11's `.ots` codec family — 16 codes: fifteen minted by A11 as D91 §7.1's
/// mechanical renames of D58 §10.4's list, plus D56's
/// `anchor-ots-digest-mismatch`, which A11 raises rather than mints.
pub const ANCHOR_OTS: CoverageDomain = CoverageDomain {
    name: "OtsError",
    prefix: "anchor-",
    claimed_in_integration_target: &[],
    owed: &[
        (
            "anchor-ots-bad-magic",
            "A21 - row or recorded non-row; A11's codec suite drives it from real bytes",
        ),
        (
            "anchor-ots-unsupported-version",
            "A21 - row or recorded non-row; A11's codec suite drives it from real bytes",
        ),
        (
            "anchor-ots-unsupported-digest-type",
            "A21 - row or recorded non-row; A11's codec suite drives it from real bytes",
        ),
        (
            "anchor-ots-truncated",
            "A21 - row or recorded non-row; A11's codec suite drives it from real bytes",
        ),
        (
            "anchor-ots-trailing-bytes",
            "A21 - row or recorded non-row; A11's codec suite drives it from real bytes",
        ),
        (
            "anchor-ots-varint-too-long",
            "A21 - row or recorded non-row; A11's codec suite drives it from real bytes",
        ),
        (
            "anchor-ots-digest-mismatch",
            "A21 - MATRIX.json pending row `anchor-ots-digest-mismatch` (D56 O2 / D91 S6.2)",
        ),
        (
            "anchor-ots-too-many-ops",
            "A21 - row or recorded non-row; A11's codec suite drives it from real bytes",
        ),
        (
            "anchor-ots-too-deep",
            "A21 - row or recorded non-row; A11's codec suite drives it from real bytes",
        ),
        (
            "anchor-ots-branch-too-wide",
            "A21 - row or recorded non-row; A11's codec suite drives it from real bytes",
        ),
        (
            "anchor-ots-too-many-attestations",
            "A21 - row or recorded non-row; A11's codec suite drives it from real bytes",
        ),
        (
            "anchor-ots-operand-too-long",
            "A21 - row or recorded non-row; A11's codec suite drives it from real bytes",
        ),
        (
            "anchor-ots-value-too-long",
            "A21 - row or recorded non-row; A11's codec suite drives it from real bytes",
        ),
        (
            "anchor-ots-attestation-payload-too-long",
            "A21 - row or recorded non-row; A11's codec suite drives it from real bytes",
        ),
        (
            "anchor-ots-attestation-payload-not-consumed",
            "A21 - row or recorded non-row; A11's codec suite drives it from real bytes",
        ),
        (
            "anchor-ots-unknown-op",
            "A21 - row or recorded non-row; A11's codec suite drives it from real bytes",
        ),
    ],
};

/// A12's embedded-header family — **one code, and it is not an error code**.
///
/// `anchor-ots-header-uncommitted` (D56 rule O8) is a `const` on
/// `EmbeddedHeader`, not a `code()` arm: A12 answers one offline question and
/// deliberately does not own an `AnchorState`, so the code travels as a
/// diagnostic string that A18 attaches to a verdict. It is a family of one for
/// exactly that reason, and it is registered rather than skipped because a
/// code outside every enumerator is a code that can be renamed with a fully
/// green suite — the hole Q52 exists to close, reopened for one string.
///
/// It is the first member of a shape the A domain will have more of: D56's
/// `anchor-ots-online-header-mismatch` and `anchor-ots-online-block-absent`
/// (rules O6/O7) are the same kind and are **not** registered here, because
/// A18 has not landed them and a snapshot may only carry codes something
/// actually emits.
pub const ANCHOR_HEADER: CoverageDomain = CoverageDomain {
    name: "EmbeddedHeader",
    prefix: "anchor-",
    claimed_in_integration_target: &[],
    owed: &[(
        "anchor-ots-header-uncommitted",
        "A21 - row or recorded non-row; A12's embedded-header suite drives it offline",
    )],
};

#[cfg(test)]
mod tests {
    use super::*;

    /// Every code `BundleError` can emit.
    fn bundle_universe() -> Vec<&'static str> {
        crate::bundle::error::all_code_exemplars()
            .iter()
            .map(crate::bundle::BundleError::code)
            .collect()
    }

    /// Every code `ManifestError` can emit.
    fn manifest_universe() -> Vec<&'static str> {
        crate::manifest::error::all_code_exemplars()
            .iter()
            .map(crate::manifest::ManifestError::code)
            .collect()
    }

    /// Every code `AnchorError` can emit (A5/A8).
    fn anchor_universe() -> Vec<&'static str> {
        crate::anchor::error::all_code_exemplars()
            .iter()
            .map(crate::anchor::AnchorError::code)
            .collect()
    }

    /// Every code `OtsError` can emit (A11).
    fn anchor_ots_universe() -> Vec<&'static str> {
        crate::anchor::ots::all_code_exemplars()
            .iter()
            .map(crate::anchor::ots::OtsError::code)
            .collect()
    }

    /// A12's one diagnostic code, which lives on a `const` rather than in an
    /// error enum.
    fn anchor_header_universe() -> Vec<&'static str> {
        vec![crate::anchor::ots::EmbeddedHeader::UNCOMMITTED_CODE]
    }

    /// Dispatch on the **name**, not the prefix.
    ///
    /// D91 §6.1 gives the whole A domain one prefix, so three of the five
    /// domains answer `"anchor-"`. Keying this lookup on the prefix — as it
    /// did until A38 — would have handed `OtsError` the `AnchorError`
    /// universe: every `anchor-ots-*` code reported unaccounted, and one
    /// family swept twice.
    fn universe_of(domain: &CoverageDomain) -> Vec<&'static str> {
        match domain.name {
            "BundleError" => bundle_universe(),
            "ManifestError" => manifest_universe(),
            "AnchorError" => anchor_universe(),
            "OtsError" => anchor_ots_universe(),
            "EmbeddedHeader" => anchor_header_universe(),
            other => panic!("no universe wired for the `{other}` domain"),
        }
    }

    /// Every domain in [`DOMAINS`] has a universe wired, no two share a name,
    /// and none is empty.
    ///
    /// Without this, adding a `CoverageDomain` and forgetting the
    /// `universe_of` arm is a panic in one test rather than a statement; two
    /// domains sharing a name makes the dispatch silently ambiguous — the
    /// failure the prefix key already had — and an empty universe is a
    /// reverse-coverage check over nothing.
    #[test]
    fn every_registered_domain_has_a_wired_universe() {
        let mut names: Vec<&str> = Vec::new();
        for domain in DOMAINS {
            assert!(
                !names.contains(&domain.name),
                "two coverage domains are named `{}`; the `universe_of` dispatch cannot tell \
                 them apart",
                domain.name
            );
            names.push(domain.name);
            assert!(
                !universe_of(domain).is_empty(),
                "`{}` has an empty universe — a reverse-coverage check over nothing is the \
                 purest form of a check that cannot fail",
                domain.name
            );
        }
        assert_eq!(
            names.len(),
            5,
            "the coverage-domain roster changed size; a family added to `DOMAINS` needs a \
             `universe_of` arm, and a family REMOVED from it stops being swept at all"
        );
    }

    /// Every row registered on the **lib** side, whichever domain owns it.
    ///
    /// Read from the slices rather than from a hand-kept list, so a row
    /// landing in any domain counts immediately.
    fn lib_rows() -> Vec<TamperRow> {
        let mut rows = Vec::new();
        rows.extend_from_slice(super::super::tamper_rows_crypto::ROWS);
        rows.extend_from_slice(super::super::tamper_rows_fine_tree::ROWS);
        rows.extend_from_slice(super::super::tamper_rows_format::ROWS);
        rows.extend_from_slice(super::super::tamper_rows_mirror::ROWS);
        rows.extend_from_slice(super::super::tamper_rows_version::ROWS);
        rows.extend_from_slice(super::super::tamper_rows_structural::ROWS);
        rows.extend_from_slice(super::super::tamper_rows_pipeline::ROWS);
        rows
    }

    /// **F23, extended to the A domain by A38.** Every code of every
    /// registered domain is claimed by a row, by a named integration row, or
    /// by a task recorded as owing one.
    ///
    /// Renamed at A38 from every_f_side_code_has_a_row_or_a_named_owner
    /// (unbackticked: Q69's guard reads a backticked test name as a live
    /// pointer, and this is a record of one that is gone), when A38
    /// appended `AnchorError`, `OtsError` and `EmbeddedHeader` to [`DOMAINS`]:
    /// the sweep is no longer F-side, and a guard whose name asserts something
    /// false is the defect this project keeps finding in its own prose.
    #[test]
    fn every_registered_domain_code_has_a_row_or_a_named_owner() {
        let rows = lib_rows();
        let mut report = String::new();
        for domain in DOMAINS {
            let unaccounted = domain.unaccounted(&universe_of(domain), &rows);
            if !unaccounted.is_empty() {
                report.push_str(&format!(
                    "\n{} ({} unaccounted): {unaccounted:?}",
                    domain.name,
                    unaccounted.len()
                ));
            }
        }
        assert!(
            report.is_empty(),
            "these codes have no tamper row and no named owner:{report}\n\
             A new schema rejection class needs a row, an entry in \
             `claimed_in_integration_target` naming the row that binds it, or an entry in \
             `owed` naming the task that owes it — the whole point of this check is that the \
             third option is a deliberate, reviewed statement rather than silence."
        );
    }

    /// The accounting must not go stale in the other direction: a code
    /// recorded as owed or as claimed elsewhere must still be a real code of
    /// its family, and must not *also* be claimed by a lib row.
    #[test]
    fn the_coverage_accounting_is_not_stale() {
        let rows = lib_rows();
        for domain in DOMAINS {
            let universe = universe_of(domain);
            for (code, note) in domain
                .claimed_in_integration_target
                .iter()
                .chain(domain.owed)
            {
                assert!(
                    universe.contains(code),
                    "{}: `{code}` ({note}) is recorded in a coverage list, but no variant emits \
                     it",
                    domain.name
                );
                assert!(
                    !rows
                        .iter()
                        .any(|row| row.expected == ExpectedOutcome::ErrorCode(code)),
                    "{}: `{code}` is recorded as covered elsewhere AND claimed by a lib row — \
                     check_registry would refuse the pair",
                    domain.name
                );
            }
            for code in &universe {
                assert!(
                    code.starts_with(domain.prefix),
                    "{}: `{code}` does not carry the family prefix `{}`",
                    domain.name,
                    domain.prefix
                );
            }
        }
    }

    /// A code appears in **at most one** accounting list, so "who owes this"
    /// always has one answer.
    #[test]
    fn no_code_is_accounted_for_twice() {
        for domain in DOMAINS {
            for (code, _) in domain.claimed_in_integration_target {
                assert!(
                    !domain.owed.iter().any(|(owed, _)| owed == code),
                    "{}: `{code}` is both claimed by a row and recorded as owed",
                    domain.name
                );
            }
            let mut seen: Vec<&str> = Vec::new();
            for (code, _) in domain
                .owed
                .iter()
                .chain(domain.claimed_in_integration_target)
            {
                assert!(
                    !seen.contains(code),
                    "{}: `{code}` listed twice",
                    domain.name
                );
                seen.push(code);
            }
        }
    }

    /// **Test of the test.** A code the universe contains and no list
    /// mentions is reported — the state the check exists to make impossible
    /// to reach silently.
    ///
    /// Stands in for minting a throwaway variant: a fabricated code is
    /// indistinguishable, from the check's point of view, from a real one
    /// nobody rowed.
    #[test]
    fn the_check_goes_red_on_an_unowned_code() {
        let domain = CoverageDomain {
            name: "Fabricated",
            prefix: "bundle-",
            claimed_in_integration_target: &[],
            owed: &[("bundle-owed-exemplar", "F39")],
        };
        let universe = ["bundle-owed-exemplar", "bundle-nobody-owns-this"];
        assert_eq!(
            domain.unaccounted(&universe, &[]),
            vec!["bundle-nobody-owns-this"],
            "an unowned code must be reported, and an owed one must not"
        );
    }
}
