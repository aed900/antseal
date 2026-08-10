//! The anchor-stage structural limits A5 chooses at M2 (D60 §6, §7.1).
//!
//! # What is here and what is deliberately not
//!
//! [`crate::codec::caps`] is the **frozen v1 format surface** — D10's byte and
//! count caps over the bundle's anchor *fields*, which fire in verify stage 1
//! before any AEAD, hash or signature. Nothing in this module duplicates one
//! of those. Per D84 §5, A5 **consumes** `MAX_INTERMEDIATE_COUNT`,
//! `MAX_CERT_BYTES` and `MAX_TSA_TOKEN_BYTES` by name and defines no
//! second constant over the same quantity.
//!
//! What *is* here is the other half of the split: limits on the **internal
//! structure of a foreign artifact**, which D84 §7 puts explicitly outside
//! the v1 freeze. They are verifier policy over a format antseal does not
//! own, and they obey F1–F4 (`docs/format/anchor-artifact-limits.md` §1):
//!
//! - **F1** — evaluated only in the anchor stage (R12), never reachable from
//!   [`crate::bundle::SealProof`]'s decode.
//! - **F2** — exceeding one fails **that anchor alone**; never the bundle,
//!   never the manifest verdict, never another anchor.
//! - **F3** — the over-limit anchor renders `invalid`.
//! - **F4** — raise-only after M2's first release. The F4 registry rows for
//!   these three, and for the depth limit that is *not* declared here, are in
//!   D60 §6 and belong in `docs/format/anchor-artifact-limits.md` §5.
//!
//! # Why there is no `MAX_DER_NESTING_DEPTH`
//!
//! Because minting one would require antseal to measure depth, and measuring
//! depth requires a walker. D60 §2.4 measured what a recursive DER walker
//! does on hostile input: at depth 20 000 (83 407 bytes) it overflows the
//! stack and **aborts** — `SIGABRT`, not a catchable panic, and a trap on
//! `wasm32`. That is a direct violation of A5's "adversarial input returns
//! typed errors, never panics".
//!
//! `der 0.8.1` already enforces `MAX_DEPTH = 64` in `Reader::split_nested`
//! (`reader/position.rs:20,76-79`): 63 nested constructions accepted, 64
//! rejected with `ErrorKind::NestingDepth`, per parse invocation. The deepest
//! of the nine live TSA responses is **19** — a 3.3× margin — so the limit is
//! consumed from `der` by name rather than minted, and
//! `tests/der_pin_eval.rs::der_nesting_depth_limit_is_63` is the F4
//! raise-only guard: it fails if a `der` bump moves the constant in *either*
//! direction, so a lowering is refused at the bump review instead of shipped.
//!
//! # Why the count limit is not `MAX_INTERMEDIATE_COUNT`
//!
//! D84 §5 forbids merging them and D60 §6 b2 gives the operational reason.
//! `MAX_INTERMEDIATE_COUNT` bounds a **bundle field**; [`MAX_CHAIN_CERTS`]
//! bounds the **certificate material one TSA token contributes to a path
//! build**, which arrives inside the token and is bounded only by
//! `MAX_TSA_TOKEN_BYTES` — 1 MiB, i.e. thousands of small certificates.
//! Path enumeration is quadratic in candidates and 16 mutually name-chaining
//! intermediates are cheap to manufacture and fit the bundle cap, so the two
//! quantities are genuinely different and only one of them is already bound.

/// Longest certificate path A9 will build, signer through pinned root, and
/// the largest certificate set one TSA token may contribute to it.
///
/// **8** (D60 §6 b2). Measured against
/// `testdata/anchors/A25-bootstrap/D60-tsa-globalsign-resp.tsr`, the largest
/// of the nine live captures, which carries **4** certificates — margin
/// **2.0×**. The deepest real validated path is 3 links (DigiCert leaf → G4
/// TS CA → pinned Trusted Root G4), 4 if closed through the cross-certificate
/// to Assured ID Root.
///
/// **Not 18** (`MAX_INTERMEDIATE_COUNT + signer + root`), even though 18 is
/// the arithmetic ceiling, because a path can never *exceed* 18: an
/// 18-limit is a check that cannot fail, and a test that cannot fail is the
/// defect class this project keeps finding. At 8 the limit is reachable and
/// `tests/anchor_caps.rs::chain_cert_count_cap_is_reachable` reaches it.
pub const MAX_CHAIN_CERTS: usize = 8;

/// Largest single certificate accepted out of a TSA token.
///
/// **16 KiB** (D60 §6 b3). Measured against
/// `testdata/anchors/A25-bootstrap/D60-tsa-swisssign-resp.tsr`, whose signer
/// certificate is **2 105 B** — the largest of the 27 certificates embedded
/// across the nine captures — margin **7.8×**.
///
/// This is **not** a duplicate of [`crate::codec::caps::MAX_CERT_BYTES`], and
/// the difference is the whole reason it exists: `MAX_CERT_BYTES` fires in
/// stage 1 over each element of the bundle's `intermediates` field, whereas
/// the certificates A9 validates come out of the **token**, where the only
/// bound is `MAX_TSA_TOKEN_BYTES` = 1 MiB. Nothing else stops a hostile token
/// carrying a 900 KiB "certificate".
pub const MAX_CHAIN_CERT_BYTES: u32 = 16_384;

/// Largest `signedAttrs` set accepted on a `SignerInfo`.
///
/// **16** (D60 §6 b4). Measured against
/// `testdata/anchors/A25-bootstrap/D60-tsa-digicert-resp.tsr` (also DFN,
/// SwissSign and Certum), which carries **5** — margin **3.2×**. RFC 5652's
/// attribute set for a timestamp token is small and closed; 16 is generous
/// and still reachable, and
/// `tests/anchor_caps.rs::signed_attr_count_cap_is_reachable` reaches it.
pub const MAX_SIGNED_ATTRS: usize = 16;

// ── rule 6: structural allocation cost (D102 §3.1, applied here by §6) ────
//
// The DER target has never gone red. **That is not evidence** — `anchor_ots`
// was green until its *first remote execution*, which found A100's
// disagreement in 3 140 execs — and the only difference between the two
// targets is that one count limit is 1 024 and the other is 8. Three orders
// of magnitude, not a difference in kind, and `MAX_CHAIN_CERTS` is raise-only
// under F4 exactly as `MAX_OTS_DEPTH` is. D102 §6 therefore rules that this
// path takes the derivation **now, while it is still green**.

/// Bytes one certificate carried out of a token's bag occupies.
///
/// Measured by the compiler from `x509_cert::Certificate`, never transcribed
/// (rule 6 clause (a)) — it is a foreign type on a pre-1.0 pin, so a version
/// bump may move it and the cost must move with it.
pub const CHAIN_CERTIFICATE_BYTES: usize = core::mem::size_of::<x509_cert::Certificate>();

/// Bytes one retained DER copy's *handle* occupies in `chain_certificates`'
/// second vector. The bytes it points at are bounded by
/// [`MAX_CHAIN_CERT_BYTES`] and are a length-driven allocation, i.e. rule 4's,
/// not this rule's.
pub const CHAIN_CERT_DER_HANDLE_BYTES: usize = core::mem::size_of::<Vec<u8>>();

/// Bytes one node of A9's bounded path search occupies.
pub const CHAIN_PATH_NODE_BYTES: usize = core::mem::size_of::<super::chain::Node<'static>>();

/// Most nodes `PathBuilder::new` can reserve: the signer, plus everything the
/// token's bag contributes, plus the bundle's `intermediates` field.
pub const MAX_PATH_NODES: usize =
    MAX_CHAIN_CERTS + crate::codec::caps::MAX_INTERMEDIATE_COUNT as usize + 1;

/// The certificate bag's share of rule 6's cost: `tsa::chain_certificates`'
/// two vectors.
///
/// **Split out of [`TSA_STRUCTURAL_ALLOC_BYTES`] by A110**, which needed a
/// number to put in [`MAX_CHAIN_CERTS`]' F4 registry row. The sum answers
/// *"what does this parse reserve?"*; a registry row has to answer *"what
/// does **this limit** cost?"*, and those are different questions — the sum
/// includes bytes the frozen `MAX_INTERMEDIATE_COUNT` owns and no raise of
/// `MAX_CHAIN_CERTS` can move.
///
/// **4 288 B** on x86-64, **3 200 B** on `wasm32-unknown-unknown`.
pub const TSA_STRUCTURAL_CERT_BAG_BYTES: usize =
    MAX_CHAIN_CERTS * (CHAIN_CERTIFICATE_BYTES + CHAIN_CERT_DER_HANDLE_BYTES);

/// The path search's share: `chain::PathBuilder::new`'s `nodes`.
///
/// **A ceiling, not a reservation**, and the registry row says so.
/// `PathBuilder::new` reserves `Vec::with_capacity(supplied.len() + 1)`, so
/// this is reached only when a token and a bundle between them supply the
/// full [`MAX_PATH_NODES`] candidates — where the `.ots` parser's `walk.rest`
/// reserves its bound on any input deep enough to need it. That asymmetry is
/// worth carrying, because the `.ots` registry cells describe a reservation
/// that always happens and these do not.
///
/// **Only [`MAX_CHAIN_CERTS`]' share of this is an F4 cost.** Of the 3 200 B
/// on x86-64, `MAX_CHAIN_CERTS` owns `8 x 128` = 1 024 B, the signer owns
/// 128 B, and 2 048 B belongs to `MAX_INTERMEDIATE_COUNT` — a **frozen** D10
/// row that F4 cannot raise. Charging the whole figure to `MAX_CHAIN_CERTS`,
/// which is what [`MAX_PATH_NODES`]' definition invites, misattributes
/// 2 176 B; the number a raise argument needs is the marginal one, **664 B**
/// per additional certificate.
pub const TSA_STRUCTURAL_PATH_NODE_BYTES: usize = MAX_PATH_NODES * CHAIN_PATH_NODE_BYTES;

/// Rule 6's **structural allocation cost** for the RFC 3161 / CMS / X.509
/// path: every count-bounded container live in one `verify_token`.
///
/// Three sites, all `Vec::with_capacity(count)` **after** the count is
/// checked, so each reserves its capacity exactly and none regrows:
///
/// | site | count bound | element |
/// | --- | --- | --- |
/// | `tsa::chain_certificates` `certs` | [`MAX_CHAIN_CERTS`] | [`CHAIN_CERTIFICATE_BYTES`] |
/// | `tsa::chain_certificates` `ders` | [`MAX_CHAIN_CERTS`] | [`CHAIN_CERT_DER_HANDLE_BYTES`] |
/// | `chain::PathBuilder::new` `nodes` | [`MAX_PATH_NODES`] | [`CHAIN_PATH_NODE_BYTES`] |
///
/// **[`MAX_SIGNED_ATTRS`] is deliberately absent, and that is a measured
/// finding rather than an omission.** D102 §6 names it alongside the other
/// two, but antseal reserves nothing from it: `signed_attrs` arrives already
/// decoded inside `SignerInfo` and the count check at `tsa.rs` rejects
/// *afterwards*, so the only allocation the attribute set drives belongs to
/// `der`'s decoder and is bounded by the input, which is rule 4's business.
/// Raising `MAX_SIGNED_ATTRS` therefore costs no structural bytes — but
/// [`tests::the_der_structural_cost_is_the_one_measured_today`] pins this
/// constant at equality, so *adding* a container under that limit reddens a
/// test on the day it is added, which is the day it matters.
pub const TSA_STRUCTURAL_ALLOC_BYTES: usize =
    TSA_STRUCTURAL_CERT_BAG_BYTES + TSA_STRUCTURAL_PATH_NODE_BYTES;

/// **Rule 6 clause (c)** for the DER path, against
/// [`crate::codec::caps::MAX_TSA_TOKEN_BYTES`] (D10 row 17, also 1 MiB).
///
/// Same mechanism and same reason as the `.ots` side: a raise of
/// [`MAX_CHAIN_CERTS`] that outgrows the token byte cap fails `cargo build`,
/// on every lane and on `wasm32`, rather than reddening something rerunnable.
const _: () = assert!(
    TSA_STRUCTURAL_ALLOC_BYTES as u64 <= crate::codec::caps::MAX_TSA_TOKEN_BYTES,
    "D58 §10.3 rule 6 clause (c): the RFC 3161 path's count-bounded \
     containers now reserve more than MAX_TSA_TOKEN_BYTES. A count limit was \
     raised without arguing its structural cost in memory — re-argue it \
     (D102 §3.2, §6) rather than relaxing this assertion."
);

/// Rule 6's cost for one **`input_len`-byte** token, which is what an
/// allocation guard may exempt.
///
/// A function of the input, not the flat constant, for the reason D102 §3.3
/// gives: a constant exemption is a window a hostile allocation can hide in
/// regardless of how few bytes bought it. Every certificate in the bag and
/// every bundle intermediate costs at least one wire byte, so the `min` is
/// sound and a short token gets almost no exemption.
///
/// Consumed by `fuzz/fuzz_targets/anchor_token.rs`, so the derivation exists
/// exactly once.
#[must_use]
pub fn tsa_structural_alloc_bytes(input_len: usize) -> usize {
    input_len.min(MAX_CHAIN_CERTS) * (CHAIN_CERTIFICATE_BYTES + CHAIN_CERT_DER_HANDLE_BYTES)
        + input_len.min(MAX_PATH_NODES) * CHAIN_PATH_NODE_BYTES
}

// The A28-shaped derived constraint (D60 §6 b3): a certificate accepted out
// of a token must afterwards be embeddable in a `.sealproof` as an
// intermediate, or the seal anchors and then cannot be revealed. Asserted at
// build time rather than assumed, so the relationship between the two
// constants is checked by the compiler and not by a comment. It also covers
// the pinned roots, which are compiled in and reviewed at A7/A26.
const _: () = assert!(MAX_CHAIN_CERT_BYTES as u64 <= crate::codec::caps::MAX_CERT_BYTES);

/// Every (b)-class limit this module **declares**, paired with the name its
/// F4 registry row carries.
///
/// One list, so the registry cross-check and the "is every declared limit
/// classified?" scan cannot go stale by omission when a fourth is added —
/// the same shape, and for the same reason, as `anchor::ots::limits::ALL`.
///
/// **The fourth A5 limit is deliberately absent**: max DER nesting depth is
/// consumed from `der` and declared nowhere here (see the module docs), so it
/// has a row and a behavioural pin rather than a constant, and
/// [`tests::the_der_limits_match_the_f4_registry`] checks it separately.
///
/// Test-only: the limits are consumed by name at their use sites, and a table
/// of them has no runtime purpose.
#[cfg(test)]
const ALL: &[(&str, u64)] = &[
    ("MAX_CHAIN_CERTS", MAX_CHAIN_CERTS as u64),
    ("MAX_CHAIN_CERT_BYTES", MAX_CHAIN_CERT_BYTES as u64),
    ("MAX_SIGNED_ATTRS", MAX_SIGNED_ATTRS as u64),
];

#[cfg(test)]
mod tests {
    use super::*;

    /// The values are the ones D60 §6 ruled and the F4 registry rows record.
    /// F4 is raise-only, so this test's job is to make a *lowering* a red
    /// build rather than a diff nobody reads.
    #[test]
    fn f4_registry_values() {
        assert_eq!(MAX_CHAIN_CERTS, 8, "D60 §6 b2 / F4 registry row");
        assert_eq!(MAX_CHAIN_CERT_BYTES, 16_384, "D60 §6 b3 / F4 registry row");
        assert_eq!(MAX_SIGNED_ATTRS, 16, "D60 §6 b4 / F4 registry row");
    }

    /// **A110: the DER half of the F4 registry, cross-checked like the `.ots`
    /// half has been since A11.**
    ///
    /// The `.ots` rows have been pinned to their constants since D58 §11, by
    /// `anchor::ots::limits::tests::ots_limits_match_the_f4_registry`. The
    /// DER rows had no rows to pin, and the reason three separate instruments
    /// missed that is A21's shape exactly: the `traceability` job never reads
    /// this file; the `.ots` cross-check builds its needle with the owner cell
    /// hardcoded to `A11`, which no A5 row could ever match; and
    /// [`f4_registry_values`] compares these constants against literals **in
    /// this same file** while their doc comments claim the registry records
    /// them. Three checkers, none able to see the thing they were collectively
    /// cited for.
    ///
    /// `include_str!` rather than `fs::read_to_string`, for A43's reason and
    /// with an edge this file has already been bitten by: the
    /// `wasm32-core-tests` lane has no filesystem, **and a change to this file
    /// is exactly what selects that lane** (Q125 pinned the trigger's positive
    /// self-test arm to this path by name). The byte-count needles are
    /// therefore gated on 64-bit, because the registry records the x86-64
    /// measurement it says it records; the **derivations** are checked
    /// everywhere, because that is the part that must not drift.
    #[test]
    fn the_der_limits_match_the_f4_registry() {
        const REGISTRY: &str = include_str!("../../../../docs/format/anchor-artifact-limits.md");

        for (name, value) in ALL {
            let needle = format!("| `{name}` | A5 | {} |", format_underscored(*value));
            assert!(
                REGISTRY.contains(&needle),
                "docs/format/anchor-artifact-limits.md §5 has no A5 row reading {needle:?} — \
                 the constant and its F4 registry row have drifted, which is what A110 \
                 found was impossible to notice while the rows did not exist"
            );
        }
        assert_eq!(
            ALL.len(),
            3,
            "D60 §6 declares three constants here; its fourth (b)-class limit, max DER \
             nesting depth, is consumed from `der` and has no constant. Update deliberately"
        );

        // The fourth row, and the ruling A110 had to take to write it.
        //
        // **It is pinned behaviourally, not to a mirror constant.** A
        // `#[cfg(test)]` mirror of 63 was the alternative, and it is worse:
        // `der`'s `MAX_DEPTH` is private, so a mirror could only ever be
        // *hand-transcribed* — clause (a)'s "a number typed by hand is a
        // number that survives a raise" — and the thing keeping it honest
        // would still be the behavioural test below. That buys two
        // transcriptions where one will do, and pins the registry row to the
        // copy rather than to the behaviour. So `63` is spelled **once in
        // this crate**, here, and tied to both artifacts that must agree with
        // it: the registry row, and the guard whose name carries the number.
        //
        // What makes it fail: a `der` bump that moves the limit reddens
        // `der_pin_eval.rs` first, on the behaviour; renaming or deleting
        // that test — the only way to make it green again — reddens this.
        const DER_PIN: &str = include_str!("../../tests/der_pin_eval.rs");
        const DER_NESTING_DEPTH: u32 = 63;

        assert!(
            REGISTRY.contains(&format!(
                "| `MAX_DER_NESTING_DEPTH` | A5 | {DER_NESTING_DEPTH} |"
            )),
            "§5 has no A5 row for the max DER nesting depth at {DER_NESTING_DEPTH} — it is \
             the one F4 limit antseal does not declare (module docs above; D60 §6 b1), so \
             the row is the only place its value is recorded at all"
        );
        assert!(
            DER_PIN.contains(&format!(
                "fn der_nesting_depth_limit_is_{DER_NESTING_DEPTH}"
            )),
            "the F4 raise-only guard for the DER depth limit is gone or renamed. That row \
             is pinned behaviourally rather than to a constant, so this test IS the pin — \
             if `der` moved the limit, re-measure and move the registry row with it"
        );
        assert!(
            REGISTRY.contains("der_nesting_depth_limit_is_63"),
            "the DER depth row no longer names the behavioural guard it is pinned by — a \
             reader has no other way to learn that this row's value is not a constant"
        );
    }

    /// **A110's Accept, third clause: a limit declared without a row reddens
    /// something.**
    ///
    /// [`ALL`] and the registry cross-check above are only as complete as
    /// `ALL` is, and a list a lane forgets to extend is the omission that put
    /// the DER half outside the registry for two waves. So the module's own
    /// source is scanned: every `pub const MAX_*` it declares is either an F4
    /// limit with a row, or is classified here as not being one, with its
    /// reason. A fourth declaration is red until a lane says which it is.
    #[test]
    fn every_max_constant_declared_here_is_classified() {
        /// `pub const MAX_*` names in this module that are **not** F4 limits,
        /// each with the reason, because an exemption without one is how a
        /// list stops meaning anything.
        const NOT_F4_LIMITS: &[(&str, &str)] = &[(
            "MAX_PATH_NODES",
            "derived from MAX_CHAIN_CERTS and the frozen MAX_INTERMEDIATE_COUNT — it \
             sizes a container, it is not a limit on a foreign artifact's structure, \
             and nothing rejects an artifact for exceeding it",
        )];

        const THIS_FILE: &str = include_str!("caps.rs");
        // The library region only: `ALL` and this test both spell these names.
        let library_region = THIS_FILE.split("#[cfg(test)]").next().unwrap_or("");

        let mut declared = 0_usize;
        for line in library_region.lines() {
            let Some(rest) = line.strip_prefix("pub const MAX_") else {
                continue;
            };
            let Some((name, _)) = rest.split_once(':') else {
                continue;
            };
            let name = format!("MAX_{name}");
            declared += 1;
            let has_row = ALL.iter().any(|(n, _)| *n == name);
            let exempt = NOT_F4_LIMITS.iter().any(|(n, _)| *n == name);
            assert!(
                has_row ^ exempt,
                "`{name}` is declared in anchor/caps.rs and is neither in `ALL` — whose \
                 every entry is cross-checked against a §5 F4 registry row — nor listed \
                 in this test's `NOT_F4_LIMITS` with a reason. A11's half of the registry \
                 went two waves without rows because nothing could see this; classify it"
            );
        }
        assert_eq!(
            declared,
            ALL.len() + NOT_F4_LIMITS.len(),
            "the scan found {declared} `pub const MAX_*` declarations against {} classified \
             — if it found none, the scan itself has broken and this test is measuring \
             nothing, which is the failure mode it exists to prevent",
            ALL.len() + NOT_F4_LIMITS.len()
        );
    }

    /// **A110: the `structural cost` cells of the DER rows, derived and
    /// asserted rather than typed** (D102 rule 6 clause (a)).
    ///
    /// The `.ots` twin is
    /// `anchor::ots::limits::tests::the_structural_cost_column_states_the_derivation_and_its_value`,
    /// and it does **not** parse the table — it is two `contains` loops over a
    /// closed list. This is the same instrument for the DER half, and it has
    /// one thing to say that the `.ots` side does not: the DER containers
    /// reserve with `Vec::with_capacity` **after** the count check and never
    /// regrow, so the cells read plain `limit x size_of::<T>()` and **must
    /// not** copy the `.ots` rows' `next_pow2(limit) x size_of::<T>()` shape.
    #[test]
    fn the_der_structural_cost_column_states_the_derivation_and_its_value() {
        const REGISTRY: &str = include_str!("../../../../docs/format/anchor-artifact-limits.md");

        // Everywhere: the derivations. No pointer width in any of them, so a
        // cell that drifts from the code is red on `wasm32` too.
        for formula in [
            format!("`{MAX_CHAIN_CERTS} x (size_of::<Certificate>() + size_of::<Vec<u8>>())`"),
            format!("`{MAX_PATH_NODES} x size_of::<Node>()`"),
            format!("`{MAX_CHAIN_CERTS} x size_of::<Node>()`"),
            format!("`{MAX_CHAIN_CERTS} x size_of::<Certificate>()`"),
        ] {
            assert!(
                REGISTRY.contains(&formula),
                "the F4 registry no longer states {formula} — clause (a) says the cost is \
                 derived, and the row must say from what"
            );
        }
        // …and not the `.ots` shape, which would be wrong here: these
        // containers are reserved once at their exact count.
        assert!(
            !REGISTRY.contains("next_pow2(8)") && !REGISTRY.contains("next_pow2(25)"),
            "a DER row has copied the `.ots` rows' next_pow2 shape. `chain_certificates` \
             and `PathBuilder::new` reserve after the count check and never regrow, so \
             rounding up to a power of two overstates every one of these numbers"
        );

        // 64-bit only: the measured layout the registry says it records.
        if core::mem::size_of::<usize>() == 8 {
            for (what, bytes) in [
                ("the certificate bag", TSA_STRUCTURAL_CERT_BAG_BYTES),
                ("the path-node ceiling", TSA_STRUCTURAL_PATH_NODE_BYTES),
                ("the whole DER path", TSA_STRUCTURAL_ALLOC_BYTES),
                (
                    "MAX_CHAIN_CERTS' share of the path nodes",
                    MAX_CHAIN_CERTS * CHAIN_PATH_NODE_BYTES,
                ),
                (
                    "MAX_INTERMEDIATE_COUNT's share, which F4 cannot raise",
                    crate::codec::caps::MAX_INTERMEDIATE_COUNT as usize * CHAIN_PATH_NODE_BYTES,
                ),
                (
                    "the marginal cost of one more certificate",
                    CHAIN_CERTIFICATE_BYTES + CHAIN_CERT_DER_HANDLE_BYTES + CHAIN_PATH_NODE_BYTES,
                ),
                (
                    "the tie with the fuzz guard's slack",
                    MAX_CHAIN_CERTS * CHAIN_CERTIFICATE_BYTES,
                ),
            ] {
                let needle = format!("**{}**", format_spaced(bytes));
                assert!(
                    REGISTRY.contains(&needle),
                    "the F4 registry has no cell reading {needle:?} for {what} — the \
                     derived cost and its registry row have drifted, which is the one \
                     thing D102's column exists to make impossible"
                );
            }
        }
    }

    /// D58 renders registry values with `_` group separators, and the DER rows
    /// follow the document's convention rather than D60's draft block, which
    /// wrote `16384`. Duplicated from `anchor::ots::limits::tests` rather than
    /// shared: `ots::limits` is a private module of `ots`, so nothing outside
    /// it can name its test helpers, and widening a module's visibility to
    /// share eight lines of formatting is the worse trade.
    fn format_underscored(value: u64) -> String {
        group(&value.to_string(), '_')
    }

    /// The registry renders byte counts with a space thousands separator
    /// (`4 288 B`), which is the document's convention and not this module's.
    fn format_spaced(value: usize) -> String {
        format!("{} B", group(&value.to_string(), ' '))
    }

    fn group(digits: &str, sep: char) -> String {
        let mut out = String::new();
        for (i, ch) in digits.chars().enumerate() {
            if i > 0 && (digits.len() - i).is_multiple_of(3) {
                out.push(sep);
            }
            out.push(ch);
        }
        out
    }

    /// The D10 constants A5 consumes by name are unchanged by this module —
    /// the grep-level review item in A5's Accept row, asserted instead of
    /// grepped. If any of these three moved, a limit above would silently
    /// stop meaning what its doc comment says.
    #[test]
    fn the_frozen_d10_constants_are_consumed_not_redefined() {
        assert_eq!(crate::codec::caps::MAX_INTERMEDIATE_COUNT, 16);
        assert_eq!(crate::codec::caps::MAX_CERT_BYTES, 65_536);
        assert_eq!(crate::codec::caps::MAX_TSA_TOKEN_BYTES, 1_048_576);
    }

    /// The build-time assertion above proves `<=`. This proves the margin is
    /// real — that the two constants are not the same number wearing two
    /// names, which is the shape D84 §5 rules out.
    #[test]
    fn chain_cert_bytes_is_strictly_below_the_bundle_field_cap() {
        assert!(u64::from(MAX_CHAIN_CERT_BYTES) < crate::codec::caps::MAX_CERT_BYTES);
    }

    /// **Rule 6 clause (b) for the DER path** (D102 §6).
    ///
    /// The `.ots` side asserts its derived cost against a measured allocator
    /// peak, because there its containers *are* the peak. Here they are not:
    /// the whole structural cost fits inside the fuzz guard's 4 KiB `SLACK`,
    /// so no input makes it the peak and there is nothing to measure it
    /// against. D102 §6 rules that this is *"a measured finding … committed
    /// **as an equality assertion**, because that assertion is what goes red
    /// the day someone adds a container or raises a count — which is the day
    /// it matters. An unmeasured 'it's fine' is what this whole record is
    /// about."*
    ///
    /// What makes it fail: adding a fourth count-bounded container, raising
    /// `MAX_CHAIN_CERTS` or `MAX_INTERMEDIATE_COUNT`, or an `x509-cert` /
    /// `der` bump that moves `size_of::<Certificate>()`. Every one of those is
    /// a reviewed event, and every one of them should re-read this number.
    /// **Pointer width, corrected 2026-08-08.** As first written this row
    /// asserted the literals unconditionally and **failed the
    /// `wasm32-core-tests` lane**: `size_of::<x509_cert::Certificate>()` is
    /// **376** on `wasm32-unknown-unknown` against 512 on x86-64. That is not
    /// the event this row exists to catch. It conflated *"a crate bump moved
    /// the layout"* — reviewed, and the whole point — with *"we are on 32-bit
    /// pointers"*, which is neither a defect nor reviewable.
    ///
    /// So it now splits the way the `.ots` side already did (`limits.rs`,
    /// `the_structural_cost_column_states_the_derivation_and_its_value`): the
    /// **derivation** is asserted everywhere, from the constants rather than
    /// from literals, because that is the part that must not drift; the
    /// **measured byte counts** are asserted on 64-bit only, because the
    /// registry records the x86-64 measurement it says it records.
    ///
    /// It also cost this project a CI red on a lane the local gate could not
    /// see: `scripts/local-gate.sh`'s `wasm32` lane was a `cargo build`, and
    /// its name did not say so. **Closed by Q125** — that lane is now
    /// `wasm32-build`, and a second lane, `wasm32-tests`, runs
    /// `scripts/wasm-tests.sh --check` (which *executes* this test on
    /// `wasm32-unknown-unknown`) whenever the diff touches anything that can
    /// move wasm32 behaviour. A change to THIS file selects it — the trigger's
    /// positive self-test arm is pinned to this path by name for exactly that
    /// reason. Force it with `ANTSEAL_GATE_WASM=1`.
    #[test]
    fn the_der_structural_cost_is_the_one_measured_today() {
        // Everywhere: the formula. A fourth container, or a raised count,
        // parts these two and reddens on every target including wasm32.
        assert_eq!(
            TSA_STRUCTURAL_ALLOC_BYTES,
            MAX_CHAIN_CERTS * (CHAIN_CERTIFICATE_BYTES + CHAIN_CERT_DER_HANDLE_BYTES)
                + MAX_PATH_NODES * CHAIN_PATH_NODE_BYTES,
            "the derivation and its measured value have parted"
        );
        // Everywhere: a count limit, not a layout — no pointer width in it.
        assert_eq!(MAX_PATH_NODES, 25);

        // 64-bit only: the measured layout this record was written against.
        if core::mem::size_of::<usize>() == 8 {
            assert_eq!(
                CHAIN_CERTIFICATE_BYTES, 512,
                "size_of::<x509_cert::Certificate>() moved — re-measure \
                 TSA_STRUCTURAL_ALLOC_BYTES and this row together"
            );
            assert_eq!(CHAIN_CERT_DER_HANDLE_BYTES, 24);
            assert_eq!(CHAIN_PATH_NODE_BYTES, 128);
            assert_eq!(TSA_STRUCTURAL_ALLOC_BYTES, 7_488);
        }
    }

    /// The DER path's structural cost is **small**, and that is the finding —
    /// not a reason to skip asserting it.
    ///
    /// `anchor_ots` and `anchor_token` share an entry point and a default
    /// budget; the only difference between them is that one count limit is
    /// 1 024 and the other is 8. This row records where the second one sits
    /// relative to the fuzz guard's fixed slack, so a raise that moves it past
    /// that line is visible as a changed verdict here rather than as a fuzz
    /// red weeks later.
    #[test]
    fn the_der_structural_cost_relative_to_the_guards_fixed_slack() {
        const FUZZ_SLACK: usize = 4 * 1024;

        // D102 §6 anticipated that the whole derivation might *"come out small
        // enough to fit inside `SLACK`"*, in which case the exemption would be
        // inert. **It does not.** The overshoot is stated as a number rather
        // than as an inequality so that a shrink is as visible as a growth.
        //
        // 64-bit only, and the `saturating_sub` is not defensive padding: on a
        // 32-bit target the whole derivation *can* land under `SLACK`, and a
        // bare `-` would underflow-panic before the assertion could say so.
        if core::mem::size_of::<usize>() == 8 {
            assert_eq!(
                TSA_STRUCTURAL_ALLOC_BYTES - FUZZ_SLACK,
                3_392,
                "the DER path's structural cost has moved relative to the guard's \
                 fixed slack — re-record the measurement, in either direction"
            );
        } else {
            // wasm32 is narrower throughout, so the overshoot is smaller. The
            // property that must survive is that clause (c) still binds, which
            // the unconditional assertion at the end of this test states.
            assert!(
                TSA_STRUCTURAL_ALLOC_BYTES.saturating_sub(FUZZ_SLACK) < 3_392,
                "the 32-bit derivation is no longer narrower than the 64-bit one \
                 ({TSA_STRUCTURAL_ALLOC_BYTES} B) — that inverts the assumption \
                 this split was written on"
            );
        }

        // **The finding, and it is sharper than D102 §6 stated it.** The
        // single largest of the three reservations is `chain_certificates`'
        // `certs`, and it is *exactly* `SLACK`:
        //
        //     MAX_CHAIN_CERTS x size_of::<Certificate>() = 8 x 512 = 4 096
        //
        // The guard's cap is `len x 1 + SLACK`, so this reservation clears it
        // by a margin of **`len` bytes — zero at the boundary**. The bag's
        // count is `set.0.len()`, which counts every `CertificateChoices`
        // entry including a tiny `[3] other`, so a few hundred bytes of token
        // reserves the full 4 096 B. `anchor_token` has never gone red on the
        // exact arithmetic that made `anchor_ots` red four times, and the
        // reason is a **tie**: not a margin, not a design, a tie. Raise
        // `MAX_CHAIN_CERTS` to 9, or let an `x509-cert` bump add one word to
        // `Certificate`, and the same A100 defect arrives on the DER path.
        //
        // This assertion is the thing that says so before CI does.
        //
        // **The tie is a 64-bit fact**, corrected 2026-08-08 after this row
        // reddened `wasm32-core-tests`: there `size_of::<Certificate>()` is
        // 376, so the same product is `8 x 376 = 3 008` and the reservation
        // clears `SLACK` by nearly a kilobyte. The browser tab — the tightest
        // ceiling this parser actually runs under — is the target with the
        // *most* headroom. The tie belongs to the host that fuzzes, not to the
        // format, and that is worth knowing rather than asserting away.
        let cert_bag = MAX_CHAIN_CERTS * CHAIN_CERTIFICATE_BYTES;
        if core::mem::size_of::<usize>() == 8 {
            assert_eq!(
                cert_bag, FUZZ_SLACK,
                "the certificate-bag reservation has moved off its exact tie with \
                 the fuzz guard's SLACK. If it grew, `anchor_token` is now the \
                 `anchor_ots` of A100 and the scoped budget is what stands between \
                 it and a red lane; if it shrank, say so here. Either way this is \
                 a measurement to re-record, not a number to update silently"
            );
        } else {
            assert!(
                cert_bag < FUZZ_SLACK,
                "the 32-bit certificate bag ({cert_bag} B) has reached the fuzz \
                 guard's SLACK. wasm32 was the target with headroom; if it no \
                 longer is, the DER path is one raise from A100 on every target"
            );
        }

        // …and still two orders of magnitude under clause (c)'s ceiling.
        assert!(
            (TSA_STRUCTURAL_ALLOC_BYTES as u64) * 100 < crate::codec::caps::MAX_TSA_TOKEN_BYTES,
            "clause (c)'s headroom on the DER path has fallen below 100x"
        );
    }
}
