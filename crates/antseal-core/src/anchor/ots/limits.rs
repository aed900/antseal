//! The seven **(b)-class** `.ots` structural limits (task **A11**).
//!
//! Every value here is **D58 §9.1's**, with D58 §9.2's derivation and D58
//! §9.5's F4 registry row. They are not re-derived: A11's `Do` says *"D58 §7
//! sets all seven values with their F4 rows and structural derivations — use
//! them; do not re-derive."*
//!
//! # What class each limit is in (A27/D84 §5)
//!
//! A11's limits split in two. The **(a)** half is *already frozen* and is
//! consumed by name: the byte cap over a bundle-embedded `.ots` **is**
//! [`crate::codec::caps::MAX_OTS_BYTES`] (D10 row 16), which fires in verify
//! stage 1 as `bundle-ots-too-large`. **Nothing in this file is a byte cap
//! over the whole artifact**, and
//! `tests::no_ots_constant_duplicates_max_ots_bytes` makes that mechanical
//! rather than a review item.
//!
//! The **(b)** half is what this file holds. All seven obey **F1–F4**
//! (`docs/format/anchor-artifact-limits.md` §1):
//!
//! - **F1** — evaluated only in the anchor stage. Nothing here is reachable
//!   from `SealProof::decode`; [`super::parse_ots`] is called by the anchor
//!   stage and by nothing else.
//! - **F2** — an over-limit artifact fails *that anchor alone*.
//! - **F3** — an over-limit artifact renders `invalid`, never
//!   `internally-consistent-only`. **Unknown is not over-limit** and keeps
//!   its own treatment (D58 §9.4; [`super::OtsAttestation::UnknownType`] and
//!   the indeterminate-value path).
//! - **F4** — raise-only, forever. Every value below is `lowered: never` in
//!   the registry, and `tests::ots_limits_match_the_f4_registry` pins the
//!   constants to their rows so the two cannot drift.
//!
//! # Why the parser can afford a generous depth
//!
//! [`MAX_OTS_DEPTH`] is 1 024 where the rejected `opentimestamps` crate's
//! stack-bound ceiling was 255 (D58 §3.5). The difference is structural, not
//! a judgement call: this parser is **iterative** (D58 §10.3 rule 1), so a
//! level of depth costs one `Vec` entry rather than one native stack frame,
//! and native and `wasm32` behave identically at depth. Pinning the crate
//! would have made 255 the permanent ceiling under F4 — a number chosen in
//! 2023 by someone bounding their own stack.

/// Total op steps across every branch (D58 §9.2).
///
/// Structural ceiling for an honest artifact: a Bitcoin merkle path costs 3
/// ops per level and block transaction count is consensus-bounded to
/// ≈ 16 666 txs, so ≤ 14 levels → ≤ 42 ops, plus 2 for the coinbase split =
/// 44; a calendar aggregating 2²⁰ requests in one round costs 60. An honest
/// branch is ≤ ~110 ops and an 8-calendar merge ≤ ~880. **40.96× the largest
/// real file measured** (100 ops).
pub const MAX_OTS_OPS: u32 = 4_096;

/// Longest root-to-attestation path, in **op edges**, root at 0 (D58 §9.2).
///
/// Depth is edges from the root step: a chain of `N` ops terminated by an
/// attestation has depth `N`. D58 §9.3 states that definition normatively —
/// *"it must be the one the implementation uses"* — because it is what makes
/// the §9.3 witnesses computable. An attestation is a leaf hanging off a
/// node, not a node of its own, so it does not add a level.
///
/// **15.28× the measured 67.** D58's own table says 69, which is that
/// definition's off-by-two: the F4 registry records the measurement and the
/// correction, and the direction is safe.
pub const MAX_OTS_DEPTH: u32 = 1_024;

/// Children of one fork node (D58 §9.2).
///
/// A13 emits one branch per calendar and each upgrade adds one more under
/// that calendar, so honest width ≈ 2 × calendars. 64 admits 32 fully
/// upgraded calendars against the spec's ≥ 2-calendar policy — **21.33× the
/// measured 3**.
pub const MAX_OTS_BRANCH_WIDTH: u32 = 64;

/// Attestation nodes in the whole file (D58 §9.2).
///
/// **This limit is load-bearing, not decorative.** Measured by D58: a
/// 1 048 566-byte `.ots` — *under* [`crate::codec::caps::MAX_OTS_BYTES`] —
/// carries **74 893** attestations at 14 bytes each. The byte cap does not
/// bound the count usefully; only this does. Numerically the same as its
/// bundle-side sibling [`crate::codec::caps::MAX_OTS_ANCHOR_COUNT`],
/// deliberately.
pub const MAX_OTS_ATTESTATIONS: u32 = 256;

/// One append/prepend operand, in bytes (D58 §9.2).
///
/// The honest maximum is a fat coinbase transaction split around its
/// OP_RETURN commitment; pools paying hundreds of outputs directly from the
/// coinbase reach several KB, so the reference implementation's 4 096 would
/// be **too tight**, not too loose. **94.16× the measured 174 B**, and 1.6 %
/// of the byte cap, so no single operand can dominate a file.
pub const MAX_OTS_OPERAND_BYTES: u32 = 16_384;

/// The running value at any step, checked **before** allocating the new one
/// (D58 §9.2).
///
/// Admits a full 16 384-byte prepend and a full 16 384-byte append around a
/// 32-byte hash, which is the honest worst case. **156.04× the measured
/// 210 B.** This is the limit that closes D58 §3.2 — the 102-byte `.ots`
/// that drove the rejected crate to ask for 2 TiB.
pub const MAX_OTS_VALUE_BYTES: u32 = 32_768;

/// The declared payload of one attestation, checked **before** allocating
/// (D58 §9.2).
///
/// Not guessed: it is `python-opentimestamps`' own `MAX_PAYLOAD_SIZE = 8192`
/// (D58 §4), so a payload this parser accepts is one the reference accepts
/// and vice versa. **178.09× the measured 46 B.** This is the limit that
/// closes D58 §3.1 — the 80-byte `.ots` that drove the rejected crate into a
/// 549 755 813 887-byte allocation and an uncatchable `SIGABRT`.
pub const MAX_OTS_ATTESTATION_PAYLOAD_BYTES: u32 = 8_192;

/// Every (b)-class limit, paired with the name its F4 registry row carries.
///
/// One list, so the registry cross-check and the byte-cap-duplication check
/// cannot go stale by omission when an eighth limit is added.
///
/// Test-only: the limits themselves are consumed by name in the walk, and a
/// table of them has no runtime purpose.
#[cfg(test)]
pub(super) const ALL: &[(&str, u32)] = &[
    ("MAX_OTS_OPS", MAX_OTS_OPS),
    ("MAX_OTS_DEPTH", MAX_OTS_DEPTH),
    ("MAX_OTS_BRANCH_WIDTH", MAX_OTS_BRANCH_WIDTH),
    ("MAX_OTS_ATTESTATIONS", MAX_OTS_ATTESTATIONS),
    ("MAX_OTS_OPERAND_BYTES", MAX_OTS_OPERAND_BYTES),
    ("MAX_OTS_VALUE_BYTES", MAX_OTS_VALUE_BYTES),
    (
        "MAX_OTS_ATTESTATION_PAYLOAD_BYTES",
        MAX_OTS_ATTESTATION_PAYLOAD_BYTES,
    ),
];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::caps::MAX_OTS_BYTES;

    /// The F4 registry is the record that a limit was never lowered; a
    /// constant that has drifted from its row makes the record a fiction.
    ///
    /// Same shape as the existing `format_registry_freeze.rs` cross-check,
    /// and D58 §11 names it. `include_str!` rather than `fs::read_to_string`
    /// so the assertion also runs in the `wasm32-core-tests` lane, which has
    /// no filesystem (P14).
    #[test]
    fn ots_limits_match_the_f4_registry() {
        const REGISTRY: &str = include_str!("../../../../../docs/format/anchor-artifact-limits.md");

        let mut found = 0_usize;
        for (name, value) in ALL {
            let needle = format!("| `{name}` | A11 | {} |", format_underscored(*value));
            assert!(
                REGISTRY.contains(&needle),
                "docs/format/anchor-artifact-limits.md §5 has no A11 row reading {needle:?} — \
                 the constant and its F4 registry row have drifted"
            );
            found += 1;
        }
        assert_eq!(found, ALL.len(), "every (b) limit needs a registry row");
        assert_eq!(ALL.len(), 7, "D58 §9.1 sets seven — update deliberately");
    }

    /// D58 renders the values with `_` group separators; the registry rows
    /// are pasted verbatim from §9.5, so the cross-check must compare the
    /// same rendering rather than a bare integer.
    fn format_underscored(value: u32) -> String {
        let digits = value.to_string();
        let mut out = String::new();
        for (i, ch) in digits.chars().enumerate() {
            if i > 0 && (digits.len() - i).is_multiple_of(3) {
                out.push('_');
            }
            out.push(ch);
        }
        out
    }

    /// A11's grep-level review item, made mechanical (D58 §11).
    ///
    /// The byte cap over a bundle-embedded `.ots` is `MAX_OTS_BYTES` and is
    /// consumed by name from `codec::caps`. A second constant over the same
    /// quantity is exactly the CLI-vs-page divergence MVP-SPEC.md line 73
    /// exists to prevent (`docs/format/anchor-artifact-limits.md` §3).
    #[test]
    fn no_ots_constant_duplicates_max_ots_bytes() {
        for (name, value) in ALL {
            assert_ne!(
                u64::from(*value),
                MAX_OTS_BYTES,
                "{name} duplicates MAX_OTS_BYTES — consume D10 row 16 by name instead"
            );
        }

        // …and no *unnamed* one hides in this file either. The library
        // region only: a test may legitimately spell the cap to compare
        // against it, as the assertion above does.
        const THIS_FILE: &str = include_str!("limits.rs");
        let library_region = THIS_FILE.split("#[cfg(test)]").next().unwrap_or("");
        for spelling in ["1_048_576", "1048576"] {
            assert!(
                !library_region.contains(spelling),
                "a byte cap over the whole artifact is re-minted in limits.rs \
                 (found {spelling:?}); D58 §10.3 rule 5 says parse_ots takes none"
            );
        }
    }

    /// Every limit is far enough under the byte cap that its `cap + 1`
    /// witness fits — the half of D58 §9.3 that is a property of the numbers
    /// alone. The other half (each witness returns *its own* code) needs the
    /// parser and lives in `super::tests`.
    #[test]
    fn every_limit_is_reachable_under_the_byte_cap() {
        // The cheapest witness for each limit, in bytes, taken from D58 §9.3.
        // Deliberately hand-transcribed rather than computed: a computed
        // bound would restate the parser instead of checking it.
        for (name, bytes) in [
            ("MAX_OTS_OPS", 4_234_u64),
            ("MAX_OTS_DEPTH", 1_103),
            ("MAX_OTS_BRANCH_WIDTH", 975),
            ("MAX_OTS_ATTESTATIONS", 4_608),
            ("MAX_OTS_OPERAND_BYTES", 16_455),
            ("MAX_OTS_VALUE_BYTES", 32_900),
            ("MAX_OTS_ATTESTATION_PAYLOAD_BYTES", 8_275),
        ] {
            assert!(
                bytes < MAX_OTS_BYTES,
                "{name}'s witness is {bytes} B, at or over MAX_OTS_BYTES — \
                 its rejection test could never fail"
            );
        }
    }
}
