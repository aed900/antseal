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
//!
//! **Corrected 2026-08-07 by D102 §5**
//! (`docs/decisions/D102-parser-structural-allocation-cost.md`). The paragraph
//! above used to end
//! *"which is why it can be generous"*, and D58 §9.2 said the same. The clause
//! is true and the inference was not: **nobody ever costed the `Vec` entry.**
//! One is [`OTS_FRAME_BYTES`] wide, so 1 024 of them is
//! [`OTS_STRUCTURAL_WORK_STACK_BYTES`] — reached from a **1 145-byte** legal
//! artifact that `super::tests::parser_is_iterative_at_max_depth` requires to
//! parse. Generous is still the right call (D102 §5 declines to lower the
//! limit), but the next raiser inherits the arithmetic below rather than a
//! reassurance.
//!
//! # Structural allocation cost (D58 §10.3 rule 6, added by D102)
//!
//! Rule 6 governs a container bounded by a **count limit** rather than by a
//! length header, which is the class D10 §4's clamp rule was never about.
//! There are two in this parser — the work stack under [`MAX_OTS_DEPTH`] and
//! the attestation list under [`MAX_OTS_ATTESTATIONS`] — and their cost is
//! derived here, from the limit constants and `size_of`, per clause (a).
//! Clause (b)'s equality assertions live in
//! `crates/antseal-core/tests/anchor_ots_alloc.rs`; clause (c) is the `const`
//! assertion below, so a raise that outgrows [`MAX_OTS_BYTES`] fails
//! `cargo build` on every lane rather than reddening one that can be rerun.
//!
//! [`MAX_OTS_BYTES`]: crate::codec::caps::MAX_OTS_BYTES

/// Total op steps across every branch (D58 §9.2).
///
/// Structural ceiling for an honest artifact: a Bitcoin merkle path costs 3
/// ops per level and block transaction count is consensus-bounded to
/// ≈ 16 666 txs, so ≤ 14 levels → ≤ 42 ops, plus 2 for the coinbase split =
/// 44; a calendar aggregating 2²⁰ requests in one round costs 60. An honest
/// branch is ≤ ~110 ops and an 8-calendar merge ≤ ~880. **16.79× the largest
/// real artifact measured** — **244** ops, the three-way splice A22 froze.
///
/// Re-measured 2026-08-10 (**A48**). This read *"40.96× … (100 ops)"*, which
/// was `rust-opentimestamps-LARGE_TEST.ots`, a third-party crate's January-2017
/// test constant standing in for an artifact that did not exist when A11
/// landed. One does now.
pub const MAX_OTS_OPS: u32 = 4_096;

/// Longest root-to-attestation path, in **op edges**, root at 0 (D58 §9.2).
///
/// Depth is edges from the root step: a chain of `N` ops terminated by an
/// attestation has depth `N`. D58 §9.3 states that definition normatively —
/// *"it must be the one the implementation uses"* — because it is what makes
/// the §9.3 witnesses computable. An attestation is a leaf hanging off a
/// node, not a node of its own, so it does not add a level.
///
/// **12.05× the measured 85** — the three-way splice A22 froze, which is the
/// artifact a verifier parses. Depth is *attachment depth plus fragment
/// depth*, so the merged whole is deeper than any fragment: the six upgrade
/// fragments measure 67/70/73 individually.
///
/// **This is the smallest margin in the F4 registry**, and it was already the
/// smallest before it was measured. Re-measured 2026-08-10 (**A48**); this
/// read *"15.28× the measured 67"*, which was
/// `rust-opentimestamps-LARGE_TEST.ots` — a third-party crate's test constant,
/// not an antseal artifact — and D104 §4 records A109 reasoning from that
/// figure. D104's KEEP-1 024 ruling is unaffected and was argued at 85: the
/// admissible floor is `8 × 85 = 680`, every cap in `(512, 1 024]` reserves
/// identical bytes, so 1 024 weakly dominates.
///
/// D58's own table says 69, which is that definition's off-by-two over the
/// borrowed fixture: the F4 registry records that correction too, and the
/// direction is safe.
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

// ── rule 6: structural allocation cost (D102 §3.1) ───────────────────────

/// Bytes one work-stack entry occupies — `size_of::<Frame>()`, measured by
/// the compiler and never transcribed (rule 6 clause (a)).
///
/// **40** on x86-64 and **24** on `wasm32-unknown-unknown`, both measured;
/// the difference is `Option<Vec<u8>>`'s pointer width. Every consumer below
/// derives from this rather than from either number, which is what makes
/// D102's kill criterion 5 — *"`size_of::<Frame>()` moves on a supported
/// target and the derived cost is not recomputed"* — impossible rather than
/// merely unlikely.
pub const OTS_FRAME_BYTES: usize = core::mem::size_of::<super::parse::Frame>();

/// Bytes one collected attestation occupies — `size_of::<OtsAttestation>()`.
///
/// **48** on x86-64 and **32** on `wasm32-unknown-unknown`, both measured.
/// Together with [`OTS_FRAME_BYTES`] that puts the whole structural cost at
/// **32 768 B in the verifier page**, against 53 248 B natively — the browser
/// tab, which is the tightest ceiling this parser runs under, is also the
/// cheapest place it runs.
pub const OTS_ATTESTATION_BYTES: usize = core::mem::size_of::<super::OtsAttestation>();

/// Peak bytes the parser's work stack can reserve in one allocation.
///
/// `walk.rest` holds the root-to-current path, so `rest.len()` **is** the
/// current depth and [`MAX_OTS_DEPTH`] is its only bound. `Vec` grows by
/// doubling from capacity 4, so the largest single reservation is the first
/// power of two at or above the limit.
pub const OTS_STRUCTURAL_WORK_STACK_BYTES: usize =
    (MAX_OTS_DEPTH as usize).next_power_of_two() * OTS_FRAME_BYTES;

/// The same for the attestation list, bounded by [`MAX_OTS_ATTESTATIONS`].
///
/// **Reachable, and not merely on paper** (D102 §1.3): an open-fork spine
/// leaves every ancestor genuinely open, so 129 attestations — and this
/// allocation, not the work stack — is the measured peak of a 1 869-byte
/// input.
pub const OTS_STRUCTURAL_ATTESTATION_BYTES: usize =
    (MAX_OTS_ATTESTATIONS as usize).next_power_of_two() * OTS_ATTESTATION_BYTES;

/// Every count-bounded container live in one parse, summed — rule 6's
/// **structural allocation cost** for this parser.
pub const OTS_STRUCTURAL_ALLOC_BYTES: usize =
    OTS_STRUCTURAL_WORK_STACK_BYTES + OTS_STRUCTURAL_ATTESTATION_BYTES;

/// **Rule 6 clause (c)**, as a build-stopping assertion rather than a test.
///
/// A raise of a count limit under F4 must keep the parser's structural
/// bookkeeping under the artifact byte cap this verifier has already
/// committed to holding ([`crate::codec::caps::MAX_OTS_BYTES`], D10 row 16 —
/// frozen v1 surface, consumed by name, costing zero new constants). Written
/// as a `const` for the reason `fuzz_entry.rs`'s start-digest-offset assert
/// is: *"the build stops here rather than the target quietly losing its
/// coverage."* A raise that breaks it fails `cargo build` on every lane, on
/// `wasm32`, for every contributor — there is no lane to rerun and no budget
/// to adjust.
///
/// Measured headroom at 40 B per frame (D102 §3.2): 1 024 → 5.08 % of the
/// cap, 4 096 → green, 16 384 → green and the last one, 32 768 → **red**,
/// 65 536 → red at 2.51×.
const _: () = assert!(
    OTS_STRUCTURAL_ALLOC_BYTES as u64 <= crate::codec::caps::MAX_OTS_BYTES,
    "D58 §10.3 rule 6 clause (c): the .ots parser's count-bounded containers \
     now reserve more than MAX_OTS_BYTES. A count limit was raised without \
     arguing its structural cost in memory — re-argue it (D102 §3.2) rather \
     than relaxing this assertion."
);

/// Rule 6's cost for one **`input_len`-byte** input, which is what an
/// allocation guard may exempt.
///
/// Not the flat [`OTS_STRUCTURAL_ALLOC_BYTES`]: a constant exemption is the
/// shape D102 §4.2 refutes, because it would hide the entire D58 §3.1/§3.2
/// class the fuzz target exists to catch. The bound is a **function of the
/// input**, and it is sound for one arithmetic reason — **every frame and
/// every attestation costs at least one wire byte** (a bare `0x08`, a bare
/// `0x00`), so `rest.len() ≤ ops ≤ input_len` and
/// `attestations.len() ≤ input_len`. An input that never goes deep gets
/// almost no exemption.
///
/// Consumed by `fuzz/fuzz_targets/anchor_ots.rs` and by
/// `crates/antseal-core/tests/anchor_ots_alloc.rs`, so the derivation exists
/// exactly once.
#[must_use]
pub fn ots_structural_alloc_bytes(input_len: usize) -> usize {
    let frames = input_len.min(MAX_OTS_DEPTH as usize).next_power_of_two();
    let attestations = input_len
        .min(MAX_OTS_ATTESTATIONS as usize)
        .next_power_of_two();
    frames * OTS_FRAME_BYTES + attestations * OTS_ATTESTATION_BYTES
}

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

    /// **§5's eighth row is pinned by nothing, and this records why rather
    /// than leaving the next audit to rediscover it** (D107 §8 (i)).
    ///
    /// The needle above hardcodes the owner cell to `A11`, so it reaches
    /// seven rows. The eighth — A42's `MAX_OTS_CALENDAR_RESPONSE_BYTES`,
    /// added by D54 §7 after this cross-check was written — is **not** one of
    /// them, and cannot be: its constant lives in
    /// `antseal-anchor`'s `ots::MAX_OTS_CALENDAR_RESPONSE_BYTES`, and
    /// `antseal-anchor` depends on `antseal-core`, not the reverse. A pin
    /// written here could only compare the row against a **literal typed in
    /// this file**, which is the defect A110's notes name in `caps.rs`'s own
    /// `f4_registry_values`: an instrument that checks a number against
    /// itself. So the row is pinned from the crate that can see both — where
    /// `antseal_anchor::ots::tests::the_measured_upgrade_response_sizes_are_the_f4_row`
    /// already reads the fixtures the row's margin cell cites — and this
    /// assertion records the boundary rather than pretending to cross it.
    ///
    /// What is checked here is the one thing this crate *can* see: that the
    /// eighth row exists with the owner D54 §7 gave it, so a silent deletion
    /// of the row is red somewhere even though its value is not.
    #[test]
    fn the_eighth_registry_row_is_a42s_and_this_crate_cannot_pin_its_value() {
        const REGISTRY: &str = include_str!("../../../../../docs/format/anchor-artifact-limits.md");

        assert!(
            REGISTRY.contains("| `MAX_OTS_CALENDAR_RESPONSE_BYTES` | A42 |"),
            "§5's eighth row is gone or has changed owner — D54 §7 rules the row and \
             A42 owns it; its *value* is pinned from `antseal-anchor`, which is the \
             only crate that can see both the constant and this document"
        );
    }

    /// **Rule 6's registry column, cross-checked like the values are.**
    ///
    /// D102 gave every §5 row a `structural cost` cell. A documented number
    /// nothing checks is the F19 → F14 failure this whole document exists to
    /// prevent, and the two cells that carry a *number* are exactly the two
    /// that move when a count limit is raised — so they are pinned to the
    /// derivation rather than to a literal.
    ///
    /// `include_str!` for the same reason the row above uses it: the
    /// `wasm32-core-tests` lane has no filesystem. The **formula**, which is
    /// the part that must not drift, is checked everywhere, and *"stated
    /// somewhere normative"* is the whole of that claim — so it stays a
    /// document-wide search. The **byte counts** are checked per target, and
    /// need no `cfg` to be: the needles are built from the `size_of`-derived
    /// constants, so on x86-64 this reads the x86-64 figure §5's row states
    /// and on `wasm32-unknown-unknown` — where `Frame` is 24 B and
    /// `OtsAttestation` 32 B — it reads the `wasm32` figure from the same
    /// cell. **Neither target asserts the other's
    /// numbers**, which is the split `anchor/caps.rs` took at `873a1cf` when
    /// the same omission on `size_of::<Certificate>()` reddened that lane.
    /// There the measurements were literals and the split had to be written
    /// out; here they are derived, so it falls out of clause (a).
    ///
    /// **D104 §6 rules the 32-bit arm** (A121). Until it landed the byte
    /// counts ran only under `size_of::<usize>() == 8`, so §5a's `wasm32`
    /// figures were exactly the *"number typed by hand is a number that
    /// survives a raise"* that clause (a) forbids — one file over from where
    /// clause (a) is written.
    ///
    /// **The byte counts are read out of the row, not out of the document**
    /// (A123). They were `REGISTRY.contains(&needle)` over the whole file
    /// until 2026-08-10, which pins *"this number appears in this
    /// document"* — not *"this row states this number"*. Proved by
    /// mutation, not by reading: changing the `MAX_OTS_ATTESTATIONS` row's
    /// own structural-cost figure and nothing else left this test — and
    /// every other test in this crate — **green**, because §5a's two-target
    /// table still carried the string elsewhere in the file. A121 had just
    /// doubled the number of places any one figure legitimately appears,
    /// which makes a substring search weaker rather than stronger. So each
    /// figure is now matched inside the `structural cost` cell of the row it
    /// belongs to, **carrying its target label**, because that cell states
    /// both targets and an unqualified match would survive the two being
    /// swapped. `registry_rows` is the parse — the one this file already
    /// had for §6's cross-check, not a second one.
    #[test]
    fn the_structural_cost_column_states_the_derivation_and_its_value() {
        const REGISTRY: &str = include_str!("../../../../../docs/format/anchor-artifact-limits.md");

        for formula in [
            "`next_pow2(1_024) x size_of::<Frame>()`",
            "`next_pow2(256) x size_of::<OtsAttestation>()`",
        ] {
            assert!(
                REGISTRY.contains(formula),
                "the F4 registry's structural-cost cell no longer states {formula} — \
                 clause (a) says the cost is derived, and the row must say from what"
            );
        }

        let mut violations = Vec::new();
        let rows = registry_rows(&unfenced(REGISTRY), &mut violations);
        assert!(
            violations.is_empty(),
            "§5's registry table did not parse, so no cell can be read out of it — \
             every figure below would be unchecked rather than red: {violations:?}"
        );

        // Everywhere, per target: the derived cost against the figure the
        // row itself prints for whichever target is running this test. The
        // label is part of the needle — the cell renders both targets as
        // `**N NNN B** (x86-64) and **N NNN B** (`wasm32`)`, so its exact
        // rendering is load-bearing here and a reword of it is a red test
        // rather than a silently unchecked cell.
        let (target, label) = if core::mem::size_of::<usize>() == 8 {
            ("x86-64", "(x86-64)")
        } else {
            ("wasm32", "(`wasm32`)")
        };
        for (limit, what, bytes) in [
            (
                "MAX_OTS_DEPTH",
                "the parser's `walk.rest`",
                OTS_STRUCTURAL_WORK_STACK_BYTES,
            ),
            (
                "MAX_OTS_ATTESTATIONS",
                "the attestation list",
                OTS_STRUCTURAL_ATTESTATION_BYTES,
            ),
        ] {
            let Some(row) = rows.iter().find(|r| r.name == limit) else {
                panic!(
                    "§5 carries no `{limit}` row — D102's `structural cost` column hangs \
                     off that row, and this assertion is the only thing that reads it"
                );
            };
            let needle = format!("**{}** {label}", format_spaced(bytes));
            assert!(
                row.structural_cost.contains(&needle),
                "§5's `{limit}` row states no structural cost of {needle:?} for {what} on \
                 {target}; its cell reads {:?}. The derived cost and its registry row have \
                 drifted, which is the one thing D102's column exists to make impossible",
                row.structural_cost
            );
        }

        // The **sum** is the one figure with no row to be read out of: §5's
        // `structural cost` column is per limit, and the total of both
        // containers is stated only by §5a's two-target table. So it stays a
        // document-wide search — and says so by requiring exactly one match,
        // which is the property that made the searches above pass for
        // reasons their author never intended. A second home for this figure
        // is not a defect, but it is the moment this line stops meaning what
        // it says, and the next lane should read A123 before relaxing it.
        let summed = format!("**{}**", format_spaced(OTS_STRUCTURAL_ALLOC_BYTES));
        assert_eq!(
            REGISTRY.matches(summed.as_str()).count(),
            1,
            "§5a's two-target table is the single site that states the summed structural \
             cost, and it must state {summed:?} for {target} — exactly once, because this \
             one is matched against the document rather than against a cell"
        );

        // 32-bit only, mirroring `caps.rs`'s else-arm at `873a1cf`: the
        // *direction* §5a states and A109's lowering argument inverted. An
        // inequality rather than an equality because 53 248 is the **other**
        // target's measurement — this arm reports that the browser tab is
        // still the cheaper venue without pinning a number it cannot measure.
        // Bound to a local for `caps.rs`'s reason too: a bare const on the
        // left is `clippy::assertions_on_constants`, which would push this
        // into a `const` block and lose the target split.
        let structural = OTS_STRUCTURAL_WORK_STACK_BYTES + OTS_STRUCTURAL_ATTESTATION_BYTES;
        if core::mem::size_of::<usize>() != 8 {
            assert!(
                structural < 53_248,
                "the 32-bit structural cost ({structural} B) has reached the x86-64 \
                 measurement §5a records. The browser tab was the *cheapest* venue this \
                 parser runs in, not the tightest; if it no longer is, §5a's direction \
                 claim and D104 §6's first ground are both stale"
            );
        }
    }

    // ── D107 (Q126): §6's limit-change log, checked against §5's rows ─────
    //
    // D107 moves §6's obligation off *lowering* — the branch F4 makes nearly
    // impossible (D104 §2.1 closes its window at first release, D104 §3 rules
    // its only proposed exercise empty) — and onto **any change to a limit's
    // recorded value**, which is the branch F4 exists to permit ("always
    // available and never expires", D104 §10). The checker below is a pure
    // function of two `&str`s, so its positive arm is committed fixture
    // strings rather than a hypothetical future commit: no script, no gate
    // lane, no temp files, and nothing target-dependent, so the
    // `wasm32-core-tests` lane runs it for the price of a string comparison.

    /// Which way a §6 entry says a limit moved — R2.3's third field.
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    enum Verb {
        Raised,
        Lowered,
    }

    /// One §5 row, reduced to the cells R1 calls a limit's *recorded value*,
    /// plus the two A113 needs to recompute the `margin` column and the
    /// `structural cost` cell A123 needs to read a figure **out of its own
    /// row** rather than out of the document.
    struct RegistryRow {
        name: String,
        value: String,
        measured_against: String,
        margin: String,
        lowered: String,
        structural_cost: String,
    }

    /// One §6 entry, reduced to the head R2.3 says the checker parses.
    struct LogEntry {
        date: String,
        limit: Option<String>,
        verb: Option<Verb>,
        from: Option<String>,
    }

    /// The §5 table's header, which is also how the table is located.
    ///
    /// D107 R2.1 renamed `initial value` to `value`; the needle is written
    /// against the new name so a revert to the old header is a red test
    /// rather than a silently unchecked table.
    const REGISTRY_HEADER: &str = "| limit | owner | value | date set |";

    /// Lines with fenced code blocks removed.
    ///
    /// R2.3 prints the entry grammar inside a fence, and a grammar example is
    /// documentation rather than a log entry — a checker that read it would
    /// report `LIMIT_NAME` as a limit with no row, every run, forever.
    fn unfenced(doc: &str) -> Vec<&str> {
        let mut out = Vec::new();
        let mut fenced = false;
        for line in doc.lines() {
            if line.trim_start().starts_with("```") {
                fenced = !fenced;
                continue;
            }
            if !fenced {
                out.push(line);
            }
        }
        out
    }

    /// The chunks of `text` that sit between backticks.
    fn backticked(text: &str) -> Vec<&str> {
        text.split('`')
            .enumerate()
            .filter_map(|(i, part)| (i % 2 == 1).then_some(part))
            .collect()
    }

    /// R2.1's grammar for a `value` cell: one bare value, nothing else.
    fn is_bare_value(cell: &str) -> bool {
        !cell.is_empty() && cell.chars().all(|c| c.is_ascii_digit() || c == '_')
    }

    /// Shaped like a limit constant, so an entry naming one that has no row
    /// is caught rather than silently skipped.
    ///
    /// Deliberately narrower than "any backticked token": §6 entries cite
    /// paths and tasks in backticks too, and R2.4's zero-point entry is
    /// exempt from R2.3 precisely *by naming no limit*.
    fn is_limit_name(token: &str) -> bool {
        token.len() >= 5
            && token.contains('_')
            && token.starts_with(|c: char| c.is_ascii_uppercase())
            && token
                .chars()
                .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
    }

    /// R2.3's first field: the entry opens on a `YYYY-MM-DD` date.
    fn is_date_prefixed(field: &str) -> bool {
        let b = field.as_bytes();
        b.len() >= 10
            && b[..4].iter().all(u8::is_ascii_digit)
            && b[4] == b'-'
            && b[5..7].iter().all(u8::is_ascii_digit)
            && b[7] == b'-'
            && b[8..10].iter().all(u8::is_ascii_digit)
    }

    fn registry_rows(lines: &[&str], violations: &mut Vec<String>) -> Vec<RegistryRow> {
        let mut rows = Vec::new();
        let Some(start) = lines
            .iter()
            .position(|l| l.trim_start().starts_with(REGISTRY_HEADER))
        else {
            violations.push(format!(
                "§5's registry table is unreadable: no line begins {REGISTRY_HEADER:?}"
            ));
            return rows;
        };
        for line in &lines[start + 1..] {
            let row = line.trim();
            if !row.starts_with('|') {
                break;
            }
            if row.starts_with("| ---") {
                continue;
            }
            let cells: Vec<&str> = row
                .trim_start_matches('|')
                .trim_end_matches('|')
                .split('|')
                .map(str::trim)
                .collect();
            if cells.len() != 8 {
                violations.push(format!(
                    "§5 row {:?} has {} cells, not the 8 its header declares — a cell \
                     carrying a stray table separator makes every column after it a \
                     different column",
                    cells.first().copied().unwrap_or(row),
                    cells.len()
                ));
                continue;
            }
            let Some(name) = cells[0]
                .strip_prefix('`')
                .and_then(|n| n.strip_suffix('`'))
                .filter(|n| !n.contains('`'))
            else {
                violations.push(format!(
                    "§5's limit cell {:?} is not one backticked limit name — the column \
                     is this table's key, and every cross-check reads it as one",
                    cells[0]
                ));
                continue;
            };
            rows.push(RegistryRow {
                name: name.to_string(),
                value: cells[2].to_string(),
                measured_against: cells[4].to_string(),
                margin: cells[5].to_string(),
                lowered: cells[6].to_string(),
                structural_cost: cells[7].to_string(),
            });
        }
        rows
    }

    fn log_entries(lines: &[&str], violations: &mut Vec<String>) -> Vec<LogEntry> {
        let Some(start) = lines.iter().position(|l| l.starts_with("## 6.")) else {
            violations.push(
                "the limit-change log is gone: no `## 6.` heading. D107 §2(b) refuses \
                 deleting it — a `lowered` cell is written only by a lowering, so it \
                 cannot carry the reason for the raise F4 exists to permit"
                    .to_string(),
            );
            return Vec::new();
        };

        // Gather each entry's full text: a `- ` line plus its continuations.
        let mut raw: Vec<String> = Vec::new();
        let mut in_entry = false;
        for line in &lines[start + 1..] {
            if line.starts_with("## ") {
                break;
            }
            if let Some(rest) = line.strip_prefix("- ") {
                raw.push(rest.trim().to_string());
                in_entry = true;
            } else if in_entry && line.starts_with(char::is_whitespace) && !line.trim().is_empty() {
                if let Some(last) = raw.last_mut() {
                    last.push(' ');
                    last.push_str(line.trim());
                }
            } else {
                in_entry = false;
            }
        }

        let mut entries = Vec::new();
        for text in raw {
            let Some((date, after)) = text
                .strip_prefix("**")
                .and_then(|rest| rest.split_once("**"))
            else {
                violations.push(format!(
                    "§6 entry {text:?} does not open with a bolded date — R2.3's first field"
                ));
                continue;
            };
            if !is_date_prefixed(date) {
                violations.push(format!(
                    "§6 entry's bolded field {date:?} does not start with a YYYY-MM-DD \
                     date — R2.3's first field, and the only one that orders the log"
                ));
                continue;
            }

            // R2.3: everything after the second em dash is free prose the
            // checker does not parse. An entry with fewer dashes is scanned
            // whole, which is what exempts R2.4's zero point by naming no
            // limit rather than by living in a special case.
            let segments: Vec<&str> = after.split('—').collect();
            let head = if segments.len() >= 2 {
                segments[1]
            } else {
                segments[0]
            };

            let tokens = backticked(head);
            let limit = tokens
                .iter()
                .find(|t| is_limit_name(t))
                .map(|t| (*t).to_string());
            let verb = match (head.contains("raised"), head.contains("lowered")) {
                (true, false) => Some(Verb::Raised),
                (false, true) => Some(Verb::Lowered),
                _ => None,
            };
            let from = tokens
                .iter()
                .find(|t| is_bare_value(t))
                .map(|t| (*t).to_string());
            entries.push(LogEntry {
                date: date.to_string(),
                limit,
                verb,
                from,
            });
        }
        entries
    }

    /// D107 R4's invariant, both directions, over one document.
    ///
    /// Forward: a §5 row whose **recorded value** has moved — its `value`
    /// cell no longer one bare value, or its `lowered` cell no longer
    /// `never` — needs a §6 entry naming it. Reverse: a §6 entry naming a
    /// limit must name one this table carries, and the table must corroborate
    /// what the entry claims. The reverse arm is D104 §5's refusal of
    /// fabricated provenance made mechanical: a lane cannot write *"we
    /// lowered X"* into §6 unless §5 says so.
    fn limit_change_log_violations(doc: &str) -> Vec<String> {
        let mut violations = Vec::new();
        let lines = unfenced(doc);
        let rows = registry_rows(&lines, &mut violations);
        let entries = log_entries(&lines, &mut violations);

        for row in &rows {
            let cause = if !is_bare_value(&row.value) {
                format!("its value cell reads {:?}, not one bare value", row.value)
            } else if row.lowered != "never" {
                format!("its lowered cell reads {:?}", row.lowered)
            } else {
                continue;
            };
            if !entries
                .iter()
                .any(|e| e.limit.as_deref() == Some(row.name.as_str()))
            {
                violations.push(format!(
                    "§5's `{}` records a change ({cause}) and §6 names no such limit — \
                     D107 R1: a commit may not change a limit's recorded value without \
                     a §6 entry naming it",
                    row.name
                ));
            }
        }

        for entry in &entries {
            let Some(limit) = entry.limit.as_deref() else {
                continue;
            };
            let Some(row) = rows.iter().find(|r| r.name == limit) else {
                violations.push(format!(
                    "§6's {} entry names `{limit}`, which has no §5 row — this log \
                     records changes to limits this table carries, and nothing else",
                    entry.date
                ));
                continue;
            };
            match entry.verb {
                None => violations.push(format!(
                    "§6's {} entry names `{limit}` but says neither raised nor lowered \
                     — R2.3's third field is what §5 is checked against",
                    entry.date
                )),
                Some(Verb::Lowered) => {
                    if row.lowered == "never" {
                        violations.push(format!(
                            "§6's {} entry says `{limit}` was lowered and §5's lowered \
                             cell still reads `never` — fabricated provenance, refused \
                             mechanically (D104 §5)",
                            entry.date
                        ));
                    }
                }
                Some(Verb::Raised) => match entry.from.as_deref() {
                    None => violations.push(format!(
                        "§6's {} entry says `{limit}` was raised and does not say from \
                         what — R2.3's `N` is the value §5 is checked against",
                        entry.date
                    )),
                    Some(from) => {
                        if row.value == from {
                            violations.push(format!(
                                "§6's {} entry says `{limit}` was raised from `{from}` \
                                 and §5 still records `{from}` — fabricated provenance, \
                                 refused mechanically (D104 §5)",
                                entry.date
                            ));
                        }
                    }
                },
            }
        }
        violations
    }

    /// The tree's own document satisfies R1 in both directions.
    ///
    /// Today this passes because **zero rows trigger the forward arm**: every
    /// `value` cell holds one bare value and every `lowered` cell reads
    /// `never`. That is a fact rather than an absence, and
    /// [`the_limit_change_log_checker_catches_every_planted_violation`] is
    /// what keeps it from being a checker that cannot go red.
    #[test]
    fn the_limit_change_log_agrees_with_the_registry_rows() {
        const REGISTRY: &str = include_str!("../../../../../docs/format/anchor-artifact-limits.md");

        let violations = limit_change_log_violations(REGISTRY);
        assert!(
            violations.is_empty(),
            "docs/format/anchor-artifact-limits.md violates D107 R1:\n  {}",
            violations.join("\n  ")
        );
    }

    /// **The whole positive arm** (D107 §6): every violation the checker can
    /// emit, planted, each asserted to name the thing it is about.
    ///
    /// D107 §6: *"Run the planted cases before trusting the green one … if a
    /// fixture passes the checker, the checker is not checking."* That is
    /// A104's rule — *"a planted fault passed green in a brand-new suite
    /// until the row was widened"* — so the row is widened here rather than
    /// after the fact: D107 R4's table names four cases, and this covers the
    /// nine distinct violations the implementation can actually produce.
    #[test]
    fn the_limit_change_log_checker_catches_every_planted_violation() {
        /// A miniature registry, so a planted violation is one visible line
        /// rather than a diff against four hundred lines of real document.
        fn doc(rows: &str, log: &str) -> String {
            format!(
                "## 5. The F4 registry\n\n\
                 {REGISTRY_HEADER} measured against (A25 fixture path) | margin | lowered | structural cost (D102) |\n\
                 | --- | --- | --- | --- | --- | --- | --- | --- |\n\
                 {rows}\n\n\
                 ## 6. Limit-change log\n\n\
                 {log}\n"
            )
        }
        const UNCHANGED: &str =
            "| `MAX_OTS_OPS` | A11 | 4_096 | 2026-08-02 | a fixture | 40.96x | never | none |";
        const ZERO_POINT: &str =
            "- **2026-07-28** — table created; no limit's recorded value has changed since.";

        let cases: [(&str, String, &str); 12] = [
            (
                "a raise appended to the value cell, §6 silent",
                doc(
                    "| `MAX_OTS_OPS` | A11 | 4_096 (2026-08-02), 8_192 (2026-09-01) | \
                     2026-08-02 | a fixture | 40.96x | never | none |",
                    ZERO_POINT,
                ),
                "MAX_OTS_OPS",
            ),
            (
                "a lowering recorded in the cell, §6 silent",
                doc(
                    "| `MAX_OTS_DEPTH` | A11 | 1_024 | 2026-08-02 | a fixture | 15.28x | \
                     `2026-09-01` | none |",
                    ZERO_POINT,
                ),
                "MAX_OTS_DEPTH",
            ),
            (
                "§6 claims a raise the table does not corroborate",
                doc(
                    UNCHANGED,
                    "- **2026-09-01** — `MAX_OTS_OPS` raised `4_096` → `8_192` (A11) — \
                     because we said so.",
                ),
                "raised from `4_096`",
            ),
            (
                "§6 claims a lowering the table does not corroborate",
                doc(
                    UNCHANGED,
                    "- **2026-09-01** — `MAX_OTS_OPS` lowered `4_096` → `2_048` (A11) — \
                     because we said so.",
                ),
                "was lowered",
            ),
            (
                "§6 names a limit with no §5 row",
                doc(
                    UNCHANGED,
                    "- **2026-09-01** — `MAX_INVENTED_LIMIT` raised `1` → `2` (A11) — \
                     from nowhere.",
                ),
                "MAX_INVENTED_LIMIT",
            ),
            (
                "§6 names a limit and no direction",
                doc(
                    UNCHANGED,
                    "- **2026-09-01** — `MAX_OTS_OPS` adjusted `4_096` → `8_192` (A11) \
                     — with no verb.",
                ),
                "neither raised nor lowered",
            ),
            (
                "§6 claims a raise and does not say from what",
                doc(
                    UNCHANGED,
                    "- **2026-09-01** — `MAX_OTS_OPS` raised (A11) — to something.",
                ),
                "does not say from what",
            ),
            (
                "§6 entry with no date",
                doc(
                    UNCHANGED,
                    "- **someday** — `MAX_OTS_OPS` raised `4_096` → `8_192`.",
                ),
                "YYYY-MM-DD",
            ),
            (
                "§6 deleted outright",
                format!(
                    "## 5. The F4 registry\n\n\
                     {REGISTRY_HEADER} measured against (A25 fixture path) | margin | lowered | structural cost (D102) |\n\
                     | --- | --- | --- | --- | --- | --- | --- | --- |\n\
                     {UNCHANGED}\n"
                ),
                "no `## 6.` heading",
            ),
            // …and three structural faults, which are about the table rather
            // than about a limit, so they carry no limit name to assert on.
            (
                "the §5 table renamed out from under the checker",
                "## 5. The F4 registry\n\n| limit | owner | initial value | date set |\n\n## 6. \
                 Limit-change log\n\n- **2026-07-28** — table created.\n"
                    .to_string(),
                "no line begins",
            ),
            (
                "a row with a stray cell boundary",
                doc(
                    "| `MAX_OTS_OPS` | A11 | 4_096 | 2026-08-02 | a | fixture | 40.96x | \
                     never | none |",
                    ZERO_POINT,
                ),
                "not the 8 its header declares",
            ),
            (
                "a limit cell that is not one backticked name",
                doc(
                    "| MAX_OTS_OPS | A11 | 4_096 | 2026-08-02 | a fixture | 40.96x | never | \
                     none |",
                    ZERO_POINT,
                ),
                "not one backticked limit name",
            ),
        ];

        // Every case is reported, not just the first: a fixture set where one
        // break hides the rest cannot tell a lane whether it broke one arm or
        // deleted the checker.
        let mut passed_the_checker: Vec<&str> = Vec::new();
        for (what, fixture, expected) in &cases {
            let violations = limit_change_log_violations(fixture);
            if !violations.iter().any(|v| v.contains(expected)) {
                passed_the_checker.push(what);
            }
        }
        assert!(
            passed_the_checker.is_empty(),
            "{} of {} planted cases produced no violation naming what they are about, \
             which means the checker is not checking them: {passed_the_checker:?}",
            passed_the_checker.len(),
            cases.len()
        );
    }

    // ── A113: the `margin` column, recomputed rather than read ───────────
    //
    // Until this landed, `margin` was **the only numeric column in §5 that no
    // test reached**: `ots_limits_match_the_f4_registry`'s needle stops at the
    // `value` cell boundary (column 3) and never sees column 6. That is not a
    // hypothetical gap — D104 §4 records A109 reasoning from a **15.28x**
    // figure that had been derived against a third-party crate's test constant
    // and was, by then, wrong about every antseal artifact. A number that
    // reads like the checked ones and is checked by nothing is worse than an
    // absent number, because it is quoted with the others' authority.
    //
    // The check is **document-internal arithmetic**, deliberately: `margin` is
    // defined as `value / measured`, and both operands are already in the row.
    // That keeps this test free of any hand-typed measurement — the defect
    // A110's notes name in `caps.rs`'s `f4_registry_values`, "an instrument
    // that checks a number against itself". The two operands are pinned
    // elsewhere, each by a named test, and neither pin is here:
    //
    //   * `value`    — `ots_limits_match_the_f4_registry` (A11 rows) and
    //                  `anchor::caps::tests::f4_registry_values` (A5 rows).
    //   * `measured` — the parser, over the artifacts the cells cite:
    //                  `super::tests::the_committed_fixtures_have_the_shape_the_f4_registry_records`
    //                  and, for the 3 808-byte upgraded artifact,
    //                  `crates/antseal-core/tests/anchor_vectors.rs`'s
    //                  `vector_anchor_upgraded_artifact_has_the_shape_the_f4_registry_records`.
    //
    // So this row closes the triangle rather than adding a fourth opinion.

    /// The measured quantity a `measured against` cell states: its **first
    /// bolded number**.
    ///
    /// §5's Update rule requires exactly this rendering, which is what makes
    /// the column machine-readable without a ninth column: the cell is prose
    /// naming a fixture and explaining a choice, and the one number the
    /// margin divides by is the one in bold. Trailing ` B` and the document's
    /// space thousands-separator are its own conventions (`2 105 B`).
    fn measured_quantity(cell: &str) -> Option<u64> {
        cell.split("**")
            .skip(1)
            .step_by(2)
            .filter_map(|span| {
                let token = span.trim().trim_end_matches(" B").replace(' ', "");
                (!token.is_empty() && token.chars().all(|c| c.is_ascii_digit()))
                    .then(|| token.parse().ok())
                    .flatten()
            })
            .next()
    }

    /// A `margin` cell's leading `N.MMx`, as `(scaled integer, decimals)`.
    ///
    /// The decimal count is read from the cell rather than fixed, because the
    /// table genuinely uses two precisions — the `.ots` rows print 2 places
    /// and D60's DER rows print 1 — and recomputing at a precision the cell
    /// does not use would fail every row for a reason that is not the reason.
    /// Prose after the `x` is allowed and ignored; A42's row carries some.
    fn printed_margin(cell: &str) -> Option<(u64, u32)> {
        let head: String = cell
            .chars()
            .take_while(|c| c.is_ascii_digit() || *c == '.')
            .collect();
        if !cell[head.len()..].starts_with('x') {
            return None;
        }
        let (whole, frac) = head.split_once('.')?;
        if whole.is_empty() || frac.is_empty() {
            return None;
        }
        Some((format!("{whole}{frac}").parse().ok()?, frac.len() as u32))
    }

    /// `value / measured`, scaled by `10^decimals` and rounded half-up.
    ///
    /// Integer arithmetic throughout: the same expression must produce the
    /// same digits on x86-64 and on `wasm32`, and a float round-trip through
    /// a formatter is the one step in this file that could differ.
    fn scaled_margin(value: u64, measured: u64, decimals: u32) -> u64 {
        (value * 10_u64.pow(decimals) * 2 + measured) / (measured * 2)
    }

    /// **A113.** Every `margin` cell is its own row's `value / measured`.
    ///
    /// Quantified over **every** §5 row, not just the seven this module's
    /// constants cover — the arithmetic needs no constant, so A42's row and
    /// D60's four A5 rows are checked here even though their *values* are
    /// pinned from other crates (see
    /// [`the_eighth_registry_row_is_a42s_and_this_crate_cannot_pin_its_value`],
    /// which records that boundary for the value cell and is unaffected).
    /// `MAX_DER_NESTING_DEPTH` needs no exemption either, although it is the
    /// one row whose value is pinned *behaviourally*, to `der`'s private
    /// `MAX_DEPTH`, rather than to an antseal constant: what is divided here
    /// is the number the table records, and the table records 63.
    #[test]
    fn the_margin_column_is_the_value_over_the_measurement() {
        const REGISTRY: &str = include_str!("../../../../../docs/format/anchor-artifact-limits.md");

        let mut violations: Vec<String> = Vec::new();
        let rows = registry_rows(&unfenced(REGISTRY), &mut violations);
        assert!(
            violations.is_empty(),
            "§5's table did not parse: {violations:?}"
        );

        let mut checked = 0_usize;
        for row in &rows {
            let name = &row.name;
            let Ok(value) = row.value.replace('_', "").parse::<u64>() else {
                violations.push(format!(
                    "`{name}`'s value cell {:?} is not a number",
                    row.value
                ));
                continue;
            };
            let Some(measured) = measured_quantity(&row.measured_against) else {
                violations.push(format!(
                    "`{name}`'s `measured against` cell states no bolded number, so its \
                     margin divides by nothing this document records — §5's Update rule \
                     requires the measured quantity in bold"
                ));
                continue;
            };
            let Some((printed, decimals)) = printed_margin(&row.margin) else {
                violations.push(format!(
                    "`{name}`'s margin cell {:?} does not open `N.MMx`",
                    row.margin
                ));
                continue;
            };
            if measured == 0 {
                violations.push(format!(
                    "`{name}` measures 0 — a margin over it is undefined"
                ));
                continue;
            }
            let recomputed = scaled_margin(value, measured, decimals);
            if recomputed != printed {
                let places = decimals as usize;
                let scale = 10_u64.pow(decimals);
                violations.push(format!(
                    "`{name}`: {value} / {measured} is {}.{:0places$}x at this cell's own \
                     precision, and the cell reads {}.{:0places$}x",
                    recomputed / scale,
                    recomputed % scale,
                    printed / scale,
                    printed % scale,
                ));
            }
            checked += 1;
        }

        assert!(
            violations.is_empty(),
            "docs/format/anchor-artifact-limits.md §5's margin column does not agree with \
             its own value and measurement cells:\n  {}",
            violations.join("\n  ")
        );
        assert_eq!(
            checked,
            rows.len(),
            "every §5 row's margin is recomputed, or this test has grown a silent exemption"
        );
        assert!(checked >= 12, "§5 lost rows: only {checked} were checked");
    }

    /// The positive arm: the checker goes red on each way a margin cell can
    /// be wrong, so the green run above is evidence rather than a tautology.
    ///
    /// A104's rule, and D107 §6's — *"if a fixture passes the checker, the
    /// checker is not checking"*. Each case is one visible row rather than a
    /// mutation of the real four-hundred-line document.
    #[test]
    fn a_wrong_margin_cell_is_caught_in_every_way_it_can_be_wrong() {
        for (what, value, measured_against, margin, expected) in [
            (
                "a margin off by one unit in the last printed place",
                "1_024",
                "the artifact (depth **85**)",
                "12.04x",
                "12.05x",
            ),
            (
                "the retired figure, which is what A109 actually quoted",
                "1_024",
                "the artifact (depth **85**)",
                "15.28x",
                "12.05x",
            ),
            (
                "a margin recomputed against the wrong measurement",
                "16_384",
                "the artifact (**89** B operand)",
                "94.16x",
                "184.09x",
            ),
            (
                "a value cell and a margin cell that disagree",
                "2_048",
                "the artifact (depth **85**)",
                "12.05x",
                "24.09x",
            ),
        ] {
            let doc = format!(
                "## 5. The F4 registry\n\n\
                 {REGISTRY_HEADER} measured against | margin | lowered | structural cost |\n\
                 | --- | --- | --- | --- | --- | --- | --- | --- |\n\
                 | `MAX_OTS_DEPTH` | A11 | {value} | 2026-08-02 | {measured_against} | \
                 {margin} | never | none |\n"
            );
            let mut violations = Vec::new();
            let rows = registry_rows(&unfenced(&doc), &mut violations);
            let row = rows.first().expect("the planted row parses");
            let value = row.value.replace('_', "").parse::<u64>().expect("a number");
            let measured = measured_quantity(&row.measured_against).expect("a bolded number");
            let (printed, decimals) = printed_margin(&row.margin).expect("an `N.MMx` cell");
            let recomputed = scaled_margin(value, measured, decimals);
            assert_ne!(
                recomputed, printed,
                "{what}: the planted fault was accepted"
            );

            let places = decimals as usize;
            let scale = 10_u64.pow(decimals);
            assert_eq!(
                format!("{}.{:0places$}x", recomputed / scale, recomputed % scale),
                expected,
                "{what}: the checker names the wrong correct value"
            );
        }

        // …and the two shapes that carry no number at all.
        assert_eq!(
            measured_quantity("a fixture with **no** bolded number"),
            None
        );
        assert_eq!(printed_margin("never measured"), None);
        assert_eq!(printed_margin("12.05"), None, "a margin cell ends in `x`");
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

    /// The registry renders byte counts with a space thousands separator
    /// (`40 960 B`), which is the document's own convention and not this
    /// module's; matching it is what makes the cross-check a string the
    /// reader can see rather than a number they must recompute.
    fn format_spaced(value: usize) -> String {
        let digits = value.to_string();
        let mut out = String::new();
        for (i, ch) in digits.chars().enumerate() {
            if i > 0 && (digits.len() - i).is_multiple_of(3) {
                out.push(' ');
            }
            out.push(ch);
        }
        out.push_str(" B");
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
