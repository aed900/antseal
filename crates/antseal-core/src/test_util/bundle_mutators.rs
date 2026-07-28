//! **The shared hostile-bundle generator** (task R10): one mutation engine
//! driving both the in-suite proptest and the cargo-fuzz target.
//!
//! MVP-SPEC.md line 153 requires parser hardening and fuzzing in CI for the
//! formats M0 owns, and line 187 names hostile bundles as a risk. The
//! obligation on `verify_bundle` is exact and worth stating as an invariant
//! rather than a vibe:
//!
//! > For **every** byte string, `verify_bundle` returns a typed
//! > [`VerifyError`] or a [`VerificationReport`]. It never panics, never
//! > aborts, and never loops without returning.
//!
//! That is the "parse defensively" working principle in executable form,
//! and it is stronger than any tamper row: rows assert *which* error a
//! *chosen* mutation produces, whereas this asserts that *no* input escapes
//! the type.
//!
//! # Why the engine lives here and not in the fuzz crate
//!
//! A fuzz target that carries its own mutators is exercised only when
//! someone runs the fuzzer. Putting the engine in the library, behind
//! `test-util`, means:
//!
//! - the **normal test suite** runs it every CI build, through R10's
//!   proptest — so the mutators cannot silently rot between fuzz runs;
//! - the fuzz target is a thin shim over [`mutate_from_entropy`] and
//!   [`drive`], so a crash the fuzzer finds is reproducible from the same
//!   code path the proptest uses, with no "works under proptest, differs
//!   under libfuzzer" gap to debug;
//! - **no fuzzing dependency enters this crate.** The driver takes raw
//!   entropy bytes and interprets them itself, so nothing here needs
//!   `arbitrary`, and the audited dependency graph is untouched.
//!
//! # What this complements, and does not duplicate
//!
//! F17 fuzzes the **CBOR decoders** — it is looking for decoder bugs on
//! arbitrary bytes, and most of its inputs die at the first byte. This
//! target's job is the opposite end: get *past* the decoder and stress the
//! stages behind it, which is why most of its budget goes on structure-aware
//! mutation of **valid R6 bundles** rather than on random bytes. The two
//! overlap only in the uninteresting region, and [`Outcome`] is reported per
//! input so a corpus run can show how much of the budget actually reached
//! the pipeline.
//!
//! # The mutation set
//!
//! [`Mutation`] is deliberately small and total: every variant is defined
//! for every input (out-of-range indices wrap or clamp), so entropy is never
//! wasted on a rejected mutation and the fuzzer's corpus stays meaningful.
//! Structure-*aware* here means "derived from a valid bundle" rather than
//! "schema-aware": the mutators work on encoded bytes, and the typed
//! reveal-shape mutations are R6's [`Tweak`] knobs, which
//! [`seed_corpus`] draws on.
//!
//! # The second mutation class: section-level recombination (R34)
//!
//! [`Recombination`] is the class byte-level mutation cannot reach. Its
//! members move a whole **section** — the reveal arrays, the touched-file
//! list, the anchors, the storage record, or the embedded manifest itself —
//! from one bundle into another, and the result is guaranteed to *decode*
//! rather than to die in the codec. That matters because the interesting
//! bugs are behind stage 1: a bundle that pairs one work's signed manifest
//! with another work's reveals exercises every decode-then-cross-check path
//! at once, and a bit-flip finds that shape only by accident.
//!
//! The guarantee is structural, not statistical. Every recombination goes
//! `decode → `[`BundleV1::into_parts`] → move sections → [`BundleV1::new`] →
//! [`encode_bundle`], so the tier-`[X]` rules run again on the way back in.
//! A recombination that would violate one is refused there and reported as
//! [`None`] — *unrepresentable*, which is a stronger statement about the
//! format than "rejected" and is worth distinguishing (R10's
//! `the_single_unit_downgrade_is_unrepresentable` makes the same point about
//! a different attack).
//!
//! Recombined bundles join [`seed_corpus`] under their own `recombined-`
//! name class, so the fuzz target and R10's proptest consume them without
//! either having to know they exist — and the byte-level mutators then run
//! *on top of* them, composing the two classes for free.
//!
//! [`BundleV1::into_parts`]: crate::bundle::BundleV1::into_parts
//! [`BundleV1::new`]: crate::bundle::BundleV1::new
//! [`Tweak`]: super::bundle_fixtures::Tweak
//! [`VerificationReport`]: crate::verify::VerificationReport
//! [`VerifyError`]: crate::verify::VerifyError
//! [`encode_bundle`]: crate::bundle::encode_bundle

use crate::bundle::{BundleV1, FullReveal, NonCoveredReveal, encode_bundle};
use crate::crypto::material::{Key32, Salt16, Seed32};
use crate::verify::{VerifyOptions, verify_bundle};

use super::bundle_fixtures::{
    AnchorSet, BuiltFixture, FileSelection, Selection, Tweak, build_tweaked, shapes,
};

/// One structure-aware mutation of an encoded bundle.
///
/// Every variant is **total**: applied to any input, including an empty
/// one, it produces some output rather than failing. That is what lets the
/// fuzzer's entropy map onto mutations without a rejection path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mutation {
    /// Leave the bundle alone — the control, and the corpus entry a fuzzer
    /// starts from.
    None,
    /// XOR `mask` into the byte at `index % len`.
    FlipBit {
        /// Byte offset, reduced modulo the input length.
        index: usize,
        /// Bits to flip. Never zero, so this is always a real mutation.
        mask: u8,
    },
    /// Keep the first `len % (input.len() + 1)` bytes.
    ///
    /// Truncation is called out separately from bit-flipping because it is
    /// the shape a length-prefixed format is most likely to mis-handle: a
    /// decoder that trusts a count it can no longer satisfy.
    Truncate {
        /// Kept prefix length, reduced modulo `input.len() + 1`.
        len: usize,
    },
    /// Append `count` bytes of `fill` — trailing garbage after a
    /// well-formed document, which the canonical profile must reject.
    Extend {
        /// How many bytes, clamped to a small bound.
        count: usize,
        /// The byte to append.
        fill: u8,
    },
    /// Overwrite the `len` bytes at `at` with a run of `fill`.
    ///
    /// Wider than a bit flip, which matters for hitting length and count
    /// fields hard enough to demand an allocation the caps must refuse.
    Overwrite {
        /// Start offset, reduced modulo the input length.
        at: usize,
        /// Run length, clamped to the remaining input.
        len: usize,
        /// The byte to write.
        fill: u8,
    },
    /// Swap two equal-length windows of `len` bytes at `a` and `b`.
    ///
    /// The byte-level stand-in for a section swap: applied to the reveal
    /// arrays it moves one entry's material under another's, which is the
    /// shape decision D81's swapped-unit non-row is about.
    SwapWindows {
        /// First window start, reduced modulo the input length.
        a: usize,
        /// Second window start, reduced modulo the input length.
        b: usize,
        /// Window length, clamped so both windows stay in bounds.
        len: usize,
    },
    /// Splice `len` bytes taken from `donor` at `from` over the bytes at
    /// `at` — cross-bundle material, which single-bundle mutation cannot
    /// produce and which is exactly what a relay holding two bundles has.
    SpliceFromDonor {
        /// Which seed-corpus entry to take bytes from.
        donor: usize,
        /// Offset in the donor, reduced modulo its length.
        from: usize,
        /// Offset in the target, reduced modulo its length.
        at: usize,
        /// How many bytes, clamped to both sides.
        len: usize,
    },
}

impl Mutation {
    /// Apply the mutation, given the seed corpus for the donor variant.
    ///
    /// Total: never panics, never returns an error, and is defined on an
    /// empty input (where every variant degenerates to the identity or to
    /// an append).
    #[must_use]
    pub fn apply(&self, input: &[u8], corpus: &[Vec<u8>]) -> Vec<u8> {
        let mut out = input.to_vec();
        match *self {
            Self::None => {}
            Self::FlipBit { index, mask } => {
                if !out.is_empty() {
                    let index = index % out.len();
                    out[index] ^= if mask == 0 { 0x01 } else { mask };
                }
            }
            Self::Truncate { len } => {
                let keep = len % (out.len() + 1);
                out.truncate(keep);
            }
            Self::Extend { count, fill } => {
                out.extend(core::iter::repeat_n(fill, count.min(MAX_EXTEND)));
            }
            Self::Overwrite { at, len, fill } => {
                if !out.is_empty() {
                    let at = at % out.len();
                    let end = at.saturating_add(len.min(MAX_EXTEND)).min(out.len());
                    out[at..end].fill(fill);
                }
            }
            Self::SwapWindows { a, b, len } => {
                if !out.is_empty() {
                    let a = a % out.len();
                    let b = b % out.len();
                    let len = len
                        .min(MAX_EXTEND)
                        .min(out.len() - a.max(b))
                        .min(a.abs_diff(b));
                    for offset in 0..len {
                        out.swap(a + offset, b + offset);
                    }
                }
            }
            Self::SpliceFromDonor {
                donor,
                from,
                at,
                len,
            } => {
                if let Some(source) = corpus.get(donor % corpus.len().max(1))
                    && !source.is_empty()
                    && !out.is_empty()
                {
                    let from = from % source.len();
                    let at = at % out.len();
                    let len = len
                        .min(MAX_EXTEND)
                        .min(source.len() - from)
                        .min(out.len() - at);
                    out[at..at + len].copy_from_slice(&source[from..from + len]);
                }
            }
        }
        out
    }
}

/// Bound on how much a single mutation may add or rewrite.
///
/// Not a safety limit — [`verify_bundle`] has its own caps, and testing
/// those is the point. It bounds the *fuzzer's* per-input work so budget is
/// spent on many shapes rather than on a few enormous ones.
const MAX_EXTEND: usize = 4096;

// ---------------------------------------------------------------------------
// section-level recombination (R34)
// ---------------------------------------------------------------------------

/// One **section-level** recombination of two bundles: a whole section of
/// `donor` replaces the corresponding section of `target`.
///
/// Every variant produces a bundle that **decodes** or produces nothing at
/// all — see the module docs for why that is structural. Unlike
/// [`Mutation`], these are therefore *not* total: [`recombine`] returns
/// [`None`] when the result would violate a rule [`BundleV1::new`] owns,
/// which is the honest report ("this attack has no representable form on
/// this pair") rather than a silently-degraded input.
///
/// # Why these sections and not others
///
/// Each names a cross-check the pipeline performs between the *signed*
/// manifest and the *unsigned* bundle around it. A relay holding two
/// bundles can build all of them for free, which is exactly the M0 threat
/// (MVP-SPEC.md line 187).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Recombination {
    /// Decode and re-encode with nothing moved — the control.
    ///
    /// Its value is the assertion it supports: the seam is byte-identity on
    /// an untouched bundle, so any difference a sibling variant produces is
    /// the section it moved and not the round trip.
    RoundTrip,
    /// Graft the donor's embedded **manifest** under the target's reveals —
    /// one work's signed claims over another work's disclosed bytes.
    ///
    /// The headline cross-work graft (R34's Accept), and the shape no
    /// single-work fixture can produce.
    GraftManifest,
    /// The dual: the donor's two **reveal sections** under the target's own
    /// manifest.
    GraftRevealSections,
    /// The donor's `touched_files` under the target's reveals — disclosed
    /// paths and `path_salt`s that belong to a different work.
    GraftTouchedFiles,
    /// The donor's `full_reveals` — full-reveal material for files of
    /// another work.
    GraftFullReveals,
    /// The donor's anchor artifacts and receipt.
    ///
    /// Expected to still **verify** at M0: the anchor stage is a stub that
    /// emits one `absent` slot per embedded artifact and R12 replaces it at
    /// M2, so an artifact's *provenance* is not yet verdict-bearing. That
    /// makes this the section-level twin of R10's
    /// `m0_anchor_artifacts_are_inert_until_r12_wires_the_anchor_stage`, and
    /// it is written to go red at the same moment.
    ///
    /// **There is deliberately no storage-record graft.** R6 gives every
    /// fixture the *same* constant storage record, so grafting one across
    /// works is a provable no-op — a corpus entry that duplicated its own
    /// target under a name claiming otherwise. R10's
    /// `the_unauthenticated_region_at_m0_is_exactly_the_storage_record`
    /// already pins that region byte by byte; reaching it *here* needs a
    /// per-work storage record in R6 (task R38).
    GraftAnchors,
    /// Move **every** covered reveal into `noncovered_reveals`, keying each
    /// on a `unit_salt` borrowed from the donor.
    ///
    /// The wholesale form of R6's per-unit `misplace_covered_unit` knob.
    /// A borrowed salt is meaningless on purpose: the reveal-section rule is
    /// adjudicated at stage 2, before anything opens a salt, so the input
    /// exercises the misplacement and nothing else.
    ///
    /// Deliberately one-directional. The reverse — migrating non-covered
    /// entries into `covered_reveals` — would have to fabricate cover
    /// entries, and a fixture that hard-codes the cover-seed wire shape is a
    /// fixture that breaks when that shape changes. R6's
    /// `misplace_noncovered_unit` knob covers the direction typed, at one
    /// unit, where borrowing a real cover is cheap.
    MigrateCoveredIntoNonCovered,
    /// Re-point the target's first `full_reveals` entry at another
    /// `file_id`, keeping its `file_salt` and `s_root`.
    ///
    /// Representable only when that id is already in `touched_files`, since
    /// `full_reveals ⊆ touched_files` is tier `[X]`; otherwise [`None`].
    MoveFullReveal {
        /// The `file_id` the entry is moved onto.
        to_file_id: u64,
    },
}

impl Recombination {
    /// Every variant, with the one parameterised case instantiated at the
    /// `file_id`s a fixture work actually has.
    ///
    /// Names carry the [`seed_corpus`] `recombined-` prefix because that is
    /// where they end up, and a name that reaches fuzz-crash triage should
    /// be the same string in the corpus, in a test message, and in a bug
    /// report. Named rather than derived so the corpus is stable across
    /// runs: a seed corpus that reshuffled between builds would make triage
    /// guesswork.
    #[must_use]
    pub fn all() -> Vec<(&'static str, Self)> {
        vec![
            ("recombined-round-trip", Self::RoundTrip),
            ("recombined-graft-manifest", Self::GraftManifest),
            (
                "recombined-graft-reveal-sections",
                Self::GraftRevealSections,
            ),
            ("recombined-graft-touched-files", Self::GraftTouchedFiles),
            ("recombined-graft-full-reveals", Self::GraftFullReveals),
            ("recombined-graft-anchors", Self::GraftAnchors),
            (
                "recombined-migrate-covered-into-noncovered",
                Self::MigrateCoveredIntoNonCovered,
            ),
            (
                "recombined-move-full-reveal-to-file-1",
                Self::MoveFullReveal { to_file_id: 1 },
            ),
            (
                "recombined-move-full-reveal-to-file-2",
                Self::MoveFullReveal { to_file_id: 2 },
            ),
        ]
    }
}

/// Apply a [`Recombination`] of `donor` into `target`.
///
/// Returns [`None`] when either input does not decode, when the result
/// would violate a tier-`[X]` rule, or when the encoder refuses it — the
/// three ways a recombination can be *unrepresentable* rather than merely
/// rejected. A `Some` result is always a bundle that decodes.
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn recombine(target: &[u8], donor: &[u8], how: Recombination) -> Option<Vec<u8>> {
    let mut parts = BundleV1::decode(target).ok()?.into_parts();
    let donor_parts = BundleV1::decode(donor).ok()?.into_parts();

    match how {
        Recombination::RoundTrip => {}
        Recombination::GraftManifest => parts.manifest = donor_parts.manifest,
        Recombination::GraftRevealSections => {
            parts.covered_reveals = donor_parts.covered_reveals;
            parts.noncovered_reveals = donor_parts.noncovered_reveals;
        }
        Recombination::GraftTouchedFiles => parts.touched_files = donor_parts.touched_files,
        Recombination::GraftFullReveals => parts.full_reveals = donor_parts.full_reveals,
        Recombination::GraftAnchors => {
            parts.ots_anchors = donor_parts.ots_anchors;
            parts.tsa_anchors = donor_parts.tsa_anchors;
            parts.receipt = donor_parts.receipt;
        }
        Recombination::MigrateCoveredIntoNonCovered => {
            // A real derived salt from the donor, so the entry is
            // well formed and only its *section* is wrong.
            let borrowed = donor_parts.noncovered_reveals.first()?;
            let salt_bytes = *borrowed.unit_salt().as_bytes();
            for covered in core::mem::take(&mut parts.covered_reveals) {
                let unit_id = covered.unit_id();
                let k_u = Key32::from_bytes(*covered.k_u().as_bytes());
                let ciphertext = covered.ciphertext().clone();
                parts.noncovered_reveals.push(
                    NonCoveredReveal::new(unit_id, k_u, ciphertext, Salt16::from_bytes(salt_bytes))
                        .ok()?,
                );
            }
            // `new` requires strict ascent; the two sections were each
            // ascending and disjoint, so sorting the union restores it.
            parts
                .noncovered_reveals
                .sort_by_key(NonCoveredReveal::unit_id);
        }
        Recombination::MoveFullReveal { to_file_id } => {
            let entry = parts.full_reveals.first()?;
            let moved = FullReveal::new(
                to_file_id,
                Salt16::from_bytes(*entry.file_salt().as_bytes()),
                entry
                    .disclosed_s_root()
                    .map(|seed| Seed32::from_bytes(*seed.as_bytes())),
            );
            parts.full_reveals = vec![moved];
        }
    }

    encode_bundle(&BundleV1::new(parts).ok()?).ok()
}

/// What `verify_bundle` did with one input.
///
/// The invariant is that one of these is always produced — the absence of a
/// fourth "panicked" variant is not an omission, it is the property, and
/// the harness that observes a panic reports it as a test failure rather
/// than as an outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// A full report — the input verified. Vanishingly rare on mutated
    /// input, and legitimate: `Mutation::None` produces it.
    Verified,
    /// A typed [`VerifyError`](crate::verify::VerifyError), reported by its
    /// stable code so a corpus run can be summarised by which stage the
    /// budget is reaching.
    Rejected(&'static str),
}

impl Outcome {
    /// Whether the input got **past the decoder** — the signal that a fuzz
    /// budget is reaching the stages this target exists to stress rather
    /// than re-fuzzing F17's territory.
    #[must_use]
    pub fn reached_the_pipeline(self) -> bool {
        match self {
            Self::Verified => true,
            Self::Rejected(code) => {
                !code.starts_with("cbor-")
                    && !code.starts_with("bundle-")
                    && !code.starts_with("manifest-")
            }
        }
    }
}

/// Run one input through `verify_bundle` and classify what came back.
///
/// This is the whole assertion surface: if the call panics, the caller
/// (proptest, or libfuzzer) reports it. There is deliberately no
/// `catch_unwind` here — swallowing the panic would defeat the property.
#[must_use]
pub fn drive(bytes: &[u8]) -> Outcome {
    match verify_bundle(bytes, &VerifyOptions::new()) {
        Ok(_) => Outcome::Verified,
        Err(err) => Outcome::Rejected(err.code()),
    }
}

/// The seed corpus: valid bundles of every shape R6 builds cheaply, R7's
/// tamper fixtures, and R34's section-level recombinations.
///
/// R10's accept requires the tamper fixtures specifically, and the reason
/// is worth keeping: a mutation of an *already invalid* bundle reaches
/// error paths that a mutation of a valid one reaches only by accident —
/// the second failure inside a stage that has already found one.
///
/// Each entry is `(name, bytes)`; the name reaches crash triage, and a
/// fuzz corpus directory is written from it. The **name prefix is a
/// claim**, asserted by `the_seeds_are_what_their_names_say`:
///
/// | prefix | claim |
/// |---|---|
/// | `valid-` | verifies |
/// | `tamper-` | is rejected |
/// | `recombined-` | gets **past the decoder** — verdict left open |
///
/// The third class's claim is deliberately about *reach* rather than
/// outcome. Some recombinations verify (grafting the storage record must,
/// at M0) and most do not, and pinning either would be pinning the wrong
/// thing: what R34 buys is that the input lands in the stages behind the
/// codec instead of dying in it.
#[must_use]
pub fn seed_corpus() -> Vec<(&'static str, Vec<u8>)> {
    let multi = shapes::multi_file();
    let mixed = shapes::multi_file_mixed_selection();
    let mut seeds: Vec<(&'static str, Vec<u8>)> = Vec::new();

    let mut push = |name: &'static str, built: BuiltFixture| seeds.push((name, built.bytes));

    // ── valid bundles ──
    push(
        "valid-multi-file-mixed",
        build_tweaked(&multi, &mixed, &Tweak::default()),
    );
    push(
        "valid-multi-file-all",
        build_tweaked(&multi, &Selection::all(3), &Tweak::default()),
    );
    push(
        "valid-multi-file-nothing",
        build_tweaked(&multi, &Selection::nothing(3), &Tweak::default()),
    );
    push(
        "valid-single-text-with-mirror",
        build_tweaked(
            &shapes::single_text_with_mirror(),
            &Selection::all(1),
            &Tweak::default(),
        ),
    );
    push(
        "valid-split-multi-unit-partial",
        build_tweaked(
            &shapes::split_multi_unit(),
            &Selection(vec![FileSelection::Units(vec![1])]),
            &Tweak::default(),
        ),
    );
    push(
        "valid-multi-file-anchored",
        build_tweaked(&shapes::multi_file_anchored(), &mixed, &Tweak::default()),
    );

    // ── R7/R8 tamper fixtures: one per stage the pipeline can fail at, so
    //    the fuzzer starts from an input that is already deep in the
    //    machine rather than having to mutate its way there ──
    for (name, tweak) in [
        (
            "tamper-tiling-out-of-bounds",
            Tweak {
                range_out_of_bounds: Some(4),
                ..Tweak::default()
            },
        ),
        (
            "tamper-true-length-excess",
            Tweak {
                true_length_excess: Some(3),
                ..Tweak::default()
            },
        ),
        (
            "tamper-unknown-touched-file",
            Tweak {
                unknown_touched_file: Some(9),
                ..Tweak::default()
            },
        ),
        (
            "tamper-drop-touched-file",
            Tweak {
                drop_touched_file: Some(1),
                ..Tweak::default()
            },
        ),
        (
            "tamper-touch-without-reveal",
            Tweak {
                touch_without_reveal: Some(2),
                ..Tweak::default()
            },
        ),
        (
            "tamper-misplace-covered-unit",
            Tweak {
                misplace_covered_unit: Some(0),
                ..Tweak::default()
            },
        ),
        (
            "tamper-leak-full-material",
            Tweak {
                leak_full_material: Some(1),
                ..Tweak::default()
            },
        ),
        (
            "tamper-corrupt-ciphertext",
            Tweak {
                corrupt_ciphertext: Some(3),
                ..Tweak::default()
            },
        ),
        (
            "tamper-corrupt-canon-commit",
            Tweak {
                corrupt_canon_commit: Some(0),
                ..Tweak::default()
            },
        ),
        (
            "tamper-corrupt-disclosed-s-root",
            Tweak {
                corrupt_disclosed_s_root: Some(0),
                ..Tweak::default()
            },
        ),
    ] {
        push(name, build_tweaked(&multi, &mixed, &tweak));
    }

    // The `unit_commit` tamper needs the all-revealed selection, since its
    // subject (unit 5) is only in the bundle there.
    push(
        "tamper-corrupt-unit-commit",
        build_tweaked(
            &multi,
            &Selection::all(3),
            &Tweak {
                corrupt_unit_commit: Some(5),
                ..Tweak::default()
            },
        ),
    );

    // ── R34 section-level recombinations ──
    //
    // Target and donor are two *different works* — the mixed-selection
    // multi-file bundle and the anchored one built under `--all` — so every
    // graft below genuinely crosses a work boundary rather than shuffling
    // one bundle's own sections. The anchored donor is what makes
    // `graft-anchors` a real change rather than a copy of two empty lists.
    let (target, donor) = recombination_pair();
    for (name, how) in Recombination::all() {
        // An unrepresentable recombination contributes no seed rather than
        // an empty one: `None` here is a statement about the format
        // (`unrepresentable_recombinations_are_named` pins which are which),
        // and a zero-byte corpus entry would only re-test the empty input.
        if let Some(bytes) = recombine(&target, &donor, how) {
            seeds.push((name, bytes));
        }
    }

    seeds
}

/// The `(target, donor)` pair [`seed_corpus`] recombines.
///
/// Choosing it took two corrections, both worth recording because both are
/// facts about R6 that a future donor swap will meet again:
///
/// 1. **`with_anchors` does not make a different work.** The obvious donor
///    is [`shapes::multi_file_anchored`], but that helper changes only
///    *bundle* sections — the work, and so the manifest bytes, are
///    identical to the target's. `GraftManifest` was a silent no-op and the
///    headline cross-work graft R34 asks for was not exercised at all.
/// 2. **R6's per-file material is keyed on `file_id`, not on the work.**
///    Every fixture shares one master secret, and `file_salt`/`s_root` come
///    from `(W, file_id)` — so two *different* works that both fully reveal
///    their file 0 emit byte-identical `full_reveals` entries, and a
///    "cross-work" graft of that section moves nothing. The donor must
///    therefore differ in the section's **shape** (how many files it fully
///    reveals), not merely in which work it came from. Production material
///    is keyed on the seal's own `W` and has no such collision; giving R6 a
///    per-work secret is task R39.
///
/// [`shapes::raw_mirror_sources`] satisfies both: a different work (two
/// text files, different title, different file table) that fully reveals
/// **two** files against the target's one, so the full-reveal graft lands
/// material for a file the target only partially reveals — a genuine
/// proof-downgrade shape. Anchors are attached so the anchor graft is a
/// real change against the target's empty sections.
///
/// Exposed so the property tests recombine the same pair the corpus does
/// rather than a second one that could drift away from it.
#[must_use]
pub fn recombination_pair() -> (Vec<u8>, Vec<u8>) {
    let donor = shapes::raw_mirror_sources().with_anchors(AnchorSet::EveryKind { receipt: true });
    (
        build_tweaked(
            &shapes::multi_file(),
            &shapes::multi_file_mixed_selection(),
            &Tweak::default(),
        )
        .bytes,
        build_tweaked(&donor, &Selection::all(2), &Tweak::default()).bytes,
    )
}

/// Just the seed bytes, in [`seed_corpus`] order — what
/// [`Mutation::apply`]'s donor variant indexes into.
#[must_use]
pub fn seed_bytes() -> Vec<Vec<u8>> {
    seed_corpus().into_iter().map(|(_, bytes)| bytes).collect()
}

/// Interpret raw fuzzer entropy as `(seed choice, mutation)` and produce the
/// input to drive.
///
/// The layout is fixed and documented so a crashing input found by the
/// fuzzer can be decoded by hand:
///
/// | bytes | meaning |
/// |---|---|
/// | `[0]` | seed selector. `0` means *no seed*: the remaining entropy is used as the raw bundle, which is what keeps arbitrary-byte coverage in the target at all. Otherwise `(b - 1) % corpus.len()` picks a seed. |
/// | `[1]` | mutation selector, `% 7` |
/// | `[2..]` | mutation parameters, little-endian, short reads treated as zero |
///
/// An input shorter than two bytes degenerates to "raw bytes, unmutated",
/// which is correct rather than special-cased: the empty bundle and the
/// one-byte bundle are both inputs the property covers.
#[must_use]
pub fn mutate_from_entropy(entropy: &[u8], corpus: &[Vec<u8>]) -> Vec<u8> {
    let (&selector, rest) = entropy.split_first().unwrap_or((&0, &[]));
    let (&mutation_kind, params) = rest.split_first().unwrap_or((&0, &[]));

    let base: Vec<u8> = if selector == 0 || corpus.is_empty() {
        params.to_vec()
    } else {
        corpus[usize::from(selector - 1) % corpus.len()].clone()
    };

    let mutation = decode_mutation(mutation_kind, params);
    mutation.apply(&base, corpus)
}

/// Decode a mutation from a selector byte plus parameter bytes.
///
/// Separate from [`mutate_from_entropy`] so the proptest can build
/// mutations directly and the two paths still share the semantics.
#[must_use]
pub fn decode_mutation(kind: u8, params: &[u8]) -> Mutation {
    let word = |index: usize| -> usize {
        let mut bytes = [0u8; 4];
        for (slot, byte) in bytes.iter_mut().enumerate() {
            *byte = params.get(index * 4 + slot).copied().unwrap_or(0);
        }
        u32::from_le_bytes(bytes) as usize
    };
    let byte = |index: usize| -> u8 { params.get(index).copied().unwrap_or(0) };

    match kind % 7 {
        0 => Mutation::None,
        1 => Mutation::FlipBit {
            index: word(0),
            mask: byte(4),
        },
        2 => Mutation::Truncate { len: word(0) },
        3 => Mutation::Extend {
            count: word(0),
            fill: byte(4),
        },
        4 => Mutation::Overwrite {
            at: word(0),
            len: word(1),
            fill: byte(8),
        },
        5 => Mutation::SwapWindows {
            a: word(0),
            b: word(1),
            len: word(2),
        },
        _ => Mutation::SpliceFromDonor {
            donor: word(0),
            from: word(1),
            at: word(2),
            len: word(3),
        },
    }
}

/// One end-to-end fuzz iteration: entropy in, [`Outcome`] out.
///
/// The fuzz target is this function plus `#![no_main]` boilerplate, which
/// is the point — everything testable is on this side of the boundary.
#[must_use]
pub fn fuzz_once(entropy: &[u8], corpus: &[Vec<u8>]) -> Outcome {
    drive(&mutate_from_entropy(entropy, corpus))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_seed_corpus_is_non_empty_and_named_uniquely() {
        let seeds = seed_corpus();
        assert!(seeds.len() >= 15, "got {} seeds", seeds.len());
        let mut names: Vec<&str> = seeds.iter().map(|(name, _)| *name).collect();
        names.sort_unstable();
        let before = names.len();
        names.dedup();
        assert_eq!(before, names.len(), "seed names must be unique");
        for (name, bytes) in &seeds {
            assert!(!bytes.is_empty(), "seed `{name}` is empty");
        }
    }

    /// The valid seeds verify and the tamper seeds do not — otherwise the
    /// corpus would be mislabelled and a "tamper" seed could quietly be a
    /// second copy of a valid one.
    ///
    /// R34's `recombined-` class makes the weaker but more useful claim its
    /// name carries (see [`seed_corpus`]): it reached the stages behind the
    /// decoder. A recombined seed that died in the codec would be a seam
    /// bug, since the seam re-encodes through `BundleV1::new`.
    #[test]
    fn the_seeds_are_what_their_names_say() {
        for (name, bytes) in seed_corpus() {
            let outcome = drive(&bytes);
            if name.starts_with("valid-") {
                assert_eq!(outcome, Outcome::Verified, "seed `{name}` must verify");
            } else if name.starts_with("recombined-") {
                assert!(
                    outcome.reached_the_pipeline(),
                    "seed `{name}` died in the codec ({outcome:?}) — a recombined bundle is \
                     re-encoded through `BundleV1::new`, so it must decode"
                );
            } else {
                assert!(
                    matches!(outcome, Outcome::Rejected(_)),
                    "seed `{name}` must be rejected"
                );
            }
        }
    }

    /// Every mutation is total on the awkward inputs: empty, one byte, and
    /// an index far past the end.
    #[test]
    fn mutations_are_total_on_degenerate_inputs() {
        let corpus = vec![vec![1u8, 2, 3], Vec::new()];
        let mutations = (0u8..7)
            .map(|kind| decode_mutation(kind, &[0xFF; 16]))
            .collect::<Vec<_>>();
        for mutation in &mutations {
            for input in [&[][..], &[0u8][..], &[0u8; 64][..]] {
                let out = mutation.apply(input, &corpus);
                assert!(out.len() <= input.len() + MAX_EXTEND);
            }
        }
    }

    /// `SwapWindows` must not corrupt the length or lose bytes — it is a
    /// permutation, and a mutator that silently truncated would weaken
    /// every input built on it.
    #[test]
    fn swapping_windows_is_a_permutation() {
        let input: Vec<u8> = (0u8..64).collect();
        let out = Mutation::SwapWindows {
            a: 0,
            b: 32,
            len: 8,
        }
        .apply(&input, &[]);
        assert_eq!(out.len(), input.len());
        let (mut a, mut b) = (input.clone(), out.clone());
        a.sort_unstable();
        b.sort_unstable();
        assert_eq!(a, b, "swap must preserve the multiset of bytes");
        assert_ne!(out, input, "and must actually change something");
    }

    /// The entropy layout is a documented contract — a crashing fuzz input
    /// is decoded by hand against it, so it is pinned.
    #[test]
    fn the_entropy_layout_is_the_documented_one() {
        let corpus = seed_bytes();

        // Selector 0 = raw bytes, mutation 0 = identity.
        assert_eq!(
            mutate_from_entropy(&[0, 0, 9, 9, 9], &corpus),
            vec![9, 9, 9]
        );

        // Selector 1 = the first seed, unmutated.
        assert_eq!(mutate_from_entropy(&[1, 0], &corpus), corpus[0]);

        // Short inputs degenerate rather than special-case.
        assert!(mutate_from_entropy(&[], &corpus).is_empty());
        assert_eq!(mutate_from_entropy(&[0], &corpus), Vec::<u8>::new());

        // Selector wraps, so no entropy byte is wasted on a rejected seed.
        let wrapped = usize::from(u8::MAX - 1) % corpus.len();
        assert_eq!(mutate_from_entropy(&[u8::MAX, 0], &corpus), corpus[wrapped]);
    }

    /// A structure-aware run reaches past the decoder for a decent share of
    /// its inputs. Without this the target could silently degenerate into a
    /// slower copy of F17's CBOR fuzzers and nobody would notice.
    #[test]
    fn structure_aware_mutation_reaches_past_the_decoder() {
        let corpus = seed_bytes();
        let mut past = 0usize;
        let mut total = 0usize;
        for seed in 1..=u8::try_from(corpus.len()).unwrap_or(u8::MAX) {
            for kind in 0u8..7 {
                for salt in 0u8..4 {
                    let mut entropy = vec![seed, kind];
                    entropy.extend_from_slice(&[salt; 16]);
                    if fuzz_once(&entropy, &corpus).reached_the_pipeline() {
                        past += 1;
                    }
                    total += 1;
                }
            }
        }
        assert!(
            past * 4 >= total,
            "only {past}/{total} structure-aware inputs got past the decoder; the target is \
             supposed to stress the stages behind it, not re-fuzz F17's territory"
        );
    }

    // ── R34: the section-level seam ──

    /// **The seam loses nothing.** Decoding a bundle, destructuring it
    /// through [`BundleV1::into_parts`], and re-encoding reproduces the
    /// input byte for byte.
    ///
    /// This is the load-bearing test of R34, and it is what makes every
    /// other recombination interpretable: if the round trip were lossy, a
    /// grafted bundle would differ from its target in the grafted section
    /// *and* in whatever the round trip dropped, and no test below could
    /// tell the two apart.
    ///
    /// The [`recombination_pair`] donor is included **by name and on
    /// purpose**: no ordinary seed populates the optional receipt slot, so
    /// a seam that silently dropped the receipt passed this test until the
    /// maximal-shape bundle was added to it. An identity assertion is only
    /// as strong as the widest shape it runs on.
    #[test]
    fn the_recombination_seam_is_byte_identity_on_an_untouched_bundle() {
        let (target, donor) = recombination_pair();
        let extra = [
            ("recombination-target", target),
            ("recombination-donor (every anchor kind + receipt)", donor),
        ];
        let seeds = seed_corpus()
            .into_iter()
            .filter(|(name, _)| !name.starts_with("recombined-")) // already a round-trip product
            .chain(extra);

        for (name, bytes) in seeds {
            let round_tripped = recombine(&bytes, &bytes, Recombination::RoundTrip)
                .unwrap_or_else(|| panic!("seed `{name}` must round-trip through the seam"));
            assert_eq!(
                round_tripped, bytes,
                "seed `{name}`: the R34 seam is not byte-identity — a section is being dropped \
                 or reordered on the way through `into_parts`"
            );
        }
    }

    /// Every recombination is either representable and **decodable**, or
    /// refused outright. Nothing in between.
    ///
    /// The distinction is R34's whole point: a byte-level mutator reaches
    /// past stage 1 by luck, this class reaches it by construction.
    #[test]
    fn every_representable_recombination_decodes() {
        let (target, donor) = recombination_pair();
        let mut representable = 0usize;
        for (name, how) in Recombination::all() {
            let Some(bytes) = recombine(&target, &donor, how) else {
                continue;
            };
            representable += 1;
            let outcome = drive(&bytes);
            assert!(
                outcome.reached_the_pipeline(),
                "`{name}` produced bytes that died in the codec ({outcome:?})"
            );
        }
        assert!(
            representable >= 8,
            "only {representable} of the recombinations were representable on this pair"
        );
    }

    /// Every recombination except the control actually **changes** the
    /// bundle.
    ///
    /// Without this a graft whose donor happened to carry an identical
    /// section would be a silently empty test, and the corpus would gain a
    /// duplicate of its own target under a name claiming otherwise.
    #[test]
    fn every_recombination_but_the_control_changes_the_bundle() {
        let (target, donor) = recombination_pair();
        for (name, how) in Recombination::all() {
            let Some(bytes) = recombine(&target, &donor, how) else {
                continue;
            };
            if how == Recombination::RoundTrip {
                assert_eq!(bytes, target, "the control must be the identity");
            } else {
                assert_ne!(bytes, target, "`{name}` did not change the bundle");
            }
        }
    }

    /// Which recombinations are **unrepresentable** on the corpus pair, and
    /// why — recorded rather than left as a silent `None`.
    ///
    /// `move-full-reveal-to-file-2` is the one: the corpus target reveals
    /// nothing of file 2, so no `touched_files` entry names it, and F8's
    /// tier-`[X]` rule `full_reveals ⊆ touched_files` refuses to construct
    /// the bundle. That is the format doing its job one layer below the
    /// verifier, and it is the same shape R10's
    /// `the_single_unit_downgrade_is_unrepresentable` records.
    #[test]
    fn unrepresentable_recombinations_are_named() {
        let (target, donor) = recombination_pair();
        let unrepresentable: Vec<&str> = Recombination::all()
            .into_iter()
            .filter(|(_, how)| recombine(&target, &donor, *how).is_none())
            .map(|(name, _)| name)
            .collect();
        assert_eq!(
            unrepresentable,
            ["recombined-move-full-reveal-to-file-2"],
            "the set of unrepresentable recombinations moved; if that is intended, say why here"
        );
    }

    /// **No cross-work graft of an evidence-bearing section verifies.** The
    /// anchor graft is the sole exception, and only until R12.
    ///
    /// This is the security statement R34 exists to make, and it is
    /// stronger than "the mutators produce decodable bundles": a bundle
    /// pairing one work's signed manifest with another work's reveals must
    /// be *rejected*, not merely parsed. Grafting anchors is the one
    /// section-level move an M0 verifier is entitled to accept, because the
    /// anchor stage is still a stub (R12 replaces it at M2) — so this test
    /// goes red exactly when R12 lands, and whoever lands it moves
    /// `GraftAnchors` out of the exception.
    #[test]
    fn no_cross_work_graft_verifies_except_the_m0_inert_anchor_section() {
        let (target, donor) = recombination_pair();
        for (name, how) in Recombination::all() {
            let Some(bytes) = recombine(&target, &donor, how) else {
                continue;
            };
            let verifies = drive(&bytes) == Outcome::Verified;
            let expected = matches!(how, Recombination::RoundTrip | Recombination::GraftAnchors);
            assert_eq!(
                verifies, expected,
                "`{name}`: verified = {verifies}, expected {expected}. If R12 has landed, the \
                 anchor stage is no longer a stub and this test has done its job: move \
                 `GraftAnchors` out of the exception and give it a tamper row (A21)."
            );
        }
    }

    /// The property itself, over a deterministic sweep. R10's proptest
    /// (`tests/verify_fuzz.rs`) is the randomized form; this is the cheap
    /// always-on one, so the invariant holds even if proptest is skipped.
    #[test]
    fn no_entropy_makes_verify_bundle_panic() {
        let corpus = seed_bytes();
        for seed in 0u8..=u8::try_from(corpus.len()).unwrap_or(16) {
            for kind in 0u8..7 {
                for pattern in [0x00u8, 0x01, 0x7F, 0x80, 0xFF] {
                    let mut entropy = vec![seed, kind];
                    entropy.extend_from_slice(&[pattern; 24]);
                    // Reaching here at all is the assertion: `fuzz_once`
                    // returns an `Outcome` or the test aborts.
                    let _ = fuzz_once(&entropy, &corpus);
                }
            }
        }
    }
}
