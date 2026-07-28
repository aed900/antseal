//! **G's registry slice for the tamper matrix** (task G19): the two
//! fine-tree-owned M0 rows, plus the over-broad-cover construction helper the
//! R lane consumes.
//!
//! The harness — distinctness, no-panic and exact-outcome assertions, and the
//! add-a-row procedure — is [`super::tamper`]; the code contract these rows
//! bind to is `docs/testing/error-code-contract.md`, whose recorded
//! `fine-root-` prefix exception (ratified 2026-07-28) is why these rows'
//! expected codes are `fine-root-…` rather than `content-…` while their row
//! **ids** keep the `content-` domain prefix.
//!
//! # The two rows (MVP-SPEC.md line 168)
//!
//! | spec family | mutation | code |
//! | --- | --- | --- |
//! | altered manifest field — covered unit | flip one bit of a covered unit's revealed content | `fine-root-binding-failed` |
//! | over-broad GGM cover | substitute a dyadically valid ancestor node spanning an unrevealed real leaf | `fine-root-over-broad-cover` |
//!
//! Both start from the **same known-good opening fixture**: G14's golden
//! work (`crate::content::fixtures`), file 0 — the CRLF text file split into
//! three paragraph units — opened against the `fine_root` the assembled model
//! committed. Reusing G14's fixture rather than minting a private one is
//! deliberate: a tamper row is only meaningful if its base is an artifact the
//! honest path actually produces, and G17's end-to-end suite asserts that
//! this exact opening verifies.
//!
//! # Why these two and not more
//!
//! G13's taxonomy has seven codes. The other five are **R's**: the two
//! wrong-length classes and `fine-root-range-out-of-bounds` /
//! `fine-root-byte-len-mismatch` / `fine-root-wrong-cover-shape` are
//! bundle-shape faults reached through `verify_bundle`, and Q8's registry
//! assigns them to R7/R8 so that no code is claimed by two rows (the harness
//! would correctly refuse the pair). What is G-owned is the pair whose
//! meaning is *cryptographic* rather than structural: the binding of revealed
//! bytes to `fine_root`, and the leaf-exactness rule that keeps an unrevealed
//! leaf's salt inside the vault (spec line 96).
//!
//! # The R-lane seam
//!
//! [`over_broad_cover`] is the single construction helper for a dyadically
//! valid but over-broad cover. R7 was told not to build a second one: per
//! Q8's registry the G19/R7 pair on `fine-root-over-broad-cover` yields
//! **one** row (R's wrapper arms surface the inner code unchanged, error-code
//! contract §2), so R consumes this helper for its property assertion rather
//! than registering a colliding row.

use crate::content::fine_tree::{
    FineRoot, FineTreeError, RangeProof, RangeProofView, WireNode, minimal_cover, prove_range,
    verify_range,
};
use crate::content::fixtures::{GOLDEN_FILE_TEXT_SPLIT, SYNTHETIC_FINE_SEEDS, golden_model};
use crate::content::ggm::{NodeAddress, SaltTree};
use crate::content::{ByteRange, ContentModel, FineSeedSource};
use crate::crypto::hkdf::FileId;
use crate::crypto::material::Seed32;

use super::tamper::{ActualOutcome, ExpectedOutcome, TamperRow};

// ---------------------------------------------------------------------------
// the known-good opening fixture both rows mutate
// ---------------------------------------------------------------------------

/// The fixture file: G14's golden CRLF text file, `--split blank-lines`,
/// three covered paragraph units over 34 canonical bytes.
pub const FIXTURE_FILE_ID: u64 = GOLDEN_FILE_TEXT_SPLIT;

/// The fixture file's leaf count `n` — its `size` field (MVP-SPEC.md line
/// 98). Pinned so a fixture drift shows up here rather than as a puzzling
/// row failure.
pub const FIXTURE_LEAF_COUNT: u64 = 34;

/// The covered unit row (1) opens and then corrupts: the fixture's **second**
/// paragraph, `[21, 28)`.
pub const FIXTURE_UNIT_RANGE: ByteRange = ByteRange::new(21, 7);

/// The range row (2) opens: `[16, 24)`, chosen because it is exactly one
/// dyadic block at level 3 of the depth-6 grid, so its honest cover is a
/// **single** node and the mutation is a true substitution rather than an
/// addition.
pub const FIXTURE_OVER_BROAD_RANGE: ByteRange = ByteRange::new(16, 8);

/// A known-good opening: the model-committed root, the file's byte domain,
/// and the `s_root` the model built that root from.
pub struct OpeningFixture {
    model: ContentModel<'static>,
    s_root: Seed32,
}

impl OpeningFixture {
    /// Assemble G14's golden work and take file 0's opening context.
    #[must_use]
    pub fn new() -> Self {
        Self {
            model: golden_model(),
            s_root: SYNTHETIC_FINE_SEEDS.fine_seed(FileId(FIXTURE_FILE_ID)),
        }
    }

    /// The `s_root` the fixture's `fine_root` was built from.
    #[must_use]
    pub const fn s_root(&self) -> &Seed32 {
        &self.s_root
    }

    /// The file's byte domain — canonical bytes, this file being text.
    #[must_use]
    pub fn domain(&self) -> &[u8] {
        self.file().domain_bytes()
    }

    /// The file's leaf count `n`.
    #[must_use]
    pub fn leaf_count(&self) -> u64 {
        self.file().size()
    }

    /// The `fine_root` the assembled model committed — the value a manifest
    /// would carry.
    #[must_use]
    pub fn fine_root(&self) -> &FineRoot {
        self.file()
            .fine_root()
            .expect("the fixture file is fine-tree covered")
    }

    /// The revealed bytes of `range` in the file's byte domain.
    #[must_use]
    pub fn revealed(&self, range: ByteRange) -> &[u8] {
        let domain = self.domain();
        let start = usize::try_from(range.start()).unwrap_or(usize::MAX);
        let end = range
            .end()
            .and_then(|end| usize::try_from(end).ok())
            .unwrap_or(usize::MAX);
        domain.get(start..end).unwrap_or(&[])
    }

    /// An honest opening of `range`, as the sealer would produce it.
    #[must_use]
    pub fn open(&self, range: ByteRange) -> Option<RangeProof> {
        prove_range(&self.s_root, self.domain(), range, self.leaf_count()).ok()
    }

    fn file(&self) -> &crate::content::FileModel<'static> {
        self.model
            .file(FIXTURE_FILE_ID)
            .expect("the golden work has file 0")
    }
}

impl Default for OpeningFixture {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// the over-broad-cover construction helper (owned here; consumed by R)
// ---------------------------------------------------------------------------

/// A dyadically valid GGM cover node that spans a **real leaf the reveal does
/// not show** — the artifact MVP-SPEC.md line 96 exists to forbid, since its
/// seed derives that leaf's `salt_j` and reopens the per-byte confirmation
/// attack.
///
/// Carries the genuine seed derived from `s_root` at that address, not a
/// random one: the point of the row is that *only* the address is wrong, so a
/// verifier cannot reject it on any incidental ground.
/// Not `Clone`: [`Seed32`] is zeroize-on-drop and deliberately un-cloneable
/// (C7's disclosure discipline), and a cover node has no reason to exist
/// twice.
#[derive(Debug)]
pub struct OverBroadCoverNode {
    address: NodeAddress,
    seed: Seed32,
    /// The real-leaf span this node commits, `[first, end)` truncated at `n`.
    real_span: (u64, u64),
}

impl OverBroadCoverNode {
    /// The node's grid address.
    #[must_use]
    pub const fn address(&self) -> NodeAddress {
        self.address
    }

    /// The real-leaf interval this node's seed would derive salts for,
    /// truncated at the file's leaf count. Strictly wider than the revealed
    /// range in at least one direction — that is what makes it over-broad.
    #[must_use]
    pub const fn real_span(&self) -> (u64, u64) {
        self.real_span
    }

    /// The node in the wire shape [`verify_range`] consumes, so a caller
    /// substitutes it straight into a [`RangeProofView`]'s cover.
    #[must_use]
    pub fn wire_node(&self) -> WireNode<'_> {
        WireNode {
            level: self.address.level(),
            index: self.address.index(),
            bytes: self.seed.as_bytes(),
        }
    }
}

/// Construct a dyadically valid but **over-broad** cover node for `range` —
/// the shallowest ancestor of an honest cover node whose real-leaf span
/// escapes the revealed range (tasks/G.md G19 row 2; MVP-SPEC.md line 96).
///
/// This is the single construction of its kind in the workspace: G19's tamper
/// row and R's pipeline-level property assertion both call it, so there is
/// one definition of "over-broad but structurally legal" rather than two that
/// could drift (Q8 single-owner rule; error-code contract §2).
///
/// Deterministic: it walks the honest cover in order and returns the first
/// (lowest) qualifying ancestor.
///
/// `None` — never a panic — when no such node exists:
///
/// - the range is invalid for `leaf_count` (there is no honest cover);
/// - the range is the **whole file**, whose cover is `s_root` itself and has
///   no ancestor (over-broadness is unreachable by construction there — the
///   D75 shape);
/// - every ancestor would span only unused slots, which is a *shape* fault
///   (`fine-root-wrong-cover-shape`), not a disclosure one, and must not be
///   confused with it.
#[must_use]
pub fn over_broad_cover(
    s_root: &Seed32,
    range: ByteRange,
    leaf_count: u64,
) -> Option<OverBroadCoverNode> {
    let cover = minimal_cover(range, leaf_count).ok()?;
    if cover.releases_s_root() {
        // Full reveal: the cover IS the root seed, so no ancestor exists.
        return None;
    }
    let depth = cover.depth();
    let range_end = range.end()?;
    let tree = SaltTree::new(s_root, leaf_count)?;

    for node in cover.nodes() {
        let mut address = node.address();
        while address.level() > 0 {
            let Ok(parent) = NodeAddress::try_new(address.level() - 1, address.index() / 2) else {
                break;
            };
            address = parent;
            let (Ok(first), Ok(width)) = (address.first_slot(depth), address.slot_width(depth))
            else {
                break;
            };
            if first >= leaf_count {
                // Commits nothing real: a shape fault, not a disclosure one.
                continue;
            }
            let real_end = u64::try_from((u128::from(first) + width).min(u128::from(leaf_count)))
                .unwrap_or(leaf_count);
            if first < range.start() || real_end > range_end {
                let seed = tree.seed_at(address).ok()?;
                return Some(OverBroadCoverNode {
                    address,
                    seed,
                    real_span: (first, real_end),
                });
            }
        }
    }
    None
}

// ---------------------------------------------------------------------------
// the row exercises
// ---------------------------------------------------------------------------

/// Marker outcome for a fixture that could not be built — never a panic, and
/// never silently a pass. The harness reports it as a wrong code against the
/// row's expectation, naming the row.
fn fixture_failure(what: &str) -> ActualOutcome {
    ActualOutcome::ErrorCode(format!("g19-fixture-construction-failed:{what}"))
}

/// Row 1 — flip one bit of a **covered unit's** revealed content and verify
/// the otherwise-untouched opening against the committed `fine_root`.
///
/// The mutation changes neither the range nor the proof, so every earlier
/// precedence stage passes unchanged (the range is in bounds, the revealed
/// length still matches, the cover and boundary are the canonical ones) and
/// the fault surfaces exactly where the spec says it must: the leaf-range /
/// boundary-path check against `fine_root` (MVP-SPEC.md line 168's
/// "altered manifest field" family, covered-unit half).
fn covered_unit_content_flipped() -> ActualOutcome {
    let fixture = OpeningFixture::new();
    let Some(proof) = fixture.open(FIXTURE_UNIT_RANGE) else {
        return fixture_failure("open-unit-range");
    };
    let mut revealed = fixture.revealed(FIXTURE_UNIT_RANGE).to_vec();
    let Some(byte) = revealed.first_mut() else {
        return fixture_failure("empty-reveal");
    };
    *byte ^= 0x01;

    ActualOutcome::from_result(
        proof.verify(&revealed, fixture.fine_root()),
        FineTreeError::code,
    )
}

/// Row 2 — substitute a dyadically valid but over-broad GGM cover whose node
/// spans an unrevealed real leaf, leaving the revealed bytes, the claimed
/// range and the boundary path honest.
///
/// The substituted node is the honest cover node's parent, carrying its
/// genuine `s_root`-derived seed, so the *only* thing wrong with the offered
/// proof is that this seed would derive salts for leaves the reveal does not
/// show. That is precisely the disclosure fault line 96 forbids, and G13
/// classifies it ahead of the shape fault the wrong node count also
/// constitutes — the security-bearing code wins.
fn over_broad_ggm_cover() -> ActualOutcome {
    let fixture = OpeningFixture::new();
    let range = FIXTURE_OVER_BROAD_RANGE;
    let Some(proof) = fixture.open(range) else {
        return fixture_failure("open-range");
    };
    let Some(over_broad) = over_broad_cover(fixture.s_root(), range, fixture.leaf_count()) else {
        return fixture_failure("construct-over-broad-cover");
    };

    let cover = [over_broad.wire_node()];
    let boundary = proof.wire_boundary();
    let view = RangeProofView {
        range,
        cover: &cover,
        boundary: &boundary,
    };
    ActualOutcome::from_result(
        verify_range(
            &view,
            fixture.revealed(range),
            fixture.leaf_count(),
            fixture.fine_root(),
        ),
        FineTreeError::code,
    )
}

// ---------------------------------------------------------------------------
// the registry slice
// ---------------------------------------------------------------------------

/// G's M0 tamper rows. Row ids are permanent handles; see the harness docs
/// ([`super::tamper`]) for the add-a-row procedure and
/// `docs/testing/error-code-contract.md` for why an expected code may never
/// be edited to make a failing run pass.
pub const ROWS: &[TamperRow] = &[
    TamperRow {
        id: "content-fine-root-binding-failed",
        base: "golden-work-covered-unit-opening",
        mutation: "flip one bit of a covered unit's revealed content",
        expected: ExpectedOutcome::ErrorCode("fine-root-binding-failed"),
        exercise: covered_unit_content_flipped,
    },
    TamperRow {
        id: "content-fine-root-over-broad-cover",
        base: "golden-work-byte-range-opening",
        mutation: "substitute the honest cover node with its parent, which spans an unrevealed \
                   real leaf",
        expected: ExpectedOutcome::ErrorCode("fine-root-over-broad-cover"),
        exercise: over_broad_ggm_cover,
    },
];

/// The construction helper R's bundle-level assertions reuse, named
/// explicitly so the seam is visible rather than implied (mirrors
/// [`super::tamper_rows_crypto::helpers`]).
///
/// | helper | family |
/// | --- | --- |
/// | [`over_broad_cover`] / [`OverBroadCoverNode`] | over-broad GGM cover |
/// | [`OpeningFixture`] | the known-good opening both rows mutate |
pub mod helpers {
    pub use super::{OpeningFixture, OverBroadCoverNode, over_broad_cover};
}
