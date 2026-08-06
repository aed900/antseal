//! The seeded, deterministic **test-only bundle fixture constructor**
//! (task R6) — the substrate R7–R10 mutate and R9's golden vectors pin.
//!
//! R5's own `verify::pipeline::tests::fixture` is one hand-built work whose
//! only job was to let the orchestration be tested at all. This module is
//! the general form: describe a work as data ([`WorkSpec`]), describe what a
//! reveal shows ([`Selection`]), and get back a `.sealproof` byte string
//! that [`verify_bundle`](crate::verify::verify_bundle) accepts — for every
//! M0 shape the milestone enumerates.
//!
//! # Covered shapes (the M0 checklist, MVP-SPEC.md line 153)
//!
//! | shape | how it is expressed |
//! | --- | --- |
//! | single / multi-file | [`WorkSpec::files`] length |
//! | text / binary | [`FileSpec::text`] / [`FileSpec::binary`] |
//! | `--split` multi-unit | [`FileSpec::split`] |
//! | `--no-fine-tree` | [`FileSpec::without_fine_tree`] |
//! | raw mirror (CRLF / BOM / NFD source) | any text [`FileSpec`] whose raw bytes are not already canonical — the mirror is emitted automatically (G7's `needs_mirror` rule) |
//! | empty file | zero-length raw bytes; the fine tree is forced absent (G4) |
//! | one-byte file | one-byte raw bytes |
//! | unbalanced `n = 6` | a 6-byte fine-tree file — the *leaf* count is what is unbalanced, not the unit count |
//! | full / partial / `--all` selections | [`FileSelection`] and [`Selection::all`] |
//! | empty anchors | [`AnchorSet::Empty`] — the UNANCHORED bundle |
//! | every anchor kind + optional slot | [`AnchorSet::EveryKind`], receipt in or out (F13) |
//!
//! [`shapes`] holds one named constructor per row, so R7/R9/R10 name a shape
//! rather than re-deriving one, and a shape's bytes can only change in one
//! place.
//!
//! # Relationship to `manifest::fixtures` (F5): complementary, not superseded
//!
//! [`crate::manifest::fixtures`] stays exactly as it is. It builds manifest
//! *bodies* whose commitments, nonces and addresses are recognisable
//! constant patterns — `commit32(0x01)`, `nonce(0x11)` — which is precisely
//! what F5/F6/F7's **schema**-level accept/reject matrices and the
//! `manifest-ids` golden vectors need: bytes that are stable, obviously
//! synthetic, and cheap.
//!
//! Those fixtures can never feed `verify_bundle`, because their commitments
//! do not open to anything. This module is the other tier: every commitment,
//! seed, key and proof here is genuinely derived, so the artifact survives
//! the evidence pipeline. The two are used by disjoint suites and neither
//! absorbs the other — extending `manifest::fixtures` into cryptographic
//! consistency would have made F5's cheap schema matrices slow and would
//! have forced `work_id` vectors to move whenever a crypto detail changed.
//!
//! # Determinism
//!
//! Everything is a pure function of `(seed, spec, selection, tweak)`. The one
//! genuinely random input a real seal has — the per-unit AEAD nonce, which
//! [`encrypt_unit`] draws internally and admits no caller value for — comes
//! from [`FixtureRng`], so two runs with the same seed produce
//! **byte-identical** bundles. `fixtures_are_byte_reproducible` asserts it,
//! and `the_seed_is_live` asserts the seed actually reaches the bytes.
//!
//! # WASM-safety and the feature gate
//!
//! Gated on **`test-vectors`**, not `test-util`. `test-util` implies
//! `test-vectors` (`Cargo.toml`), so every `test-util` consumer still gets
//! this module — but the smaller gate is what lets the `wasm32-core-tests`
//! lane use it, since that lane's dev-dependency edge enables `test-vectors`
//! only (P14's target-split dev-dependencies). Nothing here does I/O, draws
//! from `getrandom`, reads a clock, or touches an optional dependency, so
//! the `core-dep-graph` verdict is untouched by construction.
//!
//! # Secret hygiene (project rule 6)
//!
//! Every secret is synthetic: the master secret is
//! [`TEST_MASTER_SECRET_W`](super::TEST_MASTER_SECRET_W) unless a spec names
//! [`alternate_test_secret`](super::alternate_test_secret) material, per
//! `testdata/README.md`. Nothing here logs, and [`BuiltFixture`]'s `Debug`
//! renders lengths rather than bytes.
//!
//! What a built bundle *discloses* is exactly what the selection asks for.
//! The generation side derives no `file_salt`, no `s_root` and no GGM seed
//! for a file it is not fully revealing — enforced by construction in
//! [`assemble`], and asserted structurally over randomized works by
//! `partial_reveals_disclose_no_full_reveal_material` and
//! `no_disclosed_cover_seed_is_an_ancestor_of_an_unrevealed_leaf`.
//!
//! # What R13 (the M3 production builder) must preserve
//!
//! R13 replaces or absorbs this constructor under a parity test, so the seam
//! is drawn where the two can meet:
//!
//! 1. **Assembly is a pure function of already-computed material.** [`build`]
//!    takes a spec and returns bytes; it never reads a file, contacts a
//!    network, or consults a clock. R13's signature (tasks/R.md R13) is the
//!    same shape with the plaintext manifest, storage record, resolved
//!    selection, ciphertexts and derivation handle passed in — so a parity
//!    test can feed both the *same* inputs.
//! 2. **Derivation is C's and G's, never re-implemented here.** Every salt,
//!    seed and key comes from [`crate::crypto::hkdf`]; every commitment from
//!    [`crate::crypto::commit`]; every cover and boundary path from
//!    [`prove_range`]. Parity is then a statement about *assembly*, which is
//!    the only thing R13 genuinely re-implements.
//! 3. **Isolation is enforced by construction, not by a post-check.**
//!    Full-reveal material is derived inside the one branch that has already
//!    established `full(F)`, and cover seeds only ever come out of
//!    [`prove_range`]'s leaf-exact cover. R13's Do text requires exactly this
//!    ("derive and emit nothing for untouched files"), so the parity test
//!    compares two implementations of one rule rather than a rule against a
//!    lint.
//! 4. **The manifest-order contract.** Units are numbered work-globally in
//!    manifest order, files in file-table order, and a file's raw mirror is
//!    its **last** unit (D23). All three must survive: `unit_id` is the LE64
//!    ordinal every derivation keys on, so a renumbering is a format break,
//!    not a refactor.
//! 5. **[`Tweak`] is a fixture-only concept.** It exists so R7 can build
//!    *invalid* bundles by typed construction rather than byte-patching. R13
//!    must have no equivalent: a production builder that can emit a leaking
//!    bundle on request is one that can do it by accident. The parity test
//!    therefore compares [`Tweak::default`] output only.
//!
//! [`encrypt_unit`]: crate::crypto::unit_aead::encrypt_unit
//! [`FixtureRng`]: super::fixture_rng::FixtureRng
//! [`prove_range`]: crate::content::fine_tree::prove_range

use crate::bundle::{
    AnchorStatus, BundleParts, BundleV1, CoverEntry as BundleCoverEntry, CoveredReveal, FullReveal,
    NonCoveredReveal, OpaqueBytes, OtsAnchor, OtsUpgrade, PathNode, ReceiptRecord, StorageRecord,
    TouchedFile as BundleTouchedFile, TsaAnchor, encode_bundle,
};
use crate::canon::{TextMode, UNICODE_17_0_0, canonicalize_v};
use crate::content::fine_tree::{canonical_leaf_level_payload, prove_range, rebuild_fine_root};
use crate::content::ggm::{NodeAddress, depth_for_leaf_count};
use crate::content::unit::ByteRange as ContentByteRange;
use crate::crypto::commit::{CommitmentDigest, canon_commit, path_commit, raw_commit, unit_commit};
use crate::crypto::disclosure::UnitBinding;
use crate::crypto::hkdf::{
    FileId, UnitId, derive_file_salt, derive_fine_seed, derive_path_salt, derive_unit_key,
    derive_unit_salt,
};
use crate::crypto::material::{MasterSecretRef, NodeHash32, Salt16, Seed32};
use crate::crypto::secrets::SealId;
use crate::crypto::sig_policy::{SigPolicy, public_keys, sign_body};
use crate::crypto::unit_aead::encrypt_unit;
use crate::manifest::body::{
    ByteRange, CanonMode, ContentAddress, FileEntry, FineTree, ManifestBodyV1,
    Nonce24 as ManifestNonce, UnitEntry, encode_body,
};
use crate::manifest::registry::UnitKind;
use crate::manifest::{SigAlgMap, SigMaterial, encode_envelope};

use super::TEST_MASTER_SECRET_W;
use super::fixture_rng::FixtureRng;

// ---------------------------------------------------------------------------
// fixed fixture constants
// ---------------------------------------------------------------------------

/// The `app_version` every fixture records — a fixed placeholder, never the
/// real crate version, so a version bump cannot silently change committed
/// bundle bytes. Matches the manifest fixtures' own constant.
pub const FIXTURE_APP_VERSION: &str = "antseal-fixture/1";

/// The `claimed_time` every fixture records: 2026-01-01T00:00:00Z as POSIX
/// seconds. Fixed, so fixtures are time-independent.
pub const FIXTURE_CLAIMED_TIME: u64 = 1_767_225_600;

/// The fixture `seal_id` — public manifest data, NON-SECRET, and distinct
/// from every other committed fixture id in the tree.
pub const FIXTURE_SEAL_ID: [u8; 16] = [
    0xB6, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
];

/// The default [`WorkSpec::seed`]. Any `u64` works; this is the value the
/// [`shapes`] constructors are reproducible under.
pub const DEFAULT_SEED: u64 = 0x5EED_0006;

/// The placeholder Arbitrum One block number a fixture receipt records.
///
/// A receipt is *supporting evidence only* at M0 — no on-chain datum contains
/// `anchor_digest`, so nothing here can carry a proven time (registry §7.10).
pub const FIXTURE_BLOCK_NUMBER: u64 = 300_000_000;

// ---------------------------------------------------------------------------
// the work specification
// ---------------------------------------------------------------------------

/// Which byte domain a file's unit tiling covers (MVP-SPEC.md line 83).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileKindSpec {
    /// Binary: offsets are raw-byte offsets; no canonical rendition, no
    /// mirror, no `canon_commit`.
    Binary,
    /// Text: offsets are canonical-byte offsets. A raw mirror is emitted
    /// **iff** the raw bytes are not already canonical (G7's rule).
    Text,
}

/// One file of a synthetic work.
///
/// Built through the constructors rather than literally, so the invariants
/// the manifest schema enforces (a non-empty unit table, coverage agreeing
/// with the fine-tree state) are established before [`build`] runs.
#[derive(Debug, Clone)]
pub struct FileSpec {
    path: String,
    raw: Vec<u8>,
    kind: FileKindSpec,
    fine_tree: bool,
    /// Widths of successive normal units over the tiling domain. Empty
    /// means "one whole-file unit".
    unit_widths: Vec<u64>,
    /// Replaces `canonicalize_v(raw)` as the file's canonical bytes.
    ///
    /// Fixture-only, and the honest way to express R7's raw-mirror
    /// canonicalization row: the raw bytes (and therefore `raw_commit` and
    /// the mirror's `unit_commit`) stay self-consistent while the canonical
    /// domain deliberately is not what the raw bytes canonicalize to.
    canonical_override: Option<Vec<u8>>,
}

impl FileSpec {
    /// A binary file: one whole-file unit, fine tree present.
    #[must_use]
    pub fn binary(path: &str, raw: impl Into<Vec<u8>>) -> Self {
        Self::new(path, raw.into(), FileKindSpec::Binary)
    }

    /// A text file: one whole-file unit over the canonical bytes, fine tree
    /// present, plus a raw mirror iff the raw bytes are not canonical.
    #[must_use]
    pub fn text(path: &str, raw: impl Into<Vec<u8>>) -> Self {
        Self::new(path, raw.into(), FileKindSpec::Text)
    }

    fn new(path: &str, raw: Vec<u8>, kind: FileKindSpec) -> Self {
        Self {
            path: path.to_owned(),
            raw,
            kind,
            fine_tree: true,
            unit_widths: Vec::new(),
            canonical_override: None,
        }
    }

    /// `--no-fine-tree`: the file's units carry `unit_commit` instead
    /// (spec lines 84, 94) and no `fine_root` is recorded.
    #[must_use]
    pub fn without_fine_tree(mut self) -> Self {
        self.fine_tree = false;
        self
    }

    /// `--split`: tile the file with units of exactly these widths, in
    /// order. They must sum to the tiling-domain size; [`build`] panics
    /// otherwise, since a fixture that does not tile is a fixture bug, not
    /// a verifier input.
    #[must_use]
    pub fn split(mut self, widths: impl Into<Vec<u64>>) -> Self {
        self.unit_widths = widths.into();
        self
    }

    /// Override the canonical bytes — see [`Self::canonical_override`].
    #[must_use]
    pub fn with_canonical_override(mut self, canonical: impl Into<Vec<u8>>) -> Self {
        self.canonical_override = Some(canonical.into());
        self
    }

    /// The file's path.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }
}

/// Which anchor artifacts a bundle carries.
///
/// The anchor stage is an M0 stub (one `absent` slot per artifact), so the
/// artifact *bytes* are opaque placeholders — what the shapes exercise is
/// the empty-versus-populated section, which is the M0 requirement
/// (line 153's empty-anchor vector).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum AnchorSet {
    /// Both anchor sections empty — the **UNANCHORED** bundle.
    #[default]
    Empty,
    /// One OTS artifact and two TSA artifacts (the spec's ≥2-TSA shape),
    /// each with its optional sub-structure **absent**: no OTS upgrade
    /// group, no TSA intermediates, no receipt.
    OneOtsTwoTsa,
    /// **Every anchor kind and every optional slot the F8 schema defines**,
    /// populated with opaque placeholder bytes (F13):
    ///
    /// - two OTS artifacts — one carrying the D79 upgrade group (block
    ///   height, the 80-byte header, fetch date), one without it;
    /// - two TSA artifacts — one with intermediates, one without;
    /// - the Arbitrum receipt record when `receipt`.
    ///
    /// `receipt: false` is the receipt-**excluded** twin of the same shape,
    /// so the pair is a one-section diff. Presence *is* the sealer's
    /// `--include-receipt` choice (registry §7.10) and carries no verdict,
    /// which is exactly why both need a committed vector.
    ///
    /// Added by F13: `OneOtsTwoTsa` leaves the upgrade group, the
    /// intermediate list and the whole receipt section unexercised by any
    /// committed artifact, and *"a bundle with every anchor kind
    /// populated"* plus *"receipt-included and receipt-excluded variants"*
    /// are named F13 vectors.
    EveryKind {
        /// Whether the receipt section is present.
        receipt: bool,
    },
}

/// A whole synthetic work.
#[derive(Debug, Clone)]
pub struct WorkSpec {
    /// Human title recorded in the manifest body.
    pub title: String,
    /// The files, in file-table order — index **is** `file_id` (spec
    /// line 76).
    pub files: Vec<FileSpec>,
    /// Which signature algorithms the manifest's `sig_policy` lists.
    pub policy: SigPolicy,
    /// Which anchor artifacts the bundle embeds.
    pub anchors: AnchorSet,
    /// Seeds the deterministic fixture RNG the AEAD nonces come from.
    pub seed: u64,
}

impl WorkSpec {
    /// A work over `files` with the hybrid policy, empty anchors and
    /// [`DEFAULT_SEED`].
    #[must_use]
    pub fn new(title: &str, files: Vec<FileSpec>) -> Self {
        Self {
            title: title.to_owned(),
            files,
            policy: SigPolicy::hybrid(),
            anchors: AnchorSet::Empty,
            seed: DEFAULT_SEED,
        }
    }

    /// Re-seed the fixture RNG.
    #[must_use]
    pub const fn with_seed(mut self, seed: u64) -> Self {
        self.seed = seed;
        self
    }

    /// Attach anchor artifacts.
    #[must_use]
    pub const fn with_anchors(mut self, anchors: AnchorSet) -> Self {
        self.anchors = anchors;
        self
    }

    /// Use the Ed25519-only fallback policy (spec line 97).
    #[must_use]
    pub fn with_ed25519_only_policy(mut self) -> Self {
        self.policy = SigPolicy::ed25519_only();
        self
    }
}

// ---------------------------------------------------------------------------
// the reveal selection
// ---------------------------------------------------------------------------

/// What a reveal shows of one file.
///
/// Deliberately expressed as *what the sealer selected*, never as a declared
/// shape: `full(F)` is derived by the verifier from the revealed set (D28
/// rider 1), and [`FileSelection::Units`] naming every normal unit is
/// therefore a **full** reveal — the `full-reveal-via-enumerated-units`
/// positive case. The builder derives it the same way the verifier does, so
/// the two cannot disagree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileSelection {
    /// Nothing shown, and no `touched_files` entry — the committed
    /// placeholder shape.
    Untouched,
    /// Reveal these normal units, by index within the file's normal-unit
    /// list (not by work-global `unit_id`, so a selection survives having a
    /// file inserted before it).
    Units(Vec<usize>),
    /// [`Self::Units`] **plus the raw mirror**, if the file has one — a
    /// bundle no honest CLI emits (`mirror_selectable`,
    /// MVP-SPEC.md line 92, forbids naming a mirror in a `--units` list)
    /// but which the verifier deliberately accepts as a *partial* reveal
    /// when the indices are a strict subset (mirrors are exempt by kind,
    /// D28 rider 1).
    ///
    /// This is R53's shape: the 2026-07-31 review (finding 8) showed a
    /// partial reveal's report naming a mirror whose bytes rows 9–10 never
    /// bound, and no valid generator could express the shape — every
    /// fixture revealed mirrors only via [`Self::Full`]. Naming all the
    /// indices makes it equivalent to `Full`, the same derivation rule as
    /// the enumerated-units case.
    UnitsWithMirror(Vec<usize>),
    /// Reveal every normal unit, plus the raw mirror if the file has one.
    Full,
    /// Reveal every normal unit but withhold the raw mirror — still a full
    /// reveal (mirrors are exempt *by kind*), and the shape that leaves
    /// D28's rows 9–10 unexercised.
    FullNoMirror,
}

/// A whole reveal selection: one [`FileSelection`] per file, in file order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Selection(pub Vec<FileSelection>);

impl Selection {
    /// `--all`: every file fully revealed, mirrors included.
    #[must_use]
    pub fn all(file_count: usize) -> Self {
        Self(vec![FileSelection::Full; file_count])
    }

    /// Every file untouched — a bundle that proves the work exists and
    /// shows none of it.
    #[must_use]
    pub fn nothing(file_count: usize) -> Self {
        Self(vec![FileSelection::Untouched; file_count])
    }

    fn for_file(&self, file_id: usize) -> &FileSelection {
        self.0.get(file_id).unwrap_or(&FileSelection::Untouched)
    }
}

// ---------------------------------------------------------------------------
// the fixture-only mutation knobs (R7's substrate)
// ---------------------------------------------------------------------------

/// Fixture-only mutations, applied **by typed construction** rather than by
/// patching encoded bytes.
///
/// One knob per tamper row: a row sets exactly one field, which is what makes
/// "this mutation, this error" an honest claim. R13 must have no equivalent
/// (module docs, point 5).
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct Tweak {
    /// Widen this unit's **manifest** range past the end of its file.
    pub range_out_of_bounds: Option<u64>,
    /// Swap the manifest ranges of this file's first two normal units, so
    /// the unit table is no longer ascending by `range_start`.
    pub unsorted_ranges: Option<u64>,
    /// Record `true_length = range_width + 1` for this unit, keeping its
    /// content and its padding bucket.
    pub true_length_excess: Option<u64>,
    /// Attach a `full_reveals` entry (with `file_salt`, and `s_root` when
    /// the file has a fine tree) for this file even though it is not fully
    /// revealed.
    pub leak_full_material: Option<u64>,
    /// Drop this fully revealed file's `full_reveals` entry entirely.
    pub drop_full_material: Option<u64>,
    /// Emit this fully revealed file's `full_reveals` entry **without** its
    /// `s_root`, even though the file has a fine tree.
    pub drop_s_root: Option<u64>,
    /// Attach an `s_root` to this fully revealed file's entry even though
    /// the file has **no** fine tree (D74).
    pub extraneous_s_root: Option<u64>,
    /// Flip a bit of this file's manifest `canon_commit`.
    pub corrupt_canon_commit: Option<u64>,
    /// Flip a bit of this file's manifest `raw_commit`.
    pub corrupt_raw_commit: Option<u64>,
    /// Flip a bit of this file's **disclosed** `s_root`, leaving the
    /// per-unit cover seeds correct.
    pub corrupt_disclosed_s_root: Option<u64>,
    /// Flip a bit of this file's disclosed `s_root`'s **inert tail** (bytes
    /// 16..32), leaving its salt half and every cover seed correct (D83).
    ///
    /// Observable only at `n == 1`, where `d == 0` makes the grid root a
    /// leaf and the tail is fixed at zero; at any larger `n` the tail is the
    /// real seed and this produces a bundle that fails the *rebuild*
    /// instead. That asymmetry is the rule, so tests state which they mean.
    pub corrupt_s_root_tail: Option<u64>,
    /// Flip a bit of the **inert tail** (bytes 16..32) of this covered
    /// unit's first `level == d` cover entry, leaving its address, its salt
    /// half, the boundary path and the revealed bytes honest (D83).
    ///
    /// A no-op when the unit's cover has no leaf-level node — the incidence
    /// rule is `d == 0 ∨ a odd ∨ (b odd ∧ b < n)` — so a test using this
    /// knob must assert the mutation actually landed.
    pub corrupt_leaf_cover_tail: Option<u64>,
    /// The counterpart of [`Self::corrupt_leaf_cover_tail`]: flip a bit of
    /// the **salt half** (bytes 0..16) of the same `level == d` cover entry,
    /// leaving D83's zero tail intact.
    ///
    /// Exists so a test can show the two halves of one 32-byte field fail as
    /// *different* classes — the tail as a canonicality rejection, the salt
    /// as a binding failure — rather than "any change to these bytes fails".
    pub corrupt_leaf_cover_salt: Option<u64>,
    /// Emit a `touched_files` entry naming this `file_id`, which no file
    /// table row has.
    pub unknown_touched_file: Option<u64>,
    /// Emit a **correct** `touched_files` entry — real path, real
    /// `path_salt` — for this existing file, from which the selection
    /// reveals no unit. This is the **D82** shape.
    ///
    /// The salt is genuinely derived, not junk, and that matters: a junk
    /// salt would fail R3's `path_commit` recomputation at stage 2, so the
    /// row would pin `path-commit-mismatch` and silently test something
    /// else entirely. The whole point of this knob is that the entry is
    /// *impeccable in every respect except* that nothing of the file is
    /// shown.
    pub touch_without_reveal: Option<u64>,
    /// Flip a bit of this revealed unit's embedded ciphertext.
    pub corrupt_ciphertext: Option<u64>,
    /// Flip a bit of this **non-covered** unit's manifest `unit_commit`,
    /// leaving its bytes and its salt alone (R8's *altered manifest field*
    /// mutation, non-covered arm).
    ///
    /// The manifest is signed, so this also invalidates the signature — and
    /// that is exactly what the row proves: the frozen stage order puts
    /// Units (3) and Files (4) before Signatures (5), so a bundle whose
    /// content contradicts its manifest is reported as a content failure
    /// rather than as a signature failure.
    pub corrupt_unit_commit: Option<u64>,
    /// Present the **first** unit's ciphertext under the **second** unit's
    /// bundle entry, keeping the second's key, nonce and `unit_id` (R8's
    /// *swapped unit*; decision D81's recorded non-row).
    ///
    /// Both must be revealed. The AAD's `unit_id` binding, not a
    /// commitment, is what rejects it — see the C-level
    /// `aad_unit_id_binding_rejects_a_foreign_unit_id`, which varies the
    /// AAD alone.
    pub swap_ciphertext_into: Option<(u64, u64)>,
    /// Ship this revealed unit's entry with **another unit's** `k_u`
    /// (D81's second recorded non-row: pipeline-level wrong key).
    ///
    /// The substitute is a genuinely derived key, not a junk buffer, so the
    /// mutation is the one a relay could actually perform — and the
    /// donor id is the knob's second field.
    pub wrong_unit_key: Option<(u64, u64)>,
    /// Ship this **non-covered** revealed unit's entry with another unit's
    /// `unit_salt`, so its `unit_commit` recomputation fails.
    ///
    /// A genuinely derived salt for the same reason as `wrong_unit_key`,
    /// and 16 bytes long so R3's length group cannot claim it first.
    pub wrong_unit_salt: Option<(u64, u64)>,
    /// Omit this file's `touched_files` entry even though the reveal shows
    /// units of it (D80).
    pub drop_touched_file: Option<u64>,
    /// Ship this fine-tree-covered unit in `noncovered_reveals` instead.
    pub misplace_covered_unit: Option<u64>,
    /// Encrypt this unit one 256-byte pad bucket too long, so it
    /// authenticates and then fails the `padded_length` recompute.
    ///
    /// `test-util` only: C9's mis-encryptors live behind that feature, and a
    /// knob that were silently ignored on the smaller feature tier would be
    /// worse than an absent one.
    #[cfg(feature = "test-util")]
    pub over_pad: Option<u64>,
    /// Encrypt this unit with a non-zero final pad byte, so it
    /// authenticates at the right length and then fails the all-zero check.
    #[cfg(feature = "test-util")]
    pub non_zero_pad: Option<u64>,
    /// Ship this non-covered unit in `covered_reveals` instead.
    ///
    /// A covered reveal must carry a non-empty cover, so the entry borrows
    /// the cover its file's first normal unit would have had. That is
    /// semantically meaningless on purpose: the reveal-section rule is
    /// adjudicated at stage 2, before anything opens a cover, so the row
    /// pins the misplacement and nothing else.
    pub misplace_noncovered_unit: Option<u64>,
}

impl Tweak {
    /// The untweaked fixture — what [`build`] produces for a valid bundle.
    #[must_use]
    pub fn none() -> Self {
        Self::default()
    }
}

// ---------------------------------------------------------------------------
// the built fixture
// ---------------------------------------------------------------------------

/// One built `.sealproof` plus the facts a test needs to make assertions
/// about it without re-deriving the plan.
pub struct BuiltFixture {
    /// The encoded `.sealproof` bytes — the input to `verify_bundle`.
    pub bytes: Vec<u8>,
    /// The encoded manifest **envelope** bytes the bundle embeds.
    pub manifest: Vec<u8>,
    /// Per file, in file-table order.
    pub files: Vec<FileFacts>,
    /// Work-global `unit_id`s the bundle reveals, ascending.
    pub revealed_unit_ids: Vec<u64>,
}

impl core::fmt::Debug for BuiltFixture {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Lengths, never bytes: a fixture's bytes carry synthetic key
        // material and printing them is a habit worth not forming.
        f.debug_struct("BuiltFixture")
            .field("bytes", &format_args!("<{} B>", self.bytes.len()))
            .field("manifest", &format_args!("<{} B>", self.manifest.len()))
            .field("files", &self.files)
            .field("revealed_unit_ids", &self.revealed_unit_ids)
            .finish()
    }
}

/// What a built fixture knows about one of its files.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileFacts {
    /// Index in the file table.
    pub file_id: u64,
    /// The disclosed path (whether or not the bundle discloses it).
    pub path: String,
    /// Size of the tiling domain — canonical bytes for text, raw for binary.
    pub size: u64,
    /// Whether the manifest records a fine tree.
    pub fine_tree: bool,
    /// Work-global `unit_id`s of the file's **normal** units, in order.
    pub normal_unit_ids: Vec<u64>,
    /// The raw mirror's `unit_id`, if the file has one.
    pub mirror_unit_id: Option<u64>,
    /// Whether the selection makes this a full reveal (`|R(F)| == |N(F)| > 0`).
    pub fully_revealed: bool,
}

// ---------------------------------------------------------------------------
// the planner
// ---------------------------------------------------------------------------

/// One unit as the builder plans it, before the manifest or bundle exists.
struct PlannedUnit {
    unit_id: u64,
    file_id: u64,
    kind: UnitKind,
    /// The manifest range as it will be written (a [`Tweak`] may have
    /// widened or swapped it).
    range: ByteRange,
    /// The range the content actually occupies — what proofs are cut over.
    true_range: ByteRange,
    /// The manifest `true_length` as it will be written.
    true_length: u64,
    bytes: Vec<u8>,
    covered: bool,
    ciphertext: Vec<u8>,
    nonce: ManifestNonce,
}

/// One file, resolved.
struct PlannedFile {
    file_id: u64,
    path: String,
    raw: Vec<u8>,
    /// Canonical bytes, present iff the file is text.
    canonical: Option<Vec<u8>>,
    /// The tiling domain — canonical for text, raw for binary.
    tiling: Vec<u8>,
    fine_tree: bool,
    /// Indices into the planned unit vector.
    normal_units: Vec<usize>,
    mirror_unit: Option<usize>,
}

fn w() -> MasterSecretRef<'static> {
    MasterSecretRef::from_bytes(&TEST_MASTER_SECRET_W)
}

fn seal_id() -> SealId {
    SealId::from_bytes(FIXTURE_SEAL_ID)
}

/// Flip the low bit of a 32-byte digest — the canonical "right shape, wrong
/// value" mutation.
fn flip(digest: &CommitmentDigest) -> CommitmentDigest {
    let mut out = *digest;
    out[0] ^= 0x01;
    out
}

/// A recognisable per-unit content address. Fixtures never fetch, so the
/// address only has to be a well-formed 32-byte value that differs per unit.
fn fixture_address(unit_id: u64) -> ContentAddress {
    let mut bytes = [0xADu8; 32];
    bytes[..8].copy_from_slice(&unit_id.to_le_bytes());
    ContentAddress::from_bytes(bytes)
}

/// Resolve a [`FileSpec`] into content, unit ranges and mirror presence.
///
/// Panics (test-only) when a `--split` plan does not tile its file: an
/// untileable fixture is a fixture bug, and surfacing it as a verifier
/// rejection would silently weaken every row built on it.
fn plan_file(file_id: u64, spec: &FileSpec) -> (PlannedFile, Vec<(UnitKind, ByteRange, Vec<u8>)>) {
    let canonical = match spec.kind {
        FileKindSpec::Binary => None,
        FileKindSpec::Text => Some(spec.canonical_override.clone().unwrap_or_else(|| {
            canonicalize_v(UNICODE_17_0_0, TextMode::Forced, &spec.raw)
                .expect("fixture text canonicalizes under forced mode")
                .into_bytes()
        })),
    };
    let tiling = canonical.clone().unwrap_or_else(|| spec.raw.clone());
    let size = u64::try_from(tiling.len()).expect("fixture files are small");

    // G4: an empty file has no fine tree (there is no leaf to hash), and
    // still carries exactly one empty unit (spec line 78).
    let fine_tree = spec.fine_tree && size > 0;

    let widths: Vec<u64> = if spec.unit_widths.is_empty() {
        vec![size]
    } else {
        spec.unit_widths.clone()
    };
    assert_eq!(
        widths.iter().copied().sum::<u64>(),
        size,
        "fixture file {file_id} (`{}`): split widths must tile [0, {size})",
        spec.path
    );

    let mut units = Vec::new();
    let mut cursor = 0u64;
    for width in widths {
        let start = usize::try_from(cursor).expect("small");
        let end = start + usize::try_from(width).expect("small");
        units.push((
            UnitKind::Normal,
            ByteRange::new(cursor, width),
            tiling[start..end].to_vec(),
        ));
        cursor += width;
    }

    // G7: a text file needs a raw mirror iff its raw bytes are not already
    // its canonical bytes. D23: the mirror is the file's LAST unit.
    let needs_mirror = canonical.as_ref().is_some_and(|canon| *canon != spec.raw);
    if needs_mirror {
        let raw_len = u64::try_from(spec.raw.len()).expect("fixture files are small");
        units.push((
            UnitKind::RawMirror,
            ByteRange::new(0, raw_len),
            spec.raw.clone(),
        ));
    }

    let planned = PlannedFile {
        file_id,
        path: spec.path.clone(),
        raw: spec.raw.clone(),
        canonical,
        tiling,
        fine_tree,
        normal_units: Vec::new(),
        mirror_unit: None,
    };
    (planned, units)
}

// ---------------------------------------------------------------------------
// build
// ---------------------------------------------------------------------------

/// Build a valid `.sealproof` for `spec` under `selection`.
///
/// # Panics
///
/// On a malformed *fixture* (a split that does not tile, a selection naming
/// a unit index the file does not have). Never on anything a verifier would
/// see: a [`Tweak`]'s output is a well-formed bundle that a verifier
/// rejects, which is the whole point.
#[must_use]
pub fn build(spec: &WorkSpec, selection: &Selection) -> BuiltFixture {
    build_tweaked(spec, selection, &Tweak::none())
}

/// Build a `.sealproof` for `spec` under `selection`, applying `tweak`.
///
/// # Panics
///
/// See [`build`].
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn build_tweaked(spec: &WorkSpec, selection: &Selection, tweak: &Tweak) -> BuiltFixture {
    let mut rng = FixtureRng::from_label(spec.seed);

    // ── plan the files and number the units work-globally ──────────────
    let mut files: Vec<PlannedFile> = Vec::with_capacity(spec.files.len());
    let mut units: Vec<PlannedUnit> = Vec::new();
    for (index, file_spec) in spec.files.iter().enumerate() {
        let file_id = u64::try_from(index).expect("fixture works are small");
        let (mut planned, planned_units) = plan_file(file_id, file_spec);
        for (kind, range, bytes) in planned_units {
            let unit_id = u64::try_from(units.len()).expect("fixture works are small");
            // A unit is fine-tree-covered iff its file has a tree AND it is
            // not the raw mirror (the mirror lives in the raw domain, spec
            // line 94) — the single rule `FileEntry::new` re-checks.
            let covered = planned.fine_tree && kind == UnitKind::Normal;
            let (ciphertext, nonce) = encrypt_for(tweak, unit_id, &bytes, &mut rng);
            let index_in_units = units.len();
            match kind {
                UnitKind::Normal => planned.normal_units.push(index_in_units),
                UnitKind::RawMirror => planned.mirror_unit = Some(index_in_units),
            }
            let width = range.length();
            units.push(PlannedUnit {
                unit_id,
                file_id,
                kind,
                range,
                true_range: range,
                true_length: width,
                bytes,
                covered,
                ciphertext,
                nonce: ManifestNonce::from_bytes(*nonce.as_bytes()),
            });
        }
        files.push(planned);
    }

    // ── apply the manifest-side tweaks ─────────────────────────────────
    apply_manifest_tweaks(&mut units, &files, tweak);

    // ── resolve the selection ──────────────────────────────────────────
    let mut revealed: Vec<u64> = Vec::new();
    let mut facts: Vec<FileFacts> = Vec::with_capacity(files.len());
    for file in &files {
        let chosen = selection.for_file(usize::try_from(file.file_id).expect("small"));
        let mut file_revealed: Vec<u64> = Vec::new();
        match chosen {
            FileSelection::Untouched => {}
            FileSelection::Units(indices) | FileSelection::UnitsWithMirror(indices) => {
                for &index in indices {
                    let unit = *file
                        .normal_units
                        .get(index)
                        .expect("selection names a normal unit the file has");
                    file_revealed.push(units[unit].unit_id);
                }
                if matches!(chosen, FileSelection::UnitsWithMirror(_))
                    && let Some(mirror) = file.mirror_unit
                {
                    file_revealed.push(units[mirror].unit_id);
                }
            }
            FileSelection::Full | FileSelection::FullNoMirror => {
                for &unit in &file.normal_units {
                    file_revealed.push(units[unit].unit_id);
                }
                if *chosen == FileSelection::Full
                    && let Some(mirror) = file.mirror_unit
                {
                    file_revealed.push(units[mirror].unit_id);
                }
            }
        }
        file_revealed.sort_unstable();
        file_revealed.dedup();

        // full(F) ⟺ N(F) ≠ ∅ ∧ R(F) = N(F), derived exactly as R4 derives
        // it — mirrors exempt by kind, and the anti-vacuity clause explicit.
        let normal_ids: Vec<u64> = file
            .normal_units
            .iter()
            .map(|&index| units[index].unit_id)
            .collect();
        let fully_revealed = !normal_ids.is_empty()
            && normal_ids
                .iter()
                .all(|unit_id| file_revealed.contains(unit_id));

        facts.push(FileFacts {
            file_id: file.file_id,
            path: file.path.clone(),
            size: u64::try_from(file.tiling.len()).expect("small"),
            fine_tree: file.fine_tree,
            normal_unit_ids: normal_ids,
            mirror_unit_id: file.mirror_unit.map(|index| units[index].unit_id),
            fully_revealed,
        });
        revealed.extend(file_revealed);
    }
    revealed.sort_unstable();

    // ── the manifest ───────────────────────────────────────────────────
    let manifest_bytes = encode_manifest(spec, &files, &units, tweak);

    // ── the bundle ─────────────────────────────────────────────────────
    let bytes = assemble(
        spec,
        &files,
        &units,
        &facts,
        &revealed,
        tweak,
        &manifest_bytes,
    );

    BuiltFixture {
        bytes,
        manifest: manifest_bytes,
        files: facts,
        revealed_unit_ids: revealed,
    }
}

/// Encrypt one unit, honouring the two padding mis-encryption knobs.
///
/// The mis-encryptors are C9's own (`crypto::unit_aead::mis_encrypt`), never
/// a second padding implementation here: a fixture that padded wrongly by
/// its own arithmetic would stop proving anything about the real formula the
/// day that formula changed.
fn encrypt_for(
    tweak: &Tweak,
    unit_id: u64,
    bytes: &[u8],
    rng: &mut FixtureRng,
) -> (Vec<u8>, crate::crypto::unit_aead::Nonce24) {
    #[cfg(feature = "test-util")]
    {
        use crate::crypto::unit_aead::mis_encrypt;
        if tweak.over_pad == Some(unit_id) {
            return mis_encrypt::encrypt_unit_overpadded(
                w(),
                &seal_id(),
                UnitId(unit_id),
                bytes,
                rng,
            )
            .expect("fixture mis-encryption succeeds");
        }
        if tweak.non_zero_pad == Some(unit_id) {
            return mis_encrypt::encrypt_unit_nonzero_padding(
                w(),
                &seal_id(),
                UnitId(unit_id),
                bytes,
                rng,
            )
            .expect("fixture mis-encryption succeeds");
        }
    }
    let _ = tweak;
    encrypt_unit(w(), &seal_id(), UnitId(unit_id), bytes, rng).expect("fixture encryption succeeds")
}

/// The tweaks that alter what the **manifest** claims about a unit's extent.
fn apply_manifest_tweaks(units: &mut [PlannedUnit], files: &[PlannedFile], tweak: &Tweak) {
    if let Some(unit_id) = tweak.range_out_of_bounds
        && let Some(unit) = units.iter_mut().find(|unit| unit.unit_id == unit_id)
    {
        unit.range = ByteRange::new(unit.range.start(), unit.range.length() + 1);
        unit.true_length = unit.range.length();
    }
    if let Some(file_id) = tweak.unsorted_ranges
        && let Some(file) = files.iter().find(|file| file.file_id == file_id)
    {
        assert!(
            file.normal_units.len() >= 2,
            "`unsorted_ranges` needs a file with at least two normal units"
        );
        let first = file.normal_units[0];
        let second = file.normal_units[1];
        let a = units[first].range;
        let b = units[second].range;
        assert_eq!(
            a.length(),
            b.length(),
            "`unsorted_ranges` needs equal-width units so only the order changes"
        );
        units[first].range = b;
        units[second].range = a;
    }
    if let Some(unit_id) = tweak.true_length_excess
        && let Some(unit) = units.iter_mut().find(|unit| unit.unit_id == unit_id)
    {
        // Stage 2 (padding) runs before stage 3 (`true_length` vs width), so
        // the excess must stay inside the same 256-byte padding bucket or
        // the row would bind `padded-length-mismatch` instead.
        assert!(
            crate::crypto::padding::padded_length(
                usize::try_from(unit.true_length).expect("small")
            ) == crate::crypto::padding::padded_length(
                usize::try_from(unit.true_length + 1).expect("small")
            ),
            "`true_length_excess` needs a unit whose width + 1 stays in the same padding bucket"
        );
        unit.true_length += 1;
    }
}

/// Encode the manifest envelope for the planned work.
fn encode_manifest(
    spec: &WorkSpec,
    files: &[PlannedFile],
    units: &[PlannedUnit],
    tweak: &Tweak,
) -> Vec<u8> {
    let entries: Vec<FileEntry> = files
        .iter()
        .map(|file| {
            let file_salt = derive_file_salt(w(), FileId(file.file_id));
            let path_salt = derive_path_salt(w(), FileId(file.file_id));

            let mut raw = raw_commit(&file_salt, &file.raw);
            if tweak.corrupt_raw_commit == Some(file.file_id) {
                raw = flip(&raw);
            }
            let canon = match &file.canonical {
                None => CanonMode::Binary,
                Some(canonical) => {
                    let mut commit = canon_commit(&file_salt, canonical);
                    if tweak.corrupt_canon_commit == Some(file.file_id) {
                        commit = flip(&commit);
                    }
                    CanonMode::Text {
                        canon_commit: commit,
                        unicode_version: UNICODE_17_0_0.to_owned(),
                    }
                }
            };
            let fine_tree = if file.fine_tree {
                let root =
                    rebuild_fine_root(&derive_fine_seed(w(), FileId(file.file_id)), &file.tiling)
                        .expect("fixture fine root builds");
                FineTree::Present {
                    root: *root.as_bytes(),
                }
            } else {
                FineTree::Absent
            };

            let mut file_units: Vec<usize> = file.normal_units.clone();
            file_units.extend(file.mirror_unit);
            FileEntry::new(
                path_commit(&path_salt, &file.path),
                raw,
                canon,
                u64::try_from(file.tiling.len()).expect("small"),
                fine_tree,
                file_units
                    .into_iter()
                    .map(|index| manifest_entry(&units[index], tweak))
                    .collect(),
            )
            .expect("fixture file entry is well formed")
        })
        .collect();

    let pubkeys = SigAlgMap::new(SigMaterial::Pubkey, public_keys(w(), &spec.policy))
        .expect("fixture pubkeys");
    let body = ManifestBodyV1::new(
        FIXTURE_APP_VERSION.to_owned(),
        seal_id(),
        spec.title.clone(),
        FIXTURE_CLAIMED_TIME,
        pubkeys,
        spec.policy.algorithms().to_vec(),
        entries,
    )
    .expect("fixture body is well formed");
    let body_bytes = encode_body(body).expect("fixture body encodes");

    let signatures = SigAlgMap::new(
        SigMaterial::Signature,
        sign_body(w(), &spec.policy, &body_bytes),
    )
    .expect("fixture signatures");
    encode_envelope(&body_bytes, &signatures).expect("fixture envelope encodes")
}

fn manifest_entry(unit: &PlannedUnit, tweak: &Tweak) -> UnitEntry {
    let binding = if unit.covered {
        UnitBinding::FineTreeCovered
    } else {
        let mut commit = unit_commit(&derive_unit_salt(w(), UnitId(unit.unit_id)), &unit.bytes);
        if tweak.corrupt_unit_commit == Some(unit.unit_id) {
            commit = flip(&commit);
        }
        UnitBinding::NonCovered {
            unit_commit: commit,
        }
    };
    UnitEntry::new(
        unit.unit_id,
        unit.kind,
        unit.range,
        unit.true_length,
        binding,
        unit.nonce,
        fixture_address(unit.unit_id),
    )
}

/// Assemble and encode the bundle.
///
/// **This is the isolation-by-construction site** (module docs, point 3):
/// full-reveal material is derived only inside the `fully_revealed` branch,
/// and cover seeds only ever come out of [`prove_range`]'s leaf-exact cover.
#[allow(clippy::too_many_lines)]
fn assemble(
    spec: &WorkSpec,
    files: &[PlannedFile],
    units: &[PlannedUnit],
    facts: &[FileFacts],
    revealed: &[u64],
    tweak: &Tweak,
    manifest_bytes: &[u8],
) -> Vec<u8> {
    let mut covered_reveals = Vec::new();
    let mut noncovered_reveals = Vec::new();

    for unit in units {
        if !revealed.contains(&unit.unit_id) {
            continue;
        }
        let mut ciphertext = unit.ciphertext.clone();
        if tweak.corrupt_ciphertext == Some(unit.unit_id) {
            ciphertext[0] ^= 0x01;
        }
        // Swapped unit: the donor's ciphertext under the recipient's entry.
        // Everything else about the entry — key, nonce, `unit_id` — stays
        // the recipient's, so the AAD's `unit_id` binding is what fails.
        if let Some((donor, recipient)) = tweak.swap_ciphertext_into
            && recipient == unit.unit_id
        {
            ciphertext = units
                .iter()
                .find(|other| other.unit_id == donor)
                .expect("`swap_ciphertext_into` names a unit the work has")
                .ciphertext
                .clone();
        }
        // Wrong `k_u`: another unit's genuinely derived key.
        let key_owner = match tweak.wrong_unit_key {
            Some((victim, donor)) if victim == unit.unit_id => donor,
            _ => unit.unit_id,
        };
        let k_u = derive_unit_key(w(), UnitId(key_owner));

        // The reveal-section rule (R5 coherence): a unit belongs in the
        // section its manifest binding dictates. These two knobs put it in
        // the other one.
        let misplaced = tweak.misplace_covered_unit == Some(unit.unit_id)
            || tweak.misplace_noncovered_unit == Some(unit.unit_id);
        let as_covered = unit.covered != misplaced;

        if as_covered {
            let file = &files[usize::try_from(unit.file_id).expect("small")];
            let s_root = derive_fine_seed(w(), FileId(unit.file_id));
            let leaf_count = u64::try_from(file.tiling.len()).expect("small");
            // A misplaced non-covered unit has no leaf range of its own, so
            // it borrows the file's first normal unit's (see `Tweak`).
            let range = if unit.covered {
                unit.true_range
            } else {
                units[*file
                    .normal_units
                    .first()
                    .expect("a misplaced mirror's file has a normal unit")]
                .true_range
            };
            let proof = prove_range(
                &s_root,
                &file.tiling,
                ContentByteRange::new(range.start(), range.length()),
                leaf_count,
            )
            .expect("fixture range proof");

            let mut cover: Vec<BundleCoverEntry> = proof
                .cover()
                .iter()
                .map(|entry| {
                    // The disclosed form, not the derived seed: at
                    // `level == d` they differ by D83's canonical zero tail.
                    BundleCoverEntry::new(
                        entry.node().address(),
                        Seed32::from_bytes(*entry.payload().as_bytes()),
                    )
                })
                .collect();
            // D83: the two halves of a `level == d` payload, corrupted one at
            // a time. Bytes 16..32 are fixed at zero (a canonicality rule);
            // bytes 0..16 are `salt_i` (a binding input). Everything else
            // about the entry stays honest — its address, the boundary path,
            // the ciphertext.
            for (knob, at_byte) in [
                (tweak.corrupt_leaf_cover_tail, 16usize),
                (tweak.corrupt_leaf_cover_salt, 0),
            ] {
                if knob == Some(unit.unit_id)
                    && let Some(depth) = depth_for_leaf_count(leaf_count)
                    && let Some(at) = cover
                        .iter()
                        .position(|entry| entry.address().level() == depth)
                {
                    let mut bytes = *cover[at].seed().as_bytes();
                    bytes[at_byte] ^= 0x01;
                    cover[at] =
                        BundleCoverEntry::new(cover[at].address(), Seed32::from_bytes(bytes));
                }
            }
            let paths: Vec<PathNode> = proof
                .boundary()
                .iter()
                .map(|node| {
                    PathNode::new(
                        node.address(),
                        NodeHash32::from_bytes(*node.hash().as_bytes()),
                    )
                })
                .collect();
            covered_reveals.push(
                CoveredReveal::new(
                    unit.unit_id,
                    k_u,
                    OpaqueBytes::from_vec(ciphertext),
                    cover,
                    paths,
                )
                .expect("fixture covered reveal"),
            );
        } else {
            // Wrong `unit_salt`: another unit's genuinely derived salt, so
            // it is the right length and only the commitment opening fails.
            let salt_owner = match tweak.wrong_unit_salt {
                Some((victim, donor)) if victim == unit.unit_id => donor,
                _ => unit.unit_id,
            };
            noncovered_reveals.push(
                NonCoveredReveal::new(
                    unit.unit_id,
                    k_u,
                    OpaqueBytes::from_vec(ciphertext),
                    derive_unit_salt(w(), UnitId(salt_owner)),
                )
                .expect("fixture non-covered reveal"),
            );
        }
    }

    // touched_files: every file the reveal touches, plus the tweak's
    // deliberately unknown id.
    let mut touched: Vec<BundleTouchedFile> = facts
        .iter()
        .filter(|file| !file.normal_unit_ids.is_empty() || file.mirror_unit_id.is_some())
        .filter(|file| {
            revealed
                .iter()
                .any(|unit_id| touches(units, *unit_id, file.file_id))
        })
        .filter(|file| tweak.drop_touched_file != Some(file.file_id))
        .map(|file| {
            BundleTouchedFile::new(
                file.file_id,
                file.path.clone(),
                derive_path_salt(w(), FileId(file.file_id)),
            )
        })
        .collect();
    if let Some(file_id) = tweak.unknown_touched_file {
        touched.push(BundleTouchedFile::new(
            file_id,
            "phantom.txt".to_owned(),
            derive_path_salt(w(), FileId(file_id)),
        ));
    }
    if let Some(file_id) = tweak.touch_without_reveal {
        let file = facts
            .iter()
            .find(|file| file.file_id == file_id)
            .expect("`touch_without_reveal` names a file the work has");
        assert!(
            !revealed
                .iter()
                .any(|unit_id| touches(units, *unit_id, file_id)),
            "`touch_without_reveal` needs a file the selection reveals NOTHING from — file \
             {file_id} has a revealed unit, so the entry would be an ordinary touched file"
        );
        // Real path, real salt: the entry opens `path_commit` correctly, so
        // the only thing wrong with it is the D82 question itself.
        touched.push(BundleTouchedFile::new(
            file_id,
            file.path.clone(),
            derive_path_salt(w(), FileId(file_id)),
        ));
    }
    touched.sort_by_key(BundleTouchedFile::file_id);

    // full_reveals: derived **only** for files the selection fully reveals.
    // Everything else in this vector is a Tweak deliberately breaking that
    // rule so R7 can pin the verifier's rejection.
    let mut full_reveals: Vec<FullReveal> = Vec::new();
    for file in facts {
        let leak = tweak.leak_full_material == Some(file.file_id);
        if !file.fully_revealed && !leak {
            continue;
        }
        if tweak.drop_full_material == Some(file.file_id) {
            continue;
        }
        // F8 rejects `full_reveals ⊄ touched_files` at decode, so dropping a
        // file's path necessarily drops its full-reveal entry too — the D80
        // row therefore has to target a file with no full reveal.
        if tweak.drop_touched_file == Some(file.file_id) {
            continue;
        }
        let file_salt = derive_file_salt(w(), FileId(file.file_id));
        // The DISCLOSED `s_root`, which is the derived fine seed at every
        // size but one: at `n == 1` the GGM depth is 0, so the grid root
        // **is** the single leaf and D83 fixes the disclosed form at
        // `salt_0 ‖ 0x00·16` (registry §7.14 key 2). Routed through the same
        // prover-side rule `cover_seeds` uses, so a sealer has exactly one
        // implementation of it.
        let mut s_root = if file.fine_tree {
            Some(canonical_leaf_level_payload(
                &derive_fine_seed(w(), FileId(file.file_id)),
                NodeAddress::root(),
                depth_for_leaf_count(file.size).unwrap_or(u8::MAX),
            ))
        } else {
            None
        };
        if tweak.drop_s_root == Some(file.file_id) {
            s_root = None;
        }
        if tweak.extraneous_s_root == Some(file.file_id) {
            s_root = Some(derive_fine_seed(w(), FileId(file.file_id)));
        }
        if tweak.corrupt_disclosed_s_root == Some(file.file_id)
            && let Some(seed) = s_root
        {
            let mut bytes = *seed.as_bytes();
            bytes[0] ^= 0x01;
            s_root = Some(Seed32::from_bytes(bytes));
        }
        if tweak.corrupt_s_root_tail == Some(file.file_id)
            && let Some(seed) = s_root
        {
            // D83, the §7.14 site: the tail only, salt half untouched.
            let mut bytes = *seed.as_bytes();
            bytes[16] ^= 0x01;
            s_root = Some(Seed32::from_bytes(bytes));
        }
        full_reveals.push(FullReveal::new(
            file.file_id,
            Salt16::from_bytes(*file_salt.expose_bytes_for_test_vectors()),
            s_root,
        ));
    }
    full_reveals.sort_by_key(FullReveal::file_id);

    let (ots_anchors, tsa_anchors, receipt) = anchors(spec.anchors);

    let bundle = BundleV1::new(BundleParts {
        manifest: manifest_bytes,
        storage_record: StorageRecord::new(
            ContentAddress::from_bytes([0x5E; 32]),
            ManifestNonce::from_bytes([0x5A; 24]),
            crate::crypto::material::Key32::from_bytes([0x5C; 32]),
        ),
        ots_anchors,
        tsa_anchors,
        receipt,
        covered_reveals,
        noncovered_reveals,
        touched_files: touched,
        full_reveals,
    })
    .expect("fixture bundle is well formed");

    encode_bundle(&bundle).expect("fixture bundle encodes")
}

fn touches(units: &[PlannedUnit], unit_id: u64, file_id: u64) -> bool {
    units
        .iter()
        .any(|unit| unit.unit_id == unit_id && unit.file_id == file_id)
}

// ---------------------------------------------------------------------------
// anchor artifacts (opaque placeholders until A's M2 recorded fixtures)
// ---------------------------------------------------------------------------

/// The placeholder 80-byte "Bitcoin block header" the D79 upgrade group
/// carries.
///
/// **Deliberately self-labelling ASCII**, zero-padded to the schema's exact
/// 80 bytes: anyone who hexdumps a fixture bundle reads what it is instead of
/// mistaking a synthetic ramp for a recorded header. The format layer
/// enforces only the length (F8); the header's *meaning* is A's, and A swaps
/// in recorded real bytes at M2 with **no schema change** (tasks/F.md F13
/// notes).
pub const FIXTURE_BLOCK_HEADER: [u8; 80] = {
    let label = b"antseal M0 placeholder - NOT a real Bitcoin header";
    let mut header = [0u8; 80];
    let mut i = 0;
    while i < label.len() {
        header[i] = label[i];
        i += 1;
    }
    header
};

/// The placeholder Bitcoin block height an upgraded OTS artifact records.
pub const FIXTURE_BLOCK_HEIGHT: u64 = 900_000;

/// Build the anchor sections for an [`AnchorSet`].
///
/// Every artifact byte string here is a **schema-opaque placeholder**: the M0
/// format layer treats `.ots`, DER tokens, certificates and receipt payloads
/// as opaque `bstr`s by design (F8), and A parses them at M2. What the shapes
/// exercise is the *section structure* — empty versus populated, each
/// optional slot present versus absent.
fn anchors(set: AnchorSet) -> (Vec<OtsAnchor>, Vec<TsaAnchor>, Option<ReceiptRecord>) {
    match set {
        AnchorSet::Empty => (Vec::new(), Vec::new(), None),
        AnchorSet::OneOtsTwoTsa => (
            vec![
                OtsAnchor::new(
                    AnchorStatus::Pending,
                    OpaqueBytes::from_vec(b"fixture .ots artifact".to_vec()),
                    None,
                )
                .expect("fixture .ots is under the D10 caps"),
            ],
            vec![
                TsaAnchor::new(
                    AnchorStatus::Proven,
                    OpaqueBytes::from_vec(b"fixture TSA token A".to_vec()),
                    Vec::new(),
                    FIXTURE_CLAIMED_TIME,
                )
                .expect("fixture TSA anchor is under the D10 caps"),
                TsaAnchor::new(
                    AnchorStatus::Proven,
                    OpaqueBytes::from_vec(b"fixture TSA token B".to_vec()),
                    Vec::new(),
                    FIXTURE_CLAIMED_TIME,
                )
                .expect("fixture TSA anchor is under the D10 caps"),
            ],
            None,
        ),
        AnchorSet::EveryKind { receipt } => (
            vec![
                // The D79 upgrade group present — all three fields or none.
                OtsAnchor::new(
                    AnchorStatus::Attested,
                    OpaqueBytes::from_vec(b"fixture .ots artifact, upgraded".to_vec()),
                    Some(OtsUpgrade::new(
                        FIXTURE_BLOCK_HEIGHT,
                        FIXTURE_BLOCK_HEADER,
                        FIXTURE_CLAIMED_TIME,
                    )),
                )
                .expect("fixture .ots is under the D10 caps"),
                // …and absent, in the same bundle.
                OtsAnchor::new(
                    AnchorStatus::Pending,
                    OpaqueBytes::from_vec(b"fixture .ots artifact, pending".to_vec()),
                    None,
                )
                .expect("fixture .ots is under the D10 caps"),
            ],
            vec![
                // Intermediates present…
                TsaAnchor::new(
                    AnchorStatus::Proven,
                    OpaqueBytes::from_vec(b"fixture TSA token A".to_vec()),
                    vec![
                        OpaqueBytes::from_vec(b"fixture TSA intermediate A1".to_vec()),
                        OpaqueBytes::from_vec(b"fixture TSA intermediate A2".to_vec()),
                    ],
                    FIXTURE_CLAIMED_TIME,
                )
                .expect("fixture TSA anchor is under the D10 caps"),
                // …and absent, so both optional shapes are committed.
                TsaAnchor::new(
                    AnchorStatus::ValidAtStampingCertSinceExpired,
                    OpaqueBytes::from_vec(b"fixture TSA token B".to_vec()),
                    Vec::new(),
                    FIXTURE_CLAIMED_TIME,
                )
                .expect("fixture TSA anchor is under the D10 caps"),
            ],
            receipt.then(|| {
                ReceiptRecord::new(
                    vec![[0xE1; 32], [0xE2; 32]],
                    FIXTURE_BLOCK_NUMBER,
                    OpaqueBytes::from_vec(b"fixture Arbitrum receipt payload (opaque)".to_vec()),
                )
                .expect("fixture receipt has transaction hashes")
            }),
        ),
    }
}

// ---------------------------------------------------------------------------
// the named shapes
// ---------------------------------------------------------------------------

/// One constructor per M0 shape (module-doc table). R7/R9/R10 name a shape
/// rather than re-deriving one, so a shape's bytes can only change here.
pub mod shapes {
    use super::{AnchorSet, FileSelection, FileSpec, Selection, WorkSpec};

    /// Raw bytes whose canonical form differs from them (CRLF), so the file
    /// gets a raw mirror.
    pub const CRLF_TEXT: &[u8] = b"first line\r\nsecond line\r\nthird line\r\n";
    /// Raw bytes carrying a leading BOM.
    pub const BOM_TEXT: &[u8] = b"\xEF\xBB\xBFwith a byte order mark\n";
    /// Raw bytes in NFD (`e` + combining acute), which NFC recomposes.
    pub const NFD_TEXT: &[u8] = b"cafe\xCC\x81 and more\n";
    /// Raw bytes that are already canonical, so no mirror is emitted.
    pub const CANONICAL_TEXT: &[u8] = b"already canonical\nno mirror needed\n";
    /// The **odd-length** CRLF source (R37): 38 raw bytes canonicalizing to
    /// **35**, so `d = 6` and the file tiles into odd-boundary units.
    ///
    /// Every other text constant here canonicalizes to an even length, which
    /// is why no committed fixture produced a `level == d` GGM cover node
    /// before R37 (D83 §1 Fact 2). One odd number unlocks the class.
    pub const ODD_CRLF_TEXT: &[u8] = b"odd length line\r\nsecond\r\nthird piece\r\n";

    /// A single text file with a raw mirror, fine tree, one unit.
    #[must_use]
    pub fn single_text_with_mirror() -> WorkSpec {
        WorkSpec::new(
            "single text with mirror",
            vec![FileSpec::text("notes/intro.md", CRLF_TEXT)],
        )
    }

    /// A single binary file, fine tree, one unit.
    #[must_use]
    pub fn single_binary() -> WorkSpec {
        WorkSpec::new(
            "single binary",
            vec![FileSpec::binary(
                "data/blob.bin",
                (0u8..64).collect::<Vec<u8>>(),
            )],
        )
    }

    /// A `--split` text file: three canonical units plus a raw mirror.
    #[must_use]
    pub fn split_multi_unit() -> WorkSpec {
        // The CRLF source canonicalizes to 34 bytes; split 12 / 12 / 10.
        WorkSpec::new(
            "split multi unit",
            vec![FileSpec::text("notes/split.md", CRLF_TEXT).split(vec![12, 12, 10])],
        )
    }

    /// The **odd-boundary** twin of [`split_multi_unit`] (R37): 35 canonical
    /// bytes split 11 / 11 / 13, plus a raw mirror.
    ///
    /// This is the shape whose *full* reveal ships `level == d` cover nodes.
    /// It is not enough for the file to be odd-length: by D83 §1 Fact 1 a
    /// whole-file cover `[0, n)` is the single root node for **every** `n`,
    /// so an unsplit odd file discloses no leaf-level node at all (except at
    /// `n == 1`). What produces one is an odd **unit** boundary, which is
    /// what D75-BOTH then exposes once per unit — units `[0, 11)` and
    /// `[11, 22)` each contribute one here, at `(6, 10)` and `(6, 11)`,
    /// exactly reproducing D83 §1 Fact 5's `n = 35, split 11/11/13` row.
    #[must_use]
    pub fn odd_split_multi_unit() -> WorkSpec {
        WorkSpec::new(
            "odd split multi unit",
            vec![FileSpec::text("notes/odd-split.md", ODD_CRLF_TEXT).split(vec![11, 11, 13])],
        )
    }

    /// A `--no-fine-tree` text file: one whole-file unit bound by
    /// `unit_commit`.
    #[must_use]
    pub fn no_fine_tree() -> WorkSpec {
        WorkSpec::new(
            "no fine tree",
            vec![FileSpec::text("archive/old.txt", CANONICAL_TEXT).without_fine_tree()],
        )
    }

    /// A BOM-bearing and an NFD-bearing text file — the two other raw-mirror
    /// sources.
    #[must_use]
    pub fn raw_mirror_sources() -> WorkSpec {
        WorkSpec::new(
            "raw mirror sources",
            vec![
                FileSpec::text("mirror/bom.txt", BOM_TEXT),
                FileSpec::text("mirror/nfd.txt", NFD_TEXT),
            ],
        )
    }

    /// An empty file: `size` 0, one empty unit, no fine tree (G4).
    #[must_use]
    pub fn empty_file() -> WorkSpec {
        WorkSpec::new(
            "empty file",
            vec![FileSpec::binary("data/empty.bin", vec![])],
        )
    }

    /// A one-byte file.
    #[must_use]
    pub fn one_byte_file() -> WorkSpec {
        WorkSpec::new(
            "one byte file",
            vec![FileSpec::binary("data/one.bin", vec![0x42])],
        )
    }

    /// A 6-byte fine-tree file — the **unbalanced n = 6** shape (spec
    /// line 153): 6 real leaves on a depth-3 dyadic grid, so the cover is
    /// genuinely ragged.
    #[must_use]
    pub fn unbalanced_n6() -> WorkSpec {
        WorkSpec::new(
            "unbalanced n6",
            vec![FileSpec::binary("data/n6.bin", vec![0, 1, 2, 3, 4, 5]).split(vec![2, 2, 2])],
        )
    }

    /// [`unbalanced_n6`] retiled **2 / 1 / 3** (R37, G24): the same six
    /// leaves on the same `d = 3` grid, with odd unit boundaries.
    ///
    /// Unit 1 is the single leaf `[2, 3)`, whose minimal cover is exactly the
    /// one node `(3, 2)` — G11's own normative KAT (`minimal_cover`'s
    /// doc-test, `verify_range`'s precedence fixture, and D83's committed
    /// proptest counterexample all use it), reachable at **bundle** level for
    /// the first time here. Unit 2 is `[3, 6)`, which contributes `(3, 3)`,
    /// so the work's full reveal carries two leaf-level nodes and its
    /// single-unit reveal carries one.
    #[must_use]
    pub fn unbalanced_n6_odd_split() -> WorkSpec {
        WorkSpec::new(
            "unbalanced n6 odd split",
            vec![FileSpec::binary("data/n6-odd.bin", vec![0, 1, 2, 3, 4, 5]).split(vec![2, 1, 3])],
        )
    }

    /// The multi-file work the pipeline shapes exercise together: a text
    /// file with a mirror, a split binary file, and a `--no-fine-tree` file.
    #[must_use]
    pub fn multi_file() -> WorkSpec {
        WorkSpec::new(
            "multi file",
            vec![
                FileSpec::text("notes/intro.md", CRLF_TEXT),
                FileSpec::binary("data/blob.bin", (0u8..30).collect::<Vec<u8>>())
                    .split(vec![10, 10, 10]),
                FileSpec::text("archive/old.txt", CANONICAL_TEXT).without_fine_tree(),
            ],
        )
    }

    /// [`multi_file`] with anchors attached — the non-empty anchor section.
    #[must_use]
    pub fn multi_file_anchored() -> WorkSpec {
        multi_file().with_anchors(AnchorSet::OneOtsTwoTsa)
    }

    /// [`multi_file`] with **every** anchor kind and optional slot populated,
    /// receipt included (F13).
    #[must_use]
    pub fn multi_file_every_anchor_kind() -> WorkSpec {
        multi_file().with_anchors(AnchorSet::EveryKind { receipt: true })
    }

    /// The receipt-**excluded** twin of [`multi_file_every_anchor_kind`] — a
    /// one-section diff, since receipt presence *is* the sealer's opt-in and
    /// carries no verdict (registry §7.10).
    #[must_use]
    pub fn multi_file_every_anchor_kind_no_receipt() -> WorkSpec {
        multi_file().with_anchors(AnchorSet::EveryKind { receipt: false })
    }

    /// The selection [`multi_file`] is usually built with: file 0 fully
    /// revealed, file 1 partially (its middle unit), file 2 untouched.
    #[must_use]
    pub fn multi_file_mixed_selection() -> Selection {
        Selection(vec![
            FileSelection::Full,
            FileSelection::Units(vec![1]),
            FileSelection::Untouched,
        ])
    }

    /// One entry of the [`catalogue`]: a named work + the reveal selection
    /// that exercises it.
    #[derive(Debug, Clone)]
    pub struct Case {
        /// Stable handle, `"<shape>/<selection>"`.
        ///
        /// Treat it like an error code: R9's committed golden vectors name
        /// cases by this string, so renaming one is a vector edit, not a
        /// refactor.
        pub name: &'static str,
        /// The work to seal.
        pub spec: WorkSpec,
        /// What the reveal shows of it.
        pub selection: Selection,
    }

    /// **The named case catalogue**: every M0 shape paired with the selection
    /// that exercises it.
    ///
    /// Promoted out of R6's own `#[cfg(test)]` list so exactly one definition
    /// of "the M0 shapes" exists. R6's suite iterates it, and R9's `report`
    /// golden vectors resolve their `shape` field through [`by_name`] — on
    /// wasm32 as well as natively, which is why it sits on the `test-vectors`
    /// tier with everything else here.
    ///
    /// Adding a case is additive; **renaming** one breaks a committed vector
    /// by design.
    #[must_use]
    #[allow(clippy::too_many_lines)]
    pub fn catalogue() -> Vec<Case> {
        let case = |name, spec, selection| Case {
            name,
            spec,
            selection,
        };
        vec![
            case(
                "single-text-with-mirror/full",
                single_text_with_mirror(),
                Selection::all(1),
            ),
            case(
                "single-text-with-mirror/full-no-mirror",
                single_text_with_mirror(),
                Selection(vec![FileSelection::FullNoMirror]),
            ),
            case(
                "single-text-with-mirror/untouched",
                single_text_with_mirror(),
                Selection::nothing(1),
            ),
            case("single-binary/full", single_binary(), Selection::all(1)),
            case(
                "split-multi-unit/partial",
                split_multi_unit(),
                Selection(vec![FileSelection::Units(vec![1])]),
            ),
            case(
                "split-multi-unit/partial-two-of-three",
                split_multi_unit(),
                Selection(vec![FileSelection::Units(vec![0, 2])]),
            ),
            case(
                "split-multi-unit/full-via-enumerated-units",
                split_multi_unit(),
                Selection(vec![FileSelection::Units(vec![0, 1, 2])]),
            ),
            // R53 — a *partial* reveal that also reveals the raw mirror: one
            // normal unit of three, plus the mirror. The bundle verifies
            // (mirrors are exempt by kind, D28 rider 1), the mirror unit is
            // AEAD/`unit_commit`-verified like any unit, but rows 9–10 never
            // run for it — so the report must NOT name it as the file's raw
            // mirror (2026-07-31 review finding 8). No valid generator
            // produced this shape before; pinned by the pipeline's
            // `partial_reveal_*` tests.
            case(
                "split-multi-unit/partial-with-mirror",
                split_multi_unit(),
                Selection(vec![FileSelection::UnitsWithMirror(vec![1])]),
            ),
            case(
                "split-multi-unit/all",
                split_multi_unit(),
                Selection::all(1),
            ),
            // R37 — the leaf-level (`level == d`) cover class, which no
            // fixture produced before: 35 canonical bytes split 11/11/13.
            // The full reveal ships one `level == d` node per odd-boundary
            // unit under D75-BOTH; the partial reveal ships one on its own,
            // so the shape is not reachable only through a whole-file
            // disclosure. Asserted directly — never inferred from the file
            // length — by `tests/leaf_level_cover_shapes.rs`.
            case(
                "odd-split-multi-unit/all",
                odd_split_multi_unit(),
                Selection::all(1),
            ),
            case(
                "odd-split-multi-unit/partial",
                odd_split_multi_unit(),
                Selection(vec![FileSelection::Units(vec![1])]),
            ),
            case("no-fine-tree/full", no_fine_tree(), Selection::all(1)),
            case(
                "raw-mirror-sources/all",
                raw_mirror_sources(),
                Selection::all(2),
            ),
            case("empty-file/full", empty_file(), Selection::all(1)),
            case("empty-file/untouched", empty_file(), Selection::nothing(1)),
            case("one-byte-file/full", one_byte_file(), Selection::all(1)),
            case("unbalanced-n6/all", unbalanced_n6(), Selection::all(1)),
            // The three single-unit reveals of the unbalanced n = 6 file.
            // Each unit is two bytes, so each opens a different depth-1 GGM
            // subtree — leaves {0,1}, {2,3}, {4,5}. Taken together they walk
            // every non-palindromic path of the d = 3 grid, which is what
            // pins MSB-first indexing *through the pipeline* (R9) rather
            // than at the tree layer alone (G15).
            case(
                "unbalanced-n6/unit-0",
                unbalanced_n6(),
                Selection(vec![FileSelection::Units(vec![0])]),
            ),
            case(
                "unbalanced-n6/unit-1",
                unbalanced_n6(),
                Selection(vec![FileSelection::Units(vec![1])]),
            ),
            case(
                "unbalanced-n6/unit-2",
                unbalanced_n6(),
                Selection(vec![FileSelection::Units(vec![2])]),
            ),
            // The same six leaves retiled 2/1/3 (R37, G24). Unit 1 is the
            // lone leaf [2, 3), so its cover is the single node (3, 2) —
            // G11's normative KAT, and the shape D83's tamper row names.
            case(
                "unbalanced-n6-odd-split/unit-1",
                unbalanced_n6_odd_split(),
                Selection(vec![FileSelection::Units(vec![1])]),
            ),
            case(
                "unbalanced-n6-odd-split/all",
                unbalanced_n6_odd_split(),
                Selection::all(1),
            ),
            case(
                "multi-file/mixed",
                multi_file(),
                multi_file_mixed_selection(),
            ),
            case("multi-file/all", multi_file(), Selection::all(3)),
            case(
                "multi-file-anchored/mixed",
                multi_file_anchored(),
                multi_file_mixed_selection(),
            ),
            case(
                "ed25519-only-policy/full",
                single_binary().with_ed25519_only_policy(),
                Selection::all(1),
            ),
        ]
    }

    /// Look a [`catalogue`] case up by its stable name.
    ///
    /// Returns `None` for an unknown name rather than panicking: the caller
    /// is a golden-vector executor parsing a committed file, and an unknown
    /// shape there is adversarial-shaped input to be reported, not a bug to
    /// abort on.
    #[must_use]
    pub fn by_name(name: &str) -> Option<Case> {
        catalogue().into_iter().find(|case| case.name == name)
    }
}

#[cfg(test)]
mod tests {
    use super::shapes;
    use super::*;
    use crate::bundle::SealProof;
    use crate::content::ggm::depth_for_leaf_count;
    use crate::verify::{VerifyOptions, verify_bundle};

    fn verify(built: &BuiltFixture) -> crate::verify::VerificationReport {
        match verify_bundle(&built.bytes, &VerifyOptions::new()) {
            Ok(report) => report,
            Err(err) => panic!("fixture must verify, got `{}`: {err}", err.code()),
        }
    }

    /// Every named M0 shape, paired with the selection that exercises it.
    ///
    /// One definition, in [`shapes::catalogue`] — R9's committed golden
    /// vectors resolve the very same names through `shapes::by_name`, so a
    /// shape cannot mean one thing here and another there.
    fn every_shape() -> Vec<(&'static str, WorkSpec, Selection)> {
        shapes::catalogue()
            .into_iter()
            .map(|case| (case.name, case.spec, case.selection))
            .collect()
    }

    /// The catalogue is a lookup table, so its names must be unique, and
    /// [`shapes::by_name`] must find every one of them and nothing else.
    #[test]
    fn the_shape_catalogue_is_a_usable_registry() {
        let catalogue = shapes::catalogue();
        assert!(!catalogue.is_empty());
        let mut names: Vec<&str> = catalogue.iter().map(|case| case.name).collect();
        let count = names.len();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), count, "catalogue names must be unique");
        for case in &catalogue {
            let found = shapes::by_name(case.name).expect("every case resolves by name");
            assert_eq!(found.name, case.name);
            assert_eq!(found.selection, case.selection);
        }
        assert!(shapes::by_name("no-such-shape/never").is_none());
    }

    /// R6's headline: every M0 shape the milestone enumerates builds and
    /// verifies end to end.
    #[test]
    fn every_m0_shape_builds_and_verifies() {
        for (name, spec, selection) in every_shape() {
            let built = build(&spec, &selection);
            let report = match verify_bundle(&built.bytes, &VerifyOptions::new()) {
                Ok(report) => report,
                Err(err) => panic!("shape `{name}` must verify, got `{}`: {err}", err.code()),
            };
            assert!(report.evidence.passed, "shape `{name}` must pass");
            assert_eq!(
                report.evidence.units_verified,
                u64::try_from(built.revealed_unit_ids.len()).expect("small"),
                "shape `{name}` verified a different number of units than it revealed"
            );
        }
    }

    /// Accept bullet 1: seeded runs are byte-reproducible.
    #[test]
    fn fixtures_are_byte_reproducible() {
        for (name, spec, selection) in every_shape() {
            let a = build(&spec, &selection);
            let b = build(&spec, &selection);
            assert_eq!(a.bytes, b.bytes, "shape `{name}` is not reproducible");
        }
    }

    /// …and the seed is genuinely live: it reaches the AEAD nonces, hence
    /// the bytes. Without this, the reproducibility claim above would also
    /// hold for a constructor that ignored the seed entirely.
    #[test]
    fn the_seed_is_live() {
        let selection = Selection::all(1);
        let a = build(&shapes::single_binary().with_seed(1), &selection);
        let b = build(&shapes::single_binary().with_seed(2), &selection);
        assert_ne!(a.bytes, b.bytes, "the seed must reach the bundle bytes");
        // Both still verify — a different seed is a different honest seal.
        verify(&a);
        verify(&b);
    }

    /// The empty-anchor (UNANCHORED) bundle yields an empty anchor list; the
    /// populated one yields one slot per embedded artifact (the M0 stub).
    #[test]
    fn anchor_sections_round_trip_to_the_report() {
        let unanchored = build(&shapes::multi_file(), &shapes::multi_file_mixed_selection());
        assert!(verify(&unanchored).anchors.is_empty());

        let anchored = build(
            &shapes::multi_file_anchored(),
            &shapes::multi_file_mixed_selection(),
        );
        assert_eq!(verify(&anchored).anchors.len(), 3);
    }

    // -----------------------------------------------------------------
    // Accept bullet 3 — structural isolation of partial reveals
    // -----------------------------------------------------------------

    /// The revealed **normal**-unit byte ranges of one file, in the tiling
    /// domain — what a leaf-exact cover may legitimately span.
    fn revealed_leaf_ranges(built: &BuiltFixture, file: &FileFacts) -> Vec<(u64, u64)> {
        let proof = SealProof::decode(&built.bytes).expect("fixture decodes");
        let body = proof.manifest().body();
        let entry = &body.files()[usize::try_from(file.file_id).expect("small")];
        entry
            .units()
            .iter()
            .filter(|unit| {
                unit.kind() == UnitKind::Normal && built.revealed_unit_ids.contains(&unit.unit_id())
            })
            .map(|unit| (unit.range().start(), unit.range().length()))
            .collect()
    }

    /// Accept bullet 3, part 1: a file that is not fully revealed gets
    /// **no** `file_salt` and **no** `s_root` — asserted over the decoded
    /// bundle, not over the builder's intent.
    #[test]
    fn partial_reveals_disclose_no_full_reveal_material() {
        for (name, spec, selection) in every_shape() {
            let built = build(&spec, &selection);
            let proof = SealProof::decode(&built.bytes).expect("fixture decodes");
            for file in &built.files {
                let material = proof
                    .bundle()
                    .full_reveals()
                    .iter()
                    .find(|full| full.file_id() == file.file_id);
                if file.fully_revealed {
                    assert!(
                        material.is_some(),
                        "shape `{name}` file {} is fully revealed but carries no material",
                        file.file_id
                    );
                } else {
                    assert!(
                        material.is_none(),
                        "shape `{name}` LEAKED full-reveal material for the partially revealed \
                         file {}",
                        file.file_id
                    );
                }
            }
        }
    }

    /// Accept bullet 3, part 2: **no disclosed GGM seed is an ancestor of an
    /// unrevealed leaf** (MVP-SPEC.md line 96) — checked by recomputing each
    /// cover node's real-leaf span from its `(level, index)` address and
    /// requiring it to lie inside a revealed range.
    #[test]
    fn no_disclosed_cover_seed_is_an_ancestor_of_an_unrevealed_leaf() {
        for (name, spec, selection) in every_shape() {
            let built = build(&spec, &selection);
            let proof = SealProof::decode(&built.bytes).expect("fixture decodes");
            let body = proof.manifest().body();

            for reveal in proof.bundle().covered_reveals() {
                let file_index = body
                    .files()
                    .iter()
                    .position(|file| {
                        file.units()
                            .iter()
                            .any(|unit| unit.unit_id() == reveal.unit_id())
                    })
                    .expect("every covered reveal names a manifest unit");
                let file = &built.files[file_index];
                let depth =
                    depth_for_leaf_count(file.size).expect("a covered file has at least one leaf");
                let revealed = revealed_leaf_ranges(&built, file);

                for entry in reveal.cover() {
                    let address = entry.address();
                    let span = 1u64 << (depth - address.level());
                    let start = address.index() * span;
                    // Real leaves only: the dyadic grid is padded up to 2^d,
                    // and phantom leaves >= n disclose nothing.
                    let end = (start + span).min(file.size);
                    assert!(
                        start < end,
                        "shape `{name}`: cover node ({}, {}) spans no real leaf",
                        address.level(),
                        address.index()
                    );
                    assert!(
                        revealed
                            .iter()
                            .any(|(r_start, r_len)| start >= *r_start && end <= r_start + r_len),
                        "shape `{name}`: cover node ({}, {}) spans real leaves [{start}, {end}), \
                         which are NOT all revealed — that seed opens an unrevealed leaf",
                        address.level(),
                        address.index()
                    );
                }
            }
        }
    }

    /// Accept bullet 4 (hygiene): nothing a fixture builds leaks the master
    /// secret, an unrevealed unit's key, or an untouched file's salts into
    /// the committed bundle bytes.
    #[test]
    fn no_secret_beyond_the_disclosure_appears_in_the_bytes() {
        let built = build(&shapes::multi_file(), &shapes::multi_file_mixed_selection());
        let contains = |needle: &[u8]| {
            built
                .bytes
                .windows(needle.len())
                .any(|window| window == needle)
        };

        assert!(!contains(&TEST_MASTER_SECRET_W), "W reached the bundle");

        // File 2 is untouched: none of its derived material may appear.
        let untouched = FileId(2);
        assert!(!contains(derive_path_salt(w(), untouched).as_bytes()));
        assert!(!contains(
            derive_file_salt(w(), untouched).expose_bytes_for_test_vectors()
        ));
        assert!(!contains(derive_fine_seed(w(), untouched).as_bytes()));

        // File 1's withheld units keep their keys: the mixed selection shows
        // only its middle unit.
        let withheld: Vec<u64> = built.files[1]
            .normal_unit_ids
            .iter()
            .copied()
            .filter(|unit_id| !built.revealed_unit_ids.contains(unit_id))
            .collect();
        assert!(!withheld.is_empty(), "file 1 must be partially revealed");
        for unit_id in withheld {
            assert!(
                !contains(derive_unit_key(w(), UnitId(unit_id)).as_bytes()),
                "k_u for unrevealed unit {unit_id} reached the bundle"
            );
        }
    }

    /// The fixture's own `Debug` renders lengths, never bytes (project
    /// rule 6's hygiene discipline).
    #[test]
    fn debug_renders_lengths_not_bytes() {
        let built = build(&shapes::single_binary(), &Selection::all(1));
        let rendered = format!("{built:?}");
        assert!(rendered.contains(" B>"), "{rendered}");
    }

    // -----------------------------------------------------------------
    // R30 — the report's native<->wasm32 byte-match over CONSTRUCTED
    // bundles
    // -----------------------------------------------------------------
    //
    // R9 pins the same property over *committed* vectors, for the 21 of the
    // catalogue's shapes its own document names (adding a shape here never
    // moves that vector — `tests/report_vectors.rs`'s `CASES` says so). This is the constructed half,
    // and it asserts over `shapes::catalogue()` **directly**, so a shape
    // added to R6 is covered from the moment it exists rather than at the
    // next vector re-emit (R9's rider on R30).
    //
    // Why a pinned table is the mechanism. This module's tests run on both
    // targets — natively via `cargo test -p antseal-core`, and on wasm32
    // via the `wasm32-core-tests` lane's `cargo test -p antseal-core --lib
    // --target wasm32-unknown-unknown`. Nothing carries a value *between*
    // those two runs, so "the same test passed twice" proves only that each
    // target agrees with itself. The committed digest is the carrier: both
    // lanes check the constructed bytes against one number in the source,
    // so a platform divergence turns exactly one lane red with a message
    // naming the shape — diagnosed once, not twice (R30 accept bullet 2).

    /// Domain tag for R30's per-shape report digest. Deliberately its own
    /// domain: this is not a golden-vector recomputation and must not
    /// collide with `vectors::RECOMPUTED_DIGEST_DOMAIN`, nor with any tag
    /// in the C1 registry (this is test infrastructure, not wire format).
    const R30_REPORT_DIGEST_DOMAIN: &[u8] = b"antseal/test-util/r30/report-bytes/v1\x00";

    /// `SHA-256(domain || len(name) || name || len(report) || report)`.
    ///
    /// The shape name is bound in so a table row cannot be silently
    /// reassigned to a different shape, and both fields are
    /// length-prefixed so no two (name, bytes) pairs can collide by
    /// concatenation.
    fn report_bytes_digest(name: &str, report: &[u8]) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut digest = Sha256::new();
        digest.update(R30_REPORT_DIGEST_DOMAIN);
        digest.update(crate::test_util::vectors::prefix_len(name.len()));
        digest.update(name.as_bytes());
        digest.update(crate::test_util::vectors::prefix_len(report.len()));
        digest.update(report);
        digest.finalize().into()
    }

    /// The canonical report bytes every `shapes::catalogue()` entry
    /// produces, digested — the value native and wasm32 must both compute.
    ///
    /// Regenerate with
    /// `cargo test -p antseal-core --features test-util --lib -- --ignored
    /// emit_r30_report_digest_table --nocapture` and paste the output here.
    /// Adding a catalogue shape without adding its row is a **failure**,
    /// not a silent gap — that is the coverage the rider asked for.
    ///
    /// These are digests of report bytes, so they are hiding by
    /// construction; the test additionally scans the preimages for the
    /// work's secret material (R30 accept bullet 3).
    static REPORT_DIGEST_BY_SHAPE: &[(&str, &str)] = &[
        // @generated — see emit_r30_report_digest_table
        (
            "single-text-with-mirror/full",
            "88f231daea7fc5f298812f24280a76f66c94386d8c6b3cd74ec70764e7b9dde6",
        ),
        (
            "single-text-with-mirror/full-no-mirror",
            "38f2d2313b53124bbddec51bef4b953ff5683910d2763506b25e8513af712067",
        ),
        (
            "single-text-with-mirror/untouched",
            "b522cb7d28615ea2f98beea01af414434b1c7c3fd3dadd206105324b4346b42d",
        ),
        (
            "single-binary/full",
            "8d4681e61e4c814476162828447976b3851d0625fd9498c9e2e133c8f2d61bec",
        ),
        (
            "split-multi-unit/partial",
            "995286f5fd97e380c65c3638a71acd743c68098b3df9cfaa3a039df9572beb6e",
        ),
        (
            "split-multi-unit/partial-two-of-three",
            "7daca40444946e441e296fef8d84ab579c34e5e1c21eb3ed0e82640a1f3c1663",
        ),
        (
            "split-multi-unit/full-via-enumerated-units",
            "88e484564ec77d38fd5c1cd750469b50203e5bd5b834be187c4f602205f5e0d7",
        ),
        (
            "split-multi-unit/partial-with-mirror",
            "35543a07eceebc7a01d203fe8280c5afdc65f186fa2214ae2077d4c64f5deb19",
        ),
        (
            "split-multi-unit/all",
            "36790a0147430d67ea3ac09ba62d20c55b0959b4d340ff3478a8d3297bf20d3b",
        ),
        (
            "odd-split-multi-unit/all",
            "fd2d0e230820bdcc7696ec307e3acd68c587f97c006453bc039c6d7895095c33",
        ),
        (
            "odd-split-multi-unit/partial",
            "308f4977d8d60a9d3429e1c3f4954a68a21060ae6e311a3e575d8044a3c87025",
        ),
        (
            "no-fine-tree/full",
            "e1c790e17196ac4ea1827c5e5759a9c829bace88f49012cda3e6c91c2769b3f8",
        ),
        (
            "raw-mirror-sources/all",
            "e8e575cccfd7ec6f41979279ce627ef92cd79251384b03cd41ef974d31bb1cf1",
        ),
        (
            "empty-file/full",
            "10f4dfc71956c3b3c61fcfd8d21fd018d728459e0d86024de6ac33ecbe12d3d9",
        ),
        (
            "empty-file/untouched",
            "f0ed4edf307aefe397d60ea9fdd867278332e767320dadfb698457d5d9deb86f",
        ),
        (
            "one-byte-file/full",
            "252db121e3c27207a89a3fd3c8888f7596e66f56479d7fc2bb0af3b28f203d51",
        ),
        (
            "unbalanced-n6/all",
            "e5b32940cf661a2fe38478400d094950e633c700ada7a7b30b7f8202323e292c",
        ),
        (
            "unbalanced-n6/unit-0",
            "3b35bb7852ba6e3e8db728b5720e8cd3ae434138f23b3ed6880301875fd00061",
        ),
        (
            "unbalanced-n6/unit-1",
            "463812337fb4a916d7272c752635f6e0bec90b4dec7736efdb01da8bcf5b2811",
        ),
        (
            "unbalanced-n6/unit-2",
            "5e6d96f0c17321e4719f1fccf5e7f3a2d6f80a8f0d56b5e27da7ad648fcaf543",
        ),
        (
            "unbalanced-n6-odd-split/unit-1",
            "44029b3a35bcf3e7ad41bf4278db0a3e08711851c27a8aae353a79a4d9f2267f",
        ),
        (
            "unbalanced-n6-odd-split/all",
            "d610bf71358b2b714aa93425fc4ca8dc63b0a5c58813d8c527979fa8cff79781",
        ),
        (
            "multi-file/mixed",
            "2020bc38330c40fd10d563d98dd38f1966f7e61d2684b849fb02b1ab66e93c74",
        ),
        (
            "multi-file/all",
            "37050d92f4d0e3fa1db6c04ebbdc9b721742e55e3ea29094a2928e3c5d07a9a5",
        ),
        (
            "multi-file-anchored/mixed",
            "e450be7356404a79b8bd90733c17821f063879004f399bf734a97174137bff8e",
        ),
        (
            "ed25519-only-policy/full",
            "ddbdb0c96529f346970f05e115771daca79ec3359fac830bf7ed7ec564bc959a",
        ),
    ];

    /// R30: every named R6 shape's canonically-serialized
    /// `VerificationReport` is byte-identical on native and wasm32, pinned
    /// per shape, and carries no secret material.
    #[test]
    fn every_shape_report_matches_its_pinned_bytes_on_every_target() {
        let catalogue = shapes::catalogue();
        assert!(!catalogue.is_empty(), "the catalogue is empty");

        let pinned: std::collections::BTreeMap<&str, &str> =
            REPORT_DIGEST_BY_SHAPE.iter().copied().collect();
        assert_eq!(
            pinned.len(),
            REPORT_DIGEST_BY_SHAPE.len(),
            "REPORT_DIGEST_BY_SHAPE has a duplicate shape name"
        );

        let mut seen = 0usize;
        for case in catalogue {
            let name = case.name;
            let built = build(&case.spec, &case.selection);
            let report = verify(&built);
            let bytes = report
                .to_canonical_json()
                .unwrap_or_else(|e| panic!("shape `{name}`: report must encode: {e}"));

            // Accept bullet 3: R6's hygiene assertion, extended from one
            // shape's bundle to every shape's REPORT — the bytes this test
            // digests. The report model is normatively secret-free
            // (verify::report module docs); this is the constructed-side
            // check that it stays so for every shape that exists.
            let contains = |needle: &[u8]| {
                !needle.is_empty() && bytes.windows(needle.len()).any(|win| win == needle)
            };
            assert!(
                !contains(&TEST_MASTER_SECRET_W),
                "shape `{name}`: W reached the report"
            );
            for file in &built.files {
                let file_id = FileId(file.file_id);
                assert!(
                    !contains(derive_path_salt(w(), file_id).as_bytes()),
                    "shape `{name}`: path_salt for file {} reached the report",
                    file.file_id
                );
                assert!(
                    !contains(derive_fine_seed(w(), file_id).as_bytes()),
                    "shape `{name}`: fine seed for file {} reached the report",
                    file.file_id
                );
                assert!(
                    !contains(derive_file_salt(w(), file_id).expose_bytes_for_test_vectors()),
                    "shape `{name}`: file_salt for file {} reached the report",
                    file.file_id
                );
                for unit_id in file.normal_unit_ids.iter().chain(&file.mirror_unit_id) {
                    assert!(
                        !contains(derive_unit_key(w(), UnitId(*unit_id)).as_bytes()),
                        "shape `{name}`: k_u for unit {unit_id} reached the report"
                    );
                }
            }

            let actual = crate::test_util::vectors::hex(&report_bytes_digest(name, &bytes));
            let expected = pinned.get(name).copied().unwrap_or_else(|| {
                panic!(
                    "shape `{name}` has no pinned report digest. A new R6 shape is covered by \
                     R30 from the moment it exists: add its row to REPORT_DIGEST_BY_SHAPE with \
                     `cargo test -p antseal-core --features test-util --lib -- --ignored \
                     emit_r30_report_digest_table --nocapture`"
                )
            });
            assert_eq!(
                actual,
                expected,
                "shape `{name}`: the canonical report bytes are not the pinned ones \
                 ({} B). Native and wasm32 both check this number, so one of THREE things \
                 happened and the re-pin must name which (D94 §2a): the report byte format \
                 changed (a FORMAT EVENT — every shape moves, and it costs a \
                 `REPORT_VERSION` bump); the verifier now computes a different VALUE for \
                 this shape under an unchanged format (a VERDICT EVENT — re-pin, no version \
                 bump, and R12 was the first); or this target diverged from the other \
                 (MVP-SPEC.md lines 167/169). If more shapes moved than the change \
                 accounts for, suspect a D84 rule F2 breach and fix the code rather than \
                 the table — this is the only test of F2's blast radius the tree has",
                bytes.len()
            );
            seen += 1;
        }

        assert_eq!(
            seen,
            REPORT_DIGEST_BY_SHAPE.len(),
            "REPORT_DIGEST_BY_SHAPE pins a shape the catalogue no longer has — a stale row \
             would silently stop asserting anything"
        );
    }

    /// Regenerate [`REPORT_DIGEST_BY_SHAPE`]. **Ignored by default**: a
    /// re-pin is a deliberate act with a byte-format consequence, never a
    /// side effect of running the suite.
    #[test]
    #[ignore = "prints the R30 digest table; run deliberately when a shape is added or the report bytes change"]
    fn emit_r30_report_digest_table() {
        for case in shapes::catalogue() {
            let built = build(&case.spec, &case.selection);
            let bytes = verify(&built)
                .to_canonical_json()
                .unwrap_or_else(|e| panic!("shape `{}`: {e}", case.name));
            println!(
                "        ({:?}, {:?}),",
                case.name,
                crate::test_util::vectors::hex(&report_bytes_digest(case.name, &bytes))
            );
        }
    }

    // -----------------------------------------------------------------
    // Accept bullet 2 — the property test
    // -----------------------------------------------------------------

    #[cfg(feature = "test-util")]
    mod properties {
        use super::*;
        use crate::test_util::proptest::prelude::*;
        use crate::test_util::strategies::proptest_config;

        /// The tiling-domain size a spec resolves to — needed to build a
        /// split that actually tiles.
        fn tiling_size(spec: &FileSpec) -> u64 {
            let (planned, _) = super::super::plan_file(0, spec);
            u64::try_from(planned.tiling.len()).expect("small")
        }

        /// How many **normal** units a spec resolves to.
        fn normal_unit_count(spec: &FileSpec) -> usize {
            super::super::plan_file(0, spec)
                .1
                .iter()
                .filter(|(kind, ..)| *kind == UnitKind::Normal)
                .count()
        }

        /// A synthetic file: raw bytes, kind, fine-tree opt-out, split.
        fn file_spec(index: usize) -> impl Strategy<Value = FileSpec> {
            (
                prop::collection::vec(any::<u8>(), 0..40usize),
                any::<bool>(),
                any::<bool>(),
                any::<bool>(),
            )
                .prop_map(move |(raw, binary, no_tree, split)| {
                    // A text spec's source is drawn from a small alphabet
                    // that is always valid UTF-8 and that regularly needs
                    // canonicalizing (CR/LF), so the mirror path is
                    // genuinely exercised; a binary spec takes the bytes
                    // exactly as drawn.
                    let spec = if binary {
                        FileSpec::binary(&format!("data/f{index}.bin"), raw)
                    } else {
                        let text: Vec<u8> = raw
                            .iter()
                            .map(|byte| match byte % 4 {
                                0 => b'\r',
                                1 => b'\n',
                                2 => b'a',
                                _ => b' ',
                            })
                            .collect();
                        FileSpec::text(&format!("notes/f{index}.txt"), text)
                    };
                    let spec = if no_tree {
                        spec.without_fine_tree()
                    } else {
                        spec
                    };
                    if !split {
                        return spec;
                    }
                    let size = tiling_size(&spec);
                    if size < 2 {
                        spec
                    } else {
                        spec.split(vec![size / 2, size - size / 2])
                    }
                })
        }

        fn work() -> impl Strategy<Value = WorkSpec> {
            (1usize..4usize, any::<u64>()).prop_flat_map(|(count, seed)| {
                let files: Vec<_> = (0..count).map(file_spec).collect();
                files.prop_map(move |files| WorkSpec::new("property work", files).with_seed(seed))
            })
        }

        /// A **valid** selection for `spec`: every named unit index exists.
        fn selection_for(spec: &WorkSpec) -> impl Strategy<Value = Selection> + use<> {
            let per_file: Vec<BoxedStrategy<FileSelection>> = spec
                .files
                .iter()
                .map(|file| {
                    let normals = normal_unit_count(file).max(1);
                    prop_oneof![
                        Just(FileSelection::Untouched),
                        Just(FileSelection::Full),
                        Just(FileSelection::FullNoMirror),
                        prop::collection::vec(0..normals, 0..=normals).prop_map(|mut picks| {
                            picks.sort_unstable();
                            picks.dedup();
                            FileSelection::Units(picks)
                        }),
                    ]
                    .boxed()
                })
                .collect();
            per_file.prop_map(Selection)
        }

        /// Q3's shared config with a **lowered** local case count.
        ///
        /// Every case here builds *and* fully verifies a hybrid-signed
        /// bundle; unoptimized ML-DSA-65 keygen + signing dominates, at
        /// roughly 100 ms per case in a debug test build. 64 cases keeps the
        /// suite responsive locally while CI still explores far more —
        /// `PROPTEST_CASES` **overrides** a hardcoded `cases` (C18's
        /// finding), so raising it in the `test` lane works exactly as it
        /// does for every other suite. Nothing here is a spec-mandated
        /// floor, so lowering the local default costs no coverage guarantee.
        fn config() -> ProptestConfig {
            ProptestConfig {
                cases: 64,
                ..proptest_config(0x5EED_0006)
            }
        }

        proptest! {
            #![proptest_config(config())]

            /// **R6 Accept bullet 2** — the M0 early form of R14's guarantee:
            /// for randomized synthetic works crossed with randomized *valid*
            /// selections, every constructed bundle passes `verify_bundle`.
            #[test]
            fn every_constructed_bundle_verifies(
                (spec, selection) in work().prop_flat_map(|spec| {
                    let selection = selection_for(&spec);
                    (Just(spec), selection)
                })
            ) {
                let built = build(&spec, &selection);
                match verify_bundle(&built.bytes, &VerifyOptions::new()) {
                    Ok(report) => prop_assert!(report.evidence.passed),
                    Err(err) => prop_assert!(
                        false,
                        "constructed bundle failed with `{}`: {err}",
                        err.code()
                    ),
                }
            }

            /// Isolation holds over randomized works too, not just the named
            /// shapes: no file short of a full reveal carries material.
            #[test]
            fn randomized_partial_reveals_never_leak_material(
                (spec, selection) in work().prop_flat_map(|spec| {
                    let selection = selection_for(&spec);
                    (Just(spec), selection)
                })
            ) {
                let built = build(&spec, &selection);
                let proof = SealProof::decode(&built.bytes).expect("fixture decodes");
                for file in &built.files {
                    let has_material = proof
                        .bundle()
                        .full_reveals()
                        .iter()
                        .any(|full| full.file_id() == file.file_id);
                    prop_assert_eq!(has_material, file.fully_revealed);
                }
            }
        }
    }
}
