//! The fine tree (tasks/G.md G9–G13) — the per-byte range commitment that is
//! the **sole** content commitment of a fine-tree-covered file
//! (MVP-SPEC.md lines 85, 94, 96, 114, 118, 121).
//!
//! # The chain
//!
//! | task | module | what it owns |
//! | --- | --- | --- |
//! | G8 | [`ggm`](super::ggm) | `s_root` → per-leaf 16-byte salts on the depth-`d` dyadic grid |
//! | G9 | [`build`] | streaming construction with O(log n) memory; [`rebuild_fine_root`] |
//! | G10 | [`cost`] | the seal-time cost estimate `seal` prints for large files |
//! | G11 | [`cover`] | the leaf-exact minimal GGM sub-cover, and the only seed-disclosure path |
//! | G12 | [`proof`] | range-proof generation; per-unit reveals as leaf-aligned ranges |
//! | G13 | [`verify`](mod@verify) | range-proof verification against `fine_root`, defensively |
//! | — | [`error`] | the shared `fine-root-*` failure taxonomy (R2's seam) |
//! | — | `ggm_walk` | the amortized sequential salt walker G9/G12/G13 share |
//!
//! # The one rule everything here exists to enforce
//!
//! > **Normative: the cover MUST be leaf-exact** … a merely-valid dyadic
//! > cover whose node spans an unrevealed real leaf `j < n` would disclose
//! > `salt_j` and reopen the per-byte confirmation attack; **no seed that is
//! > an ancestor of any unrevealed leaf ever leaves the vault**
//! > (MVP-SPEC.md line 96)
//!
//! It is enforced twice, in opposite directions:
//!
//! - **By construction, on the prover side.** [`LeafExactCover`] is the only
//!   type [`cover_seeds`] will derive seeds for, and the only way to obtain
//!   one is [`minimal_cover`], which emits a node only when the node's
//!   *real*-leaf span lies wholly inside the revealed range. `s_root` is
//!   released **iff** the range is `[0, n)` — a consequence of that rule,
//!   not a separate check.
//! - **By rejection, on the verifier side** (G13) — the recomputed cover is
//!   compared against the offered one, and anything spanning an unrevealed
//!   real leaf is [`FineTreeError::OverBroadCover`], its own permanent code
//!   and its own tamper row.
//!
//! # WASM-safety and determinism
//!
//! Everything is pure, deterministic and allocation-bounded: no I/O, no
//! clocks, no randomness, no float. Auxiliary memory during construction is
//! `O(log n)`; a range opening's memory is `O(log n)` plus the revealed bytes
//! the caller already holds.

pub mod build;
pub mod cost;
pub mod cover;
pub mod error;
mod ggm_walk;
pub mod proof;
pub mod verify;

pub use build::{FineRoot, FineTreeBuilder, FineTreeStats, rebuild_fine_root};
pub use cost::{CostEstimate, estimate_fine_tree_cost};
pub use cover::{CoverEntry, CoverNode, LeafExactCover, cover_seeds, minimal_cover};
pub use error::FineTreeError;
pub use proof::{BoundaryNode, CoveredUnit, RangeProof, WireNode, prove_range, prove_unit};
pub use verify::{RangeProofView, verify_range};
