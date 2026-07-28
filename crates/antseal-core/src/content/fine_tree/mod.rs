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
//! | — | [`error`] | the shared `fine-root-*` failure taxonomy (R2's seam) |
//! | — | `ggm_walk` | the amortized sequential salt walker G9/G12/G13 share |
//!
//! G11 (leaf-exact cover), G12 (range-proof generation) and G13
//! (range-proof verification) land as further modules here; the taxonomy and
//! the walker are already shaped for them.
//!
//! # The one rule everything here exists to enforce
//!
//! > **Normative: the cover MUST be leaf-exact** … a merely-valid dyadic
//! > cover whose node spans an unrevealed real leaf `j < n` would disclose
//! > `salt_j` and reopen the per-byte confirmation attack; **no seed that is
//! > an ancestor of any unrevealed leaf ever leaves the vault**
//! > (MVP-SPEC.md line 96)
//!
//! # WASM-safety and determinism
//!
//! Everything is pure, deterministic and allocation-bounded: no I/O, no
//! clocks, no randomness, no float. Auxiliary memory during construction is
//! `O(log n)`; a range opening's memory is `O(log n)` plus the revealed bytes
//! the caller already holds.

pub mod build;
pub mod error;
mod ggm_walk;

pub use build::{FineRoot, FineTreeBuilder, FineTreeStats, rebuild_fine_root};
pub use error::FineTreeError;
