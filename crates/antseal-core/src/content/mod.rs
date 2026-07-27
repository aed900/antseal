//! The content model (tasks/G.md) — how a work's files are described,
//! divided into units, and salted for byte-range commitment.
//!
//! Everything here is pure, deterministic, allocation-bounded, and WASM-safe:
//! no I/O, no clocks, no randomness. Bytes arrive from the caller (S reads
//! files; R reads bundles), decisions come back.
//!
//! Module layout:
//!
//! - [`descriptor`] (G4) — the per-file canonicalization descriptor: kind,
//!   fine-tree presence, its byte domain, and the frozen Unicode data version
//!   (MVP-SPEC.md line 83), with the seal-time decision logic and the
//!   decode-time cross-field validation predicate.
//! - [`unit`] (G5) — the unit model: work-global `unit_id` assignment in
//!   manifest order (MVP-SPEC.md line 76), the file-table `size` semantics
//!   (line 98), and the `is_fine_tree_covered` predicate that decides whether a
//!   unit carries its own `unit_commit` (line 94).
//! - [`ggm`] (G8) — the GGM salt tree: `s_root` → per-leaf 16-byte salts over a
//!   complete depth-`d` dyadic grid, with the canonical node-address type
//!   shared by covers and boundary paths (MVP-SPEC.md line 96).
//! - [`error`] — the `content-`-coded error taxonomy these three share.
//!
//! # Where the boundaries are
//!
//! - **C** supplies the inputs: `s_root = HKDF(W, "fine-seed", file_id)`, the
//!   `0x06` domain tag, and the SHA-256 primitive. This module never derives
//!   from `W` itself.
//! - **F** owns every wire encoding. The semantic field sets and their legality
//!   rules live here; the CBOR spellings live in
//!   `docs/format/registry-v1.md`.
//! - **R** owns verdicts. This module supplies predicates and distinct errors;
//!   it never decides that a bundle is invalid.

pub mod descriptor;
pub mod error;
pub mod ggm;
pub mod unit;

pub use descriptor::{CanonDescriptor, ContentKind, FileKind, FineTreeDomain, FineTreeOptOut};
pub use error::ContentError;
pub use ggm::{ChildBit, NodeAddress, SaltTree, child_seed, depth_for_leaf_count};
pub use unit::{
    ByteRange, FileLengths, FileUnitPlan, SplitEligibleText, Unit, UnitKind, assign_unit_ids,
    is_fine_tree_covered, requires_unit_commit,
};
