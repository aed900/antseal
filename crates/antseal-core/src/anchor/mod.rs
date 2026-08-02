//! Anchor verification — **all of it**, and all of it WASM-safe.
//!
//! MVP-SPEC.md line 47–53 and line 106 put the network side in
//! `antseal-anchor` and **every** anchor *verification* step in
//! `antseal-core`: RFC 3161 `TimeStampResp`/`TSTInfo` parse + verify against
//! a pinned TSA root store, `.ots` parse + op execution + embedded-header
//! check, and the per-anchor verdict. Nothing under this module may read a
//! clock, a socket or a file: verification time is an explicit parameter and
//! online results arrive as data ([`model::OnlineEvidence`]).
//!
//! At M2 the module holds:
//!
//! - [`model`] (task **A2**) — the artifact and verdict data model: what a
//!   verifier is entitled to read out of a bundle's anchor sections, the
//!   per-anchor verdict datum over the frozen seven states, the online
//!   evidence a host feeds in, and the capture records U persists in the
//!   vault.

pub mod model;
pub mod ots;
