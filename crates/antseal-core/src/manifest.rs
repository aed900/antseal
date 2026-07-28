//! The v1 manifest: body schema (F5), envelope codec (F6), and the two
//! identity digests `work_id` / `anchor_digest` (F7).
//!
//! MVP-SPEC.md lines 73–75 (Definitions & encoding), 90 (`seal_id`),
//! 91–98 (unit/file/body fields), 100 (binding assumption). Key numbers,
//! types, presence rules, and exact lengths come from the v1 wire
//! registry, `docs/format/registry-v1.md` (+ its machine mirror
//! `registry-v1.json`); [`registry`] is the code side of that table and
//! `crates/antseal-core/tests/format_registry_draft.rs` asserts the two
//! agree 1:1.
//!
//! ```text
//! Manifest (envelope)          {0: body-as-bstr, 1: signatures}
//!   └── ManifestBodyV1         {0: format_version … 7: files}
//!         └── FileEntry        {0: path_commit … 6: units}
//!               ├── CanonDescriptor   {0: kind … 3: unicode_version}
//!               └── UnitEntry         {0: unit_id … 6: address}
//! ```
//!
//! # Who rejects what (the three-layer split)
//!
//! 1. **F3, [`crate::codec::decode`]** — CBOR canonicality (spec line 73):
//!    definite lengths, shortest-form heads, strictly ascending map keys,
//!    no floats/simples/tags, no trailing bytes, valid UTF-8. Every read
//!    this module performs goes through that strict reader, so the schema
//!    decode *is* a canonicality pass — there is no skipped subtree and
//!    no second walk.
//! 2. **F5/F6, this module** — schema *shape*: the key set of every map
//!    (unknown vs reserved slot), item types, exact byte lengths,
//!    conditional presence (the iff-rules of spec lines 94/98), closed
//!    enum values, `sig_policy` well-formedness (spec line 97), non-empty
//!    containers, and the stored-`unit_id` ↔ manifest-order equality.
//! 3. **R (verify)** — *semantic* invariants over an already-well-formed
//!    body (MVP-SPEC.md line 121). These are deliberately **not** parse
//!    rules:
//!    - per-file tiling of the non-mirror units over `[0, size)` — sorted,
//!      gapless, non-overlapping, in-bounds;
//!    - `true_length` = byte-range width (the wire carries both
//!      independently *so that* the tamper row "`true_length` ≠ range
//!      width" is expressible — registry §4);
//!    - `start + length` overflow at the point the exclusive end is formed
//!      ([`ByteRange::end_exclusive`] returns `None` rather than wrapping);
//!    - present-signature-set = `sig_policy` set and pubkey-set = policy
//!      set (C14/R5 — the parse layer checks each map's *own* shape only);
//!    - leaf-exact GGM covers, partial-reveal isolation, and every
//!      commitment opening.
//!
//!    The boundary rule: **this module answers "is this a well-formed v1
//!    manifest?", never "is it true?"**. A schema-valid body may still be
//!    a lie; that is what the verifier is for (the sealer is an adversary,
//!    spec line 121).
//!
//! # Construction is validation
//!
//! A schema-invalid [`ManifestBodyV1`] cannot exist: every field is
//! private and both construction paths — [`ManifestBodyV1::new`] (seal
//! side) and [`ManifestBodyV1::decode`] (verify side) — funnel through the
//! same `validate` pass, so "constructible" and "decodable" are the same
//! predicate. Several rules are stronger still: they are unrepresentable
//! rather than checked (see [`body::CanonMode`], [`body::FineTree`], and
//! [`crate::crypto::disclosure::UnitBinding`], which carries `unit_commit`
//! iff the unit is non-covered).
//!
//! # Wire integers are `u64`
//!
//! No `usize` appears in any wire-facing type, error payload, or length
//! check (R2 finding, flagged for F5). Sizes, offsets, ranges, ids, and
//! byte counts are `u64` on the wire and `u64` in Rust, so decode results
//! and error values are identical on wasm32 and on 64-bit natives — a
//! precondition for the WASM↔native bit-match requirement.
//!
//! # Raw-mirror placement (D23)
//!
//! A file's raw mirror is its **last** unit
//! (`docs/decisions/D23-raw-mirror-placement.md`). That is a *seal-side
//! construction* rule: [`crate::manifest`] documents and
//! [`body::FileEntry::raw_mirror`] exposes it, but parse does **not**
//! enforce position — per D23 the verifier identifies mirrors by `kind`
//! only, never by position, so a hand-built manifest that misplaces its
//! mirror stays fully checkable (it fails on the substantive checks it
//! actually violates, not on a construction convention).
//!
//! # Secret hygiene (project rule 6)
//!
//! Nothing in the manifest body is secret: it is the plaintext artifact
//! every bundle embeds. Error payloads here carry key numbers, lengths,
//! ids, and closed enum discriminants only — never field *content* — so
//! a malformed body cannot leak the bytes it carried, and the same errors
//! are safe to render in the WASM verifier page.

#![deny(clippy::unwrap_used)]

pub mod body;
pub mod envelope;
pub mod error;
pub mod ids;
pub mod registry;
pub mod sigmap;

// `test-vectors` (implied by `test-util`) — the fixtures are pure constant
// data with no dependencies, so they are part of the WASM-safe tier and
// remain available to the wasm32 `--lib` unit-test build (P14).
#[cfg(feature = "test-vectors")]
pub mod fixtures;

pub use body::{
    ByteRange, CanonDescriptor, CanonMode, ContentAddress, FileEntry, FineTree, ManifestBodyV1,
    Nonce24, UnitEntry, encode_body,
};
pub use envelope::{Manifest, encode_envelope};
pub use error::{
    AlgPosition, CondField, ContainerField, EnumId, FixedLenField, Layer, ManifestError,
};
pub use ids::{AnchorDigest, WorkId, anchor_digest, work_id};
pub use registry::{
    DescriptorKind, FineTreeDomain, KeyClass, MapId, UnitKind, sig_alg_from_wire, sig_alg_to_wire,
};
pub use sigmap::{SigAlgMap, SigMaterial};
