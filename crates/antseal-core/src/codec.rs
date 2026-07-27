//! Deterministic-CBOR codec (tasks F2/F3) — the profile of MVP-SPEC.md
//! line 73.
//!
//! Every hashed, signed, stored, or paid-for byte of the antseal formats
//! flows through this module. The wire profile is **RFC 8949 §4.2.1 Core
//! Deterministic Encoding** narrowed by the spec: definite lengths only,
//! shortest-form integer and length heads, map keys in strictly ascending
//! bytewise order of their encoded form, no floats, no indefinite-length
//! items — and, because the v1 wire registry (F4) admits no simple values
//! and no tags anywhere, those item types are out of schema everywhere and
//! rejected at this layer too.
//!
//! Two halves:
//!
//! - [`encode`] (F2): closure-scoped builders that make non-canonical
//!   output **unrepresentable** — there is no API path that can emit a
//!   float, an indefinite-length item, or an unsorted map, and the only
//!   way to obtain bytes is [`encode::encode_item`], which returns them
//!   only after the whole item closed cleanly.
//! - [`decode`] (F3): a canonicality-enforcing reader that hard-errors,
//!   with one distinct [`decode::DecodeError`] variant per rejection
//!   class of spec line 73, on any input not in canonical form. It is
//!   invoked on outer envelopes (manifest, bundle) and on inner `body`
//!   bstr contents alike — an embedded byte string is opaque to the outer
//!   pass by design, so each layer runs its own strict pass (spec
//!   line 74: verifiers never re-encode).
//!
//! Layer boundaries (who rejects what):
//!
//! - **This module (F3)**: duplicate map keys, non-shortest int heads,
//!   non-shortest length heads, indefinite-length items, out-of-order map
//!   keys, floats / simple values / tags, trailing bytes, invalid UTF-8
//!   in tstr — plus truncation/malformed-head totality so no input can
//!   panic.
//! - **Schema layer (F5/F8)**: unknown/extra map keys in a fixed schema,
//!   presence rules, field lengths — built on this module's typed reader
//!   ([`decode::CanonicalDecoder`] + [`decode::MapReader`]).
//! - **Resource caps (F11)**: byte-size/count/depth cap constants and
//!   their budget tracker. Until F11 freezes them, this module carries a
//!   provisional recursion guard ([`decode::MAX_NESTING_DEPTH`]) so the
//!   generic walker is panic-free on hostile nesting today.
//!
//! The codec is built on the exact-pinned `minicbor = "=2.3.0"`
//! (decision D7, `docs/decisions/D7-cbor-crate.md`): emission and payload
//! consumption go through the pinned crate (its encoder is shortest-form
//! by construction; its `str()` is the native invalid-UTF-8 rejection),
//! while the strict rejections are wrapper logic over the crate's raw
//! probe surface (`input()`/`position()`), exactly as D7 records. No
//! minicbor type appears in this module's public API, so the D7
//! in-house-codec contingency would be an implementation swap, not a
//! caller-visible change. WASM-safe: no I/O, no floats, `alloc` only;
//! output and error values are platform-independent (positions are `u64`,
//! never `usize`) so native and wasm32 behavior bit-match.

pub mod decode;
pub mod encode;

pub use decode::{
    CanonicalDecoder, DecodeError, ExpectedKind, ForbiddenKind, ItemKind, MAX_NESTING_DEPTH,
    MapReader, check_canonical,
};
pub use encode::{ArrayEncoder, CanonicalEncoder, EncodeError, MapEncoder, encode_item};
