//! The v1 `.sealproof` reveal bundle: schema types + parse-time shape
//! validation (F8), and the nested-strict-decoding codec (F9).
//!
//! MVP-SPEC.md lines 112–114 (bundle contents), 98 (manifest storage
//! record), 108–110 (anchor artifacts), 121 (verifier structural
//! invariants), 123 (format stability). Key numbers, types, presence rules,
//! and exact lengths come from the v1 wire registry,
//! `docs/format/registry-v1.md` §§7.6–7.15 (+ its machine mirror
//! `registry-v1.json`); [`registry`] is the code side of that table and
//! `crates/antseal-core/tests/format_registry_draft.rs` asserts the two
//! agree 1:1.
//!
//! ```text
//! BundleV1                      {0: format_version … 9: full_reveals}
//!   ├── manifest (bstr)         OPAQUE here — F9's layer 2 decodes it
//!   ├── StorageRecord           {0: address, 1: nonce, 2: k_m}
//!   ├── OtsAnchor               {0: status, 1: ots, 2–4: upgrade group}
//!   ├── TsaAnchor               {0: status … 4: source}
//!   ├── ReceiptRecord           {0: tx_hashes, 1: block_number, 2: payload}
//!   ├── CoveredReveal           {0: unit_id … 4: paths}
//!   │     ├── CoverEntry        [level, index, seed]
//!   │     └── PathNode          [level, index, hash]
//!   ├── NonCoveredReveal        {0: unit_id … 3: unit_salt}
//!   ├── TouchedFile             {0: file_id, 1: path, 2: path_salt}
//!   └── FullReveal              {0: file_id, 1: file_salt, 2: s_root?}
//! ```
//!
//! # Who rejects what
//!
//! A `.sealproof` decodes in **three strict layers**, each with its own error
//! class so a tamper row can name which one a mutation broke (registry
//! §7.6.3):
//!
//! | layer | input | decoder | error type |
//! | --- | --- | --- | --- |
//! | 1 | the whole file | [`BundleV1::decode`] | [`BundleError`] |
//! | 2 | key 1's `bstr` contents | [`crate::manifest::Manifest::decode`] | [`crate::manifest::ManifestError::Envelope`] |
//! | 3 | the envelope's `body` `bstr` | `ManifestBodyV1::decode` | [`crate::manifest::ManifestError::Body`] |
//!
//! [`SealProof::decode`] runs all three; [`SealProofError`] keeps the two
//! error families in separate variants and reports the layer.
//!
//! Beneath all three sits F3's canonicality layer (spec line 73), whose
//! `cbor-*` codes each layer surfaces unchanged through its own wrapper arm.
//! Above them sits R, which owns every rule needing *both* the bundle and the
//! manifest (MVP-SPEC.md line 121).
//!
//! # D78: this module never opens the embedded manifest
//!
//! Bundle **schema** validation is decidable from the bundle's own bytes.
//! Key 1 is an opaque `bstr` to [`BundleV1`], and [`BundleError`] has no arm
//! that could carry a [`crate::manifest::ManifestError`] — so a bundle that
//! is *well-formed but inconsistent with its manifest* cannot possibly report
//! a `bundle-` code, and a malformed manifest inside a well-formed bundle
//! cannot lose its `manifest-` identity. Under D30 error families are
//! permanent, so this is a structural property rather than a convention:
//! "malformed bundle" and "lying sealer" never render alike.
//!
//! The composition of layers 2 and 3 lives in [`proof`], on a separate error
//! type ([`SealProofError`]) that is the only place the two families meet.
//!
//! # Version dispatch and the line-123 stability contract (F10)
//!
//! [`BundleV1::decode`] is **not** the v1 decoder: it is F10's dispatch
//! entry point. The bundle's discriminant is a top-level key of the file
//! (registry §7.6 key 0) and canonical maps ascend, so it is the first
//! thing on the wire — an unsupported bundle is
//! [`BundleError::UnsupportedFormatVersion`] after a few bytes, before any
//! section is walked and before F11's caps come into play. It is never a
//! canonicality or unknown-key error: "too new" and "corrupt" are different
//! claims about the sender.
//!
//! This discriminant is **independent** of the embedded manifest's
//! (registry §7.2 key 0) — a v1 bundle may one day carry a v2 manifest, and
//! D78 keeps the two rejections in separate families so they never render
//! alike. The v1 decoder is reachable only with [`crate::format::V1`], an
//! admission witness with no public constructor, so a future v2 cannot
//! alter v1's byte behaviour.
//!
//! Full policy: [`crate::format`].
//!
//! # Construction is validation
//!
//! A schema-invalid [`BundleV1`] cannot exist: every field is private and
//! both construction paths — [`BundleV1::new`] (reveal side) and
//! [`BundleV1::decode`] (verify side) — funnel through the same checks. See
//! [`schema`] for the rules that are unrepresentable rather than checked.
//!
//! # Secret hygiene (project rule 6)
//!
//! A `.sealproof` carries **disclosed** key material — `k_u` per reveal,
//! `k_m` in the storage record, and the three 16-byte salts. Disclosed to the
//! bundle's recipient is not "safe to log": all of it is held in the crypto
//! layer's redacting, zeroizing newtypes, opaque payloads render as a byte
//! count, and error payloads carry key numbers, lengths, ids, and closed enum
//! discriminants only — never field content.

#![deny(clippy::unwrap_used)]

pub mod error;
pub mod proof;
pub mod registry;
pub mod schema;

pub use error::{
    BundleError, CiphertextDefect, ContainerField, FixedLenField, OrderedList, TupleId,
};
pub use proof::{ProofLayer, SealProof, SealProofError};
pub use registry::{AnchorStatus, BundleMapId};
pub use schema::{
    BundleParts, BundleV1, CoverEntry, CoveredReveal, FullReveal, NonCoveredReveal, OpaqueBytes,
    OtsAnchor, OtsUpgrade, PathNode, ReceiptRecord, StorageRecord, TouchedFile, TsaAnchor,
    encode_bundle,
};
