//! Cryptographic primitives for antseal (MVP-SPEC.md, "Cryptography (v1)",
//! lines 89–98, plus the normative "Definitions & encoding" section, lines
//! 73–79).
//!
//! Layout (each module is the *single* home of its concern):
//!
//! - [`domain`] — the hash domain-tag registry and the [`domain::tagged_sha256`]
//!   helper every commitment / tree / salt-derivation preimage routes through
//!   (C1).
//! - [`hkdf`] — HKDF-SHA256 derivation from the master secret `W` with the
//!   frozen label registry and the injective, length-prefixed info encoding
//!   (C2).
//! - [`material`] — fixed-length newtypes for derived key/salt/seed material
//!   (zeroize-on-drop), the borrowed master-secret view, the length-checked
//!   bundle-value constructors, and the opaque `FileSalt` (C2/C5/C6/C7).
//! - [`secrets`] — the owning master secret `W`, the public `seal_id`, and
//!   the zeroizing passphrase buffer; generation from **injected** CSPRNGs
//!   only (C5).
//! - [`commit`] — the four salted commitments, compute + constant-time
//!   verify (C6).
//! - [`disclosure`] — the commitment-mode and salt-disclosure rules as
//!   unrepresentable-misuse API shapes (C7).
//! - [`padding`] — the v1 unit padding codec: formula, apply, length-first
//!   strip (C8).
//! - [`unit_aead`] — unit XChaCha20-Poly1305 with AAD binding and the
//!   `(k_u, nonce)` single-use invariant (C9).
//! - [`manifest_aead`] — manifest XChaCha20-Poly1305 under `k_m` with the
//!   frozen **empty** AAD, plus the `{nonce, k_m}` storage-record values
//!   (C10).
//! - [`error`] — the crypto error taxonomy, one distinct variant per tamper-
//!   matrix failure class (C4).
//!
//! # Secret hygiene (project rule 6)
//!
//! Secret material (`W`, unit keys, salts, seeds) must never appear in logs,
//! error messages, or test fixtures. Concretely, in this module tree:
//!
//! - all secret-bearing types redact their `Debug` output, implement no
//!   `Display`, and zeroize on drop ([`material`], [`secrets`]);
//! - error variants carry only kinds, lengths, offsets, and ids — never key,
//!   salt, seed, or plaintext bytes (see [`error`]);
//! - committed vectors under `testdata/` derive from fixed, clearly marked
//!   NON-SECRET fixture inputs only.
//!
//! # Randomness is injected, never linked
//!
//! Nothing in this crate reaches for an OS randomness source: generation
//! and nonce-drawing paths take `&mut impl rand_core::TryCryptoRng`
//! (the pinned `rand_core` is a dependency-free trait crate, so `getrandom`
//! cannot enter the graph). Production callers inject the OS CSPRNG; the
//! wasm32 `getrandom` backend recipe is P14's, outside this crate. See
//! [`secrets`].
//!
//! # No panics on adversarial input
//!
//! Library code in this module tree returns [`error::CryptoError`] — it never
//! unwraps or panics on data an adversary controls (bundles, manifests,
//! bundle-supplied salts/seeds/signatures). `clippy::unwrap_used` is denied
//! for the whole tree below.

#![deny(clippy::unwrap_used)]

pub mod commit;
pub mod disclosure;
pub mod domain;
pub mod error;
pub mod hkdf;
pub mod manifest_aead;
pub mod material;
pub mod padding;
pub mod secrets;
pub mod unit_aead;

pub use error::CryptoError;
