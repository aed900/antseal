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
//!   and the borrowed master-secret view (C2; extended by C5/C6).
//! - [`error`] — the crypto error taxonomy, one distinct variant per tamper-
//!   matrix failure class (C4).
//!
//! # Secret hygiene (project rule 6)
//!
//! Secret material (`W`, unit keys, salts, seeds) must never appear in logs,
//! error messages, or test fixtures. Concretely, in this module tree:
//!
//! - all secret-bearing types redact their `Debug` output and implement no
//!   `Display`;
//! - error variants carry only kinds, lengths, offsets, and ids — never key,
//!   salt, seed, or plaintext bytes (see [`error`]);
//! - committed vectors under `testdata/` derive from fixed, clearly marked
//!   NON-SECRET fixture inputs only.
//!
//! # C5 seam — zeroization and RNG land later
//!
//! C1–C4 deliberately contain **no RNG** (nothing here draws randomness) and
//! **no zeroization** (the `zeroize` pin lands with C5). C5 adds the owning
//! `MasterSecret` / `SealId` types (CSPRNG generation, `ZeroizeOnDrop`,
//! redacted `Debug`) in `crypto::secrets`, borrowing into
//! [`material::MasterSecretRef`]; C5/C21 then retrofit zeroization onto the
//! [`material`] newtypes. Until then, callers must treat those buffers as
//! secret and short-lived.
//!
//! # No panics on adversarial input
//!
//! Library code in this module tree returns [`error::CryptoError`] — it never
//! unwraps or panics on data an adversary controls (bundles, manifests,
//! bundle-supplied salts/seeds/signatures). `clippy::unwrap_used` is denied
//! for the whole tree below.

#![deny(clippy::unwrap_used)]

pub mod domain;
pub mod error;
pub mod hkdf;
pub mod material;

pub use error::CryptoError;
