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
//! - [`confirmation_attack`] — *why* they are salted: the confirmation
//!   attack executed against deliberately-unsalted toy variants and defeated
//!   by the production ones, as doc-tests that run on every CI run (C19).
//! - [`disclosure`] — the commitment-mode and salt-disclosure rules as
//!   unrepresentable-misuse API shapes (C7).
//! - [`padding`] — the v1 unit padding codec: formula, apply, length-first
//!   strip (C8).
//! - [`unit_aead`] — unit XChaCha20-Poly1305 with AAD binding and the
//!   `(k_u, nonce)` single-use invariant (C9).
//! - [`manifest_aead`] — manifest XChaCha20-Poly1305 under `k_m` with the
//!   frozen **empty** AAD, plus the `{nonce, k_m}` storage-record values
//!   (C10).
//! - [`sig_ed25519`] — the Ed25519 half of the author signature: keys from
//!   `W`, the `ctx ‖ 0x00 ‖ body` pre-image, and strict/canonical
//!   verification with the D16 pre-validation layer (C12).
//! - [`sig_mldsa`] — the ML-DSA-65 half: FIPS 204 keys from a `W`-derived
//!   xi, deterministic signing with the frozen `ctx`, and canonical-strict
//!   verification (C13).
//! - [`sig_policy`] — `sig_policy` validation, the algorithm-id registry,
//!   and hybrid sign/verify orchestration enforcing present-set ==
//!   policy-set (C14).
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
//!
//! # Zeroization, and its limits (C21; MVP-SPEC.md line 143)
//!
//! Every owning secret type here wipes on drop: [`secrets::MasterSecret`]
//! (`W`), [`secrets::SecretBuf`] (passphrase-class buffers),
//! [`material::Key32`] (both [`unit_aead::UnitKey`] and
//! [`manifest_aead::ManifestKey`]), [`material::Seed32`] (the fine seed and
//! both signature seeds), [`material::Salt16`], [`material::FileSalt`], and
//! [`manifest_aead::ManifestStorageRecord`]. None of them is `Clone`, none
//! implements `Display`, and all redact their `Debug`. Intermediate copies
//! are wiped where the API allows: the HKDF OKM buffers in [`hkdf`], and the
//! padded-plaintext buffer in [`unit_aead`] on both the encrypt path and the
//! decrypt-failure path. The full per-buffer audit, **including the buffers
//! that cannot be wiped and why**, is `docs/zeroization-audit.md`.
//!
//! ## Normative caveat — the browser verifier
//!
//! **The WASM verifier cannot guarantee zeroization for bundle-supplied keys
//! (`k_u`, `k_m`, salts) in browser memory.** The types above still call
//! `zeroize` under `wasm32`, and the writes are still volatile and
//! unreorderable — but that is a promise about *this* linear-memory
//! allocation, not about the machine. A JavaScript engine may have copied the
//! bundle bytes into any number of engine-owned buffers before they ever
//! reached linear memory (`fetch` and `File` results, the `ArrayBuffer` the
//! bytes were copied from, string intermediates), the whole WebAssembly
//! memory may be moved wholesale by `memory.grow`, and the browser may swap
//! or snapshot the tab's pages. None of that is reachable from Rust. So on
//! the web the honest statement is: wiping is best-effort and unverifiable,
//! and a browser that has verified a bundle should be treated as having
//! retained that bundle's `k_u`/`k_m`/salts until the tab is closed.
//!
//! This is bounded, not catastrophic — those keys open exactly the content
//! the bundle already contains in the clear, and `W` never reaches a browser
//! at all (the verifier holds bundle-supplied keys, never the master secret).
//! It is recorded as a residual risk in `docs/threat-model.md` §2.10 rather
//! than mitigated, because there is no mitigation available at this layer.

#![deny(clippy::unwrap_used)]

pub mod commit;
pub mod confirmation_attack;
pub mod disclosure;
pub mod domain;
pub mod error;
pub mod hkdf;
pub mod manifest_aead;
pub mod material;
pub mod padding;
pub mod secrets;
pub mod sig_ed25519;
pub mod sig_mldsa;
pub mod sig_policy;
pub mod unit_aead;

pub use error::CryptoError;

/// The **frozen author-signature context string** `"antseal-manifest-v1"`
/// (MVP-SPEC.md line 97), fixed at M0 so a signature can never be lifted into
/// another context.
///
/// It lives here, at the crypto module root, because it belongs to neither
/// algorithm: both halves of the hybrid signature bind *this same* string,
/// each in the way its own standard prescribes —
///
/// - Ed25519 ([`sig_ed25519`]) folds it into the pre-image:
///   `message = ctx ‖ 0x00 ‖ body` (RFC 8032 has no context parameter for
///   plain Ed25519, so the domain prefix is the construction);
/// - ML-DSA-65 ([`sig_mldsa`]) passes it as the FIPS 204 `ctx` parameter,
///   which the standard absorbs as `0x00 ‖ len(ctx) ‖ ctx` ahead of the
///   message.
///
/// Changing these bytes is a format event, not a refactor: every existing
/// signature would stop verifying.
pub const SIG_CONTEXT: &[u8] = b"antseal-manifest-v1";

/// The C21 zeroization sweep, as compile-time trait assertions.
///
/// Each module already asserts its own types (C5/C9/C10/C13). This module is
/// the **single roll-up**: one list, in one place, covering every
/// secret-bearing type the crypto tree owns plus the third-party key state it
/// holds. The individual assertions are the working ones; this one is what a
/// reviewer reads to answer "is anything missing?", and what fails if a new
/// secret type is added to a module that forgot to assert it.
///
/// These are `const` assertions — checked when this crate's test target
/// compiles, on every target including `wasm32-unknown-unknown`, not when the
/// tests run. A dependency bump that silently dropped a `zeroize` feature
/// would fail the build rather than pass a green test suite.
///
/// The prose audit, including the buffers that are **not** covered and the
/// reason each cannot be, is `docs/zeroization-audit.md`.
#[cfg(test)]
mod zeroization_sweep {
    use super::{disclosure, manifest_aead, material, secrets, unit_aead};
    use zeroize::ZeroizeOnDrop;

    const fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}

    // Every owning secret type in this crate's crypto tree.
    //
    // Anonymous `const _` on purpose: a *named* private const is itself dead
    // code, so rustc would not count the calls inside it as uses and the
    // assertion helper would warn as unused. `const _` is always evaluated.
    const _: () = {
        // The master secret W and passphrase-class buffers (C5).
        assert_zeroize_on_drop::<secrets::MasterSecret>();
        assert_zeroize_on_drop::<secrets::SecretBuf>();

        // Derived key/salt/seed material (C2/C6/C7). `Key32` is the concrete
        // type behind both AEAD key aliases; `Seed32` behind the fine seed,
        // both signature seeds, and bundle-supplied GGM covering seeds.
        assert_zeroize_on_drop::<material::Key32>();
        assert_zeroize_on_drop::<material::Seed32>();
        assert_zeroize_on_drop::<material::Salt16>();
        assert_zeroize_on_drop::<material::FileSalt>();

        // The AEAD key aliases, asserted through their public names so a
        // future de-aliasing cannot quietly drop the property.
        assert_zeroize_on_drop::<unit_aead::UnitKey>();
        assert_zeroize_on_drop::<manifest_aead::ManifestKey>();

        // The composite that owns k_m (C10).
        assert_zeroize_on_drop::<manifest_aead::ManifestStorageRecord>();

        // Disclosure sets whose fields all wipe by drop glue (C7).
        // `PartialRevealDisclosure` is absent on purpose — its `Vec` growth
        // path strands un-wiped salts on reallocation; see residual risk R2
        // in `docs/zeroization-audit.md` and the note in `disclosure`.
        assert_zeroize_on_drop::<disclosure::NonCoveredUnitDisclosure>();
        assert_zeroize_on_drop::<disclosure::FullFileRevealDisclosure>();
    };

    // Third-party key state we hold but do not define. Each of these is
    // `ZeroizeOnDrop` only because a NON-DEFAULT `zeroize` feature is enabled
    // in the workspace pin (D13/D14 consumption shapes). That is exactly the
    // kind of thing a routine version bump loses silently, so it is asserted
    // rather than trusted.
    //
    // The gap this list does NOT cover — hkdf/hmac's PRK-keyed state, which
    // no feature combination on the pinned crates makes wipeable — is
    // recorded as residual risk R1 in `docs/zeroization-audit.md`.
    const _: () = {
        // Ed25519 signing key — holds dalek's own copy of the W-derived seed
        // and the expanded scalar (`ed25519-dalek` feature `zeroize`).
        assert_zeroize_on_drop::<ed25519_dalek::SigningKey>();

        // ML-DSA-65 signing key and its expanded form — the latter holds
        // rho/K/tr/s1/s2/t0 (`ml-dsa` feature `zeroize`, non-default).
        assert_zeroize_on_drop::<ml_dsa::SigningKey<ml_dsa::MlDsa65>>();
        assert_zeroize_on_drop::<ml_dsa::ExpandedSigningKey<ml_dsa::MlDsa65>>();

        // The AEAD cipher's internal key copy (`chacha20poly1305` feature
        // `zeroize`). Both AEAD modules build one per call and drop it there.
        assert_zeroize_on_drop::<chacha20poly1305::XChaCha20Poly1305>();
    };

    /// `MasterSecretRef` is a `Copy` **borrow** and must NOT be
    /// `ZeroizeOnDrop`: it owns nothing, so a wiping drop would either be a
    /// lie or would wipe through a shared reference. The owning
    /// [`secrets::MasterSecret`] is what wipes. Asserted as a live check that
    /// the borrow/own split is still the shape it claims to be.
    #[test]
    fn the_master_secret_view_is_a_borrow_not_an_owner() {
        let bytes = [0x5Au8; 32];
        let view = material::MasterSecretRef::from_bytes(&bytes);
        let copied = view; // `Copy`: a borrow may be duplicated freely.
        assert_eq!(copied.as_bytes(), &bytes);
        // Letting both views go out of scope leaves the borrowed buffer
        // untouched — wiping is the owner's job, and the owner is not here.
        // (No `drop` call: dropping a `Copy` type is a no-op the compiler
        // rightly warns about, which is itself the point being made.)
        assert_eq!(bytes, [0x5Au8; 32]);
    }
}
