//! The vault KDF block (U6, decision D40): schema, pre-auth caps,
//! and passphrase → vault-key derivation.
//!
//! # The two registered KDFs and their frozen creation values (D40 §1)
//!
//! | | algorithm id | creation values (the only ones our writer emits) |
//! | --- | --- | --- |
//! | **default** | 1 = Argon2id | `m = 262144 KiB (256 MiB), t = 3, p = 1` |
//! | explicit-only | 2 = scrypt | `N = 2²⁰ (log₂N = 20), r = 8, p = 1` |
//!
//! plus a random 16-byte salt in both cases. scrypt is selectable **only**
//! by an explicit init-time choice (D40: operator policy, never a resource
//! escape — it needs *more* memory, 1 GiB against Argon2id's 256 MiB).
//! There is no auto-tuner and no fallback path: v1 writes exactly these
//! values, and a machine that cannot allocate them gets the typed
//! `vault-kdf-memory` error at create **and** at unlock (D40 §2).
//!
//! # Block schema (rides vault format v1 — the opaque `kdf_block` slot of
//! [`crate::vault::header::VaultHeader`])
//!
//! ```text
//! kdf_block := canonical CBOR map {
//!     0: algorithm id   (uint; the registry above)
//!     1: salt           (bstr, exactly 16 bytes)
//!     2: m_cost_kib     (Argon2id)   | log2_n (scrypt)
//!     3: t_cost         (Argon2id)   | r      (scrypt)
//!     4: p              (both)
//! }
//! ```
//!
//! A future KDF or a parameter-range raise is a **header-version event**
//! (D40 §3): the registry and the caps below version with vault format v1.
//!
//! # Pre-auth caps (D40 §3 — the D10 precedent carried to the vault)
//!
//! The KDF runs *before* any AEAD can authenticate anything (the key does
//! not exist yet), so these parameters are the one attacker-suppliable
//! input acted on pre-authentication. [`KdfParams::decode`] therefore
//! enforces floors and ceilings **before any KDF allocation** — a
//! substituted header demanding 1 TiB is rejected with the distinct
//! `vault-kdf-params-out-of-range` error without a byte being reserved.
//! The same parse serves unlock and D47's `vault import` (one rule, two
//! call sites). Below-floor values are unreachable from our own writer but
//! rejected anyway: the header is adversarial input.
//!
//! # Key schedule (recorded choice — the U9 record store builds on it)
//!
//! The task entry fixes `passphrase → KDF → vault key → AEAD over the
//! store` and is silent on any further schedule, so U6 records the
//! simplest sound one: **the 32-byte KDF output is the single vault key**,
//! used directly as the XChaCha20-Poly1305 key for every record, with a
//! **fresh random 24-byte nonce drawn per record write** and the AAD
//! carrying the serialized KDF header plus the record identity (D42
//! rider; [`crate::vault::cipher`]). XChaCha20's 192-bit nonce makes
//! random-nonce collision negligible, and no per-record sub-key derivation
//! is needed for that property — U10's wallet sub-key is the one recorded
//! exception (blast-radius separation), derived when U10 lands.
//!
//! # Measured cost (U6 Accept; release build, this project's 2-core
//! reference host, 2026-08-01)
//!
//! | derivation (= every vault create AND every unlock) | measured |
//! | --- | --- |
//! | Argon2id, m = 256 MiB, t = 3, p = 1 | **≈ 0.68 s** (3 runs: 673/679/691 ms) |
//! | scrypt, N = 2²⁰, r = 8, p = 1 (1 GiB) | **≈ 2.4 s** (2 runs: 2.33/2.47 s) |
//!
//! This is the designed per-invocation unlock tax D40 §cost predicted at
//! "~1 s" and "~3–5 s" respectively; no key caching softens it, by
//! design. Debug-profile figures and the `[profile.dev.package.*]`
//! overrides that keep tests fast are documented in the workspace
//! Cargo.toml.
//!
//! # Zeroization
//!
//! The passphrase arrives and stays in [`SecretBuf`]; the derived key
//! lives in the zeroize-on-drop [`VaultKey`]; the Argon2id arena is
//! allocated by us and wiped before release ([`wipe_blocks`]); argon2's
//! own temporaries are wiped by its `zeroize` feature and blake2's
//! chaining state by the force-enabled `blake2/zeroize`
//! (workspace Cargo.toml; residue-probed in `tests/kdf_residue.rs`).
//! Honest limit, recorded: scrypt 0.12.0 offers no wiping for its internal
//! B/V work buffers — password-*derived* material (never the passphrase
//! itself, which only transits the sha2/zeroize-wiped PBKDF2) is freed
//! unwiped by that crate on the explicit-only scrypt path.

use antseal_core::codec::{CanonicalDecoder, DecodeError, EncodeError, encode_item};
use antseal_core::crypto::material::Key32;
use antseal_core::crypto::secrets::SecretBuf;
use rand_core::TryCryptoRng;
use thiserror::Error;
use zeroize::Zeroize;

use crate::error::CliError;

/// The vault key: the KDF's 32-byte output, used directly as the record
/// AEAD key (module docs, "key schedule"). Zeroize-on-drop via C's
/// material newtype, exactly like `UnitKey`/`ManifestKey`.
pub type VaultKey = Key32;

/// Length of the vault key in bytes (the KDF output length).
pub const VAULT_KEY_LEN: usize = 32;

/// Length of the KDF salt in bytes (MVP-SPEC.md line 143: random 16-B salt).
pub const KDF_SALT_LEN: usize = 16;

/// Algorithm id: Argon2id (the sole default, D40 §1).
pub const KDF_ALG_ARGON2ID: u64 = 1;
/// Algorithm id: scrypt (explicit init-time selection only, D40 §1).
pub const KDF_ALG_SCRYPT: u64 = 2;

/// Frozen Argon2id creation values (D40 §1; also the decode floors).
pub const ARGON2ID_M_COST_KIB: u32 = 262_144;
/// Argon2id time cost at creation (and decode floor).
pub const ARGON2ID_T_COST: u32 = 3;
/// Argon2id lane count at creation (exact at decode).
pub const ARGON2ID_P_COST: u32 = 1;

/// Frozen scrypt creation values (D40 §1; also the decode floors).
pub const SCRYPT_LOG2_N: u8 = 20;
/// scrypt block size at creation (exact at decode).
pub const SCRYPT_R: u32 = 8;
/// scrypt parallelism at creation (exact at decode).
pub const SCRYPT_P: u32 = 1;

/// D40 §3 cap: Argon2id `m_cost` ceiling (4 GiB in KiB).
pub const ARGON2ID_M_COST_KIB_MAX: u32 = 4_194_304;
/// D40 §3 cap: Argon2id `t_cost` ceiling.
pub const ARGON2ID_T_COST_MAX: u32 = 64;
/// D40 §3 cap: scrypt `log₂ N` ceiling.
pub const SCRYPT_LOG2_N_MAX: u8 = 24;

/// Injected failure for the D40 §2 low-RAM tests: the derivation seam
/// aborts exactly where the real fallible arena reservation would fail, at
/// create and at unlock alike, so the typed-error path is deterministic to
/// exercise without actually exhausting memory.
#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KdfFailPoint {
    /// No injected failure (the production path).
    None,
    /// The KDF arena reservation fails (simulated allocation failure).
    AllocFails,
}

/// Everything that can be wrong with a KDF block or a derivation. Total
/// over adversarial input — no panic path.
#[derive(Debug, Error)]
pub enum KdfError {
    /// D40 §3: a parameter is outside its registered floor/cap window (or
    /// the algorithm id is not in the v1 registry). Raised **before** any
    /// KDF allocation.
    #[error("{detail}")]
    ParamsOutOfRange { detail: String },

    /// D40 §2: the machine cannot allocate the KDF's memory floor. No
    /// fallback exists, by design.
    #[error("cannot allocate the {required_mib} MiB KDF arena")]
    Memory { required_mib: u32 },

    /// The block is not canonical CBOR / not decodable.
    #[error("vault KDF block is not canonical CBOR: {source}")]
    Codec {
        #[from]
        source: DecodeError,
    },

    /// Canonical CBOR of the wrong shape for the v1 block schema
    /// (including a salt of the wrong length).
    #[error("vault KDF block structure is invalid: {detail}")]
    Schema { detail: &'static str },

    /// Writer-side encode failure (unreachable for the fixed v1 shape;
    /// kept as an error rather than a panic — library discipline).
    #[error("could not encode the vault KDF block: {source}")]
    Encode {
        #[from]
        source: EncodeError,
    },

    /// The KDF crate itself rejected the run (unreachable for
    /// cap-validated parameters; kept total — library discipline).
    #[error("KDF execution failed: {detail}")]
    Execution { detail: String },

    /// The injected CSPRNG failed while drawing the salt.
    #[error("the OS random source failed while drawing the KDF salt")]
    RngFailure,
}

impl From<KdfError> for CliError {
    fn from(err: KdfError) -> Self {
        match err {
            KdfError::ParamsOutOfRange { detail } => CliError::VaultKdfParamsOutOfRange { detail },
            KdfError::Memory { required_mib } => CliError::VaultKdfMemory { required_mib },
            // A malformed block is indistinguishable from tamper: collapse
            // into the vault-auth class (U6 "insofar as safe"; same
            // collapse the U5 header parser applies).
            KdfError::Codec { .. } | KdfError::Schema { .. } => CliError::VaultAuthFailure,
            // Writer-side/unreachable classes are bugs, not vault states.
            KdfError::Encode { source } => CliError::Internal {
                detail: format!("vault KDF block encode failed: {source}"),
            },
            KdfError::Execution { detail } => CliError::Internal {
                detail: format!("KDF execution failed on cap-validated parameters: {detail}"),
            },
            KdfError::RngFailure => CliError::Internal {
                detail: "OS random source failed while drawing the KDF salt".to_owned(),
            },
        }
    }
}

/// The user's init-time KDF choice (D40 §1; surfaced by U11 per D39).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KdfSelection {
    /// Argon2id at the frozen defaults — the sole default.
    Argon2id,
    /// scrypt at the frozen values — explicit selection only; needs *more*
    /// memory than the default (1 GiB vs 256 MiB), documented at the
    /// selection point so nobody reaches for it as a low-RAM escape.
    Scrypt,
}

/// A parsed (or to-be-written) KDF block: algorithm, full parameters, and
/// the salt. Constructible only through the frozen-value constructors and
/// [`KdfParams::decode`], both of which enforce the same D40 §3 windows —
/// constructible == decodable (the F41 lesson).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KdfParams {
    alg: KdfAlg,
    salt: [u8; KDF_SALT_LEN],
}

/// Per-algorithm parameters, range-validated at construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KdfAlg {
    Argon2id {
        m_cost_kib: u32,
        t_cost: u32,
        p: u32,
    },
    Scrypt {
        log2_n: u8,
        r: u32,
        p: u32,
    },
}

impl KdfParams {
    /// Fresh creation-time parameters for the selected KDF: exactly the
    /// frozen D40 values plus a salt drawn from the injected CSPRNG.
    ///
    /// # Errors
    ///
    /// [`KdfError::RngFailure`] when the injected source fails.
    pub fn generate<R: TryCryptoRng + ?Sized>(
        selection: KdfSelection,
        rng: &mut R,
    ) -> Result<Self, KdfError> {
        let mut salt = [0u8; KDF_SALT_LEN];
        rng.try_fill_bytes(&mut salt)
            .map_err(|_| KdfError::RngFailure)?;
        let alg = match selection {
            KdfSelection::Argon2id => KdfAlg::Argon2id {
                m_cost_kib: ARGON2ID_M_COST_KIB,
                t_cost: ARGON2ID_T_COST,
                p: ARGON2ID_P_COST,
            },
            KdfSelection::Scrypt => KdfAlg::Scrypt {
                log2_n: SCRYPT_LOG2_N,
                r: SCRYPT_R,
                p: SCRYPT_P,
            },
        };
        Ok(KdfParams { alg, salt })
    }

    /// The D40 §3 window checks, shared by decode and (via the generate
    /// constants being inside every window) by construction.
    fn check_ranges(alg: &KdfAlg) -> Result<(), KdfError> {
        let out_of_range = |detail: String| KdfError::ParamsOutOfRange { detail };
        match *alg {
            KdfAlg::Argon2id {
                m_cost_kib,
                t_cost,
                p,
            } => {
                if !(ARGON2ID_M_COST_KIB..=ARGON2ID_M_COST_KIB_MAX).contains(&m_cost_kib) {
                    return Err(out_of_range(format!(
                        "Argon2id m_cost {m_cost_kib} KiB is outside \
                         [{ARGON2ID_M_COST_KIB}, {ARGON2ID_M_COST_KIB_MAX}]"
                    )));
                }
                if !(ARGON2ID_T_COST..=ARGON2ID_T_COST_MAX).contains(&t_cost) {
                    return Err(out_of_range(format!(
                        "Argon2id t_cost {t_cost} is outside \
                         [{ARGON2ID_T_COST}, {ARGON2ID_T_COST_MAX}]"
                    )));
                }
                if p != ARGON2ID_P_COST {
                    return Err(out_of_range(format!(
                        "Argon2id p {p} must be exactly {ARGON2ID_P_COST}"
                    )));
                }
            }
            KdfAlg::Scrypt { log2_n, r, p } => {
                if !(SCRYPT_LOG2_N..=SCRYPT_LOG2_N_MAX).contains(&log2_n) {
                    return Err(out_of_range(format!(
                        "scrypt log2(N) {log2_n} is outside [{SCRYPT_LOG2_N}, {SCRYPT_LOG2_N_MAX}]"
                    )));
                }
                if r != SCRYPT_R {
                    return Err(out_of_range(format!(
                        "scrypt r {r} must be exactly {SCRYPT_R}"
                    )));
                }
                if p != SCRYPT_P {
                    return Err(out_of_range(format!(
                        "scrypt p {p} must be exactly {SCRYPT_P}"
                    )));
                }
            }
        }
        Ok(())
    }

    /// Serialize to the exact `kdf_block` bytes the header stores (and,
    /// through the header, every vault AAD binds).
    ///
    /// # Errors
    ///
    /// [`KdfError::Encode`] — unreachable for the fixed v1 shape, but
    /// never a panic.
    pub fn encode(&self) -> Result<Vec<u8>, KdfError> {
        let bytes = encode_item(|e| {
            e.map(|m| {
                match self.alg {
                    KdfAlg::Argon2id {
                        m_cost_kib,
                        t_cost,
                        p,
                    } => {
                        m.entry(0, |e| e.u64(KDF_ALG_ARGON2ID))?;
                        m.entry(2, |e| e.u64(u64::from(m_cost_kib)))?;
                        m.entry(3, |e| e.u64(u64::from(t_cost)))?;
                        m.entry(4, |e| e.u64(u64::from(p)))?;
                    }
                    KdfAlg::Scrypt { log2_n, r, p } => {
                        m.entry(0, |e| e.u64(KDF_ALG_SCRYPT))?;
                        m.entry(2, |e| e.u64(u64::from(log2_n)))?;
                        m.entry(3, |e| e.u64(u64::from(r)))?;
                        m.entry(4, |e| e.u64(u64::from(p)))?;
                    }
                }
                m.entry(1, |e| e.bytes(&self.salt))
            })
        })?;
        Ok(bytes)
    }

    /// Parse KDF-block bytes defensively, enforcing the D40 §3 caps
    /// **before returning** — a caller holding a `KdfParams` holds
    /// cap-validated parameters, so no KDF-invoking path can act on an
    /// out-of-range header (no allocation is attempted here or anywhere
    /// before this returns).
    ///
    /// # Errors
    ///
    /// [`KdfError::ParamsOutOfRange`] for out-of-window values and
    /// unregistered algorithm ids; [`KdfError::Codec`]/[`KdfError::Schema`]
    /// for malformed bytes (which the caller collapses into the vault-auth
    /// class).
    pub fn decode(bytes: &[u8]) -> Result<Self, KdfError> {
        let mut d = CanonicalDecoder::new(bytes);
        let mut map = d.map()?;
        if map.remaining() != 5 {
            return Err(KdfError::Schema {
                detail: "v1 KDF block must be a 5-entry map {0: alg, 1: salt, 2..4: params}",
            });
        }
        let expect_key = |map: &mut antseal_core::codec::MapReader,
                          d: &mut CanonicalDecoder<'_>,
                          key: u64,
                          name: &'static str|
         -> Result<(), KdfError> {
            if map.next_key(d)? != Some(key) {
                return Err(KdfError::Schema { detail: name });
            }
            Ok(())
        };
        expect_key(
            &mut map,
            &mut d,
            0,
            "v1 KDF block key 0 (algorithm) missing",
        )?;
        let alg_id = d.u64()?;
        expect_key(&mut map, &mut d, 1, "v1 KDF block key 1 (salt) missing")?;
        let salt_bytes = d.bytes()?;
        let salt: [u8; KDF_SALT_LEN] = salt_bytes.try_into().map_err(|_| KdfError::Schema {
            detail: "v1 KDF block salt must be exactly 16 bytes",
        })?;
        expect_key(&mut map, &mut d, 2, "v1 KDF block key 2 missing")?;
        let field2 = d.u64()?;
        expect_key(&mut map, &mut d, 3, "v1 KDF block key 3 missing")?;
        let field3 = d.u64()?;
        expect_key(&mut map, &mut d, 4, "v1 KDF block key 4 missing")?;
        let field4 = d.u64()?;
        d.finish()?;

        let narrow_u32 = |v: u64, what: &str| -> Result<u32, KdfError> {
            u32::try_from(v).map_err(|_| KdfError::ParamsOutOfRange {
                detail: format!("{what} {v} exceeds the u32 parameter space"),
            })
        };
        let alg = match alg_id {
            KDF_ALG_ARGON2ID => KdfAlg::Argon2id {
                m_cost_kib: narrow_u32(field2, "Argon2id m_cost")?,
                t_cost: narrow_u32(field3, "Argon2id t_cost")?,
                p: narrow_u32(field4, "Argon2id p")?,
            },
            KDF_ALG_SCRYPT => KdfAlg::Scrypt {
                log2_n: u8::try_from(field2).map_err(|_| KdfError::ParamsOutOfRange {
                    detail: format!("scrypt log2(N) {field2} exceeds the u8 parameter space"),
                })?,
                r: narrow_u32(field3, "scrypt r")?,
                p: narrow_u32(field4, "scrypt p")?,
            },
            other => {
                return Err(KdfError::ParamsOutOfRange {
                    detail: format!(
                        "KDF algorithm id {other} is not in the v1 registry \
                         (1 = Argon2id, 2 = scrypt)"
                    ),
                });
            }
        };
        Self::check_ranges(&alg)?;
        Ok(KdfParams { alg, salt })
    }

    /// The KDF's peak arena requirement in MiB (for the typed low-RAM
    /// error message; D40 §2's "use a machine with ≥ …" guidance).
    #[must_use]
    pub fn required_mib(&self) -> u32 {
        match self.alg {
            KdfAlg::Argon2id { m_cost_kib, .. } => m_cost_kib.div_ceil(1024),
            KdfAlg::Scrypt { log2_n, r, p } => {
                // V array: 128·r·N bytes; B: 128·r·p; T: 128·r. Dominated
                // by V. Saturating shift keeps the *message* honest even
                // for the largest cap-admitted values.
                let n = 1u64 << log2_n;
                let bytes = 128u64
                    .saturating_mul(u64::from(r))
                    .saturating_mul(n + u64::from(p) + 1);
                u32::try_from(bytes.div_ceil(1024 * 1024)).unwrap_or(u32::MAX)
            }
        }
    }

    /// Derive the vault key from a passphrase (the production path:
    /// fallible arena, typed low-RAM error).
    ///
    /// # Errors
    ///
    /// [`KdfError::Memory`] when the arena cannot be allocated (D40 §2 —
    /// the same typed error at create and unlock; best-effort under OS
    /// overcommit, as D40 records honestly); [`KdfError::Execution`] for
    /// unreachable crate-level failures.
    pub fn derive_key(&self, passphrase: &SecretBuf) -> Result<VaultKey, KdfError> {
        self.derive_key_impl(passphrase, KdfFailPoint::None)
    }

    pub(crate) fn derive_key_impl(
        &self,
        passphrase: &SecretBuf,
        fail: KdfFailPoint,
    ) -> Result<VaultKey, KdfError> {
        let memory_err = || KdfError::Memory {
            required_mib: self.required_mib(),
        };
        if fail == KdfFailPoint::AllocFails {
            // The injected failure models exactly the fallible-reservation
            // failure below, at the same point in the sequence: after cap
            // validation, before any KDF work.
            return Err(memory_err());
        }
        let mut out = [0u8; VAULT_KEY_LEN];
        match self.alg {
            KdfAlg::Argon2id {
                m_cost_kib,
                t_cost,
                p,
            } => {
                let params = argon2::Params::new(m_cost_kib, t_cost, p, Some(VAULT_KEY_LEN))
                    .map_err(|e| KdfError::Execution {
                        detail: format!("argon2 parameter build: {e}"),
                    })?;
                let ctx = argon2::Argon2::new(
                    argon2::Algorithm::Argon2id,
                    argon2::Version::V0x13,
                    params.clone(),
                );
                // The KDF arena, allocated fallibly by us (not by the
                // crate) so exhaustion surfaces as the typed error instead
                // of an abort. `try_reserve_exact` performs the one real
                // allocation; the `resize` fills within that capacity.
                let count = params.block_count();
                let mut arena: Vec<argon2::Block> = Vec::new();
                arena.try_reserve_exact(count).map_err(|_| memory_err())?;
                arena.resize(count, argon2::Block::default());
                let result = ctx.hash_password_into_with_memory(
                    passphrase.as_bytes(),
                    &self.salt,
                    &mut out,
                    arena.as_mut_slice(),
                );
                // The filled arena is key-derived secret material: wipe it
                // before the Vec releases the pages (volatile writes via
                // `zeroize` — a plain fill could be elided before a free).
                wipe_blocks(&mut arena);
                result.map_err(|e| KdfError::Execution {
                    detail: format!("argon2 derivation: {e}"),
                })?;
            }
            KdfAlg::Scrypt { log2_n, r, p } => {
                // scrypt 0.12.0 allocates its B/V/T buffers internally and
                // infallibly, so the typed low-RAM error can only be
                // produced by a preflight: reserve the same total once,
                // release it, then run. Best-effort by construction (the
                // gap between probe and run, and OS overcommit, are both
                // recorded in D40 §2) — but it converts the common
                // cannot-possibly-fit case into the typed error instead of
                // an abort.
                let n = 1usize << log2_n;
                let preflight_bytes = 128usize
                    .saturating_mul(r as usize)
                    .saturating_mul(n + p as usize + 1);
                let mut probe: Vec<u8> = Vec::new();
                probe
                    .try_reserve_exact(preflight_bytes)
                    .map_err(|_| memory_err())?;
                drop(probe);
                let params =
                    scrypt::Params::new(log2_n, r, p).map_err(|e| KdfError::Execution {
                        detail: format!("scrypt parameter build: {e}"),
                    })?;
                scrypt::scrypt(passphrase.as_bytes(), &self.salt, &params, &mut out).map_err(
                    |e| KdfError::Execution {
                        detail: format!("scrypt derivation: {e}"),
                    },
                )?;
            }
        }
        let key = VaultKey::from_bytes(out);
        out.zeroize();
        Ok(key)
    }
}

/// Wipe a filled Argon2id arena with volatile writes. Extracted so the
/// wipe itself is unit-testable (the arena is otherwise a local the tests
/// cannot observe).
pub(crate) fn wipe_blocks(blocks: &mut [argon2::Block]) {
    for block in blocks {
        block.as_mut().zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The arena wipe really zeroes every word (the in-house half of the
    /// zeroization story; the third-party half is `tests/kdf_residue.rs`).
    #[test]
    fn wipe_blocks_zeroes_every_word() {
        let mut arena = vec![argon2::Block::default(); 3];
        for block in &mut arena {
            block
                .as_mut()
                .iter_mut()
                .for_each(|w| *w = 0xAAAA_AAAA_AAAA_AAAA);
        }
        wipe_blocks(&mut arena);
        for block in &arena {
            assert!(
                block.as_ref().iter().all(|&w| w == 0),
                "arena word survived the wipe"
            );
        }
    }

    /// `required_mib` reports the documented D40 figures for the frozen
    /// creation values (256 MiB Argon2id; ~1 GiB scrypt).
    #[test]
    fn required_mib_matches_d40_figures() {
        let a = KdfParams {
            alg: KdfAlg::Argon2id {
                m_cost_kib: ARGON2ID_M_COST_KIB,
                t_cost: ARGON2ID_T_COST,
                p: ARGON2ID_P_COST,
            },
            salt: [0; 16],
        };
        assert_eq!(a.required_mib(), 256);
        let s = KdfParams {
            alg: KdfAlg::Scrypt {
                log2_n: SCRYPT_LOG2_N,
                r: SCRYPT_R,
                p: SCRYPT_P,
            },
            salt: [0; 16],
        };
        // V = 128·8·2^20 B = 1 GiB, plus B (p·r·128 B) and T (r·128 B):
        // 1 GiB + 2 KiB rounds up to 1025 MiB — the exact peak, so the
        // low-RAM message never understates.
        assert_eq!(s.required_mib(), 1025);
    }
}
