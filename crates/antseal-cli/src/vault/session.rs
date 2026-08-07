//! Vault create/unlock (U6): passphrase → KDF → vault key → the unlocked
//! handle every record read/write goes through.
//!
//! # Create sequence (all writes atomic per U5)
//!
//! 1. refuse if a vault header already exists (the D39 absolute refusal is
//!    U11's user-facing copy; this is the primitive beneath it);
//! 2. draw the 16-byte salt, freeze the D40 creation parameters
//!    ([`crate::vault::kdf::KdfParams::generate`]);
//! 3. derive the vault key — a machine that cannot allocate the arena
//!    fails HERE with the typed `vault-kdf-memory` error and **no vault is
//!    created** (D40 §2: no fallback, no prompt);
//! 4. write the **key-check record** (`store/check`): the AEAD over a
//!    fixed public marker, bound to `RecordIdentity::KeyCheck`;
//! 5. write the header **last** — header presence is the "vault exists"
//!    marker, so a crash mid-create never leaves a header without the
//!    check record behind it.
//!
//! # Unlock sequence
//!
//! 1. read the header file (bounded read: `MAX_HEADER_BYTES + 1`),
//!    decode it (U5's parser — newer-version and cap errors are distinct);
//! 2. dispatch on the D50 wrap mode: 0 unwrapped, 1 combine the keyfile
//!    factor (U8), 2 the distinct "wrap mode not supported" refusal —
//!    never the generic auth failure, because the mode is a registered id
//!    and the vault is intact;
//! 3. decode the KDF block — the D40 §3 caps run here, **before** any
//!    allocation, so a hostile header is rejected cheaply;
//! 4. derive the vault key — same typed low-RAM error as create;
//! 5. open the key-check record: wrong passphrase, edited header, and
//!    corrupt store all surface as the one vault-auth failure (U6
//!    "insofar as safe" — nothing here may distinguish *which* secret-
//!    dependent step failed).
//!
//! The unlock tax is the KDF itself — ~1 s at the Argon2id defaults (D40
//! §cost; measured value recorded in the U6 task entry). No unlocked-key
//! caching exists anywhere, by design.

use std::io::Read;
use std::path::Path;
use std::sync::Arc;

use antseal_core::crypto::secrets::SecretBuf;
use rand_core::TryCryptoRng;

use super::cipher::{RecordIdentity, open_record, seal_record};
use super::fs::atomic_write;
use super::header::{
    MAX_HEADER_BYTES, VaultHeader, WRAP_MODE_KEYFILE, WRAP_MODE_OS_KEYSTORE_RESERVED,
};
use super::kdf::{KdfFailPoint, KdfParams, KdfSelection, VaultKey};
use super::keyfile::{self, WrapChoice};
use super::layout::VaultLayout;
use crate::error::CliError;

/// The key-check record's plaintext: a fixed public marker (never secret;
/// its confidentiality value is nil — its authentication under the vault
/// key and header AAD is the entire point).
pub const KEY_CHECK_PLAINTEXT: &[u8] = b"antseal vault key check v1";

/// Bounded read cap for the check record file (defensive; a real blob is
/// nonce + marker + tag ≈ 66 bytes).
const MAX_CHECK_RECORD_BYTES: usize = 4096;

/// An unlocked vault: the derived key, the exact header bytes every
/// record AAD binds, and the layout. Every record operation (U9's store,
/// U10's wallet) goes through this handle; D42's upgrade-hook rule keys on
/// holding one.
///
/// Deliberately neither `Clone` nor `Debug`-revealing: the key rides in
/// C's zeroize-on-drop [`VaultKey`], and uncontrolled copies defeat
/// zeroization.
pub struct UnlockedVault {
    layout: VaultLayout,
    header_bytes: Vec<u8>,
    key: VaultKey,
}

impl std::fmt::Debug for UnlockedVault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UnlockedVault")
            .field("layout", &self.layout)
            .field("key", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl UnlockedVault {
    /// The vault layout this handle covers.
    #[must_use]
    pub fn layout(&self) -> &VaultLayout {
        &self.layout
    }

    /// The exact serialized header bytes bound as AAD into every record.
    #[must_use]
    pub fn header_bytes(&self) -> &[u8] {
        &self.header_bytes
    }

    /// Encrypt one record for this vault (fresh nonce, header + identity
    /// AAD). The store layer (U9) owns where the blob lands on disk.
    ///
    /// # Errors
    ///
    /// Propagates [`super::cipher::CipherError`] via [`CliError`]
    /// (RNG failure is the only reachable class).
    pub fn seal_record<R: TryCryptoRng + ?Sized>(
        &self,
        identity: RecordIdentity<'_>,
        plaintext: &[u8],
        rng: &mut R,
    ) -> Result<Vec<u8>, CliError> {
        Ok(seal_record(
            &self.key,
            &self.header_bytes,
            identity,
            plaintext,
            rng,
        )?)
    }

    /// Decrypt one record blob of this vault (zeroizing plaintext).
    ///
    /// # Errors
    ///
    /// [`CliError::VaultAuthFailure`] for anything the AEAD rejects —
    /// tamper, splice, or corruption.
    pub fn open_record(
        &self,
        identity: RecordIdentity<'_>,
        blob: &[u8],
    ) -> Result<SecretBuf, CliError> {
        Ok(open_record(&self.key, &self.header_bytes, identity, blob)?)
    }

    /// The wallet sub-key (U10): HKDF-SHA256 of the vault key under the
    /// wallet domain label — the one recorded exception to U6's
    /// single-vault-key schedule. Derived on demand, never stored; the
    /// caller ([`crate::vault::wallet`]) drops it after the record
    /// operation, and [`VaultKey`] wipes on that drop.
    ///
    /// Label separation is the whole mechanism: the sub-key is
    /// computationally independent of the vault key (HKDF-Expand under a
    /// distinct `info`), so corrupting/decrypting one domain says nothing
    /// about the other, and a future external-signer build can delete the
    /// wallet record without touching any work record's key schedule.
    /// # Errors
    ///
    /// [`CliError::Internal`] on HKDF-Expand failure — structurally
    /// unreachable for a fixed 32-byte output (32 ≤ 255·HashLen), kept
    /// total rather than panicking, and never degraded into a silent
    /// all-zero key (which the *encrypt* side would happily use).
    pub(crate) fn wallet_subkey(&self) -> Result<VaultKey, CliError> {
        use hkdf::Hkdf;
        use sha2::Sha256;
        use zeroize::Zeroize;

        let hk = Hkdf::<Sha256>::new(Some(&[]), self.key.as_bytes());
        let mut okm = [0u8; 32];
        hk.expand(super::wallet::WALLET_SUBKEY_INFO, &mut okm)
            .map_err(|_| CliError::Internal {
                detail: "HKDF-Expand failed for the fixed-length wallet sub-key".to_owned(),
            })?;
        let key = VaultKey::from_bytes(okm);
        okm.zeroize();
        Ok(key)
    }
}

/// Create a fresh vault (the primitive under U11's `init`).
///
/// # Errors
///
/// [`CliError::Usage`] when a vault already exists at the layout root;
/// [`CliError::VaultKdfMemory`] when the KDF arena cannot be allocated
/// (no vault is created); I/O errors from the atomic writes.
pub fn create_vault<R: TryCryptoRng + ?Sized>(
    layout: &VaultLayout,
    passphrase: &SecretBuf,
    selection: KdfSelection,
    rng: &mut R,
) -> Result<UnlockedVault, CliError> {
    create_vault_impl(
        layout,
        passphrase,
        selection,
        &WrapChoice::None,
        rng,
        KdfFailPoint::None,
    )
}

/// Create a vault with an explicit D50 wrap choice (U8).
///
/// [`create_vault`] is this with [`WrapChoice::None`] — kept as the
/// mode-0 name so no existing caller has to say "no wrap" to mean the
/// default, and so U6's whole suite keeps exercising the unwrapped path
/// byte for byte.
///
/// # Errors
///
/// As [`create_vault`], plus [`CliError::Usage`] when the keyfile path
/// already exists (never overwritten — it might be another vault's only
/// second factor) and [`CliError::Io`] for a failed keyfile write.
pub fn create_vault_with_wrap<R: TryCryptoRng + ?Sized>(
    layout: &VaultLayout,
    passphrase: &SecretBuf,
    selection: KdfSelection,
    wrap: &WrapChoice,
    rng: &mut R,
) -> Result<UnlockedVault, CliError> {
    create_vault_impl(layout, passphrase, selection, wrap, rng, KdfFailPoint::None)
}

pub(crate) fn create_vault_impl<R: TryCryptoRng + ?Sized>(
    layout: &VaultLayout,
    passphrase: &SecretBuf,
    selection: KdfSelection,
    wrap: &WrapChoice,
    rng: &mut R,
    fail: KdfFailPoint,
) -> Result<UnlockedVault, CliError> {
    let header_path = layout.beside_path(super::layout::BesideFile::Header);
    if header_path.exists() {
        return Err(CliError::Usage {
            message: format!(
                "a vault already exists at {} — antseal never overwrites a vault (D39)",
                layout.root().display()
            ),
        });
    }

    // Directories first (idempotent), then the KDF (the fallible step, so
    // a low-RAM machine leaves at most empty directories behind).
    let io_err = |context: String| move |source| CliError::Io { context, source };
    std::fs::create_dir_all(layout.works_dir())
        .map_err(io_err(format!("creating {}", layout.works_dir().display())))?;

    let params = KdfParams::generate(selection, rng).map_err(CliError::from)?;
    let kdf_block = params.encode().map_err(CliError::from)?;
    let recorded_path = match wrap {
        WrapChoice::None => None,
        WrapChoice::Keyfile {
            path,
            record_path: true,
        } => Some(path.to_string_lossy().into_owned()),
        WrapChoice::Keyfile {
            record_path: false, ..
        } => None,
    };
    let header = VaultHeader::new_with_keyfile_path(kdf_block, wrap.mode(), recorded_path)
        .map_err(CliError::from)?;
    let header_bytes = header.encode().map_err(CliError::from)?;

    let key = params
        .derive_key_impl(passphrase, fail)
        .map_err(CliError::from)?;

    // The keyfile is generated AFTER the KDF (the expensive, failable
    // step) and BEFORE the header is written: the header's presence is
    // the "vault exists" marker, so a failure here — a bad path, a
    // read-only medium, a file already there — leaves no vault at all
    // rather than one whose second factor was never created.
    let key = match wrap {
        WrapChoice::None => key,
        WrapChoice::Keyfile { path, .. } => {
            let secret = keyfile::generate(path, rng)?;
            keyfile::combine(&key, &secret)?
        }
    };

    let vault = UnlockedVault {
        layout: layout.clone(),
        header_bytes,
        key,
    };

    // Check record before the header: header presence marks "vault
    // exists", so no crash window shows a vault whose unlock must fail.
    let check_blob = vault.seal_record(RecordIdentity::KeyCheck, KEY_CHECK_PLAINTEXT, rng)?;
    let check_path = layout.check_record_path();
    atomic_write(&check_path, &check_blob)
        .map_err(io_err(format!("writing {}", check_path.display())))?;
    atomic_write(&header_path, &vault.header_bytes)
        .map_err(io_err(format!("writing {}", header_path.display())))?;

    Ok(vault)
}

/// Unlock an existing vault.
///
/// # Errors
///
/// [`CliError::Usage`] when no vault exists at the layout root;
/// [`CliError::VaultNewerVersion`] /
/// [`CliError::VaultKdfParamsOutOfRange`] / [`CliError::VaultKdfMemory`]
/// per their decision-fixed semantics; [`CliError::VaultAuthFailure`] for
/// a wrong passphrase, a tampered header, or a corrupt store.
pub fn unlock_vault(
    layout: &VaultLayout,
    passphrase: &SecretBuf,
) -> Result<UnlockedVault, CliError> {
    unlock_vault_impl(layout, passphrase, None, KdfFailPoint::None)
}

/// Unlock, supplying the keyfile path explicitly (U8).
///
/// The canonical CLI surface carries no `--keyfile` flag, so production
/// unlocks pass `None` and the path comes from `ANTSEAL_KEYFILE` or the
/// header recording ([`super::keyfile::locate`]). This entry exists for
/// in-process callers and for tests, which must not race on a process-
/// global environment variable.
///
/// # Errors
///
/// As [`unlock_vault`], plus [`CliError::VaultKeyfileMissing`] and
/// [`CliError::VaultWrapModeUnsupported`].
pub fn unlock_vault_with_keyfile(
    layout: &VaultLayout,
    passphrase: &SecretBuf,
    keyfile_path: Option<&Path>,
) -> Result<UnlockedVault, CliError> {
    unlock_vault_impl(layout, passphrase, keyfile_path, KdfFailPoint::None)
}

/// **The only way a command may obtain an unlocked vault** (D99 R2): unlock,
/// and arm U24's opportunistic upgrade hook with the same handle, in one
/// expression.
///
/// D42's rule keys the hook on the dispatching command *already holding* an
/// unlocked handle. No point in the tree sees both every subcommand and a
/// vault — `run::run` takes a `&Cli`, every handler unlocks for itself, and
/// [`UnlockedVault`] is deliberately `!Clone` — so the handle is moved up into
/// a dispatcher-owned [`VaultSlot`] instead. Doing that as a separate step
/// after the unlock would be a step a handler could forget, and a handler that
/// forgot would be a command that silently skips the hook. Here it is not a
/// step at all: there is one expression, and it does both.
///
/// The other half is a scan —
/// `the_unlock_primitives_are_named_in_exactly_two_production_files` refuses
/// [`unlock_vault`]/[`unlock_vault_with_keyfile`] in any production source but
/// this one and `vault/export.rs` — so "a command that unlocked without
/// arming" is not merely discouraged, it is unrepresentable without reddening
/// a test that names the offending file.
///
/// `init` and `vault import` do **not** go through this, and that is a
/// correction to D42 rather than a deviation from it: measured (D99 §1.1),
/// neither holds a handle at the dispatch layer — `init` consumes the
/// [`create_vault`] result inside `run_init`, and `vault import`'s only unlock
/// is the self-verification inside `import_vault`. A fresh vault has nothing
/// to upgrade, and arming after an import would mean either threading the slot
/// through the import primitive's internals or paying a second ~1 s Argon2id
/// derivation for a vault the user's next command will unlock properly.
///
/// # Errors
///
/// As [`unlock_vault`].
pub(crate) fn unlock_for_command(
    layout: &VaultLayout,
    passphrase: &SecretBuf,
    slot: &crate::upgrade_hook::VaultSlot,
) -> Result<Arc<UnlockedVault>, CliError> {
    Ok(slot.arm(Arc::new(unlock_vault(layout, passphrase)?)))
}

pub(crate) fn unlock_vault_impl(
    layout: &VaultLayout,
    passphrase: &SecretBuf,
    explicit_keyfile: Option<&Path>,
    fail: KdfFailPoint,
) -> Result<UnlockedVault, CliError> {
    let header_path = layout.beside_path(super::layout::BesideFile::Header);
    let header_bytes = match read_bounded(&header_path, MAX_HEADER_BYTES + 1) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(CliError::Usage {
                message: format!(
                    "no vault exists at {} — run `antseal init` first",
                    layout.root().display()
                ),
            });
        }
        Err(source) => {
            return Err(CliError::Io {
                context: format!("reading {}", header_path.display()),
                source,
            });
        }
    };
    let header = VaultHeader::decode(&header_bytes).map_err(CliError::from)?;

    // D50's registry, dispatched before any expensive work. Mode 2 is a
    // registered id with no M1 implementation: its refusal is distinct,
    // says the vault is intact, and is emphatically NOT the generic auth
    // failure — that collapse exists to hide which secret-dependent step
    // failed, and nothing secret is involved in reading a mode byte.
    if header.wrap_mode() == WRAP_MODE_OS_KEYSTORE_RESERVED {
        return Err(CliError::VaultWrapModeUnsupported {
            mode: header.wrap_mode(),
            name: "os-keystore, reserved (D50)",
        });
    }

    // The keyfile is located BEFORE the KDF runs: an unplugged USB stick
    // should not cost a second of Argon2id first, and the answer does not
    // depend on the passphrase.
    let wrap_factor = if header.wrap_mode() == WRAP_MODE_KEYFILE {
        let path = keyfile::locate(explicit_keyfile, header.keyfile_path().map(Path::new))
            .ok_or_else(|| CliError::VaultKeyfileMissing {
                path: std::path::PathBuf::from("<no path known>"),
                detail: format!(
                    "this vault records no keyfile path, so one must be supplied — set \
                     {}=<path>",
                    super::keyfile::KEYFILE_ENV
                ),
            })?;
        Some(keyfile::read_from(&path)?)
    } else {
        None
    };

    // D40 §3: caps inside this decode run before any KDF allocation.
    let params = KdfParams::decode(header.kdf_block()).map_err(CliError::from)?;
    let key = params
        .derive_key_impl(passphrase, fail)
        .map_err(CliError::from)?;
    let key = match &wrap_factor {
        Some(secret) => keyfile::combine(&key, secret)?,
        None => key,
    };

    let vault = UnlockedVault {
        layout: layout.clone(),
        header_bytes,
        key,
    };

    // The key check: wrong passphrase, edited header, and corrupt store
    // all collapse here into the one vault-auth failure.
    let check_path = layout.check_record_path();
    let check_blob = match read_bounded(&check_path, MAX_CHECK_RECORD_BYTES) {
        Ok(bytes) => bytes,
        // A vault with a header but no (or an unreadable) check record is
        // corrupt: same collapse.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(CliError::VaultAuthFailure);
        }
        Err(source) => {
            return Err(CliError::Io {
                context: format!("reading {}", check_path.display()),
                source,
            });
        }
    };
    let plaintext = vault.open_record(RecordIdentity::KeyCheck, &check_blob)?;
    if plaintext.as_bytes() != KEY_CHECK_PLAINTEXT {
        return Err(CliError::VaultAuthFailure);
    }
    Ok(vault)
}

/// Read a file with a hard byte cap (defensive: beside-files are
/// adversary-suppliable, so no read may be unbounded). Returns raw
/// `io::Error` so callers can branch on `NotFound`. Shared with the
/// wallet-record (U10) and export (U12) readers.
pub(crate) fn read_bounded(path: &Path, cap: usize) -> std::io::Result<Vec<u8>> {
    let file = std::fs::File::open(path)?;
    let mut bytes = Vec::new();
    // `cap` is a small constant; the +0/+1 slack is the caller's choice.
    file.take(cap as u64).read_to_end(&mut bytes)?;
    Ok(bytes)
}

/// The D40 §2 low-RAM matrix. Lives with the primitive (the failpoint
/// seam is crate-private), exactly like the U5 kill matrix in `fs.rs`;
/// the rest of the U6 acceptance suite is `tests/vault_encryption.rs`.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::ErrorClass;
    use crate::vault::layout::BesideFile;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;
    use std::path::PathBuf;

    /// Fixed, public, NON-SECRET fixtures (project rule 6).
    const TEST_RNG_SEED: [u8; 32] = [0x42u8; 32];
    const FIXTURE_PASSPHRASE: &[u8] = b"correct horse battery staple fixture";

    fn passphrase() -> SecretBuf {
        SecretBuf::new(FIXTURE_PASSPHRASE.to_vec())
    }

    struct TestDir(PathBuf);

    impl TestDir {
        fn new(tag: &str) -> Self {
            use std::sync::atomic::{AtomicU64, Ordering};
            static SEQ: AtomicU64 = AtomicU64::new(0);
            let dir = std::env::temp_dir().join(format!(
                "antseal-cli-session-{tag}-{}-{}",
                std::process::id(),
                SEQ.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir_all(&dir).expect("create test dir");
            TestDir(dir)
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// Simulated allocation failure at CREATE: the typed
    /// `vault-kdf-memory` error (exit 13), no fallback path (the outcome
    /// IS the error — no prompt exists and no scrypt substitution
    /// happens: scrypt needs MORE memory, D40's arithmetic), and no vault
    /// is left behind — the same create succeeds once the "RAM" returns.
    #[test]
    fn low_ram_at_create_is_typed_and_leaves_no_vault() {
        let dir = TestDir::new("lowram-create");
        let layout = VaultLayout::at(dir.0.join("vault"));
        let mut rng = ChaCha20Rng::from_seed(TEST_RNG_SEED);
        let err = create_vault_impl(
            &layout,
            &passphrase(),
            KdfSelection::Argon2id,
            &WrapChoice::None,
            &mut rng,
            KdfFailPoint::AllocFails,
        )
        .expect_err("simulated allocation failure");
        assert_eq!(err.class(), ErrorClass::VaultKdfMemory);
        assert_eq!(err.exit_code(), 13);
        let rendered = err.to_string();
        assert!(
            rendered.contains("256 MiB"),
            "actionable floor figure: {rendered}"
        );
        assert!(
            !layout.beside_path(BesideFile::Header).exists(),
            "no vault may exist after a failed create"
        );
        assert!(
            !layout.check_record_path().exists(),
            "no check record may exist after a failed create"
        );
        // The machine gets its memory back: the identical create now
        // succeeds — nothing was half-written.
        create_vault(&layout, &passphrase(), KdfSelection::Argon2id, &mut rng)
            .expect("clean create after failure");
    }

    /// **D99 R2's scan.** The two unlock primitives are nameable in production
    /// sources in exactly two places: here, where they are defined, and
    /// `vault/export.rs`, whose import primitive unlocks the freshly-installed
    /// vault to self-verify it.
    ///
    /// A third file is a **command that unlocked without arming U24's hook**.
    /// That compiles, it runs, and it is silently wrong in the way D42's rule
    /// is designed to make impossible: the command holds a vault, so the hook
    /// is owed a pass, and it silently gets none. Nothing about it is a type
    /// error, so it has to be a failing test — the same shape, and the same
    /// reasoning, as S36's two scans one module over.
    ///
    /// Test modules are exempt by construction (`production_files_naming` cuts
    /// each file at its first `#[cfg(test)]`), because the suites unlock
    /// directly on purpose: a harness has no dispatcher and no slot, and a
    /// rule that could not tell the two apart would be switched off the first
    /// time it fired.
    #[test]
    fn the_unlock_primitives_are_named_in_exactly_two_production_files() {
        let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let expected = ["vault/export.rs".to_owned(), "vault/session.rs".to_owned()];
        for needle in ["unlock_vault(", "unlock_vault_with_keyfile("] {
            let (named, visited) = crate::seal_session::production_files_naming(&src, needle);
            assert!(
                visited > 20,
                "the scan visited only {visited} source files — it is not looking where it thinks"
            );
            assert!(
                named.iter().all(|file| expected.contains(file)),
                "`{needle}` is named in a production source that is neither its definition nor \
                 the import primitive: {named:?}. A command that calls it directly has unlocked \
                 a vault WITHOUT arming U24's opportunistic upgrade hook — D42's rule says the \
                 hook runs iff the dispatching command holds an unlocked handle, and this one \
                 would hold one and never hand it up. Go through \
                 `vault::session::unlock_for_command`, which unlocks and arms in one expression \
                 (D99 R2)"
            );
        }
        // Anti-vacuity: the definitions themselves must be found, or the scan
        // is reporting a clean tree because it is looking at nothing.
        let (named, _) = crate::seal_session::production_files_naming(&src, "unlock_vault(");
        assert!(
            named.contains(&"vault/session.rs".to_owned()),
            "the scan did not even find the definition: {named:?}"
        );
    }

    /// Simulated allocation failure at UNLOCK: same typed error, same
    /// code — a vault created on a capable machine is not openable on one
    /// that cannot allocate its recorded `m`, and nothing weaker is
    /// offered; the vault itself is untouched.
    #[test]
    fn low_ram_at_unlock_is_typed_and_vault_survives() {
        let dir = TestDir::new("lowram-unlock");
        let layout = VaultLayout::at(dir.0.join("vault"));
        let mut rng = ChaCha20Rng::from_seed(TEST_RNG_SEED);
        create_vault(&layout, &passphrase(), KdfSelection::Argon2id, &mut rng).expect("create");
        let err = unlock_vault_impl(&layout, &passphrase(), None, KdfFailPoint::AllocFails)
            .expect_err("simulated allocation failure");
        assert_eq!(err.class(), ErrorClass::VaultKdfMemory);
        assert_eq!(err.exit_code(), 13);
        // The real unlock still works: the failure wrote nothing.
        unlock_vault(&layout, &passphrase()).expect("vault unharmed");
    }
}
