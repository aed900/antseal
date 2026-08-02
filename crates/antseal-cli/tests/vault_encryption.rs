//! U6 acceptance suite: vault encryption — KDF KATs, the D40 §3 pre-auth
//! caps, header-bound AAD tamper behavior, low-RAM typed errors, and the
//! create/unlock round trips at the frozen parameters.
//!
//! House checklist: the KDF block has committed golden vectors and a
//! tamper matrix in which every mutation fails with its distinct, asserted
//! error class. The RFC 9106 / RFC 7914 known-answer vectors pin the KDF
//! crates: a swap or bump that changes output bytes goes loud here, which
//! matters because KDF output bytes are vault-format bytes (D40).
//!
//! NON-SECRET: every passphrase, salt, and seed in this file is a
//! documented public fixture (project rule 6).
//!
//! Cost note: the round trips run the REAL frozen parameters — Argon2id
//! 256 MiB and scrypt 1 GiB — which is the point (U6's Accept measures the
//! real thing). The workspace `[profile.dev.package.*]` overrides keep the
//! debug-mode cost in seconds; unlock-side scenarios share one created
//! vault via `OnceLock` and tamper on copies, so creation is paid once.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use antseal_cli::error::{CliError, ErrorClass};
use antseal_cli::vault::header::{VaultHeader, WRAP_MODE_KEYFILE};
use antseal_cli::vault::kdf::{
    ARGON2ID_M_COST_KIB, ARGON2ID_T_COST, KDF_ALG_ARGON2ID, KDF_ALG_SCRYPT, KdfError, KdfParams,
    KdfSelection, SCRYPT_LOG2_N, SCRYPT_R,
};
use antseal_cli::vault::layout::{BesideFile, VaultLayout};
use antseal_cli::vault::session::{create_vault, unlock_vault};
use antseal_core::codec::encode_item;
use antseal_core::crypto::secrets::SecretBuf;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

// ─────────────────────────────────────────────────────────────────────
// Test scaffolding
// ─────────────────────────────────────────────────────────────────────

/// Fixed, public, NON-SECRET fixtures (project rule 6).
const TEST_RNG_SEED: [u8; 32] = [0x42u8; 32];
const FIXTURE_PASSPHRASE: &[u8] = b"correct horse battery staple fixture";
const WRONG_PASSPHRASE: &[u8] = b"wrong horse battery staple fixture!!";
const FIXTURE_SALT: [u8; 16] = [0x0F; 16];

fn passphrase() -> SecretBuf {
    SecretBuf::new(FIXTURE_PASSPHRASE.to_vec())
}

struct TestDir(PathBuf);

impl TestDir {
    fn new(tag: &str) -> Self {
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "antseal-cli-enc-{tag}-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).expect("create test dir");
        TestDir(dir)
    }
    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The one shared Argon2id vault (creation paid once for every
/// unlock-side scenario; tamper tests copy it first).
struct SharedVault {
    // Held for its Drop (directory cleanup at process exit is
    // best-effort; the TestDir lives as long as the suite).
    _dir: TestDir,
    layout: VaultLayout,
}

fn shared_vault() -> &'static SharedVault {
    static VAULT: OnceLock<SharedVault> = OnceLock::new();
    VAULT.get_or_init(|| {
        let dir = TestDir::new("shared");
        let layout = VaultLayout::at(dir.path().join("vault"));
        let mut rng = ChaCha20Rng::from_seed(TEST_RNG_SEED);
        create_vault(&layout, &passphrase(), KdfSelection::Argon2id, &mut rng)
            .expect("create shared vault");
        SharedVault { _dir: dir, layout }
    })
}

/// Copy a vault's on-disk state into a fresh directory (tamper substrate).
fn clone_vault(src: &VaultLayout, tag: &str) -> (TestDir, VaultLayout) {
    let dir = TestDir::new(tag);
    let dst = VaultLayout::at(dir.path().join("vault"));
    std::fs::create_dir_all(dst.works_dir()).expect("mk store dirs");
    for file in [BesideFile::Header, BesideFile::Config, BesideFile::Lockfile] {
        let from = src.beside_path(file);
        if from.exists() {
            std::fs::copy(&from, dst.beside_path(file)).expect("copy beside file");
        }
    }
    if src.check_record_path().exists() {
        std::fs::copy(src.check_record_path(), dst.check_record_path()).expect("copy check");
    }
    (dir, dst)
}

/// Craft a raw v1 KDF block from arbitrary field values (tamper harness —
/// deliberately bypasses `KdfParams`' validating constructors).
fn craft_block(alg: u64, salt: &[u8], f2: u64, f3: u64, f4: u64) -> Vec<u8> {
    encode_item(|e| {
        e.map(|m| {
            m.entry(0, |e| e.u64(alg))?;
            m.entry(1, |e| e.bytes(salt))?;
            m.entry(2, |e| e.u64(f2))?;
            m.entry(3, |e| e.u64(f3))?;
            m.entry(4, |e| e.u64(f4))
        })
    })
    .expect("craft block")
}

/// Replace the shared vault copy's header with one carrying `block`.
fn install_block(layout: &VaultLayout, block: Vec<u8>, wrap_mode: u8) {
    let header = VaultHeader::new(block, wrap_mode).expect("craft header");
    antseal_cli::vault::fs::atomic_write(
        &layout.beside_path(BesideFile::Header),
        &header.encode().expect("encode header"),
    )
    .expect("install header");
}

// ─────────────────────────────────────────────────────────────────────
// Known-answer vectors (the pin gates)
// ─────────────────────────────────────────────────────────────────────

/// RFC 9106 §5.3 — the Argon2id v0x13 known-answer vector, run through
/// the same caller-allocated-arena entry point production uses. A crate
/// swap or bump that changes output bytes fails here first.
#[test]
fn rfc9106_argon2id_known_answer() {
    let params = {
        let mut b = argon2::ParamsBuilder::new();
        b.m_cost(32)
            .t_cost(3)
            .p_cost(4)
            .data(argon2::AssociatedData::new(&[0x04; 12]).expect("associated data"));
        b.build().expect("params")
    };
    let secret = [0x03u8; 8];
    let ctx = argon2::Argon2::new_with_secret(
        &secret,
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        params.clone(),
    )
    .expect("context");
    let mut arena = vec![argon2::Block::default(); params.block_count()];
    let mut out = [0u8; 32];
    ctx.hash_password_into_with_memory(&[0x01; 32], &[0x02; 16], &mut out, arena.as_mut_slice())
        .expect("derive");
    const EXPECTED: [u8; 32] = [
        0x0d, 0x64, 0x0d, 0xf5, 0x8d, 0x78, 0x76, 0x6c, 0x08, 0xc0, 0x37, 0xa3, 0x4a, 0x8b, 0x53,
        0xc9, 0xd0, 0x1e, 0xf0, 0x45, 0x2d, 0x75, 0xb6, 0x5e, 0xb5, 0x25, 0x20, 0xe9, 0x6b, 0x01,
        0xe6, 0x59,
    ];
    assert_eq!(out, EXPECTED, "RFC 9106 §5.3 Argon2id tag mismatch");
}

/// RFC 7914 §12 — scrypt known-answer vectors 1–3 (vector 4, at the
/// production N = 2²⁰, runs in the scrypt round trip's cost class and has
/// its own test below).
#[test]
fn rfc7914_scrypt_known_answers() {
    struct Vector {
        password: &'static [u8],
        salt: &'static [u8],
        log_n: u8,
        r: u32,
        p: u32,
        expected: [u8; 64],
    }
    let vectors = [
        Vector {
            password: b"",
            salt: b"",
            log_n: 4,
            r: 1,
            p: 1,
            expected: [
                0x77, 0xd6, 0x57, 0x62, 0x38, 0x65, 0x7b, 0x20, 0x3b, 0x19, 0xca, 0x42, 0xc1, 0x8a,
                0x04, 0x97, 0xf1, 0x6b, 0x48, 0x44, 0xe3, 0x07, 0x4a, 0xe8, 0xdf, 0xdf, 0xfa, 0x3f,
                0xed, 0xe2, 0x14, 0x42, 0xfc, 0xd0, 0x06, 0x9d, 0xed, 0x09, 0x48, 0xf8, 0x32, 0x6a,
                0x75, 0x3a, 0x0f, 0xc8, 0x1f, 0x17, 0xe8, 0xd3, 0xe0, 0xfb, 0x2e, 0x0d, 0x36, 0x28,
                0xcf, 0x35, 0xe2, 0x0c, 0x38, 0xd1, 0x89, 0x06,
            ],
        },
        Vector {
            password: b"password",
            salt: b"NaCl",
            log_n: 10,
            r: 8,
            p: 16,
            expected: [
                0xfd, 0xba, 0xbe, 0x1c, 0x9d, 0x34, 0x72, 0x00, 0x78, 0x56, 0xe7, 0x19, 0x0d, 0x01,
                0xe9, 0xfe, 0x7c, 0x6a, 0xd7, 0xcb, 0xc8, 0x23, 0x78, 0x30, 0xe7, 0x73, 0x76, 0x63,
                0x4b, 0x37, 0x31, 0x62, 0x2e, 0xaf, 0x30, 0xd9, 0x2e, 0x22, 0xa3, 0x88, 0x6f, 0xf1,
                0x09, 0x27, 0x9d, 0x98, 0x30, 0xda, 0xc7, 0x27, 0xaf, 0xb9, 0x4a, 0x83, 0xee, 0x6d,
                0x83, 0x60, 0xcb, 0xdf, 0xa2, 0xcc, 0x06, 0x40,
            ],
        },
        Vector {
            password: b"pleaseletmein",
            salt: b"SodiumChloride",
            log_n: 14,
            r: 8,
            p: 1,
            expected: [
                0x70, 0x23, 0xbd, 0xcb, 0x3a, 0xfd, 0x73, 0x48, 0x46, 0x1c, 0x06, 0xcd, 0x81, 0xfd,
                0x38, 0xeb, 0xfd, 0xa8, 0xfb, 0xba, 0x90, 0x4f, 0x8e, 0x3e, 0xa9, 0xb5, 0x43, 0xf6,
                0x54, 0x5d, 0xa1, 0xf2, 0xd5, 0x43, 0x29, 0x55, 0x61, 0x3f, 0x0f, 0xcf, 0x62, 0xd4,
                0x97, 0x05, 0x24, 0x2a, 0x9a, 0xf9, 0xe6, 0x1e, 0x85, 0xdc, 0x0d, 0x65, 0x1e, 0x40,
                0xdf, 0xcf, 0x01, 0x7b, 0x45, 0x57, 0x58, 0x87,
            ],
        },
    ];
    for v in vectors {
        let params = scrypt::Params::new(v.log_n, v.r, v.p).expect("params");
        let mut out = [0u8; 64];
        scrypt::scrypt(v.password, v.salt, &params, &mut out).expect("derive");
        assert_eq!(
            out, v.expected,
            "RFC 7914 vector (log_n={}) mismatch",
            v.log_n
        );
    }
}

/// RFC 7914 §12 vector 4 — the one at the production floor N = 2²⁰
/// (1 GiB): pins the crate at exactly the parameter shape every scrypt
/// vault runs.
#[test]
fn rfc7914_scrypt_known_answer_at_production_n() {
    let params = scrypt::Params::new(20, 8, 1).expect("params");
    let mut out = [0u8; 64];
    scrypt::scrypt(b"pleaseletmein", b"SodiumChloride", &params, &mut out).expect("derive");
    const EXPECTED: [u8; 64] = [
        0x21, 0x01, 0xcb, 0x9b, 0x6a, 0x51, 0x1a, 0xae, 0xad, 0xdb, 0xbe, 0x09, 0xcf, 0x70, 0xf8,
        0x81, 0xec, 0x56, 0x8d, 0x57, 0x4a, 0x2f, 0xfd, 0x4d, 0xab, 0xe5, 0xee, 0x98, 0x20, 0xad,
        0xaa, 0x47, 0x8e, 0x56, 0xfd, 0x8f, 0x4b, 0xa5, 0xd0, 0x9f, 0xfa, 0x1c, 0x6d, 0x92, 0x7c,
        0x40, 0xf4, 0xc3, 0x37, 0x30, 0x40, 0x49, 0xe8, 0xa9, 0x52, 0xfb, 0xcb, 0xf4, 0x5c, 0x6f,
        0xa7, 0x7a, 0x41, 0xa4,
    ];
    assert_eq!(out, EXPECTED, "RFC 7914 N=2^20 vector mismatch");
}

// ─────────────────────────────────────────────────────────────────────
// KDF block: golden vectors + round trip
// ─────────────────────────────────────────────────────────────────────

/// Golden vectors for the v1 KDF block encoding (fixture salt): byte
/// drift here is a vault-format break.
#[test]
fn kdf_block_golden_vectors() {
    // map(5){0: 1, 1: h'0f'*16, 2: 262144, 3: 3, 4: 1}
    let mut argon2id_expected = vec![0xa5, 0x00, 0x01, 0x01, 0x50];
    argon2id_expected.extend_from_slice(&FIXTURE_SALT);
    argon2id_expected
        .extend_from_slice(&[0x02, 0x1a, 0x00, 0x04, 0x00, 0x00, 0x03, 0x03, 0x04, 0x01]);
    let block = craft_block(KDF_ALG_ARGON2ID, &FIXTURE_SALT, 262_144, 3, 1);
    assert_eq!(block, argon2id_expected, "argon2id golden block");
    let params = KdfParams::decode(&block).expect("golden decodes");
    assert_eq!(params.encode().expect("re-encode"), argon2id_expected);

    // map(5){0: 2, 1: h'0f'*16, 2: 20, 3: 8, 4: 1}
    let mut scrypt_expected = vec![0xa5, 0x00, 0x02, 0x01, 0x50];
    scrypt_expected.extend_from_slice(&FIXTURE_SALT);
    scrypt_expected.extend_from_slice(&[0x02, 0x14, 0x03, 0x08, 0x04, 0x01]);
    let block = craft_block(KDF_ALG_SCRYPT, &FIXTURE_SALT, 20, 8, 1);
    assert_eq!(block, scrypt_expected, "scrypt golden block");
    let params = KdfParams::decode(&block).expect("golden decodes");
    assert_eq!(params.encode().expect("re-encode"), scrypt_expected);
}

/// Generated creation parameters carry exactly the frozen D40 values and
/// round-trip through the block encoding.
#[test]
fn generated_params_are_frozen_values_and_round_trip() {
    let mut rng = ChaCha20Rng::from_seed(TEST_RNG_SEED);
    for selection in [KdfSelection::Argon2id, KdfSelection::Scrypt] {
        let params = KdfParams::generate(selection, &mut rng).expect("generate");
        let bytes = params.encode().expect("encode");
        let reparsed = KdfParams::decode(&bytes).expect("decode");
        assert_eq!(params, reparsed, "{selection:?} round trip");
    }
    // Two generations draw distinct salts (the RNG is really consulted).
    let a = KdfParams::generate(KdfSelection::Argon2id, &mut rng).expect("generate");
    let b = KdfParams::generate(KdfSelection::Argon2id, &mut rng).expect("generate");
    assert_ne!(a, b, "fresh salt per generation");
}

// ─────────────────────────────────────────────────────────────────────
// D40 §3: the pre-auth cap matrix (no KDF ever runs on these)
// ─────────────────────────────────────────────────────────────────────

/// Every out-of-window parameter is rejected at decode with the distinct
/// params-out-of-range class (exit 14) — before any KDF allocation. The
/// header-substitution resource bomb (1 TiB `m`) dies here.
#[test]
fn pre_auth_caps_reject_out_of_range_params() {
    let m = u64::from(ARGON2ID_M_COST_KIB);
    let below_above: &[(&str, Vec<u8>)] = &[
        // Argon2id m below floor (the "downgrade" direction — dies at the
        // caps, before any AEAD could even be consulted) and above cap
        // (the 1 TiB resource bomb: 2^30 KiB).
        (
            "m below floor",
            craft_block(KDF_ALG_ARGON2ID, &FIXTURE_SALT, m - 1, 3, 1),
        ),
        (
            "m at half floor",
            craft_block(KDF_ALG_ARGON2ID, &FIXTURE_SALT, m / 2, 3, 1),
        ),
        (
            "m of 1 TiB",
            craft_block(KDF_ALG_ARGON2ID, &FIXTURE_SALT, 1 << 30, 3, 1),
        ),
        (
            "m beyond u32",
            craft_block(KDF_ALG_ARGON2ID, &FIXTURE_SALT, u64::MAX, 3, 1),
        ),
        (
            "t below floor",
            craft_block(KDF_ALG_ARGON2ID, &FIXTURE_SALT, m, 2, 1),
        ),
        (
            "t above cap",
            craft_block(KDF_ALG_ARGON2ID, &FIXTURE_SALT, m, 65, 1),
        ),
        (
            "p of 0",
            craft_block(KDF_ALG_ARGON2ID, &FIXTURE_SALT, m, 3, 0),
        ),
        (
            "p of 2",
            craft_block(KDF_ALG_ARGON2ID, &FIXTURE_SALT, m, 3, 2),
        ),
        // scrypt windows.
        (
            "log2N below floor",
            craft_block(KDF_ALG_SCRYPT, &FIXTURE_SALT, 19, 8, 1),
        ),
        (
            "log2N above cap",
            craft_block(KDF_ALG_SCRYPT, &FIXTURE_SALT, 25, 8, 1),
        ),
        (
            "scrypt r of 1",
            craft_block(KDF_ALG_SCRYPT, &FIXTURE_SALT, 20, 1, 1),
        ),
        (
            "scrypt p of 2",
            craft_block(KDF_ALG_SCRYPT, &FIXTURE_SALT, 20, 8, 2),
        ),
        // Unregistered algorithm ids.
        ("alg id 0", craft_block(0, &FIXTURE_SALT, 20, 8, 1)),
        ("alg id 3", craft_block(3, &FIXTURE_SALT, 20, 8, 1)),
    ];
    for (what, block) in below_above {
        let err = KdfParams::decode(block).expect_err(what);
        assert!(
            matches!(err, KdfError::ParamsOutOfRange { .. }),
            "{what}: wrong class: {err:?}"
        );
        let cli: CliError = err.into();
        assert_eq!(
            cli.class(),
            ErrorClass::VaultKdfParamsOutOfRange,
            "{what}: wrong CLI class"
        );
        assert_eq!(cli.exit_code(), 14, "{what}: wrong exit code");
    }
}

/// Malformed blocks (schema violations rather than range violations)
/// collapse into the vault-auth class, indistinguishable from tamper.
#[test]
fn malformed_blocks_collapse_to_vault_auth() {
    let cases: Vec<(&str, Vec<u8>)> = vec![
        (
            "salt of 8 bytes",
            craft_block(KDF_ALG_ARGON2ID, &[0x0F; 8], 262_144, 3, 1),
        ),
        (
            "salt of 17 bytes",
            craft_block(KDF_ALG_ARGON2ID, &[0x0F; 17], 262_144, 3, 1),
        ),
        ("empty bytes", Vec::new()),
        ("garbage bytes", vec![0xFF, 0x00, 0xAB]),
        // A 4-entry map (missing p).
        (
            "missing field",
            encode_item(|e| {
                e.map(|m| {
                    m.entry(0, |e| e.u64(KDF_ALG_ARGON2ID))?;
                    m.entry(1, |e| e.bytes(&FIXTURE_SALT))?;
                    m.entry(2, |e| e.u64(262_144))?;
                    m.entry(3, |e| e.u64(3))
                })
            })
            .expect("craft"),
        ),
    ];
    for (what, block) in cases {
        let err = KdfParams::decode(&block).expect_err(what);
        let cli: CliError = err.into();
        assert_eq!(cli.class(), ErrorClass::VaultAuthFailure, "{what}");
        assert_eq!(cli.exit_code(), 12, "{what}");
    }
}

// ─────────────────────────────────────────────────────────────────────
// Create / unlock round trips at the frozen parameters
// ─────────────────────────────────────────────────────────────────────

/// Argon2id (the default): create → unlock with the right passphrase
/// succeeds; the wrong passphrase fails with the vault-auth code.
#[test]
fn argon2id_round_trip_and_wrong_passphrase() {
    let vault = shared_vault();
    let unlocked = unlock_vault(&vault.layout, &passphrase()).expect("unlock");
    assert_eq!(
        unlocked.header_bytes(),
        std::fs::read(vault.layout.beside_path(BesideFile::Header))
            .expect("read header")
            .as_slice(),
        "the handle carries the exact on-disk header bytes (the AAD)"
    );

    let err = unlock_vault(&vault.layout, &SecretBuf::new(WRONG_PASSPHRASE.to_vec()))
        .expect_err("wrong passphrase must fail");
    assert_eq!(err.class(), ErrorClass::VaultAuthFailure);
    assert_eq!(err.exit_code(), 12);
}

/// scrypt (explicit-only): the same round trip at N = 2²⁰, r = 8, p = 1 —
/// the 1 GiB path, exercised for real.
#[test]
fn scrypt_round_trip() {
    let dir = TestDir::new("scrypt");
    let layout = VaultLayout::at(dir.path().join("vault"));
    let mut rng = ChaCha20Rng::from_seed(TEST_RNG_SEED);
    create_vault(&layout, &passphrase(), KdfSelection::Scrypt, &mut rng).expect("create");
    unlock_vault(&layout, &passphrase()).expect("unlock");
    // The header records algorithm id 2 (the explicit selection is what
    // every later unlock keys on — no automatic path chooses it).
    let header_bytes = std::fs::read(layout.beside_path(BesideFile::Header)).expect("read header");
    let header = VaultHeader::decode(&header_bytes).expect("decode header");
    let params = KdfParams::decode(header.kdf_block()).expect("decode block");
    // 1 GiB V array + the small B/T buffers = 1025 MiB exact peak.
    assert_eq!(
        params.required_mib(),
        1025,
        "the scrypt floor is the 1 GiB shape"
    );
    let _ = (SCRYPT_LOG2_N, SCRYPT_R); // constants asserted via required_mib
}

/// A second vault created with the same passphrase draws a different salt
/// and therefore a different key: its records cannot open under the first
/// vault's header (cross-vault splice fails on both key and AAD).
#[test]
fn distinct_vaults_have_distinct_keys() {
    let vault = shared_vault();
    let dir = TestDir::new("second");
    let layout = VaultLayout::at(dir.path().join("vault"));
    // A different RNG seed → a different salt.
    let mut rng = ChaCha20Rng::from_seed([0x24u8; 32]);
    create_vault(&layout, &passphrase(), KdfSelection::Argon2id, &mut rng).expect("create");
    // Splice the second vault's check record into the first vault.
    let (_tamper_dir, tampered) = clone_vault(&vault.layout, "cross-splice");
    std::fs::copy(layout.check_record_path(), tampered.check_record_path())
        .expect("splice check record");
    let err = unlock_vault(&tampered, &passphrase()).expect_err("cross-vault splice");
    assert_eq!(err.class(), ErrorClass::VaultAuthFailure);
}

// ─────────────────────────────────────────────────────────────────────
// Header/parameter tamper on a valid vault
// ─────────────────────────────────────────────────────────────────────

/// The spec-mandated downgrade direction: a lowered `m` (and lowered `N`
/// for scrypt) in the header of a valid vault. Under D40 §3 the floors sit
/// AT the creation values, so the downgrade dies at the pre-auth caps with
/// the distinct params-out-of-range error — **before any KDF runs or any
/// allocation happens** — which is strictly stronger than the
/// auth-failure the task text imagined (recorded deviation, tasks/U.md
/// U6). No path opens a vault with weakened parameters.
#[test]
fn downgraded_params_are_rejected_pre_auth() {
    let vault = shared_vault();
    for (what, block) in [
        (
            "halved m",
            craft_block(
                KDF_ALG_ARGON2ID,
                &FIXTURE_SALT,
                u64::from(ARGON2ID_M_COST_KIB) / 2,
                3,
                1,
            ),
        ),
        (
            "scrypt N of 2^19",
            craft_block(KDF_ALG_SCRYPT, &FIXTURE_SALT, 19, 8, 1),
        ),
    ] {
        let (_dir, tampered) = clone_vault(&vault.layout, "downgrade");
        install_block(&tampered, block, antseal_cli::vault::header::WRAP_MODE_NONE);
        let err = unlock_vault(&tampered, &passphrase()).expect_err(what);
        assert_eq!(err.class(), ErrorClass::VaultKdfParamsOutOfRange, "{what}");
        assert_eq!(err.exit_code(), 14, "{what}");
    }
}

/// The other direction — parameters RAISED within the registered windows,
/// so the caps pass and the KDF actually runs: the derived key and the
/// AAD both differ, and unlock fails as an authentication failure, never
/// a silent open. Together with `downgraded_params_are_rejected_pre_auth`
/// this is the both-directions parameter-tamper coverage.
#[test]
fn raised_params_within_caps_fail_authentication() {
    let vault = shared_vault();
    let real_header =
        std::fs::read(vault.layout.beside_path(BesideFile::Header)).expect("read real header");
    let real_block = VaultHeader::decode(&real_header)
        .expect("decode")
        .kdf_block()
        .to_vec();
    // Sanity: the block parses (so the tamper below is the only change).
    KdfParams::decode(&real_block).expect("real params decode");

    // Keep the REAL salt (block layout per the golden vector:
    // `a5 00 <alg> 01 50 <16-byte salt> …`) and raise only t_cost 3 → 4:
    // the caps pass, the KDF runs once, and both the derived key and the
    // header AAD differ.
    let real_salt = &real_block[5..21];
    let raised = craft_block(
        KDF_ALG_ARGON2ID,
        real_salt,
        u64::from(ARGON2ID_M_COST_KIB),
        u64::from(ARGON2ID_T_COST) + 1,
        1,
    );
    let (_dir, tampered) = clone_vault(&vault.layout, "raise");
    install_block(
        &tampered,
        raised,
        antseal_cli::vault::header::WRAP_MODE_NONE,
    );
    let err = unlock_vault(&tampered, &passphrase()).expect_err("raised t");
    assert_eq!(err.class(), ErrorClass::VaultAuthFailure);
    assert_eq!(err.exit_code(), 12);
}

/// A substituted salt (parameters intact): different derived key → the
/// check record fails authentication.
#[test]
fn flipped_salt_fails_authentication() {
    let vault = shared_vault();
    let block = craft_block(
        KDF_ALG_ARGON2ID,
        &[0xEE; 16],
        u64::from(ARGON2ID_M_COST_KIB),
        u64::from(ARGON2ID_T_COST),
        1,
    );
    let (_dir, tampered) = clone_vault(&vault.layout, "salt");
    install_block(&tampered, block, antseal_cli::vault::header::WRAP_MODE_NONE);
    let err = unlock_vault(&tampered, &passphrase()).expect_err("flipped salt");
    assert_eq!(err.class(), ErrorClass::VaultAuthFailure);
}

/// A garbled KDF block inside an otherwise valid header: vault-auth
/// collapse (indistinguishable from tamper, deliberately).
#[test]
fn garbled_kdf_block_fails_as_vault_auth() {
    let vault = shared_vault();
    let (_dir, tampered) = clone_vault(&vault.layout, "garble");
    install_block(
        &tampered,
        vec![0xAB; 24],
        antseal_cli::vault::header::WRAP_MODE_NONE,
    );
    let err = unlock_vault(&tampered, &passphrase()).expect_err("garbled block");
    assert_eq!(err.class(), ErrorClass::VaultAuthFailure);
}

/// A wrap-mode flip on a valid vault, **re-mapped by U8 exactly as this
/// test predicted it would be**.
///
/// Flipping a mode-0 vault's header to mode 1 now makes the unlock look
/// for a keyfile — and there is no path recorded (the flip only edited a
/// byte) and none supplied, so it stops at
/// `vault-keyfile-missing` (18) rather than the old bug-class `internal`.
/// The property the test was written for is unchanged and is the only one
/// that matters: **never a silent open, and never a misleading
/// bad-passphrase message**. The pure-AAD direction is proven at the
/// cipher layer, where the KDF inputs are held fixed while the header
/// bytes change; `tests/vault_keyfile.rs` proves the 1 → 0 direction,
/// which reaches the AEAD and fails authentication.
#[test]
fn wrap_mode_flip_is_refused() {
    let vault = shared_vault();
    let real_header =
        std::fs::read(vault.layout.beside_path(BesideFile::Header)).expect("read real header");
    let block = VaultHeader::decode(&real_header)
        .expect("decode")
        .kdf_block()
        .to_vec();
    let (_dir, tampered) = clone_vault(&vault.layout, "wrap");
    install_block(&tampered, block, WRAP_MODE_KEYFILE);
    let err = unlock_vault(&tampered, &passphrase()).expect_err("wrap flip");
    assert_eq!(err.class(), ErrorClass::VaultKeyfileMissing);
    assert_ne!(
        err.class(),
        ErrorClass::VaultAuthFailure,
        "a flipped mode byte must not be reported as a wrong passphrase"
    );
}

/// Missing and corrupt check records both collapse into vault-auth
/// (corrupt store is indistinguishable from tamper, U6).
#[test]
fn missing_or_corrupt_check_record_fails_as_vault_auth() {
    let vault = shared_vault();

    let (_dir, missing) = clone_vault(&vault.layout, "check-missing");
    std::fs::remove_file(missing.check_record_path()).expect("remove check");
    let err = unlock_vault(&missing, &passphrase()).expect_err("missing check");
    assert_eq!(err.class(), ErrorClass::VaultAuthFailure);

    let (_dir, corrupt) = clone_vault(&vault.layout, "check-corrupt");
    let mut blob = std::fs::read(corrupt.check_record_path()).expect("read check");
    let last = blob.len() - 1;
    blob[last] ^= 0x01;
    antseal_cli::vault::fs::atomic_write(&corrupt.check_record_path(), &blob)
        .expect("write corrupted");
    let err = unlock_vault(&corrupt, &passphrase()).expect_err("corrupt check");
    assert_eq!(err.class(), ErrorClass::VaultAuthFailure);
}

// The D40 §2 low-RAM matrix (typed `vault-kdf-memory` at create AND
// unlock via the injected allocation failpoint, no partial vault, no
// fallback) lives with the primitive as unit tests in
// `src/vault/session.rs` — the failpoint seam is crate-private, exactly
// like the U5 kill matrix in `src/vault/fs.rs`.

// ─────────────────────────────────────────────────────────────────────
// Edges
// ─────────────────────────────────────────────────────────────────────

/// No vault at the path: a distinct usage-class error pointing at `init`,
/// never an auth failure.
#[test]
fn unlock_without_vault_is_a_usage_error() {
    let dir = TestDir::new("none");
    let layout = VaultLayout::at(dir.path().join("vault"));
    let err = unlock_vault(&layout, &passphrase()).expect_err("no vault");
    assert_eq!(err.class(), ErrorClass::Usage);
    assert!(err.to_string().contains("antseal init"), "{err}");
}

/// Creating over an existing vault is refused (the primitive beneath
/// D39's absolute init refusal).
#[test]
fn create_over_existing_vault_is_refused() {
    let vault = shared_vault();
    let mut rng = ChaCha20Rng::from_seed(TEST_RNG_SEED);
    let err = create_vault(
        &vault.layout,
        &passphrase(),
        KdfSelection::Argon2id,
        &mut rng,
    )
    .expect_err("existing vault");
    assert_eq!(err.class(), ErrorClass::Usage);
    assert!(err.to_string().contains("already exists"), "{err}");
}
