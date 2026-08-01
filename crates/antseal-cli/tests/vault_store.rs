//! U5 acceptance suite: vault layout, versioned header, atomic writes,
//! and the single-writer lock.
//!
//! House checklist for a new format: the header has a committed golden
//! vector and a tamper matrix in which every mutation fails with a
//! distinct, asserted error. The kill-during-write matrix lives with the
//! primitive (`src/vault/fs.rs` unit tests); here the primitives are
//! exercised end-to-end against a real directory.
//!
//! NON-SECRET: every byte in this file is a documented placeholder
//! (`00112233…` filler); no real KDF parameters, salts, or key material
//! exist at U5 — the KDF block schema itself is U6's.

use std::path::{Path, PathBuf};

use antseal_cli::error::{CliError, ErrorClass};
use antseal_cli::vault::fs::atomic_write;
use antseal_cli::vault::header::{
    HEADER_MAGIC, HeaderError, MAX_HEADER_BYTES, MAX_KDF_BLOCK_BYTES, VAULT_FORMAT_VERSION,
    VaultHeader, WRAP_MODE_KEYFILE, WRAP_MODE_NONE, WRAP_MODE_OS_KEYSTORE_RESERVED,
};
use antseal_cli::vault::layout::{BesideFile, LayoutError, VaultLayout};
use antseal_cli::vault::lock::{LockError, VaultLock};
use antseal_core::codec::encode_item;

// ─────────────────────────────────────────────────────────────────────
// Test scaffolding (std-only temp dirs)
// ─────────────────────────────────────────────────────────────────────

struct TestDir(PathBuf);

impl TestDir {
    fn new(tag: &str) -> Self {
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "antseal-cli-vault-{tag}-{}-{}",
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

/// Placeholder KDF block: 16 documented filler bytes (a real block is
/// U6's schema; NON-SECRET by construction).
const KDF_PLACEHOLDER: [u8; 16] = [
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
];

fn golden_header() -> VaultHeader {
    VaultHeader::new(KDF_PLACEHOLDER.to_vec(), WRAP_MODE_NONE).expect("golden header")
}

/// Craft a header file with an arbitrary envelope (tamper harness).
fn craft(version: u64, body: &[u8]) -> Vec<u8> {
    let envelope = encode_item(|e| {
        e.array(|a| {
            a.item(|e| e.u64(version))?;
            a.item(|e| e.bytes(body))
        })
    })
    .expect("craft envelope");
    let mut out = HEADER_MAGIC.to_vec();
    out.extend_from_slice(&envelope);
    out
}

/// Craft a v1 body map from raw entries (tamper harness).
fn craft_body(entries: &[(u64, BodyValue<'_>)]) -> Vec<u8> {
    encode_item(|e| {
        e.map(|m| {
            for (key, value) in entries {
                match value {
                    BodyValue::Bytes(b) => m.entry(*key, |e| e.bytes(b))?,
                    BodyValue::Uint(v) => m.entry(*key, |e| e.u64(*v))?,
                }
            }
            Ok(())
        })
    })
    .expect("craft body")
}

enum BodyValue<'a> {
    Bytes(&'a [u8]),
    Uint(u64),
}

// ─────────────────────────────────────────────────────────────────────
// Golden vector + round trips
// ─────────────────────────────────────────────────────────────────────

/// The committed golden encoding of the v1 header (NON-SECRET filler):
/// magic ‖ array(2)[1, bstr( map{0: 16-byte kdf placeholder, 1: 0} )].
#[test]
fn golden_header_vector_is_byte_exact() {
    #[rustfmt::skip]
    let expected: Vec<u8> = [
        // "ANTSEAL VAULT HEADER"
        HEADER_MAGIC.as_slice(),
        // envelope: array(2), version 1, bstr(21)
        &[0x82, 0x01, 0x55],
        // body: map(2), key 0, bstr(16)
        &[0xa2, 0x00, 0x50],
        &KDF_PLACEHOLDER,
        // key 1, wrap_mode 0
        &[0x01, 0x00],
    ]
    .concat();

    let encoded = golden_header().encode().expect("encode");
    assert_eq!(
        encoded, expected,
        "golden header bytes moved — format event"
    );

    let decoded = VaultHeader::decode(&expected).expect("decode golden");
    assert_eq!(decoded, golden_header());
}

#[test]
fn header_round_trips_across_the_field_space() {
    let cases = [
        (Vec::new(), WRAP_MODE_NONE),
        (vec![0xAB; 1], WRAP_MODE_KEYFILE),
        (
            vec![0x5C; MAX_KDF_BLOCK_BYTES],
            WRAP_MODE_OS_KEYSTORE_RESERVED,
        ),
    ];
    for (kdf, wrap) in cases {
        let header = VaultHeader::new(kdf.clone(), wrap).expect("construct");
        let bytes = header.encode().expect("encode");
        let back = VaultHeader::decode(&bytes).expect("decode");
        assert_eq!(back, header, "kdf len {} wrap {wrap}", kdf.len());
        assert_eq!(back.kdf_block(), kdf.as_slice());
        assert_eq!(back.wrap_mode(), wrap);
    }
}

/// Constructible == decodable (the F41 lesson): the constructor enforces
/// exactly the decode-side caps.
#[test]
fn constructor_enforces_the_decode_caps() {
    let too_big = vec![0u8; MAX_KDF_BLOCK_BYTES + 1];
    assert!(matches!(
        VaultHeader::new(too_big, WRAP_MODE_NONE),
        Err(HeaderError::KdfBlockTooLarge { len }) if len == MAX_KDF_BLOCK_BYTES + 1
    ));
    assert!(matches!(
        VaultHeader::new(Vec::new(), 3),
        Err(HeaderError::WrapModeUnknown { found: 3 })
    ));
}

// ─────────────────────────────────────────────────────────────────────
// Tamper matrix: every mutation fails with a distinct error
// ─────────────────────────────────────────────────────────────────────

#[test]
fn tamper_bad_magic() {
    let mut bytes = golden_header().encode().expect("encode");
    bytes[0] ^= 0x01;
    assert!(matches!(
        VaultHeader::decode(&bytes),
        Err(HeaderError::BadMagic)
    ));
}

#[test]
fn tamper_truncation_sweep_never_panics() {
    let bytes = golden_header().encode().expect("encode");
    for cut in 0..bytes.len() {
        let err = VaultHeader::decode(&bytes[..cut]).expect_err("every prefix errors");
        if cut < HEADER_MAGIC.len() {
            assert!(matches!(err, HeaderError::BadMagic), "cut {cut}");
        }
    }
}

#[test]
fn tamper_trailing_bytes_rejected() {
    let mut bytes = golden_header().encode().expect("encode");
    bytes.push(0x00);
    assert!(matches!(
        VaultHeader::decode(&bytes),
        Err(HeaderError::Codec { .. })
    ));
}

#[test]
fn tamper_version_zero_is_invalid() {
    let body = craft_body(&[
        (0, BodyValue::Bytes(&KDF_PLACEHOLDER)),
        (1, BodyValue::Uint(0)),
    ]);
    assert!(matches!(
        VaultHeader::decode(&craft(0, &body)),
        Err(HeaderError::InvalidVersion)
    ));
}

#[test]
fn newer_version_yields_the_clean_upgrade_error_without_parsing_the_body() {
    // The body is deliberately garbage a v1 parser would reject: a
    // future header must still be classified by version alone.
    for future in [u64::from(VAULT_FORMAT_VERSION) + 1, u64::MAX] {
        let err = VaultHeader::decode(&craft(future, b"\xff\xff-not-cbor")).expect_err("future");
        assert!(
            matches!(err, HeaderError::NewerVersion { found } if found == future),
            "version {future}"
        );
        // U2 mapping: the dedicated vault-newer-version class, code 16.
        let cli: CliError = err.into();
        assert_eq!(cli.class(), ErrorClass::VaultNewerVersion);
        assert_eq!(cli.exit_code(), 16);
    }
}

#[test]
fn tamper_non_canonical_version_int_rejected() {
    // 0x18 0x01 is a non-shortest encoding of 1 — canonicality violation.
    let body = craft_body(&[
        (0, BodyValue::Bytes(&KDF_PLACEHOLDER)),
        (1, BodyValue::Uint(0)),
    ]);
    let bstr_head_and_body = encode_item(|e| e.bytes(&body)).expect("bstr");
    let mut bytes = HEADER_MAGIC.to_vec();
    bytes.extend_from_slice(&[0x82, 0x18, 0x01]);
    bytes.extend_from_slice(&bstr_head_and_body);
    assert!(matches!(
        VaultHeader::decode(&bytes),
        Err(HeaderError::Codec { .. })
    ));
}

#[test]
fn tamper_envelope_wrong_arity() {
    let envelope = encode_item(|e| {
        e.array(|a| {
            a.item(|e| e.u64(1))?;
            a.item(|e| e.bytes(b""))?;
            a.item(|e| e.u64(9))
        })
    })
    .expect("arity-3 envelope");
    let mut bytes = HEADER_MAGIC.to_vec();
    bytes.extend_from_slice(&envelope);
    assert!(matches!(
        VaultHeader::decode(&bytes),
        Err(HeaderError::Schema { .. })
    ));
}

#[test]
fn tamper_body_not_a_map() {
    let body = encode_item(|e| e.u64(7)).expect("uint body");
    assert!(matches!(
        VaultHeader::decode(&craft(1, &body)),
        Err(HeaderError::Codec { .. })
    ));
}

#[test]
fn tamper_body_missing_and_extra_keys() {
    // One entry only.
    let short = craft_body(&[(0, BodyValue::Bytes(&KDF_PLACEHOLDER))]);
    assert!(matches!(
        VaultHeader::decode(&craft(1, &short)),
        Err(HeaderError::Schema { .. })
    ));
    // Three entries.
    let long = craft_body(&[
        (0, BodyValue::Bytes(&KDF_PLACEHOLDER)),
        (1, BodyValue::Uint(0)),
        (2, BodyValue::Uint(0)),
    ]);
    assert!(matches!(
        VaultHeader::decode(&craft(1, &long)),
        Err(HeaderError::Schema { .. })
    ));
    // Right arity, wrong keys.
    let wrong = craft_body(&[(1, BodyValue::Uint(0)), (2, BodyValue::Uint(0))]);
    assert!(matches!(
        VaultHeader::decode(&craft(1, &wrong)),
        Err(HeaderError::Schema { .. })
    ));
}

#[test]
fn tamper_kdf_block_over_cap_rejected() {
    let big = vec![0u8; MAX_KDF_BLOCK_BYTES + 1];
    let body = craft_body(&[(0, BodyValue::Bytes(&big)), (1, BodyValue::Uint(0))]);
    assert!(matches!(
        VaultHeader::decode(&craft(1, &body)),
        Err(HeaderError::KdfBlockTooLarge { .. })
    ));
}

#[test]
fn tamper_wrap_mode_above_registry_rejected() {
    let body = craft_body(&[
        (0, BodyValue::Bytes(&KDF_PLACEHOLDER)),
        (1, BodyValue::Uint(3)),
    ]);
    assert!(matches!(
        VaultHeader::decode(&craft(1, &body)),
        Err(HeaderError::WrapModeUnknown { found: 3 })
    ));
}

#[test]
fn tamper_oversized_file_rejected_before_parsing() {
    let bytes = vec![0u8; MAX_HEADER_BYTES + 1];
    assert!(matches!(
        VaultHeader::decode(&bytes),
        Err(HeaderError::TooLarge { .. })
    ));
}

/// The safe collapse (U6 "insofar as safe"): mangled headers map to the
/// vault-auth class; only newer-version keeps its own class.
#[test]
fn header_errors_map_to_the_decided_cli_classes() {
    let cli: CliError = HeaderError::BadMagic.into();
    assert_eq!(cli.class(), ErrorClass::VaultAuthFailure);
    assert_eq!(cli.exit_code(), 12);
}

// ─────────────────────────────────────────────────────────────────────
// Layout: the structural D42 partition
// ─────────────────────────────────────────────────────────────────────

#[test]
fn beside_set_is_exactly_the_three_d42_files() {
    let layout = VaultLayout::at(PathBuf::from("/vault"));
    let named: Vec<&str> = [BesideFile::Config, BesideFile::Header, BesideFile::Lockfile]
        .into_iter()
        .map(BesideFile::file_name)
        .collect();
    assert_eq!(named, ["config.toml", "vault.header", "vault.lock"]);
    assert_eq!(
        layout.beside_path(BesideFile::Header),
        PathBuf::from("/vault/vault.header")
    );
    // Everything else resolves under the ciphertext-only store area.
    assert_eq!(layout.store_root(), PathBuf::from("/vault/store"));
    assert_eq!(layout.works_dir(), PathBuf::from("/vault/store/works"));
    assert_eq!(
        layout.wallet_record_path(),
        PathBuf::from("/vault/store/wallet")
    );
}

#[test]
fn layout_resolution_prefers_the_env_override() {
    use std::ffi::OsStr;
    let by_env = VaultLayout::resolve_from(
        Some(OsStr::new("/custom/vault")),
        Some(PathBuf::from("/home/u")),
    )
    .expect("env override");
    assert_eq!(by_env.root(), Path::new("/custom/vault"));

    let by_home =
        VaultLayout::resolve_from(None, Some(PathBuf::from("/home/u"))).expect("home fallback");
    assert_eq!(by_home.root(), Path::new("/home/u/.antseal"));

    // An empty override is ignored, not honored.
    let empty = VaultLayout::resolve_from(Some(OsStr::new("")), Some(PathBuf::from("/home/u")))
        .expect("empty override falls back");
    assert_eq!(empty.root(), Path::new("/home/u/.antseal"));

    assert!(matches!(
        VaultLayout::resolve_from(None, None),
        Err(LayoutError::NoHome)
    ));
}

// ─────────────────────────────────────────────────────────────────────
// Lock: mutual exclusion, fail-fast, stale-file inertness
// ─────────────────────────────────────────────────────────────────────

#[test]
fn second_acquire_fails_fast_with_the_lock_held_class() {
    let dir = TestDir::new("lock-held");
    let lock_path = dir.path().join("vault.lock");
    let held = VaultLock::acquire(&lock_path).expect("first acquire");
    assert_eq!(held.path(), lock_path.as_path());

    let err = VaultLock::acquire(&lock_path).expect_err("second acquire must fail");
    match &err {
        LockError::Held { holder_pid, .. } => {
            assert_eq!(*holder_pid, Some(std::process::id()), "advisory pid");
        }
        other => panic!("expected Held, got {other:?}"),
    }
    let cli: CliError = err.into();
    assert_eq!(cli.class(), ErrorClass::VaultLockHeld);
    assert_eq!(cli.exit_code(), 15);

    // Release → re-acquire succeeds.
    drop(held);
    let reacquired = VaultLock::acquire(&lock_path).expect("re-acquire after release");
    drop(reacquired);
}

#[test]
fn stale_lockfile_from_a_dead_process_is_inert() {
    let dir = TestDir::new("lock-stale");
    let lock_path = dir.path().join("vault.lock");
    // A leftover file with a plausible-but-dead pid, no lock held: the
    // kernel released the dead holder's lock, so acquire succeeds and no
    // liveness heuristic ever runs.
    std::fs::write(&lock_path, "999999\n").expect("plant stale lockfile");
    let lock = VaultLock::acquire(&lock_path).expect("stale file must not block");
    drop(lock);

    // Garbage content is equally inert.
    std::fs::write(&lock_path, b"not-a-pid\0\xff").expect("plant garbage");
    let lock = VaultLock::acquire(&lock_path).expect("garbage content must not block");
    drop(lock);
}

#[test]
fn missing_vault_directory_is_an_io_error_not_a_creation() {
    let dir = TestDir::new("lock-nodir");
    let lock_path = dir.path().join("no-such-dir").join("vault.lock");
    let err = VaultLock::acquire(&lock_path).expect_err("missing dir");
    assert!(matches!(err, LockError::Io { .. }));
    let cli: CliError = err.into();
    assert_eq!(cli.class(), ErrorClass::IoError);
}

// ─────────────────────────────────────────────────────────────────────
// Composition: header + atomic write against a real layout
// ─────────────────────────────────────────────────────────────────────

#[test]
fn header_written_atomically_reads_back_byte_exact() {
    let dir = TestDir::new("compose");
    let layout = VaultLayout::at(dir.path().to_owned());
    let header_path = layout.beside_path(BesideFile::Header);

    let header = golden_header();
    let bytes = header.encode().expect("encode");
    atomic_write(&header_path, &bytes).expect("atomic write");

    let read = std::fs::read(&header_path).expect("read back");
    assert_eq!(read, bytes, "AAD bytes are exactly the file bytes");
    assert_eq!(VaultHeader::decode(&read).expect("decode"), header);

    // Old-or-new under replacement: a rewrite with a different wrap mode
    // lands completely.
    let v2 = VaultHeader::new(KDF_PLACEHOLDER.to_vec(), WRAP_MODE_KEYFILE).expect("v2");
    atomic_write(&header_path, &v2.encode().expect("encode v2")).expect("rewrite");
    assert_eq!(
        VaultHeader::decode(&std::fs::read(&header_path).expect("read"))
            .expect("decode")
            .wrap_mode(),
        WRAP_MODE_KEYFILE
    );
}
