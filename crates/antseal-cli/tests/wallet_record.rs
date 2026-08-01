//! U10 acceptance suite: the Arbitrum wallet-key record under its own
//! vault sub-key — round trip across a fresh unlock, tamper/splice
//! authentication failures in both directions, and the blast-radius
//! decoupling (corrupting either domain leaves the other readable).
//!
//! The key-isolation half of the sub-key claim (a main-key blob with the
//! correct identity still fails) lives as a unit test inside
//! `vault/wallet.rs` — it needs the crate-private main-key seal path.
//!
//! NON-SECRET: every key byte here is a documented fixture pattern.

use std::path::PathBuf;

use antseal_cli::error::{CliError, ErrorClass};
use antseal_cli::vault::kdf::KdfSelection;
use antseal_cli::vault::layout::VaultLayout;
use antseal_cli::vault::session::{UnlockedVault, create_vault, unlock_vault};
use antseal_cli::vault::store::{SealShapingFlags, WorkRecord, WorkState, WorkStore};
use antseal_cli::vault::wallet::{WalletKeyHandle, load_wallet_key, store_wallet_key};
use antseal_core::crypto::secrets::{MasterSecret, SealId, SecretBuf};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

const TEST_RNG_SEED: [u8; 32] = [0x42u8; 32];
const FIXTURE_PASSPHRASE: &[u8] = b"correct horse battery staple fixture";
const FIXTURE_WALLET_KEY: [u8; 32] = [0x5Au8; 32];

fn rng() -> ChaCha20Rng {
    ChaCha20Rng::from_seed(TEST_RNG_SEED)
}

fn passphrase() -> SecretBuf {
    SecretBuf::new(FIXTURE_PASSPHRASE.to_vec())
}

struct TestVault {
    _root: TestDir,
    layout: VaultLayout,
}

struct TestDir(PathBuf);

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A private vault per test (the wallet record is a vault-global
/// singleton, so tests must not share one).
fn fresh_vault(tag: &str) -> (TestVault, UnlockedVault) {
    let root = std::env::temp_dir().join(format!(
        "antseal-cli-wallet-it-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos()
    ));
    std::fs::create_dir_all(&root).expect("mk root");
    let layout = VaultLayout::at(root.join("vault"));
    let unlocked = create_vault(&layout, &passphrase(), KdfSelection::Argon2id, &mut rng())
        .expect("create vault");
    (
        TestVault {
            _root: TestDir(root),
            layout,
        },
        unlocked,
    )
}

fn fixture_work(vault: &UnlockedVault) -> SealId {
    let seal_id = SealId::from_bytes([0xC1u8; 16]);
    let record = WorkRecord {
        w: MasterSecret::from_bytes([0x11u8; 32]),
        seal_id,
        network: "devnet".to_owned(),
        state: WorkState::IncompletePrePay,
        degraded: false,
        unanchored: false,
        input_paths_as_given: vec!["notes.md".to_owned()],
        input_paths_absolute: vec!["/home/fixture/notes.md".to_owned()],
        shaping: SealShapingFlags::default(),
        work_id: None,
        cost_atto: None,
        consent: None,
    };
    WorkStore::new(vault)
        .create_work(&record, &mut rng())
        .expect("create fixture work");
    seal_id
}

/// Round trip: store → drop every handle → fresh unlock from disk → load
/// byte-identically. Absence beforehand is a state (`None`), not an
/// error.
#[test]
fn wallet_key_round_trips_across_reopen() {
    let (tv, unlocked) = fresh_vault("roundtrip");
    assert!(
        load_wallet_key(&unlocked)
            .expect("absent wallet reads as None")
            .is_none()
    );
    store_wallet_key(
        &unlocked,
        &WalletKeyHandle::from_bytes(FIXTURE_WALLET_KEY),
        &mut rng(),
    )
    .expect("store");
    drop(unlocked);

    let reopened = unlock_vault(&tv.layout, &passphrase()).expect("fresh unlock");
    let loaded = load_wallet_key(&reopened).expect("load").expect("present");
    assert_eq!(loaded.secret_bytes(), &FIXTURE_WALLET_KEY);
}

/// Tamper: any flipped byte in the stored blob is an authentication
/// failure with the vault-auth class, and a truncated blob likewise.
#[test]
fn tampered_wallet_record_fails_authentication() {
    let (_tv, unlocked) = fresh_vault("tamper");
    store_wallet_key(
        &unlocked,
        &WalletKeyHandle::from_bytes(FIXTURE_WALLET_KEY),
        &mut rng(),
    )
    .expect("store");

    let path = unlocked.layout().wallet_record_path();
    let original = std::fs::read(&path).expect("read blob");

    // Flip one byte in each region: nonce, ciphertext body, tag.
    for index in [0, original.len() / 2, original.len() - 1] {
        let mut mutated = original.clone();
        mutated[index] ^= 0x01;
        std::fs::write(&path, &mutated).expect("install tamper");
        let err = load_wallet_key(&unlocked).expect_err("tampered blob");
        assert!(matches!(err, CliError::VaultAuthFailure), "byte {index}");
        assert_eq!(err.class(), ErrorClass::VaultAuthFailure);
    }

    // Truncation is equally loud.
    std::fs::write(&path, &original[..original.len() - 1]).expect("truncate");
    assert!(matches!(
        load_wallet_key(&unlocked).expect_err("truncated blob"),
        CliError::VaultAuthFailure
    ));

    // Restore and prove the matrix falsifiable.
    std::fs::write(&path, &original).expect("restore");
    assert!(load_wallet_key(&unlocked).expect("intact").is_some());
}

/// Splice, both directions: the wallet blob in a work-meta slot fails,
/// and a work-meta blob in the wallet slot fails — different sub-key AND
/// different AAD identity, either alone suffices.
#[test]
fn wallet_and_work_records_do_not_splice() {
    let (_tv, unlocked) = fresh_vault("splice");
    let seal_id = fixture_work(&unlocked);
    store_wallet_key(
        &unlocked,
        &WalletKeyHandle::from_bytes(FIXTURE_WALLET_KEY),
        &mut rng(),
    )
    .expect("store");

    let wallet_path = unlocked.layout().wallet_record_path();
    let meta_path = {
        let mut hex = String::new();
        for byte in seal_id.as_bytes() {
            use std::fmt::Write;
            let _ = write!(hex, "{byte:02x}");
        }
        unlocked.layout().works_dir().join(hex).join("meta")
    };
    let wallet_blob = std::fs::read(&wallet_path).expect("wallet blob");
    let meta_blob = std::fs::read(&meta_path).expect("meta blob");

    // Wallet blob into the meta slot.
    std::fs::write(&meta_path, &wallet_blob).expect("splice into meta");
    let store = WorkStore::new(&unlocked);
    assert_eq!(
        CliError::from(store.load_meta(&seal_id).expect_err("spliced meta")).class(),
        ErrorClass::VaultAuthFailure
    );
    std::fs::write(&meta_path, &meta_blob).expect("repair meta");

    // Meta blob into the wallet slot.
    std::fs::write(&wallet_path, &meta_blob).expect("splice into wallet");
    assert!(matches!(
        load_wallet_key(&unlocked).expect_err("spliced wallet"),
        CliError::VaultAuthFailure
    ));
    std::fs::write(&wallet_path, &wallet_blob).expect("repair wallet");

    // Both slots intact again (falsifiability).
    assert!(store.load_meta(&seal_id).is_ok());
    assert!(load_wallet_key(&unlocked).expect("intact").is_some());
}

/// Blast radius (the U10 Accept, both directions): corrupting the wallet
/// record leaves every work record readable, and corrupting a work
/// record leaves the wallet readable.
#[test]
fn corruption_blast_radius_is_decoupled() {
    let (_tv, unlocked) = fresh_vault("blast");
    let seal_id = fixture_work(&unlocked);
    store_wallet_key(
        &unlocked,
        &WalletKeyHandle::from_bytes(FIXTURE_WALLET_KEY),
        &mut rng(),
    )
    .expect("store");
    let store = WorkStore::new(&unlocked);

    // Direction 1: garbage wallet record, work records fine.
    let wallet_path = unlocked.layout().wallet_record_path();
    let wallet_blob = std::fs::read(&wallet_path).expect("save wallet blob");
    std::fs::write(&wallet_path, b"garbage").expect("corrupt wallet");
    assert!(
        load_wallet_key(&unlocked).is_err(),
        "wallet corrupt is loud"
    );
    let meta = store.load_meta(&seal_id).expect("work record unaffected");
    assert_eq!(meta.network, "devnet");
    std::fs::write(&wallet_path, &wallet_blob).expect("repair wallet");

    // Direction 2: garbage work meta, wallet fine.
    let mut hex = String::new();
    for byte in seal_id.as_bytes() {
        use std::fmt::Write;
        let _ = write!(hex, "{byte:02x}");
    }
    let meta_path = unlocked.layout().works_dir().join(hex).join("meta");
    std::fs::write(&meta_path, b"garbage").expect("corrupt meta");
    assert!(store.load_meta(&seal_id).is_err(), "meta corrupt is loud");
    let loaded = load_wallet_key(&unlocked)
        .expect("wallet unaffected")
        .expect("present");
    assert_eq!(loaded.secret_bytes(), &FIXTURE_WALLET_KEY);
}

/// Overwrite draws a fresh nonce (key rotation/re-import writes are
/// legal and never reuse a nonce), and the latest value wins.
#[test]
fn rewrite_uses_fresh_nonce_and_latest_value_wins() {
    let (_tv, unlocked) = fresh_vault("rewrite");
    let mut r = rng();
    store_wallet_key(
        &unlocked,
        &WalletKeyHandle::from_bytes(FIXTURE_WALLET_KEY),
        &mut r,
    )
    .expect("first store");
    let first_blob = std::fs::read(unlocked.layout().wallet_record_path()).expect("blob 1");
    store_wallet_key(
        &unlocked,
        &WalletKeyHandle::from_bytes([0x33u8; 32]),
        &mut r,
    )
    .expect("second store");
    let second_blob = std::fs::read(unlocked.layout().wallet_record_path()).expect("blob 2");
    assert_ne!(
        first_blob[..24],
        second_blob[..24],
        "fresh nonce per write (nonce prefix differs)"
    );
    let loaded = load_wallet_key(&unlocked).expect("load").expect("present");
    assert_eq!(loaded.secret_bytes(), &[0x33u8; 32]);
}
