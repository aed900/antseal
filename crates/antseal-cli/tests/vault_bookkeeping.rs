//! U34's vault-global bookkeeping record: the store slot, the D42 splice
//! matrix's new row, and the export/import carriage U18's nag depends on.
//!
//! NON-SECRET: fixture passphrases and byte patterns only (project rule 6).

mod common;

use antseal_cli::vault::bookkeeping::{self, Bookkeeping};
use antseal_cli::vault::cipher::RecordIdentity;
use antseal_cli::vault::store::WorkStore;
use common::IsolatedVault;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

fn rng(seed: u8) -> ChaCha20Rng {
    ChaCha20Rng::from_seed([seed; 32])
}

/// U34 Accept row 1, first half: create → reopen round trip, with
/// **absent treated as a state** rather than as a failure.
#[test]
fn the_record_round_trips_and_a_missing_slot_is_the_default() {
    let vault = IsolatedVault::create("bk-roundtrip");
    let unlocked = vault.unlock();

    // A fresh vault has no slot at all, and reading it is not an error —
    // every vault created before U34 is in exactly this state.
    assert!(!unlocked.layout().bookkeeping_record_path().exists());
    assert_eq!(
        bookkeeping::load(&unlocked).expect("absent is a state"),
        Bookkeeping::default()
    );

    let recorded =
        bookkeeping::record_export(&unlocked, 1_800_000_000, &mut rng(0x11)).expect("record");
    assert_eq!(recorded.exports, 1);
    assert_eq!(recorded.last_export_unix_secs, Some(1_800_000_000));
    assert!(recorded.ever_exported());
    drop(unlocked);

    // Survives a full close/reopen (a real unlock, not a live cache).
    let reopened = vault.unlock();
    assert_eq!(bookkeeping::load(&reopened).expect("load"), recorded);

    // Read-modify-write: the count accumulates, the timestamp moves.
    let again =
        bookkeeping::record_export(&reopened, 1_800_000_099, &mut rng(0x12)).expect("record");
    assert_eq!(again.exports, 2);
    assert_eq!(again.last_export_unix_secs, Some(1_800_000_099));
}

/// U34 Accept row 1, second half: **the D42 splice matrix extends by one
/// row.** A blob is bound to its record class, so moving one into or out
/// of this slot fails authentication rather than being read as some other
/// record.
#[test]
fn splicing_into_or_out_of_the_bookkeeping_slot_fails_authentication() {
    let vault = IsolatedVault::create("bk-splice");
    let unlocked = vault.unlock();
    bookkeeping::record_export(&unlocked, 1_800_000_000, &mut rng(0x21)).expect("record");

    let slot = unlocked.layout().bookkeeping_record_path();
    let bookkeeping_blob = std::fs::read(&slot).expect("read the blob");

    // Out: the bookkeeping blob read under the key-check identity.
    assert!(
        unlocked
            .open_record(RecordIdentity::KeyCheck, &bookkeeping_blob)
            .is_err(),
        "a bookkeeping blob must not authenticate as the key-check record"
    );

    // In: the key-check blob dropped into the bookkeeping slot.
    let check_blob = std::fs::read(unlocked.layout().check_record_path()).expect("read check");
    std::fs::write(&slot, &check_blob).expect("splice");
    let err = bookkeeping::load(&unlocked).expect_err("a spliced blob is refused");
    assert_eq!(
        err.class(),
        antseal_cli::error::ErrorClass::VaultAuthFailure,
        "splice is an authentication failure, not a parse error"
    );

    // Tamper: one flipped byte of the real blob.
    let mut tampered = bookkeeping_blob.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 0x01;
    std::fs::write(&slot, &tampered).expect("tamper");
    assert_eq!(
        bookkeeping::load(&unlocked)
            .expect_err("tamper is refused")
            .class(),
        antseal_cli::error::ErrorClass::VaultAuthFailure
    );

    // Restoring the real bytes restores the record: the failures above
    // were about authentication, not about a broken reader.
    std::fs::write(&slot, &bookkeeping_blob).expect("restore");
    assert_eq!(bookkeeping::load(&unlocked).expect("load").exports, 1);
}

/// U34 Accept row 2: export → wipe → import carries the record, **and** a
/// payload without the key still imports.
#[test]
fn the_export_carries_the_record_and_a_payload_without_it_still_imports() {
    use antseal_cli::vault::export::{export_vault, import_vault};
    use antseal_cli::vault::layout::VaultLayout;

    // ── (a) a vault WITH a recorded export ──
    let source = IsolatedVault::create("bk-export-a");
    let unlocked = source.unlock();
    {
        let store = WorkStore::new(&unlocked);
        assert_eq!(store.list_works().expect("list").len(), 0);
    }
    bookkeeping::record_export(&unlocked, 1_798_761_800, &mut rng(0x31)).expect("record");
    let file = source.root.join("with-record.sealvault");
    export_vault(&unlocked, &common::passphrase(), &file, &mut rng(0x32)).expect("export");
    drop(unlocked);

    let target_root = source.root.join("restored-a");
    let target = VaultLayout::at(target_root.join("vault"));
    import_vault(&file, &target, || Ok(common::passphrase()), &mut rng(0x33)).expect("import");
    let restored = antseal_cli::vault::session::unlock_vault(&target, &common::passphrase())
        .expect("unlock the restored vault");
    let carried = bookkeeping::load(&restored).expect("load");
    assert_eq!(carried.exports, 1, "the count travelled");
    assert_eq!(
        carried.last_export_unix_secs,
        Some(1_798_761_800),
        "and so did the timestamp"
    );

    // ── (b) a vault with NO record: the payload omits key 5 entirely ──
    let plain = IsolatedVault::create("bk-export-b");
    let unlocked = plain.unlock();
    assert_eq!(
        bookkeeping::load(&unlocked).expect("load"),
        Bookkeeping::default(),
        "nothing recorded, so the payload will carry no key 5"
    );
    let file = plain.root.join("no-record.sealvault");
    export_vault(&unlocked, &common::passphrase(), &file, &mut rng(0x34)).expect("export");
    drop(unlocked);

    let target_root = plain.root.join("restored-b");
    let target = VaultLayout::at(target_root.join("vault"));
    import_vault(&file, &target, || Ok(common::passphrase()), &mut rng(0x35))
        .expect("an export without the bookkeeping key still imports");
    let restored =
        antseal_cli::vault::session::unlock_vault(&target, &common::passphrase()).expect("unlock");

    // …and the imported vault knows it has a backup, because consuming an
    // export file IS the proof of one. The timestamp stays absent: when
    // that backup was taken is genuinely unknown here.
    let record = bookkeeping::load(&restored).expect("load");
    assert!(
        record.ever_exported(),
        "a vault restored from a backup must not claim it has none"
    );
    assert_eq!(record.last_export_unix_secs, None);
}
