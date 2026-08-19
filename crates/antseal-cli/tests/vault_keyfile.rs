//! U8's keyfile wrap (D50 mode 1) end to end: create → lock → unlock, the
//! distinct refusals, the header recording, and what `vault export` does
//! with a two-factor vault.
//!
//! **The environment variable is never set here.** `ANTSEAL_KEYFILE` is a
//! process-global, and these tests run in parallel with every other suite
//! in this binary; each unlock passes its path explicitly through
//! `unlock_vault_with_keyfile` instead. The env channel's *precedence* is
//! unit-tested inside `vault::keyfile` where no vault is involved.
//!
//! NON-SECRET: fixture passphrases and byte patterns only (project rule 6).

use std::path::{Path, PathBuf};

use antseal_cli::error::ErrorClass;
use antseal_cli::vault::header::{
    VaultHeader, WRAP_MODE_KEYFILE, WRAP_MODE_NONE, WRAP_MODE_OS_KEYSTORE_RESERVED,
};
use antseal_cli::vault::kdf::KdfSelection;
use antseal_cli::vault::keyfile::{KEYFILE_LEN, WrapChoice};
use antseal_cli::vault::layout::{BesideFile, VaultLayout};
use antseal_cli::vault::session::{
    create_vault, create_vault_with_wrap, unlock_vault_with_keyfile,
};
use antseal_cli::vault::store::WorkStore;
use antseal_core::crypto::secrets::SecretBuf;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

/// NON-SECRET fixture passphrase.
const FIXTURE_PASSPHRASE: &[u8] = b"keyfile suite fixture passphrase";

fn passphrase() -> SecretBuf {
    SecretBuf::new(FIXTURE_PASSPHRASE.to_vec())
}

fn rng(seed: u8) -> ChaCha20Rng {
    ChaCha20Rng::from_seed([seed; 32])
}

struct Dir(PathBuf);

impl Dir {
    fn new(tag: &str) -> Self {
        let root = std::env::temp_dir().join(format!(
            "antseal-cli-keyfile-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).expect("mk dir");
        Self(root)
    }

    fn layout(&self) -> VaultLayout {
        VaultLayout::at(self.0.join("vault"))
    }

    fn keyfile(&self) -> PathBuf {
        self.0.join("second-factor.key")
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn header_of(layout: &VaultLayout) -> VaultHeader {
    let bytes = std::fs::read(layout.beside_path(BesideFile::Header)).expect("read header");
    VaultHeader::decode(&bytes).expect("header decodes")
}

/// **U8 Accept row 1.** Create → lock → unlock with the keyfile; and
/// without it, a *distinct* error rather than the generic auth failure.
#[test]
fn a_keyfile_vault_round_trips_and_refuses_distinctly_without_its_keyfile() {
    let dir = Dir::new("roundtrip");
    let layout = dir.layout();
    let keyfile = dir.keyfile();

    let vault = create_vault_with_wrap(
        &layout,
        &passphrase(),
        KdfSelection::Argon2id,
        &WrapChoice::Keyfile {
            path: keyfile.clone(),
            record_path: true,
        },
        &mut rng(0x41),
    )
    .expect("create a keyfile-wrapped vault");
    // Prove the vault is usable, not merely constructible.
    let store = WorkStore::new(&vault);
    assert_eq!(store.list_works().expect("list").len(), 0);
    drop(vault);

    assert_eq!(
        std::fs::read(&keyfile).expect("keyfile written").len(),
        KEYFILE_LEN
    );

    // With the keyfile: opens. (Explicit path AND the recorded one, since
    // the header remembers it.)
    unlock_vault_with_keyfile(&layout, &passphrase(), Some(&keyfile)).expect("explicit path");
    unlock_vault_with_keyfile(&layout, &passphrase(), None).expect("recorded path");

    // Without it: its own class, its own exit code — never the generic
    // vault-auth failure, which would send the user to re-type a
    // passphrase that is perfectly correct.
    std::fs::remove_file(&keyfile).expect("unplug the second factor");
    let err = unlock_vault_with_keyfile(&layout, &passphrase(), None).expect_err("no keyfile");
    assert_eq!(err.class(), ErrorClass::VaultKeyfileMissing);
    assert_eq!(err.exit_code(), 18);
    assert_ne!(err.class(), ErrorClass::VaultAuthFailure);
    let rendered = err.to_string();
    assert!(rendered.contains("second-factor.key"), "{rendered}");
    assert!(rendered.contains("ANTSEAL_KEYFILE"), "{rendered}");
}

/// A *wrong* keyfile is an authentication failure, not a missing-keyfile
/// error: the file was there and the right size, so what failed is the
/// key — which is precisely U6's deliberate one-code collapse.
#[test]
fn a_wrong_keyfile_is_an_auth_failure_and_a_wrong_passphrase_still_is_too() {
    let dir = Dir::new("wrong");
    let layout = dir.layout();
    let keyfile = dir.keyfile();
    drop(
        create_vault_with_wrap(
            &layout,
            &passphrase(),
            KdfSelection::Argon2id,
            &WrapChoice::Keyfile {
                path: keyfile.clone(),
                record_path: true,
            },
            &mut rng(0x42),
        )
        .expect("create"),
    );

    let decoy = dir.0.join("decoy.key");
    std::fs::write(&decoy, [0x77u8; KEYFILE_LEN]).expect("write decoy");
    assert_eq!(
        unlock_vault_with_keyfile(&layout, &passphrase(), Some(&decoy))
            .expect_err("wrong keyfile")
            .class(),
        ErrorClass::VaultAuthFailure
    );

    // Right keyfile, wrong passphrase: still the same collapse.
    assert_eq!(
        unlock_vault_with_keyfile(
            &layout,
            &SecretBuf::new(b"not the passphrase".to_vec()),
            Some(&keyfile),
        )
        .expect_err("wrong passphrase")
        .class(),
        ErrorClass::VaultAuthFailure
    );
}

/// **U8 Accept row 2.** The mode is recorded in the header; flipping it is
/// an AEAD authentication failure (the header is AAD for every record);
/// and a header claiming the reserved mode 2 gets the distinct
/// "wrap mode not supported" refusal.
#[test]
fn the_header_records_the_mode_a_flip_fails_auth_and_mode_two_is_its_own_refusal() {
    let dir = Dir::new("header");
    let layout = dir.layout();
    let keyfile = dir.keyfile();
    drop(
        create_vault_with_wrap(
            &layout,
            &passphrase(),
            KdfSelection::Argon2id,
            &WrapChoice::Keyfile {
                path: keyfile.clone(),
                record_path: true,
            },
            &mut rng(0x43),
        )
        .expect("create"),
    );

    let header = header_of(&layout);
    assert_eq!(header.wrap_mode(), WRAP_MODE_KEYFILE);
    assert_eq!(
        header.keyfile_path(),
        Some(keyfile.display().to_string()).as_deref()
    );

    let header_path = layout.beside_path(BesideFile::Header);
    let original = std::fs::read(&header_path).expect("read");

    // Mode flip 1 → 0: a header that claims no wrap. It parses (0 is
    // registered) and the unlock then derives an unwrapped key, which
    // fails the key-check AEAD — the header is bound as AAD, so no edit
    // that survives the parser survives authentication.
    let flipped = VaultHeader::new(header.kdf_block().to_vec(), WRAP_MODE_NONE)
        .expect("mode 0 is registered")
        .encode()
        .expect("encodes");
    std::fs::write(&header_path, &flipped).expect("write");
    assert_eq!(
        unlock_vault_with_keyfile(&layout, &passphrase(), Some(&keyfile))
            .expect_err("a mode flip is caught")
            .class(),
        ErrorClass::VaultAuthFailure
    );

    // Mode 2: registered, unimplemented, and refused with its OWN class —
    // not corruption, not a wrong passphrase, and it says the vault is
    // intact so a later build can open it.
    let reserved = VaultHeader::new(header.kdf_block().to_vec(), WRAP_MODE_OS_KEYSTORE_RESERVED)
        .expect("mode 2 is registered")
        .encode()
        .expect("encodes");
    std::fs::write(&header_path, &reserved).expect("write");
    let err = unlock_vault_with_keyfile(&layout, &passphrase(), Some(&keyfile))
        .expect_err("mode 2 has no M1 implementation");
    assert_eq!(err.class(), ErrorClass::VaultWrapModeUnsupported);
    assert_eq!(err.exit_code(), 19);
    let rendered = err.to_string();
    assert!(rendered.contains("os-keystore"), "{rendered}");
    assert!(rendered.contains("does not implement"), "{rendered}");
    assert!(rendered.contains("intact"), "{rendered}");

    // The real header still opens: every failure above was about the
    // edit, not about a broken reader.
    std::fs::write(&header_path, &original).expect("restore");
    unlock_vault_with_keyfile(&layout, &passphrase(), Some(&keyfile)).expect("unharmed");
}

/// **U8 Accept row 3.** Declining the offer leaves a passphrase-only
/// vault: mode 0, no recorded path, and a header byte-identical in shape
/// to the ones every U6 test already exercises.
#[test]
fn declining_the_wrap_leaves_a_plain_mode_zero_vault() {
    let dir = Dir::new("declined");
    let declined = VaultLayout::at(dir.0.join("declined"));
    let plain = VaultLayout::at(dir.0.join("plain"));

    drop(
        create_vault_with_wrap(
            &declined,
            &passphrase(),
            KdfSelection::Argon2id,
            &WrapChoice::None,
            &mut rng(0x44),
        )
        .expect("create"),
    );
    drop(
        create_vault(
            &plain,
            &passphrase(),
            KdfSelection::Argon2id,
            &mut rng(0x44),
        )
        .expect("create"),
    );

    for layout in [&declined, &plain] {
        let header = header_of(layout);
        assert_eq!(header.wrap_mode(), WRAP_MODE_NONE);
        assert_eq!(header.keyfile_path(), None);
    }
    // Same RNG seed, same inputs: the explicit decline and the default
    // path produce the identical header bytes.
    assert_eq!(
        std::fs::read(declined.beside_path(BesideFile::Header)).expect("read"),
        std::fs::read(plain.beside_path(BesideFile::Header)).expect("read"),
    );
    // And it opens with no keyfile anywhere in sight.
    unlock_vault_with_keyfile(&declined, &passphrase(), None).expect("passphrase only");
}

/// A vault may carry mode 1 **without** recording where the keyfile is —
/// then nothing in the vault directory says where the second factor
/// lives, and the path must arrive out of band.
#[test]
fn an_unrecorded_path_forces_the_caller_to_supply_one() {
    let dir = Dir::new("unrecorded");
    let layout = dir.layout();
    let keyfile = dir.keyfile();
    drop(
        create_vault_with_wrap(
            &layout,
            &passphrase(),
            KdfSelection::Argon2id,
            &WrapChoice::Keyfile {
                path: keyfile.clone(),
                record_path: false,
            },
            &mut rng(0x45),
        )
        .expect("create"),
    );

    let header = header_of(&layout);
    assert_eq!(header.wrap_mode(), WRAP_MODE_KEYFILE);
    assert_eq!(
        header.keyfile_path(),
        None,
        "nothing in the vault directory points at the keyfile"
    );

    let err = unlock_vault_with_keyfile(&layout, &passphrase(), None)
        .expect_err("no path from any channel");
    assert_eq!(err.class(), ErrorClass::VaultKeyfileMissing);
    assert!(err.to_string().contains("ANTSEAL_KEYFILE"), "{err}");

    unlock_vault_with_keyfile(&layout, &passphrase(), Some(&keyfile))
        .expect("supplied out of band");
}

/// **D47, and U8's expectation deliberately overturned.** A v1 export is
/// encrypted under the passphrase alone, so writing one from a two-factor
/// vault would silently turn it into a one-factor backup. Both directions
/// refuse instead, and both say why.
#[test]
fn a_wrapped_vault_is_refused_by_export_and_a_wrapped_payload_by_import() {
    use antseal_cli::vault::export::export_vault;

    let dir = Dir::new("export");
    let layout = dir.layout();
    let keyfile = dir.keyfile();
    let vault = create_vault_with_wrap(
        &layout,
        &passphrase(),
        KdfSelection::Argon2id,
        &WrapChoice::Keyfile {
            path: keyfile,
            record_path: true,
        },
        &mut rng(0x46),
    )
    .expect("create");

    let out = dir.0.join("backup.sealvault");
    let err = export_vault(&vault, &passphrase(), &out, &mut rng(0x47))
        .expect_err("a two-factor vault has no one-factor backup");
    assert_eq!(err.class(), ErrorClass::Usage);
    let rendered = err.to_string();
    assert!(rendered.contains("passphrase alone"), "{rendered}");
    assert!(rendered.contains("two-factor"), "{rendered}");
    assert!(rendered.contains("nothing was written"), "{rendered}");
    assert!(
        !out.exists(),
        "the refusal must leave no half-written backup behind"
    );
}

/// The command name that must appear exactly when it will run.
const EXPORT_COMMAND: &str = "antseal vault export";

/// `init`'s report for a vault of the given class, in
/// `tests/init_command.rs::render_report_surface`'s idiom: constructed,
/// deterministic, and rendered by the real [`InitReport::render`].
fn report_for(wrapped: bool, vault_dir: &Path, keyfile: &Path) -> String {
    use antseal_cli::init::InitReport;
    use antseal_net::NetworkId;

    InitReport {
        address: "0x0000000000000000000000000000000000000000".to_owned(),
        network: NetworkId::Devnet,
        vault_dir: vault_dir.to_path_buf(),
        wallet_source: "generate",
        kdf: "argon2id",
        keyfile: wrapped.then(|| keyfile.to_path_buf()),
        asked: Vec::new(),
    }
    .render()
    .join("\n")
}

/// **U84 / D151 §2 R10.** The backup advice and the backup command,
/// measured against each other instead of against themselves.
///
/// What this replaces and why: `vault::keyfile`'s unit guard asserted that
/// `placement_guidance(...)` *contained the string* "does NOT contain the
/// keyfile" — the copy checked against its own words, green precisely
/// because the sentence existed, while the sentence was false. Do not
/// reintroduce a check whose expected value is the copy under test.
///
/// The two faults a copy-versus-copy test cannot see, and which this one
/// catches: putting `antseal vault export` back into `LOSS_WARNING` (it
/// reddens the wrapped row only, which is exactly why the old guard was
/// blind to it), and making the class parameter decorative.
///
/// **What this test cannot see on its own, measured rather than assumed.**
/// `copy` is the join of three producers, so `contains` is an OR over
/// them: a regression in exactly one producer's mode-0 arm hides behind
/// the other two and this test stays green. Both halves were planted and
/// watched — swapping only `init::standing_warnings`'s mode-0 arm leaves
/// this test green and reddens `init`'s own two-arm unit test; emptying
/// only `export_nag` leaves this test green and reddens
/// `vault::bookkeeping`'s. Each producer therefore keeps its own two-arm
/// guard (D151 §2 R11) and this test holds only the cross-producer claim.
/// Do not delete either unit pair on the grounds that "the integration
/// test covers it" — measured, it does not.
#[test]
fn the_backup_advice_matches_what_export_actually_does() {
    use antseal_cli::init::standing_warnings;
    use antseal_cli::vault::bookkeeping::export_nag;
    use antseal_cli::vault::export::export_vault;

    for wrapped in [false, true] {
        let dir = Dir::new(if wrapped {
            "advice-wrapped"
        } else {
            "advice-plain"
        });
        let layout = dir.layout();
        let keyfile = dir.keyfile();
        let wrap = if wrapped {
            WrapChoice::Keyfile {
                path: keyfile.clone(),
                record_path: true,
            }
        } else {
            WrapChoice::None
        };
        let vault = create_vault_with_wrap(
            &layout,
            &passphrase(),
            KdfSelection::Argon2id,
            &wrap,
            &mut rng(0x52),
        )
        .expect("create");

        // 1. What the product DOES, measured, not assumed.
        let out = dir.0.join("backup.sealvault");
        let export = export_vault(&vault, &passphrase(), &out, &mut rng(0x53));
        let succeeded = export.is_ok();
        assert_eq!(
            succeeded, !wrapped,
            "wrap mode {wrapped}: `vault export`'s own verdict moved. If that is \
             deliberate it is a D47 format event and D151 §2 R1 must be re-ruled \
             before this copy changes: {export:?}"
        );
        // The refusal must be the **deliberate** one, and `is_ok()` alone
        // cannot say so — measured, not assumed. Deleting the export-side
        // refusal (`vault/export.rs`, the overturned-U8 block) does NOT
        // make a wrapped export succeed: the mandatory D47 self-verify
        // re-reads the file through full import-side validation, whose
        // own wrap refusal then fails it as `ExportSelfVerifyFailed`. So
        // `succeeded` is `false` in both worlds and the plant D151 §2
        // R10's T1 names would pass over an `is_ok()` check. R1's stated
        // verification is the refusal's *verdict* per class; this is it.
        if wrapped {
            let err = export.as_ref().expect_err("the wrapped arm refuses");
            assert_eq!(
                err.class(),
                ErrorClass::Usage,
                "wrap mode {wrapped}: the export failed, but not with the deliberate \
                 pre-write refusal — it reached the write path and died downstream. \
                 The copy in this test is written against a refusal that names the \
                 by-hand procedure and writes nothing; that refusal is gone: {err:?}"
            );
            let rendered = err.to_string();
            assert!(
                rendered.contains("separately by hand"),
                "wrap mode {wrapped}: the refusal no longer names the by-hand procedure \
                 that `BACKUP_BY_HAND` sends the user to: {rendered}"
            );
            assert!(
                !out.exists(),
                "wrap mode {wrapped}: the refusal must leave no half-written backup"
            );
        }

        // 2. What the product SAYS to a user of this class, from the real
        //    producers — `init`'s whole report (which composes
        //    `placement_guidance` and `standing_warnings`) and `seal`'s nag.
        //    The second element is redundant *by design*: it pins the
        //    producer directly, so a future `render()` that stops calling
        //    it cannot hide a false line behind the composition.
        let copy = [
            report_for(wrapped, layout.root(), &keyfile),
            standing_warnings(wrapped).join("\n"),
            export_nag(wrapped).join("\n"),
        ]
        .join("\n");

        // Anti-vacuity: the class-keyed line was reached at all. Without
        // this, an empty `copy` would satisfy the wrapped row for free.
        assert!(
            copy.contains("BACK UP"),
            "wrap mode {wrapped}: no backup line rendered"
        );
        assert!(
            copy.len() > 1_000,
            "wrap mode {wrapped}: copy is {} bytes",
            copy.len()
        );

        // 3. The biconditional. Both directions are defects.
        assert_eq!(
            copy.contains(EXPORT_COMMAND),
            succeeded,
            "wrap mode {wrapped}: the CLI {} `{EXPORT_COMMAND}` while the command {}. \
             U84: no antseal output may name a command that refuses the vault it is \
             describing, and none may withhold the one that works.",
            if copy.contains(EXPORT_COMMAND) {
                "names"
            } else {
                "does not name"
            },
            if succeeded { "runs" } else { "refuses" },
        );
    }
}

/// U8 Accept row 4's dependency assertion — **narrowed to what is true**,
/// and the narrowing is a finding rather than a convenience.
///
/// The row reads "no keystore crate in the workspace graph". Taken
/// literally it is already false and was false before U8: `keyring` sits
/// in `Cargo.lock` as a transitive dependency of `ant-quic`, which arrives
/// through the **`ant-backend` feature's** ant-core graph. D50's actual
/// claim — the one its evidence supports and the one that protects the
/// vault — is that *the wrap itself* introduces no keystore crate and no
/// new dependency of any kind.
///
/// So this asserts two things that are both true and both load-bearing:
/// the CLI's own manifest names none (U8 added zero edges), and the
/// **default-feature** graph — what a plain `cargo build` produces, and
/// what `scripts/ci-lanes.sh dep-graph` pins at 129 packages — contains
/// none either. Recorded as **U43**.
#[test]
fn the_keyfile_wrap_added_no_dependency_and_the_default_graph_has_no_keystore() {
    const KEYSTORE_CRATES: [&str; 4] = [
        "keyring",
        "linux-keyutils",
        "security-framework",
        "secret-service",
    ];

    let manifest =
        std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml"))
            .expect("read the CLI manifest");
    for forbidden in KEYSTORE_CRATES {
        assert!(
            !manifest.contains(forbidden),
            "D50: the keyfile wrap ships with ZERO new dependencies, and `{forbidden}` is in \
             the manifest"
        );
    }

    // The default-feature graph, from cargo itself rather than from a
    // hand-maintained list.
    let out = std::process::Command::new(env!("CARGO"))
        .args([
            "tree",
            "-p",
            "antseal-cli",
            "--edges",
            "normal",
            "--prefix",
            "none",
        ])
        .current_dir(Path::new(env!("CARGO_MANIFEST_DIR")).join("../.."))
        .output()
        .expect("cargo tree");
    assert!(out.status.success(), "cargo tree failed");
    let tree = String::from_utf8_lossy(&out.stdout);
    for forbidden in KEYSTORE_CRATES {
        assert!(
            !tree.lines().any(|l| l.starts_with(forbidden)),
            "D50: `{forbidden}` reached the DEFAULT antseal-cli graph"
        );
    }
    // …and the wrap's own primitives are ones already present.
    assert!(tree.lines().any(|l| l.starts_with("hkdf ")), "{tree}");
    assert!(tree.lines().any(|l| l.starts_with("sha2 ")), "{tree}");
}
