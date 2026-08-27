//! U21 — the secret-hygiene harness.
//!
//! # What it proves
//!
//! A vault is built whose every secret is a **known sentinel**: the
//! passphrase, the wallet key, and the per-work master secret `W`. Every
//! implemented command is then driven against it at every verbosity level
//! the surface has (`RUST_LOG` unset, `debug`, `trace`), in plain and
//! `--json` mode, and every byte the process emits — stdout, stderr, the
//! JSON document, and the files it wrote outside the vault — is scanned
//! for those sentinels in **raw, lowercase-hex, uppercase-hex and base64**
//! form.
//!
//! "Every implemented command" is a claim, so it is machine-checked:
//! `COMMANDS` must cover exactly `machine::ALL_COMMAND_NAMES`
//! ([`the_harness_enumerates_every_command_on_the_surface`]), and the set
//! the harness *actually drove* is read back and checked against the same
//! axis. `init` is the one command that cannot meet the sentinel vault —
//! it refuses when a vault already exists — so its cells get a fresh
//! empty home each and really do build a vault out of the sentinel
//! passphrase, which is then unlocked with it to prove they did.
//!
//! Per D41 the scan also covers the running process's own
//! `/proc/<pid>/cmdline` and `/proc/<pid>/environ`. That channel is why
//! `--passphrase-fd` exists at all: argv and the environment are readable
//! by any process of the same user for the lifetime of the process and
//! cannot be wiped, so "antseal never puts a secret there" has to be a
//! measured fact rather than a coding convention.
//!
//! # Why the self-tests are the important part
//!
//! A scanner that cannot fail proves nothing. Four self-tests plant a
//! sentinel where the harness claims to look — in an environment
//! variable, in argv, in stdout, and in each encoding — and require the
//! scanner to catch it. If the D41 assertion ever becomes false, these
//! are what makes the rest of the file go red rather than stay silently
//! green.
//!
//! # Deliberately NOT here
//!
//! `scripts/ci-lanes.sh secret-guard` is the sibling that scans the
//! *repository* for secret-shaped literals. This file scans a *running
//! process*. Neither subsumes the other: a hard-coded key is a source
//! problem, and a key echoed into a log line is a runtime problem.
//!
//! NON-SECRET: every sentinel here is a documented fixture (project rule
//! 6) — deliberately shaped so that a real value could never equal it.

#[path = "common/spawn.rs"]
mod spawn;
use std::collections::BTreeSet;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use antseal_cli::machine::ALL_COMMAND_NAMES;
use antseal_cli::vault::kdf::KdfSelection;
use antseal_cli::vault::layout::{BesideFile, VaultLayout};
use antseal_cli::vault::session::create_vault;
use antseal_cli::vault::store::{SealShapingFlags, WorkRecord, WorkState, WorkStore};
use antseal_cli::vault::wallet::{WalletKeyHandle, store_wallet_key};
use antseal_core::crypto::secrets::{MasterSecret, SealId, SecretBuf};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

// ─────────────────────────────────────────────────────────────────────
// The sentinels
// ─────────────────────────────────────────────────────────────────────

/// The vault passphrase. Long enough to clear U7's 12-byte create floor,
/// and shaped so no real passphrase could collide.
const SENTINEL_PASSPHRASE: &str = "ANTSEAL-U21-SENTINEL-PASSPHRASE-NEVER-PRINT-ME";

/// The wallet key: a valid secp256k1 scalar (far below the group order)
/// whose hex spelling is a distinctive repeating run.
const SENTINEL_WALLET_KEY: [u8; 32] = [
    0x0D, 0xEC, 0x0D, 0xE5, 0x0D, 0xEC, 0x0D, 0xE5, 0x0D, 0xEC, 0x0D, 0xE5, 0x0D, 0xEC, 0x0D, 0xE5,
    0x0D, 0xEC, 0x0D, 0xE5, 0x0D, 0xEC, 0x0D, 0xE5, 0x0D, 0xEC, 0x0D, 0xE5, 0x0D, 0xEC, 0x0D, 0xE5,
];

/// A work's master secret `W` — the reason the vault exists.
const SENTINEL_W: [u8; 32] = [
    0x11, 0x5E, 0xC2, 0xE7, 0x11, 0x5E, 0xC2, 0xE7, 0x11, 0x5E, 0xC2, 0xE7, 0x11, 0x5E, 0xC2, 0xE7,
    0x11, 0x5E, 0xC2, 0xE7, 0x11, 0x5E, 0xC2, 0xE7, 0x11, 0x5E, 0xC2, 0xE7, 0x11, 0x5E, 0xC2, 0xE7,
];

/// One sentinel and every spelling of it the scan looks for.
struct Sentinel {
    what: &'static str,
    forms: Vec<String>,
}

fn sentinels() -> Vec<Sentinel> {
    let mut out = vec![Sentinel {
        what: "the vault passphrase",
        forms: spellings(SENTINEL_PASSPHRASE.as_bytes()),
    }];
    out.push(Sentinel {
        what: "the wallet key",
        forms: spellings(&SENTINEL_WALLET_KEY),
    });
    out.push(Sentinel {
        what: "the work's master secret W",
        forms: spellings(&SENTINEL_W),
    });
    // Salts are HKDF-derived from `W` with frozen labels, so they leak
    // only if `W` does — but "covered transitively" is a claim, and this
    // turns it into a measurement over one concrete derived value.
    let derived = antseal_core::crypto::hkdf::derive_file_salt(
        antseal_core::crypto::material::MasterSecretRef::from_bytes(&SENTINEL_W),
        antseal_core::crypto::hkdf::FileId(0),
    );
    out.push(Sentinel {
        what: "a salt derived from W",
        forms: spellings(derived.expose_bytes_for_test_vectors()),
    });
    out
}

/// Raw, lowercase hex, uppercase hex, and base64 — the four ways a secret
/// realistically escapes into text.
fn spellings(bytes: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    if let Ok(text) = std::str::from_utf8(bytes) {
        out.push(text.to_owned());
    }
    let lower: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    let upper = lower.to_uppercase();
    out.push(lower);
    out.push(upper);
    out.push(base64(bytes));
    // A short prefix is not distinctive enough to assert on; every form
    // used here is at least 16 characters.
    out.retain(|f| f.len() >= 16);
    out
}

/// Std-alphabet base64, unpadded-safe (test-only; no dependency joins the
/// graph for four lines of arithmetic).
fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(ALPHABET[((n >> (18 - 6 * i)) & 0x3F) as usize] as char);
            }
        }
    }
    out
}

/// The scan itself: `Err(description)` when any sentinel appears.
fn scan(haystack: &str, where_: &str) -> Result<(), String> {
    for sentinel in sentinels() {
        for form in &sentinel.forms {
            if haystack.contains(form.as_str()) {
                return Err(format!(
                    "{where_} contains {} (as {} bytes of text). Secret material must never \
                     reach an output stream, a log, a JSON document or process metadata \
                     (project rule 6; D41)",
                    sentinel.what,
                    form.len()
                ));
            }
        }
    }
    Ok(())
}

/// The same scan over raw bytes (files, /proc entries — which are
/// NUL-separated and not valid UTF-8 as a whole).
fn scan_bytes(haystack: &[u8], where_: &str) -> Result<(), String> {
    scan(&String::from_utf8_lossy(haystack), where_)
}

// ─────────────────────────────────────────────────────────────────────
// The self-tests: the harness must be able to fail
// ─────────────────────────────────────────────────────────────────────

#[test]
fn the_scanner_catches_a_planted_sentinel_in_every_encoding() {
    // Raw.
    assert!(scan(&format!("prefix {SENTINEL_PASSPHRASE} suffix"), "self-test").is_err());
    // Lowercase hex, uppercase hex, base64 — of the wallet key.
    let lower: String = SENTINEL_WALLET_KEY
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    assert!(scan(&format!("key={lower}"), "self-test").is_err());
    assert!(scan(&format!("key={}", lower.to_uppercase()), "self-test").is_err());
    assert!(
        scan(
            &format!("key={}", base64(&SENTINEL_WALLET_KEY)),
            "self-test"
        )
        .is_err(),
        "the base64 spelling must be caught: a Debug impl that prints a \
         base64 blob leaks exactly as much as one that prints hex"
    );
    // W and a derived salt.
    let w_hex: String = SENTINEL_W.iter().map(|b| format!("{b:02x}")).collect();
    assert!(scan(&w_hex, "self-test").is_err());

    // And ordinary output passes, so the scan is not vacuously red.
    scan(
        "Sealed. work-id a1a1a1a1  cost 4200000000000000000 atto-ANT",
        "self-test",
    )
    .expect("a clean line passes");
}

#[test]
fn the_base64_encoder_agrees_with_the_published_vectors() {
    // RFC 4648 §10 — so a broken encoder cannot make the base64 arm of
    // the scan silently unable to match anything.
    assert_eq!(base64(b"f"), "Zg");
    assert_eq!(base64(b"fo"), "Zm8");
    assert_eq!(base64(b"foo"), "Zm9v");
    assert_eq!(base64(b"foob"), "Zm9vYg");
    assert_eq!(base64(b"fooba"), "Zm9vYmE");
    assert_eq!(base64(b"foobar"), "Zm9vYmFy");
}

/// **The D41 env-leak self-test**: a sentinel deliberately exported into
/// the child's environment MUST be caught by the environ scan. Without
/// this, "no secret reaches the environment" would be an assertion the
/// harness is incapable of falsifying.
///
/// The child has to still *exist* when `/proc` is read, which is a real
/// constraint and one the first draft of this file got wrong: a stub
/// command answers and exits in milliseconds, `/proc/<pid>` disappears
/// with it, and the scan then finds nothing and reports a clean pass —
/// the exact silent-success failure these tests exist to prevent. So the
/// child is one that genuinely **blocks**: a vault-touching command with
/// `--passphrase-fd 0`, parked reading a pipe this process holds open.
#[test]
fn the_environ_scan_can_fail() {
    let vault = SentinelVault::create();
    let home = vault.home.clone();
    let held = HeldChild::spawn(&["list", "--passphrase-fd", "0"], |cmd| {
        cmd.env("HOME", &home)
            .current_dir(&home)
            .env("ANTSEAL_U21_DELIBERATE_LEAK", SENTINEL_PASSPHRASE);
    });
    let environ = held.read_proc("environ");
    held.finish();
    assert!(
        !environ.is_empty(),
        "the child's environ read back empty — nothing to scan either way"
    );
    assert!(
        scan_bytes(&environ, "the child's environ").is_err(),
        "the environ scan did not catch a sentinel planted in the child's \
         environment — the D41 measurement is not measuring anything"
    );
}

/// The same, for argv.
#[test]
fn the_cmdline_scan_can_fail() {
    // `vault export [FILE]` takes an optional positional AND blocks on
    // the passphrase, so the sentinel really lands in argv of a process
    // that is still alive to be inspected.
    let vault = SentinelVault::create();
    let home = vault.home.clone();
    let held = HeldChild::spawn(
        &[
            "vault",
            "export",
            SENTINEL_PASSPHRASE,
            "--passphrase-fd",
            "0",
        ],
        |cmd| {
            cmd.env("HOME", &home).current_dir(&home);
        },
    );
    let cmdline = held.read_proc("cmdline");
    held.finish();
    assert!(
        !cmdline.is_empty(),
        "the child's cmdline read back empty — nothing to scan either way"
    );
    assert!(
        scan_bytes(&cmdline, "the child's cmdline").is_err(),
        "the cmdline scan did not catch a sentinel planted in argv"
    );
}

// ─────────────────────────────────────────────────────────────────────
// The sentinel vault
// ─────────────────────────────────────────────────────────────────────

struct SentinelVault {
    home: PathBuf,
    _root: PathBuf,
}

impl SentinelVault {
    /// A real vault, created through the real APIs, holding all three
    /// sentinels: the passphrase (as the KDF input), the wallet key
    /// (under U10's sub-key) and one work record carrying `W`.
    fn create() -> Self {
        let root = std::env::temp_dir().join(format!(
            "antseal-u21-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        let home = root.join("home");
        std::fs::create_dir_all(&home).expect("mk home");
        let layout = VaultLayout::at(home.join(".antseal"));

        let passphrase = SecretBuf::new(SENTINEL_PASSPHRASE.as_bytes().to_vec());
        let mut rng = ChaCha20Rng::from_seed([0x21; 32]);
        create_vault(&layout, &passphrase, KdfSelection::Argon2id, &mut rng)
            .expect("create the sentinel vault");

        let vault = antseal_cli::vault::session::unlock_vault(&layout, &passphrase)
            .expect("unlock the sentinel vault");
        store_wallet_key(
            &vault,
            &WalletKeyHandle::from_bytes(SENTINEL_WALLET_KEY),
            &mut rng,
        )
        .expect("store the sentinel wallet key");

        // A work whose `W` is the sentinel, in the state `list` renders
        // most fully (complete, with a cost and a title).
        let store = WorkStore::new(&vault);
        let record = WorkRecord {
            w: MasterSecret::from_bytes(SENTINEL_W),
            seal_id: SealId::from_bytes([0xE7; 16]),
            network: "devnet".to_owned(),
            state: WorkState::Complete,
            degraded: false,
            unanchored: true,
            input_paths_as_given: vec!["notes.txt".to_owned()],
            input_paths_absolute: vec!["/w/notes.txt".to_owned()],
            shaping: SealShapingFlags {
                title: Some("a sentinel work".to_owned()),
                no_anchor: true,
                ..SealShapingFlags::default()
            },
            work_id: Some([0xA7; 32]),
            cost_atto: Some(4_200_000_000_000_000_000),
            consent: Some(antseal_cli::vault::store::ConsentRecord {
                total_ant_atto: 4_200_000_000_000_000_000,
                gas_estimate_wei: 21_000,
                consent_time_unix_secs: 1_798_762_000,
                channel: antseal_cli::vault::store::ConsentChannel::YesFlag,
            }),
        };
        store
            .create_work(&record, &mut rng)
            .expect("write the sentinel work record");

        Self { home, _root: root }
    }

    /// An **empty** home beside the sentinel vault, for the one command
    /// that must not meet an existing one.
    ///
    /// `init` refuses outright when a vault already exists (D39 Decision
    /// 4; `run_init` step 1) and it refuses *before* a passphrase is
    /// collected — so an `init` cell pointed at the sentinel home would
    /// scan a usage error and never reach the passphrase-handling path
    /// this harness exists to measure. Each cell gets its own fresh home
    /// instead, under the same root, so `Drop` still cleans them all up.
    fn fresh_home(&self, tag: &str) -> PathBuf {
        let home = self._root.join(tag);
        std::fs::create_dir_all(&home).expect("mk a fresh home");
        home
    }
}

impl Drop for SentinelVault {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self._root);
    }
}

// ─────────────────────────────────────────────────────────────────────
// Driving the binary
// ─────────────────────────────────────────────────────────────────────

fn bin() -> Command {
    let mut cmd = spawn::antseal();
    // A clean slate: nothing the developer's shell exports may seed a
    // false pass (or a false fail).
    cmd.env_remove("RUST_LOG");
    cmd.env_remove("ANTSEAL_DEVNET_ENV");
    cmd
}

/// One completed invocation's observable output.
struct Observed {
    label: String,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

/// Run one command with the sentinel passphrase supplied over the D41 fd
/// channel (never argv, never the environment).
///
/// `home` is the `HOME` the child sees: the sentinel vault's for every
/// command that reads a vault, a fresh empty one for `init`, which
/// creates one (see [`SentinelVault::fresh_home`]).
fn run(home: &Path, args: &[&str], verbosity: Option<&str>, json: bool) -> Observed {
    let mut argv: Vec<String> = args.iter().map(|s| (*s).to_owned()).collect();
    argv.push("--passphrase-fd".to_owned());
    argv.push("0".to_owned());
    if json {
        argv.push("--json".to_owned());
    }

    let mut cmd = bin();
    cmd.env("HOME", home)
        .current_dir(home)
        .args(&argv)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(level) = verbosity {
        cmd.env("RUST_LOG", level);
    }

    let mut child = cmd.spawn().expect("spawn antseal");
    child
        .stdin
        .as_mut()
        .expect("stdin is piped")
        .write_all(SENTINEL_PASSPHRASE.as_bytes())
        .expect("write the sentinel passphrase");
    drop(child.stdin.take());
    let out = child.wait_with_output().expect("collect output");

    Observed {
        label: format!(
            "`antseal {}`{}{}",
            argv.join(" "),
            verbosity
                .map(|v| format!(" RUST_LOG={v}"))
                .unwrap_or_default(),
            if json { " [json]" } else { "" }
        ),
        stdout: out.stdout,
        stderr: out.stderr,
    }
}

/// A child held alive on an unclosed stdin pipe, so `/proc/<pid>/…` can
/// be read while it exists.
struct HeldChild {
    child: std::process::Child,
}

impl HeldChild {
    fn spawn(args: &[&str], tweak: impl FnOnce(&mut Command)) -> Self {
        let mut cmd = bin();
        cmd.args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        tweak(&mut cmd);
        Self {
            child: cmd.spawn().expect("spawn antseal"),
        }
    }

    /// Read one `/proc/<pid>/` entry of the child — **after** waiting for
    /// its `execve` to have happened.
    ///
    /// # The bug this exists to prevent (found by the self-tests below)
    ///
    /// `fork` gives the child a copy of the *parent's* argv and
    /// environment, and only `execve` replaces them. A read taken between
    /// the two returns **this test binary's** cmdline and environ — which
    /// are non-empty, contain no sentinel, and therefore make every scan
    /// here pass while measuring the wrong process entirely. The first
    /// draft polled for non-emptiness and did exactly that; the two
    /// deliberately-leaky self-tests are what caught it, which is the
    /// whole argument for having them.
    ///
    /// So the wait condition is not "non-empty" but "`/proc/<pid>/cmdline`
    /// names the binary we spawned", and failing to reach that state is a
    /// loud panic rather than a silent empty read.
    fn read_proc(&self, what: &str) -> Vec<u8> {
        let exe = spawn::antseal_exe();
        for _ in 0..500 {
            if String::from_utf8_lossy(&self.read_proc_raw("cmdline")).contains(exe) {
                return self.read_proc_raw(what);
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        panic!(
            "/proc/{}/cmdline never named {exe}: the child either exited before it could be \
             inspected or never exec'd, and scanning it now would measure this test binary \
             rather than antseal",
            self.child.id()
        );
    }

    fn read_proc_raw(&self, what: &str) -> Vec<u8> {
        std::fs::read(format!("/proc/{}/{what}", self.child.id())).unwrap_or_default()
    }

    fn finish(mut self) {
        drop(self.child.stdin.take());
        let _ = self.child.wait();
    }
}

// ─────────────────────────────────────────────────────────────────────
// The harness proper
// ─────────────────────────────────────────────────────────────────────

/// Every command the surface has, with a minimal valid argv. Stubs are
/// included deliberately: a stub that grew a secret-bearing message would
/// be caught the moment it landed, not the moment someone remembered to
/// add it here.
///
/// # This array is not the enumeration axis — it is *checked against* it
///
/// [`ALL_COMMAND_NAMES`] is the axis, and
/// [`the_harness_enumerates_every_command_on_the_surface`] asserts set
/// equality between the two. Hand-maintaining a second list beside the
/// canonical one is precisely how `init` — the command that takes the
/// passphrase at its rawest — went unscanned here from the day this file
/// landed. It was never typed, the doc comment above said "every command
/// the surface has", and nothing in the workspace was capable of noticing
/// the difference. An eleventh command
/// now cannot reach the surface without either appearing here or
/// reddening that test.
const COMMANDS: [&[&str]; 10] = [
    // First, so the array opens on the name `ALL_COMMAND_NAMES` opens on
    // — and so a leak planted in `init`'s output reddens the harness in
    // seconds rather than after fifty-odd other cells.
    //
    // What this cell covers: the **passphrase** at its rawest. It arrives
    // on the D41 fd channel, becomes a KDF input, and a vault is really
    // built out of it — asserted below by unlocking that vault with it.
    //
    // What it does not, and why the gap is structural rather than
    // forgotten: the cell's wallet key is `--wallet generate`'s fresh
    // one, not `SENTINEL_WALLET_KEY`. Feeding the sentinel key in needs
    // `--wallet import --wallet-key-fd <n>` with `n != 0` (0 is taken by
    // `--passphrase-fd`, and equal fds are a usage error), and handing a
    // child an fd above 2 needs `CommandExt::pre_exec` — `unsafe`, which
    // `[workspace.lints.rust] unsafe_code = "deny"` refuses workspace-wide
    // for the same reason `common/spawn.rs` records. The sentinel wallet
    // key is measured through every *other* command instead, over the
    // vault that already holds it.
    &["init"],
    &["list"],
    &["show", "a7a7a7a7"],
    &["status", "a7a7a7a7"],
    &["restore", "a7a7a7a7"],
    &["reveal", "a7a7a7a7", "--all", "--yes"],
    &["verify", "nonexistent.sealproof"],
    &["vault", "export"],
    &["vault", "import", "nonexistent.sealvault"],
    &[
        "seal",
        "notes.txt",
        "--no-anchor",
        "--network",
        "devnet",
        "--yes",
    ],
];

/// The canonical command name one harness argv drives, spelled the way
/// [`ALL_COMMAND_NAMES`] spells it.
///
/// Longest matching prefix rather than `argv[0]`, because `vault export`
/// and `vault import` are two-token names: a first-token rule would
/// collapse them into a single entry called `vault`, which is not on the
/// surface at all, and would make the completeness check simultaneously
/// wrong in one direction and blind in the other.
fn canonical_name(argv: &[&str]) -> &'static str {
    for take in (1..=argv.len().min(3)).rev() {
        let candidate = argv[..take].join(" ");
        if let Some(name) = ALL_COMMAND_NAMES.iter().find(|n| **n == candidate) {
            return name;
        }
    }
    panic!(
        "`antseal {}` begins with no name in ALL_COMMAND_NAMES ({ALL_COMMAND_NAMES:?}), so the \
         harness cannot say which command it covers",
        argv.join(" ")
    );
}

/// Assert that `covered` is **exactly** the command surface, naming both
/// directions of the difference.
///
/// Set equality, not `len()`. A length check passes on a swap — drop one
/// command, duplicate another — and passes on a rename, which are the two
/// ways a hand-maintained list realistically goes wrong once someone is
/// already looking at it.
fn assert_covers_the_surface(covered: &BTreeSet<&'static str>, what: &str) {
    let declared: BTreeSet<&'static str> = ALL_COMMAND_NAMES.iter().copied().collect();
    let missing: Vec<&str> = declared.difference(covered).copied().collect();
    let extra: Vec<&str> = covered.difference(&declared).copied().collect();
    assert!(
        missing.is_empty() && extra.is_empty(),
        "{what} is not the command surface. Never scanned: {missing:?}. Not on the surface: \
         {extra:?}. U21's `Do` opens its flow list on `init`, and U32 Accept asks for this \
         harness \"green across the full command set\" — `ALL_COMMAND_NAMES` is what \"full\" \
         means here. A command that reaches the surface without reaching this harness is a \
         secret-bearing path nobody measures"
    );
}

/// **The mechanism this file was missing.** `COMMANDS` covers exactly
/// [`ALL_COMMAND_NAMES`]: no command on the surface goes unscanned, and
/// no entry here names a command that no longer exists.
///
/// Cheap and vault-free on purpose — it answers in milliseconds, so the
/// enumeration defect is reported by its own name rather than inferred
/// from a seventy-second harness that stayed green while never running
/// the command in question.
#[test]
fn the_harness_enumerates_every_command_on_the_surface() {
    let covered: BTreeSet<&'static str> =
        COMMANDS.iter().map(|argv| canonical_name(argv)).collect();
    assert_covers_the_surface(&covered, "the COMMANDS table");
}

/// Scan every file under `dir`, recursively; returns how many were read,
/// so a caller can refuse a walk that found nothing.
fn scan_tree(dir: &Path) -> usize {
    let mut scanned = 0;
    for entry in std::fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("read {}: {e}", dir.display()))
        .flatten()
    {
        let path = entry.path();
        if path.is_dir() {
            scanned += scan_tree(&path);
        } else if path.is_file() {
            let bytes = std::fs::read(&path).expect("read a produced file");
            scan_bytes(&bytes, &format!("the file {}", path.display()))
                .unwrap_or_else(|e| panic!("{e}"));
            scanned += 1;
        }
    }
    scanned
}

/// **The harness.** Every command × every verbosity × {plain, `--json`},
/// against a vault whose every secret is a sentinel.
#[test]
fn no_command_at_any_verbosity_emits_a_sentinel() {
    let vault = SentinelVault::create();
    // A real input file, so `seal` gets past argument validation and into
    // the code that actually holds secrets.
    std::fs::write(vault.home.join("notes.txt"), b"sentinel work content\n")
        .expect("write the input file");

    let mut ran = 0usize;
    let mut ran_names: BTreeSet<&'static str> = BTreeSet::new();
    let mut init_homes: Vec<PathBuf> = Vec::new();
    for command in COMMANDS {
        let name = canonical_name(command);
        for verbosity in [None, Some("debug"), Some("trace")] {
            for json in [false, true] {
                // `init` is the one command that creates a vault rather
                // than reading one, so it needs a home with none.
                let home = if name == "init" {
                    let fresh = vault.fresh_home(&format!("init-home-{ran}"));
                    init_homes.push(fresh.clone());
                    fresh
                } else {
                    vault.home.clone()
                };
                let observed = run(&home, command, verbosity, json);
                ran += 1;
                ran_names.insert(name);
                scan_bytes(&observed.stdout, &format!("{}: stdout", observed.label))
                    .unwrap_or_else(|e| panic!("{e}"));
                scan_bytes(&observed.stderr, &format!("{}: stderr", observed.label))
                    .unwrap_or_else(|e| panic!("{e}"));
            }
        }
    }
    assert_eq!(
        ran,
        COMMANDS.len() * 3 * 2,
        "the harness must actually have run every cell"
    );
    // The axis, read back off what actually ran rather than off the
    // table. `the_harness_enumerates_every_command_on_the_surface` checks
    // the declaration; this checks the execution, and a `continue` in the
    // loop above would satisfy the first and defeat the second.
    assert_covers_the_surface(&ran_names, "the set of commands the harness actually drove");

    // `init` must genuinely have *built* a vault out of the sentinel
    // passphrase. If it had refused early — an existing vault, a missing
    // channel — its cells would have scanned a usage error, the harness
    // would still be green, and the passphrase would still be unmeasured
    // at its rawest, which is the exact failure this case exists to end.
    assert_eq!(init_homes.len(), 3 * 2, "one fresh home per `init` cell");
    for home in &init_homes {
        let header = VaultLayout::at(home.join(".antseal")).beside_path(BesideFile::Header);
        assert!(
            header.exists(),
            "`init` wrote no vault header at {} — that cell scanned a refusal, not the \
             passphrase-handling path",
            header.display()
        );
    }
    // And one of those vaults opens with the sentinel passphrase, which
    // is the only thing that proves the D41 fd channel — rather than some
    // default or an empty read — is what `init` derived the vault key
    // from.
    antseal_cli::vault::session::unlock_vault(
        &VaultLayout::at(init_homes[0].join(".antseal")),
        &SecretBuf::new(SENTINEL_PASSPHRASE.as_bytes().to_vec()),
    )
    .expect("the vault `init` built opens with the sentinel passphrase it was fed on fd 0");

    // Those vaults are where the passphrase is allowed to have left a
    // trace — as a KDF salt and a wrapped key, never as itself. Scan
    // every byte of them.
    for home in &init_homes {
        assert!(
            scan_tree(home) >= 1,
            "the walk of {} read no files at all — a clean scan of nothing is not a pass",
            home.display()
        );
    }

    // The commands wrote files outside the vault (a `vault export`
    // backup, at least). Those are encrypted, but "encrypted" is the
    // claim under test — scan them.
    let mut scanned_files = 0usize;
    for entry in std::fs::read_dir(&vault.home)
        .expect("read the home dir")
        .flatten()
    {
        let path = entry.path();
        if path.is_file() {
            let bytes = std::fs::read(&path).expect("read a produced file");
            scan_bytes(&bytes, &format!("the file {}", path.display()))
                .unwrap_or_else(|e| panic!("{e}"));
            scanned_files += 1;
        }
    }
    assert!(
        scanned_files >= 2,
        "expected at least notes.txt and a vault export beside it; found {scanned_files}"
    );
}

/// **D41's measurement**: while a real invocation is running with the
/// passphrase travelling over the fd channel, neither its argv nor its
/// environment carries any sentinel.
///
/// The two self-tests above prove this scan can fail; this is the
/// positive half.
#[test]
fn a_running_invocation_carries_no_sentinel_in_cmdline_or_environ() {
    let vault = SentinelVault::create();
    let home = vault.home.clone();

    // `list --passphrase-fd 0` blocks reading stdin until we close it,
    // which is the window /proc is read in.
    let held = HeldChild::spawn(&["list", "--passphrase-fd", "0"], |cmd| {
        cmd.env("HOME", &home).current_dir(&home);
    });
    let cmdline = held.read_proc("cmdline");
    let environ = held.read_proc("environ");
    assert!(!cmdline.is_empty(), "the /proc read found nothing to scan");
    // `read_proc` already refused to answer until the child had exec'd,
    // so this is antseal's own argv and environment, not this binary's.
    assert!(
        String::from_utf8_lossy(&cmdline).contains("--passphrase-fd"),
        "the scanned cmdline is not the invocation under test"
    );

    scan_bytes(&cmdline, "the running process's /proc/<pid>/cmdline")
        .unwrap_or_else(|e| panic!("{e}"));
    scan_bytes(&environ, "the running process's /proc/<pid>/environ")
        .unwrap_or_else(|e| panic!("{e}"));

    // Now feed the passphrase and let it finish, so the fd channel is
    // exercised end to end rather than merely opened.
    if let Some(stdin) = held.child.stdin.as_ref() {
        let mut stdin = stdin;
        let _ = stdin.write_all(SENTINEL_PASSPHRASE.as_bytes());
    }
    held.finish();
}

/// A panic can only print what `Debug` prints. Every type that holds
/// secret material must redact — so the panic-message channel is closed
/// at its source rather than by filtering output.
#[test]
fn panic_messages_cannot_carry_secret_material() {
    let handle = WalletKeyHandle::from_bytes(SENTINEL_WALLET_KEY);
    let secret = SecretBuf::new(SENTINEL_PASSPHRASE.as_bytes().to_vec());
    let w = MasterSecret::from_bytes(SENTINEL_W);

    for (what, rendered) in [
        ("WalletKeyHandle", format!("{handle:?}")),
        ("SecretBuf", format!("{secret:?}")),
        ("MasterSecret", format!("{w:?}")),
    ] {
        scan(&rendered, &format!("the Debug of {what}")).unwrap_or_else(|e| panic!("{e}"));
    }

    // And the real thing: a panic carrying one of those values renders
    // through the same `Debug`, so catch one and scan its payload.
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let payload = std::panic::catch_unwind(|| {
        let handle = WalletKeyHandle::from_bytes(SENTINEL_WALLET_KEY);
        panic!("a bug that names the wallet key: {handle:?}");
    })
    .expect_err("the closure panics");
    std::panic::set_hook(previous);

    let text = payload
        .downcast_ref::<String>()
        .cloned()
        .unwrap_or_else(|| "<non-string panic payload>".to_owned());
    assert!(text.contains("a bug that names"), "the panic was captured");
    scan(&text, "a panic message naming a secret-bearing value").unwrap_or_else(|e| panic!("{e}"));
}

/// Every `CliError` variant's rendered message and JSON object, scanned.
/// U2 promised no variant carries secret material; this is where that
/// promise is measured rather than reviewed.
#[test]
fn no_cli_error_renders_a_sentinel() {
    use antseal_cli::error::{CliError, PassphraseFailure};

    // The variants that could plausibly interpolate input: the ones that
    // carry strings the user or the vault supplied.
    let errors = vec![
        CliError::PassphraseUnavailable {
            reason: PassphraseFailure::FdForbiddenByte,
        },
        CliError::VaultAuthFailure,
        CliError::ImportAuthFailed,
        CliError::InvalidSealArgument {
            problems: vec!["notes.txt is a directory".to_owned()],
        },
        CliError::Usage {
            message: "the vault's wallet key is not a valid payment key".to_owned(),
        },
    ];
    for err in errors {
        scan(&err.to_string(), "a CliError Display").unwrap_or_else(|e| panic!("{e}"));
        scan(&err.error_object().to_string(), "a CliError JSON object")
            .unwrap_or_else(|e| panic!("{e}"));
    }
}

/// A guard on the harness itself: the sentinel vault really does contain
/// the sentinels, so a clean scan means "nothing leaked" rather than
/// "nothing was there".
#[test]
fn the_sentinel_vault_actually_holds_the_sentinels() {
    let vault = SentinelVault::create();
    let layout = VaultLayout::at(vault.home.join(".antseal"));
    let unlocked = antseal_cli::vault::session::unlock_vault(
        &layout,
        &SecretBuf::new(SENTINEL_PASSPHRASE.as_bytes().to_vec()),
    )
    .expect("the sentinel passphrase opens the sentinel vault");

    let handle = antseal_cli::vault::wallet::load_wallet_key(&unlocked)
        .expect("wallet record reads")
        .expect("wallet record exists");
    assert_eq!(handle.secret_bytes(), &SENTINEL_WALLET_KEY);

    let store = WorkStore::new(&unlocked);
    let works = store.list_works().expect("list");
    assert_eq!(works.len(), 1);
    let record = store.load_meta(&works[0]).expect("meta");
    assert_eq!(record.w.secret_ref().as_bytes(), &SENTINEL_W);

    // And the on-disk bytes are NOT the plaintext — the vault files are
    // where the sentinels are allowed to be, in encrypted form only.
    let meta_bytes = std::fs::read(
        layout
            .works_dir()
            .join(
                works[0]
                    .as_bytes()
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>(),
            )
            .join("meta"),
    )
    .expect("read the meta record");
    scan_bytes(&meta_bytes, "the encrypted meta record on disk").unwrap_or_else(|e| panic!("{e}"));
}

/// The harness's own file must not become the leak: `Path` is imported
/// for this one check, which keeps the fixture-material rule honest.
#[test]
fn this_harness_declares_its_fixtures_as_non_secret() {
    let source = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/secret_hygiene.rs"),
    )
    .expect("read this file");
    assert!(
        source.contains("NON-SECRET"),
        "project rule 6: fixture secret material must be labelled"
    );
}
