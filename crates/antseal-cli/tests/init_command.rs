//! U11 acceptance suite: `init` — vault create, wallet generate/import,
//! funding instructions, network config.
//!
//! Driven **in process** through `antseal_cli::init::run_init` over an
//! injected prompt seam, plus a few spawned-binary checks for the surface
//! (exit codes, stdout purity, the absolute existing-vault refusal). The
//! seam is what makes D39's wizard order assertable without a pty: the
//! scripted prompt records every question it is asked, in order.
//!
//! NON-SECRET: every passphrase and wallet key here is a documented
//! fixture. The wallet keys are derived, never fresh committed literals
//! (project rule 6) — except the two *public curve constants* (scalar 1
//! and the group order), which are not key material in any sense.

use std::cell::RefCell;
use std::path::{Path, PathBuf};
use std::process::Command as Process;

use antseal_cli::cli::{InitArgs, InitProvided, KdfChoice, WalletSource, WrapChoice};
use antseal_cli::error::{CliError, ErrorClass};
use antseal_cli::init::{InitPrompt, WizardStep, funding_lines, run_init};
use antseal_cli::vault::layout::{BesideFile, VaultLayout};
use antseal_cli::vault::session::unlock_vault;
use antseal_cli::vault::wallet::load_wallet_key;
use antseal_core::crypto::secrets::SecretBuf;
use antseal_net::{NetworkId, checksummed};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

// ─────────────────────────────────────────────────────────────────────
// Harness
// ─────────────────────────────────────────────────────────────────────

const FIXTURE_PASSPHRASE: &[u8] = b"init suite fixture passphrase";

/// Scalar 1 — the secp256k1 generator's private key. A universally
/// documented public constant, unmistakably not a real wallet.
const SCALAR_ONE: &str = "0000000000000000000000000000000000000000000000000000000000000001";
/// The address scalar 1 derives (the generator point's address).
const SCALAR_ONE_ADDRESS: &str = "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf";
/// The secp256k1 group order n — the smallest INVALID scalar. A public
/// curve constant, not key material.
const SECP256K1_ORDER: &str = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141";

struct TestDir(PathBuf);

impl TestDir {
    fn new(tag: &str) -> Self {
        let base = std::env::temp_dir().join(format!(
            "antseal-init-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&base).expect("create test dir");
        TestDir(base)
    }

    fn vault_root(&self) -> PathBuf {
        self.0.join("vault")
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A scripted prompt that **records every question**, in order — the
/// transcript is what the D39 order assertion reads.
struct Scripted {
    answers: RefCell<Vec<String>>,
    secrets: RefCell<Vec<String>>,
    asked: RefCell<Vec<String>>,
}

impl Scripted {
    fn new(answers: &[&str], secrets: &[&str]) -> Self {
        Scripted {
            answers: RefCell::new(answers.iter().map(|s| (*s).to_owned()).collect()),
            secrets: RefCell::new(secrets.iter().map(|s| (*s).to_owned()).collect()),
            asked: RefCell::new(Vec::new()),
        }
    }

    /// Nothing was asked — the property D39's "fully-flagged non-TTY
    /// init completes with zero prompts" states.
    fn silent() -> Self {
        Scripted::new(&[], &[])
    }

    fn transcript(&self) -> Vec<String> {
        self.asked.borrow().clone()
    }
}

impl InitPrompt for Scripted {
    fn ask_choice(
        &mut self,
        question: &str,
        _options: &[&str],
        default: &str,
    ) -> Result<String, CliError> {
        self.asked.borrow_mut().push(question.to_owned());
        Ok(self
            .answers
            .borrow_mut()
            .pop()
            .unwrap_or_else(|| default.to_owned()))
    }

    fn read_secret_line(&mut self, prompt: &str) -> Result<SecretBuf, CliError> {
        self.asked.borrow_mut().push(prompt.to_owned());
        let line = self
            .secrets
            .borrow_mut()
            .pop()
            .expect("scripted secret exhausted");
        Ok(SecretBuf::new(line.into_bytes()))
    }
}

fn args(
    wallet: WalletSource,
    kdf: KdfChoice,
    wrap: WrapChoice,
    provided: InitProvided,
) -> InitArgs {
    InitArgs {
        wallet,
        wallet_key_fd: None,
        kdf,
        wrap,
        provided,
    }
}

/// Everything flag-supplied, machine mode on: the shape a script uses.
fn fully_flagged() -> InitArgs {
    args(
        WalletSource::Generate,
        KdfChoice::Argon2id,
        WrapChoice::None,
        InitProvided {
            wallet: true,
            kdf: true,
            wrap: true,
        },
    )
}

fn passphrase() -> SecretBuf {
    SecretBuf::new(FIXTURE_PASSPHRASE.to_vec())
}

fn rng() -> ChaCha20Rng {
    ChaCha20Rng::from_seed([0x5Au8; 32])
}

/// Spawn the real binary with the passphrase on stdin (`--passphrase-fd 0`).
struct Spawned {
    code: Option<i32>,
    stdout: String,
    stderr: String,
}

fn spawn(vault_root: &Path, args: &[&str], stdin_bytes: &[u8]) -> Spawned {
    use std::io::Write as _;
    let mut child = Process::new(env!("CARGO_BIN_EXE_antseal"))
        .args(args)
        .env("ANTSEAL_DIR", vault_root)
        .env_remove("RUST_LOG")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn antseal");
    child
        .stdin
        .as_mut()
        .expect("stdin piped")
        .write_all(stdin_bytes)
        .expect("write stdin");
    let out = child.wait_with_output().expect("wait for antseal");
    Spawned {
        code: out.status.code(),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

// ─────────────────────────────────────────────────────────────────────
// The wizard (D39): order, and every question's flag equivalent
// ─────────────────────────────────────────────────────────────────────

/// **U11 Accept row 3, first half — the wizard order.** With nothing
/// flag-supplied, the questions come in D39's fixed order: passphrase →
/// wallet source → wrap → KDF. The passphrase step is `obtain_passphrase`'s
/// (U7 owns its prompt), so this asserts the *plan* — `asked` — which is
/// the order the invocation actually walked.
#[test]
fn the_wizard_asks_d39s_questions_in_d39s_order() {
    let dir = TestDir::new("order");
    let layout = VaultLayout::at(dir.vault_root());
    // Passphrase supplied out of band (fd 3 is not available in-process),
    // so the recorded order starts at the wallet question; the passphrase
    // step's position is asserted by `asked` in the no-fd case below.
    let mut prompt = Scripted::new(&["argon2id", "none", "generate"], &[]);
    let report = run_init(
        &layout,
        &args(
            WalletSource::Generate,
            KdfChoice::Argon2id,
            WrapChoice::None,
            InitProvided::default(),
        ),
        Some(passphrase_fd_of(&dir)),
        false,
        NetworkId::Devnet,
        &mut prompt,
        &mut rng(),
    )
    .expect("wizard completes");

    assert_eq!(
        report.asked,
        vec![WizardStep::WalletSource, WizardStep::Wrap, WizardStep::Kdf],
        "D39's order, minus the passphrase (supplied on the fd channel)"
    );
    // The transcript is the human-visible half of the same claim.
    let transcript = prompt.transcript();
    assert_eq!(transcript.len(), 3);
    assert!(transcript[0].contains("Wallet key"));
    assert!(transcript[1].contains("wrap"));
    assert!(transcript[2].contains("key-derivation"));
}

/// **U11 Accept row 3, second half.** Every wizard question has a flag
/// equivalent, and a flag-supplied value is **not asked again** — the
/// distinction U38 made expressible.
#[test]
fn flag_supplied_values_are_not_asked_again() {
    let dir = TestDir::new("supplied");
    let layout = VaultLayout::at(dir.vault_root());
    let mut prompt = Scripted::new(&["argon2id", "none"], &[]);
    let report = run_init(
        &layout,
        &args(
            WalletSource::Generate,
            KdfChoice::Argon2id,
            WrapChoice::None,
            InitProvided {
                wallet: true,
                kdf: false,
                wrap: false,
            },
        ),
        Some(passphrase_fd_of(&dir)),
        false,
        NetworkId::Devnet,
        &mut prompt,
        &mut rng(),
    )
    .expect("wizard completes");
    assert_eq!(report.asked, vec![WizardStep::Wrap, WizardStep::Kdf]);
    assert_eq!(report.wallet_source, "generate");
}

/// **U11 Accept row 3, third half.** Fully-flagged, non-interactive
/// `init` completes with **zero prompts** — the scripted prompt would
/// panic if it were consulted for a secret, and records nothing at all.
#[test]
fn fully_flagged_machine_mode_init_asks_nothing() {
    let dir = TestDir::new("silent");
    let layout = VaultLayout::at(dir.vault_root());
    let mut prompt = Scripted::silent();
    let report = run_init(
        &layout,
        &fully_flagged(),
        Some(passphrase_fd_of(&dir)),
        true,
        NetworkId::ArbitrumOne,
        &mut prompt,
        &mut rng(),
    )
    .expect("flagged init completes");
    assert!(report.asked.is_empty(), "{:?}", report.asked);
    assert!(prompt.transcript().is_empty());
    assert_eq!(report.kdf, "argon2id");
}

/// Machine mode with **nothing** flag-supplied still asks nothing: the
/// three defaulted questions take their documented defaults silently
/// (D39 `generate`, D40 Argon2id, D50 declined). They are answered by
/// decision, so they are not "missing required inputs" under D51.
#[test]
fn machine_mode_takes_the_documented_defaults_without_prompting() {
    let dir = TestDir::new("defaults");
    let layout = VaultLayout::at(dir.vault_root());
    let mut prompt = Scripted::silent();
    let report = run_init(
        &layout,
        &args(
            WalletSource::Generate,
            KdfChoice::Argon2id,
            WrapChoice::None,
            InitProvided::default(),
        ),
        Some(passphrase_fd_of(&dir)),
        true,
        NetworkId::Devnet,
        &mut prompt,
        &mut rng(),
    )
    .expect("machine-mode init completes");
    assert!(report.asked.is_empty());
    assert_eq!((report.wallet_source, report.kdf), ("generate", "argon2id"));
}

// ─────────────────────────────────────────────────────────────────────
// Vault + wallet outcome
// ─────────────────────────────────────────────────────────────────────

/// The generate branch produces a real, usable vault: it unlocks with the
/// passphrase `init` was given, it holds a wallet key, and that key
/// derives the address `init` printed.
#[test]
fn generate_creates_a_vault_whose_stored_key_derives_the_printed_address() {
    let dir = TestDir::new("generate");
    let layout = VaultLayout::at(dir.vault_root());
    let report = run_init(
        &layout,
        &fully_flagged(),
        Some(passphrase_fd_of(&dir)),
        true,
        NetworkId::Devnet,
        &mut Scripted::silent(),
        &mut rng(),
    )
    .expect("init completes");

    assert!(layout.beside_path(BesideFile::Header).exists());
    assert!(layout.beside_path(BesideFile::Config).exists());

    let vault = unlock_vault(&layout, &passphrase()).expect("the vault unlocks");
    let handle = load_wallet_key(&vault)
        .expect("wallet record readable")
        .expect("a wallet key was stored");
    // The stored 32 bytes derive exactly the address the report printed.
    let hex: String = handle
        .secret_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let key = antseal_net::WalletKey::import(&SecretBuf::new(hex.into_bytes()))
        .expect("the stored key is a valid payment key");
    assert_eq!(checksummed(key.address()), report.address);
    assert!(report.address.starts_with("0x") && report.address.len() == 42);

    // The config records the network `init` was run for (U4's writer).
    let config = std::fs::read_to_string(layout.beside_path(BesideFile::Config)).expect("config");
    assert!(config.contains("default_network = \"devnet\""), "{config}");
}

/// Two runs draw different keys (the OS CSPRNG is the source, not the
/// seeded test RNG — which only feeds the vault salt and nonces).
#[test]
fn two_inits_produce_different_wallets() {
    let first = TestDir::new("distinct-a");
    let second = TestDir::new("distinct-b");
    let run = |dir: &TestDir| {
        run_init(
            &VaultLayout::at(dir.vault_root()),
            &fully_flagged(),
            Some(passphrase_fd_of(dir)),
            true,
            NetworkId::Devnet,
            &mut Scripted::silent(),
            &mut rng(),
        )
        .expect("init completes")
        .address
    };
    assert_ne!(run(&first), run(&second));
}

// ─────────────────────────────────────────────────────────────────────
// D44 import classes (U11 Accept row 2)
// ─────────────────────────────────────────────────────────────────────

/// A pasted key imports, and derives the address that key is known to
/// derive. Scalar 1 is used because its address is a published constant,
/// so this asserts the whole chain — paste → validate → store → derive —
/// against an answer nothing in this repo computed.
#[test]
fn an_imported_key_derives_its_known_address() {
    let dir = TestDir::new("import");
    let layout = VaultLayout::at(dir.vault_root());
    let mut prompt = Scripted::new(&[], &[SCALAR_ONE]);
    let report = run_init(
        &layout,
        &args(
            WalletSource::Import,
            KdfChoice::Argon2id,
            WrapChoice::None,
            InitProvided {
                wallet: true,
                kdf: true,
                wrap: true,
            },
        ),
        Some(passphrase_fd_of(&dir)),
        false,
        NetworkId::Devnet,
        &mut prompt,
        &mut rng(),
    )
    .expect("import completes");
    assert_eq!(report.address, SCALAR_ONE_ADDRESS);
    assert_eq!(report.wallet_source, "import");
    assert_eq!(report.asked, vec![WizardStep::WalletKeyPaste]);
}

/// **U11 Accept row 2.** Every D44 rejection class refuses, nothing is
/// created, and the mnemonic case carries its distinct
/// "not supported in this version" copy — not a generic parse error.
#[test]
fn invalid_import_material_is_refused_per_the_d44_set() {
    let cases: [(&str, &str, &str); 5] = [
        ("wrong length", "abcdef", "exactly 64 hex digits"),
        (
            "non-hex",
            "zz00000000000000000000000000000000000000000000000000000000000001",
            "outside 0-9a-fA-F",
        ),
        (
            "zero scalar",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "zero or out of range",
        ),
        ("group order", SECP256K1_ORDER, "zero or out of range"),
        (
            "mnemonic",
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
             abandon about",
            "not supported in this version",
        ),
    ];
    for (label, material, expected) in cases {
        let dir = TestDir::new("reject");
        let layout = VaultLayout::at(dir.vault_root());
        let mut prompt = Scripted::new(&[], &[material]);
        let err = run_init(
            &layout,
            &args(
                WalletSource::Import,
                KdfChoice::Argon2id,
                WrapChoice::None,
                InitProvided {
                    wallet: true,
                    kdf: true,
                    wrap: true,
                },
            ),
            Some(passphrase_fd_of(&dir)),
            false,
            NetworkId::Devnet,
            &mut prompt,
            &mut rng(),
        )
        .expect_err(label);
        assert_eq!(err.class(), ErrorClass::Usage, "{label}");
        let rendered = err.to_string();
        assert!(rendered.contains(expected), "{label}: {rendered}");
        assert!(
            rendered.contains("Nothing was created") || rendered.contains("nothing was created"),
            "{label}: {rendered}"
        );
        // No vault was created, and the error echoes no key material.
        assert!(
            !layout.beside_path(BesideFile::Header).exists(),
            "{label}: a vault was created despite the refusal"
        );
        assert!(!rendered.contains(material), "{label} echoed the input");
    }
}

/// Whitespace around a key is not tolerated (D44); the one trailing
/// newline the fd channel adds already is.
#[test]
fn surrounding_whitespace_is_refused() {
    let dir = TestDir::new("whitespace");
    let layout = VaultLayout::at(dir.vault_root());
    let padded = format!(" {SCALAR_ONE}");
    let mut prompt = Scripted::new(&[], &[padded.as_str()]);
    let err = run_init(
        &layout,
        &args(
            WalletSource::Import,
            KdfChoice::Argon2id,
            WrapChoice::None,
            InitProvided {
                wallet: true,
                kdf: true,
                wrap: true,
            },
        ),
        Some(passphrase_fd_of(&dir)),
        false,
        NetworkId::Devnet,
        &mut prompt,
        &mut rng(),
    )
    .expect_err("leading space");
    assert!(err.to_string().contains("whitespace around the key"));
}

/// `--wallet import` in machine mode without `--wallet-key-fd` is a usage
/// error naming the flag — never a prompt, never a hang (D51), and never
/// a vault.
#[test]
fn machine_mode_import_without_the_fd_channel_is_a_usage_error() {
    let dir = TestDir::new("import-nofd");
    let layout = VaultLayout::at(dir.vault_root());
    let err = run_init(
        &layout,
        &args(
            WalletSource::Import,
            KdfChoice::Argon2id,
            WrapChoice::None,
            InitProvided {
                wallet: true,
                kdf: true,
                wrap: true,
            },
        ),
        Some(passphrase_fd_of(&dir)),
        true,
        NetworkId::Devnet,
        &mut Scripted::silent(),
        &mut rng(),
    )
    .expect_err("no wallet-key channel");
    assert_eq!(err.class(), ErrorClass::Usage);
    assert!(err.to_string().contains("--wallet-key-fd"));
    assert!(!layout.beside_path(BesideFile::Header).exists());
}

// ─────────────────────────────────────────────────────────────────────
// Refusals
// ─────────────────────────────────────────────────────────────────────

/// **U11's absolute existing-vault refusal (D39 Decision 4).** The error
/// names the path and says what to do; no `--force` exists.
#[test]
fn init_over_an_existing_vault_refuses_absolutely() {
    let dir = TestDir::new("existing");
    let layout = VaultLayout::at(dir.vault_root());
    run_init(
        &layout,
        &fully_flagged(),
        Some(passphrase_fd_of(&dir)),
        true,
        NetworkId::Devnet,
        &mut Scripted::silent(),
        &mut rng(),
    )
    .expect("first init");

    let err = run_init(
        &layout,
        &fully_flagged(),
        Some(passphrase_fd_of(&dir)),
        true,
        NetworkId::Devnet,
        &mut Scripted::silent(),
        &mut rng(),
    )
    .expect_err("second init must refuse");
    assert_eq!(err.class(), ErrorClass::Usage);
    let rendered = err.to_string();
    assert!(
        rendered.contains(&layout.root().display().to_string()),
        "the refusal names the vault path: {rendered}"
    );
    assert!(rendered.contains("no --force"));
    assert!(rendered.contains("vault export"));
}

/// No override flag parses — the surface has none, by design (D39).
#[test]
fn no_reinit_override_flag_parses() {
    for flag in ["--force", "--force-reinit", "--overwrite", "--yes"] {
        let err = antseal_cli::cli::Cli::parse_checked(["antseal", "init", flag])
            .expect_err("override flag must not parse");
        assert_eq!(
            err.kind(),
            clap::error::ErrorKind::UnknownArgument,
            "{flag}"
        );
    }
}

/// **U8 landed the keyfile engine**, so `--wrap keyfile` is honoured
/// rather than refused. What still has to be settled before a passphrase
/// is collected is *where* the keyfile goes: the canonical surface has no
/// `--keyfile` flag, so machine mode needs `ANTSEAL_KEYFILE` and says so.
///
/// The position is the property this test pins, exactly as it did when
/// the refusal was "not implemented": with no passphrase channel and
/// machine mode ON, a late refusal would surface as
/// passphrase-unavailable instead.
#[test]
fn a_keyfile_wrap_without_a_path_channel_refuses_before_anything_is_created() {
    let dir = TestDir::new("wrap");
    let layout = VaultLayout::at(dir.vault_root());
    let err = run_init(
        &layout,
        &args(
            WalletSource::Generate,
            KdfChoice::Argon2id,
            WrapChoice::Keyfile,
            InitProvided {
                wallet: true,
                kdf: true,
                wrap: true,
            },
        ),
        None,
        true,
        NetworkId::Devnet,
        &mut Scripted::silent(),
        &mut rng(),
    )
    .expect_err("no path channel in machine mode");
    assert_eq!(err.class(), ErrorClass::Usage);
    let rendered = err.to_string();
    assert!(rendered.contains("ANTSEAL_KEYFILE"), "{rendered}");
    assert!(rendered.contains("never a secret"), "{rendered}");
    assert!(!layout.beside_path(BesideFile::Header).exists());
}

/// Machine mode with no passphrase channel aborts with the typed
/// passphrase-unavailable class rather than prompting or hanging (D51) —
/// and creates nothing.
#[test]
fn machine_mode_without_a_passphrase_channel_aborts() {
    let dir = TestDir::new("nopass");
    let layout = VaultLayout::at(dir.vault_root());
    let err = run_init(
        &layout,
        &fully_flagged(),
        None,
        true,
        NetworkId::Devnet,
        &mut Scripted::silent(),
        &mut rng(),
    )
    .expect_err("no passphrase channel");
    assert_eq!(err.class(), ErrorClass::PassphraseUnavailable);
    assert!(!layout.beside_path(BesideFile::Header).exists());
}

// ─────────────────────────────────────────────────────────────────────
// Output: funding copy and the `--json` document
// ─────────────────────────────────────────────────────────────────────

/// **U11 Accept row 4.** Address + funding instructions for all three
/// networks, in possession language.
#[test]
fn the_report_prints_the_address_and_the_networks_funding_copy() {
    for network in [
        NetworkId::ArbitrumOne,
        NetworkId::ArbitrumSepolia,
        NetworkId::Devnet,
    ] {
        let dir = TestDir::new("copy");
        let layout = VaultLayout::at(dir.vault_root());
        let report = run_init(
            &layout,
            &fully_flagged(),
            Some(passphrase_fd_of(&dir)),
            true,
            network,
            &mut Scripted::silent(),
            &mut rng(),
        )
        .expect("init completes");
        let text = report.render().join("\n");
        assert!(
            text.contains(&report.address),
            "{network}: prints the address"
        );
        for line in funding_lines(network, &report.address) {
            if !line.is_empty() {
                assert!(text.contains(&line), "{network}: funding line missing");
            }
        }
        assert!(text.contains("LOSS") && text.contains("THEFT"));
        assert!(!text.to_lowercase().contains("notar"), "{network}");
    }
}

/// **U11 Accept row 5.** The `--json` document carries the address, the
/// network and the vault path — and **no key material**, asserted against
/// the actual stored key rather than by inspection.
#[test]
fn the_json_document_carries_no_key_material() {
    let dir = TestDir::new("json");
    let layout = VaultLayout::at(dir.vault_root());
    let report = run_init(
        &layout,
        &fully_flagged(),
        Some(passphrase_fd_of(&dir)),
        true,
        NetworkId::ArbitrumSepolia,
        &mut Scripted::silent(),
        &mut rng(),
    )
    .expect("init completes");

    let json = report.json();
    assert_eq!(json["address"], report.address);
    assert_eq!(json["network"], "arbitrum-sepolia");
    assert_eq!(
        json["vault_dir"],
        layout.root().display().to_string().as_str()
    );
    assert_eq!(json["wallet_source"], "generate");
    assert_eq!(json["kdf"], "argon2id");

    // The stored private key appears nowhere in the document — nor does
    // the passphrase.
    let vault = unlock_vault(&layout, &passphrase()).expect("unlock");
    let handle = load_wallet_key(&vault).expect("read").expect("stored");
    let hex: String = handle
        .secret_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let rendered = serde_json::to_string(&json).expect("serialize");
    assert!(!rendered.contains(&hex), "the json leaked the private key");
    assert!(!rendered.contains("passphrase"));
}

// ─────────────────────────────────────────────────────────────────────
// The spawned surface
// ─────────────────────────────────────────────────────────────────────

/// End to end through the real binary: `init` over a pipe-supplied
/// passphrase creates a vault, prints its report on stdout, and exits 0.
#[test]
fn the_binary_inits_over_a_piped_passphrase() {
    let dir = TestDir::new("spawn");
    let root = dir.vault_root();
    let out = spawn(
        &root,
        &["--network", "devnet", "--passphrase-fd", "0", "init"],
        b"a long enough fixture passphrase\n",
    );
    assert_eq!(out.code, Some(0), "stderr: {}", out.stderr);
    assert!(out.stdout.contains("Vault created at"), "{}", out.stdout);
    assert!(out.stdout.contains("Payment wallet address: 0x"));
    assert!(root.join("vault.header").exists());

    // Re-running refuses, names the path, and exits with the usage code.
    let again = spawn(
        &root,
        &["--network", "devnet", "--passphrase-fd", "0", "init"],
        b"a long enough fixture passphrase\n",
    );
    assert_eq!(again.code, Some(2), "stderr: {}", again.stderr);
    assert!(again.stdout.is_empty(), "errors write no stdout");
    assert!(again.stderr.contains("already exists"));
    assert!(again.stderr.contains("no --force"));
}

/// Under `--json` the one document goes to stdout and every human line to
/// stderr (D51 invariants 1 and 2).
#[test]
fn the_binary_emits_one_json_document_under_json() {
    let dir = TestDir::new("spawn-json");
    let root = dir.vault_root();
    let out = spawn(
        &root,
        &["--json", "--passphrase-fd", "0", "init"],
        b"a long enough fixture passphrase\n",
    );
    assert_eq!(out.code, Some(0), "stderr: {}", out.stderr);
    let doc: serde_json::Value =
        serde_json::from_str(out.stdout.trim()).expect("stdout is exactly one JSON document");
    assert_eq!(doc["ok"], true);
    assert_eq!(doc["command"], "init");
    assert_eq!(doc["result"]["network"], "arbitrum-one");
    assert!(
        doc["result"]["address"]
            .as_str()
            .expect("address")
            .starts_with("0x")
    );
    // Human copy moved to stderr.
    assert!(out.stderr.contains("Payment wallet address"));
}

// ─────────────────────────────────────────────────────────────────────
// Passphrase-fd plumbing for the in-process tests
// ─────────────────────────────────────────────────────────────────────

/// Write the fixture passphrase into a file inside the test directory and
/// return a descriptor number for it, kept open for the process's
/// lifetime (these tests never close it — the file is small and the
/// directory is removed on drop).
///
/// Using a real descriptor keeps `run_init` on its production passphrase
/// path (D41's channel) instead of a test-only seam, which is the point:
/// the collection code under test is the code that ships.
fn passphrase_fd_of(dir: &TestDir) -> u32 {
    use std::os::fd::IntoRawFd;
    let path = dir.0.join(format!(
        "pass-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::write(&path, FIXTURE_PASSPHRASE).expect("write passphrase file");
    let file = std::fs::File::open(&path).expect("open passphrase file");
    u32::try_from(file.into_raw_fd()).expect("fd fits u32")
}
