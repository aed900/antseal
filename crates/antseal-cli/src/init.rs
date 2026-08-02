//! `init` (U11): vault create, wallet generate/import, funding
//! instructions, network config — per **D39**'s hybrid interaction model.
//!
//! # The order, and what it costs to get wrong
//!
//! ```text
//! resolve layout
//!   → existing-vault refusal        (absolute; before any prompt)
//!   → unimplementable flag answers  (refused before a secret is asked for)
//!   → wizard: passphrase → wallet source → wrap → KDF   (D39 Decision 1)
//!   → create vault → store wallet key → write config
//!   → print address + funding instructions
//! ```
//!
//! Two of those positions are load-bearing:
//!
//! - **The existing-vault refusal is first.** Overwriting a vault destroys
//!   `W` — every sealed work's reveal/restore ability, forever
//!   (MVP-SPEC.md line 143). D39 Decision 4 makes the refusal absolute:
//!   **there is no `--force`**, and none parses. Moving the directory by
//!   hand is the consent.
//! - **A question we cannot honour is refused before the passphrase.**
//!   Asking for a secret and then refusing is rude as well as pointless —
//!   the same rule U36 applied at the backend seam.
//!
//! # "Was it supplied?" (U38)
//!
//! `--wallet`, `--kdf` and `--wrap` all carry clap defaults, so the parsed
//! value alone cannot answer D39's "a value already supplied by flag/fd is
//! not asked again". [`InitProvided`] carries the answer out of the parse;
//! this module is its only consumer.
//!
//! # Machine mode never prompts (D51)
//!
//! Machine mode arrives from [`crate::machine::machine_mode_for`] — the
//! single detection point — never from a local isatty probe. In it:
//! the passphrase must come from `--passphrase-fd` (else the typed
//! passphrase-unavailable abort); an `import` must come with
//! `--wallet-key-fd` (else a usage error naming the flag); and the three
//! defaulted questions take their **documented defaults silently** rather
//! than aborting — they are not "missing required inputs", they are
//! answered by decision (D39 `generate`, D40 Argon2id, D50 declined).
//!
//! # Secret hygiene (project rule 6)
//!
//! The passphrase and any pasted wallet key exist only inside
//! [`SecretBuf`]/`WalletKey`, never in argv, never in the environment
//! (D41), never in a log line, and never in this command's `--json`
//! document — which carries the address, the network and the vault path,
//! and nothing else.

use std::io::{BufRead, Write};
use std::path::PathBuf;

use antseal_core::crypto::secrets::SecretBuf;
use antseal_net::{NetworkId, WalletImportError, WalletKey, checksummed};
use rand_core::TryCryptoRng;

use crate::cli::{GlobalArgs, InitArgs, KdfChoice, WalletSource, WrapChoice};
use crate::error::{CliError, Milestone, PassphraseFailure};
use crate::passphrase::{PassphrasePurpose, obtain_passphrase, read_secret_fd};
use crate::vault::kdf::KdfSelection;
use crate::vault::layout::{BesideFile, VaultLayout};
use crate::vault::session::create_vault;
use crate::vault::wallet::{WalletKeyHandle, store_wallet_key};

/// One wizard question, in D39's order. The enum exists so the order is a
/// value a test can assert rather than a property of control flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WizardStep {
    /// Passphrase entry + confirmation (no-echo). Always first.
    Passphrase,
    /// `--wallet generate|import`.
    WalletSource,
    /// The no-echo key paste that follows an interactive `import`.
    WalletKeyPaste,
    /// The U8 wrap offer (`--wrap`).
    Wrap,
    /// The D40 KDF question (`--kdf`).
    Kdf,
}

impl WizardStep {
    /// The stable label the order snapshot records.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Passphrase => "passphrase",
            Self::WalletSource => "wallet-source",
            Self::WalletKeyPaste => "wallet-key-paste",
            Self::Wrap => "wrap",
            Self::Kdf => "kdf",
        }
    }
}

/// The prompt seam (`passphrase.rs` reserves it: "U11's wizard will define
/// its own interaction seam over this module's public functions").
///
/// Production reads a TTY; tests script it and record the transcript,
/// which is what makes the D39 order assertable without a pty.
pub trait InitPrompt {
    /// Ask a closed-set question. `options` are the accepted spellings;
    /// an empty answer takes `default`.
    fn ask_choice(
        &mut self,
        question: &str,
        options: &[&str],
        default: &str,
    ) -> Result<String, CliError>;

    /// Read one no-echo secret line (the `import` paste).
    fn read_secret_line(&mut self, prompt: &str) -> Result<SecretBuf, CliError>;
}

/// The production prompt: questions on **stderr** (D51's stream
/// contract — stdout is reserved for the one `--json` document), answers
/// on stdin, secrets through the same no-echo `/dev/tty` path U7 uses.
pub struct TtyInitPrompt;

/// How many times a mistyped answer may be re-asked before `init` gives
/// up. Bounded so a non-interactive stdin that slipped past the machine-
/// mode gate cannot spin.
const MAX_ANSWER_ATTEMPTS: usize = 3;

impl InitPrompt for TtyInitPrompt {
    fn ask_choice(
        &mut self,
        question: &str,
        options: &[&str],
        default: &str,
    ) -> Result<String, CliError> {
        let rendered = options.join(" / ");
        for _ in 0..MAX_ANSWER_ATTEMPTS {
            eprint!("{question} [{rendered}] (default: {default}): ");
            let _ = std::io::stderr().flush();
            let mut line = String::new();
            if std::io::stdin().lock().read_line(&mut line).is_err() {
                return Err(CliError::Usage {
                    message: format!("could not read an answer for: {question}"),
                });
            }
            let answer = line.trim();
            if answer.is_empty() {
                return Ok(default.to_owned());
            }
            if let Some(found) = options.iter().find(|o| o.eq_ignore_ascii_case(answer)) {
                return Ok((*found).to_owned());
            }
            eprintln!("  not one of: {rendered}");
        }
        Err(CliError::Usage {
            message: format!("no valid answer for: {question}"),
        })
    }

    fn read_secret_line(&mut self, prompt: &str) -> Result<SecretBuf, CliError> {
        let line =
            rpassword::prompt_password(prompt).map_err(|_| CliError::PassphraseUnavailable {
                reason: PassphraseFailure::PromptFailed,
            })?;
        Ok(SecretBuf::new(line.into_bytes()))
    }
}

/// What a completed `init` produced — the `--json` document's source and
/// the human report's. **Carries no key material**, by shape: the private
/// key never leaves the vault record it was written into.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InitReport {
    /// The wallet's EVM address, EIP-55 checksummed (the form explorers
    /// and wallets show, and the form that catches a mistyped address).
    pub address: String,
    /// Which network `init` configured.
    pub network: NetworkId,
    /// The vault directory that now exists.
    pub vault_dir: PathBuf,
    /// `generate` or `import` — how the key came to be.
    pub wallet_source: &'static str,
    /// The KDF the vault header records.
    pub kdf: &'static str,
    /// The wizard questions this invocation actually asked, in order
    /// (empty when everything was flag-supplied — D39's "fully-flagged
    /// non-TTY init completes with zero prompts").
    pub asked: Vec<WizardStep>,
}

impl InitReport {
    /// The `--json` document: address, network, vault path. Deliberately
    /// nothing else — no key material, no passphrase-derived value, no
    /// KDF salt.
    #[must_use]
    pub fn json(&self) -> serde_json::Value {
        serde_json::json!({
            "address": self.address,
            "network": self.network.as_str(),
            "vault_dir": self.vault_dir.display().to_string(),
            "wallet_source": self.wallet_source,
            "kdf": self.kdf,
        })
    }

    /// The human report: address, the funding instructions for the
    /// configured network, and the two things a new user must be told
    /// once (loss and theft), in possession language.
    #[must_use]
    pub fn render(&self) -> Vec<String> {
        let mut out = vec![
            format!("Vault created at {}.", self.vault_dir.display()),
            format!("Network: {}.", self.network.as_str()),
            String::new(),
            format!("Payment wallet address: {}", self.address),
            String::new(),
        ];
        out.extend(funding_lines(self.network, &self.address));
        out.push(String::new());
        out.extend(standing_warnings());
        out
    }
}

/// Per-network funding instructions (U11: "address + funding instructions
/// printed for all three networks").
///
/// Two currencies, always both, because a wallet holding one and not the
/// other fails at a different step with a different error — which is the
/// distinction S8's preflight exists to keep sharp.
#[must_use]
pub fn funding_lines(network: NetworkId, address: &str) -> Vec<String> {
    let mut out = vec!["To seal, this address needs two things:".to_owned()];
    match network {
        NetworkId::ArbitrumOne => {
            out.push(
                "  1. ANT tokens on Arbitrum One — they pay for the storage itself.".to_owned(),
            );
            out.push(
                "  2. A little ETH on Arbitrum One — it pays the gas for the payment \
                 transaction."
                    .to_owned(),
            );
            out.push(String::new());
            out.push(
                "Acquire ANT on Arbitrum One and send it to the address above, then bridge or \
                 buy a small amount of Arbitrum One ETH for gas. Real funds move on this \
                 network, and a seal is permanent and paid once."
                    .to_owned(),
            );
        }
        NetworkId::ArbitrumSepolia => {
            out.push("  1. Test-ANT on Arbitrum Sepolia (chain 421614).".to_owned());
            out.push("  2. Arbitrum Sepolia ETH for gas.".to_owned());
            out.push(String::new());
            out.push(
                "This is Arbitrum Sepolia, NOT Ethereum Sepolia (11155111): ETH and contracts \
                 from Ethereum Sepolia are useless here. Use an Arbitrum Sepolia gas faucet, \
                 or bridge Sepolia ETH to Arbitrum Sepolia; test-ANT comes from the \
                 project's Sepolia runbook (docs/, D38). Nothing here has value."
                    .to_owned(),
            );
        }
        NetworkId::Devnet => {
            out.push("  1. Devnet ANT — minted by the local devnet's own deployment.".to_owned());
            out.push("  2. Devnet ETH for gas — Anvil pre-funds its accounts.".to_owned());
            out.push(String::new());
            out.push(
                "On the local devnet there is no faucet and no funding step for the built-in \
                 accounts: `scripts/devnet/local-up` starts Anvil with pre-funded well-known \
                 keys and exports one in `.devnet/`. To pay from THIS address instead, send \
                 devnet ANT and ETH to it from that account. Nothing here has value, and the \
                 chain is discarded when the devnet stops."
                    .to_owned(),
            );
        }
    }
    let _ = address;
    out
}

/// The two standing warnings MVP-SPEC.md line 143 requires `init` to give
/// once, plus the positioning limit in possession language.
#[must_use]
pub fn standing_warnings() -> Vec<String> {
    vec![
        "Two things to understand before you seal anything:".to_owned(),
        "  LOSS  — lose this vault and its passphrase, and no one can ever reveal or restore \
         your sealed works again. The sealed data itself stays safely unreadable. Run \
         `antseal vault export` and keep the backup somewhere else."
            .to_owned(),
        "  THEFT — whoever holds this vault (or an export) and the passphrase can decrypt \
         every work you have ever sealed, retroactively and permanently. The ciphertexts are \
         public and undeletable, and there is no key rotation. Treat the passphrase as a \
         long-term, high-value key."
            .to_owned(),
        String::new(),
        "What a seal proves: that the holder of this vault possessed the content by the \
         anchored time. Not authorship, and not exclusive possession — someone you shared \
         with can seal the same work earlier and outrank you. Seal before you share."
            .to_owned(),
    ]
}

/// Run `init` over an injected prompt seam and RNG (the production entry
/// is [`crate::commands::init`]).
///
/// # Errors
///
/// [`CliError::Usage`] for an existing vault (absolute — D39 Decision 4),
/// a missing non-interactive input, or an unusable wallet-key channel;
/// [`CliError::NotImplemented`] for a wrap mode whose engine has not
/// landed; [`CliError::PassphraseUnavailable`] per D41/D51;
/// [`CliError::VaultKdfMemory`] when the KDF arena cannot be allocated
/// (typed hard error, **no fallback** — D40 §2); I/O errors from the
/// atomic writes.
pub fn run_init<P: InitPrompt, R: TryCryptoRng + ?Sized>(
    layout: &VaultLayout,
    args: &InitArgs,
    passphrase_fd: Option<u32>,
    machine: bool,
    network: NetworkId,
    prompt: &mut P,
    rng: &mut R,
) -> Result<InitReport, CliError> {
    // ── 1. Existing-vault refusal: absolute, and before anything else ──
    //
    // `create_vault` refuses too (the primitive owns its own invariant),
    // but the refusal must happen before a passphrase is collected, so it
    // is checked here as well rather than relied on there.
    let header = layout.beside_path(BesideFile::Header);
    if header.exists() {
        return Err(existing_vault_refusal(layout.root()));
    }

    // ── 2. Answers we cannot honour, refused before any secret ──
    if args.provided.wrap && args.wrap != WrapChoice::None {
        return Err(unimplemented_wrap());
    }

    let mut asked: Vec<WizardStep> = Vec::new();

    // ── 3. The D39 wizard, in order: passphrase → wallet → wrap → KDF ──
    //
    // `obtain_passphrase` owns the create-time floor, the confirmation
    // (TTY path only, D41 §5) and the typed no-channel abort; machine
    // mode without `--passphrase-fd` must not reach its prompt branch at
    // all, which is what the explicit gate below enforces (D51: the
    // `--json`-with-a-real-TTY case is invisible to the isatty probe).
    if passphrase_fd.is_none() && machine {
        return Err(CliError::PassphraseUnavailable {
            reason: PassphraseFailure::NoChannel,
        });
    }
    if passphrase_fd.is_none() {
        asked.push(WizardStep::Passphrase);
    }
    let passphrase = obtain_passphrase(PassphrasePurpose::Create, passphrase_fd)?;

    let wallet_source = if args.provided.wallet || machine {
        args.wallet
    } else {
        asked.push(WizardStep::WalletSource);
        match prompt
            .ask_choice(
                "Wallet key: generate a fresh one, or import an existing hex private key?",
                &["generate", "import"],
                "generate",
            )?
            .as_str()
        {
            "import" => WalletSource::Import,
            _ => WalletSource::Generate,
        }
    };

    let wrap = if args.provided.wrap || machine {
        args.wrap
    } else {
        asked.push(WizardStep::Wrap);
        // Only `none` is offered while U8's keyfile engine is unwritten:
        // offering a choice the vault cannot honour would be a lie in the
        // one place a user is deciding how their key is protected. The
        // flag still parses and still refuses, loudly, above.
        match prompt
            .ask_choice(
                "Extra wrap for the master secret? (keyfile wrap arrives with U8; only `none` \
                 is available in this build)",
                &["none"],
                "none",
            )?
            .as_str()
        {
            "none" => WrapChoice::None,
            _ => return Err(unimplemented_wrap()),
        }
    };
    if wrap != WrapChoice::None {
        return Err(unimplemented_wrap());
    }

    let kdf = if args.provided.kdf || machine {
        args.kdf
    } else {
        asked.push(WizardStep::Kdf);
        match prompt
            .ask_choice(
                "Vault key-derivation function? scrypt needs MORE memory than argon2id \
                 (~1 GiB vs 256 MiB) — it is a construction preference, never a low-RAM escape",
                &["argon2id", "scrypt"],
                "argon2id",
            )?
            .as_str()
        {
            "scrypt" => KdfChoice::Scrypt,
            _ => KdfChoice::Argon2id,
        }
    };

    // ── 4. The wallet key itself ──
    let wallet_key = match wallet_source {
        WalletSource::Generate => WalletKey::generate().map_err(|e| CliError::Internal {
            detail: e.to_string(),
        })?,
        WalletSource::Import => {
            let candidate = match args.wallet_key_fd {
                Some(fd) => read_secret_fd(fd).map_err(wallet_fd_error)?,
                None if machine => {
                    return Err(CliError::Usage {
                        message: "`--wallet import` needs the key material on a file descriptor: \
                                  pass `--wallet-key-fd <n>` (D41 — key material never travels in \
                                  argv or the environment). Nothing was created."
                            .to_owned(),
                    });
                }
                None => {
                    asked.push(WizardStep::WalletKeyPaste);
                    prompt.read_secret_line(
                        "Wallet private key (64 hex digits, optional 0x; input is hidden): ",
                    )?
                }
            };
            WalletKey::import(&candidate).map_err(import_error)?
        }
    };
    let address = checksummed(wallet_key.address());
    let handle = handle_from(&wallet_key)?;
    drop(wallet_key);

    // ── 5. Create the vault, store the key, write the config ──
    //
    // Nothing before this line wrote anything, so every refusal above
    // leaves the filesystem exactly as it found it.
    let selection = match kdf {
        KdfChoice::Argon2id => KdfSelection::Argon2id,
        KdfChoice::Scrypt => KdfSelection::Scrypt,
    };
    let vault = create_vault(layout, &passphrase, selection, rng)?;
    store_wallet_key(&vault, &handle, rng)?;

    let config_path = layout.beside_path(BesideFile::Config);
    crate::vault::fs::atomic_write(
        &config_path,
        crate::config::initial_config_text(network).as_bytes(),
    )
    .map_err(|source| CliError::Io {
        context: format!("writing {}", config_path.display()),
        source,
    })?;

    Ok(InitReport {
        address,
        network,
        vault_dir: layout.root().to_path_buf(),
        wallet_source: match wallet_source {
            WalletSource::Generate => "generate",
            WalletSource::Import => "import",
        },
        kdf: match kdf {
            KdfChoice::Argon2id => "argon2id",
            KdfChoice::Scrypt => "scrypt",
        },
        asked,
    })
}

/// The effective network for this invocation, resolved before the vault
/// exists (so `config::load` cannot be consulted — there is no config
/// yet): the flag, else the built-in default.
#[must_use]
pub fn init_network(globals: &GlobalArgs) -> NetworkId {
    crate::config::effective_network(globals.network, &crate::config::Config::default())
}

/// **D39 Decision 4's absolute refusal**, as one function so the message
/// has exactly one author: the handler emits it, and the registered
/// envelope fixture renders it from here rather than from a hand-copied
/// string (U19's rule — a fixture documenting text no build emits is
/// worse than none).
///
/// Overwriting a vault destroys `W`, and with it every sealed work's
/// reveal/restore ability, forever. There is no `--force`, and none
/// parses; moving the directory by hand is the consent.
#[must_use]
pub fn existing_vault_refusal(root: &std::path::Path) -> CliError {
    CliError::Usage {
        message: format!(
            "a vault already exists at {root} — antseal never overwrites a vault, and there is \
             no --force flag: overwriting one destroys the reveal and restore keys of every \
             work it holds, forever. If you want a fresh vault, run `antseal vault export` \
             first when the contents matter, then move or remove {root} yourself.",
            root = root.display(),
        ),
    }
}

/// D50's registry has the slot; U8 has the engine, and it has not landed.
/// A distinct, honest refusal beats a vault whose header claims a wrap it
/// does not have.
fn unimplemented_wrap() -> CliError {
    CliError::NotImplemented {
        command: "init --wrap keyfile",
        milestone: Milestone::M1,
    }
}

/// D44's rejection classes, given `init`'s own voice. The mnemonic case
/// keeps its distinct "not supported in this version" wording — U11 owns
/// the copy and must not claim forever.
fn import_error(err: WalletImportError) -> CliError {
    CliError::Usage {
        message: format!("{err} — nothing was created; re-run `antseal init` with valid material"),
    }
}

/// A wallet-key fd that could not be read. Deliberately **not** the
/// passphrase-unavailable class: this is a different secret on a
/// different channel, and conflating them would send a user to the wrong
/// flag.
fn wallet_fd_error(reason: PassphraseFailure) -> CliError {
    let detail = match reason {
        PassphraseFailure::FdReadFailed | PassphraseFailure::NoChannel => {
            "the descriptor could not be read"
        }
        PassphraseFailure::FdEmpty => "the descriptor yielded no bytes",
        PassphraseFailure::FdOverCap => "the descriptor yielded more than 1 KiB (D41's cap)",
        PassphraseFailure::FdForbiddenByte => {
            "the descriptor's bytes contain interior NUL/LF/CR, which a private key never does"
        }
        // Unreachable through this channel (the fd path never prompts and
        // never confirms), but stated rather than collapsed into a
        // catch-all that could hide a future rewiring.
        PassphraseFailure::PromptEmpty
        | PassphraseFailure::PromptFailed
        | PassphraseFailure::ConfirmMismatch => "the descriptor could not be read",
    };
    CliError::Usage {
        message: format!(
            "could not read the wallet key from --wallet-key-fd: {detail}. Nothing was created."
        ),
    }
}

/// The canonical 64-hex form → the vault's 32 raw bytes. The inverse of
/// the payment-side bridge in [`crate::backend`], and total by
/// construction: `WalletKey`'s invariant is exactly 64 lowercase hex
/// ASCII digits.
fn handle_from(key: &WalletKey) -> Result<WalletKeyHandle, CliError> {
    let hex = key.as_hex().as_bytes();
    let mut raw = [0u8; crate::vault::wallet::WALLET_KEY_LEN];
    if hex.len() != raw.len() * 2 {
        return Err(CliError::Internal {
            detail: "a validated wallet key was not 64 hex digits".to_owned(),
        });
    }
    for (index, byte) in raw.iter_mut().enumerate() {
        let pair = &hex[index * 2..index * 2 + 2];
        let text = core::str::from_utf8(pair).map_err(|_| CliError::Internal {
            detail: "a validated wallet key was not ASCII".to_owned(),
        })?;
        *byte = u8::from_str_radix(text, 16).map_err(|_| CliError::Internal {
            detail: "a validated wallet key was not hex".to_owned(),
        })?;
    }
    Ok(WalletKeyHandle::from_bytes(raw))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn funding_copy_covers_all_three_networks_in_possession_language() {
        for network in [
            NetworkId::ArbitrumOne,
            NetworkId::ArbitrumSepolia,
            NetworkId::Devnet,
        ] {
            let lines = funding_lines(network, "0xdeadBEEF");
            let text = lines.join("\n");
            assert!(!lines.is_empty(), "{network} has funding copy");
            // Both currencies, always: they fail at different steps with
            // different remedies (S8's preflight split).
            assert!(text.contains("ANT"), "{network} names the payment token");
            assert!(text.contains("ETH"), "{network} names the gas token");
            // Positioning discipline (MVP-SPEC.md line 28).
            let lower = text.to_lowercase();
            assert!(!lower.contains("notar"), "{network}: banned token");
        }
        // The wrong-Sepolia hazard is called out where it bites.
        let sepolia = funding_lines(NetworkId::ArbitrumSepolia, "0x0").join("\n");
        assert!(sepolia.contains("NOT Ethereum Sepolia"));
        assert!(sepolia.contains("421614"));
    }

    #[test]
    fn standing_warnings_state_loss_and_theft_and_the_positioning_limit() {
        let text = standing_warnings().join("\n");
        assert!(text.contains("LOSS") && text.contains("THEFT"));
        assert!(text.contains("vault export"), "loss copy names the remedy");
        assert!(
            text.contains("no key rotation"),
            "theft copy states the irreversibility"
        );
        assert!(text.contains("possessed the content by the anchored time"));
        assert!(text.contains("Not authorship"));
        assert!(text.contains("Seal before you share"));
        assert!(!text.to_lowercase().contains("notar"));
        assert!(
            !text.to_lowercase().contains("priority"),
            "unqualified priority claims are banned (MVP-SPEC.md line 28)"
        );
    }

    #[test]
    fn wizard_step_labels_are_stable() {
        assert_eq!(
            [
                WizardStep::Passphrase,
                WizardStep::WalletSource,
                WizardStep::WalletKeyPaste,
                WizardStep::Wrap,
                WizardStep::Kdf,
            ]
            .map(WizardStep::label),
            [
                "passphrase",
                "wallet-source",
                "wallet-key-paste",
                "wrap",
                "kdf"
            ]
        );
    }
}
