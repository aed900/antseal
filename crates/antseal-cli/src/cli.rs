//! The canonical `antseal` command surface — frozen from day one (U1).
//!
//! This module is the one place the CLI surface is defined. The command
//! tree below enumerates **exactly** the canonical surface of MVP-SPEC.md
//! line 149 plus the two recorded 2026-08-01 surface amendments:
//!
//! - the global `--passphrase-fd <n>` (D41 — the non-interactive
//!   passphrase channel; secrets never transit argv or the environment);
//! - the D39 `init` flag set (`--wallet`, `--wallet-key-fd`, `--kdf`,
//!   `--wrap`) — the spec's canonical list names no `init` flags, and the
//!   additions are justified in docs/decisions/D39-init-interaction-model.md.
//!
//! Nothing else joins the surface. Later-milestone commands parse today and
//! return a typed "not implemented until M<x>" error (`crate::error`), so
//! scripts written against this surface never break as handlers land. The
//! committed help snapshot (`tests/cli_surface.rs`) enumerates the whole
//! tree; any surface drift fails that test.
//!
//! Two deliberate parse-level interpretations, recorded here because the
//! canonical list under-specifies them:
//!
//! - `vault import <FILE>` takes one required positional (an import with no
//!   input is not implementable; D47 fixes the *format*, says "naming is
//!   U12's", and forbids only *flags*), and `vault export [FILE]` takes one
//!   optional positional (default naming is U12's). Positional growth is
//!   additive; removal would be breaking — hence the minimal shapes here.
//! - `--no-fine-tree <glob>` accepts a single glob value (the canonical
//!   list shows one occurrence); accepting repeats later would be additive.
//!
//! `RUST_LOG` (tracing env-filter, stderr only) is the sanctioned
//! verbosity channel; the surface deliberately has no verbosity flags.

use std::path::PathBuf;

use clap::error::ErrorKind;
use clap::{ArgGroup, Args, CommandFactory, Parser, Subcommand, ValueEnum};

/// Top-level parser: globals + the canonical command tree.
///
/// `disable_help_subcommand`: clap's implicit `help` subcommand is surface
/// the canonical list does not enumerate; `--help` (intrinsic) covers it.
#[derive(Debug, Parser)]
#[command(
    name = "antseal",
    version,
    disable_help_subcommand = true,
    about = "Seal your work into permanent encrypted public storage with independently \
             verifiable timestamps; later, reveal all of it — or any chosen part — to \
             anyone, with proof it belongs to what you sealed.",
    long_about = None
)]
pub struct Cli {
    #[command(flatten)]
    pub globals: GlobalArgs,

    #[command(subcommand)]
    pub command: Command,
}

/// Global flags, valid on every subcommand.
#[derive(Debug, Args)]
pub struct GlobalArgs {
    /// Target network (default: arbitrum-one, or config.toml's
    /// default_network — flag > config > default; "arbitrum-sepolia" is
    /// Arbitrum Sepolia, chain 421614, not Ethereum Sepolia)
    //
    // Parses as `Option` ON PURPOSE (U4): with a clap-level default an
    // explicit `--network arbitrum-one` would be indistinguishable from
    // absence, and the config file could never sit between flag and
    // built-in default. Resolution lives in `crate::config`.
    #[arg(long, global = true, value_enum, value_name = "NETWORK")]
    pub network: Option<Network>,

    /// Machine output: exactly one JSON document on stdout; all human copy
    /// on stderr; never prompts (machine mode, D51)
    #[arg(long, global = true)]
    pub json: bool,

    /// Read the vault passphrase from file descriptor <FD> (D41; stdin is
    /// `--passphrase-fd 0`). Secrets never transit argv or the environment
    #[arg(long, global = true, value_name = "FD")]
    pub passphrase_fd: Option<u32>,
}

/// `--network` values (MVP-SPEC.md line 149). Anything else is a parse
/// error — there is no free-form network string.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Network {
    /// Arbitrum One mainnet (the release default; real, permanent spends)
    ArbitrumOne,
    /// Arbitrum Sepolia (chain 421614) via the self-hosted devnet contracts
    ArbitrumSepolia,
    /// Local devnet (25 nodes + Anvil; development only)
    Devnet,
}

impl Network {
    /// The canonical CLI spelling (also the U3 envelope's `network`
    /// value) — identical to the clap value-enum rendering.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Network::ArbitrumOne => "arbitrum-one",
            Network::ArbitrumSepolia => "arbitrum-sepolia",
            Network::Devnet => "devnet",
        }
    }
}

/// The canonical command tree (MVP-SPEC.md line 149 order).
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Create the vault: passphrase, wallet key (generate or import),
    /// funding instructions, network config
    Init(InitArgs),

    /// Seal files into permanent encrypted public storage (paid,
    /// irreversible; every cheap failable step runs first)
    Seal(SealArgs),

    /// List sealed works, incomplete seals, pending-anchor nags, and
    /// per-work cost
    List,

    /// Show every unit of a work: file, byte-range, size, local snippet —
    /// the preview for `reveal --units`
    Show {
        /// The work to show
        #[arg(value_name = "WORK-ID")]
        work_id: String,
    },

    /// Show per-anchor status; `--upgrade` completes pending OTS
    /// attestations
    Status {
        /// The work to query
        #[arg(value_name = "WORK-ID")]
        work_id: String,

        /// Poll OTS calendars and upgrade pending attestations now
        #[arg(long)]
        upgrade: bool,
    },

    /// Fetch ciphertexts, decrypt with vault keys, verify against the
    /// manifest commitments, write the original files
    Restore {
        /// The work to restore
        #[arg(value_name = "WORK-ID")]
        work_id: String,

        /// Output directory (default per D48's output policy)
        #[arg(short = 'o', value_name = "DIR")]
        output: Option<PathBuf>,
    },

    /// Build a self-contained proof bundle disclosing the whole work or
    /// chosen units (irreversible disclosure; asks for confirmation)
    Reveal(RevealArgs),

    /// Verify a proof bundle offline (third-party; needs no vault and
    /// never prompts)
    Verify {
        /// The `.sealproof` bundle to verify
        #[arg(value_name = "BUNDLE")]
        bundle: PathBuf,

        /// Also confirm the Bitcoin header and Arbitrum tx via two pinned,
        /// must-agree public endpoints per source
        #[arg(long)]
        online: bool,

        /// Also re-fetch ciphertexts from Autonomi and byte-compare them
        /// against the bundle to prove persistence
        #[arg(long)]
        live: bool,
    },

    /// Encrypted vault backup: export to / import from a single file
    Vault {
        #[command(subcommand)]
        command: VaultCommand,
    },
}

/// `init` flags — the D39 v1 set, exactly; every wizard question has a
/// flag/fd equivalent so `init` scripts without a TTY.
#[derive(Debug, Args)]
pub struct InitArgs {
    /// Wallet key source: generate a fresh key, or import existing key
    /// material via --wallet-key-fd
    #[arg(long, value_enum, default_value_t = WalletSource::Generate, value_name = "SOURCE")]
    pub wallet: WalletSource,

    /// Read wallet key material from file descriptor <FD> (D41 mechanism;
    /// must differ from --passphrase-fd). Only meaningful with
    /// `--wallet import`
    #[arg(long, value_name = "FD")]
    pub wallet_key_fd: Option<u32>,

    /// Vault key-derivation function (D40). scrypt is an explicit operator
    /// choice and needs MORE memory (~1 GiB vs argon2id's 256 MiB) — it is
    /// not a low-RAM escape
    #[arg(long, value_enum, default_value_t = KdfChoice::Argon2id, value_name = "KDF")]
    pub kdf: KdfChoice,

    /// Optional extra wrap for the master secret (D50 registry; default:
    /// declined)
    #[arg(long, value_enum, default_value_t = WrapChoice::None, value_name = "WRAP")]
    pub wrap: WrapChoice,
}

/// `--wallet` values (D39: default `generate` — the non-destructive branch).
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum WalletSource {
    /// Generate a fresh key and print its address + funding instructions
    Generate,
    /// Import existing key material (format per D44) via --wallet-key-fd
    Import,
}

/// `--kdf` values (D40: Argon2id is the sole default; scrypt only ever by
/// this explicit selection — no automatic or fallback path picks it).
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum KdfChoice {
    /// Argon2id m=256 MiB, t=3, p=1 (the default)
    Argon2id,
    /// scrypt N=2^20, r=8, p=1 (~1 GiB — more memory than argon2id, chosen
    /// for construction preference, never for resources)
    Scrypt,
}

/// `--wrap` values (D50 wrap-mode registry: 0 = none, 1 = keyfile;
/// 2 = os-keystore is format-reserved with no M1 implementation and is
/// deliberately NOT a value here).
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum WrapChoice {
    /// No extra wrap: passphrase-only vault (the default)
    None,
    /// Wrap the master secret with a generated high-entropy keyfile,
    /// required alongside the passphrase at every unlock
    Keyfile,
}

/// `seal` arguments (MVP-SPEC.md line 149).
#[derive(Debug, Args)]
pub struct SealArgs {
    /// Files to seal (files only — a directory argument is a hard error,
    /// D46)
    #[arg(required = true, value_name = "PATH")]
    pub paths: Vec<PathBuf>,

    /// Title embedded in the manifest — visible to every bundle recipient
    /// (`seal` warns about this)
    #[arg(long, value_name = "TITLE")]
    pub title: Option<String>,

    /// Unit-splitting strategy for text files
    #[arg(long, value_enum, value_name = "MODE")]
    pub split: Option<SplitMode>,

    /// Treat inputs as text even where detection says binary (D20)
    #[arg(long)]
    pub force_text: bool,

    /// Exclude files matching <GLOB> from the fine-grained byte tree:
    /// they become whole-file-revealable only, permanently
    #[arg(long, value_name = "GLOB")]
    pub no_fine_tree: Option<String>,

    /// Run every free step and print the plan + true cost quote; nothing
    /// is paid, anchored, or uploaded (D49)
    #[arg(long)]
    pub dry_run: bool,

    /// Consent in advance to the permanence gate (for scripts; the consent
    /// report still prints)
    #[arg(long)]
    pub yes: bool,

    /// Proceed even if fewer than one TSA token was obtained (records a
    /// degraded anchor set, loudly)
    #[arg(long)]
    pub force_degraded: bool,

    /// Dev-only: skip anchoring entirely, producing an UNANCHORED seal.
    /// Rejected on arbitrum-one. Hidden from help by design (canonical
    /// surface, dev-only; MVP-SPEC.md line 149).
    #[arg(long, hide = true)]
    pub no_anchor: bool,
}

/// `--split` values: the canonical surface admits exactly `blank-lines`
/// (heading-aware splitting is parked v1.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum SplitMode {
    /// Split text into units at blank-line boundaries (D22)
    BlankLines,
}

/// `reveal` arguments: exactly one of `--all` / `--units` at parse time.
#[derive(Debug, Args)]
#[command(group(
    ArgGroup::new("selection")
        .required(true)
        .multiple(false)
        .args(["all", "units"])
))]
pub struct RevealArgs {
    /// The work to reveal from
    #[arg(value_name = "WORK-ID")]
    pub work_id: String,

    /// Reveal every unit of the work
    #[arg(long)]
    pub all: bool,

    /// Reveal exactly these units (work-global ordinals as printed by
    /// `show`), e.g. --units 3,5
    #[arg(long, value_delimiter = ',', value_name = "UNIT")]
    pub units: Vec<u64>,

    /// Write the proof bundle here
    #[arg(short = 'o', value_name = "FILE")]
    pub output: Option<PathBuf>,

    /// Include the Arbitrum payment receipt in the bundle (off by default —
    /// it exposes the paying wallet)
    #[arg(long)]
    pub include_receipt: bool,

    /// Consent in advance to the disclosure confirmation (for scripts)
    #[arg(long)]
    pub yes: bool,
}

/// `vault` subcommands (D47: single re-encrypted file, no flags).
#[derive(Debug, Subcommand)]
pub enum VaultCommand {
    /// Write the whole vault as one encrypted backup file (same
    /// passphrase, proven by the unlock export performs; D47)
    Export {
        /// Output file (default naming per U12)
        #[arg(value_name = "FILE")]
        file: Option<PathBuf>,
    },
    /// Reconstruct the vault directory from an export file on a clean
    /// machine (validates fully before touching anything; refuses an
    /// existing vault)
    Import {
        /// The export file to import
        #[arg(value_name = "FILE")]
        file: PathBuf,
    },
}

impl Cli {
    /// Parse + the cross-argument checks clap's declarative layer cannot
    /// express. This is the single entry every driver (binary, tests)
    /// uses, so no path can skip validation.
    ///
    /// # Errors
    ///
    /// Returns the `clap::Error` for malformed argv, `--help`/`--version`
    /// requests (clap models those as errors with exit code 0), and the
    /// D39 fd-collision usage error.
    pub fn parse_checked<I, T>(itr: I) -> Result<Self, clap::Error>
    where
        I: IntoIterator<Item = T>,
        T: Into<std::ffi::OsString> + Clone,
    {
        let cli = Self::try_parse_from(itr)?;
        cli.cross_validate()?;
        Ok(cli)
    }

    /// D39 rules with no declarative clap encoding:
    /// - `--wallet-key-fd` equal to `--passphrase-fd` is a usage error
    ///   (the two secrets must travel distinct channels);
    /// - `--wallet-key-fd` without `--wallet import` is a usage error
    ///   (silently ignoring a secret-bearing channel would be worse).
    fn cross_validate(&self) -> Result<(), clap::Error> {
        if let Command::Init(args) = &self.command {
            if let (Some(pass_fd), Some(wallet_fd)) =
                (self.globals.passphrase_fd, args.wallet_key_fd)
                && pass_fd == wallet_fd
            {
                return Err(Self::command().error(
                    ErrorKind::ArgumentConflict,
                    format!(
                        "--wallet-key-fd {wallet_fd} equals --passphrase-fd {pass_fd}: the \
                         wallet key and the passphrase must arrive on different file \
                         descriptors (D39)"
                    ),
                ));
            }
            if args.wallet_key_fd.is_some() && args.wallet != WalletSource::Import {
                return Err(Self::command().error(
                    ErrorKind::ArgumentConflict,
                    "--wallet-key-fd is only meaningful with --wallet import",
                ));
            }
        }
        Ok(())
    }
}
