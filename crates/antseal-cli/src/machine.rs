//! The `--json` machine-output framework (U3): the one-document
//! contract, the versioned envelope, single-point machine-mode detection
//! (D51), and the prompt-class registry.
//!
//! # The one-document contract
//!
//! Under `--json`, stdout carries **exactly one JSON document per
//! invocation** — the versioned envelope below, success or failure — and
//! every human-facing byte (reports, prompts-that-would-have-been, nags,
//! warnings, tracing) goes to stderr. Exit codes are identical to plain
//! mode (D51 invariant 2). Two intrinsic surfaces are exempt, documented:
//! `--help`/`--version` render clap's text on stdout with code 0 (they
//! are not command invocations and industry convention wins), and argv
//! that cannot parse at all gets a best-effort envelope only when the
//! literal `--json` token is present in argv (see
//! [`argv_requests_json`]).
//!
//! # The envelope (v1 — the U2 provisional error object, finalized)
//!
//! ```json
//! { "v": 1, "command": "<name>|null", "network": "<name>|null",
//!   "ok": true,  "result": { … } }
//! { "v": 1, "command": "<name>|null", "network": "<name>|null",
//!   "ok": false, "error": { "class": "<kebab>", "exit_code": n,
//!                            "message": "<human>" } }
//! ```
//!
//! The inner `error` object keeps U2's exact provisional shape
//! (`class`/`exit_code`/`message`) — kept rather than re-versioned,
//! deliberately: scripts written against the U2 shape keep working, and
//! the envelope adds `v`/`command`/`network` around it. `command` and
//! `network` are `null` only on the unparseable-argv path, where neither
//! is knowable. Committed examples: `tests/snapshots/json-envelopes.txt`
//! (one per command — the schema-registry fixture the harness enforces).
//!
//! # Machine mode (D51, the single detection point)
//!
//! machine ⇔ `--json` ∨ stdin is not a TTY ∨ stdin consumed by
//! `--passphrase-fd 0` — [`machine_mode_for`], which delegates to the U7
//! primitive (stdin `isatty` only; `/dev/tty` probing is rejected by
//! D51). **In machine mode nothing prompts, ever**: each prompt class
//! aborts through its declared channel's absence with its dedicated
//! class — consent → `consent-not-obtained`, authentication →
//! `passphrase-unavailable`, configuration → `usage`, destructive
//! confirm → `consent-not-obtained`. Consumers (U14's gate, the
//! passphrase seam in `commands.rs`) take this determination as an
//! input and never probe TTY-ness themselves.
//!
//! # The prompt-class registry
//!
//! Every command registers its prompt classes and each class's declared
//! non-interactive channel — or a deliberate `None` (D51: `vault
//! import`'s overwrite confirm has no channel; its v1 disposition is
//! refuse-always, in every mode). The registry rides the same exhaustive
//! `match` as [`command_name`], so a new subcommand fails to compile
//! until it is both named and registered; the abort-not-hang harness
//! (`tests/machine_mode.rs`) then drives every registered command ×
//! machine-mode flag combination under a watchdog and asserts the typed
//! abort.

use crate::cli::{Cli, Command, GlobalArgs, VaultCommand};
use crate::error::CliError;

/// Envelope schema version. Bumping it is a machine-interface event:
/// committed fixtures, this doc, and consumers move together.
pub const ENVELOPE_VERSION: u32 = 1;

/// The canonical command names, exactly the ten of the frozen surface —
/// the harness's enumeration axis and the fixture registry's key set.
pub const ALL_COMMAND_NAMES: [&str; 10] = [
    "init",
    "seal",
    "list",
    "show",
    "status",
    "restore",
    "reveal",
    "verify",
    "vault export",
    "vault import",
];

/// A command's registered interactivity profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommandSpec {
    /// Canonical name (the envelope's `command` field).
    pub name: &'static str,
    /// Declared prompt classes (empty = zero prompts by construction).
    pub prompts: &'static [PromptDeclaration],
}

/// One registered prompt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PromptDeclaration {
    /// Which D51 class this prompt belongs to.
    pub class: PromptClass,
    /// The declared non-interactive channel, or `None` for a deliberate
    /// absence (machine mode then has no path but the abort).
    pub channel: Option<&'static str>,
}

/// The D51 prompt classes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PromptClass {
    /// Permanence/disclosure consent (`--yes` consents in advance;
    /// machine mode without it → consent-not-obtained).
    Consent,
    /// The vault passphrase (`--passphrase-fd`; machine mode without it
    /// → passphrase-unavailable).
    Authentication,
    /// `init`-wizard configuration questions (D39 flags; machine mode
    /// with a required input missing → usage).
    Configuration,
    /// A destructive overwrite confirm. `vault import`'s is registered
    /// with NO channel: v1 disposition is refuse-always (D51 — the
    /// manual move/remove of the existing vault is the consent).
    DestructiveConfirm,
}

const AUTH: PromptDeclaration = PromptDeclaration {
    class: PromptClass::Authentication,
    channel: Some("--passphrase-fd"),
};
const CONSENT_YES: PromptDeclaration = PromptDeclaration {
    class: PromptClass::Consent,
    channel: Some("--yes"),
};
const INIT_CONFIG: PromptDeclaration = PromptDeclaration {
    class: PromptClass::Configuration,
    channel: Some("--wallet / --wallet-key-fd / --kdf / --wrap (D39)"),
};
const IMPORT_OVERWRITE: PromptDeclaration = PromptDeclaration {
    class: PromptClass::DestructiveConfirm,
    channel: None,
};

/// The registry (one row per command; the exhaustive `match` is the
/// compile-time completeness guarantee).
#[must_use]
pub fn spec(command: &Command) -> CommandSpec {
    match command {
        Command::Init(_) => CommandSpec {
            name: "init",
            prompts: &[AUTH, INIT_CONFIG],
        },
        Command::Seal(_) => CommandSpec {
            name: "seal",
            prompts: &[CONSENT_YES, AUTH],
        },
        Command::List => CommandSpec {
            name: "list",
            prompts: &[AUTH],
        },
        Command::Show { .. } => CommandSpec {
            name: "show",
            prompts: &[AUTH],
        },
        Command::Status { .. } => CommandSpec {
            name: "status",
            prompts: &[AUTH],
        },
        // D48: restore's per-file overwrite policy replaces the y/n
        // convention — no consent prompt exists by construction.
        Command::Restore { .. } => CommandSpec {
            name: "restore",
            prompts: &[AUTH],
        },
        // U29 (M3) inherits the D51 matrix unchanged — registered now so
        // M3 makes no fresh decision.
        Command::Reveal(_) => CommandSpec {
            name: "reveal",
            prompts: &[CONSENT_YES, AUTH],
        },
        // Vault-less and prompt-free, mandated (tasks/U.md U30).
        Command::Verify { .. } => CommandSpec {
            name: "verify",
            prompts: &[],
        },
        Command::Vault { command } => match command {
            VaultCommand::Export { .. } => CommandSpec {
                name: "vault export",
                prompts: &[AUTH],
            },
            VaultCommand::Import { .. } => CommandSpec {
                name: "vault import",
                prompts: &[AUTH, IMPORT_OVERWRITE],
            },
        },
    }
}

/// Canonical command name (the envelope's `command` field).
#[must_use]
pub fn command_name(command: &Command) -> &'static str {
    spec(command).name
}

/// The single machine-mode detection point (D51): delegates to the U7
/// primitive over the real stdin. Everything that must not prompt keys
/// on this — never on a local isatty probe.
#[must_use]
pub fn machine_mode_for(globals: &GlobalArgs) -> bool {
    crate::passphrase::machine_mode(globals.json, globals.passphrase_fd)
}

/// Does raw argv ask for JSON? The best-effort token scan for the
/// unparseable-argv path (documented limitation: a literal `--json`
/// appearing as another flag's *value* also matches — harmless, since
/// the emitted envelope is still one well-formed JSON document, and a
/// parse that failed has no better source of intent).
#[must_use]
pub fn argv_requests_json(args: &[std::ffi::OsString]) -> bool {
    args.iter().any(|a| a == "--json")
}

/// The success envelope: exactly one of these on stdout per successful
/// `--json` invocation.
#[must_use]
pub fn success_envelope(
    command: &str,
    network: &str,
    result: serde_json::Value,
) -> serde_json::Value {
    serde_json::json!({
        "v": ENVELOPE_VERSION,
        "command": command,
        "network": network,
        "ok": true,
        "result": result,
    })
}

/// The error envelope (inner object = U2's shape, finalized).
#[must_use]
pub fn error_envelope(command: &str, network: &str, err: &CliError) -> serde_json::Value {
    serde_json::json!({
        "v": ENVELOPE_VERSION,
        "command": command,
        "network": network,
        "ok": false,
        "error": err.error_object(),
    })
}

/// The unparseable-argv envelope (`command`/`network` unknowable →
/// null; class fixed to `usage`, matching clap's exit code 2).
#[must_use]
pub fn unparseable_argv_envelope(message: &str) -> serde_json::Value {
    serde_json::json!({
        "v": ENVELOPE_VERSION,
        "command": serde_json::Value::Null,
        "network": serde_json::Value::Null,
        "ok": false,
        "error": {
            "class": "usage",
            "exit_code": 2,
            "message": message,
        }
    })
}

/// Convenience for tests and the registry harness: every command's spec,
/// resolved by parsing its minimal argv (specs are reachable only
/// through [`spec`]'s exhaustive match, so this list and the match can
/// never disagree without a compile or test failure).
#[must_use]
pub fn all_specs() -> Vec<CommandSpec> {
    MINIMAL_ARGV
        .iter()
        .map(|argv| {
            let cli = Cli::parse_checked(argv.iter().copied())
                .unwrap_or_else(|e| panic!("minimal argv {argv:?} must parse: {e}"));
            spec(&cli.command)
        })
        .collect()
}

/// One minimal valid argv per command (the harness drives these).
pub const MINIMAL_ARGV: [&[&str]; 10] = [
    &["antseal", "init"],
    &["antseal", "seal", "x.txt"],
    &["antseal", "list"],
    &["antseal", "show", "w1"],
    &["antseal", "status", "w1"],
    &["antseal", "restore", "w1"],
    &["antseal", "reveal", "w1", "--all"],
    &["antseal", "verify", "b.sealproof"],
    &["antseal", "vault", "export"],
    &["antseal", "vault", "import", "backup.sealvault"],
];

#[cfg(test)]
mod tests {
    use super::*;

    /// The name list, the minimal-argv list, and the registry agree 1:1
    /// and in order.
    #[test]
    fn registry_covers_exactly_the_canonical_surface() {
        let specs = all_specs();
        assert_eq!(specs.len(), ALL_COMMAND_NAMES.len());
        for (spec, name) in specs.iter().zip(ALL_COMMAND_NAMES) {
            assert_eq!(spec.name, name);
        }
    }

    /// Every consent-class declaration's channel is `--yes`, and the
    /// command's surface really accepts it (the declared channel must
    /// exist, or the declaration is a lie).
    #[test]
    fn declared_consent_channels_parse() {
        for (argv, spec) in MINIMAL_ARGV.iter().zip(all_specs()) {
            for prompt in spec.prompts {
                if prompt.class == PromptClass::Consent {
                    assert_eq!(prompt.channel, Some("--yes"), "{}", spec.name);
                    let mut with_yes: Vec<&str> = argv.to_vec();
                    with_yes.push("--yes");
                    Cli::parse_checked(with_yes.iter().copied()).unwrap_or_else(|e| {
                        panic!("{} declares --yes but rejects it: {e}", spec.name)
                    });
                }
            }
        }
    }

    /// The one deliberate channel-less prompt is vault import's
    /// destructive confirm (D51) — and only that one.
    #[test]
    fn the_only_channel_less_prompt_is_the_import_overwrite() {
        let mut found = Vec::new();
        for spec in all_specs() {
            for prompt in spec.prompts {
                if prompt.channel.is_none() {
                    found.push((spec.name, prompt.class));
                }
            }
        }
        assert_eq!(
            found,
            vec![("vault import", PromptClass::DestructiveConfirm)]
        );
    }
}
