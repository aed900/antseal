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
//! **`ok` means "a `result` document is present", not "the exit code is
//! 0"** (D69 §3 R1; maintainer-confirmed 2026-08-12). The two were
//! coincident until M3 and are separated deliberately: `verify` reports a
//! bad verdict at a nonzero code (41/42/43) while still emitting its full
//! result, because D27 §4 means an *error* envelope has no report at all
//! — modelling a verdict as a `CliError` would delete the verdict's
//! detail from the machine surface. `ok:false` continues to mean exactly
//! *`error` is present and `result` is not*. No key was added, removed or
//! renamed, so this is not the machine-interface event
//! [`ENVELOPE_VERSION`] reserves a bump for. D51 invariant 2 still holds:
//! the code is computed before the mode branch, so plain and `--json`
//! runs exit identically.
//!
//! # Schema stability — the three tiers (D65 §3; **this is the M3 home**)
//!
//! The `--json` document has three regions with three different honest
//! promises. `docs/decisions/D65-json-schema-stability-commitment.md` is
//! the record; the division of labour with the other normative surface is
//! stated once: **`docs/testing/error-code-contract.md` owns the `error`
//! object's identifier semantics** (`class` is U2's committed table,
//! disjoint from the verifier's rejection-code namespace; `message` is
//! freely rewordable) and **this module owns everything else** — the
//! envelope grammar, the tiers, the carriage rule, and the null/type
//! rules below. U32 lifts this table into release docs at M4.
//!
//! | tier | scope | promise |
//! |---|---|---|
//! | **A — frozen** | `result.report` on `verify --json` | exactly [`antseal_core::verify::report::VerificationReport::to_canonical_json`]'s bytes: the same bytes 21 golden vectors pin, the same bytes wasm32 bit-matches. Field set, order, spellings and JSON types move only through a `REPORT_VERSION` bump (a D105 §2.4 format event). |
//! | **B — stable-additive from M3** | the wrapper: `v`, `command`, `network`, `ok`, exactly one of `result`/`error`; and `class`, `exit_code`, `message` inside `error` | no key is renamed, removed, retyped, or moved between the top level and `result` without an [`ENVELOPE_VERSION`] bump. New top-level keys may be added without one. `v` is the discriminant a consumer reads first. |
//! | **C — unstable until U32** | everything else inside `result` — for `verify` the `overlay`, `live` and `verdict` siblings; for every already-shipped command the whole `result` interior | none, and saying so is the point. Keys here may be renamed, removed or retyped between M3 and M4 with no version moving. Every such change is **reviewed** (`envelope_fixtures_match_the_committed_snapshot` reddens), but review is not compatibility. |
//!
//! **Tier A's one hole, priced rather than hidden**: enum-valued keys
//! inside the report (`anchors[].state`, `work.signature_scheme`,
//! `storage_linkage`, `supporting_evidence`, `anchors[].kind`) may gain a
//! spelling with **no version moving anywhere** — D105 §2.4 rules a new
//! variant a value addition, and carrying the report verbatim imports
//! that permission into `--json`. **A consumer must treat every
//! enum-valued key as open and always write the default arm.**
//!
//! The sentence for a scripter, in full:
//!
//! > At M3, gate your scripts on the **exit code**, on `ok`, on `v`, and
//! > on `result.report` — those are stable. Everything else under
//! > `result` is reviewed but not promised until the M4 release freeze,
//! > and every enum-valued field may gain a value, so always write the
//! > default arm.
//!
//! ## Carriage: `result.report` is byte-verbatim (D65 §5)
//!
//! Those bytes are spliced, not re-serialized: [`success_envelope`]'s
//! `serde_json::Value` parameter **cannot** express verbatim carriage,
//! because `serde_json::Map` is a `BTreeMap` in this build and a `Value`
//! round trip alphabetizes the report's keys, destroying D29 rule 1's
//! declaration order. `verify` therefore renders its whole `result`
//! through serde on typed values and hands the text to
//! [`success_envelope_raw`]. `preserve_order` must not be enabled for
//! `serde_json` anywhere in the workspace: it would silently reorder
//! every `--json` document in the product for no product gain.
//!
//! ## Null, types, and key order (D65 §7)
//!
//! At **every** tier, including C:
//!
//! - **absence is `null`, never a missing key** — which is what makes a
//!   presence-only key assertion a meaningful instrument;
//! - **no float ever appears** in any `--json` document; integers and
//!   strings only;
//! - **any integer that can exceed 2⁵³ is a decimal string** (the
//!   `cost_atto` rule);
//! - **a key's JSON type never changes** without the version whose scope
//!   contains it — number↔string is breaking;
//! - **time-shaped values carry their provenance in their JSON type**:
//!   verifier-derived integers are JSON numbers, sealer-recorded values
//!   are decimal strings reproduced verbatim and never reformatted.
//!
//! **Key order is promised nowhere except inside `result.report`**, where
//! it is the wire order (D29 rule 1) and the reason the carriage rule
//! exists. Outside it, the alphabetical ordering is an artifact of
//! `serde_json::Map` being a `BTreeMap` — a dependency default, not a
//! decision. Consumers must not depend on it; a JSON parser does not
//! preserve it anyway.
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
///
/// **It is this document's only schema version** (D65 §4). `REPORT_VERSION`
/// is *not* a `--json` schema version and must never be used as one: it
/// versions a determinism artifact shared with a second implementation and
/// pinned by 21 frozen vectors, and it appears here only because the report
/// is carried verbatim — as `result.report.report_version`, a field of an
/// opaque member rather than the document's version. **Neither derives from
/// the other**: `v:1` beside `report_version:2` is legal and is not an error
/// state, so code that computes one from the other is wrong.
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

/// The success envelope over a **pre-rendered** `result` document — D65
/// §5's carriage route for `verify`, whose `report` member must reach stdout
/// byte-for-byte as `to_canonical_json()` produced it.
///
/// `result` is spliced in verbatim and must be one well-formed JSON value.
/// The four wrapper members are rendered through `serde_json` (so a network
/// or command name containing a quote or a backslash escapes correctly) and
/// emitted in the **alphabetical** order [`success_envelope`]'s
/// `serde_json::Map` produces — `command`, `network`, `ok`, `result`, `v` —
/// so no document's bytes move and the two constructors are
/// interchangeable for every result a `Value` can express.
///
/// That interchangeability is asserted rather than described:
/// `tests/machine_mode.rs`'s
/// `the_raw_envelope_is_byte_identical_to_the_value_envelope` runs both
/// constructors over **every registered fixture** and compares bytes. A
/// hand-built document that drifted from the `json!` one would redden
/// there, on nine real documents, rather than being discovered by a
/// consumer.
///
/// Returns a `String` rather than a `Value` on purpose: a `Value` return
/// would have to parse the splice back, which is the exact round trip this
/// function exists to avoid.
#[must_use]
pub fn success_envelope_raw(command: &str, network: &str, result: &str) -> String {
    // `to_string` on a `&str` cannot fail (no map keys, no floats, no
    // non-UTF-8), but library code never unwraps: the fallback is a
    // JSON-quoted empty string, which keeps the document well-formed.
    let quote = |s: &str| serde_json::to_string(s).unwrap_or_else(|_| "\"\"".to_owned());
    format!(
        "{{\"command\":{},\"network\":{},\"ok\":true,\"result\":{result},\"v\":{ENVELOPE_VERSION}}}",
        quote(command),
        quote(network),
    )
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
