//! U1 acceptance suite: the canonical command surface is frozen from day
//! one.
//!
//! - `clap::Command::debug_assert` validates the whole parse tree;
//! - every `--help` screen (root + each subcommand, recursively) is
//!   snapshot-tested against ONE committed fixture,
//!   `tests/snapshots/cli-surface.help.txt` — the snapshot *enumerates* the
//!   surface, so any addition, removal, or wording drift fails here. To
//!   regenerate after a deliberate surface change:
//!   `ANTSEAL_BLESS=1 cargo test -p antseal-cli` (then review the diff);
//! - parse-level rules of U1's Accept list are pinned one test each;
//! - the binary is spawned to prove exit-code wiring, stdout purity, and
//!   stderr-only tracing.
//!
//! Everything here is non-secret: argv fixtures and rendered help text.

#[path = "common/spawn.rs"]
mod spawn;
use std::process::Command as Process;

use antseal_cli::cli::{Cli, Command, Network, SplitMode, VaultCommand, WalletSource};
use clap::CommandFactory;

// ─────────────────────────────────────────────────────────────────────
// Parse-tree validity
// ─────────────────────────────────────────────────────────────────────

#[test]
fn clap_debug_assert_accepts_the_command_tree() {
    Cli::command().debug_assert();
}

// ─────────────────────────────────────────────────────────────────────
// Help-surface snapshot
// ─────────────────────────────────────────────────────────────────────

/// Render the long help of the root command and every subcommand,
/// depth-first, into one deterministic document (no color and no terminal
/// width probing are compiled in — see the clap feature comment in the
/// workspace Cargo.toml).
fn render_surface() -> String {
    fn walk(cmd: &mut clap::Command, path: &str, out: &mut String) {
        out.push_str(&format!("════ {path} ════\n"));
        out.push_str(&cmd.render_long_help().to_string());
        out.push('\n');
        let subs: Vec<String> = cmd
            .get_subcommands()
            .map(|s| s.get_name().to_owned())
            .collect();
        for name in subs {
            let sub = cmd
                .find_subcommand_mut(&name)
                .expect("subcommand just enumerated");
            let sub_path = format!("{path} {name}");
            walk(sub, &sub_path, out);
        }
    }
    let mut root = Cli::command();
    root.build();
    let mut out = String::new();
    walk(&mut root, "antseal", &mut out);
    out
}

#[test]
fn help_surface_matches_committed_snapshot() {
    let rendered = render_surface();
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/snapshots/cli-surface.help.txt");
    if std::env::var_os("ANTSEAL_BLESS").is_some() {
        std::fs::write(&path, &rendered).expect("write blessed snapshot");
        return;
    }
    let committed = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "missing committed help snapshot at {}: {e}\n\
             (generate once with ANTSEAL_BLESS=1 and review the diff)",
            path.display()
        )
    });
    assert!(
        committed == rendered,
        "the rendered CLI surface differs from the committed snapshot \
         {}.\nThe surface is frozen (U1): if this change is deliberate, \
         regenerate with ANTSEAL_BLESS=1 and justify the diff in review.",
        path.display()
    );
}

/// The snapshot must cover every node of the tree — if a subcommand is
/// added, both this count and the snapshot change together.
#[test]
fn snapshot_enumerates_every_command_node() {
    let rendered = render_surface();
    for header in [
        "════ antseal ════",
        "════ antseal init ════",
        "════ antseal seal ════",
        "════ antseal list ════",
        "════ antseal show ════",
        "════ antseal status ════",
        "════ antseal restore ════",
        "════ antseal reveal ════",
        "════ antseal verify ════",
        "════ antseal vault ════",
        "════ antseal vault export ════",
        "════ antseal vault import ════",
    ] {
        assert!(rendered.contains(header), "snapshot lost section {header}");
    }
    assert_eq!(
        rendered.matches("════ antseal").count(),
        12,
        "command tree grew or shrank: update the canonical list, the \
         snapshot, and this count together (deliberately)"
    );
}

// ─────────────────────────────────────────────────────────────────────
// Parse rules (U1 Accept list, one test each)
// ─────────────────────────────────────────────────────────────────────

fn parse(args: &[&str]) -> Result<Cli, clap::Error> {
    Cli::parse_checked(args.iter().copied())
}

#[test]
fn network_accepts_exactly_the_three_networks_and_absence_is_none() {
    for (value, expected) in [
        ("arbitrum-one", Network::ArbitrumOne),
        ("arbitrum-sepolia", Network::ArbitrumSepolia),
        ("devnet", Network::Devnet),
    ] {
        let cli = parse(&["antseal", "--network", value, "list"]).expect("valid network");
        assert_eq!(cli.globals.network, Some(expected));
    }
    // Absence parses as None ON PURPOSE (U4): the arbitrum-one default is
    // applied by `config::effective_network` (flag > config > default),
    // where an explicit `--network arbitrum-one` must stay
    // distinguishable from no flag at all. The precedence table lives in
    // tests/config_file.rs.
    let cli = parse(&["antseal", "list"]).expect("no flag");
    assert_eq!(cli.globals.network, None);

    let err = parse(&["antseal", "--network", "mainnet", "list"]).expect_err("unknown network");
    assert_eq!(err.kind(), clap::error::ErrorKind::InvalidValue);
}

#[test]
fn network_is_global_and_parses_after_the_subcommand() {
    let cli = parse(&["antseal", "list", "--network", "devnet"]).expect("global position");
    assert_eq!(cli.globals.network, Some(Network::Devnet));
}

#[test]
fn split_accepts_only_blank_lines() {
    let cli = parse(&["antseal", "seal", "a.txt", "--split", "blank-lines"]).expect("valid split");
    match cli.command {
        Command::Seal(args) => assert_eq!(args.split, Some(SplitMode::BlankLines)),
        other => panic!("expected seal, got {other:?}"),
    }
    let err = parse(&["antseal", "seal", "a.txt", "--split", "headings"]).expect_err("bad split");
    assert_eq!(err.kind(), clap::error::ErrorKind::InvalidValue);
}

#[test]
fn no_fine_tree_takes_a_glob_value() {
    let cli = parse(&["antseal", "seal", "a.txt", "--no-fine-tree", "*.bin"]).expect("glob value");
    match cli.command {
        Command::Seal(args) => assert_eq!(args.no_fine_tree.as_deref(), Some("*.bin")),
        other => panic!("expected seal, got {other:?}"),
    }
    let err = parse(&["antseal", "seal", "a.txt", "--no-fine-tree"]).expect_err("missing value");
    assert_eq!(err.kind(), clap::error::ErrorKind::InvalidValue);
}

#[test]
fn seal_requires_at_least_one_path() {
    let err = parse(&["antseal", "seal"]).expect_err("no paths");
    assert_eq!(err.kind(), clap::error::ErrorKind::MissingRequiredArgument);
}

#[test]
fn reveal_requires_exactly_one_of_all_or_units() {
    let cli = parse(&["antseal", "reveal", "w1", "--all"]).expect("--all alone");
    match cli.command {
        Command::Reveal(args) => {
            assert!(args.all);
            assert!(args.units.is_empty());
        }
        other => panic!("expected reveal, got {other:?}"),
    }

    let cli = parse(&["antseal", "reveal", "w1", "--units", "3,5"]).expect("--units alone");
    match cli.command {
        Command::Reveal(args) => {
            assert!(!args.all);
            assert_eq!(args.units, vec![3, 5]);
        }
        other => panic!("expected reveal, got {other:?}"),
    }

    let err = parse(&["antseal", "reveal", "w1"]).expect_err("neither selector");
    assert_eq!(err.kind(), clap::error::ErrorKind::MissingRequiredArgument);

    let err =
        parse(&["antseal", "reveal", "w1", "--all", "--units", "3"]).expect_err("both selectors");
    assert_eq!(err.kind(), clap::error::ErrorKind::ArgumentConflict);
}

/// **U68 / D68 §3 R3**: a range-shaped `--units` value is refused by a
/// message that names the comma form and `show`, not by clap's bare
/// `invalid digit found in string`.
///
/// Asserted **by message content, never by exit code** — a bare clap digit
/// error also exits 2, so a code-only assertion would pass against the very
/// defect this row exists to fix.
#[test]
fn a_range_shaped_units_value_is_refused_by_a_message_naming_the_comma_form() {
    for spelling in ["3-5", "3..5", "3..=5", "10-40"] {
        let err = parse(&["antseal", "reveal", "w1", "--units", spelling])
            .expect_err("ranges are refused for MVP");
        let rendered = err.render().to_string();
        assert!(
            rendered.contains(spelling),
            "the refusal names the offending value: {rendered}"
        );
        assert!(
            rendered.contains("ranges are not supported"),
            "the refusal says ranges are out: {rendered}"
        );
        assert!(
            rendered.contains("--units 3,4,5"),
            "the refusal shows the supported comma form: {rendered}"
        );
        assert!(
            rendered.contains("antseal show"),
            "the refusal points at where the ids come from: {rendered}"
        );
        assert!(
            !rendered.contains("invalid digit found in string"),
            "the generic digit message is exactly what this row replaces: {rendered}"
        );
    }
}

/// D68 §3 R2's acceptance envelope, kept **byte for byte** by the U68
/// parser: everything that is not range-shaped still gets `u64`'s own
/// message, and everything that parsed before still parses.
///
/// The rows are the ones D68 §1 (g) measured against the shipped binary.
#[test]
fn the_units_acceptance_envelope_is_unchanged_outside_the_range_case() {
    // Accepted, unchanged.
    for (argv, expected) in [
        (vec!["--units", "3,5"], vec![3u64, 5]),
        // clap `Append`: the repeated flag is the ARG_MAX escape hatch.
        (vec!["--units", "3", "--units", "5"], vec![3, 5]),
        // Duplicates reach R16, which dedups them (a typo with no
        // disclosure consequence).
        (vec!["--units", "3,3,5"], vec![3, 3, 5]),
        // Rust's `u64::FromStr` takes a leading `+`; refusing it would mint
        // a custom integer parser for zero safety gain.
        (vec!["--units", "+3"], vec![3]),
        (vec!["--units", "0"], vec![0]),
    ] {
        let mut args = vec!["antseal", "reveal", "w1"];
        args.extend(argv.iter().copied());
        let cli = parse(&args).unwrap_or_else(|e| panic!("{argv:?} must parse: {e}"));
        match cli.command {
            Command::Reveal(reveal) => assert_eq!(reveal.units, expected, "{argv:?}"),
            other => panic!("expected reveal, got {other:?}"),
        }
    }

    // Refused, each with `u64`'s own sentence — NOT the range message.
    for (value, expected) in [
        ("0x3", "invalid digit found in string"),
        (" 3", "invalid digit found in string"),
        ("", "cannot parse integer from empty string"),
        ("3,,5", "cannot parse integer from empty string"),
        ("3,5,", "cannot parse integer from empty string"),
        (
            "99999999999999999999",
            "number too large to fit in target type",
        ),
    ] {
        let rendered = parse(&["antseal", "reveal", "w1", "--units", value])
            .expect_err(value)
            .render()
            .to_string();
        assert!(rendered.contains(expected), "`{value}`: {rendered}");
        assert!(
            !rendered.contains("ranges are not supported"),
            "`{value}` is not range-shaped: {rendered}"
        );
    }
}

#[test]
fn passphrase_fd_rejects_non_numeric_values() {
    let cli = parse(&["antseal", "--passphrase-fd", "3", "list"]).expect("numeric fd");
    assert_eq!(cli.globals.passphrase_fd, Some(3));
    let err = parse(&["antseal", "--passphrase-fd", "three", "list"]).expect_err("non-numeric fd");
    assert_eq!(err.kind(), clap::error::ErrorKind::ValueValidation);
}

#[test]
fn wallet_key_fd_equal_to_passphrase_fd_is_a_usage_error() {
    let err = parse(&[
        "antseal",
        "--passphrase-fd",
        "3",
        "init",
        "--wallet",
        "import",
        "--wallet-key-fd",
        "3",
    ])
    .expect_err("equal fds");
    assert_eq!(err.kind(), clap::error::ErrorKind::ArgumentConflict);

    let cli = parse(&[
        "antseal",
        "--passphrase-fd",
        "3",
        "init",
        "--wallet",
        "import",
        "--wallet-key-fd",
        "4",
    ])
    .expect("distinct fds parse");
    match cli.command {
        Command::Init(args) => {
            assert_eq!(args.wallet, WalletSource::Import);
            assert_eq!(args.wallet_key_fd, Some(4));
        }
        other => panic!("expected init, got {other:?}"),
    }
}

#[test]
fn wallet_key_fd_without_wallet_import_is_a_usage_error() {
    let err = parse(&["antseal", "init", "--wallet-key-fd", "4"]).expect_err("generate + key fd");
    assert_eq!(err.kind(), clap::error::ErrorKind::ArgumentConflict);
}

#[test]
fn init_defaults_are_the_decided_ones() {
    let cli = parse(&["antseal", "init"]).expect("bare init");
    match cli.command {
        Command::Init(args) => {
            // D39: generate is the default (safe branch); D40: argon2id is
            // the sole default; D50: the wrap offer defaults to declined.
            assert_eq!(args.wallet, WalletSource::Generate);
            assert_eq!(format!("{:?}", args.kdf), "Argon2id");
            assert_eq!(format!("{:?}", args.wrap), "None");
        }
        other => panic!("expected init, got {other:?}"),
    }
}

/// **U38's red-then-green test.** The three defaulted `init` values must
/// report whether they were *typed*, not merely what they are — D39
/// Decision 1 ("a value already supplied by flag/fd is not asked again")
/// and U11 Accept row 3 both turn on the distinction, and before U38 the
/// parsed struct could not express it.
///
/// The shape is deliberately "same value, different provenance": a bare
/// `init` and an `init --wallet generate` **agree** on `wallet` and
/// **disagree** on `provided.wallet`. Asserting only the flagged side
/// would pass against a `provided` hard-coded to `true`.
#[test]
fn defaulted_init_values_report_whether_they_were_supplied() {
    let bare = parse(&["antseal", "init"]).expect("bare init");
    let Command::Init(bare) = bare.command else {
        panic!("expected init")
    };
    // Nothing typed ⇒ nothing counts as supplied, and the wizard asks.
    assert_eq!(
        (bare.provided.wallet, bare.provided.kdf, bare.provided.wrap),
        (false, false, false)
    );

    // Each flag, typed with EXACTLY the value clap would have defaulted
    // to: the values agree, the provenance does not.
    for (flag, value) in [
        ("--wallet", "generate"),
        ("--kdf", "argon2id"),
        ("--wrap", "none"),
    ] {
        let cli = parse(&["antseal", "init", flag, value]).expect("explicit default value parses");
        let Command::Init(args) = cli.command else {
            panic!("expected init")
        };
        assert_eq!(args.wallet, bare.wallet, "{flag}: value must be unchanged");
        assert_eq!(
            format!("{:?}", args.kdf),
            format!("{:?}", bare.kdf),
            "{flag}: value must be unchanged"
        );
        assert_eq!(
            format!("{:?}", args.wrap),
            format!("{:?}", bare.wrap),
            "{flag}: value must be unchanged"
        );
        let supplied = match flag {
            "--wallet" => (
                args.provided.wallet,
                !args.provided.kdf,
                !args.provided.wrap,
            ),
            "--kdf" => (
                args.provided.kdf,
                !args.provided.wallet,
                !args.provided.wrap,
            ),
            _ => (
                args.provided.wrap,
                !args.provided.wallet,
                !args.provided.kdf,
            ),
        };
        assert_eq!(
            supplied,
            (true, true, true),
            "{flag}: exactly this one must read as supplied"
        );
    }

    // A non-default value is supplied too (the obvious direction, kept so
    // a regression that keys off "value != default" is caught as well).
    let imported = parse(&[
        "antseal",
        "init",
        "--wallet",
        "import",
        "--wallet-key-fd",
        "4",
    ])
    .expect("import parses");
    let Command::Init(imported) = imported.command else {
        panic!("expected init")
    };
    assert!(imported.provided.wallet);
    assert!(!imported.provided.kdf);

    // Hand-constructed args (fixtures, tests) default to "ask", never
    // "assume" — the safe direction.
    assert_eq!(
        antseal_cli::cli::InitProvided::default(),
        antseal_cli::cli::InitProvided {
            wallet: false,
            kdf: false,
            wrap: false,
        }
    );
}

/// U38 must not touch the frozen U1 surface: `#[arg(skip)]` fields are
/// invisible to clap's builder, so no argument named `provided` exists and
/// the committed help snapshot is unchanged. (The snapshot test above is
/// the real check; this states the mechanism so a future reader knows a
/// re-blessed snapshot here would be a defect signal, not a chore.)
#[test]
fn the_value_source_field_adds_no_argument_to_the_surface() {
    let mut root = Cli::command();
    let init = root
        .get_subcommands_mut()
        .find(|c| c.get_name() == "init")
        .expect("init exists");
    let names: Vec<&str> = init.get_arguments().map(|a| a.get_id().as_str()).collect();
    assert!(
        !names.contains(&"provided"),
        "the U38 field must not become a flag: {names:?}"
    );
    assert_eq!(
        names,
        vec!["wallet", "wallet_key_fd", "kdf", "wrap"],
        "init's argument set is the frozen D39 v1 set"
    );
    assert!(!render_surface().contains("provided"));
}

#[test]
fn no_anchor_parses_but_is_hidden_from_help() {
    let cli = parse(&["antseal", "seal", "a.txt", "--no-anchor"]).expect("dev flag parses");
    match cli.command {
        Command::Seal(args) => assert!(args.no_anchor),
        other => panic!("expected seal, got {other:?}"),
    }
    assert!(
        !render_surface().contains("no-anchor"),
        "--no-anchor is dev-only and must stay hidden from help output"
    );
}

#[test]
fn vault_subcommands_parse() {
    let cli = parse(&["antseal", "vault", "export"]).expect("export, default naming");
    match cli.command {
        Command::Vault {
            command: VaultCommand::Export { file },
        } => assert!(file.is_none()),
        other => panic!("expected vault export, got {other:?}"),
    }
    let cli = parse(&["antseal", "vault", "import", "backup.antseal"]).expect("import with file");
    match cli.command {
        Command::Vault {
            command: VaultCommand::Import { file },
        } => assert_eq!(file, std::path::PathBuf::from("backup.antseal")),
        other => panic!("expected vault import, got {other:?}"),
    }
    let err = parse(&["antseal", "vault", "import"]).expect_err("import needs its file");
    assert_eq!(err.kind(), clap::error::ErrorKind::MissingRequiredArgument);
}

// ─────────────────────────────────────────────────────────────────────
// Binary wiring: exit codes, stdout purity, stderr-only tracing
// ─────────────────────────────────────────────────────────────────────

fn antseal_bin() -> Process {
    spawn::antseal()
}

#[test]
fn a_dispatched_command_keeps_stdout_clean_and_traces_only_to_stderr() {
    // **This row used to be the stub exemplar, and it has run out of
    // stubs.** It moved seven times as handlers landed — `vault
    // export|import` at U12, `init` at U11, `seal` at U13, `list`/`restore`
    // at U19/U20, `status` at U23 (which emptied M2), `show` at U27,
    // `reveal` at U28/U29 — and **U30 empties M3**, so no dispatch arm can
    // produce the not-implemented class any more.
    //
    // What the row was always really about survives unchanged: stdout stays
    // reserved for command output, and `RUST_LOG` tracing is env-filtered
    // and stderr-only. The vehicle is `verify`, which needs no vault and
    // never prompts, so it reaches dispatch on any machine; its bundle path
    // does not exist, so it stops in the ordinary I/O class.
    let out = antseal_bin()
        .args(["verify", "b.sealproof"])
        .env("RUST_LOG", "debug")
        .output()
        .expect("spawn antseal");
    assert_eq!(out.status.code(), Some(4), "io-error exit code");
    assert!(
        out.stdout.is_empty(),
        "stdout must stay reserved for command output; got {:?}",
        String::from_utf8_lossy(&out.stdout)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("b.sealproof"),
        "the refusal names the file it could not read; stderr was {stderr:?}"
    );
    // RUST_LOG=debug: the dispatch trace event must land on stderr —
    // proving tracing is wired, env-filtered, and stderr-only.
    assert!(
        stderr.contains("dispatch"),
        "expected the debug-level dispatch trace on stderr; got {stderr:?}"
    );
}

#[test]
fn no_command_names_a_milestone_any_more() {
    // The inverse of the row above, kept so a shrinking list cannot
    // silently accept a regression. `verify` was the last stub of the
    // frozen surface (U30) and `reveal` the one before it (U28/U29); both
    // reach a real handler without a vault, so both can be driven here on
    // any machine. A stub message from either would mean a dispatch arm
    // came undone.
    //
    // The class itself is deliberately NOT deleted: `CliError::NotImplemented`
    // still exists for the type's own exhaustive matches and for a future
    // surface addition. What is asserted is that nothing *reaches* it.
    for args in [
        ["verify", "b.sealproof", ""].as_slice(),
        ["reveal", "w1", "--all"].as_slice(),
    ] {
        let args: Vec<&str> = args.iter().copied().filter(|a| !a.is_empty()).collect();
        let out = antseal_bin().args(&args).output().expect("spawn antseal");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            !stderr.contains("not implemented"),
            "`{args:?}` is no longer a stub; stderr was {stderr:?}"
        );
        assert_ne!(
            out.status.code(),
            Some(3),
            "`{args:?}` must not exit in the not-implemented class; stderr was {stderr:?}"
        );
    }
}

#[test]
fn help_exits_zero_on_stdout_and_usage_error_exits_two_on_stderr() {
    let out = antseal_bin().arg("--help").output().expect("spawn antseal");
    assert_eq!(out.status.code(), Some(0), "--help is success");
    assert!(!out.stdout.is_empty(), "help renders on stdout");
    assert!(out.stderr.is_empty(), "help writes nothing to stderr");

    // `mainnet` is not a network this build knows, so this fails inside
    // **clap**, before dispatch — which is why the subcommand named here is
    // irrelevant and deliberately stayed `status` when U23 implemented it.
    // Nothing runs, so no vault is opened and no passphrase is asked for.
    let out = antseal_bin()
        .args(["--network", "mainnet", "status", "w1"])
        .output()
        .expect("spawn antseal");
    assert_eq!(out.status.code(), Some(2), "usage errors exit 2");
    assert!(out.stdout.is_empty(), "usage errors render on stderr");
    assert!(!out.stderr.is_empty());
}
