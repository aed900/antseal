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
    Process::new(env!("CARGO_BIN_EXE_antseal"))
}

#[test]
fn stub_command_exits_with_the_not_implemented_code_and_clean_stdout() {
    let out = antseal_bin()
        .arg("list")
        .env("RUST_LOG", "debug")
        .output()
        .expect("spawn antseal");
    assert_eq!(out.status.code(), Some(3), "not-implemented exit code");
    assert!(
        out.stdout.is_empty(),
        "stdout must stay reserved for command output; got {:?}",
        String::from_utf8_lossy(&out.stdout)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("not implemented until M1"),
        "stub error names its milestone; stderr was {stderr:?}"
    );
    // RUST_LOG=debug: the dispatch trace event must land on stderr —
    // proving tracing is wired, env-filtered, and stderr-only.
    assert!(
        stderr.contains("dispatch"),
        "expected the debug-level dispatch trace on stderr; got {stderr:?}"
    );
}

#[test]
fn stub_milestones_are_named_per_command() {
    // Rows shrink as real handlers land (U1's arrival map): `vault
    // export|import` left this list at U12.
    for (args, milestone) in [
        (vec!["status", "w1"], "M2"),
        (vec!["show", "w1"], "M3"),
        (vec!["reveal", "w1", "--all"], "M3"),
        (vec!["verify", "b.sealproof"], "M3"),
        (vec!["restore", "w1"], "M1"),
    ] {
        let out = antseal_bin().args(&args).output().expect("spawn antseal");
        assert_eq!(out.status.code(), Some(3), "{args:?}");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            stderr.contains(&format!("not implemented until {milestone}")),
            "{args:?} must name {milestone}; stderr was {stderr:?}"
        );
    }
}

#[test]
fn help_exits_zero_on_stdout_and_usage_error_exits_two_on_stderr() {
    let out = antseal_bin().arg("--help").output().expect("spawn antseal");
    assert_eq!(out.status.code(), Some(0), "--help is success");
    assert!(!out.stdout.is_empty(), "help renders on stdout");
    assert!(out.stderr.is_empty(), "help writes nothing to stderr");

    let out = antseal_bin()
        .args(["--network", "mainnet", "list"])
        .output()
        .expect("spawn antseal");
    assert_eq!(out.status.code(), Some(2), "usage errors exit 2");
    assert!(out.stdout.is_empty(), "usage errors render on stderr");
    assert!(!out.stderr.is_empty());
}
