//! S42 (D178 R1, R3, R4): the spawned binary and upstream's state file.
//!
//! The pinned client reads, and on every drop writes, `client_adaptive.json` in
//! a data directory it finds through `XDG_DATA_HOME`, `HOME` and `USERPROFILE`
//! — and panics, after dialing, when none of them resolves
//! (`antseal_net::network::upstream_state`). These rows hold both halves of
//! S42 through the binary a user runs:
//!
//! - **the precondition (both builds)**: cargo's `[env]` table in
//!   `.cargo/config.toml` has set this test process's `XDG_DATA_HOME` to
//!   `<workspace>/target/upstream-data-home`, so every client a test builds —
//!   in process, or in a child that inherits the variable — writes there and
//!   not into the developer's own `~/.local/share/ant` (D178 R3);
//! - **the refusal (feature build)**: a `reveal` that must fetch, run with
//!   neither `HOME`, `XDG_DATA_HOME` nor `USERPROFILE`, exits in the network
//!   class (23) with the S42 refusal — never 101, the panic — and so does one
//!   whose `XDG_DATA_HOME` is set but empty, which upstream would have
//!   written under the current directory (D178 R1);
//! - **the confinement, with its positive control (feature build)**: the same
//!   command with `HOME` pointed at a fresh temporary directory leaves that
//!   directory empty while it inherits the cargo `XDG_DATA_HOME`; and with
//!   `XDG_DATA_HOME` removed, it writes
//!   `<temporary home>/.local/share/ant/client_adaptive.json` holding exactly
//!   `schema` and `channels{quote,store,fetch}` — which is what makes "left
//!   it empty" mean something: the command does build a client, and upstream
//!   does write (D178 R4).
//!
//! The command is `reveal` over a work whose unit ciphertexts are evicted from
//! the vault cache, with a devnet definition whose one bootstrap peer is a
//! dead loopback port: the cheapest command that builds a storage client
//! without a network. Every child runs in its own scratch directory, so a
//! write into the current directory lands where these rows can see it and
//! nowhere in the tree.
//!
//! NON-SECRET: every fixture byte string is documented here; the dead export
//! is walletless and names Anvil's well-known deterministic contracts.

mod common;

#[path = "common/spawn.rs"]
mod spawn;

use std::path::{Path, PathBuf};

/// `<workspace>/target/upstream-data-home`, the value `.cargo/config.toml`
/// gives `XDG_DATA_HOME` (`relative = true` resolves it against the directory
/// holding `.cargo/`, the workspace root).
fn confined_data_home() -> PathBuf {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    manifest
        .parent()
        .and_then(Path::parent)
        .expect("the crate sits two levels below the workspace root")
        .join("target")
        .join("upstream-data-home")
}

/// **D178 R3/R4, the precondition.** Every test cargo runs from inside the
/// tree has `XDG_DATA_HOME` pointed into `target/` — the one line of
/// `.cargo/config.toml` that keeps every in-process and inherited client out
/// of the developer's home.
#[test]
fn s42_cargo_points_this_test_processs_xdg_data_home_into_target() {
    let expected = confined_data_home();
    let actual = std::env::var_os("XDG_DATA_HOME");
    assert_eq!(
        actual.as_deref(),
        Some(expected.as_os_str()),
        "S42: XDG_DATA_HOME = {actual:?}; expected {} (the [env] line in .cargo/config.toml, \
         D178 R3)",
        expected.display()
    );
}

#[cfg(feature = "ant-backend")]
mod feature_build {
    use std::io::Write as _;
    use std::path::{Path, PathBuf};
    use std::process::Stdio;
    use std::time::{Duration, Instant};

    use antseal_cli::pipeline::journal::UNIT_ENTRY_BASE;
    use antseal_cli::pipeline::{
        NoBarriers, Pipeline, SealFile, SealRequest, SealResult, VaultJournal, hex32,
    };
    use antseal_cli::vault::session::UnlockedVault;
    use antseal_cli::vault::store::{SealShapingFlags, WorkStore};
    use antseal_core::content::FileFlags;
    use antseal_core::crypto::sig_policy::SigPolicy;
    use antseal_net::NetworkId;
    use antseal_net::network::upstream_state;
    use antseal_net::test_util::{MockBackend, block_on};
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    use super::common::{FIXTURE_PASSPHRASE, IsolatedVault, RecordingGate, ScriptedConsent};
    use super::spawn;

    /// The reader's one connect trace (`backend::connect_read_only`).
    const READER_CONNECT_TRACE: &str = "connecting the read-only reader";
    /// The reveal engine's sentence for a unit it could not obtain.
    const UNFETCHABLE_SENTENCE: &str = "could not be fetched from the network";
    /// What the rows read from stderr.
    const LOG: &str = "antseal_cli::backend=debug";
    /// A hang guard, not a speed claim: a refused run takes about a second, a
    /// dead-loopback connect about six (D170).
    const RUN_CAP: Duration = Duration::from_secs(120);

    /// A scratch directory that removes itself.
    struct Scratch(PathBuf);

    impl Scratch {
        fn new(tag: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "antseal-s42-{tag}-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .expect("clock")
                    .as_nanos()
            ));
            std::fs::create_dir_all(&path).expect("mk scratch");
            Self(path)
        }

        /// A fresh, empty subdirectory.
        fn dir(&self, name: &str) -> PathBuf {
            let path = self.0.join(name);
            std::fs::create_dir_all(&path).expect("mk scratch subdirectory");
            path
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// A vault holding one sealed work whose unit ciphertexts are all evicted
    /// from the cache, so a reveal of it must fetch — and so must build a
    /// storage client. Returns the vault and the printed work id.
    fn fixture_needing_a_fetch(tag: &str, seed: u8) -> (IsolatedVault, String) {
        let vault = IsolatedVault::create(tag);
        let unlocked = vault.unlock();
        let work_id = seal_one_file(&unlocked, seed);
        let store = WorkStore::new(&unlocked);
        let works = store.list_works().expect("list");
        assert_eq!(works.len(), 1, "the fixture vault holds one work");
        let units: Vec<u64> = store
            .list_journal_entries(&works[0])
            .expect("entries")
            .into_iter()
            .filter(|entry| *entry >= UNIT_ENTRY_BASE)
            .collect();
        assert!(!units.is_empty(), "the seal cached its unit ciphertexts");
        for unit in &units {
            store
                .delete_journal_entry(&works[0], *unit)
                .expect("evict a cached unit");
        }
        drop(unlocked);
        (vault, work_id)
    }

    /// Seal one small file on `devnet` through the real pipeline over a
    /// `MockBackend`.
    fn seal_one_file(vault: &UnlockedVault, seed: u8) -> String {
        let files = vec![SealFile {
            path_as_given: "notes.txt",
            path_absolute: "/w/notes.txt",
            bytes: b"s42 fixture: one short paragraph\n",
            flags: FileFlags::new(),
        }];
        let mock = MockBackend::new();
        let mut journal_rng = ChaCha20Rng::from_seed([seed ^ 0xA5; 32]);
        let journal = VaultJournal::new(WorkStore::new(vault), &mut journal_rng);
        let gate = RecordingGate::new();
        let consent = ScriptedConsent::always_yes();
        let pipeline = Pipeline::new(&mock, &gate, &journal, &consent, &NoBarriers);
        let request = SealRequest {
            files: &files,
            title: "s42 fixture".to_owned(),
            claimed_time_unix_secs: 1_800_000_000,
            app_version: "antseal-test/1".to_owned(),
            network: NetworkId::Devnet,
            no_anchor: false,
            degraded: false,
            dry_run: false,
            sig_policy: SigPolicy::hybrid(),
            shaping: SealShapingFlags::default(),
        };
        match block_on(pipeline.seal(&request, &mut ChaCha20Rng::from_seed([seed; 32])))
            .expect("the fixture seals")
        {
            SealResult::Sealed(outcome) => hex32(&outcome.work_id),
            SealResult::DryRun(_) => unreachable!("not a dry run"),
        }
    }

    /// A devnet definition that reaches nothing: its one bootstrap peer is a
    /// loopback UDP port bound and released a moment ago, its payment RPC a
    /// loopback TCP port likewise. Walletless; Anvil's well-known contracts.
    fn dead_devnet_export(dir: &Path) -> PathBuf {
        let udp = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind a loopback probe socket");
        let bootstrap = udp.local_addr().expect("the probe's address");
        drop(udp);
        let tcp =
            std::net::TcpListener::bind("127.0.0.1:0").expect("bind a loopback probe listener");
        let rpc_port = tcp.local_addr().expect("the probe's address").port();
        drop(tcp);
        let text = format!(
            "# antseal devnet environment: a dead one, for S42's rows\n\
             ANTSEAL_DEVNET_RPC_URL='http://127.0.0.1:{rpc_port}/'\n\
             ANTSEAL_DEVNET_CHAIN_ID='31337'\n\
             ANTSEAL_DEVNET_TOKEN_ADDRESS='0x5FbDB2315678afecb367f032d93F642f64180aa3'\n\
             ANTSEAL_DEVNET_PAYMENT_VAULT_ADDRESS='0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512'\n\
             ANTSEAL_DEVNET_BOOTSTRAP='{bootstrap}'\n\
             ANTSEAL_DEVNET_NODE_COUNT='1'\n\
             ANTSEAL_DEVNET_BASE_PORT='{port}'\n\
             ANTSEAL_DEVNET_DATA_DIR='{data}'\n\
             ANTSEAL_DEVNET_PID='{pid}'\n",
            port = bootstrap.port(),
            data = dir.display(),
            pid = std::process::id(),
        );
        let path = dir.join("dead-devnet.env");
        std::fs::write(&path, text).expect("write the dead devnet export");
        path
    }

    /// How a row sets the three variables upstream reads.
    enum UpstreamEnv<'a> {
        /// None of `HOME`, `XDG_DATA_HOME`, `USERPROFILE`.
        Nothing,
        /// `XDG_DATA_HOME` set but empty; no `HOME`, no `USERPROFILE`.
        EmptyXdg,
        /// `HOME` set, `XDG_DATA_HOME` removed: upstream's own default.
        HomeOnly(&'a Path),
        /// `HOME` set, `XDG_DATA_HOME` inherited from this process (cargo's).
        HomeInheritingXdg(&'a Path),
    }

    /// What a spawned `antseal` answered.
    struct Spawned {
        code: Option<i32>,
        stdout: String,
        stderr: String,
    }

    impl Spawned {
        fn document(&self) -> serde_json::Value {
            serde_json::from_str(self.stdout.trim_end_matches('\n')).unwrap_or_else(|error| {
                panic!(
                    "stdout is not one JSON document ({error}).\nstdout:\n{}\nstderr:\n{}",
                    self.stdout, self.stderr
                )
            })
        }

        fn message(&self) -> String {
            self.document()["error"]["message"]
                .as_str()
                .unwrap_or_else(|| panic!("an error message: {}", self.document()))
                .to_owned()
        }

        fn connect_traces(&self) -> usize {
            self.stderr.matches(READER_CONNECT_TRACE).count()
        }
    }

    /// Spawn `antseal --json --passphrase-fd 0 reveal <work> --all --yes -o
    /// <bundle>` over `vault`, in `cwd`, with `env` deciding the three
    /// variables and `export` the only devnet definition.
    fn spawn_reveal(
        vault: &IsolatedVault,
        work_id: &str,
        bundle: &Path,
        export: &Path,
        cwd: &Path,
        env: &UpstreamEnv<'_>,
    ) -> Spawned {
        let bundle_arg = bundle.to_str().expect("a utf-8 scratch path").to_owned();
        let mut command = spawn::antseal();
        command
            .args([
                "--json",
                "--passphrase-fd",
                "0",
                "reveal",
                work_id,
                "--all",
                "--yes",
                "-o",
                &bundle_arg,
            ])
            .current_dir(cwd)
            .env("ANTSEAL_DIR", vault.layout.root())
            .env("ANTSEAL_DEVNET_ENV", export)
            .env("RUST_LOG", LOG)
            .env_remove("USERPROFILE")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        match env {
            UpstreamEnv::Nothing => {
                command.env_remove("HOME").env_remove("XDG_DATA_HOME");
            }
            UpstreamEnv::EmptyXdg => {
                command.env_remove("HOME").env("XDG_DATA_HOME", "");
            }
            UpstreamEnv::HomeOnly(path) => {
                command.env("HOME", path).env_remove("XDG_DATA_HOME");
            }
            UpstreamEnv::HomeInheritingXdg(path) => {
                command.env("HOME", path);
            }
        }
        let started = Instant::now();
        let mut child = command.spawn().expect("spawn antseal");
        // Ignored on purpose: a command that refuses before reading the
        // passphrase closes the pipe first.
        let _ = child
            .stdin
            .as_mut()
            .expect("stdin is piped")
            .write_all(FIXTURE_PASSPHRASE);
        drop(child.stdin.take());
        let out = child.wait_with_output().expect("wait for antseal");
        let elapsed = started.elapsed();
        assert!(
            elapsed < RUN_CAP,
            "the run took {elapsed:?} — a hang, not a refusal"
        );
        Spawned {
            code: out.status.code(),
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        }
    }

    /// Every file under `dir`, relative to it.
    fn files_under(dir: &Path) -> Vec<String> {
        fn walk(root: &Path, dir: &Path, out: &mut Vec<String>) {
            let Ok(entries) = std::fs::read_dir(dir) else {
                return;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    walk(root, &path, out);
                }
                out.push(
                    path.strip_prefix(root)
                        .unwrap_or(&path)
                        .display()
                        .to_string(),
                );
            }
        }
        let mut out = Vec::new();
        walk(dir, dir, &mut out);
        out.sort();
        out
    }

    /// A row the S42 refusal must end: the network class (23), never the
    /// panic (101); the refusal's sentence in the message; and nothing
    /// written into the current directory.
    fn assert_refused(label: &str, run: &Spawned, cwd: &Path, case: &str) {
        assert_ne!(
            run.code,
            Some(101),
            "{label}: the binary panicked — upstream's HomeDirNotFound was reached (S42). \
             stderr:\n{}",
            run.stderr
        );
        // Before the exit code: a run that was not refused also ends in 23 (its
        // fetch fails), so what tells the two apart first is the write.
        let written = files_under(cwd);
        assert!(
            written.is_empty(),
            "{label}: upstream wrote into the current directory: {written:?}"
        );
        assert_eq!(
            run.code,
            Some(23),
            "{label}: expected Some(23) with the S42 refusal, got {:?}. stderr:\n{}",
            run.code,
            run.stderr
        );
        let document = run.document();
        assert_eq!(
            document["error"]["class"],
            serde_json::json!("network-failure"),
            "{label}: {document}"
        );
        let message = run.message();
        assert!(
            message.contains(upstream_state::REFUSAL) && message.contains(case),
            "{label}: the S42 refusal, naming the case `{case}`: {message}"
        );
    }

    /// **S42 Accept 2 (A1).** No `HOME`, no `XDG_DATA_HOME`, no
    /// `USERPROFILE`: upstream would panic after dialing. The binary must end
    /// in the network class with the S42 refusal instead.
    #[test]
    fn s42_a_reveal_with_no_home_at_all_is_refused_never_a_panic() {
        let scratch = Scratch::new("no-home");
        let (vault, work_id) = fixture_needing_a_fetch("s42-no-home", 0x42);
        let export = dead_devnet_export(&scratch.dir("export"));
        let cwd = scratch.dir("cwd");
        let bundle = scratch.0.join("no-home.sealproof");
        let run = spawn_reveal(
            &vault,
            &work_id,
            &bundle,
            &export,
            &cwd,
            &UpstreamEnv::Nothing,
        );
        assert_refused(
            "no HOME, XDG_DATA_HOME or USERPROFILE",
            &run,
            &cwd,
            "XDG_DATA_HOME, HOME and USERPROFILE are all unset",
        );
        assert!(!bundle.exists(), "a refused reveal writes no bundle");
        let _ = std::fs::remove_dir_all(&vault.root);
    }

    /// **S42 (A2).** `XDG_DATA_HOME` set but empty, and no `HOME`: upstream
    /// would not panic — it would write `ant/client_adaptive.json` into the
    /// current directory. Refused, and the directory stays empty.
    #[test]
    fn s42_an_empty_xdg_data_home_is_refused_and_nothing_lands_in_the_cwd() {
        let scratch = Scratch::new("empty-xdg");
        let (vault, work_id) = fixture_needing_a_fetch("s42-empty-xdg", 0x43);
        let export = dead_devnet_export(&scratch.dir("export"));
        let cwd = scratch.dir("cwd");
        let bundle = scratch.0.join("empty-xdg.sealproof");
        let run = spawn_reveal(
            &vault,
            &work_id,
            &bundle,
            &export,
            &cwd,
            &UpstreamEnv::EmptyXdg,
        );
        assert_refused(
            "empty XDG_DATA_HOME",
            &run,
            &cwd,
            "XDG_DATA_HOME is set but empty",
        );
        let _ = std::fs::remove_dir_all(&vault.root);
    }

    /// **S42 Accept 1 (A6) with its positive control (A3).**
    ///
    /// Control first: `HOME` at a fresh temporary directory and
    /// `XDG_DATA_HOME` removed. The command is not refused, it builds a client
    /// (the reader's connect trace, once), the fetch fails in the network
    /// class in the engine's own sentence — and upstream writes
    /// `<home>/.local/share/ant/client_adaptive.json` holding exactly
    /// `schema` and `channels{quote,store,fetch}`.
    ///
    /// Then the assertion: the same command with `HOME` at another fresh
    /// directory and `XDG_DATA_HOME` inherited from this process — cargo's —
    /// leaves that home empty, and upstream's file is under
    /// `target/upstream-data-home`.
    #[test]
    fn s42_cargos_xdg_data_home_keeps_upstreams_file_out_of_a_temporary_home() {
        let scratch = Scratch::new("confined");
        let (vault, work_id) = fixture_needing_a_fetch("s42-confined", 0x44);
        let export = dead_devnet_export(&scratch.dir("export"));

        // ── the positive control ─────────────────────────────────────────
        let control_home = scratch.dir("control-home");
        let control_cwd = scratch.dir("control-cwd");
        let control = spawn_reveal(
            &vault,
            &work_id,
            &scratch.0.join("control.sealproof"),
            &export,
            &control_cwd,
            &UpstreamEnv::HomeOnly(&control_home),
        );
        assert_eq!(
            control.code,
            Some(23),
            "CONTROL: the fetch over a dead network fails in the network class. stderr:\n{}",
            control.stderr
        );
        let message = control.message();
        assert!(
            message.contains(UNFETCHABLE_SENTENCE) && !message.contains(upstream_state::REFUSAL),
            "CONTROL: with HOME set the client is built and the fetch fails — refused with HOME \
             set? {message}"
        );
        assert_eq!(
            control.connect_traces(),
            1,
            "CONTROL: the reader was connected once. stderr:\n{}",
            control.stderr
        );
        let snapshot = control_home
            .join(".local")
            .join("share")
            .join("ant")
            .join(upstream_state::FILE_NAME);
        let text = std::fs::read_to_string(&snapshot).unwrap_or_else(|error| {
            panic!(
                "CONTROL: upstream wrote no {} under the temporary HOME ({error}) — so a clean \
                 home below would prove nothing. Files there: {:?}",
                snapshot.display(),
                files_under(&control_home)
            )
        });
        let state: serde_json::Value =
            serde_json::from_str(&text).expect("upstream's snapshot is JSON");
        let keys = |value: &serde_json::Value| -> Vec<String> {
            let mut keys: Vec<String> = value
                .as_object()
                .map(|object| object.keys().cloned().collect())
                .unwrap_or_default();
            keys.sort();
            keys
        };
        assert_eq!(keys(&state), ["channels", "schema"], "{text}");
        assert_eq!(
            keys(&state["channels"]),
            ["fetch", "quote", "store"],
            "{text}"
        );
        assert!(
            files_under(&control_cwd).is_empty(),
            "CONTROL: nothing lands in the current directory"
        );

        // ── the assertion ────────────────────────────────────────────────
        let home = scratch.dir("confined-home");
        let cwd = scratch.dir("confined-cwd");
        let run = spawn_reveal(
            &vault,
            &work_id,
            &scratch.0.join("confined.sealproof"),
            &export,
            &cwd,
            &UpstreamEnv::HomeInheritingXdg(&home),
        );
        assert_eq!(
            run.code,
            Some(23),
            "the confined run fails its fetch like the control. stderr:\n{}",
            run.stderr
        );
        assert_eq!(run.connect_traces(), 1, "stderr:\n{}", run.stderr);
        let leaked = files_under(&home);
        assert!(
            leaked.is_empty(),
            "upstream wrote into the temporary HOME although XDG_DATA_HOME points into target/ \
             (D178 R3): {leaked:?}"
        );
        assert!(files_under(&cwd).is_empty(), "nothing lands in the cwd");
        let confined = super::confined_data_home()
            .join("ant")
            .join(upstream_state::FILE_NAME);
        assert!(
            confined.is_file(),
            "the confined write landed under target/: {}",
            confined.display()
        );
        let _ = std::fs::remove_dir_all(&vault.root);
    }
}
