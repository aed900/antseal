//! The CLI's peer resolution through the spawned binary (D173 §2 R4, R6, R7;
//! D174 §2 R2) — the `ant-backend` build only.
//!
//! # Why this suite runs in the feature build alone
//!
//! A build with no storage backend answers `seal` at the backend seam (exit
//! 23, the no-backend refusal) before `seal_over_backend`'s live arm, and the
//! live arm is where the vault lock, the network definition and the peer
//! resolution live; `U73`'s rows in `seal_command.rs` hold that per build.
//! So the ordering these rows prove — peers resolved **before** the
//! passphrase — is only reachable in a build that has a backend:
//!
//! ```text
//! cargo test -p antseal-cli --features ant-backend --test peer_resolution
//! ```
//!
//! # No network, by construction
//!
//! Every row either refuses before any socket or is refused by the storage
//! gate (D173 §2 R9) as the **first** fallible step of the payer, before its
//! payment-RPC call and before any storage peer is dialed. The gate is armed
//! here twice over: by the debug-build arm every `cargo test` binary carries,
//! and by the variable this suite sets on every spawn. The one control that
//! proceeds past resolution uses a `devnet` export whose only peer and whose
//! RPC are loopback ports nothing listens on.
//!
//! # What each row discriminates
//!
//! - **Before the passphrase.** Machine mode with no `--passphrase-fd`
//!   cannot collect a passphrase, so a handler that asked for one first
//!   would exit 11 (`passphrase-unavailable`); the row demands 2, and
//!   reads D42's hook trace as the process-level witness that no vault was
//!   unlocked. The vault directory is fingerprinted before and after: every
//!   file but the lockfile — which the single-writer lock rewrites on every
//!   acquisition — must be byte-identical.
//! - **The override reaches the backend constructor (D173 §2 R4's
//!   consumer-level test).** The gate's refusal counts the peers it refused,
//!   so the number in the message is the number the constructor was handed:
//!   one with a one-entry override, the vendored list's size without one. A
//!   merge would show their sum.
//!
//! NON-SECRET: the passphrase is a documented fixture; no key is written
//! anywhere but the vault `init` creates for each row.

#![cfg(feature = "ant-backend")]

#[path = "common/spawn.rs"]
mod spawn;

use std::collections::BTreeMap;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::Stdio;

use antseal_cli::upgrade_hook::{HOOK_ARMED, HOOK_NOT_ARMED};
use antseal_net::arbitrum_one_vendored_peers;
use antseal_net::network::storage_gate;
use sha2::{Digest as _, Sha256};

/// The passphrase every vault here is created with (an `init` floor-length
/// fixture; non-secret).
const PASSPHRASE: &[u8] = b"a long enough fixture passphrase\n";

/// The traces these rows read: D42's hook says whether the invocation
/// unlocked a vault; the backend's debug trace says whether a read-only
/// connection was attempted.
const HANDLER_LOG: &str = "antseal_cli::upgrade_hook=debug,antseal_cli::backend=debug";

/// `connect_read_only`'s one trace, emitted inside its future — so only when
/// a connection is actually attempted.
const READER_CONNECT_TRACE: &str = "connecting the read-only reader";

struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "antseal-peer-resolution-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        std::fs::create_dir_all(&path).expect("create scratch");
        Self(path)
    }

    fn join(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct Spawned {
    code: Option<i32>,
    stdout: String,
    stderr: String,
}

impl Spawned {
    /// The one `--json` document on stdout.
    fn document(&self) -> serde_json::Value {
        serde_json::from_str(self.stdout.trim_end_matches('\n')).unwrap_or_else(|error| {
            panic!(
                "stdout is not one JSON document ({error}).\nstdout:\n{}\nstderr:\n{}",
                self.stdout, self.stderr
            )
        })
    }

    fn error_message(&self) -> String {
        let document = self.document();
        document["error"]["message"]
            .as_str()
            .unwrap_or_else(|| panic!("an error message: {document}"))
            .to_owned()
    }
}

/// Spawn `antseal <args>` over the vault at `vault_root`, from `cwd`, with
/// the storage gate armed, `devnet_env` as the only devnet definition it can
/// see (`None` strips any the developer's shell exported), and `stdin`
/// written to its standard input (`None` closes it).
fn run(
    vault_root: &Path,
    cwd: &Path,
    args: &[&str],
    devnet_env: Option<&Path>,
    stdin: Option<&[u8]>,
) -> Spawned {
    let mut command = spawn::antseal();
    command
        .args(args)
        .env("ANTSEAL_DIR", vault_root)
        .env("RUST_LOG", HANDLER_LOG)
        // D173 §2 R9: the debug-build arm already arms the gate in a test
        // binary; naming it here makes the row's precondition visible and
        // keeps it true under any profile.
        .env(storage_gate::ENV, "1")
        .current_dir(cwd)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    match devnet_env {
        Some(path) => {
            command.env("ANTSEAL_DEVNET_ENV", path);
        }
        None => {
            command.env_remove("ANTSEAL_DEVNET_ENV");
        }
    }
    match stdin {
        Some(bytes) => {
            command.stdin(Stdio::piped());
            let mut child = command.spawn().expect("spawn antseal");
            // A write failure is ignored on purpose: a build that refuses
            // before reading its input exits first and closes the pipe.
            let _ = child
                .stdin
                .as_mut()
                .expect("stdin is piped")
                .write_all(bytes);
            drop(child.stdin.take());
            let out = child.wait_with_output().expect("wait for antseal");
            Spawned {
                code: out.status.code(),
                stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
                stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
            }
        }
        None => {
            command.stdin(Stdio::null());
            let out = command.output().expect("spawn antseal");
            Spawned {
                code: out.status.code(),
                stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
                stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
            }
        }
    }
}

/// A vault created by the real `init`, in machine mode, with a generated
/// wallet key — so a `seal` that gets past resolution has a key to sign
/// with and reaches the backend constructor.
fn init_vault(scratch: &Scratch) -> PathBuf {
    let root = scratch.join("vault");
    let run = run(
        &root,
        &scratch.0,
        &["--json", "--passphrase-fd", "0", "init"],
        None,
        Some(PASSPHRASE),
    );
    assert_eq!(run.code, Some(0), "init: stderr:\n{}", run.stderr);
    assert!(root.join("vault.header").exists(), "init wrote the vault");
    root
}

/// Every file under `root`, by relative path, with its length and SHA-256.
fn fingerprint(root: &Path) -> BTreeMap<String, (u64, [u8; 32])> {
    fn walk(root: &Path, dir: &Path, out: &mut BTreeMap<String, (u64, [u8; 32])>) {
        for entry in std::fs::read_dir(dir).expect("read the vault directory") {
            let path = entry.expect("a directory entry").path();
            if path.is_dir() {
                walk(root, &path, out);
                continue;
            }
            let bytes = std::fs::read(&path).expect("read a vault file");
            let relative = path
                .strip_prefix(root)
                .expect("under the root")
                .to_string_lossy()
                .into_owned();
            out.insert(
                relative,
                (bytes.len() as u64, Sha256::digest(&bytes).into()),
            );
        }
    }
    let mut out = BTreeMap::new();
    walk(root, root, &mut out);
    out
}

/// A `devnet` export that reaches **nothing**: its one peer is a loopback
/// UDP port bound and released a moment ago, its RPC a loopback TCP port
/// likewise. Chain 31337 with Anvil's deterministic contracts (non-secret;
/// no wallet line — the vault's key signs).
fn dead_devnet_export(dir: &Path) -> PathBuf {
    let udp = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind a loopback probe socket");
    let bootstrap = udp.local_addr().expect("the probe's address");
    drop(udp);
    let tcp = std::net::TcpListener::bind("127.0.0.1:0").expect("bind a loopback probe listener");
    let rpc_port = tcp.local_addr().expect("the probe's address").port();
    drop(tcp);
    let text = format!(
        "# antseal devnet environment: a dead one, for a control\n\
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

/// The gate's count line for a set of `n` refused peers, as
/// `StorageGateRefusal`'s `Display` renders it.
fn refused_count(n: usize) -> String {
    format!("{n} of {n} bootstrap peer(s) are not loopback")
}

/// **D173 §2 R7 (S40 Accept row 1, restated): a network with no peers is
/// refused by `seal` with usage 2 before any passphrase is read, and no
/// vault file but the lockfile changes.**
///
/// `arbitrum-sepolia` with `ANTSEAL_DEVNET_ENV` unset is a production-
/// reachable empty peer set, so the row needs no plant. The discriminator is
/// exit 11: in machine mode with no `--passphrase-fd`, a handler that
/// collected the passphrase before resolving peers cannot collect one and
/// says so with `passphrase-unavailable`. The control proves the row can see
/// past the gate: the same vault, with a definition that has peers, is
/// unlocked (the hook arms) and fails only at its dead network.
#[test]
fn seal_refuses_a_network_with_no_peers_before_any_passphrase_and_touches_only_the_lockfile() {
    let scratch = Scratch::new("before-passphrase");
    let vault = init_vault(&scratch);
    std::fs::write(scratch.join("note.txt"), b"a note to seal\n").expect("write the input");
    let before = fingerprint(&vault);
    assert!(
        before.contains_key("vault.header") && before.contains_key("config.toml"),
        "the fingerprint reads the vault it is about to compare: {:?}",
        before.keys().collect::<Vec<_>>()
    );

    let refused = run(
        &vault,
        &scratch.0,
        &[
            "--json",
            "--network",
            "arbitrum-sepolia",
            "seal",
            "note.txt",
        ],
        None,
        None,
    );
    assert_eq!(
        refused.code,
        Some(2),
        "seal must refuse missing peers before collecting a passphrase: expected exit 2, got \
         {:?} (11 is passphrase-unavailable — the passphrase was asked for first). stderr:\n{}",
        refused.code,
        refused.stderr
    );
    let document = refused.document();
    assert_eq!(
        document["error"]["class"],
        serde_json::json!("usage"),
        "{document}"
    );
    let message = refused.error_message();
    for fragment in [
        "arbitrum-sepolia",
        "scripts/devnet/sepolia-up",
        "ANTSEAL_DEVNET_ENV",
        "no public Autonomi storage network on Arbitrum Sepolia",
    ] {
        assert!(
            message.contains(fragment),
            "the refusal names `{fragment}`: {message}"
        );
    }
    assert!(
        refused.stderr.contains(HOOK_NOT_ARMED) && !refused.stderr.contains(HOOK_ARMED),
        "refused BEFORE the passphrase: no vault was unlocked. stderr:\n{}",
        refused.stderr
    );

    let after = fingerprint(&vault);
    let changed: Vec<&String> = before
        .iter()
        .filter(|(path, digest)| after.get(*path) != Some(digest))
        .map(|(path, _)| path)
        .chain(after.keys().filter(|path| !before.contains_key(*path)))
        .collect();
    assert!(
        after.contains_key("vault.lock"),
        "the single-writer lock was taken (U5): {:?}",
        after.keys().collect::<Vec<_>>()
    );
    assert!(
        changed.iter().all(|path| path.as_str() == "vault.lock"),
        "a refused seal changes no vault file but the lockfile; changed: {changed:?}"
    );

    // CONTROL: a definition with peers gets past resolution — the vault is
    // unlocked (the hook arms) and the run fails only at its dead network,
    // in the network class, so the row above can tell "refused at
    // resolution" from "refused at anything".
    let dead = dead_devnet_export(&scratch.0);
    let control = run(
        &vault,
        &scratch.0,
        &[
            "--json",
            "--network",
            "devnet",
            "--passphrase-fd",
            "0",
            "seal",
            "note.txt",
        ],
        Some(&dead),
        Some(PASSPHRASE),
    );
    assert_eq!(
        control.code,
        Some(23),
        "the control proceeds past resolution to its dead network: stderr:\n{}",
        control.stderr
    );
    assert!(
        control.stderr.contains(HOOK_ARMED),
        "the control unlocked the vault — resolution passed. stderr:\n{}",
        control.stderr
    );
}

/// **D173 §2 R4's consumer-level test, and §2 R6's replace-not-merge
/// through the binary.** The `NetworkConfig` handed to the backend
/// constructor carries exactly the override's peers: the storage gate,
/// armed, refuses the constructor's set and counts it — one with a
/// one-entry override, the vendored list's size without one, and never
/// their sum.
#[test]
fn the_backend_constructor_is_handed_exactly_the_override_peers_never_a_merge() {
    let scratch = Scratch::new("override");
    let vault = init_vault(&scratch);
    std::fs::write(scratch.join("note.txt"), b"a note to seal\n").expect("write the input");
    let vendored = arbitrum_one_vendored_peers().len();
    assert!(
        vendored >= 2,
        "the vendored list must hold several peers for a merge to be distinguishable"
    );

    // RFC 5737 documentation address: never routed, and refused by the
    // armed gate before any socket.
    std::fs::write(
        vault.join("config.toml"),
        "default_network = \"arbitrum-one\"\n\n[networks.arbitrum-one]\nbootstrap = \
         [\"192.0.2.10:10000\"]\n",
    )
    .expect("write the override");
    let argv = ["--json", "--passphrase-fd", "0", "seal", "note.txt"];
    let with_override = run(&vault, &scratch.0, &argv, None, Some(PASSPHRASE));
    assert_eq!(
        with_override.code,
        Some(23),
        "the armed gate refuses the override in the network class: stderr:\n{}",
        with_override.stderr
    );
    let message = with_override.error_message();
    assert!(
        message.contains(storage_gate::REFUSAL),
        "the refusal is the storage gate's: {message}"
    );
    assert!(
        message.contains(&refused_count(1)),
        "the backend config built from the override carries exactly its one peer, got: {message}"
    );
    assert!(
        !message.contains(&refused_count(vendored + 1)),
        "the override must replace the vendored list, never be merged with it: {message}"
    );
    assert!(
        with_override.stderr.contains(HOOK_ARMED),
        "the vault was unlocked before the constructor ran. stderr:\n{}",
        with_override.stderr
    );

    // The same vault without the key: the vendored list, whole.
    std::fs::write(
        vault.join("config.toml"),
        "default_network = \"arbitrum-one\"\n",
    )
    .expect("drop the override");
    let built_in = run(&vault, &scratch.0, &argv, None, Some(PASSPHRASE));
    assert_eq!(built_in.code, Some(23), "stderr:\n{}", built_in.stderr);
    let message = built_in.error_message();
    assert!(
        message.contains(&refused_count(vendored)),
        "without an override the constructor is handed the vendored list ({vendored} peers): \
         {message}"
    );
}

/// **D173 §2 R7 for `verify --live` (D170 §2 R6's precedent).** A network
/// with no peers is a usage error (2) **before verification**: the bundle is
/// a tampered one, so a handler that verified first would have answered 40,
/// and the control without `--live` shows that it does. Nothing is
/// connected.
#[test]
fn verify_live_refuses_a_network_with_no_peers_before_verification() {
    use antseal_core::test_util::bundle_fixtures::{Selection, Tweak, build_tweaked, shapes};

    let scratch = Scratch::new("verify-live");
    let mut tweak = Tweak::none();
    tweak.corrupt_canon_commit = Some(0);
    let tampered = build_tweaked(
        &shapes::single_text_with_mirror(),
        &Selection::all(1),
        &tweak,
    )
    .bytes;
    let bundle = scratch.join("t.sealproof");
    std::fs::write(&bundle, &tampered).expect("write the bundle");
    let path = bundle.to_str().expect("a utf-8 scratch path");
    // No vault is needed, and none exists at this root.
    let no_vault = scratch.join("no-vault-here");

    let refused = run(
        &no_vault,
        &scratch.0,
        &[
            "--json",
            "--network",
            "arbitrum-sepolia",
            "verify",
            path,
            "--live",
        ],
        None,
        None,
    );
    assert_eq!(
        refused.code,
        Some(2),
        "no peers is a usage error before verification: stderr:\n{}",
        refused.stderr
    );
    assert_eq!(refused.document()["error"]["class"], "usage");
    let message = refused.error_message();
    for fragment in ["scripts/devnet/sepolia-up", "ANTSEAL_DEVNET_ENV"] {
        assert!(message.contains(fragment), "`{fragment}`: {message}");
    }
    assert!(
        !refused.stderr.contains(READER_CONNECT_TRACE),
        "nothing was connected. stderr:\n{}",
        refused.stderr
    );

    // CONTROL: the same bundle without `--live` is its own rejection, so the
    // 2 above came first rather than instead.
    let control = run(
        &no_vault,
        &scratch.0,
        &["--json", "--network", "arbitrum-sepolia", "verify", path],
        None,
        None,
    );
    assert_eq!(
        control.code,
        Some(40),
        "the tampered bundle is rejected on its own when nothing refuses first: stderr:\n{}",
        control.stderr
    );
}
