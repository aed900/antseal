# Foreign-node interop runbook (S41, D177)

> **Status.** First run 2026-10-16, against ant-node **v0.23.0** (the latest
> non-prerelease that day, published hours before the run) after a green
> v0.15.0 control arm: **PASS**, 4 suites and 29 tests in each arm, both
> stage-0 rehearsals PASS. The verdict line is recorded verbatim on `S41` in
> `tasks/S.md`; this page keeps the procedure and the measurements.

**The question** (`S41`, [D173](../decisions/D173-mainnet-peers-are-upstreams-published-bytes-and-no-test-can-dial-them.md) §2 R17):
can antseal's **pinned** client (`ant-core =0.5.0`) quote, pay, store, fetch
and restore against the `ant-node` release the network actually runs? The
network's nodes upgrade themselves to upstream's latest non-prerelease within
about a day, while antseal moves its pin only as a deliberate event (project
rule 2).

**Why `devnet-launcher` cannot answer it.** The launcher runs its nodes
in-process through ant-core 0.5.0's `devnet` feature, which links
`ant-node ^0.15.0` (ant-core 0.5.0 `Cargo.toml.orig:68`; upstream's own
comment says a version skew makes the two crates' `MultiAddr` types
incompatible), and ant-node 0.22.0 needs rustc 1.95 against the pinned
1.92.0 ([D177](../decisions/D177-the-pinned-client-meets-the-signed-node-release-on-loopback-and-stage-0-has-one-strict-predicate.md) §2 R1).

**What answers it.** Upstream's **released, signed** `ant-node` binary — the
bytes the fleet installs — run as 14 processes plus Anvil inside unprivileged
namespaces whose only network interface is `lo`, with the repository's own
four devnet suites pointed at them through a hand-written export, and the
v0.15.0 release run first as a **control arm** under the identical harness.
Nothing upstream is built; no product or launcher code changes (D177 §2
R2–R4).

## What a green proves, and what it does not

| Proves | Does not prove |
| --- | --- |
| The pinned client's quote, payment, store, fetch and restore paths work against N loopback nodes of the named release, paying through the pinned `evmlib` contracts on Anvil | What mainnet runs today (inferred from the upgrade monitor's rule, never dialed) |
| The node release accepts the client's legacy `QuoteRequest` variant and its payment proofs, with distinct rewards addresses so the node's redirection check can fail | Transport behaviour across real NATs, real latency, or a hostile peer |
| The stage-0 predicate behaves on a live loopback fleet (PASS) and on a dead RPC and dead nodes (STOP) | Operator settings such as `ANT_PRICE_FLOOR_ENFORCE`, or client/node disagreement about issuer closeness — neither is testable on 14 loopback nodes |

The residual risk the reading names is the transport: about 4,200 changed
code lines in `saorsa-transport` between the pin and the release, unread
(D177 §2 R8).

## Hazards of the released binary

Read from ant-node's source at v0.22.0 (D177 §1.4; paths under `src/`); each
one would reach the public network or the operator's files if the binary ran
unconfined:

| Default behaviour | Where | What closes it here |
| --- | --- | --- |
| Bootstrap peers auto-discovered: `ANT_BOOTSTRAP_PEERS_PATH`, then **the file next to the executable** (`bootstrap_peers.toml`, 7 public peers ship in the archive), then XDG config, then `/etc/ant` | `config.rs:670-682` (`discover()`: a set variable returns at once, found or not), `:703-730` (the search order) | the namespace (no route); only the `ant-node` member is extracted; `ANT_BOOTSTRAP_PEERS_PATH` names a file that does not exist, which ends discovery |
| `--evm-network` defaults to `arbitrum-one` | `bin/ant-node/cli.rs:77-83` | the namespace; `--evm-rpc-url` + token + vault select the loopback Anvil |
| An upgrade monitor polls `api.github.com` hourly, 24 h rollout, **no off switch** (`UpgradeConfig` has no `enabled` field) | `node.rs:153-156`, `upgrade/monitor.rs:352`, `config.rs:288-319, 536-542` | the namespace; `--stop-on-upgrade` (a found upgrade would exit the node, which the liveness check reports, rather than replace it) |
| The upgrade cache lives under `$XDG_DATA_HOME/ant/upgrades` | `upgrade/cache_dir.rs:21-27` | `HOME` and every `XDG_*` point into the node's own directory |
| A rewards address is required even in development mode | `node.rs:548-552` | a **distinct** Anvil account per node |

Flags are a second layer. The guarantee is the namespace, proven inside
before anything starts.

## The layers, and why each is there (measured 2026-10-16)

D177 §2 R2 ruled a user + network namespace, and its amendment a mount
namespace hiding the operator's secrets. Building it showed that a mount
mask alone leaves three doors open, so the harness adds the layers below.
Each row was measured on the development host before the layer was added.

| Layer | What it closes | Measurement |
| --- | --- | --- |
| Network namespace | Egress. The only link is `lo`; both main route tables are empty | `links=[lo] routes4(main)=[] routes6(main)=[] egress4=ENETUNREACH egress6=ENETUNREACH loopback=ECONNREFUSED` |
| User namespace | Reaching the operator's processes' filesystems through `/proc/<pid>/root` | With no PID namespace, the traversal was refused: `ls: cannot access '/proc/<pid>/root': Permission denied` (the kernel's cross-user-namespace ptrace rule) |
| PID namespace | Seeing and signalling the operator's processes | Without it: 262 host PIDs visible, the operator's command lines readable, `kill -0` on the operator's shell **permitted**. With it: 4 PIDs, none of that |
| Masks on `/tmp`, `/var/tmp`, `/dev/shm`, `/run/user/<uid>` | Path-named Unix sockets — **a network namespace does not isolate them** | A socket listening in the scratch area outside was **connectable** from inside the network namespace; after masking `/tmp`, not even its directory was reachable. On the host, `/run/user/<uid>` holds the session bus, the gnupg and keyring agents and terminal IPC sockets, and `SSH_AUTH_SOCK` was set |
| Home mask | The ruled secrets, and everything else in the home | The whole home becomes an empty tmpfs; only named paths are bound back (below) |
| No capabilities for any workload | A workload unmounting a mask | `setpriv --bounding-set=-all --inh-caps=-all --ambient-caps=-all --no-new-privs`; `umount /tmp` fails for every workload, proven in each run |
| A nested view for the nodes | The nodes writing code the operator runs later: `~/.cargo/bin`, the repository's scripts and `.git/hooks` | The node view re-masks the home with **only** the nodes' directory (rw) and the binary (ro) bound back; the repository, the cargo home and the controller's results are absent, proven from outside the view |
| `env -i` for every workload | Inherited agent sockets, bus addresses and tokens | No workload sees the operator's environment |

What remains, named rather than hidden: the kernel is shared (a kernel
exploit escapes any namespace); world-readable system files (`/etc`, `/usr`)
stay visible; the controller's view (not the nodes') keeps the repository,
`~/.cargo` and `~/.rustup`, because the suites need cargo.

## One arm, in order

Each arm (control, then subject) runs the same sequence. Every step's
refusal stops the arm before the next step starts.

1. **Identity, outside the namespace.** The archive's sha256 must equal its
   line in `SHA256SUMS.txt`, the digest GitHub's release API reports, and —
   for a tag this script knows — the digest it pins. The release must be
   neither a draft nor a prerelease. The key embedded in `signature.rs` at
   the tag must hash to the pinned key digest, under the pinned context. The
   signature must verify (below). Only then is the `ant-node` member — and
   nothing else — extracted.
2. **Enter** user + network + mount + PID + IPC + UTS namespaces, unprivileged.
3. **Prove isolation first**, before any parameter is read: links `[lo]`,
   both main route tables empty, then a socket probe (egress unreachable on
   both families, loopback refusing). Anything else: `REFUSED
   reason=NOT-ISOLATED`, exit 3, nothing started.
4. **Canary positive control.** A random canary under `/tmp` must be
   readable before masking, or its unreadability afterwards would prove
   nothing.
5. **Mask, then prove the controller's view** (the probe's lines below).
6. **Anvil and the contracts** (capability-free workloads), with on-chain
   assertions.
7. **The node view**: a nested mount + PID namespace masks again, keeping only
   the nodes' directory and the binary. The controller proves that view
   from outside it (`nsenter`), and checks `ant-node --version` against the
   tag, **before** any node starts.
8. **Fourteen nodes**, readiness, then stabilization.
9. **The export**, the four suites, the stage-0 rehearsal.
10. **Liveness** of every node, the node view **re-proven** after the
    suites, teardown. When the controller exits, the kernel kills everything
    left in its PID namespace.

## Masking: what is hidden, and the proof

The home becomes an empty tmpfs. Bound back into the controller's view: the
repository (rw), the cargo home (rw, with `~/.cargo/credentials` and
`~/.cargo/credentials.toml` overlaid by `/dev/null`), the rustup home (rw),
the foundry bin directory (ro) and the run directory (rw). Bound back into
the node view: the nodes' directory (rw) and the binary (ro), nothing else.
`/tmp`, `/var/tmp`, `/dev/shm` and `/run/user/<uid>` are empty tmpfs in both
views. The mask root is never itself a bind-back: a spec that equals or
contains a mask root is refused before anything is mounted.

`--probe-namespace` runs exactly this and starts no node and no chain. Its
lines on the development host, 2026-10-16 (`~` is the operator's home; the
real paths are printed in the run's evidence):

```
isolation: links=[lo] routes4(main)=[] routes6(main)=[] egress4=ENETUNREACH egress6=ENETUNREACH loopback=ECONNREFUSED
masking(l1): canary unreadable (it is readable outside)
masking(l1): ~/.minisign outside=present inside=absent
masking(l1): ~/.ssh outside=present inside=absent
masking(l1): ~/.gnupg outside=absent inside=absent
masking(l1): ~/.config/gh outside=present inside=absent
masking(l1): ~/.local/share/ant outside=present inside=absent
masking(l1): ~/.cargo/credentials outside=absent inside=absent
masking(l1): ~/.cargo/credentials.toml outside=present inside=masked(/dev/null)
masking(l1): the home shows [.cargo,.foundry,.rustup,Documents] (outside: 140 entries), all bind-backs
masking(l1): /run/user/<uid> empty (agent, bus and terminal sockets unreachable)
masking(l1): a workload cannot unmount a mask (no capabilities)
masking(l2): canary unreadable (it is readable outside)
masking(l2): ~/.cargo/credentials.toml outside=present inside=absent
masking(l2): the home shows [] (outside: 140 entries), all bind-backs
masking(l2): a workload cannot unmount a mask (no capabilities)
masking(l2): the repository, the cargo home and L1's results are invisible to the nodes
s41-interop: PROBE ok commit=fbcee1e — isolation and masking only; no node and no chain was started
```

(The six ruled paths print in both views; the `l2` lines omitted above read
the same as `l1`'s, except that `~/.cargo/credentials.toml` is absent rather
than overlaid, because the node view has no cargo home at all.)

## Signature verification (D177 §2 R12)

**The trust root** is the key compiled into the node itself:
`RELEASE_SIGNING_KEY` in `src/upgrade/signature.rs` at the release's tag —
independent of GitHub's release assets. The file is byte-identical at
v0.15.0 and v0.22.0, and the crates.io `ant-node` 0.22.0 crate carries the
same key: 1,952 bytes, sha256
`163f903d7b56cede4a049fe3eb871d8ac434b124059d992932f07f4ce1606643`, pinned in
the script. The crate's own `sign/release-signing-key.pub` is a **different**
key and does not verify the releases; never use it.

**The scheme** (`verify_binary_signature_with_key`, `signature.rs:203-233`):
pure ML-DSA-65 (FIPS 204) with the context string `ant-node-release-v1`,
over the whole archive file; the `.sig` asset is the 3,309-byte signature.

**Extracting the key** from a fetched `signature.rs`:

```
scripts/s41-interop.sh --extract-key <fetch-dir>/signature.rs release-key.bin
# key_sha256=163f903d… context=ant-node-release-v1 (pinned: 163f903d…) MATCH
```

**The verifier** is built out of tree — nothing cargo would read as a project
enters the repository (D177 §2 R12). Two files, in an empty directory of your
own:

`Cargo.toml`
```toml
[package]
name = "sigcheck"
version = "0.0.0"
edition = "2021"
publish = false

[dependencies]
fips204 = { version = "=0.4.6", default-features = false, features = ["ml-dsa-65"] }

[workspace]
```

`src/main.rs`
```rust
//! Verify an ant-node release archive's detached ML-DSA-65 signature
//! (FIPS 204, pure ML-DSA with a context string) against a raw public key.
//! Usage: sigcheck <pubkey.bin> <archive> <archive.sig> <context>
//! Exit 0 = VERIFY OK, 1 = VERIFY FAIL, 2 = usage or I/O error. No panics.
use fips204::ml_dsa_65::{PublicKey, PK_LEN, SIG_LEN};
use fips204::traits::{SerDes, Verifier};
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let [_, pk_path, msg_path, sig_path, ctx] = args.as_slice() else {
        eprintln!("usage: sigcheck <pubkey.bin> <archive> <archive.sig> <context>");
        return ExitCode::from(2);
    };
    let read = |p: &String| std::fs::read(p).map_err(|e| eprintln!("sigcheck: cannot read {p}: {e}"));
    let (Ok(pk), Ok(msg), Ok(sig)) = (read(pk_path), read(msg_path), read(sig_path)) else {
        return ExitCode::from(2);
    };
    let fail = |why: &str| {
        println!("VERIFY FAIL ctx={ctx:?} msg_len={} ({why})", msg.len());
        ExitCode::from(1)
    };
    let Ok(pk) = <[u8; PK_LEN]>::try_from(pk.as_slice()) else { return fail("public key length") };
    let Ok(sig) = <[u8; SIG_LEN]>::try_from(sig.as_slice()) else { return fail("signature length") };
    let Ok(pk) = PublicKey::try_from_bytes(pk) else { return fail("public key rejected") };
    if pk.verify(&msg, &sig, ctx.as_bytes()) {
        println!("VERIFY OK ctx={ctx:?} msg_len={}", msg.len());
        ExitCode::SUCCESS
    } else {
        fail("signature does not verify")
    }
}
```

Build it with its own target directory (one job, so it never competes with a
workspace build), and run its controls:

```
CARGO_TARGET_DIR="$PWD/target" cargo build --release --offline -j1
./target/release/sigcheck release-key.bin ant-node-cli-linux-x64.tar.gz ant-node-cli-linux-x64.tar.gz.sig ant-node-release-v1
# VERIFY OK ctx="ant-node-release-v1" msg_len=11226608     (v0.22.0; v0.15.0: msg_len=7452611)
```

`fips204 =0.4.6` is the version the workspace already locks (checksum
`c9fb5a36…0b15` in both lock files), so `--offline` builds from the local
registry. Measured 2026-10-16: 22.6 s on two CPUs, rustc 1.92.0.

**How the harness uses it.** It believes a verifier only if the verifier
can say no: the genuine archive must print exactly `VERIFY OK
ctx="ant-node-release-v1" msg_len=<archive size>`, and a copy with one
flipped byte and the wrong context must both print `VERIFY FAIL`. Anything
else is `REFUSED reason=SIGNATURE` before extraction. With no `--sigcheck`
the run refuses unless `--allow-unchecked-signature` is passed, and then
the verdict line says `sig=unchecked` — never `ok` on a digest match alone.

Measured controls, 2026-10-16: both archives `VERIFY OK`; a flipped byte,
the wrong context, the crate's `sign/` key and an empty signature all
`VERIFY FAIL`; the harness's own `--self-test` reproduces the flipped-byte
case against the real v0.22.0 archive.

## The contracts (D177 §2 R3)

Deployed with `cast` from the **pinned** `evmlib` 0.9.0 artifacts in the
local cargo registry (byte-identical to 0.10.0's; both files' sha256 are
pinned in the script), by Anvil's unlocked account 0 — no key on any command
line. **The two artifacts are in different formats**, and that is the trap:

| Artifact | Format | Creation bytecode at |
| --- | --- | --- |
| `AutonomiNetworkToken.json` | Hardhat | `.bytecode` (a hex string) |
| `PaymentVaultV2.json` | Foundry | `.bytecode.object` |

Reading the token with `.bytecode.object` yields nothing, and `cast` then
deploys an empty contract without complaint; reading the vault with
`.bytecode` yields an object, not code. The harness branches on the type,
refuses anything that is not non-empty hex, and asserts on chain:

```
deploy: token 0x5fbdb2315678afecb367f032d93f642f64180aa3 vault 0xe7f1725e7734ce288f8367e1bb143e90bb3f0512 (evmlib 0.9.0 artifacts, sha256 pinned)
deploy: token code bytes: 7889
deploy: vault code bytes: 3937
deploy: token.balanceOf(payer)=2500000000000000000000000 vault.antToken()=token vault.batchLimit()=512
rewards: 14 of 14 distinct, none is the payer
```

(The addresses are deterministic on a fresh Anvil: account 0's nonces 0 and 1.)

## The export

A hand-written ten-key file in the launcher's key order
(`crates/devnet-launcher/src/export.rs`), read by the suites and the CLI
through `ANTSEAL_DEVNET_ENV`: the Anvil RPC, chain 31337, the two contract
addresses, account 0's key (Anvil's public constant, read from Anvil's own
`--config-out` file and never echoed), the fourteen `127.0.0.1:<port>`
bootstrap addresses, the node count, the base port, the nodes' data
directory, and as `ANTSEAL_DEVNET_PID` the node namespace's process, so the
suites' stale-export guard (`/proc/<pid>` must exist) watches the fleet
itself. The export lives in the controller's results directory, which the
node view cannot see.

## The fleet

Every node runs with an empty environment except `HOME` and every `XDG_*`
inside its own directory, `ANT_BOOTSTRAP_PEERS_PATH` naming a file that does
not exist, and `ANT_DISABLE_WEBRTC_DIRECT=true` — **`true`, not `1`**: the
variable feeds clap's boolean `--disable-webrtc-direct`, and v0.22.0 exits at
once on `1` (*"invalid value '1' for '--disable-webrtc-direct' [possible values:
true, false]"*, measured 2026-10-16; v0.15.0 has no WebRTC listener and ignores
the variable). The flags are the set both versions accept:

```
--root-dir <node>/root --port <20001..20014> --ipv4-only --network-mode development
--metrics-port 0 --rewards-address <Anvil account i> --evm-rpc-url http://127.0.0.1:18545/
--evm-payment-token <token> --evm-payment-vault <vault>
--enable-logging --log-format json --log-level info --stop-on-upgrade [--bootstrap 127.0.0.1:2000{1,2,3}]
```

Upstream's own devnet shape (`src/devnet.rs`): three bootstrap nodes with no
peers, then the other eleven bootstrapping from those three, 200 ms apart.
v0.15.0 differs from v0.22.0 only by lacking the four `--webrtc-direct-*`
flags.

**Ready** means every node logged `Node running, waiting for shutdown signal`
(`src/node.rs`, the last line before the event loop). **Stable** means every
node then logged at least three distinct `Added peer <id> to DHT routing
table` lines — upstream's own stabilization rule, a minimum of three
connections per node. No suite sees the export before both hold. The node's
first log line carries its build commit (`"message":"ant-node
starting","version":"0.15.0","commit":"c8b01de"`); that is self-reported and
recorded as `node_commit=`; the archive digest and the signature are the
identity proof.

## The suites (D177 §2 R6)

The rows `scripts/e2e-devnet.sh --list-suites` marks live — S6-S8
(`antseal-net`, `devnet_backend`), S17 (`e2e_devnet`), S18
(`e2e_kill_resume`), S19 (`e2e_restore`), all `--features ant-backend`. They
are **pre-built outside** the namespace in exactly the environment they run
in inside, then run inside, capability-free, with `CARGO_NET_OFFLINE=true`.
A suite counts only if it exits 0, prints **no `SKIP:` line** (the suites
print `SKIP:` and return `Ok` when the export is missing, unparseable or names
a dead process), fails and ignores nothing, and its pass count equals what
`cargo test -- --list` enumerates at the run's commit (never a number taken
from a record).

## Stage 0, rehearsed (D177 §2 R10)

After the suites, each arm runs `scripts/stage0.sh --rehearse` against its
own fleet: a throwaway vault on account 0's key, a small smoke file, and
three time-boxed `seal --dry-run --json` arms judged by the one strict
predicate — **dead RPC** (the export's RPC rewritten to a port nothing
listens on) must STOP with exit 23 and the message *payment RPC unreachable
(eth_chainId)*; **dead nodes** (the bootstrap list rewritten to ports no node
holds) must STOP, exit 23 or the time box; **live** must PASS. A timeout is a
STOP. The script's `--gate` mode — arbitrum-one, the released binary, the
maintainer's typed consent — is written and never run here.

## The control arm (D177 §2 R4)

v0.15.0, the version the client was developed against, runs **first** under
the identical harness. A red control means the harness is broken, not the
client: the run prints `control arm (ant-node v0.15.0) FAILED — harness
defect, no S41 verdict`, exits 2, and does not start the subject arm. Only a
green control lets the subject's result become the S41 verdict.

## Running it

Never concurrently with the local gate or another build: the run pre-builds
the suites, and fourteen nodes plus four suites contend for the same CPUs.

```
# 1. Fetch both releases (read-only GETs; each into a new, empty directory).
scripts/s41-interop.sh --fetch v0.15.0 <dir>/v0.15.0
scripts/s41-interop.sh --fetch latest  <dir>/latest       # prints N and the ant-core lag

# 2. Build the verifier out of tree (above), then prove the harness can go red.
scripts/s41-interop.sh --self-test --sigcheck <sigcheck> --archive-dir <dir>/latest
scripts/stage0.sh --self-test

# 3. Optional: the namespace alone, then one fleet without suites.
scripts/s41-interop.sh --probe-namespace
scripts/s41-interop.sh --boot-only --node-dir <dir>/latest --sigcheck <sigcheck> --hold 45

# 4. The run: control arm, subject arm, verdict.
scripts/s41-interop.sh --control-dir <dir>/v0.15.0 --subject-dir <dir>/latest --sigcheck <sigcheck>
```

Evidence lands in `target/s41-interop/<UTC>-<commit>/` unless `--run-dir`
says otherwise: one directory per arm with `results/` (identity, isolation,
masking, deploy, boot, suites, stage 0, logs) and `nodes/` (each node's log).
**`results/anvil.json` and `results/devnet.env` hold Anvil's dev keys** —
public constants, still key-shaped: never paste them into a record. Every
capture that reaches the terminal goes through the same key-name redaction
as `scripts/e2e-devnet.sh`.

**Cost**, estimated from the hosted devnet E2E (the four suites took 487 s on
four vCPUs; run 38550457695) and the boots measured below: boot and
stabilization take seconds; the suites likely 12–20 min per arm on two CPUs;
stage 0 up to three five-minute time boxes, though only the dead-nodes arm
should come near one. That makes 20–30 min per arm and 40–60 min for both.
A cold pre-build adds 20–40 min, a warm one 2–5. Idle, the fourteen nodes
used about 300–400 MiB of RAM in total at v0.15.0 and about 510 MiB at
v0.22.0. Logs: 3 MiB in the first 50 s at v0.15.0, but 17.7 MiB in under a
minute at v0.22.0 — budget hundreds of MiB per subject arm once the suites
run (not measured yet).

## Reading the result

The verdict line, recorded verbatim on `S41`, `Q34` and in
`docs/threat-model.md` §2.11 (D177 §2 R7):

```
s41-interop: <PASS|FAIL> commit=<sha7> client=ant-core-0.5.0 node=ant-node-<tag> node_commit=<…> archive_sha256=<…> sig=<ok|unchecked> nodes=<live> suites_run=4 tests=<n> skipped=0 failed=[…] control=<PASS|FAIL>(ant-node-v0.15.0) netns=isolated anvil=<ver> secs=<n> date=<UTC>
```

followed by one notes line: N and the `ant-core` lag, the control's test
count, the masks, both arms' stage-0 rehearsal results and the evidence
directory. `client=` is read from `Cargo.lock`, not typed.

| Exit | Meaning |
| --- | --- |
| 0 | PASS: control green, subject green |
| 1 | FAIL: control green, subject red — **the S41 red** |
| 2 | Harness defect: control red; no S41 verdict, the subject was not run |
| 3 | REFUSED before any node started: isolation, masking, digest, key, signature or preflight; the reason is named |

**Reading a red.** With a green control, a red subject is the client and the
release disagreeing. The planning round pre-registered the signatures a
reading of the code predicts will **not** appear; search the suite logs and
the subject's node logs for each before anything else:

- `was redirected: recorded rewards address prefix` — the node's redirection
  check (payment credited to an address other than its own);
- `was not paid enough` — pricing or median disagreement;
- `is not among this node's local K=` — close-group disagreement;
- `ClientUpdateRequired` — a client-version policy applied to the legacy
  request.

If none appears, the residual named in advance is the transport. A
`SKIP:` line, a count below `--list`, or a dead node is a FAIL of its own
kind and is named in `failed=[…]` or in the arm's lines.

## N, and the lag

**N** is the number of non-prerelease `ant-node` releases after the dev pin
v0.15.0: **11** at the first run (v0.16.0 through v0.23.0; v0.23.0 was
published at 02:27Z on 2026-10-16, which moved N from 10 to 11 and the
subject from v0.22.0 to v0.23.0 between planning and the run — prereleases
never count, and the upgrade monitor never installs one). The **ant-core
lag** beside it is **10** (0.5.1 through 0.13.0, none yanked). `--fetch`
recounts both from the releases API and the crates.io index each time, and
the run's subject is whatever is latest when it starts.

## What a red costs (D177 §2 R9)

A red makes a deliberate pin bump a prerequisite of `Q34` (project rule 5:
survey, pinning, devnet E2E). It does not come alone: `ant-core` 0.12.0
requires `saorsa-transport` 0.38.0, which requires **rustc 1.95.0**, so the
toolchain pin moves 1.92.0 → ≥ 1.95.0 in the same act. The same bump changes
licences: `saorsa-core` 0.26.2 (AGPL-3.0), `evmlib` 0.9.0 and
`self_encryption` 0.36.0 (GPL-3.0) are replaced by `saorsa-core` 0.29.0,
`evmlib` 0.10.0 and `self_encryption` ≥ 0.36.1, all MIT OR Apache-2.0, so
`deny.toml`'s copyleft exceptions shrink.

## Not established

- **A mixed-version fleet** — old and new nodes together, as mainnet is
  during a release's 24-hour rollout; every run here is one version.
- Why a few nodes' **replication** rejects forwarded proofs of payment, and
  what that costs in replication depth (first run: `WARN
  ant_node::replication` *"PoP verification error for [paid notify] key
  …"*, carrying the pre-registered phrases *"is not among this node's local
  K=… closest peers"* with *"was not paid enough"* at v0.15.0 or *"was
  redirected: recorded rewards address prefix …"* at v0.23.0 — 334 lines
  over 55 records from 5 nodes in the control, 77 over 15 from 3 in the
  subject; none reached the client, every suite passed).
- What mainnet runs — inferred from the monitor's rule, never dialed.
- Whether a partial `[upgrade]` table in a config file is accepted (the
  harness passes no config file).
- Operators' `ANT_PRICE_FLOOR_ENFORCE`; client/node disagreement about
  issuer closeness.

## Measurements (2026-10-16, development host, two CPUs)

| What | Result | Load average |
| --- | --- | --- |
| `--probe-namespace` | isolation and both views proven; no node, no chain | — |
| `--boot-only` v0.15.0 | 14 of 14 ready 4 s after start; 14 alive after a 45 s hold; nodes' RSS about 300 MiB in total; 3 MiB of logs | 6.25 at start (other builds running) |
| DHT peers per node, v0.15.0, after the hold | 11–13 distinct (the maximum is 13) | — |
| `--boot-only` v0.22.0, first attempt (`ANT_DISABLE_WEBRTC_DIRECT=1`) | all 14 nodes exited at once: *"invalid value '1' for '--disable-webrtc-direct'"*; the harness then waited out its readiness timeout. Since fixed: the variable is `true`, and a node that exits before the fleet is ready now fails the wait at once, quoting its first lines | 1.61 |
| `--boot-only` v0.22.0 | 14 of 14 ready 6 s after start; stable (every node ≥ 3 DHT peers; fewest 11) 1 s later; node claims `version=0.22.0 commit=008d2ad` (the tag's commit); the export written; 14 alive after a 45 s hold; nodes' RSS about 510 MiB; **17.7 MiB of logs in under a minute** | 4.07 at ready (another lane's tests running) |
| `--boot-only` v0.15.0, second run, with the liveness plant | 14 of 14 ready in 4 s, stable 1 s later (fewest 11); claims `version=0.15.0 commit=c8b01de` (the tag's commit); node 7 killed with `kill -9` from outside during the hold → `node 7 (pid 570) exited during the run`, `nodes_live=13` | 3.18 |
| The first run (control v0.15.0, subject v0.23.0) | PASS: per arm 4 suites, 29 of 29 tests (= `--list`), 0 SKIP, 14 nodes alive; boot 15 s / 5 s; stage 0 dead RPC → 23 in 1–2 s, **dead nodes → 23 in 8 s** (*"insufficient peers: Witnessed close group lookup failed before payment …"*), live → PASS in 5–7 s; nothing recompiled inside the namespace; `secs=1963` | 1.97 at launch; every other build held |
| `--self-test` (s41-interop) | 55 arms, 0 not run (with the verifier and an archive); 53 + 2 not run without them | — |
| `--self-test` (stage0) | 57 arms: the 4 committed seal envelopes, 31 mutations, 11 conjunct deletions, the refusals, and the rehearsal plumbing with a stub CLI | — |
