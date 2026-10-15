# Disk-loss restore drill (Q32 Do (c))

**Status: WRITTEN, NEVER EXECUTED.** This procedure has not been run by
anyone. Writing it is the closed half of Q32 Do (c); *executing* it and
*recording the walkthrough* is the OPEN half of Q32 Accept row 3
("procedures executable by a non-author — walkthrough recorded"), and that
half belongs to a future execution lane or the maintainer, after the
maintainer's P17 funding makes a Sepolia seal possible. Whether a run on a
Sepolia devnet's own host — the only venue a Sepolia-era work has, see
"Where the drill runs" — discharges that row is for `Q32` and `Q34` to
decide, not this document. Nothing in this document is evidence that a
restore drill has ever succeeded. The first execution will find wrong
assumptions; fix this document, then re-run — never adjust the evidence to
fit the document.

*Corrected 2026-09-15, still never executed* (D174 §2 R10, D175 §2 R12): the
restore step no longer passes `--network`; a Sepolia-era drill runs on the
devnet's own host, because no second machine can reach that devnet's nodes;
and `reveal` is named among the steps that need the network.

## What this drill proves (and what it does not)

The claim under test, in the row's own words: **a second clean machine
with nothing but the encrypted vault backup** can `vault import` →
`restore` → produce **byte-identical originals**, and `reveal` + `verify`
still work. Only a run against the public Autonomi network can test that
claim in full; a Sepolia-era run tests a narrower one (see "Where the drill
runs").

- "Nothing but the encrypted vault backup" means the export file plus the
  two things that are *knowledge*, not files: the vault **passphrase**
  (and the **keyfile**, only if the vault was created with
  `--wrap keyfile`). An export without its passphrase is designed to be
  useless — that is the vault's threat model working, not a drill failure.
- The drill needs **network access** for `restore` (it re-fetches the
  encrypted payloads), for `reveal` (a vault rebuilt from a backup holds the
  work's manifest but none of its encrypted units, so every unit of each
  file the selection touches is fetched), and for `verify --online`/`--live`
  if attempted. Nothing in this drill pays: restore, reveal, and verify are
  all unpaid operations. **No stage of this drill may spend funds.**
- Byte-identical is proven by comparison, never asserted: sha256 of every
  original (carried in the drill packet) against sha256 of every restored
  file, plus `cmp`. A verdict without both hash columns filled in is not
  a completed drill.

## Where the drill runs

The network the work was sealed on decides the venue, and the venue decides
what a PASS may claim (D174 §2 R10). The packet names the network (item 6).

| Work sealed on | Venue | What a PASS claims |
| --- | --- | --- |
| `arbitrum-one` — the public Autonomi network | a **second clean machine** | the claim above in full: recovery on a machine that never held the vault |
| `arbitrum-sepolia` — a Sepolia devnet | **the host running that Sepolia devnet**, under a fresh `ANTSEAL_DIR`, with `ANTSEAL_DEVNET_ENV` pointed at that devnet's export (`.devnet/env`) | recovery from the backup alone, into a vault directory that never held the vault — **not** recovery on a second machine |

No second machine can run a Sepolia-era drill. The devnet's nodes bind
loopback on the host that ran `scripts/devnet/sepolia-up`, and on any other
machine `127.0.0.1` is that machine itself; no export file can change that.
So the "second clean machine" claim is reserved for a public-network run, and
a Sepolia-era PASS is never recorded as one.

Two more facts bind the Sepolia venue:

- **The devnet that stored the work must still be the one running.** A
  devnet's stored data does not outlive the run that stored it: stopping it
  with `scripts/devnet/local-down` leaves nothing in `.devnet/` but
  `sepolia-env` ([sepolia-devnet.md](../devnet/sepolia-devnet.md)). A
  restarted devnet holds none of the work, and a restore against it can only
  fail.
- **The host is not clean, and the drill does not pretend it is.** The
  sealer's own vault and the original files may be on it. The drill uses
  neither: its vault is a fresh `ANTSEAL_DIR` that does not exist before step
  4, and its byte-compare reads only the packet's `originals.sha256`.

## Who runs this

A **non-author**: someone who did not write antseal and did not build the
drill packet. If the executor has to ask the author what a step means, that
is a finding — record it in the deviations section of the evidence
template; the fix is to this document.

## Drill packet (assembled by the sealer beforehand)

The person who owns the vault prepares, on the *primary* machine:

1. The encrypted vault backup: `antseal vault export drill-vault.bak`
   (one file; same passphrase as the vault — the export proves it by
   unlocking).
2. `originals.sha256` — `sha256sum` lines for every file of the work(s)
   under test, recorded **at seal time** on the primary machine.
3. The work id(s) to restore (64 hex characters, as `antseal list`
   prints).
4. A release binary of the **same version** for the clean machine, with
   its expected sha256 — or instructions to fetch and verify a release
   artifact. The drill does not build from source.
5. The passphrase, transmitted however the operator's own security policy
   allows — never inside the packet, never in a file next to the backup.
6. The **network each work was sealed on**, as `antseal show <WORK-ID>`
   prints it beside the title. It decides the venue ("Where the drill
   runs"). For an `arbitrum-sepolia` work, also the `ANTSEAL_DEVNET_PID`
   line from the `.devnet/env` of the Sepolia devnet that stored it, copied
   at seal time, so the executor can confirm that the same devnet run is
   still up.
7. Whether the sealer's `config.toml` carries a `[networks.arbitrum-one]
   bootstrap` override. `vault export` embeds `config.toml` in the backup
   and `vault import` restores it (D47), so the override travels with the
   backup, and a restore of an `arbitrum-one` work then dials the
   override's peers and not the built-in list — by design: an override
   replaces the built-in list and is never merged with it
   ([`../config.md`](../config.md), "Bootstrap peers"). The executor should
   learn that from the packet, not from the peers the restore dials.

The packet deliberately does **not** contain: the vault directory, any
`.sealproof` bundle, any original file. If any of those are present, the
drill cannot prove backup-only recovery — start over. Nor does it contain a
devnet export: a Sepolia-era drill reads the export of the devnet running on
its own host.

## Procedure

Record every step's `REAL_EXIT` in a copy of
[`vault-restore-drill-evidence-template.md`](vault-restore-drill-evidence-template.md)
**as you go**, reading each exit code from `$?` immediately after the
command — not from memory at the end. Capture terminal output with
`script` or `tee` where available.

Where a step says what to expect (*Expected:*) and when to stop (*STOP if*),
a STOP ends the run: record what happened in the evidence template's
deviations table, and do not record a PASS for that run.

1. **Clean-machine check.** On the second machine, confirm no vault
   exists: the antseal state directory (default location, or wherever
   `ANTSEAL_DIR` points if you set it) must be absent. Record the exact
   command you used to look and what it showed. If a vault exists, this
   machine is not clean — stop.
   **On the Sepolia venue**, instead: choose a vault directory path that
   does not exist, `export ANTSEAL_DIR=<that path>` in the shell you will use
   for every later step, and confirm the path is absent. Then, from the root
   of the checkout that runs the devnet, check its export:
   `scripts/e2e-sepolia.sh --check-env .devnet/env` (it reads that one file
   and nothing else), and `grep ANTSEAL_DEVNET_PID .devnet/env`.
   *Expected:* the path absent; `e2e-sepolia: CHECK-ENV OK chain=421614 …`
   with `REAL_EXIT=0`; the PID line identical to the packet's.
   *STOP if* the path exists; the check refuses (`WRONG-DEVNET-MODE` — that
   devnet is not in Sepolia mode); or the PID line differs (the devnet that
   stored the work is gone, and the work's data with it).
2. **Verify the binary.** `sha256sum` the antseal binary against the
   packet's expected hash. Record both values. Run `antseal --version`
   and record the output.
3. **Stage the backup.** Copy `drill-vault.bak` onto the machine. Record
   its sha256 and byte size. Nothing else from the primary machine may be
   copied. On the Sepolia venue the backup is already on the host: copy it
   into an empty working directory of its own, and use nothing else of the
   sealer's.
4. **Import.** `antseal vault import drill-vault.bak`, supplying the
   passphrase when prompted (or via `--passphrase-fd` from a file
   descriptor if scripting). *Expected:* it validates fully before touching
   anything and refuses an existing vault. Record `REAL_EXIT`.
5. **Restore.** For each work id in the packet:
   `antseal restore <WORK-ID> -o restored/`
   Pass **no** `--network`. `restore` uses the network the work was sealed
   on, read from the imported vault; it does not consult `config.toml`'s
   `default_network` (it reads that file for one key only, the
   `[networks.arbitrum-one] bootstrap` override of packet item 7), and a
   `--network` naming a different network is refused as a usage error (exit
   code 2). On the Sepolia venue, first
   `export ANTSEAL_DEVNET_ENV=<absolute path to the checkout>/.devnet/env`,
   and keep it set through step 7.
   *Expected:* `REAL_EXIT=0`, and the work's files under `restored/`.
   *STOP if* the exit code is not `0`; copy the message into the evidence.
   An exit code of `2` is a usage error — for instance a missing or unusable
   devnet export — and its fix is to the environment or the command, never
   to the evidence. Record `REAL_EXIT`.
6. **Byte-compare.** `cd restored/` and check every line of the packet's
   `originals.sha256` against freshly computed hashes:
   `sha256sum -c <path-to>/originals.sha256`. Every file must read `OK`.
   Copy the full output into the evidence. One mismatch or one missing
   file fails the drill.
7. **Reveal still works.** Pick a strict subset of units (preview with
   `antseal show <WORK-ID>`):
   `antseal reveal <WORK-ID> --units 0 -o drill.sealproof --yes`.
   This step needs the network: the imported vault holds the work's
   manifest but none of its encrypted units, and step 5's restore does not
   keep them, so every unit of each file the selection touches is fetched
   from the network the work was sealed on, through a read-only reader the
   binary connects once, at the first fetch (D175). As in step 5, pass no
   `--network` — a `--network` naming another network is refused as a usage
   error (exit code `2`) at that first fetch — and on the Sepolia venue keep
   `ANTSEAL_DEVNET_ENV` set: a missing or unusable export is the same usage
   error, raised after the passphrase. An unreachable network ends the step
   with exit code `23` and no bundle written. Record `REAL_EXIT`. (Disclosure warning: this bundle really discloses
   those units — use a work sealed for testing, not a private one.)
8. **Verify still works.** `antseal verify drill.sealproof` — fully
   offline, no vault needed. Record `REAL_EXIT` and the verdict line. If
   the drill's network policy allows, also record
   `antseal verify drill.sealproof --online`.
9. **Verdict.** The drill passes only if steps 4–8 all exited 0 **and**
   step 6 shows every hash `OK`. Fill in the template's verdict, naming the
   venue, sign it with date and operator role, and file the completed
   evidence with the wave record.
10. **Clean up.** Remove the restored files, the bundle, and the imported
    vault from the drill machine unless the drill's owner directs
    otherwise; the backup file's handling follows the vault owner's own
    backup policy. On the Sepolia venue, the vault to remove is the fresh
    `ANTSEAL_DIR` — never the sealer's own vault — and the devnet is left
    running or stopped as its owner directs.

## Recording

- The completed evidence file is the drill's product. A drill whose
  numbers live only in a terminal scrollback did not happen
  (evidence-belongs-in-the-row).
- The evidence names the venue. A Sepolia-venue PASS is recorded as
  recovery from the backup into a fresh `ANTSEAL_DIR` on the devnet's host,
  never as recovery on a second clean machine.
- Where the walkthrough is recorded (screen capture, transcript), name
  the artifact's location in the evidence file. The recording is what
  Accept row 3's "walkthrough recorded" means — a filled template alone
  does not discharge it.
- Never write the passphrase, any key material, or any personal
  identifier into the evidence. Machine descriptions stay generic (OS,
  architecture, version) — no hostnames that identify people, no user
  names, no absolute home paths.
