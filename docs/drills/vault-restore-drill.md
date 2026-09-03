# Disk-loss restore drill (Q32 Do (c))

**Status: WRITTEN, NEVER EXECUTED.** This procedure has not been run by
anyone. Writing it is the closed half of Q32 Do (c); *executing* it on a
second clean machine and *recording the walkthrough* is the OPEN half of
Q32 Accept row 3 ("procedures executable by a non-author — walkthrough
recorded"), and that half belongs to a future execution lane or the
maintainer, after the maintainer's P17 funding makes a Sepolia seal
possible. Nothing in this document is evidence that a restore drill has
ever succeeded. The first execution will find wrong assumptions; fix this
document, then re-run — never adjust the evidence to fit the document.

## What this drill proves (and what it does not)

The claim under test, in the row's own words: **a second clean machine
with nothing but the encrypted vault backup** can `vault import` →
`restore` → produce **byte-identical originals**, and `reveal` + `verify`
still work.

- "Nothing but the encrypted vault backup" means the export file plus the
  two things that are *knowledge*, not files: the vault **passphrase**
  (and the **keyfile**, only if the vault was created with
  `--wrap keyfile`). An export without its passphrase is designed to be
  useless — that is the vault's threat model working, not a drill failure.
- The drill needs **network access** for `restore` (it re-fetches the
  encrypted payloads) and for `verify --online`/`--live` if attempted.
  Nothing in this drill pays: restore, reveal, and verify are all unpaid
  operations. **No stage of this drill may spend funds.**
- Byte-identical is proven by comparison, never asserted: sha256 of every
  original (carried in the drill packet) against sha256 of every restored
  file, plus `cmp`. A verdict without both hash columns filled in is not
  a completed drill.

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

The packet deliberately does **not** contain: the vault directory, any
`.sealproof` bundle, any original file. If any of those are present, the
drill cannot prove backup-only recovery — start over.

## Procedure

Record every step's `REAL_EXIT` in a copy of
[`vault-restore-drill-evidence-template.md`](vault-restore-drill-evidence-template.md)
**as you go**, reading each exit code from `$?` immediately after the
command — not from memory at the end. Capture terminal output with
`script` or `tee` where available.

1. **Clean-machine check.** On the second machine, confirm no vault
   exists: the antseal state directory (default location, or wherever
   `ANTSEAL_DIR` points if you set it) must be absent. Record the exact
   command you used to look and what it showed. If a vault exists, this
   machine is not clean — stop.
2. **Verify the binary.** `sha256sum` the antseal binary against the
   packet's expected hash. Record both values. Run `antseal --version`
   and record the output.
3. **Stage the backup.** Copy `drill-vault.bak` onto the machine. Record
   its sha256 and byte size. Nothing else from the primary machine may be
   copied.
4. **Import.** `antseal vault import drill-vault.bak`, supplying the
   passphrase when prompted (or via `--passphrase-fd` from a file
   descriptor if scripting). Expected: it validates fully before touching
   anything and refuses an existing vault. Record `REAL_EXIT`.
5. **Restore.** For each work id in the packet:
   `antseal --network <network> restore <WORK-ID> -o restored/`
   (`<network>` as the packet directs; a Sepolia-era drill uses
   `--network arbitrum-sepolia` with the devnet environment the packet
   describes). Record `REAL_EXIT`.
6. **Byte-compare.** `cd restored/` and check every line of the packet's
   `originals.sha256` against freshly computed hashes:
   `sha256sum -c <path-to>/originals.sha256`. Every file must read `OK`.
   Copy the full output into the evidence. One mismatch or one missing
   file fails the drill.
7. **Reveal still works.** Pick a strict subset of units (preview with
   `antseal show <WORK-ID>`):
   `antseal reveal <WORK-ID> --units 0 -o drill.sealproof --yes`.
   Record `REAL_EXIT`. (Disclosure warning: this bundle really discloses
   those units — use a work sealed for testing, not a private one.)
8. **Verify still works.** `antseal verify drill.sealproof` — fully
   offline, no vault needed. Record `REAL_EXIT` and the verdict line. If
   the drill's network policy allows, also record
   `antseal verify drill.sealproof --online`.
9. **Verdict.** The drill passes only if steps 4–8 all exited 0 **and**
   step 6 shows every hash `OK`. Fill in the template's verdict, sign it
   with date and operator role, and file the completed evidence with the
   wave record.
10. **Clean up.** Remove the restored files, the bundle, and the imported
    vault from the drill machine unless the drill's owner directs
    otherwise; the backup file's handling follows the vault owner's own
    backup policy.

## Recording

- The completed evidence file is the drill's product. A drill whose
  numbers live only in a terminal scrollback did not happen
  (evidence-belongs-in-the-row).
- Where the walkthrough is recorded (screen capture, transcript), name
  the artifact's location in the evidence file. The recording is what
  Accept row 3's "walkthrough recorded" means — a filled template alone
  does not discharge it.
- Never write the passphrase, any key material, or any personal
  identifier into the evidence. Machine descriptions stay generic (OS,
  architecture, version) — no hostnames that identify people, no user
  names, no absolute home paths.
