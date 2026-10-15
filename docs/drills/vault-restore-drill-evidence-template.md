# Vault restore drill — evidence record (template)

Copy this file, fill every field during the drill (never afterwards from
memory), and file the copy with the wave record. Instructions for each
step: [`vault-restore-drill.md`](vault-restore-drill.md). A field that
does not apply is written `n/a` with one line saying why — never left
blank. **No passphrases, no key material, no personal identifiers:
operator is a role, machine is a description.**

## Run identity

| Field | Value |
| --- | --- |
| Date (UTC) | |
| Operator (role, e.g. "non-author executor") | |
| Drill machine (OS, arch, e.g. "Debian 12 x86_64 VM") | |
| Network each work was sealed on (packet item 6) | |
| Sealer's `config.toml` carries a `[networks.arbitrum-one] bootstrap` override (packet item 7: yes/no — a restore of an `arbitrum-one` work dials it, not the built-in list) | |
| Venue ("second clean machine", or "Sepolia devnet host, fresh `ANTSEAL_DIR`") — must be the one "Where the drill runs" assigns that network | |
| Clean at start (step 1 command + what it showed: no vault; on the Sepolia venue, the fresh `ANTSEAL_DIR` path absent) | |
| Sepolia venue only: `scripts/e2e-sepolia.sh --check-env .devnet/env` output line + `REAL_EXIT` | |
| Sepolia venue only: `ANTSEAL_DEVNET_PID` — packet value / value on the host (must be equal) | |
| antseal binary version (`antseal --version`) | |
| Binary sha256 — expected (from packet) | |
| Binary sha256 — measured | |
| Backup file sha256 | |
| Backup file size (bytes) | |
| Work id(s) under test | |
| Walkthrough recording (kind + where filed) | |

## Per-step results

Read each `REAL_EXIT` from `$?` immediately after the command.
Write paths as the drill names them (`restored/`, `<checkout>/.devnet/env`),
never as absolute home paths.

| Step | Command (as typed, secrets elided) | REAL_EXIT | Notes |
| --- | --- | --- | --- |
| 4 vault import | | | |
| 5 restore (no `--network`; Sepolia venue: `ANTSEAL_DEVNET_ENV` set) | | | |
| 6 byte-compare | | | |
| 7 reveal subset (no `--network`; needs the network — the reader connects once at the first fetch; `2` = export or flag refusal, `23` = network unreachable) | | | |
| 8 verify (offline) | | | |
| 8 verify --online (if run) | | | |

## Byte-compare detail (step 6)

Paste the full `sha256sum -c` output — every line, including the `OK`s:

```
(paste here)
```

Files expected: ____  Files restored: ____  Files OK: ____

## Verdict

- [ ] Steps 4–8 all exited 0
- [ ] Every file byte-identical (all `OK`, counts equal, none missing)
- [ ] The venue is the one the work's network allows, and the verdict below
      names it (a Sepolia-venue PASS is not a second-machine PASS)
- [ ] Walkthrough recorded and filed
- [ ] No secret material and no personal identifiers in this record

**Drill verdict (PASS / FAIL), with venue:** ____

## Deviations and findings

Anything the procedure did not predict — a step that needed the author,
a flag spelled differently, an extra prompt, a STOP. Each finding names the
fix (usually: an edit to `vault-restore-drill.md`).

| # | What happened | Fix owed to |
| --- | --- | --- |
| | | |
