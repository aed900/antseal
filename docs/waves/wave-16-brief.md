# Wave 16 brief — the ship-path wave

**Date**: 2026-08-11 · **Authority**: D125 + `TODO.md` protocol rule 8 · **Queue**: A25 → Q208 → R13 → R14 → R15

First wave under the starvation rule: instrument-about-instrument findings go to `docs/instrument-ledger.md` (no ID, no row); only Q112-class product defects mint rows, and IDs come from the registrar, never from lanes.

## Targets, in order

1. **A25 — complete the real-endpoint smoke. Start day 1: the OTS cycle is two calendar days and runs on the calendar, not on effort.**
   - ⚠ **Consent gate**: runbook §1 (`docs/anchors/real-smoke-runbook.md`) requires fresh, recorded, in-the-moment maintainer consent before ANY real-endpoint contact — a previous day's or wave's permission does not carry. Do not start the cycle without it; record it in the capture log.
   - Capture provenance per Q123's four fields (consent record · per-file SHA-256 · per-request UTC · the 2026-08-07 header-capture format). The capture must not be considered finished without all four — back-filling hashes later proves nothing about what arrived over the wire.
   - U22 is done, so A25's Accept row 2 (the M2 real-smoke execution) is executable for the first time.
2. **Q208 — mint and word the M1/M2/M3 gate-execution rows** (S). Per D122, the `CURRENT_MILESTONE` bump belongs to the gate row — which is why Q183 has no owner today. Model the rows on Q14 (M0's, executed) and Q34 (M4's, pending). Write M2's row so it can execute the moment A25's fixtures land.
3. **R13 — bundle builder** (L; after R5, R6 + C7, G11, G12, F9 — all measured ✅). The head of the M3 chain; all of M3 is downstream of it.
4. **R14 — builder property tests** (M; after R13).
5. **R15 — disclosure-preview computation** (S; after C9 + U9 — both ✅).

**Queued behind (waves 17–18 — do not start early at the cost of the above)**: R16–R18 → R19–R23 → R24–R27 + U27–U30 + Q19. Execute the M2 gate as soon as A25's fixtures and Q208's M2 row exist.

## Standing lane rules (each has cost a wave before)

- **No `git stash` / `checkout` / `restore` in any lane** — lanes share one working tree. Never write while a self-test is staging the tree; snapshot mid-wave.
- **IDs are assigned centrally by the registrar.** Lanes report discoveries; they never number them. (Five consecutive zero-collision waves under this rule.)
- **Instrument findings → the ledger**, per rule 8. Unsure which class? Does fixing it change what a user's seal/verify does → row; only what a checker says → ledger.
- **Verify a failure by its message, never by exit code alone** — a crash exits nonzero too; after a pipe, read `PIPESTATUS[0]`.
- **`pgrep -f` / `pkill -f` match their own shell** — bracket the first character of the pattern.
- **No real anchor network anywhere except A25's sanctioned, consent-recorded smoke.** The runtime gate fails closed; do not loosen it for convenience.
- **Cite the frozen registry by section, never line number.**
- **Full local gate before wave close.** `check-traceability.py`'s FLAGLESS run is the check (it has no `--check` flag); run every mode a script offers; read `--help` before writing a flag into a brief.
- **A 13-second `0 of 19` with zero steps** on a CI run is the dispatch-refusal signature, never a verdict on the code.

## Maintainer track (parallel, external — no lane can do these)

- **A25 consent** (target 1) — needed before the wave's first act.
- **P2**: `cargo login` + `scripts/reserve-crates.sh --execute` (availability decays; all 5 names last re-verified FREE 2026-07-27).
- **P3**: register antseal.org + antseal.dev — **on the M3 critical path** (R26 cannot deploy without the domain).
