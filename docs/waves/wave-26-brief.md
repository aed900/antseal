# Wave 26 brief — the M4 unblocked tranche

**Date**: 2026-08-18 · **Authority**: `TODO.md` Current-focus (M4) + protocol rules 4/7/8 ·
**Phase**: M4 — Hardening & release, 27 of 49 rows open at wave open

Wave 25 closed the U-tranche that gates U32 (U78–U83) and minted U84/U85. This wave takes
the rows that are **genuinely unblocked** — every `after:` predecessor ticked and no
maintainer-only act required — plus a planning round on the one dependency edge that, if it
falls, opens the M4 ship path's head.

## What the readiness survey found (2026-08-18, re-measured at wave open)

The M4 block holds 27 open rows. Every one was checked against its `after:` clause on the
TODO.md row **and** its `- Deps:` line in `tasks/*.md`, with each named predecessor's live
checkbox state read from `TODO.md`. Result:

| Class | Rows |
|---|---|
| **Unblocked, no external act** | `Q240`, `Q250`, `Q251`, `U77`, `U84`, `U85` |
| Blocked on `Q65` (publish flip) | `Q242`, `Q254`, `Q255`, `Q257`, `Q238` |
| Blocked on `Q30`/`Q31` (signing key, release workflow) | `Q22`, `Q241`, `Q249`, `Q31`, `Q32` |
| Blocked on a remote CI run this account cannot buy | `Q246`, `Q247`, `Q256` |
| Blocked on a downstream row | `Q28`, `Q33`, `Q34`, `Q35`, `U32`, `U76` |

Two facts from that survey are load-bearing for this wave and were **not** what the queue assumed:

1. **`Q255` and `Q257` are `after Q65`.** Both read as free-standing work — a version bump and a
   line in `CONTRIBUTING.md` — and neither is available under rule 7, which makes the `after:`
   lists authoritative. They are not in this wave.
2. **`Q22`'s only open predecessor is `Q30`**, and `Q30` is open solely because the *key acts are
   the maintainer's*. `D141 §2 R3` already struck this row's `Q31` edge on reasoning that may
   transfer. That question is **D150**, act 1.

## Act 1 — planning round (three records, parallel lanes)

| Decision | Question | Blocks |
|---|---|---|
| **D150** | Does `Q22`'s `Q30` edge survive `D141 §2 R3`'s own reasoning, and what may a README truthfully say about verifying a signature against a key that does not exist? | `Q22` → `Q28` → `Q65` → `Q31`/`Q34` — the M4 ship path's head |
| **D151** | `U84`: the copy or the refusal? `LOSS_WARNING`'s disposition, and whether MVP-SPEC.md line 143 dictates wording or only the obligation | `U84`, and `U32`'s freeze, which must not ratify a false sentence |
| **D152** | `U85`: which arm makes `list`'s resume hint honest, and is arm (a)'s predicate soundly evaluable from what `list` holds? | `U85` |

Each lane writes **exactly one file** — its own `docs/decisions/D1NN-*.md` — and nothing else.

## Act 2 — implementation, in write-scope-disjoint lanes

| Lane | Rows | Write scope (exclusive) |
|---|---|---|
| **A** | `Q240` + `Q250` | `docs/threat-model.md`, `crates/antseal-net/**` |
| **B** | `Q251` | `docs/testing/verification-matrix.md` |
| **C** | `U77` | `crates/antseal-cli/tests/verify_command.rs` |
| **D** | `U84` (per D151) | `crates/antseal-cli/src/vault/**`, `crates/antseal-cli/tests/init_command.rs`, `crates/antseal-cli/tests/snapshots/init-report.txt` |
| **E** | `U85` (per D152) | `crates/antseal-cli/src/listing.rs` |
| **F** | `Q22` (only if D150 licenses it) | `README.md`, `docs/user/**` |

**`Q240` and `Q250` are one lane and not two** because both amend `docs/threat-model.md` §2.3.
Two lanes on one section of one file is the write-scope rule's exact failure case.

## Standing lane rules (each has cost a wave before)

- **No `git stash` / `checkout` / `restore` / branch ops in any lane** — lanes share ONE working tree.
- **Declare a disjoint write scope per lane and stay inside it.** Never `cargo fmt` the workspace.
  One lane only for `Cargo.lock` (this wave: none should need it).
- **IDs are assigned centrally by the registrar.** Lanes report discoveries; they never number them.
  (Ten consecutive zero-collision waves under this rule.)
- **Lanes never edit `TODO.md`, `tasks/*.md`, `docs/decisions/README.md`, or
  `docs/instrument-ledger.md`.** Every record and every lane report ends with a
  `Registrar's edit set`; the registrar lands it. Never two registrars at once.
- **Instrument findings → the ledger** per rule 8. Does fixing it change what a user's
  seal/verify/restore does → row; only what a checker says → ledger.
- **Briefed to OVERTURN, not to confirm.** The register's one-line framing is a hypothesis.
  Waves 24 and 25 each had every planning lane overturn something handed to it as fact — and
  wave 25's sharpest finding was **a ruling whose own stated verification could not fail**.
  Neither streak is a prior; test the lean either way.
- **Measure, don't assert.** Every load-bearing claim cites a `file:line`, a command with its
  actual output, or a spec line quoted verbatim. **Re-measure every figure a brief hands you** —
  counts in this tracker have drifted four separate times, once inside the sentence promising
  they had not.
- **Verify a failure by its message, never by exit code alone** — a crash exits nonzero too;
  after a pipe read `PIPESTATUS[0]`; write `REAL_EXIT=` to a file and read it back, because the
  harness's own "(exit code 0)" reports the LAST command in a wrapper, not the one measured.
- **Plant a fault in every check you add.** The dominant defect class here is an assertion that
  is green because nothing reachable could redden it. A new test that has never been seen red is
  not evidence.
- **Evidence belongs in the row.** A measurement that lives only in a transcript is not evidence;
  write the capture into the report the registrar reads.
- **Banned mid-wave** (each stages a full tree copy or writes tracked files):
  `scripts/local-gate.sh`, `scripts/check-traceability.py --self-test`,
  `scripts/check-copy-style.py --self-test`, `scripts/check-ci-paths.py --self-test`.
  `check-traceability.py`'s **flagless** run is the check — it has no `--check` flag.
  Read `--help` before writing a flag into a brief.
- **No external actions of any kind** — no push, no publish, no repo-settings change, no
  registration, no funding, no calendar submission. Read-only `gh api` GETs against public
  repositories are measurement and are permitted. The publish flip is **not** taken by any lane.
- **Full local gate before wave close**, on a quiet tree, by the registrar alone.

## Maintainer track (parallel, external — no lane can do these)

Unchanged from wave 25 and none of it is discharged: the `antseal.org` parking-A-record removal
and auto-renew; `Q30`'s signing keypair (`minisign -G` prompts interactively and cannot be run
through an agent); `Q33`'s gate-wallet funding; the `Q65` publish flip and, co-timed with it,
`Q242`'s private-vulnerability-reporting enable; branch protection, whose stated cause is stale
and whose blocked status stands unmeasured since the Pro upgrade.

**Hosted CI still refuses every job** — exhausted Actions minutes, zero steps in 3–5 s, never a
code verdict — so the local gate remains the only witness, as it has been since wave 20.
