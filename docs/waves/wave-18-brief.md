# Wave 18 brief — the M3 tranche

**Date**: 2026-08-12 · **Authority**: `TODO.md` Current-focus (wave-18 queue) + protocol rules 4/8 · **Phase**: M3 — Reveal + verifier, 6 of 24 rows

M2 passed 2026-08-11 (Q236). This wave runs M3's product tranche. It opens with a
**planning round** because six M3 decisions are open and five of them block a row in
this wave's own queue.

## Act 1 — planning round (six records, parallel lanes)

| Decision | Question | Blocks |
|---|---|---|
| **D62** | Verifier-page host + the one canonical URL constant | R26 (which **owns** the constant), U28 (the only Rust consumer), Q22/Q28 (docs) — *corrected 2026-08-12*: this row and `tasks/R.md:673` both said R16/R25, and R16 disclaims the constant in its own `Do` while R25's subject is the build, the sums and the footer |
| **D63** | Footer build-hash mechanism + the exact artifact set the published SHA-256 covers | R25 |
| **D65** | `--json` verdict-report schema-stability commitment | R21, U30 |
| **D66** | CORS viability of the pinned esplora/Arbitrum endpoints from browsers; fallback policy | R24 |
| **D68** | `--units` syntax (ranges in MVP?) + `reveal`'s default output filename | U28 |
| **D69** | Verify exit-code mapping per verdict class (UNANCHORED = 0 or distinct nonzero?) | U30, U2's reserved space, R16's unmapped `RevealError` |

## Act 2 — implementation, in dependency order

1. **R19** (M) redaction-view model + CLI renderer — after R5, R18
2. **R20** (M) storage-linkage stage — after R5, R18 + S4, C10
3. **U27** (M) `show <work-id>` unit preview — after U3, U9 + R15
4. **R21** (L) verify orchestration library API — after R11, R17–R20 + A16–A18
5. **R22** (S) wasm-bindgen binding surface — after R5, R17–R20 + P14
6. **U28** (L) `reveal` wiring — after U27 + R15/R16, needs **D68**
7. **U29** (S) reveal consent + receipt-exposure warning — after U28
8. **U30** (M) `verify` CLI — after R21, needs **D69** + **D65**

**Queued behind (wave 19)**: R23/R24 (page) → R25/R26 → R27 + Q19 → **Q237** (the M3 gate).
R26 is an external deploy and R25/Q19 spend CI minutes — both wait on the maintainer.

## Standing lane rules (each has cost a wave before)

- **No `git stash` / `checkout` / `restore` / branch ops in any lane** — lanes share ONE working tree.
- **IDs are assigned centrally by the registrar.** Lanes report discoveries; they never number them.
  (Six consecutive zero-collision waves under this rule.)
- **Lanes never edit `TODO.md`, `docs/decisions/README.md`, `docs/instrument-ledger.md`, or
  `tasks/*.md`.** Every record ends with a `Registrar's edit set` section; the registrar lands it.
- **Instrument findings → the ledger** per rule 8 (report them; the registrar appends). Unsure which
  class? Does fixing it change what a user's seal/verify does → row; only what a checker says → ledger.
- **Briefed to OVERTURN, not to confirm.** The register's one-line framing is a hypothesis. Waves 16
  and 17 each had every lean survive on measurement — two in a row is the thing to distrust, not to
  extrapolate.
- **Measure, don't assert.** Every load-bearing claim cites a `file:line`, a command with its output,
  or a spec line quoted verbatim.
- **Verify a failure by its message, never by exit code alone** — a crash exits nonzero too; after a
  pipe read `PIPESTATUS[0]`.
- **No real anchor network** outside a consent-recorded smoke. Read-only CORS/liveness probes of
  already-pinned public endpoints are D66's measurement and are not submissions.
- **Cite the frozen registry by section, never line number.**
- **Full local gate before wave close.** `check-traceability.py`'s FLAGLESS run is the check (it has
  no `--check` flag); run every mode a script offers; read `--help` before writing a flag into a brief.
- **A 13-second `0 of 19` with zero steps** on a CI run is the dispatch-refusal signature, never a
  verdict on the code.

## Maintainer track (parallel, external — no lane can do these)

- **D62's host choice** and **R26's deploy** — external, consent-gated, and the domain (antseal.org,
  registered 2026-08-11) is already in hand.
- **V7.1's upgrade half** (D127) — `scripts/anchor-smoke upgrade` of the eight pendings in
  `testdata/anchors/A25-wave17-cycle/`, under fresh in-the-moment consent. Closes M2's one ruled hole.
- **P3**: antseal.dev as optional name-protection — D62's call.
- **CI minutes are a stated constraint this wave**: one push at wave close, one run.
