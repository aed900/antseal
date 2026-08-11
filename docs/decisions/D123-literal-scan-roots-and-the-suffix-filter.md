# D123 — Q190: the suffix filter is a directory rule, and a named file is not a directory

- **Status: RESOLVED — `CITATION_SUFFIXES` does not change, and the suffix
  question is refused as the wrong question.** `CITATION_SCAN` gains a
  **per-entry rule**: a literal file entry is read **as itself, unfiltered**,
  because naming it *is* the deliberation; a directory entry contributes the
  files whose suffix is in `CITATION_SUFFIXES`, which is the only job that set
  has ever had. The row leans toward *"widen with `.toml`, plus a mechanism for
  suffixless files"*. **Measured, `.toml` reaches none of the three files the
  row is about.** `deny.toml` is a *root-level* file, and root-level files are
  reached only by being **named** — adding `.toml` to the suffix set moves the
  file count 359 → 365 and every one of the six new files is a
  `crates/*/Cargo.toml`; `deny.toml` is not among them. The suffix set is not
  the gate on any of these three.
  **And the route the row proposes cannot finish.** To reach every root-level
  citation surface by suffix you need `.toml` **and** `.txt`: 359 → **377
  files, 15 of them collateral nobody asked for** (six crate manifests, seven
  CLI golden snapshots, two proptest seed files) — and it **still** cannot
  reach `.gitattributes` or `.gitignore`, because the empty string is not a
  member of any suffix set and never will be. The per-entry rule reaches all
  five in **+5 files, zero collateral**.
  **The row scopes three root files. There are five.** Beyond `deny.toml`,
  `.gitattributes` and `.gitignore`, the root `Cargo.toml` carries **57
  distinct task ids in 100 occurrences and 19 distinct decision ids** — a
  larger unread citation surface than the row's three combined — and
  `requirements-crosscheck.txt` carries 2 task ids and 3 decision ids. Fixing
  three of five would reproduce, in the same constant, the exact partial
  widening that produced this row.
  **The defect is proven by construction, both ways.** A bare hole id planted
  as a comment in `deny.toml` leaves the lane reporting
  `[task-citations] ok — 391 distinct task ids cited across 359 files, all
  resolve`, exit 0 — the check certifying a tree that contains an unresolvable
  id. The same planted tree under the ruled semantics produces the check's own
  annotated finding naming the file. `deny.toml` was restored byte-for-byte
  (sha256 `d2a360db…658a8a`, 8654 bytes, unchanged in `git status`).
  **The row's false-positive fear is measurably unfounded, and that is not what
  makes the suffix route wrong.** Every `.toml` and `.txt` file the widening
  would reach was swept and classified: 62 distinct task ids across the six
  crate manifests, **all allocated, none above its ceiling, zero would-fail**;
  19 decision-id tokens across the snapshots, all resolving, all real citations
  in user-facing CLI copy; `deny.toml`'s license expressions and its
  `RUSTSEC-…` advisory ids produce **zero** spurious matches. The suffix route
  is wrong because it is incomplete by construction and pays 15 files of
  undeliberated surface, not because it is noisy.
  **The row's direction-of-risk sentence is refuted and replaced.** Ids are
  never deleted from the register (protocol rule 1 — struck, never deleted),
  so an id in these files cannot rot by the register moving under it. The only
  way one becomes unresolvable is being **wrong when written** — a typo, or an
  id minted in a brief and never registered, which is the `A71` class this
  sweep was widened for. Rarity of edit does not *cause* the rot; it
  *preserves* it. And rarity cuts the other way on cost: a hand-edited,
  rarely-touched file is the cheapest possible thing to put inside a sweep.
- **Date: 2026-08-11** (wave 15, D123 lane, briefed to overturn the row's lean
  toward widening `CITATION_SUFFIXES` with `.toml` plus a per-root override or
  a literal-filename allowlist — overturned on the measurement that `.toml`
  reaches none of the three files, and the allowlist refused as the second
  constant D116 R1 deleted five constants to prevent).
- **Owning tasks: Q190** (the ruling; its `Problem` figures are corrected in
  two places and its `Notes` direction-of-risk sentence is replaced).
- **Amends**: **`TODO.md`'s Q190 row** and **`tasks/Q.md`'s Q190 entry** — see
  §7.3. The bullet above is the D118 front-matter form deliberately, not the
  anchored `**Owner: <ID>**` of D113 RULING 2: only two per-ruling assignments
  exist in the whole corpus, and minting a third would oblige the Q190 row to
  back-cite `D123` before the orchestrator has allocated the register entry.
- **Binds against**: `scripts/check-traceability.py`'s `CITATION_SCAN`,
  `CITATION_SUFFIXES` and the two — possibly three, see §7.1 E1b — copies of
  the scan-root loop. Nothing frozen is touched; zero frozen bytes.

---

## The problem, in one sentence

Q176 made root-level files scan roots and wrote the limit of its own widening
into the constant in the same act — *"an entry is filtered by
`CITATION_SUFFIXES` like any other path, so naming a root file whose suffix is
not in that set … adds a scan root that reads nothing at all"* — and the
question left behind is not *which suffixes to add* but **why a file that
someone deliberately named is being asked to justify itself to a filter written
for a directory walk.**

---

## 1. What was measured

Every number below was re-derived in this tree on 2026-08-11 by importing
`scripts/check-traceability.py` and using **its own** constants and regexes —
`CITATION_SCAN`, `CITATION_SUFFIXES`, `CITATION_SCAN_SELF`, `TASK_BARE`,
`TASK_MARKED`, `TASK_ID_NOT_A_CITATION`, `allocated_task_ids()`,
`task_id_ceiling()`, `allocated_decision_ids()`, `open_decision_ids()`. Nothing
here is transcribed from the row, the entry or the ledger.

### 1.1 The mechanism, confirmed

`CITATION_SUFFIXES` is `{.rs, .md, .json, .py, .sh, .mjs}` — six members — and
both sweeps apply it identically. `check_decisions()` and
`sweep_task_surfaces()` each carry the same two lines: the file-or-directory
branch Q176 added, and immediately under it a filter that tests
`path.suffix not in CITATION_SUFFIXES` **without regard to which branch the
path came from**. So a file that was named is filtered exactly like a file that
was found by `rglob`. The hazard sentence is exact, and it is exact for all
three files, not two — it names `deny.toml` and `.gitattributes` and omits
`.gitignore`, which is in the same state.

### 1.2 The citations, re-counted (the row's totals are wrong in two places)

| file | distinct task ids | occurrences | distinct decision ids |
| --- | --- | --- | --- |
| `deny.toml` | **7** — P12, P13, P15, P16, Q10, Q29, S20 | **16** (Q29×6, P16×3, P13×2, Q10×2) | 4 (D6×5, D19×4, D7×2, D60×2) |
| `.gitattributes` | **6** — A6, G3, Q1, Q2, Q4, Q7 | **6** | 1 (D57) |
| `.gitignore` | **6** — A23, F17, P16, P17, Q9, R10 | **7** (P16×2) | 0 |

- **`deny.toml`'s seven is right, `P15` included.** The row's correction of the
  ledger holds.
- **`.gitignore` is six, not four.** The row says *"names four — the `P16`/`P17`
  pair, the `R10`/`F17`/`A23` group, and `Q9`"*: four is not the number of ids
  (6), not the number of occurrences (7), and not the number of groups it then
  lists (3).
- **The three-file total is not seventeen.** It is **19 (id, file) pairs, 18
  distinct ids** (`P16` appears in two of the files) **and 29 occurrences**. The
  row's *"seventeen citations in three files"* is 7 + 6 + 4 and inherits the
  `.gitignore` error.
- **Every one of the 29 occurrences is BARE.** `TASK_MARKED` finds nothing in
  any of the three. This is load-bearing for the fixture design in §7.

### 1.3 Naming the three files, with the suffix set unchanged, reads nothing

Simulated against the real constants: `CITATION_SCAN` + the three files, suffix
set untouched → **359 files, new files versus baseline: NONE.** The hazard is
not a caution about a possible future; it is a description of what the constant
does today.

### 1.4 Adding `.toml` reaches none of the three

`CITATION_SUFFIXES ∪ {.toml}`, scan roots untouched → **365 files**, and the six
new files are exactly `crates/{antseal-anchor, antseal-cli, antseal-core,
antseal-net, devnet-launcher, wasm-bitmatch}/Cargo.toml`. The simulation's own
line: `does it reach deny.toml? False`. It cannot: `deny.toml` sits at the
repository root, and after Q176 a root-level file is reached **only by being
named**. The row's first question — *"whether `.toml` joins
`CITATION_SUFFIXES`"* — is a question about `crates/`, not about `deny.toml`.

### 1.5 The `Cargo.toml` census confirms the row and enlarges it

Nine `Cargo.toml` outside `target/`: the root manifest, six under `crates/`,
`fuzz/Cargo.toml`, `probes/sig-probe/Cargo.toml`. **Six are inside
`CITATION_SCAN`.** `fuzz/` and `probes/` are outside it entirely and the root
manifest is reachable only if named. The row's corrected figures are right.
Fifteen `.toml` files exist outside `target/` in total; a suffix widening
reaches six of them.

### 1.6 The row scopes three root files; there are five

Every root-level entry was classified for *is it a citation surface* and *is it
read*:

| root file | suffix | task ids (distinct / occ.) | decision ids | read today? |
| --- | --- | --- | --- | --- |
| `Cargo.toml` | `.toml` | **57 / 100** | **19** | **no** |
| `deny.toml` | `.toml` | 7 / 16 | 4 | **no** |
| `.gitattributes` | *(none)* | 6 / 6 | 1 | **no** |
| `.gitignore` | *(none)* | 6 / 7 | 0 | **no** |
| `requirements-crosscheck.txt` | `.txt` | 2 / 2 | 3 | **no** |
| `CHANGELOG.md` | `.md` | 14 | 15 | yes (Q176) |
| `CONTRIBUTING.md` | `.md` | 34 | 4 | yes (Q176) |
| `README.md` | `.md` | 1 | 0 | yes (Q176) |
| `MVP-SPEC.md` | `.md` | 0 | 0 | yes (Q176) |
| `SPEC-REVIEW.md` | `.md` | 6 | 0 | no — **deliberate** (preserved artifact) |
| `MVP-SPEC.orig.md` | `.md` | 0 | 0 | no — **deliberate** (preserved artifact) |
| `TODO.md` | `.md` | 596 | 120 | no — **deliberate** (it is the register) |
| `Cargo.lock`, `clippy.toml`, `rustfmt.toml`, `rust-toolchain.toml` | — | 0 | 0 | no — nothing to read |

Three findings in that table:

1. **The root `Cargo.toml` is the largest unread root-level citation surface in
   the tree** — larger than the row's three files combined, on both halves.
2. **`requirements-crosscheck.txt` is a fifth instance in a third suffix.** A
   suffix answer would need `.txt` as well.
3. **`Cargo.lock` is doubly unreachable and empty.** Its suffix is `.lock`, so
   no widening to `.toml` touches it; it is not named; and it contains **zero**
   task-shaped and **zero** `D<n>` tokens. The concern that it might be dragged
   in is void twice over.

### 1.7 The measured cost of each route

| route | files swept | delta | collateral | reaches the two dotfiles? | new failures |
| --- | --- | --- | --- | --- | --- |
| baseline (today) | 359 | — | — | — | 0 |
| name the three, suffix set unchanged | 359 | **+0** | 0 | no — reads nothing | 0 |
| add `.toml` only | 365 | +6 | 6 | no | 0 |
| add `.toml`, name the three | 366 | +7 | 6 | no | 0 |
| **add `.toml` + `.txt`, name all five** | **377** | **+18** | **15** | **NO — impossible** | 0 |
| **per-entry rule, name all five** | **364** | **+5** | **0** | **yes** | **0** |

The 15 collateral files on the suffix route are the six `crates/*/Cargo.toml`,
seven CLI golden snapshots under `crates/antseal-cli/tests/snapshots/`, and the
two `crates/antseal-core/proptest-regressions/*.txt` seed files. The
simulation's own closing line for that route:
`still unreachable by the suffix route: ['.gitattributes', '.gitignore']`.

### 1.8 The false-positive fear, measured — and refuted

Everything the suffix route would newly read was swept and each token
classified against `allocated_task_ids()`, the domain ceilings and the decision
registers:

- The six `crates/*/Cargo.toml`: **62 distinct task ids, every one allocated,
  none in a domain hole, none above its domain ceiling** — zero would-fail, and
  zero landing in the bare-above-ceiling blind spot.
- The nine `crates/**/*.txt`: **0 task ids** and **19 distinct `D<n>` tokens**
  (7 in `cli-errors.display.txt`, 11 in `cli-surface.help.txt`, 1 in
  `json-envelopes.txt`) — all resolving, and all genuine citations inside
  user-facing error and help copy.
- `deny.toml`'s license expressions (`BlueOak-1.0.0`, `GPL-3.0`, `Apache-2.0`)
  and its `RUSTSEC-2023-0089`-shaped advisory ids: **zero** matches. `TASK_BARE`
  requires a word boundary before an **uppercase** domain letter, which excludes
  every one of them.

So the brief's suspicion that `.toml` tokenisation produces false hits in
manifests, `clippy.toml`, `rustfmt.toml`, `rust-toolchain.toml`, license
expressions or the lockfile is **refuted by measurement**. The argument against
the suffix route is completeness and collateral, not noise — and saying so is
the difference between a ruling and a hunch.

### 1.9 Marginal coverage, stated honestly

Of the 18 distinct ids in the row's three files, **17 are already cited
somewhere else** in the swept surface. Only `P12` is new. Across all five root
files, only `P12` and `P23` are new: the task half moves **391 → 393 distinct
ids** while the file count moves 359 → 364.

This is the honest bound on the benefit, and it is not the benefit. The sweep
checks **(id, path)** pairs, not a global id set: another file citing `P16`
correctly says nothing about whether `.gitignore` cites it correctly. §2 is the
demonstration.

---

## 2. Proof by construction — the defect, and the fix, on one planted tree

A single bare hole id was planted as a trailing comment line in `deny.toml`.
The id is the lowest unallocated number in the Q domain — Q's ceiling is 203 and
it has 21 holes — which is below the ceiling and therefore a **tier-1**
citation: bare form is enough to fire, no marking required.

**The tree as it stands, with the fault present:**

```
[task-citations] ok — 391 distinct task ids cited across 359 files, all resolve
(3 registered as not-citations); no unregistered id cited in marked form above
its domain ceiling
check-traceability: ok (task-citations)
exit=0
```

The lane is **green while an unresolvable id sits in the tree**. That is the
whole of Q190, executed.

**The same planted tree, four candidate rules, one run:**

| rule | files | verdict on the planted id |
| --- | --- | --- |
| baseline | 359 | silent |
| the three named, suffix set unchanged | 359 | **silent** |
| `.toml` added, roots unchanged | 365 | silent (`deny.toml` not reached) |
| `.toml` added **and** the three named | 366 | caught |
| **per-entry rule, the three named** | **362** | **caught** |

**The check's own message under the ruled semantics**, produced by calling the
real `check_task_citations()` with the literal-entry sweep:

```
::error::check-traceability [task-citations] Q45 is cited (deny.toml) but has
no row in TODO.md's register. Either the id was minted in a brief and never
registered — add the row and its tasks/Q.md entry — or the token is not a task
citation at all, in which case register it in TASK_ID_NOT_A_CITATION keyed by
(id, path) with the reason.
```

Verified by **message**, with the check's own `::error::check-traceability
[task-citations]` annotation present — not by exit code, which a traceback also
satisfies.

**Restoration.** `deny.toml` was rewritten to its original bytes with the editor
(never `git checkout`/`restore`): sha256
`d2a360db58f7e61dc0a5860aade139162faf24c250714812743f08f451658a8a` before and
after, 8654 bytes both times, `grep -n Q45 deny.toml` exits 1, and
`git status --short` does not list it.

> The hole id appears verbatim above because the check's message is the
> evidence. This document lives in `docs/decisions/`, which **both** sweeps
> exclude by D109 §3.3 — a record's job includes proposing work — so the token
> cannot become a citation. It is also, today, the value `first_hole("Q")`
> computes for the harness's own fixtures; the new cases in §7 reuse that
> helper rather than hard-coding it, so they stay correct as the register fills.

---

## 3. Every shape, attacked one by one

### 3.1 The row's lean — widen with `.toml`, plus a mechanism for suffixless files — **REFUSED**

Three measured reasons, any one of which is sufficient:

1. **`.toml` reaches none of the three files the row is about** (§1.4). The
   widening the row wants measured is a widening of `crates/`, arriving under
   the name of a root-file fix. Whatever its merits, they are not Q190's.
2. **The route cannot finish** (§1.7). `.toml` + `.txt` is +18 files with 15
   collateral and **still** leaves both dotfiles unreachable. There is no
   suffix that matches the empty suffix; `Path(".gitignore").suffix` is `""`,
   and adding `""` to `CITATION_SUFFIXES` would match every extensionless file
   under every scan directory — a filter that no longer filters.
3. **The "mechanism" the row offers is a second constant.** *"An explicit
   allowlist of literal filenames"* beside `CITATION_SCAN` is precisely the
   shape the comment at that constant rejects in its own voice — *"two
   constants held in step by a comment is the defect D112 spent a wave on … the
   only honest comment on two here would be 'these are the same, one is
   stale'"* — and it is what D116 R1 deleted five constants (`DECISION_SCAN`,
   `DECISION_SUFFIXES`, `TASK_SCAN`, `TASK_SUFFIXES`, `TASK_SCAN_SELF`) to
   prevent. Reintroducing one to hold two dotfiles is the wave's worst trade.

The row's other offered mechanism, a **per-root suffix override** (making
`CITATION_SCAN` a mapping of root → suffix set), is refused as
over-expressive: no root in this tree wants a *different* suffix set. The five
want **no filter at all**. Paying a data-structure change for expressiveness
nothing uses buys a second thing that can be wrong.

### 3.2 Leave the sweep alone; record the exclusion at the constant — **REFUSED, with the cost measured**

This is the row's own `Accept` alternative — *"or outside with a reason at the
constant"* — and it is a real ruling, so it was costed rather than dismissed.

**For it:** these files are hand-edited and rare; a sweep buys an assertion at
the price of a surface.

**Against it, measured:**

- **The price is not a surface, it is five files.** +5 files, zero collateral,
  zero new failures on either half (§1.7). The maintenance cost of a sweep is
  paid in churn, and hand-edited rarely-touched files generate none. **Rarity
  is an argument for inclusion.** The row's own note uses rarity to argue the
  opposite and gets it backwards.
- **The thing bought is not decoration.** `deny.toml`'s ids sit inside RUSTSEC
  advisory-ignore `reason` strings carrying a dated review obligation — one
  entry pins an advisory to `P16` and to a `Review by 2026-11-01`. A rotted id
  there makes the justification for **silencing a security advisory**
  unverifiable at the exact moment somebody tries to verify it. That is the one
  concrete, nameable harm among the three and it is not the one the row leads
  with.
- **Documenting the exclusion is itself a maintenance liability.** A comment
  saying *"these root files are outside, and here is why"* is an inventory of
  root-level files, and inventories rot: it was already wrong on the day Q176
  wrote it, naming `deny.toml` and `.gitattributes` and silently omitting
  `.gitignore`, and it would have to grow two more entries today for
  `Cargo.toml` and `requirements-crosscheck.txt`. **The exclusion comment is a
  hand-maintained list of exactly the thing the constant is a list of.**
- **The failure it would leave open is demonstrated, not hypothetical** (§2).

**This is the one arm where the row's instinct survives contact with the
measurements, and it is recorded as such.** The brief invited a ruling that
declines to widen; the cost came out at five files and two lines of code
against a green-lane-over-a-real-fault demonstration, and it did not survive.

### 3.3 Interrogating the row's stated direction of risk — **the sentence is refuted and replaced**

The row says: *"these files are edited rarely and by hand, which is why nobody
noticed, and is also why a stale id in one of them would survive a long time."*

**The mechanism it describes does not exist.** Protocol rule 1 says a retired
task is struck, never deleted — the register carries one struck row today and
`--task-entries` parses it, which is why `TASK_ROW` matches `- ~~**P18**` as
well as a checkbox. So no id cited in these files can be un-allocated by
anything happening in `TODO.md`. There is no decay path.

**The real path is different and worth naming precisely:** an id in one of these
files becomes unresolvable only by being **wrong at the moment it is written** —
a typo, or an id minted in a brief and never registered. That is the `A71`
class, in a committed gate script, which is why `scripts/` joined the sweep at
all (D109 §1.5). Rarity of hand-editing does not make that more likely; it makes
it **survive undetected**, and it makes the check nearly free to run.

**And the harm is not uniform across the three, which the row flattens:**

- **`deny.toml` — real and dated.** Advisory-suppression justifications with a
  review deadline (above). Highest cost.
- **`.gitignore` — real and expensive, one step removed.** Its ids justify *why*
  a path is ignored (`R10`/`F17`/`A23` the fuzz corpora, `Q9` the minimized
  corpus, `P16`/`P17` devnet state). A wrong id invites a future lane to delete
  an ignore line as obsolete — and Q191 measured what is behind those lines:
  **922 files, ~5.1 MB** of `fuzz/corpus` and `fuzz/artifacts`, currently
  git-ignored and copied on every self-test.
- **`.gitattributes` — navigational only.** The globs work whatever the comment
  says; the cost is a reader chasing `Q7` and landing somewhere unrelated.

So: **the row's conclusion is right and its stated reason is wrong.** Recorded
here because the reason is what a future lane will reuse.

### 3.4 The per-entry rule — **RULED** (see §4)

### 3.5 Two shapes nobody proposed, and why they are not the answer

- **`"."` as a scan root.** Already refused at the constant with reasons that
  still hold: it reaches `target/`, `testdata/`, every dot-directory and
  `TODO.md` itself, *"turning the register into a citation surface that reports
  every id it allocates"* — measured under the check's **real** floor, ceiling
  and suppression rules: **596 task-shaped and 120 `D<n>` tokens**, of which
  **nine would fire**. Five at tier 1 — three domain holes (`Q100`, `S33`,
  `S35`) plus `Q72` and `R46`, whose suppressions are keyed to *other* paths and
  therefore cannot mute them here. And **four at tier 2** — `P384`, `U256`,
  `F64` and `S310`, written **marked** in the register's own prose: the curve
  name, the integer width and the codec discriminant that
  `check_task_citations()`'s blind-spot comment names, one by one, as the reason
  tier 2 is not widened to bare occurrences. Four of the nine are the exact
  tokens the check documents as the thing it must never report. (Four more —
  `A0`, `C0`, `F0`, `U0` — are caught by the floor rule and stay silent, which
  is the floor working.) Not reopened.
- **Suffix-filter only literal entries whose suffix is *known-binary*.** A
  denylist instead of an allowlist. It inverts a filter that is currently
  correct-by-construction into one that must enumerate the world, and it buys
  nothing: `read_text(encoding="utf-8")` is already wrapped in
  `except (UnicodeDecodeError, OSError): continue`, so a named binary file is
  already inert rather than a crash.

---

## 4. Ruling

**R1. `CITATION_SUFFIXES` is not edited.** It stays
`{.rs, .md, .json, .py, .sh, .mjs}`. It is a **directory-walk filter** — the
answer to *"which files inside a tree are citation surfaces"* — and it has never
been anything else. Applying it to an explicitly named file is a category
error, and the hazard sentence is the tree noticing that category error and
documenting it instead of fixing it.

**R2. `CITATION_SCAN` entries carry a per-entry rule.** A **literal file** entry
is read as itself, **unfiltered**: the act of naming it in a reviewed constant
is the deliberation, and no second gate is owed. A **directory** entry is walked
recursively and filtered by `CITATION_SUFFIXES`, exactly as today. Both sweeps
take the change **byte-identically**, per D116 R2.

**R3. The hazard sentence is deleted, not expanded.** It described a defect;
under R2 it is false. It is replaced by a statement of the rule, with a dated
note recording what it replaced and why — silence about a superseded sentence is
what D117 forbids, not the superseding.

**R4. All five root-level citation surfaces are named**, not the row's three:
`Cargo.toml`, `deny.toml`, `requirements-crosscheck.txt`, `.gitattributes`,
`.gitignore`. Fixing three of five would leave a remainder of the same shape as
the one this row *is*, in the same constant, in the same wave — and the row's
own `Do` says *"decide the suffix rule rather than adding files one at a time."*

**R5. `SPEC-REVIEW.md`, `MVP-SPEC.orig.md` and `TODO.md` stay out**, on the
live-versus-preserved rule and the register rule already recorded at the
constant. R4 is not a licence to sweep the root; it is the completion of a
census.

**R6. The new property gets a self-test case on each half.** A literal root
whose suffix is outside `CITATION_SUFFIXES` must be *demonstrably* read, by both
sweeps. Nothing in the harness can prove this today: every existing scan root
has an in-set suffix, so case (b2) and case (o2) would pass unchanged if R2 were
silently reverted. The task-half fixture plants its id **bare**, because all 29
citation occurrences across the five files are bare and a marked fixture would
leave the only form these files use unproven.

**R7. The asymmetry R4 creates is written down where it is created.** After this
ruling the **root** `Cargo.toml` is swept and the six **member** manifests under
`crates/` are not — the root one because it was named, the members because
`.toml` is not a directory-walk suffix. That is coherent and it looks arbitrary,
so the constant says it in its own voice and points at the separate question
(§10 (a)) rather than leaving the next reader to infer an oversight.

---

## 5. Why the per-entry rule and not the suffix set — the one-paragraph version

Two questions wear the same clothes here. *"Is this file a citation surface?"*
and *"which of the files I just found by walking a tree are citation surfaces?"*
The second needs a filter, because a tree walk has no opinion and will hand you
`.png`, `.cbor` and `.lock`. The first does not, because the answer was
already given — by a human, in a reviewed constant, in a diff. Q176 widened
`CITATION_SCAN` to answer the first question and reused the second question's
machinery to do it, and the hazard sentence is the receipt. The fix is to stop
asking the answered question twice.

---

## 6. Why the ruling can land in one act

Both halves were run against the ruled semantics with all five roots named,
using the real check functions:

```
[task-citations] ok — 393 distinct task ids cited across 364 files, all resolve
(3 registered as not-citations); no unregistered id cited in marked form above
its domain ceiling
decisions half: files=364 unresolved=[] registry-line-citations=[]
```

Zero unresolvable task ids, zero unresolvable decision ids, zero
`registry-v1.md:<line>` citations in any of the five newly-read files. **The
ruling is green on landing** — it does not import a backlog, and the
implementing lane is not also a repair lane.

---

## 7. Edit set

Exactly one source file changes, plus bookkeeping. **`scripts/check-traceability.py`
is being edited by two other lanes this wave** (Q184's fixture sweep, D120 on
`--self-test` staging). The hunks below are at the `CITATION_SCAN` comment
block, the two sweep loop bodies, and the `cases` list; line numbers are **as of
2026-08-11 pre-edit** and are given as an aid only — every hunk is anchored on a
**name**, per the tree's names-over-numbers convention.
- `docs/decisions/README.md` — this decision's index row. **Applied 2026-08-11**, executing [D119](D119-decision-index-identity-and-the-index-row-sections.md) §5 step 4; the former `## Index row` section is demoted to this line under D119 RULING 4, and RULING 6 puts the row in the act that commits the record.

### 7.1 `scripts/check-traceability.py` — five edits

**E1 — the two sweep loops, byte-identically** (in `check_decisions()`, and in
`sweep_task_surfaces()`; pre-edit ≈ `:656`–`:658` and `:883`–`:885`). Replace

```python
        for path in ([base] if base.is_file() else base.rglob("*")):
            if not path.is_file() or path.suffix not in CITATION_SUFFIXES:
                continue
```

with

```python
        literal = base.is_file()
        for path in ([base] if literal else base.rglob("*")):
            if not path.is_file() or (not literal and path.suffix not in CITATION_SUFFIXES):
                continue
```

Neither function binds `literal` today, so there is no shadowing. Everything
after the filter — the `target`/`node_modules`/`__pycache__` prune, the
`CITATION_SCAN_SELF` exclusion, the guarded `read_text` — is unchanged and
still applies to literal entries.

**E1b — a THIRD site, if the Q184 hunk lands.** Measured in the working tree on
2026-08-11: the concurrent Q184 lane is adding `scratch_decision_citations()`
inside `self_test()`, which **re-implements this same loop a third time** over
the scratch tree. Its docstring states its intent exactly — *"Reads
`CITATION_SCAN`/`CITATION_SUFFIXES` rather than restating them, so a narrowing
of either moves this fixture with the check instead of leaving it aimed at a
surface nothing reads any more"* — and that intent is **defeated by copying the
filter**: it shares the constants but not the semantics, so under E1 it would
apply the suffix filter to a literal entry and aim its fixture at a surface the
real check reads and it does not. **If that hunk is in the tree at
implementation time, E1 applies at three sites, not two.** Check for it; do not
assume two. The implementing lane must grep for `path.suffix not in
CITATION_SUFFIXES` and confirm the count before and after.

**E2 — the comment above each loop, byte-identically** (pre-edit ≈ `:650`–`:655`
and `:877`–`:882`). The existing Q176 paragraph keeps its `rglob`-on-a-file fact
(still true) and gains the rule and its reason. Suggested text, to be used
verbatim in **both** places:

> `Q176 + Q190/D123 — an entry may be a directory (swept recursively and`
> `filtered by CITATION_SUFFIXES) or a single FILE (swept as itself,`
> `UNFILTERED). Two branches because they answer different questions: a tree`
> `walk has no opinion about what it finds, so it needs the suffix set; a named`
> `file was already deliberated in a reviewed constant, so a second gate is`
> `owed to nobody. Filtering a named file is what made deny.toml,`
> `.gitattributes and .gitignore scan roots that read nothing at all. Without`
> `the branch at all, a filename here is a silent no-op: Path.rglob on a`
> `non-directory yields nothing. Both sweeps carry these lines identically`
> `(D116 R2); see the note at CITATION_SCAN.`

**E3 — the `CITATION_SCAN` comment block** (pre-edit `:551`–`:553`). **Replace**
the `HAZARD` paragraph — do not append to it; under E1 it is false. The
replacement states R1/R2 and carries the dated correction:

> `SUFFIXES ARE A DIRECTORY RULE (Q190/D123, 2026-08-11). A literal file entry`
> `above is read as itself and is NOT filtered by CITATION_SUFFIXES; a`
> `directory entry is walked and filtered. This paragraph replaces a HAZARD`
> `note written by Q176 in the same act that created the hazard — "an entry is`
> `filtered by CITATION_SUFFIXES like any other path, so naming a root file`
> `whose suffix is not in that set adds a scan root that reads nothing at all"`
> `— which was TRUE of the old semantics and named two of the three files then`
> `in that state. Measured before the change: naming the files with the suffix`
> `set unchanged moved the swept count 359 -> 359. Adding .toml instead reached`
> `SIX crates/*/Cargo.toml and NOT deny.toml, because a root-level file is`
> `reached only by being named; and no suffix can ever reach a dotfile, whose`
> `suffix is the empty string. Do NOT "simplify" this back to one filter.`

**E4 — five entries in `CITATION_SCAN`** (pre-edit `:561`–`:571`), after the
four `.md` root files, with the R7 note attached:

```python
    # Root-level files whose suffix is outside CITATION_SUFFIXES, reachable
    # only under the literal-entry rule above (Q190/D123). Measured 2026-08-11:
    # 57/7/2 distinct task ids and 19/4/3 decision ids in the three with
    # suffixes, 6 and 6 in the two dotfiles; all resolve.
    "Cargo.toml",
    "deny.toml",
    "requirements-crosscheck.txt",
    ".gitattributes",
    ".gitignore",
```

and, in the block comment, the R7 sentence: the **root** manifest is swept
because it is named here; the **six member manifests under `crates/`** are not,
because `.toml` is not a directory-walk suffix — a separate question with its
own measurement, deliberately not answered as a side effect of this one.

**E5 — `CITATION_SUFFIXES` is NOT edited.** Stated as an instruction because the
row leans the other way: an implementing lane that "helpfully" adds `.toml`
takes 6 undeliberated files and does not reach a single file this ruling is
about.

### 7.2 `scripts/check-traceability.py` — two new `--self-test` cases (R6)

**(b3), immediately after case (b2)** — the task half, on a literal root with an
out-of-set suffix:

```python
            (
                "task-citations",
                "deny.toml",
                lambda t: t + f"\n# follow-up: {hole_q}\n",
                "red",
            ),
```

Comment to carry, in the voice of (b2): this is the only case that can prove a
literal entry is read **unfiltered** — every other scan root has an in-set
suffix, so reverting D123's branch leaves (b) and (b2) green. The id is planted
**BARE**, not marked, because all 29 citation occurrences across the five root
files are bare and a marked fixture would leave the only form these files use
unproven; bare below the ceiling is tier 1 and fires. `deny.toml` is the target
because its ids sit in RUSTSEC advisory-suppression `reason` strings with a
dated review obligation. And by the harness's missing-target rule — never a
skip — deleting or renaming `deny.toml` also goes red.

**(o3), immediately after case (o2)** — the decision half, same surface. Same
four-tuple shape, `"decisions"` / `"deny.toml"` / `"red"`, with a mutation that
appends a TOML comment line carrying a **line-number citation into the frozen
wire registry** — the same fixture shape cases (o) and (o2) already use, copied
from whichever of them is adjacent at implementation time so the two stay in
step. (The literal is deliberately **not** reproduced here: this record is
outside both sweeps by D109 §3.3, but the tree's convention is to describe
mutation strings rather than propagate them, and the constant's own comment
states its registry citation in an abstract form for the same reason —
*"documenting the trap does not lay another one"*.)

The Q58 line-citation is the mechanism for the reason (o) and (o2) already
record: the `D` namespace is dense with zero holes, so no single-file mutation
can make a `D<n>` citation fail. Without (o3) the widening is proven on one
half only — which is the gap D116 R1 collapsed five constants to close, re-opened
from the test side.

Both cases are TOML-comment-shaped so the fixture leaves valid TOML while
staged; the harness reverts it either way.

### 7.3 Bookkeeping (orchestrator)

- **`TODO.md`** — the Q190 row: status line in §"Report back" item 3 below.
- **`tasks/Q.md` ### Q190** — a dated correction line in the entry's own voice:
  `.gitignore` carries **six** distinct ids in **seven** occurrences, not four;
  the three-file totals are **19 (id, file) pairs / 18 distinct ids / 29
  occurrences**, not *"seventeen citations"*; and the row scopes three root
  files where the census finds **five**. Per D117, a decided body takes a dated
  correction rather than silence.
- **`CHANGELOG.md`** — if the wave's convention adds one, note that five
  root-level files became citation surfaces and the swept count moved 359 → 364.
  `CHANGELOG.md` is itself swept, so any id written there must resolve.

---

## 8. Commands run, with verdicts

| command | verdict, by message |
| --- | --- |
| `python3 scripts/check-traceability.py --check` | **argparse error** — `unrecognized arguments: --check`, exit 2. **`--check` is not a flag of this script**; see §10 (f). |
| `python3 scripts/check-traceability.py` (flagless = all six) | **GREEN**: `check-traceability: ok (freeze-boundary, matrix, decisions, task-citations, task-entries, decision-owners)`; `[decisions] ok — 104 … across 359 files`; `[task-citations] ok — 391 … across 359 files`; `[task-entries] ok — 582 rows (581 live + 1 struck) against 582 entries` |
| `python3 scripts/check-traceability.py --task-citations`, **fault planted in `deny.toml`** | **GREEN — this is the defect**: `[task-citations] ok — 391 distinct task ids cited across 359 files, all resolve`, exit 0, with an unresolvable id in the tree |
| real `check_task_citations()` with the literal-entry sweep, same planted tree | **RED, by its own annotation**: `::error::check-traceability [task-citations] Q45 is cited (deny.toml) but has no row in TODO.md's register…` |
| four-rule simulation over the planted tree | baseline **silent**; three-named-suffix-unchanged **silent** (359 files, +0); `.toml`-only **silent** (365, `does it reach deny.toml? False`); `.toml`+named **caught** (366); per-entry rule **caught** (362) |
| both halves under the ruled semantics, five roots | `[task-citations] ok — 393 … across 364 files, all resolve`; decisions half `files=364 unresolved=[] registry-line-citations=[]` |
| `sha256sum deny.toml` before / after the plant | `d2a360db…658a8a` both times; `wc -c` 8654 both times; `grep -n Q45 deny.toml` exits 1 |
| `python3 scripts/check-traceability.py --self-test` | see §11 |
| `git status --short` | see §11 |

Every red above was read by its **message**, and every green by the check's own
`ok —` line, never by exit status alone.

---

## 9. What this does not do

- **It does not add `.toml` or `.txt` to `CITATION_SUFFIXES`.** The six
  `crates/*/Cargo.toml` (62 distinct task ids, all resolving) and the nine
  `crates/**/*.txt` (19 decision-id tokens, all resolving) remain unswept. §10 (a)
  and (b).
- **It does not touch `.github/`** (out by D116 §2 (c), and Q156's question) or
  anything under `docs/` beyond `docs/format` and `docs/testing` (Q181's
  question: the nine `.md` at the root of `docs/` are outside both sweeps with
  no recorded reason).
- **It does not reach `.cargo/config.toml`, `fuzz/` or `probes/`.** All three sit
  under no scan root at all, and the literal-file rule reaches dot-**files**, not
  dot-**directories**. §10 (c), (d).
- **It does not make `SPEC-REVIEW.md`, `MVP-SPEC.orig.md` or `TODO.md` citation
  surfaces.** R5.
- **It does not close the bare-above-ceiling blind spot**; the five new files
  inherit it. Measured: **zero** of the 69 distinct ids across them sit above
  their domain ceiling today, so the blind spot is currently empty on this
  surface — inherited, not fixed, and not a reason to widen tier 2 (green case
  (d) exists to make that a decision rather than an edit).
- **It does not check that a citation is apt.** The sweep proves an id
  *resolves*; it never proves the id is the *right* one. A `.gitignore` line
  attributing the fuzz corpora to the wrong registered task stays green.
- **It does not change `deny.toml`'s meaning to `cargo-deny`.** Nothing in the
  ruling edits that file; the self-test's mutation is a comment line, reverted
  by the harness.
- **It does not assert a floor on the swept file count.** 359 → 364 is legible
  because this document states it; nothing in the script does. §10 (e).

---

## 10. Discovered work — described, not registered

**(a) The six crate manifests under `crates/` are a 62-id citation surface no
sweep reads.** Measured: 12 / 18 / 26 / 10 / 2 / 1 distinct task ids in
`antseal-anchor` / `antseal-cli` / `antseal-core` / `antseal-net` /
`devnet-launcher` / `wasm-bitmatch`, **all allocated, none above ceiling, zero
would-fail**, plus decision ids in five of the six. Adding `.toml` as a
**directory-walk** suffix would land green today. It is a question about
`crates/`, deliberately not answered here, and after R4 it acquires its
strongest argument: the root manifest is swept and its members are not. Whoever
takes it should re-measure rather than trust these numbers — that is the whole
lesson of this row.

**(b) The nine `crates/**/*.txt` carry 19 decision-id tokens in real,
user-facing CLI copy** — 7 in `cli-errors.display.txt`, 11 in
`cli-surface.help.txt`, 1 in `json-envelopes.txt`, all resolving. But seven of
the nine are **golden snapshots**: making them a citation surface couples the
traceability lane to CLI-output regeneration, a trade nobody has decided. The
two `proptest-regressions/*.txt` are machine-written seed files with zero tokens
and are the standing argument against a blanket `.txt`. The decision is
*snapshots-yes/no*, not *`.txt`-yes/no*.

**(c) `.cargo/config.toml` carries four task ids and one decision id under no
scan root at all.** It is in a dot-*directory*, and `"."` as a root is refused
at the constant for reasons that still hold. Whether a dot-directory can ever be
a scan root is a question this ruling does not open.

**(d) `fuzz/` and `probes/` are outside `CITATION_SCAN` with no recorded
reason.** `fuzz/Cargo.toml` (10 task ids), `fuzz/rust-toolchain.toml` (1) and
`probes/sig-probe/Cargo.toml` (4 task ids, 2 decision ids) are unswept, and the
comment at the constant gives a reason for `docs/decisions/`, for `.github/`,
for `TODO.md` and for the two preserved spec artifacts — but says nothing about
these two directories. **The missing reason is the finding**, not the coverage:
an exclusion nobody wrote down is indistinguishable from one nobody made. Same
class as Q181.

**(e) The green line reports a file count and nothing asserts it.** D116 R3
chose the count over a floor deliberately, so a narrowing shows up only to a
reader who remembers the old number. Three partial widenings in three waves
(Q156, Q176, this one) make it worth asking whether a **minimum** swept-file
count belongs beside the reported one — as a constant with a comment saying what
last moved it, not as a magic number.

**(f) `--check` is not a flag of `scripts/check-traceability.py`.** This lane's
brief instructs `python3 scripts/check-traceability.py --check`; argparse
answers `unrecognized arguments: --check` and exits **2**, having run nothing.
The flagless invocation is what runs all six checks. A lane that reads exit 2 as
a verdict would be reading an argument error as a red lane — Q149's
exit-code-only failure in a new costume, and the second instance this wave of a
nonzero exit that is not a finding. Worth fixing wherever the lane-brief
boilerplate lives, and worth a line in `CONTRIBUTING.md` naming the flagless
invocation as the one CI runs.

**(g) The sweep loop is duplicated by hand, and this wave makes it three.**
D116 R1 collapsed five constants into one pair so the two sweeps could not
disagree — but it collapsed the *constants*, not the *loop*. The nine-line body
that resolves a scan root, filters it, prunes, excludes self and reads the text
is written out in full in `check_decisions()` and again in
`sweep_task_surfaces()`, held at parity by a comment saying so; and the
concurrent Q184 lane is adding a third copy in `scratch_decision_citations()`
whose docstring says it reads the constants *precisely so that it moves with the
check* — which the copied filter defeats. **One generator —
`iter_citation_files()` yielding `(relative_path, text)` — would make D123's
change a one-line edit at one site instead of an identical edit at three**, and
would make the next widening structurally incapable of reaching one sweep and
not the other. That is the same argument D116 R1 already won one level up, and
the reason to raise it now is that the third copy is being written this wave,
before anyone has had to maintain parity across three.

**(h) The hazard sentence named two of three files on the day it was written.**
Q176 wrote *"(`deny.toml`, `.gitattributes`)"* and `.gitignore` was in the same
state at the same moment. Nothing was wrong with the reasoning; the enumeration
was simply incomplete, and it stayed incomplete because a parenthetical is not a
list anything checks. That is the argument for R3's *delete, don't expand* and
for E4 putting the files in the constant rather than in prose about the
constant.

---

## Outcome

`CITATION_SUFFIXES` keeps its six members and its one job. `CITATION_SCAN`
starts meaning what it says: a named directory is walked and filtered, a named
file is **read**. Five root-level files — `Cargo.toml`, `deny.toml`,
`requirements-crosscheck.txt`, `.gitattributes`, `.gitignore` — carrying **69
distinct task ids and 22 distinct decision ids** between them (unions, measured,
not sums), none of which any instrument has ever read, join both sweeps in one
act: **359 → 364 files, 391 →
393 distinct task ids, zero collateral, zero new failures on either half.** Two
self-test cases pin the new property on both halves, one of them planting bare
because bare is the only form these files use. The hazard sentence Q176 wrote
about its own widening is deleted rather than grown, with a dated note of what
it said and why it stopped being true.

The row asked whether `.toml` should join the suffix set. The answer is that the
question was about a different directory: `.toml` reaches six crate manifests
and not one file the row names, and no suffix will ever reach a dotfile. What
the three files needed was not a wider filter but an exemption from a filter
that was never written for them.
