# D144 — The `/home/…` scrub and its lint: the Accept row is unsatisfiable, the privacy justification is false, and the whole live surface is two lines

- **Status: RESOLVED. Q65's Accept row *"The `/home/…` path scrub landed, with a
  lint so it cannot return"* is AMENDED because it cannot be executed, and the
  briefed lean is overturned in both halves — but not by the mechanism the brief
  expected.** The lean was *"scrub the live surfaces, leave the frozen spec and
  the historical records alone, and write the lint with an explicit allow-list of
  those exempt paths."*
  - **The allow-list half is refused outright.** An exemption whose remedy is
    *"add your file to the list"* is this project's dominant defect class wearing
    a register's clothes. The replacement is a **reserved-placeholder
    vocabulary**: five names (`user`, `fixture`, `runner`, `u`, `x`) that any
    contributor may use, so the remedy for a violation is *use a reserved name*,
    never *edit the lint*. Measured: that vocabulary already covers **27 of the
    29** home-path occurrences inside the live surface, with zero edits to any of
    them.
  - **The "scrub the live surfaces" half survives in direction and dies in
    scale.** The live surface is not something this record has to invent — it is
    `check-traceability.py`'s `CITATION_SCAN`, already reviewed, already ruled on
    the *live vs preserved* distinction (`:595-596`), already running on every
    push including a docs-only one. Inside it there are exactly **two**
    non-placeholder occurrences: `MVP-SPEC.md:42` and
    `scripts/wasm-pack-build.sh:46`. **The scrub is one edit, not 61.**
- **The brief's own hypothesis — that this is D139's unbuildable-frozen-block
  shape again — is REFUTED on measurement, and the refutation matters.**
  `MVP-SPEC.md` is covered by **no** digest (`docs/format/FROZEN.sha256` pins
  `registry-v1.{md,json}` and nothing else; `scripts/vector-freeze.sh` covers
  `testdata/vectors/v<n>/*.json`) and by **no** freeze-boundary block
  (`BOUNDARY_COPIES` is `tasks/Q.md`, `docs/format/anchor-artifact-limits.md`,
  `docs/user/format-stability.md`). Nothing mechanical would go red if line 42
  were edited today. **What actually forbids the edit is a protocol and a
  measured fragility, not an instrument** — and the fragility is worse than a
  freeze, because a freeze fails loudly: **1 707 line-number citations point into
  `MVP-SPEC.md` and not one of them is verified by anything** (`F44` is open and
  `Q58` was ticked with exactly this residual deferred to it). A line-count change
  in that file is a **silent** corruption of 1 707 citations, six of which are
  ranges that straddle line 42 itself.
- **The arm nobody listed, and the one this record takes: `MVP-SPEC.md:42` is not
  scrubbed, exempted, or flagged in prose — it is PINNED.** It becomes a
  registered still-present divergence in the lint's own register, anchored on its
  exact line **text**, asserted to occur exactly once. Edit it and the lint reds,
  demanding the register entry be deleted in the same act. Delete the entry while
  the line stands and the lint reds too. That is the `OWED_PRESENCE` /
  `ALLOWED_INLINE` discipline this repo already applies three times over — *"a
  debt that cannot go stale is an exemption, and exemptions rot"*
  (`scripts/check-copy-style.py:160-166`) — and it is the difference between a
  hole and a pin.
- **The privacy justification is REFUSED, and Q65's row may not be ticked on
  it.** Q65 says the scrub exists because the paths *"publish the maintainer's
  machine layout and local username."* Measured: `/home/deb` is present in the
  **published** history at the initial commit `01cdc83`, at the pushed tag
  `format-v1-freeze`, at `main~200` and at HEAD; **21** commits on `main` change
  its content; the remote carries `main` at `de71a09` — **544 commits, identical
  to this clone** — and the project has ruled no rewrite is warranted with a
  pushed tag in the way. Scrubbing HEAD removes the string from `git grep` on a
  fresh checkout and **from nothing else**. What the rule actually buys is
  machine-independence of live instructions, which is a real and durable property
  — so the row is amended to claim that instead of a confidentiality it cannot
  deliver.
- **Date: 2026-08-18**
- **Owning task: Q65** (whose Accept row 2 is amended here, verbatim replacement
  in §2 R1). The lint and the one edit are ruled onto a **new row**, described in
  full in §2 R8 and §5 without an id — ids are assigned centrally.
- Related: **D141** (the publish flip's ordering — this record rules the *content*
  of the scrub debt and deliberately rules nothing about when the flip happens),
  D139 (the copy lint's admission rules, and the byte-frozen-block precedent this
  record had to test and reject), D140 §2 R5 (the README row that is Q65's other
  precondition), D123/Q190 (the per-entry scan-root rule reused here verbatim),
  D116 §1.3 / D109 §3.3 (why `docs/decisions/` is not a lintable surface — the
  ruling this record extends from citations to paths), Q245 (the derived-fixture-
  count discipline the self-test copies), Q252 (a self-test fixture must
  *construct* its subject), Q58/**F44** (the unverified `MVP-SPEC.md` citation
  graph, §5 defect 5), Q251 (the collector for spec divergences at the M4 gate),
  Q2 (`secret-guard`, the host this record refuses and why).

---

## 1. The measurement

Every figure below was taken on 2026-08-18 against the working tree at
`de71a09`, which is also the remote's `main`. Commands are given inline.

### 1.1 Every figure the brief handed me, confirmed or corrected

| Figure | Recorded where | Recorded value | Measured 2026-08-18 | Verdict |
| --- | --- | --- | --- | --- |
| tracked files containing `/home/deb` | brief | 24 | **24** | **CONFIRMED** |
| lines containing it | brief | 61 | **61** | **CONFIRMED** |
| files / lines | `tasks/Q.md:938`, `TODO.md:822` (a 2026-08-17 correction of a recorded **five**) | 22 / 53 | **24 / 61** | **STALE — the fourth drift of this figure** |
| files / lines | `docs/reviews/pre-public-scrub-worktree.md:226,537` | 18 / 39 | **24 / 61** | **STALE — evidence, not to be rewritten (§2 R7)** |
| occurrences (not lines) | nowhere | — | **63** | new — two lines carry it twice |
| files in `docs/decisions/` or `docs/reviews/` | brief | 17 | **15** (12 + 3), carrying 41 lines | **CORRECTED** — see §1.2 |
| `MVP-SPEC.md:42` contains it | brief | yes | **yes**, verbatim, once in the file | **CONFIRMED** |
| `MVP-SPEC.md` is byte-frozen by a digest | brief (hypothesis) | possibly | **no instrument covers it** | **REFUTED** — §1.4 |
| `--matrix` resolves the matrix against `MVP-SPEC.md`'s line numbers | brief, from `tasks/Q.md:938` | yes | **no** — `check_matrix` opens `ROOT / MATRIX` and nothing else (`:399`); it resolves the *test references* a row names, and its "34 rows over 34 spec bullets" is counted off the matrix itself. `docs/testing/verification-matrix.md:5` does cite *"MVP-SPEC.md lines 165–175"* — in prose, parsed by nothing | **CORRECTED, and it makes things worse, not better**: the one place the record claimed a checker was guarding spec line numbers is guarding none. §1.5 (c) |
| `/home/deb` in history, no rewrite | brief | 116 blobs | **not re-derived**; present at `01cdc83`, `format-v1-freeze`, `main~200`, HEAD; 21 commits on `main` change it | **CONFIRMED in direction** — §1.6, falsifier f5 |
| `tasks/P.md:47` cites it as a Spec requirement | brief | yes | **yes**, on **P4, a discharged row**, as a *range* `lines 40–58` | **CONFIRMED, with the fact that changes the ruling** |
| the 24 files' breakdown | brief (partial) | `tasks/P.md` 3, `tasks/Q.md` 2, `TODO.md` 3, `wasm-pack-build.sh` 1, `ci-verification.md` 1, `wasm-toolchain.md` 4, `MVP-SPEC.orig.md` 1 | **all seven exact** | **CONFIRMED** |

```
$ git grep -l '/home/deb' -- . | wc -l      → 24
$ git grep -n '/home/deb' -- . | wc -l      → 61
$ git grep -o '/home/deb' -- . | wc -l      → 63
```

**So the brief is right and every figure in the record is wrong**, which is now
the fourth consecutive time this one number has drifted. §2 R7 rules that it
stops being written down as a number.

Two of Q65 finding 1's figures have also drifted since 2026-08-17 and are
corrected here for the same reason: whole-tree files citing `MVP-SPEC.md`
**434/435 → 441**; occurrences **1 996 → 2 078**. The load-bearing half —
**242** files across `crates/`, `scripts/`, `.github/` — is **exact and
unchanged**.

### 1.2 The full per-file breakdown, by class

24 files, 61 lines. The class column is this record's, and §2 R2 is where the
line between the classes is drawn.

| File | lines | Class | What the occurrence actually is |
| --- | --- | --- | --- |
| `MVP-SPEC.md` | 1 | **FROZEN** | `:42` — *"Cargo workspace, greenfield in `/home/deb/Documents/code0`:"* |
| `MVP-SPEC.orig.md` | 1 | **PRESERVED-BY-MANDATE** | `:39` — the same sentence in the reviewed original, kept verbatim so `SPEC-REVIEW.md`'s references resolve (`check-traceability.py:598-601`) |
| `docs/reviews/pre-public-scrub-worktree.md` | 8 | RECORD (the scrub's own evidence) | `:79` the detector table, `:223-227` S1's heading and finding, `:248-249` a captured `git grep` block, `:522` the untracked-set scan, `:537` the claims table |
| `docs/decisions/D91-…` | 6 | RECORD | `:392-397` — a captured six-row table of file/line locators, **three of them naming a second local checkout** `/home/deb/Documents/code0-m2-beta` (§5 defect 6) |
| `docs/wasm-toolchain.md` | 4 | RECORD (measurement) | `:320` the 52-occurrence embedding count; `:411-414` the three-row reproducibility table |
| `docs/reviews/pre-public-scrub-github-side.md` | 4 | RECORD (the scrub's own evidence) | `:128` the detector list, `:138` the canary description, `:167`/`:312` the result rows |
| `docs/research/dms-mortsafe-design-round.md` | 4 | RECORD | `:22,26,119,123` — absolute paths inside a design-round transcript (§5 defect 7) |
| `TODO.md` | 3 | REGISTER | `:822` Q65's row, `:1010` D135's row, `:1068` the wave-22 log — **all three are the record of this scrub** |
| `tasks/P.md` | 3 | REGISTER | `:47` P4's `Spec:` line, `:48` its `Do:`, `:282` the D3 decision row |
| `docs/reviews/pre-public-scrub-history.md` | 3 | RECORD (evidence) | `:161,225,230` — the history findings |
| `docs/decisions/D63-…` | 3 | RECORD | `:191,193` a shell transcript, `:1196` a results table |
| `docs/decisions/D3-repo-layout.md` | 3 | RECORD | `:9,10,15` — the repo-root ruling, stated in terms of the path |
| `docs/decisions/D132-…` | 3 | RECORD (measurement) | `:1053,1054,1056` a three-row probe table |
| `docs/decisions/D60-…` | 2 | RECORD | `:78,1020` absolute paths in two *"add this to"* instructions |
| `docs/decisions/D116-…` | 2 | RECORD | `:254,319` captured `file(1)` output |
| `tasks/Q.md` | 2 | REGISTER | `:938` Q65 finding 3, `:948` Q65's registrar note — **the record of this scrub** |
| `docs/decisions/D71-…` | 2 | RECORD | `:317,318` a `strings | grep -c` transcript |
| `scripts/wasm-pack-build.sh` | 1 | **LIVE** | `:46` — a comment inside a script contributors run |
| `docs/ci-verification.md` | 1 | RECORD (verbatim output) | `:18` — quoted cargo output, *"(overridden by '…/rust-toolchain.toml')"* |
| `docs/decisions/D72-…` | 1 | RECORD | `:531` quotes Q65's own (then-current) *"five tracked files"* |
| `docs/decisions/D140-…` | 1 | RECORD | `:683` names *"the `/home/deb` scrub"* as still owed |
| `docs/decisions/D136-…` | 1 | RECORD | `:208` a captured node stack trace |
| `docs/decisions/D135-…` | 1 | RECORD | `:377` a measurement sentence |
| `docs/decisions/D124-…` | 1 | RECORD | `:85` *"Every command below was run from `/home/deb/Documents/code0`"* |

Totals by class: **FROZEN 1 · PRESERVED-BY-MANDATE 1 · RECORD 50 · REGISTER 8 ·
LIVE 1** — 61.

**The brief's fifth figure is the one it got wrong.** It reads *"17 of the 24 are
`docs/decisions/*` or `docs/reviews/*`"*. Measured: **15** — 12 decisions and 3
reviews (`git grep -l '/home/deb' -- . | grep -cE '^docs/(decisions|reviews)/'`),
carrying **41** of the 61 lines. The figure that does the work is one step wider:
**all 18 `docs/` files carry exactly 50 lines**, and every one of them is class
RECORD. The direction of the brief's claim is right and its number is not.

**Three observations that decide §2.**

1. **Six of the 61 lines exist to record this very scrub**: `TODO.md:822` (Q65's
   row), `TODO.md:1068` (the wave-22 log), `tasks/Q.md:938` (finding 3),
   `tasks/Q.md:948` (the registrar's note), `docs/decisions/D140-…:683` (*"the
   `/home/deb` scrub … is Q65's"*) and `docs/decisions/D72-…:531`. A lint that
   reddens on them demands the deletion of its own mandate. This is not an edge
   case to be exempted; it is proof that the lint's subject cannot be *the string
   anywhere in the tree*.
2. **Three of the 24 files are `docs/reviews/pre-public-scrub-*.md`, whose paths
   are the evidence the scrub produced** (15 lines between them), and all 50
   record-class lines are captured transcripts, `file(1)` output, stack traces,
   measurement tables or dated findings. Rewriting them does not remove a
   disclosure — it **falsifies a measurement**, which is a strictly worse outcome
   than the one being avoided.
3. **Exactly one line, `scripts/wasm-pack-build.sh:46`, is a live instruction
   surface.** `MVP-SPEC.md:42` is the second candidate and is disposed of
   separately in §1.5.

### 1.3 The live surface already exists, and inside it the problem is two lines

`scripts/check-traceability.py:628-670` defines `CITATION_SCAN`, whose comment
spends thirty lines drawing exactly the line this record needs: *"The line is
drawn at **live** versus **preserved**, which is `docs/decisions/`'s distinction
one directory up"* (`:596`). `docs/decisions/`, `docs/reviews/`, `docs/research/`,
`TODO.md`, `tasks/*.md`, `MVP-SPEC.orig.md` and `SPEC-REVIEW.md` are all
**already out**, each with its reason recorded and ruled (D109 §3.3, D116 §1.3,
Q176, Q190/D123).

Scanning that root set — directories filtered by `CITATION_SUFFIXES`, literal
files unfiltered, the checker itself excluded per `CITATION_SCAN_SELF` — for
`/home/<name>`, `/Users/<name>` and `C:\Users\<name>` over every tracked file:

```
IN  CITATION_SCAN roots   29 occurrences in 10 files
      13  /home/user        7  /home/fixture     5  /home/u
       2  /home/deb         1  /home/x           1  /home/runner
OUT of scan roots         93 occurrences
      61  /home/deb        16  /home/runner     11  /home/user
       1  /Users/runner     1  /home/fixture     1  /home/u
       1  /home/x           1  /home/vault
```

The two in-scan `/home/deb` occurrences, in full:

```
MVP-SPEC.md:42                 Cargo workspace, greenfield in `/home/deb/Documents/code0`:
scripts/wasm-pack-build.sh:46  # `/home/deb/.cargo/registry`, **52 occurrences each**. Base64-expanded
```

The other 27 are deliberate placeholders and every one of them is already in the
vocabulary §2 R4 reserves: `/home/user/…` (13, all `antseal-cli` tests and their
JSON fixtures), `/home/fixture/…` (7, `work_store.rs`, `vault_export.rs`,
`wallet_record.rs`, `export.rs`), `/home/u` (5, `vault_store.rs`'s HOME-fallback
tests), `/home/x` (1, `ci-lanes.sh:743`'s planted `dep-graph` fixture),
`/home/runner` (1, `wasm-pack-build.sh:45`, the real GitHub Actions path).

**`.github/` carries zero home paths of any spelling** (`git grep -nE
'/home/[A-Za-z0-9._-]+|/Users/…' -- .github` → empty), so D116 §2 (c)'s
deliberate exclusion of `.github/` from `CITATION_SCAN` costs this check nothing
today. It is a falsifier, not a gap — §4 f3.

### 1.4 What is *not* frozen, measured — the brief's hypothesis fails

| Instrument | Covers | Covers `MVP-SPEC.md`? |
| --- | --- | --- |
| `docs/format/FROZEN.sha256` + `scripts/format-freeze.sh` | `docs/format/registry-v1.{md,json}`, by discovery (`registry_files()`) | **No.** Two digest lines, both `registry-v1.*` |
| `scripts/vector-freeze.sh` | `testdata/vectors/v<n>/*.json` | **No** |
| `check-traceability.py --freeze-boundary` | D84 §7 block in 3 `BOUNDARY_COPIES` | **No** |
| `security_assumptions_drift.rs` | `docs/security-assumptions.md` ↔ the marked block in `docs/threat-model.md` | **No** |
| `check-copy-style.py` | `COPY_SCAN` — README, the guide, `verifier-web/`, `docs/user/`, two snapshot dirs | **No** |

There is no fifth instrument. **`MVP-SPEC.md` is byte-frozen by nothing.** D139's
finding does not replicate: there, a live requirement sat inside a block a
*running drift test* pinned, so the flip was mechanically unbuildable. Here the
mechanism is absent and the constraint is entirely governance plus fragility —
which is why this record can rule on it at all, and why the ruling has to be
argued rather than measured off a red lane.

### 1.5 What actually makes `MVP-SPEC.md:42` untouchable

Four measurements, in ascending order of force.

**(a) It has never been edited.** `git log --numstat -- MVP-SPEC.md` returns
exactly one commit: `01cdc83` (2026-07-27), `189 0`. Not one byte has changed in
the project's life. Editing line 42 would be the first edit ever made to it.

**(b) The protocol says flag, not edit.** `TODO.md:3`: *"**Source of truth for
scope**: `MVP-SPEC.md` (Revision 2, 2026-07-27 — frozen…). When this list and
the spec disagree, the spec wins; flag the conflict, don't silently diverge."*
The tree applies this literally and repeatedly: `TODO.md:540` (A136) — *"the spec
is frozen, so that arm is a flag, never an edit"*; `TODO.md:836` (Q251) exists
solely to **collect** spec divergences for the M4 gate; and `tasks/P.md:62`
records a layout deviation as *"one RECORDED DEVIATION, taken now rather than
deferred to an **M4 spec amendment**"* — i.e. the project has already decided
that amending the spec is an M4 event, and has already chosen the flag over the
edit once.

**(c) The citation graph into it is large and verified by nothing.**

```
$ git grep -ohE 'MVP-SPEC\.md:[0-9]+' -- . | wc -l          → 123
$ git grep -ohE 'MVP-SPEC\.md lines? [0-9]+' -- . | wc -l   → 1584
```

**1 707 line-number citations.** `Q58` (`TODO.md:319`, ✅ 2026-07-28) converted
the *registry → registry* direction to sections and lints against a
reintroduction, and states its residual in the tick itself: *"the `MVP-SPEC.md
line <n>` direction is **F44**'s"*. `F44` (`TODO.md:174`) is **open**. There is
no anchor register in `check-traceability.py` and no check of any kind resolves
an `MVP-SPEC.md line <n>` citation. So a line-count change there fails
**silently**, at scale — the exact failure mode `Q58`'s own Discovered-by
paragraph describes happening twice unnoticed one document over.

**(d) Line 42 sits inside six cited ranges.** `MVP-SPEC.md lines 40–58`
(`tasks/P.md:47`, `:59`, `:72`) and `lines 44–58` (`docs/decisions/D3-…:8`,
`D34-…:42`, `D5-…:8`, `tasks/P.md:250`). An in-place, equal-line-count
replacement leaves all six valid; a reflow breaks all six and nothing notices.
The scrub review reached the same constraint independently
(`pre-public-scrub-worktree.md:252-255`), which is worth saying: two lanes, same
answer, from different directions.

**Line 42 is cited by exactly one site in the tree** —
`docs/reviews/pre-public-scrub-worktree.md:248`, which is captured `git grep`
output. Nothing else depends on its content. The exact bytes, for the pin:

```
Cargo workspace, greenfield in `/home/deb/Documents/code0`:
```

`grep -c 'Cargo workspace, greenfield in' MVP-SPEC.md` → **1**;
`grep -c '/home/deb' MVP-SPEC.md` → **1**. The anchor is unambiguous.

### 1.6 What publishing HEAD actually withholds — nothing

| Question | Measured |
| --- | --- |
| Remote refs | `refs/heads/main` = `de71a09` (identical to this clone), `refs/tags/format-v1-freeze` |
| Commits on `main` | **544** |
| Distinct author/committer identity | **1** — `aed900 <129773515+aed900@users.noreply.github.com>`, on all 544 |
| `/home/deb` at the initial commit `01cdc83` | **2 files** |
| `/home/deb` at `format-v1-freeze` | **5 files** |
| `/home/deb` at `main~200` | **5 files** |
| `/home/deb` at HEAD | **24 files** |
| Commits on `main` that change its content | **21** (`git log -S'/home/deb' --oneline main`) |
| History rewrite | ruled **not warranted**, `docs/reviews/pre-public-scrub-history.md`; the pushed `format-v1-freeze` tag is the cost |
| `/home/deb` in history | **116 distinct blobs across 20 paths** (history review, `:225`) |
| `deb` as a bare username token in tracked files | **0** (`USER=`, `LOGNAME=`, `deb@`, `~deb`) |

The GitHub identity `aed900` is public the instant the repository is, by
construction. The *unix* username `deb` is a distinct datum — and it is in the
first commit, in the pushed tag, and in 116 blobs that will publish regardless.

**Priced honestly: scrubbing HEAD moves `/home/deb` from "visible in `git grep`
on a fresh checkout" to "visible in `git log -S`, one command later". It buys
nothing that can be called confidentiality.** §2 R2 acts on that.

### 1.7 The two hosts the record suggests, both measured wrong

**`scripts/check-copy-style.py`** — nominated by the scrub review
(`pre-public-scrub-worktree.md:257-258`, *"is the natural host; nothing enforces
this today"*). `COPY_SCAN` is `README.md`, `docs/positioning-copy-style.md`,
`verifier-web/`, `docs/user/`, `crates/antseal-cli/tests/snapshots/`,
`crates/antseal-core/tests/snapshots/`. Classifying all 24 files against it:
**0 of 24 are inside it.** The nominated host would scan **none** of the
offending files, and neither of the two live sites. Its subject is also wrong —
`COPY_SCAN` is product *claims*, and a machine path makes no claim about a seal.

**`secret-guard`** (`scripts/ci-lanes.sh:1055`) — the tree's existing continuous
pattern scanner, and the model the scrub's own `abspath-homedeb` /
`abspath-anyuser` detectors were cut from. Two disqualifications, both structural:
its `ex()` helper is `grep -rlaE … --exclude='ci-lanes.sh' **--exclude='*.md'**`,
so it is blind to Markdown — **22 of the 24 files, and `MVP-SPEC.md:42` itself**;
and its verdict sentence is *"No real secret material may ever be committed
(project rule 6)"*. Q65's own text says the path *"is not a secret"*. Housing a
portability rule there would teach every future reader that a `/home/` path is a
credential finding. What it *does* contribute is its self-test discipline, which
§2 R7 copies wholesale.

### 1.8 Tree state at the time of writing

`python3 scripts/check-traceability.py` (flagless, read-only) exits **1** with
**2** problems, both `[decision-index]`: `D141` and `D142` have records and no
index rows. That is the known mid-act window — a record file landing before the
registrar applies its index row (D119 RULING 6; already in
`docs/instrument-ledger.md`). **This record will make it three until its own
index row lands** (§2 R9). Every other check is green: `[freeze-boundary]` 3
copies · `[matrix]` 34 rows / 118 references · `[decisions]` 132 decisions across
452 files · `[task-citations]` 438 ids · `[task-entries]` **679 rows / 679
entries** · `[decision-owners]` 2 assignments.

---

## 2. The ruling

### §2 R1 — Q65's Accept row 2 is AMENDED. Replacement text, verbatim

The row as written cannot be executed by anyone. *"The `/home/…` path scrub
landed"* demands 61 line edits; **59** of them are captured evidence, preserved
records, the register that mandates the scrub, or a spec that has never been
edited — and *"a lint so it cannot return"* demands a check that would redden on
all 59 the moment it was written. Amend it. **Owner: the registrar** (a lane
resolving this may not edit `tasks/*.md`).

Replace the single line at `tasks/Q.md` Q65 `- Accept:` row 2 with:

```
  - **The machine-path rule landed at the live sites, with a lint whose remedy is
    never an exemption** *(AMENDED 2026-08-18 by D144 §2 R1; the row this replaces
    read "The `/home/…` path scrub landed, with a lint so it cannot return" and was
    unsatisfiable — of the 61 lines it demanded, 50 are captured evidence or dated
    records, 8 are register rows (six of which record this very scrub), 2 are the
    frozen spec and the preserved original, and exactly ONE is a live instruction)*:
    - `scripts/wasm-pack-build.sh:46` no longer names a developer's home directory,
      and the 3-byte path-length datum its own arithmetic depends on survives the edit.
    - `MVP-SPEC.md:42` is **NOT edited**. It is registered as a still-present,
      still-owed divergence, pinned by its exact line text and asserted to occur
      exactly once; the lint reds if that text changes or vanishes without the
      register entry going with it, and reds if the entry is deleted while the line
      stands. The spec is frozen: the protocol flags divergences, it does not edit
      them (`TODO.md:3`; precedent `tasks/P.md:62`, A136, Q251).
    - The lint scans the live-surface partition (`check-traceability.py`'s
      `CITATION_SCAN`, minus `MVP-SPEC.md`, minus the checker itself) and bans any
      absolute home path — `/home/<name>`, `/Users/<name>`, `C:\Users\<name>` —
      outside a closed reserved-placeholder vocabulary (`user`, `fixture`, `runner`,
      `u`, `x`). A contributor's remedy is to use a reserved name; adding a path to
      an exemption list is not available, because there is no such list.
    - Its self-test CONSTRUCTS every subject (Q252), plants one fault per rule arm
      with the fixture count DERIVED from the fixture list (Q245), and asserts each
      arm on the message that fault produces, never on exit status (Q149).
    - **This row may NOT be ticked on a confidentiality claim.** `/home/deb` is in
      the published history at `01cdc83`, at `format-v1-freeze` and at HEAD; 21
      commits on `main` change it; no rewrite is warranted
      (`docs/reviews/pre-public-scrub-history.md`). What the rule buys is
      machine-independence of live instructions, and this row says so rather than
      claiming a privacy it cannot deliver.
```

### §2 R2 — The class boundary, stated once so it can be applied without rediscovery

Three classes, and the rule for each. This is the boundary every subsequent
ruling appeals to.

1. **LIVE** — text that instructs a reader about the repository as it is now:
   scripts, code, product copy, the M4 user docs, the front-door files. **Scrub
   and lint.** Today: `scripts/wasm-pack-build.sh:46`.
2. **RECORD** — captured evidence and dated findings: transcripts, tool output,
   stack traces, measurement tables, decision records, reviews, research rounds,
   and the register rows that record the work. **Never edited, never linted.**
   Editing a transcript does not remove a disclosure, it destroys a measurement —
   and eight of these lines are the record of this scrub, so a lint over them
   would demand the deletion of its own mandate. Corrections here go by **dated
   addendum**, the practice `docs/instrument-ledger.md`'s header states
   (*"Append-only — a correction is a new entry naming the entry it corrects,
   never an edit"*) and that Q65's own Notes already follow.
3. **FROZEN / PRESERVED-BY-MANDATE** — `MVP-SPEC.md` and `MVP-SPEC.orig.md`.
   **Neither edited nor silently exempted: pinned** (§2 R5).

The boundary is not this record's invention and does not need a new list to
express: `CITATION_SCAN` already draws it, for citations, with every exclusion
reasoned in place. §2 R6 reuses it rather than restating it, because *"the only
honest comment on two [lists] here would be 'these are the same, one is stale'"*
(D116 R1).

### §2 R3 — The one live edit. Exact text

**File:** `scripts/wasm-pack-build.sh`, lines 45–46. **Who:** the lane that
takes the new row in §2 R8. Current bytes:

```
# builder's absolute $CARGO_HOME — `/home/runner/.cargo/registry` against
# `/home/deb/.cargo/registry`, **52 occurrences each**. Base64-expanded
```

Replace with, exactly two lines so the surrounding comment block does not reflow:

```
# builder's absolute $CARGO_HOME — `/home/runner/.cargo/registry` against a
# three-characters-shorter local one, **52 occurrences each**. Base64-expanded
```

**The constraint that makes this a ruling and not a chore:** lines 50–52 of the
same comment do arithmetic on this datum — *"52 x 3 B of path-length predicts
156 B against 192 B measured"*. The 3-byte delta is `/home/runner` (12) minus
`/home/deb` (9). Any replacement that drops the length relation falsifies the
paragraph below it. `$CARGO_HOME` alone is **not** an acceptable substitute for
that reason; a reserved placeholder such as `/home/user` is not either, because
it is 10 characters and would make the arithmetic wrong by one.

`docs/reviews/pre-public-scrub-worktree.md:241` cites this line as
`scripts/wasm-pack-build.sh:46`. That citation is **dated evidence and is not
repaired**: it will describe a line that no longer reads that way, exactly as
D139 §C's 28 locators were invalidated by the work D139 existed to enable. If the
executing lane wants the pointer to stay useful, the permitted form is a dated
addendum in the review, never a rewrite of `:241`.

### §2 R4 — The lint's rule: a reserved vocabulary, not an exemption list

**Banned in a scanned file:** an absolute home path in any of the three platform
spellings —

```
/home/<name>/         /Users/<name>/         C:\Users\<name>\
```

— where `<name>` is not in the reserved set.

**Reserved placeholder names (the complete set):** `user`, `fixture`, `runner`,
`u`, `x`.

Why this is not the allow-list under another name, stated so it can be checked
rather than believed:

- **The remedy for a violation is to change the code.** A contributor whose test
  writes `/home/alice/notes.md` fixes it by writing `/home/user/notes.md`. They
  never touch the lint. An allow-list's only remedy is to touch the lint, which
  is why allow-lists grow monotonically and why *"a check green because nothing
  reachable could redden it"* is this project's dominant defect class.
- **It does not grow with violations.** It grows only when a genuinely new
  *placeholder role* is needed, which has happened five times in a year. The
  set's size is `O(roles)`, not `O(files)`.
- **Adding a name is guarded.** The set is asserted against a derived count in
  the self-test (§2 R7), so a sixth name cannot land without its own fixture in
  the same act — the Q245 shape, applied one level up from where Q245 applied it.
- **Every current use is already covered.** 27 of 29 in-scan occurrences, zero
  edits (§1.3). If a reserved vocabulary were the wrong instrument, that number
  would not be 27.

The anchoring detail, because it is where a naive pattern goes wrong: the match
must require the **trailing separator or end-of-token** after `<name>`, so that
`/homework/`, a bare `/home`, `$HOME/...` and `~/...` do not match. §2 R7 plants
all four as green controls.

**Refused explicitly: a lint on the literal `/home/deb`.** It protects exactly
one machine, is green for every other contributor from the day it lands, and is
therefore a check that cannot fail for anyone but its author — the defect class
by name. The brief asked whether `/home/deb` is the right thing to lint for. It
is not, and this is why.

### §2 R5 — `MVP-SPEC.md:42` is PINNED, not edited and not exempted

The register entry, in the check:

```python
# A machine path that is present ON PURPOSE and may not be removed, with the
# reason it may not and the row that owns the divergence. This is a PIN, not
# an exemption: the check asserts the text is STILL THERE, verbatim and
# exactly once. Repair the line and the check goes RED demanding this entry
# be deleted in the same act; delete the entry while the line stands and it
# goes RED the other way. A debt that cannot go stale is an exemption, and
# exemptions rot (check-copy-style.py OWED_PRESENCE, check-ci-shell.py
# ALLOWED_INLINE, verdict_wording.rs RESIDUE — the same discipline, third
# instrument).
#
# Anchored on TEXT, never on a line number: D139's 28 locators into
# docs/threat-model.md died inside the wave that wrote them.
KNOWN_MACHINE_PATH_DIVERGENCE: dict[str, tuple[str, str]] = {
    "MVP-SPEC.md": (
        "Cargo workspace, greenfield in `/home/deb/Documents/code0`:",
        "Q65 / D144 §2 R5 — the spec is frozen (TODO.md:3: the spec wins, the "
        "conflict is FLAGGED, not silently diverged). MVP-SPEC.md has one commit "
        "in its life (01cdc83, 189 lines added, zero changed since), 1 707 "
        "line-number citations point into it and F44 measures that NOTHING "
        "verifies one of them, and line 42 sits inside six cited ranges "
        "(lines 40-58, lines 44-58). Amending the spec is an M4 event "
        "(tasks/P.md:62's RECORDED DEVIATION took the flag over the edit for "
        "the same reason). If a spec amendment is ever taken, it is an "
        "IN-PLACE, EQUAL-LINE-COUNT replacement on line 42 or it corrupts all "
        "six ranges silently.",
    ),
}
```

Three assertions, three distinct messages (§2 R7 lists them). The pin also
asserts that `MVP-SPEC.md` contains **no other** home path, so the entry can
never widen into a blanket file exemption — which is precisely what an
allow-list entry would have been.

**Why not simply edit it in place?** Because it is mechanically safe and
governance-wrong, and this record will not trade the second for the first. The
equal-line-count edit provably breaks nothing (§1.5 d). But `MVP-SPEC.md` has
never been edited; the protocol names flagging as the response to a spec
conflict; A136 and Q251 both took the flag within the last three weeks; and the
citation graph that would have caught a mistake **does not exist** (F44). Taking
the first-ever spec edit — for a cosmetic reason, in a wave with five other lanes
in the same tree, over an unverified 1 707-citation graph — is a precedent
bought at a price nobody priced. The pin gets the durable property (the line can
never change unobserved again) without the precedent.

**If the maintainer wants the sentence repaired anyway**, that is an M4 spec
amendment, it belongs on Q251's collector with the other divergences, and the
permitted form is fixed: in place, on line 42, `wc -l MVP-SPEC.md` unchanged at
**189**, asserted in the same act. This record does not authorise it.

### §2 R6 — Host: an eighth check in `check-traceability.py`, riding the existing lane

`--machine-paths`, added to the seven checks already in
`scripts/check-traceability.py`, run by the flagless invocation like every other.

Four reasons, each measured:

1. **The live-surface partition is already there and already ruled.** Reusing
   `CITATION_SCAN` means no new scan-root list, no second list to hold in step
   with the first (D116 R1's refusal), and — the property that matters most —
   **any new file in a scanned root is covered from its first commit**, which is
   D139 §1.4's measured argument for a directory entry over per-file
   registration.
2. **It adds no required status context.** Memory of the wave: hosted CI refuses
   every job on an exhausted allowance, and *no required context may be added*
   until Q65's flip restores free minutes for a public repository. A new script
   would want a lane; this wants nothing.
3. **It runs on exactly the pushes that matter.** The `traceability` lane lives
   in `.github/workflows/ci-always.yml`, which is *"filtered by nothing"* and
   whose header states the inversion: for this lane a docs-only push is *"its
   BUSIEST case, not its emptiest"* (D138 §2). A `/home/…` path re-enters this
   tree through a doc, and a doc push is precisely when `ci.yml` is skipped.
4. **Python stdlib only, no cargo.** `check-traceability.py`'s own docstring
   pins that property and D124/Q182 assert the job invokes no cargo. A path lint
   needs nothing more.

**The one place `CITATION_SCAN` is not reused verbatim, and its guard.**
`MVP-SPEC.md` is a `CITATION_SCAN` literal entry (a citation into it must
resolve — correct) but is *preserved* for content. So:

```python
PATH_SCAN_EXCLUDES = {"MVP-SPEC.md"}   # pinned instead, see KNOWN_… above
PATH_SCAN_REQUIRED = {"crates", "scripts", "verifier-web", "docs/user",
                      "README.md", "CONTRIBUTING.md", "CHANGELOG.md"}
```

`PATH_SCAN_REQUIRED` is the coupling guard, and it is the answer to the obvious
objection that reusing another check's constant lets a future edit made for
citation reasons silently shrink path coverage. **Widening `CITATION_SCAN` is
always safe** (more surface). **Narrowing it is not**, so the check asserts each
required root is still present and reds by name if one is removed. Falsifier f2
is the test that this guard is real.

### §2 R7 — The lint's exact shape: messages, planted faults, controls

**Four failure messages**, each distinct, each naming its own fault — the
`scripts/lib/red-arm.sh` rule (*"A RED ARM MUST MATCH ON THE MESSAGE THE CHECK
PRINTS WHEN IT FINDS THE PLANTED FAULT, NOT ON THE EXIT STATUS ALONE"*):

```
M1  ::error::check-traceability [machine-paths] {rel}:{line}: absolute home path
    `{hit}` in a live surface. Live instructions must not name a developer's
    machine — use a reserved placeholder name (user, fixture, runner, u, x) or a
    $HOME-relative path. There is no exemption list to add this file to (D144 §2 R4).

M2  ::error::check-traceability [machine-paths] MVP-SPEC.md: the registered
    divergence text is no longer present verbatim — the file was edited or the
    anchor moved. If the edit was deliberate, delete the KNOWN_MACHINE_PATH_
    DIVERGENCE entry in the same act; if it was not, revert it. The spec is frozen
    and the protocol FLAGS divergences rather than editing them (TODO.md:3, D144 §2 R5).

M3  ::error::check-traceability [machine-paths] MVP-SPEC.md: the registered
    divergence text occurs {n} times, not once — the pin cannot identify its
    subject (D144 §2 R5).

M4  ::error::check-traceability [machine-paths] CITATION_SCAN no longer contains
    `{root}`, so this check silently stopped scanning it. Restore the root, or give
    this check its own root list in the same act (D144 §2 R6).
```

A fifth message covers the pin's other direction — a registered file that no
longer carries **any** machine path, i.e. the entry has gone stale and must be
deleted. It is folded into M2's wording deliberately: one message, one remedy.

**Faults to plant in `--self-test`, all CONSTRUCTED (Q252) in the staged tree,
never found in it** — the harness already stages a copy; every subject below is
written by the fixture, so draining the tree of violations can never disarm it:

| # | Planted into the staged copy | Required |
| --- | --- | --- |
| 1 | `crates/antseal-cli/tests/__machine_path_probe.rs` containing `"/home/nonesuch/work/a.txt"` | **RED**, M1, naming `/home/nonesuch` and that path |
| 2 | same file, `"/Users/nonesuch/work/a.txt"` | **RED**, M1 — the macOS arm has **zero** live occurrences, so without this it is an assertion that cannot fail |
| 3 | same file, `"C:\\Users\\nonesuch\\work"` | **RED**, M1 — same reason, zero live occurrences |
| 4 | same file, `"/home/user/work/a.txt"` | **GREEN** — the reserved vocabulary is live, not decorative |
| 5 | same file, `"/homework/notes"`, `"/home"`, `"$HOME/x"`, `"~/x"` | **GREEN** — the near-miss set; proves the pattern is separator-anchored |
| 6 | append ` AND ONE WORD MORE` to staged `MVP-SPEC.md` line 42 | **RED**, M2 |
| 7 | duplicate staged line 42 | **RED**, M3 |
| 8 | call the check with `PATH_SCAN_REQUIRED`'s `"scripts"` removed from the passed root list | **RED**, M4 |
| 9 | a violation planted in `docs/decisions/`, `docs/reviews/`, `tasks/`, `TODO.md` and `MVP-SPEC.orig.md` | **GREEN**, all five — the preserved classes are out of scan **by assertion**, not by nobody having checked |

**Fixture count is DERIVED, never written down** (Q245): `planted =
len(fixtures)`, and the number of pattern arms is read off the rule table so an
arm added without a fixture fails the self-test with its own message rather than
letting the totals balance. Case 9 is the arm this project would otherwise
skip and is the one that makes §2 R2's class boundary a measured property.

**The checker excludes itself.** `check-traceability.py` will contain
`/home/deb` (the pin's anchor text) and every banned pattern. `CITATION_SCAN_SELF`
already exists for exactly this reason and already carries the *"documenting the
trap does not lay another one"* note; `check-copy-style.py` and `ci-lanes.sh`
(`--exclude='ci-lanes.sh'`) do the same. Third instrument, same shape.

### §2 R8 — The work is ONE new row. Full description; orchestrator assigns the id

- **Title:** *The machine-path rule: one live edit, one pin, and the lint that
  keeps live instructions machine-independent.*
- **Domain:** Q. **Size:** S. **Milestone:** M4.
- **After:** nothing. Blocks **Q65**'s amended Accept row 2 and therefore the
  visibility flip.
- **Do:** (1) the `scripts/wasm-pack-build.sh:45-46` edit at §2 R3, preserving the
  3-byte datum; (2) `--machine-paths` in `scripts/check-traceability.py` per §2 R4
  / R6 / R7, including `KNOWN_MACHINE_PATH_DIVERGENCE`, `PATH_SCAN_EXCLUDES`,
  `PATH_SCAN_REQUIRED` and the nine self-test cases; (3) one line in
  `docs/positioning-copy-style.md`'s neighbourhood **or** `CONTRIBUTING.md`
  stating the reserved-placeholder vocabulary where a contributor will meet it
  before the lint does.
- **Accept:**
  - `python3 scripts/check-traceability.py` green with `[machine-paths]` reporting
    its scanned-file count and its zero.
  - `--self-test` red on cases 1, 2, 3, 6, 7, 8, each **by its own message**;
    green on 4, 5, 9.
  - `MVP-SPEC.md` byte-identical to `01cdc83` (`sha256sum` recorded in the row's
    Notes, `wc -l` = 189).
  - The reserved vocabulary is documented on a surface a contributor reads.
  - **No exemption list exists in the implementation.** A reviewer can grep for
    one and find nothing.
- **Notes must carry the evidence in the row itself**, not only in the wave
  transcript: the `[machine-paths]` line from the green run, the six red messages,
  and the `MVP-SPEC.md` digest.

### §2 R9 — This record's own index row

`docs/decisions/README.md` gains one row for D144, in ascending id order, with
this record's status word and date — added by the **registrar**, in the act that
commits the record (D119 RULING 6). Until then `[decision-index]` is red for
D144 as it is today for D141 and D142 (§1.8). That is the known window, not a new
defect, and it is named here so no one re-discovers it.

---

## 3. What this record refused

**The allow-list, which is the half of the lean this record kills.** An
`EXEMPT_PATHS` list would have had 17 entries on day one, would have grown by one
per future record that quotes a transcript, and every entry would have been added
by the person whose change made it necessary. The project's own instruments say
why that is not acceptable — `check-copy-style.py:160-166` on `OWED_PRESENCE`,
`check-ci-shell.py`'s `ALLOWED_INLINE`, `verdict_wording.rs`'s `RESIDUE`: *"A debt
that cannot go stale is an exemption, and exemptions rot."* What replaces it is
two instruments that cannot rot: a **reserved vocabulary** whose remedy is in the
contributor's file, and a **pin** that is asserted still-present in both
directions.

**The privacy framing.** Refused on §1.6, and refused specifically as a *tick
criterion*: a row ticked with *"the maintainer's machine layout is no longer
published"* would be a false statement in the register of a project whose product
is evidence. The work survives on a different and honest justification.

**A blanket substitution over the 61 lines.** It would falsify 50 captured
measurements and dated findings, rewrite 8 register rows — six of which are the
record of the scrub itself — into unreadability, edit two documents the
project has ruled unmodifiable, and — the detail that settles it —
`MVP-SPEC.orig.md:39` **can never be scrubbed at all**, because it exists to be
unedited so `SPEC-REVIEW.md`'s references resolve (`check-traceability.py:598-601`).
A blanket rule with a permanently unreachable member is not a rule.

**`check-copy-style.py` as the host**, against the scrub review's own
recommendation, on 0-of-24 coverage (§1.7). **`secret-guard` as the host**, on the
`--exclude='*.md'` blind spot and on subject mislabelling (§1.7). **A new
standalone script**, because it would want a lane and a context in the one month
where no context may be added.

**A lint on the literal `/home/deb`** (§2 R4) — protects one machine, cannot fail
for anyone else.

**A naive "any home path" lint without a vocabulary** — 29 in-scan occurrences,
**27 false positives**, a 93 % false-positive rate on the corpus it would police.
The brief was right that a single-username literal is too narrow; the correction
is not to widen the pattern alone but to widen it *and* reserve the vocabulary.

**Editing `MVP-SPEC.md:42`** (§2 R5), and with it the brief's suggestion that the
correct target might be *"the one line that made the path normative"*,
`tasks/P.md:47`. That line reads `- Spec: Architecture — "greenfield in
/home/deb/Documents/code0" (MVP-SPEC.md lines 40–58)` on **P4, a discharged row**
whose requirement was met when the repository was created. Rewriting a discharged
row's `Spec:` line edits the record of what was required at the time — class
RECORD, §2 R2 — to remove a string that stays in the spec regardless. It buys
nothing and costs a falsified record.

**A `.mailmap`-style indirection, or a note at the top of the repo.** Refused on
measurement: `README.md` and `CONTRIBUTING.md` contain **no clone instruction and
no path of any kind** (`grep -nEi 'clone|workspace root|cd '` → empty in both).
There is no live instruction misdirecting a contributor to `/home/deb/...`, so a
note would create a claim where none exists and give a reader a correction to a
mistake they were never at risk of making. The one place the path could mislead —
`MVP-SPEC.md:42` — is dated, revision-stamped and frozen, and reads as history.

---

## 4. Falsifiers

**f1 — The pin is only as good as its anchor.** If `MVP-SPEC.md:42`'s sentence is
ever legitimately amended, M2 fires and someone must delete the register entry.
If they instead *update the anchor text* to match the new line, the pin degrades
into an exemption silently. Test: after any M2 red, the resolving commit must
either delete the entry or be a spec amendment recorded on Q251 — never a
one-line anchor edit. **Falsified if a commit is ever found that edits the anchor
string and nothing else.**

**f2 — The `CITATION_SCAN` coupling.** `PATH_SCAN_REQUIRED` guards removal of
seven roots. It does **not** guard a narrowing of `CITATION_SUFFIXES` (dropping
`.rs` would blind the check to every test fixture while leaving all seven roots
present) nor a change to D123's per-entry semantics. **Falsified if
`CITATION_SUFFIXES` ever shrinks without `[machine-paths]` reporting a lower
scanned-file count** — which is why §2 R8's Accept requires the count be printed
and recorded, not just the zero.

**f3 — `.github/` is out of scan and carries zero home paths today.** Both halves
are measured. If a workflow ever hardcodes one, this check will not see it and
`check-ci-shell.py` does not look for paths. **Falsified the first time
`git grep -E '/home/[A-Za-z0-9._-]+' -- .github` is non-empty**; the fix is D116
§2 (c)'s question reopened, not an exemption.

**f4 — The reserved set could be gamed.** Nothing stops a contributor naming a
real directory `/home/user/...` that is not a fixture. The check cannot tell a
placeholder from a real path with a placeholder-shaped name. This is accepted:
the property being protected is *"no live instruction names a specific
developer's machine"*, and a reserved name names nobody.

**f5 — The history claim.** §1.6 rests on `git log -S`, four sampled revisions,
and the history review's 116-blob figure, which this record did **not**
re-derive (a full-history blob grep over 166 MB was judged not worth the wave's
time). **Falsified if a full rev-list scan finds zero `/home/deb` blobs
unreachable from the current index** — in which case scrubbing HEAD *would* be a
confidentiality act and §2 R2 must be revisited. The four sampled revisions make
that outcome very unlikely.

**f6 — 1 707 citations, counted by regex.** `git grep -ohE 'MVP-SPEC\.md lines?
[0-9]+'` counts a range like `lines 40–58` once and does not verify any of them
resolve — that is F44's job and F44 is open. The figure is an upper bound on
*sites* and a lower bound on *affected line numbers*. **Falsified only in
magnitude**, not in direction: the argument in §1.5 needs the number to be large
and unverified, and both are established independently by F44's existence.

**f7 — This ruling assumes the flip still happens.** If Q65 resolves to *stay
private*, the machine-independence justification survives (it never depended on
publication) but the urgency does not, and the new row drops off Q65's critical
path. D141 owns the ordering; this record deliberately owns none of it.

---

## 5. Defects found that are not this decision's subject

1. **The `/home/deb` figure has now drifted four times and is still being written
   down as a number.** `five` → `22 files, 53 lines` (`tasks/Q.md:938`,
   2026-08-17) → `18 files, 39 lines` (`pre-public-scrub-worktree.md:226,537`,
   2026-08-16) → **24 files, 61 lines** today. Every recorded value is wrong and
   they disagree with each other. **Recommendation (registrar):** replace the
   number in Q65 finding 3 with the *command*, `git grep -n '/home/deb' -- . | wc
   -l`, plus a dated *"was 24/61 on 2026-08-18"* — the same move D140 §2 R5b made
   when it deleted the README's task count rather than updating it. A figure that
   has drifted four times is not a figure, it is a query someone keeps
   memoising.

2. **Q65 finding 1's whole-tree figures are stale by one day.** `434/435 tracked
   files` → **441**; `1 996 occurrences` → **2 078**. The load-bearing `242` is
   exact. Same remedy as defect 1.

3. **`docs/reviews/pre-public-scrub-worktree.md:257-258` names a host that would
   scan none of its own findings.** *"`scripts/check-copy-style.py` is the natural
   host; nothing enforces this today."* Measured: 0 of 24 files are inside
   `COPY_SCAN`. Class RECORD, so the correction is a **dated addendum**, not an
   edit — and it is worth making, because the next lane to read S1 would
   implement it.

4. **`docs/reviews/pre-public-scrub-worktree.md:537`'s claims table is itself now
   stale** in two of three rows (`18 files, 39 lines` → 24/61; `433 tracked files`
   → 441). Same remedy.

5. **F44 is the largest instrument gap this lane touched, and it is open.**
   `1 707` line-number citations into `MVP-SPEC.md`, verified by **nothing**, in a
   project whose `--decisions` check exists precisely to stop line-number citations
   into a *frozen* document from rotting. Q58 shipped the registry half and
   deferred this one explicitly. The asymmetry is stark: the registry, which is
   digest-frozen and therefore cannot move, is protected; the spec, which is
   protected by convention alone and has 14× the citations, is not. **This is the
   real reason `MVP-SPEC.md` cannot be edited**, and it will remain so until F44
   lands. Recommend F44 be re-priced against Q34 rather than left at `(S)`.

6. **`docs/decisions/D91-…:395-397` publishes a second local checkout's path**,
   `/home/deb/Documents/code0-m2-beta`, three times — disclosing not just a home
   directory but the existence and name of a separate working copy. Class RECORD,
   so it is not scrubbed; but it belongs in **Q65's Accept row 1**, the per-file
   `public`/`private`/`private-until-release` classification, which has not yet
   been written and which is the row that can legitimately decide a whole file's
   disposition. Flagged there, not here.

7. **`docs/research/dms-mortsafe-design-round.md` has no publication
   classification and is the one file in the 24 that looks like the material Q65
   itself calls genuinely private.** It records a 9-agent design round for a
   custody/dead-man's-switch layer *"strictly additive above the frozen v1
   format"* — i.e. unshipped product direction. Q65's own text says *"the
   genuinely private material is commercial timing, not security."* Accept row 1's
   territory, and it should not be discovered at the moment of the flip.

8. **`README.md` and `CONTRIBUTING.md` contain no clone instruction, no build
   invocation and no path at all.** Measured while refusing the indirection note
   (§3). For a repository about to be made public and to ask strangers to audit
   its verifier, *"how do I get and build this"* being absent from both front-door
   files is a gap — Q22's, not this record's, and worth naming before the flip
   rather than after.

9. **`docs/ci-verification.md:18` quotes a toolchain-override message containing
   the maintainer's path, and it is the runbook Q65's Accept row 3 points at** for
   recording the flip ordering. It is class RECORD (verbatim tool output) and
   stays. Named only so that the lane executing Accept row 3 does not "helpfully"
   scrub it on its way past.

10. **`scripts/check-copy-style.py --self-test` stages a full tree copy**
    (`stage(root, dest)`, `:631`), exactly as `check-traceability.py --self-test`
    and `local-gate.sh` do. It is therefore in the same banned-mid-wave class, and
    the wave brief's prohibition list names only the latter two. Worth adding to
    the standing list so it is not discovered by a race.
