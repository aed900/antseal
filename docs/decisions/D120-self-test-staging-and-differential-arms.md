# D120 — Q191: which tree `--self-test` stages, and why the staging choice alone cannot fix it

- **Status: RESOLVED — the self-test keeps exercising the WORKING tree, but
  stages only what git can see in it, and its arms become DELTAS against a
  measured baseline; the snapshot options are refused and the row's own
  objection is why.** Q191 frames the deliverable as *"which tree did the red
  arm actually exercise?"* and offers four staging mechanisms. **Measured, the
  question is answerable and the four mechanisms do not answer it**, because
  the failure the row is trying to kill is not produced by the red arms at all.
  It is produced by the **green** arms.
  **All 27 cases were counted: 19 red and 8 green, and every one of the six
  checks has at least one green arm.** A green arm asserts that
  `--<check>` exits 0 with its mutation applied — which is an assertion that
  the staged tree is otherwise clean on that check. Eight such arms across six
  checks means **`--self-test` silently re-runs the entire check suite over a
  copy of the tree**, and inherits every unrelated red in it. That is the
  self-healing red, and no choice of tree removes it while the arms are
  absolute.
  **Reproduced twice, once by accident.** A sibling lane registering a row
  before writing its entry — the ordinary wave-15 act — turns `--self-test` red
  with two messages that name *green-case mutations of `TODO.md` and
  `tasks/P.md`* and never name the row. Then this lane left two scratch `.py`
  files in `scripts/` and reddened its own harness a second time, with three
  messages naming two crate files it had not touched. Both healed on removal.
  **The gate makes it worse than the row says.** `lane_traceability` runs
  `--self-test` first and `return 1`s on failure, so the flagless check — which
  names the real cause in one exact sentence — **never runs**. Measured: the
  planted id appears **zero** times in the whole lane output, and the lane's own
  annotation says *a check stayed green over corrupted input* when what happened
  was a check going **red where it had to stay green**. The gate reports the
  inverse of the observed failure.
  **`git archive HEAD` is refused on the row's own objection, now measured
  rather than argued.** Head to head on one working tree carrying an
  uncommitted prose edit that rots a fixture's match side: **the HEAD snapshot
  exits 0 with 28 ok lines and says nothing**; the live copy exits 1 and names
  the rot; the ruled design exits 1 and names the rot **and nothing else**. In
  CI the snapshot is a no-op — the checkout *is* `HEAD` — so its only real
  effect is to move every fixture-rot detection off the contributor's machine
  and into a push. Wave 14 found two such rots locally, before the push. The
  index snapshot is the same trade with an extra failure mode.
  **The synthetic minimal tree is refused on cost, and the cost is
  countable: 21 of the 27 cases name a target that is fixed in the file** — 17
  string literals over 8 distinct paths, plus 4 through the matrix constant —
  and the other 6 are computed from the staged tree at fixture time. A
  synthetic tree must fabricate all nine paths *and* a register, an entry
  corpus, a decision corpus and a matrix rich enough to derive the other six
  from. It would also be structurally unable to catch the class Q184 exists
  for, because a fixture cannot rot against content the fixture ships.
  **The residue is closable, and not by a glob.** Every item the code's comment
  concedes is already named in this repository's own ignore rules: the bytecode
  directory and its suffixes, the editor swap suffix, both fuzz directories,
  the transient agent-worktree directory, the devnet directories. Git knows all
  of them and a hand-written `ignore_patterns` tuple never will. **But git does
  not know this project's atomic-write shape** — `git check-ignore` returns
  *not ignored* for both spellings of it — so the `*.tmp.*` pattern Q150 landed
  **stays**, on top of git's set. Neither closes the class alone.
  **The measured cost of staging is not the bytes.** The current mechanism
  stages **1,983 files** where at most **474** can be opened by any check:
  **1,509 files are staged that nothing reads**, 925 of them untracked. Under a
  continuously churning writer the three-attempt retry was exhausted **5 runs
  out of 5**; staging git's view of the same tree completed **3 of 3** in
  0.17–0.21 s. The whole difference costs **+0.4 s** on a 6.3 s self-test.
- **Date: 2026-08-11** (M2 wave 15, D120 lane; briefed to overturn the row's
  lean toward a snapshot and to rule for the live copy if the measurements
  supported it. They support the working tree and they refuse the brief's own
  framing: this is not a staging decision. Staging fixes the race; only the
  arms fix the red that self-heals, and the row's `Accept` demands both.)
- **Owning tasks: Q191** (the ruling; its `Do` is answered and its `Notes`
  are sharpened). Touching, not executing: **Q184** (the fixture sweep — this
  lane measured the target-path half of its class and hands the literal half
  back), **Q192** (the same race in shell, where the ruled mechanism is
  directly transplantable), **Q150** (whose fix is kept in full, not replaced).
- **Amends**: **`tasks/Q.md`'s Q191 entry** — the `Problem`'s *"922 files,
  ~5.1 MB"*, which conflates two measurements, and the `Do`'s framing of the
  four mechanisms as the decision. **`TODO.md`'s Q191 row** — the same size
  figure. Both are the orchestrator's to apply.
  **Supersedes**: nothing. **Corrects**: nothing in a resolved record. Two
  figures reported by the Q150 lane and carried into Q191 on report are
  **reproduced here with artifacts** rather than corrected: the saturated
  writer and the sibling lane's self-healing red.
- **Binds against**: Q150's two guards and the comment that states their limits;
  `lane_traceability` in `scripts/ci-lanes.sh` and the `traceability` job in
  `.github/workflows/ci.yml`; Q66's derive-the-fixture-from-the-tree rule;
  D109 R7's floor/ceiling assertion; D116's `scripts/`-is-a-citation-surface
  widening; the checker's standard-library-only docstring.

---

## The problem, in one sentence

`--self-test` stages a copy of the live working tree and mutates it, so a
sibling lane's ordinary half-finished edit reddens a required gate with a
message that names the wrong file, suppresses the message that names the right
one, and disappears when the sibling finishes — and every candidate replacement
tree in the row either has the same property or trades it for blindness to the
contributor's own uncommitted work.

---

## 1. What was measured

Read and executed against the working tree on 2026-08-11, wave 15, with ten
lanes running concurrently. Every figure has its command in §7. **Locate the
constructs below by name, not by line number**: `scripts/check-traceability.py`
was being edited by the Q184 lane throughout this measurement, and D118 was
already corrected once for citing a line in this file that had moved.

### 1.1 The staging block is exactly as the row describes it

Inside `self_test()`, before any fixture is built, a three-attempt loop calls
`shutil.copytree(ROOT, tree, ...)` with `ignore=shutil.ignore_patterns(".git",
"target", "node_modules", "*.tmp.*")`, sleeping `0.25 * attempt` seconds
between tries — so 0.25 s then 0.50 s — and on the third failure printing a
sentence that quotes the last exception and returning 1. `ROOT` is
`Path(__file__).resolve().parent.parent`, the live tree. The comment above it
concedes, in its own words, that the bytecode files written by any concurrent
`python3 scripts/…` run are **not** ignored, and that an editor swap file has
been observed appearing under the vector directory. **Every clause of the row's
description of the code is exact.**

The `"target"` entry is a **basename** match, and that is load-bearing beyond
what anyone wrote down: it excludes the 39 GiB root build directory *and* the
1.5 GiB `fuzz/target`, which no rule names.

### 1.2 The 922 is right; the 5.1 MB is two different measurements

| what | measured |
| --- | --- |
| files under `fuzz/corpus` + `fuzz/artifacts` | **922** (921 + 1) |
| their total size in bytes | **2,312,609 B = 2.21 MiB = 2.31 MB** |
| `du -sh fuzz/corpus` | **5.1 M** |
| `du -sh fuzz/artifacts` | **28 K** |

The row's *"922 files, ~5.1 MB"* pairs a count that includes both directories
with a `du` figure for **one** of them — and `du` reports block allocation, not
content. 921 corpus files averaging 2.4 KB each occupy 5.1 MiB of 4 KiB blocks
while containing 2.2 MiB of bytes. **The count is exact; the size overstates
the payload by 2.2×** and is measuring the wrong thing anyway, because the cost
of these files is not their bytes (§1.4).

### 1.3 What the copy actually stages, and what any check can read

| | files | bytes |
| --- | --- | --- |
| staged by the current mechanism | **1,983** | 22,459,806 (21.42 MiB) |
| tracked by git | **1,058** | 20,030,112 (19.10 MiB) |
| staged but **not** tracked | **925** | |
| tracked but **not** staged | **0** | |

The 925 break down exactly: **921** `fuzz/corpus`, **1** `fuzz/artifacts`, **2**
`scripts/__pycache__/*.pyc`, **1** `.claude/scheduled_tasks.lock`.

The last one is worth its own sentence. **A lock file is staged on every run** —
a file whose entire purpose is to be created and removed by a concurrent
process. Nobody has named it, and no glob anyone would write by hand would
catch it.

Against that, an upper bound on what the six checks can open: the two sweeps
read **359** files (the checker prints the number itself), plus the register,
nine task files, 105 decision records and the matrix — **at most 474**.
**1,509 of the 1,983 staged files cannot be read by any check.**

### 1.4 The real cost of the fuzz directories is race surface, not bytes

Timed on the live tree, three runs: **0.406 s / 0.271 s / 0.266 s**. The 922
fuzz files are 46.5% of the staged *entries* and about 10% of the staged bytes,
and dropping them saves a fraction of a second on a **6.3 s** self-test.

What they are is **46.5% of the surface a concurrent writer can race**, in a
directory that `cargo fuzz` rewrites continuously by design — new inputs
appearing, minimised inputs vanishing — for as long as a fuzz run is going. The
row is right to want them gone and right about the count; the reason to remove
them is that they are the largest population of files in the copy that (a) no
check can read and (b) another tool is actively churning.

### 1.5 Git already names every conceded residue — except this project's own

`.gitignore` is 57 lines. It names, at its own lines: both fuzz data
directories (17, 18), the bytecode directory and its suffix family (44, 45),
the editor swap suffix (50), the devnet directory (30), the transient
agent-worktree directory (57). `.git/info/exclude` line 8 names the lock file —
**which means a ".gitignore-derived ignore set" parsed out of `.gitignore` alone
would miss it**, while asking git would not. That distinction is the difference
between the row's third candidate and the ruling.

And the one git does **not** know:

```
$ git check-ignore -v "TODO.md.tmp.12345.abcdef"   → rc 1 (not ignored)
$ git check-ignore -v "crates/antseal-core/.vault.tmp.999.3" → rc 1 (not ignored)
```

**This project's atomic-write shape is untracked and unignored.** It is exactly
the file that vanished in Q150's measured instance. So git's ignore knowledge
does not subsume Q150's glob, and Q150's glob does not subsume git's. **The
ruling keeps both.**

### 1.6 `git archive` really is absent, and only three lines mention it

`grep -rn "git archive" scripts/` returns **rc 1, no output**. Repository-wide
it appears in exactly three places: two `TODO.md` rows and the Q191 entry — all
three of them proposals, none of them code.

### 1.7 The case table: 27 cases, 19 red, 8 green, six checks, eight green arms

| check | red | green |
| --- | --- | --- |
| `freeze-boundary` | 2 | 2 |
| `decisions` | 4 | 1 |
| `matrix` | 3 | 1 |
| `task-citations` | 5 | 1 |
| `task-entries` | 3 | 2 |
| `decision-owners` | 2 | 1 |
| **total** | **19** | **8** |

**Every check has a green arm.** That is the whole mechanism of the row's
expensive failure mode, and it is not stated anywhere in the file.

Targets: **17** of the 27 are hard-coded string literals over **8 distinct
paths**; **4** more are the matrix constant; **6** are computed from the staged
tree at fixture time. Q184's *"nine hard-coded target paths"* is confirmed
(8 literals + the constant). Q184's *"~10 of 27 embed a literal borrowed from
live tree content"* this lane could **not** re-derive with a method it trusts —
two attempts gave 12 and 3 depending on how the match side was extracted — and
it is **Q184's row, not this one**. It is left to Q184 unamended, with the note
that the *target-path* half of the coupling is exactly 21 of 27.

### 1.8 The self-healing red, reproduced — deliberately, then by accident

**(a) Deliberate.** A row registered in `TODO.md` with no entry yet in
`tasks/Q.md` — the most ordinary act in a wave, performed by ten lanes this
week. Result:

- the flagless check exits 1 and says, precisely, that the row has no entry in
  `tasks/Q.md`, that a lane opening the file finds nothing and improvises, and
  that there is no exemption register;
- `--self-test` exits 1 with **two** messages, both naming a *green-case
  mutation* — one of `TODO.md`, one of `tasks/P.md` — and **neither naming the
  row**;
- removing the row: `--self-test` exits **0** with 28 ok lines and empty stderr.

**(b) Accidental, and this lane produced it on itself.** Two scratch `.py`
files were written into `scripts/` — a swept citation surface since D116, and
the obvious place to put a scratch script. `--self-test` exited 1 with **three**
messages naming two crate files and an unmutated-tree condition, none of them
the scratch files. The flagless check named them in its first line. Removing
them restored green.

**(c) The gate makes it strictly worse.** `lane_traceability` is
`if ! python3 scripts/check-traceability.py --self-test; then …; return 1; fi`
followed by the flagless run. Executed on (a)'s tree, the lane exits 1, the
planted id appears **0 times** in the entire lane output, and the lane's own
annotation reads *"a check stayed green over corrupted input"* — the exact
inverse of what happened, which was a check going red where it was required to
stay green. **A reader is told the self-test is vacuous when it is actually
contaminated, and is not told which file to look at.**

### 1.9 The saturated writer, reproduced 5 of 5

A writer creating and unlinking files continuously in a swept directory, with
no quiet window:

| mechanism | result |
| --- | --- |
| current `copytree` + 3-attempt retry | **exhausted 5 of 5** |
| staging tracked paths only | **3 of 3**, 1,058 copied, **0 vanished**, 0.17–0.21 s |
| staging tracked + untracked-unignored | **3 of 3 completed**, but **1, 31 and 49** untracked paths vanished between listing and copy |

An earlier, *bursty* writer (create-phase then delete-phase) exhausted only
**1 of 3** — worth recording, because it says the reproduction is
rate-dependent and that a lane failing to reproduce it has not refuted it.

The middle row is the ruling's mechanism and the third column is why it needs a
per-file tolerance: an all-or-nothing archiver over the same list would have
failed all three times. **A vanished untracked path is a skip; a vanished
tracked path is an error** — that asymmetry is measured, not assumed.

### 1.10 In CI, all four candidates are the same tree

The `traceability` job is `actions/checkout@v4` followed by
`./scripts/ci-lanes.sh traceability`. No build step runs before it; the job
deliberately carries no toolchain. So on the runner the working tree **is**
`HEAD`, `fuzz/corpus` does not exist (it is not committed), there are no
concurrent writers, and every mechanism in this decision stages the same 1,058
files. **Q191 is a local-workflow defect end to end.** Nothing in it is
observable on the remote, which is precisely why it took a parallel-lane wave to
find it.

---

## 2. The question, restated so it can be answered

The row asks *"which tree did the red arm actually exercise?"*. The measurements
say the question is aimed one arm to the left.

A **red** arm is robust to the tree's state. It requires the check to produce a
finding it did not produce before, carrying that check's own annotation, without
a traceback. If the tree is already red for an unrelated reason, a red arm still
passes — wrongly comfortable, but not noisy.

A **green** arm is not robust to anything. It requires exit 0. Any unrelated
finding anywhere in that check's surface fails it. With eight green arms over
six checks, **the union of the green arms is the whole check suite**, and
`--self-test` therefore contains a complete second `--check` run that nobody
declared, nobody documented, and nobody can see in the output.

So there are two questions, and the row merges them:

1. **Which tree should be staged?** — a question about the *race surface* and
   about what the fixtures may be derived from.
2. **What should an arm assert?** — a question about whether the tree's own
   state can produce a verdict.

Question 1 alone cannot satisfy the row's `Accept` bullet 3 (*"a concurrent
writer can no longer produce a red that is unrelated to traceability and
disappears on re-run"*), because the concurrent writer's edit lands in a
**tracked** file — `TODO.md` — that every candidate except a snapshot stages.
And a snapshot satisfies bullet 3 only by giving up bullets 1 and 2's whole
point. **Both questions have to be ruled, or the row is not closed.**

---

## 3. The candidates, one at a time

Each is scored on the row's question — *which tree does each arm exercise?* —
and on the three `Accept` bullets.

### 3.1 Snapshot from `HEAD` (`git archive HEAD`) — REFUSED

**Which tree:** the last committed one. Arms exercise content the contributor
may have already changed and may be about to change again.

Measured head to head. One working tree, one uncommitted prose edit that rots
the match side of the freeze-boundary fixture in `docs/format/anchor-artifact-limits.md`:

| staging | verdict |
| --- | --- |
| **HEAD snapshot** | **exit 0, 28 ok lines, silent** |
| current live copy | exit 1, names the rot, **plus 2 spurious green-arm failures** |
| ruled design (§4) | exit 1, names the rot, **and nothing else** |

The row states the objection and this is its measurement: **HEAD is not the
tree the contributor is about to push.** Three further findings against it:

1. **In CI it changes nothing** (§1.10). The runner's tree *is* `HEAD`. So the
   snapshot's entire practical effect is on the developer's machine — where it
   makes the self-test blind to exactly the work in progress.
2. **It moves fixture-rot detection from local to post-push.** Wave 14 found two
   such rots. The status-gate pair broke locally the moment the matrix cell they
   were pinned to moved, before any commit — under a HEAD snapshot they would
   have passed locally and broken on the remote. The register itself records the
   other direction too: a prose paragraph disarmed a first-occurrence mutation
   and **CI caught what the local check had not**. Both events argue for
   detecting earlier, not later.
3. **It silently changes what `--self-test` proves about a dirty tree.** It
   would have gone green over this lane's two scratch files in `scripts/` while
   the flagless check went red on them — an unannounced disagreement between the
   two halves of one lane.

Accept bullets: 1 ✗ (the recorded trade-off would have to say "the arms do not
exercise the tree being checked"), 2 ✓ (git-ignored data is absent by
construction), 3 ✓ (but by blindness).

### 3.2 Snapshot from the index — REFUSED, and worse than 3.1

**Which tree:** whatever was last `git add`-ed. In a project whose lanes are
told never to run `git stash`, `git checkout`, `git restore` or `git reset`, and
where the orchestrator stages at merge, **the index is usually identical to
`HEAD`** — so this is 3.1 with an extra failure mode: on the rare occasion the
index is *not* `HEAD`, the staged tree is a third thing that matches neither
what is committed nor what is on disk, and no error message would say so.
Measured cost is the same (0.25 s, 1,058 files). It buys nothing 3.1 does not
and adds a state nobody can see. **Refused for being unobservable.**

### 3.3 Copy with a `.gitignore`-derived ignore set — REFUSED as stated, ADOPTED as corrected

**Which tree:** the working tree — the right answer.

Two defects as the row words it, both measured:

- **Deriving from the `.gitignore` file misses `.git/info/exclude`**, which is
  the only rule that names the lock file (§1.5). A per-developer exclude file is
  exactly where machine-local churn gets listed, so a parser of the tracked
  ignore file is guaranteed to be the weaker of the two.
- **Re-implementing gitignore semantics in Python is a second implementation of
  a specification** — negation, anchoring, directory-only patterns, precedence
  across files — held in step with the real one by nothing. That is D112's
  two-constants-and-a-comment defect at specification scale.

Corrected to *"ask git what it can see"* — `git ls-files` for tracked paths and
`git ls-files --others --exclude-standard` for untracked-but-not-ignored ones —
it becomes the ruling's staging half. §4 states it.

### 3.4 Keep the live copy, widen the retry — REFUSED

**Which tree:** the working tree, including everything in it.

**Measured: the retry cannot be widened into a fix.** Under a continuous writer
the three attempts were exhausted 5 of 5 (§1.9). Widening to five or ten
attempts trades a red lane for a slow one and still loses to a writer that does
not stop; the retry's own comment already says it is for transients. And the
retry addresses only the *race*. It does nothing at all about the green arms
inheriting a sibling's finished-but-uncommitted edit — the failure this lane
reproduced twice, which involves no race whatsoever. Half the row's problem is
outside the retry's reach by construction.

### 3.5 A synthetic minimal tree built by the self-test — REFUSED, and this is the one the row omits

**Which tree:** a fabricated one. The brief proposes it on the reading that the
self-test's job is to test the **checks**, not the tree — and the docstring
agrees in one sentence: *prove both checks are able to fail*. If that is the
job, provenance is irrelevant and a purpose-built fixture is the clean answer.

It is still refused, on three counts, two of them countable.

1. **Cost, counted (§1.7).** 21 of 27 targets are fixed in the file: nine
   distinct paths that would have to exist in the synthetic tree with content
   satisfying each mutation's match side. The other 6 targets are *derived* —
   the first register row that has an entry, the first live row with an entry,
   the lowest unallocated number in two domains, the first per-ruling owner
   assignment whose owned row cites its decision back, the first suppression in
   the not-a-citation register. **Deriving them requires a synthetic register,
   a synthetic entry corpus, a synthetic decision corpus and a synthetic
   matrix** that are internally consistent enough for six independent finders to
   succeed — and each finder raises rather than returning a literal when it
   finds nothing, so every one of them is a hard failure if the fabrication
   drifts.
2. **It is structurally blind to the class Q184 exists for.** A fixture pinned
   to a value that ordinary project work changes can only rot against **real**
   content. If the harness ships the content its fixtures match, they match
   forever, and the no-op guard — the loud, self-announcing mechanism that
   caught the status-gate pair and caught the register-line mutation being eaten
   by prose — **can never fire again**. That guard is the single most productive
   instrument in this file's history. A synthetic tree disarms it permanently.
3. **It cannot notice a check that stopped reading a real surface.** D116's
   finding was that `scripts/` was not swept and a real citation there was
   invisible. The case that pins it works by mutating a real committed script.
   Over a synthetic tree the case would pin the synthetic layout, and narrowing
   the sweep back to the doc and code roots would pass.

**Its virtue is real and is kept**: total isolation from concurrent writers.
§4's differential rule buys that virtue without paying any of these three
prices, because it makes the tree's own state incapable of producing a verdict
while leaving the tree real.

### 3.6 Git's view of the working tree, with delta arms — RULED

**Which tree:** the working tree — the same one the flagless check reads,
including every uncommitted edit — minus the files git is certain nobody
checks, minus this project's atomic-write shape, with each arm measured as a
change against that same tree's own baseline.

Accept bullets: 1 ✓ (§4 R1 is the trade-off, recorded at the code), 2 ✓
(excluded, with the reason: **no check can open them**, §1.3), 3 ✓ (measured:
3 of 3 green under the writer that exhausted the current mechanism 5 of 5, and
27 of 27 arms green on a tree carrying a sibling lane's unentered row).

---

## 4. Ruling

**R1 — `--self-test` stages the WORKING tree, and stages it as git sees it.**
The staged set is `git ls-files` ∪ `git ls-files --others --exclude-standard`,
minus the `*.tmp.*` shape Q150 named. The trade-off recorded at the code is one
sentence: *the arms exercise the tree the contributor is about to push, which is
the same tree the flagless half checks; a snapshot would prove the checks can
bite committed content while the thing being checked went unproven.*

**R2 — the git-ignored directories are EXCLUDED, and the reason is not
tidiness.** `fuzz/corpus` and `fuzz/artifacts` are excluded because **no check
can open them**: they are outside every citation scan root, outside the
register, outside the matrix. 922 files, 46.5% of the staged entries, zero
readable by any check, and continuously rewritten by another tool. The same
argument excludes the bytecode files, the swap files, the lock file, the agent
worktree directory and the devnet directories — and it is git, not a glob, that
enumerates them, including the ones listed in `.git/info/exclude` where a
`.gitignore` parser cannot see.

**R3 — `*.tmp.*` stays, on top of git's ignore set.** Measured: `git
check-ignore` reports this project's atomic-write shape as **not ignored**, in
both spellings. Git's knowledge does not subsume Q150's glob. Q150's fix is
kept whole; nothing in it is replaced.

**R4 — a vanished TRACKED path is an error; a vanished UNTRACKED path is a
skip, and the skip is announced.** Measured (§1.9): under saturation the
tracked list lost nothing across three runs while the untracked list lost 1, 31
and 49 entries. A tracked path cannot vanish under an atomic-write discipline —
`rename` never leaves the name absent — so its disappearance is a real event
worth failing on. An untracked one disappearing is the definition of transient.

**R5 — the retry is kept, bounded and unchanged in shape, and is now a
backstop rather than the mechanism.** Three attempts, same backoff, same quoted
final exception. It exists for the residue R4 does not cover: a tracked file
genuinely removed mid-stage, or an I/O fault.

**R6 — every arm becomes a DELTA against a baseline measured on the same staged
tree.** Before the case loop, each check named in the table is run once,
unmutated, and its own `::error::` annotations are collected with line numbers
normalised. Then:

- a **red** arm passes when the mutation **adds** at least one annotation from
  that check;
- a **green** arm passes when the mutation **changes** nothing — nothing added,
  nothing removed;
- a **traceback** fails either arm, unchanged from today;
- a non-empty baseline is **printed as a note**, naming the check and the count,
  so a contaminated tree is visible rather than silent.

This is what makes the tree's own state incapable of producing a verdict. It is
the reason a snapshot is unnecessary, and it is measured in §7 rows 12–17.

**R7 — the floor/ceiling assertion stops requiring a green tree.** It currently
fails outright if the citation check is not green on the unmutated tree. That
gate is redundant: the assertion's real question is whether the six
non-citation tokens appear in the report, and that question is answerable
whatever else the check found. **Replace the exit-code gate with a
traceback gate** — a crash must still fail, because an empty report from a
crashed check would let the assertion pass by absence, which is the exact
failure the surrounding comment already warns about.

**R8 — no git, no staging: fall back and say so.** The checker's docstring
commits to the Python standard library because the lane must not acquire
dependencies. `git` is not a Python dependency and the CI job cannot exist
without it — `actions/checkout` is git — but a source tarball has no work tree.
If `git rev-parse --is-inside-work-tree` fails, fall back to today's
`copytree` path and **print a note saying which mechanism staged the tree**, so
that a run's provenance is never ambiguous.

---

## 5. Why the ruling is not the row's snapshot

The row leans toward a consistent snapshot and states, in the same breath, the
objection that kills it. This lane's job was to take that objection seriously
enough to rule the other way, and the measurement did it in one table (§3.1):
on one working tree, the snapshot exits **0** and prints 28 lines of "ok" while
a fixture that the contributor is about to push is already dead.

The deeper reason is that the snapshot answers the wrong bullet. It satisfies
`Accept` bullet 3 by removing the *input*: no uncommitted edit reaches the
staged tree, so no uncommitted edit can redden the arms. R6 satisfies the same
bullet by removing the *coupling*: uncommitted edits reach the staged tree, and
the arms stop caring what state that tree is in. **One buys silence and the
other buys indifference, and only indifference leaves the instrument pointed at
the tree it is supposed to be proving things about.**

And the snapshot's cost is not hypothetical. Q184 exists because two fixtures
died the moment a matrix cell moved — locally, before a commit, loudly. That
event is the best thing this harness has ever done, and it is available only to
a self-test that reads the tree as it is on disk.

---

## 6. Edit set

One file. Another lane is editing it this wave for Q184's fixture sweep; the
hunks below are the staging block, the case-loop runner and the closing
floor/ceiling gate, while Q184's are inside the case **table** between them.
They do not overlap, but **Q184 should land first** — its sweep may retarget
cases, and R6's baseline map is keyed on check names, which its retargets do not
change. Locate every hunk by construct; do not trust a line number in this
document.
- `docs/decisions/README.md` — this decision's index row. **Applied 2026-08-11**, executing [D119](D119-decision-index-identity-and-the-index-row-sections.md) §5 step 4; the former `## Index row` section is demoted to this line under D119 RULING 4, and RULING 6 puts the row in the act that commits the record.

### `scripts/check-traceability.py`

**(1) Replace the `copytree` call inside `self_test()`; keep the retry loop
around it.** Inside the `try`, stage as R1/R2/R3/R4 say:

- list tracked paths with `git -C ROOT ls-files -z`, and
  untracked-but-not-ignored paths with
  `git -C ROOT ls-files --others --exclude-standard -z`;
- drop any path matching the `*.tmp.*` shape, using `fnmatch` on the relative
  path — the same pattern Q150 landed, moved from `copytree`'s `ignore=` to
  this filter, with its comment carried over intact;
- copy each surviving path with `copy2`, creating parents as needed;
- on `FileNotFoundError` / `NotADirectoryError`: if the path came from the
  tracked list, re-raise so the existing retry sees it; otherwise count it and
  continue;
- after the loop, if anything was skipped, print a note with the count.

Keep the three attempts, the `rmtree` of the partial destination between them,
the `0.25 * attempt` backoff and the final message quoting the last exception —
**unchanged**. Add the R8 fallback: if `git rev-parse --is-inside-work-tree`
fails, stage with today's `copytree` call and print which mechanism was used.

The comment above the block gains R1's one-sentence trade-off, R2's reason for
excluding git-ignored data (*no check can open it*), and R3's measured note that
git does not ignore this project's atomic-write shape.

**(2) Add a `findings(check_name)` helper and a baseline pass, immediately
before the case loop.** It runs one check on the staged tree, returns the set of
that check's own `::error::` annotation lines with `:\d+` collapsed to a
placeholder — so an unrelated line shift is not counted as a diff — and returns
a sentinel if the output carries a traceback. Then, for each distinct check
named in the table, compute its baseline once and print the R6 note if it is
non-empty.

**(3) Rewrite the four verdict branches in the case loop** to use `added` and
`removed` against that baseline, per R6. Keep, byte for byte: the
missing-target hard failure (never a skip), the no-op-mutation guard (**this is
the instrument Q184 depends on — do not weaken it**), the crash branch and its
comment, and both success messages. The annotation check folds into `added`,
because `findings()` only ever collects that check's own annotations — so a
non-zero exit from anywhere else can no longer be mistaken for the check
biting.

**(4) Replace the exit-code gate on the closing floor/ceiling assertion with a
traceback gate**, per R7, and rewrite its message to say that a crashed check
would let the assertion pass by an empty report.

**(5) Do not touch** the case table, the fixture finders, `CITATION_SCAN`,
`CITATION_SUFFIXES`, or any check body.

### Nothing else

No workflow change: `lane_traceability` and the `traceability` job are correct
as written once the self-test stops going red for reasons that are not its own.
No `TODO.md` or `tasks/*.md` edit — the two amendments in the front matter are
described for the orchestrator.

### The acceptance test the implementing lane should run

1. Clean tree → 27 arms ok, plus the closing assertion. (Measured: 28 ok, rc 0.)
2. Register a row with no entry, re-run → **still rc 0**, with one note naming
   the check and its one pre-existing finding. (Measured.)
3. Same tree, flagless check → **rc 1**, naming the row. The two halves now
   disagree *correctly*: the tree is red, the checks are proven.
4. Rot a fixture's match side in the working tree → **rc 1 with exactly one
   message**, the no-op guard's. (Measured.)
5. Narrow a scan root so a red case stops biting → **rc 1**, *added no finding*.
   (Measured: two cases.)
6. Run under a continuous writer in a swept directory → **rc 0**. (Measured
   3 of 3, against 5 of 5 exhaustion today.)

---

## 7. Commands run, with verdicts

Every experiment ran on copies of the repository under this session's scratch
directory. **The repository working tree was not written to by this lane**,
except for this file.

| # | command | verdict |
| --- | --- | --- |
| 1 | `find fuzz/corpus fuzz/artifacts -type f \| wc -l` | **922** — the row's count is exact |
| 2 | `find … -printf '%s\n' \| awk` and `du -sh` on both | **2,312,609 B (2.21 MiB)** of content; `du` says **5.1 M** for `fuzz/corpus` alone, **28 K** for artifacts |
| 3 | `grep -rn "git archive" scripts/` | **rc 1, no output** — absent, as the row says. Three mentions repo-wide, all proposals |
| 4 | `copytree` with the live ignore tuple, into scratch | **1,983 files, 22,459,806 B**; `fuzz` 933, `testdata` 502, `crates` 342, `docs` 137 |
| 5 | `git ls-files \| wc -l`, staged-vs-tracked diff | tracked **1,058**; staged-not-tracked **925** = 921 + 1 + 2 `.pyc` + **1 lock file**; tracked-not-staged **0** |
| 6 | `git check-ignore -v` on the lock file, a `.pyc`, both fuzz dirs | lock file ignored by **`.git/info/exclude`**, not `.gitignore`; `.pyc` by `.gitignore`'s bytecode rule; fuzz dirs by their own two lines |
| 7 | `git check-ignore -v` on both spellings of the atomic-write shape | **rc 1 both** — not ignored by git |
| 8 | three staging mechanisms, timed | `git archive HEAD` **0.36 s**, `checkout-index` **0.25 s**, tracked-list copy **0.13 s**, union **0.17 s**, live `copytree` **0.406/0.271/0.266 s** — all 1,058 files except the live copy's 1,983 |
| 9 | `--self-test` on a clean copy | **rc 0**, 28 ok lines, **6.37 s** |
| 10 | plant an unentered row, then `--self-test` | **rc 1**: *task-entries went red on the green-case mutation of `TODO.md`* and *… of `tasks/P.md`*. Flagless check names the row precisely |
| 11 | revert the row, `--self-test` again | **rc 0**, 28 ok, empty stderr — **the self-heal, on an artifact** |
| 12 | `scripts/ci-lanes.sh traceability` on the same tree | **rc 1**; planted id appears **0 times**; annotation claims a check *stayed green over corrupted input* — the inverse of the observed failure; flagless half never runs |
| 13 | two scratch `.py` files left in `scripts/`, `--self-test` | **rc 1**, three messages, none naming them; flagless check names them in its first line. **Accidental second reproduction** |
| 14 | HEAD-snapshot variant, working tree carrying a rotted fixture literal | **rc 0, 28 ok, silent** |
| 15 | current live copy, same tree | **rc 1** — names the rot, plus 2 spurious green-arm failures |
| 16 | ruled design (union staging + delta arms), same tree | **rc 1 with exactly one message** — the no-op guard's |
| 17 | ruled design on clean / on the unentered-row tree | **rc 0 / rc 0**, 28 ok both, one note on the second |
| 18 | ruled design, scan root narrowed so a surface stops being swept | **rc 1**: *decisions added no finding…*, *task-citations added no finding…* — red arms stay sharp |
| 19 | continuous writer + current mechanism, 5 probes | **exhausted 5 of 5**. Bursty writer: 1 of 3 — the reproduction is rate-dependent |
| 20 | continuous writer + tracked-only / union staging | tracked **3/3, 0 vanished**; union **3/3**, with **1, 31, 49** untracked vanished — R4's asymmetry |
| 21 | continuous writer + ruled design, 3 runs | **rc 0, 28 ok, 3 of 3** |
| 22 | `--self-test` timing, current vs ruled, 3 runs each | **6.28 / 6.52 / 6.21 s** vs **6.72 / 6.79 / 6.76 s** — **+0.4 s, +6%** |
| 23 | `python3 scripts/check-traceability.py --check` **on the repository** | **rc 2** — *unrecognized arguments: --check*. There is no such flag; the check half is the flagless run |
| 24 | `python3 scripts/check-traceability.py` **on the repository** | **rc 0**, empty stderr, six ok lines: 2 boundary copies; 34 matrix rows / 97 references / 22 gated rows; 104 decisions across 359 files; 391 task ids; **582 rows against 582 entries**; 2 owner assignments |
| 25 | `python3 scripts/check-traceability.py --self-test` **on the repository** | **rc 0**, empty stderr, **28 ok lines** — green despite the Q184 lane's in-flight edit to this very file and eight other files modified by sibling lanes |

Measurement hygiene: no exit code in this table was taken after a pipe.
Command 3's `rc 1` is `grep`'s own no-match status, read directly. Every
"failed" verdict above was read from the **message**, and every one of them
appears in stderr **before** the ok lines on stdout.

---

## 8. What this does not do

- **It does not edit `scripts/check-traceability.py`.** The Q184 lane is
  editing that file this wave. §6 is written to be executed, not admired, and
  says which hunks are whose.
- **It does not resolve Q184.** The target-path half of its class is measured
  here (21 of 27 fixed, 9 distinct paths); the borrowed-literal count is left to
  Q184, explicitly un-re-derived, because two honest extraction methods
  disagreed.
- **It does not fix Q192.** The shell scripts stage with a recursive copy under
  `set -euo pipefail` and have the same defect. R1's mechanism transplants
  directly — a tracked-path list is a tracked-path list in any language — but
  that is Q192's row and its six copy sites are its own to count.
- **It does not change any check.** No scan root, suffix set, register or check
  body moves. The six checks' verdicts on any tree are identical before and
  after.
- **It does not remove the second `--check` run.** R6 makes the arms indifferent
  to the tree's state; the six baseline runs still execute the checks over the
  staged tree, which is what makes a delta meaningful. The duplication is now
  **declared and printed** rather than hidden inside eight green arms.
- **It does not claim the self-test becomes concurrency-proof.** A tracked file
  rewritten non-atomically mid-stage still yields a torn copy. That is a
  different failure — content, not existence — and the project's writers use
  atomic rename, which is why R4 can treat a vanished tracked path as an error.
- **It does not touch `TODO.md` or `tasks/*.md`.**

---

## 9. Discovered work — described, not registered

No ids are minted here.

**(i) The self-test's floor/ceiling assertion straddles two trees, and only
coincidence hides it.** The closing block calls the surface sweep with no
argument, so the sweep runs against `ROOT` — **the live tree** — while the
`--task-citations` run it guards executes against the **staged copy**. The
assertion "these six tokens are present, so the skip is not passing by absence"
is therefore made about one tree and relied upon for another. Today the two are
near-identical and no divergence is possible; under any snapshot mechanism it
becomes real, and under the ruled mechanism it becomes possible the moment a
token lives only in an ignored file. The fix is one parameter. It is small, it
is invisible, and it is the kind of thing this project has twice found the
expensive way.

**(ii) Nothing in the harness declares that its green arms are a second full
check run.** Eight arms over six checks add up to the whole suite, and that
identity is stated in no comment, no docstring and no runbook — it is a property
that emerges from the case table's composition and changes silently whenever a
case is added or removed. Worth a one-line invariant in the file, or better, an
assertion: *every check named in the table has at least one green arm* is a real
property (it is true today, for all six) and it is the thing that makes R6's
baseline necessary. If it is worth relying on, it is worth asserting.

**(iii) The gate lane's failure annotation can state the inverse of what
happened.** `lane_traceability` prints *"a check stayed green over corrupted
input"* whenever the self-test exits non-zero — but the self-test has at least
six distinct failure modes, including a check going **red** where it had to stay
green, a target file missing, a mutation matching nothing, a traceback, a
staging exhaustion, and a token vanishing from the swept tree. Measured: on the
most likely of them, the annotation is exactly backwards. The lane should relay
the self-test's own message rather than assert a cause.

**(iv) A lock file is staged into the self-test's tree on every local run.**
`.claude/scheduled_tasks.lock` is ignored by `.git/info/exclude` and by nothing
in `.gitignore`, so it survives every ignore rule the project has written down
and lands in the mutation harness's copy. R2 removes it. What it suggests is
broader: **the project's own ignore rules and the developer-local ones have
diverged**, and only one of them is reviewed. A short audit of what
`.git/info/exclude` carries — and whether any of it belongs in `.gitignore` —
is cheap and has never been done.

**(v) `fuzz/target` is 1.5 GiB and is excluded by an accident of basename
matching.** The ignore tuple's `"target"` entry has no path anchoring, which is
what saves the copy from the root build directory (39 GiB) *and* from
`fuzz/target`. `.gitignore` names both explicitly and says why. Under R1 this
stops mattering for the self-test, but the same basename-vs-path question exists
in the shell copies Q192 covers, and nobody has checked whether their exclusion
of build output is anchored or accidental.

**(vi) Two of the six checks' green arms are the only thing pinning a
normalisation rule, and they now measure a delta.** The pair that tolerate
checkbox state in either direction and either case exist so the normalisation
cannot widen to "compare nothing". Under R6 they assert *no change in
findings*, which is strictly stronger than *exit 0* — a widening that made the
check report **fewer** findings would now fail them, where today it would not.
That is an improvement nobody asked for and it should be stated where those
cases are, so a later lane does not "simplify" it away.

---

## Outcome

`--self-test` stages the tree the contributor is about to push, and will keep
staging it. What changes is what it stages of that tree — git's view of it,
minus the atomic-write shape git does not know about — and what its arms
assert: a change in findings, not an absolute verdict.

The row asked which tree the red arm exercises. The red arms were never the
problem; **eight green arms over six checks were quietly re-running the entire
check suite**, and every unrelated edit in the tree came back as a message
naming the wrong file. Twice reproduced, once by this lane on itself. At the
gate the accurate diagnosis is not merely buried — it is never printed, and the
annotation that replaces it says the opposite of what occurred.

`git archive HEAD` would have silenced all of it, at the price the row itself
names and this decision measured: on one tree, with a fixture already dead, the
snapshot exits 0 and prints twenty-eight lines of "ok". A self-test that cannot
see the work in progress is a self-test that will always be green on the machine
where being green is worth the least.
