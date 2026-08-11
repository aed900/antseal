# D124 — Q182: the `traceability` job's cargo-free property, and where an assertion of it can actually live

- **Status: RESOLVED — the property becomes a machine assertion, and it is
  expressed at the job as a runtime fact, not in `check-ci-shell.py`'s parse.**
  The row's proposed home is refused on a ground the row does not consider.
  A per-job predicate over `run:` block text is **vacuous against the very
  incident that produced the row**: Q153's near-miss line —
  `./scripts/gate-features.sh --check-partition` — carries no `cargo` token,
  and neither does any of the five `run:` lines the job carries today
  (measured, all six, below). Reading one level deeper is worse, not better:
  grepping the called script turns **all five of today's green steps red**,
  including the one step Q153 measured cargo-free at runtime
  (`wasm-bitmatch.sh` contains 4 `cargo ` occurrences; `ci-lanes.sh`, the
  callee of 4 of the 5 steps, contains 31, belonging to other lanes).
  **The row's stated blocker is not the blocker.** Job attribution costs
  **9 added lines** to `run_blocks`, attributes **65 of 65** run blocks across
  all four workflows with **zero unattributed**, and its total matches the
  number `check-ci-shell.py` already prints — so *"that is the larger half of
  the work"* is refuted by measurement. The parse is cheap; the predicate it
  would feed is empty. Cheapness was never the question.
  **The failure mode the row describes does not exist.** The row says a cargo
  step there *"will fail on a missing toolchain or run slowly against whatever
  is cached"*. No workflow in this repository installs rustup — every toolchain
  step is `rustup show active-toolchain || rustup toolchain install`, which
  presumes the shim is already on `PATH` — so **cargo is on `PATH` in
  `traceability` right now** and nothing would fail; and the job has no
  `Swatinem/rust-cache@v2` step, so *"whatever is cached"* is **empty**. The
  real mechanism is the one `docs/ci-verification.md` already recorded
  correctly and the row garbled: the rustup shim resolves `rust-toolchain.toml`
  and **implicitly installs the pinned 1.92.0 plus `rustfmt`, `clippy` and the
  `wasm32-unknown-unknown` std**, on every PR and every push, in a job that
  bills in seconds — **green the whole time**. That is silent, it is billed,
  and it lands on a repository whose Actions minutes were exhausted eight days
  ago.
  **The drift surface is four times what the row states.** The row says the
  property *"exists as prose in three places (`ci.yml` twice, `ci-lanes.sh`
  once)"*. Measured: **16 statements across 6 files** — 5 in `ci.yml`, 1 in
  `ci-lanes.sh`, 2 in `local-gate.sh`, **6 in `docs/ci-verification.md` which
  the row does not count at all**, 1 in `docs/testing/fuzzing.md`, 1 in
  `docs/testing/anchor-ci-policy.md`.
  **The converse is not merely unasserted, it is actively misdiagnosing.** The
  row says `core-dep-graph`'s property *"is asserted by nothing either, but its
  failure mode is loud, which is why this row names only the silent
  direction"*. Measured: loud **and wrong**. With cargo masked,
  `gate-features.sh --check-partition` prints an unhandled
  `json.decoder.JSONDecodeError` traceback and then
  `::error::gate-features: cargo metadata returned NO features at all — the
  extractor is broken`. A reader is sent to debug `declared_features()`. So the
  converse gets `--require` in the same instrument, granting the row's own
  *"the same kind of fact"* instruction but as an executed fact rather than a
  predicate table.
  **The mechanism**: one new committed script, `scripts/cargo-free.sh`, armed
  as the **first** step of `traceability` (it installs failing `cargo`,
  `rustc` and `rustup` shims ahead of the real ones on `$GITHUB_PATH`, so it
  covers every step of the job **including ones not yet written**) and read
  back as the **last** step, which is what makes the diagnosis survive the
  measured hazard that a callee redirects the shim's stderr to `/dev/null`.
  The two steps guard each other: deleting the arm turns the verdict red.
  **Safe to install today**: all five current steps produce **byte-identical
  output** with `cargo`, `rustc` and `rustup` masked.
  **Zero new required-status contexts — the set stays at 19.**
- **Date: 2026-08-11** (wave 15, D124 lane. The brief's lean was that PyYAML
  being *"one import away"* would flip the ruling toward doing the parse. It is
  one import away — PyYAML 6.0 is installed here — and the ruling does not flip
  that way, because a correct parse hands you the same tokenless strings the
  hand-rolled scanner hands you, and because adopting it would put a
  hash-pinned `pip install` step inside the one job whose cheapness is the
  property being asserted. The brief's second lever — assert it at the job by
  running with cargo off `PATH` — is **accepted in substance and refuted in
  every detail**: see §3.6.)

---

## The problem, in one sentence

The argument that placed three gate lanes into two CI jobs rests on a property
of one job — *nothing in `traceability` runs cargo* — that is stated sixteen
times and checked zero times, in a project whose own record already shows that
statement of the property being wrong once.

---

## 1. What was measured

Every command below was run from `/home/deb/Documents/code0` on 2026-08-11.
The working tree was clean at the start of the lane and no file in it was
written by this lane except this document.

### 1.1 The `traceability` job's step list, and the absence of toolchain and cache

```
$ sed -n '691,740p' .github/workflows/ci.yml
  traceability:
    name: traceability
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Self-test (prove both checks can fail), then check
        run: ./scripts/ci-lanes.sh traceability
      - name: Q43 — every workflow `run:` block is a committed script or an allowlisted line
        run: ./scripts/ci-lanes.sh ci-shell
      - name: Q81 — the scheduled fuzz lane fits its named minutes ceiling
        run: ./scripts/ci-lanes.sh fuzz-budget
      - name: Q16 — the no-real-anchor-network policy is armed, not merely stated
        run: ./scripts/ci-lanes.sh anchor-net-policy
      - name: Q153/Q128 — the wasm-bitmatch trigger still selects a vectors-only change
        run: ./scripts/wasm-bitmatch.sh --trigger-self-test
```

One `uses:` (checkout) and five `run:` steps. No `rustup` step, no
`Swatinem/rust-cache@v2`, no `dtolnay/rust-toolchain`, no `actions-rs`.
Confirmed by classifying every job in the file:

```
$ python3 - <<'PY'   # (full script in §6)
...
NO-TOOLCHAIN    secret-guard
NO-TOOLCHAIN    traceability
```

with all fifteen other jobs `HAS-TOOLCHAIN`. **The "only two jobs" claim in
`ci.yml`, `local-gate.sh` and `docs/ci-verification.md` is exact.**

A note on the method, because it is the first cost of the parse the row wanted:
a naive scan for two-space-indented keys also reports `pull_request` and `push`
as jobs — they are children of `on:`, at the same indent. A hand-rolled job
attribution must track the `jobs:` section, not the indent alone. This lane's
own first prototype had that defect.

### 1.2 Cargo is on `PATH` in that job, and nothing there would fail

```
$ grep -rn "rustup-init\|dtolnay/rust-toolchain\|actions-rs\|curl.*sh.rustup.rs\|apt.*rust" .github/workflows/
  NONE — no workflow installs rustup; every job that needs cargo just calls it

$ grep -n "rustup" .github/workflows/ci.yml | head
3:# Toolchain: taken exclusively from rust-toolchain.toml — the rustup step in
117:      - name: rustup show (toolchain from rust-toolchain.toml)
119:          rustup show active-toolchain || rustup toolchain install
120:          rustup show
```

`rustup show active-toolchain || rustup toolchain install` is a command that
**presumes rustup is already installed and on `PATH`**. Fifteen jobs use that
form and none of them installs it. That is this workflow's own evidence that
the runner image ships rustup, and therefore the `cargo` and `rustc` shims,
before any step runs.

`rust-toolchain.toml` pins what would be pulled down:

```
[toolchain]
channel = "1.92.0"
components = ["rustfmt", "clippy"]
targets = ["wasm32-unknown-unknown"]
```

`docs/ci-verification.md:1768-1772` already states the resulting mechanism
correctly:

> A `cargo` invocation there would resolve `rust-toolchain.toml` through the
> rustup shim and implicitly install the pinned 1.92.0 — plus `rustfmt`,
> `clippy` and the `wasm32-unknown-unknown` std — on one of the only **two**
> jobs in this workflow that need no toolchain at all (`secret-guard` is the
> other), on a repository whose minute consumption is the standing suspect for
> the refused dispatch recorded in the section above.

**So the failure is not a red. It is a green job that quietly costs minutes,
for ever.** Q182's row states the opposite; its own source has it right.

### 1.3 The sixteen prose sites, quoted

The row says three, in two files. Measured, scoped to *statements asserting
that the `traceability` job, or a step placed in it, needs no cargo / no
toolchain / no cache*:

| # | site | the statement |
| --- | --- | --- |
| 1 | `ci.yml:672` | *"Neither needs cargo, so this lane is seconds, not minutes."* |
| 2 | `ci.yml:702-704` | *"it needs no cargo and no network, so folding it in costs SECONDS and ZERO new required-status contexts"* |
| 3 | `ci.yml:710-712` | *"for the same reason `ci-shell` and `fuzz-budget` do: Python only, no cargo, no network, so it costs SECONDS"* |
| 4 | `ci.yml:734-737` | *"it is genuinely cargo-free AND git-free — verified by running it with cargo off PATH, rc 0 — so it adds no setup to a job that deliberately has none"* |
| 5 | `ci.yml:239-244` | *"`traceability` carries no toolchain and no cache BY DESIGN … on one of the only TWO jobs in this workflow that need no toolchain at all"* |
| 6 | `ci-lanes.sh:852` | *"Python-only, no cargo, no network, so it rides in the `traceability` job"* |
| 7 | `local-gate.sh:57-64` | the correction record (quoted in §1.4) |
| 8 | `local-gate.sh:75-78` | *"Measured cargo-free and git-free — it runs green with cargo off PATH — which is what earns it the job that has no toolchain."* |
| 9 | `ci-verification.md:1371-1373` | *"it needs no cargo and no network, so the required-context set stays at 19"* |
| 10 | `ci-verification.md:1430-1431` | *"which rides as a step of the existing `traceability` job — Python only, no cargo, no network"* |
| 11 | `ci-verification.md:1440-1441` | *"`traceability` needs no toolchain and no cache, so the step adds no setup."* |
| 12 | `ci-verification.md:1753-1772` | the Q153 measurement table and *"That matters because `traceability` has no toolchain bootstrap and no cache"* |
| 13 | `ci-verification.md:1784` | *"cargo-free and git-free, verified rather than assumed, so it adds no setup to the job that deliberately has none"* |
| 14 | `ci-verification.md:1909-1911` | *"that job has no toolchain bootstrap and no cache, and this document already records that as a property of it"* |
| 15 | `fuzzing.md:312` | *"reads four committed literals; no cargo, no network"* |
| 16 | `anchor-ci-policy.md:148-149` | *"a step on the existing `traceability` job — Python only, no cargo, no network, seconds"* |

**Six files, not two. Sixteen statements, not three.** The file with the
largest share — `docs/ci-verification.md`, six statements — is the one the row
does not count.

### 1.4 `local-gate.sh`'s record of the prose being wrong

```
$ sed -n '55,78p' scripts/local-gate.sh
#   gate-features --self-test        now ALSO a step of CI's `core-dep-graph`
#   gate-features --check-partition  job, not `traceability` as Q153's row
#                                    said. The row called these two "seconds
#                                    and cargo-free"; they are seconds and
#                                    they are NOT cargo-free —
#                                    `declared_features()` runs `cargo
#                                    metadata --no-deps --locked`, and with
#                                    cargo off PATH `--check-partition` exits
#                                    1. `traceability` deliberately carries no
#                                    toolchain and no cache, so cargo there
#                                    would mean an implicit rustup install of
#                                    the 1.92.0 pin on one of only TWO CI jobs
#                                    that need no toolchain at all
```

Confirmed as the row describes it. It is the project's own record of this
property being asserted in prose and being wrong.

### 1.5 `check-ci-shell.py`'s actual parse shape

The row's entry says the script does not attribute per job, against an
orchestrator ledger that said it does. **The entry is right.**

- `run_blocks(text) -> list[tuple[int, str]]` (`:94`) — a hand-rolled line
  cursor returning `(1-based line number, body)`. No job, no section, no
  structure above the `run:` key.
- `check(*targets)` (`:133`) flattens to
  `[(w, n, b) for w in targets for n, b in run_blocks(...)]` — `(workflow,
  lineno, body)`.
- `$ grep -n "job" scripts/check-ci-shell.py` returns **exactly one line**,
  `:59`, inside an `ALLOWED_INLINE` reason string: *"toolchain bootstrap;
  byte-identical in every job…"*.

And the docstring at `:96-101` gives the deliberate reason for the hand-roll:

> Hand-rolled rather than via a YAML library: this check must work with no
> third-party dependency (the `traceability` lane it joins needs none), and a
> YAML loader would also normalise away the very indentation that tells a
> single-line `run:` from a block one.

**Its first clause is a seventeenth statement of the property, inside the very
file the row proposes as the property's home.** Its second clause is
measurably false — see §3.2.

### 1.6 The vacuity measurement — the one that decides the ruling

```
$ python3 - <<'PY'   # attribute run: lines to jobs, then test for a `cargo` token
traceability run: lines ->
  ci.yml:697: ./scripts/ci-lanes.sh traceability          [contains 'cargo': False]
  ci.yml:699: ./scripts/ci-lanes.sh ci-shell              [contains 'cargo': False]
  ci.yml:708: ./scripts/ci-lanes.sh fuzz-budget           [contains 'cargo': False]
  ci.yml:719: ./scripts/ci-lanes.sh anchor-net-policy     [contains 'cargo': False]
  ci.yml:740: ./scripts/wasm-bitmatch.sh --trigger-self-test  [contains 'cargo': False]

Q153's NEAR-MISS, as it would have been written:
  run: ./scripts/gate-features.sh --check-partition       [contains 'cargo': False]
```

Six lines. Zero `cargo` tokens. **The predicate the row asks for reads green on
the incident the row exists to prevent.**

One level deeper is not a fix:

```
$ grep -c "cargo " scripts/gate-features.sh scripts/ci-lanes.sh scripts/wasm-bitmatch.sh
scripts/gate-features.sh:8
scripts/ci-lanes.sh:31
scripts/wasm-bitmatch.sh:4
```

A checker that greps the callee turns **all five** of today's steps red —
four of them because `ci-lanes.sh` carries the cargo calls of `dep-graph`,
`audit-deny`, `tamper-matrix` and the rest, and the fifth because
`wasm-bitmatch.sh` mentions cargo in code paths `--trigger-self-test` never
reaches. The one step Q153 measured cargo-free at runtime would be the first
false red.

### 1.7 The parse the row calls "the larger half of the work"

Prototyped against the real `run_blocks`, changing nothing but the addition of
a tracked current-job:

```
$ python3 /…/scratchpad/attrib_proto.py
total run blocks: 65   (check-ci-shell.py reports 65)
unattributed: 0

   3  advisory-cron.yml:advisory-weekly     5  ci.yml:traceability
   3  ci.yml:audit-deny                     3  ci.yml:vector-freeze
   2  ci.yml:clippy                         4  ci.yml:wasm-bitmatch
   4  ci.yml:core-dep-graph                 2  ci.yml:wasm32-core
   5  ci.yml:cross-check                    4  ci.yml:wasm32-core-tests
   2  ci.yml:cross-os                       2  devnet-e2e-cron.yml:devnet-e2e-scheduled
   2  ci.yml:fmt                            7  fuzz-nightly.yml:fuzz-long
   3  ci.yml:format-freeze                  6  ci.yml:fuzz-smoke
   2  ci.yml:golden-vectors                 1  ci.yml:secret-guard
   3  ci.yml:tamper-matrix                  2  ci.yml:test
```

**Nine added lines. 65 of 65 attributed. Zero unattributed. The total matches
the number the shipping checker already prints.** *"The larger half of the
work"* is refuted. It is not the larger half of anything — which does not save
the shape, because §1.6 already emptied it.

### 1.8 All five current steps are cargo-free, measured by masking

A shim directory containing `cargo`, `rustc` and `rustup` — each exiting 127
with an error — was prepended to `PATH`, and `~/.cargo/bin` removed from it.
Each step was run twice, control and masked, and the outputs diffed:

| step | control | masked | output |
| --- | --- | --- | --- |
| `ci-lanes.sh traceability` | rc 0 | rc 0 | **byte-identical** |
| `ci-lanes.sh ci-shell` | rc 0 | rc 0 | **byte-identical** |
| `ci-lanes.sh fuzz-budget` | rc 0 | rc 0 | **byte-identical** |
| `ci-lanes.sh anchor-net-policy` | rc 0 | rc 0 | **byte-identical** |
| `wasm-bitmatch.sh --trigger-self-test` | rc 0 | rc 0 | **byte-identical** |

`$ grep -c "cargo" scripts/check-traceability.py` → `0`.

**This is what makes the ruling installable today rather than a migration.**

**One measurement this lane got wrong first, recorded rather than quietly
dropped**: the first control run of `ci-lanes.sh traceability` took
`real 4m28.229s` against `real 0m6.862s` masked, with identical output. A 39x
figure would have entered this document as fact. Re-measured warm:
`real 0m7.123s` control, identical output. **The gap was cold page cache under
ten concurrent lanes, not cargo.** No timing claim about cargo is made from
that pair.

### 1.9 The converse, at `core-dep-graph` — loud and wrong

```
$ env PATH="<mask>:<PATH minus .cargo/bin>" ./scripts/gate-features.sh --check-partition
rc=1
Traceback (most recent call last):
  File "<string>", line 3, in <module>
  ...
json.decoder.JSONDecodeError: Expecting value: line 1 column 1 (char 0)
::error::gate-features: cargo metadata returned NO features at all — the extractor is broken, so a green verdict here would mean nothing
```

Two things the row does not have:

1. The diagnosis is **wrong**. Nothing is broken about the extractor. The
   reader is sent to `declared_features()`.
2. The shim's own message never appears. `scripts/gate-features.sh:116` is
   `{ cargo metadata --format-version 1 --no-deps --locked 2>/dev/null | python3 -c '…'`.
   **The callee redirects the diagnosis to `/dev/null`.** The exit status
   survives; the message does not.

Point 2 is the single most consequential measurement for the *design* of the
guard, and it is why the ruling is not simply "mask cargo".

### 1.10 Environment facts the brief asked to be checked before ruling

```
$ python3 -c "import yaml; print('PyYAML OK', yaml.__version__)"
PyYAML OK 6.0

$ grep -rln "import yaml\|yaml.safe_load\|yaml.load" scripts/ crates/ probes/
(no output)
```

PyYAML **is** available here. **No script in this repository parses YAML with a
parser**; all workflow reading is line-scanning. `check-ci-shell.py` refuses a
YAML library on purpose (§1.5) and `check-traceability.py:26` states the house
rule it shares: *"Python standard library only, by deliberate choice: this runs
in a CI lane"*. The one hash-pinned Python install in the project,
`requirements-crosscheck.txt`, exists for `cross-check` alone and is
allowlisted in `check-ci-shell.py`'s `ALLOWED_INLINE` as a *"pinned,
hash-checked tool install"*.

---

## 2. What the row asks, restated exactly

- *Do*: make the property an assertion; the obvious home is
  `check-ci-shell.py`; job attribution must be added first and *"that is the
  larger half of the work"*; rule whether it is worth it; if yes, express the
  property as **data** (a per-job predicate list), not a job-name special case,
  because `core-dep-graph`'s converse is the same kind of fact.
- *Accept*: a step invoking cargo inside `traceability` turns a check red
  **naming the job and the property**; the property is stated **once, where the
  check reads it**; and if the parse is not worth it, that ruling is recorded
  at the job with the prose sites pointed at it.

Two of the row's three `Accept` clauses survive intact and drive the ruling.
The `Do`'s instrument does not.

---

## 3. Every shape, attacked one by one

### 3.1 The row's lean — job attribution in `check-ci-shell.py`, plus a per-job cargo predicate

**Refused. Vacuous, measured (§1.6).** The predicate would be evaluated against
`run:` block text, and neither the five green steps nor the one near-miss
contains the token. The row's own `Notes` says the near-miss *"was caught by
reading, not by a check"* — and this check would not have caught it either.

Worth being precise about what fails here: not the parse, not the data-driven
shape, not the file. **The observable.** `run:` text is the wrong observable
for a property of a process tree. Any static instrument reading that observable
inherits the emptiness, however well it is built.

### 3.2 The same, but with a real YAML parser

**Refused, twice.**

*First, it does not fix anything.* `yaml.safe_load` hands you exactly the same
strings:

```
$ python3 -c "…yaml.safe_load(ci.yml)['jobs']['traceability']['steps']…"
  run -> './scripts/ci-lanes.sh traceability'
  run -> './scripts/ci-lanes.sh ci-shell'
  run -> './scripts/ci-lanes.sh fuzz-budget'
  run -> './scripts/ci-lanes.sh anchor-net-policy'
  run -> './scripts/wasm-bitmatch.sh --trigger-self-test'
```

Job attribution comes free, and the vacuity comes free with it. A correct parse
of an empty predicate is an empty predicate.

*Second, it would damage the property it asserts.* Every `run:` block in this
repository must be a committed script call or an allowlisted line (Q43), and
every Python install must be version- and hash-pinned. Adding PyYAML to
`check-ci-shell.py` therefore adds a hash-pinned `pip install` step **to the
`traceability` job** — the job whose freedom from setup is the property. The
mechanism would consume its own subject. `check-ci-shell.py:96-101` refuses
the library for that exact reason and was right to.

*Recorded against that docstring anyway, because it is half wrong*: its second
stated reason — *"a YAML loader would also normalise away the very indentation
that tells a single-line `run:` from a block one"* — is false. Measured, a
loader tells them apart **better**: a block scalar returns with its trailing
newline, and the `defaults: run: shell: bash` case that the hand-rolled scanner
special-cases at `:112-117` comes back as a `dict` rather than a `str`, which
is a type distinction rather than an indentation heuristic. The real cost of
`safe_load` is **line numbers** — every failure message in the file is
`workflow.name:lineno`, and recovering that needs a mark-recording `Loader`
subclass. The docstring names the wrong cost and omits the real one.

### 3.3 Static assertion by recursing into the called script

**Refused. Five false reds on a green job today (§1.6)**, including on
`wasm-bitmatch.sh --trigger-self-test`, the step whose cargo-freeness Q153
verified by running it. `ci-lanes.sh` is a dispatcher: its cargo calls belong
to lanes the `traceability` job never selects. A static reader cannot follow
`$1`.

### 3.4 Static assertion of the *other* half — "this job has no toolchain step and no cache step"

**Refused: it asserts the half that was never at risk.** The near-miss added no
toolchain step; it added a step that shells out to cargo. This predicate would
have been green throughout. It is also made redundant by the ruling: under the
runtime guard, adding a toolchain step does not clear the red, because the
shims sit ahead of whatever the toolchain step installs.

### 3.5 Job-level `env: RUSTUP_TOOLCHAIN: <a sentence>` — the two-line shape

Genuinely attractive and genuinely measured:

```
$ env RUSTUP_TOOLCHAIN=antseal-traceability-is-cargo-free cargo metadata --format-version 1 --no-deps --locked
rc=1
error: override toolchain 'antseal-traceability-is-cargo-free' is not installed: the RUSTUP_TOOLCHAIN environment variable specifies an uninstalled toolchain
```

Two lines of YAML, no new script, no new step, no runtime cost, it covers every
future step of the job, it fails instantly, it **prevents** the expensive
implicit install rather than merely reporting it, and the poison value itself
carries the message.

**Refused as the primary mechanism, on one measurement:**

```
$ env RUSTUP_TOOLCHAIN=antseal-traceability-is-cargo-free ./scripts/gate-features.sh --check-partition
rc=1
…
json.decoder.JSONDecodeError: Expecting value: line 1 column 1 (char 0)
::error::gate-features: cargo metadata returned NO features at all — the extractor is broken, so a green verdict here would mean nothing
```

Run through the exact command of the exact near-miss, the beautiful message is
swallowed by `gate-features.sh:116`'s `2>/dev/null`, and what a maintainer
reads is a Python traceback blaming the wrong file. **That fails the row's
`Accept` — "turns a check red *naming the job and the property*".** It turns a
check red naming neither.

It is not merely rejected but **subsumed**: the ruling's `rustup` shim covers
every case this covers, and the marker file covers the case this cannot.

### 3.6 The brief's shape — "run the `traceability` job's steps with cargo removed from `PATH`"

**Accepted in substance. Refuted in all three of its details**, and the details
are the whole engineering:

1. *Removal is the wrong operation.* A script guarded by
   `command -v cargo >/dev/null || …` — `scripts/reserve-crates.sh:74` is the
   shape, and `ci-lanes.sh:1204` and `fuzz.sh:133` are the same idiom for
   cargo subcommands — **skips silently** when the binary is absent. Removal
   converts a would-be red into a quiet no-op, which is the failure direction
   this row exists to close. A **failing shim** is required: it makes
   `command -v` succeed and the invocation fail.
2. *The message must not travel by stderr alone.* Measured at
   `gate-features.sh:116` (§1.9): the callee redirects it to `/dev/null`. The
   guard needs a channel the callee cannot redirect — **a marker file** — and a
   later step that reads it.
3. *It must not be a second execution.* Re-running the job's five steps under a
   stripped `PATH` doubles a job that exists because it is cheap. The mask must
   be **the job's default for every step**, installed once, costing nothing.

### 3.7 A per-step wrapper — `run: ./scripts/cargo-free.sh ./scripts/ci-lanes.sh …`

**Refused: opt-in cannot catch what it exists to catch.** It would pass Q43
(`SCRIPT_CALL` finds both paths on the one line and both exist and are
executable), it needs no new Actions mechanism, and it is self-documenting at
each step. And it is useless here, because the step that one day adds cargo
will simply be written without the prefix, and nothing will fire. Only a
**job-scoped** mechanism covers steps that do not yet exist.

### 3.8 Do nothing — record the ruling at the job and point the sixteen sites at it

The row names this arm explicitly and it must be taken if the measurements
support it. **They point the other way, on five counts:**

1. The failure is **silent** (§1.2) — a green job, minutes slower, for ever.
   Silent decay is the class this project prioritises above all others.
2. The cost is **billed**, on a repository that exhausted its Actions minutes
   on 2026-08-10 and whose own CI document names minute consumption as the
   standing suspect for the refused dispatch.
3. The near-miss has **already happened once**, and was caught by one lane
   reading carefully.
4. The prose has **already been wrong once**, and `local-gate.sh:57-64` is the
   project's own record of it.
5. The drift surface is **16 statements across 6 files** (§1.3), not the 3
   across 2 the row assumes — so the do-nothing arm's own remedy ("point the
   three prose sites at the ruling") is a five-fold larger edit than the row
   costs it at, and buys prose pointing at prose.

Against that, the ruling costs one script, two steps on one job, one step on
another, and no new required context.

---

## 4. Ruling

**RULING 1 — the property becomes a machine assertion.** The do-nothing arm is
refused on §3.8's five measured counts.

**RULING 2 — it is not expressed in `check-ci-shell.py`, and the reason is the
observable, not the cost.** A per-job predicate over `run:` text is vacuous
against the incident that produced the row (§1.6). This is recorded *at*
`check-ci-shell.py` so the next reader does not re-propose it: the row's
instinct was right that the file is where workflow facts get checked, and wrong
that this is a workflow fact. It is a fact about a process tree.

**RULING 3 — job attribution is not added.** Measured cheap (§1.7, nine lines,
65/65) and therefore **not** refused on cost — refused because nothing in this
ruling needs it. It is recorded as measured-and-available in §8 so that a
future row wanting a genuine per-job workflow predicate does not re-litigate
the price.

**RULING 4 — the assertion is `scripts/cargo-free.sh`, a new committed script
with four modes**, armed at the job:

- `--arm <job>` — runs `--self-test` first (house rule: self-test, then act),
  then creates
  `${RUNNER_TEMP:-${TMPDIR:-/tmp}}/antseal-cargo-free/` containing `bin/cargo`,
  `bin/rustc` and `bin/rustup`. Each shim appends its own `argv` to
  `…/TRIPPED`, prints `::error::` naming the job and the property to **both**
  stdout and stderr, and exits **127** — the status a caller would have seen
  had the binary genuinely been absent, so no `|| return 1`, `set -e` or
  `PIPESTATUS` idiom in any callee meets a novel value. It then appends
  `…/bin` to `$GITHUB_PATH`, which prepends it for **every subsequent step of
  the job, including steps not yet written**. Outside Actions (`$GITHUB_PATH`
  unset) it prints the equivalent `PATH` export and exits 0, so the script is
  runnable locally.
- `--verdict <job>` — the last step. **Red if `…/TRIPPED` exists**, printing
  every recorded invocation, the job name and the property. **Also red if the
  guard directory does not exist at all**, because that means `--arm` never
  ran: the two steps guard each other, and deleting the arm alone turns the
  verdict red without any static parse.
- `--require <job>` — the converse, for `core-dep-graph`: assert cargo resolves
  and runs, failing with a message naming the job and the property. This is the
  row's *"`core-dep-graph`'s converse property … is the same kind of fact"*,
  granted — as an executed fact rather than a predicate table, because §1.9
  showed the converse's current failure is loud **and misdiagnosing**.
- `--self-test <no arg>` — plants the failure of each of the three arms in a
  scratch directory and requires each to go red **by its message, not by its
  exit status**, per `scripts/lib/red-arm.sh`. It builds both a cargo-present
  and a cargo-absent `PATH` inside its own scratch tree, so it is independent
  of the ambient `PATH` and gives the same verdict inside the armed job as
  outside it.

**RULING 5 — the property is stated once, in `scripts/cargo-free.sh`'s
header**, and the sixteen sites lose their assertion of it and keep only their
own local point, citing the script. This is the row's second `Accept` clause,
executed at the measured scale rather than the assumed one.

**RULING 6 — no new job, no new required-status context. The set stays at 19.**
Three steps are added across two existing jobs, and Q56's generated context
list is untouched.

---

## 5. Edit set

Exactly what an implementing lane does. Quoted anchors are the reliable
handles; line numbers are as of this document's date and will drift.
- `docs/decisions/README.md` — this decision's index row. **Applied 2026-08-11**, executing [D119](D119-decision-index-identity-and-the-index-row-sections.md) §5 step 4; the former `## Index row` section is demoted to this line under D119 RULING 4, and RULING 6 puts the row in the act that commits the record.

### 5.1 `scripts/cargo-free.sh` — NEW, executable (`chmod +x`)

Header states the property **once** and is the single source RULING 5 points
at. Body implements the four modes of RULING 4. Constraints an implementer must
honour, each traceable to a measurement in §1:

- Guard dir: `${RUNNER_TEMP:-${TMPDIR:-/tmp}}/antseal-cargo-free`. **Never
  inside the workspace** — `secret-guard`, `vector-freeze` and
  `check-traceability.py --self-test` all read or copy the tree.
- Shims write to `TRIPPED` **before** printing, because the print may be
  discarded (§1.9) and the file may not.
- Shims exit **127**, not 1.
- `--arm` must be idempotent: re-arming an already-armed job is a no-op success,
  so a re-run of the step cannot erase a `TRIPPED` marker.
- `--verdict` prints the full recorded `argv` list, so the reader learns *which*
  step tripped it without re-running anything.
- `--require` must distinguish "not on `PATH`" from "on `PATH` but refuses to
  run" and say which.
- No `unsafe` idioms in shell terms: `set -euo pipefail`, quoted expansions,
  and `${PIPESTATUS[0]}` wherever a pipe's status is read.

### 5.2 `.github/workflows/ci.yml` — three steps and five comment edits

**(a) `traceability`, immediately after `- uses: actions/checkout@v4`:**

```yaml
      # D124/Q182 — this job's cargo-free property, asserted instead of
      # stated. Installs failing `cargo`/`rustc`/`rustup` shims ahead of the
      # real ones for every step below, INCLUDING STEPS NOT YET WRITTEN, and
      # self-tests first. The property itself is stated once, in
      # scripts/cargo-free.sh's header. Measured 2026-08-11: all five steps
      # below run byte-identically with cargo masked.
      - name: Q182 — self-test the cargo-free guard, then arm it
        run: ./scripts/cargo-free.sh --arm traceability
```

**(b) `traceability`, as the LAST step of the job** (after the
`--trigger-self-test` step):

```yaml
      # D124/Q182 — reads the marker back. Red if any step above invoked
      # cargo, AND red if the arming step above is gone, so the two steps
      # guard each other. The marker exists because a callee can redirect the
      # shim's stderr to /dev/null and one already does
      # (scripts/gate-features.sh:116).
      - name: Q182 — no step of this job invoked cargo
        run: ./scripts/cargo-free.sh --verdict traceability
```

**(c) `core-dep-graph`, after the `Swatinem/rust-cache@v2` step and before
`Assert antseal-core normal deps are I/O-free`:**

```yaml
      # D124/Q182 — the converse property, asserted for the same reason and
      # in the same instrument. Without it, cargo missing here surfaces as an
      # unhandled JSONDecodeError and `the extractor is broken` — loud, and
      # pointing at the wrong file (D124 §1.9).
      - name: Q182 — the converse: cargo IS available in this job
        run: ./scripts/cargo-free.sh --require core-dep-graph
```

**(d) Comment edits, sites 1-5 of §1.3.** Each keeps its own local point
(why the step rides that job, the context count) and **drops the assertion**,
replacing it with a citation. Anchor text → replacement intent:

| anchor | change |
| --- | --- |
| `ci.yml:672` *"Neither needs cargo, so this lane is seconds, not minutes."* | keep the cost claim, cite the guard for the cargo claim |
| `ci.yml:702-704` *"it needs no cargo and no network, so folding it in costs SECONDS"* | keep "no network" and the context arithmetic; cargo clause → citation |
| `ci.yml:710-712` *"Python only, no cargo, no network"* | same |
| `ci.yml:734-737` *"it is genuinely cargo-free AND git-free — verified by running it with cargo off PATH, rc 0"* | keep the git-free claim (nothing asserts it); replace the cargo half with the citation — this is the site where the manual verification becomes permanent |
| `ci.yml:239-244` *"`traceability` carries no toolchain and no cache BY DESIGN"* | keep the placement argument; the property clause cites `--arm`/`--verdict`, and the sentence gains a pointer to `--require` on this job |

### 5.3 `scripts/ci-lanes.sh`

- `:852` *"Python-only, no cargo, no network, so it rides in the `traceability`
  job"* → keep the placement, cite the guard for the cargo clause.
- Add a lane `cargo-free` that runs `./scripts/cargo-free.sh --self-test`, so
  the guard's own command is executed before a push. This is Q43's rule
  applied to the guard itself — *"a guard whose own command has never been
  executed"* is the defect `check-ci-shell.py`'s docstring opens with.

### 5.4 `scripts/local-gate.sh`

- Add the `cargo-free` lane to the gate.
- `:57-64` — the correction record **stays** (it is history, and D117 forbids
  deleting a ruled record); append one line that the property is now
  machine-asserted, citing D124.
- `:75-78` *"Measured cargo-free and git-free … which is what earns it the job
  that has no toolchain"* → *"measured"* becomes *"asserted every run"*, citing
  the guard.
- Add the new lane to the header's both-directions ledger that Q153 built, on
  the *gate-and-CI-agree* side.

### 5.5 `docs/ci-verification.md` — six sites and one new section

- Sites 9-14 of §1.3 drop their assertion and cite the guard.
- Site 12 (`:1753-1772`, the Q153 measurement table) is a **record of a
  measurement on a date** and must not be rewritten — append that the manual
  measurement is now an every-run assertion, in D117 §2.2's dated-correction
  form.
- New section for D124: what is asserted, where, the two-steps-guard-each-other
  property, `--require`'s converse, and **the required-context count unchanged
  at 19, recounted from `ci.yml` rather than read from this file** (this
  document's own rule).
- Correct the record at the `traceability` placement argument: the failure mode
  of a cargo step there is an **implicit toolchain install on a green job**,
  not a failure — this file already says so at `:1768-1771` and is the source
  Q182's row garbled.

### 5.6 `docs/testing/fuzzing.md:312` and `docs/testing/anchor-ci-policy.md:148-149`

Sites 15 and 16. Same treatment: keep the cost/placement claim, cite the guard
for the cargo clause.

### 5.7 `scripts/check-ci-shell.py` — two comments, no code

- At `run_blocks`'s docstring: record that a **per-job cargo predicate was
  considered here and refused as vacuous** (D124 §3.1), so the row's instinct
  is not re-proposed; and correct the second stated reason for the hand-roll,
  which is false (D124 §3.2) — a loader distinguishes the two `run:` forms
  better, and the real cost is line numbers.
- At the same site: record that job attribution was **prototyped and measured
  at nine lines, 65/65 attributed** (D124 §1.7), so a future row that genuinely
  needs it does not price it at "the larger half of the work".

### 5.8 `tasks/Q.md` — Q182's entry

Append a dated correction, in D117 §2.2's form, for the three measured
refutations of the row's own body: the failure mode (§1.2), the prose-site
count (§1.3), and *"the larger half of the work"* (§1.7). The row's `Do` is
**superseded**, not struck — it named a real requirement and the wrong
instrument.

---

## 6. Commands run, with verdicts

Every command below was run by this lane. Failures are reported by message.

| command | verdict |
| --- | --- |
| `git status --short` (start of lane) | clean |
| `sed -n '691,740p' .github/workflows/ci.yml` | 1 `uses:`, 5 `run:`, no rustup step, no cache step |
| job classifier over `ci.yml` (§1.1) | 15 HAS-TOOLCHAIN, **2 NO-TOOLCHAIN**: `secret-guard`, `traceability` — the "only two" claim is exact |
| `grep -rn "rustup-init\|dtolnay/rust-toolchain\|actions-rs\|curl.*sh.rustup.rs\|apt.*rust" .github/workflows/` | no output — **no workflow installs rustup** |
| `grep -n "job" scripts/check-ci-shell.py` | **one line**, `:59`, inside a prose reason string — Q182's entry is confirmed and the ledger it refutes stays refuted |
| vacuity test over the 5 run lines + the near-miss (§1.6) | **0 of 6 contain a `cargo` token** |
| `grep -c "cargo " scripts/{gate-features,ci-lanes,wasm-bitmatch}.sh` | 8 / 31 / 4 — callee-grep would red all five green steps |
| `python3 attrib_proto.py` | `total run blocks: 65 … unattributed: 0` — matches the shipping checker's own count |
| `python3 -c "import yaml; print(yaml.__version__)"` | `PyYAML OK 6.0` — available, and it changes nothing (§3.2) |
| `grep -rln "import yaml\|yaml.safe_load\|yaml.load" scripts/ crates/ probes/` | no output — **nothing in the tree parses YAML** |
| 5 × (control, masked) step runs | rc 0 / rc 0, **byte-identical output**, all five |
| warm re-measure of `ci-lanes.sh traceability` | `real 0m7.123s` control vs `0m6.862s` masked — the earlier 4m28 was cold cache; **no cargo claim is made from it** |
| `gate-features.sh --check-partition` with cargo masked | **rc 1**, message: unhandled `JSONDecodeError` then `::error::gate-features: cargo metadata returned NO features at all — the extractor is broken` — loud and **misdiagnosing** |
| `RUSTUP_TOOLCHAIN=<sentence> cargo metadata …` | **rc 1**, `error: override toolchain '…' is not installed: the RUSTUP_TOOLCHAIN environment variable specifies an uninstalled toolchain` |
| the same, through `gate-features.sh --check-partition` | **rc 1**, message swallowed by `2>/dev/null`; reader sees the wrong diagnosis — this is what refuses §3.5 |
| `grep -rn "GITHUB_PATH\|GITHUB_ENV\|GITHUB_STEP_SUMMARY" .github/ scripts/` | no output — the ruling introduces the **first** use of `$GITHUB_PATH` in this repository (§7) |
| `python3 scripts/check-traceability.py --check` | **argparse error, exit 2** — `check-traceability.py: error: unrecognized arguments: --check`. **The flag does not exist**; the ordinary check is flagless. See §8 (v) |
| `python3 scripts/check-traceability.py` (the actual check) | **PASS** — `check-traceability: ok (freeze-boundary, matrix, decisions, task-citations, task-entries, decision-owners)`; matrix `34 rows over 34 spec bullets, 97 references resolved … status gate: all 22 row(s) at or before M1 read 'covered'`; entries `582 rows (581 live + 1 struck) against 582 entries` |
| `python3 scripts/check-traceability.py --self-test` | **PASS** — 28 cases, every one `self-test: ok`, no `matched nothing` and no `stayed green` |
| `python3 scripts/check-ci-shell.py` | **PASS** — `65 run: block(s) across 4 workflow(s) … every one is a committed script call or one of 9 allowlisted lines` |
| `git status --short` (end of lane) | this lane's only repository write is `docs/decisions/D124-asserting-the-cargo-free-job-property.md`. The tree also carries nine other paths modified or added by the nine sibling lanes running concurrently in it; a clean status is not obtainable mid-wave and is not claimed |

---

## 7. What this does not do

1. **It does not assert the property locally.** `local-gate.sh` will run
   `cargo-free.sh --self-test`, which proves the guard can go red; it does not
   run the CI job, so the property itself is asserted on the remote only. That
   is the right venue — the property is about a *job* — but it means a
   contributor cannot break it locally and find out locally.
2. **It introduces `$GITHUB_PATH` to this repository for the first time.**
   Measured: no workflow and no script uses it today. It is a stable, documented
   Actions mechanism, but it is a new kind of thing in a workflow that until now
   used only `uses:` and `run:`, and a reader of `ci.yml` will not see the
   `PATH` change at the step that causes it.
3. **It cannot catch a cargo invocation by absolute path.** A step running
   `/usr/share/rust/.cargo/bin/cargo` or `$CARGO_HOME/bin/cargo` bypasses
   `PATH` entirely. Nothing in the tree does this and the idiom would be
   conspicuous in review, but the guard's coverage is `PATH` resolution, not
   process creation.
4. **It does not make deletion of both guard steps loud.** Deleting `--arm`
   alone reds the verdict; deleting both is a two-step deliberate act that
   removes two steps whose names say what they are, and nothing fires. Closing
   that needs the static per-job step-presence check RULING 3 declined to build.
5. **It does not fix `gate-features.sh`'s unhandled traceback.** `--require`
   on `core-dep-graph` fires *before* the extractor is reached, so the wrong
   diagnosis stops being seen — but the naked `JSONDecodeError` on empty stdin
   remains in the code, reachable by any other cause of empty `cargo metadata`
   output. See §8.
6. **It does not touch the required-context set, the frozen registry, or any
   golden vector.** Zero frozen bytes.
7. **It does not adjudicate `--heavy` or `e2e-devnet.sh --self-test`**, the two
   Q153 lanes that stayed local. Their ruling stands.

---

## 8. Discovered work — described, not registered

Prose only; the orchestrator assigns identifiers at bookkeeping.

**(i) `gate-features.sh`'s extractor crashes on empty input and blames itself.**
`scripts/gate-features.sh:116` pipes `cargo metadata … 2>/dev/null` into an
inline `python3 -c` that calls `json.load(sys.stdin)` with no guard. Any cause
of empty output — cargo absent, cargo failing, a lock conflict, a network stall
on `--locked` resolution — produces an unhandled `JSONDecodeError` traceback
followed by an `::error::` that says *the extractor is broken*, which is the
one thing that is not wrong. Two defects in one line: cargo's exit status is
discarded, and its stderr is discarded with it. This project's own rule is that
library code parses defensively and never panics on malformed input; a CI guard
that hands a maintainer a stack trace naming the wrong file is the same defect
in shell. Small, and independent of D124.

**(ii) `check-ci-shell.py`'s docstring gives a false reason for its own
design.** Its stated second reason for hand-rolling the scan — that a YAML
loader normalises away the indentation distinguishing a single-line `run:` from
a block one — is measurably false; a loader distinguishes them better, and
returns the `defaults: run:` mapping case as a `dict`, which is exactly the
case the scanner special-cases by hand. The real cost is line numbers, which
the docstring never mentions. This is the same class as the *"seconds and
cargo-free"* prose: a design justification that reads as an explanation and was
never re-measured. Worth a sweep of the other "hand-rolled rather than X"
justifications in `scripts/`, of which there are several.

**(iii) The per-job step-presence predicate that RULING 3 declined.** Job
attribution is measured, prototyped and cheap (nine lines, 65/65 attributed,
zero unattributed). It is useless for cargo but non-vacuous for a class of
facts this project already cares about: *this named step is still present in
this named job*. `check-anchor-net.py` already asserts a sibling — an env var
armed in every workflow — but only per file, because the thing it checks lives
at workflow level. The moment a second guard is armed at a *job*, the
step-presence predicate stops being speculative and closes §7.4. Filing the
measurement now so the price is not re-litigated at "the larger half of the
work".

**(iv) Sixteen prose sites for one property, and no rule about when that is
allowed.** Q146 removed a drift surface rather than build a checker for prose,
and RULING 5 does the same here at a scale five times what the row assumed.
Neither produced a rule. Some repetition is correct — each of the sixteen sites
had a local reason to mention the property. What is missing is the distinction
between *citing* a property and *asserting* it, which is exactly the edit
RULING 5 performs sixteen times by hand. A one-paragraph rule in
`CONTRIBUTING.md` would let the next author get it right without a decision
record. Related to Q185's preamble question, which is the same distinction in a
different document.

**(v) The lane-brief template instructs a command that does not exist, and
this is the fourth consecutive record of it.** Every planning lane is told to
finish by running `python3 scripts/check-traceability.py --check`. There is no
`--check` flag; argparse exits 2 with `unrecognized arguments: --check`, and
the ordinary check is the flagless run. **D119 §(19), D122 and D123 §10 (f) —
three sibling wave-15 decisions — each record the identical finding**, and this
document is the fourth. The instance is therefore already well documented and
does not need registering again; **what is new is the count**. Four independent
lanes discovering the same nonexistent flag in the same wave is not four lane
errors, it is one template error, and the template is the artefact that should
be corrected — otherwise every future lane pays the same wasted invocation and
spends a paragraph recording it. Note the hazard this creates and which this
lane nearly demonstrated: a lane that pre-fills its verdict table before
running the commands will record a **PASS for a command that cannot run**.
This document did exactly that and the row was corrected after measurement,
which is why §6's rows are now quoted from output rather than anticipated.

**(vi) `wasm-bitmatch.sh --trigger-self-test`'s git-freeness is asserted by
nothing.** `ci.yml:734-736` claims it is *"genuinely cargo-free AND git-free —
verified by running it with cargo off PATH"*. D124 makes the cargo half an
assertion; the git half stays a 2026-08-10 measurement in a comment. The same
guard shape extends to it at near-zero cost — a `git` shim alongside the other
three — and the question is only whether the job's other four steps are
genuinely git-free, which this lane did **not** measure and must not be assumed
from the one step that was.

---

## Outcome

The row asked whether an assertion was worth a parse. **The parse turned out to
be cheap and the assertion turned out not to need it.** Nine lines buy job
attribution for all sixty-five `run:` blocks in the repository; and the
predicate those nine lines would have fed reads green on the exact line that
produced the row, because `./scripts/gate-features.sh --check-partition`
contains no `cargo` token and neither does anything else the job runs. The cost
was never the obstacle. The observable was.

What the property actually is: a claim about what happens when five committed
scripts execute — which argument they were called with, which branch they took,
what they shelled out to. No reading of the YAML can see that, and the two
readings available see either nothing at all or five false reds on a job that
is green. So the assertion goes where the fact is: at the job, at runtime,
where a shim either gets called or does not.

The failure this closes is not the one the row describes. Cargo is on `PATH` in
`traceability` today — the runner ships rustup and no workflow installs it — so
a cargo step there does not fail. It resolves `rust-toolchain.toml`, downloads
1.92.0 with `rustfmt`, `clippy` and the `wasm32` std into a job with no cache,
and reports success, on every pull request and every push, on a repository that
ran out of Actions minutes eight days ago. The row's own source records that
correctly at `docs/ci-verification.md:1768-1771`; the row garbled it into a
missing toolchain and a cache that does not exist. The direction it named as
*silent* is more silent than it knew.

And the direction it dismissed as *loud* is loud and wrong. With cargo masked,
`core-dep-graph`'s partition check prints a Python stack trace and tells the
reader the extractor is broken. It is not. That measurement did two things: it
earned `--require` its place in the same instrument, and it produced the
constraint that shapes the whole design — `gate-features.sh:116` sends cargo's
stderr to `/dev/null`, so any guard whose diagnosis travels by stderr can be
silenced by the code it is guarding. Hence a marker file, and a step that reads
it back, and two steps that keep each other honest.

Sixteen statements across six files become one, in the header of the script
that enforces it. That is the row's second `Accept` clause, at five times the
scale the row costed it — and the reason the count was wrong is the reason the
assertion is worth building: nobody had counted, because nothing was counting.
