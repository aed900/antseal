# D181 — `Q111` is promoted because its shape is **live in the M4 gate's own Sepolia preflight**, and the lint forbids the pipeline shape **in every tracked shell file** without judging the payload

- **Status: RESOLVED. The row's direction survived. The survey's frozen-class reading was right
  for the row as written, and a measurement overturned it. Three of the row's premises fell.**
  - **`Q111` is promoted under rule 8.** Survey lane PS classified `Q111` in the frozen instrument
    class, for four reasons:
    - it is an M2 row minted on 2026-08-06, before D125;
    - its subject is a shell idiom in the CI and gate scripts;
    - its one live firing, in `secret-guard`'s self-test, was fixed at that site on 2026-10-15;
    - no ship-path `Accept` was waiting on its lint.

    Planning lane P4 then found the shape **live** on the ship path, in
    `scripts/devnet/sepolia-preflight --self-test`. That self-test is the runbook step that proves
    the preflight's wrong-chain refusal before `Q32`'s Sepolia run. It failed **38/500** at
    `fbcee1e`, and **0/500** with its three sites converted. That blocks `Q32`'s *"Sepolia run green
    before any mainnet action"*, which `Q34`'s gate consumes, so rule 8's condition for promotion is
    met (§2 R1).
  - **The census counted 11 sites; there are 16.** It missed five, three of them live:
    - `sepolia-preflight` ×3, which has no `.sh` suffix;
    - `ci-lanes.sh:1380`, whose writer is an external `grep`;
    - `wasm-toolchain-audit.sh:77–78`, where the pipe is split across lines by a trailing `|`.

    Each was either judged safe by eye or never opened.
  - **The rule must key on the reader, not on `printf` and not on `pipefail`.**
    - `echo` races just as `printf` does: two-line output missed 53 and 46 times in 3 000.
    - `-m`, `-l` and `-L` stop reading early, like `-q`.
    - The libs set nothing themselves and are sourced by scripts that set `pipefail`.

    The safe property is neither a small payload nor, strictly, one line of output. It is that
    **nothing is written after the matched line's newline**: a multi-line output matched on its last
    line raced 0 times.
  - **`Q111`'s `Do` gives the wrong mechanism for a right fix.** On bash 5.2.15 a here-string of up
    to 60 000 B is a pipe, not a temp file. It is still safe, because the shell writes it whole
    before the reader starts.
  - **Two neighbouring rules are refused on yield.** A `| head` rule would flag 35 sites, none a
    true positive. A `grep -c` rule would target a different hazard: `grep -c` reads to EOF, and its
    risk is exiting 1 on a zero count.
- **Date: 2026-10-16**
- Owner rows: **`Q111`** (promoted by §2 R1; its lint, its sixteen conversions and both `Accept`
  rows are §2 R2–R7); **`Q32`** (the acceptance the promotion protects, through its Sepolia run's
  runbook step).
- Related:
  - **D125** (rule 8 and the frozen class);
  - **`Q43`** (committed scripts, cited as though it closed this class, which it does not);
  - **D52** and `CONTRIBUTING.md`'s list of storage-touching paths (`scripts/devnet/**`);
  - `scripts/lib/red-arm.sh` (arms are judged by their own message);
  - the 2026-10-15 ledger entry on the `secret-guard` firing.

## 0. What was measured against

`HEAD` `fbcee1e`.

Planning lane P4 (wave 37) used bash 5.2.15 and GNU grep 3.8, run under `env -i PATH=/usr/bin:/bin`
because the session's `grep` is a ugrep wrapper. It:
- prototyped the lint over every tracked shell file;
- raced each writer shape thousands of times;
- looped the preflight's self-test 500 times at `HEAD` and 500 times on a converted copy.

The baseline gate was running throughout (load 1–4). No tracked file was written. Survey lane PS
classified every open row against rule 8.

Before writing, the records lane re-counted the sites with an independent rough pattern. The same
selection rule gives 31 files and the same sixteen `file:line` pairs. The lane also re-read
`scripts/devnet/sepolia-preflight:228-292`, `docs/devnet/sepolia-devnet.md:58-65` and
`scripts/check-ci-shell.py` at `HEAD`.

## 1. What was measured

### 1.1 The sixteen sites

The selection is `git ls-files -z`, then any file with a shell shebang, a `.sh` suffix, or a
`# shellcheck shell=` line. That gives 31 files: 28 scripts that set `pipefail`, the `/bin/sh` hook,
and 2 libs sourced by `pipefail` scripts. Together they hold 398 pipes:
- 16 pipe into `grep` with an option that stops reading early;
- 35 pipe into `head`;
- none sits inside the 26 heredocs.

| site | writer | status |
| --- | --- | --- |
| `scripts/ci-lanes.sh:315, 319, 323, 571, 575, 844, 905, 909` | one-line literal | safe |
| `scripts/ci-lanes.sh:1380` | external `grep` | safe |
| `scripts/e2e-sepolia.sh:150, 224, 326` | one value, no newline | safe |
| `scripts/wasm-toolchain-audit.sh:77–78` | one-line `cargo metadata` | safe (0/200) |
| `scripts/devnet/sepolia-preflight:244, 269, 279` | multi-line `$out` | **live** |

The 2026-10-15 note on `Q111` counted eleven sites (the eight `ci-lanes.sh` literals and the three
`e2e-sepolia.sh` values) and judged them safe by their output.

**The live sites are in the preflight's self-test** (`self_test()`, under `set -uo pipefail` at
`:33`).
- Failures by probe at `HEAD`, over 500 runs:

  | probe | failures |
  | --- | --- |
  | Ethereum Sepolia | 9 |
  | funded | 9 |
  | other chain | 7 |
  | no contract | 7 |
  | zero ANT | 6 |
  | contracts present (it matches on the last line) | 0 |

- Totals: **38/500 at `HEAD` and 0/500 converted**. Interleaved runs gave 11/300 against 0/300.
- A failure reads *"output did not contain THIS IS ETHEREUM SEPOLIA"*, followed by a dump of output
  that does contain it.
- Every failure is a false red: the race can only make the self-test report a correct preflight as
  broken.

### 1.2 Mechanism

- GNU grep matches whole lines. `-q`, `-m`, `-l` and `-L` make it exit at the first match and close
  the pipe.
- A writer that writes again after that gets `SIGPIPE` (exit 141), and `pipefail` makes that the
  pipeline's status. The guard therefore reports *no match* exactly when it matched early.
- A writer paused mid-line gives `0 0`; one paused after the matched line gives `141 0`.
- Misses in 3 000 runs, by writer:

  | writer | misses |
  | --- | --- |
  | one-line literal | 0 |
  | two-line literal | 37 |
  | two-line variable | 44 |
  | single value | 0 |
  | multi-line `%s` | 32 |
  | item 5 of a 12-line list | 50 |
  | external-grep writer | 0 |
  | here-string | 0 |
  | `echo` | 53 |
  | `printf '%s\n' a b` | 46 |

- A 55 140 B single-line `cargo metadata` raced 0 times in 200.
- `-q`, `-m1`, `-l` and `head` make `seq` exit 141; `sed -n 1p` and `grep -c` do not.
- `yes | grep -x y >/dev/null` timed out (rc 124). GNU grep drains its input, so `>/dev/null` is not
  a disguised `-q`. (grep 3.11's `finalize_input` → `drain_input`, `grep.c:1801–1813`, was read, not
  run.)
- **Here-strings.** On bash 5.2.15 a here-string of ≤ 60 000 B is a pipe, and one of 70 000 B is a
  temp file. Either way the shell writes it whole before the reader starts.

### 1.3 Nothing parses a pipeline today, and the venue already runs

- `scripts/check-ci-shell.py` reads only workflows (`:52`, `:171`, `:231`, `:317`) and only
  `stat()`s scripts (`:190–192`).
- `check-ci-paths.py` reads scripts only for path literals and `scripts/x` references.
- `shellcheck` is absent, and no lane runs `bash -n`.
- `ci-shell` already runs at `local-gate.sh:450` and `ci-always.yml:167`.
- The rule needs no `check-ci-paths.py` edge, because `ci.yml` never reaches `check-ci-shell.py`
  (`check-ci-paths.py:355`, UNREACHED). A new script called from `ci-lanes.sh` would need an
  `UNREACHED_EDGES` entry (R4e, `:921–936`).
- The existing self-test plants its faults into a dot-prefixed scratch workflow under
  `.github/workflows/` (`.ci-shell-selftest.yml`), which is a write to the live tree.

### 1.4 The rules not taken

- **`| head`**: 35 sites. 33 discard its status, mask it, or use only the value. The two that
  consume the status are safe:
  - `vector-freeze.sh:281` runs under `set -e` and writes a 1 272 B manifest in one write;
  - `e2e-devnet.sh:415` raced 0 times in 300.
- **`grep -c`** reads to EOF; its hazard is exiting 1 on a zero count.
- **`-m`, `-l` and `-L` stay in the rule.** Each made `seq` exit 141 in 3 of 3 runs, though no site
  uses them today.

### 1.5 The rule-8 reading, and the ship-path link

Rule 8 promotes an instrument finding *"only when it blocks an acceptance on the ship path"*, and
unfreezes a frozen row *"by promotion only"*. PS's reading at `HEAD` (`TODO.md:762`: *"The lint is
still owed"*) found no such acceptance. P4 measured this link:
- `Q32`'s `Accept` row 1 is *"Sepolia run green before any mainnet action"*.
- Its script, `scripts/e2e-sepolia.sh`, runs `scripts/devnet/sepolia-preflight --address …` as
  stage S1 (`:110`, `:254`).
- The Sepolia runbook lists `scripts/devnet/sepolia-preflight --self-test` among its commands,
  annotated *"offline; planted wrong-chain answers must go red"* (`docs/devnet/sepolia-devnet.md:62`).
- `Q34`'s gate order begins with *Sepolia E2E green*.

## 2. RULING

### §2 R1 — `Q111` is promoted under rule 8, and only `Q111` (the promotion)

The shape is live in the M4 gate's Sepolia preflight: its self-test fails 38/500 at `fbcee1e` and
0/500 converted. That blocks `Q32`'s Sepolia run, a ship-path acceptance. This record takes the row
out of the frozen class. No other frozen row moves with it, and PS's reading stands as the reading
of the row as it was written.

### §2 R2 — Rule `[Q111]` lives in `scripts/check-ci-shell.py` and reads every tracked shell file (P4 A R1)

The rule selects files with `git ls-files -z`, then keeps any file with a shell shebang, a `.sh`
suffix, or a `# shellcheck shell=` line. It is not keyed on `pipefail`: the libs set nothing
themselves, and the wider scope adds no findings.

### §2 R3 — The shape (P4 A R2)

The rule flags a `|` or `|&` in code context — at any `$( )` depth, and after a `\` continuation, a
trailing `|`, or a `&&` — when the next command is `grep`, `egrep` or `fgrep` with `-q`, `--quiet`,
`--silent`, `-m`, `--max-count`, `-l`, `-L` or `--files-with[out]-match[es]`.
- Option clusters are parsed. `e`, `f`, `m`, `A`, `B`, `C`, `d` and `D` take an argument, so in
  `-e -q` the `-q` is a pattern, not an option.
- Environment-assignment prefixes do not hide the command.
- The message names the file, the line, the tag `[Q111]` and the fix: `grep -q P <<<"$v"` for a
  value, or `<<<"$(cmd)"` / `< <(cmd)` for a command writer.

### §2 R4 — The docstring states what the rule does not judge, and why the shape is safe to forbid (P4 A R3)

It says three things in words:
- **Payload blindness.** The rule forbids the shape. It never judges whether an output is large or
  multi-line enough to race, because judging that is what missed five sites, three of them live
  (`Q111` `Accept` row 2).
- **Heredoc bodies are not scanned.**
- **The mechanism.** A writer is safe if nothing is written after the matched line's newline. A
  here-string of ≤ 60 000 B is a pipe on bash 5.2.15, but it is written whole before the reader
  starts.

### §2 R5 — All sixteen sites convert in the same act (P4 A R4)

The sites are `ci-lanes.sh` ×9, `e2e-sepolia.sh` ×3, `wasm-toolchain-audit.sh:77–78` and
`sepolia-preflight` ×3. P4's converted copy is lint-green (16 findings → 0) and passes `bash -n`, and
its eight literal sites give the same verdicts before and after.

### §2 R6 — Two rules are refused, in the docstring (P4 A R5)

There is no `| head` rule (35 sites, 0 true positives) and no `grep -c` rule (a different class).
The docstring writes each refusal beside its yield.

### §2 R7 — The self-test: in-memory arms judged by message, and a tree control (P4 A R6)

Every arm is a string held in memory and is judged by the tag and line it reports, so this rule's
self-test writes no file. The tree control requires 0 findings over the live tree and prints the
file count.

## 3. Fault plants

P4's prototype ran **23 cases with 0 wrong verdicts**: 13 red arms and 10 green arms.
- **Red arms**, each judged by its `[Q111]` finding:
  - A1 is `Accept` row 1's `printf '%s' "$var" | grep -q x`;
  - the same shape inside `$( )`, behind an environment prefix, and through `|&`;
  - the same shape after a quoted `<<word` heredoc (the first draft's blind spot, which swallowed
    `e2e-devnet.sh`);
  - the same shape across a trailing-`|` continuation (site 16's form);
  - the same shape with `-m`, `-l`, `-L`, the long options, and clustered flags.
- **Green arms**:
  - A1 converted to `grep -q x <<<"$var"` (the other direction of `Accept` row 1);
  - `-e -q`, `grep -c`, `< <( )`, `||`, a `case`, `[[ ]]`, a comment, a heredoc body, and quoted
    text.
- **The tree.** Red at `HEAD`, with exactly the sixteen §1.1 sites. Green with 0 after §2 R5, with
  the file count printed (31 at `fbcee1e`).
- **Behaviour (a green prediction).** `scripts/devnet/sepolia-preflight --self-test` is green; P4's
  converted copy failed 0 times in 500.

## 4. What this record does NOT decide

- How grep 3.11's drain behaves on a hosted runner. It was read from source, not run.
- Adopting `shellcheck`, or adding a `bash -n` lane. Neither was proposed nor ruled.
- Promoting any other frozen row. The class stays frozen (D125).
- Untracked shell files, which are outside the rule by construction. A shell file another lane adds
  this wave (D177's `scripts/stage0.sh`, if it lands) is inside the rule from its first commit.

## 5. Edit list — per write scope, with the lane named before this record was written

### L-TOOL — exclusive owner this wave of `scripts/ci-lanes.sh` and `scripts/wasm-toolchain-audit.sh`

- `scripts/check-ci-shell.py`: the rule, its docstring, its in-memory arms and the tree control
  (§2 R2–R4, R6, R7).
- The sixteen conversions (§2 R5):
  - `scripts/ci-lanes.sh:315, 319, 323, 571, 575, 844, 905, 909, 1380`;
  - `scripts/e2e-sepolia.sh:150, 224, 326`;
  - `scripts/wasm-toolchain-audit.sh:77–78`;
  - `scripts/devnet/sepolia-preflight:244, 269, 279`.
- Gate consequences:
  - `scripts/devnet/` is in `HEAVY_TRIGGER_PATHS` and in CONTRIBUTING's storage-touching list, so
    the close gate runs the heavy tier and the devnet E2E.
  - `wasm-toolchain-audit.sh` is in `WASM_TRIGGER_PATHS`, so the wasm32 lanes run.

### Orchestrator — `TODO.md`, `tasks/Q.md`, `docs/instrument-ledger.md`, `docs/decisions/README.md`

- `Q111`: record the promotion (§2 R1) on its row. Its Notes record the census (11 → 16) and the
  here-string mechanism. Its `Do`'s *"a herestring is a temp file"* takes a dated correction, not a
  rewrite.
- `docs/instrument-ledger.md`: two entries attributed to this record, one for the census judged by
  eye and one for the here-string mechanism.
- The index row and the register row.

## 6. As built — wave 37, lane L-TOOL (recorded in place before this record was first committed)

The lane converted the 16 sites P4 named, exactly as P4 wrote them, and landed rule `[Q111]` in
`scripts/check-ci-shell.py`. Where the build says more than the ruling did:

- **§2 R1's scope is a superset.** It is `git ls-files` plus the untracked files git does not
  ignore (D120 R2's set), so a new script is linted before its first `git add`. CI checkouts carry
  no untracked files, so both venues agree on committed content.
- **A lexer, not P4's line scanner.** P4's scanner lost quote state across physical lines. It
  counted 31 `case` alternations as pipes and missed a real pipe at `wasm-bitmatch.sh:332`: 398
  "pipes" against the lexer's 368 at `HEAD`, though both found the same 16 sites. The lexer tracks
  quoting, comments, here-document bodies, `$( )`, backticks, process substitution, `${ }`,
  arithmetic and `case` patterns. A file it cannot lex is red (`[Q111-lex]`), never passed.
- **§2 R2's reach is widened within its spirit**, each widening with its own arm:
  - long-option prefixes, resolved as grep's `getopt_long` resolves them (measured on grep 3.8);
  - options after the pattern (GNU permutation);
  - wrappers;
  - compound readers;
  - a newline or a comment after `|`.

  The self-test runs 42 in-memory arms (24 red, 15 green, 3 refusals) and 7 scope arms. Seven
  deliberate breakages of the rule each turned it red.
- **The conversions are equivalent.** A 27-row before/after harness shows 0 differences, and a
  planted non-equivalent conversion shows 1. `secret-guard`'s output is byte-identical before and
  after.
- **The live race, re-measured.** `sepolia-preflight --self-test`, interleaved A/B with N = 500 per
  arm, failed 31 times at `fbcee1e` and 0 times converted (P4: 38/500 sequential, 11/300
  interleaved).
- **`ci-shell` is no longer git-free.** The "no git" groupings in `ci-always.yml`, `ci-lanes.sh` and
  `local-gate.sh` were corrected. `docs/testing/anchor-ci-policy.md` was corrected by the DOCS lane.
- **Final state:** `check-ci-shell [Q111]: 33 shell file(s) read (6 without a .sh suffix), 444
  pipe(s) … — no pipeline feeds an early-exit grep`, exit 0. The self-test's `.github/workflows/`
  dotfile is gone afterwards.

## Closing — this record is not consent

It changes scripts and documents. It runs nothing against a public network: the preflight's
self-test is offline, and the Sepolia run remains `Q32`'s, behind its own owed acts.
