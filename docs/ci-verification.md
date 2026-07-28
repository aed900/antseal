# CI verification status (P8 + Q1)

The CI workflow (`.github/workflows/ci.yml` — P8 skeleton, extended to the
full M0 matrix by Q1) has **never run remotely** — the push carrying it is
blocked (see "Remote blocker" below). Until the blocker clears, this
document is the acceptance evidence: every lane's exact command was executed
locally on the pinned toolchain, from the committed tree. The maintainer
runbook at the end sequences the remote steps — **branch protection comes
last, only after the first green remote run**.

## Local lane-equivalent verification — 2026-07-27

Environment:

- Host: `x86_64-unknown-linux-gnu` (Linux)
- Toolchain: **1.92.0**, selected by `rust-toolchain.toml` (verified:
  `rustup show active-toolchain` → `1.92.0-x86_64-unknown-linux-gnu
  (overridden by '/home/deb/Documents/code0/rust-toolchain.toml')`)
- `rustc 1.92.0 (ded5c06cf 2025-12-08)`, `cargo 1.92.0 (344c4567c 2025-10-21)`
- `wasm32-unknown-unknown` target installed for 1.92.0 (from the toolchain
  file's `targets` list)
- Tree: commit `eea4eed` ("P8: CI skeleton — …"), working tree clean

| Lane | Exact command | Result |
| --- | --- | --- |
| `fmt` | `cargo fmt --check` | **PASS** (exit 0) |
| `clippy` | `cargo clippy --all-targets --locked -- -D warnings` | **PASS** (exit 0) |
| `test` | `cargo test --workspace --locked` | **PASS** (exit 0; all workspace unit + doc tests green, incl. the scaffold `version_matches_scaffold` tests) |
| `wasm32-core` | `cargo build -p antseal-core --target wasm32-unknown-unknown --locked` | **PASS** (exit 0) |
| `core-dep-graph` | the `Assert antseal-core normal deps are I/O-free` script from `ci.yml`, executed verbatim | **PASS** (exit 0; `cargo tree -p antseal-core -e normal` = `antseal-core v0.0.0` only; script printed `OK: antseal-core normal dep graph is free of forbidden crates.`) |

### Workflow-file sanity check

`actionlint` is not installed on this machine; stand-ins used instead:

- **Structural parse** (PyYAML): file parses; triggers = `pull_request` +
  `push` on `main`; `permissions: contents: read`; five jobs
  (`fmt`, `clippy`, `test`, `wasm32-core`, `core-dep-graph`), each
  `checkout@v4` → rustup-from-toolchain-file → `rust-cache@v2` → lane command.
- **Script execution**: the `core-dep-graph` shell script was run verbatim
  locally (table above) — stronger evidence than lint for the only
  non-trivial script in the file.
- **Manual read**: no hardcoded toolchain version anywhere
  (`grep '1\.92' ci.yml` → no matches — the toolchain comes exclusively from
  `rust-toolchain.toml`); `--locked` present in every dependency-resolving
  lane; jobs are small named units per the documented extension-point
  contract (Q1/Q5/Q9/Q31/P13/P14).
- Run `actionlint` once as part of the post-unblock steps below (it is
  available prebuilt or via `go install`; not blocking).

**Conclusion: all five lanes green locally on the pinned toolchain,
2026-07-27.** This is lane-equivalent evidence only; the P8 acceptance items
that inherently need the remote provider (runs on PR + default branch, cache
behavior on the runners, the red-lane probe) remain pending below.

## Remote blocker — push rejected without `workflow` scope

`origin` (`https://github.com/aed900/antseal.git`, the private repo under
the maintainer account — see the D2 amendment) is a fresh empty repo: ALL
local history is unpushed. The P8 commit adds `.github/workflows/ci.yml`, and
GitHub rejects pushes that create or update workflow files from credentials
lacking the `workflow` OAuth scope:

```
refusing to allow an OAuth App to create or update workflow ... without workflow scope
```

Both available `gh` tokens lack that scope. This is user-blocked — no push
can succeed until the maintainer re-authorizes.

**Unblock procedure (maintainer, interactive):**

1. `gh auth refresh -h github.com -s workflow` — device flow; grants the
   `workflow` scope to the existing token.
2. `git push origin main`

## Pending P8 acceptance steps (execute post-unblock)

> **[Q1 note]** Superseded in part: the workflow now has **thirteen** lanes,
> not five — the green-run confirmation and all remote steps are re-sequenced
> in the "Maintainer runbook" at the end of this file. The wasm-guard probe
> procedure below (step 2) is still exactly right and is referenced from
> there.

1. **Green run on `main`**: after the push, confirm the `ci` workflow runs
   on `main` and all five lanes pass. Record the run URL here:
   - main run: <https://github.com/aed900/antseal/actions/runs/30309407509> — GREEN, all 14 contexts, 2026-07-27 (first push after the workflow-scope grant)
2. **Red-lane probe** (P8 accept: "wasm32 lane demonstrably fails when a
   non-WASM dep is added to antseal-core — verified once with a throwaway
   commit"). Procedure:
   1. `git switch -c ci-probe/wasm-guard`
   2. Add a WASM-hostile dep that is also on the forbidden-crate list to
      `crates/antseal-core/Cargo.toml`, e.g.
      `tokio = { version = "1", features = ["rt", "net"] }` (probe-only
      exception to the workspace-dependencies rule — this commit is
      throwaway and never merges).
   3. `cargo check -p antseal-core` to update `Cargo.lock`, and commit both
      files — otherwise every `--locked` lane fails on lockfile drift and
      muddies the probe signal.
   4. Push the branch and **open a draft PR** — required to trigger CI: the
      workflow runs on `pull_request` and on push to `main` only; a bare
      branch push starts nothing.
   5. Confirm BOTH probe-target lanes fail, each for its own reason:
      - `wasm32-core` — compile failure (`mio`/`socket2` do not build for
        `wasm32-unknown-unknown`);
      - `core-dep-graph` — script failure naming `tokio`, `mio`, `socket2`
        as offenders.
      `fmt`/`clippy`/`test` should stay green (sharpens the signal).
   6. Record both failing run URLs here, then close the PR (never merge) and
      delete the branch.
   - wasm32-core failing run: _(pending)_
   - core-dep-graph failing run: _(pending)_
3. Run `actionlint` against `.github/workflows/ci.yml` once and note the
   result here: _(pending)_

---

# Q1 — extension to the full M0 matrix (2026-07-27)

## What Q1 added

- **Cross-OS lane** — one matrix job, three permanent contexts
  (`cross-os-linux`, `cross-os-macos`, `cross-os-windows`; context names are
  decoupled from runner labels via `matrix.label` so pinning a runner image
  later never renames a required context). It runs the
  cross-platform-sensitive suites via **reserved test-name markers**: any
  test whose fully-qualified libtest name contains `corpus_` (G3 UTF-8
  corpus) or `vector_` (Q4 golden vectors) is run on all three OSes with
  `cargo test -p antseal-core --locked -- corpus_ vector_` (libtest
  substring filters, OR-combined). **Allowed-empty by design**: today zero
  tests match, the lane passes and logs a `::notice::` that the suite set is
  empty; G3/Q4 populate it with no lane change. Scope is `-p antseal-core`
  deliberately (canonicalization + vector verification are core by
  architecture; the 3-OS lane must not depend on the net/anchor dependency
  stacks building on Windows/macOS). Convention documented in
  CONTRIBUTING.md ("Cross-OS suite naming").
- **Mount-point jobs** — five real no-op jobs, one per later lane:
  `golden-vectors` (Q4), `wasm-bitmatch` (Q5), `tamper-matrix` (Q7),
  `fuzz-smoke` (Q9), `audit-deny` (P13/Q10). Approach chosen: **real jobs
  that exit 0**, not comment stubs — the job name *is* the future
  required-status context, so reserving it green from day one lets branch
  protection list the final context set once and never be edited when
  content lands. The misleading-green risk is mitigated by loud "MOUNT
  POINT — green here asserts NOTHING" step logs and the lane tables in
  CONTRIBUTING.md. Owning tasks replace the step body only; job id/`name:`
  are permanent.
- **`.gitattributes`** — `testdata/** -text`: the windows-latest image sets
  `core.autocrlf=true` machine-wide, which would CRLF-mangle
  text-classified fixtures at checkout and break golden byte comparisons in
  the cross-OS lane.
- **Header task-ID correction** — the P8 workflow header mapped "fuzz
  lanes" to Q1 and "golden-vector retention" to Q9; per `tasks/Q.md` the
  authoritative IDs are Q9 = fuzz, Q4 = golden-vector runner, Q6 =
  retention/freeze guard, Q5 = bit-match. The header now carries the
  corrected map.
- **CONTRIBUTING.md** — lane map (live + mount points), the reserved-marker
  naming convention, and the mount-point claiming procedure.

Existing lanes (`fmt`, `clippy`, `test`, `wasm32-core`, `core-dep-graph`)
are untouched.

## Final lane set = future required-status contexts (13)

> **[wave-2 note]** Superseded: Q2 adds a 14th context (`secret-guard`) and
> Q4/P13 turn `golden-vectors`/`audit-deny` from mount points into live
> lanes. The authoritative context list and branch-protection payload are
> now in the "Q2/Q3/Q4 + P13 (wave 2)" section at the end of this file.

```
fmt
clippy
test
wasm32-core
core-dep-graph
cross-os-linux
cross-os-macos
cross-os-windows
golden-vectors
wasm-bitmatch
tamper-matrix
fuzz-smoke
audit-deny
```

## Local verification — 2026-07-27 (all evidence **local**; remote CI has still never run)

Environment: as in the P8 record above (linux x86_64, toolchain 1.92.0 from
`rust-toolchain.toml`), Q1 tree.

| Check | Method | Result |
| --- | --- | --- |
| Workflow YAML validity | `actionlint` still not installed locally; PyYAML structural parse (`yaml.safe_load`) + job dump | **PASS** — parses; 11 jobs; the 5 P8 jobs unchanged (4 steps each); `cross-os` matrix = {linux/ubuntu-latest, macos/macos-latest, windows/windows-latest}, `fail-fast: false`, `defaults.run.shell: bash`; 5 mount jobs with 1 step each |
| Cross-OS step body, empty state (linux) | Step body executed verbatim (`bash -eo pipefail`, mirroring `shell: bash`) | **PASS** (exit 0) — `running 0 tests` / `test result: ok` (the scaffold test `version_matches_scaffold` correctly `1 filtered out`); printed `matched 0 test(s)` + the `::notice::…suite set is EMPTY…` line |
| Cross-OS filter positive control (test-of-the-test) | Planted a temporary `corpus_probe_temp` test in `antseal-core`, re-ran the step body, reverted | **PASS** — `matched 1 test(s)`, the planted test ran (`1 passed`), no EMPTY notice; revert confirmed by clean `git status` |
| Mount-point bodies ×5 | All five step bodies executed verbatim in one script | **PASS** (exit 0 each; expected MOUNT POINT logs printed) |
| `fmt` on the Q1 tree | `cargo fmt --check` | **PASS** (exit 0) |
| `clippy` on the Q1 tree | `cargo clippy --all-targets --locked -- -D warnings` | **PASS** (exit 0) |
| `test` on the Q1 tree | `cargo test --workspace --locked` | **PASS** (exit 0; 1 passed, rest empty) |
| `wasm32-core` on the Q1 tree | `cargo build -p antseal-core --target wasm32-unknown-unknown --locked` | **PASS** (exit 0) |
| `core-dep-graph` on the Q1 tree | lane script executed verbatim | **PASS** (exit 0; `OK: antseal-core normal dep graph is free of forbidden crates.`) |
| No hardcoded toolchain | `grep '1\.92' ci.yml` | **PASS** — no matches; toolchain comes only from `rust-toolchain.toml` |
| `--locked` coverage | manual read | **PASS** — every dependency-resolving invocation is `--locked`, including both cross-OS `cargo test` invocations; mount jobs resolve nothing |

**Not verifiable locally** (recorded, to be discharged by the runbook below):

- Execution on macOS and Windows runners — including
  rustup-from-toolchain-file on those images, Git Bash as `shell: bash` on
  Windows, and `Swatinem/rust-cache` behavior there.
- The rendered check-run names of the matrix job (`cross-os-linux` etc.) —
  runbook step 3 confirms them **before** they are used as required
  contexts.
- `::notice::` annotation rendering, PR triggering, and cache behavior on
  the runners.
- `actionlint` (not installed locally; unchanged from P8) — runbook step 6.

## Maintainer runbook (remote steps, in this exact order)

> Ordering is normative. **Do not apply branch protection (step 5) before
> step 3 shows all thirteen lanes green on `main`** — required contexts that
> have never reported would block every push/merge to `main`, including the
> pending backlog.

1. **Token refresh** (interactive):
   `gh auth refresh -h github.com -s workflow`
2. **Push the backlog**: `git push origin main`
3. **Confirm the first green run**: the `ci` workflow runs on `main`; all
   **13** checks green, including the three-OS matrix. Capture the exact
   check-run names and compare against the context list above:

   ```bash
   gh api "repos/aed900/antseal/commits/$(git rev-parse main)/check-runs" \
     --paginate --jq '.check_runs[].name' | sort -u
   ```

   Expect exactly the 13 names (in particular `cross-os-linux`,
   `cross-os-macos`, `cross-os-windows` — if these render differently,
   fix/reconcile BEFORE step 5). Record the run URL here:
   - main run: <https://github.com/aed900/antseal/actions/runs/30309407509> — GREEN, all 14 contexts, 2026-07-27 (first push after the workflow-scope grant)
4. **wasm-guard probe**: execute the P8 red-lane probe procedure (P8
   section above, "Pending P8 acceptance steps", step 2) and record the two
   failing-run URLs there. The probe PR will also exercise all Q1 lanes on
   a PR event — confirm the mount lanes and cross-OS lanes report there
   too.
5. **Branch protection — only now.** Required contexts = the lane names.
   **[wave-2 note]** The payload below predates Q2's `secret-guard` lane —
   use the updated 14-context payload in the wave-2 section at the end of
   this file; everything else about this step (ordering, verification,
   semantics) stands. Original invocation (classic branch-protection API;
   needs repo admin):

   ```bash
   gh api -X PUT repos/aed900/antseal/branches/main/protection --input - <<'EOF'
   {
     "required_status_checks": {
       "strict": true,
       "checks": [
         { "context": "fmt" },
         { "context": "clippy" },
         { "context": "test" },
         { "context": "wasm32-core" },
         { "context": "core-dep-graph" },
         { "context": "cross-os-linux" },
         { "context": "cross-os-macos" },
         { "context": "cross-os-windows" },
         { "context": "golden-vectors" },
         { "context": "wasm-bitmatch" },
         { "context": "tamper-matrix" },
         { "context": "fuzz-smoke" },
         { "context": "audit-deny" }
       ]
     },
     "enforce_admins": false,
     "required_pull_request_reviews": null,
     "restrictions": null
   }
   EOF
   ```

   Verify:

   ```bash
   gh api repos/aed900/antseal/branches/main/protection \
     --jq '.required_status_checks.checks[].context'
   ```

   (must print the 13 names). Semantics to be aware of:
   - With required status checks, **direct pushes to `main` are rejected**
     unless the pushed SHA already carries green required checks — the
     workflow becomes PR-first. `"enforce_admins": false` (chosen here)
     leaves the repo admin an explicit bypass for emergencies while the
     project is single-maintainer; flip it to `true` (re-run the same PUT
     with that one change) once PR-first is the steady state.
   - `"strict": true` = branches must be up to date with `main` before
     merging.
   - Mount-point contexts (`golden-vectors`, `wasm-bitmatch`,
     `tamper-matrix`, `fuzz-smoke`, `audit-deny`) are vacuously green until
     their tasks land — required-from-day-one is deliberate ("allowed-empty,
     later required", tasks/Q.md Q1) so this protection payload never needs
     editing when content arrives.
   - Record execution here: _(pending)_
6. **actionlint** (also discharges P8 pending step 3): run `actionlint`
   against `.github/workflows/ci.yml` and note the result here:
   _(pending)_

---

# Q2/Q3/Q4 + P13 — wave-2 lane changes (2026-07-27)

## What changed

- **`golden-vectors` — mount point → LIVE (Q4).** Body: checkout → rustup
  (toolchain file) → rust-cache → `cargo test -p antseal-core --locked --
  vector_` plus a match-count step that **fails on an empty suite** (the
  Q4 runner must always match — unlike the allowed-empty cross-os lane).
  The suite = the runner (`tests/vector_runner.rs`: directory-walk
  discovery over `testdata/vectors/`, envelope validation, kind dispatch,
  loud failure on malformed/unclassifiable/zero-vector states) + the C3
  vector-pinning test (`tests/hkdf_golden.rs`). Job id/name unchanged.
- **`audit-deny` — mount point → LIVE (P13).** cargo-deny **only**
  (decision [D19](decisions/D19-advisory-lane.md); no cargo-audit), exact
  tool pin `=0.19.8` (dependency-policy §5) installed via
  `cargo install cargo-deny --version 0.19.8 --locked` behind an
  `actions/cache` keyed on the version string; command:
  `cargo deny --locked check advisories bans sources` against the
  committed `deny.toml` (licenses stubbed until Q29 — hence the explicit
  check list). Job id/name unchanged (context stability beats name
  accuracy).
- **`secret-guard` — NEW job, NEW required context (Q2).** Greps the
  checkout for vault-export/wallet-key file signatures (PEM private-key
  blocks; EVM keystore JSON — both `"ciphertext"` and `"kdfparams"` in one
  file; the reserved `ANTSEAL VAULT EXPORT` magic; age/minisign secret-key
  markers), excluding `.git/`, `target/`, `.github/` (the patterns
  themselves live there) and `*.md` (prose may discuss formats). Each run
  **self-tests first**: four fakes planted in a `mktemp -d` directory must
  all be detected before the repo verdict is trusted (permanent
  test-of-the-test, nothing committed).
- **`test` lane env (Q3)**: `PROPTEST_CASES: "1024"` — CI runs 4× the
  local default; deterministic per-block seeds unaffected
  ([proptest conventions](testing/proptest-conventions.md)).
- **NEW workflow `.github/workflows/advisory-cron.yml` (P13/D19)**: weekly
  `schedule` (`17 6 * * 1`) + `workflow_dispatch`, single job
  `advisory-weekly` (never a PR context), same pinned cargo-deny + same
  command as `audit-deny` — a new RUSTSEC advisory surfaces with zero
  pushes. GitHub runs cron against the **default branch only**, so the
  schedule is inert until the push blocker clears; `workflow_dispatch`
  also only appears once the workflow file is on the default branch.

## Authoritative context set (now 14)

> **[wave-4 note]** Superseded: P14 adds a 15th context
> (`wasm32-core-tests`). The authoritative list and the updated
> branch-protection payload are in the "P14 + Q5 (wave 4)" section at the end
> of this file.

```
fmt
clippy
test
wasm32-core
core-dep-graph
cross-os-linux
cross-os-macos
cross-os-windows
golden-vectors
wasm-bitmatch
tamper-matrix
fuzz-smoke
audit-deny
secret-guard
```

Updated branch-protection payload for runbook step 5 (only change: the
`secret-guard` line):

```bash
gh api -X PUT repos/aed900/antseal/branches/main/protection --input - <<'EOF'
{
  "required_status_checks": {
    "strict": true,
    "checks": [
      { "context": "fmt" },
      { "context": "clippy" },
      { "context": "test" },
      { "context": "wasm32-core" },
      { "context": "core-dep-graph" },
      { "context": "cross-os-linux" },
      { "context": "cross-os-macos" },
      { "context": "cross-os-windows" },
      { "context": "golden-vectors" },
      { "context": "wasm-bitmatch" },
      { "context": "tamper-matrix" },
      { "context": "fuzz-smoke" },
      { "context": "audit-deny" },
      { "context": "secret-guard" }
    ]
  },
  "enforce_admins": false,
  "required_pull_request_reviews": null,
  "restrictions": null
}
EOF
```

## Local verification — 2026-07-27 (remote CI has still never run)

Environment: as the P8/Q1 records (linux x86_64, toolchain 1.92.0 from
`rust-toolchain.toml`), wave-2 tree.

| Check | Method | Result |
| --- | --- | --- |
| Workflow YAML validity ×2 | PyYAML structural parse of `ci.yml` (12 jobs) and `advisory-cron.yml` (1 job; triggers `schedule` + `workflow_dispatch`); `actionlint` still not installed (unchanged from P8; runbook step 6) | **PASS** |
| `golden-vectors` body | Step body executed verbatim: `cargo test -p antseal-core --locked -- vector_` then the `--list` count | **PASS** — 9 tests matched and passed (8 runner incl. all fail-loudly cases + the C3 committed-file test); count guard took the non-empty branch |
| `audit-deny` body | `cargo deny --version` → `cargo-deny 0.19.8` (the pin, already installed locally); `cargo deny --locked check advisories bans sources` | **PASS** — `advisories ok, bans ok, sources ok`; 3 duplicate-version warnings printed as intended (`multiple-versions = "warn"`, recorded in deny.toml/D19) |
| `secret-guard` body | Step body executed verbatim from a scratch file | **PASS** — self-test detected 4/4 planted fakes; repo scan clean |
| `secret-guard` red path (test-of-the-test at repo level) | Planted `testdata/PROBE-fake-vault.bin` containing the vault-export magic, re-ran, removed | **PASS** — exit 1, offending path printed, `::error::` emitted; clean re-run green |
| `test` lane with the Q3 env | `PROPTEST_CASES=1024 cargo test --workspace --locked` (see gate table below) | **PASS** |
| Full gate on the wave-2 tree | `cargo fmt --check` · `cargo clippy --all-targets --locked -- -D warnings` · `cargo test --workspace --locked` · `cargo build -p antseal-core --target wasm32-unknown-unknown --locked` · `cargo deny --locked check advisories bans sources` | **PASS** (all exit 0) |

**Not verifiable locally** (added to the runbook's remote expectations):

- The cron trigger itself (default-branch-only) and `workflow_dispatch`
  listing for `advisory-cron` — first weekly run lands after the push
  blocker clears; record its URL in the D19 record when it does.
- The D19 red-lane demonstration (synthetic ignore/advisory turning the
  scheduled lane red) — procedure in
  [D19](decisions/D19-advisory-lane.md), execute post-unblock alongside
  the wasm-guard probe.
- `actions/cache` behavior for the pinned cargo-deny binary on the
  runners (first run compiles ~minutes; subsequent runs hit the
  version-keyed cache).
- Check-run name of `secret-guard` (expected verbatim; confirm in runbook
  step 3 before step 5, exactly like the cross-os names).

---

# P14 — wave-4 lane changes (2026-07-28)

## What changed

- **`wasm32-core-tests` — NEW job, NEW required context (P14).** The first
  lane that *executes* rather than merely compiles for
  `wasm32-unknown-unknown`. Two steps:
  1. `cargo test -p antseal-core --lib --target wasm32-unknown-unknown
     --locked`. A Rust libtest binary for this target has **zero imports**
     and exports `main` + `memory`, so `scripts/wasm-test-runner.mjs`
     executes it under plain `WebAssembly.instantiate` in node — no
     wasm-bindgen, no wasm-pack, no browser, and therefore no pre-emption of
     decision **D18**. cargo invokes the runner automatically via the
     `runner` key added to `.cargo/config.toml`. The technique is the one
     `docs/research/C11-signature-probe.md` §5 already used for its executed
     native↔wasm byte match.
  2. `./scripts/wasm-toolchain-audit.sh` — the getrandom recipe on every
     wasm32 build graph, plus the wasm-bindgen crate↔CLI pin equality of
     `docs/dependency-policy.md` §5.
- **`.cargo/config.toml` — NEW file.** Carries the `--cfg` half of the
  getrandom recipe (`[target.wasm32-unknown-unknown] rustflags`) and the
  wasm32 test `runner`. The runner path is `../../scripts/…` because cargo
  sets a test binary's working directory to the **package** root.
- **`antseal-core` feature split.** New `test-vectors` feature = the
  WASM-safe subset of the test-support surface, activating **zero** optional
  dependencies; `test-util = ["test-vectors", "dep:proptest"]` as before.
  The self dev-dependency is target-split so wasm32 test builds get
  `test-vectors` (no proptest) and native builds get `test-util`.
  **`core-dep-graph` is unaffected by construction**: a feature that
  activates no optional dependency cannot change `cargo tree -p antseal-core
  -e normal`.
- **`wasm32-core` unchanged** (still build-only); its header comment now
  points at the new lane instead of promising the getrandom upgrade.
- **Docs**: new `docs/wasm-toolchain.md` (the normative recipe, the audit
  table of which dependency sits on which getrandom line, what the runner
  can and cannot observe, why wasm-pack/wasm-bindgen are deliberately not
  pinned yet, red-lane evidence); cross-references added to
  `docs/toolchain.md`, `docs/dependency-policy.md` §5 + Enforcement, and
  `CONTRIBUTING.md` (lane table + PR checklist).

## Authoritative context set (now 15)

> **[wave-5 note]** Superseded: Q6 adds a 16th context (`vector-freeze`).
> The authoritative list and the updated branch-protection payload are in
> the "Q6 (wave 5)" section at the end of this file.

```
fmt
clippy
test
wasm32-core
wasm32-core-tests      <-- NEW (P14)
core-dep-graph
cross-os-linux
cross-os-macos
cross-os-windows
golden-vectors
wasm-bitmatch
tamper-matrix
fuzz-smoke
audit-deny
secret-guard
```

**Branch-protection payload delta: +1 line, `wasm32-core-tests`.** Nothing
else about runbook step 5 changes. Full updated payload (this supersedes the
wave-2 one):

```bash
gh api -X PUT repos/aed900/antseal/branches/main/protection --input - <<'EOF'
{
  "required_status_checks": {
    "strict": true,
    "checks": [
      { "context": "fmt" },
      { "context": "clippy" },
      { "context": "test" },
      { "context": "wasm32-core" },
      { "context": "wasm32-core-tests" },
      { "context": "core-dep-graph" },
      { "context": "cross-os-linux" },
      { "context": "cross-os-macos" },
      { "context": "cross-os-windows" },
      { "context": "golden-vectors" },
      { "context": "wasm-bitmatch" },
      { "context": "tamper-matrix" },
      { "context": "fuzz-smoke" },
      { "context": "audit-deny" },
      { "context": "secret-guard" }
    ]
  },
  "enforce_admins": false,
  "required_pull_request_reviews": null,
  "restrictions": null
}
EOF
```

> Unlike the Q1 mount points, `wasm32-core-tests` is a **live** lane from its
> first run: it has never reported on the remote, so — per the runbook's
> normative ordering — it must be observed green on `main` (step 3) **before**
> this payload is applied (step 5).

## Local verification — 2026-07-28 (remote CI has still never run)

Environment: linux `x86_64-unknown-linux-gnu`; toolchain **1.92.0** from
`rust-toolchain.toml`; `wasm32-unknown-unknown` target installed from the
same file; **node v24.12.0**; P14 tree.

| Check | Method | Result |
| --- | --- | --- |
| `wasm32-core-tests` step 1 | `cargo test -p antseal-core --lib --target wasm32-unknown-unknown --locked` | **PASS** — runner reported `main() = 0, execution witness present (1 hit(s)); imports: 0; memory: 1769472 B`; **286** unit tests executed on wasm32 (of 311 native; the 25-test delta is enumerated in docs/wasm-toolchain.md §2) |
| `wasm32-core-tests` step 2 | `./scripts/wasm-toolchain-audit.sh` | **PASS** (exit 0) — no getrandom in any wasm32 graph; wasm-bindgen pin check `N/A` |
| `wasm32-core` (unchanged lane) | `cargo build -p antseal-core --target wasm32-unknown-unknown --locked` | **PASS** (exit 0) with the full M0 crypto set (ed25519-dalek 3.0.0, ml-dsa 0.1.1, minicbor, hkdf/sha2/hmac, chacha20poly1305, subtle, zeroize, unicode-normalization, serde/serde_json) |
| `core-dep-graph` unaffected by the feature split | lane script verbatim, plus `cargo tree -p antseal-core -e normal` compared with and without `--features test-vectors` | **PASS** — identical graphs; `OK: antseal-core normal dep graph is free of forbidden crates.` |
| `fmt` / `clippy` / `test` on the P14 tree | `cargo fmt --all --check` · `cargo clippy --all-targets --all-features --locked -- -D warnings` · `cargo test --workspace --all-features --locked` | **PASS** (all exit 0) |
| Workflow YAML validity | PyYAML structural parse of `ci.yml` | **PASS** — 13 jobs; the new `wasm32-core-tests` job follows the checkout → rustup-from-toolchain-file → rust-cache → content pattern |

### Red-lane probes (test-of-the-test), executed and reverted

| Guard | Probe | Observed |
| --- | --- | --- |
| a failing wasm32 unit test turns the lane red | temporarily broke `antseal_core::tests::version_matches_scaffold`, ran step 1, reverted | **RED** — `::error::wasm32 test runner: the test binary trapped: unreachable. …` and `error: test failed` (exit 1) |
| non-vacuity: a suite that runs zero tests must NOT pass | temporarily perturbed the witness pattern so the runner's post-`main` scan misses it, ran step 1, reverted | **RED** — `::error::… main() returned 0 but the execution witness is absent — the suite ran ZERO tests.` (exit 1) |
| the getrandom detector actually detects | `ANTSEAL_WASM_AUDIT_TARGET=x86_64-unknown-linux-gnu ./scripts/wasm-toolchain-audit.sh` (puts proptest's getrandom 0.3 **and** 0.4 into the audited graph) | **RED** (exit 1) — both lines named, each with the missing `wasm_js` feature *and* the missing `--cfg`, and the fix stanza printed |

**Not verifiable locally** (added to the runbook's remote expectations):

- Execution of `wasm32-core-tests` on the GitHub runner image — in
  particular that the preinstalled node satisfies the v18 floor asserted by
  the runner (`node --version` is logged as the lane's first step) and that
  `Swatinem/rust-cache` caches the wasm32 target artifacts.
- The rendered check-run name `wasm32-core-tests` — confirm in runbook step 3
  **before** applying the 15-context payload in step 5, exactly like the
  cross-os and `secret-guard` names.

---

# Q5 — wave-4 lane changes (2026-07-28)

## What changed

- **`wasm-bitmatch` — mount point → LIVE (Q5).** No context change: the job
  id and `name:` were reserved by Q1 and are byte-identical, so **the
  branch-protection payload is unchanged from the 15-context P14 payload
  above.** Body: checkout → rustup (toolchain file) → rust-cache →
  `node --version` → `./scripts/wasm-bitmatch.sh --self-test` →
  `./scripts/wasm-bitmatch.sh`.
- **`crates/wasm-bitmatch` — NEW workspace member, test-only.**
  `publish = false`, not named `antseal-*`, depended on by no product crate.
  A *member* rather than a standalone crate (unlike `probes/sig-probe`)
  because a bit-match between builds resolved from different lockfiles would
  prove nothing — both sides must compile the same pinned versions from the
  single root `Cargo.lock`. It depends on `antseal-core` with
  `features = ["test-vectors"]`, the tier that activates zero optional
  dependencies, so the edge cannot perturb `core-dep-graph`.
  **No new third-party dependency**: `serde`, `serde_json` and `sha2` are
  already exact-pinned for `antseal-core`.
- **No wasm-bindgen anywhere.** The wasm entry points are a raw C ABI
  (`bitmatch_len` / `bitmatch_ptr` / `bitmatch_transcript_version`) over a
  module with **zero imports**, asserted by the runner each run. Decision
  **D18** remains entirely free.
- **`VectorSummary::recomputed_digest` (antseal-core).** New field: SHA-256
  over every byte the vector executor recomputed, length-prefixed and
  domain-separated with a harness-local prefix that is deliberately outside
  the C1 domain-tag registry. This is the substance of the bit-match ("report
  bytes **plus recomputed digests**") and the medium through which **C3's
  HKDF vectors join the harness**, discharging their standing rider. The Q4
  runner now prints it too, so the `golden-vectors` and `wasm-bitmatch` logs
  are directly comparable.
- **Transcript byte format**: compact JSON under the **D29** rules, consumed
  as a *recommendation* — `TRANSCRIPT_VERSION` is `0` and moves to `1` when
  **Q14** freezes the report byte format. Nothing here freezes D29.

## Local verification — 2026-07-28 (remote CI has still never run)

Environment: linux `x86_64-unknown-linux-gnu`; toolchain **1.92.0** from
`rust-toolchain.toml`; node **v24.12.0**; Q5 tree.

| Check | Method | Result |
| --- | --- | --- |
| `wasm-bitmatch` step 2 (the lane) | `./scripts/wasm-bitmatch.sh` | **PASS** — native transcript 543 B, sha256 `7b6c5063af4c269cd69b030b715ec0a53f01aa73ac9758e1408f81eac6d166ec`; wasm32 transcript **byte-identical**, same sha256; 1 vector, 8 items, recomputed digest `949c49ebf664a65ff59b3ecfbb674b74c43f5e0fb795527a567bbe0ffb00d976` |
| wasm module self-containment | runner asserts `WebAssembly.Module.imports(module).length === 0` | **PASS** — zero imports; exports are `memory`, `bitmatch_len`, `bitmatch_ptr`, `bitmatch_transcript_version` |
| Harness native guards | `cargo test -p wasm-bitmatch --locked` | **PASS** — 7 tests: embedded table equals the committed tree (staleness), embedded bytes equal file bytes, transcript deterministic, non-vacuous, path-sorted, total over malformed input, D29 rules held |
| Full gate on the Q5 tree | `cargo fmt --all` · `cargo clippy --all-targets --all-features --locked -- -D warnings` · `cargo test --workspace --all-features --locked` · `cargo build -p antseal-core --target wasm32-unknown-unknown --locked` · `cargo test -p antseal-core --lib --target wasm32-unknown-unknown --locked` · `./scripts/wasm-toolchain-audit.sh` · `cargo deny --locked check advisories bans sources` | **PASS** (all exit 0) |
| Workflow YAML validity | PyYAML structural parse of `ci.yml` | **PASS** — 13 jobs; `wasm-bitmatch` keeps its job id and `name:` (required-status context unchanged) |

### Red-lane proof (permanent, runs on every CI run — not a one-off)

`./scripts/wasm-bitmatch.sh --self-test` rebuilds **only** the wasm32 side
with `--cfg antseal_bitmatch_inject_divergence`, which makes the wasm
transcript reverse its entry order **and** uppercase its hex digests — the
two classic platform-divergence shapes (container iteration order, i.e. Q5's
own "HashMap-ordered serialization" example, and platform-dependent
formatting). Both are injected so the self-test cannot decay into a no-op at
any vector count. Executed 2026-07-28:

```
  native transcript: 543 bytes, sha256 7b6c5063af4c269cd69b030b715ec0a53f01aa73ac9758e1408f81eac6d166ec
  wasm32 transcript: 543 bytes, sha256 0237b8335ed583ec01e50904aa93bbccc08020e6ac1817ee3492de44bc3275bf
  first difference at byte 465 (of 543 native / 543 wasm)
  native …fff.","items":8,"recomputed_digest":"949c49ebf664a65ff59b3ecfbb674b74c43f5e0fb79…
  wasm32 …fff.","items":8,"recomputed_digest":"949C49EBF664A65FF59B3ECFBB674B74C43F5E0FB79…
::error::wasm-bitmatch: wasm32 transcript differs from native — the WASM build does NOT
bit-match native verification (MVP-SPEC.md lines 167/169). …

SELF-TEST PASSED: the injected divergence turned the lane red (exit 1), as required.
```

The script inverts the exit code (a correctly-failing lane is a *passing*
self-test) and rebuilds a clean artifact before returning, so it is safe as
the lane's first step. A subsequent clean run was confirmed green.

**Not verifiable locally** (added to the runbook's remote expectations):

- Execution of the two `./scripts/*.sh` steps on the runner image (the
  scripts are POSIX `bash` with `set -euo pipefail`; `node --version` is
  logged first).
- Whether `Swatinem/rust-cache` caches the `wasm32-unknown-unknown`
  artifacts of a `cdylib` member across runs (a cold build compiles the full
  crypto stack for wasm32 — ~15 s locally).
- The rendered check-run name `wasm-bitmatch` is **unchanged** from the Q1
  mount point, so no new confirmation is needed beyond step 3's existing
  check.

---

# Q6 — wave-5 lane changes (2026-07-28)

## What changed

- **New lane `vector-freeze`** (`.github/workflows/ci.yml`). It is a **new
  required-status context**, not a mount point: the Q1 map reserved
  `golden-vectors` for Q4 and left Q6's freeze guard as "a sibling job or
  extends this one (Q6's call)". Sibling job chosen — the two assert
  different things (execute what exists vs. *exactly this set exists,
  byte-for-byte*), and a separate context makes a freeze violation
  legible in the checks list rather than buried in a runner failure.
- Driver `scripts/vector-freeze.sh` (`--self-test`, `--update`); checker
  `crates/antseal-core/tests/vector_freeze.rs`; manifest
  `testdata/vectors/v1/FROZEN.sha256`.
- Docs: `testdata/vectors/README.md` (freeze contract, directive
  vocabulary, before/after-Q14 table), `testdata/README.md` (normative
  retention policy, referenced by Q27), `CONTRIBUTING.md` (lane table).

## Authoritative context set (now 16)

```
fmt
clippy
test
wasm32-core
wasm32-core-tests
core-dep-graph
cross-os-linux
cross-os-macos
cross-os-windows
golden-vectors
vector-freeze          <-- NEW (Q6)
wasm-bitmatch
tamper-matrix
fuzz-smoke
audit-deny
secret-guard
```

**Branch-protection payload delta: +1 line, `vector-freeze`.** Nothing else
about runbook step 5 changes. Full updated payload (this supersedes the
wave-4 one):

```bash
gh api -X PUT repos/aed900/antseal/branches/main/protection --input - <<'EOF'
{
  "required_status_checks": {
    "strict": true,
    "checks": [
      { "context": "fmt" },
      { "context": "clippy" },
      { "context": "test" },
      { "context": "wasm32-core" },
      { "context": "wasm32-core-tests" },
      { "context": "core-dep-graph" },
      { "context": "cross-os-linux" },
      { "context": "cross-os-macos" },
      { "context": "cross-os-windows" },
      { "context": "golden-vectors" },
      { "context": "vector-freeze" },
      { "context": "wasm-bitmatch" },
      { "context": "tamper-matrix" },
      { "context": "fuzz-smoke" },
      { "context": "audit-deny" },
      { "context": "secret-guard" }
    ]
  },
  "enforce_admins": false,
  "required_pull_request_reviews": null,
  "restrictions": null
}
EOF
```

Runbook step 3 must confirm the rendered check-run name `vector-freeze`
**before** applying the 16-context payload in step 5, exactly like `Q5`'s
and `P14`'s new contexts.

## Local verification (2026-07-28)

| Check | Command | Result |
| --- | --- | --- |
| `vector-freeze` step 1 (self-test) | `./scripts/vector-freeze.sh --self-test` | **PASS** — a mutated frozen vector and a deleted frozen vector each turn the digest check red on a scratch copy; the untouched copy is green first, so the self-test cannot pass vacuously |
| `vector-freeze` step 2 (the lane) | `./scripts/vector-freeze.sh` | **PASS** — layer 1: `v1: 7 frozen vector(s) OK (independent sha256sum check)`; layer 2: 19 tests |
| Idempotence | `./scripts/vector-freeze.sh --update` | **PASS** — `v1: unchanged`, empty `git diff` |

**Test-of-the-test coverage** (`tests/vector_freeze.rs`), one test per
failure class, each asserting the specific message: mutated vector,
**deleted** vector, unfrozen addition, missing manifest, second version
directory checked independently, unknown directive, misfiled
`format-version`, malformed digest line, path escaping the version
directory, duplicate entry, empty manifest, `status frozen` with a pending
obligation, `pending` without an owner, and freezing a `*.py` generator.
Plus the positive controls: the scratch baseline is green, and a **legal
addition** (vector + manifest line) stays green.

**Not verifiable locally**: execution of the two `./scripts/*.sh` steps on
the runner image (POSIX `bash`, `set -euo pipefail`; `sha256sum` from the
image's coreutils, with a `shasum -a 256` fallback for non-GNU hosts).

---

# Q8 — wave-5 lane changes (2026-07-28)

## What changed

- **Mount point `tamper-matrix` claimed.** Job id and `name:` are
  **byte-identical** to the Q1 placeholder, so this is *not* a new
  required-status context and the branch-protection payload is unchanged
  from the 16-context Q6 payload above. Only the step bodies changed, per
  the CONTRIBUTING.md "CI lanes" rule.
- The lane now runs Q7's harness self-tests (`--lib -- test_util::tamper`),
  Q7's registry, C17's crypto suite, and Q8's completeness check, with
  `--nocapture` so the Q14 gate report appears in the log every run.
- Registry `testdata/tamper/MATRIX.json`; checker
  `crates/antseal-core/tests/tamper_completeness/mod.rs` (wired from
  `tests/tamper_matrix.rs`, which owns the assembled row registry).

**Only one mount point remains**: `fuzz-smoke` (Q9).

## Local verification (2026-07-28)

| Check | Command | Result |
| --- | --- | --- |
| Harness self-tests | `cargo test -p antseal-core --locked --lib -- test_util::tamper` | **PASS** — 8 tests |
| Registry + completeness | `cargo test -p antseal-core --locked --test tamper_matrix --test tamper_crypto` | **PASS** — 20 + 8 tests |

Gate report printed by the lane:

```
Q14 gate — M0 tamper matrix: NOT COMPLETE, 13 row(s) owed:
    F15: oversized-or-deep-cbor/{oversized, deep}
    G19: altered-manifest-field/covered-unit-fails-fine-root, over-broad-ggm-cover/…
    R7:  wrong-length-salt-or-seed/ggm-seed-32, non-mirror-range-violations/out-of-bounds,
         raw-mirror-canonicalization-mismatch/…, true-length-range-mismatch/…,
         partial-reveal-material-leak/{file-salt-leak, s-root-leak}
    R8:  flipped-ciphertext-byte/…, altered-manifest-field/non-covered-unit-fails-unit-commit,
         swapped-unit/…
    M2 anchor rows additionally registered for Q18: 7
tamper completeness: 37 M0 spec case(s) — 24 implemented, 13 pending;
                     9 project-added row(s); 2 recorded non-row(s)
```

That the lane is green **while 13 rows are owed** is deliberate and is the
point of the design: the gap is enumerated with named owners rather than
hidden by a weakened check. Q14 flips zero-pending into the gate condition.

**Test-of-the-test coverage** (14 cases in the checker module), one per way
the registry could lie: a case with no coverage and no pending marker; a
stale pending marker on an implemented case; a case naming a nonexistent
row; an implemented row accounted for nowhere; a `spec_quote` absent from
the spec line; a deleted family; a pending row colliding with an
implemented one; two pending rows colliding without a note; a pending
marker reserving a live row id; a pending marker without a task id; a
non-row whose `collides_with` points at nothing; a project addition with an
empty justification; an unknown field. Plus the positive control (the
committed registry passes through the identical text path).

---

## What changed — Q11 (D31): the `cross-check` lane, and the first Python in CI

`cross-check` was added to `.github/workflows/ci.yml` by F14 carrying the CBOR
surface only, and was never recorded here. Q11 completed it to all six
surfaces. Both facts land in this section.

### The lane is the first in this workflow to require Python

Every other lane is Rust plus coreutils. `cross-check` runs
`actions/setup-python@v5` at `python-version: '3.12'` and installs one
hash-pinned dev tool:

```
pip install --require-hashes -r requirements-crosscheck.txt
```

which pins `cbor2==6.1.3` by wheel/sdist SHA-256 (the file lists all
distributions for the version, so `--require-hashes` succeeds on any runner
architecture). `cbor2` is a **dev tool only**: it never enters a Rust
dependency graph, and the lane's drift-guard step refuses to let its name
appear in a Cargo manifest (`docs/dependency-policy.md` §5).

**Everything else the lane runs is Python-standard-library only.** That is not
an accident of convenience — it is what keeps the reference implementations
independent of both our Rust stack and of PyPI. The only surface with an
external Python dependency is the CBOR one, and there `cbor2` is restricted to
**decoding**; the RFC 8949 §4.2.1 canonical encoder we compare against is ours
(D31 §8).

### No path filter, deliberately

D31 §8 rejected filtering the lane to `testdata/vectors/`. No job in this
workflow has a path filter, and one here would be a foot-gun the first time a
vector directory is renamed — the lane would go green by not running. The
~30 s per PR is the correct price.

### Lane steps

| step | command |
| --- | --- |
| self-test | `./scripts/cross-check.sh --self-test --require` |
| the check | `./scripts/cross-check.sh --check --require` |
| drift guard | `cargo test -p antseal-core --all-features --locked --test cbor_crosscheck_contract` |

`--require` turns "a dev tool is missing" (exit 2) into a failure, which is
what CI wants and what a local contributor does not.

The **self-test runs first**, as in `vector-freeze` and `secret-guard`: it
stages a copy of `testdata/` in a temp directory, plants one fault per surface,
and requires each checker to go red and then green again. A checker never
observed failing is not evidence (D31 §11 item 6), and running it before the
real check means a green lane is trustworthy rather than merely quiet.

### ML-DSA-65 is not in this lane

Its vehicle is NIST ACVP — tier T0 — replayed from Rust against `ml-dsa
=0.1.1`. The fixtures are committed under `testdata/acvp/`, so the replay is
an ordinary `#[test]` in the existing **`test`** lane
(`crates/antseal-core/tests/acvp_ml_dsa.rs`): no new job, no network, no
Python. The neighbouring `ml-dsa`↔`fips204` comparison
(`tests/mldsa_fallback_equivalence.rs`) is **T2** and is D14's fallback
evidence, never the independence claim (D31 §4a).

### `core-dep-graph` is unaffected

`fips204` became a **native-only dev-dependency** of `antseal-core` for the T2
test. Verified by cargo-tree diff at landing:
`cargo tree -p antseal-core -e normal --prefix none --locked` is byte-identical
before and after (102 lines) and `fips204` does not appear in it. `Cargo.lock`
gains 12 dev-only packages; `deny.toml` sets `multiple-versions = "warn"`, so
the duplicate RustCrypto 0.10-generation pairs it introduces warn rather than
fail. Recorded in D14's 2026-07-28 addendum.

## Authoritative context set (now 17)

```
fmt
clippy
test
wasm32-core
wasm32-core-tests
core-dep-graph
cross-os-linux
cross-os-macos
cross-os-windows
golden-vectors
cross-check            <-- NEW (F14 + Q11/D31)
vector-freeze
wasm-bitmatch
tamper-matrix
fuzz-smoke
audit-deny
secret-guard
```

## Local verification (2026-07-28)

| Check | Command | Result |
| --- | --- | --- |
| `cross-check` step 1 (self-test) | `./scripts/cross-check.sh --self-test --require` | **PASS** — 7 surface proofs, each red with a planted fault and green after restore, plus the CBOR checker's own 8 planted faults and 1 control |
| `cross-check` step 2 (the lane) | `./scripts/cross-check.sh --check --require` | **PASS** — 1 reference self-test (20 published known answers, 4 optional third-party corroborations), 4 generators, 1 CBOR checker: 225 CBOR checks over 14 cases, 33 RFC 8949 Appendix A examples, 1 537 Unicode NormalizationTest lines, 37 corpus fixtures, all committed crypto/HKDF/fine-tree vectors. **Zero discrepancies.** |
| `cross-check` step 3 (drift guard) | `cargo test -p antseal-core --all-features --locked --test cbor_crosscheck_contract` | **PASS** |
| ML-DSA T0 replay (in the `test` lane) | `cargo test -p antseal-core --test acvp_ml_dsa` | **PASS** — 6 tests, 115 NIST ACVP cases, zero disagreements |
| ML-DSA T2 fallback equivalence (in the `test` lane) | `cargo test -p antseal-core --test mldsa_fallback_equivalence` | **PASS** — 2 tests |
| `core-dep-graph` unperturbed by the `fips204` dev-dependency | `cargo tree -p antseal-core -e normal --prefix none --locked`, diffed before/after | **PASS** — byte-identical, 102 lines, `fips204` absent |

The full dated freeze report, with the per-surface vehicle, version, tier and
discrepancy count that Q14 quotes, is `docs/testing/cross-check.md`.
