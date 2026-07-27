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

`origin` (`https://github.com/aed900/antseal.git`) is 1 commit behind
local `main`: the P8 commit `eea4eed` adds `.github/workflows/ci.yml`, and
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
   - main run: _(pending)_
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
   - main run: _(pending)_
4. **wasm-guard probe**: execute the P8 red-lane probe procedure (P8
   section above, "Pending P8 acceptance steps", step 2) and record the two
   failing-run URLs there. The probe PR will also exercise all Q1 lanes on
   a PR event — confirm the mount lanes and cross-OS lanes report there
   too.
5. **Branch protection — only now.** Required contexts = the 13 lane names.
   Exact invocation (classic branch-protection API; needs repo admin):

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
