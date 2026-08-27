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
   **[wave-7 note] THIS STEP IS BLOCKED BY GITHUB PLAN — see the dated
   section at the end of this file. It is not pending; it is unavailable
   on a private repository on GitHub Free (403, verified on both the
   classic API and rulesets). The payload below is also stale at 13
   contexts; the current set is 19.**
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
  as a *recommendation*. Nothing here freezes D29. `TRANSCRIPT_VERSION` is
  `0` and **stays** `0` through Q14 — corrected at **R32**, which bumped
  `REPORT_VERSION` to `1` and found the advertised coupling false: the
  transcript versions its own envelope, carries no report field, aggregates
  all seven vector kinds, and is never frozen.

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

# Q9 — wave-6 lane changes (2026-07-28)

## What changed

- **The last mount point, `fuzz-smoke`, is claimed.** Job id and `name:`
  are **byte-identical** to the Q1 placeholder, so this is *not* a new
  required-status context and the branch-protection payload is unchanged
  from the 16-context Q6 payload above. Only the step bodies changed, per
  the CONTRIBUTING.md "CI lanes" rule. **No mount-point lanes remain.**
- **A new scheduled workflow**, `.github/workflows/fuzz-nightly.yml`, job
  `fuzz-long`. Like `advisory-weekly` it is **not** a PR status context and
  never becomes one, so it adds nothing to the branch-protection payload.
  GitHub runs `schedule:` triggers against the default branch only, so it is
  inert until it lands on main.
- **A second toolchain pin**, `fuzz/rust-toolchain.toml`
  (`nightly-2026-01-26`), governing `fuzz/` only. cargo-fuzz needs nightly;
  the workspace pin (= the MSRV) is untouched. Both workflows install *from
  that file* (`working-directory: fuzz`), so no toolchain version literal
  appears in either — the same rule the ci.yml header already states.
- **A new pinned dev-tool**: cargo-fuzz `=0.13.2`
  (docs/dependency-policy.md §5). The version literal appears in `ci.yml`,
  `fuzz-nightly.yml`, `scripts/fuzz.sh` and the policy doc — grep
  `0\.13\.2` to move all four at once, exactly like cargo-deny's.
  `scripts/fuzz.sh` **refuses to run** on a different version rather than
  installing one silently.
- Both lanes call `scripts/fuzz.sh`, never inline cargo invocations, so
  adding A23's M2 targets (Q17) edits `fuzz/Cargo.toml` and the script's
  `TARGETS` list and touches no workflow.
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
| Toolchain pin resolves | `rustup toolchain install nightly-2026-01-26` | **PASS** — `rustc 1.95.0-nightly (873d4682c 2026-01-25)`; `scripts/fuzz.sh` picks it up from `fuzz/` with no `+toolchain` argument |
| `fuzz-smoke` step 1 | `./scripts/fuzz.sh lint` | **PASS** (exit 0) — `cargo fmt --check` + `cargo clippy --all-targets --locked -- -D warnings` over the fuzz crate, on the **workspace stable** toolchain |
| `fuzz-smoke` step 2 | `./scripts/fuzz.sh build` | **PASS** — four instrumented binaries (`manifest_decode`, `bundle_decode`, `codec_round_trip`, `verify_bundle`) |
| `fuzz-smoke` step 3 (self-test) | `./scripts/fuzz.sh selftest` | **PASS** — all four targets: injected panic crashed the run **and** wrote a reproducer to `fuzz/artifacts/<target>/`; the script fails if either half is missing, so a green self-test cannot pass vacuously |
| `fuzz-smoke` step 4 (the lane) | `./scripts/fuzz.sh runs 100000` per target | **PASS** — 4 × 100 000 = **400 000 iterations, zero crashes**. `manifest_decode` 12 500 exec/s, `bundle_decode` 11 111, `codec_round_trip` 4 347, `verify_bundle` 574 |
| Corpus minimization | `./scripts/fuzz.sh cmin` | **PASS** — working corpus 827 files / 4.3 MB → 557 files / 3.0 MB |
| Committed corpora are the generated ones | `cargo test -p antseal-core --features test-util --test codec_fuzz` | **PASS** — 10 tests; drift, stray-file and from-disk drive checks green |

**The one finding, and it is a real one.** The first 20 000-iteration run of
`manifest_decode` crashed in seconds on the *allocation budget* the target
asserts. A 152-byte manifest whose `signatures` map head claims 59 638
entries drives a 4 704-byte single allocation — 147 elements of
`(SigAlg, Vec<u8>)` at 32 B each. The clamp is working exactly as D10 §4
specifies; what was wrong is the **claim**: `parser_caps_alloc.rs` states
the consequence as "never more than the attacker's own bytes", which holds
there only because its two inputs are under 32 bytes so the element-size
multiplier hides inside a 4 KiB slack. Scaled to `MAX_MANIFEST_BYTES`, a
16 MiB manifest can drive a ~512 MiB reservation before one map entry is
read. No verdict changes (capacity is a hint), so the lane now asserts the
*true* bound and task **F30** carries the fix plus the prose correction.

**Closed by F30 (M0 wave 7).** `clamped_capacity` is generic in the element
type and divides the remaining bytes by its width, so the reservation is
bounded in bytes by the input. Measured on the counting allocator at the two
worst sites: `signatures` 2 097 152 B → **65 536 B** for a 65 549 B input
(32.0× → 1.00×) and `files` 3 145 728 B → **19 968 B** for a 20 005 B input
(157.2× → 1.00×). No cap constant changed value and no error code moved.
`MAX_CLAMPED_ELEMENT_BYTES` is now **1** and the fuzz lane asserts the strong
claim literally; `TOTAL_FACTOR` was decoupled from it and held at 1 024,
because F30 measured the clamp and produced no evidence about payload copies.

**Not verifiable locally**: execution on the runner image; the
`actions/cache` corpus-persistence round trip (`fuzz-corpus-<run_id>` key
with a `fuzz-corpus-` restore prefix — immutable caches mean a fixed key
would freeze the corpus on day one); `actions/upload-artifact` of
`fuzz/artifacts/` on failure; and the `schedule:` trigger, which is inert
until the workflow lands on main.

## Authoritative context set (still 16)

Unchanged from the Q6 payload above. `fuzz-smoke` was already in it as a
mount point; claiming it changed the step bodies only, and `fuzz-long` is
not a PR context. **Runbook step 5 needs no re-run for this wave.**
| `cross-check` step 1 (self-test) | `./scripts/cross-check.sh --self-test --require` | **PASS** — 7 surface proofs, each red with a planted fault and green after restore, plus the CBOR checker's own 8 planted faults and 1 control |
| `cross-check` step 2 (the lane) | `./scripts/cross-check.sh --check --require` | **PASS** — 1 reference self-test (20 published known answers, 4 optional third-party corroborations), 4 generators, 1 CBOR checker: 225 CBOR checks over 14 cases, 33 RFC 8949 Appendix A examples, 1 537 Unicode NormalizationTest lines, 37 corpus fixtures, all committed crypto/HKDF/fine-tree vectors. **Zero discrepancies.** |
| `cross-check` step 3 (drift guard) | `cargo test -p antseal-core --all-features --locked --test cbor_crosscheck_contract` | **PASS** |
| ML-DSA T0 replay (in the `test` lane) | `cargo test -p antseal-core --test acvp_ml_dsa` | **PASS** — 6 tests, 115 NIST ACVP cases, zero disagreements |
| ML-DSA T2 fallback equivalence (in the `test` lane) | `cargo test -p antseal-core --test mldsa_fallback_equivalence` | **PASS** — 2 tests |
| `core-dep-graph` unperturbed by the `fips204` dev-dependency | `cargo tree -p antseal-core -e normal --prefix none --locked`, diffed before/after | **PASS** — byte-identical, 102 lines, `fips204` absent |

The full dated freeze report, with the per-surface vehicle, version, tier and
discrepancy count that Q14 quotes, is `docs/testing/cross-check.md`.

---

## Authoritative context set (18) — correction, 2026-07-28 (M0 wave 7)

**Two sections above are wrong, and they are wrong in different ways.** This
section supersedes both. The earlier ones are left in place because this
document's convention is dated append-only sections — rewriting them would
destroy the record of what was believed when the branch-protection payload
was last prepared, which is exactly the thing a maintainer needs to diff.

- *"Authoritative context set (now 17)"* lists 17 names and **omits
  `traceability`**. Q13 added that job in the same wave that added
  `cross-check`; the section recorded one of the two new contexts and missed
  the other.
- *"Authoritative context set (still 16)"* appears **after** the 17-section
  and says the set is unchanged at 16. It is describing the fuzz-smoke mount
  point being claimed (which genuinely changed no context), but it states a
  total that was already stale two sections earlier.

The set at this commit is **18 contexts from 16 jobs** — `cross-os` is a
three-way matrix (`linux`, `macos`, `windows`) and contributes three:

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
cross-check
vector-freeze
wasm-bitmatch
tamper-matrix
fuzz-smoke
audit-deny
secret-guard
traceability
```

Recompute rather than trust this list — a count kept by hand is what produced
both errors above:

```sh
# job ids (16), excluding the `on:` trigger keys
awk '/^jobs:/{j=1;next} j && /^  [a-z0-9-]+:$/{gsub(/[ :]/,"");print}' .github/workflows/ci.yml
# then expand any matrix job by its `include:` length
```

**Consequence for the branch-protection payload**, which remains an
outstanding maintainer action: it must list **18** contexts, and both
`traceability` and `cross-check` are among them. A payload cut from either
superseded section would silently leave a required lane unprotected —
`traceability` under the 17-list, and five lanes under the 16-claim.

Registered as **Q56**: generate this set from `ci.yml` rather than
maintaining it by hand. The failure here is not carelessness; it is that
three sections each had to be edited by a different wave and nothing compared
them to the workflow or to each other.

---

## A lane that has never run on the remote is not evidence (Q43, M0 wave 7)

**The general form, and the reason this section exists:**

> **A lane that has never run on the remote is not evidence, no matter how
> long it has been committed.** Neither is a guard whose own command has
> never been executed.

Wave 6 pushed 182 commits at once, so five lanes ran remotely for the first
time simultaneously. The two brand-new ones (`cross-check`, `traceability`)
passed and the *old* one failed — the opposite of the intuition. Run
30376120625 turned `tamper-matrix` red on `tamper-matrix registry target is
EMPTY — the harness or the completeness check is broken`. The harness was
fine. The **counting command** was malformed: `cargo test … --test
tamper_matrix --list` passes `--list` to *cargo*, which rejects it, where it
must reach the test binary after `--`. Q8 introduced it when it repurposed
Q1's counter; Q1's own two counters had the correct form and stayed green.

The guard behaved exactly as designed — it refused to report success from a
check that produced no evidence, which is the false-green it exists to
prevent. What failed is that **the guard's own command had never been run**,
because it existed only inside a `run:` block, and `scripts/local-gate.sh`
ran four lanes to CI's eighteen.

### What changed

Both CI-logic defects this project has had were in inline YAML shell; the
lanes that call `scripts/vector-freeze.sh`, `scripts/cross-check.sh`,
`scripts/fuzz.sh` and `scripts/check-traceability.py` were green on their
first remote run. So the logic moved to where it can be executed:

| was inline in | now |
| --- | --- |
| `core-dep-graph` | `scripts/ci-lanes.sh dep-graph` |
| `cross-os` | `scripts/ci-lanes.sh cross-os` |
| `golden-vectors` | `scripts/ci-lanes.sh golden-vectors` |
| `tamper-matrix` (both steps) | `scripts/ci-lanes.sh tamper-matrix` |
| `cross-check`'s drift guard | `scripts/ci-lanes.sh cbor-drift-guard` |
| `traceability` | `scripts/ci-lanes.sh traceability` |
| `secret-guard` (60 lines) | `scripts/ci-lanes.sh secret-guard` |
| `audit-deny`, in **two** workflows | `scripts/ci-lanes.sh audit-deny` |
| `wasm32-core-tests` (both steps) | `scripts/wasm-tests.sh` |
| `fuzz-nightly`'s corpus-size loop | `scripts/fuzz.sh corpus-report` |

**All three workflows, not just `ci.yml`.** Q43's Accept names `ci.yml`, but
`advisory-cron.yml` carried a second copy of the `cargo deny` invocation and
`fuzz-nightly.yml` a corpus loop; scoping the check to one file would have
closed the instance again.

### The check that keeps it closed

`scripts/check-ci-shell.py` enumerates every `run:` block in every workflow
and requires each to be either a committed-script call or one of nine
allowlisted lines — each allowlist entry recording the **local lane that
exercises it** (e.g. `cargo fmt --check` → `scripts/local-gate.sh`'s `fmt`).
A stale allowlist entry that no block uses is also a failure: an exemption
nobody needs is how an allowlist stops meaning anything. A script call with
logic wrapped around it fails too — that is still inline logic.

At this commit: **54 `run:` blocks across 3 workflows**, all classified.

### Test-of-the-test

| Guard | Probe | Observed |
| --- | --- | --- |
| the CI-shell check | `scripts/check-ci-shell.py --self-test` — three planted faults: a new inline `run:` block with logic, logic wrapped around a script call, a call to a script that does not exist | RED on each, GREEN on the unmodified control |
| **the Q8 defect itself** | `scripts/ci-lanes.sh --self-test` — puts `--list` back before `--` in a copy of the lane script and runs the lane | control counts **25** tests; with the fault the lane exits non-zero on `registry target is EMPTY`; restored, green again. The defect now turns a **local** lane red |
| a failing wasm32 test is named | `scripts/wasm-tests.sh --self-test` (R41) | see `docs/wasm-toolchain.md` §8 |

Both self-tests run in `scripts/local-gate.sh` (`ci-shell`, `ci-lanes`) and in
CI — `ci-shell` inside the `traceability` job and the Q8 reproduction inside
`tamper-matrix`, deliberately as steps of existing jobs so the **18-context
set above is unchanged**.

### One thing this tightened rather than relaxed

`secret-guard`'s scan excluded all of `.github/` because the guard lived in
the workflow and its self-test plants literal key material. Moving it to
`scripts/` naively would have meant excluding all of `scripts/` — a strictly
larger hole, in a directory far more likely to receive a stray key. The
exclusion is now the single file that carries the literals
(`--exclude='ci-lanes.sh'`), and `.github/` is scanned again.

### Still not verifiable locally

Execution on the runner image, `actions/cache` round trips,
`actions/upload-artifact`, the `schedule:` trigger, and the matrix expansion
on the macOS and Windows runners. Those remain first-run-on-the-remote
risks — which is precisely why the shell inside them no longer is.

---

## Branch protection is BLOCKED BY PLAN — verified 2026-07-28 (wave 7)

**Runbook step 5 has never been executable, and the runbook did not say so.**
It has sat in the maintainer-actions list across several waves as though it
were merely pending. It is not pending; it is unavailable on this repository
as currently hosted. Verified directly, both mechanisms:

```
$ gh api repos/aed900/antseal/branches/main/protection
{"message":"Upgrade to GitHub Pro or make this repository public to enable
 this feature.", "status":"403"}

$ gh api repos/aed900/antseal/rulesets
  … same 403.
```

`aed900/antseal` is a **private repository on GitHub Free**, and GitHub gates
both classic protected branches and the newer rulesets behind a paid plan for
private repositories. Three options, and the second has a consequence far
larger than the CI question that raises it:

1. **GitHub Pro** (~$4/month) — unlocks both. Smallest change.
2. **Make the repository public** — free, and it publishes the entire history
   in one step. **This triggers Q65** (publish-scope decision + pre-public
   scrub), which must be executed *before* the visibility change, never after.
   Do not take this option for a CI reason without taking Q65 first.
3. **Do without**, which is the current state and costs less than it sounds —
   see below.

### Why option 3 is defensible here

Branch protection buys *"a red lane blocks the merge"*. Nearly every guard
this project relies on is **in-repo** rather than in GitHub, and fires with no
network and no platform feature:

- `testdata/vectors/v1/FROZEN.sha256` and `docs/format/FROZEN.sha256` refuse a
  changed digest — that is what makes the format freeze real
- `testdata/error-codes/v1/CODES.txt` (Q52) catches a renamed error code
- `scripts/ci-lanes.sh` + `scripts/check-ci-shell.py` (Q43) run the CI shell
  **locally, before a push** — which is how the malformed `tamper-matrix`
  counter was caught
- `scripts/local-gate.sh` gates fmt/clippy/tests/`wasm32-build`/`wasm32-tests`
  (diff-triggered — Q125)/cross-check/format-freeze before anything leaves the
  machine. Its header enumerates the CI contexts it does **not** reproduce;
  that list is the honest answer to "what can still break after a green gate"

With a single maintainer pushing directly, protection would add little: it
cannot block a push it never sees, and the payload's own
`"enforce_admins": false` leaves the admin a bypass regardless. What it *would*
genuinely add — and what is currently unprotected — is **force-push and branch
deletion protection**, which matters more now that a published freeze tag
exists.

### The payload, generated rather than hand-maintained

**19 contexts from 17 jobs** at this commit (`cross-os` is a three-way
matrix). The payload in runbook step 5 lists **13** and the wave-2 note
promises 14; both are stale. Regenerate rather than copy — that is Q56:

```sh
awk '/^jobs:/{j=1;next} j && /^  [a-z0-9-]+:$/{gsub(/[ :]/,"");print}' \
  .github/workflows/ci.yml     # 17 job ids; expand any matrix job's labels
```

```bash
gh api -X PUT repos/aed900/antseal/branches/main/protection --input - <<'EOF'
{ "required_status_checks": { "strict": true, "checks": [
    {"context":"fmt"},{"context":"clippy"},{"context":"test"},
    {"context":"wasm32-core"},{"context":"wasm32-core-tests"},
    {"context":"core-dep-graph"},
    {"context":"cross-os-linux"},{"context":"cross-os-macos"},
    {"context":"cross-os-windows"},
    {"context":"golden-vectors"},{"context":"cross-check"},
    {"context":"vector-freeze"},{"context":"format-freeze"},
    {"context":"wasm-bitmatch"},{"context":"tamper-matrix"},
    {"context":"fuzz-smoke"},{"context":"audit-deny"},
    {"context":"secret-guard"},{"context":"traceability"} ] },
  "enforce_admins": false, "required_pull_request_reviews": null,
  "restrictions": null }
EOF
```

Precondition unchanged from step 5: every listed context must have passed on
`main` at least once first. A required context that has never run blocks the
next push, including the maintainer's own.

## The devnet E2E is deliberately NOT in that payload (Q15, D52 — 2026-08-02)

`devnet-e2e-cron` / job `devnet-e2e-scheduled`
(`.github/workflows/devnet-e2e-cron.yml`) is a **scheduled, non-required**
lane on the `fuzz-nightly` / `advisory-cron` pattern: `schedule:` +
`workflow_dispatch`, no `pull_request` trigger, therefore **not a status
context**. The generated context list above is unchanged at **19 from 17
jobs** — the regeneration command reads `ci.yml` only, and this workflow is
a separate file for exactly that reason.

That is a decision, not an oversight. [D52](decisions/D52-devnet-e2e-venue.md)
records why a per-PR devnet job was rejected — starting from the section
directly above: on this plan a 20th *required* context could not be required
any more than the existing 19 can, so the CI job's only claimed advantage over
a required local gate does not exist here. The gate itself is
`scripts/e2e-devnet.sh`, mandatory before merging storage-touching changes
(CONTRIBUTING, "Devnet E2E gate"), and the scheduled lane runs the same script
bytes so the remote half of Q43's evidence rule is still discharged.

**Promote-to-required trigger — the one a future maintainer needs from this
page.** Two preconditions, both required:

1. **The plan allows it**: GitHub Pro (option 1 above), or the repository goes
   public — which triggers **Q65 first**, never after.
2. **The evidence exists**: **≥ 20 clean scheduled runs** with **warm runtime
   ≤ 15 min**, per D52 Adversarial-test 4. The runtime is not a guess to be
   re-litigated: every run of `scripts/e2e-devnet.sh` prints
   `e2e-devnet: <verdict> … secs=<n> …` and writes it to
   `target/e2e-devnet/<run>/evidence.txt`, which the workflow uploads as the
   `devnet-e2e-evidence` artifact.

   **[MEASURED 2026-08-27, wave 31 — precondition 2 is unreachable three ways,
   and none of the three was recorded here. `Q247`'s `Accept` rows 1-2.]**

   a. **The store holds ONE artifact, not twelve.** `gh api
      repos/aed900/antseal/actions/artifacts --paginate`, filtered to
      `devnet-e2e-evidence`, returns exactly `9132238802` (2026-08-12,
      `expired=false`) — and that one is the **red** 5-node run's, so the
      count of *clean* runs in the store is **0**. `Q247`'s row states twelve;
      the row is wrong by eleven and is corrected at source in the same act.

   b. **Retention makes 20 coexisting runs impossible.** The lane is weekly
      and `retention-days: 30` is landed
      (`.github/workflows/devnet-e2e-cron.yml`), so by D145's own table
      R=30 keeps **5** coexisting artifacts, not 13. Twenty weekly runs need
      **≥ 133 days**; the window is **35**. The trigger as written can never
      be satisfied by a weekly cadence at this retention — it needs a longer
      retention, a faster cadence, or a committed running tally that outlives
      the artifacts. That is a decision, and it is not taken here.

   c. **`secs=` is never warm, and the number is now attached.** The clock
      starts at `scripts/e2e-devnet.sh:329`, *before* the `cargo test` at
      `:365`, and the workflow has no separate build step — so every hosted
      `secs=` includes a cold build. Measured locally: **787 s build + ~6 s
      boot + 466-485 s suites ≈ 21 min against a 15 min trigger**, with the
      build alone **87.4 %** of the budget. D145 §2 R4 reached *"no run of it
      is ever warm"* and attached no figure; the figure is above, and it says
      the gap is not marginal. **Nothing here is a hosted measurement** — every
      run since 2026-08-16 has been refused — so treat these as a local
      projection of the hosted shape, not as the hosted number.

   Consequence for a future maintainer: **do not read precondition 2 as
   waiting on time.** It is waiting on a ruling about cadence, retention and
   what "warm" is measured from. Until that ruling exists, the count cannot
   advance past what the store can hold.

Then, and only then, add `{"context":"devnet-e2e-scheduled"}` to the payload
above — after moving the job onto a `pull_request` trigger, since a lane that
only ever runs on a schedule can never satisfy a per-PR required check (the
"has passed on `main` at least once" precondition is necessary but not
sufficient here). Two related knobs, recorded so the promotion is one
reviewed change rather than an archaeology exercise: the lane deliberately
carries **no `Swatinem/rust-cache`** (D52 E3 — the devnet target dir would
evict the 19 required lanes' caches inside the 10 GiB per-repo cap), and it
runs **weekly** rather than daily until the first `workflow_dispatch` runs
measure the cold-build cost. If the measurement says the cost does not fit
the minutes budget, the correct action is to **delete this lane and record
the measurement** (D52's D→C degradation), not to quietly let it run red.

**Triage while it is non-required** (D52 residual risk 2): a red scheduled run
gets a tracking note in the next wave's bookkeeping; **two consecutive reds
block storage-wave starts** until diagnosed.

---

# Q81/D61 — the scheduled fuzz lane was read for the first time (2026-08-02)

## The five runs nobody had ever looked at

`fuzz-nightly.yml` landed on the default branch at commit **5302829**
(2026-07-28) and has been firing `cron: "41 3 * * *"` ever since. D61
Correction 1 found that **nothing anywhere recorded that a single one of
those runs had happened, passed, or cost anything** — the general form of
the gap Q43 and Q66 were written to close, one level out: not a lane that
never ran, but a lane that ran and was never read.

D61 Decision 1 says to measure before changing anything. Executed
**2026-08-02**, read-only:

```
gh api /repos/aed900/antseal/actions/workflows/fuzz-nightly.yml/runs \
  --jq '.workflow_runs[] | [.created_at, .conclusion, .run_started_at, .updated_at] | @tsv'
```

| started (UTC) | conclusion | wall clock |
| --- | --- | --- |
| 2026-07-29T06:16:44Z | success | 62 m 50 s |
| 2026-07-30T06:09:41Z | success | 61 m 40 s |
| 2026-07-31T06:32:13Z | success | 61 m 39 s |
| 2026-08-01T06:15:51Z | success | 61 m 34 s |
| 2026-08-02T06:19:15Z | success | 61 m 40 s |

**Exactly five runs, all green.** D61 §1's precondition — *"if any of the
five was red, that is a finding to triage under §7 before the cadence change
lands"* — is therefore discharged, and the count confirms D61 Correction 1's
derived figure of five rather than the ≥ 2 the git evidence alone bounded.

Three things the numbers settle that the derivation could not.

1. **Per-run overhead is ~1.9 minutes, not 15.** Wall clock is 61.6–62.8 min
   against 60 min of `-max_total_time`, because both caches hit
   (`Swatinem/rust-cache` on `fuzz/`, and the pinned `cargo-fuzz` binary).
   D61's `PER_RUN_OVERHEAD_MINUTES = 15` is ~8× that and is **kept
   deliberately** — over-estimating is the safe direction for a guard whose
   failure mode is "every workflow in the repository stops", and lowering it
   loosens the guard, which is a decision rather than an implementer's call.
   D61's revisit trigger anticipated the *opposite* finding (an overhead far
   **above** 15); it did not occur, so the trigger does not fire.
2. **The real bill exceeds D61's lower bound.** 61.87 min × 30.33 runs/month
   = **~1 877 min/month, 94 %** of the 2 000-minute GitHub Free allowance,
   against the ≥ 1 824 / 91 % D61 derived from the committed literals alone.
   The measurement tightens the ruling in the direction D61 predicted it
   could only tighten.
3. **GitHub started these runs at ~06:15Z against an 03:41Z cron** — a
   2.5-hour slip, consistently. Scheduled instants are best-effort under
   load. It changes no arithmetic (the count per month is what bills), and
   it is a second reason not to sit on the 7-day cache-eviction boundary.

## The cadence change, and the guard that keeps it

Landed in one commit with the guard, because the guard is red at the
configuration it replaces (D61 §5's landing-order note): twice weekly
(`41 3 * * 1,4`) at 600 s/target ⇒ **476.85 min/month, 23 %** of the
allowance, against a named ceiling of 700 (35 %).

`scripts/ci-lanes.sh fuzz-budget` computes that from four committed literals
— `TARGETS` in `scripts/fuzz.sh`, the `seconds` default and the scheduled
`|| '600'` fallback in `fuzz-nightly.yml`, and the `cron:` day-of-week field
— and refuses the configuration if it exceeds the ceiling **or** if the cron
leaves more than 5 days between runs (the corpus cache is evicted after 7
days without access, and accumulation is this lane's only reason to exist).

It rides as a **step of the existing `traceability` job**, not as a job of
its own: it needs no network, and that job's cargo-freeness — which is what
makes riding there free — is asserted on every run since D124/Q182 rather
than claimed here. So the **required-context set stays at 19** and Q56's
generated context list is untouched.

**Billing was not read.** `gh api /users/aed900/settings/billing/actions`
needs the `user` OAuth scope, which this token does not carry; obtaining it
(`gh auth refresh`) is an account-bearing action. So the allowance-share
figures above remain derived from the per-run measurement, not read from
GitHub's own counter. Recorded as the one half of D61 §1 that is still owed.

**Failure policy** (D61 §7) is now asserted rather than inferred:
`scripts/fuzz.sh classify-failure` runs on `failure()` and distinguishes a
**crash** (a reproducer was written — release-blocking on the *first*
occurrence, no grace) from an **infrastructure red** (no reproducer —
D52's tracking-note convention, two consecutive block wave starts). It is a
committed script rather than inline YAML because Q43's `check-ci-shell.py`
refuses a `run:` block that carries logic, and is right to.

---

# Q16 — the no-real-anchor-network policy (2026-08-06)

## The context set does not change: still 19

**Recounted from `.github/workflows/ci.yml`, not read from this file.** 17
jobs; `cross-os` is a 3-way matrix (`linux`/`macos`/`windows`), every other
job is one context: **19**. Q16 adds **no job**. The branch-protection
payload and Q56's generated context list are untouched.

(Recounting rather than trusting is the standing instruction for this
document, which has declared the context set repeatedly and has not always
agreed with itself. The list, for the next recount to compare against:
`fmt`, `clippy`, `test`, `wasm32-core`, `wasm32-core-tests`, `core-dep-graph`,
`cross-os-linux`, `cross-os-macos`, `cross-os-windows`, `golden-vectors`,
`cross-check`, `vector-freeze`, `format-freeze`, `wasm-bitmatch`,
`tamper-matrix`, `fuzz-smoke`, `audit-deny`, `secret-guard`, `traceability`.)

## What CI ran for the anchor surface before, and what changed

**Before: all of it, already.** `test` runs `cargo test --workspace --locked`
and D90 deliberately left `antseal-anchor` **ungated** — no feature hides its
network half — precisely so that A3/A10/A13/A16/A17's local-stub tests are
compiled by a default-features-only lane. The 189 anchor unit tests, the
`antseal-core` anchor suites and `antseal-cli`'s anchor integration targets
were all running. Q16's row does not need a new lane and did not get one; a
job would have cost a 20th required context for coverage that existed.

**What was missing was the policy half.** "No test contacts a real endpoint"
was prose in five files, each arguing it held *by construction* because the
stubs bind `127.0.0.1:0`. That argument is about the stubs, not the tests,
and the tree carries the counterexample: `ots/engine.rs`'s
`upgrade_pending_with` seam records a suite that drove the production upgrade
path with the committed `.ots` artifact — whose pending URIs are the real
calendar hostnames — and **contacted live calendars on every run while every
assertion passed**.

**After:** the policy is enforced at runtime by
`crates/antseal-anchor/src/http/offline.rs` inside `HttpClient::attempt`, and
its out-of-Rust half by `scripts/ci-lanes.sh anchor-net-policy`, which rides
as a **step of the existing `traceability` job** — Python only, no network,
and cargo-free by that job's asserted property (D124/Q182) rather than by
this sentence — exactly as `ci-shell` and `fuzz-budget` do.

## Minute cost

**Effectively zero, and no new job.** The added step is one `python3`
invocation over committed text: it reads 4 workflow files, 6 manifests,
`scripts/local-gate.sh` and antseal-anchor's sources, with six in-memory
planted faults first. Measured locally on this 2-core host over three runs:
**0.13 s / 0.10 s / 0.10 s** wall, self-test included.
`traceability` needs no toolchain and no cache, so the step adds no setup — a
property this document used to state and D124/Q182 now asserts on every run of
that job. The `test` lane gains 5 unit tests and one integration target whose
parent spawns three short child processes; on a 2-core host
`cargo test -p antseal-anchor` went from **189 tests / 9.69 s** before to
**194 + 1 tests / 9.90–10.67 s** across four runs — inside this host's own
run-to-run spread, so the honest statement is "no measurable cost", not a
delta.

Against the standing budget picture (Q78/Q81 — 19 required contexts,
`cross-os-macos` billing 10×, the scheduled fuzz lane at 23 % of the
allowance after its cadence change), this is not a material addition and
required no re-derivation of the fuzz budget.

## Red-lane evidence (test-of-the-test)

Every check below was executed in its **red** direction. The two faults that
would otherwise have made a real request were run inside `unshare -rn`, so
the planted-unguarded run could not reach a real endpoint even in principle —
which is also what makes its failure message the proof.

| planted fault | result | what it said |
| --- | --- | --- |
| gate's `cfg(test)` arm returns `None` | **RED** | `https://freetsa.org/tsr produced Transport { … "failed to lookup address information" } instead of RealNetworkDenied — this call reached the network stack` |
| loopback carve-out deleted (gate denies everything) | **RED** | `a loopback IP literal is exempt and must still be dialled: RealNetworkDenied { endpoint: "http://127.0.0.1:40035", … }` — plus ~60 stub-driven tests across `esplora`, `arbitrum::confirm`, `http`, `tsa` |
| gate's environment arm returns `None` | **RED** | `assertion left == right failed: the gate did NOT fire in the armed arm` |
| R1 workflow arming deleted from `ci.yml` | **RED** | `ci.yml does not set ANTSEAL_NO_REAL_ANCHOR_NETWORK: "1" in its workflow-level env: block` |
| R1 `local-gate.sh` export deleted | **RED** | `the local gate is the venue a contributor actually runs; unarmed, it is the one place an integration test can still reach a real TSA` |
| R2 second client, `[dev-dependencies.reqwest]` | **RED** | `a second client bypasses the gate entirely and no other lane would see it` |
| R2 renamed client, `{ package = "isahc" }` | **RED** | as above, via the rename spelling |
| R2 `ureq` declared outside `antseal-anchor` | **RED** | `only antseal-anchor (and the root [workspace.dependencies] pin) may` |
| R3 new URL constant the gate test never names | **RED** | `BACKUP_TSA_URLS … is outside the walk that proves every default endpoint is refused` |

**Two defects were found by these instruments in the instruments
themselves**, which is the reason for running them:

1. R3's anti-vacuity guard fired on its first execution: the detector found
   **zero** URL constants in a tree that has six, because a line-based
   comment stripper split `"https://…"` on its own `//`. Had the guard not
   been there, R3 would have been permanently, silently vacuous.
2. R2's self-test caught R2 checking only `crate = "…"`, so
   `[dev-dependencies.reqwest]` — a perfectly ordinary Cargo spelling —
   walked straight through. All three spellings are now checked.

## What is NOT proven here

> **Superseded 2026-08-06 — it has now run.** The 180-commit push put this
> step on the remote for the first time. It has **passed on every run since**
> (runs 31086210534, 31095668522 and the head run at `9145dc6`), inside the
> `traceability` job, and the context count stayed at 19. What follows is
> kept as the record of what was owed before that, because the reasoning is
> what made the gap visible.

The step had **never run on the remote**. It is a script call exercised
locally by `scripts/local-gate.sh` (`anchor-net` lane), which is what Q43's
rule asks for, but this document's own standing warning applied: a lane that
has never executed remotely is not evidence, however long it has been
committed.

`ANTSEAL_NO_REAL_ANCHOR_NETWORK` being *honoured* by a GitHub runner was not
in doubt (it is an ordinary environment variable), but the arming reaching
every job through workflow-level `env:` inheritance had been read, not
observed.

## The push of 2026-08-06, and the four defects it found (wave 5)

`518f342..a053272`, 180 commits, then four fix/bookkeeping commits to
`9145dc6`. Every lane in the repository ran remotely for the first time
since 2026-08-01, and this document's standing warning paid out at scale:
**four defects surfaced that no local run had shown.**

1. **`core-dep-graph` — a guard idiom that inverts its own verdict.** Under
   `set -o pipefail`, `printf '%s\n' "$var" | grep -q PATTERN` reports *no
   match exactly when the match is found early*: `grep -q` exits on first hit
   and closes the pipe, bash's `printf` builtin takes `EPIPE` mid-flush, and
   `pipefail` promotes that to the pipeline's status. The P20 self-test
   asserts that `ant-node` **is** in the devnet-featured tree — it is, twice,
   near the top, which is exactly why grep exits early enough to lose the
   race on the runner and not on a 2-core dev host. **The self-test failed
   because it succeeded.** Demonstrated deterministically with an 8.4 MB
   payload whose match is on line 1: the old form reports NO MATCH, the
   herestring form reports MATCH. 32 sites converted (→ **Q111** adds the
   lint; every surviving `printf | grep -q` is safe only because its payload
   is a small literal, which an edit can silently change).
2. **`fuzz-smoke` — a real finding, on the target's first remote run.** In
   3140 execs, `anchor_ots` found that it and `parse_ots` assert two
   different allocation rules: D58's absolute `MAX_OTS_VALUE_BYTES = 32_768`
   against D10 §4's input-relative clamp. A 248-byte input peaked at 5120 B —
   legal under one rule, illegal under the other (→ **A100**). Left red on
   purpose: D84 holds that anchor-artifact internal limits are verifier
   policy and **not** D10 format surface, which points at the target, but
   tightening the executor is a live option that has to be argued.
3. **`heavy-features` — U22 shipped code that does not compile under
   `--features ant-backend`.** A shadowed `config` binding retyped an
   argument. Nothing could catch it: required CI passes no `--features`, and
   `HEAVY_TRIGGER_PATHS` names neither `commands.rs` nor `seal_run.rs`, so
   the tier was classified `n/a` for the whole wave (→ **Q112**). The run
   that recorded Q112 then reported `n/a` on a `commands.rs` edit, which is
   the defect demonstrating itself.
4. **Pre-existing, surfaced by the same run.** `json-envelopes.txt` pins text
   that differs **by `cfg` on purpose** and commits only one variant, so the
   heavy tier can never be green (→ **Q113**; verified present at the wave-4
   head).

**Scheduled-lane read (Q79), and the reason it matters.** `fuzz-nightly` had
run **daily** — 2026-08-01 through 2026-08-06, all success, wall clock
61.6–61.8 min each — because Q81's re-cadence to `41 3 * * 1,4` was committed
on 2026-08-02 and **not pushed**. This workflow says it itself: GitHub runs
`schedule:` against the **default branch only**, so a committed cron is inert
until it lands on `main`. The push activated it. **A CI configuration change
is not in effect until it is pushed** — the config-side twin of this
document's rule about lanes.

**Verdict at the head (`9145dc6`): 18 of 19 contexts green.** `fuzz-smoke` is
red on A100 and the heavy tier on Q113 — both recorded, neither blessed away.
Judge by per-job conclusions, never by annotation glyphs: the planted-fault
self-tests emit failure-styled annotations from **succeeding** steps.

## The push of 2026-08-06 (waves 6–7), and a verdict that arrived late

`99556ab..d82f72e`, fast-forward, waves 6 and 7 both aboard.

**For several hours this head had no remote verdict at all, and two runs
existed that must not be mistaken for one.** The distinction is the whole
point of this document, so it is recorded rather than tidied away:

- **No run was created for `d82f72e` at push time.** GitHub Actions was in a
  confirmed `major_outage` (githubstatus, active critical incident:
  *"Capacity remains constrained and jobs may still be delayed or fail"*).
  A push that triggers nothing leaves the head **unverified** — it does not
  leave it green.
- **Run 31117310646 at `99556ab` is not a code verdict.** Its six failures
  and seven cancellations all log `Failed to resolve action download info.
  Error: Service Unavailable`: the runners never compiled anything. Reading
  that run by its conclusions would have reported this milestone as breaking
  six lanes it never reached. **An infrastructure failure and a test failure
  are the same red glyph** — the log, not the glyph, says which one it is.

**Run 31127730409 at `d82f72e` (event `push`, queued 20:36Z) is the real
verdict.** The runners compiled and executed, so it may be judged by its
conclusions. **18 of 19 jobs green; `fuzz-smoke` is the single red.**

Green includes every lane wave 7 touched — `tamper-matrix`, `wasm32-core`,
`wasm32-core-tests`, `wasm-bitmatch`, `golden-vectors`, `vector-freeze`,
`format-freeze`, `traceability`, `cross-check`,
`cross-os-{linux,macos,windows}`, `test`, `clippy`, `fmt`, `audit-deny`,
`secret-guard`, `core-dep-graph`. The M2 tamper matrix and the wasm32 lanes
are therefore now **remotely executed**, not merely locally green, which is
the standard this document holds them to.

**The one red is A100, and it reproduced rather than regressed.** The
`anchor_ots` target panicked in `assert_within_budget`: *"peak single
allocation 5120 B for a 744 B input (cap 4840 B = len x 1 + 4096)"*. The
first witness (run 31086210534) was a **248-byte** input found in 3140 execs;
this one is a **744-byte** input found at **exec #476** under a different
libFuzzer seed. Different length, different seed, different exec count —
**identical 5120 B peak.** The relative cap moved (4344 B → 4840 B) and the
allocation did not, which is evidence the peak is a fixed step rather than a
function of input length; where that step is reached the guard fails an input
**iff `len < 1024`**. That is a fact for the ruling to use, not a licence to
patch: A100 stays open and red on purpose.

**What this run does not settle, and a correction to how that was phrased.**
Only the `ci` workflow ran for this sha. It is tempting to record that as
"the heavy tier did not run this time" — but that understates it. The heavy
tier is **not a remote job at all**: `heavy-features` exists only in
`scripts/local-gate.sh`, which shells out to `scripts/gate-features.sh
--heavy`, and **no workflow in `.github/workflows/` invokes either script**.
`ci.yml` defines 17 jobs (19 contexts, `cross-os` being a 3-way matrix) and
none of them is it; consistent with wave 5's finding that required CI passes
no `--features`.

So **Q113 cannot be confirmed or cleared by any remote run at any head**, and
no future green `ci` should be read as having touched it. Its standing is
exactly what it was: a finding whose only evidence is local, on a tier this
document's own rule says is therefore not remotely verified. Q113 is not the
weaker case here — **the heavy tier is the blind spot**, and the gap is in
the workflow set, not in the run.

---

## The CBOR checker's self-test counts — correction, 2026-08-10 (M2 wave 13)

**A row in "Local verification (2026-07-28)" above is now wrong about the
present, and is left standing anyway.** Its `cross-check` step 1 entry records
*"7 surface proofs, each red with a planted fault and green after restore,
plus the CBOR checker's own 8 planted faults and 1 control"*. That was
accurate for the run it dates. This section supersedes it in the same form,
and for the same reason, as the context-set correction above: this document's
convention is dated append-only sections, and rewriting a dated row would
destroy the record of what was actually observed — which is the thing a
maintainer diffing two runs is looking for.

**Q130** (wave 12) made `./scripts/cross-check.sh --self-test` sweep every
in-scope document rather than the first, and made every number in the CBOR
checker's summary **computed from the run**. The shape it reports is: per
in-scope document, **7 vector mutations + 1 control**, plus **one wrong RFC
8949 expectation per run**. Those totals scale with the in-scope set, so this
note states the structure and lets the run state the numbers — restating them
is what produced **Q146**, four prose sites carrying a count the tool had
stopped printing. The two other checkers named in that row were re-verified
and are unchanged.

**No verdict moved.** `--self-test` was rc 0 then and is rc 0 now, and CI
still runs it as its own step with `--require`. What moved is local: **Q141**
(wave 13) added that step to `scripts/local-gate.sh`, which had run `--check`
only and therefore could not observe any of Q130's new instruments — CI could,
because it runs the two as separate steps.

---

## The push of 2026-08-10 (waves 12–13), and a run that never started

`5fbc48d..1c702d4`, two commits — `d23dccc` (wave 12) and `1c702d4` (wave 13).
The push succeeded and `origin/main` carries both. **CI did not fail; CI never
ran**, and the distinction is the whole content of this section.

Run **31407751482** on `1c702d4` reports `0 of 19`. Read naively that is the
worst result this project has ever recorded, immediately after four
consecutive all-green runs. It is not a result at all. **Every one of the 19
jobs has zero steps, no runner assigned (`runner_name: ""`), and the entire run
completed in 13 s** against ~28 min for the green run on `5fbc48d` eight hours
earlier. Nothing was checked out, compiled or executed.

**Reproduced, not inferred.** The run was re-run at 16:56 UTC, 44 minutes after
the first attempt. Attempt 2 is identical: 19 of 19 jobs, zero steps, no runner,
**14 s**. Two attempts, same signature, no code or configuration change between
them.

Four benign explanations were eliminated by measurement rather than argument:

| candidate | how it was ruled out |
| --- | --- |
| waves 12–13 broke the CI config | `git diff 5fbc48d..1c702d4 -- .github/` is **empty** — the pushed range touches no workflow file |
| Actions disabled on the repository | `actions/permissions` reports `enabled: true`, `allowed_actions: all` |
| a GitHub platform incident | githubstatus.com reported **All Systems Operational**, no incidents, at both attempts |
| a transient scheduling blip | attempt 2 reproduced it exactly, 44 minutes later |

A job that is created, is never assigned a runner, and dies in seconds across
**every** label — including plain `ubuntu-latest`, not merely the `macos` and
`windows` legs — is a dispatch refusal at the account level, not a property of
this repository or this commit. On a **private repo on GitHub Free**, where
Actions minutes are metered, the standing candidate is an exhausted minute
allowance or a reached spending limit. That is consistent with the other
account-level refusal this project already records: branch protection returning
403 for the same class of reason (D52).

**Unconfirmable from the checkout, and the reason is worth recording.** The
billing endpoint requires the `user` token scope, which the working token does
not carry (`gist`, `read:org`, `repo`, `workflow`); a device-flow refresh was
attempted and its one-time code expired before completion. Independently,
`actions/runs/<id>/timing` reports **`0` billable milliseconds for every job of
the *successful* `5fbc48d` run**, so that endpoint is not a usable probe for
consumption here and should not be treated as one by a later reader. The
diagnosis above therefore rests on the dispatch signature, which is
reproducible, rather than on a quota figure, which is not readable.

**The failed dispatches cost nothing.** No runner was assigned, so neither
attempt billed minutes — which is also why re-running was the cheap decisive
test rather than an expensive gamble.

#### ~~Correction — the refusal signature is `conclusion: failure` with `steps == []`, not "no runner assigned"~~ — **WITHDRAWN 2026-08-16, the correction was the defect**

> **Read this box before the section below it.** The correction that follows was
> written by the orchestrator on 2026-08-16 and is **wrong**. It reported that
> the 45 refused jobs *"WERE assigned runners"* on the strength of their
> `started_at`/`completed_at` stamps being populated — which is true, and which
> answers a different question from the one the original text asked.
> **Re-measured against the field that actually carries the claim, all 45 have
> `runner_name: ""`.** The section it "corrects" was accurate as written.
>
> A refused job is **stamped, unassigned, and stepless — all three at once**, so
> either `runner_name == ""` or `steps == []` finds it and the original wording
> misleads nobody. The correction below is struck rather than deleted because
> the failure it demonstrates is worth keeping: *a claim about runner assignment
> was checked by reading a timestamp field, and the wrong answer was then
> published as a correction to somebody else's correct work.* That is the same
> shape as the defects this document exists to catch, committed by the person
> auditing them.
>
> **Its one surviving clause** is the last paragraph's: *"the failed dispatches
> cost nothing"* is restored to its original reading — with `runner_name: ""`
> there is no runner to bill, so **zero** stands and the "at most one billed
> minute per job" hedge below is unnecessary.
>
> **Prospectively confirmed the same day.** The wave-21 push produced `ci`
> **`31943527193`** — 19/19 jobs, `steps == []`, `runner_name: ""`, 7 s — and the
> Q19 dispatch `verifier-page` **`31943600047`** — 1/1, same shape, 5 s. Both
> workflow files parse. **The allowance is exhausted**, exactly as
> `docs/decisions/D135` §1.1 predicted, and this is the first time the refusal
> has been seen coming rather than diagnosed afterwards.

#### Correction (superseded — see the box above), 2026-08-16

**The corrected clauses, quoted verbatim**, from the section above:

> **Every one of the 19 jobs has zero steps, no runner assigned
> (`runner_name: ""`), and the entire run completed in 13 s**

> **The failed dispatches cost nothing.** No runner was assigned, so neither
> attempt billed minutes

**The finding stands whole. Its mechanism is one word off, and the word is the
one a future reader will grep for.** Re-measured 2026-08-15 by the orchestrator
over every workflow run created on or after 2026-08-01 in `aed900/antseal`
(43 runs, 583 jobs), read-only `gh api` GETs only:

- **45 jobs across exactly three runs executed ZERO steps** — `ci`
  **#31407751482** (19/19), `ci` **#31412086640** (19/19), `ci`
  **#31117310646** (7/19). The count and the runs are **exact**, and the two
  08-10 runs are 51 minutes apart, which is the *"re-run 44 minutes later
  reproduced it exactly"* pair the section above records.
- **They WERE assigned runners.** All 45 carry real `started_at`/`completed_at`
  stamps **3–12 s apart** and `conclusion: failure`. A query for jobs with **no
  runner assignment returns zero** across the whole window.

**So the signature this repository should look for is `conclusion: failure`
with `steps == []` in seconds** — not *"no runner assigned"*, which never
appears in the API and which a future reader grepping for it will not find,
concluding wrongly that the episode did not happen. The diagnosis
("an exhausted minute allowance or a reached spending limit") is unaffected and
so is the *"a lane that has never run on the remote is not evidence"* rule the
section exists to serve; only the query changes.

**One clause is now unverifiable rather than corrected**: *"the failed
dispatches cost nothing"* rested on the absence of a runner. With runners
assigned for 3–12 s the claim needs the billing endpoint, which this token
cannot read (see the paragraph above), so it should be read as **"cost at most
one billed minute per job"** — GitHub billing whole minutes — and not as zero.
Nothing downstream depends on it.

**The independent re-measurement of the bill, recorded here because
`docs/decisions/D135` §1.1 cites this document and this document should carry
the number it is cited for.** Every job's wall clock rounded **up** to the whole
minute as GitHub bills it, multiplied by the runner-OS factor (Linux ×1,
Windows ×2, macOS ×10): **3 324 weighted minutes, 2026-08-01 → 2026-08-15.**
D135 §1.1 independently computed **3 154** by the same method; the two agree to
within 5 % and the difference is rounding convention and window edges. **Both
are over a 3 000-minute allowance with 16 days of the month remaining.** Run mix
in the window: `ci` ×30, `fuzz-nightly` ×8, `pages` ×2, `advisory-cron` ×2,
`devnet-e2e-cron` ×1; job conclusions 517 success, 59 failure, 7 cancelled.

**Where a push's ~84 weighted minutes go** (run `31873411737`, 19 jobs), because
the shape matters more than the total when pricing a new required context:

| job | wall | mult | billed |
| --- | --- | --- | --- |
| `test` | 32.0 min | ×1 | 32.0 |
| `fuzz-smoke` | 11.2 min | ×1 | 11.2 |
| `cross-os-macos` | 1.3 min | **×10** | **13.2** |
| `cross-os-windows` | 4.8 min | **×2** | **9.7** |
| `wasm32-core-tests` | 3.7 min | ×1 | 3.7 |
| the other 14 jobs | 14.0 min | ×1 | 14.0 |
| | **67.0 raw** | | **83.7 weighted** |

**The two cross-OS jobs are 27 % of a push's bill for 9 % of its wall clock.**
This is the arithmetic **Q238** must re-take before promoting R86's comparison
to a required push context, and the reason **D135 §10 R2** chose a
workflow-level `paths:` filter — evaluated *before any runner is assigned*, so a
push touching no build input bills nothing at all.

**Authority.** Orchestrator re-measurement 2026-08-15, recorded by the registrar
at the wave-21 close 2026-08-16; the correction to `D135` §1.1's wording is
already applied in that record, in both places the phrase appeared.

### What `1c702d4` is and is not verified by

**Is:** the full local gate, green — **23 printed lanes, 21 PASS, zero reds,
2437 tests** — plus `scripts/ci-lanes.sh secret-guard` run by hand (not in the
gate), whose own self-test detected all 5 planted fakes first. The 23rd lane is
new this wave and is **Q141**'s fix: `cross-check-st` runs `--self-test` before
`--check`, so the gate now runs the half that selects.

**Is not:** anything only the remote can reach. This document's standing
warning — *a lane that has never run on the remote is not evidence* (Q43) —
applies to this commit in full, and it applies with unusual force here, because
**Q140 changed a `build.rs` that backs `golden-vectors`, `cross-os-*` and
`test`**. D116 §1.5(a) is the reason that matters: the row named one walker and
the tree held two, and a `build.rs`-only fix would have left four required
contexts brickable. The macOS and Windows legs of that change have not run
anywhere. **Until a CI run completes on `1c702d4` or a successor, the
cross-platform half of Q140 is unverified**, and no later reader should treat
the green local gate as covering it.

Restoring dispatch is a maintainer action: raise the spending limit, wait for
the monthly reset, or reduce what the workflow spends — `cross-os-macos` bills
at a 10x multiplier and is by far the most expensive of the 19 jobs.

---

## Q153 — three gate lanes moved onto the remote, and two ruled to stay local (2026-08-10, M2 wave 14)

**Status of this section: DISCHARGED 2026-08-10 — the run-id cell is filled
and the three promoted steps have been observed green on a runner. The
discharging evidence is the appended section below; the body of this section
is left as written.**

| | |
| --- | --- |
| Remote run id | **31436791456** (on `5bcdf7d`; see the appended discharge section) |
| Remote verdict | **green — all three promoted steps `success`**, in a 19-of-19 run |
| Local verdict | green, measured below — which this document's own rule says **is not evidence**, and which is why the cell above was left empty until a runner filled it |

Filling that run-id cell is the whole of what remains. Until it carries a
number, the three steps below are exactly what the rule at "A lane that has
never run on the remote is not evidence" describes: committed, plausible, and
unexecuted. **No later reader should treat this section as closing Q153.**

### What Q153 was, and the part of it that was wrong

Q153 measured five lanes that `scripts/local-gate.sh` runs and CI did not:
`gate-features.sh --self-test`, `gate-features.sh --check-partition`,
`gate-features.sh --heavy`, `wasm-bitmatch.sh --trigger-self-test` and
`e2e-devnet.sh --self-test`. `grep -rn 'gate-features' .github/` returned
**zero hits**, so S22's entire feature-partition mechanism — the guard that
makes dropping `--all-features` safe — had never run on a runner, and the
HEAVY features were compiled by no CI lane at all.

The row said the first two and the fourth were "seconds and cargo-free" and
should therefore ride the `traceability` job. **Half of that is false.**
`gate-features.sh`'s `declared_features()` runs `cargo metadata
--format-version 1 --no-deps --locked`, so `--check-partition` and the
`--self-test` that wraps it are **not cargo-free**. Measured by removing cargo
from `PATH` and running each lane:

| lane | with cargo | cargo off `PATH` |
| --- | --- | --- |
| `gate-features.sh --check-partition` | rc 0 | **rc 1** — `cargo metadata returned NO features at all` |
| `gate-features.sh --self-test` | rc 0 | **rc 1** — arm 1 fails to reach its planted-fault message |
| `wasm-bitmatch.sh --trigger-self-test` | rc 0 | **rc 0** — genuinely cargo-free and git-free |

That matters because `traceability` **has no toolchain bootstrap and no
cache**, which the Q16 section above states as a property of the job ("needs
no toolchain and no cache, so the step adds no setup"). A `cargo` invocation
there would resolve `rust-toolchain.toml` through the rustup shim and
implicitly install the pinned 1.92.0 — plus `rustfmt`, `clippy` and the
`wasm32-unknown-unknown` std — on one of the only **two** jobs in this
workflow that need no toolchain at all (`secret-guard` is the other), on a
repository whose minute consumption is the standing suspect for the refused
dispatch recorded in the section above.

#### Correction — the cargo-off-`PATH` table is a measurement on a date, and the property it measured is now asserted on every run, 2026-08-11

**The corrected clause, quoted verbatim**, from the paragraph immediately
above ("What Q153 was, and the part of it that was wrong"):

> That matters because `traceability` **has no toolchain bootstrap and no
> cache**, which the Q16 section above states as a property of the job

**The table and that paragraph are correct and are not rewritten.** What is
corrected is their *status*: they read as a standing property of the job, and
they were a **one-off measurement taken on 2026-08-10** by removing cargo from
`PATH` and running each lane once. Nothing re-took it, and nothing would have
noticed if a later step had made it false — which is Q182.

**The measured fact, with the command and its output.** Since D124/Q182 the
property is asserted by `scripts/cargo-free.sh`, armed as the first step of
`traceability` and read back as its last. Re-measured 2026-08-11 through the
real guard, prepending its shim directory to `PATH` exactly as a
`$GITHUB_PATH` entry does, control and masked, output diffed:

| step | control | masked | output | shims tripped |
| --- | --- | --- | --- | --- |
| `ci-lanes.sh traceability` | rc 0 | rc 0 | **byte-identical** | 0 |
| `ci-lanes.sh ci-shell` | rc 0 | rc 0 | **byte-identical** | 0 |
| `ci-lanes.sh fuzz-budget` | rc 0 | rc 0 | **byte-identical** | 0 |
| `ci-lanes.sh anchor-net-policy` | rc 0 | rc 0 | **byte-identical** | 0 |
| `wasm-bitmatch.sh --trigger-self-test` | rc 0 | rc 0 | **byte-identical** | 0 |

Each was verified **by its message, not by its exit status** — `cargo`,
`rustc` and `rustup` were each confirmed to resolve to the shim and to print
`invoked a masked toolchain binary` at exit 127 before the steps were run, and
the run of a control before *and* after each masked run separates "the mask
changed nothing" from "the shared tree moved under the measurement".

The near-miss was then reproduced end to end. With the job armed,
`./scripts/gate-features.sh --check-partition` — Q153's actual first placement
— was run **with both its streams discarded**, which is
`scripts/gate-features.sh:116`'s own shape:

```
    step exit status: 1        (gate-features' own rc — proof of nothing)
::error::cargo-free: the 'traceability' job invoked a masked toolchain binary
  — 1 invocation(s) recorded. …
::error::  no-step-id	cargo metadata --format-version 1 --no-deps --locked
```

**Authority**: D124 (Q182), wave-15 implementing lane, 2026-08-11. This
correction lands in the same change as the guard it describes.

**Which findings still stand**: all of them, and in the direction that
strengthens them. The three cargo-off-`PATH` rows above are unchanged; the
placement of the two `gate-features.sh` steps on `core-dep-graph` is
unchanged and now has its own assertion (`--require`); and the paragraph's
account of the failure mode — *an implicit install of the pinned 1.92.0 on a
green job*, not a red — is the account Q182's row garbled into "will fail on a
missing toolchain", and it is this document that had it right.

### Where the three actually landed

Two jobs, **no new job**, so no new required context:

| step | job | why that job |
| --- | --- | --- |
| `./scripts/gate-features.sh --self-test` | `core-dep-graph` | already bootstraps the toolchain, already caches, already runs `cargo metadata`/`cargo tree`, and is the **complementary half of the same claim**: dep-graph proves the heavy graph stays out of the default build, the partition proves every declared feature is compiled by some tier. `gate-features.sh`'s own header calls the two complementary and says why neither substitutes for the other. |
| `./scripts/gate-features.sh --check-partition` | `core-dep-graph` | as above; self-test runs first, as everywhere else in this workflow. |
| `./scripts/wasm-bitmatch.sh --trigger-self-test` | `traceability` | git-free, verified rather than assumed; and cargo-free — **asserted every run since D124/Q182** rather than measured once — so it adds no setup to the job that deliberately has none, the same argument `ci-shell`, `fuzz-budget` and `anchor-net-policy` made for the same job. |

**The context set does not change: still 19.** Recounted from
`.github/workflows/ci.yml`, not read from this file: 17 job ids
(`fmt`, `clippy`, `test`, `wasm32-core`, `wasm32-core-tests`, `core-dep-graph`,
`cross-os`, `golden-vectors`, `cross-check`, `vector-freeze`, `format-freeze`,
`wasm-bitmatch`, `tamper-matrix`, `fuzz-smoke`, `audit-deny`, `secret-guard`,
`traceability`), of which `cross-os` is a 3-way matrix — **19**. Q153 adds
three *steps* and zero jobs. The branch-protection payload and Q56's generated
context list are untouched.

### Minute cost

Measured locally, three runs each, 2-core host, warm toolchain:

| step | run 1 | run 2 | run 3 |
| --- | --- | --- | --- |
| `gate-features.sh --self-test` | 0.72 s | 0.69 s | 0.75 s |
| `gate-features.sh --check-partition` | 0.48 s | 0.17 s | 0.16 s |
| `wasm-bitmatch.sh --trigger-self-test` | 0.08 s | 0.08 s | 0.08 s |

Under two seconds in total, added to two jobs that already pay checkout and —
for `core-dep-graph` — toolchain and cache. Nothing here required
re-deriving the fuzz budget.

**The figures are labelled, not laundered** (Q128's standard). Those three
runs each were taken back to back on an otherwise idle host. A fourth run of
the same three commands, taken later while sibling wave lanes were running
cargo on the same 2-core box, measured **1.83 s / 0.28 s / 1.95 s** — the
trigger self-test, which touches neither cargo nor git, moved 24x on
scheduling alone. So the honest claim is the ORDER: all three are
sub-two-second shell-and-Python checks whose cost is dominated by whatever
else the machine is doing, not a runner budget. The runner numbers are part
of what the pending run will produce.

### The ruling on the two that did not move

**`gate-features.sh --heavy` stays local.** It is not a check, it is a
**compile**: `cargo clippy` and `cargo test` for three package/feature pairs
(`antseal-net --features ant-backend`, `antseal-cli --features ant-backend`,
`devnet-launcher --features devnet`) over the ant-core/ant-node/EVM graph —
**475 packages against the default 120**, measured by `ci-lanes.sh dep-graph`.
Per PR that is the single most expensive thing this workflow could gain, on a
private repo on GitHub Free whose 2 000-minute allowance is already the
standing candidate for the dispatch refusal recorded above, and where the
scheduled fuzz lane is separately budgeted against a named 700-minute ceiling.
It stays the local, diff-selected tier-2 gate that D52/S22 designed it to be.

**The residual is stated rather than hidden.** After this change CI *can* see
a feature that no tier classifies — that is what `--check-partition` proves,
and it now proves it on the remote. CI still **cannot** see a heavy-gated code
path that has stopped compiling; the HEAVY features remain compiled by zero CI
lanes. Q112 is the standing evidence that this failure mode is real and not
theoretical. The difference from before is that this is now a priced decision
with the price written down, rather than an absence nobody had noticed.

**`e2e-devnet.sh --self-test` stays out of `ci.yml`, and its home is named.**
It needs no devnet and costs seconds, so cost is not the argument. The
argument is venue: `.github/workflows/devnet-e2e-cron.yml` runs
`./scripts/e2e-devnet.sh` **bare** — the lane without its test-of-the-test —
and putting the self-test on a per-PR job would leave the self-test in one
venue and the lane it guards in another. It belongs **beside the bare lane, in
the cron workflow, as its own step immediately before it**, matching how
`ci.yml` already runs the cross-check's two halves as separate steps. That
work is **Q154**, which owns that file; this section records the ruling so
Q154's executor does not have to re-derive it, and takes nothing from it.

### What produces the missing evidence

`ci.yml` has **no `workflow_dispatch` trigger**; it runs on `pull_request` and
on `push` to `main`. There is therefore no way to exercise these three steps
remotely without a push, which is a maintainer action requiring express
consent. The sequence that fills the cell at the top of this section:

```
git push origin main                       # maintainer action, express consent
gh run list --workflow=ci.yml --limit 1    # take the run id
gh run view <id> --log | grep -E 'Q153'    # the three new steps, by name
```

The three steps to look for, by their `name:` in the workflow:

- `Q153 — self-test the S22 feature partition (prove it can go red)` — job `core-dep-graph`
- `Q153 — every declared feature is on exactly one gate tier` — job `core-dep-graph`
- `Q153/Q128 — the wasm-bitmatch trigger still selects a vectors-only change` — job `traceability`

**That run is also the test of something else, and this section claims neither
outcome.** The three runs before it (31407751482, 31412086640 and one further
attempt) all died in ~13 s with 19 jobs, zero steps and no runner assigned —
the account-level dispatch refusal diagnosed in the section above. If the next
run reproduces that signature, it says nothing whatever about Q153; these
steps will simply not have executed, and this section stays PENDING.

### What was verified locally, and what that is worth

All three lanes were run at this commit and are green, with the timings above,
and the surrounding lanes were re-run after the edits: `ci-lanes.sh ci-shell`
green (**65** `run:` blocks across 4 workflows, up from 62 — every one a
committed script call, which is what Q43's check requires of the three new
ones), `ci-lanes.sh traceability` green, `ci-lanes.sh anchor-net-policy` green
(it reads `scripts/local-gate.sh`, whose header this change rewrites), and
`gate-features.sh --check-partition` green after that rewrite (it parses
`GATE_LIGHT_FEATURES` out of the same file).

Per this document's own rule, none of that is evidence for the thing Q153
asked for. It is evidence that the change is well-formed. The remote run is
the evidence, and it does not exist yet.

---

## Q153 discharged — the three promoted lanes observed green on a runner, and the dispatch refusal is over (2026-08-10, M2 wave 14)

**Run `31436791456`, head `5bcdf7d`, conclusion `success`, 19 of 19.** This is
the project's fifth all-green run and the first since the dispatch refusal.

The three steps Q153 moved onto the remote, by `name:`, each `success`:

| job | step | verdict |
| --- | --- | --- |
| `core-dep-graph` | `Q153 — self-test the S22 feature partition (prove it can go red)` | success |
| `core-dep-graph` | `Q153 — every declared feature is on exactly one gate tier` | success |
| `traceability` | `Q153/Q128 — the wasm-bitmatch trigger still selects a vectors-only change` | success |

Required-context count is **unchanged at 19** — 17 job ids with `cross-os` a
three-way matrix. Three steps were added and no job was, which is why the two
cargo-touching lanes ride `core-dep-graph` rather than `traceability`: that
job has no toolchain bootstrap and no cache. **This document used to be the
record of that property; since D124/Q182 it is asserted on every run of the
job by `scripts/cargo-free.sh`, and stated once in that script's header** —
which is what this sentence now cites instead of asserting.

**The dispatch refusal is resolved and its diagnosis is confirmed.** The three
refused runs (`31407751482`, `31412086640`, and the run on `95fcee0`) each
reported 19 jobs with **zero steps, no runner, ~13 s**. The maintainer upgraded
the account to Pro, and the next run **queued** rather than completing
instantly — jobs waiting for runners is the signature of dispatch working. Runs
`31432412612` and `31436791456` both report **zero zero-step jobs**. The
standing candidate recorded in the earlier section — exhausted Actions minutes
on a private repo on GitHub Free — is therefore confirmed by intervention, not
merely by elimination. **A 13-second run reporting `0 of 19` with zero steps is
a dispatch refusal and is never a verdict on the code**; check `len(steps)` and
duration before reading any red.

**One red preceded this green and it is worth recording, because the remote
caught what the local gate passed.** Run `31432412612` on `360ea2a` was
**18 of 19**, with `traceability` failing on
*"decisions went green on the red-case mutation of TODO.md"*. The cause was in
`TODO.md`, not in the lane: the `decisions` red case mutates that file with a
first-occurrence string replacement over `D18`'s unchecked register line, and
the wave's Current-focus block had reproduced that line verbatim in prose
hundreds of lines above the register, so the replacement consumed the prose
copy and left the register row untouched. The check then passed over input
that was supposed to break it.

That is the second instance of the shape in one wave — the first was caught
during bookkeeping, in the row registering the defect — and it is the
argument Q153 was filed on, demonstrated within hours of the lanes landing:
**a lane that has never run on the remote is not evidence**, and here the
remote falsified a locally-green tree. It was repaired in `5bcdf7d` by
describing the line instead of quoting it, with no change to `scripts/`.
**Q184** remains open as the sweep for other self-test fixtures pinned to
mutable tree values; it now has two instances rather than one.

Appended, not edited, except for the status table of the section above, whose
own text states that filling its run-id cell *"is the whole of what remains"*.

---

## A blast radius measured under fail-fast is a lower bound, not a radius (Q196, M2 wave 15 — 2026-08-11)

**The general form, and the reason this section exists:**

> **Any measurement of blast radius — the answer to *"how much does this
> break?"* — records the command that produced it and the predicate it
> counted. If the command is `cargo test`, it carries `--no-fail-fast`.**
> A count taken without the flag is not wrong; it is a **lower bound**, and a
> lower bound reported as a radius is the defect.

This is the sibling of the standing rule in *"A lane that has never run on the
remote is not evidence (Q43, M0 wave 7)"* above. Both say the same thing about
a different half of a measurement: Q43 about **where it ran**, this one about
**what it was allowed to count**.

### What the flag does, and the two things it does not do

`cargo test --help`, cargo 1.92.0 (the pinned toolchain), verbatim:

> `--no-fail-fast` — Run all tests regardless of failure. Without this flag,
> Cargo will exit after the first executable fails. **The Rust test harness
> will run all tests within the executable to completion, this flag only
> applies to the executable as a whole.**

**(1) The loss is at test-target granularity, never at test granularity.**
Within the first failing executable the count is *already complete* — libtest
runs the whole binary and reports `N passed; M failed`. What a fail-fast run
loses is every test in every *subsequent* target, all of it. So a fail-fast
survey is not "the first failure and nothing after it"; it is "one target,
counted in full, and zero from every other target". Its tightness therefore
depends on **target order**, which nothing in this repository pins or asserts.
Anyone writing *"cargo test stops at the first failure"* has the mechanism
wrong in a way that matters: it predicts a count of 1 where the true fail-fast
count is however many tests that one target happens to hold.

**(2) It does nothing for a breakage that stops the compile.** From the same
manual page:

> While `cargo test` involves compilation, it does not provide a
> `--keep-going` flag. Use `--no-fail-fast` to run as many tests as possible
> without stopping at the first failure. To "compile" as many tests as
> possible, use `--tests` to build test binaries separately.
>
> ```
> cargo build --tests --keep-going
> cargo test --tests --no-fail-fast
> ```

A survey of a change that breaks a build script, a shared type or a macro must
run the two commands in that order, or it measures the first compile error and
stops. **D116 §1.5 is exactly this case and no test flag would have widened
it**: a planted `.pyc` made `crates/wasm-bitmatch`'s build script panic, so
`cargo check --workspace` exited 101 before any test binary existed.

### Surveying and gating are different jobs, and only one of them needs the flag

| | question it answers | flag |
| --- | --- | --- |
| **Survey** | *how much of the tree does this move?* | `--no-fail-fast` (and `cargo build --tests --keep-going` first, when the breakage can stop a compile) |
| **Gate** | *is this tree shippable?* | **no flag, deliberately** |

The gate's job is to **stop**, not to survey. One red is already the whole
answer to *"is this shippable?"*, and the marginal reds cost a full run of a
broken tree — slower, and noisier at exactly the moment the operator wants one
name to go and fix. **Do not add `--no-fail-fast` to `scripts/local-gate.sh`,
to any `lane_*` in `scripts/ci-lanes.sh`, or to any workflow.** That is a
different question with a different cost, and this section is not an argument
for it.

A survey is therefore a **separate, deliberate, ad-hoc invocation**, run by the
lane that needs the number and written down with the number. It is not a lane
and must not become one.

### Recording the number: the command and the predicate, both

Two figures in this tracker have been misread, and only one of them was
misread because of a flag:

- **The command**, because a bare count does not say what was allowed to stop.
  D95 §7 is the one place in this repository that got this right before the
  convention existed — *"`cargo test -p antseal-core --features test-util
  --no-fail-fast --tests`: **five** red, not D94 step 0's predicted two"* — and
  the reason it is quotable is that the flag is inside the quote.
- **The predicate**, because a bare count attaches itself to whatever the
  reader is already thinking about (Q160's generalisation; D116 §9 item 8's
  *"a measurement recorded without its subject is a measurement that will be
  applied to the wrong thing"*). D116 §1.5(a)'s *"two walkers"* and the Q157
  census's *"twelve walk sites"* count **different predicates** over the same
  directory and are both true; the row that read the second as superseding the
  first (Q196) is the measured instance of the hazard.

So: *"eight tests across four targets, `cargo test --workspace --locked
--no-fail-fast` at `<commit>`, counting failing test functions"* is a radius.
*"eight tests"* is not.

The epoch rule of D117 §2.5 applies to a radius the same way it applies to any
count: name the commit it was taken at, or write it as a command the reader can
re-run.

### The measured state of the tree, 2026-08-11 (working tree at `1f82da1` plus wave-15 lanes)

- **`--no-fail-fast` appears in no invocation anywhere.** Not in `scripts/`,
  not in `.github/`, not in `CONTRIBUTING.md`'s PR checklist. Its only
  occurrence as a *record* is D95 §7, quoted above. (Its other occurrences are
  in `TODO.md`'s and `tasks/Q.md`'s Q196 rows, which are this convention's own
  paperwork — the "exactly once in the whole repository" figure those rows
  state was falsified by the act of writing them down.)
- **Twelve `cargo test` invocations execute tests, and every one runs
  fail-fast**: `local-gate.sh`'s `test` lane; `ci-lanes.sh`'s `lane_cross_os`,
  `lane_golden_vectors`, `lane_tamper_matrix` (two) and `lane_cbor_drift_guard`;
  `gate-features.sh`'s per-feature lane; `format-freeze.sh`'s and
  `vector-freeze.sh`'s authoritative checkers; `wasm-tests.sh`'s wasm32 unit-test
  lane; `e2e-devnet.sh`'s devnet target; and `ci.yml`'s `test` job.
- Two further `cargo test` invocations execute nothing and are correctly
  unaffected: `ci-lanes.sh`'s `count_matched` (`-- --list`) and
  `wasm-tests.sh`'s planted-fault build (`--no-run`).

**All twelve are correct as they stand.** Every one of them is a gate, not a
survey. Nothing in this section asks for a single one of them to change.

### What this does not claim

A fail-fast count is not a false count. It is a true count of a smaller thing,
and for the question a gate asks it is the *right* thing. This section is
about one sentence in a write-up: the sentence that turns a true lower bound
into a claimed radius by omitting the command that produced it.

Appended, not edited.

---

# Q182/D124 — the `traceability` job's cargo-free property, asserted rather than stated (2026-08-11, M2 wave 15)

## The context set does not change: still 19

**Recounted from `.github/workflows/ci.yml`, not read from this file**, per
this document's standing instruction. **17** job ids — `fmt`, `clippy`,
`test`, `wasm32-core`, `wasm32-core-tests`, `core-dep-graph`, `cross-os`,
`golden-vectors`, `cross-check`, `vector-freeze`, `format-freeze`,
`wasm-bitmatch`, `tamper-matrix`, `fuzz-smoke`, `audit-deny`, `secret-guard`,
`traceability` — of which `cross-os` is a 3-way matrix (`linux`/`macos`/
`windows`) and every other job is one context: 17 − 1 + 3 = **19**. D124 adds
**three steps and zero jobs**. The branch-protection payload and Q56's
generated context list are untouched.

## What is asserted, and where

Two steps on `traceability` and one on `core-dep-graph`, all calling one new
committed script, `scripts/cargo-free.sh`:

| job | step | what it asserts |
| --- | --- | --- |
| `traceability` | `cargo-free.sh --arm traceability` — **first**, right after checkout | self-tests the guard, then installs failing `cargo`, `rustc` and `rustup` shims under `$RUNNER_TEMP` and appends that directory to `$GITHUB_PATH`, which prepends it for **every later step of the job, including steps not yet written** |
| `traceability` | `cargo-free.sh --verdict traceability` — **last** | red if any step tripped a shim, red if the guard directory is gone, red if the shims are not what `PATH` resolves |
| `core-dep-graph` | `cargo-free.sh --require core-dep-graph` — after the cache step | the **converse**: this job does have a working cargo and rustc, which two of its steps need |

**The property itself is stated exactly once**, in `scripts/cargo-free.sh`'s
header. Sixteen prose statements across six files — five in `ci.yml`, one in
`ci-lanes.sh`, two in `local-gate.sh`, **six in this document**, one in
`docs/testing/fuzzing.md`, one in `docs/testing/anchor-ci-policy.md` — kept
their own local point (why a step rides that job, the context arithmetic) and
**dropped the assertion**, citing the guard instead. A seventeenth sat inside
`check-ci-shell.py`'s own docstring.

## Why not in `check-ci-shell.py`, where workflow facts get checked

**Because a per-job predicate over `run:` text is vacuous against the incident
that produced the row, not because it is expensive.** Q153's near-miss line —
`./scripts/gate-features.sh --check-partition` — carries no `cargo` token, and
neither does any of the five `run:` lines the job carried before this change:
**0 of 6**. Reading one level into the callee is worse, not better:
`ci-lanes.sh` holds 31 `cargo` occurrences belonging to other lanes and
`wasm-bitmatch.sh` 4, so a callee-grep turns **all five of the job's green
steps red**, starting with the one step Q153 verified cargo-free by running
it.

Job attribution itself was prototyped and **measured at nine lines, 65 of 65
`run:` blocks attributed, zero unattributed** — so *"that is the larger half
of the work"* is refuted, and the parse is declined because nothing needs it
rather than because it costs anything. Both facts are recorded at
`run_blocks()` so the shape is not re-proposed and the price is not
re-litigated.

`run:` text is simply the wrong **observable**. The property is a claim about
a *process tree*: which argument a committed script was called with, which
branch it took, what it shelled out to. So the assertion goes where the fact
is — at the job, at runtime, where a shim either gets called or does not.

## The two steps guard each other

Deleting the arming step does not quietly disarm the job: `--verdict` is red
when the guard directory does not exist, which is what the arming step
creates. It is also red when `cargo` no longer resolves to the shim, which
closes the subtler hole — an **empty marker file read as "clean" when it means
"never armed"**. Deleting *both* steps is a deliberate two-step act that
removes two steps whose names say what they are, and nothing fires; closing
that needs the per-job step-presence check D124 declined to build.

## Why a marker file rather than a message

Because the message can be taken away and the file cannot.
`scripts/gate-features.sh:116` pipes `cargo metadata … 2>/dev/null`: with
cargo masked, the exit status survives and the diagnosis does not, and what a
maintainer reads is an unhandled `JSONDecodeError` followed by *"cargo
metadata returned NO features at all — the extractor is broken"* — loud, and
pointing at the wrong file. That measurement is why `--require` exists at all,
and why the shims write their record **before** printing anything.

## Cost

Three steps, no new job, no new required context. `--arm` and `--verdict` read
and write a handful of small files under `$RUNNER_TEMP`; `--require` runs
`cargo --version` and `rustc --version` on a job that has already bootstrapped
its toolchain and restored its cache. **No wall-clock figure is recorded
here**: this lane's measurements were taken on a 2-core host under ten
concurrent lanes, where D124 already caught itself recording a 39× figure that
was cold page cache and nothing else. A figure with no honest sample is worse
than no figure — the rule is `local-gate.sh`'s own, and Q160's.

## What this does not do

1. **The property is asserted on the remote only.** `--arm` works by appending
   to `$GITHUB_PATH`, which covers a job's *later steps*, and a local run has
   no later steps. `local-gate.sh` runs `cargo-free.sh --self-test`, which
   proves the guard can go red; it does not run the job. A contributor can
   break this property locally and find out only on the remote — recorded in
   `local-gate.sh`'s own both-directions ledger rather than only here.
2. **It introduces `$GITHUB_PATH` to this repository for the first time.** No
   workflow and no script used it before. A reader of `ci.yml` will not see
   the `PATH` change at the step that causes it, which is why both steps carry
   comments naming each other.
3. **It cannot catch a cargo invocation by absolute path.** A step running
   `/usr/share/rust/.cargo/bin/cargo` bypasses `PATH` entirely. Nothing in the
   tree does this and the idiom would be conspicuous in review, but the
   guard's coverage is `PATH` resolution, not process creation.
4. **It does not fix `gate-features.sh`'s unhandled traceback.** `--require`
   fires before the extractor is reached, so the wrong diagnosis stops being
   *seen* on that job; the naked `JSONDecodeError` on empty stdin remains in
   the code, reachable by any other cause of empty `cargo metadata` output.

## Remote verdicts — 2026-08-11 (recorded at wave-16 open)

- **Run `31450497379` on `f9e315d` (wave 15): 19 of 19 GREEN** — `completed
  success`, re-verified via `gh run view` immediately before this entry was
  written rather than copied from memory. The project's sixth all-green
  remote run and the first carrying the `cargo-free` guard. This entry
  closes wave 15's one recorded loose end: the run was green for a day
  before the project's own convention had a record of it.
- **Run `31493145976` on `5654518` (D125 + P3-partial + A25 day-1): 19 of 19
  GREEN** — `completed success`, job conclusions counted from the API
  (`{"success": 19}`), not inferred from the watch's exit code. The seventh
  all-green remote run, dispatched normally in under a minute on the Pro
  plan — the second consecutive push with no trace of the dispatch-refusal
  signature.

## Remote verdicts — 2026-08-11 (recorded at wave-16 close, ~17:45Z)

- **Run `31516683380` on `e50bb1a` (the wave-16 range, `5654518..e50bb1a`,
  10 commits): 19 of 19 GREEN** — `completed success`, job conclusions
  counted from the API (`{"success": 19}`), recorded within the hour of the
  verdict. The eighth consecutive all-green remote run, and the first
  carrying the R13 builder, the R14 property suite, the R15 preview, the
  Q236/Q237 gate rows and `scripts/anchor-smoke` — the wasm32 lanes ran on
  the diff selection (the range touches `antseal-core`), and the range also
  carried this file's wave-15/seventh-verdict record, closing the loop where
  a verdict-record commit rides the next wave's push. One non-verdict
  observation from the run log: `actions/checkout@v4` now warns that Node.js
  20 is deprecated and is being forced onto Node 24 by the runner — an
  upstream-action deprecation to absorb at the next deliberate workflow
  touch, not a failure and not this wave's to chase.

## Remote verdicts — 2026-08-12 (recorded at wave-17 close, ~00:05Z)

- **Run `31546885357` on `3c8095a` (the wave-17 range, `e50bb1a..3c8095a`,
  10 commits): 19 of 19 GREEN** — `completed success`, job conclusions
  counted from the API (`{"success": 19}`, zero skipped), started
  2026-08-11T23:32:52Z, concluded 2026-08-12T00:03:28Z, recorded within the
  hour of the verdict. **The ninth consecutive all-green remote run**, and
  the first carrying **M2's passed gate** — `CURRENT_MILESTONE = "M2"` and
  the register's first-ever `ACCEPTED_NON_COVERED` entry (`V7.1`, ruled by
  D127) — together with R16's reveal-flow API, R17's verdict aggregation
  and online overlay, and R18's frozen wording set with its snapshot.
  The wasm32 lanes ran on the diff selection (the range touches
  `antseal-core` heavily), and the `traceability` job is the one that
  matters most this wave: it executes the same status gate that now covers
  **27 rows** rather than 22, so the milestone bump is verified remotely and
  not merely locally.
- **Run `31627097358` on `fbf70e4` (the wave-18 range, `3c8095a..fbf70e4`,
  3 commits): 19 of 19 GREEN** — `completed success`, job conclusions counted
  from the API (`{"success": 19}`, zero skipped), started
  2026-08-12T18:19:56Z, concluded 2026-08-12T18:46:50Z, recorded within the
  hour of the verdict. **The tenth consecutive all-green remote run**, and
  the first carrying a **zero-hole M2** — `ACCEPTED_NON_COVERED` is empty
  again, `V7.1` reads `covered`, and the status gate's 27 rows at or before
  M2 are all `covered` with no exception standing — together with the whole
  CLI half of M3 (R19–R22, U27–U30) and the fifth crate, `antseal-wasm`.
  **What this run proves that the local gate could not**: `core-dep-graph`
  passed with a new workspace member in the tree, so D18's central claim —
  that a target-gated `wasm-bindgen` edge in a separate crate leaves the
  core's reviewed graph untouched **by construction** — is verified remotely
  and not merely by the lane that asserted it.
- **What this run does NOT prove, and it is the sharpest such gap yet
  recorded.** `heavy-features` is **not a CI job** — Q153 ruled it local-only
  (475 packages against the default 120) and it is additionally
  diff-triggered — so this green says nothing whatever about the
  `--features ant-backend` build. That build's `machine_mode` suite is **red
  right now** and was red at `3c8095a` before wave 18 began: one committed
  `json-envelopes.txt` cannot hold the two different texts
  `backend::unavailable`'s two `#[cfg]` arms emit, so whichever build the
  snapshot documents, the other's machine surface is asserted by nothing.
  **R82** owns it. This is the exact shape Q43's rule warns about pointing
  the other way — a lane that has never run on the remote is not evidence —
  except here the lane runs locally, is red, and the remote's green is
  silent rather than contradictory.
- **What this run does NOT prove, stated because the range invites the
  inference**: it says nothing about the anchor endpoints. The A25
  wave-17-cycle submissions (2026-08-11T23:39Z, eight `pending-accepted`
  through A13's own client) landed **after** this run's commit and are
  excluded from CI by policy in any case — no lane may contact a real
  anchor endpoint (`docs/testing/anchor-ci-policy.md`, Q16), and
  `check-anchor-net.py` is what asserts that, not this verdict.
- One non-verdict observation, unchanged from the eighth run:
  `actions/checkout@v4` still warns that Node.js 20 is deprecated and is
  being forced onto Node 24 by the runner — an upstream-action deprecation
  to absorb at the next deliberate workflow touch, not a failure.

# R22/D18 — the verifier-page module's build, and the profile its Accept row ran at (2026-08-12, M3 wave 18)

## The context set does not change: still 19

Both structural checks D18 §5 R6/R7 require ride jobs that already exist, and
that is a ruling rather than a convenience (§5 R8: *"CI minutes are a stated
constraint and neither check needs a runner of its own"*):

- **the graph rule** (§5 R6) is a second block inside `lane_dep_graph`, so it
  runs in the **`core-dep-graph`** job, which already bootstraps the toolchain
  and runs `cargo tree`;
- **the import allow-list** (§5 R7) runs at the end of
  `scripts/wasm-bitmatch.sh`, so it runs in the **`wasm-bitmatch`** job, which
  already builds a wasm32 artifact and instantiates one in node.

No job id, no `name:`, and no required-status context is added or renamed.

## Which artifact the import allow-list runs against in CI, and why not the other one

`scripts/wasm-imports.mjs` enumerates **two** spellings of the same import
table, because the module is checked at two points in its life:

| where | artifact | imports (measured 2026-08-12) |
| --- | --- | --- |
| `wasm-bitmatch` job (CI) | `cargo build -p antseal-wasm --target wasm32-unknown-unknown` | 5 — `__wbindgen_placeholder__.{__wbindgen_describe, __wbg___wbindgen_throw_*, __wbg_Error_*}` + `__wbindgen_externref_xform__.{table_grow, table_set_null}` |
| `scripts/wasm-pack-build.sh` (local / R25) | `wasm-pack build --release --target web` | 3 — `./antseal_wasm_bg.js.{__wbg___wbindgen_throw_*, __wbg_Error_*, __wbindgen_init_externref_table}` |

CI checks the **cargo** artifact deliberately: neither `wasm-pack` nor
`wasm-bindgen-cli` is installed in any CI job, and installing them there would
spend the minutes this wave was told not to spend. The property is not
weakened by the choice — a module's imports are generated from its **declared
bindings**, and the CLI's post-processing renames the placeholder module
rather than adding or removing a capability; both spellings are enumerated in
one committed list, so a new capability appears in whichever artifact is
checked first. The `wasm-pack` artifact is checked by the script that is the
only thing which produces one, and that script is R25's build entry point.

## Accept row 2 ran at the SHIPPED profile

D18 §5 R9 splits the `--release` question so neither half is unowned, and
gives R22 the boundary comparison at the shipped profile. Executed
2026-08-12 on the 2-core dev host:

- artifact: `wasm-pack build crates/antseal-wasm --release --target web
  --no-pack --no-opt --mode no-install`, i.e. **the `release` profile**, 1.84 MB;
- corpus: all **21** cases of `testdata/vectors/v1/report/verification-reports.json`,
  rebuilt and verified natively by `crates/antseal-wasm/examples/boundary-emit.rs`
  under `VerifyOptions::new()`;
- result: **21/21 byte-identical** through the JS boundary
  (`scripts/wasm-boundary.mjs`), plus typed `Error` throws for four hostile
  inputs, the closed five-name export surface, and `storage_linkage` evaluated.

This is the first comparison this project has run over the **shipped codegen
path**. F29 keeps only its own remaining question — whether the Q5 *vector*
bit-match gains a second pass at the release profile — and now has
`[profile.release.package.antseal-wasm]` to scope it with (unused today; the
crate declares no profile stanza).

## The build is hermetic, and it is hermetic only because two flags say so

D18 §7 P5 flagged two build-time hazards as *"R22's first act to measure, not
to assume"*. Measured, with every proxy variable pointed at a dead port:

- **`wasm-pack build --dev`** — no download, no `wasm-opt`, 1.2 s. It emits one
  warning, `failed to get wasm-pack version`, which is its own self-update
  check being denied egress: harmless, but evidence that the tool reaches for
  the network unprompted.
- **`wasm-pack build --release`** — **downloaded a `wasm-opt` binary and ran
  it**. The proxy variables did not stop it. The cache directory
  `~/.cache/.wasm-pack/` did not exist before the run and afterwards held
  `wasm-opt-1ceaaea8b7b5f7e0/bin/wasm-opt`, which reports **`wasm-opt version
  117`** and is dated **2024-02-28**. Nothing in this repository pins binaryen
  and `which wasm-opt` is empty.

That is a network fetch of an unpinned, unreviewed program that then **edits
the artifact whose SHA-256 the page publishes about itself** — a breach of both
D63 §5 R5's *"no network access during the build"* fence and
`docs/dependency-policy.md` §5's *"exact-pinned wherever installed"*. So
`scripts/wasm-pack-build.sh` passes **`--no-opt --mode no-install`**, and the
flags carry that measurement at the site. Cost of the choice, measured: 1.84 MB
unoptimized against 1.53 MB optimized, and 2.8 s against 3 m 05 s. Re-enabling
the optimizer needs a **pinned** binaryen first; it is F29/R25's question and
not a flag an implementation lane may flip.

## Where the toolchain pins are asserted

`scripts/wasm-toolchain-audit.sh` (in the `wasm32-core-tests` job) compares the
`wasm-bindgen` crate pin against every recorded `wasm-bindgen-cli --version`
line. Before R22 it was **RED** —
`::error::wasm-bindgen-cli is pinned (0.2.126) but no wasm-bindgen crate pin
exists in the root Cargo.toml` — because the maintainer's install line landed
in `docs/wasm-toolchain.md` before the committed crate pin did. With the pin in
`[workspace.dependencies]` it reports `OK    wasm-bindgen crate and CLI both
pinned at 0.2.126`. `scripts/wasm-pack-build.sh` additionally asserts the
**installed** binaries equal their pins before it builds anything, which the
audit cannot do (it reads files, never `--version`).

## The panic hook is load-bearing, and that was measured rather than assumed

R22's Accept row asks for a panic hook *and* a typed JS error object. The
second half is asserted by `scripts/wasm-boundary.mjs` over four hostile
inputs. The first half cannot be asserted against the shipped module — nothing
in it panics by design — so it was measured on a four-line probe built OUTSIDE
the repository with the same pinned toolchain (`wasm-bindgen =0.2.126`,
`rustc 1.92.0`, release, `--target web`), the same technique D18's own planning
lane used:

| build | what JS catches when a Rust panic fires |
| --- | --- |
| **no hook** | `RuntimeError: unreachable` — an opaque trap naming nothing |
| **the hook `crates/antseal-wasm/src/boundary.rs` installs** | `Error: antseal verifier panicked: panicked at src/lib.rs:18:5:\nplanted panic` — `instanceof Error`, catchable, carrying the message and the location |

A control call after the caught panic still returned its value, so the panic
does not poison the instance for the page's next drop. This is why the hook is
four hand-written lines calling `wasm_bindgen::throw_str` rather than the
`console_error_panic_hook` crate: the crate would be a seventh name in a
dependency graph whose entire point is that every name in it was argued for
(D18 §5 R6), and it logs where this throws.

## Why the amended Accept row was not a formality

D128 §9.3 amended R22's Accept row 2 from "byte-identical to the R9 vectors" to
"byte-identical to the report **native `verify_bundle` produces for the same
bundle under the same options**". Measured at R22's landing, over all 21 cases:

```
cases: 21   identical to the committed vector: 0   different: 21
first differing case: single-text-with-mirror/full
  vector file (suppressed tuple): …"storage_linkage":"not-evaluated","anchors":[]…
  R22 corpus  (default tuple)   : …"storage_linkage":{"evaluated":{"units_matched":0,…
```

The pre-amendment row would have failed **21 of 21**, every one of them at
`storage_linkage` and none of them for a reason about the boundary. The
comparison this row actually needs — native ≡ wasm32 for one input under one
options value — passes 21 of 21.

# R25/R26/R86 — the second deploy, the live bytes, and the reproducibility gate that has never run remotely (2026-08-16, M3 wave 21)

## The context set does not change: still 19

Nothing in this chapter adds, removes or renames a required status context.
`pages.yml` and `verifier-page.yml` are both `workflow_dispatch:`-only and
neither is a required context; **Q238** is the row that would change that, and
its precondition is a re-measured bill under the allowance.

## The deploy that is live, measured against the origin rather than the workflow

Run **31873422229**, workflow `pages.yml`, event `workflow_dispatch`,
`conclusion: success`, `run_attempt: 1`, `created_at 2026-08-15T08:01:00Z`,
`updated_at 2026-08-15T08:02:50Z` — **1.8 min wall against 8.4 min for the
first deploy** (`31847839638`), which is the cold-versus-warm difference
`verifier-page.yml`'s own header cites as the reason a rarely-run lane is always
a cold lane. `head_sha = 9317a35b3adaef56b03eaa22a80a2b76e232a7d9`, corroborated
by the origin's `last-modified: Sat, 15 Aug 2026 08:02:40 GMT`.

Measured from the local host by `curl` and read-only `gh api` GETs, **against
the live origin and not against a workflow step** — which is the distinction
this document exists to keep:

- **2 516 397 B**, `sha256 ea7e9447584be131443a6948c70ea2f5a624882d6ea7d1f953e6c08d04f43951`.
  That is the **post-remap** size R25 predicted; the pre-remap page was
  2 517 337 B.
- `content-type: text/html; charset=utf-8`; `cache-control: max-age=600`;
  `access-control-allow-origin: *`; `etag "6a801d20-2665ad"`; **no security
  header of any kind**, which is exactly why **D62 §3 R6** puts the CSP inside
  the hashed artifact.
- **Identity and gzip fetches decode to byte-identical bodies** — both
  2 516 397 B, both `ea7e9447…3951` (`Accept-Encoding: identity` against
  `--compressed`, `content-encoding: gzip` observed on the second). So the host
  does not rewrite the body and is **not disqualified by D63 §10 (iii)**.
- Site state (`GET repos/aed900/antseal/pages`): `cname antseal.org`,
  `build_type workflow`, `protected_domain_state verified`,
  `https_enforced true`, `https_certificate state=approved`,
  `expires_at 2026-11-12`, `domains ['antseal.org']`.

**Re-measured by the registrar at the wave-21 close, not transcribed.**
`gh run list --workflow pages.yml --json databaseId,conclusion,headSha,createdAt,updatedAt`
returns **exactly two runs, both `success`**, and every figure above is theirs:

```
31873422229  9317a35b3adaef56b03eaa22a80a2b76e232a7d9  2026-08-15T08:01:00Z → 08:02:50Z  (1.83 min)
31847839638  08c074c4f8a1926a29ade95b299aee7a75b6187b  2026-08-14T22:45:19Z → 22:53:43Z  (8.40 min)
```

Two runs is the whole deploy history of this project. It is also the measurement
behind two claims further down: that R86's reproducibility step has executed
**zero** times remotely (both runs predate it), and that the cold-versus-warm
gap on a rarely-run lane is real and is 4.6×.

## R26's standing debt is discharged, and its reasoning is corrected rather than carried forward

`TODO.md`'s R26 row and `tasks/R.md`'s R26 entry both carried **"STANDING DEBT:
a redeploy is owed"**. It ran, at the run and time above.

**But the note's reasoning must not be transcribed forward.** It said the live
bytes *"no longer reproduce from HEAD"*. That framing is wrong in a way that
misleads: the module carries an **`ANTSEAL_SOURCE_COMMIT`** stamp, and
**D135 §1.5** measured what that means — `08c074c` and `9317a35` produce modules
of **identical size, 1 853 031 B, with different digests**, and
`git diff --name-only 08c074c..9317a35` over every compile input
(`crates/antseal-core/src`, `crates/antseal-wasm`, `Cargo.lock`, `Cargo.toml`,
`.cargo`, `rust-toolchain.toml`) is **empty**. Not one compile input changed;
the only differing input is a 40-character hex string stamped through
`cargo::rustc-env`.

So the footer digest is a function of **the commit**, and the live artifact
reproduces from **`9317a35` and from no other commit** — including every commit
this wave adds. **The honest claim is "reproducible at the commit it was
deployed from", never "reproducible from HEAD"**, and R25/R26 now say so.

## What the served bytes say about themselves, and the one line a `curl` cannot read

- Footer: `id="page-build">page build <code>70235b8b6192b983b1d1eb3b926e5e5925257cd806b6763eeb2aff76539403c0</code>`
  — the **module's** digest, per D129 §5 R7, under a label that says "page".
  This is precisely the conflation **D136 §2 R12** ruled repaired this wave
  (`verifier-web/index.template.html:146` now reads `module build`), so the
  **live page predates the repair** and the next deploy carries it.
- `id="advice">for high-stakes verification, run <code>antseal verify</code> and compare verdicts`
  — `MVP-SPEC.md` line 139's sentence, verbatim, in the served bytes.
- **`id="build"` is EMPTY in the static bytes** (`id="build"></p>`): the
  provenance line is filled by JS at run time from the module's build info, so a
  static fetch cannot see it. **Any row claiming to have read the served
  provenance line is claiming something a `curl` cannot produce** — only a
  browser arm can, which is one more reason Q19's venue matters.

## The reproducibility gate is real and has never run on a hosted runner

**R86** landed as **a step, not a job**: `build and check the page`
(`./scripts/pages-publish.sh --build`) inside `pages.yml`'s pre-existing
`publish` job, positioned **before** `actions/configure-pages` so a red ends the
job with nothing staged and nothing published. Searched at this review,
`.github/workflows/` contains **no** two-build byte-identity job at all — the
tier is D135 §3 R1's **deploy-gated**, chosen against the measured bill above,
and a new job would have been a new metered runner.

**What this run does NOT prove.** Both deploys on record — `31847839638`
(2026-08-14, `08c074c`) and `31873422229` (2026-08-15, `9317a35`) — **predate
that step**, so the gate has executed **zero** times on a hosted runner. Every
clause of R86 was proven **on the local host** by driving
`scripts/pages-publish.sh --build` and its planted-fault control directly. The
exposure that follows is D135 §3 R4.1's, in its own words: *"Nothing between
deploys. A commit that breaks reproducibility is detected at the next deploy,
not at the push that broke it"* — measured at **days to weeks**, and acceptable
only while the repository is private and nobody has been invited to reproduce
anything. That is the whole content of **Q238**.

## Q19's lane has also never run remotely, and two dispatches are owed

`gh run list --workflow verifier-page.yml` returned **`[]`** at this review —
re-run by the registrar at the wave-21 close and still `[]`, so this is a
measurement and not a forwarded claim: the workflow is registered and active but
has **zero runs in its existence**. Under
**Q43**'s rule and **D136 §2 R6**, that is why **Q19 does not tick** — R6 makes
one witnessing dispatch a tick precondition in as many words. Owed, at a stated
**~8.30 weighted minutes each** (the measured first-ever `pages` run being the
closest analogue):

1. **`seed_failure` empty** — witnesses the lane on a hosted runner for the
   first time, closing Q19's Accept row 1.
2. **`seed_failure: bundle`** — the first execution ever of the `if: failure()`
   artifact-upload path, closing Accept row 2's remote half.

**Binding precondition**, set by the CI-venue lane: dispatch only after a green
local `./scripts/verifier-page-browser.sh --check` **at the exact commit being
dispatched**. A dispatch of a commit whose driver is red spends the same minutes
and proves nothing. **Ordering**: commit → push → dispatch, because
`workflow_dispatch` resolves a ref **on the remote**, so dispatching before the
push witnesses the old commit.

When they run, this document owes the same three things Q153's discharge
carried: the run id and verdict, an explicit statement that **the
required-context count is unchanged (still 19)**, and a *"what this run does NOT
prove"* bullet naming the surfaces a dispatch-only lane leaves unwitnessed on
every subsequent push.

## Three local lanes prove things no CI run repeats, and the M3 gate must name them

Recorded here so **Q237**'s evidence lines can cite a venue rather than a check:

| lane | what it proves | why no CI run repeats it |
| --- | --- | --- |
| `heavy-features` | the `ant-backend` machine surface (R82/Q113/U73) — measured green 2026-08-16, `cargo test -p antseal-cli --features ant-backend --test seal_command` → 23 passed, 0 failed, 47.73 s | **Q153** rules it local-only: 475 packages resolved against the default build's 120, and it is additionally diff-triggered |
| `page-browser` | R27's 13 fixtures / 86 rows and R85's 14 more, string-identical to the CLI capture | its workflow is `workflow_dispatch`-only and has **never been dispatched** |
| the `pages.yml` reproducibility step | R86's two-environment byte-identity, including its planted regression | `pages.yml` runs only on deploy, and both deploys predate the step |

---

# Q237 — the M3 gate's venue, and the CI fact that decides it (2026-08-16, M3 wave 21)

## The context set does not change: still 19

Nothing in this chapter adds, removes or renames a required status context. The
M3 gate ran no workflow and dispatched nothing; **Q238** is the row that would
change the set, and **Q19**'s two owed dispatches change it not at all — a
`workflow_dispatch` lane is not a context.

## No hosted runner has seen a byte of wave 21, and that is a measurement

This is the fact every clause of the M3 gate is qualified by, so it is recorded
here rather than left in a row.

`scripts/local-gate.sh:270` prints `git rev-parse --short HEAD` and the subject
of that commit, and then runs every lane **against the working tree**. A log
headed `gate: d8ce569 — …` therefore names the commit the tree happens to sit
on. **It is a label, not the revision under test**, and reading it as the latter
is the same class of error as reading a green `--check` as evidence the packaged
bytes came from the tree (R83).

Measured at this review, read-only:

```
gh run list --workflow ci.yml   → newest: 31873411737  push  success
                                   9317a35…  2026-08-15T08:00:45Z
git rev-list --left-right --count origin/main...HEAD   → 0  1
git diff --stat 9317a35..HEAD -- crates/               → (empty)
git diff --shortstat -- crates/    → 42 files changed, 3 560 insertions(+), 336 deletions(-)
git status --porcelain | grep '^??' | grep '/tests/'   → 7 new test files
```

So: `origin/main` is `9317a35`; the one local commit ahead of it touches no
crate file; and wave 21's code is **uncommitted**. The newest hosted `test` job
ran over a tree that predates R27, R82–R88, U67–U73, Q20 and every D136 repair.

**A note on how that fourth figure has to be taken, because the first attempt at
it was wrong.** `git diff --stat -- 'crates/*/tests'` returns **empty** here —
the pathspec does not match what it reads as though it should — so a run that
reported "14 files" came from naming the test directories one by one and
therefore measured a subset. The whole-`crates/` shortstat above is the figure
that is not a subset, and the untracked count is listed separately **because no
`git diff` counts an untracked file at all**: seven new test files exist in this
tree that a diff-based measurement would silently value at zero. Same family as
[[assertions-that-cannot-fail]], one level down — a command that returns nothing
looks like a small number rather than like a mis-aimed query.

**What follows, stated so no row inherits the opposite.** The register warned
that three lanes prove things no CI run repeats — `heavy-features`,
`page-browser`, and the `pages.yml` reproducibility step (table in the chapter
above). At these bytes **the `test` lane is a fourth**: the R18 wording
snapshot moved this wave, so the hosted `test` job at `9317a35` is not a witness
for the clause that asserts it. Every clause of the M3 gate is proven on **this
local host**. That is a statement about venue and not about strength — the
evidence is real, the machine is one — and it is the reason each gate clause
carries its machine rather than only its check.

## The gate re-run the M3 verdict rests on

`ANTSEAL_GATE_WASM=1 ANTSEAL_GATE_BITMATCH=1 ANTSEAL_GATE_HEAVY=1
./scripts/local-gate.sh`, on this local host (Debian, Linux 6.1.0-51-amd64,
x86_64, 2 cores, 7 GiB):

```
GATE_EXIT=0 — 30 lane lines: 29 PASS, 1 SKIP, 0 FAIL
  SKIP: e2e-devnet (needs ANTSEAL_GATE_E2E=1)
  test lane: 2 871 tests
```

**30 lane lines over 28 distinct names** — `features` and `format-freeze` each
print twice. The wave-21 close recorded the *preceding* run as *"29 lanes: 26
PASS"*; recounted from the log it was **30 lines, 27 PASS, 1 SKIP, 2 FAIL**, and
both homes of that figure are struck and corrected. The finding that run carried
is unaffected: `verifier-page` failed as **R83's guard working exactly as
designed** (the wave moved the module's bytes; the guard named `STALE ARTIFACT`,
rebuilt, and the re-run is green), and `heavy-features` failed on a genuine
**pre-existing** red that no CI job has ever been able to see, because Q153
keeps that lane local-only — minted **U73**, fixed, re-measured 23 passed /
0 failed.

## What this chapter does NOT prove

- **Nothing here was witnessed remotely.** The gate is a local instrument by
  construction; that is not a defect, but it means a push that breaks a lane
  outside the 19 required contexts is found by someone running the gate, or not
  at all.
- **It does not discharge Q19.** The page browser arm is green on this host and
  has still never executed on a hosted runner. The two owed dispatches, their
  binding precondition and their ordering are recorded in the chapter above and
  on Q19's row.
- **It does not discharge Q238.** R86's step remains deploy-gated, and the
  exposure D135 §3 R4.1 names — a reproducibility break sitting between deploys
  for days to weeks — is unchanged by M3 passing.

# Q254/Q65 — the publish flip, as an ordered procedure (2026-08-19, M4 wave 27)

**This is the runbook Q65's `Accept` row 3 names.** Q65 owns the *decision* —
what is public, what is not, and the scrub that precedes it. This chapter owns
the *execution*: which steps, in which order, each with the command that reads
back its own result. D154 §2 R2 records that the two are halves of one act
(`with Q65`), not a queue.

The "Maintainer runbook (remote steps, in this exact order)" earlier in this
file is a **different runbook** and is not superseded: it sequences the first
push and branch protection. Its step 5 has been blocked by plan since wave 7,
and the flip below is one of the three ways that block lifts — see *"Branch
protection is BLOCKED BY PLAN"*. Do not take the flip for that reason. Take it
because Q65 resolved to *public* on its own terms.

## The flip is an external action, and no prior consent carries forward to it

**Nothing in this chapter authorises anything.** Making `aed900/antseal` public
is irreversible in the only sense that matters — the bytes are copyable the
instant they are readable — and it is an external action in the strict sense:
it changes state on a third-party service under a named account.

It therefore requires **express, in-the-moment consent from the maintainer,
naming all three of**:

1. the **action** — "make the repository public";
2. the **destination** — `github.com/aed900/antseal`;
3. the **account** — `aed900`.

**No prior consent carries forward.** A decision recorded in `TODO.md`, a
resolved `Q65`, a planning-round ruling, this chapter, and an agent's own task
brief are **none of them consent**. "Go public after a scrub" (maintainer,
2026-08-16) is the *decision*; the *act* still needs its own confirmation at
the moment it is taken. The same applies to every `PATCH`/`PUT`/`POST` step in
Phase B below: each one writes to GitHub, and consent to the flip is not
consent to the settings changes that share its window — name them together
when consent is sought, and say so out loud if any is dropped.

An agent executing this chapter runs the **read-back** commands. It does not
run the writes.

## Ordering vocabulary — three words, and two of them are not "first"

The defect this chapter exists to close is reading a co-timed step as a
prerequisite. The three markers below are used on every step and mean exactly
this:

| Marker | Meaning | Failure if you get it wrong |
| --- | --- | --- |
| **BEFORE** | Must be complete *and verified* before consent is sought. The flip does not happen until every BEFORE step reads back green. | The thing it guards is exposed at the instant of the flip, with no window to react. |
| **AT THE FLIP (co-timed)** | Cannot be done earlier — the API refuses it while the repository is private — and must not be left for later. Same sitting, same hour, one continuous act. | A window opens in which the repository is public and the setting is not yet true. This is the D140 103-minute false-window class. |
| **AFTER** | Reads back a property that only exists once the repository is public. Verification, not execution. | Nothing is exposed; you simply have no evidence the flip did what it claimed. |

**A co-timed step is not a prerequisite and must never be written as one.**
D154 §2 R2 struck `Q254 after Q242` for exactly this reason: Q242's `Accept`
row 2 requires private vulnerability reporting to read *enabled* **in the same
window as the visibility change**, and the endpoint refuses while private, so
`after` was an edge that could never be satisfied. Measured 2026-08-19, on this
host, with the `aed900` token:

```
$ gh api repos/aed900/antseal/private-vulnerability-reporting
{"message":"Not Found","documentation_url":"https://docs.github.com/rest","status":"404"}
gh: Not Found (HTTP 404)                                    # REAL_EXIT=1
```

That 404 is the mechanism. `SECURITY.md` (9 690 B, landed) ships naming a route
that does not resolve, and the gap between flip and enable is a window in which
the only disclosure route for a cryptographic verifier is a public issue.

## How to read the observation status on each step

Every step carries one of two tags, and the distinction is the point of the
row:

- **[OBSERVED 2026-08-19]** — the command was run on this host, against this
  account, and the output shown is what it printed. Exit codes are recorded as
  `REAL_EXIT=` read back from a file, never inferred from a pipeline's status.
- **[UNOBSERVED — <reason>]** — the command is stated with what it *should*
  return, and it was **not run**. Two reasons occur: the step needs the
  repository already public, or it is a write no agent may take. An unobserved
  expectation is a prediction. Treat a mismatch as new information about
  GitHub, not as a failure of the step.

## Phase A — BEFORE. Every step here reads back green before consent is sought

### A1 — BEFORE. Q65's own remaining `Accept` rows are discharged

This chapter is Q65's execution half, not its substitute. Its `Accept` rows 1,
2, 5 and 6 are separate obligations and none of them is satisfied by writing a
checklist.

**[CORRECTED 2026-08-22 by D161 §2 R8 — this step names a row that does not
exist, and it has been stale in a second way since the day it was written.]**

1. **There is no `Accept` row 6.** `Q65` has exactly **five** top-level
   `Accept` bullets, and D156 §2 R5 says so in its own words (*"this row's
   five `Accept` rows"*). The list above appears to skip row 3 correctly —
   `Q254` owns it — and then run one high; read it as rows **1, 2, 4 and 5**.
   This is the **sixth** silent count drift of the class the tracker header
   tracks, and it is the one that sits in a file a maintainer reads aloud at
   the flip.
2. **Rows 1 and 5 are now DISCHARGED**, by `docs/decisions/D161-what-the-flip-publishes.md`
   — the classification record (ruled **per class**, because the flip
   publishes history and the per-file function is a constant) and the D61 §9
   re-read ((a) FALSE, measured; (b) FALSE). Row 2 was already green under
   D144 §2 R1. **Row 4 is satisfied vacuously** — its antecedent is *"if the
   answer is 'stay private indefinitely'"* and the answer is public — and
   **row 3's ordering conjunct is already stated** (`Q254`'s checklist landed).
   **What actually remains at the flip is row 3's *"executed before any
   visibility change"* deadline** plus the `Do`'s finding-4 settings items,
   which are B3-B5.

```bash
grep -nE '^- \[.\] \*\*Q(65|242|243|244|254|255)\*\*' TODO.md | cut -c1-60
```

**[OBSERVED 2026-08-19]** — `REAL_EXIT=0`, six rows:

```
825:- [ ] **Q65** (M) Publish-scope decision + the pre-publ
830:- [ ] **Q242** (S) **A cryptographic verifier invites a
831:- [x] **Q243** (S) **The job that publishes the devnet
832:- [x] **Q244** (S) **Nine third-party actions, fifty-se
833:- [ ] **Q255** (S) **The Pages action set is two years
845:- [ ] **Q254** (S) **The publish flip has no ordered ex
```

Expected **at the flip**: `Q65`, `Q242`, `Q243`, `Q244`, `Q254` all `[x]`.
`Q255` may still be `[ ]` — see B6, which records that exposure rather than
closing it.

**[RE-MEASURED 2026-08-27, wave 31.]** `Q242` is now **`[x]`**, and it was
*landed-and-unticked* rather than unfinished: `securityPolicyUrl` reads
`https://github.com/aed900/antseal/security/policy` with
`isSecurityPolicyEnabled: true`, `SECURITY.md` is at the repository root and
linked from `README.md:255`, the issue-template set carries a private-advisory
contact link with `blank_issues_enabled: false`, and `SECURITY.md` is a literal
`COPY_SCAN` entry so the policy is positioning-linted every run. Its one open
clause — private vulnerability reporting **enabled** — is unsatisfiable before
the flip by construction and is **B2**, carried as a `🟡` residue on the ticked
row with B2 and the Maintainer-actions block named as its live owners. So the
row list above now reads: `Q242`, `Q243`, `Q244`, `Q254` **`[x]`**; `Q65`
**`[ ]`**, ticking in this sitting; `Q255` `[ ]` by permission.

**Two rows joined the pre-flip set this wave and neither is `Q65`'s**, so read
them here rather than discovering them at B0: **`Q266`** (the history scan is
now a script, and nothing runs it — the flip publishes history, and the only
prior scan was a dated document already stale by 504 objects) and **`Q268`**
(the scrub reports put the maintainer's personal address into the history they
were certifying clean — 15 blobs, 4 paths, all live in `HEAD`; accept or
rewrite, and there is no rollback after the flip). Neither blocks the flip by
ruling; both are things a maintainer should have decided **before** it rather
than after. The two Q65 obligations that this file cannot see are the per-file
`public`/`private`/`private-until-release` decision record and the two
registered `OWED_PRESENCE` clauses (`limit-exclusive-possession`,
`compelled-disclosure`), which are **Q22's** and not this row's; both are
tracked and neither reddens a checker, so **read them, do not grep for a
failure that cannot arrive**.

**[CORRECTED 2026-08-22 by D161 §2 R8. The sentence above has been stale since
the day it was written, and it names one obligation too many.]** The two
`OWED_PRESENCE` clauses were **discharged 2026-08-19** by `Q22`'s lane, which
wrote both clauses into `README.md` and deleted both register entries in one
act. D150 §2 R6's own anchored predicate settles it and is re-measured at every
registration — **`0` is the value that permits the flip**:

```bash
python3 scripts/check-copy-style.py | grep -c '^check-copy-style: registered debt'
```

**[OBSERVED 2026-08-22]** — returns **`0`**, with the flagless run at
`REAL_EXIT=0`. So **one** obligation was invisible to this file, not two — and
that one, the classification record, is itself now discharged by D161 (see the
correction at the head of this step). With the register empty the check has
changed direction as well: an unstated required clause no longer has an entry
to excuse it and is a **finding**, so *"neither reddens a checker"* is now
historical for this half.

### A2 — BEFORE. The machine-path lint is green on the live surface

Q65 `Accept` row 2, as amended by D144 §2 R1. The check is the **flagless**
run; `--machine-paths` is the narrow arm and `--self-test` stages a full tree
copy and must not be run mid-wave.

```bash
python3 scripts/check-traceability.py
```

**[OBSERVED 2026-08-19]** — `REAL_EXIT=0`, all eight checks ok. The line that
matters here:

```
[machine-paths] ok — 0 absolute home paths outside the reserved vocabulary
(user, fixture, runner, u, x) across 455 live file(s) in 14 scan root(s);
1 registered divergence(s) still present verbatim and exactly once (MVP-SPEC.md)
```

Read the numbers, not the word `ok`: the scan-root count and the live-file
count both move as the tree grows, and a scan that silently stopped covering a
directory would still print `ok`. **This lint does not buy confidentiality**
and Q65 says so itself — `/home/deb` is already in the published history at
`01cdc83` and at `format-v1-freeze`. What it buys is machine-independence of
live instructions.

### A3 — BEFORE. All three scrub halves exist and are committed

```bash
ls -l docs/reviews/pre-public-scrub-*.md
```

**[OBSERVED 2026-08-19]** — `REAL_EXIT=0`, three files:

```
47278  docs/reviews/pre-public-scrub-github-side.md
27644  docs/reviews/pre-public-scrub-history.md
33364  docs/reviews/pre-public-scrub-worktree.md
```

Zero credential findings in all three. **They are dated documents, not live
guards**: the worktree half's own figures were stale by the commits that landed
it. A2 is the live check; these are the record of the sweep.

### A4 — BEFORE, strictly. Q243's evidence-artifact gate is in the publishing job

The `devnet-e2e-evidence` artifact becomes publicly downloadable at the instant
visibility changes, so the gate that proves its redaction must already be in
the job that uploads it. This is the one ordering in this chapter that D141
§2 R5(a) inverted from an outright backwards edge.

```bash
grep -n 'e2e-devnet.sh' .github/workflows/devnet-e2e-cron.yml
```

**[OBSERVED 2026-08-19]** — `REAL_EXIT=0`:

```
133:        run: ./scripts/e2e-devnet.sh --self-test
163:        run: ./scripts/e2e-devnet.sh
179:        run: ./scripts/e2e-devnet.sh --scan-evidence
```

Both of D141's arms are present: `--self-test` proves the redactor in that
environment before capture, and `--scan-evidence` asserts the **artifact
itself** after capture and before upload — the one that survives a refactor
that stops calling `redact()` at all.

**The existing artifact is not covered by this gate and is kept anyway.**
D145 §2 R2: run `9132238802` predates the gate by five days, was scanned by
hand instead (`files=8 findings=0 verdict=CLEAN`), and is retained. Record that
when the flip is taken; do not claim the gate covers it.

### A5 — BEFORE, strictly. Q244's SHA pins are landed

The mitigations that made mutable action tags tolerable — private repository,
no fork PRs, read-only default token — are exactly what the flip removes, so
the pins precede it.

**[CORRECTED 2026-08-27, wave 31 — this step's command was blind to 11 of the
57 invocations, and the paragraph that noticed the gap explained it away.]**
The command below is the corrected one. The superseded form was

```
grep -rhoE '(^|- )uses: \S+' .github/workflows/ | grep -vE '@[0-9a-f]{40}'
```

which anchors on line-start-or-`- ` and therefore matches only `- uses:` steps
and column-0 `uses:` lines. Every **bare-indented** `uses:` — the continuation
form inside a step block — was invisible to it: `verifier-page.yml:124,138`,
`pages.yml:85`, `ci.yml:677,694,723`, `fuzz-nightly.yml:93,121,166`,
`devnet-e2e-cron.yml:247`, `advisory-cron.yml:63`. All eleven are pinned today,
so the step **read green by luck**, and `pages.yml:85` is `actions/deploy-pages`
— the highest-blast-radius invocation in the tree. The check could not have
reddened on any of them.

The old paragraph noticed the discrepancy and drew the wrong conclusion from
it: it read the gap between its own **46** and `Q244`'s **57** as the row being
stale, and told the reader to *"verify by running the command, never by quoting
the row"*. The row was right. It then named the mirror-image bug — that
`^\s*uses:` alone misses every `- uses:` step — while carrying exactly the
inverse of it. Its fault plant used the `- uses:` form only, so the blind spot
was **un-plantable by construction**, which is why a proved-able-to-fail claim
sat over it for eight days. **[assertions-that-cannot-fail.]**

```bash
grep -rhoE '^[[:space:]]*-?[[:space:]]*uses: \S+' .github/workflows/ |
  grep -vE '@[0-9a-f]{40}'
```

**[OBSERVED 2026-08-27]** — prints **nothing**; `REAL_EXIT=0` from the first
element of the pipeline read back via `PIPESTATUS[0]`. Counts: **57** `uses:`
invocations across **8** workflow files, **57** pinned to a 40-hex commit,
**0** unpinned. That agrees with `scripts/check-action-pins.py`, which is the
authority and reports *"57 `uses:` invocation(s) across 8 workflow(s) … 9
ledger row(s), every one used"*. **Cross-check the two rather than trusting
either**: this step exists so the flip sitting can read a pin count without
running Python, and the eight-day-old version of it disagreed with the checker
by eleven and said the checker was wrong.

**The corrected check is proved able to fail, on the form that defeated the old
one.** Run against a three-line fixture holding one `- uses:` tag reference,
one **bare-indented** tag reference and one SHA reference, the pipeline prints
exactly the two tag lines:

```
- uses: actions/checkout@v4
  uses: actions/deploy-pages@v4
```

### A6 — BEFORE, and it is a branch. Read every signing-key anchor back

**[D153 §2 R8, 2026-08-19. WIDENED 2026-08-22 by `Q262`.]** The publishing act
and the key-publishing act are owned by different rows, and only one of them
knows about the DNS pin. This step exists so the flip cannot become a key's
first publication by accident.

**Until 2026-08-22 this step read `README.md` and nothing else, and it was
complete only by accident.** The verifier page footer had no key element and no
marker pair, so the README was the only place in the tree a key could sit.
`R96` closed that gap — `verifier-web/index.template.html:172-175` now carries
the *same* `minisign-public-key` marker pair — and the footer is the sharper of
the two locations, because the page is **already live and public** at
`https://antseal.org/` while this repository is private. A step that greps one
file misses it. `Q262` owns the widening, and it is a hazard `R96` created
rather than one it found lying there.

#### A6.1 — derive the location list, never transcribe it

`docs/signing/maintainer-key-procedure.md` §5 owns the list of publication
locations and is the only thing that owns it. **Read the list out of §5.** A
fourth location added there must be covered without a second edit to this file,
and a list copied into this chapter would agree on the day it was copied and
drift afterwards — which is the defect this step is a widening of.

```bash
a6_locations() {
  awk '/^## 5\. Publish the key/,/^## 6\./' \
      docs/signing/maintainer-key-procedure.md |
    grep -oE '`[^`]+`' | tr -d '`' | sort -u |
    while read -r t; do
      for p in "$t" "docs/signing/$t"; do
        [ -f "$p" ] && { printf '%s\n' "$p"; break; }
      done
    done | sort -u
}
a6_locations | tee /tmp/a6-locations
```

Every backticked token in §5, resolved against the repository root and against
§5's own directory (`docs/signing/`, for the relative links it writes), kept
if it names a file that exists.

**[OBSERVED 2026-08-22]** — `REAL_EXIT=0`, **7** paths:

```
crates/antseal-wasm/tests/page_template.rs
docs/ci-verification.md
docs/signing/key-custody.md
docs/signing/verifying-a-release.md
README.md
scripts/pages-publish.sh
verifier-web/index.template.html
```

**It is a superset of §5's three numbered items, and the superset is the safe
direction.** `minisign.pub` and `minisign.pub.ots` are named by §5 item 3 and
are **not** in the list: they are release assets, not tree-resident, so `[ -f ]`
drops them and A6 — a check on the tree — has nothing to read. Four files §5
mentions only in prose stay in, and this is deliberate rather than tolerated:
checking them costs nothing and a key pasted into `verifying-a-release.md`,
which §5 itself calls *"the one page a stranger actually follows"*, is exactly
the miss this step exists to prevent. **Narrowing to the numbered items was
refused on measurement**: §5 puts the footer's *file name* in the prose bullet
at `:221-238`, not in item 2, which names the footer by URL. A parser that kept
only the numbered items would drop `verifier-web/index.template.html` — the one
location `Q262` was minted for.

**This chapter is inside its own scanned set.** `docs/ci-verification.md`
appears above because §5's hazard bullet names it. So A6 may quote the markers
— it does, below — but **must never quote a literal key**, or A6.3 goes red on
its own runbook. That is a constraint on this file, stated here because nothing
else will state it.

**Prove the derivation non-empty before scanning anything.** A `grep` invoked
with no file operands reads standard input and hangs, and a derivation that
silently returned nothing would turn A6.2 and A6.3 into checks that cannot
fail. The floor is asserted first, and it names the two locations `Q262`
requires by name:

```bash
grep -qx 'README.md' /tmp/a6-locations &&
grep -qx 'verifier-web/index.template.html' /tmp/a6-locations &&
[ "$(wc -l < /tmp/a6-locations)" -ge 2 ]
echo $? > /tmp/a6-floor ; cat /tmp/a6-floor
```

**[OBSERVED 2026-08-22]** — `0`. **Proved able to fail**: with §5's heading
pattern altered to one that matches nothing, `a6_locations` printed **0** paths
and the floor read `1`.

#### A6.2 — is there a key between any anchor's markers?

Threshold and character set are **taken from `R96`'s own detector**
(`crates/antseal-wasm/tests/page_template.rs`, `longest_base64_run` ≥ 40 over
`[A-Za-z0-9+/=]`) rather than chosen here, so the two cannot drift into
disagreeing about what a key looks like. Forty is a margin below the 56 a
minisign public key actually is; measured 2026-08-22, the longest base64-ish
run inside any live anchor is **23** characters, so there are 17 characters of
headroom and no false red available.

```bash
a6_anchor_scan() {
  local rc=1 f n
  while read -r f; do
    grep -q 'BEGIN minisign-public-key' "$f" || continue
    n=$(sed -n '/BEGIN minisign-public-key/,/END minisign-public-key/p' "$f" |
          grep -cE '[A-Za-z0-9+/=]{40}')
    if [ "$n" != 0 ]; then
      printf 'KEY IN ANCHOR: %s carries a key-shaped run between its minisign-public-key markers\n' "$f"
      rc=0
    fi
  done < /tmp/a6-locations
  return $rc
}
a6_anchor_scan ; echo $? > /tmp/a6-anchor ; cat /tmp/a6-anchor
```

**`1` is the pass and `0` is the finding**, matching `grep`'s convention rather
than this chapter's; the inversion is stated because every other `REAL_EXIT=`
here reads the other way. **[OBSERVED 2026-08-22]** — `1`, and the anchors read
back:

```
README.md
<!-- BEGIN minisign-public-key (docs/signing/maintainer-key-procedure.md §5 step 1) -->
No key is published here yet. The 56-character public key goes between these
two markers when it is published, alongside a pointer to
[checking a download](docs/signing/verifying-a-release.md).
<!-- END minisign-public-key -->

verifier-web/index.template.html
<!-- BEGIN minisign-public-key (docs/signing/maintainer-key-procedure.md §5 step 2) -->
No signing key is published here yet. The 56-character minisign public key
goes between these two markers when it is published.
<!-- END minisign-public-key -->
```

Four of the seven locations carry a marker pair — those two, plus this file and
`page_template.rs`, which quote them. **A location with no marker pair is not a
failure**: `key-custody.md`, `verifying-a-release.md` and `pages-publish.sh`
have none and are not supposed to, which is why A6.3 exists.

#### A6.3 — is there a key anywhere else in those files?

A6.2 can only see between markers. A key pasted into a location that has no
markers — `verifying-a-release.md`'s three placeholders are the live example —
is invisible to it.

```bash
grep -nHE 'RW[A-Za-z0-9+/]{54}' $(cat /tmp/a6-locations)
echo $? > /tmp/a6-outside ; cat /tmp/a6-outside
```

**[OBSERVED 2026-08-22]** — no output, `1`. Again `1` is the pass.

**Why this arm is prefix-anchored where A6.2 is not.** Every minisign public
key is base64 over a 42-byte blob whose first two bytes are the algorithm
identifier, so every one of them begins `RW`; 56 characters total. Outside the
markers these files are full of 64-character hex digests, and each of those
contains a 56-character alphanumeric run — measured 2026-08-22, the unprefixed
pattern reports **5** hits in this file alone, all of them build digests. An
unprefixed whole-file arm is not a check, it is noise. The cost is stated
rather than hidden: **A6.3 would miss a key written without its `RW` prefix**,
which no real minisign key is.

#### Then branch on what came back

- **No anchor carries a key** — the state on 2026-08-22, observed above.
  **Record the read-back and proceed.** The flip publishes no key material and
  D71 §A R4's precondition does not fire.
- **Any anchor carries a key** — then **the flip is that key's first
  publication**, and D71 §A R4 applies to *this* step: the pin's clock starts
  the moment the key is first published, it cannot be retrofitted, and without
  it the scheme's security at first contact reduces to trusting GitHub. The
  TXT record must resolve **first**:

  ```bash
  dig +short TXT antseal.org
  ```

  Expected in that branch: a line containing `antseal-minisign-key=` matching
  the anchor's key. **[OBSERVED 2026-08-19]** — the command returns **no
  output** with `REAL_EXIT=0`. An empty answer and a `NXDOMAIN` both print
  nothing here and both exit 0, so **assert on the string, never on the exit
  code**:

  ```bash
  dig +short TXT antseal.org | grep -q 'antseal-minisign-key=' ; echo "PIN_PRESENT_EXIT=$?"
  ```

  `PIN_PRESENT_EXIT=0` means present; `1` means absent. Today it is `1`.

**This is not a contradiction with D71 §A R5**, which deliberately release-times
the TXT pin and the OTS anchor. Nothing here asks for them early. It asks that
*if* an anchor already carries a key when the flip is taken, the pin precedes
the publication — which is the same ruling read in the other direction.

#### What A6 does not cover, and where the rest of it lives

**A6 is a check on the repository, run once, before one act.** It does not see
the built page. `target/verifier-web/index.html` is what a stranger loads, it
is never committed (D131 §5 R4), and `pages.yml` deploys it on its own schedule
to a URL that is already public — so a key in the footer reaches the world
through a path this step never runs on. That is `Q262`'s second half and it is
built where it belongs, in the publishing script itself:

```bash
./scripts/pages-publish.sh --check-key-anchor
```

`--build` runs it over the artifact it just produced, before anything is
staged. Its scope is the built `<p id="signing-key">` element and **not** the
whole page: measured 2026-08-22, the 2 542 496-byte artifact embeds the wasm
module as one base64 string, in which `RW[A-Za-z0-9+/]{54}` matches **138**
times by chance and the unprefixed 56-run matches **44 474** times. A
whole-page scan is unusable in either form, and the element is 8 lines.

Three further limits, stated so no reader assumes otherwise. A6 does not check
that a key which *is* published is the **right** key — no arm here compares an
anchor against `minisign.pub` or against the pin's value. It does not read the
**live** site, only the tree. And a location added to §5 in a form that is not
a backticked path — a bare URL, say — is derived by nothing and covered by
nothing; §5 item 2 is already that shape and is reached only because the prose
bullet beneath it names the file.

### A7 — BEFORE. D61 §9 is re-read, and the re-read is written down

D61 is **resolved with a condition**, and Q65 is the named owner of its
trigger. The re-read records which of D61 §9's two conditions hold:

- **(a)** `aed900/antseal` is public. **False today** — and it becomes true in
  Phase B, which is why this step is written before the flip and read back
  after it (C3). It reopens the **budget half only**: standard GitHub-hosted
  runners are free on public repositories.
- **(b)** the project can point to use by parties other than its maintainer,
  sufficient to argue OSS-Fuzz's own *"a significant user base and/or be
  critical to the global IT infrastructure"* criterion. **False**, and the flip
  does not change it.

**(a) alone does not reopen the OSS-Fuzz arm.** Until both hold, OSS-Fuzz is
*not applicable* rather than *pending*, and no wave may carry D61 as open on
that account. Write that sentence into the wave record with both verdicts
attached; a re-read that concludes "still closed" is a discharged obligation,
not a skipped one.

The budget half is the part that actually changes, and it changes in the
project's favour: the hosted CI has refused every job since wave 20 on an
exhausted Actions allowance, and free minutes on a public repository is the
mechanism by which that stops. **Do not add any required status context on the
strength of that expectation** — see C2.

**[EXECUTED 2026-08-22 — this step is DONE, and the flip sitting reads it back
rather than re-deriving it.]** The re-read landed as **D161 §2 R7**
(`docs/decisions/D161-what-the-flip-publishes.md`), with `Q65`'s `Accept` row 5
amended at source in `tasks/Q.md` in the same act. Condition **(a)** was
**measured, not assumed**:

```bash
gh api repos/aed900/antseal --jq '.visibility'
```

**[OBSERVED 2026-08-22T08:49Z]** — `private`, `REAL_EXIT=0`. It is a read, not
a state change, and needs no consent. **(b)** is FALSE and the flip does not
change it. Verdict recorded: **OSS-Fuzz is *not applicable* rather than
*pending*** until both hold.

**The timing was contested and is settled**, because reading it the other way
would have made this step premature: D61 §9's trigger takes the **row** as its
subject (*"when Q65 resolves to 'public'"*), while condition (a) takes the
**repository** (*"`aed900/antseal` is public — the Q65-gated flip"*). The
record keeps them apart deliberately, which is why this step is a **BEFORE**
step at all. The trigger fired at the maintainer's 2026-08-16 call.

**This step stays in the checklist.** C3 still reads condition (a) back after
the flip, and that read-back is what makes the *"predicted"* half honest.

### A8 — BEFORE. Push `main` **by name**

```bash
git push origin main
```

**[UNOBSERVED — this is a write to the remote, and no agent may take it.]**
Expected: the remote's `refs/heads/main` advances to the local `main`. Read it
back with the same command that establishes the pre-state:

```bash
git ls-remote origin
```

**[OBSERVED 2026-08-19]** — `REAL_EXIT=0`, four lines and no more:

```
dc0bac80964172ea3a458cc1a495f003a32cd6f0	HEAD
dc0bac80964172ea3a458cc1a495f003a32cd6f0	refs/heads/main
5b72bb0fdfaf4e50ab953c4b0d36d5a12c666e8f	refs/tags/format-v1-freeze
d3345e1622bf4ae8d90d5d02b9e80317c73b7683	refs/tags/format-v1-freeze^{}
```

The remote carries **one branch and one tag**. Locally: `main` is **3 commits
ahead** of `dc0bac8` (waves 25–27), **549** commits total, **36** branches,
**2** tags, and **1** ref under `refs/original`.

**Why this step is before the flip and not after.** The pre-public scrub scanned
*this clone*; publishing a remote whose content is a subset of what was scanned
keeps that coverage true, and it means the repository that becomes public is the
one the scrub describes rather than one that grows into public view commit by
commit. The cost is that the first push still lands on a CI that refuses jobs —
the free-minutes change arrives only with the flip — so **expect no green run
from this step**. The first genuine remote verdict is C4.

#### `git push --all` and `git push --mirror` are FORBIDDEN, and the reason is measured

Not style. Measured on this host, 2026-08-19:

| Local-only object class | Count | On the remote? |
| --- | --- | --- |
| Branches besides `main` | **35** (36 total) | no |
| `refs/original` filter-branch backup | **1** (`refs/original/refs/heads/m2w4-kappa` → `d286d4e`) | no |
| Unreachable commits | **61** | no |
| Unreachable blobs | **83** | no |
| Unreachable trees | **279** | no |
| Unreachable tags | **1** | no |
| Local-only tags | **1** (`pre-trailer-strip-949dd9d` → `949dd9d`) | no |

Going public exposes what the **remote** holds — 533 commits and 3 364 blobs at
the scrub's measurement — **not** the larger set in this clone. Every row above
is local-only **and stops being local the instant anyone runs `git push --all`
or `git push --mirror`**. `--mirror` is the worse of the two: it pushes
`refs/*` entire, including `refs/original` and every tag, **and it deletes
remote refs that are absent locally**, so it is destructive in both directions
against a remote carrying a published freeze tag.

Two specifics worth naming, because the summary hides them:

- **`refs/original/refs/heads/m2w4-kappa`** is a filter-branch backup. Pushing
  it republishes precisely the history a rewrite was taken to remove — it
  undoes the rewrite while leaving the rewritten branch in place, which is
  worse than never having rewritten.
- **`pre-trailer-strip-949dd9d`** points at `949dd9d`, and
  `git merge-base --is-ancestor 949dd9d main` **exits 1** — it is *not* an
  ancestor of `main`. It is a second pre-rewrite line, and `--mirror` publishes
  it. So does the smaller, more tempting `git push --tags`, which is why the
  ban is stated as *push `main` by name* rather than as a list of two flags to
  avoid.

The read-back for the ban is the same `git ls-remote origin` above: after any
push in this procedure it must still print `refs/heads/main` and
`refs/tags/format-v1-freeze` (with its peeled `^{}` line) and **nothing else**.

```bash
git ls-remote origin | awk '{print $2}' | grep -vE '^(HEAD|refs/heads/main|refs/tags/format-v1-freeze(\^\{\})?)$'
```

Expected: **no output**. Any line printed is a ref that should not be there.
**[OBSERVED 2026-08-19]** — no output; the trailing `grep` exits **1**, which is
the clean result and the inverse of the usual convention, so read the *lines*,
not the status. Run against a synthetic list carrying `refs/heads/m2w4-kappa`,
the same filter printed that one line and exited 0 — the check can fail.

### A9 — BEFORE, and it is a branch. `Q238`/`Q265` — the required-context promotion

**[ADDED 2026-08-27 by D164 §2 R4 and §2 R8.]** `Q238`'s headline said the
reproducibility comparison becomes a required push context *"before the
repository goes public"*, and its `Notes` said `Q34` and `Q65` are *"where it
must be checked"*. **Neither of those rows names it back** — `Q34`'s ordering
run is `after Q13,Q21,Q28,Q31–Q33,Q65`, `Q65`'s row names no `Q238`, and the
M4 `Gate =` line names five clauses, none of them this row. That was an
assertion nothing could redden, and under rule 4 the gate is the exit
criterion, so M4 could have passed with the obligation open and silent. **The
gate is deliberately NOT widened.** The check lands here instead, as a step the
flip operator reads in the sitting — a human checkpoint that exists, rather
than a machine one that does not.

**This step is a branch, on the `A6` precedent.** Read it; never expect it:

```bash
gh api repos/aed900/antseal/commits/main/check-runs \
  --jq '.check_runs[] | select(.name|test("repro|reproduc")) | "\(.name) \(.conclusion)"'
```

- **Branch 1 — the context has reported `success` on `main`.** Arming is a
  **Phase A** act: take it here, before `B0`, and the maintainer's *"before
  public"* wish is met literally. Regenerate the payload from
  `scripts/check-ci-paths.py`'s `REQUIRED_CONTEXTS` — **never increment a
  prose copy** (D164 §2 R7; C2's own rule). `Q265` ticks on the read-back.
- **Branch 2 — it has not.** Arming becomes a **Phase C** act tied to `C4`,
  and **the flip proceeds** carrying a recorded exposure in `B6`'s shape:
  dated, owned by `Q265`, and named aloud in the sitting rather than
  discovered afterwards. This is the expected branch today — no hosted job has
  produced a verdict since 2026-08-15.

**Do not arm on the strength of an expectation.** C2's prohibition stands for
the case where nothing has reported. What D164 §2 R2 removed is the *reason*
that prohibition was being read as permanent: the claim that a never-green
required context blocks the maintainer's own push **names no mechanism**, and
this file prescribes `"enforce_admins": false` at `:277` and calls it an
explicit admin bypass at `:292-294`. A **ruleset** has no such implicit bypass.
**Which mechanism is used is undecided and is `Q265`'s first clause** — the two
differ on exactly the case `Q238`'s lane shape creates, and nothing in this
register has ever distinguished them.

**This step does not depend on whether the flip restores CI.** D164 §2 R5 rules
that no step may assert either branch of the refusal disjunction; the cut is at
the green-run predicate precisely so that question does not have to be answered
here.

## Phase B — AT THE FLIP. One sitting. Every step here is co-timed, none is a prerequisite

**Read this heading literally.** B1 through B7 are **not** a queue in which B1
must be finished and verified before B2 is attempted on some later day. They
are one act. B1 is first only because the API refuses B2 and B5 until it has
happened, and each hour between B1 and B7 is an hour in which the repository is
public and its hardening is not yet true.

Have every command below open before consent is sought. The read-backs are the
deliverable; run them all again at the end of the sitting.

### B0 — Consent, named. Not a step any agent takes

Before B1: the maintainer states, in the moment, that they are making
**`github.com/aed900/antseal` public** under the account **`aed900`**, and that
the settings writes in B2–B5 are included. Nothing in this file, in `TODO.md`,
in a decision record or in an agent's brief substitutes for that.

```bash
gh auth status
```

**[OBSERVED 2026-08-19]** — `REAL_EXIT=0`. Confirms which account the writes
would run as, and this host has **two**:

```
✓ Logged in to github.com account aed900 (keyring)   - Active account: true
  Token scopes: 'gist', 'read:org', 'repo', 'workflow'
✓ Logged in to github.com account <second-account> (keyring) - Active account: false
```

**Check the active account before every write in this phase.** A second
authenticated account on the same host is exactly how a named-destination
consent gets executed somewhere else.

**[REDACTED 2026-08-27, wave 31, at the maintainer's instruction — `Q268`.]**
The second account's name is replaced by `<second-account>` above. **Do not
restore it**: the check this step prescribes is *"is the active account
`aed900`?"*, and that question is answered by the `Active account: true` line
alone — the other account's name was never an input to it. Read the name off
`gh auth status` live when you run the step; it does not belong in a file that
goes public.

### B1 — AT THE FLIP. The visibility change

Either the web UI (Settings → General → Danger Zone → Change visibility, which
requires typing the repository name — a useful second confirmation), or:

```bash
gh api -X PATCH repos/aed900/antseal -f visibility=public
```

**[UNOBSERVED — this is the flip itself; it is the one act this whole chapter
exists to sequence, and no agent may take it.]**

Read back, and read it back **twice** — once authenticated, once not, because
only the second proves the change is visible to the world rather than to the
token:

```bash
gh api repos/aed900/antseal --jq '{visibility:.visibility,private:.private}'
curl -sS -o /dev/null -w '%{http_code}\n' https://api.github.com/repos/aed900/antseal
```

Expected after: `{"private":false,"visibility":"public"}` and `200`.

**[OBSERVED 2026-08-19 — the pre-state]** — `REAL_EXIT=0` for both:

```
{"default_branch":"main","has_issues":true,"homepage":null,"private":true,"topics":[],"visibility":"private"}
404
```

The unauthenticated `404` is the honest before-picture: GitHub returns `404`
rather than `403` for a private repository, so *"the repo is invisible"* and
*"the URL is wrong"* look identical from outside. After B1 that `404` becomes
`200`, and it is the only read-back in this chapter that does not depend on a
credential.

### B2 — AT THE FLIP, co-timed with B1. Private vulnerability reporting (Q242)

**This is the step the co-timing vocabulary was written for.** Q242's `Accept`
row 2 requires this to read *enabled* **in the same window as the visibility
change**. It cannot be done before B1 — the endpoint refuses — and leaving it
for later opens the window in which the only disclosure route for a
cryptographic verifier is a public issue.

```bash
gh api -X PUT repos/aed900/antseal/private-vulnerability-reporting
```

**[UNOBSERVED — a write, and it is refused while the repository is private.]**
Expected: `204 No Content`. Read back:

```bash
gh api repos/aed900/antseal/private-vulnerability-reporting
```

Expected after: `{"enabled":true}`.

**[OBSERVED 2026-08-19 — the pre-state]** — `REAL_EXIT=1`:

```
{"message":"Not Found","documentation_url":"https://docs.github.com/rest","status":"404"}
gh: Not Found (HTTP 404)
```

**Do not over-read that 404.** It is consistent with *"the feature is
unavailable on a private repository"* and with *"this path does not exist"*,
and from here the two are indistinguishable. If the `GET` still 404s after a
successful `PUT`, confirm in the UI (Settings → Advanced Security → Private
vulnerability reporting) rather than concluding the `PUT` failed.

Q242's **other** clauses do not need the flip, and one of them is already true:

```bash
gh api graphql -f query='{repository(owner:"aed900",name:"antseal"){securityPolicyUrl isSecurityPolicyEnabled}}'
```

**[OBSERVED 2026-08-19]** — `REAL_EXIT=0`:

```
{"data":{"repository":{"securityPolicyUrl":"https://github.com/aed900/antseal/security/policy","isSecurityPolicyEnabled":true}}}
```

`SECURITY.md` is on the remote and GitHub already serves the policy URL, **on a
private repository**. So Q242 splits: its policy half is landed and needs
nothing from this phase, and only the *mechanism* half is co-timed. Do not
carry the row's 2026-08-17 measurement (*"`securityPolicyUrl` empty, no
`SECURITY.md`"*) into the flip — it is stale, and re-running the query is the
whole cost of finding that out.

### B3 — AT THE FLIP, co-timed. `homepage`

Q65 finding 4. `https://antseal.org/` has been live and canonical since D62,
and the repository does not say so.

```bash
gh api -X PATCH repos/aed900/antseal -f homepage='https://antseal.org/'
```

**[UNOBSERVED — a write.]** Read back:

```bash
gh api repos/aed900/antseal --jq '.homepage'
```

Expected after: `https://antseal.org/`. **[OBSERVED 2026-08-19 — pre-state]**
`null`.

Use the canonical form with the trailing slash; the copy-style checker holds
every other spelling of the product URL to be a defect, and the repository
sidebar is a copy surface like any other.

### B4 — AT THE FLIP, co-timed. `topics`

```bash
gh api -X PUT repos/aed900/antseal/topics -f names[]=rust -f names[]=proof-of-existence \
  -f names[]=timestamping -f names[]=merkle-tree -f names[]=autonomi
```

**[UNOBSERVED — a write. The topic list itself is Q65's call, not this
chapter's; what is fixed here is that the field is set in this window and read
back.]** Read back:

```bash
gh api repos/aed900/antseal/topics
```

Expected after: a `names` array matching what was set. **[OBSERVED 2026-08-19 —
pre-state]** `{"names":[]}`, `REAL_EXIT=0`.

Positioning discipline applies to topics exactly as it does to prose: this is
proof of existence, integrity and priority. A topic like `notary` would be a
claim the product does not make, in the one field search engines read first.

### B5 — AT THE FLIP, co-timed. Fork-PR contributor approval, which only becomes queryable now

Q65 finding 4 records this as *unqueryable* rather than merely unset, and the
endpoint name matters — the neighbouring path answers with a different and
misleading status.

```bash
gh api repos/aed900/antseal/actions/permissions/fork-pr-contributor-approval
```

**[OBSERVED 2026-08-19 — pre-state]** — `REAL_EXIT=1`:

```
{"message":"Validation Failed",
 "errors":"Fork PR approval is not allowed for private repositories.",
 "documentation_url":".../permissions#get-fork-pr-contributor-approval-permissions-for-a-repository",
 "status":"422"}
```

That **422**, quoting the reason, is the signal. Its neighbour
`actions/permissions/fork-pr-workflows` returns a bare `404 Not Found` on the
same repository — **[OBSERVED 2026-08-19]**, `REAL_EXIT=1` — which says nothing
about visibility and would be read as "no such setting". Query the
`fork-pr-contributor-approval` path, and treat the disappearance of the 422 as
the confirmation that the flip took effect.

Then set it, in the same window:

```bash
gh api -X PUT repos/aed900/antseal/actions/permissions/fork-pr-contributor-approval \
  -f approval_policy=all_external_contributors
```

**[UNOBSERVED — a write, and it is refused until B1 lands.]** Read back with
the `GET` above; expected `{"approval_policy":"all_external_contributors"}`.

Verify the three hardening settings that are already correct have **not** moved,
since B1 and B3 both `PATCH` the repository object:

```bash
gh api repos/aed900/antseal/actions/permissions/workflow
gh api repos/aed900/antseal/actions/permissions/access
```

**[OBSERVED 2026-08-19]** — `REAL_EXIT=0` for both:

```
{"default_workflow_permissions":"read","can_approve_pull_request_reviews":false}
{"access_level":"none"}
```

Expected after: unchanged. A read-only default token is worth more once the
repository is public than it was before, and a settings write that silently
resets it is the kind of thing only a read-back finds.

### B6 — AT THE FLIP, co-timed. `sha_pinning_required` stays `false`, and that is recorded, not fixed

```bash
gh api repos/aed900/antseal/actions/permissions
```

**[OBSERVED 2026-08-19]** — `REAL_EXIT=0`:

```
{"enabled":true,"allowed_actions":"all","sha_pinning_required":false}
```

Expected after: **the same**. This is a **recorded exposure, not a step to
execute.** A5 established that all 46 `uses:` invocations are already pinned to
40-hex, so the setting is currently weaker than the files — but flipping it to
`true` is gated behind **Q255**, whose action set is stale and whose middle
action carries a transitive moving tag into the only write-scope job. Turning
the enforcement on before Q255 resolves risks blocking the very change that
would fix it.

Write the reading into the wave record with its owner. **Do not tick anything
on the strength of this step** — it asserts that a known-loose setting is still
exactly as loose as it was, which is evidence, not progress.

### B7 — AT THE FLIP, co-timed. The artifacts that become publicly downloadable

```bash
gh api repos/aed900/antseal/actions/artifacts --paginate \
  --jq '.artifacts[] | [.name,.size_in_bytes,.expired,.expires_at] | @tsv'
```

**[OBSERVED 2026-08-19]** — `REAL_EXIT=0` via `PIPESTATUS[0]`, ten artifacts:

```
github-pages           865661  true   2026-08-16T08:02:37Z
devnet-e2e-evidence     52269  false  2026-11-10T06:56:33Z
fuzz-smoke-artifacts       672 false  2026-11-05T09:42:20Z
fuzz-smoke-artifacts      1100 false  2026-11-04T21:46:09Z
fuzz-smoke-artifacts       820 false  2026-11-04T20:36:04Z
fuzz-smoke-artifacts       854 false  2026-11-04T15:45:58Z
fuzz-smoke-artifacts       854 false  2026-11-04T12:16:46Z
fuzz-smoke-artifacts       812 false  2026-11-04T11:47:50Z
fuzz-smoke-artifacts       490 false  2026-11-04T09:30:30Z
fuzz-smoke-artifacts       402 false  2026-11-04T08:45:26Z
```

Q65 finding 4's figures reproduce exactly: **eight** live `fuzz-smoke-artifacts`
totalling **6 004 bytes**, `github-pages` already **expired**, and
`devnet-e2e-evidence` at **52 269 B** retained to **2026-11-10**.

The ruling is **leave them to expire, do not delete them**, and the deletion
endpoint is not in this chapter for that reason. What this step owes is the
record:

- The eight fuzz artifacts are crash-corpus fragments of a few hundred bytes
  each and carry no key material; they expire on their own on 2026-11-04/05.
- **`devnet-e2e-evidence` is the one to read twice.** A4 is why: this artifact
  predates Q243's gate, is covered by a **hand** scan (`files=8 findings=0
  verdict=CLEAN`, D145 §2 R2) rather than by the job, and it becomes publicly
  downloadable at B1. State that in the record — that the coverage is a manual
  sweep on a dated artifact, and that every artifact produced from now on is
  covered by `--scan-evidence` in the uploading job instead.

## Phase C — AFTER. Reading back what only exists once the repository is public

Nothing in this phase exposes anything. Each step reads a property that could
not be read before B1, and a failure here means missing evidence rather than an
open window.

### C1 — AFTER. The ref surface did not grow

The single most consequential thing that can go wrong in this procedure leaves
no trace in any settings API. Re-run the stray-ref filter from A8:

```bash
git ls-remote origin | awk '{print $2}' \
  | grep -vE '^(HEAD|refs/heads/main|refs/tags/format-v1-freeze(\^\{\})?)$'
```

Expected: **no output**, exactly as observed on 2026-08-19. Every ref that
prints here is now world-readable. Run it once immediately after B1 and once at
the end of the sitting, because the flip is precisely the moment someone is
tempted to "push everything while we're here".

### C2 — AFTER. Branch protection is now available, and must still not be armed

The wave-7 block lifts here: *"Branch protection is BLOCKED BY PLAN"* earlier in
this file lists three options, and B1 is option 2. **[OBSERVED 2026-08-19 —
pre-state]**, and note both of these have already moved since that chapter was
written:

```
$ gh api repos/aed900/antseal/rulesets
[]                                                          # REAL_EXIT=0
$ gh api repos/aed900/antseal/branches/main/protection
{"message":"Branch not protected", …, "status":"404"}       # REAL_EXIT=1
```

The 403s that chapter recorded are gone — GitHub un-gated rulesets for private
Free repositories — so the flip is **not** what unblocks protection, and taking
it for that reason would be taking it for a stale reason. `main` is unprotected
today and so is `format-v1-freeze`; the freeze is enforced in-repo by digest
files, not by the platform.

**Do not add a required status context in this sitting.** The prohibition
stands; its stated *reason* does not, and the difference matters because four
surfaces were resting on the reason.

**[QUALIFIED 2026-08-27 by D164 §2 R2. The sentence below is kept because
D163 §1.6, D163 §2 R4, Maintainer actions entry (8) and `Q238`'s `Accept` row 3
all quote it — but it names no mechanism, and this file contradicts it twice.]**
It read: *"A required context that has never reported green on `main` blocks
the next push, including the maintainer's own — and the hosted CI has refused
every job since wave 20 on an exhausted Actions allowance, so no context has a
recent green."*

Two corrections, neither of which reopens the prohibition:

1. **"including the maintainer's own" is unqualified and this file refutes it
   twice.** `:277` prescribes `"enforce_admins": false`, `:292-294` says that
   *"leaves the repo admin an explicit bypass for emergencies"*, and `:1216`
   says it *"leaves the admin a bypass regardless"*. Under **classic branch
   protection with that flag**, an admin push is **not** blocked. Under a
   **ruleset**, there is no implicit admin bypass at all — a ruleset must grant
   one explicitly. **The register has never distinguished the two mechanisms**,
   and they differ on precisely the case `Q238`'s lane shape creates: a
   docs-only direct push with the promoted context unreported. So *"arming
   early is actively unsafe"* is **UNPROVEN** — which removes the reason to
   defer without supplying any reason to hurry. Deciding the mechanism is
   **`Q265`**'s first clause and is a prerequisite of the write, not a detail
   of it.
2. **"on an exhausted Actions allowance" states one branch of a disjunction as
   fact.** The refusal annotation reads *"recent account payments have failed
   **or** your spending limit needs to be increased"* — see C4. The evidence
   favours the allowance reading, but no step may assert it (D164 §2 R5).

**What survives unchanged, and is the operative instruction:** do not arm a
context that has never reported. The correct order is still runbook step 3 →
step 5 — first a green run on `main` (C4), then protection — and the *reading*
of that order is now **A9**, which carries it as a branch rather than as a
deadline against the flip.

When it is armed, **regenerate the payload rather than copying one**. That
chapter's payload lists 19 contexts from 17 jobs; measured 2026-08-19,
`ci.yml` now declares **15** job ids:

```bash
awk '/^jobs:/{j=1;next} j && /^  [a-z0-9-]+:$/{gsub(/[ :]/,"");print}' \
  .github/workflows/ci.yml | wc -l
```

**[OBSERVED 2026-08-19]** — `15`, `REAL_EXIT=0`. Every hand-maintained context
list in this file has gone stale at least once; that is the whole of Q56.

### C3 — AFTER. D61 §9's condition (a) now holds in fact

A7 wrote the re-read with `(a)` predicted. Read it back against the world:

```bash
gh api repos/aed900/antseal --jq '.visibility'
```

Expected: `public`. Then the re-read reads: **(a) holds**, **(b) does not**,
therefore **OSS-Fuzz remains *not applicable* rather than *pending***, and only
the budget half of D61 reopens — on its own merits, in its own wave, not here.
A wave that carries D61 as open on the strength of (a) alone is carrying it
wrongly.

### C4 — AFTER. The first CI run that a hosted runner actually executes

**[QUALIFIED 2026-08-27 by D164 §2 R5 — the sentence below is a PREDICTION,
and it is labelled as one because D161 §2 R7's own rider says *"the expectation
is not a measurement"*.]** *Free minutes on public repositories is the mechanism
that ends the refusal streak* — expected, not established. Three things are
measured and they do not settle it:

- **The refusal annotation is a DISJUNCTION and cannot discriminate.** Verbatim
  from the check-run annotation on run `33083210871` (2026-08-27): *"The job was
  not started because recent account payments have failed **or** your spending
  limit needs to be increased. Please check the 'Billing & plans' section in
  your settings"*. GitHub emits the same bytes for a failed payment and for an
  allowance spent behind a $0 spending limit.
- **The evidence favours the allowance reading.** Last run with a runner:
  `31873411737`, 2026-08-15. D135 §1.1 measured ~3 154–3 324 weighted minutes
  against a 3 000 allowance over 2026-08-01→15; refusals begin 2026-08-16. That
  is a mid-cycle exhaustion signature.
- **But a billing-side action alone has already cleared this, with no flip.**
  The byte-identical annotation appeared on run `31407751482` on 2026-08-10, and
  the same day a 1 589 s run succeeded at 22:05 — repository still private. So
  the flip is demonstrably **not the only route**, and Maintainer action **(9)**
  routes the cheap one: check the Actions spending limit first, because it is
  free and reversible and the flip is neither.

**In a genuinely delinquent-payment state it is not established that the flip
helps at all**, and no read-only endpoint reachable with this host's scopes
distinguishes the two states (`/user/settings/billing/actions` → **404**, not
403; `gh api /user --jq .plan` → **`null`**). Do not record the streak as ended
because the repository went public; record it as ended when a runner produces a
verdict. Confirm with a **verdict**, not with a queued job:

```bash
gh api "repos/aed900/antseal/commits/$(git rev-parse main)/check-runs" \
  --paginate --jq '.check_runs[] | [.name,.status,.conclusion] | @tsv' | sort
```

**[UNOBSERVED — needs a run on a public repository; on this account today every
job is refused.]** Expected: one row per context, `completed` with `success`.

**The refusal signature is what to watch for, and it is not an error message.**
A refused job reports `conclusion: failure` with an empty `steps` array, in
3–5 seconds, having never reached a code verdict. Confirm the run took a
plausible wall time and that its steps are non-empty before calling the streak
over:

```bash
gh run list --limit 5 --json databaseId,conclusion,createdAt,updatedAt
```

Until a run passes that test, the local gate remains the only witness this
project has, and every gate claim in this file keeps saying so.

### C5 — AFTER. One block, run again, at the end of the sitting

Every read-back in this chapter, in one place, so the closing record is a single
capture rather than a reconstruction:

```bash
set -o pipefail
{
  gh auth status
  gh api repos/aed900/antseal --jq '{visibility:.visibility,private:.private,homepage:.homepage,topics:.topics}'
  curl -sS -o /dev/null -w 'anon_http=%{http_code}\n' https://api.github.com/repos/aed900/antseal
  gh api repos/aed900/antseal/topics
  gh api repos/aed900/antseal/private-vulnerability-reporting
  gh api repos/aed900/antseal/actions/permissions
  gh api repos/aed900/antseal/actions/permissions/workflow
  gh api repos/aed900/antseal/actions/permissions/access
  gh api repos/aed900/antseal/actions/permissions/fork-pr-contributor-approval
  gh api repos/aed900/antseal/actions/artifacts --paginate \
    --jq '.artifacts[] | [.name,.size_in_bytes,.expired,.expires_at] | @tsv'
  git ls-remote origin
} > flip-readback.txt 2>&1
echo "REAL_EXIT=$?" >> flip-readback.txt
```

Then **read `REAL_EXIT=` back out of the file**. The exit status a harness or a
terminal reports is the status of the *last* command in the wrapper, which here
is `echo`; it has announced `0` for runs that exited `1` and `101`. Paste the
captured file into the wave record — a measurement that lives only in a
transcript is not evidence.

## What this checklist does NOT cover

- **It does not decide anything.** The per-file `public` / `private` /
  `private-until-release` record is Q65's, the topic list is Q65's, the
  disclosure policy's contents are Q242's, and the pin renewal cadence is
  Q244's. This chapter sequences acts whose content is decided elsewhere.
- **It does not authorise the flip**, and it is not evidence of consent. See
  B0.
- **It says nothing about reversing the flip.** Making a repository private
  again does not un-copy anything, does not remove forks, and does not retract
  a downloaded artifact. There is no rollback step in this chapter because
  there is no rollback.
- **It does not cover releases, packages, or `crates.io`.** Release assets
  inherit repository visibility (D72 §2 R6) and change status at B1, but the
  release process itself is Q31/Q34's and the publication scope of the crates
  is D72's.
- **It does not cover the Pages deployment.** `https://antseal.org/` is already
  public and served from this repository; the flip changes the visibility of
  the *source*, not of the page. `github-pages` as an artifact is already
  expired (B7).
- **It does not cover history rewriting.** The scrub's history half measured
  that none is warranted. If that verdict ever changes, this chapter is the
  wrong instrument — a rewrite against a published freeze tag is its own
  decision.
- **It does not arm branch protection** (C2), **does not set
  `sha_pinning_required`** (B6, behind Q255), and **does not delete any
  artifact** (B7, ruled expire-not-delete).
- **Seven of its steps were never executed.** A8, B1, B2, B3, B4, B5 and C4
  carry expectations, not observations; each is tagged `[UNOBSERVED]` with its
  reason at the step, and the count is checkable without counting this sentence:
  every step-level tag opens its own line, so
  `grep -c '^..\[UNOBSERVED' docs/ci-verification.md` returns **7** while the
  legend entry and this paragraph, which are indented, do not. Six of the seven are
  writes no agent may take; C4 is a read that has no public repository to read
  yet. Every pre-state around them was measured on 2026-08-19 on this host with
  the `aed900` token, and **a pre-state is not a result**.
- **The read-backs are only as good as the moment they were run.** Q242's own
  row carried a 2026-08-17 measurement that this chapter found stale two days
  later (B2), Q244's invocation count moved from 57 to 46 (A5), and `ci.yml`'s
  job count moved from 17 to 15 (C2). Re-run every command; quote no figure
  from a row.
