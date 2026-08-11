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
