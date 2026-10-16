# D182 — wasm-pack's update check is **suppressed**, because a hermetic page build may not reach the network; a tool-lockfile advisory lane and a tool pin bump are **refused**

- **Status: RESOLVED. The question put to planning is answered and the lane it implied is refused.
  The route to the one reachable advisory turned out to be a defect in its own right, and that defect
  is now a row.**
  - **The question.** Do the wasm tools' own lockfiles carry advisories, and does any of them reach
    us? The 2026-10-15 consented-acts note left it open: *"`cargo install --locked` of the two wasm
    tools compiles their OWN lockfiles' `rustls` … whether any advisory applies to those versions was
    not measured"*.
  - **The answer.**
    - RUSTSEC-2026-0285, 0346, 0348 and 0349 match each tool's own `rustls` (0.23.40 in wasm-pack
      0.15.0, 0.23.41 in wasm-bindgen-cli 0.2.126).
    - `rustls-webpki` 0.103.13 matches nothing.
    - Only 0285 is reachable, and it has no confidentiality or integrity impact.
    - wasm-bindgen-cli's `rustls` never runs in our use.
  - **The way 0285 is reached is itself the defect.**
    - On every invocation, before parsing its arguments, wasm-pack 0.15.0 asks crates.io for its
      latest version. Only a stamp less than 24 h old, sitting next to its executable, skips the
      call; `--mode no-install --no-opt` does not.
    - That is network access during the build, which D63 §5 R5 prohibits. It happens in the job that
      holds `pages: write` and `id-token: write`.
    - `wasm-pack-build.sh:13` calls the build *"HERMETIC"* without knowing about it.
    - This host's stamp records a successful call 40 s after `c36949f`.
  - **Suppress, not accept.** The other arm was to accept the call with a D63 addendum and a
    corrected header. It is not taken.
  - **Two refusals, on yield.**
    - A tool-lockfile advisory lane would be red from its first run, with 9 vulnerabilities and 9
      warnings (1 reachable, 0 with impact), and nothing we can do would turn it green.
    - A tool pin bump has nowhere to go. No newer wasm-pack exists, and wasm-bindgen-cli 0.2.129 only
      reduces 5 vulnerabilities to 4 while moving D18's coupled crate pin.
- **Date: 2026-10-16**
- Owner rows: **`Q276`** (minted with this record for the update check; §2 R1, R2 and R4).
- Related:
  - **D63** §5 R5 (*"any network access during the build"* is prohibited; D63 takes a dated
    addendum);
  - **D18** (the `wasm-bindgen` crate pin the CLI must equal);
  - **R22** (the 2026-08-12 measurement behind `--no-opt` and `--mode no-install`);
  - **D171** and **`Q274`** (the same `publish` job, its cache removed and its deploy witnessed);
  - **`Q275`** (the same `rustls` advisories on antseal's own graph, assessed LOW);
  - **D19** (cargo-deny is the advisory lane's only tool).

## 0. What was measured against

`HEAD` `fbcee1e`.

Planning lane P4 (wave 37):
- downloaded the published crates and checked them: each `.crate`'s sha256 equals the index
  `cksum` (wasm-pack 0.15.0 `a5368ae4…`, wasm-bindgen-cli 0.2.126 `8e2ebf6e…`), and ureq 2.12.1 and
  rustls 0.23.40 equal their lock checksums;
- ran cargo-audit 0.22.1 over the published lockfiles, against advisory-db `edb58f5974b8`
  (2026-10-14);
- read the sources and this host's stamp.

No build was allowed, so whether either suppression mechanism works is not established.

Before this record was written, the records lane re-read:
- from that download, `wasm-pack-0.15.0/src/main.rs:25-100` and `src/manifest/mod.rs:149-250`;
- the stamp on this host;
- `scripts/wasm-pack-build.sh:1-31,123-146` and `scripts/wasm-tools-provision.sh:44-77`;
- `.github/workflows/pages.yml:44-47,109`.

## 1. What was measured

### 1.1 The update check

- **It starts before anything is parsed.** `run()` opens with `background_check_for_updates()`
  (`main.rs:61`), which spawns a detached thread (`:25-43`) before `Cli::parse()` runs. No flag can
  reach it.
- **A single stamp file next to the executable decides whether the call is made.**
  - `manifest/mod.rs:149-170` reads `current_exe().with_extension("stamp")` (`:212-219`).
  - If there is no stamp, or its `created` value is older than 24 h, it GETs
    `https://crates.io/api/v1/crates/wasm-pack` through `ureq` 2.12.1 → `rustls` 0.23.40
    (`:237-250`). The agent honours proxy variables (`try_proxy_from_env(true)`).
  - **If the stamp's `created` value does not parse, the check returns `Ok(None)` and never makes
    the call** (`:155-166`).
- **Every attempt rewrites the stamp, whether it succeeds or fails** (`:172-184`: *"We always
  override the stamp file with the current time"*). Reading the stamp back therefore tells "never
  tried" from "tried". A failed check only warns: the build still exits 0.
- **It ran on this host.** The `wasm-pack.stamp` beside this host's executable reads
  `created 2026-10-15T12:09:05.684534780+01:00` / `version 0.15.0`. That is a successful call made
  40 s after `c36949f` was committed (12:08:25+01:00), consistent with wave 36's close build.
- **Hosted jobs make the call.**
  - `pages.yml`'s `publish` job holds `pages: write` and `id-token: write` (`:44-47`) and builds at
    `:109`. It restores no cache (D171), so it starts with no stamp and always makes the call.
  - `ci.yml`'s `test` job (`verifier-page-build.sh --build-only`, `:225`), `reproducible-build.yml`
    (`:95-97`) and `verifier-page.yml` run wasm-pack too. They make the call unless a restored cache
    happens to bring a stamp less than 24 h old.
- **The first wasm-pack process in each of those jobs is `--version`.**
  - `wasm-tools-provision.sh`'s `have` (`:47`, called at `:66` and `:77`) and `wasm-pack-build.sh`'s
    `installed` (`:126`, called at `:141`) each run `wasm-pack --version` before `wasm-pack build`
    (`:231`).
  - Each such process spawns the check's thread before clap prints the version and exits.
  - Whether such a process sends anything before it exits is **not established**.
- **The script's header knew about one network path, not two.**
  - `wasm-pack-build.sh:13-31` says *"The build is HERMETIC, and both flags are load-bearing"*.
  - That header records a measurement from 2026-08-12 (R22): with every proxy variable pointed at a
    dead port, `wasm-pack build --release` still downloaded and ran a `wasm-opt` (binaryen 117).
    `--no-opt` and `--mode no-install` closed that path.
  - Nothing else reaches the network: `install/mod.rs` finds wasm-bindgen 0.2.126 on `PATH`
    (`Status::Found`).

### 1.2 The tools' own lockfiles

cargo-audit over the published lockfiles:

| tool | vulnerabilities | warnings |
| --- | --- | --- |
| wasm-pack 0.15.0 | **4** | **2** |
| wasm-bindgen-cli 0.2.126 | **5** | **7** |
| wasm-bindgen-cli 0.2.129 | 4 | 5 |

The four `rustls` advisories, by reachability:
- **RUSTSEC-2026-0285** is reached on every handshake of the update check. The advisory says the
  transcript stays authenticated, so there is no confidentiality or integrity impact.
- **RUSTSEC-2026-0346** has no venue: ureq uses rustls' built-in session store (`rtls.rs:126-132`).
- **RUSTSEC-2026-0348** has no venue: neither lockfile's `rustls` enables `brotli`.
- **RUSTSEC-2026-0349** has no venue: `ring` offers only X25519, P-256 and P-384
  (`crypto/ring/mod.rs:179-180`), so there is nothing hybrid to downgrade.

wasm-bindgen-cli 0.2.126's fifth vulnerability is crossbeam-epoch RUSTSEC-2026-0204. The four in
0.2.129 are all on its `rustls` 0.23.45: 0346, 0347, 0348 and 0349. 0347 affects exactly
0.23.44–0.23.45 (`Q275`). The records lane read these per-id lists from P4's audit output.

wasm-bindgen-cli uses ureq only in `src/wasm_bindgen_test_runner/headless.rs`, which our build never
runs. On `HEAD`'s own lockfile, cargo-audit's extra quinn-proto and derivative hits are lock-only
(`cargo tree -i` → *nothing to print*), and the pinned cargo-deny reports `advisories ok`.

### 1.3 What a lane or a bump could change

- A lane over the two published lockfiles would report 9 vulnerabilities and 9 warnings, 1
  reachable and 0 with impact. It would be red from its first run, and only upstream could make it
  green.
- No wasm-pack newer than 0.15.0 exists.
- wasm-bindgen-cli 0.2.129 carries 4 vulnerabilities against 0.2.126's 5, and it would move the
  crate pin that D18 couples to the CLI (`dependency-policy.md` §5).

## 2. RULING

### §2 R1 — `Q276` is minted (P4 B R1)

The row records the defect: wasm-pack 0.15.0 GETs crates.io's API on every page build unless a stamp
under 24 h old sits next to the executable. This is network access that D63 §5 R5 prohibits. It
happens in the job that holds `pages` and `id-token` write, and it is the only runtime path to the
tools' own `rustls` (RUSTSEC-2026-0285 is reachable, with no impact).

### §2 R2 — Suppress, never accept (P4 B R1, ruled)

- `scripts/wasm-pack-build.sh` arranges that the update check **never runs**.
- The lane measures and picks the mechanism. One candidate is a stamp next to the wasm-pack
  executable whose `created` value does not parse (`manifest/mod.rs:158-166`); another mechanism is
  equally acceptable.
- Whatever the mechanism, it is asserted **by reading the stamp back after a build**.
- If achievable, the lane also makes a one-time local proof that the page build completes inside a
  network namespace whose only interface is `lo`, with a warm cargo cache.
- `wasm-pack-build.sh:13`'s *HERMETIC* claim is corrected to say what is now enforced.

Accepting the call is refused.

### §2 R3 — No tool-lockfile lane, and no tool pin bump (P4 B R2–R3)

- A tool-lockfile advisory lane is refused. It would be red from day one, and we cannot fix it
  (§1.3).
- A tool pin bump is refused. No newer wasm-pack exists; wasm-bindgen-cli 0.2.129 only goes from 5
  vulnerabilities to 4, and it moves D18's pin.

### §2 R4 — One policy line (P4 B R4)

`docs/dependency-policy.md` §5 gains one line: a wasm-tool pin bump audits the tool's published
lockfile and records each match with its reachability.

## 3. Fault plants

Every plant is judged by the stamp's bytes, never by the build's exit status. A build that never
tried and a build whose attempt failed both exit 0 (§1.1). Save the host's real stamp before the
first plant and restore it exactly after the last.

- **Red.** With the suppression off and the stamp aged past 24 h (or absent), a full
  `wasm-pack-build.sh --build-only` moves `created`.
- **Green.** With the suppression on, the same build leaves the stamp `cmp`-identical.
- **The namespace proof, if achievable.** Inside a loopback-only namespace with a warm cache, the
  page build exits 0 and writes the module. That shows the build needs no network. Only the stamp
  read-back shows that it does not try: an attempt inside the namespace fails, warns, rewrites the
  stamp, and still exits 0.

## 4. What this record does NOT decide

- **The mechanism.** The lane picks it, by measurement. Where a stamp-based suppression writes is
  part of that choice: the stamp lives beside the executable, in cargo's install directory, outside
  the repository, on a hosted runner and on a developer's machine alike.
- **Whether a `wasm-pack --version` process sends anything before it exits.** If it does, the
  suppression must be in place before the first wasm-pack process of any kind.
  `scripts/wasm-tools-provision.sh` runs first in every hosted job, and it is in no lane's write
  scope this wave (§5).
- **The hosted witness.** `pages.yml`, `ci.yml` and `reproducible-build.yml` run the change only on
  a push or a dispatch, so the first hosted run of the suppression waits for consent.
- **The reachability of crossbeam-epoch RUSTSEC-2026-0204 inside wasm-bindgen-cli.** Not
  established, and moot under §2 R3.

## 5. Edit list — per write scope, with the lane named before this record was written

### L-TOOL — `scripts/wasm-pack-build.sh`

- The suppression, its stamp read-back assertion and the corrected header (§2 R2). The namespace
  proof's result is recorded in the lane's report.

### DOCS — `docs/dependency-policy.md`

- The new §5 line (§2 R4).

### Orchestrator — `TODO.md`, `tasks/Q.md`, `docs/decisions/README.md`, dated addenda

- Mint `Q276`.
- D63: a dated addendum on §5 R5 that names the update check as a second network path and records
  that §2 R2 suppresses it.
- The index row and the register row.

### Conditional, no lane named — `scripts/wasm-tools-provision.sh`

- Only if L-TOOL measures a `--version` process reaching the network: the same suppression, in
  place before that script's first `wasm-pack` call. The orchestrator either names a lane before the
  edit or records why none is needed.
- *[Discharged in place by the orchestrator, wave 37, before this record was first committed.]*
  L-TOOL measured it reaching the network: with no network, a bare `wasm-pack --version`
  completed a call attempt before it exited in 1 of 20 runs. The orchestrator took the edit itself:
  - `wasm-pack-build.sh` gained a mode, `--suppress-update-check`, that only writes the stamp and
    prints its path. The stamp keeps one writer and one text.
  - `wasm-tools-provision.sh` calls it before its first `wasm-pack` process and again right after
    `cargo install wasm-pack`, and reads the stamp back after its last one.
  - `scripts/check-ci-paths.py` moves the provision → build edge from `UNREACHED_EDGES` to
    `FOLLOW_EDGES`.

  Proven with stubs on `PATH`:
  - an honest stub over an aged stamp is suppressed, exit 0;
  - a stub that rewrites its stamp on every run is refused by message, *"… moved while provisioning:
    a wasm-pack process called crates.io …"*, exit 1;
  - with no `wasm-pack` on `PATH`, no stamp is written.

  `check-ci-paths` passed, flagless and in its self-test, with the seven files it rewrites hashed
  identically before and after. `check-ci-shell` also passed.

## 6. As built — wave 37, lane L-TOOL (recorded in place before this record was first committed)

- **The mechanism is the stamp.** Before its first `wasm-pack` process, `scripts/wasm-pack-build.sh`
  writes `<wasm-pack executable>.stamp`, whose `created` cannot be parsed. The path is `readlink
  -f` of the `wasm-pack` on `PATH`, plus Rust's `with_extension("stamp")`; a symlink was used to
  check that it matches `current_exe`. After the build the script asserts the stamp is
  byte-identical, which shows wasm-pack made no crates.io call. The *"HERMETIC"* header is corrected
  to what is enforced, and `--self-test` gained a fourth arm for the read-back.
- **Both directions, judged by the stamp's bytes.** Measured on a scratch copy of the binary, in a
  network namespace with only loopback:
  - an aged stamp plus a real build moved `created`, so a call was attempted;
  - the suppression stamp stayed unchanged across a build and 20 `--version` runs.
- **The page build ran with no network.** It was built from a `git archive` of `fbcee1e` inside
  `unshare -rn`, with `CARGO_NET_OFFLINE=true` and a warm cargo cache. It exited 0 in 170 s, the
  stamp was unchanged, and the module was byte-identical (`b9f84e3d…`) to the in-tree build of the
  same commit.
- **Two writes outside the tree.** The stamp lives beside the binary, in `~/.cargo/bin` for a
  `cargo install`ed wasm-pack, and it outlives the run. The next local gate replaces this host's
  2026-10-15 stamp, which recorded a real call, with the suppression text. That is intended.
- **Not suppressed, documented.** A cold runner still downloads the locked crates during the build:
  `pages.yml` restores no cache. Enforcing it would need a `cargo fetch --locked` step before the
  build and offline mode during it, which changes the publish job. That is a ruling of its own, not
  this record's (`Q279`).
- **Not established.** No hosted run has witnessed the stamp's path on a runner, the read-back, or
  whether a bare `--version` on a fresh runner puts a request on the wire. Offline, only call
  completions were observed.

## Closing — this record is not consent

It changes a build script and a policy document. Its hosted witness needs the maintainer's express
consent naming the act: either a push, or a dispatch of `pages.yml`, which redeploys the live page.
