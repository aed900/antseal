# D171 — `Q255`'s held term is re-decided: the default-setup A2 acceptance **stands**, because cache write on `main` is ambient to every job and replacing default setup would close none of it; the exposure D169 §2 R4 named is re-scoped to the one job whose output is served, and **a job that publishes or signs bytes restores no Actions cache**

- **Status: RESOLVED. The orchestrator's lean fell on its remedy while both of its
  technical premises held.**
  - **Cargo does not re-verify anything already on disk** — measured, not read.
    A poisoned `registry/cache/*.crate` (valid gzip, sha256 different from
    `Cargo.lock`'s checksum), a poisoned extracted `registry/src/*` tree marked
    `.cargo-ok`, and a poisoned dependency artifact in `target/` were each compiled
    or linked **silently, exit 0, under `--offline`, `--locked`, `--frozen` and plain
    builds**, and the binary ran the poison. §1.1.
  - **A cache entry written by another workflow can satisfy `pages.yml`'s restore
    key** — with two corrections: entries are immutable per key, so the existing
    `publish` entry cannot be overwritten, and benign cross-workflow consumption does
    not happen because the key carries the job id. The openings are adversarial only:
    the restore-key prefix fallback, the first deploy after a `Cargo.lock` or
    toolchain change, and LRU eviction. §1.2.
  - **The remedy the lean proposed — revoke the acceptance and replace default
    setup — is MIS-TARGETED.** §2 R4's first reopen trigger rests on default setup
    becoming *"the last A2-exposed code on `main` with cache write"*. **Measured
    false**: every job that runs on `main` holds the runtime token that creates cache
    entries, whatever its `GITHUB_TOKEN` scope, so `reproducible-build.yml`, `ci.yml`
    and `ci-always.yml` are cache writers exactly as default setup is. Replacing
    default setup closes none of the path. The exposure is **`pages.yml` restoring a
    cache inside the job whose bytes are served**. §1.3.
  - **The mitigation D169's addendum feared was weak is weaker than it feared**: the
    deploy job's two-environment comparison is blind to a poisoned `.crate` **and** to
    a poisoned build-tool binary restored into `~/.cargo/bin`, because build B copies
    build A's registry and shares A's `$PATH` tools. It catches a poisoned extracted
    tree and a poisoned `target/`. §1.4.
- **Date: 2026-09-15**
- Owner rows: **`Q255`** (its held `Accept` term is discharged by §2 R1; the row
  ticks), **`Q274`** (minted with this record: the deploy job restores a cache any
  `main` job can write, and cargo trusts cached crates without re-verifying them —
  owns §2 R3's witness and §2 R4), **`Q31`** (inherits §2 R5 before any release
  workflow is written).
- Related: **D143** (adversary A2; §5.1 *"pinned by a cache key, not by a digest"*;
  §5 *"the Actions cache is a cross-job channel the permissions table does not
  describe"*), **D169** §2 R4 and its 2026-09-13 addendum (the question), **D135**
  §5 R3 and **D168** (the two-environment comparison and its no-network fence),
  **R86**, **D166** (the unwitnessed release workflow).

## 0. What was measured against

`HEAD` `3473ab2` (== `origin/main`). Planning lane P5 (wave 36) ran a throwaway
cargo project entirely inside the session scratchpad — its own `CARGO_HOME` and
`CARGO_TARGET_DIR`, `cargo 1.92.0 (344c4567c 2025-10-21)` (the repository's pinned
toolchain), one dependency `itoa = "=1.0.15"` — read cargo's source at that commit,
read `Swatinem/rust-cache` at the SHA `pages.yml` pins, read GitHub's cache
documentation and the published cache-poisoning research, and read the job log of
the one recent deploy with read-only API calls. Nothing in the repository or its
`target/` was touched. The orchestrator re-read `pages.yml:83` (the cache step, no
`with:`) and `scripts/reproducible-build.sh:381-383` (build B's `cp -a` of build A's
`registry/cache` and `registry/index`) before this record was written.

## 1. What was measured

### 1.1 Three cache layers, three silent trusts (cargo 1.92.0)

Baseline: pristine cache, fresh target, `build --locked --offline` → exit 0, the
binary prints `42`. The `.crate`'s sha256 equalled `Cargo.lock`'s checksum
`4a5f13b8…8e2c`.

| layer poisoned | flags | cargo output | exit | binary prints |
|---|---|---|---|---|
| `registry/cache/itoa-1.0.15.crate` (sha `48b878b1…`, valid gzip), extracted tree and `target/` deleted | `--offline`, `--locked`, `--frozen`, `--locked --offline`, plain | `Compiling itoa v1.0.15` / `Finished` | 0 | `P5-SILENT-POISON` |
| extracted `registry/src/…/itoa-1.0.15/src/lib.rs`, `.cargo-ok` present, fresh `target/` | `--locked --offline`; `--locked` with network | `Compiling itoa v1.0.15` | 0 | `P5-SRC-TREE-POISON` |
| `target/` built from the poisoned tree; registry made pristine again | `touch src/main.rs` | `Compiling p5probe` only — `itoa` not recompiled | 0 | `P5-SRC-TREE-POISON` |

No warning, no checksum message and no re-download in any mode. **The mechanism, at
cargo's own commit `344c4567c634a25837e3c3476aac08af84cf9203`**:
`src/cargo/sources/registry/download.rs:53-63` returns any non-empty file at the
tarball path as ready without consulting the checksum; the only sha256 comparison
(`download.rs:110-121`, *"Verify what we just downloaded"*) runs on bytes that
arrived over the network; `mod.rs:602-620` uses an extracted tree whose `.cargo-ok`
reads `{"v":1}` as-is; and `mod.rs:941-942` makes a registry unit's fingerprint its
version string, which is why a warm `target/` is trusted with no reference to the
registry at all.

**A trap for whoever re-runs this, recorded because it would produce a confident
wrong witness**: the one "checksum" message cargo printed in the whole campaign was
`archive header checksum mismatch` — a flip in the middle of the archive, caught by
**tar's 8-byte header checksum**, a corruption detector, not `Cargo.lock`'s sha256.
A grep for `checksum` over that output returns a match. A flip in the gzip trailer
was not detected at all. And the lane's first loud plant was malformed and failed on
an unrelated `rustc` error — judged by exit code it would have "proved" the plant;
judged by message it did not.

### 1.2 What `pages.yml` restores, under what key, from whom

`Swatinem/rust-cache@6323deb102c322ba6fcbdcafc7e3dddab59af2b6` (v2.9.2), read at that
SHA. With no `with:`, it caches `CARGO_HOME/registry`, `CARGO_HOME/git`,
**`CARGO_HOME/bin`** (`cache-bin` defaults true) and the workspace `target/`
(`src/config.ts:265-277`); on save it deletes `registry/src/*` except `-sys` crates
and keeps the `.crate` archives (`src/cleanup.ts:99-160`). The key is
`v0-rust-${GITHUB_JOB}-${os}-${arch}-<envhash8>-<lockhash8>` and the restore key drops
the lock hash (`src/config.ts:69-264`, `:133`); restore verifies nothing about the
bytes (`src/restore.ts:41-56`). For `pages.yml`'s `publish` job every input is public
since the flip, and the two eight-hex hashes are low-entropy.

GitHub's documentation (dependency-caching reference, read 2026-09-15): *"Workflow
runs can restore caches created in either the current branch or the default
branch"*; *"You cannot change the contents of an existing cache"*; a restore key
returns *"the most recently created cache"* among partial matches; no
`actions: write` is required to create one. Published research (A. Khan, *The
Monsters in Your Build Cache*, 2024): the runtime token issued to **every** job
*"grants cache write access regardless of `GITHUB_TOKEN` permissions"*; existing
entries cannot be overwritten with it, deleting one needs `actions: write`, and
GitHub's late-2024 mitigation stops writes after the originating job ends — not
writes from a live compromised job.

The one recent deploy, `pages.yml` run `34782645736`: the cache restore took **1 s**
and printed **`No cache found.`**; `build and check the page` took **4 m 26 s**
cold; the post step saved the first `v0-rust-publish-…` entry.
**[Corrected in place before this record landed, 2026-09-15, by the lane implementing
it.]** As first written this paragraph concluded *"the cache bought the deploy
nothing"*. **That is false for a warm deploy, and D135 §1.4 had already measured it**:
run `31873422229` got a full-match restore (289 MB), skipped both `cargo install`s, and
its build step took **1.8 min against 8.4 min** cold — 335 s of a 452 s step. That run
used exactly the `~/.cargo/bin` tool layer §1.4 shows the comparison is blind to, so the
finding strengthens §2 R3; it changes only the ruling's stated cost.

### 1.3 Cache write on `main` is ambient

`reproducible-build.yml` (push to `main`, no path filter) and `ci.yml` restore and
save `rust-cache` on `main`; `ci-always.yml` and CodeQL default setup run on `main`
(`code-scanning/analyses` → `ref=refs/heads/main`, 2026-09-14). **[Corrected in place
before this record landed, 2026-09-15: as first written this sentence also said
`ci-always.yml` restores and saves `rust-cache` — it has zero cache-action steps (measured:
`ci.yml` 16, `fuzz-nightly.yml` 3, `advisory-cron.yml` 2, one each in the other three).
The conclusion is unchanged, because the runtime token that creates cache entries does not
depend on a job having a cache step.]** Every one of those jobs holds the runtime token,
none holds `actions: write` (the repository's
`default_workflow_permissions` is `read`, D143 §1.2), so all are equal **new-key**
writers and none can delete. D169 §2 R4's trigger (1) premise — *"default setup then
becomes the last A2-exposed code on `main` with cache write"* — is **false**, and it
was false when written: the other writers existed then.

### 1.4 Whether a poisoned cache reaches the served page

`publish`: checkout → `rust-cache` restore (`pages.yml:83`) →
`pages-publish.sh --build` (`:85`) → `wasm-tools-provision.sh` →
`wasm-pack-build.sh --check` (build A) → `reproducible-build.sh --compare` (build B)
→ package. `wasm-tools-provision.sh` skips `cargo install` when a binary on `$PATH`
reports the pinned `--version`, and a poisoned binary can print any version.

| restored layer poisoned | build A | build B | comparison |
|---|---|---|---|
| `registry/cache/*.crate` | uses it | re-extracts the **same** copied archive | **green — blind** |
| `registry/src/*` tree | uses it | re-extracts from the archive, clean | red — caught |
| `target/` | uses it | its own fresh `target` | red — caught |
| `~/.cargo/bin` tool | uses it | the **same** `$PATH` tool | **green — blind** |

The poisoned bytes would be the ones `SHA256SUMS` and the page's self-published
footer digest describe.

## 2. RULING

### §2 R1 — The default-setup A2 acceptance is RE-AFFIRMED, and `Q255`'s held term is discharged

D169 §2 R4's acceptance stands on its three original reasons, which remain true. Its
reopen trigger (1) fired and is answered here: the exposure it named is real, but it
is not reduced by replacing default setup, because the cache→deploy path is open to
every job on `main` (§1.3). The trigger's premise is recorded as **measured false**,
by a dated addendum on D169, never by rewriting it. Triggers (2)–(4) stand unchanged.
**`Q255` ticks**: its `Accept` rows 1–4 were witnessed by run `34782645736`, and the
one held term is this re-decision.

### §2 R2 — The exposure is re-scoped and gets its own row

The defect is **`Q274`**: the deploy job restores an Actions cache that any live job
on `main` can create entries in, cargo consumes a poisoned entry silently, and the
job's two-environment comparison is blind to two of the four layers. It is a defect
of `pages.yml` and of what the comparison is claimed to prove, not of CodeQL setup.

### §2 R3 — `pages.yml`'s `publish` job restores no Actions cache

The `Swatinem/rust-cache` step is **removed** from `publish`. With no restored cache
every crate is downloaded and checked against its checksum (`download.rs:110-121`),
and `wasm-bindgen-cli`/`wasm-pack` are installed with `cargo install --locked
--version`, so the registry, `target/` and tool layers leave the served path at once.
Measured cost: **zero** on the only recent deploy (the restore found nothing and the build
was cold), and **about 6.6 minutes** on a warm one (D135 §1.4: 1.8 min against 8.4 min,
almost all of it the two tool installs) — paid on a job that runs by hand, to take the
served bytes off a cache any `main` job can write. **Refused**: keeping the cache behind a post-restore digest gate
(checking every `.crate` against `Cargo.lock` and pinning the tool binaries' sha256)
— it still trusts an extracted tree and `target/` unless those are also disabled, and
it buys a warm deploy a few minutes on a job that runs by hand. The change is a
behaviour change to a live deploy path, so `Q274` stays open until a consented
`workflow_dispatch` of `pages.yml` witnesses it: the log shows no cache step, the tools
installed, and the served bytes equal to the build's digest.

### §2 R4 — The comparison's claim is scoped to what it checks

`reproducible-build.sh`'s two environments vary the checkout path and `CARGO_HOME`;
they do **not** vary crate provenance or build tools, and D135 §5 R3's no-network
fence is why. That is a sound design for the property the lane exists to prove — no
builder path reaches the artifact — and an overstatement wherever it is read as a
supply-chain defence. The script's header comment and the reproducibility section of
`docs/ci-verification.md` say so in one sentence each: *reproducible given the pinned
crate set and the pinned tools; crate provenance on the served path rests on cargo's
download-time checksum, which §2 R3 guarantees by restoring no cache.* D168 and R86
take a dated addendum saying the same. **Not ruled**: a build B that re-downloads
and re-verifies the registry — it trades away the fence for a property §2 R3 already
delivers on the served path; `Q274` carries it as a refused alternative.

### §2 R5 — A job that publishes or signs bytes restores no Actions cache, checked mechanically

The property is stated for the class, not for one file, because `Q31`'s release job
is the next member: **any job granted `pages: write`, `contents: write` or
`id-token: write` contains no step using `Swatinem/rust-cache` or `actions/cache`**
(nor `actions/cache/restore`). A committed checker asserts it over every workflow,
**prints how many such jobs it examined**, and fails naming the workflow, the job and
the step. Today it examines exactly one job (`pages.yml` `publish`); a count of zero
is a failure, not a pass.

### §2 R6 — What stays accepted, stated so it is not read as absent

Jobs that neither publish nor sign — `ci.yml`, `reproducible-build.yml`, `fuzz-nightly.yml`,
`advisory-cron.yml` and the rest — keep their caches. A poisoned entry there can turn a
verdict green, never a served byte. The one cross-check that would notice a poisoned
comparison is R97's, which compared the live module to `reproducible-build`'s: a
divergence between the served digest and the required context's digest is a signal,
recorded as detection, not prevention. Reopen triggers: any such job starts producing
bytes the project publishes or signs; GitHub changes who can create cache entries; a
cache-poisoning incident is disclosed for any action this repository runs.

## 3. Fault plants

Owed by the CI lane, each judged by its message: re-add the `rust-cache` step to
`publish` (the checker reds naming `pages.yml`, `publish` and the step); add
`actions/cache/restore` instead (same red — the class, not one action); grant
`contents: write` to a job that restores a cache in a scratch copy of a workflow (red
naming that job); an empty workflow set (the examined-job count is zero, red). Green
control: the real tree, examined-job count exactly **1**.

## 4. What this record does NOT decide

- The literal eight-hex environment and lock hashes of `publish`'s key — the
  composition was read, not reproduced.
- Default setup's cache behaviour beyond D169 §1.7's measurement (its workflow is
  GitHub-managed and not in the tree).
- The exact cost on the next deploy — D135 §1.4 measured a warm build at 1.8 min
  against 8.4 min cold; `Q274` records the first post-change dispatch's build time.
- Whether release assets from `Q31`'s future workflow need a digest gate beyond §2 R5.

## 5. Edit list — per write scope, with the lane named before this record was written

### L-CI (the CI lane, exclusive owner of every file `check-ci-paths.py --self-test` rewrites)
- `.github/workflows/pages.yml` per §2 R3; `.github/action-pins.tsv` and
  `scripts/check-action-pins.py` wherever a `rust-cache` count or literal moves.
- The §2 R5 checker (its home chosen by the lane, with a self-test that stages
  nothing in the live tree) and its `scripts/local-gate.sh` lane, plus any
  `scripts/check-ci-paths.py` edge it needs.
- `scripts/reproducible-build.sh`'s header comment and `docs/ci-verification.md`'s
  reproducibility section per §2 R4.

### Registrar — `TODO.md`, `tasks/Q.md`, `docs/decisions/README.md`, `docs/instrument-ledger.md`, dated addenda
- Tick `Q255` per §2 R1; mint `Q274` per §2 R2; `Q31` Notes per §2 R5.
- Dated addenda on `D169` (§2 R4 re-decided here, trigger (1)'s premise false), `D168`
  and `D135` (§2 R4's scope sentence) — and on `D135` §5 R1, whose *"build A may use the
  job's cache"* this record supersedes (found by the implementing lane).

### L-CI (phase 2, added by the implementing lane's report)
- `scripts/pages-publish.sh`'s prose still describing a cache save in `publish`, and the
  new checker's entry in `scripts/lib/red-arm.sh`'s register.
- `docs/instrument-ledger.md`: tar's header checksum is the only checksum message
  cargo prints for a corrupt cached archive and is not `Cargo.lock`'s sha256; D169
  §2 R4's trigger premise was false when written.
- Index row and register row for this record.

## Closing — this record is not consent

It changes no setting and dispatches nothing. §2 R3's witness is a `workflow_dispatch`
of `pages.yml` on `main`, which redeploys `https://antseal.org/`; it needs the
maintainer's express consent naming that action, the destination
`github.com/aed900/antseal` and the account `aed900`.
