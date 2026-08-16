# D136 — What Q19's page-verification lane actually is, now that playwright is refused

- **Status: RESOLVED — the register's lean SURVIVES on its trigger and is
  OVERTURNED on the word that mattered. The lean is "`workflow_dispatch`-only,
  unchanged." The trigger is confirmed on measured cost. "Unchanged" is
  refused, because the lane as committed CANNOT GO GREEN ON A HOSTED RUNNER
  and never could have.**
  **The lane has never run on the remote — zero runs, measured today**
  (`gh run list --workflow verifier-page.yml` returns `[]`; the workflow is
  registered and active as id `334668690`). That alone is the Q153/R82 class.
  What the measurement then found is worse and more useful: **the reason it
  would fail is not the one anybody wrote down.** The workflow's own header
  premise is **correct** — `ubuntu-latest` really does carry `/usr/bin/chromium`
  (`install-google-chrome.sh` ends `ln -s $chromium_bin /usr/bin/chromium`), so
  the browser was never the exposure. **The exposure is a missing step:
  `verifier-page.yml` never installs `wasm-pack` or `wasm-bindgen-cli`, the
  hosted image ships neither, and `scripts/wasm-pack-build.sh:133` and `:142`
  `die` when either is absent.** `pages.yml`'s header says the provisioning is
  done "by `cargo install`, **which no other job does**" — that sentence is
  true, and it is the bug. The first thing a hosted run would actually produce
  is earlier still and worse: on a cold checkout `target/wasm-pack/` is empty,
  so `verifier-page-build.sh --check`'s **first** command crashes with an
  unhandled node `ENOENT` stack trace (measured), and the `if: failure()`
  artifact step then uploads **nothing**, because its path
  `target/verifier-web/` does not exist and `if-no-files-found: ignore`.
  **Three of Q19's `Do` clauses are false, not one.** Beyond playwright (D133),
  the page is loaded from **`file://`**, not "served from localhost"; and the
  endpoint-disagreement case runs by **CDP `Fetch.fulfillRequest`
  interception**, not "against local stub endpoints". Q19 ships by naming all
  three, on the R19/R23 precedent.
  **R25's Accept row 3 rests on a comparison that cannot be made.** Measured
  in this tree: the footer renders `page build
  f49ce3fd89a8049f87514817592fc8b39e53a094b87d9ab9923c94c782c5d017`, which is
  the SHA-256 of the **module**; `SHA256SUMS` publishes
  `04a1920a07c567b1e00fc0bb29c189a60e9e8b1493e7089484a5fd586fd2d932
  index.html`, the SHA-256 of the **page**. They are different objects, they
  can never be equal, and a page cannot contain its own hash. The row is
  corrected to a **two-link chain** and the browser arm is ruled its
  instrument — for the half no static check can reach.
  **One of the brief's own premises is stale and is corrected here**: the
  advice-line drift test R25 and `TODO.md` both record as *"does not exist"*
  **exists**, at `crates/antseal-wasm/tests/page_template.rs:145`, reading
  `MVP-SPEC.md` rather than a copied literal. That file carries **six** tests,
  not the five on record.
  **Cost, measured rather than estimated.** One `ci` push run is **83.7
  weighted minutes** across 19 jobs — recomputed from run `31873411737` today,
  matching the brief exactly. **30 `ci` runs since 2026-08-01** project to
  **~5 000 weighted minutes/month** against Pro's 3 000 included, so the
  maintainer's constraint is quantitatively right and no per-push job is
  affordable. The inversion that decides the trigger: **a dispatch-only lane
  is always a COLD lane**, and cold is measured — the first-ever `pages` run
  cost **8.30 min**, the second, nine hours later, **1.72 min**.
- **Date: 2026-08-15** (M3 page wave, D136 lane; briefed to overturn the lean
  rather than confirm it. Every figure below was executed in this working tree
  or read from this repository's own Actions history today: two full local
  `--check` runs, three isolated browser drives, one deliberate probe of the
  cold-checkout failure path, and read-only `gh` queries. Nothing was
  dispatched — no Actions minute was spent by this lane.)
- **Owning task: Q19.** Consumers: **R27** (the assertions this venue carries),
  **R25** (Accept row 3, closed here by construction), **Q237** (the M3 gate's
  machine-naming constraint), **R86** (the two-runner witness, adjacent and
  untouched).
  Builds on **D129** (§5 R9 assertion 8 and its self-routing to "R27/Q19's
  venue"; §5 R7/R8 on the footer digest and the served manifest), **D133** (the
  materialised fixture, §5.4's gate constraint), **D131** (§9.2's
  self-test-then-lane pairing; §3 R8 (d) and §4, which are where the refusal of
  Playwright is actually *numbered* — D129 states it only as a method note),
  **D132** (route off `verify_rendered(b).plan`), **Q153** (the cheap-lane
  precedent, and the requirement that the evidence be a remote run id),
  **Q43** (`docs/ci-verification.md:1080`, the never-run-on-the-remote rule),
  **Q234** (pre-image assertion on a planted fixture), **R83** (the stale-artifact
  guard, whose behaviour under a warm `target/` is measured here for the first
  time).
  **Boundary: this record rules the VENUE. It does not write R27's assertions,
  does not touch `testdata/`, does not change any trigger by itself, and does
  not authorise a dispatch — enabling or running the workflow is the
  maintainer's act, named in §2 R6 as a precondition rather than performed
  here.**

---

## 1. What was measured

Every subsection below is a command run in this tree at `d8ce569` today, or a
read-only query against this repository's Actions history, or a read of
upstream `actions/runner-images` source. Where something is taken on report it
says so in the sentence that uses it.

### (a) The lane has never run on the remote. Not once.

```
$ gh run list --repo aed900/antseal --workflow verifier-page.yml \
    --limit 20 --json databaseId,conclusion,createdAt,event
[]
```

The workflow is not missing and not disabled — `gh workflow list --all` shows
`verifier-page  active  334668690`, registered alongside `pages` (`334668689`),
its sibling from the same commit. It is committed, reviewable, syntactically
live, and **entirely unwitnessed**.

`docs/ci-verification.md:1080` states the rule this triggers, verbatim:

> **A lane that has never run on the remote is not evidence, no matter how
> long it has been committed.** Neither is a guard whose own command has
> never been executed.

Q43's incident is the near-precedent and its cure was to move logic out of
inline `run:` blocks into scripts that can be executed locally.
`verifier-page.yml` already complies with that cure — its one substantive step
is a script call, and that script runs green here. **This lane is the first in
the repository whose defect the cure does not reach**, because the defect is
not a wrong command inside a script. It is a **missing step in the YAML**, and
a missing step is invisible to every local execution of the script that step
was supposed to prepare for. §6 item 1 records that as a general finding.

### (b) `ubuntu-latest` DOES carry `chromium` on `PATH`. The workflow's premise is correct.

The brief expected this to be the exposure. It is not. From
`actions/runner-images`, `images/ubuntu/scripts/build/install-google-chrome.sh`
(read via `gh api`, current `main`), the last three lines before its test
invocations:

```sh
ln -s $chromium_bin /usr/bin/chromium
ln -s $chromium_bin /usr/bin/chromium-browser
```

with `chromium_bin="${CHROMIUM_DIR}/chrome-linux/chrome"` and
`CHROMIUM_DIR="/usr/local/share/chromium"`. `Ubuntu2404-Readme.md` corroborates
at the version level: *"Google Chrome 151.0.7922.108, ChromeDriver
151.0.7922.77, **Chromium 151.0.7922.0**, …"*. The installer is shared across
the Ubuntu images rather than per-version, so the finding survives
`ubuntu-latest` moving from 24.04 to 26.04.

`scripts/verifier-page-browser.sh:47` defaults `BROWSER="${ANTSEAL_BROWSER:-chromium}"`,
so the `/usr/bin/chromium` symlink is exactly the name it needs. **The
workflow's header comment — "`ubuntu-latest` ships a usable chromium" — is
true, and it is the only load-bearing environmental claim in that file that
is.**

One caveat, recorded because it is cheap to record and expensive to discover:
the image's **own** test suite (`images/ubuntu/scripts/tests/Browsers.Tests.ps1`)
asserts `chromium-browser --version` and **not** `chromium`. Both symlinks are
created, only one is guarded upstream. If the unguarded one is ever dropped,
upstream's tests stay green and this lane exits 2. §2 R7 pins the name for
that reason.

The driver also needs node ≥ 22 for global `WebSocket`
(`verifier-page-browser.mjs:32`). The image lists **Node.js 22.23.2** — above
the floor, but at its own major. Recorded, not a finding.

### (c) The real defect: the workflow never installs the two pinned wasm tools, and the image has neither.

`scripts/wasm-pack-build.sh::check_toolchain` is unconditional and fatal:

```sh
have_bindgen="$(installed wasm-bindgen)"
[ -n "$have_bindgen" ] || die "wasm-bindgen-cli is not on PATH. Install the pinned one: cargo install wasm-bindgen-cli --locked --version ${want_bindgen}"
...
have_pack="$(installed wasm-pack)"
[ -n "$have_pack" ] || die "wasm-pack is not on PATH. Install the pinned one: cargo install wasm-pack --locked --version ${want_pack}"
```

`die` is `exit 1` (`wasm-pack-build.sh:103`).

`Ubuntu2404-Readme.md`'s Rust Tools section lists **Cargo, Rust, Rustdoc,
Rustup, Rustfmt** and nothing else; neither `wasm-pack` nor `wasm-bindgen-cli`
appears anywhere in the image manifest.

`.github/workflows/verifier-page.yml` has five steps — `checkout`, `rustup show`,
`Swatinem/rust-cache@v2`, `./scripts/verifier-page-browser.sh --check`, and the
failure artifact upload. **There is no `cargo install` step.**

`scripts/pages-publish.sh:53-65` is where the provisioning actually lives:

```sh
if [ "$(wasm-bindgen --version 2>/dev/null | awk '{print $2}')" != "$bindgen" ]; then
  cargo install wasm-bindgen-cli --locked --version "$bindgen" || return 1
fi
if [ "$(wasm-pack --version 2>/dev/null | awk '{print $2}')" != "$pack" ]; then
  cargo install wasm-pack --locked --version "$pack" || return 1
fi
```

and `pages.yml`'s own header names the asymmetry without noticing it is a
defect: *"it provisions wasm-bindgen-cli and wasm-pack by `cargo install`,
**which no other job does**."*

`Swatinem/rust-cache@v2` does not rescue this. Its cache key includes the job
name; `verifier-page.yml`'s job is `browser` and `pages.yml`'s is `publish`, so
they never share a cache — and the `browser` key has never been written,
because the job has never run.

### (d) The first failure is earlier than (c), and it is a raw stack trace.

On a cold checkout `target/wasm-pack/antseal-wasm/` does not exist.
`verifier-page-build.sh::cmd_check` runs the packaging self-test **before**
`cmd_build`, so the toolchain check in (c) is never reached. Probed directly:

```
$ node scripts/verifier-page-pack.mjs --self-test /nonexistent/pkg verifier-web/index.template.html
node:fs:440
    return binding.readFileUtf8(path, stringToFlags(options.flag));
                   ^
Error: ENOENT: no such file or directory, open '/nonexistent/pkg/antseal_wasm.js'
    at readFileSync (node:fs:440:20)
    at selfTest (file:///home/deb/Documents/code0/scripts/verifier-page-pack.mjs:273:16)
EXIT=1
```

So the hosted run's log would end in `node:fs:440` — **no `::error::`
annotation, no mention of wasm-pack, no mention of the page**. A maintainer
enabling this lane gets a red job whose visible cause is a filesystem error in
a self-test, and would have to reverse-engineer that the actual cause is a step
that was never written.

The ordering, stated once so no implementer re-derives it: `command -v chromium`
**passes** (b) → the pack self-test **crashes** (d) → the toolchain `die` (c) is
never reached → the browser is never launched.

### (e) The failure artifact is empty, and would be useless if it were not.

The workflow uploads `path: target/verifier-web/` with
`if-no-files-found: ignore`. In the (d) failure that directory **does not
exist**, so the step succeeds having uploaded nothing and the job's only
diagnostic is the stack trace.

Even after a green build, that directory holds exactly two files, measured:

```
index.html    2 516 397 B
SHA256SUMS           77 B
```

No screenshot. No log. No event dump. Not even the fixtures — those live in
`target/verifier-web-fixtures/`, a **different** directory the artifact path
does not cover. So the uploaded "failure artifact" is a 2.5 MB copy of a page
that is byte-reproducible from the commit under test (R25/R86), carrying **zero
bits of information about why the run failed**. This is the assertions-that-
cannot-fail class wearing an artifact's clothes.

### (f) The exit-2 SKIP branch the script's own header describes does not exist.

`scripts/verifier-page-browser.sh:31-36` says:

> **Exit 2 means "no browser on THIS machine"** … A visible SKIP locally …
> Q19's lane is local-only by the maintainer's ruling, so a developer without
> a browser must not be blocked by it — **but the workflow that CAN run it
> passes `--check`, where absence is a hard failure.**

The code has no such branch. Lines 49-53 are **top-level**, above the `case`
that dispatches on `$1`:

```sh
command -v "$BROWSER" >/dev/null || {
  printf '::notice::%s is not installed — the browser arm cannot run here.\n' "$BROWSER" >&2
  ...
  exit 2
}
```

`--check` and `--self-test` get identical treatment. The distinction the
comment draws is a fiction. The behaviour is not *wrong* in CI — exit 2 is
nonzero, so a hosted run would go red rather than silently skip, which is the
right polarity — but it goes red **under a `::notice::` annotation**, so the
log presents the cause as informational while the job fails. The comment must
be corrected to describe the code (§2 R7); the code's polarity is fine.

### (g) The cost of the lane, priced from this repository's own runs.

`pages.yml` is the only comparable job: same runner, same toolchain step, same
rust-cache, same wasm build, same page packaging. Its two runs, from
`gh api .../jobs`:

| run | date | job wall | step 5 "build and check the page" |
| --- | --- | --- | --- |
| `31847839638` | 2026-08-14 22:45 | **498 s = 8.30 min** | 452 s |
| `31873422229` | 2026-08-15 08:01 | **103 s = 1.72 min** | 55 s |

The first was the first-ever `pages` run, so its rust-cache was empty and it
paid both `cargo install`s. The second ran 9 h 16 m later against a warm cache
and paid neither. **The delta between them — 395 s — is almost entirely the two
`cargo install`s**, which is the same provisioning this lane is missing and
must gain.

What differs for `verifier-page`, priced from measurements in (h):

- **minus** the four deploy steps (`configure-pages`, `upload-pages-artifact`,
  `deploy-pages`, `--verify`), together 9 s in the warm run;
- **minus** `wasm-pack-build.sh --check`'s boundary comparison, which
  `pages-publish.sh` runs and `verifier-page-browser.sh` does not (it reaches
  `wasm-pack-build.sh` only through `--build-only`);
- **plus** the fixture materialisation, ~0.7 s warm;
- **plus** the browser drive, **10.34 s** measured.

Net: **~8.5 weighted min cold, ~2.0 weighted min warm.** ubuntu runners carry
a ×1 multiplier, so weighted equals wall here.

### (h) The lane, run green on this machine, and timed.

Two full runs of `./scripts/verifier-page-browser.sh --check`, this host,
2 cores, warm cargo:

- **Run 1 — RED at 35.30 s.** See (i); the failure is real and correct.
- **Run 2 — GREEN at 30.16 s**, `EXIT=0`. Its verdict line:

  ```
  OK: booted offline, 1 request(s) (the page only), zero CSP violations, 12 bundle(s) rendered.
  ```

  with `#build` reading `antseal-core 0.0.0 · formats 1 · source d8ce569a…`,
  all twelve fixtures — the ten F13 cases plus D133's two attested ones —
  reaching `RESULT`.

Isolated, so the marginal cost is separable from the build:

| command | wall |
| --- | --- |
| driver, 12 bundles + `--self-test` | **10.34 s** |
| driver, boot only, no bundles | **2.25 s** |

`scripts/local-gate.sh:505-508` records `verifier-page-build.sh --check` at
**1.49 s / 1.42 s** warm on this same host. So the **marginal** cost of adding
the browser arm to a gate that already runs the page lane is
`1.5 (duplicate build) + 0.7 (fixtures) + 10.3 (drive)` ≈ **12.5 s**. That
figure decides §2 R9.

### (i) The stale-artifact guard reddens on a warm `target/` — measured, and it matters for CI.

Run 1 failed on a **clean tree at `d8ce569` with nothing modified by this lane**:

```
::error::verifier-page-build: STALE ARTIFACT — the module in target/wasm-pack/antseal-wasm was not built from this tree.
  was:   70235b8b6192b983b1d1eb3b926e5e5925257cd806b6763eeb2aff76539403c0
  is:    f49ce3fd89a8049f87514817592fc8b39e53a094b87d9ab9923c94c782c5d017
```

Run 2, immediately after, printed `module unchanged by the rebuild:
f49ce3fd89a8049f…` and went green. So the red was a **stale `target/`**, not a
non-reproducible build — R83's guard doing precisely its job, and the first
recorded observation of it firing on real drift rather than on a planted fault.

The CI consequence is not hypothetical. `stale_guard` is a no-op when `before`
is empty, so a **cold** runner is safe. A runner whose `target/` was restored
from a **previous commit's** cache is in exactly Run 1's position: the restored
module was built from a different tree, the rebuild produces different bytes,
and the lane goes red with `STALE ARTIFACT` for a reason that is not a defect
in the page. Whether `Swatinem/rust-cache@v2` preserves `target/wasm-pack/` —
a non-profile subdirectory it has no reason to clean — **was not measured
here** and is the one open mechanism this record leaves; §5 makes it the
witnessing run's job to answer, since a single dispatch settles it for free.

### (j) The footer digest and the published sum are different objects.

Measured on the artifact built in Run 2:

```
$ grep -o 'page build <code>[0-9a-f]*</code>' target/verifier-web/index.html
page build <code>f49ce3fd89a8049f87514817592fc8b39e53a094b87d9ab9923c94c782c5d017</code>

$ sha256sum target/wasm-pack/antseal-wasm/antseal_wasm_bg.wasm
f49ce3fd89a8049f87514817592fc8b39e53a094b87d9ab9923c94c782c5d017      ← the MODULE

$ cat target/verifier-web/SHA256SUMS
04a1920a07c567b1e00fc0bb29c189a60e9e8b1493e7089484a5fd586fd2d932  index.html   ← the PAGE
```

The template's source line is `verifier-web/index.template.html:135`:

```html
<p id="page-build">page build <code>__ANTSEAL_MODULE_SHA256__</code></p>
```

The token is named `MODULE`, the label reads `page build`, and the value is the
module's digest. **R25 Accept row 3 asks the footer to show "the build hash
matching the published sum". No footer value matches the published sum, and
none can** — a file cannot contain its own SHA-256. `MVP-SPEC.md` line 139
inherits the same conflation: *"the page footer displays **its own** build
hash"*.

**And the split is not an accident — it is ruled, twice, by D129.** §5 R8:
*"D63 §5 R2's digest is `SHA-256(the module as `wasm-pack` produced it, before
packaging)`"*. §5 R7 goes further and rules the module **out** of the served
`SHA256SUMS` on purpose (a manifest line would oblige the host to serve a
1.84 MB artifact the page never loads), locating it in the signed release
instead, and states the intended relationship in as many words:

> Its digest **is** the footer's value, by construction, and the reader then
> has two independent routes to the same number: extract-decode-hash from the
> page (§1 o, 29 ms) or `sha256sum` the release artifact.

So the architecture is coherent and D129 knew exactly what it was doing. The
packaging step is likewise internally consistent and guarded:
`verifier-page-build.sh --self-test`'s third planted fault is *"a footer digest
that is not the module's"*, observed going **RED** in both runs above.

**R25's Accept row 3 is the outlier** — it describes a comparison D129 §5 R7
had already ruled impossible by design — together with the **label**, which
says "page" over a module digest and so invites precisely the comparison that
must fail. §2 R11/R12 rule the repair of both.

The footer's third element is intact and verbatim:

```html
<p id="advice">for high-stakes verification, run <code>antseal verify</code> and compare verdicts</p>
```

matching `MVP-SPEC.md` line 139's quoted sentence, comma included.

### (k) The advice drift test EXISTS. R25's and TODO.md's record of it is stale.

R25's `Notes` and `TODO.md:747` both state that the D63 §5 R6 / §7 rule 5
advice-line drift test *"does not exist"*, and that
`crates/antseal-wasm/tests/page_template.rs` *"carries exactly five tests …
and none of them is it"*. Measured today:

```
$ grep -c '#\[test\]' crates/antseal-wasm/tests/page_template.rs
6
```

and the sixth, at **line 145**, is
`the_footer_advice_line_has_not_drifted_from_the_spec` — which reads
`MVP-SPEC.md` at runtime and pulls the sentence out of it rather than
restating a literal, for the reason its own comment gives: *"a literal copied
into this file would be a second source of truth that agrees on the day it is
written."*

**The record is stale in the tree's favour.** One boundary survives and is
what §5 turns on: that test asserts the **template**, via `template()`, not
the **built page** and not the **rendered DOM**.

### (l) What `--self-test` actually plants — and what it does not.

`verifier-page-browser.mjs`'s `--self-test` writes a throwaway page that calls
`fetch("https://example.invalid/probe")` and requires the observed-request list
to be non-empty:

```
planted fault: a page that calls fetch()        -> SEEN (https://example.invalid/probe)
```

Three properties of that plant decide §6:

1. **It is a positive control, not a seeded failure.** It proves the network
   instrument is not blind. Its success path is the *green* path — it never
   makes the job fail.
2. **It covers one row of four.** The boot row, the CSP row and the
   bundle-render rows have no plant at all.
3. **`--check` runs it** (`verifier-page-browser.sh:99` passes `--self-test`
   through), so the lane self-tests inline, per D131 §9.2. Good, and unchanged
   by this record.

Consequence: **no path in this repository has ever made the browser job go
red**, so the workflow's `if: failure()` artifact branch has never executed —
not locally, not remotely, not under any self-test. Q19's Accept row 2 is
currently unmet in the strongest possible sense.

### (m) The Actions budget, computed rather than assumed.

Recomputed from `gh api repos/aed900/antseal/actions/runs/31873411737/jobs`
(the most recent `ci` push run) with the documented multipliers — Linux ×1,
Windows ×2, macOS ×10:

```
test              31.97 min  x1     macos  1.32 x10 = 13.17
fuzz-smoke        11.15 min  x1     windows 4.85 x2 =  9.70
--- 19 jobs   raw 67.0 min   WEIGHTED 83.7 min
```

**83.7 weighted minutes**, matching the brief's figure exactly — verified here,
not taken on report. `gh run list --created '>=2026-08-01'` returns **30 `ci`
runs** in the first 15 days of the month: `30 × 83.7 ≈ 2 511` weighted minutes
in half a month, projecting to **~5 000/month**.

**The allowance itself is recorded inconsistently in this project and the
discrepancy is flagged rather than resolved here.** This lane was briefed that
the account is **Pro** (3 000 included minutes). The tree's own Q153 ruling, at
`docs/ci-verification.md`, says something else — *"a private repo on GitHub
**Free** whose **2 000-minute** allowance is already the standing candidate for
the dispatch refusal recorded above"* — and the `fuzz-nightly` lane is budgeted
against a named 700-minute ceiling on that basis. One of the two is stale;
this record cannot tell which, because the billing API is unreadable (below),
and it does not need to: **the conclusion is invariant.** At ~5 000 projected
weighted minutes the account is over its allowance on either figure, by 67 %
against Pro or 150 % against Free. Whoever next touches the budget should
reconcile the two, because a 700-minute fuzz ceiling derived from the wrong
denominator is a real planning error even though it does not change this
ruling.

The billing API is **not readable with the available token**
(`/users/aed900/settings/billing/actions` → 404; `/user/...` → needs the `user`
scope), so the remaining allowance could not be measured and weighted
wall-clock is the only proxy — exactly as the brief states. What can be said
without the billing API is enough: **`ci` alone plausibly exceeds the monthly
allowance, and any per-push addition is the wrong direction.**

---

## 2. The ruling

### What Q19 is

**R1 — Q19's `Do` has THREE false clauses, and the row ships by replacing all
three verbatim-for-verbatim.** This follows R19/R23: a row whose premise is
false ships by saying so, never by quietly doing something else. The
replacements, sentence for sentence:

| replaced | replacement |
| --- | --- |
| *"Install playwright + chromium in CI"* | **"Install nothing for the browser — `ubuntu-latest` carries `/usr/bin/chromium` (§1 b) and D133 rules there is no playwright in this repository and none is to be added. Install the two pinned wasm tools the workflow currently omits, `wasm-bindgen-cli` and `wasm-pack`, at the versions `scripts/wasm-pack-build.sh` reads from their declaration sites (§1 c)."** |
| *"serve R's built page from localhost with external network disabled (the offline verdict must need no network)"* | **"load R's built page from a `file://` origin — D129 rules the page is one file and R23's offline Accept is `file://`; the driver asserts the page ATTEMPTS zero further requests, which is strictly stronger than blocking them (§1 h, and the driver's own header: 'a page that asked and was refused has still asked')."** |
| *"the online-mode endpoint-disagreement case (against local stub endpoints)"* | **"the online-mode endpoint-disagreement case by CDP `Fetch.enable` + `Fetch.requestPaused` + `Fetch.fulfillRequest`/`failRequest` over the existing session (D133/R27), replaying the committed 960767 captures — no stub server, no listening socket."** |

The `Do`'s remaining clauses — running R's suite, uploading artifacts on
failure, logging the wasm build hash — survive and are ruled in R2, R10 and R11.

**R2 — "screenshot + trace" is half available and half dead, and the row says
which.** `screenshot` is **kept**: CDP offers `Page.captureScreenshot`, one
call on the session the driver already holds, no dependency. `trace` is
**ruled dead**: it is a playwright artifact (`trace.zip` for the playwright
trace viewer) with no CDP equivalent that means the same thing. CDP's
`Tracing.start`/`Tracing.end` produce a performance trace, which is not what
the clause wants and would answer no question this lane asks.

Its replacement is the artifact the assertions **actually read**, which the
driver already collects in memory and currently discards: **the event log** —
every `Network.requestWillBeSent` URL, every `Log.entryAdded` entry, every
`Runtime.exceptionThrown`, plus the per-bundle `RESULT`/`FAILURE`/`TIMEOUT`
state and the page and module digests from R10. Accept row 2's parenthetical
becomes **"(screenshot + event log)"**.

Rationale, stated because the substitution is not a downgrade: every browser
row in this lane is decided by the event log. A screenshot shows what a render
failure looked like; the event log is the only artifact that can explain a
zero-network violation or a CSP violation, which are the two rows every other
M3 claim leans on.

**R3 — Accept row 1's parenthetical is corrected in the strengthening
direction.** *"(external requests blocked, verdict still renders)"* becomes
**"(zero external requests ATTEMPTED — `Network.requestWillBeSent` fires for
requests the CSP then blocks, so 'blocked' is the weaker claim; verdict still
renders)"**. The instrument built is better than the Accept row describes, and
the row should not license a future weakening to it.

### The tier

**R4 — `workflow_dispatch`-only is CONFIRMED. The lean survives, on measured
cost, and this section records the attempt to overturn it that failed.**

The attempt, in full, so it is not re-run: the warm cost of this lane is
**~2.0 min** (§1 g), which against 83.7 weighted minutes per push is **+2.4 %**
— genuinely small, and the sort of number that usually wins a required-context
argument. It loses here on the denominator, not the numerator: at ~5 000
projected weighted minutes against 3 000 included (§1 m), the account is
already over, and **+2.4 % of an over-budget total is still spending money the
maintainer said not to spend**, on a lane whose subject — a static page built
from a reproducible artifact — changes on a small minority of pushes.

Scheduled was also considered and refused, on the inversion in §1 g: **a
rarely-run lane is always a cold lane.** GitHub evicts caches unused for
7 days (upstream documented behaviour, taken on report), so a weekly or
monthly schedule pays the **8.30 min** cold path essentially every time, not
the 1.72 min warm one — the worse per-run cost, on a cadence nobody is reading
the results of. Dispatch-only pays the same cold cost but only when a human
has a reason.

**R5 — but "unchanged" is OVERTURNED, and this is the half of the lean that
was wrong.** The lean's word was "unchanged"; the workflow must change or it
can never go green (§1 c/d/e). The changes Q19 owns, and their whole extent:

1. a provisioning step installing the two pinned tools before the lane step —
   the same two `cargo install` lines `pages-publish.sh:58-65` already carries,
   **reached through a shared path rather than copied**, so the two jobs cannot
   drift to different versions;
2. an artifact path that covers something diagnostic (R11);
3. the header comment in §1 f corrected to describe the code.

The trigger line itself does not change.

**R6 — Q19 may NOT be ticked on a lane that has never run. One witnessing
dispatch is a tick precondition, and its cost is stated so the decision is the
maintainer's to make on a number.**

Q43's rule (§1 a) is not satisfiable any other way, and this record exists
because the lane's most important properties are precisely the ones only a
hosted run can establish: that the provisioning step works, that
`/usr/bin/chromium` is really there and really launches headless under
`--no-sandbox`, that node 22.23.2 clears the driver's floor, and that the
rust-cache question in §1 i has the harmless answer.

**The cost of that witness is 8.30 weighted minutes** — the measured first-ever
`pages` run, which is the closest possible analogue. That is **0.17 % of one
month's projected consumption, and 10 % of ONE `ci` push run.** Stated that way
the trade is not close: one dispatch buys the difference between a lane nobody
has run and a lane with a run id.

**This record does not perform that dispatch.** `gh workflow run` spends the
maintainer's minutes and is theirs to authorise. Q19's implementing lane must
request it explicitly, naming the workflow and the account, and must not tick
the row until the run id, its conclusion, its date and its commit are written
into the row's Notes (D133 §5.4's machine-naming constraint, and the
evidence-belongs-in-the-row discipline).

**The evidence's second home is `docs/ci-verification.md`, and that is
Q153's precedent rather than a preference of this record.** Q153's Accept
required *"a remote run id recorded in `docs/ci-verification.md`, per that
document's own evidence rule, not a local run asserted to be equivalent"*, and
it was discharged with run `31436791456` on `5bcdf7d`. Q19's dated section in
that document must carry the same three things Q153's did: the run id and
verdict, an explicit statement that **the required-context count is unchanged
(still 19)**, and a *"what this run does NOT prove"* bullet naming the
surfaces a dispatch-only lane leaves unwitnessed on every subsequent push.

**R7 — the browser binary is pinned by name and the header is corrected.** The
lane keeps `chromium` as the default and does **not** switch to
`google-chrome`: `chromium` is what D129 measured against, and the workflow
should not silently drive a different engine. Because upstream guards only
`chromium-browser` (§1 b), the workflow sets `ANTSEAL_BROWSER` explicitly
rather than relying on the unguarded symlink's continued existence, and
`verifier-page-browser.sh`'s exit-2 header comment is rewritten to say what the
code does: **absence exits 2 in every mode, which is a SKIP locally and a red
job in CI, and there is no `--check`-specific branch.**

**R8 — what the M3 gate cites, now that the lean survived.** Q237's constraint
(D133 §5.4) is that a green local gate is **not** evidence for the page
surface while this lane is dispatch-only and not required. With R4 confirmed,
that stays true, and the gate cites **three** things for the page-surface
clauses, never fewer:

1. the **named dispatch run** from R6 — workflow, run id, date, commit,
   conclusion;
2. the **local gate run** from R9, naming the host and the browser version
   (`Chromium 150.0.7871.181` on this machine today);
3. the explicit statement that **no push-triggered job covers this surface**,
   so the reader knows what the green does not span.

Any Q14-style evidence line naming only the command is insufficient for these
clauses, by D133 §5.4.

### The local gate

**R9 — `scripts/verifier-page-browser.sh` JOINS `scripts/local-gate.sh`, with a
bespoke wrapper.** The marginal cost is **~12.5 s** (§1 h) on a gate that
already spends minutes, and it is cheaper than lanes the gate already carries
(`wasm-bitmatch`'s trigger self-test alone is recorded at 53 s). Q153's
precedent is that a cheap lane rides locally rather than becoming a CI job, and
this is the same trade with a smaller number.

Three constraints on the wiring, each measured rather than assumed:

- **It must not use the generic `run()` helper.** `run()` treats every nonzero
  exit as `FAIL` (`local-gate.sh`), and this script exits **2** when no browser
  is present. A developer without chromium would get a red gate — the exact
  outcome the script's exit-2 design and `local-gate.sh:499-502`'s own comment
  ("this gate must stay runnable on a host without one") exist to prevent. It
  needs a wrapper with a `2) SKIP` branch, modelled on the existing
  `crosscheck_lane`.
- **It is placed after the existing `run verifier-page` lane**, so it inherits
  a freshly built page. The duplicate `verifier-page-build.sh --check` inside
  the script costs ~1.5 s warm and is accepted rather than engineered around;
  the alternative is a new script mode whose only purpose is to save a second.
- **`local-gate.sh:499-502`'s comment must be updated in the same act.** It
  currently states the browser half is "deliberately NOT here". After R9 that
  sentence is false, and this project's own record of what a green gate does
  not cover is the last place a stale claim should sit.

**R10 — the hash clause: WHICH hash, printed WHERE, and ASSERTED.** Q19's
Accept says *"Lane consumes the reproducible build output, hash logged"*. An
echoed hash nobody compares is not evidence, so the clause is ruled as **two
assertions and one echo**:

1. **`sha256(the page file the driver actually loaded)` == the sole entry in
   the `SHA256SUMS` sitting beside it.** Both read **by the driver, from disk,
   after the build**, never taken from the build step's stdout — those are two
   different reads and only the second speaks about the bytes that were driven.
   This is the assertion that makes "the lane consumes the reproducible build
   output" checkable rather than asserted.
2. **The rendered `#page-build` digest == `sha256(the module file)`.** See R12.
3. **Echoed, not asserted:** the `#build` provenance line
   (`antseal-core 0.0.0 · formats 1 · source <commit>`), because the commit is
   context rather than a claim this lane can check.

The failure message must name **which** of the two comparisons failed and print
both sides. Its negative control is in R13.

### R25 Accept row 3

**R11 — R25's Accept row 3 is CORRECTED, because its comparison cannot be
made.** Verbatim-for-verbatim:

> *"Footer shows the build hash matching the published sum, plus the advice
> string (snapshot/playwright-asserted)"*

becomes

> **"The footer's `#page-build` digest equals the SHA-256 of the module the
> page was built from, and the SHA-256 of the page file equals the sole
> `SHA256SUMS` entry published beside it — a two-link chain, because a file
> cannot contain its own hash. The `#advice` string renders verbatim as
> `MVP-SPEC.md` line 139 quotes it. Asserted natively over the artifact
> (`verifier-page-build.sh --self-test`, `page_template.rs:145`) and over the
> rendered DOM by the CDP browser arm."**

`(snapshot/playwright-asserted)` is ruled **dead** on D133.

**R12 — the CDP arm IS the instrument, and what it uniquely asserts is
RENDERING.** The naive reading — "the browser checks the digest" — would
duplicate work already done better elsewhere, and this record refuses it. The
division, by what each instrument can see:

| claim | already asserted by | browser arm adds |
| --- | --- | --- |
| footer digest == module digest | `verifier-page-build.sh --self-test`'s third planted fault, observed RED twice today (§1 j) | that the value **survives into the DOM** — `boot()` runs after injection and could blank or overwrite the footer, which no static read of the file can see |
| advice string == spec line 139 | `page_template.rs:145` (§1 k) — but over the **template** | that it renders **in the built page**, after CSP and after JS, as visible text |
| page digest == `SHA256SUMS` | nothing | the whole assertion (R10.1) |

So the browser arm's three assertions are, precisely:

1. `document.getElementById('page-build').textContent` contains, as its only
   hex run, exactly `sha256(module)` — passed in by the caller, not recomputed
   in the browser;
2. `document.getElementById('advice').textContent`, with markup stripped,
   equals `MVP-SPEC.md` line 139's quoted sentence — pulled from the spec at
   run time, never a literal in the driver, following `page_template.rs:145`'s
   own reasoning;
3. R10.1's page-vs-`SHA256SUMS` comparison, done on disk beside the load.

**The label is repaired in the same act.** `<p id="page-build">page build
<code>…</code></p>` renders the **module's** digest under the word "page", so a
user performing the obvious check — compare the footer to the published
`SHA256SUMS` — gets a mismatch on a **good** page. Rule: the visible text
becomes **`module build`** (or any wording that names the module), and R25's
row records that `MVP-SPEC.md` line 139's *"its own build hash"* is the source
of the conflation and is a spec correction Q237 or the M4 docs row must carry.
That is a spec-versus-code divergence and is flagged, not silently diverged
from.

### The seeded-failure proof

**R13 — the seed is planted by an environment variable, verified BY ITS
MESSAGE, and the existing `--self-test` does NOT cover it.**

§1 l establishes that `--self-test` is a *positive control on one row* whose
success path is green, so it can never exercise `if: failure()`. Q19's Accept
row 2 needs a plant that makes the **job** red. The ruled mechanism:

- **The plant:** `ANTSEAL_PAGE_SEED_FAILURE=<row-name>` read by
  `verifier-page-browser.mjs`, which forces exactly the named row's `check()`
  to fail with its own real message. Row names are the existing labels
  (`boot`, `network`, `csp`, `bundle`). An environment variable, not a patched
  file, because a plant that edits the tree in a shared working directory is
  the hazard this project has already met.
- **The verification:** the run is judged **by its message** — the harness
  requires the log to carry
  `::error::verifier-page-browser: <the named row's label>` and requires the
  uploaded artifact set to be **non-empty and to contain the screenshot and the
  event log**. A nonzero exit is **not** the evidence; a crash exits nonzero
  too.
- **The pre-image assertion (Q234's lesson):** before planting, the harness
  asserts the named row is **green unplanted**. A seeded failure that was
  already failing proves nothing, and this project has recorded that exact
  class three times.
- **The negative control on the artifact clause:** with the variable unset the
  same invocation must be green **and** upload nothing, so the artifact
  branch's presence is shown to be caused by the plant rather than by every
  run.

This plant also, for free, becomes the first execution of the workflow's
`if: failure()` path — which R11's artifact-path fix (§1 e) needs, since that
path has never run and its current `target/verifier-web/` value is measurably
the wrong directory.

**R14 — the artifact path is fixed in the same act.** `path:
target/verifier-web/` becomes a set covering the **diagnosis**: the screenshot,
the event log, and the fixture directory `target/verifier-web-fixtures/`.
`if-no-files-found:` moves from `ignore` to **`error`** for the seeded-failure
run specifically, because "the artifact step succeeded having uploaded
nothing" is precisely the false green §1 e measured. The 2.5 MB page itself is
**dropped** from the artifact: it is byte-reproducible from the commit under
test (R25/R86), so uploading it spends storage to convey nothing.

### The R27 boundary

**R15 — R27 owns the ASSERTIONS; Q19 owns the VENUE. Neither may tick citing
the other's green.**

D129 §5 R9 assertion 8 is the seam, and its text is explicit that it is one
assertion in two halves:

> 8. **The page loads and verifies**, headless, from a `file://` URL, with
> **zero** network requests **and a report byte-identical to native for at
> least one R9 vector.** This is R27/Q19's venue …

Measured: the **first** half is built and green (§1 h). The **second** is not —
`verifier-page-browser.mjs` asserts only `RESULT`/`FAILURE`/`TIMEOUT` per
bundle, so nothing yet distinguishes an `attested` render from any other
verdict, as D133 §8 item 6 and R27's row already record. D129 says *"R27 owns
making it permanent."*

The division, so neither row assumes the other did it:

**Q19 owns** — the workflow file and its provisioning (R5); the trigger (R4);
the witnessing dispatch and its recorded evidence (R6, R8); the local-gate
wiring and its SKIP wrapper (R9); the hash assertions (R10); the seeded-failure
plant and the artifact set (R13, R14); the browser-name pin and the corrected
header (R7).

**R27 owns** — everything the driver *asserts about what rendered*: the
CLI-versus-page parity comparison that closes assertion 8's second half; the
per-bundle verdict identity that replaces the tri-state; the four online cases
over `Fetch.fulfillRequest`; the redaction-view checks; the verdict-wording
snapshots. R12's three footer/advice assertions are **Q19's**, because they are
about the artifact's provenance rather than about verification behaviour.

**The explicit non-assumption, both directions:** Q19 may **not** tick on
"R27's suite is green", because Q19's own obligations (R6, R10, R13, R14) are
untouched by any assertion R27 writes. R27 may **not** tick on "the lane runs",
because a venue that executes a suite asserting a tri-state has not
demonstrated parity. D132's parity warning survives both and is discharged by
neither: both surfaces derive the probe set from one function, so a defect in
`ProbePlan::from_bundle` stays invisible to a rendering-comparison gate.

---

## 3. Refused shapes

**Adding the lane to the required-contexts matrix** — refused on §1 m. Not on
principle: the warm delta is +2.4 %, which would be affordable against a budget
that had room. It does not, and the maintainer's constraint is explicit.

**A `schedule:` trigger** — refused on the cold-lane inversion (§1 g, R4). It
pays the worse per-run cost on a cadence nobody reads.

**Riding an existing `ci` job for zero new required contexts** — the move Q153
used to promote its three cheap lanes, and the first thing to try here. Refused
on mechanism: Q153's three rode `traceability`/`core-dep-graph` **because they
were cargo-free and took under a second**; this lane needs a wasm32 release
build, two `cargo install`s and a browser process. The only `ci` job whose
environment could host it is `test`, already the most expensive job at
**31.97 min** (§1 m), and appending to it makes the browser arm a required
context by the back door — the outcome R4 just refused, with none of the
visibility of having decided it.

**Switching the driver to `google-chrome`** to use the symlink upstream
actually guards — refused (R7). D129's measurements are against Chromium, and
silently driving a different engine to dodge a symlink question is the kind of
change that makes a future divergence unattributable. The `ANTSEAL_BROWSER`
pin addresses the real risk at no cost.

**Copying `pages-publish.sh`'s two `cargo install` lines into
`verifier-page.yml`** — refused (R5). Two copies of a version-derivation would
agree on the day they are written; that is the failure mode
`wasm-pack-build.sh`'s own `recorded_pin()` comment exists to prevent
("A version literal copied into this script is a second copy that would agree
today and drift afterwards").

**Making the browser arm re-assert the footer-digest-equals-module property** —
refused as a duplicate of a native check that already has a planted fault and
was observed red twice today (§1 j, R12). The browser arm asserts the
**rendered** value, which is the part no static check can reach.

**Adding a screenshot to every run** — refused. Screenshots are a
failure-path artifact (R2); capturing one per green run spends storage to
convey that the page looked like the page.

**Fixing the STALE ARTIFACT hazard (§1 i) by weakening `stale_guard`** —
refused outright. The guard is R83's and it fired correctly. If the witnessing
run shows rust-cache does restore `target/wasm-pack/`, the cure is to scope
what that job caches, never to make the guard quieter.

---

## 4. What each row must implement

**Q19** — R1's three `Do` replacements and R2/R3's `Accept` corrections written
into the row; R5's workflow changes; R7's browser pin and header correction;
R9's gate wiring with a SKIP wrapper and the `local-gate.sh:499` comment
update; R10's two hash assertions; R13's seeded-failure plant with its
pre-image assertion and negative control; R14's artifact set. Then R6: request
the dispatch, and record run id, date, commit and conclusion in the row before
ticking.

**R27** — the assertion half of D129 §5 R9 assertion 8, per R15. Unblocked
already by D133's fixture; unaffected by this record except that its venue now
has a defined owner.

**R25** — Accept row 3 replaced per R11; the `page build` label repaired per
R12; the row's `Notes` corrected per §1 k, since the advice drift test it
records as absent exists at `page_template.rs:145` and the file carries six
tests, not five.

**Q237** — cites the page surface per R8's three-part rule. Two further
corrections it must carry at the citation rather than restate: the M3 `Gate:`
line's *"page (playwright)"* (D133 §5.4 already records this), and
`MVP-SPEC.md` line 139's *"its own build hash"* (R12).

**TODO.md** — R25's row and Q19's row both carry the stale
advice-drift-test claim; a registrar act corrects them with §1 k's measurement.

---

## 5. Residual risk, and what this record does not cover

**The rust-cache question is open** (§1 i). Whether
`Swatinem/rust-cache@v2` restores `target/wasm-pack/` across commits, and
therefore whether the `browser` job can red on `STALE ARTIFACT` for a
non-defect, was **not measured**. It is answered for free by R6's witnessing
dispatch if that run is dispatched twice at different commits — which R6 does
not require, and which is therefore named here as the one thing a single
witness will not settle.

**The 7-day cache eviction window is taken on report** from GitHub's
documentation, not measured. It supports R4's refusal of `schedule:` but is not
the only support; the cold/warm figures in §1 g are measured and sufficient on
their own.

**No hosted run has confirmed headless chromium launches under this driver's
flag set.** §1 b establishes the binary exists; `--no-sandbox` is in the
driver's `FLAGS`, which neutralises the Ubuntu 24.04+ unprivileged-user-
namespace restriction that breaks unpacked Chromium builds — but that is
reasoning, not a measurement, and only R6's dispatch converts it.

**This record does not rule R27's assertions**, does not touch `testdata/`,
does not change any trigger by itself, and did not dispatch anything.

**The `page build` label has been shipping wrong.** The page is live at
`https://antseal.org/` (R26). A user comparing the footer to the published
`SHA256SUMS` today gets a mismatch on a good page. R12 repairs it; the exposure
window is recorded here because it is a user-facing correctness defect rather
than an internal one, and the next deploy is what closes it.

---

## 6. Discovered work — described, not registered

1. **A workflow-precondition check with no id.** Every workflow in this
   repository asserts things about its *commands*; none asserts things about
   its *environment*. A cheap script — "for each workflow, which binaries do
   its scripts require, and which steps provide them" — would have found §1 c
   by reading, at zero Actions minutes. `verifier-page.yml` is the first lane
   whose defect is a missing step, and it will not be the last.
2. **`verifier-page-build.sh`'s self-test crashes rather than fails on a cold
   tree** (§1 d). Every other instrument here dies with an `::error::`
   annotation naming its own cause; this one emits a node stack trace. A
   one-line existence check before `selfTest()` would make the cold-checkout
   failure self-describing.
3. **The advice drift test guards the template, not the artifact** (§1 k).
   R12's browser assertion covers the rendered DOM, which leaves no gap once
   Q19 lands — but if R9's gate wiring is ever removed, the artifact half goes
   unguarded silently.

---

## 7. Quoted entry notes (registrar's to apply)

*No ids are minted here. These are the notes the register's rows should carry;
the registrar verifies rather than transcribes, and should say so if any
sentence below does not hold in the tree.*

**On Q19** (`tasks/Q.md` and the `TODO.md` row) —

> **[D136, 2026-08-15] THE LANE HAS NEVER RUN ON THE REMOTE — zero runs,
> measured — AND AS COMMITTED IT COULD NOT HAVE PASSED.**
> `.github/workflows/verifier-page.yml` never installs `wasm-pack` or
> `wasm-bindgen-cli`; `ubuntu-latest` ships neither; `scripts/wasm-pack-build.sh`
> `die`s when either is absent. On a cold checkout the run dies even earlier, in
> `verifier-page-build.sh`'s packaging self-test, with an unhandled node `ENOENT`
> stack trace and no `::error::` annotation — and the `if: failure()` step then
> uploads **nothing**, because `target/verifier-web/` does not exist and
> `if-no-files-found: ignore`. **The one environmental premise anybody wrote
> down is the one that is true**: `ubuntu-latest` really does carry
> `/usr/bin/chromium` (`install-google-chrome.sh` symlinks it), so the browser
> was never the exposure. **THREE of this row's `Do` clauses are false, not
> one** — playwright (D133), *"serve … from localhost"* (the driver loads
> `file://`), and *"local stub endpoints"* (CDP `Fetch.fulfillRequest`) — and
> the row ships by replacing all three verbatim (D136 §2 R1), on the R19/R23
> precedent. *"screenshot + trace"*: screenshot is **kept**
> (`Page.captureScreenshot`, one CDP call); **trace is ruled dead** as a
> playwright artifact and replaced by the driver's **event log** (D136 §2 R2).
> Accept row 1's *"external requests blocked"* is corrected **upward** to
> *"zero requests ATTEMPTED"*, which is what the instrument measures (§2 R3).
> **Tier: `workflow_dispatch`-only CONFIRMED** on measured cost — one `ci` push
> run is **83.7 weighted minutes** (recomputed from run `31873411737`), 30 `ci`
> runs since 08-01 project to ~5 000 weighted minutes/month, and the account is
> over its allowance on either figure the tree records. **But "unchanged" is
> OVERTURNED**: the workflow must gain provisioning, a diagnostic artifact set
> and a corrected header (§2 R5). **A single witnessing dispatch is a TICK
> PRECONDITION** (§2 R6) — it costs **8.30 weighted minutes**, the measured
> first-ever `pages` run, which is 10 % of one `ci` push; the maintainer
> authorises it, this record did not, and the run id, date, commit and
> conclusion go in this row and in `docs/ci-verification.md` per Q153's
> precedent. `scripts/verifier-page-browser.sh` **JOINS**
> `scripts/local-gate.sh` (§2 R9) at a measured marginal cost of **~12.5 s**,
> with a bespoke wrapper honouring **exit 2 as SKIP** — the generic `run()`
> would turn a browserless host red — and `local-gate.sh:499`'s "deliberately
> NOT here" comment moves in the same act. The hash clause is **two assertions
> and one echo** (§2 R10): page-file digest == the `SHA256SUMS` entry beside it,
> both read from disk by the driver after the build; rendered `#page-build` ==
> `sha256(module)`; the `#build` provenance line echoed only. The seeded-failure
> clause is **not** covered by today's `--self-test`, which is a *positive
> control on one row* whose success path is green and which therefore has never
> made the job red (§2 R13).

**On R25** —

> **[D136, 2026-08-15] Accept row 3 rests on a comparison that cannot be made,
> and the row is corrected rather than chased.** Measured: the footer renders
> `page build f49ce3fd…`, the SHA-256 of the **module**; `SHA256SUMS` publishes
> `04a1920a…  index.html`, the SHA-256 of the **page**. Different objects, never
> equal, and a file cannot contain its own hash. **This split is D129's own
> ruling, not a defect** — §5 R8 defines the footer digest as the module's
> pre-packaging digest, and §5 R7 deliberately keeps the module **out** of the
> served manifest while stating that its digest *"**is** the footer's value, by
> construction"*. The outlier is this row's wording, replaced per D136 §2 R11
> with a **two-link chain**, and the **label**, which says "page" over a module
> digest and so invites the one comparison that must fail — repaired to name the
> module (§2 R12). `MVP-SPEC.md` line 139's *"the page footer displays **its
> own** build hash"* is the source of the conflation and is a spec correction,
> flagged not silently diverged from. **The live site has been shipping the
> misleading label**, so a user doing the obvious check gets a mismatch on a
> good page; the next deploy closes it. **A second correction, in the tree's
> favour: this row's `Notes` and the `TODO.md` row both record the advice-line
> drift test as *"does not exist"* and the file as carrying *"exactly five
> tests"*. Both are STALE** —
> `crates/antseal-wasm/tests/page_template.rs` carries **six**, and the sixth,
> at line 145, is `the_footer_advice_line_has_not_drifted_from_the_spec`, which
> reads `MVP-SPEC.md` at run time rather than restating a literal. One boundary
> survives and is what the browser arm covers: that test asserts the
> **template**, not the built page and not the rendered DOM.

**On R27** —

> **[D136, 2026-08-15] The venue is ruled; the assertions remain this row's.**
> D129 §5 R9 assertion 8 is one assertion in two halves — *"zero network
> requests **and** a report byte-identical to native for at least one R9
> vector"* — and D129 says *"R27 owns making it permanent."* The first half is
> built and green; the second is not, because `verifier-page-browser.mjs`
> asserts only `RESULT`/`FAILURE`/`TIMEOUT` per bundle (D133 §8 item 6).
> **Neither row may tick citing the other's green** (D136 §2 R15): Q19 owns the
> workflow, its provisioning, the witnessing dispatch, the gate wiring, the hash
> assertions, the seeded-failure plant and the artifact set; R27 owns the parity
> comparison, the per-bundle verdict identity that replaces the tri-state, the
> four `Fetch.fulfillRequest` cases, the redaction-view checks and the wording
> snapshots. The footer/advice assertions are **Q19's**, being about provenance
> rather than verification behaviour. **D132's parity warning is discharged by
> neither** and stays with the core equality row. Note D129 §10 (iii): the R9
> corpus exercises only `invalid` anchors, so this row still owns the page's
> first exercise of the richer anchor states.

**On Q237** —

> **[D136, 2026-08-15] What the M3 gate cites for the page surface, now that
> dispatch-only survived.** D133 §5.4's constraint is unchanged and this record
> confirms rather than relaxes it: a green local gate is **not** evidence for
> the page surface. The gate cites **three** things for those clauses, never
> fewer (D136 §2 R8): the named dispatch run (workflow, id, date, commit,
> conclusion); the local gate run naming its host and browser version; and the
> explicit statement that **no push-triggered job covers this surface**. Two
> further inherited wordings are corrected at the citation rather than restated:
> the `Gate:` line's *"page (playwright)"* (already recorded at D133 §5.4) and
> `MVP-SPEC.md` line 139's *"its own build hash"* (D136 §2 R12).

**On R86** — *no change.* The two-runner byte-identity question is adjacent and
untouched; D136 rules the browser venue, not the reproducibility witness.

---

## Outcome

The lean survives its trigger and loses its adjective. `workflow_dispatch`-only
is right, and the measurement that makes it right is not the lane's own cost —
it is that 30 `ci` runs at 83.7 weighted minutes project to roughly 5 000
minutes against 3 000 included, so the affordable question was never "is this
lane cheap" but "is anything per-push affordable". "Unchanged" was wrong,
because the lane cannot pass: it never installs the two tools it needs, on an
image that ships neither, and it would have died on a node stack trace before
reaching the browser everyone assumed was the problem.

The chromium premise — the one thing in that workflow anybody had thought to
justify — turned out to be the one thing that was true.

Three of Q19's `Do` clauses are false rather than one, and Q19 ships by
replacing all three. R25's Accept row 3 was asking for a comparison between two
different objects, which is why it could never be met; the footer publishes the
module's digest under a label that says "page", and the live site has been
inviting a check that fails on a good page. And the brief's own premise about
the missing drift test was stale in the tree's favour — the test exists, reads
the spec instead of a literal, and guards the template.

What is left is one dispatch. It costs 8.30 weighted minutes, a tenth of a
single push, and it is the difference between a lane nobody has run and a lane
with a run id — which is the only currency `docs/ci-verification.md:1080`
accepts.

---

## Correction — §1 (k)'s test count went stale the same day, and §2 R9's marginal cost is superseded by measurement, 2026-08-16

**(1) The corrected measurement, quoted verbatim**, from **§1 (k)**:

> ```
> $ grep -c '#\[test\]' crates/antseal-wasm/tests/page_template.rs
> 6
> ```
>
> and the sixth, at **line 145**, is
> `the_footer_advice_line_has_not_drifted_from_the_spec`

**Re-measured at the wave-21 close**, same command, same file:

```
$ grep -c '#\[test\]' crates/antseal-wasm/tests/page_template.rs
7
```

The seventh is `the_footer_names_the_module_not_the_page_as_the_subject_of_its_digest`
at **line 244** — added later the same day by **R85 act 1**, executing **this
record's own §2 R12**. **The locator holds**: line 145 is still
`the_footer_advice_line_has_not_drifted_from_the_spec`, so §1 (k)'s point —
that R25's and `TODO.md`'s *"the drift test does not exist … the file carries
exactly five tests"* is stale in the tree's favour — stands whole, and its
boundary (that test asserts the **template**, not the built page and not the
rendered DOM) is untouched. Only the ordinal moved. Recorded because §1 (k)
exists precisely to correct a stale count, and a correction that goes stale the
same day is worth naming.

**(2) The corrected figure, quoted verbatim**, from **§2 R9**:

> The marginal cost is **~12.5 s** (§1 h) on a gate that already spends minutes

**Measured after R27 and R85 landed their assertions:** **~38 s** warm for
R27's 13 fixtures / 86 rows, **~50 s** warm with R85's 14 further rows
(`--check` 72.6 s cold on the R85 run, `--self-test` 8.2 s, `--seed-test`
51.3 s). **The growth is not overhead.** §1 h's 12.5 s was measured against a
driver whose per-bundle wait was **vacuous**: `dropBundle` polled *"is `#result`
hidden?"*, and the page unhides `#result` on the first success and never
re-hides it, so from the second drop the exit condition was already satisfied by
the previous bundle's DOM. The corrected driver waits for **13 real
verifications** instead of racing past twelve of them, and opens **5 browser
sessions** for the online cases.

**This is a re-recording, not a re-decision.** §2 R9's ruling — the script joins
`scripts/local-gate.sh` with a bespoke wrapper carrying a `2) SKIP` branch, placed
after the existing `verifier-page` lane — is unaffected, and 38–50 s remains
below `wasm-bitmatch`'s trigger self-test at 53 s, which is the comparison R9
argues from. §7's quoted entry note carries the same superseded figure and is
corrected by this section.

**Authority.** The **R27** lane and the CI-venue lane, 2026-08-16, both by
measurement on the local host; registered by the registrar at the wave-21 close
in the same commit as R27's tick.

**Which rulings still stand.** All of them. Both errors run in the direction of
**under-stating what this record achieved** — one more test than it counted, and
a lane that does more work than it priced. §2 R1 (the three verbatim `Do`
replacements), R4 (the trigger), R5 (provisioning), **R6 (one witnessing
dispatch as a tick precondition — still unmet: `gh run list --workflow
verifier-page.yml` returned `[]` at the wave-21 close)**, R11 (R25's Accept row 3
replacement), R12 (the label repair and its three CDP assertions) and R15 (the
R27/Q19 division, and the ban on either ticking for the other) are untouched.
