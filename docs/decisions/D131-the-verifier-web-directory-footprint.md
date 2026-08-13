# D131 — What `verifier-web/` contains, what is committed, what scans it, and where the page's tests live

- **Status: RESOLVED — `verifier-web/` is a SOURCE-ONLY directory holding exactly
  one committed file, the template `verifier-web/index.template.html`; the
  484-byte placeholder `verifier-web/index.html` is DELETED in R23's commit; the
  built 2.47 MB page is NEVER committed and never written into `verifier-web/`
  — it is built to `target/verifier-web/index.html`, which `/target` at
  `.gitignore:8` already covers, so this ruling changes `.gitignore` not at
  all.** The template name D129 §7 minted — `verifier-web/index.html.template` —
  is **overturned on a planted fault**: `Path::new("index.html.template")
  .extension()` is `Some("template")`, which
  `crates/antseal-core/tests/verdict_wording.rs:941`'s
  `matches!(ext, "rs" | "html" | "js" | "css")` does not walk, so a frozen
  verdict sentence planted in a template under that name leaves all nine tests
  **green**, while the same sentence under `index.template.html` turns the scan
  **red** naming `verifier-web/index.template.html:2`. **The name is not the
  defect, it is the symptom.** With `verifier-web/` holding only an unwalked
  template the scan reports **54 files, every one of them from
  `crates/antseal-cli/src`** — page coverage exactly **zero** — and the
  anti-vacuity guard at `:863` (`sources.len() > 10`) cannot fire, now or ever,
  because the CLI alone supplies 54. So the guard is ruled **per-root**, which
  fixes the class rather than this instance. A **second, independent** coverage
  defect the survey did not name is measured here and ruled with it: the residue
  assertion at `:884` reads the **union** of the two roots, so a page-side copy
  of a residue sentence **masks** its deletion from the CLI — measured red, then
  green, with the CLI deletion unchanged — and it is therefore scoped to the CLI
  root alone. Traceability gains `verifier-web` as a scan root and `.html` as a
  suffix: measured **420 → 421 files with ZERO collateral**, because no `.html`
  file exists under any existing root. The base64 is **ONE LINE**, and **not**
  on the silent-skip footgun the survey offered — that footgun is real (49
  `//`-prefixed lines at wrap-76, **6.2×** the uniform prediction) and **inert**,
  since none of `wording.rs`'s 131 string literals is base64-shaped — but on
  determinism: **wrap width is a free parameter that enters the artifact's
  identity and its CSP hash**, and five plausible implementations of the same
  step split two ways on it.
- **Date: 2026-08-12** (wave 19 planning round, D131 lane; briefed to overturn
  rather than confirm. Four of the survey's seven findings survive as stated,
  one is overturned in its reasoning while its conclusion survives, and two new
  defects are found that the survey did not contain — the residue-masking
  direction and the domain-blind vacuity guard. Every scan claim below was
  established by **planting a fault and reading the failure's own message**, in
  an isolated copy of the tree; **no file in the working repository was modified
  by this lane except this record**.)
- **Owning tasks: R23** (authors the template under the ruled name, deletes the
  placeholder, lands the per-root guard and the residue scoping, and makes the
  traceability widening), **R25** (the packaging script, its `--self-test`, and
  the built-artifact assertions), **R26** (deploys from the build output, never
  from the tree), **R27/Q19** (the browser venue), **R18** (the scan whose
  coverage this repairs; unedited in its ruling), **R22** (the `--self-test`
  script shape this ruling reuses).
- **Amends**: `docs/decisions/D129-…` §7 and §11.1 (the template's filename —
  one rider, quoted in §9.4), and therefore `tasks/R.md` R23's `Notes`, whose
  registrar-applied copy at `tasks/R.md:297` already carries the escaping name.
  **Supersedes**: nothing. **Corrects**: nothing shipped — the defects ruled
  here are latent and land the day R23 does. Answers **D63 §10 (iv)** in full
  and closes it; D129 §10 (iv) forwarded it unchanged.

---

## 1. What was measured

**Method note.** Every scan arm ran against an **isolated `rsync` copy** of the
tree at `HEAD` = `9ffe8b7`, under
`/tmp/claude-1000/…/scratchpad/repo`, with its own `target/`, so no
result below depends on — or disturbs — the working repository or the
concurrent D130 lane. Scan verdicts are never inferred from a nonzero exit:
each is a **planted fault** whose failure message is quoted. The built-page
stand-in is a real artifact — the committed template's authored residue, the
**verbatim** `wasm-pack --target web` glue from
`target/wasm-pack/antseal-wasm/antseal_wasm.js` (11 181 B), and the real
base64 of the real `antseal_wasm_bg.wasm` (1 841 981 B → 2 455 976 chars) —
totalling **2 469 406 B**, within 0.03 % of the 2 470 000 B D129 §1 (n)
measured. Browser arms are **Chromium 150.0.7871.181** and **Firefox
140.13.0esr**, the two engines D129 used, each reporting through its own beacon.

### (a) The name D129 minted escapes the scan D129 says will scan it — confirmed at the mechanism

```
$ rustc -O ext.rs && ./ext
index.html               extension()=Some("html")      walked_by_verdict_wording=true
index.html.template      extension()=Some("template")  walked_by_verdict_wording=false
index.template.html      extension()=Some("html")      walked_by_verdict_wording=true
index.tmpl.html          extension()=Some("html")      walked_by_verdict_wording=true
index.html.in            extension()=Some("in")        walked_by_verdict_wording=false
index.html.tpl           extension()=Some("tpl")       walked_by_verdict_wording=false
index.htm                extension()=Some("htm")       walked_by_verdict_wording=false
```

`Path::extension()` returns the segment after the **last** dot, so
`index.html.template` presents as a `.template` file and
`crates/antseal-core/tests/verdict_wording.rs:941` —
`.is_some_and(|ext| matches!(ext, "rs" | "html" | "js" | "css"))` — does not
collect it. `index.htm` escapes by the same rule, which is worth recording
because it is the one plausible typo that fails silently.

### (b) The same fact, established the only way that counts — a planted frozen sentence, and the scan's own message

The frozen banner `UNANCHORED — integrity and signature only, no provable time`
(`crates/antseal-core/src/verify/wording.rs:172`) planted as a **code literal**
in a template under each candidate name, one name at a time, with
`no_renderer_source_spells_a_frozen_verdict_string` run against each:

| template filename | test verdict | files scanned | offending hit |
| --- | --- | --- | --- |
| `index.html.template` (**D129 §7's name**) | `test result: ok` | — | **NONE** |
| `index.template.html` | `test result: FAILED` | **56** | `verifier-web/index.template.html:2` |
| `index.html.tpl` | `test result: ok` | — | **NONE** |
| `index.htm` | `test result: ok` | — | **NONE** |

The failing arm's message, verbatim from the assertion at `:876`:

> `verdict wording is spelled outside the table in 56 scanned renderer files:`
> `verifier-web/index.template.html:2: the UNANCHORED banner — …`

56 = 54 CLI sources + the placeholder `index.html` + the template. **The scan
works; the name D129 gave it does not reach the scan.**

### (c) The name is the symptom. The guard is the defect — page coverage goes to ZERO and nothing reddens

The realistic R23 landing — the placeholder replaced by the template under
D129's name, so `verifier-web/` holds exactly one file and it is unwalked:

```
$ cargo test -p antseal-core --test verdict_wording
test result: ok. 9 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.57s
```

and, with a probe literal planted in a CLI file to make the scan print its own
domain:

```
spelled outside the table in 54 scanned renderer files
crates/antseal-cli/src/main.rs:14
```

**54 files, every one of them from `crates/antseal-cli/src`.** The anti-vacuity
guard at `verdict_wording.rs:863` is

```rust
assert!(
    sources.len() > 10,
    "the source walk found {} files — the walk is broken, not the tree clean",
    sources.len()
);
```

— a count over the **union**, and the CLI alone supplies 54 today and will
supply more tomorrow. The guard is not merely insufficient here; it is
**structurally incapable** of noticing that one of its two roots contributes
nothing. What `docs/instrument-ledger.md:46` and
`docs/testing/verification-matrix.md:169` (row V8.3) both claim of this scan —
that *"shared verbatim by CLI and page"* is **asserted rather than assumed** —
would become false, silently, in R23's landing commit. §3 R2 fixes the class.

### (d) Three tests, not one — and only two of them read a file

| test | site | what it reads | what a new template does to it |
| --- | --- | --- | --- |
| `the_wording_set_satisfies_the_positioning_checklist` | `:594` | `rendered_rows()` — the **in-memory** wording table. **No file is opened.** | **nothing.** The `BANNED_TOKENS` positioning ban (`notary`, `priority`, `certify`, …) has never covered `verifier-web/` and does not begin to |
| `no_renderer_source_spells_a_frozen_verdict_string` | `:860` | the union of both roots, via `renderer_sources()` at `:807` | bans the template from **duplicating** any of the 27 `single_sourced()` needles (`:667`) |
| `every_recorded_residue_is_still_there` | `:884` | the same union | asserts the 6 `RESIDUE` needles (`:765`) are **present** — see (e), which is where this goes wrong |

The first row is the finding the survey's item 2 half-named and it matters
beyond bookkeeping: **the page's own copy is under no positioning ban at all.**
The vocabulary test's subject is `antseal_core::verify::wording`'s table, so
R23's chrome — headings, drop-zone copy, footer prose — could say *notary* and
no committed check would object. D63 §5 R6 already places that copy under Q20's
copy lint and Q28's sweep; §8 (i) records that the gap is real today and is
**not** this record's to close.

### (e) The residue assertion runs in the wrong direction, and a page-side copy MASKS a CLI deletion

Not in the survey. `every_recorded_residue_is_still_there` asserts presence
over the **union**, so any file under either root satisfies it. Two arms,
identical CLI state:

```
step 1 — delete the CLI's copy, verifier-web carries nothing
  CLI carrier: crates/antseal-cli/src/seal_run.rs
  "these residue entries no longer exist"
  test result: FAILED                                    <-- correct

step 2 — same deletion, plus verifier-web/page-probe.html carrying the string
  test result: ok                                        <-- MASKED
```

The needle was `UNANCHORED: this seal carries no timestamp attestations`
(`RESIDUE[4]`), whose whole purpose per the file's own doc at `:755-757` is that
*"the list cannot go stale: move one onto the table and this test reddens until
the entry is deleted on purpose."* A page that renders the same sentence — and
R23's page renders the same sentences, which is the point of R18 — silently
disarms it. So the two file-walking tests want **opposite** domains: the ban
wants the page **in**, the residue wants the page **out**. Today they share one
`renderer_sources()` and the collision is invisible because `verifier-web/`
holds 484 bytes of placeholder.

### (f) Base64 cannot false-positive the ban scan — confirmed, at the alphabet

```
$ python3  # every string literal in crates/antseal-core/src/verify/wording.rs
string literals in wording.rs: 131
literals >8 chars that are pure base64 alphabet (could collide): 0 []
```

Zero of 131. Every needle carries a space, a colon or an em dash, none of which
is in `[A-Za-z0-9+/=]`, so no frozen sentence can occur inside a base64 token.
The survey's claim holds — **and §2.3 records why this is a weaker guarantee
than it reads**, because it is a property of the current needle list, not of the
mechanism.

### (g) The silent-skip footgun is real, and 6.2× more common than predicted

`occurrences()` at `:842` skips any line whose `trim_start()` begins with `//`,
`<!--` or `*` (`:846-847`). Over the real module's base64:

| wrap | lines | lines beginning `//` | uniform prediction (1/4096) |
| --- | --- | --- | --- |
| **none (`-w0`)** | **1** | **0** | 0 |
| 76 | 32 316 | **49** | 7.9 |
| 64 | 38 375 | **76** | 9.4 |
| 120 | 20 467 | **36** | 5.0 |

The survey's *"~1 in 4096"* under-counts by **6.2×**, because base64 of
WebAssembly is not uniform: `//` encodes twelve consecutive one-bits, and LEB128
negatives and `0xFF` runs make that common. `*` and `<!--` cannot begin a line —
neither character is in the alphabet — so `//` is the whole exposure: **3 724
base64 characters, ≈2 793 module bytes, invisible to the predicate** at wrap-76.

### (h) What the built page costs the scan — and wrapping costs exactly double

`cargo test -p antseal-core --test verdict_wording`, three runs per arm, warm:

| what sits at `verifier-web/index.html` | suite time | delta |
| --- | --- | --- |
| the 484-byte placeholder | **0.61 · 0.65 · 0.62 s** | — |
| the built page, base64 on **one line** (2 469 406 B) | **0.87 · 0.86 · 0.89 s** | **+0.25 s** |
| the built page, base64 **wrapped at 76** (2 501 721 B) | **1.13 · 1.13 · 1.14 s** | **+0.51 s** |

The survey's remembered *"+267 ms debug"* reproduces (+250 ms). The new number
is the third row: `text.lines()` with a `trim_start()` and three `starts_with`
per line over 32 707 lines costs **twice** what one long line costs. Both
deltas are erased entirely by §3 R4, under which no built page is ever inside a
scanned root.

### (i) `atob` accepts wrapped base64 in both engines — so the runtime does NOT decide the wrap question

The probe page carries the same module twice, once unwrapped and once wrapped
at 76, and reports through a beacon. **Chromium 150** (`HeadlessChrome/150.0.0.0`):

```json
{"oneline": {"ok": true, "len": 1841981, "ms": 179, "hasNewline": false},
 "wrapped": {"ok": true, "len": 1841981, "ms":  90, "hasNewline": true},
 "strictWhitespace": "accepted", "internalNewline": "accepted", "spaceInside": "accepted"}
```

**Firefox 140.13.0esr** (`rv:140.0`):

```json
{"oneline": {"ok": true, "len": 1841981, "ms": 147, "hasNewline": false},
 "wrapped": {"ok": true, "len": 1841981, "ms": 120, "hasNewline": true},
 "strictWhitespace": "accepted", "internalNewline": "accepted", "spaceInside": "accepted"}
```

Both engines implement forgiving-base64: `atob("QQ==\n")`, `atob("QU\nJD")` and
even `atob("QU JD")` are accepted, and both arms decode to the **identical
1 841 981 bytes**. The obvious argument against wrapping — *it would break the
portable `atob` path D129 §5 R4 rules* — is **false, twice over**. (The
apparent speed-up on the wrapped arm is JIT ordering, not a property of
wrapping: it ran second in both engines. It is recorded so nobody cites it.)

### (j) The reader's own check works either way, too

D63 §5 R2's reader must be able to recover the footer's number from the page
alone. Both shapes, shell only:

```
one line : grep -o 'const B64="[A-Za-z0-9+/=]*"' … | base64 -d | sha256sum   51 ms
wrapped  : sed -n '/const B64="/,/";<\/script>/p' … | tr -d '\n' | base64 -d  29 ms
both     -> 5bbdc113d45d5b6c3dbe209003a4d0d37cf289bb31ed3d5837a088c15f6539c4
ground truth: sha256sum target/wasm-pack/antseal-wasm/antseal_wasm_bg.wasm
             = 5bbdc113d45d5b6c3dbe209003a4d0d37cf289bb31ed3d5837a088c15f6539c4
```

Equal. **Two of the three arguments a wrap ruling could rest on are neutral.**
(The digest differs from D129 §1 (b)'s `8c0d3a12…` for the reason D129 recorded:
the 40-byte `ANTSEAL_SOURCE_COMMIT` string inside the module, and this build sits
at a later `HEAD`.)

### (k) Wrap width is a free parameter — five implementations of one step, split two ways

The same module, through the five encoders an implementer would plausibly reach
for (SHA-256 of the encoder's output, first 16 hex):

| implementation | digest | wraps |
| --- | --- | --- |
| GNU `base64` (no flag) | `54c6e25dcc9d5cd6` | **76** |
| Python `base64.encodebytes` | `54c6e25dcc9d5cd6` | **76** |
| GNU `base64 -w0` | `da3ff74f78493b46` | none |
| Python `base64.b64encode` | `da3ff74f78493b46` | none |
| Node `Buffer.toString('base64')` | `da3ff74f78493b46` | none |

`base64 --help`: *"-w, --wrap=COLS wrap encoded lines after COLS character
(default 76). Use 0 to disable line wrapping"*. Two of five wrap, three do not,
and **the two library APIs — the ones a script actually calls — produce the
unwrapped form with no parameter at all.** Because the base64 is the text
content of a hashed inline `<script>` (D129 §5 R6's `<H1>`), a different wrap
is a different script text, a different CSP hash, and a different published
artifact **from identical inputs**. §3 R6 rules on this and nothing else.

### (l) The built page is tracked-by-default today, and one byte costs a 4.9 MB diff

```
$ git ls-files verifier-web/
verifier-web/index.html
$ git log --oneline -- verifier-web/
1f5c6ac P5: cargo workspace scaffold per MVP-SPEC architecture tree
$ grep -n "pkg\|wasm\|html\|verifier" .gitignore
(no output)
```

So R25's output, written to `verifier-web/index.html`, would land as a
modification to a tracked file and commit by default. What that costs, measured
in a throwaway repository, changing **one byte** 200 000 characters into the
base64:

| shape | `git diff --stat` | `git diff` bytes | `git diff` lines |
| --- | --- | --- | --- |
| one line | `1 insertion(+), 1 deletion(-)` | **4 912 507** | 13 |
| wrapped 76 | `1 insertion(+), 1 deletion(-)` | **876** | 13 |

**5 608×.** Both report *"1 insertion(+), 1 deletion(-)"*, so `--stat` — the
thing a reviewer reads first — is identical and tells them nothing. Storage is
not the problem: eleven commits of a wholly-changed page pack to a **2.3 MB**
`.git`. The problem is that the review surface of a rebuild is either 4.9 MB of
base64 or a diff whose `--stat` lies about its size.

### (m) `verifier-web/` is under no scan but one, in CI under none at all

```
$ git grep -n "verifier-web" -- .github scripts
$ echo $?
1
```

Empty. The directory appears in **no** workflow and **no** script. Its only
live reference in executable code remains `verdict_wording.rs:812`, exactly as
`docs/instrument-ledger.md:55` recorded for D63. And
`scripts/wasm-pack-build.sh` — R22's build-and-check driver, the nearest thing
to a page lane that exists — is called by no workflow either, so the module the
page will carry is built by nothing in CI today.

### (n) Traceability: `verifier-web` is a fourth unswept directory, and the widening is free

```
$ python3 scripts/check-traceability.py      # flagless run IS the check
[decisions] ok — 118 distinct decisions cited across 420 files, all resolve …
[task-citations] ok — 408 distinct task ids cited across 420 files, all resolve …
```

`CITATION_SCAN` (`scripts/check-traceability.py:615`) is
`["crates", "docs/format", "docs/testing", "scripts", …root files]` and
`CITATION_SUFFIXES` (`:643`) is `{".rs", ".md", ".json", ".py", ".sh", ".mjs"}`.
Neither `.html` nor `.template` is in it and `verifier-web` is not a root, so
any task or decision id R23 writes into the page is checked by nothing. Q210's
three unswept directories are `fuzz/`, `probes/` and `.cargo/`; this is a
fourth, and unlike those three it is about to acquire content.

**The collateral of the widening, which is what D123 taught us to measure
first:**

```
.html files under crates/         : 0
.html files under docs/format/    : 0
.html files under docs/testing/   : 0
.html files under scripts/        : 0
```

**Zero.** So adding `verifier-web` as a directory root and `.html` to
`CITATION_SUFFIXES` reaches exactly one new file — the template — and nothing
else. Measured in the isolated copy:

```
before : 118 distinct decisions cited across 420 files
after  : 118 distinct decisions cited across 421 files      (+1 file, 0 collateral)
with a 2.47 MB built page also present:
         119 distinct decisions cited across 421 files      0.90 s vs 0.82 s
```

Compare D123 §1's measured cost for the `.toml` route it refused: **359 → 377,
15 collateral**. This one costs +1 and none. (The `.template` suffix is refused
in §4 for a different reason: it would be minted for one file and would still
leave the wording scan blind, since that scan's suffix list is a separate
constant.)

**And what a built page would do to the sweep if one ever landed in the root**
— the reason §3 R4 is load-bearing for this check too:

```
TASK_BARE hits inside the one-line base64 (2 455 976 chars): 2   -> P7, Q1
bare D-id hits: 0 ;  marked form (`X12` / **X12**): impossible
```

Only two, because `\b` needs a non-word character and a solid base64 run has
almost none; both resolve, so the lane stays green — but the sweep's own domain
statement (*"cited across N files"*, its **only** self-check per Q211's problem
statement) would be counting a generated artifact.

### (o) The venues that already exist, and what they cost

- `cargo test -p antseal-wasm` runs **natively** today: `tests/boundary.rs`
  9 passed, `tests/carriage.rs` 5 passed, 14 in all. So the crate D18 §5 R1
  created for the page is a working home for a Rust test over a tracked file.
- `verifier-web/` **cannot** be a Cargo member: `.cargo/config.toml`'s
  `runner = ["node", "../../scripts/wasm-test-runner.mjs"]` hard-codes a
  two-level package depth, which is D18 §4.2's stated reason and is unchanged.
- The repo has **no `package.json` and no `node_modules`** anywhere. Its JS
  venue is four `scripts/*.mjs` files run by the `node` that the wasm32 runner
  already requires. D129 §1's own browser arms were driven over **raw CDP from a
  WebSocket, no puppeteer** — so a browser lane need not be the repo's first npm
  dependency. §8 (ii) records this ahead of Q19.
- **Fifteen** scripts accept a `--self-test` argument (ten `.sh`, five `.py`);
  twelve lanes are wired through `scripts/ci-lanes.sh`
  (`LANES="dep-graph cross-os golden-vectors tamper-matrix cbor-drift-guard
  traceability ci-shell secret-guard audit-deny fuzz-budget anchor-net-policy
  cargo-free"`); and `scripts/local-gate.sh` runs each self-test **before** the
  lane it guards (`run features scripts/gate-features.sh --self-test` then
  `run features scripts/gate-features.sh --check-partition`, and so on). That is
  the shape §3 R8 reuses.
- One honest note on the baseline: `check-traceability.py` is **red in the
  working tree right now**, on `[decision-index] D130 has a record … and no row
  in the index` — the concurrent D130 lane's in-flight state, exactly the
  mid-registration red `docs/instrument-ledger.md` and the wave memory predict.
  Nothing in this record depends on it, and it is not this lane's to fix.

---

## 2. The lean, dismantled

The survey handed over seven findings and an implied disposition: *rename the
template, keep the built page out of the diff, put the tests somewhere, extend
two scans, and pick a base64 shape on the silent-skip hazard.* Four findings
survive verbatim. Three do not survive in the form they were offered.

**2.1 *"Rename the template and the scan escape is settled"* — half right, and
the half it misses is the one that recurs.** §1 (b) confirms the rename works.
§1 (c) shows the rename is a **patch on one instance of a class**: the guard
that exists to prove the walk is not broken is a count over the union, so any
future edit that empties `verifier-web/` — a second rename, a suffix the walk
does not know, a directory moved under a name the walk skips like
`index.htm` — reproduces the same silent zero. This is the shape
`docs/instrument-ledger.md` already carries twice: at `:97`, where the R22 lane
found the same scan short by a whole crate; and in the wave memory's *"gate
finds what analysis misses"*. A rename fixes today. A per-root guard fixes the
class, costs three lines, and would have made the original defect impossible to
land. §3 R1 and R2 rule both, and **R2 is the one that matters**.

**2.2 *"Two tests, not one"* — it is three, and the third one runs backwards.**
§1 (d) separates them: the positioning vocabulary test never opens a file, so
the page's chrome is under **no** banned-token scan at all; and §1 (e) measures
that the residue assertion, sharing one source list with the ban, can be
**satisfied by the page** and thereby stop noticing the CLI. The survey asked
what each test does *to a template*; the answer that matters is what the
template does *to them*. One of the two gets stronger, one gets silently weaker,
and they cannot share a domain. §3 R3 splits them.

**2.3 *"Base64 cannot false-positive the scan, and the footgun is the
line-wrapped `//` skip"* — the first clause is true, the second is true and
inert, and neither decides the question.** §1 (f): zero of 131 literals are
base64-shaped, so no false positive is possible. §1 (g): the skip is real and
**6.2×** more common than the survey's estimate — and it cannot hide a frozen
sentence, for exactly the reason the first clause gives. So the footgun the
survey offered as the deciding measurement **decides nothing**, and saying so is
the honest result. What is worth keeping is the *shape* of the observation: the
scan's completeness over a wrapped payload rests on a coincidence about the
**needle alphabet** rather than on the **mechanism**, and a check whose coverage
holds by coincidence is one needle away from not holding. §1 (i) then kills the
other easy argument — `atob` accepts newlines in both engines — and §1 (j) kills
the third, since the reader's extract-decode-hash works either way. Three
plausible grounds, all neutral. The ruling therefore rests on §1 (k), the one
place the two shapes are **not** equivalent: wrap width is a free parameter that
five implementations split two ways on, and it enters the hashed script text.
That is D129 §6's own refusal of inline compression — *"a compressor version and
level become inputs to the published artifact's identity"* — one level down, and
D63 §7 rule 1's class exactly.

**2.4 *"The built page lands as a modification to a tracked file"* — true, and
the conclusion it invites is the wrong one.** §1 (l) confirms every clause:
tracked since `1f5c6ac`, no `.gitignore` entry, commits by default. The
tempting fix is to wrap the base64 so the diff is 876 bytes instead of 4.9 MB —
and it works, 5 608× — but it accepts the premise. **The premise is what should
go.** D62 §3 R2 rules the publishing source is *"**GitHub Actions**, not a
branch. R25's reproducible build must be the thing that produces the deployed
bytes; a branch source invites a hand-copied artifact between the build that was
hashed and the bytes that are served."* A committed built page **is** that
hand-copied artifact, sitting in the tree, one stale rebuild away from
disagreeing with the template and module it claims to be. It is also, precisely,
D129 §6's refused hybrid one level out — *"two byte sequences both claiming to be
the antseal verifier"* — with the tree copy as the second. Nothing needs it:
Pages builds, the signed release carries the bytes Q30/Q31 sign, and the reader
gets them from the canonical URL. §3 R4 refuses it, and the wrap question loses
its only real argument in the same act.

**2.5 *"`verifier-web/tests/` has no runner, so use `carriage.rs`'s
precedent"* — right, and the precedent says something sharper than "put it in a
crate".** `crates/antseal-wasm/tests/carriage.rs` exists because the property
was about **that crate** and core was not to be edited. Read that way it does
not send *every* page-shaped test to `antseal-wasm`. It sends each test to the
venue that can actually hold its subject, and this ruling has three different
subjects: a **tracked file** (the template), a **generated file** (the built
page), and a **running browser**. §1 (h) is the measurement that forces the
split — the wording suite's own runtime moved from 0.62 s to 0.87 s to 1.13 s
depending on what happened to be sitting in `verifier-web/` at the moment. **A
`cargo test` whose result depends on whether somebody has run a build is not a
test.** §3 R8 puts built-artifact assertions in a script that builds first, and
template assertions in a crate.

**2.6 What the survey did not contain.** The residue-masking direction
(§1 e), the domain-blindness of the anti-vacuity guard (§1 c), the fact that the
positioning vocabulary ban never reaches the page at all (§1 d), and the
measured freeness of the traceability widening (§1 n: zero collateral, against
D123's refused route at 15).

---

## 3. The ruling

Nine rules. "Template" = the committed, loadable page with placeholders.
"Built page" = the packaged `index.html` D129 §5 R1 rules. "The scan" =
`crates/antseal-core/tests/verdict_wording.rs`.

**R1 — The template is `verifier-web/index.template.html`, and the placeholder
`verifier-web/index.html` is DELETED in the same commit.** The name is chosen on
one measured property and one design property. Measured (§1 a, b): its extension
is `html`, so `walk()` at `verdict_wording.rs:924` collects it and a frozen
sentence planted in it turns the scan red naming the file and the line —
whereas D129 §7's `index.html.template`, and `index.html.tpl`, and `index.htm`,
are all silently invisible. Design: the name keeps template and artifact
distinguishable in every path citation, test name and error message, which is
what D129 §7 wanted the trailing `.template` for. **D129 §7 and §11.1 need a
rider, quoted in §9.4, and `tasks/R.md:297` carries the escaping name today and
must be corrected with it.** The deletion is not tidiness: leaving a tracked
`index.html` beside the template invites R25 to write its output over it, which
R4 forbids, and leaves the 484-byte stub that `docs/instrument-ledger.md:52` and
D129 §10 (iv) both still describe as live.

**R2 — The anti-vacuity guard becomes PER-ROOT, and this is the rule that
outlives the rename.** `renderer_sources()` (`:807`) must return, or expose,
its files **keyed by the root they came from**, and
`no_renderer_source_spells_a_frozen_verdict_string` must assert **both** roots
non-empty before it asserts anything about their contents — with a floor on the
CLI root that is not 10. Literally: assert `crates/antseal-cli/src` contributed
**at least 40** files and `verifier-web` contributed **at least 1**, each with
its own message naming the root that came up empty. The single
`sources.len() > 10` at `:863` is deleted, not supplemented: it is the assertion
that would have been green through the failure §1 (c) measures. **A guard over a
union of roots is not a guard on any of them.**

**R3 — The residue assertion is scoped to `crates/antseal-cli/src` and to
nothing else.** `every_recorded_residue_is_still_there` (`:884`) reads **only**
the CLI root. Measured (§1 e): over the union, a page-side occurrence of a
`RESIDUE` needle keeps the test green through a deletion of the CLI's copy —
the exact rot the test's own doc comment at `:757` says it exists to prevent.
`RESIDUE`'s six entries are, by their own definition at `:754`,
*"Verdict-shaped sentences that still live in **`antseal-cli`**"* (the constant
runs `:765-803`); the domain in the code must
say what the domain in the comment says. The scoping is a change of one argument
at one call site and is **R23's**, because R23 is the act that makes the union
unsafe.

**R4 — The built page is NEVER committed and NEVER written into
`verifier-web/`. It is built to `target/verifier-web/index.html`.**

- **`.gitignore` is not edited.** `/target` at `.gitignore:8` already covers it.
  This is a positive property, not a convenience: `.gitignore`'s own safety rule
  forbids narrowing and prefers explicit deny-by-default patterns, and adding no
  pattern adds no chance of one shadowing something.
- **`verifier-web/` is source-only** and contains, after R23, exactly one file.
  R5 makes that an assertion.
- **The precedent is already in the tree**: `scripts/wasm-pack-build.sh` writes
  the module to `target/wasm-pack/antseal-wasm/`, and nothing about the page is
  more deployable than the module it contains.
- **For R26 this changes nothing and confirms everything**: D62 §3 R2 already
  rules the publishing source is GitHub Actions, so Pages **never** publishes
  from the tree, and the same clause names the hazard a committed artifact
  is — *"a hand-copied artifact between the build that was hashed and the bytes
  that are served."* R26 uploads what R25 built, from `target/verifier-web/`,
  in the same run.
- **For `git diff` this is the whole answer.** §1 (l)'s 4 912 507-byte diff and
  its lying `--stat` never occur, because no rebuild ever appears in a diff.
- **The tracked placeholder** is disposed of by R1.

**R5 — `verifier-web/` contains exactly the template, and that is asserted, not
remembered.** The template-side test home of R8 (b) carries one test asserting
that the set of files under `verifier-web/` is **exactly**
`{index.template.html}`. It fails on a stray build output, on a second template,
on an editor dropping, and on the reintroduction of `index.html`. Two things it
buys: the scan's domain cannot drift under the scan (R2's guard then means what
it says), and R4 is enforced by something other than discipline.

**R6 — The base64 is ONE LINE, unwrapped.** Not on the silent-skip hazard —
which §1 (g) measures as real and §1 (f) measures as inert — and not on
runtime, since `atob` accepts newlines in both engines (§1 i), and not on the
reader's check, which works either way (§1 j). On **determinism**: a wrap width
is a free parameter of a step whose output is hashed into the published CSP
(D129 §5 R6's `<H1>`), and §1 (k) measures five plausible implementations
splitting two ways on it — with the two library APIs a script would call
producing the unwrapped form **with no parameter at all**. One line has no
parameter to agree on, no default to inherit from a coreutils version or a
platform's BSD `base64`, and nothing for D63 §7 rule 2's two-runner
byte-identity to diverge on. D129 §5 R9 assertion 4's alphabet check stays
exactly as written — `[A-Za-z0-9+/=]`, with no newline admitted — which is only
true under this rule. **The packaging step calls the encoder with an explicit
no-wrap argument and asserts the token contains no `\n`.**

**R7 — What scans `verifier-web/` after R23, exhaustively.**

1. **The wording ban** — `verdict_wording.rs:860`, over the template, repaired
   by R1+R2. Direction: the template may not spell any of the 27
   `single_sourced()` needles.
2. **The residue assertion** — `verdict_wording.rs:884`, scoped **off**
   `verifier-web/` by R3. Direction: CLI only.
3. **The positioning vocabulary ban** — `verdict_wording.rs:594` — does **not**
   scan `verifier-web/` and is **not** extended here. It is a table test, its
   subject is `wording.rs`, and D63 §5 R6 already assigns page chrome to Q20's
   copy lint and Q28's sweep. §8 (i) records the gap rather than closing it by
   side effect.
4. **Traceability** — `scripts/check-traceability.py`, **extended**, and the
   extension is **R23's** because R23 lands the first citation-bearing file:
   - `CITATION_SCAN` at **`:615`** gains the entry `"verifier-web",` — a
     **directory** entry, so D123's per-entry rule filters it by suffix.
   - `CITATION_SUFFIXES` at **`:643`** gains `".html"`, giving
     `{".rs", ".md", ".json", ".py", ".sh", ".mjs", ".html"}`.
   - Measured cost: **420 → 421 files, zero collateral** (§1 n), against D123's
     refused `.toml` route at 359 → 377 with 15. The suffix route is chosen over
     D123's literal-file route because it survives a rename of the template and
     the arrival of a second source file, and because at zero collateral the
     objection that made D123 prefer naming does not arise.
   - The **flagless run is the check**; `check-traceability.py` has no
     `--check`.
5. **Nothing else.** In particular no new CI job is created by this record;
   §3 R8's homes ride jobs that exist.

**R8 — Where each kind of test lives, with the runner that executes it.**

| kind | home | runner | owner |
| --- | --- | --- | --- |
| (a) frozen-wording ban over the template; per-root guard; residue scoping | `crates/antseal-core/tests/verdict_wording.rs` (**already there**) | `cargo test` → CI job `test` | R23 |
| (b) assertions over the **committed template** — the D63 §5 R6 advice-line drift test, the CSP `<meta>` present with D129 §5 R6's literal directives, no `style=` attribute, all four placeholders present, R5's directory-contents assertion | **`crates/antseal-wasm/tests/page_template.rs`** (new file, `carriage.rs`'s precedent) | `cargo test` → CI job `test` | R23 authors; R25 adds the advice-line drift test |
| (c) assertions over the **built artifact** — D129 §5 R9 (1)–(7), D66's `page_csp_permits_connect_to_the_pinned_origins`, the `SHA256SUMS` one-line check, injector non-idempotence (D63 §5 R1) | **`scripts/verifier-page-build.sh`**, with `--build-only`, `--check` and `--self-test`, in `scripts/wasm-pack-build.sh`'s exact shape | the script; wired into `scripts/local-gate.sh` beside the other `--self-test`-then-lane pairs | R25 |
| (d) assertions requiring a **browser** — D129 §5 R9 (8), R27's parity gate, offline zero-requests, drag-and-drop | `scripts/verifier-page-browser.mjs` driven by a `--self-test`-bearing shell entry point, in `scripts/wasm-boundary.mjs`'s venue | node, **locally** per the maintainer's Q19 ruling; the workflow file is authored and committed but is **not** added to the required-contexts matrix | R27 authors the suite; Q19 owns the lane |

Three things fix these homes rather than taste. **(b) is a crate and not
`antseal-core`** because `carriage.rs` set the rule that a scan belongs to the
thing it is about and core is not to grow page concerns; `cargo test -p
antseal-wasm` runs natively today with 14 tests green (§1 o), and
`verifier-web/` cannot be a member at all (§1 o, D18 §4.2). **(c) is a script
and not a `cargo test`** because its subject does not exist until something
builds it: §1 (h) measures the wording suite's own runtime moving 0.62 → 0.87 →
1.13 s purely with the contents of a directory, and a test that passes or fails
on whether a build has happened is the same pathology one file over. **(d) is
`.mjs` and not `package.json`** because the repo has neither a `package.json`
nor a `node_modules` (§1 o) and D129 drove both engines over raw CDP without
one.

**R9 — What this ruling does not permit.**

- **No `.gitignore` entry for `verifier-web/`, and no negated pattern.** Under
  R4 there is nothing to ignore, and an ignore rule over a source directory is
  how a source file stops being committed by accident.
- **No build output under any scanned root** — not `verifier-web/`, not
  `crates/`, not `docs/`, not `scripts/`. R5 asserts the one that matters.
- **No second copy of the built page anywhere in the tree**, under any name,
  including `dist/`, `public/` or `site/`. One build output path, `target/`.
- **No `.template` (or `.tpl`, or `.in`) suffix in either suffix list.** Both
  lists are then carrying a suffix minted for one file, and — measured, §1 (a) —
  the wording scan's list and the traceability list are separate constants, so
  a `.template` name obliges **both** to learn it or leaves one blind. An
  `.html` template needs neither to change except the one addition R7 (4) rules.
- **No widening of `verdict_wording.rs`'s walk suffix list** to reach a
  template. R1 makes the walk unnecessary to change, which is the point of
  choosing the name over the filter.
- **No new required CI context** from this record. The GIVEN's Q19 tier stands;
  §7 records what that leaves unwitnessed.

---

## 4. Refused shapes

| shape | refused on |
| --- | --- |
| `verifier-web/index.html.template` (D129 §7's name) | measured invisible to the scan D129 says will scan it: `extension()` is `Some("template")`, and a planted frozen sentence leaves all nine tests green (§1 a, b) |
| `index.html.tpl` · `index.html.in` · `index.htm` | same escape, same measurement (§1 a) |
| keeping the template at `verifier-web/index.html` | walked, so it fixes the scan — but it puts template and artifact under one basename, and the assertion that the injector never writes over its input becomes a path comparison instead of a name difference. R1 keeps D129 §7's intent at zero cost |
| fixing the escape by adding `"template"` to `verdict_wording.rs:941`'s suffix list | fixes one scan and leaves `check-traceability.py`'s separate suffix constant blind, so the same name must be learned twice — and it leaves the vacuity guard of §1 (c) untouched, which is the defect that recurs |
| the rename **alone**, without the per-root guard | measured: with `verifier-web/` empty of walked files the scan reports 54 files and passes. A rename is a patch on one instance; §1 (c) is the class (§2.1) |
| leaving `every_recorded_residue_is_still_there` over the union | measured: a page-side copy of a `RESIDUE` needle keeps it green through the CLI deletion it exists to catch — red, then green, same CLI state (§1 e) |
| extending the `BANNED_TOKENS` positioning test to `verifier-web/` | it reads no files at all (`:594`, over `rendered_rows()`); making it a file scan is a different test with a different subject, and D63 §5 R6 already routes page chrome to Q20/Q28. Recorded as a real gap in §8 (i), not closed by side effect |
| committing the built `index.html` | it is D62 §3 R2's named hazard — *"a hand-copied artifact between the build that was hashed and the bytes that are served"* — and D129 §6's refused hybrid one level out: a second byte sequence claiming to be the antseal verifier, one stale rebuild from disagreeing with the template and module it names |
| committing it **and** wrapping the base64 to keep diffs small | the 876-byte diff is real (5 608× smaller, §1 l) and it buys a reviewable diff of an artifact that should not be in the review at all; it also accepts a `--stat` that says *"1 insertion(+), 1 deletion(-)"* for a whole-payload change |
| a `dist/` or `public/` output directory | needs a new `.gitignore` pattern where `/target` already suffices, and mints a second build-output convention against `scripts/wasm-pack-build.sh`'s existing one |
| line-wrapped base64 | wrap width is a free parameter of a step whose output is hashed into the CSP; five implementations split two ways, and the two library APIs default to unwrapped (§1 k). Also doubles the scan cost where a scan sees it (§1 h) and forfeits D129 §5 R9 assertion 4's newline-free alphabet check |
| wrapping **because** of the `//` silent skip | the skip is real and 6.2× underestimated, and it cannot hide a frozen sentence: zero of `wording.rs`'s 131 literals is base64-shaped (§1 f, g). The stated reason does not carry the ruling; §1 (k) does |
| refusing wrapping because it would break `atob` | measured false in both engines: `atob` accepts newlines and spaces, and both arms decode to the identical 1 841 981 bytes (§1 i) |
| putting the built-artifact assertions in a `cargo test` | its subject does not exist until a build runs; §1 (h) measures a sibling suite's runtime moving 0.62 → 1.13 s on directory contents alone, and a test that depends on whether somebody built is not a test |
| putting the template assertions in `antseal-core` | `carriage.rs`'s precedent is that a scan belongs to the thing it is about, and core is the WASM-safe frozen-format crate. `antseal-wasm` is the page's crate by D18 §5 R1 and runs natively today (§1 o) |
| a `verifier-web/tests/` directory | no runner can reach it: `verifier-web/` is not and cannot be a Cargo member (`.cargo/config.toml`'s two-level runner path, D18 §4.2) |
| introducing `package.json` + Playwright for (d) | the repo has no `package.json` and no `node_modules`; D129 drove Chromium **and** Firefox over raw CDP with neither. A first npm dependency is a supply-chain decision, not a test-venue detail (§8 ii) |
| adding `.template` to `CITATION_SUFFIXES` | a suffix minted for one file, in a constant D123 spent a wave teaching to be read as a directory rule; `.html` costs the same and generalizes (§1 n) |
| naming the template as a **literal** `CITATION_SCAN` entry (D123's route) | correct and cheaper by one suffix, but it does not survive a rename or a second source file, and D123 preferred naming precisely where the suffix route had **collateral**. Here it has none (§1 n) |
| a new required CI context for the page | outside this record: the maintainer's Q19 tier is given. §7 records the consequence rather than re-ruling it |

---

## 5. What R23 / R25 / R26 / R27 / Q19 must implement

**R23** — in one commit:

1. Author `verifier-web/index.template.html` (§3 R1), with everything D129 §7
   already specifies of it: four visible placeholders, the §5 R6 CSP verbatim,
   one inline `<style>`, no `style=` attributes, a `data:` icon or none,
   drag-and-drop plus file-picker, `initSync({ module })` and never the default
   init.
2. **Delete `verifier-web/index.html`** (§3 R1).
3. Repair the scan, in `crates/antseal-core/tests/verdict_wording.rs`:
   **delete** the `sources.len() > 10` assertion at `:863` and replace it with
   the per-root floors of §3 R2 (`crates/antseal-cli/src` ≥ 40,
   `verifier-web` ≥ 1, each with its own message); **scope**
   `every_recorded_residue_is_still_there` at `:884` to the CLI root (§3 R3).
   Both changes ride the existing `test` job.
4. Widen traceability (§3 R7 (4)): `"verifier-web",` into `CITATION_SCAN` at
   `scripts/check-traceability.py:615`, `".html"` into `CITATION_SUFFIXES` at
   `:643`. Verify with the **flagless** run; expect the swept-file count to move
   by exactly one.
5. Create `crates/antseal-wasm/tests/page_template.rs` with the template-side
   assertions of §3 R8 (b), including §3 R5's *"`verifier-web/` contains exactly
   `index.template.html`"*.
6. **Plant a fault against each new assertion before believing any of them.**
   The class this record exists to fix is the assertion that cannot fail; the
   arm in §1 (b) is the pattern, and its failure message names the file and line.

**R25** —

1. `scripts/verifier-page-build.sh`, with `--build-only`, `--check` (default)
   and `--self-test`, in `scripts/wasm-pack-build.sh`'s shape: build, package,
   then assert. Output to **`target/verifier-web/index.html`** (§3 R4); inputs
   are `verifier-web/index.template.html` and R22's `target/wasm-pack/…`
   artifacts.
2. Base64 with an **explicit no-wrap argument**, and assert the token contains
   no `\n` (§3 R6). D129 §5 R9 assertion 4's `[A-Za-z0-9+/=]` alphabet check
   stays literal.
3. Host D129 §5 R9 (1)–(7) and D66's
   `page_csp_permits_connect_to_the_pinned_origins` — which D66's own table
   calls an *"R23/R25 build check, **no network**"* that *"runs against the built
   artifact"*, i.e. exactly this venue — plus the D129 §5 R6 addition that a
   **non-pinned `https:` origin is permitted**.
4. The advice-line drift test (D63 §5 R6, §7 rule 5) goes in
   `crates/antseal-wasm/tests/page_template.rs`, not in the script: its two
   subjects — `MVP-SPEC.md` line 139 and the committed template — are both
   tracked files that exist without a build.
5. Wire the script into `scripts/local-gate.sh` as a `--self-test`-then-lane
   pair, beside `gate-features` and `format-freeze`.
6. Nothing in this record touches R25's open preconditions: path remapping and
   the unpinned binaryen its own `Notes` record are exactly where D63 §7 rule 1
   and D129 §7 leave them.

**R26** — deploys `target/verifier-web/index.html` produced by R25 **in the same
workflow run**, never a tree file. D62 §3 R2's Actions publishing source is
confirmed by this ruling rather than changed by it, and its warning about a
hand-copied artifact is now structurally unreachable: there is no tree copy to
hand-copy. Everything else in D129 §7's R26 paragraph stands.

**R27 / Q19** — the browser venue of §3 R8 (d): `scripts/verifier-page-browser.mjs`
behind a `--self-test`-bearing entry point, driven over CDP against the artifact
at `target/verifier-web/index.html` at a `file://` origin. **Per the
maintainer's given ruling the lane runs locally**; the workflow file is authored
and committed and is **not** added to the required-contexts matrix, so it costs
zero Actions minutes until enabled. §7 records what that leaves unwitnessed.
R27 additionally owns the first page-side exercise of the richer anchor states
(D129 §10 (iii)).

---

## 6. Spec conformance

- **Line 123 — format stability.** Untouched. **Zero frozen bytes**: no registry
  key, error code, HKDF label, domain tag, golden vector or wording snapshot
  moves. The wording *snapshot* is not touched either — §3 R2 and R3 change the
  scan's **domain**, never its needles, and the ban's 27 needles and the
  residue's 6 are unchanged in content and count.
- **Line 127 — *"Plain HTML/JS + `antseal-core` WASM … Offline-first: full local
  verification"*.** Unaffected by where files live. §3 R4 makes the offline
  artifact reachable only by building it, which is the same act D129 §5 R1
  already required.
- **Lines 128–136 — the verdict taxonomy and the one authoritative wording
  set.** This is the line these rules exist to protect. Spec line 127's
  *"one authoritative wording set; M3 snapshot-tests it"* is enforced for the
  page by the scan at `verdict_wording.rs:860` and by nothing else, and §1 (c)
  measures that enforcement going to **zero** in R23's landing commit under
  D129's name. §3 R1–R3 are the conformance repair.
- **Line 137 — *"No framework, no build beyond `wasm-pack`"*.** Held. §3 R6's
  explicit no-wrap argument keeps the packaging step inside D63 §5 R5's closed
  operation list as D129 §11.4's rider extends it (*"deterministic textual
  encodings of build inputs, with base64 named"*), and adds no tool. §3 R8 (d)'s
  refusal of `package.json` keeps the repo's build surface where line 137 puts
  it.
- **Line 139 — page provenance.** Strengthened in one place and unchanged
  elsewhere. The footer digest, the published SHA-256 over the served closure
  and the canonical URL are untouched. What changes is that the bytes carrying
  them now exist in exactly **one** place per lifecycle stage — template in the
  tree, artifact in `target/`, served copy at the canonical URL, signed copy in
  the release — with no fourth copy in git to go stale, which is D62 §3 R2's own
  stated reason for an Actions publishing source.

---

## 7. Residual risk

- **The page's own copy is under no banned-token scan** (§1 d). `notary`,
  `priority` and `certify` are banned in the wording *table* and nowhere in
  `verifier-web/`. D63 §5 R6 assigns page chrome to Q20's copy lint and Q28's
  sweep, and neither exists yet. Between R23 and Q20 the page's positioning copy
  is reviewed by humans only. Named in §8 (i); deliberately not closed here,
  because a file scan for those tokens over an HTML page is a different
  instrument with its own false-positive surface.
- **The browser half stays unwitnessed by CI, and this reproduces R82.** The
  maintainer's Q19 tier is given and not re-ruled — but the consequence is worth
  stating in the same words the wave already uses for `heavy-features`: a lane
  that runs only on one machine is not evidence about any other machine, and
  D129 §5 R9 assertion 8 is *"the assertion that would have caught every failure
  mode in §1"*. Until the workflow enters the required matrix, the strongest
  check this project has over the page runs at one developer's discretion.
- **`scripts/wasm-pack-build.sh` is still called by no workflow** (§1 m). §3 R8
  (c) adds a second such script. `scripts/local-gate.sh` wiring makes both
  runnable-before-push, which is the mitigation this repo already relies on, and
  it is weaker than a required context.
- **The per-root floor of 40 is a number that can rot.** It is chosen with 54
  CLI files present; a legitimate consolidation could take the CLI under 40 and
  redden the lane for the wrong reason. That is the intended failure direction —
  loud and immediately diagnosable from the message — but it is a maintenance
  cost and it is real.
- **§3 R5's directory-contents assertion will fail on an editor dropping.** A
  `.swp` or `~` file under `verifier-web/` reddens `cargo test`. Judged correct:
  the alternative is an assertion with an exception list, which is how a
  directory quietly acquires a second file.
- **The traceability widening reaches a file class nothing else in the sweep
  contains.** `.html` joins a suffix set of six that has only ever held code and
  prose. Zero collateral today (§1 n) is a fact about today's tree; a future
  `docs/testing/*.html` would enter the sweep unremarked.
- **This record does not make the built page reproducible.** R25's Accept row 1
  stands exactly where D63 §7 rule 1, D129 §7 and R25's own binaryen note leave
  it. §3 R6 removes **one** free parameter from the packaging step; the module's
  own preconditions are untouched.

---

## 8. Discovered work — described, not registered

No ids are minted here.

**(i) The positioning-vocabulary ban has never covered the verifier page, and
after R23 that is a real hole rather than a vacuous one.**
`the_wording_set_satisfies_the_positioning_checklist`
(`verdict_wording.rs:594`) sweeps `rendered_rows()` — the in-memory table — for
twelve banned tokens including `notary` and `priority`, MVP-SPEC line 28's two
named prohibitions. It opens no file. Today that is harmless: `verifier-web/`
holds 484 bytes of placeholder. From R23 it holds the page's entire authored
copy, including headings, the drop-zone prompt and the footer, and none of it is
under any token ban. D63 §5 R6 routes that copy to Q20's style guide and Q28's
sweep, both unwritten. **Instrument-shaped**, adjacent to Q20; recorded so R23
does not read the existence of a positioning test as coverage of its own prose.

**(ii) A browser lane need not be this repo's first npm dependency.** Q19's `Do`
says *"install playwright + chromium in CI"*. D129 §1 drove **both** Chromium
150 and Firefox 140.13.0esr — CSP violation events, `Log.entryAdded`,
`Network.requestWillBeSent`, `DOM.setFileInputFiles`, real drag dispatch — from
a raw WebSocket over the DevTools Protocol, with **no puppeteer and no
playwright**, and this lane reproduced the pattern for §1 (i)'s beacon arm. The
repo has no `package.json` and no `node_modules` (§1 o), and `node` is already
required by `.cargo/config.toml`'s wasm32 runner. So the choice between "add
Playwright" and "drive CDP directly" is a live one with a measured precedent on
both engines, and it is a supply-chain decision — a first `package.json`, a
lockfile, a browser download step — rather than a test-harness detail. **Adjacent
to Q19**; recorded before Q19 writes the dependency in.

**(iii) `renderer_sources()` conflates two domains and the fix generalizes.**
§3 R2 and R3 both come down to the same shape: one function returns a flat list
built from two roots, and two callers want different subsets of it. The same
shape is what `docs/instrument-ledger.md:97` records for `crates/antseal-wasm` —
a third root the scan does not cover at all. A `renderer_sources()` that returns
per-root groups makes all three questions answerable in one place, and makes
adding `crates/antseal-wasm/src` later a one-line change with a guard that
notices if it goes empty. **Instrument-shaped**, adjacent to R18.

**(iv) The traceability sweep's own domain statement is its only self-check, and
a generated artifact would pollute it.** §1 (n) measures a built page
contributing two spurious bare task ids (`P7`, `Q1`) and one real decision
citation to the counts the lane prints. Both resolve, so the lane stays green
and only the number moves — which is exactly the failure mode Q211's problem
statement describes (*"a widening that silently reaches nothing … produce a green
line with a different number and no other signal"*). §3 R4 keeps generated files
out of every scan root, so the exposure is closed by construction here; it is
recorded because the general property — **no scan root may contain generated
files** — is not written down anywhere in the repo and is worth one line
somewhere that a future widening will be read.

---

## 9. Quoted entry notes (registrar's to apply)

### 9.1 `tasks/R.md` R23 — append a `Notes` line

> - Notes: **[D131, 2026-08-12]** The directory footprint is ruled
>   (docs/decisions/D131-the-verifier-web-directory-footprint.md), and it
>   **corrects the template filename this row already carries**. The template is
>   **`verifier-web/index.template.html`**, not `index.html.template`:
>   `Path::new("index.html.template").extension()` is `Some("template")`, which
>   `crates/antseal-core/tests/verdict_wording.rs:941`'s
>   `matches!(ext, "rs" | "html" | "js" | "css")` does not walk — measured with a
>   **planted frozen sentence**, which under D129's name leaves all nine tests
>   green and under the ruled name turns the scan red naming
>   `verifier-web/index.template.html:2`. `index.html.tpl` and `index.htm`
>   escape identically. **The 484-byte placeholder `verifier-web/index.html` is
>   DELETED in this row's commit**, leaving the directory source-only with
>   exactly one file. **The name is the symptom; the guard is the defect**:
>   measured, with `verifier-web/` holding only an unwalked template the scan
>   reports **54 files, all from `crates/antseal-cli/src`**, page coverage
>   **zero**, and `sources.len() > 10` at `:863` cannot fire because the CLI
>   alone supplies 54 — so this row **deletes that assertion** and replaces it
>   with **per-root floors** (`crates/antseal-cli/src` ≥ 40, `verifier-web` ≥ 1,
>   each with its own message). A **second defect, not previously recorded**:
>   `every_recorded_residue_is_still_there` at `:884` reads the **union** of both
>   roots, so a page-side copy of a `RESIDUE` sentence **masks** its deletion
>   from the CLI — measured RED with the deletion alone, then GREEN with a
>   `verifier-web` file carrying the string — so this row **scopes the residue
>   assertion to `crates/antseal-cli/src`**. The two file-walking tests want
>   opposite domains and may not share one source list. This row also makes the
>   **traceability widening**, since it lands the first citation-bearing file
>   there: `"verifier-web",` into `CITATION_SCAN`
>   (`scripts/check-traceability.py:615`) and `".html"` into
>   `CITATION_SUFFIXES` (`:643`) — measured **420 → 421 files with ZERO
>   collateral**, because no `.html` file exists under `crates/`, `docs/format/`,
>   `docs/testing/` or `scripts/` (against D123's refused `.toml` route at
>   359 → 377 with 15); the **flagless run is the check**, there is no `--check`
>   flag. Template-side assertions — the CSP `<meta>` present with D129 §5 R6's
>   literal directives, no `style=` attribute, all four placeholders present, and
>   *"`verifier-web/` contains exactly `index.template.html`"* — go in a new
>   **`crates/antseal-wasm/tests/page_template.rs`** (`tests/carriage.rs`'s
>   precedent: a scan belongs to the crate it is about, and core is not edited).
>   **Plant a fault against every new assertion before believing it** — the class
>   this ruling repairs is precisely the assertion that cannot fail.
>   **One gap named and deliberately NOT closed here**: the positioning
>   vocabulary ban at `:594` reads the in-memory wording table and **opens no
>   file**, so `notary`/`priority`/`certify` are banned in the table and nowhere
>   in `verifier-web/` — this row's authored chrome is under no token scan, and
>   D63 §5 R6 routes it to Q20/Q28 (D131 §8 (i)).

### 9.2 `tasks/R.md` R25 — append a `Notes` line

> - Notes: **[D131, 2026-08-12]** Build output and test venue ruled
>   (docs/decisions/D131-the-verifier-web-directory-footprint.md). **The built
>   page is NEVER committed and never written into `verifier-web/`**: it is built
>   to **`target/verifier-web/index.html`**, which `/target` at `.gitignore:8`
>   already covers, so **`.gitignore` is not edited at all** — the precedent is
>   `scripts/wasm-pack-build.sh`, which already writes the module to
>   `target/wasm-pack/antseal-wasm/`. A committed artifact is D62 §3 R2's named
>   hazard in the tree — *"a hand-copied artifact between the build that was
>   hashed and the bytes that are served"* — and D129 §6's refused hybrid one
>   level out. Cost of the alternative, measured: a **one-byte** change to a
>   committed one-line page produces a **4 912 507-byte `git diff`** whose
>   `--stat` reads *"1 insertion(+), 1 deletion(-)"*; wrapped at 76 the same
>   change is **876 bytes**, 5 608× smaller — the one real argument for wrapping,
>   and it evaporates when the artifact is not in the tree. **The base64 is ONE
>   LINE**, and **not** on the `//`-skip footgun (real — **49** `//`-prefixed
>   lines at wrap-76, **6.2×** the uniform prediction — but **inert**, since zero
>   of `wording.rs`'s 131 literals is base64-shaped) and **not** on runtime
>   (`atob` accepts newlines and spaces in **both** Chromium 150 and Firefox
>   140.13.0esr; both arms decode to the identical 1 841 981 bytes) and **not**
>   on the reader's check (extract-decode-hash reproduces the module digest
>   either way, 51 ms vs 29 ms). It is ruled on **determinism**: wrap width is a
>   free parameter entering the hashed script text and therefore the published
>   CSP hash, and five plausible implementations split two ways on it — GNU
>   `base64` (no flag) and Python `encodebytes` wrap at 76; `base64 -w0`, Python
>   `b64encode` and Node `Buffer.toString('base64')` do not. **Call the encoder
>   with an explicit no-wrap argument and assert the token contains no `\n`**;
>   D129 §5 R9 assertion 4's `[A-Za-z0-9+/=]` alphabet check then stays literal.
>   **Venue**: D129 §5 R9 (1)–(7), D66's
>   `page_csp_permits_connect_to_the_pinned_origins` (which D66 already calls a
>   *no-network build check against the built artifact*) plus D129 §5 R6's
>   non-pinned-`https:`-permitted half, the one-line `SHA256SUMS` and D63 §5 R1's
>   injector non-idempotence all live in **`scripts/verifier-page-build.sh`**
>   with `--build-only` / `--check` / `--self-test`, in
>   `scripts/wasm-pack-build.sh`'s exact shape, wired into
>   `scripts/local-gate.sh` as a self-test-then-lane pair. **They are not a
>   `cargo test`**: their subject does not exist until a build runs, and measured,
>   the sibling wording suite's own runtime moves **0.62 s → 0.87 s → 1.13 s**
>   purely with what happens to be sitting in `verifier-web/` — a test that
>   depends on whether somebody built is not a test. The **advice-line drift
>   test** (D63 §5 R6 / §7 rule 5) is the exception and goes in
>   `crates/antseal-wasm/tests/page_template.rs`, because both its subjects —
>   `MVP-SPEC.md` line 139 and the committed template — are tracked files that
>   exist without a build. Nothing here touches this row's open preconditions:
>   path remapping and the unpinned binaryen stand exactly as D63 §7 rule 1 and
>   this row's own `Notes` leave them.

### 9.3 `tasks/R.md` R26 — append a `Notes` line

> - Notes: **[D131, 2026-08-12]** This row deploys **`target/verifier-web/index.html`
>   as produced by R25 in the same workflow run**, never a file from the tree
>   (docs/decisions/D131-…): the built page is not committed and
>   `verifier-web/` holds only the template. This **confirms D62 §3 R2 rather
>   than changing it** — the Actions publishing source exists precisely so that
>   *"R25's reproducible build is the thing that produces the deployed bytes"*
>   and so that no hand-copied artifact sits between the build that was hashed
>   and the bytes that are served; under D131 §3 R4 there is no tree copy to
>   hand-copy, so the hazard is structurally unreachable rather than merely
>   forbidden. Everything else in this row's D129 note stands: one file in the
>   closure, `Content-Type: text/html`, the two-encoding tripwire, and the
>   set-equality check written over served **responses** rather than requests.

### 9.4 `docs/decisions/D129-verifier-page-file-shape-and-the-in-artifact-csp.md` §7 and §11.1 — one rider, at both sites

> **[D131, 2026-08-12 — rider. One filename is corrected; no ruling of D129 is
> changed.]** §7 gives the committed template the name
> `verifier-web/index.html.template`, marked *"(name is R23's)"*, and §11.1's
> quoted `Notes` repeats it. **That name is invisible to the very scan this
> record's §10 (iv) says will be scanning it.** Measured (D131 §1 a, b):
> `Path::new("index.html.template").extension()` is `Some("template")`, and
> `crates/antseal-core/tests/verdict_wording.rs:941` collects only
> `"rs" | "html" | "js" | "css"` — so a frozen verdict sentence planted in a
> template under that name leaves all nine tests **green**, while the same
> sentence under `index.template.html` turns the scan **red** naming
> `verifier-web/index.template.html:2`. The template is therefore
> **`verifier-web/index.template.html`**, which keeps this section's intent — a
> name that distinguishes template from artifact in every citation — and adds
> the property it lacked. **Nothing else in §7 or §11.1 moves**: the four
> placeholders, the verbatim CSP, the single inline `<style>`, the absence of
> `style=` attributes, the `data:` icon and the `initSync({ module })` rule are
> unchanged. §10 (iv)'s open question is now answered in full by
> [D131](D131-the-verifier-web-directory-footprint.md), which additionally rules
> that the built page is **never** committed and never written into
> `verifier-web/` (it is built to `target/verifier-web/index.html`), that the
> base64 is **one line**, and that this record's §5 R9 assertions live in a
> build script rather than a `cargo test`.

### 9.5 `docs/decisions/D63-footer-build-hash-and-artifact-set.md` §10 (iv) — mark it answered, at the site

> **[D131, 2026-08-12]** **ANSWERED and CLOSED** by
> [D131](D131-the-verifier-web-directory-footprint.md). `verifier-web/` becomes a
> **source-only** directory holding exactly one committed file, the template
> `index.template.html`; the built page is never committed and is built to
> `target/verifier-web/`; the injector and packaging assertions live in
> `scripts/verifier-page-build.sh` (`--self-test`, the
> `scripts/wasm-pack-build.sh` shape, wired through `scripts/local-gate.sh`), the
> §7 rule 5 drift test and the template-side assertions in
> `crates/antseal-wasm/tests/page_template.rs`, and the browser assertions in a
> `scripts/*.mjs` driver under R27/Q19. The directory gains a **second** scan —
> `check-traceability.py`, `verifier-web` as a `CITATION_SCAN` root plus `.html`
> in `CITATION_SUFFIXES`, measured +1 file and zero collateral — which is the
> Q210-adjacent half of this observation. The *ban* scan root this paragraph
> names was additionally found to be **about to go vacuous**: D131 §1 (c)
> measures page coverage falling to zero, with all nine tests green, under the
> template name D129 §7 had minted.

### 9.6 `docs/instrument-ledger.md` — three entries

> - 2026-08-12 · D131 planning lane · **a scan root that silently contributes
>   zero files, behind a guard that cannot notice.**
>   `crates/antseal-core/tests/verdict_wording.rs` walks two roots and guards
>   itself with `sources.len() > 10` over their **union**; `crates/antseal-cli/src`
>   supplies 54, so the guard is satisfied forever no matter what the other root
>   contains. Measured with a planted frozen sentence: under the template name
>   D129 §7 minted (`index.html.template`, `extension()` = `Some("template")`)
>   page coverage is **zero** and all nine tests pass. **A guard over a union of
>   roots is not a guard on any of them** · crates/antseal-core/tests/verdict_wording.rs:863 · D131 §1 (c)
> - 2026-08-12 · D131 planning lane · **an assertion that a second root can
>   satisfy on the first root's behalf.**
>   `every_recorded_residue_is_still_there` asserts six sentences **present**
>   across the union of `crates/antseal-cli/src` and `verifier-web/`; measured,
>   deleting the CLI's copy turns it RED, and adding any `verifier-web` file
>   carrying the same string turns it GREEN with the deletion still in place. The
>   ban and the residue tests want **opposite** domains and shared one source
>   list · crates/antseal-core/tests/verdict_wording.rs:884 · D131 §1 (e)
> - 2026-08-12 · D131 planning lane · **`atob` accepts wrapped base64 in both
>   engines, and a build page's cost is where you put it.** Chromium 150 and
>   Firefox 140.13.0esr both decode newline- and space-bearing base64 to
>   identical bytes (forgiving-base64), so line-wrapping breaks no runtime; what
>   it does break is determinism — five plausible encoders split two ways on the
>   default wrap, and the width enters the hashed script text. Separately, the
>   wording suite's runtime moves 0.62 → 0.87 → 1.13 s purely with the contents
>   of `verifier-web/`, which is why build-artifact assertions belong to a build
>   script and not to `cargo test` · scripts/ · D131 §1 (h)(i)(k)

### 9.7 Registrar's edit set

**This lane wrote one file: this one.** Everything below is instruction.

1. `TODO.md` decision register, the **D131** line → the resolved form supplied
   in the lane's closing report.
2. `docs/decisions/README.md` → one index row for this record, in ascending id
   order, status/date taken from this record's own `- **Status`/`- **Date`
   lines (D119 RULING 1/3; the row rides this record's commit per D119 RULING 6).
3. `tasks/R.md` → R23 gains §9.1, R25 §9.2, R26 §9.3. **R23's existing D129
   `Notes` line at `tasks/R.md:297` carries the escaping filename
   `verifier-web/index.html.template` in its final clause and must be corrected
   to `verifier-web/index.template.html` in the same act** — a registrar
   correction applying §9.4's rider, not a new ruling.
4. `docs/decisions/D129-…` → the rider of §9.4, placed at **both** §7 (R23's
   paragraph) and §11.1 (the quoted `Notes`), in the at-the-site style D63
   already carries for its own amendments.
5. `docs/decisions/D63-…` → §10 (iv) marked answered per §9.5, at the site.
6. `docs/instrument-ledger.md` → the three entries of §9.6.
7. **No edits** to `MVP-SPEC.md`, `docs/format/registry-v1.md`, the frozen
   registry, `wording.rs`, any snapshot, any golden vector, any fixture, or any
   product code are requested by this ruling. **Zero frozen bytes.** The scan
   changes of §3 R2/R3 move a test's **domain**, never its needles: the ban's 27
   and the residue's 6 are unchanged in content and in count.

---

## Outcome

D63 asked what CI does with `verifier-web/` and answered nothing, twice — its
own §10 (iv), and D129's forwarding of it unchanged. The answer turns out to be
that CI does nothing with it today and would go on doing nothing while believing
otherwise, because the name D129 minted for the template is invisible to the one
scan that reaches the directory at all. That much the survey found. What
measurement adds is that the name is the smaller half. Rename the file and the
scan works; leave the guard as it is and the next rename, or the next suffix, or
a typo as small as `index.htm`, empties the root again with all nine tests
green — because the guard counts a union that fifty-four CLI files satisfy on
their own. So the guard is ruled per-root, and the class closes rather than the
instance.

Underneath it sat a second defect nobody had named, running the other way. The
residue assertion pins six sentences **present**, over the same union, so the
moment the page carries a sentence the CLI also carries, deleting the CLI's copy
stops reddening anything. Measured red, then green, with the CLI unchanged. One
of these two tests wants the page in its domain and the other wants it out, and
they had been sharing a domain for as long as `verifier-web/` held nothing worth
scanning.

The rest followed from refusing a premise rather than optimizing inside it. A
2.47 MB build artifact in the tree makes every rebuild a 4.9 MB diff whose
`--stat` says *one insertion, one deletion*; the tempting fix is to wrap the
base64, which shrinks that diff by five thousand six hundred fold and is the
only argument wrapping has. D62 had already ruled the deploy publishes from a
build and not a branch, and named the committed artifact as the hazard that
choice exists to prevent. So the artifact leaves the tree, `.gitignore` needs
nothing because `/target` already covers it, and the wrap question loses its
case — along with the footgun that was supposed to decide it, which is real,
six times more common than predicted, and cannot hide a frozen sentence, and
along with the runtime objection, which two browsers refuted by decoding wrapped
base64 to the same 1 841 981 bytes. What survives is the smallest reason and
the only durable one: a wrap width is a parameter, five implementations of the
same step split two ways on it, and it lands inside a hash the page publishes
about itself.
