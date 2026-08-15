# D63 — Footer build-hash mechanism, and the exact artifact set the published SHA-256 covers

- **Status: RESOLVED — the footer's digest is INJECTED AT BUILD TIME and is
  the SHA-256 of the deployed `.wasm` module exactly as the browser loads it
  (64 ungrouped lowercase hex chars), rendered beside the identity fields the
  module exports about itself (core version, supported format versions,
  source commit — R22's already-written "build info for the footer") and the
  spec's verbatim advice line. The published artifact is a `SHA256SUMS`
  manifest over the COMPLETE SERVED CLOSURE — `index.html` and every
  subresource, post-injection, content-decoded — which lives with the SIGNED
  RELEASE and is never authoritative when served by the page's own host. The
  chicken-and-egg is cut by rule 3+4 together: the footer names the one
  artifact that cannot contain it, and the manifest — which is outside its
  own list — covers everything including the injected file.** The register's
  **dichotomy is half overturned**: as the mechanism for the *digest* it is
  real and **build-time injection wins ON MEASUREMENT** (the runtime
  self-hash breaks the `file://` mode R23's Accept requires, costs a second
  full read of the module, makes the footer async, and defends nothing extra
  — measured in §3); as the mechanism for *the footer* it is **false**,
  because the footer carries two classes of datum with exactly one possible
  source each, and R22's Do already committed the module to exporting the
  second class. The **unexamined assumption that one artifact set is
  obviously right is also overturned**: the footer's set and the published
  set are **deliberately different sets** (one file vs the whole closure),
  and collapsing them is precisely what creates the circularity.
- **Date: 2026-08-12** (wave 18 Act 1, D63 planning lane; briefed to overturn
  the dichotomy itself. One arm dies on measurement, the framing dies on
  R22's own text, and the "obviously right" artifact set turns out to be two
  sets. One arm nobody supplied — a build id over build *inputs* — is refused
  too, on verifiability rather than on taste.)
- **Owning tasks: R25** (the build script, the sums artifact, the footer —
  its Do names this as the open decision), **R22** (exports the identity
  half; its Do already says *"build info for the footer"*), **R23** (renders
  the footer; owns the page's file shape, which this record is deliberately
  written to survive either way), **R26** (deploys the set and scripts the
  served-bytes check), **Q19/Q31** (consume "the wasm build hash" by name),
  **Q28** (footer copy in the corpus sweep).
- **Amends**: `tasks/R.md` R25 (`Notes` added), R22 and R26 (`Notes` added),
  and the `Open decisions (R)` bullet for the footer build hash — all quoted
  in §11, the registrar's to apply. **Supersedes**: nothing. **Corrects**:
  nothing in code; one stale factual claim in an open row is reported to the
  ledger (§10 (i)).

---

## 1. What was measured

**(a) The spec's two sentences, quoted, and what each one actually decides.**

`MVP-SPEC.md` line 139:

> **Page provenance** (the page is itself a trust point — any host can serve
> lying JS): reproducible `wasm-pack` build with a published SHA-256 and
> signed releases; **one canonical URL** used in all docs and printed by the
> CLI in `reveal` output; the page footer displays its own build hash + "for
> high-stakes verification, run `antseal verify` and compare verdicts". Page
> hosting/deploy is an M3 deliverable.

`MVP-SPEC.md` line 186:

> - **Malicious verifier host** → reproducible build, published hash,
>   canonical URL, footer build-hash, CLI cross-check advice.

Line 186's mitigation for the malicious host is a list of **five** items. The
footer build-hash is **one** of them and — §2 proves — the only one of the
five that is *computed by the adversary*. The spec never says the footer
defends against the host; it lists the footer among the things that, taken
together with a *published* hash, *signed* releases, a *canonical* URL and
*CLI cross-check*, address that risk. Reading line 186 as "the footer is the
malicious-host mitigation" is the misreading this record exists to prevent.

**(b) Line 139's own advice line names the real mitigation, and it is not a
hash.** *"for high-stakes verification, run `antseal verify` and compare
verdicts"* routes the reader to a **different implementation, on a different
machine, under their own control**. That is the one thing in the footer a
lying host cannot forge, because it does not execute on the host's page. The
spec put it *next to* the hash for exactly that reason.

**(c) The advice line is NOT in R18's frozen wording set — measured.**

```
$ grep -rn "high-stakes" --include=*.rs --include=*.md --include=*.json \
    --include=*.txt --include=*.snap --include=*.html --include=*.js .
MVP-SPEC.md:139:...
SPEC-REVIEW.md:287:...
tasks/R.md:310:...
$ grep -n "high-stakes\|antseal verify\|compare verdict\|footer\|build hash" \
    crates/antseal-core/tests/snapshots/verdict-wording.txt
$ echo $?
1
```

The committed R18 document is 127 lines and contains **none** of those
tokens. So R25's Accept row (`tasks/R.md:314` — *"plus the advice string
(snapshot/playwright-asserted)"*) has **no snapshot to assert against
today**: R25 must create that pin itself, and this record must say where the
string lives so a second spelling cannot arise. **§5 R6 rules it.**

One spelling hazard found while measuring: `SPEC-REVIEW.md:287` renders the
sentence **without the comma** (*"for high-stakes verification run"*).
`MVP-SPEC.md` is frozen Revision 2 and outranks; the comma form at line 139
is normative. `tasks/R.md:310` already carries the correct form.

**(d) R22's Do already commits the module to exporting footer material.**
`tasks/R.md:273`: *"exports for core version, format versions supported, and
**build info for the footer**. No I/O inside the WASM module."* This is the
sentence that breaks the register's dichotomy. Part of the footer comes from
**inside** the artifact by a decision already taken, regardless of how the
digest gets there — so "build-time injection **vs** runtime self-hash" is not
a choice between two producers of the footer. It is a choice between two
producers of **one field** of it.

**(e) Three downstream consumers already name the value "the wasm build
hash", in their own words, written before this decision.**

- `tasks/Q.md:382` (Q19, playwright): *"log the **wasm build hash** of the
  page under test."*
- `tasks/Q.md:512` (Q31, release): *"publish a draft release containing
  artifacts, hashes, **the wasm build hash**, and a release-notes
  template."*
- `tasks/Q.md:1026` (Q's cross-domain expectations of R): *"reproducible
  wasm-pack build recipe + **build hash** for Q19/Q31."*

Three independent rows, none of them R's, already read the published
identifier as **the wasm module's** digest. That is a measured convergence,
not a preference, and §4 shows it is also the only non-circular choice.

**(f) The published artifact is a per-file manifest over the served set —
also already written.** `tasks/R.md:310` (R25 Do): *"Emit a SHA-256SUMS
artifact **over the page file set** for publication."* `tasks/R.md:323` (R26
Accept): *"Canonical URL serves the page; **served bytes hash-match the
published SHA-256SUMS** (scripted check)."* So the published thing is plural
and per-file, and its correctness condition is stated against **what the host
serves** — not against what the build directory happens to contain. Both
halves of §5 R4 are the spec-adjacent text's, not this lane's invention.

**(g) `verifier-web/` is a 12-line placeholder with no build, no lane, and no
membership.** `verifier-web/index.html` is 484 B and says *"Offline verifier
page — arrives at M3 (R23)"*. It is **not** a workspace member
(`Cargo.toml` `members` lists five crates, none of them the page), appears in
**no** CI workflow, and is referenced from live code in exactly one place:
`crates/antseal-core/tests/verdict_wording.rs:710`, where it is a **scan
root** for R18's ban on renderers spelling frozen verdict sentences. That
scan is a **prohibition**, not coverage: it asserts the page does not
re-spell table rows; it asserts nothing about strings the table does not
contain — which is exactly the advice line's situation (c).

**(h) The reproducible build does not exist and cannot be run here.**

```
$ which wasm-pack wasm-bindgen        # (no output)
$ rustc --version
rustc 1.92.0 (ded5c06cf 2025-12-08)
```

Neither tool is installed on this machine, and neither is pinned in the repo
— **deliberately**. `docs/wasm-toolchain.md` §4 is titled *"wasm-pack /
wasm-bindgen: deliberately not pinned yet"* and gives three reasons, the
governing one being that a pin *"would pre-empt **D18** … and R22's
reproducible-build pin"*. `docs/dependency-policy.md` §5 says the same
(*"**neither is installed yet**"*), and `scripts/wasm-toolchain-audit.sh`
carries a live check that prints `N/A` until the first pin appears and starts
enforcing crate↔CLI equality with no further wiring. **So the brief's "run
two builds and diff them" is not available**, and R25's Accept row
(`tasks/R.md:312`, *"Two clean CI builds (different runners) produce
byte-identical artifacts"*) is not measurable today. What is missing, named:
a `wasm-pack` pin, a `wasm-bindgen` crate pin equal to a `wasm-bindgen-cli`
pin, and **D18** (which of the two homes the surface lives in).

**(i) No determinism machinery exists — three greps, all empty.**

```
$ grep -rn "remap-path-prefix" .   (excluding target/, .git/)      → 0 hits
$ grep -rn "SOURCE_DATE_EPOCH" .   (excluding target/, .git/)      → 1 hit,
      docs/decisions/D98-…:148, prose about what is NOT a clock
$ grep -rn "wasm-opt\|binaryen" .  (excluding target/, .git/)      → 0 hits
```

`.cargo/config.toml` sets exactly one `rustflags` entry — the getrandom
`--cfg` — and nothing about paths. R25's Do already asks for *"path-prefix
remapping"*; this measurement says none is present to build on, and the
`wasm-opt` result says a **third binary that may sit in wasm-pack's default
release path is named nowhere in this repo** and must be pinned or disabled
before any hash is published (§7 rule 1, §9).

**(j) The current wasm artifacts embed this machine's absolute paths —
measured, on the real tree.**

```
$ f=target/wasm32-unknown-unknown/debug/wasm_bitmatch.wasm
$ grep -a -o "/home/deb/Documents/code0" "$f" | wc -l
300
$ grep -a -o "/home/deb/.cargo/registry" "$f" | wc -l
1274
```

So today the checkout directory and `$CARGO_HOME` are **inputs to the
artifact bytes**. Different runner, different bytes. This is the debug
profile (DWARF-bearing), so (k) isolates how much of it survives without
debug info.

**(k) Path leakage survives `debuginfo=0` for dependency paths, and
`--remap-path-prefix` fixes it — measured with `rustc` directly, no cargo
lock contention.** A four-line crate, built for `wasm32-unknown-unknown` at
`-C opt-level=3 -C debuginfo=0` (the shape a release page ships):

| invocation | occurrences of the absolute build dir |
| --- | --- |
| source given as `src/lib.rs` (relative) | **0** |
| source given as `<abs>/src/lib.rs` — *what cargo does for every registry dependency* | **1** |
| same, plus `--remap-path-prefix <abs>=/x` | **0** (and `/x/src/lib.rs` present) |

The artifact also contains `/rust/deps/dlmalloc-0.2.10/src/lib.rs` — the
**already-remapped** std path, which is the same mechanism applied upstream:
the fix is standard, and std is deterministic for this reason already. Two
further facts fell out and both are load-bearing:

- **rustc is byte-deterministic across identical invocations.** Two runs to
  the *same* output path: `7657b6c1672e4503a23780c8b54412ba56e0be9b421e9c1f378a3012a9e6a711`
  both times.
- **The output *filename* is inside the artifact.** Two runs identical except
  for `-o probe_remap.wasm` vs `-o probe_remap2.wasm` produced **different
  hashes**, differing from byte 1 364 179 (the trailing name/producers
  sections) and by exactly one byte of length. **This kills the
  content-addressed-filename escape from the chicken-and-egg** (§4 way 6b) on
  measurement rather than on taste: naming a file after its own hash is a
  fixed point too.

**(l) `[profile.*]` is no longer absent from the root manifest.** `Cargo.toml`
lines 651–670 declare ten `[profile.dev.package.<crate>]` stanzas at
`opt-level = 3` (argon2, blake2, scrypt, salsa20, pbkdf2, **sha2**, hmac,
**chacha20poly1305**, chacha20, poly1305), landed 2026-08-01 in `68d2fa4`
(U6). `--release` occurs in `.github/workflows` and `scripts` in exactly two
places, both `cargo build --release -p devnet-launcher`
(`scripts/devnet/local-up:70`, `scripts/devnet/sepolia-up:117`) — so **F29's
"no `--release` anywhere in CI" still holds** and **F29's "the root
`Cargo.toml` declares no `[profile.*]`" is now false** (§10 (i)). The
substantive consequence for D63 is small but real: the bit-match lane's
wasm32 build already runs the hottest crypto at `opt-level 3`, so the codegen
gap F29 names is narrower than its prose, and still open for `antseal-core`
itself and for whatever post-processing wasm-pack's release path applies.

**(m) The house hex spelling is settled and this record inherits it.**
`Digest32` renders as *"64 lowercase hex characters (D29 rule: binary data is
lowercase hex …)"* (`crates/antseal-core/src/verify/report.rs:105-106`),
emitted `{byte:02x}` ungrouped (`:113`). D67 §1 (e) already refused minting a
second hex spelling. The footer is not exempt.

---

## 2. What the footer can prove, to whom, and under what assumption

This section is the decision's spine. A ruling that lets a reader believe the
footer answers line 186's malicious host would be worse than no footer.

**2.1 Against a malicious host, the footer proves nothing. Both arms. Not
"less" — nothing.**

Line 139's own parenthetical states the threat: *"the page is itself a trust
point — **any host can serve lying JS**"*. Under that threat the adversary
controls every byte the browser receives and therefore every instruction that
executes:

- **Build-time injection** puts a literal in `index.html`. The adversary
  serves a modified `.wasm` and an unmodified literal. Cost of the forgery:
  editing one string. The footer displays the *published* hash while the
  page runs *other* bytes.
- **Runtime self-hash** computes the digest in JS the adversary also serves.
  `return PUBLISHED_CONSTANT;` is a one-line forgery, and it is *cheaper*
  than the first because it need not even keep the two artifacts consistent.

There is no third arm that improves this, because the improvement would have
to be a computation the host cannot control, and every computation on the
page is the host's. **A self-reported provenance value is evidence only about
an honest reporter.** That is the assumption, stated once and plainly: *the
footer's hash is true iff the page serving it is the page you think it is* —
which is the proposition the reader wanted checked.

**2.2 What the footer does do, and for whom.** Four jobs, all real, none of
them integrity-against-a-host:

1. **Names the build, to an honest host's reader.** "Which version am I
   looking at?" is the ordinary question, and the ordinary answer is a
   provenance label. Most readers, most days, are not being attacked.
2. **Makes the out-of-band check *possible*.** The check that actually works
   is: fetch the bytes yourself, hash them, compare against the **signed**
   `SHA256SUMS` obtained from the **release channel** — a different origin,
   a different trust root, an offline signature (Q30). Without a build
   identifier on the page, a reader holding page bytes cannot tell *which*
   release to compare against. The footer is a **pointer into the published
   sums**, not a substitute for them. This is the job that determines §5 R2:
   the value must be one the reader can **recompute from bytes they hold**.
3. **Catches accident, which is the likely failure.** Stale CDN object, half
   finished deploy, a `.wasm` from one build beside JS from another, a host
   silently serving last month's page. All of these are caught by a visible
   build identifier and none of them involve an adversary.
4. **Carries the advice line** — the one mitigation in the footer that
   survives a hostile host, because it executes elsewhere (§1 b).

**2.3 The consequence for wording, ruled in §5 R6.** Because (2.1) is true,
the footer must never be phrased as a security claim about the page. It
states *what this build is*, and hands the reader the two things that do work
— compare against the signed sums; run the CLI. No "verified", no "secure",
no "integrity". This is the same discipline `crates/antseal-core/tests/`
`verdict_wording.rs`'s positioning checklist item 6 applies to verdicts —
*"Never 'verified' about something this run did not verify"* — applied to
page chrome, where the run verifying is the reader's, not the page's.

---

## 3. The dichotomy, taken to measurement

### 3.1 Runtime self-hash of the fetched wasm — **refused**

- **It breaks the mode the spec privileges.** Line 127: *"Offline-first: full
  local verification."* `tasks/R.md:287` (R23 Accept) makes it testable:
  *"Works fully offline: **file://** or a no-network browser context
  completes verification incl. anchor checks."* A self-hash needs the module
  bytes as data — i.e. a `fetch()`/XHR of a sibling file — and browsers block
  cross-file `file://` reads (opaque origins). So the footer's value is
  unobtainable, or obtainable only in http contexts, in precisely the mode
  R23 must demonstrate. An arm whose only claimed advantage is "it hashes
  what was really loaded" and which cannot run where the page is really
  loaded is refused on its own premise.
- **It defends nothing extra** (§2.1). The whole argument for paying the cost
  evaporates on the threat it was reached for.
- **It costs a second full read and a second full hash of the largest
  artifact**, doubling peak memory at load on the device class R23 already
  worries about (R54's note in `tasks/R.md`: multi-second wasm verifies at
  cap remain plausible on slow devices).
- **It makes the footer asynchronous and mutable.** A provenance line that
  renders empty, then "computing…", then a value, is a line whose *absence*
  and *presence* both look normal — so a broken self-hash degrades silently,
  which is the failure direction this project refuses everywhere else.
- **Its one honest gain is already bought elsewhere.** "Does the wasm match
  the HTML that loaded it?" is a *self-consistency* question, and the
  complete answer is the published `SHA256SUMS` over the whole closure
  (§5 R4) plus R26's scripted served-bytes check (`tasks/R.md:323`) — which
  runs off the page, on the real host, against a signed list.

### 3.2 Build-time injection — **adopted**, with the constraint the register omitted

Injection wins every axis above. It carries one liability the register's
framing hid, and it must be met rather than glossed:

**`MVP-SPEC.md` line 137 ends: *"No framework, no build beyond
`wasm-pack`."*** A build-time injection step *is* a step beyond `wasm-pack`.
Read alone, that sentence favours the arm §3.1 just refused.

It cannot be read alone. **Line 139 mandates a footer build hash, and a
digest of an artifact cannot exist before the artifact does** — so line 139
requires a post-`wasm-pack` step by construction, and line 156 puts
*"reproducible build + published hash"* in M3 as a deliverable. Two frozen
sentences, one consistent reading, and the project has already written it
down: R23's Accept spells line 137's enforced form as *"**no framework or
bundler in the repo**"* (`tasks/R.md:289`) — frameworks, bundlers,
transpilers. A deterministic step that computes a digest and substitutes one
declared token is not a build system.

So the reading is adopted **with a fence around it**, and the fence is
normative (§5 R5): the build script may run the pinned `wasm-pack`, copy
files, compute digests, substitute pre-declared tokens in committed
templates, and emit the sums manifest — **and nothing else**. No minifying,
bundling, transpiling, templating language, or page-code generation. The
committed template must itself be a loadable page, so template→artifact is a
one-token diff any reviewer can eyeball. *(→ **NARROWED, 2026-08-12, by D129**,
at the same scope and for the same reason as the §5 R5 rider recorded after
`## Outcome`: this is the sentence D129 §4.2 and §11.4 actually quote, and the
narrowing applies here too. The purpose — a mechanically reviewable
template→artifact step — is preserved and replaced, not withdrawn; the fence
and its prohibitions are untouched.)* Without that fence, "line 139 lets
me add a step" becomes a warrant for a toolchain, and line 137 stops meaning
anything.

### 3.3 The dichotomy as a *framing* — **overturned**

The register asks which mechanism produces "the footer". Measured (§1 d),
R22's Do already commits the module to exporting *"build info for the
footer"*, and no module can contain its own digest (§4). So the footer has
**two** classes of datum with **one** possible source each:

| datum | only possible source | why there is no choice |
| --- | --- | --- |
| core version, supported format versions, source commit | **inside the wasm**, via R22's export | they are properties of the module; putting them in HTML instead lets HTML and module disagree undetectably |
| SHA-256 of the wasm | **injected into the HTML at build time** | no artifact can contain its own digest (§4) |
| the advice line | the **spec**, verbatim (§1 c) | it is dictated text, not a computed value |

Neither register arm is "the mechanism". The answer is a composition, and
seeing it buys a free check nobody had asked for: because the version now
exists in two places derived from one build, **R27/Q19 can assert the
footer's rendered version equals the version the module exports at runtime**,
which catches a mixed deploy in CI — the exact accident §2.2 (3) names, found
by a test rather than by a user.

### 3.4 The arm nobody supplied — a build id over build *inputs* — **refused**

Dissolve the circularity by making the identifier not a function of the
outputs at all: `build_id = SHA-256(canonical descriptor of {source commit,
rustc pin, wasm-pack/wasm-bindgen pins, target, profile, remap prefixes,
file list})`. It is deterministic, injectable, and has **no fixed point** —
genuinely the most elegant escape from §4.

Refused, on the job description in §2.2 (2): **the reader cannot recompute
it.** A build id derived from inputs can be checked only by someone who
rebuilds; a digest of the artifact can be checked by anyone holding the
bytes, with `sha256sum`, in one command, on the machine they already have.
The footer's only job that survives an adversary is *enabling the out-of-band
check*, and this arm removes exactly that. It is independently refused by
`tasks/R.md:314`, whose Accept requires the *"build hash matching the
published sum"* — an input-descriptor hash matches no sum. Recorded because
it is the right answer to a different question: if the release ever needs to
name a whole build in one token, this is the shape, and it belongs to Q31's
version scheme, not to the footer.

---

## 4. The chicken-and-egg, enumerated and cut

The problem, precisely: if the footer's value `H` is injected into
`index.html`, and the published sums cover `index.html`, then `H` is a
function of a set containing a file whose bytes are a function of `H`.

**Way 1 — hash a set excluding the injecting file.** *Refused.*
`index.html` is the loader: it chooses which JS and which wasm run. Line
139's threat is *"any host can serve **lying JS**"*. A sums manifest that
covers the payload and omits the file that selects the payload publishes
integrity for the cargo and none for the manifest of lading. It also breaks
R26's Accept (`tasks/R.md:323`), which compares **served bytes** — and the
served bytes include `index.html`.

**Way 2 — two-pass / fixed point.** *Refused, and the terminal form is
impossible, not merely awkward.* The terminal form — `index.html` containing
`SHA-256(index.html)` — is a fixed point of `f(H) = SHA-256(template[H])`
over a 256-bit codomain. Such a point exists at all only with probability
≈ 1 − 1/e, and **locating one costs ≈ 2²⁵⁶ evaluations**: it is a preimage
search, not a build step. So "two-pass" can only ever mean *publish two
numbers* — the pre-injection hash in the footer and the post-injection hash
in the sums — and that is refused for a plainer reason: it hands the reader
two similar-looking 64-hex values whose difference is unexplainable in a
footer, in a check whose entire value is that a mismatch is unambiguous. A
provenance mechanism whose correct use requires the reader to know which of
two hashes not to compare has failed at its job.

**Way 3 — hash only the wasm.** ***Adopted, for the footer's displayed
value.*** The wasm is the one artifact that (i) structurally **cannot**
contain the footer, so no cycle exists; (ii) carries **all** the verification
semantics — line 127: *"`antseal-core` WASM (which contains **all**
verification, anchors included)"*, with R22's page JS doing *"layout only"*
(`tasks/R.md:273`); and (iii) is **already named by three downstream rows**
as "the wasm build hash" (§1 e). Non-circular, semantically the right
artifact, and consistent with text written before the question was asked.

**Way 4 — a manifest file.** ***Adopted, for the published artifact*** —
`SHA256SUMS`, one `sha256sum`-format line per served file, computed **after**
injection, covering `index.html` and every subresource. A file cannot list
its own hash, so the manifest sits outside its own set and no cycle exists.
R25's Do already calls for exactly this artifact (§1 f).

**Ways 3 and 4 are the cut, and they are the cut only together.** The
circularity is manufactured by assuming *one* set: that the number in the
footer must be the identity of the whole published set. Drop that assumption
— which nobody had examined — and the problem dissolves. The footer names
**one file that cannot contain it**; the manifest covers **every file
including the injected one**; the release publishes both, so the footer's
value is literally one line of the published sums and R25's Accept row 314
(*"the build hash matching the published sum"*) is true by construction, in
its narrowest and most checkable reading.

**Way 5 — Subresource Integrity.** *Not a provenance mechanism; permitted as
hygiene.* SRI on a `<script>` tag records the JS digest inside `index.html`,
which makes `index.html`'s single sums line transitively cover the JS —
genuinely nice, and it introduces no cycle (HTML depends on JS, JS does not
depend on HTML: a DAG). But it is **no defense against the host**, who edits
the `integrity` attribute in the same breath as the script; it is **not
enforced on `file://`**; and it does **not apply to WebAssembly** fetched and
instantiated by script. So: **not required by D63, permitted and encouraged
if R23 ships multiple files, never counted or worded as a defense.**

**Way 6 — two escapes measured and closed.** (a) An identifier that is not a
function of the outputs — §3.4, refused on unverifiability. (b) A
content-addressed filename (`antseal-<hash>.wasm`) so the name carries the
digest: **refused on measurement** — §1 (k) shows the output filename is
*inside* the artifact, so a file named after its own hash is the same fixed
point as way 2, one level of indirection out.

---

## 5. The ruling

Six rules. "Module" = the `.wasm` file the browser loads. "Closure" = the
transitive set of files a fresh load of the canonical URL fetches.

**R1 — Mechanism: build-time injection, of one token, into a committed
template.** The build script computes the digest and substitutes exactly one
pre-declared placeholder token in a committed page template. **No runtime
self-hash exists anywhere on the page**, and no code path recomputes,
verifies, or compares the digest in the browser — a page checking its own
hash is theatre (§2.1) and this record forbids minting it. Substitution is
**not idempotent by design**: running the injector over an already-injected
file is a hard error, never a silent no-op, so a double-injected artifact can
never be published.

**R2 — The displayed digest: SHA-256 of the deployed module, as loaded.**

```text
footer digest = SHA-256(bytes of the .wasm file the host serves)
```

Taken **after** every step of the build chain, including any wasm-bindgen
post-processing and any optimizer (§7 rule 1) — the reader must be able to
`sha256sum` the file their browser fetched and get this number. Rendered as
**64 ungrouped lowercase hex characters, no `0x` prefix**, selectable and
copyable, one hex spelling in the product (§1 m, D67 §1 e). **No truncation**:
a shortened digest is a weaker comparison bought for a shorter footer, and
the reader is copying it, not reading it aloud. If R23 inlines the module
into a single file, the digest is still of the module **as produced by
`wasm-pack`, before packaging** — the reader's check becomes extract-decode-
hash, which is longer to describe and identical in what it proves. **The rule
is deliberately shape-independent, so R23's file-layout choice (§10 (ii))
does not reopen D63.**

**R3 — The identity fields come from the module, not from the HTML.** Core
version, supported format versions and the source commit are rendered from
R22's export (`tasks/R.md:273`, already written). They are never
independently injected into the HTML — one datum, one source — and
**R27/Q19 assert the rendered version equals the module's exported version**,
which is the mixed-deploy detector §3.3 bought for free.

**R4 — The published artifact: `SHA256SUMS` over the complete served
closure.**

- **In the set**: `index.html` (post-injection) and every subresource a fresh
  load fetches — page JS, wasm-bindgen glue, CSS, the `.wasm`. Exactly the
  closure, no more.
- **Out of the set**: `SHA256SUMS` itself (it cannot list its own hash);
  every `wasm-pack` byproduct the page does not load (`package.json`,
  `*.d.ts`, generated README) — **deleted before the sums are computed**, so
  the sums list *is* the deploy list and "extra file in the deploy" is
  detectable; and host/deploy furniture that is not page bytes (`_headers`,
  `_redirects`, `404.html`, `robots.txt`, `.well-known/*`).
- **Bytes are the content-decoded entity body.** A host serving `gzip` or
  `br` must not change a sum; R26's check compares after content-decoding.
- **Authority lives with the signed release, never with the page's host.**
  The authoritative `SHA256SUMS` is the copy published and signed under
  Q30/Q31. Serving a convenience copy from the page host is permitted and
  **carries no authority** — no doc, no footer, and no instruction may cite
  it, because a lying host serves a self-consistent lie and the reader who
  checks it has been given false comfort, which is worse than no check.
- **R26's scripted check** (`tasks/R.md:323`) fetches every file in the set
  from the canonical URL and compares against the signed copy, and
  additionally asserts the load fetches **nothing outside the set** — which
  R23's Accept already asserts offline (`tasks/R.md:289`).

**R5 — The build script's permitted operations, closed list** (the §3.2
fence, holding line 137 and line 139 together): (i) invoke `wasm-pack` at the
pinned versions with `--locked`; (ii) copy files; (iii) compute digests;
(iv) substitute pre-declared tokens in committed templates; (v) emit
`SHA256SUMS` and delete non-served byproducts. **Prohibited**: minifying,
bundling, transpiling, templating languages, generating page code, and any
network access during the build. The committed template must be a valid,
loadable page on its own, with the placeholder visible, so template→artifact
is a one-token diff. — **RIDER + NARROWING, 2026-08-12, by
[D129](D129-verifier-page-file-shape-and-the-in-artifact-csp.md)**: operation
(iii) is read as *"compute digests and deterministic textual encodings of
build inputs"*, with **base64** named, and the *one-token diff* clause is
**narrowed** for the single-file page D129 §5 R1 rules. Nothing above is
withdrawn or restated; see "Amendment — §5 R5's operation list and its
one-token-diff clause, 2026-08-12" below. — **CORRECTION, 2026-08-15 (R25):
operation (i)'s `--locked` is NECESSARY BUT NOT SUFFICIENT.** Measured with
the lock file deleted, `wasm-pack build … -- --locked` exits **0** and
**recreates `Cargo.lock`**, because wasm-pack runs `cargo metadata` before the
build and that call re-resolves; the flag then binds a build against a lock it
has just regenerated. See "Correction — §5 R5 (i)'s `--locked`, and §7 rule 1's
forward-cited path counts, 2026-08-15" below.

**R6 — The advice line: spec-owned, page-resident, drift-tested — and not
added to R18's frozen table.** The exact sentence, from `MVP-SPEC.md`
line 139 (comma included; §1 c records the variant to avoid):

> for high-stakes verification, run `antseal verify` and compare verdicts

It lives as a literal in the committed page template, and R25 lands **two**
pins for it: a **drift test** asserting byte-equality against the sentence as
quoted in this record's §1 (a) — the house pattern is
`crates/antseal-core/tests/security_assumptions_drift.rs`, which reads
tracked files and asserts verbatim equality mechanically *"in the same house
style as `identifier_bans.rs`"* — and R27/Q19's rendered assertion. It is
**not** added to `antseal_core::verify::wording`: that table is the *verdict*
wording set (its own module doc: *"Every verdict sentence the product prints
lives here"*), the advice line is not a verdict, and adding it would move a
frozen snapshot (a declared *"wording-snapshot event"*) to buy nothing. No
conflict arises with R18's source scan, which bans page sources from spelling
**table rows** and this is not one (§1 g). The rest of the footer's copy is
**page chrome** — D64 §5's category — authored by R23/Q20 and swept by Q28
(`tasks/Q.md:478`, which already inspects *"page copy and footer"*), under
the §2.3 constraint: no "verified", "secure", or "integrity" claim about the
page.

---

## 6. Refused shapes

| shape | refused on |
| --- | --- |
| runtime self-hash of the fetched wasm | unobtainable under `file://`, the mode R23's Accept requires (`tasks/R.md:287`); defends nothing extra (§2.1); doubles peak memory; makes the footer async and silently degradable (§3.1) |
| the register's framing that one mechanism produces "the footer" | R22's Do already commits the module to exporting footer identity fields (`tasks/R.md:273`); the footer has two datum classes with one source each (§3.3) |
| a build id over build *inputs* (git/toolchain descriptor) | the reader cannot recompute it from bytes they hold, which is the footer's only adversary-surviving job (§2.2 (2)); also fails `tasks/R.md:314` (§3.4) |
| sums that exclude the injecting file | `index.html` is the loader and is what "lying JS" means; breaks R26's served-bytes check (§4 way 1) |
| two-pass fixed point (`index.html` containing its own hash) | a fixed point of `f(H)=SHA-256(template[H])`: ≈2²⁵⁶ to find, may not exist (§4 way 2) |
| two-pass publishing two numbers | a footer whose correct use requires knowing which of two hashes *not* to compare (§4 way 2) |
| content-addressed filename (`antseal-<hash>.wasm`) | measured: the output filename is inside the artifact (§1 k), so this is the same fixed point one level out (§4 way 6b) |
| SRI as a provenance mechanism | the host edits the `integrity` attribute too; unenforced on `file://`; does not apply to instantiated wasm — permitted as hygiene only (§4 way 5) |
| truncated / grouped / `0x`-prefixed footer digest | weaker comparison for a shorter line; mints a second hex spelling against every existing surface (§1 m, D67 §1 e) |
| serving the authoritative `SHA256SUMS` from the page's own host | a lying host serves a self-consistent lie; a check that cannot fail is worse than no check (§5 R4) |
| page-side verification of its own hash ("integrity: OK") | theatre — the checker is the suspect (§2.1); forbidden outright by §5 R1 |
| footer copy claiming verification/security/integrity of the page | §2.3; the same discipline as `verdict_wording.rs`'s checklist item 6 |
| adding the advice line to `wording.rs` | it is not a verdict sentence; moves a frozen snapshot for no gain (§5 R6) |
| a minifier/bundler/templating step in the build script | line 137 + R23's Accept *"no framework or bundler in the repo"* (`tasks/R.md:289`); §5 R5's closed list |

---

## 7. What R25 must implement (verbatim for the implementation lane)

1. **Preconditions, ~~none of which exist today~~ ~~three of which remain
   unmet~~ of which the path remap is now discharged too
   (§1 h, i).** Before any hash is
   published: ~~**D18** ruled;~~ — **DISCHARGED 2026-08-12 by
   [D18](D18-wasm-bindgen-surface-location.md)**; see "Amendment — §7 rule 1's
   first precondition, discharged, 2026-08-12" below. ~~The remaining three
   stand~~ — **the remap is DISCHARGED 2026-08-15 by R25 (below); the pin and
   optimizer items are dispositioned on their own rows (R25, R83's `Notes`) and
   are not re-adjudicated here**: `wasm-pack` and `wasm-bindgen-cli` exact-pinned
   with the CLI equal to the `wasm-bindgen` crate pin
   (`docs/dependency-policy.md` §5 — `scripts/wasm-toolchain-audit.sh` starts
   enforcing the equality automatically the moment either appears, no wiring
   needed); `--remap-path-prefix` for **both** the workspace root and
   `$CARGO_HOME/registry` ~~(§1 j measured 300 and 1 274 absolute-path
   occurrences respectively, and §1 k proves the flag removes them at
   `debuginfo=0`)~~ — **DISCHARGED 2026-08-15 by R25**, and the two counts
   carried into this precondition are the **debug** artifact's, which §1 (j)
   says of itself and this sentence does not: on the release module this build
   ships, the workspace root occurs **zero** times and `$CARGO_HOME/registry`
   **52**; see "Correction — §5 R5 (i)'s `--locked`, and §7 rule 1's
   forward-cited path counts, 2026-08-15" below; and **any post-`wasm-pack` optimizer either pinned by
   exact version or disabled** — `wasm-opt`/`binaryen` is named **nowhere**
   in this repo (§1 i), and an unpinned binary in the chain makes the
   published number unreproducible by construction. Whichever is chosen,
   record it: the tool list *is* part of the build's identity.
2. **Two-runner byte-identity is Accept row `tasks/R.md:312` and is not
   measurable today.** rustc itself is byte-deterministic across identical
   invocations (§1 k), so the work is entirely in removing environment from
   the inputs: paths (1), timestamps, filenames (§1 k — the output name is in
   the artifact, so the deployed names must be fixed by the build script and
   not derived from anything environmental), and locale/`$HOME`.
   `SOURCE_DATE_EPOCH` machinery does not exist in this repo and should be
   added only if a measured timestamp source is actually found — do not
   import ceremony for a leak nobody demonstrated.
3. **Footer**, per §5 R1–R3 and R6: one injected token = the module digest,
   64 lowercase hex, ungrouped; identity fields rendered from R22's export;
   the advice line verbatim with its drift test; no page-side hash
   computation, comparison, or "integrity OK" affordance anywhere.
4. **`SHA256SUMS`**, per §5 R4: `sha256sum` format, one line per served file,
   computed after injection, byproducts deleted first, `SHA256SUMS` itself
   excluded, content-decoded bytes, handed to Q30/Q31 for signing. The file
   list is the deploy list.
5. **Assert the mechanism cannot be undone quietly**: a test that the built
   `index.html` contains no remaining placeholder token; a test that the
   injector refuses an already-injected input; a test that the page source
   contains no `crypto.subtle`/`SubtleCrypto`/`fetch`-of-own-wasm call
   (§5 R1's prohibition, in the same enforced-invariant style as
   `scripts/wasm-toolchain-audit.sh`); and R27/Q19's version-parity
   assertion (§5 R3).
6. **Docs must state §2.1 in the reader's language** — the check that works
   is *hash the bytes you received against the signed sums, or run the CLI* —
   and must never present the footer as evidence against a hostile host. Q20's
   copy lint and Q28's sweep are the enforcement surfaces (`tasks/Q.md:478`).

---

## 8. Spec conformance

- **Line 139 realized in all three clauses**: a reproducible `wasm-pack`
  build (§7 rule 1–2 name the missing preconditions rather than assume them),
  a published SHA-256 (§5 R4 — resolved to a per-file manifest over the
  served closure, which is R25's own wording), and a footer displaying *"its
  own build hash"* — resolved to the digest of the module the page runs,
  which is the only artifact that can carry a self-digest at all (§4).
- **Line 137 held, not bent.** *"No framework, no build beyond `wasm-pack`"*
  is read with line 139 rather than against it, and the reading is fenced by
  §5 R5's closed operation list plus R23's own Accept phrasing (§3.2).
- **Line 186 honoured by refusing to over-claim.** The footer is recorded as
  one of five listed mitigations and explicitly **not** the one that answers
  the malicious host; the answers are the published+signed sums, the
  canonical URL, and the CLI cross-check (§2).
- **Line 123 untouched.** Nothing here concerns manifest/bundle format
  versions. **Zero frozen bytes**: no registry key, no error code, no HKDF
  label, no domain tag, no golden vector, and the R18 snapshot is
  deliberately *not* moved (§5 R6).
- **One recorded narrowing**: the footer displays **one** digest, of the
  module, not of the page as a whole. Stated in the ruling so that no reader
  infers the HTML/JS are covered by the number they see. They are covered by
  the *published sums*, which is where coverage belongs.

---

## 9. Residual risk (of the decision taken)

- **The footer remains forgeable, permanently, by design.** No mechanism
  exists that would change this, and pretending otherwise is the failure mode
  §2 exists to prevent. Mitigation is the reader's out-of-band check and the
  advice line; the residual is that most readers will do neither. Accepted,
  and it is why the advice line is normative text rather than decoration.
- **The reproducible build is unproven and its tool chain is incomplete.**
  Measured today: no `wasm-pack`, no `wasm-bindgen` pin, no path remapping,
  no optimizer pin, no release-profile lane anywhere (§1 h, i, l). Until §7
  rule 1 is discharged, the published number would be a hash of *one
  runner's* output, which is a different and much weaker claim than the one
  line 139 makes. R25 must not publish before it can rebuild.
- **A host that rewrites bytes silently defeats R26's check by making it
  always red.** Static hosts that inject analytics, minify HTML, or rewrite
  links cannot serve a byte-stable page. This is a **selection criterion for
  D62**, not a fixable R25 problem, and it is handed over in §10 (iii).
- **The wasm digest does not cover the JS.** A host swapping only the glue or
  the page JS leaves the footer's number correct. This is not a weakness of
  the choice (§2.1: no number would help) but it is a real gap between what
  the footer shows and what the sums cover, and §5 R6's wording constraint
  plus §7 rule 6's docs obligation exist because of it.
- **F29's gap is inherited whole.** The bit-match compares debug codegen; the
  page ships a release build. This ruling does not close it and cannot — it
  simply makes the shipped profile's identity *published*, which is the
  precondition for ever comparing it.

---

## 10. Discovered work — described, not registered

No ids are minted here.

**(i) F29's justification prose carries a claim that is now false.**
`tasks/F.md:399`'s Discovered-by paragraph (and `TODO.md:128`'s row text)
assert *"the root `Cargo.toml` declares no `[profile.*]`"*. Measured:
`Cargo.toml:651-670` declares **ten** `[profile.dev.package.*]` stanzas at
`opt-level = 3`, landed 2026-08-01 in `68d2fa4` (U6) — after F29 was written
on 2026-07-28. The `--release`-in-CI half of the claim still holds (only
`scripts/devnet/local-up:70` and `scripts/devnet/sepolia-up:117`, both
`devnet-launcher`). Two consequences a future F29 lane would otherwise
re-derive: the wasm32 bit-match already runs sha2/chacha20poly1305/blake2 et
al. at `opt-level 3`, so the codegen gap is **narrower** than the row says;
and F29's incidental-effect estimate (*"the 12.35 s of debug crypto … would
fall by roughly an order of magnitude"*) predates those overrides and is
stale in the same direction. **Ledger material** — it changes what a row
claims, not what any product code does.

**(ii) R23 owns an unruled question that D63 was written to survive but
someone must answer: can the page be multiple files at all?**
`tasks/R.md:287` requires *"file:// or a no-network browser context completes
verification"*. Under `file://`, browsers treat each file as an opaque origin
and block `fetch`/XHR of siblings — which is how wasm-bindgen's generated
glue ordinarily loads the module. So the `file://` half of that Accept row
plausibly forces either a **single self-contained HTML file with the module
inlined** or a **narrowing of the Accept row to http-served offline
contexts**. This is R23's shape decision, not D63's; §5 R2 is deliberately
written to hold under either. Flagged because it is currently unowned by any
row, and because it changes R25's artifact-set arithmetic from "five files"
to "one".

**(iii) A host requirement for D62, discovered here.** §5 R4 and R26's Accept
(`tasks/R.md:323`) require the host to serve bytes **byte-identical** to the
built artifacts. Hosts that inject analytics, minify HTML, or rewrite links
cannot satisfy this. **D62's host choice should be filtered on it**, and the
deploy procedure R26 records must state that content-encoding is transparent
to the sums (§5 R4). Same-act hand-off; no row needed if D62 absorbs it.

**(iv) `verifier-web/` has no lane, no membership, and no scan root.** It is
not in `Cargo.toml`'s `members`, appears in no workflow, and its only live
reference is as a *ban* scan root at `verdict_wording.rs:710` (§1 g). When
R23/R25 land, someone must decide what CI does with it — at minimum the
injector tests and the drift test of §7 rule 5 need a home. Adjacent to
Q210's open observation that three directories carry citations under no scan
root. Instrument-shaped; recorded so R23 does not discover it late.

**(v) R25's Accept row 314 asserts a snapshot that does not exist.** *"Footer
shows the build hash matching the published sum, plus the advice string
(snapshot/playwright-asserted)"* — measured, there is no snapshot containing
the advice string anywhere in the tree (§1 c). §5 R6 tells R25 to create it;
recorded here so the Accept row is not read as describing something already
in place.

---

## 11. Quoted entry notes (registrar's to apply)

### 11.1 `tasks/R.md` — `Open decisions (R)`, replace the footer bullet

> - Footer build-hash mechanism (build-time injection into HTML vs runtime
>   self-hash of the fetched wasm) and exactly which artifact set the
>   published SHA-256 covers — blocks R25; by M3. — **[2026-08-12]**
>   RESOLVED (**D63**): **build-time injection**; the footer digest is
>   SHA-256 of the deployed `.wasm` **as loaded** (64 ungrouped lowercase hex,
>   never truncated), the identity fields come from R22's module export, and
>   the advice line is the spec's verbatim sentence. The **published
>   `SHA256SUMS` covers the complete served closure** (`index.html`
>   post-injection + every subresource, content-decoded, byproducts deleted)
>   and is authoritative **only** in its signed-release copy. The
>   chicken-and-egg is cut by using **two different sets**: the footer names
>   the one artifact that cannot contain it; the manifest sits outside its
>   own list and covers everything. Runtime self-hash refused (dies under
>   `file://`, defends nothing); the **dichotomy is half overturned** — it is
>   a real choice for the digest and a false framing for the footer
>   (docs/decisions/D63-footer-build-hash-and-artifact-set.md).

### 11.2 `tasks/R.md` R25 — add a `Notes` line

> - Notes: **[D63, 2026-08-12]** Mechanism + artifact set ruled
>   (docs/decisions/D63-footer-build-hash-and-artifact-set.md): **build-time
>   injection of one declared token** into a committed template (injector
>   refuses an already-injected input; no page-side hash computation,
>   comparison or "integrity OK" affordance may exist — §5 R1); the value is
>   **SHA-256 of the deployed `.wasm` as the browser loads it**, 64 ungrouped
>   lowercase hex, untruncated, taken after every post-`wasm-pack` step;
>   version/format-version/commit render from **R22's export**, not from
>   injected HTML, and R27/Q19 assert the two agree. Published artifact =
>   `SHA256SUMS` over the **served closure**, post-injection,
>   content-decoded, `wasm-pack` byproducts deleted first, `SHA256SUMS`
>   itself excluded; the **signed release copy is the only authoritative
>   one** — a copy served by the page's host carries none. Build script is
>   limited to a closed operation list (wasm-pack · copy · digest ·
>   token-substitute · emit sums), which is how spec line 137's *"no build
>   beyond `wasm-pack`"* and line 139's mandated footer hash are held
>   together. **Preconditions measured absent 2026-08-12 and blocking Accept
>   row 1**: D18 unruled; no `wasm-pack`/`wasm-bindgen(-cli)` pin anywhere
>   (deliberate — `docs/wasm-toolchain.md` §4); no `--remap-path-prefix`
>   (the current wasm32 artifact embeds the checkout path 300× and
>   `$CARGO_HOME/registry` 1 274×); no optimizer pin — `wasm-opt`/`binaryen`
>   is named nowhere in the repo. **The advice line is NOT in R18's frozen
>   set** (measured: zero hits in `tests/snapshots/verdict-wording.txt`), so
>   Accept row 3's snapshot is R25's to create; it lives in the page
>   template with a drift test against `MVP-SPEC.md` line 139 (comma
>   included — `SPEC-REVIEW.md:287`'s comma-less variant is not normative),
>   in the `security_assumptions_drift.rs` style, and is **not** added to
>   `wording.rs`.

### 11.3 `tasks/R.md` R22 — add a `Notes` line

> - Notes: **[D63, 2026-08-12]** The Do's *"build info for the footer"* is
>   load-bearing and now has a contract
>   (docs/decisions/D63-footer-build-hash-and-artifact-set.md §5 R3): the
>   module exports the identity fields it can honestly know about itself —
>   `antseal-core` version, supported format versions, source commit — and
>   the page renders them from that export and **never** from separately
>   injected HTML, so the two cannot disagree undetectably. The module
>   **cannot** carry its own digest (that is the fixed point D63 §4 refuses),
>   so the SHA-256 arrives by build-time injection instead; R22 must not grow
>   a self-hash entry point. R27/Q19 assert the footer's rendered version
>   equals this export's value — the mixed-deploy detector.

### 11.4 `tasks/R.md` R26 — add a `Notes` line

> - Notes: **[D63, 2026-08-12]** The Accept row's *"served bytes hash-match
>   the published SHA-256SUMS"* is scoped by D63 §5 R4: the set is the
>   **served closure** (`index.html` + every subresource), comparison is on
>   **content-decoded** bytes so gzip/br are transparent, and the check also
>   asserts the load fetches nothing outside the set. The authoritative sums
>   are the **signed release** copy; any copy served by the host itself is
>   non-authoritative and must not be cited by docs or footer. **A host that
>   rewrites, minifies, or injects into served bytes cannot satisfy this and
>   is disqualified — a D62 selection criterion** (D63 §10 (iii)).

---

## Registrar's edit set

**This lane wrote one file: this one.** Everything below is instruction.

1. `TODO.md` decision register, the D63 line (line 909 at time of writing) →
   the resolved form supplied in the lane's closing report.
2. `docs/decisions/README.md` → one index row for this record, in ascending
   id order, status/date taken from this record's own `- **Status`/`- **Date`
   lines (D119 RULING 1/3).
3. `tasks/R.md` — the `Open decisions (R)` footer bullet per §11.1; R25 gains
   the `Notes` line in §11.2; R22 gains §11.3; R26 gains §11.4.
4. `docs/instrument-ledger.md` → the §10 (i) finding (F29's `[profile.*]`
   claim, false since `68d2fa4` 2026-08-01) and, at the registrar's
   discretion, §10 (iv) (`verifier-web/` has no lane or membership).
5. **Hand §10 (iii) to the D62 lane in this same act** — the byte-identical
   serving requirement is a host selection criterion and D62 is being ruled
   in parallel.
6. **No edits** to `MVP-SPEC.md`, the frozen registry, `wording.rs`, the R18
   snapshot, any code, or any fixture are requested by this ruling. **Zero
   frozen bytes.**

---

## Outcome

The register asked which of two mechanisms should produce the footer's hash,
and treated the artifact set as a detail. Both halves were wrong in
instructive ways. The mechanism question is real, and build-time injection
wins it on measurement — the runtime self-hash cannot run in the `file://`
mode R23's Accept requires, costs a second full read of the largest artifact,
makes a provenance line asynchronous and silently degradable, and buys
nothing against the threat that motivated asking. But "which mechanism
produces the footer" is the wrong question, because R22's Do had already
decided that part of the footer comes from inside the module, and no module
can carry its own digest: the footer is a composition of two datum classes
with one possible source each, plus one sentence the spec dictates.

The artifact set was the more consequential assumption. Treating "the
published hash" and "the footer's hash" as one identity is what manufactures
the circularity — and once they are allowed to be two sets, the problem
disappears: the footer names the single artifact that structurally cannot
contain it and that three downstream rows already called "the wasm build
hash", while the manifest, sitting outside its own list, covers every served
byte including the injected file. The two-pass alternative is not awkward but
infeasible — its terminal form is a preimage search — and the
content-addressed-filename escape died on a measurement nobody expected to
need: the output filename is itself inside the artifact.

What the record refuses to do is let any of this read as a defense. Against
the host line 186 names, a build-time hash and a runtime self-hash are
equally worthless, because both are computed by the suspect. The footer's
honest jobs are naming the build, catching partial deploys, and pointing the
reader at the two checks that do survive — hash the bytes you received
against a signed list from another channel, and run `antseal verify` and
compare verdicts. The spec put that sentence in the footer for a reason, and
it is the strongest thing there.

---

## Amendment — §7 rule 1's first precondition, discharged, 2026-08-12

**This section adds no ruling to D63 and corrects no statement of it.** It
records that one item of §7 rule 1's precondition list — a list a lane would
execute — has been satisfied by an event outside this record, which is why the
item is struck at the site rather than replaced (D117 §2.1(a): the original
wording survives verbatim).

**1. The struck clause, quoted verbatim, with its section identifier.**
§7 rule 1 read:

> **Preconditions, none of which exist today (§1 h, i).** Before any hash is
> published: **D18** ruled; `wasm-pack` and `wasm-bindgen-cli` exact-pinned
> with the CLI equal to the `wasm-bindgen` crate pin …

**2. What changed.** **D18 is RESOLVED, 2026-08-12**
([D18-wasm-bindgen-surface-location.md](D18-wasm-bindgen-surface-location.md)):
the shipped wasm-bindgen surface is a **new workspace member
`crates/antseal-wasm`** (`cdylib`+`rlib`, `publish = false`), its
`wasm-bindgen` edge target-gated to `cfg(target_arch = "wasm32")`, its export
list closed, and `antseal-core` edited not at all. Two consequences land
directly on this record:

- **The digest of §5 R2 now has a determinate subject.** §1 (k) here measured
  that the *output filename is inside the artifact*; D18 §5 R1 therefore
  **freezes the package name**, citing that measurement, so the name
  `wasm-pack` derives the emitted `.wasm` from can no longer be changed by an
  implementation lane.
- **§4.2 of D18 answers half of §10 (iv) here**: `verifier-web/` does **not**
  become a Cargo workspace member, refused on `.cargo/config.toml`'s
  two-level runner-path invariant and on this record's §5 R4/R5
  committed-template-versus-built-output separation. The other half — what CI
  does with the directory, and where R25's injector and drift tests live —
  is untouched and stays with R23/R25.

**3. Authority, and whether this lands separately from its subject.** The
authority is **D18** (wave 18 Act 1b's planning lane), whose *Registrar's edit
set* item 6 instructs this strike; the registrar applied it. It lands in a
**different commit from the text it corrects** — D63 was committed 2026-08-12
earlier in the wave — so D117 §2.1(c)'s same-commit disclosure is not needed.

**4. Which rulings still stand.** **All of them.** §5 R1–R6 are untouched, and
the discharge runs in the direction that strengthens them: the artifact the
footer names is now a named package with a frozen filename rather than an
undetermined build unit. Of §7 rule 1's four preconditions, **three remain
unmet in the repository** and rule 1 stands as the gate on publishing any
hash:

- **the pins** — now *specified* rather than open. D18 §7 rules
  `wasm-bindgen = "=0.2.126"` (the version the committed `Cargo.lock` already
  resolves through the ant-core subtree, so the pin is coupled to the upstream
  stack) with `wasm-bindgen-cli` equal, as a **single-line**
  `[workspace.dependencies]` entry landing in the **same commit** as the CLI
  install line. The maintainer resolved the one value D18 could not measure
  and installed both tools on the build machine the same day —
  `wasm-bindgen-cli 0.2.126` and **`wasm-pack 0.15.0`**, each
  `cargo install … --locked` — so `docs/dependency-policy.md` §5 is satisfied
  *there*; **nothing is committed yet**, and `scripts/wasm-toolchain-audit.sh`
  still reports `N/A` until R22 lands the pair;
- **`--remap-path-prefix`** for the workspace root and `$CARGO_HOME/registry`
  — unchanged, and D18 §10 adds the rider that these flags are
  **target-scoped** in `.cargo/config.toml`, so they will move the bytes of
  `wasm_bitmatch.wasm` too; the Q5 lane compares transcripts rather than
  module bytes, so no lane should go red, and **R25 should verify that rather
  than assume it**;
- **the optimizer, pinned or disabled** — unchanged and still unowned;
  `wasm-opt`/`binaryen` is named nowhere in this repository. D18 §7 P5 makes
  measuring what the installed `wasm-pack` actually does about fetching a
  `wasm-bindgen-cli` and running a downloaded `wasm-opt` **R22's first act**,
  because either would breach §5 R5's no-network-during-build fence here.

---

## Amendment — §5 R5's operation list and its one-token-diff clause, 2026-08-12

**This section withdraws no ruling of D63 and corrects no measurement of it.**
It records one clarifying **rider** on §5 R5's closed operation list and one
**narrowing** of that rule's closing clause, both required by a decision taken
after this record and both quoted for the registrar in that record's §11.4.
The original wording of §5 R5 survives verbatim at the site (D117 §2.1 (a));
what stands there is a pointer to this section, not an argument.

**1. The clauses, quoted verbatim, with their section identifiers.**
§5 R5's list reads:

> (i) invoke `wasm-pack` at the pinned versions with `--locked`; (ii) copy
> files; (iii) compute digests; (iv) substitute pre-declared tokens in
> committed templates; (v) emit `SHA256SUMS` and delete non-served
> byproducts.

and §5 R5 closes:

> The committed template must be a valid, loadable page on its own, with the
> placeholder visible, so template→artifact is a one-token diff.

The same promise is made more fully in **§3.2**, and that is the sentence
[D129](D129-verifier-page-file-shape-and-the-in-artifact-csp.md) §4.2 quotes:

> The committed template must itself be a loadable page, so template→artifact
> is a one-token diff any reviewer can eyeball.

**Registrar's note, so the difference is not read as a change**: §5 R5's
sentence has never carried the words *"any reviewer can eyeball"* — they are
§3.2's — while D129 §4.2 and §11.4 attribute the fuller sentence to R5. The
two sentences state **one** promise, the narrowing below is of that promise,
and it therefore applies at **both** sites.

**2. What changed.** D129 (2026-08-12) rules the published verifier page to be
**one file**, `index.html`, with the `wasm-pack --target web` glue inlined
verbatim and the module inlined as base64 (its §5 R1–R2). Two consequences
land on this rule and neither was settled by it.

- **(1) Scope of operation (iii) — a rider, not a new class.** *"compute
  digests"* is read as *"compute digests **and deterministic textual encodings
  of build inputs**"*, with **base64** named. Base64 sits beside a digest
  rather than forming a new operation class: it is total, deterministic, and —
  unlike a digest — **exactly invertible**, so it is strictly *more* reviewable
  (D129 §1 (o): 29 ms to recover the module from the artifact byte-for-byte).
  **The fence of §3.2 is untouched**: base64 resolves no module graph, rewrites
  no identifier, generates no code the author did not write, and reaches no
  network — and the prohibitions of §5 R5 (minifying, bundling, transpiling,
  templating languages, generating page code, network access) are unchanged and
  unengaged. The distinction is testable rather than rhetorical: D129 §5 R9
  assertion 1 requires the glue to appear in the built page **verbatim, as a
  contiguous substring**, which is exactly the line between concatenation and
  bundling.
- **(2) The *"one-token diff"* clause is NARROWED.** Under D129 §5 R1 the
  template→artifact diff is 2.47 MB, so the clause cannot be honoured in
  letter. Its **purpose** — a reviewer can confirm the artifact is the template
  plus declared substitutions, **without trusting the build script** — is
  preserved and strengthened, and the replacement is mechanical rather than
  visual: (a) the **authored** text remains a one-token-per-substitution diff
  and measures **2 858 bytes** of a 2 470 000-byte artifact, which is the part
  a human was ever going to read; (b) the two large tokens are checked by
  **byte-equality with the build inputs** — the base64 token must decode to the
  `wasm-pack` module byte-for-byte and its SHA-256 must equal the injected
  footer digest, and the glue file's bytes must appear verbatim (D129 §5 R9
  assertions 1–3) — which is a stronger review of 1.8 MB of WebAssembly than
  eyeballing was ever going to be; and (c) the committed template stays
  **loadable**, rendering its chrome with its placeholders visible. It does not
  verify — `<script>__ANTSEAL_GLUE__</script>` is a `ReferenceError` — and
  *"loadable"* is what this rule asked for, not *"functional"*.

**3. Authority, and whether this lands separately from its subject.** The
authority is **D129** (wave 19's planning round, D129 lane), whose *Registrar's
edit set* item 4 instructs this rider and whose §11.4 supplies its wording; the
registrar applied it. As with the amendment above, it lands in a **different
commit from the text it amends** — D63 was committed earlier in 2026-08-12 —
so D117 §2.1 (c)'s same-commit disclosure is not needed.

**4. Which rulings still stand.** **All of them.** §5 R1–R4 and §5 R6 are
untouched; §5 R5's closed list, its prohibitions and its loadable-template
requirement are untouched. §5 R2's digest is unaffected and is now measured
**invariant under the target choice** as well: D129 §1 (b) built the module at
one commit under `--target web` and `--target no-modules` and got the same
SHA-256, so the file-shape decision moves no number this record names. §5 R4 is
**applied, not amended** — its subject is the *complete served closure*, and
D129 §5 R1 makes that closure one file, so the manifest has one entry and the
*"the sums list **is** the deploy list"* invariant holds exactly; the
pre-packaging `.wasm` becomes a build **input** and is published as a named
artifact of the signed release instead (D129 §5 R7). And §7 rule 1's remaining
preconditions are **unchanged**: D129 §1 (o) measures the *packaging* step
deterministic, which is not the module's determinism, and the optimizer stays
the open one.

---

## Amendment — §10 (iv) answered and closed, 2026-08-12

**§10 (iv)** — *"`verifier-web/` has no lane, no membership, and no scan root"* —
is **ANSWERED and CLOSED** by
[D131](D131-the-verifier-web-directory-footprint.md). Per D117 §2.2 this section
is the single home of the fact; §10's own text is not edited.

`verifier-web/` becomes a **source-only** directory holding exactly one committed
file, the template `index.template.html`; the built page is **never** committed
and is built to `target/verifier-web/`. The injector and packaging assertions
live in `scripts/verifier-page-build.sh` (`--self-test`, in
`scripts/wasm-pack-build.sh`'s shape, wired through `scripts/local-gate.sh`); the
§7 rule 5 drift test and the template-side assertions in
`crates/antseal-wasm/tests/page_template.rs`; and the browser assertions in a
`scripts/*.mjs` driver under R27/Q19. The directory gains a **second** scan —
`check-traceability.py`, with `verifier-web` as a `CITATION_SCAN` root plus
`.html` in `CITATION_SUFFIXES`, measured **+1 file and zero collateral** — which
is the Q210-adjacent half of this observation.

**The *ban* scan root this paragraph names was additionally found to be about to
go vacuous.** D131 §1 (c) measures page coverage falling to **zero**, with all
nine tests green, under the template name D129 §7 had minted — because the walk's
extension filter does not reach it and the anti-vacuity guard counts a union
fifty-four CLI files satisfy on their own. So the answer to §10 (iv) is not only
*"a lane now owns it"* but *"the scan that was assumed to cover it did not"*.

**Registrar's note, 2026-08-12 — one clause of the answer is NOT yet true.** The
**§7 rule 5 drift test** routed above into
`crates/antseal-wasm/tests/page_template.rs` **does not exist** as of R25's
landing: that file carries five tests (placeholders, the directory's exact
contents, the ruled CSP, no `style=` attribute, no default init) and none of them
compares the page's advice line against `MVP-SPEC.md` line 139. The advice line
is present in the template and correctly spelled, comma included — which is
exactly the condition under which a string drifts unnoticed, and exactly what
rule 5 exists to prevent. Recorded on **R25**, whose Accept row 3 is therefore
not satisfied on its assertion half. §10 (iv) is closed as a *venue* question;
this is an unmet obligation of the venue, not a re-opening of it.

---

## Correction — §5 R5 (i)'s `--locked`, and §7 rule 1's forward-cited path counts, 2026-08-15

Two statements in this record are wrong in the way that matters most for a
build whose whole purpose is that two machines agree: one names a mechanism
that does not enforce what its name says, and one carries a count for the
wrong artifact into the precondition a lane executes. Both were measured by
the **R25** lane closing Accept row 1's first clause, and both are recorded
here rather than at the sites, per D117 §2.2.

### 1. §5 R5 (i) — `--locked` through `wasm-pack` is necessary but NOT sufficient

The clause, quoted verbatim:

> (i) invoke `wasm-pack` at the pinned versions with `--locked` — §5 **R5**.

Measured on cargo 1.92.0, in a scratch copy of the tree with `Cargo.lock`
deleted:

| invocation | exit | lock recreated |
| --- | --- | --- |
| `cargo build --target wasm32-unknown-unknown --release --locked` | **101** — *"the lock file … needs to be updated but `--locked` was passed"* | no |
| `wasm-pack build … -- --locked` | **0** | **yes** |

Extra options *do* reach cargo — a deliberately bogus one is rejected — so the
flag is not being dropped on the way through. **`wasm-pack` runs `cargo
metadata` before the build**; that call re-resolves and writes `Cargo.lock`,
and the `--locked` build then trivially agrees with the lock it has just
regenerated. In the probe, the re-resolution picked `thiserror 2.0.20` where
the committed lock names `2.0.19` — a different dependency graph, silently,
which is exactly what R25's Accept row 1 forbids and exactly what a reader of
R5 (i) would believe could not happen.

**What this correction does and does not do.** It states that the named
mechanism does not deliver the property attributed to it. It mints no
replacement rule: how R25 closes the gap is R25's, and what shipped —
`scripts/wasm-pack-build.sh` recording `sha256(Cargo.lock)` before and after
the build and failing by name if it moved — is recorded on that row and in
`docs/wasm-toolchain.md` §4.1, not here. `--locked` is still passed: it binds
the build step, and measured, it does not move the digest.

### 2. §7 rule 1 — the 300 / 1 274 occurrence counts are the DEBUG artifact's

The precondition, quoted verbatim:

> `--remap-path-prefix` for **both** the workspace root and
> `$CARGO_HOME/registry` (§1 j measured 300 and 1 274 absolute-path
> occurrences respectively, and §1 k proves the flag removes them at
> `debuginfo=0`) — §7 **rule 1**.

**§1 (j) is not wrong and is not corrected.** It measures
`target/wasm32-unknown-unknown/debug/wasm_bitmatch.wasm` and says so in its own
closing sentence: *"This is the debug profile (DWARF-bearing), so (k) isolates
how much of it survives without debug info."* The defect is the **forward
citation**: §7 rule 1 carries the two numbers into the precondition for the
**release** module the page ships, where they do not hold. Measured on that
module at `08c074c`:

| root | occurrences in the release module | §7 rule 1 leads a reader to expect |
| --- | --- | --- |
| workspace root (`/home/deb/Documents/code0`) | **0** | 300 |
| `$CARGO_HOME/registry` | **52** | 1 274 |

The workspace root is absent because cargo already hands the crate being built
a **relative** path — §1 (k)'s own first table row, measured there on a probe
crate and confirmed here on the shipped artifact. Corroborated from the other
direction by the registrar, on the built module in `target/`: the workspace
remap's **placeholder** never appears either, and the strings that do are
relative (`crates/antseal-core/src/manifest/body.rs`, and the emitted
`./antseal_wasm_bg.js`), against **52** `/cargo/registry` placeholders and
**zero** occurrences of this machine's `$CARGO_HOME` or checkout path. The
registry paths survive in
the `#[track_caller]`/panic-location strings of registry dependencies
(`crypto-bigint` 17, `der` 5, `ml-dsa` 4, …).

**The consequence is nil for the ruling and real for the reader.** Both roots
are remapped anyway — the workspace one costs nothing today and is precisely
what starts leaking the moment any profile turns `debuginfo` back on — so the
precondition as executed is exactly the precondition as written. What a reader
would have got wrong is the **size** of the defect, and therefore the size of
the evidence needed to believe it fixed: 52 strings, not 1 574.

### 3. The precondition is DISCHARGED, and this is what discharged it

`scripts/wasm-pack-build.sh` derives both prefixes from the environment doing
the building — never hard-coded, which is the property under test — and passes
them on the one `wasm-pack` command through
`CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUSTFLAGS`, the only one of four candidate
channels that **merges** with `.cargo/config.toml`'s getrandom `--cfg` instead
of replacing it (`RUSTFLAGS`, `CARGO_ENCODED_RUSTFLAGS` and
`--config target.cfg(…).rustflags` all measured the cfg count to **0**;
`[profile.release] trim-paths` is not stabilized in cargo 1.92.0). Three
builds at `08c074c` — baseline, a 122-character checkout path, and a different
`$CARGO_HOME` — produced **byte-identical** module and glue,
`baee3fc9125a04429232dcb8510985b570bb682f81cc1f54ef54f8dab54522a3`, module
1 853 031 B, page 2 516 397 B.

**The footer digest this moves** is a consequence of the discharge, not a
correction of §5 R2: the number is a function of the module and the module
changed on purpose, so any page deployed before this change carries the old
digest until it is redeployed.

**The per-occurrence arithmetic is NOT the evidence, and the record should not
be read as if it were.** 52 × 3 B of path-length difference predicts 156 B
against the 192 B two-runner delta measured, and the local fix predicts 520 B
against 512 B measured; the residual is data-section and offset encoding. The
claim rests on the byte-identity above — which is why it was measured on two
roots rather than counted in characters.

**Authority.** The R25 lane, 2026-08-15, closing Accept row 1's first clause;
recorded by the registrar in the act that registers **R86** (the row for that
Accept clause's *second* half, which no CI job performs). Lands in the same
commit as its subject.

**Which rulings still stand.** All of them, and both errors run in the
direction that **understates** the discipline rather than licensing a shortcut.
§5 R5's closed operation list is unchanged, including (i) — the flag is still
invoked, it is merely not self-enforcing. §7 rule 1's remap requirement is
unchanged in substance and is now met. §7 rule 2's remaining environment axes
(locale, `TZ`, `HOME`, user, host) are **not** proven independent by the three
builds above, which shared all of them, and this correction claims nothing
about them.
