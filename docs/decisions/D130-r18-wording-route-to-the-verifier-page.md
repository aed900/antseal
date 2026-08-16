# D130 — How R18's frozen wording reaches the verifier page: a fifth export carrying a rendered document

- **Status: RESOLVED — the wording reaches the page as a CORE-BUILT RENDERED
  DOCUMENT across a FIFTH wasm-bindgen export,
  `verify_rendered(bundle_bytes) -> String`. D18 §5 R4's closed list opens to
  **five** entries by this record and closes again there. The report is not
  touched: `REPORT_VERSION` stays `1`, zero frozen vectors move, and `verify()`'s
  bytes stay byte-identical to native — measured *with the fifth export present
  in the module*. R23's `Do` sentence *"All wording comes verbatim from the
  report's R18 strings"* is **FALSE and is corrected here**: measured, all 21
  committed report cases carry **zero** rendered prose — the only multi-word
  strings in any of them are the sealer's own fixture titles — and the same false
  sentence is written into two shipped source files
  (`crates/antseal-wasm/src/lib.rs:4-6`, `crates/antseal-wasm/src/api.rs:96-98`),
  which are corrected too.** The half of the mechanism nobody had noticed decides
  its cost: **`RenderedVerdict` already exists, is already `Serialize`, and is
  already built on EVERY verification** (`orchestration.rs:1016`,
  unconditional) — so the shipped module already computes the entire offline
  verdict block, already carries its strings in its bytes, and **throws it away
  at the boundary**. Exposing it costs **+3 678 bytes (+0.20 %)**. The redaction
  half does not exist and is minted here as `RenderedRedaction`; both halves
  together cost **+31 772 bytes (+1.72 %), +11 028 gzipped**, with the import
  table **unchanged at 3 allow-listed shims** — so a fifth export widens no
  capability surface. **Re-authoring the wording in page JS (arm c) is already a
  RED gate today**, not a matter of taste: planted into `verifier-web/index.html`
  it fails `no_renderer_source_spells_a_frozen_verdict_string` with four named
  offenders — **but the identical content planted as
  `verifier-web/index.html.template`, which is the file R23 is chartered to
  author, passes GREEN**, because the walk's extension filter is
  `rs|html|js|css`. The guard has a hole at exactly the file the blocked row
  writes, and this record closes it.
- **Date: 2026-08-12** (wave 19 planning round, D130 lane; briefed to overturn its
  own lean. Two arms die on committed rules rather than on judgement — a report
  field is a FORMAT EVENT under D105 §2.4 (21 vectors + 26 digest rows), and D64
  §6 already adjudicated *this exact question* for the online half and ruled the
  same way this record rules for the offline half. The lean that a fifth export
  is expensive is overturned by measurement: it is 0.20 % of the module for the
  half the page mostly needs, and the thing it exposes is already computed. One
  arm nobody supplied — overloading the existing fourth export so the count
  stays "four" — is refused for being *quieter* than the honest addition. Two
  defects were found by measuring rather than reading: the template-extension
  hole above, and three sealer-authored strings that `RenderedVerdict` embeds
  **unescaped** today.)
- **Owning tasks: R23** (blocked by this; authors the page and consumes the
  document), **R19** (its redaction renderer becomes layout-only; the
  `RenderedRedaction` minted here is the R19-shaped half), **R22** (the boundary
  crate; gains the fifth shim and the amended guard), **R27/Q19** (the parity
  gate, whose subject this record fixes), **R25** (the artifact grows by the
  measured amount), **R18** (owns the frozen table and the source scan whose hole
  is closed here), **R21** (owns `VerifyOutcome`; gains one serializer).
- **Amends**: `docs/decisions/D18-…` §5 R4 and its Status line (four → five, at
  the five sites quoted in §9), `scripts/wasm-boundary.mjs`'s `EXPECTED_EXPORTS`
  and its diagnosis string, `crates/antseal-core/tests/verdict_wording.rs`'s
  `walk()` extension filter, `crates/antseal-wasm/src/lib.rs`'s module doc,
  `crates/antseal-wasm/src/api.rs`'s `verify_json` doc, `tasks/R.md` R23 (`Do`
  correction + `Notes`), R27 (`Notes`), R19 and R22 (`Notes`).
  **Supersedes**: nothing. **Corrects**: R23's `Do` sentence; two shipped doc
  comments; one gap in R18's source scan.

---

## 1. What was measured

Every command below was run on this tree at commit `9ffe8b7`. Build experiments
ran in a **copy** of the repository under the session scratchpad
(`rsync -a --exclude 'target/'`), never in the working tree; nothing in
`crates/`, `tasks/` or `TODO.md` was written by this lane.

### (a) The brief's five measurements, re-run

1. **No `wording` in the wasm crate.** Confirmed.

   ```
   $ grep -rn 'wording' crates/antseal-wasm/src/ ; echo "exit=$?"
   exit=1
   ```

2. **The R9 report vectors carry no prose — with a stronger instrument than the
   brief's.** Rather than spot-checking four fields, every string leaf of every
   case's `report` was enumerated and filtered for a space:

   ```
   $ python3 -c "…walk every string leaf of expect.cases[].report…"
   string leaves with a space (i.e. possible prose):
      /work/title = 'empty file'
      /work/title = 'multi file'
      /work/title = 'no fine tree'
      /work/title = 'one byte file'
      /work/title = 'raw mirror sources'
      /work/title = 'single binary'
      /work/title = 'single text with mirror'
      /work/title = 'split multi unit'
      /work/title = 'unbalanced n6'
   total distinct string leaves: 38
   ```

   **21 cases, 38 distinct string leaves, and the only multi-word ones are the
   nine sealer-authored fixture titles.** Not one rendered sentence exists in any
   report. Grepping the document for seven frozen sentences returns zero for all
   of them; the two `UNANCHORED` hits are in the vector file's own `description`
   prose, not in a report.

3. **`wording.rs` is 937 lines: 19 `pub const` string constants and 55
   argument-taking functions** (the brief's "17-ish / ~48" is close; the exact
   counts are 19 and 55). The asymmetry the brief flagged is real and is sharper
   than stated — of the 55, **15 contain a `match`, an `if`, a loop or an
   iterator chain** and cannot be expressed as a template at all:

   ```
   pub fns: 55  with branch/loop/iterator: 15  straight-line format!: 40
   BRANCHING: kind_label, headline_tag, state_meaning, anchor_state_line,
   source_line, fetch_date_line, signature_scheme_label, redacted_file_line,
   storage_linkage_line, storage_linkage_fail_line, endpoint_failures_line,
   no_evidence_line, probe_failure_class_label, receipt_confirmed_line,
   endpoints_line
   ```

4. **The closed export list is exactly as quoted**, at
   `scripts/wasm-boundary.mjs:85`, with the comment at `:80-82` reading *"a fifth
   export is how that rule would quietly stop holding"*.

5. **`wording::` consumers**: the four CLI modules named, plus core internals.
   Confirmed.

### (b) The finding that decides the cost — `RenderedVerdict` already exists, and the module already builds it

`crates/antseal-cli/src/verify_out.rs:144-199` does **not** call `wording::` for
the verdict block. It calls one accessor:

```rust
let rendered = self.outcome.rendered();
let mut out = vec![rendered.headline_line.clone()];
```

`RenderedVerdict` (`crates/antseal-core/src/verify/orchestration.rs:393-415`) is
a `#[derive(…, Serialize)]` struct of **final display strings beside their
values**, and its own doc states the contract this record is being asked to
supply:

> *"Every string is drawn from [`wording`], which R18 froze; a renderer adds
> indentation, escaping and its own surface's markup and **nothing else**. Field
> declaration order is render order."*

It is built **unconditionally on every verification** —
`orchestration.rs:1016`, inside `verify_with_host`, before the mode branch:

```rust
let rendered = RenderedVerdict::new(&report, &offline_verdict);
```

and is stored on `VerifyOutcome` (`:856`). Therefore the shipped verifier module
**already computes the whole offline verdict block on every drop and discards
it**. The strings are measurably in the shipped bytes:

```
$ strings -n 6 target/wasm-pack/antseal-wasm/antseal_wasm_bg.wasm | grep -c UNANCHORED
1
$ … grep -c "existed no later than"   → 1
$ … grep -c "this alone carries"      → 1
$ … grep -c "advisory"                → 2
$ … grep -c "sealed, and not revealed" → 0
$ … grep -c "disclosure totals"        → 0
```

The redaction wording is absent because `VerifyOutcome::redaction()`
(`orchestration.rs:887`) derives its view **on demand** and nothing on the wasm
path calls it, so the linker strips those rows. That asymmetry is exactly the
cost split measured in (d).

### (c) The online half already does what this record must rule for the offline half

`verify_online` returns `OnlineOverlay`, and `OnlineOverlay`
(`crates/antseal-core/src/verify/overlay.rs:523-544`) carries
`framing_line: String` and `headline_impact_line: String` — **rendered prose,
crossing the wasm boundary today**, produced by `wording::overlay_framing_line()`
(`overlay.rs:667`). The boundary script asserts it:

```js
check("verify_online() returns an overlay document",
  typeof overlay.framing_line === "string" && overlay.framing_line.length > 0, …)
```

So the premise that "the boundary carries no prose" is already false in the
shipped artifact. **D64 §6 ruled it deliberately**, in words that decide this
record's class:

> *"**Final display strings embedded** (the R74/R22 pattern: renderers — CLI and
> page JS alike — do layout only)."*

and, of the alternative:

> *"without this type, the page's disagreement and fetch-failure lines would be
> **page-authored wording, recreating exactly the R61 asymmetry class**."*

D64 also performed, for the overlay, the exact adjudication arm (b) needs:

> *"an `overlay` field on `VerificationReport` is a FORMAT EVENT (D105 §2.4 …) —
> refused."*

### (d) The fifth export, built and priced

A fifth export was added **in the scratchpad copy** and built with the
repository's own script (`./scripts/wasm-pack-build.sh --build-only`, which
passes `--no-opt --mode no-install`, so the numbers are the shipped
configuration).

| build | module bytes | Δ raw | gzip ‑9 | Δ gzip | imports |
| --- | ---: | ---: | ---: | ---: | ---: |
| baseline (4 exports) | 1 841 981 | — | 586 027 | — | 3 |
| + `RenderedVerdict` only | 1 845 659 | **+3 678 (+0.200 %)** | — | — | 3 |
| + `RenderedVerdict` **and** `RenderedRedaction` | 1 873 753 | **+31 772 (+1.725 %)** | 597 055 | **+11 028 (+1.88 %)** | 3 |

Three facts ride those numbers, each from the tool's own output:

- **The import table does not move.** `scripts/wasm-imports.mjs` passed its
  self-test and reported the same three wasm-bindgen shims in both experimental
  builds: *"OK: every import is allow-listed wasm-bindgen runtime plumbing; no
  host capability is reachable."* **A fifth export widens no capability
  surface** — the property D18 §5 R7 exists to hold is untouched.
- **The report does not move.** With the fifth export present,
  `scripts/wasm-boundary.mjs` still reported
  *"OK   all 21 R9 vectors produce reports byte-identical to native"*, plus
  *"OK   verify() runs the storage-linkage layer"* and *"OK   the rung is NOT a
  field of the report"*.
- **The guard fires, and it fires with the right words** (verified by its
  message, not by an exit code):

  ```
  ::error::wasm-boundary: the JS surface is the closed export list —
    unexpected: [render] missing: [] — D18 §5 R4 closes the surface at four
    entries plus the panic hook
  ```

The experimental export was then called through the JS boundary on the
`multi-file-anchored/mixed` vector. It returns every element R23's `Do`
enumerates. Abridged (full output in §5's schema):

```json
{"verdict":{
  "headline_line":"UNANCHORED — integrity and signature only, no provable time",
  "unanchored":true,"divergence_line":null,
  "anchors":[{"slot":"ots-1","kind":"ots","state":"invalid","headline_tag":"",
    "state_line":"invalid — the signature or op check failed — this anchor proves nothing",
    "guidance_lines":[],"source_line":null,"fetch_date_line":null}, …],
  "claimed_time_line":"claimed time: 1767225600 (asserted by sealer — NOT verified)",
  "storage_linkage_line":"storage linkage: 4 of 4 recorded address(es) do not match the bytes in this bundle — the evidence verdict above is unchanged",
  "signature_scheme_line":"signature scheme: hybrid (PQ)",
  "seal_meaning_line":"a seal proves the holder of the sealing key possessed this content by the proven time — not authorship, and not exclusive possession"},
 "redaction":{
  "view_label":"disclosure map — what this bundle reveals, and where each revealed range sits in its file",
  "declared_size_note":"every size below is the sealer's declared figure, not a measurement by this run",
  "files":[{"file_id":1,"path":"data/blob.bin","total_size":30,"fully_revealed":false,
    "header_line":"file #1 \"data/blob.bin\" — 30 declared byte(s), partially revealed",
    "block_lines":["unit 2 blacked out: 10 byte(s) at offset 0 of 30 declared — sealed, and not revealed by this bundle",
                   "unit 3 revealed: 10 byte(s) at offset 10 of 30 declared", …],
    "mirror_line":null}, …],
  "withheld_file_lines":["file #2 — 35 declared byte(s), path withheld: this bundle reveals nothing of this file and names it only by ordinal"],
  "totals_line":"disclosure totals: 44 of 99 declared byte(s) revealed, across 2 of 3 file(s)",
  "withheld_totals_line":"withheld: 20 byte(s) blacked out inside revealed files; 35 byte(s) across 1 wholly unrevealed file(s)"}}
```

Rendered document: **3 082 bytes** against the same bundle's report at **1 224
bytes**.

### (e) Arm (c) is a RED gate today — and it has a hole at exactly R23's file

`crates/antseal-core/tests/verdict_wording.rs:807-837` walks
**`crates/antseal-cli/src` and `verifier-web/`** and scans every non-comment line
for the table's own sentences. `verifier-web/index.html` exists today (a 484-byte
placeholder) and **is** in the walk.

Baseline in the scratchpad copy: all 9 tests green. Then a page written the way a
page author would write arm (c) — a `const WORDING = {…}` object with four frozen
strings — was planted as `verifier-web/index.html`:

```
verdict wording is spelled outside the table in 55 scanned renderer files:
  verifier-web/index.html:9: the UNANCHORED banner — `UNANCHORED — integrity and signature only, no provable time`
  verifier-web/index.html:11: the claimed-time label — `asserted by sealer — NOT verified`
  verifier-web/index.html:10: the evidence-layer label — `evidence — this alone carries the evidentiary verdict`
  verifier-web/index.html:12: the one headline template — `existed no later than`
Renderers receive final strings from `antseal_core::verify::wording` (R18).
```

**The identical bytes, renamed to `verifier-web/index.html.template`, pass
green** (`test result: ok. 1 passed`). The cause is one line,
`verdict_wording.rs:938-942`:

```rust
} else if path
    .extension()
    .and_then(|ext| ext.to_str())
    .is_some_and(|ext| matches!(ext, "rs" | "html" | "js" | "css"))
```

`Path::extension()` of `index.html.template` is `template`. And
`verifier-web/index.html.template` is **precisely the file D129 and R23's own
`Notes` charter R23 to author** (*"`verifier-web/index.html.template` (name is
R23's) as a loadable page carrying four visible placeholders"*). The one guard
that would have caught a page-side re-authoring does not cover the page's source
file. This was found by planting the fault in both places, not by reading the
filter.

### (f) The frozen snapshot itself already states the mechanism's class

`crates/antseal-core/tests/snapshots/verdict-wording.txt:1-3`, the committed
document R18 froze:

> antseal — the one authoritative verdict-wording set (R18, frozen)
> Every string below is final display text. **Renderers — the CLI, the verifier
> page, the online overlay — receive these strings** and do layout only.

The page **receives** them. That is not this record's inference; it is the frozen
document's own first sentence, and it has been sitting in the tree since R18.

### (g) The two shipped source files that assert the false premise

`crates/antseal-wasm/src/lib.rs:3-6`:

> *"This crate contributes **a boundary and no verification logic**. Every
> decision the page renders is computed by `antseal-core`, **whose report already
> carries R18's final display strings**, so page JS does layout only."*

`crates/antseal-wasm/src/api.rs:96-98`:

> *"The returned string is exactly `VerificationReport::to_canonical_json`'s
> bytes: **every display string R18 renders is already inside it**, so page JS
> does layout only."*

Both sentences are false of the 21 vectors measured in (a). R23's `Do` did not
invent its premise; it inherited it, and it is written into the code the page
loads.

### (h) D65's tier partition already answers who may depend on what

- **Tier A — FROZEN**: `result.report`. *"Its field set, field order, spellings
  and JSON types change only through a `REPORT_VERSION` bump, which is a FORMAT
  EVENT under D105 §2.4 and moves all 21 vectors plus D29's fixed-fixture
  snapshot."*
- **Tier C — DECLARED UNSTABLE until U32**: *"the overlay and live siblings and
  the verdict data"*. *"Keys here may be renamed, removed or retyped between M3
  and M4 with no version moving."*

A rendered sibling document lands in **tier C**, beside the overlay it is
modelled on. No version, no freeze, reviewed rather than promised. Tier C's two
riding rules apply: absence is `null` and a key's JSON type does not wobble.

D105 §2.4's distinguishing test, quoted, is what disqualifies arm (b):

> *"adding a **variant** to a report enum is a value addition whatever its
> payload, and adding a **field** to a frozen struct is not. … Anything that adds
> a field to `VerificationReport`, `AnchorResult`, `WorkMetadata`,
> `EvidenceLayerResult`, `RevealSet`, `FileReveal`, `UnitSpan` or
> `UnrevealedFilePlaceholder` is a FORMAT EVENT and costs the bump."*

Priced: **21** report vector cases + **26** `REPORT_DIGEST_BY_SHAPE` rows
(counted:`bundle_fixtures.rs:2315`ff) + D29's fixed-fixture snapshot.

### (i) D65 §4: no interior versions

> *"the `--json` surface today: seven commands, nine documents, **zero interior
> versions**"*

so the rendered document gets **no `schema` or `version` key of its own**. The
one version a consumer reads is `build_info()`'s, which R25's footer already
renders.

### (j) The escape question, and a live defect found while asking it

`wording::redacted_file_line` (`wording.rs:505-528`) takes an
**already-escaped** path, and says why:

> *"`path` arrives **already escaped for the caller's surface** — the D67 §3 R6
> value-vs-rendering split, and load-bearing here: the path is sealer-authored
> text that reaches a terminal or a DOM, and **the two surfaces neutralise
> different byte sets**. This table spells the sentence; the renderer decides
> what a control character looks like in its own medium."*

D67 §3 R8 puts the escape helper in `antseal-cli` and says *"`seal-core` WASM
safety is untouched because `seal-core` is untouched"*, so the escape set must
**not** move into core. Its four production callers are `preview.rs:210`,
`show.rs:622`, `redaction_out.rs:125` and `reveal_consent.rs` — measured with
`grep -rn 'escape_for_terminal' --include=*.rs crates/ | grep -v tests`.

**None of them is on the verdict path.** `RenderedVerdict` embeds three
sealer/artifact-authored values with no escaping at all —
`claimed_time_line` (`orchestration.rs:466-470`), and `source_line` /
`fetch_date_line` inside `rendered_slot` — and `verify_out.rs::render()` prints
them raw. The house rule for exactly this class is already written down
(`orchestration.rs:231-234`, on `LiveBlobOutcome::FetchFailed::reason`):

> *"It is host-authored text that reaches a display line, so a renderer escapes
> it for its own surface exactly as it escapes `FileRedaction::path` (D67 §3
> R6's value-vs-rendering split)."*

So the rule exists, is stated, and is not applied on the verdict path. That is a
pre-existing defect (§8), and it constrains this ruling: the escape seam must
cover **every** sealer-authored value the document embeds, not only `path`.

### (k) Parity is sound over the R9 corpus, and only over it

All nine distinct paths in the 21 cases — `archive/old.txt`, `data/blob.bin`,
`data/empty.bin`, `data/n6.bin`, `data/one.bin`, `mirror/bom.txt`,
`mirror/nfd.txt`, `notes/intro.md`, `notes/split.md` — contain **no byte the D67
escape set changes** (measured). On this corpus a terminal escape and a DOM
escape are both the identity, so *string-equal* parity between the CLI and the
page is achievable. On a hostile-path fixture it is **not**, by design.

### (l) Repeated verification is a real cost, so the call count matters

Every export re-verifies the bundle from bytes. Timed through the JS boundary on
the largest vector (`multi-file/all`, 9 307 bundle bytes, 200 iterations):

```
  verify         1.602 ms/call
  verdict_class  1.347 ms/call
  render         1.338 ms/call
```

The vectors are small; the caps are not. R54's `Notes` records at-cap bundles at
*"~0.13 s release native"* with *"multi-second wasm verifies at cap … plausible
on slow devices"*, over a legal ~8 MiB at-cap bundle, and D129 §5 R10 measured
that **no Web Worker shape is admissible under the page's CSP**, so the wait is
on the main thread. A page that called `verify()`, `verdict_class()` and a
rendering export would verify the same bundle **three times** for one drop.

---

## 2. The lean, dismantled

**The lean this lane started with**: *the export surface is a ruled boundary that
was closed deliberately and only weeks ago; reopening it is the expensive arm, so
the answer is probably to relocate the CLI's renderer into core (arm d) and find
some way to reach it without a new export.*

Three things kill it, in order of how badly.

**First, the "relocate the renderer" half is already done and the lean did not
know it.** Arm (d) reads as a refactor with a cost. Measured, the verdict block's
renderer has lived in core since R21 (`RenderedVerdict`, `orchestration.rs:393`),
the CLI has been layout-only over it since U30 (`verify_out.rs:144`), and the
wasm module *builds it on every call already*. There is nothing to relocate for
the verdict half. What is missing is not a renderer — it is **a route out of the
module**. The lean was solving the wrong problem, and the cost it feared
(+3 678 bytes, 0.20 %) is smaller than the cost of the thing it feared it would
avoid.

**Second, "reaching it without a new export" has exactly three shapes and each is
worse than the honest addition.**

- *Grow `verify()`'s return into an envelope.* It breaks D18 §5 R5 (the module
  returns the report's bytes), breaks the boundary script's byte-identity row,
  and breaks D65 tier A's statement that the page's binding returns *"the same
  bytes 21 committed golden vectors pin"*. Refused.
- *Put the lines in the report.* D105 §2.4, quoted in §1 (h): a field on
  `VerificationReport` is a FORMAT EVENT. D64 §6 already refused precisely this
  for the overlay, in the same words. Refused, and disqualifying on its own as
  the brief suspected.
- *Overload the fourth export* so `verdict_class` carries the rendered document
  and the list stays literally "four". This is the arm nobody supplied, and it is
  the **worst** one: `scripts/wasm-boundary.mjs`'s upper bound would keep passing
  while the surface's meaning changed underneath it, and D18 §5 R4's own
  rationale is that *"a fifth export is how that rule would quietly stop
  holding"*. An arm whose entire merit is that the counter does not move is a
  quieter version of the failure the counter exists to catch. Refused for being
  quiet.

**Third, the boundary is not as closed as the lean assumed, and D18 said so.**
D18 §5 R4's own text is *"additions are a decision, not a code change"* — an
amendment procedure, not a prohibition. What reopening actually requires,
measured, is: this record; five sentences in D18 (§9 quotes each); one array and
one string in `scripts/wasm-boundary.mjs`; one table row in
`crates/antseal-wasm/src/lib.rs`. It requires **nothing** in
`scripts/ci-lanes.sh`'s dep-graph rule (D18 §5 R6 — the graph is unmoved: no
dependency is added), and **nothing** in `scripts/wasm-imports.mjs`'s allow-list
(D18 §5 R7 — measured: the import table is still exactly 3). The expensive part
of D18 — the graph and the import table, the two structural halves of *"no
I/O"* — is untouched by a fifth export. That is the measurement that turns the
lean around.

**The arm the lean would have reached for instead — build-time extraction (e) —
dies on measurement 3 taken seriously.** Of 55 functions, **15** branch or
iterate: `anchor_state_line` is a wildcard-free match over seven states,
`storage_linkage_line` a match over the layer's arms, `endpoints_line` and
`endpoint_failures_line` fold over slices. A data table cannot carry a fold. The
extraction would therefore ship 19 constants and 40 templates as data *and*
re-implement 15 functions in JS — arm (c) wearing a table for a hat. It also
breaks D63 §5 R5's closed operation list (`wasm-pack · copy · digest ·
token-substitute · emit sums`): an extraction step is a sixth operation, and the
last time this project let a build step outside that list, it fetched an unpinned
binaryen over the network (R25's `Notes`). And it would embed the strings in the
page **a second time**, because §1 (b) measured them already present in the
module's bytes.

**What survives is not the lean but its opposite**: the cheap arm is the one that
opens the surface, because the surface is the only thing in the way.

**One argument this lane expected to make and could not.** It expected to argue
that a rendered document is a *new kind of thing* for this boundary and needs
justifying against D18 §5 R5's "bytes, never a structured value". It is not new:
`verify_online` has returned `framing_line` and `headline_impact_line` — rendered
sentences — since R22, and D18 §5 R5's actual subject is *serialization paths*,
not prose. The rule it states is "one `to_canonical_json()`, spliced, never a
`serde_json::Value` round trip", and the ruling below obeys it exactly. Recorded
so nobody re-derives the objection.

---

## 3. The ruling

Eleven rules. "The document" = the JSON text the new export returns. "The table"
= `antseal_core::verify::wording`, frozen by R18.

**R1 — The mechanism is a FIFTH export, and the list closes again at five.**

```rust
#[wasm_bindgen]
pub fn verify_rendered(bundle_bytes: &[u8]) -> Result<String, JsError>
```

in `crates/antseal-wasm/src/boundary.rs`, a two-line shim over
`crate::api::verify_rendered_json` exactly like the other four (D18 §5 R3's
split, so the native gate type-checks and executes the behaviour). **It takes no
options and no evidence document.** D18 §5 R4's list becomes:

| # | export | returns |
| --- | --- | --- |
| 1 | `verify(bundle_bytes)` | the report's canonical bytes |
| 2 | `verify_online(bundle_bytes, evidence_json)` | the advisory overlay |
| 3 | `verdict_class(bundle_bytes, evidence_json?)` | D69's rung datum |
| 4 | `build_info()` | the module's identity |
| 5 | **`verify_rendered(bundle_bytes)`** | **the offline document the page displays** |

plus the panic hook. **Additions beyond five remain a decision, not a code
change.**

**R2 — No evidence parameter, and this is load-bearing.** The offline rendered
block is byte-identical under every mode (D64 §2, and `RenderedVerdict` is built
from the **offline** aggregate at `orchestration.rs:1016` under all modes). The
online lines already have a home — `verify_online`'s overlay carries its own
final display strings. So R24's online mode needs **no** further export, and the
surface closes at five rather than drifting to six.

**R3 — The document is assembled by SPLICING four canonical byte strings, and the
page's offline path is ONE module call.** Members, in the alphabetical order the
CLI's `--json` `result` already emits:

```json
{"redaction": {…}, "rendered": {…}, "report": {…}, "verdict": {…}}
```

- **`report`** — `outcome.report_bytes()`, **byte-verbatim**. Tier A, identical
  to what `verify()` returns. This is what makes one call sufficient (§1 l).
- **`rendered`** — `RenderedVerdict`, serialized by a new
  `RenderedVerdict::to_canonical_json` in the `SiblingEncodeError` idiom already
  used at `orchestration.rs:698` and `:779`.
- **`redaction`** — `RenderedRedaction`, minted by R4 below.
- **`verdict`** — `VerdictClass::to_canonical_json`, **without** `exit_code`:
  D69 §3 R1 keeps exactly one code table in the product and it is U2's, CLI-side.

Assembly is `format!` over the four byte strings, the third carriage route D65's
Correction section recognised and `verify_out.rs::json()` already uses. **No
`serde_json::Value` on this path, ever** — a round trip alphabetizes the report's
keys and destroys D29 rule 1's declaration order (D18 §5 R5, D65 §5).
`crates/antseal-wasm/tests/carriage.rs` already scans `api.rs` for the refused
shapes; the new function is inside its scope by construction.

**No `schema` key and no interior version** (D65 §4, §1 i). The version a
consumer reads is `build_info()`'s.

**R4 — `RenderedRedaction` is minted in `antseal-core`, beside `RedactionView`,
and it is the R19-shaped half of the same contract `RenderedVerdict` already
satisfies.** Schema, values beside renderings per D67 §3 R6:

```
RenderedRedaction {
  view_label:          &'static str,   // wording::REDACTION_VIEW_LABEL
  declared_size_note:  &'static str,   // wording::DECLARED_SIZE_NOTE
  files: [ RenderedRedactionFile ],
  withheld_files: [ { file_id: u64, size: u64, line: String } ],
  totals_line:          String,
  withheld_totals_line: String,
}
RenderedRedactionFile {
  file_id: u64, path: String, total_size: u64, fully_revealed: bool,
  header_line:  String,          // wording::redacted_file_line, escaped path
  block_lines:  [String],        // revealed_span_line / blackout_span_line, position order
  mirror_line:  Option<String>,  // wording::mirror_full_reveal_line
}
```

Field declaration order is render order, as `RenderedVerdict`'s doc requires. The
work-level totals are `u128` (`RedactionTotals.declared_bytes`) and appear
**only inside `totals_line` / `withheld_totals_line`, never as JSON numbers** —
D65 §7 forbids a JSON number that can exceed 2⁵³, and this document introduces no
integer the report does not already carry in the same form.

**R5 — The escape is a CALLER-SUPPLIED function; no escape set moves into core.**

```rust
impl RenderedRedaction {
    pub fn new(view: &RedactionView<'_>, escape: &impl Fn(&str) -> String) -> Self
}
```

The CLI passes `crate::preview::escape_for_terminal`; `antseal-wasm` passes its
own DOM policy, which lives in `crates/antseal-wasm/src/` (not in `boundary.rs`,
so the native gate tests it). **D67 §3 R8 is untouched** — nothing moves into
core, and `seal-core` WASM safety is unchanged because the escape stays above
core, where each surface's code lives. This is the value-vs-rendering split D67
§3 R6 states and `wording.rs:507-513` already spells out: *"the two surfaces
neutralise different byte sets."*

**The escape is applied to every sealer- or artifact-authored value the document
embeds, not only to `path`.** That is `path`, and — per R9 below — the three
values `RenderedVerdict` embeds today unescaped.

**R6 — The CLI becomes layout-only over both halves.**
`crates/antseal-cli/src/redaction_out.rs` stops calling `wording::` and folds
over `RenderedRedaction`, exactly as `verify_out.rs` folds over
`RenderedVerdict`. Its indents (`FILE_INDENT`, `UNIT_INDENT`), its
`escape_for_terminal` call and its ordering commentary stay; its nine
`wording::` call sites (`redaction_out.rs:79, 80, 93, 100, 109, 123, 142, 153,
155`) go. This is what makes "one authoritative wording set"
(spec line 127) a property of the **assembly** and not only of the vocabulary:
after this, exactly one function composes a redaction block and both surfaces
call it.

**R7 — Frozen vs free, stated so an implementer cannot get it wrong.**

- **FROZEN**: every *string* in the document. They come from the table, R18 froze
  them, and `verdict_wording.rs` snapshots them. A page or a renderer may not
  spell one.
- **FROZEN**: the `report` member's bytes — tier A, byte-verbatim, identical to
  `verify()`'s.
- **FREE (tier C, declared unstable until U32)**: the *shape* of `rendered`,
  `redaction` and `verdict` — key names, nesting, additions. Reviewed via the
  snapshot, not promised. Tier C's riding rules apply: absence is `null`, never a
  missing key; a key's JSON type does not wobble.
- **NOT MOVED**: `REPORT_VERSION` stays `1`. Zero report vectors, zero
  `REPORT_DIGEST_BY_SHAPE` rows, zero frozen bytes.

**R8 — The guards move, in three places, and one of them is a hole this record
found.**

1. `scripts/wasm-boundary.mjs:85` — `EXPECTED_EXPORTS` gains `"verify_rendered"`;
   the diagnosis at `:93` says *five* entries. Two new rows: the document's four
   members are all present; and **`verify_rendered(b).report` is byte-identical
   to `verify(b)`** — required because after this ruling the page calls
   `verify_rendered` and not `verify`, so without this row the gate's subject and
   the page's path would silently diverge.
2. `crates/antseal-core/tests/verdict_wording.rs:941` — the walk's extension
   filter gains `"template"`. Measured in §1 (e): without it, the file R23
   authors is invisible to the one guard that refuses page-authored wording. The
   test's own self-test (`the_source_scan_catches_a_planted_copy_of_a_frozen_sentence`)
   should plant into a `.template` path so the coverage cannot silently narrow
   again.
3. `crates/antseal-core/tests/verdict_wording.rs` — the snapshot gains no
   section: R4 mints no sentence. If an implementer finds themselves adding a row
   to the table, they have left this ruling's scope.

**R9 — The three unescaped sealer values are fixed on the way through, not left
for later.** `claimed_time_line`, `source_line` and `fetch_date_line` are built
from sealer- and artifact-authored text with no neutralisation (§1 j).
`RenderedVerdict::new` gains the same caller-supplied escape parameter R5 gives
`RenderedRedaction::new`, and both CLI and page pass their surface's policy. This
is not scope creep: R23's page renders those three lines from adversary-authored
bytes, D129 already requires every bundle-derived string to reach the DOM by
`textContent`, and shipping a second surface over an unescaped seam is how the
first one's defect becomes permanent.

**R10 — What this decision does NOT change.** `antseal-core` gains no
dependency, no feature and no `crate-type` — `RenderedRedaction` is ordinary
`serde` code beside `RedactionView`, so D18 §5 R6's dep-graph rule and
`gate-features --check-partition` are untouched **by construction**. The import
allow-list is unchanged (measured: 3). No required CI context is added; the count
stays 19. No registry key, error code, HKDF label, domain tag, golden vector or
wording snapshot moves. `verify()`, `verify_online()`, `verdict_class()` and
`build_info()` keep their signatures and their contracts. D129's file shape, CSP
and packaging order are untouched.

**R11 — R23's premise is corrected on the record, in the row and in the code.**
The sentence *"All wording comes verbatim from the report's R18 strings"* is
false and is replaced (§9). The two shipped doc comments that assert the same
thing (§1 g) are corrected in the same wave. **The half of R23's `Do` that is
true — that the page authors no wording and does layout only — is kept
verbatim**, because it is what this ruling makes achievable for the first time.
This follows R19's precedent: a row whose premise is half false is shipped by
saying so, not by implementing the false half.

---

## 4. Refused shapes

| shape | refused on |
| --- | --- |
| **(b)** rendered lines as a field of `VerificationReport` | D105 §2.4: a field on a frozen report struct is a **FORMAT EVENT** — 21 vector cases + 26 `REPORT_DIGEST_BY_SHAPE` rows + D29's fixed-fixture snapshot + a `REPORT_VERSION` bump. D64 §6 already refused this exact shape for the overlay, in the same words (§1 c, h) |
| **(c)** the wording re-authored in page JS | already a **RED gate**: planted into `verifier-web/index.html` it fails `no_renderer_source_spells_a_frozen_verdict_string` with four named offenders (§1 e). Independently: the frozen snapshot's own header says the page *receives* the strings (§1 f); D64 §6 names page-authored wording *"the R61 asymmetry class"*; and the strings are already in the shipped module's bytes (§1 b), so the page would carry them twice |
| **(e)** build-time extraction into a data table in the page | 15 of 55 functions branch or iterate and cannot be a table (§1 a.3) — the arm degenerates into (c) for those; adds a sixth operation to D63 §5 R5's closed build list, the fence whose last breach was an unpinned binaryen fetch; duplicates strings measured already present in the module |
| **overloading `verdict_class` so the count stays "four"** (unsupplied arm) | the boundary script's upper bound would keep passing while the surface's meaning changed — quieter than the failure D18 §5 R4 exists to catch, whose own words are *"a fifth export is how that rule would quietly stop holding"* (§2) |
| growing `verify()`'s return into an envelope | breaks D18 §5 R5 (the module returns the report's bytes), the boundary script's byte-identity row, and D65 tier A's *"the same bytes the page's R22 binding returns"* |
| moving D67 §3 R3's escape set into `antseal-core` so one policy serves both | D67 §3 R8 places it in `antseal-cli` and states *"`seal-core` … is untouched"*; unnecessary, because R5's caller-supplied function gives core the assembly without the set (§1 j) |
| a `schema` or `version` key on the rendered document | D65 §4: *"seven commands, nine documents, **zero interior versions**"*; `build_info()` is the one version the page reads (§1 i) |
| carrying `RedactionTotals`' `u128` figures as JSON numbers | D65 §7: any integer that can exceed 2⁵³ is a decimal string, never a JSON number; the totals ride inside their rendered lines instead (R4) |
| a sixth export for the online rendered block | unnecessary — the offline block is mode-invariant (D64 §2) and `verify_online` already returns final display strings (§1 c); R2 |
| the page calling `verify()` + `verdict_class()` + a rendering export | three verifications per drop, at-cap multi-second each in wasm, on the main thread because no Web Worker is admissible under the page's CSP (D129 §5 R10, R54's `Notes`, §1 l) |
| `serde_wasm_bindgen` / a structured JS object for the document | D18 §5 R5, unchanged and unweakened by this record: one serialization path, splice of canonical bytes |
| leaving the `.template` extension out of the wording scan | measured: identical bytes pass green as `.template` and fail red as `.html`, and `.template` is the file R23 authors (§1 e) |

---

## 5. What R23 / R25 / R27 must implement

### R23 — the page

1. **Call `verify_rendered(bytes)` once per drop.** Do not call `verify()`,
   `verdict_class()` or both alongside it on the offline path: everything the
   page displays offline is in the one document, and each extra call re-verifies
   the bundle (§1 l).
2. **Render every element of the `Do` list from the document's strings**, by
   `textContent`, adding markup and nothing else:
   `rendered.headline_line` (or the UNANCHORED banner — `rendered.unanchored`
   says which) · `rendered.divergence_line` · `rendered.evidence_layer_label` ·
   `rendered.anchors[]` with `.slot`, `.state_line`, `.headline_tag` (`[H]`),
   `.guidance_lines[]`, `.source_line`, `.fetch_date_line` ·
   `rendered.claimed_time_line` · `rendered.supporting_evidence.{class_line,
   detail_line}` · `rendered.storage_linkage_label` +
   `rendered.storage_linkage_line` (the page's entire storage story) ·
   `rendered.signature_scheme_line` · `rendered.seal_meaning_line` ·
   `redaction.*` for the disclosure map · format version from
   `report.work.format_version`.
3. **Author no sentence.** The page's JS contains no verdict-shaped string
   literal. After R8.2 the source scan enforces this on
   `verifier-web/index.html.template` as well as on the built page.
4. **Keep the `[H]` tag structural**: `headline_tag` is `"[H]"` or `""` from the
   module; the page does not compute eligibility.
5. **Escaping is not the page's to invent for the redaction path** — the
   document's `header_line` arrives already neutralised by the DOM policy R5
   places in `antseal-wasm`. The page still routes every string through
   `textContent` (D129), and gives each line its own element so a control
   character cannot forge a row.
6. Everything D129 ruled — one file, the in-artifact CSP, the template's four
   placeholders — is unchanged.

### R19 — the redaction renderer

`redaction_out.rs` folds over `RenderedRedaction` and calls `wording::` nowhere
(R6). Its module doc's claim that *"R23's page draws from [the table] too"*
becomes true for the first time and should be restated as *draws from the same
assembly*.

### R25 — provenance and the artifact

The module grows by the measured amount: **+31 772 bytes raw, +11 028 gzipped**,
against D129's recorded page figures (2 470 000 B raw / 846 607 B gzipped). No
mechanism of R25's moves — the footer digest is still SHA-256 of the module as
`wasm-pack` produced it, the packaging order is unchanged, `SHA256SUMS` still has
one entry. R25 must not treat the growth as a regression to optimise away by
re-enabling `wasm-opt`: that precondition (a pinned binaryen) is unchanged.

### R27 / Q19 — the parity gate

1. **The gate's subject is now well defined**, which it was not before: for each
   R9 vector, `JSON.parse(verify_rendered(b))` on the page and the CLI's
   `VerifyRun::render()` lines must agree **string for string** after the CLI's
   indentation is stripped. Both sides read the same assembly, so a difference is
   a real defect and not a rendering opinion.
2. **Parity holds over the R9 corpus and must not be extended to hostile-path
   fixtures without excluding `redaction.files[].header_line`** — the two
   surfaces neutralise different byte sets **by design** (R5, D67 §3 R6).
   Measured: all nine vector paths are unchanged by either policy, so on this
   corpus the strings are equal (§1 k). A hostile-path fixture belongs in each
   renderer's own suite, asserting *its own* escape, never in the parity gate.
3. **The storage-linkage row is a known parity hazard and must be handled the way
   the boundary script already handles it.** The export takes no options, so the
   layer always runs (D128 §3 R5) and `storage_linkage_line` reads *"n of n
   recorded address(es) do not match…"*, while the committed vectors pin the
   **suppressed** tuple. Compare against a native run under
   `VerifyOptions::new()`, exactly as `scripts/wasm-boundary.mjs`'s header
   explains — never against the vector file.
4. Add the boundary rows of R8.1 (`verify_rendered(b).report` ≡ `verify(b)`; all
   four members present).

---

## 6. Spec conformance

**MVP-SPEC.md line 127**, the sentence this record exists to serve:

> Plain HTML/JS + `antseal-core` WASM (which contains *all* verification, anchors
> included). Offline-first: full local verification. **Verdict taxonomy per
> anchor** (**one authoritative wording set; M3 snapshot-tests it**);
> **headline-eligible** states are tagged [H]

Three obligations, and the ruling meets each by construction rather than by
promise:

- *"one authoritative wording set"* — after R6 there is exactly one **vocabulary**
  (the table) and exactly one **assembly** per block (`RenderedVerdict`,
  `RenderedRedaction`), and both surfaces call the assembly. Arm (c) would have
  satisfied the letter with two authorings; the snapshot's own header (§1 f)
  says the page *receives* the strings.
- *"M3 snapshot-tests it"* — `verdict_wording.rs` already does, and R8.2 closes
  the hole through which the page's own file escaped the scan.
- *"which contains **all** verification"* — unchanged; the module still computes
  everything, and now says so in words the page cannot restate.

**Lines 123–139**, the block this record touches:

- **123** *"every released manifest/bundle format version remains verifiable by
  all future CLI and page releases"* — untouched: `REPORT_VERSION` stays `1` and
  no format moves (R7). This is the line arm (b) would have spent.
- **125–137**, the verdict taxonomy and the seven per-anchor states — every one
  of them reaches the page as `rendered.anchors[].state_line` with its `[H]` tag,
  from the table, unretyped.
- **131** *"The Arbitrum receipt is **not an anchor** and renders in a separate
  class"* — `rendered.supporting_evidence` is a separate member from
  `rendered.anchors`; the page cannot merge them without deliberately doing so.
- **133** *"Claimed time renders visually subordinate, labeled 'asserted by
  sealer — NOT verified'"* — `rendered.claimed_time_line` carries the label
  inside the string; the page controls only the subordination.
- **137** *"Online mode: … rendered as an advisory overlay distinct from the
  offline cryptographic verdict"* — R2 keeps the two documents separate at the
  export level, so "distinct" is structural.
- **137** *"No framework, no build beyond `wasm-pack`"* — untouched; the ruling
  adds no build step (which is arm (e)'s refusal).
- **139**, page provenance — untouched; R25's mechanism is unchanged.

**Line 121** — *"Every reveal displays position + total size (anti-out-of-context
guardrail)"* — is now enforced for **both** surfaces by one fold:
`RenderedRedaction`'s `block_lines` are built from `revealed_span_line` /
`blackout_span_line`, whose revealed and blacked-out arms take the same three
figures. Before this ruling the page would have had to re-derive the guardrail;
after it, there is no rendering path on which a position could be dropped,
because there is only one path.

**Line 28** — the positioning checklist — is unmoved: no sentence is minted, so
`the_wording_set_satisfies_the_positioning_checklist` has nothing new to sweep.

---

## 7. Residual risk

1. **The surface is open by one, and the next request will be easier to make.**
   Five is not four, and a record that opens a closed list weakens the list's
   rhetorical force even while keeping its procedure. Mitigation is procedural
   and stated: R1 closes the list again at five and repeats D18's own sentence.
   The honest statement is that this is a real cost, paid deliberately, and the
   thing that made it payable is that the graph and the import table — the two
   structural halves of "no I/O" — were measured **unmoved**.
2. **Tier C is a real absence of promise.** `rendered` and `redaction` may be
   renamed or retyped before U32 with no version moving. A third-party consumer
   who scrapes the page's document has no contract. This is D65's ruling, not a
   new exposure, but the page is a more visible surface than `--json` and the
   risk is larger in practice than the tier's text suggests.
3. **The parity gate can pass while the two surfaces disagree on hostile input.**
   R27's corpus has no hostile path (§1 k), so the two escape policies are never
   differentiated by it. A defect in either policy is invisible to parity and
   visible only to each renderer's own suite. Stated so that a later lane does
   not read a green parity gate as evidence about escaping.
4. **R9's escape fix is a behaviour change to shipped CLI output** for bundles
   whose TSA subject, claimed time or fetch date contains control or bidi
   characters. No committed vector exercises one, so no snapshot moves — which
   also means the fix ships **unexercised** unless a fixture is added. That is
   the same class D105 §7's Q127 records for report enums.
5. **The `.template` hole may have siblings.** The extension filter is one of
   several places where coverage is defined by a literal set; this record fixes
   the one it measured. Whether other guards (the literal scan roots of D123, the
   sweep coverage of D116) have the same blind spot at `.template` is
   **unverified** — not measured by this lane, and named in §8.
6. **One call per drop makes `verify()` unused by the page.** R8.1's new row is
   what keeps the gate's subject and the page's path from diverging; if that row
   is not implemented, the boundary comparison silently stops describing what the
   page does.
7. **Unverified**: no browser was driven in this lane. Every measurement here is
   native, node-hosted, or a build artifact. That the rendered document reaches a
   DOM correctly in Chromium and Firefox is R23's to measure, and D129's
   two-engine method is the precedent for how.

---

## 8. Discovered work — described, not registered

**No IDs are minted here.**

1. **The renderer source scan does not cover the file R23 authors.** Measured in
   §1 (e): identical bytes red as `.html`, green as `.template`. R8.2 closes it
   for this filter; the registrar should also decide whether the self-test plants
   into a `.template` path so the coverage cannot narrow again silently.
2. **Three sealer/artifact-authored values reach a terminal unescaped today.**
   `claimed_time_line`, `source_line`, `fetch_date_line` — §1 (j). R9 fixes them
   as part of this work; if that is deferred, it is a live CLI defect of the
   Trojan-Source class D67 §3 R3 was minted for, and it should be carried as one
   rather than as a rendering nicety.
3. **Two shipped doc comments assert a measurably false property** of the report
   (§1 g). They are corrected by R11, but the class is worth noting: the false
   premise entered R23's row *and* the code, from the same source, and neither
   was caught by review.
4. **`RenderedVerdict` is `Serialize` and nothing serializes it.** Measured: no
   consumer outside tests. That is how a whole rendered block sat in core,
   computed on every run, invisible to the row that needed it. Worth a
   convention: a `Serialize` derive with no serializer is a hint that a surface
   is missing.
5. **`RenderedAnchorSlot` deliberately omits the attested block height**
   (`orchestration.rs:497-505`, *"Rendering it here would make this block
   underivable from the report alone"*). R18's residue list already records the
   question as open. This record does not move it, but the page will render an
   `attested` anchor with no height while the overlay's promoted line has one —
   a visible asymmetry a reader may report as a bug.
6. **Whether other coverage-by-literal-set guards share the `.template` blind
   spot** is unverified (§7.5) and worth one sweep.
7. **The rendered document is 2.5× the report** on the measured vector (3 082 B
   vs 1 224 B). Nothing budgets a page-side document size; at cap with 16 384
   files the redaction half is the term that grows. Not a defect, and not
   measured at cap by this lane.

---

## 9. Quoted entry notes (registrar's to apply)

### 9.1 `tasks/R.md` R23 — replace one sentence of `Do`

Strike, from the `Do`:

> All wording comes verbatim from the report's R18 strings.

Replace with:

> All wording arrives as final display strings from `antseal-core` via R22's
> fifth export `verify_rendered` (D130 §3 R1) — **not** from the report, which
> carries none (D130 §1 a.2). The page authors no sentence and does layout only.

### 9.2 `tasks/R.md` R23 — append a `Notes` paragraph

> **[D130, 2026-08-12]** Wording route ruled
> (docs/decisions/D130-r18-wording-route-to-the-verifier-page.md): **this row's
> premise was false and is corrected.** There are no *"report's R18 strings"* —
> measured, all **21** committed report cases carry **zero** rendered prose (the
> only multi-word strings in any of them are the nine sealer-authored fixture
> titles), and the same false sentence sits in two shipped files
> (`crates/antseal-wasm/src/lib.rs:4-6`, `api.rs:96-98`), corrected in the same
> wave. The wording reaches the page as a **core-built rendered document across a
> FIFTH export**, `verify_rendered(bundle_bytes) -> String`, taking no options
> and no evidence document; D18 §5 R4's list opens to five and closes again. The
> document has four members in alphabetical order — `redaction` (new
> `RenderedRedaction`), `rendered` (the existing `RenderedVerdict`), `report`
> (**byte-verbatim**, tier A, identical to `verify()`'s bytes) and `verdict`
> (`VerdictClass`, **without** `exit_code` — D69 §3 R1 keeps one code table and
> it is the CLI's) — assembled by splicing four canonical byte strings, never
> through `serde_json::Value` (D18 §5 R5, D65 §5). **The page calls it ONCE per
> drop and calls nothing else offline**: every export re-verifies from bytes, at
> cap that is multi-second in wasm (R54), and no Web Worker is admissible under
> this row's own CSP (D129 §5 R10), so three calls would be three main-thread
> waits. **What made the fifth export the cheap arm**: `RenderedVerdict` already
> exists, is already `Serialize`, and is built **unconditionally on every
> verification** (`orchestration.rs:1016`) — the shipped module already computes
> the entire offline verdict block, already carries its strings in its bytes
> (measured with `strings`), and throws it away at the boundary. Exposing it
> costs **+3 678 B (+0.20 %)**; with the redaction half **+31 772 B (+1.72 %),
> +11 028 gzipped** — and the **import table is unchanged at 3 allow-listed
> shims**, so D18 §5 R6/R7's structural *"no I/O"* halves are untouched and all
> **21** R9 vectors still verify byte-identically to native *with the fifth
> export present*. **Re-authoring the wording in page JS is already a RED gate**:
> planted into `verifier-web/index.html` it fails
> `no_renderer_source_spells_a_frozen_verdict_string` with four named offenders —
> **but the identical bytes as `verifier-web/index.html.template`, the file this
> row authors, pass GREEN**, because the walk's extension filter is
> `rs|html|js|css` (`verdict_wording.rs:941`); D130 §3 R8.2 adds `template`.
> Escaping stays per-surface (D67 §3 R6/R8 untouched, nothing moves into core):
> `RenderedRedaction::new(view, escape)` takes the caller's function, the CLI
> passing `escape_for_terminal` and `antseal-wasm` its own DOM policy — and it
> applies to **every** sealer-authored value the document embeds, including the
> three (`claimed_time_line`, `source_line`, `fetch_date_line`) that
> `RenderedVerdict` embeds **unescaped today**. Report untouched: `REPORT_VERSION`
> stays 1, zero vectors move. D129's file shape, CSP and packaging order are
> unchanged; the artifact grows by the measured amount and that is R25's to
> record, not to optimise away.

### 9.3 `tasks/R.md` R27 — append to `Notes`

> **[D130, 2026-08-12]** The parity gate's subject is now well defined and its
> limits are stated. Both surfaces read **one assembly**: the page renders
> `verify_rendered`'s document, the CLI folds over the same `RenderedVerdict` /
> `RenderedRedaction`, so a string difference is a defect and not a rendering
> opinion. Three riders. **(i)** Parity holds over the R9 corpus and **must not
> be extended to hostile-path fixtures without excluding
> `redaction.files[].header_line`** — the terminal and DOM escapes neutralise
> different byte sets *by design* (D67 §3 R6), and measured, all nine vector
> paths are unchanged by either policy, so on this corpus the strings are equal.
> A hostile path belongs in each renderer's own suite asserting its own escape.
> **(ii)** The storage-linkage row is a known hazard: the export takes no options
> so the layer always runs (D128 §3 R5), while the committed vectors pin the
> **suppressed** tuple — compare against a native run under `VerifyOptions::new()`
> exactly as `scripts/wasm-boundary.mjs`'s header already explains, never against
> the vector file. **(iii)** Two boundary rows are owed with the fifth export:
> the document's four members are all present, and **`verify_rendered(b).report`
> is byte-identical to `verify(b)`** — required because after D130 the page calls
> `verify_rendered` and not `verify`, so without it the gate's subject and the
> page's path diverge silently.

### 9.4 `tasks/R.md` R22 — append to `Notes`

> **[D130, 2026-08-12]** The closed export list opens to **five**
> (docs/decisions/D130-…): `verify_rendered(bundle_bytes) -> Result<String,
> JsError>`, a two-line shim over `crate::api` like the other four, taking no
> options and no evidence document (the offline rendered block is mode-invariant
> — D64 §2 — and `verify_online` already returns final display strings, so R24
> needs no sixth entry). `scripts/wasm-boundary.mjs`'s `EXPECTED_EXPORTS` and its
> *"four entries"* diagnosis both move; **`scripts/ci-lanes.sh`'s dep-graph rule
> and `scripts/wasm-imports.mjs`'s allow-list do not** — measured, the wasm32
> graph is unmoved (no dependency added) and the built module's import table is
> still exactly **3**. The `lib.rs` module-doc table gains a fifth row, and its
> opening sentence *"whose report already carries R18's final display strings"*
> is **false** and is struck (as is the same claim at `api.rs:96-98`): measured,
> the 21 committed report cases carry zero rendered prose.

### 9.5 `tasks/R.md` R19 — append to `Notes`

> **[D130, 2026-08-12]** `redaction_out.rs` becomes **layout-only**, like
> `verify_out.rs`: core gains `RenderedRedaction` (beside `RedactionView`),
> built once and consumed by both surfaces, and this module's nine `wording::`
> call sites (`:79, 80, 93, 100, 109, 123, 142, 153, 155`) go while its indents,
> its `escape_for_terminal` call and its ordering commentary stay. Its module doc's claim that *"R23's page draws from
> [the table] too"* becomes true for the first time and should be restated as
> *draws from the same assembly*. Work-level totals are `u128` and ride **inside**
> `totals_line` / `withheld_totals_line`, never as JSON numbers (D65 §7 forbids a
> JSON number that can exceed 2⁵³).

### 9.6 `docs/decisions/D18-…` — the four→five amendment, at five sites

An **Amendment** section (D117 §2.2 form: one home, all sites named), striking
*"at most four entries"* → *"at most five entries"* at line 7 (Status) and line
593 (§5 R4), *"closed at four"* → *"closed at five"* in the quoted entry notes at
lines 935, 989 and 1110, and appending entry 5 to R4's numbered list:

> 5. **the offline rendered document** — `verify_rendered(bundle_bytes)`,
>    returning the four-member document D130 §3 R3 fixes. Added by **D130**,
>    2026-08-12, on the measurement that the module already computes
>    `RenderedVerdict` on every run and discards it, that exposing it costs
>    0.20 % of the module, and that the import table does not move. **The list
>    closes again here**: additions beyond five remain a decision, not a code
>    change.

### 9.7 No edits requested

`MVP-SPEC.md` (no line moves — this record implements line 127 rather than
reinterpreting it), `docs/decisions/D29-…`, `D63-…`, `D64-…`, `D65-…`,
`D105-…`, `D128-…`, `D129-…` (each is applied, not amended), `testdata/vectors/**`
(zero frozen bytes move), `crates/antseal-core/tests/snapshots/verdict-wording.txt`
(no sentence is minted).

---

## Registrar's edit set

1. `TODO.md` — mark D130 resolved; **R23 unblocked**.
2. `docs/decisions/INDEX` (or the register's decision index) — one row for D130.
3. `tasks/R.md` — R23 `Do` correction (§9.1) and `Notes` (§9.2); R27 (§9.3);
   R22 (§9.4); R19 (§9.5).
4. `docs/decisions/D18-…` — the Amendment section of §9.6.
5. No other file is edited by the registrar; R8's guard changes and R11's code
   corrections are the implementation lane's.

---

## Outcome

The register asked by what mechanism R18's frozen wording reaches the verifier
page, and the honest first answer is that the question contained a false
statement: there are no report strings to reach it with. Twenty-one committed
report vectors carry thirty-eight distinct string leaves, and the only multi-word
ones are the sealer's own fixture titles. The same false sentence had already
been written into the module's own documentation twice, which is how a row and
the code it blocks can agree with each other and both be wrong.

What the measurement then found is that the mechanism was three-quarters built
and nobody had noticed. `RenderedVerdict` — every string drawn from the frozen
table, values beside renderings, declaration order equal to render order — has
been in core since R21, is built unconditionally on every verification, and its
sentences are sitting in the shipped `.wasm` right now, computed on every drop
and thrown away at the boundary. The CLI has been layout-only over it since U30.
The arm that looked expensive, opening a list closed three weeks ago, turned out
to cost three thousand six hundred and seventy-eight bytes and to move neither
the dependency graph nor the import table — while the arm that looked cheap,
writing the sentences again in JavaScript, is already a red test with four named
offenders.

Except that it is red only by luck. The same bytes pass green under the name the
page will actually be written to, because a walk filters on four extensions and
`index.html.template` has a fifth. The guard that refuses page-authored wording
does not cover the page. That was not visible from reading the filter; it took
planting the fault twice and watching one of them not fire — which is the same
lesson this project keeps paying for, that the medium of the measurement decides
the answer, and that a test's coverage is a thing to measure rather than a thing
to trust.

Two decisions had already ruled most of this without being asked. D64 refused an
overlay field on the report as a format event and put the overlay's final display
strings in a sibling document *"because renderers — CLI and page JS alike — do
layout only"*, naming page-authored wording as a refused class. D65 partitioned
the machine surface into tiers where a byte-verbatim report is frozen and a
rendered sibling is declared unstable. This record does for the offline block
exactly what D64 did for the online one, in the same shape, at a measured cost,
and closes the list again behind it.

---

## Amendment — §3 R2, §3 R3 and §5 R23 item 1, by D132, 2026-08-12

**Amended by [D132](D132-the-pages-probe-plan.md)** at three sites. Per D117 §2.2
this section is the single home of the new fact; the argued body is not edited.

**§3 R2** — the sentence *"So R24's online mode needs **no** further export"*
reaches the right conclusion by the wrong route, and is **annotated, not struck**:
its premise is about the online **wording**, and R24's unmet need was the online
**fetch inputs**. Measured, the block heights fall out of the overlay
incidentally and the transaction hash falls out of nothing. The surface does
close at five — but because of D132, and not because of R2's reasoning.

**§3 R3** — *"Members, in the alphabetical order…"* becomes **five** members,
`plan` first: `{"plan":…,"redaction":…,"rendered":…,"report":…,"verdict":…}`.
R3's own rationale for the `report` member — *"This is what makes one call
sufficient"* — is what admits `plan`: the document is what **one call gives the
page**, not only what the page displays, and it already carried a non-displayed
member.

**§5 R23 item 1** — *"Call `verify_rendered(bytes)` once per drop"* gains its
consequence: the page keeps the parsed document for the session, because `plan`
is read from it at confirm-online time, and **the online path is one further
call, never two** — an empty-evidence bootstrap is refused at a measured
0.96–1.02 × `verify()`.

---

## Correction — two of this record's own figures, and the disposition of §3 R8.2, 2026-08-12

**Three statements of this record did not survive the wave that implemented it.**
The first two are numbers this record itself labelled as predictions; the third
is a rule a sibling decision overtook. No ruling of this record is reversed.

**(1) The module-size figure.** §1 (d) and the Status line state the two halves
together at ***"+31 772 bytes (+1.72 %), +11 028 gzipped"***. Measured on the
shipped module by the implementing lane: **+15 251 B raw (+0.828 %), +5 881
gzipped** — under half the predicted raw cost. The **+3 678 B (+0.20 %)** figure
for the `RenderedVerdict` half alone is not disturbed. The measured pair governs;
the prediction is left in place rather than deleted, so the size of the gap
between a priced arm and a built one stays on the record.

**(2) The count of unescaped values.** §1 (j) names ***three*** sealer-authored
values that `RenderedVerdict` embeds unescaped (`claimed_time_line`,
`source_line`, `fetch_date_line`). It is **FOUR**: `headline_line` embeds
`wording::source_slot(headline.source())`, which is **artifact-authored** and was
equally unneutralised. The implementing lane escaped it under §3 R5's own
*"every sealer- or artifact-authored value"* rule — so the **rule was right and
only its enumeration was short** — and documented the full table on
`RenderedVerdict::new`. The error runs in the direction that strengthens §3 R5:
an escape rule stated by class caught a member its own example list had missed.

**(3) §3 R8.2 is SUPERSEDED, not applied.** It directs adding `"template"` to
`crates/antseal-core/tests/verdict_wording.rs`'s extension filter, so that the
page template this record measured as passing GREEN under a planted fault would
be walked. [D131](D131-the-verifier-web-directory-footprint.md) §5 R1 instead
**renamed the file** to `verifier-web/index.template.html` — extension already
`html`, already walked — and §5 R2 replaced the vacuous `sources.len() > 10`
guard with **per-root floors**. Applying R8.2 literally would mint a filter entry
for a file that no longer needs one, and would leave the guard defect unrepaired.
**§3 R8.1 and the finding behind R8.2 both stand**: the hole was real, it was
found by planting the fault rather than by reading the filter, and the scan is
now red-capable at the ruled name — proven in the implementing wave by a planted
UNANCHORED banner, which the scan named at `verifier-web/index.template.html:39`.

**Authority.** The wave 19 implementing lanes for R23/R24/R25 and the registrar,
2026-08-12, in the same commit as the subject. **All rulings of §3 stand**, and
every error above runs toward the ruling rather than away from it: the export is
cheaper than argued, the escape rule caught more than it listed, and the guard
hole is closed by a better mechanism than the one prescribed.

---

## Correction — the parity clause's comparison is not the one that holds, and it does not live where two documents cite it, 2026-08-16

**The corrected sentence, quoted verbatim**, from **§5**, subsection
`### R27 / Q19 — the parity gate`, clause 1:

> for each R9 vector, `JSON.parse(verify_rendered(b))` on the page and the CLI's
> `VerifyRun::render()` lines must agree **string for string** after the CLI's
> indentation is stripped.

**Two things are wrong, and the second is the expensive one.**

**(1) The locator.** Both `docs/decisions/D133-the-attested-anchor-fixture.md`
(its R27 note) and `tasks/R.md`'s R27 entry cite this clause as **"D130 §7.3"**.
This record has no §7.3 clause of that content: §7 is `## Residual risk`, and its
item 3 is a different claim — *"the parity gate can pass while the two surfaces
disagree on hostile input"*. A lane sent to §7.3 to read the parity rule finds a
sentence about escaping instead.

**(2) The comparison.** Indentation is **not** the only difference between the
two renderings. Measured 2026-08-16 by the **R27** lane while building the
comparison the clause describes:

```
CLI  (crates/antseal-cli/src/verify_out.rs:156):
     one line per slot — "{slot}: {state_line}{tag}"
page (the rendered DOM):
     "{slot} {tag}" in one <p>, and {state_line} in the next
```

So the page's text for one slot is **two elements** where the CLI's is **one
line**, and the tag sits on the opposite side of the state text. **A lane taking
the sentence literally builds a gate that reddens on a correct page** — which is
what happened, and what the R27 lane had to work around before its 86-row
comparison could go green.

**Authority.** The **R27** lane, 2026-08-16, by constructing the parity
extractor this clause specifies and measuring both surfaces; recorded by the
registrar at the wave-21 close, in the same commit as R27's tick, because the
corrected text is what the shipped extractor contradicts.

**Which rulings still stand.** All of them, and the error runs in the direction
that **understates the work** rather than overstating the guarantee. §3 R3's
one-assembly ruling is untouched and is exactly why the comparison is meaningful:
both surfaces read `verify_rendered`'s document, so a real difference is a defect
and not a rendering opinion. §5's requirement that the gate compare rendered
strings stands; only its description of the *shape* of the two renderings is
corrected, and the correct comparison is per-slot rather than per-line. §7 item 3
(hostile input) and §7.3 (i)'s `header_line` guidance are unaffected — R27's
fixtures are not hostile-path fixtures and need no exclusion.
