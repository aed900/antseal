# D64 — Online-overlay ↔ headline presentation: the frozen two-block layout, and what the overlay computation returns

- **Status: RESOLVED — TWO STACKED BLOCKS, and the lean survives its block
  structure ON MEASUREMENT while its overlay-content clause is OVERTURNED on
  the spec's own sentence.** The offline verdict renders first, complete, and
  **byte-identical to a run without `--online`** — the UNANCHORED banner
  included — because that is already a frozen acceptance (R24: *"Offline
  verdict rendering is byte-identical before and after overlay activation
  (overlay strictly additive)"*), which kills every composite-single-verdict
  arm outright and forces a stronger corollary the lean missed: **the offline
  block may carry no overlay-contingent marking at all; every contrast label
  lives inside the overlay block.** The overlay is **not** the lean's
  "re-states nothing it doesn't change" delta: MVP-SPEC line 137's UNANCHORED
  sentence says `--online` *"then supplies the headline"*, R21/R24 both say
  *"promoted headline attribution"*, and the promoted time **exists nowhere in
  report v1** (`AnchorResult::verified_time_unix` is `null` on `attested`; the
  `proven` time is read off the *agreed* header's `nTime` at promotion) — so
  the overlay is a **full second aggregation** over the online-augmented
  anchor states, rendered as an **impact against the offline verdict**:
  exactly one headline-impact line (supplies / stands / still-unanchored),
  always-rendered per-probed-anchor outcome lines, and change-only aggregate
  lines. The overlay's headline, when it exists, **reuses the one spec
  headline template with a mandatory online-attribution marker** — never a
  second claim-shape (Q89 discipline). Data home: the overlay is a **sibling
  document beside report v1, never a report field** — `REPORT_VERSION` stays
  `1`, zero frozen bytes move, and the never-overwrite rule becomes a
  machine equality: *the report bytes of a `--online` run are identical to
  the offline run's.*
- **Date: 2026-08-11** (wave 17 planning lane, briefed to overturn the
  register's two-block lean; all three overturn arms taken to measurement —
  one kills a clause of the lean, two die on frozen acceptances and on what
  report v1 provably cannot carry)
- **Owning tasks: R17** (output contract bound THIS WAVE, §6), **R18**
  (freezes the strings inside this structure, §3), **R21/R24** (render both
  surfaces under it; R21 gains the report-byte equality), **R22** (the overlay
  entry is the page's carriage), **R61** (declares the non-string surfaces,
  §5), **U30/D65** (envelope carriage of the sibling document). Register
  entry: the D64 row under `TODO.md` "Due M3".
- **Method**: read/grep only (shared working tree; no builds, no writes
  outside this file). Code line numbers below were measured on the tree as of
  this record's date while sibling lanes were active; cite them as
  snapshots, not as stable anchors. The frozen registry is cited by section
  only.

---

## 1. What was measured

**(a) The spec's own sentences — which words are normative, and which are
task gloss.**

MVP-SPEC.md line 137 (verifier page, online mode) is the decision's anchor,
and it contains **both** halves of the tension in one line:

> Online mode: **two pinned default endpoints per source, results must
> agree** (…), user-overridable, **rendered as an advisory overlay distinct
> from the offline cryptographic verdict.**

and, earlier in the same line, for the zero-eligible-offline case:

> It arises only for `--force-degraded`/`--no-anchor` seals, or a bundle
> carrying only a `pending`/`attested` OTS — **where `--online` or a later
> `status --upgrade` then supplies the headline.**

So *"advisory overlay distinct from the offline cryptographic verdict"* is
the **spec's own text**, not a task-entry gloss — overturn arm (i)'s premise
is half false. The *"never overwriting"* phrasing is the task entries'
(R17/R21), but it is a faithful gloss: R24's Accept makes it mechanical
(*"Offline verdict rendering is byte-identical before and after overlay
activation (overlay strictly additive)"*, `tasks/R.md` §R24). What the same
line 137 **also** grants — and the lean under-sold — is that the online run
owns a headline: *"supplies the headline"* is spec text too.

Line 108 (anchoring): `--online` *"promotes the anchor to `proven`
(headline-eligible) — normally the earliest, strongest anchor."* Note the
physics: for a normally-anchored same-day seal the TSA `genTime` is the seal
instant while the Bitcoin block confirming the calendar's commitment is
mined later, so "earliest" holds routinely only for the bundles line 137
enumerates (no offline-eligible anchor) — recorded as spec-prose tension in
§9, not code-facing, since earliest-wins handles both.

Line 38 (verify flow) orders the surfaces: *"offline verdict: … Optional
`--online` confirms …"* — offline first is the spec's own narration. Line 28
(positioning) requires possession language everywhere; the overlay's framing
inherits it.

**(b) The frozen acceptances that decide the block question.**

- `tasks/R.md` §R24 Accept: offline rendering **byte-identical** before and
  after activation — a composite verdict with provenance columns would
  rewrite the headline line on activation; dead.
- `tasks/R.md` §R21 Do: *"produce an advisory overlay distinct from and
  never overwriting the offline verdict, including promoted headline
  attribution, `invalid` on header mismatch, and an explicit disagreement
  outcome when the endpoint pair conflicts (no promotion on disagreement)"*;
  Accept: *"disagreement → advisory disagreement outcome, offline verdict
  untouched"*.
- `tasks/R.md` §R17 Do: *"a second, online-augmented computation …
  producing an overlay verdict distinct from, and never overwriting, the
  offline verdict"*; Accept: *"promotion feeds only the overlay
  computation"*.
- The open-decision row itself (`tasks/R.md`, Open decisions): *"exact
  layout for how a `--online`-promoted anchor **supplies the headline**
  while the offline cryptographic verdict stays distinct and visible"* — the
  register's own question presumes the overlay owns a headline slot.

**(c) What the shipped code already enforces — the disagreement outcome
cannot reach a verdict, and the promoted time cannot reach the report.**

- `crates/antseal-core/src/anchor/model.rs` (~:398–518): `OnlineBlockResult`
  has **no failure variant, deliberately** — D56 §3 rules that
  attempted-but-unreachable and attempted-but-disagreeing both leave an
  anchor at `attested`, and the ruling is *structural*: those cases are the
  **absence of the entry** in `BlockEvidence`, the matches are
  wildcard-free so adding a failure variant does not compile, and the doc
  records *"`antseal-anchor` keeps A16's richer typed outcome for the
  overlay; it simply has nothing to hand core."* The disagreement datum is
  host-side today, by construction.
- `crates/antseal-core/src/anchor/verdicts.rs` (~:763–825): D93 §5's guard —
  agreed evidence can **refute** (O6 header-differs, O7 no-such-block →
  `invalid`) as well as promote (O3 → `AnchorVerdict::proven(Ots,
  nTime-of-agreed-header, Some(bitcoin_source(height)), …)` with identity
  `AnchorIdentity::BitcoinChain`, per D92 §5.1: what proved it is Bitcoin,
  not the calendars). The promoted **time is read from the agreed header**,
  a value that exists only when online evidence was supplied.
- `crates/antseal-core/src/verify/report.rs` (~:146–176, :542–603):
  `VerificationReport` has seven fields, none an aggregate — the report doc
  itself says the UNANCHORED outcome *"aggregates from exactly this data in
  R17"*. `AnchorResult` has exactly five fields; `verified_time_unix` is
  populated *"only for time-proving states"* — an `attested` slot carries
  `null`, and no field carries the block height. The receipt doc records
  that the two-RPC confirmation is *"deliberately absent: it is an overlay
  on an overlay … and `verify_bundle` performs no online step at all."*
  **Therefore no overlay layout is renderable from report bytes** — overturn
  arm (iii) is measured true and, rather than overturning the block
  structure, it binds R17's contract (§6).
- `crates/antseal-anchor/src/agree.rs`: A16's `must_agree` compares
  consumer-extracted values; `EndpointFailure` keeps transport / payload /
  wrong-chain apart — the typed outcomes the overlay must render, living in
  a non-WASM crate.
- House conventions, `crates/antseal-cli/src/status.rs` (~:414–545, U23):
  headline as *"existed no later than \<unix\> (\<kind\>, \<source\>)"*,
  eligibility delegated to **one** predicate (*"there is no second
  eligibility table here"*), per-anchor rows slot-named, receipt outside the
  per-anchor section, the `--json` document wrapped by U3's envelope
  (:594–597) — the wrap-don't-extend pattern this record reuses.
- Precedent for the data home: R11's execution note (`tasks/R.md` §R11):
  `LiveVerdict` *"never enters `REPORT_VERSION` bytes, and R20/R21 render it
  in its own section where it stays advisory."*
- D95 rider (b): the report is a machine format; renderers receive final
  strings (R74's no-bump route is *"R18 embedding final display strings"*,
  which is also the only route by which the page can render the `attested`
  wording's block H — the height is in `AnchorVerdicts`, not in any
  `AnchorResult` field).
- Q89 (`tasks/Q.md` §Q89): two true numbers side by side read as a
  contradiction *"unless the datum names diverge"* — the wording is
  R18/R61's; the **placement** of the two headline-shaped sentences this
  layout can produce is this record's.

---

## 2. Ruling 1 — two stacked blocks, and the offline block is inviolate

**The online run renders two stacked blocks: the offline verdict first,
complete, byte-identical to a run without `--online`; the overlay appended
below it.** Never a composite verdict, never provenance columns inside the
offline block, never a reordering that leads with the overlay.

The corollary that does the real work: because activation may not move an
offline byte (R24 Accept), **the offline block cannot gain a heading, a
label, or any "see below" marker when the overlay activates. All contrast
marking — the advisory framing, the reference to "the offline verdict
above", the online-attribution on the overlay's headline — lives inside the
overlay block.** The offline rendering is one artifact with one spelling,
whether or not an overlay follows it.

Order is offline-first on three grounds: appending is what "strictly
additive" means operationally on both surfaces (the page's overlay section
is created on user action below an already-rendered verdict, R24); line 38
narrates the product that way; and leading with the network-contingent
advisory would front the weaker-provenance claim against line 28's
positioning discipline.

## 3. Ruling 2 — the overlay is a full second verdict, rendered as impact

**R17's online-augmented computation is a complete aggregation** (same
eligibility map, same earliest-wins, same divergence rule, same UNANCHORED
predicate — one predicate, per U23's precedent) **over the anchor states
`evaluate_anchors` produces when given the agreed online evidence.** The
overlay block renders that computation **as an impact against the offline
one**, in this fixed structure (all strings illustrative; authorship marked
in §3.1):

```
<offline verdict — byte-identical to a run without --online>

online advisory — <framing sentence: must-agree endpoint pairs; does not
                   replace the offline verdict above; can strengthen or refute>
  <headline-impact line — exactly one of three>
  <per-probed-anchor outcome lines — always, one per probed anchor, slot-named>
  <receipt confirmation line — only when a receipt is present and was probed>
  <endpoints disclosure line — pinned defaults, or labeled override>
  <change-only aggregate lines — e.g. a newly-flagged >48 h divergence>
```

**The headline-impact line renders always, and is exactly one of:**

1. **Supplies** — the online computation's headline differs from the offline
   one (a promoted anchor is now earliest), or the offline block was
   UNANCHORED and the online set has an eligible anchor. Renders a **full
   headline sentence** using **the one spec template** — *"Existed no later
   than \<time\> (source)"* — with a **mandatory online-attribution marker**
   in or beside the source slot (the promoted verdict's own verified datum:
   Bitcoin block H, online-confirmed; D92 §5.1's `BitcoinChain` identity is
   the Verified-register source, satisfying R74's claimed/verified
   discipline). This is line 137's *"supplies the headline"* and R21/R24's
   *"promoted headline attribution"*, made a place.
2. **Stands** — the online computation's headline equals the offline one
   (the routine case: TSA `genTime` precedes the confirming block's
   `nTime`). Renders an explicit stands-line pointing at the offline
   headline; it does **not** restate the sentence.
3. **Still unanchored** — the online set still has zero eligible anchors
   (probe failed / disagreed / refuted-only). Renders an explicit
   still-unanchored line.

Why neither pure option: **pure delta** (the lean) dies on line 137's
*supplies* sentence — in the UNANCHORED-offline case the overlay carries the
product's only provable-time claim and must state it whole — and on the
report measurement (§1c): the promoted time is not derivable anywhere else.
**Pure full-restatement** dies on Q89: an identical sentence printed twice
reads as redundancy or contradiction, and restating the offline headline
inside the advisory block is exactly what lets the advisory block be quoted
alone as if it were the verdict. The impact form keeps the lean's correct
core — subordination, no gratuitous restatement — while giving the spec's
*supplies* case a complete sentence.

**Template unity is frozen:** the overlay never mints a second
"existed no later than"-class shape. One template, two provenance labels
(the offline sentence bare, the overlay's marked) is what makes two times in
one output read as two facts — Q89's rule applied to headlines.

## 4. Ruling 3 — UNANCHORED + successful promotion

**The loud UNANCHORED banner renders in the offline block, unchanged and
unsoftened, and the overlay directly below carries the Supplies-form
headline.** Forced, not chosen: the banner is part of the offline rendering
R24 freezes byte-identical, and the offline cryptographic verdict of such a
bundle *is* unanchored — the spec designs this exact adjacency (line 137's
UNANCHORED sentence and its *supplies* clause are one sentence). The
overlay's framing sentence and attribution marker are what keep the pair
readable as "no offline provable time; an online-confirmed time follows",
and the adjacency is a mandatory R18 snapshot case (§8, L3).

## 5. Ruling 4 — where disagreement and refutation render

Two different things, kept apart by the machinery already shipped:

- **Endpoint-pair disagreement** (blockstream and mempool answer
  differently, or an endpoint fails): structurally invisible to
  `evaluate_anchors` (no failure variant; absence of the entry), so **both
  computations leave the anchor `attested` and the outcome renders only in
  the overlay**, as that anchor's always-rendered outcome line — advisory
  register, **no state word** (nothing changed state), naming the
  disagreement (or the per-endpoint failures, R24) and stating that the
  offline state stands. **It suppresses promotion for that anchor alone**:
  `BlockEvidence` is keyed by height, so other anchors with agreed evidence
  still promote — measured on `with_block`/`block(height)`.
- **Agreed refutation** (agreed header differs from the embedded one; agreed
  no-such-block): the online computation renders that anchor `invalid`
  (D93 §5's guard, O6/O7). **It renders in the overlay** — the offline block
  still shows `attested`, correctly: offline, the bundle is internally
  consistent, which is line 108's deliberate online-gating — as that
  anchor's outcome line carrying the **state word `invalid` and the error
  code** (the `anchor-forged-header` tamper family). The framing sentence
  must therefore say the overlay can strengthen **or refute** — the lean's
  "advisory = good news" framing under-described it.

TSA anchors get no outcome line (no online step, R21); the framing sentence
carries the scope. The receipt confirmation renders only in the overlay, in
the supporting-evidence register, with no time and no state — the report-side
shape (`SupportingEvidenceResult` carries *"no time field and no state
field — not a null one, none"*) is the model.

## 6. Ruling 5 — R17's output contract, and the D105 adjudication

**The overlay is a sibling document beside report v1 — never a report
field, never a value addition, never renderer-composed.**

- **Report-cost adjudication (D105):** an `overlay` field on
  `VerificationReport` is a FORMAT EVENT (D105 §2.4 as restated in R20's
  entry: a field on any of the eight named structs costs the
  `REPORT_VERSION` bump) — refused. Mutating anchor states inside the report
  on an online run is refused twice over: it overwrites the offline verdict
  (line 137) and it breaks R24's byte-identity. No value addition is needed
  either: **the online computation's states never serialize into report v1
  at all.** `REPORT_VERSION` stays `1`; zero frozen vectors move.
- **The equality that makes "never overwriting" red-capable:** for one
  bundle and one `verify_at`, **the canonical report bytes of a `--online`
  run are byte-identical to the offline run's** — promotion, refutation,
  disagreement and all. This is the D95-rider-(c) move: the containment is
  an equality, not an adjective. R21 gains it as an Accept row (§8).
- **R17 ships, in `antseal-core`, WASM-safe and deterministic:**
  1. `VerdictAggregate` (or equivalent) — headline
     `{time, kind, source}` by earliest-wins over the eligible set,
     eligible count, the >48 h divergence outcome, the UNANCHORED predicate,
     the receipt's class — computed from `AnchorVerdicts` via the **single**
     eligibility predicate (U23's "no second table" rule).
  2. `OnlineOverlay` — built from the offline aggregate, the
     online-augmented aggregate, and the probe log: per-probed-anchor
     outcome (**closed class set frozen here**: `Promoted{time, height,
     source}` · `Refuted{state=invalid, code}` · `NotPromoted{disagreed |
     endpoint-failures(per-endpoint) | no-evidence}`), the three-way
     `HeadlineImpact` (`Supplies{headline}` · `Stands` ·
     `StillUnanchored`), the receipt confirmation echo, the endpoint
     disclosure (identities + pinned-or-overridden), and change-only
     aggregate outcomes (newly-flagged divergence). **Final display strings
     embedded** (the R74/R22 pattern: renderers — CLI and page JS alike —
     do layout only). Slot names align with the offline block's per-anchor
     rows (U23's slot convention).
  3. **A typed probe-outcome input** — new, core-owned, data-only,
     constructible from literals — carrying what D56 §3 keeps out of the
     verdict path: per-height agreed/disagreed/failed(per-endpoint)/
     not-attempted, the receipt probe outcome, endpoint identities and the
     overridden flag. The CLI populates it from `antseal-anchor`'s A16/A17
     typed outcomes (`EndpointFailure` et al.); the page populates it from
     its own `fetch()` outcomes through R22's overlay entry. **It is a
     rendering input, never a verdict input**: `evaluate_anchors`'s
     signature and the no-failure-variant rule are untouched — without this
     type, the page's disagreement and fetch-failure lines would be
     page-authored wording, recreating exactly the R61 asymmetry class.
- **Two computations, one run:** the orchestration (R21) obtains offline
  verdicts (empty `OnlineEvidence`) and online-augmented verdicts (agreed
  evidence supplied), aggregates each, and hands both plus the probe log to
  the overlay builder. R17's Accept already pins the direction: *"promotion
  feeds only the overlay computation."*
- **Carriage:** the overlay document serializes deterministically under
  D29's discipline by construction (compact JSON, declaration order, no
  conditional keys) but is **not** governed by D29's report freeze — it
  rides U30's `--json` envelope **beside** the verbatim report bytes
  (status.rs's U3 wrap pattern; envelope schema stability is **D65's**, not
  pre-empted here) and is the return value of R22's overlay entry for the
  page. The live section (R11's `LiveCheckReport`) is the precedent and
  stays a third sibling, CLI-only.

## 7. What does **not** decide it

- **Line 108's "normally the earliest, strongest anchor" does not make the
  promoted headline the run's one headline.** The same spec line 137 that
  grants *supplies* also mandates the advisory overlay "distinct from the
  offline cryptographic verdict", and R24's byte-identity acceptance is
  already frozen. The two-block layout gives the promotion its full
  headline sentence — in the overlay, attributed.
- **The page's data poverty does not force composite rendering.** R22's
  second entry exists precisely so the page can render online results
  without report-v1 carriage; what it forces is the embedded-strings
  contract (§6), not a layout.
- **D56 §3's network-weather rule is not softened by rendering
  disagreement.** The overlay renders the *probe outcome*; no state moves.
  The wildcard-free matches stay the enforcement.
- **Cost did not decide the report question.** A report field would have
  been cheap to write; it loses on meaning (an offline canonical document
  carrying run-contingent network results) before it loses on the version
  bump — the same shape as D95 §2c's "suppression loses on meaning".

## 8. Implementer edits and proposed instruments

**Edits beyond R17/R18's own entries** (enumerated for the registrar; none
performed here):

1. `crates/antseal-core/src/verify/report.rs` — `to_canonical_json`'s doc
   ("Also the payload for CLI `--json` (R21/U30) and the page binding (R22)
   — one serialization path everywhere") gains one line when R21 lands: the
   envelope carries overlay/live sections **beside** these bytes, never
   inside them; the report bytes remain the one offline payload, verbatim.
2. `crates/antseal-core/src/anchor/model.rs` — `OnlineBlockResult`'s doc
   sentence *"it simply has nothing to hand core"* gains a D64
   cross-reference: core gains a **rendering-input** probe type (§6.3); the
   no-failure-variant rule remains the law of the **verdict** path.
3. `tasks/R.md` §R21 — Accept gains the report-byte equality row (§6): one
   bundle, one `verify_at`, `--online` and offline runs produce
   byte-identical report bytes.
4. `tasks/R.md` §R61 — the declared-divergence header gains the overlay's
   non-string surfaces: the activation affordance (CLI flag vs page
   button + pre-activation placeholder), the page's visual distinction
   (CSS), and R23's busy affordance — chrome, never verdict wording, and
   the busy affordance renders inside neither block.
5. `tasks/R.md` §R24 — note: the "departing from pinned defaults" label is
   the overlay's endpoints-disclosure line, sourced from the shared table
   via overlay data, not page-authored.

**String authorship**: D64 freezes the *structure* — block order; offline
immutability; the overlay heading containing "online" and "advisory" plus a
non-replacement clause referring to the verdict **above**; the framing's
strengthen-or-refute disclosure; the three-way impact class and its
one-of-three obligation; headline-template reuse with mandatory
online-attribution marker; always-on probe lines (slot-named, TSA-less,
state-word only on refutation); overlay-only receipt confirmation in the
supporting-evidence register; the endpoints-disclosure line; change-only
aggregate lines. **Every sentence spelling inside that structure is R18's
to author**, under line 28's possession language.

**Proposed instrument-ledger lines** (proposed only; not written):

- **L1**: R21 report-byte equality under `--online` (the never-overwrite
  equality, §6) — red-capable against any implementation that renders the
  online computation as *the* verdict.
- **L2**: exhaustive overlay-outcome rendering — every §6.2 outcome class
  has an R18 row; a new class without one fails (R18's existing
  exhaustive-enumeration pattern).
- **L3**: adjacency snapshots, CLI/page string-equal via R27: (a)
  UNANCHORED offline + Supplies overlay (§4); (b) earlier-promoted-time —
  two headline-shaped sentences, labels diverging; (c) disagreement —
  offline bytes untouched, advisory line rendered (already R21/R27's case,
  extended to the layout).

## 9. Measured vs. assumed, and residual risks

**Measured:** everything in §1, on the named files/sections at this record's
date (shared-tree snapshot caveat in the front matter). **Assumed:** that
R22's overlay entry returns the serialized `OnlineOverlay` (its entry text
predates this record and says only "an entry accepting pre-fetched
online-endpoint responses"; this record fixes its return by contract, R22
executes); that A25's recorded fixtures plus A18's test surfaces suffice for
overlay snapshots without live calendars (R27's mock routes are the venue).

**Risks / revisit triggers:**

- **The spec-prose tension** (line 108's "normally the earliest") is
  recorded, not edited: earliest-wins over the augmented set is the rule on
  both blocks, and no code branches on "normally". Trigger: any implementer
  citing line 108 to rank the promoted anchor above an earlier TSA.
- **D65 could later fold the overlay into a report v2.** Legal, but it must
  arrive as a deliberate FORMAT EVENT with the equality (L1) consciously
  re-scoped — never as a drive-by field. Trigger: any `overlay`-named key
  appearing inside `VerificationReport`'s serialization.
- **The stands-line's restraint depends on headline equality being exact.**
  Two eligible anchors at the same second with different sources compare
  equal on time; the impact classifier must compare the headline datum
  (time + source), not time alone, or a source-only change would render
  "stands" while the parenthesis silently differed. R17 owns the tiebreak;
  its earliest-wins tests already exercise time ties.
- **R18 freezing before the probe-input type exists** would leave
  fetch-failure/disagreement rows unexercisable by core tests. Order inside
  the wave: R17's types land before R18's snapshots — already R18's
  dependency direction (Deps: R17).
