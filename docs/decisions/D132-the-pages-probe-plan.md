# D132 — How the verifier page learns what to probe: a fifth member on D130's document, not a sixth export

- **Status: RESOLVED — the page gets its probe plan as a **FIFTH MEMBER,
  `plan`, on the document D130's fifth export already returns**.
  `verify_rendered(bundle_bytes)` becomes a five-member document
  (`plan`, `redaction`, `rendered`, `report`, `verdict`) and **D18 §5 R4's list
  stays at FIVE** — no sixth export is minted. The register's framing is wrong
  in both directions and the measurements say so. **The Bitcoin half was never
  the question**: it is reachable *three* ways today, and the cheapest of them
  (an empty-evidence `verify_online`) returns every height, measured. **The
  receipt half is reachable zero ways** — the transaction hash
  `eth_getTransactionReceipt` needs is in no document the page can see, proven
  at the value level and not merely by grep. So D132 is a decision about **one
  32-byte value**, and every "no new surface" arm solves only the half that was
  already solved. **The cost intuition is also wrong: a sixth export costs
  146 bytes.** What costs bytes is the plan *value* — **+11 368 B (+0.622 %)** —
  and **both** arms pay it identically, so bytes do not decide between them
  (the export shim is 1.6 % of the change). Nor does time: `probe_plan` as its
  own export is a decode, **0.0199 ms — 1.2 % of a `verify()`**. What decides
  is that a decode-only export would hand a plan to a bundle that **failed
  verification**, while a member on `verify_rendered` **cannot exist without a
  passing offline verdict**, and that D130 §7.1's own recorded risk — *"the
  surface is open by one, and the next request will be easier to make"* — comes
  due one wave later and is answered by refusing. **D130 §3 R2 is half right
  and is corrected here**: *"R24's online mode needs no further export"* is true
  of the online **wording** and false of the online **inputs**.
- **Date: 2026-08-12** (wave 19 planning round, D132 lane; briefed to overturn
  its own lean, and the lean lost its two best reasons to measurement — a sixth
  export is neither expensive nor slow. Three findings came from running things
  rather than reading them: the CLI's probe set is **strictly wider** than the
  overlay's and the difference is **provably inert** in all three documents,
  including under a refuting answer; **all 21 R9 vectors yield an empty probe
  plan**, so the committed corpus cannot exercise online mode at all; and both
  "obvious" cheaper encodings of the transaction hash are **measured backwards**
  — a hand-rolled hex table costs **+11 977 B more** than `format!("{b:02x}")`.)
- **Owning tasks: R24** (blocked by this; performs the fetches and builds the
  evidence document), **R22** (the boundary crate; the document gains one
  member and `ProbePlan` reaches it), **R21** (owns the orchestration seam the
  plan is derived at), **R23** (its document grows by one member it does not
  display), **R27/Q19** (the online cases, whose fixture hole this record
  names), **R25** (the artifact grows by the measured amount), **U30** (the CLI
  probe path becomes a call to the shared function).
- **Amends**: `docs/decisions/D130-…` §3 R2 (its second sentence — the online
  *inputs* clause), §3 R3 (four members → five) and §5 R23 item 1;
  `docs/decisions/D64-…` **not at all** (§3's receipt presence rule stands —
  see §4). **Supersedes**: nothing. **Corrects**: D130 §3 R2's *"needs no
  further export"* reasoning, which is sound in its conclusion and unsound in
  its premise.

---

## 1. What was measured

Everything below was run on `9ffe8b7`. Rust and wasm experiments ran in a
**clean `git archive HEAD` extraction** under the session scratchpad — not an
`rsync` of the working tree — because the **D130 implementation lane is editing
the working tree concurrently**; nothing in `crates/`, `tasks/`, `scripts/` or
`TODO.md` was written by this lane. Working-tree line numbers below carry the
timestamp at which they were read.

### (a) The Bitcoin half is reachable, and the bootstrap returns exactly the heights — run, not reasoned

`overlay.rs:606-631` walks `artifacts.ots()` and pushes an
`OverlayAnchorOutcome { slot, height, class, line }` for every anchor whose
**offline** state is `Attested`; `classify_probed_anchor` handles
`probes.block(height)` being `None`. Run against a genuinely attested bundle —
built the way `orchestration/tests.rs`'s `attested_bundle()` builds one (R6
fixture, typed anchor substitution, re-encoded through `encode_bundle`, the
`.ots` stamping the rebuilt bundle's own `anchor_digest`) — with a host holding
`OnlineEvidence::new()` and `ProbeLog::new(endpoints)`:

```json
{"framing_line":"online advisory — must-agree endpoint pairs; …",
 "headline_impact":"still-unanchored",
 "anchor_outcomes":[{"slot":"ots-1","height":700311,
   "class":{"not-promoted":{"reason":"no-evidence"}},
   "line":"ots-1: no agreed online evidence for block 700311 — no promotion; the offline state stands"}],
 "receipt":null, "endpoints":{…}, "aggregate_deltas":[]}
```

**The height is there, as a `u64`, beside its line.** Two attested anchors give
two rows. Confirmed again through the **JS boundary** on the shipped artifact
(`target/wasm-pack/antseal-wasm/`, copied to the scratchpad before the D130
lane could rebuild it; SHA-256
`5bbdc113d45d5b6c3dbe209003a4d0d37cf289bb31ed3d5837a088c15f6539c4`,
1 841 981 B, four exports):

```
one-attested:        ACCEPTED — heights=[700311]        receipt=null
two+broken+receipt:  ACCEPTED — heights=[700311,700412] receipt=null
multi-file/all:      ACCEPTED — heights=[]              receipt=null
```

So the brief's measurement 1 holds. **It is not the only route.** Two more
exist and both were measured:

- **The report already carries the height, inside a display string.** A
  verified report of the attested fixture renders
  `"anchors":[{"kind":"ots","state":"attested",…,"source":"bitcoin-block-700311",…}]`.
  A page could regex `bitcoin-block-(\d+)` out of tier A. Refused in §4, but it
  is a real third route and the record should not pretend otherwise.
- **The page holds the bundle bytes** and could walk the CBOR itself. Refused
  in §4.

### (b) The receipt half is reachable zero ways — at the value level, not by grep

`crates/antseal-cli/src/verify_host.rs:160-168`:

```rust
if let Some(pair) = &endpoints.arbitrum
    && let Some(tx_hash) = bundle
        .receipt()
        .and_then(|record| record.tx_hashes().first().copied())
```

Every route to JS was checked by **running a receipt-bearing bundle through the
machinery and searching the emitted bytes for the hash**, rather than by
grepping source:

```
report contains tx hash?  false
overlay contains tx hash? false
verdict_class contains?   false
```

and structurally:

- `SupportingEvidenceResult::ArbitrumReceipt` (`report.rs:745-757`) carries
  **`block_number` and `transaction_count`, and nothing else** — its doc says
  the arm carries *"no time field and no state field — not a null one, none"*;
  it carries no hash either.
- `RenderedVerdict::supporting_evidence` is built from that arm
  (`orchestration.rs:472-481`), so it inherits the same two figures.
- `OnlineOverlay::receipt` is `Option<ReceiptEcho>` and `receipt_echo`
  **returns `None` for `ReceiptProbe::NotAttempted`** (`overlay.rs:790-801`).
  Measured on a receipt-bearing bundle with an empty probe log: `receipt:null`.
  A receipt-only bundle with no anchors yields
  `anchor_outcomes:[] receipt:null` — **the bootstrap overlay is completely
  silent that a receipt exists at all.**
- `tx_hash`/`tx_hashes` appears in no `antseal-wasm` file (grep, exit 1) and in
  no serializer outside `test_util/vectors_bundle.rs`.

**This is the whole of D132.** One 32-byte value, on a boundary that already
carries the 10 KB bundle it came from — so no confidentiality argument is
available against moving it: the page has the bytes.

### (c) The CLI's probe set is strictly wider than the overlay's, and the difference is provably inert

`verify_host.rs:142-149` probes **every OTS anchor carrying an upgrade**;
`overlay.rs:606-631` names only the **offline-`attested`** ones. On a fixture
with two attested anchors plus one whose embedded header commits a different
digest:

```
cli plan heights   = [700311, 700412, 900001]
overlay heights    = [700311, 700412]
```

The extra height belongs to an anchor that is offline `invalid`. Whether that
matters was **measured, not argued** — the same bundle run twice, once with the
page's (narrow) evidence and once with the CLI's (wide):

```
report identical?   true
overlay identical?  true
verdict identical?  true
```

and again with a **refuting** answer at the broken height (the chain returning
the *other* header):

```
report identical to page's?  true
overlay identical to page's? true
verdict identical to page's? true
```

So the two plans are interchangeable for every document either surface emits.
The set relation also cannot invert: `{carries an upgrade}` ⊆
`{attested} ∪ {invalid}` (O4 requires the upgrade; a partially-upgraded merge
is attested, not pending — `verdicts/tests.rs:1029`), and `invalid` has no
promotion path, so the narrow set can never miss a promotion the wide one
catches. **Either is correct; §3 R4 rules the wide one and says why.**

### (d) The empty-evidence document, exactly, and what it may not omit

Accepted by the shipped module (158 bytes):

```json
{"schema":"antseal.online-evidence.v1","endpoints":{"identities":["https://blockstream.info/api","https://mempool.space/api"],"overridden":false},"blocks":[]}
```

Variant acceptance, measured through `verify_online` on the shipped artifact:

| variant | outcome |
| --- | --- |
| `blocks` omitted entirely | **OK** (`#[serde(default)]`) |
| `endpoints` omitted | **REFUSED** — *"missing field `endpoints`"* |
| `identities: []` | **OK**, and renders *"endpoints: none recorded (pinned defaults)"* — a **false disclosure** if the page sends it |
| `receipt: null` explicit | **OK** |
| any extra key (e.g. `"plan": true`) | **REFUSED** — `deny_unknown_fields`; *"unknown field `plan`, expected one of `schema`, `endpoints`, `blocks`, `receipt`"* |

The last row is load-bearing for §4: **the evidence document cannot be widened
to carry a hint**, by construction.

### (e) The bootstrap costs a whole verification; a decode-only export costs 1.2 % of one

Interleaved rounds (all arms equally JIT-warm; 12 rounds × 40 calls; medians),
through the JS boundary on the shipped artifact:

| bundle | `verify` | `verdict_class` | `verify_online(EMPTY)` |
| --- | ---: | ---: | ---: |
| `multi-file/all` (9 307 B) | 1.356 ms | 1.449 ms | **1.385 ms** |
| attested fixture (9 486 B) | 1.369 ms | 1.344 ms | **1.318 ms** |

**A bootstrap is 0.96–1.02 × a `verify()`** — it *is* a verification, and it is
**serial before any fetch can start**. Against R54's `Notes` (*"~0.13 s release
native"* at cap, *"multi-second wasm verifies at cap remain plausible on slow
devices"*) and D129 §5 R10 (no Web Worker shape is admissible under the page's
CSP), a bootstrap is one more multi-second main-thread block at cap.

A `probe_plan` export that **decodes without verifying** is a different animal
entirely:

```
verify                           median 1.7149 ms
verify_online(EMPTY) bootstrap   median 1.3524 ms
probe_plan (decode only)         median 0.0199 ms      -> 1.2 % of a verify()
```

**This kills the call-count objection to a sixth export** and is why §2's lean
had to be dismantled rather than confirmed.

### (f) The sixth export, built and priced — and the shim is not what costs

Built with the repository's own invocation (`--release --target web --no-pack
--no-opt --mode no-install`, `ANTSEAL_SOURCE_COMMIT` supplied), from the clean
HEAD extraction. **Reproducible to the byte** — baseline and `plan-full` were
each rebuilt and returned identical sizes.

| build | module bytes | Δ raw | Δ % |
| --- | ---: | ---: | ---: |
| baseline (4 exports) | 1 827 304 | — | — |
| + a trivial no-op export (`ping`) † | — | **+146** | +0.008 % |
| + `probe_plan`, **blocks only** | 1 829 762 | +2 458 | +0.135 % |
| + `probe_plan`, blocks + `tx_hash` as `format!("{b:02x}")` | **1 838 672** | **+11 368** | **+0.622 %** |
| + `probe_plan`, blocks + `tx_hash` as `Vec<u8>` (JSON int array) | 1 842 786 | +15 482 | +0.847 % |
| + `probe_plan`, blocks + `tx_hash` via a hand-rolled hex table | 1 850 649 | +23 345 | +1.278 % |

† the `ping` row was measured on the same tree under a marginally different
flag set (`--out-name`, no `--no-pack`): baseline **1 827 240** → ping
**1 827 386**. Only the **+146 delta** is quoted, because its absolute pair is
not the one the other rows share.

Three things ride this table:

1. **The import table does not move.** All variants report the same three
   allow-listed wasm-bindgen shims (`__wbindgen_throw`, `__wbg_Error`,
   `__wbindgen_init_externref_table`). **No arm here widens a capability
   surface** — D18 §5 R7's property is untouched, as it was for D130's fifth.
2. **The export shim is 146 bytes — 1.6 % of the change.** The 11 KB is the
   plan *value*: a new `Serialize` impl, a `Vec<u64>` sequence serializer and
   the hex. **Both arm (a) and arm (b) pay all of it.** *"A sixth export is
   expensive"* is false, and so is *"a member is cheaper"*.
3. **The receipt half is +8 910 B of the +11 368**, and both obvious ways to
   shrink it are **measured backwards**: emitting the hash as bytes costs
   **+4 114 more**, and hand-rolling the hex costs **+11 977 more** — because
   `format!("{b:02x}")` reuses `core::fmt` machinery the module already links,
   while `String::push(char)` drags in a UTF-8 path it does not. An implementer
   who "optimises" this will make the artifact bigger.

**One honest discrepancy.** A from-HEAD build with the repository's own flags
is **1 827 304 B**, while the artifact sitting in `target/wasm-pack/` is
**1 841 981 B with the same four exports** — a 14 677 B (0.80 %) gap this lane
did not resolve. It is consistent with that artifact having been built from a
working tree already carrying the concurrent D130 implementation's core edits.
**Every delta in the table above is from one instrument in one tree**; the
absolute figures are not comparable with D130 §1 (d)'s.

### (g) The R9 corpus cannot exercise online mode — at all

Every one of the 21 committed report vectors was run through `verify` and
through the empty-evidence `verify_online` on the shipped artifact:

```
shape                        | anchors in report                   | overlay heights | receipt
… (19 shapes) …              | -                                   | []              | "none"
multi-file-anchored/mixed    | ots:invalid tsa:invalid tsa:invalid | []              | "none"
ed25519-only-policy/full     | -                                   | []              | "none"
```

**Twenty of 21 cases have no anchors; the one that does has an OTS anchor that
is offline `invalid`, so it can never promote. Zero cases carry a receipt.**
Every case's probe plan is `{"blocks":[],"receipt":null}`. R27's four named
online cases — *agreement/promotion, disagreement, mismatch→invalid,
one-endpoint-down* — and R24's Accept row 2 therefore have **no fixture in the
committed corpus**, and neither does the receipt half. §8 records this; it is
not D132's to mint.

### (h) The CLI discloses four endpoints whether or not it probes a receipt

`endpoints_from_config` (`verify_host.rs:252-279`, working tree) resolves the Arbitrum pair
from `verify_rpcs(network)` **before looking at the bundle**, and
`OnlineEndpoints::identities()` (`:211-224`) appends it whenever it exists. So
on mainnet the CLI's `endpoints_line` always names **four** URLs, receipt or
no receipt. Anything the page does must match that or R27's parity gate
compares two different disclosures — which is one more reason arm (e) fails
(§4): a page that never probes Arbitrum would either under-disclose or disclose
endpoints it structurally cannot use.

### (i) There is no frozen wording for "a receipt exists and was not probed"

`wording.rs` has exactly four receipt lines for the overlay —
`receipt_confirmed_line` (`:886`), `receipt_not_on_chain_line` (`:900`),
`receipt_disagreed_line` (`:907`), `receipt_failed_line` (`:913`) — plus the
report-side `receipt_class_line` (`:395`) and `receipt_detail_line` (`:402`).
`ReceiptEcho` is `{ outcome, line }`: **every variant renders**. So arm (c) —
making the receipt row appear un-probed so it can carry the hash — cannot be
done without **minting a wording row in a table R18 froze**, which is a
snapshot event, and without putting a *fetch input* inside a document keyed by
*fetch outcome*.

### (j) `rendered` must stay derivable from the report alone — and the plan is not

`orchestration.rs:507-513` states the invariant in its own words, about
`attested` deliberately getting no block row:

> *"the height is not on `AnchorResult` — it lives on the artifact's upgrade
> group, which is why `build_online_overlay` takes the artifacts as a separate
> parameter. Rendering it here would make this block underivable from the
> report alone, which is the property that lets R22's page draw the same rows
> from the same bytes."*

The plan is derivable from the **bundle**, never from the report (the height
only as a substring of a display identity; the hash not at all). **So the plan
may not be hung on `rendered.anchors[]`** — it must be its own member, sourced
from the bundle. This invariant is what fixes the shape in §3 R2.

### (k) The document the plan would join, as it stands right now

Read at **2026-08-12T21:51Z**, in the working tree, mid-flight: the D130
implementation lane has landed `verify_rendered` (`boundary.rs`, five
`#[wasm_bindgen]` items) and `api::verify_rendered_json`, whose tail is

```rust
Ok(format!(
    "{{\"redaction\":{redaction},\"rendered\":{rendered},\"report\":{report},\"verdict\":{verdict}}}"
))
```

— a splice of four canonical byte strings, no `serde_json::Value`. `plan`
sorts **before** `redaction`, so the member is prepended and no existing member
moves. Re-measure before implementing; that lane is still writing.

### (l) The exact Arbitrum request the page must reproduce

`arbitrum/confirm.rs:193-238`: `guard_chain_id` first (this is the
`WrongChain` class), then `eth_getTransactionReceipt` with params
`["0x<64 hex>"]`; the reply's `transactionHash` is **echoed back and compared**
as a per-endpoint validity check (a mismatch is `Payload`, deliberately not
`Disagreed`), and the compared tuple is `{status, blockNumber, blockHash}`.
Esplora is two GETs per endpoint (`esplora.rs:87-91`):
`{base}/block-height/{H}` → 64 hex hash, then `{base}/block/{hash}/header` →
160 hex.

### (m) A report field for the hash would be a format event that moves zero pins

`REPORT_DIGEST_BY_SHAPE` has **26 rows** and the report vector document has
**21 cases**; the shape names were enumerated and **not one is
receipt-bearing** — `AnchorSet::EveryKind { receipt: true }` appears in
`bundle_fixtures.rs`'s catalogue but in neither pinned table, and every one of
the 21 reports carries `"supporting_evidence":"none"` (§1 g). The **only**
artifact in the tree that renders the arm inside a whole canonical report is
`EXPECTED_CANONICAL_JSON_WITH_RECEIPT` (`verify/mod.rs`, R69's instrument).

So adding `tx_hash` to `SupportingEvidenceResult::ArbitrumReceipt` would move
**one literal and nothing else** — and D105 §2.4's corroboration rule (*"a
FORMAT EVENT moves all 21 report cases and all 26 rows … a value addition
nothing yet emits moves zero"*) would report **zero**, i.e. would positively
affirm the change as legal. §4 refuses arm (d) on that, not merely on the rule.

---

## 2. The lean, dismantled

**The lean this lane started with**: *the export list was reopened to five
three weeks after it closed at four, and reopening it again is the expensive
arm; so the answer is probably the bootstrap — an empty-evidence `verify_online`
costs nothing new, and the receipt half can be squeezed in beside it or dropped.*

Every clause of that is wrong, and the ways it is wrong point in opposite
directions.

**First, the bootstrap is not a partial answer — it is an answer to a question
nobody needed asked.** The Bitcoin half has three routes and the *report itself*
is one of them; the bootstrap's contribution is to make that route typed. Its
contribution to the receipt half is **exactly nothing**: measured, a
receipt-bearing bundle with an empty probe log returns `receipt:null`, and a
receipt-only bundle returns `anchor_outcomes:[] receipt:null` — the document is
silent that a receipt exists. So the bootstrap must be **paired** with some
mechanism for the hash, and every mechanism that carries a 32-byte hash carries
a `Vec<u64>` for free. **A bootstrap plus a receipt mechanism is strictly
dominated by the receipt mechanism alone**, and it costs a whole extra
verification (§1 e) to be dominated. That is not a judgement call; it is
arithmetic over measured facts.

**Second, "reopening the list is expensive" is false, and the two measurements
that would have justified it both came back the other way.** A sixth export
costs **146 bytes** and **0.02 ms**. This lane expected to refuse arm (a) on
cost and could not. The `probe_plan` export it built is *cheaper per call than
anything else in the module by a factor of 68*, because it decodes and does not
verify.

**Third, the thing that actually decides it is not on the register's list of
considerations at all.** A decode-only export answers for a bundle that has
**not passed verification** — structural, unit and signature stages never ran.
The page would then hold a fetch plan whose block heights and transaction hash
were chosen by an unverified, adversary-supplied file. The severity is low (the
hosts are pinned, the attacker controls numeric path components) but the
*shape* is exactly the one this project refuses elsewhere: a capability
reachable without the check that is supposed to gate it. A `plan` member on
`verify_rendered` **cannot be obtained without a passing offline verdict**,
because the export throws. That is a structural property, not a discipline, and
it is the tiebreaker.

**Fourth, D130 §7.1 wrote down this exact risk one wave ago** — *"the surface
is open by one, and the next request will be easier to make… a record that
opens a closed list weakens the list's rhetorical force even while keeping its
procedure"* — and D130 §3 R1 closed the list with *"Additions beyond five
remain a decision, not a code change."* The first request arrived within the
same wave. Granting it, on a benefit measured at 146 bytes and 0.02 ms that the
page does not need, would be the cheapest possible way to prove D130's residual
risk correct.

**One argument this lane expected to make and could not.** It expected to argue
that a probe plan is a different *kind* of thing from a rendered document —
D130 §3 R3's members are what the page **displays**, and a plan is not
displayed. Measured, the objection dissolves: **`report` is already a
non-displayed member.** D130 §3 R3's own words for it are *"This is what makes
one call sufficient"* — the page renders `rendered.*`, not `report.*`. The
document is not "what the page displays"; it is **what one call gives the page**,
and it already contains a member carried for call-count reasons alone. `plan`
is the same class. Recorded so nobody re-derives the objection.

**What survives is not the lean but its inversion**: the arm that looked free
is the one that costs a verification and answers half the question, and the arm
that looked expensive is 146 bytes — and is refused anyway, for a reason
neither cost nor speed could have found.

---

## 3. The ruling

Eleven rules. "The document" = the JSON text `verify_rendered` returns. "The
plan" = the `plan` member ruled here.

**R1 — The mechanism is a FIFTH MEMBER on D130's document. The export list
stays at five.**

`crates/antseal-wasm/src/boundary.rs` gains **nothing**.
`crates/antseal-wasm/src/api.rs::verify_rendered_json` gains one spliced byte
string. D18 §5 R4's list is unchanged at the five entries D130 fixed, and
**additions beyond five remain a decision, not a code change** — this record is
the first application of that sentence and it declines.

**R2 — The exact document, and `plan` sorts first.**

```json
{"plan":{…},"redaction":{…},"rendered":{…},"report":{…},"verdict":{…}}
```

Assembled by extending D130's `format!` splice; **no `serde_json::Value` on
this path, ever** (D18 §5 R5, D65 §5). No existing member moves — `plan` <
`redaction` alphabetically. `crates/antseal-wasm/tests/carriage.rs` already
scans `api.rs` for the refused shapes and the new string is inside its scope by
construction.

**R3 — The plan's exact shape.**

```json
"plan": {"blocks": [700311, 700412, 900001],
         "receipt": {"tx_hash": "e1e1e1e1…e1e1"}}
```

and, when there is nothing to fetch:

```json
"plan": {"blocks": [], "receipt": null}
```

- **`blocks`** — `[u64]`, **ascending, deduplicated**, `[]` when empty. Never
  absent, never `null`.
- **`receipt`** — `{"tx_hash": "<64 lowercase hex characters>"}` or **`null`**.
  Never absent. (D65 §7's null rule rides tier C: *"a key that exists is always
  present; its JSON type does not wobble."*)
- **No `schema` key and no interior version** (D65 §4). The one version a
  consumer reads is `build_info()`'s.
- **The hex is `format!("{b:02x}")`.** Not a hand-rolled table, not a byte
  array — both are measured **larger** (§1 f), by 11 977 B and 4 114 B
  respectively. This is a measurement, not a style preference, and a reviewer
  should treat a "cleaner" replacement as a regression until it is re-measured.

**R4 — The block set is the CLI's set, and one function computes it for both
surfaces.** Mint in `antseal-core`:

```rust
// crates/antseal-core/src/verify/plan.rs
pub struct ProbePlan { pub blocks: Vec<u64>, pub receipt: Option<ReceiptTarget> }
pub struct ReceiptTarget { pub tx_hash: String }

impl ProbePlan {
    #[must_use]
    pub fn from_bundle(bundle: &BundleV1<'_>) -> Self;
    pub fn to_canonical_json(&self) -> Result<Vec<u8>, SiblingEncodeError>;
}
```

`blocks` = the `block_height()` of **every OTS anchor carrying an upgrade
group**, sorted and deduplicated — byte-for-byte the set
`verify_host.rs:142-149` already builds. `receipt` = `bundle.receipt()
.and_then(|r| r.tx_hashes().first())`, hex-encoded — the **first** hash, which
is the rule `verify_host.rs:160-168` already applies.

**`crates/antseal-cli/src/verify_host.rs::probe_online` is rewritten to call
`ProbePlan::from_bundle` for both halves**, replacing its own `filter_map`/
`first()` lines. Its behaviour does not change — that is the point: after this,
*"the two surfaces ask the same question"* is a property of there being one
function, not of two lists agreeing today.

The narrower **overlay-derived** set is **refused**, on the measurement that it
is *equally* correct rather than more correct (§1 c) and on two robustness
grounds: it needs the offline verdicts, so it could not be computed by a pure
bundle walk; and if a future O-rule ever made a non-`attested` state
promotable, the narrow set would silently stop probing and the wide one would
not. The recorded counter-consideration: the wide set discloses one extra
height per upgraded-but-refuted anchor to the pinned endpoints. Narrowing it is
a tier-C change and §1 (c) is the measurement that says it is safe.

**R5 — `SiblingEncodeError`'s constructor must be reachable, or the plan lives
beside it.** Measured while building the experiment: `SiblingEncodeError` is a
tuple struct with a **private** field (`orchestration.rs:790`, HEAD), so a sibling
module cannot construct it (`E0423`). The implementer either adds a
`pub(crate)` constructor, or places `ProbePlan` in `orchestration.rs` beside
the other sibling documents. **A new public error type is not minted for this**
— the plan is a sibling document and it has a sibling document's error.

**R6 — The plan is a product of a PASSING verdict, and this is load-bearing.**
`verify_rendered` runs `run_offline` first and throws on any rejection, so a
bundle that fails verification yields **no plan** and the page has nothing to
fetch with. This is the property that decided the ruling (§2) and it must not
be optimised away — in particular, **no entry point may return a plan from a
decode alone**, however cheap that would be (measured: 0.0199 ms).

**R7 — The page's online path is ONE module call, and there is no bootstrap.**
R24 does **not** call `verify_online` with an empty-evidence document. The
sequence is exactly:

1. drop → `verify_rendered(bytes)` once (D130 §5 R23 item 1), keep the parsed
   document for the session;
2. "confirm online" → fetch per `doc.plan`;
3. one `verify_online(bytes, evidence)` and render the overlay.

Two verifications per full offline+online session, not three. The bootstrap is
recorded as **measured to work** (§1 a, d) and **refused** (§4) so that a later
lane does not rediscover it as a shortcut.

**R8 — Frozen vs free.**

- **FREE (tier C, declared unstable until U32)**: the plan's *shape* — member
  names, nesting, additions. Reviewed via the boundary rows of R9, not
  promised. Tier C's riding rules apply (R3).
- **FROZEN**: nothing new. **The plan mints no string**, so
  `crates/antseal-core/tests/snapshots/verdict-wording.txt` gains no row and
  `verdict_wording.rs` gains no section. **If an implementer finds themselves
  adding a sentence, they have left this ruling's scope.**
- **NOT MOVED**: `REPORT_VERSION` stays `1`; zero report vectors, zero
  `REPORT_DIGEST_BY_SHAPE` rows, zero frozen bytes. `verify()`,
  `verify_online()`, `verdict_class()` and `build_info()` keep their signatures
  and contracts. D64 §3's receipt-presence rule is **unamended**.

**R9 — The guards, in two places.**

1. `scripts/wasm-boundary.mjs` — the row D130 §3 R8.1 adds (*the document's
   members are all present*) becomes **five** members, and gains one row of its
   own: **`verify_rendered(b).plan.blocks` is an ascending, duplicate-free
   array of integers, and `plan.receipt` is `null` or an object whose `tx_hash`
   matches `/^[0-9a-f]{64}$/`.** The upper bound on `EXPECTED_EXPORTS` **does
   not move** and its *"five entries"* diagnosis stands.
2. A core test asserting **`ProbePlan::from_bundle`'s block set equals the set
   `probe_online` probes** — trivially true once R4 lands, and that is the
   point: it is what keeps a later edit from re-forking the two lists. It is
   also the anti-vacuity row for R4, so it must be red-capable (plant a
   divergence and see it fire, per this project's own discipline).

**R10 — What this decision does NOT change.** `antseal-core` gains no
dependency, no feature and no `crate-type` — `ProbePlan` is ordinary `serde`
code, so D18 §5 R6's dep-graph rule and `gate-features --check-partition` are
untouched by construction. The import allow-list is unchanged (measured: 3, on
every variant). No required CI context is added; the count stays 19. No
registry key, error code, HKDF label, domain tag, golden vector or wording
snapshot moves. D129's file shape, CSP and packaging order are untouched.
D66's request constraints are untouched — this record says *what* to fetch, D66
says *how*.

**R11 — D130 §3 R2 is corrected on the record.** Its sentence *"So R24's online
mode needs **no** further export, and the surface closes at five rather than
drifting to six"* reaches the **right conclusion by the wrong route**. Its
premise — *"The online lines already have a home — `verify_online`'s overlay
carries its own final display strings"* — answers *where the online **wording**
comes from*, and R24's unmet need is *what the online **fetches** take as
input*. Measured, the wording is covered and the inputs are not: the block
heights fall out of the overlay by luck (§1 a) and the transaction hash falls
out of nothing (§1 b). The conclusion survives — the surface does close at five
— but only because of this record, not because of that reasoning. This follows
R11/R19/R23's precedent: **a claim that is half true is shipped by saying which
half.**

---

## 4. Refused shapes

| shape | refused on |
| --- | --- |
| **(a)** a sixth export `probe_plan(bundle_bytes) -> String` | **not on cost** — built and measured at **+146 B of shim** and **0.0199 ms/call**, both negligible. Refused because a decode-only export returns a fetch plan for a bundle that **never passed verification** (§2), and because D18 §5 R4's list was closed at five **one wave ago** with *"additions beyond five remain a decision"* — granting the first request inside the same wave, for a benefit the page does not need, is the exact failure D130 §7.1 recorded |
| **(c)** widening `receipt_echo` so an un-probed receipt renders, carrying the hash | needs a **wording row R18 froze** — measured, the table has four receipt lines and none for "present, not probed" (§1 i) — and `ReceiptEcho` is `{outcome, line}` where **every variant renders**. It also puts a *fetch input* inside a document keyed by *fetch outcome*. Would be a D64 §3 amendment; D64 §3's rule is deliberate and stands |
| **(d)** the transaction hash as a report field | **FORMAT EVENT** under D105 §2.4, and **the most dangerous kind**: adding a field to `SupportingEvidenceResult::ArbitrumReceipt`'s payload makes a struct-like value report v1 can already serialize *gain a field*, which is D105 §2.4's own test for a bump. §2.4's worked enumeration lists eight structs and does not name enum-variant payloads, so this record **applies** the test rather than citing a listed case — and the corroborating instruments D105 §2.4 offers **cannot corroborate here**: measured, **0 of 21** report vector cases and **0 of 26** `REPORT_DIGEST_BY_SHAPE` rows are receipt-bearing (§1 m), so the change would move **zero pins** and read exactly like a legal value addition. That is D105 §4.3's *"a correct format signal and an empty coverage signal"* in its worst form. D64 §6 refused the same shape for the overlay in the same words |
| **(e)** scoping the page's receipt probe out of v1 | **spec line 137 names it**: *"two pinned default endpoints per source … (esplora-style: blockstream.info + mempool.space; **two public Arbitrum RPCs**)"*, inside the **Verifier web page** section. It would also break the endpoints disclosure: the CLI names **four** endpoints regardless of receipt presence (§1 h), so the page would either under-disclose or disclose endpoints it cannot use — and `endpoints_line` is the page's statement of what it used (D66 §3 R6) |
| **the bootstrap** — an empty-evidence `verify_online` as the plan mechanism | measured to work for the Bitcoin half and measured **silent** for the receipt half (`receipt:null`, §1 b), so it must be paired with a hash mechanism that subsumes it. It costs **0.96–1.02 × a `verify()`**, serial before any fetch, on a main thread with no admissible Web Worker (D129 §5 R10) — a whole extra verification to be dominated (§2) |
| a `plan` hint key inside the online-evidence document | **structurally impossible**: `deny_unknown_fields` refuses it, measured — *"unknown field `plan`, expected one of `schema`, `endpoints`, `blocks`, `receipt`"* |
| the page regexing `bitcoin-block-(\d+)` out of `report.anchors[].source` | the height reaches the report only as a substring of a **display identity** D92 §5.1 owns; D65 tier A freezes the report's **bytes**, not a parsing contract for a substring. It makes the page's fetch target depend on rendered prose — the R61 asymmetry class D64 §6 names — and **it does not help the receipt half at all**, which is the whole decision |
| the page walking the bundle CBOR in JS | a second parser for adversary-supplied bytes, with different rules from `SealProof::decode`, in the surface whose entire premise is that `antseal-core` contains *all* verification (spec line 127). Same disqualifier as above: it is a second answer to the half that already had three |
| confirming the receipt by `block_number` instead of `tx_hash` (the "no new data" dodge) | it would render `receipt_confirmed_line` — *"both RPC endpoints confirm the recorded transaction on Arbitrum block N"* — having **never looked at the transaction**. A false rendering, and a divergence from A17's `confirm_arbitrum_tx`, whose per-endpoint `transactionHash` echo check (§1 l) exists precisely to stop an endpoint answering about a different transaction |
| hanging the height on `rendered.anchors[]` | breaks the invariant `orchestration.rs:507-513` states in its own words — *"would make this block underivable from the report alone, which is the property that lets R22's page draw the same rows from the same bytes"* (§1 j) |
| the plan's block set narrowed to the overlay's `attested` set | measured **equally** correct, not more (§1 c); needs the offline verdicts rather than a bundle walk; and would silently stop probing if a future O-rule made another state promotable (§3 R4) |
| `tx_hash` as a byte array, or via a hand-rolled hex table | **measured larger**: +4 114 B and +11 977 B against `format!("{b:02x}")` (§1 f). Both are the "obvious optimisation" and both are backwards |
| a `schema` or `version` key on the plan | D65 §4: *"seven commands, nine documents, **zero interior versions**"*; `build_info()` is the one version the page reads |
| omitting `receipt` when there is none | D65 §7's null rule, riding tier C: absence is `null`, never a missing key |

---

## 5. What R24 / R27 must implement

### R24 — the page

1. **On drop**: `const doc = JSON.parse(verify_rendered(bytes))`, once, and
   keep it for the session (D130 §5 R23 item 1). The plan is `doc.plan`.
   **Never call `verify_online` with an empty-evidence document.**
2. **The affordance is not gated on a non-empty plan.** A plan of
   `{"blocks":[],"receipt":null}` means zero fetches and **the overlay still
   renders** — which is exactly what `antseal verify --online` does on the same
   bundle, and is therefore what parity requires. Do not invent a "nothing to
   check" message; there is no frozen wording for one.
3. **Bitcoin, per height in `plan.blocks`, per endpoint** — two GETs
   (`esplora.rs:87-91`): `{base}/block-height/{H}` → 64 hex hash, then
   `{base}/block/{hash}/header` → 160 hex. Under D66 §3 R1's constraints
   verbatim: `GET`, at most `Accept: text/plain`, **no other header**,
   `credentials:'omit'`, `mode:'cors'`. A thrown fetch is `transport` and
   **never** `no-such-block` (D66 §3 R2); a 404 is `no-such-block` **only** when
   its body says `Block not found`.
4. **Arbitrum, only when `plan.receipt !== null`** — per endpoint: the chain-id
   guard first (a mismatch is the `wrong-chain` class), then
   `eth_getTransactionReceipt` with params `["0x" + plan.receipt.tx_hash]`.
   Reject a reply whose `transactionHash` is not the one asked for as
   **`payload`**, never as a disagreement (§1 l). The compared tuple is
   `{status, blockNumber, blockHash}`.
5. **Build one evidence document and make one call.** The literal shape is
   `crates/antseal-wasm/README.md`'s, unchanged. Two rules this record fixes:
   - **`endpoints.identities` is the CLI's disclosure list** — the Bitcoin pair
     then the Arbitrum pair, i.e. **four entries on mainnet, receipt or no
     receipt** (§1 h). Never `[]`: measured, an empty list renders
     *"endpoints: none recorded (pinned defaults)"*, which would be false.
   - **Omit `receipt` entirely when no receipt probe was attempted** — that is
     what makes the CLI's `ReceiptProbe::NotAttempted` and the page's agree.
6. `blocks` entries: one per height, in plan order. A duplicate height is
   **refused** by the parser; `plan.blocks` is deduplicated, so the page cannot
   produce one.
7. Everything D66 rules about overrides is unchanged and applies to the
   endpoints, not to the plan: `https://` only, exactly two per source,
   rendered as text, session-scoped, and the label is `endpoints_line`'s.

### R27 / Q19 — the online cases

1. **The mocked routes are derived from the plan**, so the fixture and the
   intercepts cannot drift: route on `**/block-height/{H}` and
   `**/block/{hash}/header` for each `plan.blocks` entry, and on the JSON-RPC
   POST when `plan.receipt !== null`.
2. **The committed corpus cannot serve these cases and this must not be
   discovered at implementation time.** Measured (§1 g): all 21 R9 vectors
   yield `{"blocks":[],"receipt":null}`; the one anchored vector's OTS anchor
   is offline `invalid`; no vector carries a receipt. The promotion,
   disagreement, mismatch and one-endpoint-down cases need a fixture built the
   way `orchestration/tests.rs::attested_bundle()` builds one, and the receipt
   case needs a receipt-bearing twin. §8 records the gap.
3. **One case the corpus *can* serve, and it is worth having**: an online
   confirmation over any R9 vector makes **zero fetches** and still renders the
   overlay, on both surfaces, identically. It is the cheapest available proof
   that the plan-driven path does not invent work.
4. Add R9's boundary rows (`plan.blocks` ascending and duplicate-free;
   `plan.receipt` null or 64-hex).

---

## 6. Spec conformance

**MVP-SPEC.md line 137**, the sentence this record serves, inside the
**Verifier web page** section (line 125):

> Online mode: **two pinned default endpoints per source, results must agree**
> (esplora-style: blockstream.info + mempool.space; **two public Arbitrum
> RPCs**), **user-overridable**, rendered as an advisory overlay distinct from
> the offline cryptographic verdict.

- *"per source"*, with **both** sources enumerated, is why arm (e) is refused:
  the Arbitrum pair is the page's, not only the CLI's, and the page cannot use
  it without the transaction hash. This ruling is what makes the second half of
  that sentence implementable at all.
- *"results must agree"* is untouched — the must-agree fold stays in
  `antseal-wasm/src/online.rs`, the page decides nothing. The plan says *what*
  to ask; `online.rs` says what *agreement* means.
- *"user-overridable"* is untouched and is deliberately **not** a property of
  the plan. The plan names heights and a transaction; the *endpoints* are the
  user's (D66 §3 R5). Keeping those two things in different documents is what
  stops an override from being able to change what is asked about.
- *"rendered as an advisory overlay distinct from the offline cryptographic
  verdict"* — the plan is not rendered at all, and the two documents stay
  separate at the export level (D130 §3 R2's surviving half).

**Line 108** — *"`--online` fetches block H from the must-agree esplora
endpoints"* — is now the same H on both surfaces by construction (R4), rather
than by two lists happening to agree.

**Line 127** — *"Plain HTML/JS + `antseal-core` WASM (which contains **all**
verification, anchors included)"* — is why the page may not parse the bundle
for itself (§4). After this ruling the page contains no knowledge of the bundle
format whatsoever: it receives a list of integers and a hex string.

**Line 38** — the verify flow's ordering, *"offline verdict … Optional
`--online` confirms"* — becomes structural: R6 makes the plan unobtainable
without a passing offline verdict.

**Line 119** — no `--live` affordance on the page — untouched; the plan carries
no storage address and `PageHost::live_inputs` still returns the empty value.

**Line 139**, page provenance — the artifact grows by the measured amount and
that is R25's to record. No mechanism moves.

---

## 7. Residual risk

1. **The 11 KB is mostly the hash, and it is paid on every page load whether or
   not a bundle has a receipt.** +8 910 B of the +11 368 is the receipt half.
   No committed vector exercises it (§1 g), so it ships as dead weight until a
   receipt-bearing bundle is dropped. This is a real cost of honouring line
   137's second source and it is paid deliberately.
2. **The `format!` finding may not survive a toolchain bump.** It is a
   consequence of what `core::fmt` the module already links; a future
   `wasm-opt` (pinned, per R25/F29) or a rustc change could invert it. The
   number is a measurement of *this* toolchain, and §3 R3's instruction should
   be re-measured, not obeyed forever.
3. **The plan is tier C and the page is a visible surface.** A third-party
   scraping `plan` has no contract before U32 — D130 §7.2's risk, one member
   larger.
4. **R4 makes the CLI and the page share a function they did not share
   before.** That is the point, but it means a defect in `ProbePlan::from_bundle`
   is now a defect in both surfaces at once, and R27's parity gate — which
   compares *renderings* — cannot see it. R9's core test is the only instrument
   that can, which is why it must be red-capable rather than merely present.
5. **Nothing measured here ran in a browser.** Every figure is native,
   node-hosted, or a build artifact. That `plan` survives a real `fetch()`
   round trip in Chromium and Firefox is R24's to measure, and D129's
   two-engine method is the precedent.
6. **The working tree moved under this lane and will move again.** §1 (k)'s
   reading of `verify_rendered_json` is timestamped 2026-08-12T21:51Z, mid-flight;
   ~~§1 (f)'s 14 677 B discrepancy against the on-disk artifact is unexplained.~~
   — **EXPLAINED 2026-08-15 (staleness), see the note below**;
   An implementer must re-measure both before splicing a fifth member.
7. **`plan.blocks` is wider than the overlay renders, and a reader may report
   that as a bug** — the page fetches a height that produces no row. Measured
   harmless (§1 c); named here so it is recognised rather than "fixed" by
   someone who has not read the measurement.

---

## 8. Discovered work — described, not registered

**No IDs are minted here.**

1. **R27's four named online cases and R24's Accept row 2 have no fixture.**
   Measured over all 21 R9 vectors: every probe plan is empty, the only
   anchored vector's OTS anchor is offline `invalid`, and no vector carries a
   receipt (§1 g). Promotion, disagreement, mismatch→invalid, one-endpoint-down
   and every receipt case need fixtures that do not exist. This is the largest
   thing this lane found and it is not D132's to mint.
2. **The receipt probe consults only the first of up to 256 transaction
   hashes.** `verify_host.rs:164`'s `.first()` is a pre-existing narrowing
   with no record; the report meanwhile publishes `transaction_count`. A bundle
   whose payment spanned three transactions is confirmed on one of them, and
   nothing says so. R4 gives that rule one home for the first time; whether it
   is the *right* rule is unasked and unanswered.
3. **A hand-rolled hex encoder is 12 KB worse than `format!`** in this module
   (§1 f). The general form — that "avoid the formatter" is backwards once
   `core::fmt` is already linked — is worth a note wherever wasm size is
   discussed, because it is the opposite of the received wisdom.
4. **`SiblingEncodeError` cannot be constructed outside `orchestration`**
   (`E0423`, measured). Every future sibling document hits this; it wants a
   `pub(crate)` constructor once rather than a new error type each time.
5. **A from-HEAD build is 14 677 B smaller than the artifact in `target/`**
   with the same four exports (§1 f). Either the committed artifact is not from
   HEAD, or the build is not reproducible from source alone. R25's whole
   premise is that it is. ~~Worth one measurement.~~ — **MEASURED 2026-08-15
   by R25/R83: the second disjunct is REFUTED and the first is the
   explanation**; see "Note — §1 (f)'s honest discrepancy, and the disjunct
   §7.6 and §8.5 left open, 2026-08-15" below.
6. **The empty-evidence `verify_online` is a legal call with a surprising
   reading.** It is accepted, it renders *"no agreed online evidence for block
   H"* for every attested anchor, and a page that made it by accident would
   render a plausible, wrong overlay. Nothing refuses it. Whether the module
   should refuse an evidence document with no blocks **and** no receipt is a
   question this record does not answer.
7. **`identities: []` renders "endpoints: none recorded (pinned defaults)"** —
   a disclosure line that names no endpoint while claiming the defaults. Legal
   today, false whenever it appears.

---

## 9. Quoted entry notes (registrar's to apply)

### 9.1 `tasks/R.md` R24 — append to `Notes`

> **[D132, 2026-08-12]** Probe-plan route ruled
> (docs/decisions/D132-the-pages-probe-plan.md): the page learns what to fetch
> from a **fifth member `plan` on D130's `verify_rendered` document** — **no
> sixth export**; D18 §5 R4's list stays at five. Shape, exactly:
> `"plan":{"blocks":[<u64 ascending, deduplicated>],"receipt":{"tx_hash":"<64
> lowercase hex>"}|null}`, both keys always present, no `schema`, no interior
> version (D65 §4). **The register's framing was wrong in both directions.**
> The **Bitcoin half was already reachable three ways** — measured, an
> empty-evidence `verify_online` returns every attested anchor's height as a
> `u64` beside its line, and the report carries it inside
> `anchors[].source = "bitcoin-block-<H>"`. The **receipt half was reachable
> zero ways**: the transaction hash `eth_getTransactionReceipt` needs is in no
> document the page can see — proven by running a receipt-bearing bundle and
> searching the emitted bytes (report `false`, overlay `false`, verdict-class
> `false`), and structurally, because `receipt_echo` returns `None` for
> `NotAttempted` so a bootstrap overlay is **silent that a receipt exists at
> all**. So this row turned on **one 32-byte value**. **Cost did not decide
> it**: a sixth export was built and measured at **+146 B and 0.0199 ms/call**
> (a decode, 1.2 % of a `verify()`), while the plan *value* costs **+11 368 B
> (+0.622 %)** — which **both** arms pay. What decided it is that a decode-only
> export returns a fetch plan for a bundle that **never passed verification**,
> while a member on `verify_rendered` cannot exist without a passing offline
> verdict; and that D18's list was closed at five **one wave earlier** with
> *"additions beyond five remain a decision"*. **The bootstrap is refused**: it
> costs a whole extra verification (0.96–1.02 × `verify()`, measured,
> **serial** before any fetch, main thread — no Web Worker under D129's CSP)
> and answers only the half that was already answered. **This row makes ONE
> module call on the online path.** `plan.blocks` = every OTS anchor carrying
> an upgrade group, ascending and deduplicated — **identical to the CLI's set**,
> because `ProbePlan::from_bundle` becomes the one function both surfaces call
> (`verify_host.rs::probe_online` is rewritten onto it, behaviour unchanged).
> Measured: that set is **strictly wider** than the overlay's `attested` set
> and the difference is **inert** — report, overlay and verdict-class all
> byte-identical either way, including when the extra height answers
> **refutingly**. Two rules for the evidence document this row sends:
> `endpoints.identities` is the CLI's **four**-entry mainnet disclosure list
> whether or not a receipt is probed (`OnlineEndpoints::identities()` appends
> the Arbitrum pair before the bundle is consulted), and `[]` is forbidden —
> measured, it renders *"endpoints: none recorded (pinned defaults)"*, which is
> false; and `receipt` is **omitted entirely** when no receipt probe was
> attempted, which is what makes it agree with `ReceiptProbe::NotAttempted`.
> An **empty plan does not disable the affordance**: zero fetches, and the
> overlay still renders, exactly as `antseal verify --online` does — there is
> no frozen wording for "nothing to check" and none is minted. Arbitrum
> requests reproduce A17 exactly: chain-id guard first (`wrong-chain`), then
> `eth_getTransactionReceipt` with `["0x"+tx_hash]`, and a reply whose
> `transactionHash` is not the one asked for is **`payload`**, never a
> disagreement. D66's request constraints are untouched — D132 says *what* to
> fetch, D66 says *how*. **Scoping the receipt probe out of v1 is refused**:
> spec line 137 names *"two public Arbitrum RPCs"* inside the verifier-page
> section, and the CLI discloses four endpoints regardless, so a page that
> never probed Arbitrum would either under-disclose or disclose endpoints it
> cannot use.

### 9.2 `tasks/R.md` R27 — append to `Notes`

> **[D132, 2026-08-12]** The online cases are plan-driven, and **the committed
> corpus cannot serve them**. Route the playwright intercepts off
> `verify_rendered(b).plan` — `**/block-height/{H}` and `**/block/{hash}/header`
> per `plan.blocks` entry, the JSON-RPC POST when `plan.receipt !== null` — so
> the fixture and the intercepts cannot drift. **Measured over all 21 R9
> vectors: every probe plan is `{"blocks":[],"receipt":null}`.** Twenty have no
> anchors at all; `multi-file-anchored/mixed`'s OTS anchor is offline
> **`invalid`**, so it can never promote; **zero** vectors carry a receipt. So
> *agreement/promotion*, *disagreement*, *mismatch→invalid*,
> *one-endpoint-down* and every receipt case need fixtures that **do not
> exist** — built the way `orchestration/tests.rs::attested_bundle()` builds
> one (R6 fixture, typed anchor substitution, re-encoded through
> `encode_bundle`, the `.ots` stamping the rebuilt bundle's own
> `anchor_digest`), plus a receipt-bearing twin. One case the corpus **can**
> serve and should: an online confirmation over any R9 vector makes **zero
> fetches** and still renders the overlay, identically on both surfaces — the
> cheapest proof that the plan-driven path invents no work. Two boundary rows
> are owed beside D130's: `plan.blocks` is an ascending duplicate-free integer
> array, and `plan.receipt` is `null` or an object whose `tx_hash` matches
> `/^[0-9a-f]{64}$/`. **Parity note**: after D132 both surfaces derive their
> probe set from one function, so a defect in it is a defect in **both** and is
> **invisible to a rendering-comparison gate** — the core equality test
> (`ProbePlan::from_bundle` ≡ what `probe_online` probes) is the only
> instrument that can see it and must be red-capable, not merely present.

### 9.3 `tasks/R.md` R22 — append to `Notes`

> **[D132, 2026-08-12]** The document D130 opened gains a **fifth member,
> `plan`** — and **no export is added**: `boundary.rs` is untouched and
> `EXPECTED_EXPORTS` does not move. `api::verify_rendered_json`'s splice gains
> one byte string, prepended (`plan` < `redaction`, so no existing member
> moves), assembled by `format!` and never through `serde_json::Value`.
> `ProbePlan` / `ReceiptTarget` are minted in `antseal-core`
> (`ProbePlan::from_bundle(&BundleV1) -> ProbePlan`, `to_canonical_json`), add
> no dependency and no feature, and the built module's import table is
> **unchanged at 3** across every variant measured. Two implementation facts
> that were measured and would otherwise be re-discovered the expensive way:
> **`SiblingEncodeError`'s tuple field is private to `orchestration`**, so a
> sibling module cannot construct it (`E0423`) — add a `pub(crate)`
> constructor or put `ProbePlan` beside it, and do **not** mint a new public
> error type; and **the hex must be `format!("{b:02x}")`** — emitting the hash
> as a byte array costs **+4 114 B** and a hand-rolled hex table costs
> **+11 977 B**, because `format!` reuses `core::fmt` the module already links
> while `String::push(char)` drags in a UTF-8 path it does not. Total measured
> cost of the member: **+11 368 B raw (+0.622 %)**, of which the receipt half
> is **+8 910 B**.

### 9.4 `tasks/R.md` R21 — append to `Notes`

> **[D132, 2026-08-12]** `verify::plan::ProbePlan` lands beside the other
> sibling documents and becomes the **single** derivation of what an online run
> fetches: `crates/antseal-cli/src/verify_host.rs::probe_online` is rewritten
> onto `ProbePlan::from_bundle` for both halves, its own `filter_map`/`first()`
> lines going, **behaviour unchanged by construction** — which is the point,
> since after this *"the two surfaces ask the same question"* is a property of
> there being one function rather than of two lists agreeing today. The plan is
> a **product of a passing verdict**: it reaches the page only through
> `verify_rendered`, which throws on any rejection, so no entry point may ever
> return a plan from a decode alone however cheap that would be (measured:
> 0.0199 ms). Recorded finding, not fixed here: the receipt probe consults only
> **the first** of up to 256 recorded transaction hashes while the report
> publishes `transaction_count` — a pre-existing narrowing that now has one
> home and still has no justification.

### 9.5 `docs/decisions/D130-…` — an Amendment section (D117 §2.2 form)

> **Amended by D132, 2026-08-12** at three sites.
> **§3 R2** — the sentence *"So R24's online mode needs **no** further export"*
> reaches the right conclusion by the wrong route and is annotated, not struck:
> its premise is about the online **wording**, and R24's unmet need was the
> online **fetch inputs**. Measured, the block heights fall out of the overlay
> incidentally and the transaction hash falls out of nothing; the surface does
> close at five, but because of D132 and not because of R2's reasoning.
> **§3 R3** — *"Members, in the alphabetical order…"* becomes **five** members,
> `plan` first: `{"plan":…,"redaction":…,"rendered":…,"report":…,"verdict":…}`.
> R3's own rationale for the `report` member — *"This is what makes one call
> sufficient"* — is what admits `plan`: the document is what **one call gives
> the page**, not only what the page displays, and it already carried a
> non-displayed member.
> **§5 R23 item 1** — *"Call `verify_rendered(bytes)` once per drop"* gains its
> consequence: the page keeps the parsed document for the session because
> `plan` is read from it at confirm-online time, and **the online path is one
> further call, never two** — an empty-evidence bootstrap is refused at a
> measured 0.96–1.02 × `verify()`.

### 9.6 No edits requested

`MVP-SPEC.md` (no line moves — this record implements line 137's second source
rather than reinterpreting it), `docs/decisions/D18-…` (its list does not
move), `D64-…` (§3's receipt-presence rule stands **unamended**; arm (c) is
refused rather than granted), `D65-…`, `D66-…` (applied, not amended — D132
rules *what* to fetch, D66 *how*), `D105-…`, `D129-…`,
`crates/antseal-core/tests/snapshots/verdict-wording.txt` (no sentence is
minted), `testdata/vectors/**` (zero frozen bytes move).

---

## Registrar's edit set

1. `TODO.md` — mark D132 resolved; **R24 unblocked**.
2. The decision index — one row for D132.
3. `tasks/R.md` — R24 (§9.1), R27 (§9.2), R22 (§9.3), R21 (§9.4).
4. `docs/decisions/D130-…` — the Amendment section of §9.5.
5. No other file is edited by the registrar; R9's guard rows and R4/R5's code
   are the implementation lane's.

---

## Outcome

The register asked how the page learns what to probe, and the first honest
answer is that it already knew half of it three different ways. Every attested
anchor's block height is sitting in the overlay as a `u64` beside its line, and
in the report inside a display string, and in the bundle bytes the page is
holding — so the Bitcoin half needed no decision at all. What needed a decision
was a single thirty-two-byte value that is in the bundle, in the CLI's probe
call, and in no document the page can see. Measuring that exhaustively, at the
value level rather than by grep, is what turned a question about a mechanism
into a question about one field.

Both of the reasons this lane expected to use were then measured away. A sixth
export costs a hundred and forty-six bytes, and a probe-plan export that
decodes without verifying runs in one and a half percent of the time a
verification takes — sixty-eight times faster than the bootstrap the lean
preferred. The eleven kilobytes everyone would have argued about belong to the
plan itself and are paid identically by every arm that carries it. When the two
obvious deciders both come back neutral, what is left is the property nobody
had listed: a decode-only entry point hands a fetch plan to a file that never
passed verification, and a member on a document that throws cannot. That is the
whole ruling, and it is also why the list stays at five — because the first
request to open it arrived inside the same wave that closed it, on a benefit of
a hundred and forty-six bytes.

Two measurements outlived the decision they were made for. The committed corpus
cannot exercise online mode at all: twenty-one vectors, twenty with no anchors,
one with an anchor that is already refuted, none with a receipt — so four of
R27's named cases and one of R24's acceptance rows have been waiting for
fixtures nobody has noticed are missing. And hand-rolling a hex encoder to save
bytes makes the artifact twelve kilobytes larger, because the formatter it
avoids is already linked. Both are the same lesson this project keeps paying
for: the answer depends on the medium of the measurement, and reading the code
would have given the opposite result in each case.

---

## Note — §1 (f)'s honest discrepancy, and the disjunct §7.6 and §8.5 left open, 2026-08-15

**This section corrects no statement of D132 and withdraws no ruling.** It is
the single home of one new fact: the question §1 (f) recorded as unresolved,
and §7 item 6 and §8 item 5 carried forward as open, has been measured. The
heading is not `Correction` in D117 §2.2's sense — nothing here was false —
and it is not `Amendment`, because no ruling is added.

**The open sentence, quoted verbatim** (§8, discovered work, item 5):

> **A from-HEAD build is 14 677 B smaller than the artifact in `target/`**
> with the same four exports (§1 f). Either the committed artifact is not from
> HEAD, or the build is not reproducible from source alone. R25's whole
> premise is that it is. Worth one measurement.

**The measurement, made by the R25 lane on 2026-08-15 at `08c074c`.** Four
release builds of the module, differing only in the checkout path, in
`$CARGO_HOME`, and in whether the path remap was applied:

| build | checkout path | `CARGO_HOME` | remap | SHA-256 |
| --- | --- | --- | --- | --- |
| baseline | 25 characters | `/home/deb/.cargo` | on | `baee3fc9…22a3` |
| second runner, path only | 122 characters | `/home/deb/.cargo` | on | `baee3fc9…22a3` |
| second runner, both roots | 122 characters | scratch | on | `baee3fc9…22a3` |
| control | 122 characters | `/home/deb/.cargo` | **off** | `e7b722ff…d4c4` |

The three remapped builds are byte-identical in module **and** glue, and the
un-remapped control **reproduced the pre-change in-tree artifact exactly, from
a checkout path 97 characters longer than the one that produced it**.

**So the second disjunct is refuted.** At `08c074c` this build is reproducible
from source alone, across two checkout paths and two `CARGO_HOME`s, to the
byte — which leaves *"the committed artifact is not from HEAD"* as the
explanation, and is the same conclusion this record's own §1 (f) reached as a
hypothesis (*"consistent with that artifact having been built from a working
tree already carrying the concurrent D130 implementation's core edits"*).

**Two boundaries on that inference, stated so it is not over-read.** (1) It is
a property of *this build at this commit*, not a re-measurement of the two
historic artifacts, which no longer exist — the 14 677 B here and the 14 066 B
at **R83** are explained by it, not re-derived from it. (2) It says nothing
about the environment axes the four builds shared (locale, `TZ`, `HOME`, user,
host); D63 §7 rule 2's list is only partly discharged, and D63's own 2026-08-15
correction says which part.

**Where the mechanism is owned.** Not here. **R83** is the row that makes a
stale artifact impossible to package — `scripts/verifier-page-build.sh` now
rebuilds unconditionally and requires byte-equality with whatever module was
present, failing with a message naming `STALE ARTIFACT` — and it is closed on
that mechanism, not on this measurement. This note exists because D132 is where
a reader meets the number first.

**Authority.** The R25/R83 lane, 2026-08-15; recorded by the registrar in the
act that closes R83 and mints **R86**. §3's ruling (the plan rides
`verify_rendered` as a fifth member), §1 (c)'s inertness and every refused arm
are untouched — and §1 (c)'s inertness now has the witness in artifacts that
**D133** built, which no measurement here supplies.
