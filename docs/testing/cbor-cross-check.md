# The independent-CBOR cross-check contract (F19 → F14)

Normative for the F14 cross-check artifact. Spec basis: the Revision-2
pre-freeze mandate (MVP-SPEC.md line 5) and Definitions & encoding — the
cross-check obligation (line 73). Vehicle: **Python `cbor2 ==6.1.3`**,
dev-tool-only (decision D12, recorded in `docs/decisions/D7-cbor-crate.md`).

This document exists because F14's original Do text left three things
implicit that a second implementer would have had to *guess*, and a guessed
cross-check is worth nothing: **where** the artifact it compares against
lives, **how** that artifact is rendered, and **which** four checks it owes.
F12/F13 settled all three when they landed the `manifest` and `bundle`
vectors; this is that settlement written down where F14 reads it.

Implementation: `testdata/vectors/v1/crosscheck_cbor.py` (a `*.py` auxiliary,
which Q4's discovery contract admits — one copy per format version, each
checking its own directory), driven by `scripts/cross-check.sh`. The Rust side
of the same rendering is
`crates/antseal-core/src/test_util/vectors_cbor_diag.rs`. Neither is allowed
to know about the other's code — see [§6](#6-what-independence-means-here).

**Decision D31 splits the vehicle's role, and the split is normative.**
`cbor2` **decodes only**. The RFC 8949 §4.2.1 canonical **encoder is ours**,
written in the checker: cbor2's canonical mode orders map keys RFC 7049
length-first, which merely *coincides* with §4.2.1 over today's
unsigned-integer keys, so using it would have imported that coincidence as a
permanent documented exception. Writing the encoder retires the caveat, and
makes the encoding authority ours-versus-minicbor rather than one library's
canonical mode versus another's.

## 1. The sidecar is in-file, and it could not have been anything else

F14's original wording — "asserts structural equality against its
diagnostic sidecar" — reads naturally as *a sibling file beside the
vector*, e.g. `manifest.diag.json`. **That file cannot exist.** Q4's
discovery contract (`testdata/vectors/README.md` § "Directory contract")
admits exactly four things under `vectors/v<n>/`: `*.json` **vector** files,
`README.md`, `*.py` reference generators, and the two auxiliaries
(`FROZEN.sha256`, `INDEX.json`). Anything else fails the runner as
unclassifiable — and a `*.diag.json` sibling would not merely be tolerated,
it would be *executed as a vector* and fail envelope validation.

So the sidecar lives **inside** the vector, at

```
expect.cases[].diagnostic
```

as an object of **one rendered item per strict-decode layer**:

| Vector `kind` | `diagnostic` keys | Committed bytes field |
| --- | --- | --- |
| `manifest` (F12) | `envelope`, `body` | `expect.cases[].manifest_bytes` |
| `bundle` (F13) | `bundle`, `manifest`, `body` | `expect.cases[].bundle_bytes` |

F14 needs **no new file** in the vector tree, and must not add one.

## 2. There is deliberately no `body_bytes` field — and that is the point

A case commits exactly **one** byte string: the outermost layer. There is no
`body_bytes`, and for `bundle` there is no `manifest_bytes`. The inner
layers' bytes must be **read out of the enclosing item**.

This is not an oversight to be worked around, it is the property under test.
`work_id = SHA-256(manifest body)` must hash *the bytes actually embedded in
the envelope*, never a re-encoding of a decoded body. A checker handed a
convenient `body_bytes` field could not tell the difference; a checker that
digs the pre-image out of the envelope's key-0 byte string demonstrates it.

## 3. The rendering table is fixed and normative

One canonical CBOR item renders by these rules **and no others**. The table
is duplicated in three places on purpose — here, in
`testdata/vectors/README.md` § "The diagnostic sidecar", and in the
`vectors_cbor_diag` module docs — and a drift test binds them together
(§8).

| CBOR item | JSON |
| --- | --- |
| unsigned integer (major 0) | a JSON number, non-negative |
| negative integer (major 1) | a JSON number, negative |
| byte string (major 2) | `{"b": "<lowercase hex>"}` |
| text string (major 3) | a JSON string |
| array (major 4) | a JSON array |
| map (major 5) | `{"m": [[key, value], …]}`, entries in wire order |

Three consequences a second implementer must not rediscover the hard way:

- **The only JSON objects are `{"b": …}` and `{"m": …}`**, told apart by
  their single key. Nothing else renders as an object, so the form is
  unambiguous without a schema.
- **Map entries are pairs, not a JSON object.** Every v1 key is an integer
  and JSON object keys are strings; pairs keep the key's *type* and its wire
  order visible. That order — strictly ascending, RFC 8949 §4.2.1 — is
  itself part of what the vector pins. **A checker that sorts, or that
  compares maps as sets, silently deletes an entire class of the thing it
  was built to detect.**
- **Embedded CBOR is never recursed into.** A manifest's `body`, and a
  bundle's embedded manifest, render as byte strings exactly as the wire
  says. Each layer is rendered separately under its own name, because that
  boundary *is* F6/F9's three-layer strict decode.

Integers above `MAX_JSON_SAFE_INT` = 2^53 − 1 are **refused**, not emitted,
so no reader with IEEE-double JSON numbers can silently round a pinned
value. F14 **asserts** this refusal rather than assuming it (§5).

## 4. The four checks F14 owes

Per located layer:

1. **Render and compare.** Decode the layer's bytes with the independent
   implementation, render per §3, and require exact equality with the
   committed `diagnostic[layer]`. This is what catches "our encoder and our
   decoder agree with each other and are both wrong".
2. **Re-encode and compare.** Rebuild the item from the **committed**
   `diagnostic[layer]` (not from the checker's own decode — that would close
   the loop through one implementation) and re-encode it with the checker's
   **own** RFC 8949 §4.2.1 encoder (D31 row 1); require byte-equality with
   the committed bytes.

Per case:

3. **`SHA-256`(envelope key-0 byte string) == `work_id`** — the pre-image
   dug out of the envelope per §2.
4. **`SHA-256`(whole envelope) == `anchor_digest`**. Note for `bundle`:
   the envelope is the *embedded manifest* layer, **not** the bundle bytes,
   so this check is only trivial for the `manifest` kind and is a real
   structural claim for `bundle`.

Plus, over the raw bytes and in the checker's own explicit logic (D12's
recorded caveat: neither library's notion of "canonical" is trusted):

5. **Canonicality validation** — shortest-form integer heads, shortest-form
   length heads, definite lengths only, strictly-ascending unique unsigned
   map keys, exactly one top-level item, no trailing bytes.

## 5. Two things to confirm rather than assume

**Map order on load.** The sidecar pins wire order, so the whole comparison
degrades to a set comparison if the independent decoder does not preserve
it. `cbor2` preserves it via `dict` insertion order — but this must be
**demonstrated at run time**, not cited: the checker decodes a hand-built
map whose wire order is *descending* (`{2: …, 1: …}`, deliberately
non-canonical) and requires the loaded key order to come back descending. A
decoder that sorted, or that round-tripped through a set, fails there
loudly before any vector is touched.

**The `MAX_JSON_SAFE_INT` refusal.** The checker's renderer must refuse
2^53 on its own, and its self-test must exercise that refusal. Asserted, not
assumed.

## 6. What independence means here

The cross-check is a **freeze-gate input**. Its entire value is that it
shares no code with what it checks. Concretely, F14:

- must **not** import, link, call, or transitively reuse `antseal-core`'s
  CBOR code, and must not enter any Rust dependency tree
  (`dependency-policy.md` §5, dev-tool rule);
- must be checked against the **committed bytes**, never against fresh
  output from our encoder. If an expectation has to be produced by running
  our codec, the check has become a tautology;
- must be **generic over whatever is committed** — vectors are discovered
  from the tree, and no vector name, case name, layer name or byte string is
  hard-coded. Format work lands and re-emits vectors continuously; a checker
  needing per-vector wiring is one that will be quietly switched off.

The independence claim itself has one recorded correction: cbor2 **6.x is a
Rust/PyO3 extension** (`_cbor2`, pyo3 0.29) with **no pure-Python
fallback**, so D12's "different language" leg does not hold. What does hold,
and was checked rather than assumed: different author, different codebase,
and **zero shared code** — `minicbor 2.3.0` has no dependencies at all,
while cbor2's core pulls `pyo3`, `half`, `num-bigint` and `bigdecimal`. "No
shared code" was always doing the work that "different language" appeared
to.

D31 grades this tier **T1** — an independent re-implementation — and is
explicit that T1 cannot catch a **shared misreading of the spec**. So the
checker opens with a **T0 external oracle**: the worked examples of RFC 8949
Appendix A, encoded by our encoder and decoded by cbor2, both compared to
bytes the RFC itself publishes. Those bytes are the one thing here that no
amount of agreement between our two implementations could manufacture.

## 7. What this check does *not* cover

Stated so a reader of a green lane knows what green means.

- **A kind that commits format CBOR without a sidecar is silently out of
  scope, and one such kind is committed today.** Scope is "the case carries an
  object-valued `diagnostic`", which is what makes the checker generic over
  vectors that have not been written yet — but the *absence* of a sidecar
  reads identically to "this kind commits no CBOR". The measured instance is
  `testdata/vectors/v1/crypto/manifest-aead.json`, whose `manifest_bytes` is
  CBOR-shaped, **not well-formed** (`5820` declares 32 bytes over a 30-byte
  literal) and checked by nothing. Closing this needs a registry-level flag on
  the kind, which is **F31**'s and not this checker's — see
  `docs/decisions/D112-cbor-cross-check-scope-rule.md`.
- **Five kinds cannot enter scope at all, whatever they commit.** Scope is
  read from `expect.cases`, and `commitments`, `hkdf-labels`, `manifest-aead`
  and `unit-aead` carry `expect.vectors` while `signatures` carries named
  sub-objects. The checker now says which of the two silences it means; making
  those kinds *reachable* is F31's.
- **Canonical JSON is a different surface.** The `report` kind pins
  `report_json` under D29, not CBOR. D31 §7 registered that gap as **Q38**;
  nothing in this document covers it.
- **Resource caps are not canonicality.** `cbor-nesting-too-deep` (F11) and
  `bundle-too-large` (D10) are antseal limits; arbitrarily deep or large
  CBOR is perfectly canonical, so the tamper sweep records them as out of
  scope rather than pretending to confirm them.
- **T1 cannot see a shared misreading of the spec.** That is what the RFC
  8949 Appendix A anchor is for, and it covers only the profile's own
  surface — integers, byte and text strings, arrays, maps.

## 8. Keeping the two implementations from drifting

The rendering table exists twice as executable code (Rust and Python) and
three times as prose. That is a drift hazard, so it is **tested, not
promised**: `crates/antseal-core/tests/cbor_crosscheck_contract.rs`
requires the Python checker's `MAX_JSON_SAFE_INT` to equal the Rust
constant, and requires this document, the vector README and the
`vectors_cbor_diag` module to keep pointing at each other. A change to one
side that forgets the other goes red.

### 8.1 Scope is decided in exactly one place, and checked against nothing yet

A vector enters the CBOR cross-check when its `expect.cases[]` carry an
object-valued `diagnostic` — a mapping from layer name to that layer's
rendering. There is no kind allow-list, which is deliberate: a future
CBOR-committing kind is covered the day it lands, provided it commits a
sidecar.

That inference has failed in both directions, and the **false negative is the
live one** (§7). The false positive was found by the gate on 2026-08-09, when
A22 landed: the `anchor` kind commits no CBOR, but its cases carry a field also
called `diagnostic` — `AnchorDiagnostic` as a code string or `null` (D101 §3.5),
not a layer mapping — so every anchor case was pulled into scope and failed for
having no `*_bytes` field. Two vocabularies, one word. The repair narrowed the
test from `"diagnostic" in case` to `isinstance(case.get("diagnostic"), dict)`,
the weakest predicate under which `check_case` is defined at all.

**The sharper lesson is where the rule lived, not what it said.** It lived in
two functions. `run` was narrowed and `self_test` was not, so `--self-test`
selected `anchor/anchor.json` — which sorts before `bundle/` — and died on
`StopIteration`, red against a green `--check`, because CI runs them as
separate steps and only the second one selects. It is now written **once**, in
`scope_of`, which both callers use, and
`crates/antseal-core/tests/cbor_crosscheck_contract.rs::the_cbor_scope_predicate_is_written_exactly_once`
fails if a second copy is ever written. The self-test no longer selects a
sample: it sweeps **every** in-scope document, so its selection is the check's
selection in full rather than the first element of it.

The declaration this predicate should be checked against is **F31**'s
registry-level flag on the kind. Its design is fixed by
`docs/decisions/D112-cbor-cross-check-scope-rule.md`.

Worth recording *how* this was found, because no lane-local check could have:
A22's lane verified `scripts/cross-check.sh`'s generator half and never
reached this checker, which is Python and reads the committed documents rather
than the Rust. Only the full gate run saw it.
