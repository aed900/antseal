# D101 — Which home A22's anchor golden vectors take, and what their `expect` may contain

- **Status: RESOLVED — HOME B, the reserved `anchor` kind under
  `testdata/vectors/v1/`, and the home half of the lean is NOT overturnable:
  it is five committed sources against one, and one of the five is the frozen
  manifest that reserves the kind by name. What IS overturned is the second
  half — "verdict-only expect plus a binding test" — on three measured
  grounds. (1) "Verdict-only" is too narrow: `evaluate_*` returns
  `AnchorOutcome`, which carries `suppressed` (A39) and `identity` (A40)
  beside the verdict, and D92 recorded in writing that A40's OTS identity
  half "has never been pinned by a falsifiable row" — an `anchor` vector is
  exactly that row, and a verdict-only `expect` would decline to be it.
  (2) It is simultaneously too wide, in a place the brief did not look:
  `AnchorIdentity::TsaSigner { subject_dn_der }` is what **A72** is open to
  reconcile against A31's `(issuer_der, serial)`, so freezing the payload
  forever, this wave, pre-empts an unresolved task — a second
  `root_store_version`-class trap, and a nearer one, since A72 is a live
  register row and no root removal is proposed. (3) The standing binding test
  is replaced: an equality assertion between a **frozen** file and an
  **unfrozen** one is a lane that can only ever go red for a reason the frozen
  side is forbidden to fix. It becomes a committed generator plus a
  self-binding `artifact_sha256` inside the frozen document.
  On the crux, `root_store_version` is **OUT**, and the resolution is stronger
  than "drop it and accept the loss": **A26 Accept row 2 is structurally
  unable to be discharged by golden vectors at all** — it needs two stores,
  and a vector executor can reach exactly one — so it is already discharged,
  today, by `chain::tests::appending_a_root_leaves_every_existing_verdict_unchanged`
  over five real tokens with a non-vacuity guard. Row 2's phrase "all existing
  anchor golden vectors" describes a mechanism that cannot exist; the property
  it names is true and tested elsewhere. Nothing is lost by omitting the field,
  because `chain::tests::store_version_appears_in_verdict_data` already pins it
  in code, where moving it on a bump is legal. And the deeper structural finding
  the brief circles but does not name: **`anchor` is the SECOND vector kind
  whose pinned bytes are a function of the verifier rather than of the format**,
  which is the exact property D94 minted the VERDICT EVENT class for — and
  `verdict_event_ok`'s hard scope to `/report/` is an accident of `report`
  having been the only such kind on 2026-08-06, not a principle. Do **not**
  extend the hatch now; name the one event that will need it (an A26
  *removal*, or a signer-DN rendering change — not an append) and hand it off.**
- **Date: 2026-08-07** (M2 wave 9 planning round; resolves **Q109**, blocks
  **A22**)
- **Owning tasks: A22** (executes; its Accept rows are rewritten by §2.3),
  **Q109** (the register row this closes), **A26** (Accept row 2's wording,
  §4.4), **A25** (the capture the vectors quote, §7). Register entry: the D101
  row this record creates under `TODO.md` "Due M2".
- **Amends**: `tasks/A.md` A22 Accept (§2.3) and A26 Accept row 2 (§4.4);
  `testdata/vectors/README.md` rows 205-207, 418 and the stale budget figure
  (§5, §8.3); `tasks/Q.md:1373`, `TODO.md:529` and this record's own
  predecessor `D94:554-555` (§2.2). **Supersedes**: nothing. **Binds
  against**: D94 (§3.4, §6), D87 (§8.3), D57/A6 (§6), D92 (§3.3), D53 (§2.2).

---

## The problem, in one sentence

A22 must commit anchor golden vectors under `testdata/anchors/`
(`tasks/A.md:272`) and have them retained forever and verified bit-identically
on wasm32 (`:272-273`), and `crates/wasm-bitmatch/build.rs:3-5,45,53` walks
`testdata/vectors/` **only**, so the directory the first clause names is
unreachable by the lane the next two require.

---

## 1. What was measured

Everything below was read from the tree at `09a81c2` plus the working tree.
Where a task entry disagrees with the code, the code is recorded as the fact.

### 1.1 The two homes

| Fact | Where |
| --- | --- |
| The bit-match harness walks `testdata/vectors/` and nothing else; an unclassifiable file fails the **build** | `crates/wasm-bitmatch/build.rs:3-5`, `:45`, `:53` |
| It depends on `antseal-core` through a **normal** edge with `features = ["test-vectors"]` | `crates/wasm-bitmatch/Cargo.toml:44` |
| `testdata/anchors/` is documented as A25/A24's **capture area**, replayed by CI — not as a vector home | `testdata/anchors/README.md:1-13`; `testdata/README.md:20` |
| `testdata/README.md` already lists **`anchor` (A, M2)** among the kinds under `vectors/<format-version>/`, "retained forever, per version … frozen per version by Q6's `FROZEN.sha256`" | `testdata/README.md:16` |
| `testdata/vectors/README.md` reserves the `anchor` kind by name: *"recorded `.ots`/TSA-token fixtures with expected per-anchor verdict states — slots in as a kind with no envelope change"* | `testdata/vectors/README.md:205-207` |
| The **frozen manifest itself** names the reservation, and names the append path as the one S4 already executed | `testdata/vectors/v1/FROZEN.sha256:66-71` |
| Q5's own Accept requires the lane to *"automatically cover new vectors, **including M2 anchor vectors** (an explicit M2 exit criterion)"* | `tasks/Q.md:57`, `:61` |
| `testdata/anchors/` has no `FROZEN.sha256`, no `INDEX.json`, no retention clause and no wasm lane | measured: `ls testdata/anchors/` is `A16-A17-live/`, `A25-bootstrap/`, `README.md` (+ an untracked `A25-upgrade-headers/`) |

Five sources for Home B, one for Home A, and the one is a compound sentence
whose other clause contradicts it.

### 1.2 The vector machinery, and what it costs to enter

| Fact | Where |
| --- | --- |
| Adding a kind is four steps and touches no existing vector: `KNOWN_KINDS`, payload types, dispatch arm, README row | `crates/antseal-core/src/test_util/vectors.rs:15-23` |
| `KNOWN_KINDS` today holds twelve names; `anchor` is not among them | `vectors.rs:61-75` |
| The `#! kind` directives across all manifests **must equal** `KNOWN_KINDS` — so `#! kind anchor` and the executor land in one commit or CI is red | `crates/antseal-core/tests/vector_freeze.rs:368-379` |
| `INDEX.json` entries are checked against `KNOWN_KINDS` too | `crates/antseal-core/tests/vector_index.rs:256-257` |
| The template is 215 lines and recomputes the **whole** `expect` object from `inputs`, comparing it as one value, then asserts the structural coverage a value comparison cannot state | `crates/antseal-core/src/test_util/vectors_storage_address.rs:105-120` |
| The Q5 lane compares `VectorSummary::recomputed_digest` — SHA-256 over *every byte the execution recomputed* — so **the `expect` field set IS the wasm-parity surface** | `vectors.rs:145-163`, `:79-86` |

Confirmed: entry cost ~215 lines, all wiring generic and in place.

### 1.3 The evaluator surface — wider than the brief states

| Fact | Where |
| --- | --- |
| No anchor verdict type derives `Serialize`; derives are `Debug, Clone, PartialEq, Eq` (+`Copy`/`Hash` on the small ones) | `anchor/model.rs:701`, `:617`, `:667`; `anchor/verdicts.rs:384` |
| `AnchorVerdict` has **six** fields: kind, state, verified_time_unix, source, fetch_date, diagnostic | `model.rs:702-708` |
| `to_anchor_result()` **drops** the diagnostic and emits **no slot** for `absent` | `model.rs:948-971`, `:873-882` |
| Headline eligibility is a separate predicate, not a field | `model.rs:900-902` |
| **`evaluate_*` does not return `AnchorVerdict`. It returns `AnchorOutcome`, which carries `verdict` + `suppressed: Vec<AnchorAnomaly>` (A39) + `identity: Option<AnchorIdentity>` (A40)** | `verdicts.rs:384-428` |
| `AnchorOutcome::new` applies A40's rule once: an identity survives **only** where the verdict is headline-eligible | `verdicts.rs:400` |
| `suppressed` must be *"empty, never absent"* — A39 Accept row 3 | `verdicts.rs:414-421` |
| Every evaluator is public and takes `verify_at`/roots/evidence as parameters | `verdicts.rs:610-616`, `:675-679`, `:1053-1058` |
| `OnlineEvidence`/`BlockEvidence` are publicly constructible builders; `OtsUpgrade::new`, `OtsArtifactView::from_parts`, `TsaArtifactView::from_parts` are all public | `model.rs:490-502`, `:566-585`, `:129-145`, `:184-207`; `bundle/schema.rs:463-476` |

The report projection is not "complete verdict output" — the brief is right —
but it is short by **three** things, not one: diagnostic, `suppressed`, and
`identity`.

### 1.4 The `from_static` gate — confirmed, and confirmed for a sharper reason

`TsaRootStore::from_static` is `#[cfg(any(test, feature = "test-util"))]`
(`anchor/roots/mod.rs:216-218`), guarded by a source-text test that asserts the
attribute literally (`:538-540`). The gate matters here because of the feature
lattice, not the `cfg(test)`:

```
test-util = ["test-vectors", "dep:proptest"]      Cargo.toml
#[cfg(feature = "test-vectors")] pub mod test_util;   lib.rs:39-40
```

`from_static` sits on the **larger** feature; the vector executor sits on the
**smaller** one, and `wasm-bitmatch` takes the smaller one through a *normal*
dependency edge. So an executor that called `from_static` would compile under
`cargo test -p antseal-core` (where `cfg(test)` is on) and **fail to build
`wasm-bitmatch`**. The limit is real, and it fails at build time in the one
lane A22 exists to satisfy.

The tempting repair — move `from_static` down to `test-vectors` — is
**refused** (§6).

### 1.5 The crux inputs

| Fact | Where |
| --- | --- |
| `root_store_version` is a `ChainVerdict` field, populated at four construction sites from `store.version()` | `anchor/chain.rs:206`, `:272-273`, `:519`, `:535`, `:546`, `:582` |
| An injected store reports `INJECTED_STORE_VERSION = 0`, deliberately outside the released sequence | `roots/mod.rs:126-130`, `:220` |
| `TSA_ROOT_STORE_VERSION = 1`, "bumped on **any** change to the root set (A26)" | `roots/mod.rs:110-113` |
| `scripts/vector-freeze.sh` under `status frozen` refuses any moved digest, with exactly one escape | `:257-278` |
| The escape refuses anything that is not a `report/` vector, **by path**, first check in the function | `:99-101` |
| A26 Accept row 2 reads *"after appending a new root, all existing anchor golden vectors still verify unchanged (store version bumped, results stable)"* | `tasks/A.md` A26 Accept row 2 (`:328` at time of writing) |
| **That row is already discharged, and not by vectors**: `appending_a_root_leaves_every_existing_verdict_unchanged` builds two injected stores differing by one root, asserts full `ChainVerdict` equality over five real tokens, and guards non-vacuity by showing the appended root promotes SwissSign `internally-consistent-only` → `proven` | `chain.rs:2116-2157` |
| The store version already has its own committed pin, in code | `chain.rs:2095-2114` |

### 1.6 The wave-9 network item is already unblocked, and the blocker moved

`testdata/anchors/A25-upgrade-headers/` **exists on disk**: fourteen files,
captured 2026-08-07T10:36:32Z–10:37:34Z, mainnet headers for 960767/960768/960771
from both `blockstream.info` and `mempool.space`, byte-identical across
endpoints, each header verified offline by double-SHA256 against the height
lookup. Consent is recorded verbatim at the head of `CAPTURE.log`.

It is **untracked** (`git status: ?? testdata/anchors/A25-upgrade-headers/`).
So A22's remaining dependency is not a fetch — it is that commit landing. §9
plans both ways regardless.

---

## 2. Ruling 1 — the home

**RULING 1. Home B. A22's golden vectors land as the `anchor` kind under
`testdata/vectors/v1/anchor/`. `testdata/anchors/` stays what its own README
says it is: A25/A24's capture area and the provenance of record.**

The lean is confirmed, and confirming it is the honest outcome: five committed
sources against one, and refusing to say so would be the failure this brief
exists to avoid, not its avoidance. What the attack *did* produce is
everything in §3 onward.

### 2.1 The two homes were never two candidates

The framing "two specified homes" (`tasks/Q.md:1373`) reads A22 Accept row 1 as
nominating a vector location. It does not — or rather, it does so by accident.
`testdata/README.md` already assigns both directories, in adjacent rows, to
different jobs: `:16` puts the `anchor` **kind** under
`vectors/<format-version>/`, and `:20` reserves `anchors/` for *"recorded real
OTS calendar responses, `.ots` upgrade states, and TSA tokens … replayed by CI
so the anchor lane never touches real anchor networks."*

A22 row 1 collides with a rule its own tree already wrote down. The collision is
one word — "Vectors" where the sentence means "artifacts".

### 2.2 The Accept-row miscount, and the third source the brief missed

**A22 has THREE Accept rows** (`tasks/A.md:272-274`), not four. Three committed
places say four:

| Source | Text |
| --- | --- |
| `tasks/Q.md:1373` | "Three of A22's four Accept rows depend on the distinction" |
| `docs/decisions/D94-anchor-verdict-vector-re-emit.md:554-555` | "which are three of A22's four Accept rows" |
| **`TODO.md:529`** | "only the second gets retention, freeze and wasm parity — three of A22's four Accept rows" |

The brief named two of the three. The register row is the third and it is the
one that will be read most.

The mechanism is D53's, exactly: **a compound row counted as two.** Row 1 is
*"Vectors committed under `testdata/anchors/`; retained forever in CI per
format-stability policy (Q wiring)."* — a home clause and a retention clause
joined by a semicolon. Split it and there are four; do not, and there are
three. D53 recorded this same expansion on A21 (*"six semicolon clauses of
which two are compound, expanding to eight"*) and recorded it as a correction
precisely so the next lane would not re-derive it silently. Q109 re-derived it
silently.

Two things follow, and the second is worse than the arithmetic:

1. The honest statement is **three of three**, not three of four. Row 1 names
   the home *and* the retention; row 2 ("byte-identical serialized verdicts for
   every vector") is unreachable from Home A because the harness cannot see it;
   row 3 ("M2 exit checklist references these passing tests") references
   whichever tests the home produces. Rows 1 and 2 depend hard, row 3
   consequentially.

2. **All three sources name "freeze" as an A22 Accept property, and no A22
   Accept row mentions freeze.** Row 1 says "retained forever … per
   format-stability policy". Retention and freeze are different guarantees with
   different mechanisms — `FROZEN.sha256` is *"two guarantees in one file"*
   (`testdata/vectors/v1/FROZEN.sha256:3-11`) and Q6's own Accept separates
   them (`tasks/Q.md:70-72`). So Home B supplies freeze as a **consequence**,
   not because A22 asked for it. Left alone, the property that this entire
   record is about would remain unasserted by the task that owns it.

### 2.3 What A22's Accept must become

**RULING 1a.** Rewrite A22's Accept as four rows, uncompounded, with freeze
named:

- Vectors committed as the **`anchor` kind** under
  `testdata/vectors/v1/anchor/`, registered in `INDEX.json` and in
  `KNOWN_KINDS`. Not `testdata/anchors/`, which is A25's capture area and
  carries no freeze, no retention rule and no wasm parity lane (D101).
- Frozen: a `#! kind anchor A22` directive and one digest line per file
  appended to `testdata/vectors/v1/FROZEN.sha256`, and retained forever per
  Q6's per-version retention policy.
- Native and wasm runs produce byte-identical `recomputed_digest` for every
  vector — which, for this kind, means the whole `expect` object of §3.
- M2 exit checklist references the `golden-vectors`, `vector-freeze` and
  `wasm-bitmatch` lanes' passing runs **and** A21's in-module wasm32 rows
  (§6.3 — two mechanisms, one criterion); any wasm-incompatible dependency
  (A-OD6) resolved first.

And amend `tasks/Q.md:1373`, `TODO.md:529` and `D94:554-555` to "three of A22's
three Accept rows", or delete the count — a count that has been wrong in three
places at once is not load-bearing enough to keep.

---

## 3. Ruling 2 — the `expect` field set

The Q5 lane digests *everything the executor recomputed*
(`vectors.rs:79-86`, `:153-163`). So the `expect` set is not a documentation
choice: **it is exactly the surface A22's second Accept row certifies as
native↔wasm-identical.** A field left out is a field the M2 exit criterion does
not cover. A field left in is a field frozen forever with no legal way to move
it (§4.3). The set must be the widest one every member of which is invariant
under every *legal* future change.

### 3.1 `root_store_version` — **OUT**

**RULING 2a. `root_store_version` is not in the `expect`, and no anchor vector
carries a store version in any field.**

Three reasons, in increasing strength.

**(i) It is verdict provenance, not verdict content.** A golden vector pins what
the verifier computes *about a fixed artifact*. `root_store_version` is not a
function of the artifact at all — it is a build constant, identical in every
verdict the same binary produces. Pinning it in a forever-frozen file is a
category error independent of anything A26 does.

**(ii) A26's own row already draws the line on this side.** Row 2's parenthetical
is *"(store version bumped, **results stable**)"* — `tasks/A.md` A26 Accept
row 2, `:328` at time of writing. The row
distinguishes the version from the results in its own text and promises
stability only for the second.

**(iii) The decisive one: A26 Accept row 2 is structurally unable to be
discharged by golden vectors, and is already discharged without them.**
Demonstrating "appending a root changes nothing" requires evaluating the same
artifact against **two** stores. A vector executor can reach exactly one —
`pinned()` — because `from_static` is gated one feature above it (§1.4). The
comparison the row asks for cannot be written in this kind, ever.

It is written elsewhere and it is better than the row asks for.
`chain::tests::appending_a_root_leaves_every_existing_verdict_unchanged`
(`chain.rs:2116-2157`) builds `pinned()`'s root set and that set plus SwissSign,
runs five real tokens through both, asserts full `ChainVerdict` equality, and
then proves the append was real by showing SwissSign moves
`internally-consistent-only` → `proven` across it. A26 row 2's phrase *"all
existing anchor golden vectors"* describes a mechanism that does not and cannot
exist; the property it names is true, tested, and non-vacuous today.

Nothing is lost by omitting the field. `store_version_appears_in_verdict_data`
(`chain.rs:2095-2114`) already pins all three of its meanings — that it equals
`TSA_ROOT_STORE_VERSION`, that the literal is `1`, and that an injected store
reports `0` and is therefore distinguishable in verdict data. That test is
**code**, so the `assert_eq!(v.root_store_version(), 1)` on `:2103` moves on a
bump the way an assertion is supposed to move. The M2 exit criterion is not
pinning "a verdict stripped of the field A26 exists to surface" — it is pinning
the verdict, while the field A26 exists to surface stays pinned where it can
still be maintained.

**Not a third way, and refused:** teaching the executor to take the store
version as an *input* and assert the verdict echoes it. That reintroduces the
value into the frozen file under a different key and buys only the tautology
that `chain.rs:519` assigns what it assigns.

### 3.2 `suppressed` — **IN**, with its store-invariance stated as empirical

A39 requires `suppressed` to be *"empty, never absent"* — "no anomalies" and
"not computed" must never be the same value (`verdicts.rs:414-421`). Nothing in
the tree pins that distinction in a committed artifact; the report projection
cannot, because `AnchorResult` has five fields and `to_anchor_result` never sees
`AnchorOutcome`. An `anchor` vector whose every case carries `"suppressed": []`
except the one that carries a code is the first committed witness for it.

It goes in with one honest caveat recorded here rather than discovered later:
`suppressed` is derived from `ChainVerdict::suppressed_faults()`
(`verdicts.rs:1113-1118`), so it is chain-derived and therefore the one `expect`
field whose invariance under a root append is **empirical** — measured over five
tokens by `appending_a_root_leaves_every_existing_verdict_unchanged` — rather
than structural. The append shape that could move it is one that gives a
vector's token a *second* valid path. §4.2 walks it.

### 3.3 `identity` — **discriminant IN, payload OUT.** The trap the brief did not find

`AnchorOutcome::identity` is `Option<AnchorIdentity>`, and
`AnchorOutcome::new` filters it to headline-eligible verdicts only
(`verdicts.rs:400`) — A40's rule, applied once, structurally. That filter is a
genuine invariant and D92 recorded that **it has no OTS-side witness**: *"the
eligibility filter has no OTS-side witness (every test that can see it goes
through the TSA path)"*, and *"the one existing OTS identity test cannot
distinguish three of the four candidates, so A40's OTS half has never been
pinned by a falsifiable row."* A pair of OTS cases — `proven` carrying
`bitcoin-chain`, `attested` carrying `null`, same artifact bytes, differing only
in `OnlineEvidence` — is that row. This is a concrete win Home B delivers and
"verdict-only" declines.

But the payload must not go in. `AnchorIdentity::TsaSigner` carries
`subject_dn_der` (`verdicts.rs:269-272`; built by `signer_dn_der` at `:1192`), and **A72 is open to reconcile exactly
that against A31's `TsaSignerIdentity { issuer_der, serial }`** (`TODO.md:441`).
"Reconcile" does not say which side moves. If A72 moves the core-side notion,
every TSA vector's frozen `expect` moves — with no legal mechanism to move it
(§4.3). This is the same failure class as `root_store_version` with a **nearer
trigger**: no root removal is proposed, and A72 is a registered task with a
named predecessor chain.

**RULING 2b.** `expect` carries `identity_kind`: `"tsa-signer"`,
`"bitcoin-chain"`, or `null`. Not `subject_dn_der`. The discriminant is what
carries A40's filter and D92's OTS ruling; the DER payload is what A72 may
move. When A72 resolves, whether to append a payload field is a fresh question
for whoever lands it — appending a *field* to a new case is legal forever
(§5.1); moving an existing one is not.

### 3.4 `source` — **IN**, and it is the highest-risk field in the set

`verified_signer(&token)`/`claimed_signer(&token)` render the signer
certificate's `subject` (`verdicts.rs:1178-1191`) — read from the token, never
from a bundle field and never from the store, so it is a pure function of the
frozen artifact bytes. It is also a D29 report field that R12 emits, and it is
named in A22's `Do` ("state, eligibility, extracted times" is the summary;
`AnchorResult` is the shape). It goes in.

Record the exposure: a change to how a DN is *rendered* is a verifier change,
not a store change or a format change, and after A22 it would move **two**
frozen files — a `report/` vector, which has the D94 hatch, and an `anchor/`
vector, which does not. That asymmetry is the concrete, non-hypothetical reason
§4.3's hand-off exists.

### 3.5 The set

**RULING 2c.** One `inputs` case ↔ one `expect` case, positionally, both
name-keyed; the executor rebuilds the entire `expect` object from `inputs` and
compares as one value (the `storage-address` and `report` pattern), then asserts
structural coverage.

`inputs`:

| field | why |
| --- | --- |
| `verify_at_unix` | A22's "at a fixed `verify_at`"; a parameter, never a clock (A9) |
| `anchor_digest` | required by both evaluators; without it D56 §9's "someone else's seal renders `proven`" is live |
| `cases[].name` | stable handle; uniqueness asserted |
| `cases[].kind` | `"ots"` \| `"tsa"` |
| `cases[].artifact_hex` | the recorded bytes (§7) |
| `cases[].intermediates_hex` | `[]` for the A25 tokens; the field exists so a chain-shipping case is expressible |
| `cases[].fetch_date_unix` | `TsaArtifactView::from_parts` requires it; see the D60 clock trap in §7.3 |
| `cases[].upgrade` | OTS only: `{ block_height, block_header_hex, fetch_date_unix }` → `OtsUpgrade::new` |
| `cases[].online` | `[]` for offline cases; `[{height, result: "header"\|"no-such-block", header_hex?}]` → `OnlineEvidence::with_block` |
| `cases[].provenance` | the `testdata/anchors/` path the bytes came from, verbatim. Documentation inside the frozen file, not a lookup |

`expect`:

| field | recomputed from | why it is invariant |
| --- | --- | --- |
| `verify_at_unix` | echo of `inputs` | pins that the executor used the declared time |
| `cases[].name` | echo | ordering + identity |
| `cases[].artifact_len`, `artifact_sha256` | `inputs.artifact_hex` | self-binding (§7.2) |
| `cases[].state` | `AnchorVerdict::state()`, wire spelling | the M2 exit criterion's object |
| `cases[].headline_eligible` | `is_headline_eligible()` | A22 `Do` names eligibility; A21 row 5 and D93 §9 both record that a state name alone is blind to it |
| `cases[].verified_time_unix` | `verified_time_unix()`, or `null` | "extracted times" |
| `cases[].source` | `{ identity, verified }` or `null` | function of artifact bytes only (§3.4) |
| `cases[].fetch_date` | `fetch_date()` verbatim | echo of an input, through the verdict |
| `cases[].diagnostic` | `diagnostic().map(code)` or `null` | **the field `to_anchor_result` drops** (`model.rs:948-971`) — a vector is the only place it is ever pinned |
| `cases[].identity_kind` | discriminant or `null` | §3.3 |
| `cases[].suppressed` | codes, `[]` never absent | §3.2 |
| `cases[].report_slot` | `to_anchor_result()` as an object, or `null` | binds the vector to R12's projection so the two cannot drift; `null` is `absent`'s no-slot rule (`model.rs:873-882`) |

Explicitly **not** in `expect`: `root_store_version` (§3.1), `subject_dn_der`
(§3.3), any aggregate — R17 lands at M3 and aggregation over a fixed artifact
set is a different pin with a different owner.

Structural coverage the executor asserts beyond the value compare (the S4
pattern, `vectors_storage_address.rs:120-135`):

1. every case name unique;
2. at least one `tsa` and one `ots` case;
3. at least one `headline_eligible: true` and one `false`;
4. **some OTS case carries `identity_kind: "bitcoin-chain"` and some OTS case
   carries `null`** — D92's missing witness, asserted structurally so it cannot
   be lost by editing a value;
5. every `headline_eligible: true` case has non-null `verified_time_unix` and
   `identity_kind`, and every `false` case has `identity_kind: null` — A40's
   filter, stated as a law over the whole document rather than case by case;
6. `report_slot == null` iff `state == "absent"`.

---

## 4. Ruling 3 — an A26 root append, walked concretely

**RULING 3. An append moves nothing in the `expect` of §3.5. Walk it.**

Suppose A26 appends a root — the exact append
`appending_a_root_leaves_every_existing_verdict_unchanged` already simulates —
and `TSA_ROOT_STORE_VERSION` goes 1 → 2.

### 4.1 What moves

1. `roots/mod.rs:112` `TSA_ROOT_STORE_VERSION` 1 → 2, `:118` build date.
   Reviewed change, A7 provenance procedure, per A26's `Do`.
2. `chain.rs:2103` `assert_eq!(v.root_store_version(), 1)` goes red and is
   edited to `2`. **This is the whole of the version's blast radius**, it is in
   code, and editing it is legal. It is the only committed literal `1` bound to
   the store version outside `roots/mod.rs` itself.
3. `appending_a_root_leaves_every_existing_verdict_unchanged` is re-run and
   stays green — it compares two injected stores, so the bump does not reach it.
4. A44's root-expiry check reads the new set. Non-gating.

### 4.2 What does not move

Every `anchor` vector. Each `expect` field of §3.5 is either a function of the
frozen artifact bytes (`artifact_*`, `source`, `fetch_date`, `verified_time_unix`
for TSA — `genTime` is read out of the token), an echo of `inputs`
(`verify_at_unix`, `name`), a discriminant fixed by the artifact kind
(`identity_kind`), or a chain-shape value the append leaves alone
(`state`, `headline_eligible`, `diagnostic`, `suppressed`, `report_slot`).

`vector-freeze` stays green because no digest moved. `wasm-bitmatch` stays green
because `recomputed_digest` is a hash over exactly those unchanged values.
A26 Accept row 2 holds — and holds for the tokens the vectors carry, not merely
in principle, because the vectors are in CI and CI runs on the append commit.

**The one shape that would move something.** If the appended root gives a
vector's token a *second* valid path, `suppressed` can gain or lose an entry
(§3.2). No such append is proposed, the five-token measurement at
`chain.rs:2130-2143` says the current tokens are single-path against the current
store, and the vector suite runs on every append commit — so the append lane
*is* the detector. **RULING 3a: A26's `Do` gains one line — "run the
`golden-vectors` and `vector-freeze` lanes on the append commit; a moved
`anchor` vector means the append introduced a second valid path for a pinned
token and needs §4.3's hand-off, not a regeneration."**

### 4.3 The one thing that has no legal mechanism, named rather than built

`verdict_event_ok` refuses anything that is not a `report/` vector, by path,
as its first check (`scripts/vector-freeze.sh:99-101`). So a frozen `anchor`
vector can **never legally move**. Under §3.5's field set only three events
could ever require it:

| event | likelihood | today |
| --- | --- | --- |
| A26 root **removal** (a compromised CA) | rare, and A26 already requires *"an explicit compatibility note"* for it | none proposed |
| a signer-DN **rendering** change (§3.4) | low | none proposed |
| a root append introducing a second valid path (§4.2) | low | measured absent |

**RULING 3b. Do not extend the hatch now.** D94 Ruling 4 says the classes are
told apart *"mechanically, not editorially"*, and the mechanism it built is a
diff-derived check with four specific predicates. An anchor-shaped equivalent
(artifact hex byte-identical, `verify_at_unix` unchanged, `schema_version` and
`format_version` unchanged, not-all-cases-moved) is writable, but writing it
speculatively produces an untested escape hatch guarding a door nobody has
knocked on — and D94's own §4 finding was that an instrument nobody exercises is
an instrument that is quietly blind.

**RULING 3c. Name it instead, in two places**, so the event discovers the gap
rather than a red lane discovering it at merge time:

- a paragraph in `testdata/vectors/v1/FROZEN.sha256`'s prose beside the
  `#! kind anchor` line: *"`anchor` is the second kind whose bytes are a
  function of the verifier rather than of the format (D94 §2a). The D94 verdict-event
  escape is scoped to `report/` by path and does not reach it, so an `anchor`
  vector cannot legally move. The three events that could require one are listed
  in D101 §4.3; each needs its own record, which is also where
  `verdict_event_ok` would be extended."*
- a bullet in A26's `Do` beside Ruling 3a.

### 4.4 A26 Accept row 2's wording

**RULING 3d.** Amend row 2 to name the mechanism that discharges it:

> Test: after appending a new root, every existing per-anchor verdict is
> byte-identical except for the store version — `chain::tests::appending_a_root_leaves_every_existing_verdict_unchanged`,
> with a non-vacuity guard showing the appended root promotes a previously
> unanchored token. The `anchor` golden vectors (A22) additionally re-run
> unchanged on the append commit, which is a *consequence* of the property, not
> its proof: a vector executor reaches only `TsaRootStore::pinned()` and cannot
> compare two stores (D101 §3.1).

---

## 5. Ruling 4 — `testdata/vectors/README.md:418`

**RULING 4. The append path is authoritative. Row 418 is wrong and is amended
before `#! kind anchor` lands.**

The row reads:

| | now (`status pre-freeze`) | after Q14 (`status frozen`) |
| --- | --- | --- |
| Add a kind | record it as `#! kind` | new kinds land under a new format version |

Four sources say append: `FROZEN.sha256:66-71`, `testdata/vectors/README.md:205-207`,
`testdata/README.md:16`, and the **executed** S4 precedent — `storage-address`
landed post-freeze on 2026-08-01 with a new `#! kind` line and no moved digest.
One policy table says new version. It is not a close call, and the reason is not
the head count.

**Row 418 instructs a misfile.** A vector's `format_version` names *the format
the vector pins*, not the vector tree's own schema — that is `schema_version`,
declared separately in the same envelope (`vectors.rs:52-53`, `:171-174`), and
the runner has a dedicated `FormatVersionMismatch` error for a vector whose
declared version disagrees with its directory (`vectors.rs:113-121`). Anchor
verification pins **v1** artifacts: v1 `.sealproof` bundles carry v1 anchor
fields under the D84 freeze boundary. Filing an anchor vector under `v2/` would
declare that anchor verification pins format v2 — false, and false in exactly
the way that error exists to catch.

**Row 418 also contradicts row 415** in its own table. *"Add a vector →
additions stay legal forever."* A vector of a new kind is a vector. And it
contradicts the artifact it governs: `FROZEN.sha256:66-71`, inside the frozen
manifest, calls a post-freeze kind addition *"the sanctioned append path (the
same one the M2 `anchor` kind is reserved for)"*. A policy row cannot forbid
what the frozen file it describes promises by name.

**And it would cost what it was written to prevent.** A `v2/` directory triggers
Q6 per-version retention of a whole new tree, its own `FROZEN.sha256` and
`INDEX.json`, a D87 budget of its own, and a `format::SUPPORTED_VERSIONS` entry
— a *format*-version bump to accommodate a *test* artifact. That is the format
event the freeze exists to make expensive, spent on something that is not one.

### 5.1 The amendment

**RULING 4a.** Row 418's right-hand cell becomes:

> same — a new kind is an **append**: one `#! kind <name> <task>` directive plus
> its vectors' digest lines; no existing digest moves and no existing vector is
> touched. A new **format** version is for a change to the format the vectors
> *pin*, never for a new kind — a vector's `format_version` names the format it
> pins, and the runner refuses a misfiled one (`FormatVersionMismatch`).
> Executed twice: `storage-address` (S4, 2026-08-01), `anchor` (A22).

Add one sentence under the table: *"This row previously read 'new kinds land
under a new format version'. It was already false when written — the v1 freeze
manifest reserves the `anchor` kind by name — and S4 landed a post-freeze kind
against it on 2026-08-01. Corrected 2026-08-07 (D101 §5)."* The house rule is
that a corrected row quotes its own former wording; §2.2's defect class is what
happens when it does not.

**Ordering:** the amendment lands **before or in the same commit as**
`#! kind anchor`. Landing the kind first is landing it against a committed
policy row, which is the shape D94 §3 called a prediction that ages into a lie.

---

## 6. Ruling 5 — untrusted-root and mock-CA cases

**RULING 5. They stay where A21 already put them, and A22 does not try to
re-home them. The `from_static` gate is not widened.**

### 6.1 What is inexpressible, precisely

An `anchor` vector-kind executor reaches `TsaRootStore::pinned()` and nothing
else (§1.4). So every case needing an injected store is inexpressible as a
vector: A21 row 3 (untrusted root → `internally-consistent-only`), A21 row 3's
D57 positive twin, and every A24 mock-CA case (controllable genTime, PKIStatus,
RSA/ECDSA signer variants, failure modes). Also inexpressible: A26's own
two-store comparison (§3.1).

That is not a gap A22 opened. Those cases were never vector material, because a
vector pins what a *shipped verifier* computes, and a shipped verifier has one
store by construction — which is the whole content of A6's compile-time fact.

### 6.2 Their home, which already exists

A21's homing ruling of 2026-08-06 (`tasks/A.md:257`) already decided this, for
the same wasm32 reason A22 now inherits: every row is driven from the tamper
harness natively **and** pinned as an in-module `#[cfg(test)]` test beside
A18's, *"because the wasm32 lane runs `--lib` only and every integration target
is a separate crate that never executes there."* A18 runs its 44 verdict rows
that way; A43 adopted it. Inside `cfg(test)`, `from_static` exists, so the
injected-store cases run on both targets there and only there.

A22 adds nothing to this and must not. Reading A22's row 2 ("byte-identical for
every vector") as an obligation over the mock-CA matrix is how a lane arrives at
§6.4.

### 6.3 Two mechanisms, one exit criterion — state it, do not paper it

The M2 exit criterion "the WASM build must bit-match native verification"
(MVP-SPEC.md line 169) is discharged by two instruments with different
strengths, and A22's checklist row must say so rather than imply one:

| | covers | strength |
| --- | --- | --- |
| Q5 `wasm-bitmatch` over `anchor` vectors | the pinned-store cases | **byte-identical**: one SHA-256 over every recomputed value, compared across targets |
| A21/A18 in-module rows under `--lib` on wasm32 | the injected-store cases | **same-verdict**: each target asserts the same expected state/code; no cross-target byte comparison |

The second is weaker and is the strongest available, because a cross-target byte
comparison requires a serialization the harness embeds, and the harness cannot
embed a case it cannot construct. Recording the difference is the point; a
checklist row that says "wasm parity: green" over both is the row that is
technically true and practically blind.

### 6.4 The tempting repair, refused

Moving `from_static` from `test-util` down to `test-vectors` would make every
A21/A24 case expressible as a vector. **Refused, three ways:**

1. `test-vectors` is enabled through a **normal** dependency edge
   (`wasm-bitmatch/Cargo.toml:44`). Moving the symbol there puts an injectable
   root store into the normal graph — destroying precisely A6's *"page/CLI
   production paths provably use `pinned()` only"* as a **compile-time fact**
   (`roots/mod.rs:209-213`).
2. `from_static_is_absent_from_a_default_build` (`:538-540`) asserts the
   attribute's literal source text. The move fails a committed test written to
   catch this exact mutation.
3. It would let a vector pin a verdict produced by a store that is not the
   shipped one — a golden vector certifying something no user's verifier can
   compute.

---

## 7. Ruling 6 — the artifact bytes: duplicated, and what binds the copies

**RULING 6. Yes, duplicated as hex, and it is forced. The vector copy is
authoritative; `testdata/anchors/` is provenance. The binding is a committed
generator plus a self-binding digest inside the frozen document — not a standing
equality test.**

### 7.1 Duplication is forced, and `anchor` is the first kind where it is

Both existing precedents avoid embedding, deliberately, and neither route is
open here:

- `report` **names** its bundle by shape handle because R6's constructor is
  `test-vectors`-gated so *"the wasm32 lane can build bundles in-process"*
  (`vectors_report.rs:29-36`), and pins `bundle_sha256` to prove both lanes
  built identical bytes.
- `storage-address` **generates** its inputs from a documented pattern because
  literal bytes *"would otherwise put ~25 MiB of hex into a committed file and
  blow D87's budget"* (`vectors_storage_address.rs:24-27`).

A real FreeTSA ECDSA P-384 token has no in-process constructor and no generating
pattern. So `anchor` is **the first kind whose inputs are irreducibly literal
foreign bytes**, and the wasm32 side has no filesystem
(`wasm-bitmatch/build.rs:3-4`) — a path reference is not a candidate. Hex, in
the vector file.

Two consequences worth recording before someone rediscovers them: the review
surface of an `anchor` vector is genuinely opaque in a way no existing vector is
(the `description` field and `provenance` keys carry the whole burden of
reviewability), and the vector file becomes the **only frozen copy** of these
artifact bytes in the tree.

### 7.2 What binds the copies

Three links, of which only the middle one is new:

```
CAPTURE.log sha256=…        →   testdata/anchors/<file>   →   vector artifact_hex
  (recorded at fetch time)        (unfrozen archive)           (FROZEN.sha256)
```

- **Right link, self-binding, inside the frozen file:** `expect.cases[].artifact_sha256`
  and `artifact_len`, recomputed by the executor from `inputs.artifact_hex`.
  Truncated, extended, or edited hex fails the value compare on the same run
  that would have produced a wrong verdict. This is `report`'s `bundle_sha256`
  discipline — *"so an upstream change to what a shape means is a loud vector
  event and never a silent input swap"* (`vectors_report.rs:18`).
- **Left link, already committed:** `testdata/anchors/A25-bootstrap/CAPTURE.log`
  records `bytes=` and `sha256=` per response at fetch time, as does
  `A25-upgrade-headers/CAPTURE.log`. **Gap:** `D60-CAPTURE.log` — the TSA half —
  records the request form, the tool versions and the clock offset, but **no
  per-file digest**. The generator (§7.3) computes and records them, closing the
  left link for the two tokens A22 actually quotes.
- **Middle link, at generation only:** the generator reads the archive file,
  emits the hex, and the emitted vector is reviewed against the diff. Once.

### 7.3 The generator, and why it replaces the standing binding test

**RULING 6a.** Commit `testdata/vectors/v1/anchor/gen_vectors.py` beside the
vector — the README's own instruction (`:211-213`, *"commit the generator as
`*.py` beside the vectors"*). It reads the named `testdata/anchors/` paths,
emits `inputs`, prints each artifact's SHA-256 and byte count for the commit
message, and emits **no `expect` values**: unlike C16 or S4 there is no
independent reference implementation of RFC 3161 chain validation to cross-check
against, and a Python script that reimplements the Rust evaluator would pin the
same bug twice. `expect` comes from the Rust executor's own `build_expect` and
is reviewed against the artifacts' known provenance.

**RULING 6b. No standing archive-equality test.** The recon's "binding test"
would assert `sha256(testdata/anchors/<path>) == expect.artifact_sha256` on
every CI run. Refused:

1. It compares a **frozen** file against an **unfrozen** one. On divergence the
   vector is right by construction — it is the one under `FROZEN.sha256` — so
   the test's red can only ever mean "the archive moved", and the only legal fix
   is on the archive side. A lane whose failure the frozen side is forbidden to
   fix is a lane that teaches people to edit the archive to make CI green.
2. `testdata/anchors/` has no retention rule (§1.1). Nothing forbids deleting a
   capture. The test converts a legal archive action into a red required lane.
3. The risk it addresses — transcription error at landing — is a **one-time**
   risk, and the correct instrument for a one-time risk is the generator that
   made the file, not a check that runs forever.

What survives instead: `provenance` inside `inputs` (§3.5) naming the archive
path verbatim, the generator's recorded digests in the landing commit message,
and — **RULING 6c** — a retention sentence added to
`testdata/anchors/README.md`: *"Captures quoted by a frozen golden vector
(`testdata/vectors/v1/anchor/`) are retained: the vector is the authoritative
copy and is frozen, and this directory is its provenance of record. Deleting a
quoted capture does not break CI; it breaks the audit trail, which is worse
because it is silent."*

### 7.4 The D60 clock trap, so A22 does not lose a day to it

`D60-CAPTURE.log:17-27` records that the capture host's clock ran **129 s slow**,
measured against three unrelated hosts within one second of each other, and warns
in place: *"The `genTime` values inside the tokens come from the TSAs and are
~129 s AHEAD of them. An implementer writing the obvious `gen_time <= fetch_date`
sanity check would reject every token in this directory."*

`inputs.cases[].fetch_date_unix` is a required `TsaArtifactView::from_parts`
argument (`model.rs:194-207`) and A22 must choose values. Take them from the
`utc=` fields in `D60-CAPTURE.log`, record in the vector's `description` that
they are ~129 s **behind** the tokens' `genTime` and that this is measured
rather than a fixture artefact, and choose `verify_at_unix` comfortably after
both. A vector that quietly "fixes" the skew by inventing a later `fetch_date`
has destroyed the one committed artifact in the tree that demonstrates the
inequality does not hold in reality.

---

## 8. Kill criteria

Home B dies, and A22 falls back to unfrozen fixtures under `testdata/anchors/`
with the exit criterion explicitly unmet, if any of these holds. Each is
checkable **before** writing the executor; A22's first hour is checking them.

| # | Criterion | Status |
| --- | --- | --- |
| **K1** | The `anchor` executor cannot compile under `test-vectors` alone — some needed API is `test-util`-gated or requires an injected store | **Clear.** All of `evaluate_ots_artifact`, `evaluate_tsa_artifact`, `OtsArtifactView::from_parts`, `TsaArtifactView::from_parts`, `OtsUpgrade::new`, `OnlineEvidence`, `BlockEvidence`, `TsaRootStore::pinned` are public and ungated. Verify by building `wasm-bitmatch` first, before any vector exists |
| **K2** | The anchor stack fails `wasm32-unknown-unknown` (A-OD6) | **Clear as recorded, re-measure at start.** The seven D60 crates (`cms`, `const-oid`, `der`, `p384`, `rsa`, `sha1`, `x509-cert`) are declared *"RNG-free and `no_std`-shaped … +27 packages, zero new duplicate pairs, zero getrandom/rand, wasm32 green"* (`antseal-core/Cargo.toml:64-71`). This is A22 Accept row 3's own precondition; measuring it is not optional |
| **K3** | D87's 2 MiB per-version embedded-bytes ceiling breached | **Clear, measured.** v1 is at **635 562 B / 30.31 %**; headroom **1 461 590 B**. A22's need: ~27 KB of hex + envelope ≈ **35 KB**, ~1.7 % of the ceiling. See §8.3 |
| **K4** | No non-empty set of `expect` fields is invariant under every legal future change | **Clear.** §3.5's set is non-empty and is exactly A22's `Do` list. Had it been empty, the vector would pin nothing worth freezing and Home B would be a trap |
| **K5** | The generator cannot reproduce the committed vector bit-for-bit from the archive | **Gate, not a prediction.** If it cannot, the vector is unprovenanced — do not freeze it |
| **K6** | `#! kind anchor` cannot be appended to a frozen manifest | **Clear.** `--update` under `status frozen` requires every *existing* line to survive; a new `#! kind` comment and new digest lines are additions (`vector-freeze.sh:257-278`). S4 executed it on 2026-08-01 |

Not kill criteria, and named so they are not mistaken for some: A72 resolving
(handled by §3.3), an A26 append (§4), an A26 removal (§4.3 — it kills the
*immutability*, not the home).

### 8.3 The budget figure in the README is stale

`testdata/vectors/README.md` states *"Today `v1` uses 590 280 B, 28.15 % of its
budget."* Measured 2026-08-07: **635 562 B, 30.31 %**. Off by 45 282 B and 2.16
points. Harmless in itself and exactly Q110's target class — a number in prose
with nothing binding it to the thing it counts. A22 updates it in the same
commit that adds to it; whether it should be *generated* rather than typed
belongs to Q110, not here.

---

## 9. Ruling 7 — the smallest honest unit this wave

**RULING 7.** The wave-9 unit is the kind plus **five** cases over **four**
recorded artifacts. All five are offline at verification time; four need nothing
that is not already committed.

| # | case | artifact | inputs | `expect.state` | needs |
| --- | --- | --- | --- | --- | --- |
| 1 | FreeTSA ECDSA P-384 | `A25-bootstrap/D60-tsa-freetsa-resp.tsr` (4 643 B) | fixed `verify_at`, no online | `proven`, `[H]` | committed since 2026-08-02 |
| 2 | DigiCert RSA | `A25-bootstrap/D60-tsa-digicert-resp.tsr` (6 007 B) | as above | `proven`, `[H]` | committed since 2026-08-02 |
| 3 | pending `.ots` | `A25-bootstrap/merged-A.ots` (664 B) | no upgrade, no online | `pending`, not `[H]` | committed since 2026-08-02 |
| 4 | upgraded `.ots`, offline | the merged+upgraded `.ots` over digest A (`upgraded/A-*.upgrade`, ~1 000–1 105 B each) | `upgrade` present, **empty** `OnlineEvidence` | `attested`, not `[H]`, `identity_kind: null` | committed since 2026-08-03 |
| 5 | upgraded `.ots`, online | **the same bytes as 4** | `upgrade` present, `OnlineEvidence::with_block(960767, Header(…))` | `proven`, `[H]`, `identity_kind: "bitcoin-chain"` | the 80-byte header |

This covers A22's `Do` verbatim — *"real recorded FreeTSA (ECDSA P-384) and
DigiCert (RSA) tokens, a pending `.ots`, and an upgraded `.ots` with embedded
header"* — and adds case 5, which is the pair D92 says is missing (§3.3).

### 9.1 The header dependency is a commit, not a fetch

§1.6: `testdata/anchors/A25-upgrade-headers/` is on disk with all three heights
from both endpoints, byte-identical across endpoints and each verified offline by
double-SHA256 against its height lookup. It is **untracked**. A22 depends on that
capture being committed — which is A25's to land, with its consent record intact.

Note the shape of the dependency: cases 4 and 5 are the **same artifact bytes**,
differing only in the `online` input. Case 5 costs one extra `expect` case and
160 hex characters. It is the cheapest case in the set and the most valuable.

### 9.2 If the headers do not land

Ship cases 1–4. That is three of the four artifact classes A22's `Do` names,
both TSA algorithms, both offline OTS states, and the freeze/retention/wasm
wiring in full. Case 5 appends later — **an append to a frozen manifest is legal
forever** (§5), which is precisely the property Home B buys and the reason
partial landing is honest here rather than a deferral that rots. Record the
deferral as a `#! pending` line? **No** — `status frozen` requires the pending
set to be empty (`FROZEN.sha256:41-44`, Q14's gate condition). Record it in
A22's entry and in the vector's own `description`.

### 9.3 What waits, and on what

| item | waits on |
| --- | --- |
| `identity` **payload** (`subject_dn_der`) in `expect` | **A72** resolving the two TSA identity notions (§3.3) |
| extending `verdict_event_ok` to `anchor/` | the first of §4.3's three events actually being proposed |
| untrusted-root, mock-CA, two-store cases | nothing — they are permanently A21's, in-module (§6) |
| `root_store_version` in a frozen vector | permanently. It lives in `chain.rs:2095-2114` (§3.1) |
| aggregate verdicts, headline selection, >48 h divergence | **R17**, M3. A different pin with a different owner |

---

## 10. Consequences — the exact edit set

| file | edit | §|
| --- | --- | --- |
| `tasks/A.md` A22 Accept | replaced by four uncompounded rows naming the `anchor` kind and freeze | 2.3 |
| `tasks/A.md` A26 Accept row 2 + `Do` | names the discharging test; adds the append-commit vector-lane line | 4.4, 4.2 |
| `tasks/Q.md:1373`, `TODO.md:529`, `D94:554-555` | "four Accept rows" → "three", or drop the count | 2.2 |
| `testdata/vectors/README.md:418` | append path, with the former wording quoted | 5.1 |
| `testdata/vectors/README.md:205-207` | the `anchor` kind row gains its `inputs`/`expect` shape, matching the sibling rows | 3.5 |
| `testdata/vectors/README.md` budget sentence | 590 280 B / 28.15 % → measured value | 8.3 |
| `testdata/anchors/README.md` | retention sentence for quoted captures | 7.3 |
| `testdata/vectors/v1/FROZEN.sha256` | `#! kind anchor A22` + digest lines + the §4.3c prose paragraph | 4.3, 5 |
| `crates/antseal-core/src/test_util/vectors.rs` | `KNOWN_KINDS` entry + dispatch arm | 1.2 |
| `crates/antseal-core/src/test_util/vectors_anchor.rs` | new, ~215 lines, `vectors_storage_address.rs` shape | 1.2 |
| `testdata/vectors/v1/anchor/anchor.json`, `gen_vectors.py` | the vector and its generator | 7.3 |
| `testdata/vectors/v1/INDEX.json` | roster entry | 1.2 |

Zero wire bytes. Zero format-version bumps. Zero moved digests. Zero new error
codes. No existing vector is touched.

---

## 11. What this record does not decide

- **Whether A72 moves the core-side or seal-side TSA identity.** §3.3 makes A22
  independent of the answer; it does not supply one.
- **The anchor-shaped `verdict_event_ok` predicate.** §4.3 specifies what it
  would check and rules that it is not built now.
- **Whether `testdata/anchors/` should gain a freeze of its own.** §7.3 adds a
  retention sentence, not a mechanism. If the archive ever needs one it is a Q
  question about capture areas, not an A22 question about vectors.
- **R17's aggregate pins.** M3.
- **Whether the README's budget figure should be generated.** Q110.
