# D8 — Complete v1 wire registry: the sign-off

- **Status: RESOLVED — the registry is signed off with **four substantive
  changes** to the draft, **five ratifications**, and **eleven corrections**
  of stale or contradictory text. Two of the four open §13 items are
  resolved by *removing* wire surface, not by confirming it: the TSA
  `source` string leaves v1 (its only stated consumer, the report pipeline,
  has already refused it in writing), and the recorded `anchor_status`
  subset is ruled to be **no subset at all** (any narrowing would be a parse
  rule keyed on a field the design forbids trusting — D79's principle,
  generalised from presence to value). A third, the receipt's
  `block_number`, is **under-determined as drafted** under the multi-tx
  payment path S1 verified, and is given a total definition. The fourth,
  `title`/`app_version` optionality, confirms the draft's shape on entirely
  different grounds — the draft's stated reason is wrong, because the
  alternative it rejects is *also* single-encoding.**
- **Date: 2026-07-28**
- **Owning task: F4** (registry doc + JSON mirror). Consumed by **F8**
  (two schema edits), **Q14** (freeze gate), **A18/R12** (M2 anchor stage),
  **S7** (receipt capture), **R41-class** report-model doc fix.
- Gate: **Q14**. Everything below is permanent from the `format-v1-freeze`
  tag (MVP-SPEC.md line 123).

---

## 0. How to read this record

Fourteen numbered questions, in the order the brief poses them. Each ends
with an explicit **RESOLVED** line. §15 is the impact table (every registry
section that moves). §16 is the executable checklist for F4. §17 is the
list of errors, staleness and contradictions found in the existing records —
eleven of them, in the registry draft, in three decision records, in the
JSON mirror, in `TODO.md` and in code doc comments.

Two conventions used throughout:

- **Format-permanent** means: fixed at the Q14 tag, changeable afterwards
  only by a format-version event. **Movable** means: a later release may
  change it without a version bump.
- **Direction.** Line 123 promises every released format version stays
  verifiable forever. So a *later* release may **relax** a v1 rule (a
  bundle that used to be rejected starts being accepted) but may never
  **tighten** one (a bundle that used to be accepted starts being
  rejected). Where the evidence is thin, this record takes the strict or
  the absent option, because those are the ones that can still move.

Every factual claim about the tree was checked against HEAD `5f794ff`.
Claims that could not be checked are marked **[unverified]** rather than
repeated from the draft.

---

## 1. §13.1 — TSA source identity (§7.9 key 4)

### The draft's position

> **TSA source identity** (§7.9 key 4): the report model
> (`crates/antseal-core/src/verify/report.rs`, `AnchorResult::source`)
> expects a bundle-recorded source identity, but lines 112–114 do not list
> one. Proposed: optional informational `tstr` on TSA artifacts only […]
> — `docs/format/registry-v1.md:1310-1315`

The premise is that the report model *expects* the field. **That premise is
false at HEAD**, and it was falsified by the landed pipeline, not by this
record.

### Evidence

**1. The one named consumer has refused the field, in writing, in code.**
`crates/antseal-core/src/verify/pipeline.rs:72-76`:

```text
//!   plugs in at M2 through R12. No artifact byte is parsed here, and no
//!   bundle-recorded anchor metadata is copied into the report: a TSA
//!   `source` string is explicitly "never verdict-bearing"
//!   ([`TsaAnchor::source`]), and rendering a `fetch_date` would require
//!   choosing a date format — a format-permanent decision R12/A18 owns.
```

`anchor_stubs` (`verify/pipeline.rs:879`) hardcodes `source: None`. The only
non-`None` values anywhere are report-model test fixtures
(`verify/mod.rs:130,137,144,151,158,165,172`), which are hand-built and do
not read a bundle. **The wire field has zero producers and zero consumers.**

**2. The registry's own accessor doc says where the real identity comes
from.** `crates/antseal-core/src/bundle/schema.rs:616-618`:

```text
    /// **Never verdict-bearing**: the source identity a verdict reports comes
    /// from the verified certificate chain, not from this string.
```

MVP-SPEC.md line 109 is the source of that rule: the chain is "validated to
a **pinned TSA root store compiled into `antseal-core`**". A `proven` or
`valid-at-stamping` TSA anchor therefore already carries a *verified*
identity. An `internally-consistent-only` or `invalid` one carries an
*unverified* identity — from its own certificate, which is exactly as
trustworthy as the `source` string and strictly more structured.

**3. It is the only rendered string in v1 that is neither signed nor
committed.** Enumerating every `tstr` in the format:

| field | where | bound by |
| --- | --- | --- |
| `title`, `app_version`, `unicode_version` | manifest body §7.2/§7.4 | the body signature + `work_id` + `anchor_digest` |
| `path` | bundle §7.13 key 1 | `path_commit = SHA-256(0x05 ‖ path_salt ‖ path_utf8)` (line 95) |
| **`source`** | bundle §7.9 key 4 | **nothing** |

The bundle is unsigned by design (§7.6.1). So `source` is free text that any
relay — not merely the sealer — can rewrite undetectably, and that a page is
invited to render beside a verdict whose headline format is literally
"Existed no later than \<time\> **(source)**" (line 137).

**4. It has no spec line.** §12 maps every wire field to MVP-SPEC.md lines
74–75, 98, 112–114, 91, 110, 121, 161. §7.9 key 4 appears in **no** §12 row —
it is the only assigned key in v1 with no spec basis at all. Line 112's
enumeration for a TSA artifact is "TSA tokens + intermediate certs, fetch
dates". Nothing more.

**5. It is a fifth instance of the family §7.6.1 already excludes.** The four
checked absences are: a bundle-side nonce (a second sealer-controlled AEAD
input the verifier could be steered onto), a bundle signature (invites
trusting the assembler), a stored `work_id`/`anchor_digest`/`seal_id` (a
second authority), a reveal-shape discriminant (sealer-forgeable). Each is
excluded for the same reason: *do not carry a sealer's claim next to the
thing it claims about*. A provenance string beside an anchor artifact is
that pattern exactly.

### Why the draft's own argument does not survive

The draft's reason is: "the `.ots` is self-describing — calendar URLs live
inside its attestations; the TSA URL is not reliably recoverable from the
token." True, and irrelevant: what a verdict needs is the TSA's **identity**,
which the certificate carries, not the **submission URL**, which nothing
verifies and nothing consumes. The asymmetry the draft observed is real; the
conclusion it drew from it is not.

### Decision

**Remove `source` from v1.** `tsa_anchor` key 4 becomes **plain reserved**;
the map's band widens from `5..=23` to `4..=23`.

Not a *named* reserved slot: §9's named slots mean "a committed v1.1 item"
(`range_reveals`, `chain_inputs`), and a TSA source string is not committed
to anything. The option is preserved by the band, not by a name — assigning
key 4 in a later v1.x release is the ordinary additive path (§9) and needs
only a recorded format decision.

The absence is **checked**, not merely omitted: `tsa_anchor` key 4 present in
v1 input raises F10's existing reserved-slot error, and
`no_bundle_map_grows_a_deliberately_absent_field`
(`tests/format_registry_draft.rs:630-700`) gains `source` to its banned-name
list for `tsa_anchor`. No new error code is minted.

### Consequence for M2's A-domain — stated explicitly, as the brief requires

`AnchorResult::source` **stays** in the report model. It is a field of a
*separate, non-wire* format (D27/D29), and this decision does not touch it.
What changes is where M2 fills it from:

- **TSA anchors.** From the **verified certificate chain** — the signer
  certificate's subject / the ESSCertID-bound identity, evaluated against the
  pinned root store (line 109). For a `proven` or
  `valid-at-stamping-cert-since-expired` anchor this is a verified identity.
  For `internally-consistent-only` or `invalid` it is a *claimed* identity
  read from the same token and MUST render as such — the state already says
  the chain did not close, so the rendering discipline is inherited rather
  than invented.
- **OTS anchors.** From the `.ots` attestations, which name their calendars
  (the draft's own observation). Note that at HEAD the report model already
  allows `source` on `AnchorKind::Ots` while the wire never had an OTS
  `source` key — so for OTS nothing changes at all.
- **A18/R12 own the wording**; this record fixes only that the string is
  derived from artifact content the verifier has itself parsed, never copied
  from a bundle field.
- **`verify/report.rs:293-295`'s doc comment is wrong after this decision.**
  It reads "as recorded in the bundle artifact". It must read that the
  identity is derived from the verified chain / attestation. See §17 item 8.

### Cost, stated honestly

Deleting a landed field is not free. The blast radius, measured:
`bundle/registry.rs:173` (the `SOURCE` const and `RESERVED_FIRST` 5→4);
`bundle/schema.rs` (struct field :564, constructor :575, accessor :621-623,
decode arm :645, encode arm :1900); `test_util/bundle_fixtures.rs`
(:287, :294, :304, :1445); `testdata/vectors/v1/bundle/bundle.json` (6
occurrences) and `testdata/vectors/v1/bundle/README.md:61`;
`testdata/vectors/v1/FROZEN.sha256`; §11's recorded-non-caps list; §1's
`tstr` row. One vector file re-emits through the established
`scripts/vector-freeze.sh --update` path. **No report vector moves** — the
report model is untouched. **No error code moves** — the rejection is the
existing reserved-slot error.

That cost is the price of not freezing an unbindable, unconsumed, rendered
string into a format that must be verifiable forever. It is paid once, now,
at the only moment it is payable.

> **RESOLVED 2026-07-28 — §13.1: NO. `source` is removed from v1;
> `tsa_anchor` key 4 becomes plain reserved (band `4..=23`) and its absence
> is asserted. The report's `AnchorResult::source` is retained and, at M2,
> is derived from the verified certificate chain (TSA) or the `.ots`
> attestations (OTS) — never copied from a bundle field.**

---

## 2. §13.3 — `title` / `app_version` optionality (§7.2 keys 1 and 3)

### The two shapes, and why the draft's argument does not separate them

The draft proposes "required-may-be-empty `tstr` (one shape; no
absent-vs-empty split)" and offers the canonicality argument as the reason.
**That argument does not distinguish the options**, and this is the correction
the brief asks for. Both shapes can be made single-encoding:

- **(A) `req`, may be empty.** "no title" ⇒ `""`. One encoding per logical
  value. ✓
- **(B) `opt`, and non-empty when present.** "no title" ⇒ key absent;
  otherwise a non-empty `tstr`. Also one encoding per logical value. ✓

(B) is single-encoding only *with* the non-empty rule; without it, `""` and
absence would both mean "no title" and a sealer could pick — which is the
hazard the brief names, and it is a hazard of a *badly specified* (B), not of
(B) as such. The draft's §7.2 key 3 cell ("may be empty (no `--title` ⇒
`""` — one shape, §13 item 3)") therefore states a true fact about (A) while
implying a false contrast with (B).

### What actually separates them

**1. `app_version` has no absent state to model.** A manifest always has a
producing build; the version string always exists. Under (B), `app_version`
would be `opt` with a rule that makes absence illegal in practice — modelling
a state that cannot occur — or the two adjacent free-form `tstr`s of §7.2
would take *different* shapes, forking one decode pattern into two for the
sake of one of them.

**2. (B) costs permanent error codes; (A) costs none.** Under D30 every
rejection class is a permanent code
(`docs/testing/error-code-contract.md` §3). (B) needs `present ⇒ non-empty`
on one or both fields — one or two codes, forever, to save two bytes on a
manifest whose caps are measured in mebibytes.

**3. (A) is the rule the bundle already adopted, so the two artifacts share
one principle.** §7.6: "Required-may-be-empty everywhere avoids the
absent-vs-empty encoding split that would give one logical bundle two byte
encodings." Making the manifest body follow a different principle would be
gratuitous.

**4. Privacy is neutral between them.** A `title` is user text sitting in a
**plaintext** manifest that is embedded in **every** bundle, so every bundle
recipient reads it whether or not the file it names is revealed. (The
*uploaded* copy is encrypted — line 98 — so the network never sees it.) Key
presence and a non-empty value are equally informative, so (A) and (B) leak
the same thing. What matters is not the shape but that the leak is recorded:
`title` is a disclosure to every recipient, which the registry does not
currently say and must.

### Decision

**(A) — `req`, may be empty, for both keys.** The draft's shape is confirmed;
its reason is replaced by grounds 1–3 above.

Two consequences that must be written down, because they are not currently
anywhere and both are format-permanent:

- **The empty string is legal for both fields, and no non-empty check may
  ever be added.** Adding one would reject a bundle a released verifier
  accepted — the illegal direction under line 123. HEAD already behaves this
  way (`manifest/body.rs:1183-1190` decodes both with a bare `d.str()`; no
  length, charset or emptiness validation exists anywhere), so this freezes
  the status quo rather than changing it.
- **Neither field is ever verdict-bearing**, and `title` in particular is a
  disclosure to every bundle recipient. §7.2's rows must say both.

> **RESOLVED 2026-07-28 — §13.3: required-may-be-empty `tstr`, for BOTH
> `title` and `app_version`. Confirmed on new grounds (the alternative is
> equally canonical, so canonicality does not decide it): `app_version` has
> no absent state, the alternative costs permanent D30 codes to save two
> bytes, and (A) matches the rule §7.6 already adopted for the bundle. The
> empty string is legal for both and a non-empty check is permanently
> foreclosed.**

---

## 3. §13.4 — Receipt record internal split (§7.10)

### Two separate questions were bundled here; they resolve differently

The draft asks A/S to "confirm this envelope carries the full S1-surveyed
capture (quote preimages + `proof_bytes`) for the v1.1 chain". That is a
*completeness* question. But the drafted envelope also has a *totality*
defect that the draft did not notice. Taking them in the order that matters:

### 3a. The completeness question is not a Q14 question at all

This is the D84-shaped half. §7.10 key 2 already says the payload is
"**Opaque to this registry**: its internal layout is A/S's and is *not* a v1
wire format, so changing it is not a format-version event". That sentence,
taken seriously, **discharges the completeness obligation without answering
it**: because the payload is outside the registry, S6/S7 can extend, restructure
or replace the capture at any time — before M1, at M1, at M2, after M2 —
without a format event and without a reseal.

So the question "does the payload carry everything the v1.1 chain needs?"
does not have to be answered by Q14, and cannot be answered well today:
nobody has executed S6/S7 against a real payment. The parking-lot obligation
(line 110: "capture is complete from day one, so no reseal will ever be
needed") binds **S7's vault capture**, not this registry — and the vault, not
the bundle, is what a reseal would be needed to rebuild from.

**The structural rule that DOES freeze**, stated so Q14 has something to
tick:

> **The receipt's `payload` (§7.10 key 2) is an opaque `bstr` whose internal
> layout is not v1 wire format. Its contents may change in any release
> without a format-version event. Nothing in a v1 verdict may depend on its
> internal structure; the MVP verdict is "supporting evidence — no
> independently proven time" (line 110) and no reserved slot can promote it.
> The completeness of the capture is an **S-domain obligation (S7)** with no
> freeze deadline; anything v1.1 must read in a version-stable,
> cross-implementation way is promoted out of the payload into reserved key
> 3 (`chain_inputs`), which is what that slot exists for.**

This is exactly D84's move — freeze the placement and the failure shape, let
the domain that will hold the evidence choose the contents.

### 3b. `block_number` as drafted is under-determined — and that IS a Q14 question

§7.10 key 1 reads:

> | 1 | `block_number` | uint | req | the payment's Arbitrum One block number |

`docs/research/S1-ant-core-api-survey.md` §12 verified against upstream
source that a payment is **not one transaction**:

> | `pay_for_quotes` (wave/single; what `batch_pay` and the external intent
> hit) | **256 transfers** (`MAX_TRANSFERS_PER_TRANSACTION`,
> payment_vault/mod.rs:11) ⇒ 256 chunks […] | auto-chunked; one `TxHash` per
> sub-batch […] |
> | ant-core wave driver (`batch_upload_chunks*`) | 64 chunks per wave
> (`PAYMENT_WAVE_SIZE`, batch.rs:30) ⇒ one tx per wave |
>
> ⇒ `PaymentReceipt` must hold `Vec<TxHash>`

and §8:

> the spec's "one `eth_getTransactionReceipt`" (**one per tx hash**) is
> confirmed as both sufficient and necessary.

So a normal seal produces several transactions, each with its **own** block
number, and "the payment's block number" names nothing. The draft got
`tx_hashes` right (plural, S1-confirmed) and then paired it with a singular
field that cannot be filled without an arbitrary choice. Two honest
implementations — the CLI and any third-party sealer — would pick
differently, and the same logical seal would produce different bytes. That is
the divergence MVP-SPEC.md line 73 exists to prevent, arriving through a
field nobody thought was load-bearing.

Note also that MVP-SPEC.md line 66's own parenthetical, "block number (one
`eth_getTransactionReceipt`)", is the imprecision the registry inherited;
S1 §8 is the verified correction. **This is a spec-vs-research disagreement
and the research wins** — flagged per the brief's instruction to surface
spec conflicts.

### The options

- **(i) Per-tx pairs** — key 0 becomes `payments`, an array of
  `[tx_hash, block_number]` 2-tuples. Total; the illegal state (a hash
  without its block, a length mismatch) is unrepresentable, which is the
  principle §4 and §7.6.2 both invoke. Costs a renumber, a new tuple type,
  an F8 schema change and a vector re-emit — for a field with no verdict
  role.
- **(ii) Parallel arrays** — key 1 becomes `block_numbers`, equal length,
  checked. Same information as (i) but the illegal state is representable
  and needs a permanent D30 code. Strictly worse than (i).
- **(iii) Remove key 1** — leave block numbers to the opaque payload. Total
  by construction, and the most reversible option (a later v1.x release
  assigns a reserved key additively). Costs a renumber and loses a
  user-visible datum that §7.10's own rationale calls for.
- **(iv) Define key 1 totally** — keep the `uint`, and specify *which* block
  it is.

### Decision

**(iv), with the definition fixed as the earliest.** Key 1 stays a `uint`
and reads:

> the Arbitrum One block number of the **earliest-confirmed** transaction in
> key 0 — i.e. the minimum block number over the receipt's transactions. A
> payment may span several transactions (S1 §12: ≤ 256 transfers per tx, one
> `TxHash` per sub-batch), each confirmed in its own block; "the payment's
> block" is therefore defined, not observed. Display-only: unverified in v1,
> never verdict-bearing, and re-derivable from any transaction hash over RPC.
> A per-transaction structure, if a consumer ever needs one, takes a reserved
> key additively — it must then be **per tx**, never a second scalar.

Why (iv) over (i) and (iii), given the brief's preference for the reversible
direction:

1. **Reversibility is not the binding constraint here, because the datum is
   not evidence.** Line 110 forecloses it permanently: "no on-chain datum
   contains `anchor_digest`", so the receipt can never yield a proven time,
   and §7.10 already records that "no reserved slot can promote it". A field
   that can never bear a verdict cannot become a liability by existing.
2. **(i) buys structure for a display field**, and buys it with a renumber, a
   new frozen tuple arity, an F8 change and a vector re-emit — at a freeze
   gate, on the evidence-thinnest surface in the registry. §9 already warns
   that "Reserving is *not* designing"; adding structure is even further from
   it.
3. **(iii) removes a datum §7.10's own rationale names** as one of "the two
   user-visible 'supporting evidence' data", and hides it in the one place
   the WASM page cannot read (the opaque payload) — contradicting the reason
   keys 0–1 are registry-visible at all.
4. **(iv) fixes the actual defect** — under-determination — at the cost of
   one sentence and zero code, and leaves (i) available as a v1.x addition if
   S6/S7 ever produce a consumer.

`tx_hashes` (key 0) is **confirmed** as drafted: `bstr(32)` Keccak-256
elements, non-empty, capture order, capped by `MAX_TX_HASH_COUNT = 256`
(D10 row 9). S1 §12 is the evidence, and the draft read it correctly.

**One more thing the receipt must NOT carry, recorded as a checked absence.**
There is no chain identifier, and there must never be one. A sealer-written
`chain_id` would *steer the verifier's RPC choice* — the same hazard as a
bundle-side nonce (§7.6.1) or a bundle-supplied trust root (line 109:
"bundle-embedded chains supply intermediates only"). The chain is pinned by
the verifier (line 137: "two public Arbitrum RPCs", user-overridable), never
named by the artifact under inspection. A receipt captured on Sepolia or a
devnet therefore simply fails to resolve against Arbitrum One at v1.1 —
which is the correct outcome, and a stronger one than trusting the bundle to
admit it.

> **RESOLVED 2026-07-28 — §13.4: the split `{tx_hashes, block_number,
> payload}` is CONFIRMED, with key 1 given a total definition (the minimum
> block number over key 0's transactions) because the drafted wording is
> under-determined under S1's verified multi-transaction payment path. The
> completeness question is SCOPED OUT of the v1 freeze in D84's manner: the
> payload is opaque and not v1 wire format, so its contents may change in any
> release without a format event, and capture completeness is S7's obligation
> with no freeze deadline. A chain identifier is a checked absence.**

---

## 4. §13.5 — Recorded `anchor_status`, OTS `fetch_date`, anchor list order

Three sub-questions with one common thread: each asks the format to encode a
judgement that only the M2 anchor stage can make. All three resolve by
freezing the *structure* and refusing to freeze the *judgement*.

### 4a. Which of the seven states are legal *as recorded*, per kind

**Answer: all seven, for both kinds. There is no per-kind subset, in v1 or
ever.**

The draft expected otherwise — §6.1 says an `absent` artifact entry is
"self-contradictory; expected to be rejected by that semantic rule". Three
reasons that expectation is wrong:

1. **It is D79's rule, one level down.** D79 (ratified 2026-07-28) fixed that
   the OTS upgrade group's *presence* may not be conditioned on `status`,
   "because `status` is sealer-written and the design says a verifier must
   not trust it; conditioning parse on it would let a sealer choose which
   shapes decode". A per-kind legal-value subset is the same construction
   applied to the field itself: it makes *decodability* depend on a value
   whose whole design property is that it is not depended upon. D79 decided
   the principle; this is only its second application.
2. **It puts a sealer's lie in the wrong error family.** `docs/testing/error-code-contract.md`
   §2 and D78 make the split normative: a `bundle-` code means "malformed on
   the bundle's own bytes", and "a bundle that is *well-formed but
   inconsistent with its manifest* […] is a verify-pipeline outcome". A
   sealer writing `proven` on a pending OTS is lying, not malforming. Under a
   subset rule that lie becomes a **schema** rejection, and D30 makes the
   family permanent.
3. **The evidence to choose a subset does not exist.** Which states a sealer
   can legitimately observe at capture time is A-domain semantics, decided at
   M2 against A25's real artifacts. D84 §2 already established that no
   released verdict depends on artifact internals before M2 (M0/M1 render
   every anchor `absent`), so nothing is lost by deciding it later — and a
   subset frozen now against zero artifacts could only be relaxed later, which
   would make M2-produced bundles fail in M0/M1-era verifiers.

**What freezes instead — the non-consumption rule.** This is the structural
statement Q14 ticks:

> `anchor_status` (§7.8 key 0, §7.9 key 0) is the sealer's **capture-time
> record**. Its wire domain is the seven registered values `0..=6`; `7..=15`
> are reserved and rejected (§6.1). Within `0..=6` **every value is legal on
> every artifact of either kind**, including `absent`, which is representable
> and meaningless rather than illegal. **No v1 parse rule and no v1 verdict
> may read it.** A verifier derives its own per-anchor state (line 121,
> sealer-as-adversary) and MAY display the recorded value only as a
> sealer-asserted claim, with the discipline MVP-SPEC.md line 137 already
> prescribes for `claimed_time` — "asserted by sealer — NOT verified", never
> entering the headline.

That last clause matters: it gives the field a defined, harmless role rather
than leaving it as decoration nobody can explain, and it borrows a rendering
rule the spec already wrote instead of inventing one.

### 4b. What the capture date means, exactly

Both fields are `uint` POSIX seconds UTC (§3). Definitions, normative:

- **§7.9 key 3 (TSA), `req`** — the instant the sealer **received the
  `TimeStampResp`** from the TSA. It is **not** the token's `genTime`:
  `genTime` is inside the DER and is the *provable* time (line 109); this
  field is metadata about the sealer's own clock and network. Required
  because a TSA artifact exists only if a response was received, so the value
  is always known — the asymmetry with §7.8 key 4 that the draft records is
  correct and is confirmed here.
- **§7.8 key 4 (OTS), part of D79's all-or-nothing upgrade group** — the
  instant the sealer **completed the upgrade capture**: obtained the attested
  block height *and* the 80-byte header and wrote them to the journal. It is
  **not** the `.ots` submission time (not carried anywhere), and **not** the
  Bitcoin block timestamp, which lives inside the embedded header and is the
  datum `--online` confirmation promotes to `proven` (line 108). Its
  membership in the upgrade group is what makes this the only coherent
  reading: a not-yet-upgraded anchor has no upgrade to have fetched, which is
  precisely why the field is absent for one.

**Three non-rules, recorded so nobody adds them.** None of the following is a
v1 rule and none may become one after the freeze:

- no ordering relation between `fetch_date` and the header's own timestamp,
  or between it and `claimed_time` (both sides are sealer-authored; the
  relation would be unverifiable and would reject honest bundles whose clock
  drifted);
- no lower or upper bound (zero is a legal `uint`);
- no monotonicity across the anchor list.

**Recorded privacy note.** A `fetch_date` reveals, to the second, when the
sealer was online. For TSA it adds nothing (it is within seconds of the
token's own `genTime`, which ships anyway). For an OTS upgrade it reveals
when the sealer last ran the CLI — activity metadata about the *sealer*,
not about the work. Line 114 lists "fetch dates" as bundle content, so the
field stays; the leak is recorded, not eliminated.

### 4c. Anchor list order

**Confirmed as drafted: capture order, preserved as received, not
parse-checked** (§8). §8's stated reason survives scrutiny — an anchor
artifact has no content-independent sort key (status reorders on
re-verification, `fetch_date` collides, artifact bytes are meaningless) — and
with `source` removed by §1 there is one fewer candidate than the draft had.

Two additions:

1. **Order carries no meaning.** A verifier must not read "first" as
   "primary". The headline is "Existed no later than \<earliest
   headline-eligible time\>" (line 137), computed from **verified** times, never
   from position. Recorded so the M3 page cannot acquire a positional
   convention by accident.
2. **Duplicate artifacts are not rejected, deliberately — and the reason is
   not laziness.** A byte-identical duplicate `.ots` or token in one array is
   legal v1. Rejecting it was considered and declined:
   - it catches only the laziest inflation. A sealer wanting two "independent"
     TSA anchors from one TSA simply requests two tokens — different bytes,
     same TSA, passes any byte-distinctness check;
   - the check it would substitute for is a *verdict*-level one, and belongs
     to A18/R17: **anchor independence must be evaluated from verified
     identities, never from array length**. That check needs no format
     support and can be added at any time;
   - it would put up to 256 × 1 MiB of hashing into verify stage 1, which
     D10 §6 designs to be cheap and to run ahead of every AEAD, hash and
     signature.

   The price is stated plainly: this is the **irreversible** direction —
   permissive now cannot be tightened after the freeze. It is accepted because
   the check that actually matters lives where the evidence is, and putting a
   weaker proxy in the format would create exactly the false assurance the
   real check must not compete with. **Obligation on A18/R17:** derive anchor
   independence from verified identities; do not count entries.

> **RESOLVED 2026-07-28 — §13.5, three parts. (a) All seven `anchor_status`
> values are legal as recorded on both kinds; there is no per-kind subset,
> because any subset is a parse rule keyed on a field D79 forbids depending
> on and would file a sealer's lie under a `bundle-` code. What freezes is the
> non-consumption rule: no v1 parse rule and no v1 verdict reads `status`; a
> verifier may display it only as sealer-asserted, under line 137's
> `claimed_time` discipline. (b) TSA `fetch_date` = the instant the
> `TimeStampResp` was received; OTS `fetch_date` = the instant the upgrade
> capture (height + header) completed. Neither is the provable time; three
> non-rules recorded. (c) Anchor list order = capture order, unchecked,
> meaningless as a position; duplicates are legal, and anchor independence is
> A18/R17's verified-identity check, not an array property.**

---

## 5. §13.2 — Explicit `file_id` in per-file bundle sections

**RATIFIED, on a ground stronger than the four the draft gives.**

§10 argues from lookup cost, distinct tamper errors, sortability and
consistency. All four hold. But the decisive one is missing, and it is
structural rather than preferential:

**Without an explicit `file_id`, the tier-[X] rule `full_reveals ⊆
touched_files` (§7.6) is undecidable at F8.** An [X] rule is decided from the
bundle alone. Associating a `full_reveal` entry to a `touched_file` entry
without a shared id means opening `path_commit` — which needs the manifest —
so the rule would drop to tier [R], which **D78 forbids the bundle schema
layer from reaching for**. The same applies to §8's "strictly ascending
`file_id`" ordering rule on both lists, and to D80's and D82's rules, neither
of which is even expressible without the id.

So the explicit id is not a convenience the draft chose; it is forced by the
tier system the registry adopted in §0 and by the layering D78 ratified.

Code confirms: `touched_file::FILE_ID = 0` and `full_reveal::FILE_ID = 0`
(`bundle/registry.rs:227, 240`), with
`BundleV1::new` enforcing ascent and `FullRevealWithoutTouchedFile`
(`bundle/schema.rs:1445-1506`).

> **RESOLVED 2026-07-28 — §13.2: YES, ratified. §10's four reasons stand; the
> binding one is that D78 + §0's tier system make the id necessary, not merely
> better — `full_reveals ⊆ touched_files` cannot be tier [X] without it.**

---

## 6. §13.7 — `unit_id` stored and checked

**RATIFIED.** Landed and verified at HEAD:
`ManifestBodyV1::new` → `validate_unit_ordinals`
(`manifest/body.rs:1303-1319`) walks files in order, units in order, and
returns `ManifestError::UnitIdMismatch { expected, found }` on the first
divergence; code `"manifest-unit-id-mismatch"` (`manifest/error.rs:810`),
`map()` = `MapId::UnitEntry` (`manifest/error.rs:704`).

The better ground, again structural: **storing the id is spec-mandated**
(line 98 lists `unit_id` in the unit table), and **checking it is what stops
the stored copy from becoming a second authority** — §7.6.1's rule against
carrying a derived value that "could disagree with the bytes it claims to
summarize, creating a 'which one is authoritative' question with no good
answer". Storing without checking would have been exactly that. Storing *and*
checking makes the redundancy free: reveals and `--units` ids are
self-describing, and silent reordering is unrepresentable.

Changing it now would move consumed keys and is not on the table.

> **RESOLVED 2026-07-28 — §13.7: ratified. `unit_id` is stored (line 98) AND
> parse-checked equal to the derived manifest-order ordinal; the check is what
> prevents the stored copy from becoming a second authority.**

---

## 7. §6.2 — `sig_alg`, and closing D17 at Q14

### The numbers freeze exactly as drafted

| value | algorithm | pubkey | signature |
| --- | --- | --- | --- |
| 0 | `ed25519` | 32 B | 64 B |
| 1 | `ml-dsa-65` | 1952 B | 3309 B |
| 2–15 | reserved, unregistered in v1 — any appearance is a parse-time reject |

**The `*pending-D17 confirm*` annotations on §2's 1952/3309 rows are
discharged.** The values are FIPS 204 Table 2 and were verified against the
pinned crate's own source, not from memory:
`docs/research/C11-signature-probe.md:46` — "**1952** / sig **3309** for
ML-DSA-65 (src/lib.rs:262-279)". They are pinned in code at
`crypto/sig_mldsa.rs:91,95` and asserted by
`registry::tests::per_algorithm_lengths_are_frozen` and by
`format_registry_draft::code_scalar_lengths_match_the_registry`. F4 removes
both annotations.

### The duplicated mapping: keep it duplicated, and fix the pin

At HEAD there are **two** mappings:

- **C's**, `crypto/sig_policy.rs:50-75`: `ID_ED25519 = 0`, `ID_MLDSA65 = 1`,
  `FIRST_RESERVED_ID = 2`, `sig_alg_from_id` / `sig_alg_to_id`;
- **F's**, `manifest/registry.rs:442-459`: `sig_alg_from_wire` /
  `sig_alg_to_wire`, whose doc (`:428-440`) names the duplication as a "C14
  seam" and says "If C14 re-homes the mapping to `crypto::sig_policy`, the
  values move unchanged."

They are pinned to each other by `crypto_and_manifest_registries_agree`
(`crypto/sig_policy.rs:345-358`) over ids `0..=20`, and the manifest decoder
and encoder use only F's copy (`manifest/body.rs:1206, 1264`).

**Ruling: duplication stays; the gap that must close is the mirror
cross-check, not the duplication.** Grounds:

1. The registry — this document's §6.2 and the JSON mirror — is the single
   **normative** source of the numbers. How many `match` arms the crate has is
   a code-organisation matter D8 does not own.
2. Re-homing changes no value and is therefore a free refactor at any time,
   before or after Q14. Forcing it now would be churn on a freeze-critical
   file for zero observable effect.
3. **The real defect is that only one copy is checked against the mirror.**
   `format_registry_draft::code_enums_match_the_registry` drives `sig_alg`
   through `manifest::registry::sig_alg_from_wire`/`to_wire` only. C's copy is
   pinned to F's by a *sibling* test over `0..=20`, so the chain holds today —
   but it is two hops, and one of them is bounded at 20. The freeze test must
   assert **both** copies against the JSON directly.

**One more thing freezes with the enum, and nobody has said it.** The
16-value universe is **load-bearing for D10**: §11's recorded non-caps says
`sig_policy`/`pubkeys`/`signatures` are "bounded instead by the 16-value
`sig_alg` universe of §6.2". So widening the reserved band beyond 15 would
require minting caps for three lists that currently have none — i.e. the
`0..=15` universe is effectively frozen by D10 as well as by §6.2. F4 records
the cross-link.

### What F4 writes so D17's checkbox closes at Q14

1. §6.2's heading loses `— status: pending-D17` and takes the frozen marker.
2. The nine `pending-D17` status markers in the JSON (`manifest_envelope`
   key 1, `manifest_body` keys 5 and 6, four `scalars` rows, and the
   `sig_alg` reserved range) become `frozen-v1`.
3. §2 drops both `*pending-D17 confirm*` annotations.
4. The front-matter D17 bullet moves from the open list to a resolved line
   citing C14/F5 as the code ratification and this record as the formal
   freeze.
5. §14's registered vocabulary drops `pending-D17` — see §12 below.
6. §6.2 gains the D10 cross-link sentence.
7. The freeze test asserts **both** code copies against the mirror
   (§14 assertion C5 below).

> **RESOLVED 2026-07-28 — §6.2/D17: values freeze as {0: ed25519,
> 1: ml-dsa-65, 2–15 reserved-and-rejected}; 1952/3309 are confirmed against
> the pinned crate source and the annotations are removed. The duplicated
> F/C mapping STAYS duplicated — re-homing is a free refactor D8 does not
> mandate — but the freeze test must pin BOTH copies to the JSON mirror
> directly, closing the two-hop chain that exists today. The 16-value
> universe also freezes because D10's recorded non-cap on
> `sig_policy`/`pubkeys`/`signatures` depends on it.**

---

## 8. §13 items 8, 9, 10 — three decisions the draft still calls open

The draft's §13 (lines 1339-1370) introduces these three with "each is
format-permanent and **none is decided here**". All three were decided the
same day the slice was written, and the registry's *body* has partly caught
up while §13 has not. Each is confirmed against landed code below, with the
exact rewrite.

### 8.1 — Item 8 → **D78: NO, bundle schema validation never opens the manifest**

**Confirmed in code, structurally.** `BundleError` has no arm that can carry
a `ManifestError` — `bundle/error.rs:1014-1017` calls this "D78 as a type
witness […] rather than a runtime assertion because that is the strength D78
needs". `bundle/schema.rs:1544` treats key 1 as "Opaque here by D78: this
layer never opens it." `tests/bundle_codec.rs:447` asserts "a manifest
failure must never acquire a bundle- code (D78/D30)". The error-code contract
§2 records the split as normative.

**Rewrite.** §0's paragraph currently opens "**Proposed rule (D8 feed, §13
item 8): bundle schema validation never consults the embedded manifest.**"
It becomes:

> **Ratified rule (D78, 2026-07-28): bundle schema validation never consults
> the embedded manifest.**

with the rest of the paragraph unchanged (its argument is correct and is the
argument D78 records), and the trailing "Owner: D8 with F8/F9/R" removed.
§13's item 8 is deleted from the open list and appears in the closed record.

### 8.2 — Item 9 → **D79: the OTS upgrade group is FREE-STANDING**

**Confirmed in code.** `OtsAnchor::decode` (`bundle/schema.rs:500-550`)
enforces all-or-nothing over keys 2/3/4 and reads `status` nowhere in the
decision: `bundle/schema.rs:527` — "D79: all-or-nothing over the three group
keys, decided without ever …". `Option<OtsUpgrade>` "has no 'two of three'
state" (`bundle/schema.rs:40`). The failure is
`BundleError::OtsUpgradeGroupIncomplete { missing_key }`
(`bundle/error.rs:630`).

**Rewrite.** §7.8's paragraph currently reads "Whether the group's presence
is additionally **tied to `status == attested`** is a genuinely open,
format-permanent question and is **flagged to D8 as §13 item 9**". It
becomes:

> **The group is free-standing (D79, ratified 2026-07-28): its presence is
> never conditioned on `status`.** `status` is sealer-written and the design
> requires a verifier not to trust it; conditioning a *parse* rule on it
> would let a sealer choose which shapes decode — the same
> derived-not-declared principle D28 rider 1 applies to reveal shape. The
> consequence is accepted deliberately: an artifact recording
> `status = pending` while carrying height + header is well-formed v1, and
> what its status values *mean* is A-domain semantics at M2 (§6.1, §13.5).

§13's item 9 is deleted from the open list.

### 8.3 — Item 10 → **D80: a revealed unit's owning file MUST appear in
`touched_files`**

**Confirmed.** `docs/decisions/D80-revealed-unit-touched-file.md` resolves it
on spec evidence (line 95's defining use of *touches*, line 121's binary
rendering taxonomy), tier **[R]**, code `revealed-unit-file-not-touched`,
registered in `docs/testing/error-code-contract.md` §7 under "M0 wave 4, R5".
§7.6's [R] list already carries it correctly.

**Rewrite.** §13's item 10 is deleted from the open list. §7.6 needs one
addition — see §9.4 below — because **D82 subsequently closed the converse**
and the registry records neither the converse nor the resulting equality.

> **RESOLVED 2026-07-28 — §13 items 8, 9, 10: all three are closed, and were
> closed on 2026-07-28 by D78, D79 and D80 respectively. Each is confirmed
> against landed code above. §0's "Proposed rule" becomes "Ratified rule
> (D78)", §7.8's "flagged to D8 as §13 item 9" becomes D79's ruling, and all
> three items move out of §13's open list into the closed record.**

---

## 9. D74, D75 — and the two rules §7.6 is missing

### 9.1 — The §13 table is stale

§13's closing table (lines 1381-1386) is headed "Registered decisions the
bundle slice **feeds and must not resolve**" and describes D74 as "the row is
left **unassigned**" and D75 as "the draft leans 'both', with reasons, as D75
input". Both were resolved on 2026-07-28 with F8. The JSON mirror's
`fed_but_not_resolved_here` block carries the same stale text and still lists
both.

### 9.2 — What §7.14 key 2 must read (D74)

**D74: reject, with its own code.** The registry's §7.14 violation table
already carries the correct outcome inline; what must change is that it stops
reading as a fresh resolution and starts reading as settled law. The row
becomes:

> | `full(F) ∧ fine_tree = Absent`, key 2 present | `full-reveal-s-root-without-fine-tree` (**D74**). A single code: the `FileSalt` counterpart is unreachable, because key 1 is `req` at schema level and F8 rejects a key-1-less entry as `bundle-missing-key` before R4 runs |

and key 2's presence cell keeps its biconditional, its [R] tier, and D83's
`n == 1` clause. Nothing else moves: D74 minted no wire field, no HKDF label,
no domain tag.

### 9.3 — What §7.11 key 3 must read (D75), and the claim that must be deleted

**D75: BOTH — key 3 is `req`, unconditionally, tier [P].** The cell becomes
plain `req` with the [P] non-empty rule and no "(D75 RESOLVED — …; see
below)" rider.

**And the registry repeats a claim D75's own ratification has since
retracted.** §7.11's D75 block (lines 871-872) says the `s_root` rebuild
"additionally proves no extra leaves". D75 Correction 1
(`docs/decisions/D75-full-reveal-cover-shape.md:139-156`) says:

> It proves nothing of the kind, because **both routes take the leaf count
> from the same place and neither can admit a leaf the other excludes** […]
> `registry-v1.md` §7.11 repeats the same claim ("the rebuild additionally
> proves no extra leaves") and inherits the same correction.

So the correction was *recorded as owed to this document* and never applied.
F4 must replace it with D75's corrected consequence, which is sharper:

> The rebuild is **defence-in-depth for the file's content binding** (every
> unit is already bound to `fine_root` through its own cover) and
> **load-bearing and sole for the disclosed `s_root` itself**:
> `check_fine_root_rebuild` is the only consumer of a full reveal's `s_root`
> anywhere in the pipeline, so deleting it would turn key 2 into precisely
> what D74 mints a permanent code to prevent — a bundle-side field the
> verifier reads, does not check, and does not report.

The long "#### D75 — does a full reveal ship per-unit covers *and*
`s_root`?" block (lines 829-877) stays as recorded rationale but must be
re-headed so it cannot read as an open question, and its "Which way the draft
leans" paragraph must be past-tensed.

### 9.4 — Two rules §7.6 does not record: D82, and D80's converse

**D82 is absent from the registry entirely.** Grep of
`docs/format/registry-v1.md` and `registry-v1.json` for `D82`: no match. Yet
D82 (RESOLVED 2026-07-28) decided:

> **Option B — reject.** `VerifyError::TouchedFileWithoutRevealedUnit
> { file_id: u64 }` → **`touched-file-without-revealed-unit`**

and its own Permanence section says the outcome is "Format-permanent both
ways, which is why it could not stay open past Q14". A format-permanent rule
about a bundle section that the wire registry does not mention is a hole in
the registry, and Q14 would freeze around it.

**F4 must add it.** §7.6's [R] list gains a row, and the two rules together
must be stated as the equality they now form:

> **`touched_files` names exactly the files with a revealed unit** — both
> directions, both tier **[R]**:
> - every revealed unit's owning file has a `touched_files` entry — **D80**,
>   code `revealed-unit-file-not-touched`;
> - every `touched_files` entry belongs to a file with a revealed unit —
>   **D82**, code `touched-file-without-revealed-unit`.
>
> Both are [R] and not [X] for the same reason: "a revealed unit's *owning
> file*" is a manifest fact (the unit table is nested inside file entries),
> which D78 keeps out of the bundle schema layer. Neither subsumes the [X]
> rule `full_reveals ⊆ touched_files`, which stays [X]: a file may be touched
> by a unit reveal without being fully revealed.

**And this is where v1.1 will bite** — recorded now, because it is cheap now
and expensive later. Assigning bundle key 10 (`range_reveals`) in a v1.x
release requires **widening "revealed"** in both rules, and in D28's `full(F)`
predicate, to include range-revealed files and leaves. That widening is
**permissive** (bundles previously rejected become accepted), hence legal
under line 123, and old v1 verifiers reject such bundles cleanly at the
reserved-slot error rather than mis-verifying them. So the v1.1 path stays
open — but it is a coupling, not a free addition, and §9 must say so.

> **RESOLVED 2026-07-28 — D74 and D75 are settled law in the registry, not
> feeds: §7.14 key 2 rejects an `s_root` on a fine-tree-less full reveal with
> `full-reveal-s-root-without-fine-tree`, and §7.11 key 3 is `req`
> unconditionally at tier [P]. §7.11's "proves no extra leaves" claim is
> DELETED per D75 Correction 1, which named this document and was never
> applied. Additionally: D82 is missing from the registry altogether and must
> be added, stated with D80 as the equality `touched_files` = {files with a
> revealed unit}, together with the recorded note that assigning bundle key 10
> in v1.x requires a permissive widening of "revealed" in both rules and in
> D28's `full(F)`.**

---

## 10. The §0 / §13 disagreement about D76 and D77

### The disagreement, quoted from both sides

The brief locates this in "§0"; precisely, it is in the document's
**front-matter bullet list (lines 43-53)**, which precedes `## 0. Scope and
reading rules` at line 61. Nothing inside §0 proper mentions either decision.

**Front matter, `docs/format/registry-v1.md:47-50`:**

> Still open and **not** resolved here: **D77** (zero-non-mirror-unit file —
> §7.14's anti-vacuity clause makes the predicate safe without it), **D76**
> (splitting `file_salt` — recommended NO for v1).

**§13's table, `docs/format/registry-v1.md:1385`:**

> | **D77** — zero-non-mirror-unit file | §7.14's `N(F) ≠ ∅` clause |
> **RESOLVED 2026-07-28: reject at F5.** §7.3 key 6 gains "at least one
> `kind = normal` unit **[P]**", code `manifest-empty-normal-units`. The
> draft's "no registry change either way" note is thereby falsified and
> corrected |

**§13 is right; the front matter is stale.** D76 does not appear in §13's
table at all, so for D76 the front matter is the *only* statement and it is
also wrong.

### Both are resolved, and both are confirmed in code

- **D77 — reject the mirror-only file at F5.** `FileEntry::new`
  (`manifest/body.rs:702-718`) checks `units.is_empty()` first, then
  `!units.iter().any(|unit| unit.kind() == UnitKind::Normal)` →
  `ManifestError::EmptyContainer { field: ContainerField::NormalUnits }`,
  code `"manifest-empty-normal-units"` (`manifest/error.rs:783`). The check
  order is frozen and asserted in both directions
  (`tests/manifest_schema.rs:661, :691`). §7.3 key 6 already carries the
  rule; only the front matter lags.
- **D76 — NO `file_salt` split for v1.** `FullReveal` carries one
  `file_salt: Salt16` (`bundle/schema.rs:1275-1279`), decoded as a single
  16-byte field (`:1327-1333`). Grep for `raw_salt` / `canon_salt` across all
  crates and the registry: zero hits. `crypto/hkdf.rs` keeps eight labels
  with `"file-salt"` serving both commitments.

### The fix

1. Front matter lines 48-50 are replaced by resolved lines for **D76** and
   **D77**, each with its outcome and record path, moved into the
   "Resolved inputs" list.
2. §7.14 key 1 gains D76's consequence, which is currently unrecorded in the
   registry: *one `file_salt` salts both `raw_commit` and `canon_commit`
   (line 95); the two are never split in v1, and a future `raw_salt` would
   take a reserved slot rather than displace key 1.* (D76's own Consequences
   section asserts this about `registry-v1.md:861` — a line number that is
   now stale; the row is at line 922. See §17 item 5.)
3. §7.3 key 6's D77 citation is kept and upgraded from an inline note to a
   resolved-decision reference.
4. JSON `resolved_decisions` gains **D76** (it already has D77).

> **RESOLVED 2026-07-28 — §13 is right and the front matter is stale. D76 =
> NO split for v1 (one `file_salt` for both content commitments); D77 =
> reject the mirror-only file at F5 (`manifest-empty-normal-units`). Both are
> confirmed in landed code. Front-matter lines 48-50 move to the resolved
> list, and §7.14 key 1 gains D76's until-now-unrecorded consequence.**

---

## 11. D83 at both sites

**CONFIRMED — the registry already states the rule at both sites, and this is
the one place where the draft is ahead of its own §13.** Verified at HEAD:

| site | text | line |
| --- | --- | --- |
| §2, after the fixed-length table | "This binds `cover_entry` (§5, §7.11 key 3) at `level == d` **and** `full_reveal.s_root` (§7.14 key 2) at `n == 1`, the one case where the grid root is itself a leaf." | 172-181 |
| §5, tuple shapes | "At `level == d` the third element is **not** the raw seed but the canonical leaf-level payload `salt_i ‖ 0x00·16` (D83)" | 362-366 |
| §5, "Canonical leaf-level payload" | "The same rule governs `full_reveal.s_root` (§7.14 key 2) at `n == 1` […] At that size the two fields are byte-identical by rule, which is how D75's 'the two routes must agree' rider is discharged." | 349-353 |
| §7.11 key 3 | "the **canonical leaf-level payload (D83: an entry at `level == d` must carry `salt_i ‖ 0x00·16`)** are **[R]**" | 812 |
| §7.14 key 2 | "At **`n == 1`** the grid root is a leaf, so this field is the canonical leaf-level payload `salt_0 ‖ 0x00·16` and a non-zero upper half is rejected **[R]** (D83)" | 923 |

The JSON mirror carries it too: `tuples[cover_entry].elements[2].canonical_leaf_payload`
and the `resolved_decisions.D83` string, which names both binding sites.

The error code is `fine-root-leaf-seed-tail-not-zero`
(`content/fine_tree/error.rs:214`), reachable from both sites — the
`content-` prefix that appears in D83 §A5 is the *tamper row id*
(`content-fine-root-leaf-seed-tail-not-zero`), not the code, and §2's
spelling is correct.

Two housekeeping consequences at freeze:

- §5's subsection heading reads `— status: proposed (D83 RESOLVED — option
  B)`. The parenthetical becomes the plain statement and the status marker
  flips.
- §11's closing sentence points the anchor-artifact limits question at the
  wrong decision — see §17 item 1.

> **RESOLVED 2026-07-28 — D83 is stated at BOTH sites (§2, §5, §7.11 key 3,
> §7.14 key 2) in the document and at both in the JSON mirror. Confirmed, no
> content change; only the status markers and the §5 heading move.**

---

## 12. Freeze mechanics of the document itself

A registry that freezes while its items say "proposed" is not frozen. At HEAD
the mirror carries **147** `proposed` markers and **9** `pending-D17`
markers, and the document-level status is `"draft-until-Q14"`.

### The vocabulary transition

| | before Q14 | at and after Q14 |
| --- | --- | --- |
| document-level `status` | `"draft-until-Q14"` | **`"frozen-v1"`** |
| item-level `status` | `proposed` \| `pending-D9` \| `pending-D17` | **`frozen-v1`**, and nothing else |

**`proposed` is not a legal value for any v1 item after Q14**, and neither is
any `pending-*` marker. This is not a stylistic rule: an item that still says
`proposed` in a frozen registry is either a genuine unresolved question that
escaped the gate, or a lie about the document's own state. Both are worse
than a failing test.

`pending-D9` and `pending-D17` are **retired outright**, not kept on the
allow-list. §14's current reasoning for keeping `pending-D9` registered —
"the marker cannot be *silently reintroduced* under a different spelling" —
is inverted by the freeze: after Q14 the stronger property is that these
strings **must not appear at all**, which is a prohibition, not an
allow-list entry. F4 replaces the paragraph accordingly.

### How the draft-stage test becomes a freeze-stage test

`crates/antseal-core/tests/format_registry_draft.rs` is **renamed to
`format_registry_freeze.rs`**, and three of its assertions change shape:

1. `ALLOWED_ITEM_STATUSES` (line 56) —
   `["proposed", "pending-D9", "pending-D17"]` — becomes
   `const FROZEN_ITEM_STATUS: &str = "frozen-v1";`
2. `every_draft_item_carries_a_registered_status_marker` (lines 258-298)
   becomes `every_frozen_item_carries_the_frozen_marker` and asserts
   **equality** with `FROZEN_ITEM_STATUS`, not membership in a set. Equality
   is strictly stronger: an item added with no status, with `proposed`, or
   with a novel spelling all fail identically.
3. A new assertion, `no_pre_freeze_marker_survives_anywhere`: the strings
   `"proposed"`, `"pending-D9"`, `"pending-D17"` and `"draft-until-Q14"` do
   **not occur anywhere in the JSON**, at any depth, in any field — not only
   in `status` fields. This catches the case the current allow-list cannot:
   a `notes` string that still says "proposed", which is how prose rots.
4. `registry_json_parses` (lines 137-141) asserts the document-level status
   is `"frozen-v1"`.

**The test's new strictness is deliberate and is the point.** The moment a
v1.1 item is drafted into a reserved slot, assertion 2 fails — forcing the
v1.1 author to extend the vocabulary consciously, at their own gate, rather
than sliding a proposal into a frozen document. That is the same discipline
`FROZEN.sha256` applies to vectors.

### Recommended, not required: pin the mirror's digest

The registry's normative text lives in the `.md`; the `.json` is the
machine-checked mirror. Post-freeze, both should be as hard to change
casually as a golden vector. **Recommendation** (F4 may adopt or defer to
Q14/Q27): record `SHA-256(registry-v1.json)` as a constant in the freeze test
and assert it, so every post-freeze edit — including an editorial one — is a
deliberate act with a visible diff in a test file. Marked as a
recommendation because it is a process choice, not a format one, and because
Q27's format-stability policy is the natural home for it.

**Reconciliation with the concurrent Q14 freeze-gate plan.** A parallel
planning pass produced `docs/format/Q14-freeze-gate-plan.md` in the same
wave. It reaches the same findings independently (the D76/D77 contradiction,
the stale D75 lean, the caps-mirror status, the vocabulary gap at
`tests/format_registry_draft.rs:56`) and explicitly records the frozen-status
vocabulary as **not its call** — D8's. Two points where the two records must
agree, and this one governs:

- That plan describes the fix as `ALLOWED_ITEM_STATUSES` **gaining** the
  frozen value. **D8 rules otherwise**: the constant is replaced by a single
  `FROZEN_ITEM_STATUS` and the assertion becomes equality, with the three
  pre-freeze strings asserted absent from the whole file. Gaining a member
  would leave `proposed` legal in a frozen registry, which §12 rejects.
- That plan registers **Q50** — a freeze digest over
  `docs/format/registry-v1.{md,json}` under an append-only manifest reusing
  Q6's directive parser — as a *must-land-before-the-tag* disposition. That
  is the same mechanism this section recommends, in a better home. **If Q50
  lands, D8's recommendation is satisfied by it and no separate constant is
  needed.**

### The banner and the headings

The document opens with a DRAFT banner (lines 3-24) listing D8 and D17 as
open. It is replaced by a FROZEN banner naming the Q14 gate, the
`format-v1-freeze` tag and this record, and stating that any subsequent
change is a format-version event per line 123 and Q27. Every section heading
carrying `— status: proposed` (§3, §4, §5 and its subsection, §6.1, §6.3,
§9's "Version dispatch order", and §6.2's `pending-D17`) loses the suffix;
the per-item markers in the tables carry the state.

> **RESOLVED 2026-07-28 — the frozen marker is `frozen-v1` at both document
> and item level. `proposed`, `pending-D9` and `pending-D17` are illegal for
> v1 items after Q14 and are asserted absent from the mirror entirely, not
> allow-listed. `tests/format_registry_draft.rs` is renamed
> `format_registry_freeze.rs`; its status assertion changes from set
> membership to equality, and gains a whole-document prohibition on the four
> pre-freeze strings. Digest-pinning the mirror is recommended, not
> required.**

---

## 13. Are the reserved key ranges adequate?

### 13a. Does the v1.1 sub-unit range-reveal path stay possible?

**Yes, and the shape is checkable rather than hoped-for.** A v1.1 range
reveal needs, per line 114 and line 96: the file (or unit) it speaks about,
the byte range, the revealed bytes, the leaf-exact GGM sub-cover of exactly
those leaves, and the boundary Merkle paths. That is **one new bundle
section** — an array under bundle key 10, whose elements are a new map with
its own fresh `0..=23` band. Nothing in v1 has to move to accommodate it.

Three couplings that must be recorded now, because they are cheap to record
and expensive to discover:

1. **"Revealed" widens.** D80 and D82 (§9.4) and D28's `full(F)` all quantify
   over *revealed units*. A range reveal reveals part of a unit. Assigning key
   10 requires widening all three to range reveals. The widening is
   permissive, hence legal (line 123), and old verifiers reject a key-10
   bundle cleanly at the reserved-slot error.
2. **`UnknownUnitRef` stops idling.** §7.11 already records this: because
   `cover`/`paths` are nested inside the reveal they belong to, "proof reaches
   outside the revealed set" is unrepresentable in v1 and the check idles —
   "It stops idling the moment bundle key 10 (`range_reveals`) is assigned in
   v1.1". Correct, and it must survive the freeze edit rather than be tidied
   away as dead code.
3. **The proof format itself is already frozen.** `cover_entry` and
   `path_node` (§5) are what a range proof carries, and they ship in MVP
   (line 161: "the GGM range-proof format and verification already ship in
   MVP"). So v1.1 adds *selection and rendering*, not cryptography — which is
   why one reserved key suffices.

**Boundary paths** need nothing further: a range's boundary siblings are
`path_node` tuples in the same encoding, addressed by the same `(level,
index)` convention D9 froze.

### 13b. Is `0..=23` enough per map?

Headroom at freeze, computed from the code's own `RESERVED_FIRST` constants
(`manifest/registry.rs:80-164`, `bundle/registry.rs:104-248`), with §1 and §3
of this record applied:

| map | assigned | named-reserved | free slots in `0..=23` |
| --- | --- | --- | --- |
| `manifest_envelope` | 0–1 | — | **0 — frozen shape, no band, forever** (§1 rule 6) |
| `manifest_body` | 0–7 | — | 16 |
| `file_entry` | 0–6 | — | 17 |
| `canon_descriptor` | 0–3 | — | 20 |
| `unit_entry` | 0–6 | — | 17 |
| `bundle` | 0–9 | 10 `range_reveals` | **13** |
| `storage_record` | 0–2 | — | 21 |
| `ots_anchor` | 0–4 | — | 19 |
| `tsa_anchor` | 0–3 (after §1) | — | **20** (was 19) |
| `receipt_record` | 0–2 | 3 `chain_inputs` | 20 |
| `covered_reveal` | 0–4 | — | 19 |
| `noncovered_reveal` | 0–3 | — | 20 |
| `touched_file` | 0–2 | — | 21 |
| `full_reveal` | 0–2 | — | 21 |

**Confirmed adequate**, on grounds the draft does not state:

1. **The band's size is what makes its error message honest.** F10's
   reserved-slot error means "this is a v1.x field your verifier is too old
   for". That claim is credible for a small, deliberately reserved band of 24
   and would be a lie for, say, `0..=255` — where most keys will never be
   assigned and "upgrade your verifier" would be the wrong advice for what is
   simply garbage. Widening the band is therefore not free even though it
   costs no bytes: it degrades a permanent error code's meaning. And because
   D30 freezes which code fires for which input, this is decidable now or
   never.
2. **Single-byte heads keep v1.x additions cheap**, which is the original
   §1 rule 4 reason and still holds.
3. **The tightest map, `bundle` at 13 free, is the one whose additions are
   largest.** A new top-level section is a new schema, not a field; §7.6.2
   already records that "a future third anchor kind is a new top-level key,
   not a new enum value […] That is the intended shape". Thirteen such
   additions is generous.

**And exhaustion is not a defect — record it as the correct outcome.** F4
adds to §9:

> If a map's `0..=23` band is ever exhausted, the next addition is **not** a
> key ≥ 24. Keys ≥ 24 are unknown-key forever (§1 rule 4) and carry no
> "too-old verifier" meaning, so a v1.x field there would be rejected by the
> wrong code. An exhausted band means the format has run out of additive
> room, and the correct response is a **format-version event** — which §9
> already requires for anything non-additive. The headroom table above is
> recorded at freeze so exhaustion is visible before it is reached.

### 13c. `sig_alg` 2–15

**Confirmed at 16 values**, with the cross-link §7 records: D10's recorded
non-cap on `sig_policy`/`pubkeys`/`signatures` is justified *by* the 16-value
universe, so widening the band would require minting three caps. The universe
is thus frozen twice over. Fourteen free slots are ample for a project that
will register at most a wider ML-DSA parameter set and one hash-based scheme.

> **RESOLVED 2026-07-28 — the reserved ranges are ADEQUATE as drafted. The
> v1.1 sub-unit range-reveal path fits in bundle key 10 with no v1 movement,
> subject to three recorded couplings (a permissive widening of "revealed" in
> D80/D82/D28's `full(F)`; `UnknownUnitRef` stops idling; the proof tuples are
> already frozen). `0..=23` is confirmed on the ground that the band's size is
> what keeps F10's reserved-slot error honest — a wider band would make a
> permanent error code lie. Headroom is 13–21 free slots per map (0 for the
> shape-frozen envelope), recorded as a table, and band exhaustion is ruled to
> be a format-version event rather than a defect to patch with keys ≥ 24.**

---

## 14. What the 1:1 code ⟷ registry test must assert at freeze

### First, two stale claims that must go

§0 line 103: "The 1:1 assertion that **code constants match this table**
arrives with F5/F8 — the current draft test (§14) checks only the mirror's
internal consistency."
§14 line 1414: "The 1:1 code-constants ⟷ registry assertion lands with
F5/F8 […] and the F11 cap constants join the mirror when frozen."

**Both are false at HEAD.** `tests/format_registry_draft.rs` already asserts
map keys, reserved bands, enums, scalar lengths, tuple arities, version
dispatch, error→map mapping and **all 19 caps** against the JSON
(`code_caps_match_the_registry`, lines 868-995), and the mirror's `caps`
object already carries 19 entries. F4 must replace both sentences with an
accurate description, or Q14 will tick a row against a promise that was kept
months earlier and a gap that is elsewhere.

### The assertion set, named so it cannot be under-delivered

**A — mirror internal consistency (retained, unchanged).** JSON parses;
`registry_version == 1`; every key / enum value / tuple index is an unsigned
integer; no duplicate key numbers within a map, no duplicate values within an
enum; reserved ranges well-formed, mutually disjoint, colliding with no
assigned key, and abutting where a map declares several; every assigned key
and reserved bound within `profile.v1_key_band_max`; the `maps[]` set is
exactly the fourteen registered names.

**B — freeze-state assertions (new; §12).** Document status is `"frozen-v1"`;
every item's status equals `"frozen-v1"`; none of `"proposed"`,
`"pending-D9"`, `"pending-D17"`, `"draft-until-Q14"` occurs anywhere in the
JSON at any depth.

**C — code ⟷ mirror (C1–C4, C7–C9 exist today; C5, C6, C10 are the gaps).**

- **C1 map identity** — `{MapId::ALL} ∪ {BundleMapId::ALL}` by
  `registry_name()` equals `{maps[].name}`, both directions. *(exists)*
- **C2 key numbers** — per map, `assigned_keys()` equals
  `{maps[].fields[].key}`. *(exists)*
- **C3 reserved bands** — per map, `reserved_band()` equals
  `maps[].reserved`, including `None` for the envelope and the two named
  slots pinned by their code constants. *(exists)*
- **C4 enums** — `(value, registry_value_name)` pairs match for
  `DescriptorKind`, `FineTreeDomain`, `UnitKind`, `AnchorStatus`; every value
  in every declared reserved range is rejected by code. *(exists)*
- **C5 `sig_alg`, BOTH copies — GAP.** Today only
  `manifest::registry::sig_alg_from_wire`/`to_wire` is driven against the
  mirror; `crypto::sig_policy::sig_alg_from_id`/`to_id` is pinned to it only
  indirectly, by a sibling test bounded at id 20. The freeze test must assert
  **both** mappings against the JSON directly, over the full registered set
  and the full reserved band. (§7.)
- **C6 field NAMES — GAP, and the biggest under-delivery risk.** C2 compares
  key *numbers* only, so a field could be renamed in the registry with no test
  failure — and the registry is the normative text. Closing it requires code
  to expose a name per key (a `const fn field_name(key) -> Option<&'static
  str>` per map, or a const table), then asserting per map that
  `(key, name)` pairs match `maps[].fields[].{key,name}` exactly. Without C6,
  "1:1" means "the numbers line up", which is not what §14 claims.
- **C7 scalar lengths** — the thirteen `scalars[]` rows against their code
  constants, plus the bundle-side aliases (`TX_HASH_LEN`,
  `STORAGE_NONCE_LEN`, `STORAGE_ADDRESS_LEN`, `MIN_CIPHERTEXT_LEN`).
  *(exists)*
- **C8 tuple arities** — `byte_range` 2, `cover_entry` 3, `path_node` 3
  against `TupleId`. *(exists)*
- **C9 caps** — all 19 `caps.entries[]` names, values and **error codes**
  against `codec::caps` and the emitting variants' `.code()`, both directions.
  *(exists — and is what makes §14's "join the mirror when frozen" stale)*
- **C10 report `AnchorState` ⟷ wire `AnchorStatus` — GAP.** Two independent
  seven-variant enums with byte-identical kebab-case spellings
  (`verify/report.rs:256-277` and `bundle/registry.rs:441-461`) and **no test
  binding them**. Report v1 freezes at Q14 alongside the wire (D84 §7's second
  row), so this pair must be pinned: assert the ordered spellings of
  `AnchorState` equal `AnchorStatus::ALL.map(registry_value_name)`. Cheap, and
  it closes a genuine desynchronisation route.

**D — document ⟷ mirror — GAP, and the one that makes "mirrors 1:1" true.**
Nothing in the tree parses `registry-v1.md`; the "1:1" claim in §14 is
currently unbacked. The freeze test must `include_str!` the document and
assert, for the mechanical tables only:

- every `### 7.x` map section's pipe-table rows `| N | name | …` match that
  map's `maps[].fields[].{key,name}` exactly, both directions, including the
  reserved-band row;
- §6's enum tables match `enums[]`;
- §2's fixed-length table matches `scalars[]`;
- §11's cap table matches `caps.entries[]` by name, value and code.

Brittleness to formatting is a feature after the freeze: the normative
document should not be reformatted silently.

**E — recorded non-assertions.** Named so they are deliberate rather than
forgotten:

- **presence rules** (`required` / `optional` / conditional) are expressed in
  code by Rust types (`Option<T>`, enum arms), which cannot be reflected
  without a macro; the mirror carries them for humans and for F8/R, and they
  are enforced by the schema tests rather than by this one;
- **validation tiers** ([P]/[X]/[R]) have no code representation at all — they
  are a layering contract between F8 and R, enforced by which module holds
  each check;
- **§12's spec-coverage checklist** cannot be machine-checked (spec lines are
  prose) and remains a reviewed artifact;
- **the receipt `payload`'s internal layout** is deliberately outside the
  registry (§3a) and has nothing to assert.

> **RESOLVED 2026-07-28 — the freeze-time assertion set is A (mirror
> consistency, retained) + B (freeze state, new) + C1–C10 (code ⟷ mirror,
> of which C5, C6 and C10 are gaps that must close) + D (document ⟷ mirror,
> a gap that must close for §14's "1:1" claim to be true) + E (four recorded
> non-assertions). §0's and §14's claims that the 1:1 assertion "arrives with
> F5/F8" and that the caps "join the mirror when frozen" are stale — both
> landed — and must be rewritten.**

---

## 15. Impact table — every registry section that moves

**30 distinct areas of `docs/format/registry-v1.md` move substantively**,
plus eight blocks of `docs/format/registry-v1.json`. The thirty, counted so
the number is auditable: the front matter; §0; §1; §2; §3; §4; §5 and its
canonical-leaf-payload subsection; §6.1; §6.2; §6.3; §7.2; §7.3; §7.6;
§7.6.1; §7.8; §7.9; §7.10; §7.11; §7.13; §7.14; §7.15; §8; §9 and its
version-dispatch subsection; §10; §11; §12; §13; §14. The seven sections
with **no substantive change** are §7.1, §7.4, §7.5, §7.6.2, §7.6.3, §7.7 and
§7.12.

**Separately, one mechanical change touches every table in §7.**
Those tables carry a `status` column whose cells all read `proposed` (or
`pending-D17`). **Ruling: delete the `status` column from the document's
tables entirely.**

> **Correction, F4 2026-07-28 (amended at source).** This paragraph and
> §16D's D2b originally read "every table in **§2, §6 and §7**". Checked
> against the tree: **only §7's fourteen tables have a status column.** §2's
> is `| bytes | fields | source |`, §6.1's is
> `| value | state | headline-eligible |`, §6.2's is
> `| value | algorithm | pubkey | signature | notes |`, §6.3's is
> `| enum | values |` — none carries one. The count is likewise 84 cells
> (81 `proposed` + 3 `pending-D17 (…)`), not "100+". The ruling is unchanged
> and the executed edit is 14 headers, 14 separators, 84 cells. After the freeze every row carries the same value, so a
column with one value in every cell is noise and a copy-paste hazard across
100+ cells. The document-level state is carried once, by the FROZEN banner;
the per-item `frozen-v1` markers live in the **JSON mirror**, which is where
the freeze test reads them (§12) and where a future v1.x addition can be
distinguished from a frozen v1 item. Assertion family D (§14) therefore parses
`| key | field | type | presence | len/shape |` — five columns, not six.

| § | line(s) | what moves | driver |
| --- | --- | --- | --- |
| front matter | 3-24 | DRAFT banner → FROZEN banner (Q14 gate, `format-v1-freeze` tag, this record) | §12 |
| front matter | 43-53 | D74/D75/D80 stated as resolved; D76/D77 moved out of "still open"; D78/D79 added as ratified | §8, §9, §10 |
| §0 | 77-80 | status vocabulary → `frozen-v1` | §12 |
| §0 | 93-101 | "Proposed rule (D8 feed, §13 item 8)" → "Ratified rule (D78)" | §8.1 |
| §0 | 103-106 | stale "1:1 assertion arrives with F5/F8" → accurate description | §14 |
| §1 | 119 | `tstr` row drops "TSA source" | §1 |
| §1 | 140-144 | rule 4 gains the band-exhaustion ruling | §13b |
| §2 | 169-170 | `*pending-D17 confirm*` removed from both ML-DSA rows | §7 |
| §3 | 196 | heading status suffix removed | §12 |
| §4 | 224 | heading status suffix removed | §12 |
| §5 | 251, 334 | both heading status suffixes removed; D83 stated as settled | §11, §12 |
| §6.1 | 409, 424-433 | heading; the recorded-subset ruling replaces "flagged to D8, §13 item 5"; the `absent`-rejection expectation is withdrawn | §4a |
| §6.2 | 435-448 | `pending-D17` → frozen; D10 16-value cross-link added | §7 |
| §6.3 | 450 | heading status suffix removed | §12 |
| §7.2 | 499, 501 | keys 1 and 3: may-be-empty explicit for both; non-empty check permanently foreclosed; `title` recorded as a disclosure to every recipient | §2 |
| §7.3 | 518 | D77 citation upgraded to a resolved-decision reference | §10 |
| §7.6 | 596-611 | [R] list gains D82; D80+D82 stated as the equality; v1.1 "revealed"-widening coupling noted | §9.4, §13a |
| §7.6.1 | 629-641 | two new checked-absence rows: no TSA `source`, no receipt chain identifier | §1, §3b |
| §7.8 | 737 | `fetch_date` semantics defined; three non-rules | §4b |
| §7.8 | 748-753 | "flagged to D8 as §13 item 9" → D79's ruling | §8.2 |
| §7.9 | 761-768 | key 4 `source` **deleted**; band `5..=23` → `4..=23` | §1 |
| §7.9 | 766 | `fetch_date` semantics defined | §4b |
| §7.10 | 784 | key 1 `block_number` given a total definition (minimum over key 0) | §3b |
| §7.10 | 774-779, 789-803 | D84-style scoping paragraph: the payload is opaque, completeness is S7's with no freeze deadline | §3a |
| §7.11 | 812 | key 3 presence: plain `req`, [P], rider removed | §9.3 |
| §7.11 | 829-877 | D75 block re-headed as recorded rationale; **"proves no extra leaves" deleted** and replaced by D75's corrected consequence | §9.3 |
| §7.13 | 903 | §10 ratification reference | §5 |
| §7.14 | 923, 951 | key 2 D74 rider → settled law; key 1 gains D76's consequence | §9.2, §10 |
| §7.15 | 1014-1021 | `tsa_anchor` band `5..=23` → `4..=23`; the code⟷registry contract text corrected | §1, §14 |
| §8 | 1068-1070 | anchor-order ruling: order carries no meaning; duplicates legal; A18/R17 owe the identity-based independence check | §4c |
| §9 | 1090-1121 | headroom table; exhaustion ruling; v1.1 range-reveal coupling | §13 |
| §9 | 1123 | "Version dispatch order — status: proposed" suffix removed | §12 |
| §10 | 1156 | "decision: YES (proposed)" → RESOLVED; the D78-forced ground added | §5 |
| §11 | 1223 | recorded non-caps drops `source` | §1 |
| §11 | 1227-1229 | **`their freeze status is D83` → `D84`** | §17.1 |
| §12 | 1240-1303 | rows for the two new checked absences; §7.9 key-count note | §1, §3b |
| §13 | 1305-1386 | **rewritten entirely** as a closed record citing this document | all |
| §14 | 1387-1417 | vocabulary; test rename; the two stale claims; the new assertion set | §12, §14 |
| JSON | top level | `status` → `frozen-v1`; `open_decisions` emptied; `d8_feed` → closed record; `fed_but_not_resolved_here` retired | §12 |
| JSON | `resolved_decisions` | add D8, D74, D75, D76, D78, D79, D80, D82, D84 (D9/D11/D23/D28/D77/D10/D83 present) | §8, §9, §10 |
| JSON | `maps[tsa_anchor]` | key 4 deleted; reserved `{first:4,last:23}` | §1 |
| JSON | `maps[receipt_record]` | key 1 note = the total definition | §3b |
| JSON | `caps.not_in_scope` | `decision D83` → `D84` | §17.1 |
| JSON | `caps.recorded_non_caps` | drops `tsa_anchor.source` | §1 |
| JSON | `caps.status` + all 156 item statuses | → `frozen-v1` | §12 |
| JSON | `checked_absences.items` | two new rows | §1, §3b |

**Code and test artefacts that move** (a separate F-domain task; F4 does not
edit code): `bundle/registry.rs` (`SOURCE` const, `RESERVED_FIRST` 5→4),
`bundle/schema.rs` (five `source` sites), `test_util/bundle_fixtures.rs`,
`tests/format_registry_draft.rs` → `format_registry_freeze.rs` (§12, §14),
`testdata/vectors/v1/bundle/bundle.json` + `README.md:61` +
`testdata/vectors/v1/FROZEN.sha256`, and the doc comment at
`verify/report.rs:293-295`.

---

## 16. What F4 must change — the executable checklist

Each item is self-contained. Nothing here requires re-deriving an argument.

### 16A. Wire-surface changes (two, both in the bundle half)

- [ ] **A1.** Delete `§7.9 key 4 (`source`)` from the table. Change the
  reserved row to `4–23 | — | — | — | reserved`. Update §7.15's
  `tsa_anchor → 5..=23` to `tsa_anchor → 4..=23`. Update §1's `tstr` row and
  §11's recorded non-caps to drop `source`. In the JSON, delete the field and
  set `maps[tsa_anchor].reserved = [{"first":4,"last":23,…}]`.
- [ ] **A2.** Rewrite §7.10 key 1's `len/shape` cell to the total definition
  in §3b of this record (minimum block number over key 0's transactions;
  display-only; never verdict-bearing; a per-tx structure, if ever needed,
  takes a reserved key and must be per-tx). Mirror the note in the JSON.

### 16B. New normative text

- [ ] **B1.** §7.6.1 gains two checked-absence rows: **no TSA `source`
  string** (a sealer's claim about an anchor's provenance, unbindable and
  unconsumed — §1) and **no chain identifier in the receipt** (it would steer
  the verifier's RPC choice; the chain is pinned by the verifier — §3b). Add
  both to the JSON's `checked_absences.items`.
- [ ] **B2.** §6.1 replaces its closing paragraph with the non-consumption
  rule quoted in §4a: all seven values legal as recorded on both kinds, no
  per-kind subset ever, no v1 parse rule or verdict may read `status`, and a
  verifier may display it only under line 137's `claimed_time` discipline.
- [ ] **B3.** §7.8 key 4 and §7.9 key 3 gain the exact `fetch_date`
  definitions of §4b, each with the explicit statement that it is **not** the
  provable time, plus the three recorded non-rules and the privacy note.
- [ ] **B4.** §7.10 gains the D84-style scoping paragraph of §3a (the payload
  is opaque, not v1 wire format; contents may change in any release without a
  format event; completeness is S7's obligation with no freeze deadline;
  registry-visible structure is promoted into `chain_inputs`).
- [ ] **B5.** §7.6's [R] list gains the D80 + D82 equality and the reason both
  are [R] (§9.4), plus the recorded v1.1 coupling.
- [ ] **B6.** §8 gains the anchor-order additions of §4c: order carries no
  meaning; duplicates are legal; anchor independence is A18/R17's
  verified-identity check, with the three reasons the byte-distinctness rule
  was declined and the note that this is the irreversible direction, accepted.
- [ ] **B7.** §9 gains the headroom table of §13b, the band-exhaustion ruling
  ("an exhausted band is a format-version event, never a key ≥ 24"), and the
  v1.1 range-reveal coupling of §13a.
- [ ] **B8.** §1 rule 4 gains a pointer to §9's exhaustion ruling.
- [ ] **B9.** §7.2 keys 1 and 3: state that **both** may be empty, that a
  non-empty check is permanently foreclosed, that neither is verdict-bearing,
  and that `title` is a disclosure to every bundle recipient.
- [ ] **B10.** §7.14 key 1 gains D76's consequence (one `file_salt` for both
  content commitments; a future `raw_salt` takes a reserved slot, never
  displaces key 1). §6.2 gains the D10 16-value cross-link.

### 16C. Corrections of stale or contradictory text

- [ ] **C1.** §11 line 1229 and JSON `caps.not_in_scope`: **`D83` → `D84`**.
- [ ] **C2.** §7.11: **delete** "the rebuild additionally proves no extra
  leaves"; replace with D75 Correction 1's text (§9.3). Re-head the D75 block
  so it reads as recorded rationale, and past-tense its "Which way the draft
  leans" paragraph.
- [ ] **C3.** §0 lines 93-101: "Proposed rule (D8 feed, §13 item 8)" →
  "Ratified rule (D78, 2026-07-28)"; drop the "Owner: D8 with F8/F9/R" tail.
- [ ] **C4.** §7.8 lines 748-753: replace the "flagged to D8 as §13 item 9"
  paragraph with D79's ruling (§8.2).
- [ ] **C5.** Front matter lines 48-50: move D76 and D77 out of "still open"
  into the resolved list, each with its outcome and record path.
- [ ] **C6.** §0 line 103 and §14 line 1414: replace both stale claims about
  the 1:1 test and the caps mirror with the accurate description of what
  exists and the named gaps C5/C6/C10/D (§14).
- [ ] **C7.** §5's subsection heading `— status: proposed (D83 RESOLVED —
  option B)` → the plain statement. §7.11 key 3 and §7.14 key 2 drop their
  "RESOLVED … with F8" riders and read as settled law.

### 16D. Freeze mechanics

- [ ] **D1.** Replace the DRAFT banner (lines 3-24) with a FROZEN banner:
  frozen at Q14 (`format-v1-freeze`), normative, any change is a
  format-version event per line 123 and Q27, citing
  `docs/decisions/D8-wire-registry-final.md`.
- [ ] **D2.** Remove every `— status: proposed` / `— status: pending-D17`
  heading suffix (§3, §4, §5 ×2, §6.1, §6.2, §6.3, §9's version-dispatch
  subsection).
- [ ] **D2b.** Delete the `status` column from every table in §7 (see §15's
  ruling and its F4 correction — §2's and §6's tables have no status column):
  the document's tables become
  `| key | field | type | presence | len/shape |`. The per-item `frozen-v1`
  markers live only in the JSON mirror, where the freeze test reads them.
- [ ] **D3.** §0's status column definition and §14's vocabulary paragraph:
  the single value is `frozen-v1`; `proposed`, `pending-D9` and `pending-D17`
  are illegal for v1 items and must not occur anywhere.
- [ ] **D4.** JSON: document `status` → `"frozen-v1"`; all 156 item statuses
  → `"frozen-v1"`; `open_decisions` emptied; `fed_but_not_resolved_here`
  retired; `d8_feed` converted to a closed record; `resolved_decisions` gains
  D8, D74, D75, D76, D78, D79, D80, D82, D84.
- [ ] **D5.** §13 rewritten as a closed record: the seven original items and
  the three bundle-slice items, each with its outcome and the decision that
  settled it, and a closing line stating that D8 is resolved and the registry
  carries no open item.
- [ ] **D6.** §14 documents the test rename and the assertion set A/B/C/D/E
  of §14 above, including the four recorded non-assertions.

### 16E. Handed to other tasks (F4 does not do these; the orchestrator
registers them)

> **Correction, F4 2026-07-28 (amended at source).** **E1 is not separable
> from F4** and was landed with it. `format_registry_draft::code_map_keys_match_the_registry`
> asserts, in both directions, that each map's `assigned_keys()` equals its
> `maps[].fields[].key` set. Deleting `tsa_anchor` key 4 from the mirror
> (A1) without deleting `SOURCE` from `bundle::registry` therefore turns the
> suite red in the same commit — the two edits cannot be sequenced apart.
> **E2** (the rename and assertion families) is likewise inseparable: the
> mirror's flip fires the two armed tripwires, so the test must move in the
> same change. **E3** (the `verify/report.rs` doc comment) was landed with E1
> because it documents the field E1's removal redefines. Only **E4** (the
> Q14 checklist row and the A18/R17 + S7 obligations) and **E5** (the
> `docs/decisions/README.md` rows) are genuinely separable; E5's D8 row is
> landed, and its D78/D79 half became **Q57**, since those two decisions have
> no record *file* at all, not merely no row.

- [ ] **E1.** *(F-domain, next free id)* Delete `source` from the bundle
  schema: `bundle/registry.rs:173` + `RESERVED_FIRST` 5→4;
  `bundle/schema.rs:564, 575, 621-623, 645, 1900`;
  `test_util/bundle_fixtures.rs:287, 294, 304, 1445`. Add `source` to
  `no_bundle_map_grows_a_deliberately_absent_field`'s banned list for
  `tsa_anchor`. Re-emit `testdata/vectors/v1/bundle/bundle.json`, update its
  `README.md:61` and `testdata/vectors/v1/FROZEN.sha256`. **No error code is
  minted; no report vector moves.**
- [ ] **E2.** *(F-domain)* Rename `tests/format_registry_draft.rs` →
  `format_registry_freeze.rs` and implement assertion families B, C5, C6, C10
  and D (§14). C6 requires the two registries to expose a name per key.
- [ ] **E3.** *(R-domain)* Correct `verify/report.rs:293-295`'s doc comment:
  `AnchorResult::source` is derived from the verified certificate chain (TSA)
  or the `.ots` attestations (OTS), **not** "as recorded in the bundle
  artifact".
- [ ] **E4.** *(Q-domain, Q14 checklist)* Add a freeze row: *"Wire registry
  frozen (D8/F4) — `docs/format/registry-v1.md` and its JSON mirror carry no
  `proposed` / `pending-*` marker, `format_registry_freeze` is green
  including assertion families B, C5, C6, C10 and D, and §13 records D8 as
  resolved."* Also add the A18/R17 obligation from §4c and the S7 obligation
  from §3a to their owners' task text.
- [ ] **E5.** *(docs)* `docs/decisions/README.md` gains rows for **D8**,
  **D78** and **D79** — see §17 item 3.

---

## 17. Errors, staleness and contradictions found in the existing records

Eleven, each with its exact location. Per the brief, this list is as valuable
as the decision.

1. **`docs/format/registry-v1.md:1229` and `registry-v1.json`
   `caps.not_in_scope`: the anchor-artifact limits question is pointed at
   decision D83.** It is **D84**. D10's own Consequences item 4 registered the
   question "under the number 'D83', which went to G20's finding the same day"
   (D84 §Context), and the registry inherited the collision. D83 is the
   leaf-level GGM payload. Fix in both files.

2. **`docs/format/registry-v1.md:872`: "the rebuild additionally proves no
   extra leaves" is a claim D75's own ratification retracted, naming this
   document.** D75 Correction 1
   (`docs/decisions/D75-full-reveal-cover-shape.md:139-156`) states: "It
   proves nothing of the kind […] `registry-v1.md` §7.11 repeats the same
   claim […] and inherits the same correction." The correction was recorded
   as owed and never applied.

3. **D78 and D79 have no decision record file and no `docs/decisions/README.md`
   row.** *(F4 2026-07-28: confirmed; registered as **Q57**. D8's own README
   row is landed. Note also that D82's record is
   `D82-touched-file-without-reveal.md`, not the longer name §9.4's prose
   implies.)* Both are cited as normative in code (`bundle/error.rs:7`,
   `bundle/schema.rs:12`, `codec/caps.rs:179`, `verify/error.rs:429`), in the
   error-code contract §2 ("decision D78, ratified 2026-07-28"), and
   throughout the registry — but they exist only as `TODO.md:452` and
   `TODO.md:453` entries. `docs/decisions/README.md` jumps D77 → D80.
   **D8 also has no README row** and will need one. Three rows owed.

4. **`docs/format/registry-v1.md:48-50` contradicts `:1385` about D77.** The
   front matter lists D77 as "Still open and **not** resolved here"; §13's
   table records it as "RESOLVED 2026-07-28: reject at F5". §13 is right. For
   **D76** the front matter is the only statement and is also wrong (D76
   resolved the same day).

5. **`docs/decisions/D76-file-salt-split.md`'s Consequences cites
   `docs/format/registry-v1.md:861` for §7.14 key 1.** That row is now at
   line 922 — the bundle-slice pass grew the document after D76 was written.
   Line-number citations into a growing document rot; the record should cite
   the section, not the line.

6. **`registry-v1.json` is stale relative to its own `.md` on D74 and D75.**
   `fed_but_not_resolved_here` still lists both as unresolved, with the
   pre-resolution text ("the violation row is left unassigned", "draft leans
   'both'"), while the `.md` body carries the RESOLVED riders. Nothing detects
   this: no test compares the two files (see item 9).
   `resolved_decisions` also omits D74, D75, D76, D78, D79, D80, D82 and D84.

7. **`registry-v1.json` `caps.status` is `"proposed"` while
   `registry-v1.md:1184`'s heading is "## 11. Parser resource caps (D10 —
   **frozen**)".** All 19 cap entries also carry `"proposed"`. A frozen
   decision's mirror should not say proposed; the §12 vocabulary transition
   resolves it, but the contradiction exists today.

8. **`crates/antseal-core/src/verify/report.rs:293-295`'s doc comment is
   wrong even before this decision.** It says `AnchorResult::source` is "the
   anchor's source identity when known (TSA URL / calendar identity, as
   recorded in the bundle artifact)" — but `verify/pipeline.rs:72-76`
   deliberately does not copy it, and the wire never had an **OTS** `source`
   key at all, so the fixture value `Some("calendar.example")` on an
   `AnchorKind::Ots` result (`verify/mod.rs:144`) has no wire origin in any
   version.

9. **§14's claim that the JSON "mirrors this document 1:1" is unbacked.**
   Nothing in the tree reads `registry-v1.md`; the only consumer of either
   file is `tests/format_registry_draft.rs:50-53`, which reads the `.json`.
   Items 6 and 7 are the direct consequence.

10. **`docs/format/registry-v1.md:103` and `:1414` both promise a 1:1
    code-constants assertion that has already landed**, and `:1415-1416`
    promises the F11 caps "join the mirror when frozen" when they are in the
    mirror and cross-checked (`code_caps_match_the_registry`, 19 rows). Two
    forward-looking sentences describing the past.

11. **`TODO.md:88` describes F4's D8 feed as "6-item"**; §13 has ten items
    (seven original, of which two are struck, plus three added by the bundle
    slice). Written before the bundle-slice pass and never updated. *(Reported
    only — `TODO.md` is not this record's to edit.)*

Two further observations that are not errors but are worth recording:

- **`crates/antseal-core/src/crypto/sig_mldsa.rs:90, 94` cite "registry §4"
  for the ML-DSA fixed lengths.** §4 is the byte-range representation; the
  fixed scalar lengths are **§2**. A one-character doc fix, listed so it is
  not rediscovered.
- **The report's `AnchorResult::fetch_date` is `Option<String>` while the
  wire field is `u64` POSIX seconds.** The mismatch is deliberate and
  documented (`verify/pipeline.rs:74-76`: "rendering a `fetch_date` would
  require choosing a date format — a format-permanent decision R12/A18
  owns"), and §4b's definitions give R12/A18 the semantics they will need. No
  action at Q14; recorded so the gap is not read as an oversight.

---

## Outcome

**RESOLVED, 2026-07-28.** D8 is closed and the v1 wire registry is signed off
for the Q14 `format-v1-freeze` gate, subject to the §16 checklist.

Four substantive changes to the draft: the TSA `source` string leaves v1
(§1); `title`/`app_version` keep their shape on replaced grounds (§2); the
receipt's `block_number` gains a total definition and its completeness
question is scoped out of the freeze in D84's manner (§3); and the recorded
`anchor_status` is ruled to have **no** per-kind subset, with the
non-consumption rule frozen in its place (§4).

Five ratifications: explicit `file_id` (§5, on a stronger ground than the
draft's four), `unit_id` stored-and-checked (§6), D17's numeric values (§7),
the `0..=23` band and every reserved range (§13), and D83 at both of its
sites (§11).

Three known-stale §13 items cleared against landed code (§8), two resolved
feeds restated as law with one retracted claim deleted (§9), one front-matter
contradiction fixed (§10), the document's own freeze mechanics defined (§12),
and the freeze-time assertion set named with four gaps that must close (§14).

Thirty registry sections move. Eleven errors are recorded in §17, of which
three — the `D83`/`D84` mispointer, the retracted "no extra leaves" claim,
and the entirely absent D82 rule — would have been frozen into a normative
document had they not been caught here.
