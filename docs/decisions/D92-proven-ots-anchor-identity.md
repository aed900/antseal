# D92 — What a `proven` OTS anchor contributes to the anchor-independence count

- **Status: RESOLVED — a `proven` OTS anchor's identity is **Bitcoin, the
  chain**, not its calendar set and not its block. One opaque
  `AnchorIdentity::BitcoinChain`, shared by every headline-eligible OTS
  anchor in a bundle regardless of height, hash, or which calendars it
  names; `AnchorIdentity::OtsCalendars` is **deleted**, not deprecated.
  The status quo is wrong for a sharper reason than the recorded risk
  states: A40's own `TsaSigner` rustdoc rules that an identity *"is only
  ever built from a certificate a validated path to a pinned root closed
  under, never from a bundle-recorded string"*, and a calendar URI **is** a
  bundle-recorded string — read verbatim out of an unsigned `.ots`
  attestation payload, bound by nothing, chosen by the sealer at submit
  time, and provably **invariant across the whole `pending → attested →
  proven` transition** because `antseal-anchor`'s merge is a pure insertion
  that *enforces* attestation retention (`ots/upgrade.rs:356-358`). So the
  status quo lets the sealer name the verifier's "verified identity", which
  is the one thing A40 exists to prevent. The block is no better: which of
  an artifact's Bitcoin heights reaches the D79 upgrade group is decided by
  **merge order**, not by evidence (`ots/engine.rs:447-458` takes
  `merged.added.first()`), so a height-keyed identity is sealer-controlled
  too. The decisive measurement needs no adversary: in the real 2026-08-03
  cycle **one digest, three calendars, three different Bitcoin blocks**
  (960767 / 960768 / 960771) — so both the calendar key and the block key
  turn a single seal's single OTS mechanism into **three** "independent"
  identities, and MVP-SPEC.md line 19's own model counts it as **one**
  ("OpenTimestamps (Bitcoin) + ≥2 free RFC 3161 TSAs"). Two `.ots` at
  different heights are **one identity and two data points**: same chain,
  same proof-of-work, same reorg, same must-agree esplora substrate — they
  fail jointly, and joint failure is exactly what an independence count
  denies. Also ruled: a kind-scoped accessor
  `distinct_verified_identities_of(AnchorKind)`, because **A20's gate must
  never read the mixed scalar** — A40's `Do` currently instructs precisely
  that, and a lone `proven` OTS would satisfy a `>= 1` test whose spec says
  "≥1 TSA token". Three findings underneath: the eligibility filter that
  makes `attested` contribute zero has **no OTS-side witness** — every test
  that can see it goes through the TSA path; the one existing OTS identity
  test **cannot distinguish this ruling from the status quo** (it is
  satisfied by three of the four candidates); and `antseal-core` now holds
  **two disagreeing TSA identity notions** — A31's `(issuer, serial)` and
  A40's `subject` DN — of which the seal-side one over-counts → **A72**.
  Under-counting is the direction chosen and stated.**
- **Date: 2026-08-06** (M2 wave-5 planning round; minted mid-round from the
  A40 risk recorded at `TODO.md:418` as follow-up **A67**, which had no
  task row)
- **Owning tasks: A67** (new — implements this), **A40** (amended, stays
  open until A67 lands)
- **Blocks: A20** (the degradation report), **R17** (M3 aggregation),
  **U22** (seal-command wiring) — none of which reads the count today
- **Base: `323adb8`**

## Context — the recorded risk, and the two things it understates

A40 landed 2026-08-05 as PARTIAL. Its OTS half was implemented literally to
A40's own `Do` (*"for an OTS anchor, the set of calendar URLs its
attestations name"*) and the consequence was **recorded rather than quietly
re-ruled** (`TODO.md:418`):

> A40's `Do` makes a `proven` OTS anchor's identity its calendar set, but
> what proved it is **Bitcoin**, so two `.ots` proven at one height through
> disjoint calendars **over-count** independence — the dangerous direction.

That is true and it is the right instinct. It understates the problem in
two ways, both of which change the ruling:

1. **It is not only an over-count; it is a sealer-controlled identity.**
   The calendar set is not derived from evidence at all. §2 below traces
   it: `calendars_of` reads the URI out of the attestation payload, the
   merge path *enforces* that upgrading never removes an attestation, and
   the resulting value is byte-identical before and after the anchor
   becomes `proven`. A verifier that calls that a "verified identity" has
   accepted the sealer's own submit list as its independence input.
2. **The over-count is reachable without an adversary.** The recorded risk
   posits two `.ots` "through disjoint calendars". The measured 2026-08-03
   cycle produces the shape by itself, honestly, from one seal (§3).

## 1. What a `proven` OTS anchor actually proves

D56's rule **O3** (`verdicts.rs:634-667`) promotes an `.ots` to `proven`
when three things hold together: the ops commit `anchor_digest` to a merkle
root; the artifact's embedded 80-byte header carries that root; and the
**online-agreed** header for the recorded height is byte-identical to the
embedded one. The time is the agreed header's `nTime`.

Every link in that chain is Bitcoin or the esplora must-agree pair. None of
it is a calendar. MVP-SPEC.md line 108 is explicit that the offline half
proves nothing on its own — *"a lone embedded header carries no offline
time guarantee — its proof-of-work is self-referential"* — and that
`--online` *"fetches block H from the must-agree esplora endpoints"* to
promote.

**D54 §4 already ruled what a calendar contributes, and it is not
evidence.** Its five-case analysis ends:

> **So calendar compromise is a denial-of-service, not a forgery, and the
> calendar set is chosen for availability and independence of operator, not
> for trust.**

and, earlier in the same section, *"there is no key in the protocol to
pin"* — an OTS calendar signs nothing. A calendar cannot manufacture a
false time; its only freedom is a *later* one, which is a strictly weaker
claim under "existed no later than T". A party that cannot lie about the
proposition is not a witness to it, and counting it as one is a category
error, not merely an over-count.

MVP-SPEC.md's own independence model says the same thing in one line
(line 19): **"OpenTimestamps (Bitcoin) + ≥2 free RFC 3161 TSAs on every
seal"** — OTS is one mechanism, and the plurality is on the TSA side. Line
13: *"timestamps come from independent anchors (OTS / RFC 3161)"*, again
two mechanisms, not two-plus-N calendars.

### 1.1 The definition this decision uses for "independent"

Two identities are independent **iff compromising one does not compromise
the other**. That is the only reading under which registry §8's motivating
case ("two tokens, one TSA") is a defect at all, and it settles the Bitcoin
question mechanically:

| pair | independent? | why |
| --- | --- | --- |
| Sectigo signer, DigiCert signer | yes | different keys, different roots, different operators |
| two tokens, one signer certificate | no | one key compromise, one revocation, one outage |
| block 960767, block 960771 | **no** | one chain, one proof-of-work regime, one reorg, one must-agree esplora pair |
| a TSA signer, Bitcoin | yes | disjoint mechanisms, disjoint failure modes |
| alice's calendar, bob's calendar | **not applicable** | neither is a witness; both are routing (D54 §4) |

## 2. The status quo, read off the code and not off its doc

`AnchorIdentity` (`crates/antseal-core/src/anchor/verdicts.rs:219-241`) has
two arms. The TSA arm's own rustdoc (lines 229-232) states the governing
rule:

> The identity is only ever built from a certificate a validated path to a
> pinned root closed under, **never from a bundle-recorded string** — the
> wire carries no source string for either kind (D8 §1).

The OTS arm violates it. `calendars_of`
(`verdicts.rs:795-815`) collects `OtsAttestation::Pending { uri, .. }`
verbatim from the parsed payload; `verdicts.rs:598-600` makes that the
identity for every OTS state, and `AnchorOutcome::new`
(`verdicts.rs:329-345`) keeps it only where the verdict is headline-eligible
(`verdicts.rs:339`), which for OTS means **`proven` alone**.

Three facts about that value, all verified in the tree rather than assumed:

- **It is chosen by the sealer.** The URI is whatever calendar the sealer
  submitted to. D54 §6.1's `DEFAULT_OTS_CALENDARS` is a default, freely
  overridden by config.
- **It does not change when the anchor becomes `proven`.**
  `crates/antseal-anchor/src/ots/upgrade.rs:45-49` states the design
  (*"Other calendars' pending attestations are retained: the insertion adds
  a sibling and removes nothing"*), `upgrade.rs:346` performs the single
  splice, and `upgrade.rs:356-358` **enforces** it:
  `if !retains_all(&before, &after) { return Err(MergeError::LostAttestation); }`,
  with `retains_all` (`upgrade.rs:377-388`) checking containment with
  multiplicity. So the identity of a `proven` OTS anchor is *literally the
  same bytes* as the identity of the `pending` one it grew from — a value
  that cannot distinguish "no evidence" from "Bitcoin-confirmed evidence"
  is not the identity of the evidence.
- **It is a set, and sets do not partition.** `OtsCalendars(Vec<String>)`
  compares whole vectors, so `{alice}` and `{alice, bob}` are two distinct
  identities that share a member. Independence counting requires identities
  to be *equal or disjoint*; set-valued keys are neither. This is a second,
  unrecorded over-count independent of the Bitcoin question.

A fourth shape exists but is not reachable from `antseal`'s own builder: an
adversary-supplied `.ots` with no `Pending` attestation at all yields
`OtsCalendars(vec![])` — an "identity" that is the empty set. Under the
status quo that value is counted, and every such artifact shares it. It is
harmless (it under-counts) and it is diagnostic: the key is undefined for
exactly the state it is used in.

## 3. The measurement that settles it — no adversary required

`testdata/anchors/A25-bootstrap/upgraded/UPGRADE-CAPTURE.log` records the
real cycle: two digests × three calendars, all six upgraded at
2026-08-03T09:03Z. `crates/antseal-core/src/anchor/ots/header.rs:49` and
`docs/decisions/D58-opentimestamps-viability.md:649-667` record the outcome:

> the **three calendars committed to three different blocks** — 960767,
> 960768, 960771 — so a fully upgraded artifact carries three attestations
> against one embedded header

pinned as a test at
`crates/antseal-anchor/src/ots/upgrade/tests.rs:454-460`
(`vec![960_767, 960_768, 960_771]`, identically for both digests).

Now count that seal's OTS evidence under each candidate. The three upgrade
responses are three separately fetchable artifacts; a sealer may merge them
into one `.ots` (what `engine.rs` does) or carry them as three — registry §8
makes both legal, and up to 256 `ots_anchors` are permitted.

| candidate | count for ONE honest seal | verdict |
| --- | --- | --- |
| calendar set (status quo) | **3** (alice / bob / catallaxy, disjoint) | 3× over-count |
| block height, or height+hash | **3** (960767 / 960768 / 960771) | 3× over-count |
| the chain (ruled) | **1** | matches MVP-SPEC.md line 19 |
| none | **0** | contradicts `headline_eligible_count() >= 1` |

And the height is not even evidence-selected. `crates/antseal-anchor/src/ots/engine.rs:447-458`
takes `merged.added.first()` — *"The header is fetched once per artifact:
A14's `Do` says 'on the first Bitcoin attestation'"* — so **which** of the
three heights lands in the D79 `OtsUpgrade` is a function of merge order.
`crates/antseal-core/src/bundle/schema.rs:457-461` confirms the group holds
exactly one height and one header, so an artifact with three Bitcoin
attestations reports one arbitrary block.

## 4. The candidates, weighed

**(a) The confirming Bitcoin block — height, or height+hash.** Rejected.
It over-counts 3× on the measured honest case (§3); the recorded height is
chosen by merge order, not evidence (§3), so it is sealer-controlled in the
same way the calendar set is; and it answers the wrong question —
"independent of what?" is about failure modes, and two heights of one chain
share every one of theirs. Height+hash is strictly worse than height: it
adds bytes and changes nothing, since O3 already byte-compares the whole
80-byte header against the online-agreed one, so the hash is implied.

**(b) One opaque "Bitcoin" identity, shared by every `proven` OTS anchor.**
**RULED.** §1's definition of independence gives it directly; §1's spec
citations agree; it is the only candidate whose value cannot be influenced
by the sealer, because it is a constant.

**(c) The calendar set (status quo).** Rejected on §2 — it is a
bundle-recorded string, invariant under the transition it is supposed to
characterise, set-valued, and it counts as witnesses parties that D54 §4
proves cannot lie about the proposition.

**(d) No identity at all for OTS.** Rejected, and it is the one candidate
whose rejection is not about over-counting. It breaks a property the count
must have: today `distinct_verified_identities() == 0` **iff**
`aggregate().is_unanchored()`, which is the natural reading of the number
and the one every existing zero-assertion in `verdicts/tests.rs` relies on
(lines 1492, 1506, 1575). Under (d) a bundle whose only headline-eligible
anchor is a `proven` OTS reports one headline-eligible anchor and *zero*
verified identities — a verifier saying "no verified identity" about
something it just verified. Under-counting is safe; saying nothing was
verified when something was is a different error, and it is a false
statement rather than a weak one.

**(e) The agreeing online endpoint set (found while weighing, not in the
brief).** O3's promotion also depends on D55/A16's must-agree esplora pair,
so one could key on it. Rejected: the endpoint set is verifier-side and
identical for every anchor in one run, so it collapses to exactly one
identity — the same answer as (b) at more cost, and with the defect that
the count would change when the *verifier* reconfigures endpoints, which
is not a property of the evidence.

## 5. The ruling

### 5.1 The identity

A headline-eligible OTS anchor contributes the single identity
**`AnchorIdentity::BitcoinChain`**. It carries no height, no hash, no
calendar and no payload. Every `proven` OTS anchor in a bundle contributes
the same value, so the whole OTS mechanism contributes **at most 1** to
`distinct_verified_identities()`, for any number of artifacts, calendars,
blocks or bundles.

### 5.2 The type

`AnchorIdentity::OtsCalendars(Vec<String>)` is **deleted**. It has no
consumer outside `verdicts.rs` and its own tests (verified by repo-wide
grep: zero hits in `antseal-cli`, `antseal-anchor`, `antseal-net`,
`verifier-web`, `fuzz`, `probes`, `scripts`, `docs`, `tasks`,
`MVP-SPEC.md`), so deletion is a contained change, not a deprecation
window.

```rust
pub enum AnchorIdentity {
    TsaSigner { subject_dn_der: Vec<u8> },   // unchanged
    BitcoinChain,                            // replaces OtsCalendars
}
```

**One arm per independent mechanism** is the invariant the type now
carries: an arm is what a compromise takes out. A future Litecoin or
Ethereum OTS attestation (D56 rule O9 names both as live shapes) is a *new
arm*, added deliberately with its own independence argument — not a
`ChainId` payload that a later lane can extend without making that
argument. The type is in-memory only; it appears in no wire format and in
no report byte (`AnchorResult` has five fields, frozen), so adding an arm
is a source change and never a format event.

### 5.3 Per state

| OTS state | headline-eligible | identity passed | identity kept | contributes |
| --- | --- | --- | --- | --- |
| `proven` (O3) | yes | `Some(BitcoinChain)` | yes | 1, shared |
| `attested` (O4) | no | `Some(BitcoinChain)` | no (filtered) | 0 |
| `pending` (O5) | no | **`None`** (was `Some(OtsCalendars)`) | no | 0 |
| `invalid` (O1/O6–O8) | no | `None` | no | 0 |
| `internally-consistent-only` (O9) | no | `None` | no | 0 |
| `absent` (O0) | no | — (no outcome) | — | 0 |

`attested` keeps `Some(...)` so that the headline-eligibility filter at
`verdicts.rs:339` remains the **single** enforcement point — A40's stated
design, and the thing §9's T3 must witness. `pending` moves to `None`
because there is no Bitcoin block behind it at all; passing an identity
that is silently dropped is how the current code hid the question.

**The block height is not lost.** `bitcoin_source`
(`verdicts.rs:817-828`) already renders it into the verdict's `source` as
`AnchorSource::Verified("bitcoin-block-{H}")`, which R12 projects into the
report. The source says *what* attested; the identity says *who*. For a TSA
those coincide; for Bitcoin one witness signs many blocks. Nothing a user
sees loses a height.

### 5.4 The mixed count, in closed form

```
distinct_verified_identities()
  = |{ signer subject DN : headline-eligible TSA anchors }|
  + (1 if any headline-eligible OTS anchor else 0)
```

A TSA identity and an OTS identity can **never** be equal: they are
different enum arms, so `PartialEq` separates them structurally rather than
by a rule anyone must remember. The number is therefore "how many mutually
independent attesting parties this bundle establishes", and it is the
correct thing to render.

### 5.5 A kind-scoped accessor, and the A20 foot-gun it closes

Add:

```rust
/// How many distinct verified identities of one kind the headline-eligible
/// anchors establish. Never `>= 2` for `AnchorKind::Ots` (D92 §5.1).
#[must_use]
pub fn distinct_verified_identities_of(&self, kind: AnchorKind) -> usize
```

This is not decoration. **A40's `Do` instructs A20's gate to read the mixed
scalar** (*"have A20's gate and R17's divergence rule read that rather than
`anchors.len()`"*), and A20's own rule is *"proceed iff ≥1 TSA token passed
full core verification"* with an Accept row requiring *"a gate-passing seal
always holds ≥1 offline headline-eligible anchor (`proven` TSA)"*. A gate
written as `distinct_verified_identities() >= 1` would be satisfied by a
bundle with **zero** TSA anchors and one `proven` OTS. D54 §3 already ruled
the boundary — *"**OTS contributes exactly zero to A20's minimum-anchor
gate**"* — so the scalar must not be the gate's input, and the kind-scoped
form is what makes the correct thing spellable. A40's `Do` is amended
accordingly (§10).

### 5.6 What a consumer is entitled to say

The datum is wording-free; R18/R61 own every string. What the *number*
licenses:

**Permitted**

- "at least N mutually independent parties attest to this seal" — it is a
  conservative lower bound, never an upper one;
- `N == 0` ⟺ UNANCHORED (the invariant of §4(d));
- naming the parties by iterating `verified_identities()`;
- rendering artifact counts and endpoint counts **separately and
  differently labelled** — "3 anchors" and "2 independent parties" are both
  true and are different claims.

**Forbidden**

- "exactly N independent anchors", or any phrasing that presents N as a
  count of artifacts, tokens, calendars, endpoints or blocks;
- using N as A20's minimum-anchor gate input (§5.5) — the gate reads
  `AnchorSubmission::verified_tsa_count()` at seal time and, if it ever
  reads a verify-time number, `distinct_verified_identities_of(Tsa)`;
- "N Bitcoin confirmations" or any suggestion that a second `.ots`
  strengthens the Bitcoin claim — a second observation of one witness adds
  redundancy and possibly an earlier time (which R17's earliest-headline
  rule already extracts), never independence;
- deriving divergence from N. R17's >48 h rule compares *times* across
  headline-eligible anchors and is untouched by this decision.

## 6. Direction of error, stated

This ruling **under-counts**, deliberately, and in two places: two `.ots`
at different heights count 1, and (unchanged from A40) a TSA that rotates
its signing key counts 1. Both are acceptable because a lower bound on
independence is a weaker claim, never a false one — the same asymmetry
MVP-SPEC.md relies on for "existed **no later than** T".

One correction to how the irreversibility is usually stated in this
project: registry §8's *"this is the **irreversible** direction — permissive
now cannot be tightened after the freeze"* is about the **wire format**,
which is why the check was pushed into the verdict layer at all. The
verdict layer is code and can be changed. What cannot be changed is what
users were already told: a bundle verified today prints an independence
claim, and there is no channel to reach that reader and retract it. So
over-counting here is irreversible **in the claim**, not in the code, and
that is the sense in which the safe direction is mandatory.

## 7. Measured versus assumed

**Measured (read off the tree or off committed captures):**

- the three real 2026-08-03 blocks 960767/960768/960771, one digest
  (`UPGRADE-CAPTURE.log`; `ots/upgrade/tests.rs:454-460`;
  `D58-opentimestamps-viability.md:649-667`);
- pending attestations survive upgrade, **enforced**
  (`antseal-anchor/src/ots/upgrade.rs:356-358, 377-388`;
  `ots/upgrade/tests.rs:290-306` asserts `3` pendings retained beside
  1/2/3 Bitcoin attestations);
- the recorded height is `merged.added.first()`
  (`antseal-anchor/src/ots/engine.rs:451-458`);
- `OtsUpgrade` holds exactly one height and one 80-byte header
  (`bundle/schema.rs:457-461`);
- `attested` is not headline-eligible, by exhaustive match
  (`verify/aggregate.rs:48-56`), and the identity filter is
  `verdicts.rs:339`;
- `AnchorIdentity` and both count accessors have **zero** consumers outside
  `verdicts.rs` and `verdicts/tests.rs`; `evaluate_anchors` is called only
  from those tests (R12 owes the pipeline call, `TODO.md:399`);
- the LARGE_TEST fixture carries Bitcoin attestations with derived roots at
  **both** 449397 and 449399 (`anchor/ots/tests.rs:194-222`), which is what
  makes §9's T1 buildable from real material today;
- A31's `TsaSignerIdentity` is `(issuer_der, serial)`
  (`anchor/tsa.rs:172-212`), a different key from A40's `subject` DN
  (`verdicts.rs:233-236`);
- the seal gate reads `verified_tsa_count()`, not `distinct_tsas()`
  (`antseal-anchor/src/submit.rs:111-113, 267-268`).

**Assumed (and flagged):**

- that no future v1.x wire change makes `AnchorIdentity` serializable. It
  is in-memory only today and the ruling depends on that only for the "new
  arm is not a format event" claim.
- that R17's overlay verdict reuses A18's O3 promotion rather than adding a
  second promotion route. If it adds one, §5.3's table must be re-read
  against it.

**No cargo build or test was run for this decision.** Every claim above is
read from source, from committed fixtures, or from assertions in tests that
are currently green; nothing here needed a measurement the tree does not
already carry.

## 8. What implementers must change

`crates/antseal-core/src/anchor/verdicts.rs`:

1. Replace the `OtsCalendars(Vec<String>)` arm with a unit
   `BitcoinChain` arm; rewrite its rustdoc to §1/§5.1 (cite D54 §4 and
   MVP-SPEC.md line 19, not A40's `Do`).
2. `evaluate_ots_artifact`: delete the
   `let identity = AnchorIdentity::OtsCalendars(calendars);` binding at
   `verdicts.rs:600`. Pass `Some(AnchorIdentity::BitcoinChain)` at the O3
   arm (`:657-666`) and the O4 arm (`:683-691`); pass `None` at the O5 arm
   (`:701-705`). O1/O6–O8/O9 already pass `None` — leave them.
3. Keep `calendars_of` and `calendar_source` unchanged: they still build
   the `pending`/`invalid`/`internally-consistent-only` source strings
   (`verdicts.rs:598-599`), which is the only place calendars belong.
   Amend `calendars_of`'s doc, which currently ends *"That matters for A40:
   the identity is about who the artifact points at"* — after this ruling
   it matters for the **source string**, not for the identity.
4. Add `AnchorVerdicts::distinct_verified_identities_of(kind)` (§5.5) with
   the A20 warning in its rustdoc.
5. Update `AnchorIdentity`'s type-level rustdoc and
   `distinct_verified_identities`'s rustdoc: the current text *"A
   byte-identical duplicate `.ots` is **one**"* stays true but is now the
   weakest statement the rule makes; state the strong one ("every
   headline-eligible OTS anchor in a bundle is one identity, whatever its
   blocks or calendars").
6. Module header: add D92 beside D53/D56 in the list of what this module
   implements.

Nothing changes in `antseal-anchor`, `antseal-cli` or the report
projection. No wire byte, no golden vector, no report vector, no error code
moves. `seal-core` stays WASM-safe (the change removes an allocation, adds
none).

## 9. The tests, and the planted fault that proves each can report red

> **Corrected 2026-08-06 by the implementing lane (A67), which built them.**
> Two rows below are unbuildable exactly as specified, and both corrections
> make the suite *stronger*, not weaker:
>
> - **T6 could not exercise its own TSA term.** `evaluate_anchors` takes one
>   `anchor_digest` for the whole bundle, so a real TSA capture (stamped over
>   `D60_STAMPED`) and T1's OTS anchors (over `DIGEST_UPGRADED`) cannot both
>   verify. Every subset would have measured `0 + {0,1}`, and a `+ 0`
>   implementation of the TSA term would have survived the row unchanged — a
>   vacuous quantifier of exactly the kind §9 exists to prevent. Fixed with a
>   mixed sub-case inside T6: four real tokens → three TSA identities, plus one
>   `proven` OTS → total 4.
> - **T2's fixture needs a height T1 does not use.** `BlockEvidence` is
>   height-keyed with one result per height, so in T6's combination the two
>   artifacts' headers collide. `SYNTHETIC_HEIGHT = 700_001` is used.


Two anti-vacuity facts the lane must know before writing anything:

- **The one existing OTS identity test cannot see this question.**
  `a_duplicate_ots_counts_one_identity_and_still_verifies`
  (`verdicts/tests.rs:1424-1457`) uses two byte-identical artifacts, so it
  asserts `1` under the calendar key, the block key **and** the chain key
  alike. It excludes only candidate (d). It is not a witness for the
  ruling and must not be cited as one.
- **The eligibility filter has no OTS-side witness.**
  `an_upgraded_ots_is_attested_offline_and_carries_no_time`
  (`verdicts/tests.rs:529-544`) asserts state, time, eligibility and
  suppressed — never `.identity()`. The filter at `verdicts.rs:339` is
  falsifiable today only through the TSA path
  (`claimed_identities_contribute_nothing`, `:1461-1507`), so an
  OTS-specific bypass is currently invisible.

All helpers below already exist in `crates/antseal-core/src/anchor/verdicts/tests.rs`:
`UPGRADED`/`DIGEST_UPGRADED` (:60-66), `derived_root` (:157), `header_with`
(:145), `committing_upgrade` (:179), `evidence_header` (:199), `container`
(:234), `pending` (:252), `bitcoin`, `fork`, `ots_anchor` (:96),
`ots_offline` (:288), `synthetic_digest`.

| # | test | asserts | planted fault that MUST turn it red |
| --- | --- | --- | --- |
| **T1** | `two_bitcoin_heights_are_one_identity` | two anchors over the **same real** `UPGRADED` bytes, upgrade groups at **449399** and **449397** (both real, both with derived roots — `ots/tests.rs:210-222`), online evidence carrying both headers. Anti-vacuity first: both `Proven`, `headline_eligible_count() == 2`. Then `distinct_verified_identities() == 1` | re-key on the block: `AnchorIdentity::BitcoinBlock { height: u.block_height() }` → 1 becomes 2 |
| **T2** | `disjoint_calendars_at_one_height_are_one_identity` | **the recorded A67 risk, exactly.** Two synthetic artifacts over one `synthetic_digest`, each `container(&d, &fork(&[pending(<distinct uri>), bitcoin(H)]))`, one upgrade group `OtsUpgrade::new(H, header_with(&d, NTIME), …)` each, one online header. Both `Proven` at one height, disjoint calendars → `distinct_verified_identities() == 1`. Anti-vacuity: evaluate the same two byte-strings **with no upgrade group** → both `Pending`, and assert their two `source` strings differ, proving the calendar sets really are disjoint | restore `AnchorIdentity::OtsCalendars(calendars_of(&artifact))` at the O3 arm → 1 becomes 2. **This is the row the status quo fails.** |
| **T3** | `an_attested_ots_contributes_no_identity` | one `attested` OTS (`ots_offline(UPGRADED, …, Some(committing_upgrade()))`) → `outcome.identity().is_none()`; and in a bundle with one `proven` TSA, `distinct_verified_identities() == 1` | (i) delete `.filter(|_| verdict.is_headline_eligible())` at `verdicts.rs:339`; (ii) the OTS-specific bypass `verdict.is_headline_eligible() \|\| verdict.kind() == AnchorKind::Ots`. **Only T3 catches (ii)** — the existing TSA-path test catches (i) alone |
| **T4** | `a_lone_proven_ots_establishes_one_identity` | one `proven` OTS, no TSA → `distinct_verified_identities() == 1`, `!aggregate().is_unanchored()`; plus the invariant `(count == 0) == is_unanchored()` over all fixtures in the module | candidate (d): `None` at the O3 arm → 1 becomes 0 |
| **T5** | `a_tsa_and_an_ots_are_two_independent_identities` | one `proven` TSA (`DIGICERT`) + one `proven` OTS → `2`, and the set matches **one of each arm** by pattern, not merely by cardinality | the lazy implementation: express the OTS identity as `TsaSigner { subject_dn_der: b"bitcoin".to_vec() }` instead of adding an arm → the pattern assertion fires even though the count is still 2 |
| **T6** | `the_ots_contribution_is_never_more_than_one` | over every combination of {T1's two anchors, T2's two anchors} in a single bundle: `distinct_verified_identities_of(AnchorKind::Ots) <= 1`, and the total equals §5.4's closed form | either T1's or T2's fault → some combination reports 2 |
| **T7** | amend `a_duplicate_ots_counts_one_identity_and_still_verifies` | add a doc line recording that it is **insensitive** to D92 and excludes only candidate (d), so no later reader cites it as the witness | — (documentation row; T1/T2 carry the falsifiability) |

Every row must state its planted fault in its own rustdoc, in this
project's usual form, so a later reader can re-plant it without rederiving
it.

**Not required, and deliberately so:** no new fixture, no `MATRIX.json`
row, no golden vector, no error code, no wasm32-specific test. The change
touches no byte any of those pin, and A22's native-vs-wasm32 bit-match
covers the module already.

## 10. Register, task rows, amendments

### 10.1 Register entry for `TODO.md` "Due M2" (orchestrator pastes)

- [x] **D92** *(minted 2026-08-06, mid-round)* What does a `proven` OTS anchor contribute to the anchor-independence count — the calendar set, the Bitcoin block, or the chain? (A67/A40; consumed by A20, R17, U22) — **Resolved 2026-08-06** (docs/decisions/D92-proven-ots-anchor-identity.md): **the chain** — one opaque `AnchorIdentity::BitcoinChain` shared by every headline-eligible OTS anchor whatever its height or calendars, `OtsCalendars` **deleted**. The recorded risk was right and understated it twice: the calendar set is not merely an over-count, it is a **sealer-chosen, bundle-recorded string** — the exact input A40's own `TsaSigner` rustdoc forbids — and it is **provably invariant across `pending → attested → proven`**, because `antseal-anchor`'s merge is a pure insertion that *enforces* attestation retention (`ots/upgrade.rs:356-358`); and the over-count needs **no adversary**, since the measured 2026-08-03 cycle put one digest's three calendars in **three different blocks** (960767/960768/960771), which both the calendar key and the block key score as **3** where MVP-SPEC.md line 19's own model ("OpenTimestamps (Bitcoin) + ≥2 TSAs") scores **1**. The block key fails for a second reason: which height reaches the D79 upgrade group is `merged.added.first()` (`ots/engine.rs:451-458`), i.e. **merge order, not evidence**. D54 §4 already ruled calendars are not witnesses at all (*"calendar compromise is a denial-of-service, not a forgery"*; no key exists to pin). Two heights of one chain are **one identity, two data points** — same PoW, same reorg, same must-agree esplora pair, joint failure. "No identity for OTS" rejected on a different ground: it would break `count == 0 ⟺ UNANCHORED` and make the verifier say nothing was verified about something it verified. Also ruled: **A20's gate must never read the mixed scalar** (A40's `Do` instructs exactly that, and a lone `proven` OTS would clear a `>= 1` test whose spec says "≥1 TSA token" — D54 §3: *"OTS contributes exactly zero to A20's minimum-anchor gate"*), so a kind-scoped `distinct_verified_identities_of(AnchorKind)` is added and A40's `Do` amended. Three findings underneath: the eligibility filter has **no OTS-side witness** (every test that can see it goes through the TSA path); the one existing OTS identity test **cannot distinguish three of the four candidates**, so A40's OTS half has never been pinned by a falsifiable row; and `antseal-core` holds **two disagreeing TSA identity notions** — A31's `(issuer, serial)` vs A40's `subject` DN — of which the **seal-side one over-counts** (a key rotation reads as two TSAs) and is the one U22 prints → **A72**. Errs toward under-counting, stated: registry §8's irreversibility is about the *format*; here it is the **published claim** that cannot be retracted. Zero wire bytes, zero vectors, zero codes; contained to `verdicts.rs` — the count has **no consumer in the tree today** and `evaluate_anchors` is still called only from its own tests

### 10.2 New task row for `TODO.md` (A domain, M2, next to A40)

- [ ] **A67** (S) Re-key the OTS half of anchor identity onto Bitcoin, not calendars (D92) — after A40, before A20/R17 read the count (D92) 🔴

### 10.3 Full `tasks/A.md` entry for A67 (none exists)

```
### A67 — Re-key the OTS half of anchor identity onto Bitcoin, not calendars
- Milestone: M2
- Size: S
- Deps: A40 (the type and both count accessors exist); blocks A20's degradation report and R17's aggregate reading the count
- Discovered by: **A40** (2026-08-05), which implemented its own `Do` literally and recorded the consequence rather than re-ruling it; registered as a row and resolved by **D92** (2026-08-06).
- Problem: A40's `Do` makes a `proven` OTS anchor's identity the set of calendars its attestations name. What proved it is Bitcoin. The calendar URI is a **bundle-recorded string** — the exact input A40's own `TsaSigner` rustdoc forbids — it is chosen by the sealer at submit time, and `antseal-anchor`'s merge *enforces* that upgrading never drops an attestation (`crates/antseal-anchor/src/ots/upgrade.rs:356-358`), so the value is byte-identical before and after the anchor becomes `proven`. It is also set-valued, so overlapping calendar sets count as distinct identities. The measured 2026-08-03 cycle produces the over-count with no adversary: one digest, three calendars, **three different Bitcoin blocks** (960767/960768/960771), which the calendar key and the block key both score as 3 against MVP-SPEC.md line 19's 1.
- Spec: Anchoring — OTS online promotion (MVP-SPEC.md lines 19, 108); verdict taxonomy and headline (lines 129–137); `docs/format/registry-v1.md` §8; `docs/decisions/D92-proven-ots-anchor-identity.md`; D54 §4 (a calendar is not a witness), D56 rule O3
- Do: Apply D92 §8. Replace `AnchorIdentity::OtsCalendars(Vec<String>)` with a unit `AnchorIdentity::BitcoinChain`; pass it at D56's O3 and O4 arms only and `None` at O5; keep `calendars_of`/`calendar_source` for the `pending`/`invalid`/`internally-consistent-only` source strings and amend their docs to say so. Add `AnchorVerdicts::distinct_verified_identities_of(kind: AnchorKind)`, whose rustdoc records that **A20's gate must read the TSA-scoped count, never the mixed scalar** (D54 §3). Rewrite `AnchorIdentity`'s and `distinct_verified_identities`'s rustdoc onto D92 §1/§5 and off A40's `Do`. Touch no wire byte, no vector, no error code, no crate but `antseal-core`.
- Accept:
  - Two `proven` OTS anchors at **different real Bitcoin heights** (449399 and 449397, both in the committed `LARGE_TEST` fixture) are **one** identity, with `headline_eligible_count() == 2` asserted first so the row is not vacuous (D92 §9 T1).
  - Two `proven` OTS anchors at **one height through disjoint calendar sets** are **one** identity, with the disjointness witnessed by evaluating the same bytes without an upgrade group and comparing the two `pending` source strings (D92 §9 T2). This row fails under the pre-D92 code.
  - An `attested` OTS anchor's `identity()` is `None` — the first OTS-side witness for the eligibility filter, which today is falsifiable only through the TSA path (D92 §9 T3).
  - A lone `proven` OTS establishes **one** identity and is not UNANCHORED; `distinct_verified_identities() == 0` iff `aggregate().is_unanchored()` (D92 §9 T4).
  - A `proven` TSA plus a `proven` OTS is **two**, asserted by matching **one of each enum arm**, not by cardinality alone (D92 §9 T5).
  - `distinct_verified_identities_of(AnchorKind::Ots) <= 1` over every combination of the module's OTS fixtures, and the total equals D92 §5.4's closed form (D92 §9 T6).
  - Every row states its planted fault in its own rustdoc (D92 §9's table is the source).
  - `cargo clippy` clean; `antseal-core` still builds for `wasm32-unknown-unknown`; no golden vector, report vector, `MATRIX.json` row or error code changes.
- Notes: `AnchorIdentity` is in-memory only — it appears in no wire format and in no report byte — so deleting an arm is a source change, never a format event. It also has **zero** consumers outside `verdicts.rs` and its tests today, which is why this is cheap now and expensive after R12 wires `evaluate_anchors` into the pipeline. A future Litecoin/Ethereum OTS attestation (D56 rule O9) gets its **own arm**, deliberately, with its own independence argument — never a payload on `BitcoinChain`.
```

### 10.4 Amendments to A40 in `tasks/A.md`

**A40's row stays OPEN.** Closing it while its own `Do` specifies a rule
the product no longer implements is this project's dominant defect class
committed on purpose. A40 closes when A67 lands, in the same commit.

Replace the OTS clause in A40's `Do`. Current:

> for an OTS anchor, the set of calendar URLs its attestations name

Replacement:

> for an OTS anchor, the **chain that proved it** — a single opaque Bitcoin
> identity shared by every headline-eligible OTS anchor whatever its block
> or calendars (**D92**; the calendar set was A40's original text and is
> overturned there, because a calendar URI is a sealer-chosen
> bundle-recorded string that D54 §4 shows is not a witness at all)

Replace the consumer clause in A40's `Do`. Current:

> and have A20's gate and R17's divergence rule read that rather than
> `anchors.len()`

Replacement:

> and have R17's rendering read the identity count rather than
> `anchors.len()`. **A20's gate reads the TSA-scoped count, never the mixed
> scalar** (`distinct_verified_identities_of(AnchorKind::Tsa)`, or the
> seal-time `AnchorSubmission::verified_tsa_count`): D54 §3 rules that OTS
> contributes exactly zero to the minimum-anchor gate, so a `>= 1` test
> over the mixed scalar would pass a bundle with no TSA at all. R17's
> **divergence** rule compares times, not identities, and reads neither.

Add to A40's `Accept`, after row 2:

> - Two `proven` OTS anchors at different Bitcoin heights, or at one height
>   through disjoint calendar sets, are **one** identity (D92; implemented
>   at A67).

Add to A40's `Notes`:

> The OTS half shipped literally to this task's original `Do` and the
> consequence was recorded rather than re-ruled; **D92** resolves it and
> **A67** implements it. Two further findings from that review: the
> eligibility filter that makes `attested` contribute zero has no OTS-side
> witness, and `a_duplicate_ots_counts_one_identity_and_still_verifies`
> cannot distinguish the calendar key from the block key from the chain key
> — it excludes only "no identity for OTS". Both are A67's to fix.

## 11. Discovered work

Only IDs from this planner's pre-allocated block are used: **A72–A79**,
**Q88–Q91**. **A73, A75, A77, A78, A79, Q90 and Q91 are deliberately left
unallocated** — nothing found here justified them, and burning IDs to look
thorough makes them permanently unusable.

### A72 — Reconcile the two disagreeing TSA identity notions in `antseal-core`

`antseal-core` holds two, minted five days apart, keyed differently, both
called the identity of a TSA:

- **A31** — `TsaSignerIdentity { issuer_der, serial }`
  (`crates/antseal-core/src/anchor/tsa.rs:172-212`), per **certificate**.
  Its rustdoc: *"Two tokens with equal identities were signed by the same
  key under the same certificate."*
- **A40** — `AnchorIdentity::TsaSigner { subject_dn_der }`
  (`crates/antseal-core/src/anchor/verdicts.rs:233-236`), per **name**.
  Its rustdoc: *"a TSA that rotates its signing key issues two tokens under
  two keys and one name, and counting keys would report a rotation as two
  independent anchors."*

They disagree on the same seal: a TSA that rotated between two captures
reads **2** at seal time (`AnchorSubmission::distinct_tsas`,
`antseal-anchor/src/submit.rs:124-126`) and **1** at verify time. The
seal-side number is the one that **over-counts** — registry §8's forbidden
direction — and it is the one U22's degradation report prints. Both
rustdocs argue their case well; neither knows the other exists. Size S.
Owner: A domain, M2 (before U22's report renders `distinct_tsas`).

### A74 — `MIN_VERIFIED_TSA_TOKENS`'s doc claims §8's obligation is applied where it is not

`crates/antseal-anchor/src/submit.rs:284-292` says the constant is named so
*"a reader can see the gate is counting `AnchorSubmission::verified_tsa_count`
rather than `attempts.len()` — registry §8's obligation (A40) applied at
the only place it can currently bite"*, and that *"a future ≥2 policy is a
one-line change"*. `verified_tsa_count()` is a count of verified
**captures** (`submit.rs:111-113`); the identity count is `distinct_tsas()`
(`:124-126`). At a threshold of 1 the two agree, so nothing is wrong today
— but the advertised one-line change to 2 would accept **two tokens from
one TSA** as two anchors, which is registry §8's named defect verbatim
(*"a sealer wanting two 'independent' TSA anchors from one TSA simply
requests two tokens"*). Fix the doc to say what is actually applied, and
add a guard test that pins "the threshold is compared against an identity
count" so the one-line change cannot silently be the wrong one. Size XS.

### A76 — The recorded Bitcoin height is chosen by merge order, not by evidence

`crates/antseal-anchor/src/ots/engine.rs:451-458` fetches the header for
`merged.added.first()`. With the measured three-block artifact
(960767/960768/960771) the bundle therefore records whichever calendar was
merged first. D92 makes this irrelevant to the *identity* count, but it is
not irrelevant to the **time**: block heights minutes-to-an-hour apart have
different `nTime`, so an artifact can record a later provable time than its
own evidence supports. The direction is safe under "existed no later than
T" (a later T is weaker, never false) but it silently discards the user's
strongest available evidence, and MVP-SPEC.md line 137's headline is the
**earliest** headline-eligible time. Decide whether the engine should
select the earliest committing height rather than the first merged one,
and price the extra header fetch. Size S. Owner: A domain, M2/M3.

### Q88 — Do two TSA signers chaining to one pinned root count as one identity?

A40's DN key counts them **2**; A31's Notes rule the same way on purpose
(*"two genuinely different TSAs operating under one root still count as
two. TSA resale and white-labelling are ordinary in this market"*). That is
a defensible position and it is currently ruled by a **task Note**, not by
a decision, even though it is the same over-count class registry §8 exists
to close — one root compromise or one CA revocation takes out both. Either
ratify it in a decision with the reasoning that is currently buried in
A31's rustdoc, or tighten it. Note the measured near-miss that makes it
live: Sectigo and Entrust already share a *certificate*, so the tree has no
fixture for the same-root-different-signer case and would not notice a
change either way.

### Q89 — "distinct calendars" and "independent identities" are two numbers that will print side by side

D54 §3's submission outcome is keyed on *"the number of distinct normalized
pending-attestation URIs"* (≥2 = `Complete`, 1 = `Thin`, 0 = `Absent`) —
correct there, because it is a **liveness** metric for redundancy of
upgrade routes. D92 rules that the same three calendars are **one**
independent identity. U22's seal summary and A20's degradation report will
render both, and "2 distinct calendars, 1 independent party" reads as a
contradiction unless the labels carry the distinction. R18/R61 own the
wording; this question is whether the *datum* names need to diverge
(e.g. `distinct_calendar_routes` vs `distinct_verified_identities`) so the
rendering layer cannot conflate them by accident.

## 12. Residual risks and revisit triggers

- **A second chain.** If antseal ever implements a Litecoin or Ethereum OTS
  attestation, that is a new `AnchorIdentity` arm and this decision's
  reasoning must be re-run for it — specifically whether the new chain's
  security is genuinely disjoint from Bitcoin's (merge-mined chains are
  not). Trigger: any change to `OtsAttestation`'s known-type set.
- **R17's overlay.** R17's `Do` describes an online-augmented computation
  distinct from the offline verdict. If it introduces a promotion route
  other than D56's O3, §5.3's table must be checked against it before the
  overlay renders a count.
- **`AnchorIdentity` becoming serializable.** The "new arm is not a format
  event" claim holds only while it stays in-memory. Trigger: any `serde`,
  `minicbor` or report-field addition naming it.
- **The count acquiring a consumer.** It has none today. The first wiring
  (R12 into `verify/pipeline.rs`, then A20/R17/U22) is the moment §5.6's
  permitted/forbidden list stops being advice and starts being reviewable.

## Index row (orchestrator applies at merge)

| [D92](D92-proven-ots-anchor-identity.md) | What a `proven` OTS anchor contributes to the independence count — **the chain, not the calendars and not the block**. One opaque `AnchorIdentity::BitcoinChain` for every headline-eligible OTS anchor; `OtsCalendars` deleted. A40's recorded risk confirmed and sharpened twice over: the calendar set is a **sealer-chosen bundle-recorded string** (the input A40's own `TsaSigner` rustdoc forbids) and is **invariant across `pending → attested → proven`** because the merge *enforces* attestation retention; and the over-count needs **no adversary**, since the measured 2026-08-03 cycle put one digest's three calendars in **three blocks** (960767/960768/960771) — scored 3 by both the calendar key and the block key, 1 by MVP-SPEC.md line 19. The block key fails again on `merged.added.first()`: the recorded height is merge order, not evidence. Two heights of one chain are one identity and two data points. "No identity for OTS" rejected for breaking `count == 0 ⟺ UNANCHORED`. **A20's gate must never read the mixed scalar** (A40's `Do` said it should) → kind-scoped accessor added, A40's `Do` amended. Found: the eligibility filter has no OTS-side witness; the one existing OTS identity test cannot distinguish three of four candidates; two disagreeing TSA identity notions, the seal-side one over-counting → A72. Errs toward under-counting; §8's irreversibility restated as being about the **published claim**, not the code. Zero wire bytes, zero vectors, zero codes | RESOLVED | 2026-08-06 |
