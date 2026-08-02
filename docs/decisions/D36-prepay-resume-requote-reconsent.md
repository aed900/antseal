# D36 — Pre-pay resume: always re-quote (a journaled quote is never paid) and consent is per-invocation — `pay()` runs only after an affirmative consent obtained in the same process invocation against the fresh quote; "changed" governs display, never gating

- **Status: RESOLVED. The register's lean — "on cost change, re-consent"
  — is confirmed in direction and sharpened into an invariant, and the
  task-text split behind it is arbitrated: S11's conditional
  ("re-consent via U **if cost changed**", `tasks/S.md:144,150`) is
  OVERTURNED; U17's unconditional wording ("resume-pre-pay path
  re-prompts consent", `tasks/U.md:211,213`) is ratified and now has a
  decision behind it instead of an admitted inference. Grounds: (1)
  re-quoting is mandatory anyway — the quote-validity clock runs from
  node-signed quote-creation time, nothing in the pay path checks age
  before moving tokens, and paying an aged quote manufactures the
  stranded-payment state D37 Decision 6 exists to mop up; (2) once
  re-quoting is mandatory, "only if changed" saves one keypress on a
  rare path at the price of a persisted cross-process consent baseline,
  gas-jitter comparison semantics, and the demotion of U13's
  per-invocation mock invariant into a stateful cross-process property;
  (3) "unchanged" is not even well-defined below the totals — two quote
  rounds never byte-match (fresh node-signed timestamps per quote).
  One rule falls out: **consent is a single-use spend authorization
  consumed by the `pay()` it immediately precedes, in the same process
  invocation** — which also subsumes D37's proofs-expired
  re-consent-before-re-payment rule and U17's no-consent-post-receipt
  rule as corollaries rather than special cases.**
- **Date: 2026-08-01** (M1 Storage planning wave)
- **Owner: S11 (resume logic), U17 (resume UX wiring), U14 (the consent
  gate that re-fires), S10/U9 (the consent record the render reads)**
- **Blocks: S11, U17 (register "Pre-pay resume re-quote/re-consent
  policy on cost change", due M1)**
- Companion: D37 (post-pay half: proof validity window, stranded-state
  re-consent), D32 (blob set fixed at plan time), D45 (sibling, in
  flight: resume detection/keying + resume-plan UX), D51 (sibling, in
  flight: `--json` × interactivity contract). Scope fences below.

## Context

The seal pipeline's kill window between the anchor gate and `pay()`
(MVP-SPEC.md lines 34, 90) leaves a work anchored, journaled, and
unpaid. The spec's resume text (line 145) covers re-upload and
finalize semantics but is silent on quotes and consent — U17's Notes
record exactly that: "Consent-on-resume rule is a U inference (spec
silent)" (`tasks/U.md:216`). Meanwhile the two owning task texts
disagree:

- S11 Do: "post-anchor/pre-pay (re-quote, re-consent via U **if cost
  changed**, then pay)"; Accept: "consent hook re-fires **when the
  quote changed**" (`tasks/S.md:144,150`) — conditional.
- U17 Do: "re-consent via U14 when no payment has happened yet; no
  re-consent when a receipt is journaled"; Accept: "resume-pre-pay path
  re-prompts consent" (`tasks/U.md:211,213`) — unconditional.

D36 owns this cost-change policy: the re-quote rule, the consent rule,
what "changed" means, and the non-interactive interaction. Detection,
keying, and the resume-plan presentation are D45's (sibling); the
global `--json`/interactivity posture is D51's (sibling).

The consent gate being re-fired is U14's permanence-consent gate: "ANT
+ ETH balances beside the *true, complete* quote … interactive confirm,
`--yes` for scripts" (MVP-SPEC.md line 34; `tasks/U.md:171-181`).

## Evidence (all re-verified 2026-08-01 against the pinned registry sources)

### The quote clock and what upstream does about it

| # | Fact | Citation |
| --- | --- | --- |
| 1 | `PaymentQuote.timestamp` is "The local node time when the quote was created" — the validity clock starts at quote **birth**, not at payment | `evmlib-0.9.0/src/data_payments.rs:78-79` |
| 2 | The timestamp is inside the quote's ML-DSA-65-signed bytes — a client cannot refresh it | `evmlib-0.9.0/src/data_payments.rs:83-87,146-159` (`bytes_for_signing` folds `timestamp` in) |
| 3 | Storers enforce a validity window on quotes inside payment proofs: "`QUOTE_MAX_AGE_SECS` in `ant-node`, currently 24 h. After that, storers reject the proof even if the file is otherwise resumable … at worst the user re-pays" | `ant-core-0.5.0/src/data/client/cached_single.rs:48-58` |
| 4 | Upstream's own client refuses to reuse anything older than 24 h **minus a 300 s safety margin**, judged per embedded quote timestamp | `ant-core-0.5.0/src/data/client/batch.rs:1049,1057` (constants), `:1143-1163` (`proof_is_safely_fresh` iterates `proof.peer_quotes` reading `quote.timestamp`) |
| 5 | On a broken/expired cache entry, upstream's remedy is uniform: "The chunk will re-quote+re-pay" | `ant-core-0.5.0/src/data/client/batch.rs:1119-1121` |
| 6 | **Nothing in the pay path checks quote age before moving tokens**: `pay_for_quotes` filters zero amounts, chunks by `MAX_TRANSFERS_PER_TRANSACTION`, submits — no timestamp read anywhere | `evmlib-0.9.0/src/wallet.rs:431-460` (whole payment loop; the file's only timestamp references are merkle-mode fields at `:166,199`) |
| 7 | The window is node-side policy, invisible in the client crates and changeable per node release | D37 residual 1; row 3's constant lives in `ant-node`, not in anything we pin |

### What the journal holds and what consent renders

| # | Fact | Citation |
| --- | --- | --- |
| 8 | S10's journal fields today: staged ciphertexts, nonces, target addresses, encrypted-manifest blob + address, plaintext manifest, `seal_id` — **no quote, no consent record** | `tasks/S.md:131` |
| 9 | U13's accept already asserts a per-invocation call-log invariant: "no payment call before consent returns affirmative" | `tasks/U.md:164` |
| 10 | The consent render is defined as current truth: file list, byte totals, the true complete quote, and **current** ANT + ETH balances beside it; distinct insufficient-ANT vs insufficient-gas errors | MVP-SPEC.md line 34; `tasks/U.md:176,180` |
| 11 | Quotes are not manifest content — the body field list (line 98) carries no cost/quote — so re-quoting touches nothing signed or anchored | MVP-SPEC.md line 98 |
| 12 | The blob set at pre-pay resume is fixed by construction: staged ciphertexts journaled before the anchor gate, integrity-checked on resume, abandoned if unavailable | `tasks/S.md:131,144`; MVP-SPEC.md line 145 |
| 13 | The consent step precedes the anchor gate in the normative order, so every post-anchor kill point has a consent already given — in a **dead process** | MVP-SPEC.md line 34; `tasks/S.md:158` |

## The overturn, stated plainly

The register asked what to do "on cost change" and leaned re-consent.
The lean survives; the *conditional framing* around it does not, twice:

**Re-quote is not a policy choice — reuse is a footgun.** Rows 1–3: a
journaled quote's validity clock has been running since quote birth,
under a node-side constant we cannot see (row 7). Row 6: the pay path
will happily move real ANT against an arbitrarily stale quote; the
failure surfaces only later, as storers rejecting the proofs — the
stranded state D37 Decision 6 defines, self-inflicted at resume time.
Even a *successfully* reusable quote silently spends validity window:
paying a 20-hour-old quote leaves ~4 h (minus margin, row 4) to finish
finalize before every proof dies. Upstream's own answer to every
staleness doubt is row 5: re-quote. Re-quoting is free, has no side
effects, and changes nothing anchored (rows 11–12). And S10 journals no
quote to reuse in the first place (row 8) — "compare and maybe reuse"
would have required *adding* journal surface to enable the hazardous
path.

**Once re-quote is mandatory, "only if changed" buys almost nothing and
costs real structure.** The condition cannot be evaluated without the
fresh quote, so no network work is saved; the only saving is one
keypress, on a rare path, for interactive users (scripts pass `--yes`
either way). Against that: (i) it needs a persisted consented-totals
baseline (a new cross-process journal artifact) plus comparison
semantics — and every sub-choice has a sharp edge: gas estimates
jitter, so "any increase" collapses to "always" in practice, while
"ANT-only" invites silent gas drift; per-line comparison is meaningless
because two quote rounds never byte-match (row 2 — fresh signed
timestamps per quote), so "unchanged" could only ever mean "same
displayed totals", a rounding coincidence rather than an identity;
(ii) it converts U13's clean call-log invariant (row 9) — consent
before pay, in this process — into "consent before pay, possibly in a
dead process days ago, validated by a stored comparison"; (iii) it
shows the user *stale* context by construction: U14's render is defined
as current balances beside the current quote (row 10), and a days-old
consent asserted none of what is true at pay time. The permanence gate
exists to put current truth in front of the user at the moment of
irreversible spend; the project's recorded posture on such trades is
safety over cost (the abandonment rule, MVP-SPEC.md line 145).

A threshold variant ("re-consent only above ±x%") is rejected outright:
it mints an arbitrary constant into a money gate with no spec basis and
a fuzzy edge ("a 9.9% increase paid silently").

## Decision

1. **Always re-quote.** A resumed seal never passes a journaled or
   otherwise previously obtained `CostQuote` to `pay()`. The pre-pay
   resume sequence is: staged-bytes integrity check (S11, unchanged) →
   fresh `quote_batch` over the journaled blob set → consent (rule 2) →
   `pay()` with **that** quote. S10 does not journal the `CostQuote`
   object as a payment input (it may keep quote metadata for
   diagnostics; nothing reads it on the pay path).
2. **Consent is per-invocation: no `pay()` without an affirmative
   consent obtained in the same process invocation, rendered against
   the fresh quote from rule 1.** No consent carries across process
   boundaries for the purpose of authorizing payment; a consent is
   consumed by the one `pay()` it precedes. Corollaries, not special
   cases:
   - initial seal: consent → anchor gate → pay (unchanged, line 34);
   - pre-pay resume (any post-consent kill point, row 13): re-quote →
     re-consent → pay;
   - post-receipt resume: no `pay()` occurs, so no consent prompt —
     U17's "no re-consent when a receipt is journaled" holds as the
     vacuous case, finalize-only;
   - D37's proofs-expired stranded state: completing the seal requires
     a new payment ⇒ a fresh in-invocation consent — exactly D37
     Decision 6's "distinct, consented error", now derived from one
     rule instead of stated separately.
3. **Declining the re-consent aborts the invocation and nothing else.**
   The work remains `incomplete` (pre-pay), resumable later at
   whatever the market then quotes. Decline is NOT abandonment —
   abandonment remains exclusively the staged-bytes-unavailable path
   (MVP-SPEC.md line 145; S11). No state transition is written on
   decline.
4. **"Changed" is display-level only.** Nothing gates on a comparison.
   The re-consent render MUST additionally show, when a prior consent
   record exists: the previously consented totals and their timestamp,
   with a visible flag when the fresh totals differ (either direction).
   Display comparison basis: total ANT exact (atto), gas estimate as
   rendered. This requires journaling a **consent record**
   `{total_ant_atto, gas_estimate, consent_time, channel:
   interactive|yes-flag}` at every affirmative consent — an S10/U9
   field addition (consequences). If the record is absent, render
   without the prior-consent line (defensive; by row 13 the normal
   post-anchor resume always has one).
5. **Non-interactive interaction — routed, not redefined.** Resume
   re-consent IS a U14 gate render; D36 creates no new interactivity
   semantics. `--yes` on the resume invocation affirms the fresh quote
   unconditionally — identical to initial-seal semantics ("consent to
   the true, current quote"). Interactive prompts. Non-TTY without
   `--yes` aborts per U3's existing contract (`tasks/U.md:176,181`),
   and the `--json` hard-abort posture is D51's to fix — whatever D51
   rules applies here uniformly because this is the same gate. A prior
   invocation's `--yes` never carries (it is a per-invocation channel,
   rule 2). Scripts wanting a spend ceiling have no vehicle today;
   recorded as a candidate (`--max-cost`), not decided here.
6. **Nothing anchored is touched.** Re-quoting and re-consenting alter
   no manifest byte and no anchor (row 11); anchors made before the
   kill remain valid and are not re-submitted. Balance shortfalls at
   resume surface through the existing distinct insufficient-ANT /
   insufficient-gas errors (row 10), pre-pay, unchanged.

## Scope fences (siblings in flight)

- **D45** owns how a resume is detected and keyed and what the resume
  plan displays. It may layer any informational presentation it likes;
  it cannot weaken rule 2 (a money invariant), and it does not need to
  restate it. If D45 elects to show the resume plan and the consent
  render as one screen, the affirmative answer must still be the U14
  gate's.
- **D51** owns `--json` × interactivity globally. Rule 5 defers to it
  by construction.
- **D49** owns `--dry-run` quote semantics; D36 binds only `pay()`, and
  `--dry-run` never pays — no interaction.

## Consequences — task-text edits at integration

- **tasks/S.md S11** — Do: "post-anchor/pre-pay (re-quote, re-consent
  via U if cost changed, then pay)" → "post-anchor/pre-pay (always
  re-quote — a journaled quote is never paid (D36); re-consent via U
  unconditionally in the resuming invocation, rendered against the
  fresh quote with prior consented totals displayed; then pay)".
  Accept: "Post-anchor/pre-pay resume re-quotes; consent hook re-fires
  when the quote changed" → "…re-quotes; consent hook re-fires
  unconditionally before pay; the `CostQuote` passed to `pay` is
  call-log-identical to the one returned by `quote_batch` in the same
  invocation (mock-asserted)". Add: declining re-consent leaves state
  `incomplete`, no transition (D36 rule 3). (Composes with D37's
  already-owed S11 edit — proofs-expired re-consent — which rule 2 now
  derives; one wording pass at integration.)
- **tasks/S.md S10** — journal record content gains the consent record
  `{total_ant_atto, gas_estimate, consent_time, channel}` written at
  every affirmative consent; note the `CostQuote` object is not a
  journaled payment input.
- **tasks/S.md S16** — matrix rows: (i) resumed invocation performs
  `quote_batch` before `pay` (call log); (ii) consent-hook call sits
  between them in the same invocation; (iii) `pay`'s quote argument
  identity-matches that `quote_batch` return; (iv) consent-decline on
  resume → no `pay`, no state transition.
- **tasks/U.md U17** — "re-consent via U14 when no payment has happened
  yet" stands, now "(per D36)"; Notes "Consent-on-resume rule is a U
  inference (spec silent)" → "per D36 (and D45 for detection/plan)".
  Add the prior-totals + drift-flag render to the resume path's accept.
- **tasks/U.md U14** — consent render gains the optional prior-consent
  line (resume case); one added snapshot fixture for the resume-render
  variant (totals-equal and totals-differ variants).
- **tasks/U.md U19 (note)** — `list`'s incomplete-work hinting should
  distinguish the two clocks: pre-pay incomplete works have **no
  deadline** (nothing paid; quotes are refetched on resume), while
  post-pay incomplete works carry D37's ~24 h proof window ("resume
  promptly"). Extends the U-domain nag note D37 already owes.
- **TODO.md register D36 row** — integration's edit.

## Residual risks

1. **Consent fatigue in a pathological retry loop** (pay failing
   repeatedly, user re-running): one prompt per attempt. Accepted —
   the path is rare, `--yes` exists, and the alternative erodes the
   gate precisely where money moves. If real usage ever shows a hot
   loop here, the fix is retry-within-invocation (one consent, one
   `pay()` attempt sequence), not cross-invocation consent.
2. **Price movement between original consent and resume** can present
   the user a higher figure with the anchors already made. Nothing is
   lost by declining (rule 3; anchors cost no ANT), but the user cannot
   recover the original price — recorded honestly as the cost of never
   paying stale quotes. The symmetric case (price fell) is pure upside
   the conditional rule would also have captured.
3. **The gas figure remains an estimate** and never bound actual gas —
   true on the initial seal as well (the estimate does not bind the
   tx). D36 deliberately does not pretend otherwise: gas participates
   in the render and in the insufficient-gas balance check, never in a
   gating comparison.
4. **`QUOTE_MAX_AGE_SECS` drift** (row 7) — shared with D37 residual 1;
   S9 pins the observed devnet value, S20/P19 watch. D36 is robust to
   drift in either direction because it never reasons about the
   window's value, only refuses to depend on it.
5. **Double-prompt risk if D45 also mandates a confirmation** on the
   resume plan: two prompts in one resume. Integration should merge
   them into one U14 render per the scope fence; flagged so the two
   records compose deliberately.

## New decision candidates surfaced (not resolved here)

1. **`--max-cost <ant>` spend ceiling** for non-interactive seals
   (initial and resume): today `--yes` consents to whatever the fresh
   quote says, which is the documented semantic but leaves scripts
   unbounded against price spikes. U domain (U13/U14 surface; interacts
   with D51's `--json` contract); v1.1-flavored unless M1 usage shows
   need.
2. **Retry-within-invocation policy for transient `pay()` failures**
   (residual 1's fix if ever needed): whether the pipeline may retry
   a failed pay under the same in-invocation consent, and how that
   interacts with S12's fault barriers and D37's per-sub-batch
   journaling. Owner S6/S12; only if evidence demands.

---

**[Correction pointer — 2026-08-02, S9]** Evidence row 3 and the summary's
secondary clause state that "storers enforce ~24 h `QUOTE_MAX_AGE_SECS`".
That constant does not exist in the pinned ant-node 0.15.0 and the
single-node payment path applies no timestamp gate; the ~24 h figure is
ant-core's client-side proof-cache policy. Full evidence and consequences:
the dated correction at the end of `D37-multi-tx-payment.md`. **This
record's conclusion is unaffected** — "always re-quote, consent per
invocation" rests on the load-bearing clause "a journaled quote is never
paid: nothing in the pay path checks age before moving tokens", which the
S9 investigation reinforces rather than weakens.
