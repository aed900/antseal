# D53 — The state for a TSA chain that does not validate at `genTime`

- **Status: RESOLVED — the register's *binary framing* is overturned; its
  *recommendation* survives, but only for the one sub-case A9 actually calls
  "chain invalid at genTime". "A chain that does not validate at genTime" is
  not one situation, it is six, and MVP-SPEC.md has already ruled two of them
  the **opposite** way from the register's lean (lines 109 and 133 both say
  `internally-consistent-only`). The six partition on one principle, stated
  here for the first time and shared with D56: **`invalid` iff the artifact
  makes a claim the verifier can refute from material it already trusts;
  `internally-consistent-only` iff it makes no refutable claim and no
  confirmable one.** Under it — temporal invalidity at `genTime` (in either
  direction), a failed link signature, and a failed path constraint, **on a
  chain that names a pinned root**, are all `AnchorState::Invalid`; a chain
  that reaches no pinned root at all — including one closing on a
  bundle-supplied root — is `AnchorState::InternallyConsistentOnly`. No
  eighth state is needed, nothing is renamed, and **zero of the 21 frozen
  report byte strings change** (measured: exactly 1 of the 21 carries any
  anchor slot at all, and all 3 of its slots are `absent`).**
- **Date: 2026-08-02** (M2 planning round; blocks A9, A18, A21, and Q18)
- **Owning tasks: A9** (the chain validator), **A18** (the state machine that
  consumes it), **A21/Q18** (the rows that pin it). Register entry:
  `TODO.md:565` — *"State for chain-invalid-at-genTime: `invalid`
  (recommended) vs `internally-consistent-only` (A9/A18/A21 — 'A-OD1')"*.

---

## Context — what the register claimed, and what survived

The register offers a coin flip between two states for one situation. Three
things are wrong with that, in ascending order of consequence.

1. **The situation is a partition, not a coin.** The brief for this round
   enumerates six distinguishable inputs. They do not share an answer.
2. **The spec has already decided two of them, against the lean.**
   MVP-SPEC.md line 109 fixes the bundle-supplied-root case by name and line
   133 fixes the no-pinned-root case by definition; both are
   `internally-consistent-only`. A ruling of "`invalid`, as recommended"
   applied to the whole question would have contradicted the frozen scope
   authority in two places.
3. **The one sub-case A9's own `Do` means by the phrase is not either of
   those**, and for it the lean is right. `tasks/A.md` A9 lists four outcomes
   and gives *"chain invalid at genTime"* and *"well-formed chain closing
   only outside the pinned store"* as **separate** bullets — so "A-OD1" was
   always scoped to "the chain *does* close at a pinned root, and the check
   that fails is temporal". The register lost that scoping when it compressed
   A9's bullet into a title.

So: the recommendation is confirmed **for its true scope**, the framing that
carried it is overturned, and the value of this document is the partition and
the decision order, not the verdict on the headline case.

The counting is worth stating plainly. Of the six sub-cases, **two** are
already decided by the spec (`internally-consistent-only`), **one** is what
the register meant (`invalid`), and **three** — not-yet-valid at `genTime`, a
failed path constraint, a failed link signature — are decided by neither the
spec nor the register and are decided here.

---

## 1. The six sub-cases, and where each already stood

| # | Input | Prior authority | Ruling |
| --- | --- | --- | --- |
| 1 | The chain reaches no pinned root at all (no certificate in the pinned store is named by any candidate path) | MVP-SPEC.md:133 — *"a well-formed token/attestation that does not chain to a pinned root (TSA) … cryptographically well-formed but not independently anchored"* | `InternallyConsistentOnly` |
| 2 | The chain closes only against a **bundle-supplied** root | MVP-SPEC.md:109 — *"bundle-embedded chains supply intermediates only — a chain that only closes against bundle-supplied roots renders 'internally consistent only', never 'proven'"* | `InternallyConsistentOnly` |
| 3 | The chain reaches a pinned root, but a certificate in the path was **not yet valid** at `genTime` (`notBefore > genTime`) | **none — named nowhere in MVP-SPEC.md, `tasks/A.md`, or `testdata/tamper/MATRIX.json`** | `Invalid` |
| 4 | The chain reaches a pinned root, but a certificate in the path was **already expired** at `genTime` (`notAfter < genTime`) | A9 `Do` calls this "chain invalid at genTime"; `MATRIX.json` pre-registers the row `anchor-expired-at-gentime` with `outcome_kind: "error"` | `Invalid` |
| 5 | The chain reaches a pinned root, but a path constraint fails (`basicConstraints` CA, `keyUsage` `keyCertSign`, `pathLenConstraint`) | A9 `Do` lists the checks; no state assigned | `Invalid` |
| 6 | The chain reaches a pinned root, but a link's signature does not verify | A9 **Accept** — *"broken chain signature → `invalid`"* | `Invalid` |

Two observations that decide the shape of the rest of this document.

**Sub-case 3 is a gap, and it is the adversarially interesting direction.**
Expiry-at-`genTime` is mostly TSA sloppiness — a renewal that ran late, a bad
clock. `notBefore > genTime` is **back-dating**: a token asserting a time
before the signing key's certificate existed. Priority fraud is the attack
antseal exists to make expensive, and back-dating is its cheapest form. That
it is named in no spec line, no task, and no matrix entry is a finding, not a
detail. It is ruled here, and §9 gives it a mandatory named test (it cannot
be a *row* — see §8).

**Sub-cases 5 and 6 are decided by the same principle as 3 and 4, not by
their own arguments.** §2 supplies it.

---

## 2. The partition principle

Every sub-case above is "the verifier could not conclude that a pinned root
vouched for this token at `genTime`". What separates them is *why*, and the
existing tree already contains the separator — in
`docs/format/anchor-artifact-limits.md` rule **F3**, verbatim:

> An over-limit artifact renders **`invalid`** for that anchor. Not `absent`
> (the artifact is present), and not `internally-consistent-only` (that state
> means well-formed-but-unanchored; an artifact we refused to finish reading
> is not known to be well-formed).

F3 is doing more than mapping one case: it is asserting that
`internally-consistent-only` carries a **positive claim about the artifact** —
that everything checkable *has been checked and passed*, and the only missing
ingredient is an external trust anchor. Generalised:

> **P — the partition principle.** An anchor renders `Invalid` iff the
> artifact makes a claim the verifier can **refute** from material it already
> trusts (its own pinned roots, the artifact's own bytes, or agreed online
> evidence). It renders `InternallyConsistentOnly` iff it makes **no
> refutable claim and no confirmable one** — it is well-formed and it points
> at nothing the verifier holds.

Apply P:

- **1, 2** — a chain terminating in an unknown or bundle-supplied certificate
  asserts nothing about any pinned root. Nothing is refuted. →
  `InternallyConsistentOnly`. Matches lines 109 and 133 exactly.
- **6** — a certificate whose `issuer` names a pinned root, and whose
  signature does not verify under that root's public key, makes exactly one
  claim ("this root signed me") and the verifier refutes it with the root's
  own key. → `Invalid`. Independently, this is what A9's Accept already says.
- **5** — a certificate used as an issuer that its own issuer marked
  `CA:FALSE`, or lacking `keyCertSign`, is a refuted claim of authority. →
  `Invalid`.
- **3, 4** — the token asserts a `genTime` at which the CA's own certificate
  says the key was not valid. The pinned root *is* reached; the refutation
  comes from the trusted root's own subordinate statements. → `Invalid`.

### 2a. The three reasons `internally-consistent-only` is wrong for 3 and 4

P settles it, but this is the case the register put to a vote, so the
arguments are recorded rather than implied.

1. **It would state a falsehood.** R18's wording for
   `internally-consistent-only` derives from line 133: *"not independently
   anchored"*. For sub-cases 3 and 4 the token **is** anchored — a pinned
   root signed this chain. Rendering "not independently anchored" tells the
   user the TSA is unknown to us, which sends them to file a root-store bug
   for a token whose real defect is a self-contradictory time claim.
2. **It would merge the loudest failure with the quietest.** Sub-case 1 is
   the ordinary, blameless case (a TSA we do not pin; it happens on every
   alternate endpoint in D57's scope). Sub-case 3 is a back-dating attempt.
   One label for both destroys the distinction at exactly the point where the
   product's claim lives.
3. **It collides in the tamper matrix, and the only way past the collision
   is a false statement.** `MATRIX.json` pre-registers `anchor-untrusted-root`
   at `verdict:internally-consistent-only`. Under the losing option
   `anchor-expired-at-gentime` claims the same key, and
   `docs/testing/error-code-contract.md` §4b layer 3 refuses exactly that:
   *"a pending row whose expected code is already claimed — by an implemented
   row or by another pending row — fails the registry **unless the entry
   records the collision explicitly**"*. Recording a collision is a claim —
   §4b's own words for what it surfaces are *"these two mutations are one
   observable failure"* — so taking the escape hatch would assert that an
   unpinned TSA and a back-dated token are indistinguishable to a verifier.
   They are not: one reaches a pinned root and one does not.

   **Precision, because the tempting overstatement is wrong:** this check is
   **dormant today**, not violated. Both rows carry `"expected": null`, so
   layer 3 has nothing to compare — which is itself the defect Q76 exists to
   fix (§8, §10). The claim is that the losing option becomes mechanically
   blocked the moment the matrix is filled in, not that it is red now.

Argument 3 is the decisive one, because it is the only one that does not rest
on a judgement about wording: the option the register recommended against
cannot be registered without either a red matrix or a recorded assertion that
is false.

---

## 3. What a candidate path is, and the three rules that fall out of it

`AnchorState` is a property of an **artifact**, but chain validation operates
on **paths**, of which one artifact may offer several (bundle-supplied
intermediates are an unordered bag as far as correctness is concerned;
`docs/format/registry-v1.md` §8 makes their wire order a *builder* rule with
no parse check, and records that *"order carries no meaning"*). Every rule
below is therefore written as an **existential over the whole candidate set**,
never as "the first path that…", so the resulting state is invariant under
permutation of `intermediates`. §9 pins that with a property test.

**Definitions** (A9 implements these; the names are normative):

- A **trust anchor** is a certificate in the pinned root store
  (`antseal_core::anchor::roots::PinnedRootStore`, A6). **A bundle-supplied
  certificate is never a trust anchor**, even when its subject DN, or its
  whole DER encoding, equals a pinned root's — MVP-SPEC.md:109, *"bundle-embedded
  chains supply intermediates only"*. A bundle certificate that duplicates a
  pinned root is usable as an *intermediate* only, and since it is
  self-signed it can never terminate a path.
- A **candidate path** `P = [signer, i₁, …, i_k, R]` has `R` a trust anchor,
  every `iⱼ` drawn from the bundle's `intermediates` without repetition, and
  **name chaining** at every link:
  the child's `issuer` DN equals the parent's `subject` DN, and where both
  are present the child's AKI `keyIdentifier` equals the parent's SKI.
- `sig_ok(P)` — every link's signature verifies under its parent's SPKI.
- `constraints_ok(P)` — every **issuer** element of `P` (that is, every
  element except `signer`, including `R`) has `basicConstraints` CA=TRUE and
  either no `keyUsage` or one asserting `keyCertSign`; every
  `pathLenConstraint` on the path is respected.
- `time_ok_at(P, t)` — every element of `P` **except the trust anchor `R`**
  satisfies `notBefore ≤ t ≤ notAfter`.
- `expired_by(P, t)` — some element of `P` except `R` has `notAfter < t`.

Two of those definitions are rulings in their own right and are argued in §5.

**Two different bounds, and D84 §5 warns specifically against merging them.**
`k` is bounded above by `MAX_INTERMEDIATE_COUNT = 16`
(`crates/antseal-core/src/codec/caps.rs:179`) only *incidentally* — a path
cannot use more intermediates than the bundle carries, and that cap is
already enforced in verify stage 1 as a **frozen D10 constant, consumed by
name, never redefined**. The **maximum length of a path being validated** is a
separate, genuinely open M2 limit that `tasks/A.md` A5 owns and
`docs/format/anchor-artifact-limits.md` §4 lists as *"max certificate count
in a chain being validated (**distinct from** the bundle's
`MAX_INTERMEDIATE_COUNT`)"*, chosen against A25's recorded chains and
recorded in the F4 registry. This document mints neither and requires that
the path enumerator bound its search by the second, not by the first.
**Enumerating all subsets of 16 intermediates is 16! orderings in the worst
case**; a hostile bundle that supplies 16 mutually name-chaining certificates
is cheap to build, so the enumerator must be depth-first with the A5 depth
bound and a visited set, not a permutation generator. A5's `.ots`/DER fuzz
targets (A23) will not reach this path — it is behind A9 — so A9 needs its own
adversarial-input test at the bundle's cap.

### The rules

Let `NAMED` be the set of candidate paths (name chaining only — no signature,
constraint, or time predicate applied) and
`VALID = { P ∈ NAMED : sig_ok(P) ∧ constraints_ok(P) ∧ time_ok_at(P, gen_time) }`.

```text
C1.  !VALID.is_empty()
       && VALID.iter().any(|p| !expired_by(p, verify_at))
                                          ->  AnchorState::Proven                          [H]
                                              verified_time_unix = Some(gen_time)

C2.  !VALID.is_empty()                     ->  AnchorState::ValidAtStampingCertSinceExpired [H]
       (i.e. every valid path is expired       verified_time_unix = Some(gen_time)
        at verify_at)

C3.  NAMED.iter().any(|p| sig_ok(p) && constraints_ok(p))
                                          ->  AnchorState::Invalid
       (so the only failing predicate is       code "anchor-cert-not-valid-at-gentime"
        time_ok_at(p, gen_time))               verified_time_unix = None

C4.  NAMED.iter().any(|p| sig_ok(p))      ->  AnchorState::Invalid
                                              code "anchor-chain-constraint-violation"
                                              verified_time_unix = None

C5.  !NAMED.is_empty()                    ->  AnchorState::Invalid
                                              code "anchor-chain-signature-invalid"
                                              verified_time_unix = None

C6.  otherwise                            ->  AnchorState::InternallyConsistentOnly
                                              verified_time_unix = None
```

**First match wins, and the guards are evaluated in exactly this order.**
Every guard is an existential over `NAMED` or `VALID`, so the outcome — state
*and* code — is a function of the artifact and the root store alone, never of
enumeration order.

`C3 → C4 → C5` is **least-severe-wins**: report the failure of the path that
got *furthest*. Chosen for a property, not for taste: it makes classification
**monotone under adding certificates**. Appending a garbage intermediate to a
bundle whose real chain fails only on time cannot change the reported code,
because `C3`'s guard is an existential that the garbage cert does not
disturb. Under most-severe-wins the opposite holds — one appended junk cert
with a broken signature would rewrite the code of every artifact in the
bundle — and since the `.sealproof` bundle is **unsigned** (D8; only the
manifest is signed, and `ots_anchors`/`tsa_anchors` are bundle maps,
`docs/format/registry-v1.md` §7.8–§7.9), *any relay can append that cert*.
Most-severe-wins is a code-rewriting primitive handed to an untrusted relay.

`C1/C2 → C3` is the same property one level up: **a valid path is never
demoted by the existence of a failing one.** This is the rule that keeps a
relay from downgrading an honest `proven` anchor by appending junk.

### The full TSA order, with the stages above C1

`C1–C6` are stage 3. A18's per-TSA-artifact order in full:

```text
T0.  no TSA artifact in the bundle                    ->  AnchorState::Absent
T1.  A11/A5 anchor-stage limits or strict-DER reject  ->  AnchorState::Invalid   (A5's code; F1–F3)
T2.  A8 token-intrinsic checks fail                   ->  AnchorState::Invalid   (A8's code)
       CMS SignedData shape; signed attributes present with
       content-type + message-digest; signature over the DER
       SET OF re-encoding of signedAttrs verifies under the
       signer SPKI; eContent digest == message-digest attr;
       TSTInfo.messageImprint == anchor_digest; ESSCertID/v2
       binds the signer cert; signer EKU present, critical,
       containing id-kp-timeStamping (RFC 3161 §2.3)
T3.  C1 … C6 above
```

**T2 before T3 is normative and load-bearing.** It is what makes
`InternallyConsistentOnly` mean what F3 says it means: the state is
**unreachable** unless the token's own bytes have already been fully checked.
A token whose CMS signature does not verify never reaches C6 and never
acquires the "cryptographically well-formed" label. §9 pins this as a test,
and it is the one that would catch the natural wrong implementation — a
validator that tries the chain first and reports "untrusted root" for a
token that was never a token.

### Every overlapping pair, and its winner

| Both hold | Winner | Why |
| --- | --- | --- |
| T2 failure **and** any of C1–C6 | **T2** | `InternallyConsistentOnly` must imply well-formed (F3). The chain is never built. |
| C1/C2 **and** C3/C4/C5 (a valid path *and* a failing one) | **C1/C2** | A junk intermediate must not demote a good chain; the bundle is unsigned and anyone can add one. |
| C1 **and** C2 (one valid path unexpired at `verify_at`, another expired) | **C1** | `Proven` is the stronger true statement; both paths prove the same `genTime`. |
| C3 **and** C4 (one path fails only on time, another on constraints) | **C3** | Least-severe-wins; monotonicity under added certificates. |
| C4 **and** C5 | **C4** | Same. |
| C3/C4/C5 **and** C6 | C3/C4/C5 | Mutually exclusive by construction (`NAMED` non-empty vs empty); stated so the exclusivity is asserted rather than assumed. |
| Sub-case 2 **and** sub-case 4 (chain closes on a bundle-supplied root **whose certificate had also expired before `genTime`**) | **C6 — `InternallyConsistentOnly`** | `NAMED` is empty: no pinned root is named, so there is nothing to refute. This is the pair the register's binary framing gets wrong, and §9 gives it a test. |

---

## 4. What each state carries

| State | `[H]` | `verified_time_unix` | `source` |
| --- | --- | --- | --- |
| `Proven` | yes | `Some(genTime)` | **verified** signer identity from the validated path |
| `ValidAtStampingCertSinceExpired` | yes | `Some(genTime)` | **verified** signer identity |
| `InternallyConsistentOnly` | no | **`None`** | *claimed* identity from the token, rendered as claimed (R18) |
| `Invalid` | no | **`None`** | *claimed* identity, rendered as claimed |
| `Absent` | no | `None` | `None` |

Eligibility is unchanged and **no edit to
`crates/antseal-core/src/verify/aggregate.rs` is authorised by this
decision** — `headline_eligible` already returns `true` for exactly `Proven`
and `ValidAtStampingCertSinceExpired` and is already pinned exhaustively by
`exactly_the_two_spec_h_states_are_headline_eligible`.

### 4a. `absent` stops being reachable at M2, and A18's Accept bullet for it goes vacuous

Found while checking that all seven states stay reachable. They do not — and
the bullet meant to guarantee it is the kind of test the brief for this round
warns about.

`report.anchors` is built **one slot per artifact present in the bundle**
(`crates/antseal-core/src/verify/pipeline.rs`, `anchor_stubs`: it maps over
`bundle.ots_anchors()` chained with `bundle.tsa_anchors()`). Today every such
slot is `Absent` because the M0 stage parses no artifact byte. From M2 every
slot has an artifact, and every artifact lands in one of T0's successors —
`Invalid`, `InternallyConsistentOnly`, or an `[H]` state. F3 confirms the
reading in the one place it could have gone the other way: an over-limit
artifact is *"not `absent` (the artifact is present)"*. So:

> **`AnchorState::Absent` is unreachable in `report.anchors` from M2 onward.**
> A bundle with no anchors serializes `"anchors":[]` — which is itself a
> pinned byte string (`pipeline.rs`'s canonical-JSON assertion contains
> `"storage_linkage":"not-evaluated","anchors":[],`) — and a bundle with
> anchors has no absent slot.

A18's Accept says *"Exhaustive test: every one of the seven states reachable
from a concrete fixture; `absent` covered by the empty-anchor vector."* The
empty-anchor vector produces **zero** slots, so it witnesses nothing about
`Absent`; that clause passes vacuously today and would keep passing if the
variant were deleted.

**Ruling, and it is deliberately the option that changes no bytes:**
`AnchorState::Absent` is what `evaluate_anchors` returns for a **query about
an anchor kind the bundle does not carry** — not for an artifact — and
**R12 emits no `AnchorResult` slot for it.** So the variant stays reachable
and testable in A18's own domain model (call the evaluator with an empty
artifact set for a kind), the wire enum keeps its registry §6.1 value 6 (where
it is *"representable and meaningless"* by decision), and `"anchors":[]`
survives byte-identical.

The rejected alternative is worth naming because it is the obvious one:
emitting a fixed `ots` + `tsa` slot pair, `Absent` when the kind has no
artifact. It would make `Absent` reachable in the report — and it would
rewrite the `"anchors":[]` pinned string and the one report vector that
carries anchor slots. **That is a frozen-byte change and a `REPORT_VERSION`
bump**, for a cosmetic gain. Not authorised here, and not to be reached for
when the vacuity above is noticed during A18.

`verified_time_unix` is `TSTInfo.genTime` for both `[H]` states — including
`ValidAtStampingCertSinceExpired`, whose whole purpose (MVP-SPEC.md:130) is
that it *"still carries its independently-proven stamping time"*. It is
**never** populated for the other three; `aggregate_anchors` already ignores
times on ineligible slots, so this is defence in depth, and §9 tests it as
such.

---

## 5. Three sub-rulings that fall out, and are decided here

**(a) The trust anchor's own validity period is not checked.** `time_ok_at`
deliberately excludes `R`. RFC 5280 §6.1 treats a trust anchor as an input to
path validation rather than a certificate to be validated, and the
project-specific reason is stronger: pinned roots are long-lived and will
expire while sealed bundles are still being verified. Checking `R.notAfter`
would make every bundle anchored under that root flip to `Invalid` on the
root's expiry date — precisely the silent rot MVP-SPEC.md:109 and :130
forbid (*"aging bundles must not silently rot"*). A6/A26 own the root store's
lifecycle; expiry is handled by adding roots, never by failing old evidence.

**(b) `verify_at` is one-sided.** It can only distinguish `Proven` from
`ValidAtStampingCertSinceExpired`, via `expired_by(P, verify_at)` —
`notAfter < verify_at`. It is never a validity check: a `verify_at` *earlier*
than a certificate's `notBefore` (a caller with a wrong clock, or a WASM page
with no clock at all passing a fixed value) yields `Proven`, not a failure.
The state name itself forces this — "cert **since expired**" would be a lie
for "not yet valid at your clock". No path from `verify_at` to `Invalid`
exists, and §9 tests for its absence.

**(c) Bundle certificates are candidates, never anchors.** Stated in §3;
recorded here because the natural implementation — feeding intermediates and
roots into one certificate pool — silently violates MVP-SPEC.md:109 and turns
sub-case 2 into `Proven`. The pool must be two-tier by type, not by
convention.

---

## 6. Report-format impact: **zero bytes**, and the mechanism that keeps it so

Measured, not asserted. `testdata/vectors/v1/report/verification-reports.json`
holds `expect.cases` of length **21** at `report_version: 1`. Exactly **one**
of the 21 has a non-empty `anchors` array; it holds **3** slots, and every one
of them is `{"state":"absent", "verified_time_unix":null, "source":null,
"fetch_date":null}`. The strings `"proven"`, `"attested"`, `"pending"`,
`"internally-consistent-only"`, `"invalid"` and
`"valid-at-stamping-cert-since-expired"` occur **0** times in the file. This
ruling mints no state, renames none, and adds no field, so **no pinned report
byte string changes and `REPORT_VERSION` does not move.** This is not a format
event.

It stays that way only because of one constraint, which is the load-bearing
consequence of this document:

> **The per-anchor diagnostic code (`anchor-cert-not-valid-at-gentime` and
> its siblings) MUST NOT enter `VerificationReport`.**
> `crates/antseal-core/src/verify/report.rs`'s `AnchorResult` has exactly five
> fields — `kind`, `state`, `verified_time_unix`, `source`, `fetch_date` —
> and report v1 is frozen (D29/R32; Q14, 2026-07-28). The codes live in
> A18's own `AnchorVerdicts` type; **R12 projects** `AnchorVerdicts` into
> `Vec<AnchorResult>` and drops them.

This is D86's ruling one domain over — *"Decode **layer** in the user-facing
verdict — it never enters `VerificationReport`"* — and it is written down here
because the obvious way to satisfy A9's *"with a distinct error detail"* is to
add a sixth field, which would bump `REPORT_VERSION`, re-emit all 21 pinned
strings, and break `EXPECTED_CANONICAL_JSON`. See `report.rs`'s
`REPORT_VERSION` doc comment for the full coupled-edit list a bump would drag
along.

Its price is stated rather than hidden: the **verifier page cannot render the
diagnostic code**, because R22 hands the page only the report's canonical
bytes. The CLI can (it holds `AnchorVerdicts`). That CLI/page asymmetry
contradicts R18's premise of *"one authoritative wording set … shared verbatim
by CLI and page"*; it is a finding for R18, recorded in §11, and the fix is a
`report_version: 2` field — a deliberate format event, not a drive-by.

---

## 7. Error codes minted, and the prefix that does not exist yet

Three codes, all new, all pairwise distinct, none colliding with the 194
codes currently in `testdata/error-codes/v1/CODES.txt`
(`grep -v '^#\|^$' testdata/error-codes/v1/CODES.txt | grep -c '^anchor'` →
**0**; total non-comment lines → **194**). Adding codes is *"routine and
unrestricted"* per `docs/testing/error-code-contract.md` §3, and §4a's
snapshot has additions-only semantics, so no gate resists them.

| Code | Fires at | Meaning |
| --- | --- | --- |
| `anchor-cert-not-valid-at-gentime` | C3 | Some certificate on every otherwise-good path to a pinned root was outside its validity window at the token's `genTime`. Covers **both** directions; the payload names the certificate's path index and which bound was crossed. |
| `anchor-chain-constraint-violation` | C4 | Every signature-closed path to a pinned root violates `basicConstraints`, `keyUsage`, or `pathLenConstraint`. |
| `anchor-chain-signature-invalid` | C5 | Every name-chaining path to a pinned root contains a link whose signature does not verify. |

**One code for both temporal directions, deliberately.** Both are the single
predicate `notBefore ≤ genTime ≤ notAfter` failing; D85's rule applies
verbatim — *"a cause belongs in **rendering** … never in the code set"* — and
`bundle-wrong-length-block-header` is the standing precedent for one code over
a two-sided bound (`crates/antseal-core/tests/tamper_rows_anchor/mod.rs`,
*"the field has one correct length"*). The direction is in the typed payload
and in R18's rendering, and the back-dating direction gets a mandatory named
test (§9).

### The blocking defect: there is no `anchor-` prefix

`docs/testing/error-code-contract.md` §2's prefix table has rows for `cbor-`,
`manifest-`, `bundle-` (F), `crypto-` (C), `content-` (G) and *(unprefixed)*
(R). **It has no row for the A domain**, while §5 of the same document already
anticipates M2 anchor rows, and A5, A8, A9, A11 and A12 each promise distinct
error codes. §2 also forbids the workaround — *"A domain never mints a code
under another domain's prefix"* — so A cannot borrow `bundle-`. The row must
land before A5 mints its first code. Verbatim:

```markdown
| `anchor-` | A | anchor-artifact verification: strict DER/CMS, X.509 path validation, `.ots` op execution, embedded-header and online-header checks (A5–A18) |
```

`§4b` layer 4 (reverse coverage) additionally needs an A-domain exemplar
enumerator, on the pattern of F's `DecodeError` and R's `VerifyError`, or
every `anchor-` code will be unowned by construction. Both are task **A38**
(§10).

---

## 8. The M2 anchor tamper rows — the count, the defect, and the bindings

### The spec's enumeration does not come to seven

MVP-SPEC.md:168's M2 half, split on its own semicolons, is **six** clauses:

1. ``.ots``/TSA token for a different digest
2. well-formed TSA token from an untrusted root (→ `internally-consistent-only`, not headline)
3. forged Bitcoin header that fails the `--online` block match (→ `invalid`)
4. an `attested` OTS anchor correctly withheld from the offline headline
5. expired-at-genTime vs expired-after-genTime chain cases
6. BER-where-DER-required

Clauses 1 and 5 are each explicitly **compound**. Fully expanded the
enumeration is **eight** cases, not seven. The tree contains two different
sevens, and they are not the same seven:

- **`testdata/tamper/MATRIX.json`** expands clause 5 into two cases and keeps
  clause 1 as one → 6 families, **7** pending `row_id`s.
- **`tasks/A.md` A21 `Do`** expands clause 1 into two numbered rows (`.ots`
  and TSA) and keeps clause 5 as one numbered row demanding *"distinct
  outcomes"* → **7** numbered items describing **8** tests.
- **`TODO.md`'s M2 gate** says *"all 7 anchor tamper rows (A21/Q18)"* without
  saying which seven.

**Ruling: there are eight cases**, `MATRIX.json`'s
`anchor-token-for-a-different-digest` family gains a second case, and
`TODO.md`'s gate text is corrected to eight. This is not pedantry: under
§4b layer 3 the two halves of clause 1 are *different checks in different
stages on different artifact kinds* (`TSTInfo.messageImprint`, checked at T2
by A8; the `.ots` stamped digest, checked at O2 by A11), so they cannot share
an outcome key and one row cannot discharge both.

### Bindings

Of the eight, **D53 binds three** (marked ●); D56 binds three; two are owned
elsewhere.

| # | `MATRIX.json` family / case | `row_id` | `ExpectedOutcome` | Decided by |
| --- | --- | --- | --- | --- |
| 1 | `anchor-token-for-a-different-digest` / `ots-digest-mismatch` | `anchor-ots-digest-mismatch` | `ErrorCode("anchor-ots-digest-mismatch")` | D56 §5 (rule O2) |
| 2 | `anchor-token-for-a-different-digest` / `tsa-imprint-mismatch` **(new case)** | `anchor-tsa-imprint-mismatch` | `ErrorCode("anchor-tsa-imprint-mismatch")` | A8 owns the code; **D53 fixes that it fires at T2, before any chain rule** |
| 3 ● | `untrusted-tsa-root` | `anchor-untrusted-root` | `VerdictState("internally-consistent-only")` | **D53 rule C6** |
| 4 | `forged-bitcoin-header` | `anchor-forged-header` | `VerdictState("invalid")` | D56 §5 (rule O6) |
| 5 | `attested-ots-withheld-from-headline` | `anchor-attested-not-headline` | `VerdictState("attested")` | D56 §5 (rule O4) |
| 6 ● | `tsa-chain-expiry` / `expired-at-gentime` | `anchor-expired-at-gentime` | `ErrorCode("anchor-cert-not-valid-at-gentime")` | **D53 rule C3** |
| 7 ● | `tsa-chain-expiry` / `expired-after-gentime` | `anchor-expired-after-gentime` | `VerdictState("valid-at-stamping-cert-since-expired")` | **D53 rule C2** |
| 8 | `ber-where-der-required` | `anchor-ber-not-der` | `ErrorCode(<A5's strict-DER code>)` | A5 / D60 |

Distinctness holds: `verdict:internally-consistent-only`, `verdict:invalid`,
`verdict:attested`, `verdict:valid-at-stamping-cert-since-expired` are four
distinct verdict keys and the remaining four rows are error keys with four
distinct codes. **`verdict:invalid` is claimed exactly once**, by row 4 —
which is why rows 2, 6 and 8, all of which also *render* `Invalid`, must pin
codes rather than the state. That is the structural reason C3/C4/C5 mint
codes at all.

> **Clarified 2026-08-06 by [D93](D93-online-refutation-precedence.md) §6.**
> The dependency runs **one way**. `verdict:invalid` being claimed exactly
> once is a **consequence** of rows 2, 6 and 8 minting codes, not a premise of
> it: the checker enforces **distinctness, not coverage**, so *zero* claimants
> would satisfy the same constraint. This matters because the sentence above
> reads, at a glance, as though row 4's cell were load-bearing for the other
> three — it is not, and a reader who believed it would conclude that row 4's
> `expected` could never be revisited. D93 revisited it, and confirmed the
> value while rejecting that reason for it.

**The row-id `anchor-expired-at-gentime` keeps its name** even though the
code it binds covers both temporal directions: row ids are *"permanent
handles"* (`tamper_rows_anchor/mod.rs`), the row exercises the expired
direction, and the not-yet-valid direction is a named test (§9), exactly as
the 81-byte block header is.

### The `MATRIX.json` edits this decision authorises

Under `families[]`, in the `anchor-token-for-a-different-digest` family, the
existing single case is replaced by two (the family's `spec_quote` is
unchanged, so the *"literal substring"* check in `spec_source.note` still
passes):

```json
        {
          "id": "ots-digest-mismatch",
          "what": "an otherwise valid `.ots` whose stamped digest is not this seal's `anchor_digest`",
          "pending": {
            "task": "A21",
            "row_id": "anchor-ots-digest-mismatch",
            "outcome_kind": "error",
            "expected": "anchor-ots-digest-mismatch",
            "why": "D56 rule O2. Split from the TSA half at D53 §8: line 168's clause is compound, and the two checks live in different stages on different artifact kinds (`.ots` stamped digest at A11; `TSTInfo.messageImprint` at A8), so they cannot share an outcome key."
          }
        },
        {
          "id": "tsa-imprint-mismatch",
          "what": "a TSA token whose `TSTInfo.messageImprint` is a digest other than this seal's `anchor_digest`",
          "pending": {
            "task": "A21",
            "row_id": "anchor-tsa-imprint-mismatch",
            "outcome_kind": "error",
            "expected": "anchor-tsa-imprint-mismatch",
            "why": "D53 §8 row 2. A8 owns the check and the code; D53 fixes that it fires at stage T2, before any chain rule, so a token for a different digest is never classified by its chain."
          }
        }
```

And the two `expected: null` slots D53 fills:

```json
            "row_id": "anchor-expired-at-gentime",
            "outcome_kind": "error",
            "expected": "anchor-cert-not-valid-at-gentime",
            "why": "D53 rule C3. One code covers both temporal directions (D85: a cause belongs in rendering, not the code set); this row exercises the expired direction and the not-yet-valid direction is D53's named test `a_certificate_not_yet_valid_at_gentime_is_the_same_code`."
```

```json
            "row_id": "anchor-expired-after-gentime",
            "outcome_kind": "verdict",
            "expected": "valid-at-stamping-cert-since-expired",
            "why": "D53 rule C2 — the positive control for the expiry pair. `expired != invalid` when the certificate was valid AT genTime (MVP-SPEC.md:109/130, aging bundles must not silently rot)."
```

Applying these is task **Q76** (§10), and it should run **before** A21 writes
a line of code, because §4b layer 3 exists to surface the collision *"while
it is still cheap to fix"*.

---

## 9. The tests that must exist, and what makes each fail

Location: `crates/antseal-core/src/anchor/chain.rs` (unit) and
`crates/antseal-core/tests/anchor_chain_states.rs` (integration over A24's
test CA). Every one runs in both the native and the `wasm32-unknown-unknown`
suites (A21 Accept).

| Test | Claim | **What makes it fail** |
| --- | --- | --- |
| `a_valid_chain_at_gentime_and_verify_at_is_proven` | C1 | Any of: the trust anchor's own validity being checked (sub-ruling a) with a root deliberately given a short window; `verify_at` used as a two-sided validity check. |
| `a_chain_valid_at_gentime_and_expired_at_verify_at_is_valid_at_stamping` | C2 | An implementation that validates at `verify_at` instead of `genTime` — the aging-bundle rot A9's Accept names. |
| `one_fixture_two_verify_times_flips_proven_and_since_expired` | C1↔C2 on one artifact | Any implementation that reads a clock instead of the `verify_at` parameter: both calls would return the same state. |
| `verify_at_before_gentime_is_still_proven` | Sub-ruling (b) | An implementation checking `notBefore ≤ verify_at`; it would return `ValidAtStampingCertSinceExpired` or `Invalid`. |
| `an_expired_at_gentime_chain_is_invalid_with_the_temporal_code` | C3 | A validator that skips the `genTime` check, or that returns `InternallyConsistentOnly` (the register's losing option). |
| `a_certificate_not_yet_valid_at_gentime_is_the_same_code` | Sub-case 3 — **the back-dating gap** | Any implementation checking only `notAfter < genTime`. **This test is the only guard on the whole back-dating direction**; nothing in the spec, `tasks/A.md`, or `MATRIX.json` covers it. |
| `a_ca_false_intermediate_is_invalid_with_the_constraint_code` | C4 | A validator that omits `basicConstraints` — the classic "any leaf can sign" hole. |
| `a_broken_link_signature_is_invalid_with_the_signature_code` | C5 | A validator trusting name chaining alone. Also A9's own Accept bullet. |
| `an_untrusted_root_is_internally_consistent_only` | C6 | A validator that falls back to `Invalid` when no anchor is found; contradicts MVP-SPEC.md:133 and is `MATRIX.json` row `anchor-untrusted-root`. |
| `a_bundle_supplied_root_never_terminates_a_path` | Sub-case 2, sub-ruling (c) | The one-certificate-pool implementation: it returns `Proven` for a self-signed chain the sealer wrote. This is the most consequential single failure in the file. |
| `a_bundle_copy_of_a_pinned_root_is_ignored_not_trusted` | Sub-ruling (c), second half | An implementation matching trust anchors by subject DN rather than by store membership: a forged root with a copied DN would validate. |
| `an_untrusted_root_expired_before_gentime_is_internally_consistent_only` | The overlapping pair | Any implementation checking time before checking reachability. This is the pair the register's binary framing gets wrong, and the natural check order gets it wrong too. |
| `a_junk_intermediate_never_demotes_a_valid_chain` | C1/C2 over C3–C5 | An implementation returning the first path's failure. Under it, an unsigned-bundle relay could downgrade every honest anchor. |
| `the_state_is_invariant_under_permutation_of_intermediates` (proptest, seeded) | §3's existential form | A "first path wins" implementation. A naive DFS passes every fixture above and fails only here — which is why this is a property test and not a case. |
| `a_token_whose_cms_signature_fails_never_reaches_chain_classification` | T2 before T3 | A validator that builds the chain first; it would label a non-token `internally-consistent-only`, contradicting F3. |
| `no_ineligible_state_carries_a_verified_time` | §4 | An implementation populating `verified_time_unix` from `genTime` unconditionally. `aggregate_anchors` would still ignore it, so **only this test can see the defect.** |
| `absent_is_returned_for_a_kind_with_no_artifact_and_emits_no_slot` | §4a | The fixed-slot-pair implementation (it would emit two `absent` slots and break the pinned `"anchors":[]` string), **or** an A18 whose `absent` coverage is still the empty-anchor vector — which witnesses nothing, since that vector produces zero slots. |
| `the_empty_anchor_vector_still_serializes_anchors_as_an_empty_array` | §4a's byte guarantee | Any change to slot emission. Cheap, and it is the only thing standing between "make `absent` reachable" and a `REPORT_VERSION` bump. |
| `sixteen_mutually_chaining_intermediates_terminate_promptly` | §3's second bound | A permutation-style path enumerator. The bundle cap allows 16 intermediates, all of which a hostile sealer can make mutually name-chaining; the test must assert a bounded work budget (or a wall-clock ceiling under the CI profile), not merely that the call returns. |
| `every_chain_code_is_pairwise_distinct_and_anchor_prefixed` | §7 | A copy-pasted code, or one minted under `bundle-` (forbidden by §2). |

Two anti-vacuity obligations, on the R7 rule that *"every row's base must be
valid, or a row could 'pass' by pinning a defect the mutation had nothing to
do with"*:

- Every fixture above is derived from **one** A24 test-CA chain that
  `a_valid_chain_at_gentime_and_verify_at_is_proven` proves `Proven`, by
  changing exactly one field. A fixture that fails for two reasons pins
  neither.
- `an_untrusted_root_is_internally_consistent_only` must assert the token
  **passed T2** — i.e. that the same token bytes verify their CMS signature
  and `messageImprint` — or it would pass vacuously against a token that was
  malformed for an unrelated reason.

---

## 10. Discovered work

Allocated from the block **A38–A41, R61–R63, Q76–Q77**; this document uses
**A38, A39, A40, R61, Q76** (D56 shares them; the full entries are in the
planner's task file). A41, R62, R63 and Q77 are unused.

- **A38 (S)** — register the `anchor-` prefix in
  `docs/testing/error-code-contract.md` §2 and add the A-domain exemplar
  enumerator so §4b layer 4's reverse coverage sees `anchor-` codes.
  **Blocks A5** (the first task that mints one).
- **A39 (S)** — `AnchorVerdicts` carries a wording-free per-anchor
  *suppressed-anomaly* list so best-evidence-wins (C1/C2 over C3–C5; D56's
  O3–O5 over O6–O8) never silently discards a refutation. Must not enter
  `VerificationReport` (§6).
- **A40 (S)** — the orphaned obligation from `docs/format/registry-v1.md` §8:
  *"anchor independence must be evaluated from verified identities, never
  from array length — an obligation on A18/R17"*. Duplicate anchor artifacts
  are legal v1 by decision; no task text carries the consequence, and A20's
  minimum-anchor gate depends on it.
- **R61 (S)** — R18 renders the A39 anomaly list and pins the CLI/page
  asymmetry §6 creates.
- **Q76 (S)** — apply the `MATRIX.json` edits in §8 **before** A21 starts.

---

## 11. Corrections to existing prose (orchestrator applies at source)

1. **`docs/testing/error-code-contract.md` §2** — no `anchor-` prefix row.
   Add the row in §7. (Owner: A38.)
2. **`TODO.md`:48 and the M2 gate line** — *"all 7 anchor tamper rows
   (A21/Q18)"*. There are **eight** (§8). Correct both occurrences.
3. **`tasks/A.md` A21 `Do`** — item (6), *"expired-at-genTime chain (per
   A-OD1 state) vs expired-after-genTime … — distinct outcomes"*, is two rows
   presented as one numbered item, which is why A21's list reads as seven
   while describing eight tests. Renumber to eight items.
4. **`tasks/A.md` A9 `Do`** — *"chain invalid at genTime → the A-OD1 state
   with a distinct error detail"* is now *"→ `AnchorState::Invalid`, code
   `anchor-cert-not-valid-at-gentime` (D53 rule C3)"*, and the `Do` must gain
   the **not-yet-valid** direction, which it omits entirely.
5. **`tasks/A.md` A9 `Accept`** — *"expired-at-genTime → distinct non-headline
   state per A-OD1"* should read *"→ `invalid` with code
   `anchor-cert-not-valid-at-gentime`, distinct from the untrusted-root
   row's `internally-consistent-only`"*. As written it is satisfiable by
   `internally-consistent-only`, the option §2a shows is excluded by §4b
   layer 3.
6. **`tasks/A.md` A9 `Do`** — it says *"single-path chain building"* and A9's
   title says *"single-path validation"*, but §3's rules quantify over the
   **candidate set**. "Single-path" is correct about the *output* (one
   validated path suffices) and misleading about the *search*; the
   permutation-invariance property test exists because the natural reading of
   "single path" is the implementation that fails it. Add the clarification.
7. **`docs/format/registry-v1.md` §8** — *"anchor independence must be
   evaluated from verified identities … an obligation on A18/R17"* is a
   normative obligation carried by no task. (Owner: A40.)
8. **`tasks/A.md` A18 `Accept`** — *"every one of the seven states reachable
   from a concrete fixture; `absent` covered by the empty-anchor vector"*.
   The empty-anchor vector produces **zero** anchor slots, so it witnesses
   nothing about `absent`; the clause passes vacuously and would keep passing
   if the variant were deleted (§4a). Replace with *"`absent` covered by
   calling the evaluator on an anchor kind the bundle does not carry; a
   companion test asserts R12 emits no `AnchorResult` slot for it and the
   empty-anchor vector still serializes `\"anchors\":[]`."*

---

## 12. Residual risks and revisit triggers

- **The verifier page cannot show the diagnostic code** (§6). A page user sees
  `invalid` with no reason; the CLI user sees the code. Trigger: any
  `report_version` bump — carry the code with it. Do not bump *for* this.
- **The back-dating direction rests on one test.** Sub-case 3 has no spec
  line, no `MATRIX.json` case and no row (§8) — only
  `a_certificate_not_yet_valid_at_gentime_is_the_same_code`. If A21 or a later
  refactor deletes it, the whole direction goes unguarded silently. Trigger:
  any change to A9's temporal predicate; consider promoting it to a
  `project_added[]` row at that point, which needs a second code.
- **No revocation checking, by scope** (A9's own note: *"No revocation
  fetching (out of MVP scope)"*). A TSA key compromised and its certificate
  revoked *after* `genTime` still yields `Proven` here, and under sub-ruling
  (a) a revoked **root** is not detected at all. This is the accepted MVP
  position and Q's threat model documents it; recorded because the LTV
  framing ("valid at stamping") reads as stronger than it is. Trigger: any
  v1.1 CRL/OCSP work, or a real TSA compromise.
- **Least-severe-wins is chosen for a property, not for user-facing
  precision** (§3). On a multi-defect artifact the reported code names the
  *best* path's failure, so a bundle with one expired path and fifteen
  forged ones reports the temporal code. That is the honest diagnosis of the
  artifact's best attempt, and A39's anomaly list carries the rest — but a
  reader of the code alone will under-read the artifact. Trigger: A39
  landing, at which point R18's wording should lead with the anomaly count.

## Index row (orchestrator applies at merge)

| [D53](D53-chain-invalid-at-gentime.md) | State for a TSA chain that does not validate at `genTime` — the register's **binary framing is overturned**: the question is a six-way partition and MVP-SPEC.md:109/133 had already ruled two sub-cases the *opposite* way from the lean. Partition principle (shared with D56): **`invalid` iff the artifact makes a claim the verifier can refute from trusted material; `internally-consistent-only` iff it makes no refutable and no confirmable claim**. Temporal failure at `genTime` (**both** directions — the not-yet-valid/back-dating half is named in no spec line, task or matrix entry), failed path constraints, and a failed link signature on a chain **naming a pinned root** → `Invalid` with three new `anchor-` codes; no pinned root reached, bundle-supplied roots included → `InternallyConsistentOnly`. Decisive evidence for the lean's true scope is mechanical rather than editorial: error-contract §4b layer 3 refuses a pending row re-claiming `anchor-untrusted-root`'s `verdict:internally-consistent-only` key, and its only escape hatch is an explicit record asserting the two mutations are **one observable** — false for "unpinned TSA" vs "back-dated token". (The check is dormant today because both rows carry `expected: null` — itself the defect Q76 fixes.) Rules quantify over the candidate-path *set*, so the state is permutation-invariant and a relay cannot demote an honest anchor by appending a certificate to the **unsigned** bundle. Also found: **there is no `anchor-` error-code prefix** (§2's table has no A row, and A cannot borrow `bundle-`), and line 168's M2 enumeration is **six clauses / eight cases**, with two incompatible "sevens" in the tree. Zero frozen report bytes change — held so by keeping diagnostic codes out of `AnchorResult` (D86's ruling, one domain over) | RESOLVED | 2026-08-02 |
