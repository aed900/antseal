# D84 — Are A's M2 `.ots`/DER structural limits format-permanent?

- **Status: RESOLVED — NO, the numeric limits are not v1 format surface and
  do not freeze at Q14. The register's scoping is confirmed; its proposed
  *mechanism* is overturned. There is no exception to MVP-SPEC.md line 123,
  named or otherwise, because nothing about deferring these limits violates
  it. What Q14 freezes instead is the **placement and failure shape** of
  artifact-internal limits (§4), which is a structural property and must be
  decided now.**
- **Date: 2026-07-28** (planning; A27 records the contract, A5/A11 consume it
  at M2, Q14 quotes §7 verbatim)

## Context

`docs/decisions/D10-parser-caps.md` §"Consequences" item 4 registered this
question — under the number "D83", which went to G20's finding the same day —
and recommended:

> scope them explicitly as post-freeze, and record in the format-stability
> policy that artifact-internal limits are a named, documented exception to
> line 123 — the alternative is guessing DER limits at M0 with no recorded
> real token to check against.

D10's own argument for pulling rows 16–19 (`MAX_OTS_BYTES`,
`MAX_TSA_TOKEN_BYTES`, `MAX_INTERMEDIATE_CERT_BYTES`, receipt payload) into
M0 was: *"a byte-length cap on a `bstr` field decides whether a given
`.sealproof` is valid v1, so it must freeze with format v1."* tasks/A.md A5
promises "max response size, max certificate count/size, max signed-attribute
count, max nesting depth" and A11 "strict limits (max file size, max op
count, max append/prepend operand length, max branch depth/width, max
attestation count)" — both at **M2, after Q14 closes**. The register's worry
is that the same argument applies and the freeze scope is therefore
undecided.

It does not apply, for a reason neither D10 nor the register states.

## 1. The framing is wrong in two places

### 1a. The spec already scopes this, explicitly, twice

MVP-SPEC.md line 153 (M0) bounds the hardening mandate to **the formats M0
owns** and then says so in parentheses:

> **parser hardening for the formats M0 owns** — […] hard caps on bundle
> size/unit count/depth/allocations; cargo-fuzz targets for the
> bundle/manifest CBOR parsers in CI (**DER/`.ots` limits + fuzzers are
> M2**).

and, on the tamper matrix in the same line:

> Golden vectors + property tests + the **format/commitment/signature/
> structural** tamper-matrix rows (**anchor rows are M2**).

Line 155 (M2) then owns them: *"strict DER + `.ots` op/length limits and
their **cargo-fuzz targets**; the **anchor tamper-matrix rows**."*

So the scoping is not an open decision — it is normative text, and it has
been since the spec was written. What was genuinely open, and is what this
record answers, is whether that scoping is **safe**: whether a limit
introduced at M2 can retroactively invalidate a bundle sealed under v1.

### 1b. A "named exception to line 123" would be a mistake

Line 123 reads:

> **Format stability (normative)**: every released manifest/bundle format
> version remains verifiable by all future CLI and page releases; per-version
> golden vectors are retained in CI indefinitely; the hosted page supports
> all released versions.

Carving a named exception into a normative stability promise, at the exact
moment of the freeze that promise governs, is a bad trade: the exception is
permanent, it is quotable by any future task that finds a cap inconvenient,
and it concedes something that is not actually true. §2 and §3 show line 123
is never at risk, so the exception buys nothing and costs the strength of the
rule. **Do not write it.**

## 2. Why introducing these limits at M2 cannot break line 123

Line 123 binds a future release not to reject what a past release accepted.
For that to be at risk, some released verifier must have **rendered a verdict
that depends on artifact internals**. None ever has, and none can before M2:

1. **The M0 verifier does not look inside an anchor artifact at all.** R12's
   task text is explicit — it "replace[s] the M0 `absent` stub". Every anchor
   in an M0 bundle renders `absent`; the artifact bytes are carried and
   never parsed.
2. **This is asserted on disk, as an equality, not an intention.** R10's
   sweep measured the M0 authentication boundary and pinned the anchor
   artifacts as inert in
   `crates/antseal-core/tests/verify_fuzz.rs::m0_anchor_artifacts_are_inert_until_r12_wires_the_anchor_stage`
   — a test written to go red when R12 lands, with the instruction to invert
   it (`docs/security-assumptions.md`, "The M0 authentication boundary,
   measured").
3. **No bundle carrying a real artifact can exist before M2.** M1 (line 154)
   ships zero-anchor seals via `--no-anchor`; the OTS calendar client and the
   RFC 3161 request path are M2 (line 155). The first `.ots` and the first
   TSA token are produced by the same milestone that defines the limits.

The freeze discipline's whole basis — *"everything frozen at Q14 is permanent
once the first real seal exists"* — therefore does not bind here. There is no
released verdict to preserve and no sealed artifact to grandfather. Choosing
these numbers at M2, against A25's recorded real FreeTSA and DigiCert tokens
and a real pending/upgraded `.ots`, is strictly better evidence than choosing
them at M0 against nothing.

## 3. Why they are not format surface either

A v1 `.sealproof` is a CBOR document. Its anchor fields are **opaque `bstr`s**
(`docs/format/registry-v1.md` §7.8, §7.9). The v1 format's complete statement
about an `.ots` is: *a byte string, at most `MAX_OTS_BYTES`, in OTS anchor key
1*. The format has, and should have, no opinion on whether that byte string
contains 40 operations or 4 000 — exactly as it has no opinion on whether a
`title` string is a haiku.

`.ots` and DER are **foreign formats**, defined by OpenTimestamps and by
RFC 3161/5652/5280. Freezing our reading of a foreign format at Q14 would
freeze the wrong thing: those formats evolve on their own schedule, and a
`.sealproof` that embeds a valid-but-larger token five years from now must
still be verifiable. Limits over foreign content are **verifier policy**, and
verifier policy is the category line 123 does not govern.

## 4. What *is* frozen — and this is the part that cannot wait

The safety argument in §2 holds only if an over-limit artifact fails in a way
that leaves the rest of the bundle alone. If an oversized `.ots` made
`SealProof::decode` return an error, an M2 verifier *would* reject a bundle an
M1 verifier accepted, and line 123 *would* be violated — by the placement of
the check, not by its value. So the placement freezes at Q14 even though the
numbers do not.

**The four frozen rules. These are v1; A5, A11, A18 and R12 must implement
them exactly.**

- **F1 — Placement.** Artifact-internal limits are evaluated **only in the
  anchor stage (R12)**, never in verify stage 1. Stage 1's job over an anchor
  field is complete when the `bstr` decodes canonically and passes D10's byte
  cap. `SealProof::decode` must never open an artifact. (This matches D10 §6's
  staging: every D10 cap fires in stage 1 *ahead of* every AEAD, hash and
  signature; the anchor stage is downstream of all of it.)
- **F2 — Blast radius.** Exceeding an artifact-internal limit produces a
  **per-anchor verdict for that anchor only**. It never fails bundle
  decoding, never fails the evidence layer, never changes another anchor's
  state, and never changes the manifest verdict. A bundle whose sole `.ots`
  is over-limit still verifies its content and still renders its TSA anchors.
- **F3 — Verdict mapping.** An over-limit artifact renders **`invalid`** for
  that anchor. Not `absent` (the artifact is present), and not
  `internally-consistent-only` (that state means well-formed-but-unanchored;
  an artifact we refused to finish reading is not known to be well-formed).
  `invalid` is already never headline-eligible (MVP-SPEC.md lines 129–137),
  so an over-limit artifact can never contribute a headline time. **A11's
  "unknown ops/attestation types surface as typed unverifiable results" is a
  different case and keeps its own treatment** — unknown ≠ over-limit.
- **F4 — Monotonicity after M2's first release.** Once a released build
  verifies real anchors, artifact-internal limits may be **raised, never
  lowered**. Raising cannot reject a bundle a past release accepted;
  lowering can. Any lowering is a format-version event and requires the
  full freeze procedure (Q19). Record every limit's value and every change
  in the registry A27 creates, so "has this ever been lowered?" is answerable
  from the tree.

F1–F3 are the reason no exception to line 123 is needed: under them, adding
a limit at M2 changes an anchor's rendering from `absent` (M0/M1's stub) to
`invalid`, and *never* changes whether the bundle is a valid v1 bundle.

## 5. Two of A's promised caps are already frozen — A5/A11 must not mint duplicates

D10 rows 16 and 17 already fix, as v1 format surface:

| D10 row | constant | value | field |
| --- | --- | --- | --- |
| 16 | `MAX_OTS_BYTES` | `1_048_576` (1 MiB) | OTS anchor key 1 `ots` |
| 17 | `MAX_TSA_TOKEN_BYTES` | `1_048_576` (1 MiB) | TSA anchor key 1 `token` |
| 8 | `MAX_INTERMEDIATE_COUNT` | `16` | TSA anchor key 2 `intermediates` |

A11's promised "max file size" over a bundle-embedded `.ots` **is**
`MAX_OTS_BYTES` and A5's "max certificate count" over bundle-embedded
intermediates **is** `MAX_INTERMEDIATE_COUNT`. A second constant over the same
quantity is exactly the CLI-vs-page divergence MVP-SPEC.md line 73 exists to
prevent. **Ruling: A5 and A11 consume the D10 constants by name. They do not
define their own.**

A5's "max response size" is the one genuine near-duplicate and it is a
*different* quantity: it bounds the `TimeStampResp` read off the **network**
(A3/A4's HTTP path), before any bundle exists. It is not format surface — but
it is derived, not free:

> **Derived constraint**: the receive-side response cap MUST be
> `≤ MAX_TSA_TOKEN_BYTES`. A token accepted from a TSA that cannot afterwards
> be embedded in a `.sealproof` is a seal that anchors and then cannot be
> revealed.

The same derivation applies to A13's merged `.ots` against `MAX_OTS_BYTES`.

## 6. The residual open set — what A5/A11 actually still choose at M2

After §5, the genuinely open, genuinely M2, genuinely non-frozen numbers are:

| owner | limit | why it cannot be derived now |
| --- | --- | --- |
| A5 | max DER nesting depth | bounded by CMS SignedData structure; needs a real token to count against |
| A5 | max certificate count *in a chain being validated* (distinct from the bundle's `MAX_INTERMEDIATE_COUNT`) | depends on real TSA chain depth (A25) |
| A5 | max per-certificate size | RFC 5280 sets no ceiling; real DigiCert/FreeTSA certs set the scale |
| A5 | max signed-attribute count | CMS-defined set is small; the number is a hardening choice |
| A11 | max op count | OTS DAG shape from a real upgraded `.ots` |
| A11 | max append/prepend operand length | ditto |
| A11 | max branch depth / width | ditto |
| A11 | max attestation count | bounded in practice by the ≥2-calendar policy; the cap is hardening |

Every one of these is measured against an artifact A25 records. That is the
register's point, and it stands — it just is not an argument about line 123.

**Guidance carried into A27, in D10 §"Opaque artifact byte caps"'s own words:
guessing high is free, guessing low is a compatibility break.** Under F4 these
limits can only ever be raised, so choose them generously enough that no
honest artifact approaches them, and treat the F4 registry as the record that
they never had to move.

## 7. The v1 freeze boundary, in words Q14's checklist quotes verbatim

This is the deliverable the register asked for. Q14 adds these two rows to its
checklist; A27 mirrors the same text so A5/A11 read the same sentences.

> - [ ] **Anchor-artifact freeze scope (D84).** Inside the v1 freeze: the
>   anchor **envelope** — that an `.ots`, a TSA token, an intermediate
>   certificate and a receipt payload are opaque CBOR `bstr`s in their
>   registered keys (`docs/format/registry-v1.md` §7.8, §7.9); D10's byte and
>   count caps over those fields — rows 6, 7, 8, 9, 16, 17, 18, 19:
>   `MAX_OTS_ANCHOR_COUNT`, `MAX_TSA_ANCHOR_COUNT`, `MAX_INTERMEDIATE_COUNT`,
>   `MAX_TX_HASH_COUNT`, `MAX_OTS_BYTES`, `MAX_TSA_TOKEN_BYTES`,
>   `MAX_CERT_BYTES`, `MAX_RECEIPT_PAYLOAD_BYTES` — with their error codes;
>   and rules **F1–F4** of D84 §4 (limits are
>   evaluated only in the anchor stage; an over-limit artifact fails that
>   anchor alone as `invalid`; limits may afterwards be raised, never
>   lowered). **Outside the v1 freeze:** every numeric limit on the
>   *internal* structure of those artifacts — DER nesting depth, certificate
>   count and size within a validated chain, signed-attribute count, `.ots`
>   op count, operand length, branch depth/width, attestation count. Those
>   are verifier policy over foreign formats, are set at M2 against A25's
>   recorded real artifacts (MVP-SPEC.md lines 153 and 155 place them there),
>   and are **not** an exception to line 123 — under F1–F3 no released
>   verifier ever rendered a verdict that depends on them, because M0/M1
>   render every anchor `absent` (R12 replaces that stub at M2).
> - [ ] **Report-version evolution is not blocked by this freeze.** The Q14
>   freeze fixes report **v1** (`REPORT_VERSION = 1`, per R32 and D29 §8).
>   D29 records that adding fields after the freeze requires a version bump,
>   not that no bump may occur. M2's anchor stage will populate anchor states
>   that report v1 does not carry and will therefore ship report **v2**; that
>   is ordinary versioned evolution under line 123, whose promise is that v1
>   reports remain verifiable, not that v1 is the last version.

The second row exists because "all M0 golden vectors committed and frozen" is
otherwise readable as "the report format is closed", and R32's 0→1 bump
landing in this same wave makes that misreading easy to fall into.

## 8. Losing options and their real costs

**Freeze placeholder limits at Q14.** The alternative the register names.
Costs: numbers chosen against zero recorded artifacts become permanent under
D10's own "lowering is the break" rule; a too-low DER nesting depth chosen in
July would reject a legitimate DigiCert chain in September with no recourse
short of a format version; and it drags eight new error codes into the M0
append-only code registry for checks that cannot fire until M2. Rejected.

**Freeze the limits as "advisory" — enforce at M2 but do not treat as
verdict-bearing.** Superficially attractive; it is D27's rejected shape in a
new costume. A limit that does not change a verdict is not a limit, it is a
log line, and A5's whole purpose (MVP-SPEC.md line 187, hostile bundles) is to
stop a hostile artifact before it exhausts a browser. Rejected.

**Name an exception to line 123 (the register's mechanism).** Rejected in
§1b: it concedes something untrue and permanently weakens a normative rule.
The substantive half of the register's recommendation — *scope them as
post-freeze* — is adopted; only the mechanism is replaced, by F1–F4.

**Fold the limits into D10 as rows 20–27 with `status: "deferred"`.** Keeps
one registry, but puts non-format policy inside the frozen cap table and
invites a later reader to treat them as frozen. The A27 registry is a
separate artifact for that reason. Rejected.

## 9. What the implementer must report back

A27 (M0 doc) reports:

1. The exact path of the limit registry it created and the exact §7 text it
   mirrors, confirming it is byte-identical to the Q14 checklist row (a
   paraphrase here is how the two drift).
2. Confirmation that A5's and A11's entries in `tasks/A.md` now name the D10
   constants (§5) rather than promising their own, and that A5's receive-side
   cap carries the `≤ MAX_TSA_TOKEN_BYTES` derivation.

A5/A11 (M2) report:

3. Each chosen number, the recorded real artifact it was measured against
   (A25 fixture path), and the margin — the same table shape D10 §2 uses.
4. Confirmation that no artifact-internal limit is reachable from
   `SealProof::decode` (F1), demonstrated by a test that an over-limit
   artifact still yields a decodable bundle with a verified manifest and only
   its own anchor `invalid` (F2/F3).
5. The F4 registry rows, with the initial values and a `lowered: never`
   marker each.

## Consequences and open actions

1. **A27 registered** (`tasks/A.md`): write the anchor-artifact limit
   contract — F1–F4, the §5 constant-reuse ruling, the §6 open set, and the
   F4 registry skeleton — as an M0 document A5/A11 read at M2. Precedent:
   F19, which handed F14 its sidecar contract for exactly this reason.
2. **A28 registered** (`tasks/A.md`): reconcile A5's "max response size" and
   A13's merged-`.ots` size against D10's frozen bundle-field caps, per §5's
   derived constraint.
3. **Q37 registered** (`tasks/Q.md`): add §7's two rows to the Q14 checklist
   and carry the same freeze-boundary statement into Q19's format-stability
   policy.
4. **A5 and A11's `Do` text is now partly wrong on disk** — both promise caps
   that §5 rules are already-frozen D10 constants. A27 fixes the text; until
   it does, an implementer reading `tasks/A.md` alone would mint duplicates.
5. **D10 §"Consequences" item 4's recommendation is superseded** by this
   record. D10 itself is unchanged — its 19 caps and their permanence stand;
   only the recommendation it registered for D84 is overturned in mechanism.
6. **R12's Accept criteria should gain the F2 case** (over-limit artifact →
   that anchor `invalid`, bundle otherwise unaffected) when A's fixtures
   exist. Flagged, not edited — `tasks/R.md` is another planner's this wave.

## Outcome

**RESOLVED, 2026-07-28.** The numeric `.ots`/DER structural limits are **not**
v1 format surface and do **not** freeze at Q14; they are set at M2 against
A25's recorded artifacts, as MVP-SPEC.md lines 153 and 155 already provide.
No exception to line 123 is created — under rules F1–F4 (§4) none is needed,
because M0/M1 render every anchor `absent` and no released verdict depends on
artifact internals. What *does* freeze at Q14 is the anchor envelope, D10's
byte and count caps over it, and F1–F4 themselves. A5's and A11's promised
byte/count caps over bundle-embedded artifacts are ruled to be the existing
D10 constants, not new ones. §7 is the verbatim freeze-boundary text for
Q14's checklist.
