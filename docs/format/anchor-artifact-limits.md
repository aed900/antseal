# Anchor-artifact limits — the contract A5 and A11 read at M2

> **Owning task: A27** (`tasks/A.md`), milestone **M0**. **Source of truth:
> [`docs/decisions/D84-anchor-artifact-limits-permanence.md`](../decisions/D84-anchor-artifact-limits-permanence.md)**
> (RESOLVED 2026-07-28). This document exists because a rule that lives only
> in a decision record is a rule the implementing task rediscovers or
> contradicts — the F19 -> F14 precedent.
>
> **There are no numbers in this document, deliberately.** The numeric
> `.ots`/DER structural limits are set at **M2**, measured against the real
> artifacts A25 records. Writing placeholder values here is the failure mode
> D84 §8 rejects: a number chosen against zero recorded artifacts becomes
> permanent under F4's raise-only rule.

## 0. What this document is

Three things, and nothing else:

1. **The four structural rules that *do* freeze at Q14** (§1) — where an
   artifact-internal limit may be evaluated, what it may fail, what verdict
   it renders, and which direction it may move afterwards. These are v1.
   A5, A11, A18 and R12 implement them exactly.
2. **The v1 freeze boundary in quotable words** (§2) — what is inside the
   freeze and what is outside it, byte-identical to the row Q14's checklist
   carries.
3. **A ruling that stops two duplicate constants being minted** (§3), the
   list of limits genuinely left open (§4), and the registry that records
   them once they are chosen (§5).

It is **not** a cap table. `docs/decisions/D10-parser-caps.md` is the cap
table, and every cap in it is frozen v1 format surface.

## 1. The four frozen rules (D84 §4, verbatim)

**These are v1; A5, A11, A18 and R12 must implement them exactly.**

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

> **Editorial note, A27 (2026-07-28) — one cross-reference in F4 is wrong,
> and the rule is carried verbatim anyway.** F4 says a lowering "requires the
> full freeze procedure (Q19)". `tasks/Q.md` **Q19** is the headless-browser
> (playwright) page-verification CI lane, an M3 task. The format-stability
> policy document is **Q27**, and the freeze procedure Q27 mirrors is
> **Q14**. Read F4's parenthesis as **(Q27, mirroring Q14)**. The rule text
> is reproduced unaltered because A27's Accept criterion requires
> byte-identity with D84 — correcting the source is D84's edit to make, not
> this document's. The same mis-numbering appears in D84 §Consequences
> item 3 and in Q37's entry; all three are the same slip, recorded once here.

### 1a. Why F1–F3 are the reason no exception to line 123 exists

Under F1–F3, adding an artifact-internal limit at M2 changes an anchor's
rendering from `absent` (M0/M1's stub) to `invalid`, and **never** changes
whether the bundle is a valid v1 bundle. MVP-SPEC.md line 123 binds a future
release not to reject what a past release accepted; no released verifier has
ever rendered a verdict that depends on artifact internals, and none can
before M2:

- The M0 verifier does not look inside an anchor artifact at all. Every
  anchor in an M0 bundle renders `absent`; the artifact bytes are carried
  and never parsed. R12 replaces that stub at M2.
- This is pinned on disk **as an equality, not an intention**:
  `crates/antseal-core/tests/verify_fuzz.rs::m0_anchor_artifacts_are_inert_until_r12_wires_the_anchor_stage`
  — a test written to go red when R12 lands, with the instruction to invert
  it (`docs/security-assumptions.md`, "The M0 authentication boundary,
  measured").
- No bundle carrying a real artifact can exist before M2. M1 ships
  zero-anchor seals via `--no-anchor`; the OTS calendar client and the
  RFC 3161 request path are M2. The first `.ots` and the first TSA token are
  produced by the same milestone that defines the limits.

So **no exception to MVP-SPEC.md line 123 is created, named or otherwise.**
Anyone proposing to write one should read D84 §1b first: the exception would
be permanent, quotable by any future task that finds a cap inconvenient, and
it concedes something that is not true.

## 2. The v1 freeze boundary (D84 §7, verbatim)

The two rows below are byte-identical to the rows in Q14's freeze checklist
(`tasks/Q.md`, landed by task Q37). They are reproduced here so A5 and A11
read the same sentences the gate does.

<!-- FREEZE-BOUNDARY:BEGIN — D84 §7 verbatim. Byte-identical copies live in `tasks/Q.md` (Q14) and this file; `scripts/check-traceability.py --freeze-boundary` fails if they drift. Edit D84 first, then both copies. -->

- [ ] **Anchor-artifact freeze scope (D84).** Inside the v1 freeze: the
  anchor **envelope** — that an `.ots`, a TSA token, an intermediate
  certificate and a receipt payload are opaque CBOR `bstr`s in their
  registered keys (`docs/format/registry-v1.md` §7.8, §7.9); D10's byte and
  count caps over those fields — rows 6, 7, 8, 9, 16, 17, 18, 19:
  `MAX_OTS_ANCHOR_COUNT`, `MAX_TSA_ANCHOR_COUNT`, `MAX_INTERMEDIATE_COUNT`,
  `MAX_TX_HASH_COUNT`, `MAX_OTS_BYTES`, `MAX_TSA_TOKEN_BYTES`,
  `MAX_CERT_BYTES`, `MAX_RECEIPT_PAYLOAD_BYTES` — with their error codes;
  and rules **F1–F4** of D84 §4 (limits are
  evaluated only in the anchor stage; an over-limit artifact fails that
  anchor alone as `invalid`; limits may afterwards be raised, never
  lowered). **Outside the v1 freeze:** every numeric limit on the
  *internal* structure of those artifacts — DER nesting depth, certificate
  count and size within a validated chain, signed-attribute count, `.ots`
  op count, operand length, branch depth/width, attestation count. Those
  are verifier policy over foreign formats, are set at M2 against A25's
  recorded real artifacts (MVP-SPEC.md lines 153 and 155 place them there),
  and are **not** an exception to line 123 — under F1–F3 no released
  verifier ever rendered a verdict that depends on them, because M0/M1
  render every anchor `absent` (R12 replaces that stub at M2).
- [ ] **Report-version evolution is not blocked by this freeze.** The Q14
  freeze fixes report **v1** (`REPORT_VERSION = 1`, per R32 and D29 §8).
  D29 records that adding fields after the freeze requires a version bump,
  not that no bump may occur. M2's anchor stage will populate anchor states
  that report v1 does not carry and will therefore ship report **v2**; that
  is ordinary versioned evolution under line 123, whose promise is that v1
  reports remain verifiable, not that v1 is the last version.

<!-- FREEZE-BOUNDARY:END -->

## 3. A5's and A11's promised byte/count caps **are** the D10 constants

D10 already fixes these, as v1 format surface, with their error codes:

| D10 row | constant | value | field | error code |
| --- | --- | --- | --- | --- |
| 8 | `MAX_INTERMEDIATE_COUNT` | `16` | TSA anchor key 2 `intermediates` | `bundle-too-many-intermediates` |
| 16 | `MAX_OTS_BYTES` | `1_048_576` (1 MiB) | OTS anchor key 1 `ots` | `bundle-ots-too-large` |
| 17 | `MAX_TSA_TOKEN_BYTES` | `1_048_576` (1 MiB) | TSA anchor key 1 `token` | `bundle-tsa-token-too-large` |
| 18 | `MAX_CERT_BYTES` | `65_536` (64 KiB) | each `intermediates` element | `bundle-cert-too-large` |

A11's promised "max file size" over a bundle-embedded `.ots` **is**
`MAX_OTS_BYTES`. A5's "max certificate count" over bundle-embedded
intermediates **is** `MAX_INTERMEDIATE_COUNT`, and its "max certificate size"
over those elements **is** `MAX_CERT_BYTES`. A second constant over the same
quantity is exactly the CLI-vs-page divergence MVP-SPEC.md line 73 exists to
prevent.

> **Ruling (D84 §5): A5 and A11 consume the D10 constants by name. They do
> not define their own.**

### 3a. The one genuine near-duplicate, and its derived constraint

A5's "max response size" is a **different quantity**: it bounds the
`TimeStampResp` read off the **network** (A3/A4's HTTP path), before any
bundle exists. It is not format surface — but it is derived, not free:

> **Derived constraint**: the receive-side response cap MUST be
> `<= MAX_TSA_TOKEN_BYTES`. A token accepted from a TSA that cannot afterwards
> be embedded in a `.sealproof` is a seal that anchors and then cannot be
> revealed.

The same derivation applies to A13's merged `.ots` against `MAX_OTS_BYTES`.
**A28** owns both reconciliations and records the two chosen values in the
§5 registry below.

## 4. What A5 and A11 actually still choose at M2 (D84 §6)

After §3, the genuinely open, genuinely M2, genuinely non-frozen numbers are
these eight. Each is measured against an artifact **A25** records:

| owner | limit | why it cannot be derived now |
| --- | --- | --- |
| A5 | max DER nesting depth | bounded by CMS SignedData structure; needs a real token to count against |
| A5 | max certificate count *in a chain being validated* (distinct from the bundle's `MAX_INTERMEDIATE_COUNT`) | depends on real TSA chain depth (A25) |
| A5 | max per-certificate size | RFC 5280 sets no ceiling; real DigiCert/FreeTSA certs set the scale |
| A5 | max signed-attribute count | CMS-defined set is small; the number is a hardening choice |
| A11 | max op count | OTS DAG shape from a real upgraded `.ots` |
| A11 | max append/prepend operand length | ditto |
| A11 | max branch depth / width | ditto |
| A11 | max attestation count | bounded in practice by the >=2-calendar policy; the cap is hardening |

**Guidance, in D10's own words: guessing high is free, guessing low is a
compatibility break.** Under F4 these limits can only ever be raised, so
choose them generously enough that no honest artifact approaches them, and
treat the §5 registry as the record that they never had to move.

Note what is *not* in this table: A11's "unknown ops/attestation types
surface as typed unverifiable results". Per F3, unknown is not over-limit;
that behaviour keeps its own treatment and is not governed by a limit at all.

## 5. The F4 registry

**Empty at M0. This is correct** — no limit has been chosen yet. A5, A11 and
A28 fill it at M2; nothing else may.

| limit | owner | initial value | date set | measured against (A25 fixture path) | margin | lowered |
| --- | --- | --- | --- | --- | --- | --- |
| _(empty at M0 — A5/A11/A28 fill this at M2)_ | | | | | | |

**Update rule.** One row per artifact-internal limit and per receive-side
cap, added when the limit is first set, never deleted. `lowered` starts at
`never` and is the only cell that may change; changing it away from `never`
is a **format-version event** requiring the full freeze procedure (Q27,
mirroring Q14) and a dated note in §6 saying which release lowered it and
why. A raise is recorded by appending the new value and its date to the
`initial value` cell — the history stays readable, so *"has this ever been
lowered?"* is answerable from the tree, which is the whole point of F4.

Rows A28 must add on day one: the TSA receive-side response cap
(`<= MAX_TSA_TOKEN_BYTES`) and the merged-`.ots` cap (`<= MAX_OTS_BYTES`).

## 6. Changelog

- **2026-07-28 (M0 wave 6, A27/D84)** — document created. F1–F4 and the §2
  freeze-boundary rows carried verbatim from D84; the §3 constant-reuse
  ruling recorded and `tasks/A.md`'s A5 and A11 `Do` text corrected to match
  it (both previously promised caps that §3 rules already frozen, so an
  implementer reading `tasks/A.md` alone would have minted duplicates). One
  cross-reference in F4 flagged as wrong and carried unaltered — see the
  editorial note in §1. F4 registry created empty.
