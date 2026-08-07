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
  full freeze procedure (**Q27** — see the 2026-07-28 correction in D84).
  Record every limit's value and every change
  in the registry A27 creates, so "has this ever been lowered?" is answerable
  from the tree.

> **Editorial note, A27 (2026-07-28), RESOLVED 2026-07-28 (wave 7) — the
> cross-reference was wrong at the source, and the source has since been
> corrected, so this mirror is re-cut.** F4 said a lowering "requires the
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

- The M0 verifier did not look inside an anchor artifact at all. Every
  anchor in a bundle verified by the M0 verifier rendered `absent`; the
  artifact bytes were carried and never parsed. R12 replaced that stub at
  M2, so this clause is historical.
- What is pinned on disk **as an equality** is narrower than this document
  once claimed:
  `crates/antseal-core/tests/verify_fuzz.rs::anchor_artifact_bytes_never_change_the_bundles_accept_reject_outcome`
  pins rule **F2** and only F2 — no anchor byte moves `verify_bundle`'s
  accept/reject outcome — which is permanent, and the test is the standing
  guard for it. It never pinned that no verdict depends on artifact
  internals, and the former instruction to "invert it at R12" was wrong
  (**D94** §4; `docs/security-assumptions.md`, "The M0 authentication
  boundary, measured").
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
  rendered every anchor `absent` (R12 replaced that stub at M2, and this
  row is the historical statement it was always meant to be).
- [ ] **Report-version evolution is not blocked by this freeze.** The Q14
  freeze fixes report **v1** (`REPORT_VERSION = 1`, per R32 and D29 §8).
  D29 records that adding fields after the freeze requires a version bump,
  not that no bump may occur. M2's anchor stage populates anchor states that
  report v1 **already carries** — `AnchorState::ALL` is all seven at the
  freeze — so R12 moves recomputed verdicts, not format surface, and
  `REPORT_VERSION` stays 1 (**D94**: a VERDICT EVENT re-emits the frozen
  vector under the full ceremony and bumps nothing). A bump remains
  available for a genuine field addition; line 123's promise is that v1
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
A28 fill it at M2 — **and A42**, added 2026-08-03: D54 §7 rules a registry row
for `MAX_OTS_CALENDAR_RESPONSE_BYTES` and this list of owners predates that
decision. Nothing outside those four may.

| limit | owner | initial value | date set | measured against (A25 fixture path) | margin | lowered | structural cost (D102) |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `MAX_OTS_OPS` | A11 | 4_096 | 2026-08-02 | `testdata/anchors/A25-bootstrap/upgraded/rust-opentimestamps-LARGE_TEST.ots` (100 ops; **bootstrap** measurement taken on the rust-opentimestamps `LARGE_TEST` mainnet proof, blocks 449397/449399, pending A25's two-day cycle) | 40.96x | never | **none** — bounds work, not a container |
| `MAX_OTS_DEPTH` | A11 | 1_024 | 2026-08-02 | `testdata/anchors/A25-bootstrap/upgraded/rust-opentimestamps-LARGE_TEST.ots` (depth **67**; bootstrap measurement as above) | 15.28x | never | **40 960 B** = `next_pow2(1_024) x size_of::<Frame>()` (40 B, x86-64) — the parser's `walk.rest`; **3.91 %** of `MAX_OTS_BYTES` |
| `MAX_OTS_BRANCH_WIDTH` | A11 | 64 | 2026-08-02 | `testdata/anchors/A25-bootstrap/merged-A.ots` (width 3) | 21.33x | never | **none** — a per-node counter, no container |
| `MAX_OTS_ATTESTATIONS` | A11 | 256 | 2026-08-02 | `testdata/anchors/A25-bootstrap/merged-A.ots` (3) and `.../upgraded/rust-opentimestamps-LARGE_TEST.ots` (4, the binding one; bootstrap measurement as above) | 64.00x | never | **12 288 B** = `next_pow2(256) x size_of::<OtsAttestation>()` (48 B, x86-64); **1.17 %** of `MAX_OTS_BYTES` |
| `MAX_OTS_OPERAND_BYTES` | A11 | 16_384 | 2026-08-02 | `testdata/anchors/A25-bootstrap/upgraded/rust-opentimestamps-LARGE_TEST.ots` (174 B coinbase-prefix operand; bootstrap measurement as above) | 94.16x | never | **none** — a length header; D58 §10.3 rule 4's clamp governs it |
| `MAX_OTS_VALUE_BYTES` | A11 | 32_768 | 2026-08-02 | `testdata/anchors/A25-bootstrap/upgraded/rust-opentimestamps-LARGE_TEST.ots` (210 B running value; bootstrap measurement as above) | 156.04x | never | **none** — rule 4; `exec::apply` allocates the running value after checking it (32 B on the A100 path) |
| `MAX_OTS_ATTESTATION_PAYLOAD_BYTES` | A11 | 8_192 | 2026-08-02 | `testdata/anchors/A25-bootstrap/merged-A.ots` (46 B pending payload); value taken from python-opentimestamps `MAX_PAYLOAD_SIZE` | 178.09x | never | **none** — a length header; rule 4 |
| `MAX_OTS_CALENDAR_RESPONSE_BYTES` | A42 | 65_536 | 2026-08-02 | `testdata/anchors/A25-bootstrap/A-catallaxy.timestamp` (220 B — the largest of 18 real calendar **submit** responses measured for D54 §8b). The **upgrade** response is larger, carrying a Bitcoin merkle path, and has not been measured: A25's day-2 run must record it and append the second margin here (D54 §6.1) | 298.0x (submit; upgrade **not yet measured**) | never | **none** — a receive-side byte cap, not a count limit |

**A note on the row above, because the next reader will assume one number
serves both.** `MAX_OTS_CALENDAR_RESPONSE_BYTES` bounds **one HTTP reply from
one calendar**. `MAX_OTS_BYTES` (§2 row 16, 1 MiB) bounds the **merged `.ots`
artifact** a bundle embeds — every calendar, every upgrade, accumulated. They
are different quantities, and passing the second where the first belongs would
let four calendars hand `antseal-anchor` 4 MiB per seal against a measured
worst case of 220 B. It is also the only one of the rows here that is a
*network-stage* limit rather than an *artifact-parse* limit, which is why it
is not one of the eight §4 leaves it open. The strict inequality between the
two is a compile-time assertion in `crates/antseal-anchor/src/ots/mod.rs` and
`crates/antseal-anchor/src/http.rs` — strict, because equality *is* the
conflation.

**Four of the first seven rows were bootstrapped, not measured, and say so in
the cell.** *(Corrected 2026-08-03. This read "No real *upgraded* `.ots` of this
project's own exists yet — A25's two-day OTS pending → upgraded cycle started
2026-08-02T19:16Z and **cannot complete before 2026-08-04**". **Six now exist.**
The cycle completed in **13 h 47 m**, not 48 h: all six commitments returned 200
with a Bitcoin attestation at 2026-08-03T09:03Z, having served the pending body
at 19:34Z. Nothing in the protocol promises two days — a calendar aggregates and
commits its root to Bitcoin, and the wait is however long that takes. The
bootstrapped rows may now be re-measured against real material; A25 owes that
re-measurement. This paragraph sits outside the §7 rule text the freeze-boundary
check pins byte-for-byte, so correcting it here is legitimate — it is narrative,
not rule.)* The `upgraded/` rows were measured against the
`LARGE_TEST` constant of `opentimestamps-0.2.0`, a genuine mainnet proof over
Bitcoin blocks 449397 and 449399 (≈ January 2017), committed with its
provenance at `testdata/anchors/A25-bootstrap/upgraded/PROVENANCE.md`.
**A25 must re-measure them against the real fixture and append.** The values
do not change — F4 forbids lowering and none needs raising — but the
provenance cell must stop citing a third-party crate's test constant. Every
number in the `measured against` cells is produced by the parser itself
(`anchor::ots::parse_ots_measured`), so a re-measurement is a call rather
than a second implementation.

**Correction to D58 §9.5, recorded rather than silently applied.** D58's
rows read *depth 69* for the upgraded proof and *depth 13* for the merged
pending file. Under D58 §9.3's own normative definition — *"edges from the
root step, root at 0 … a chain of `N` ops terminated by an attestation has
maximum depth `N`"*, which §9.3 says *"must be the one the implementation
uses"* — the measured depths are **67** and **12**: an attestation is a leaf
hanging off a node, not a node of its own. Both values were confirmed by an
independently written length-respecting scanner as well as by the parser.
The direction is safe (the margin grows, 14.84x → 15.28x) and F4 forbids
lowering, so nothing moves; the cell records what was measured.

### 5a. The `structural cost` column, and the precondition it attaches to F4

**Added 2026-08-07 by [D102](../decisions/D102-parser-structural-allocation-cost.md)
(task A100), which amends D58 §10.3 with a sixth rule.**

A limit that bounds a **count** rather than a **length header** is not
governed by the clamp discipline every other allocation in this codebase
obeys. `walk.rest` — the `.ots` parser's iterative work stack — is bounded by
`MAX_OTS_DEPTH` and by nothing else, has no claimed length to clamp against,
and therefore costs `next_power_of_two(limit) x size_of::<Element>()` bytes
whatever the input's length is. That cost had never been computed. Measured,
it is **40 960 B of bookkeeping from a 1 145-byte legal artifact** — 35.77x
the input — and `crates/antseal-core/src/anchor/ots/tests.rs`'s
`parser_is_iterative_at_max_depth` has been building exactly that input and
asserting it parses, green and silent, since A11 landed.

> **Raise precondition (D58 §10.3 rule 6 clause (c)).** A raise of a **count**
> limit under F4 is refused unless the summed structural cost of every
> count-bounded container live in one parse stays `<= MAX_OTS_BYTES` (D10 row
> 16) for `.ots`, and `<= MAX_TSA_TOKEN_BYTES` (row 17) for the RFC 3161 path.
> The argument for a raise past that line must be made **on memory**, in a
> decision record — not on *"it only costs a `Vec` entry"*, which is the
> sentence that made this defect possible and which D102 §5 corrects in D58
> §9.2.

**This is an operating condition on a raise, not a change to F4's text.** F4
still reads exactly as §1 states it and as D84 §4 states it; the rules
themselves are untouched, byte for byte, and the copy in §1 is therefore not
re-cut. What the precondition uses is F4's own closing instruction — *"record
every limit's value and every change in the registry A27 creates"* — which is
this table.

**Where the cost is enforced, and why not here.** The numbers in the column
are **derived in code**, never transcribed: clause (a) forbids a literal,
because a number typed by hand is a number that survives a raise.

| clause | where | what fails if it is broken |
| --- | --- | --- |
| (a) derived from the limits and `size_of` | `anchor/ots/limits.rs`, `anchor/caps.rs` | nothing — it is the source |
| (b) asserted at equality against a measured peak | `crates/antseal-core/tests/anchor_ots_alloc.rs`; `anchor::caps::tests` | `cargo test` |
| (c) `<= MAX_OTS_BYTES` / `<= MAX_TSA_TOKEN_BYTES` | a `const` assertion beside each constant | **`cargo build`**, on every lane and on `wasm32` |

Clause (c) is a `const` assertion deliberately: a raise that breaks it stops
the build for every contributor, with no lane to rerun and no budget to
adjust. Measured headroom on `MAX_OTS_DEPTH` (D102 §3.2): 4 096 green,
16 384 green and the last one, 32 768 red, 65 536 red at 2.51x.

**Two rows this table still owes.** The A5/D60 limits — `MAX_CHAIN_CERTS`,
`MAX_CHAIN_CERT_BYTES`, `MAX_SIGNED_ATTRS` — have **no rows here at all**,
although `anchor/caps.rs`'s module docs say they belong here and D60 §6 sets
them. That gap predates D102 and D102 does not close it; the DER path's
structural cost (**7 488 B**, and note that its certificate-bag reservation is
`8 x 512 = 4 096 B`, *exactly* the fuzz guard's fixed slack) is derived and
asserted in `anchor/caps.rs` in the meantime. **A5 owes the rows.**

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
