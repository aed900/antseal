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

| limit | owner | value | date set | measured against — an A25 fixture path, or a derivation from committed archive bytes | margin | lowered | structural cost (D102) |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `MAX_OTS_OPS` | A11 | 4_096 | 2026-08-02 | the 3 808-byte upgraded `.ots` A22 froze (**244** ops), re-measured by A48 2026-08-10. Derived, not stored: `testdata/vectors/v1/anchor/anchor.json` cases 4–6, `sha256 c2bf8b2c…d88e0c68` | 16.79x | never | **none** — bounds work, not a container |
| `MAX_OTS_DEPTH` | A11 | 1_024 | 2026-08-02 | the same derived artifact (depth **85**, D58 §9.3's definition), re-measured by A48 2026-08-10. The retired `LARGE_TEST` proof measured 67, which is where this cell's former 15.28x came from; depth is attachment depth *plus* fragment depth, so the artifact a verifier parses is deeper than any fragment of it | 12.05x | never | **40 960 B** (x86-64) and **24 576 B** (`wasm32`) = `next_pow2(1_024) x size_of::<Frame>()` at 40 B and 24 B respectively — the parser's `walk.rest`; **3.91 %** of `MAX_OTS_BYTES` on x86-64, and §5a's table carries both targets in full |
| `MAX_OTS_BRANCH_WIDTH` | A11 | 64 | 2026-08-02 | `testdata/anchors/A25-bootstrap/merged-A.ots` (width **3**; the derived upgraded artifact measures 3 as well — a splice adds depth, never width) | 21.33x | never | **none** — a per-node counter, no container |
| `MAX_OTS_ATTESTATIONS` | A11 | 256 | 2026-08-02 | the same derived artifact (**6** — three pending, three Bitcoin — now the binding count), re-measured by A48 2026-08-10; `merged-A.ots` measures 3 and the retired `LARGE_TEST` proof 4 | 42.67x | never | **12 288 B** (x86-64) and **8 192 B** (`wasm32`) = `next_pow2(256) x size_of::<OtsAttestation>()` at 48 B and 32 B respectively; **1.17 %** of `MAX_OTS_BYTES` on x86-64, and §5a's table carries both targets in full |
| `MAX_OTS_OPERAND_BYTES` | A11 | 16_384 | 2026-08-02 | `testdata/anchors/A25-bootstrap/upgraded/rust-opentimestamps-LARGE_TEST.ots` (**174** B coinbase-prefix operand) — **still binding, and deliberately so.** The derived upgraded artifact measures only 89 B here: its operands are 32-byte merkle siblings and a 44-byte calendar commitment, where this mainnet proof carries a real fat coinbase-transaction prefix. Re-pointing the cell would *raise* the recorded margin to 184.09x by dropping the fatter real sample (A48, 2026-08-10) | 94.16x | never | **none** — a length header; D58 §10.3 rule 4's clamp governs it |
| `MAX_OTS_VALUE_BYTES` | A11 | 32_768 | 2026-08-02 | `testdata/anchors/A25-bootstrap/upgraded/rust-opentimestamps-LARGE_TEST.ots` (**210** B running value) — still binding, for the row above's reason and measured in the same walk; the derived upgraded artifact measures 125 B, which would read 262.14x (A48, 2026-08-10) | 156.04x | never | **none** — rule 4; `exec::apply` allocates the running value after checking it (32 B on the A100 path) |
| `MAX_OTS_ATTESTATION_PAYLOAD_BYTES` | A11 | 8_192 | 2026-08-02 | `testdata/anchors/A25-bootstrap/merged-A.ots` (**46** B pending payload; the derived upgraded artifact measures 46 too, so the splice does not move this row); value taken from python-opentimestamps `MAX_PAYLOAD_SIZE` | 178.09x | never | **none** — a length header; rule 4 |
| `MAX_OTS_CALENDAR_RESPONSE_BYTES` | A42 | 65_536 | 2026-08-02 | `testdata/anchors/A25-bootstrap/upgraded/A-catallaxy.upgrade` (**1 105** B — the largest of the six real calendar *upgrade* replies, captured 2026-08-03T09:03Z, pinned per file as `antseal_anchor::ots::MEASURED_MAX_UPGRADE_RESPONSE_BYTES` by `the_measured_upgrade_response_sizes_are_the_f4_row`). **The upgrade reply is the binding one of the two reply classes this cap governs**, and D54 §6.1 ruled it so before either was measured: it recorded the submit figure as provisional and required that *"the F4 row must be completed with that figure"*. The other class is the *submit* reply, largest 220 B at `testdata/anchors/A25-bootstrap/A-catallaxy.timestamp` — 5.02x smaller, pinned by the same test, and no longer a margin this table states. Re-keyed from the submit reply to the upgrade reply by A115 under D110, 2026-08-10; `value`, `date set` and `lowered` are untouched, so §6 owes no entry | 59.31x (upgrade) | never | **none** — a receive-side byte cap, not a count limit |
| `MAX_DER_NESTING_DEPTH` | A5 | 63 | 2026-08-02 | `testdata/anchors/A25-bootstrap/D60-tsa-globalsign-resp.tsr` (measured depth **19**, the deepest of the nine live TSA captures — D60 §6 b1). **No antseal constant holds this number, and this is the only row in this table whose value is pinned behaviourally rather than to a constant.** It is `der 0.8.1`'s `MAX_DEPTH` (`reader/position.rs`, private to the crate and therefore unreadable from antseal), which is 64 exclusive — 63 nested constructions accepted, the 64th rejected as `ErrorKind::NestingDepth` — consumed rather than minted, because measuring depth ourselves needs the recursive walker D60 §2.4 measured aborting the process on hostile input. The F4 raise-only guard is therefore **upstream**: `crates/antseal-core/tests/der_pin_eval.rs` `der_nesting_depth_limit_is_63` builds 63 and 64 nested SEQUENCEs and fails if a `der` bump moves the limit in **either** direction, so a lowering is refused at the bump review instead of shipped. `anchor::caps::tests` binds this row to that test by name | 3.3x | never | **none** — a per-invocation recursion counter inside `der`'s reader, not a container antseal reserves |
| `MAX_CHAIN_CERTS` | A5 | 8 | 2026-08-02 | `testdata/anchors/A25-bootstrap/D60-tsa-globalsign-resp.tsr` (**4** certificates, the largest bag of the nine live captures; the deepest real validated path is 3 links, 4 closed through the DigiCert cross-certificate — D60 §6 b2) | 2.0x | never | **4 288 B** = `8 x (size_of::<Certificate>() + size_of::<Vec<u8>>())` (512 + 24 B, x86-64) — `tsa::chain_certificates`' two vectors; **0.41 %** of `MAX_TSA_TOKEN_BYTES`. It owns a further **1 024 B** = `8 x size_of::<Node>()` (128 B) of the path-node reservation §5a splits out, and that part is a **ceiling rather than a reservation**: `chain::PathBuilder::new` reserves `supplied.len() + 1`, so an honest 4-certificate token takes 5 nodes, unlike the `.ots` parser's `walk.rest`, which always reserves its bound. Marginal cost of one more unit: **664 B** |
| `MAX_CHAIN_CERT_BYTES` | A5 | 16_384 | 2026-08-02 | `testdata/anchors/A25-bootstrap/D60-tsa-swisssign-resp.tsr` (signer certificate **2 105 B**, the largest of the 27 certificates embedded across the nine captures — D60 §6 b3). Carries the A28-shaped derived constraint `MAX_CHAIN_CERT_BYTES <= MAX_CERT_BYTES`, a `const` assertion in `anchor::caps` rather than a comment | 7.8x | never | **none** — the size check runs on the output of `to_der()`, so the bytes are already allocated and already bounded by the input; that is rule 4's business, not rule 6's |
| `MAX_SIGNED_ATTRS` | A5 | 16 | 2026-08-02 | `testdata/anchors/A25-bootstrap/D60-tsa-digicert-resp.tsr` (**5**, also DFN, SwissSign and Certum — D60 §6 b4) | 3.2x | never | **none**, and that is a *measured* finding rather than an omission: the attribute set is already decoded inside `SignerInfo` by the time the count check rejects, so antseal reserves nothing from this limit. Recorded at `anchor/caps.rs`, where `the_der_structural_cost_is_the_one_measured_today` pins the sum at equality — so adding a container under this limit reddens a test on the day it is added |

**A note on the row above, because the next reader will assume one number
serves both.** `MAX_OTS_CALENDAR_RESPONSE_BYTES` bounds **one HTTP reply from
one calendar**. `MAX_OTS_BYTES` (§2 row 16, 1 MiB) bounds the **merged `.ots`
artifact** a bundle embeds — every calendar, every upgrade, accumulated. They
are different quantities, and passing the second where the first belongs would
let four calendars hand `antseal-anchor` 4 MiB per seal against a measured
worst case of **1 105 B** — the *upgrade* reply, the larger of the two reply
classes this cap governs and the one its margin is keyed to (D110). There is
no third class: a non-2xx calendar body, including A14's two 404 upgrade
discriminators, is capped by `HTTP_ERROR_BODY_CAP_BYTES` (4 KiB) on the error
path and not by this limit. This limit is also the only one of the rows here
that is a *network-stage* limit rather than an *artifact-parse* limit, which
is why it is not one of the eight §4 leaves it open. The strict inequality
between the two is a compile-time assertion in
`crates/antseal-anchor/src/ots/mod.rs` and `crates/antseal-anchor/src/http.rs`
— strict, because equality *is* the conflation.

**The bootstrap is over — what A48 re-measured on 2026-08-10, and what it did
not.** Five of the first seven rows were **bootstrapped, not measured**, against the
`LARGE_TEST` constant of `opentimestamps-0.2.0` — a genuine mainnet proof over
Bitcoin blocks 449397 and 449399 (≈ January 2017), committed with its
provenance at `testdata/anchors/A25-bootstrap/upgraded/PROVENANCE.md`. It stood
in because, on 2026-08-02, no upgraded `.ots` over this project's own digests
existed. Six do now, since **2026-08-03T09:03Z**, and the artifact a verifier
actually parses — the three-way splice A22 froze (D103 RULING 3b) — has been
measured by the parser that enforces the limits.

**Three rows moved to it. Two did not, and that is the finding.**

| row | was | is | why |
| --- | --- | --- | --- |
| `MAX_OTS_OPS` | 100 (crate) | **244** | the splice is the whole artifact; a fragment is not |
| `MAX_OTS_DEPTH` | 67 (crate) | **85** | attachment depth *plus* fragment depth |
| `MAX_OTS_ATTESTATIONS` | 4 (crate) | **6** | three calendars, three Bitcoin branches |
| `MAX_OTS_OPERAND_BYTES` | 174 (crate) | **174** (crate) | antseal's own measures **89** — smaller |
| `MAX_OTS_VALUE_BYTES` | 210 (crate) | **210** (crate) | antseal's own measures **125** — smaller |

The last two are why *"the four `measured against` cells name an A25 fixture and
no crate"* could not simply be executed. This project's own upgraded artifact
carries 32-byte merkle siblings and a 44-byte calendar commitment; the borrowed
proof carries a real fat coinbase-transaction prefix. Re-pointing those two
cells would have **raised** the recorded margins — 94.16x → 184.09x and
156.04x → 262.14x — by dropping the fatter real sample. A margin is a claim
about the worst real artifact known, not about the most recently captured one,
so the crate fixture is **kept and demoted to exactly what A48's own Accept
row 3 offers**: *"a second, independent upgraded shape"*, still binding for two
limits and cited as such. It is no longer a stand-in for anything.

**A48's `Do` said *"the values do not change (F4 forbids lowering, every margin
is ≥ 15x)"*. The first clause is true and the parenthesis is false.** No
`value` cell moved, so no §6 entry is owed. But `MAX_OTS_DEPTH`'s margin is
**12.05x**, below 15x — and it was already below 15x before this re-measurement,
silently, because the cell was measuring a January-2017 proof from a rejected
crate rather than anything antseal produces. D104 §4 records A109 reasoning from
that 15.28x. The margin band is stated here rather than left to be rediscovered:
over these eight `.ots` and receive-side rows, **12.05x to 178.09x, and the
floor is `MAX_OTS_DEPTH`** — the ceiling moved down from 297.89x on 2026-08-10,
when D110 re-keyed A42's row from the submit reply to the binding upgrade
reply. Across the whole table the floor is lower still: A110's four DER rows,
added 2026-08-09, put `MAX_CHAIN_CERTS` at **2.0x**. D104's KEEP-1 024
ruling survives it unchanged and was argued at depth 85 explicitly — the
admissible floor is `8 x 85 = 680`, and 1 024 is the cost-minimal admissible
cap — but any future reader quoting a *"≥ 15x"* discipline over this table is
quoting something that has never been true of it.

*Attribution, corrected here 2026-08-10 (**A106**).* Two sentences in this
section read *"A25 owes that re-measurement"* and *"**A25 must re-measure
them**"*. The task is **A48**, which was written for exactly this and lists A25
only as a dependency; A25's obligation was the *capture*, discharged
2026-08-03. The correction was made in
`testdata/anchors/A25-bootstrap/upgraded/PROVENANCE.md` on 2026-08-07 and **in
that file only**, because this document was another lane's — so a reader who
came here first was misdirected for three days. That asymmetry is the reason
A106 exists as its own row: a correction landed in one of two places is a
correction that has not happened.

**Correction to D58 §9.5, recorded rather than silently applied.** D58's
rows read *depth 69* for the upgraded proof and *depth 13* for the merged
pending file. Under D58 §9.3's own normative definition — *"edges from the
root step, root at 0 … a chain of `N` ops terminated by an attestation has
maximum depth `N`"*, which §9.3 says *"must be the one the implementation
uses"* — the measured depths are **67** and **12**: an attestation is a leaf
hanging off a node, not a node of its own. Both values were confirmed by an
independently written length-respecting scanner as well as by the parser.
Both figures are about *fragments*; neither is this table's `MAX_OTS_DEPTH`
measurement any more, which is 85 against the spliced artifact. The 67-vs-69
correction moved the margin then computed from 14.84x to 15.28x and F4 forbids
lowering, so nothing moved; the row now records what was measured against the
artifact a verifier parses.

### 5a. The `structural cost` column, and the precondition it attaches to F4

**Added 2026-08-07 by [D102](../decisions/D102-parser-structural-allocation-cost.md)
(task A100), which amends D58 §10.3 with a sixth rule. This banner covers §5a
and nothing after it.** The DER paragraphs below are **A110's, 2026-08-09**,
and say so where they stand; the **Update rule** and the `Rows A28 must add on
day one` paragraph are **A27's**, from `1620543` (2026-07-28), the commit that
created this document and ten days older than this heading. D102 inserted §5a
*above* them, so from 2026-08-07 to 2026-08-10 two A27 paragraphs were filed
under a 2026-08-07 banner; **§5b now ends this section before them** (A114).
That was not a quibble about a date: D104 §1.2 records a read-only recon lane
reading the rendered document, concluding that A27's registry-*keeping*
procedure had been written ten days later by D102's lane, and building its
central finding on it.

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
adjust. Measured headroom on `MAX_OTS_DEPTH` (D102 §3.2), **on x86-64**:
4 096 green, 16 384 green and the last one, 32 768 red, 65 536 red at 2.51x.
That row is not universal, and read as though it were until 2026-08-10: on
`wasm32` the largest admissible power of two is **32 768**, because
`P x 24 + 8 192 <= MAX_OTS_BYTES` admits it (D104 §1.3). The conclusion is
safe either way — the `const` assert fires on the strictest target and CI
builds both — but the statement was unqualified.

**Every number in this column was x86-64's until A121 put both targets in the
two numeric cells, and the other target is cheaper — which is the opposite of
how the one lowering argument this project has seen used it.**
`OTS_FRAME_BYTES` and `OTS_ATTESTATION_BYTES` are `size_of`, so
this whole column is a function of pointer width; `Frame` is
`Option<Vec<u8>> + 2 x u32 + bool`, which is 24+8+1 → 40 on 64-bit and
12+8+1 → 24 on 32-bit.

| target | `size_of::<Frame>()` | `size_of::<OtsAttestation>()` | `walk.rest` | attestations | total |
| --- | --- | --- | --- | --- | --- |
| x86-64 | 40 B | 48 B | **40 960 B** | **12 288 B** | **53 248 B** — 5.08 % of `MAX_OTS_BYTES` |
| `wasm32-unknown-unknown` | 24 B | 32 B | **24 576 B** | **8 192 B** | **32 768 B** — 3.13 % |

**So the browser tab — the venue with the tightest ceiling this parser runs
under — is the *cheapest* place it runs, not the constrained one.**
`crates/antseal-core/src/anchor/ots/limits.rs` has said so at
`OTS_ATTESTATION_BYTES` since D102 landed; this document did not, and that
omission has a measured victim. A109's case for lowering `MAX_OTS_DEPTH` was
*"40 960 B of work-stack bookkeeping in a parser that runs in a browser tab"*
— the x86-64 figure applied to the one venue where the cost is 40 % lower.
D104 §1.3 corrected the number and D104 §6 ruled the asymmetry into this
document, which is why it is stated here rather than only in code: the
inversion must not be re-derivable from the registry alone.

**Both rows are asserted, each on its own target** (A121, discharging D104 §6).
`the_structural_cost_column_states_the_derivation_and_its_value` builds its
needles from `OTS_STRUCTURAL_WORK_STACK_BYTES`,
`OTS_STRUCTURAL_ATTESTATION_BYTES` and `OTS_STRUCTURAL_ALLOC_BYTES`, which are
`size_of`-derived and are therefore already the running target's own figures —
so a native `cargo test` reads the x86-64 row and `scripts/wasm-tests.sh`,
which runs `cargo test -p antseal-core --lib` on `wasm32-unknown-unknown`,
reads the `wasm32` one. Neither target asserts the other's numbers, which is
the split `anchor/caps.rs` adopted at `873a1cf` after the same omission on
`size_of::<Certificate>()` reddened `wasm32-core-tests`. **The six byte
figures in the table above are consequently no longer the hand-typed numbers
clause (a) exists to forbid**: moving `Frame` or `OtsAttestation` on either
target reddens that target's lane until this table is re-derived. §5's two
numeric `structural cost` cells carry both targets' figures for the same
reason, which is what D104 §6 ruled; this table is the derivation they point
at.

**The DER half's four rows, added 2026-08-09 by A110.** The A5/D60 limits —
`MAX_DER_NESTING_DEPTH`, `MAX_CHAIN_CERTS`, `MAX_CHAIN_CERT_BYTES` and
`MAX_SIGNED_ATTRS` — had **no rows here at all** until then, although
`anchor/caps.rs`'s module docs said they belonged here and D60 §6 set all four
with their measurements. The gap predated D102 and D102 did not close it: the
`structural cost` column D102 added went to all eight rows this table then
had, every one of them an A11 or A42 `.ots` row, so there were no DER rows to
skip. **The paragraph that described the gap got the count wrong in both
directions** — it opened *"two rows this table still owes"* and then named
three, and the true number was **four**: `anchor/caps.rs`'s own module docs
name the fourth (*"and for the depth limit that is not declared here"*), and
§4's table of what A5 still chooses lists four A5 leaves, not three. The
fourth is the one A5 does not declare, and its row says so.

**Still owed: A28's two**, below the Update rule in §5b.

**Where the DER path's 7 488 B goes, and why no one row carries it.**
`anchor::caps::TSA_STRUCTURAL_ALLOC_BYTES` is **7 488 B** on x86-64 —
**0.71 %** of `MAX_TSA_TOKEN_BYTES` — and it is two reservations under two
different bounds, only one of which is an F4 limit:

| container | bounded by | rule 6 cost |
| --- | --- | --- |
| `tsa::chain_certificates`' `certs` and `ders` | `MAX_CHAIN_CERTS` | **4 288 B** = `8 x (size_of::<Certificate>() + size_of::<Vec<u8>>())` — **0.41 %** of the token cap |
| `chain::PathBuilder::new`'s `nodes` | `MAX_PATH_NODES`, itself `MAX_CHAIN_CERTS + MAX_INTERMEDIATE_COUNT + 1` | **3 200 B** = `25 x size_of::<Node>()` — **0.31 %** of the token cap |

Of that **3 200 B**, `MAX_CHAIN_CERTS` owns **1 024 B**, the signer owns
128 B, and **2 048 B** belongs to `MAX_INTERMEDIATE_COUNT` — a **frozen** D10
row (§2, row 8), not an F4 limit at all. So charging the whole path-node
reservation to `MAX_CHAIN_CERTS`, which is the obvious reading of
`MAX_PATH_NODES`, attributes **2 176 B** to a raisable limit that an
unraisable one owns. The number a raise argument actually needs is the
**marginal cost of one more unit of `MAX_CHAIN_CERTS`: 664 B**
(`size_of::<Certificate>()` + `size_of::<Vec<u8>>()` + `size_of::<Node>()`).

Two qualifications, both of which the `.ots` rows do not need. First, the
path-node figure is a **ceiling, not a reservation**: `PathBuilder::new`
reserves `supplied.len() + 1`, so it is reached only by a token and bundle
that between them supply the full 24 candidates, where `walk.rest` reserves
its bound on any input deep enough. Second, the certificate-bag figure is a
**worst case over real certificates**: `chain_certificates` reserves on the
count of plain `Certificate` entries, so a bag of `[3] other` entries
reserves nothing (A111 — before that fix it reserved on every bag entry, and
eight ~10-byte `[3] other` entries reserved the full **4 288 B**).

**The tie, kept because it is worth knowing.** The certificate-bag
reservation alone, `8 x size_of::<Certificate>()`, is **4 096 B** on x86-64 —
*exactly* the fuzz guard's fixed slack. That is a 64-bit fact: on `wasm32` the
same product is **3 008 B** and clears the slack by nearly a kilobyte. Every
number in this subsection is derived in `anchor/caps.rs` and asserted against
this document, never transcribed.

### 5b. The Update rule

**A27's, from `1620543` (2026-07-28) — the commit that created this document,
and ten days older than §5a.** It is under its own heading because until
2026-08-10 it was not: D102's §5a banner was inserted above it and filed it,
with the `Rows A28 must add on day one` paragraph, under *"Added 2026-08-07 by
D102"*. Read it as what A27 wrote — a registry-**keeping** procedure, which
prices a change and says how to record it. It neither permits nor forbids a
lowering; that is F4 sentence 1's question, and D104 RULING 1 answers it after
A109 read this rule the other way from under the D102 banner. The bullets
below have since been revised in place (D107 §R2/R3, 2026-08-09; A113,
2026-08-10) and say so; the rule and its two paragraphs are A27's.

**Update rule.** One row per artifact-internal limit and per receive-side
cap, added when the limit is first set, never deleted.

- **`value`** holds **exactly one bare value** — the current one, rendered
  with `_` group separators. Never a history, never a date, never a
  parenthesis. `anchor::ots::limits`' cross-check reads this cell as part of
  a row prefix that ends at the next cell boundary, so anything else in it
  turns a green test red for a reason that is not the reason.
- **`measured against`** is prose — it names a fixture path *or* a derivation,
  and explains a choice where one was made — with **exactly one constraint**:
  the **first bolded number in the cell is the measured quantity the `margin`
  divides by**. Added 2026-08-10 by **A113**, because until then `margin` was
  the only numeric column in this table no test reached, and a number that
  reads like the checked ones and is checked by nothing is worse than an
  absent one — it is quoted with their authority, which is exactly how A109
  came to reason from a 15.28x figure derived against a third-party crate's
  test constant (D104 §4). Bold anything else you like *after* it. The cell no
  longer has to be a path: the artifact the `.ots` rows now measure is
  **derived and deliberately not stored as a file** (D103 RULING 3a), which is
  why this column's header was widened in the same change.
- **`margin`** is `value / measured`, rendered `N.MMx` and **recomputed, never
  transcribed**, by
  `anchor::ots::limits::tests::the_margin_column_is_the_value_over_the_measurement`
  — over *every* row, including A42's and D60's four A5 rows, because the
  arithmetic needs no constant. It is checked **at the precision the cell
  itself prints**: the `.ots` rows use two places and the DER rows one, and
  both are correct. Prose may follow the `x`. A margin that disagrees with its
  own row's two operands is a red test naming the correct value.
- **`lowered`** reads `never`, or the date of the lowering as
  `` `YYYY-MM-DD` `` and nothing more — no release and no reason, because
  those are §6's. Changing it away from `never` is a **format-version event**
  requiring the full freeze procedure (Q27, mirroring Q14).
- **A commit may not change a limit's recorded value without adding a §6
  entry naming that limit.** *Recorded value* means the `value` cell or the
  `lowered` cell, and nothing else. **Adding a row owes no entry** — the
  row's own `date set` cell is the record. **Correcting `measured against`,
  `margin` or `structural cost` owes none either**: those are things learned
  *about an unchanged limit*. §6 records what a limit **is**, never what we
  have learned about it.

**Ruled by [D107](../decisions/D107-f4-registry-limit-change-log.md) (task
Q126), which replaces the previous rule in two places, both defects.** It said
`lowered` was *"the only cell that may change"* — falsified by its own next
clause, by D102's eighth column, and by D104 §4's instruction to A48 to
rewrite two cells of the `MAX_OTS_DEPTH` row. And it said *"a raise is
recorded by appending the new value and its date to the `initial value`
cell"*, which **breaks `ots_limits_match_the_f4_registry` the first time it is
used**: that test's needle requires the value cell to hold one bare value and
a closing cell boundary, so a cell reading `4_096 (2026-08-02), 8_192
(2026-09-01)` matches no needle at all — for the new constant *or* the old —
and the failure blames a drift that never happened. Invisible only because no
raise has ever occurred. Under the rule above a raise rewrites the `value`
cell in place and its history and reason go to §6, where a reason can be a
sentence; `ots_limits_match_the_f4_registry` then becomes a **second** guard
on the same rule, since a lane that reverts to appending reddens the
row-prefix pin immediately.

Rows A28 must add on day one: the TSA receive-side response cap
(`<= MAX_TSA_TOKEN_BYTES`) and the merged-`.ots` cap (`<= MAX_OTS_BYTES`).

## 6. Limit-change log

This log records **changes to a limit's recorded value in §5**, and nothing
else. It is not a history of this document: that is
`git log -- docs/format/anchor-artifact-limits.md`, which is where D104 §1.2
read it. An empty log below the creation entry means no limit's value has
changed since the table was set — which is a fact, not an omission.

**Retitled 2026-08-09 by D107 §R3, and the retitle is load-bearing.** A
section called *Changelog* holding one entry reading *"document created"*
tells a reader this document has not changed since 2026-07-28. It has changed
eight times, one of those adding a whole section and a whole column — and
D104 §1.2 records a recon lane injured by exactly that gap, concluding from
the empty log that A27's Update rule had been written ten days later by
another lane. The editorial history has a keeper and it is named above.

One line per change, newest last, in this grammar. The checker
(`anchor::ots::limits::tests::the_limit_change_log_agrees_with_the_registry_rows`)
reads the **date**, the **backticked limit name**, the word **raised** or
**lowered** and the value raised *from*; everything after the second em dash
is free prose it does not parse, deliberately — pinning prose pins editorial
wording rather than facts.

```
- **YYYY-MM-DD** — `LIMIT_NAME` raised|lowered `N` → `M` (owner task or
  decision, release or `pre-release`) — why, in one clause.
```

The log is checked **in both directions**: a row whose recorded value has
moved without an entry is red, and an entry claiming a move the table does
not corroborate is red too. The second arm is D104 §5's refusal of fabricated
provenance made mechanical — a lane cannot write *"we lowered X"* here unless
§5 says so.

**Zero point.** The entry below names no limit, which is what makes the
emptiness beneath it a true statement rather than an absence.

- **2026-07-28 (M0 wave 6, A27/D84)** — table created; no limit's recorded
  value has changed since. F1–F4 and the §2
  freeze-boundary rows carried verbatim from D84; the §3 constant-reuse
  ruling recorded and `tasks/A.md`'s A5 and A11 `Do` text corrected to match
  it (both previously promised caps that §3 rules already frozen, so an
  implementer reading `tasks/A.md` alone would have minted duplicates). One
  cross-reference in F4 flagged as wrong and carried unaltered — see the
  editorial note in §1. F4 registry created empty.
