# D98 — What state vocabulary does `antseal status` render, and how are the vault's anchor records projected into it?

- **Status**: Resolved 2026-08-06
- **Owner**: U23 / U25 (executing) · A15 / A18 (the two machines) · U47, U48 and
  **D97** are hard dependencies
- **Companion**: **D97** was minted by this same lane, in parallel, and rules the
  blocker §"the fifth gap" reaches from the other side. The two were written
  independently and agree on every measured fact; see that section.
- **Minted**: mid-round, by the U23–U25 lane, from a question the register had
  leaned on without measuring
- **Supersedes**: nothing. **Amends**: `tasks/U.md`'s U23 Notes (state names),
  U23's Accept row (the `attested` fixture is unbuildable today), U47's scope,
  `OtsAnchorState::AttestedHeaderMissing`'s doc comment
  (`antseal-anchor/src/ots/engine.rs:510-514`), and the three stale
  *"an imported complete work carries no journal entries at all"* claims
  (`listing.rs:13-18`, `journal.rs:973-975`, `export.rs:515-516`).

## The problem, in one sentence

`antseal status` must name each anchor's state, two different state machines
claim that job with different state spaces, and the register's lean —
*run A18's bundle evaluator over the vault* — was believed to require
**fabricating a sealer verdict the vault never stored**.

## What was measured

Everything below was run or read, not inherited. The brief's four "measured
gaps" were re-checked; **two of them are false as stated**, and a fifth was
found that blocks U23 outright.

### Gap 1 — "one `AnchorStatus` must be invented". **False.**

`AnchorArtifacts::from_parts` (`anchor/model.rs:338`) does take
`&[OtsAnchor]`/`&[TsaAnchor]`, and both constructors do demand a sealer-recorded
`AnchorStatus` (`bundle/schema.rs:523`, `:636`). But **that is not the only door
into A18.** Both per-artifact evaluators are `pub`:

```rust
pub fn evaluate_ots_artifact(view: &OtsArtifactView<'_>, anchor_digest: &[u8; 32],
                             blocks: &BlockEvidence) -> AnchorOutcome         // verdicts.rs:675
pub fn evaluate_tsa_artifact(view: &TsaArtifactView<'_>, anchor_digest: &[u8; 32],
                             roots: &TsaRootStore, verify_at_unix: u64) -> AnchorOutcome  // :1053
```

and both views have `pub const fn from_parts` constructors that **take no
`AnchorStatus` at all** (`model.rs:139`, `:193`), whose doc comments name
**A18 itself** as the intended consumer (*"for A11/A12/A18 fixtures that need an
artifact without assembling a whole `.sealproof`"*). `TsaArtifactView`'s type doc
says it outright: *"Same discipline as `OtsArtifactView`: a borrowed view, and no
`status`."*

**Run, from an out-of-crate integration test** (`crates/antseal-core/tests/`,
since deleted), over the five real captures in
`testdata/anchors/A25-bootstrap/`, with no `AnchorStatus`, no `TsaAnchor` and no
`AnchorArtifacts` anywhere in the caller:

```
freetsa: Proven   digicert: Proven   dfn: Proven   sectigo: Proven
swisssign: InternallyConsistentOnly
```

So the trap the brief names — *rendering a status the sealer never claimed,
inside the tool that distinguishes claims from verification* — is not a cost of
using A18. **It is a cost of using the wrong constructor**, and the right one is
already public and already documented for this use.

What is **genuinely** unreachable: `AnchorVerdicts` has four private fields and
no public constructor (`verdicts.rs:437-442`), and `AnchorOutcome::new` is
private (`:391`). So a caller outside `antseal-core` can obtain
`Vec<AnchorOutcome>` but never an `AnchorVerdicts` — and therefore never
`project_anchor_results()`, `aggregate()`, `absent_verdict()` or
`distinct_verified_identities_of()`. That is a missing *constructor*, not a
missing datum, and the ruling below routes around it rather than adding one.

### Gap 2 — "`vec![]` intermediates is a weaker T3 input than a bundle carries". **False, twice.**

**(a) It is not weaker for any TSA in the tree.** `validate_token_chain`
(`chain.rs:469-485`) pools `token.chain_material()` **++** `bundle_intermediates`,
so a token that carries its own chain needs nothing from the bundle. Three
committed tests already prove `&[]` reaches `proven` on real material:
`real_digicert_token_reaches_proven_with_the_cross_cert_present` (`chain.rs:1227`),
`real_sectigo_token_reaches_proven_with_the_cross_cert_present` (`:1274`), and
`token_carrying_its_own_self_signed_root_still_reaches_proven` (`:1301`, FreeTSA
and DFN). The probe above reproduced all four independently.

The one non-`proven` result is **not** an intermediates fact: SwissSign's root is
deliberately quarantined out of store v1, and `chain.rs:1485-1486` asserts
exactly the measured value — `internally-consistent-only` against the production
store, `proven` against an injected one — with `&[]` in both calls.

**(b) There is no bundle to be weaker than.** `TsaAnchor::new` and
`OtsAnchor::new` have **zero call sites outside `antseal-core`**; every hit is a
test, a fixture or `verify/pipeline.rs`'s own stub builder. `grep intermediates
crates/antseal-cli/src` → zero, as the brief says — but the reason is that the
CLI has never built a bundle at all (`reveal` is M3, and `run.rs:35` returns
`NotImplemented`). So `status` passing `&[]` is not a divergence from `verify`;
it is the **same** input `verify` will get.

Error direction, recorded so nobody re-derives it: adding certificates can only
enlarge the candidate-path set, so omitting them is monotone — it can lower or
preserve a grade, never raise one. Missing intermediates can only ever
*under*-claim.

### Gap 3 — the journal-on-import contradiction. **Resolved: the code says entries 0–2 survive.**

`vault/export.rs:781-786` is the write path, and it skips exactly one thing:

```rust
if complete && entry >= UNIT_ENTRY_BASE { continue; }
```

`UNIT_ENTRY_BASE` is `3` (`journal.rs:110`). So for a **complete** work the
export carries `STATE_ENTRY` (0), `PLAN_ENTRY` (1) and `MANIFEST_BLOB_ENTRY` (2),
and the import-side validator refuses only `>= UNIT_ENTRY_BASE` (`:551-556`).
`manifest_bytes` lives on the **plan** record, entry 1 (`journal.rs:439`, decoded
at `:1053`).

**Therefore the `anchor_digest` recovery path survives `vault import`**:
`journal.plan(seal_id)?.manifest_bytes` → `antseal_core::manifest::anchor_digest`,
which is precisely the shape `pipeline/resume.rs:178-182` already uses in
production.

`export.rs:767-776` states the amendment in its own words — *"D43 (as amended
2026-08-02 by S29) … Entries 0–2 … are always exported: without entry 2's
`{address, nonce}` an encrypted manifest is unlocatable"*. So:

| claim | verdict |
| --- | --- |
| `listing.rs:13-18` — *"a `vault import`ed **complete** work carries no journal entries at all"* | **stale**, falsified by `export.rs:784` |
| `journal.rs:973-975` — same sentence on `recorded_state` | **stale** |
| `export.rs:515-516` — *"the D43 exclusion holds (a complete work carries no journal bytes)"* | **stale — and it is in the same file that implements the opposite**, a third copy the brief did not name |

A consequence worth flagging beyond this decision: `list`'s stated reason for
reading the coarse `WorkState` mirror (*"after a restore-from-backup the coarse
mirror is the only tag left"*) is now false, because entry 0 survives too. The
fallback is not wrong, but its documented justification is.

### Gap 4 — `verify_at_unix` has no CLI source. **True**, and the brief pointed at the wrong precedent.

`grep verify_at crates/antseal-cli/src` → zero. The CLI's only clock is a private
`fn now_unix_secs()` (`commands.rs:424`); there is no `Clock` trait, no
`SOURCE_DATE_EPOCH`, and none of the eleven `ANTSEAL_*` env vars is a clock.

`AnchorStageConfig.fetch_date` (`seal_run.rs:544-548`) is a real precedent for the
**mechanism** — a struct field, no CLI flag, `None` in production
(`from_config`, `:565`), a literal in tests — but its own doc rules out
transferring the **rationale**:

> Pin the `fetch_date` recorded on every capture instead of reading the host
> clock. **Safe to expose because `fetch_date` gates no outcome anywhere (A32)**
> — which is also why a deterministic test needs it.

`verify_at_unix` gates outcomes. `chain.rs:1743`
`one_fixture_two_verify_times_flips_proven_and_since_expired` is the committed
proof: one DigiCert fixture, two times, `Proven` → `ValidAtStampingCertSinceExpired`.
And it is **one-sided** (`:1766`, D53 §5(b)): an early `verify_at` can never
produce a failure, only an over-claim. Measured in the probe:
**`verify_at = 0` renders the real DigiCert token `Proven`** regardless of cert
expiry.

The correct precedent is already committed and is the *other* one:
`VerifyOptions::with_verify_at_unix` (`verify/pipeline.rs:268-306`), whose doc at
`:230-238` has already ruled this exact question — *"it separates `proven` from
`valid-at-stamping-cert-since-expired` and can never produce a failure, so a
caller with no clock loses one distinction and no safety. `None` evaluates as
`0`."*

### The fifth gap, which nobody named: **`attested` is unreachable from the vault, and U23's Accept demands it.**

The vault's anchor record is `AnchorArtifact` (`pipeline/anchors.rs:105-118`),
whose strict-v1 CBOR schema is keys **0–3** — kind, endpoint, fetch_date, bytes —
and whose decoder refuses anything else:

```rust
_ => return Err(corrupt("unknown anchor-artifact key (strict v1 schema)")),   // anchors.rs:164
```

**There is no slot for the D79 upgrade group.** `grep OtsUpgrade
crates/antseal-cli/` → zero hits. Yet the upgrade engine hands one back:
`AppliedUpgrade { artifact, upgrade: Option<OtsUpgrade> }` with the doc
*"Recorded **together** with the artifact or not at all"* (`engine.rs:157-159`).
The CLI has nowhere to put it.

The consequence lands identically on **both** candidate machines:

- **A18.** `upgrade = None` ⇒ `committed = false`; `ots_refutation` returns at its
  first line (`let upgrade = view.upgrade()?;`, `verdicts.rs:943`), so O4 and
  O6/O7/O8 are all unreachable. An upgraded `.ots` with no pending branch falls
  through to **O9 — `internally-consistent-only`**. The function's own doc says
  this in those words: *"the converse shape — a Bitcoin-attested branch with **no**
  upgrade group — falls through to O9 rather than being refuted."*
- **A15.** `anchor_status`'s `(false, true)` arm requires `anchor.upgrade.is_some()`;
  with `None` every attested artifact takes `(false, false) → AttestedHeaderMissing`
  (`engine.rs:628-632`). That state's doc calls itself *"unreachable from this
  engine"* — **the vault schema makes it universal.**

So `attested` cannot be produced from the vault by any route, while U23's Accept
requires an `attested` fixture *and* a `--upgrade` transition *"pending →
attested … (re-run shows the new state)"*. **U23 is blocked on a vault record
schema change that the register does not record as a dependency.**

**Concurrently resolved by D97, and the convergence is itself evidence.** A
second planner in this same lane reached the identical blocker from the *write*
side while this doc reached it from the *render* side, and
`D97-ots-upgrade-group-vault-home.md` rules it: the group becomes **keys 4/5/6**
of the anchor-artifact record in the existing `ots-pending` slot, all-or-nothing,
with `SEAL_JOURNAL_VERSION` 1 → 2. Nothing here is therefore minted for it — D98
consumes D97 and records it as U23's missing dependency.

The two documents agree on every measured fact and D97 adds three this one did
not reach, all of which sharpen the case below:

- With `upgrade == None`, `agreed` is `None` *whatever online evidence the
  verifier holds* (`verdicts.rs:735`), so **`--online` can neither promote nor
  refute** the artifact. The loss is not "offline `status` degrades"; it is
  total.
- An upgraded artifact with no group is **strictly worse than the pending one it
  replaced** — `pending` (O5) before, `internally-consistent-only` (O9) after —
  and `OtsUpgrade` is not re-derivable offline, so it is unrescuable.
- On the A15 side the failure is **silence, not a wrong state**: the upgrade
  empties `pending_uris`, so `has_pending` goes false and the work becomes
  `NagState::AttestedOnly` — *"`--upgrade` cannot help; `--online` verification
  can"* — **both halves of which are false for this work**, and `list` stops
  nagging about it.

### Smaller measured facts the ruling rests on

- `status` is already a frozen clap subcommand with `--upgrade` wired
  (`cli.rs:136-145`); dispatch returns `NotImplemented { "status", M2 }`
  (`run.rs:32`). It is the only `--upgrade` flag in the workspace.
- `PendingWork` has **no production constructor anywhere** — eleven hits, all in
  `engine/tests.rs`. `StoredTsaAnchor::{verified, token_present}` have no
  persisted source and would be hardcoded from slot existence, which
  `pipeline/anchors.rs:24-27` argues is sound (*"Only verified captures are
  stored"*). `StoredOtsAnchor.upgrade` would be `None` always (above).
- `AnchorVerdict::source()` returns `Option<&AnchorSource>` **with the
  `Verified`/`Claimed` discriminant intact** (`model.rs:912`). The collapse R74
  complains about happens in `to_anchor_result` → `identity()`, at the **report**
  boundary. `status` does not cross it.
- `is_verified` re-measured: **3 repo-wide hits** (`model.rs:636` definition,
  `model.rs:1255`, `verdicts/tests.rs:1235`) — exactly as R74 records.
- `ReceiptEvidence::is_headline_eligible()` is `const fn -> false` with *"there
  is no code path that could make it return `true`"* (`verdicts.rs:365-372`);
  `class()` is a one-variant `const fn`; `AnchorKind` has no receipt variant.
- `OnlineEvidence::new()` and `BlockEvidence::new()` are free, no-argument,
  no-network offline constructors (`model.rs:565`, `:490`).
- `TsaRootStore::pinned()` is reachable from the CLI and already used
  (`seal_run.rs:562`). `from_static` is `test-util`-gated and absent from shipped
  builds.
- A15's `Unreadable` and A18's O1 `invalid` are the **same call on the same
  bytes** — `parse_ots(&anchor.artifact, anchor_digest)` at `engine.rs:609` and
  `verdicts.rs:694`. They cannot disagree.
- **D65 is not in force.** No `docs/decisions/D65-*.md` exists; the register row
  is unchecked under `### Due M3` (`TODO.md:687`); the question's own text scopes
  it *"from M3"* (`tasks/R.md:676`); and **U50 exists precisely to "decide whether
  it falls under D65's stability commitment"**. The in-force machine contract is
  `ENVELOPE_VERSION` (`machine.rs:64`), about the envelope wrapper, not this field.
- Snapshot infra is hand-rolled `ANTSEAL_BLESS=1` + committed files under
  `crates/antseal-cli/tests/snapshots/`, rendering library structs in-process.
  Pinned-time literals in use: `1_800_000_000`, `1_798_761_600`.

## The options, and what kills each

**(a) The register's lean — A18 via `AnchorArtifacts`, fabricating `AnchorStatus`,
`vec![]` intermediates.** Killed by Gap 1: the fabrication is **unnecessary**, so
a design that performs it is strictly worse than one that does not, on the exact
axis the product is about. It also needs a public `AnchorVerdicts` constructor
that would let a caller desynchronise `ots_present`/`tsa_present` from `outcomes`
— a foot-gun on the two fields R70 just finished making precise.

**(b) A15's `work_status` is the honest answer; A18's vocabulary is reserved for
`verify`.** Killed by what A15 does **not** compute. `WorkAnchorStatus.tsa` is
`Vec<StoredTsaAnchor>` — three fields, none of them a state. A15 has **no TSA
verdict at all**. Routing `status` through it renders a blank where the *only
offline-headline-eligible evidence* sits — the TSA tokens the minimum-anchor
policy exists to guarantee (MVP-SPEC.md line 137). That is not conservatism; it
is silence about the strongest thing in the vault. Its one TSA bit, `verified`,
has no persisted source and would be hardcoded `true`, which is a *worse*
fabrication than the one option (a) was rejected for.

And A15's per-work answer is not merely thin, it is **wrong in the one state
that matters most**: D97 §1.2 measures that a completed-but-groupless upgrade
empties `pending_uris`, so `work_status` returns `NagState::AttestedOnly` and
`nags()` goes false — the work whose evidence was just destroyed is the work
`list` stops mentioning. A machine that goes quiet exactly when the news is worst
is not a candidate for the state column.

**(c) A third thing — a named vault-side projection mapping A15's states into
A18's words.** Killed on its own merits: it is the **only** design that guarantees
`status` and `verify` disagree. It computes a state by one rule and prints it
under a name defined by another, so every future change to D53/D56's ordered rules
silently desynchronises the two. `AttestedHeaderMissing → internally-consistent-only`
is the mapping it would have to hard-code, and that equivalence is true *today*
only because O9 happens to catch the shape — it is a consequence of the rule set,
not a definition, and a projection table would freeze it as if it were one.

**(d) Two machines, two questions, one vocabulary — the ruling.**

## Ruling

**`status` computes A18's states directly, per artifact, through the public
per-artifact evaluators — no `AnchorStatus`, no `AnchorArtifacts`, no
`AnchorVerdicts`, nothing fabricated. A15's `work_status` keeps the per-work nag
and nothing else. Neither is projected into the other, and `OtsAnchorState` is
not user-visible vocabulary.**

The two machines are not competing answers to one question:

- **A18 answers "what is this artifact's state?"** — per artifact, in the seven
  frozen names. `status` renders this.
- **A15 answers "should I nag about this work?"** — per work, four `NagState`s.
  `list` renders this (U25).
- A15's `OtsAnchorState` is a *third* thing — an artifact-shape report — that
  overlaps A18's domain without being a verdict. `status` uses A15's
  `pending_uris` and `heights` as **detail beside** the state, never as the state.

`status` and `verify` agree by construction, because they call the same functions
on the same bytes with the same `anchor_digest` and the same
`TsaRootStore::pinned()`. They can differ in exactly **two** documented ways, and
both are the taxonomy working rather than a defect:

1. **Time.** `status` evaluates at status-time, `verify` at verify-time. That
   difference *is* the `proven` / `valid-at-stamping-cert-since-expired`
   distinction (`chain.rs:1743`). A work can be `proven` today and
   `valid-at-stamping-cert-since-expired` in 2060; both are true statements about
   the same token.
2. **Online evidence.** `status` is offline (`OnlineEvidence::new()`), so an
   upgraded OTS renders `attested` and never `proven`. `verify --online` can
   promote it. MVP-SPEC.md line 108 is the rule, not an artefact of this design.

Everything else — intermediates included — is byte-identical input.

## The exact state vocabulary `status` emits

The seven frozen `AnchorState` names (`verify/report.rs:258-277`), their wire
spellings unchanged (`wire_name`, `:306`). Reachability from the vault, derived
from the rules and confirmed by the probe:

| state | TSA | OTS | why |
| --- | --- | --- | --- |
| `proven` | **yes** | **never** | T3 against pinned roots; OTS `proven` needs O3's online header, and `status` is offline |
| `valid-at-stamping-cert-since-expired` | **yes** | never | T3, cert expired after `genTime` |
| `attested` | never | **only after D97** | O4 needs the D79 upgrade group; the vault gains keys 4/5/6 for it under D97 |
| `pending` | never | **yes** | O5 |
| `internally-consistent-only` | **yes** | **yes** | T3 C6 (no path to a pinned root) / O9 |
| `invalid` | **yes** | **yes** | T1/T2 / O1–O2; A15's `Unreadable` is the same call |
| `absent` | kind-level only | kind-level only | R70: never in `outcomes()`; `status` renders it from its own slot count |

So `status` emits **six of the seven** today and all seven once D97 lands, and
two statements are permanently true of it: **an OTS anchor is never `proven` in
`status`**, and **`absent` is never an outcome** — it is a statement about a
*kind* with no artifact, which `status` knows from its own enumeration and must
print explicitly or not at all.

## Riders

Numbered, normative, implementable verbatim.

**1. The claimed/verified boundary — no status marker is needed, one source
marker is.**

1a. `status` renders **no `AnchorStatus`**, invents none, and needs no
sealer/verifier marker for one. The vault stores no sealer verdict claim —
`AnchorArtifact` has four keys and none is a status — so the distinction D95 and
R74 fight over is **vacuous for this field**. Record it as vacuous rather than
discharged; a future record schema that added a status would reopen it.

1b. The distinction is **live for the source identity**, and `status` must
honour it. `AnchorVerdict::source()` hands over `Option<&AnchorSource>` with the
discriminant intact, so a `source` under `internally-consistent-only` or
`invalid` is `AnchorSource::Claimed` and must render marked as claimed. **This
makes `status` the first consumer in the tree that can mechanise D53 §4's "MUST
render as such"** — R74's *"unreachable"* finding is about the report/page path,
which drops the discriminant at `to_anchor_result`, and `status` does not cross
that boundary. `is_verified` gains its first non-test caller.

1c. `status` never prints the word "verified" about anything it did not itself
verify. `fetch_date` is sealer-recorded and D95 governs it unchanged: rendered
unconditionally, decimal POSIX seconds, subordinate to the state.

**2. `verify_at_unix` injection — copy `VerifyOptions`'s shape, not
`AnchorStageConfig`'s rationale.**

2a. `status` takes `verify_at_unix: u64` as a **field on its context struct**,
mirroring `SealContext.now_unix_secs` (`seal_run.rs:576`). Production fills it
from `commands.rs:424`; tests assign a literal (`1_800_000_000` or
`1_798_761_600`, matching the suites already in the tree).

2b. **No user-facing surface. No `--now`, no `--verify-at`, no env var, no config
key.** The rationale, recorded so it is not re-litigated: `verify_at` is
one-sided (D53 §5(b), `chain.rs:1766`), so a user-settable value can never cause
a false failure — it can only cause a false **`proven`**. Measured:
`verify_at = 0` renders the real DigiCert token `proven` with an expired chain.
An over-claim knob on the tool whose job is to state what is proven is precisely
the knob that must not exist. `AnchorStageConfig.fetch_date` is safe to expose
*because it gates no outcome*; this one gates the headline.

2c. The clock is read **once per invocation** and threaded to every anchor, so
one rendered output cannot straddle a certificate expiry.

2d. Snapshot determinism comes from 2a and needs no fake-clock crate. But note
**U48**: the OTS slot's `fetch_date` is written from `SystemTime::now()` at
`pipeline/resume.rs:404`, which `AnchorStageConfig.fetch_date` does not reach —
so `status` must not render the OTS fetch date in a golden file until U48 lands.

**3. U25's field shape — keep the reserved count, add the class beside it.**

3a. `WorkRow.pending_anchors: Option<u64>` **keeps its documented meaning**: a
count of pending OTS attestations. `None → Some(n)` is exactly what *"reserved …
always `None` at M1"* promised, so no field already in the `--json` contract
changes meaning. **No D65 question is raised** — and D65 is not in force anyway
(measured above), with U50 the row that will draw its scope.

3b. The **class** gets its own field: `nag`, carrying `NagState`'s kebab name
(`anchored` / `only-pending-ots` / `attested-only` / `unanchored`). A count cannot
carry a class; that is `NagState`'s own doc's argument — *"'no nag' has three
different meanings and rendering them identically is how an UNANCHORED work comes
to look merely pending"* — and it applies to the JSON exactly as it applies to the
text.

3c. **Four predicates currently share the word UNANCHORED and must not be
collapsed.** `WorkRow.unanchored` is the `--no-anchor` shaping flag
(`store.rs:205`). `NagState::Unanchored` is *"no anchors at all"*. MVP-SPEC.md
line 137's UNANCHORED is *"zero headline-eligible anchors"* — which a
`--force-degraded` work carrying one pending OTS **satisfies**, while `NagState`
calls it `OnlyPendingOts` and `WorkRow.unanchored` is `false`. `list` keeps its
badge (it describes how the seal was made); **`status` must never print the
spec's UNANCHORED sentence off `WorkRow.unanchored`** — it must compute it from
headline eligibility, which `AnchorVerdict::is_headline_eligible()` gives it per
anchor.

**Extended from three to four by D108 R2** (Q129, 2026-08-09), which found the
fourth in frozen normative text. The *layer / subject* column is what makes the
fourth legible rather than merely listed: the first three are about a **work**
or a **verdict**, the fourth is about the **bytes of a `.sealproof`**.

| # | predicate | layer / subject | authority |
| --- | --- | --- | --- |
| (a) | the `--no-anchor` shaping flag | a **vault work**, at seal time | `listing.rs` (`WorkRow::unanchored`) |
| (b) | no anchor records at all | a **vault work**, now | `ots/engine.rs` (`NagState::Unanchored`) |
| (c) | zero **headline-eligible** anchors | a **verdict** over a bundle or a work | `MVP-SPEC.md:137`; `verify/aggregate.rs` (`AnchorAggregate::is_unanchored`); `status.rs` (`WorkStatus::is_unanchored`) |
| (d) | both anchor arrays empty | the **CBOR shape** of a `.sealproof`, tier [P] | `registry-v1.md:664` (**frozen**); `registry-v1.json:356` (**frozen**); `bundle/schema.rs` (`BundleParts::ots_anchors`) |

*(d) is not a competing definition; it is a true layer-1 shape fact that
borrowed the word. Its two normative sites are frozen and cannot be corrected
before the next registry version — D108 §3 rules the in-place edit refused,
`docs/format/frozen-registry-errata.md` records both sentences with their scope,
and D108 §8 records the maintainer's alternative and its price. (c) and (d) are
the pair most likely to collapse, because both are about a bundle;
`anchor/verdicts/tests.rs`'s `a_lone_proven_ots_establishes_one_identity` is the
row that goes red if they do — it builds a bundle with a **non-empty**
`ots_anchors` holding one `pending` OTS and asserts `is_unanchored()`.*

**This rider is not renumbered**: it stays 3c with four rows, so every existing
citation of "D98 rider 3c" — `listing.rs`, `engine.rs`, `status.rs`,
`status_command.rs`, Q120, Q129 — keeps resolving. The Q120 cross-surface table
stays at **three** columns and must not be extended to a fourth: its vehicle is
a vault of works, and (d) is a property of a `.sealproof`.

3d. U50 inherits 3a–3c as recorded fact rather than as a surprise.

**4. Receipt rendering — the type does not enforce it on this path, so a test
must.**

4a. Confirmed as the brief states: `ReceiptEvidence::is_headline_eligible()` is
`const fn -> false` with no path to `true`, `class()` is one-variant, and the
receipt is a separate field on `AnchorVerdicts` rather than an entry in
`outcomes()`. **But `status` cannot reach any of it** — `receipt_evidence()` is
private and `AnchorVerdicts` has no public constructor. U23's *"receipt never
rendered as an anchor is enforced by the type"* is true of the **bundle** path
and **false of the path `status` takes**.

4b. `status` renders the vault's own receipt record, **outside** the per-anchor
section, under the spec's exact sentence, as a `const`:

> `supporting evidence — no independently proven time`

(MVP-SPEC.md lines 110 and 137; U23's `Do` quotes it identically.)

4c. Because the type does not enforce it here, a test must, and it is the
replacement for the guarantee `status` does not inherit: the receipt never
appears inside the per-anchor section, and no receipt line carries any
`AnchorState` spelling.

4d. `status` renders **no time** for the receipt — not the block number as a
time, not a transaction timestamp. The block number is display-only and
unverified in v1 (registry §7.10 key 1; `model.rs:297-303`).

**5. `status`'s wording is second-person, and R18 must be told.**

MVP-SPEC.md line 130's `pending` copy — *"not yet independently provable — ask
the sealer to run `status --upgrade`"* — is written for the **verifier page**,
whose reader is a third party. `status`'s reader **is** the sealer. At M2 the
hint reads `run antseal status <id> --upgrade`, matching U25's own hint text. The
person mismatch is flagged for R18's authoritative wording set at M3, per U23's
Notes (*"re-align `status` output"* — an alignment check, not an ordering dep).

**6. `status` adds no `antseal-core` API.** Everything it needs is public today:
the two evaluators, both `from_parts` views, `OnlineEvidence::new()`,
`TsaRootStore::pinned()`, and `AnchorVerdict::{kind, state, is_headline_eligible,
verified_time_unix, source, fetch_date, diagnostic}`. A public `AnchorVerdicts`
constructor is **not** to be added for this — it would expose
`ots_present`/`tsa_present` to desynchronisation from `outcomes`, which is the
pair R70 just finished making precise.

## What this amends

- **`tasks/U.md` U23 Notes** — *"State names come from A18 at M2"* is upheld, but
  the entry implies A18's *evaluator* is reached the bundle way. It is reached
  per artifact. U23's Accept row *"pending / attested / proven (TSA) / degraded /
  UNANCHORED"* mixes three vocabularies: two are `AnchorState`s, `degraded` is
  `WorkRecord.degraded`, and UNANCHORED is rider 3c's three-way ambiguity.
- **U23's Accept is unmeetable today** — the `attested` fixture and the
  `pending → attested` `--upgrade` transition both require **D97**.
- **U47's scope** — a shared reader for the U9 anchor slots must also build
  `PendingWork`, which has no production constructor anywhere. (D97 makes U47 a
  hard predecessor for its own reasons; this is a second, independent one.)
- **`engine.rs:510-514`** — `AttestedHeaderMissing`'s *"unreachable from this
  engine"* is false while the vault cannot store the upgrade group; it is
  universal. D97 §1.2 amends the same comment from the write side; the two
  corrections are the same edit.
- **Three stale journal-on-import claims** (`listing.rs:13-18`,
  `journal.rs:973-975`, `export.rs:515-516`), and `list`'s documented reason for
  its coarse-mirror fallback.

## Residual risks and revisit triggers

- **D97 is on U23's critical path and was not a recorded dependency.** If it
  slips, `status` ships able to render five states and silently mislabels every
  upgraded `.ots` as `internally-consistent-only` — which reads to a user as
  *"your Bitcoin anchor proves nothing"* about an anchor that is fine, while
  `list` simultaneously stops nagging about it. **Trigger: any attempt to land
  U23's rendering before D97.**
- **The two documented `status`/`verify` differences are documented and not
  mechanised.** Nothing today would go red if a third crept in. Trigger: any new
  input to either evaluator that `status` and `verify` source differently.
- **Intermediates are never captured.** Harmless today — measured across all four
  pinned-root TSAs, which self-carry — but the M3 bundle builder will emit
  `intermediates: []` for the same reason, so a future TSA that does *not*
  self-carry silently costs `proven` **for every third-party verifier**, not just
  for `status`. **A101.** Trigger: adding a TSA endpoint, or any root-store bump.
- **Rider 1b makes `status` the only place the claimed/verified marker is
  mechanised**, while R74 still owes the report and the page. Trigger: R18/R22
  landing without it, which would leave one surface honest and two not.
- **`verify_at` has no user surface by ruling, not by mechanism.** Nothing stops
  a later lane adding a flag. Trigger: any `--now`/`--verify-at`/`ANTSEAL_*`
  clock appearing in the CLI surface snapshot.

## Discovered work

Ids allocated from this planner's block: **U58**, **A101**. Two used. **No U53 is
minted here** — the blocker this doc reached from the render side is D97's, and
D97 allocated U53–U57 and Q116 from the same lane's block; those ids are its own.

### U58 — three stale "an imported complete work carries no journal entries" claims
- Milestone: M2 · Size: XS · Deps: none
- `listing.rs:13-18`, `journal.rs:973-975` and `export.rs:515-516` all state a
  fact S29 falsified on 2026-08-02; the third is in the same file whose write path
  (`:781-786`) implements the opposite. Also settle whether `list`'s
  coarse-mirror fallback is still reachable, since entry 0 now survives export —
  the fallback may be correct with a false stated reason, or dead.
- Accept: no doc claims it; the fallback's reachability is asserted or its removal
  is recorded.

### A101 — TSA intermediates are never captured, and the M3 bundle inherits it
- Milestone: M3 · Size: S · Deps: A10; D98
- Nothing in `antseal-cli` has ever populated `TsaAnchor::intermediates`, so
  antseal's own bundles will carry `[]`. Measured harmless for FreeTSA, DigiCert,
  DFN and Sectigo (all self-carry; `chain.rs:1227/1274/1301` and D98's probe), and
  the error direction is monotone under-claiming. But it is luck, not design, and
  it costs `proven` for any future TSA whose token does not ship its chain.
- Accept: either the capture path stores the responder's certificate bag, or the
  reliance on self-carrying tokens is a recorded decision with a test that fails
  when a configured endpoint stops self-carrying.

---

## Index row (orchestrator applies at merge)

| [D98](D98-status-anchor-state-vocabulary.md) | What state vocabulary does `antseal status` render, and how are the vault's records projected into it? — **A18's seven names, computed per artifact through the public evaluators; A15 keeps the nag; nothing is fabricated.** The register's lean assumed `AnchorStatus` had to be invented — **false**: `evaluate_ots_artifact`/`evaluate_tsa_artifact` are `pub` and both `*ArtifactView::from_parts` constructors take no status, naming A18 as their intended consumer; measured by evaluating all five real captures with no status anywhere. `vec![]` intermediates is **not** a weaker input — `validate_token_chain` pools the token's own bag, all four pinned-root TSAs reach `proven` with `&[]` in already-committed tests, and no CLI path has *ever* populated the field (`TsaAnchor::new` has zero call sites outside core), so it is the same input `verify` will get; SwissSign's `internally-consistent-only` is root quarantine, identical either way. The journal contradiction resolves **for** S29 — `export.rs:784` skips only `>= UNIT_ENTRY_BASE`, so entries 0–2 survive import and the `anchor_digest` recovery path works; **three** stale claims say otherwise, one of them inside the file that implements the opposite. `verify_at_unix` copies **`VerifyOptions`**, never `AnchorStageConfig.fetch_date`, whose own doc says it is safe to expose *because it gates no outcome* — `verify_at` gates the headline, is one-sided, and `verify_at = 0` renders an expired DigiCert chain `proven`, so it gets no user surface at all. Option (b) dies because A15 has **no TSA verdict**; option (c) — a projection table — is the one design that guarantees `status` and `verify` diverge. `status` emits six of seven states (OTS is never `proven`; `absent` is never an outcome, R70) and adds no core API. **A fifth gap nobody named blocks U23**: `AnchorArtifact`'s key-0–3 schema cannot store the D79 upgrade group, so `attested` is unreachable under **both** machines and U23's Accept is unmeetable — reached independently from the render side here and the write side in **D97**, which rules it (keys 4/5/6, journal v2) and whose §1.2 adds that `--online` can then neither promote *nor refute*, and that `list` **stops nagging** on exactly the work whose evidence was destroyed. Discovered U58, A101 | RESOLVED (U23/U25 execute) | 2026-08-06 |
