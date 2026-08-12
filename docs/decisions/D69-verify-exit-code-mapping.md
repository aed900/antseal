# D69 — `verify`'s exit-code mapping: the carriage of a verdict set, the severity ladder, UNANCHORED, and `reveal`'s unmapped errors

- **Status: RESOLVED — the register's FRAMING is OVERTURNED, and the
  UNANCHORED sub-question is settled as a consequence rather than as the
  subject.** The hard question is not which integer UNANCHORED gets; it is
  that `antseal verify` has **no scalar verdict to map**. `verify_bundle`
  returns `Result<VerificationReport, VerifyError>`; the `Ok` arm carries a
  `Vec<AnchorResult>` in which each slot independently holds one of seven
  states, plus two layers, plus a receipt class, plus (under `--online`) a
  sibling overlay and (under `--live`) a fourth-valued storage verdict. And
  the binding constraint is not the integer but the **carriage**: the shipped
  `main_entry` has exactly two arms — `Ok(Outcome) → 0 + ok:true + result`
  and `Err(CliError) → code + ok:false + error` — so under the machine as
  built, *any* nonzero verdict exit emits **no verdict data at all** under
  `--json`. The ruling therefore adds a **third arm** (`Outcome` carries an
  optional exit class; `ok` means "a result document is present"), then folds
  the anchor set with **D48 §6's severity rank, extended — and D48's
  *carriage* corrected**, because mapping a per-row fold onto `CliError` is
  what makes D48 §6's own promise ("per-file detail always available … in the
  `--json` result") unkeepable, as the committed `restore` fixture already
  proves. Verdict rungs, severity-ordered: **`verify-bundle-rejected` 40**
  (the `Err` arm — tamper and malformed are one class, deliberately) ·
  **`verify-anchor-refuted` 41** · **`verify-headline-divergence` 42** ·
  **`verify-unanchored` 43** · everything else **0**. **UNANCHORED exits a
  distinct nonzero (43)** — distinct precisely so a script that legitimately
  accepts undated bundles has a one-line opt-back-in. `--online` **may** move
  the exit code, in all three directions, and D64 is not violated because the
  exit code is not a report byte and not an offline-block rendering; **probe
  failure and endpoint disagreement cannot move it**, and that is a theorem
  off `OnlineBlockResult`'s missing failure variant, not a policy. `--live`
  and the storage-linkage layer **never** move it (spec line 118: *"storage
  is the product's bonus, not its proof"*). `reveal`'s 23 `RevealError`
  variants — which R16 deliberately left here — map onto shipped U2 classes
  with **exactly one** new class, `reveal-inputs-unusable` (**36**, outside
  U2's reserved 40–49 band by construction).
- **Date: 2026-08-12** (wave 18, Act 1 planning lane; briefed to overturn the
  register's framing. The framing is overturned on measurement; the UNANCHORED
  answer the register floated as the whole question survives as one rung of
  four, and is sharpened by the measurement that spec line 137 guarantees a
  normal seal never reaches it.)
- **Owning tasks: U30** (finalizes the mapping — its `Do` names open decision
  13 by name), **U2** (owns the class identifiers and the code table; its
  `Notes` deferred exactly this), **U3** (the envelope's `ok` semantics and the
  registered `verify` fixture), **R21** (exposes the verdict-class data — its
  Accept already says *"the mapping itself is U30's, per D69"*), **U28**
  (writes `From<RevealError> for CliError` under §5), **U20/D48** (the third
  arm applies retroactively — §6.1), **R27** (the first lane that will gate on
  these codes). Register entry: the D69 row under `TODO.md` "Due M3".
- **Amends**: `tasks/U.md` U2 `Notes` and U30 `Do`/`Accept`; `tasks/U.md` U3
  `Notes` (the `ok` semantics); `crates/antseal-cli/src/error.rs` module-doc
  table and `crates/antseal-cli/tests/exit_codes.rs`'s reserved-band assertion
  (§7.2 — it currently *forbids* 40–49 for every class and must be amended in
  the same change). **Supersedes**: nothing. **Corrects**: **D48 §6**'s
  carriage — not its severity order, which is adopted verbatim and extended
  (§6.1).
- **Method**: read/grep only (shared working tree; the main session held the
  cargo lock). No builds, no writes outside this file. Code line numbers are
  snapshots of the tree at this record's date, not stable anchors. The frozen
  registry is cited by section only.

---

## 1. What was measured

### (a) The shipped exit-code scheme, and exactly what is free

`crates/antseal-cli/src/error.rs:11-56` carries the committed table;
`tests/exit_codes.rs:36-97` pins it literally in a `TABLE` const of 28 rows and
asserts the properties. Measured, in full:

| band | codes | status today |
|---|---|---|
| success | `0` | `ExitCode::SUCCESS`, the only 0 producer |
| general | `1` internal · `2` usage · `3` not-implemented · `4` io-error | in use |
| — | `5`–`9` | **free** |
| consent/vault | `10`–`19` | in use (10 classes) |
| seal/payment/resume | `20`–`27` | in use (8 classes) |
| — | `28`, `29` | **free** |
| restore/vault-file | `30`–`35` | in use (6 classes) |
| — | `36`–`39` | **free** |
| **verdict** | `40`–`49` | **RESERVED** — *"**bundle**-verification verdict classes, finalized in U30 (M3) — do not mint here"* (`error.rs:44`) |
| — | `50`–`124` | free |
| forbidden | `125`+ | shell/signal territory (`error.rs:46`) |

Which command uses which: every one of the 28 is a `CliError` variant reachable
from `run::run`'s dispatch, and `commands.rs` shows the current wiring state —
`init`/`seal`/`list`/`status`/`vault export|import` are landed, `restore` is
gated at the U36 backend seam (`commands.rs:411-420` → `backend::unavailable`,
which reports in the **transient network class 23** by
`backend.rs:76-95`'s own reasoning), and `show`/`reveal`/`verify` return
`NotImplemented`+M3 (`run.rs:42-51`). So **no verdict code is in use, and the
band is intact** — which is what U2 reserved it for. U2's own note on why the
band survived restore's needs is the governing precedent for numbering here:

> `error.rs:48-56` — *"That order is implemented as an explicit rank … never
> as a comparison of numeric codes — which is why restore's verification class
> can live at 35 without disturbing the 40–49 band."*

**Consequence taken, not argued around**: `reveal` is not bundle verification,
so a reveal class may not enter 40–49. §5 puts it at **36**, the first free
code after restore's band.

### (b) The carriage constraint — the measurement that reframes the decision

`crates/antseal-cli/src/lib.rs:140-151`, verbatim in structure:

```rust
let code = match run::run(&cli, &vault_slot) {
    Ok(outcome) => {
        if cli.globals.json { println!("{}", machine::success_envelope(command, network, outcome.json)); }
        ExitCode::SUCCESS
    }
    Err(err) => fail(network, &err),   // eprintln + error_envelope + err.exit_code()
};
```

and `commands.rs:37-39`: `pub(crate) struct Outcome { pub json: serde_json::Value }`
— one field. `run::run` is `Result<Outcome, CliError>` (`run.rs:36`).

There is **no third arm**. Therefore, in the build as it stands:

> **nonzero exit ⟺ `CliError` ⟺ `machine::error_envelope` ⟺ `ok:false` with
> `{class, exit_code, message}` and NO `result` key at all**
> (`machine.rs:216-243`).

So "UNANCHORED exits nonzero" is not a choice of integer. It is a choice to
emit, under `--json`, **no verdict document whatsoever** for a bundle whose
every commitment opened and every signature verified. The register's framing
("which integer?") cannot see that, and it is the whole decision.

### (c) The same hole is already live, one command early — measured, with the fixture

`crates/antseal-cli/tests/machine_mode.rs:409-411` composes the registered
`restore` fixture as

```rust
success_envelope("restore", "arbitrum-one", fixture_restore().json())
```

over a `RestoreOutput` (`machine_mode.rs:824-878`) whose rows include
`FileStatus::RefusedOverwrite` **and** `FileStatus::VerificationFailed`. The
committed line — `crates/antseal-cli/tests/snapshots/json-envelopes.txt:34` —
therefore reads `"ok":true` with `"counts":{…"refused-overwrite":1,…,"verification-failed":1…}`.

But `RestoreOutput::into_error()` (`restore_out.rs:198-224`) returns
`Some(CliError::RestoreVerificationFailed{..})` for exactly that shape — D48 §3
says a run *"exits 0 iff every file is `restored` or `already-restored`"* — and
`main_entry` emits `success_envelope` **only** on the `Ok` arm at exit 0.

**No build can produce that envelope.** The registered fixture documents a
pairing the machine forbids. (It is not currently falsifiable end-to-end
because `commands::restore` is still the U36 seam stub and `into_error()` has
**no production caller** — measured: its only callers outside its own module
are eight lines in `tests/restore_output.rs`.) This is reported as a product
defect in §9 (i); the ruling below is what makes D48 §6's own sentence true.

### (d) What the verdict actually is — a set, proved from the types

- `verify::pipeline::verify_bundle` → `Result<VerificationReport, VerifyError>`
  (`pipeline.rs:326-331`), documented *"the **normative entry point** (D27:
  fail-fast, tamper-authoritative)"* and *"returns the `VerificationReport` for
  a bundle that **passed** the evidence layer"*.
- `VerificationReport.anchors: Vec<AnchorResult>` (`report.rs:167`), and
  `AnchorResult.state: AnchorState` with `AnchorState::ALL` = **7** values
  (`report.rs:477-509`). **Nothing constrains the vector to one state.** The
  A1 test `ineligible_slots_never_contribute_time_or_eligibility`
  (`aggregate.rs:193-213`) constructs a five-element vector holding five
  *different* states at once, and
  `earliest_eligible_time_wins_and_mixed_sets_are_anchored` (`:216-227`)
  constructs a four-element mixed set. **The set problem is not hypothetical;
  it is exercised in the shipped suite.**
- `EvidenceLayerResult { passed: bool, units_verified: u64 }` with
  `passed` documented *"always `true` in an emitted report"* (`report.rs:356-359`)
  — confirming the pass/fail bit lives on the `Result` discriminant, not in
  the report.
- `StorageLinkageResult` has exactly one variant, `NotEvaluated`
  (`report.rs:402-405`), doc: *"nothing here ever gates the evidence layer,
  because 'storage is the product's bonus, not its proof'."*

### (e) What R17's aggregate can and cannot answer

`verify::verdict::VerdictAggregate` (`verdict.rs:158-165`) has five private
fields: `total_anchors`, `eligible_count`, `headline`, `divergence`, `receipt`.
`is_unanchored()` is `eligible_count == 0` (`:302-304`); `divergence` is
`Some` iff the eligible spread strictly exceeds
`HEADLINE_DIVERGENCE_THRESHOLD_SECS` (`:247-258`, and the `>` is the one the
R17 lane caught live as `>=` in wave 17).

**It carries no state field and matches on `AnchorState` nowhere** — by
deliberate design (`verdict.rs:15-24`: *"This module adds **no** second table
and contains **no** match on `AnchorState` … at all"*). So:

> `VerdictAggregate` can answer *"is there a proven time?"* and cannot answer
> *"was anything refuted?"* A bundle with one `invalid` anchor and a bundle
> with one `pending` anchor produce **identical** aggregates
> (`total_anchors: 1, eligible_count: 0, headline: None`).

That is a concrete implementation consequence: the rung classifier needs a
second, refutation-counting fold over `AnchorVerdicts`, and §3 R4 sites it.

### (f) The house already has three severity folds, and one states the governing principle

1. **D48 §6 / U20** — `FileStatus` derives `Ord` *"**the** reason this enum
   derives `Ord` in this declaration order"* (`restore_out.rs:114-129`),
   `is_success()` (`:110-112`), `most_severe()` = filter non-success then
   `max()` (`:169-175`), `into_error()` = worst class → `CliError`
   (`:201-224`). The fold shape is exactly transferable; the **`into_error()`
   destination** is what §6.1 corrects.
2. **R11 / `LiveVerdict`** (`antseal-net/src/live/manifest.rs:235-257`),
   normative doc:
   > *"the worst **established fact** wins, and uncertainty rules only when
   > nothing negative was established — `Divergent` > `SomeMissing` >
   > `Inconclusive` > `AllPersisted`."*
   This is the grammar §3 R2 adopts.
3. **D64 §3 / `HeadlineImpact`** — the three-way `Supplies` / `Stands` /
   `StillUnanchored` classifier, with exactly-one-of-three rendered always.

### (g) `status` renders `invalid` at exit 0 — the losing side's best evidence, and its scope

`crates/antseal-cli/src/status.rs:313-318`:

> *"**Damage is data here, not an error** (D100 R6) … both at **exit 0**,
> which is what `status` already does for an `.ots` whose *bytes* do not parse
> (that renders `invalid`, D98's cross-walk). One layer of wrapping apart, the
> exit codes used to be 0 and 12."*

and `:291-297`, on why `damaged` gets a field rather than a verdict:

> *"this is a fact about the **vault**, not evidence about a time, and it gets
> a field rather than a verdict or an exit code."*

Measured and quoted in full because it is the strongest argument **against**
this record's rungs, and because its own stated reason (*a fact about the
vault*) is what confines it to `status`. §4 answers it.

### (h) The two namespaces are already ruled disjoint, and the exit code is the *process* one

`docs/testing/error-code-contract.md` §2, verbatim:

> *"The two namespaces answer different questions and must not merge. An
> exit-code class is a **process outcome** — what the CLI did. A code is a
> **rejection class** — what was wrong with the bytes."*

Measured universe: `testdata/error-codes/v1/CODES.txt` holds **248** codes
today (the doc's "194" is its 2026-08-02 figure), across 23 prefixes:
`anchor bundle cbor concat content covered crypto duplicate fine full manifest
non padded partial path raw revealed tiling touched true unit unknown wrong`.
**`verify-` is free — zero codes carry it** (`grep -c "^verify-" … → 0`), so
the whole `verify-` stem is available to the exit-class namespace and is
reserved against the code namespace by §3 R8, mirroring §2's existing
`anchor-gate-abort` reservation. `VerifyError::code()` (`verify/error.rs:703-780`)
is the wildcard-free `const fn` those codes come from; a wrapper arm surfaces
the wrapped code unchanged.

### (i) `--online` cannot move a verdict on bad weather — structurally

D64 §5 and the code it measured: `anchor::model::OnlineBlockResult` has **no
failure variant, deliberately** (D56 §3) — attempted-but-unreachable and
attempted-but-disagreeing are both *the absence of the entry* in
`BlockEvidence`, and the matches are wildcard-free so adding one does not
compile. Agreed evidence can promote (`AnchorVerdict::proven(...)`) **or
refute** (D93 §5's O6/O7 → `invalid`). Therefore, over the same bundle:

> If no endpoint pair agreed, the online-augmented `AnchorVerdicts` **equal**
> the offline ones, so the online-augmented `VerdictAggregate` equals the
> offline one, so any pure function of that aggregate returns the same value.

§3 R6 states this as a theorem rather than legislating it.

### (j) The spec's own words on the states, the headline, and who reaches UNANCHORED

Line 127: *"**Verdict taxonomy per anchor** (one authoritative wording set; M3
snapshot-tests it); **headline-eligible** states are tagged [H]"*, then lines
129–135 — `proven` **[H]**, `valid-at-stamping-cert-since-expired` **[H]**,
`attested`, `pending`, `internally-consistent-only`, `invalid`, `absent`.
Line 134 in full: *"`invalid` — signature/op check fails."*

Line 137, the four sentences this record turns on, verbatim:

> *"**One headline**: "Existed no later than \<earliest headline-eligible
> time\> (source)"."*
>
> *"Divergence >48 h between *headline-eligible* anchors is flagged."*
>
> *"Zero headline-eligible anchors → **loud** "UNANCHORED — integrity and
> signature only, no provable time"."*
>
> *"A normal seal never hits this offline: the minimum-anchor policy
> guarantees ≥1 TSA token, which is `proven` (headline-eligible) offline. It
> arises only for `--force-degraded`/`--no-anchor` seals, or a bundle carrying
> only a `pending`/`attested` OTS — where `--online` or a later `status
> --upgrade` then **supplies the headline**."*

Line 118: *"This alone carries the evidentiary verdict; storage is the
product's bonus, not its proof."* Line 119 puts `--live` in the
storage-linkage layer. Line 38 makes `verify` the **third party's** command;
the frozen CLI-surface snapshot spells it *"Verify a proof bundle offline
(third-party; needs no vault and never prompts)"*
(`tests/snapshots/cli-surface.help.txt:14`, `:294-318` for the flag set —
`<BUNDLE>`, `--online`, `--live`, `--json`, `--network`). Line 149 makes
`--no-anchor` **dev-only and rejected on `--network arbitrum-one`**.

The loudest string in the product is measured, not asserted: `wording.rs:166`
`UNANCHORED_BANNER`, and `wording.rs:149-151` records that it is *"the loud
upper-case banner in this product … alone"*.

### (k) Nothing gates on `verify`'s exit code today; R27 is the first lane

Swept `scripts/`, `.github/workflows/`, `docs/`, `tasks/`, `crates/` for
`antseal verify`: every hit is prose, a task entry, or the frozen help text.
`scripts/check-anchor-net.py:591` mentions `tests/exit_codes.rs` as a
*policy-scan key*, not a gate. The runbook and D126 both record the reason —
*"`antseal verify --online` is an M3 stub"* (`docs/anchors/real-smoke-runbook.md:143`;
`run.rs:50` maps `Command::Verify` to `Milestone::M3`).

The first consumers, both specified already:

- **U30 Accept row 1**: *"runs on a vault-less machine against R's golden
  bundles (valid, tampered, UNANCHORED, pending-only) with correct verdict
  rendering and **mapped exit codes**; tampered → nonzero"*.
- **R27** (`tasks/R.md:333`): *"(a) `antseal verify` offline asserting the
  expected verdict"*.

And the M1 devnet E2E's UNANCHORED check runs through **library APIs**, never
the CLI (spec line 154; R11/R12 rows) — so no existing green lane can be
reddened by giving UNANCHORED a nonzero code.

---

## 2. The framing, overturned

The register line reads *"Verify exit-code mapping per verdict class
(UNANCHORED = 0 or distinct nonzero?)"*. Three things in it are false or too
small, each on a measurement above.

1. **"per verdict class" presupposes a scalar that does not exist.** §1 (d):
   the `Ok` arm carries a vector of independently-stated states, and the
   shipped suite already builds mixed vectors. There is no "the verdict class"
   to map — there is a *set*, two layers, a receipt class, and up to two
   sibling documents. The first ruling any record here owes is a **fold**, and
   the register's phrasing skips straight past it.

2. **The binding constraint is carriage, not numbering.** §1 (b): the process
   has one lever and it is welded to `CliError`. Answering "43" without
   answering "and the `--json` document still carries the verdict" ships a
   command that, in machine mode, replaces a perfectly good report with a
   three-key error object. §1 (c) shows the house already believed otherwise
   and committed a fixture proving it.

3. **The record's scope is larger than its title, by R16's deliberate act.**
   `TODO.md`'s R16 row records the deviation in its own words: *"no `CliError`
   mapping (U28's, **no exit-code ruling exists**)"* — 23 `RevealError`
   variants (`pipeline/reveal.rs:255-461`), none of which is a verdict.
   Silence here is what created the gap; §5 closes it.

**What survives, sharpened.** The register's binary — UNANCHORED 0 or
nonzero — is a real question and it is answered *nonzero* (§3 R2, §4). It
survives **ON MEASUREMENT**, and what sharpened it is spec line 137's last
sentence: a normal seal **cannot** reach UNANCHORED offline, because the
minimum-anchor policy guarantees a `proven` TSA. The rung fires only on
`--force-degraded`, on dev-only `--no-anchor` (which line 149 forbids on
mainnet), and on OTS-only bundles — i.e. on exactly the three populations a
third party should be told about. The strongest objection to a nonzero
UNANCHORED (*"it will fire constantly"*) is refuted by the spec's own
guarantee.

---

## 3. The ruling

Nine rules. "Rung" = a member of the severity ladder; "aggregate" = the
`VerdictAggregate` of the computation the run performed.

### R1 — The third arm: a nonzero exit that still carries its result

`commands::Outcome` gains one field:

```text
Outcome { json: serde_json::Value, exit_class: Option<ErrorClass> }
```

`main_entry`'s `Ok` arm becomes
`ExitCode::from(outcome.exit_class.map_or(0, ErrorClass::exit_code))`, and
**still emits `machine::success_envelope`**. `Err(CliError)` is unchanged.

Consequences, each deliberate:

- **`ok` is ruled to mean "a result document is present"**, not "the exit code
  is 0". The two were coincident until now and are being separated
  deliberately, because a consumer's first question is *"can I parse
  `result`?"* — and for a verdict command the answer is yes even when the
  verdict is bad news. `ok:false` continues to mean exactly `error` is present
  and `result` is not. `ENVELOPE_VERSION` stays **1**: no key is added,
  removed or renamed, and `{class, exit_code, message}` is untouched (`machine.rs:64-66`
  keeps its bump as a machine-interface event; this is not one).
- **D51 invariant 2 is preserved**: plain and `--json` runs exit identically,
  because the code is computed before the mode branch.
- The field is `Option<ErrorClass>` rather than a fresh enum so there is
  exactly **one** code table in the product, with one `exit_code()` and one
  `name()` (`error.rs:317-386`), and so U2 keeps ownership of identifiers as
  its `Notes` require.

### R2 — The full class → code table

Severity-ordered where a fold applies. `†` = reachable only through the fold;
`‡` = the `Err` arm of `verify_bundle`, where no report exists.

| # | class | code | fires when |
|---|---|---|---|
| ‡ | `verify-bundle-rejected` | **40** | `verify_bundle` returned `Err(VerifyError)` — a tampered, forged, malformed, oversized or non-canonical bundle. **One class for all 248 rejection codes**; the specific `VerifyError::code()` is the rejection class and rides in the message, never in the integer (§1 h). |
| † 1 | `verify-anchor-refuted` | **41** | ≥1 anchor slot is `AnchorState::Invalid` — offline (`signature/op check fails`, spec line 134) or by D64 §5 agreed refutation under `--online`. |
| † 2 | `verify-headline-divergence` | **42** | `aggregate.divergence().is_some()` — headline-eligible anchors disagree by strictly more than 48 h (spec line 137). |
| † 3 | `verify-unanchored` | **43** | `aggregate.is_unanchored()` — zero headline-eligible anchors (spec line 137). |
| — | *(no class)* | **0** | a verdict exists, nothing is refuted, no divergence is flagged, and at least one anchor is headline-eligible. |
| — | *reserved* | **44–49** | see R9. |

**Non-verdict classes on `verify`'s path, all existing, none minted:**

| situation | class | code |
|---|---|---|
| bad argv / unknown flag | `usage` | 2 |
| bundle file missing or unreadable | `io-error` | 4 |
| `--live` with no reachable backend | `network-failure` | 23 |
| an antseal bug on the verify path | `internal` | 1 |

`verify` needs **no vault**, so no vault class is reachable from it; it **never
prompts**, so no consent or passphrase class is either (frozen help,
`cli-surface.help.txt:14`).

**States that deliberately get no rung of their own** — `attested`, `pending`,
`internally-consistent-only`, `absent`. Each is ineligible, so each *already*
contributes to rung 3 when it is all a bundle has; and none is a refutation, so
none may outrank one. A bundle with one `proven` TSA **and** one
`internally-consistent-only` TSA exits **0**: it carries a valid, independently
proven time, and a second token from an untrusted root is a rendered fact, not
a defect in the evidence the bundle does carry. The reader who needs that
distinction reads `--json`; the integer answers one question.

### R3 — The set rule, stated as a rule

> **`exit = the code of the highest-ranked rung whose predicate holds over the
> whole anchor set; 0 when none does.`**
> Rank: `verify-anchor-refuted` **>** `verify-headline-divergence` **>**
> `verify-unanchored`. Rung 1 is *any* (existential over slots); rungs 2 and 3
> are properties of the aggregate.

This is **D48 §6's severity fold, extended** — the same shape as
`FileStatus::most_severe()` (`restore_out.rs:169-175`), and the same grammar
as R11's `LiveVerdict`: *the worst established fact wins, and uncertainty rules
only when nothing negative was established*. Refutation and divergence are
established facts (something is forged; two proofs contradict each other);
UNANCHORED is an absence, and so ranks below both.

Two properties worth stating because they make the rule cheap to reason about:

- **Rungs 2 and 3 are mutually exclusive by construction.** Divergence needs
  two timed eligible anchors, so `divergence.is_some() ⇒ eligible_count ≥ 2 ⇒
  ¬is_unanchored`. The ladder only ever arbitrates 1-vs-2 and 1-vs-3.
- **The brief's own example resolves without a special case**: one `proven`
  and one `invalid` anchor → rung 1 holds, rung 3 does not (eligible_count = 1)
  → **41**. Not because a list says so, but because the fold says so.

**Never** a bitmask, never a sum, never "1 for anything wrong". A bitmask puts
two questions in one integer, which is the sin §2 diagnoses; a generic `1` is
already `internal` (`error.rs:16`) and would collide with the bug class.

### R4 — Where the classifier lives, and the fold it needs

The classifier is a **pure function in `antseal-core`**, WASM-safe and
deterministic, beside R17's aggregate:

```text
verdict_exit_rung(aggregate: &VerdictAggregate, refuted: RefutedCount) -> Option<VerdictExitRung>
```

with `VerdictExitRung` a three-value enum, `Ord` deriving from declaration
order for the same reason `FileStatus` does, and a **wildcard-free** match
mapping rung → stable kebab name. It is core-side, not CLI-side, because
**R22's page must be able to state the same rung** — the parity gate (R27 (b),
CLI/page string-equality) is worthless if the two surfaces classify from
different code.

**The second fold is required, and §1 (e) is why**: `VerdictAggregate` carries
no state field and matches on `AnchorState` nowhere, by R17's deliberate
one-predicate rule. Counting `Invalid` slots is therefore a *separate* pass
over `AnchorVerdicts` — and it must stay separate, so that R17's "there is no
second eligibility table here" invariant is not weakened by a rung classifier
sneaking a state match into the eligibility module. The count is an input to
the classifier, not a field on the aggregate (a field would be an R17 API
change for a CLI concern, and D64 §6 already refused the analogous move on the
report).

### R5 — `--online` may move the exit code; probe weather may not

**Rule:** the exit code is `verdict_exit_rung` applied to the aggregate of
**the strongest computation the run performed** — the offline aggregate when
`--online` is absent, the online-augmented aggregate when it is present.

All three directions are legal and each is forced:

| transition | cause | forced by |
|---|---|---|
| **43 → 0** | an `attested` OTS promotes to `proven` and supplies a headline | spec line 137: *"`--online` … **then supplies the headline**"* |
| **0/43 → 41** | agreed evidence refutes an embedded header (O6/O7) | spec line 108's *forged header … (`invalid`)*; D64 §5 |
| **0 → 42** | the augmented eligible set newly spans >48 h | D64 §3 / `wording::divergence_newly_flagged_line` |

**Why this does not violate D64**, point by point against D64's own text:

- D64 §6's never-overwrite **equality is about bytes**: *"the canonical report
  bytes of a `--online` run are byte-identical to the offline run's."* An exit
  code is not a report byte; `REPORT_VERSION` stays `1` and no frozen vector
  moves.
- D64 §2's inviolability is about **the offline block's rendering** — *"the
  offline block cannot gain a heading, a label, or any 'see below' marker."*
  The exit code is not in the offline block; it is not rendered at all.
- D64 §3 already grants the overlay a **full headline sentence** in the
  Supplies case. A record that lets the overlay supply *the headline* and then
  forbids it from supplying a four-valued coarsening of the same datum is
  drawing a line with no principle behind it.
- The converse is the incoherence this record must avoid: `--online` prints
  *"existed no later than T (ots, bitcoin block H, online-confirmed)"* and the
  process exits with the UNANCHORED code. The screen and the code would
  contradict each other — the exact defect R7 forbids.

**And the weather clause is a theorem, not a policy** (§1 i): an unreachable or
disagreeing endpoint leaves the anchor `attested` because `OnlineBlockResult`
has no failure variant and the entry is simply absent from `BlockEvidence`.
The online-augmented verdicts then *equal* the offline ones, so any pure
function of the aggregate returns the same value. **A network outage cannot
change `antseal verify`'s exit code, and no code enforces that — the type
system does.** The overlay still renders the failure as that anchor's outcome
line (D64 §6.2 `NotPromoted{disagreed | endpoint-failures | no-evidence}`),
which is where a human learns it.

### R6 — `--live` and the storage-linkage layer never move the exit code

Neither `LiveVerdict` (`Divergent`/`SomeMissing`/`Inconclusive`/`AllPersisted`)
nor `StorageLinkageResult` may contribute a rung, ever.

Grounds, in the order that decides it:

1. **Spec line 118**, verbatim: *"This alone carries the evidentiary verdict;
   **storage is the product's bonus, not its proof**."* Line 119 puts `--live`
   squarely in the other layer. An exit code that answered both layers would
   be the merge that sentence exists to forbid.
2. **R20's Accept already freezes the independence**: *"each renders a distinct
   storage-linkage result while the **evidence verdict is unchanged** (test
   asserts evidence outcome identical across all three)"*.
3. **Project rule 3 / the risks section**: *"evidence validity never depends on
   Autonomi"*. A code that moved on a `get_data` failure would make a
   third-party verification gate depend on the youngest component in the
   stack.

U30's Accept row 2 — *"`--live` mismatch (mock) fails the storage-linkage layer
**distinctly** from the evidence layer"* — is satisfied by distinct rendering
and a distinct machine field, which is what "distinctly" asks for. Its row 3 —
*"`--live` without network → **clean error**, offline verdict unaffected"* — is
read the way the wave rule reads every failure: **by its message**. The run
prints the complete offline verdict, the live section renders R11's own
`Inconclusive` (*"the check could not be completed"*), and the exit code is the
evidence verdict's. A build with no storage backend compiled in is the one
case where `--live` cannot be attempted at all; that refuses at the seam as
`network-failure` (23) exactly as `seal`/`restore` already do
(`backend.rs:76-95`), before verification, and is a process outcome, not a
verdict.

### R7 — `--json`: no duplication, and disagreement made structurally impossible

The exit code is a **coarsening** of data the result already carries, not a
duplicate of it: the result carries the seven per-anchor states, the headline,
the divergence pair, the eligible count and the layers; the integer carries
one four-valued rung folded from them. Nothing is expressible in the integer
that is not expressible in the document — which is correct, because the
integer exists for the one consumer that cannot read the document.

Disagreement is prevented **by construction, not by a test alone**:

- there is exactly **one** classifier (R4), in core, and it takes the same
  `VerdictAggregate` value that serializes into `result`;
- the CLI has **no second route** to a verdict code — `Outcome.exit_class` is
  populated at exactly one call site, from the classifier's output;
- the machine surface carries **the rung's stable name and its code**, so
  `result.<verdict slot>.exit_code == $?` is an assertable equality rather
  than a convention (§7.3 makes it a test);
- a consumer therefore **never parses the integer** — it reads the name, the
  way every other machine surface in this product reads `class` rather than
  `exit_code`.

**Field names, nesting and any stability commitment are D65's, not ruled
here** — this record rules only that the class name and the code *are
exposed* and that the equality holds. (Same edge D67 §5 drew: values here,
schema there.)

### R8 — Naming, and the reserved stem

Class identifiers are `verify-bundle-rejected`, `verify-anchor-refuted`,
`verify-headline-divergence`, `verify-unanchored`, `reveal-inputs-unusable` —
kebab-case, U2's existing convention.

The `verify-` prefix was chosen on measurement (§1 h): the code universe has
**zero** `verify-` codes across 23 prefixes, so no cross-namespace near-miss of
the `anchor-gate-abort` kind is created. **`verify-` is hereby reserved
against the code namespace**, exactly as `error-code-contract.md` §2 reserves
`anchor-gate-abort` against the A domain: if R or A ever needs to name one of
these outcomes as a *rejection class*, it mints a distinct spelling.

Rejected: any `anchor-`-prefixed class name (would mint a second `anchor-`
stem across the two namespaces — the thing §2 flagged and Q77 tracks);
`bundle-rejected` bare (would share a stem with 47 live `bundle-*` codes).

### R9 — What 44–49 stays reserved for, and why nothing is minted into it now

- **a storage-linkage / `--live` rung**, if a future decision ever overturns
  R6. Deliberately unallocated rather than allocated-and-unused: a `Divergent`
  live result — the network serving *different bytes* at a manifest address,
  which R11's own doc calls something that *"should be impossible"* under
  content addressing — is the one candidate with a real argument, and it should
  arrive with its own record rather than as a slot someone finds lying around.
- **a `sig_policy`-shaped rung**, if the signature layer ever needs to be
  distinguishable from `verify-bundle-rejected` (today a `sig_policy` violation
  is a `VerifyError` and correctly lands at 40).
- **report-v2 growth** under D65.

**Revisit trigger**: any change that would make a `verify` run need a fifth
verdict-shaped code, or the first real user report that `verify-bundle-rejected`
is too coarse.

---

## 4. UNANCHORED: the losing side's best case, and why it loses

The record owes both halves, so here is the strongest form of the case for
**exit 0**, stated without hedging:

> An UNANCHORED bundle is not a failure — it is a **success with a smaller
> claim**. Every commitment opened, every signature verified, every structural
> invariant held, nothing was forged. Exiting nonzero conflates *"this evidence
> is bad"* with *"this evidence is undated"*, which are different facts a
> third party acts on differently. The product ships `--no-anchor` itself
> (spec line 149) and its own M1 verification item is *"UNANCHORED
> library-verify"* (line 154) — the product would be exiting nonzero on
> artifacts it deliberately produces. And there is direct house precedent
> pointing the other way: **`status` renders an `invalid` anchor at exit 0**
> (`status.rs:313-318`, D100 R6 — *"damage is data here, not an error"*),
> having explicitly *retreated* from an exit-12 refusal because `list` showed
> the same state as a soft row at exit 0. If a *refuted* anchor is exit-0
> material in this codebase, an *undated* one certainly is.

It loses on four measurements.

1. **The precedent's own reason confines it to `status`.** D100's sentence is
   *"this is a fact about the **vault**, not evidence about a time"*
   (`status.rs:296-297`), and the divergence it closed was `status` vs `list` —
   two **sealer-facing** commands answering *"what do I hold?"*, where every
   answer is information and the process plainly succeeded. `verify` is
   third-party by the spec's own line 38 and by its own frozen help string
   (*"third-party; needs no vault and never prompts"*). Its question is not
   *what do I hold* but *should I rely on this* — and the exit code is the only
   channel in which a non-interactive consumer can hear the answer.

2. **Exit 0 is the strongest statement the process can make, and the spec
   forbids making it here.** Line 137 does not say "render UNANCHORED"; it says
   **loud**. `UNANCHORED_BANNER` is measurably the only upper-case banner in
   the product (`wording.rs:149-151`). A command that prints the loudest string
   it owns and then exits 0 has made that string **silent to every consumer
   that is not a human at a terminal** — and the consumers that matter for a
   release gate are all of the other kind. The product's thesis is proof of
   existence **by a time**; a bundle with no provable time has not delivered
   it.

3. **The "two questions in one integer" objection is answered by the ladder,
   not by 0.** The integer answers exactly one question — *is this dated,
   unrefuted evidence?* — with a severity-ordered answer. UNANCHORED is a rung
   on that one question, not a second axis. Exit 0 would not simplify the
   integer; it would delete a value of it.

4. **The asymmetry of harm, and the escape hatch that makes the rung
   tolerable.** Exit 0 on an undated bundle: a gate passes evidence that proves
   nothing about time, invisibly and permanently. Nonzero: a script author
   reads the table, sees 43 means *verified, undated*, and writes one line —
   `antseal verify b.sealproof || [ $? -eq 43 ]` — if that is genuinely
   acceptable to them. **This is precisely why the rung must be *distinct* and
   not a generic 1**: distinctness is what converts an opinionated default into
   a policy the caller can override. A caller cannot opt back into a
   distinction that was never made.

And the objection that the rung will fire constantly is refuted by the spec's
own guarantee (§2): *"A normal seal never hits this offline: the minimum-anchor
policy guarantees ≥1 TSA token, which is `proven` (headline-eligible)
offline."* The rung fires on `--force-degraded` seals, on dev-only
`--no-anchor` seals that line 149 forbids on mainnet, and on OTS-only bundles
— populations for which a third party being told is the whole point. And it
fires on **no existing green lane**: nothing gates on `verify`'s exit code
today (§1 k), and the M1 UNANCHORED check runs through library APIs.

---

## 5. `reveal`'s 23 errors — mapped here, because silence is what left them open

`RevealError` (`crates/antseal-cli/src/pipeline/reveal.rs:255-461`), all 23
variants measured. None is a verdict; every one is a **process outcome**
(§1 h), so the mapping reuses U2's shipped classes and mints the minimum. The
`From<RevealError> for CliError` impl itself is **U28's to write** (R16's own
recorded deviation says so); this record fixes the classes it must produce.

| # | variants | class | code |
|---|---|---|---|
| 1 | `WorkNotFound`, `EmptySelection`, `UnknownUnitId`, `RawMirrorNotUnitSelectable`, `NotRevealable`, `ReceiptUnavailable`, `ReceiptUnusable`, `ReceiptBlockNumberUnknown` | `usage` | **2** |
| 2 | `Unfetchable`, `ManifestUnfetchable` | `network-failure` | **23** |
| 3 | `ManifestUnavailable`, `StorageRecordUnavailable`, `ManifestDecrypt`, `ManifestMalformed`, `ManifestIdentityMismatch`, `MalformedRecord`, `AddressMismatch`, `UnitDecrypt`, `AnchorUnembeddable`, `Build` | **`reveal-inputs-unusable`** (new) | **36** |
| 4 | `AnchorsUnreadable{source}` | delegate to the shipped `From<JournalError> for CliError` (`pipeline/journal.rs:682-706`) — `Corrupt` → `vault-auth-failure` 12, `NewerRecord` → `vault-newer-version` 16, the rest → `internal` 1 | 12 / 16 / 1 |
| 5 | `Store(_)` | delegate to the shipped `From<StoreError> for CliError` (`vault/store.rs:284-312`) | as mapped there |
| 6 | `Preview{source}` | `internal` | **1** |

The cut is *what the user does next*, which is the same test §3 R2 applies to
`verify`:

- **Group 1 — fix the command.** All eight refuse *what was asked* and each
  message already names the fix: use a different work-id, name at least one
  unit, select the whole file instead of a mirror id, finish the seal first,
  drop `--include-receipt`. The precedent is shipped and exact:
  `StoreError::WorkNotFound → CliError::Usage` with the message *"no work with
  this id exists in the vault (see `antseal list`)"* (`vault/store.rs:287-289`),
  which is U2's `usage` doing cross-validation work already. Minting a class
  per member would add codes a caller cannot act on differently.
- **Group 2 — retry later.** The transient class, D48 §6's floor.
- **Group 3 — one new class, and the only one.** These are the cases where
  something *disagrees with the manifest*: bytes that do not hash to their
  recorded address, ciphertext that will not open, a manifest that does not
  decode or does not belong to this work, a vault record that cannot drive a
  reveal, an anchor artifact that cannot be embedded, a builder refusal. No
  argv change and no retry fixes any of them. It is the reveal-side sibling of
  `restore-verification-failed` (35), and it sits at **36** — the first free
  code after restore's band and **outside U2's reserved 40–49**, because a
  reveal failure is not a bundle-verification verdict and the band's own
  wording forbids borrowing it.
- **Group 6 — `Preview` is documented as a defensive seam** (*"this module
  validates the selection and the path count first, so no input that reaches
  the preview can trip it"*). Reaching it is a bug, and `internal` is the bug
  class.

**Two flags for the implementer, recorded rather than silently absorbed:**

- `ReceiptBlockNumberUnknown` is classed `usage` on the message it carries
  (*"cannot be embedded **yet**"* — drop the flag). **U67 measured that "yet"
  to be permanent** for any work whose enrichment failed once. If U67 lands a
  production backfill host, the classification stays correct; if U67 is ever
  closed the other way, this row should be revisited, because "drop the flag"
  would then be the only remedy that exists forever.
- `Build` covers both R13's input validation *and* R13's mandatory self-check
  failing — the second is a bug (antseal built a bundle that does not verify).
  It is classed with group 3 rather than `internal` because a damaged input is
  the likelier cause and the user-facing consequence is the same; if `BuildError`
  is ever split, the self-check arm should move to `internal`.

---

## 6. Edges drawn explicitly

### 6.1 D48 — its severity order **extended**, its carriage **corrected**

**Extended, and adopted verbatim in shape.** §3 R3 is `FileStatus`'s fold with
a different rung set: declaration-order `Ord`, a success predicate, filter-then-`max`.
D48 §6's *"the reported class follows fixed severity"* is exactly the rule this
record applies to anchors, and R11's `LiveVerdict` doc supplies the grammar
both share.

**Corrected on carriage, and the correction is measured, not stylistic.** D48
§6 promises:

> *"Per-file detail always available in output and in the `--json` result
> (per-file status array; U20 fixture)."*

Under the two-arm machine that sentence is **unkeepable**: `into_error()`
returns a `CliError`, a `CliError` produces `error_envelope`, and
`error_envelope` has no `result` key. §1 (c) shows the house believed the
promise and committed a fixture — `json-envelopes.txt:34`, `ok:true` beside a
`verification-failed` row — that no build can emit.

**R1's third arm is what makes D48 §6 true**, and it applies to `restore`
identically: `RestoreOutput::into_error()` becomes
`RestoreOutput::exit_class()` returning `Option<ErrorClass>`, the human report
and the per-file JSON array render in full, and the run exits on the most
severe class present. D48's *rank* and its *classes* (30, 31, 35) are untouched;
only the destination of the fold changes. This is a product-behaviour change to
`restore` and is reported as a row in §9 (i) rather than assumed.

Note for whoever lands it: `restore`'s per-file human report already exists and
already renders; the change is that it is no longer *replaced* by a one-line
`error:` when a file failed.

### 6.2 D64 — binding on rendering, not on the exit code, and the trap named

D64 rules that the online overlay never overwrites the offline verdict, and
§1 (i) / §3 R5 show why that does **not** reach the exit code: the equality
D64 §6 states is over **report bytes**, and the inviolability D64 §2 states is
over the **offline block's rendering**. The exit code is neither.

The trap the brief names — *promotion to `proven` is exactly where a user
expects it to move* — is real, and the ruling resolves it in the user's favour
**because the spec does**: line 137's *"supplies the headline"* is spec text,
not gloss, and D64 §3 already built the Supplies-form headline a place. What
would be incoherent is the other answer: a run that prints an online-confirmed
headline and exits with the code for "no provable time".

The half of D64 that **is** binding here is the one nobody would think to
check: because the overlay's probe outcomes are structurally invisible to
`evaluate_anchors`, endpoint failure and disagreement cannot reach the exit
code at all. D64's containment is what makes this record's `--online` clause
safe.

### 6.3 D65 — the schema edge, drawn as D67 §5 drew it

**D69 owns**: which classes exist, their codes, the fold, which run's aggregate
feeds it, and that the class name + code are exposed on the machine surface
with `result.<slot>.exit_code == $?`.
**D65 owns**: field names, nesting, the envelope's verdict slot, and any
stability commitment. The `ok`-semantics restatement in R1 is handed to D65 and
U3 as an input, not pre-empted — it is a *documentation* change to
`machine.rs`'s module docs, not a schema change (no key is added, removed or
renamed; `ENVELOPE_VERSION` stays 1). *(**Answered YES, 2026-08-12** — see
"Amendment — the envelope question, answered by the maintainer, 2026-08-12"
below.)*

### 6.4 The error-code contract — a namespace note, not a namespace change

§3 R8 reserves the `verify-` stem against the code namespace and mints four
exit classes with it. `testdata/error-codes/v1/CODES.txt` is **not touched**:
these are exit-code classes, and `error-code-contract.md` §2 has already ruled
the two namespaces disjoint (28 class names, zero intersection — the count
becomes 33 with this record's five). The contract's near-miss list gains one
line (§10 edit 6) so the `anchor-gate-abort` register stays complete.

---

## 7. The tests that pin it, and where the table lives

**Doc home: `crates/antseal-cli/src/error.rs`'s module-doc table** — the house's
existing home, pinned literally by `tests/exit_codes.rs::TABLE`. No new
document is created; a second home is how tables drift.

1. **`ErrorClass` grows by five** (36, 40, 41, 42, 43). `ALL` goes 28 → 33; the
   module-doc table, `TABLE` in `tests/exit_codes.rs`, and the `class_index`
   exhaustive match (`error.rs:757-788`) all grow in the same change — that
   match exists precisely to force it, and it is a compile error otherwise.
2. **The reserved-band assertion must be amended in the same change.**
   `tests/exit_codes.rs`'s
   `codes_are_nonzero_distinct_and_avoid_reserved_ranges` (`:114-135`)
   currently asserts `!(40..=49).contains(&code)` (`:124-128`) for **every**
   class, with the message *"40–49 are reserved for U30's
   verification-verdict classes"*. It is correct today and
   becomes wrong the moment 40–43 are minted. It should narrow to: 40–43 are
   the verdict classes and are `verify-`-named; **44–49 remain forbidden**.
   Missed, this turns a correct change red for the wrong reason.
3. **The equality test (red-capable, the core of R7).** Spawn the binary over
   each golden bundle with `--json`; assert
   `process_exit_code == envelope.result.<verdict slot>.exit_code ==
   verdict_exit_rung(aggregate).code()`, and that `ok` is `true` in every case
   where a report exists. Red against any implementation that computes the code
   a second way.
4. **The rung table, exhaustive.** One case per rung plus 0, over
   `VerdictAggregate` fixtures built through `from_parts` (which exists for
   exactly this — *"for fixtures that need arbitrary states and times without
   minting artifacts"*, `verdict.rs:179-182`). Plus a sweep over
   `AnchorState::ALL` asserting the four ineligible non-`Invalid` states
   produce rung 3 when alone and rung-free when a `proven` anchor is present.
   The rung enum's match is wildcard-free, so a fourth rung breaks the build.
5. **The fold, over mixed sets** — the rule, not examples: `{proven, invalid}`
   → 41; `{proven, pending}` → 0; `{proven@T, proven@T+49h}` → 42;
   `{pending, attested}` → 43; `{invalid}` → 41 (rungs 1 and 3 both hold; 1
   wins); `{}` → 43.
6. **The `--online` triple** (mock endpoints, R21's harness): promotion
   43 → 0; agreed refutation → 41; **probe failure and endpoint disagreement →
   the code is byte-for-byte the offline run's**, asserted beside D64's
   existing report-byte equality so the two travel together.
7. **`--live` never moves it**: one bundle, three live outcomes
   (match / mismatch / fetch-failed) against `MockBackend`, one exit code.
8. **Tamper**: every tamper-matrix row through `antseal verify` exits **40**,
   and its distinct `VerifyError::code()` appears in the message — the wave
   rule *verify a failure by its message, never by exit code alone*, made a
   test. This is the one place the two namespaces meet, and the test is what
   keeps 40's coarseness honest.
9. **`reveal`** (U28's suite): one exemplar per `RevealError` variant → its
   class, in the `exit_codes.rs` exemplar style, so all 23 are pinned and the
   new class's `Display` joins `tests/snapshots/cli-errors.display.txt`.
10. **U3 fixture**: `verify` registers its `--json` result fixture (U30's
    Accept already requires it) — including at least one **nonzero-exit
    success envelope**, which is the shape R1 creates and which nothing in the
    tree exercises today.

---

## 8. Consumed rows and inputs

- **U2** (`tasks/U.md:21-31`) — its `Notes` line *"Verify-verdict exit mapping
  is deferred to U30 (open decision)"* is discharged; its 40–49 reservation is
  honoured and consumed; its ownership of identifiers is preserved (R1).
- **U30** (`tasks/U.md:499-511`) — *"Finalize the verdict-class → exit-code
  mapping (open decision 13) so CI/scripts can gate on results"*; Accept rows 1
  and 3 are the specification this table serves.
- **U3** (`tasks/U.md:33-45`) — the envelope; the `ok` restatement is its
  documentation to carry.
- **R21** (`tasks/R.md:254-266`) — *"verdict-class data is exposed for U30's
  exit-code mapping (the mapping itself is U30's, per D69)"*; R4's classifier
  is what it exposes.
- **R16** (`tasks/R.md:193-201`; `TODO.md`'s R16 row) — the deliberate
  deferral *"no `CliError` mapping (U28's, no exit-code ruling exists)"*,
  closed by §5.
- **R17/R18** (`verdict.rs`, `wording.rs`) — the aggregate and the frozen
  wording the rungs coarsen; neither is changed.
- **D48** (severity order extended, carriage corrected), **D64** (overlay
  containment; the `--online` clause), **D65** (schema edge), **D51**
  (invariant 2), **D100/D98** (the `status` precedent, §4), **D27/D29/D105**
  (report frozen; nothing here touches it), **D34** (placement), **U67** (§5's
  first flag).
- **MVP-SPEC.md** lines 38, 108, 110, 116–119, 127–137, 149, 156, 174.
- `docs/testing/error-code-contract.md` §2 (the two-namespace rule).

---

## 9. Discovered work — described, not registered

No ids are minted here.

**(i) PRODUCT — the registered `restore` `--json` fixture documents an envelope
no build can emit.** `crates/antseal-cli/tests/machine_mode.rs:409-411` wraps a
`RestoreOutput` containing `refused-overwrite` and `verification-failed` rows in
`success_envelope`, producing `json-envelopes.txt:34` with `"ok":true`. D48 §3
requires that run to exit nonzero, and `main_entry` emits `success_envelope`
**only** at exit 0. It is latent today because `commands::restore` is the U36
seam stub and `RestoreOutput::into_error()` has no production caller (measured:
callers are eight lines in `tests/restore_output.rs` and nothing else) — so
U20's wiring will hit the fork with no ruling in place, and the cheapest
resolution at that moment is to drop the per-file array, which is the half D48
§6 promised to keep. **Fix**: §6.1's `exit_class()` third arm; the fixture then
becomes producible exactly as committed, at a nonzero code. This is a product
defect (it changes what a user's `restore --json` returns) and is offered to
the registrar for an id.

**(ii) INSTRUMENT — `tests/exit_codes.rs`'s reserved-band assertion is a
correct guard that will fail for the right reason at the wrong time.**
`codes_are_nonzero_distinct_and_avoid_reserved_ranges` (`:114-135`, assertion
at `:124-128`) forbids 40–49 to every class; the first correct implementation
of this record turns it red. Flagged here so the amendment (§7.2) rides the same
change rather than being discovered as a mystery failure. Ledger material.

**(iii) INSTRUMENT — `reveal-` vs the code universe's `revealed-` stem.** §1 (h)
measured 23 code prefixes, one of which is `revealed` (`revealed-unit-file-not-touched`).
`reveal-inputs-unusable` lives in the disjoint exit-class namespace and is not a
collision, but it is the fourth `path-commit-mismatch`-kind near-miss that
document tracks and the second *across* namespaces. Q77 is the row that would
machine-check it. Ledger material.

**(iv) OBSERVATION — U30's Accept row 3 (`"--live` without network → clean
error"*) and R6 are reconcilable but not identically worded.** §3 R6 reads
"clean error" as *the message is clean and the verdict is unaffected*, not *the
exit code is the live layer's*. §11.2's quoted note makes that reading explicit
in the entry so a later implementer does not re-derive the opposite. Not a
defect; a wording sharpening the registrar can land with the entry note.

---

## 10. Registrar's edit set

**This lane wrote one file: this one.** Everything below is instruction.

1. `TODO.md` decision register, the **D69** line (Due M3 block, `TODO.md:915`)
   — replace with the resolved line in §11.1.
2. `docs/decisions/README.md` — one index row for this record, in id order,
   status and date taken from this record's own `- **Status`/`- **Date` lines
   (D119 conventions).
3. `tasks/U.md` **U2** — replace the `Notes` line per §11.2.
4. `tasks/U.md` **U30** — append the `Notes` line per §11.3; its `Do` sentence
   *"Finalize the verdict-class → exit-code mapping (open decision 13)"* stays
   as written and is now discharged by reference.
5. `tasks/U.md` **U3** — append the one-liner per §11.4 (`ok` semantics).
6. `tasks/U.md` **U28** — append the one-liner per §11.5 (reveal's mapping).
7. `tasks/R.md` **R21** — optional one-liner per §11.6.
8. `docs/testing/error-code-contract.md` §2 — one line in the near-miss /
   reserved-spellings paragraph: the `verify-` stem is reserved against the code
   namespace, and U2's class count becomes 33 (§6.4). No code is added,
   removed or renamed; `CODES.txt` is untouched.
9. **No edits** to `MVP-SPEC.md`, `docs/format/registry-v1.md`, any golden
   vector, `REPORT_VERSION`, or `ENVELOPE_VERSION` are requested by this
   ruling. Zero frozen bytes move.
10. §9 (i) is offered as a **row**; §9 (ii) and (iii) as **ledger** entries.

---

## 11. Quoted entry notes (registrar's to apply)

### 11.1 `TODO.md` D69 register line

> - [x] **D69** Verify exit-code mapping per verdict class (UNANCHORED = 0 or
>   distinct nonzero?) (U2/U30) — **Resolved 2026-08-12**
>   (docs/decisions/D69-verify-exit-code-mapping.md): **the FRAMING is
>   overturned; the UNANCHORED sub-answer survives ON MEASUREMENT as one rung
>   of four.** There is no scalar verdict to map — `verify_bundle` returns
>   `Result<Report, VerifyError>` and the `Ok` arm carries a `Vec<AnchorResult>`
>   of independently-stated states (mixed sets are exercised in the shipped A1
>   suite) — and the binding constraint is **carriage**, not numbering: shipped
>   `main_entry` has two arms, so any nonzero exit today emits `ok:false` with
>   **no `result` at all**. Ruling: a **third arm** (`Outcome.exit_class:
>   Option<ErrorClass>`; `ok` = "a result document is present"; `ENVELOPE_VERSION`
>   stays 1), then **D48 §6's severity fold extended** over the anchor set —
>   `verify-bundle-rejected` **40** (the `Err` arm; tamper and malformed are ONE
>   class, the 248 rejection codes ride in the message per the two-namespace
>   rule) > `verify-anchor-refuted` **41** > `verify-headline-divergence` **42**
>   > `verify-unanchored` **43** > **0**. Rungs 2/3 are mutually exclusive by
>   construction; `{proven, invalid}` → 41 by the rule, not by a list.
>   **UNANCHORED is nonzero, and distinct so a script can opt back in** — the
>   `status`-exits-0-on-`invalid` precedent (D100 R6) is confined by its own
>   reason (*a fact about the vault*) to a sealer-facing command, spec line 137
>   mandates a **loud** banner that exit 0 would silence for every non-human
>   consumer, and line 137's minimum-anchor guarantee means a normal seal never
>   reaches the rung. **`--online` MAY move the code, all three directions**
>   (43→0 promotion per line 137's *"supplies the headline"*, →41 agreed
>   refutation, 0→42 newly-flagged divergence) — D64 is untouched because its
>   equality is over **report bytes** and its inviolability over the **offline
>   block's rendering**, neither of which an exit code is — and **probe failure
>   / disagreement cannot move it, as a theorem** off `OnlineBlockResult`'s
>   missing failure variant. **`--live` and storage-linkage never move it**
>   (line 118). `--json` cannot disagree: ONE core-side classifier over the same
>   aggregate that serializes, `result.exit_code == $?` assertable. **D48 §6's
>   carriage is CORRECTED** — its own *"per-file detail always available in the
>   `--json` result"* is unkeepable via `CliError`, and the committed
>   `restore` fixture proves the house believed it (row minted). **`reveal`'s 23
>   `RevealError` variants mapped** (R16 left them here): shipped classes plus
>   exactly one new — `reveal-inputs-unusable` **36**, outside U2's reserved
>   40–49 by construction. `verify-` stem reserved against the code namespace.
>   Zero frozen bytes; `REPORT_VERSION` and `ENVELOPE_VERSION` unchanged

### 11.2 `tasks/U.md` U2 — replace the `Notes` line

> - Notes: Verify-verdict exit mapping ruled 2026-08-12 by **D69**
>   (docs/decisions/D69-verify-exit-code-mapping.md), which consumes the
>   reserved 40–49 band as **40** `verify-bundle-rejected` (the `Err` arm of
>   `verify_bundle` — tamper and malformed are one class; the specific
>   `VerifyError::code()` rides in the message, never in the integer), **41**
>   `verify-anchor-refuted`, **42** `verify-headline-divergence`, **43**
>   `verify-unanchored`, with **44–49 still reserved** (reasons in D69 §3 R9)
>   — and adds **36** `reveal-inputs-unusable` **outside** the band, because a
>   reveal failure is not a bundle-verification verdict. `ErrorClass::ALL` goes
>   28 → 33; the module-doc table, `tests/exit_codes.rs::TABLE` and
>   `class_index` move together (compile-forced), and
>   `codes_are_nonzero_distinct_and_avoid_reserved_ranges` must narrow its
>   `!(40..=49)` assertion to 44–49 in the same change or it fails for the
>   wrong reason. D69 also adds the **third arm** the table needs:
>   `commands::Outcome` carries `exit_class: Option<ErrorClass>` so a nonzero
>   exit can still emit the success envelope — `ok` means "a result document is
>   present", not "exit 0". Class names remain U2's to finalize; D69 fixes the
>   partitions and the rank.

### 11.3 `tasks/U.md` U30 — append a `Notes` line

> - Notes: **[D69, 2026-08-12]** Open decision 13 is closed
>   (docs/decisions/D69-verify-exit-code-mapping.md). Exit code = the
>   severity-ordered rung over the **whole anchor set** —
>   `verify-anchor-refuted` (41) > `verify-headline-divergence` (42) >
>   `verify-unanchored` (43) > 0 — with `verify-bundle-rejected` (40) on the
>   `Err` arm of `verify_bundle`, one class for every rejection code. **UNANCHORED
>   is 43, deliberately nonzero and deliberately distinct** so a caller who
>   accepts undated bundles can opt back in. The rung is computed by **one**
>   core-side pure function over the same `VerdictAggregate` that serializes
>   into `--json`, and `result.<verdict slot>.exit_code == $?` is an asserted
>   equality (field names/stability stay D65's). `--online` **does** move the
>   code — promotion 43→0, agreed refutation →41, newly-flagged divergence
>   0→42 — and probe failure or endpoint disagreement **cannot**, structurally
>   (D64/D56: `OnlineBlockResult` has no failure variant, so the augmented
>   verdicts equal the offline ones). Accept row 3's *"`--live` without network
>   → clean error"* is satisfied **by the message**: the full offline verdict
>   still renders, the live section reports R11's `Inconclusive`, and neither
>   `--live` nor storage-linkage may ever move the exit code (spec line 118 —
>   *"storage is the product's bonus, not its proof"*); only a build that
>   cannot attempt `--live` at all refuses at the backend seam as
>   `network-failure` (23), before verification. Requires U2's third arm
>   (`Outcome.exit_class`) so a nonzero verdict still emits `ok:true` + `result`.

### 11.4 `tasks/U.md` U3 — append a one-liner

> - Notes: **[D69, 2026-08-12]** The envelope's `ok` field means **"a `result`
>   document is present"**, not "the exit code is 0". The two were coincident
>   until M3 and are separated deliberately: `verify` reports a bad verdict at a
>   nonzero code while still emitting its full result (D69 §3 R1). No key is
>   added, removed or renamed and the U2 error object is untouched, so
>   `ENVELOPE_VERSION` stays **1**; the module docs in `machine.rs` carry the
>   restatement, and D51 invariant 2 (same code in both modes) is preserved
>   because the code is computed before the mode branch. `verify`'s registered
>   fixture must include at least one **nonzero-exit success envelope** — the
>   shape nothing in the tree exercises today.

### 11.5 `tasks/U.md` U28 — append a one-liner

> - Notes: **[D69, 2026-08-12]** `From<RevealError> for CliError` is this row's
>   to write, and D69 §5 fixes the classes it must produce for all 23 variants:
>   **`usage` (2)** for the eight request-shaped refusals (unknown work/unit id,
>   empty selection, bare mirror id, work not complete, and the three
>   `--include-receipt` refusals) — the shipped `StoreError::WorkNotFound →
>   Usage` precedent; **`network-failure` (23)** for the two fetch failures;
>   **`reveal-inputs-unusable` (36, new)** for the ten cases where a manifest,
>   record, ciphertext or anchor artifact disagrees with the manifest and no
>   argv change or retry fixes it; **delegate** `AnchorsUnreadable` to the
>   existing `From<JournalError>` (preserving D100's `NewerRecord` ≠ `Corrupt`)
>   and `Store` to the existing `From<StoreError>`; **`internal` (1)** for the
>   documented-unreachable `Preview` seam. One exemplar per variant in the
>   `exit_codes.rs` style; the new class's `Display` joins
>   `tests/snapshots/cli-errors.display.txt`.

### 11.6 `tasks/R.md` R21 — optional one-liner

> - Notes: **[D69, 2026-08-12]** The "verdict-class data" this row exposes is
>   D69's rung classifier: a pure, WASM-safe `antseal-core` function over
>   `VerdictAggregate` **plus a refuted-slot count** — `VerdictAggregate`
>   carries no state field and matches on `AnchorState` nowhere (R17's
>   one-predicate rule), so counting `invalid` slots is a second pass over
>   `AnchorVerdicts` and must stay one, rather than becoming an aggregate
>   field. It lives in core, not the CLI, so R22's page can state the same rung
>   and R27's parity gate has something to compare. Under `--online` the rung is
>   computed over the **online-augmented** aggregate (D69 §3 R5); the offline
>   report bytes stay byte-identical either way, so this row's D64 equality is
>   unaffected.

---

## Outcome

The register filed this as a mapping question with one interesting corner. The
mapping is the easy half: three rungs and a rejection class, folded by the same
severity rank D48 already froze and R11 already stated the grammar for. The
corner the framing named — UNANCHORED — turns out to be settled by two spec
sentences read together: the banner is **loud**, and a normal seal never
reaches it, so the rung is both obligatory and rare.

What the framing missed is that `antseal verify` has no scalar to map and no
place to put a nonzero answer. The seven states are a **set**, and the shipped
process has exactly one lever, welded to an error type that displaces the very
document the exit code is a summary of. The house already stepped on this once:
D48 promised per-file detail in the `--json` result and committed a fixture
showing it, and no build can emit that fixture. `verify` would have been the
second command to hit it, on a surface where the lost document is the product's
whole output.

So the ruling is a third arm before it is a table — a nonzero exit that still
carries its result — and everything after that is forced. One classifier over
one aggregate makes the integer and the document incapable of disagreeing.
D64's containment of the online overlay, which was written for rendering, turns
out to guarantee something stronger for free: a network outage **cannot** change
this command's exit code, because the type that would carry the failure was
deliberately never given a variant to put it in.

---

## Amendment — the envelope question, answered by the maintainer, 2026-08-12

**Authority**: the maintainer, in session 2026-08-12, answering the one question
§3 R1 rules and §6.3 hands on to D65/U3 as an input rather than pre-empting.
**Same-act disclosure (D117 §2.1 (c))**: this section lands in the same act as
the record it amends. It adds no ruling; it records that the ruling's one
open-to-another-owner clause was confirmed rather than left to be re-litigated.

The clause, quoted verbatim from §6.3:

> The `ok`-semantics restatement in R1 is handed to D65 and U3 as an input, not
> pre-empted — it is a *documentation* change to `machine.rs`'s module docs, not
> a schema change (no key is added, removed or renamed; `ENVELOPE_VERSION` stays
> 1).

**Answered YES.** `ok:true` is re-read as **"a result document is present"**,
not "exit 0". Confirmed with it, explicitly:

- **no key is added, removed or renamed** — the envelope stays
  `{v, command, network, ok, result|error}` and the U2 error object stays
  `{class, exit_code, message}`;
- **`ENVELOPE_VERSION` stays 1** — the change is to what the field *means* in
  the module docs, not to the document's shape, so it is not the
  machine-interface event `machine.rs:64-66` reserves a bump for;
- `ok:false` continues to mean exactly *`error` is present and `result` is not*.

D65 §3 tier B is unaffected — no key in the wrapper is renamed, removed, retyped
or moved — and D65 §5.2, which reached the same definition independently from
D27 §4's *"a report exists only for a bundle that passed"*, agrees with it
rather than needing reconciliation.

**Which rulings stand**: all nine. The answer confirms the premise §3 R1's third
arm rests on, so R2's table, R3's fold, R5's `--online` clause, R6's `--live`
exclusion and §5's `reveal` mapping are untouched. The one consequence worth
naming is downstream and already registered: the third arm is what makes D48
§6's own *"per-file detail always available … in the `--json` result"* true, and
the `restore` half of that correction is row **U69**.
