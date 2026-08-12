# D65 — `--json` schema stability: the commitment level at M3, its version's scope, and what a scripter may gate on

- **Status: RESOLVED — the register's lean, "promise a stable versioned JSON
  schema from M3", is OVERTURNED as a blanket and REPLACED by a three-tier
  partition that gives a scripter *more* than the lean asked for on the tier
  that matters.** The blanket is unpayable at M3 on three measurements: the
  document that would carry it does not exist (no `--json` *schema* text
  anywhere outside decision records — `docs/testing/error-code-contract.md`
  documents the error-code namespace and nothing else), the
  check that would enforce it is **U32's**, at M4, by U32's own words
  (*"snapshot baselines become compatibility promises"* / *"CI schema-freeze
  check active"*), and the instrument that exists — a whole-document byte
  snapshot regenerable with `ANTSEAL_BLESS=1` — returns the **same red** for an
  added key and a renamed one, so nothing in the tree can currently tell an
  additive change from a breaking one. But the opposite arm (*"declared
  unstable until M4"*) is refused too, and refused on a string the binary
  already prints: `CliError::NotImplemented`
  (`crates/antseal-cli/src/error.rs:407-410`) tells every user of `show`,
  `reveal` and `verify` that *"the command surface is frozen from day one **so
  scripts written today keep parsing**"*. So the ruling is a partition:
  **(A) the `report` member of `verify --json` is carried BYTE-VERBATIM and is
  therefore already frozen harder than M4 could freeze it** — 21 committed
  golden vectors, a native↔wasm32 bit-match, and `REPORT_VERSION`'s coupled-edit
  discipline; **(B) the envelope wrapper is STABLE-ADDITIVE from M3**, versioned
  by the `ENVELOPE_VERSION` that is already in force and already exact-key-set
  asserted; **(C) everything else inside `result` is DECLARED UNSTABLE until
  U32**, reviewed by the snapshot but promised to nobody. **`REPORT_VERSION` is
  not, and never becomes, a `--json` schema version** — it versions a
  determinism artifact shared with a second implementation, and a
  scripting-convenience field that moved it would cost 21 vector re-emits.
  **The measurement that forces the carriage rule**: `success_envelope`'s only
  signature takes a `serde_json::Value`
  (`crates/antseal-cli/src/machine.rs:220-233`), `serde_json::Map` is a
  `BTreeMap` in this build (no `preserve_order` in any manifest or in
  `Cargo.lock`), so routing the report through `Value` **sorts its keys
  alphabetically and destroys D29 rule 1's declaration order** — and the tree
  already demonstrates exactly this on itself, carrying the same report twice
  in the frozen vector document under two different key orders, with
  `vectors_report.rs:23-27` recording why.
- **Date: 2026-08-12** (wave 18, Act 1, D65 planning lane; briefed to overturn
  the register's stable-from-M3 lean. The lean is overturned as a blanket and
  its *concern* — that scripts need something to gate on from M3 — is measured
  satisfiable today at zero cost, on a narrower and stronger surface than the
  lean named.)
- **Owning tasks: U30** (emits the document; gains the carriage Accept row and
  the tier table), **R21** (produces the members U30 carries; its D64
  report-byte-equality row is upgraded from *equal to each other* to *equal to
  what U30 prints*), **U3** (the framework and the fixture registry this rules
  over), **U32** (M4 — inherits the partition and freezes tier C),
  **U50** (its second half — *"decide whether it falls under D65's stability
  commitment"* — is answered in §9.2). Register entry: the D65 row under
  `TODO.md` "Due M3".
- **Amends**: `tasks/U.md` U30 (Accept rows quoted in §11.2), `tasks/R.md` R21
  (Accept row quoted in §11.3), `tasks/U.md` U50 (Do/Accept, §11.4).
  **Supersedes**: nothing. **Corrects**: nothing ruled — one live doc paragraph
  (`crates/antseal-cli/src/listing.rs:63-69`, *"D65 is not in force"*) becomes
  false the moment this record lands and is on the edit set (§11.5).
- **Method**: read/grep only. No build was run (the main session holds the
  gate); every claim below is a file:line, a pasted command output, or a
  verbatim quotation. Code line numbers are snapshots taken while sibling lanes
  were active — cite them as of this record's date. The frozen registry is
  cited by section only.

---

## 1. What was measured

### (a) The `--json` surface already has a version, and it is not the report's

`crates/antseal-cli/src/machine.rs:64-66`:

```rust
/// Envelope schema version. Bumping it is a machine-interface event:
/// committed fixtures, this doc, and consumers move together.
pub const ENVELOPE_VERSION: u32 = 1;
```

It is emitted as `"v"` by all three envelope constructors (`machine.rs:225`,
`:237`, `:250`). The tree already records that this — not D65 — is the contract
in force, at `crates/antseal-cli/src/listing.rs:63-69`:

> Adding `nag` to the `--json` row is permitted now: **D65 is not in
> force.** It has no `docs/decisions/D65-*.md`, its register row is
> unchecked under "Due M3", its own text scopes it *"from M3"*, and U50
> exists to draw its scope (D98, "smaller measured facts"). The in-force
> machine contract is `ENVELOPE_VERSION`, about the envelope wrapper.
> Recorded here so a future reader does not re-derive it.

So the lean's premise is **half already true**. What is missing is not a
version; it is a **scope**. `ENVELOPE_VERSION` versions the wrapper — `v`,
`command`, `network`, `ok`, and `result`|`error` — and nothing versions or
asserts the interior of `result`.

### (b) Exactly what is asserted today, and exactly where it stops

`crates/antseal-cli/tests/machine_mode.rs:908-937`
(`every_command_has_a_registered_fixture_with_the_v1_shape`) asserts an
**exact key set**, twice, and only twice:

```rust
assert_eq!(keys, ["command", "error", "network", "ok", "v"], "{name}");
…
assert_eq!(ekeys, ["class", "exit_code", "message"], "{name}");
…
assert_eq!(keys, ["command", "network", "ok", "result", "v"], "{name}");
```

`result`'s interior is asserted by **nothing** in that test. Its only pin is
`envelope_fixtures_match_the_committed_snapshot` (`machine_mode.rs:881-901`), a
whole-file string equality against `tests/snapshots/json-envelopes.txt`,
regenerable with `ANTSEAL_BLESS=1` and failing with *"the JSON envelope drifted
from the committed fixture … machine-interface changes are reviewed, versioned
events"*.

**That instrument is a review gate, not a compatibility gate.** It goes red for
an added key and red for a renamed key, with the same message. **A promise the
tree cannot tell from its own violation is not a promise** — and that sentence,
not the calendar, is the strongest argument against a blanket M3 stability
commitment.

### (c) The two shape assertions the house already invented, without naming them

Two tests do have the right shape for a *stable-additive* rule — silent on
additions, red on removals and renames:

- `crates/antseal-cli/tests/restore_output.rs:526-560`
  (`the_json_document_carries_per_file_status`): a key list checked with
  `row.get(key).is_some()`.
- `crates/antseal-cli/tests/list_command.rs:350-376`
  (`the_json_document_carries_the_full_record_set`): the same pattern over
  `works[]`.

`Map::get` returns `Some(&Value::Null)` for a `null`, so this pattern asserts
*"the key is always there"* while tolerating new siblings. It is exactly the
enforcer tier C needs, it exists twice, and it exists for two of the seven
commands that emit a `result` document.

### (d) The `--json` surface today: seven commands, nine documents, zero interior versions

`tests/snapshots/json-envelopes.txt` (38 lines): ten error envelopes, one per
canonical command, and nine success documents — `init`, `list`, `status`,
`seal` (completed), `seal --dry-run`, `seal --dry-run` over a resumable work,
`restore`, `vault export`, `vault import`. `show`, `reveal` and `verify` are
`not-implemented` stubs. Producer sites: `init.rs:234`, `listing.rs:614` +
`row_json:1057`, `status.rs:608` + `verdict_json:741`, `seal_run.rs:220` +
`:307`, `seal_consent.rs:195`, `restore_out.rs:235`,
`pipeline/anchors.rs:607`, and two inline `serde_json::json!` literals in
`commands.rs:467` and `:516`. **No document carries a version field of its
own.** The only version anywhere in a `--json` document today is the
envelope's `v`.

### (e) `REPORT_VERSION` is a different animal, and the tree spells out what a bump costs

`crates/antseal-core/src/verify/report.rs:102` — `pub const REPORT_VERSION: u32
= 1;` — under a doc (`:66-101`) headed *"Coupled edits — everything a future
bump must carry with it"*: **all 21** pinned byte strings in
`testdata/vectors/v1/report/verification-reports.json` change at once, plus
D29's fixed-fixture snapshot `EXPECTED_CANONICAL_JSON`, with the third item
being that `wasm-bitmatch`'s transcript version is *not* coupled. D105 §2.4
gives the mechanical test for what moves it (a field on any of the eight named
structs; a variant is a value addition and does not).

So `REPORT_VERSION` versions an artifact with two properties no CLI document
has: it is **pinned in frozen vectors retained indefinitely**, and it is
**consumed by a second implementation** — R22 hands the page the same bytes,
and Q5 requires wasm32 to bit-match native. Conflating it with a `--json`
schema version would mean a scripting-convenience key costs 21 vector re-emits.

### (f) The carriage measurement — the report cannot survive the envelope's only signature

`crates/antseal-cli/src/machine.rs:220-233`:

```rust
pub fn success_envelope(
    command: &str,
    network: &str,
    result: serde_json::Value,
) -> serde_json::Value {
```

`serde_json::Map` is backed by a `BTreeMap` unless `preserve_order` is enabled
— measured in the vendored pin, `~/.cargo/registry/src/index.crates.io-…/
serde_json-1.0.151/src/map.rs:3` (*"By default the map is backed by a
[`BTreeMap`]"*, with the `#[cfg(feature = "preserve_order")]` switch at `:23`
and `:33`) — and `preserve_order` appears in **no** workspace manifest and in
**no** `Cargo.lock` entry:

```
$ rg -n "preserve_order" Cargo.lock Cargo.toml
(no output)
```

The committed fixture confirms the consequence: every `json!`-built document in
`json-envelopes.txt` is alphabetized (`{"command":…,"error":…,"network":…,
"ok":…,"v":1}` — `v` last).

**The tree already demonstrates the loss on the report itself.** The frozen
vector document carries the same report twice, and the two disagree:

```
$ python3 -c "import json,binascii; d=json.load(open('testdata/vectors/v1/report/verification-reports.json')); c=d['expect']['cases'][0]; print(list(c['report'].keys())); print(binascii.unhexlify(c['report_json']).decode()[:70])"
['anchors', 'evidence', 'report_version', 'reveal', 'storage_linkage', 'supporting_evidence', 'work']
{"report_version":1,"work":{"work_id":"057b41b0c960a606ebe2126b83fd9adc
```

and `crates/antseal-core/src/test_util/vectors_report.rs:23-27` records why in
so many words:

> `report` and `report_json` cannot drift: the executor decodes the hex and
> requires the two to agree. Only `report_json` pins **field order** (a JSON
> object compares order-insensitively, and D29 rule 1 makes declaration order
> the wire order), so the hex is the authority and the object is the reader's
> copy.

**So the obvious U30 implementation —
`success_envelope(…, json!({"report": serde_json::from_slice(&report.to_canonical_json()?)?, …}))`
— emits a document whose report is not the canonical report.** R21's D64
Accept row would stay green (it compares the *library's* bytes across two runs),
R22 would return the real bytes to the page, and the two surfaces would disagree
byte-wise on the same report while both "containing it". Nothing in the tree
would go red.

### (g) D64 already fixed the envelope's membership, and handed the shape question here

D64 §6, verbatim: the overlay *"rides U30's `--json` envelope **beside** the
verbatim report bytes (status.rs's U3 wrap pattern; **envelope schema stability
is D65's**, not pre-empted here)"*; the live section (R11's `LiveCheckReport`)
*"stays a third sibling, CLI-only"*. R11's own execution note (`tasks/R.md`
§R11) is the precedent: `LiveVerdict` *"never enters `REPORT_VERSION` bytes, and
R20/R21 render it in its own section where it stays advisory."*

So `verify --json`'s `result` has at least three members and its own shape
question, which is the one this record answers.

### (h) U32 owns the freeze, and it is M4

`tasks/U.md` U32 Do: *"freeze and document the exit-code table, **every
`--json` schema**, and all help text (**snapshot baselines become
compatibility promises**)"*. Accept: *"exit-code and JSON schema docs shipped
with the release; **CI schema-freeze check active**"*. Deps: `U1–U30`.

And there is no release: `Q34` is the M4 release gate and is unstarted
(`TODO.md:29`, `:68`) — the same ground D105 §4.1 relied on (*"No release exists
(Q34 is unstarted), so no deployed consumer can break"*).

### (i) There is no document of the `--json` *schema* anywhere — and exactly one normative doc that touches the surface

```
$ rg -l -e '--json' docs/ README.md CONTRIBUTING.md MVP-SPEC.md | sed 's|docs/decisions/.*|docs/decisions/*|' | sort | uniq -c
     24 docs/decisions/*
      1 docs/testing/error-code-contract.md
      1 docs/waves/wave-18-brief.md
      1 MVP-SPEC.md
```

`docs/` has no CLI directory; `README.md` and `CONTRIBUTING.md` contain zero
occurrences. `MVP-SPEC.md` mentions `--json` exactly once, at line 149, as a
global flag in the canonical surface list — **it states no schema, no
stability, and no version.** And spec line 123's only format-stability promise
is scoped elsewhere: *"every released **manifest/bundle** format version remains
verifiable by all future CLI and page releases"*. The spec neither grants nor
forbids a `--json` promise; D65 is free space bounded only by the tree's own
commitments.

The one non-decision normative doc, **`docs/testing/error-code-contract.md`**,
documents the *error-code namespace*, not the `--json` schema — but it makes
three statements this record is bound by, and one it cannot honour:

- **`:19-21`** — *"The code is the machine-readable name of the failure: tamper
  rows bind to it, **`--json` output carries it**, and third-party verifiers
  compare against it. **The `Display` text may be reworded freely; the code may
  not.**"* The second sentence is a stability statement about the error object
  and is adopted verbatim by §3 tier B. The first is measured **false** of
  envelope v1 — see §1m.
- **`:326-327`** — U2's `ErrorClass` is *"a committed table of kebab-case class
  names, each with a fixed exit code, **carried as the `class` field of the U3
  `--json` envelope**"*.
- **`:368-373`** — *"a `--json` consumer reads `error.class`, a verdict/tamper
  consumer reads the code, and a program that treats the two fields as one
  namespace is reading the contract wrong"* — **machine-checked** since Q77 by
  `crates/antseal-cli/tests/namespace_disjointness.rs`.
- **`:105-110`** — a **second copy** of the `decode_layer` conditional Q14's
  gate block also carries (§1l). Both resolve under §9.1.

### (j) Null, key order, and number formatting, as the code actually does them

- **Absence is `null`, everywhere, already.** Measured across every success
  document in `json-envelopes.txt`: `"detail":null`, `"failure_class":null`,
  `"raw_mirror":null`, `"resume":null`, `"upgrade":null`, `"title":null`,
  `"bytes":null`, `"source":null`, `"keyfile":null`, `"prior_consent":null`.
  Not one key is conditionally absent. On the report side this is D29 rule 4 as
  law (*"`skip_serializing_if` is banned … absence is expressed by `null`"*);
  on the CLI side it is universal practice with no rule written down.
- **No floats.** D29 forbids them in the report (*"no floats — integers and
  strings only"*); `rg -n "f64|f32"` over `crates/antseal-cli/src/` and
  `crates/antseal-core/src/verify/` returns nothing.
- **Large integers are decimal strings**, deliberately: `machine_mode.rs:436-438`
  — *"The cost is a real-shaped atto-ANT value (18 decimals — past what a JSON
  number survives, which is why the field is a decimal string)"* — and
  `list_command.rs:345-348` says the same for the same reason
  (*"amounts ride as exact decimal strings, because atto-ANT does not survive a
  JSON number in most consumers"*).
- **Times split by provenance, and the split is principled.** Report v1 carries
  three time-shaped fields in two JSON types:
  `verified_time_unix: Option<i64>` — a **number** (`report.rs:551`, *"populated
  only for time-proving states … Integer per D29's no-floats rule"*);
  `fetch_date: Option<String>` and `claimed_time_informational_only:
  Option<String>` — **strings** (`report.rs:609`, `:267`). `fetch_date`'s doc
  (`report.rs:576-593`) gives the reason: *"**Sealer-written and bound by
  nothing** … The form is `u64::to_string()` — decimal POSIX seconds … the same
  spelling `WorkMetadata::claimed_time_informational_only` froze at Q14 over
  the same kind of value."* The discriminant is **verifier-derived vs
  sealer-recorded**, and it is visible in the JSON type.
- **Key order is contractual in one region of the document and incidental in
  the other.** Inside the report member it is D29 rule 1 and is pinned by 21
  vectors. Outside it, it is alphabetical because a transitive dependency's
  default feature set makes `serde_json::Map` a `BTreeMap` (§1f) — a fact no
  decision chose.

### (k) The report's value space cannot grow silently, but it can grow

Q127 gave every report enum the triple `AnchorState` had: a `const ALL`, a
wildcard-free `wire_name()` (a new variant is a **compile error**), and a sweep
comparing the ordered spelling list against a hand-written literal
(`report.rs:993-1024` and siblings), whose failure message is *"the
signature-scheme value space moved; a new value must be written down here and
rendered in a whole report (R-VAL)"*. So a new state spelling is a deliberate,
reviewed, test-editing change — never a silent one. It is nonetheless a change
a `case` statement in a shell script will route to its `*)` arm, and D105 §2.4
permits it with **no version moving anywhere**.

### (l) The Q14 gate left D65 a named conditional

`tasks/Q.md:265-269`, the format-freeze gate's report-scope block:

> **The decode layer is never a report field (D86, permanent).** … If U30's
> `--json` **failure** envelope carries it (D65's call, M3), the field is named
> `decode_layer` and lives outside `VerificationReport`.

Answered in §9.1.

### (m) The tamper code is machine-unreachable in envelope v1

The error object is exactly `class`/`exit_code`/`message`, asserted exactly
(`machine_mode.rs:925-927`), and the two identifier fields are U2's `ErrorClass`
and its exit code. The verifier's `code()` — the kebab identifier MVP-SPEC line
168's tamper matrix binds to, the one *"the `Display` text may be reworded
freely; the code may not"* protects — has **no slot**. It reaches a `--json`
consumer only inside `message`, which the same paragraph declares freely
rewordable. So `error-code-contract.md:19`'s *"`--json` output carries it"* is
not true of the surface that exists, and `namespace_disjointness.rs` forbids the
obvious workaround of spelling the code into `class`. Consequence in §9.3.

---

## 2. The lean, taken to measurement

**Lean**: *antseal should promise a stable, versioned JSON schema from M3 so
scripts can gate on it.*

**Overturned as a blanket, on four measurements.**

1. **It would be a promise about documents nobody has read.** No release
   (§1h), no user-facing document (§1i). A compatibility promise with no
   consumer and no published text is a sentence in a decision record.
2. **The enforcement it needs is U32's deliverable, at M4** (§1h). Anything
   promised at M3 that U32 then has to break is a defect authored here — which
   is the brief's own test, and the blanket fails it: tier C members that do
   not exist yet (the overlay, the live section, the verdict data) would be
   promised at M3 and re-shaped at M4 the first time a page/CLI parity run
   disagrees with them.
3. **The tree cannot currently distinguish additive from breaking** (§1b), so
   the promise would be unfalsifiable in the only place it matters.
4. **It aims at the wrong noun.** The register's phrasing — *"is the **report
   schema** versioned/stable for scripting from M3?"* — presupposes that
   `verify --json` *is* the report. D64 §6 already ruled it is not: the report
   is one member of an envelope that also carries an overlay sibling and a live
   sibling (§1g).

**And the opposite arm — "declared unstable until M4" — is refused too**, on a
string the shipped binary prints today. `crates/antseal-cli/src/error.rs:404-410`
tells a user of `show`, `reveal` or `verify`:

> the command surface is frozen from day one **so scripts written today keep
> parsing**, and handlers land milestone by milestone

A product that says that in an error message and then declares its machine
output unstable for a milestone has two voices. The blanket-unstable arm is
also *false about the strongest member*: the report member is already frozen by
21 committed vectors and a bit-match lane, which is a harder freeze than U32 is
capable of applying.

**What survives the lean is its concern**, and it is satisfiable now: a scripter
at M3 needs *something* to gate on, and there are already four such things —
the exit code (U2's committed table), `ok`, `v`, and `result.report`'s frozen
interior. The partition below hands those over explicitly and declines to
promise the rest.

---

## 3. Ruling 1 — the commitment level at M3: three tiers, per member

The `--json` document has three regions with three different honest promises.
Stated in the words a scripter can act on:

### Tier A — FROZEN (already, and harder than M4 could make it)

**Scope**: `result.report` on `verify --json`.

**Promise**: those bytes are exactly what
`VerificationReport::to_canonical_json()` produces — the same bytes the page's
R22 binding returns, the same bytes 21 committed golden vectors pin, the same
bytes wasm32 bit-matches. Its field set, field order, spellings and JSON types
change only through a `REPORT_VERSION` bump, which is a FORMAT EVENT under
D105 §2.4 and moves all 21 vectors plus D29's fixed-fixture snapshot.

**What a script may do**: read `result.report.report_version` and branch on it;
read any documented report field by name; treat the member's bytes as stable
input to a digest.

**The one hole, priced rather than hidden**: enum-valued keys inside the report
(`anchors[].state`, `work.signature_scheme`, `storage_linkage`,
`supporting_evidence`, `anchors[].kind`) may gain a spelling with **no version
moving anywhere** — D105 §2.4 rules a variant a VALUE ADDITION, and carrying
the report verbatim imports that permission into `--json`. It cannot happen
silently (§1k: compile error, then an edited spelling literal, then R-VAL's
whole-report rendering obligation), but it can happen. **A consumer must
therefore treat every enum-valued key as open and always write the default
arm.** This is a documented property of tier A, not an exception to it.

### Tier B — STABLE-ADDITIVE from M3

**Scope**: the envelope wrapper — `v`, `command`, `network`, `ok`, and exactly
one of `result` / `error`; and the error object's `class`, `exit_code`,
`message`.

**Promise**: from M3, no key in that set is renamed, removed, retyped, or moved
between the top level and `result` without an `ENVELOPE_VERSION` bump. New keys
may be added at the top level without one. `v` is the discriminant a consumer
reads first.

**Inside the error object the promise splits by field, and the split is already
normative** (`docs/testing/error-code-contract.md:19-21`, adopted verbatim):
`class` and `exit_code` are **stable identifiers** — `class` is U2's committed
kebab table, disjoint from the verifier's code namespace and machine-checked to
stay so (`namespace_disjointness.rs`, Q77) — while **`message` is human copy
and may be reworded freely at any time, at any tier.** A script that matches on
`message` is misusing the surface, and the contract says so in its own words:
*"The `Display` text may be reworded freely; the code may not."*

**Why this tier can be promised at M3 when tier C cannot**: it already has both
halves. A version (`ENVELOPE_VERSION`, with a stated bump discipline —
`machine.rs:64-65`) and an exact-key-set assertion that reddens on every
breaking change to it (`machine_mode.rs:920-931`). Nothing is being invented;
this ruling states the level the existing machinery already enforces.

### Tier C — DECLARED UNSTABLE until U32

**Scope**: everything else inside `result` — for `verify`, the overlay and live
siblings and the verdict data; for every already-shipped command, the whole
`result` interior (`init`, `list`, `status`, `seal` ×3, `restore`, `vault
export`, `vault import`).

**Promise**: none, and saying so is the point. Keys here may be renamed,
removed or retyped between M3 and M4 with no version moving. Every such change
is **reviewed** — `envelope_fixtures_match_the_committed_snapshot` reddens and
the diff must be justified — but review is not compatibility. **U32 is where
these become promises**, by U32's own text.

**Two rules ride tier C anyway**, because they cost nothing and are already
universally true: the null/absent rule and the type rules of §7. A key that
exists is always present; its JSON type does not wobble run to run. Tier C says
the key set may move between *releases*, never that a document is
unpredictable within one.

### The sentence for the help text and the release notes

> At M3, gate your scripts on the **exit code**, on `ok`, on `v`, and on
> `result.report` — those are stable. Everything else under `result` is
> reviewed but not promised until the M4 release freeze, and every
> enum-valued field may gain a value, so always write the default arm.

---

## 4. Ruling 2 — the versioning mechanism: one version, and what `REPORT_VERSION` is not

**There is a schema version, it is `ENVELOPE_VERSION` rendered as `v`, and D65
mints no second one.** No per-command `schema_version`, no `result.version`, no
`overlay_version`.

**`REPORT_VERSION` is not a `--json` schema version and must never be used as
one.** It versions a document that is pinned in frozen vectors and consumed by
a second implementation (§1e). It appears inside a `--json` document only
because the report is carried verbatim, and it appears there as
`result.report.report_version` — a **field of an opaque member**, not the
document's version.

**The two axes are independent, and disagreement is not an error state.**

| | `v` (envelope) | `report_version` (member) |
|---|---|---|
| versions | how to find the members | how to read the report member |
| bumped by | a breaking change to the wrapper (§3 tier B) | a FORMAT EVENT per D105 §2.4 |
| costs | fixtures + this doc + consumers | 21 vectors + `EXPECTED_CANONICAL_JSON` + a bit-match re-run |
| owned by | U3/U32 | D29/D105/Q14 |

`v: 1` beside `report_version: 2` is legal and expected. So is `v: 2` beside
`report_version: 1`. **Nothing derives one from the other, and code that does
is wrong** — that is a rule a reviewer applies to a diff, and §8 names the test
that would have to go red.

**The forbidden coupling, in both directions:**

- **A `--json`-shaped need may never move `REPORT_VERSION`.** A field wanted
  for scripting convenience goes in a *sibling member of `result`*, never into
  `VerificationReport`. D105 §2.4 already prices the alternative; D64 §9's
  revisit trigger (*"any `overlay`-named key appearing inside
  `VerificationReport`'s serialization"*) is the same rule from the other side.
- **A `REPORT_VERSION` bump does not move `v`.** The envelope's contract is
  *"`result.report` is the canonical bytes of some released report version"*,
  and that sentence survives the bump. A consumer that knows `v` but not the
  new `report_version` can still read `ok`, the exit code, and the *presence*
  of a report — which is the whole forward-compatibility value of carrying the
  member opaquely.

---

## 5. Ruling 3 — carriage: the report member is byte-verbatim, and `success_envelope` cannot express that today

**`result.report` is a JSON object member whose serialized bytes are exactly
`to_canonical_json()`'s bytes, contiguous and unmodified.** Not re-serialized,
not re-ordered, not re-encoded, not pretty-printed.

**Refused: routing the report through `serde_json::Value`.** §1f measures why —
`serde_json::Map` is a `BTreeMap` here, so a `Value` round-trip alphabetizes the
report's keys and destroys D29 rule 1's declaration order. The tree already
carries the demonstration (`report` vs `report_json` in the same vector case)
and already records the conclusion (`vectors_report.rs:23-27`). D29's own
Consequences say what is at stake: *"R21/U30 reuse `to_canonical_json()` for
`--json`; R22 returns the same bytes through wasm-bindgen — one serialization
path everywhere, **so the bit-match contract covers the user-facing output
too**."* A `Value` round-trip severs exactly that.

**Refused: carrying the report as a hex or JSON string.** The vector document's
`report_json` hex is an *archival* choice for a pinned artifact; the `--json`
document is read by `jq`, and burying the report behind `fromjson` would make
the one tier-A surface the least usable thing in the file.

**Mechanism is U30's, but the constraint is stated because the existing
signature forbids the obvious route.** `success_envelope(command, network,
result: serde_json::Value)` (`machine.rs:220-233`) cannot carry verbatim bytes
— `serde_json::Value` has no raw variant, and `raw_value` is enabled nowhere
(`rg -n "raw_value|RawValue"` over the manifests and `crates/*/src` returns
nothing). ~~Two routes exist and either is acceptable~~ — **Corrected
2026-08-12 → three**; see "Correction — §5's enumeration of acceptable
carriage routes is short by one, 2026-08-12" below. The two named here: a
typed envelope struct for `verify` whose `report` field is the
`VerificationReport` itself (serde derive preserves declaration order, and the
envelope struct's own fields are declared in the alphabetical order the other
nine documents already emit, so no document's bytes move), or `serde_json`'s
`raw_value` feature plus a raw-accepting envelope constructor. **What is not acceptable is discovering the
question at implementation time**, which is why the Accept row in §11.2 is a
byte assertion and not a structural one.

**`preserve_order` must not be enabled for `serde_json` anywhere in the
workspace.** It would silently reorder every `--json` document in the product
for zero product gain. Enforcement is
`envelope_fixtures_match_the_committed_snapshot`, which would redden across all
nine documents at once; recorded here so the diff is read as a machine-interface
event rather than a feature tweak.

### 5.1 The membership of `verify --json`'s `result`, and the presence rule

Forced by D64 §6 plus §7's null rule:

```json
{"v":1,"command":"verify","network":"…","ok":true,
 "result":{"live":…|null,"overlay":…|null,"report":{…verbatim…},"verdict":…}}
```

- **`report`** — tier A, verbatim (above).
- **`overlay`** — D64's sibling document; `null` when `--online` was not
  requested. **Always present.**
- **`live`** — R11's `LiveCheckReport`; `null` when `--live` was not requested.
  **Always present.** CLI-only by spec; the page has no `--live`.
- **`verdict`** — the verdict-class datum R21 exposes for U30's exit-code
  mapping (`tasks/R.md` §R21 Accept). Present so a `jq` consumer need not read
  `$?`. **The spellings and the code values are D69's**, not this record's.

`overlay` and `live` render as `null` rather than being omitted because §7's
rule makes that the house form and because it is what lets one presence-only
key assertion cover both modes.

### 5.2 `ok` means "a report was produced", never "exit code 0"

Today `ok: false` ⟺ a `CliError` was returned, and every shipped command has
`ok: true ⟺ exit 0`. `verify` may be the first command where they differ, and
the shape must be decided here rather than discovered:

- **A bundle that fails the evidence pipeline produces no report at all.**
  D27 §4 — *"A report exists **only for a bundle that passed** the evidence
  pipeline — failures are typed errors, never report content"*
  (`report.rs:3-5`). So a tampered bundle emits the **error envelope**, three
  keys, no report. No D65 ruling can change that without re-opening D27, and a
  script must not expect report detail from a failed verification.
- **UNANCHORED passes the evidence pipeline.** It is a verdict, not a failure
  (`report.rs:164-165`: the UNANCHORED outcome *"aggregates from exactly this
  data in R17"*). **So if D69 maps UNANCHORED to a distinct nonzero exit code, the
  document is still a SUCCESS envelope carrying the report, with `ok: true`
  and a nonzero exit.** Modelling a verdict as a `CliError` to keep the
  coupling would delete the verdict's detail from the machine surface, which is
  the opposite of what a stability commitment is for.

**`ok` is therefore defined here as: a `result` document was produced.** The
exit code is a separate channel and D69 owns its values.

---

## 6. Ruling 4 — breaking vs additive, as a rule a reviewer applies to a diff

D105 §2.4's test is about **Rust structs in the report** and does not transfer:
the CLI's `result` documents are built by `serde_json::json!` literals at nine
producer sites (§1d), so there is no `pub struct` diff to read. **Its *shape* is
reused — a mechanical iff, checked by reading a diff — and its *subject* is
replaced.**

> **A `--json` change is ADDITIVE — no version moves — if and only if, for
> every document the surface can emit, the new document's key set is a
> superset of the old at every path, and every key the old document could
> carry keeps its JSON type and its meaning. Anything else is BREAKING and
> costs the version whose scope contains it: renaming a key, removing a key,
> changing a key's JSON type (including number↔string and value↔null-only),
> moving a key between paths, making a present key conditionally absent, or
> narrowing an enum-valued key's spelling set.**

Four riders, each answering a question the tree has actually asked:

1. **`null` is a value, not an absence.** A key that could be `null` and now
   cannot, or vice versa, is a **type** change and therefore breaking. This is
   the rule U50 asks for by name (*"a consumer branching on `failure_class:
   null` versus a string has nothing to rely on"*) — under this rule
   `failure_class` is **always present**, `null` when the endpoint succeeded
   and a kebab-case string otherwise, and that distinction is promised at every
   tier.
2. **Widening an enum-valued key is ADDITIVE; narrowing it is BREAKING.**
   Spelling sets are append-only in effect: §1k's triple makes growth a compile
   error plus an edited literal, and removal reddens the same literal. A
   consumer writes the default arm (§3 tier A).
3. **The report member is exempt from this rule and governed by D105 §2.4
   instead.** One document, two rulesets, and the boundary is the member
   itself. A reviewer reading a diff that touches `verify --json` asks *"did
   the report bytes move?"* (D105's question) and separately *"did the envelope
   or a sibling's key set move?"* (this rule's).
4. **Meaning counts.** A key whose type and name survive while its semantics
   change — a count that starts counting something else, a state that starts
   being computed differently — is BREAKING, and no mechanical check will catch
   it. That clause exists so a reviewer cannot discharge the rule by diffing
   key sets alone.

---

## 7. Ruling 5 — null, key order, and number formatting

**Inside the promise, at every tier:**

- **Absence is `null`, never a missing key**, on every `--json` document. This
  is D29 rule 4's discipline extended to the CLI side, it is already
  universally true (§1j), it costs nothing to state, and it is what makes the
  presence-only key assertion of §8 a meaningful instrument.
- **No float ever appears in any `--json` document.** Integers and strings
  only, matching D29's rule for the report and the CLI's measured practice.
- **Any integer that can exceed 2⁵³ is a decimal string**, not a JSON number —
  the `cost_atto` rule, already stated at two sites for the same reason (§1j).
- **A key's JSON type never changes** without the version whose scope contains
  it. number↔string is breaking (§6).
- **The provenance rule for time-shaped values**, found rather than designed
  and ruled here so it stops being an accident: **verifier-derived integers are
  JSON numbers; sealer-recorded values are JSON strings, reproduced verbatim
  and never reformatted.** `verified_time_unix` is a number because the
  verifier computed it; `fetch_date` and `claimed_time_informational_only` are
  decimal-POSIX-second strings because the sealer wrote them and *"nothing may
  ever compare [them] to anything"* (`report.rs:576-593`). The JSON type is
  therefore itself a provenance signal, and a lane that "tidied" the two
  strings into numbers would erase it.

**Outside the promise — with one region carved out:**

- **Key order is NOT promised anywhere in the document except inside the report
  member, where it is the wire order.** Outside it, alphabetical ordering is an
  artifact of `serde_json::Map` being a `BTreeMap` in this build (§1f) — a
  dependency default, not a decision, and one a feature unification could flip.
  Inside the report member it is D29 rule 1, pinned by 21 vectors, and it is the
  reason §5's carriage rule exists at all. **Consumers must not depend on key
  order outside `result.report`; a JSON parser does not preserve it anyway.**

---

## 8. Ruling 6 — where it is documented, and the test that goes red

### 8.1 Documentation home at M3

**`crates/antseal-cli/src/machine.rs`'s module doc**, extended with the tier
table of §3. Not a new file under `docs/`, on three measurements: `machine.rs`
is already the contract's stated home (it carries the envelope grammar, the two
exemptions, and the `ENVELOPE_VERSION` bump discipline); it is already what the
tree cites as authoritative when a lane needs to know the contract
(`listing.rs:63-69`); and the surface already has **two** normative statements
in two files — `machine.rs` and `docs/testing/error-code-contract.md` (§1i) —
so a third would be the second-authority shape rather than a documentation win.
**U32 lifts it into release docs**; that Accept row is unchanged.

The division of labour between the two existing homes is stated rather than
left to inference: **`error-code-contract.md` owns the `error` object's
identifier semantics** (`class` is U2's committed table, disjoint from the code
namespace, `message` freely rewordable) and **`machine.rs` owns everything
else** — the envelope grammar, the tiers, the carriage rule, and the null/type
rules of §7. Neither restates the other; §11.7's edit points each at the other
once.

Second surface: `verify --help`'s `--json` text carries the one-sentence form
from §3, so the tier boundary reaches a user who never reads a doc.

### 8.2 The tests, by tier — three enforce, two are owed

| tier | enforcer | status |
|---|---|---|
| A (report verbatim) | a byte assertion that the emitted document **contains `to_canonical_json()`'s bytes contiguously** | **owed — U30**, §11.2 |
| A (report interior) | 21 vectors + `EXPECTED_CANONICAL_JSON` + `wasm-bitmatch` | exists, in force |
| B (wrapper) | `machine_mode.rs::every_command_has_a_registered_fixture_with_the_v1_shape` — exact key sets at `:923`, `:925`, `:929` | exists, red-capable |
| C (review gate) | `machine_mode.rs::envelope_fixtures_match_the_committed_snapshot` | exists; reddens on additive changes too, by design |
| C (per-document presence) | presence-only key assertions, the `restore_output.rs:550` / `list_command.rs:361` pattern | exists for 2 of 7 commands — **owed for the rest**, §13 (ii) |

**The tier-A test, stated so it cannot be satisfied structurally**: run
`verify --json` over a golden bundle, take `VerificationReport::to_canonical_json()`
for the same bundle, and assert the stdout bytes contain that byte string as a
contiguous substring. It is red against the `Value` round-trip (§1f) and green
against every correct carriage; a `serde_json::Value` comparison would be green
against both and is therefore not the test.

**The `v`/`report_version` independence test** (§4): assert that a document with
`v: 1` carries whatever `report_version` the core constant holds, read from
`antseal_core::verify::REPORT_VERSION` rather than from a literal — so a report
bump does not redden the envelope suite, and a lane that "fixes" the envelope by
bumping `v` finds nothing to satisfy.

---

## 9. Ruling 7 — the conditionals D65 was named to answer, and one it inherited

### 9.1 The `decode_layer` conditional — **NO**, in both of its homes

The conditional is written twice — `tasks/Q.md:265-269` (the Q14 gate's
report-scope block) and `docs/testing/error-code-contract.md:105-110` — and both
leave it to D65 whether U30's failure envelope carries a `decode_layer` field.
**It does not, in envelope v1.** The error object's key set is exactly
`class`/`exit_code`/`message`, finalized from U2 unchanged and asserted exactly
(`machine_mode.rs:925-927`); a fourth key is a BREAKING change to tier B and
costs `ENVELOPE_VERSION`. Where a consumer needs the layer, it is expressible in
the **class partition** — U2's and D69's namespace, not this record's — and in
the human `message`. Both homes get the resolution (§11.7, §11.8) so the
conditional stops reading as open behind a decision that landed.

### 9.2 U50's scope question — **tier C, and the null rule answers its real question**

U50 asks *"whether [`seal --json`'s `anchors` object] falls under D65's
stability commitment"*. **It falls under tier C: reviewed, not promised, until
U32.** But U50's operative complaint — *"a consumer branching on
`failure_class: null` versus a string has nothing to rely on"* — is answered
**now** by §6 rider 1 and §7: `failure_class` is always present, `null` on
success and a kebab string on failure, and that distinction is promised at every
tier. U50's remaining deliverable is the presence-only assertion (§8.2),
which is what makes tier C reviewable rather than merely reviewed.

### 9.3 The inherited one — the tamper code has no machine slot, and the cheap window closes at Q34

§1m measures the gap: `error-code-contract.md:19` says `--json` carries the
verifier's `code()`; envelope v1 has nowhere to put it, and
`namespace_disjointness.rs` forbids spelling it into `class`. **D65 does not add
the fourth key**, for two reasons about ownership rather than merit: the error
object is U2's shape, finalized unchanged and deliberately (U3 execution note
1), and the granularity of `verify`'s failure classes is **D69's live question**
in this same Act — a fine-grained `class` partition would close the gap with no
new key at all.

What D65 *does* rule is the arithmetic, so whoever decides is not deciding
blind. A fourth key in the error object costs `ENVELOPE_VERSION` 1 → 2, and
**that bump is cheap exactly once**: Q34 is unstarted, no release exists, and
today the cost is the committed fixtures plus `machine.rs`'s doc. After Q34 the
same key is a compatibility event against deployed scripts. **So this is a
decision with an expiry, not a backlog item**, and the record says so rather
than letting the window close in silence.

Recorded consequence for `error-code-contract.md:19`: the sentence is an
overclaim about the surface that exists, and §13 (iii) records it as an
instance of the R76/R77 class.

---

## 10. What this record does not decide

- **Exit-code values, and the verdict-class spellings** — D69's, in this same
  Act. §5.2 rules only which *envelope* a verdict rides in, never which number
  it exits with.
- **The overlay document's own shape.** D64 §6 fixed its members and its
  embedded-strings contract; D65 rules only that it is a sibling of `report`
  inside `result`, always present, `null` when not requested.
- **The `--json` field names for reveal-preview snippets.** D67 §5 drew that
  edge and this record honours it: D67 owns the snippet *value*, D65 owns the
  shape around it, and neither can collide (verdict/report types carry no
  snippet by standing prohibition — `report.rs:830`, *"This type must never
  gain a path, snippet, or any content-derived field"*).
- **Whether `Deserialize` is ever derived on report types.** D105 §8 kill
  criterion 1 governs; if it lands, §3 tier A's forward-compatibility story
  needs a second clause, because a v1 reader meeting a later-minted variant
  fails.
- **U32's freeze mechanics** — which snapshots become promises, what the CI
  schema-freeze check compares, and the deprecation window for a post-release
  break. This record deliberately declines to pre-write M4's policy; it ensures
  U32 inherits a partition rather than a blank surface.
- **R76/R77's repair.** They are evidence here (§ below) and rows there.

---

## 11. Registrar's edit set

**This lane wrote one file: this one.** Everything below is instruction.

### 11.1 Register and index

1. `TODO.md` decision register, the D65 line under "Due M3" — replace with the
   resolved line from the lane's closing report (D67's line is the model).
2. `docs/decisions/README.md` — one index row, in id order, status/date from
   this record's own lines (D119 conventions).

### 11.2 `tasks/U.md` U30 — append to `Do`, and two `Accept` rows

> - Do (append): **[D65, 2026-08-12]** The `--json` document is an envelope of
>   members, not a report: `result` carries `report` (the canonical report
>   bytes, **byte-verbatim**), `overlay` and `live` (D64's siblings, `null`
>   when the mode was not requested — always present, never omitted), and
>   `verdict` (D69's class datum). `ok` means *a report was produced*, never
>   *exit code 0*: a verdict mapped to a nonzero code by D69 still emits a
>   **success** envelope carrying the report, because D27 §4 means an error
>   envelope has no report at all. The report member must **not** be routed
>   through `serde_json::Value` — `serde_json::Map` is a `BTreeMap` in this
>   build, so a round trip alphabetizes the report's keys and destroys D29
>   rule 1's declaration order (`success_envelope`'s current `Value` signature
>   cannot express verbatim carriage; a typed envelope for `verify`, or
>   `serde_json`'s `raw_value` feature, are the two acceptable routes).
>   Commitment level per D65 §3: tier A `result.report`, tier B the wrapper,
>   tier C everything else until U32.
> - Accept (add): the bytes of `verify --json`'s stdout **contain
>   `VerificationReport::to_canonical_json()`'s bytes as a contiguous
>   substring** for a golden bundle — a structural `serde_json::Value`
>   comparison does not discharge this row, because it is green against the
>   key-reordering bug the row exists to catch
> - Accept (add): a presence-only key assertion over `result` (the
>   `restore_output.rs:550` pattern) covering `report`, `overlay`, `live`,
>   `verdict` in **all four** mode combinations — every key present in every
>   combination, `null` where the mode was off
> - Accept (add): the envelope's `v` is asserted against `ENVELOPE_VERSION` and
>   the report's version is read from `antseal_core::verify::REPORT_VERSION`,
>   never a literal and never derived from each other (D65 §4)

### 11.3 `tasks/R.md` R21 — extend the D64 Accept row

> - Accept (extend the `[D64, 2026-08-11]` row): …and the bytes R21 exposes for
>   U30's `--json` are `to_canonical_json()`'s, handed over as bytes rather
>   than as a parsed `serde_json::Value` — **[D65, 2026-08-12]** the library
>   must not pre-parse the report on U30's behalf, because the parse is
>   precisely where declaration order is lost

### 11.4 `tasks/U.md` U50 — resolve its second half

> - Do (append): **[D65, 2026-08-12]** Scope answered: `seal --json`'s
>   `anchors` object is **tier C** — reviewed by the committed fixture, not
>   promised until U32. The null question is answered *now* and at every tier:
>   `failure_class` is **always present**, `null` when the endpoint succeeded
>   and a kebab-case string otherwise; absence is never a missing key (D65 §6
>   rider 1, §7). This row's remaining deliverable is the **presence-only key
>   assertion** over the `anchors` object and its `endpoints[]` rows.
> - Accept (replace the second clause): the D65 scope decision is recorded
>   (tier C, D65 §9.2); the presence rule is asserted by a fixture including
>   the `null`/string distinction on `failure_class`

### 11.5 `crates/antseal-cli/src/listing.rs:63-69` — one paragraph goes stale

The paragraph beginning *"Adding `nag` to the `--json` row is permitted now:
**D65 is not in force.**"* becomes false when this record lands. It should be
replaced with: D65 is in force from 2026-08-12; the `--json` row is **tier C**
(reviewed, not promised until U32) and the addition remains correct; the
in-force machine contract is still `ENVELOPE_VERSION`, whose scope D65 §3 tier B
now states. **Not a correction to a decision record** — a live doc paragraph
that this ruling dates.

### 11.6 `crates/antseal-cli/src/machine.rs` module doc — the tier table

Add §3's three tiers and §7's null/type/key-order rules under a new heading, and
one line under `ENVELOPE_VERSION` recording §4: it is the document's only schema
version, `REPORT_VERSION` is not one, and neither derives from the other.
**This is the M3 documentation home** (§8.1); U32 lifts it.

### 11.7 `docs/testing/error-code-contract.md` — three lines

1. **`:105-110`** — the `decode_layer` conditional resolves: *"D65 (2026-08-12)
   ruled NO for envelope v1 — the error object's key set is exactly
   `class`/`exit_code`/`message` and a fourth key costs `ENVELOPE_VERSION`; the
   layer, where a consumer needs it, is expressible in the class partition."*
   Same sentence lands at `tasks/Q.md:265-269` (§11.8).
2. **`:19-21`** — *"`--json` output carries it"* is an overclaim about envelope
   v1 (§1m). Correct it to say what is true — the code is what tamper rows bind
   to and what third-party verifiers compare against; a `--json` consumer sees
   `error.class` and the code only inside the freely-rewordable `message` — and
   point at D65 §9.3 for the open question and its Q34 expiry. **Do not delete
   the sentence about `Display` being freely rewordable**: D65 §3 tier B adopts
   it verbatim.
3. One cross-reference to `machine.rs` for the envelope's own contract, per
   §8.1's division of labour (this doc owns the `error` object's identifier
   semantics; `machine.rs` owns the rest).

### 11.8 `tasks/Q.md:265-269` — the gate block's conditional resolves

Replace *"If U30's `--json` **failure** envelope carries it (D65's call, M3),
the field is named `decode_layer` and lives outside `VerificationReport`"* with
the resolution: D65 ruled NO for envelope v1; the field is not minted; if a
future envelope version carries one it is still named `decode_layer` and still
lives outside `VerificationReport`, which D86 makes permanent either way.

### 11.9 No edits requested

`MVP-SPEC.md`, the frozen registry, `testdata/`, any golden vector, any report
type, and `docs/decisions/D29`/`D64`/`D105` (immutable) are untouched by this
ruling. `REPORT_VERSION` stays `1`, `ENVELOPE_VERSION` stays `1`. Zero frozen
bytes move.

---

## 12. Refused shapes

| shape | refused on |
| --- | --- |
| "stable, versioned JSON schema from M3" (the lean, as a blanket) | no release, no document, no additive-vs-breaking instrument; U32 owns the freeze by its own text (§2) |
| "explicitly unstable until M4" | contradicts a string the binary prints today — *"frozen from day one so scripts written today keep parsing"* (`error.rs:407-410`) — and is false about the report member, already frozen by 21 vectors (§2) |
| a per-document or per-command `schema_version` | a second version with no bump discipline and no consumer; `v` already discriminates and already has one (§4) |
| making `REPORT_VERSION` the `--json` schema version | a scripting-convenience key would cost 21 vector re-emits + `EXPECTED_CANONICAL_JSON`; it versions a bit-matched artifact shared with a second implementation (§1e, §4) |
| deriving `v` from `report_version` (or asserting a fixed pair) | orthogonal axes; the assertion reddens on an unrelated bump and teaches the wrong repair (§4, §8.2) |
| routing the report through `serde_json::Value` | `serde_json::Map` is a `BTreeMap` here — the round trip alphabetizes the report and destroys D29 rule 1; the tree already demonstrates the loss on itself (§1f, §5) |
| carrying the report as a hex or JSON string | the archival form of a pinned artifact, not a `jq` surface; makes the one frozen member the least usable (§5) |
| omitting `overlay`/`live` when the mode is off | conditional presence is the shape §7 forbids and the shape that makes a presence assertion untestable (§5.1) |
| modelling UNANCHORED as a `CliError` to keep `ok ⟺ exit 0` | deletes the verdict's detail from the machine surface — D27 §4 gives an error envelope no report (§5.2) |
| a `decode_layer` key in the error object | breaks tier B's exact key set and costs `ENVELOPE_VERSION`; the class partition and `message` already carry it (§9.1) |
| a `code` key in the error object, minted here | the error object is U2's shape and `verify`'s class granularity is D69's live question this Act; D65 rules the arithmetic and the Q34 expiry instead of the key (§9.3) |
| spelling the verifier's tamper code into `error.class` | the two namespaces are machine-checked disjoint since Q77 (`namespace_disjointness.rs`); merging them is *"reading the contract wrong"* in the contract's own words (§1i) |
| promising `error.message` | the error-code contract already says the `Display` text may be reworded freely; a promise here would contradict a normative doc (§3 tier B) |
| a new `docs/cli/json-schema.md` at M3 | mints a second authority for U32 to reconcile; `machine.rs`'s module doc is already the cited one (§8.1) |
| enabling `serde_json`'s `preserve_order` | silently reorders all nine shipped documents for zero product gain (§5) |

---

## 13. Discovered work — described, not registered

No ids are minted here.

**(i) PRODUCT — the fixture registry cannot see two commands' result shapes,
and they are the only two.** `machine_mode.rs`'s `render_fixture` renders eight
of the ten commands' documents **through the real producers**, with comments
stating the rule three times over (*"rendered by the real producer — a
hand-copied string here went stale the first time the message changed"*; *"a
fixture that documents text no build emits is worse than none (U19's rule)"*).
`vault export` and `vault import` are the exception: their entries are
hand-written `serde_json::json!` literals inside the test file
(`machine_mode.rs:415-431`), duplicating `commands.rs:467-472` and `:516-521`.
Consequence, measured: of the eight keys those two commands emit, **four are
asserted against a real producer** (`self_verified` and `works` at
`machine_mode.rs:261-262`; `works` and `wallet_restored` at
`vault_export.rs:675-676`) and **four are asserted only against the copy**
(`file`, `bytes`, `vault_dir`, `config_restored`). Renaming any of those four in
the handler moves no test. This is the exact failure mode the file's own
comments say the house corrected three times, surviving in the two commands
nobody re-checked.

**(ii) PRODUCT — tier C has no per-document enforcer for five of seven
commands.** The presence-only pattern exists for `restore` and `list` (§1c) and
for nobody else: `status`, `seal` (three documents), `init`, `vault export` and
`vault import` have no key assertion at all beyond the blessable byte snapshot.
Tier C's honesty depends on a reviewer reading a snapshot diff, which is the
weakest link in this ruling and the one worth closing before U32 arrives with
seven documents to freeze at once. U50 already owns `seal`'s.

**(iii) The R76/R77 class is not confined to `report.rs`, and this record found
two more instances on the machine surface.** Both open rows are the same shape —
*a doc stating an imperative its named consumer cannot honour* — and R77's
argument for being a row rather than a ledger line was that *"two instances make
it a pattern in `report.rs`'s docs, not an accident"*. Measured here, outside
`report.rs`:

- **`docs/testing/error-code-contract.md:19`** — *"the code is the
  machine-readable name of the failure: … **`--json` output carries it**"*. The
  error object has three keys and none is the code, and
  `namespace_disjointness.rs` forbids the workaround (§1m). This is the same
  class as R77 and it is on a **normative doc**, not a type doc, which makes it
  the more consequential of the three: a lane implementing U30 reads it as a
  requirement and finds no slot.
- **`crates/antseal-cli/src/machine.rs:33-34`** — the committed fixture is
  called *"the schema-registry fixture the harness enforces"*, and the harness
  enforces the **envelope** (§1b), not the schema. True of tier B, an overclaim
  of tier C. §11.6's edit fixes this one in passing.

Whoever takes R76/R77 should know the pattern has four instances across three
files and two layers, and that the fix at each is the same one line.

---

## Outcome

The register asked whether the report schema is versioned and stable for
scripting from M3, and the question contained two errors that the measurement
separates. `verify --json` is not the report — D64 already made it an envelope
of members — and the report is not un-versioned; it is the single most heavily
frozen document in the product, pinned by 21 vectors and bit-matched across two
targets. So the honest answer is neither of the two poles the framing offered:
the blanket promise is unpayable because M3 has no release, no document, and no
instrument that can tell an added key from a renamed one, while blanket
instability contradicts a sentence the binary already prints to users. The
partition hands a scripter four things that are true today — exit code, `ok`,
`v`, and the report member — and declines to promise the rest until U32, whose
own text says that is where snapshot baselines become compatibility promises.

The finding that changes code is smaller and sharper than the framing: the one
signature U30 must call takes a `serde_json::Value`, `serde_json::Map` is a
`BTreeMap` in this build, and the tree already proves on itself — in the frozen
vector document, carrying the same report twice under two key orders — that a
round trip through that type destroys the declaration order D29 rule 1 makes the
wire order. Left undiscovered until implementation, it would have shipped a CLI
whose `--json` report is not the report the page returns, with R21's
byte-equality row green throughout and nothing else red. That is why tier A's
acceptance test is a byte containment and not a structural comparison: the
structural comparison passes the bug.

---

## Correction — §5's enumeration of acceptable carriage routes is short by one, 2026-08-12

**This section adds no ruling** (D117 §2.2). §5's rule is unchanged and its
three refusals are unchanged; what is corrected is a **count and a closure**.
The correction runs in the direction that *strengthens* the ruling — stated at
(4).

**(1) The struck clause, quoted verbatim, with its section identifier.** §5,
the paragraph beginning *"Mechanism is U30's…"*, read:

> Two routes exist and either is acceptable: a typed envelope struct for
> `verify` whose `report` field is the `VerificationReport` itself (serde
> derive preserves declaration order, and the envelope struct's own fields are
> declared in the alphabetical order the other nine documents already emit, so
> no document's bytes move), or `serde_json`'s `raw_value` feature plus a
> raw-accepting envelope constructor.

The same enumeration is carried at two more sites: §11.2's quoted `Do` block
(*"a typed envelope for `verify`, or `serde_json`'s `raw_value` feature, are
the two acceptable routes"*) and, through it, `tasks/U.md` U30's `Do`. Those
copies carry **no separate marker**: this section is the single home of the
fact (D117 §2.2) and names all three sites, so a reader arriving at any of them
lands in one place.

**(2) The measured fact, with the commands that measured it.** Both named
routes were **unavailable to the implementing lane, and both for the same
reason** — each is a `Cargo.toml` edit, and the lane was fenced from the
manifests (a sibling R22 lane held them and the lock). Measured 2026-08-12;
the commands are the citation, not their output's line numbers, and a reader
re-runs them rather than trusting the transcript (D117 §2.5's epoch rule, §2.6):

```
$ grep "serde" crates/antseal-cli/Cargo.toml
serde_json.workspace = true

$ grep -rn "raw_value" --include=Cargo.toml --include=Cargo.lock . | grep -v "^./target/"
(no output)
```

One line in the whole manifest, and it is `serde_json`. **`serde` itself is
not a dependency of `antseal-cli` at all** — not in `[dependencies]`, not in
`[dev-dependencies]` — so route one, *"a typed envelope struct … serde derive
preserves declaration order"*, cannot be written: there is no `derive(Serialize)`
in scope to write it with. And `raw_value` is enabled nowhere in the workspace,
exactly as §5 itself measured when it was written — which is the half this
record already knew and recorded as a *route* rather than as an obstacle.

**The third route, which the enumeration missed.** U30 assembled the `result`
document from **byte strings core already produces** — `report_bytes()`,
`LiveSection::to_canonical_json()`, `OnlineOverlay::to_canonical_json()`,
`VerdictClass::to_canonical_json()` — joined with `format!` and handed to a new
`machine::success_envelope_raw`, whose only `serde_json` use is quoting two
scalar wrapper strings. `crates/antseal-cli/src/verify_out.rs` therefore
contains **no executable `serde_json` call whatsoever**; every mention of the
crate in that file is prose.

**(3) Authority, and the same-wave disclosure.** The authority is **U30** (the
implementing lane, 2026-08-12), which found it by executing §5 rather than by
reading it. **The authoring and correcting lanes are the same wave** — D65 was
written by wave 18's Act 1 planning round and this correction by the wave-18
registrar on the same date — so per D117 §2.1(c) that is stated here in one
sentence rather than left to inference: this is a same-wave amendment, not a
diff against a long-published record. The two lanes are nonetheless independent
in the way that matters, and the record says so itself: D65's Method note
records *"read/grep only. No build was run"*, while this correction rests on a
shipped implementation and on manifest measurements the planning lane did make
(§5's own `raw_value` sweep) but read as a menu rather than as a fence.

**(4) Which rulings still stand, and in which direction.** **All of them, and
the correction strengthens the one it touches.** `result.report` is a JSON
object member whose serialized bytes are exactly `to_canonical_json()`'s,
contiguous and unmodified; routing through `serde_json::Value` stays refused;
carrying the report as hex or a JSON string stays refused; `preserve_order`
stays forbidden workspace-wide. The third route satisfies §5's rule **more
strongly than either named route would have**, and the difference is not
stylistic: under a typed envelope or a `RawValue`, each member is a *second
serialization* of data that was already serialized once, and the two
serializations are equal only so long as nothing between them drifts. Under
what shipped, every member **is** the byte string R22's page receives — the
same `to_canonical_json()` output, moved and never re-encoded — so D29 rule 1's
declaration order is not preserved by a property of `serde`, it is preserved
because **there is no parse in which to lose it**. §5's sentence *"What is not
acceptable is discovering the question at implementation time"* is likewise
undisturbed: the question was not discovered at implementation time, it was
answered there, from a record that had already framed it. What the enumeration
got wrong is only that it wrote a closed list where it had measured a rule.
