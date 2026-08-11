# D29 — Deterministic verification-report byte format

- **Status: RESOLVED — FROZEN 2026-07-28 at Q14 as report v1
  (`REPORT_VERSION = 1`, bumped at R32). The `format-v1-freeze` gate is
  closed: this format no longer may change, and any change to these bytes is
  a report-format version bump.**
- **Date: 2026-07-28**
- **Correction marker (2026-08-11)**: the `Status` and `Date` lines above are
  **replacements** made under
  [D117](D117-resolved-decision-corrections.md) §2.3(a), executing
  [D119](D119-decision-index-identity-and-the-index-row-sections.md) §5
  step 1. The superseded wording is quoted verbatim in *"Correction — the
  `Status` and `Date` lines claim a pre-freeze state, 2026-08-11"* at the
  foot of this file.
- **Owning task: R1** (consumed by R5/R9 report emission and vectors, Q4
  golden-vector schema, Q5 native↔WASM bit-match lane, R21/U30 `--json`,
  R22 page binding)
- Index note: this record was authored on the R1 branch; the
  `docs/decisions/README.md` index (which lives on `main`) gains its row at
  merge.

## Context

The serialized `VerificationReport` is a byte contract: Q4's golden vectors
map canonical bundles to **expected report bytes**, and Q5's CI lane
requires the wasm32 build's report output to be **SHA-256-identical** to
native for every vector, forever (MVP-SPEC.md lines 167/169: "the WASM
build must bit-match native verification"). R1 must therefore pick a
serialization that is byte-deterministic **today** — across runs, targets
(native ↔ wasm32), and platforms — without waiting for F's deterministic
CBOR codec, which lands on a parallel branch.

## Recommendation

**Compact JSON via `serde` + `serde_json` (`serde_json::to_vec`), made
deterministic by construction rules on the report types:**

1. **Struct fields serialize in declaration order** (serde derive
   guarantee). Declaration order in
   `crates/antseal-core/src/verify/report.rs` **is** the wire order —
   reordering, adding, or removing a field is a report-format change.
2. **No `HashMap` (or any randomized/address-ordered container) anywhere
   in the report types — `Vec` and `BTreeMap` only.** The current model
   needs no maps at all (ordered `Vec`s of structs with explicit id
   fields); if a map ever becomes necessary it must be a `BTreeMap` with
   integer or string keys.
3. **No floats, anywhere.** All numbers are integers (`u32`/`u64`/`i64`);
   times are integer Unix seconds or opaque strings. This mirrors the
   deterministic-CBOR profile's float ban (MVP-SPEC.md line 73) and
   removes the one classic JSON nondeterminism hazard (float formatting).
4. **No conditional field presence** (`skip_serializing_if` is banned in
   report types): every field of a given report version serializes every
   time; absence is expressed by `null` (`Option`) or an explicit
   `not-evaluated`/`absent` state. The shape of the bytes depends only on
   the report version, never on runtime happenstance.
5. **Compact encoding** (`to_vec`, not pretty-printed), UTF-8. serde_json's
   string escaping and integer formatting (`itoa`) are deterministic and
   platform-independent.
6. **Binary data is lowercase hex** (e.g. `work_id` as 64 hex chars) via
   explicit `Serialize` impls — JSON has no byte-string type and base64
   has padding/alphabet variants; fixed lowercase hex is unambiguous.
7. **Enum wire names are kebab-case** (`#[serde(rename_all =
   "kebab-case")]`), matching the spec's own state names
   (`valid-at-stamping-cert-since-expired`,
   `internally-consistent-only`, …). Field names are the Rust snake_case
   names, unrenamed.
8. **The report carries its own format version** (`report_version`, first
   field; `0` until Q14 freezes `1`).
9. **`Serialize` only for now.** Reports are produced by us and consumed by
   renderers/vectors; nothing parses adversarial report bytes. `Deserialize`
   can be derived later (non-breaking) if Q4's runner or external tooling
   wants structural comparison instead of byte comparison.

The canonical byte form is exposed as
`VerificationReport::to_canonical_json()` in `antseal-core` (it must live
in core: Q5 byte-compares the bytes as produced *inside* the wasm32
build, and R22 returns them across the JS boundary).

### Why not CBOR now

The project's deterministic CBOR profile (RFC 8949 §4.2.1, pinned encoder,
candidate `minicbor`) is F's domain and lands on a parallel branch with its
own pin decision (P10). Choosing a second, ad-hoc CBOR encoder in R1 would
put two CBOR stacks in the tree and pre-empt P10. JSON additionally serves
two consumers for free: the CLI `--json` output (R21/U30) and the page's
`JsValue` report (R22) — both want JSON anyway, so the vector format and
the user-facing machine format coincide.

### Option to move to canonical CBOR later — and what would force it

Once the F codec lands, Q4/Q5 **may** re-base the report byte format on
the same canonical-CBOR profile (one deterministic encoding repo-wide,
native byte strings instead of hex). That is a Q4/Q5/Q14 call, to be made
**before** the Q14 freeze — after Q14 it would be a report-format version
bump. Concrete forcing conditions:

- evidence that `serde_json` output is not bit-stable across the pinned
  native/wasm32 toolchains (none is expected for integer-only data; Q5's
  injected-divergence test-of-the-test would catch it);
- vector-size or hashing-cost pressure from hex-doubling binary fields;
- a repo-wide ruling (F/Q) that exactly one canonical encoding may exist
  for all frozen byte formats.

Absent a forcing condition, the recommendation is to freeze JSON at Q14:
one human-readable vector format, no second encoder in the trust base.

## Pin consequence (dependency-policy §1)

**`serde` and `serde_json` join the exact-pin class as of R1** — appended
to the table in [`docs/dependency-policy.md`](../dependency-policy.md).
Rationale: the pin class covers format-affecting dependencies, and from R9
onward the serialized report is a committed, retained-forever vector format
whose bytes CI compares exactly (Q5/Q6). A serializer behavior change
(escaping, integer formatting, derive field ordering) would be a silent
vector break — a format incident, not a chore — so version movement must go
through the deliberate-bump procedure (§4) with a golden-vector re-run.
Pinned at the versions resolved at R1 execution: `serde = "=1.0.229"`,
`serde_json = "=1.0.151"` (recorded in `[workspace.dependencies]` and
`Cargo.lock`). `thiserror` stays outside the class (error *types* are
compiled API, not serialized bytes; caret requirement, resolved version
frozen by the lockfile like every dependency).

## Consequences

- R1 implements the report model under rules 1–9 and ships the
  determinism tests (double-serialize byte-equality + a fixed-fixture
  snapshot pinning the exact bytes) plus the wasm32 build gate.
- Q4 freezes the vector schema over these bytes; Q5 bit-matches them
  native↔wasm32; **Q14 turns this recommendation into the frozen
  report-format v1** (or records the CBOR re-base decision instead).
- R21/U30 reuse `to_canonical_json()` for `--json`; R22 returns the same
  bytes through wasm-bindgen — one serialization path everywhere, so the
  bit-match contract covers the user-facing output too.
- Any pre-Q14 field addition (e.g. R12's anchor detail, R20's
  storage-linkage arm) re-snapshots the R1 fixture — expected and cheap
  before the freeze, forbidden after it without a version bump.

---

## Correction — the `Status` and `Date` lines claim a pre-freeze state, 2026-08-11

**Both front-matter lines are REPLACED**, under
[D117](D117-resolved-decision-corrections.md) §2.3(a) — the REPLACE arm, not
the STRIKE arm — executing
[D119](D119-decision-index-identity-and-the-index-row-sections.md) §5 step 1.
The routing is the substance of this correction and is argued in §3 below
rather than asserted.

### 1. The replaced lines, quoted verbatim

The record's `- **Status` bullet, as it stood from `5494e9f` (2026-07-27) until
today:

> - **Status: RECOMMENDED (R1) — final freeze belongs to Q4/Q5 vector schema
>   work and is sealed at the Q14 `format-v1-freeze` gate. Until Q14 this
>   format may change; after Q14 any change is a report-format version bump.**

and its `- **Date` bullet:

> - **Date: 2026-07-27**

Nothing else in this record is replaced. §"Recommendation" rules 1–9, the
*Why not CBOR now* argument, the *Option to move to canonical CBOR later*
section and §"Consequences" are left standing exactly as written, including
their pre-freeze framing — see §3.

### 2. The measured fact, with the commands and their output

**The event happened, and this record never recorded it.** Q14 — the M0
`format-v1-freeze` gate — executed on **2026-07-28**, freezing this format as
report **v1**:

```
$ grep -n '^- \[.\] \*\*Q14\*\*' TODO.md
283:- [x] **Q14** (S) Execute the M0 format-freeze gate; annotated
      `format-v1-freeze` tag … ✅ 2026-07-28 — **M0 format-v1 freeze executed**
```

Both of the project's other homes for this decision's status recorded it. The
index row did:

```
$ git show dfe7071 -- docs/decisions/README.md | grep '^[-+].*\[D29\]'
-| [D29](…) | … | RECOMMENDED | 2026-07-27 |
+| [D29](…) | … | RESOLVED (FROZEN at Q14 as report v1; `REPORT_VERSION = 1`,
   R32; Q38 independent check) | 2026-07-28 |
```

`dfe7071` (2026-07-31, *"Bookkeeping sweep from the 2026-07-31 audit: counts,
statuses, …"*) is the commit that corrected the index **and did not touch this
file**. `TODO.md`'s Decision register agrees with the index — *"**FROZEN
2026-07-28 at Q14** as report **v1** (`REPORT_VERSION = 1`, bumped at R32)"*.
This record is alone, and its history says why:

```
$ git log --oneline -- docs/decisions/D29-report-byte-format.md
5494e9f R1: VerificationReport model + VerifyError taxonomy … (D29 recommended)
$ git log -1 --format=%ad --date=short 5494e9f
2026-07-27
```

**One commit, ever, dated the day before the freeze.**

**Wrong when the event happened, not gone stale.** D117 §2.5 requires this
distinction to be stated. The `Status` line was *correct as written* on
2026-07-27 and became false on **2026-07-28**, the moment Q14 closed the gate
it names — so the defect is fourteen days old, and it is a missed update
rather than a drifting measurement. The 2026-07-31 audit updated the row and
not the record, which is how a fixed index came to sit beside a wrong record
for eleven further days.

### 3. Why REPLACE and not STRIKE

D117 §2.3's test is *"would a lane act on this sentence?"* The struck-arm
candidates in this record are arguments and rationales; the `Status` line is
not one of them. It said, in the first three lines of the file, **"Until Q14
this format may change"** — a permission. A lane reading it would believe a
frozen byte format is still open, and the material it governs is covered by
`testdata/vectors/v1/FROZEN.sha256`, so acting on the permission means editing
frozen bytes. That is the REPLACE arm exactly (rules, constants, prescribed
text: anything a reader would execute).

The rest of the body routes the other way and is deliberately left standing
under D117 §2.3(b): *"Absent a forcing condition, the recommendation is to
freeze JSON at Q14"*, the CBOR re-base option and §"Consequences"' *"Q14 turns
this recommendation into the frozen report-format v1"* are the record of what
was believed and argued before the gate, they are self-limiting about the
post-Q14 rule, and their value **is** that record. No lane acts on them.

### 4. Authority, and separability

Found and measured by the wave-15 **D119** lane (owning tasks **Q180** and
**Q186**), which ruled in RULING 2 that where a record, the index and
`TODO.md`'s register disagree the **record** decides — and that where the
record is the stale one it is corrected **first**, before the index is
touched, or the index check is green over a wrong status.

**This correction is not separable from its subject in the D117 §2.1(c)
sense**, and that is stated here rather than left to be discovered: D119 and
this correction are the same wave, and this record's replacement lands in the
same act as the 35-row index backfill D119 §5 step 4 orders. It is separable
from the *sentence* it corrects, which was committed at `5494e9f` on
2026-07-27 and is quoted above from that commit.

### 5. Which rulings still stand

**All of them.** Nothing in this correction touches the recommendation itself:
compact `serde_json` under rules 1–9, declaration-order fields, `Vec`/
`BTreeMap` only, no floats, lowercase hex, kebab-case wire names, the pin
consequence for `serde =1.0.229` / `serde_json =1.0.151`, and
`to_canonical_json()`'s home in `antseal-core` are unchanged and are what Q14
froze. The error runs in the direction that **strengthens** every rule here:
each was recommended and is now binding. No section, ruling or rider
identifier moves; this record has none, and the correction is appended rather
than inserted (D117 §2.2).
