# D110 — A115: which reply class `MAX_OTS_CALENDAR_RESPONSE_BYTES`' margin divides by, and what the F4 cell says

- **Status: RESOLVED — the margin divides by the UPGRADE reply, 59.31x, and
  the brief's framing is overturned at its root.** A115 and the brief both
  present this as *"a substantive ruling about A42's limit that D54 §6.1
  assigned"*. It is not a ruling D54 §6.1 assigned — **D54 §6.1 already made
  it**, on 2026-08-02, in the same sentence that recorded the provisional
  submit figure: *"The upgrade response is larger (it carries a Bitcoin merkle
  path) and has **not** been measured; A25's two-day protocol must record it
  and **the F4 row must be completed with that figure before M2 closes**."*
  What has been open since the measurement landed on 2026-08-03 is a
  **discharge**, not a decision. Five places in the tree already state the
  upgrade keying — D54 §6.1, D54 §9 finding 3, `OTS-BOOTSTRAP.md`,
  `crates/antseal-anchor/src/ots/mod.rs` (*"it is the figure the F4 row
  takes"*) and `crates/antseal-anchor/src/testing/replay.rs` (*"the figure
  A42's F4 margin is completed from"*) — and **the registry cell is the only
  place in the tree keyed to the submit reply.** So the option A115 leans
  against is not merely worse: it contradicts a ratified decision and four
  corroborating records, and choosing it would require amending D54, which
  nothing in the tree argues for. **The value does not change**: 65 536 stays,
  the lowering window is open and deliberately not taken, and the reason is
  measured rather than asserted — **zero of the four `DEFAULT_OTS_CALENDARS`
  endpoints has ever had either reply class measured**, because the A25
  captures were taken against `*.btc.calendar.opentimestamps.org` hosts that
  the D54 default list deliberately does not contain. **The "both recorded"
  option dies on this document's own rule**, stated in §5's Update rule in the
  words A113 put there: a second margin in the column would be *"a number that
  reads like the checked ones and is checked by nothing"*, which is the exact
  defect A113 landed to remove — one column, one keyed number, the other class
  named in prose and unbolded. **§6 owes no entry**, and D107 R1's exclusion
  table says so verbatim rather than by inference. **One new test lands**,
  because A113's checker is document-internal arithmetic and is green for
  *either* keying as long as both cells move together — a consistent re-key
  back to the submit reply passes it today and must not.
- **Date: 2026-08-10** (M2 wave 12 planning round; briefed to attack every
  premise, and the load-bearing one — that this decision was still open —
  did not survive)
- **Owning tasks: A115** (closed by this record), **A42** (owner of the limit
  and of the row; its value does not move), **A113** (built the margin
  cross-check and correctly deferred the keying), **A25** (the captures both
  operands are measured from), **A114** (edits the same document; §9 sequences
  them)
- **Amends**: **D54 §6.1** — its completion obligation is **discharged**, not
  altered; **D54 §7**'s verbatim row, whose `margin` cell reads `298×`, is
  recorded as **superseded by §6.1 of its own document** and is *not* rewritten
  (a decision record is the ruling as made, and `git log` is its history —
  D107 R3's principle); **`docs/format/anchor-artifact-limits.md` §5** — the
  A42 row, the margin-band sentence and the note paragraph below the table.
  **Supersedes**: nothing. **Binds against**: D84 F4, D107 R1/R2, D102's
  §5a rule-6 precondition, D90 §6.8, D58 §10.3 rule 4.

---

## The problem, in one sentence

The F4 registry says this cap is scaled against a 220-byte submit reply and
every other record in the tree says it is scaled against a 1 105-byte upgrade
reply, and the question is not which is better but which one is the document
that has not been updated.

---

## 1. What was measured

Everything below was re-measured from bytes, source and committed tests in
this planning round. Nothing is taken from A115's row, from `tasks/A.md` or
from last wave's report.

### 1.1 The two figures, from the files rather than from the cells

`stat` over `testdata/anchors/A25-bootstrap/`:

| class | files | bytes | largest |
| --- | --- | --- | --- |
| submit (`*.timestamp`) | `{A,B}-{alice,bob,catallaxy}` | 207 / 170 / **220** / 207 / 170 / 185 | **220** |
| upgrade (`upgraded/*.upgrade`) | `{A,B}-{alice,bob,catallaxy}` | 1 000 / 1 036 / **1 105** (identical per calendar across both digests) | **1 105** |

Both figures are as A115 states. **Both are pinned by the same named test**,
which A115 does not say: `antseal_anchor::ots::tests::the_measured_upgrade_response_sizes_are_the_f4_row`
(`crates/antseal-anchor/src/ots/mod.rs:126`) asserts all six upgrade lengths
**per file**, asserts the per-calendar equality across digests, asserts
`largest == MEASURED_MAX_UPGRADE_RESPONSE_BYTES`, and asserts
`fixtures::CALENDAR_CATALLAXY_A.len() == 220` in the same body. The 220 is
pinned a second time by `crates/antseal-anchor/src/testing/replay.rs`'s
`the_committed_captures_have_their_recorded_shapes`. Run:

```
cargo test -p antseal-anchor --lib ots::tests
  the_measured_upgrade_response_sizes_are_the_f4_row ... ok
  the_discriminator_bodies_are_the_measured_ones ... ok
  2 passed
```

**One asymmetry in the evidence, in the upgrade's favour, that nobody has
recorded.** The upgrade figure's sample is **complete and committed**: six
bodies, six files, six per-file assertions. The submit figure's *"largest of
18"* is **prose-backed only** — six of the eighteen are committed, and the
other twelve exist as a sentence in D54 §8b. So the class this row is
currently keyed to is the one whose sample the tree cannot check, and the
class it is being re-keyed to is the one it can.

### 1.2 The arithmetic, at the precision each cell prints

Recomputed with the checker's own integer expression,
`(value * 10^d * 2 + measured) / (measured * 2)`, ported and run:

| keying | exact | at 2 dp |
| --- | --- | --- |
| submit, 65 536 / 220 | 297.890909… | **297.89x** |
| upgrade, 65 536 / 1 105 | 59.308597… | **59.31x** |

Both figures in A115 are correct. The column's history of being wrong (A113
found `298.0x` against an arithmetic of 297.8909 — wrong at one decimal place
*and* at two) does not repeat here.

### 1.3 What the limit is for, and where it is enforced

`MAX_OTS_CALENDAR_RESPONSE_BYTES` (`crates/antseal-anchor/src/ots/mod.rs:99`)
is an **alias** for `crate::http::OTS_CALENDAR_RESPONSE_CAP_BYTES`
(`http.rs:193`), not a second literal. It reaches the wire at exactly two
sites, both as `HttpRequest::receive_cap_bytes`:

| site | request | class |
| --- | --- | --- |
| `crates/antseal-anchor/src/ots/submit.rs:343` | `POST <calendar>/digest` | submit |
| `crates/antseal-anchor/src/ots/upgrade.rs:213` | `GET <calendar>/timestamp/<hex>` | upgrade |

`grep -n 'receive_cap_bytes' -r crates/ --include=*.rs` returns no third
production site for this constant. It is applied in `http.rs:841`,
`.limit(read_limit(request.receive_cap_bytes))`, where `read_limit` is
`cap + 1` because `ureq`'s `.limit(N)` admits at most `N − 1` — so **65 536
is the true admitted maximum** and 65 537 is a typed `OversizeBody`, never a
truncation.

**So the brief's alternative reading is the correct one, and it strengthens
rather than weakens the ruling.** This limit bounds *any single calendar HTTP
response*, not a particular request class. That is precisely why its margin
must be keyed to the **largest** class it admits: a cap that governs two
shapes is only as generous as its worst shape, and quoting the smaller one
overstates the headroom by 5.02x. A per-class limit could honestly carry a
per-class margin; a shared limit cannot.

### 1.4 The complete set of reply classes — and it is two, for a reason A115 never checked

The brief is right to ask whether *submit* and *upgrade* are the whole set.
They are, and the boundary is sharper than "no other callers":

- **Non-2xx bodies are not a third class.** `http.rs:815-830` reads an error
  body under `HTTP_ERROR_BODY_CAP_BYTES` (`http.rs:161`, 4 KiB) and **not**
  under `request.receive_cap_bytes` — the read is
  `.limit(read_limit(HTTP_ERROR_BODY_CAP_BYTES)).reader().take(HTTP_ERROR_BODY_CAP_BYTES)`
  inside `if !(200..300).contains(&status)`, and so does the
  `AnchorHttpError::Status` doc comment: *"Bounded by
  [`HTTP_ERROR_BODY_CAP_BYTES`], **not** by the request's own
  `receive_cap_bytes`"*. So A14's three-way upgrade discriminator — the 9-byte
  `Not found` and the 42-byte `Pending confirmation in Bitcoin blockchain`,
  both committed and both pinned by `the_discriminator_bodies_are_the_measured_ones`
  — is governed by a different cap and contributes nothing to this row.
- **No other request class exists.** `calendars.rs` declares exactly two paths,
  `OTS_SUBMIT_PATH = "digest"` and `OTS_UPGRADE_PATH_PREFIX = "timestamp/"`.
  There is no probe, no HEAD, no index fetch.

Two classes, both measured, one binding. That is a complete enumeration, and
§5's note paragraph should carry it so the next reader does not re-derive it
(edit **E3**).

### 1.5 D54 §6.1 did not assign this decision — it made it

The brief's premise is that D54 §6.1 *assigned* the keying question. Read in
full, §6.1 **answers** it:

> Margin: 65 536 / 220 = **298×** against the largest of 18 measured real
> submit responses. The upgrade response is larger (it carries a Bitcoin
> merkle path) and has **not** been measured; A25's two-day protocol must
> record it and the F4 row must be completed with that figure before M2
> closes.

*"That figure"* has one referent: the upgrade response's size. §9 finding 3 of
the same decision repeats the obligation from the other end — *"the runbook
must record the **upgrade** response size … which the F4 row in §7 needs"*.
The 298× in D54 §7's verbatim row is therefore **the provisional value §6.1
declares provisional in the same document**, not a competing ruling.

**What was actually open was the discharge, and it is 7 days overdue.** The
measurement landed 2026-08-03T09:03Z. A113 corrected the cell's false *"has
not been measured"* claim and its arithmetic on 2026-08-10 and explicitly left
the keying, which was right — but the thing it left was an execution step, not
a fork.

### 1.6 The registry cell is the only artefact in the tree keyed to the submit reply

`grep -rn '297\.89\|59\.31\|298x\|298×\|59\.3'` over the tree, excluding
`target/`, returns the keying claim in six places. Five say upgrade:

| where | what it says |
| --- | --- |
| `docs/decisions/D54…md:331-335` (§6.1) | the row *"must be completed with that figure"* |
| `docs/decisions/D54…md` §9 finding 3 | *"which the F4 row in §7 needs"* |
| `testdata/anchors/A25-bootstrap/OTS-BOOTSTRAP.md:96-98` | *"The largest, 1 105 B, is the figure A42's F4 margin row was left blank for: **59.3×**"* |
| `crates/antseal-anchor/src/ots/mod.rs:88-91` | *"The governing figure is the largest: 1 105 B, a 59.3× margin … and **it is the figure the F4 row takes**"* |
| `crates/antseal-anchor/src/testing/replay.rs`, `UPGRADE_A_CATALLAXY`'s doc | *"the largest of the six and **the figure A42's F4 margin is completed from**"* |

One says submit: `docs/format/anchor-artifact-limits.md:228`, the `margin`
cell, `297.89x (submit)`.

**This is A106's finding repeating one file over**, and A106's own sentence is
the diagnosis: *"a correction landed in one of two places is a correction that
has not happened."* Here it landed in five and missed the one that is
normative. `crates/antseal-anchor/src/ots/mod.rs:89-90` is not merely
consistent with the ruling — it is a **claim about the registry that the
registry currently falsifies**, and the re-key is what makes it true.

### 1.7 What no instrument reaches, and it is the reason this record ships a test

`the_margin_column_is_the_value_over_the_measurement`
(`crates/antseal-core/src/anchor/ots/limits.rs:978`) is deliberately
**document-internal arithmetic**: it divides the row's `value` cell by the
first bolded number in the row's `measured against` cell and compares to the
`margin` cell at the precision that cell prints. Its own module comment states
the boundary — *"Both operands are pinned elsewhere, each by a named test, and
neither pin is here."*

The consequence, measured rather than assumed: **the checker is green for
either keying.** `297.89x` over a `**220**` cell and `59.31x` over a `**1 105**`
cell are both internally consistent. A lane that re-keys *both* cells back to
the submit reply passes every test in the tree today. That is not a defect in
A113's checker — it is the exact scope A113 recorded for itself — but it means
this ruling has no enforcement without one, which is §6.

Run, before any change:

```
cargo test -p antseal-core --lib limits
  10 passed; 0 failed   (the_margin_column_is_the_value_over_the_measurement ... ok)
```

---

## 2. RULING 1 — the margin divides by the **upgrade** reply: **59.31x**

**The `margin` cell reads `59.31x (upgrade)`. The `measured against` cell's
first bolded number is `**1 105**`, the largest measured upgrade body. The
submit reply is named in the same cell, in prose, unbolded, and is not stated
as a margin anywhere in this table.**

Three grounds, in order of force:

1. **D54 §6.1 already ruled it** (§1.5). Keeping the submit keying is not a
   choice between two open options; it is a refusal to execute a ratified
   decision, and it would require amending D54 against the evidence D54 asked
   for and got.
2. **A shared cap is only as generous as its worst admitted shape** (§1.3).
   The constant bounds *one HTTP reply*, not *one submit reply*. 297.89x
   describes headroom the network stage does not have.
3. **The binding class is the one whose sample is committed and pinned per
   file** (§1.1). Re-keying moves the margin onto the better-evidenced of the
   two measurements, not merely the larger one.

### 2.1 Why "keep the submit keying" is wrong, not merely worse

It publishes a headroom figure 5.02x larger than the true measured worst case,
in the one table this project treats as the authority on limit headroom, for a
limit whose own owner-decision says the figure is provisional. And it is
**self-refuting in the same document**: the cell A113 left behind already
records *"margin **59.31x** — the binding one"* inside `measured against`
while the `margin` column prints 297.89x. A row that names the binding margin
in one cell and prints a different one in the next is not a conservative
choice; it is the same class of defect as the *"has not been measured"*
sentence A113 deleted, moved one column left. Nothing in the tree argues for
it: the sole record supporting it is the cell itself.

### 2.2 Why "record both" — A115's own Notes float, and the brief's option (c) — dies

A115's Notes say *"a limit with two measured reply classes arguably owes both
numbers."* The instinct is right and the placement is what kills it. Both
numbers **are** owed; the `margin` column is not where the second one goes.

- **§5's Update rule permits exactly one keyed number per row**, and the
  reason is written into the rule in A113's own words: the convention exists
  *"because until then `margin` was the only numeric column in this table no
  test reached, and a number that reads like the checked ones and is checked
  by nothing is worse than an absent one — it is quoted with their
  authority."* A second margin in that cell would be **unreachable by
  construction**: `printed_margin` reads the *leading* `N.MMx` and ignores
  everything after the `x`. So `59.31x (upgrade; 297.89x submit)` ships a
  number with the column's authority and none of its checking — manufacturing,
  in the same edit, the precise defect A113 landed to remove.
- **It re-creates the A109 failure mode by name.** D104 §4 records A109
  reasoning from a 15.28x margin that was real-looking, unchecked and wrong.
  A second, unchecked margin in the row is a 15.28x waiting to be quoted.
- **It answers a question nobody has.** A margin exists to say *how close the
  worst real artifact comes to the cap*. There is one worst real artifact for
  one cap. The lesser class's size is a fact about the lesser class, not a
  headroom claim about the limit.

**Both numbers are therefore recorded — asymmetrically and deliberately.** The
upgrade figure is bolded, keyed, and cross-checked. The submit figure is named
in the same cell, **unbolded** (so `measured_quantity` cannot reach it) and
**not formatted as a margin**, exactly as `MAX_OTS_OPERAND_BYTES` and
`MAX_OTS_VALUE_BYTES` already name their non-binding alternative measurements
in prose. This is the table's existing convention, not a new one.

---

## 3. RULING 2 — the value does **not** change: `MAX_OTS_CALENDAR_RESPONSE_BYTES` stays 65 536

Stated explicitly rather than left inferred, because the brief is right that
"59.31x is still large" is a claim and not a self-evident one.

**Nothing is close to the cap.** The largest admitted shape is 1 105 B —
**1.69 %** of 65 536. The other class peaks at 220 B (0.34 %). Non-2xx bodies
are on a 4 KiB cap elsewhere (§1.4). There is no reply class within an order
of magnitude of the ceiling.

**The lowering window is open and is deliberately not taken.** F4 sentence 1
makes limits raise-only *after first release*, and D104 §2.1 ruled no release
has occurred, so this cap could be lowered today on the same reading that
kept `MAX_OTS_DEPTH`'s window open. It is not, for four measured reasons:

1. **A lowering buys nothing structural.** The row's `structural cost` cell
   reads **none**, and it is correct: this is a receive-side byte cap on a
   transient read buffer sized by bytes actually received, not a container
   reserved from the bound. D102's rule-6 precondition governs *count* limits
   and does not reach it. The entire saving from lowering is worst-case
   transient heap: at most `4 × 65 536 = 256 KiB` across the four concurrent
   calendars, in a process that already handles a 1 MiB `MAX_OTS_BYTES`
   artifact. That is not a memory argument; it is a rounding error.
2. **The sample does not cover the production endpoints.** `DEFAULT_OTS_CALENDARS`
   (`calendars.rs:28-33`) is `a.pool.opentimestamps.org`,
   `b.pool.opentimestamps.org`, `a.pool.eternitywall.com`,
   `ots.btc.catallaxy.com`. The A25 captures were taken against
   `{alice,bob}.btc.calendar.opentimestamps.org` and
   `btc.calendar.catallaxy.com`, and `calendars.rs:6-13` says so in its own
   module docs: *"They are **not** the `*.btc.calendar.opentimestamps.org`
   hosts the A25 bootstrap capture used."* **Zero of the four shipped default
   endpoints has ever had either reply class measured**, and eternitywall has
   never been measured at all. Shaving a cap to a sample that covers none of
   the production endpoints is over-fitting.
3. **The upgrade body's size is load-dependent, not fixed.** It carries a
   merkle path from the calendar's aggregation root to a Bitcoin block, whose
   length grows with the calendar's per-cycle submission volume. The six
   captures are one instant, 13 h 47 m after one stamping. Their equality per
   calendar across two digests shows the shape is stable *within* a cycle; it
   is not evidence of an upper bound *across* cycles. (Mechanism, argued from
   the OTS aggregation model, not measured here — and that is exactly why the
   margin is left generous rather than tightened.)
4. **The failure mode of "too low" is evidence loss.** An over-cap upgrade
   reply is a typed `OversizeBody` error, so the upgrade never completes and
   the anchor stays pending — for a *real* proof that exists on Bitcoin. The
   failure mode of "too high" is reading 64 KiB from a TLS peer. These are not
   comparable harms.

**And 65 536 was already chosen against exactly this trade-off.** D54 §8b's
argument was *"65 536 can be raised later if a real artifact ever needs it;
1 MiB can never be lowered"* — the reversibility argument, applied to the
choice between the measured value and the artifact cap. Applying it a second
time to shave 65 536 toward 1 105 inverts it: the measurement is now known to
be a 3-calendar, single-instant, non-production sample, which is the case for
headroom rather than against it.

**No constant moves. `crates/antseal-anchor/src/ots/mod.rs:99`, `:104` and
`crates/antseal-anchor/src/http.rs:193` are untouched, and so is the `const`
block at `ots/mod.rs:106-114`** — its `> MEASURED_MAX_UPGRADE_RESPONSE_BYTES * 59`
assertion is already the upgrade keying expressed as a compile-time fact, and
it needs no change.

---

## 4. RULING 3 — the exact replacement row

**Verbatim. Replace the whole of `docs/format/anchor-artifact-limits.md`
line 228 with the single line below.** Eight cells, nine pipes, no cell
contains a `|`.

```
| `MAX_OTS_CALENDAR_RESPONSE_BYTES` | A42 | 65_536 | 2026-08-02 | `testdata/anchors/A25-bootstrap/upgraded/A-catallaxy.upgrade` (**1 105** B — the largest of the six real calendar *upgrade* replies, captured 2026-08-03T09:03Z, pinned per file as `antseal_anchor::ots::MEASURED_MAX_UPGRADE_RESPONSE_BYTES` by `the_measured_upgrade_response_sizes_are_the_f4_row`). **The upgrade reply is the binding one of the two reply classes this cap governs**, and D54 §6.1 ruled it so before either was measured: it recorded the submit figure as provisional and required that *"the F4 row must be completed with that figure"*. The other class is the *submit* reply, largest 220 B at `testdata/anchors/A25-bootstrap/A-catallaxy.timestamp` — 5.02x smaller, pinned by the same test, and no longer a margin this table states. Re-keyed from the submit reply to the upgrade reply by A115 under D110, 2026-08-10; `value`, `date set` and `lowered` are untouched, so §6 owes no entry | 59.31x (upgrade) | never | **none** — a receive-side byte cap, not a count limit |
```

**Cell-by-cell, so nothing is edited by accident:**

| cell | value | changed? |
| --- | --- | --- |
| `limit` | `` `MAX_OTS_CALENDAR_RESPONSE_BYTES` `` | no |
| `owner` | `A42` | no — `the_eighth_registry_row_is_a42s_and_this_crate_cannot_pin_its_value` needles `` | `MAX_OTS_CALENDAR_RESPONSE_BYTES` | A42 | `` |
| `value` | `65_536` | **no** (RULING 2) |
| `date set` | `2026-08-02` | **no** — this records when the *limit* was set, not when a cell was edited. The limit has not moved |
| `measured against` | above | **yes** — re-pointed to the upgrade fixture; first bolded number is now `**1 105**` |
| `margin` | `59.31x (upgrade)` | **yes** — was `297.89x (submit)` |
| `lowered` | `never` | **no** |
| `structural cost` | `**none** — a receive-side byte cap, not a count limit` | no |

**The convention the cell must satisfy, and the proof that it does.** §5's
Update rule requires *"the first bolded number in the cell is the measured
quantity the `margin` divides by"* (A113, 2026-08-10). **The convention does
not change**; the cell is written to satisfy it. The two parsers in
`limits.rs` were ported and run against the replacement row before it was
written into this record:

```
cells: 10   value: 65536   measured: 1105   printed: (5931, 2)
recomputed: 59.31x   MATCH
bold spans seen: ['1 105', 'The upgrade reply is the binding one of …']
```

Three properties make that hold, and an implementer must not break them:

- `**1 105**` is the **first** bold span in the cell. `measured_quantity`
  strips spaces and a trailing `" B"`, so `1 105` parses as `1105`; the `B`
  may sit inside or outside the bold.
- **No earlier bold span may be a bare number.** The date `2026-08-03T09:03Z`
  is unbolded in the replacement text precisely so this cannot regress; the
  old cell survived only because `2026-08-03` contains `-` and was rejected by
  accident.
- **The 220 is unbolded and is not written as `N.NNx`.** That is what makes it
  a fact about the lesser class rather than a second, unchecked margin (§2.2).

---

## 5. RULING 4 — §6 owes **no** entry, and D107 R1 says so verbatim

**No §6 entry. Adding one would be wrong, not merely unnecessary.**

The brief's summary of D107 — *"§6's rule fires on lowering alone"* — is the
rule D107 **replaced**, not the rule D107 made. D107 §3 moved the obligation
*off* lowering and *onto* any change to a limit's recorded value, and D107 R1
defines the term and enumerates the exclusions:

> **A commit may not change a limit's recorded value in §5 without adding a §6
> entry naming that limit.** "Recorded value" means the `value` cell or the
> `lowered` cell, and nothing else.
>
> | change | §6 duty | why |
> | correcting `measured against`, `margin` or `structural cost` | none | these are things learned **about an unchanged limit** |
>
> **§6 records what a limit *is*, never what we have learned about it.**

This edit changes `measured against` and `margin`, and nothing else. That is
the second row of R1's own exclusion table, by name. The rule is already
carried in `docs/format/anchor-artifact-limits.md` §5's Update rule in the
same words, so the next reader does not need this record to find it — but this
record is the first change after D107 and the ruling is stated so the question
is not re-opened.

**And it is enforced in both directions**, which is the part worth knowing:
`the_limit_change_log_agrees_with_the_registry_rows` is bidirectional — *"an
entry claiming a move the table does not corroborate is red too"*. A lane that
writes a §6 entry for this re-key out of caution **reddens the gate**, because
§5's value cell has not moved. So the ruling is not advisory: the wrong answer
here fails CI.

---

## 6. RULING 5 — what goes red on a re-key back: `the_f4_row_is_keyed_to_the_upgrade_reply_not_the_submit_reply`

**A113's checker is not the answer to this question.** It catches an
*inconsistent* re-key (margin moved, measurement not) and is green for a
*consistent* one (§1.7). The keying itself is unpinned, and a ruling with no
instrument is the F19 → F14 shape this document exists to prevent.

**The new test lands in `crates/antseal-anchor/src/ots/mod.rs`'s `mod tests`,
because that is the only crate that can see both the document and the
measurement.** `the_eighth_registry_row_is_a42s_and_this_crate_cannot_pin_its_value`
already records why it cannot live in `antseal-core`: *"a pin written here
could only compare the row against a literal typed in this file, which is the
defect A110's notes name in `caps.rs`'s own `f4_registry_values`: an
instrument that checks a number against itself."* From `antseal-anchor` both
operands are real — the document supplies one, `MEASURED_MAX_UPGRADE_RESPONSE_BYTES`
(itself asserted per file, four lines up) supplies the other. **Literal-free
on both sides.**

**Placement, exactly:** anywhere strictly **below** line 126 of
`crates/antseal-anchor/src/ots/mod.rs`, so that
`crates/antseal-core/tests/doc_pointer_liveness.rs`'s allowlist justification
*"lives in the antseal-anchor crate at src/ots/mod.rs:126"* stays accurate. Do
not insert lines above it.

```rust
    /// **A115/D110.** §5's A42 row is keyed to the **upgrade** reply.
    ///
    /// `the_margin_column_is_the_value_over_the_measurement` (antseal-core)
    /// recomputes `value / measured` *inside* the document, so it is green
    /// for **either** keying as long as the two cells agree: a lane that
    /// re-keys both back to the 220-byte submit reply passes it. That is the
    /// boundary that test records for itself — both operands are pinned
    /// elsewhere and neither pin is there. This is the pin for the operand.
    /// Literal-free on both sides: the document supplies one number and
    /// [`MEASURED_MAX_UPGRADE_RESPONSE_BYTES`], asserted per file above,
    /// supplies the other.
    #[test]
    fn the_f4_row_is_keyed_to_the_upgrade_reply_not_the_submit_reply() {
        const REGISTRY: &str = include_str!("../../../../docs/format/anchor-artifact-limits.md");

        let row = REGISTRY
            .lines()
            .find(|line| line.starts_with("| `MAX_OTS_CALENDAR_RESPONSE_BYTES` | A42 |"))
            .expect("§5's A42 row is gone or has changed owner");
        let cells: Vec<&str> = row.split('|').collect();
        assert_eq!(
            cells.len(),
            10,
            "§5's A42 row is not eight cells; the margin cross-check reads it positionally"
        );

        // §5's Update rule: the first bolded number in `measured against` is
        // the measured quantity the margin divides by. The same convention as
        // A113's checker, read from the other side of the crate graph.
        let measured: u64 = cells[5]
            .split("**")
            .skip(1)
            .step_by(2)
            .filter_map(|span| {
                let token = span.trim().trim_end_matches(" B").replace(' ', "");
                (!token.is_empty() && token.chars().all(|c| c.is_ascii_digit()))
                    .then(|| token.parse().ok())
                    .flatten()
            })
            .next()
            .expect("§5's Update rule requires the measured quantity in bold");

        assert_eq!(
            measured,
            MEASURED_MAX_UPGRADE_RESPONSE_BYTES,
            "§5's `MAX_OTS_CALENDAR_RESPONSE_BYTES` row divides by {measured}, not by the \
             largest measured upgrade reply ({MEASURED_MAX_UPGRADE_RESPONSE_BYTES} B). D110 \
             keys this row to the *upgrade* class: it is the binding one of the two classes \
             this cap governs, and D54 §6.1 required the row to be completed with it. {} B \
             is the largest *submit* reply — the lesser shape, and re-keying to it restores \
             the 297.89x margin A115 exists to retire",
            fixtures::CALENDAR_CATALLAXY_A.len(),
        );

        // The label and the arithmetic must name the same class. A margin cell
        // reading `(submit)` over an upgrade-keyed measurement is the defect
        // this row carried for seven days, one column to the left.
        assert!(
            cells[6].contains("upgrade"),
            "§5's A42 margin cell {:?} does not name the reply class it divides by",
            cells[6]
        );
    }
```

**What each assertion catches, so the lane can confirm the arms rather than
trust them:**

| mutation | which assertion |
| --- | --- |
| both cells re-keyed to the submit reply (`**220**` + `297.89x (submit)`) — **green today** | `assert_eq!(measured, MEASURED…)`, naming both numbers and the reason |
| the row deleted or its owner changed | `.expect("§5's A42 row is gone…")` |
| a bold number inserted ahead of `**1 105**` (e.g. re-bolding the date) | `assert_eq!(measured, MEASURED…)` |
| the bold dropped from `1 105` | `.expect("…requires the measured quantity in bold")` |
| the margin cell relabelled `(submit)` while the measurement stays upgrade | `assert!(cells[6].contains("upgrade"))` |
| a `|` introduced into a cell | `assert_eq!(cells.len(), 10, …)` |

**The class label *is* asserted, and that is deliberate against §6's
don't-pin-prose principle.** §6 refuses to parse *reasons*; a reply-class name
is not a reason, it is the fact this whole record decides, and it is the only
place the class appears in a position a checker can read. Without it the row
can print `(submit)` over upgrade arithmetic — the defect A113 found, moved one
column.

**`include_str!` depth:** `crates/antseal-anchor/src/ots/mod.rs` →
`../../../../docs/…` is four levels to the repo root, the same depth
`src/testing/replay.rs` already uses for `../../../../testdata/…`.

---

## 7. RULING 6 — provenance: inline in `measured against`, no new column

**§5 rows carry no provenance line and must not gain one.** The convention is
already established and is **inline in the `measured against` cell**, present
when a cell has been re-pointed and absent when it is original:

| row | provenance carried |
| --- | --- |
| `MAX_OTS_OPS`, `MAX_OTS_DEPTH`, `MAX_OTS_ATTESTATIONS` | *"re-measured by A48 2026-08-10"* |
| `MAX_OTS_OPERAND_BYTES`, `MAX_OTS_VALUE_BYTES` | *"(A48, 2026-08-10)"* |
| the four DER rows | source citation only (`D60 §6 b1`…) — never re-pointed |

**The exact string this row takes**, already inside RULING 3's cell text and
repeated here so it is not paraphrased:

> Re-keyed from the submit reply to the upgrade reply by A115 under D110,
> 2026-08-10; `value`, `date set` and `lowered` are untouched, so §6 owes no
> entry

It names **what changed**, **under whose authority**, **when**, and **what
deliberately did not change** — the last clause because a reader who sees a
margin move by 5x will ask whether the limit moved, and the answer belongs in
the cell rather than in a `git log` archaeology session. A ninth column is
refused: A113 already established that this table gains conventions inside
existing cells rather than columns, and a column with one populated cell out
of twelve is a column nothing checks.

---

## 8. Consequences — the exact edit set

One commit. Five edits, all mechanical after the rulings above.

| # | file | edit | rider |
| --- | --- | --- | --- |
| **E1** | `docs/format/anchor-artifact-limits.md:228` | replace the whole line with RULING 3's row, verbatim | RULING 1, 3, 7 |
| **E2** | `docs/format/anchor-artifact-limits.md:284-285` (§5, the A48 margin-band sentence) | see below | RULING 1 |
| **E3** | `docs/format/anchor-artifact-limits.md:234-240` (the note paragraph under the table) | see below | §1.4 |
| **E4** | `crates/antseal-anchor/src/ots/mod.rs`, `mod tests`, below line 126 | add `the_f4_row_is_keyed_to_the_upgrade_reply_not_the_submit_reply` verbatim from §6 | RULING 5 |
| **E5** | `crates/antseal-anchor/src/testing/replay.rs`, `CALENDAR_CATALLAXY_A`'s doc comment | see below | §1.6 |

> **Locate E5 by content, not by line.** `replay.rs` is being rewritten by a
> concurrent lane wiring A25's day-3 mainnet headers (measured 2026-08-10:
> `+333 −6` uncommitted, moving this doc comment from `:95-97` to `:172-174`
> in the working tree). Anchor on the string
> `the fixture the F4 row for` and on the `CALENDAR_CATALLAXY_A` item; do not
> trust any line number for this file, including the one in the transcript
> that discovered it.

**E2 — the margin band.** The sentence currently reads:

> The margin band is stated here rather than left to be rediscovered:
> **12.05x to 297.89x, and the floor is `MAX_OTS_DEPTH`.**

`297.89x` **is** the cell E1 re-keys, so this sentence cannot be left alone.
Recomputed from the live table (all twelve rows parsed and sorted): the eight
`.ots`/receive-side rows run 12.05x … 178.09x after the re-key, ceiling
`MAX_OTS_ATTESTATION_PAYLOAD_BYTES`; the whole table's floor is **2.0x**,
`MAX_CHAIN_CERTS`, which A110's four DER rows brought in on 2026-08-09 and
which this sentence has never accounted for. Replace with:

> The margin band is stated here rather than left to be rediscovered: over
> these eight `.ots` and receive-side rows, **12.05x to 178.09x, and the floor
> is `MAX_OTS_DEPTH`** — the ceiling moved down from 297.89x on 2026-08-10,
> when D110 re-keyed A42's row from the submit reply to the binding upgrade
> reply. Across the whole table the floor is lower still: A110's four DER
> rows, added 2026-08-09, put `MAX_CHAIN_CERTS` at **2.0x**.

**E3 — the note paragraph.** It currently ends the DoS sentence with the wrong
class's figure:

> … would let four calendars hand `antseal-anchor` 4 MiB per seal against a
> measured worst case of 220 B.

Replace that clause and append the class enumeration:

> … would let four calendars hand `antseal-anchor` 4 MiB per seal against a
> measured worst case of **1 105 B** — the *upgrade* reply, the larger of the
> two reply classes this cap governs and the one its margin is keyed to
> (D110). There is no third class: a non-2xx calendar body, including A14's
> two 404 upgrade discriminators, is capped by `HTTP_ERROR_BODY_CAP_BYTES`
> (4 KiB) on the error path and not by this limit.

*(This paragraph is prose, not a table row: no parser reads its bold spans.)*

**E5 — the fixture doc comment that inverts.** `CALENDAR_CATALLAXY_A`'s doc in
`replay.rs` reads *"…and the fixture the F4 row for
`MAX_OTS_CALENDAR_RESPONSE_BYTES` is measured against"* — **true today, false
after E1**. Leaving it is A106's
defect executed forwards instead of backwards. Replace with:

```rust
    /// A real pending calendar attestation (catallaxy, digest A, 220 B) —
    /// **the largest of the 18 measured** submit replies, and the fixture
    /// A42's F4 row was measured against until 2026-08-10, when D110 re-keyed
    /// the row to the binding *upgrade* reply ([`UPGRADE_A_CATALLAXY`],
    /// 1 105 B). It is now the lesser of the cap's two reply classes.
```

**Explicitly NOT edited, each with its reason** — recorded so the lane does
not go looking:

| not edited | why |
| --- | --- |
| `crates/antseal-anchor/src/ots/mod.rs:88-91` | already states *"it is the figure the F4 row takes"*. E1 makes it true; changing it would undo the ruling |
| `ots/mod.rs:99`, `:104`, `:106-114`, `http.rs:193` | RULING 2 — no constant moves, and the `> MEASURED_MAX_UPGRADE_RESPONSE_BYTES * 59` const assertion is already the upgrade keying |
| `ots/mod.rs:69-71`'s *"a 298x margin"* | it labels the **submit** measurement's own historical margin, and `:91` names it as such three lines later. Editing it shifts the lines above 126 that `doc_pointer_liveness`'s allowlist cites. The 298-vs-297.89 rounding drift is real and is filed as discovered work (§11), not fixed here |
| `docs/decisions/D54…md:331`, `:386` | a decision record is the ruling as made. §6.1 already declares :386 provisional; this record discharges it and `git log` is the history (D107 R3) |
| `docs/format/anchor-artifact-limits.md` §6 | RULING 4 — no entry, and writing one reddens `the_limit_change_log_agrees_with_the_registry_rows` |
| `testdata/anchors/A25-bootstrap/OTS-BOOTSTRAP.md:96-98` | already correct (*"the figure A42's F4 margin row was left blank for: 59.3×"*) |

**Verification, in order:**

```
cargo test -p antseal-core   --lib limits          # 10 tests; the margin cross-check re-reads E1
cargo test -p antseal-anchor --lib ots::tests      # 3 tests after E4
cargo fmt --check && cargo clippy --all-targets -- -D warnings
scripts/local-gate.sh                              # 22 lanes
```

**The negative arm must be executed by hand once and reported, not assumed**
(A104's rule): revert E1's `measured against` and `margin` cells to
`**220**` / `297.89x (submit)`, confirm `the_margin_column_is_the_value_over_the_measurement`
stays **green** (this is the gap being closed) and
`the_f4_row_is_keyed_to_the_upgrade_reply_not_the_submit_reply` goes **red**
naming both figures, then restore. A pass without that observation is a test
whose arm nobody has seen.

---

## 9. Sequencing with A114 — same file, no shared paragraph

The implementing lane owns **A114** as well. Measured overlap:

| | D110/A115 touches | A114 touches |
| --- | --- | --- |
| §5 table, A42 row (`:228`) | **yes** (E1) | no |
| §5 prose, A48 margin band (`:284-285`) | **yes** (E2) | no |
| §5 prose, note under the table (`:234-240`) | **yes** (E3) | no |
| §5a heading banner (`:316` + the `Added 2026-08-07 by D102` line under it) | no | **yes** |
| §5a structural-cost prose (native/wasm32 `Frame`) | no | **yes** |
| `MAX_OTS_DEPTH` row's `structural cost` cell | no | possibly |

**Two further contentions this record can see but not resolve**, both observed
from `git status` at planning time and neither read:

- **`crates/antseal-anchor/src/testing/replay.rs` is uncommitted-dirty**
  (`+333 −6`, A25 day-3 mainnet headers). E5 lands in that file. Locate it by
  content (§8) and rebase rather than apply by line.
- **A concurrent planner has created `docs/decisions/D111-registry-prose-cross-check.md`.**
  Its slug names *registry prose*, and **E2 edits registry prose that nothing
  checks** — the §5 margin-band sentence, which is also §11 item 1 here. If
  D111 rules an instrument over §5's prose, E2's replacement text is a
  candidate input to it and the two must not be written twice. This record
  claims only the sentence, not the instrument.

**No shared paragraph, but the same file.** Sequence: apply D110's E1–E3
first, then A114's §5a edits, then run `cargo test -p antseal-core --lib
limits` **once, after both** — five tests in that module `include_str!` the
same document and a half-applied pair produces a failure that blames the wrong
edit. If A114 states the wasm32 asymmetry inside `MAX_OTS_DEPTH`'s
`structural cost` cell rather than in §5a prose, it must keep that cell's
existing bold spans clear of the `measured against` column — the two columns
are parsed independently, so there is no interaction, but the row must still
hold nine pipes.

---

## 10. Kill criteria

This ruling is wrong, and must be re-opened, if any of these is shown:

1. **A third production reply class exists** under `MAX_OTS_CALENDAR_RESPONSE_BYTES`
   — i.e. a `receive_cap_bytes: MAX_OTS_CALENDAR_RESPONSE_BYTES` site outside
   `submit.rs:343` and `upgrade.rs:213`. §1.4 measured two; a third would
   re-open which is binding.
2. **A real upgrade reply above 1 105 B is captured**, in particular from any
   of the four `DEFAULT_OTS_CALENDARS` endpoints, none of which has been
   measured (§3 reason 2). That re-keys the *number*, not the *class*: the
   ruling survives and the cell's operand moves, which is exactly what E4's
   test makes noisy.
3. **`HTTP_ERROR_BODY_CAP_BYTES` is removed** or the non-2xx path is changed
   to read under `request.receive_cap_bytes`, making error bodies a third
   class of this limit.
4. **D54 §6.1 is amended** to key the row to the submit reply. Nothing in the
   tree proposes this and four records contradict it, but it is the only
   authority that could overturn RULING 1.
5. **§5's Update rule drops the first-bolded-number convention.** RULING 3's
   cell text and E4's test both read it. The convention is A113's and this
   record deliberately does **not** change it.

---

## 11. Discovered work — described, not numbered

Each of these was found while measuring this record and is outside A115's
scope. None is fixed here.

1. **The §5 margin-band sentence has never covered the whole table.** It reads
   *"the floor is `MAX_OTS_DEPTH`"* at 12.05x while `MAX_CHAIN_CERTS` has sat
   at **2.0x** since A110 added the four DER rows on 2026-08-09 — and the
   surrounding paragraph says *"any future reader quoting a '≥ 15x' discipline
   over **this table**"*, so a reader takes the band as table-wide. E2 repairs
   the sentence because the number it quotes is the one being re-keyed, but
   the broader question — whether the `.ots` and DER halves should state
   separate margin disciplines at all, given the DER rows run 2.0x–7.8x by
   construction — is unowned. Nothing checks this sentence.
2. **`298x` vs `297.89x`: a rounding the checker would reject, in five
   places.** `crates/antseal-anchor/src/ots/mod.rs:71` and `:91`,
   `crates/antseal-anchor/src/http.rs:187`, `docs/decisions/D90…md:912` and
   `:1252`, and `docs/decisions/D54…md:331` and `:386` all print the submit
   margin as `298x`/`298×`. A113's checker rejects that spelling in a table
   cell (it found and corrected exactly `298.0x`), but nothing reaches a doc
   comment. Two of the five are decision records and should stay; the three
   code-doc occurrences are a one-line sweep. Deliberately not bundled here
   because editing `ots/mod.rs` above line 126 shifts a line another crate's
   allowlist cites.
3. **The submit figure's *"largest of 18"* is prose-backed and uncheckable.**
   Six of the eighteen submit bodies are committed; the other twelve exist
   only as a D54 §8b sentence. After this ruling the number is demoted to a
   non-binding fact, so the exposure is small — but the same claim appears in
   `replay.rs:95-96` as **the largest of the 18 measured** in bold, which
   reads as a pinned figure and is not one.
4. **`the_margin_column_is_the_value_over_the_measurement`'s keying blindness
   is now documented but only pinned for one row.** E4 pins A42's keying. The
   other eleven rows have the same property: a lane can re-point `measured
   against` to a different artifact and move `margin` to match, and every test
   stays green. A48 hit precisely this on `MAX_OTS_OPERAND_BYTES` and
   `MAX_OTS_VALUE_BYTES` and resolved it by *judgement* (keeping the fatter
   third-party sample rather than flattering the margin). Whether the other
   eleven rows want per-row keying pins, or a rule stated once in §5, is
   unowned.
5. **`crates/antseal-anchor` has no `doc_pointer_liveness` sweep.** Its doc
   comments carry cross-file claims about the registry — two of which this
   record found stale or about to go stale (`replay.rs:95-97`) — and nothing
   checks them. The core crate's sweep names widening as an existing open
   question; this is a second, independent motive for it.

---

## 12. What this record does not decide

- **Whether A25 should re-capture against `DEFAULT_OTS_CALENDARS`.** D54 §9
  finding 4 already raises it. §3 reason 2 uses the gap as an argument for
  headroom, not as a demand for a capture.
- **`MAX_OTS_BYTES`, `HTTP_ERROR_BODY_CAP_BYTES`, `TSA_RESPONSE_CAP_BYTES`,
  `ESPLORA_RESPONSE_CAP_BYTES`, `RPC_RESPONSE_CAP_BYTES`.** Only the first has
  an F4 row; A28 still owes rows for the TSA and merged-`.ots` receive-side
  caps, and their margins will face this same keying question with more than
  one class each. §2's reasoning transfers; no ruling is made for them.
- **The other eleven rows' lowering windows.** Open on D104 §2.1's reading and
  untouched here.
- **A114.** §9 sequences it; it decides nothing this record decides.

---

## Outcome

**RESOLVED, 2026-08-10.** The margin divides by the **upgrade** reply:
**59.31x**, keyed to the 1 105-byte catallaxy body, `margin` cell
`59.31x (upgrade)`, `measured against` re-pointed with `**1 105**` as its
first bolded number. **The brief's framing is overturned**: this was never an
open substantive question — **D54 §6.1 ruled it on 2026-08-02** (*"the F4 row
must be completed with that figure before M2 closes"*) and four further
records agree, so the registry cell is the **only** artefact in the tree
carrying the submit keying and one of the five it contradicts is a code doc
asserting *"it is the figure the F4 row takes"*. What was open was a discharge,
seven days overdue. **The "record both" option is refused** not on taste but
on §5's own Update rule: `printed_margin` reads only the *leading* `N.MMx`, so
a second margin in that column ships a number with the column's authority and
none of its checking — manufacturing the defect A113 landed to remove and
re-creating the 15.28x that injured A109. Both figures are still recorded, the
submit one **unbolded and not formatted as a margin**, which is the table's
existing convention for a non-binding measurement. **`MAX_OTS_CALENDAR_RESPONSE_BYTES`
stays 65 536**: the largest admitted shape is **1.69 %** of the cap, the
structural cost is genuinely none, a lowering saves at most 256 KiB of
transient heap, and — the measured reason — **zero of the four shipped
`DEFAULT_OTS_CALENDARS` endpoints has ever had either reply class captured**,
because the A25 bootstrap used hosts D54's default list deliberately excludes.
**§6 owes no entry**, by D107 R1's exclusion table verbatim, and writing one
out of caution reddens the bidirectional log checker. **The ruling ships with
an instrument**, because A113's cross-check is document-internal arithmetic
and a *consistent* re-key back to the submit reply passes every test in the
tree today: `the_f4_row_is_keyed_to_the_upgrade_reply_not_the_submit_reply`
lands in `antseal-anchor` — the only crate that can see both the document and
the measurement — and is literal-free on both sides. **No constant moves.**

---

## Index row (orchestrator applies at merge)

| [D110](D110-calendar-response-margin-reply-class.md) | A115 — which reply class `MAX_OTS_CALENDAR_RESPONSE_BYTES`' margin divides by — **the UPGRADE reply, 59.31x, and the question was already ruled.** A115 and the brief both frame the keying as *"a substantive ruling D54 §6.1 assigned"*; read in full, **D54 §6.1 made it** on 2026-08-02 — *"the F4 row must be completed with that figure before M2 closes"* — and D54 §9 finding 3, `OTS-BOOTSTRAP.md`, `ots/mod.rs:89-91` (*"it is the figure the F4 row takes"*) and `replay.rs:141-142` all agree, so **the registry cell is the only artefact in the tree keyed to the submit reply** and one of the five it contradicts is a code doc asserting what the registry currently falsifies — A106's *"a correction landed in one of two places has not happened"*, one file over. Keeping submit would require **amending a ratified decision**, which nothing argues for. Re-measured from bytes, not from the row: submit 207/170/**220**/207/170/185, upgrade 1 000/1 036/**1 105** ×2 digests, **both pinned by the same test** (`the_measured_upgrade_response_sizes_are_the_f4_row`, per file) — and the upgrade's sample is **complete and committed** where the submit's *"largest of 18"* is prose-backed, six committed of eighteen. Arithmetic re-derived with the checker's own integer expression: 297.8909 → **297.89x**, 59.3086 → **59.31x**, both of A115's figures correct. The limit bounds **any single calendar reply**, not a request class (`submit.rs:343`, `upgrade.rs:213`, no third site) — which *strengthens* the ruling: a shared cap is only as generous as its worst shape. The class set is **exactly two**: non-2xx bodies, including A14's two 404 discriminators, read under `HTTP_ERROR_BODY_CAP_BYTES` (4 KiB) at `http.rs:820-835`, **not** `receive_cap_bytes`. **"Record both" is refused on §5's own rule**: `printed_margin` reads only the leading `N.MMx`, so a second margin is *"a number that reads like the checked ones and is checked by nothing"* — A113's words for the defect it landed to remove, and the 15.28x shape that injured A109; both figures are still recorded, the submit one **unbolded** and not written as a margin. **Value KEEPS 65 536** — worst shape is **1.69 %** of the cap, structural cost genuinely none, a lowering saves ≤ 256 KiB of transient heap, and **zero of the four `DEFAULT_OTS_CALENDARS` endpoints has ever been measured** (the A25 captures used `*.btc.calendar.opentimestamps.org`, which `calendars.rs:6-13` says the default list deliberately excludes). **§6 owes no entry** — and the brief's *"D107 fires on lowering alone"* is the rule **D107 replaced**; D107 R1's exclusion table names *"correcting `measured against`, `margin` or `structural cost`"* as owing none, and writing one anyway reddens the bidirectional log checker. **Ships an instrument**, because A113's cross-check is document-internal and a *consistent* re-key back passes every test today: `the_f4_row_is_keyed_to_the_upgrade_reply_not_the_submit_reply` lands in `antseal-anchor`, the only crate that can see both operands, literal-free on both sides. Also repaired: the §5 margin band's ceiling (297.89x → **178.09x**) and its floor claim, which has said `MAX_OTS_DEPTH` at 12.05x since A110 put `MAX_CHAIN_CERTS` at **2.0x** in the same table. **No constant moves** | RESOLVED (A115 executes, with A114) | 2026-08-10 |

---

## Amendments — found by the implementing lane, 2026-08-10

Recorded here rather than left in a task report. The RULING and every figure in
§1.1–§1.3 survive unchanged and were independently re-verified; what follows
corrects one justification, two pointers, and one **material omission**.

**A1 — the material one: this document says A114 decides nothing it decides,
and both are wrong about A114(b), which already has a governing ruling.**
§12 states *"A114 … decides nothing this record decides"*, and A114's own entry,
its `TODO.md` row and the implementing brief all describe A114(b) as having no
decision. It has one: **`docs/decisions/D104-max-ots-depth-lowering-window.md`
§6 is titled "RULING 5 — yes, the wasm32 asymmetry goes in the registry, and it
is A106's"**, and it rules strictly *more* than A114's `Do` — the two numeric
`structural cost` **cells** carry the wasm32 figure beside the x86-64 one, §5a
gains the direction sentence, the headroom line is target-qualified, and,
*"because clause (a) forbids adding a fourth unchecked number"*, the same edit
gives `the_structural_cost_column_states_the_derivation_and_its_value` a
**32-bit arm**. The lane executed the parts inside its file scope (§5a prose and
the headroom qualification), **refused the cells** — shipping them without the
32-bit arm manufactures the clause-(a) defect D104 itself names — and wrote the
gap into the document rather than leaving it implicit. D104 §6's named owner
**A106 closed on 2026-08-10 having explicitly excluded this work**, leaving the
ruling orphaned with no forwarding pointer. The residue is registered as its own
row at this wave's bookkeeping.

**A2 — §4's justification for why the old cell parsed safely is wrong.** This
document writes *"the old cell survived only because `2026-08-03` contains `-`
and was rejected by accident"*. The date was never reached: `measured_quantity`
takes `.next()` over bold spans and `**220**` came **first**. The old cell
survived by **order**, not by rejection. The rule derived from it — *"no earlier
bold span may be a bare number"* — is right, and the replacement row satisfies
it; only the stated reason was wrong.

**A3 — E3's verbatim insertion creates a dangling pronoun.** The sentence
following the replaced clause reads *"It is also the only one of the rows here
that is a network-stage limit…"*, and E3's insertion puts *"a non-2xx calendar
body"* and *"this limit"* between that pronoun and its antecedent. E3's text was
applied verbatim and the three pre-existing words `It is also` became `This
limit is also`, inside the paragraph E3 declares it amends. Nothing parses that
paragraph.

**A4 — the Index row's `replay.rs:141-142` is wrong even for the working tree.**
§8's rider is exactly right (`:172-174` for `CALENDAR_CATALLAXY_A`, found
there), but the Index row cites `:141-142` for `UPGRADE_A_CATALLAXY`'s doc,
which is at **:218-219**. Self-flagged by this document's own instruction not to
trust line numbers into that file.

**Verified correct, for the record.** All figures in §1.1–§1.3; the `include_str!`
depth; E1/E2/E3's line targets (`:228`, `:284-285`, `:234-240`) all still
resolved; E2's recomputed band (the eight `.ots`/receive-side rows do run
12.05x → 178.09x, DER 2.0x–7.8x); §6's test code compiles clippy-clean and both
arms behave as its mutation table predicts. §6's central claim is confirmed by
execution: under a **consistent** re-key to the submit reply,
`the_margin_column_is_the_value_over_the_measurement` stays **green** while the
new `the_f4_row_is_keyed_to_the_upgrade_reply_not_the_submit_reply` goes **red**
naming both figures — which is precisely the gap this document was written to
close. D111 is confirmed to govern the *wire* registry and does not overlap.
