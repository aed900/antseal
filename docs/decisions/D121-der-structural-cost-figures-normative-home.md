# D121 — A126: where the seven DER structural-cost figures normatively live

- **Status: RESOLVED — the document had already ruled, in two sentences nobody
  read, and the ruling splits the seven 3/4 rather than moving any of them.**
  The row offers two shapes and leans on the first: *"move or mirror the four
  into §5's structural-cost column, so one parse covers all seven and A123's
  fix applies unchanged."* **Both halves of that sentence are false against the
  tree.** §5a already states, in its own voice, *"**Where the DER path's
  7 488 B goes, and why no one row carries it**"* and *"§5's two numeric
  `structural cost` cells carry both targets' figures … **this table is the
  derivation they point at**"*. §5 is a registry **keyed by F4 limit**; three
  of the four figures belong to bounds that are **not F4 limits** —
  `MAX_PATH_NODES`, which `caps.rs`'s own `NOT_F4_LIMITS` list classifies out
  with a reason, and `MAX_INTERMEDIATE_COUNT`, a **frozen** D10 §2 row 8 that
  F4 cannot raise — and the fourth is a **sum across two containers**. §5's
  preamble names four owners and says *"Nothing outside those four may"* add a
  row. Shape (a) would put non-F4 numbers into the F4 registry to make a test
  easier to write, which is the direction of authority backwards.
  **Ruling: §5's `MAX_CHAIN_CERTS` row is authoritative for `4 288 B`,
  `1 024 B` and `664 B`; §5a is authoritative for `3 200 B`, `7 488 B`,
  `2 048 B` and `4 096 B`.** Nothing moves in the document except one added
  paragraph recording that ruling, which A126's own `Accept` requires.
  **The second half is false too: A123's fix does not have one shape, it has
  three**, and the third is exactly what §5a's four need. A123 left the
  derivation formulas as document-wide `contains`, read the two figures that
  *have* rows out of their own cells, and pinned the one figure that has **no**
  row — the `.ots` sum — with `REGISTRY.matches(needle).count() == 1`, under a
  comment saying why. So **no parse of §5a is needed, and no second parse of
  anything is introduced**: three needles get row-line scoping, four get
  exactly-once. That matters, because the row's premise that the cell fix
  ports over is **also** wrong — `registry_rows` lives in a private `tests`
  module inside `mod limits;`, which `ots/mod.rs` declares **without `pub`**,
  so `caps.rs` cannot name it and shape (a) would have forced a ~90-line
  parser duplication, the very thing A126's `Accept` forbids.
  **The defect is confirmed by mutation, not by reading.** With §5's cell
  changed to `**4 289 B**` the whole `antseal-core` lib suite is green —
  `1056 passed; 0 failed; 1 ignored` — byte-identical in verdict to the clean
  baseline, and the test that exists to pin that cell reports `ok`. Blast
  radius of the mutation is **zero tests**. The mechanism is exact: the needle
  `**4 288 B**` still occurs **twice** (§5a's table and §5a's A111 prose), so
  `contains` cannot fail.
  **A126's own entry contains an error this record corrects**: it drops the
  A123 lane's *"1056 lib tests"* figure as one that *"could not be verified
  anywhere in the tree"*. It is verifiable by running it, and it is exact —
  `cargo test -p antseal-core --lib` reports `1056 passed`. *Not recorded as a
  committed number* is not *unverifiable*.
- **Date: 2026-08-11** (wave 15, D121 lane; briefed to overturn the row's lean
  toward shape (a) — the lean is overturned, and so is the brief's own
  framing that shape (b) requires *"building the parse §5a needs"*).

## The problem, in one sentence

`the_der_structural_cost_column_states_the_derivation_and_its_value` asserts
seven byte figures with `REGISTRY.contains()` over an `include_str!` of the
**whole** of `docs/format/anchor-artifact-limits.md`, three of the seven have
more than one home so the search cannot go red at the home that matters, and
four of them have no §5 cell to be scoped to — so the row asks which text is
authoritative before any assertion is written.

## 1. What was measured

Everything below was run at `1f82da1` on the working tree. Line numbers are
measurement coordinates at that commit, not citations; the authoritative
identifiers are the section (§5, §5a) and the quoted text.

### 1.1 The seven needles, resolved from the code

The test builds each needle as `format!("**{}**", format_spaced(bytes))` from
`size_of`-derived constants in `crates/antseal-core/src/anchor/caps.rs`. On
x86-64, with `CHAIN_CERTIFICATE_BYTES = 512`, `CHAIN_CERT_DER_HANDLE_BYTES =
24`, `CHAIN_PATH_NODE_BYTES = 128`, `MAX_CHAIN_CERTS = 8`,
`MAX_PATH_NODES = 25` and `MAX_INTERMEDIATE_COUNT = 16`:

| # | needle | code expression | value |
| --- | --- | --- | --- |
| 1 | `**4 288 B**` | `TSA_STRUCTURAL_CERT_BAG_BYTES` | `8 x (512 + 24)` |
| 2 | `**3 200 B**` | `TSA_STRUCTURAL_PATH_NODE_BYTES` | `25 x 128` |
| 3 | `**7 488 B**` | `TSA_STRUCTURAL_ALLOC_BYTES` | `4 288 + 3 200` |
| 4 | `**1 024 B**` | `MAX_CHAIN_CERTS * CHAIN_PATH_NODE_BYTES` | `8 x 128` |
| 5 | `**2 048 B**` | `MAX_INTERMEDIATE_COUNT * CHAIN_PATH_NODE_BYTES` | `16 x 128` |
| 6 | `**664 B**` | `CHAIN_CERTIFICATE_BYTES + CHAIN_CERT_DER_HANDLE_BYTES + CHAIN_PATH_NODE_BYTES` | `512 + 24 + 128` |
| 7 | `**4 096 B**` | `MAX_CHAIN_CERTS * CHAIN_CERTIFICATE_BYTES` | `8 x 512` |

The row names six of the seven. The seventh is **`664 B`**, and it matters to
the ruling because it is the one figure with exactly one home, in §5's cell.

### 1.2 Occurrence counts — of the needle, not of the figure

This distinction is load-bearing and an implementing lane that counts bare
figures will design the wrong instrument. Counted with `str.count()` on the
exact needle, and separately on the bare figure:

| needle | needle count | at | bare-figure count | at | section of each |
| --- | --- | --- | --- | --- | --- |
| `**4 288 B**` | **3** | 230, 450, 470 | 3 | same | §5 cell, §5a table, §5a prose |
| `**3 200 B**` | **2** | 451, 453 | 2 | same | §5a table, §5a prose |
| `**1 024 B**` | **2** | 230, 453 | 2 | same | §5 cell, §5a prose |
| `**7 488 B**` | **1** | 444 | 2 | 443, 444 | §5a prose (443 is a bold heading, so `**7 488 B**` does not match there) |
| `**2 048 B**` | **1** | 454 | 1 | same | §5a prose |
| `**664 B**` | **1** | 230 | 2 | 230, 459 | §5 cell (459's `**` wrap the whole phrase, so the needle does not match) |
| `**4 096 B**` | **1** | 473 | 1 | same | §5a prose |

So the row's counts are **correct as stated** — three needles with multiple
homes, four figures absent from §5 — and they are correct only because the
`**` delimiters are part of the needle. Two of the seven would be
double-counted by a `grep "664 B"`.

### 1.3 `anchor-artifact-limits.md` is not frozen

`docs/format/FROZEN.sha256` carries exactly two digests, for
`registry-v1.json` and `registry-v1.md`. `anchor-artifact-limits.md` appears
nowhere in it. Re-verified as the brief asked: shape (a) is therefore **not**
dead on arrival for freeze reasons, and is refused on the document's own logic
instead — which is the stronger refusal, because it survives the freeze
manifest changing.

**But the document is not unguarded, and an implementing lane needs the
boundary.** `scripts/check-traceability.py`'s `freeze-boundary` check lists
`docs/format/anchor-artifact-limits.md` in `BOUNDARY_COPIES` and compares it
byte-for-byte against D84 §7's rule text — *"2 copies identical to
`docs/decisions/D84-anchor-artifact-limits-permanence.md` §7 (2175 bytes of
rule text; checkbox state excluded, Q49)"*, and the `--self-test` opens with
*"freeze-boundary goes red when `docs/format/anchor-artifact-limits.md` is
corrupted"*. That copy is **§2**, *"The v1 freeze boundary (D84 §7, verbatim)"*.
**§5 and §5a are outside it.** So the §5a paragraph §9.2 adds is safe, the §9.3
sentence correction is safe, and a careless edit to §2 is not — which is also
why the mutation in §1.7 could go green: it was in §5, where no checker looks.

### 1.4 §5 has twelve rows and none of them is what the four figures need

The §5 table's limit column, read at `1f82da1`, holds exactly:
`MAX_OTS_OPS`, `MAX_OTS_DEPTH`, `MAX_OTS_BRANCH_WIDTH`,
`MAX_OTS_ATTESTATIONS`, `MAX_OTS_OPERAND_BYTES`, `MAX_OTS_VALUE_BYTES`,
`MAX_OTS_ATTESTATION_PAYLOAD_BYTES`, `MAX_OTS_CALENDAR_RESPONSE_BYTES`,
`MAX_DER_NESTING_DEPTH`, `MAX_CHAIN_CERTS`, `MAX_CHAIN_CERT_BYTES`,
`MAX_SIGNED_ATTRS`.

`MAX_PATH_NODES` occurs in the document only in §5a (twice). It has no row and
**cannot** have one: `caps.rs`'s `every_max_constant_declared_here_is_classified`
lists it in `NOT_F4_LIMITS` with the reason *"it sizes a container, it is not a
limit on a foreign artifact's structure, and nothing rejects an artifact for
exceeding it"*. `MAX_INTERMEDIATE_COUNT` is a **D10 §2 row 8** constant — the
document's own §2 table carries it at value `16` — and §5a calls it *"a
**frozen** D10 row (§2, row 8), not an F4 limit at all"*.

§5's preamble: *"A5, A11 and A28 fill it at M2 — **and A42** … Nothing outside
those four may."*

### 1.5 What A123 actually built — three arms, not one

Read at `crates/antseal-core/src/anchor/ots/limits.rs`. The fixed `.ots` test
does three different things:

1. **Derivation formulas** — plain document-wide `REGISTRY.contains(formula)`,
   unchanged from before A123, because *"stated somewhere normative"* is the
   whole claim.
2. **Figures that have a §5 row** (`MAX_OTS_DEPTH`, `MAX_OTS_ATTESTATIONS`) —
   `registry_rows()` → `row.structural_cost.contains(&needle)`, per target.
3. **The one figure with no row** — the summed cost — kept as a document-wide
   search *and strengthened with an exact count*, under this comment:

> The **sum** is the one figure with no row to be read out of: §5's
> `structural cost` column is per limit, and the total of both containers is
> stated only by §5a's two-target table. So it stays a document-wide search —
> and says so by requiring exactly one match, which is the property that made
> the searches above pass for reasons their author never intended.

`assert_eq!(REGISTRY.matches(summed.as_str()).count(), 1, …)`.

**Arm 3 is the answer to A126's four**, and it was already in the tree when
the row was written. The row's `Do` — *"accept that they live in §5a and build
the parse §5a needs"* — assumes a parse is needed. It is not.

### 1.6 `registry_rows` is unreachable from `caps.rs`, and this kills shape (a) twice

`crates/antseal-core/src/anchor/ots/mod.rs` declares `mod limits;` — **no
`pub`**. `registry_rows`, `RegistryRow`, `REGISTRY_HEADER` and `unfenced` all
live inside `limits.rs`'s `#[cfg(test)] mod tests`. Two visibility barriers,
either one sufficient. `caps.rs` already documents having hit this, in the
comment on its duplicated `format_underscored`:

> Duplicated from `anchor::ots::limits::tests` rather than shared:
> `ots::limits` is a private module of `ots`, so nothing outside it can name
> its test helpers, and widening a module's visibility to share eight lines of
> formatting is the worse trade.

Eight lines of formatting is one trade; ~90 lines of table parser is another.
So shape (a) does **not** buy *"one parse covers all seven"* — it buys a
**second** parse in a second crate module, which is exactly what A126's
`Accept` refuses (*"no second parse of the registry is introduced"*).

### 1.7 The defect, proved by mutation

Baseline, clean tree:

```
cargo test -p antseal-core --lib --no-fail-fast
test result: ok. 1056 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out; finished in 281.69s
```

Then §5's `MAX_CHAIN_CERTS` structural-cost cell **only** was changed,
`**4 288 B**` → `**4 289 B**` (one line, the `| 2.0x | never | **4 288 B** =`
occurrence, which is unique to that row). Under the mutation the needle still
occurs twice:

```
UNDER MUTATION: **4 288 B** occurrences = 2
  at lines: [450, 470]
  **4 289 B** at: [230]
  => REGISTRY.contains("**4 288 B**") == True
```

and the suite is green:

```
cargo test -p antseal-core --lib --no-fail-fast
test anchor::caps::tests::the_der_structural_cost_column_states_the_derivation_and_its_value ... ok
test result: ok. 1056 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out; finished in 205.98s
```

**Identical verdict to baseline. Blast radius: zero tests.** A126 recorded
this as *"taken on report, and not re-run here — no cargo was invoked"*. It is
now run, and the report was right.

The document was restored byte-for-byte immediately afterwards; `git status
--short -- docs/format/` is empty and `**4 288 B**` is back to three
occurrences. §10 carries the verdicts.

## 2. The document has already ruled, and the ruling is not the row's lean

Two sentences in §5a, neither of which A126 or its sources cite:

> **Where the DER path's 7 488 B goes, and why no one row carries it.**

> §5's two numeric `structural cost` cells carry both targets' figures for the
> same reason, which is what D104 §6 ruled; **this table is the derivation
> they point at**.

Together they state the architecture exactly: **§5 is the per-limit registry
and §5a is the derivation behind it.** A figure that an F4 limit owns is
stated in that limit's row and *derived* in §5a. A figure that no F4 limit
owns is stated in §5a and nowhere else, and the document says so in a heading.

That is the answer to *"which text is authoritative for these four figures?"*,
and it was written down before the question was asked.

## 3. Shape (a) — move or mirror the four into §5's structural-cost column

**Refused, on four independent grounds, any one of which is sufficient.**

1. **It inverts the direction of authority.** The document would be edited to
   suit an assertion. A5, A11, A28 and A42 own §5's rows; a test lane is not
   among them, and §5's preamble says *"Nothing outside those four may."*
2. **Three of the four figures belong to things that are not F4 limits.**
   `3 200 B` is `MAX_PATH_NODES`', and `MAX_PATH_NODES` is classified *out* of
   the F4 set in code with a reason. `2 048 B` is `MAX_INTERMEDIATE_COUNT`'s,
   and that constant is **frozen** at D10 §2 row 8 — putting it in the F4
   registry would advertise as raisable a number F4 cannot raise, which is
   the precise confusion §5a's paragraph exists to prevent (*"charging the
   whole path-node reservation to `MAX_CHAIN_CERTS` … attributes **2 176 B**
   to a raisable limit that an unraisable one owns"*).
3. **`7 488 B` is a sum across two containers under two different bounds.**
   There is no single row it belongs to; the document titles the paragraph
   *"why no one row carries it"*. A123 hit the identical case on the `.ots`
   side and did **not** invent a row — it used arm 3.
4. **It does not deliver what it promises.** *"One parse covers all seven"* is
   false: `caps.rs` cannot reach `registry_rows` (§1.6), so shape (a) yields a
   duplicated parser, not a shared one.

`4 096 B` — the fuzz-guard tie — is the one figure for which shape (a) is
merely pointless rather than wrong: it is a **sub-product** of a cell that
already states the whole (`8 x size_of::<Certificate>()` inside
`8 x (size_of::<Certificate>() + size_of::<Vec<u8>>())`). Adding it to §5's
cell would state a partial derivation beside its own total.

## 4. Shape (b) — accept that they live in §5a, and build the parse §5a needs

**The first half is ruled; the second half is refused as unnecessary.**

§5a **is** where they live, for §2 and §3's reasons. But §5a needs no parse:

- `**7 488 B**`, `**2 048 B**` and `**4 096 B**` each have **exactly one**
  occurrence in the whole document. `matches(needle).count() == 1` pins each
  at its only home, goes red at `0` if it drifts, and goes red at `2` the day
  someone gives it a second home — which is the failure that produced A123 and
  A126 in the first place. This is arm 3, unchanged.
- `**3 200 B**` is the only §5a figure with two homes: §5a's per-container
  table row and the decomposition sentence below it. It is pinned by joining
  the figure to its derivation, which the table states and the prose does not:
  `**3 200 B** = \`25 x size_of::<Node>()\`` occurs **exactly once** (measured;
  see §10). Both halves are already code-derived — the formula is one of the
  four the test asserts today — so the joined needle adds no literal.

A `§5a` table parser would be a second parse of the same document to read one
cell that a unique substring already identifies, and A126's `Accept` and the
Q157 class both argue against it. Refused.

## 5. Shape (c) — assert from the code's constants, and check the document against the code

**Refused as a category error: it is already true, and it answers nothing.**

The test never asserts a literal. Every needle is `format!`-built from
`size_of`-derived constants — that is why the row's figures are `TSA_…_BYTES`
expressions and not numbers. The direction shape (c) proposes is the direction
the project chose long ago, with three pieces of evidence:

- **D102 rule 6 clause (a), verbatim**: *"**derived in code from the limit
  constants and `size_of`, never written as a literal.** A number typed by
  hand is a number that survives a raise."*
- **D102 §10 kill criterion 5**: *"Clause (a) exists to make this impossible;
  if a literal ever appears, clause (a) has been violated."*
- **The document's own closing sentence in §5a**: *"Every number in this
  subsection is derived in `anchor/caps.rs` and asserted against this
  document, never transcribed."*

So the code is already the source of the number and the document is already
the thing checked. A126's question is a different one — *which document text
must carry the code's number* — and shape (c) does not touch it. Adopting it
as if it were an answer would leave all seven needles document-wide and the
defect exactly where it is.

(That closing sentence is also **not true as written**. See §12.)

## 6. Shape (d) — delete needles that a §5-scoped parse already covers

**Refused: nothing is duplicated, and deleting would break a promise the
document makes.**

No two of the seven needles assert the same fact. `4 288 B` (bag),
`4 096 B` (bag's certificate half) and `664 B` (marginal unit) are three
different derivations that happen to share operands. A §5-scoped instrument
covers three of the seven; deleting the other four would remove the only
assertion behind §5a's whole DER decomposition — which D102 §6 ruled must
*"assert it at equality"*, *"because that assertion is what goes red the day
someone adds a container or raises a count"* — and would falsify §5a's closing
sentence further rather than less.

## 7. A122's argument is not this row's argument, and the row is right to warn

A126 warns that reading A122's doc comment as this row's answer yields the
wrong conclusion. Verified, and the distinction is this:

- **A122 is about the per-target label.** A123's arm 2 needles are
  `format!("**{}** {label}", …)` with `label` = `(x86-64)` or `` (`wasm32`) ``,
  because §5's `.ots` cells render *both* targets in one cell
  (`**40 960 B** (x86-64) and **24 576 B** (`wasm32`)`). That mechanism needs
  the document to record two targets. §5's `MAX_CHAIN_CERTS` cell records one,
  which is why the DER figures sit inside `if size_of::<usize>() == 8`.
- **A126 is about row scoping** — reading a figure out of the named row rather
  than out of the whole file. That is orthogonal to how many targets the cell
  records. A one-target cell is scoped exactly as well as a two-target one.

A123 shipped both at once because the `.ots` rows happened to need both. **The
label is refused here (A122's ground); the scoping is not.** Conflating them
would discard the fix for a reason that applies only to its other half.

**One correction to A122's ground, recorded because a later lane will lean on
it.** A122 argues from *"§5a records `size_of::<x509_cert::Certificate>()` on
x86-64 and nowhere else"*. §5a does record one `wasm32` DER figure: *"on
`wasm32` the same product is **3 008 B**"*, from which the `wasm32`
per-certificate size (376 B) follows by division. A122's narrow claim — the
per-certificate size is never *stated* for `wasm32` — holds. The broader
reading, that the document carries no `wasm32` DER figure at all, is false, and
§12 records what that opens.

## 8. Ruling

**§5's `MAX_CHAIN_CERTS` row is the authoritative home for three figures;
§5a is the authoritative home for four. Nothing moves.**

| # | needle | authoritative text | why | instrument |
| --- | --- | --- | --- | --- |
| 1 | `**4 288 B**` | §5's `MAX_CHAIN_CERTS` row, `structural cost` cell | it is that F4 limit's own cost, and it has a row | row-line scoping |
| 4 | `**1 024 B**` | §5's `MAX_CHAIN_CERTS` row, `structural cost` cell | the same limit's share of the path nodes; the cell states it | row-line scoping |
| 6 | `**664 B**` | §5's `MAX_CHAIN_CERTS` row, `structural cost` cell | *"the number a raise argument actually needs"*, per unit of that limit | row-line scoping |
| 2 | `**3 200 B**` | §5a's per-container table, `chain::PathBuilder::new`'s `nodes` row | `MAX_PATH_NODES` is classified **not** an F4 limit; no row exists or may | exactly-once, needle joined to its derivation |
| 3 | `**7 488 B**` | §5a's prose, *"why no one row carries it"* | a sum across two containers under two bounds | exactly-once |
| 5 | `**2 048 B**` | §5a's prose, the decomposition sentence | `MAX_INTERMEDIATE_COUNT` is frozen at D10 §2 row 8, not an F4 limit | exactly-once |
| 7 | `**4 096 B**` | §5a's prose, the fuzz-guard tie paragraph | a sub-product of a cell that states the whole | exactly-once |

The §5a restatements of `4 288 B` (§5a's table and its A111 prose) and of
`3 200 B` (the decomposition sentence) are **derivation and commentary, not
statements of record**. They are deliberately left unpinned; §12 records the
consequence.

## 9. Edit set

Three files. An implementing lane does exactly this and nothing else.
- `docs/decisions/README.md` — this decision's index row. **Applied 2026-08-11**, executing [D119](D119-decision-index-identity-and-the-index-row-sections.md) §5 step 4; the former `## Index row` section is demoted to this line under D119 RULING 4, and RULING 6 puts the row in the act that commits the record.

### 9.1 `crates/antseal-core/src/anchor/caps.rs` — the test

Inside `the_der_structural_cost_column_states_the_derivation_and_its_value`:

**Leave unchanged**: the four-formula `contains` loop, and the `next_pow2`
negative pair. Both are *"stated somewhere normative"* claims, which is what
A123 left alone on the `.ots` side and what A126's `Accept` preserves.

**Replace** the single seven-element loop inside
`if core::mem::size_of::<usize>() == 8 { … }` with two loops:

1. **Row-scoped**, for `TSA_STRUCTURAL_CERT_BAG_BYTES`,
   `MAX_CHAIN_CERTS * CHAIN_PATH_NODE_BYTES` and
   `CHAIN_CERTIFICATE_BYTES + CHAIN_CERT_DER_HANDLE_BYTES + CHAIN_PATH_NODE_BYTES`.
   Select the row with
   `REGISTRY.lines().find(|l| l.starts_with("| `MAX_CHAIN_CERTS` |"))`, failing
   with a message naming §5 and D102's column if it is absent, then assert
   `row.contains(&needle)` per figure. **`starts_with` and not `contains` is
   load-bearing**: the string `| \`MAX_CHAIN_CERTS\` |` occurs on two lines —
   §5's row, which *opens* with it, and §5a's table row, where it is the
   `bounded by` cell mid-line. Measured: exactly one line **starts** with it.
2. **Exactly-once**, for `TSA_STRUCTURAL_PATH_NODE_BYTES`,
   `TSA_STRUCTURAL_ALLOC_BYTES`,
   `MAX_INTERMEDIATE_COUNT as usize * CHAIN_PATH_NODE_BYTES` and
   `MAX_CHAIN_CERTS * CHAIN_CERTIFICATE_BYTES`, with
   `assert_eq!(REGISTRY.matches(needle.as_str()).count(), 1, …)`. For
   `TSA_STRUCTURAL_PATH_NODE_BYTES` **only**, the needle is the figure joined
   to its derivation —
   `format!("**{}** = \`{MAX_PATH_NODES} x size_of::<Node>()\`", format_spaced(bytes))` —
   because the bare figure has two homes in §5a and the joined form has one.
   The other three take the bare `format!("**{}**", …)` needle.

**No new helper, no new parse, no change to `format_spaced`/`group`.** Carry a
comment saying that arm 2 is A123's third arm and that a count of `2` is a
second home, not a pass — the same warning A123 wrote on the `.ots` sum.

Failure messages must name the section they mean: *"§5's `MAX_CHAIN_CERTS`
row states no structural cost of …"* for arm 1, and *"§5a is the single site
that states …"* for arm 2.

### 9.2 `docs/format/anchor-artifact-limits.md` — record the ruling

A126's `Accept` requires *"the ruling on where the four non-§5 figures live is
recorded in the registry document itself"*. **One paragraph, added to §5a
after the fuzz-guard-tie paragraph**, before the closing sentence. It records
§8's table in prose: that the three figures §5's `MAX_CHAIN_CERTS` row states
are authoritative *in that cell*, with §5a's table as the derivation the cell
points at; that the four this subsection alone states are authoritative
**here**, because no §5 row carries them — `MAX_PATH_NODES` is not an F4
limit, `MAX_INTERMEDIATE_COUNT` is frozen at §2 row 8, `7 488 B` is a sum
across two containers, and `4 096 B` is a sub-product of a cell that states
the whole; and that §5 is keyed by F4 limit, so a number no F4 limit owns has
no row to move to.

**This is not shape (a).** It adds a statement *about* where the numbers live;
it moves no number and touches no §5 cell. It is also the only change to this
document in the whole edit set, and it changes **zero** frozen bytes —
`FROZEN.sha256` covers `registry-v1.json` and `registry-v1.md` only.

### 9.3 `docs/format/anchor-artifact-limits.md` — one factual correction

§5a's closing sentence, *"Every number in this subsection is derived in
`anchor/caps.rs` and asserted against this document, never transcribed"*, is
false in its second clause: `2 176 B`, `3 008 B`, the signer's `128 B` and the
three percentages (`0.71 %`, `0.41 %`, `0.31 %`) are stated in §5a and asserted
by nothing. Narrow the claim to the numbers that *are* asserted — the seven —
and leave *"derived … never transcribed"* intact, which is true and is clause
(a)'s requirement.

This must be a **dated correction with the original wording preserved**, not a
silent rewrite. The nearest governing precedent is **D117 §2.3(b)** — *a
sentence a lane would act on is replaced, with a dated marker; the original
survives verbatim* — and this is such a sentence, because a lane reading it
concludes the numbers are pinned. **D117's stated subject is a resolved
decision's body, and `anchor-artifact-limits.md` is a format document**, so
this applies D117's form by analogy rather than by its own scope. An
implementing lane should say so in the marker rather than cite D117 as if it
governed here.

### 9.4 What is explicitly **not** in the edit set

- No new module, no widened visibility on `ots::limits`, no shared registry
  helper. §12 describes the case for one; it is not this row's.
- No 32-bit arm, and no change to the `size_of::<usize>() == 8` gate. That is
  A122's territory and its ground survives (§7).
- No touch to §5a's `40 960 B` prose sites — A124 owns those.
- No touch to any §5 cell.

## 10. Commands run, with verdicts

| command | verdict, by its message |
| --- | --- |
| `cat docs/format/FROZEN.sha256` | two digests, `registry-v1.json` and `registry-v1.md`; **`anchor-artifact-limits.md` absent** |
| `python3` exact-needle counts over the document | as §1.2's table; `**664 B**` ×1 and `**7 488 B**` ×1 against bare-figure ×2 each |
| `python3` joined-needle count | ``**3 200 B** = `25 x size_of::<Node>()` `` → **1**; `` `8 x size_of::<Certificate>()`, is **4 096 B** `` → **1**; `` **4 288 B** = `8 x (size_of::<Certificate>() + size_of::<Vec<u8>>())` `` → **2**, which is why #1 is row-scoped and not counted |
| `python3` row-line uniqueness | lines **starting** `` | `MAX_CHAIN_CERTS` | `` → `[230]`; lines **containing** it → `[230, 450]` |
| `grep -n "^mod \| pub mod " …/ots/mod.rs` | `mod limits;` — **no `pub`**; `registry_rows` unreachable from `caps.rs` |
| `cargo test -p antseal-core --lib --no-fail-fast` (clean) | `test result: ok. 1056 passed; 0 failed; 1 ignored` in 281.69s |
| `cargo test -p antseal-core --lib --no-fail-fast` (§5 cell → `**4 289 B**`) | `test result: ok. 1056 passed; 0 failed; 1 ignored` in 205.98s, and the DER test itself `... ok` — **the defect, realised** |
| `git status --short -- docs/format/` after restore | **empty**; `**4 288 B**` back to 3 occurrences, `**4 289 B**` to 0 |
| `python3 scripts/check-traceability.py --check` | **`error: unrecognized arguments: --check`**, exit 2 — the flag does not exist and never has; `git show HEAD:scripts/check-traceability.py` has no `--check` either. The run-all invocation is **flagless** |
| `python3 scripts/check-traceability.py` | `check-traceability: ok (freeze-boundary, matrix, decisions, task-citations, task-entries, decision-owners)`, exit 0. `[task-entries] ok — 582 rows (581 live + 1 struck) against 582 entries`; `[decisions] ok — 104 distinct decisions cited across 359 files, all resolve` |
| `python3 scripts/check-traceability.py --self-test` | 28 lines, **every one `self-test: ok`**, exit 0 — verified by `grep -v "self-test: ok"` returning nothing, not by reading the tail, since failures print first |

Both `cargo` runs used `--no-fail-fast`, per Q196: a fail-fast count is a lower
bound and this project has been misled by one. The two runs report the same
count from the same suite, which is what makes *"blast radius: zero"* a
measurement rather than an absence.

## 11. What this does not do

- **It does not write the test.** §9.1 is executable but it is A126's work, not
  this record's; no code changed here.
- **It does not close the §5a-internal consistency gap.** Under this ruling the
  restatements of `4 288 B` and `3 200 B` inside §5a remain unpinned, so a
  decomposition that stops adding up (`1 024 + 128 + 2 048 = 3 200`) is still
  invisible. That is a document-consistency instrument, not a code-drift one,
  and §12 describes it.
- **It does not re-open A122**, whose narrow ground holds, or A124, which owns
  the `40 960 B` prose sites.
- **It does not touch the freeze.** Zero frozen bytes move, and the ruling is
  deliberately argued from §5a's own text rather than from the freeze manifest,
  so it survives the manifest changing.
- **It does not verify the `wasm32` path.** Everything measured here is x86-64;
  the seven figures sit behind a 64-bit gate and `scripts/wasm-tests.sh` was
  not run.

## 12. Discovered work — described, not registered

1. **§5a's closing sentence overclaims, and four numbers in §5a are asserted by
   nothing.** `2 176 B`, `3 008 B`, the signer's `128 B` and the three
   percentages are stated in the document's own voice and pinned by no test,
   while the sentence says *"every number in this subsection … asserted against
   this document"*. §9.3 narrows the sentence; **widening the assertions
   instead is the other half, and it is a separate row** — `2 176 B` and the
   signer's `128 B` are derivable from constants already in `caps.rs`, so the
   cost is small and the judgement (assert more, or claim less) is real.
2. **§5a's own arithmetic is unchecked.** The decomposition asserts
   `3 200 = 1 024 + 128 + 2 048` in prose, and nothing verifies the sum. A
   checker over §5a's decomposition — in the class of `limit_change_log_violations`,
   which already does this shape for §6 — would catch a restatement drifting
   from the table above it. This is the gap §11 names, and it is the only
   residue this ruling knowingly leaves.
3. **`3 008 B` means the fuzz-guard tie could be asserted on both targets.**
   §7 records that §5a *does* carry one `wasm32` DER figure. A 32-bit arm for
   `**4 096 B**`/`**3 008 B**` alone is now possible without A122's obstacle,
   which applies to the per-certificate size and not to this product. Held back
   deliberately: it is A122's and A121's territory and folding it in here would
   be the scope creep D104 §6 already suffered.
4. **Test helpers that parse the registry are trapped behind `mod limits;`.**
   `caps.rs` has now duplicated `format_underscored`/`group` for this reason and
   would have had to duplicate `registry_rows` under shape (a). A `#[cfg(test)]`
   registry-document helper visible to both — one parse, two consumers — would
   end the pattern before a third module needs it. **Not needed for A126**,
   which is precisely why it should be argued on its own and not smuggled in.
5. **A126's entry needs a dated correction.** It records the A123 lane's
   *"1056 lib tests"* as a figure that *"could not be verified anywhere in the
   tree"* and omits it. The figure is exact and reproducible —
   `cargo test -p antseal-core --lib` reports `1056 passed` at `1f82da1` — and
   the entry conflates *not recorded as a committed number* with *unverifiable*.
   D117 rules that a **resolved decision's** body takes dated corrections and
   that silence is what is forbidden; a **task entry** is not that, and how
   `tasks/*.md` entries take corrections is settled by the bookkeeping
   convention rather than by D117. The correction is owed either way.
6. **A126's `Do` should lose the clause *"build the parse §5a needs"***, which
   this record refutes. Left to the orchestrator for two reasons: this lane owns
   exactly one file, and D115 §3.6's principle — that a **task entry** is the
   wrong place for a ruling to enter the tree — cuts the same way in reverse,
   since a `Do` rewritten by a planner to match its own record would move the
   ruling back into the entry.

## Outcome

A126 is unblocked with the decision it was waiting on, and the answer is
smaller than either shape the row offered: **nothing moves, no parse is
written, and the document's existing §5/§5a split is what governs.** Three
needles become row-scoped reads of §5's `MAX_CHAIN_CERTS` row; four become
exactly-once searches of §5a, one of them joined to its derivation because it
has two homes there. §5a gains one paragraph recording the ruling — which
A126's `Accept` requires — and one narrowed sentence that is currently false.

The row's lean is overturned on the document's own logic rather than on the
freeze, and the brief's framing of the alternative is overturned too: shape (b)
needed no parse, because A123's fix already contained the instrument for a
figure with no row and nobody had noticed it was three instruments and not one.
