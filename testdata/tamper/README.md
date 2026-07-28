# tamper/ — tamper-matrix fixtures (Q7/Q8)

Pre-mutated fixtures for the tamper-matrix harness (MVP-SPEC.md line 168:
**every mutation fails with a distinct error**; no row may panic). The Q7
harness defines the row shape `{row-id, base fixture, mutation, expected
outcome}`; rows are contributed by **F, C, G, A, R** (each owning its
format's mutation families).

## `MATRIX.json` — the Q8 completeness registry

Maps the spec's M0/M2 mutation enumeration **1:1** onto implemented rows.
Checker: `crates/antseal-core/tests/tamper_completeness/mod.rs`, run from
`tests/tamper_matrix.rs` (CI lane `tamper-matrix`). Error-code contract the
rows bind to: `../../docs/testing/error-code-contract.md` (D30).

> **Format note.** `tasks/Q.md` Q8 suggests `MATRIX.toml` ("e.g."). JSON was
> chosen instead: the workspace has no `toml` crate, adding a dependency is
> a deliberate reviewed event (`docs/dependency-policy.md`), and `serde_json`
> is already a normal dependency of `antseal-core`. This follows F4's
> precedent — `docs/format/registry-v1.json` is the machine-readable mirror
> for the same reason.

Three kinds of entry, and the distinction is the point:

| Section | Meaning |
| --- | --- |
| `families[]` | The spec's own rows. Every **case** either names implemented row ids or carries a `pending` marker naming the task that owes it. **There is no third state** — a case with neither fails the check, so a missing row is never silently absent. |
| `project_added[]` | Implemented rows the spec's line-168 list does *not* name. Legitimate — line 168's framing is "every mutation fails with a distinct error", which its list illustrates rather than exhausts — but each carries a recorded justification, so the 1:1 spec mapping stays honest about which rows came from where. |
| `non_rows[]` | Mutations that deliberately will **not** become rows, because another row already claims their outcome and Q7's distinctness assertion correctly refuses the pair. Recorded with the reason and where the property lives instead. |

What makes it a real 1:1 check rather than a restatement: every family's
`spec_quote` must be a **literal substring of MVP-SPEC.md line 168**, in its
own milestone's half of that line. A family cannot be invented, and a
reworded spec line turns the check red instead of drifting. Family counts,
the exact pending set, and the non-row set are pinned in the checker as a
second layer, so nothing can be deleted to make a run green.

**Pending markers.** F15, G19, R7 and R8 have not run, so the M0 matrix is
genuinely incomplete. The gap is held as enumerated markers — task, row id,
and the outcome the row will bind — not by weakening the check. **Q14's
gate condition is zero pending**, printed by the lane every run.

**Q18** extends the same structure with the M2 anchor rows, which are
already enumerated here as pending, so extending is a data change rather
than a schema change.

### Adding a row

1. Write the row per the harness procedure
   (`crates/antseal-core/src/test_util/tamper.rs` module docs).
2. In `MATRIX.json`, either replace the case's `pending` block with
   `"rows": ["<row-id>"]`, or — if the spec does not name the mutation —
   add a `project_added` entry with an owner and a justification.
3. If it was pending, delete its `EXPECTED_M0_PENDING` entry in the checker
   **in the same commit**. That pairing is deliberate: it forces the
   completeness claim to be reviewed alongside the row.
4. If the row cannot exist because another row already claims its outcome,
   that is a `non_rows` entry plus a property test — never an edited
   expected code (error-code contract §3).

Fuzz regression cases from crash triage (Q9) are also added here when a
crash reduces to a deterministic malformed input.

NON-SECRET fixtures only (see `../README.md`): mutations are applied to
fixtures derived from the documented fixed test seed — a tampered fixture
is still committed material and follows the same convention.
