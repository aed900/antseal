//! Q8 — the tamper-matrix **completeness** registry check.
//!
//! Q7 built the harness and proved that every *registered* row fails
//! distinctly. That says nothing about the rows that were never written.
//! This module closes the other half: `testdata/tamper/MATRIX.json` maps
//! MVP-SPEC.md line 168's mutation enumeration onto implemented rows, and
//! the checks here make the mapping impossible to fake.
//!
//! # The three states, and why there is no fourth
//!
//! Every spec case is **implemented** (names live row ids), **pending**
//! (names the task that owes it, the row id it will carry, and the outcome
//! it will bind), or discharged by a recorded **non-row** (names a
//! `non_rows[]` entry). There is no "not applicable" and no silent gap: a
//! case with none of the three is a hard failure, and so is a case with two.
//! The registry is therefore complete *by construction* whether or not the
//! matrix is.
//!
//! **Since F15 (2026-07-28) the M0 half is complete: zero pending.** That is
//! Q14's gate condition, and it is now satisfied rather than merely
//! enumerated. The M2 anchor cases stay pending under A21/Q18, which is why
//! every mechanism below — the three states, the pinned pending set, the
//! collision checks — remains live rather than vestigial; the tests of those
//! mechanisms simply anchor on M2 cases now that no M0 one is owed.
//!
//! ## Why the third state exists (decision D81)
//!
//! It was added deliberately, and it is a widening, so the constraint
//! matters. Some spec cases can **never** have a row: their mutation is
//! observationally identical to another case's, so `check_registry` would
//! correctly refuse the pair. Before D81 such a case could only be written
//! `pending` — and **Q14's gate is `m0_pending.is_empty()`**, so a case that
//! can never land a row would have kept the freeze gate red forever. That is
//! not a reason to weaken the gate; it is a reason for the registry to be
//! able to say "discharged, and here is the argument".
//!
//! The discharge is checked, not prose. A `non_row` case names an entry in
//! `non_rows[]`, and every such entry's `collides_with` must already resolve
//! to a live or reserved row id — so discharging a case this way
//! transitively names a row that actually claims the outcome, which is the
//! same strength `pending` has. It is pinned twice besides: the non-row set
//! is pinned by [`EXPECTED_NON_ROWS`] and the discharged-case set by
//! [`EXPECTED_M0_NON_ROW_CASES`], both outside the registry, so a case
//! cannot be silently discharged by editing one file.
//!
//! It remains weaker than a row, and D81 says so in its own cost section.
//! The alternative was to mint a permanent error code for information the
//! construction is built not to have.
//!
//! Implemented rows the spec does **not** name are legitimate — line 168's
//! own framing is "every mutation fails with a distinct error", and its
//! list illustrates that rule rather than exhausting it — but each must be
//! declared in `project_added` with a recorded justification, so the 1:1
//! spec mapping stays honest about which rows came from where.
//!
//! # What makes this a real 1:1 check
//!
//! Every family carries a `spec_quote` that must be a **literal substring
//! of MVP-SPEC.md line 168**, in the correct milestone's half of that line.
//! A family cannot be invented, and if the spec line is reworded the
//! registry goes red instead of quietly drifting. Counts and the exact
//! pending set are pinned besides, so a family or a pending marker cannot
//! be deleted to make a run green.
//!
//! # Non-rows
//!
//! Some mutations deliberately will **not** become rows because they
//! surface as an outcome another row already claims, and Q7's distinctness
//! assertion correctly refuses the pair. Recording them — with the reason
//! and where the property lives instead — is what stops a future
//! contributor from "completing" the matrix by adding one and breaking the
//! harness. See `non_rows` in the registry.

use std::collections::{BTreeMap, BTreeSet};

use antseal_core::test_util::tamper::TamperRow;
use serde_json::Value;

/// The committed registry (workspace-relative via the crate manifest dir).
const MATRIX_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../testdata/tamper/MATRIX.json"
);

/// The spec the registry maps against.
const SPEC_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../MVP-SPEC.md");

/// Registry schema version this checker implements.
const REGISTRY_VERSION: u64 = 1;

// ---------------------------------------------------------------------------
// pinned expectations — the second layer over the registry's own contents
// ---------------------------------------------------------------------------

/// **Every M0 spec case still owed, with its owning task**, pinned here so
/// a `pending` marker cannot be deleted to make the registry look complete.
///
/// Entries are `(family/case, task, row_id)` in registry order. Landing one
/// means deleting its registry `pending` block *and* its row here, in the
/// same commit as the tamper row — which is exactly the review moment the
/// pinning exists to force.
///
/// **Empty since F15 (2026-07-28): the M0 tamper matrix is COMPLETE.** The
/// last two owed rows were `oversized-or-deep-cbor`'s pair, and F15 landed
/// them as `cbor-oversized` (code `bundle-too-large`) and
/// `cbor-nesting-too-deep`. Emptiness is not the absence of a pin — it *is*
/// the pin: [`assert_pending_set_is_the_pinned_one`] requires this list and
/// the registry's pending set to agree in both directions, so re-opening an
/// M0 obligation means adding a row here in the same commit, and Q14's gate
/// (zero pending) reads the same predicate.
///
/// Source: MVP-SPEC.md line 168, cross-read against tasks/F.md F15,
/// tasks/G.md G19 and tasks/R.md R7/R8, which owned the rows.
const EXPECTED_M0_PENDING: &[(&str, &str, &str)] = &[];

/// Number of **M0** families the spec's line-168 enumeration contains.
///
/// Derived by enumerating that line's `(M0)` clause; changing this number
/// means re-reading the spec line, not adjusting a constant to fit.
const EXPECTED_M0_FAMILIES: usize = 17;

/// Number of **M2** anchor families on the same line, registered ahead of
/// Q18 so extending the matrix is a data change, not a schema change
/// (tasks/Q.md Q8 accept: "Registry format supports the M2 anchor
/// extension").
///
/// **Families, not cases** — the (M2) clause has six semicolon-separated
/// clauses and two of them are compound, so six families carry
/// [`EXPECTED_M2_CASES`] cases. Splitting a compound clause adds a case and
/// must NOT add a family.
const EXPECTED_M2_FAMILIES: usize = 6;

/// Number of **M2** anchor spec cases the six families expand to.
///
/// **Eight, and the number is the finding.** `TODO.md`, the M2 gate line and
/// `tasks/A.md` A21 all said seven — and the tree reached "seven" twice by
/// *different* routes, so the two sevens were never the same seven: this
/// registry split the expiry clause and kept the digest clause whole (6
/// families, 7 cases), while A21's `Do` split the digest clause and kept the
/// expiry clause whole (7 numbered items describing 8 tests). D53 §8 read
/// line 168's (M2) half back: six clauses, of which clauses 1 and 5 are each
/// explicitly compound, expanding to **eight** cases. Both halves of clause 1
/// are now cases here, because under §4b layer 3 they are different checks in
/// different stages on different artifact kinds (`.ots` stamped digest at
/// A11; `TSTInfo.messageImprint` at A8) and cannot share an outcome key.
///
/// Pinned on **cases** rather than on pending markers so it survives A21:
/// when a case lands its row it stops being pending, but it is still a case.
const EXPECTED_M2_CASES: usize = 8;

/// M2 anchor cases whose expected outcome is still `null`, each with the
/// decision that owes the code.
///
/// **This list is the anti-dormancy latch.** §4b layer 3 —
/// *"a pending row whose expected code is already claimed … fails the
/// registry"* — compares `expected` keys and **skips every case whose
/// `expected` is null**. Until Q76 filled them in, four of the seven M2
/// anchor cases carried `null`, so the check that D53 §2a calls the decisive
/// argument (a back-dated token cannot be registered at
/// `verdict:internally-consistent-only`, because `anchor-untrusted-root`
/// already claims that key) had **nothing to compare**: it was dormant, not
/// satisfied. Filling the keys in is what arms it. This list is what keeps it
/// armed — every remaining null must be named here with the decision that
/// owes it, so a second null cannot appear silently and this one cannot
/// outlive its decision.
///
/// Pinned in **both** directions, the [`EXPECTED_M0_PENDING`] pattern: an
/// unlisted null fails, and a listed case whose code has since been minted
/// fails too.
/// **Empty since Q75 (2026-08-06), and empty is the finished state.** The
/// last entry — `ber-where-der-required` — was released when D93 §10 ruled
/// that A5's code `anchor-der-not-strict` had been named by D60 §7.3 and the
/// cell was simply owed an edit. With it gone, layer 3 compares **all eight**
/// M2 outcome keys instead of seven, which is the whole of Q76's arming
/// argument discharged.
///
/// Emptying it is not the same as removing it: the arming assertion still
/// reads it in both directions, so the first future null that appears
/// unlisted fails immediately. What *did* change with A21 is that a null can
/// no longer hide in a pending case at all — there are none — which is why
/// [`assert_m2_anchor_set_is_armed`] now follows the M2 cases into their live
/// state rather than iterating a set that is permanently empty (decision
/// D96 rider (b)).
///
/// **One entry.** Three more were held here between Q76 and **D91**, because
/// two decisions resolved on 2026-08-02 proposed different prefixes for the A
/// domain (D53 §7 `anchor-` vs D58 §10.4 `ots-` plus a predicted `tsa-`) and
/// §3 of the error-code contract makes whichever binds first permanent —
/// filling them would have decided the namespace by accident. D91 ruled one
/// prefix, `anchor-`, and the three were released (D91 §9.1/§9.2). The row
/// ids were never held: a prefix ruling renames no row.
///
/// **The list must never silently empty**, which is why the release is an
/// edit here rather than a deletion of the mechanism: the arming assertion
/// reads it in *both* directions, so an unlisted null fails and a listed cell
/// that has since been filled fails too.
///
/// The four **verdict** cells are deliberately absent. Verdict states live in
/// a namespace separate from error codes (contract §5, owned by A18/R17), so
/// no prefix ruling reaches them — which is what kept layer 3 comparing
/// something rather than nothing while the codes were owed.
const EXPECTED_M2_UNMINTED: &[(&str, &str)] = &[];

/// Mutations deliberately recorded as non-rows (see the module docs).
///
/// **Vec equality — order is part of the pin**, so an entry cannot be
/// swapped for another without the diff showing it.
const EXPECTED_NON_ROWS: &[&str] = &[
    "full-reveal-unit-strip-downgrade",
    "crypto-level-ggm-seed-length",
    "full-reveal-cover-seed-not-descending-from-s-root",
    "swapped-unit-ciphertext",
    "pipeline-level-wrong-unit-key",
    "pipeline-level-wrong-unit-salt",
];

/// **Every M0 spec case discharged by a recorded non-row**, as
/// `(family/case, non_row id)` in registry order (decision D81).
///
/// Pinned outside the registry for the same reason [`EXPECTED_M0_PENDING`]
/// is: `non_row` is the one case state that neither names a live row nor
/// leaves an obligation on Q14's gate, so without this a case could be
/// discharged by editing one file and nothing would notice. Adding an entry
/// here is the review moment where someone has to agree that the case
/// genuinely cannot have a row.
///
/// One entry, and D81 is the record that justifies it: the spec's
/// `swapped unit` mutation is observationally identical to the flipped
/// ciphertext byte, because an AEAD authentication failure is one bit by
/// construction. It is asserted by two named tests and an R10 property
/// instead.
const EXPECTED_M0_NON_ROW_CASES: &[(&str, &str)] =
    &[("swapped-unit/swapped-unit", "swapped-unit-ciphertext")];

// ---------------------------------------------------------------------------
// model
// ---------------------------------------------------------------------------

/// One still-owed spec case.
pub struct PendingCase {
    /// `family/case`.
    pub path: String,
    /// Task id that owes it.
    pub task: String,
    /// Row id it will carry.
    pub row_id: String,
    /// Namespaced expected outcome (`error:…` / `verdict:…`), when known.
    pub expected_key: Option<String>,
}

/// The checked registry.
pub struct Registry {
    /// Still-owed M0 cases, in registry order.
    pub m0_pending: Vec<PendingCase>,
    /// Still-owed M2 cases, in registry order.
    pub m2_pending: Vec<PendingCase>,
    /// M0 spec cases with at least one implemented row.
    pub m0_implemented_cases: usize,
    /// M0 spec cases discharged by a recorded non-row, as
    /// `(family/case, non_row id)` in registry order (D81).
    pub m0_non_row_cases: Vec<(String, String)>,
    /// Total M0 spec cases (implemented + pending + non-row).
    pub m0_cases: usize,
    /// Total M2 spec cases, in whatever state (see [`EXPECTED_M2_CASES`]).
    pub m2_cases: usize,
    /// M2 spec cases discharged by **live rows**, as `(family/case, row id)`
    /// in registry order.
    ///
    /// Added when A21 emptied the M2 pending set (D96 rider (b)): with
    /// nothing pending, an arming check that only reads `m2_pending` reads
    /// nothing, so the assertion follows the cases into their live state
    /// instead.
    pub m2_rows: Vec<(String, String)>,
    /// Implemented rows declared as project additions.
    pub project_added: Vec<String>,
    /// Deliberate non-row ids.
    pub non_rows: Vec<String>,
}

impl Registry {
    /// **Q14's gate condition.** The M0 tamper matrix is complete when no
    /// spec case is still owed.
    #[must_use]
    pub fn m0_is_complete(&self) -> bool {
        self.m0_pending.is_empty()
    }
}

// ---------------------------------------------------------------------------
// JSON helpers — every accessor is fallible and names its context
// ---------------------------------------------------------------------------

struct Checker {
    failures: Vec<String>,
}

fn obj<'a>(value: &'a Value, ctx: &str) -> Result<&'a serde_json::Map<String, Value>, String> {
    value
        .as_object()
        .ok_or_else(|| format!("{ctx}: expected a JSON object"))
}

fn array<'a>(value: &'a Value, key: &str, ctx: &str) -> Result<&'a Vec<Value>, String> {
    value
        .get(key)
        .and_then(Value::as_array)
        .ok_or_else(|| format!("{ctx}: field `{key}` must be an array"))
}

fn text<'a>(value: &'a Value, key: &str, ctx: &str) -> Result<&'a str, String> {
    let found = value
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{ctx}: field `{key}` must be a string"))?;
    if found.trim().is_empty() {
        return Err(format!(
            "{ctx}: field `{key}` is empty — every justification, owner and description in this \
             registry is load-bearing"
        ));
    }
    Ok(found)
}

/// Reject unknown keys: a typo'd field would otherwise be silently ignored
/// and its rule silently unenforced.
fn only_keys(value: &Value, allowed: &[&str], ctx: &str) -> Result<(), String> {
    let map = obj(value, ctx)?;
    let unknown: Vec<&str> = map
        .keys()
        .map(String::as_str)
        .filter(|k| !allowed.contains(k))
        .collect();
    if unknown.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "{ctx}: unknown field(s) {unknown:?} — allowed: {allowed:?}"
        ))
    }
}

fn is_task_id(task: &str) -> bool {
    let mut chars = task.chars();
    chars.next().is_some_and(|c| c.is_ascii_uppercase())
        && chars.clone().count() > 0
        && chars.all(|c| c.is_ascii_digit())
}

// ---------------------------------------------------------------------------
// the check
// ---------------------------------------------------------------------------

/// Read, parse and fully check the committed registry against `rows`.
///
/// # Errors
///
/// Every violation found, so one run reports the whole picture.
pub fn check(rows: &[TamperRow]) -> Result<Registry, Vec<String>> {
    let text_bytes = match std::fs::read_to_string(MATRIX_PATH) {
        Ok(t) => t,
        Err(e) => return Err(vec![format!("cannot read {MATRIX_PATH}: {e}")]),
    };
    check_text(&text_bytes, rows)
}

/// The whole check over registry *text*, so the tests-of-the-test below can
/// feed deliberately broken registries through the identical path.
#[expect(
    clippy::too_many_lines,
    reason = "one linear pass over one registry file; the checks share the \
              accumulated claim/outcome state, and splitting them would mean \
              threading five maps through helpers"
)]
fn check_text(text_bytes: &str, rows: &[TamperRow]) -> Result<Registry, Vec<String>> {
    let mut c = Checker {
        failures: Vec::new(),
    };

    let root: Value = match serde_json::from_str(text_bytes) {
        Ok(v) => v,
        Err(e) => return Err(vec![format!("{MATRIX_PATH} does not parse: {e}")]),
    };
    if let Err(e) = only_keys(
        &root,
        &[
            "registry_version",
            "_readme",
            "spec_source",
            "families",
            "project_added",
            "non_rows",
        ],
        "registry root",
    ) {
        c.failures.push(e);
    }
    match root.get("registry_version").and_then(Value::as_u64) {
        Some(v) if v == REGISTRY_VERSION => {}
        other => c.failures.push(format!(
            "registry_version must be {REGISTRY_VERSION}, got {other:?}"
        )),
    }

    // The two halves of MVP-SPEC.md line 168, located by content rather
    // than by line number so a spec edit above it cannot silently
    // mis-anchor the check.
    let (m0_spec, m2_spec) = match spec_halves(&root) {
        Ok(halves) => halves,
        Err(e) => {
            c.failures.push(e);
            (String::new(), String::new())
        }
    };

    // Live rows, by id and by the outcome they claim.
    let live_ids: BTreeSet<&str> = rows.iter().map(|r| r.id).collect();
    if live_ids.len() != rows.len() {
        c.failures.push(
            "the live registry has duplicate row ids (Q7's own check should have caught \
                   this first)"
                .to_owned(),
        );
    }
    let mut outcome_owner: BTreeMap<String, String> = BTreeMap::new();
    for row in rows {
        outcome_owner.insert(row.expected.key(), row.id.to_owned());
    }

    // Which live rows each part of the registry claims, so we can prove
    // every row is accounted for exactly once.
    let mut claimed: BTreeMap<String, String> = BTreeMap::new();
    let mut registry = Registry {
        m0_pending: Vec::new(),
        m2_pending: Vec::new(),
        m0_implemented_cases: 0,
        m0_non_row_cases: Vec::new(),
        m0_cases: 0,
        m2_cases: 0,
        m2_rows: Vec::new(),
        project_added: Vec::new(),
        non_rows: Vec::new(),
    };
    // Row ids a `pending` block reserves, so `non_rows.collides_with` may
    // point at a row that does not exist yet.
    let mut reserved_ids: BTreeSet<String> = BTreeSet::new();

    // Non-row ids, collected in a pre-pass because a case may discharge
    // itself by naming one (D81) and cases are walked first. The entries
    // themselves are validated in their own section below; here we only
    // need the id set.
    let declared_non_rows: BTreeSet<String> = array(&root, "non_rows", "registry root")
        .map(|list| {
            list.iter()
                .filter_map(|entry| entry.get("id").and_then(Value::as_str))
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();

    let families = match array(&root, "families", "registry root") {
        Ok(list) => list.clone(),
        Err(e) => {
            c.failures.push(e);
            Vec::new()
        }
    };
    let mut family_ids: BTreeSet<String> = BTreeSet::new();
    let mut m0_families = 0usize;
    let mut m2_families = 0usize;

    for family in &families {
        let ctx = "families[]";
        if let Err(e) = only_keys(
            family,
            &["id", "milestone", "owner", "spec_quote", "note", "cases"],
            ctx,
        ) {
            c.failures.push(e);
        }
        let (id, milestone, quote) = match (
            text(family, "id", ctx),
            text(family, "milestone", ctx),
            text(family, "spec_quote", ctx),
        ) {
            (Ok(a), Ok(b), Ok(d)) => (a, b, d),
            (a, b, d) => {
                for e in [a.err(), b.err(), d.err()].into_iter().flatten() {
                    c.failures.push(e);
                }
                continue;
            }
        };
        let ctx = format!("families[{id}]");
        if let Err(e) = text(family, "owner", &ctx) {
            c.failures.push(e);
        }
        if !family_ids.insert(id.to_owned()) {
            c.failures.push(format!("{ctx}: duplicate family id"));
        }

        // The 1:1 anchor: the family is quoted from the spec, in its own
        // milestone's half of the line.
        let half = match milestone {
            "M0" => {
                m0_families += 1;
                &m0_spec
            }
            "M2" => {
                m2_families += 1;
                &m2_spec
            }
            other => {
                c.failures
                    .push(format!("{ctx}: milestone must be M0 or M2, got `{other}`"));
                continue;
            }
        };
        if !half.is_empty() && !half.contains(quote) {
            c.failures.push(format!(
                "{ctx}: spec_quote is not a literal substring of MVP-SPEC.md line 168's \
                 ({milestone}) half — the registry may not invent a family, and a reworded spec \
                 line must be re-read, not worked around.\n      quote: {quote}"
            ));
        }

        let cases = match array(family, "cases", &ctx) {
            Ok(list) => list.clone(),
            Err(e) => {
                c.failures.push(e);
                continue;
            }
        };
        if cases.is_empty() {
            c.failures.push(format!("{ctx}: `cases` is empty"));
        }
        let mut case_ids: BTreeSet<String> = BTreeSet::new();
        for case in &cases {
            if let Err(e) = only_keys(case, &["id", "what", "rows", "pending", "non_row"], &ctx) {
                c.failures.push(e);
            }
            let case_id = match text(case, "id", &ctx) {
                Ok(v) => v,
                Err(e) => {
                    c.failures.push(e);
                    continue;
                }
            };
            let path = format!("{id}/{case_id}");
            if let Err(e) = text(case, "what", &path) {
                c.failures.push(e);
            }
            if !case_ids.insert(case_id.to_owned()) {
                c.failures.push(format!("{path}: duplicate case id"));
            }
            if milestone == "M0" {
                registry.m0_cases += 1;
            } else {
                registry.m2_cases += 1;
            }

            // Exactly one of the three states (module docs, D81). Zero is
            // the silent gap the registry exists to prevent; two or three
            // is an unresolved claim about the same case, and a stale
            // marker beside a live one is how coverage gets overstated.
            let states: Vec<&str> = ["rows", "pending", "non_row"]
                .into_iter()
                .filter(|key| case.get(*key).is_some())
                .collect();
            match states.as_slice() {
                [] => c.failures.push(format!(
                    "{path}: has none of `rows`, `pending` or `non_row`. A spec case is never \
                     silently absent: name the row ids, name the task that owes it, or name the \
                     recorded non-row that discharges it"
                )),
                [_] => {}
                many => c.failures.push(format!(
                    "{path}: declares {many:?} together — a case is in exactly ONE of the three \
                     states, and a stale marker beside a live one hides which claim is current"
                )),
            }
            if states.len() == 1 {
                match states[0] {
                    "rows" => {
                        if milestone == "M0" {
                            registry.m0_implemented_cases += 1;
                        } else {
                            for id in case
                                .get("rows")
                                .and_then(Value::as_array)
                                .into_iter()
                                .flatten()
                                .filter_map(Value::as_str)
                            {
                                registry.m2_rows.push((path.clone(), id.to_owned()));
                            }
                        }
                        c.check_case_rows(case, &path, &live_ids, &mut claimed);
                    }
                    "pending" => {
                        if let Some(p) = c.check_pending(
                            case,
                            &path,
                            &live_ids,
                            &outcome_owner,
                            &mut reserved_ids,
                        ) {
                            if milestone == "M0" {
                                registry.m0_pending.push(p);
                            } else {
                                registry.m2_pending.push(p);
                            }
                        }
                    }
                    _ => {
                        if let Some(id) = c.check_case_non_row(case, &path, &declared_non_rows)
                            && milestone == "M0"
                        {
                            registry.m0_non_row_cases.push((path.clone(), id));
                        }
                    }
                }
            }
        }
    }

    // Pending outcomes must be distinct from each other too, unless the
    // entry says out loud that they are not.
    c.check_pending_cross_distinctness(&families);

    // Implemented rows the spec does not name.
    for entry in array(&root, "project_added", "registry root")
        .cloned()
        .unwrap_or_default()
    {
        let ctx = "project_added[]";
        if let Err(e) = only_keys(&entry, &["row_id", "owner", "why"], ctx) {
            c.failures.push(e);
        }
        let row_id = match text(&entry, "row_id", ctx) {
            Ok(v) => v,
            Err(e) => {
                c.failures.push(e);
                continue;
            }
        };
        let ctx = format!("project_added[{row_id}]");
        for key in ["owner", "why"] {
            if let Err(e) = text(&entry, key, &ctx) {
                c.failures.push(e);
            }
        }
        if !live_ids.contains(row_id) {
            c.failures.push(format!(
                "{ctx}: names no implemented row — a project addition documents a row that \
                 EXISTS; a row that does not is a `pending` case instead"
            ));
        }
        if let Some(other) = claimed.insert(row_id.to_owned(), format!("project_added[{row_id}]")) {
            c.failures
                .push(format!("{ctx}: row already claimed by {other}"));
        }
        registry.project_added.push(row_id.to_owned());
    }

    // Deliberate non-rows.
    for entry in array(&root, "non_rows", "registry root")
        .cloned()
        .unwrap_or_default()
    {
        let ctx = "non_rows[]";
        if let Err(e) = only_keys(
            &entry,
            &[
                "id",
                "milestone",
                "owner",
                "mutation",
                "collides_with",
                "why",
                "instead",
                "record",
                "warning",
            ],
            ctx,
        ) {
            c.failures.push(e);
        }
        let id = match text(&entry, "id", ctx) {
            Ok(v) => v,
            Err(e) => {
                c.failures.push(e);
                continue;
            }
        };
        let ctx = format!("non_rows[{id}]");
        for key in [
            "milestone",
            "owner",
            "mutation",
            "collides_with",
            "why",
            "instead",
            "record",
        ] {
            if let Err(e) = text(&entry, key, &ctx) {
                c.failures.push(e);
            }
        }
        // The whole point of a non-row is that some OTHER row already owns
        // its outcome. If that row exists in neither the live registry nor
        // the pending set, the justification is unverifiable prose.
        if let Ok(collides) = text(&entry, "collides_with", &ctx)
            && !live_ids.contains(collides)
            && !reserved_ids.contains(collides)
        {
            c.failures.push(format!(
                "{ctx}: `collides_with` names `{collides}`, which is neither an implemented row \
                 nor a row id reserved by a `pending` marker — a non-row is only justified by a \
                 row that actually claims the outcome"
            ));
        }
        registry.non_rows.push(id.to_owned());
    }

    // Nothing implemented may sit outside the registry.
    for row in rows {
        if !claimed.contains_key(row.id) {
            c.failures.push(format!(
                "implemented row `{}` is in NO registry entry — map it to the spec case it \
                 satisfies, or declare it in `project_added` with a justification. An \
                 unaccounted row makes the 1:1 spec mapping meaningless",
                row.id
            ));
        }
    }

    // Counts pinned outside the registry, so a family cannot be deleted.
    if m0_families != EXPECTED_M0_FAMILIES {
        c.failures.push(format!(
            "registry has {m0_families} M0 families; MVP-SPEC.md line 168's (M0) clause \
             enumerates {EXPECTED_M0_FAMILIES}"
        ));
    }
    if m2_families != EXPECTED_M2_FAMILIES {
        c.failures.push(format!(
            "registry has {m2_families} M2 families; the (M2) clause enumerates \
             {EXPECTED_M2_FAMILIES}"
        ));
    }

    if c.failures.is_empty() {
        Ok(registry)
    } else {
        Err(c.failures)
    }
}

impl Checker {
    fn check_case_rows(
        &mut self,
        case: &Value,
        path: &str,
        live_ids: &BTreeSet<&str>,
        claimed: &mut BTreeMap<String, String>,
    ) {
        let list = match array(case, "rows", path) {
            Ok(list) => list.clone(),
            Err(e) => {
                self.failures.push(e);
                return;
            }
        };
        if list.is_empty() {
            self.failures.push(format!(
                "{path}: `rows` is empty — an implemented case names at least one row id"
            ));
        }
        for row in &list {
            let Some(row_id) = row.as_str() else {
                self.failures
                    .push(format!("{path}: `rows` entries must be strings"));
                continue;
            };
            match live_ids.get(row_id) {
                None => self.failures.push(format!(
                    "{path}: names row `{row_id}`, which does not exist in the live tamper \
                     registry. Either the row was renamed — row ids are permanent handles — or \
                     this case is not implemented and belongs under a `pending` marker"
                )),
                Some(live) => {
                    if let Some(other) = claimed.insert((*live).to_owned(), path.to_owned()) {
                        self.failures.push(format!(
                            "{path}: row `{row_id}` is already claimed by {other} — a row \
                             satisfies exactly one registry entry"
                        ));
                    }
                }
            }
        }
    }

    /// A case discharged by a recorded non-row (D81).
    ///
    /// The only rule is that the named id is a real `non_rows[]` entry —
    /// and that is enough, because every such entry has already been
    /// required to name a `collides_with` row that is live or reserved. So
    /// discharging a case this way transitively names a row that claims the
    /// outcome, rather than resting on prose. A dangling name would make
    /// the discharge unverifiable, which is exactly the state a `pending`
    /// marker with no task id would be in.
    fn check_case_non_row(
        &mut self,
        case: &Value,
        path: &str,
        declared_non_rows: &BTreeSet<String>,
    ) -> Option<String> {
        let Some(id) = case.get("non_row").and_then(Value::as_str) else {
            self.failures
                .push(format!("{path}: `non_row` must be a string"));
            return None;
        };
        if !declared_non_rows.contains(id) {
            self.failures.push(format!(
                "{path}: `non_row` names `{id}`, which is not an entry in `non_rows[]` — a case \
                 discharged without a row is only honest if the recorded argument exists, and \
                 that entry is where its colliding row is named"
            ));
            return None;
        }
        Some(id.to_owned())
    }

    fn check_pending(
        &mut self,
        case: &Value,
        path: &str,
        live_ids: &BTreeSet<&str>,
        outcome_owner: &BTreeMap<String, String>,
        reserved_ids: &mut BTreeSet<String>,
    ) -> Option<PendingCase> {
        let pending = case.get("pending")?;
        let ctx = format!("{path}.pending");
        if let Err(e) = only_keys(
            pending,
            &[
                "task",
                "row_id",
                "outcome_kind",
                "expected",
                "why",
                "hazard",
                "collision_note",
            ],
            &ctx,
        ) {
            self.failures.push(e);
        }
        let task = text(pending, "task", &ctx).ok()?;
        let row_id = text(pending, "row_id", &ctx).ok()?;
        if let Err(e) = text(pending, "why", &ctx) {
            self.failures.push(e);
        }
        if !is_task_id(task) {
            self.failures.push(format!(
                "{ctx}: `task` must be a task id like `R7`, got `{task}` — an unowned obligation \
                 is indistinguishable from a forgotten one"
            ));
        }
        if live_ids.contains(row_id) {
            self.failures.push(format!(
                "{ctx}: reserves row id `{row_id}`, which ALREADY EXISTS — the case is \
                 implemented; replace the pending marker with `rows`"
            ));
        }
        if !reserved_ids.insert(row_id.to_owned()) {
            self.failures
                .push(format!("{ctx}: row id `{row_id}` reserved twice"));
        }

        let kind = match pending.get("outcome_kind").and_then(Value::as_str) {
            Some(k @ ("error" | "verdict")) => k,
            other => {
                self.failures.push(format!(
                    "{ctx}: `outcome_kind` must be `error` or `verdict` (the two namespaces the \
                     Q7 harness keeps separate), got {other:?}"
                ));
                return None;
            }
        };
        // `expected` may be null: for rows whose owning task still has to
        // MINT the code (F15's size cap, the M2 anchor set). Null is a
        // recorded unknown, not a missing field — the key must be present.
        if !pending
            .get("expected")
            .is_some_and(|v| v.is_string() || v.is_null())
        {
            self.failures.push(format!(
                "{ctx}: `expected` must be a string or null (null = the owning task still mints \
                 the code); the field itself is never omitted"
            ));
        }
        let expected_key = pending
            .get("expected")
            .and_then(Value::as_str)
            .map(|code| format!("{kind}:{code}"));

        // A pending row that claims an outcome an implemented row already
        // owns cannot become a row. Saying so here — at registry time —
        // beats discovering it when `check_registry` refuses the pair.
        if let Some(key) = &expected_key
            && let Some(owner) = outcome_owner.get(key)
            && pending.get("collision_note").is_none()
        {
            self.failures.push(format!(
                "{ctx}: expected outcome `{key}` is ALREADY claimed by implemented row \
                 `{owner}`, so this row cannot be added — Q7's distinctness assertion would \
                 refuse it. Either the owning task mints a distinct code (error-code contract \
                 §4) or this becomes a `non_rows` entry. Add a `collision_note` if the collision \
                 is known and deliberate"
            ));
        }

        Some(PendingCase {
            path: path.to_owned(),
            task: task.to_owned(),
            row_id: row_id.to_owned(),
            expected_key,
        })
    }

    /// Two pending rows expecting the same outcome are the same collision
    /// as two implemented ones — it just has not happened yet. Surface it
    /// now, unless the registry already says so.
    fn check_pending_cross_distinctness(&mut self, families: &[Value]) {
        let mut seen: BTreeMap<String, String> = BTreeMap::new();
        for family in families {
            let family_id = family.get("id").and_then(Value::as_str).unwrap_or("?");
            for case in family
                .get("cases")
                .and_then(Value::as_array)
                .map(Vec::as_slice)
                .unwrap_or_default()
            {
                let case_id = case.get("id").and_then(Value::as_str).unwrap_or("?");
                let Some(pending) = case.get("pending") else {
                    continue;
                };
                let (Some(kind), Some(code)) = (
                    pending.get("outcome_kind").and_then(Value::as_str),
                    pending.get("expected").and_then(Value::as_str),
                ) else {
                    continue;
                };
                let path = format!("{family_id}/{case_id}");
                let key = format!("{kind}:{code}");
                if let Some(other) = seen.insert(key.clone(), path.clone()) {
                    if pending.get("collision_note").is_none() {
                        self.failures.push(format!(
                            "{path}.pending: expected outcome `{key}` is also claimed by pending \
                             case `{other}`. Both cannot become rows — record a \
                             `collision_note` saying which one does and where the other is \
                             asserted instead"
                        ));
                    }
                    // Keep the first claimant so a third collision on the
                    // same outcome still reports against it.
                    seen.insert(key, other);
                }
            }
        }
    }
}

/// Split MVP-SPEC.md line 168 into its `(M0)` and `(M2)` halves.
fn spec_halves(root: &Value) -> Result<(String, String), String> {
    let source = root
        .get("spec_source")
        .ok_or_else(|| "registry root: missing `spec_source`".to_owned())?;
    only_keys(
        source,
        &["file", "line_anchor", "m0_marker", "m2_marker", "note"],
        "spec_source",
    )?;
    let anchor = text(source, "line_anchor", "spec_source")?;
    let m0_marker = text(source, "m0_marker", "spec_source")?;
    let m2_marker = text(source, "m2_marker", "spec_source")?;

    let spec =
        std::fs::read_to_string(SPEC_PATH).map_err(|e| format!("cannot read {SPEC_PATH}: {e}"))?;
    let mut matching = spec.lines().filter(|line| line.starts_with(anchor));
    let line = matching
        .next()
        .ok_or_else(|| format!("{SPEC_PATH}: no line starts with `{anchor}`"))?;
    if matching.next().is_some() {
        return Err(format!(
            "{SPEC_PATH}: `{anchor}` matches more than one line — the registry's spec anchor \
             must identify exactly one"
        ));
    }
    let m0_start = line
        .find(m0_marker)
        .ok_or_else(|| format!("{SPEC_PATH}: the tamper-matrix line has no `{m0_marker}`"))?;
    let m2_start = line
        .find(m2_marker)
        .ok_or_else(|| format!("{SPEC_PATH}: the tamper-matrix line has no `{m2_marker}`"))?;
    if m2_start <= m0_start {
        return Err(format!(
            "{SPEC_PATH}: the (M2) marker precedes the (M0) marker"
        ));
    }
    Ok((
        line[m0_start..m2_start].to_owned(),
        line[m2_start..].to_owned(),
    ))
}

fn render(failures: &[String]) -> String {
    let mut out = format!("{} tamper-completeness failure(s):\n", failures.len());
    for failure in failures {
        out.push_str("  - ");
        out.push_str(failure);
        out.push('\n');
    }
    out
}

/// Run the full check or panic with every violation.
pub fn checked(rows: &[TamperRow]) -> Registry {
    match check(rows) {
        Ok(registry) => registry,
        Err(failures) => panic!("{}", render(&failures)),
    }
}

// ---------------------------------------------------------------------------
// the assertions `tests/tamper_matrix.rs` runs
// ---------------------------------------------------------------------------

/// Spec cases map onto implemented rows or explicitly owed ones, every
/// implemented row is accounted for, and the pinned counts hold.
pub fn assert_registry_is_consistent(rows: &[TamperRow]) {
    let registry = checked(rows);
    println!(
        "tamper completeness: {} M0 spec case(s) — {} implemented, {} pending, {} \
         discharged by a non-row; {} project-added row(s); {} recorded non-row(s)",
        registry.m0_cases,
        registry.m0_implemented_cases,
        registry.m0_pending.len(),
        registry.m0_non_row_cases.len(),
        registry.project_added.len(),
        registry.non_rows.len()
    );
    assert_eq!(
        registry.m0_implemented_cases + registry.m0_pending.len() + registry.m0_non_row_cases.len(),
        registry.m0_cases,
        "every M0 spec case is implemented, pending, or discharged by a recorded non-row (D81); \
         there is no fourth state"
    );
}

/// The set of cases discharged **without a row** is exactly the pinned one.
///
/// This is the assertion that keeps D81's widening honest. A `non_row` case
/// is the only state that neither names a live row nor leaves an obligation
/// on Q14's gate, so it is the only one a contributor could use to make the
/// gate green by argument. Pinning the set outside the registry means doing
/// so requires editing this file too, in the same commit, with the decision
/// record named.
pub fn assert_non_row_cases_are_the_pinned_ones(rows: &[TamperRow]) {
    let registry = checked(rows);
    let actual: Vec<(&str, &str)> = registry
        .m0_non_row_cases
        .iter()
        .map(|(path, id)| (path.as_str(), id.as_str()))
        .collect();
    for (path, id) in &actual {
        println!("tamper matrix DISCHARGED-BY-NON-ROW {path} — {id}");
    }
    assert_eq!(
        actual, EXPECTED_M0_NON_ROW_CASES,
        "the set of spec cases discharged by a recorded non-row changed. Discharging a case this \
         way says it can NEVER have a row — the decision belongs in a record, and landing it \
         means editing this constant in the same commit as the registry"
    );
}

/// The still-owed rows are exactly the enumerated ones, each with its owner.
///
/// This is the check that keeps a gap **visible**: while the M0 matrix was
/// incomplete the honest way to hold that was an enumerated list rather than
/// a weakened check. The list is empty since F15, and the assertion is now
/// what stops it silently re-filling — an M0 case slipping back to `pending`
/// turns this red instead of only moving Q14's gate.
pub fn assert_pending_set_is_the_pinned_one(rows: &[TamperRow]) {
    let registry = checked(rows);
    let actual: Vec<(&str, &str, &str)> = registry
        .m0_pending
        .iter()
        .map(|p| (p.path.as_str(), p.task.as_str(), p.row_id.as_str()))
        .collect();
    for p in &registry.m0_pending {
        println!(
            "tamper matrix PENDING [{}] {} — {}",
            p.task, p.path, p.row_id
        );
    }
    assert_eq!(
        actual, EXPECTED_M0_PENDING,
        "the M0 pending set changed. Landing a row means deleting its registry `pending` block \
         AND its EXPECTED_M0_PENDING entry in the same commit; adding one means the spec was \
         re-read"
    );
    // The two must agree in **both** directions. Before F15 this arm read
    // `assert!(!m0_is_complete())`, which was the right assertion while the
    // pin was non-empty and would have become a permanent falsehood the
    // moment the matrix completed. Stated as an equality it keeps working
    // either way: a registry that reports COMPLETE with an obligation still
    // pinned is as much a bug as one that reports incomplete with none.
    assert_eq!(
        registry.m0_is_complete(),
        EXPECTED_M0_PENDING.is_empty(),
        "the registry's M0 completeness and EXPECTED_M0_PENDING disagree — one of the two is \
         stale, and Q14's gate reads the registry"
    );
}

/// The M2 anchor set is the right size **and its layer-3 check is armed**.
///
/// Two claims, and the second is the one that had to be earned.
///
/// 1. **Size.** [`EXPECTED_M2_CASES`] cases across [`EXPECTED_M2_FAMILIES`]
///    families. The families are already pinned inside `check_registry`; the
///    *case* count was not, which is how the tree came to hold two different
///    sevens without anything going red (see [`EXPECTED_M2_CASES`]).
/// 2. **Armed.** Every M2 case's expected outcome is a real key, except the
///    ones [`EXPECTED_M2_UNMINTED`] names — because a `null` expected makes
///    `check_pending_cross_distinctness` skip the case entirely. A registry
///    that is complete but whose distinctness check silently compares
///    nothing has not proved anything, and that was the state of this half
///    of the matrix from Q8 until Q76.
///
/// Also printed, every run: the outcome key each M2 case claims. Layer 3
/// asserts they are pairwise distinct; printing them is what lets a reader
/// see *which* eight outcomes the M2 milestone is buying.
///
/// # 3. **Discharged** — the claim that keeps 1 and 2 from going hollow
///
/// **Added by D96 rider (b), when A21 emptied the M2 pending set.** Claim 2
/// and the print loop both iterate `m2_pending`. Once nothing is pending they
/// iterate nothing, and this whole function collapses to
/// `assert_eq!(m2_cases, 8)` — which is *exactly* the "complete but comparing
/// nothing" failure claim 2 was written to prevent, one level up. Two
/// independent planners found this before the code was written, and it is the
/// edit A21 would otherwise have made by deleting an
/// [`EXPECTED_M2_UNMINTED`] entry and moving on.
///
/// So the assertion follows the cases into their live state: every M2 case is
/// now discharged by a **live row**, those rows' outcome keys are pairwise
/// distinct, and they are printed exactly as the pending keys used to be. The
/// scaffold became a permanent check instead of a vacuous one.
pub fn assert_m2_anchor_set_is_armed(rows: &[TamperRow]) {
    let registry = checked(rows);
    for p in &registry.m2_pending {
        println!(
            "tamper matrix M2 [{}] {} — {} -> {} (PENDING)",
            p.task,
            p.path,
            p.row_id,
            p.expected_key.as_deref().unwrap_or("<code to be minted>")
        );
    }
    let mut live_keys: Vec<String> = Vec::new();
    for (path, row_id) in &registry.m2_rows {
        let row = rows
            .iter()
            .find(|row| row.id == *row_id)
            .unwrap_or_else(|| panic!("M2 case {path} names row `{row_id}`, which is not live"));
        let key = row.expected.key();
        println!("tamper matrix M2 {path} — {row_id} -> {key}");
        live_keys.push(key);
    }
    assert_eq!(
        registry.m2_rows.len() + registry.m2_pending.len(),
        EXPECTED_M2_CASES,
        "every M2 case must be in exactly one of the two states this milestone has — discharged \
         by a live row, or still pending. A case in neither means the M2 half is being counted \
         by a number rather than by its contents"
    );
    let before = live_keys.len();
    live_keys.sort_unstable();
    live_keys.dedup();
    assert_eq!(
        before,
        live_keys.len(),
        "two M2 cases are discharged by rows claiming ONE outcome key. `check_registry` would \
         refuse the pair globally; this says which milestone lost the distinction"
    );
    assert_eq!(
        registry.m2_cases, EXPECTED_M2_CASES,
        "the M2 anchor case count changed. It is EIGHT (D53 §8: line 168's (M2) half is six \
         clauses, two of them compound); the project reached `seven` twice by different routes \
         and the two sevens were not the same seven. Changing this number means re-reading the \
         spec line, not adjusting a constant to fit"
    );
    let unminted: Vec<(&str, &str)> = registry
        .m2_pending
        .iter()
        .filter(|p| p.expected_key.is_none())
        .map(|p| {
            (
                p.path.as_str(),
                EXPECTED_M2_UNMINTED
                    .iter()
                    .find(|(path, _)| *path == p.path)
                    .map_or(
                        "<UNRECORDED — name the decision that owes this code>",
                        |e| e.1,
                    ),
            )
        })
        .collect();
    assert_eq!(
        unminted, EXPECTED_M2_UNMINTED,
        "the set of M2 cases with a null `expected` changed. A null makes layer 3 SKIP the case, \
         so every one of them is a hole in the cross-distinctness check and must be named here \
         with the decision that owes the code — and a case whose code has since been minted must \
         be removed here in the same commit"
    );
}

/// **Q14's gate condition**, expressed as executable code rather than
/// prose: the freeze may not be taken while any M0 spec case is still owed.
///
/// It is deliberately *not* an assertion — Q14 owns the gate, and Q8's job
/// is to compute and print the predicate every run rather than to enforce
/// it. Green since F15; the printed line is what the freeze reads.
pub fn report_q14_gate(rows: &[TamperRow]) {
    let registry = checked(rows);
    if registry.m0_is_complete() {
        println!("Q14 gate — M0 tamper matrix: COMPLETE (0 pending)");
    } else {
        println!(
            "Q14 gate — M0 tamper matrix: NOT COMPLETE, {} row(s) owed:",
            registry.m0_pending.len()
        );
        let mut by_task: BTreeMap<&str, Vec<String>> = BTreeMap::new();
        for p in &registry.m0_pending {
            // An outcome the owning task must still MINT (`expected: null`)
            // is called out: it is a code-set change, not just a fixture.
            let outcome = p
                .expected_key
                .clone()
                .unwrap_or_else(|| "<code to be minted>".to_owned());
            by_task
                .entry(&p.task)
                .or_default()
                .push(format!("{} -> {outcome}", p.path));
        }
        for (task, cases) in &by_task {
            println!("    {task}:");
            for case in cases {
                println!("      {case}");
            }
        }
        println!(
            "    M2 anchor rows additionally registered for Q18: {}",
            registry.m2_pending.len()
        );
    }
}

/// Deliberate non-rows are recorded, so a contributor cannot "complete" the
/// matrix by adding a mutation the harness will correctly refuse.
pub fn assert_non_rows_are_recorded(rows: &[TamperRow]) {
    let registry = checked(rows);
    let actual: Vec<&str> = registry.non_rows.iter().map(String::as_str).collect();
    assert_eq!(
        actual, EXPECTED_NON_ROWS,
        "the recorded non-row set changed — each entry is a mutation that MUST NOT become a row \
         because another row already claims its outcome; deleting one invites a future \
         contributor to add it and break Q7's distinctness assertion"
    );
}

// ---------------------------------------------------------------------------
// tests-of-the-test: every way the registry could lie turns the check red
//
// Each case takes the COMMITTED registry, breaks exactly one thing, and
// requires the failure. Without these, a check that silently accepted a
// hollowed-out registry would look identical to one that works.
// ---------------------------------------------------------------------------

/// The committed registry as a mutable `Value`.
fn committed_value() -> Value {
    let text = std::fs::read_to_string(MATRIX_PATH)
        .unwrap_or_else(|e| panic!("cannot read {MATRIX_PATH}: {e}"));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("committed registry does not parse: {e}"))
}

/// Rows to check against — a stand-in registry would not do, since the
/// point is the mapping onto the *real* one.
fn live_rows() -> Vec<TamperRow> {
    super::all_rows()
}

#[track_caller]
fn expect_red(root: &Value, needle: &str) {
    let text = serde_json::to_string(root).expect("serialize");
    match check_text(&text, &live_rows()) {
        Err(failures) => {
            let rendered = render(&failures);
            assert!(
                rendered.contains(needle),
                "failure must mention `{needle}`, got:\n{rendered}"
            );
        }
        Ok(_) => panic!("the check must fail (expected `{needle}`), but the registry passed"),
    }
}

/// [`expect_red`], plus: the failure list has **exactly one** entry.
///
/// **D96 rider (a).** [`expect_red`] matches its needle against the rendered
/// *list*, so a fixture whose synthesized input is broken in some second,
/// unnoticed way passes while being carried by that other failure. The
/// borrowed-case fixtures were coupled to committed data, which caught that
/// for free; synthesized ones are not, so the guarantee is asserted instead.
/// Measured when D96 landed: every fixture below emits exactly one failure,
/// so pinning it costs nothing and turns "my synthetic block went stale"
/// from a silent pass into a red test.
///
/// Deliberately **not** used by [`completeness_red_on_a_deleted_family`],
/// which orphans that family's rows by design and must report every one.
#[track_caller]
fn expect_only_red(root: &Value, needle: &str) {
    let text = serde_json::to_string(root).expect("serialize");
    match check_text(&text, &live_rows()) {
        Err(failures) => {
            let rendered = render(&failures);
            assert!(
                rendered.contains(needle),
                "failure must mention `{needle}`, got:\n{rendered}"
            );
            assert_eq!(
                failures.len(),
                1,
                "exactly one failure expected — a second means the synthesized input broke \
                 something else too, and this fixture would be passing on the wrong one:\n{rendered}"
            );
        }
        Ok(_) => panic!("the check must fail (expected `{needle}`), but the registry passed"),
    }
}

/// Mutable access to a case, **by its `family/case` path**.
///
/// Deliberately not by array index: the cases below need a case in a
/// *particular state* (pending, or implemented), and a case's state changes
/// as the matrix is populated. Index-anchored fixtures broke every time a
/// row landed and said nothing useful when they did; a path that no longer
/// resolves fails with the path in the message.
fn case_mut<'a>(root: &'a mut Value, path: &str) -> &'a mut Value {
    let (family_id, case_id) = path.split_once('/').expect("path is `family/case`");
    root.get_mut("families")
        .and_then(Value::as_array_mut)
        .expect("families array")
        .iter_mut()
        .find(|family| family.get("id").and_then(Value::as_str) == Some(family_id))
        .and_then(|family| family.get_mut("cases"))
        .and_then(Value::as_array_mut)
        .expect("family exists and has cases")
        .iter_mut()
        .find(|case| case.get("id").and_then(Value::as_str) == Some(case_id))
        .unwrap_or_else(|| panic!("no case `{path}` in the committed registry"))
}

/// A case the committed registry currently holds as **pending**. The
/// Install a **synthetic pending case** in the parsed registry and return a
/// mutable handle to the case object.
///
/// # Why the pending-marker fixtures stopped borrowing a live case
///
/// They used to reach into the committed registry and mutate a real
/// `pending` block. That anchor was re-pointed twice in ten days — M0 → M2
/// (F15), then within M2 (Q76) — and **A21 removed the last one**: it landed
/// all eight M2 anchor rows, and since a case can only exist for a clause
/// MVP-SPEC.md line 168 actually names, and M0's set must stay empty because
/// *that is Q14's gate condition*, there is now nothing left to re-point to
/// and nothing that could create a replacement. Decision **D96** rules the
/// consequence: synthesize.
///
/// It is the same move D81 forced one state down, and this file already
/// records the reasoning verbatim in
/// [`completeness_red_when_two_pending_rows_collide_without_a_note`] —
/// *"a test that depended on one would have to be deleted or kept alive by
/// leaving a collision in place. Building the pair here instead makes the
/// rule permanently testable and independent of what the matrix happens to
/// contain."* Substitute "pending case" for "collision" and the second
/// option becomes *deliberately not landing one of A21's eight rows to feed
/// a fixture*, which is a fixture requiring the project never to finish.
///
/// # Why a case and not a family
///
/// [`check_text`] pins **family** counts but never asserts a case count
/// (`EXPECTED_M2_CASES` is read by [`assert_m2_anchor_set_is_armed`], which
/// no fixture calls), so an appended case is invisible to every pin. A
/// synthetic *family* would break both counts and need a real `spec_quote`;
/// converting a real implemented case would orphan its live row and add a
/// second, unrelated failure to every fixture below. Appending one case is
/// what keeps this section's contract — *"takes the COMMITTED registry,
/// breaks exactly one thing"* — literally true.
///
/// `Z99` is a deliberately impossible task id (`tasks/` holds A, C, F, G, P,
/// Q, R, S, U), and `expected` is derived from `case_id` so two installed
/// cases reserve **distinct** keys and a collision has to be asked for.
fn synthetic_pending_case<'a>(root: &'a mut Value, case_id: &str) -> &'a mut Value {
    let cases = root
        .get_mut("families")
        .and_then(Value::as_array_mut)
        .expect("families array")
        .last_mut()
        .expect("the registry has at least one family")
        .get_mut("cases")
        .and_then(Value::as_array_mut)
        .expect("the last family has a cases array");
    cases.push(serde_json::json!({
        "id": case_id,
        "what": "synthetic: installed by a test-of-the-test, never committed",
        "pending": {
            "task": "Z99",
            "row_id": format!("verify-{case_id}"),
            "outcome_kind": "error",
            "expected": format!("synthetic-{case_id}"),
            "why": "synthetic: this marker exists only inside this test's parsed value"
        }
    }));
    cases.last_mut().expect("just pushed")
}

/// Install a synthetic pending case and return its `pending` object.
fn synthetic_pending<'a>(
    root: &'a mut Value,
    case_id: &str,
) -> &'a mut serde_json::Map<String, Value> {
    synthetic_pending_case(root, case_id)
        .get_mut("pending")
        .and_then(Value::as_object_mut)
        .expect("the synthetic case is pending")
}

/// The `pending` object of a synthetic case **already installed** by
/// [`synthetic_pending_case`].
///
/// Distinct from [`synthetic_pending`], which *installs*: a fixture needing
/// two claimants must be able to come back to the first one, and calling the
/// installer twice would silently push a third case rather than reach the
/// one it meant.
fn installed_pending<'a>(
    root: &'a mut Value,
    case_id: &str,
) -> &'a mut serde_json::Map<String, Value> {
    root.get_mut("families")
        .and_then(Value::as_array_mut)
        .expect("families array")
        .last_mut()
        .expect("the registry has at least one family")
        .get_mut("cases")
        .and_then(Value::as_array_mut)
        .expect("the last family has a cases array")
        .iter_mut()
        .find(|case| case.get("id").and_then(Value::as_str) == Some(case_id))
        .unwrap_or_else(|| panic!("no synthetic case `{case_id}` has been installed"))
        .get_mut("pending")
        .and_then(Value::as_object_mut)
        .expect("the synthetic case is pending")
}

/// A case the committed registry currently holds as **implemented**.
const AN_IMPLEMENTED_CASE: &str = "wrong-salt/unit-commit";

/// The positive control: the committed registry passes through the same
/// text path every red case below uses.
#[test]
fn completeness_committed_registry_is_green() {
    let text = serde_json::to_string(&committed_value()).expect("serialize");
    if let Err(failures) = check_text(&text, &live_rows()) {
        panic!("{}", render(&failures));
    }
}

/// A spec case in none of the three states is the silent gap this whole
/// registry exists to prevent.
#[test]
fn completeness_red_on_a_case_with_no_coverage_and_no_pending_marker() {
    let mut root = committed_value();
    synthetic_pending_case(&mut root, "no-state")
        .as_object_mut()
        .expect("case object")
        .remove("pending");
    expect_only_red(&root, "has none of `rows`, `pending` or `non_row`");
}

/// **D81's third state, positive control.** A case discharged by a
/// `non_row` that names a real `non_rows[]` entry is accepted — otherwise
/// every red case below would be indistinguishable from a checker that
/// simply rejects the new key.
#[test]
fn completeness_green_on_a_case_discharged_by_a_recorded_non_row() {
    let mut root = committed_value();
    let case = synthetic_pending_case(&mut root, "discharged")
        .as_object_mut()
        .expect("case object");
    case.remove("pending");
    case.insert(
        "non_row".to_owned(),
        serde_json::json!("crypto-level-ggm-seed-length"),
    );
    let text = serde_json::to_string(&root).expect("serialize");
    if let Err(failures) = check_text(&text, &live_rows()) {
        panic!(
            "a case discharged by a recorded non-row must be accepted:\n{}",
            render(&failures)
        );
    }
}

/// **D81's third state, the constraint that makes it more than prose.** A
/// `non_row` naming an id no `non_rows[]` entry has is an unverifiable
/// discharge: nothing then guarantees a row claims the outcome.
#[test]
fn completeness_red_on_a_case_discharged_by_an_unrecorded_non_row() {
    let mut root = committed_value();
    let case = synthetic_pending_case(&mut root, "bad-discharge")
        .as_object_mut()
        .expect("case object");
    case.remove("pending");
    case.insert(
        "non_row".to_owned(),
        serde_json::json!("nobody-recorded-this"),
    );
    expect_only_red(&root, "is not an entry in `non_rows[]`");
}

/// Two states at once is an unresolved claim about one case, whichever two
/// they are — the `rows`/`pending` pair has its own case below.
#[test]
fn completeness_red_on_a_case_in_two_states_at_once() {
    let mut root = committed_value();
    synthetic_pending_case(&mut root, "two-states")
        .as_object_mut()
        .expect("case object")
        .insert(
            "non_row".to_owned(),
            serde_json::json!("crypto-level-ggm-seed-length"),
        );
    expect_only_red(&root, "declares [\"pending\", \"non_row\"] together");
}

/// A pending marker left on an implemented case understates coverage and
/// keeps a phantom obligation on Q14's gate.
#[test]
fn completeness_red_on_a_stale_pending_marker() {
    let mut root = committed_value();
    case_mut(&mut root, AN_IMPLEMENTED_CASE)
        .as_object_mut()
        .expect("case object")
        .insert(
            "pending".to_owned(),
            serde_json::json!({
                "task": "R7",
                "row_id": "verify-not-a-real-row",
                "outcome_kind": "error",
                "expected": null,
                "why": "stale"
            }),
        );
    expect_red(&root, "declares [\"rows\", \"pending\"] together");
}

/// Naming a row that does not exist claims coverage that is not there.
#[test]
fn completeness_red_on_a_case_naming_a_nonexistent_row() {
    let mut root = committed_value();
    case_mut(&mut root, AN_IMPLEMENTED_CASE)
        .as_object_mut()
        .expect("case object")
        .insert(
            "rows".to_owned(),
            serde_json::json!(["crypto-does-not-exist"]),
        );
    expect_red(&root, "does not exist in the live tamper registry");
}

/// An implemented row that no entry accounts for makes the 1:1 mapping
/// meaningless — extras are legitimate, *undeclared* extras are not.
#[test]
fn completeness_red_on_an_unaccounted_implemented_row() {
    let mut root = committed_value();
    root.get_mut("project_added")
        .and_then(Value::as_array_mut)
        .expect("project_added array")
        .pop();
    expect_red(&root, "is in NO registry entry");
}

/// A family whose quote is not in the spec line is an invented family.
#[test]
fn completeness_red_on_a_spec_quote_that_is_not_in_the_spec() {
    let mut root = committed_value();
    root.get_mut("families")
        .and_then(|f| f.get_mut(0))
        .and_then(Value::as_object_mut)
        .expect("family object")
        .insert(
            "spec_quote".to_owned(),
            serde_json::json!("a mutation family the spec never named"),
        );
    expect_red(&root, "not a literal substring");
}

/// Deleting a family to make the mapping look complete is caught by the
/// pinned count.
#[test]
fn completeness_red_on_a_deleted_family() {
    let mut root = committed_value();
    root.get_mut("families")
        .and_then(Value::as_array_mut)
        .expect("families array")
        .remove(0);
    expect_red(&root, "M0 families; MVP-SPEC.md line 168");
}

/// A pending row claiming an outcome an implemented row already owns can
/// never become a row — Q7's distinctness assertion would refuse it.
/// Saying so at registry time beats discovering it mid-implementation.
#[test]
fn completeness_red_on_a_pending_row_colliding_with_an_implemented_one() {
    let mut root = committed_value();
    // Already owned by the implemented row `verify-tiling-gap`.
    synthetic_pending(&mut root, "collides")
        .insert("expected".to_owned(), serde_json::json!("tiling-gap"));
    expect_only_red(&root, "is ALREADY claimed by implemented row");
}

/// Two pending rows claiming one outcome is the same collision, earlier.
///
/// **Synthesized rather than borrowed from the registry.** Until R8 the
/// committed registry happened to contain such a pair (flipped ciphertext
/// byte vs swapped unit, both `unit-decrypt-failed`) carrying a
/// `collision_note`, and this test worked by stripping it. D81 resolved
/// that pair — the swap became a recorded non-row — so there is no longer
/// any collision to borrow, and a test that depended on one would have to
/// be deleted or kept alive by leaving a collision in place. Building the
/// pair here instead makes the rule permanently testable and independent of
/// what the matrix happens to contain.
///
/// Both directions are checked, because "red without a note" is only
/// meaningful if "green with one" also holds — otherwise the check could be
/// rejecting the collision itself rather than the missing note. The note
/// goes on the **second** claimant in registry order, which is the one the
/// checker reports against.
///
/// **Both claimants are now synthesized too (D96).** The second used to be a
/// borrowed live case, `untrusted-tsa-root`; A21 landed that row, so its key
/// `verdict:internally-consistent-only` is now owned by an *implemented*
/// row — a naive rewrite would still go red, but on *"is ALREADY claimed by
/// implemented row"*, a different rule from the one under test. Installing
/// both claimants makes the key unclaimable by any minted code and puts
/// registry order under the fixture's control rather than under whatever
/// order the spec happens to enumerate families in.
#[test]
fn completeness_red_when_two_pending_rows_collide_without_a_note() {
    /// Install the pair: `second` reserves its own derived key, and `first`
    /// is then made to claim that same key.
    fn collide(root: &mut Value) {
        // The earlier claimant, made to claim the key the later one reserves.
        synthetic_pending(root, "first-claimant").insert(
            "expected".to_owned(),
            serde_json::json!("synthetic-second-claimant"),
        );
        synthetic_pending_case(root, "second-claimant");
    }

    let mut root = committed_value();
    collide(&mut root);
    expect_only_red(&root, "is also claimed by pending case");

    // The same collision, declared: accepted, because the registry has said
    // out loud that it knows.
    let mut root = committed_value();
    collide(&mut root);
    installed_pending(&mut root, "second-claimant").insert(
        "collision_note".to_owned(),
        serde_json::json!("synthetic: deliberate, and this is the note"),
    );
    let text = serde_json::to_string(&root).expect("serialize");
    let failures = check_text(&text, &live_rows()).err().unwrap_or_default();
    assert!(
        !failures
            .iter()
            .any(|f| f.contains("is also claimed by pending case")),
        "a declared collision must not be reported: {}",
        render(&failures)
    );
}

/// A pending marker reserving a row id that already exists means the case
/// is implemented and the marker was never cleared.
#[test]
fn completeness_red_on_a_pending_marker_reserving_a_live_row_id() {
    let mut root = committed_value();
    synthetic_pending(&mut root, "stale-reservation")
        .insert("row_id".to_owned(), serde_json::json!("verify-tiling-gap"));
    expect_only_red(&root, "ALREADY EXISTS");
}

/// A pending marker without a task id is an unowned obligation.
#[test]
fn completeness_red_on_a_pending_marker_without_a_task_id() {
    let mut root = committed_value();
    synthetic_pending(&mut root, "unowned").insert("task".to_owned(), serde_json::json!("someone"));
    expect_only_red(&root, "must be a task id");
}

/// A non-row is justified only by the row that actually claims its
/// outcome; a dangling `collides_with` is unverifiable prose.
#[test]
fn completeness_red_on_a_non_row_pointing_at_nothing() {
    let mut root = committed_value();
    root.get_mut("non_rows")
        .and_then(|n| n.get_mut(0))
        .and_then(Value::as_object_mut)
        .expect("non_row object")
        .insert(
            "collides_with".to_owned(),
            serde_json::json!("verify-nothing-claims-this"),
        );
    expect_red(&root, "is neither an implemented row nor a row id reserved");
}

/// A project addition without a justification defeats the point of
/// declaring it.
#[test]
fn completeness_red_on_a_project_addition_without_a_justification() {
    let mut root = committed_value();
    root.get_mut("project_added")
        .and_then(|p| p.get_mut(0))
        .and_then(Value::as_object_mut)
        .expect("project_added object")
        .insert("why".to_owned(), serde_json::json!("  "));
    expect_red(&root, "is empty");
}

/// A typo'd field would silently disable whatever rule reads it.
#[test]
fn completeness_red_on_an_unknown_field() {
    let mut root = committed_value();
    synthetic_pending_case(&mut root, "typo")
        .as_object_mut()
        .expect("case object")
        .insert("rowz".to_owned(), serde_json::json!([]));
    expect_only_red(&root, "unknown field(s)");
}
