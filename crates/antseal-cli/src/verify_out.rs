//! The `verify` command's output layer (task U30) — the run, its rendering,
//! its exit-code fold, and the one place `--json`'s document is built.
//!
//! Everything evidentiary is `antseal-core`'s. R21's
//! [`verify_with_host`](antseal_core::verify::verify_with_host) performs the
//! verification and composes the advisory siblings; R18 froze every sentence;
//! R19 derives the redaction view. This module adds **layout, the integer,
//! and the envelope member order** — nothing else. It coins no verdict
//! wording (`crates/antseal-core/tests/verdict_wording.rs`'s source scan
//! covers this file) and computes no verdict of its own.
//!
//! # The exit code is a coarsening, and there is exactly one route to it
//!
//! D69 §3 R3, verbatim:
//!
//! > *the code of the highest-ranked rung whose predicate holds over the
//! > whole anchor set; 0 when none does.*
//!
//! The fold itself lives in core ([`verdict_exit_rung`]) so R22's page can
//! state the same rung and R27's parity gate has something to compare; this
//! module maps the rung's **name** onto U2's committed table through
//! [`ErrorClass::for_rung`], which is the CLI's only route to a verdict code.
//! [`VerifyRun::exit_class`] is the single expression that produces one, and
//! [`VerifyRun::json`] reads the same [`VerifyOutcome`] — so the integer and
//! the document cannot disagree by construction rather than by test (D69 §3
//! R7).
//!
//! Two exclusions are structural rather than checked:
//!
//! - **`--live` and the storage-linkage layer never move it** (D69 §3 R6;
//!   MVP-SPEC.md line 118 — *"storage is the product's bonus, not its
//!   proof"*). Neither is a parameter of the fold, so there is no code here
//!   to get wrong.
//! - **Probe weather cannot move it** (D69 §3 R5): an unreachable or
//!   disagreeing endpoint leaves the anchor's state untouched, because
//!   `OnlineBlockResult` has **no failure variant** — so the online-augmented
//!   aggregate equals the offline one and any pure function of it returns the
//!   same value. Promotion, agreed refutation and newly-flagged divergence
//!   *do* move it, in all three directions, which is what makes the screen
//!   and the code agree.
//!
//! # `--json`: byte-verbatim carriage, and why there is no `Value` here
//!
//! D65 §5 refuses routing the report through `serde_json::Value`:
//! `serde_json::Map` is a `BTreeMap` in this build, so a round trip
//! alphabetizes the report's keys and destroys D29 rule 1's declaration
//! order. `success_envelope`'s only signature takes a `Value`, so `verify`
//! renders its whole `result` **out of core's own canonical bytes** and
//! hands the text to
//! [`success_envelope_raw`](crate::machine::success_envelope_raw).
//!
//! D65 §5 named two acceptable routes — a typed `#[derive(Serialize)]`
//! envelope, or `serde_json`'s `raw_value` feature — and **neither is
//! available to this crate as it stands**: `serde` is not a dependency here
//! (only `serde_json` is), and `raw_value` is enabled nowhere. Both would
//! need a manifest edit. What is available is better than either: every
//! member already has a canonical serializer in core — `report_bytes()` for
//! the report, `to_canonical_json()` for the overlay, the live section and
//! the verdict datum — so assembling those four is a *third* route that
//! satisfies the same rule and adds no second serialization path. The bytes
//! this document carries are, member for member, the bytes R22's page
//! receives.
//!
//! The one field the CLI owns is `verdict.exit_code`, appended to core's own
//! verdict object rather than nesting it under a key, so a field added
//! upstream appears here with no edit. The splice is guarded and the guard
//! is tested.
//!
//! The trap is closed **by construction**, not by discipline: no
//! `serde_json::Value` is ever built on this path, R21 deliberately exposes
//! no accessor that returns one, and the members are emitted in the
//! alphabetical order the other nine documents already produce, so nothing
//! about this document reads unlike the rest.
//!
//! `overlay` and `live` are `null` when their mode was off — **always
//! present, never omitted** (D65 §5.1), which is what lets one presence-only
//! key assertion cover all four mode combinations.
//!
//! [`verdict_exit_rung`]: antseal_core::verify::rung::verdict_exit_rung

use antseal_core::verify::orchestration::{
    LiveSection, SiblingEncodeError, VerifyHost, VerifyModes, VerifyOutcome, VerifyRunError,
    verify_with_host,
};
use antseal_core::verify::overlay::OnlineOverlay;
use antseal_core::verify::rung::VerdictExitRung;
use antseal_core::verify::{VerifyOptions, wording};

use crate::error::{CliError, ErrorClass};
use crate::preview::escape_for_terminal;

/// Indent of a row inside a layer's block (the house's two spaces, as in
/// `status::WorkStatus::render` and `redaction_out`).
const ROW_INDENT: &str = "  ";

/// Indent of a detail row beneath its own row.
const DETAIL_INDENT: &str = "      ";

/// One completed `verify` run: the core outcome, plus the three things the
/// CLI owes on top of it.
///
/// Holds the [`VerifyOutcome`] rather than copies of its parts, so the
/// rendering, the exit code and the `--json` document are three readings of
/// **one** value and cannot describe different runs.
pub struct VerifyRun {
    outcome: VerifyOutcome,
}

impl VerifyRun {
    /// The core outcome, for a caller that wants the typed data.
    #[must_use]
    pub const fn outcome(&self) -> &VerifyOutcome {
        &self.outcome
    }

    /// D69's rung as a U2 class, or `None` for the clean verdict (exit 0).
    ///
    /// The **only** expression in the CLI that turns a verdict into a code.
    #[must_use]
    pub fn exit_class(&self) -> Option<ErrorClass> {
        self.outcome.exit_rung().map(ErrorClass::for_rung)
    }

    /// The rung itself, for a caller that wants the name rather than the
    /// integer.
    #[must_use]
    pub fn exit_rung(&self) -> Option<VerdictExitRung> {
        self.outcome.exit_rung()
    }

    /// The exit code this run reports: D69's rung, or 0.
    #[must_use]
    pub fn exit_code(&self) -> u8 {
        self.exit_class().map_or(0, ErrorClass::exit_code)
    }

    /// The human report, as lines.
    ///
    /// The caller routes them to stdout (or, under `--json`, to stderr —
    /// D51). Order is: the evidence layer, the online advisory when one was
    /// computed, the storage layer (offline linkage **always**, `--live`'s
    /// rows joining it when requested — D128 §3 R1/R5), the redaction view,
    /// and the closing note on what a seal proves.
    #[must_use]
    pub fn render(&self) -> Vec<String> {
        let rendered = self.outcome.rendered();
        let mut out = vec![rendered.headline_line.clone()];
        if let Some(line) = &rendered.divergence_line {
            out.push(line.clone());
        }

        // ── the evidence layer — "this alone carries the evidentiary
        //    verdict" (MVP-SPEC.md line 118) ────────────────────────────
        out.push(rendered.evidence_layer_label.to_owned());
        for slot in &rendered.anchors {
            out.push(format!(
                "{ROW_INDENT}{}: {}{}",
                slot.slot, slot.state_line, slot.headline_tag
            ));
            for line in &slot.guidance_lines {
                out.push(format!("{DETAIL_INDENT}{line}"));
            }
            if let Some(line) = &slot.source_line {
                out.push(format!("{DETAIL_INDENT}{line}"));
            }
            if let Some(line) = &slot.fetch_date_line {
                out.push(format!("{DETAIL_INDENT}{line}"));
            }
        }
        if let Some(line) = &rendered.claimed_time_line {
            out.push(format!("{ROW_INDENT}{line}"));
        }
        if let Some(receipt) = &rendered.supporting_evidence {
            out.push(format!("{ROW_INDENT}{}", receipt.class_line));
            out.push(format!("{DETAIL_INDENT}{}", receipt.detail_line));
        }
        out.push(format!("{ROW_INDENT}{}", rendered.signature_scheme_line));

        // ── the online advisory (D64): after the offline block, because
        //    the framing sentence says "the offline verdict above" ──────
        if let Some(overlay) = self.outcome.overlay() {
            out.extend(overlay_lines(overlay));
        }

        // ── the storage layer: one layer, two questions (MVP-SPEC.md line
        //    119). The offline linkage row renders on EVERY run — D128 §3
        //    R5: there is no `--no-storage-linkage`, and `--live`'s rows
        //    join this section rather than constituting it. ─────────────
        out.push(rendered.storage_linkage_label.to_owned());
        out.push(format!("{ROW_INDENT}{}", rendered.storage_linkage_line));
        if let Some(live) = self.outcome.live() {
            out.extend(live_lines(live));
        }

        // ── the redaction view (R19's renderer, unchanged) ─────────────
        out.extend(crate::redaction_out::render_report(self.outcome.report()));

        out.push(rendered.seal_meaning_line.to_owned());
        out
    }

    /// The `--json` `result` document, as text.
    ///
    /// Byte-verbatim in `report` (D65 §5). See the module docs for why this
    /// returns a `String` and not a `serde_json::Value`.
    ///
    /// # Errors
    ///
    /// [`CliError::Internal`] — the serializer failed. Structurally
    /// unreachable (no maps, no non-string keys, no floats in any member),
    /// and typed anyway because library code never unwraps.
    pub fn json(&self) -> Result<String, CliError> {
        // Member order is alphabetical — what `serde_json::Map`'s `BTreeMap`
        // produces for the other nine commands — so this document reads like
        // every other one even though it never becomes a `Map`. Key order is
        // promised nowhere outside `report` (D65 §7); this is consistency,
        // not a commitment.
        //
        // Absence is `null`, never a missing key (D65 §5.1/§7), which is
        // exactly what makes a presence-only key assertion meaningful across
        // all four mode combinations.
        let live = match self.outcome.live() {
            Some(live) => text(&live.to_canonical_json()?)?,
            None => "null".to_owned(),
        };
        let overlay = match self.outcome.overlay() {
            Some(overlay) => {
                text(
                    &overlay
                        .to_canonical_json()
                        .map_err(|source| CliError::Internal {
                            detail: format!("the online overlay could not be serialized: {source}"),
                        })?,
                )?
            }
            None => "null".to_owned(),
        };
        // Tier A. `report_bytes()` is exactly `to_canonical_json()`'s
        // output, computed once by R21 and never re-serialized here.
        let report = text(self.outcome.report_bytes())?;
        let verdict = self.verdict_member()?;
        Ok(format!(
            "{{\"live\":{live},\"overlay\":{overlay},\"report\":{report},\"verdict\":{verdict}}}"
        ))
    }

    /// The `verdict` member: core's datum, with the one field the CLI owns.
    ///
    /// [`VerdictClass`](antseal_core::verify::orchestration::VerdictClass)
    /// carries the rung's **name** and no integer, deliberately —
    /// `ErrorClass` and its committed code table are U2's, and D69 §3 R1
    /// keeps exactly one code table in the product. So `exit_code` is added
    /// here, at the surface, and `result.verdict.exit_code == $?` is an
    /// asserted equality (D69 §3 R7).
    ///
    /// The field is **appended to core's own object** rather than nesting
    /// core's document under a key, so a field added to the datum upstream
    /// appears here with no edit and the two cannot drift into different
    /// field sets. The splice is guarded: core's serializer produces a
    /// non-empty JSON object for this type, and anything else is reported
    /// rather than concatenated into a malformed document.
    fn verdict_member(&self) -> Result<String, CliError> {
        let class = text(&self.outcome.verdict_class().to_canonical_json()?)?;
        let inner = class
            .strip_prefix('{')
            .and_then(|rest| rest.strip_suffix('}'))
            .filter(|inner| !inner.is_empty())
            .ok_or_else(|| CliError::Internal {
                detail: "the verdict datum did not serialize as a non-empty JSON object".to_owned(),
            })?;
        Ok(format!("{{{inner},\"exit_code\":{}}}", self.exit_code()))
    }
}

/// One canonical document's bytes as text.
///
/// `serde_json` emits UTF-8 by construction, so the error arm is
/// unreachable; it is typed rather than unwrapped because library code never
/// unwraps, and because this is the one place a malformed member could reach
/// stdout.
fn text(bytes: &[u8]) -> Result<String, CliError> {
    core::str::from_utf8(bytes)
        .map(str::to_owned)
        .map_err(|source| CliError::Internal {
            detail: format!("a verify `--json` member was not valid UTF-8: {source}"),
        })
}

/// Sibling-document encoding failures are structurally unreachable (no maps,
/// no non-string keys, no floats) and are the bug class when they do arrive.
impl From<SiblingEncodeError> for CliError {
    fn from(source: SiblingEncodeError) -> Self {
        CliError::Internal {
            detail: format!("a verify sibling document could not be serialized: {source}"),
        }
    }
}

/// The online advisory's lines, in D64 §3's fixed order.
fn overlay_lines(overlay: &OnlineOverlay) -> Vec<String> {
    let mut out = vec![
        overlay.framing_line.clone(),
        format!("{ROW_INDENT}{}", overlay.headline_impact_line),
    ];
    for outcome in &overlay.anchor_outcomes {
        out.push(format!("{ROW_INDENT}{}", outcome.line));
    }
    if let Some(receipt) = &overlay.receipt {
        // D137 §3 R10 — indentation and nothing else. This row and the
        // verifier page's `#overlay-receipt` print the SAME `overlay.receipt
        // .line`, so a correction to the sentence is one edit in
        // `antseal_core::verify::wording` and both surfaces move together.
        // The clause is on `single_sourced()`'s table (D137 §3 R10), so
        // spelling it here as a literal reddens
        // `no_renderer_source_spells_a_frozen_verdict_string`; and
        // `verify_command.rs`'s cross-surface pin holds the other direction —
        // that this row still prints the module's bytes, unextended.
        out.push(format!("{ROW_INDENT}{}", receipt.line));
    }
    for delta in &overlay.aggregate_deltas {
        out.push(format!("{ROW_INDENT}{}", delta.line));
    }
    out.push(format!("{ROW_INDENT}{}", overlay.endpoints.line));
    out
}

/// The `--live` section's lines, inside the storage layer's block.
///
/// The layer label is rendered even for a section with no rows, because a
/// requested check that found nothing to check is a fact about the run —
/// [`LiveSection`] reports `NothingChecked` rather than a vacuous pass, and
/// suppressing the label would hide it.
///
/// # Why no `escape_for_terminal` here, after R79
///
/// This is the fourth and last hop R79's register entry names: the live rows
/// arrive here finished and are pushed straight to the surface, with the
/// escape used elsewhere in this file never applied to them. **After R79 both
/// of a live row's authored parts are closed sets, so there is nothing left
/// to escape**, and that is the ruling rather than an omission:
///
/// - the fetch-failure detail is `antseal_net::FetchFailureClass`'s
///   `&'static str` label, from a closed class mapped wildcard-free over
///   `StorageError` (R79 arm (a)); and
/// - `row.subject` is `antseal_net::subject_label`'s output, whose whole
///   grammar is `unit <digits>`, `unit <digits> (raw mirror)` and
///   `encrypted manifest` — a `u64`'s decimal rendering inside static text.
///
/// Neither can carry a byte a bundle, a backend or a network chose. Adding an
/// escape pass would neutralise nothing and would suggest the channel exists.
/// If a future row ever renders a value from outside those two vocabularies,
/// this is the site that must gain the escape, and `LiveSection::new`'s
/// caller has one in scope to pass.
fn live_lines(live: &LiveSection) -> Vec<String> {
    let mut out = vec![format!("{ROW_INDENT}{}", live.label)];
    if let Some(line) = &live.verdict_line {
        out.push(format!("{ROW_INDENT}{line}"));
    }
    for row in &live.rows {
        out.push(format!("{DETAIL_INDENT}{}", row.line));
    }
    out
}

/// Verify a bundle and prepare its three outputs.
///
/// Generic over the host for the reason R21's entry is: the host seam is the
/// only route a network-derived datum has into verification, so a test drives
/// fixture inputs through exactly the code the binary runs.
///
/// `options` is passed through whole — R21's signature takes it for the clock
/// (`verify_at_unix`), and R21 constructs its **own** options for the
/// storage-linkage bit (D128 §3 R5). Nothing here calls
/// `without_storage_linkage`: `verify` has no such flag and must not mint
/// one, and the tree-wide literal scan closes that method's caller list at
/// two committed-exhibit generators.
///
/// # Errors
///
/// [`CliError::VerifyBundleRejected`] (40) — the bundle did not pass the
/// evidence layer. One class for every rejection code, with the specific
/// `VerifyError::code()` in the message (D69 §3 R2's `‡` row).
///
/// [`CliError::Internal`] (1) — the verified report could not be serialized,
/// which is an antseal bug on the verify path and not an input problem.
///
/// # The escape this surface renders under
///
/// R21 builds the offline block on this call, so the neutralisation policy
/// its sealer- and artifact-authored values need arrives with it (D130 §3
/// R5/R9): D67 §3 R3's terminal set, the same one
/// [`redaction_out`](crate::redaction_out) hands the disclosure block. This
/// is the **only** place the CLI names it for the verdict block, so the
/// claimed time, the anchor sources and the sealer-recorded fetch dates
/// cannot reach a terminal raw — which, measured, is what they did before
/// D130 (§1 j).
pub fn run_verify<H>(
    bundle: &[u8],
    options: &VerifyOptions,
    modes: VerifyModes,
    host: &H,
) -> Result<VerifyRun, CliError>
where
    H: VerifyHost + ?Sized,
{
    let outcome = verify_with_host(bundle, options, modes, host, &escape_for_terminal)?;
    Ok(VerifyRun { outcome })
}

/// D69 §3 R2 routes the run error's two arms to two different classes, and
/// names both destinations.
impl From<VerifyRunError> for CliError {
    fn from(error: VerifyRunError) -> Self {
        match error.verify_error() {
            // The `‡` row: tamper, forgery, malformation, over-cap and
            // non-canonical bytes are ONE class. The distinct rejection code
            // rides in the message — the two namespaces are disjoint
            // (`docs/testing/error-code-contract.md` §2), and D69 §7 row 8
            // makes "its code appears in the message" a test.
            Some(verify) => CliError::VerifyBundleRejected {
                code: verify.code(),
                detail: verify.to_string(),
            },
            // The serializer arm. No input reaches it — report v1 has no
            // map, no non-string key and no float — so it is the bug class.
            None => CliError::Internal {
                detail: error.to_string(),
            },
        }
    }
}

/// The one-sentence stability form D65 §3 states for a scripter, as the
/// `verify` command's own closing advice.
///
/// Lives here rather than in `cli.rs` because the `--json` flag is **global**
/// (it renders identically in all ten commands' help), and only `verify`
/// emits a `result.report`: putting this sentence in the flag's help would
/// promise nine other commands a tier-A member they do not have. The M3
/// documentation home is `machine.rs`'s module doc (D65 §8.1); this is the
/// line a user meets without reading it.
pub const JSON_STABILITY_NOTE: &str = "--json: gate scripts on the exit code, on `ok`, on `v`, and on `result.report` — those are \
     stable. Everything else under `result` is reviewed but not promised until the M4 release \
     freeze, and every enum-valued field may gain a value, so always write the default arm.";

/// The layer labels this renderer emits, re-exported so a test can assert
/// the CLI prints core's strings rather than its own.
#[must_use]
pub const fn evidence_layer_label() -> &'static str {
    wording::EVIDENCE_LAYER_LABEL
}

#[cfg(test)]
#[path = "verify_out/tests.rs"]
mod tests;
