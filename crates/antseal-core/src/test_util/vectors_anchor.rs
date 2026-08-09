//! Golden-vector kind **`anchor`** (task A22): the per-anchor verdict object
//! for recorded RFC 3161 tokens and `.ots` artifacts, at a fixed
//! `verify_at` against [`TsaRootStore::pinned`].
//!
//! Spec basis: the seven frozen per-anchor states (MVP-SPEC.md lines
//! 127-135), the `[H]` headline-eligibility marker, and the M2 exit criterion
//! that *"the WASM build must bit-match native verification"* (line 169).
//! Home, `expect` field set and coverage assertions: **D101** as amended by
//! **D103**.
//!
//! # What the document pins
//!
//! Seven cases over **four** distinct artifacts, one `anchor_digest` (the
//! manifest digest the whole A25 bootstrap stamped) and one
//! `verify_at_unix`:
//!
//! 1. `tsa-freetsa-p384` — a real FreeTSA ECDSA P-384 token, `proven`;
//! 2. `tsa-digicert-rsa` — a real DigiCert RSA token, `proven`;
//! 3. `ots-pending` — the un-upgraded three-calendar `.ots`, `pending`;
//! 4. `ots-upgraded-offline` — the three-way merged+upgraded `.ots`, no
//!    online evidence: `attested`, and `identity_kind: null` because
//!    `AnchorOutcome::new` is *handed* `BitcoinChain` and drops it — A40's
//!    eligibility filter with the OTS-side witness D92 recorded as missing;
//! 5. `ots-upgraded-online-proven` — **the same bytes** plus an agreed header
//!    matching the embedded one: `proven`, `identity_kind: "bitcoin-chain"`,
//!    and the time read from the *agreed* header's `nTime` (D56 §5);
//! 6. `ots-upgraded-online-block-absent` — the same bytes again, with an
//!    agreed `no-such-block` at the recorded height: `pending`, carrying the
//!    O7 refutation as an A39 **suppressed** anomaly. That is D56 §4's
//!    anti-downgrade rule, and it is this kind's only non-empty `suppressed`
//!    — without it the field would be frozen having never been non-empty,
//!    which is the "empty vs absent" ambiguity A39 exists to prevent
//!    (D103 §5.2);
//! 7. `ots-wrong-seal` — the `.ots` for the *other* seal under this
//!    document's `anchor_digest`: `invalid`,
//!    `anchor-ots-digest-mismatch`. D56 §9's sharpest defect, promoted from
//!    the tamper matrix's *same-verdict* wasm32 tier to a *byte-identical*
//!    one (D101 §6.3, D103 §5.3), and the only thing that pins the top-level
//!    `anchor_digest` at all.
//!
//! Cases 4, 5 and 6 carry the artifact hex in full rather than by reference
//! (D103 RULING 4a). The duplication is self-checking: `artifact_sha256` must
//! be identical across the three, and a diverging copy fails the value
//! compare on the same run that would have produced a wrong verdict.
//!
//! # The artifact bytes are literal, and this is the first kind where they
//! must be
//!
//! `report` names its bundle by shape handle and `storage-address` generates
//! its inputs from a pattern; a real FreeTSA token has neither an in-process
//! constructor nor a generating pattern, and the wasm32 side has no
//! filesystem. So the hex goes in the file, the vector copy is authoritative,
//! and `testdata/anchors/` is its provenance of record (D101 RULING 6). Each
//! case's `provenance` key names the archive path verbatim; the three-way
//! splice is derived and its derivation record is
//! `testdata/vectors/v1/anchor/gen_vectors.py`.
//!
//! # Feature tier — the trap that fails as a *build*, not as a red test
//!
//! `crate::anchor::testing` is `#[cfg(any(test, feature = "test-util"))]`
//! (`anchor/mod.rs:77`) and `wasm-bitmatch` takes `antseal-core` with
//! `test-vectors` through a **normal** edge. This module therefore names
//! **no** item from it — not `MERGED_A`, not `DIGEST_A`, not `ots_writer`,
//! not `TsaRootStore::from_static` — and every byte it needs arrives as hex
//! from the vector while every root comes from [`TsaRootStore::pinned`].
//! Naming one would compile under `cargo test -p antseal-core`, where
//! `cfg(test)` is on, and fail to build the single crate this kind exists to
//! satisfy (D103 RULING 7, §1.6).
//!
//! # `expect` has no independent reference implementation, deliberately
//!
//! There is no second RFC 3161 chain validator or `.ots` evaluator to
//! cross-check against, and a Python one would pin the same judgement twice
//! (D101 §7.3). The executor recomputes the **whole** `expect` object from
//! `inputs` through the public evaluators and compares it as one value; the
//! sibling `gen_vectors.py` is a **derivation record** for `inputs` only.
//! What stands in for a cross-check on the one derived artifact is
//! `antseal-anchor`'s own test running the shipped `merge_upgrade` over the
//! same archive bytes to the same SHA-256 (D103 RULING 2a).

use serde::Deserialize;
use sha2::{Digest, Sha256};

use super::vectors::{
    RECOMPUTED_DIGEST_DOMAIN, VectorError, VectorSummary, decode_hex, first_difference, hex,
    prefix_len,
};
use crate::anchor::model::{
    AnchorSource, AnchorVerdict, BlockEvidence, OnlineBlockResult, OnlineEvidence, OtsArtifactView,
    TsaArtifactView,
};
use crate::anchor::roots::TsaRootStore;
use crate::anchor::verdicts::{
    AnchorIdentity, AnchorOutcome, evaluate_ots_artifact, evaluate_tsa_artifact,
};
use crate::bundle::registry::BLOCK_HEADER_LEN;
use crate::bundle::schema::{OpaqueBytes, OtsUpgrade};

/// The registered kind string.
pub const KIND: &str = "anchor";

/// `inputs.cases[].kind` — an OpenTimestamps artifact.
const CASE_KIND_OTS: &str = "ots";
/// `inputs.cases[].kind` — an RFC 3161 artifact.
const CASE_KIND_TSA: &str = "tsa";

/// `inputs.cases[].online[].result` — both endpoints returned this header.
const ONLINE_HEADER: &str = "header";
/// `inputs.cases[].online[].result` — both endpoints agreed the height holds
/// no block.
const ONLINE_NO_SUCH_BLOCK: &str = "no-such-block";

/// `expect.cases[].identity_kind` for [`AnchorIdentity::TsaSigner`]. The
/// **discriminant only**: `subject_dn_der` is what A72 is open to move, and a
/// frozen file has no legal way to move with it (D101 RULING 2b).
const IDENTITY_TSA_SIGNER: &str = "tsa-signer";
/// `expect.cases[].identity_kind` for [`AnchorIdentity::BitcoinChain`].
const IDENTITY_BITCOIN_CHAIN: &str = "bitcoin-chain";

// ---------------------------------------------------------------------------
// inputs
// ---------------------------------------------------------------------------

/// Every field is **required**, including the ones that are `null` or `[]` on
/// most cases. That is the A39 discipline applied to the document itself:
/// "not applicable" and "forgotten" must not be the same absence, and a
/// reviewer of a frozen file whose reviewability rests entirely on
/// `description` and `provenance` (D101 §7.1) should be able to read every
/// case's whole shape without knowing which keys default.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Inputs {
    verify_at_unix: u64,
    anchor_digest: String,
    cases: Vec<CaseInput>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CaseInput {
    name: String,
    kind: String,
    artifact_hex: String,
    intermediates_hex: Vec<String>,
    /// TSA only — `TsaArtifactView::from_parts` requires it. `null` on every
    /// OTS case, whose fetch date lives inside the D79 upgrade group.
    fetch_date_unix: Option<u64>,
    /// OTS only — the D79 group, all three parts or none.
    upgrade: Option<UpgradeInput>,
    online: Vec<OnlineInput>,
    /// The `testdata/anchors/` path the bytes came from, verbatim, or the
    /// derivation for the one artifact that is not a file. Documentation
    /// inside the frozen file, never a lookup: nothing resolves it.
    provenance: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct UpgradeInput {
    block_height: u64,
    block_header_hex: String,
    fetch_date_unix: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct OnlineInput {
    height: u64,
    result: String,
    /// Present for `header`, `null` for `no-such-block`. There is no failure
    /// variant to spell: an unreachable or disagreeing probe is the *absence*
    /// of the entry (D56 §3), which is why this list is empty rather than
    /// carrying a third result.
    header_hex: Option<String>,
}

/// Execute an `anchor` vector (module docs; A22 accept rows 1-3).
pub fn execute(
    inputs: serde_json::Value,
    expect: serde_json::Value,
    description: String,
) -> Result<VectorSummary, VectorError> {
    let payload_err = |problem: String| VectorError::Payload {
        kind: KIND,
        problem,
    };
    let check_err = |check: &'static str, problem: String| VectorError::Check {
        kind: KIND,
        check,
        problem,
    };

    let inputs: Inputs =
        serde_json::from_value(inputs).map_err(|e| payload_err(format!("inputs: {e}")))?;

    for (index, case) in inputs.cases.iter().enumerate() {
        if inputs.cases[..index].iter().any(|c| c.name == case.name) {
            return Err(check_err(
                "case-names-unique",
                format!("case name `{}` appears more than once", case.name),
            ));
        }
    }

    // 1. The whole `expect` object, recomputed from `inputs` through the
    //    public evaluators and compared as one value.
    let recomputed = build_expect(&inputs)?;
    if recomputed != expect {
        return Err(check_err(
            "document",
            first_difference("expect", &recomputed, &expect),
        ));
    }

    // 2. Structural coverage a value comparison cannot state (D101 §3.5 as
    //    amended by D103 §6). A regenerated document that quietly lost a case
    //    class must fail even though every value it still carries is right.
    assert_coverage(&inputs, &recomputed, &check_err)?;

    // 3. Q5 bit-match: SHA-256 over the serialization of the recomputed
    //    value, so every recomputed state, time, source string, diagnostic,
    //    identity discriminant, anomaly code and report slot is compared
    //    native<->wasm32 byte-for-byte. For this kind the digested surface IS
    //    the M2 exit criterion's object (A22 accept row 3).
    let serialized = serde_json::to_vec(&recomputed)
        .map_err(|e| check_err("digest-serialization", e.to_string()))?;
    let mut digest = Sha256::new();
    digest.update(RECOMPUTED_DIGEST_DOMAIN);
    digest.update(KIND.as_bytes());
    digest.update([0x00]);
    digest.update(prefix_len(serialized.len()));
    digest.update(&serialized);

    Ok(VectorSummary {
        kind: KIND,
        description,
        items: inputs.cases.len(),
        recomputed_digest: digest.finalize().into(),
    })
}

/// Recompute the entire `expect` object from an already-parsed `inputs`.
///
/// Public so `tests/anchor_vectors.rs` can regenerate and diff the committed
/// document without a second description of what `expect` contains — the
/// `report`/`content-model` pattern. It takes the raw JSON rather than the
/// private `Inputs` type so the regenerator needs no access to it.
///
/// # Errors
///
/// [`VectorError`] if `inputs` is malformed or internally inconsistent.
pub fn build_expect_from_json(inputs: serde_json::Value) -> Result<serde_json::Value, VectorError> {
    let inputs: Inputs = serde_json::from_value(inputs).map_err(|e| VectorError::Payload {
        kind: KIND,
        problem: format!("inputs: {e}"),
    })?;
    build_expect(&inputs)
}

fn build_expect(inputs: &Inputs) -> Result<serde_json::Value, VectorError> {
    let check_err = |check: &'static str, problem: String| VectorError::Check {
        kind: KIND,
        check,
        problem,
    };

    let anchor_digest: [u8; 32] = decode_hex(KIND, "inputs.anchor_digest", &inputs.anchor_digest)?
        .try_into()
        .map_err(|_| {
            check_err(
                "anchor-digest-length",
                "inputs.anchor_digest must be exactly 32 bytes".to_owned(),
            )
        })?;

    // One store, `pinned()`, for every case — and there is no second one a
    // vector could reach. `from_static` sits on the larger `test-util`
    // feature (D101 §1.4), so the untrusted-root and mock-CA cases are
    // permanently A21's, in-module (D101 RULING 5).
    let roots = TsaRootStore::pinned();

    let mut cases = Vec::with_capacity(inputs.cases.len());
    for case in &inputs.cases {
        // The whole reviewability of this kind rests on `description` and
        // `provenance` (D101 §7.1) — the artifact hex is opaque in a way no
        // other kind's inputs are. A blank provenance is an unreviewable
        // frozen artifact, so it is refused rather than merely discouraged.
        if case.provenance.trim().is_empty() {
            return Err(check_err(
                "provenance",
                format!(
                    "case `{}`: `provenance` is empty. It is the only thing that says \
                     where these bytes came from (D101 §7.1)",
                    case.name
                ),
            ));
        }
        let artifact = decode_hex(KIND, "inputs.cases[].artifact_hex", &case.artifact_hex)?;
        let outcome = match case.kind.as_str() {
            CASE_KIND_OTS => evaluate_ots_case(case, &artifact, &anchor_digest, &check_err)?,
            CASE_KIND_TSA => evaluate_tsa_case(
                case,
                &artifact,
                &anchor_digest,
                roots,
                inputs.verify_at_unix,
                &check_err,
            )?,
            other => {
                return Err(check_err(
                    "case-kind",
                    format!(
                        "case `{}`: kind `{other}` is neither `{CASE_KIND_OTS}` nor \
                         `{CASE_KIND_TSA}`",
                        case.name
                    ),
                ));
            }
        };
        cases.push(render_case(&case.name, &artifact, &outcome));
    }

    Ok(serde_json::json!({
        "verify_at_unix": inputs.verify_at_unix,
        "cases": cases,
    }))
}

/// One `.ots` artifact through D56's O1-O9.
fn evaluate_ots_case(
    case: &CaseInput,
    artifact: &[u8],
    anchor_digest: &[u8; 32],
    check_err: &impl Fn(&'static str, String) -> VectorError,
) -> Result<AnchorOutcome, VectorError> {
    if case.fetch_date_unix.is_some() {
        return Err(check_err(
            "ots-fetch-date-placement",
            format!(
                "case `{}`: an OTS case carries its fetch date inside the D79 upgrade \
                 group; `fetch_date_unix` must be null",
                case.name
            ),
        ));
    }
    if !case.intermediates_hex.is_empty() {
        return Err(check_err(
            "ots-intermediates",
            format!(
                "case `{}`: an OTS artifact has no certificate chain; \
                 `intermediates_hex` must be empty",
                case.name
            ),
        ));
    }

    let upgrade = match &case.upgrade {
        None => None,
        Some(group) => {
            let header: [u8; BLOCK_HEADER_LEN as usize] = decode_hex(
                KIND,
                "inputs.cases[].upgrade.block_header_hex",
                &group.block_header_hex,
            )?
            .try_into()
            .map_err(|_| {
                check_err(
                    "block-header-length",
                    format!(
                        "case `{}`: a Bitcoin block header is exactly \
                         {BLOCK_HEADER_LEN} bytes",
                        case.name
                    ),
                )
            })?;
            Some(OtsUpgrade::new(
                group.block_height,
                header,
                group.fetch_date_unix,
            ))
        }
    };

    let mut online = OnlineEvidence::new();
    for entry in &case.online {
        let result = match entry.result.as_str() {
            ONLINE_HEADER => {
                let Some(header_hex) = entry.header_hex.as_deref() else {
                    return Err(check_err(
                        "online-header-present",
                        format!(
                            "case `{}`: online result `{ONLINE_HEADER}` needs a \
                             `header_hex`",
                            case.name
                        ),
                    ));
                };
                let header: [u8; BLOCK_HEADER_LEN as usize] =
                    decode_hex(KIND, "inputs.cases[].online[].header_hex", header_hex)?
                        .try_into()
                        .map_err(|_| {
                            check_err(
                                "block-header-length",
                                format!(
                                    "case `{}`: an agreed header is exactly \
                                     {BLOCK_HEADER_LEN} bytes",
                                    case.name
                                ),
                            )
                        })?;
                OnlineBlockResult::Header(header)
            }
            ONLINE_NO_SUCH_BLOCK => {
                if entry.header_hex.is_some() {
                    return Err(check_err(
                        "online-header-absent",
                        format!(
                            "case `{}`: online result `{ONLINE_NO_SUCH_BLOCK}` carries \
                             no header; `header_hex` must be null",
                            case.name
                        ),
                    ));
                }
                OnlineBlockResult::NoSuchBlock
            }
            other => {
                return Err(check_err(
                    "online-result",
                    format!(
                        "case `{}`: online result `{other}` is neither \
                         `{ONLINE_HEADER}` nor `{ONLINE_NO_SUCH_BLOCK}`. There is no \
                         failure variant: an unreachable or disagreeing probe is the \
                         absence of the entry (D56 §3)",
                        case.name
                    ),
                ));
            }
        };
        online = online.with_block(entry.height, result);
    }

    // `&BlockEvidence`, not `&OnlineEvidence` — the anchor rules cannot name
    // the receipt (D55 §4), and this call site inherits that.
    let blocks: &BlockEvidence = online.blocks();
    Ok(evaluate_ots_artifact(
        &OtsArtifactView::from_parts(artifact, upgrade.as_ref()),
        anchor_digest,
        blocks,
    ))
}

/// One RFC 3161 artifact through D53's T1-T3.
fn evaluate_tsa_case(
    case: &CaseInput,
    artifact: &[u8],
    anchor_digest: &[u8; 32],
    roots: &TsaRootStore,
    verify_at_unix: u64,
    check_err: &impl Fn(&'static str, String) -> VectorError,
) -> Result<AnchorOutcome, VectorError> {
    let Some(fetch_date) = case.fetch_date_unix else {
        return Err(check_err(
            "tsa-fetch-date-required",
            format!(
                "case `{}`: `TsaArtifactView::from_parts` requires a fetch date",
                case.name
            ),
        ));
    };
    if case.upgrade.is_some() {
        return Err(check_err(
            "tsa-upgrade",
            format!(
                "case `{}`: the D79 upgrade group is OTS-only; `upgrade` must be null",
                case.name
            ),
        ));
    }
    if !case.online.is_empty() {
        return Err(check_err(
            "tsa-online",
            format!(
                "case `{}`: no TSA rule reads online evidence in any D53 sub-case, and \
                 `evaluate_tsa_artifact` takes none; `online` must be empty",
                case.name
            ),
        ));
    }

    let mut intermediates = Vec::with_capacity(case.intermediates_hex.len());
    for der in &case.intermediates_hex {
        intermediates.push(OpaqueBytes::from_vec(decode_hex(
            KIND,
            "inputs.cases[].intermediates_hex[]",
            der,
        )?));
    }

    Ok(evaluate_tsa_artifact(
        &TsaArtifactView::from_parts(artifact, &intermediates, fetch_date),
        anchor_digest,
        roots,
        verify_at_unix,
    ))
}

/// One case's whole `expect` entry.
fn render_case(name: &str, artifact: &[u8], outcome: &AnchorOutcome) -> serde_json::Value {
    let verdict: &AnchorVerdict = outcome.verdict();
    serde_json::json!({
        "name": name,
        // Self-binding (D101 §7.2): truncated, extended or edited
        // `artifact_hex` fails the value compare on the same run that would
        // have produced a wrong verdict.
        "artifact_len": artifact.len(),
        "artifact_sha256": hex(&Sha256::digest(artifact)),
        "state": verdict.state().wire_name(),
        // A state name alone is blind to eligibility (A21 row 5, D93 §9).
        "headline_eligible": verdict.is_headline_eligible(),
        "verified_time_unix": verdict.verified_time_unix(),
        "source": verdict.source().map(|source| {
            serde_json::json!({
                "identity": source.identity(),
                // The verified/claimed kind is chosen by the state, never by
                // a caller (A2); pinning it is what makes that visible.
                "verified": matches!(source, AnchorSource::Verified(_)),
            })
        }),
        "fetch_date": verdict.fetch_date(),
        // The field `to_anchor_result` DROPS (D53 §6): report v1 is frozen
        // and `AnchorResult` has five fields, so a vector is the only place
        // the diagnostic is ever pinned.
        "diagnostic": verdict.diagnostic().map(|d| d.code()),
        "identity_kind": outcome.identity().map(|identity| match identity {
            AnchorIdentity::TsaSigner { .. } => IDENTITY_TSA_SIGNER,
            AnchorIdentity::BitcoinChain => IDENTITY_BITCOIN_CHAIN,
        }),
        // Codes only, empty never absent (A39 accept row 3). The locus is
        // deliberately out: D101 §3.5 rules "codes", and pinning more of a
        // datum than the ruling names is a freeze nobody decided.
        "suppressed": outcome.suppressed().iter().map(|a| a.code()).collect::<Vec<_>>(),
        // Binds the vector to R12's projection so the two cannot drift.
        "report_slot": verdict.to_anchor_result(),
    })
}

// ---------------------------------------------------------------------------
// structural coverage (D101 §3.5 1-5, D103 §6.2's 6' and §6.3's 5a)
// ---------------------------------------------------------------------------

fn assert_coverage(
    inputs: &Inputs,
    expect: &serde_json::Value,
    check_err: &impl Fn(&'static str, String) -> VectorError,
) -> Result<(), VectorError> {
    let cases = expect["cases"]
        .as_array()
        .ok_or_else(|| check_err("coverage-shape", "expect.cases is not an array".to_owned()))?;

    // 2. Both artifact kinds are exercised.
    for kind in [CASE_KIND_OTS, CASE_KIND_TSA] {
        if !inputs.cases.iter().any(|c| c.kind == kind) {
            return Err(check_err(
                "kind-coverage",
                format!("no `{kind}` case — the document must exercise both artifact kinds"),
            ));
        }
    }

    // 3. Both sides of the `[H]` marker.
    for eligible in [true, false] {
        if !cases.iter().any(|c| c["headline_eligible"] == eligible) {
            return Err(check_err(
                "eligibility-coverage",
                format!("no case with headline_eligible = {eligible}"),
            ));
        }
    }

    // 4. D92's missing OTS-side witness, asserted structurally so it cannot
    //    be lost by editing a value: some OTS case establishes Bitcoin as the
    //    identity, and some OTS case establishes none.
    let ots = |index: usize| inputs.cases[index].kind == CASE_KIND_OTS;
    let ots_identities: Vec<&serde_json::Value> = cases
        .iter()
        .enumerate()
        .filter(|(index, _)| ots(*index))
        .map(|(_, case)| &case["identity_kind"])
        .collect();
    if !ots_identities
        .iter()
        .any(|k| k.as_str() == Some(IDENTITY_BITCOIN_CHAIN))
    {
        return Err(check_err(
            "ots-identity-coverage",
            format!(
                "no OTS case carries identity_kind `{IDENTITY_BITCOIN_CHAIN}` — D92 §5.1's \
                 witness would be lost"
            ),
        ));
    }
    if !ots_identities.iter().any(|k| k.is_null()) {
        return Err(check_err(
            "ots-identity-coverage",
            "no OTS case carries identity_kind null — A40's eligibility filter would have \
             no OTS-side witness (D92)"
                .to_owned(),
        ));
    }

    for case in cases {
        let name = case["name"].as_str().unwrap_or("<unnamed>");

        // 5. A40's filter, as a law over the whole document rather than case
        //    by case.
        if case["headline_eligible"] == true {
            if case["verified_time_unix"].is_null() {
                return Err(check_err(
                    "eligibility-law",
                    format!("case `{name}` is headline-eligible with no verified_time_unix"),
                ));
            }
            if case["identity_kind"].is_null() {
                return Err(check_err(
                    "eligibility-law",
                    format!("case `{name}` is headline-eligible with no identity_kind"),
                ));
            }
        } else if !case["identity_kind"].is_null() {
            return Err(check_err(
                "eligibility-law",
                format!(
                    "case `{name}` is not headline-eligible yet carries identity_kind \
                     {} — `AnchorOutcome::new` filters an identity to headline-eligible \
                     verdicts only (A40)",
                    case["identity_kind"]
                ),
            ));
        }

        // 6'. D101 §3.5's assertion 6 was `report_slot == null` iff
        //     `state == "absent"`, which can never fire: `absent` is a
        //     KIND-level answer on `AnchorVerdicts::absent_verdict` and every
        //     case here is one artifact, so both sides are uniformly false —
        //     a tautology over an empty domain, which is D94 §4's "instrument
        //     nobody exercises". D103 RULING 5 replaces it with the two
        //     halves that can go red. A case that ever produced `absent`
        //     would mean `absent_verdict`'s domain had moved (D53 §4a).
        if case["report_slot"].is_null() {
            return Err(check_err(
                "report-slot",
                format!("case `{name}` emits no report slot; every artifact emits one"),
            ));
        }
        if case["state"].as_str() == Some("absent") {
            return Err(check_err(
                "state-absent-unreachable",
                format!(
                    "case `{name}` rendered `absent`, which is a kind-level answer \
                     (D53 §4a) and unreachable per artifact"
                ),
            ));
        }
    }

    // 5a (D103 RULING 5a). `fetch_date` is a pass-through R72 pins in code;
    // this states the same property over the frozen document, which is what
    // makes D103's `fetch_date` ruling checkable rather than merely written
    // down.
    for (case, input) in cases.iter().zip(&inputs.cases) {
        let supplied = input.fetch_date_unix.is_some() || input.upgrade.is_some();
        if case["fetch_date"].is_null() == supplied {
            return Err(check_err(
                "fetch-date-pass-through",
                format!(
                    "case `{}`: inputs {} a fetch date but expect.fetch_date is {}",
                    input.name,
                    if supplied { "supply" } else { "supply no" },
                    case["fetch_date"]
                ),
            ));
        }
    }

    Ok(())
}
