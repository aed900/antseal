//! Golden-vector kind **`bundle`** (task F13): the committed `.sealproof`
//! bytes, their three-layer diagnostic sidecars, and the reveal structure
//! each one discloses — **including the empty-anchor (UNANCHORED) bundle**,
//! which is a named M0 milestone bullet.
//!
//! Spec basis: the reveal bundle's content list (MVP-SPEC.md lines 112–114),
//! the deterministic-CBOR profile (line 73), the M0 milestone's
//! *"manifest/bundle encode–decode incl. empty-anchor vectors"* (line 153),
//! Verification's golden vectors (line 167), and the per-version testdata
//! layout (line 57).
//!
//! # What one case pins
//!
//! | field | freezes |
//! | --- | --- |
//! | `bundle_bytes` | the canonical `.sealproof` bytes — the whole format, byte for byte |
//! | `work_id` / `anchor_digest` | the identity of the manifest the bundle embeds, recomputed from the embedded bytes |
//! | `diagnostic.bundle` / `.manifest` / `.body` | **all three** strict-decode layers (F9), rendered structurally — F14's cross-check target |
//! | `decoded` | the schema-layer reading: sections, reveals, covers, boundary paths, anchors, receipt |
//!
//! The three diagnostic layers are the point. A bundle's embedded manifest is
//! a byte string to the outer pass, so its canonicality is only established by
//! running the strict decoder on the inner bytes themselves — and the sidecar
//! mirrors exactly that, rendering each layer separately under its own name
//! rather than silently flattening the nesting.
//!
//! # The empty-anchor vector
//!
//! The case `empty-anchor-unanchored` is the artifact Q6's must-exist slug
//! `bundle-empty-anchor` owed. An UNANCHORED bundle is a perfectly valid
//! `.sealproof` — it proves existence, integrity and authorship and simply
//! carries no independently proven time — so nothing about the format may
//! require an anchor, and it must decode, round-trip and verify like any
//! other.
//!
//! [`require_shape_coverage`] enforces its presence **structurally**: some
//! case must have all three anchor sections empty. That is deliberately a
//! per-file check, which is why all eight cases live in one vector file
//! rather than the milestone one being split out — a second file would have
//! to satisfy the whole F13 coverage list on its own, and each half would
//! then silently under-claim. `tests/bundle_vectors.rs` names the case
//! directly as a second layer.
//!
//! # Anchor artifact bytes are schema-opaque placeholders (a note for A)
//!
//! `.ots` blobs, DER tokens, intermediate certificates, the 80-byte Bitcoin
//! header and the receipt payload are **opaque `bstr`s at the format layer**
//! by design (F8): F enforces lengths and structure, A parses contents at M2.
//! Every artifact byte in these vectors is therefore a self-labelling
//! placeholder from R6's constructor. **A swaps in recorded real `.ots`/TSA
//! fixtures at M2 with no schema change** (tasks/F.md F13, tasks/A.md A25);
//! doing so re-generates these files' bytes and digests but touches neither
//! the kind's payload shape nor the wire registry.
//!
//! # Where the bytes come from, and the R handshake
//!
//! Cases are declarative work specifications plus a reveal selection, driven
//! through **R6's fixture constructor** — the single definition of "a valid
//! antseal work and a valid reveal" in this repository (R29). The executor
//! additionally runs every committed bundle back through
//! [`verify_bundle`](crate::verify::verify_bundle): F13's accept clause is
//! *"R's M3 verification tests can consume these vectors unmodified"*, and a
//! bundle the verifier rejects would not be consumable however well it
//! decodes. Only acceptance is asserted here — the canonical **report bytes**
//! over the same shapes are R9's `report` vectors, and duplicating them would
//! create two artifacts that must agree.

use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::bundle::{
    BundleV1, CoveredReveal, FullReveal, NonCoveredReveal, OpaqueBytes, OtsAnchor, ReceiptRecord,
    SealProof, TouchedFile, TsaAnchor, encode_bundle,
};
use crate::manifest::{anchor_digest, work_id};
use crate::test_util::bundle_fixtures::{
    AnchorSet, FIXTURE_APP_VERSION, FIXTURE_CLAIMED_TIME, FIXTURE_SEAL_ID, FileSelection,
    Selection, build,
};
use crate::verify::{VerifyOptions, verify_bundle};

use super::TEST_MASTER_SECRET_W;
use super::vectors::{VectorError, VectorSummary, decode_hex, first_difference, hex};
use super::vectors_cbor_diag;
use super::vectors_manifest::{WorkInput, check_err, payload_err};

/// The registered kind name.
pub const KIND: &str = "bundle";

fn payload(problem: String) -> VectorError {
    payload_err(KIND, problem)
}

fn check(name: &'static str, problem: String) -> VectorError {
    check_err(KIND, name, problem)
}

// ---------------------------------------------------------------------------
// payload types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Inputs {
    /// The documented fixed test seed (hex).
    w: String,
    /// The fixture `seal_id` (hex, 16 B).
    seal_id: String,
    /// The fixture `app_version`.
    app_version: String,
    /// The fixture `claimed_time`, POSIX seconds.
    claimed_time: u64,
    cases: Vec<CaseInput>,
}

/// One bundle: a work, a reveal selection over it, and an anchor set.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CaseInput {
    /// Stable **case** handle. Distinct from `work.name`, which names the
    /// work: several cases deliberately reveal the same work differently,
    /// and the receipt in/out pair differs in nothing else at all.
    name: String,
    /// Which anchor artifacts the bundle carries.
    anchors: AnchorSetInput,
    /// One entry per file, in file-table order.
    selection: Vec<SelectionInput>,
    /// The work being sealed.
    work: WorkInput,
}

/// The anchor sections, as a closed vocabulary.
#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum AnchorSetInput {
    /// Both sections empty — the UNANCHORED bundle.
    Empty,
    /// One OTS artifact and two TSA artifacts, every optional slot absent.
    OneOtsTwoTsa,
    /// Every anchor kind and optional slot populated, receipt included.
    EveryKind,
    /// The same, receipt excluded.
    EveryKindNoReceipt,
}

impl From<AnchorSetInput> for AnchorSet {
    fn from(value: AnchorSetInput) -> Self {
        match value {
            AnchorSetInput::Empty => Self::Empty,
            AnchorSetInput::OneOtsTwoTsa => Self::OneOtsTwoTsa,
            AnchorSetInput::EveryKind => Self::EveryKind { receipt: true },
            AnchorSetInput::EveryKindNoReceipt => Self::EveryKind { receipt: false },
        }
    }
}

/// What a reveal shows of one file.
///
/// Externally tagged, so the unit variants are the strings `"untouched"`,
/// `"full"`, `"full-no-mirror"` and the enumerated form is
/// `{"units": [0, 2]}` — readable in the committed file without a legend.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum SelectionInput {
    /// Nothing shown, and no `touched_files` entry.
    Untouched,
    /// Every normal unit, plus the raw mirror if the file has one.
    Full,
    /// Every normal unit, withholding the raw mirror — still a full reveal,
    /// since mirrors are exempt *by kind* (D28).
    FullNoMirror,
    /// These normal units, by index within the file's normal-unit list.
    Units(Vec<usize>),
}

impl From<&SelectionInput> for FileSelection {
    fn from(value: &SelectionInput) -> Self {
        match value {
            SelectionInput::Untouched => Self::Untouched,
            SelectionInput::Full => Self::Full,
            SelectionInput::FullNoMirror => Self::FullNoMirror,
            SelectionInput::Units(indices) => Self::Units(indices.clone()),
        }
    }
}

// ---------------------------------------------------------------------------
// executor
// ---------------------------------------------------------------------------

/// Execute a `bundle` vector (module docs).
///
/// # Errors
///
/// Every [`VectorError`] class: a malformed payload, a recomputation that
/// disagrees with the committed document, or a behavioural assertion the
/// committed values cannot express.
pub fn execute(
    inputs: serde_json::Value,
    expect: serde_json::Value,
    description: String,
) -> Result<VectorSummary, VectorError> {
    let parsed: Inputs =
        serde_json::from_value(inputs).map_err(|e| payload(format!("inputs: {e}")))?;
    check_fixture_constants(&parsed)?;

    // 1. The whole `expect` object, recomputed and compared as one value.
    let recomputed = build_expect(&parsed)?;
    if recomputed != expect {
        return Err(check(
            "document",
            first_difference("expect", &recomputed, &expect),
        ));
    }

    // 2. The assertions a value comparison cannot state, all run against the
    //    **committed** bytes.
    let cases = expect
        .get("cases")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| payload("expect.cases must be an array".to_owned()))?;
    for case in cases {
        check_case_behaviour(case)?;
    }
    require_shape_coverage(&parsed, cases)?;

    // 3. Q5 bit-match: SHA-256 over the serialization of every recomputed
    //    artifact.
    let serialized = serde_json::to_vec(&recomputed)
        .map_err(|e| check("digest-serialization", e.to_string()))?;
    let mut digest = Sha256::new();
    digest.update(super::vectors::RECOMPUTED_DIGEST_DOMAIN);
    digest.update(KIND.as_bytes());
    digest.update([0x00]);
    digest.update(super::vectors::prefix_len(serialized.len()));
    digest.update(&serialized);

    Ok(VectorSummary {
        kind: KIND,
        description,
        items: parsed.cases.len(),
        recomputed_digest: digest.finalize().into(),
    })
}

/// The fixture-discipline gate (project rule 6; `testdata/README.md`).
fn check_fixture_constants(inputs: &Inputs) -> Result<(), VectorError> {
    if decode_hex(KIND, "inputs.w", &inputs.w)? != TEST_MASTER_SECRET_W {
        return Err(check(
            "w-is-documented-test-seed",
            "inputs.w is not the documented fixed test seed 0x00..0x1f (testdata/README.md)"
                .to_owned(),
        ));
    }
    if decode_hex(KIND, "inputs.seal_id", &inputs.seal_id)? != FIXTURE_SEAL_ID {
        return Err(check(
            "seal-id-is-the-fixture-constant",
            "inputs.seal_id is not the published fixture seal_id".to_owned(),
        ));
    }
    if inputs.app_version != FIXTURE_APP_VERSION {
        return Err(check(
            "app-version-is-the-fixture-constant",
            format!(
                "inputs.app_version is `{}`, the fixture constant is `{FIXTURE_APP_VERSION}`",
                inputs.app_version
            ),
        ));
    }
    if inputs.claimed_time != FIXTURE_CLAIMED_TIME {
        return Err(check(
            "claimed-time-is-the-fixture-constant",
            format!(
                "inputs.claimed_time is {}, the fixture constant is {FIXTURE_CLAIMED_TIME}",
                inputs.claimed_time
            ),
        ));
    }
    Ok(())
}

/// Recompute the entire `expect` object from `inputs`, through R6's
/// constructor and the public codec API.
///
/// # Errors
///
/// [`VectorError::Payload`] for a malformed case, [`VectorError::Check`] when
/// the codec refuses one.
fn build_expect(inputs: &Inputs) -> Result<serde_json::Value, VectorError> {
    let mut cases = Vec::with_capacity(inputs.cases.len());
    for case in &inputs.cases {
        cases.push(build_case(case)?);
    }
    Ok(serde_json::json!({ "cases": cases }))
}

/// Regenerate the whole `expect` object from a committed document's own
/// `inputs`, so a native regenerator can diff it against the file.
///
/// # Errors
///
/// As [`build_expect`], plus [`VectorError::Envelope`] when the document is
/// not a `bundle` vector at all.
pub fn regenerate_expect(document: &serde_json::Value) -> Result<serde_json::Value, VectorError> {
    let kind = document.get("kind").and_then(serde_json::Value::as_str);
    if kind != Some(KIND) {
        return Err(VectorError::Envelope(format!(
            "not a `{KIND}` vector (kind is {kind:?})"
        )));
    }
    let inputs = document
        .get("inputs")
        .ok_or_else(|| VectorError::Envelope("document has no `inputs`".to_owned()))?;
    let parsed: Inputs =
        serde_json::from_value(inputs.clone()).map_err(|e| payload(format!("inputs: {e}")))?;
    check_fixture_constants(&parsed)?;
    build_expect(&parsed)
}

/// One case's `expect` entry.
fn build_case(case: &CaseInput) -> Result<serde_json::Value, VectorError> {
    let spec = case
        .work
        .to_work_spec(KIND)?
        .with_anchors(case.anchors.into());
    if case.selection.len() != spec.files.len() {
        return Err(check(
            "selection-covers-every-file",
            format!(
                "case `{}`: {} selection entries for {} files",
                case.name,
                case.selection.len(),
                spec.files.len()
            ),
        ));
    }
    let selection = Selection(case.selection.iter().map(FileSelection::from).collect());
    let built = build(&spec, &selection);

    let proof = SealProof::decode(&built.bytes).map_err(|e| {
        check(
            "fixture-bundle-decodes",
            format!("case `{}`: {e}", case.name),
        )
    })?;

    Ok(serde_json::json!({
        "name": case.name,
        "bundle_bytes": hex(&built.bytes),
        "work_id": work_id(proof.manifest().body_bytes()).to_hex(),
        "anchor_digest": anchor_digest(proof.anchor_digest_preimage()).to_hex(),
        "diagnostic": diagnostic_of(&case.name, &built.bytes, proof.manifest())?,
        "decoded": decoded_view(&proof),
    }))
}

/// All three strict-decode layers, rendered structurally (F14's target).
fn diagnostic_of(
    case: &str,
    bundle_bytes: &[u8],
    manifest: &crate::manifest::Manifest<'_>,
) -> Result<serde_json::Value, VectorError> {
    let render = |what: &'static str, bytes: &[u8]| {
        vectors_cbor_diag::render(bytes)
            .map_err(|e| check("diagnostic", format!("case `{case}`, {what}: {e}")))
    };
    Ok(serde_json::json!({
        "bundle": render("bundle", bundle_bytes)?,
        "manifest": render("manifest", manifest.encoded_bytes())?,
        "body": render("body", manifest.body_bytes())?,
    }))
}

/// `{len, sha256}` for a schema-opaque blob. Its bytes are already frozen by
/// `bundle_bytes` and by the diagnostic; a third copy of a 272-byte
/// ciphertext or a DER token would pin nothing new.
fn blob(bytes: &[u8]) -> serde_json::Value {
    serde_json::json!({ "len": bytes.len(), "sha256": hex(&Sha256::digest(bytes)) })
}

fn opaque(bytes: &OpaqueBytes) -> serde_json::Value {
    blob(bytes.as_slice())
}

/// The schema-layer reading of the bundle, section by named section.
///
/// Cryptographic material a verifier actually *uses* — `k_u`, `unit_salt`,
/// `path_salt`, `file_salt`, `s_root`, cover seeds, boundary hashes — is
/// written out in full: it is 32 bytes at most, it is what a reviewer checks,
/// and it is NON-SECRET fixture material by construction. Opaque artifact
/// blobs and ciphertexts are summarised instead.
fn decoded_view(proof: &SealProof<'_>) -> serde_json::Value {
    let bundle: &BundleV1<'_> = proof.bundle();
    let body = proof.manifest().body();
    serde_json::json!({
        "format_version": crate::bundle::registry::FORMAT_VERSION_V1,
        "manifest_summary": {
            "title": body.title(),
            "sig_policy": body.sig_policy().iter().map(ToString::to_string).collect::<Vec<_>>(),
            "file_count": body.files().len(),
            "units_total": body.units_total(),
        },
        "storage_record": {
            "address": hex(bundle.storage_record().address().as_bytes()),
            "nonce": hex(bundle.storage_record().nonce().as_bytes()),
            "k_m": hex(bundle.storage_record().k_m().as_bytes()),
        },
        "ots_anchors": bundle.ots_anchors().iter().map(ots_view).collect::<Vec<_>>(),
        "tsa_anchors": bundle.tsa_anchors().iter().map(tsa_view).collect::<Vec<_>>(),
        "receipt": bundle.receipt().map(receipt_view),
        "covered_reveals": bundle.covered_reveals().iter().map(covered_view).collect::<Vec<_>>(),
        "noncovered_reveals":
            bundle.noncovered_reveals().iter().map(noncovered_view).collect::<Vec<_>>(),
        "touched_files": bundle.touched_files().iter().map(touched_view).collect::<Vec<_>>(),
        "full_reveals": bundle.full_reveals().iter().map(full_view).collect::<Vec<_>>(),
        "revealed_unit_ids": bundle.revealed_unit_ids(),
    })
}

fn ots_view(anchor: &OtsAnchor) -> serde_json::Value {
    serde_json::json!({
        "status": anchor.status().to_string(),
        "ots": opaque(anchor.ots()),
        // D79: the upgrade group is all-or-nothing and never keyed on
        // `status`, so it is rendered as one present-or-absent object.
        "upgrade": anchor.upgrade().map(|upgrade| serde_json::json!({
            "block_height": upgrade.block_height(),
            "block_header": blob(upgrade.block_header()),
            "fetch_date": upgrade.fetch_date(),
        })),
    })
}

fn tsa_view(anchor: &TsaAnchor) -> serde_json::Value {
    serde_json::json!({
        "status": anchor.status().to_string(),
        "token": opaque(anchor.token()),
        "intermediates": anchor.intermediates().iter().map(opaque).collect::<Vec<_>>(),
        "fetch_date": anchor.fetch_date(),
    })
}

fn receipt_view(receipt: &ReceiptRecord) -> serde_json::Value {
    serde_json::json!({
        "tx_hashes": receipt.tx_hashes().iter().map(|h| hex(h)).collect::<Vec<_>>(),
        "block_number": receipt.block_number(),
        "payload": opaque(receipt.payload()),
    })
}

fn covered_view(reveal: &CoveredReveal) -> serde_json::Value {
    serde_json::json!({
        "unit_id": reveal.unit_id(),
        "k_u": hex(reveal.k_u().as_bytes()),
        "ciphertext": opaque(reveal.ciphertext()),
        "cover": reveal.cover().iter().map(|entry| serde_json::json!({
            "level": entry.address().level(),
            "index": entry.address().index(),
            "seed": hex(entry.seed().as_bytes()),
        })).collect::<Vec<_>>(),
        "paths": reveal.paths().iter().map(|node| serde_json::json!({
            "level": node.address().level(),
            "index": node.address().index(),
            "hash": hex(node.hash().as_bytes()),
        })).collect::<Vec<_>>(),
    })
}

fn noncovered_view(reveal: &NonCoveredReveal) -> serde_json::Value {
    serde_json::json!({
        "unit_id": reveal.unit_id(),
        "k_u": hex(reveal.k_u().as_bytes()),
        "ciphertext": opaque(reveal.ciphertext()),
        "unit_salt": hex(reveal.unit_salt().as_bytes()),
    })
}

fn touched_view(file: &TouchedFile) -> serde_json::Value {
    serde_json::json!({
        "file_id": file.file_id(),
        "path": file.path(),
        "path_salt": hex(file.path_salt().as_bytes()),
    })
}

fn full_view(reveal: &FullReveal) -> serde_json::Value {
    serde_json::json!({
        "file_id": reveal.file_id(),
        "file_salt": hex(reveal.file_salt().as_bytes()),
        "s_root": reveal.disclosed_s_root().map(|seed| hex(seed.as_bytes())),
    })
}

// ---------------------------------------------------------------------------
// the behavioural assertions
// ---------------------------------------------------------------------------

/// What the committed values state about themselves: the F9 three-layer
/// decode, the round-trip byte-identity, the two manifest digests recomputed
/// from the *embedded* bytes, the sidecar's fidelity to each layer, and
/// acceptance by the verifier R will consume these vectors with.
fn check_case_behaviour(case: &serde_json::Value) -> Result<(), VectorError> {
    let name = case
        .get("name")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("<unnamed>")
        .to_owned();
    let at = |what: &'static str, problem: String| check(what, format!("case `{name}`: {problem}"));
    let hex_field = |key: &str| -> Result<String, VectorError> {
        case.get(key)
            .and_then(serde_json::Value::as_str)
            .map(ToOwned::to_owned)
            .ok_or_else(|| payload(format!("case `{name}`: `{key}` must be a string")))
    };

    let bytes = decode_hex(
        KIND,
        "expect.cases[].bundle_bytes",
        &hex_field("bundle_bytes")?,
    )?;

    // F9: all three strict layers — outer bundle, embedded manifest envelope,
    // inner body — over one input buffer.
    let proof = SealProof::decode(&bytes).map_err(|e| at("bundle-decodes", format!("{e}")))?;

    // F9 accept: re-encoding a decoded bundle is byte-identical.
    let re_encoded =
        encode_bundle(proof.bundle()).map_err(|e| at("bundle-re-encodes", format!("{e}")))?;
    if re_encoded != bytes {
        return Err(at(
            "bundle-round-trip",
            "re-encoding the decoded bundle is not byte-identical".to_owned(),
        ));
    }

    // The zero-copy seam: the `anchor_digest` pre-image is the embedded
    // envelope exactly as received, not a re-derivation.
    if proof.anchor_digest_preimage() != proof.bundle().manifest_bytes() {
        return Err(at(
            "anchor-digest-preimage-is-the-embedded-manifest",
            "the decoded manifest's bytes are not the bundle's embedded bytes".to_owned(),
        ));
    }
    if work_id(proof.manifest().body_bytes()).to_hex() != hex_field("work_id")? {
        return Err(at(
            "work-id",
            "SHA-256 of the embedded body bytes is not the committed work_id".to_owned(),
        ));
    }
    if anchor_digest(proof.anchor_digest_preimage()).to_hex() != hex_field("anchor_digest")? {
        return Err(at(
            "anchor-digest",
            "SHA-256 of the embedded manifest bytes is not the committed anchor_digest".to_owned(),
        ));
    }

    // The sidecar describes *these* bytes, at every layer.
    let diagnostic = case
        .get("diagnostic")
        .ok_or_else(|| payload(format!("case `{name}`: no `diagnostic`")))?;
    let rendered = diagnostic_of(&name, &bytes, proof.manifest())?;
    if &rendered != diagnostic {
        return Err(at(
            "diagnostic-describes-the-committed-bytes",
            first_difference("diagnostic", &rendered, diagnostic),
        ));
    }

    // F13 accept: R's verification consumes these vectors unmodified. Only
    // acceptance is asserted — the canonical report bytes are R9's vectors.
    verify_bundle(&bytes, &VerifyOptions::new()).map_err(|e| {
        at(
            "verifier-accepts-the-committed-bundle",
            format!("verify_bundle rejected it with `{}`: {e}", e.code()),
        )
    })?;
    Ok(())
}

/// The shape coverage F13 enumerates, asserted **structurally**.
fn require_shape_coverage(inputs: &Inputs, cases: &[serde_json::Value]) -> Result<(), VectorError> {
    let missing = |what: &str| {
        check(
            "shape-coverage",
            format!("no case exercises {what} (tasks/F.md F13)"),
        )
    };
    let list = |case: &serde_json::Value, key: &str| -> Vec<serde_json::Value> {
        case.pointer(&format!("/decoded/{key}"))
            .and_then(serde_json::Value::as_array)
            .cloned()
            .unwrap_or_default()
    };

    // **The M0 milestone bullet**: a bundle carrying no anchors at all.
    if !cases.iter().any(|case| {
        list(case, "ots_anchors").is_empty()
            && list(case, "tsa_anchors").is_empty()
            && case
                .pointer("/decoded/receipt")
                .is_some_and(|r| r.is_null())
    }) {
        return Err(missing(
            "the empty-anchor (UNANCHORED) bundle — an explicit M0 milestone bullet \
             (MVP-SPEC.md line 153)",
        ));
    }
    // A whole-work reveal: every file fully revealed.
    if !cases.iter().any(|case| {
        let files = case
            .pointer("/decoded/manifest_summary/file_count")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0);
        files > 1 && list(case, "full_reveals").len() as u64 == files
    }) {
        return Err(missing("a whole-work reveal (every file fully revealed)"));
    }
    // A single covered-unit reveal carrying a leaf-exact sub-cover AND a
    // non-empty boundary path — a partial reveal, not the degenerate
    // whole-file cover.
    if !cases.iter().any(|case| {
        list(case, "covered_reveals").iter().any(|reveal| {
            reveal["cover"].as_array().is_some_and(|c| !c.is_empty())
                && reveal["paths"].as_array().is_some_and(|p| !p.is_empty())
        })
    }) {
        return Err(missing(
            "a covered-unit reveal with a leaf-exact sub-cover and boundary paths",
        ));
    }
    // A non-covered unit reveal: `unit_salt` in place of a cover.
    if !cases
        .iter()
        .any(|case| !list(case, "noncovered_reveals").is_empty())
    {
        return Err(missing("a non-covered unit reveal"));
    }
    // A full-file reveal disclosing both `file_salt` and `s_root`, over a
    // file that has a raw mirror (so the mirror path is exercised too).
    if !cases.iter().any(|case| {
        list(case, "full_reveals")
            .iter()
            .any(|reveal| !reveal["s_root"].is_null())
    }) {
        return Err(missing(
            "a full-file reveal disclosing file_salt and s_root",
        ));
    }
    // Every anchor kind and optional slot populated.
    if !cases.iter().any(|case| {
        list(case, "ots_anchors")
            .iter()
            .any(|a| !a["upgrade"].is_null())
            && list(case, "tsa_anchors").iter().any(|a| {
                a["intermediates"].as_array().is_some_and(|i| !i.is_empty())
                    && !a["source"].is_null()
            })
    }) {
        return Err(missing(
            "a bundle with every anchor kind populated (OTS upgrade group, TSA \
             intermediates and source)",
        ));
    }
    // Receipt in and out, over the otherwise identical bundle.
    let with_receipt = cases.iter().any(|case| {
        case.pointer("/decoded/receipt")
            .is_some_and(|r| !r.is_null())
    });
    if !with_receipt {
        return Err(missing("a receipt-included bundle"));
    }
    let pairs: Vec<(&str, &str)> = inputs
        .cases
        .iter()
        .map(|case| (case.work.name.as_str(), anchor_label(case.anchors)))
        .collect();
    if !pairs.iter().any(|(work, anchors)| {
        *anchors == "every-kind"
            && pairs
                .iter()
                .any(|(other, kind)| other == work && *kind == "every-kind-no-receipt")
    }) {
        return Err(missing(
            "the receipt-included / receipt-excluded pair over one identical work",
        ));
    }
    Ok(())
}

const fn anchor_label(set: AnchorSetInput) -> &'static str {
    match set {
        AnchorSetInput::Empty => "empty",
        AnchorSetInput::OneOtsTwoTsa => "one-ots-two-tsa",
        AnchorSetInput::EveryKind => "every-kind",
        AnchorSetInput::EveryKindNoReceipt => "every-kind-no-receipt",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The selection vocabulary really is the strings the committed files
    /// carry — a rename would otherwise silently change what a frozen vector
    /// means.
    #[test]
    fn selection_vocabulary_is_stable() {
        for (json, expected) in [
            ("\"untouched\"", FileSelection::Untouched),
            ("\"full\"", FileSelection::Full),
            ("\"full-no-mirror\"", FileSelection::FullNoMirror),
            ("{\"units\":[0,2]}", FileSelection::Units(vec![0, 2])),
        ] {
            let parsed: SelectionInput = serde_json::from_str(json).expect("parses");
            assert_eq!(FileSelection::from(&parsed), expected, "{json}");
        }
    }

    /// The anchor vocabulary likewise, including the receipt in/out split.
    #[test]
    fn anchor_vocabulary_is_stable() {
        for (json, expected) in [
            ("\"empty\"", AnchorSet::Empty),
            ("\"one-ots-two-tsa\"", AnchorSet::OneOtsTwoTsa),
            ("\"every-kind\"", AnchorSet::EveryKind { receipt: true }),
            (
                "\"every-kind-no-receipt\"",
                AnchorSet::EveryKind { receipt: false },
            ),
        ] {
            let parsed: AnchorSetInput = serde_json::from_str(json).expect("parses");
            assert_eq!(AnchorSet::from(parsed), expected, "{json}");
            assert_eq!(
                serde_json::from_str::<serde_json::Value>(json)
                    .expect("parses")
                    .as_str(),
                Some(anchor_label(parsed))
            );
        }
    }
}
