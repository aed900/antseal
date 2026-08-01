//! Golden-vector kind **`manifest`** (task F12): the committed manifest
//! bytes, their diagnostic sidecars, and the `work_id` / `anchor_digest`
//! each one hashes to.
//!
//! Spec basis: `work_id` / `anchor_digest` (MVP-SPEC.md line 75), the
//! deterministic-CBOR profile (line 73), the manifest body field list
//! (line 98), the per-version testdata layout (line 57), the M0 milestone
//! (line 153) and Verification's golden vectors (line 167).
//!
//! # What this kind pins, and what it discharges
//!
//! **F7 deliberately deferred its committed artifact to here.** F7 built
//! [`work_id`] and [`anchor_digest`] as two distinct named functions and
//! proved their properties in unit tests, but its accept clause *"fixed
//! manifest fixture → expected `work_id` and `anchor_digest` hex committed
//! to testdata"* needed a manifest whose bytes were themselves frozen —
//! which is F12. This kind closes that debt: every case commits the manifest
//! envelope bytes **and** the two hex digests, and the executor recomputes
//! both through the public API.
//!
//! Concretely, one case pins:
//!
//! | field | what it freezes |
//! | --- | --- |
//! | `manifest_bytes` | the canonical envelope bytes — the whole format, byte for byte |
//! | `work_id` | `SHA-256(body)`, over the embedded `body` byte string *as received* |
//! | `anchor_digest` | `SHA-256(envelope)`, signatures included |
//! | `diagnostic.envelope` / `diagnostic.body` | the two CBOR layers, rendered structurally — F14's cross-check target ([`super::vectors_cbor_diag`]) |
//! | `decoded` | the same data read back through the *schema* layer, field by named field |
//!
//! `diagnostic` and `decoded` are not redundant with each other. The
//! diagnostic is schema-blind: it says "key 3 of the body map holds this
//! text string". The decoded view says "the title is …". Only holding both
//! catches a schema layer that reads the registry consistently but wrongly —
//! a swapped key pair encodes and decodes cleanly and would pass a
//! bytes-only vector.
//!
//! # Why the `work_id` pre-image is not a separate field
//!
//! It would be a duplicate: the pre-image is exactly the envelope's key-0
//! byte string, available at `expect.cases[i].diagnostic.envelope.m[0][1].b`.
//! Two fields that must agree are a place for them to disagree, and making
//! the cross-check *reach into the envelope* for the pre-image is the more
//! honest exercise — it demonstrates that `work_id` hashes the embedded
//! bytes and never a re-encoding (F6/F7's "verifiers never re-encode").
//!
//! # Where the bytes come from
//!
//! Cases are declarative work specifications ([`WorkInput`]) driven through
//! **R6's fixture constructor** ([`crate::test_util::bundle_fixtures`]),
//! which is the single definition of "a valid antseal work" in this
//! repository. The vector therefore cannot drift from the substrate R7–R10
//! mutate and R9's report vectors pin, and adding a second, parallel notion
//! of a well-formed manifest is avoided by construction (the hazard recorded
//! as R29).
//!
//! Every case is fully crypto-consistent: real commitments, real fine-tree
//! roots, real hybrid signatures over the real body bytes — all derived from
//! the documented NON-SECRET fixture seed
//! [`TEST_MASTER_SECRET_W`](super::TEST_MASTER_SECRET_W) (project rule 6).
//!
//! # `sig_policy` economics (why most cases are Ed25519-only)
//!
//! ML-DSA-65 costs 1952 B of public key plus 3309 B of signature — 10.5 kB
//! of hex per case, appearing twice (bytes and sidecar). The signature map
//! is a *sibling* of the body, not interleaved with it, so a hybrid case
//! pins nothing about the file/unit table that an Ed25519-only case does
//! not. The suite therefore carries the hybrid policy on the smallest work
//! and on the richest one, and pairs the smallest work with its Ed25519-only
//! twin so the two policies are directly diffable at a glance.
//!
//! [`work_id`]: crate::manifest::work_id
//! [`anchor_digest`]: crate::manifest::anchor_digest

use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::crypto::domain::MAX_DOMAIN_TAG;
use crate::crypto::error::SigAlg;
use crate::crypto::sig_policy::SigPolicy;
use crate::manifest::{
    ByteRange, Manifest, ManifestBodyV1, SigAlgMap, anchor_digest, encode_body, encode_envelope,
    work_id,
};
use crate::test_util::bundle_fixtures::{
    FIXTURE_APP_VERSION, FIXTURE_CLAIMED_TIME, FIXTURE_SEAL_ID, FileSpec, Selection, WorkSpec,
    build,
};

use super::TEST_MASTER_SECRET_W;
use super::vectors::{VectorError, VectorSummary, decode_hex, first_difference, hex};
use super::vectors_cbor_diag;

/// The registered kind name.
pub const KIND: &str = "manifest";

pub(super) fn payload_err(kind: &'static str, problem: String) -> VectorError {
    VectorError::Payload { kind, problem }
}

pub(super) fn check_err(kind: &'static str, check: &'static str, problem: String) -> VectorError {
    VectorError::Check {
        kind,
        check,
        problem,
    }
}

// ---------------------------------------------------------------------------
// the shared declarative work specification (also used by kind `bundle`)
// ---------------------------------------------------------------------------

/// One synthetic work, described as data.
///
/// Deliberately *not* "the name of a `bundle_fixtures::shapes` constructor":
/// a frozen vector must be readable without the crate that generated it, and
/// naming a Rust function would make a rename a format event. The
/// declarative form says what the work *is*; [`Self::to_work_spec`] is the
/// only bridge to R6.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct WorkInput {
    /// Stable case handle, unique within the file.
    pub name: String,
    /// The manifest `title` field.
    pub title: String,
    /// `hybrid` | `ed25519-only` — the `sig_policy` (spec line 97).
    pub policy: String,
    /// Seeds R6's deterministic fixture RNG, which is where the per-unit
    /// AEAD nonces recorded in the manifest come from.
    pub seed: u64,
    /// The files, in file-table order; the index **is** the `file_id`.
    pub files: Vec<FileInput>,
}

/// One file of a synthetic work.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct FileInput {
    /// The (committed, not disclosed) path.
    pub path: String,
    /// `binary` | `text` — which byte domain the unit tiling covers.
    pub kind: String,
    /// The file's raw bytes, hex. For a text file whose raw bytes are not
    /// already canonical, R6 emits the raw mirror automatically (G7).
    pub raw: String,
    /// `false` is `--no-fine-tree`: the units carry `unit_commit` instead
    /// and no `fine_root` is recorded (spec lines 84, 94).
    pub fine_tree: bool,
    /// `--split` unit widths over the tiling domain; empty means one
    /// whole-file unit.
    pub split: Vec<u64>,
}

impl WorkInput {
    /// Bridge to R6's constructor.
    pub(super) fn to_work_spec(&self, kind: &'static str) -> Result<WorkSpec, VectorError> {
        let mut files = Vec::with_capacity(self.files.len());
        for file in &self.files {
            let raw = decode_hex(kind, "cases[].files[].raw", &file.raw)?;
            let mut spec = match file.kind.as_str() {
                "binary" => FileSpec::binary(&file.path, raw),
                "text" => FileSpec::text(&file.path, raw),
                other => {
                    return Err(check_err(
                        kind,
                        "file-kind",
                        format!("file `{}`: unknown kind `{other}`", file.path),
                    ));
                }
            };
            if !file.fine_tree {
                spec = spec.without_fine_tree();
            }
            if !file.split.is_empty() {
                spec = spec.split(file.split.clone());
            }
            files.push(spec);
        }
        let mut work = WorkSpec::new(&self.title, files).with_seed(self.seed);
        match self.policy.as_str() {
            "hybrid" => {}
            "ed25519-only" => work = work.with_ed25519_only_policy(),
            other => {
                return Err(check_err(
                    kind,
                    "sig-policy",
                    format!("case `{}`: unknown policy `{other}`", self.name),
                ));
            }
        }
        Ok(work)
    }
}

// ---------------------------------------------------------------------------
// payload types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Inputs {
    /// The documented fixed test seed (hex).
    w: String,
    /// The fixture `seal_id` every case records (hex, 16 B).
    seal_id: String,
    /// The fixture `app_version` — pinned in `inputs` so the constant is
    /// visible in the vector rather than hidden in the constructor.
    app_version: String,
    /// The fixture `claimed_time`, POSIX seconds (spec line 98:
    /// informational, never a proven time).
    claimed_time: u64,
    cases: Vec<WorkInput>,
}

// ---------------------------------------------------------------------------
// executor
// ---------------------------------------------------------------------------

/// Execute a `manifest` vector (module docs).
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
        serde_json::from_value(inputs).map_err(|e| payload_err(KIND, format!("inputs: {e}")))?;
    check_fixture_constants(&parsed)?;

    // 1. The whole `expect` object, recomputed from `inputs` and compared as
    //    one value: a missing, extra or reordered field fails like a wrong
    //    byte would.
    let recomputed = build_expect(&parsed)?;
    if recomputed != expect {
        return Err(check_err(
            KIND,
            "document",
            first_difference("expect", &recomputed, &expect),
        ));
    }

    // 2. The assertions a value comparison cannot state — all of them run
    //    against the **committed** bytes, so the file's own hex is what is
    //    decoded, re-encoded and hashed.
    let cases = expect
        .get("cases")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| payload_err(KIND, "expect.cases must be an array".to_owned()))?;
    for case in cases {
        check_case_behaviour(case)?;
    }
    require_shape_coverage(&parsed, cases)?;

    // 3. Q5 bit-match: SHA-256 over the serialization of every recomputed
    //    artifact — the bytes themselves, not a verdict.
    let serialized = serde_json::to_vec(&recomputed)
        .map_err(|e| check_err(KIND, "digest-serialization", e.to_string()))?;
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

/// The fixture-discipline gate: the document must derive from the documented
/// seed and the published fixture constants, never from unknown material
/// (project rule 6; `testdata/README.md`).
fn check_fixture_constants(inputs: &Inputs) -> Result<(), VectorError> {
    let w = decode_hex(KIND, "inputs.w", &inputs.w)?;
    if w != TEST_MASTER_SECRET_W {
        return Err(check_err(
            KIND,
            "w-is-documented-test-seed",
            "inputs.w is not the documented fixed test seed 0x00..0x1f (testdata/README.md)"
                .to_owned(),
        ));
    }
    let seal_id = decode_hex(KIND, "inputs.seal_id", &inputs.seal_id)?;
    if seal_id != FIXTURE_SEAL_ID {
        return Err(check_err(
            KIND,
            "seal-id-is-the-fixture-constant",
            "inputs.seal_id is not the published fixture seal_id".to_owned(),
        ));
    }
    if inputs.app_version != FIXTURE_APP_VERSION {
        return Err(check_err(
            KIND,
            "app-version-is-the-fixture-constant",
            format!(
                "inputs.app_version is `{}`, the fixture constant is `{FIXTURE_APP_VERSION}`",
                inputs.app_version
            ),
        ));
    }
    if inputs.claimed_time != FIXTURE_CLAIMED_TIME {
        return Err(check_err(
            KIND,
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
/// constructor and antseal-core's public codec API.
///
/// Also the **regenerator**: `tests/manifest_vectors.rs` calls it through
/// [`regenerate_expect`] and diffs the result against the committed file.
///
/// # Errors
///
/// [`VectorError::Payload`] for a malformed case and [`VectorError::Check`]
/// when the codec itself refuses one.
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
/// not a `manifest` vector at all.
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
    let parsed: Inputs = serde_json::from_value(inputs.clone())
        .map_err(|e| payload_err(KIND, format!("inputs: {e}")))?;
    check_fixture_constants(&parsed)?;
    build_expect(&parsed)
}

/// One case's `expect` entry.
fn build_case(case: &WorkInput) -> Result<serde_json::Value, VectorError> {
    let spec = case.to_work_spec(KIND)?;
    // The manifest is a function of the *work*, never of what a reveal
    // shows, so the selection here is "nothing" and the bytes are the same
    // under any other (asserted in `tests/manifest_vectors.rs`).
    let built = build(&spec, &Selection::nothing(spec.files.len()));
    let manifest = Manifest::decode(&built.manifest).map_err(|e| {
        check_err(
            KIND,
            "fixture-manifest-decodes",
            format!("case `{}`: {e}", case.name),
        )
    })?;

    Ok(serde_json::json!({
        "name": case.name,
        "manifest_bytes": hex(&built.manifest),
        "work_id": work_id(manifest.body_bytes()).to_hex(),
        "anchor_digest": anchor_digest(&built.manifest).to_hex(),
        "diagnostic": diagnostic_of(&case.name, &built.manifest, manifest.body_bytes())?,
        "decoded": decoded_view(&manifest),
    }))
}

/// Both CBOR layers, rendered structurally (F14's cross-check target).
pub(super) fn diagnostic_of(
    case: &str,
    envelope_bytes: &[u8],
    body_bytes: &[u8],
) -> Result<serde_json::Value, VectorError> {
    let render = |what: &'static str, bytes: &[u8]| {
        vectors_cbor_diag::render(bytes)
            .map_err(|e| check_err(KIND, "diagnostic", format!("case `{case}`, {what}: {e}")))
    };
    Ok(serde_json::json!({
        "envelope": render("envelope", envelope_bytes)?,
        "body": render("body", body_bytes)?,
    }))
}

/// The schema-layer reading of the same manifest, field by named field.
///
/// Large opaque blobs — public keys and signatures — are recorded as
/// `{len, sha256}` rather than hex. Their bytes are already frozen by
/// `manifest_bytes` and by the diagnostic; repeating 3309 bytes of ML-DSA
/// signature in a third place would triple the file to pin nothing new, and
/// nobody reads a signature by eye. The digest still fails loudly on any
/// change.
fn decoded_view(manifest: &Manifest<'_>) -> serde_json::Value {
    let body = manifest.body();
    serde_json::json!({
        "format_version": body.format_version(),
        "app_version": body.app_version(),
        "seal_id": hex(body.seal_id().as_bytes()),
        "title": body.title(),
        "claimed_time": body.claimed_time(),
        "sig_policy": body.sig_policy().iter().map(ToString::to_string).collect::<Vec<_>>(),
        "pubkeys": blob_map(body.pubkeys()),
        "signatures": blob_map(manifest.signatures()),
        "units_total": body.units_total(),
        "files": body.files().iter().enumerate().map(|(file_id, file)| {
            let descriptor = file.descriptor();
            serde_json::json!({
                "file_id": file_id,
                "path_commit": hex(file.path_commit()),
                "raw_commit": hex(file.raw_commit()),
                "canon_commit": file.canon().canon_commit().map(|c| hex(c)),
                "size": file.size(),
                "descriptor": {
                    "kind": descriptor.kind().to_string(),
                    "fine_tree_present": descriptor.fine_tree_present(),
                    "fine_tree_domain": descriptor.fine_tree_domain().map(|d| d.to_string()),
                    "unicode_version": descriptor.unicode_version(),
                },
                "fine_root": file.fine_tree().root().map(|r| hex(r)),
                "units": file.units().iter().map(|unit| serde_json::json!({
                    "unit_id": unit.unit_id(),
                    "kind": unit.kind().to_string(),
                    "range_start": unit.range().start(),
                    "range_length": unit.range().length(),
                    "true_length": unit.true_length(),
                    "unit_commit": unit.unit_commit().map(|c| hex(c)),
                    "nonce": hex(unit.nonce().as_bytes()),
                    "address": hex(unit.address().as_bytes()),
                })).collect::<Vec<_>>(),
            })
        }).collect::<Vec<_>>(),
    })
}

/// `{alg, len, sha256}` per entry of a signature-algorithm map.
fn blob_map(map: &SigAlgMap) -> serde_json::Value {
    serde_json::Value::Array(
        map.iter()
            .map(|(alg, bytes)| {
                serde_json::json!({
                    "alg": alg.to_string(),
                    "len": bytes.len(),
                    "sha256": hex(&Sha256::digest(bytes)),
                })
            })
            .collect(),
    )
}

// ---------------------------------------------------------------------------
// the behavioural assertions
// ---------------------------------------------------------------------------

/// Everything the committed values state *about themselves*, run against the
/// committed bytes: the F6 envelope round-trip, the F5/F2 body round-trip,
/// the two F7 digests, the sidecar's fidelity, and `work_id`'s independence
/// from the signature container.
fn check_case_behaviour(case: &serde_json::Value) -> Result<(), VectorError> {
    let name = case
        .get("name")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("<unnamed>")
        .to_owned();
    let at = |check: &'static str, problem: String| {
        check_err(KIND, check, format!("case `{name}`: {problem}"))
    };
    let field = |key: &str| -> Result<String, VectorError> {
        case.get(key)
            .and_then(serde_json::Value::as_str)
            .map(ToOwned::to_owned)
            .ok_or_else(|| payload_err(KIND, format!("case `{name}`: `{key}` must be a string")))
    };

    let envelope_bytes = decode_hex(
        KIND,
        "expect.cases[].manifest_bytes",
        &field("manifest_bytes")?,
    )?;

    // F6: the committed bytes decode, and re-encoding from the received body
    // bytes reproduces them exactly. A verifier never re-encodes a body, so
    // this is the only re-encode the format admits.
    let manifest =
        Manifest::decode(&envelope_bytes).map_err(|e| at("manifest-decodes", format!("{e}")))?;
    let body_bytes = manifest.body_bytes();
    let re_encoded = encode_envelope(body_bytes, manifest.signatures())
        .map_err(|e| at("envelope-re-encodes", format!("{e}")))?;
    if re_encoded != envelope_bytes {
        return Err(at(
            "envelope-round-trip",
            "re-encoding the envelope from its received body bytes is not byte-identical"
                .to_owned(),
        ));
    }

    // F5/F2: the body decodes and re-encodes to the identical bytes.
    let body =
        ManifestBodyV1::decode(body_bytes).map_err(|e| at("body-decodes", format!("{e}")))?;
    let re_encoded_body = encode_body(body).map_err(|e| at("body-re-encodes", format!("{e}")))?;
    if re_encoded_body != body_bytes {
        return Err(at(
            "body-round-trip",
            "re-encoding the decoded body is not byte-identical to the received body bytes"
                .to_owned(),
        ));
    }

    // F7: the two digests, recomputed over the committed bytes.
    let expected_work_id = field("work_id")?;
    if work_id(body_bytes).to_hex() != expected_work_id {
        return Err(at(
            "work-id",
            "SHA-256 of the received body bytes is not the committed work_id".to_owned(),
        ));
    }
    let expected_anchor_digest = field("anchor_digest")?;
    if anchor_digest(&envelope_bytes).to_hex() != expected_anchor_digest {
        return Err(at(
            "anchor-digest",
            "SHA-256 of the committed envelope bytes is not the committed anchor_digest".to_owned(),
        ));
    }

    // The domain-tag disjointness `crypto::domain`'s docs promise F asserts
    // on every vector (F41 made the promise true): both digest pre-images
    // start with a CBOR *map* head, above the 0x00..=0x06 tag range — the
    // property that lets `work_id`/`anchor_digest` hash untagged bytes
    // (spec line 79). It is a property of the two pre-image languages, not
    // of canonical items in general: uint 0 encodes as 0x00.
    for (check, bytes) in [
        ("body-clears-domain-tag-range", body_bytes),
        (
            "envelope-clears-domain-tag-range",
            envelope_bytes.as_slice(),
        ),
    ] {
        let head = bytes.first().copied();
        if head.is_none_or(|h| h >> 5 != 5 || h <= MAX_DOMAIN_TAG) {
            return Err(at(
                check,
                format!("pre-image head {head:?} is not a map head above MAX_DOMAIN_TAG"),
            ));
        }
    }

    // F7's separation property, stated as a claim about *this* manifest: a
    // different signature container over the same body moves `anchor_digest`
    // and leaves `work_id` where it was. Vacuous only if the two functions
    // read the same pre-image, which is exactly what it exists to refute.
    let mutated = mutate_first_signature(manifest.signatures())?;
    let mutated_envelope = encode_envelope(body_bytes, &mutated)
        .map_err(|e| at("signature-mutation-encodes", format!("{e}")))?;
    if anchor_digest(&mutated_envelope).to_hex() == expected_anchor_digest {
        return Err(at(
            "anchor-digest-covers-signatures",
            "flipping a signature byte left anchor_digest unchanged".to_owned(),
        ));
    }
    let mutated_manifest = Manifest::decode(&mutated_envelope)
        .map_err(|e| at("signature-mutation-decodes", format!("{e}")))?;
    if work_id(mutated_manifest.body_bytes()).to_hex() != expected_work_id {
        return Err(at(
            "work-id-is-signature-independent",
            "flipping a signature byte moved work_id".to_owned(),
        ));
    }

    // The sidecar describes *these* bytes, layer by layer — F14's contract.
    let diagnostic = case
        .get("diagnostic")
        .ok_or_else(|| payload_err(KIND, format!("case `{name}`: no `diagnostic`")))?;
    let rendered = diagnostic_of(&name, &envelope_bytes, body_bytes)?;
    if &rendered != diagnostic {
        return Err(at(
            "diagnostic-describes-the-committed-bytes",
            first_difference("diagnostic", &rendered, diagnostic),
        ));
    }
    Ok(())
}

/// A signature container with one byte of its first entry flipped.
fn mutate_first_signature(signatures: &SigAlgMap) -> Result<SigAlgMap, VectorError> {
    let entries: Vec<(SigAlg, Vec<u8>)> = signatures
        .iter()
        .enumerate()
        .map(|(index, (alg, bytes))| {
            let mut bytes = bytes.to_vec();
            if index == 0
                && let Some(first) = bytes.first_mut()
            {
                *first ^= 0x01;
            }
            (alg, bytes)
        })
        .collect();
    SigAlgMap::new(crate::manifest::SigMaterial::Signature, entries).map_err(|e| {
        check_err(
            KIND,
            "signature-mutation",
            format!("rebuilding the signature map failed: {e}"),
        )
    })
}

/// The shape coverage F12 enumerates, asserted **structurally** rather than
/// by case name: a renamed case still counts, a silently dropped shape does
/// not.
fn require_shape_coverage(inputs: &Inputs, cases: &[serde_json::Value]) -> Result<(), VectorError> {
    let missing = |what: &str| {
        check_err(
            KIND,
            "shape-coverage",
            format!("no case exercises {what} (tasks/F.md F12)"),
        )
    };
    let files = |case: &serde_json::Value| -> Vec<serde_json::Value> {
        case.pointer("/decoded/files")
            .and_then(serde_json::Value::as_array)
            .cloned()
            .unwrap_or_default()
    };
    let units = |file: &serde_json::Value| -> Vec<serde_json::Value> {
        file.get("units")
            .and_then(serde_json::Value::as_array)
            .cloned()
            .unwrap_or_default()
    };

    // A single-file work whose one unit is binary and fine-tree covered.
    if !cases.iter().any(|case| {
        let files = files(case);
        files.len() == 1
            && files[0].pointer("/descriptor/kind") == Some(&serde_json::json!("binary"))
            && units(&files[0]).len() == 1
    }) {
        return Err(missing("a minimal single-file binary work"));
    }
    // A raw-mirror unit (spec line 94: the mirror lives in the raw domain).
    if !cases.iter().any(|case| {
        files(case)
            .iter()
            .any(|file| units(file).iter().any(|u| u["kind"] == "raw-mirror"))
    }) {
        return Err(missing("a text file with a raw-mirror unit"));
    }
    // `--no-fine-tree`: no `fine_root`, and the unit carries `unit_commit`.
    if !cases.iter().any(|case| {
        files(case).iter().any(|file| {
            file["fine_root"].is_null() && units(file).iter().any(|u| !u["unit_commit"].is_null())
        })
    }) {
        return Err(missing("a --no-fine-tree file carrying unit_commit"));
    }
    // A multi-file work with a multi-unit file.
    if !cases.iter().any(|case| {
        let files = files(case);
        files.len() > 1
            && files
                .iter()
                .any(|file| units(file).iter().filter(|u| u["kind"] == "normal").count() > 1)
    }) {
        return Err(missing("a multi-file, multi-unit body"));
    }
    // The empty file: size 0, one unit, true_length 0, no fine tree (G4).
    if !cases.iter().any(|case| {
        files(case).iter().any(|file| {
            file["size"] == 0 && units(file).len() == 1 && units(file)[0]["true_length"] == 0
        })
    }) {
        return Err(missing("an empty-file unit"));
    }
    // Both `sig_policy` shapes (spec line 97).
    for (label, policy) in [
        ("hybrid", SigPolicy::hybrid()),
        ("ed25519-only", SigPolicy::ed25519_only()),
    ] {
        let wanted: Vec<String> = policy
            .algorithms()
            .iter()
            .map(ToString::to_string)
            .collect();
        if !cases
            .iter()
            .any(|case| case.pointer("/decoded/sig_policy") == Some(&serde_json::json!(wanted)))
        {
            return Err(missing(&format!("the `{label}` sig_policy")));
        }
    }
    // The two policies must sit over the *same* work, so the pair is a
    // one-field diff rather than two unrelated manifests.
    let signature: Vec<(String, Vec<String>)> = inputs
        .cases
        .iter()
        .map(|case| {
            (
                case.policy.clone(),
                case.files.iter().map(|f| f.raw.clone()).collect(),
            )
        })
        .collect();
    if !signature.iter().any(|(policy, files)| {
        policy == "hybrid"
            && signature
                .iter()
                .any(|(other, other_files)| other == "ed25519-only" && other_files == files)
    }) {
        return Err(missing(
            "the two sig_policy shapes over one identical work (the diffable pair)",
        ));
    }
    Ok(())
}

/// A `ByteRange` re-export guard: the decoded view reports `range_start` and
/// `range_length`, which is the registry's start+length representation. If
/// the registry ever moved to start+end this would stop compiling, which is
/// the intended alarm.
const _: fn(ByteRange) -> (u64, u64) = |r| (r.start(), r.length());

#[cfg(test)]
mod tests {
    use super::*;

    /// The blob summary really does move when a byte does — the `{len,
    /// sha256}` shorthand is a digest, not a placeholder.
    #[test]
    fn blob_summaries_are_digests() {
        let a = SigAlgMap::new(
            crate::manifest::SigMaterial::Pubkey,
            [(SigAlg::Ed25519, vec![0x01; 32])],
        )
        .expect("fixture map");
        let b = SigAlgMap::new(
            crate::manifest::SigMaterial::Pubkey,
            [(SigAlg::Ed25519, {
                let mut bytes = vec![0x01; 32];
                bytes[0] = 0x02;
                bytes
            })],
        )
        .expect("fixture map");
        assert_ne!(blob_map(&a), blob_map(&b));
    }

    /// The signature mutation flips exactly one byte of exactly one entry,
    /// which is what makes the F7 separation claim a one-variable statement.
    #[test]
    fn signature_mutation_touches_one_byte() {
        let map = SigAlgMap::new(
            crate::manifest::SigMaterial::Signature,
            [(SigAlg::Ed25519, vec![0x00; 64])],
        )
        .expect("fixture map");
        let mutated = mutate_first_signature(&map).expect("mutation rebuilds");
        let original = map.get(SigAlg::Ed25519).expect("present");
        let changed = mutated.get(SigAlg::Ed25519).expect("present");
        assert_eq!(original.len(), changed.len());
        assert_eq!(
            original.iter().zip(changed).filter(|(a, b)| a != b).count(),
            1
        );
    }
}
