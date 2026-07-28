//! Golden-vector envelope: schema types, validation, kind dispatch, and
//! execution (Q4). Documented schema + add-a-vector procedure:
//! `testdata/vectors/README.md`.
//!
//! Deliberately **WASM-safe**: everything here operates on in-memory bytes
//! — zero I/O — so the Q5 native↔WASM bit-match lane executes committed
//! vectors through this exact code path. File discovery/reading is native
//! and lives in `crates/antseal-core/tests/vector_runner.rs`.
//!
//! Failure discipline (Q4 accept): a malformed vector file is a hard
//! [`VectorError`], never a skip — and this is adversarial-input practice
//! too (working principle "parse defensively"): no panics on malformed
//! input, typed errors throughout.
//!
//! # Adding a kind (framework extension — never per-vector)
//!
//! 1. Add the kind name to [`KNOWN_KINDS`].
//! 2. Define its `inputs`/`expect` payload types (`deny_unknown_fields`).
//! 3. Add the dispatch arm in [`execute_vector_bytes`] with an executor
//!    that recomputes every expectation through public `antseal-core` APIs.
//! 4. Document the kind's row in `testdata/vectors/README.md`.
//!
//! The runner test and existing vector files never change.

use serde::Deserialize;

use crate::crypto::commit::{
    canon_commit, path_commit, raw_commit, unit_commit, verify_canon_commit, verify_path_commit,
    verify_raw_commit, verify_unit_commit,
};
use crate::crypto::domain::{TAG_CANON_COMMIT, TAG_PATH_COMMIT, TAG_RAW_COMMIT, TAG_UNIT_COMMIT};
use crate::crypto::hkdf::{
    FileId, IdDomain, Label, SENTINEL_ID, UnitId, derive_file_salt, derive_fine_seed,
    derive_manifest_key, derive_path_salt, derive_sig_ed25519_seed, derive_sig_mldsa65_seed,
    derive_unit_key, derive_unit_salt,
};
use crate::crypto::material::{FileSalt, MasterSecretRef, Salt16};

/// The envelope `schema` discriminator string.
pub const SCHEMA: &str = "antseal-golden-vector";

/// The envelope schema version this executor implements (independent of
/// the *format* version a vector pins).
pub const SCHEMA_VERSION: u32 = 1;

/// Marker every vector file's `non_secret` field must contain (project
/// rule 6; `testdata/README.md` secret-material convention).
pub const NON_SECRET_MARKER: &str = "NON-SECRET";

/// Registered vector kinds. Extending this list is a framework change
/// (see the module docs), not a per-vector event.
pub const KNOWN_KINDS: &[&str] = &["hkdf-labels", "commitments"];

/// Why a vector file failed. Every variant is a *loud* failure in the
/// runner — nothing is skipped.
#[derive(Debug, thiserror::Error)]
pub enum VectorError {
    /// Not valid JSON, or the envelope shape is wrong (missing field,
    /// unknown field, wrong type).
    #[error("vector envelope is malformed: {0}")]
    Envelope(String),
    /// An envelope field parsed but violates its contract.
    #[error("vector envelope field `{field}` is invalid: {problem}")]
    EnvelopeField {
        /// Offending envelope field.
        field: &'static str,
        /// What was wrong with it.
        problem: String,
    },
    /// `kind` is not in [`KNOWN_KINDS`] — the vector predates its executor
    /// or the name is misspelled; either way it must not pass silently.
    #[error(
        "unknown vector kind `{0}` — register it in test_util::vectors before committing vectors of it"
    )]
    UnknownKind(String),
    /// The file's `format_version` disagrees with the
    /// `vectors/<format-version>/` directory it was discovered in.
    #[error(
        "vector declares format_version `{in_file}` but was discovered under version directory `{expected}` (misfiled vector)"
    )]
    FormatVersionMismatch {
        /// `format_version` as declared in the file.
        in_file: String,
        /// Version implied by the directory the file sits in.
        expected: String,
    },
    /// The kind-specific `inputs`/`expect` payload does not conform to the
    /// kind's schema.
    #[error("`{kind}` payload is malformed: {problem}")]
    Payload {
        /// Vector kind whose payload failed.
        kind: &'static str,
        /// What was wrong with it.
        problem: String,
    },
    /// The vector parsed cleanly but an expectation did not reproduce —
    /// the golden data and the implementation disagree.
    #[error("`{kind}` vector check `{check}` failed: {problem}")]
    Check {
        /// Vector kind whose execution failed.
        kind: &'static str,
        /// Which check failed.
        check: &'static str,
        /// The mismatch, in terms of public fixture data only.
        problem: String,
    },
}

/// What a successfully executed vector file verified.
#[derive(Debug, Clone)]
pub struct VectorSummary {
    /// The registered kind that executed.
    pub kind: &'static str,
    /// The file's own `description`.
    pub description: String,
    /// Number of vector entries verified (each entry = multiple byte
    /// comparisons).
    pub items: usize,
}

/// The generic envelope (schema documented in `testdata/vectors/README.md`).
/// All fields required; unknown fields rejected.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    schema: String,
    schema_version: u32,
    format_version: String,
    kind: String,
    non_secret: String,
    description: String,
    inputs: serde_json::Value,
    expect: serde_json::Value,
}

/// Parse, validate, and execute one vector file's bytes.
///
/// `expected_format_version` is the `v<n>` directory name the file was
/// discovered under; a disagreeing `format_version` field fails
/// ([`VectorError::FormatVersionMismatch`]) so misfiled vectors cannot
/// hide.
pub fn execute_vector_bytes(
    bytes: &[u8],
    expected_format_version: &str,
) -> Result<VectorSummary, VectorError> {
    let envelope: Envelope =
        serde_json::from_slice(bytes).map_err(|e| VectorError::Envelope(e.to_string()))?;
    if envelope.schema != SCHEMA {
        return Err(VectorError::EnvelopeField {
            field: "schema",
            problem: format!("expected `{SCHEMA}`, found `{}`", envelope.schema),
        });
    }
    if envelope.schema_version != SCHEMA_VERSION {
        return Err(VectorError::EnvelopeField {
            field: "schema_version",
            problem: format!(
                "this executor implements schema_version {SCHEMA_VERSION}, file declares {}",
                envelope.schema_version
            ),
        });
    }
    if !envelope.non_secret.contains(NON_SECRET_MARKER) {
        return Err(VectorError::EnvelopeField {
            field: "non_secret",
            problem: format!(
                "must contain the `{NON_SECRET_MARKER}` marker (secret-material convention, testdata/README.md)"
            ),
        });
    }
    if envelope.format_version != expected_format_version {
        return Err(VectorError::FormatVersionMismatch {
            in_file: envelope.format_version,
            expected: expected_format_version.to_owned(),
        });
    }
    match envelope.kind.as_str() {
        "hkdf-labels" => execute_hkdf_labels(envelope),
        "commitments" => execute_commitments(envelope),
        other => Err(VectorError::UnknownKind(other.to_owned())),
    }
}

/// Check that a vector file's `inputs.w` is the documented fixed test seed
/// and hand back the borrowable array (secret-material convention,
/// `testdata/README.md`): a vector derived from any other `W` is either
/// mis-generated or smuggling unknown material, and must not pass.
fn require_test_master_secret(kind: &'static str, w_hex: &str) -> Result<[u8; 32], VectorError> {
    let bytes = decode_hex(kind, "inputs.w", w_hex)?;
    let array: [u8; 32] = bytes.try_into().map_err(|_| VectorError::Check {
        kind,
        check: "w-length",
        problem: "inputs.w must be exactly 32 bytes".to_owned(),
    })?;
    if array != super::TEST_MASTER_SECRET_W {
        return Err(VectorError::Check {
            kind,
            check: "w-is-documented-test-seed",
            problem:
                "inputs.w is not the documented fixed test seed 0x00..0x1f (testdata/README.md)"
                    .to_owned(),
        });
    }
    Ok(array)
}

// ---------------------------------------------------------------------------
// kind: hkdf-labels (C3)
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct HkdfInputs {
    w: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct HkdfExpect {
    vectors: Vec<HkdfVectorEntry>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct HkdfVectorEntry {
    label: String,
    id: String,
    id_domain: String,
    info: String,
    okm: String,
}

const HKDF_KIND: &str = "hkdf-labels";

/// Execute an `hkdf-labels` vector: full label-registry coverage, then per
/// label re-encode `info` and re-derive `okm` through the typed public API
/// and byte-compare (MVP-SPEC.md line 77; tasks/C.md C3).
fn execute_hkdf_labels(envelope: Envelope) -> Result<VectorSummary, VectorError> {
    let payload_err = |problem: String| VectorError::Payload {
        kind: HKDF_KIND,
        problem,
    };
    let inputs: HkdfInputs =
        serde_json::from_value(envelope.inputs).map_err(|e| payload_err(format!("inputs: {e}")))?;
    let expect: HkdfExpect =
        serde_json::from_value(envelope.expect).map_err(|e| payload_err(format!("expect: {e}")))?;

    let w_array = require_test_master_secret(HKDF_KIND, &inputs.w)?;
    let w = MasterSecretRef::from_bytes(&w_array);

    // Full-registry coverage: exactly one vector per registered label.
    if expect.vectors.len() != Label::ALL.len() {
        return Err(VectorError::Check {
            kind: HKDF_KIND,
            check: "registry-coverage",
            problem: format!(
                "expected exactly {} vectors (one per registered label), found {}",
                Label::ALL.len(),
                expect.vectors.len()
            ),
        });
    }
    for label in Label::ALL {
        let count = expect
            .vectors
            .iter()
            .filter(|v| v.label == label.as_str())
            .count();
        if count != 1 {
            return Err(VectorError::Check {
                kind: HKDF_KIND,
                check: "registry-coverage",
                problem: format!("label `{}` appears {count} times, want 1", label.as_str()),
            });
        }
    }

    for entry in &expect.vectors {
        verify_hkdf_entry(w, entry)?;
    }

    Ok(VectorSummary {
        kind: HKDF_KIND,
        description: envelope.description,
        items: expect.vectors.len(),
    })
}

fn verify_hkdf_entry(w: MasterSecretRef<'_>, entry: &HkdfVectorEntry) -> Result<(), VectorError> {
    let check_err = |check: &'static str, problem: String| VectorError::Check {
        kind: HKDF_KIND,
        check,
        problem,
    };
    let name = entry.label.as_str();
    let label = Label::ALL
        .into_iter()
        .find(|l| l.as_str() == entry.label)
        .ok_or_else(|| check_err("label-registered", format!("unknown label `{name}`")))?;

    let id = parse_id64(name, &entry.id)?;
    let id_domain = match entry.id_domain.as_str() {
        "unit_id" => IdDomain::UnitId,
        "file_id" => IdDomain::FileId,
        "sentinel" => IdDomain::Sentinel,
        other => {
            return Err(check_err(
                "id-domain",
                format!("{name}: unknown id_domain `{other}`"),
            ));
        }
    };
    if id_domain != label.id_domain() {
        return Err(check_err(
            "id-domain",
            format!(
                "{name}: file declares {:?}, registry says {:?}",
                id_domain,
                label.id_domain()
            ),
        ));
    }
    if label.id_domain() == IdDomain::Sentinel && id != SENTINEL_ID {
        return Err(check_err(
            "sentinel-id",
            format!("{name}: sentinel-domain labels must use id 0x{SENTINEL_ID:016x}"),
        ));
    }

    // Info bytes: the encoder must reproduce the committed encoding.
    let expected_info = decode_hex(HKDF_KIND, "info", &entry.info)?;
    let actual_info = label.info_bytes(id);
    if actual_info != expected_info {
        return Err(check_err(
            "info-bytes",
            format!(
                "{name}: encoder produced {}, vector pins {}",
                hex(&actual_info),
                entry.info
            ),
        ));
    }

    // Output: length per registry, bytes per the independent reference.
    let expected_okm = decode_hex(HKDF_KIND, "okm", &entry.okm)?;
    if expected_okm.len() != label.output_len() {
        return Err(check_err(
            "okm-length",
            format!(
                "{name}: okm is {} bytes, registry output length is {}",
                expected_okm.len(),
                label.output_len()
            ),
        ));
    }
    let derived = derive_via_typed_api(w, label, id);
    if derived != expected_okm {
        return Err(check_err(
            "okm-bytes",
            format!(
                "{name}: derived {}, vector pins {}",
                hex(&derived),
                entry.okm
            ),
        ));
    }
    Ok(())
}

/// Derive through the public typed API, dispatching per label (the only
/// derivation path — there is deliberately no free-form label API).
fn derive_via_typed_api(w: MasterSecretRef<'_>, label: Label, id: u64) -> Vec<u8> {
    match label {
        Label::UnitKey => derive_unit_key(w, UnitId(id)).into_bytes().to_vec(),
        Label::UnitSalt => derive_unit_salt(w, UnitId(id)).into_bytes().to_vec(),
        Label::PathSalt => derive_path_salt(w, FileId(id)).into_bytes().to_vec(),
        // `FileSalt` is opaque by C7's disclosure rule; the byte accessor
        // for committed-vector verification exists only under `test-util`
        // (this module's own feature gate — production code has no path).
        Label::FileSalt => derive_file_salt(w, FileId(id))
            .expose_bytes_for_test_vectors()
            .to_vec(),
        Label::FineSeed => derive_fine_seed(w, FileId(id)).into_bytes().to_vec(),
        Label::SigEd25519 => derive_sig_ed25519_seed(w).into_bytes().to_vec(),
        Label::SigMlDsa65 => derive_sig_mldsa65_seed(w).into_bytes().to_vec(),
        Label::ManifestKey => derive_manifest_key(w).into_bytes().to_vec(),
    }
}

// ---------------------------------------------------------------------------
// kind: commitments (C16 / C6)
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CommitmentsInputs {
    w: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CommitmentsExpect {
    vectors: Vec<CommitmentEntry>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CommitmentEntry {
    name: String,
    commitment: String,
    domain_tag: String,
    salt_label: String,
    id: String,
    salt: String,
    message: String,
    digest: String,
}

const COMMITMENTS_KIND: &str = "commitments";

/// The four salted commitments, each with the **frozen** `(domain tag, salt
/// label)` pair the construction is defined by (MVP-SPEC.md lines 79, 93–95;
/// the module table in [`crate::crypto::commit`]).
///
/// A vector that pairs a commitment with the wrong tag or the wrong salt
/// label is mis-generated and must fail — which is why these three columns
/// are all carried in the file and all re-checked here, rather than being
/// implied by the `commitment` field alone.
const COMMITMENT_REGISTRY: [(&str, u8, Label); 4] = [
    ("unit", TAG_UNIT_COMMIT, Label::UnitSalt),
    ("raw", TAG_RAW_COMMIT, Label::FileSalt),
    ("canon", TAG_CANON_COMMIT, Label::FileSalt),
    ("path", TAG_PATH_COMMIT, Label::PathSalt),
];

/// Execute a `commitments` vector: every registered commitment kind is
/// covered, then per entry the salt is re-derived through C2's typed API,
/// the digest is recomputed through C6's public commitment function and
/// byte-compared, and the matching `verify_*_commit` accepts the same
/// inputs (MVP-SPEC.md lines 79, 93–95; tasks/C.md C16).
fn execute_commitments(envelope: Envelope) -> Result<VectorSummary, VectorError> {
    let payload_err = |problem: String| VectorError::Payload {
        kind: COMMITMENTS_KIND,
        problem,
    };
    let inputs: CommitmentsInputs =
        serde_json::from_value(envelope.inputs).map_err(|e| payload_err(format!("inputs: {e}")))?;
    let expect: CommitmentsExpect =
        serde_json::from_value(envelope.expect).map_err(|e| payload_err(format!("expect: {e}")))?;

    let w_array = require_test_master_secret(COMMITMENTS_KIND, &inputs.w)?;
    let w = MasterSecretRef::from_bytes(&w_array);

    // Registry coverage: every commitment kind must be exercised, so a
    // dropped construction cannot go unvectored.
    for (kind, _, _) in COMMITMENT_REGISTRY {
        if !expect.vectors.iter().any(|v| v.commitment == kind) {
            return Err(VectorError::Check {
                kind: COMMITMENTS_KIND,
                check: "registry-coverage",
                problem: format!("no vector covers the `{kind}` commitment"),
            });
        }
    }

    for entry in &expect.vectors {
        verify_commitment_entry(w, entry)?;
    }

    Ok(VectorSummary {
        kind: COMMITMENTS_KIND,
        description: envelope.description,
        items: expect.vectors.len(),
    })
}

fn verify_commitment_entry(
    w: MasterSecretRef<'_>,
    entry: &CommitmentEntry,
) -> Result<(), VectorError> {
    let check_err = |check: &'static str, problem: String| VectorError::Check {
        kind: COMMITMENTS_KIND,
        check,
        problem,
    };
    let name = entry.name.as_str();

    let (_, tag, salt_label) = COMMITMENT_REGISTRY
        .into_iter()
        .find(|(kind, _, _)| *kind == entry.commitment)
        .ok_or_else(|| {
            check_err(
                "commitment-registered",
                format!("{name}: unknown commitment `{}`", entry.commitment),
            )
        })?;

    // The frozen domain tag (MVP-SPEC.md line 79), pinned as its own field
    // so a tag renumbering is a vector break, not a silent re-derivation.
    if entry.domain_tag != format!("{tag:02x}") {
        return Err(check_err(
            "domain-tag",
            format!(
                "{name}: file pins tag `{}`, registry says `{tag:02x}`",
                entry.domain_tag
            ),
        ));
    }
    // The frozen salt label (MVP-SPEC.md line 95): `raw`/`canon` share
    // `file-salt`; `path` uses its own independent `path-salt`.
    if entry.salt_label != salt_label.as_str() {
        return Err(check_err(
            "salt-label",
            format!(
                "{name}: file pins salt label `{}`, registry says `{}`",
                entry.salt_label,
                salt_label.as_str()
            ),
        ));
    }

    // The salt must be C2's derivation for this (label, id) — the chain
    // from `W` to the commitment is pinned end to end, not assumed.
    let id = parse_id64_for(COMMITMENTS_KIND, name, &entry.id)?;
    let expected_salt = decode_hex(COMMITMENTS_KIND, "salt", &entry.salt)?;
    let derived_salt: [u8; 16] = match salt_label {
        Label::UnitSalt => *derive_unit_salt(w, UnitId(id)).as_bytes(),
        Label::PathSalt => *derive_path_salt(w, FileId(id)).as_bytes(),
        // `FileSalt` is opaque by C7's disclosure rule; the byte accessor
        // for committed-vector verification exists only under `test-util`.
        Label::FileSalt => *derive_file_salt(w, FileId(id)).expose_bytes_for_test_vectors(),
        other => {
            return Err(check_err(
                "salt-label",
                format!(
                    "{name}: label `{}` derives no commitment salt",
                    other.as_str()
                ),
            ));
        }
    };
    if derived_salt.as_slice() != expected_salt {
        return Err(check_err(
            "salt-bytes",
            format!(
                "{name}: derived {}, vector pins {}",
                hex(&derived_salt),
                entry.salt
            ),
        ));
    }

    // Recompute the commitment through the public C6 API and byte-compare,
    // then confirm the matching verifier accepts the very same inputs.
    let message = decode_hex(COMMITMENTS_KIND, "message", &entry.message)?;
    let expected_digest: [u8; 32] = decode_hex(COMMITMENTS_KIND, "digest", &entry.digest)?
        .try_into()
        .map_err(|_| check_err("digest-length", format!("{name}: digest must be 32 bytes")))?;

    let salt16 = Salt16::from_bytes(derived_salt);
    let file_salt = FileSalt::from_disclosed(Salt16::from_bytes(derived_salt));
    let (computed, verified) = match entry.commitment.as_str() {
        "unit" => (
            unit_commit(&salt16, &message),
            verify_unit_commit(&salt16, &message, &expected_digest),
        ),
        "raw" => (
            raw_commit(&file_salt, &message),
            verify_raw_commit(&file_salt, &message, &expected_digest),
        ),
        "canon" => (
            canon_commit(&file_salt, &message),
            verify_canon_commit(&file_salt, &message, &expected_digest),
        ),
        // `path_commit` takes `&str` by type — paths are UTF-8 by
        // construction — so a non-UTF-8 `message` is a malformed vector.
        "path" => {
            let path = core::str::from_utf8(&message).map_err(|e| {
                check_err(
                    "path-utf8",
                    format!("{name}: path message is not valid UTF-8: {e}"),
                )
            })?;
            (
                path_commit(&salt16, path),
                verify_path_commit(&salt16, path, &expected_digest),
            )
        }
        other => {
            return Err(check_err(
                "commitment-registered",
                format!("{name}: unknown commitment `{other}`"),
            ));
        }
    };

    if computed != expected_digest {
        return Err(check_err(
            "digest-bytes",
            format!(
                "{name}: computed {}, vector pins {}",
                hex(&computed),
                entry.digest
            ),
        ));
    }
    verified.map_err(|e| {
        check_err(
            "verify-accepts",
            format!("{name}: verify rejected the vector's own inputs: {e}"),
        )
    })
}

// ---------------------------------------------------------------------------
// shared field parsing (strict: canonical lowercase hex, 0x-prefixed ids)
// ---------------------------------------------------------------------------

/// Parse a `0x`-prefixed, exactly-16-digit lowercase-hex LE64 id value
/// (`testdata/vectors/README.md`) for the `hkdf-labels` kind.
fn parse_id64(context: &str, id: &str) -> Result<u64, VectorError> {
    parse_id64_for(HKDF_KIND, context, id)
}

/// [`parse_id64`], attributed to an arbitrary vector kind.
fn parse_id64_for(kind: &'static str, context: &str, id: &str) -> Result<u64, VectorError> {
    let malformed = |problem: String| VectorError::Check {
        kind,
        check: "id-encoding",
        problem,
    };
    let digits = id
        .strip_prefix("0x")
        .ok_or_else(|| malformed(format!("{context}: id `{id}` is not 0x-prefixed")))?;
    if digits.len() != 16
        || !digits
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(malformed(format!(
            "{context}: id `{id}` must be exactly 16 lowercase hex digits"
        )));
    }
    u64::from_str_radix(digits, 16).map_err(|e| malformed(format!("{context}: id `{id}`: {e}")))
}

/// Decode canonical lowercase hex (rejects uppercase and odd length —
/// committed vectors are canonical by convention).
fn decode_hex(
    kind: &'static str,
    field: &'static str,
    hex_str: &str,
) -> Result<Vec<u8>, VectorError> {
    let malformed = |problem: String| VectorError::Payload {
        kind,
        problem: format!("field `{field}`: {problem}"),
    };
    if !hex_str.len().is_multiple_of(2) {
        return Err(malformed("odd-length hex".to_owned()));
    }
    if !hex_str
        .bytes()
        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(malformed(
            "non-canonical hex (lowercase [0-9a-f] only)".to_owned(),
        ));
    }
    (0..hex_str.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&hex_str[i..i + 2], 16)
                .map_err(|e| malformed(format!("bad hex byte at offset {i}: {e}")))
        })
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    use core::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a valid `hkdf-labels` vector document from the crate's own
    /// derivations (self-consistent by construction) so tamper tests can
    /// mutate a known-good baseline without touching committed fixtures.
    fn valid_hkdf_document() -> serde_json::Value {
        let w = MasterSecretRef::from_bytes(&super::super::TEST_MASTER_SECRET_W);
        let vectors: Vec<serde_json::Value> = Label::ALL
            .into_iter()
            .map(|label| {
                let id: u64 = match label.id_domain() {
                    IdDomain::Sentinel => SENTINEL_ID,
                    IdDomain::UnitId | IdDomain::FileId => 3,
                };
                let domain = match label.id_domain() {
                    IdDomain::UnitId => "unit_id",
                    IdDomain::FileId => "file_id",
                    IdDomain::Sentinel => "sentinel",
                };
                serde_json::json!({
                    "label": label.as_str(),
                    "id": format!("0x{id:016x}"),
                    "id_domain": domain,
                    "info": hex(&label.info_bytes(id)),
                    "okm": hex(&derive_via_typed_api(w, label, id)),
                })
            })
            .collect();
        serde_json::json!({
            "schema": SCHEMA,
            "schema_version": SCHEMA_VERSION,
            "format_version": "v1",
            "kind": "hkdf-labels",
            "non_secret": "NON-SECRET synthetic self-test document",
            "description": "framework self-test",
            "inputs": { "w": hex(&super::super::TEST_MASTER_SECRET_W) },
            "expect": { "vectors": vectors },
        })
    }

    fn execute(value: &serde_json::Value) -> Result<VectorSummary, VectorError> {
        let bytes = serde_json::to_vec(value).expect("test JSON serializes");
        execute_vector_bytes(&bytes, "v1")
    }

    #[test]
    fn self_consistent_document_executes_green() {
        let summary = execute(&valid_hkdf_document()).expect("valid document must execute");
        assert_eq!(summary.kind, "hkdf-labels");
        assert_eq!(summary.items, Label::ALL.len());
    }

    #[test]
    fn invalid_json_fails_loudly() {
        let err = execute_vector_bytes(b"{ not json", "v1").expect_err("must fail");
        assert!(matches!(err, VectorError::Envelope(_)), "{err}");
    }

    #[test]
    fn unknown_envelope_field_fails_loudly() {
        let mut doc = valid_hkdf_document();
        doc["surprise"] = serde_json::json!(1);
        let err = execute(&doc).expect_err("must fail");
        assert!(matches!(err, VectorError::Envelope(_)), "{err}");
    }

    #[test]
    fn missing_envelope_field_fails_loudly() {
        let mut doc = valid_hkdf_document();
        doc.as_object_mut()
            .expect("document is an object")
            .remove("non_secret");
        let err = execute(&doc).expect_err("must fail");
        assert!(matches!(err, VectorError::Envelope(_)), "{err}");
    }

    #[test]
    fn wrong_schema_string_fails_loudly() {
        let mut doc = valid_hkdf_document();
        doc["schema"] = serde_json::json!("somebody-elses-vector");
        let err = execute(&doc).expect_err("must fail");
        assert!(
            matches!(
                err,
                VectorError::EnvelopeField {
                    field: "schema",
                    ..
                }
            ),
            "{err}"
        );
    }

    #[test]
    fn wrong_schema_version_fails_loudly() {
        let mut doc = valid_hkdf_document();
        doc["schema_version"] = serde_json::json!(2);
        let err = execute(&doc).expect_err("must fail");
        assert!(
            matches!(
                err,
                VectorError::EnvelopeField {
                    field: "schema_version",
                    ..
                }
            ),
            "{err}"
        );
    }

    #[test]
    fn missing_non_secret_marker_fails_loudly() {
        let mut doc = valid_hkdf_document();
        doc["non_secret"] = serde_json::json!("totally fine, trust me");
        let err = execute(&doc).expect_err("must fail");
        assert!(
            matches!(
                err,
                VectorError::EnvelopeField {
                    field: "non_secret",
                    ..
                }
            ),
            "{err}"
        );
    }

    #[test]
    fn format_version_mismatch_fails_loudly() {
        let mut doc = valid_hkdf_document();
        doc["format_version"] = serde_json::json!("v2");
        let err = execute(&doc).expect_err("must fail");
        assert!(
            matches!(err, VectorError::FormatVersionMismatch { .. }),
            "{err}"
        );
    }

    #[test]
    fn unknown_kind_fails_loudly() {
        let mut doc = valid_hkdf_document();
        doc["kind"] = serde_json::json!("quantum-labels");
        let err = execute(&doc).expect_err("must fail");
        assert!(matches!(err, VectorError::UnknownKind(_)), "{err}");
    }

    #[test]
    fn tampered_okm_fails_loudly() {
        let mut doc = valid_hkdf_document();
        let okm = doc["expect"]["vectors"][0]["okm"]
            .as_str()
            .expect("okm is a string")
            .to_owned();
        // Flip the final hex digit to a different valid lowercase digit.
        let mut flipped = okm.clone();
        let last = flipped.pop().expect("okm non-empty");
        flipped.push(if last == '0' { '1' } else { '0' });
        doc["expect"]["vectors"][0]["okm"] = serde_json::json!(flipped);
        let err = execute(&doc).expect_err("must fail");
        assert!(
            matches!(
                err,
                VectorError::Check {
                    check: "okm-bytes",
                    ..
                }
            ),
            "{err}"
        );
    }

    #[test]
    fn tampered_info_fails_loudly() {
        let mut doc = valid_hkdf_document();
        let info = doc["expect"]["vectors"][0]["info"]
            .as_str()
            .expect("info is a string")
            .to_owned();
        let mut flipped = info.clone();
        let last = flipped.pop().expect("info non-empty");
        flipped.push(if last == '0' { '1' } else { '0' });
        doc["expect"]["vectors"][0]["info"] = serde_json::json!(flipped);
        let err = execute(&doc).expect_err("must fail");
        assert!(
            matches!(
                err,
                VectorError::Check {
                    check: "info-bytes",
                    ..
                }
            ),
            "{err}"
        );
    }

    #[test]
    fn wrong_master_secret_fails_loudly() {
        let mut doc = valid_hkdf_document();
        // A W that is not the documented fixed test seed must be rejected
        // even if internally self-consistent (secret-material convention).
        doc["inputs"]["w"] = serde_json::json!(hex(&[0xAB; 32]));
        let err = execute(&doc).expect_err("must fail");
        assert!(
            matches!(
                err,
                VectorError::Check {
                    check: "w-is-documented-test-seed",
                    ..
                }
            ),
            "{err}"
        );
    }

    #[test]
    fn dropped_label_fails_registry_coverage() {
        let mut doc = valid_hkdf_document();
        doc["expect"]["vectors"]
            .as_array_mut()
            .expect("vectors is an array")
            .pop();
        let err = execute(&doc).expect_err("must fail");
        assert!(
            matches!(
                err,
                VectorError::Check {
                    check: "registry-coverage",
                    ..
                }
            ),
            "{err}"
        );
    }

    // -----------------------------------------------------------------
    // kind: commitments — tests-of-the-test
    //
    // These mutate a *synthetic* baseline built from the crate's own
    // derivations (self-consistent by construction), never the committed
    // fixtures, so they prove the executor is load-bearing: every field it
    // claims to check must be able to fail the run.
    // -----------------------------------------------------------------

    /// Build a valid `commitments` document covering all four kinds.
    fn valid_commitments_document() -> serde_json::Value {
        let w = MasterSecretRef::from_bytes(&super::super::TEST_MASTER_SECRET_W);
        let message: &[u8] = b"vector executor self-test message";
        let path = "docs/self-test.md";
        let unit_salt = derive_unit_salt(w, UnitId(1));
        let path_salt = derive_path_salt(w, FileId(2));
        let file_salt = derive_file_salt(w, FileId(2));
        let file_salt16 = Salt16::from_bytes(*file_salt.expose_bytes_for_test_vectors());

        let entries = [
            (
                "unit",
                "02",
                "unit-salt",
                1u64,
                *unit_salt.as_bytes(),
                message.to_vec(),
                unit_commit(&unit_salt, message),
            ),
            (
                "raw",
                "03",
                "file-salt",
                2,
                *file_salt16.as_bytes(),
                message.to_vec(),
                raw_commit(&file_salt, message),
            ),
            (
                "canon",
                "04",
                "file-salt",
                2,
                *file_salt16.as_bytes(),
                message.to_vec(),
                canon_commit(&file_salt, message),
            ),
            (
                "path",
                "05",
                "path-salt",
                2,
                *path_salt.as_bytes(),
                path.as_bytes().to_vec(),
                path_commit(&path_salt, path),
            ),
        ];

        let vectors: Vec<serde_json::Value> = entries
            .iter()
            .map(|(kind, tag, label, id, salt, msg, digest)| {
                serde_json::json!({
                    "name": format!("self-test-{kind}"),
                    "commitment": kind,
                    "domain_tag": tag,
                    "salt_label": label,
                    "id": format!("0x{id:016x}"),
                    "salt": hex(salt),
                    "message": hex(msg),
                    "digest": hex(digest),
                })
            })
            .collect();

        serde_json::json!({
            "schema": SCHEMA,
            "schema_version": SCHEMA_VERSION,
            "format_version": "v1",
            "kind": "commitments",
            "non_secret": "NON-SECRET synthetic self-test document",
            "description": "framework self-test",
            "inputs": { "w": hex(&super::super::TEST_MASTER_SECRET_W) },
            "expect": { "vectors": vectors },
        })
    }

    #[test]
    fn self_consistent_commitments_document_executes_green() {
        let summary = execute(&valid_commitments_document()).expect("valid document must execute");
        assert_eq!(summary.kind, "commitments");
        assert_eq!(summary.items, 4);
    }

    #[test]
    fn tampered_commitment_digest_fails_loudly() {
        let mut doc = valid_commitments_document();
        let digest = doc["expect"]["vectors"][0]["digest"]
            .as_str()
            .expect("digest is a string")
            .to_owned();
        let mut flipped = digest;
        let last = flipped.pop().expect("digest non-empty");
        flipped.push(if last == '0' { '1' } else { '0' });
        doc["expect"]["vectors"][0]["digest"] = serde_json::json!(flipped);
        let err = execute(&doc).expect_err("must fail");
        assert!(
            matches!(
                err,
                VectorError::Check {
                    check: "digest-bytes",
                    ..
                }
            ),
            "{err}"
        );
    }

    /// A salt that is not C2's derivation for the entry's `(label, id)`
    /// breaks the W→salt→commitment chain and must fail — even though the
    /// digest would still be self-consistent with it if the executor
    /// merely re-hashed the file's own salt.
    #[test]
    fn tampered_commitment_salt_fails_loudly() {
        let mut doc = valid_commitments_document();
        doc["expect"]["vectors"][0]["salt"] = serde_json::json!(hex(&[0xABu8; 16]));
        let err = execute(&doc).expect_err("must fail");
        assert!(
            matches!(
                err,
                VectorError::Check {
                    check: "salt-bytes",
                    ..
                }
            ),
            "{err}"
        );
    }

    /// The frozen domain tag is pinned as its own field (MVP-SPEC.md line
    /// 79): a renumbering must break the vector, not be re-derived from it.
    #[test]
    fn wrong_domain_tag_fails_loudly() {
        let mut doc = valid_commitments_document();
        doc["expect"]["vectors"][0]["domain_tag"] = serde_json::json!("03");
        let err = execute(&doc).expect_err("must fail");
        assert!(
            matches!(
                err,
                VectorError::Check {
                    check: "domain-tag",
                    ..
                }
            ),
            "{err}"
        );
    }

    /// `path_commit` must use `path-salt`, never the content `file-salt`
    /// (MVP-SPEC.md line 95: the two salts are independent so a path reveal
    /// discloses nothing content-side).
    #[test]
    fn wrong_salt_label_fails_loudly() {
        let mut doc = valid_commitments_document();
        doc["expect"]["vectors"][3]["salt_label"] = serde_json::json!("file-salt");
        let err = execute(&doc).expect_err("must fail");
        assert!(
            matches!(
                err,
                VectorError::Check {
                    check: "salt-label",
                    ..
                }
            ),
            "{err}"
        );
    }

    #[test]
    fn dropped_commitment_kind_fails_registry_coverage() {
        let mut doc = valid_commitments_document();
        doc["expect"]["vectors"]
            .as_array_mut()
            .expect("vectors is an array")
            .pop();
        let err = execute(&doc).expect_err("must fail");
        assert!(
            matches!(
                err,
                VectorError::Check {
                    check: "registry-coverage",
                    ..
                }
            ),
            "{err}"
        );
    }

    /// Defensive parsing: a `path` entry whose message is not valid UTF-8
    /// is a malformed vector, not a panic (`path_commit` takes `&str`).
    #[test]
    fn non_utf8_path_message_fails_loudly() {
        let mut doc = valid_commitments_document();
        doc["expect"]["vectors"][3]["message"] = serde_json::json!("ff");
        let err = execute(&doc).expect_err("must fail");
        assert!(
            matches!(
                err,
                VectorError::Check {
                    check: "path-utf8",
                    ..
                }
            ),
            "{err}"
        );
    }

    #[test]
    fn commitments_document_with_wrong_master_secret_fails_loudly() {
        let mut doc = valid_commitments_document();
        doc["inputs"]["w"] = serde_json::json!(hex(&[0xABu8; 32]));
        let err = execute(&doc).expect_err("must fail");
        assert!(
            matches!(
                err,
                VectorError::Check {
                    check: "w-is-documented-test-seed",
                    ..
                }
            ),
            "{err}"
        );
    }

    #[test]
    fn uppercase_hex_is_rejected_as_non_canonical() {
        let mut doc = valid_hkdf_document();
        let okm = doc["expect"]["vectors"][0]["okm"]
            .as_str()
            .expect("okm is a string")
            .to_uppercase();
        doc["expect"]["vectors"][0]["okm"] = serde_json::json!(okm);
        let err = execute(&doc).expect_err("must fail");
        assert!(matches!(err, VectorError::Payload { .. }), "{err}");
    }
}
