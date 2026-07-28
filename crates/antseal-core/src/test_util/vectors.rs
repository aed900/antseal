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
use sha2::{Digest, Sha256};

use crate::crypto::hkdf::{
    FileId, IdDomain, Label, SENTINEL_ID, UnitId, derive_file_salt, derive_fine_seed,
    derive_manifest_key, derive_path_salt, derive_sig_ed25519_seed, derive_sig_mldsa65_seed,
    derive_unit_key, derive_unit_salt,
};
use crate::crypto::material::MasterSecretRef;

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
pub const KNOWN_KINDS: &[&str] = &["hkdf-labels", super::vectors_sig_reject::KIND];

/// Domain prefix of the **recomputed-artifact digest** ([`VectorSummary::
/// recomputed_digest`]).
///
/// This is a *harness* digest, not a format commitment: it exists so the Q5
/// native↔WASM lane can byte-compare every value the executor recomputed,
/// not merely the pass/fail verdict. It deliberately does **not** use
/// [`crate::crypto::domain::tagged_sha256`] and its long ASCII prefix cannot
/// collide with the single-byte tags of the C1 domain-tag registry
/// (MVP-SPEC.md line 79) — nothing here is ever hashed into a manifest,
/// bundle, or signature preimage.
pub(super) const RECOMPUTED_DIGEST_DOMAIN: &[u8] = b"antseal/test-util/vectors/recomputed/v0\x00";

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
    /// SHA-256 over **every byte this execution recomputed**, in a
    /// length-prefixed, domain-separated stream (see
    /// [`RECOMPUTED_DIGEST_DOMAIN`]).
    ///
    /// The Q5 native↔WASM bit-match compares this digest, so a platform
    /// divergence anywhere in the recomputation is caught even where it does
    /// not (yet) change a pass/fail verdict — that is Q5's "report bytes
    /// **plus recomputed digests**" requirement. Only the digest is ever
    /// surfaced; the recomputed key material itself never leaves the
    /// executor (project rule 6).
    pub recomputed_digest: [u8; 32],
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
        // C15's reject-vector suites; executor in a sibling module so this
        // dispatch stays a one-liner per kind.
        super::vectors_sig_reject::KIND => super::vectors_sig_reject::execute(
            envelope.inputs,
            envelope.expect,
            envelope.description,
        ),
        other => Err(VectorError::UnknownKind(other.to_owned())),
    }
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

    // The fixture master secret must be the documented fixed test seed
    // (secret-material convention): a vector derived from any other W is
    // either mis-generated or smuggling unknown material.
    let w_bytes = decode_hex(HKDF_KIND, "inputs.w", &inputs.w)?;
    let w_array: [u8; 32] = w_bytes.try_into().map_err(|_| VectorError::Check {
        kind: HKDF_KIND,
        check: "w-length",
        problem: "inputs.w must be exactly 32 bytes".to_owned(),
    })?;
    if w_array != super::TEST_MASTER_SECRET_W {
        return Err(VectorError::Check {
            kind: HKDF_KIND,
            check: "w-is-documented-test-seed",
            problem:
                "inputs.w is not the documented fixed test seed 0x00..0x1f (testdata/README.md)"
                    .to_owned(),
        });
    }
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

    // Accumulates every recomputed artifact, in file order, for the Q5
    // bit-match (see `VectorSummary::recomputed_digest`).
    let mut recomputed = Sha256::new();
    recomputed.update(RECOMPUTED_DIGEST_DOMAIN);
    recomputed.update(HKDF_KIND.as_bytes());
    recomputed.update([0x00]);
    for entry in &expect.vectors {
        verify_hkdf_entry(w, entry, &mut recomputed)?;
    }

    Ok(VectorSummary {
        kind: HKDF_KIND,
        description: envelope.description,
        items: expect.vectors.len(),
        recomputed_digest: recomputed.finalize().into(),
    })
}

fn verify_hkdf_entry(
    w: MasterSecretRef<'_>,
    entry: &HkdfVectorEntry,
    recomputed: &mut Sha256,
) -> Result<(), VectorError> {
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

    // Length-prefixed so no two distinct recomputations can produce the same
    // stream; little-endian and fixed-width so the digest is identical on
    // every target (that is the whole point — Q5 byte-compares it native vs
    // wasm32).
    recomputed.update(label.as_str().as_bytes());
    recomputed.update([0x00]);
    recomputed.update(id.to_le_bytes());
    recomputed.update(prefix_len(actual_info.len()));
    recomputed.update(&actual_info);
    recomputed.update(prefix_len(derived.len()));
    recomputed.update(&derived);
    Ok(())
}

/// 8-byte little-endian length prefix (never panics; `u64` covers every
/// possible in-memory length on both 32- and 64-bit targets).
pub(super) fn prefix_len(len: usize) -> [u8; 8] {
    (len as u64).to_le_bytes()
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
// shared field parsing (strict: canonical lowercase hex, 0x-prefixed ids)
// ---------------------------------------------------------------------------

/// Parse a `0x`-prefixed, exactly-16-digit lowercase-hex LE64 id value
/// (`testdata/vectors/README.md`).
fn parse_id64(context: &str, id: &str) -> Result<u64, VectorError> {
    let malformed = |problem: String| VectorError::Check {
        kind: HKDF_KIND,
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
/// committed vectors are canonical by convention). Shared with the sibling
/// kind executors so hex parsing cannot fork per kind.
pub(super) fn decode_hex(
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

/// Canonical lowercase hex rendering (shared with the sibling kind
/// executors, as [`decode_hex`] is).
pub(super) fn hex(bytes: &[u8]) -> String {
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

    /// Same as [`valid_hkdf_document`] but with every non-sentinel id set to
    /// `id`, so the recomputed artifacts genuinely differ.
    fn valid_hkdf_document_with_id(id: u64) -> serde_json::Value {
        let w = MasterSecretRef::from_bytes(&super::super::TEST_MASTER_SECRET_W);
        let vectors: Vec<serde_json::Value> = Label::ALL
            .into_iter()
            .map(|label| {
                let id: u64 = match label.id_domain() {
                    IdDomain::Sentinel => SENTINEL_ID,
                    IdDomain::UnitId | IdDomain::FileId => id,
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
        let mut doc = valid_hkdf_document();
        doc["expect"]["vectors"] = serde_json::json!(vectors);
        doc
    }

    #[test]
    fn self_consistent_document_executes_green() {
        let summary = execute(&valid_hkdf_document()).expect("valid document must execute");
        assert_eq!(summary.kind, "hkdf-labels");
        assert_eq!(summary.items, Label::ALL.len());
    }

    /// The Q5 bit-match medium: the digest must be a deterministic function
    /// of what was recomputed — stable across runs, and different when any
    /// recomputed artifact differs.
    #[test]
    fn recomputed_digest_is_deterministic_and_covers_the_recomputation() {
        let doc = valid_hkdf_document();
        let first = execute(&doc).expect("valid document").recomputed_digest;
        let second = execute(&doc).expect("valid document").recomputed_digest;
        assert_eq!(first, second, "digest must be deterministic");
        assert_ne!(first, [0u8; 32], "digest must actually be computed");

        let other = execute(&valid_hkdf_document_with_id(4))
            .expect("valid document")
            .recomputed_digest;
        assert_ne!(
            first, other,
            "a different id changes every info/okm, so the digest must change"
        );
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
