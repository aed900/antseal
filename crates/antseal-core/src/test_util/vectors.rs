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
use crate::crypto::manifest_aead::{
    MANIFEST_AAD, ManifestKey, decrypt_manifest, decrypt_manifest_with_key,
};
use crate::crypto::material::{FileSalt, MasterSecretRef, Salt16};
use crate::crypto::padding::{PAD_BLOCK, apply_padding, padded_length};
use crate::crypto::secrets::SealId;
use crate::crypto::sig_policy::{PolicyLabel, SigPolicy};
use crate::crypto::unit_aead::{Nonce24, UnitKey, decrypt_unit, decrypt_unit_with_key, unit_aad};
use crate::crypto::{SIG_CONTEXT, error::SigAlg, sig_ed25519, sig_mldsa, sig_policy};

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
pub const KNOWN_KINDS: &[&str] = &[
    "hkdf-labels",
    "commitments",
    "unit-aead",
    "manifest-aead",
    "signatures",
    super::vectors_sig_reject::KIND,
    super::vectors_fine_tree::KIND,
    super::vectors_content_model::KIND,
    super::vectors_report::KIND,
    super::vectors_manifest::KIND,
    super::vectors_bundle::KIND,
    super::vectors_storage_address::KIND,
];

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
        "commitments" => execute_commitments(envelope),
        "unit-aead" => execute_unit_aead(envelope),
        "manifest-aead" => execute_manifest_aead(envelope),
        "signatures" => execute_signatures(envelope),
        // C15's reject-vector suites; executor in a sibling module so this
        // dispatch stays a one-liner per kind.
        super::vectors_sig_reject::KIND => super::vectors_sig_reject::execute(
            envelope.inputs,
            envelope.expect,
            envelope.description,
        ),
        // G15's fine-tree/GGM vectors; executor in a sibling module for the
        // same reason.
        super::vectors_fine_tree::KIND => super::vectors_fine_tree::execute(
            envelope.inputs,
            envelope.expect,
            envelope.description,
        ),
        // G21's content-model vectors: the seal-side assembly's derived
        // values (descriptors, work-global ids, tilings, mirrors,
        // `fine_root`s) as a committed FILE, so the Q5 bit-match sees them.
        super::vectors_content_model::KIND => super::vectors_content_model::execute(
            envelope.inputs,
            envelope.expect,
            envelope.description,
        ),
        // R9's verification-report vectors: canonical bundles -> expected
        // report bytes, the native<->WASM bit-match medium.
        super::vectors_report::KIND => {
            super::vectors_report::execute(envelope.inputs, envelope.expect, envelope.description)
        }
        // F12's manifest bytes + diagnostic sidecars + work_id/anchor_digest.
        super::vectors_manifest::KIND => {
            super::vectors_manifest::execute(envelope.inputs, envelope.expect, envelope.description)
        }
        // F13's `.sealproof` bytes, three-layer sidecars and reveal
        // structure — including the empty-anchor (UNANCHORED) bundle.
        super::vectors_bundle::KIND => {
            super::vectors_bundle::execute(envelope.inputs, envelope.expect, envelope.description)
        }
        // S4's storage-address rule (D32): BLAKE3-256 addresses over the
        // size ladder, cap+1 committed as a rejection.
        super::vectors_storage_address::KIND => super::vectors_storage_address::execute(
            envelope.inputs,
            envelope.expect,
            envelope.description,
        ),
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

    let mut recomputed = Sha256::new();
    recomputed.update(RECOMPUTED_DIGEST_DOMAIN);
    recomputed.update(COMMITMENTS_KIND.as_bytes());
    recomputed.update([0x00]);
    for entry in &expect.vectors {
        verify_commitment_entry(w, entry, &mut recomputed)?;
    }

    Ok(VectorSummary {
        kind: COMMITMENTS_KIND,
        description: envelope.description,
        items: expect.vectors.len(),
        recomputed_digest: recomputed.finalize().into(),
    })
}

fn verify_commitment_entry(
    w: MasterSecretRef<'_>,
    entry: &CommitmentEntry,
    recomputed: &mut Sha256,
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
    // Q5 bit-match: the salt this run derived and the digest it computed.
    recomputed.update(name.as_bytes());
    recomputed.update([0x00]);
    recomputed.update(prefix_len(derived_salt.len()));
    recomputed.update(derived_salt);
    recomputed.update(prefix_len(computed.len()));
    recomputed.update(computed);

    verified.map_err(|e| {
        check_err(
            "verify-accepts",
            format!("{name}: verify rejected the vector's own inputs: {e}"),
        )
    })
}

// ---------------------------------------------------------------------------
// kind: unit-aead (C16 / C8 + C9)
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct UnitAeadInputs {
    w: String,
    seal_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct UnitAeadExpect {
    vectors: Vec<UnitAeadEntry>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct UnitAeadEntry {
    name: String,
    unit_id: String,
    true_length: usize,
    unit_bytes: String,
    k_u: String,
    aad: String,
    padded_plaintext: String,
    nonce: String,
    ciphertext: String,
}

const UNIT_AEAD_KIND: &str = "unit-aead";

/// XChaCha20-Poly1305 tag length, in bytes.
const AEAD_TAG_LEN: usize = 16;

/// Execute a `unit-aead` vector (MVP-SPEC.md line 91; tasks/C.md C16).
///
/// # Why pinning the *decrypt* direction pins the ciphertext exactly
///
/// [`encrypt_unit`](crate::crypto::unit_aead::encrypt_unit) deliberately
/// exposes no way to supply a nonce — the `(k_u, nonce)` single-use
/// invariant is structural — so a committed vector cannot simply call the
/// encryptor and compare. It does not need to: AEAD encryption is a
/// *deterministic function* of `(key, nonce, aad, plaintext)`, and
/// XChaCha20-Poly1305 is injective in the plaintext for a fixed triple
/// (the ciphertext body is the keystream XOR, the tag is then determined).
/// So a ciphertext that authenticates back to the pinned plaintext under
/// the pinned `(k_u, nonce, aad)` **is** the ciphertext antseal would have
/// produced, byte for byte. The independent implementation ran the encrypt
/// direction; this runs the decrypt direction; agreement is exact.
fn execute_unit_aead(envelope: Envelope) -> Result<VectorSummary, VectorError> {
    let payload_err = |problem: String| VectorError::Payload {
        kind: UNIT_AEAD_KIND,
        problem,
    };
    let inputs: UnitAeadInputs =
        serde_json::from_value(envelope.inputs).map_err(|e| payload_err(format!("inputs: {e}")))?;
    let expect: UnitAeadExpect =
        serde_json::from_value(envelope.expect).map_err(|e| payload_err(format!("expect: {e}")))?;

    let w_array = require_test_master_secret(UNIT_AEAD_KIND, &inputs.w)?;
    let w = MasterSecretRef::from_bytes(&w_array);
    let seal_id = SealId::from_bytes(decode_hex_array::<{ SealId::LEN }>(
        UNIT_AEAD_KIND,
        "inputs.seal_id",
        &inputs.seal_id,
    )?);

    // The C16-mandated boundary cases must be present, so the two lengths
    // the padding formula is most easily got wrong on cannot go unvectored.
    if !expect.vectors.iter().any(|v| v.true_length == 0) {
        return Err(VectorError::Check {
            kind: UNIT_AEAD_KIND,
            check: "boundary-coverage",
            problem: "no vector covers the empty unit (true_length 0 → 256-B plaintext)".to_owned(),
        });
    }
    if !expect
        .vectors
        .iter()
        .any(|v| v.true_length > 0 && v.true_length.is_multiple_of(PAD_BLOCK))
    {
        return Err(VectorError::Check {
            kind: UNIT_AEAD_KIND,
            check: "boundary-coverage",
            problem: "no vector covers a 256-aligned unit".to_owned(),
        });
    }

    let mut recomputed = Sha256::new();
    recomputed.update(RECOMPUTED_DIGEST_DOMAIN);
    recomputed.update(UNIT_AEAD_KIND.as_bytes());
    recomputed.update([0x00]);
    for entry in &expect.vectors {
        verify_unit_aead_entry(w, &seal_id, entry, &mut recomputed)?;
    }

    Ok(VectorSummary {
        kind: UNIT_AEAD_KIND,
        description: envelope.description,
        items: expect.vectors.len(),
        recomputed_digest: recomputed.finalize().into(),
    })
}

fn verify_unit_aead_entry(
    w: MasterSecretRef<'_>,
    seal_id: &SealId,
    entry: &UnitAeadEntry,
    recomputed: &mut Sha256,
) -> Result<(), VectorError> {
    let check_err = |check: &'static str, problem: String| VectorError::Check {
        kind: UNIT_AEAD_KIND,
        check,
        problem,
    };
    let name = entry.name.as_str();

    let unit_id = UnitId(parse_id64_for(UNIT_AEAD_KIND, name, &entry.unit_id)?);
    let unit_bytes = decode_hex(UNIT_AEAD_KIND, "unit_bytes", &entry.unit_bytes)?;
    if unit_bytes.len() != entry.true_length {
        return Err(check_err(
            "true-length",
            format!(
                "{name}: true_length {} but unit_bytes is {} bytes",
                entry.true_length,
                unit_bytes.len()
            ),
        ));
    }

    // k_u = HKDF(W, "unit-key", unit_id) — the chain from W is pinned.
    let k_u: UnitKey = derive_unit_key(w, unit_id);
    let expected_k_u = decode_hex(UNIT_AEAD_KIND, "k_u", &entry.k_u)?;
    if k_u.as_bytes().as_slice() != expected_k_u {
        return Err(check_err(
            "unit-key-bytes",
            format!(
                "{name}: derived {}, vector pins {}",
                hex(k_u.as_bytes()),
                entry.k_u
            ),
        ));
    }

    // AAD = seal_id ‖ LE64(unit_id), 24 bytes.
    let aad = unit_aad(seal_id, unit_id);
    let expected_aad = decode_hex(UNIT_AEAD_KIND, "aad", &entry.aad)?;
    if aad.as_slice() != expected_aad {
        return Err(check_err(
            "aad-bytes",
            format!("{name}: computed {}, vector pins {}", hex(&aad), entry.aad),
        ));
    }

    // The C8 padded plaintext, byte-exact (not merely the right length).
    let padded = apply_padding(&unit_bytes);
    let expected_padded = decode_hex(UNIT_AEAD_KIND, "padded_plaintext", &entry.padded_plaintext)?;
    if padded != expected_padded {
        return Err(check_err(
            "padded-plaintext",
            format!(
                "{name}: padded to {} bytes, vector pins {} bytes (or the fill differs)",
                padded.len(),
                expected_padded.len()
            ),
        ));
    }
    if padded.len() != padded_length(entry.true_length) {
        return Err(check_err(
            "padded-length-formula",
            format!(
                "{name}: padded_length({}) is {}, padded plaintext is {}",
                entry.true_length,
                padded_length(entry.true_length),
                padded.len()
            ),
        ));
    }

    // The ciphertext: exact length, then authenticated decryption back to
    // the pinned plaintext (which pins its bytes — see the executor docs).
    let nonce = Nonce24::from_bytes(decode_hex_array::<{ Nonce24::LEN }>(
        UNIT_AEAD_KIND,
        "nonce",
        &entry.nonce,
    )?);
    let ciphertext = decode_hex(UNIT_AEAD_KIND, "ciphertext", &entry.ciphertext)?;
    if ciphertext.len() != padded.len() + AEAD_TAG_LEN {
        return Err(check_err(
            "ciphertext-length",
            format!(
                "{name}: ciphertext is {} bytes, want padded {} + tag {AEAD_TAG_LEN}",
                ciphertext.len(),
                padded.len()
            ),
        ));
    }

    // Key-direct path (the verifier-side seam: a bundle supplies k_u, the
    // verifier never holds W — spec line 114).
    let via_key = decrypt_unit_with_key(
        &k_u,
        seal_id,
        unit_id,
        &nonce,
        &ciphertext,
        entry.true_length,
    )
    .map_err(|e| check_err("decrypt-with-key", format!("{name}: {e}")))?;
    if via_key != unit_bytes {
        return Err(check_err(
            "plaintext-bytes",
            format!("{name}: decrypted plaintext does not equal the pinned unit_bytes"),
        ));
    }
    // W path (sealer-side restore/preview) — same implementation by
    // delegation; running both pins that the delegation is real.
    let via_w = decrypt_unit(w, seal_id, unit_id, &nonce, &ciphertext, entry.true_length)
        .map_err(|e| check_err("decrypt-with-w", format!("{name}: {e}")))?;
    if via_w != unit_bytes {
        return Err(check_err(
            "plaintext-bytes",
            format!("{name}: the W path decrypted differently from the key-direct path"),
        ));
    }

    // Q5 bit-match: the key, AAD and padded plaintext this run derived, and
    // the plaintext it decrypted back out.
    recomputed.update(name.as_bytes());
    recomputed.update([0x00]);
    recomputed.update(prefix_len(k_u.as_bytes().len()));
    recomputed.update(k_u.as_bytes());
    recomputed.update(prefix_len(aad.len()));
    recomputed.update(aad);
    recomputed.update(prefix_len(padded.len()));
    recomputed.update(&padded);
    recomputed.update(prefix_len(via_key.len()));
    recomputed.update(&via_key);

    Ok(())
}

// ---------------------------------------------------------------------------
// kind: manifest-aead (C16 / C10)
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ManifestAeadInputs {
    w: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ManifestAeadExpect {
    k_m: String,
    vectors: Vec<ManifestAeadEntry>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ManifestAeadEntry {
    name: String,
    manifest_bytes: String,
    aad: String,
    nonce: String,
    blob: String,
}

const MANIFEST_AEAD_KIND: &str = "manifest-aead";

/// Execute a `manifest-aead` vector (MVP-SPEC.md line 98; tasks/C.md C16).
///
/// Pins the sentinel-id `k_m` derivation, the **frozen empty AAD**, and the
/// blob bytes (by the same decrypt-direction argument as
/// [`execute_unit_aead`]). Every entry's `aad` field must be the empty
/// string *and* [`MANIFEST_AAD`] must itself be empty: the vector would
/// otherwise still pass if the constant ever grew a value, since the
/// generator and the implementation would simply be wrong together.
fn execute_manifest_aead(envelope: Envelope) -> Result<VectorSummary, VectorError> {
    let payload_err = |problem: String| VectorError::Payload {
        kind: MANIFEST_AEAD_KIND,
        problem,
    };
    let inputs: ManifestAeadInputs =
        serde_json::from_value(envelope.inputs).map_err(|e| payload_err(format!("inputs: {e}")))?;
    let expect: ManifestAeadExpect =
        serde_json::from_value(envelope.expect).map_err(|e| payload_err(format!("expect: {e}")))?;

    let w_array = require_test_master_secret(MANIFEST_AEAD_KIND, &inputs.w)?;
    let w = MasterSecretRef::from_bytes(&w_array);

    // The frozen empty AAD, asserted against the constant itself.
    if !MANIFEST_AAD.is_empty() {
        return Err(VectorError::Check {
            kind: MANIFEST_AEAD_KIND,
            check: "manifest-aad-is-empty",
            problem: "MANIFEST_AAD is no longer empty — that is a format event (spec line 98)"
                .to_owned(),
        });
    }

    // k_m = HKDF(W, "manifest-key", sentinel) — work-global, sentinel id.
    let k_m: ManifestKey = derive_manifest_key(w);
    let expected_k_m = decode_hex(MANIFEST_AEAD_KIND, "k_m", &expect.k_m)?;
    if k_m.as_bytes().as_slice() != expected_k_m {
        return Err(VectorError::Check {
            kind: MANIFEST_AEAD_KIND,
            check: "manifest-key-bytes",
            problem: format!(
                "derived {}, vector pins {}",
                hex(k_m.as_bytes()),
                expect.k_m
            ),
        });
    }

    let mut recomputed = Sha256::new();
    recomputed.update(RECOMPUTED_DIGEST_DOMAIN);
    recomputed.update(MANIFEST_AEAD_KIND.as_bytes());
    recomputed.update([0x00]);
    for entry in &expect.vectors {
        verify_manifest_aead_entry(w, &k_m, entry, &mut recomputed)?;
    }

    Ok(VectorSummary {
        kind: MANIFEST_AEAD_KIND,
        description: envelope.description,
        items: expect.vectors.len(),
        recomputed_digest: recomputed.finalize().into(),
    })
}

fn verify_manifest_aead_entry(
    w: MasterSecretRef<'_>,
    k_m: &ManifestKey,
    entry: &ManifestAeadEntry,
    recomputed: &mut Sha256,
) -> Result<(), VectorError> {
    let check_err = |check: &'static str, problem: String| VectorError::Check {
        kind: MANIFEST_AEAD_KIND,
        check,
        problem,
    };
    let name = entry.name.as_str();

    if !entry.aad.is_empty() {
        return Err(check_err(
            "empty-aad",
            format!(
                "{name}: aad is `{}`, but the manifest AAD is frozen empty (spec line 98)",
                entry.aad
            ),
        ));
    }

    let manifest_bytes = decode_hex(MANIFEST_AEAD_KIND, "manifest_bytes", &entry.manifest_bytes)?;
    let nonce = Nonce24::from_bytes(decode_hex_array::<{ Nonce24::LEN }>(
        MANIFEST_AEAD_KIND,
        "nonce",
        &entry.nonce,
    )?);
    let blob = decode_hex(MANIFEST_AEAD_KIND, "blob", &entry.blob)?;
    if blob.len() != manifest_bytes.len() + AEAD_TAG_LEN {
        return Err(check_err(
            "blob-length",
            format!(
                "{name}: blob is {} bytes, want plaintext {} + tag {AEAD_TAG_LEN}",
                blob.len(),
                manifest_bytes.len()
            ),
        ));
    }

    // Key-direct path (the bundle-side persistence check) and the W path.
    let via_key = decrypt_manifest_with_key(k_m, &nonce, &blob)
        .map_err(|e| check_err("decrypt-with-key", format!("{name}: {e}")))?;
    if via_key != manifest_bytes {
        return Err(check_err(
            "plaintext-bytes",
            format!("{name}: decrypted blob does not equal the pinned manifest_bytes"),
        ));
    }
    let via_w = decrypt_manifest(w, &nonce, &blob)
        .map_err(|e| check_err("decrypt-with-w", format!("{name}: {e}")))?;
    if via_w != manifest_bytes {
        return Err(check_err(
            "plaintext-bytes",
            format!("{name}: the W path decrypted differently from the key-direct path"),
        ));
    }

    // Q5 bit-match: the manifest bytes this run decrypted back out.
    recomputed.update(name.as_bytes());
    recomputed.update([0x00]);
    recomputed.update(prefix_len(via_key.len()));
    recomputed.update(&via_key);

    Ok(())
}

// ---------------------------------------------------------------------------
// kind: signatures (C16 / C12 + C13 + C14)
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SignaturesInputs {
    w: String,
    body: String,
    context: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SignaturesExpect {
    ed25519: Ed25519Entry,
    mldsa65: MlDsaEntry,
    hybrid: HybridEntry,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Ed25519Entry {
    seed: String,
    public_key: String,
    /// The full signed pre-image `ctx ‖ 0x00 ‖ body` — pinned as its own
    /// field so the frozen construction cannot drift silently.
    signing_message: String,
    signature: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MlDsaEntry {
    seed: String,
    public_key: String,
    signature: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct HybridEntry {
    policy_ids: Vec<u64>,
    policy_label: String,
}

const SIGNATURES_KIND: &str = "signatures";

/// Execute a `signatures` vector (MVP-SPEC.md lines 97, 104; tasks/C.md
/// C16): per algorithm the `W`-derived seed, the public key, and the
/// signature bytes are recomputed and byte-compared, then the whole hybrid
/// orchestration is run through C14's policy-enforcing verifier.
///
/// # Why signature *bytes* can be pinned at all
///
/// Both halves are deterministic. Ed25519 derives its nonce from the key
/// and message (RFC 8032), and ML-DSA-65 signs with the FIPS 204
/// deterministic variant `rnd = 0^32` (decision D15). Had D15 selected
/// hedged signing, this vector could only have pinned keygen plus
/// verification of a stored signature — the fallback C16's task notes
/// describe. It did not, so the bytes are portable across implementations,
/// which is exactly what makes the `fips204` cross-check possible.
fn execute_signatures(envelope: Envelope) -> Result<VectorSummary, VectorError> {
    let payload_err = |problem: String| VectorError::Payload {
        kind: SIGNATURES_KIND,
        problem,
    };
    let check_err = |check: &'static str, problem: String| VectorError::Check {
        kind: SIGNATURES_KIND,
        check,
        problem,
    };
    let inputs: SignaturesInputs =
        serde_json::from_value(envelope.inputs).map_err(|e| payload_err(format!("inputs: {e}")))?;
    let expect: SignaturesExpect =
        serde_json::from_value(envelope.expect).map_err(|e| payload_err(format!("expect: {e}")))?;

    let w_array = require_test_master_secret(SIGNATURES_KIND, &inputs.w)?;
    let w = MasterSecretRef::from_bytes(&w_array);
    let body = decode_hex(SIGNATURES_KIND, "inputs.body", &inputs.body)?;

    // The frozen context (MVP-SPEC.md line 97): changing these bytes is a
    // format event — every existing signature would stop verifying.
    let context = decode_hex(SIGNATURES_KIND, "inputs.context", &inputs.context)?;
    if context != SIG_CONTEXT {
        return Err(check_err(
            "sig-context",
            format!(
                "vector pins context {}, the frozen SIG_CONTEXT is {}",
                inputs.context,
                hex(SIG_CONTEXT)
            ),
        ));
    }

    // --- Ed25519 half (C12) ---
    let ed_seed = derive_sig_ed25519_seed(w);
    let expected_ed_seed = decode_hex(SIGNATURES_KIND, "ed25519.seed", &expect.ed25519.seed)?;
    if ed_seed.as_bytes().as_slice() != expected_ed_seed {
        return Err(check_err(
            "ed25519-seed",
            "derived seed differs from the vector's".to_owned(),
        ));
    }
    let ed_pk = sig_ed25519::public_key(w);
    if hex(ed_pk.as_bytes()) != expect.ed25519.public_key {
        return Err(check_err(
            "ed25519-public-key",
            format!(
                "derived {}, vector pins {}",
                hex(ed_pk.as_bytes()),
                expect.ed25519.public_key
            ),
        ));
    }
    // The pre-image `ctx ‖ 0x00 ‖ body`, pinned byte-exact.
    let message = sig_ed25519::signing_message(&body);
    if hex(&message) != expect.ed25519.signing_message {
        return Err(check_err(
            "ed25519-signing-message",
            format!(
                "constructed {}, vector pins {}",
                hex(&message),
                expect.ed25519.signing_message
            ),
        ));
    }
    let ed_sig = sig_ed25519::sign(w, &body);
    if hex(ed_sig.as_bytes()) != expect.ed25519.signature {
        return Err(check_err(
            "ed25519-signature",
            format!(
                "signed {}, vector pins {}",
                hex(ed_sig.as_bytes()),
                expect.ed25519.signature
            ),
        ));
    }
    sig_ed25519::verify(&ed_pk, &body, &ed_sig)
        .map_err(|e| check_err("ed25519-verify", format!("{e}")))?;

    // --- ML-DSA-65 half (C13) ---
    let mldsa_seed = derive_sig_mldsa65_seed(w);
    let expected_mldsa_seed = decode_hex(SIGNATURES_KIND, "mldsa65.seed", &expect.mldsa65.seed)?;
    if mldsa_seed.as_bytes().as_slice() != expected_mldsa_seed {
        return Err(check_err(
            "mldsa65-seed",
            "derived seed differs from the vector's".to_owned(),
        ));
    }
    let mldsa_pk = sig_mldsa::public_key(w);
    if hex(mldsa_pk.as_bytes()) != expect.mldsa65.public_key {
        return Err(check_err(
            "mldsa65-public-key",
            "derived public key differs from the vector's".to_owned(),
        ));
    }
    let mldsa_sig = sig_mldsa::sign(w, &body);
    if hex(mldsa_sig.as_bytes()) != expect.mldsa65.signature {
        return Err(check_err(
            "mldsa65-signature",
            "signature differs from the vector's — deterministic signing (D15) means \
             this is a real divergence, not a nonce difference"
                .to_owned(),
        ));
    }
    sig_mldsa::verify(&mldsa_pk, &body, &mldsa_sig)
        .map_err(|e| check_err("mldsa65-verify", format!("{e}")))?;

    // --- hybrid orchestration (C14) ---
    let policy = SigPolicy::from_ids(expect.hybrid.policy_ids.iter().copied())
        .map_err(|e| check_err("policy-ids", format!("{e}")))?;
    let label = policy.label();
    if policy_label_name(label) != expect.hybrid.policy_label {
        return Err(check_err(
            "policy-label",
            format!(
                "policy resolves to `{}`, vector pins `{}`",
                policy_label_name(label),
                expect.hybrid.policy_label
            ),
        ));
    }
    // The policy-driven key/signature production must reproduce exactly the
    // per-algorithm bytes pinned above — the orchestration is not allowed to
    // derive or sign differently from the per-algorithm entry points.
    let pubkeys = sig_policy::public_keys(w, &policy);
    let signatures = sig_policy::sign_body(w, &policy, &body);
    for (alg, expected) in [
        (SigAlg::Ed25519, &expect.ed25519.public_key),
        (SigAlg::MlDsa65, &expect.mldsa65.public_key),
    ] {
        let found = pubkeys
            .iter()
            .find(|(a, _)| *a == alg)
            .ok_or_else(|| check_err("hybrid-pubkeys", format!("policy omitted {alg:?}")))?;
        if &hex(&found.1) != expected {
            return Err(check_err(
                "hybrid-pubkeys",
                format!("{alg:?}: policy-derived key differs from the pinned one"),
            ));
        }
    }
    for (alg, expected) in [
        (SigAlg::Ed25519, &expect.ed25519.signature),
        (SigAlg::MlDsa65, &expect.mldsa65.signature),
    ] {
        let found = signatures
            .iter()
            .find(|(a, _)| *a == alg)
            .ok_or_else(|| check_err("hybrid-signatures", format!("policy omitted {alg:?}")))?;
        if &hex(&found.1) != expected {
            return Err(check_err(
                "hybrid-signatures",
                format!("{alg:?}: policy-produced signature differs from the pinned one"),
            ));
        }
    }
    let verified = sig_policy::verify_body(&policy, &pubkeys, &signatures, &body)
        .map_err(|e| check_err("hybrid-verify", format!("{e}")))?;
    if verified != label {
        return Err(check_err(
            "hybrid-verify",
            "verify_body returned a different policy label than the policy reports".to_owned(),
        ));
    }

    // Q5 bit-match: every key and signature this run derived, in a fixed
    // order (Ed25519 seed / public key / signing message / signature, then
    // ML-DSA-65 seed / public key / signature, then the hybrid policy's own
    // signatures tagged by algorithm id).
    let mut recomputed = Sha256::new();
    recomputed.update(RECOMPUTED_DIGEST_DOMAIN);
    recomputed.update(SIGNATURES_KIND.as_bytes());
    recomputed.update([0x00]);
    for bytes in [
        ed_seed.as_bytes().as_slice(),
        ed_pk.as_bytes(),
        message.as_slice(),
        ed_sig.as_bytes(),
        mldsa_seed.as_bytes().as_slice(),
        mldsa_pk.as_bytes(),
        mldsa_sig.as_bytes(),
    ] {
        recomputed.update(prefix_len(bytes.len()));
        recomputed.update(bytes);
    }
    for (alg, sig) in &signatures {
        // The algorithm's frozen registry name; SigAlg deliberately exposes no
        // numeric id (C14 maps ids to algorithms, not the reverse).
        recomputed.update(alg.to_string().as_bytes());
        recomputed.update([0x00]);
        recomputed.update(prefix_len(sig.len()));
        recomputed.update(sig);
    }

    Ok(VectorSummary {
        kind: SIGNATURES_KIND,
        // Two algorithms plus the hybrid orchestration over them.
        items: 3,
        description: envelope.description,
        recomputed_digest: recomputed.finalize().into(),
    })
}

/// Stable wire-facing name for a [`PolicyLabel`] (R's verdict datum).
fn policy_label_name(label: PolicyLabel) -> &'static str {
    match label {
        PolicyLabel::Hybrid => "hybrid",
        PolicyLabel::Ed25519Only => "ed25519-only",
        PolicyLabel::Other => "other",
    }
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

/// [`decode_hex`] into an exactly-`N`-byte array — the fixed-width wire
/// values (`seal_id`, nonces, keys). A wrong length is a malformed vector,
/// reported rather than panicked on (defensive parsing).
fn decode_hex_array<const N: usize>(
    kind: &'static str,
    field: &'static str,
    hex_str: &str,
) -> Result<[u8; N], VectorError> {
    let bytes = decode_hex(kind, field, hex_str)?;
    let len = bytes.len();
    <[u8; N]>::try_from(bytes).map_err(|_| VectorError::Payload {
        kind,
        problem: format!("field `{field}`: expected {N} bytes, found {len}"),
    })
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

/// Locate the first structural difference between two JSON values, as a
/// path plus the two sides — so a failing vector says *where*, not just
/// "documents differ" over 18 kB of hex.
///
/// Cross-kind and kind-agnostic (task R31): it landed with G15's `fine-tree`
/// executor but has nothing fine-tree-specific in it, and by the time R9's
/// `report` kind arrived, four executors and four regenerator tests were
/// importing it from a sibling kind's module. `pub`, unlike [`hex`] and
/// [`decode_hex`], because the regenerator tests under
/// `crates/antseal-core/tests/` are out-of-crate consumers.
pub fn first_difference(
    path: &str,
    recomputed: &serde_json::Value,
    committed: &serde_json::Value,
) -> String {
    match (recomputed, committed) {
        (serde_json::Value::Object(a), serde_json::Value::Object(b)) => {
            for (key, value) in a {
                match b.get(key) {
                    None => return format!("{path}.{key}: recomputed has it, the file does not"),
                    Some(other) if other != value => {
                        return first_difference(&format!("{path}.{key}"), value, other);
                    }
                    Some(_) => {}
                }
            }
            for key in b.keys() {
                if !a.contains_key(key) {
                    return format!("{path}.{key}: the file has it, recomputation does not");
                }
            }
            format!("{path}: objects differ but no field does (unreachable)")
        }
        (serde_json::Value::Array(a), serde_json::Value::Array(b)) => {
            if a.len() != b.len() {
                return format!(
                    "{path}: recomputed {} entr(ies), the file pins {}",
                    a.len(),
                    b.len()
                );
            }
            for (i, (value, other)) in a.iter().zip(b).enumerate() {
                if value != other {
                    return first_difference(&format!("{path}[{i}]"), value, other);
                }
            }
            format!("{path}: arrays differ but no element does (unreachable)")
        }
        (a, b) => format!("{path}: recomputed {a}, the file pins {b}"),
    }
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

    // -----------------------------------------------------------------
    // kinds: unit-aead / manifest-aead — tests-of-the-test
    // -----------------------------------------------------------------

    /// Fixture `seal_id` for the synthetic AEAD self-test documents.
    const SELF_TEST_SEAL_ID: [u8; 16] = [0xA5; 16];

    fn self_test_rng() -> rand_chacha::ChaCha20Rng {
        use rand_core::SeedableRng as _;
        rand_chacha::ChaCha20Rng::from_seed([0x16; 32])
    }

    /// Build a valid `unit-aead` document, including the two boundary
    /// cases the executor requires (empty unit, 256-aligned unit).
    fn valid_unit_aead_document() -> serde_json::Value {
        let w = MasterSecretRef::from_bytes(&super::super::TEST_MASTER_SECRET_W);
        let seal_id = SealId::from_bytes(SELF_TEST_SEAL_ID);
        let mut rng = self_test_rng();

        let cases: [(&str, u64, Vec<u8>); 3] = [
            ("self-test-empty", 0, Vec::new()),
            ("self-test-aligned", 1, vec![0x7E; PAD_BLOCK]),
            ("self-test-ordinary", 2, b"unit bytes".to_vec()),
        ];
        let vectors: Vec<serde_json::Value> = cases
            .iter()
            .map(|(name, id, bytes)| {
                let unit_id = UnitId(*id);
                let (ciphertext, nonce) =
                    crate::crypto::unit_aead::encrypt_unit(w, &seal_id, unit_id, bytes, &mut rng)
                        .expect("seeded rng encrypts");
                serde_json::json!({
                    "name": name,
                    "unit_id": format!("0x{id:016x}"),
                    "true_length": bytes.len(),
                    "unit_bytes": hex(bytes),
                    "k_u": hex(derive_unit_key(w, unit_id).as_bytes()),
                    "aad": hex(&unit_aad(&seal_id, unit_id)),
                    "padded_plaintext": hex(&apply_padding(bytes)),
                    "nonce": hex(nonce.as_bytes()),
                    "ciphertext": hex(&ciphertext),
                })
            })
            .collect();

        serde_json::json!({
            "schema": SCHEMA,
            "schema_version": SCHEMA_VERSION,
            "format_version": "v1",
            "kind": "unit-aead",
            "non_secret": "NON-SECRET synthetic self-test document",
            "description": "framework self-test",
            "inputs": {
                "w": hex(&super::super::TEST_MASTER_SECRET_W),
                "seal_id": hex(&SELF_TEST_SEAL_ID),
            },
            "expect": { "vectors": vectors },
        })
    }

    #[test]
    fn self_consistent_unit_aead_document_executes_green() {
        let summary = execute(&valid_unit_aead_document()).expect("valid document must execute");
        assert_eq!(summary.kind, "unit-aead");
        assert_eq!(summary.items, 3);
    }

    /// The load-bearing check: a flipped ciphertext byte must fail
    /// authentication, which is what makes "decrypts to the pinned
    /// plaintext" equivalent to pinning the ciphertext bytes.
    #[test]
    fn tampered_ciphertext_fails_loudly() {
        let mut doc = valid_unit_aead_document();
        let mut ct = doc["expect"]["vectors"][0]["ciphertext"]
            .as_str()
            .expect("ciphertext is a string")
            .to_owned();
        let last = ct.pop().expect("non-empty");
        ct.push(if last == '0' { '1' } else { '0' });
        doc["expect"]["vectors"][0]["ciphertext"] = serde_json::json!(ct);
        let err = execute(&doc).expect_err("must fail");
        assert!(
            matches!(
                err,
                VectorError::Check {
                    check: "decrypt-with-key",
                    ..
                }
            ),
            "{err}"
        );
    }

    #[test]
    fn tampered_unit_key_fails_loudly() {
        let mut doc = valid_unit_aead_document();
        doc["expect"]["vectors"][0]["k_u"] = serde_json::json!(hex(&[0xABu8; 32]));
        let err = execute(&doc).expect_err("must fail");
        assert!(
            matches!(
                err,
                VectorError::Check {
                    check: "unit-key-bytes",
                    ..
                }
            ),
            "{err}"
        );
    }

    #[test]
    fn tampered_aad_fails_loudly() {
        let mut doc = valid_unit_aead_document();
        doc["expect"]["vectors"][0]["aad"] = serde_json::json!(hex(&[0xABu8; 24]));
        let err = execute(&doc).expect_err("must fail");
        assert!(
            matches!(
                err,
                VectorError::Check {
                    check: "aad-bytes",
                    ..
                }
            ),
            "{err}"
        );
    }

    #[test]
    fn tampered_padded_plaintext_fails_loudly() {
        let mut doc = valid_unit_aead_document();
        // Correct length, wrong fill: a non-zero pad byte.
        let mut padded = vec![0u8; PAD_BLOCK];
        padded[PAD_BLOCK - 1] = 0xFF;
        doc["expect"]["vectors"][0]["padded_plaintext"] = serde_json::json!(hex(&padded));
        let err = execute(&doc).expect_err("must fail");
        assert!(
            matches!(
                err,
                VectorError::Check {
                    check: "padded-plaintext",
                    ..
                }
            ),
            "{err}"
        );
    }

    #[test]
    fn inconsistent_true_length_fails_loudly() {
        let mut doc = valid_unit_aead_document();
        // Entry 2 is the ordinary (non-boundary) case: mutating a boundary
        // entry's length would trip `boundary-coverage` first, which runs
        // before any per-entry check.
        doc["expect"]["vectors"][2]["true_length"] = serde_json::json!(7);
        let err = execute(&doc).expect_err("must fail");
        assert!(
            matches!(
                err,
                VectorError::Check {
                    check: "true-length",
                    ..
                }
            ),
            "{err}"
        );
    }

    /// C16 accept names the empty unit and the 256-aligned unit explicitly;
    /// dropping either must fail rather than quietly shrink coverage.
    #[test]
    fn missing_aead_boundary_case_fails_loudly() {
        for drop_index in [0usize, 1] {
            let mut doc = valid_unit_aead_document();
            doc["expect"]["vectors"]
                .as_array_mut()
                .expect("vectors is an array")
                .remove(drop_index);
            let err = execute(&doc).expect_err("must fail");
            assert!(
                matches!(
                    err,
                    VectorError::Check {
                        check: "boundary-coverage",
                        ..
                    }
                ),
                "dropping vector {drop_index}: {err}"
            );
        }
    }

    /// Build a valid `manifest-aead` document.
    fn valid_manifest_aead_document() -> serde_json::Value {
        let w = MasterSecretRef::from_bytes(&super::super::TEST_MASTER_SECRET_W);
        let mut rng = self_test_rng();
        let manifest: &[u8] = b"manifest bytes (self-test)";
        let (blob, record) = crate::crypto::manifest_aead::encrypt_manifest(w, manifest, &mut rng)
            .expect("seeded rng encrypts");

        serde_json::json!({
            "schema": SCHEMA,
            "schema_version": SCHEMA_VERSION,
            "format_version": "v1",
            "kind": "manifest-aead",
            "non_secret": "NON-SECRET synthetic self-test document",
            "description": "framework self-test",
            "inputs": { "w": hex(&super::super::TEST_MASTER_SECRET_W) },
            "expect": {
                "k_m": hex(derive_manifest_key(w).as_bytes()),
                "vectors": [{
                    "name": "self-test-manifest",
                    "manifest_bytes": hex(manifest),
                    "aad": "",
                    "nonce": hex(record.nonce().as_bytes()),
                    "blob": hex(&blob),
                }],
            },
        })
    }

    #[test]
    fn self_consistent_manifest_aead_document_executes_green() {
        let summary =
            execute(&valid_manifest_aead_document()).expect("valid document must execute");
        assert_eq!(summary.kind, "manifest-aead");
        assert_eq!(summary.items, 1);
    }

    /// The frozen empty AAD (spec line 98): a vector claiming any other AAD
    /// is rejected outright, so the constant cannot drift unnoticed.
    #[test]
    fn non_empty_manifest_aad_field_fails_loudly() {
        let mut doc = valid_manifest_aead_document();
        doc["expect"]["vectors"][0]["aad"] = serde_json::json!("00");
        let err = execute(&doc).expect_err("must fail");
        assert!(
            matches!(
                err,
                VectorError::Check {
                    check: "empty-aad",
                    ..
                }
            ),
            "{err}"
        );
    }

    #[test]
    fn tampered_manifest_key_fails_loudly() {
        let mut doc = valid_manifest_aead_document();
        doc["expect"]["k_m"] = serde_json::json!(hex(&[0xABu8; 32]));
        let err = execute(&doc).expect_err("must fail");
        assert!(
            matches!(
                err,
                VectorError::Check {
                    check: "manifest-key-bytes",
                    ..
                }
            ),
            "{err}"
        );
    }

    #[test]
    fn tampered_manifest_blob_fails_loudly() {
        let mut doc = valid_manifest_aead_document();
        let mut blob = doc["expect"]["vectors"][0]["blob"]
            .as_str()
            .expect("blob is a string")
            .to_owned();
        let last = blob.pop().expect("non-empty");
        blob.push(if last == '0' { '1' } else { '0' });
        doc["expect"]["vectors"][0]["blob"] = serde_json::json!(blob);
        let err = execute(&doc).expect_err("must fail");
        assert!(
            matches!(
                err,
                VectorError::Check {
                    check: "decrypt-with-key",
                    ..
                }
            ),
            "{err}"
        );
    }

    /// Fixed-width fields reject a wrong length rather than panicking
    /// (defensive parsing — `decode_hex_array`).
    #[test]
    fn wrong_length_fixed_width_field_fails_loudly() {
        let mut doc = valid_unit_aead_document();
        doc["expect"]["vectors"][0]["nonce"] = serde_json::json!(hex(&[0u8; 23]));
        let err = execute(&doc).expect_err("must fail");
        assert!(matches!(err, VectorError::Payload { .. }), "{err}");

        let mut doc = valid_unit_aead_document();
        doc["inputs"]["seal_id"] = serde_json::json!(hex(&[0u8; 15]));
        let err = execute(&doc).expect_err("must fail");
        assert!(matches!(err, VectorError::Payload { .. }), "{err}");
    }

    // -----------------------------------------------------------------
    // kind: signatures — tests-of-the-test
    // -----------------------------------------------------------------

    /// Build a valid `signatures` document from the crate's own signing
    /// paths (self-consistent by construction).
    fn valid_signatures_document() -> serde_json::Value {
        let w = MasterSecretRef::from_bytes(&super::super::TEST_MASTER_SECRET_W);
        let body: &[u8] = b"self-test body";
        serde_json::json!({
            "schema": SCHEMA,
            "schema_version": SCHEMA_VERSION,
            "format_version": "v1",
            "kind": "signatures",
            "non_secret": "NON-SECRET synthetic self-test document",
            "description": "framework self-test",
            "inputs": {
                "w": hex(&super::super::TEST_MASTER_SECRET_W),
                "body": hex(body),
                "context": hex(SIG_CONTEXT),
            },
            "expect": {
                "ed25519": {
                    "seed": hex(derive_sig_ed25519_seed(w).as_bytes()),
                    "public_key": hex(sig_ed25519::public_key(w).as_bytes()),
                    "signing_message": hex(&sig_ed25519::signing_message(body)),
                    "signature": hex(sig_ed25519::sign(w, body).as_bytes()),
                },
                "mldsa65": {
                    "seed": hex(derive_sig_mldsa65_seed(w).as_bytes()),
                    "public_key": hex(sig_mldsa::public_key(w).as_bytes()),
                    "signature": hex(sig_mldsa::sign(w, body).as_bytes()),
                },
                "hybrid": { "policy_ids": [0, 1], "policy_label": "hybrid" },
            },
        })
    }

    #[test]
    fn self_consistent_signatures_document_executes_green() {
        let summary = execute(&valid_signatures_document()).expect("valid document must execute");
        assert_eq!(summary.kind, "signatures");
        assert_eq!(summary.items, 3);
    }

    /// The frozen context (MVP-SPEC.md line 97): a vector pinning any other
    /// ctx must fail, so the constant cannot drift under the vectors.
    #[test]
    fn wrong_sig_context_fails_loudly() {
        let mut doc = valid_signatures_document();
        doc["inputs"]["context"] = serde_json::json!(hex(b"antseal-manifest-v2"));
        let err = execute(&doc).expect_err("must fail");
        assert!(
            matches!(
                err,
                VectorError::Check {
                    check: "sig-context",
                    ..
                }
            ),
            "{err}"
        );
    }

    /// The pre-image `ctx ‖ 0x00 ‖ body` is pinned as its own field, so
    /// dropping the separator (or the context) is a vector break rather
    /// than something only the signature bytes would catch.
    #[test]
    fn tampered_signing_message_fails_loudly() {
        let mut doc = valid_signatures_document();
        let mut without_separator = SIG_CONTEXT.to_vec();
        without_separator.extend_from_slice(b"self-test body");
        doc["expect"]["ed25519"]["signing_message"] = serde_json::json!(hex(&without_separator));
        let err = execute(&doc).expect_err("must fail");
        assert!(
            matches!(
                err,
                VectorError::Check {
                    check: "ed25519-signing-message",
                    ..
                }
            ),
            "{err}"
        );
    }

    #[test]
    fn tampered_ed25519_signature_fails_loudly() {
        let mut doc = valid_signatures_document();
        let mut sig = doc["expect"]["ed25519"]["signature"]
            .as_str()
            .expect("signature is a string")
            .to_owned();
        let last = sig.pop().expect("non-empty");
        sig.push(if last == '0' { '1' } else { '0' });
        doc["expect"]["ed25519"]["signature"] = serde_json::json!(sig);
        let err = execute(&doc).expect_err("must fail");
        assert!(
            matches!(
                err,
                VectorError::Check {
                    check: "ed25519-signature",
                    ..
                }
            ),
            "{err}"
        );
    }

    /// Deterministic ML-DSA signing (D15) is what makes a byte mismatch a
    /// real divergence rather than a nonce difference — so it must fail.
    #[test]
    fn tampered_mldsa_signature_fails_loudly() {
        let mut doc = valid_signatures_document();
        let mut sig = doc["expect"]["mldsa65"]["signature"]
            .as_str()
            .expect("signature is a string")
            .to_owned();
        let last = sig.pop().expect("non-empty");
        sig.push(if last == '0' { '1' } else { '0' });
        doc["expect"]["mldsa65"]["signature"] = serde_json::json!(sig);
        let err = execute(&doc).expect_err("must fail");
        assert!(
            matches!(
                err,
                VectorError::Check {
                    check: "mldsa65-signature",
                    ..
                }
            ),
            "{err}"
        );
    }

    #[test]
    fn tampered_public_key_fails_loudly() {
        let mut doc = valid_signatures_document();
        doc["expect"]["ed25519"]["public_key"] = serde_json::json!(hex(&[0xABu8; 32]));
        let err = execute(&doc).expect_err("must fail");
        assert!(
            matches!(
                err,
                VectorError::Check {
                    check: "ed25519-public-key",
                    ..
                }
            ),
            "{err}"
        );
    }

    /// An anti-downgrade guard on the vector itself: a file claiming the
    /// Ed25519-only policy while carrying hybrid material must not pass.
    #[test]
    fn downgraded_policy_label_fails_loudly() {
        let mut doc = valid_signatures_document();
        doc["expect"]["hybrid"]["policy_ids"] = serde_json::json!([0]);
        let err = execute(&doc).expect_err("must fail");
        assert!(
            matches!(
                err,
                VectorError::Check {
                    check: "policy-label",
                    ..
                }
            ),
            "{err}"
        );
    }

    /// An unregistered algorithm id is rejected by C14's `from_ids`
    /// (ids 2–15 are reserved), surfaced as a vector failure, not a panic.
    #[test]
    fn unknown_policy_id_fails_loudly() {
        let mut doc = valid_signatures_document();
        doc["expect"]["hybrid"]["policy_ids"] = serde_json::json!([0, 1, 7]);
        let err = execute(&doc).expect_err("must fail");
        assert!(
            matches!(
                err,
                VectorError::Check {
                    check: "policy-ids",
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

    /// The diff locator names the field, not just "they differ".
    ///
    /// Moved here with [`first_difference`] itself (R31); it was written for
    /// the `fine-tree` kind, and its `fine_root` field name is kept so the
    /// move is visibly a move.
    #[test]
    fn first_difference_locates_the_field() {
        let a = serde_json::json!({"cases": [{"n": 6, "fine_root": "aa"}]});
        let b = serde_json::json!({"cases": [{"n": 6, "fine_root": "bb"}]});
        let message = first_difference("expect", &a, &b);
        assert!(message.contains("cases[0].fine_root"), "{message}");
        let short = serde_json::json!({"cases": []});
        assert!(first_difference("expect", &short, &b).contains("entr"));
    }
}
