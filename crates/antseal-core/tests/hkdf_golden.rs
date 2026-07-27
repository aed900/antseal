//! C3 — the M0 HKDF golden tests (MVP-SPEC.md line 153) and the committed
//! golden-vector verification (`testdata/vectors/hkdf/`).
//!
//! Exercises only the public API of `antseal_core::crypto::hkdf`; the
//! structural-injectivity property test over arbitrary labels lives next to
//! the crate-private encoder in `src/crypto/hkdf.rs`.

use antseal_core::crypto::hkdf::{
    FileId, IdDomain, Label, SENTINEL_ID, UnitId, derive_file_salt, derive_fine_seed,
    derive_manifest_key, derive_path_salt, derive_sig_ed25519_seed, derive_sig_mldsa65_seed,
    derive_unit_key, derive_unit_salt,
};
use antseal_core::crypto::material::MasterSecretRef;

/// Fixed, public, NON-SECRET test master secret (bytes 0x00..0x1f) — must
/// equal the `w =` line of the committed vector file (project rule 6: never
/// a real secret).
const TEST_W: [u8; 32] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
];

const VECTOR_FILE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../testdata/vectors/hkdf/hkdf-sha256-v1.txt"
);

/// **The M0 golden test** mandated by MVP-SPEC.md line 153: *"a golden test
/// asserting all registered HKDF infos are pairwise distinct"*.
///
/// Enumerates every registered label crossed with the representative id set
/// {0, 1, max-real, sentinel} (max-real = `u64::MAX - 1`, the largest id a
/// real unit/file table could carry — one below the sentinel) and asserts
/// all encoded info byte strings are pairwise distinct. Distinct infos ⇒
/// independent PRF outputs ⇒ keys and salts of different roles never
/// collide (spec line 77).
#[test]
fn m0_golden_all_registered_hkdf_infos_pairwise_distinct() {
    let representative_ids: [u64; 4] = [0, 1, u64::MAX - 1, SENTINEL_ID];
    let mut infos: Vec<(String, Vec<u8>)> = Vec::new();
    for label in Label::ALL {
        for id in representative_ids {
            infos.push((
                format!("({}, {id:#x})", label.as_str()),
                label.info_bytes(id),
            ));
        }
    }
    assert_eq!(infos.len(), Label::ALL.len() * representative_ids.len());
    for i in 0..infos.len() {
        for j in (i + 1)..infos.len() {
            assert_ne!(
                infos[i].1, infos[j].1,
                "HKDF infos must be pairwise distinct: {} vs {} encode identically",
                infos[i].0, infos[j].0
            );
        }
    }
}

/// One parsed `vector` line of the committed golden file.
struct Vector {
    label: Label,
    id: u64,
    id_domain: IdDomain,
    info: Vec<u8>,
    okm: Vec<u8>,
}

/// C3 accept: the committed golden vectors — produced by the independent
/// Python reference implementation in `testdata/vectors/hkdf/` — verify
/// against this crate's public derivation API: info bytes, output length,
/// and output bytes, for all 8 registry labels.
///
/// The `vector_` name prefix opts this test into the cross-OS CI lane
/// (Q1 convention, CONTRIBUTING.md): committed-vector byte stability must
/// hold on linux, macOS, and windows.
#[test]
fn vector_committed_hkdf_golden_file_verifies() {
    let content = std::fs::read_to_string(VECTOR_FILE)
        .unwrap_or_else(|e| panic!("cannot read {VECTOR_FILE}: {e}"));

    // The fixture file must self-declare as non-secret (project rule 6).
    assert!(
        content.contains("NON-SECRET"),
        "vector file must carry the NON-SECRET fixture marker"
    );

    let (file_w, vectors) = parse_vector_file(&content);
    assert_eq!(
        file_w, TEST_W,
        "vector-file W must equal the committed NON-SECRET fixture"
    );

    // Exactly the 8 registry labels, each exactly once.
    assert_eq!(vectors.len(), Label::ALL.len());
    for label in Label::ALL {
        assert_eq!(
            vectors.iter().filter(|v| v.label == label).count(),
            1,
            "expected exactly one vector for {}",
            label.as_str()
        );
    }

    let w = MasterSecretRef::from_bytes(&TEST_W);
    for vector in &vectors {
        let name = vector.label.as_str();
        // Registry metadata pinned by the file.
        assert_eq!(
            vector.id_domain,
            vector.label.id_domain(),
            "{name}: id_domain"
        );
        if vector.label.id_domain() == IdDomain::Sentinel {
            assert_eq!(
                vector.id, SENTINEL_ID,
                "{name}: sentinel labels use the sentinel id"
            );
        }
        // Info bytes: the encoder must reproduce the committed encoding.
        assert_eq!(
            vector.info,
            vector.label.info_bytes(vector.id),
            "{name}: info bytes"
        );
        // Output: length per registry, bytes per the independent reference.
        assert_eq!(
            vector.okm.len(),
            vector.label.output_len(),
            "{name}: okm length"
        );
        let derived = derive_via_typed_api(w, vector.label, vector.id);
        assert_eq!(
            derived, vector.okm,
            "{name}: derived output must match the golden vector"
        );
    }
}

/// Derive through the public typed API, dispatching per label (the only
/// derivation path — there is deliberately no free-form label API).
fn derive_via_typed_api(w: MasterSecretRef<'_>, label: Label, id: u64) -> Vec<u8> {
    match label {
        Label::UnitKey => derive_unit_key(w, UnitId(id)).into_bytes().to_vec(),
        Label::UnitSalt => derive_unit_salt(w, UnitId(id)).into_bytes().to_vec(),
        Label::PathSalt => derive_path_salt(w, FileId(id)).into_bytes().to_vec(),
        Label::FileSalt => derive_file_salt(w, FileId(id)).into_bytes().to_vec(),
        Label::FineSeed => derive_fine_seed(w, FileId(id)).into_bytes().to_vec(),
        Label::SigEd25519 => derive_sig_ed25519_seed(w).into_bytes().to_vec(),
        Label::SigMlDsa65 => derive_sig_mldsa65_seed(w).into_bytes().to_vec(),
        Label::ManifestKey => derive_manifest_key(w).into_bytes().to_vec(),
    }
}

fn parse_vector_file(content: &str) -> ([u8; 32], Vec<Vector>) {
    let mut file_w: Option<[u8; 32]> = None;
    let mut vectors = Vec::new();
    for (line_no, raw_line) in content.lines().enumerate() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(w_hex) = line.strip_prefix("w =") {
            let bytes = decode_hex(w_hex.trim(), line_no);
            let array: [u8; 32] = bytes
                .try_into()
                .unwrap_or_else(|_| panic!("line {}: w must be 32 bytes", line_no + 1));
            file_w = Some(array);
        } else if let Some(fields) = line.strip_prefix("vector ") {
            vectors.push(parse_vector_line(fields, line_no));
        } else {
            panic!(
                "line {}: unrecognized line in vector file: {line}",
                line_no + 1
            );
        }
    }
    let file_w = file_w.unwrap_or_else(|| panic!("vector file has no `w =` line"));
    (file_w, vectors)
}

fn parse_vector_line(fields: &str, line_no: usize) -> Vector {
    let mut label = None;
    let mut id = None;
    let mut id_domain = None;
    let mut info = None;
    let mut okm = None;
    for field in fields.split_whitespace() {
        let (key, value) = field
            .split_once('=')
            .unwrap_or_else(|| panic!("line {}: malformed field {field}", line_no + 1));
        match key {
            "label" => {
                label = Label::ALL.into_iter().find(|l| l.as_str() == value);
                assert!(
                    label.is_some(),
                    "line {}: unknown label {value}",
                    line_no + 1
                );
            }
            "id" => {
                let hex = value
                    .strip_prefix("0x")
                    .unwrap_or_else(|| panic!("line {}: id must be 0x-prefixed", line_no + 1));
                id = Some(
                    u64::from_str_radix(hex, 16)
                        .unwrap_or_else(|e| panic!("line {}: bad id {value}: {e}", line_no + 1)),
                );
            }
            "id_domain" => {
                id_domain = Some(match value {
                    "unit_id" => IdDomain::UnitId,
                    "file_id" => IdDomain::FileId,
                    "sentinel" => IdDomain::Sentinel,
                    other => panic!("line {}: unknown id_domain {other}", line_no + 1),
                });
            }
            "info" => info = Some(decode_hex(value, line_no)),
            "okm" => okm = Some(decode_hex(value, line_no)),
            other => panic!("line {}: unknown field key {other}", line_no + 1),
        }
    }
    fn require<T>(field: Option<T>, name: &str, line_no: usize) -> T {
        field.unwrap_or_else(|| panic!("line {}: vector line is missing `{name}`", line_no + 1))
    }
    Vector {
        label: require(label, "label", line_no),
        id: require(id, "id", line_no),
        id_domain: require(id_domain, "id_domain", line_no),
        info: require(info, "info", line_no),
        okm: require(okm, "okm", line_no),
    }
}

fn decode_hex(hex: &str, line_no: usize) -> Vec<u8> {
    assert!(
        hex.len().is_multiple_of(2),
        "line {}: odd-length hex",
        line_no + 1
    );
    (0..hex.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&hex[i..i + 2], 16)
                .unwrap_or_else(|e| panic!("line {}: bad hex: {e}", line_no + 1))
        })
        .collect()
}
