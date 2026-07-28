//! **C's registry slice for the tamper matrix** (task C17): the M0
//! crypto-owned rows, each mutating one valid artifact in exactly one way
//! and pinning the distinct error a verifier must produce (MVP-SPEC.md
//! line 168: *every mutation fails with a distinct error*).
//!
//! The harness — distinctness, no-panic and exact-outcome assertions, and
//! the add-a-row procedure — is [`super::tamper`]; the code contract these
//! rows bind to is `docs/testing/error-code-contract.md`. Rows live here,
//! in the library behind `test-util`, rather than in one integration test
//! so that (a) the *whole* registry can be assembled in one place for the
//! cross-domain distinctness sweep (contract §4 layer 2), and (b) they are
//! WASM-safe: every exercise function below is pure crypto over in-memory
//! bytes, no I/O, so the wasm lane runs the identical rows.
//!
//! # Coverage against the spec's M0 crypto row list (line 168)
//!
//! | spec row | code | where |
//! | --- | --- | --- |
//! | wrong salt — `unit_salt` | `crypto-unit-commit-mismatch` | here |
//! | wrong salt — `path_salt` | `crypto-path-commit-mismatch` | here |
//! | wrong salt — `file_salt` (raw) | `crypto-raw-commit-mismatch` | here |
//! | wrong salt — `file_salt` (canon) | `crypto-canon-commit-mismatch` | here |
//! | wrong-length salt — 15-B `unit_salt` | `crypto-unit-salt-length` | here |
//! | wrong-length salt — 17-B `file_salt` | `crypto-file-salt-length` | here |
//! | wrong-length salt — 15-B `path_salt` | `crypto-path-salt-length` | Q7 seed row |
//! | wrong-length seed — 31-B `s_root` | `crypto-seed-length` | here |
//! | wrong-length node hash — 33-B | `crypto-node-hash-length` | here |
//! | wrong key | `crypto-aead-decrypt-failed` | here |
//! | `sig_policy` empty | `crypto-sig-policy-empty` | here |
//! | `sig_policy` missing sig | `crypto-signature-missing-ml-dsa-65` | here |
//! | `sig_policy` invalid sig | `crypto-signature-invalid-ed25519` | here |
//! | `sig_policy` unlisted-extra sig | `crypto-signature-unlisted-ml-dsa-65` | here |
//! | non-canonical Ed25519 `S` | `crypto-non-canonical-signature-ed25519` | here |
//! | non-canonical ML-DSA encoding | `crypto-non-canonical-signature-ml-dsa-65` | here |
//! | over-padded unit | `crypto-padding-length-mismatch` | Q7 seed row |
//! | non-zero pad byte | `crypto-non-zero-padding` | Q7 seed row |
//!
//! Two rows beyond the spec's list complete the `SigPolicy` reject family
//! (`crypto-sig-policy-duplicate`, `crypto-sig-policy-unknown-alg`) — C14's
//! other two parse-time rejects, distinct outcomes both, and free to pin.
//!
//! **Deliberately not rows here.** `crypto-fine-root-commit-mismatch` is
//! G's fine-tree machinery (G19). The mirrored per-algorithm codes
//! (`…-missing-ed25519`, `…-invalid-ml-dsa-65`, `…-unlisted-ed25519`) are
//! reachable and pairwise distinct, but the spec's row list names one row
//! per *policy violation*, not per (violation × algorithm); the symmetric
//! cases are covered by C15's committed reject vectors and C14's own tests.
//! `crypto-rng-failure` is not a tampering outcome at all.
//!
//! # Fixture-owner split with R7 (Q8's single-owner rule)
//!
//! The rows here exercise C's *primitives*: the newtype length constructors,
//! the commitment verifiers, the AEAD, and the policy orchestration. The
//! **committed bundle-level fixtures** for the wrong-length and over-padding
//! families are R7's, so Q8's registry lists R as the fixture owner there
//! and cross-references these primitive rows — no duplicate rows, and no
//! family without a row. The mutation helpers R7 needs are re-exported from
//! [`helpers`].

use crate::crypto::commit::{
    canon_commit, path_commit, raw_commit, unit_commit, verify_canon_commit, verify_path_commit,
    verify_raw_commit, verify_unit_commit,
};
use crate::crypto::error::{CryptoError, SaltKind, SigAlg};
use crate::crypto::hkdf::{
    FileId, UnitId, derive_file_salt, derive_fine_seed, derive_path_salt, derive_unit_salt,
};
use crate::crypto::material::{FileSalt, MasterSecretRef, NodeHash32, Salt16, Seed32};
use crate::crypto::secrets::SealId;
use crate::crypto::sig_ed25519;
use crate::crypto::sig_mldsa::{self, OFFSET_HINT_CUTS, OFFSET_HINT_INDICES, OMEGA};
use crate::crypto::sig_policy::{AlgMaterial, SigPolicy, public_keys, sign_body, verify_body};
use crate::crypto::unit_aead::{decrypt_unit, encrypt_unit};

use super::fixture_rng::FixtureRng;
use super::tamper::{ActualOutcome, ExpectedOutcome, TamperRow};
use super::{TEST_MASTER_SECRET_W, alternate_test_secret};

// ---------------------------------------------------------------------------
// the shared base fixtures every row mutates
// ---------------------------------------------------------------------------

/// Label of the "other author" whose material the wrong-key rows use
/// (derived from the documented test seed — see
/// [`super::alternate_test_secret`]).
pub const WRONG_KEY_LABEL: &[u8] = b"antseal C17 wrong key";

/// The fixture unit's id, file id, and bytes. Public so R7's bundle-level
/// fixtures can be built over the *same* base artifact these rows mutate.
pub const FIXTURE_UNIT_ID: UnitId = UnitId(3);
/// See [`FIXTURE_UNIT_ID`].
pub const FIXTURE_FILE_ID: FileId = FileId(1);
/// See [`FIXTURE_UNIT_ID`].
pub const FIXTURE_UNIT_BYTES: &[u8] = b"the unit bytes under commitment\n";
/// The fixture file's path, committed by `path_commit`.
pub const FIXTURE_PATH: &str = "docs/chapter-one.md";
/// The fixture file's raw and canonical bytes (they differ: the raw form
/// carries a CRLF the canonical form does not).
pub const FIXTURE_RAW_BYTES: &[u8] = b"chapter one\r\nsecond line\r\n";
/// See [`FIXTURE_RAW_BYTES`].
pub const FIXTURE_CANON_BYTES: &[u8] = b"chapter one\nsecond line\n";
/// The fixture `seal_id` (public manifest data, NON-SECRET).
pub const FIXTURE_SEAL_ID: [u8; 16] = [
    0xC1, 0x7A, 0x00, 0x01, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13,
];
/// Seed of the deterministic fixture RNG the AEAD rows encrypt under.
pub const FIXTURE_RNG_SEED: [u8; 32] = [0xC1; 32];
/// Manifest body bytes the signature rows sign (stand-in for F's canonical
/// CBOR body).
pub const FIXTURE_BODY: &[u8] = b"antseal manifest body bytes (fixture)\n";

fn w() -> MasterSecretRef<'static> {
    MasterSecretRef::from_bytes(&TEST_MASTER_SECRET_W)
}

fn code(err: &CryptoError) -> &'static str {
    err.code()
}

/// Flip the lowest bit of the first byte — the canonical "wrong salt"
/// mutation: a value that is the right *shape* and the wrong *value*.
fn flip_first_bit(bytes: &[u8; 16]) -> Salt16 {
    let mut flipped = *bytes;
    flipped[0] ^= 0x01;
    Salt16::from_bytes(flipped)
}

// ---------------------------------------------------------------------------
// (1) wrong salt — one row per salted commitment
// ---------------------------------------------------------------------------

fn unit_commit_wrong_salt() -> ActualOutcome {
    let salt = derive_unit_salt(w(), FIXTURE_UNIT_ID);
    let expected = unit_commit(&salt, FIXTURE_UNIT_BYTES);
    let wrong = flip_first_bit(salt.as_bytes());
    ActualOutcome::from_result(
        verify_unit_commit(&wrong, FIXTURE_UNIT_BYTES, &expected),
        code,
    )
}

fn path_commit_wrong_salt() -> ActualOutcome {
    let salt = derive_path_salt(w(), FIXTURE_FILE_ID);
    let expected = path_commit(&salt, FIXTURE_PATH);
    let wrong = flip_first_bit(salt.as_bytes());
    ActualOutcome::from_result(verify_path_commit(&wrong, FIXTURE_PATH, &expected), code)
}

fn raw_commit_wrong_salt() -> ActualOutcome {
    let salt = derive_file_salt(w(), FIXTURE_FILE_ID);
    let expected = raw_commit(&salt, FIXTURE_RAW_BYTES);
    let wrong = FileSalt::from_disclosed(flip_first_bit(salt.expose_bytes_for_test_vectors()));
    ActualOutcome::from_result(
        verify_raw_commit(&wrong, FIXTURE_RAW_BYTES, &expected),
        code,
    )
}

fn canon_commit_wrong_salt() -> ActualOutcome {
    let salt = derive_file_salt(w(), FIXTURE_FILE_ID);
    let expected = canon_commit(&salt, FIXTURE_CANON_BYTES);
    let wrong = FileSalt::from_disclosed(flip_first_bit(salt.expose_bytes_for_test_vectors()));
    ActualOutcome::from_result(
        verify_canon_commit(&wrong, FIXTURE_CANON_BYTES, &expected),
        code,
    )
}

// ---------------------------------------------------------------------------
// (2) wrong-length salt / seed / node hash — the line-121 structural checks
// ---------------------------------------------------------------------------

fn unit_salt_truncated() -> ActualOutcome {
    let salt = derive_unit_salt(w(), FIXTURE_UNIT_ID);
    ActualOutcome::from_result(
        Salt16::try_from_slice(SaltKind::Unit, &salt.as_bytes()[..15]),
        code,
    )
}

fn file_salt_extended() -> ActualOutcome {
    let salt = derive_file_salt(w(), FIXTURE_FILE_ID);
    let mut extended = salt.expose_bytes_for_test_vectors().to_vec();
    extended.push(0x00);
    ActualOutcome::from_result(Salt16::try_from_slice(SaltKind::File, &extended), code)
}

fn s_root_truncated() -> ActualOutcome {
    let s_root = derive_fine_seed(w(), FIXTURE_FILE_ID);
    ActualOutcome::from_result(Seed32::try_from(&s_root.as_bytes()[..31]), code)
}

fn node_hash_extended() -> ActualOutcome {
    // A real 32-byte digest standing in for a boundary Merkle node hash.
    let node = unit_commit(&derive_unit_salt(w(), FIXTURE_UNIT_ID), FIXTURE_UNIT_BYTES);
    let mut extended = node.to_vec();
    extended.push(0x00);
    ActualOutcome::from_result(NodeHash32::try_from(extended.as_slice()), code)
}

// ---------------------------------------------------------------------------
// (3) wrong key — a genuine encrypted unit, opened under another `W`
// ---------------------------------------------------------------------------

/// Encrypt the fixture unit reproducibly (the AEAD draws its own nonce, so
/// the generator — not a nonce — is what gets injected; see
/// [`super::fixture_rng`]). Public because R7's bundle-level fixtures need
/// the *same* ciphertext this row mutates around.
///
/// # Errors
///
/// [`CryptoError::RngFailure`] only, and only if the fixture generator
/// itself fails — it cannot.
pub fn encrypt_fixture_unit() -> Result<(Vec<u8>, crate::crypto::unit_aead::Nonce24), CryptoError> {
    let mut rng = FixtureRng::from_seed(FIXTURE_RNG_SEED);
    encrypt_unit(
        w(),
        &SealId::from_bytes(FIXTURE_SEAL_ID),
        FIXTURE_UNIT_ID,
        FIXTURE_UNIT_BYTES,
        &mut rng,
    )
}

fn unit_aead_wrong_key() -> ActualOutcome {
    let (ciphertext, nonce) = match encrypt_fixture_unit() {
        Ok(pair) => pair,
        // Surfacing the error as an outcome (rather than unwrapping) keeps
        // the no-panic rule: a broken fixture shows up as a wrong code.
        Err(err) => return ActualOutcome::ErrorCode(err.code().to_owned()),
    };
    let other = alternate_test_secret(WRONG_KEY_LABEL);
    ActualOutcome::from_result(
        decrypt_unit(
            MasterSecretRef::from_bytes(&other),
            &SealId::from_bytes(FIXTURE_SEAL_ID),
            FIXTURE_UNIT_ID,
            &nonce,
            &ciphertext,
            FIXTURE_UNIT_BYTES.len(),
        ),
        code,
    )
}

// ---------------------------------------------------------------------------
// (4-7) sig_policy — C14's hard-fail classes
// ---------------------------------------------------------------------------

/// The honest hybrid material over [`FIXTURE_BODY`]: `(pubkeys, signatures)`
/// in policy order. Public so R7 can build a bundle around the same signed
/// body these rows mutate.
#[must_use]
pub fn hybrid_material() -> (AlgMaterial, AlgMaterial) {
    let policy = SigPolicy::hybrid();
    (
        public_keys(w(), &policy),
        sign_body(w(), &policy, FIXTURE_BODY),
    )
}

fn sig_policy_empty() -> ActualOutcome {
    // The parse-time reject: a manifest whose sig_policy lists nothing can
    // never verify vacuously (spec line 97).
    ActualOutcome::from_result(SigPolicy::new([]), code)
}

fn sig_policy_duplicate() -> ActualOutcome {
    ActualOutcome::from_result(SigPolicy::new([SigAlg::Ed25519, SigAlg::Ed25519]), code)
}

fn sig_policy_unknown_alg() -> ActualOutcome {
    // Wire id 7 is in the reserved 2..=15 band: unregistered, so a verifier
    // would otherwise be asked to honour an algorithm it cannot check.
    ActualOutcome::from_result(SigPolicy::from_ids([0, 7]), code)
}

fn sig_policy_missing_signature() -> ActualOutcome {
    let policy = SigPolicy::hybrid();
    let (keys, mut sigs) = hybrid_material();
    sigs.retain(|(alg, _)| *alg != SigAlg::MlDsa65);
    ActualOutcome::from_result(verify_body(&policy, &keys, &sigs, FIXTURE_BODY), code)
}

fn sig_policy_invalid_signature() -> ActualOutcome {
    let policy = SigPolicy::hybrid();
    let (keys, mut sigs) = hybrid_material();
    let other = alternate_test_secret(WRONG_KEY_LABEL);
    let other_w = MasterSecretRef::from_bytes(&other);
    for entry in &mut sigs {
        if entry.0 == SigAlg::Ed25519 {
            entry.1 = sig_ed25519::sign(other_w, FIXTURE_BODY).as_bytes().to_vec();
        }
    }
    ActualOutcome::from_result(verify_body(&policy, &keys, &sigs, FIXTURE_BODY), code)
}

fn sig_policy_unlisted_signature() -> ActualOutcome {
    // Policy lists Ed25519 only, but a *valid* ML-DSA signature rides along:
    // the present set must EQUAL the policy set, so this is a hard failure
    // even though nothing about the extra signature is wrong.
    let policy = SigPolicy::ed25519_only();
    let keys = public_keys(w(), &policy);
    let mut sigs = sign_body(w(), &policy, FIXTURE_BODY);
    sigs.push((
        SigAlg::MlDsa65,
        sig_mldsa::sign(w(), FIXTURE_BODY).as_bytes().to_vec(),
    ));
    ActualOutcome::from_result(verify_body(&policy, &keys, &sigs, FIXTURE_BODY), code)
}

// ---------------------------------------------------------------------------
// (8-9) non-canonical signature encodings, through the verifier path
// ---------------------------------------------------------------------------

/// `s + L`: the same scalar mod `L`, a non-canonical encoding — the classic
/// RFC 8032 malleability maul. Public as a mutation helper (R7).
#[must_use]
pub fn maul_ed25519_s_out_of_range(signature: &[u8]) -> Vec<u8> {
    /// `L`, little-endian (RFC 8032 §5.1).
    const L_LE: [u8; 32] = [
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde,
        0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x10,
    ];
    let mut mauled = signature.to_vec();
    if mauled.len() != 64 {
        return mauled;
    }
    let mut carry = 0u16;
    for i in 0..32 {
        let v = u16::from(mauled[32 + i]) + u16::from(L_LE[i]) + carry;
        mauled[32 + i] = (v & 0xff) as u8;
        carry = v >> 8;
    }
    mauled
}

/// Overwrite the hint region so the cumulative cut exceeds ω = 55 — a
/// FIPS 204 Algorithm 21 step 4 violation, rejected at `sigDecode`. Public
/// as a mutation helper (R7).
#[must_use]
pub fn maul_mldsa_hint_count(signature: &[u8]) -> Vec<u8> {
    let mut mauled = signature.to_vec();
    if mauled.len() != sig_mldsa::SIGNATURE_LEN {
        return mauled;
    }
    mauled[OFFSET_HINT_INDICES..].fill(0);
    let over = u8::try_from(OMEGA + 1).unwrap_or(u8::MAX);
    mauled[OFFSET_HINT_CUTS..].fill(over);
    mauled
}

fn non_canonical_ed25519_s() -> ActualOutcome {
    let policy = SigPolicy::hybrid();
    let (keys, mut sigs) = hybrid_material();
    for entry in &mut sigs {
        if entry.0 == SigAlg::Ed25519 {
            entry.1 = maul_ed25519_s_out_of_range(&entry.1);
        }
    }
    ActualOutcome::from_result(verify_body(&policy, &keys, &sigs, FIXTURE_BODY), code)
}

fn non_canonical_mldsa_encoding() -> ActualOutcome {
    // The Ed25519 half stays honest, so the verdict is attributable to the
    // ML-DSA encoding alone (policy order checks Ed25519 first).
    let policy = SigPolicy::hybrid();
    let (keys, mut sigs) = hybrid_material();
    for entry in &mut sigs {
        if entry.0 == SigAlg::MlDsa65 {
            entry.1 = maul_mldsa_hint_count(&entry.1);
        }
    }
    ActualOutcome::from_result(verify_body(&policy, &keys, &sigs, FIXTURE_BODY), code)
}

// ---------------------------------------------------------------------------
// the registry slice
// ---------------------------------------------------------------------------

/// C's M0 tamper rows. Row ids are permanent handles; see the harness docs
/// ([`super::tamper`]) for the add-a-row procedure and
/// `docs/testing/error-code-contract.md` for why an expected code may never
/// be edited to make a failing run pass.
pub const ROWS: &[TamperRow] = &[
    // (1) wrong salt
    TamperRow {
        id: "crypto-unit-commit-wrong-salt",
        base: "committed-unit",
        mutation: "flip one bit of the disclosed unit_salt",
        expected: ExpectedOutcome::ErrorCode("crypto-unit-commit-mismatch"),
        exercise: unit_commit_wrong_salt,
    },
    TamperRow {
        id: "crypto-path-commit-wrong-salt",
        base: "committed-path",
        mutation: "flip one bit of the disclosed path_salt",
        expected: ExpectedOutcome::ErrorCode("crypto-path-commit-mismatch"),
        exercise: path_commit_wrong_salt,
    },
    TamperRow {
        id: "crypto-raw-commit-wrong-salt",
        base: "full-file-reveal",
        mutation: "flip one bit of the disclosed file_salt, opening raw_commit",
        expected: ExpectedOutcome::ErrorCode("crypto-raw-commit-mismatch"),
        exercise: raw_commit_wrong_salt,
    },
    TamperRow {
        id: "crypto-canon-commit-wrong-salt",
        base: "full-file-reveal",
        mutation: "flip one bit of the disclosed file_salt, opening canon_commit",
        expected: ExpectedOutcome::ErrorCode("crypto-canon-commit-mismatch"),
        exercise: canon_commit_wrong_salt,
    },
    // (2) wrong-length salt / seed / node hash
    TamperRow {
        id: "crypto-unit-salt-wrong-length",
        base: "committed-unit",
        mutation: "truncate the disclosed unit_salt to 15 bytes",
        expected: ExpectedOutcome::ErrorCode("crypto-unit-salt-length"),
        exercise: unit_salt_truncated,
    },
    TamperRow {
        id: "crypto-file-salt-wrong-length",
        base: "full-file-reveal",
        mutation: "append a byte to the disclosed file_salt (17 bytes)",
        expected: ExpectedOutcome::ErrorCode("crypto-file-salt-length"),
        exercise: file_salt_extended,
    },
    TamperRow {
        id: "crypto-s-root-wrong-length",
        base: "full-file-reveal",
        mutation: "truncate the disclosed s_root to 31 bytes",
        expected: ExpectedOutcome::ErrorCode("crypto-seed-length"),
        exercise: s_root_truncated,
    },
    TamperRow {
        id: "crypto-node-hash-wrong-length",
        base: "boundary-node-hash",
        mutation: "append a byte to a boundary Merkle node hash (33 bytes)",
        expected: ExpectedOutcome::ErrorCode("crypto-node-hash-length"),
        exercise: node_hash_extended,
    },
    // (3) wrong key
    TamperRow {
        id: "crypto-unit-aead-wrong-key",
        base: "encrypted-unit",
        mutation: "decrypt under a different master secret W",
        expected: ExpectedOutcome::ErrorCode("crypto-aead-decrypt-failed"),
        exercise: unit_aead_wrong_key,
    },
    // (4-7) sig_policy
    TamperRow {
        id: "crypto-sig-policy-empty",
        base: "hybrid-signed-body",
        mutation: "strip every algorithm from sig_policy",
        expected: ExpectedOutcome::ErrorCode("crypto-sig-policy-empty"),
        exercise: sig_policy_empty,
    },
    TamperRow {
        id: "crypto-sig-policy-duplicate",
        base: "hybrid-signed-body",
        mutation: "list ed25519 twice in sig_policy",
        expected: ExpectedOutcome::ErrorCode("crypto-sig-policy-duplicate"),
        exercise: sig_policy_duplicate,
    },
    TamperRow {
        id: "crypto-sig-policy-unknown-alg",
        base: "hybrid-signed-body",
        mutation: "add reserved algorithm id 7 to sig_policy",
        expected: ExpectedOutcome::ErrorCode("crypto-sig-policy-unknown-alg"),
        exercise: sig_policy_unknown_alg,
    },
    TamperRow {
        id: "crypto-sig-policy-missing-signature",
        base: "hybrid-signed-body",
        mutation: "delete the ML-DSA-65 signature, leaving one good signature",
        expected: ExpectedOutcome::ErrorCode("crypto-signature-missing-ml-dsa-65"),
        exercise: sig_policy_missing_signature,
    },
    TamperRow {
        id: "crypto-sig-policy-invalid-signature",
        base: "hybrid-signed-body",
        mutation: "replace the Ed25519 signature with one by another author",
        expected: ExpectedOutcome::ErrorCode("crypto-signature-invalid-ed25519"),
        exercise: sig_policy_invalid_signature,
    },
    TamperRow {
        id: "crypto-sig-policy-unlisted-signature",
        base: "ed25519-only-signed-body",
        mutation: "add a valid ML-DSA-65 signature the policy does not list",
        expected: ExpectedOutcome::ErrorCode("crypto-signature-unlisted-ml-dsa-65"),
        exercise: sig_policy_unlisted_signature,
    },
    // (8-9) non-canonical signature encodings
    TamperRow {
        id: "crypto-non-canonical-ed25519-s",
        base: "hybrid-signed-body",
        mutation: "maul the Ed25519 S to S + L (same scalar, non-canonical encoding)",
        expected: ExpectedOutcome::ErrorCode("crypto-non-canonical-signature-ed25519"),
        exercise: non_canonical_ed25519_s,
    },
    TamperRow {
        id: "crypto-non-canonical-mldsa-hints",
        base: "hybrid-signed-body",
        mutation: "raise the ML-DSA hint cut above omega = 55",
        expected: ExpectedOutcome::ErrorCode("crypto-non-canonical-signature-ml-dsa-65"),
        exercise: non_canonical_mldsa_encoding,
    },
];

/// Mutation helpers R7's **committed bundle-level fixtures** reuse, gathered
/// under one name so the seam is explicit rather than implied (C17 accept:
/// "the mutation helpers … are exported for R7's committed bundle-level
/// fixtures").
///
/// | helper | family |
/// | --- | --- |
/// | [`Salt16::try_from_slice`] / [`Seed32::try_from`] / [`NodeHash32::try_from`] | wrong-length salt / seed / node hash |
/// | [`crate::crypto::unit_aead::mis_encrypt::encrypt_unit_overpadded`] | over-padded unit |
/// | [`crate::crypto::unit_aead::mis_encrypt::encrypt_unit_nonzero_padding`] | non-zero pad byte |
/// | [`super::alternate_test_secret`] | wrong key / wrong author |
/// | [`maul_ed25519_s_out_of_range`] | non-canonical Ed25519 `S` |
/// | [`maul_mldsa_hint_count`] | non-canonical ML-DSA encoding |
/// | [`encrypt_fixture_unit`] / [`hybrid_material`] | the base artifacts to mutate |
pub mod helpers {
    pub use super::{
        encrypt_fixture_unit, hybrid_material, maul_ed25519_s_out_of_range, maul_mldsa_hint_count,
    };
    pub use crate::crypto::unit_aead::mis_encrypt::{
        encrypt_unit_nonzero_padding, encrypt_unit_overpadded,
    };
}
