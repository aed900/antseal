//! The four salted commitments — compute and verify (tasks/C.md C6;
//! MVP-SPEC.md lines 93–95, 79).
//!
//! *Every* content commitment is salted: an unsalted hash anywhere would
//! re-enable the confirmation attack this design exists to prevent,
//! including against bundle recipients guessing unrevealed files (spec
//! line 93). Hiding rests on the 128-bit secret salt (random-oracle-model,
//! spec line 101); binding on standard-model SHA-256 collision resistance
//! (spec line 100).
//!
//! | commitment     | preimage (via [`tagged_sha256`])            | salt (C2 derivation)                  |
//! |----------------|---------------------------------------------|---------------------------------------|
//! | `unit_commit`  | `0x02 ‖ unit_salt ‖ unit_bytes`             | `HKDF(W, "unit-salt", unit_id)`       |
//! | `raw_commit`   | `0x03 ‖ file_salt ‖ raw_bytes`              | `HKDF(W, "file-salt", file_id)`       |
//! | `canon_commit` | `0x04 ‖ file_salt ‖ canonical_bytes` (text) | `HKDF(W, "file-salt", file_id)`       |
//! | `path_commit`  | `0x05 ‖ path_salt ‖ path_utf8`              | `HKDF(W, "path-salt", file_id)`       |
//!
//! Two independent per-file salts (spec line 95): `path_salt` ships whenever
//! any reveal *touches* the file; `file_salt` — salting both content
//! commitments — only on a full-file reveal. The type system enforces the
//! split: `file_salt` is the opaque [`FileSalt`] (disclosure only via
//! [`crate::crypto::disclosure::FullFileRevealDisclosure`]), so the
//! `raw_commit`/`canon_commit` functions are not even callable with a
//! freely-disclosed [`Salt16`] by accident.
//!
//! # Verification discipline
//!
//! Verify functions recompute the commitment and compare **constant-time**
//! (`subtle::ConstantTimeEq`) — commitment digests derive from secret salts,
//! and verdict-bearing comparisons must not leak match prefixes — returning
//! the tamper matrix's [`CryptoError::CommitmentMismatch`] with the exact
//! [`CommitmentKind`] (spec line 168: *wrong salt* / *altered manifest
//! field* fail distinctly per commitment).

use subtle::ConstantTimeEq;

use super::domain::{
    TAG_CANON_COMMIT, TAG_PATH_COMMIT, TAG_RAW_COMMIT, TAG_UNIT_COMMIT, tagged_sha256,
};
use super::error::{CommitmentKind, CryptoError};
use super::material::{FileSalt, Salt16};

/// A commitment digest as stored in the manifest (32-byte SHA-256 output).
/// Public manifest data — commitments are *hiding*, that's their point.
pub type CommitmentDigest = [u8; 32];

/// `unit_commit = SHA-256(0x02 ‖ unit_salt ‖ unit_bytes)` (spec line 94).
///
/// Present **iff** the unit is NOT fine-tree-covered — the
/// single-authoritative-commitment rule; see
/// [`crate::crypto::disclosure::UnitBinding`] (C7) for the enforcement and
/// rationale.
#[must_use]
pub fn unit_commit(unit_salt: &Salt16, unit_bytes: &[u8]) -> CommitmentDigest {
    tagged_sha256(TAG_UNIT_COMMIT, &[unit_salt.as_bytes(), unit_bytes])
}

/// `raw_commit = SHA-256(0x03 ‖ file_salt ‖ raw_bytes)` (spec line 95).
#[must_use]
pub fn raw_commit(file_salt: &FileSalt, raw_bytes: &[u8]) -> CommitmentDigest {
    tagged_sha256(TAG_RAW_COMMIT, &[file_salt.as_salt().as_bytes(), raw_bytes])
}

/// `canon_commit = SHA-256(0x04 ‖ file_salt ‖ canonical_bytes)` — text
/// files only; the canonical bytes are G's canonicalization output (spec
/// line 95). Shares `file_salt` with [`raw_commit`] by design (both are
/// full-file content commitments, disclosed together on full reveal only).
#[must_use]
pub fn canon_commit(file_salt: &FileSalt, canonical_bytes: &[u8]) -> CommitmentDigest {
    tagged_sha256(
        TAG_CANON_COMMIT,
        &[file_salt.as_salt().as_bytes(), canonical_bytes],
    )
}

/// `path_commit = SHA-256(0x05 ‖ path_salt ‖ path_utf8)` (spec line 95).
/// `path` is UTF-8 by type; file paths live in the vault, not the manifest
/// — this commitment is what the manifest carries instead.
#[must_use]
pub fn path_commit(path_salt: &Salt16, path: &str) -> CommitmentDigest {
    tagged_sha256(TAG_PATH_COMMIT, &[path_salt.as_bytes(), path.as_bytes()])
}

/// Constant-time digest comparison → the per-kind mismatch error.
fn verify(
    kind: CommitmentKind,
    computed: &CommitmentDigest,
    expected: &CommitmentDigest,
) -> Result<(), CryptoError> {
    if bool::from(computed[..].ct_eq(&expected[..])) {
        Ok(())
    } else {
        Err(CryptoError::CommitmentMismatch { kind })
    }
}

/// Verify revealed unit bytes against a manifest `unit_commit`
/// (evidence-layer step for non-covered units, spec line 118).
///
/// # Errors
///
/// [`CryptoError::CommitmentMismatch`] (`kind = Unit`) when the salt or the
/// bytes do not reproduce `expected`.
pub fn verify_unit_commit(
    unit_salt: &Salt16,
    unit_bytes: &[u8],
    expected: &CommitmentDigest,
) -> Result<(), CryptoError> {
    verify(
        CommitmentKind::Unit,
        &unit_commit(unit_salt, unit_bytes),
        expected,
    )
}

/// Verify full-reveal raw bytes against a manifest `raw_commit`.
///
/// # Errors
///
/// [`CryptoError::CommitmentMismatch`] (`kind = Raw`).
pub fn verify_raw_commit(
    file_salt: &FileSalt,
    raw_bytes: &[u8],
    expected: &CommitmentDigest,
) -> Result<(), CryptoError> {
    verify(
        CommitmentKind::Raw,
        &raw_commit(file_salt, raw_bytes),
        expected,
    )
}

/// Verify full-reveal canonical bytes against a manifest `canon_commit`.
///
/// # Errors
///
/// [`CryptoError::CommitmentMismatch`] (`kind = Canon`).
pub fn verify_canon_commit(
    file_salt: &FileSalt,
    canonical_bytes: &[u8],
    expected: &CommitmentDigest,
) -> Result<(), CryptoError> {
    verify(
        CommitmentKind::Canon,
        &canon_commit(file_salt, canonical_bytes),
        expected,
    )
}

/// Verify a disclosed path against a manifest `path_commit` (runs whenever
/// a reveal touches the file, spec line 95).
///
/// # Errors
///
/// [`CryptoError::CommitmentMismatch`] (`kind = Path`).
pub fn verify_path_commit(
    path_salt: &Salt16,
    path: &str,
    expected: &CommitmentDigest,
) -> Result<(), CryptoError> {
    verify(
        CommitmentKind::Path,
        &path_commit(path_salt, path),
        expected,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::hkdf::{FileId, UnitId, derive_file_salt, derive_path_salt};
    use crate::crypto::material::MasterSecretRef;
    use sha2::{Digest, Sha256};

    /// Fixed, public, NON-SECRET test master secret (project rule 6).
    const TEST_W: [u8; 32] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
        0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D,
        0x1E, 0x1F,
    ];

    fn test_salt() -> Salt16 {
        Salt16::from_bytes([0xA5u8; 16])
    }

    fn test_file_salt() -> FileSalt {
        FileSalt::from_disclosed(Salt16::from_bytes([0x5Au8; 16]))
    }

    /// Independent one-shot SHA-256 over `tag ‖ salt ‖ msg` — the reference
    /// each commitment must equal (C6 accept: golden fixtures computed
    /// independently of `tagged_sha256`).
    fn reference(tag: u8, salt: &[u8; 16], msg: &[u8]) -> [u8; 32] {
        let mut preimage = vec![tag];
        preimage.extend_from_slice(salt);
        preimage.extend_from_slice(msg);
        Sha256::digest(&preimage).into()
    }

    /// C6 accept: each of the four commitments over a known salt + message
    /// equals the independently computed `SHA-256(tag ‖ salt ‖ msg)`.
    #[test]
    fn four_commitments_match_independent_sha256() {
        let msg = b"the unit bytes under commitment";
        let path = "docs/chapter-one.md";

        assert_eq!(
            unit_commit(&test_salt(), msg),
            reference(0x02, &[0xA5u8; 16], msg)
        );
        assert_eq!(
            raw_commit(&test_file_salt(), msg),
            reference(0x03, &[0x5Au8; 16], msg)
        );
        assert_eq!(
            canon_commit(&test_file_salt(), msg),
            reference(0x04, &[0x5Au8; 16], msg)
        );
        assert_eq!(
            path_commit(&test_salt(), path),
            reference(0x05, &[0xA5u8; 16], path.as_bytes())
        );
    }

    /// The four domain tags actually separate: identical salt bytes +
    /// identical message give four pairwise-distinct digests.
    #[test]
    fn same_input_distinct_commitment_kinds() {
        let msg = b"same bytes";
        let salt = test_salt();
        let file_salt = FileSalt::from_disclosed(Salt16::from_bytes(*salt.as_bytes()));
        let digests = [
            unit_commit(&salt, msg),
            raw_commit(&file_salt, msg),
            canon_commit(&file_salt, msg),
            path_commit(&salt, "same bytes"),
        ];
        for i in 0..digests.len() {
            for j in (i + 1)..digests.len() {
                assert_ne!(digests[i], digests[j], "{i} vs {j}");
            }
        }
    }

    /// Verify round-trips on match and yields the exact per-kind
    /// `CommitmentMismatch` on any perturbation of salt, message, or
    /// expected digest (tamper-matrix rows *wrong salt* / *altered manifest
    /// field*, spec line 168).
    #[test]
    fn verify_matches_and_mismatches_per_kind() {
        let msg = b"unit content";
        let path = "src/lib.rs";
        let salt = test_salt();
        let file_salt = test_file_salt();

        let unit = unit_commit(&salt, msg);
        let raw = raw_commit(&file_salt, msg);
        let canon = canon_commit(&file_salt, msg);
        let path_c = path_commit(&salt, path);

        assert!(verify_unit_commit(&salt, msg, &unit).is_ok());
        assert!(verify_raw_commit(&file_salt, msg, &raw).is_ok());
        assert!(verify_canon_commit(&file_salt, msg, &canon).is_ok());
        assert!(verify_path_commit(&salt, path, &path_c).is_ok());

        // Wrong message byte.
        assert_eq!(
            verify_unit_commit(&salt, b"unit contenT", &unit).expect_err("must fail"),
            CryptoError::CommitmentMismatch {
                kind: CommitmentKind::Unit
            }
        );
        // Wrong (bit-flipped) salt.
        let mut flipped = *salt.as_bytes();
        flipped[0] ^= 0x01;
        assert_eq!(
            verify_unit_commit(&Salt16::from_bytes(flipped), msg, &unit).expect_err("must fail"),
            CryptoError::CommitmentMismatch {
                kind: CommitmentKind::Unit
            }
        );
        // Wrong expected digest (altered manifest field).
        let mut altered = raw;
        altered[31] ^= 0x80;
        assert_eq!(
            verify_raw_commit(&file_salt, msg, &altered).expect_err("must fail"),
            CryptoError::CommitmentMismatch {
                kind: CommitmentKind::Raw
            }
        );
        assert_eq!(
            verify_canon_commit(&file_salt, b"different canonical bytes", &canon)
                .expect_err("must fail"),
            CryptoError::CommitmentMismatch {
                kind: CommitmentKind::Canon
            }
        );
        assert_eq!(
            verify_path_commit(&salt, "src/lib.rS", &path_c).expect_err("must fail"),
            CryptoError::CommitmentMismatch {
                kind: CommitmentKind::Path
            }
        );
    }

    /// C6 accept: `path_salt` and `file_salt` for the same `file_id` are
    /// distinct values (independent HKDF labels, spec line 95), and
    /// disclosing one does not disclose the other — a `path_commit` opened
    /// with the *file* salt (or vice versa) fails.
    #[test]
    fn path_salt_and_file_salt_are_independent() {
        let w = MasterSecretRef::from_bytes(&TEST_W);
        let file_id = FileId(3);
        let path_salt = derive_path_salt(w, file_id);
        let file_salt = derive_file_salt(w, file_id);

        // Distinct derived values.
        assert_ne!(path_salt.as_bytes(), file_salt.as_salt().as_bytes());

        // Cross-use fails: knowing path_salt opens nothing content-side.
        let content = b"file content";
        let real_canon = canon_commit(&file_salt, content);
        let with_path_salt_as_file_salt =
            FileSalt::from_disclosed(Salt16::from_bytes(*path_salt.as_bytes()));
        assert!(verify_canon_commit(&with_path_salt_as_file_salt, content, &real_canon).is_err());

        // And knowing file_salt does not open path_commit.
        let path = "notes/secret-project.txt";
        let real_path_commit = path_commit(&path_salt, path);
        let file_salt_as_salt16 = Salt16::from_bytes(*file_salt.as_salt().as_bytes());
        assert!(verify_path_commit(&file_salt_as_salt16, path, &real_path_commit).is_err());
    }

    /// Unit salts differ per unit id — two units with identical bytes get
    /// unlinkable commitments (hiding across units of one work).
    #[test]
    fn identical_bytes_different_units_unlinkable() {
        use crate::crypto::hkdf::derive_unit_salt;
        let w = MasterSecretRef::from_bytes(&TEST_W);
        let bytes = b"identical paragraph";
        let c0 = unit_commit(&derive_unit_salt(w, UnitId(0)), bytes);
        let c1 = unit_commit(&derive_unit_salt(w, UnitId(1)), bytes);
        assert_ne!(c0, c1);
    }

    /// Empty message and empty path still commit (degenerate inputs are
    /// well-defined, no panics).
    #[test]
    fn empty_inputs_are_well_defined() {
        let salt = test_salt();
        let digest = unit_commit(&salt, b"");
        assert_eq!(digest, reference(0x02, &[0xA5u8; 16], b""));
        assert!(verify_unit_commit(&salt, b"", &digest).is_ok());
        let empty_path = path_commit(&salt, "");
        assert!(verify_path_commit(&salt, "", &empty_path).is_ok());
    }
}
