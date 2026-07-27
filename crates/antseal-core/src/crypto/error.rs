//! Crypto error taxonomy (tasks/C.md C4) — one distinct variant per failure
//! class, sized for the tamper matrix's distinct-error requirement
//! (MVP-SPEC.md line 168: *every mutation fails with a distinct error*).
//!
//! # Secret-redaction discipline (project rules 4 and 6)
//!
//! **No variant carries key, salt, seed, or plaintext bytes** — only kinds,
//! lengths, offsets, and ids. This is structural: every payload field is a
//! `usize` or a closed kind enum, so no code path can smuggle input bytes
//! into a `Debug`/`Display` rendering. The exact-string `Display` tests
//! below pin the rendered output of every variant; any future field addition
//! must keep this property and update those tests deliberately.

use core::fmt;
use thiserror::Error;

/// Which salted commitment failed to verify
/// (MVP-SPEC.md lines 94–96; names as the spec spells them).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum CommitmentKind {
    /// `unit_commit` (spec line 94) — non-fine-tree-covered units only.
    Unit,
    /// `raw_commit` (spec line 95).
    Raw,
    /// `canon_commit` (spec line 95) — text files only.
    Canon,
    /// `path_commit` (spec line 95).
    Path,
    /// `fine_root` (spec line 96) — leaf-range/boundary-path check failure;
    /// carried for G's fine-tree verification.
    FineRoot,
}

impl CommitmentKind {
    /// Every kind, for pairwise-distinctness tests.
    pub const ALL: [Self; 5] = [
        Self::Unit,
        Self::Raw,
        Self::Canon,
        Self::Path,
        Self::FineRoot,
    ];
}

impl fmt::Display for CommitmentKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Unit => "unit_commit",
            Self::Raw => "raw_commit",
            Self::Canon => "canon_commit",
            Self::Path => "path_commit",
            Self::FineRoot => "fine_root",
        })
    }
}

/// Which 16-byte salt had the wrong length (MVP-SPEC.md lines 94–95; the
/// verifier length-checks every bundle-supplied salt, spec line 96 end).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SaltKind {
    /// `unit_salt` (spec line 94).
    Unit,
    /// `path_salt` (spec line 95).
    Path,
    /// `file_salt` (spec line 95).
    File,
}

impl SaltKind {
    /// Every kind, for pairwise-distinctness tests.
    pub const ALL: [Self; 3] = [Self::Unit, Self::Path, Self::File];
}

impl fmt::Display for SaltKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Unit => "unit_salt",
            Self::Path => "path_salt",
            Self::File => "file_salt",
        })
    }
}

/// Signature algorithm identifier as carried in error payloads
/// (MVP-SPEC.md line 97: hybrid Ed25519 + ML-DSA-65).
///
/// C14 seam: the registered `sig_policy` algorithm-ID registry (numeric IDs
/// coordinated with F's CBOR schema) lands in `crypto::sig_policy` (C14) and
/// adopts this type; C4 defines it only so signature errors can name their
/// algorithm without carrying bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SigAlg {
    /// Ed25519 (RFC 8032, strict verification per spec line 97).
    Ed25519,
    /// ML-DSA-65 (FIPS 204, canonical-encoding verification per spec line 97).
    MlDsa65,
}

impl SigAlg {
    /// Every registered algorithm, for pairwise-distinctness tests.
    pub const ALL: [Self; 2] = [Self::Ed25519, Self::MlDsa65];
}

impl fmt::Display for SigAlg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Ed25519 => "ed25519",
            Self::MlDsa65 => "ml-dsa-65",
        })
    }
}

/// Every crypto failure class, one distinct variant each (tasks/C.md C4;
/// MVP-SPEC.md line 168). Payloads are kinds/lengths/offsets only — never
/// secret or input bytes (module docs).
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CryptoError {
    /// A salted commitment did not verify (wrong salt, wrong bytes, or a
    /// mismatched commitment value). Tamper-matrix row: *wrong salt* /
    /// *altered manifest field* (spec line 168).
    #[error("{kind} commitment mismatch")]
    CommitmentMismatch {
        /// Which commitment failed.
        kind: CommitmentKind,
    },

    /// A bundle-supplied salt is not exactly 16 bytes. Tamper-matrix row:
    /// *wrong-length salt* (spec line 168); structural check executed via
    /// C6's `Salt16::try_from` in R's verifier path.
    #[error("{kind} has invalid length: expected {expected} bytes, got {got}")]
    SaltLength {
        /// Which salt was mis-sized.
        kind: SaltKind,
        /// Required length in bytes (16).
        expected: usize,
        /// Length actually supplied.
        got: usize,
    },

    /// A bundle-supplied 32-byte seed (`s_root` / GGM covering seed) has the
    /// wrong length. Tamper-matrix row: *wrong-length seed* (spec line 168).
    #[error("seed has invalid length: expected {expected} bytes, got {got}")]
    SeedLength {
        /// Required length in bytes (32).
        expected: usize,
        /// Length actually supplied.
        got: usize,
    },

    /// A bundle-supplied 32-byte Merkle boundary node hash has the wrong
    /// length (spec lines 96, 168).
    #[error("node hash has invalid length: expected {expected} bytes, got {got}")]
    NodeHashLength {
        /// Required length in bytes (32).
        expected: usize,
        /// Length actually supplied.
        got: usize,
    },

    /// AEAD decryption/authentication failed (wrong key, wrong nonce, wrong
    /// AAD, or tampered ciphertext — deliberately not distinguished, as the
    /// AEAD cannot tell). Tamper-matrix rows: *flipped ciphertext byte*,
    /// *wrong key* (spec line 168). Fires before, and distinctly from, the
    /// padding checks, which run only on successfully decrypted plaintext.
    #[error("AEAD decryption failed")]
    AeadDecryptFailed,

    /// Decrypted unit plaintext length ≠ `padded_length(true_length)` —
    /// blocks silent over-padding (spec lines 91, 121; tamper-matrix row
    /// *over-padded unit*, line 168).
    #[error("padding length mismatch: expected {expected} bytes of padded plaintext, got {got}")]
    PaddingLengthMismatch {
        /// `padded_length(true_length)` per the spec formula.
        expected: usize,
        /// Decrypted plaintext length actually seen.
        got: usize,
    },

    /// A pad byte beyond `true_length` is non-zero. Companion reject to
    /// [`CryptoError::PaddingLengthMismatch`] (spec line 91).
    #[error("non-zero padding byte at offset {offset}")]
    NonZeroPadding {
        /// Offset (within the padded plaintext) of the first offending byte.
        offset: usize,
    },

    /// `sig_policy` is empty — rejected at parse time so a signature-less
    /// manifest can never verify vacuously (spec line 97).
    #[error("sig_policy is empty")]
    SigPolicyEmpty,

    /// `sig_policy` lists the same algorithm more than once (spec line 97).
    #[error("sig_policy contains a duplicate algorithm id")]
    SigPolicyDuplicate,

    /// `sig_policy` lists an unregistered algorithm id (spec line 97).
    #[error("sig_policy lists an unregistered algorithm id")]
    SigPolicyUnknownAlg,

    /// A policy-listed signature is absent. The hybrid rule — present
    /// signature set MUST equal the policy set — hard-fails here rather than
    /// passing on one good signature (spec line 97; tamper matrix line 168).
    #[error("signature missing for policy-listed algorithm {alg}")]
    SignatureMissing {
        /// The policy-listed algorithm whose signature is absent.
        alg: SigAlg,
    },

    /// A signature is well-formed but does not verify over the body bytes
    /// (wrong key or wrong message).
    #[error("signature invalid for algorithm {alg}")]
    SignatureInvalid {
        /// The algorithm whose signature failed verification.
        alg: SigAlg,
    },

    /// A signature is present for an algorithm the policy does not list —
    /// hard failure per the present-set = policy-set rule (spec line 97).
    #[error("signature present but not listed in sig_policy: {alg}")]
    SignatureUnlisted {
        /// The unlisted algorithm.
        alg: SigAlg,
    },

    /// A signature failed strict/canonical encoding checks — Ed25519
    /// non-canonical `S ≥ L` or small-order/non-canonical `R`/`A`
    /// (RFC 8032 `verify_strict`), or a non-canonical/out-of-range ML-DSA-65
    /// encoding (hint/`z` bounds). Distinct from
    /// [`CryptoError::SignatureInvalid`] — mauled-but-strict-invalid vs
    /// wrong-signature-over-right-bytes (spec lines 97, 168).
    #[error("non-canonical signature encoding for algorithm {alg}")]
    NonCanonicalSignature {
        /// The algorithm whose signature encoding is non-canonical.
        alg: SigAlg,
    },

    /// The operating system CSPRNG failed to supply randomness. C1–C4 draw
    /// no randomness; this variant serves C5's generation and C9's
    /// nonce-drawing paths.
    #[error("random number generator failure")]
    RngFailure,
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::discriminant;
    use std::error::Error as _;

    /// One instance of every variant, dummy payloads. The payload numbers are
    /// deliberately recognizable so the Display tests can prove that only
    /// *these* sanctioned metadata values — and no byte content — appear.
    fn one_of_each() -> Vec<CryptoError> {
        vec![
            CryptoError::CommitmentMismatch {
                kind: CommitmentKind::Unit,
            },
            CryptoError::SaltLength {
                kind: SaltKind::File,
                expected: 16,
                got: 17,
            },
            CryptoError::SeedLength {
                expected: 32,
                got: 31,
            },
            CryptoError::NodeHashLength {
                expected: 32,
                got: 33,
            },
            CryptoError::AeadDecryptFailed,
            CryptoError::PaddingLengthMismatch {
                expected: 256,
                got: 512,
            },
            CryptoError::NonZeroPadding { offset: 42 },
            CryptoError::SigPolicyEmpty,
            CryptoError::SigPolicyDuplicate,
            CryptoError::SigPolicyUnknownAlg,
            CryptoError::SignatureMissing {
                alg: SigAlg::MlDsa65,
            },
            CryptoError::SignatureInvalid {
                alg: SigAlg::Ed25519,
            },
            CryptoError::SignatureUnlisted {
                alg: SigAlg::Ed25519,
            },
            CryptoError::NonCanonicalSignature {
                alg: SigAlg::MlDsa65,
            },
            CryptoError::RngFailure,
        ]
    }

    /// C4 accept: pairwise-distinct discriminants across all variants used by
    /// tamper-matrix rows.
    #[test]
    fn discriminants_pairwise_distinct() {
        let all = one_of_each();
        assert_eq!(
            all.len(),
            15,
            "keep this list exhaustive when adding variants"
        );
        for i in 0..all.len() {
            for j in (i + 1)..all.len() {
                assert_ne!(
                    discriminant(&all[i]),
                    discriminant(&all[j]),
                    "{:?} vs {:?}",
                    all[i],
                    all[j]
                );
            }
        }
    }

    /// C4 accept: `Display` output of every variant, constructed with dummy
    /// data, contains no input byte content. Exact-string comparison — only
    /// sanctioned metadata (kind names, lengths, offsets) may render, and any
    /// change to a rendering is a reviewed event.
    #[test]
    fn display_renders_metadata_only() {
        let expected: [(CryptoError, &str); 15] = [
            (
                CryptoError::CommitmentMismatch {
                    kind: CommitmentKind::Unit,
                },
                "unit_commit commitment mismatch",
            ),
            (
                CryptoError::SaltLength {
                    kind: SaltKind::File,
                    expected: 16,
                    got: 17,
                },
                "file_salt has invalid length: expected 16 bytes, got 17",
            ),
            (
                CryptoError::SeedLength {
                    expected: 32,
                    got: 31,
                },
                "seed has invalid length: expected 32 bytes, got 31",
            ),
            (
                CryptoError::NodeHashLength {
                    expected: 32,
                    got: 33,
                },
                "node hash has invalid length: expected 32 bytes, got 33",
            ),
            (CryptoError::AeadDecryptFailed, "AEAD decryption failed"),
            (
                CryptoError::PaddingLengthMismatch {
                    expected: 256,
                    got: 512,
                },
                "padding length mismatch: expected 256 bytes of padded plaintext, got 512",
            ),
            (
                CryptoError::NonZeroPadding { offset: 42 },
                "non-zero padding byte at offset 42",
            ),
            (CryptoError::SigPolicyEmpty, "sig_policy is empty"),
            (
                CryptoError::SigPolicyDuplicate,
                "sig_policy contains a duplicate algorithm id",
            ),
            (
                CryptoError::SigPolicyUnknownAlg,
                "sig_policy lists an unregistered algorithm id",
            ),
            (
                CryptoError::SignatureMissing {
                    alg: SigAlg::MlDsa65,
                },
                "signature missing for policy-listed algorithm ml-dsa-65",
            ),
            (
                CryptoError::SignatureInvalid {
                    alg: SigAlg::Ed25519,
                },
                "signature invalid for algorithm ed25519",
            ),
            (
                CryptoError::SignatureUnlisted {
                    alg: SigAlg::Ed25519,
                },
                "signature present but not listed in sig_policy: ed25519",
            ),
            (
                CryptoError::NonCanonicalSignature {
                    alg: SigAlg::MlDsa65,
                },
                "non-canonical signature encoding for algorithm ml-dsa-65",
            ),
            (CryptoError::RngFailure, "random number generator failure"),
        ];
        for (err, want) in expected {
            assert_eq!(err.to_string(), want);
            // No variant exposes hex-formatted byte content.
            assert!(!err.to_string().contains("0x"), "{err}");
        }
    }

    /// Kind enums render the spec's own names and are pairwise distinct.
    #[test]
    fn kind_enums_render_spec_names() {
        let commitment_names: Vec<String> = CommitmentKind::ALL
            .iter()
            .map(ToString::to_string)
            .collect();
        assert_eq!(
            commitment_names,
            [
                "unit_commit",
                "raw_commit",
                "canon_commit",
                "path_commit",
                "fine_root"
            ]
        );
        let salt_names: Vec<String> = SaltKind::ALL.iter().map(ToString::to_string).collect();
        assert_eq!(salt_names, ["unit_salt", "path_salt", "file_salt"]);
        let alg_names: Vec<String> = SigAlg::ALL.iter().map(ToString::to_string).collect();
        assert_eq!(alg_names, ["ed25519", "ml-dsa-65"]);
    }

    /// `CryptoError` implements `std::error::Error` (thiserror) with no
    /// source chain that could leak wrapped input.
    #[test]
    fn error_trait_no_source() {
        for err in one_of_each() {
            assert!(err.source().is_none(), "{err}");
        }
    }
}
