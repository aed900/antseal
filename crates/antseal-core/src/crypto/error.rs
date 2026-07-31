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

/// Which per-algorithm material collection carried a duplicate entry — the
/// body's `pubkeys` map or the envelope's `signatures` map, as enumerated
/// for `crypto::sig_policy::verify_body` (C28). Named after the registry
/// maps themselves (MVP-SPEC.md line 97), matching the wire schema's
/// `manifest::sigmap::SigMaterial` naming.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SigMaterialKind {
    /// The body's `pubkeys` map.
    Pubkeys,
    /// The envelope's `signatures` map.
    Signatures,
}

impl SigMaterialKind {
    /// Every kind, for pairwise-distinctness tests.
    pub const ALL: [Self; 2] = [Self::Pubkeys, Self::Signatures];
}

impl fmt::Display for SigMaterialKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Pubkeys => "pubkeys",
            Self::Signatures => "signatures",
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

    /// A `pubkeys` or `signatures` collection carries the same algorithm
    /// more than once. F's schema makes this unrepresentable on the wire (a
    /// repeated map key is `cbor-duplicate-map-key`), and
    /// `crypto::sig_policy::verify_body` re-checks it (C28) so its
    /// first-wins entry lookup can never silently pick one of two
    /// conflicting entries on non-schema input — the cross-implementation
    /// divergence class MVP-SPEC.md line 73 names. Deliberately **not** a
    /// reuse of [`CryptoError::SigPolicyDuplicate`], which asserts a
    /// different fact (the *policy list* repeats an algorithm; here the
    /// policy is valid and a *material map* repeats a key). The duplicated
    /// algorithm rides as payload rather than fanning the code, because the
    /// failed check is the per-collection duplicate scan — codes name the
    /// check, not the field (`docs/testing/error-code-contract.md`,
    /// D85/R33 entry).
    #[error("{kind} contains a duplicate entry for algorithm {alg}")]
    SigMaterialDuplicate {
        /// Which collection carried the duplicate.
        kind: SigMaterialKind,
        /// The duplicated algorithm.
        alg: SigAlg,
    },

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

impl CryptoError {
    /// Stable machine-readable code, pairwise-distinct across every
    /// (variant, discriminant) pair — the C-side leg of Q7's error-code
    /// stability contract (open decision D30), delegated through
    /// `verify::VerifyError::Crypto` exactly like the codec's `cbor-*`
    /// codes (F3 precedent). Lowercase kebab-case, `crypto-` prefixed so
    /// the global tamper matrix stays distinct across domains (the
    /// unprefixed forms would collide with R's verify-side codes, e.g.
    /// `non-zero-padding`); never changes once a tamper row binds to it.
    ///
    /// The exhaustive, wildcard-free match is the compile-time guard: a
    /// new variant (or a new [`CommitmentKind`]/[`SaltKind`]/[`SigAlg`]
    /// discriminant) fails compilation here until it receives a distinct
    /// code — and an exemplar in `all_code_exemplars`.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::CommitmentMismatch { kind } => match kind {
                CommitmentKind::Unit => "crypto-unit-commit-mismatch",
                CommitmentKind::Raw => "crypto-raw-commit-mismatch",
                CommitmentKind::Canon => "crypto-canon-commit-mismatch",
                CommitmentKind::Path => "crypto-path-commit-mismatch",
                CommitmentKind::FineRoot => "crypto-fine-root-commit-mismatch",
            },
            Self::SaltLength { kind, .. } => match kind {
                SaltKind::Unit => "crypto-unit-salt-length",
                SaltKind::Path => "crypto-path-salt-length",
                SaltKind::File => "crypto-file-salt-length",
            },
            Self::SeedLength { .. } => "crypto-seed-length",
            Self::NodeHashLength { .. } => "crypto-node-hash-length",
            Self::AeadDecryptFailed => "crypto-aead-decrypt-failed",
            Self::PaddingLengthMismatch { .. } => "crypto-padding-length-mismatch",
            Self::NonZeroPadding { .. } => "crypto-non-zero-padding",
            Self::SigPolicyEmpty => "crypto-sig-policy-empty",
            Self::SigPolicyDuplicate => "crypto-sig-policy-duplicate",
            Self::SigPolicyUnknownAlg => "crypto-sig-policy-unknown-alg",
            // Fans out per collection only: the duplicated algorithm is
            // payload, not a code discriminant (see the variant docs).
            Self::SigMaterialDuplicate { kind, .. } => match kind {
                SigMaterialKind::Pubkeys => "crypto-pubkeys-duplicate",
                SigMaterialKind::Signatures => "crypto-signatures-duplicate",
            },
            Self::SignatureMissing { alg } => match alg {
                SigAlg::Ed25519 => "crypto-signature-missing-ed25519",
                SigAlg::MlDsa65 => "crypto-signature-missing-ml-dsa-65",
            },
            Self::SignatureInvalid { alg } => match alg {
                SigAlg::Ed25519 => "crypto-signature-invalid-ed25519",
                SigAlg::MlDsa65 => "crypto-signature-invalid-ml-dsa-65",
            },
            Self::SignatureUnlisted { alg } => match alg {
                SigAlg::Ed25519 => "crypto-signature-unlisted-ed25519",
                SigAlg::MlDsa65 => "crypto-signature-unlisted-ml-dsa-65",
            },
            Self::NonCanonicalSignature { alg } => match alg {
                SigAlg::Ed25519 => "crypto-non-canonical-signature-ed25519",
                SigAlg::MlDsa65 => "crypto-non-canonical-signature-ml-dsa-65",
            },
            Self::RngFailure => "crypto-rng-failure",
        }
    }
}

/// One exemplar per distinct [`CryptoError::code`] — every (variant,
/// code-fanning discriminant) pair exactly once, with pairwise-distinct
/// `Display` renderings (payload values chosen so no two collide).
/// Payload-only fields — lengths, offsets, and `SigMaterialDuplicate`'s
/// `alg` — are held at a fixed value, since they do not change the code. Consumed by this
/// module's code tests and by `verify::error::all_error_exemplars`, which
/// wraps each in the `VerifyError::Crypto` arm so the R-side distinctness
/// meta-test covers the delegated codes too (F3's `cbor-*` precedent).
///
/// Also the **code universe** the C15 vector executor and the C17 tamper
/// rows validate their expected codes against: a committed artifact naming
/// a code no variant can emit is a typo, and this list is what catches it.
/// `test-util` only — no production build sees it.
#[cfg(any(test, feature = "test-vectors"))]
#[must_use]
pub fn all_code_exemplars() -> Vec<CryptoError> {
    use CryptoError as E;
    let mut exemplars = Vec::new();
    for kind in CommitmentKind::ALL {
        exemplars.push(E::CommitmentMismatch { kind });
    }
    for kind in SaltKind::ALL {
        exemplars.push(E::SaltLength {
            kind,
            expected: 16,
            got: 17,
        });
    }
    exemplars.extend([
        E::SeedLength {
            expected: 32,
            got: 31,
        },
        E::NodeHashLength {
            expected: 32,
            got: 33,
        },
        E::AeadDecryptFailed,
        E::PaddingLengthMismatch {
            expected: 256,
            got: 512,
        },
        E::NonZeroPadding { offset: 42 },
        E::SigPolicyEmpty,
        E::SigPolicyDuplicate,
        E::SigPolicyUnknownAlg,
    ]);
    for kind in SigMaterialKind::ALL {
        exemplars.push(E::SigMaterialDuplicate {
            kind,
            alg: SigAlg::Ed25519,
        });
    }
    for alg in SigAlg::ALL {
        exemplars.extend([
            E::SignatureMissing { alg },
            E::SignatureInvalid { alg },
            E::SignatureUnlisted { alg },
            E::NonCanonicalSignature { alg },
        ]);
    }
    exemplars.push(E::RngFailure);
    exemplars
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
            CryptoError::SigMaterialDuplicate {
                kind: SigMaterialKind::Signatures,
                alg: SigAlg::Ed25519,
            },
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
            16,
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
        let expected: [(CryptoError, &str); 16] = [
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
                CryptoError::SigMaterialDuplicate {
                    kind: SigMaterialKind::Signatures,
                    alg: SigAlg::Ed25519,
                },
                "signatures contains a duplicate entry for algorithm ed25519",
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
        let material_names: Vec<String> = SigMaterialKind::ALL
            .iter()
            .map(ToString::to_string)
            .collect();
        assert_eq!(material_names, ["pubkeys", "signatures"]);
    }

    /// `CryptoError` implements `std::error::Error` (thiserror) with no
    /// source chain that could leak wrapped input.
    #[test]
    fn error_trait_no_source() {
        for err in one_of_each() {
            assert!(err.source().is_none(), "{err}");
        }
    }

    /// Stable-code contract (D30 open decision; Q7): one exemplar per
    /// (variant, code-fanning discriminant) pair — 27 in total — with
    /// pairwise-distinct `crypto-`-prefixed kebab-case codes and
    /// pairwise-distinct Display strings (the property `verify::error`'s
    /// meta-test relies on when it wraps these in the
    /// `VerifyError::Crypto` arm).
    #[test]
    fn codes_are_pairwise_distinct_and_prefixed() {
        use std::collections::BTreeSet;

        let exemplars = super::all_code_exemplars();
        assert_eq!(
            exemplars.len(),
            27,
            "one exemplar per (variant, code-fanning discriminant) pair"
        );

        let codes: BTreeSet<&'static str> = exemplars.iter().map(CryptoError::code).collect();
        assert_eq!(codes.len(), exemplars.len(), "codes pairwise distinct");
        for code in &codes {
            assert!(
                code.starts_with("crypto-"),
                "code {code:?} must carry the domain prefix"
            );
            assert!(
                code.chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'),
                "code {code:?} is not lowercase kebab-case"
            );
        }

        let displays: BTreeSet<String> = exemplars.iter().map(ToString::to_string).collect();
        assert_eq!(
            displays.len(),
            exemplars.len(),
            "displays pairwise distinct"
        );

        // Every variant of `one_of_each` (the per-variant list) is covered
        // by the per-code list — no variant can miss a code.
        for variant in one_of_each() {
            assert!(
                exemplars
                    .iter()
                    .any(|e| discriminant(e) == discriminant(&variant)),
                "{variant:?} missing from all_code_exemplars"
            );
        }
    }
}
