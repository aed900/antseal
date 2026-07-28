//! C18 — the crypto property suite (tasks/C.md C18; MVP-SPEC.md line 167).
//!
//! Properties over the **public** `antseal-core` API for each primitive C
//! owns: HKDF info-encoding injectivity (extending C3's raw-encoder
//! property to the registry and to the derived outputs), commitment
//! exactness including the salt/message boundary, the padding codec's
//! round-trip and rejection completeness, unit-AEAD round-trip and AAD
//! binding, and the hybrid sign/verify round-trip.
//!
//! Conventions: `docs/testing/proptest-conventions.md` (Q3) — proptest
//! arrives through the `antseal_core::test_util::proptest` re-export, every
//! block sets its own fixed seed so CI failures reproduce byte-for-byte,
//! and `PROPTEST_CASES` (raised to 1024 in the CI `test` lane) scales case
//! counts. No test name here uses the reserved `corpus_`/`vector_`
//! markers — these are properties, not byte-stability suites.
//!
//! # Failure persistence in an integration test
//!
//! Blocks here use [`strategies::integration_test_config`] rather than the
//! plain [`strategies::proptest_config`]. proptest's default persistence
//! (`SourceParallel`) locates its regressions directory by walking up from
//! the test's source file to a `lib.rs`/`main.rs`; a test in `tests/` has
//! no such ancestor, so the lookup fails and **nothing is persisted** —
//! silently defeating Q3 §5 and C18's "failure seeds are reproducible"
//! accept bullet. The explicit-path config fixes it; found failures land in
//! `crates/antseal-core/proptest-regressions/crypto_properties.txt`, which
//! is committed and never deleted.
//!
//! # Cost (measured 2026-07-28, debug build, x86_64 linux)
//!
//! At the CI lane's `PROPTEST_CASES=1024`, wall time per block: everything
//! except the signature blocks is well under 1.5 s; `ed25519_only…` is
//! ~5.6 s; **`hybrid_…` is ~92 s** and dominates the file. ML-DSA-65 costs
//! ~45 ms per operation unoptimized, and that block performs one signature
//! and one verification per case (already the minimum — see
//! [`Coverage::Core`]).
//!
//! If that becomes too slow, the levers, in order of preference: lower the
//! `test` lane's `PROPTEST_CASES`; or optimize dependencies in the dev
//! profile (`[profile.dev.package."*"] opt-level = 2`), which would speed
//! up every crypto test in the workspace. Note that the `cases` value in
//! the hybrid block **cannot** serve as the lever — see the `PROPTEST_CASES`
//! correction in `docs/testing/proptest-conventions.md` §4.
//!
//! # Relationship to the in-module property tests
//!
//! C3 (`src/crypto/hkdf.rs`) and C8 (`src/crypto/padding.rs`) already carry
//! properties next to their crate-private internals. This file deliberately
//! does not restate them: it exercises the same primitives from **outside**
//! the crate — the surface third-party verifiers see — and adds the cases
//! those in-module blocks do not reach (registry-level injectivity and
//! output distinctness; per-offset pad-byte rejection completeness).
//!
//! # wasm32 status (C18 accept, third bullet)
//!
//! "A representative subset compiled for wasm32" is blocked on **P14**, not
//! on this code: the `test-util` feature's only dependency is proptest,
//! which pulls `getrandom`, which needs the `wasm_js` recipe P14 owns —
//! so *no* proptest suite in this workspace can compile for wasm32 yet.
//! The primitives under test are all in antseal-core's default graph, which
//! does build for wasm32 today. Q5 picks this up with P14.

use antseal_core::crypto::commit::{
    canon_commit, path_commit, raw_commit, unit_commit, verify_canon_commit, verify_path_commit,
    verify_raw_commit, verify_unit_commit,
};
use antseal_core::crypto::error::{CommitmentKind, CryptoError, SigAlg};
use antseal_core::crypto::hkdf::{
    FileId, IdDomain, Label, SENTINEL_ID, UnitId, derive_file_salt, derive_fine_seed,
    derive_manifest_key, derive_path_salt, derive_sig_ed25519_seed, derive_sig_mldsa65_seed,
    derive_unit_key, derive_unit_salt,
};
use antseal_core::crypto::material::{FileSalt, MasterSecretRef, Salt16};
use antseal_core::crypto::padding::{PAD_BLOCK, apply_padding, padded_length, strip_padding};
use antseal_core::crypto::secrets::SealId;
use antseal_core::crypto::sig_policy::{SigPolicy, public_keys, sign_body, verify_body};
use antseal_core::crypto::unit_aead::{Nonce24, decrypt_unit, encrypt_unit, unit_aad};
use antseal_core::test_util::proptest::prelude::*;
use antseal_core::test_util::{TEST_MASTER_SECRET_W, strategies};

use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

/// The fixed NON-SECRET test master secret (project rule 6). Values these
/// properties generate live only in test memory; the committed-fixture
/// convention governs fixtures, not in-run values.
fn w() -> MasterSecretRef<'static> {
    MasterSecretRef::from_bytes(&TEST_MASTER_SECRET_W)
}

/// The upper bound C18 mandates for the padding properties: `4·256 + 3`,
/// i.e. four full buckets plus a partial one.
const MAX_PAD_LEN: usize = 4 * PAD_BLOCK + 3;

/// Where proptest persists any failure it finds here (module docs; Q3 §5).
/// Relative to the package root, which is `cargo test`'s working directory.
const REGRESSIONS: &str = "proptest-regressions/crypto_properties.txt";

// ---------------------------------------------------------------------------
// HKDF — registry-level injectivity and output distinctness (extends C3)
// ---------------------------------------------------------------------------

/// Derive through the public typed API, dispatching per label. Returned as
/// `Vec<u8>` because registry output lengths differ (16 vs 32 bytes).
fn derive_bytes(label: Label, id: u64) -> Vec<u8> {
    match label {
        Label::UnitKey => derive_unit_key(w(), UnitId(id)).into_bytes().to_vec(),
        Label::UnitSalt => derive_unit_salt(w(), UnitId(id)).into_bytes().to_vec(),
        Label::PathSalt => derive_path_salt(w(), FileId(id)).into_bytes().to_vec(),
        Label::FileSalt => derive_file_salt(w(), FileId(id))
            .expose_bytes_for_test_vectors()
            .to_vec(),
        Label::FineSeed => derive_fine_seed(w(), FileId(id)).into_bytes().to_vec(),
        Label::SigEd25519 => derive_sig_ed25519_seed(w()).into_bytes().to_vec(),
        Label::SigMlDsa65 => derive_sig_mldsa65_seed(w()).into_bytes().to_vec(),
        Label::ManifestKey => derive_manifest_key(w()).into_bytes().to_vec(),
    }
}

/// The id a label *actually* derives under: sentinel-domain labels take no
/// caller id, so every id collapses to [`SENTINEL_ID`] for them. Without
/// this normalization the "distinct pairs derive distinctly" property would
/// be false for the three sentinel labels — correctly so.
fn effective_id(label: Label, id: u64) -> u64 {
    match label.id_domain() {
        IdDomain::Sentinel => SENTINEL_ID,
        IdDomain::UnitId | IdDomain::FileId => id,
    }
}

proptest! {
    #![proptest_config(strategies::integration_test_config(
        0x5EED_C180,
        REGRESSIONS,
    ))]

    /// C18 (extends C3): registry-level injectivity. C3's property covers
    /// the crate-private encoder over *arbitrary byte* labels; this covers
    /// the eight **registered** labels through the public API, and takes it
    /// one step further to the derived bytes — which is the property that
    /// actually matters for key separation (MVP-SPEC.md line 77: distinct
    /// infos ⇒ independent PRF outputs).
    ///
    /// A registry-level collision C3's test cannot see — two entries
    /// accidentally sharing a label string — fails here.
    #[test]
    fn hkdf_registry_pairs_encode_and_derive_distinctly(
        index_a in 0usize..Label::ALL.len(),
        index_b in 0usize..Label::ALL.len(),
        id_a in any::<u64>(),
        id_b in any::<u64>(),
    ) {
        let (label_a, label_b) = (Label::ALL[index_a], Label::ALL[index_b]);
        let (eff_a, eff_b) = (effective_id(label_a, id_a), effective_id(label_b, id_b));

        let info_a = label_a.info_bytes(eff_a);
        let info_b = label_b.info_bytes(eff_b);
        let same_pair = label_a.as_str() == label_b.as_str() && eff_a == eff_b;

        if same_pair {
            prop_assert_eq!(&info_a, &info_b);
            prop_assert_eq!(derive_bytes(label_a, eff_a), derive_bytes(label_b, eff_b));
        } else {
            prop_assert_ne!(&info_a, &info_b, "distinct registry pairs must encode distinctly");
            // Distinct infos must yield distinct output. Equal-length
            // outputs colliding would be a real PRF failure; different
            // lengths differ trivially, which is still the property.
            prop_assert_ne!(
                derive_bytes(label_a, eff_a),
                derive_bytes(label_b, eff_b),
                "distinct pairs must derive distinct material"
            );
        }

        // Each derivation is the registry's declared length, always.
        prop_assert_eq!(derive_bytes(label_a, eff_a).len(), label_a.output_len());
    }
}

// ---------------------------------------------------------------------------
// Commitments — exactness, and the salt/message boundary
// ---------------------------------------------------------------------------

/// Compute and verify one commitment kind over a `(salt, message)` pair,
/// through the public API. Returns `(digest, verify-with-the-same-inputs)`.
fn commit_and_verify(
    kind: CommitmentKind,
    salt: [u8; 16],
    message: &[u8],
) -> ([u8; 32], Result<(), CryptoError>) {
    let salt16 = Salt16::from_bytes(salt);
    let file_salt = FileSalt::from_disclosed(Salt16::from_bytes(salt));
    match kind {
        CommitmentKind::Unit => {
            let d = unit_commit(&salt16, message);
            (d, verify_unit_commit(&salt16, message, &d))
        }
        CommitmentKind::Raw => {
            let d = raw_commit(&file_salt, message);
            (d, verify_raw_commit(&file_salt, message, &d))
        }
        CommitmentKind::Canon => {
            let d = canon_commit(&file_salt, message);
            (d, verify_canon_commit(&file_salt, message, &d))
        }
        CommitmentKind::Path => {
            // Paths are UTF-8 by type; the generated bytes are used as a
            // lossy-decoded string so the property still ranges over
            // arbitrary content.
            let path = String::from_utf8_lossy(message).into_owned();
            let d = path_commit(&salt16, &path);
            (d, verify_path_commit(&salt16, &path, &d))
        }
        // `CommitmentKind` is `#[non_exhaustive]`. A new variant must be
        // added to `COMMITMENT_KINDS` and handled here — failing loudly is
        // the point: a silently unexercised commitment kind is exactly the
        // coverage hole these properties exist to prevent.
        other => panic!("unhandled commitment kind {other:?}: add it to COMMITMENT_KINDS"),
    }
}

/// Verify an arbitrary `(salt, message)` pair against a *given* digest.
fn verify_against(
    kind: CommitmentKind,
    salt: [u8; 16],
    message: &[u8],
    digest: &[u8; 32],
) -> Result<(), CryptoError> {
    let salt16 = Salt16::from_bytes(salt);
    let file_salt = FileSalt::from_disclosed(Salt16::from_bytes(salt));
    match kind {
        CommitmentKind::Unit => verify_unit_commit(&salt16, message, digest),
        CommitmentKind::Raw => verify_raw_commit(&file_salt, message, digest),
        CommitmentKind::Canon => verify_canon_commit(&file_salt, message, digest),
        CommitmentKind::Path => {
            let path = String::from_utf8_lossy(message).into_owned();
            verify_path_commit(&salt16, &path, digest)
        }
        other => panic!("unhandled commitment kind {other:?}: add it to COMMITMENT_KINDS"),
    }
}

const COMMITMENT_KINDS: [CommitmentKind; 4] = [
    CommitmentKind::Unit,
    CommitmentKind::Raw,
    CommitmentKind::Canon,
    CommitmentKind::Path,
];

proptest! {
    #![proptest_config(strategies::integration_test_config(
        0x5EED_C181,
        REGRESSIONS,
    ))]

    /// C18: commitment verification succeeds **iff** the `(salt, bytes)`
    /// pair matches exactly. Any single-byte perturbation of either the
    /// salt or the message must fail with that kind's
    /// `CommitmentMismatch` (MVP-SPEC.md lines 93–95, 168).
    #[test]
    fn commitment_verifies_iff_salt_and_message_match_exactly(
        kind_index in 0usize..COMMITMENT_KINDS.len(),
        salt in any::<[u8; 16]>(),
        message in proptest::collection::vec(any::<u8>(), 0..192),
        salt_index in 0usize..16,
        salt_delta in 1u8..=255,
        message_delta in 1u8..=255,
        message_index in 0usize..192,
    ) {
        let kind = COMMITMENT_KINDS[kind_index];
        let (digest, verified) = commit_and_verify(kind, salt, &message);
        prop_assert_eq!(verified, Ok(()), "the exact pair must verify");

        // Perturb one salt byte (any position, any non-zero delta).
        let mut wrong_salt = salt;
        wrong_salt[salt_index] = wrong_salt[salt_index].wrapping_add(salt_delta);
        prop_assert_eq!(
            verify_against(kind, wrong_salt, &message, &digest),
            Err(CryptoError::CommitmentMismatch { kind }),
            "a perturbed salt must not open the commitment"
        );

        // Perturb one message byte (when the message is non-empty).
        if !message.is_empty() {
            let mut wrong_message = message.clone();
            let at = message_index % wrong_message.len();
            wrong_message[at] = wrong_message[at].wrapping_add(message_delta);
            // `path` decodes lossily, so a perturbation inside a multi-byte
            // sequence can decode to the same replacement char; skip only
            // that degenerate case by checking the decoded form changed.
            let differs = match kind {
                CommitmentKind::Path => {
                    String::from_utf8_lossy(&wrong_message) != String::from_utf8_lossy(&message)
                }
                _ => true,
            };
            if differs {
                prop_assert_eq!(
                    verify_against(kind, salt, &wrong_message, &digest),
                    Err(CryptoError::CommitmentMismatch { kind }),
                    "a perturbed message must not open the commitment"
                );
            }
        }

        // Appending or truncating the message also fails.
        let mut extended = message.clone();
        extended.push(0x00);
        prop_assert!(verify_against(kind, salt, &extended, &digest).is_err());
    }
}

proptest! {
    #![proptest_config(strategies::integration_test_config(
        0x5EED_C182,
        REGRESSIONS,
    ))]

    /// C18 accept (explicit): the **salt/message boundary shift**.
    ///
    /// Every commitment preimage is `tag ‖ salt ‖ message`. If the salt had
    /// a *variable* length, `(salt, msg)` and `(salt ‖ msg[0], msg[1..])`
    /// would produce the identical preimage — a second opening of one
    /// digest, i.e. a broken binding. The fixed 16-byte salt removes that
    /// degree of freedom at the type level: `Salt16` is `[u8; 16]`, so a
    /// 17-byte "salt" is not constructible at all, and the decomposition of
    /// the preimage into `(salt, message)` is unique.
    ///
    /// What is testable — and tested here — is the observable consequence:
    /// shifting the boundary by taking the salt one byte later in the
    /// combined buffer yields a *different* preimage (one byte shorter),
    /// hence a different digest, and the shifted pair does not open the
    /// original commitment.
    #[test]
    fn commitment_boundary_shift_cannot_open_the_commitment(
        kind_index in 0usize..COMMITMENT_KINDS.len(),
        salt in any::<[u8; 16]>(),
        message in proptest::collection::vec(any::<u8>(), 1..192),
    ) {
        // The fixed length is the whole defence — assert it here, where the
        // property depends on it (C18 accept: "16-B fixed length asserted").
        prop_assert_eq!(Salt16::LEN, 16);

        let kind = COMMITMENT_KINDS[kind_index];
        let (digest, _) = commit_and_verify(kind, salt, &message);

        // Slide the 16-byte window one byte into the message: the shifted
        // salt is salt[1..] ‖ message[0], and the shifted message is
        // message[1..]. The combined bytes are one shorter than the
        // original, so the preimage — and the digest — must differ.
        let mut shifted_salt = [0u8; 16];
        shifted_salt[..15].copy_from_slice(&salt[1..]);
        shifted_salt[15] = message[0];
        let shifted_message = &message[1..];

        let (shifted_digest, _) = commit_and_verify(kind, shifted_salt, shifted_message);
        prop_assert_ne!(
            shifted_digest, digest,
            "a boundary shift must change the digest — otherwise the commitment \
             would have a second opening"
        );
        prop_assert_eq!(
            verify_against(kind, shifted_salt, shifted_message, &digest),
            Err(CryptoError::CommitmentMismatch { kind }),
            "the shifted pair must not open the original commitment"
        );

        // The concatenations really are different lengths — the structural
        // reason the digests differ.
        prop_assert_eq!(
            salt.len() + message.len(),
            shifted_salt.len() + shifted_message.len() + 1
        );
    }
}

// ---------------------------------------------------------------------------
// Padding — round-trip and rejection completeness
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(strategies::integration_test_config(
        0x5EED_C183,
        REGRESSIONS,
    ))]

    /// C18: padding round-trip over the mandated length range
    /// `0..=4·256+3`, through the public API (MVP-SPEC.md line 91).
    #[test]
    fn padding_round_trips_over_the_mandated_range(
        bytes in proptest::collection::vec(any::<u8>(), 0..=MAX_PAD_LEN),
    ) {
        let padded = apply_padding(&bytes);
        prop_assert_eq!(padded.len(), padded_length(bytes.len()));
        prop_assert!(padded.len() > bytes.len(), "always at least one pad byte");
        prop_assert!(padded.len().is_multiple_of(PAD_BLOCK));
        prop_assert!(padded.len() - bytes.len() <= PAD_BLOCK);
        // Length-first stripping returns the exact bytes — including any
        // genuine trailing zeros, which are never inferred away.
        prop_assert_eq!(strip_padding(&padded, bytes.len()).expect("valid padding"), &bytes[..]);
    }

    /// C18: strip-**rejection completeness** for the non-zero-pad class.
    /// For a validly padded buffer, setting *any* byte in the pad region to
    /// a non-zero value must be rejected, with the offset of the **first**
    /// offending byte (MVP-SPEC.md line 121; the line-168 companion row).
    #[test]
    fn any_non_zero_pad_byte_is_rejected_at_its_offset(
        bytes in proptest::collection::vec(any::<u8>(), 0..=MAX_PAD_LEN),
        offset_pick in any::<usize>(),
        value in 1u8..=255,
    ) {
        let mut padded = apply_padding(&bytes);
        let pad_start = bytes.len();
        let pad_len = padded.len() - pad_start;
        prop_assert!(pad_len >= 1);
        let at = pad_start + offset_pick % pad_len;

        padded[at] = value;
        prop_assert_eq!(
            strip_padding(&padded, bytes.len()),
            Err(CryptoError::NonZeroPadding { offset: at }),
            "the first non-zero pad byte must be reported at its own offset"
        );
    }

    /// C18: strip-rejection completeness for the length class. For a
    /// validly padded buffer, *any* length change rejects with
    /// `PaddingLengthMismatch` carrying the recomputed expectation — the
    /// over-padded-unit tamper row and its truncation counterpart.
    #[test]
    fn any_length_change_is_rejected_as_a_length_mismatch(
        bytes in proptest::collection::vec(any::<u8>(), 0..=MAX_PAD_LEN),
        delta in 1usize..=(2 * PAD_BLOCK),
        grow in any::<bool>(),
    ) {
        let padded = apply_padding(&bytes);
        let mutated = if grow {
            let mut longer = padded.clone();
            longer.resize(padded.len() + delta, 0);
            longer
        } else {
            let shorter_len = padded.len().saturating_sub(delta);
            padded[..shorter_len].to_vec()
        };
        prop_assume!(mutated.len() != padded.len());

        prop_assert_eq!(
            strip_padding(&mutated, bytes.len()),
            Err(CryptoError::PaddingLengthMismatch {
                expected: padded_length(bytes.len()),
                got: mutated.len(),
            })
        );
    }
}

// ---------------------------------------------------------------------------
// Unit AEAD — round-trip and AAD binding
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(strategies::integration_test_config(
        0x5EED_C184,
        REGRESSIONS,
    ))]

    /// C18: unit-AEAD round-trip over arbitrary unit bytes and ids, and
    /// decrypt failure on **any** AAD component mismatch — the AAD is
    /// `seal_id ‖ LE64(unit_id)` (MVP-SPEC.md line 91), so both halves are
    /// perturbed independently here.
    ///
    /// Every failure mode is `AeadDecryptFailed`: the AEAD cannot, and must
    /// not, distinguish which input was wrong.
    #[test]
    fn unit_aead_round_trips_and_binds_every_aad_component(
        unit_bytes in proptest::collection::vec(any::<u8>(), 0..600),
        unit_id in any::<u64>(),
        seal_id_bytes in any::<[u8; 16]>(),
        rng_seed in any::<[u8; 32]>(),
    ) {
        let seal_id = SealId::from_bytes(seal_id_bytes);
        let id = UnitId(unit_id);
        let mut rng = ChaCha20Rng::from_seed(rng_seed);

        let (ciphertext, nonce) =
            encrypt_unit(w(), &seal_id, id, &unit_bytes, &mut rng).expect("seeded rng encrypts");
        prop_assert_eq!(ciphertext.len(), padded_length(unit_bytes.len()) + 16);

        // Round-trip.
        prop_assert_eq!(
            decrypt_unit(w(), &seal_id, id, &nonce, &ciphertext, unit_bytes.len())
                .expect("round-trips"),
            unit_bytes.clone()
        );

        // AAD component 1: a different seal_id. (k_u does not depend on
        // seal_id, so this is a pure AAD-binding failure.)
        let mut other_seal_bytes = seal_id_bytes;
        other_seal_bytes[0] ^= 0x01;
        let other_seal = SealId::from_bytes(other_seal_bytes);
        prop_assert_eq!(
            decrypt_unit(w(), &other_seal, id, &nonce, &ciphertext, unit_bytes.len()),
            Err(CryptoError::AeadDecryptFailed)
        );
        prop_assert_ne!(unit_aad(&seal_id, id), unit_aad(&other_seal, id));

        // AAD component 2: a different unit_id (changes both k_u and AAD).
        let other_id = UnitId(unit_id ^ 1);
        prop_assert_eq!(
            decrypt_unit(w(), &seal_id, other_id, &nonce, &ciphertext, unit_bytes.len()),
            Err(CryptoError::AeadDecryptFailed)
        );
        prop_assert_ne!(unit_aad(&seal_id, id), unit_aad(&seal_id, other_id));

        // Nonce and ciphertext are bound too.
        let mut wrong_nonce = *nonce.as_bytes();
        wrong_nonce[0] ^= 0x01;
        prop_assert_eq!(
            decrypt_unit(
                w(), &seal_id, id, &Nonce24::from_bytes(wrong_nonce),
                &ciphertext, unit_bytes.len()
            ),
            Err(CryptoError::AeadDecryptFailed)
        );
        let mut tampered = ciphertext.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 0x80;
        prop_assert_eq!(
            decrypt_unit(w(), &seal_id, id, &nonce, &tampered, unit_bytes.len()),
            Err(CryptoError::AeadDecryptFailed)
        );
    }
}

// ---------------------------------------------------------------------------
// Hybrid signatures — round-trip and mutation
// ---------------------------------------------------------------------------

/// Assert the sign/verify round-trip and the mutation property for one
/// How much of the signature contract to assert per case.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Coverage {
    /// Round-trip + mutation only: **one** `sign_body` and one successful
    /// `verify_body` per case. Used by the hybrid block, where each
    /// `sign_body` is an ML-DSA-65 signature costing ~65 ms in a debug
    /// build.
    Core,
    /// [`Coverage::Core`] plus the two extra signing legs — re-signing to
    /// show determinism, and signing the mutated body to show the binding
    /// is symmetric. Used by the cheap Ed25519-only block.
    Full,
}

/// Assert the sign/verify round-trip and the mutation property for one
/// policy. Shared by the two blocks below so the Ed25519-only and hybrid
/// policies are held to the *same* contract — C14 runs both down one code
/// path, and this keeps the test honest about that.
fn assert_sign_verify_round_trip_and_mutation(
    policy: &SigPolicy,
    body: &[u8],
    flip_index: usize,
    flip_bit: u32,
    coverage: Coverage,
) -> Result<(), TestCaseError> {
    let pubkeys = public_keys(w(), policy);
    let signatures = sign_body(w(), policy, body);

    prop_assert_eq!(
        verify_body(policy, &pubkeys, &signatures, body),
        Ok(policy.label())
    );

    // Any single-bit body mutation breaks verification. Ed25519 is checked
    // first by C14's fixed order, so the reported algorithm is
    // deterministic for both policies — and, for the hybrid policy, that
    // short-circuit is also why this leg costs no ML-DSA verification.
    let mut mutated = body.to_vec();
    let at = flip_index % mutated.len();
    mutated[at] ^= 1u8 << flip_bit;
    prop_assert_ne!(&mutated[..], body);
    prop_assert_eq!(
        verify_body(policy, &pubkeys, &signatures, &mutated),
        Err(CryptoError::SignatureInvalid {
            alg: SigAlg::Ed25519
        })
    );

    if coverage == Coverage::Core {
        return Ok(());
    }

    // Deterministic signing: signing the same body twice is identical
    // (RFC 8032 for Ed25519, D15's rnd = 0^32 for ML-DSA-65). This is what
    // makes C16's byte-pinned signature vectors possible. For ML-DSA the
    // same fact is pinned exactly — and cross-implementation — by C16's
    // committed `signatures.json`, so the hybrid block skips this leg.
    prop_assert_eq!(sign_body(w(), policy, body), signatures.clone());

    // …and signatures over the mutated body do not verify over the
    // original either (binding is symmetric).
    let mutated_signatures = sign_body(w(), policy, &mutated);
    prop_assert_ne!(&mutated_signatures, &signatures);
    prop_assert_eq!(
        verify_body(policy, &pubkeys, &mutated_signatures, body),
        Err(CryptoError::SignatureInvalid {
            alg: SigAlg::Ed25519
        })
    );
    Ok(())
}

proptest! {
    #![proptest_config(strategies::integration_test_config(
        0x5EED_C185,
        REGRESSIONS,
    ))]

    /// C18: sign/verify round-trip and mutation over the **Ed25519-only**
    /// policy — cheap, so this block carries the broad exploration and
    /// scales with `PROPTEST_CASES` like every other block here.
    ///
    /// C14 runs the fallback policy down the identical orchestration path
    /// as the hybrid one, so the cases explored here exercise that shared
    /// path at full breadth (MVP-SPEC.md lines 97, 104).
    #[test]
    fn ed25519_only_sign_verify_round_trips_and_any_body_mutation_fails(
        body in proptest::collection::vec(any::<u8>(), 1..96),
        flip_index in any::<usize>(),
        flip_bit in 0u32..8,
    ) {
        assert_sign_verify_round_trip_and_mutation(
            &SigPolicy::ed25519_only(), &body, flip_index, flip_bit, Coverage::Full,
        )?;
    }
}

proptest! {
    // ML-DSA-65 dominates this block's cost: ~65 ms per signing or
    // verification in a debug build. [`Coverage::Core`] therefore keeps it
    // to **one** signature and one verification per case; the two extra
    // signing legs run at full breadth in the cheap Ed25519-only block
    // above (identical orchestration path, identical contract), and the
    // ML-DSA bytes themselves are pinned exactly — and cross-checked
    // against a second implementation — by C16's committed vector.
    //
    // `cases` is set low for local runs. **It does not cap CI**: proptest's
    // `proptest!` macro re-applies `contextualize_config` to whatever
    // config it is given, so `PROPTEST_CASES` overrides an explicit `cases`
    // rather than the other way round (see the note in
    // docs/testing/proptest-conventions.md §4). The lever for CI cost is
    // that lane's env var, not this constant.
    #![proptest_config(ProptestConfig {
        cases: 48,
        ..strategies::integration_test_config(0x5EED_C186, REGRESSIONS)
    })]

    /// C18: hybrid sign/verify round-trip over arbitrary bodies, with any
    /// body mutation causing failure (MVP-SPEC.md lines 97, 104).
    ///
    /// Runs through C14's policy-enforcing orchestration, so **both** halves
    /// must verify for the round-trip to succeed.
    #[test]
    fn hybrid_sign_verify_round_trips_and_any_body_mutation_fails(
        body in proptest::collection::vec(any::<u8>(), 1..96),
        flip_index in any::<usize>(),
        flip_bit in 0u32..8,
    ) {
        let policy = SigPolicy::hybrid();
        // The hybrid policy really does carry both algorithms — otherwise
        // this block would be a slower copy of the Ed25519-only one.
        prop_assert_eq!(policy.algorithms().len(), 2);
        prop_assert!(policy.requires(SigAlg::MlDsa65));

        assert_sign_verify_round_trip_and_mutation(
            &policy, &body, flip_index, flip_bit, Coverage::Core,
        )?;
    }
}
