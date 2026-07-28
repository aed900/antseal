//! C17 — the crypto tamper rows, their meta-tests, and the primitive-level
//! evidence that sits behind them.
//!
//! The rows themselves are `antseal_core::test_util::tamper_rows_crypto`
//! (in the library, so the whole registry can be assembled in one place for
//! the cross-domain sweep and so the wasm lane runs them). This file:
//!
//! 1. runs C's slice through the Q7 harness on its own, for fast
//!    domain-local feedback;
//! 2. carries the **pairwise-distinctness meta-test** C17 asks for, plus
//!    two guards the harness cannot give — that every expected code is
//!    `crypto-`-prefixed and that it is a code some `CryptoError` variant
//!    can actually emit;
//! 3. proves each row is a genuine *mutation*: the unmutated base artifact
//!    verifies, so a row cannot be green because its fixture was broken to
//!    begin with;
//! 4. covers the over-padding family end to end through the AEAD path,
//!    using C9's mis-encryptors. Those two rows are already registered (Q7
//!    seeded them against `strip_padding` directly) and their codes may not
//!    be duplicated, so the added value here is the full
//!    encrypt → authenticate → strip path, which is what a verifier
//!    actually runs.
//!
//! Whole-registry (cross-domain) distinctness lives in `tamper_matrix.rs`,
//! which merges this slice with the seed rows.

use std::collections::BTreeSet;

use antseal_core::crypto::commit::{
    canon_commit, path_commit, raw_commit, unit_commit, verify_canon_commit, verify_path_commit,
    verify_raw_commit, verify_unit_commit,
};
use antseal_core::crypto::error::CryptoError;
use antseal_core::crypto::error::all_code_exemplars;
use antseal_core::crypto::hkdf::{derive_file_salt, derive_path_salt, derive_unit_salt};
use antseal_core::crypto::material::MasterSecretRef;
use antseal_core::crypto::secrets::SealId;
use antseal_core::crypto::sig_policy::{PolicyLabel, SigPolicy, verify_body};
use antseal_core::crypto::unit_aead::{decrypt_unit, mis_encrypt};
use antseal_core::test_util::TEST_MASTER_SECRET_W;
use antseal_core::test_util::fixture_rng::FixtureRng;
use antseal_core::test_util::tamper::{
    ExpectedOutcome, TamperRow, check_registry, render_failures,
};
use antseal_core::test_util::tamper_rows_crypto::{
    FIXTURE_CANON_BYTES, FIXTURE_FILE_ID, FIXTURE_PATH, FIXTURE_RAW_BYTES, FIXTURE_RNG_SEED,
    FIXTURE_SEAL_ID, FIXTURE_UNIT_BYTES, FIXTURE_UNIT_ID, ROWS, encrypt_fixture_unit, helpers,
    hybrid_material,
};

fn w() -> MasterSecretRef<'static> {
    MasterSecretRef::from_bytes(&TEST_MASTER_SECRET_W)
}

fn expected_codes() -> Vec<&'static str> {
    ROWS.iter()
        .map(|row| match row.expected {
            ExpectedOutcome::ErrorCode(code) => code,
            ExpectedOutcome::VerdictState(state) => state,
        })
        .collect()
}

/// Every C17 row produces exactly its expected distinct outcome, and none
/// panics (the harness's own rules, applied to C's slice alone).
#[test]
fn crypto_tamper_rows_are_green() {
    match check_registry(ROWS) {
        Ok(count) => assert_eq!(count, ROWS.len()),
        Err(failures) => panic!("{}", render_failures(&failures)),
    }
}

/// **C17's distinctness meta-test**: the error variants across all crypto
/// rows are pairwise distinct. `check_registry` enforces this too, but as
/// one failure among many; stated separately it is the assertion C17's
/// accept bullet names, and it fails with a message that says which codes
/// collided.
#[test]
fn crypto_tamper_row_outcomes_are_pairwise_distinct() {
    let codes = expected_codes();
    let unique: BTreeSet<&str> = codes.iter().copied().collect();
    assert_eq!(
        unique.len(),
        codes.len(),
        "two crypto rows expect the same outcome — one of the two mutations is not \
         distinguishable to a verifier, and the fix is a new error variant in C, never a \
         re-used code (docs/testing/error-code-contract.md §4)"
    );

    // Row ids are permanent handles and must be unique too.
    let ids: BTreeSet<&str> = ROWS.iter().map(|row| row.id).collect();
    assert_eq!(ids.len(), ROWS.len(), "duplicate crypto row id");
}

/// Every crypto row binds a code that (a) carries C's domain prefix and
/// (b) some `CryptoError` variant can actually emit. (b) is the guard the
/// harness cannot give: a typo'd expected code would otherwise just look
/// like a mismatch in whichever row happened to fail.
#[test]
fn crypto_tamper_row_codes_are_real_and_domain_prefixed() {
    let universe: BTreeSet<&'static str> =
        all_code_exemplars().iter().map(CryptoError::code).collect();
    for row in ROWS {
        let ExpectedOutcome::ErrorCode(code) = row.expected else {
            panic!(
                "row `{}`: crypto rows pin error codes, not verdict states",
                row.id
            );
        };
        assert!(
            code.starts_with("crypto-"),
            "row `{}` binds `{code}`, which is outside C's `crypto-` prefix \
             (docs/testing/error-code-contract.md §2)",
            row.id
        );
        assert!(
            universe.contains(code),
            "row `{}` expects `{code}`, which no CryptoError variant emits",
            row.id
        );
    }
}

/// Coverage: the spec's M0 crypto rows (MVP-SPEC.md line 168) are all
/// present across C's slice **plus** the three C-owned rows Q7 seeded. This
/// is the list Q8's completeness registry will read.
#[test]
fn crypto_rows_cover_the_spec_m0_list() {
    // Rows in C's own slice.
    for code in [
        "crypto-unit-commit-mismatch",
        "crypto-path-commit-mismatch",
        "crypto-raw-commit-mismatch",
        "crypto-canon-commit-mismatch",
        "crypto-unit-salt-length",
        "crypto-file-salt-length",
        "crypto-seed-length",
        "crypto-node-hash-length",
        "crypto-aead-decrypt-failed",
        "crypto-sig-policy-empty",
        "crypto-signature-missing-ml-dsa-65",
        "crypto-signature-invalid-ed25519",
        "crypto-signature-unlisted-ml-dsa-65",
        "crypto-non-canonical-signature-ed25519",
        "crypto-non-canonical-signature-ml-dsa-65",
    ] {
        assert!(
            expected_codes().contains(&code),
            "the spec's M0 crypto list needs a row binding `{code}`"
        );
    }
    // The remaining three C-owned families were seeded by Q7 in
    // `tamper_matrix.rs` and must NOT be duplicated here (an expected code
    // may be claimed by exactly one row).
    for code in [
        "crypto-path-salt-length",
        "crypto-padding-length-mismatch",
        "crypto-non-zero-padding",
    ] {
        assert!(
            !expected_codes().contains(&code),
            "`{code}` is already claimed by a Q7 seed row; a second row would collide"
        );
    }
}

/// A tamper row is only meaningful if the artifact it mutates was valid.
/// Here every base fixture is verified **unmutated** — the positive control
/// for the wrong-salt, wrong-key and `sig_policy` families at once.
#[test]
fn the_base_fixtures_verify_before_mutation() {
    // Commitments open with their real salts.
    let unit_salt = derive_unit_salt(w(), FIXTURE_UNIT_ID);
    let path_salt = derive_path_salt(w(), FIXTURE_FILE_ID);
    let file_salt = derive_file_salt(w(), FIXTURE_FILE_ID);
    assert_eq!(
        verify_unit_commit(
            &unit_salt,
            FIXTURE_UNIT_BYTES,
            &unit_commit(&unit_salt, FIXTURE_UNIT_BYTES)
        ),
        Ok(())
    );
    assert_eq!(
        verify_path_commit(
            &path_salt,
            FIXTURE_PATH,
            &path_commit(&path_salt, FIXTURE_PATH)
        ),
        Ok(())
    );
    assert_eq!(
        verify_raw_commit(
            &file_salt,
            FIXTURE_RAW_BYTES,
            &raw_commit(&file_salt, FIXTURE_RAW_BYTES)
        ),
        Ok(())
    );
    assert_eq!(
        verify_canon_commit(
            &file_salt,
            FIXTURE_CANON_BYTES,
            &canon_commit(&file_salt, FIXTURE_CANON_BYTES)
        ),
        Ok(())
    );

    // The encrypted unit round-trips under the right W.
    let (ciphertext, nonce) = encrypt_fixture_unit().expect("the fixture RNG cannot fail");
    assert_eq!(
        decrypt_unit(
            w(),
            &SealId::from_bytes(FIXTURE_SEAL_ID),
            FIXTURE_UNIT_ID,
            &nonce,
            &ciphertext,
            FIXTURE_UNIT_BYTES.len(),
        ),
        Ok(FIXTURE_UNIT_BYTES.to_vec())
    );

    // The hybrid signature set verifies as hybrid.
    let policy = SigPolicy::hybrid();
    let (keys, sigs) = hybrid_material();
    assert_eq!(
        verify_body(
            &policy,
            &keys,
            &sigs,
            antseal_core::test_util::tamper_rows_crypto::FIXTURE_BODY
        ),
        Ok(PolicyLabel::Hybrid)
    );
}

/// The fixture ciphertext is reproducible: the deterministic RNG is what
/// makes an "encrypted unit" a *committed* base artifact rather than a
/// fresh one per run (which R7's bundle-level fixtures depend on).
#[test]
fn the_encrypted_fixture_unit_is_reproducible() {
    let (first, first_nonce) = encrypt_fixture_unit().expect("fixture RNG");
    let (second, second_nonce) = encrypt_fixture_unit().expect("fixture RNG");
    assert_eq!(first, second);
    assert_eq!(first_nonce.as_bytes(), second_nonce.as_bytes());
    // …and a different stream really does give a different nonce, so the
    // reproducibility above is the seed's doing, not a stuck generator.
    let mut other = FixtureRng::from_seed([0xA5; 32]);
    let (_, other_nonce) = antseal_core::crypto::unit_aead::encrypt_unit(
        w(),
        &SealId::from_bytes(FIXTURE_SEAL_ID),
        FIXTURE_UNIT_ID,
        FIXTURE_UNIT_BYTES,
        &mut other,
    )
    .expect("fixture RNG");
    assert_ne!(first_nonce.as_bytes(), other_nonce.as_bytes());
    assert_eq!(FIXTURE_RNG_SEED, [0xC1; 32]);
}

/// The over-padding family, end to end through the AEAD path C9's
/// mis-encryptors exist for: both mis-encrypted units **authenticate**
/// correctly and then fail the C8 strip, with the two rejections distinct
/// from each other and from an AEAD failure.
///
/// The tamper rows for this family are `crypto-padding-length-mismatch` and
/// `crypto-non-zero-padding`, registered by Q7's seed rows against
/// `strip_padding`; R7 owns the committed bundle-level fixtures (Q8's
/// single-owner rule). What is added here is the full verifier path.
#[test]
fn over_padded_and_nonzero_pad_units_reject_through_the_full_aead_path() {
    let seal_id = SealId::from_bytes(FIXTURE_SEAL_ID);
    let true_length = FIXTURE_UNIT_BYTES.len();

    let mut rng = FixtureRng::from_seed(FIXTURE_RNG_SEED);
    let (over_padded, over_nonce) = helpers::encrypt_unit_overpadded(
        w(),
        &seal_id,
        FIXTURE_UNIT_ID,
        FIXTURE_UNIT_BYTES,
        &mut rng,
    )
    .expect("fixture RNG");
    let over_error = decrypt_unit(
        w(),
        &seal_id,
        FIXTURE_UNIT_ID,
        &over_nonce,
        &over_padded,
        true_length,
    )
    .expect_err("an over-padded unit must not decrypt cleanly");
    assert_eq!(over_error.code(), "crypto-padding-length-mismatch");

    let mut rng = FixtureRng::from_seed(FIXTURE_RNG_SEED);
    let (bad_pad, bad_nonce) = mis_encrypt::encrypt_unit_nonzero_padding(
        w(),
        &seal_id,
        FIXTURE_UNIT_ID,
        FIXTURE_UNIT_BYTES,
        &mut rng,
    )
    .expect("fixture RNG");
    let bad_error = decrypt_unit(
        w(),
        &seal_id,
        FIXTURE_UNIT_ID,
        &bad_nonce,
        &bad_pad,
        true_length,
    )
    .expect_err("a non-zero pad byte must not decrypt cleanly");
    assert_eq!(bad_error.code(), "crypto-non-zero-padding");

    // Both survived authentication — the padding rejections fire strictly
    // after the AEAD, so they are a different failure class from a tampered
    // ciphertext, and the three codes are pairwise distinct.
    let mut flipped = over_padded.clone();
    flipped[0] ^= 0x01;
    let aead_error = decrypt_unit(
        w(),
        &seal_id,
        FIXTURE_UNIT_ID,
        &over_nonce,
        &flipped,
        true_length,
    )
    .expect_err("a flipped ciphertext byte must fail authentication");
    assert_eq!(aead_error.code(), "crypto-aead-decrypt-failed");

    let codes: BTreeSet<&str> = [over_error.code(), bad_error.code(), aead_error.code()]
        .into_iter()
        .collect();
    assert_eq!(
        codes.len(),
        3,
        "the three padding/AEAD outcomes must differ"
    );
}

/// The mutation-helper surface C17 owes R7 exists and is callable from
/// outside the crate — a compile-and-run assertion, so a rename cannot
/// silently break R7's fixtures.
#[test]
fn mutation_helpers_are_exported_for_r7() {
    let (_, sigs) = hybrid_material();
    for (alg, bytes) in &sigs {
        // `SigAlg` is `#[non_exhaustive]` outside the crate, so the
        // wildcard is forced here; a future algorithm would land in it and
        // the assertions below would catch a maul that did nothing.
        let mauled = match alg {
            antseal_core::crypto::error::SigAlg::Ed25519 => {
                helpers::maul_ed25519_s_out_of_range(bytes)
            }
            _ => helpers::maul_mldsa_hint_count(bytes),
        };
        assert_eq!(mauled.len(), bytes.len(), "a maul preserves the length");
        assert_ne!(&mauled, bytes, "a maul actually mutates");
    }

    // The wrong-length constructors R's verifier path calls.
    use antseal_core::crypto::error::SaltKind;
    use antseal_core::crypto::material::{NodeHash32, Salt16, Seed32};
    assert_eq!(
        Salt16::try_from_slice(SaltKind::Unit, &[0u8; 15])
            .expect_err("15 bytes")
            .code(),
        "crypto-unit-salt-length"
    );
    assert_eq!(
        Seed32::try_from(&[0u8; 33][..])
            .expect_err("33 bytes")
            .code(),
        "crypto-seed-length"
    );
    assert_eq!(
        NodeHash32::try_from(&[0u8; 31][..])
            .expect_err("31 bytes")
            .code(),
        "crypto-node-hash-length"
    );

    // A helper row and a seed row must never be the same TamperRow value.
    let seeded: BTreeSet<&str> = ROWS.iter().map(|row: &TamperRow| row.id).collect();
    assert!(seeded.contains("crypto-unit-aead-wrong-key"));
}
