//! Per-unit evidence stages: decrypt, padding verify/strip, true-length
//! binding, content-binding dispatch (task R2).
//!
//! For every revealed unit a `.sealproof` bundle carries, the evidence
//! layer runs this fixed stage order (MVP-SPEC.md lines 91, 114, 118, 121;
//! the per-check order within the stage is part of D27's deterministic
//! first-error contract — `docs/decisions/D27-verify-error-mode.md`):
//!
//! 1. **AEAD decrypt** of the embedded ciphertext with the
//!    **bundle-supplied `k_u`** (spec line 114 — the verifier never holds
//!    `W`), the **manifest-recorded nonce** (the single authoritative
//!    copy; see below), and `AAD = seal_id ‖ LE64(unit_id)` (spec
//!    line 91). Failure → [`VerifyError::UnitDecryptFailed`].
//! 2. **Padding verification + length-first strip**: the AEAD plaintext
//!    length must equal `padded_length = ⌈(true_length + 1) / 256⌉ · 256`
//!    recomputed from the **manifest's** `true_length` (rejects silent
//!    over-/under-padding → [`VerifyError::PaddedLengthMismatch`]); every
//!    byte beyond `true_length` must be `0x00`
//!    (→ [`VerifyError::NonZeroPadding`]); then strip to `true_length`,
//!    length-first, so genuine trailing `0x00` content survives. Runs
//!    only after successful authentication — structurally distinct from
//!    stage 1 (C9's failure ordering). Stages 1–2 execute inside the
//!    single crypto implementation,
//!    [`crate::crypto::unit_aead::decrypt_unit_with_key`] — the AEAD/strip
//!    logic is **not** forked into this module.
//! 3. **True-length ↔ range binding**: `true_length` must equal the
//!    unit's manifest byte-range width, so a unit cannot claim more span
//!    than it reveals (spec line 121; the per-unit slice of the
//!    structural invariants, ordered here per tasks/R.md R2 before any
//!    commitment work) → [`VerifyError::TrueLengthRangeMismatch`].
//! 4. **Content-binding dispatch** on the unit's commitment mode
//!    (the single-authoritative-commitment rule, spec line 94;
//!    [`crate::crypto::disclosure::UnitBinding`]):
//!    - **non-covered** (`--no-fine-tree` / raw-mirror): recompute
//!      `unit_commit = SHA-256(0x02 ‖ unit_salt ‖ bytes)` over the
//!      bundle-supplied `unit_salt` via C6 and match the manifest
//!      → [`VerifyError::UnitCommitMismatch`];
//!    - **fine-tree-covered**: G13's leaf-range verification against
//!      `fine_root` through the [`FineRangeCheck`] seam
//!      → [`VerifyError::FineRootBindingFailed`] wrapping
//!      [`FineTreeError`].
//!
//! # Nonces come from the manifest only (spec lines 91, 114)
//!
//! [`RevealedUnitInput`] carries exactly **one** nonce, defined as the
//! manifest unit table's recorded value — "Nonces come from the manifest
//! (single source of truth)" (spec line 114). F's bundle schema has **no
//! per-unit nonce field**, so no bundle-side nonce exists to consult, and
//! this API deliberately provides no second nonce parameter through which
//! one could be smuggled in.
//!
//! # The G13 seam
//!
//! G's fine-root range verification (tasks/G.md G13: sub-cover length
//! checks, leaf-exact-cover enforcement, salt derivation, leaf rebuild,
//! boundary-path fold) does not exist yet. [`FineTreeError`] and
//! [`FineRangeCheck`] pin the contract it plugs into; see their docs.
//! End-to-end covered-unit verification tests land with G13/G17 — until
//! then the covered arm is exercised against the placeholder error type.

use core::fmt;

use crate::crypto::commit::{CommitmentDigest, verify_unit_commit};
use crate::crypto::error::CryptoError;
use crate::crypto::hkdf::UnitId;
use crate::crypto::material::Salt16;
use crate::crypto::padding::padded_length_exact;
use crate::crypto::secrets::SealId;
use crate::crypto::unit_aead::{Nonce24, UnitKey, decrypt_unit_with_key};

use super::error::VerifyError;

/// G-side fine-tree range-verification failure.
///
/// **Relocated to G by G13, exactly as R2 planned** ("G13 may relocate the
/// type into G's fine-tree module; the `VerifyError` arm and its codes are
/// the stable surface"): the definition now lives in
/// [`crate::content::fine_tree::error`] alongside the `verify_range`
/// implementation that produces it — `content` is the lower layer and must
/// not depend on `verify` — and is re-exported here so this path, and
/// [`VerifyError::FineRootBindingFailed`]'s `source`, are unchanged.
///
/// The two classes R2 declared ([`FineTreeError::RootMismatch`],
/// [`FineTreeError::OverBroadCover`]) keep their shape *and their codes*
/// verbatim; G13 appended `WrongCoverShape`, `BadSeedLength`,
/// `BadNodeHashLength`, `RangeOutOfBounds` and `ByteLenMismatch`, each of
/// which broke the wildcard-free match in [`VerifyError::code`] until it
/// received a distinct stable code and an exemplar — the mechanism working
/// as designed.
pub use crate::content::fine_tree::FineTreeError;

/// The covered-unit range-verification hook — **the stage signature G13's
/// implementation plugs into**.
///
/// The R5 orchestrator pre-binds G13's
/// `verify_range(proof, revealed_bytes, n, fine_root)` over the bundle's
/// leaf-exact GGM sub-cover + boundary Merkle paths (`proof`), the file's
/// size field (`n`), the unit's manifest byte-range, and the manifest's
/// `fine_root` — leaving exactly one free argument: the unit bytes this
/// stage verified in stages 1–3, passed as the revealed leaf range.
pub type FineRangeCheck<'a> = &'a dyn Fn(&[u8]) -> Result<(), FineTreeError>;

/// Everything stage 1–3 of the per-unit pipeline consumes, split by
/// provenance. All of it is adversary-controlled — the sealer is an
/// adversary too (MVP-SPEC.md line 121) — but the manifest side is at
/// least covered by the signed body while the bundle side is free-floating
/// bundle content.
///
/// There is exactly **one** nonce field, and it is manifest-side (module
/// docs; spec lines 91, 114 — F's bundle schema has no nonce field).
#[derive(Debug, Clone, Copy)]
pub struct RevealedUnitInput<'a> {
    /// Manifest-side: the work's `seal_id` (AAD component; spec line 90).
    pub seal_id: &'a SealId,
    /// Manifest-side: the unit's work-global id (AAD component, key/salt
    /// derivation index, and the error-payload subject).
    pub unit_id: UnitId,
    /// Manifest-side: the unit-table nonce — the **single authoritative
    /// copy** (spec line 91). No bundle-side nonce exists.
    pub nonce: &'a Nonce24,
    /// Manifest-side: the unit table's `true_length`, driving the
    /// `padded_length` recompute and the length-first strip. `u64` because
    /// it is a wire value an adversarial manifest controls — conversion to
    /// this target's `usize` is handled totally inside the stage.
    pub true_length: u64,
    /// Manifest-side: the width of the unit's byte-range (`end − start`)
    /// as validated structurally by R3 (range well-formedness — ordering,
    /// bounds — is R3's tiling/structural stage, which R5 runs first).
    pub range_width: u64,
    /// Bundle-side: the disclosed per-unit key `k_u` (spec line 114). The
    /// verifier decrypts with this — never with `W`.
    pub k_u: &'a UnitKey,
    /// Bundle-side: the embedded unit ciphertext.
    pub ciphertext: &'a [u8],
}

/// Stage-4 dispatch input: how the manifest binds this unit's content —
/// the verification-side mirror of
/// [`crate::crypto::disclosure::UnitBinding`] (single-authoritative-
/// commitment rule, spec line 94), carrying each mode's check inputs.
/// The R5 orchestrator selects the arm from the manifest's kind-conditional
/// `unit_commit` field; a bundle disagreeing with the manifest about a
/// unit's coverage is caught by R3's referential/structural stage before
/// this one runs.
#[derive(Clone, Copy)]
pub enum ContentBinding<'a> {
    /// Non-covered unit (`--no-fine-tree` whole-file or raw-mirror):
    /// content is bound by `unit_commit` alone (spec lines 92, 94).
    NonCovered {
        /// Bundle-supplied 16-byte `unit_salt` (already length-checked at
        /// R3's structural stage via `Salt16::try_from_slice`).
        unit_salt: &'a Salt16,
        /// The manifest's `unit_commit` to match against.
        unit_commit: &'a CommitmentDigest,
    },
    /// Fine-tree-covered unit: content is bound **solely** by `fine_root`
    /// through G13's range verification (spec lines 94, 96).
    FineTreeCovered {
        /// The pre-bound G13 range check (see [`FineRangeCheck`]).
        verify_range: FineRangeCheck<'a>,
    },
}

impl fmt::Debug for ContentBinding<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NonCovered {
                unit_salt,
                unit_commit: _,
            } => f
                .debug_struct("NonCovered")
                // `Salt16`'s own Debug is redacted; the commitment digest
                // is public manifest data but adds nothing here.
                .field("unit_salt", unit_salt)
                .finish_non_exhaustive(),
            Self::FineTreeCovered { .. } => {
                f.debug_struct("FineTreeCovered").finish_non_exhaustive()
            }
        }
    }
}

/// `usize → u64`, total on every supported target (`usize` is at most
/// 64 bits, so the conversion never actually saturates — the fallback
/// exists to keep the code panic-free by construction).
fn as_u64(n: usize) -> u64 {
    u64::try_from(n).unwrap_or(u64::MAX)
}

/// The spec's `padded_length` recompute over the manifest's `u64`
/// `true_length`, in exact wide arithmetic saturated only into the error
/// payload — identical on 64-bit native and 32-bit wasm32 for every input
/// (the native↔WASM verdict-parity requirement, MVP-SPEC.md line 169).
fn padded_length_u64(true_length: u64) -> u64 {
    u64::try_from(padded_length_exact(u128::from(true_length))).unwrap_or(u64::MAX)
}

/// Run the per-unit evidence stages for one revealed unit, in the
/// normative order (module docs), returning the unit's verified exact
/// bytes (canonical for text, raw for binary/raw-mirror) for the
/// file-level stages (R4: concatenation, full-reveal cross-checks).
///
/// Fail-fast: the first failing stage returns its distinct typed error
/// (D27). Never panics on adversarial input — every manifest/bundle value
/// is handled totally, including `true_length` values exceeding this
/// target's `usize`.
///
/// # Errors
///
/// In stage order, all field-identifying (subject = `unit_id`):
///
/// - [`VerifyError::UnitDecryptFailed`] — stage 1 (wrong `k_u`, tampered
///   ciphertext, wrong nonce, or an AAD mismatch from a swapped unit).
/// - [`VerifyError::PaddedLengthMismatch`] /
///   [`VerifyError::NonZeroPadding`] — stage 2, only after successful
///   authentication.
/// - [`VerifyError::TrueLengthRangeMismatch`] — stage 3.
/// - [`VerifyError::UnitCommitMismatch`] (non-covered) /
///   [`VerifyError::FineRootBindingFailed`] (covered) — stage 4.
/// - [`VerifyError::Crypto`] — defensive totality only: a crypto failure
///   class outside this stage's mapped set (none is currently reachable
///   from the functions called here) surfaces through the wrapper arm
///   with its own distinct `crypto-*` code instead of panicking.
pub fn verify_revealed_unit(
    input: RevealedUnitInput<'_>,
    binding: ContentBinding<'_>,
) -> Result<Vec<u8>, VerifyError> {
    let unit_id = input.unit_id.0;

    // Stages 1 + 2 — AEAD open with the BUNDLE-supplied k_u under the
    // manifest nonce/AAD, then the C8 padded-length check, all-zero-pad
    // check, and length-first strip, fused in the single crypto
    // implementation (never forked here). The `usize` conversion is
    // saturating: on 32-bit targets a manifest `true_length ≥ 2^32` makes
    // the (exact, wide-arithmetic) strip comparison unsatisfiable by any
    // real plaintext, so the verdict is the same PaddedLengthMismatch as
    // on 64-bit targets — and the payload below is recomputed in wide
    // arithmetic so the rendered error is target-identical too. Decrypt
    // still runs first, keeping the D27 first-error order intact.
    let true_length = usize::try_from(input.true_length).unwrap_or(usize::MAX);
    let bytes = decrypt_unit_with_key(
        input.k_u,
        input.seal_id,
        input.unit_id,
        input.nonce,
        input.ciphertext,
        true_length,
    )
    .map_err(|error| match error {
        // Stage 1: authentication failure. The AEAD cannot (and must not)
        // distinguish wrong key / wrong nonce / wrong AAD / tampering.
        CryptoError::AeadDecryptFailed => VerifyError::UnitDecryptFailed { unit_id },
        // Stage 2a: authenticated plaintext with the wrong padded length.
        CryptoError::PaddingLengthMismatch { got, .. } => VerifyError::PaddedLengthMismatch {
            unit_id,
            expected: padded_length_u64(input.true_length),
            actual: as_u64(got),
        },
        // Stage 2b: authenticated plaintext with a non-zero pad byte.
        CryptoError::NonZeroPadding { offset } => VerifyError::NonZeroPadding {
            unit_id,
            offset: as_u64(offset),
        },
        // Defensive totality: no other class is reachable from
        // `decrypt_unit_with_key` today; if C ever adds one it surfaces
        // distinctly through the wrapper arm rather than panicking.
        other => VerifyError::Crypto(other),
    })?;

    // Stage 3 — the manifest's true_length must equal the unit's manifest
    // byte-range width (spec line 121: a unit cannot claim more span than
    // it reveals). Pure u64 comparison of two manifest wire values.
    if input.true_length != input.range_width {
        return Err(VerifyError::TrueLengthRangeMismatch {
            unit_id,
            true_length: input.true_length,
            range_width: input.range_width,
        });
    }

    // Stage 4 — bind the bytes to the manifest's single content
    // commitment (spec lines 94, 118).
    match binding {
        ContentBinding::NonCovered {
            unit_salt,
            unit_commit,
        } => {
            verify_unit_commit(unit_salt, &bytes, unit_commit).map_err(|error| match error {
                // This call site checks exactly the unit commitment, so
                // any mismatch kind from it is the unit's opening failure.
                CryptoError::CommitmentMismatch { .. } => {
                    VerifyError::UnitCommitMismatch { unit_id }
                }
                other => VerifyError::Crypto(other),
            })?;
        }
        ContentBinding::FineTreeCovered { verify_range } => {
            verify_range(&bytes)
                .map_err(|source| VerifyError::FineRootBindingFailed { unit_id, source })?;
        }
    }

    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use core::cell::RefCell;

    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    use super::*;
    use crate::crypto::commit::unit_commit;
    use crate::crypto::hkdf::{derive_unit_key, derive_unit_salt};
    use crate::crypto::material::{Key32, MasterSecretRef};
    use crate::crypto::padding::padded_length;
    use crate::crypto::unit_aead::{encrypt_unit, mis_encrypt};

    /// Fixed, public, NON-SECRET fixtures (project rule 6).
    const TEST_W: [u8; 32] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
        0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D,
        0x1E, 0x1F,
    ];
    const TEST_SEED: [u8; 32] = [0x52u8; 32];

    fn w() -> MasterSecretRef<'static> {
        MasterSecretRef::from_bytes(&TEST_W)
    }

    fn seal_id() -> SealId {
        SealId::from_bytes([
            0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD,
            0xBE, 0xBF,
        ])
    }

    /// How the fixture's ciphertext is produced.
    enum Encryption {
        /// The honest sealer path ([`encrypt_unit`]).
        Honest,
        /// The C9 wrong-bucket mis-encryptor (`test-util`): authenticates,
        /// then violates the `padded_length` formula by one 256-B block.
        OverPadded,
        /// The C9 non-zero-pad mis-encryptor (`test-util`): authenticates,
        /// correct bucket, final pad byte `0xFF`.
        NonZeroPad,
    }

    /// One revealed unit as the verifier sees it: manifest-side values +
    /// bundle-side disclosures, all owned so tests can borrow into
    /// [`RevealedUnitInput`] with arbitrary overrides.
    struct Fixture {
        seal_id: SealId,
        unit_id: UnitId,
        content: Vec<u8>,
        ciphertext: Vec<u8>,
        nonce: Nonce24,
        k_u: Key32,
        unit_salt: Salt16,
        unit_commit: CommitmentDigest,
    }

    impl Fixture {
        fn new(unit_id: u64, content: &[u8], encryption: Encryption) -> Self {
            let mut rng = ChaCha20Rng::from_seed(TEST_SEED);
            let unit_id = UnitId(unit_id);
            let (ciphertext, nonce) = match encryption {
                Encryption::Honest => encrypt_unit(w(), &seal_id(), unit_id, content, &mut rng),
                Encryption::OverPadded => mis_encrypt::encrypt_unit_overpadded(
                    w(),
                    &seal_id(),
                    unit_id,
                    content,
                    &mut rng,
                ),
                Encryption::NonZeroPad => mis_encrypt::encrypt_unit_nonzero_padding(
                    w(),
                    &seal_id(),
                    unit_id,
                    content,
                    &mut rng,
                ),
            }
            .expect("test encryption succeeds");
            let unit_salt = derive_unit_salt(w(), unit_id);
            let commitment = unit_commit(&unit_salt, content);
            Self {
                seal_id: seal_id(),
                unit_id,
                content: content.to_vec(),
                ciphertext,
                nonce,
                k_u: derive_unit_key(w(), unit_id),
                unit_salt,
                unit_commit: commitment,
            }
        }

        /// The honest verifier input: manifest and bundle agree.
        fn input(&self) -> RevealedUnitInput<'_> {
            let len = as_u64(self.content.len());
            RevealedUnitInput {
                seal_id: &self.seal_id,
                unit_id: self.unit_id,
                nonce: &self.nonce,
                true_length: len,
                range_width: len,
                k_u: &self.k_u,
                ciphertext: &self.ciphertext,
            }
        }

        /// The honest non-covered binding for this unit.
        fn non_covered(&self) -> ContentBinding<'_> {
            ContentBinding::NonCovered {
                unit_salt: &self.unit_salt,
                unit_commit: &self.unit_commit,
            }
        }
    }

    /// Stage 1 fires first and distinctly: with a wrong bundle-supplied
    /// `k_u`, even a padding-violating ciphertext fails as
    /// `UnitDecryptFailed` (padding is never consulted before
    /// authentication); with the right key the same ciphertext reaches the
    /// distinct stage-2 error — the deterministic D27 first-error order.
    #[test]
    fn wrong_key_fails_before_padding_checks() {
        let fixture = Fixture::new(3, b"stage-order fixture content", Encryption::OverPadded);

        let wrong_key = derive_unit_key(w(), UnitId(999));
        let mut input = fixture.input();
        input.k_u = &wrong_key;
        let decrypt_err =
            verify_revealed_unit(input, fixture.non_covered()).expect_err("wrong key must fail");
        assert_eq!(decrypt_err, VerifyError::UnitDecryptFailed { unit_id: 3 });
        assert_eq!(decrypt_err.code(), "unit-decrypt-failed");

        let padding_err = verify_revealed_unit(fixture.input(), fixture.non_covered())
            .expect_err("over-padded must fail post-AEAD");
        assert_eq!(padding_err.code(), "padded-length-mismatch");
        assert_ne!(decrypt_err.code(), padding_err.code());
    }

    /// Stage 2 rows via the test-util mis-encryptors: the over-padded unit
    /// and the non-zero-pad unit fail with their two distinct errors and
    /// exact field-identifying payloads (`padded_length` recomputed from
    /// the manifest `true_length`; first offending pad offset).
    #[test]
    fn over_padded_and_nonzero_pad_rows_fire_distinctly() {
        let content: &[u8] = b"twenty bytes of unit";
        let expected_padded = as_u64(padded_length(content.len()));

        let over = Fixture::new(4, content, Encryption::OverPadded);
        let over_err = verify_revealed_unit(over.input(), over.non_covered())
            .expect_err("over-padded must fail");
        assert_eq!(
            over_err,
            VerifyError::PaddedLengthMismatch {
                unit_id: 4,
                expected: expected_padded,
                actual: expected_padded + 256,
            }
        );

        let nonzero = Fixture::new(5, content, Encryption::NonZeroPad);
        let nonzero_err = verify_revealed_unit(nonzero.input(), nonzero.non_covered())
            .expect_err("non-zero pad must fail");
        assert_eq!(
            nonzero_err,
            VerifyError::NonZeroPadding {
                unit_id: 5,
                offset: expected_padded - 1,
            }
        );

        assert_ne!(over_err.code(), nonzero_err.code());
    }

    /// Stage 3: a manifest whose `true_length` differs from the unit's
    /// byte-range width fails with `TrueLengthRangeMismatch` — and only
    /// after the padding stages (an over-padded unit with a wrong range
    /// width reports the stage-2 error), and before content binding (an
    /// honest unit with a wrong range width *and* a wrong commitment
    /// reports the stage-3 error).
    #[test]
    fn true_length_range_width_binding() {
        let fixture = Fixture::new(6, b"span-claim fixture", Encryption::Honest);
        let len = as_u64(fixture.content.len());

        let mut input = fixture.input();
        input.range_width = len + 1;
        let err = verify_revealed_unit(input, fixture.non_covered())
            .expect_err("width mismatch must fail");
        assert_eq!(
            err,
            VerifyError::TrueLengthRangeMismatch {
                unit_id: 6,
                true_length: len,
                range_width: len + 1,
            }
        );
        assert_eq!(err.code(), "true-length-range-mismatch");

        // Stage 2 before stage 3: over-padded + wrong width ⇒ padding.
        let over = Fixture::new(6, b"span-claim fixture", Encryption::OverPadded);
        let mut input = over.input();
        input.range_width = len + 1;
        assert_eq!(
            verify_revealed_unit(input, over.non_covered())
                .expect_err("must fail")
                .code(),
            "padded-length-mismatch"
        );

        // Stage 3 before stage 4: wrong width + wrong commitment ⇒ range.
        let mut input = fixture.input();
        input.range_width = len + 1;
        let wrong_commit = [0xEEu8; 32];
        let binding = ContentBinding::NonCovered {
            unit_salt: &fixture.unit_salt,
            unit_commit: &wrong_commit,
        };
        assert_eq!(
            verify_revealed_unit(input, binding)
                .expect_err("must fail")
                .code(),
            "true-length-range-mismatch"
        );
    }

    /// Stage 4, non-covered arm: the honest opening verifies and returns
    /// the exact unit bytes; a wrong bundle-supplied `unit_salt` and an
    /// altered manifest `unit_commit` both fail as `UnitCommitMismatch`
    /// (wrong salt, wrong bytes, and wrong digest are indistinguishable
    /// openings of a salted commitment).
    #[test]
    fn non_covered_commit_binding() {
        let fixture = Fixture::new(8, b"bound by unit_commit", Encryption::Honest);

        let bytes = verify_revealed_unit(fixture.input(), fixture.non_covered())
            .expect("honest unit verifies");
        assert_eq!(bytes, fixture.content);

        let wrong_salt = derive_unit_salt(w(), UnitId(999));
        let binding = ContentBinding::NonCovered {
            unit_salt: &wrong_salt,
            unit_commit: &fixture.unit_commit,
        };
        let err = verify_revealed_unit(fixture.input(), binding).expect_err("must fail");
        assert_eq!(err, VerifyError::UnitCommitMismatch { unit_id: 8 });
        assert_eq!(err.code(), "unit-commit-mismatch");

        let mut altered = fixture.unit_commit;
        altered[31] ^= 0x80;
        let binding = ContentBinding::NonCovered {
            unit_salt: &fixture.unit_salt,
            unit_commit: &altered,
        };
        assert_eq!(
            verify_revealed_unit(fixture.input(), binding).expect_err("must fail"),
            VerifyError::UnitCommitMismatch { unit_id: 8 }
        );
    }

    /// Stage 4, covered arm (G13 seam): the placeholder errors drive
    /// through to their two distinct `VerifyError` codes — the over-broad
    /// cover row is its own code, never folded into the generic binding
    /// failure — and the check closure receives exactly the stripped,
    /// verified unit bytes.
    #[test]
    fn covered_arm_seam_drives_placeholder_errors_to_distinct_codes() {
        let fixture = Fixture::new(9, b"covered by fine_root", Encryption::Honest);

        // Success path: the seam sees the stripped bytes, not the padded
        // plaintext or the ciphertext.
        let seen: RefCell<Vec<u8>> = RefCell::new(Vec::new());
        let record = |bytes: &[u8]| -> Result<(), FineTreeError> {
            seen.borrow_mut().extend_from_slice(bytes);
            Ok(())
        };
        let bytes = verify_revealed_unit(
            fixture.input(),
            ContentBinding::FineTreeCovered {
                verify_range: &record,
            },
        )
        .expect("covered unit verifies when the range check passes");
        assert_eq!(bytes, fixture.content);
        assert_eq!(*seen.borrow(), fixture.content);

        // Generic binding failure keeps R1's original stable code.
        let root_mismatch =
            |_: &[u8]| -> Result<(), FineTreeError> { Err(FineTreeError::RootMismatch) };
        let err = verify_revealed_unit(
            fixture.input(),
            ContentBinding::FineTreeCovered {
                verify_range: &root_mismatch,
            },
        )
        .expect_err("must fail");
        assert_eq!(
            err,
            VerifyError::FineRootBindingFailed {
                unit_id: 9,
                source: FineTreeError::RootMismatch,
            }
        );
        assert_eq!(err.code(), "fine-root-binding-failed");

        // The over-broad-cover rejection surfaces as its own distinct
        // code through the same arm (R2 accept; G19 constructs the real
        // fixture once G13 lands).
        let over_broad =
            |_: &[u8]| -> Result<(), FineTreeError> { Err(FineTreeError::OverBroadCover) };
        let err = verify_revealed_unit(
            fixture.input(),
            ContentBinding::FineTreeCovered {
                verify_range: &over_broad,
            },
        )
        .expect_err("must fail");
        assert_eq!(
            err,
            VerifyError::FineRootBindingFailed {
                unit_id: 9,
                source: FineTreeError::OverBroadCover,
            }
        );
        assert_eq!(err.code(), "fine-root-over-broad-cover");
    }

    /// Edge vector: the empty unit — `true_length = 0` pads to one full
    /// 256-B block (spec line 91) — verifies and returns empty bytes.
    #[test]
    fn edge_empty_unit_true_length_zero() {
        let fixture = Fixture::new(10, b"", Encryption::Honest);
        // The AEAD plaintext is exactly one 256-B padded block.
        assert_eq!(fixture.ciphertext.len(), 256 + 16);
        let bytes = verify_revealed_unit(fixture.input(), fixture.non_covered())
            .expect("empty unit verifies");
        assert!(bytes.is_empty());
    }

    /// Edge vector: a unit ending exactly on a 256-B boundary takes one
    /// extra all-zero pad block (unambiguous by the always-≥1-pad-byte
    /// formula) and still strips back to its exact bytes.
    #[test]
    fn edge_unit_ending_on_block_boundary() {
        let content = [0x7Eu8; 256];
        let fixture = Fixture::new(11, &content, Encryption::Honest);
        assert_eq!(fixture.ciphertext.len(), 512 + 16);
        let bytes = verify_revealed_unit(fixture.input(), fixture.non_covered())
            .expect("boundary unit verifies");
        assert_eq!(bytes, content);
    }

    /// Edge vector: the single-byte unit verifies through both binding
    /// arms — the covered arm passes exactly one byte to the range check
    /// (the single-leaf-tree end-to-end case itself lands with G13/G17).
    #[test]
    fn edge_single_byte_unit() {
        let fixture = Fixture::new(12, b"x", Encryption::Honest);

        let bytes = verify_revealed_unit(fixture.input(), fixture.non_covered())
            .expect("single-byte unit verifies (non-covered)");
        assert_eq!(bytes, b"x");

        let leaf_count: RefCell<usize> = RefCell::new(usize::MAX);
        let single_leaf = |bytes: &[u8]| -> Result<(), FineTreeError> {
            *leaf_count.borrow_mut() = bytes.len();
            Ok(())
        };
        verify_revealed_unit(
            fixture.input(),
            ContentBinding::FineTreeCovered {
                verify_range: &single_leaf,
            },
        )
        .expect("single-byte unit verifies (covered)");
        assert_eq!(*leaf_count.borrow(), 1);
    }

    /// The nonce is read only from the manifest unit table: this API's one
    /// nonce input *is* the manifest value (F's bundle schema carries no
    /// per-unit nonce field, so there is no bundle nonce to consult — and
    /// no parameter through which one could be supplied). Substituting any
    /// other value fails authentication, proving the input is
    /// verdict-bearing.
    #[test]
    fn nonce_is_manifest_side_only() {
        let fixture = Fixture::new(13, b"nonce provenance", Encryption::Honest);

        let mut flipped = *fixture.nonce.as_bytes();
        flipped[0] ^= 0x01;
        let substituted = Nonce24::from_bytes(flipped);
        let mut input = fixture.input();
        input.nonce = &substituted;
        assert_eq!(
            verify_revealed_unit(input, fixture.non_covered()).expect_err("must fail"),
            VerifyError::UnitDecryptFailed { unit_id: 13 }
        );

        verify_revealed_unit(fixture.input(), fixture.non_covered())
            .expect("manifest nonce verifies");
    }

    /// Adversarial manifest `true_length` values — including ones
    /// exceeding a 32-bit target's `usize` — produce the deterministic
    /// stage-2 error with target-independent wide-arithmetic payloads,
    /// never a panic (and never before stage 1: with a wrong key they are
    /// still `UnitDecryptFailed`).
    #[test]
    fn adversarial_true_length_is_total_and_target_independent() {
        let fixture = Fixture::new(14, b"adversarial manifest", Encryption::Honest);

        for extreme in [u64::from(u32::MAX) + 1, u64::MAX - 255, u64::MAX] {
            let mut input = fixture.input();
            input.true_length = extreme;
            input.range_width = extreme;
            let err = verify_revealed_unit(input, fixture.non_covered())
                .expect_err("absurd true_length must fail");
            match err {
                VerifyError::PaddedLengthMismatch {
                    unit_id,
                    expected,
                    actual,
                } => {
                    assert_eq!(unit_id, 14);
                    assert_eq!(expected, padded_length_u64(extreme));
                    assert_eq!(actual, as_u64(fixture.ciphertext.len() - 16));
                }
                other => panic!("expected PaddedLengthMismatch, got {other:?}"),
            }

            // Stage order holds even here: wrong key still fails first.
            let wrong_key = derive_unit_key(w(), UnitId(999));
            let mut input = fixture.input();
            input.true_length = extreme;
            input.range_width = extreme;
            input.k_u = &wrong_key;
            assert_eq!(
                verify_revealed_unit(input, fixture.non_covered()).expect_err("must fail"),
                VerifyError::UnitDecryptFailed { unit_id: 14 }
            );
        }

        // The u64 recompute agrees with the usize formula everywhere the
        // two domains overlap, and saturates (only) in the degenerate top
        // range no real buffer can occupy.
        assert_eq!(padded_length_u64(0), 256);
        assert_eq!(padded_length_u64(255), 256);
        assert_eq!(padded_length_u64(256), 512);
        assert_eq!(padded_length_u64(u64::MAX), u64::MAX);
    }
}
