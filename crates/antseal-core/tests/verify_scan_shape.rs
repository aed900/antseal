//! R54 — the verify pipeline is linear in its input at the D10 cap product.
//!
//! D10 §2 states in bold that `MAX_FILE_COUNT` (16 384) and
//! `MAX_UNIT_COUNT` (65 536) are **simultaneously reachable** inside
//! `MAX_MANIFEST_BYTES`, and nothing bounds their product (§5 amendment,
//! 2026-08-01). The 2026-07-31 adversarial review (finding 6, plus U1/U3)
//! found stages 2–4 and the report's reveal set built from nested linear
//! scans over those adversary-controlled counts — ~10⁹ pre-authenticator
//! iterations for a legal ~7 MiB bundle revealing **nothing** — which in
//! the browser verifier is a hang. R54 replaced every such scan with a
//! built-once index; this test is the permanent guard.
//!
//! # The two guards, and why not an operation counter
//!
//! The honest guard would count operations, but the scans lived in five
//! modules and an operation counter would thread test-only state through
//! production code paths (and D26's precedent for counters is
//! G9-instrumented *builders*, not the verifier). Instead, two
//! complementary asserts over one fixture pair (half-cap and full-cap —
//! the full work has exactly 2× the files and 2× the units):
//!
//! 1. **A scaling ratio, machine-speed-free.** A linear verifier costs
//!    ~2× at full-cap; a files×units one ~4×. Measured 2026-08-01 on the
//!    project's 2-core box: pre-R54 **3.73×** debug / **4.46×** release;
//!    post-R54 **2.01×** debug / **2.13×** release. The 3.0 threshold
//!    sits ~45 % above the measured linear ratio (load noise between two
//!    back-to-back runs is far smaller) and below every measured
//!    quadratic one. A regression confined to a single stage lands near
//!    the threshold rather than safely above it — accepted: the absolute
//!    bound backs it up, and a flaky guard would be disabled, which
//!    guards nothing.
//! 2. **A generous absolute smoke bound.** Measured full-cap
//!    `verify_bundle`: pre-R54 **28.96 s** debug / **3.11 s** release;
//!    post-R54 **2.61 s** debug / **0.13 s** release. 15 s is ~5.7× the
//!    measured post-fix debug time — CI load does not plausibly cost
//!    5.7× on a wall clock — and the full pre-R54 shape at ~29 s cannot
//!    pass it.

use std::time::{Duration, Instant};

use antseal_core::bundle::{BundleParts, BundleV1, StorageRecord, encode_bundle};
use antseal_core::codec::caps;
use antseal_core::crypto::disclosure::UnitBinding;
use antseal_core::crypto::material::{Key32, MasterSecretRef};
use antseal_core::crypto::secrets::SealId;
use antseal_core::crypto::sig_policy::{SigPolicy, public_keys, sign_body};
use antseal_core::manifest::body::{
    ByteRange, CanonMode, ContentAddress, FileEntry, FineTree, ManifestBodyV1,
    Nonce24 as ManifestNonce, UnitEntry, encode_body,
};
use antseal_core::manifest::registry::UnitKind;
use antseal_core::manifest::{SigAlgMap, SigMaterial, encode_envelope};
use antseal_core::verify::{VerifyOptions, verify_bundle};

/// Fixed, public, NON-SECRET master secret (project rule 6): the same
/// recognisable pattern the R5 pipeline fixture uses; derived from no real
/// secret and committed in no artifact.
const TEST_W: [u8; 32] = [0x5A; 32];
/// Fixed, public, NON-SECRET `seal_id`.
const TEST_SEAL_ID: [u8; 16] = [0xB0; 16];

/// Units per file at the cap product: `16 384 × 4 = 65 536`, exactly D10
/// §2's "16 384 files at four units each" legitimate-maximum example.
const UNITS_PER_FILE: u64 = 4;

fn w() -> MasterSecretRef<'static> {
    MasterSecretRef::from_bytes(&TEST_W)
}

/// Build a **valid** no-reveal `.sealproof` over `file_count` binary files
/// of `UNITS_PER_FILE` one-byte units each.
///
/// Every commitment digest is an arbitrary public pattern: with nothing
/// revealed and no file touched, no commitment is ever opened, no fine
/// tree is ever rebuilt, and no ciphertext exists — the bundle's only
/// verifiable claims are its structure and its (genuine) hybrid signature.
/// That is precisely the adversarial shape of the 2026-07-31 review's
/// finding 6: maximal count-driven work, zero honest AEAD work to hide
/// behind.
fn at_scale_no_reveal_bundle(file_count: u64) -> Vec<u8> {
    let seal_id = SealId::from_bytes(TEST_SEAL_ID);

    let mut files = Vec::with_capacity(usize::try_from(file_count).expect("fits"));
    let mut unit_id: u64 = 0;
    for _ in 0..file_count {
        let mut units = Vec::with_capacity(usize::try_from(UNITS_PER_FILE).expect("fits"));
        for offset in 0..UNITS_PER_FILE {
            units.push(UnitEntry::new(
                unit_id,
                UnitKind::Normal,
                ByteRange::new(offset, 1),
                1,
                UnitBinding::FineTreeCovered,
                ManifestNonce::from_bytes([0x5C; 24]),
                ContentAddress::from_bytes([0xAD; 32]),
            ));
            unit_id += 1;
        }
        files.push(
            FileEntry::new(
                [0xF1; 32],
                [0xF2; 32],
                CanonMode::Binary,
                UNITS_PER_FILE,
                FineTree::Present { root: [0xF3; 32] },
                units,
            )
            .expect("a tiled covered file entry is well formed"),
        );
    }

    let policy = SigPolicy::hybrid();
    let pubkeys =
        SigAlgMap::new(SigMaterial::Pubkey, public_keys(w(), &policy)).expect("fixture pubkeys");
    let body = ManifestBodyV1::new(
        "antseal-r54/1".to_owned(),
        seal_id,
        "R54 at-cap scan-shape fixture".to_owned(),
        1_767_225_600,
        pubkeys,
        policy.algorithms().to_vec(),
        files,
    )
    .expect("the at-cap body is inside the D10 caps");
    let body_bytes = encode_body(body).expect("fixture body encodes");
    let signatures = SigAlgMap::new(SigMaterial::Signature, sign_body(w(), &policy, &body_bytes))
        .expect("fixture signatures");
    let manifest_bytes = encode_envelope(&body_bytes, &signatures).expect("fixture envelope");

    let bundle = BundleV1::new(BundleParts {
        manifest: &manifest_bytes,
        storage_record: StorageRecord::new(
            ContentAddress::from_bytes([0x77; 32]),
            ManifestNonce::from_bytes([0x78; 24]),
            Key32::from_bytes([0x79; 32]),
        ),
        ots_anchors: Vec::new(),
        tsa_anchors: Vec::new(),
        receipt: None,
        covered_reveals: Vec::new(),
        noncovered_reveals: Vec::new(),
        touched_files: Vec::new(),
        full_reveals: Vec::new(),
    })
    .expect("the no-reveal bundle is well formed");
    encode_bundle(&bundle).expect("fixture bundle encodes")
}

/// Verify `input`, assert the expected report shape for a no-reveal work
/// of `file_count` files, and return the elapsed wall time.
fn verify_and_check(input: &[u8], file_count: u64) -> Duration {
    let start = Instant::now();
    let report = verify_bundle(input, &VerifyOptions::new())
        .expect("a valid no-reveal at-scale bundle verifies");
    let elapsed = start.elapsed();
    eprintln!(
        "verify_bundle over {file_count} files / {} B: {elapsed:?}",
        input.len()
    );

    assert!(report.evidence.passed);
    assert_eq!(report.evidence.units_verified, 0, "nothing is revealed");
    assert!(
        report.reveal.files.is_empty(),
        "no file is touched, so none is disclosed"
    );
    assert_eq!(
        report.reveal.unrevealed_files.len() as u64,
        file_count,
        "every file is a committed placeholder"
    );
    elapsed
}

/// D10's bold §2 claim, held to: the cap-product manifest really is legal.
#[test]
fn the_cap_product_fixture_is_inside_the_frozen_caps() {
    assert_eq!(
        caps::MAX_FILE_COUNT * UNITS_PER_FILE,
        caps::MAX_UNIT_COUNT,
        "the fixture's shape is D10 §2's own at-both-caps example"
    );
}

/// The R54 guard: the at-cap no-reveal bundle — `MAX_FILE_COUNT` files,
/// `MAX_UNIT_COUNT` units, nothing revealed — verifies inside a bound only
/// a scan-shape regression can breach (module docs for the calibration).
#[test]
fn at_cap_no_reveal_bundle_verifies_in_linear_time() {
    let full = at_scale_no_reveal_bundle(caps::MAX_FILE_COUNT);
    assert!(
        full.len() as u64 <= caps::MAX_MANIFEST_BYTES,
        "the whole bundle sits inside even the manifest cap ({} B) — \
         D10 §2's simultaneous-reachability claim, demonstrated",
        full.len()
    );

    let half = at_scale_no_reveal_bundle(caps::MAX_FILE_COUNT / 2);
    let half_elapsed = verify_and_check(&half, caps::MAX_FILE_COUNT / 2);
    let full_elapsed = verify_and_check(&full, caps::MAX_FILE_COUNT);

    // Guard 1 — the scaling ratio (module docs: measured ~2.0–2.1 linear,
    // ~3.7–4.5 quadratic; machine speed cancels).
    let ratio = full_elapsed.as_secs_f64() / half_elapsed.as_secs_f64().max(1e-9);
    assert!(
        ratio < 3.0,
        "verify_bundle scaled {ratio:.2}× for a 2× input \
         (half-cap {half_elapsed:?} → full-cap {full_elapsed:?}); \
         a linear pipeline scales ~2× — a files×units scan has likely \
         returned (R54; 2026-07-31 review, finding 6 / U1)"
    );

    // Guard 2 — the generous absolute smoke bound (module docs: ~5.7× the
    // measured post-R54 debug time; ~half the measured pre-R54 one).
    let bound = Duration::from_secs(15);
    assert!(
        full_elapsed < bound,
        "verify_bundle took {full_elapsed:?} at the D10 cap product \
         (half-cap: {half_elapsed:?}); the R54 scan-shape guard allows \
         {bound:?} — a quadratic files×units scan has likely returned \
         (2026-07-31 review, finding 6 / U1)"
    );
}
