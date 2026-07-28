//! F10 — version discriminants, per-version decode dispatch, and reserved
//! slots, exercised **from real bytes**.
//!
//! Spec: MVP-SPEC.md line 123 (format stability), line 98 (the body's
//! `format_version`), line 153 (M0). Registry: `docs/format/registry-v1.md`
//! §7.2 key 0 (manifest body), §7.6 key 0 (bundle), §9 (version policy).
//!
//! The bytes come from the hand-rolled writers in
//! [`manifest_wire`]/[`bundle_wire`], not from the crate's own encoder —
//! `ManifestBodyV1`/`BundleV1` cannot *represent* a version-2 artifact, which
//! is exactly why proving dispatch rejects one needs a writer that does not
//! share the schema's assumptions.

#[path = "manifest_wire/mod.rs"]
mod manifest_wire;

#[path = "bundle_wire/mod.rs"]
mod bundle_wire;

use antseal_core::bundle::{BundleError, BundleV1, SealProof, SealProofError};
use antseal_core::format::{SUPPORTED_VERSIONS, peek_format_version};
use antseal_core::manifest::{Manifest, ManifestBodyV1, ManifestError};

use manifest_wire::{bstr, envelope_around, map, set, uint, uint_non_shortest};

/// Versions with no row in the dispatch table. `0` matters as much as `2`:
/// a zero discriminant is not "absent", it is a version we never released.
const UNROWED: [u64; 6] = [0, 2, 3, 23, 24, u64::MAX];

/// One mutation applied to a hand-built body entry list.
type BodyMutation = Box<dyn Fn(&mut Vec<(u64, Vec<u8>)>)>;

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

/// A manifest body at an arbitrary declared version, otherwise valid v1.
fn body_at_version(version: u64) -> Vec<u8> {
    let mut body = manifest_wire::default_body();
    set(
        &mut body,
        antseal_core::manifest::registry::key::body::FORMAT_VERSION,
        uint(version),
    );
    map(&body)
}

/// A bundle at an arbitrary declared version, otherwise valid v1.
fn bundle_at_version(version: u64) -> Vec<u8> {
    let mut bundle = bundle_wire::default_bundle();
    set(
        &mut bundle,
        antseal_core::bundle::registry::key::bundle::FORMAT_VERSION,
        uint(version),
    );
    bundle_wire::encode(&bundle)
}

fn expect_manifest_version_error(bytes: &[u8], found: u64, ctx: &str) {
    match ManifestBodyV1::decode(bytes) {
        Err(ManifestError::UnsupportedFormatVersion {
            found: got,
            supported,
        }) => {
            assert_eq!(got, found, "{ctx}: wrong `found`");
            assert_eq!(supported, SUPPORTED_VERSIONS, "{ctx}: wrong `supported`");
        }
        other => panic!("{ctx}: expected UnsupportedFormatVersion({found}), got {other:?}"),
    }
}

fn expect_bundle_version_error(bytes: &[u8], found: u64, ctx: &str) {
    match BundleV1::decode(bytes) {
        Err(BundleError::UnsupportedFormatVersion {
            found: got,
            supported,
        }) => {
            assert_eq!(got, found, "{ctx}: wrong `found`");
            assert_eq!(supported, SUPPORTED_VERSIONS, "{ctx}: wrong `supported`");
        }
        other => panic!("{ctx}: expected UnsupportedFormatVersion({found}), got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// the F10 accept: a version-2 artifact yields UnsupportedVersion, and nothing
// else
// ---------------------------------------------------------------------------

/// The headline accept for the manifest half: a synthetic version-2 body is
/// the version error — not a canonicality error, not an unknown-key error.
#[test]
fn synthetic_version_2_manifest_is_unsupported_version() {
    let bytes = body_at_version(2);
    expect_manifest_version_error(&bytes, 2, "v2 body");
    assert_eq!(
        ManifestBodyV1::decode(&bytes)
            .expect_err("must reject")
            .code(),
        "manifest-unsupported-format-version"
    );
}

/// The headline accept for the bundle half.
#[test]
fn synthetic_version_2_bundle_is_unsupported_version() {
    let bytes = bundle_at_version(2);
    expect_bundle_version_error(&bytes, 2, "v2 bundle");
    assert_eq!(
        BundleV1::decode(&bytes).expect_err("must reject").code(),
        "bundle-unsupported-format-version"
    );
}

/// Every unrowed discriminant behaves alike — `0` and `u64::MAX` included, so
/// the table is a lookup and not a `found > 1` comparison.
#[test]
fn every_unrowed_version_is_the_same_rejection_class() {
    for found in UNROWED {
        expect_manifest_version_error(&body_at_version(found), found, "body");
        expect_bundle_version_error(&bundle_at_version(found), found, "bundle");
    }
}

/// **Precedence.** Dispatch runs *before* the schema pass, so an artifact
/// that is both a future version *and* full of things v1 would reject still
/// reports the version — the whole point of F10. A verifier that reported
/// "unknown key 8" for a v2 manifest would tell the user their file is
/// corrupt when it is merely newer.
#[test]
fn version_wins_over_every_v1_schema_rejection() {
    use antseal_core::manifest::registry::key as mkey;

    // Each mutation is, on its own, a *different* v1 rejection class.
    let mutations: Vec<(&str, BodyMutation)> = vec![
        (
            "reserved key",
            Box::new(|b: &mut Vec<(u64, Vec<u8>)>| set(b, 8, uint(0))),
        ),
        (
            "unknown key",
            Box::new(|b: &mut Vec<(u64, Vec<u8>)>| set(b, 24, uint(0))),
        ),
        (
            "missing required key",
            Box::new(|b: &mut Vec<(u64, Vec<u8>)>| manifest_wire::remove(b, mkey::body::TITLE)),
        ),
        (
            "wrong-length seal_id",
            Box::new(|b: &mut Vec<(u64, Vec<u8>)>| set(b, mkey::body::SEAL_ID, bstr(&[0u8; 15]))),
        ),
        (
            "empty sig_policy",
            Box::new(|b: &mut Vec<(u64, Vec<u8>)>| {
                set(b, mkey::body::SIG_POLICY, manifest_wire::array(&[]))
            }),
        ),
    ];

    for (name, mutate) in mutations {
        // Sanity: at v1 the mutation really does produce a *different* error.
        let mut v1 = manifest_wire::default_body();
        mutate(&mut v1);
        let v1_err = ManifestBodyV1::decode(&map(&v1))
            .expect_err(&format!("{name}: mutation must reject at v1"));
        assert_ne!(
            v1_err.code(),
            "manifest-unsupported-format-version",
            "{name}: control case must not already be the version error"
        );

        // At v2 the same bytes are the version error instead.
        let mut v2 = manifest_wire::default_body();
        mutate(&mut v2);
        set(&mut v2, mkey::body::FORMAT_VERSION, uint(2));
        expect_manifest_version_error(&map(&v2), 2, name);
    }
}

/// The same precedence on the bundle's own discriminant, including against a
/// **canonicality** failure elsewhere in the map. A future-version bundle is
/// "too new", never "corrupt".
#[test]
fn bundle_version_wins_over_schema_and_canonicality_rejections() {
    use antseal_core::bundle::registry::key as bkey;

    // Reserved slot (bundle key 10, the v1.1 `range_reveals` slot).
    let mut reserved = bundle_wire::default_bundle();
    set(&mut reserved, bkey::bundle::RESERVED_RANGE_REVEALS, uint(0));
    assert_eq!(
        BundleV1::decode(&bundle_wire::encode(&reserved))
            .expect_err("must reject")
            .code(),
        "bundle-reserved-key",
        "control: at v1 this is the reserved-slot error"
    );
    set(&mut reserved, bkey::bundle::FORMAT_VERSION, uint(2));
    expect_bundle_version_error(&bundle_wire::encode(&reserved), 2, "reserved + v2");

    // Non-canonical integer *after* key 0 — the peek has already read the
    // version by the time those bytes are reached.
    let mut noncanon = bundle_wire::default_bundle();
    set(
        &mut noncanon,
        bkey::bundle::STORAGE_RECORD,
        map(&[(0, uint_non_shortest(1))]),
    );
    assert_eq!(
        BundleV1::decode(&bundle_wire::encode(&noncanon))
            .expect_err("must reject")
            .code(),
        "cbor-non-shortest-int",
        "control: at v1 this is a canonicality error"
    );
    set(&mut noncanon, bkey::bundle::FORMAT_VERSION, uint(2));
    expect_bundle_version_error(&bundle_wire::encode(&noncanon), 2, "non-canonical + v2");
}

/// The two discriminants are **independent** (registry §7.6 key 0 vs §7.2
/// key 0): a v1 bundle wrapping a v2 manifest is a *manifest* version error,
/// and it arrives through the pipeline's manifest arm, not its bundle arm.
#[test]
fn the_two_discriminants_are_independent() {
    let v2_manifest = envelope_around(&body_at_version(2));
    let mut bundle = bundle_wire::default_bundle();
    set(
        &mut bundle,
        antseal_core::bundle::registry::key::bundle::MANIFEST,
        bstr(&v2_manifest),
    );
    let bytes = bundle_wire::encode(&bundle);

    // Layer 1 is happy: the bundle itself is v1 and well formed (D78 — the
    // bundle decoder never opens the manifest).
    BundleV1::decode(&bytes).expect("the bundle is a valid v1 bundle");

    match SealProof::decode(&bytes) {
        Err(SealProofError::Manifest {
            source: ManifestError::UnsupportedFormatVersion { found, .. },
        }) => assert_eq!(found, 2),
        other => panic!("expected the manifest's version error, got {other:?}"),
    }
    assert_eq!(
        SealProof::decode(&bytes).expect_err("must reject").code(),
        "manifest-unsupported-format-version"
    );
}

/// A **versionless** artifact is malformed, not unsupported. The peek
/// declines rather than guessing, and the schema pass produces the
/// authoritative `missing-key` rejection.
#[test]
fn a_missing_discriminant_is_missing_key_not_unsupported_version() {
    use antseal_core::bundle::registry::key as bkey;
    use antseal_core::manifest::registry::key as mkey;

    let mut body = manifest_wire::default_body();
    manifest_wire::remove(&mut body, mkey::body::FORMAT_VERSION);
    assert_eq!(
        ManifestBodyV1::decode(&map(&body))
            .expect_err("must reject")
            .code(),
        "manifest-missing-key"
    );

    let mut bundle = bundle_wire::default_bundle();
    manifest_wire::remove(&mut bundle, bkey::bundle::FORMAT_VERSION);
    assert_eq!(
        BundleV1::decode(&bundle_wire::encode(&bundle))
            .expect_err("must reject")
            .code(),
        "bundle-missing-key"
    );
}

/// A discriminant of the wrong *type* is a codec rejection, not a version
/// one: the peek cannot read it, so the real decoder reports what it is.
#[test]
fn a_non_integer_discriminant_is_a_codec_rejection() {
    use antseal_core::manifest::registry::key as mkey;

    let mut body = manifest_wire::default_body();
    set(
        &mut body,
        mkey::body::FORMAT_VERSION,
        manifest_wire::tstr("1"),
    );
    let err = ManifestBodyV1::decode(&map(&body)).expect_err("must reject");
    assert!(
        err.code().starts_with("cbor-"),
        "expected a codec code, got {}",
        err.code()
    );
}

/// A non-canonical *version head* is a canonicality rejection at v1 — the
/// peek shares F3's strict reader, so it cannot be fooled into reading a
/// version out of bytes the decoder would reject.
#[test]
fn a_non_canonical_version_head_is_rejected_as_non_canonical() {
    use antseal_core::manifest::registry::key as mkey;

    let mut body = manifest_wire::default_body();
    set(&mut body, mkey::body::FORMAT_VERSION, uint_non_shortest(1));
    assert_eq!(
        ManifestBodyV1::decode(&map(&body))
            .expect_err("must reject")
            .code(),
        "cbor-non-shortest-int"
    );

    // …and the same for a *future* version written non-shortest: it must not
    // become a version error, because the artifact is not canonical CBOR at
    // all and its declared version is therefore not trustworthy.
    let mut body = manifest_wire::default_body();
    set(&mut body, mkey::body::FORMAT_VERSION, uint_non_shortest(2));
    assert_eq!(
        ManifestBodyV1::decode(&map(&body))
            .expect_err("must reject")
            .code(),
        "cbor-non-shortest-int"
    );
}

/// Valid v1 artifacts still decode — dispatch is transparent on the happy
/// path, and the wrapping envelope/pipeline paths reach it too.
#[test]
fn v1_still_decodes_through_dispatch() {
    let body = map(&manifest_wire::default_body());
    let decoded = ManifestBodyV1::decode(&body).expect("valid v1 body");
    assert_eq!(decoded.format_version(), 1);

    let envelope = envelope_around(&body);
    let manifest = Manifest::decode(&envelope).expect("valid v1 manifest");
    assert_eq!(manifest.body().format_version(), 1);

    let bundle = bundle_wire::encode(&bundle_wire::default_bundle());
    BundleV1::decode(&bundle).expect("valid v1 bundle");
    SealProof::decode(&bundle).expect("valid v1 sealproof");
}

// ---------------------------------------------------------------------------
// the peek, over real artifacts
// ---------------------------------------------------------------------------

/// The public peek reads the discriminant of both artifact kinds without
/// decoding either — the property F11's caps and any future streaming
/// verifier rely on.
#[test]
fn peek_reads_both_discriminants_without_decoding() {
    for v in [1u64, 2, u64::MAX] {
        assert_eq!(peek_format_version(&body_at_version(v)), Some(v));
        assert_eq!(peek_format_version(&bundle_at_version(v)), Some(v));
    }
    // The envelope is NOT versioned — its shape is frozen across versions,
    // so its first key is `body`, whose value is a bstr and not a version.
    assert_eq!(
        peek_format_version(&envelope_around(&body_at_version(1))),
        None,
        "the manifest envelope carries no discriminant of its own"
    );
}
