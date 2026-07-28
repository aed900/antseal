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

// ---------------------------------------------------------------------------
// reserved-slot mechanics (F4's registry, exercised exhaustively)
// ---------------------------------------------------------------------------
//
// Registry §1 rule 4 / §7.15: every v1 key lives in `0..=23`. Inside that
// band an unassigned key is **reserved** for a future v1.x field, and its
// presence means a newer producer met an older verifier — a different claim
// from "this key was never assignable", which is what `>= 24` means. The two
// therefore carry different codes.
//
// The sweep below injects **every** reserved key of **every** v1 map into
// otherwise-valid input and requires the reserved-slot error naming that key.
// Driving it off `MapId::ALL` / `BundleMapId::ALL` and off each map's own
// `reserved_band()` is what makes it exhaustive by construction: a map added
// to the registry without a reserved-slot rejection fails here.

use antseal_core::bundle::registry::{BundleMapId, key as bkey};
use antseal_core::manifest::registry::{MapId, V1_KEY_BAND_MAX, key as mkey};

/// The first key that was never assignable in v1 — one past the band.
const FIRST_UNKNOWN_KEY: u64 = V1_KEY_BAND_MAX + 1;

/// A manifest body carrying `key` injected into an instance of `map_id`,
/// everything else valid v1.
fn body_with_injected(map_id: MapId, key: u64) -> Vec<u8> {
    let injected = uint(0);
    match map_id {
        MapId::Envelope => unreachable!("the envelope is handled separately: no reserved band"),
        MapId::Body => {
            let mut b = manifest_wire::default_body();
            set(&mut b, key, injected);
            map(&b)
        }
        MapId::FileEntry => {
            let mut f = manifest_wire::text_file_with_mirror();
            set(&mut f, key, injected);
            map(&manifest_wire::body(vec![f]))
        }
        MapId::Descriptor => {
            let mut d = manifest_wire::descriptor(1, true);
            set(&mut d, key, injected);
            let mut f = manifest_wire::text_file_with_mirror();
            set(&mut f, mkey::file::DESCRIPTOR, map(&d));
            map(&manifest_wire::body(vec![f]))
        }
        MapId::UnitEntry => {
            let mut u = manifest_wire::covered_unit(0, 0, 1024);
            set(&mut u, key, injected);
            let f = manifest_wire::file_entry(
                1,
                true,
                1024,
                vec![u, manifest_wire::noncovered_unit(1, 1, 0, 1030)],
            );
            map(&manifest_wire::body(vec![f]))
        }
    }
}

/// A bundle carrying `key` injected into an instance of `map_id`, everything
/// else valid v1.
fn bundle_with_injected(map_id: BundleMapId, key: u64) -> Vec<u8> {
    use bundle_wire as w;
    let injected = uint(0);
    let mut b = w::default_bundle();
    match map_id {
        BundleMapId::Bundle => set(&mut b, key, injected),
        BundleMapId::StorageRecord => {
            let mut m = w::storage_record();
            set(&mut m, key, injected);
            set(&mut b, bkey::bundle::STORAGE_RECORD, map(&m));
        }
        BundleMapId::OtsAnchor => {
            let mut m = w::ots_anchor(2, true);
            set(&mut m, key, injected);
            set(&mut b, bkey::bundle::OTS_ANCHORS, w::section(&[m]));
        }
        BundleMapId::TsaAnchor => {
            let mut m = w::tsa_anchor(0, 2, Some("https://freetsa.org/tsr"));
            set(&mut m, key, injected);
            set(&mut b, bkey::bundle::TSA_ANCHORS, w::section(&[m]));
        }
        BundleMapId::ReceiptRecord => {
            let mut m = w::receipt();
            set(&mut m, key, injected);
            set(&mut b, bkey::bundle::RECEIPT, map(&m));
        }
        BundleMapId::CoveredReveal => {
            let mut m = w::covered_reveal(0);
            set(&mut m, key, injected);
            set(&mut b, bkey::bundle::COVERED_REVEALS, w::section(&[m]));
        }
        BundleMapId::NonCoveredReveal => {
            let mut m = w::noncovered_reveal(2);
            set(&mut m, key, injected);
            set(&mut b, bkey::bundle::NONCOVERED_REVEALS, w::section(&[m]));
        }
        BundleMapId::TouchedFile => {
            let mut m = w::touched_file(0, "notes/pitch.md");
            set(&mut m, key, injected);
            set(
                &mut b,
                bkey::bundle::TOUCHED_FILES,
                w::section(&[m, w::touched_file(1, "logo.png")]),
            );
        }
        BundleMapId::FullReveal => {
            let mut m = w::full_reveal(0, true);
            set(&mut m, key, injected);
            set(&mut b, bkey::bundle::FULL_REVEALS, w::section(&[m]));
        }
    }
    w::encode(&b)
}

/// **The F10 accept**: every reserved key of every manifest map, injected into
/// valid v1 input, is the reserved-slot error naming that key.
#[test]
fn every_reserved_manifest_key_is_the_reserved_slot_error() {
    let mut checked = 0;
    for map_id in MapId::ALL {
        let Some((first, last)) = map_id.reserved_band() else {
            continue; // the envelope — asserted separately below
        };
        for key in first..=last {
            let bytes = body_with_injected(map_id, key);
            match ManifestBodyV1::decode(&bytes) {
                Err(ManifestError::ReservedKey { map: got, key: k }) => {
                    assert_eq!(got, map_id, "{map_id} key {key}: wrong map in payload");
                    assert_eq!(k, key, "{map_id} key {key}: wrong key in payload");
                }
                other => panic!("{map_id} key {key}: expected ReservedKey, got {other:?}"),
            }
            let err = ManifestBodyV1::decode(&bytes).expect_err("must reject");
            assert_eq!(err.code(), "manifest-reserved-key", "{map_id} key {key}");
            // "naming the key" is a rendering requirement, not just a payload
            // one: the message a user sees has to say which slot it was.
            assert!(
                err.to_string().contains(&key.to_string()),
                "{map_id} key {key}: message must name the key, got `{err}`"
            );
            checked += 1;
        }
    }
    assert!(checked >= 4 * 16, "sweep looks too small: {checked} cases");
}

/// The same sweep over every bundle map.
#[test]
fn every_reserved_bundle_key_is_the_reserved_slot_error() {
    let mut checked = 0;
    for map_id in BundleMapId::ALL {
        let (first, last) = map_id.reserved_band();
        for key in first..=last {
            let bytes = bundle_with_injected(map_id, key);
            match BundleV1::decode(&bytes) {
                Err(BundleError::ReservedKey { map: got, key: k }) => {
                    assert_eq!(got, map_id, "{map_id} key {key}: wrong map in payload");
                    assert_eq!(k, key, "{map_id} key {key}: wrong key in payload");
                }
                other => panic!("{map_id} key {key}: expected ReservedKey, got {other:?}"),
            }
            let err = BundleV1::decode(&bytes).expect_err("must reject");
            assert_eq!(err.code(), "bundle-reserved-key", "{map_id} key {key}");
            assert!(
                err.to_string().contains(&key.to_string()),
                "{map_id} key {key}: message must name the key, got `{err}`"
            );
            checked += 1;
        }
    }
    assert!(checked >= 9 * 10, "sweep looks too small: {checked} cases");
}

/// The **named** reserved slots of registry §9 — bundle key 10
/// (v1.1 `range_reveals`) and receipt key 3 (v1.1 `chain_inputs`) — take the
/// *ordinary* reserved-slot error. A named slot is documentation, not a
/// separate code (registry §7.15); minting one would spend a permanent code
/// on a distinction no verifier acts on.
#[test]
fn named_reserved_slots_use_the_ordinary_reserved_error() {
    for (map_id, key) in [
        (BundleMapId::Bundle, bkey::bundle::RESERVED_RANGE_REVEALS),
        (
            BundleMapId::ReceiptRecord,
            bkey::receipt::RESERVED_CHAIN_INPUTS,
        ),
    ] {
        let bytes = bundle_with_injected(map_id, key);
        assert!(matches!(
            BundleV1::decode(&bytes),
            Err(BundleError::ReservedKey { .. })
        ));
        assert_eq!(
            BundleV1::decode(&bytes).expect_err("must reject").code(),
            "bundle-reserved-key",
            "{map_id} key {key} is a NAMED slot but must not have its own code"
        );
    }
}

/// The band boundary, both sides. `RESERVED_FIRST - 1` is the map's last
/// assigned key (so the band abuts the schema with no hole), and `24` is
/// outside every band forever — a **different** code, because "reserved for
/// v1.x" and "never assignable" are different facts about the sender.
#[test]
fn the_reserved_band_abuts_the_schema_and_ends_at_23() {
    for map_id in MapId::ALL {
        let Some((first, last)) = map_id.reserved_band() else {
            continue;
        };
        assert_eq!(last, V1_KEY_BAND_MAX, "{map_id}");
        assert!(first > 0, "{map_id}: key 0 is always assigned");
        // One below the band is assigned, so injecting it is NOT a reserved
        // error (it collides with a real field instead).
        assert_ne!(
            ManifestBodyV1::decode(&body_with_injected(map_id, first - 1))
                .err()
                .map(|e| e.code()),
            Some("manifest-reserved-key"),
            "{map_id}: key {} must be assigned, not reserved",
            first - 1
        );
        // One above the band was never assignable.
        assert_eq!(
            ManifestBodyV1::decode(&body_with_injected(map_id, FIRST_UNKNOWN_KEY))
                .expect_err("must reject")
                .code(),
            "manifest-unknown-key",
            "{map_id}: key {FIRST_UNKNOWN_KEY} must be unknown, not reserved"
        );
    }

    for map_id in BundleMapId::ALL {
        let (first, last) = map_id.reserved_band();
        assert_eq!(last, V1_KEY_BAND_MAX, "{map_id}");
        assert!(first > 0, "{map_id}: key 0 is always assigned");
        assert_eq!(
            BundleV1::decode(&bundle_with_injected(map_id, FIRST_UNKNOWN_KEY))
                .expect_err("must reject")
                .code(),
            "bundle-unknown-key",
            "{map_id}: key {FIRST_UNKNOWN_KEY} must be unknown, not reserved"
        );
    }
}

/// The manifest **envelope** is the one map with no reserved band at all: its
/// `{0: body, 1: signatures}` shape is frozen across every format version
/// (you must parse it to find the version), so it has no room for a future
/// field and *any* other key is an unknown key, never a reserved slot.
#[test]
fn the_envelope_has_no_reserved_slots_because_its_shape_is_frozen_forever() {
    assert_eq!(MapId::Envelope.reserved_band(), None);

    let body = map(&manifest_wire::default_body());
    for key in [2u64, 3, 8, V1_KEY_BAND_MAX, FIRST_UNKNOWN_KEY] {
        let mut env = vec![
            (mkey::envelope::BODY, bstr(&body)),
            (
                mkey::envelope::SIGNATURES,
                map(&manifest_wire::hybrid_signatures()),
            ),
        ];
        set(&mut env, key, uint(0));
        let err = Manifest::decode(&map(&env)).expect_err("must reject");
        assert_eq!(
            err.code(),
            "manifest-unknown-key",
            "envelope key {key} must be unknown, never reserved"
        );
    }
}
