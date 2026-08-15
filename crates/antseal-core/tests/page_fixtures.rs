//! R84 / D133 — the browser venue's fixtures: the `.sealproof` files that
//! verify **offline** to `attested`, assembled from committed frozen vectors.
//!
//! # Why this file exists
//!
//! `scripts/verifier-page-browser.mjs` hands bundles to the page as **file
//! paths** (`DOM.setFileInputFiles`), so a browser case needs a *file*. Every
//! bundle on disk before D133 verified to an empty or all-`invalid` anchor
//! set, which left R27's four online cases — agreement/promotion,
//! disagreement, mismatch→invalid, one-endpoint-down — unwritable in the
//! browser: the overlay gate skips any slot whose **offline** state is not
//! `attested`, so no synthetic-status bundle can substitute.
//!
//! The library halves of those four cases were never missing. They are green
//! in `crates/antseal-core/src/verify/orchestration/tests.rs` (natively and on
//! `wasm32-unknown-unknown`) and again in
//! `crates/antseal-cli/tests/verify_command.rs`. D133 §1 (a) corrected R84's
//! problem statement on that point; what was missing was the file.
//!
//! # The fixture is MATERIALISED, not committed
//!
//! Nothing here is written to `testdata/`. `scripts/verifier-page-browser.sh`
//! already argues why, for the ten F13 bundles it decodes into `target/`: *"a
//! second binary copy of the same bundle committed under another name would be
//! a second source of truth that agrees on the day it is written."* The same
//! reasoning applies with more force here, because these bytes are a
//! re-encoding of material that is already frozen twice over.
//!
//! Without `ANTSEAL_EMIT_PAGE_FIXTURES` this suite **only asserts** — it is
//! the row that goes red if the format moves under the fixture, and it runs in
//! every `cargo test`. With `ANTSEAL_EMIT_PAGE_FIXTURES=<dir>` each fixture is
//! additionally written to that directory, **after** its assertions have
//! passed, so the bytes the browser is handed are the bytes this file just
//! checked. One emitter, one source of truth.
//!
//! # The material is real, already committed, and binds by construction
//!
//! A25's consented calendar campaign stamped
//! `083f87df00fd5c703d35b883d83535644c686f9e53f1584d7df126abdabd69df`, which
//! **is** the `anchor_digest` of the F13 case `empty-anchor-unanchored`. So
//! the real merged-and-upgraded `.ots` committed inside the frozen anchor
//! vector as `ots-upgraded-offline` (3 808 B, expected state `attested`, real
//! mainnet block 960767) binds to that bundle's manifest by construction:
//! `anchor_digest` covers **only the manifest envelope**, so replacing a
//! bundle's anchor section wholesale cannot move it. That is asserted below
//! rather than assumed.
//!
//! # No freeze event of any class
//!
//! `testdata/vectors/` is **read, never written** — no `--update`, no
//! `--verdict-event`, no `FROZEN.sha256` line moves. `scripts/vector-freeze.sh`
//! must stay green without `--update`, and that is the check that proves the
//! classification (D133 §3 R12).
//!
//! Test names carry the reserved `vector_` marker so the three `cross-os-*`
//! lanes run them everywhere (CONTRIBUTING.md).

#![cfg(not(target_arch = "wasm32"))] // reads the committed documents from disk

use std::fs;
use std::path::PathBuf;

use antseal_core::anchor::model::AnchorArtifacts;
use antseal_core::bundle::{
    AnchorStatus, BundleV1, OpaqueBytes, OtsAnchor, OtsUpgrade, SealProof, encode_bundle,
};
use antseal_core::manifest::anchor_digest;
use antseal_core::verify::{
    AnchorState, ProbeEndpoints, ProbeLog, ProbePlan, VerifyOptions, build_online_overlay,
    offline_verdicts, verify_bundle,
};
use serde_json::Value;

// ---------------------------------------------------------------------------
// the committed inputs — all three read-only
// ---------------------------------------------------------------------------

/// F13's `.sealproof` golden vectors (frozen, Q14).
const BUNDLE_VECTOR: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../testdata/vectors/v1/bundle/bundle.json"
);

/// The anchor golden vectors (frozen, Q14) — the real upgraded `.ots` lives
/// here, with its D79 upgrade group.
const ANCHOR_VECTOR: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../testdata/vectors/v1/anchor/anchor.json"
);

/// A25's day-3 capture of real mainnet headers for this project's own
/// attestations. Read for two reasons: to prove below that the header
/// embedded in the frozen upgrade group **is** what both esplora endpoints
/// answered for 960767 (so R27's intercepts replay recorded reality rather
/// than inventing bytes), and to supply the second fixture's inert 960768
/// group. Reads only — see that directory's README for the consent record.
const HEADER_CAPTURES: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../testdata/anchors/A25-upgrade-headers"
);

/// The base bundle. Chosen because its `anchor_digest` is the digest A25
/// stamped, and because both its anchor sections are empty — so substituting
/// the anchors is a fill, not an overwrite.
const BASE_CASE: &str = "empty-anchor-unanchored";

/// The F13 case whose four anchor artifacts are schema-opaque placeholders.
/// One of its `.ots` blobs is the second fixture's deliberately-`invalid`
/// anchor.
const PLACEHOLDER_CASE: &str = "every-anchor-kind-no-receipt";

/// The real merged-and-upgraded `.ots`, expected state `attested`.
const UPGRADED_CASE: &str = "ots-upgraded-offline";

/// The negative control: a real `.ots` stamped over the **other** committed
/// digest, so `parse_ots` step 5 refuses it against this bundle's manifest.
const WRONG_SEAL_CASE: &str = "ots-wrong-seal";

/// The block the frozen upgrade group attests.
const ATTESTED_HEIGHT: u64 = 960_767;

/// The height the second fixture's `invalid` anchor claims. Deliberately a
/// *different* real block: R27's mismatch case serves 960768's real header as
/// an agreed-but-wrong answer for 960767, and that only stays a refutation
/// while no **attested** anchor claims 960768. Asserted below, on both
/// fixtures.
const INERT_HEIGHT: u64 = 960_768;

/// D133 §1 (d)'s measured size of the assembled attested bundle.
const ATTESTED_FIXTURE_LEN: usize = 4_846;

/// Measured here, at R84, on the same assembly plus the second anchor.
const WIDE_FIXTURE_LEN: usize = 4_978;

/// The emitted file names (D133 §3 R5, R11). The name states the state and the
/// height, so a route interception and the file it belongs to cannot drift
/// silently apart.
const ATTESTED_FIXTURE: &str = "attested-ots-960767.sealproof";
const WIDE_FIXTURE: &str = "attested-plus-invalid-ots.sealproof";

// ---------------------------------------------------------------------------
// reading the committed documents
//
// Every accessor fails with a message naming the missing case AND the file it
// looked in: these are two frozen documents whose internal structure this
// suite depends on, and a bare `unwrap` on a renamed case would report a
// `None` with no way back to the cause.
// ---------------------------------------------------------------------------

fn document(path: &str) -> Value {
    let raw = fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("{path}: the committed vector document must exist: {e}"));
    serde_json::from_str(&raw).unwrap_or_else(|e| panic!("{path}: not valid JSON: {e}"))
}

fn decode_hex(hex: &str, what: &str) -> Vec<u8> {
    assert!(
        hex.len().is_multiple_of(2),
        "{what}: odd-length hex in the committed document"
    );
    (0..hex.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&hex[i..i + 2], 16)
                .unwrap_or_else(|e| panic!("{what}: not hex at byte {}: {e}", i / 2))
        })
        .collect()
}

fn header_80(hex: &str, what: &str) -> [u8; 80] {
    let bytes = decode_hex(hex, what);
    let len = bytes.len();
    <[u8; 80]>::try_from(bytes.as_slice())
        .unwrap_or_else(|_| panic!("{what}: a Bitcoin block header is 80 bytes, got {len}"))
}

/// One named case of a document's `cases` array, under `section`.
fn case_of<'d>(document: &'d Value, path: &str, section: &str, name: &str) -> &'d Value {
    document[section]["cases"]
        .as_array()
        .unwrap_or_else(|| panic!("{path}: {section}.cases is an array"))
        .iter()
        .find(|case| case["name"] == name)
        .unwrap_or_else(|| panic!("{path}: case `{name}` present in the committed document"))
}

/// The committed `bundle_bytes` of one F13 case.
fn f13_bundle(name: &str) -> Vec<u8> {
    let document = document(BUNDLE_VECTOR);
    let case = case_of(&document, BUNDLE_VECTOR, "expect", name);
    let hex = case["bundle_bytes"]
        .as_str()
        .unwrap_or_else(|| panic!("{BUNDLE_VECTOR}: case `{name}` has no bundle_bytes string"));
    decode_hex(hex, "bundle_bytes")
}

/// The committed `anchor_digest` of one F13 case, as lowercase hex.
fn f13_anchor_digest(name: &str) -> String {
    let document = document(BUNDLE_VECTOR);
    let case = case_of(&document, BUNDLE_VECTOR, "expect", name);
    case["anchor_digest"]
        .as_str()
        .unwrap_or_else(|| panic!("{BUNDLE_VECTOR}: case `{name}` has no anchor_digest string"))
        .to_owned()
}

/// The committed `.ots` artifact bytes of one anchor-vector case.
fn anchor_artifact(name: &str) -> Vec<u8> {
    let document = document(ANCHOR_VECTOR);
    let case = case_of(&document, ANCHOR_VECTOR, "inputs", name);
    let hex = case["artifact_hex"]
        .as_str()
        .unwrap_or_else(|| panic!("{ANCHOR_VECTOR}: case `{name}` has no artifact_hex string"));
    decode_hex(hex, "artifact_hex")
}

/// The committed D79 upgrade group of one anchor-vector case.
fn anchor_upgrade(name: &str) -> OtsUpgrade {
    let document = document(ANCHOR_VECTOR);
    let case = case_of(&document, ANCHOR_VECTOR, "inputs", name);
    let upgrade = &case["upgrade"];
    assert!(
        upgrade.is_object(),
        "{ANCHOR_VECTOR}: case `{name}` carries no upgrade group"
    );
    let height = upgrade["block_height"]
        .as_u64()
        .unwrap_or_else(|| panic!("{ANCHOR_VECTOR}: case `{name}` upgrade.block_height"));
    let fetch_date = upgrade["fetch_date_unix"]
        .as_u64()
        .unwrap_or_else(|| panic!("{ANCHOR_VECTOR}: case `{name}` upgrade.fetch_date_unix"));
    let header = header_80(
        upgrade["block_header_hex"]
            .as_str()
            .unwrap_or_else(|| panic!("{ANCHOR_VECTOR}: case `{name}` upgrade.block_header_hex")),
        "upgrade.block_header_hex",
    );
    OtsUpgrade::new(height, header, fetch_date)
}

/// One captured esplora `block/<hash>/header` response, as raw header bytes.
fn captured_header(endpoint: &str, height: u64) -> [u8; 80] {
    let path = format!("{HEADER_CAPTURES}/esplora-{endpoint}-header-{height}.txt");
    let hex = fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("{path}: the committed A25 header capture must exist: {e}"));
    header_80(hex.trim(), &path)
}

/// The first placeholder `.ots` blob F13 embeds — bytes the anchor stage
/// cannot finish reading, which is why it renders `invalid`
/// (`vector_every_anchor_kind_bundle_is_all_invalid_and_unanchored_at_m2`
/// asserts exactly that over all four of them).
fn f13_placeholder_ots() -> Vec<u8> {
    let bytes = f13_bundle(PLACEHOLDER_CASE);
    let bundle = BundleV1::decode(&bytes)
        .unwrap_or_else(|e| panic!("the committed `{PLACEHOLDER_CASE}` vector decodes: {e}"));
    let anchors = bundle.ots_anchors();
    assert!(
        !anchors.is_empty(),
        "{BUNDLE_VECTOR}: case `{PLACEHOLDER_CASE}` carries no OTS anchor to borrow"
    );
    anchors[0].ots().as_slice().to_vec()
}

// ---------------------------------------------------------------------------
// the assembly (D133 §3 R4) — public API only, manifest untouched
// ---------------------------------------------------------------------------

/// Substitute a bundle's OTS anchor section wholesale and re-encode.
///
/// The manifest is **not touched**, which is what keeps `anchor_digest` where
/// A25 stamped it. Re-encoding through `encode_bundle` re-runs the tier-`[X]`
/// layer-1 rules on the way back in, as every fixture in this tree is required
/// to do — nothing here hand-builds a wire shape.
fn substitute_ots_anchors(base: &[u8], anchors: Vec<OtsAnchor>) -> Vec<u8> {
    let mut parts = BundleV1::decode(base)
        .unwrap_or_else(|e| panic!("the committed `{BASE_CASE}` vector decodes to the model: {e}"))
        .into_parts();
    parts.ots_anchors = anchors;
    // `tsa_anchors` stays empty and `receipt` stays `None`: the receipt-bearing
    // twin is R85's, deferred because its transaction hash would point at
    // whatever R85 has not yet ruled.
    let bundle =
        BundleV1::new(parts).unwrap_or_else(|e| panic!("the rebuilt bundle is well-formed: {e}"));
    encode_bundle(&bundle).unwrap_or_else(|e| panic!("the rebuilt bundle re-encodes: {e}"))
}

/// One OTS anchor over a committed artifact, with a committed upgrade group.
///
/// The sealer-claimed `status` is `attested` on **every** anchor this file
/// builds, including the two that render `invalid`. That is deliberate: it is
/// what makes the state assertions below differential rather than
/// tautological — a stage that believed the bundle's own `status` field would
/// call all of them attested.
fn ots_anchor(artifact: Vec<u8>, upgrade: OtsUpgrade) -> OtsAnchor {
    OtsAnchor::new(
        AnchorStatus::Attested,
        OpaqueBytes::from_vec(artifact),
        Some(upgrade),
    )
    .unwrap_or_else(|e| panic!("a committed artifact is under the D10 caps: {e}"))
}

/// **The fixture.** The F13 base bundle carrying the real merged-and-upgraded
/// `.ots` from the frozen anchor vector, with that vector's real 960767
/// upgrade group.
fn attested_fixture() -> Vec<u8> {
    let anchor = ots_anchor(
        anchor_artifact(UPGRADED_CASE),
        anchor_upgrade(UPGRADED_CASE),
    );
    substitute_ots_anchors(&f13_bundle(BASE_CASE), vec![anchor])
}

/// The wide-versus-narrow witness (D133 §3 R11): the fixture above plus one
/// more anchor, whose artifact is an F13 placeholder and whose upgrade group
/// names a *second* real block.
///
/// The extra anchor is offline-`invalid`, so it is in `ProbePlan`'s **wide**
/// set (a walk over the bundle's shape, which consults no artifact) and out of
/// the overlay's **narrow** set (which admits only offline-`attested` slots).
/// The 80 header bytes are inert to every verdict here — the artifact fails to
/// parse long before them — so they are the real captured 960768 header rather
/// than filler, on the same principle as the rest of this fixture.
fn attested_plus_invalid_fixture() -> Vec<u8> {
    let attested = ots_anchor(
        anchor_artifact(UPGRADED_CASE),
        anchor_upgrade(UPGRADED_CASE),
    );
    let inert = ots_anchor(
        f13_placeholder_ots(),
        OtsUpgrade::new(
            INERT_HEIGHT,
            captured_header("blockstream", INERT_HEIGHT),
            anchor_upgrade(UPGRADED_CASE).fetch_date(),
        ),
    );
    substitute_ots_anchors(&f13_bundle(BASE_CASE), vec![attested, inert])
}

// ---------------------------------------------------------------------------
// shared assertions
// ---------------------------------------------------------------------------

/// The per-anchor offline states a bundle renders, in wire order.
fn anchor_states(bytes: &[u8]) -> Vec<AnchorState> {
    let report = verify_bundle(bytes, &VerifyOptions::new())
        .unwrap_or_else(|e| panic!("the assembled fixture passes the evidence layer: {e:?}"));
    report.anchors.iter().map(|slot| slot.state).collect()
}

/// `ProbePlan`'s block list — the **wide** set an `--online` run would fetch.
fn plan_blocks(bytes: &[u8]) -> Vec<u64> {
    let bundle = BundleV1::decode(bytes).unwrap_or_else(|e| panic!("the fixture decodes: {e}"));
    ProbePlan::from_bundle(&bundle).blocks
}

/// How many rows D64's overlay would carry — the **narrow** set.
///
/// Computed with an attempted-nothing probe log and the offline verdicts on
/// both sides, so no network, no host and no evidence is involved: the only
/// thing being counted is which slots the builder admits.
fn overlay_rows(bytes: &[u8]) -> usize {
    let proof = SealProof::decode(bytes).unwrap_or_else(|e| panic!("the fixture decodes: {e:?}"));
    let verdicts = offline_verdicts(&proof, &VerifyOptions::new());
    let artifacts = AnchorArtifacts::from_bundle(proof.bundle());
    let probes = ProbeLog::new(ProbeEndpoints::new(
        vec![
            "https://blockstream.example/api".to_owned(),
            "https://mempool.example/api".to_owned(),
        ],
        false,
    ));
    build_online_overlay(&artifacts, &verdicts, &verdicts, &probes)
        .anchor_outcomes
        .len()
}

/// D133 §7 residual risk 5, enforced rather than remembered: R27's mismatch
/// case serves block 960768's real header as an agreed-but-wrong answer, and
/// that is only a refutation while nothing in either fixture is **attested**
/// at 960768.
fn assert_no_attested_anchor_at_the_inert_height(bytes: &[u8], fixture: &str) {
    let bundle = BundleV1::decode(bytes).unwrap_or_else(|e| panic!("the fixture decodes: {e}"));
    let states = anchor_states(bytes);
    for (index, anchor) in bundle.ots_anchors().iter().enumerate() {
        if anchor.upgrade().map(OtsUpgrade::block_height) == Some(INERT_HEIGHT) {
            assert_ne!(
                states.get(index).copied(),
                Some(AnchorState::Attested),
                "{fixture}: anchor {index} is attested at {INERT_HEIGHT}, which turns R27's \
                 mismatch header into a correct one"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// the emitter (D133 §3 R6)
// ---------------------------------------------------------------------------

/// Write one fixture, if and only if the emitter was asked for.
///
/// Called last in each test, after every assertion above it has passed, so a
/// bundle that does not verify is never left on disk for the browser to pick
/// up.
///
/// # The path must be absolute, and that is a refusal rather than a preference
///
/// Cargo runs an integration test with its working directory set to the
/// **package** root, not the workspace root — so a caller in
/// `scripts/` that passes `target/verifier-web-fixtures` and a test that
/// resolves it mean two different directories, and the mistake is silent in
/// both halves: the emitter reports a relative path that looks right, and the
/// caller's `ls` glob finds the files it wrote itself and drives on. Measured
/// here at R84 — the browser arm went **green having rendered ten bundles
/// instead of twelve**, which is the shape of a gate that proves nothing.
///
/// Refusing a relative path makes that unreachable for every future caller,
/// not just the one that was fixed.
fn emit(name: &str, bytes: &[u8]) {
    let Some(dir) = std::env::var_os("ANTSEAL_EMIT_PAGE_FIXTURES").map(PathBuf::from) else {
        return;
    };
    assert!(
        dir.is_absolute(),
        "ANTSEAL_EMIT_PAGE_FIXTURES must be an ABSOLUTE path, got `{}`. A \
         cargo integration test's working directory is the package root, so a \
         relative path here resolves somewhere the caller is not looking and \
         the miss is silent on both sides",
        dir.display()
    );
    fs::create_dir_all(&dir)
        .unwrap_or_else(|e| panic!("{}: creating the emit directory: {e}", dir.display()));
    let path = dir.join(name);
    fs::write(&path, bytes)
        .unwrap_or_else(|e| panic!("{}: writing the fixture: {e}", path.display()));
    println!("  emitted {} ({} B)", path.display(), bytes.len());
}

// ---------------------------------------------------------------------------
// the tests
// ---------------------------------------------------------------------------

/// **The fixture, asserted by state.** One anchor, offline state `attested`,
/// and a non-empty probe plan naming the real block it was committed in.
///
/// This is the row that goes red if the format moves under the fixture: it
/// runs in every `cargo test`, while the file it emits has no freeze manifest
/// line and no retention guarantee by construction.
#[test]
fn vector_page_fixture_verifies_attested_offline() {
    let bytes = attested_fixture();

    assert_eq!(
        anchor_states(&bytes),
        vec![AnchorState::Attested],
        "the real merged-and-upgraded `.ots` over this bundle's own \
         anchor_digest must render `attested` OFFLINE — the overlay gate \
         admits no other state, so nothing weaker unblocks R27"
    );

    assert_eq!(
        plan_blocks(&bytes),
        vec![ATTESTED_HEIGHT],
        "the non-empty probe plan is the whole point: every fixture on disk \
         before this one planned zero fetches"
    );

    assert_eq!(
        bytes.len(),
        ATTESTED_FIXTURE_LEN,
        "D133 §1 (d) measured this assembly at {ATTESTED_FIXTURE_LEN} B. A \
         different size means the codec, the base vector or the anchor vector \
         moved under the fixture — investigate before re-pinning the number"
    );

    assert_no_attested_anchor_at_the_inert_height(&bytes, ATTESTED_FIXTURE);
    emit(ATTESTED_FIXTURE, &bytes);
}

/// The binding is a **mechanism**, not a coincidence of these bytes.
///
/// `anchor_digest` is SHA-256 over the manifest envelope alone, so replacing a
/// bundle's anchor section wholesale cannot move it — which is why an `.ots`
/// stamped by A25 over the base case's digest stays bound to every bundle
/// built from that manifest, however its anchors are rewritten. Asserted
/// against the committed value in the F13 document, so the claim is checked
/// against a frozen number rather than against itself.
#[test]
fn vector_page_fixture_leaves_the_anchor_digest_where_a25_stamped_it() {
    let base = f13_bundle(BASE_CASE);
    let rebuilt = attested_fixture();

    let digest_of = |bytes: &[u8]| {
        let proof = SealProof::decode(bytes).unwrap_or_else(|e| panic!("decodes: {e:?}"));
        anchor_digest(proof.anchor_digest_preimage()).to_string()
    };

    let committed = f13_anchor_digest(BASE_CASE);
    assert_eq!(digest_of(&base), committed, "the base vector's own digest");
    assert_eq!(
        digest_of(&rebuilt),
        committed,
        "substituting the anchor section moved the anchor_digest, so the \
         committed `.ots` no longer binds and the fixture is unbuildable"
    );
}

/// **The negative controls.** A fixture builder that cannot produce a
/// non-attested result is not proven to be producing attestation.
///
/// Two of them, both from committed material:
///
/// 1. the **unmodified** base bundle renders no anchor slot at all, so the
///    `attested` above comes from the substitution and not from the base; and
/// 2. the same assembly with the `ots-wrong-seal` artifact swapped in — a real
///    `.ots` stamped over the *other* digest A25 stamped — renders `invalid`.
///
/// Control 2 goes red for the right reason (`parse_ots` step 5 refuses the
/// start digest against this bundle's manifest) rather than by absence, and
/// its slot's claimed `status` is `attested` exactly like the real one's: the
/// state is derived, never read off the bundle.
#[test]
fn vector_page_fixture_negative_controls_are_not_attested() {
    assert!(
        anchor_states(&f13_bundle(BASE_CASE)).is_empty(),
        "the unmodified base case must carry no anchor slot"
    );

    let wrong_seal = substitute_ots_anchors(
        &f13_bundle(BASE_CASE),
        vec![ots_anchor(
            anchor_artifact(WRONG_SEAL_CASE),
            anchor_upgrade(UPGRADED_CASE),
        )],
    );
    assert_eq!(
        anchor_states(&wrong_seal),
        vec![AnchorState::Invalid],
        "an `.ots` stamped over another digest must refuse to bind here"
    );
    assert_eq!(
        plan_blocks(&wrong_seal),
        vec![ATTESTED_HEIGHT],
        "the plan is the WIDE set: it walks the bundle's shape and consults no \
         artifact, so an offline-invalid anchor still puts its height in it \
         (`an_upgraded_ots_anchor_puts_its_height_in_the_plan_whatever_its_verdict` \
         on real material rather than placeholders)"
    );
}

/// **The wide-versus-narrow witness** (D133 §3 R11). The second fixture plans
/// two fetches and produces one overlay row.
///
/// `ProbePlan::from_bundle` is a walk over the bundle's shape; the overlay
/// admits only slots whose **offline** state is `attested`. Those two sets are
/// not the same set, and until now the difference existed only in argument.
#[test]
fn vector_page_fixture_wide_plan_exceeds_the_narrow_overlay_set() {
    let bytes = attested_plus_invalid_fixture();

    assert_eq!(
        anchor_states(&bytes),
        vec![AnchorState::Attested, AnchorState::Invalid],
        "one real attested anchor and one placeholder the stage cannot parse"
    );
    assert_eq!(
        plan_blocks(&bytes),
        vec![ATTESTED_HEIGHT, INERT_HEIGHT],
        "the wide set names both heights"
    );
    assert_eq!(
        overlay_rows(&bytes),
        1,
        "the narrow set admits only the offline-attested slot"
    );
    assert_eq!(
        overlay_rows(&attested_fixture()),
        1,
        "and the single-anchor fixture's narrow set is the same one row, which \
         is what makes the second fixture a witness to the DIFFERENCE rather \
         than to a second anchor"
    );

    assert_eq!(
        bytes.len(),
        WIDE_FIXTURE_LEN,
        "measured at R84; a different size means something moved under the \
         fixture — investigate before re-pinning the number"
    );

    assert_no_attested_anchor_at_the_inert_height(&bytes, WIDE_FIXTURE);
    emit(WIDE_FIXTURE, &bytes);
}

/// The embedded header **is** what mainnet answered, from both endpoints.
///
/// R27's four browser cases replay `testdata/anchors/A25-upgrade-headers/`
/// through route interception; this is the row that keeps those recordings and
/// this fixture from drifting apart. It is also the answer to the reader who
/// mistakes a recorded response for a live one: nothing here reaches the
/// network, and the bytes being compared are both committed.
#[test]
fn vector_page_fixture_header_is_what_both_endpoints_recorded() {
    let embedded = *anchor_upgrade(UPGRADED_CASE).block_header();
    for endpoint in ["blockstream", "mempool"] {
        assert_eq!(
            captured_header(endpoint, ATTESTED_HEIGHT),
            embedded,
            "the {endpoint} capture for {ATTESTED_HEIGHT} is not the header the \
             frozen upgrade group embeds, so R27's promotion case would replay \
             bytes that refute instead of agreeing"
        );
    }
    assert_ne!(
        captured_header("blockstream", INERT_HEIGHT),
        embedded,
        "R27's mismatch case needs {INERT_HEIGHT}'s header to be a DIFFERENT \
         real header from the embedded one"
    );
}
