//! The boundary's behaviour, on the host, where `wasm-bindgen` is not
//! compiled at all.
//!
//! Everything the four exports do lives in `crate::api`; the wasm32 shims add
//! a `JsError` conversion and nothing else. So these run natively — in the
//! `cargo test --workspace` gate, on every platform, with no node and no
//! toolchain — and the node harness
//! (`scripts/wasm-boundary.mjs`, driven by `scripts/wasm-pack-build.sh`)
//! proves the same behaviour survives the boundary itself.

use antseal_core::test_util::bundle_fixtures::{build, shapes};
use antseal_core::verify::{VerifyOptions, verify_bundle};
use antseal_wasm::api::{build_info_json, verdict_class_json, verify_json, verify_online_json};

/// A bundle every case here can use: one file, fully revealed.
fn honest_bundle() -> Vec<u8> {
    let case = shapes::by_name("single-text-with-mirror/full")
        .expect("the R9 catalogue must carry this shape");
    build(&case.spec, &case.selection).bytes
}

/// An online-evidence document with a real must-agree pair over one height.
fn evidence(first: &str, second: &str) -> String {
    format!(
        r#"{{"schema":"antseal.online-evidence.v1",
             "endpoints":{{"identities":["https://one.example","https://two.example"],
                           "overridden":false}},
             "blocks":[{{"height":800000,"responses":[{first},{second}]}}]}}"#
    )
}

/// The 80-byte header both endpoints return in the agreeing case.
const HEADER: &str = concat!(
    "00000020",
    "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
    "2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40",
    "62ffff7f",
    "0000000a",
    "deadbeef"
);

#[test]
fn verify_returns_exactly_the_bytes_native_verification_produces() {
    let bundle = honest_bundle();
    let native = verify_bundle(&bundle, &VerifyOptions::new())
        .expect("the fixture bundle verifies")
        .to_canonical_json()
        .expect("the report encodes");
    let through_the_binding = verify_json(&bundle).expect("the binding verifies the same bundle");
    assert_eq!(
        through_the_binding.as_bytes(),
        native.as_slice(),
        "the binding must hand over `to_canonical_json()`'s bytes verbatim — one serialization \
         path everywhere (D29/D65), which is what lets the bit-match contract cover the page"
    );
}

#[test]
fn verify_runs_the_storage_linkage_layer() {
    // D128: the export takes no options, so the page has nothing to opt in
    // with, and spec line 38 names this layer as the page's entire storage
    // story. The NEGATIVE half is the red-capable one: a renderer that emits
    // the key and nothing under it would satisfy a `contains("storage_linkage")`
    // check.
    let report = verify_json(&honest_bundle()).expect("the fixture bundle verifies");
    assert!(
        report.contains("\"storage_linkage\""),
        "the report must carry the storage-linkage member"
    );
    assert!(
        !report.contains("not-evaluated") && !report.contains("not_evaluated"),
        "the layer must have RUN, not been suppressed: R22 never calls \
         `without_storage_linkage` (D128 §3 R5). Report: {report}"
    );
}

#[test]
fn malformed_input_is_a_typed_error_carrying_the_frozen_code() {
    for (label, bytes) in [
        ("empty", Vec::new()),
        ("random", vec![0xde, 0xad, 0xbe, 0xef]),
        ("truncated", honest_bundle()[..24].to_vec()),
    ] {
        let error = verify_json(&bytes).expect_err("malformed input must be refused");
        let code = error
            .code()
            .unwrap_or_else(|| panic!("{label}: a bundle rejection must carry core's stable code"));
        assert!(
            error.message().starts_with(&format!("{code}: ")),
            "{label}: the message JS receives must lead with the stable code, got {:?}",
            error.message()
        );
        assert!(
            code.contains('-'),
            "{label}: `{code}` is not shaped like an error-code-contract code"
        );
    }
}

#[test]
fn the_binding_mints_no_error_code_of_its_own() {
    // The frozen universe is append-only and belongs to antseal-core
    // (docs/testing/error-code-contract.md §3). A binding-level failure must
    // therefore have NO code — not a new one.
    let error = verify_online_json(&honest_bundle(), "{\"schema\":\"nope\"}")
        .expect_err("a wrong schema token must be refused");
    assert!(
        error.code().is_none(),
        "the binding must not mint a code; got {:?}",
        error.code()
    );
    assert!(
        error.message().contains("online-evidence document"),
        "the refusal must say what it refused, got {:?}",
        error.message()
    );
}

#[test]
fn a_malformed_online_document_is_refused_in_every_shape() {
    let bundle = honest_bundle();
    for (label, document) in [
        ("not JSON", "{".to_owned()),
        ("wrong schema", r#"{"schema":"other","endpoints":{"identities":[],"overridden":false}}"#.to_owned()),
        (
            "unknown key",
            r#"{"schema":"antseal.online-evidence.v1","endpoints":{"identities":[],"overridden":false},"extra":1}"#
                .to_owned(),
        ),
        (
            "a pair of one",
            r#"{"schema":"antseal.online-evidence.v1","endpoints":{"identities":[],"overridden":false},
                "blocks":[{"height":1,"responses":[{"outcome":"no-such-block"}]}]}"#
                .to_owned(),
        ),
        (
            "a header that is not hex",
            evidence(
                r#"{"outcome":"header","header_hex":"zz"}"#,
                r#"{"outcome":"no-such-block"}"#,
            ),
        ),
        (
            "an unknown failure class",
            evidence(
                r#"{"outcome":"failed","endpoint":"https://one.example","class":"whatever"}"#,
                r#"{"outcome":"no-such-block"}"#,
            ),
        ),
        (
            "a duplicate height",
            r#"{"schema":"antseal.online-evidence.v1","endpoints":{"identities":[],"overridden":false},
                "blocks":[{"height":1,"responses":[{"outcome":"no-such-block"},{"outcome":"no-such-block"}]},
                          {"height":1,"responses":[{"outcome":"no-such-block"},{"outcome":"no-such-block"}]}]}"#
                .to_owned(),
        ),
    ] {
        let error = verify_online_json(&bundle, &document)
            .expect_err(&format!("{label}: a malformed document must be refused"));
        assert!(
            error.code().is_none(),
            "{label}: an input-document refusal is not a member of the frozen code universe"
        );
    }
}

#[test]
fn the_must_agree_fold_matches_the_cli_rule() {
    let bundle = honest_bundle();
    let header = format!(r#"{{"outcome":"header","header_hex":"{HEADER}"}}"#);
    let other = format!(
        r#"{{"outcome":"header","header_hex":"{}"}}"#,
        HEADER.replacen("00000020", "00000040", 1)
    );
    let failed = r#"{"outcome":"failed","endpoint":"https://one.example","class":"transport"}"#;
    let absent = r#"{"outcome":"no-such-block"}"#;

    // All four outcomes must produce an overlay rather than an error: a probe
    // that could fail the run would make a third party's verification depend
    // on a public endpoint's mood.
    for (label, first, second) in [
        ("agreement", header.as_str(), header.as_str()),
        ("disagreement", header.as_str(), other.as_str()),
        ("failure first", failed, header.as_str()),
        ("agreed absence", absent, absent),
    ] {
        let overlay = verify_online_json(&bundle, &evidence(first, second))
            .unwrap_or_else(|e| panic!("{label}: the overlay must be produced, got {e}"));
        assert!(
            overlay.contains("framing_line"),
            "{label}: the overlay must carry its framing sentence"
        );
    }
}

#[test]
fn the_online_run_moves_no_report_byte() {
    // D64 §3: the overlay is a sibling document carried beside the report,
    // never a report field. An `--online` run and an offline run over the same
    // bundle expose byte-identical report bytes.
    let bundle = honest_bundle();
    let offline = verify_json(&bundle).expect("offline verifies");
    let _overlay = verify_online_json(
        &bundle,
        &evidence(
            r#"{"outcome":"no-such-block"}"#,
            r#"{"outcome":"no-such-block"}"#,
        ),
    )
    .expect("the online run produces an overlay");
    let offline_again = verify_json(&bundle).expect("offline verifies again");
    assert_eq!(offline, offline_again, "the report bytes must not move");
}

#[test]
fn the_verdict_datum_is_available_and_is_not_a_report_field() {
    let bundle = honest_bundle();
    let report = verify_json(&bundle).expect("verifies");
    let datum = verdict_class_json(&bundle, None).expect("the datum encodes");
    assert!(
        datum.contains("\"rung\""),
        "the datum must carry the rung, got {datum}"
    );
    assert!(
        !report.contains("\"rung\""),
        "the rung is NOT a report field — that is precisely why D18 §5 R4's \
         fourth export exists"
    );
}

#[test]
fn build_info_carries_the_identity_the_footer_renders() {
    let info = build_info_json().expect("the build info encodes");
    for needle in [
        "core_version",
        "supported_format_versions",
        "report_version",
        "source_commit",
    ] {
        assert!(
            info.contains(needle),
            "build info must carry {needle}: {info}"
        );
    }
    assert!(
        info.contains(antseal_core::VERSION),
        "the core version must be the library's own: {info}"
    );
    // D63 §4/§11.3: no self-hash entry point, and no digest field either.
    for forbidden in ["sha256", "digest", "hash"] {
        assert!(
            !info.contains(forbidden),
            "the module cannot carry its own digest (D63 §4's refused fixed point): {info}"
        );
    }
}
