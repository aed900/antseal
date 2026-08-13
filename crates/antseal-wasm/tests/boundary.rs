//! The boundary's behaviour, on the host, where `wasm-bindgen` is not
//! compiled at all.
//!
//! Everything the five exports do lives in `crate::api`; the wasm32 shims add
//! a `JsError` conversion and nothing else. So these run natively — in the
//! `cargo test --workspace` gate, on every platform, with no node and no
//! toolchain — and the node harness
//! (`scripts/wasm-boundary.mjs`, driven by `scripts/wasm-pack-build.sh`)
//! proves the same behaviour survives the boundary itself.

use antseal_core::test_util::bundle_fixtures::{build, shapes};
use antseal_core::verify::{VerifyOptions, verify_bundle};
use antseal_wasm::api::{
    build_info_json, verdict_class_json, verify_json, verify_online_json, verify_rendered_json,
};

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

// ─────────────────────────────────────────────────────────────────────
// the fifth export (D130 §3 R1/R3)
// ─────────────────────────────────────────────────────────────────────

/// The document's five members, in the order they must be spliced.
const MEMBERS: [&str; 5] = ["plan", "redaction", "rendered", "report", "verdict"];

#[test]
fn the_rendered_document_carries_five_members_in_alphabetical_order() {
    let document = verify_rendered_json(&honest_bundle()).expect("the bundle verifies");
    let mut at = 0usize;
    for member in MEMBERS {
        let key = format!("\"{member}\":");
        let found = document[at..]
            .find(&key)
            .unwrap_or_else(|| panic!("`{member}` is missing or out of order:\n{document}"));
        at += found + key.len();
    }
    assert!(
        document.starts_with("{\"plan\":") && document.ends_with('}'),
        "the document is one spliced object and D132's member sorts first:\n{document}"
    );
    // D65 §4: zero interior versions. The one version a consumer reads is
    // `build_info()`'s.
    assert!(
        !document.contains("\"schema\":") && !document.contains("\"version\":"),
        "the rendered document must carry no schema key and no interior version"
    );
}

#[test]
fn the_documents_report_member_is_verify_json_verbatim() {
    // Without this the gate's subject and the page's path diverge silently:
    // after D130 the page calls `verify_rendered` and never `verify`.
    let bundle = honest_bundle();
    let report = verify_json(&bundle).expect("the bundle verifies");
    let document = verify_rendered_json(&bundle).expect("the bundle verifies");
    assert!(
        document.contains(&format!("\"report\":{report},\"verdict\":")),
        "the `report` member must be the report's bytes VERBATIM (tier A), spliced \
         between `rendered` and `verdict` — not re-serialized"
    );
}

#[test]
fn the_document_carries_the_frozen_sentences_the_report_does_not() {
    // The measurement D130 §1 (a.2)/(b) turned on, restated as a test: the
    // wording reaches the page through THIS export and through nothing else.
    let bundle = build(
        &shapes::multi_file(),
        &antseal_core::test_util::bundle_fixtures::Selection::all(3),
    )
    .bytes;
    let report = verify_json(&bundle).expect("the bundle verifies");
    let document = verify_rendered_json(&bundle).expect("the bundle verifies");
    for sentence in [
        antseal_core::verify::wording::UNANCHORED_BANNER,
        antseal_core::verify::wording::EVIDENCE_LAYER_LABEL,
        antseal_core::verify::wording::SEAL_MEANING_NOTE,
        antseal_core::verify::wording::REDACTION_VIEW_LABEL,
        antseal_core::verify::wording::DECLARED_SIZE_NOTE,
    ] {
        assert!(
            !report.contains(sentence),
            "the report carries no rendered prose, yet it carries `{sentence}` — \
             D130 §1 (a.2) measured zero across all 21 committed cases"
        );
        assert!(
            document.contains(sentence),
            "the rendered document must carry `{sentence}`"
        );
    }
}

#[test]
fn the_document_states_position_and_total_size_for_every_block() {
    // MVP-SPEC.md line 121, now enforced for BOTH surfaces by one fold: the
    // page cannot drop a position because it does not compose the row.
    let bundle = build(&shapes::multi_file(), &shapes::multi_file_mixed_selection()).bytes;
    let document = verify_rendered_json(&bundle).expect("the bundle verifies");
    assert!(
        document.contains(" byte(s) at offset "),
        "every block row states size, offset and the declared total:\n{document}"
    );
    assert!(
        document.contains("sealed, and not revealed by this bundle"),
        "the blacked-out arm renders too:\n{document}"
    );
}

// ─────────────────────────────────────────────────────────────────────
// the plan member (D132 §3 R2/R3)
// ─────────────────────────────────────────────────────────────────────

#[test]
fn the_plan_member_always_carries_both_keys() {
    // D132 §3 R3, riding D65 §7's null rule: `blocks` is `[]` when there is
    // nothing to fetch and `receipt` is `null` when there is no receipt.
    // Never an absent key — the page reads `plan.receipt` unconditionally.
    let document = verify_rendered_json(&honest_bundle()).expect("the bundle verifies");
    assert!(
        document.starts_with(r#"{"plan":{"blocks":[],"receipt":null},"redaction":"#),
        "an unanchored bundle plans nothing, and says so in both keys:\n{document}"
    );
}

#[test]
fn the_plan_names_every_upgraded_anchor_and_the_first_transaction_hash() {
    // The F13 shape: one OTS anchor carrying D79's upgrade group at block
    // 900 000, one without it, and a receipt whose first transaction hash is
    // 32 x 0xE1. The anchor's `.ots` bytes are an opaque placeholder, so it
    // verifies **offline-invalid** — and the height is planned anyway, which
    // is the wide set D132 §3 R4 rules and §1 (c) measured inert.
    let bundle = build(
        &shapes::multi_file_every_anchor_kind(),
        &antseal_core::test_util::bundle_fixtures::Selection::all(3),
    )
    .bytes;
    let document = verify_rendered_json(&bundle).expect("the bundle verifies");
    assert!(
        document.starts_with(&format!(
            r#"{{"plan":{{"blocks":[900000],"receipt":{{"tx_hash":"{}"}}}},"redaction":"#,
            "e1".repeat(32)
        )),
        "the plan carries the upgraded height and the first hash as 64 lowercase hex:\n{document}"
    );
}

#[test]
fn the_receipt_excluded_twin_plans_a_null_receipt_and_the_same_block() {
    // Receipt presence is the sealer's opt-in and carries no verdict
    // (registry §7.10). The twin differs from its sibling in the receipt
    // member and nowhere else — including in `blocks`.
    let bundle = build(
        &shapes::multi_file_every_anchor_kind_no_receipt(),
        &antseal_core::test_util::bundle_fixtures::Selection::all(3),
    )
    .bytes;
    let document = verify_rendered_json(&bundle).expect("the bundle verifies");
    assert!(
        document.starts_with(r#"{"plan":{"blocks":[900000],"receipt":null},"redaction":"#),
        "the receipt-excluded twin plans a null receipt:\n{document}"
    );
}

#[test]
fn a_refused_bundle_yields_no_plan_and_no_new_failure_class() {
    // D132 §3 R6, the property that decided the ruling: the plan is a product
    // of a PASSING verdict, because the one entry point that produces it runs
    // the offline verification first and returns its rejection. So a refused
    // bundle hands the page **no document at all** — and the refusal is still
    // core's own frozen code, not something the plan path minted (D132 §3 R8:
    // the plan mints no string and no code).
    //
    // A bundle that decodes at the bundle layer and fails deeper is the case
    // that would expose an ordering mistake: the plan's own decode succeeds
    // for it, so only running the verification first can refuse it.
    let mut tampered = honest_bundle();
    let last = tampered.len() - 1;
    tampered[last] ^= 0xff;

    for (label, bytes) in [
        ("empty", Vec::new()),
        ("random", vec![0xde, 0xad, 0xbe, 0xef]),
        ("truncated", honest_bundle()[..32].to_vec()),
        ("a flipped byte", tampered),
    ] {
        let error = verify_rendered_json(&bytes).expect_err("malformed input must be refused");
        let code = error
            .code()
            .unwrap_or_else(|| panic!("{label}: the refusal must carry core's stable code"));
        assert!(
            error.message().starts_with(&format!("{code}: ")),
            "{label}: {}",
            error.message()
        );
    }
}

#[test]
fn the_verdict_member_carries_no_exit_code() {
    // D69 §3 R1 keeps exactly one code table in the product and it is U2's,
    // CLI-side. A second one here is the disagreement D69 §3 R7 prevents.
    let document = verify_rendered_json(&honest_bundle()).expect("the bundle verifies");
    assert!(
        !document.contains("exit_code"),
        "the document must carry the rung's NAME and no integer:\n{document}"
    );
    assert!(document.contains("\"rung\""), "the rung is the datum");
}

#[test]
fn the_rendered_document_is_refused_for_every_shape_verify_refuses() {
    // One export, one refusal surface: a bundle `verify` rejects cannot be
    // rendered, and the failure carries core's own frozen code.
    for (label, bytes) in [
        ("empty", Vec::new()),
        ("random", vec![0xde, 0xad, 0xbe, 0xef]),
        ("truncated", honest_bundle()[..24].to_vec()),
    ] {
        let error = verify_rendered_json(&bytes).expect_err("malformed input must be refused");
        let code = error
            .code()
            .unwrap_or_else(|| panic!("{label}: a bundle rejection must carry core's stable code"));
        assert!(error.message().starts_with(&format!("{code}: ")), "{label}");
    }
}

#[test]
fn the_page_neutralises_the_values_it_embeds() {
    // D130 §3 R5/R9: every sealer- or artifact-authored value the document
    // embeds arrives through the page's own DOM policy. The bundle's own
    // paths are the reachable one here; the policy itself is proved over the
    // hostile classes in `src/escape.rs`'s own suite.
    use antseal_wasm::escape_for_dom;
    assert_eq!(escape_for_dom("notes/intro.md"), "notes/intro.md");
    let document = verify_rendered_json(&honest_bundle()).expect("the bundle verifies");
    let hostile = "a\u{202e}b\nc";
    assert!(
        !document.contains(hostile),
        "no raw hostile sequence can reach the document"
    );
    assert_eq!(escape_for_dom(hostile), "a\\u{202e}b\\nc");
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
