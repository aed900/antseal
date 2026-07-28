//! F2/F3 acceptance suite for `antseal_core::codec` (MVP-SPEC.md
//! lines 73 and 168; tasks/F.md F2/F3 Accept lists):
//!
//! - one test per rejection class × {outer envelope, inner body},
//!   proving the exact distinct [`DecodeError`] variant (with exact
//!   positions where the fixture pins them);
//! - the truncation sweep (every strict prefix of a valid golden
//!   encoding is a typed error, never a panic);
//! - round-trips: `decode(encode(x)) == x` and
//!   `encode(decode(bytes)) == bytes` for canonical inputs;
//! - encoder→strict-decoder self-consistency;
//! - the secret-bearing-fixture review: no error `Display`/`Debug`
//!   (native or wrapped in `verify::VerifyError`) contains input byte
//!   content — and, as the same fixture set, a proof that **every**
//!   stable `cbor-*` code is reachable from real adversarial bytes.
//!
//! Secret material convention (project rule 6): the "secrets" here are
//! the published dummy patterns of the verify test suite — repeated
//! 0xC7/0xB6 filler and an ASCII marker — never real key or salt
//! material.

use antseal_core::codec::{
    CanonicalDecoder, DecodeError, EncodeError, ExpectedKind, ForbiddenKind, ItemKind,
    MAX_CBOR_DEPTH, check_canonical, encode_item,
};
use antseal_core::verify::VerifyError;

// ─────────────────────────────────────────────────────────────────────
// Envelope fixture: the {0: body-bstr, 1: signatures} shape the F6
// manifest codec will use. The body is an *embedded byte string*: the
// outer strict pass treats it as opaque payload, so inner canonicality
// exists only where the layer is re-run on the inner bytes (spec
// lines 73–74) — exactly what these tests rehearse.
// ─────────────────────────────────────────────────────────────────────

/// Canonical outer envelope embedding `body` verbatim.
fn envelope(body: &[u8]) -> Vec<u8> {
    encode_item(|e| {
        e.map(|m| {
            m.entry(0, |e| e.bytes(body))?;
            m.entry(1, |e| e.array(|a| a.item(|e| e.bytes(&[0xAB; 4]))))?;
            Ok(())
        })
    })
    .expect("envelope fixture encodes")
}

/// Typed-path extraction of the embedded body bytes (the F6 pattern),
/// draining and finishing the outer envelope strictly.
fn extract_body(env: &[u8]) -> Vec<u8> {
    let mut d = CanonicalDecoder::new(env);
    let mut m = d.map().expect("outer envelope is a map");
    let key = m
        .next_key(&mut d)
        .expect("first key reads")
        .expect("first key present");
    assert_eq!(key, 0, "body slot");
    let body = d.bytes().expect("body bstr reads").to_vec();
    let key = m
        .next_key(&mut d)
        .expect("second key reads")
        .expect("second key present");
    assert_eq!(key, 1, "signatures slot");
    let sigs = d.array().expect("signatures array head");
    for _ in 0..sigs {
        d.bytes().expect("signature bytes read");
    }
    assert_eq!(m.next_key(&mut d).expect("map exhausts"), None);
    d.finish().expect("no trailing bytes after envelope");
    body
}

/// The envelope layout is stable and byte-pinned (head positions in the
/// outer-mutant fixtures below depend on it).
#[test]
fn envelope_fixture_bytes_are_pinned() {
    let body = [0xa1, 0x01, 0x18, 0x18]; // {1: 24}, canonical
    assert_eq!(
        envelope(&body),
        vec![
            0xa2, 0x00, 0x44, 0xa1, 0x01, 0x18, 0x18, 0x01, 0x81, 0x44, 0xAB, 0xAB, 0xAB, 0xAB
        ]
    );
    assert_eq!(check_canonical(&envelope(&body)), Ok(()));
    assert_eq!(extract_body(&envelope(&body)), body);
}

// ─────────────────────────────────────────────────────────────────────
// Rejection-class matrix × inner body: a canonical outer envelope
// embedding a non-canonical body passes the outer pass and fails the
// inner pass with the exact class variant.
// ─────────────────────────────────────────────────────────────────────

/// Run one inner-body row: outer pass clean, inner pass = `expected`.
fn assert_inner_body_row(body: &[u8], expected: DecodeError) {
    let env = envelope(body);
    assert_eq!(
        check_canonical(&env),
        Ok(()),
        "outer pass must not see inside the body bstr ({body:02x?})"
    );
    assert_eq!(extract_body(&env), body, "body round-trips verbatim");
    assert_eq!(check_canonical(body), Err(expected), "inner pass rejects");
}

#[test]
fn inner_body_non_shortest_int_is_rejected() {
    assert_inner_body_row(
        &[0xa1, 0x01, 0x18, 0x05],
        DecodeError::NonShortestInt { position: 2 },
    );
}

#[test]
fn inner_body_non_shortest_length_is_rejected() {
    assert_inner_body_row(
        &[0xa1, 0x01, 0x58, 0x01, 0xAA],
        DecodeError::NonShortestLength { position: 2 },
    );
}

#[test]
fn inner_body_indefinite_length_is_rejected() {
    assert_inner_body_row(
        &[0xa1, 0x01, 0x9f, 0xff],
        DecodeError::IndefiniteLength { position: 2 },
    );
}

#[test]
fn inner_body_duplicate_map_key_is_rejected() {
    assert_inner_body_row(
        &[0xa2, 0x01, 0x00, 0x01, 0x00],
        DecodeError::DuplicateMapKey { position: 3 },
    );
}

#[test]
fn inner_body_unsorted_map_keys_are_rejected() {
    assert_inner_body_row(
        &[0xa2, 0x02, 0x00, 0x01, 0x00],
        DecodeError::UnsortedMapKeys { position: 3 },
    );
}

#[test]
fn inner_body_float_is_rejected() {
    assert_inner_body_row(
        &[0xa1, 0x01, 0xf9, 0x3c, 0x00],
        DecodeError::ForbiddenType {
            kind: ForbiddenKind::Float,
            position: 2,
        },
    );
}

#[test]
fn inner_body_simple_value_is_rejected() {
    assert_inner_body_row(
        &[0xa1, 0x01, 0xf6],
        DecodeError::ForbiddenType {
            kind: ForbiddenKind::Simple,
            position: 2,
        },
    );
}

#[test]
fn inner_body_tag_is_rejected() {
    assert_inner_body_row(
        &[0xa1, 0x01, 0xc2, 0x41, 0x01],
        DecodeError::ForbiddenType {
            kind: ForbiddenKind::Tag,
            position: 2,
        },
    );
}

#[test]
fn inner_body_trailing_bytes_are_rejected() {
    assert_inner_body_row(
        &[0x01, 0x02],
        DecodeError::TrailingBytes {
            position: 1,
            trailing: 1,
        },
    );
}

#[test]
fn inner_body_invalid_utf8_is_rejected() {
    assert_inner_body_row(
        &[0xa1, 0x01, 0x61, 0xff],
        DecodeError::InvalidUtf8 { position: 2 },
    );
}

#[test]
fn inner_body_truncation_is_rejected() {
    assert_inner_body_row(&[0xa1, 0x01], DecodeError::Truncated { position: 2 });
}

// ─────────────────────────────────────────────────────────────────────
// Rejection-class matrix × outer envelope: the same classes at the
// envelope layer itself (handcrafted bytes; positions per the pinned
// envelope layout).
// ─────────────────────────────────────────────────────────────────────

#[test]
fn outer_envelope_non_shortest_int_is_rejected() {
    // Envelope key 0 encoded wide.
    assert_eq!(
        check_canonical(&[0xa1, 0x18, 0x00, 0x41, 0xAA]),
        Err(DecodeError::NonShortestInt { position: 1 })
    );
}

#[test]
fn outer_envelope_non_shortest_length_is_rejected() {
    // Body bstr with a wide length head.
    assert_eq!(
        check_canonical(&[0xa1, 0x00, 0x58, 0x01, 0xAA]),
        Err(DecodeError::NonShortestLength { position: 2 })
    );
}

#[test]
fn outer_envelope_indefinite_length_is_rejected() {
    // Signatures slot holding an indefinite array.
    assert_eq!(
        check_canonical(&[0xa1, 0x01, 0x9f, 0x41, 0xAB, 0xff]),
        Err(DecodeError::IndefiniteLength { position: 2 })
    );
}

#[test]
fn outer_envelope_duplicate_map_key_is_rejected() {
    // {0: h'AA', 0: h'BB'} — the sig_policy-duplication shape of spec
    // line 73, one level up.
    assert_eq!(
        check_canonical(&[0xa2, 0x00, 0x41, 0xAA, 0x00, 0x41, 0xBB]),
        Err(DecodeError::DuplicateMapKey { position: 4 })
    );
}

#[test]
fn outer_envelope_unsorted_map_keys_are_rejected() {
    assert_eq!(
        check_canonical(&[0xa2, 0x01, 0x00, 0x00, 0x00]),
        Err(DecodeError::UnsortedMapKeys { position: 3 })
    );
}

#[test]
fn outer_envelope_float_is_rejected() {
    assert_eq!(
        check_canonical(&[0xa1, 0x00, 0xf9, 0x3c, 0x00]),
        Err(DecodeError::ForbiddenType {
            kind: ForbiddenKind::Float,
            position: 2
        })
    );
}

#[test]
fn outer_envelope_simple_value_is_rejected() {
    assert_eq!(
        check_canonical(&[0xa1, 0x00, 0xf6]),
        Err(DecodeError::ForbiddenType {
            kind: ForbiddenKind::Simple,
            position: 2
        })
    );
}

#[test]
fn outer_envelope_tag_is_rejected() {
    // The whole envelope wrapped in a tag.
    assert_eq!(
        check_canonical(&[0xc2, 0x41, 0x01]),
        Err(DecodeError::ForbiddenType {
            kind: ForbiddenKind::Tag,
            position: 0
        })
    );
}

#[test]
fn outer_envelope_trailing_bytes_are_rejected() {
    let mut env = envelope(&[0xa1, 0x01, 0x18, 0x18]);
    let len = env.len() as u64;
    env.push(0x00);
    assert_eq!(
        check_canonical(&env),
        Err(DecodeError::TrailingBytes {
            position: len,
            trailing: 1
        })
    );
}

#[test]
fn outer_envelope_invalid_utf8_is_rejected() {
    assert_eq!(
        check_canonical(&[0xa1, 0x00, 0x61, 0xff]),
        Err(DecodeError::InvalidUtf8 { position: 2 })
    );
}

#[test]
fn outer_envelope_truncation_is_rejected() {
    let env = envelope(&[0xa1, 0x01, 0x18, 0x18]);
    let cut = &env[..env.len() - 1];
    assert!(
        matches!(check_canonical(cut), Err(DecodeError::Truncated { .. })),
        "cut envelope must be a truncation error"
    );
}

// ─────────────────────────────────────────────────────────────────────
// Truncation sweep (F3 Accept): every strict prefix of a valid golden
// encoding returns a typed error — never panics — through both the
// generic walker and the typed envelope parse.
// ─────────────────────────────────────────────────────────────────────

#[test]
fn truncation_sweep_every_strict_prefix_is_a_typed_error() {
    // Rich golden: nested containers, wide ints, bstr, tstr.
    let body = encode_item(|e| {
        e.map(|m| {
            m.entry(0, |e| e.u64(65_536))?;
            m.entry(1, |e| e.bytes(&[0x5A; 30]))?;
            m.entry(24, |e| {
                e.array(|a| {
                    a.item(|e| e.str("antseal"))?;
                    a.item(|e| e.i64(-257))
                })
            })?;
            Ok(())
        })
    })
    .expect("golden body encodes");
    let env = envelope(&body);
    assert_eq!(check_canonical(&env), Ok(()), "golden must be canonical");

    for end in 0..env.len() {
        let prefix = &env[..end];
        // Generic walker: always a typed Truncated (a strict prefix of
        // one canonical item can be nothing else).
        assert!(
            matches!(check_canonical(prefix), Err(DecodeError::Truncated { .. })),
            "prefix of length {end} must be a typed truncation error"
        );
        // Typed pull path: some typed error, never a panic. The closure
        // returns the first error from the same parse the extractor
        // performs.
        let typed: Result<Vec<u8>, DecodeError> = (|| {
            let mut d = CanonicalDecoder::new(prefix);
            let mut m = d.map()?;
            let mut body = Vec::new();
            while let Some(key) = m.next_key(&mut d)? {
                match key {
                    0 => body = d.bytes()?.to_vec(),
                    1 => {
                        let sigs = d.array()?;
                        for _ in 0..sigs {
                            d.bytes()?;
                        }
                    }
                    _ => {
                        // Unknown-key rejection is the schema layer's
                        // (F5/F8); the sweep only needs typed totality.
                        return Err(DecodeError::Truncated { position: 0 });
                    }
                }
            }
            d.finish()?;
            Ok(body)
        })();
        assert!(typed.is_err(), "typed parse of prefix {end} must error");
    }
}

// ─────────────────────────────────────────────────────────────────────
// Round-trips (F3 Accept): decode(encode(x)) == x and
// encode(decode(bytes)) == bytes for canonical inputs, over a
// test-local generic item model built on the public API.
// ─────────────────────────────────────────────────────────────────────

/// Test-local generic CBOR item (uint map keys, i64-range integers —
/// the registry's value domain).
#[derive(Debug, Clone, PartialEq, Eq)]
enum Item {
    U(u64),
    N(i64),
    B(Vec<u8>),
    T(String),
    A(Vec<Item>),
    M(Vec<(u64, Item)>),
}

fn encode_value(
    e: &mut antseal_core::codec::CanonicalEncoder,
    item: &Item,
) -> Result<(), EncodeError> {
    match item {
        Item::U(v) => e.u64(*v),
        Item::N(v) => e.i64(*v),
        Item::B(b) => e.bytes(b),
        Item::T(s) => e.str(s),
        Item::A(items) => e.array(|a| {
            for x in items {
                a.item(|e| encode_value(e, x))?;
            }
            Ok(())
        }),
        Item::M(entries) => e.map(|m| {
            for (k, v) in entries {
                m.entry(*k, |e| encode_value(e, v))?;
            }
            Ok(())
        }),
    }
}

fn encode_full(item: &Item) -> Vec<u8> {
    encode_item(|e| encode_value(e, item)).expect("fixture item encodes")
}

fn decode_value(d: &mut CanonicalDecoder<'_>) -> Result<Item, DecodeError> {
    Ok(match d.peek_kind()? {
        ItemKind::Unsigned => Item::U(d.u64()?),
        ItemKind::Negative => Item::N(d.i64()?),
        ItemKind::Bytes => Item::B(d.bytes()?.to_vec()),
        ItemKind::Text => Item::T(d.str()?.to_owned()),
        ItemKind::Array => {
            let n = d.array()?;
            let mut items = Vec::new();
            for _ in 0..n {
                items.push(decode_value(d)?);
            }
            Item::A(items)
        }
        ItemKind::Map => {
            let mut m = d.map()?;
            let mut entries = Vec::new();
            while let Some(key) = m.next_key(d)? {
                entries.push((key, decode_value(d)?));
            }
            Item::M(entries)
        }
    })
}

fn decode_full(bytes: &[u8]) -> Result<Item, DecodeError> {
    let mut d = CanonicalDecoder::new(bytes);
    let item = decode_value(&mut d)?;
    d.finish()?;
    Ok(item)
}

/// Structured fixtures spanning every kind and every head-width
/// boundary the registry can produce.
fn item_fixtures() -> Vec<Item> {
    vec![
        Item::U(0),
        Item::U(23),
        Item::U(24),
        Item::U(255),
        Item::U(256),
        Item::U(65_535),
        Item::U(65_536),
        Item::U(u64::from(u32::MAX)),
        Item::U(u64::from(u32::MAX) + 1),
        Item::U(u64::MAX),
        Item::N(-1),
        Item::N(-24),
        Item::N(-25),
        Item::N(-256),
        Item::N(-257),
        Item::N(i64::MIN),
        Item::B(Vec::new()),
        Item::B(vec![0x00; 23]),
        Item::B(vec![0x5A; 24]),
        Item::B(vec![0xFF; 256]),
        Item::T(String::new()),
        Item::T("antseal".to_owned()),
        Item::T("mixed-scripts: κρυπτο-графия-暗号".to_owned()),
        Item::A(Vec::new()),
        Item::A(vec![Item::U(1), Item::N(-2), Item::T("x".to_owned())]),
        Item::M(Vec::new()),
        Item::M(vec![
            (0, Item::U(65_536)),
            (1, Item::B(vec![0xAB; 40])),
            (2, Item::A(vec![Item::U(23), Item::U(24)])),
            (3, Item::M(vec![(0, Item::B(vec![0xCD; 16]))])),
            (24, Item::T("boundary key".to_owned())),
        ]),
    ]
}

#[test]
fn decode_of_encode_is_identity_on_items() {
    for item in item_fixtures() {
        let bytes = encode_full(&item);
        assert_eq!(
            decode_full(&bytes),
            Ok(item.clone()),
            "decode(encode(x)) == x for {item:?}"
        );
    }
}

#[test]
fn encode_of_decode_is_identity_on_canonical_bytes() {
    let goldens: &[&[u8]] = &[
        &[0x00],
        &[0x17],
        &[0x18, 0x18],
        &[0x1b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
        &[0x20],
        &[0x3b, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
        &[0x40],
        &[0x41, 0x00],
        &[0x60],
        &[0x63, 0xe2, 0x82, 0xac],
        &[0x80],
        &[0xa0],
        &[0x82, 0x01, 0x82, 0x02, 0x03],
        &[0xa2, 0x01, 0x41, 0xAA, 0x02, 0x19, 0x01, 0x00],
    ];
    for bytes in goldens {
        let item = decode_full(bytes).expect("golden decodes");
        assert_eq!(
            encode_full(&item).as_slice(),
            *bytes,
            "encode(decode(bytes)) == bytes for {bytes:02x?}"
        );
    }
    // And the composite envelope round-trips the same way.
    let env = envelope(&[0xa1, 0x01, 0x18, 0x18]);
    let item = decode_full(&env).expect("envelope decodes generically");
    assert_eq!(encode_full(&item), env);
}

/// F2 Accept (self-consistency): every encoder output passes the strict
/// decoder.
#[test]
fn every_encoder_output_passes_the_strict_decoder() {
    for item in item_fixtures() {
        let bytes = encode_full(&item);
        assert_eq!(
            check_canonical(&bytes),
            Ok(()),
            "self-consistency: {item:?}"
        );
    }
    // Including a wide map crossing the 24-entry and 24-key boundaries.
    let wide = encode_item(|e| {
        e.map(|m| {
            for k in 0..40u64 {
                m.entry(k, |e| e.u64(k))?;
            }
            Ok(())
        })
    })
    .expect("wide map encodes");
    assert_eq!(check_canonical(&wide), Ok(()));
}

// ─────────────────────────────────────────────────────────────────────
// Secret-bearing fixture review (F3 Accept) + code reachability: every
// stable cbor-* code is produced from real bytes, and no error surface
// (Display, Debug, code; native or wrapped in VerifyError) contains
// input byte content.
// ─────────────────────────────────────────────────────────────────────

#[test]
fn error_surfaces_never_contain_input_byte_content() {
    // Published dummy-secret patterns (verify test-suite convention):
    // 0xC7 = unit_salt stand-in, 0xB6 = k_u stand-in, plus an ASCII
    // marker for text payloads. Never real secret material.
    const SALT: [u8; 16] = [0xC7; 16];
    const KEY: [u8; 16] = [0xB6; 16];
    const MARKER: &[u8] = b"TOPSECRETPAYLOAD";

    let bstr_salt = {
        let mut v = vec![0x50]; // bstr(16)
        v.extend_from_slice(&SALT);
        v
    };

    let mut errors: Vec<DecodeError> = Vec::new();

    // cbor-truncated: bstr claiming 32 bytes, carrying only the salt.
    let mut hostile = vec![0x58, 0x20];
    hostile.extend_from_slice(&SALT);
    errors.push(check_canonical(&hostile).expect_err("truncated"));

    // cbor-malformed: stray break.
    errors.push(check_canonical(&[0xff]).expect_err("malformed"));

    // cbor-float / cbor-simple-value: array [forbidden, salt-bstr].
    let mut with_float = vec![0x82, 0xf9, 0x3c, 0x00];
    with_float.extend_from_slice(&bstr_salt);
    errors.push(check_canonical(&with_float).expect_err("float"));
    let mut with_simple = vec![0x82, 0xf6];
    with_simple.extend_from_slice(&bstr_salt);
    errors.push(check_canonical(&with_simple).expect_err("simple"));

    // cbor-tag: tagged salt bytes.
    let mut tagged = vec![0xc2];
    tagged.extend_from_slice(&bstr_salt);
    errors.push(check_canonical(&tagged).expect_err("tag"));

    // cbor-indefinite-length: indefinite bytes assembling the salt.
    let mut indef = vec![0x5f];
    indef.extend_from_slice(&bstr_salt);
    indef.push(0xff);
    errors.push(check_canonical(&indef).expect_err("indefinite"));

    // cbor-non-shortest-int: wide map key, salt value.
    let mut wide_key = vec![0xa1, 0x19, 0x00, 0x05];
    wide_key.extend_from_slice(&bstr_salt);
    errors.push(check_canonical(&wide_key).expect_err("wide int"));

    // cbor-non-shortest-length: wide length head on the salt itself.
    let mut wide_len = vec![0x58, 0x10];
    wide_len.extend_from_slice(&SALT);
    errors.push(check_canonical(&wide_len).expect_err("wide length"));

    // cbor-duplicate-map-key: two identical salt-bstr keys.
    let mut dup = vec![0xa2];
    dup.extend_from_slice(&bstr_salt);
    dup.push(0x00);
    dup.extend_from_slice(&bstr_salt);
    dup.push(0x00);
    errors.push(check_canonical(&dup).expect_err("duplicate"));

    // cbor-unsorted-map-keys: salt key then key-material key
    // (bytewise-smaller: 0xB6 < 0xC7).
    let mut unsorted = vec![0xa2];
    unsorted.extend_from_slice(&bstr_salt);
    unsorted.push(0x00);
    unsorted.push(0x50);
    unsorted.extend_from_slice(&KEY);
    unsorted.push(0x00);
    errors.push(check_canonical(&unsorted).expect_err("unsorted"));

    // cbor-invalid-utf8: the marker text plus an invalid byte.
    let mut bad_text = vec![0x71]; // tstr(17)
    bad_text.extend_from_slice(MARKER);
    bad_text.push(0xff);
    errors.push(check_canonical(&bad_text).expect_err("utf8"));

    // cbor-trailing-bytes: salt item followed by loose salt bytes.
    let mut trailing = bstr_salt.clone();
    trailing.extend_from_slice(&[0xC7, 0xC7]);
    errors.push(check_canonical(&trailing).expect_err("trailing"));

    // cbor-nesting-too-deep: the salt buried beyond the depth guard.
    let mut deep = vec![0x81; usize::from(MAX_CBOR_DEPTH) + 1];
    deep.extend_from_slice(&bstr_salt);
    errors.push(check_canonical(&deep).expect_err("deep"));

    // cbor-unexpected-type: typed read of salt bytes as an integer.
    let mut d = CanonicalDecoder::new(&bstr_salt);
    errors.push(d.u64().expect_err("unexpected type"));

    // cbor-int-out-of-range: canonical u64::MAX read as i64.
    let umax = [0x1b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
    let mut d = CanonicalDecoder::new(&umax);
    errors.push(d.i64().expect_err("out of range"));

    // Reachability: the fixture set exercises every stable code.
    let codes: std::collections::BTreeSet<&'static str> =
        errors.iter().map(DecodeError::code).collect();
    assert_eq!(
        codes.len(),
        15,
        "all 15 distinct cbor-* codes must be reachable from real bytes: {codes:?}"
    );

    // Redaction: no surface may contain the byte content. "199"/"182"
    // are the decimal renderings of 0xC7/0xB6 a leaked Vec<u8> Debug
    // would produce (fixture positions stay far below those values).
    let leak_patterns = ["c7c7", "C7C7", "b6b6", "B6B6", "199", "182", "TOPSECRET"];
    for e in &errors {
        let wrapped = VerifyError::from(e.clone());
        let surface = format!(
            "{e} | {e:?} | {} | {wrapped} | {wrapped:?} | {}",
            e.code(),
            wrapped.code()
        );
        for pattern in leak_patterns {
            assert!(
                !surface.contains(pattern),
                "error surface leaks {pattern:?}: {surface}"
            );
        }
    }
}

// ─────────────────────────────────────────────────────────────────────
// Wrapper-arm smoke: the codec layer's distinct variants survive the
// verify::VerifyError wrapping with their exact codes (Q7 keying).
// ─────────────────────────────────────────────────────────────────────

#[test]
fn wrapped_codec_errors_keep_distinct_codes() {
    let duplicate = check_canonical(&[0xa2, 0x01, 0x00, 0x01, 0x00]).expect_err("duplicate");
    let unsorted = check_canonical(&[0xa2, 0x02, 0x00, 0x01, 0x00]).expect_err("unsorted");
    assert_eq!(
        VerifyError::from(duplicate).code(),
        "cbor-duplicate-map-key"
    );
    assert_eq!(VerifyError::from(unsorted).code(), "cbor-unsorted-map-keys");

    let unexpected = DecodeError::UnexpectedType {
        expected: ExpectedKind::Unsigned,
        found: ItemKind::Bytes,
        position: 0,
    };
    assert_eq!(VerifyError::from(unexpected).code(), "cbor-unexpected-type");
}
