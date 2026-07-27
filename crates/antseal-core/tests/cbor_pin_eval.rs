//! F1/P10 pin-evaluation evidence for `minicbor = "=2.3.0"` (decision D7,
//! `docs/decisions/D7-cbor-crate.md`).
//!
//! SCOPE: these tests are the *pin evaluation* kept live in CI — they prove
//! the pinned crate still exhibits every behavior the D7 decision relied on:
//! shortest-form heads at all integer/length boundaries, definite lengths,
//! caller-controlled (sorted-uint) map-key emission, the header/probe APIs
//! the strict-decode layer (F3) builds its rejection rules on, and
//! trailing-byte detectability. They are **not** the codec: the canonical
//! encode layer is F2 and the strict canonical decoder with its distinct
//! error taxonomy is F3. Rejection itself happens there; here we only prove
//! the pinned crate exposes the signals.
//!
//! A deliberate version bump (docs/dependency-policy.md §4) must keep this
//! file green UNMODIFIED — any needed edit here reopens D7's in-house-codec
//! contingency question.
//!
//! Fixture bytes are trivial constants; no secret material (project rule 6).

use minicbor::data::Type;
use minicbor::decode::Decoder;
use minicbor::encode::Encoder;

/// Encode one unsigned integer and return the produced bytes.
fn enc_u64(v: u64) -> Vec<u8> {
    let mut out = Vec::new();
    Encoder::new(&mut out)
        .u64(v)
        .expect("encoding an integer into a Vec cannot fail");
    out
}

/// RFC 8949 §4.2.1: shortest-form integer heads at every width boundary.
#[test]
fn shortest_form_integer_heads_at_boundaries() {
    let cases: &[(u64, &[u8])] = &[
        (0, &[0x00]),
        (23, &[0x17]),
        (24, &[0x18, 24]),
        (255, &[0x18, 0xff]),
        (256, &[0x19, 0x01, 0x00]),
        (65535, &[0x19, 0xff, 0xff]),
        (65536, &[0x1a, 0x00, 0x01, 0x00, 0x00]),
        (u64::from(u32::MAX), &[0x1a, 0xff, 0xff, 0xff, 0xff]),
        (u64::from(u32::MAX) + 1, &[0x1b, 0, 0, 0, 1, 0, 0, 0, 0]),
        (
            u64::MAX,
            &[0x1b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
        ),
    ];
    for (v, want) in cases {
        assert_eq!(enc_u64(*v).as_slice(), *want, "shortest form for {v}");
    }
}

/// Length heads (bstr shown; same head machinery serves tstr/array/map) are
/// shortest-form at the 23/24 and 255/256 boundaries, and always definite.
#[test]
fn shortest_form_length_heads_and_definite_lengths() {
    let cases: &[(usize, &[u8])] = &[
        (23, &[0x57]),
        (24, &[0x58, 24]),
        (255, &[0x58, 0xff]),
        (256, &[0x59, 0x01, 0x00]),
    ];
    for (len, want_head) in cases {
        let payload = vec![0xAAu8; *len];
        let mut out = Vec::new();
        Encoder::new(&mut out)
            .bytes(&payload)
            .expect("encoding bytes into a Vec cannot fail");
        assert_eq!(&out[..want_head.len()], *want_head, "bstr length {len}");
        assert_eq!(
            out.len(),
            want_head.len() + len,
            "definite: head + payload only"
        );
    }
    // map(n)/array(n) emit definite heads; indefinite emission exists only as
    // the separate begin_*() calls, which F2 simply never exposes.
    let mut out = Vec::new();
    let mut e = Encoder::new(&mut out);
    e.map(1)
        .and_then(|e| e.u8(1))
        .and_then(|e| e.u8(2))
        .expect("encoding into a Vec cannot fail");
    assert_eq!(out, vec![0xa1, 0x01, 0x02]);
    let mut out = Vec::new();
    let mut e = Encoder::new(&mut out);
    e.array(2)
        .and_then(|e| e.u8(1))
        .and_then(|e| e.u8(2))
        .expect("encoding into a Vec cannot fail");
    assert_eq!(out, vec![0x82, 0x01, 0x02]);
}

/// Map-key emission order is entirely caller-controlled: keys appear exactly
/// in call order, so F2 can guarantee bytewise-sorted keys (== ascending
/// numeric order for the registry's shortest-form unsigned-int keys).
#[test]
fn map_key_emission_order_is_caller_controlled() {
    // Ascending uint keys spanning the 1-byte/2-byte head boundary.
    let mut out = Vec::new();
    let mut e = Encoder::new(&mut out);
    e.map(4).expect("encoding into a Vec cannot fail");
    for k in [1u64, 2, 10, 24] {
        e.u64(k)
            .and_then(|e| e.u64(0))
            .expect("encoding into a Vec cannot fail");
    }
    assert_eq!(
        out,
        vec![0xa4, 0x01, 0x00, 0x02, 0x00, 0x0a, 0x00, 0x18, 24, 0x00]
    );

    // Deliberately unsorted emission is preserved verbatim — the crate never
    // reorders behind our back, so order control is truly ours (and F3 can
    // observe disorder on the decode side).
    let mut out = Vec::new();
    let mut e = Encoder::new(&mut out);
    e.map(2)
        .and_then(|e| e.u64(2))
        .and_then(|e| e.u64(0))
        .and_then(|e| e.u64(1))
        .and_then(|e| e.u64(0))
        .expect("encoding into a Vec cannot fail");
    assert_eq!(out, vec![0xa2, 0x02, 0x00, 0x01, 0x00]);
}

/// F3 probe: a deliberately NON-SHORTEST integer encoding is detectable via
/// (a) the raw head byte (`input()` + `position()`) and (b) the consumed
/// width (`position()` delta vs the value's shortest-form width).
#[test]
fn probe_detects_non_shortest_int_encodings() {
    // (value, non-shortest encoding, canonical width in bytes)
    let cases: &[(u64, &[u8], usize)] = &[
        (5, &[0x18, 0x05], 1),
        (5, &[0x19, 0x00, 0x05], 1),
        (255, &[0x19, 0x00, 0xff], 2),
        (65535, &[0x1a, 0x00, 0x00, 0xff, 0xff], 3),
        (65536, &[0x1b, 0, 0, 0, 0, 0x00, 0x01, 0x00, 0x00], 5),
    ];
    for (value, bytes, canonical_width) in cases {
        let mut d = Decoder::new(bytes);
        let head = d.input()[d.position()];
        let before = d.position();
        let got = d.u64().expect("minicbor is lenient: wide ints decode fine");
        let consumed = d.position() - before;
        assert_eq!(got, *value);
        assert!(
            head >= 0x18,
            "wide encodings always use a multi-byte head (got 0x{head:02x})"
        );
        assert!(
            consumed > *canonical_width,
            "probe sees {consumed} bytes consumed for a {canonical_width}-byte value — F3 rejects"
        );
    }
}

/// F3 probe: a deliberately NON-SHORTEST length head is detectable the same
/// way (head byte + consumed width vs canonical).
#[test]
fn probe_detects_non_shortest_length_heads() {
    // 1-byte bstr with a u8 length argument (canonical is immediate 0x41):
    let wide8 = [0x58u8, 0x01, 0xAA];
    let mut d = Decoder::new(&wide8);
    let head = d.input()[d.position()];
    let before = d.position();
    let payload = d.bytes().expect("lenient decode of wide length head");
    assert_eq!((head, payload), (0x58, &[0xAAu8][..]));
    assert_eq!(
        d.position() - before,
        3,
        "canonical would consume 2 — F3 rejects"
    );

    // 1-byte bstr with a u16 length argument:
    let wide16 = [0x59u8, 0x00, 0x01, 0xAA];
    let mut d = Decoder::new(&wide16);
    let head = d.input()[d.position()];
    let before = d.position();
    let payload = d.bytes().expect("lenient decode of wide length head");
    assert_eq!((head, payload), (0x59, &[0xAAu8][..]));
    assert_eq!(
        d.position() - before,
        4,
        "canonical would consume 2 — F3 rejects"
    );
}

/// F3 probe: indefinite-length items are classified as DISTINCT `Type`
/// variants before any consumption, and `map()`/`array()` independently
/// report `None` for indefinite heads.
#[test]
fn probe_detects_indefinite_items_before_consumption() {
    let dt = |bytes: &[u8]| {
        Decoder::new(bytes)
            .datatype()
            .expect("classifying a present head byte succeeds")
    };
    assert_eq!(dt(&[0xbf, 0x01, 0x02, 0xff]), Type::MapIndef);
    assert_eq!(dt(&[0x9f, 0x01, 0xff]), Type::ArrayIndef);
    assert_eq!(dt(&[0x5f, 0x41, 0xAA, 0xff]), Type::BytesIndef);
    assert_eq!(dt(&[0x7f, 0x61, 0x61, 0xff]), Type::StringIndef);
    // ...and their definite counterparts classify differently:
    assert_eq!(dt(&[0xa1, 0x01, 0x02]), Type::Map);
    assert_eq!(dt(&[0x81, 0x01]), Type::Array);

    let mut d = Decoder::new(&[0xbf, 0x01, 0x02, 0xff]);
    assert_eq!(d.map().expect("indefinite map head parses"), None);
    let mut d = Decoder::new(&[0x9f, 0x01, 0xff]);
    assert_eq!(d.array().expect("indefinite array head parses"), None);
}

/// F3 probe: floats and out-of-schema simple values classify as distinct
/// `Type` variants (float *decoding* is not even compiled in without the
/// opt-in `half` feature, which stays off — the profile bans floats).
#[test]
fn probe_classifies_floats_and_simples() {
    let dt = |bytes: &[u8]| {
        Decoder::new(bytes)
            .datatype()
            .expect("classifying a present head byte succeeds")
    };
    assert_eq!(dt(&[0xf9, 0x3c, 0x00]), Type::F16);
    assert_eq!(dt(&[0xfa, 0, 0, 0, 0]), Type::F32);
    assert_eq!(dt(&[0xfb, 0, 0, 0, 0, 0, 0, 0, 0]), Type::F64);
    assert_eq!(dt(&[0xf4]), Type::Bool);
    assert_eq!(dt(&[0xf6]), Type::Null);
    assert_eq!(dt(&[0xf7]), Type::Undefined);
    assert_eq!(dt(&[0xf8, 0x20]), Type::Simple);
}

/// Native rejections in `str()` (the one place the pinned crate is already
/// strict): invalid UTF-8 in a tstr errors, and indefinite text is refused
/// outright — F3's invalid-UTF-8 class needs no wrapper logic.
#[test]
fn str_rejects_invalid_utf8_and_indefinite_text_natively() {
    // tstr of length 1 whose payload 0xff is not valid UTF-8.
    assert!(Decoder::new(&[0x61, 0xff]).str().is_err());
    // Indefinite text refused by str() (definite-length API).
    assert!(Decoder::new(&[0x7f, 0x61, 0x61, 0xff]).str().is_err());
    // Control: a valid 1-char tstr decodes.
    assert_eq!(
        Decoder::new(&[0x61, 0x61])
            .str()
            .expect("valid tstr decodes"),
        "a"
    );
}

/// F3 probe: sequential key reads expose duplicate and out-of-order keys, so
/// strict-ascent enforcement (two distinct error variants in F3) has all the
/// data it needs.
#[test]
fn sequential_key_reads_support_strict_ascent() {
    let read_keys = |bytes: &[u8]| -> Vec<u64> {
        let mut d = Decoder::new(bytes);
        let n = d
            .map()
            .expect("definite map head parses")
            .expect("fixture maps are definite");
        let mut keys = Vec::new();
        for _ in 0..n {
            keys.push(d.u64().expect("fixture keys are uints"));
            d.skip().expect("fixture values are well-formed");
        }
        keys
    };
    // Out-of-order: F3 sees 1 after 2 (strictly-descending step) — reject.
    assert_eq!(read_keys(&[0xa2, 0x02, 0x00, 0x01, 0x00]), vec![2, 1]);
    // Duplicate: F3 sees an equal successor — reject with the *other* variant.
    assert_eq!(read_keys(&[0xa2, 0x01, 0x00, 0x01, 0x01]), vec![1, 1]);
}

/// F3 probe: trailing bytes after the top-level item are detectable by
/// comparing `position()` against `input().len()`.
#[test]
fn trailing_bytes_are_detectable() {
    let bytes = [0x01u8, 0x02];
    let mut d = Decoder::new(&bytes);
    assert_eq!(d.u64().expect("leading item decodes"), 1);
    assert!(
        d.position() < d.input().len(),
        "trailing byte visible — F3 rejects"
    );

    // Exact consumption on clean input, so the same check accepts it.
    let clean = [0xa1u8, 0x01, 0x02];
    let mut d = Decoder::new(&clean);
    d.skip().expect("well-formed map skips");
    assert_eq!(d.position(), d.input().len());
}

/// F11 compatibility: decode is zero-copy borrowing, so a hostile length
/// claim (bstr of u64::MAX bytes on a 9-byte input) fails with a typed error
/// and cannot allocate by construction.
#[test]
fn hostile_claimed_length_errors_without_allocation() {
    let hostile = [0x5bu8, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
    let mut d = Decoder::new(&hostile);
    assert!(d.bytes().is_err(), "claimed length beyond input must error");
}

/// Library-code discipline preview (full sweep is F3's): malformed and
/// truncated inputs return `Err`, never panic. Every strict prefix of a
/// valid canonical encoding fails to skip as a complete item.
#[test]
fn malformed_and_truncated_inputs_error_never_panic() {
    for bad in [&[0xffu8][..], &[0x18], &[0x19, 0x01], &[0x1b, 0, 0, 0], &[]] {
        assert!(
            Decoder::new(bad).u64().is_err(),
            "input {bad:02x?} must error"
        );
    }
    // Canonical {1: h'AA', 2: 256} — every strict prefix is an error.
    let valid = [0xa2u8, 0x01, 0x41, 0xAA, 0x02, 0x19, 0x01, 0x00];
    assert!(Decoder::new(&valid).skip().is_ok());
    for end in 0..valid.len() {
        let prefix = &valid[..end];
        assert!(
            Decoder::new(prefix).skip().is_err(),
            "strict prefix of length {end} must error, not panic"
        );
    }
}

/// RECORDED LENIENCY (the reason F3 exists): minicbor's own decoder
/// deliberately accepts non-shortest encodings and normalizes them. D7
/// depends on this staying true *and detectable* — if a future pinned
/// version starts rejecting (or stops exposing the probes above), the
/// strict layer's assumptions changed and D7's contingency question opens.
#[test]
fn pinned_decoder_leniency_is_as_recorded() {
    let mut d = Decoder::new(&[0x18, 0x05]);
    assert_eq!(d.u64().expect("wide int accepted (lenient)"), 5);
    let mut d = Decoder::new(&[0x59, 0x00, 0x01, 0xAA]);
    assert_eq!(d.bytes().expect("wide length accepted (lenient)"), &[0xAA]);
}
