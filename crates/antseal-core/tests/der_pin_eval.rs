//! What `der 0.8.1` actually rejects, pinned (task **A5**).
//!
//! D60 §2 measured these behaviours; this file is what makes them *stay*
//! measured. Every case is written so that a `der` bump which changes the
//! behaviour goes red here rather than silently changing what antseal accepts
//! as a genuine timestamp.
//!
//! Two of these tests exist to catch a change in the **permissive**
//! direction, and two to catch a change in the **strict** direction. That
//! asymmetry is deliberate: the strict-direction tests are the ones nobody
//! writes, and they are the ones that would have caught the two defects D60
//! found by measurement — the `to_der(from_der(x)) == x` rule that rejects
//! six of nine real TSAs, and the "reject any leading zero" hardening that
//! rejects every DigiCert token.
//!
//! Native-only: it reads committed fixtures, and `wasm32-unknown-unknown` has
//! no filesystem. The behaviours it pins are target-independent — `der` does
//! no platform-conditional decoding — and `wasm32-core-tests` executes the
//! in-crate unit tests that cover the same decoders.
#![cfg(not(target_arch = "wasm32"))]

use antseal_core::anchor::rfc3161::TimeStampResp;
use der::asn1::{GeneralizedTime, Int};
use der::{Decode, ErrorKind};

const FIXTURES: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../testdata/anchors/A25-bootstrap"
);

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(format!("{FIXTURES}/{name}")).unwrap_or_else(|e| panic!("{name}: {e}"))
}

/// Indefinite-length BER, in both committed shapes.
///
/// **The second leg is the whole test.** Asserting only that the fixture is
/// rejected cannot distinguish "rejected for being BER" from "rejected for
/// being garbage" — and a fixture that is merely corrupt would pass that
/// assertion forever while proving nothing. So each fixture is also fed to
/// `Decode::from_ber`, which must **accept** it: that is what makes it a real
/// BER-where-DER-required case.
///
/// `from_ber` is reachable only because `cms 0.3.0-pre.2` forces `der`'s
/// `ber` feature on for the whole graph (D60 §1.3). It has no legitimate
/// caller in antseal source and A30 bans the token at lane level; **this
/// test is the one sanctioned use**, and it is a use that proves the ban is
/// safe rather than one that erodes it.
#[test]
fn der_pin_rejects_indefinite_length() {
    for name in [
        "D60-ber-indefinite-freetsa.tsr",
        "D60-ber-indefinite-digicert.tsr",
    ] {
        let bytes = fixture(name);
        let err = TimeStampResp::parse(&bytes).expect_err("indefinite lengths are not DER");
        assert_eq!(
            err.code(),
            "anchor-der-not-strict",
            "{name} must be refused as non-DER, not as malformed"
        );

        // The anti-vacuity leg.
        let as_ber = TimeStampResp::from_ber(&bytes);
        assert!(
            as_ber.is_ok(),
            "{name} must be valid BER, or the test above proves nothing about DER strictness"
        );
    }
}

/// Non-minimal long-form lengths: `30 84 00 00 12 1f` where `30 82 12 1f`
/// says the same thing.
#[test]
fn der_pin_rejects_nonminimal_length() {
    for name in [
        "D60-ber-nonminimal-len-freetsa.tsr",
        "D60-ber-nonminimal-len-digicert.tsr",
    ] {
        let bytes = fixture(name);
        let err = TimeStampResp::parse(&bytes).expect_err("non-minimal lengths are not DER");
        assert_eq!(err.code(), "anchor-der-not-strict", "{name}");
    }
}

/// **The anti-over-strictness test.** A leading `00` octet in a DER INTEGER
/// is *required*, not redundant, when the next octet's high bit is set —
/// otherwise the value would read as negative.
///
/// DigiCert's real `TSTInfo.serialNumber` is exactly that shape, 17 octets
/// beginning `00 D5`. Without this test a future "reject any leading zero"
/// hardening reads as an obvious improvement, passes review, and breaks every
/// DigiCert token in the field.
#[test]
fn der_pin_accepts_required_integer_leading_zero() {
    const DIGICERT_SERIAL: &[u8] = &[
        0x02, 0x11, 0x00, 0xD5, 0x8D, 0x33, 0xF1, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0x99, 0xAA, 0xBB, 0xCC,
    ];
    let parsed = Int::from_der(DIGICERT_SERIAL).expect("a required sign prefix is legal DER");
    assert_eq!(
        parsed.as_bytes()[0],
        0x00,
        "the sign prefix must survive decoding; it is part of the value"
    );
    assert_eq!(parsed.as_bytes().len(), 17);
}

/// The other side of the same rule: a leading `00` whose successor's high bit
/// is *clear* is redundant, and redundant is not DER.
#[test]
fn der_pin_rejects_redundant_integer_leading_zero() {
    for (label, bytes) in [
        ("redundant zero", &[0x02u8, 0x02, 0x00, 0x05][..]),
        ("redundant ff", &[0x02, 0x02, 0xFF, 0x80][..]),
        ("empty integer", &[0x02, 0x00][..]),
    ] {
        let err = Int::from_der(bytes).expect_err(label);
        assert!(
            matches!(err.kind(), ErrorKind::Noncanonical { .. }),
            "{label}: expected Noncanonical, got {:?}",
            err.kind()
        );
    }
}

/// The F4 raise-only guard for limit b1, and it binds **upstream**.
///
/// No antseal constant holds this number: the depth limit is `der`'s
/// `Reader::MAX_DEPTH`, consumed rather than minted, because measuring depth
/// ourselves would need a walker and a recursive walker aborts the process on
/// hostile input (D60 §2.4). F4 says a limit may be raised and never lowered,
/// so this test fails if a `der` bump moves the constant in **either**
/// direction — a lowering is then refused at the bump review instead of
/// shipped.
#[test]
fn der_nesting_depth_limit_is_63() {
    /// `n` nested SEQUENCEs around a NULL, built **iteratively** — building
    /// the fixture recursively would overflow the stack before the test ran,
    /// which is the same hazard D60 §2.4 measured in a parser.
    fn nested(n: usize) -> Vec<u8> {
        // Exactly `n` constructions: an empty innermost SEQUENCE, wrapped
        // `n - 1` times. The bottom is empty rather than a NULL because a
        // NULL is itself a construction as far as `split_nested` is
        // concerned — the off-by-one that makes a naive fixture measure 62.
        let mut buf = vec![0x30u8, 0x00];
        for _ in 1..n {
            let mut next = vec![0x30u8];
            // Minimal DER length: short form below 128, else one length octet.
            if buf.len() < 0x80 {
                next.push(u8::try_from(buf.len()).expect("checked above"));
            } else {
                next.push(0x81);
                next.push(u8::try_from(buf.len()).expect("fixture stays under 256 B"));
            }
            next.extend_from_slice(&buf);
            buf = next;
        }
        buf
    }

    // `der::Any` does NOT descend — it captures a TLV's value bytes without
    // parsing them — so decoding the fixture as `Any` exercises depth 1 and
    // would pass at any limit. The depth guard lives in `split_nested`, which
    // only a decoder that actually descends will reach. `Nest` is that
    // decoder: it is recursive, it lives in a test rather than in
    // `antseal-core` (D60 §2.4 bans a recursive walker in the crate), and it
    // is safe here precisely because the guard under test stops it at 64.
    #[derive(Debug)]
    struct Nest;
    impl der::FixedTag for Nest {
        const TAG: der::Tag = der::Tag::Sequence;
    }
    impl<'a> der::DecodeValue<'a> for Nest {
        type Error = der::Error;
        fn decode_value<R: der::Reader<'a>>(
            reader: &mut R,
            _header: der::Header,
        ) -> der::Result<Self> {
            if !reader.is_finished() {
                let _ = Self::decode(reader)?;
            }
            Ok(Self)
        }
    }

    // Self-test FIRST, in the house pattern: prove the decoder really
    // descends, or every assertion below is about a parser that stopped at
    // the first byte.
    assert!(
        Nest::from_der(&nested(3)).is_ok(),
        "the probe decoder must descend at all"
    );
    // Self-test the FIXTURE too: `nested(n)` must really be n constructions.
    assert_eq!(nested(1), vec![0x30, 0x00]);
    assert_eq!(nested(2), vec![0x30, 0x02, 0x30, 0x00]);

    assert!(
        Nest::from_der(&nested(63)).is_ok(),
        "63 nested constructions must decode"
    );
    let err = Nest::from_der(&nested(64)).expect_err("64 nested constructions must not decode");
    assert!(
        matches!(err.kind(), ErrorKind::NestingDepth),
        "expected NestingDepth, got {:?} — `der`'s MAX_DEPTH has moved, and F4 \
         makes a LOWERING a format-version event rather than a bump",
        err.kind()
    );
}

/// DER admits exactly one `GeneralizedTime` spelling:
/// `YYYYMMDDHHMMSSZ`, 15 octets, second precision, `Z`-terminated. All nine
/// live TSAs emit exactly that; every other spelling below is a real
/// encoding some tool produces.
#[test]
fn der_pin_rejects_non_der_generalized_time() {
    let good = tlv(0x18, b"20260802192227Z");
    assert!(
        GeneralizedTime::from_der(&good).is_ok(),
        "the canonical form must decode"
    );

    for (label, text) in [
        ("fractional seconds", &b"20260802192227.5Z"[..]),
        ("seconds omitted", &b"202608021922Z"[..]),
        ("numeric offset", &b"20260802192227+0100"[..]),
        ("no Z", &b"20260802192227"[..]),
    ] {
        let der = tlv(0x18, text);
        assert!(
            GeneralizedTime::from_der(&der).is_err(),
            "{label} is not DER and must be rejected"
        );
    }
}

/// **A change here would be welcome and must still be a review event.**
///
/// `der 0.8.1` does not *reject* an unsorted `SET OF`: `SetOfVec::decode_value`
/// calls `der_sort` and silently canonicalises. That is a documented
/// deviation (D60 §2.2), not an oversight — and the reason it cannot simply
/// be hardened is in §2.3: the CMS `certificates` field is a `SET OF`, real
/// TSAs emit it in chain order rather than DER order, and **six of nine live
/// TSAs including DigiCert** would fail a strict-ordering rule.
///
/// So this test asserts today's behaviour, in order that the day it changes
/// is visible in a diff instead of in a field report.
#[test]
fn der_pin_setof_ordering_is_canonicalised_not_rejected() {
    // SET OF { BOOLEAN FALSE, NULL } in the two possible orders.
    let sorted = [0x31u8, 0x05, 0x01, 0x01, 0x00, 0x05, 0x00];
    let unsorted = [0x31u8, 0x05, 0x05, 0x00, 0x01, 0x01, 0x00];

    let a = der::asn1::SetOfVec::<der::Any>::from_der(&sorted).expect("sorted SET OF decodes");
    let b = der::asn1::SetOfVec::<der::Any>::from_der(&unsorted)
        .expect("`der` canonicalises rather than rejecting an unsorted SET OF");
    assert_eq!(
        a, b,
        "both orders must decode to the same canonical sequence"
    );

    // Duplicates are accepted too (`der`'s own test is named
    // `der_sort_preserves_duplicates`), which is why `signedAttrs` duplicate
    // detection is antseal's job and not the decoder's.
    let dup = [0x31u8, 0x04, 0x05, 0x00, 0x05, 0x00];
    let decoded =
        der::asn1::SetOfVec::<der::Any>::from_der(&dup).expect("duplicates are not rejected");
    assert_eq!(decoded.len(), 2, "both duplicate elements survive");
}

/// The nested-length finding, stated correctly after the first version of
/// this test **falsified it**.
///
/// The claim I started from was "`der` silently accepts content left unread
/// inside a nested construction, because `Reader::finish` runs only at the
/// top level". The first half is true — `read_nested`/`resume_nested` restore
/// the outer input length and never check the inner reader was drained
/// (`der-0.8.1/src/reader/position.rs:93-97`) — and the conclusion does not
/// follow. `resume_nested` does not restore the *position*, so unread inner
/// bytes are simply re-offered to the **outer** decoder, and the top-level
/// `finish()` still requires every byte to be consumed exactly once. Appending
/// junk therefore does not go unnoticed.
///
/// What it does instead is worse and quieter: the junk can be consumed by an
/// *outer* OPTIONAL field of a compatible tag, so the byte count balances and
/// a field is read **from inside another field's length**. That is a genuine
/// parser differential, and it is what `anchor::rfc3161`'s `finish_nested`
/// actually prevents.
///
/// The fixture below is a `TimeStampResp` whose `timeStampToken` is smuggled
/// *inside* the `PKIStatusInfo`'s length. Every length is well-formed and the
/// total balances, so `from_der` alone accepts it — and a second
/// implementation reading the same bytes sees a response with **no token at
/// all**, because the token is not inside the field where a token lives.
#[test]
fn a_token_smuggled_inside_the_status_field_is_rejected() {
    // A minimal well-formed ContentInfo: SEQUENCE { OID id-signedData,
    // [0] EXPLICIT NULL }.
    let content_info = {
        let mut body = vec![
            0x06u8, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02,
        ];
        body.extend_from_slice(&[0xa0, 0x02, 0x05, 0x00]);
        tlv(0x30, &body)
    };

    // PKIStatusInfo { status 0, statusString "wrong" } — statusString is
    // present deliberately: without it the greedy SEQUENCE peek would absorb
    // the smuggled ContentInfo as the statusString and the smuggle would be
    // inert, which would make this test pass for the wrong reason.
    let status_body = {
        let mut b = vec![0x02u8, 0x01, 0x00];
        b.extend_from_slice(&tlv(0x30, &tlv(0x0c, b"wrong")));
        b
    };

    // The legitimate shape: the token sits beside the status block.
    let honest = {
        let mut body = tlv(0x30, &status_body);
        body.extend_from_slice(&content_info);
        tlv(0x30, &body)
    };

    // The smuggled shape: identical bytes, but the status block's length is
    // grown to cover the token.
    let smuggled = {
        let mut inflated = status_body.clone();
        inflated.extend_from_slice(&content_info);
        tlv(0x30, &tlv(0x30, &inflated))
    };
    assert_eq!(
        honest.len(),
        smuggled.len(),
        "the two fixtures must differ only in where a length boundary falls"
    );

    // ANTI-VACUITY LEG: the honest shape is accepted, so the rejection below
    // is about the boundary and not about the bytes.
    let ok = TimeStampResp::parse(&honest).expect("a token beside the status block is legal");
    assert!(
        ok.time_stamp_token.is_some(),
        "the honest fixture must actually carry a token"
    );

    let err = TimeStampResp::parse(&smuggled)
        .expect_err("a token inside the status block's length must be refused");
    assert_eq!(
        err.code(),
        "anchor-der-malformed",
        "expected the drained-reader check in `anchor::rfc3161` to fire"
    );
}

/// Wrap `body` in a TLV with the given tag. Single-octet lengths only — every
/// fixture here is small, and a helper that silently mis-encodes a long form
/// would be worse than one that refuses.
fn tlv(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![tag, u8::try_from(body.len()).expect("fixture body < 128 B")];
    out.extend_from_slice(body);
    out
}
