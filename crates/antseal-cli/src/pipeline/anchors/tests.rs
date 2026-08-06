//! The anchor-artifact slot record: round trip, and the tamper matrix.
//!
//! These bytes come back out of a vault that an adversary with disk access
//! may have edited (the AEAD catches that, but this decoder must be total
//! either way), so every mutation below must produce a distinct, non-panicking
//! error rather than a plausible-looking record.
//!
//! NON-SECRET: every value here is an obviously synthetic fixture.

use super::*;
use antseal_core::codec::encode_item;

fn fixture() -> AnchorArtifact {
    AnchorArtifact {
        kind: ArtifactKind::TsaToken,
        endpoint: "http://127.0.0.1:1/tsr".to_owned(),
        fetch_date: 1_800_000_000,
        bytes: vec![0x30, 0x82, 0x01, 0x02],
    }
}

#[test]
fn a_record_round_trips_byte_identically() {
    let artifact = fixture();
    let encoded = artifact.encode().expect("encodes");
    assert_eq!(AnchorArtifact::decode(&encoded).expect("decodes"), artifact);
    // Deterministic: the same value encodes to the same bytes.
    assert_eq!(artifact.encode().expect("encodes"), encoded);
}

/// The empty-endpoint OTS shape is a real record, not an accident — the
/// merged `.ots` names its calendars internally.
#[test]
fn the_ots_shape_round_trips_with_an_empty_endpoint() {
    let artifact = AnchorArtifact {
        kind: ArtifactKind::OtsPending,
        endpoint: String::new(),
        fetch_date: 0,
        bytes: vec![0x00, 0x4F, 0x54, 0x53],
    };
    let encoded = artifact.encode().expect("encodes");
    assert_eq!(AnchorArtifact::decode(&encoded).expect("decodes"), artifact);
}

/// **The tamper matrix.** Every mutation fails, each with its own message,
/// and none of them panics.
#[test]
fn every_mutation_is_refused_with_its_own_message() {
    let good = fixture().encode().expect("encodes");

    // 1. A flipped byte anywhere in the record: every one must either be
    //    refused or decode to a **different** record.
    //
    //    Not "must error": flipping a byte inside a CBOR byte string is a
    //    different token, not a malformed one, and detecting *that* is the
    //    vault AEAD's job (U9 binds the record identity as AAD) rather than
    //    this decoder's. What must never happen is a mutation this codec
    //    silently reads back as the original — which is what a decoder that
    //    dropped a field would do, and what this loop reddens on.
    let original = fixture();
    for index in 0..good.len() {
        let mut bad = good.clone();
        bad[index] ^= 0xFF;
        match AnchorArtifact::decode(&bad) {
            Err(_) => {}
            Ok(decoded) => assert_ne!(
                decoded, original,
                "a flipped byte at {index} decoded back to the original record"
            ),
        }
    }

    // 2. Truncation at every length.
    for cut in 0..good.len() {
        assert!(
            AnchorArtifact::decode(&good[..cut]).is_err(),
            "a record truncated to {cut} bytes decoded"
        );
    }

    // 3. Trailing bytes after a complete record.
    let mut trailing = good.clone();
    trailing.push(0x00);
    assert!(AnchorArtifact::decode(&trailing).is_err(), "trailing bytes");

    // 4. An unregistered kind tag — refused, never defaulted to a family.
    let body = encode_item(|e| {
        e.map(|m| {
            m.entry(0, |e| e.u64(7))?;
            m.entry(1, |e| e.str(""))?;
            m.entry(2, |e| e.u64(1))?;
            m.entry(3, |e| e.bytes(&[]))
        })
    })
    .expect("encodes");
    let record = envelope(&body).expect("envelope");
    assert!(
        matches!(
            AnchorArtifact::decode(&record),
            Err(JournalError::Corrupt {
                detail: "unregistered anchor-artifact kind"
            })
        ),
        "kind 7 must be refused by name"
    );

    // 5. An unknown map key — the strict-v1 rule, not a forward-compatible
    //    skip: a record this build cannot fully read must not be acted on.
    let body = encode_item(|e| {
        e.map(|m| {
            m.entry(0, |e| e.u64(1))?;
            m.entry(1, |e| e.str(""))?;
            m.entry(2, |e| e.u64(1))?;
            m.entry(3, |e| e.bytes(&[]))?;
            m.entry(9, |e| e.u64(0))
        })
    })
    .expect("encodes");
    let record = envelope(&body).expect("envelope");
    assert!(
        matches!(
            AnchorArtifact::decode(&record),
            Err(JournalError::Corrupt {
                detail: "unknown anchor-artifact key (strict v1 schema)"
            })
        ),
        "an unknown key must be refused by name"
    );

    // 6. Each required key missing, one at a time.
    for (missing, detail) in [
        (0u64, "artifact kind missing"),
        (1, "artifact endpoint missing"),
        (2, "artifact fetch date missing"),
        (3, "artifact bytes missing"),
    ] {
        let body = encode_item(|e| {
            e.map(|m| {
                if missing != 0 {
                    m.entry(0, |e| e.u64(1))?;
                }
                if missing != 1 {
                    m.entry(1, |e| e.str(""))?;
                }
                if missing != 2 {
                    m.entry(2, |e| e.u64(1))?;
                }
                if missing != 3 {
                    m.entry(3, |e| e.bytes(&[]))?;
                }
                Ok(())
            })
        })
        .expect("encodes");
        let record = envelope(&body).expect("envelope");
        match AnchorArtifact::decode(&record) {
            Err(JournalError::Corrupt { detail: found }) => assert_eq!(found, detail),
            other => panic!("missing key {missing} produced {other:?}"),
        }
    }
}

/// A record from a newer antseal refuses as *newer*, never as corrupt —
/// "upgrade antseal" and "your vault is damaged" are different sentences.
#[test]
fn a_future_version_refuses_distinctly() {
    let body = encode_item(|e| e.map(|m| m.entry(0, |e| e.u64(1)))).expect("encodes");
    let future = encode_item(|e| {
        e.array(|a| {
            a.item(|e| e.u64(u64::from(super::super::journal::SEAL_JOURNAL_VERSION) + 1))?;
            a.item(|e| e.bytes(&body))
        })
    })
    .expect("encodes");
    assert!(matches!(
        AnchorArtifact::decode(&future),
        Err(JournalError::NewerRecord { .. })
    ));
}

/// Slot names satisfy U9's grammar (`[a-z0-9][a-z0-9._-]{0,63}`) for every
/// index a real seal can produce, and the OTS slot is a constant.
#[test]
fn slot_names_satisfy_the_u9_grammar() {
    let grammar = |slot: &str| {
        !slot.is_empty()
            && slot.len() <= 64
            && slot
                .bytes()
                .next()
                .is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
            && slot.bytes().all(|b| {
                b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'-' | b'_')
            })
    };
    assert!(grammar(OTS_SLOT));
    for index in [0usize, 1, 9, 10, 999] {
        assert!(grammar(&tsa_slot(index)), "tsa-{index}");
    }
    assert_eq!(tsa_slot(0), "tsa-0");
}
