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
        upgrade: None,
    }
}

/// A synthetic 80-byte block header: every byte is `0xB0 + (i % 16)`, so a
/// truncation or an off-by-one splice is visible in a failure dump.
fn header() -> [u8; 80] {
    let mut bytes = [0u8; 80];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = 0xB0u8.wrapping_add(u8::try_from(index % 16).expect("small"));
    }
    bytes
}

/// The upgraded OTS shape: keys 0..3 plus D79's group at 4/5/6.
fn upgraded_fixture() -> AnchorArtifact {
    AnchorArtifact {
        kind: ArtifactKind::OtsPending,
        endpoint: String::new(),
        // The ORIGINAL submission's date (R4) — deliberately different from
        // the group's, so a write site that confused the two is visible.
        fetch_date: 1_800_000_000,
        bytes: vec![0x00, 0x4F, 0x54, 0x53, 0x01],
        upgrade: Some(OtsUpgrade::new(870_123, header(), 1_800_090_000)),
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
        upgrade: None,
    };
    let encoded = artifact.encode().expect("encodes");
    assert_eq!(AnchorArtifact::decode(&encoded).expect("decodes"), artifact);
}

/// D97's whole point in one assertion: the artifact and its upgrade group
/// live in **one** record, so they round-trip together or not at all — and
/// the record's own fetch date (key 2, the submission's) survives beside the
/// group's (key 6, the header fetch's) without either overwriting the other.
#[test]
fn the_upgraded_ots_shape_round_trips_with_both_fetch_dates_intact() {
    let artifact = upgraded_fixture();
    let encoded = artifact.encode().expect("encodes");
    let back = AnchorArtifact::decode(&encoded).expect("decodes");
    assert_eq!(back, artifact);
    assert_eq!(
        artifact.encode().expect("encodes"),
        encoded,
        "deterministic"
    );

    let upgrade = back.upgrade.as_ref().expect("the group survives");
    assert_eq!(back.fetch_date, 1_800_000_000, "key 2 is the submission's");
    assert_eq!(upgrade.fetch_date(), 1_800_090_000, "key 6 is the header's");
    assert_eq!(upgrade.block_height(), 870_123);
    assert_eq!(upgrade.block_header(), &header());
}

/// **R8: v1 bytes under the v2 parser.**
///
/// [`open_envelope`] throws the version away (`journal.rs:965`), so a record
/// written before D97 arrives at the v2 decoder with nothing to branch on.
/// That is safe here *only* because keys 4/5/6 are optional and
/// absent-means-`None` — which is exactly the right reading of a
/// never-upgraded artifact. This test is what stops the bump being invisible
/// to CI, and it is the rule the next journal schema change must either honour
/// or replace (U54).
#[test]
fn a_v1_envelope_record_still_decodes_and_carries_no_upgrade_group() {
    assert_eq!(
        super::super::journal::SEAL_JOURNAL_VERSION,
        2,
        "this test is about v1 bytes reaching a v2 parser"
    );
    let body = encode_item(|e| {
        e.map(|m| {
            m.entry(0, |e| e.u64(0))?;
            m.entry(1, |e| e.str(""))?;
            m.entry(2, |e| e.u64(1_800_000_000))?;
            m.entry(3, |e| e.bytes(&[0x00, 0x4F, 0x54, 0x53]))
        })
    })
    .expect("encodes");
    let v1_record = encode_item(|e| {
        e.array(|a| {
            a.item(|e| e.u64(1))?;
            a.item(|e| e.bytes(&body))
        })
    })
    .expect("encodes");

    let decoded = AnchorArtifact::decode(&v1_record).expect("a v1 record still decodes at v2");
    assert_eq!(decoded.kind, ArtifactKind::OtsPending);
    assert_eq!(decoded.fetch_date, 1_800_000_000);
    assert_eq!(
        decoded.upgrade, None,
        "absent keys 4/5/6 must read as `not upgraded`, never as a default group"
    );
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

    // 5. An unknown map key — the strict rule, not a forward-compatible
    //    skip: a record this build cannot fully read must not be acted on.
    //
    //    The needle carries no version token on purpose (Q116): it used to
    //    read "strict v1 schema", which D97's bump would have silently
    //    invalidated — the cheapest repair being to edit the needle, which is
    //    how an assertion stops asserting anything.
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
                detail: "unknown anchor-artifact key (strict schema)"
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

/// Build an upgraded-OTS record body by hand, so a row can omit or mis-size
/// exactly one key of the group.
///
/// `kind` is the wire tag, so a row can plant the group on a TSA record
/// without going through [`AnchorArtifact::encode`], which refuses it.
fn hand_built(
    kind: u64,
    height: Option<u64>,
    header_bytes: Option<&[u8]>,
    header_date: Option<u64>,
) -> Vec<u8> {
    let body = encode_item(|e| {
        e.map(|m| {
            m.entry(0, |e| e.u64(kind))?;
            m.entry(1, |e| e.str(""))?;
            m.entry(2, |e| e.u64(1_800_000_000))?;
            m.entry(3, |e| e.bytes(&[0x00, 0x4F, 0x54, 0x53]))?;
            if let Some(height) = height {
                m.entry(4, |e| e.u64(height))?;
            }
            if let Some(bytes) = header_bytes {
                m.entry(5, |e| e.bytes(bytes))?;
            }
            if let Some(date) = header_date {
                m.entry(6, |e| e.u64(date))?;
            }
            Ok(())
        })
    })
    .expect("encodes");
    envelope(&body).expect("envelope")
}

/// **R9: the upgrade group's own tamper matrix.**
///
/// D79 is a parse rule about the *bundle*, and R1 makes this a copy of it
/// rather than a second opinion: the vault and the bundle must reach the same
/// verdict on a partial group, or an artifact that survives one decoder dies
/// in the other and the evidence is lost between them. Every row below is a
/// state an owner with disk access can write, and each fails by its own name.
#[test]
fn every_upgrade_group_mutation_is_refused_with_its_own_message() {
    let good = header();

    // 1. Keys 4 and 5 present, 6 absent — the missing key is named, and it is
    //    the lowest-numbered absent one.
    match AnchorArtifact::decode(&hand_built(0, Some(870_123), Some(&good), None)) {
        Err(JournalError::Corrupt { detail }) => assert_eq!(
            detail, "artifact upgrade group is missing its header fetch date",
            "4+5 without 6 must name key 6"
        ),
        other => panic!("a partial group decoded: {other:?}"),
    }

    // 2. Keys 5 and 6 present, 4 absent — the same rule, naming key 4. Both
    //    rows exist because "report the lowest-numbered absent key" is only
    //    observable when the absent set differs.
    match AnchorArtifact::decode(&hand_built(0, None, Some(&good), Some(1_800_090_000))) {
        Err(JournalError::Corrupt { detail }) => assert_eq!(
            detail, "artifact upgrade group is missing its block height",
            "5+6 without 4 must name key 4"
        ),
        other => panic!("a partial group decoded: {other:?}"),
    }

    // 2b. Only key 5 — two absent, and the report is deterministic rather
    //     than whichever check happened to run first.
    match AnchorArtifact::decode(&hand_built(0, None, Some(&good), None)) {
        Err(JournalError::Corrupt { detail }) => assert_eq!(
            detail, "artifact upgrade group is missing its block height",
            "with 4 and 6 both absent the LOWEST-numbered one is reported"
        ),
        other => panic!("a partial group decoded: {other:?}"),
    }

    // 3. The header is refused **by length**, on both sides of 80 — the same
    //    fixed-length rule `FixedLenField::BlockHeader` applies in the bundle.
    //    A short header is the interesting one: 79 bytes of a real header is a
    //    prefix that parses as plausibly as the whole thing.
    for len in [79usize, 81] {
        let mut sized = good.to_vec();
        sized.resize(len, 0xEE);
        match AnchorArtifact::decode(&hand_built(
            0,
            Some(870_123),
            Some(&sized),
            Some(1_800_090_000),
        )) {
            Err(JournalError::Corrupt { detail }) => assert_eq!(
                detail, "artifact block header must be exactly 80 bytes",
                "a {len}-byte header must be refused by length"
            ),
            other => panic!("a {len}-byte block header decoded: {other:?}"),
        }
    }
    // …and exactly 80 is accepted, so the row above is testing the length and
    // not the shape.
    assert!(
        AnchorArtifact::decode(&hand_built(
            0,
            Some(870_123),
            Some(&good),
            Some(1_800_090_000)
        ))
        .is_ok(),
        "80 bytes is the accepted length"
    );

    // 4. R2: a complete, well-formed group on a `TsaToken` record. Nothing
    //    about the group's *shape* is wrong here — only where it was found,
    //    which is a cross-family confusion the two-slot representation could
    //    not even have expressed.
    match AnchorArtifact::decode(&hand_built(
        1,
        Some(870_123),
        Some(&good),
        Some(1_800_090_000),
    )) {
        Err(JournalError::Corrupt { detail }) => assert_eq!(
            detail, "an upgrade group is only legal on an OTS artifact",
            "a group on a TSA record must be refused by its own message"
        ),
        other => panic!("an upgrade group on a TSA record decoded: {other:?}"),
    }

    // 4b. The write side refuses the same thing, so this codec can never emit
    //     bytes its own decoder rejects.
    let illegal = AnchorArtifact {
        upgrade: upgraded_fixture().upgrade,
        ..fixture()
    };
    assert!(
        matches!(
            illegal.encode(),
            Err(JournalError::IllegalAnchorWrite {
                detail: "an upgrade group may only be recorded on an OTS artifact"
            })
        ),
        "encoding a TSA record with a group must be refused, not written"
    );
}

/// The whole-record matrix, re-run over the **upgraded** shape: flipped
/// bytes, truncations and trailing bytes must behave no differently for a
/// record that is 90 bytes longer and carries a fixed-length field.
#[test]
fn the_upgraded_shape_survives_the_same_whole_record_matrix() {
    let original = upgraded_fixture();
    let good = original.encode().expect("encodes");

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
    for cut in 0..good.len() {
        assert!(
            AnchorArtifact::decode(&good[..cut]).is_err(),
            "a record truncated to {cut} bytes decoded"
        );
    }
    let mut trailing = good.clone();
    trailing.push(0x00);
    assert!(AnchorArtifact::decode(&trailing).is_err(), "trailing bytes");
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

// ─────────────────────────────────────────────────────────────────────────
// U47: the shared reader
//
// `StoredAnchors::read` is the I/O half and is exercised end-to-end over a
// real encrypted vault in `tests/seal_journal.rs`. What lives here is the
// ordering and cross-checking half, over `assemble` — the same code path
// `read` funnels into, testable without an Argon2id derivation per row.
// ─────────────────────────────────────────────────────────────────────────

fn tsa_record(index: usize) -> (String, AnchorArtifact) {
    (
        tsa_slot(index),
        AnchorArtifact {
            kind: ArtifactKind::TsaToken,
            endpoint: format!("http://127.0.0.1:1/tsr/{index}"),
            fetch_date: 1_800_000_000 + index as u64,
            bytes: vec![0x30, u8::try_from(index).expect("small fixture")],
            upgrade: None,
        },
    )
}

/// Twelve TSA captures plus the OTS slot, handed over in exactly the order
/// `list_anchors` produces: `sort_unstable` on the names, which is lexical.
fn twelve_captures_in_directory_order() -> Vec<(String, AnchorArtifact)> {
    let mut records: Vec<(String, AnchorArtifact)> = (0..12).map(tsa_record).collect();
    records.push((OTS_SLOT.to_owned(), upgraded_fixture()));
    records.sort_by(|a, b| a.0.cmp(&b.0));
    records
}

/// **The bug the ≥11-token fixture exists to see.**
///
/// `list_anchors` sorts lexically (`vault/store.rs:744`), so `tsa-10` and
/// `tsa-11` come back between `tsa-1` and `tsa-2`. The engine indexes anchors
/// **positionally** — `AppliedUpgrade::anchor_index` is an offset into
/// `PendingWork::ots` — so a reader that passed the directory order through
/// would pair the eleventh capture with the second one's slot the first time a
/// work had eleven TSAs. Ten or fewer cannot show it: `tsa-0`..`tsa-9` sort
/// lexically and numerically alike, which is why the existing
/// `tests/anchor_stage.rs` fixture (one TSA) is blind to it.
#[test]
fn the_reader_re_sorts_numerically_because_the_directory_order_is_lexical() {
    let directory_order: Vec<String> = twelve_captures_in_directory_order()
        .into_iter()
        .map(|(slot, _)| slot)
        .collect();
    assert_eq!(
        directory_order,
        vec![
            "ots-pending",
            "tsa-0",
            "tsa-1",
            "tsa-10",
            "tsa-11",
            "tsa-2",
            "tsa-3",
            "tsa-4",
            "tsa-5",
            "tsa-6",
            "tsa-7",
            "tsa-8",
            "tsa-9",
        ],
        "the premise: this is what `list_anchors` hands over, and it is wrong \
         for the engine"
    );

    let stored = StoredAnchors::assemble(twelve_captures_in_directory_order(), Vec::new());
    let anchors = stored.require_intact().expect("well-formed slots");
    let read_order: Vec<&str> = anchors
        .all()
        .iter()
        .map(|(slot, _)| slot.as_str())
        .collect();
    assert_eq!(
        read_order,
        vec![
            "ots-pending",
            "tsa-0",
            "tsa-1",
            "tsa-2",
            "tsa-3",
            "tsa-4",
            "tsa-5",
            "tsa-6",
            "tsa-7",
            "tsa-8",
            "tsa-9",
            "tsa-10",
            "tsa-11",
        ],
        "OTS first, then TSA by PARSED index"
    );

    // The two families are contiguous halves, not an interleaving that a
    // caller has to filter — which is what makes `ots()` an index space.
    assert_eq!(anchors.ots().len(), 1);
    assert_eq!(anchors.tsa().len(), 12);
    assert_eq!(anchors.len(), 13);
    assert!(!anchors.is_empty());
    assert_eq!(anchors.tsa()[10].0, "tsa-10");
    assert_eq!(
        anchors.tsa()[10].1.endpoint,
        "http://127.0.0.1:1/tsr/10",
        "the record travelled with its slot, not just the name"
    );
}

/// **R10: `anchor_index` resolves through the list the reader built.**
///
/// The index is an offset into `PendingWork::ots`, never a slot name, and the
/// mapping back is owed by whoever produced the ordering. Today the OTS list
/// is always length ≤ 1, so a wrong answer would be invisible — which is
/// exactly why the invariant is asserted rather than relied on.
#[test]
fn an_anchor_index_maps_to_the_slot_the_same_read_produced() {
    let stored = StoredAnchors::assemble(twelve_captures_in_directory_order(), Vec::new());
    let anchors = stored.require_intact().expect("well-formed slots");

    assert_eq!(anchors.ots_slot(0), Some(OTS_SLOT));
    let (slot, artifact) = anchors.ots_entry(0).expect("one OTS anchor");
    assert_eq!(slot, OTS_SLOT);
    assert_eq!(artifact, &upgraded_fixture());

    // An index past the end is `None`, not a panic and not a neighbouring
    // slot: a report naming an anchor this work does not have is a caller bug
    // that must surface, and TSA slots are NOT reachable through this index
    // space however many of them there are.
    assert_eq!(anchors.ots_slot(1), None);
    assert_eq!(anchors.ots_slot(12), None);
    assert!(anchors.ots_entry(usize::MAX).is_none());
}

/// A work with no anchor slots reads as empty — a state, not a failure.
/// `--no-anchor` seals and works killed before the anchor gate both have one.
#[test]
fn a_work_with_no_anchor_slots_reads_as_empty() {
    let stored = StoredAnchors::assemble(Vec::new(), Vec::new());
    assert!(stored.is_empty());
    let anchors = stored.require_intact().expect("no slots is not a failure");
    assert!(anchors.is_empty());
    assert_eq!(anchors.len(), 0);
    assert!(anchors.all().is_empty());
    assert!(anchors.ots().is_empty());
    assert!(anchors.tsa().is_empty());
    assert_eq!(anchors.ots_slot(0), None);
}

/// The reader's own refusal matrix: a slot set it cannot read wholly is a
/// slot set it refuses wholly, and each refusal has its own message.
#[test]
fn the_reader_refuses_a_slot_set_it_cannot_read_wholly() {
    // 1. A slot name in neither family. U9's grammar admits far more names
    //    than the two families use, so `list_anchors` will hand these over
    //    without complaint — and silently dropping one would hide evidence.
    for alien in ["ots-upgrade", "tsa-01", "tsa-", "tsa-x", "notes.der", "0"] {
        let records = vec![(alien.to_owned(), fixture())];
        match StoredAnchors::assemble(records, Vec::new()).require_intact() {
            Err(JournalError::Corrupt { detail }) => assert_eq!(
                detail, "anchor slot name belongs to no known artifact family",
                "{alien} must be refused by name"
            ),
            other => panic!("the alien slot {alien} was accepted: {other:?}"),
        }
    }

    // 2. A record whose kind disagrees with its slot's family. The slot name
    //    sits outside the AEAD and the kind inside it; U9's identity AAD stops
    //    a *replay* into another slot but not a writer putting the wrong
    //    family in, and a TSA token counted as an OTS anchor is an anchor the
    //    upgrade engine would try to poll.
    let mismatched = vec![(OTS_SLOT.to_owned(), fixture())];
    match StoredAnchors::assemble(mismatched, Vec::new()).require_intact() {
        Err(JournalError::Corrupt { detail }) => {
            assert_eq!(detail, "anchor slot family disagrees with the record kind")
        }
        other => panic!("a TSA token in the OTS slot was accepted: {other:?}"),
    }

    // 3. …and the honest pairing is accepted, so row 2 is testing the
    //    disagreement rather than the slot.
    assert!(
        StoredAnchors::assemble(vec![(OTS_SLOT.to_owned(), upgraded_fixture())], Vec::new())
            .require_intact()
            .is_ok(),
        "an OTS record in the OTS slot is the honest case"
    );
}

// ─────────────────────────────────────────────────────────────────────────
// D100: the refusal is a value, and the two doors
// ─────────────────────────────────────────────────────────────────────────

/// **R10.5**: the decoder is a guardrail, not a casualty. A damaged slot
/// carries the decoder's **own** reason and its **own** message, verbatim.
///
/// The whole tamper matrix above tests `decode` directly and is unaffected by
/// D100 — the decoder must keep refusing exactly as it does, with exactly the
/// messages it does. Only the *caller* softens. This row is what pins that:
/// if a future reader "improved" a damaged slot's sentence, the decoder and
/// the renderer would start telling two stories about one byte.
#[test]
fn a_damaged_slot_carries_the_decoders_own_reason_and_message() {
    // One representative of each of R1's three reasons.

    // `Undecodable`, straight from `assemble`'s family check.
    let stored = StoredAnchors::assemble(vec![(OTS_SLOT.to_owned(), fixture())], Vec::new());
    let (intact, damaged) = stored.intact_and_damaged();
    assert!(intact.is_empty());
    assert_eq!(damaged.len(), 1);
    assert_eq!(damaged[0].reason.name(), "undecodable");
    assert_eq!(
        damaged[0].reason.detail(),
        "anchor slot family disagrees with the record kind",
        "the renderer publishes the decoder's string and does not paraphrase it"
    );
    assert_eq!(damaged[0].reason.format_version(), None);
    assert_eq!(stored.total_slots(), 1);

    // …and the identical string is what `decode` itself raises for the
    // schema refusals, so the two cannot drift.
    let mut truncated = fixture().encode().expect("encodes");
    truncated.truncate(truncated.len() - 1);
    let raised = match AnchorArtifact::decode(&truncated) {
        Err(JournalError::Corrupt { detail }) => detail,
        other => panic!("a truncated record must refuse: {other:?}"),
    };
    let carried = DamageReason::Undecodable { detail: raised };
    assert_eq!(carried.detail(), raised);
    assert_eq!(carried.name(), "undecodable");

    // `NewerRecord` keeps the version, which is the only thing that makes
    // "upgrade antseal" a different sentence from "your vault is damaged".
    let newer = DamageReason::NewerRecord { found: 7 };
    assert_eq!(newer.name(), "newer-record");
    assert_eq!(newer.format_version(), Some(7));
    assert_ne!(newer.detail(), carried.detail());

    // `SlotMoved` is not damage at all: `list` takes no lock by design, so a
    // concurrent seal makes it expected, and rendering it as damage would be
    // a new false accusation replacing the old one.
    let moved = DamageReason::SlotMoved;
    assert_eq!(moved.name(), "slot-moved");
    assert_eq!(moved.format_version(), None);

    // Three reasons, three spellings, no collisions.
    let names = [carried.name(), newer.name(), moved.name()];
    let mut unique = names;
    unique.sort_unstable();
    assert_eq!(unique, ["newer-record", "slot-moved", "undecodable"]);
}

/// **R2**: `require_intact` refuses in the same order the old whole-read did.
///
/// D100 §8 names this as the one place a "behaviour-preserving" refactor can
/// drift silently: `read` used to decode every slot (aborting at the first
/// failure, in `list_anchors`' lexical order) and only then assemble, so
/// **decode** failures preceded **family** failures. If the two passes were
/// merged, two vaults would swap their diagnoses — the same damage reported
/// under a different slot's name.
#[test]
fn the_evidence_door_reports_decode_damage_before_family_damage() {
    // The decode pass found `tsa-9` (lexically last); the family pass finds
    // `ots-pending` (lexically first). The decode failure must still win.
    let decode_damage = vec![DamagedSlot {
        slot: tsa_slot(9),
        reason: DamageReason::Undecodable {
            detail: "journal record is not canonical CBOR",
        },
    }];
    let stored = StoredAnchors::assemble(
        vec![(OTS_SLOT.to_owned(), fixture())],
        decode_damage.clone(),
    );
    match stored.require_intact() {
        Err(JournalError::Corrupt { detail }) => assert_eq!(
            detail, "journal record is not canonical CBOR",
            "the decode pass's finding is the diagnosis, not the family pass's"
        ),
        other => panic!("a damaged set must refuse at the evidence door: {other:?}"),
    }
    assert_eq!(stored.damaged().len(), 2, "both are still reported");
    assert_eq!(stored.damaged()[0].slot, tsa_slot(9));
    assert_eq!(stored.damaged()[1].slot, OTS_SLOT);

    // And `NewerRecord` survives the door with its own class, so the exit
    // code stays `VaultNewerVersion` rather than collapsing into 12.
    let newer = StoredAnchors::assemble(
        Vec::new(),
        vec![DamagedSlot {
            slot: OTS_SLOT.to_owned(),
            reason: DamageReason::NewerRecord { found: 4 },
        }],
    );
    match newer.require_intact() {
        Err(JournalError::NewerRecord { found }) => assert_eq!(found, 4),
        other => panic!("a newer record must keep its class through the door: {other:?}"),
    }

    // A slot that vanished raises the sentence it always raised.
    let moved = StoredAnchors::assemble(
        Vec::new(),
        vec![DamagedSlot {
            slot: OTS_SLOT.to_owned(),
            reason: DamageReason::SlotMoved,
        }],
    );
    match moved.require_intact() {
        Err(JournalError::Corrupt { detail }) => {
            assert_eq!(
                detail,
                "an anchor slot vanished between listing and reading"
            );
        }
        other => panic!("a moved slot must refuse at the evidence door: {other:?}"),
    }
}

/// **R2's residual, closed by a scan** (the S36 shape, as D99 R2 and D97 R3
/// close their equivalents).
///
/// A caller can take the reporting door and drop its second element with an
/// explicit `_`. That is greppable and reviewable, unlike an absent call — so
/// the rule enforced here is *who may hold it at all*: a production file
/// naming `intact_and_damaged(` without being a reporter is a caller that
/// took the reporting door for the artifacts alone.
///
/// Proven red the way every scan in this tree is: point it at a directory
/// containing a planted violation and it must name that file.
#[test]
fn only_the_reporting_commands_take_the_reporting_door() {
    // D100 R2's allowed set. `upgrade_hook.rs` is in it and does not
    // currently need it — the rule is an upper bound, so a reporter that
    // stops reporting does not redden this row; a fourth file does.
    const MAY_REPORT: [&str; 3] = ["listing.rs", "status.rs", "upgrade_hook.rs"];
    // The rule is about **callers**. This module declares the method and
    // documents it, so it names the needle by construction — the same
    // exemption `antseal-anchor`'s own scan takes for a definition site, and
    // it cannot hide a violation because a call here would be a call from
    // the reader into itself.
    const DEFINES: &str = "pipeline/anchors.rs";

    // S36's helper cuts each file at its first `#[cfg(test)]` line, which
    // handles this crate's inline suites — but not the ones it keeps in a
    // `#[path]`-included `foo/tests.rs`, where the attribute sits in the
    // *parent*. `antseal-anchor`'s own scan records the same fact and takes
    // the same exemption. A `tests.rs` is not production by definition, and
    // the rows above this one are built out of exactly the call this rule
    // forbids, so a scan that could not tell the two apart would either
    // delete that evidence or be switched off the first time it fired.
    let is_test_file = |file: &str| file.rsplit('/').next() == Some("tests.rs");

    let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let (named, visited) =
        crate::seal_session::production_files_naming(&src, "intact_and_damaged(");
    assert!(
        visited > 20,
        "the scan must have walked the crate: {visited}"
    );
    assert!(
        named.iter().any(|f| f == DEFINES),
        "the definition site must be found, or the scan is looking at the wrong tree: {named:?}"
    );
    for file in named.iter().filter(|f| *f != DEFINES && !is_test_file(f)) {
        let base = file.rsplit('/').next().unwrap_or(file);
        assert!(
            MAY_REPORT.contains(&base),
            "{file} takes the reporting door without being a reporter — the artifacts are \
             behind `require_intact()`, which refuses rather than handing over a partial \
             picture (D100 R2). Allowed: {MAY_REPORT:?}"
        );
    }
    assert!(
        named.iter().any(|f| f.ends_with("listing.rs")),
        "the scan must be finding real call sites, or it proves nothing: {named:?}"
    );

    // The red direction, planted: a file outside the set that names it.
    let dir = std::env::temp_dir().join("antseal-d100-reporting-door-scan");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("scratch dir");
    std::fs::write(
        dir.join("reveal.rs"),
        "fn build() { let (intact, _) = stored.intact_and_damaged(); }\n",
    )
    .expect("plant");
    let (planted, _) = crate::seal_session::production_files_naming(&dir, "intact_and_damaged(");
    assert_eq!(
        planted,
        vec!["reveal.rs".to_owned()],
        "the scan must name a planted violation, or it is not enforcing anything"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
