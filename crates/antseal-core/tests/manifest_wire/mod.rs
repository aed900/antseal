//! An **independent** hand-rolled CBOR writer for the manifest test
//! suites (F5/F6/F7).
//!
//! Deliberately *not* built on `antseal_core::codec::encode`: the schema
//! tests need bytes the F2 encoder makes unrepresentable — unassigned map
//! keys, wrong-length byte strings, unregistered enum values,
//! non-canonical heads, out-of-order keys. Writing the heads by hand also
//! gives the golden round-trip assertions a second opinion on what
//! canonical CBOR looks like, which is the F2/F3 cross-check the D12
//! independent implementation performs at a larger scale.
//!
//! Everything here is NON-SECRET fixture material: constant byte
//! patterns only, mirroring `antseal_core::manifest::fixtures`.

#![allow(dead_code)] // each test crate uses a different subset

use antseal_core::manifest::registry::key;

// ---------------------------------------------------------------------------
// primitive item writers
// ---------------------------------------------------------------------------

/// A shortest-form CBOR head: `major` in `0..=7`, `arg` the argument.
#[must_use]
pub fn head(major: u8, arg: u64) -> Vec<u8> {
    let mut out = Vec::new();
    let m = major << 5;
    if arg < 24 {
        out.push(m | u8::try_from(arg).expect("arg < 24"));
    } else if let Ok(v) = u8::try_from(arg) {
        out.push(m | 24);
        out.push(v);
    } else if let Ok(v) = u16::try_from(arg) {
        out.push(m | 25);
        out.extend_from_slice(&v.to_be_bytes());
    } else if let Ok(v) = u32::try_from(arg) {
        out.push(m | 26);
        out.extend_from_slice(&v.to_be_bytes());
    } else {
        out.push(m | 27);
        out.extend_from_slice(&arg.to_be_bytes());
    }
    out
}

/// A deliberately **non-shortest** head: forces additional info `ai`
/// (24/25/26/27) regardless of how small `arg` is.
#[must_use]
pub fn head_wide(major: u8, arg: u64, ai: u8) -> Vec<u8> {
    let mut out = vec![(major << 5) | ai];
    match ai {
        24 => out.push(u8::try_from(arg).expect("fits u8")),
        25 => out.extend_from_slice(&u16::try_from(arg).expect("fits u16").to_be_bytes()),
        26 => out.extend_from_slice(&u32::try_from(arg).expect("fits u32").to_be_bytes()),
        _ => out.extend_from_slice(&arg.to_be_bytes()),
    }
    out
}

/// Unsigned integer (major 0).
#[must_use]
pub fn uint(v: u64) -> Vec<u8> {
    head(0, v)
}

/// Unsigned integer written with a wider-than-necessary head.
#[must_use]
pub fn uint_non_shortest(v: u64) -> Vec<u8> {
    head_wide(0, v, 25)
}

/// Byte string (major 2).
#[must_use]
pub fn bstr(payload: &[u8]) -> Vec<u8> {
    let mut out = head(2, payload.len() as u64);
    out.extend_from_slice(payload);
    out
}

/// Text string (major 3).
#[must_use]
pub fn tstr(s: &str) -> Vec<u8> {
    let mut out = head(3, s.len() as u64);
    out.extend_from_slice(s.as_bytes());
    out
}

/// Definite-length array of already-encoded items (major 4).
#[must_use]
pub fn array(items: &[Vec<u8>]) -> Vec<u8> {
    let mut out = head(4, items.len() as u64);
    for item in items {
        out.extend_from_slice(item);
    }
    out
}

/// Definite-length map (major 5) with uint keys, emitted in **ascending**
/// key order — canonical (RFC 8949 §4.2.1).
#[must_use]
pub fn map(entries: &[(u64, Vec<u8>)]) -> Vec<u8> {
    let mut sorted = entries.to_vec();
    sorted.sort_by_key(|(k, _)| *k);
    map_in_given_order(&sorted)
}

/// Definite-length map emitted in exactly the order given — used to
/// build the non-canonical out-of-order and duplicate-key cases.
#[must_use]
pub fn map_in_given_order(entries: &[(u64, Vec<u8>)]) -> Vec<u8> {
    let mut out = head(5, entries.len() as u64);
    for (k, v) in entries {
        out.extend_from_slice(&uint(*k));
        out.extend_from_slice(v);
    }
    out
}

// ---------------------------------------------------------------------------
// entry-list helpers (tests mutate these before encoding)
// ---------------------------------------------------------------------------

/// Overwrite (or add) one map entry.
pub fn set(entries: &mut Vec<(u64, Vec<u8>)>, k: u64, v: Vec<u8>) {
    match entries.iter_mut().find(|(existing, _)| *existing == k) {
        Some(slot) => slot.1 = v,
        None => entries.push((k, v)),
    }
}

/// Drop one map entry (the missing-key and absent-field cases).
pub fn remove(entries: &mut Vec<(u64, Vec<u8>)>, k: u64) {
    entries.retain(|(existing, _)| *existing != k);
}

// ---------------------------------------------------------------------------
// valid v1 shapes (the baseline every reject case perturbs)
// ---------------------------------------------------------------------------

/// The fixture Unicode version (decision D25).
pub const UNICODE_VERSION: &str = "unicode-17.0.0";

/// 32-byte constant-pattern commitment.
#[must_use]
pub fn commit(seed: u8) -> Vec<u8> {
    bstr(&[seed; 32])
}

/// 24-byte constant-pattern nonce.
#[must_use]
pub fn nonce(seed: u8) -> Vec<u8> {
    bstr(&[seed; 24])
}

/// 32-byte constant-pattern address.
#[must_use]
pub fn address(seed: u8) -> Vec<u8> {
    bstr(&[seed; 32])
}

/// `[start, length]` byte range.
#[must_use]
pub fn range(start: u64, length: u64) -> Vec<u8> {
    array(&[uint(start), uint(length)])
}

/// A canonicalization descriptor.
#[must_use]
pub fn descriptor(kind: u64, fine_tree: bool) -> Vec<(u64, Vec<u8>)> {
    let mut entries = vec![
        (key::descriptor::KIND, uint(kind)),
        (
            key::descriptor::FINE_TREE_PRESENT,
            uint(u64::from(fine_tree)),
        ),
    ];
    if fine_tree {
        // Domain is a function of kind: binary => raw (0), text => canonical (1).
        entries.push((key::descriptor::FINE_TREE_DOMAIN, uint(kind)));
    }
    if kind == 1 {
        entries.push((key::descriptor::UNICODE_VERSION, tstr(UNICODE_VERSION)));
    }
    entries
}

/// A fine-tree-covered normal unit (no `unit_commit`).
#[must_use]
pub fn covered_unit(unit_id: u64, start: u64, length: u64) -> Vec<(u64, Vec<u8>)> {
    vec![
        (key::unit::UNIT_ID, uint(unit_id)),
        (key::unit::KIND, uint(0)),
        (key::unit::RANGE, range(start, length)),
        (key::unit::TRUE_LENGTH, uint(length)),
        (key::unit::NONCE, nonce(0x11)),
        (key::unit::ADDRESS, address(0x51)),
    ]
}

/// A non-covered unit (`kind` 0 for a `--no-fine-tree` file, 1 for a raw
/// mirror) — carries a `unit_commit`.
#[must_use]
pub fn noncovered_unit(unit_id: u64, kind: u64, start: u64, length: u64) -> Vec<(u64, Vec<u8>)> {
    vec![
        (key::unit::UNIT_ID, uint(unit_id)),
        (key::unit::KIND, uint(kind)),
        (key::unit::RANGE, range(start, length)),
        (key::unit::TRUE_LENGTH, uint(length)),
        (key::unit::UNIT_COMMIT, commit(0x31)),
        (key::unit::NONCE, nonce(0x12)),
        (key::unit::ADDRESS, address(0x52)),
    ]
}

/// A text file with a fine tree, one covered unit, and a raw mirror last
/// (decision D23).
#[must_use]
pub fn text_file_with_mirror() -> Vec<(u64, Vec<u8>)> {
    file_entry(
        1,
        true,
        1024,
        vec![
            covered_unit(0, 0, 1024),
            noncovered_unit(1, 1, 0, 1030), // mirror, raw domain
        ],
    )
}

/// A binary file with a fine tree and one covered unit.
#[must_use]
pub fn binary_file() -> Vec<(u64, Vec<u8>)> {
    file_entry(0, true, 4096, vec![covered_unit(0, 0, 4096)])
}

/// A `--no-fine-tree` text file: one whole-file non-covered unit.
#[must_use]
pub fn no_fine_tree_file() -> Vec<(u64, Vec<u8>)> {
    file_entry(1, false, 700, vec![noncovered_unit(0, 0, 0, 700)])
}

/// An empty file: `size` 0, no fine tree, one `[0, 0]` unit.
#[must_use]
pub fn empty_file() -> Vec<(u64, Vec<u8>)> {
    file_entry(0, false, 0, vec![noncovered_unit(0, 0, 0, 0)])
}

/// Assemble a file entry from a descriptor kind, fine-tree flag, size,
/// and unit list.
#[must_use]
pub fn file_entry(
    kind: u64,
    fine_tree: bool,
    size: u64,
    units: Vec<Vec<(u64, Vec<u8>)>>,
) -> Vec<(u64, Vec<u8>)> {
    let mut entries = vec![
        (key::file::PATH_COMMIT, commit(0x01)),
        (key::file::RAW_COMMIT, commit(0x02)),
        (key::file::SIZE, uint(size)),
        (key::file::DESCRIPTOR, map(&descriptor(kind, fine_tree))),
        (
            key::file::UNITS,
            array(&units.iter().map(|u| map(u)).collect::<Vec<_>>()),
        ),
    ];
    if kind == 1 {
        entries.push((key::file::CANON_COMMIT, commit(0x03)));
    }
    if fine_tree {
        entries.push((key::file::FINE_ROOT, commit(0x04)));
    }
    entries
}

/// The hybrid `pubkeys` map.
#[must_use]
pub fn hybrid_pubkeys() -> Vec<(u64, Vec<u8>)> {
    vec![(0, bstr(&[0xE1; 32])), (1, bstr(&[0xD1; 1952]))]
}

/// The hybrid `signatures` map.
#[must_use]
pub fn hybrid_signatures() -> Vec<(u64, Vec<u8>)> {
    vec![(0, bstr(&[0x51; 64])), (1, bstr(&[0x52; 3309]))]
}

/// A body carrying the given file entries, hybrid policy throughout.
#[must_use]
pub fn body(files: Vec<Vec<(u64, Vec<u8>)>>) -> Vec<(u64, Vec<u8>)> {
    vec![
        (key::body::FORMAT_VERSION, uint(1)),
        (key::body::APP_VERSION, tstr("antseal-fixture/1")),
        (key::body::SEAL_ID, bstr(&fixture_seal_id())),
        (key::body::TITLE, tstr("fixture work")),
        (key::body::CLAIMED_TIME, uint(1_767_225_600)),
        (key::body::PUBKEYS, map(&hybrid_pubkeys())),
        (key::body::SIG_POLICY, array(&[uint(0), uint(1)])),
        (
            key::body::FILES,
            array(&files.iter().map(|f| map(f)).collect::<Vec<_>>()),
        ),
    ]
}

/// The default valid body: one text file with a raw mirror.
#[must_use]
pub fn default_body() -> Vec<(u64, Vec<u8>)> {
    body(vec![text_file_with_mirror()])
}

/// The fixture `seal_id` bytes: `00 01 … 0f` (NON-SECRET).
#[must_use]
pub fn fixture_seal_id() -> [u8; 16] {
    let mut bytes = [0u8; 16];
    for (i, slot) in bytes.iter_mut().enumerate() {
        *slot = i as u8;
    }
    bytes
}

/// Wrap body bytes in a manifest envelope with the hybrid signatures.
#[must_use]
pub fn envelope_around(body_bytes: &[u8]) -> Vec<u8> {
    map(&[
        (key::envelope::BODY, bstr(body_bytes)),
        (key::envelope::SIGNATURES, map(&hybrid_signatures())),
    ])
}
