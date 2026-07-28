//! An **independent** hand-rolled CBOR writer for the `.sealproof` bundle
//! test suites (F8/F9).
//!
//! Deliberately *not* built on `antseal_core::codec::encode` or on the
//! bundle's own encoder: the schema tests need bytes the F2 encoder — and
//! the F8 schema types — make unrepresentable. A wrong-length `k_u`, a
//! reserved key, a two-of-three OTS upgrade group, an unregistered
//! `anchor_status`, an unsorted cover: none of those can be *constructed*
//! through `BundleV1`, which is exactly why proving the validator rejects
//! them requires a writer that does not share its assumptions.
//!
//! The primitive item writers are reused from
//! [`crate::manifest_wire`](../manifest_wire/index.html) — one hand-rolled
//! CBOR layer for both halves of the registry, so a bug in the test writer
//! cannot make one half look healthier than the other.
//!
//! Everything here is NON-SECRET fixture material: constant byte patterns
//! only. No key, salt, or seed value in this file was ever derived from a
//! real master secret (project rule 6).

#![allow(dead_code)] // each test crate uses a different subset

use antseal_core::bundle::registry::key;

use crate::manifest_wire::{array, bstr, envelope_around, map, tstr, uint};

// ---------------------------------------------------------------------------
// leaf shapes
// ---------------------------------------------------------------------------

/// A 32-byte constant-pattern disclosed key (`k_u`, `k_m`).
#[must_use]
pub fn key32(seed: u8) -> Vec<u8> {
    bstr(&[seed; 32])
}

/// A 16-byte constant-pattern disclosed salt.
#[must_use]
pub fn salt16(seed: u8) -> Vec<u8> {
    bstr(&[seed; 16])
}

/// A 32-byte constant-pattern GGM seed / node hash / tx hash.
#[must_use]
pub fn bytes32(seed: u8) -> Vec<u8> {
    bstr(&[seed; 32])
}

/// A 24-byte constant-pattern nonce.
#[must_use]
pub fn nonce24(seed: u8) -> Vec<u8> {
    bstr(&[seed; 24])
}

/// An 80-byte constant-pattern Bitcoin block header.
#[must_use]
pub fn block_header(seed: u8) -> Vec<u8> {
    bstr(&[seed; 80])
}

/// A well-shaped unit ciphertext: `blocks` padding blocks plus the 16-byte
/// AEAD tag, so `len >= 272` and `len ≡ 16 (mod 256)` (registry §2).
#[must_use]
pub fn ciphertext(blocks: usize, seed: u8) -> Vec<u8> {
    bstr(&vec![seed; blocks * 256 + 16])
}

/// `cover_entry = [level, index, seed]` (registry §5).
#[must_use]
pub fn cover_entry(level: u64, index: u64, seed: u8) -> Vec<u8> {
    array(&[uint(level), uint(index), bytes32(seed)])
}

/// `path_node = [level, index, hash]` (registry §5).
#[must_use]
pub fn path_node(level: u64, index: u64, seed: u8) -> Vec<u8> {
    array(&[uint(level), uint(index), bytes32(seed)])
}

// ---------------------------------------------------------------------------
// sections
// ---------------------------------------------------------------------------

/// The manifest storage record (registry §7.7).
#[must_use]
pub fn storage_record() -> Vec<(u64, Vec<u8>)> {
    vec![
        (key::storage_record::ADDRESS, bytes32(0xA0)),
        (key::storage_record::NONCE, nonce24(0xA1)),
        (key::storage_record::K_M, key32(0xA2)),
    ]
}

/// An OTS anchor artifact (registry §7.8). `upgraded` decides whether the
/// whole all-or-nothing upgrade group is present (D79).
#[must_use]
pub fn ots_anchor(status: u64, upgraded: bool) -> Vec<(u64, Vec<u8>)> {
    let mut entries = vec![
        (key::ots_anchor::STATUS, uint(status)),
        (key::ots_anchor::OTS, bstr(&[0x4F; 96])),
    ];
    if upgraded {
        entries.push((key::ots_anchor::BLOCK_HEIGHT, uint(870_000)));
        entries.push((key::ots_anchor::BLOCK_HEADER, block_header(0xB7)));
        entries.push((key::ots_anchor::FETCH_DATE, uint(1_767_225_600)));
    }
    entries
}

/// A TSA anchor artifact (registry §7.9).
#[must_use]
pub fn tsa_anchor(status: u64, intermediates: usize, source: Option<&str>) -> Vec<(u64, Vec<u8>)> {
    let certs: Vec<Vec<u8>> = (0..intermediates)
        .map(|i| bstr(&[0xC0 + i as u8; 48]))
        .collect();
    let mut entries = vec![
        (key::tsa_anchor::STATUS, uint(status)),
        (key::tsa_anchor::TOKEN, bstr(&[0x30; 128])),
        (key::tsa_anchor::INTERMEDIATES, array(&certs)),
        (key::tsa_anchor::FETCH_DATE, uint(1_767_225_601)),
    ];
    if let Some(url) = source {
        entries.push((key::tsa_anchor::SOURCE, tstr(url)));
    }
    entries
}

/// The opt-in Arbitrum receipt record (registry §7.10).
#[must_use]
pub fn receipt() -> Vec<(u64, Vec<u8>)> {
    vec![
        (
            key::receipt::TX_HASHES,
            array(&[bytes32(0xE0), bytes32(0xE1)]),
        ),
        (key::receipt::BLOCK_NUMBER, uint(263_000_000)),
        (key::receipt::PAYLOAD, bstr(&[0x50; 64])),
    ]
}

/// A covered-unit reveal (registry §7.11) whose cover and boundary path are
/// strictly ascending by leaf-interval start.
///
/// Modelled on a real opening so the ordering fixture is not accidentally
/// degenerate: an 8-leaf grid (`d = 3`) with the unit spanning leaves
/// `[1, 6)`. Its leaf-exact dyadic cover is `(3,1)` → `[1,2)`, `(2,1)` →
/// `[2,4)`, `(2,2)` → `[4,6)` (starts 1, 2, 4) and the boundary siblings are
/// `(3,0)` → `[0,1)` and `(2,3)` → `[6,8)` (starts 0, 6).
#[must_use]
pub fn covered_reveal(unit_id: u64) -> Vec<(u64, Vec<u8>)> {
    vec![
        (key::covered_reveal::UNIT_ID, uint(unit_id)),
        (key::covered_reveal::K_U, key32(0x11)),
        (key::covered_reveal::CIPHERTEXT, ciphertext(2, 0x22)),
        (
            key::covered_reveal::COVER,
            array(&[
                cover_entry(3, 1, 0x31),
                cover_entry(2, 1, 0x32),
                cover_entry(2, 2, 0x33),
            ]),
        ),
        (
            key::covered_reveal::PATHS,
            array(&[path_node(3, 0, 0x41), path_node(2, 3, 0x42)]),
        ),
    ]
}

/// A covered-unit reveal spanning the whole grid: non-empty cover, empty
/// boundary path (registry §7.11 — the "empty exactly when the unit spans
/// `[0, n)`" case, whose *exactly* is R's).
#[must_use]
pub fn covered_reveal_whole_grid(unit_id: u64) -> Vec<(u64, Vec<u8>)> {
    vec![
        (key::covered_reveal::UNIT_ID, uint(unit_id)),
        (key::covered_reveal::K_U, key32(0x13)),
        (key::covered_reveal::CIPHERTEXT, ciphertext(1, 0x24)),
        (
            key::covered_reveal::COVER,
            array(&[cover_entry(0, 0, 0x35)]),
        ),
        (key::covered_reveal::PATHS, array(&[])),
    ]
}

/// A non-covered-unit reveal (registry §7.12) — the `--no-fine-tree` and
/// raw-mirror case. There is no mirror flag: the manifest's `kind`
/// identifies it (D23).
#[must_use]
pub fn noncovered_reveal(unit_id: u64) -> Vec<(u64, Vec<u8>)> {
    vec![
        (key::noncovered_reveal::UNIT_ID, uint(unit_id)),
        (key::noncovered_reveal::K_U, key32(0x12)),
        (key::noncovered_reveal::CIPHERTEXT, ciphertext(1, 0x23)),
        (key::noncovered_reveal::UNIT_SALT, salt16(0x61)),
    ]
}

/// A touched-file entry (registry §7.13).
#[must_use]
pub fn touched_file(file_id: u64, path: &str) -> Vec<(u64, Vec<u8>)> {
    vec![
        (key::touched_file::FILE_ID, uint(file_id)),
        (key::touched_file::PATH, tstr(path)),
        (key::touched_file::PATH_SALT, salt16(0x71)),
    ]
}

/// A full-reveal entry (registry §7.14). `s_root` present is the
/// fine-tree case; absent is the `--no-fine-tree`/empty-file case. Which one
/// is *correct* for a given file is D28's derived predicate — tier [R].
#[must_use]
pub fn full_reveal(file_id: u64, with_s_root: bool) -> Vec<(u64, Vec<u8>)> {
    let mut entries = vec![
        (key::full_reveal::FILE_ID, uint(file_id)),
        (key::full_reveal::FILE_SALT, salt16(0x81)),
    ];
    if with_s_root {
        entries.push((key::full_reveal::S_ROOT, bytes32(0x91)));
    }
    entries
}

// ---------------------------------------------------------------------------
// whole bundles
// ---------------------------------------------------------------------------

/// The embedded plaintext manifest envelope every fixture bundle carries.
#[must_use]
pub fn embedded_manifest() -> Vec<u8> {
    let body = map(&crate::manifest_wire::default_body());
    envelope_around(&body)
}

/// Encode a list of section entry-lists as a CBOR array of maps.
#[must_use]
pub fn section(entries: &[Vec<(u64, Vec<u8>)>]) -> Vec<u8> {
    array(&entries.iter().map(|e| map(e)).collect::<Vec<_>>())
}

/// The default valid bundle: both anchor kinds (the OTS one upgraded), the
/// receipt opted in, one covered and one non-covered reveal, two touched
/// files, and one full reveal whose `file_id` also appears in
/// `touched_files`.
#[must_use]
pub fn default_bundle() -> Vec<(u64, Vec<u8>)> {
    vec![
        (key::bundle::FORMAT_VERSION, uint(1)),
        (key::bundle::MANIFEST, bstr(&embedded_manifest())),
        (key::bundle::STORAGE_RECORD, map(&storage_record())),
        (key::bundle::OTS_ANCHORS, section(&[ots_anchor(2, true)])),
        (
            key::bundle::TSA_ANCHORS,
            section(&[tsa_anchor(0, 2, Some("https://freetsa.org/tsr"))]),
        ),
        (key::bundle::RECEIPT, map(&receipt())),
        (
            key::bundle::COVERED_REVEALS,
            section(&[covered_reveal(0), covered_reveal_whole_grid(1)]),
        ),
        (
            key::bundle::NONCOVERED_REVEALS,
            section(&[noncovered_reveal(2)]),
        ),
        (
            key::bundle::TOUCHED_FILES,
            section(&[
                touched_file(0, "notes/pitch.md"),
                touched_file(1, "logo.png"),
            ]),
        ),
        (key::bundle::FULL_REVEALS, section(&[full_reveal(0, true)])),
    ]
}

/// The **empty-anchor, zero-reveal** bundle: every required section present
/// and empty, receipt absent (registry §7.6 — required-may-be-empty, so this
/// has exactly one encoding rather than one with keys missing).
#[must_use]
pub fn empty_bundle() -> Vec<(u64, Vec<u8>)> {
    vec![
        (key::bundle::FORMAT_VERSION, uint(1)),
        (key::bundle::MANIFEST, bstr(&embedded_manifest())),
        (key::bundle::STORAGE_RECORD, map(&storage_record())),
        (key::bundle::OTS_ANCHORS, section(&[])),
        (key::bundle::TSA_ANCHORS, section(&[])),
        (key::bundle::COVERED_REVEALS, section(&[])),
        (key::bundle::NONCOVERED_REVEALS, section(&[])),
        (key::bundle::TOUCHED_FILES, section(&[])),
        (key::bundle::FULL_REVEALS, section(&[])),
    ]
}

/// Encode a bundle entry list to canonical CBOR bytes.
#[must_use]
pub fn encode(entries: &[(u64, Vec<u8>)]) -> Vec<u8> {
    map(entries)
}
