//! F11 acceptance suite: the D10-frozen parser resource caps
//! (`docs/decisions/D10-parser-caps.md`; registry §11).
//!
//! The accept list this file discharges:
//!
//! - **per cap: at-cap passes, cap+1 fails with that cap's distinct code** —
//!   nineteen pairs, one per row of D10 §1. "Passes" means *the cap does not
//!   fire*: the cap is checked on the claimed count at the array head, before
//!   any element is read, so an at-cap fixture that supplies no elements fails
//!   later and differently (`cbor-truncated`). That distinction is the whole
//!   point — a tamper row must be able to pin the cap code and nothing else.
//! - **stage-1 precedence** (D10 §5): the size cap is the first statement of
//!   the decode, so an oversized bundle that is *also* non-canonical reports
//!   `bundle-too-large`.
//! - **legitimate maxima fit** (F11 accept): the spec's own worked case
//!   `n = 10^8` needs `2*ceil(log2 n) = 54` cover seeds, comfortably inside
//!   `MAX_COVER_ENTRIES = 256`.
//!
//! The adversarial-allocation assertion (a small input claiming a huge array
//! length allocates nothing large) needs a counting global allocator and
//! therefore lives in its own binary, `tests/parser_caps_alloc.rs`.
//!
//! Secret-material convention (project rule 6): every byte here is a
//! published filler pattern or a length header — never key, salt, or
//! plaintext material.

use antseal_core::bundle::{BundleError, BundleV1};
use antseal_core::codec::caps;
use antseal_core::manifest::{Manifest, ManifestError};

// ─────────────────────────────────────────────────────────────────────
// A minimal hand-rolled canonical-CBOR writer.
//
// Hand-rolled on purpose: F2's builders make a *truncated* item
// unrepresentable, and every fixture here is exactly "a length head that
// claims more than it delivers". The writer emits shortest-form heads, so
// the head-canonicality check (which precedes every cap, D10 §4) passes and
// the cap is what the fixture actually exercises.
// ─────────────────────────────────────────────────────────────────────

fn head(major: u8, arg: u64) -> Vec<u8> {
    let mt = major << 5;
    if arg < 24 {
        vec![mt | arg as u8]
    } else if arg <= u64::from(u8::MAX) {
        vec![mt | 24, arg as u8]
    } else if arg <= u64::from(u16::MAX) {
        let mut v = vec![mt | 25];
        v.extend_from_slice(&(arg as u16).to_be_bytes());
        v
    } else if arg <= u64::from(u32::MAX) {
        let mut v = vec![mt | 26];
        v.extend_from_slice(&(arg as u32).to_be_bytes());
        v
    } else {
        let mut v = vec![mt | 27];
        v.extend_from_slice(&arg.to_be_bytes());
        v
    }
}

fn uint(n: u64) -> Vec<u8> {
    head(0, n)
}
fn arr(n: u64) -> Vec<u8> {
    head(4, n)
}
fn map(n: u64) -> Vec<u8> {
    head(5, n)
}
fn bstr(payload: &[u8]) -> Vec<u8> {
    let mut v = head(2, payload.len() as u64);
    v.extend_from_slice(payload);
    v
}
/// A `bstr` **head** claiming `len` bytes, followed by `len` filler bytes.
/// Separate from [`bstr`] so the large-artifact fixtures do not have to build
/// their payload twice.
fn bstr_of(len: u64) -> Vec<u8> {
    let mut v = head(2, len);
    v.resize(v.len() + len as usize, 0xC7);
    v
}

fn cat(parts: &[&[u8]]) -> Vec<u8> {
    let mut v = Vec::new();
    for p in parts {
        v.extend_from_slice(p);
    }
    v
}

// ─────────────────────────────────────────────────────────────────────
// Bundle prefixes: enough valid, ascending keys to reach the list under
// test, and nothing after it. Keys 0 (version), 1 (manifest bstr) and 2
// (storage record) are required and must decode cleanly first.
// ─────────────────────────────────────────────────────────────────────

fn storage_record() -> Vec<u8> {
    cat(&[
        &map(3),
        &uint(0),
        &bstr_of(32), // address
        &uint(1),
        &bstr_of(24), // nonce
        &uint(2),
        &bstr_of(32), // k_m
    ])
}

/// A bundle map declaring `entries` entries, carrying keys 0/1/2 in full and
/// then `tail` — which is a key followed by whatever the fixture wants.
fn bundle_prefix(entries: u64, tail: &[u8]) -> Vec<u8> {
    cat(&[
        &map(entries),
        &uint(0),
        &uint(1), // format_version = 1
        &uint(1),
        &bstr(&[]), // manifest bstr (never decoded — layer 1 only)
        &uint(2),
        &storage_record(),
        tail,
    ])
}

/// A bundle whose key `key` is an array head claiming `claimed` elements and
/// supplying none.
fn bundle_with_list(key: u64, claimed: u64) -> Vec<u8> {
    bundle_prefix(4, &cat(&[&uint(key), &arr(claimed)]))
}

/// A bundle whose first OTS anchor carries an `ots` blob of `len` bytes.
fn bundle_with_ots_of(len: u64) -> Vec<u8> {
    let anchor = cat(&[
        &map(2),
        &uint(0),
        &uint(0), // status
        &uint(1),
        &bstr_of(len), // ots
    ]);
    bundle_prefix(
        4,
        &cat(&[&uint(3), &arr(1), &anchor, &uint(4), &arr(0), &uint(6)]),
    )
}

/// A bundle whose first TSA anchor carries a `token` of `token_len` bytes and
/// `certs` intermediates of `cert_len` bytes each.
fn bundle_with_tsa(token_len: u64, certs: &[u64]) -> Vec<u8> {
    let mut anchor = cat(&[
        &map(4),
        &uint(0),
        &uint(0), // status
        &uint(1),
        &bstr_of(token_len), // token
        &uint(2),
        &arr(certs.len() as u64),
    ]);
    for len in certs {
        anchor.extend_from_slice(&bstr_of(*len));
    }
    anchor.extend_from_slice(&cat(&[&uint(3), &uint(0)])); // fetch_date
    bundle_prefix(
        5,
        &cat(&[&uint(3), &arr(0), &uint(4), &arr(1), &anchor, &uint(6)]),
    )
}

/// A bundle whose receipt carries a `payload` of `len` bytes.
fn bundle_with_receipt_payload(len: u64) -> Vec<u8> {
    let receipt = cat(&[
        &map(3),
        &uint(0),
        &arr(1),
        &bstr_of(32), // tx_hashes
        &uint(1),
        &uint(7), // block_number
        &uint(2),
        &bstr_of(len), // payload
    ]);
    bundle_prefix(
        6,
        &cat(&[
            &uint(3),
            &arr(0),
            &uint(4),
            &arr(0),
            &uint(5),
            &receipt,
            &uint(6),
        ]),
    )
}

/// A bundle whose receipt's `tx_hashes` array head claims `claimed`.
fn bundle_with_tx_hashes(claimed: u64) -> Vec<u8> {
    let receipt = cat(&[&map(3), &uint(0), &arr(claimed)]);
    bundle_prefix(
        6,
        &cat(&[
            &uint(3),
            &arr(0),
            &uint(4),
            &arr(0),
            &uint(5),
            &receipt,
            &uint(6),
        ]),
    )
}

/// A bundle whose first covered reveal's key `key` (3 = cover, 4 = paths) is
/// an array head claiming `claimed`.
fn bundle_with_covered_list(key: u64, claimed: u64) -> Vec<u8> {
    let mut reveal = cat(&[
        &map(if key == 3 { 4 } else { 5 }),
        &uint(0),
        &uint(0), // unit_id
        &uint(1),
        &bstr_of(32), // k_u
        &uint(2),
        &bstr_of(272), // ciphertext (shape-valid: 272 = 256 + 16)
    ]);
    if key == 4 {
        // `paths` needs a valid `cover` ahead of it (keys ascend).
        reveal.extend_from_slice(&cat(&[&uint(3), &arr(0)]));
    }
    reveal.extend_from_slice(&cat(&[&uint(key), &arr(claimed)]));
    bundle_prefix(
        6,
        &cat(&[
            &uint(3),
            &arr(0),
            &uint(4),
            &arr(0),
            &uint(6),
            &arr(1),
            &reveal,
        ]),
    )
}

// ─────────────────────────────────────────────────────────────────────
// Manifest fixtures (layer 2 → layer 3).
// ─────────────────────────────────────────────────────────────────────

/// A manifest envelope `{0: body, 1: signatures}` wrapping `body`.
fn envelope(body: &[u8]) -> Vec<u8> {
    cat(&[
        &map(2),
        &uint(0),
        &bstr(body),
        &uint(1),
        &map(1),
        &uint(0),
        &bstr_of(64), // ed25519 signature, right length
    ])
}

/// A body carrying every required key validly, ending with a `files` array
/// head that claims `claimed` entries.
fn body_with_files(claimed: u64) -> Vec<u8> {
    // `app_version` and `title` are `tstr` (major 3), not `bstr`, so they are
    // written with `head(3, ..)` rather than through `bstr`.
    cat(&[
        &map(8),
        &uint(0),
        &uint(1),
        &uint(1),
        &head(3, 1),
        b"t", // app_version
        &uint(2),
        &bstr_of(16), // seal_id
        &uint(3),
        &head(3, 0), // title
        &uint(4),
        &uint(0), // claimed_time
        &uint(5),
        &map(1),
        &uint(0),
        &bstr_of(32), // pubkeys {0: ed25519}
        &uint(6),
        &arr(1),
        &uint(0), // sig_policy [ed25519]
        &uint(7),
        &arr(claimed), // files
    ])
}

/// A body with one file entry whose `units` array head claims `claimed`.
fn body_with_units(claimed: u64) -> Vec<u8> {
    let file = cat(&[
        &map(5),
        &uint(0),
        &bstr_of(32), // path_commit
        &uint(1),
        &bstr_of(32), // raw_commit
        &uint(3),
        &uint(0), // size
        &uint(4),
        &cat(&[&map(2), &uint(0), &uint(0), &uint(1), &uint(0)]), // kind=binary, fine_tree_present=0
        &uint(6),
        &arr(claimed),
    ]);
    let mut out = body_with_files(1);
    out.extend_from_slice(&file);
    out
}

// ─────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────

#[track_caller]
fn bundle_code(input: &[u8]) -> &'static str {
    BundleV1::decode(input)
        .map(|_| ())
        .expect_err("fixture must not decode")
        .code()
}

#[track_caller]
fn manifest_code(input: &[u8]) -> &'static str {
    Manifest::decode(input)
        .map(|_| ())
        .expect_err("fixture must not decode")
        .code()
}

/// The shape every count-cap row asserts.
///
/// The cap is checked on the **claimed count at the array head**, before any
/// element is read (D10 §4 order), so an at-cap fixture that supplies no
/// elements gets past the cap and then dies of its own incompleteness — with a
/// `cbor-*`/`*-missing-key` code, never the cap's. At cap+1 the cap fires and
/// nothing else runs. Asserting "not the cap code" at cap rather than one
/// specific replacement keeps the row about the cap, which is what a tamper
/// row binds to.
#[track_caller]
fn assert_count_cap(build: impl Fn(u64) -> Vec<u8>, cap: u64, code: &str) {
    let at_cap = bundle_code(&build(cap));
    assert_ne!(
        at_cap, code,
        "at cap the cap must not fire (fixture reported {at_cap})"
    );
    assert_eq!(
        bundle_code(&build(cap + 1)),
        code,
        "cap+1 must fire this cap's distinct code"
    );
}

// ─────────────────────────────────────────────────────────────────────
// 1. The ten bundle count caps
// ─────────────────────────────────────────────────────────────────────

#[test]
fn cap_ots_anchor_count() {
    assert_count_cap(
        |n| bundle_with_list(3, n),
        caps::MAX_OTS_ANCHOR_COUNT,
        "bundle-too-many-ots-anchors",
    );
}

#[test]
fn cap_tsa_anchor_count() {
    assert_count_cap(
        |n| bundle_with_list(4, n),
        caps::MAX_TSA_ANCHOR_COUNT,
        "bundle-too-many-tsa-anchors",
    );
}

#[test]
fn cap_covered_reveal_count() {
    assert_count_cap(
        |n| bundle_with_list(6, n),
        caps::MAX_COVERED_REVEAL_COUNT,
        "bundle-too-many-covered-reveals",
    );
}

#[test]
fn cap_noncovered_reveal_count() {
    assert_count_cap(
        |n| bundle_with_list(7, n),
        caps::MAX_NONCOVERED_REVEAL_COUNT,
        "bundle-too-many-noncovered-reveals",
    );
}

#[test]
fn cap_touched_file_count() {
    assert_count_cap(
        |n| bundle_with_list(8, n),
        caps::MAX_TOUCHED_FILE_COUNT,
        "bundle-too-many-touched-files",
    );
}

#[test]
fn cap_full_reveal_count() {
    assert_count_cap(
        |n| bundle_with_list(9, n),
        caps::MAX_FULL_REVEAL_COUNT,
        "bundle-too-many-full-reveals",
    );
}

#[test]
fn cap_tx_hash_count() {
    assert_count_cap(
        bundle_with_tx_hashes,
        caps::MAX_TX_HASH_COUNT,
        "bundle-too-many-tx-hashes",
    );
}

#[test]
fn cap_cover_entries() {
    assert_count_cap(
        |n| bundle_with_covered_list(3, n),
        caps::MAX_COVER_ENTRIES,
        "bundle-too-many-cover-entries",
    );
}

#[test]
fn cap_path_nodes() {
    assert_count_cap(
        |n| bundle_with_covered_list(4, n),
        caps::MAX_PATH_NODES,
        "bundle-too-many-path-nodes",
    );
}

#[test]
fn cap_intermediate_count() {
    // At cap: 16 intermediates, each a 1-byte cert, decode fine and the
    // failure comes later (a missing `fetch_date`), not from the cap.
    let at_cap = bundle_with_tsa(1, &vec![1; caps::MAX_INTERMEDIATE_COUNT as usize]);
    assert_ne!(bundle_code(&at_cap), "bundle-too-many-intermediates");
    let over = bundle_with_tsa(1, &vec![1; caps::MAX_INTERMEDIATE_COUNT as usize + 1]);
    assert_eq!(bundle_code(&over), "bundle-too-many-intermediates");
}

// ─────────────────────────────────────────────────────────────────────
// 2. The four opaque-artifact byte caps
// ─────────────────────────────────────────────────────────────────────

#[test]
fn cap_ots_bytes() {
    assert_ne!(
        bundle_code(&bundle_with_ots_of(caps::MAX_OTS_BYTES)),
        "bundle-ots-too-large"
    );
    assert_eq!(
        bundle_code(&bundle_with_ots_of(caps::MAX_OTS_BYTES + 1)),
        "bundle-ots-too-large"
    );
}

#[test]
fn cap_tsa_token_bytes() {
    assert_ne!(
        bundle_code(&bundle_with_tsa(caps::MAX_TSA_TOKEN_BYTES, &[])),
        "bundle-tsa-token-too-large"
    );
    assert_eq!(
        bundle_code(&bundle_with_tsa(caps::MAX_TSA_TOKEN_BYTES + 1, &[])),
        "bundle-tsa-token-too-large"
    );
}

#[test]
fn cap_cert_bytes() {
    assert_ne!(
        bundle_code(&bundle_with_tsa(1, &[caps::MAX_CERT_BYTES])),
        "bundle-cert-too-large"
    );
    assert_eq!(
        bundle_code(&bundle_with_tsa(1, &[caps::MAX_CERT_BYTES + 1])),
        "bundle-cert-too-large"
    );
}

#[test]
fn cap_receipt_payload_bytes() {
    assert_ne!(
        bundle_code(&bundle_with_receipt_payload(
            caps::MAX_RECEIPT_PAYLOAD_BYTES
        )),
        "bundle-receipt-payload-too-large"
    );
    assert_eq!(
        bundle_code(&bundle_with_receipt_payload(
            caps::MAX_RECEIPT_PAYLOAD_BYTES + 1
        )),
        "bundle-receipt-payload-too-large"
    );
}

// ─────────────────────────────────────────────────────────────────────
// 3. The two manifest count caps and the work-global unit budget
// ─────────────────────────────────────────────────────────────────────

#[test]
fn cap_file_count() {
    let at_cap = manifest_code(&envelope(&body_with_files(caps::MAX_FILE_COUNT)));
    assert_ne!(
        at_cap, "manifest-too-many-files",
        "at cap the cap must not fire"
    );
    assert_eq!(
        manifest_code(&envelope(&body_with_files(caps::MAX_FILE_COUNT + 1))),
        "manifest-too-many-files"
    );
}

#[test]
fn cap_unit_count() {
    let at_cap = manifest_code(&envelope(&body_with_units(caps::MAX_UNIT_COUNT)));
    assert_ne!(
        at_cap, "manifest-too-many-units",
        "at cap the cap must not fire"
    );
    assert_eq!(
        manifest_code(&envelope(&body_with_units(caps::MAX_UNIT_COUNT + 1))),
        "manifest-too-many-units"
    );
}

/// One valid, minimal, non-covered normal unit — enough for `FileEntry::new`
/// to accept the file (`--no-fine-tree`, so every unit carries a
/// `unit_commit`; D77 needs at least one `kind = normal`).
fn unit_entry(unit_id: u64) -> Vec<u8> {
    cat(&[
        &map(7),
        &uint(0),
        &uint(unit_id), // unit_id
        &uint(1),
        &uint(0), // kind = normal
        &uint(2),
        &cat(&[&arr(2), &uint(0), &uint(0)]), // range [0, 0)
        &uint(3),
        &uint(0), // true_length
        &uint(4),
        &bstr_of(32), // unit_commit
        &uint(5),
        &bstr_of(24), // nonce
        &uint(6),
        &bstr_of(32), // address
    ])
}

/// A `--no-fine-tree` binary file entry carrying `units.len()` real units.
fn file_entry(units: &[Vec<u8>]) -> Vec<u8> {
    // Five entries: keys 0, 1, 3, 4, 6 (no canon_commit — binary; no
    // fine_root — no fine tree).
    let mut out = cat(&[
        &map(5),
        &uint(0),
        &bstr_of(32), // path_commit
        &uint(1),
        &bstr_of(32), // raw_commit
        &uint(3),
        &uint(0), // size
        &uint(4),
        &cat(&[&map(2), &uint(0), &uint(0), &uint(1), &uint(0)]), // kind=binary, fine_tree_present=0
        &uint(6),
        &arr(units.len() as u64),
    ]);
    for u in units {
        out.extend_from_slice(u);
    }
    out
}

/// **The property `DecodeBudget` exists for.** The unit cap is *work-global*,
/// not per-file: a second file does not get a fresh allowance. A per-file cap
/// would let a hostile manifest multiply unit count by file count — "2^20
/// files claiming one unit each" would slip through a cap that stops "one file
/// claiming 2^20 units".
///
/// Observed end to end on real bytes: file 1 spends the whole budget with
/// genuine units, then file 2 asks for one more and is refused with
/// `manifest-too-many-units`. The control run — file 1 one unit short — gets
/// past the budget and fails elsewhere.
#[test]
fn unit_budget_is_charged_across_files_not_per_file() {
    let units: Vec<Vec<u8>> = (0..caps::MAX_UNIT_COUNT).map(unit_entry).collect();

    // Budget exhausted by file 1; file 2's array head is over.
    let mut body = body_with_files(2);
    body.extend_from_slice(&file_entry(&units));
    body.extend_from_slice(&file_entry(&units[..1]));
    assert_eq!(
        manifest_code(&envelope(&body)),
        "manifest-too-many-units",
        "a second file must not get a fresh per-file allowance"
    );

    // Control: one unit short, so file 2's single unit still fits.
    let mut ok = body_with_files(2);
    ok.extend_from_slice(&file_entry(&units[..units.len() - 1]));
    ok.extend_from_slice(&file_entry(&units[..1]));
    let control = manifest_code(&envelope(&ok));
    assert_ne!(
        control, "manifest-too-many-units",
        "exactly at the work-global cap must still be admitted (got {control})"
    );
}

// ─────────────────────────────────────────────────────────────────────
// 4. The two input-size caps and stage-1 precedence
// ─────────────────────────────────────────────────────────────────────

#[test]
fn cap_manifest_bytes() {
    // At cap: a 16 MiB slice is admitted by the size check and then fails on
    // its own contents, not on the cap.
    let at_cap = vec![0u8; caps::MAX_MANIFEST_BYTES as usize];
    assert_ne!(manifest_code(&at_cap), "manifest-too-large");
    let over = vec![0u8; caps::MAX_MANIFEST_BYTES as usize + 1];
    assert_eq!(manifest_code(&over), "manifest-too-large");
}

#[test]
fn cap_bundle_bytes() {
    let at_cap = vec![0u8; caps::MAX_BUNDLE_BYTES as usize];
    assert_ne!(bundle_code(&at_cap), "bundle-too-large");
    let over = vec![0u8; caps::MAX_BUNDLE_BYTES as usize + 1];
    assert_eq!(bundle_code(&over), "bundle-too-large");
}

/// **D10 §5, frozen precedence.** The bundle size cap is the first statement
/// of `BundleV1::decode`, so it beats every other rejection — including the
/// canonicality classes that would otherwise fire first. An oversized bundle
/// that is *also* non-canonical reports `bundle-too-large`.
#[test]
fn the_bundle_size_cap_precedes_canonicality() {
    // A deliberately non-canonical prefix (indefinite-length map) padded past
    // the cap. Under the cap it reports the canonicality class; over the cap
    // the size check wins.
    let mut under = vec![0xbf_u8]; // indefinite map — always non-canonical
    under.resize(caps::MAX_BUNDLE_BYTES as usize, 0);
    assert_eq!(bundle_code(&under), "cbor-indefinite-length");

    let mut over = vec![0xbf_u8];
    over.resize(caps::MAX_BUNDLE_BYTES as usize + 1, 0);
    assert_eq!(
        bundle_code(&over),
        "bundle-too-large",
        "the O(1) size check must precede the O(input) walk"
    );
}

/// The manifest counterpart: `Manifest::decode`'s size cap likewise precedes
/// the envelope walk, so an oversized manifest is never reported as corrupt.
#[test]
fn the_manifest_size_cap_precedes_canonicality() {
    let mut over = vec![0xbf_u8];
    over.resize(caps::MAX_MANIFEST_BYTES as usize + 1, 0);
    assert_eq!(manifest_code(&over), "manifest-too-large");
}

// ─────────────────────────────────────────────────────────────────────
// 5. Distinctness, and the sizing sanity check F11's accept list names
// ─────────────────────────────────────────────────────────────────────

/// Every cap code is distinct from every other, and all eighteen exist.
/// A tamper row binds to a code, so two caps sharing one would make the two
/// mutations indistinguishable.
#[test]
fn the_eighteen_cap_codes_are_pairwise_distinct() {
    use antseal_core::bundle::error::{BundleListKind, OpaqueField};
    use antseal_core::manifest::error::ManifestListKind;
    use std::collections::BTreeSet;

    let mut codes: Vec<&'static str> = vec![
        BundleError::InputTooLarge { len: 1, cap: 0 }.code(),
        ManifestError::InputTooLarge { len: 1, cap: 0 }.code(),
    ];
    for list in BundleListKind::ALL {
        codes.push(
            BundleError::ListTooLong {
                list,
                claimed: 1,
                cap: 0,
            }
            .code(),
        );
    }
    for field in OpaqueField::ALL {
        codes.push(
            BundleError::ArtifactTooLarge {
                field,
                len: 1,
                cap: 0,
            }
            .code(),
        );
    }
    for list in ManifestListKind::ALL {
        codes.push(
            ManifestError::ListTooLong {
                list,
                claimed: 1,
                cap: 0,
            }
            .code(),
        );
    }

    assert_eq!(codes.len(), 18, "D10 mints eighteen new codes");
    let unique: BTreeSet<&str> = codes.iter().copied().collect();
    assert_eq!(unique.len(), 18, "cap codes must be pairwise distinct");
    for code in &unique {
        assert!(code.contains("-too-large") || code.contains("-too-many-"));
    }
}

/// **F11 accept: "legitimate maxima fit with margin".** The spec's own worked
/// case is `n = 10^8` (line 96), whose leaf-exact minimal GGM cover is
/// `2*ceil(log2 n) = 54` seeds with at most as many boundary path nodes.
/// Both sit far inside the 256-entry caps — and, because `size` is a CBOR
/// `uint`, `d <= 64` bounds *any* representable file at 128, exactly half the
/// cap. That is why the cap is safe to freeze forever.
#[test]
fn legitimate_maxima_fit_with_margin() {
    let n: u64 = 100_000_000;
    let d = 64 - (n - 1).leading_zeros() as u64; // ceil(log2 n) for n > 1
    assert_eq!(d, 27, "ceil(log2 10^8) = 27");
    assert!(
        2 * d <= caps::MAX_COVER_ENTRIES / 4,
        "≥4x margin at the spec's own case"
    );
    assert!(2 * d <= caps::MAX_PATH_NODES / 4);

    // The absolute bound for any file the format can express.
    const MAX_D: u64 = 64;
    assert_eq!(2 * MAX_D * 2, caps::MAX_COVER_ENTRIES);
    assert_eq!(2 * MAX_D * 2, caps::MAX_PATH_NODES);
}
