//! **F's registry slice for the tamper matrix** (task F15): the
//! format-level fixtures — one mutation each, applied to bytes derived from
//! the F12/F13 golden vectors — plus the seven of them that carry a
//! harness row.
//!
//! The harness (distinctness, no-panic and exact-outcome assertions, and
//! the add-a-row procedure) is [`super::tamper`]; the code contract these
//! rows bind to is `docs/testing/error-code-contract.md`.
//!
//! # Fixtures and rows are different populations, and the difference is the
//! finding
//!
//! A **fixture** is "these bytes, this surface, this outcome". A **row** is
//! additionally a claim of *distinctness*: Q7 refuses two rows expecting the
//! same outcome, because that would mean two mutations are one observable
//! failure (MVP-SPEC.md line 168).
//!
//! F6/F9 decided — deliberately, and the error-code contract §2 records it —
//! that a wrapped codec rejection **surfaces its inner code unchanged** at
//! every layer. `SealProofError::code()` delegates; so does
//! `ManifestError::{Envelope, Body}`. What distinguishes the layers is
//! [`ManifestError::layer`]/[`SealProofError::layer`], which is *pipeline
//! context, not a rejection class*.
//!
//! The consequence for F15 is structural: a duplicate map key in the
//! manifest **body**, in the manifest **envelope**, in the **bundle** map,
//! and in the **embedded manifest** are four different fixtures that all
//! report `cbor-duplicate-map-key`. They cannot be four rows — Q7 would
//! correctly refuse the set — and inventing per-layer codes to make them
//! rows would fork one taxonomy into four, which is exactly what the
//! contract forbids. So:
//!
//! - every fixture is checked on **`(code, layer)`**, which *is* pairwise
//!   informative, by the mapping table's consumer
//!   (`crates/antseal-core/tests/format_tamper_fixtures.rs`);
//! - a fixture becomes a **row** only when its code is not already claimed
//!   anywhere in the global registry.
//!
//! # The seven rows
//!
//! | row id | code | why it is a row |
//! | --- | --- | --- |
//! | `cbor-non-shortest-length` | `cbor-non-shortest-length` | line-73 class no seed row claimed |
//! | `manifest-unknown-key` | `manifest-unknown-key` | F5's unknown-key class, body map |
//! | `manifest-reserved-key` | `manifest-reserved-key` | F4's reserved band, body map |
//! | `bundle-unknown-key` | `bundle-unknown-key` | F8's unknown-key class, bundle map |
//! | `bundle-reserved-key` | `bundle-reserved-key` | F8's reserved band (key 10, the named `range_reveals` slot) |
//! | `cbor-oversized` | `bundle-too-large` | MVP-SPEC.md line 168's `oversized … CBOR` |
//! | `cbor-nesting-too-deep` | `cbor-nesting-too-deep` | line 168's `… /deep CBOR` |
//!
//! The four spec-named body mutations (duplicate key, non-shortest int,
//! indefinite length, trailing bytes) already have rows — Q7's seed rows in
//! `crates/antseal-core/tests/tamper_matrix.rs`, mapped by
//! `testdata/tamper/MATRIX.json`'s `non-canonical-cbor-body` family. F15
//! gives each of them a **real manifest-body fixture** rather than a second,
//! colliding row: same four distinct codes, now produced by mutating the
//! golden vectors' own manifest body and driving it through
//! `Manifest::decode`.
//!
//! # Two rows that are deliberately not shaped like the rest
//!
//! - **`cbor-nesting-too-deep` is a direct call on `check_canonical`.**
//!   `docs/decisions/D10-parser-caps.md` §6 established that over-deep CBOR
//!   is *unreachable* through `SealProof::decode`: every v1 field has a
//!   fixed type, so nesting an array where a `uint` is expected yields
//!   `cbor-unexpected-type` at level 1 and never a depth violation at level
//!   9. The depth guard lives in the generic walker, so the row exercises
//!   the walker — the same shape R3's `wrong-length-*` rows and R7's
//!   `s_root` row already use.
//! - **`cbor-oversized` is synthesized, not committed.** Its mutation is a
//!   *length*: `MAX_BUNDLE_BYTES + 1` bytes. [`oversized_bundle`] builds a
//!   zero-filled buffer of exactly that length with the golden bundle
//!   copied over its prefix, so the row's claim ("a real bundle, padded one
//!   byte past the cap") is honest without 256 MiB entering the repository.
//!   The buffer is `vec![0u8; n]`, i.e. `alloc_zeroed`, and nothing reads
//!   past the O(1) length check D10 §5 makes the first statement of
//!   `BundleV1::decode`.
//!
//! # Provenance of the bases
//!
//! Both bases are built by R6's deterministic constructor from the *same*
//! work the golden vectors pin — `single binary`, ed25519-only,
//! `data/blob.bin` = `00..3f`:
//!
//! | base | golden vector |
//! | --- | --- |
//! | [`base_manifest`] | `testdata/vectors/v1/manifest/manifest.json`, case `minimal-binary-ed25519-only`, `manifest_bytes` |
//! | [`base_bundle`] | `testdata/vectors/v1/bundle/bundle.json`, case `empty-anchor-unanchored`, `bundle_bytes` |
//!
//! That equality is **asserted**, not asserted-in-prose: the mapping
//! table's consumer diffs both against the committed vector documents, so
//! "derived from the golden vectors" fails loudly if it ever stops being
//! true.

use crate::bundle::registry::key as bundle_key;
use crate::bundle::{SealProof, SealProofError};
use crate::codec::caps::{MAX_BUNDLE_BYTES, MAX_CBOR_DEPTH};
use crate::codec::decode::{CanonicalDecoder, DecodeError, check_canonical};
use crate::manifest::registry::{V1_KEY_BAND_MAX, key as manifest_key};
use crate::manifest::{Manifest, ManifestError, encode_envelope};

use super::bundle_fixtures::{Selection, WorkSpec, build, shapes};
use super::tamper::{ActualOutcome, ExpectedOutcome, TamperRow};

/// **F25's span-locating primitives, exposed beside F15's own.**
///
/// F15's primitives ([`insert_first_entry`](self), [`append_entry`](self),
/// [`widen_head`](self), …) reach a top-level map head and the end of the
/// slice. [`super::cbor_span`] reaches an *arbitrary* item, by
/// `(path-to-item)` rather than by a pinned offset, and is built on the same
/// F3 public surface — so the two sets are interchangeable in kind and a
/// fixture can pick whichever expresses its mutation honestly.
pub use super::cbor_span::{
    ItemSpan, MAJOR_ARRAY, MAJOR_BYTES, Step, all_item_spans, canonical_head, item_span,
    span_at_path, span_of_next_item, splice_head_at_path, splice_item_at_path,
};

// ---------------------------------------------------------------------------
// the two bases
// ---------------------------------------------------------------------------

/// The work both bases derive from: the golden vectors' `single binary`
/// case under the ed25519-only `sig_policy`, which is what keeps the bases
/// small enough to commit (no 3 309-byte ML-DSA signature) while still
/// being real sealed artifacts.
fn base_work() -> WorkSpec {
    shapes::single_binary().with_ed25519_only_policy()
}

/// The base **manifest envelope** bytes: byte-identical to the F12 golden
/// vector's `minimal-binary-ed25519-only` case (module docs).
///
/// The manifest is a function of the work and not of what a reveal shows,
/// which is why the selection here is "nothing" — the same choice
/// [`super::vectors_manifest`] makes.
#[must_use]
pub fn base_manifest() -> Vec<u8> {
    build(&base_work(), &Selection::nothing(1)).manifest
}

/// The base **`.sealproof`** bytes: byte-identical to the F13 golden
/// vector's `empty-anchor-unanchored` case — the UNANCHORED bundle, fully
/// revealing its one file (module docs).
#[must_use]
pub fn base_bundle() -> Vec<u8> {
    build(&base_work(), &Selection::all(1)).bytes
}

/// The base manifest **body** bytes — the envelope's key-0 `bstr` contents,
/// which is the layer-3 input and the pre-image of `work_id`.
#[must_use]
pub fn base_body() -> Option<Vec<u8>> {
    let envelope = base_manifest();
    let manifest = Manifest::decode(&envelope).ok()?;
    Some(manifest.body_bytes().to_vec())
}

// ---------------------------------------------------------------------------
// canonical-CBOR splicing primitives
//
// Every one of these is total and fallible: they return `None` rather than
// panicking on an input that is not the canonical map they expect, so a
// fixture whose base drifted fails as a wrong outcome naming its row rather
// than as a crash inside the harness.
// ---------------------------------------------------------------------------

/// `(head_len, entry_count)` of the canonical CBOR map starting at byte 0.
///
/// Read through the F3 decoder's own public surface rather than by
/// re-implementing head parsing, so a fixture can never disagree with the
/// decoder about where a map head ends.
fn map_head(map: &[u8]) -> Option<(usize, u64)> {
    let mut d = CanonicalDecoder::new(map);
    let reader = d.map().ok()?;
    Some((d.position(), reader.remaining()))
}

/// The shortest-form (canonical) head for a map of `count` entries.
fn canonical_map_head(count: u64) -> Vec<u8> {
    /// Major type 5 (map) in the top three bits.
    const MAJOR: u8 = 0xA0;
    if count <= 23 {
        vec![MAJOR | (count as u8)]
    } else if count <= u64::from(u8::MAX) {
        vec![MAJOR | 24, count as u8]
    } else if count <= u64::from(u16::MAX) {
        let mut v = vec![MAJOR | 25];
        v.extend_from_slice(&(count as u16).to_be_bytes());
        v
    } else if count <= u64::from(u32::MAX) {
        let mut v = vec![MAJOR | 26];
        v.extend_from_slice(&(count as u32).to_be_bytes());
        v
    } else {
        let mut v = vec![MAJOR | 27];
        v.extend_from_slice(&count.to_be_bytes());
        v
    }
}

/// Re-head `map` with `count` entries and the given body bytes after the
/// head.
fn rehead(count: u64, entries: &[&[u8]]) -> Vec<u8> {
    let mut out = canonical_map_head(count);
    for entry in entries {
        out.extend_from_slice(entry);
    }
    out
}

/// Insert `entry` immediately **after the head**, before the first existing
/// entry, and bump the entry count by one.
fn insert_first_entry(map: &[u8], entry: &[u8]) -> Option<Vec<u8>> {
    let (head_len, count) = map_head(map)?;
    let rest = map.get(head_len..)?;
    Some(rehead(count.checked_add(1)?, &[entry, rest]))
}

/// Append `entry` **after the last existing entry** and bump the entry
/// count by one.
///
/// The map is the whole slice, so "after the last entry" is "at the end" —
/// no per-entry span walk is needed, which is what keeps these primitives
/// free of a second CBOR implementation.
fn append_entry(map: &[u8], entry: &[u8]) -> Option<Vec<u8>> {
    let (head_len, count) = map_head(map)?;
    let rest = map.get(head_len..)?;
    Some(rehead(count.checked_add(1)?, &[rest, entry]))
}

/// Replace the definite map head with the indefinite-length one (`0xBF`),
/// terminating the map with a break so the mutated item is a *well-formed*
/// indefinite map and the only fault is that the profile forbids it.
fn make_head_indefinite(map: &[u8]) -> Option<Vec<u8>> {
    let (head_len, _) = map_head(map)?;
    let rest = map.get(head_len..)?;
    let mut out = vec![0xBF_u8];
    out.extend_from_slice(rest);
    out.push(0xFF);
    Some(out)
}

/// Re-encode the map head one argument width wider — same entry count, a
/// non-shortest length argument (RFC 8949 §4.2.1).
fn widen_head(map: &[u8]) -> Option<Vec<u8>> {
    let (head_len, count) = map_head(map)?;
    let rest = map.get(head_len..)?;
    // One width up from the shortest form for this count.
    let wide = match canonical_map_head(count).len() {
        1 => vec![0xB8_u8, count as u8],
        2 => {
            let mut v = vec![0xB9_u8];
            v.extend_from_slice(&(count as u16).to_be_bytes());
            v
        }
        4 => {
            let mut v = vec![0xBA_u8];
            v.extend_from_slice(&(count as u32).to_be_bytes());
            v
        }
        _ => {
            let mut v = vec![0xBB_u8];
            v.extend_from_slice(&count.to_be_bytes());
            v
        }
    };
    let mut out = wide;
    out.extend_from_slice(rest);
    Some(out)
}

/// Replace `old_len` bytes at offset `at` with `new`.
fn splice(bytes: &[u8], at: usize, old_len: usize, new: &[u8]) -> Option<Vec<u8>> {
    let before = bytes.get(..at)?;
    let after = bytes.get(at.checked_add(old_len)?..)?;
    let mut out = Vec::with_capacity(before.len() + new.len() + after.len());
    out.extend_from_slice(before);
    out.extend_from_slice(new);
    out.extend_from_slice(after);
    Some(out)
}

/// One byte appended after a complete top-level item.
fn append_trailing(bytes: &[u8]) -> Vec<u8> {
    let mut out = bytes.to_vec();
    out.push(0x00);
    out
}

// ---------------------------------------------------------------------------
// body-layer construction
// ---------------------------------------------------------------------------

/// The body's first entry on the wire: key 0 (`format_version`) with the
/// value 1. Both halves are one byte, which is what makes the value-level
/// mutations (non-shortest int, float) a fixed-offset splice.
const BODY_FIRST_ENTRY: [u8; 2] = [
    manifest_key::body::FORMAT_VERSION as u8,
    crate::manifest::registry::FORMAT_VERSION_V1 as u8,
];

/// Byte offset of the body's `format_version` **value**, and a check that
/// the first entry really is the one [`BODY_FIRST_ENTRY`] describes.
fn body_first_value_offset(body: &[u8]) -> Option<usize> {
    let (head_len, _) = map_head(body)?;
    let first = body.get(head_len..head_len.checked_add(2)?)?;
    if first != BODY_FIRST_ENTRY {
        return None;
    }
    head_len.checked_add(1)
}

/// Wrap mutated body bytes back into the base envelope, keeping the base's
/// signatures untouched.
///
/// The envelope is re-encoded (its `bstr` length head follows the mutated
/// body's length), which is the only honest way to present a mutated body:
/// a length head left stale would be a *second* mutation.
fn envelope_around(body: &[u8]) -> Option<Vec<u8>> {
    let base = base_manifest();
    let manifest = Manifest::decode(&base).ok()?;
    encode_envelope(body, manifest.signatures()).ok()
}

/// Apply `mutate` to the base body and re-wrap it in the base envelope.
fn body_fixture(mutate: impl FnOnce(&[u8]) -> Option<Vec<u8>>) -> Option<Vec<u8>> {
    let body = base_body()?;
    envelope_around(&mutate(&body)?)
}

// ---------------------------------------------------------------------------
// envelope-layer construction
// ---------------------------------------------------------------------------

/// `(head_len, end of the key-0 entry)` of a manifest envelope.
///
/// The envelope is `{0: bstr(body), 1: signatures}`, so these two offsets
/// split it into its exactly two entries without a general span walk.
fn envelope_entry_split(envelope: &[u8]) -> Option<(usize, usize)> {
    let mut d = CanonicalDecoder::new(envelope);
    let mut reader = d.map().ok()?;
    let head_len = d.position();
    reader.next_key(&mut d).ok()??;
    d.bytes().ok()?;
    Some((head_len, d.position()))
}

/// The base envelope's two entries, as byte slices of a freshly built base.
fn envelope_entries() -> Option<(Vec<u8>, Vec<u8>)> {
    let envelope = base_manifest();
    let (head_len, split) = envelope_entry_split(&envelope)?;
    Some((
        envelope.get(head_len..split)?.to_vec(),
        envelope.get(split..)?.to_vec(),
    ))
}

// ---------------------------------------------------------------------------
// the twenty fixtures
// ---------------------------------------------------------------------------

/// Which strict surface a fixture's bytes are fed to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Surface {
    /// [`check_canonical`] — the schema-agnostic strict pass.
    Canonical,
    /// `Manifest::decode` — layers 2 and 3 of registry §7.6.3.
    ManifestDecode,
    /// `SealProof::decode` — all three layers.
    SealProofDecode,
}

impl Surface {
    /// The name the mapping table records.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Canonical => "check_canonical",
            Self::ManifestDecode => "Manifest::decode",
            Self::SealProofDecode => "SealProof::decode",
        }
    }
}

/// One format-level tamper fixture: bytes, the surface they are fed to, and
/// the `(code, layer)` pair they must produce.
pub struct FormatFixture {
    /// Stable fixture id; also the committed file's stem.
    pub id: &'static str,
    /// Which base the mutation starts from (`manifest` / `bundle`).
    pub base: &'static str,
    /// One-line description of the single mutation applied.
    pub mutation: &'static str,
    /// The strict surface the bytes are fed to.
    pub surface: Surface,
    /// The stable code the surface must report.
    pub code: &'static str,
    /// The decode layer the failure must be attributed to, when the surface
    /// is a layered decoder.
    ///
    /// `None` **iff** the surface is not one. Exactly one surface
    /// qualifies: [`Surface::Canonical`], the schema-agnostic strict pass,
    /// which has no notion of layers. `Manifest::decode` and
    /// `SealProof::decode` attribute a layer to every rejection,
    /// canonicality and schema alike, because a schema rejection names its
    /// own map and the map coarsens to a layer (D86 §4.5).
    ///
    /// Before D86 the two accessors were asymmetric — a bundle schema
    /// rejection was `Some("bundle")` while a manifest schema rejection was
    /// `None` — so `layer == null` meant "schema rejection **inside the
    /// manifest**", and `manifest-unknown-key` at the envelope was
    /// indistinguishable from the same code at the body.
    pub layer: Option<&'static str>,
    /// Whether the fixture's bytes are committed under
    /// `testdata/tamper/format/`. False only for [`oversized_bundle`],
    /// whose mutation is a length (module docs).
    pub committed: bool,
    /// The harness row this fixture is the evidence for, if any. `None`
    /// means the fixture's code is already claimed by another row, so a
    /// second row would fail Q7's distinctness assertion by design.
    pub row: Option<&'static str>,
    /// Builds the mutated bytes. `None` means the base drifted; the caller
    /// turns that into a loud failure rather than a skip.
    pub build: fn() -> Option<Vec<u8>>,
}

macro_rules! body_fixture_fn {
    ($name:ident, $body:expr) => {
        fn $name() -> Option<Vec<u8>> {
            body_fixture($body)
        }
    };
}

// ── the four spec-named body mutations (MVP-SPEC.md line 168) ──

body_fixture_fn!(body_duplicate_map_key, |body| insert_first_entry(
    body,
    &BODY_FIRST_ENTRY
));

body_fixture_fn!(body_non_shortest_int, |body| {
    let at = body_first_value_offset(body)?;
    // The value 1, re-encoded in a two-byte head.
    splice(body, at, 1, &[0x18, 0x01])
});

body_fixture_fn!(body_indefinite_length, make_head_indefinite);

body_fixture_fn!(body_trailing_bytes, |body| Some(append_trailing(body)));

// ── the remaining line-73 rejection classes, in the body ──

body_fixture_fn!(body_unsorted_map_keys, |body| append_entry(
    body,
    // Key 0 after the map's largest key: descending, not duplicate.
    &[manifest_key::body::FORMAT_VERSION as u8, 0x00]
));

body_fixture_fn!(body_non_shortest_length, widen_head);

body_fixture_fn!(body_float, |body| {
    let at = body_first_value_offset(body)?;
    // Half-precision 1.0 — the profile bans floats outright.
    splice(body, at, 1, &[0xF9, 0x3C, 0x00])
});

body_fixture_fn!(body_reserved_key, |body| append_entry(
    body,
    // The body's first reserved key (registry §1 rule 4).
    &[manifest_key::body::RESERVED_FIRST as u8, 0x00]
));

body_fixture_fn!(body_unknown_key, |body| append_entry(
    body,
    // 24 — the first key above the v1 band, never reserved.
    &[0x18, (V1_KEY_BAND_MAX + 1) as u8, 0x00]
));

// ── the same canonicality classes at the OUTER manifest layer ──

fn envelope_duplicate_map_key() -> Option<Vec<u8>> {
    let (entry0, entry1) = envelope_entries()?;
    Some(rehead(3, &[&entry0, &entry0, &entry1]))
}

fn envelope_unsorted_map_keys() -> Option<Vec<u8>> {
    let (entry0, entry1) = envelope_entries()?;
    Some(rehead(2, &[&entry1, &entry0]))
}

fn envelope_trailing_bytes() -> Option<Vec<u8>> {
    Some(append_trailing(&base_manifest()))
}

fn envelope_unknown_key() -> Option<Vec<u8>> {
    // The envelope is shape-frozen and reserves nothing (registry §1 rule
    // 6), so *any* key besides 0/1 is unknown — permanently. There is no
    // envelope-layer reserved-key fixture for the same reason.
    append_entry(&base_manifest(), &[0x02, 0x00])
}

// ── the bundle map (layer 1) ──

fn bundle_first_entry() -> Option<[u8; 2]> {
    let bundle = base_bundle();
    let (head_len, _) = map_head(&bundle)?;
    let first = bundle.get(head_len..head_len.checked_add(2)?)?;
    let expected = [
        bundle_key::bundle::FORMAT_VERSION as u8,
        crate::bundle::registry::FORMAT_VERSION_V1 as u8,
    ];
    (first == expected).then_some(expected)
}

fn bundle_duplicate_map_key() -> Option<Vec<u8>> {
    let entry = bundle_first_entry()?;
    insert_first_entry(&base_bundle(), &entry)
}

fn bundle_trailing_bytes() -> Option<Vec<u8>> {
    Some(append_trailing(&base_bundle()))
}

fn bundle_reserved_key() -> Option<Vec<u8>> {
    // Key 10 — the *named* reserved slot (v1.1 `range_reveals`), which
    // registry §7.15 requires to raise the ordinary reserved-slot error.
    append_entry(
        &base_bundle(),
        &[bundle_key::bundle::RESERVED_FIRST as u8, 0x00],
    )
}

fn bundle_unknown_key() -> Option<Vec<u8>> {
    append_entry(&base_bundle(), &[0x18, (V1_KEY_BAND_MAX + 1) as u8, 0x00])
}

// ── the embedded-manifest layer (layer 2, inside a canonical layer 1) ──

/// Transpose the embedded manifest envelope's two entries **in place**
/// inside an otherwise untouched bundle.
///
/// The swap is length-preserving, so the bundle's `bstr` length head — and
/// therefore every byte of layer 1 — is unchanged: layer 1 stays perfectly
/// canonical and the fault exists only at layer 2. That is the shape F15
/// asks for by "non-canonical embedded-manifest layer", and it is the one
/// mutation that proves the per-layer strict pass is really run rather than
/// implied by the outer one.
fn embedded_manifest_unsorted_map_keys() -> Option<Vec<u8>> {
    let bundle = base_bundle();
    let envelope = base_manifest();
    let mutated = envelope_unsorted_map_keys()?;
    if mutated.len() != envelope.len() {
        return None;
    }
    let at = bundle
        .windows(envelope.len())
        .position(|window| window == envelope.as_slice())?;
    splice(&bundle, at, envelope.len(), &mutated)
}

// ── the two spec-named size/depth mutations ──

/// A real bundle padded one byte past [`MAX_BUNDLE_BYTES`].
///
/// Synthesized rather than committed (module docs). `vec![0u8; n]` takes
/// the `alloc_zeroed` path, and `BundleV1::decode`'s first statement is the
/// O(1) length comparison, so nothing after the copied prefix is ever read.
#[must_use]
pub fn oversized_bundle() -> Option<Vec<u8>> {
    let base = base_bundle();
    let over = usize::try_from(MAX_BUNDLE_BYTES).ok()?.checked_add(1)?;
    if over < base.len() {
        return None;
    }
    let mut out = vec![0u8; over];
    out.get_mut(..base.len())?.copy_from_slice(&base);
    Some(out)
}

/// The golden manifest body wrapped in `MAX_CBOR_DEPTH + 1` single-element
/// arrays, so the body map sits one container deeper than the walker admits.
///
/// A direct-call fixture: D10 §6 records why this is unreachable through
/// `SealProof::decode` (module docs).
fn over_deep_body() -> Option<Vec<u8>> {
    let body = base_body()?;
    let depth = usize::from(MAX_CBOR_DEPTH).checked_add(1)?;
    // 0x81 = array(1).
    let mut out = vec![0x81_u8; depth];
    out.extend_from_slice(&body);
    Some(out)
}

/// Every format-level fixture, in committed-file order.
pub const FIXTURES: &[FormatFixture] = &[
    // ── the four MVP-SPEC.md line 168 body mutations ──
    FormatFixture {
        id: "body-duplicate-map-key",
        base: "manifest",
        mutation: "repeat the body's key-0 entry, bumping the map head to n+1",
        surface: Surface::ManifestDecode,
        code: "cbor-duplicate-map-key",
        layer: Some("manifest body"),
        committed: true,
        row: Some("cbor-duplicate-map-key"),
        build: body_duplicate_map_key,
    },
    FormatFixture {
        id: "body-non-shortest-int",
        base: "manifest",
        mutation: "re-encode the body's `format_version` value in a two-byte head",
        surface: Surface::ManifestDecode,
        code: "cbor-non-shortest-int",
        layer: Some("manifest body"),
        committed: true,
        row: Some("cbor-non-shortest-int"),
        build: body_non_shortest_int,
    },
    FormatFixture {
        id: "body-indefinite-length",
        base: "manifest",
        mutation: "re-head the body map as indefinite-length, terminated by a break",
        surface: Surface::ManifestDecode,
        code: "cbor-indefinite-length",
        layer: Some("manifest body"),
        committed: true,
        row: Some("cbor-indefinite-length"),
        build: body_indefinite_length,
    },
    FormatFixture {
        id: "body-trailing-bytes",
        base: "manifest",
        mutation: "append one byte after the body's top-level item",
        surface: Surface::ManifestDecode,
        code: "cbor-trailing-bytes",
        layer: Some("manifest body"),
        committed: true,
        row: Some("cbor-trailing-bytes"),
        build: body_trailing_bytes,
    },
    // ── the remaining line-73 classes, in the body ──
    FormatFixture {
        id: "body-unsorted-map-keys",
        base: "manifest",
        mutation: "append a key-0 entry after the body's largest key",
        surface: Surface::ManifestDecode,
        code: "cbor-unsorted-map-keys",
        layer: Some("manifest body"),
        committed: true,
        row: Some("cbor-unsorted-map-keys"),
        build: body_unsorted_map_keys,
    },
    FormatFixture {
        id: "body-non-shortest-length",
        base: "manifest",
        mutation: "widen the body map's length head by one argument width",
        surface: Surface::ManifestDecode,
        code: "cbor-non-shortest-length",
        layer: Some("manifest body"),
        committed: true,
        row: Some("cbor-non-shortest-length"),
        build: body_non_shortest_length,
    },
    FormatFixture {
        id: "body-float",
        base: "manifest",
        mutation: "replace the body's `format_version` value with a half-precision float",
        surface: Surface::ManifestDecode,
        code: "cbor-float",
        layer: Some("manifest body"),
        committed: true,
        row: Some("cbor-float"),
        build: body_float,
    },
    FormatFixture {
        id: "body-reserved-key",
        base: "manifest",
        mutation: "append the body's first reserved key (8) with a zero value",
        surface: Surface::ManifestDecode,
        code: "manifest-reserved-key",
        layer: Some("manifest body"),
        committed: true,
        row: Some("manifest-reserved-key"),
        build: body_reserved_key,
    },
    FormatFixture {
        id: "body-unknown-key",
        base: "manifest",
        mutation: "append body key 24 — above the v1 band, never reserved",
        surface: Surface::ManifestDecode,
        code: "manifest-unknown-key",
        layer: Some("manifest body"),
        committed: true,
        row: Some("manifest-unknown-key"),
        build: body_unknown_key,
    },
    // ── the same classes one layer out, at the manifest envelope ──
    FormatFixture {
        id: "envelope-duplicate-map-key",
        base: "manifest",
        mutation: "repeat the envelope's key-0 (body) entry",
        surface: Surface::ManifestDecode,
        code: "cbor-duplicate-map-key",
        layer: Some("manifest envelope"),
        committed: true,
        row: None,
        build: envelope_duplicate_map_key,
    },
    FormatFixture {
        id: "envelope-unsorted-map-keys",
        base: "manifest",
        mutation: "transpose the envelope's two entries, emitting key 1 before key 0",
        surface: Surface::ManifestDecode,
        code: "cbor-unsorted-map-keys",
        layer: Some("manifest envelope"),
        committed: true,
        row: None,
        build: envelope_unsorted_map_keys,
    },
    FormatFixture {
        id: "envelope-trailing-bytes",
        base: "manifest",
        mutation: "append one byte after the outer manifest's top-level item",
        surface: Surface::ManifestDecode,
        code: "cbor-trailing-bytes",
        layer: Some("manifest envelope"),
        committed: true,
        row: None,
        build: envelope_trailing_bytes,
    },
    FormatFixture {
        id: "envelope-unknown-key",
        base: "manifest",
        mutation: "append envelope key 2 — the envelope is shape-frozen and reserves nothing",
        surface: Surface::ManifestDecode,
        code: "manifest-unknown-key",
        // The layer is what distinguishes this fixture from
        // `body-unknown-key`: same code, one layer out (D86 §2).
        layer: Some("manifest envelope"),
        committed: true,
        row: None,
        build: envelope_unknown_key,
    },
    // ── the bundle map (layer 1) ──
    FormatFixture {
        id: "bundle-duplicate-map-key",
        base: "bundle",
        mutation: "repeat the bundle's key-0 entry, bumping the map head to n+1",
        surface: Surface::SealProofDecode,
        code: "cbor-duplicate-map-key",
        layer: Some("bundle"),
        committed: true,
        row: None,
        build: bundle_duplicate_map_key,
    },
    FormatFixture {
        id: "bundle-trailing-bytes",
        base: "bundle",
        mutation: "append one byte after the outer bundle's top-level item",
        surface: Surface::SealProofDecode,
        code: "cbor-trailing-bytes",
        layer: Some("bundle"),
        committed: true,
        row: None,
        build: bundle_trailing_bytes,
    },
    FormatFixture {
        id: "bundle-reserved-key",
        base: "bundle",
        mutation: "append bundle key 10 — the named v1.1 `range_reveals` reserved slot",
        surface: Surface::SealProofDecode,
        code: "bundle-reserved-key",
        layer: Some("bundle"),
        committed: true,
        row: Some("bundle-reserved-key"),
        build: bundle_reserved_key,
    },
    FormatFixture {
        id: "bundle-unknown-key",
        base: "bundle",
        mutation: "append bundle key 24 — above the v1 band, never reserved",
        surface: Surface::SealProofDecode,
        code: "bundle-unknown-key",
        layer: Some("bundle"),
        committed: true,
        row: Some("bundle-unknown-key"),
        build: bundle_unknown_key,
    },
    // ── the embedded-manifest layer, inside a canonical layer 1 ──
    FormatFixture {
        id: "embedded-manifest-unsorted-map-keys",
        base: "bundle",
        mutation: "transpose the embedded manifest envelope's two entries, length-preserving",
        surface: Surface::SealProofDecode,
        code: "cbor-unsorted-map-keys",
        layer: Some("manifest envelope"),
        committed: true,
        row: None,
        build: embedded_manifest_unsorted_map_keys,
    },
    // ── the two size/depth mutations line 168 names ──
    FormatFixture {
        id: "bundle-oversized",
        base: "bundle",
        mutation: "zero-pad the bundle to MAX_BUNDLE_BYTES + 1 bytes",
        surface: Surface::SealProofDecode,
        code: "bundle-too-large",
        layer: Some("bundle"),
        committed: false,
        row: Some("cbor-oversized"),
        build: oversized_bundle,
    },
    FormatFixture {
        id: "body-nesting-too-deep",
        base: "manifest",
        mutation: "wrap the body in MAX_CBOR_DEPTH + 1 single-element arrays",
        surface: Surface::Canonical,
        code: "cbor-nesting-too-deep",
        layer: None,
        committed: true,
        row: Some("cbor-nesting-too-deep"),
        build: over_deep_body,
    },
];

/// Look up a fixture by id.
#[must_use]
pub fn fixture(id: &str) -> Option<&'static FormatFixture> {
    FIXTURES.iter().find(|f| f.id == id)
}

// ---------------------------------------------------------------------------
// running a fixture
// ---------------------------------------------------------------------------

/// What a surface reported for one fixture: its stable code and the layer
/// it attributed the failure to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observed {
    /// The stable machine-readable code, or `None` when the surface
    /// **accepted** the mutated bytes (always a failure for a fixture).
    pub code: Option<String>,
    /// The layer the surface attributed the failure to — `None` only for
    /// [`Surface::Canonical`], which is not a layered decoder (D86 §4.5).
    pub layer: Option<String>,
}

/// Feed `bytes` to `surface` and report the `(code, layer)` pair.
#[must_use]
pub fn run_surface(surface: Surface, bytes: &[u8]) -> Observed {
    match surface {
        Surface::Canonical => Observed {
            code: check_canonical(bytes)
                .err()
                .map(|e| DecodeError::code(&e).to_owned()),
            layer: None,
        },
        Surface::ManifestDecode => match Manifest::decode(bytes) {
            Ok(_) => Observed {
                code: None,
                layer: None,
            },
            Err(err) => Observed {
                code: Some(ManifestError::code(&err).to_owned()),
                // Total since D86: a layered decoder always reports a layer.
                layer: Some(err.layer().to_string()),
            },
        },
        Surface::SealProofDecode => match SealProof::decode(bytes) {
            Ok(_) => Observed {
                code: None,
                layer: None,
            },
            Err(err) => Observed {
                code: Some(SealProofError::code(&err).to_owned()),
                // Total since D86: a layered decoder always reports a layer.
                layer: Some(err.layer().to_string()),
            },
        },
    }
}

/// Build a fixture and run it, as the harness's [`ActualOutcome`].
///
/// A fixture whose base drifted reports a distinctive construction-failure
/// code rather than panicking — the harness turns that into a wrong-outcome
/// failure naming the row (the G19 precedent).
#[must_use]
pub fn exercise(fixture: &FormatFixture) -> ActualOutcome {
    let Some(bytes) = (fixture.build)() else {
        return ActualOutcome::ErrorCode(format!("f15-fixture-construction-failed:{}", fixture.id));
    };
    match run_surface(fixture.surface, &bytes).code {
        None => ActualOutcome::Accepted,
        Some(code) => ActualOutcome::ErrorCode(code),
    }
}

/// Exercise the fixture with this id, or report the lookup failure as an
/// outcome. Row exercises are `fn()` pointers, so each names its id here.
fn exercise_id(id: &'static str) -> ActualOutcome {
    match fixture(id) {
        Some(f) => exercise(f),
        None => ActualOutcome::ErrorCode(format!("f15-fixture-missing:{id}")),
    }
}

fn row_non_shortest_length() -> ActualOutcome {
    exercise_id("body-non-shortest-length")
}
fn row_manifest_reserved_key() -> ActualOutcome {
    exercise_id("body-reserved-key")
}
fn row_manifest_unknown_key() -> ActualOutcome {
    exercise_id("body-unknown-key")
}
fn row_bundle_reserved_key() -> ActualOutcome {
    exercise_id("bundle-reserved-key")
}
fn row_bundle_unknown_key() -> ActualOutcome {
    exercise_id("bundle-unknown-key")
}
fn row_oversized() -> ActualOutcome {
    exercise_id("bundle-oversized")
}
fn row_nesting_too_deep() -> ActualOutcome {
    exercise_id("body-nesting-too-deep")
}

// ---------------------------------------------------------------------------
// the registry slice
// ---------------------------------------------------------------------------

/// F's M0 tamper rows. Row ids are permanent handles; see the harness docs
/// ([`super::tamper`]) for the add-a-row procedure and
/// `docs/testing/error-code-contract.md` for why an expected code may never
/// be edited to make a failing run pass.
///
/// Seven rows for twenty fixtures: the module docs explain why the other
/// thirteen cannot be rows (their codes are claimed, by design, because a
/// wrapped codec rejection surfaces unchanged at every layer).
pub const ROWS: &[TamperRow] = &[
    TamperRow {
        id: "cbor-non-shortest-length",
        base: "golden-manifest-ed25519-only",
        mutation: "widen the body map's length head by one argument width",
        expected: ExpectedOutcome::ErrorCode("cbor-non-shortest-length"),
        exercise: row_non_shortest_length,
    },
    TamperRow {
        id: "manifest-reserved-key",
        base: "golden-manifest-ed25519-only",
        mutation: "append the body's first reserved key (8)",
        expected: ExpectedOutcome::ErrorCode("manifest-reserved-key"),
        exercise: row_manifest_reserved_key,
    },
    TamperRow {
        id: "manifest-unknown-key",
        base: "golden-manifest-ed25519-only",
        mutation: "append body key 24, above the v1 key band",
        expected: ExpectedOutcome::ErrorCode("manifest-unknown-key"),
        exercise: row_manifest_unknown_key,
    },
    TamperRow {
        id: "bundle-reserved-key",
        base: "golden-bundle-unanchored",
        mutation: "append bundle key 10, the named v1.1 `range_reveals` reserved slot",
        expected: ExpectedOutcome::ErrorCode("bundle-reserved-key"),
        exercise: row_bundle_reserved_key,
    },
    TamperRow {
        id: "bundle-unknown-key",
        base: "golden-bundle-unanchored",
        mutation: "append bundle key 24, above the v1 key band",
        expected: ExpectedOutcome::ErrorCode("bundle-unknown-key"),
        exercise: row_bundle_unknown_key,
    },
    TamperRow {
        id: "cbor-oversized",
        base: "golden-bundle-unanchored",
        mutation: "zero-pad the bundle to MAX_BUNDLE_BYTES + 1 bytes",
        expected: ExpectedOutcome::ErrorCode("bundle-too-large"),
        exercise: row_oversized,
    },
    TamperRow {
        id: "cbor-nesting-too-deep",
        base: "golden-manifest-ed25519-only",
        mutation: "wrap the body in MAX_CBOR_DEPTH + 1 single-element arrays",
        expected: ExpectedOutcome::ErrorCode("cbor-nesting-too-deep"),
        exercise: row_nesting_too_deep,
    },
];

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    /// Every fixture builds, and produces exactly its declared
    /// `(code, layer)` pair. This is the in-crate half of F15's accept; the
    /// committed-bytes half lives in `tests/format_tamper_fixtures.rs`,
    /// which needs file I/O.
    ///
    /// Including the oversized fixture, which allocates
    /// `MAX_BUNDLE_BYTES + 1`. That is affordable because the buffer is
    /// zeroed-on-allocation and only its first ~1 KiB is ever written, and
    /// because this module is `test-util`-gated: the `wasm32-core-tests`
    /// lane enables `test-vectors` only, so none of it reaches a target
    /// where a 256 MiB `memory.grow` would be a real commitment.
    #[test]
    fn every_fixture_produces_its_declared_code_and_layer() {
        for fixture in FIXTURES {
            let bytes = (fixture.build)()
                .unwrap_or_else(|| panic!("fixture `{}` failed to build", fixture.id));
            let observed = run_surface(fixture.surface, &bytes);
            assert_eq!(
                observed.code.as_deref(),
                Some(fixture.code),
                "fixture `{}` reported the wrong code",
                fixture.id
            );
            assert_eq!(
                observed.layer.as_deref(),
                fixture.layer,
                "fixture `{}` reported the wrong layer",
                fixture.id
            );
        }
    }

    /// F15 accept: the four spec-named body mutations are four separate
    /// fixtures with four distinct errors.
    #[test]
    fn the_four_named_body_mutations_are_four_fixtures_with_four_codes() {
        const NAMED: [&str; 4] = [
            "body-duplicate-map-key",
            "body-non-shortest-int",
            "body-indefinite-length",
            "body-trailing-bytes",
        ];
        let mut codes = BTreeSet::new();
        for id in NAMED {
            let f = fixture(id).unwrap_or_else(|| panic!("no fixture `{id}`"));
            assert_eq!(
                f.layer,
                Some("manifest body"),
                "`{id}` must fail at the body layer, not the envelope"
            );
            assert!(codes.insert(f.code), "`{id}` shares a code with a sibling");
        }
        assert_eq!(codes.len(), 4);
    }

    /// F15 accept: `oversized != over-deep`. They are different mutations,
    /// different surfaces and different codes — the pairing the spec names
    /// as one family but requires two errors for.
    #[test]
    fn oversized_and_over_deep_are_two_fixtures_with_two_errors() {
        let over = fixture("bundle-oversized").expect("oversized fixture");
        let deep = fixture("body-nesting-too-deep").expect("over-deep fixture");
        assert_ne!(over.code, deep.code);
        assert_ne!(over.surface, deep.surface);
        assert_eq!(over.code, "bundle-too-large");
        assert_eq!(deep.code, "cbor-nesting-too-deep");
    }

    /// Fixture ids and committed-file stems are unique, and every fixture
    /// that names a row names one this slice actually registers.
    #[test]
    fn fixture_ids_are_unique_and_rows_resolve() {
        let ids: BTreeSet<&str> = FIXTURES.iter().map(|f| f.id).collect();
        assert_eq!(ids.len(), FIXTURES.len(), "duplicate fixture id");
        let rows: BTreeSet<&str> = ROWS.iter().map(|r| r.id).collect();
        assert_eq!(rows.len(), ROWS.len(), "duplicate row id");
        for fixture in FIXTURES {
            if let Some(row_id) = fixture.row {
                // A fixture may point at a Q7 seed row that lives in the
                // integration target, so membership of this slice is not
                // required — but if the id IS ours, its code must agree.
                if let Some(row) = ROWS.iter().find(|r| r.id == row_id) {
                    assert_eq!(
                        row.expected,
                        ExpectedOutcome::ErrorCode(fixture.code),
                        "fixture `{}` and row `{row_id}` disagree about the code",
                        fixture.id
                    );
                }
            }
        }
    }

    /// Every row this slice registers is backed by a fixture, so a row can
    /// never assert something the committed fixture set does not show.
    #[test]
    fn every_row_is_backed_by_a_fixture() {
        for row in ROWS {
            let backing = FIXTURES
                .iter()
                .find(|f| f.row == Some(row.id))
                .unwrap_or_else(|| panic!("row `{}` has no backing fixture", row.id));
            assert_eq!(backing.row, Some(row.id));
        }
    }

    /// The two bases are the artifacts the module claims they are: real
    /// sealed bytes that decode cleanly. (Byte-equality with the committed
    /// golden vectors is asserted natively, where the vector files can be
    /// read.)
    #[test]
    fn the_bases_decode() {
        let manifest = base_manifest();
        assert!(Manifest::decode(&manifest).is_ok(), "base manifest decodes");
        let bundle = base_bundle();
        assert!(SealProof::decode(&bundle).is_ok(), "base bundle decodes");
        let body = base_body().expect("base body");
        assert!(!body.is_empty());
        // The body really is the envelope's embedded bstr contents.
        assert!(
            manifest
                .windows(body.len())
                .any(|window| window == body.as_slice())
        );
    }

    /// The splicing primitives are exact: re-heading a map with its own
    /// entry count and entries reproduces the input byte for byte.
    #[test]
    fn rehead_round_trips_the_base_body() {
        let body = base_body().expect("base body");
        let (head_len, count) = map_head(&body).expect("body is a canonical map");
        let rest = body.get(head_len..).expect("body has entries");
        assert_eq!(rehead(count, &[rest]), body);
        // And the widened head is a genuine one-width-wider re-encoding.
        let widened = widen_head(&body).expect("widen");
        assert_eq!(widened.len(), body.len() + 1);
        assert_eq!(
            check_canonical(&widened),
            Err(DecodeError::NonShortestLength { position: 0 })
        );
    }

    /// The embedded-manifest fixture must be length-preserving, or it would
    /// be two mutations (the swap *and* a rewritten `bstr` head) and its
    /// claim about layer 1 staying canonical would be false.
    #[test]
    fn the_embedded_manifest_fixture_is_length_preserving() {
        let base = base_bundle();
        let mutated =
            embedded_manifest_unsorted_map_keys().expect("embedded-manifest fixture builds");
        assert_eq!(mutated.len(), base.len());
        assert_eq!(
            mutated
                .iter()
                .zip(&base)
                .filter(|(a, b)| a != b)
                .count()
                .min(1),
            1,
            "the fixture must actually differ from its base"
        );
    }
}
