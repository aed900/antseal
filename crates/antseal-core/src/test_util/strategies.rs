//! Shared proptest strategies + the deterministic config builder (Q3).
//!
//! Conventions these implement: `docs/testing/proptest-conventions.md`.
//! Domains (F/C/G/S/A/R) import from here instead of redefining
//! work-shaped generators, so structural invariants (e.g. "unit ranges
//! exactly tile `[0, size)`", MVP-SPEC.md line 121) are generated the same
//! way everywhere.
//!
//! Values produced by these strategies exist only in test memory — the
//! committed-fixture secret-material convention (`testdata/README.md`)
//! does not restrict them; anything *committed* must derive from
//! [`super::TEST_MASTER_SECRET_W`].

use core::ops::Range;

use proptest::prelude::*;
use proptest::test_runner::{FileFailurePersistence, RngSeed};

/// The project-standard proptest configuration (Q3):
///
/// - **deterministic**: the RNG seed is fixed per `proptest!` block —
///   every test picks its own stable literal, so CI failures reproduce
///   exactly and case exploration never depends on the runner;
/// - **environment-tunable case counts**: everything else starts from
///   [`ProptestConfig::default()`], which honours proptest's own
///   environment overrides — CI raises `PROPTEST_CASES` (set in the `test`
///   lane), local runs use the default, and tests with spec-mandated
///   floors (e.g. C3's ≥10 000) hardcode `cases` on top of this builder.
///
/// ```rust
/// use antseal_core::test_util::proptest::prelude::*;
/// use antseal_core::test_util::strategies;
///
/// proptest! {
///     #![proptest_config(strategies::proptest_config(0x5EED_0001))]
///     #[test]
///     fn doubling_is_even(n in 0u32..1000) {
///         prop_assert_eq!((n * 2) % 2, 0);
///     }
/// }
/// ```
#[must_use]
pub fn proptest_config(rng_seed: u64) -> ProptestConfig {
    ProptestConfig {
        rng_seed: RngSeed::Fixed(rng_seed),
        ..ProptestConfig::default()
    }
}

/// [`proptest_config`] for a property suite living in `tests/` — an
/// **integration test** — with failure persistence that actually works
/// there (Q3 §5: regressions files are committed and never deleted).
///
/// # Why integration tests need this
///
/// proptest's default persistence is
/// `FileFailurePersistence::SourceParallel("proptest-regressions")`, which
/// walks *up* from the test's source file looking for a directory holding
/// `lib.rs` or `main.rs`. That works for `#[cfg(test)]` blocks inside
/// `src/`, but an integration test in `tests/` has no such ancestor: the
/// lookup fails, proptest prints
///
/// ```text
/// proptest: FileFailurePersistence::SourceParallel set, but failed to find lib.rs or main.rs
/// ```
///
/// and — having no source file configured either — **persists nothing**. A
/// failure found in CI would then be unreproducible locally, which is
/// exactly what Q3 §5 exists to prevent.
///
/// Passing the path explicitly (`Direct`) fixes it. `cargo test` runs with
/// the package root as the working directory, so a relative path lands at
/// `crates/<crate>/proptest-regressions/<name>.txt` — the same place
/// `SourceParallel` would have chosen for an in-`src` test, and the
/// location Q3 documents.
///
/// ```rust
/// use antseal_core::test_util::proptest::prelude::*;
/// use antseal_core::test_util::strategies;
///
/// proptest! {
///     #![proptest_config(strategies::integration_test_config(
///         0x5EED_0003,
///         "proptest-regressions/my_suite.txt",
///     ))]
///     #[test]
///     fn tripling_is_divisible_by_three(n in 0u32..1000) {
///         prop_assert_eq!((n * 3) % 3, 0);
///     }
/// }
/// ```
///
/// `regressions_file` must be `'static` (proptest's API) and should be
/// `proptest-regressions/<test-file-stem>.txt`, matching the test file it
/// belongs to.
#[must_use]
pub fn integration_test_config(rng_seed: u64, regressions_file: &'static str) -> ProptestConfig {
    ProptestConfig {
        failure_persistence: Some(Box::new(FileFailurePersistence::Direct(regressions_file))),
        ..proptest_config(rng_seed)
    }
}

/// A work-shaped unit tiling: `ranges` are sorted, non-overlapping,
/// contiguous byte ranges exactly tiling `[0, total_size)` — the verifier
/// structural invariant for non-mirror units (MVP-SPEC.md line 121). The
/// empty-work case is one empty unit (`0..0`, spec line 78).
///
/// `unit_id`s are the range indices in order (work-global manifest-order
/// ordinals, spec line 76).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnitTiling {
    /// Total tiled size in bytes (0 for the empty work).
    pub total_size: u64,
    /// The tiling ranges, in order; never empty.
    pub ranges: Vec<Range<u64>>,
}

/// Strategy for [`UnitTiling`]: 1..=`max_units` units of 1..=`max_unit_len`
/// bytes each (plus the occasional empty-work case). Both bounds must be
/// ≥ 1 and small enough that the total cannot overflow `u64` (test-util
/// contract; violations abort the strategy loudly rather than generating
/// nonsense).
pub fn unit_tiling(max_units: usize, max_unit_len: u64) -> impl Strategy<Value = UnitTiling> {
    assert!(max_units >= 1, "unit_tiling: max_units must be >= 1");
    assert!(max_unit_len >= 1, "unit_tiling: max_unit_len must be >= 1");
    let tiled = proptest::collection::vec(1..=max_unit_len, 1..=max_units).prop_map(|lens| {
        let mut ranges = Vec::with_capacity(lens.len());
        let mut offset: u64 = 0;
        for len in lens {
            let end = offset
                .checked_add(len)
                .expect("unit_tiling bounds must not overflow u64");
            ranges.push(offset..end);
            offset = end;
        }
        UnitTiling {
            total_size: offset,
            ranges,
        }
    });
    // (`once(..).collect()` rather than `vec![0..0]`: the literal one-empty-
    // range Vec is exactly what the empty work means — one empty unit.)
    let empty_work = UnitTiling {
        total_size: 0,
        ranges: core::iter::once(0..0).collect(),
    };
    prop_oneof![
        // Empty work: one empty unit (MVP-SPEC.md line 78).
        1 => Just(empty_work),
        9 => tiled,
    ]
}

// ===========================================================================
// F16: schema-valid manifest/bundle generators, and the reduced-cap profile
// ===========================================================================

/// **The test-only reduced-cap profile** (F16; flagged by decision D10 §5,
/// consequence 5).
///
/// Generating at the production caps is not viable in a property corpus:
/// `MAX_UNIT_COUNT` is 65 536 and `MAX_BUNDLE_BYTES` is 256 MiB, so a single
/// worst case would dwarf a whole run. F16 therefore generates against these
/// reduced bounds and leaves the real caps to F11's dedicated at-cap/cap+1
/// matrix (`tests/parser_caps.rs`), which exercises each boundary exactly
/// once instead of thousands of times.
///
/// # Why it cannot leak into a production path
///
/// This is a **generation** bound, not an enforcement bound. Nothing in
/// `codec::caps` — the module the decoders consult — knows this type exists;
/// there is no setter, no `cfg` switch, no global, and no code path by which a
/// decoder could read a reduced value. A production decoder therefore enforces
/// D10's frozen numbers no matter what a test generates, which is the property
/// D10 §11 requires ("no local override exists, and none should be added": a
/// per-verifier cap knob would let the CLI and the WASM page disagree about
/// whether a bundle is valid).
///
/// The module is additionally behind the `test-util` feature, which no
/// production build enables and which may never be turned on over a normal
/// dependency edge.
///
/// Every field is asserted `<=` its production counterpart by
/// [`GenCaps::assert_within_production_caps`], so the profile can never drift
/// *above* an enforced cap and start generating inputs the decoder refuses —
/// which would turn a round-trip property into a silent no-op.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GenCaps {
    /// Upper bound on generated files per body (production: 16 384).
    pub max_files: usize,
    /// Upper bound on generated units per file (production: 65 536,
    /// work-global).
    pub max_units_per_file: usize,
    /// Upper bound on generated anchors per section (production: 256).
    pub max_anchors: usize,
    /// Upper bound on generated `intermediates` (production: 16).
    pub max_intermediates: usize,
    /// Upper bound on generated `tx_hashes` (production: 256).
    pub max_tx_hashes: usize,
    /// Upper bound on generated cover entries / path nodes per covered
    /// reveal (production: 256 each).
    pub max_cover_or_path: usize,
    /// Upper bound on generated opaque-artifact byte lengths (production:
    /// 64 KiB–16 MiB depending on the field).
    pub max_artifact_bytes: usize,
    /// Upper bound on generated free-form text lengths.
    pub max_text_len: usize,
}

impl Default for GenCaps {
    fn default() -> Self {
        Self::PROFILE
    }
}

impl GenCaps {
    /// The profile F16's suites use. Sized so a worst-case generated bundle
    /// stays in the low hundreds of kilobytes: with proptest running 256–1024
    /// cases per property, per-case cost is the binding constraint, and
    /// structural variety matters far more than magnitude for the properties
    /// F16 states (round-trip, determinism, canonicality).
    pub const PROFILE: Self = Self {
        max_files: 4,
        max_units_per_file: 4,
        max_anchors: 3,
        max_intermediates: 3,
        max_tx_hashes: 3,
        max_cover_or_path: 4,
        max_artifact_bytes: 64,
        max_text_len: 16,
    };

    /// Every generated bound sits at or under the D10-frozen production cap.
    ///
    /// The direction matters: a profile *above* an enforced cap would generate
    /// inputs the decoder rejects, and every round-trip property would then
    /// pass vacuously on the rejection instead of exercising the codec.
    ///
    /// # Panics
    ///
    /// If any field exceeds its production counterpart.
    pub fn assert_within_production_caps(self) {
        use crate::codec::caps;
        let rows: [(&str, u64, u64); 8] = [
            ("max_files", self.max_files as u64, caps::MAX_FILE_COUNT),
            (
                "max_units_per_file",
                self.max_units_per_file as u64,
                caps::MAX_UNIT_COUNT,
            ),
            (
                "max_anchors",
                self.max_anchors as u64,
                caps::MAX_OTS_ANCHOR_COUNT.min(caps::MAX_TSA_ANCHOR_COUNT),
            ),
            (
                "max_intermediates",
                self.max_intermediates as u64,
                caps::MAX_INTERMEDIATE_COUNT,
            ),
            (
                "max_tx_hashes",
                self.max_tx_hashes as u64,
                caps::MAX_TX_HASH_COUNT,
            ),
            (
                "max_cover_or_path",
                self.max_cover_or_path as u64,
                caps::MAX_COVER_ENTRIES.min(caps::MAX_PATH_NODES),
            ),
            (
                "max_artifact_bytes",
                self.max_artifact_bytes as u64,
                caps::MAX_CERT_BYTES,
            ),
            (
                "max_text_len",
                self.max_text_len as u64,
                caps::MAX_MANIFEST_BYTES,
            ),
        ];
        for (name, generated, production) in rows {
            assert!(
                generated <= production,
                "GenCaps::{name} = {generated} exceeds the production cap {production}: \
                 the corpus would generate inputs the decoder refuses, and every \
                 round-trip property would pass vacuously"
            );
        }
        // The work-global unit budget must also admit the worst generated body.
        let worst = (self.max_files * self.max_units_per_file) as u64;
        assert!(
            worst <= caps::MAX_UNIT_COUNT,
            "GenCaps: max_files * max_units_per_file = {worst} exceeds the \
             work-global MAX_UNIT_COUNT of {}",
            caps::MAX_UNIT_COUNT
        );
    }
}

// ---------------------------------------------------------------------------
// Schema-valid manifest generators (F16)
// ---------------------------------------------------------------------------

use crate::crypto::disclosure::UnitBinding;
use crate::crypto::error::SigAlg;
use crate::crypto::secrets::SealId;
use crate::manifest::registry::{pubkey_len, sig_len};
use crate::manifest::{
    ByteRange, CanonMode, ContentAddress, FileEntry, FineTree, ManifestBodyV1, Nonce24, SigAlgMap,
    SigMaterial, UnitEntry, UnitKind, encode_body, encode_envelope,
};

/// A 32-byte commitment-shaped value from a single seed byte. Fixture
/// material only: distinctness, not entropy, is what the codec cares about
/// (project rule 6 — no real secret ever reaches a generator).
fn digest32(seed: u8) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = seed.wrapping_add(i as u8);
    }
    out
}

/// One schema-valid unit entry.
///
/// `binding` is forced to agree with the file's fine-tree state and the
/// unit's kind, because `FileEntry::new` enforces that agreement — a
/// generator that ignored it would spend the whole corpus on rejections
/// instead of on round-trips.
fn arb_unit(kind: UnitKind, covered: bool) -> impl Strategy<Value = UnitEntry> {
    (0u64..1_000_000, 0u64..4096, any::<u8>()).prop_map(move |(start, length, seed)| {
        let binding = if covered {
            UnitBinding::FineTreeCovered
        } else {
            UnitBinding::NonCovered {
                unit_commit: digest32(seed),
            }
        };
        UnitEntry::new(
            // Ids are assigned work-globally by `renumber_units`; any value
            // here would be overwritten, so 0 is as good as random.
            0,
            kind,
            ByteRange::new(start, length),
            length,
            binding,
            Nonce24::from_bytes([seed; 24]),
            ContentAddress::from_bytes(digest32(seed ^ 0x5A)),
        )
    })
}

/// One schema-valid file entry (unit ids are fixed up later).
///
/// Covers the shapes the format admits: binary/text × fine-tree/no-fine-tree,
/// plus the raw mirror only a text file may carry. **D77 holds by
/// construction** — the normal-unit list is never empty, so a mirror is only
/// ever appended alongside real normal units and a mirror-only file is
/// ungeneratable.
pub fn arb_file(caps: GenCaps) -> impl Strategy<Value = FileEntry> {
    (
        any::<bool>(), // text?
        any::<bool>(), // fine tree?
        any::<bool>(), // raw mirror? (text only)
        any::<u8>(),
        0u64..1_000_000,
    )
        .prop_flat_map(move |(text, fine_tree, mirror, seed, size)| {
            let mirror = mirror && text;
            let normal = proptest::collection::vec(
                arb_unit(UnitKind::Normal, fine_tree),
                1..=caps.max_units_per_file,
            );
            // A mirror lives in the *raw* byte domain the canonical fine tree
            // does not cover, so it is never fine-tree-covered (spec line 92).
            let mirror_unit = proptest::collection::vec(
                arb_unit(UnitKind::RawMirror, false),
                usize::from(mirror)..=usize::from(mirror),
            );
            (normal, mirror_unit).prop_map(move |(mut list, mut mirror_unit)| {
                // D23: the mirror is the file's LAST unit.
                list.append(&mut mirror_unit);
                let canon = if text {
                    CanonMode::Text {
                        canon_commit: digest32(seed ^ 0x11),
                        unicode_version: "unicode-17.0.0".to_owned(),
                    }
                } else {
                    CanonMode::Binary
                };
                let tree = if fine_tree {
                    FineTree::Present {
                        root: digest32(seed ^ 0x22),
                    }
                } else {
                    FineTree::Absent
                };
                FileEntry::new(
                    digest32(seed),
                    digest32(seed ^ 0x33),
                    canon,
                    size,
                    tree,
                    list,
                )
                .expect("arb_file must generate schema-valid entries")
            })
        })
}

/// A schema-valid manifest body, bounded by [`GenCaps`].
pub fn arb_manifest_body(caps: GenCaps) -> impl Strategy<Value = ManifestBodyV1> {
    (
        ".{0,16}",
        ".{0,16}",
        any::<u64>(),
        any::<u8>(),
        any::<bool>(),
        proptest::collection::vec(arb_file(caps), 1..=caps.max_files),
    )
        .prop_map(|(app_version, title, claimed_time, seed, hybrid, files)| {
            let sig_policy = if hybrid {
                vec![SigAlg::Ed25519, SigAlg::MlDsa65]
            } else {
                vec![SigAlg::Ed25519]
            };
            ManifestBodyV1::new(
                app_version,
                SealId::from_bytes([seed; 16]),
                title,
                claimed_time,
                pubkeys_for(&sig_policy),
                sig_policy,
                renumber_units(files),
            )
            .expect("arb_manifest_body must generate schema-valid bodies")
        })
}

/// Rewrite every unit's id to its **work-global manifest-order ordinal**,
/// which is what `ManifestBodyV1::new` enforces (registry §7.5 key 0). Done
/// after generation rather than during it so the per-file strategy stays
/// independent and shrinks cleanly.
fn renumber_units(files: Vec<FileEntry>) -> Vec<FileEntry> {
    let mut next: u64 = 0;
    files
        .into_iter()
        .map(|file| {
            let units: Vec<UnitEntry> = file
                .units()
                .iter()
                .map(|u| {
                    let renumbered = UnitEntry::new(
                        next,
                        u.kind(),
                        u.range(),
                        u.true_length(),
                        *u.binding(),
                        *u.nonce(),
                        *u.address(),
                    );
                    next += 1;
                    renumbered
                })
                .collect();
            FileEntry::new(
                *file.path_commit(),
                *file.raw_commit(),
                file.canon().clone(),
                file.size(),
                file.fine_tree(),
                units,
            )
            .expect("renumbering preserves schema validity")
        })
        .collect()
}

/// Schema-correct dummy public keys for a policy. Published filler bytes of
/// the registry-mandated lengths — never real key material (project rule 6).
fn pubkeys_for(policy: &[SigAlg]) -> SigAlgMap {
    let entries = policy
        .iter()
        .map(|alg| (*alg, vec![0xA5u8; pubkey_len(*alg) as usize]));
    SigAlgMap::new(SigMaterial::Pubkey, entries).expect("policy is non-empty and duplicate-free")
}

/// Schema-correct dummy signatures for a policy.
fn signatures_for(policy: &[SigAlg]) -> SigAlgMap {
    let entries = policy
        .iter()
        .map(|alg| (*alg, vec![0x5Au8; sig_len(*alg) as usize]));
    SigAlgMap::new(SigMaterial::Signature, entries).expect("policy is non-empty and duplicate-free")
}

/// A canonical, schema-valid **manifest envelope** as encoded bytes, together
/// with the body bytes it embeds.
///
/// Both are returned because F16's mutation properties need to reach layer 3
/// (the body) as well as layer 2 (the envelope): mutating body bytes and
/// re-wrapping is the only way to make an inner-layer rejection observable
/// through `Manifest::decode`, since an embedded `bstr` is opaque to the outer
/// pass by design (spec line 74).
pub fn arb_manifest_bytes(caps: GenCaps) -> impl Strategy<Value = (Vec<u8>, Vec<u8>)> {
    arb_manifest_body(caps).prop_map(|body| {
        let policy: Vec<SigAlg> = body.sig_policy().to_vec();
        let body_bytes = encode_body(body).expect("a schema-valid body encodes");
        let envelope = encode_envelope(&body_bytes, &signatures_for(&policy))
            .expect("an envelope over valid parts encodes");
        (envelope, body_bytes)
    })
}

/// A deterministic, canonical `(envelope, body)` byte pair rich enough for the
/// F16 **coverage sweep** to find a site for every mutation class.
///
/// Deliberately not a strategy: the coverage assertion must not depend on
/// what a random corpus happened to generate, or a class could silently go
/// untested on a lucky run. The shape is chosen to contain, at minimum, a map
/// with >= 2 entries (key reorder / duplicate key), a non-empty `tstr`
/// (invalid UTF-8), a small uint (int widening), a short `bstr` (length-head
/// widening) and a non-empty array (indefinite rewrite).
#[must_use]
pub fn canonical_manifest_pair() -> (Vec<u8>, Vec<u8>) {
    let sig_policy = vec![SigAlg::Ed25519, SigAlg::MlDsa65];
    let units = vec![UnitEntry::new(
        0,
        UnitKind::Normal,
        ByteRange::new(0, 7),
        7,
        UnitBinding::NonCovered {
            unit_commit: digest32(0x11),
        },
        Nonce24::from_bytes([0x22; 24]),
        ContentAddress::from_bytes(digest32(0x33)),
    )];
    let file = FileEntry::new(
        digest32(0x44),
        digest32(0x55),
        CanonMode::Text {
            canon_commit: digest32(0x66),
            unicode_version: "unicode-17.0.0".to_owned(),
        },
        7,
        FineTree::Absent,
        units,
    )
    .expect("the coverage fixture is schema-valid");
    let body = ManifestBodyV1::new(
        "antseal-test".to_owned(),
        SealId::from_bytes([0x77; 16]),
        "coverage fixture".to_owned(),
        1_700_000_000,
        pubkeys_for(&sig_policy),
        sig_policy.clone(),
        vec![file],
    )
    .expect("the coverage fixture is schema-valid");
    let body_bytes = encode_body(body).expect("encodes");
    let envelope = encode_envelope(&body_bytes, &signatures_for(&sig_policy)).expect("encodes");
    (envelope, body_bytes)
}

/// Re-wrap `body_bytes` in a canonical envelope. Used by the mutation
/// properties to make a layer-3 rejection reachable through the public
/// `Manifest::decode` entry point.
#[must_use]
pub fn envelope_around(body_bytes: &[u8]) -> Vec<u8> {
    encode_envelope(body_bytes, &signatures_for(&[SigAlg::Ed25519]))
        .expect("the envelope shape is fixed and always encodes")
}

// ---------------------------------------------------------------------------
// Canonicality mutations over encoded bytes (F16)
// ---------------------------------------------------------------------------

/// One CBOR item located inside a canonical encoding, as a byte span plus the
/// spans of its children.
///
/// Only ever built from bytes this crate's own encoder produced, so the walk
/// can assume canonical, definite-length, shortest-form input — this is a
/// *mutation aid*, deliberately not a second parser, and nothing security-
/// relevant may be built on it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ItemSpan {
    /// Offset of the item's head byte.
    pub start: usize,
    /// Length of the head (1, 2, 3, 5 or 9 bytes).
    pub head_len: usize,
    /// One past the item's last byte.
    pub end: usize,
    /// CBOR major type, 0..=7.
    pub major: u8,
    /// The head's argument: the value for integers, the length or element
    /// count otherwise.
    pub arg: u64,
    /// Child items: array elements, or a map's alternating key/value items.
    pub children: Vec<ItemSpan>,
}

impl ItemSpan {
    /// This item and every item nested inside it, outermost first.
    #[must_use]
    pub fn flatten(&self) -> Vec<&Self> {
        let mut out = vec![self];
        for child in &self.children {
            out.extend(child.flatten());
        }
        out
    }
}

/// Walk one canonical CBOR item starting at `at`.
///
/// Returns `None` on anything the walk does not understand, so a caller can
/// never be handed a bogus span; every caller treats `None` as "skip this
/// mutation", never as a test failure.
#[must_use]
pub fn scan_item(bytes: &[u8], at: usize) -> Option<ItemSpan> {
    let initial = *bytes.get(at)?;
    let major = initial >> 5;
    let ai = initial & 0x1f;
    let (arg, head_len) = match ai {
        0..=23 => (u64::from(ai), 1),
        24 => (u64::from(*bytes.get(at + 1)?), 2),
        25 => (
            u64::from(u16::from_be_bytes(
                bytes.get(at + 1..at + 3)?.try_into().ok()?,
            )),
            3,
        ),
        26 => (
            u64::from(u32::from_be_bytes(
                bytes.get(at + 1..at + 5)?.try_into().ok()?,
            )),
            5,
        ),
        27 => (
            u64::from_be_bytes(bytes.get(at + 1..at + 9)?.try_into().ok()?),
            9,
        ),
        _ => return None, // indefinite / reserved: not producible by F2
    };
    let payload = at + head_len;
    let (end, children) = match major {
        0 | 1 => (payload, Vec::new()),
        2 | 3 => (payload.checked_add(usize::try_from(arg).ok()?)?, Vec::new()),
        4 | 5 => {
            // A map's `arg` counts entries; each entry is two items.
            let items = if major == 5 { arg.checked_mul(2)? } else { arg };
            let mut cursor = payload;
            let mut children = Vec::new();
            for _ in 0..items {
                let child = scan_item(bytes, cursor)?;
                cursor = child.end;
                children.push(child);
            }
            (cursor, children)
        }
        _ => return None, // major 7: not producible by F2
    };
    if end > bytes.len() {
        return None;
    }
    Some(ItemSpan {
        start: at,
        head_len,
        end,
        major,
        arg,
        children,
    })
}

/// The canonicality classes F16's mutations target.
///
/// This is the enumeration the **coverage assertion** runs over: every line-73
/// rejection class reachable by mutating a canonical encoding must be hit at
/// least once across the corpus (tasks/F.md F16 accept).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MutationKind {
    /// A shortest-form integer head rewritten wide → `cbor-non-shortest-int`.
    IntWidening,
    /// A shortest-form *length* head rewritten wide →
    /// `cbor-non-shortest-length`.
    LengthHeadWidening,
    /// Two adjacent map entries swapped → `cbor-unsorted-map-keys`.
    KeyReorder,
    /// A map entry duplicated → `cbor-duplicate-map-key`.
    DuplicateKey,
    /// A definite container head rewritten indefinite →
    /// `cbor-indefinite-length`.
    IndefiniteLength,
    /// A byte appended after the top-level item → `cbor-trailing-bytes`.
    TrailingByte,
    /// An item replaced by a half-float → `cbor-float`.
    FloatSubstitution,
    /// An item replaced by `null` → `cbor-simple-value`.
    SimpleSubstitution,
    /// An item replaced by a tagged item → `cbor-tag`.
    TagSubstitution,
    /// A `tstr` payload byte replaced by an invalid UTF-8 byte →
    /// `cbor-invalid-utf8`.
    InvalidUtf8,
    /// The encoding truncated → `cbor-truncated`.
    Truncation,
    /// An item replaced by an empty array where the schema wants a scalar →
    /// `cbor-unexpected-type`. This is the class decision D10 §6 identified:
    /// because every v1 field has a fixed type, nesting a container where a
    /// scalar belongs is caught at level 1 as a *type* error and can never
    /// become `cbor-nesting-too-deep`.
    TypeSubstitution,
}

impl MutationKind {
    /// Every mutation class, for the coverage assertion.
    pub const ALL: [Self; 12] = [
        Self::IntWidening,
        Self::LengthHeadWidening,
        Self::KeyReorder,
        Self::DuplicateKey,
        Self::IndefiniteLength,
        Self::TrailingByte,
        Self::FloatSubstitution,
        Self::SimpleSubstitution,
        Self::TagSubstitution,
        Self::InvalidUtf8,
        Self::Truncation,
        Self::TypeSubstitution,
    ];

    /// The `cbor-*` code this mutation must produce.
    ///
    /// One expected code per class is what makes "always fail with the
    /// correct error class" a checkable statement rather than "fails
    /// somehow".
    #[must_use]
    pub const fn expected_code(self) -> &'static str {
        match self {
            Self::IntWidening => "cbor-non-shortest-int",
            Self::LengthHeadWidening => "cbor-non-shortest-length",
            Self::KeyReorder => "cbor-unsorted-map-keys",
            Self::DuplicateKey => "cbor-duplicate-map-key",
            Self::IndefiniteLength => "cbor-indefinite-length",
            Self::TrailingByte => "cbor-trailing-bytes",
            Self::FloatSubstitution => "cbor-float",
            Self::SimpleSubstitution => "cbor-simple-value",
            Self::TagSubstitution => "cbor-tag",
            Self::InvalidUtf8 => "cbor-invalid-utf8",
            Self::Truncation => "cbor-truncated",
            Self::TypeSubstitution => "cbor-unexpected-type",
        }
    }
}

/// Apply `kind` to `bytes`, choosing among the eligible sites with `pick`.
///
/// Returns `None` when the encoding offers no site for that mutation — for
/// example `KeyReorder` on bytes containing no map with two entries. A `None`
/// is a *skip*, never a failure: the corpus is wide enough that every class
/// finds its sites, and the coverage assertion is what proves it did.
#[must_use]
pub fn mutate(bytes: &[u8], kind: MutationKind, pick: usize) -> Option<Vec<u8>> {
    let root = scan_item(bytes, 0)?;
    let items = root.flatten();
    let choose = |candidates: Vec<&ItemSpan>| -> Option<ItemSpan> {
        if candidates.is_empty() {
            None
        } else {
            Some(candidates[pick % candidates.len()].clone())
        }
    };

    match kind {
        MutationKind::TrailingByte => {
            let mut out = bytes.to_vec();
            out.push(0x00);
            Some(out)
        }
        MutationKind::Truncation => {
            if bytes.len() < 2 {
                return None;
            }
            Some(bytes[..bytes.len() - 1].to_vec())
        }
        // Widening an integer head and widening a *length* head are the same
        // byte rewrite on different major types, and they carry different
        // codes — which is exactly why F3 keeps them apart.
        MutationKind::IntWidening | MutationKind::LengthHeadWidening => {
            let wanted: &[u8] = if kind == MutationKind::IntWidening {
                &[0, 1]
            } else {
                &[2, 3, 4, 5]
            };
            let item = choose(
                items
                    .iter()
                    .copied()
                    .filter(|i| wanted.contains(&i.major) && i.head_len == 1 && i.arg < 24)
                    .collect(),
            )?;
            let mut out = Vec::with_capacity(bytes.len() + 1);
            out.extend_from_slice(&bytes[..item.start]);
            out.push((item.major << 5) | 24);
            out.push(item.arg as u8);
            out.extend_from_slice(&bytes[item.start + 1..]);
            Some(out)
        }
        MutationKind::IndefiniteLength => {
            let item = choose(
                items
                    .iter()
                    .copied()
                    .filter(|i| (i.major == 4 || i.major == 5) && i.arg > 0)
                    .collect(),
            )?;
            let mut out = Vec::with_capacity(bytes.len() + 2);
            out.extend_from_slice(&bytes[..item.start]);
            out.push(if item.major == 4 { 0x9f } else { 0xbf });
            out.extend_from_slice(&bytes[item.start + item.head_len..item.end]);
            out.push(0xff); // break
            out.extend_from_slice(&bytes[item.end..]);
            Some(out)
        }
        MutationKind::KeyReorder => {
            let item = choose(
                items
                    .iter()
                    .copied()
                    .filter(|i| i.major == 5 && i.arg >= 2)
                    .collect(),
            )?;
            // Swap entries 0 and 1: keys stay unique, so the map is
            // *unsorted* rather than duplicated — two distinct codes.
            let (k0, v0) = (&item.children[0], &item.children[1]);
            let (k1, v1) = (&item.children[2], &item.children[3]);
            let mut out = Vec::with_capacity(bytes.len());
            out.extend_from_slice(&bytes[..k0.start]);
            out.extend_from_slice(&bytes[k1.start..v1.end]);
            out.extend_from_slice(&bytes[k0.start..v0.end]);
            out.extend_from_slice(&bytes[v1.end..]);
            Some(out)
        }
        MutationKind::DuplicateKey => {
            let item = choose(
                items
                    .iter()
                    .copied()
                    .filter(|i| i.major == 5 && i.arg >= 1 && i.arg < 23)
                    .collect(),
            )?;
            let (k0, v0) = (&item.children[0], &item.children[1]);
            let mut out = Vec::with_capacity(bytes.len() + (v0.end - k0.start) + 1);
            out.extend_from_slice(&bytes[..item.start]);
            // The head stays one byte because `arg < 23`, so no other offset
            // shifts and the map is exactly "one entry repeated".
            out.push((5 << 5) | (item.arg as u8 + 1));
            out.extend_from_slice(&bytes[k0.start..v0.end]);
            out.extend_from_slice(&bytes[k0.start..]);
            Some(out)
        }
        MutationKind::FloatSubstitution
        | MutationKind::SimpleSubstitution
        | MutationKind::TagSubstitution
        | MutationKind::TypeSubstitution => {
            // Replace one *non-root* item's whole span. Definite containers
            // count items, not bytes, so swapping one item for another of a
            // different length keeps every enclosing head correct.
            let replacement: &[u8] = match kind {
                MutationKind::FloatSubstitution => &[0xf9, 0x3c, 0x00], // half 1.0
                MutationKind::SimpleSubstitution => &[0xf6],            // null
                MutationKind::TagSubstitution => &[0xc2, 0x41, 0x01],   // tag 2 (bignum)
                _ => &[0x80],                                           // empty array
            };
            let candidates: Vec<&ItemSpan> = items
                .iter()
                .copied()
                .filter(|i| {
                    // Never the root (a replaced root is a different test),
                    // and for the type substitution never an item that is
                    // already an array — that would be a no-op in kind.
                    i.start != root.start
                        && !(kind == MutationKind::TypeSubstitution && i.major == 4)
                })
                .collect();
            let item = choose(candidates)?;
            let mut out = Vec::with_capacity(bytes.len() + replacement.len());
            out.extend_from_slice(&bytes[..item.start]);
            out.extend_from_slice(replacement);
            out.extend_from_slice(&bytes[item.end..]);
            Some(out)
        }
        MutationKind::InvalidUtf8 => {
            let item = choose(
                items
                    .iter()
                    .copied()
                    .filter(|i| i.major == 3 && i.arg > 0)
                    .collect(),
            )?;
            let mut out = bytes.to_vec();
            // 0xFF is never a valid UTF-8 byte in any position.
            out[item.start + item.head_len] = 0xff;
            Some(out)
        }
    }
}

// ---------------------------------------------------------------------------
// Schema-valid bundle generators (F16)
// ---------------------------------------------------------------------------

/// Arbitrary **schema-valid `.sealproof` bytes**, bounded by [`GenCaps`].
///
/// Built through R6's fixture constructor rather than by assembling
/// `BundleParts` here, deliberately: R6 already establishes every invariant a
/// bundle must satisfy to exist (ascending ids per section, no unit revealed
/// twice, no full reveal without a touched file, D28's full-reveal material),
/// and it is the substrate the tamper and vector lanes already mutate. A
/// second, parallel bundle builder in this module would be a second thing to
/// keep correct, and the first one to drift.
///
/// The variety generated is *structural* — file kinds, fine-tree presence,
/// unit splits, reveal selection, anchor set, signature policy — which is
/// what the codec properties actually exercise. Magnitude is left to F11's
/// at-cap matrix.
pub fn arb_bundle_bytes(caps: GenCaps) -> impl Strategy<Value = Vec<u8>> {
    use crate::test_util::bundle_fixtures::{
        AnchorSet, FileSelection, FileSpec, Selection, WorkSpec, build,
    };

    // Text raw bytes are restricted to printable ASCII: canonicalization
    // (UTF-8/NFC/LF/no-BOM) is only defined on valid UTF-8, and a generator
    // that emitted arbitrary bytes as "text" would be testing G's rejection
    // path rather than F's codec.
    let file = (
        any::<bool>(),                                   // text?
        any::<bool>(),                                   // fine tree?
        proptest::collection::vec(0x20u8..0x7f, 1..=48), // raw bytes
        proptest::option::of(1u64..8),                   // split width
    );
    (
        proptest::collection::vec(file, 1..=caps.max_files),
        // Weighted toward the Ed25519-only policy: ML-DSA-65 signing
        // dominates per-case cost in this strategy, and the codec cannot tell
        // the two policies apart beyond a key length. The hybrid shape is
        // still generated ~25 % of the time so its longer `bstr` heads (1952
        // and 3309 bytes, i.e. two-byte length heads) stay in the corpus.
        prop_oneof![3 => Just(false), 1 => Just(true)], // hybrid policy?
        any::<bool>(),                                  // anchored?
        any::<u64>(),                                   // fixture RNG seed
        proptest::collection::vec(0usize..4, 1..=caps.max_files), // per-file selection
    )
        .prop_map(move |(files, hybrid, anchored, seed, selections)| {
            let specs: Vec<FileSpec> = files
                .iter()
                .enumerate()
                .map(|(i, (text, fine_tree, raw, split))| {
                    let path = format!("f{i}.bin");
                    let mut spec = if *text {
                        FileSpec::text(&path, raw.clone())
                    } else {
                        FileSpec::binary(&path, raw.clone())
                    };
                    if !*fine_tree {
                        spec = spec.without_fine_tree();
                    }
                    // Split only binary files. A unit tiling covers the
                    // file's *tiling domain*, which for text is the
                    // canonical rendition — a different length from the
                    // raw bytes — so widths derived from `raw.len()`
                    // would not tile a text file at all.
                    if let Some(width) = split
                        && !*text
                        && raw.len() as u64 > *width
                    {
                        let mut widths = Vec::new();
                        let mut left = raw.len() as u64;
                        while left > *width {
                            widths.push(*width);
                            left -= *width;
                        }
                        widths.push(left);
                        if widths.len() <= caps.max_units_per_file {
                            spec = spec.split(widths);
                        }
                    }
                    spec
                })
                .collect();

            let mut work = WorkSpec::new("property work", specs)
                .with_seed(seed)
                .with_anchors(if anchored {
                    AnchorSet::OneOtsTwoTsa
                } else {
                    AnchorSet::Empty
                });
            if !hybrid {
                work = work.with_ed25519_only_policy();
            }

            let selection = Selection(
                (0..work.files.len())
                    .map(|i| match selections.get(i).copied().unwrap_or(0) {
                        0 => FileSelection::Untouched,
                        1 => FileSelection::Full,
                        2 => FileSelection::FullNoMirror,
                        _ => FileSelection::Units(vec![0]),
                    })
                    .collect(),
            );

            build(&work, &selection).bytes
        })
}
