//! The raw-mirror model (tasks/G.md G7) — detection, entry construction, the
//! kind-based exemptions, and the selection rule (MVP-SPEC.md line 92).
//!
//! # What a raw mirror is
//!
//! Text content is hashed, tiled, and encrypted over its **canonical**
//! rendition (spec line 83). Where a text file's raw bytes differ from that
//! rendition — CRLF endings, a leading BOM, NFD sequences, or `--force-text`
//! bytes that are not valid UTF-8 — the original bytes would otherwise never
//! reach storage, and `raw_commit` would be unopenable from the network. The
//! raw mirror is the fix: the raw file is additionally encrypted and uploaded
//! as **one extra unit** of that file.
//!
//! It is a full unit-table entry, distinguished **only** by
//! `kind = raw-mirror` (there is no separate link field — spec line 98):
//!
//! - its own work-global `unit_id`, assigned in manifest order like any unit,
//!   so `k_u`, `unit_salt`, and the AEAD AAD derive normally (line 76);
//! - byte-range `[0, raw_size)` in the **raw** byte domain — deliberately a
//!   different domain from the file's other units;
//! - `true_length = raw_size` (a text file's raw byte count reaches the
//!   manifest *only* here; the file-table `size` is the canonical count,
//!   line 98);
//! - a `unit_commit`, because a mirror is never fine-tree-covered
//!   ([`is_fine_tree_covered`](super::is_fine_tree_covered) — the canonical
//!   fine tree does not reach the raw domain, line 94);
//! - nonce and ciphertext address, attached by C/S at assembly.
//!
//! At most one mirror per file, and it is the file's **last** unit (D23) —
//! [`FileUnitPlan::with_raw_mirror`] is the single seam that builds it, so
//! placement and field values cannot drift apart.
//!
//! # Exemptions are decided by `kind`, never by position
//!
//! A mirror lives in the raw domain, so it is exempt from the two invariants
//! that are statements about the canonical/tiling domain (spec lines 92, 121):
//! the per-file **tiling/overlap** invariant ([`tiling_exempt`]) and
//! **full-reveal concatenation** ([`full_reveal_concat_exempt`]). Both
//! predicates read `kind` alone. That matters for the verifier: D23's
//! placement rule is a seal-side construction rule, so R must exempt by kind
//! and stay correct against a hand-built manifest that puts its mirror
//! somewhere else.
//!
//! # Selection: never by a bare id
//!
//! A mirror discloses a file's exact original bytes, so it is includable
//! **only** via a whole-file reveal or `--all`; a bare `--units <mirror-id>`
//! is rejected ([`mirror_selectable`], [`ContentError::RawMirrorNotUnitSelectable`])
//! so a mistyped id can never disclose a raw file (spec line 92).
//!
//! # Two verify paths (spec lines 92, 114, 121)
//!
//! A bundle may carry either or both:
//!
//! 1. **`unit_commit` opening — always.** Because a mirror is never covered,
//!    G5's [`requires_unit_commit`](super::requires_unit_commit) is true for
//!    it and the manifest carries
//!    `unit_commit = SHA-256(0x02 || unit_salt || unit_bytes)` (line 94). A
//!    revealed mirror ships the non-covered-unit shape
//!    `{unit_id, unit_salt, k_u, ciphertext}` (line 114) and the verifier
//!    opens the commitment.
//! 2. **`file_salt`-keyed `raw_commit` opening — when proving exact original
//!    bytes.** `raw_commit` is the file-table commitment over the raw bytes;
//!    opening it needs the file's `file_salt`, which a bundle carries only for
//!    **fully** revealed files (partial-reveal isolation, line 121). This is
//!    the path `restore` (line 37) and "these are the exact original bytes"
//!    rely on.
//!
//! On top of them, R executes the **raw-mirror <-> canonical binding**:
//! whenever a reveal discloses both a file's mirror bytes and its canonical
//! content (every full reveal carrying a mirror), the verifier MUST recompute
//! [`canonicalize_v`](crate::canon::canonicalize_v) with the descriptor's
//! recorded Unicode version and require the result to equal the validated
//! canonical bytes (line 121) — otherwise a sealer could co-timestamp an
//! "original" that does not canonicalize to the sealed content.
//!
//! **R4 must perform that recompute in [`TextMode::Forced`]** (D20): forced
//! mode is the *total* transform and is byte-identical to detected mode on
//! valid UTF-8, whereas a `--force-text` file's mirror bytes are by definition
//! invalid UTF-8 — a `Detected` recompute would fail with a decode error on
//! exactly the files the binding exists to bind. The mirror check must return
//! an integrity verdict, never a decode error.
//!
//! [`TextMode::Forced`]: crate::canon::TextMode::Forced

use crate::canon::CanonicalBytes;

use super::error::ContentError;
use super::unit::{FileUnitPlan, Unit, UnitKind};

/// Does this file need a raw mirror? **Byte inequality** between its raw bytes
/// and its canonical rendition (MVP-SPEC.md line 92).
///
/// That single comparison is the whole rule; the familiar cases — CRLF or lone
/// CR endings, a leading BOM, NFD sequences, and `--force-text` bytes that are
/// not valid UTF-8 — are consequences of it, not separate tests. Binary files
/// never need one: they have no canonical rendition, so their units already
/// *are* the raw bytes (line 83).
///
/// Taking [`CanonicalBytes`] rather than a byte slice is deliberate: the
/// comparison is only meaningful against a genuine G2 output, and the type is
/// the only way to obtain one.
#[must_use]
pub fn needs_mirror(raw_bytes: &[u8], canonical: &CanonicalBytes) -> bool {
    raw_bytes != canonical.as_bytes()
}

/// Attach the file's raw mirror to `plan` iff [`needs_mirror`] — the seal-side
/// construction step, routed through G5's [`FileUnitPlan::with_raw_mirror`] so
/// the mirror's fields and its D23 placement have exactly one implementation.
///
/// `raw_size` is taken from `raw_bytes` itself, so the entry's byte-range
/// `[0, raw_size)` and `true_length` cannot be mis-stated. `usize -> u64` is
/// lossless on every supported target.
#[must_use]
pub fn with_raw_mirror_if_needed(
    plan: FileUnitPlan,
    raw_bytes: &[u8],
    canonical: &CanonicalBytes,
) -> FileUnitPlan {
    if needs_mirror(raw_bytes, canonical) {
        plan.with_raw_mirror(raw_bytes.len() as u64)
    } else {
        plan
    }
}

/// Whether a unit is exempt from the **per-file tiling/overlap invariant**:
/// true exactly for raw mirrors (MVP-SPEC.md lines 92, 121).
///
/// The invariant — non-mirror byte-ranges sorted, non-overlapping, exactly
/// tiling `[0, size)` — is a statement about the file's *tiling domain*
/// (canonical bytes for text, raw for binary). A mirror spans `[0, raw_size)`
/// in the raw domain, so including it would compare offsets from two different
/// coordinate systems.
#[must_use]
pub const fn tiling_exempt(kind: UnitKind) -> bool {
    matches!(kind, UnitKind::RawMirror)
}

/// Whether a unit is exempt from **full-reveal concatenation**: true exactly
/// for raw mirrors (MVP-SPEC.md lines 92, 121).
///
/// On a full file reveal the concatenated **non-mirror** unit bytes must hash
/// to `canon_commit` (text) / `raw_commit` (binary) and rebuild `fine_root`.
/// The mirror's bytes are the same file in the other domain, so concatenating
/// them in would append the whole file to itself.
#[must_use]
pub const fn full_reveal_concat_exempt(kind: UnitKind) -> bool {
    matches!(kind, UnitKind::RawMirror)
}

/// How a reveal came to include a unit — the input to the raw-mirror selection
/// rule (MVP-SPEC.md lines 92, 149).
///
/// This is the semantic form of U's `reveal` flags; the CLI surface is U's and
/// the bundle-side re-check is R's.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RevealSelection {
    /// `reveal --all`: every unit of the work. The user asked for everything,
    /// mirrors included.
    All,
    /// A whole-file reveal: every unit of the mirror's own file. This is the
    /// reveal that carries `file_salt` and `s_root` (spec line 114) and the
    /// one that can prove exact original bytes.
    WholeFile,
    /// `reveal --units <id>...`: an explicit id list. A mirror named here is
    /// rejected — the mistyped-id guard (spec line 92).
    UnitIds,
}

impl RevealSelection {
    /// Every selection, for truth-table tests.
    pub const ALL: [Self; 3] = [Self::All, Self::WholeFile, Self::UnitIds];
}

/// The raw-mirror selection rule: a mirror is includable **only** via a
/// whole-file reveal or `--all` (MVP-SPEC.md line 92).
///
/// # Errors
///
/// [`ContentError::RawMirrorNotUnitSelectable`] for
/// [`RevealSelection::UnitIds`] — the distinct rejection a bare
/// `--units <mirror-id>` must produce, so a mistyped id can never disclose a
/// raw file. U maps it to a CLI error naming the id and pointing at
/// `--all`/whole-file reveal; R re-checks it on any bundle it is handed.
pub const fn mirror_selectable(selection: RevealSelection) -> Result<(), ContentError> {
    match selection {
        RevealSelection::All | RevealSelection::WholeFile => Ok(()),
        RevealSelection::UnitIds => Err(ContentError::RawMirrorNotUnitSelectable),
    }
}

/// [`mirror_selectable`] applied to a concrete unit: normal units are
/// selectable under every selection, and only mirrors are constrained.
///
/// This is the total predicate a reveal builder wants — it can ask the
/// question of every unit it is about to include without first branching on
/// `kind`.
///
/// # Errors
///
/// [`ContentError::RawMirrorNotUnitSelectable`] when `unit` is a raw mirror
/// named by a bare `--units` id list.
pub const fn unit_selectable(unit: &Unit, selection: RevealSelection) -> Result<(), ContentError> {
    match unit.kind() {
        UnitKind::Normal => Ok(()),
        UnitKind::RawMirror => mirror_selectable(selection),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canon::{TextMode, UnicodeVersion, canonicalize};
    use crate::content::descriptor::{CanonDescriptor, ContentKind, FineTreeOptOut};
    use crate::content::split::plan_blank_line_split;
    use crate::content::unit::{
        ByteRange, FileLengths, SplitEligibleText, assign_unit_ids, is_fine_tree_covered,
        requires_unit_commit,
    };
    // Property tests need the proptest-bearing `test-util` tier, which the
    // wasm32 `--lib` test build deliberately does not enable (P14,
    // docs/wasm-toolchain.md). Everything else in this module runs on both.
    #[cfg(feature = "test-util")]
    use crate::test_util::strategies::proptest_config;
    #[cfg(feature = "test-util")]
    use proptest::prelude::*;

    /// Canonicalize with G2 — every fixture below derives its canonical bytes
    /// from the real pipeline rather than hand-written expectations.
    fn canon(raw: &[u8]) -> CanonicalBytes {
        canonicalize(UnicodeVersion::CURRENT, TextMode::Detected, raw).expect("valid UTF-8")
    }

    fn text_desc(size: u64) -> CanonDescriptor {
        CanonDescriptor::describe_file(
            ContentKind::Text(UnicodeVersion::CURRENT),
            size,
            FineTreeOptOut::NotRequested,
        )
    }

    // ── Detection (G7 accept) ───────────────────────────────────────────

    /// G7 accept: a CRLF-only difference triggers a mirror.
    #[test]
    fn crlf_only_difference_needs_a_mirror() {
        let raw = b"alpha\r\nbeta\r\n";
        let canonical = canon(raw);
        assert_eq!(canonical.as_str(), "alpha\nbeta\n");
        assert!(needs_mirror(raw, &canonical));
        // The lone-CR (classic Mac) flavour too.
        let lone_cr = b"alpha\rbeta\r";
        assert!(needs_mirror(lone_cr, &canon(lone_cr)));
    }

    /// G7 accept: a BOM-only difference triggers a mirror.
    #[test]
    fn bom_only_difference_needs_a_mirror() {
        let raw = "\u{FEFF}alpha\n".as_bytes();
        let canonical = canon(raw);
        assert_eq!(canonical.as_str(), "alpha\n");
        assert!(needs_mirror(raw, &canonical));

        // An *interior* U+FEFF is content and survives, so no mirror.
        let interior = "alpha\u{FEFF}beta\n".as_bytes();
        assert!(!needs_mirror(interior, &canon(interior)));
    }

    /// G7 accept: an NFD-only difference triggers a mirror.
    #[test]
    fn nfd_only_difference_needs_a_mirror() {
        let raw = "cafe\u{0301}\n".as_bytes(); // e + COMBINING ACUTE ACCENT
        let canonical = canon(raw);
        assert_eq!(canonical.as_str(), "caf\u{00E9}\n");
        assert!(needs_mirror(raw, &canonical));

        // The NFC twin of the same text needs none.
        let nfc = "caf\u{00E9}\n".as_bytes();
        assert!(!needs_mirror(nfc, &canon(nfc)));
    }

    /// G7 accept: raw == canonical -> no mirror.
    #[test]
    fn already_canonical_file_needs_no_mirror() {
        for raw in [
            &b""[..],
            &b"alpha\n"[..],
            &b"alpha\n\nbeta\n"[..],
            "caf\u{00E9} \u{4E2D}\u{6587}\n".as_bytes(),
        ] {
            assert!(!needs_mirror(raw, &canon(raw)), "{raw:?}");
        }
    }

    /// A `--force-text` file whose bytes are not valid UTF-8 always needs a
    /// mirror: lossy decode mints U+FFFD, so the canonical rendition cannot
    /// equal the raw bytes (D20). This is why R4's recompute must use
    /// [`TextMode::Forced`] — module docs.
    #[test]
    fn forced_text_invalid_utf8_needs_a_mirror() {
        let raw = b"alpha\xFF\xFEbeta\n";
        let canonical = canonicalize(UnicodeVersion::CURRENT, TextMode::Forced, raw)
            .expect("forced text is total");
        assert!(needs_mirror(raw, &canonical));
        // And the recompute R runs is exactly this one, so it agrees with
        // itself: canonicalizing the mirror bytes reproduces the canonical
        // rendition (spec line 121's binding, in the mode D20 mandates).
        assert_eq!(
            canonicalize(UnicodeVersion::CURRENT, TextMode::Forced, raw).expect("total"),
            canonical
        );
    }

    // ── Entry construction (G7 accept) ──────────────────────────────────

    /// G7 accept: the mirror entry's fields are exactly the spec's — kind,
    /// raw-domain range `[0, raw_size)`, `true_length = raw_size` — and it is
    /// the file's last unit (D23). Built end to end from G2's canonicalization
    /// through G5's plan seam.
    #[test]
    fn mirror_entry_fields_match_the_spec() {
        let raw = b"alpha\r\n\r\nbeta\r\n";
        let canonical = canon(raw);
        let lengths = FileLengths::Text {
            canonical: canonical.len() as u64,
            raw: raw.len() as u64,
        };
        assert_eq!(
            lengths.size_field(),
            12,
            "canonical count is the size field"
        );
        assert_eq!(lengths.raw(), 15);

        let plan = with_raw_mirror_if_needed(
            FileUnitPlan::whole_file(lengths.size_field()),
            raw,
            &canonical,
        );
        assert_eq!(plan.mirror_raw_size(), Some(15));
        assert_eq!(plan.unit_count(), 2);

        let units = assign_unit_ids(&[plan]);
        let mirror = *units.last().expect("mirror exists");
        assert_eq!(mirror.kind(), UnitKind::RawMirror);
        assert_eq!(mirror.file_id(), 0);
        assert_eq!(mirror.byte_range(), ByteRange::new(0, 15));
        assert_eq!(mirror.true_length(), 15, "the raw byte count lives here");
        assert!(mirror.true_length_matches_range());
        assert_eq!(mirror.unit_id(), 1, "the file's LAST unit (D23)");

        // Never covered => it carries a unit_commit (spec lines 92, 94).
        let descriptor = text_desc(lengths.size_field());
        assert!(!is_fine_tree_covered(&mirror, &descriptor));
        assert!(requires_unit_commit(&mirror, &descriptor));
    }

    /// No mirror is attached when the file is already canonical — the plan
    /// comes back untouched.
    #[test]
    fn no_mirror_is_attached_when_raw_equals_canonical() {
        let raw = b"alpha\nbeta\n";
        let canonical = canon(raw);
        let plan = with_raw_mirror_if_needed(FileUnitPlan::whole_file(11), raw, &canonical);
        assert_eq!(plan.mirror_raw_size(), None);
        assert_eq!(plan.unit_count(), 1);
        assert_eq!(assign_unit_ids(&[plan]).len(), 1);
    }

    /// A file of nothing but BOMs canonicalizes to zero bytes: the empty-file
    /// rule gives it one empty unit (spec line 78) and the mirror still carries
    /// the original bytes, so nothing is lost.
    #[test]
    fn empty_canonical_rendition_still_gets_a_mirror() {
        let raw = "\u{FEFF}\u{FEFF}".as_bytes();
        let canonical = canon(raw);
        assert!(canonical.is_empty());
        assert!(needs_mirror(raw, &canonical));

        let plan = with_raw_mirror_if_needed(FileUnitPlan::whole_file(0), raw, &canonical);
        let units = assign_unit_ids(&[plan]);
        assert_eq!(units.len(), 2);
        assert_eq!(units[0].byte_range(), ByteRange::empty());
        assert_eq!(units[1].kind(), UnitKind::RawMirror);
        assert_eq!(units[1].true_length(), 6, "two 3-byte U+FEFF scalars");
    }

    /// G7 accept: id assignment interleaves correctly with G5's work-global
    /// counter across **two** files — the mirror takes an ordinal like any
    /// unit, and the counter does not restart at the file boundary (spec
    /// line 76, D23).
    #[test]
    fn mirror_ids_interleave_with_the_global_counter() {
        // File 0: CRLF text, split into two paragraphs, so mirror id = 2.
        let raw0 = b"alpha\r\n\r\nbeta\r\n";
        let canonical0 = canon(raw0);
        let eligible = SplitEligibleText::of(&text_desc(canonical0.len() as u64))
            .expect("covered text file is split-eligible");
        let plan0 = with_raw_mirror_if_needed(
            plan_blank_line_split(eligible, &canonical0),
            raw0,
            &canonical0,
        );
        // File 1: already-canonical text, one unit, no mirror.
        let raw1 = b"gamma\n";
        let canonical1 = canon(raw1);
        let plan1 = with_raw_mirror_if_needed(FileUnitPlan::whole_file(6), raw1, &canonical1);
        // File 2: BOM'd text, one unit plus a mirror.
        let raw2 = "\u{FEFF}delta\n".as_bytes();
        let canonical2 = canon(raw2);
        let plan2 = with_raw_mirror_if_needed(FileUnitPlan::whole_file(6), raw2, &canonical2);

        let units = assign_unit_ids(&[plan0, plan1, plan2]);
        let shape: Vec<(u64, u64, UnitKind, u64, u64)> = units
            .iter()
            .map(|u| {
                (
                    u.unit_id(),
                    u.file_id(),
                    u.kind(),
                    u.byte_range().length(),
                    u.true_length(),
                )
            })
            .collect();
        assert_eq!(
            shape,
            vec![
                (0, 0, UnitKind::Normal, 7, 7),      // "alpha\n\n"
                (1, 0, UnitKind::Normal, 5, 5),      // "beta\n"
                (2, 0, UnitKind::RawMirror, 15, 15), // file 0's LAST unit
                (3, 1, UnitKind::Normal, 6, 6),      // no mirror for file 1
                (4, 2, UnitKind::Normal, 6, 6),
                (5, 2, UnitKind::RawMirror, 9, 9), // BOM = 3 raw bytes more
            ]
        );
    }

    // ── Predicates (G7 accept) ──────────────────────────────────────────

    /// Both exemptions are decided by `kind` alone, and only mirrors are
    /// exempt (spec lines 92, 121).
    #[test]
    fn exemption_predicates_are_kind_based() {
        for kind in UnitKind::ALL {
            let expected = kind == UnitKind::RawMirror;
            assert_eq!(tiling_exempt(kind), expected, "tiling: {kind:?}");
            assert_eq!(
                full_reveal_concat_exempt(kind),
                expected,
                "concat: {kind:?}"
            );
        }
        assert!(!tiling_exempt(UnitKind::Normal));
        assert!(tiling_exempt(UnitKind::RawMirror));
    }

    /// G7 accept: the selection truth table, and the distinct rejection value a
    /// bare `--units <mirror-id>` produces (spec line 92).
    #[test]
    fn mirror_selection_rejects_bare_unit_ids() {
        assert_eq!(mirror_selectable(RevealSelection::All), Ok(()));
        assert_eq!(mirror_selectable(RevealSelection::WholeFile), Ok(()));
        assert_eq!(
            mirror_selectable(RevealSelection::UnitIds),
            Err(ContentError::RawMirrorNotUnitSelectable),
            "a mistyped id must never disclose a raw file"
        );
        assert_eq!(
            ContentError::RawMirrorNotUnitSelectable.code(),
            "content-raw-mirror-not-unit-selectable"
        );

        // Exhaustive over the frozen selection set.
        for selection in RevealSelection::ALL {
            let allowed = selection != RevealSelection::UnitIds;
            assert_eq!(
                mirror_selectable(selection).is_ok(),
                allowed,
                "{selection:?}"
            );
        }
    }

    /// Only mirrors are constrained: a normal unit is selectable under every
    /// selection, including a bare id list.
    #[test]
    fn normal_units_are_selectable_under_every_selection() {
        let normal = Unit::new(0, 0, UnitKind::Normal, ByteRange::new(0, 10));
        let mirror = Unit::new(1, 0, UnitKind::RawMirror, ByteRange::new(0, 12));
        for selection in RevealSelection::ALL {
            assert_eq!(unit_selectable(&normal, selection), Ok(()), "{selection:?}");
            assert_eq!(
                unit_selectable(&mirror, selection),
                mirror_selectable(selection),
                "{selection:?}"
            );
        }
        assert_eq!(
            unit_selectable(&mirror, RevealSelection::UnitIds),
            Err(ContentError::RawMirrorNotUnitSelectable)
        );
    }

    /// G7 accept, truth test: a mirror built by this module is never
    /// `is_fine_tree_covered`, under **any** descriptor — the canonical fine
    /// tree does not cover the raw domain (spec line 92) — so it always
    /// carries a `unit_commit`.
    #[test]
    fn mirror_is_never_fine_tree_covered() {
        let raw = b"alpha\r\nbeta\r\n";
        let canonical = canon(raw);
        let units = assign_unit_ids(&[with_raw_mirror_if_needed(
            FileUnitPlan::whole_file(canonical.len() as u64),
            raw,
            &canonical,
        )]);
        let mirror = *units.last().expect("mirror exists");
        assert_eq!(mirror.kind(), UnitKind::RawMirror);

        for size in [0u64, 1, 11, 4096] {
            for opt_out in FineTreeOptOut::ALL {
                for kind in [
                    ContentKind::Text(UnicodeVersion::CURRENT),
                    ContentKind::Binary,
                ] {
                    let descriptor = CanonDescriptor::describe_file(kind, size, opt_out);
                    assert!(!is_fine_tree_covered(&mirror, &descriptor));
                    assert!(requires_unit_commit(&mirror, &descriptor));
                }
            }
        }
    }

    // ── Property tests ──────────────────────────────────────────────────

    /// Bytes that canonicalization often changes: CR, BOM, combining marks,
    /// plus ordinary content.
    #[cfg(feature = "test-util")]
    fn mirror_prone_text() -> impl Strategy<Value = String> {
        proptest::collection::vec(
            prop_oneof![
                20 => proptest::char::range('a', 'z'),
                10 => Just('\n'),
                10 => Just('\r'),
                6 => Just('\u{FEFF}'),
                6 => Just('\u{0301}'),
                6 => Just('\u{00E9}'),
                4 => Just('e'),
            ],
            0..32,
        )
        .prop_map(|chars| chars.into_iter().collect())
    }

    #[cfg(feature = "test-util")]
    proptest! {
        #![proptest_config(proptest_config(0x0064_0007))]

        /// `needs_mirror` is exactly byte inequality, and it drives attachment:
        /// the plan gains a mirror iff the bytes differ, with `raw_size` equal
        /// to the raw byte count.
        #[test]
        fn needs_mirror_is_byte_inequality(text in mirror_prone_text()) {
            let raw = text.as_bytes();
            let canonical = canonicalize(UnicodeVersion::CURRENT, TextMode::Detected, raw)
                .expect("generated text is valid UTF-8");
            let differs = raw != canonical.as_bytes();
            prop_assert_eq!(needs_mirror(raw, &canonical), differs);

            let plan = with_raw_mirror_if_needed(
                FileUnitPlan::whole_file(canonical.len() as u64),
                raw,
                &canonical,
            );
            prop_assert_eq!(
                plan.mirror_raw_size(),
                if differs { Some(raw.len() as u64) } else { None }
            );
            prop_assert_eq!(plan.unit_count(), if differs { 2 } else { 1 });

            // Whenever a mirror exists it is the file's last unit, in the raw
            // domain, and never covered (D23; spec lines 92, 94).
            let descriptor = CanonDescriptor::describe_file(
                ContentKind::Text(UnicodeVersion::CURRENT),
                canonical.len() as u64,
                FineTreeOptOut::NotRequested,
            );
            let units = assign_unit_ids(&[plan]);
            if differs {
                let mirror = units.last().expect("mirror exists");
                prop_assert_eq!(mirror.kind(), UnitKind::RawMirror);
                prop_assert_eq!(mirror.byte_range(), ByteRange::new(0, raw.len() as u64));
                prop_assert_eq!(mirror.true_length(), raw.len() as u64);
                prop_assert!(!is_fine_tree_covered(mirror, &descriptor));
                prop_assert!(requires_unit_commit(mirror, &descriptor));
                prop_assert!(tiling_exempt(mirror.kind()));
                prop_assert!(full_reveal_concat_exempt(mirror.kind()));
            } else {
                prop_assert!(units.iter().all(|u| u.kind() == UnitKind::Normal));
            }
        }

        /// A canonical rendition never needs a mirror against itself — the
        /// consequence of G2's idempotence that keeps `restore` from shipping a
        /// redundant second copy of an already-canonical file. Holds over
        /// arbitrary bytes through the total forced-text transform (D20).
        #[test]
        fn canonical_bytes_never_need_a_mirror(raw in proptest::collection::vec(any::<u8>(), 0..64)) {
            let canonical = canonicalize(UnicodeVersion::CURRENT, TextMode::Forced, &raw)
                .expect("forced text is total");
            let again = canonicalize(UnicodeVersion::CURRENT, TextMode::Forced, canonical.as_bytes())
                .expect("forced text is total");
            prop_assert!(!needs_mirror(canonical.as_bytes(), &again));
        }
    }
}
