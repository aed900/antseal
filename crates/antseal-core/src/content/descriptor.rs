//! Per-file canonicalization descriptor (tasks/G.md G4) — the manifest field
//! that records **how a file was canonicalized and committed**, plus the
//! seal-time decision logic that builds it and the cross-field validation
//! predicate F's decoder and R's verifier run on descriptors that arrived from
//! an adversary.
//!
//! MVP-SPEC.md line 83 defines the field set: *"The per-file canonicalization
//! descriptor records the kind, the fine tree's presence, its domain
//! (canonical vs raw bytes), and the exact Unicode data version used for
//! NFC."* Line 85 adds the fine tree's default-on/`--no-fine-tree`-opt-out
//! rule, and line 78 the empty-file rule (no fine tree, one empty unit).
//!
//! # The rule this module exists to enforce: descriptor-recorded version,
//! never "latest"
//!
//! NFC output depends on the Unicode data version, so the version is **frozen
//! per seal** and written here; a verifier that must recompute canonicalization
//! — the raw-mirror `canonicalize(raw) == canonical` binding of MVP-SPEC.md
//! line 121 — applies the **descriptor-recorded** version and never "latest"
//! (MVP-SPEC.md line 83). Otherwise an aging honest bundle would false-positive
//! as tampered the moment the verifier's Unicode tables drift, which for a
//! permanent-storage product is a correctness bug with a multi-year fuse.
//! [`CanonDescriptor::resolve_unicode_version`] is the only sanctioned way to
//! get from a descriptor to a normalization table; [`UnicodeVersion::CURRENT`]
//! is seal-side only (G1/D25).
//!
//! # Layers
//!
//! - [`CanonDescriptor::describe_file`] — **seal side.** Total and infallible:
//!   the decision logic of MVP-SPEC.md lines 83/85/78 applied to a file whose
//!   kind, size, and `--no-fine-tree` match are already known. Illegal outputs
//!   are unrepresentable, not rejected.
//! - [`CanonDescriptor::try_new`] — **decode side.** The validation predicate:
//!   the only way to build a descriptor from untrusted wire fields, returning a
//!   distinct [`ContentError`] for every illegal field combination.
//! - [`CanonDescriptor::validate_with_size`] — the size-aware rider F/R run
//!   once the file-table `size` is in hand (the descriptor alone cannot see
//!   `n`, so the empty-file rule of line 78 is checked there).
//!
//! # Wire encoding is F's
//!
//! The semantic field set and its legality rules are G's; the deterministic
//! CBOR encoding (map keys, the `uint` 0/1 spellings of [`FileKind`] and
//! [`FineTreeDomain`]) belongs to F and lives in `docs/format/registry-v1.md`
//! §6.3/§7.4. The variant **order** of the two enums here is declared to match
//! that draft (binary/raw first) so the two never drift apart silently, but no
//! numeric value appears in this module.

use core::fmt;

use crate::canon::{UnicodeVersion, UnicodeVersionError};

use super::error::ContentError;

/// The descriptor's `kind` field: whether the file has a canonical rendition
/// (MVP-SPEC.md line 83).
///
/// Text = valid UTF-8, or forced by `--force-text`. Per decision D20 the
/// descriptor records **no** forced-text flag: `kind = Text` alone determines
/// recompute semantics, and a verifier recomputing a text file's canonical
/// rendition always uses the total lossy mode
/// ([`TextMode::Forced`](crate::canon::TextMode::Forced)).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FileKind {
    /// No canonical rendition: offsets, `size`, and fine-tree leaves are all
    /// raw bytes (MVP-SPEC.md line 83).
    Binary,
    /// Has a canonical rendition (UTF-8, NFC, LF, no BOM): offsets, `size`,
    /// and fine-tree leaves are canonical bytes (MVP-SPEC.md line 83).
    Text,
}

impl FileKind {
    /// Both kinds, for truth-table tests.
    pub const ALL: [Self; 2] = [Self::Binary, Self::Text];

    /// The byte domain this kind's fine tree — and its unit offsets, `size`
    /// field, and content commitments — live in: canonical bytes for text,
    /// raw bytes for binary (MVP-SPEC.md lines 83, 85, 98).
    ///
    /// This is the *only* place the kind → domain rule is written; both
    /// [`CanonDescriptor::describe_file`] and the validation predicate route
    /// through it, so they cannot disagree.
    #[must_use]
    pub const fn fine_tree_domain(self) -> FineTreeDomain {
        match self {
            Self::Binary => FineTreeDomain::Raw,
            Self::Text => FineTreeDomain::Canonical,
        }
    }
}

impl fmt::Display for FileKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Binary => "binary",
            Self::Text => "text",
        })
    }
}

/// Which byte domain a present fine tree commits (MVP-SPEC.md lines 83, 85).
///
/// Recorded explicitly even though it is a function of [`FileKind`]: the spec
/// lists it as its own descriptor field (line 83), and an explicit field lets a
/// verifier reject a kind/domain contradiction as a *descriptor* error rather
/// than discovering it as an unexplained root mismatch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FineTreeDomain {
    /// Leaves are the file's raw bytes — binary files, and the raw-mirror
    /// unit's domain (MVP-SPEC.md lines 83, 92).
    Raw,
    /// Leaves are the canonical rendition's bytes — text files
    /// (MVP-SPEC.md line 85).
    Canonical,
}

impl FineTreeDomain {
    /// Both domains, for truth-table tests.
    pub const ALL: [Self; 2] = [Self::Raw, Self::Canonical];
}

impl fmt::Display for FineTreeDomain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Raw => "raw",
            Self::Canonical => "canonical",
        })
    }
}

/// What [`CanonDescriptor::describe_file`] is told about a file: binary, or
/// text **together with the exact Unicode data version its canonical rendition
/// was produced under**.
///
/// Pairing the version with the text case at the *input* is what makes the two
/// version-related illegal combinations (text without a version, version on
/// binary) unrepresentable on the seal side instead of merely rejected.
///
/// This is the seal-time decision (detection or `--force-text`); the recorded
/// wire field is [`FileKind`], reachable via [`Self::file_kind`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ContentKind {
    /// Not text: no canonical rendition, no normalization, no version.
    Binary,
    /// Text, canonicalized under this Unicode data version — the version the
    /// descriptor freezes and every later recompute must use
    /// (MVP-SPEC.md line 83).
    Text(UnicodeVersion),
}

impl ContentKind {
    /// The `kind` field this decision records.
    #[must_use]
    pub const fn file_kind(self) -> FileKind {
        match self {
            Self::Binary => FileKind::Binary,
            Self::Text(_) => FileKind::Text,
        }
    }

    /// The Unicode data version, present iff this is text.
    #[must_use]
    pub const fn unicode_version(self) -> Option<UnicodeVersion> {
        match self {
            Self::Binary => None,
            Self::Text(version) => Some(version),
        }
    }
}

/// Whether `--no-fine-tree <glob>` matched this file (MVP-SPEC.md line 85).
///
/// A named type rather than a bare `bool` because the consequence is
/// **permanent**: an opted-out file is whole-file-reveal-only forever, in a
/// format frozen at seal time. `seal` warns about it (line 85), and the model
/// offers no override path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FineTreeOptOut {
    /// Default: build the fine tree (MVP-SPEC.md line 85 — "for **every file**
    /// by default").
    NotRequested,
    /// `--no-fine-tree` matched: no fine tree, permanently whole-file-reveal
    /// only.
    Requested,
}

impl FineTreeOptOut {
    /// Both choices, for truth-table tests.
    pub const ALL: [Self; 2] = [Self::NotRequested, Self::Requested];

    /// `true` iff the opt-out was requested.
    #[must_use]
    pub const fn is_requested(self) -> bool {
        matches!(self, Self::Requested)
    }
}

/// The per-file canonicalization descriptor (MVP-SPEC.md lines 83, 98).
///
/// Fields are private and every constructor validates, so a value of this type
/// is a witness that the field combination is legal — F can encode one without
/// re-checking, and R can trust the biconditionals (`domain` iff tree present;
/// `unicode_version` iff text) when dispatching.
///
/// See the module docs for the seal-side / decode-side split and for the
/// "descriptor-recorded version, never latest" rule (MVP-SPEC.md lines 83, 85).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonDescriptor {
    kind: FileKind,
    fine_tree_present: bool,
    /// Present iff `fine_tree_present` (enforced by every constructor).
    fine_tree_domain: Option<FineTreeDomain>,
    /// Present iff `kind == Text` (enforced by every constructor). Stored as
    /// the **recorded string**, not a resolved [`UnicodeVersion`]: a descriptor
    /// naming a version this build does not register is a "verifier too old"
    /// condition, which must stay distinct from both a decode error and an
    /// integrity verdict (G1/D25). Resolution happens at
    /// [`Self::resolve_unicode_version`], at the moment a table is needed.
    unicode_version: Option<String>,
}

impl CanonDescriptor {
    /// **Seal side.** Build the descriptor for one file (tasks/G.md G4
    /// decision logic; MVP-SPEC.md lines 83, 85, 78).
    ///
    /// Decisions, in the spec's own terms:
    ///
    /// - **kind** — from `kind`: detection (valid UTF-8) or `--force-text`
    ///   (line 83). The Unicode version rides along in [`ContentKind::Text`].
    /// - **fine-tree presence** — default `true` (line 85: built for every file
    ///   by default), `false` iff `--no-fine-tree` matched **or** the file is
    ///   empty (`size == 0`: no leaves, hence no tree — line 78).
    /// - **domain** — recorded iff a tree is present, and then canonical for
    ///   text / raw for binary ([`FileKind::fine_tree_domain`]; lines 83, 85).
    /// - **unicode_version** — recorded iff text (line 83).
    ///
    /// `size` is the file's **`size` field**: the leaf count `n` in the file's
    /// own domain — canonical byte count for text, raw byte count for binary
    /// (MVP-SPEC.md line 98; [`FileLengths::size_field`](super::FileLengths::size_field)
    /// computes it).
    ///
    /// The result always satisfies [`Self::validate`] and
    /// `validate_with_size(size)`; both are proptest-asserted.
    #[must_use]
    pub fn describe_file(kind: ContentKind, size: u64, opt_out: FineTreeOptOut) -> Self {
        let file_kind = kind.file_kind();
        let fine_tree_present = !opt_out.is_requested() && size > 0;
        Self {
            kind: file_kind,
            fine_tree_present,
            fine_tree_domain: fine_tree_present.then(|| file_kind.fine_tree_domain()),
            unicode_version: kind
                .unicode_version()
                .map(|version| version.as_str().to_owned()),
        }
    }

    /// **Decode side.** The cross-field validation predicate: assemble a
    /// descriptor from wire field values, rejecting every illegal combination
    /// with its own distinct error.
    ///
    /// Arguments are in registry key order (`docs/format/registry-v1.md` §7.4:
    /// `kind`, `fine_tree_present`, `fine_tree_domain`, `unicode_version`) so a
    /// decoder reads straight down its map.
    ///
    /// # What is *not* checked here
    ///
    /// - **Version registration.** `unicode_version` is taken as received;
    ///   whether this build ships that table is resolved later, distinctly, by
    ///   [`Self::resolve_unicode_version`] (an unknown version means "upgrade
    ///   the verifier", never "tampered" — G1/D25). Bounding a hostile
    ///   version string's length is F's decode-cap job.
    /// - **The empty-file rule.** Needs the file's `size`; see
    ///   [`Self::validate_with_size`].
    ///
    /// # Error precedence
    ///
    /// Fixed and total, so F/R get a deterministic code for any input:
    /// (1) kind × version presence, (2) tree presence × domain presence,
    /// (3) kind × domain value.
    ///
    /// # Errors
    ///
    /// - [`ContentError::TextMissingUnicodeVersion`] — text, no version.
    /// - [`ContentError::BinaryUnicodeVersion`] — binary with a version.
    /// - [`ContentError::FineTreePresentWithoutDomain`] — tree, no domain.
    /// - [`ContentError::FineTreeAbsentWithDomain`] — domain, no tree.
    /// - [`ContentError::BinaryCanonicalFineTreeDomain`] — binary + canonical.
    /// - [`ContentError::TextRawFineTreeDomain`] — text + raw.
    pub fn try_new(
        kind: FileKind,
        fine_tree_present: bool,
        fine_tree_domain: Option<FineTreeDomain>,
        unicode_version: Option<&str>,
    ) -> Result<Self, ContentError> {
        check_fields(
            kind,
            fine_tree_present,
            fine_tree_domain,
            unicode_version.is_some(),
        )?;
        Ok(Self {
            kind,
            fine_tree_present,
            fine_tree_domain,
            unicode_version: unicode_version.map(ToOwned::to_owned),
        })
    }

    /// The recorded `kind` (MVP-SPEC.md line 83).
    #[must_use]
    pub const fn kind(&self) -> FileKind {
        self.kind
    }

    /// Whether this file has a fine tree (MVP-SPEC.md line 85).
    ///
    /// `false` means permanently whole-file-reveal-only: the file has exactly
    /// one unit, and that unit carries a `unit_commit` because no `fine_root`
    /// covers it ([`is_fine_tree_covered`](super::is_fine_tree_covered);
    /// MVP-SPEC.md line 94).
    #[must_use]
    pub const fn fine_tree_present(&self) -> bool {
        self.fine_tree_present
    }

    /// The fine tree's byte domain — `Some` iff [`Self::fine_tree_present`].
    #[must_use]
    pub const fn fine_tree_domain(&self) -> Option<FineTreeDomain> {
        self.fine_tree_domain
    }

    /// The recorded Unicode data version string — `Some` iff the file is text
    /// (MVP-SPEC.md line 83). Returned verbatim, as recorded; use
    /// [`Self::resolve_unicode_version`] to get a usable table.
    #[must_use]
    pub fn unicode_version(&self) -> Option<&str> {
        self.unicode_version.as_deref()
    }

    /// Re-run the cross-field validation predicate.
    ///
    /// Always `Ok` for a value obtained from [`Self::describe_file`] or
    /// [`Self::try_new`] — the type carries the invariant. Exposed so R can
    /// assert it at stage boundaries and so the rule has one public name.
    ///
    /// # Errors
    ///
    /// As [`Self::try_new`].
    pub fn validate(&self) -> Result<(), ContentError> {
        check_fields(
            self.kind,
            self.fine_tree_present,
            self.fine_tree_domain,
            self.unicode_version.is_some(),
        )
    }

    /// [`Self::validate`] plus the **empty-file rule**: a file whose `size` is
    /// 0 has no leaves, hence no fine tree and one empty unit
    /// (MVP-SPEC.md line 78).
    ///
    /// Separate from [`Self::validate`] because the descriptor does not carry
    /// `n`; F/R call this once the file-table `size` is decoded.
    ///
    /// # Errors
    ///
    /// [`ContentError::FineTreePresentOnEmptyFile`] when `size == 0` and a tree
    /// is recorded, plus everything [`Self::validate`] rejects.
    pub fn validate_with_size(&self, size: u64) -> Result<(), ContentError> {
        self.validate()?;
        if size == 0 && self.fine_tree_present {
            return Err(ContentError::FineTreePresentOnEmptyFile);
        }
        Ok(())
    }

    /// Resolve the **descriptor-recorded** Unicode version to the shipped
    /// normalization table — the one sanctioned path from a descriptor to NFC
    /// (MVP-SPEC.md lines 83, 85).
    ///
    /// Returns `Ok(None)` for binary files (nothing to normalize). Verifiers
    /// recomputing a text file's canonical rendition (the raw-mirror binding of
    /// MVP-SPEC.md line 121) MUST feed the resolved version to
    /// [`canonicalize`](crate::canon::canonicalize) and MUST NOT substitute
    /// [`UnicodeVersion::CURRENT`]: "latest" would make an aging honest bundle
    /// false-positive as tampered once the verifier's tables drift
    /// (MVP-SPEC.md line 83).
    ///
    /// # Errors
    ///
    /// [`UnicodeVersionError::UnknownUnicodeVersion`] when this build does not
    /// register the recorded version. That is a *"this bundle needs a newer
    /// verifier"* condition and must never be surfaced as an integrity failure
    /// (G1/D25).
    pub fn resolve_unicode_version(&self) -> Result<Option<UnicodeVersion>, UnicodeVersionError> {
        match self.unicode_version.as_deref() {
            None => Ok(None),
            Some(recorded) => UnicodeVersion::resolve(recorded).map(Some),
        }
    }
}

/// The cross-field legality rules of MVP-SPEC.md lines 83/85, in the fixed
/// precedence [`CanonDescriptor::try_new`] documents. Shared by every
/// constructor and by `validate`, so there is exactly one copy of the rule.
fn check_fields(
    kind: FileKind,
    fine_tree_present: bool,
    fine_tree_domain: Option<FineTreeDomain>,
    has_unicode_version: bool,
) -> Result<(), ContentError> {
    // (1) kind × Unicode-version presence (line 83: the version is the text
    //     file's NFC input; binary files never normalize).
    match (kind, has_unicode_version) {
        (FileKind::Text, false) => return Err(ContentError::TextMissingUnicodeVersion),
        (FileKind::Binary, true) => return Err(ContentError::BinaryUnicodeVersion),
        _ => {}
    }

    // (2) tree presence × domain presence — a biconditional (line 83: the
    //     domain is recorded *for the tree*; line 85: no tree, nothing to
    //     describe).
    match (fine_tree_present, fine_tree_domain) {
        (true, None) => return Err(ContentError::FineTreePresentWithoutDomain),
        (false, Some(_)) => return Err(ContentError::FineTreeAbsentWithDomain),
        _ => {}
    }

    // (3) kind × domain value (line 85: canonical bytes for text, raw bytes
    //     for binary). Only reachable when a domain is present.
    if let Some(domain) = fine_tree_domain
        && domain != kind.fine_tree_domain()
    {
        return Err(match kind {
            FileKind::Binary => ContentError::BinaryCanonicalFineTreeDomain,
            FileKind::Text => ContentError::TextRawFineTreeDomain,
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canon::UNICODE_17_0_0;
    use crate::test_util::strategies::proptest_config;
    use proptest::prelude::*;

    const V: UnicodeVersion = UnicodeVersion::CURRENT;

    fn text() -> ContentKind {
        ContentKind::Text(V)
    }

    // ── describe_file decision logic (G4 accept) ────────────────────────

    /// Default: every file gets a fine tree, in its own kind's domain, and a
    /// text file records its Unicode version (MVP-SPEC.md lines 83, 85).
    #[test]
    fn describe_file_defaults_to_a_fine_tree_in_the_kind_domain() {
        let text_desc = CanonDescriptor::describe_file(text(), 42, FineTreeOptOut::NotRequested);
        assert_eq!(text_desc.kind(), FileKind::Text);
        assert!(text_desc.fine_tree_present());
        assert_eq!(
            text_desc.fine_tree_domain(),
            Some(FineTreeDomain::Canonical)
        );
        assert_eq!(text_desc.unicode_version(), Some(UNICODE_17_0_0));

        let bin_desc =
            CanonDescriptor::describe_file(ContentKind::Binary, 42, FineTreeOptOut::NotRequested);
        assert_eq!(bin_desc.kind(), FileKind::Binary);
        assert!(bin_desc.fine_tree_present());
        assert_eq!(bin_desc.fine_tree_domain(), Some(FineTreeDomain::Raw));
        assert_eq!(bin_desc.unicode_version(), None);
    }

    /// G4 accept: an empty file (`n == 0`) gets **no** fine tree — no leaves,
    /// no tree (MVP-SPEC.md line 78) — for both kinds and regardless of the
    /// opt-out flag.
    #[test]
    fn empty_file_has_no_fine_tree() {
        for kind in [text(), ContentKind::Binary] {
            for opt_out in FineTreeOptOut::ALL {
                let desc = CanonDescriptor::describe_file(kind, 0, opt_out);
                assert!(!desc.fine_tree_present(), "{kind:?} {opt_out:?}");
                assert_eq!(desc.fine_tree_domain(), None);
                // The size-aware rider agrees with the constructor.
                assert_eq!(desc.validate_with_size(0), Ok(()));
            }
        }
    }

    /// G4 accept: a `--no-fine-tree` match yields `false`, and the model
    /// exposes **no override path** — the descriptor has no mutator and no
    /// alternative constructor that can set presence back to `true` for the
    /// same file (MVP-SPEC.md line 85: "permanently whole-file-reveal only").
    #[test]
    fn no_fine_tree_opt_out_is_false_and_permanent() {
        for kind in [text(), ContentKind::Binary] {
            let desc = CanonDescriptor::describe_file(kind, 4096, FineTreeOptOut::Requested);
            assert!(!desc.fine_tree_present());
            assert_eq!(desc.fine_tree_domain(), None);
            assert_eq!(desc.validate(), Ok(()));
            // Round-tripping the recorded fields cannot resurrect the tree:
            // the only legal reconstruction is the same tree-less descriptor
            // (a `true` presence would need a domain that was never recorded).
            let round_tripped = CanonDescriptor::try_new(
                desc.kind(),
                desc.fine_tree_present(),
                desc.fine_tree_domain(),
                desc.unicode_version(),
            )
            .expect("descriptor round-trips");
            assert_eq!(round_tripped, desc);
            assert_eq!(
                CanonDescriptor::try_new(desc.kind(), true, None, desc.unicode_version()),
                Err(ContentError::FineTreePresentWithoutDomain)
            );
        }
    }

    /// The single kind → domain rule, used by construction and validation
    /// alike (MVP-SPEC.md lines 83, 85).
    #[test]
    fn kind_selects_its_fine_tree_domain() {
        assert_eq!(FileKind::Text.fine_tree_domain(), FineTreeDomain::Canonical);
        assert_eq!(FileKind::Binary.fine_tree_domain(), FineTreeDomain::Raw);
        assert_eq!(text().file_kind(), FileKind::Text);
        assert_eq!(ContentKind::Binary.file_kind(), FileKind::Binary);
        assert_eq!(text().unicode_version(), Some(V));
        assert_eq!(ContentKind::Binary.unicode_version(), None);
        // Display spellings match the spec's own words.
        assert_eq!(FileKind::Text.to_string(), "text");
        assert_eq!(FileKind::Binary.to_string(), "binary");
        assert_eq!(FineTreeDomain::Canonical.to_string(), "canonical");
        assert_eq!(FineTreeDomain::Raw.to_string(), "raw");
    }

    // ── Validation predicate: one distinct error per illegal combination ──

    /// G4 accept: **every** invalid field combination yields its own distinct
    /// error. The four the task names, plus the two completeness riders the
    /// biconditional field set implies (`domain` without a tree; text with a
    /// raw domain) — six in total, pairwise distinct.
    #[test]
    fn each_invalid_combination_yields_a_distinct_error() {
        let cases: [(&str, Result<CanonDescriptor, ContentError>, ContentError); 6] = [
            (
                "binary + canonical domain",
                CanonDescriptor::try_new(
                    FileKind::Binary,
                    true,
                    Some(FineTreeDomain::Canonical),
                    None,
                ),
                ContentError::BinaryCanonicalFineTreeDomain,
            ),
            (
                "text + raw domain",
                CanonDescriptor::try_new(
                    FileKind::Text,
                    true,
                    Some(FineTreeDomain::Raw),
                    Some(UNICODE_17_0_0),
                ),
                ContentError::TextRawFineTreeDomain,
            ),
            (
                "text without unicode_version",
                CanonDescriptor::try_new(
                    FileKind::Text,
                    true,
                    Some(FineTreeDomain::Canonical),
                    None,
                ),
                ContentError::TextMissingUnicodeVersion,
            ),
            (
                "version on binary",
                CanonDescriptor::try_new(
                    FileKind::Binary,
                    true,
                    Some(FineTreeDomain::Raw),
                    Some(UNICODE_17_0_0),
                ),
                ContentError::BinaryUnicodeVersion,
            ),
            (
                "present tree without domain",
                CanonDescriptor::try_new(FileKind::Binary, true, None, None),
                ContentError::FineTreePresentWithoutDomain,
            ),
            (
                "absent tree with domain",
                CanonDescriptor::try_new(FileKind::Binary, false, Some(FineTreeDomain::Raw), None),
                ContentError::FineTreeAbsentWithDomain,
            ),
        ];

        let mut seen = Vec::new();
        for (name, got, want) in cases {
            assert_eq!(got, Err(want), "{name}");
            assert!(!seen.contains(&want.code()), "duplicate error for {name}");
            seen.push(want.code());
        }
        assert_eq!(seen.len(), 6, "six pairwise-distinct rejection codes");
    }

    /// The empty-file rider is its own distinct error, reachable only through
    /// the size-aware check (the descriptor cannot see `n`).
    #[test]
    fn fine_tree_on_empty_file_is_a_distinct_error() {
        let desc =
            CanonDescriptor::try_new(FileKind::Binary, true, Some(FineTreeDomain::Raw), None)
                .expect("legal in isolation");
        assert_eq!(desc.validate(), Ok(()));
        assert_eq!(
            desc.validate_with_size(0),
            Err(ContentError::FineTreePresentOnEmptyFile)
        );
        assert_eq!(desc.validate_with_size(1), Ok(()));
        // A tree-less descriptor is fine at any size (an opted-out non-empty
        // file is exactly that).
        let no_tree = CanonDescriptor::try_new(FileKind::Binary, false, None, None)
            .expect("tree-less is legal");
        assert_eq!(no_tree.validate_with_size(0), Ok(()));
        assert_eq!(no_tree.validate_with_size(9_000), Ok(()));
    }

    /// Error precedence is fixed and documented, so a doubly-illegal input
    /// still produces one deterministic code.
    #[test]
    fn error_precedence_is_deterministic() {
        // Binary + version (rule 1) *and* canonical domain (rule 3): rule 1
        // wins.
        assert_eq!(
            CanonDescriptor::try_new(
                FileKind::Binary,
                true,
                Some(FineTreeDomain::Canonical),
                Some(UNICODE_17_0_0)
            ),
            Err(ContentError::BinaryUnicodeVersion)
        );
        // Text without version (rule 1) *and* absent tree with domain (rule
        // 2): rule 1 wins.
        assert_eq!(
            CanonDescriptor::try_new(FileKind::Text, false, Some(FineTreeDomain::Canonical), None),
            Err(ContentError::TextMissingUnicodeVersion)
        );
        // Tree present without domain (rule 2) beats the kind/domain rule,
        // which has nothing to look at.
        assert_eq!(
            CanonDescriptor::try_new(FileKind::Text, true, None, Some(UNICODE_17_0_0)),
            Err(ContentError::FineTreePresentWithoutDomain)
        );
    }

    /// All four legal shapes are accepted (the complement of the rejection
    /// table above).
    #[test]
    fn legal_combinations_are_accepted() {
        assert!(
            CanonDescriptor::try_new(
                FileKind::Text,
                true,
                Some(FineTreeDomain::Canonical),
                Some(UNICODE_17_0_0)
            )
            .is_ok()
        );
        assert!(
            CanonDescriptor::try_new(FileKind::Text, false, None, Some(UNICODE_17_0_0)).is_ok()
        );
        assert!(
            CanonDescriptor::try_new(FileKind::Binary, true, Some(FineTreeDomain::Raw), None)
                .is_ok()
        );
        assert!(CanonDescriptor::try_new(FileKind::Binary, false, None, None).is_ok());
    }

    // ── Descriptor-recorded version, never "latest" ─────────────────────

    /// The recorded version resolves through G1's registry; binary files
    /// resolve to `None`; an unregistered version is the registry's own
    /// distinct "verifier too old" error, never an integrity verdict
    /// (MVP-SPEC.md line 83; D25).
    #[test]
    fn resolve_unicode_version_uses_the_recorded_string() {
        let text_desc = CanonDescriptor::describe_file(text(), 10, FineTreeOptOut::NotRequested);
        assert_eq!(text_desc.resolve_unicode_version(), Ok(Some(V)));

        let bin_desc =
            CanonDescriptor::describe_file(ContentKind::Binary, 10, FineTreeOptOut::NotRequested);
        assert_eq!(bin_desc.resolve_unicode_version(), Ok(None));

        // A descriptor from a newer antseal: shape-legal, version unknown.
        let future = CanonDescriptor::try_new(
            FileKind::Text,
            true,
            Some(FineTreeDomain::Canonical),
            Some("unicode-99.0.0"),
        )
        .expect("field combination is legal — only the version is unknown");
        assert_eq!(future.validate(), Ok(()));
        assert_eq!(future.unicode_version(), Some("unicode-99.0.0"));
        let err = future
            .resolve_unicode_version()
            .expect_err("unregistered version must not resolve");
        assert_eq!(
            err,
            UnicodeVersionError::UnknownUnicodeVersion {
                requested: "unicode-99.0.0".to_owned()
            }
        );
    }

    /// The recorded string is stored verbatim: no trimming, no case folding,
    /// no substitution of `CURRENT` (MVP-SPEC.md line 83 — the verifier must
    /// see exactly what was sealed).
    #[test]
    fn recorded_version_string_is_verbatim() {
        for recorded in ["unicode-17.0.0", " unicode-17.0.0", "UNICODE-17.0.0", ""] {
            let desc = CanonDescriptor::try_new(FileKind::Text, false, None, Some(recorded))
                .expect("field combination is legal");
            assert_eq!(desc.unicode_version(), Some(recorded));
        }
    }

    // ── Property tests ──────────────────────────────────────────────────

    fn content_kind() -> impl Strategy<Value = ContentKind> {
        prop_oneof![Just(ContentKind::Binary), Just(ContentKind::Text(V))]
    }

    fn opt_out() -> impl Strategy<Value = FineTreeOptOut> {
        prop_oneof![
            Just(FineTreeOptOut::NotRequested),
            Just(FineTreeOptOut::Requested)
        ]
    }

    proptest! {
        #![proptest_config(proptest_config(0x0064_0001))]

        /// `describe_file` never builds an illegal descriptor: its output
        /// passes both the field predicate and the size-aware rider, for
        /// every (kind, size, opt-out) triple.
        #[test]
        fn describe_file_output_always_validates(
            kind in content_kind(),
            size in 0u64..=u64::MAX,
            opt_out in opt_out(),
        ) {
            let desc = CanonDescriptor::describe_file(kind, size, opt_out);
            prop_assert_eq!(desc.validate(), Ok(()));
            prop_assert_eq!(desc.validate_with_size(size), Ok(()));
            // The two biconditionals hold.
            prop_assert_eq!(desc.fine_tree_domain().is_some(), desc.fine_tree_present());
            prop_assert_eq!(
                desc.unicode_version().is_some(),
                desc.kind() == FileKind::Text
            );
            // Presence is exactly the spec's rule.
            prop_assert_eq!(
                desc.fine_tree_present(),
                !opt_out.is_requested() && size > 0
            );
        }

        /// Decode round-trip: every descriptor rebuilt from its own recorded
        /// fields equals the original (what F's encode/decode pair must
        /// preserve).
        #[test]
        fn wire_field_round_trip(
            kind in content_kind(),
            size in 0u64..=u64::MAX,
            opt_out in opt_out(),
        ) {
            let desc = CanonDescriptor::describe_file(kind, size, opt_out);
            let rebuilt = CanonDescriptor::try_new(
                desc.kind(),
                desc.fine_tree_present(),
                desc.fine_tree_domain(),
                desc.unicode_version(),
            );
            prop_assert_eq!(rebuilt, Ok(desc));
        }

        /// Exhaustive legality oracle: over the whole 2×2×3×2 field-value
        /// space, `try_new` accepts exactly the combinations an independent
        /// restatement of MVP-SPEC.md lines 83/85 calls legal.
        #[test]
        fn try_new_accepts_exactly_the_legal_space(
            kind_is_text in any::<bool>(),
            present in any::<bool>(),
            domain_idx in 0usize..3,
            version_present in any::<bool>(),
        ) {
            let kind = if kind_is_text { FileKind::Text } else { FileKind::Binary };
            let domain = [None, Some(FineTreeDomain::Raw), Some(FineTreeDomain::Canonical)]
                [domain_idx];
            let version = version_present.then_some(UNICODE_17_0_0);

            // Independent restatement of the rules.
            let version_ok = version_present == kind_is_text;
            let domain_presence_ok = domain.is_some() == present;
            let domain_value_ok = match domain {
                None => true,
                Some(FineTreeDomain::Canonical) => kind_is_text,
                Some(FineTreeDomain::Raw) => !kind_is_text,
            };
            let legal = version_ok && domain_presence_ok && domain_value_ok;

            prop_assert_eq!(
                CanonDescriptor::try_new(kind, present, domain, version).is_ok(),
                legal
            );
        }
    }
}
