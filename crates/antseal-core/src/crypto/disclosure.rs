//! Commitment-mode and salt-disclosure rules, encoded as unrepresentable
//! misuse in the API type system (tasks/C.md C7; MVP-SPEC.md lines 94–95,
//! 114, 121).
//!
//! Two normative rules live here:
//!
//! # Rule 1 — `unit_commit` presence **iff** not fine-tree-covered (line 94)
//!
//! For a fine-tree-covered unit there is **no** `unit_commit`: its content
//! is bound *solely* by `fine_root`, so a per-unit reveal and a v1.1
//! byte-range reveal of overlapping bytes cannot disagree. Committing the
//! same bytes under **two** independent salted hashes (`unit_commit` *and*
//! `fine_root`), cross-checked only on a full reveal the sealer may never
//! issue, would let a malicious sealer open byte *i* to X via `unit_commit`
//! for one counterparty and to Y ≠ X via a `fine_root` range proof for
//! another — under one anchored `work_id`. That is a break of "proof it
//! belongs to what you sealed", frozen unfixably at M0. Hence the
//! **single-authoritative-commitment rule**, made structural by
//! [`UnitBinding`]: the `FineTreeCovered` variant *has no field* to carry a
//! commitment, so generation code cannot construct a covered unit with a
//! `unit_commit` — the misuse does not compile (see the `compile_fail`
//! doc-test on [`UnitBinding`]).
//!
//! # Rule 2 — `file_salt` discloses only on a full-file reveal (line 95)
//!
//! `canon_commit`/`raw_commit` sit in the manifest embedded in **every**
//! bundle. A shared or early-disclosed `file_salt` would therefore hand any
//! recipient of a single-unit partial reveal an **offline full-file
//! confirmation oracle**: recompute `canon_commit` for a guessed document
//! and compare — exactly the confirmation attack this design exists to
//! prevent. So `file_salt` is disclosed **only on a full-file reveal**,
//! where the content is shown anyway (zero marginal disclosure). The
//! generation-side guarantee is structural: the salts API returns the
//! opaque [`FileSalt`] (no byte accessor — see
//! [`crate::crypto::material::FileSalt`]), and the only public byte path is
//! [`FullFileRevealDisclosure::file_salt_bytes`], whose construction
//! requires a [`FullFileRevealContext`] witness. R's M3 bundle builder
//! cannot leak `file_salt` on a partial reveal even by bug: the
//! partial-reveal type ([`PartialRevealDisclosure`]) has no slot for it.
//!
//! By contrast (line 95): **`path_salt` is freely obtainable per touched
//! file** (it salts only `path_commit`, and ships whenever any reveal
//! touches the file) and **`unit_salt` per revealed non-covered unit**
//! (gated on [`UnitBinding::NonCovered`] by
//! [`NonCoveredUnitDisclosure::for_unit`]).
//!
//! # What is *not* here
//!
//! The symmetric guard for `s_root`/GGM ancestor seeds — no seed that is an
//! ancestor of any unrevealed leaf ever leaves the vault; `s_root` conveys
//! only on a full-file reveal — is G's machinery (G11; spec line 96). A
//! full reveal's disclosure set is `{file_salt}` from this module *plus*
//! `s_root` from G's side, attached to the same full-reveal context.
//! The verifier-side tamper check "`file_salt`/`s_root` present for an
//! only-partially-revealed file" (line 121) is R's; this module supplies
//! the generation-side types plus [`encoded_output_contains_file_salt`],
//! the runtime serialization assertion R reuses.

use super::commit::CommitmentDigest;
use super::hkdf::{FileId, UnitId, derive_file_salt, derive_path_salt, derive_unit_salt};
use super::material::{FileSalt, MasterSecretRef, Salt16};

/// How a unit's content is bound in the manifest — the structural encoding
/// of the line-94 single-authoritative-commitment rule (module docs,
/// Rule 1). F's manifest schema carries `unit_commit` as a kind-conditional
/// field derived from exactly this shape.
///
/// A covered unit **cannot** carry a `unit_commit` — the variant has no
/// such field:
///
/// ```compile_fail,E0559
/// use antseal_core::crypto::disclosure::UnitBinding;
///
/// // error[E0559]: variant `UnitBinding::FineTreeCovered` has no field
/// // named `unit_commit` — the single-authoritative-commitment rule of
/// // MVP-SPEC.md line 94 is structural, not a convention.
/// let binding = UnitBinding::FineTreeCovered { unit_commit: [0u8; 32] };
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnitBinding {
    /// The unit's bytes are covered by the file's fine tree: content is
    /// bound **solely** by `fine_root` (G's leaf-range machinery verifies
    /// reveals). No `unit_commit` exists — deliberately unrepresentable.
    FineTreeCovered,
    /// The unit is NOT fine-tree-covered — only `--no-fine-tree`
    /// whole-file units and raw-mirror units (which live in the raw byte
    /// domain the canonical fine tree does not cover; spec lines 92, 94).
    /// Content is bound by this `unit_commit`.
    NonCovered {
        /// `unit_commit = SHA-256(0x02 ‖ unit_salt ‖ unit_bytes)`
        /// ([`crate::crypto::commit::unit_commit`]).
        unit_commit: CommitmentDigest,
    },
}

impl UnitBinding {
    /// The unit's `unit_commit`, present iff the unit is not covered — the
    /// exact kind-conditional field F's manifest schema stores (spec
    /// line 98).
    #[must_use]
    pub const fn unit_commit(&self) -> Option<&CommitmentDigest> {
        match self {
            Self::FineTreeCovered => None,
            Self::NonCovered { unit_commit } => Some(unit_commit),
        }
    }

    /// Whether the unit's bytes are fine-tree-covered.
    #[must_use]
    pub const fn is_fine_tree_covered(&self) -> bool {
        matches!(self, Self::FineTreeCovered)
    }
}

/// The disclosure for one revealed **non-covered** unit: `{unit_id,
/// unit_salt}` (spec line 114). Constructible only against a
/// [`UnitBinding::NonCovered`] binding — a covered unit's reveal goes
/// through G's GGM sub-cover instead and has no `unit_salt` to ship.
#[derive(Debug)]
pub struct NonCoveredUnitDisclosure {
    unit_id: UnitId,
    unit_salt: Salt16,
}

impl NonCoveredUnitDisclosure {
    /// Derive the disclosure for a revealed unit, iff the unit is
    /// non-covered (line 95: `unit_salt` per revealed non-covered unit).
    /// Returns `None` for a fine-tree-covered unit — there is nothing to
    /// disclose at this layer, and shipping a salt for a unit whose
    /// commitment does not exist would be pure confusion surface.
    #[must_use]
    pub fn for_unit(
        w: MasterSecretRef<'_>,
        unit_id: UnitId,
        binding: &UnitBinding,
    ) -> Option<Self> {
        match binding {
            UnitBinding::FineTreeCovered => None,
            UnitBinding::NonCovered { .. } => Some(Self {
                unit_id,
                unit_salt: derive_unit_salt(w, unit_id),
            }),
        }
    }

    /// The unit this disclosure opens.
    #[must_use]
    pub const fn unit_id(&self) -> UnitId {
        self.unit_id
    }

    /// The disclosed `unit_salt` (freely shippable for a revealed
    /// non-covered unit; spec lines 94, 114).
    #[must_use]
    pub const fn unit_salt(&self) -> &Salt16 {
        &self.unit_salt
    }
}

/// The per-file disclosure set of a **partial** reveal (the file is
/// *touched* but not fully revealed): `path_salt` + the revealed
/// non-covered units' salts. **Structurally contains no `file_salt`** —
/// the type has no slot for one, so R's bundle builder cannot leak it even
/// by bug (module docs, Rule 2):
///
/// ```compile_fail,E0599
/// use antseal_core::crypto::disclosure::PartialRevealDisclosure;
/// use antseal_core::crypto::hkdf::FileId;
/// use antseal_core::crypto::material::MasterSecretRef;
///
/// let w_bytes = [0u8; 32];
/// let w = MasterSecretRef::from_bytes(&w_bytes);
/// let partial = PartialRevealDisclosure::new(w, FileId(0));
/// // error[E0599]: no `file_salt_bytes` on a partial disclosure — only
/// // `FullFileRevealDisclosure` has the accessor (MVP-SPEC.md line 95).
/// let leaked = partial.file_salt_bytes();
/// ```
#[derive(Debug)]
pub struct PartialRevealDisclosure {
    file_id: FileId,
    path_salt: Salt16,
    revealed_units: Vec<NonCoveredUnitDisclosure>,
}

impl PartialRevealDisclosure {
    /// Open the disclosure set for a touched file: derives `path_salt`
    /// (which ships whenever any reveal touches the file, so the recipient
    /// can verify the path; spec line 95).
    #[must_use]
    pub fn new(w: MasterSecretRef<'_>, file_id: FileId) -> Self {
        Self {
            file_id,
            path_salt: derive_path_salt(w, file_id),
            revealed_units: Vec::new(),
        }
    }

    /// Attach a revealed non-covered unit's disclosure (build one with
    /// [`NonCoveredUnitDisclosure::for_unit`]).
    pub fn add_revealed_unit(&mut self, unit: NonCoveredUnitDisclosure) {
        self.revealed_units.push(unit);
    }

    /// The file this disclosure touches.
    #[must_use]
    pub const fn file_id(&self) -> FileId {
        self.file_id
    }

    /// The disclosed `path_salt` (freely obtainable per touched file).
    #[must_use]
    pub const fn path_salt(&self) -> &Salt16 {
        &self.path_salt
    }

    /// The revealed non-covered units' disclosures.
    #[must_use]
    pub fn revealed_units(&self) -> &[NonCoveredUnitDisclosure] {
        &self.revealed_units
    }
}

/// Witness that a reveal covers **every** non-mirror unit of a file — the
/// structural precondition for disclosing `file_salt` (module docs,
/// Rule 2).
///
/// [`attest`](Self::attest) checks the claim against the file's complete
/// non-mirror unit-id list (from the manifest; raw-mirror units are exempt
/// from tiling/full-reveal concatenation by `kind`, spec line 92) and the
/// revealed set. Lying to this constructor about `all_non_mirror_units`
/// can only leak the *caller's own* `file_salt` (generation side holds
/// `W`); the point of the witness is that honest builder code paths cannot
/// drift into partial-reveal leakage. M3's bundle builder (R) is expected
/// to call this with the real manifest unit table.
#[derive(Debug)]
pub struct FullFileRevealContext {
    file_id: FileId,
}

impl FullFileRevealContext {
    /// Attest that `revealed_units` is exactly the file's complete
    /// non-mirror unit set. Returns `None` — no context, hence no
    /// `file_salt` — when the sets differ, either list holds duplicates,
    /// or the unit list is empty (every file tiles `[0, size)` with at
    /// least one unit, spec line 121; an empty attestation is vacuous and
    /// refused).
    #[must_use]
    pub fn attest(
        file_id: FileId,
        all_non_mirror_units: &[UnitId],
        revealed_units: &[UnitId],
    ) -> Option<Self> {
        fn sorted_dedup_checked(ids: &[UnitId]) -> Option<Vec<u64>> {
            let mut sorted: Vec<u64> = ids.iter().map(|id| id.0).collect();
            sorted.sort_unstable();
            if sorted.windows(2).any(|pair| pair[0] == pair[1]) {
                return None;
            }
            Some(sorted)
        }

        if all_non_mirror_units.is_empty() {
            return None;
        }
        let all = sorted_dedup_checked(all_non_mirror_units)?;
        let revealed = sorted_dedup_checked(revealed_units)?;
        (all == revealed).then_some(Self { file_id })
    }

    /// The fully revealed file.
    #[must_use]
    pub const fn file_id(&self) -> FileId {
        self.file_id
    }
}

/// The per-file disclosure set of a **full-file** reveal — the one place
/// `file_salt` bytes become publicly reachable (module docs, Rule 2; spec
/// lines 95, 114). Carries `path_salt` too (a full reveal touches the
/// file). G's side attaches `s_root` (the full `[0, n)` cover — discloses
/// nothing, since every leaf is revealed) to the same context (G11;
/// referenced, not implemented here).
///
/// ```
/// use antseal_core::crypto::disclosure::{FullFileRevealContext, FullFileRevealDisclosure};
/// use antseal_core::crypto::hkdf::{FileId, UnitId};
/// use antseal_core::crypto::material::MasterSecretRef;
///
/// // Fixed, public, NON-SECRET fixture W (project rule 6).
/// let w_bytes = [0x07u8; 32];
/// let w = MasterSecretRef::from_bytes(&w_bytes);
///
/// // The file's complete non-mirror unit set, fully revealed:
/// let all = [UnitId(0), UnitId(1)];
/// let ctx = FullFileRevealContext::attest(FileId(0), &all, &[UnitId(1), UnitId(0)])
///     .expect("exact coverage attests");
/// let full = FullFileRevealDisclosure::new(w, ctx);
/// assert_eq!(full.file_salt_bytes().len(), 16);
///
/// // A partial reveal cannot mint the context — no context, no file_salt:
/// assert!(FullFileRevealContext::attest(FileId(0), &all, &[UnitId(0)]).is_none());
/// ```
#[derive(Debug)]
pub struct FullFileRevealDisclosure {
    file_id: FileId,
    path_salt: Salt16,
    file_salt: FileSalt,
}

impl FullFileRevealDisclosure {
    /// Derive the full-reveal disclosure set for the attested file:
    /// `{path_salt, file_salt}`.
    #[must_use]
    pub fn new(w: MasterSecretRef<'_>, context: FullFileRevealContext) -> Self {
        let file_id = context.file_id();
        Self {
            file_id,
            path_salt: derive_path_salt(w, file_id),
            file_salt: derive_file_salt(w, file_id),
        }
    }

    /// The fully revealed file.
    #[must_use]
    pub const fn file_id(&self) -> FileId {
        self.file_id
    }

    /// The disclosed `path_salt`.
    #[must_use]
    pub const fn path_salt(&self) -> &Salt16 {
        &self.path_salt
    }

    /// The disclosed `file_salt` bytes — **the only public byte path to a
    /// derived `file_salt` in the crate** (module docs, Rule 2). Reaching
    /// this required a [`FullFileRevealContext`], i.e. the full-reveal
    /// context, where the file's content is shown anyway (zero marginal
    /// disclosure, spec line 95).
    #[must_use]
    pub const fn file_salt_bytes(&self) -> &[u8; 16] {
        self.file_salt.as_salt().as_bytes()
    }
}

/// Runtime serialization assertion (the helper R's builder reuses, C7
/// accept): does `encoded` — a serialized partial-reveal bundle or
/// disclosure blob — contain the file's `file_salt` as a byte
/// subsequence?
///
/// Derives the salt internally from `W` (builder side holds `W`) and scans;
/// only a `bool` comes back, so nothing is exposed. A false positive needs
/// an accidental 16-byte collision (~2⁻¹²⁸ per offset — negligible). R
/// asserts this returns `false` for every partially-revealed file's output
/// before emitting a bundle (defense-in-depth on top of the type-level
/// guarantee; verifier-side rejection of a present `file_salt` is R's
/// line-121 tamper check).
#[must_use]
pub fn encoded_output_contains_file_salt(
    w: MasterSecretRef<'_>,
    file_id: FileId,
    encoded: &[u8],
) -> bool {
    let file_salt = derive_file_salt(w, file_id);
    let needle: &[u8] = file_salt.as_salt().as_bytes();
    encoded.windows(needle.len()).any(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Fixed, public, NON-SECRET test master secret (project rule 6).
    const TEST_W: [u8; 32] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
        0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D,
        0x1E, 0x1F,
    ];

    fn w() -> MasterSecretRef<'static> {
        MasterSecretRef::from_bytes(&TEST_W)
    }

    /// Rule 1: the kind-conditional `unit_commit` accessor — `None` iff
    /// covered (spec lines 94, 98).
    #[test]
    fn unit_commit_present_iff_not_covered() {
        let covered = UnitBinding::FineTreeCovered;
        assert!(covered.is_fine_tree_covered());
        assert_eq!(covered.unit_commit(), None);

        let digest = [0x11u8; 32];
        let non_covered = UnitBinding::NonCovered {
            unit_commit: digest,
        };
        assert!(!non_covered.is_fine_tree_covered());
        assert_eq!(non_covered.unit_commit(), Some(&digest));
    }

    /// `unit_salt` is obtainable only per revealed **non-covered** unit
    /// (line 95): the disclosure constructor refuses covered bindings.
    #[test]
    fn unit_salt_disclosure_gated_on_non_covered() {
        let covered = UnitBinding::FineTreeCovered;
        assert!(NonCoveredUnitDisclosure::for_unit(w(), UnitId(3), &covered).is_none());

        let non_covered = UnitBinding::NonCovered {
            unit_commit: [0u8; 32],
        };
        let disclosure = NonCoveredUnitDisclosure::for_unit(w(), UnitId(3), &non_covered)
            .expect("non-covered units disclose their unit_salt");
        assert_eq!(disclosure.unit_id(), UnitId(3));
        // The disclosed salt is the C2 derivation for that unit.
        let expected = crate::crypto::hkdf::derive_unit_salt(w(), UnitId(3));
        assert_eq!(disclosure.unit_salt().as_bytes(), expected.as_bytes());
    }

    /// `path_salt` is freely obtainable per touched file and matches the C2
    /// derivation.
    #[test]
    fn path_salt_freely_obtainable_per_touched_file() {
        let partial = PartialRevealDisclosure::new(w(), FileId(9));
        let expected = crate::crypto::hkdf::derive_path_salt(w(), FileId(9));
        assert_eq!(partial.path_salt().as_bytes(), expected.as_bytes());
        assert_eq!(partial.file_id(), FileId(9));
    }

    /// C7 accept: a partial-reveal disclosure set provably contains no
    /// `file_salt` — runtime serialization assertion over everything the
    /// type can emit.
    #[test]
    fn partial_reveal_serialization_contains_no_file_salt() {
        let file_id = FileId(4);
        let mut partial = PartialRevealDisclosure::new(w(), file_id);
        let binding = UnitBinding::NonCovered {
            unit_commit: [0x22u8; 32],
        };
        for unit in [UnitId(7), UnitId(8)] {
            partial.add_revealed_unit(
                NonCoveredUnitDisclosure::for_unit(w(), unit, &binding)
                    .expect("non-covered discloses"),
            );
        }

        // Serialize every byte the partial-disclosure type exposes, the way
        // a (buggy) builder would: path_salt + each unit's (id, salt).
        let mut encoded = Vec::new();
        encoded.extend_from_slice(partial.path_salt().as_bytes());
        for unit in partial.revealed_units() {
            encoded.extend_from_slice(&unit.unit_id().0.to_le_bytes());
            encoded.extend_from_slice(unit.unit_salt().as_bytes());
        }

        assert!(
            !encoded_output_contains_file_salt(w(), file_id, &encoded),
            "partial-reveal output must not contain the file's file_salt"
        );
    }

    /// C7 accept: a full-file reveal yields exactly `{file_salt}` at this
    /// layer (`s_root` is G's, referenced not implemented) — the bytes
    /// equal the C2 derivation, and the serialization helper finds them.
    #[test]
    fn full_reveal_disclosure_yields_the_derived_file_salt() {
        let file_id = FileId(4);
        let all = [UnitId(0), UnitId(1), UnitId(2)];
        let ctx = FullFileRevealContext::attest(file_id, &all, &[UnitId(2), UnitId(0), UnitId(1)])
            .expect("exact coverage attests");
        assert_eq!(ctx.file_id(), file_id);
        let full = FullFileRevealDisclosure::new(w(), ctx);

        // The disclosed bytes are the real derivation (cross-checked via
        // the test-util vector accessor).
        let derived = crate::crypto::hkdf::derive_file_salt(w(), file_id);
        assert_eq!(
            full.file_salt_bytes(),
            derived.expose_bytes_for_test_vectors()
        );

        // And the serialization helper detects them in an encoded blob.
        let mut encoded = Vec::new();
        encoded.extend_from_slice(full.path_salt().as_bytes());
        encoded.extend_from_slice(full.file_salt_bytes());
        assert!(encoded_output_contains_file_salt(w(), file_id, &encoded));

        // path_salt also ships (a full reveal touches the file).
        let expected_path_salt = crate::crypto::hkdf::derive_path_salt(w(), file_id);
        assert_eq!(full.path_salt().as_bytes(), expected_path_salt.as_bytes());
    }

    /// The full-reveal witness refuses every non-exact coverage claim:
    /// missing unit, extra unit, duplicates, and the vacuous empty file.
    #[test]
    fn full_reveal_context_requires_exact_coverage() {
        let file_id = FileId(1);
        let all = [UnitId(10), UnitId(11), UnitId(12)];

        // Exact, order-insensitive: attests.
        assert!(
            FullFileRevealContext::attest(file_id, &all, &[UnitId(12), UnitId(10), UnitId(11)])
                .is_some()
        );

        // Missing one revealed unit: refused.
        assert!(FullFileRevealContext::attest(file_id, &all, &[UnitId(10), UnitId(11)]).is_none());
        // Extra unit not in the file: refused.
        assert!(
            FullFileRevealContext::attest(
                file_id,
                &all,
                &[UnitId(10), UnitId(11), UnitId(12), UnitId(13)]
            )
            .is_none()
        );
        // Duplicate in the revealed list: refused.
        assert!(
            FullFileRevealContext::attest(
                file_id,
                &all,
                &[UnitId(10), UnitId(10), UnitId(11), UnitId(12)]
            )
            .is_none()
        );
        // Duplicate in the claimed unit table: refused.
        assert!(
            FullFileRevealContext::attest(
                file_id,
                &[UnitId(10), UnitId(10)],
                &[UnitId(10), UnitId(10)]
            )
            .is_none()
        );
        // Vacuous empty attestation: refused.
        assert!(FullFileRevealContext::attest(file_id, &[], &[]).is_none());
    }

    /// The serialization helper does not false-positive on unrelated bytes
    /// and does not treat the (freely disclosed) path/unit salts as
    /// file_salt.
    #[test]
    fn contains_file_salt_helper_is_specific() {
        let file_id = FileId(2);
        assert!(!encoded_output_contains_file_salt(w(), file_id, &[]));
        assert!(!encoded_output_contains_file_salt(w(), file_id, &[0u8; 64]));
        let path_salt = crate::crypto::hkdf::derive_path_salt(w(), file_id);
        assert!(!encoded_output_contains_file_salt(
            w(),
            file_id,
            path_salt.as_bytes()
        ));
    }
}
