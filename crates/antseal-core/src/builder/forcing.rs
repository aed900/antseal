//! **Test-only forcing seam** for the bundle builder — the hook R14's
//! negative controls drive (tasks/R.md R14 Accept: *"forcing the builder to
//! emit a forbidden item makes the self-check fail"*; decision D70 §7.7 for
//! why the mirror-rule controls target the internal assertions instead).
//!
//! [`build_bundle_forced`] runs the **identical** assembly and the
//! **identical** [`finish`](super::finish) gate as
//! [`build_bundle`](super::build_bundle) — same encode, same mandatory
//! `verify_bundle` self-check, same D70 §7.3 internal assertions — with one
//! typed [`Force`] applied to the assembled sections in between. There is
//! no way to skip a guard through here: the seam exists to prove each guard
//! **can fail**, not to bypass it. What each force is for:
//!
//! | force | the guard it trips | surfaced as |
//! | --- | --- | --- |
//! | [`Force::leak_full_material`] | the mandatory self-check (R4's partial-reveal isolation) | [`BuildError::SelfCheck`] |
//! | [`Force::omit_mirror`] | internal assertion, converse mirror direction — `verify_bundle` **accepts** the shape (frozen `full-no-mirror` vector), D70 §1b | [`BuildError::MirrorMissingFromFullReveal`] |
//! | [`Force::emit_mirror_for`] | internal assertion, forward mirror direction — `verify_bundle` **accepts** the shape (R53 tolerance), D70 §1b | [`BuildError::MirrorEmittedWithoutFullReveal`] |
//! | [`Force::drop_receipt`] / [`Force::inject_receipt`] | internal assertion, receipt ⟺ opted — presence is legal either way on the wire | [`BuildError::ReceiptPresenceMismatch`] |
//! | [`Force::smuggle`] | internal assertion, the post-encode byte scans — the verifier holds no `W` and cannot derive the needles; the carrier is an anchor artifact, whose bytes never fail a bundle (D84 rule F2) | [`BuildError::ForbiddenBytesInEncoding`] |
//!
//! # Feature gate: `test-vectors`, matching R6 for R6's recorded reason
//!
//! R6's `bundle_fixtures` sits on the `test-vectors` tier so the
//! `wasm32-core-tests` lane — whose dev-dependency edge enables
//! `test-vectors` only (P14) — can use it. This seam's negative-control
//! tests run in the same `--lib` binary on both targets, so it takes the
//! same gate. Like everything on that tier it does no I/O, draws no
//! randomness, and activates zero optional dependencies. No production
//! build (CLI, verifier page, wasm lanes) enables the feature, so no
//! shipped builder can emit a forced bundle (R6 seam point 5: the
//! production API has no `Tweak`-equivalent — this seam is not part of the
//! production API and does not compile into it).
//!
//! # Panics
//!
//! On seam **misuse** — naming a file or unit the manifest does not have,
//! omitting a mirror that was never emitted, forcing against inputs that
//! cannot express the target shape. This is R6's own convention for
//! test-only constructors: a malformed forcing is a test bug, and
//! surfacing it as a builder error would silently weaken the negative
//! control built on it. Honest-input paths never panic; they are
//! [`build_bundle`](super::build_bundle)'s.

use crate::bundle::{
    AnchorStatus, FullReveal, NonCoveredReveal, OpaqueBytes, OtsAnchor, ReceiptRecord,
};
use crate::crypto::disclosure::NonCoveredUnitDisclosure;
use crate::crypto::hkdf::{FileId, UnitId, derive_file_salt, derive_fine_seed, derive_unit_key};
use crate::crypto::material::Salt16;
use crate::manifest::Manifest;
use crate::manifest::body::ManifestBodyV1;

use super::{BuildError, BuildInputs, Sections, assemble, disclosed_s_root, finish};

/// What to smuggle into an anchor artifact's opaque bytes so the byte-scan
/// assertions have something to find (each variant is one scan's negative
/// control).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Smuggle {
    /// This file's derived `file_salt` (16 B). Meaningful only for a file
    /// the plan does **not** fully reveal — a full reveal discloses the
    /// salt legitimately and the scan skips it.
    FileSalt(u64),
    /// This file's derived fine seed (32 B). Meaningful only for a
    /// not-fully-revealed file whose manifest records a fine tree.
    FineSeed(u64),
    /// This unit's manifest AEAD nonce (24 B). Meaningful only for a
    /// **revealed** unit — the scan covers exactly those.
    UnitNonce(u64),
}

/// One forced deviation, applied by typed construction between assembly and
/// [`finish`](super::finish) — never by byte-patching, so each control
/// mutates exactly the thing it claims to (the R7 `Tweak` discipline).
///
/// [`Force::default`] forces nothing: `build_bundle_forced` with it is
/// byte-identical to `build_bundle` (asserted by
/// `the_default_force_is_byte_identical_to_the_production_path`).
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct Force {
    /// Attach a `full_reveals` entry — real derived `file_salt`, real
    /// `s_root` when the file has a fine tree — for this file even though
    /// it is not fully revealed. Target a **partially revealed** file: an
    /// untouched file has no `touched_files` entry, so F8's cross-section
    /// rule rejects the shape before the self-check can (a different, also
    /// legitimate, abort).
    pub leak_full_material: Option<u64>,
    /// Remove this fully-revealed mirror-bearing file's emitted mirror
    /// entry, producing the mirror-less full reveal the verifier accepts.
    pub omit_mirror: Option<u64>,
    /// Emit this partially-revealed mirror-bearing file's mirror as an
    /// ordinary §7.12 entry — genuinely derived salt and key, the supplied
    /// ciphertext — producing the R53 shape the verifier accepts.
    pub emit_mirror_for: Option<u64>,
    /// Drop the receipt from the bundle while the caller's opt-in stands.
    pub drop_receipt: bool,
    /// Inject a synthetic receipt the caller never opted in.
    pub inject_receipt: bool,
    /// Embed derived vault material inside an appended OTS anchor
    /// artifact's opaque bytes.
    pub smuggle: Option<Smuggle>,
}

impl Force {
    /// Force nothing — the production shape.
    #[must_use]
    pub fn none() -> Self {
        Self::default()
    }
}

/// [`build_bundle`](super::build_bundle) with `force` applied to the
/// assembled sections — same assembly, same self-check, same internal
/// assertions (module docs).
///
/// # Errors
///
/// As [`build_bundle`](super::build_bundle); the whole point is which
/// [`BuildError`] a given force is refused with.
///
/// # Panics
///
/// On seam misuse (module docs).
pub fn build_bundle_forced(
    mut inputs: BuildInputs<'_>,
    force: &Force,
) -> Result<Vec<u8>, BuildError> {
    let decoded = Manifest::decode(inputs.manifest)?;
    let mut sections = assemble(&inputs, decoded.body())?;

    // The caller's opt-in, captured BEFORE the receipt forces mutate the
    // inputs — desynchronizing the two is exactly what the receipt
    // assertion exists to catch.
    let receipt_opted = inputs.receipt.is_some();

    apply(&mut inputs, decoded.body(), &mut sections, force);

    finish(inputs, decoded.body(), sections, receipt_opted)
}

/// Apply one [`Force`] to the assembled sections (and, for the receipt and
/// smuggle forces, to the not-yet-consumed inputs).
fn apply(
    inputs: &mut BuildInputs<'_>,
    body: &ManifestBodyV1,
    sections: &mut Sections,
    force: &Force,
) {
    let w = inputs.w;

    if let Some(file_id) = force.leak_full_material {
        let entry = file_entry(body, file_id);
        // The derived salt, via the test-vectors byte accessor — the same
        // deliberate C7 bypass R6's `Tweak::leak_full_material` uses; no
        // production path can reach these bytes.
        let file_salt = Salt16::from_bytes(
            *derive_file_salt(w, FileId(file_id)).expose_bytes_for_test_vectors(),
        );
        let s_root = disclosed_s_root(w, file_id, entry)
            .expect("forcing: the target file's fine-tree depth is derivable");
        let at = sections
            .full_reveals
            .partition_point(|full| full.file_id() < file_id);
        sections
            .full_reveals
            .insert(at, FullReveal::new(file_id, file_salt, s_root));
    }

    if let Some(file_id) = force.omit_mirror {
        let mirror_id = mirror_unit_id(body, file_id);
        let before = sections.noncovered.len();
        sections
            .noncovered
            .retain(|reveal| reveal.unit_id() != mirror_id);
        assert_eq!(
            sections.noncovered.len() + 1,
            before,
            "forcing: `omit_mirror` names a file whose mirror was not emitted"
        );
    }

    if let Some(file_id) = force.emit_mirror_for {
        let entry = file_entry(body, file_id);
        let mirror = entry
            .raw_mirror()
            .expect("forcing: `emit_mirror_for` names a mirror-bearing file");
        let mirror_id = mirror.unit_id();
        let ciphertext = inputs
            .unit_ciphertexts
            .get(&mirror_id)
            .expect("forcing: the mirror's ciphertext is supplied")
            .clone();
        let disclosure = NonCoveredUnitDisclosure::for_unit(w, UnitId(mirror_id), mirror.binding())
            .expect("forcing: a raw mirror is always non-covered");
        let reveal = NonCoveredReveal::new(
            mirror_id,
            derive_unit_key(w, UnitId(mirror_id)),
            OpaqueBytes::from_vec(ciphertext),
            Salt16::from_bytes(*disclosure.unit_salt().as_bytes()),
        )
        .expect("forcing: the mirror ciphertext has a valid shape");
        let at = sections
            .noncovered
            .partition_point(|existing| existing.unit_id() < mirror_id);
        sections.noncovered.insert(at, reveal);
    }

    if force.drop_receipt {
        assert!(
            inputs.receipt.is_some(),
            "forcing: `drop_receipt` needs an opted-in receipt to drop"
        );
        inputs.receipt = None;
    }
    if force.inject_receipt {
        assert!(
            inputs.receipt.is_none(),
            "forcing: `inject_receipt` needs a receipt-less input to inject into"
        );
        inputs.receipt = Some(
            ReceiptRecord::new(
                vec![[0xF0; 32]],
                1,
                OpaqueBytes::from_vec(b"forced synthetic receipt (test seam)".to_vec()),
            )
            .expect("forcing: the synthetic receipt is well formed"),
        );
    }

    if let Some(smuggle) = force.smuggle {
        let needle: Vec<u8> = match smuggle {
            Smuggle::FileSalt(file_id) => derive_file_salt(w, FileId(file_id))
                .expose_bytes_for_test_vectors()
                .to_vec(),
            Smuggle::FineSeed(file_id) => derive_fine_seed(w, FileId(file_id)).as_bytes().to_vec(),
            Smuggle::UnitNonce(unit_id) => body
                .files()
                .iter()
                .flat_map(|entry| entry.units())
                .find(|unit| unit.unit_id() == unit_id)
                .expect("forcing: `UnitNonce` names a manifest unit")
                .nonce()
                .as_bytes()
                .to_vec(),
        };
        // The carrier: an anchor artifact's opaque bytes. Anchor artifacts
        // never fail a bundle (D84 rule F2 — an unverifiable artifact
        // renders `invalid` in its own slot), so the self-check passes and
        // only the byte scan can object.
        let mut artifact = b"forced artifact carrying smuggled bytes: ".to_vec();
        artifact.extend_from_slice(&needle);
        inputs.ots_anchors.push(
            OtsAnchor::new(AnchorStatus::Pending, OpaqueBytes::from_vec(artifact), None)
                .expect("forcing: the smuggle artifact is under the D10 caps"),
        );
    }
}

/// The manifest file entry for `file_id`, or a seam-misuse panic.
fn file_entry(body: &ManifestBodyV1, file_id: u64) -> &crate::manifest::body::FileEntry {
    body.files()
        .get(usize::try_from(file_id).expect("forcing: file_id fits usize"))
        .expect("forcing: the named file exists in the manifest")
}

/// The mirror unit id of `file_id`, or a seam-misuse panic.
fn mirror_unit_id(body: &ManifestBodyV1, file_id: u64) -> u64 {
    file_entry(body, file_id)
        .raw_mirror()
        .expect("forcing: the named file has a raw mirror")
        .unit_id()
}
