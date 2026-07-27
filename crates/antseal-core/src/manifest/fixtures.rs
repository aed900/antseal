//! Deterministic manifest fixtures — **NON-PRODUCTION**, compiled only
//! under the `test-util` feature (the `FileSalt` test accessor's
//! precedent).
//!
//! Every byte here is fixed test data under the secret-material
//! convention of `testdata/README.md`: commitments, nonces, addresses,
//! keys and `seal_id`s are recognisable constant patterns, never real or
//! derived-from-real material, and nothing is randomly generated. They
//! are shared by this module tree's unit tests, by the F5/F6/F7
//! integration suites, and by the `manifest-ids` golden-vector executor,
//! so a committed vector and an in-repo assertion can never drift apart.
//!
//! The fixtures deliberately span the F5 accept matrix:
//!
//! | fixture | shape |
//! | --- | --- |
//! | [`text_with_mirror_body`] | text file, fine tree, two units + a raw mirror (D23: mirror last) |
//! | [`binary_single_unit_body`] | binary file, fine tree, one unit |
//! | [`no_fine_tree_body`] | `--no-fine-tree` text file — whole-file unit with a `unit_commit` |
//! | [`empty_file_body`] | empty file: `size` 0, one unit, `true_length` 0, no fine tree |
//! | [`multi_file_split_body`] | three files, `--split`-shaped, mixed modes |
//! | [`ed25519_only_body`] | the reserved `sig_policy = [ed25519]` fallback shape |

use crate::crypto::commit::CommitmentDigest;
use crate::crypto::disclosure::UnitBinding;
use crate::crypto::error::SigAlg;
use crate::crypto::secrets::SealId;

use super::body::{
    ByteRange, CanonMode, ContentAddress, FileEntry, FineTree, ManifestBodyV1, Nonce24, encode_body,
};
use super::envelope::encode_envelope;
use super::registry::{UnitKind, pubkey_len, sig_len};
use super::sigmap::{SigAlgMap, SigMaterial};

/// The Unicode data version every text fixture records (decision D25).
pub const UNICODE_VERSION: &str = "unicode-17.0.0";

/// The `app_version` string every fixture records — a fixed placeholder,
/// never the real crate version, so a version bump cannot silently
/// change committed vector bytes.
pub const APP_VERSION: &str = "antseal-fixture/1";

/// The `claimed_time` every fixture records: 2026-01-01T00:00:00Z as
/// POSIX seconds (registry §3). Fixed, so fixtures are time-independent.
pub const CLAIMED_TIME: u64 = 1_767_225_600;

/// A recognisable 32-byte fixture value: every byte is `seed`.
#[must_use]
pub const fn commit32(seed: u8) -> CommitmentDigest {
    [seed; 32]
}

/// A recognisable 24-byte fixture nonce.
#[must_use]
pub const fn nonce(seed: u8) -> Nonce24 {
    Nonce24::from_bytes([seed; 24])
}

/// A recognisable 32-byte fixture address.
#[must_use]
pub const fn address(seed: u8) -> ContentAddress {
    ContentAddress::from_bytes([seed; 32])
}

/// The fixture `seal_id`: `00 01 02 … 0f` (NON-SECRET, and distinct from
/// the 32-byte `TEST_MASTER_SECRET_W` pattern it echoes).
#[must_use]
pub fn seal_id() -> SealId {
    let mut bytes = [0u8; 16];
    let mut i = 0usize;
    while i < 16 {
        bytes[i] = i as u8;
        i += 1;
    }
    SealId::from_bytes(bytes)
}

/// A `pubkeys` map covering the hybrid policy, with per-algorithm
/// constant-pattern keys of the exact registry lengths.
#[must_use]
pub fn hybrid_pubkeys() -> SigAlgMap {
    SigAlgMap::new(
        SigMaterial::Pubkey,
        [
            (
                SigAlg::Ed25519,
                vec![0xE1; pubkey_len(SigAlg::Ed25519) as usize],
            ),
            (
                SigAlg::MlDsa65,
                vec![0xD1; pubkey_len(SigAlg::MlDsa65) as usize],
            ),
        ],
    )
    .expect("fixture pubkeys are well formed")
}

/// The Ed25519-only `pubkeys` map (the ML-DSA-probe fallback shape).
#[must_use]
pub fn ed25519_pubkeys() -> SigAlgMap {
    SigAlgMap::new(
        SigMaterial::Pubkey,
        [(
            SigAlg::Ed25519,
            vec![0xE1; pubkey_len(SigAlg::Ed25519) as usize],
        )],
    )
    .expect("fixture pubkeys are well formed")
}

/// A `signatures` map matching [`hybrid_pubkeys`].
#[must_use]
pub fn hybrid_signatures() -> SigAlgMap {
    SigAlgMap::new(
        SigMaterial::Signature,
        [
            (
                SigAlg::Ed25519,
                vec![0x51; sig_len(SigAlg::Ed25519) as usize],
            ),
            (
                SigAlg::MlDsa65,
                vec![0x52; sig_len(SigAlg::MlDsa65) as usize],
            ),
        ],
    )
    .expect("fixture signatures are well formed")
}

/// A covered (fine-tree) normal unit.
#[must_use]
fn covered_unit(unit_id: u64, start: u64, length: u64, seed: u8) -> super::body::UnitEntry {
    super::body::UnitEntry::new(
        unit_id,
        UnitKind::Normal,
        ByteRange::new(start, length),
        length,
        UnitBinding::FineTreeCovered,
        nonce(seed),
        address(seed.wrapping_add(0x40)),
    )
}

/// A non-covered unit (raw mirror, or a unit of a `--no-fine-tree` file).
#[must_use]
fn noncovered_unit(
    unit_id: u64,
    kind: UnitKind,
    start: u64,
    length: u64,
    seed: u8,
) -> super::body::UnitEntry {
    super::body::UnitEntry::new(
        unit_id,
        kind,
        ByteRange::new(start, length),
        length,
        UnitBinding::NonCovered {
            unit_commit: commit32(seed.wrapping_add(0x20)),
        },
        nonce(seed),
        address(seed.wrapping_add(0x40)),
    )
}

/// A text file with a fine tree, two canonical units, and a raw mirror
/// appended last (decision D23).
#[must_use]
pub fn text_file_with_mirror(first_unit_id: u64) -> FileEntry {
    FileEntry::new(
        commit32(0x01),
        commit32(0x02),
        CanonMode::Text {
            canon_commit: commit32(0x03),
            unicode_version: UNICODE_VERSION.to_owned(),
        },
        1024,
        FineTree::Present {
            root: commit32(0x04),
        },
        vec![
            covered_unit(first_unit_id, 0, 512, 0x11),
            covered_unit(first_unit_id + 1, 512, 512, 0x12),
            // D23: the mirror is the file's LAST unit. It is never
            // fine-tree-covered (raw byte domain), so it carries a
            // unit_commit even though the file has a tree.
            noncovered_unit(first_unit_id + 2, UnitKind::RawMirror, 0, 1030, 0x13),
        ],
    )
    .expect("fixture file entry is well formed")
}

/// A binary file with a fine tree and a single unit.
#[must_use]
pub fn binary_file(first_unit_id: u64) -> FileEntry {
    FileEntry::new(
        commit32(0x21),
        commit32(0x22),
        CanonMode::Binary,
        4096,
        FineTree::Present {
            root: commit32(0x24),
        },
        vec![covered_unit(first_unit_id, 0, 4096, 0x31)],
    )
    .expect("fixture file entry is well formed")
}

/// A `--no-fine-tree` text file: one whole-file unit carrying a
/// `unit_commit`, and no `fine_root`.
#[must_use]
pub fn no_fine_tree_file(first_unit_id: u64) -> FileEntry {
    FileEntry::new(
        commit32(0x41),
        commit32(0x42),
        CanonMode::Text {
            canon_commit: commit32(0x43),
            unicode_version: UNICODE_VERSION.to_owned(),
        },
        700,
        FineTree::Absent,
        vec![noncovered_unit(
            first_unit_id,
            UnitKind::Normal,
            0,
            700,
            0x51,
        )],
    )
    .expect("fixture file entry is well formed")
}

/// An empty file: `size` 0, no fine tree (G4), one empty unit whose range
/// is `[0, 0]` and whose `true_length` is 0 (spec line 78).
#[must_use]
pub fn empty_file(first_unit_id: u64) -> FileEntry {
    FileEntry::new(
        commit32(0x61),
        commit32(0x62),
        CanonMode::Binary,
        0,
        FineTree::Absent,
        vec![noncovered_unit(first_unit_id, UnitKind::Normal, 0, 0, 0x71)],
    )
    .expect("fixture file entry is well formed")
}

/// Body: one text file with a raw mirror, hybrid policy.
#[must_use]
pub fn text_with_mirror_body() -> ManifestBodyV1 {
    body_with(
        vec![text_file_with_mirror(0)],
        hybrid_pubkeys(),
        vec![SigAlg::Ed25519, SigAlg::MlDsa65],
    )
}

/// Body: one binary file, single unit, hybrid policy.
#[must_use]
pub fn binary_single_unit_body() -> ManifestBodyV1 {
    body_with(
        vec![binary_file(0)],
        hybrid_pubkeys(),
        vec![SigAlg::Ed25519, SigAlg::MlDsa65],
    )
}

/// Body: one `--no-fine-tree` file.
#[must_use]
pub fn no_fine_tree_body() -> ManifestBodyV1 {
    body_with(
        vec![no_fine_tree_file(0)],
        hybrid_pubkeys(),
        vec![SigAlg::Ed25519, SigAlg::MlDsa65],
    )
}

/// Body: one empty file.
#[must_use]
pub fn empty_file_body() -> ManifestBodyV1 {
    body_with(
        vec![empty_file(0)],
        hybrid_pubkeys(),
        vec![SigAlg::Ed25519, SigAlg::MlDsa65],
    )
}

/// Body: three files (text-with-mirror, binary, `--no-fine-tree`) whose
/// unit ids run 0..5 work-globally — the `--split`-shaped case.
#[must_use]
pub fn multi_file_split_body() -> ManifestBodyV1 {
    body_with(
        vec![
            text_file_with_mirror(0),
            binary_file(3),
            no_fine_tree_file(4),
        ],
        hybrid_pubkeys(),
        vec![SigAlg::Ed25519, SigAlg::MlDsa65],
    )
}

/// Body: the reserved Ed25519-only fallback policy (spec line 97 — the
/// format is unchanged, the slot is simply unused).
#[must_use]
pub fn ed25519_only_body() -> ManifestBodyV1 {
    body_with(
        vec![binary_file(0)],
        ed25519_pubkeys(),
        vec![SigAlg::Ed25519],
    )
}

fn body_with(files: Vec<FileEntry>, pubkeys: SigAlgMap, sig_policy: Vec<SigAlg>) -> ManifestBodyV1 {
    ManifestBodyV1::new(
        APP_VERSION.to_owned(),
        seal_id(),
        "fixture work".to_owned(),
        CLAIMED_TIME,
        pubkeys,
        sig_policy,
        files,
    )
    .expect("fixture body is well formed")
}

/// An encoded fixture: the canonical body bytes and the envelope that
/// embeds them, in the spec's pipeline order (line 90).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedFixture {
    /// Canonical body bytes — the `work_id` pre-image.
    pub body: Vec<u8>,
    /// Full envelope bytes — the `anchor_digest` pre-image.
    pub envelope: Vec<u8>,
}

/// Encode a body and wrap it in an envelope carrying `signatures`.
#[must_use]
pub fn seal(body: ManifestBodyV1, signatures: &SigAlgMap) -> SealedFixture {
    let body = encode_body(body).expect("fixture body encodes");
    let envelope = encode_envelope(&body, signatures).expect("fixture envelope encodes");
    SealedFixture { body, envelope }
}

/// [`text_with_mirror_body`] sealed with [`hybrid_signatures`].
#[must_use]
pub fn text_with_mirror_manifest() -> SealedFixture {
    seal(text_with_mirror_body(), &hybrid_signatures())
}

/// [`binary_single_unit_body`] sealed with [`hybrid_signatures`].
#[must_use]
pub fn binary_single_unit_manifest() -> SealedFixture {
    seal(binary_single_unit_body(), &hybrid_signatures())
}

/// [`multi_file_split_body`] sealed with [`hybrid_signatures`] — the
/// fixture the `manifest-ids` golden vectors pin.
#[must_use]
pub fn multi_file_split_manifest() -> SealedFixture {
    seal(multi_file_split_body(), &hybrid_signatures())
}

/// The same fixture with **one signature byte flipped** — same body, so
/// the same `work_id`, but a different `anchor_digest` (F7 accept).
#[must_use]
pub fn multi_file_split_manifest_mutated_signature() -> SealedFixture {
    let mut signatures: Vec<(SigAlg, Vec<u8>)> = hybrid_signatures()
        .iter()
        .map(|(alg, bytes)| (alg, bytes.to_vec()))
        .collect();
    // Flip the low bit of the Ed25519 signature's first byte.
    for (alg, bytes) in &mut signatures {
        if *alg == SigAlg::Ed25519 {
            bytes[0] ^= 0x01;
        }
    }
    let signatures = SigAlgMap::new(SigMaterial::Signature, signatures)
        .expect("mutated fixture signatures keep their lengths");
    seal(multi_file_split_body(), &signatures)
}
