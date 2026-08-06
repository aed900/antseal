//! A minimal `.ots` writer, for the shapes no captured artifact contains —
//! **task A82**.
//!
//! # Why this is here and not in a `#[cfg(test)]` module
//!
//! It began as a private helper inside `anchor::verdicts::tests`, which put it
//! out of reach of **both** homes the tamper matrix uses: `test_util` is not
//! `cfg(test)`, and `crates/antseal-core/tests/` is a separate crate that
//! cannot see another crate's `cfg(test)` items at all. A21's rows need
//! exactly the shapes no capture holds — a **single-branch committed** upgrade
//! group, an unknown attestation type, a Bitcoin branch with no upgrade group
//! — so the writer had to move before those rows could be written (D93 §9).
//!
//! It sits beside [`MockTsa`](super::MockTsa) and under the same
//! `cfg(any(test, feature = "test-util"))` gate, so it is unreachable from
//! every production build and present in the `--lib` test binary on
//! `wasm32-unknown-unknown` — which is where A18's rows run alongside their
//! native selves.
//!
//! # Every format constant is imported, not restated
//!
//! [`OTS_MAGIC`], [`OTS_VERSION`], [`OTS_DIGEST_TYPE_SHA256`] and
//! [`OTS_PENDING_TAG`] come from the parser by name. A format change therefore
//! **breaks the build here** rather than silently minting bytes the parser
//! rejects for the wrong reason — which is the failure mode that makes a
//! negative test pass for a reason nobody chose.
//!
//! **The parser's own suite deliberately does the opposite** and must keep
//! doing it: `anchor::ots::tests` restates the magic as a literal
//! *"independently of the parser's copy, so that a mutation of `parse::MAGIC`
//! cannot silently move every fixture with it"*. Re-pointing that suite here
//! would blind the parser's tests to a mutation of the parser's own
//! constants — a green suite over bytes that moved with the code. The two
//! copies are not redundancy; they are opposite instruments, and only this one
//! belongs in a shared home.
//!
//! # Wire shape (D58 §7)
//!
//! `magic ‖ varuint(version) ‖ digest-type ‖ digest ‖ body`, with a body of
//! ops and attestations. `0xff` is the fork marker written before every child
//! but the last; `0x00` introduces an attestation, followed by its 8-byte tag,
//! a varuint payload length and the payload.

use crate::bundle::schema::OtsUpgrade;

use crate::anchor::ots::{
    OTS_DIGEST_TYPE_SHA256, OTS_MAGIC, OTS_PENDING_TAG, OTS_VERSION, OtsAttestation, parse_ots,
};

// ── real captured material the synthetic headers are pinned to ──────────

/// A real **upgraded** mainnet proof: two pending branches and two Bitcoin
/// attestations, at heights 449397 and 449399, both carrying ops-derived
/// merkle roots.
pub const UPGRADED_LARGE_TEST: &[u8] = include_bytes!(
    "../../../../../testdata/anchors/A25-bootstrap/upgraded/rust-opentimestamps-LARGE_TEST.ots"
);

/// The digest [`UPGRADED_LARGE_TEST`] was stamped over.
pub const DIGEST_UPGRADED_LARGE_TEST: [u8; 32] = [
    0x6f, 0xd9, 0xc1, 0xc4, 0xf0, 0x96, 0xb7, 0x7e, 0x6d, 0x44, 0x57, 0xba, 0xc1, 0xc7, 0xf5, 0x10,
    0x10, 0xd3, 0x18, 0xdb, 0x48, 0x3f, 0x28, 0x68, 0xd3, 0x79, 0x58, 0x43, 0xf0, 0x98, 0xd3, 0x78,
];

/// The height whose Bitcoin attestation the upgrade fixtures pin to.
pub const ATTESTED_HEIGHT: u64 = 449_399;

/// The *other* real height in [`UPGRADED_LARGE_TEST`], also with a derived
/// root — the material that makes "two Bitcoin heights, one identity"
/// (D92 §9 T1) buildable without inventing a block.
pub const SECOND_ATTESTED_HEIGHT: u64 = 449_397;

/// A recognisable `nTime` for the synthetic headers.
///
/// Never read from an *embedded* header to produce a verdict (D56 §5): the
/// `proven` time is the online-agreed header's.
pub const HEADER_NTIME: u32 = 1_483_398_000;

/// The `fetch_date` every synthetic upgrade group records. No rule reads it.
pub const FETCH_DATE: u64 = 1_785_000_100;

// ── attestation tags ────────────────────────────────────────────────────

/// The Bitcoin attestation tag (D58 §7.3).
///
/// Restated rather than imported because the parser does not export it: A11
/// keeps it private to `parse`. `the_bitcoin_tag_is_the_one_the_parser_recognises`
/// is what pins the two together, so a divergence is a red test rather than a
/// fixture the parser silently reads as unknown.
pub const BITCOIN_TAG: [u8; 8] = [0x05, 0x88, 0x96, 0x0d, 0x73, 0xd7, 0x19, 0x01];

/// An attestation type this verifier does not implement — the shape D56 §2
/// says keeps `internally-consistent-only` reachable for OTS. Litecoin and
/// Ethereum calendars really do exist.
pub const UNKNOWN_TAG: [u8; 8] = [0x0f, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee];

// ── the writer ──────────────────────────────────────────────────────────

/// Little-endian base-128, minimal form.
#[must_use]
pub fn varuint(mut value: u64) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let byte = u8::try_from(value % 128).expect("masked to 7 bits");
        value /= 128;
        if value == 0 {
            out.push(byte);
            return out;
        }
        out.push(byte | 0x80);
    }
}

/// `magic ‖ version ‖ digest-type ‖ digest ‖ body`.
#[must_use]
pub fn container(digest: &[u8; 32], body: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&OTS_MAGIC);
    out.extend_from_slice(&varuint(OTS_VERSION));
    out.push(OTS_DIGEST_TYPE_SHA256);
    out.extend_from_slice(digest);
    out.extend_from_slice(body);
    out
}

/// One attestation: `0x00 ‖ tag ‖ varuint(len) ‖ payload`.
#[must_use]
pub fn attestation(tag: [u8; 8], payload: &[u8]) -> Vec<u8> {
    let mut out = vec![0x00];
    out.extend_from_slice(&tag);
    out.extend_from_slice(&varuint(payload.len() as u64));
    out.extend_from_slice(payload);
    out
}

/// A pending attestation, whose payload is a varbytes calendar URI.
#[must_use]
pub fn pending(uri: &str) -> Vec<u8> {
    let mut payload = varuint(uri.len() as u64);
    payload.extend_from_slice(uri.as_bytes());
    attestation(OTS_PENDING_TAG, &payload)
}

/// A Bitcoin attestation, whose payload is a varuint block height.
#[must_use]
pub fn bitcoin(height: u64) -> Vec<u8> {
    attestation(BITCOIN_TAG, &varuint(height))
}

/// An attestation of a type this verifier does not implement.
#[must_use]
pub fn unknown() -> Vec<u8> {
    attestation(
        UNKNOWN_TAG,
        b"opaque payload from a calendar we do not implement",
    )
}

/// `N` children under one node: a fork marker before every child but the last
/// (D58 §7.2).
#[must_use]
pub fn fork(children: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    for (i, child) in children.iter().enumerate() {
        if i + 1 < children.len() {
            out.push(0xff);
        }
        out.extend_from_slice(child);
    }
    out
}

/// A synthetic digest, distinct from every committed one.
#[must_use]
pub const fn synthetic_digest(seed: u8) -> [u8; 32] {
    [seed; 32]
}

// ── headers and upgrade groups ──────────────────────────────────────────

/// The 80-byte header shape: `root` at bytes 36..68, `ntime` little-endian at
/// 68..72, everything else a recognisable filler.
///
/// # Panics
///
/// If `root` is not 32 bytes.
#[must_use]
pub fn header_with(root: &[u8], ntime: u32) -> [u8; 80] {
    let mut header = [0xaa_u8; 80];
    header[36..68].copy_from_slice(root);
    header[68..72].copy_from_slice(&ntime.to_le_bytes());
    header
}

/// The merkle root [`UPGRADED_LARGE_TEST`]'s ops derive at `height`.
///
/// Read out of the parsed artifact rather than transcribed, so a synthetic
/// header built from it commits what the real ops actually produce and cannot
/// drift from them.
///
/// # Panics
///
/// If the fixture stops parsing, or stops attesting `height`.
#[must_use]
pub fn derived_root(height: u64) -> Vec<u8> {
    let artifact = parse_ots(UPGRADED_LARGE_TEST, &DIGEST_UPGRADED_LARGE_TEST)
        .expect("the real fixture parses");
    artifact
        .attestations
        .iter()
        .find_map(|attestation| match attestation {
            OtsAttestation::Bitcoin {
                height: h,
                merkle_root: Some(root),
            } if *h == height => Some(root.clone()),
            _ => None,
        })
        .expect("the fixture attests this height")
}

/// The upgrade group [`UPGRADED_LARGE_TEST`]'s ops **do** commit, at `height`.
///
/// The merkle-root field is the real ops-derived value; the surrounding 48
/// bytes are filler, because no fetched mainnet header for these heights is in
/// the tree (A25/A48 owe that). Nothing reads a filler byte: the only fields
/// any rule touches are the merkle root and `nTime`.
#[must_use]
pub fn committing_upgrade_at(height: u64) -> OtsUpgrade {
    OtsUpgrade::new(
        height,
        header_with(&derived_root(height), HEADER_NTIME),
        FETCH_DATE,
    )
}

/// [`committing_upgrade_at`] at [`ATTESTED_HEIGHT`].
#[must_use]
pub fn committing_upgrade() -> OtsUpgrade {
    committing_upgrade_at(ATTESTED_HEIGHT)
}

/// A **single-branch, ops-committing** upgraded `.ots`, minted whole:
/// `(digest, bytes, upgrade)`.
///
/// The shape no capture contains, and the one D56's online refutation rules
/// are actually about. With zero ops a branch's commitment *is* the stamped
/// digest, so a header carrying that digest at bytes 36..68 is committed by
/// the ops — which means **forging one costs no mining at all**: the attacker
/// picks the ops, reads the root they derive, and writes 80 bytes of its
/// choosing around it. MVP-SPEC.md line 108's *"a minimal-difficulty forged
/// header mines in seconds"* is the expensive version of this artifact.
///
/// Both halves of the name are load-bearing for any row built on it
/// (D93 §9 row 4):
///
/// - **committed**, because the *uncommitted* forgery is already `invalid`
///   offline through rule O8, so a row built that way passes without the
///   online gate ever running;
/// - **single-branch**, because a pending sibling makes rule O5 fire first and
///   the artifact renders `pending` instead (D56 §4).
///
/// With no online evidence it renders `attested`; with the embedded header
/// agreed, `proven`; with any other agreed header, `invalid`.
#[must_use]
pub fn committed_single_branch(seed: u8, height: u64) -> ([u8; 32], Vec<u8>, OtsUpgrade) {
    let digest = synthetic_digest(seed);
    let bytes = container(&digest, &bitcoin(height));
    let upgrade = OtsUpgrade::new(height, header_with(&digest, HEADER_NTIME), FETCH_DATE);
    (digest, bytes, upgrade)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// [`BITCOIN_TAG`] is restated here because A11 keeps it private; this is
    /// what stops the two drifting.
    ///
    /// What makes it fail: any edit to either copy of the tag. A wrong tag
    /// would not fail loudly — the parser would read the attestation as
    /// *unknown*, every `bitcoin()`-built fixture would quietly become an O9
    /// artifact, and a dozen negative rows would pass for the wrong reason.
    #[test]
    fn the_bitcoin_tag_is_the_one_the_parser_recognises() {
        let digest = synthetic_digest(0x01);
        let artifact = parse_ots(&container(&digest, &bitcoin(700_000)), &digest)
            .expect("a one-branch bitcoin artifact parses");
        assert!(
            matches!(
                artifact.attestations.as_slice(),
                [OtsAttestation::Bitcoin {
                    height: 700_000,
                    ..
                }]
            ),
            "the parser read {:?}, not a Bitcoin attestation",
            artifact.attestations
        );

        // …and the unknown tag really is unknown, or every O9 fixture in the
        // tree is testing something else.
        let artifact = parse_ots(&container(&digest, &unknown()), &digest).expect("parses");
        assert!(
            matches!(
                artifact.attestations.as_slice(),
                [OtsAttestation::UnknownType {
                    tag: UNKNOWN_TAG,
                    ..
                }]
            ),
            "the parser read {:?}, not an unknown attestation",
            artifact.attestations
        );
    }

    /// The writer's own anti-vacuity row: `committed_single_branch` really
    /// does produce an artifact whose ops commit the embedded header.
    ///
    /// What makes it fail: building the header over anything but the stamped
    /// digest — the shape is `container(&d, &bitcoin(h))` with **no ops**, so
    /// the branch commitment is `d` itself and nothing else can commit.
    #[test]
    fn committed_single_branch_really_commits_its_header() {
        use crate::anchor::ots::{EmbeddedHeader, check_embedded_header, merkle_root_of};

        let (digest, bytes, upgrade) = committed_single_branch(0x7c, ATTESTED_HEIGHT);
        let artifact = parse_ots(&bytes, &digest).expect("the minted artifact parses");
        assert_eq!(artifact.attestations.len(), 1, "single-branch");
        assert_eq!(
            check_embedded_header(&artifact, &upgrade),
            EmbeddedHeader::Committed
        );
        assert_eq!(merkle_root_of(upgrade.block_header()), digest);
    }

    /// Both real heights carry an ops-derived root, which is what makes
    /// D92 §9's T1 buildable from committed material.
    #[test]
    fn the_large_test_fixture_attests_two_heights_with_derived_roots() {
        for height in [ATTESTED_HEIGHT, SECOND_ATTESTED_HEIGHT] {
            assert_eq!(derived_root(height).len(), 32, "height {height}");
        }
        assert_ne!(
            derived_root(ATTESTED_HEIGHT),
            derived_root(SECOND_ATTESTED_HEIGHT),
            "two heights, two roots, or T1 compares a thing with itself"
        );
    }
}
