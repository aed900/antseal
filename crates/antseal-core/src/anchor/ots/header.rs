//! The embedded Bitcoin block header, offline (task **A12**).
//!
//! One question, asked entirely offline: **do the `.ots` ops commit the
//! merkle root of the header the bundle embeds, at the height it claims?**
//! On yes, the anchor is `attested` (D56 rule O4). On no — with an upgrade
//! group present — it is `invalid` with D56 rule O8's
//! `anchor-ots-header-uncommitted`.
//!
//! # `attested` is never headline-eligible offline, and carries no time
//!
//! MVP-SPEC.md line 108: a lone header's proof-of-work is **self-referential**
//! — an attacker picks its own `nBits`, so a minimal-difficulty forged header
//! mines in seconds. That is why Bitcoin is gated online and why a forged
//! header can never produce an offline headline time.
//!
//! D56 §5 adds the rule A12's `Do` omitted: **`verified_time_unix` MUST be
//! `None` for an `attested` anchor**, *"the invariant no existing test can
//! see"*, because `aggregate_anchors` already drops times on ineligible
//! slots. A2 made it unrepresentable rather than checked —
//! [`crate::anchor::model::AnchorVerdict::attested`] has no time parameter —
//! and `tests::an_attested_anchor_never_carries_a_verified_time` pins that
//! the property survives through this path.
//!
//! # Byte order
//!
//! The ops-derived value at a Bitcoin attestation is the block's merkle root
//! in Bitcoin's **internal** byte order, which is the order the 80-byte
//! header stores it in, so the comparison is direct with no reversal. The
//! structural evidence is in the artifact: in the real upgraded proof this
//! module is tested against, each Bitcoin attestation is preceded by a chain
//! of `append`/`prepend` of 32-byte siblings each followed by `08 08` —
//! double SHA-256 — which is Bitcoin's own merkle algorithm operating on
//! internal-order hashes.
//!
//! **That is structural, not empirical.** A12's `Do` asks for the byte order
//! to be *"pinned empirically by a real upgraded fixture"*, and pinning it
//! against a fetched mainnet header is **A25's**, once the two-day OTS cycle
//! completes (not before 2026-08-04): no real upgraded `.ots` of this
//! project's own exists yet. What is pinned here is that the implementation
//! does **not** reverse — `tests::a_byte_reversed_merkle_root_does_not_match`
//! goes red if anyone adds a reversal — and that the field is read at bytes
//! 36..68.

use crate::bundle::registry::BLOCK_HEADER_LEN;
use crate::bundle::schema::OtsUpgrade;

use super::{OtsArtifact, OtsAttestation};

/// The registry's block-header length, as a `usize` for array types.
///
/// **Consumed by name, not re-minted.** `docs/format/anchor-artifact-limits.md`
/// §3 rules that A5 and A11 take the D10/registry constants rather than
/// defining their own; a second 80 here would be the CLI-vs-page divergence
/// MVP-SPEC.md line 73 exists to prevent. F's wire gate already rejects a 79-
/// or 81-byte header as `bundle-wrong-length-block-header`, so one cannot
/// reach this module at all: `OtsUpgrade::block_header` is `[u8; 80]`.
const HEADER_LEN: usize = BLOCK_HEADER_LEN as usize;

/// Offset of the merkle-root field: `version(4) ‖ prev_block(32)`.
const MERKLE_ROOT_OFFSET: usize = 36;

/// Offset of the `nTime` field: the merkle root ends at 68.
const NTIME_OFFSET: usize = MERKLE_ROOT_OFFSET + 32;

/// The merkle root a block header commits to, in internal byte order.
#[must_use]
pub const fn merkle_root_of(header: &[u8; HEADER_LEN]) -> [u8; 32] {
    let mut root = [0_u8; 32];
    let mut i = 0;
    // Constant bounds over a fixed-size array: `MERKLE_ROOT_OFFSET + 31 = 67`
    // is inside 80, so no index here can be out of range.
    while i < 32 {
        root[i] = header[MERKLE_ROOT_OFFSET + i];
        i += 1;
    }
    root
}

/// A block header's `nTime`, POSIX seconds UTC, little-endian.
///
/// **Never read this from the *embedded* header to produce a verdict time.**
/// D56 §5: the `proven` time is the `nTime` of the **online-agreed** header,
/// and reading the embedded one would reinstate exactly the offline forgeable
/// time the online gate exists to prevent — invisibly, since the two headers
/// are equal on every honest bundle. It is `pub` because A18 needs it for the
/// agreed header (rule O3) and header parsing belongs here.
#[must_use]
pub const fn header_time_unix(header: &[u8; HEADER_LEN]) -> u32 {
    u32::from_le_bytes([
        header[NTIME_OFFSET],
        header[NTIME_OFFSET + 1],
        header[NTIME_OFFSET + 2],
        header[NTIME_OFFSET + 3],
    ])
}

/// Does this attestation commit the embedded header, at the height the
/// upgrade group records?
///
/// D56 §5's `header_commits`, over A11's real attestation type. Both halves
/// are required: the height must match **and** the ops must derive the
/// header's merkle root. An attestation with an indeterminate commitment
/// (its path crossed a registered-but-unimplemented op) commits nothing —
/// reporting a value there would be a fabricated commitment.
#[must_use]
pub fn header_commits(attestation: &OtsAttestation, upgrade: &OtsUpgrade) -> bool {
    let OtsAttestation::Bitcoin {
        height,
        merkle_root: Some(derived),
    } = attestation
    else {
        return false;
    };
    *height == upgrade.block_height()
        && derived.as_slice() == merkle_root_of(upgrade.block_header())
}

/// A12's offline verdict over an upgraded `.ots`.
///
/// Deliberately **not** an `AnchorState`: the artifact's single state is A18's
/// (D56 rules O0–O9), which also weighs pending branches, online evidence and
/// best-evidence-wins precedence. A12 answers one question and says so.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EmbeddedHeader {
    /// At least one Bitcoin attestation commits the embedded header at its
    /// recorded height → the anchor is `attested` unless something stronger
    /// applies (D56 rule O4/O3).
    Committed,
    /// An upgrade group is present and **no** Bitcoin attestation commits it
    /// → D56 rule O8, `anchor-ots-header-uncommitted`.
    ///
    /// One outcome for three shapes, because the predicate is one (D56 §5):
    /// the recorded height has a Bitcoin branch whose derived root disagrees;
    /// the recorded height has no Bitcoin branch at all; or the artifact
    /// carries an upgrade group with no evaluable Bitcoin attestation
    /// whatsoever — which `docs/format/registry-v1.md` §7.8 makes well-formed
    /// v1 on purpose.
    Uncommitted,
}

impl EmbeddedHeader {
    /// D56 rule O8's diagnostic code, for the `Uncommitted` case.
    ///
    /// Owned by D56 §7, not minted here; A18 attaches it to the verdict.
    pub const UNCOMMITTED_CODE: &'static str = "anchor-ots-header-uncommitted";
}

/// Evaluate the embedded header against a parsed artifact, offline.
///
/// Existential over the attestation set, so the answer is invariant under
/// branch order — the permutation-invariance D56 §5 requires of every rule.
#[must_use]
pub fn check_embedded_header(artifact: &OtsArtifact, upgrade: &OtsUpgrade) -> EmbeddedHeader {
    if artifact
        .attestations
        .iter()
        .any(|attestation| header_commits(attestation, upgrade))
    {
        EmbeddedHeader::Committed
    } else {
        EmbeddedHeader::Uncommitted
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::anchor::model::{AnchorKind, AnchorState, AnchorVerdict, headline_eligible};

    /// A header whose merkle-root field is `root` and whose `nTime` is
    /// `ntime`, every other field a recognisable filler.
    fn header_with(root: [u8; 32], ntime: u32) -> [u8; HEADER_LEN] {
        let mut header = [0xaa_u8; HEADER_LEN];
        header[MERKLE_ROOT_OFFSET..NTIME_OFFSET].copy_from_slice(&root);
        header[NTIME_OFFSET..NTIME_OFFSET + 4].copy_from_slice(&ntime.to_le_bytes());
        header
    }

    fn distinct_root() -> [u8; 32] {
        let mut root = [0_u8; 32];
        for (i, slot) in root.iter_mut().enumerate() {
            *slot = i as u8;
        }
        root
    }

    #[test]
    fn the_merkle_root_is_read_at_bytes_36_to_68() {
        let root = distinct_root();
        assert_eq!(merkle_root_of(&header_with(root, 0)), root);
        assert_eq!(MERKLE_ROOT_OFFSET, 36);
        assert_eq!(NTIME_OFFSET, 68);
    }

    #[test]
    fn ntime_is_little_endian_at_bytes_68_to_72() {
        let header = header_with([0; 32], 1_483_398_000);
        assert_eq!(header_time_unix(&header), 1_483_398_000);
        assert_eq!(header[NTIME_OFFSET], 0x70);
    }

    /// The mutation guard for the byte-order convention: a reversal added
    /// anywhere on this path turns this test red. The *empirical* pin against
    /// a fetched mainnet header is A25's — see the module docs.
    #[test]
    fn a_byte_reversed_merkle_root_does_not_match() {
        let root = distinct_root();
        let mut reversed = root;
        reversed.reverse();
        assert_ne!(root, reversed, "the witness must not be a palindrome");

        let upgrade = OtsUpgrade::new(449_399, header_with(root, 0), 0);
        let good = OtsAttestation::Bitcoin {
            height: 449_399,
            merkle_root: Some(root.to_vec()),
        };
        let flipped = OtsAttestation::Bitcoin {
            height: 449_399,
            merkle_root: Some(reversed.to_vec()),
        };
        assert!(header_commits(&good, &upgrade));
        assert!(!header_commits(&flipped, &upgrade));
    }

    #[test]
    fn a_root_mismatch_and_a_height_mismatch_are_both_uncommitted() {
        let root = distinct_root();
        let upgrade = OtsUpgrade::new(449_399, header_with(root, 0), 0);

        let mut other_root = root;
        other_root[0] ^= 0x01;

        for attestation in [
            // right height, wrong root
            OtsAttestation::Bitcoin {
                height: 449_399,
                merkle_root: Some(other_root.to_vec()),
            },
            // right root, wrong height
            OtsAttestation::Bitcoin {
                height: 449_397,
                merkle_root: Some(root.to_vec()),
            },
            // right height, indeterminate value — never a fabricated commit
            OtsAttestation::Bitcoin {
                height: 449_399,
                merkle_root: None,
            },
            // a pending branch commits no header
            OtsAttestation::Pending {
                uri: "https://alice.btc.calendar.opentimestamps.org".to_owned(),
                commitment: Some(root.to_vec()),
            },
        ] {
            let artifact = OtsArtifact {
                attestations: vec![attestation.clone()],
            };
            assert_eq!(
                check_embedded_header(&artifact, &upgrade),
                EmbeddedHeader::Uncommitted,
                "{attestation:?}"
            );
        }
    }

    /// D56 rule O8's third shape, which `registry-v1.md` §7.8 makes
    /// well-formed v1 on purpose: an upgrade group over an `.ots` carrying no
    /// Bitcoin attestation at all. An O8 predicate written as "the root
    /// disagrees" would find no root to disagree and fall through.
    #[test]
    fn an_upgrade_group_with_no_bitcoin_attestation_is_uncommitted() {
        let upgrade = OtsUpgrade::new(449_399, header_with(distinct_root(), 0), 0);
        let artifact = OtsArtifact {
            attestations: vec![OtsAttestation::Pending {
                uri: "https://bob.btc.calendar.opentimestamps.org".to_owned(),
                commitment: Some(vec![0; 44]),
            }],
        };
        assert_eq!(
            check_embedded_header(&artifact, &upgrade),
            EmbeddedHeader::Uncommitted
        );
    }

    /// Best-evidence-wins at A12's own level: a committing branch is not
    /// hidden by a non-committing sibling, in either order (D56 §4).
    #[test]
    fn a_committing_branch_is_found_regardless_of_sibling_order() {
        let root = distinct_root();
        let upgrade = OtsUpgrade::new(449_399, header_with(root, 0), 0);
        let good = OtsAttestation::Bitcoin {
            height: 449_399,
            merkle_root: Some(root.to_vec()),
        };
        let junk = OtsAttestation::Bitcoin {
            height: 449_399,
            merkle_root: Some(vec![0xff; 32]),
        };
        for attestations in [
            vec![good.clone(), junk.clone()],
            vec![junk.clone(), good.clone()],
        ] {
            let artifact = OtsArtifact { attestations };
            assert_eq!(
                check_embedded_header(&artifact, &upgrade),
                EmbeddedHeader::Committed
            );
        }
    }

    /// D56 §5's invariant, and A12's `Do` as corrected on 2026-08-02.
    ///
    /// A2 made it unrepresentable: `AnchorVerdict::attested` takes no time
    /// parameter. This asserts the property end to end anyway, because the
    /// rule it defends is one that `aggregate_anchors` would otherwise hide —
    /// it drops times on ineligible slots, so a wrongly populated one is
    /// invisible downstream.
    #[test]
    fn an_attested_anchor_never_carries_a_verified_time() {
        let verdict = AnchorVerdict::attested(AnchorKind::Ots, None, None);
        assert_eq!(verdict.state(), AnchorState::Attested);
        assert_eq!(verdict.verified_time_unix(), None);
    }

    /// MVP-SPEC.md lines 108/131, asserted at the anchor level too
    /// (`MATRIX.json` row `anchor-attested-not-headline`).
    #[test]
    fn attested_is_never_headline_eligible() {
        assert!(!headline_eligible(AnchorState::Attested));
    }

    /// A12 Accept: "79- and 81-byte headers rejected."
    ///
    /// They are rejected **before** this module, and cannot be spelled here:
    /// `OtsUpgrade::block_header` is `[u8; 80]` and F's wire gate raises
    /// `bundle-wrong-length-block-header` (asserted over real bundle bytes by
    /// `crates/antseal-core/tests/bundle_schema.rs`). This records the
    /// division so that nobody adds a second, weaker length check here — the
    /// duplicate-constant failure `docs/format/anchor-artifact-limits.md` §3
    /// exists to prevent.
    #[test]
    fn a_wrong_length_header_is_unrepresentable_at_this_boundary() {
        assert_eq!(HEADER_LEN, 80);
        let upgrade = OtsUpgrade::new(1, [0; HEADER_LEN], 0);
        assert_eq!(upgrade.block_header().len(), HEADER_LEN);
    }
}
