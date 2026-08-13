//! What an online confirmation would fetch — D132's probe plan, derived from
//! the bundle and from nothing else (tasks R21/R22; D132 §3 R3/R4).
//!
//! # One derivation, two surfaces
//!
//! `antseal verify --online` and R24's page ask the **same** questions of the
//! **same** endpoints, and after D132 that is a property of there being one
//! function rather than of two lists happening to agree today:
//! `antseal-cli`'s `verify_host::probe_online` takes **both halves** of its
//! probe run from [`ProbePlan::from_bundle`], and `antseal-wasm` splices
//! [`ProbePlan::to_canonical_json`]'s bytes into the document
//! `verify_rendered` returns, as its `plan` member.
//!
//! The consequence is recorded rather than left to be discovered: a defect
//! here is a defect in **both** surfaces at once, and a gate that compares
//! their *renderings* cannot see it (D132 §7.4). The row that can is the one
//! beside `probe_online`, which drives the production collector against stub
//! endpoints and reads the request targets that actually went out.
//!
//! # The block set is the WIDE one, deliberately
//!
//! [`ProbePlan::blocks`] names every OTS anchor carrying a D79 upgrade group
//! — **whatever the offline verdict made of that anchor**, which is strictly
//! more than the overlay's `attested` rows. D132 §1 (c) measured the
//! difference inert: report, overlay and verdict datum are byte-identical
//! whether the extra height is probed or not, including when the endpoints
//! answer *refutingly*. The wide set is ruled because it is derivable from
//! the bundle alone — the narrow one needs the offline verdicts, so it could
//! not be computed by a pure bundle walk — and because a future rule that made
//! some other anchor state promotable would silently stop the narrow set
//! probing while the wide one carried on.
//!
//! A reader may notice that the page fetches a height which produces no
//! overlay row and report it as a bug. It is not: §1 (c) is the measurement,
//! and narrowing the set is a decision, not a fix.
//!
//! # The plan is a product of a PASSING verdict, and not because of this file
//!
//! Nothing here enforces that and nothing here can: this is a pure walk over
//! an already-decoded bundle. The property lives at the entry points —
//! `verify_rendered` runs the offline verification first and throws on any
//! rejection, so a page cannot obtain a plan for a bundle that failed. **No
//! entry point may return a plan from a decode alone** (D132 §3 R6), however
//! cheap that would be.
//!
//! # WASM-safe
//!
//! Pure data: no clock, no I/O, ordinary `serde`, and no dependency, feature
//! or `crate-type` beyond what this crate already has (D132 §3 R10).

use serde::Serialize;

use super::orchestration::SiblingEncodeError;
use crate::bundle::registry::TX_HASH_LEN;
use crate::bundle::{BundleV1, OtsUpgrade};

/// The Arbitrum receipt one online run would confirm.
///
/// Constructed only by [`ProbePlan::from_bundle`]: the byte field is private,
/// so no caller can pair a hex string with different bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReceiptTarget {
    /// The transaction hash as **64 lowercase hex characters** — the value
    /// `eth_getTransactionReceipt` takes, `0x`-prefixed by the caller.
    ///
    /// The encoding is `format!("{b:02x}")`, and that is a **measurement, not
    /// a style preference**: emitting the hash as a byte array costs +4 114 B
    /// of wasm and a hand-rolled hex table costs +11 977 B, because `format!`
    /// reuses `core::fmt` machinery the module already links while
    /// `String::push(char)` drags in a UTF-8 path it does not (D132 §1 f). A
    /// "cleaner" replacement is a regression until it has been re-measured —
    /// and D132 §7.2 notes the finding is this toolchain's, not a law.
    pub tx_hash: String,

    /// The same value as bytes, for `confirm_arbitrum_tx`, which takes
    /// `&[u8; 32]`.
    ///
    /// Skipped by `serde`: the document carries the hex and nothing else
    /// (D132 §3 R3). It is carried beside the hex rather than decoded back out
    /// of it because D132 §3 R4 requires the CLI to take *both* halves of its
    /// probe set from this one function, and a hex round trip there would be a
    /// second, fallible spelling of a value that is already exact.
    #[serde(skip)]
    tx_hash_bytes: [u8; TX_HASH_LEN as usize],
}

impl ReceiptTarget {
    /// The 32 bytes, for the caller that speaks JSON-RPC.
    #[must_use]
    pub const fn tx_hash_bytes(&self) -> &[u8; TX_HASH_LEN as usize] {
        &self.tx_hash_bytes
    }

    /// Hex once, beside the bytes it came from.
    fn new(tx_hash_bytes: [u8; TX_HASH_LEN as usize]) -> Self {
        Self {
            tx_hash: tx_hash_bytes.iter().map(|b| format!("{b:02x}")).collect(),
            tx_hash_bytes,
        }
    }
}

/// What an `--online` run would fetch for one bundle: the Bitcoin block
/// heights, and the transaction hash when the bundle carries a receipt.
///
/// **Both members are always present.** `blocks` is `[]` when there is nothing
/// to probe and `receipt` is `null` when there is no receipt; absence is
/// `null`, never a missing key (D65 §7's rule, riding tier C).
///
/// No `schema` key and no interior version (D65 §4): the one version a
/// consumer reads is `build_info()`'s.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProbePlan {
    /// Every upgraded OTS anchor's block height, **ascending and
    /// deduplicated** — two anchors committed in the same block are one
    /// question, and the probe log is keyed by height.
    pub blocks: Vec<u64>,

    /// The receipt to confirm, or `None` when the bundle carries none.
    ///
    /// The **first** of up to 256 recorded transaction hashes, which is the
    /// rule the CLI's receipt probe has always applied. D132 §8.2 records that
    /// the narrowing has no justification written down anywhere while the
    /// report meanwhile publishes `transaction_count`; this is now its one
    /// home, so a later record can change it in one place.
    pub receipt: Option<ReceiptTarget>,
}

impl ProbePlan {
    /// Derive the plan from a decoded bundle.
    #[must_use]
    pub fn from_bundle(bundle: &BundleV1<'_>) -> Self {
        let mut blocks: Vec<u64> = bundle
            .ots_anchors()
            .iter()
            .filter_map(|anchor| anchor.upgrade().map(OtsUpgrade::block_height))
            .collect();
        blocks.sort_unstable();
        blocks.dedup();

        let receipt = bundle
            .receipt()
            .and_then(|record| record.tx_hashes().first().copied())
            .map(ReceiptTarget::new);

        Self { blocks, receipt }
    }

    /// The plan's canonical bytes, for the rendered document's `plan` member
    /// (D132 §3 R2) — the same [`SiblingEncodeError`] idiom the other sibling
    /// documents use.
    ///
    /// Deterministic by construction — compact JSON, declaration order, no
    /// maps — but **tier C** under D65 §3: reviewed, not promised until U32.
    ///
    /// # Errors
    ///
    /// [`SiblingEncodeError`] — structurally unreachable for this type (a
    /// sequence of integers and one string), and typed rather than unwrapped
    /// because library code never unwraps.
    pub fn to_canonical_json(&self) -> Result<Vec<u8>, SiblingEncodeError> {
        serde_json::to_vec(self).map_err(SiblingEncodeError)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bundle::{AnchorStatus, OpaqueBytes, OtsAnchor, encode_bundle};
    use crate::test_util::bundle_fixtures::{
        FIXTURE_BLOCK_HEADER, FIXTURE_BLOCK_HEIGHT, Selection, build, shapes,
    };

    /// The fetch date the synthetic upgrade groups below record. Never read by
    /// the plan — it is here because D79's group is all three fields or none.
    const FETCH_DATE: u64 = 1_767_225_600;

    /// The F13 shape that populates every anchor kind and optional slot,
    /// receipt included: one upgraded OTS anchor at
    /// [`FIXTURE_BLOCK_HEIGHT`], one without an upgrade group, and a receipt
    /// whose first transaction hash is 32 × `0xE1`.
    fn every_kind_with_receipt() -> Vec<u8> {
        build(&shapes::multi_file_every_anchor_kind(), &Selection::all(3)).bytes
    }

    /// Its receipt-excluded twin — a one-section diff.
    fn every_kind_no_receipt() -> Vec<u8> {
        build(
            &shapes::multi_file_every_anchor_kind_no_receipt(),
            &Selection::all(3),
        )
        .bytes
    }

    /// A bundle whose OTS anchors carry exactly `heights`, in the order given,
    /// so ordering and duplication are inputs rather than accidents.
    ///
    /// The `.ots` bytes are opaque placeholders: the plan is a walk over the
    /// bundle's shape and consults no artifact, which is exactly why it is
    /// derivable without a verdict.
    fn bundle_with_ots_heights(heights: &[u64]) -> Vec<u8> {
        let built = build(&shapes::multi_file(), &Selection::all(3));
        let mut parts = BundleV1::decode(&built.bytes)
            .expect("the R6 fixture decodes to the model")
            .into_parts();
        parts.ots_anchors = heights
            .iter()
            .enumerate()
            .map(|(ordinal, height)| {
                OtsAnchor::new(
                    AnchorStatus::Attested,
                    OpaqueBytes::from_vec(format!("fixture .ots artifact {ordinal}").into_bytes()),
                    Some(OtsUpgrade::new(*height, FIXTURE_BLOCK_HEADER, FETCH_DATE)),
                )
                .expect("a placeholder artifact is under the D10 caps")
            })
            .collect();
        encode_bundle(&BundleV1::new(parts).expect("a well-formed bundle"))
            .expect("the rebuilt bundle re-encodes")
    }

    /// `ProbePlan::from_bundle` over already-encoded bytes.
    fn plan_of(bytes: &[u8]) -> ProbePlan {
        ProbePlan::from_bundle(&BundleV1::decode(bytes).expect("the bundle decodes"))
    }

    /// The plan's canonical bytes as text.
    fn json_of(plan: &ProbePlan) -> String {
        String::from_utf8(plan.to_canonical_json().expect("the plan encodes"))
            .expect("serde_json emits UTF-8")
    }

    #[test]
    fn an_unanchored_bundle_plans_nothing_and_still_carries_both_keys() {
        // D132 §3 R3, and the shape the page's empty path already reads:
        // `blocks` is `[]` and `receipt` is `null`. Never an absent key.
        let plan = plan_of(&build(&shapes::multi_file(), &Selection::all(3)).bytes);
        assert!(plan.blocks.is_empty(), "no anchors, nothing to probe");
        assert!(plan.receipt.is_none(), "no receipt section");
        assert_eq!(json_of(&plan), r#"{"blocks":[],"receipt":null}"#);
    }

    #[test]
    fn an_upgraded_ots_anchor_puts_its_height_in_the_plan_whatever_its_verdict() {
        // The wide set (D132 §3 R4): the F13 fixture's `.ots` bytes are opaque
        // placeholders, so the anchor verifies OFFLINE-INVALID — and its
        // height is planned anyway, because the plan is a walk over the
        // bundle and not over the verdicts. This is the whole of the
        // wide-versus-narrow difference, in one fixture.
        let plan = plan_of(&every_kind_with_receipt());
        assert_eq!(plan.blocks, vec![FIXTURE_BLOCK_HEIGHT]);
    }

    #[test]
    fn heights_are_ascending_and_deduplicated() {
        // Two anchors committed in the same block are ONE question, and the
        // probe log is keyed by height — so the input order and the repeat
        // are both deliberate.
        let plan = plan_of(&bundle_with_ots_heights(&[900_002, 900_001, 900_001]));
        assert_eq!(plan.blocks, vec![900_001, 900_002]);
        assert_eq!(
            json_of(&plan),
            r#"{"blocks":[900001,900002],"receipt":null}"#
        );
    }

    #[test]
    fn an_anchor_without_an_upgrade_group_contributes_no_height() {
        // The F13 shape carries one upgraded OTS anchor and one without the
        // group; `OneOtsTwoTsa`'s single anchor has no group at all. Both
        // arms, so "every OTS anchor" is not mistaken for "every anchor".
        assert_eq!(plan_of(&every_kind_with_receipt()).blocks.len(), 1);
        assert!(
            plan_of(&build(&shapes::multi_file_anchored(), &Selection::all(3)).bytes)
                .blocks
                .is_empty(),
            "a pending anchor has no upgrade group and nothing to fetch"
        );
    }

    #[test]
    fn the_receipt_target_is_the_first_transaction_hash_as_lowercase_hex() {
        let bytes = every_kind_with_receipt();
        let bundle = BundleV1::decode(&bytes).expect("the bundle decodes");
        let plan = ProbePlan::from_bundle(&bundle);
        let target = plan.receipt.as_ref().expect("the F13 twin carries one");

        // The rule stated independently of the implementation, from the
        // bundle's own accessor: the FIRST of up to 256 hashes.
        let expected = bundle
            .receipt()
            .and_then(|record| record.tx_hashes().first().copied())
            .expect("the F13 receipt records transaction hashes");
        assert_eq!(target.tx_hash_bytes(), &expected);

        assert_eq!(target.tx_hash.len(), 64, "64 hex characters, always");
        assert!(
            target
                .tx_hash
                .chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
            "lowercase hex only: {}",
            target.tx_hash
        );
        // …and the hex is the bytes, decoded back the long way round so the
        // assertion does not restate the encoder.
        for (byte, pair) in expected
            .iter()
            .zip(target.tx_hash.as_bytes().chunks_exact(2))
        {
            let text = core::str::from_utf8(pair).expect("ASCII");
            assert_eq!(
                u8::from_str_radix(text, 16).expect("a hex pair"),
                *byte,
                "the hex disagrees with the bytes it names"
            );
        }
    }

    #[test]
    fn the_receipt_excluded_twin_plans_a_null_receipt() {
        // Receipt presence *is* the sealer's opt-in and carries no verdict
        // (registry §7.10); the plan says so in the one way tier C allows.
        let plan = plan_of(&every_kind_no_receipt());
        assert!(plan.receipt.is_none());
        assert_eq!(
            json_of(&plan),
            format!(r#"{{"blocks":[{FIXTURE_BLOCK_HEIGHT}],"receipt":null}}"#),
            "the twin differs from its sibling in the receipt member and nowhere else"
        );
    }

    #[test]
    fn the_document_carries_no_schema_key_and_no_interior_version() {
        // D65 §4: seven commands, nine documents, zero interior versions.
        for bytes in [every_kind_with_receipt(), every_kind_no_receipt()] {
            let json = json_of(&plan_of(&bytes));
            assert!(!json.contains("\"schema\""), "{json}");
            assert!(!json.contains("\"version\""), "{json}");
        }
    }

    #[test]
    fn the_receipt_member_is_the_hex_and_nothing_else() {
        // The bytes ride in the Rust value for the CLI's sake and must not
        // reach the document: a second spelling of the same value on a tier-C
        // surface is a shape nobody ruled.
        let json = json_of(&plan_of(&every_kind_with_receipt()));
        assert_eq!(
            json,
            format!(
                r#"{{"blocks":[{FIXTURE_BLOCK_HEIGHT}],"receipt":{{"tx_hash":"{}"}}}}"#,
                "e1".repeat(32)
            )
        );
    }
}
