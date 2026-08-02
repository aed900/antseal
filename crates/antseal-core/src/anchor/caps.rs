//! The anchor-stage structural limits A5 chooses at M2 (D60 §6, §7.1).
//!
//! # What is here and what is deliberately not
//!
//! [`crate::codec::caps`] is the **frozen v1 format surface** — D10's byte and
//! count caps over the bundle's anchor *fields*, which fire in verify stage 1
//! before any AEAD, hash or signature. Nothing in this module duplicates one
//! of those. Per D84 §5, A5 **consumes** `MAX_INTERMEDIATE_COUNT`,
//! `MAX_CERT_BYTES` and `MAX_TSA_TOKEN_BYTES` by name and defines no
//! second constant over the same quantity.
//!
//! What *is* here is the other half of the split: limits on the **internal
//! structure of a foreign artifact**, which D84 §7 puts explicitly outside
//! the v1 freeze. They are verifier policy over a format antseal does not
//! own, and they obey F1–F4 (`docs/format/anchor-artifact-limits.md` §1):
//!
//! - **F1** — evaluated only in the anchor stage (R12), never reachable from
//!   [`crate::bundle::SealProof`]'s decode.
//! - **F2** — exceeding one fails **that anchor alone**; never the bundle,
//!   never the manifest verdict, never another anchor.
//! - **F3** — the over-limit anchor renders `invalid`.
//! - **F4** — raise-only after M2's first release. The F4 registry rows for
//!   these three, and for the depth limit that is *not* declared here, are in
//!   D60 §6 and belong in `docs/format/anchor-artifact-limits.md` §5.
//!
//! # Why there is no `MAX_DER_NESTING_DEPTH`
//!
//! Because minting one would require antseal to measure depth, and measuring
//! depth requires a walker. D60 §2.4 measured what a recursive DER walker
//! does on hostile input: at depth 20 000 (83 407 bytes) it overflows the
//! stack and **aborts** — `SIGABRT`, not a catchable panic, and a trap on
//! `wasm32`. That is a direct violation of A5's "adversarial input returns
//! typed errors, never panics".
//!
//! `der 0.8.1` already enforces `MAX_DEPTH = 64` in `Reader::split_nested`
//! (`reader/position.rs:20,76-79`): 63 nested constructions accepted, 64
//! rejected with `ErrorKind::NestingDepth`, per parse invocation. The deepest
//! of the nine live TSA responses is **19** — a 3.3× margin — so the limit is
//! consumed from `der` by name rather than minted, and
//! `tests/der_pin_eval.rs::der_nesting_depth_limit_is_63` is the F4
//! raise-only guard: it fails if a `der` bump moves the constant in *either*
//! direction, so a lowering is refused at the bump review instead of shipped.
//!
//! # Why the count limit is not `MAX_INTERMEDIATE_COUNT`
//!
//! D84 §5 forbids merging them and D60 §6 b2 gives the operational reason.
//! `MAX_INTERMEDIATE_COUNT` bounds a **bundle field**; [`MAX_CHAIN_CERTS`]
//! bounds the **certificate material one TSA token contributes to a path
//! build**, which arrives inside the token and is bounded only by
//! `MAX_TSA_TOKEN_BYTES` — 1 MiB, i.e. thousands of small certificates.
//! Path enumeration is quadratic in candidates and 16 mutually name-chaining
//! intermediates are cheap to manufacture and fit the bundle cap, so the two
//! quantities are genuinely different and only one of them is already bound.

/// Longest certificate path A9 will build, signer through pinned root, and
/// the largest certificate set one TSA token may contribute to it.
///
/// **8** (D60 §6 b2). Measured against
/// `testdata/anchors/A25-bootstrap/D60-tsa-globalsign-resp.tsr`, the largest
/// of the nine live captures, which carries **4** certificates — margin
/// **2.0×**. The deepest real validated path is 3 links (DigiCert leaf → G4
/// TS CA → pinned Trusted Root G4), 4 if closed through the cross-certificate
/// to Assured ID Root.
///
/// **Not 18** (`MAX_INTERMEDIATE_COUNT + signer + root`), even though 18 is
/// the arithmetic ceiling, because a path can never *exceed* 18: an
/// 18-limit is a check that cannot fail, and a test that cannot fail is the
/// defect class this project keeps finding. At 8 the limit is reachable and
/// `tests/anchor_caps.rs::chain_cert_count_cap_is_reachable` reaches it.
pub const MAX_CHAIN_CERTS: usize = 8;

/// Largest single certificate accepted out of a TSA token.
///
/// **16 KiB** (D60 §6 b3). Measured against
/// `testdata/anchors/A25-bootstrap/D60-tsa-swisssign-resp.tsr`, whose signer
/// certificate is **2 105 B** — the largest of the 27 certificates embedded
/// across the nine captures — margin **7.8×**.
///
/// This is **not** a duplicate of [`crate::codec::caps::MAX_CERT_BYTES`], and
/// the difference is the whole reason it exists: `MAX_CERT_BYTES` fires in
/// stage 1 over each element of the bundle's `intermediates` field, whereas
/// the certificates A9 validates come out of the **token**, where the only
/// bound is `MAX_TSA_TOKEN_BYTES` = 1 MiB. Nothing else stops a hostile token
/// carrying a 900 KiB "certificate".
pub const MAX_CHAIN_CERT_BYTES: u32 = 16_384;

/// Largest `signedAttrs` set accepted on a `SignerInfo`.
///
/// **16** (D60 §6 b4). Measured against
/// `testdata/anchors/A25-bootstrap/D60-tsa-digicert-resp.tsr` (also DFN,
/// SwissSign and Certum), which carries **5** — margin **3.2×**. RFC 5652's
/// attribute set for a timestamp token is small and closed; 16 is generous
/// and still reachable, and
/// `tests/anchor_caps.rs::signed_attr_count_cap_is_reachable` reaches it.
pub const MAX_SIGNED_ATTRS: usize = 16;

// The A28-shaped derived constraint (D60 §6 b3): a certificate accepted out
// of a token must afterwards be embeddable in a `.sealproof` as an
// intermediate, or the seal anchors and then cannot be revealed. Asserted at
// build time rather than assumed, so the relationship between the two
// constants is checked by the compiler and not by a comment. It also covers
// the pinned roots, which are compiled in and reviewed at A7/A26.
const _: () = assert!(MAX_CHAIN_CERT_BYTES as u64 <= crate::codec::caps::MAX_CERT_BYTES);

#[cfg(test)]
mod tests {
    use super::*;

    /// The values are the ones D60 §6 ruled and the F4 registry rows record.
    /// F4 is raise-only, so this test's job is to make a *lowering* a red
    /// build rather than a diff nobody reads.
    #[test]
    fn f4_registry_values() {
        assert_eq!(MAX_CHAIN_CERTS, 8, "D60 §6 b2 / F4 registry row");
        assert_eq!(MAX_CHAIN_CERT_BYTES, 16_384, "D60 §6 b3 / F4 registry row");
        assert_eq!(MAX_SIGNED_ATTRS, 16, "D60 §6 b4 / F4 registry row");
    }

    /// The D10 constants A5 consumes by name are unchanged by this module —
    /// the grep-level review item in A5's Accept row, asserted instead of
    /// grepped. If any of these three moved, a limit above would silently
    /// stop meaning what its doc comment says.
    #[test]
    fn the_frozen_d10_constants_are_consumed_not_redefined() {
        assert_eq!(crate::codec::caps::MAX_INTERMEDIATE_COUNT, 16);
        assert_eq!(crate::codec::caps::MAX_CERT_BYTES, 65_536);
        assert_eq!(crate::codec::caps::MAX_TSA_TOKEN_BYTES, 1_048_576);
    }

    /// The build-time assertion above proves `<=`. This proves the margin is
    /// real — that the two constants are not the same number wearing two
    /// names, which is the shape D84 §5 rules out.
    #[test]
    fn chain_cert_bytes_is_strictly_below_the_bundle_field_cap() {
        assert!(u64::from(MAX_CHAIN_CERT_BYTES) < crate::codec::caps::MAX_CERT_BYTES);
    }
}
