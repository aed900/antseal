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

// ── rule 6: structural allocation cost (D102 §3.1, applied here by §6) ────
//
// The DER target has never gone red. **That is not evidence** — `anchor_ots`
// was green until its *first remote execution*, which found A100's
// disagreement in 3 140 execs — and the only difference between the two
// targets is that one count limit is 1 024 and the other is 8. Three orders
// of magnitude, not a difference in kind, and `MAX_CHAIN_CERTS` is raise-only
// under F4 exactly as `MAX_OTS_DEPTH` is. D102 §6 therefore rules that this
// path takes the derivation **now, while it is still green**.

/// Bytes one certificate carried out of a token's bag occupies.
///
/// Measured by the compiler from `x509_cert::Certificate`, never transcribed
/// (rule 6 clause (a)) — it is a foreign type on a pre-1.0 pin, so a version
/// bump may move it and the cost must move with it.
pub const CHAIN_CERTIFICATE_BYTES: usize = core::mem::size_of::<x509_cert::Certificate>();

/// Bytes one retained DER copy's *handle* occupies in `chain_certificates`'
/// second vector. The bytes it points at are bounded by
/// [`MAX_CHAIN_CERT_BYTES`] and are a length-driven allocation, i.e. rule 4's,
/// not this rule's.
pub const CHAIN_CERT_DER_HANDLE_BYTES: usize = core::mem::size_of::<Vec<u8>>();

/// Bytes one node of A9's bounded path search occupies.
pub const CHAIN_PATH_NODE_BYTES: usize = core::mem::size_of::<super::chain::Node<'static>>();

/// Most nodes `PathBuilder::new` can reserve: the signer, plus everything the
/// token's bag contributes, plus the bundle's `intermediates` field.
pub const MAX_PATH_NODES: usize =
    MAX_CHAIN_CERTS + crate::codec::caps::MAX_INTERMEDIATE_COUNT as usize + 1;

/// Rule 6's **structural allocation cost** for the RFC 3161 / CMS / X.509
/// path: every count-bounded container live in one `verify_token`.
///
/// Three sites, all `Vec::with_capacity(count)` **after** the count is
/// checked, so each reserves its capacity exactly and none regrows:
///
/// | site | count bound | element |
/// | --- | --- | --- |
/// | `tsa::chain_certificates` `certs` | [`MAX_CHAIN_CERTS`] | [`CHAIN_CERTIFICATE_BYTES`] |
/// | `tsa::chain_certificates` `ders` | [`MAX_CHAIN_CERTS`] | [`CHAIN_CERT_DER_HANDLE_BYTES`] |
/// | `chain::PathBuilder::new` `nodes` | [`MAX_PATH_NODES`] | [`CHAIN_PATH_NODE_BYTES`] |
///
/// **[`MAX_SIGNED_ATTRS`] is deliberately absent, and that is a measured
/// finding rather than an omission.** D102 §6 names it alongside the other
/// two, but antseal reserves nothing from it: `signed_attrs` arrives already
/// decoded inside `SignerInfo` and the count check at `tsa.rs` rejects
/// *afterwards*, so the only allocation the attribute set drives belongs to
/// `der`'s decoder and is bounded by the input, which is rule 4's business.
/// Raising `MAX_SIGNED_ATTRS` therefore costs no structural bytes — but
/// [`tests::the_der_structural_cost_is_the_one_measured_today`] pins this
/// constant at equality, so *adding* a container under that limit reddens a
/// test on the day it is added, which is the day it matters.
pub const TSA_STRUCTURAL_ALLOC_BYTES: usize = MAX_CHAIN_CERTS
    * (CHAIN_CERTIFICATE_BYTES + CHAIN_CERT_DER_HANDLE_BYTES)
    + MAX_PATH_NODES * CHAIN_PATH_NODE_BYTES;

/// **Rule 6 clause (c)** for the DER path, against
/// [`crate::codec::caps::MAX_TSA_TOKEN_BYTES`] (D10 row 17, also 1 MiB).
///
/// Same mechanism and same reason as the `.ots` side: a raise of
/// [`MAX_CHAIN_CERTS`] that outgrows the token byte cap fails `cargo build`,
/// on every lane and on `wasm32`, rather than reddening something rerunnable.
const _: () = assert!(
    TSA_STRUCTURAL_ALLOC_BYTES as u64 <= crate::codec::caps::MAX_TSA_TOKEN_BYTES,
    "D58 §10.3 rule 6 clause (c): the RFC 3161 path's count-bounded \
     containers now reserve more than MAX_TSA_TOKEN_BYTES. A count limit was \
     raised without arguing its structural cost in memory — re-argue it \
     (D102 §3.2, §6) rather than relaxing this assertion."
);

/// Rule 6's cost for one **`input_len`-byte** token, which is what an
/// allocation guard may exempt.
///
/// A function of the input, not the flat constant, for the reason D102 §3.3
/// gives: a constant exemption is a window a hostile allocation can hide in
/// regardless of how few bytes bought it. Every certificate in the bag and
/// every bundle intermediate costs at least one wire byte, so the `min` is
/// sound and a short token gets almost no exemption.
///
/// Consumed by `fuzz/fuzz_targets/anchor_token.rs`, so the derivation exists
/// exactly once.
#[must_use]
pub fn tsa_structural_alloc_bytes(input_len: usize) -> usize {
    input_len.min(MAX_CHAIN_CERTS) * (CHAIN_CERTIFICATE_BYTES + CHAIN_CERT_DER_HANDLE_BYTES)
        + input_len.min(MAX_PATH_NODES) * CHAIN_PATH_NODE_BYTES
}

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

    /// **Rule 6 clause (b) for the DER path** (D102 §6).
    ///
    /// The `.ots` side asserts its derived cost against a measured allocator
    /// peak, because there its containers *are* the peak. Here they are not:
    /// the whole structural cost fits inside the fuzz guard's 4 KiB `SLACK`,
    /// so no input makes it the peak and there is nothing to measure it
    /// against. D102 §6 rules that this is *"a measured finding … committed
    /// **as an equality assertion**, because that assertion is what goes red
    /// the day someone adds a container or raises a count — which is the day
    /// it matters. An unmeasured 'it's fine' is what this whole record is
    /// about."*
    ///
    /// What makes it fail: adding a fourth count-bounded container, raising
    /// `MAX_CHAIN_CERTS` or `MAX_INTERMEDIATE_COUNT`, or an `x509-cert` /
    /// `der` bump that moves `size_of::<Certificate>()`. Every one of those is
    /// a reviewed event, and every one of them should re-read this number.
    /// **Pointer width, corrected 2026-08-08.** As first written this row
    /// asserted the literals unconditionally and **failed the
    /// `wasm32-core-tests` lane**: `size_of::<x509_cert::Certificate>()` is
    /// **376** on `wasm32-unknown-unknown` against 512 on x86-64. That is not
    /// the event this row exists to catch. It conflated *"a crate bump moved
    /// the layout"* — reviewed, and the whole point — with *"we are on 32-bit
    /// pointers"*, which is neither a defect nor reviewable.
    ///
    /// So it now splits the way the `.ots` side already did (`limits.rs`,
    /// `the_structural_cost_column_states_the_derivation_and_its_value`): the
    /// **derivation** is asserted everywhere, from the constants rather than
    /// from literals, because that is the part that must not drift; the
    /// **measured byte counts** are asserted on 64-bit only, because the
    /// registry records the x86-64 measurement it says it records.
    ///
    /// It also cost this project a CI red on a lane the local gate cannot
    /// see — `scripts/local-gate.sh` *builds* for wasm32 but does not *run*
    /// the wasm32 tests.
    #[test]
    fn the_der_structural_cost_is_the_one_measured_today() {
        // Everywhere: the formula. A fourth container, or a raised count,
        // parts these two and reddens on every target including wasm32.
        assert_eq!(
            TSA_STRUCTURAL_ALLOC_BYTES,
            MAX_CHAIN_CERTS * (CHAIN_CERTIFICATE_BYTES + CHAIN_CERT_DER_HANDLE_BYTES)
                + MAX_PATH_NODES * CHAIN_PATH_NODE_BYTES,
            "the derivation and its measured value have parted"
        );
        // Everywhere: a count limit, not a layout — no pointer width in it.
        assert_eq!(MAX_PATH_NODES, 25);

        // 64-bit only: the measured layout this record was written against.
        if core::mem::size_of::<usize>() == 8 {
            assert_eq!(
                CHAIN_CERTIFICATE_BYTES, 512,
                "size_of::<x509_cert::Certificate>() moved — re-measure \
                 TSA_STRUCTURAL_ALLOC_BYTES and this row together"
            );
            assert_eq!(CHAIN_CERT_DER_HANDLE_BYTES, 24);
            assert_eq!(CHAIN_PATH_NODE_BYTES, 128);
            assert_eq!(TSA_STRUCTURAL_ALLOC_BYTES, 7_488);
        }
    }

    /// The DER path's structural cost is **small**, and that is the finding —
    /// not a reason to skip asserting it.
    ///
    /// `anchor_ots` and `anchor_token` share an entry point and a default
    /// budget; the only difference between them is that one count limit is
    /// 1 024 and the other is 8. This row records where the second one sits
    /// relative to the fuzz guard's fixed slack, so a raise that moves it past
    /// that line is visible as a changed verdict here rather than as a fuzz
    /// red weeks later.
    #[test]
    fn the_der_structural_cost_relative_to_the_guards_fixed_slack() {
        const FUZZ_SLACK: usize = 4 * 1024;

        // D102 §6 anticipated that the whole derivation might *"come out small
        // enough to fit inside `SLACK`"*, in which case the exemption would be
        // inert. **It does not.** The overshoot is stated as a number rather
        // than as an inequality so that a shrink is as visible as a growth.
        //
        // 64-bit only, and the `saturating_sub` is not defensive padding: on a
        // 32-bit target the whole derivation *can* land under `SLACK`, and a
        // bare `-` would underflow-panic before the assertion could say so.
        if core::mem::size_of::<usize>() == 8 {
            assert_eq!(
                TSA_STRUCTURAL_ALLOC_BYTES - FUZZ_SLACK,
                3_392,
                "the DER path's structural cost has moved relative to the guard's \
                 fixed slack — re-record the measurement, in either direction"
            );
        } else {
            // wasm32 is narrower throughout, so the overshoot is smaller. The
            // property that must survive is that clause (c) still binds, which
            // the unconditional assertion at the end of this test states.
            assert!(
                TSA_STRUCTURAL_ALLOC_BYTES.saturating_sub(FUZZ_SLACK) < 3_392,
                "the 32-bit derivation is no longer narrower than the 64-bit one \
                 ({TSA_STRUCTURAL_ALLOC_BYTES} B) — that inverts the assumption \
                 this split was written on"
            );
        }

        // **The finding, and it is sharper than D102 §6 stated it.** The
        // single largest of the three reservations is `chain_certificates`'
        // `certs`, and it is *exactly* `SLACK`:
        //
        //     MAX_CHAIN_CERTS x size_of::<Certificate>() = 8 x 512 = 4 096
        //
        // The guard's cap is `len x 1 + SLACK`, so this reservation clears it
        // by a margin of **`len` bytes — zero at the boundary**. The bag's
        // count is `set.0.len()`, which counts every `CertificateChoices`
        // entry including a tiny `[3] other`, so a few hundred bytes of token
        // reserves the full 4 096 B. `anchor_token` has never gone red on the
        // exact arithmetic that made `anchor_ots` red four times, and the
        // reason is a **tie**: not a margin, not a design, a tie. Raise
        // `MAX_CHAIN_CERTS` to 9, or let an `x509-cert` bump add one word to
        // `Certificate`, and the same A100 defect arrives on the DER path.
        //
        // This assertion is the thing that says so before CI does.
        //
        // **The tie is a 64-bit fact**, corrected 2026-08-08 after this row
        // reddened `wasm32-core-tests`: there `size_of::<Certificate>()` is
        // 376, so the same product is `8 x 376 = 3 008` and the reservation
        // clears `SLACK` by nearly a kilobyte. The browser tab — the tightest
        // ceiling this parser actually runs under — is the target with the
        // *most* headroom. The tie belongs to the host that fuzzes, not to the
        // format, and that is worth knowing rather than asserting away.
        let cert_bag = MAX_CHAIN_CERTS * CHAIN_CERTIFICATE_BYTES;
        if core::mem::size_of::<usize>() == 8 {
            assert_eq!(
                cert_bag, FUZZ_SLACK,
                "the certificate-bag reservation has moved off its exact tie with \
                 the fuzz guard's SLACK. If it grew, `anchor_token` is now the \
                 `anchor_ots` of A100 and the scoped budget is what stands between \
                 it and a red lane; if it shrank, say so here. Either way this is \
                 a measurement to re-record, not a number to update silently"
            );
        } else {
            assert!(
                cert_bag < FUZZ_SLACK,
                "the 32-bit certificate bag ({cert_bag} B) has reached the fuzz \
                 guard's SLACK. wasm32 was the target with headroom; if it no \
                 longer is, the DER path is one raise from A100 on every target"
            );
        }

        // …and still two orders of magnitude under clause (c)'s ceiling.
        assert!(
            (TSA_STRUCTURAL_ALLOC_BYTES as u64) * 100 < crate::codec::caps::MAX_TSA_TOKEN_BYTES,
            "clause (c)'s headroom on the DER path has fallen below 100x"
        );
    }
}
