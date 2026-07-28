//! Frozen v1 parser resource caps (task F11; decision **D10**).
//!
//! MVP-SPEC.md line 153 requires "hard caps on bundle size/unit count/
//! depth/allocations" and line 187 names hostile bundles — adversary-authored
//! CBOR parsed in a counterparty's browser — as a standing risk. This module
//! is the single home of every cap constant, of the universal clamp rule, and
//! of the work-global unit budget.
//!
//! # Where the caps run
//!
//! `verify::pipeline`'s frozen stage order is `decode → structural → units →
//! files → sigs → anchors`, and stage 1 is exactly `SealProof::decode`. Every
//! cap here fires inside that call, so a hostile bundle dies **before** any
//! AEAD decrypt, GGM/Merkle work, `work_id`/`anchor_digest` hashing, or
//! signature verification. F11 adds no stage and moves no stage boundary; it
//! tightens stage 1.
//!
//! Ordering inside stage 1 is frozen (D10 §5):
//!
//! | order | check | cost | code |
//! | --- | --- | --- | --- |
//! | 1 | `input.len() > MAX_BUNDLE_BYTES`, first statement of `BundleV1::decode` | O(1) | `bundle-too-large` |
//! | 2 | layer-1 CBOR canonicality + bundle schema, caps at each head | O(input) | `cbor-*`, `bundle-*` |
//! | 3 | `input.len() > MAX_MANIFEST_BYTES`, first statement of `Manifest::decode` | O(1) | `manifest-too-large` |
//! | 4 | layer-2/3 canonicality + manifest schema, unit/file caps | O(manifest) | `cbor-*`, `manifest-*` |
//!
//! So an oversized bundle that *also* has a bad signature — or non-canonical
//! CBOR — reports `bundle-too-large`, because the size check precedes the
//! walk. That precedence is deliberate and pinned by tests.
//!
//! # The clamp rule (normative, D10 §4)
//!
//! > **Every pre-allocation is clamped to `min(claimed_length,
//! > remaining_input)`.** No exceptions, including lists with no cap.
//!
//! Every element of a definite-length array costs at least one wire byte, so
//! the bytes remaining after an array head bound the element count. The clamp
//! turns "a length header can drive an allocation" into "a length header can
//! drive an allocation no larger than the attacker's own input" — the property
//! F17's fuzz invariant needs in order to be statable at all.
//!
//! Frozen order at every array head, which fixes tamper-row precedence:
//!
//! 1. `d.array()` — head canonicality (so a non-shortest length head beats
//!    every cap code with `cbor-non-shortest-length`);
//! 2. **cap check on the claimed count**, before a single element is read —
//!    cheap by construction, since the rejecting input is an array head and
//!    nothing else;
//! 3. `Vec::with_capacity(clamped_capacity(claimed, d.remaining()))`;
//! 4. decode elements.
//!
//! Two classes need no change and must not be "fixed":
//!
//! - **`bstr`/`tstr` payloads** — [`super::decode::CanonicalDecoder`] already
//!   refuses a claimed length exceeding the remaining input, in `u64`, before
//!   any `usize` conversion, and reads borrow. The only copies copy exactly
//!   the validated borrowed length, which *is* the clamp.
//! - **Element loops** — `for _ in 0..count { push }` already terminates on
//!   truncation. The clamp bounds the capacity *hint*, not the loop.
//!
//! # wasm32 parity (D10 §8)
//!
//! Every byte/count cap is `u64` and every comparison happens in `u64`:
//! `input.len()` widens **up** (`as u64`, lossless on 32- and 64-bit) and a
//! cap is never narrowed **down** to `usize`, which on wasm32 would silently
//! truncate and make one bundle valid on one target and invalid on the other.
//! Every cap is `<= u32::MAX` (the largest, `MAX_BUNDLE_BYTES`, is 2^28 —
//! sixteen-fold under 2^32), so each is *reachable* on wasm32 too and at-cap /
//! cap+1 tests mean the same thing on both targets. The one `usize`
//! conversion is [`clamped_capacity`]'s return, lossless by its documented
//! invariant. [`MAX_CBOR_DEPTH`] is the deliberate `u16` exception: it counts
//! containers, never wire lengths.
//!
//! # Permanence
//!
//! All 19 values are **format-permanent and freeze at Q14**: a receiver that
//! rejects a bundle a sealer produced is a compatibility break, and
//! MVP-SPEC.md line 123 binds every future release to every released version.
//! There is deliberately **no local override** — a per-verifier cap knob would
//! let the CLI and the WASM page disagree on whether a bundle is valid, which
//! is precisely the divergence line 73 exists to prevent. Sizing rationale per
//! row lives in `docs/decisions/D10-parser-caps.md`; the values are mirrored
//! in `docs/format/registry-v1.md` §11 and its JSON mirror, with a test
//! asserting code == registry.

// ---------------------------------------------------------------------------
// The frozen cap table (D10 §1)
// ---------------------------------------------------------------------------

/// Layer-1 `.sealproof` input slice: 256 MiB.
///
/// Sized from a **whole-work reveal** of the spec's own worked case
/// (`n = 10^8`, line 96) in its worst shape — text, split, with a raw mirror:
/// 95.4 MiB canonical ciphertext + 17.0 MiB per-unit padding and tags + 95.4
/// MiB raw-mirror ciphertext + ~10.2 MiB manifest ≈ 219 MiB, ~14 % headroom.
/// The padding term being as large as the whole manifest is the non-obvious
/// interaction, and is why this is 256 MiB and not 128 MiB.
pub const MAX_BUNDLE_BYTES: u64 = 268_435_456;

/// Layer-2 input — the bundle's key 1 `bstr` contents, i.e. the manifest
/// envelope bytes: 16 MiB.
///
/// Admits [`MAX_UNIT_COUNT`] and [`MAX_FILE_COUNT`] simultaneously (≈10.2 MiB)
/// at 1.57×, with headroom for title/`app_version` text and additive v1.x
/// fields. It also bounds the SHA-256 work behind `work_id` and
/// `anchor_digest`. The **body** gets no separate constant: it is a `bstr`
/// inside the envelope, so `len(body) < len(envelope)` by construction.
pub const MAX_MANIFEST_BYTES: u64 = 16_777_216;

/// Enclosing containers of any item, in the generic walker: 8.
///
/// Registry §7.6.3 computes the v1 structural maximum — bundle chain 5,
/// manifest chain 6, and the two do **not** nest because layer 2 starts a
/// fresh decoder over the `bstr` contents. So the requirement is `>= 6`;
/// `8 = 6 + 2` leaves room for one additive v1.x field nested one level deeper
/// without permitting absurd nesting.
///
/// Semantics, stated so no off-by-one can creep in: an item with
/// `MAX_CBOR_DEPTH` enclosing containers is **accepted**; one with
/// `MAX_CBOR_DEPTH + 1` is **rejected**, as
/// [`DecodeError::NestingTooDeep`](super::decode::DecodeError::NestingTooDeep)
/// → `cbor-nesting-too-deep`.
///
/// `u16`, not `u64` (D10 §8 rule 4): depth is a container count compared
/// against the walker's own `u16` counter and never touches a wire length, so
/// the widening rule does not apply and the narrow type makes the confusion
/// impossible.
pub const MAX_CBOR_DEPTH: u16 = 8;

/// Manifest body key 7 `files`: 2^14 = 16 384.
///
/// Covers a full source tree or a dataset directory with wide margin. A work
/// larger than that is a filesystem archive, which is not what "seal your
/// work" targets.
pub const MAX_FILE_COUNT: u64 = 16_384;

/// **Work-global** running budget over every file's key 6 `units`: 2^16 =
/// 65 536.
///
/// A 1 000-page book splits into roughly 20 000 paragraphs, so this admits
/// three such books, or [`MAX_FILE_COUNT`] files at four units each. It is a
/// *work-global* budget, not a per-file one, so "one file claiming 2^20 units"
/// and "2^20 files claiming one unit each" hit the same cap with the same code
/// ([`DecodeBudget`]).
pub const MAX_UNIT_COUNT: u64 = 65_536;

/// Bundle key 3 `ots_anchors`: 256.
///
/// The minimum-anchor policy wants >= 2 OTS calendars (spec line 108); an
/// honest bundle today has single digits. 256 admits two decades of monthly
/// re-anchoring — verifier-side expiry semantics are v1, so anchor sets are
/// expected to grow rather than be fixed at seal time.
pub const MAX_OTS_ANCHOR_COUNT: u64 = 256;

/// Bundle key 4 `tsa_anchors`: 256. Same basis as [`MAX_OTS_ANCHOR_COUNT`].
pub const MAX_TSA_ANCHOR_COUNT: u64 = 256;

/// TSA anchor key 2 `intermediates`: 16.
///
/// Real TSA chains are leaf + 1–3 intermediates; cross-certified chains reach
/// 5–6. 16 is ~4× the realistic maximum.
///
/// **This is the weakest-evidence cap in the table** (D10 §2): every other row
/// derives from a type width, a spec sizing statement, or an arithmetic worst
/// case, while this one derives from what public CAs do. A must confirm it
/// against A25's recorded FreeTSA/DigiCert fixtures before Q14, while raising
/// it is still free (it is a hardening-only cap, so raising is
/// backward-compatible for receivers).
pub const MAX_INTERMEDIATE_COUNT: u64 = 16;

/// Receipt key 0 `tx_hashes`: 256.
///
/// One batch-payment tx per seal, with room for a batch split across many.
/// `256 x 33 B` = 8.4 KB, negligible.
pub const MAX_TX_HASH_COUNT: u64 = 256;

/// Bundle key 6 `covered_reveals`, defined **as** [`MAX_UNIT_COUNT`].
///
/// Separately named on purpose: D78 forbids the bundle schema layer from
/// consulting the manifest, so the bundle's bound on "how many units may be
/// revealed" has to be a bundle-side constant. Defining it *as* the
/// manifest-side constant is what keeps the two from drifting apart.
pub const MAX_COVERED_REVEAL_COUNT: u64 = MAX_UNIT_COUNT;

/// Bundle key 7 `noncovered_reveals`, defined **as** [`MAX_UNIT_COUNT`]; see
/// [`MAX_COVERED_REVEAL_COUNT`] for why it is named separately.
pub const MAX_NONCOVERED_REVEAL_COUNT: u64 = MAX_UNIT_COUNT;

/// Covered reveal key 3 `cover`: 256.
///
/// **Derived from a type width, not guessed.** A file's leaf count `n` is a
/// CBOR `uint`, so `d = ceil(log2 n) <= 64`. Spec line 96 bounds a leaf-exact
/// minimal GGM cover at `2*ceil(log2 n)` seeds, i.e. `<= 128` for *any*
/// representable file. 256 is exactly 2× the theoretical maximum, so it can
/// never be exceeded by an honest cover for any future file size — the
/// property that makes it safe to freeze. Margin over the spec's own worked
/// case (`n = 10^8` ⇒ 54 seeds): 4.7×.
pub const MAX_COVER_ENTRIES: u64 = 256;

/// Covered reveal key 4 `paths`: 256.
///
/// Same derivation as [`MAX_COVER_ENTRIES`]: at most one path of `d` nodes per
/// range boundary, i.e. `2*d <= 128` for any representable file.
pub const MAX_PATH_NODES: u64 = 256;

/// Bundle key 8 `touched_files`, defined **as** [`MAX_FILE_COUNT`].
pub const MAX_TOUCHED_FILE_COUNT: u64 = MAX_FILE_COUNT;

/// Bundle key 9 `full_reveals`, defined **as** [`MAX_FILE_COUNT`].
pub const MAX_FULL_REVEAL_COUNT: u64 = MAX_FILE_COUNT;

/// OTS anchor key 1 `ots`: 1 MiB (~250× a real `.ots`, which is ~0.5 KB
/// pending and 1–4 KB upgraded).
///
/// A byte-length cap on a v1 `bstr` field decides whether a given `.sealproof`
/// is valid v1, so it freezes with format v1 even though the artifact's
/// *internals* are A's at M2. Guessing high is free; guessing low is a
/// compatibility break.
pub const MAX_OTS_BYTES: u64 = 1_048_576;

/// TSA anchor key 1 `token`: 1 MiB (~100× a real DER token with certs).
pub const MAX_TSA_TOKEN_BYTES: u64 = 1_048_576;

/// Each `intermediates` element: 64 KiB (~32× a real X.509 intermediate).
pub const MAX_CERT_BYTES: u64 = 65_536;

/// Receipt key 2 `payload`: 16 MiB (~60× quote preimages + `proof_bytes` at
/// ~256 chunks).
pub const MAX_RECEIPT_PAYLOAD_BYTES: u64 = 16_777_216;

// ---------------------------------------------------------------------------
// The clamp rule
// ---------------------------------------------------------------------------

/// Clamp a pre-allocation to what the remaining input could possibly hold.
///
/// Every element of a definite-length array costs at least one wire byte, so
/// `remaining` bounds the element count. The result is
/// `<= remaining <= input.len() <= usize::MAX`, which is why the `as usize` is
/// lossless on wasm32 as well as native — that invariant is the whole reason
/// the function exists rather than an inline `min`.
///
/// Callers apply this **after** the relevant cap check, so the allocation is
/// bounded by `min(cap, remaining_input)`. Lists with no cap (D10 §3) still
/// call it: a cap and a clamp are different mechanisms.
#[must_use]
pub fn clamped_capacity(claimed: u64, remaining: u64) -> usize {
    // `min` in u64 first, then one narrowing that cannot lose bits because
    // the result is <= `remaining`, itself derived from a `usize` length.
    usize::try_from(claimed.min(remaining)).unwrap_or(usize::MAX)
}

/// Work-global decode budget threaded through the manifest body decode.
///
/// **Not a wire field.** It exists so that "one file claiming 2^20 units" and
/// "2^20 files claiming one unit each" hit the same cap with the same code —
/// a per-file cap would let a hostile manifest multiply its unit count by its
/// file count.
#[derive(Debug)]
pub struct DecodeBudget {
    units_remaining: u64,
}

impl Default for DecodeBudget {
    fn default() -> Self {
        Self::new()
    }
}

impl DecodeBudget {
    /// A fresh budget: [`MAX_UNIT_COUNT`] units for the whole work.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            units_remaining: MAX_UNIT_COUNT,
        }
    }

    /// Units still available across the rest of the work.
    #[must_use]
    pub const fn units_remaining(&self) -> u64 {
        self.units_remaining
    }

    /// Charge `claimed` units against the work-global budget.
    ///
    /// # Errors
    ///
    /// `Err(())` when `claimed` exceeds what is left. The caller raises
    /// `ManifestError::ListTooLong { list: Units, claimed, cap: MAX_UNIT_COUNT }`
    /// — the cap reported is always the work-global constant, never the
    /// residue, so the error a hostile manifest sees never depends on how far
    /// through the file list it got.
    // `clippy::result_unit_err` fires on the `Result<(), ()>`. The signature is
    // frozen by D10 §9, and the unit error is right on the merits: this module
    // is below `manifest` in the layering and cannot name `ManifestError`, and
    // a bespoke error type here would carry exactly the `claimed`/`cap` pair
    // the caller already has — two spellings of one failure, which is the
    // duplication D30 §1's "one code per outcome" rule exists to prevent. The
    // only caller is `ManifestBodyV1::decode`, three lines away from the
    // conversion.
    #[allow(clippy::result_unit_err)]
    pub fn take_units(&mut self, claimed: u64) -> Result<(), ()> {
        match self.units_remaining.checked_sub(claimed) {
            Some(left) => {
                self.units_remaining = left;
                Ok(())
            }
            None => Err(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// D10 §8 rule 2: every cap is `<= u32::MAX`, which is what makes each of
    /// them *reachable* on wasm32 as well as native — so an at-cap / cap+1
    /// pair means the same thing on both targets.
    #[test]
    fn every_cap_is_representable_on_a_32_bit_target() {
        for (name, value) in ALL_BYTE_AND_COUNT_CAPS {
            assert!(
                value <= u64::from(u32::MAX),
                "{name} = {value} exceeds u32::MAX and would not be reachable on wasm32"
            );
        }
        assert!(u64::from(MAX_CBOR_DEPTH) <= u64::from(u32::MAX));
    }

    /// The four aliased rows are defined *as* their partner (D10 §1), not
    /// copied. A drift here would let the bundle and manifest halves disagree
    /// about the same quantity.
    #[test]
    fn aliased_caps_track_their_partner() {
        assert_eq!(MAX_COVERED_REVEAL_COUNT, MAX_UNIT_COUNT);
        assert_eq!(MAX_NONCOVERED_REVEAL_COUNT, MAX_UNIT_COUNT);
        assert_eq!(MAX_TOUCHED_FILE_COUNT, MAX_FILE_COUNT);
        assert_eq!(MAX_FULL_REVEAL_COUNT, MAX_FILE_COUNT);
    }

    // The "cap clears the v1 schema maximum of 6 containers" guard lives in
    // `super::decode`'s `depth_guard_admits_the_deepest_v1_schema_chain`,
    // which is strictly stronger: it asserts the inequality *and* decodes a
    // 6-deep item through the real walker.

    #[test]
    fn clamp_takes_the_smaller_side() {
        assert_eq!(clamped_capacity(10, 100), 10);
        assert_eq!(clamped_capacity(100, 10), 10);
        assert_eq!(clamped_capacity(u64::MAX, 7), 7);
        assert_eq!(clamped_capacity(0, 0), 0);
    }

    /// The invariant the `as usize` rests on: the result never exceeds
    /// `remaining`, so it never exceeds the input length.
    #[test]
    fn clamp_never_exceeds_remaining_input() {
        for claimed in [0u64, 1, 255, 65_536, u64::from(u32::MAX), u64::MAX] {
            for remaining in [0u64, 1, 9, 4096] {
                let got = clamped_capacity(claimed, remaining);
                assert!(got as u64 <= remaining);
                assert!(got as u64 <= claimed);
            }
        }
    }

    #[test]
    fn budget_is_work_global_not_per_file() {
        let mut budget = DecodeBudget::new();
        // Two files, each half the cap: together exactly at cap.
        assert_eq!(budget.take_units(MAX_UNIT_COUNT / 2), Ok(()));
        assert_eq!(budget.take_units(MAX_UNIT_COUNT / 2), Ok(()));
        assert_eq!(budget.units_remaining(), 0);
        // One more unit, in a third file, is one over.
        assert_eq!(budget.take_units(1), Err(()));
    }

    #[test]
    fn budget_rejects_a_single_over_cap_claim_without_underflowing() {
        let mut budget = DecodeBudget::new();
        assert_eq!(budget.take_units(u64::MAX), Err(()));
        // A refused claim does not consume budget.
        assert_eq!(budget.units_remaining(), MAX_UNIT_COUNT);
        assert_eq!(budget.take_units(MAX_UNIT_COUNT), Ok(()));
    }

    /// Every byte/count cap by name — used by the wasm32-reachability check
    /// above and by the registry cross-check in
    /// `tests/format_registry_draft.rs`, which reads the same 19 rows from
    /// `docs/format/registry-v1.json`.
    const ALL_BYTE_AND_COUNT_CAPS: [(&str, u64); 18] = [
        ("MAX_BUNDLE_BYTES", MAX_BUNDLE_BYTES),
        ("MAX_MANIFEST_BYTES", MAX_MANIFEST_BYTES),
        ("MAX_FILE_COUNT", MAX_FILE_COUNT),
        ("MAX_UNIT_COUNT", MAX_UNIT_COUNT),
        ("MAX_OTS_ANCHOR_COUNT", MAX_OTS_ANCHOR_COUNT),
        ("MAX_TSA_ANCHOR_COUNT", MAX_TSA_ANCHOR_COUNT),
        ("MAX_INTERMEDIATE_COUNT", MAX_INTERMEDIATE_COUNT),
        ("MAX_TX_HASH_COUNT", MAX_TX_HASH_COUNT),
        ("MAX_COVERED_REVEAL_COUNT", MAX_COVERED_REVEAL_COUNT),
        ("MAX_NONCOVERED_REVEAL_COUNT", MAX_NONCOVERED_REVEAL_COUNT),
        ("MAX_COVER_ENTRIES", MAX_COVER_ENTRIES),
        ("MAX_PATH_NODES", MAX_PATH_NODES),
        ("MAX_TOUCHED_FILE_COUNT", MAX_TOUCHED_FILE_COUNT),
        ("MAX_FULL_REVEAL_COUNT", MAX_FULL_REVEAL_COUNT),
        ("MAX_OTS_BYTES", MAX_OTS_BYTES),
        ("MAX_TSA_TOKEN_BYTES", MAX_TSA_TOKEN_BYTES),
        ("MAX_CERT_BYTES", MAX_CERT_BYTES),
        ("MAX_RECEIPT_PAYLOAD_BYTES", MAX_RECEIPT_PAYLOAD_BYTES),
    ];
}
