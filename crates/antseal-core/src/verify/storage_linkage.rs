//! The offline storage-linkage layer (task R20; MVP-SPEC.md lines 116, 119).
//!
//! One question, asked of bytes the bundle already carries: **do these
//! ciphertexts address to the addresses this work records?** Nothing here
//! fetches, and nothing here can fail a bundle.
//!
//! ```text
//! per embedded unit ciphertext   BLAKE3-256(ciphertext)          == manifest unit entry `address`?
//! once, for the manifest         BLAKE3-256(AEAD(k_m, nonce, m)) == storage record `address`?
//! ```
//!
//! `m` is the plaintext manifest envelope the bundle embeds, and the AEAD is
//! C10's — XChaCha20-Poly1305 under the storage record's own `k_m` and nonce
//! with the **empty** AAD (spec line 98). It is deterministic in its inputs,
//! so re-running it reproduces the blob that was uploaded at seal time; the
//! address is a hash of *that*, never of the plaintext, because anchored
//! bytes ≠ stored bytes (spec line 98).
//!
//! # Why this is a layer and not a stage of the evidence pipeline
//!
//! MVP-SPEC.md line 118: *"storage is the product's bonus, not its proof"*.
//! Line 119 puts the linkage layer beside the evidence layer, not inside it.
//! Two things make that structural rather than remembered:
//!
//! 1. **[`check_storage_linkage`] returns no `Result`.** There is no value it
//!    can produce that a caller could propagate as a failure — the same shape
//!    the anchor stage uses for D84 rule F2, where "this artifact does not
//!    verify" changes that artifact's slot and nothing else.
//! 2. **It runs after every evidence stage**, over data those stages have
//!    already finished with, so no evidence check can be sequenced behind it.
//!
//! A bundle whose every recorded address is wrong still verifies. That is not
//! a leniency: the addresses are *sealer-written claims about a network*, the
//! `.sealproof` is unsigned over its storage record (`verify_fuzz.rs`'s
//! `the_unauthenticated_region_at_m0_is_exactly_the_storage_record` sweeps
//! all 88 bytes of it and requires the bundle to verify), and evidence
//! validity may never depend on Autonomi (project rule 4).
//!
//! # BLAKE3-256, and the recorded spec deviation
//!
//! The address rule is [`compute_storage_address`] — one blob is one chunk
//! and its address is BLAKE3-256 of the ciphertext bytes (D32/D35, pinned to
//! `ant-protocol`'s own `compute_address`). MVP-SPEC.md line 119 says "via
//! `self_encryption`"; under D32 that crate appears nowhere in antseal, and
//! the deviation is recorded — [`crate::storage`] carries the citation.
//!
//! # Offline, WASM-safe, and useful with no Autonomi access at all
//!
//! Every input is a sub-slice of the caller's `.sealproof`. There is no I/O,
//! no clock, no randomness and no network, so this runs in the browser
//! verifier and in `wasm32-unknown-unknown` tests exactly as it does
//! natively. Whether the network *still serves* those bytes is a different
//! question with a different answer shape and its own advisory section —
//! `--live` (R11/R21), which is not this.
//!
//! [`compute_storage_address`]: crate::storage::compute_storage_address

use crate::crypto::manifest_aead::{ManifestKey, recompute_manifest_blob};
use crate::crypto::unit_aead::Nonce24;
use crate::manifest::ContentAddress;
use crate::storage::compute_storage_address;

use super::report::StorageLinkageResult;

/// One embedded unit ciphertext and the address the **signed manifest**
/// records for that unit.
///
/// The two halves come from opposite sides of the bundle on purpose: the
/// bytes from the reveal section, the address from the manifest unit table.
/// Checking a bundle's ciphertext against an address the same bundle chose
/// freely would be a tautology; checking it against the manifest's is a
/// statement about what the sealer signed.
#[derive(Debug, Clone, Copy)]
pub struct UnitLinkageSubject<'a> {
    /// Manifest unit-table ordinal, carried so a caller can attribute a
    /// result; this stage reports counts, never ids (see
    /// [`StorageLinkageResult`]).
    pub unit_id: u64,
    /// The ciphertext bytes the bundle embeds for that unit.
    pub ciphertext: &'a [u8],
    /// The address the manifest's unit entry records.
    pub recorded_address: &'a ContentAddress,
}

/// The manifest's own storage triple, plus the plaintext bytes to rebuild
/// the blob from.
///
/// All four fields are bundle content. `manifest_bytes` must be the exact
/// embedded envelope bytes — the pre-image of `anchor_digest` and the input
/// the seal pipeline encrypted (`BundleV1::manifest_bytes`), never a
/// re-encoding: a re-encoded manifest can differ byte-for-byte from the
/// received one and would produce a mismatch that says nothing about
/// storage.
#[derive(Debug, Clone, Copy)]
pub struct ManifestLinkageSubject<'a> {
    /// The embedded plaintext manifest envelope, as received.
    pub manifest_bytes: &'a [u8],
    /// The storage record's nonce.
    pub nonce: &'a Nonce24,
    /// The storage record's `k_m` — disclosed in every bundle, and opening
    /// nothing the bundle does not already contain.
    pub k_m: &'a ManifestKey,
    /// The address the storage record claims.
    pub recorded_address: &'a ContentAddress,
}

/// Reproduce the **encrypted-manifest blob** a bundle's storage record
/// describes: `XChaCha20-Poly1305(k_m, nonce, MANIFEST_AAD, manifest_bytes)`,
/// the bytes the sealer uploaded.
///
/// This is the manifest arm of [`check_storage_linkage`], exposed as its own
/// function so a caller who needs the bytes rather than the verdict can have
/// them — `verify --live`, which byte-compares what the network still serves
/// at [`ManifestLinkageSubject::recorded_address`] against what this returns.
///
/// # R81's ruling: arm (b), and why not the one-word change
///
/// R81 asked for a route to these bytes and named four arms. **Arm (b) is
/// taken: a verification-shaped `pub fn` here, while
/// `recompute_manifest_blob` stays `pub(crate)` in
/// [`crypto::manifest_aead`](crate::crypto::manifest_aead).** The reasoning,
/// recorded so nobody re-derives it:
///
/// - **Arm (a) — widening `recompute_manifest_blob` to `pub` — was refused.**
///   Its own rustdoc argues the `pub(crate)` deliberately: *"A `pub` version
///   of this function would be a general encrypt-under-a-chosen-nonce API
///   wearing a verification name."* That is a nonce-reuse guardrail on the
///   `(k_m, nonce)` single-use invariant, not an oversight, and R81 refuses
///   arm (a) unless the claim is rewritten in the same change. Taking (b)
///   spends nothing: the crypto module still exports no nonce-taking
///   encryption door, so the module's structural claim stays literally true
///   of the API it exports.
/// - **The material was already public, and only the computation was not.**
///   Every input this takes is a field of [`ManifestLinkageSubject`], which
///   is `pub` with `pub` fields because [`check_storage_linkage`] is a public
///   stage. A caller who can call this could already read `k_m`, the nonce
///   and the plaintext out of any bundle and drive `chacha20poly1305`
///   directly — `k_m` ships in every bundle and *"decrypts exactly one thing
///   — the manifest the bundle already embeds in plaintext"*. So this widens
///   reachability of a computation, never disclosure of material.
/// - **The parameter shape is the guardrail, not decoration.** The nonce
///   arrives inside a named linkage subject whose every field is documented
///   as bundle content, in the **verification** layer, rather than as a free
///   `(key, nonce, plaintext)` triple in the crypto layer. A future caller
///   reaching for "encrypt this under a nonce I chose" does not find this
///   function, because it does not have that shape or that home.
/// - **Arm (c)** (compare addresses instead of bytes) was not taken: R11's
///   `StorageRecord` compares against a ciphertext copy, so (c) changes that
///   type — R11-owning work, not this row's.
/// - **Arm (d)** (render the absence permanently) is **not needed once this
///   lands**, and that is the point: the live section reports the manifest
///   subject instead of a sentence explaining why it cannot. The one residue
///   is the `None` case below, and it is unreachable for any decoded
///   manifest.
///
/// Returns `None` exactly when `recompute_manifest_blob` does — only above
/// XChaCha20-Poly1305's `P_MAX` (≈ 256 GiB), which F11's caps put far out of
/// reach. The honest reading of `None` is *these bytes have no blob and so no
/// address*, which is why it is an `Option` and not a verification finding.
///
/// (`crypto::manifest_aead::recompute_manifest_blob` is named in plain text
/// rather than linked: it is `pub(crate)`, and a public item linking to a
/// private one is a rustdoc warning — which is itself the evidence that the
/// encrypt-door was not widened.)
#[must_use]
pub fn recompute_manifest_storage_blob(subject: &ManifestLinkageSubject<'_>) -> Option<Vec<u8>> {
    recompute_manifest_blob(subject.k_m, subject.nonce, subject.manifest_bytes)
}

/// Recompute every subject's address and count the agreements — R20's whole
/// stage, as a pure function.
///
/// Returns [`StorageLinkageResult::Evaluated`] unconditionally: this stage
/// ran, so the slot says so, whatever it found. It never returns
/// [`StorageLinkageResult::NotEvaluated`] — that value means *the stage did
/// not run*, and a stage that reported it about itself would be lying about
/// its own execution.
///
/// A subject whose ciphertext is over [`MAX_CHUNK_SIZE`] counts as a
/// mismatch rather than a third outcome, and the reason is that it is one:
/// v1 has no data-map path, so over-cap content has **no address at all**
/// (D32) and cannot possibly be the content at the recorded one.
///
/// [`MAX_CHUNK_SIZE`]: crate::storage::MAX_CHUNK_SIZE
#[must_use]
pub fn check_storage_linkage(
    units: &[UnitLinkageSubject<'_>],
    manifest: &ManifestLinkageSubject<'_>,
) -> StorageLinkageResult {
    let mut units_matched: u64 = 0;
    let mut units_mismatched: u64 = 0;

    for subject in units {
        if address_matches(subject.ciphertext, subject.recorded_address) {
            units_matched = units_matched.saturating_add(1);
        } else {
            units_mismatched = units_mismatched.saturating_add(1);
        }
    }

    // A manifest that cannot be rebuilt (only reachable above the AEAD's
    // P_MAX) is not a match: there are no blob bytes, so there is no address
    // to agree with the recorded one.
    //
    // Through the public door (R81), not around it: the offline stage and
    // `--live` must reproduce the *same* blob from the *same* code, or the
    // two halves of one storage section could disagree about their subject
    // for a reason no test would show.
    let manifest_matched = recompute_manifest_storage_blob(manifest)
        .is_some_and(|blob| address_matches(&blob, manifest.recorded_address));

    StorageLinkageResult::Evaluated {
        units_matched,
        units_mismatched,
        manifest_matched,
    }
}

/// Does `blob` address to `recorded`? Over-cap content has no address, and
/// so matches nothing (module docs; D32).
fn address_matches(blob: &[u8], recorded: &ContentAddress) -> bool {
    compute_storage_address(blob).is_ok_and(|address| &address == recorded)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::material::Key32;

    /// A `k_m` and nonce with no relationship to any real derivation — this
    /// module only ever *uses* them as AEAD inputs, so a fixture key is a
    /// key.
    fn record_key() -> ManifestKey {
        Key32::from_bytes([0x5C; 32])
    }

    fn record_nonce() -> Nonce24 {
        Nonce24::from_bytes([0x5A; 24])
    }

    /// The address the manifest half is *supposed* to record, computed the
    /// long way round: rebuild the blob, hash it.
    fn true_manifest_address(manifest_bytes: &[u8]) -> ContentAddress {
        let blob = recompute_manifest_blob(&record_key(), &record_nonce(), manifest_bytes)
            .expect("a fixture manifest is far below P_MAX");
        compute_storage_address(&blob).expect("a fixture blob is under the cap")
    }

    fn address_of(bytes: &[u8]) -> ContentAddress {
        compute_storage_address(bytes).expect("fixture bytes are under the cap")
    }

    fn flip(address: &ContentAddress) -> ContentAddress {
        let mut bytes = *address.as_bytes();
        bytes[0] ^= 0x01;
        ContentAddress::from_bytes(bytes)
    }

    /// Everything agrees: three units and the manifest.
    #[test]
    fn all_matching_subjects_report_no_mismatch() {
        let manifest_bytes = b"the plaintext manifest envelope".as_slice();
        let manifest_address = true_manifest_address(manifest_bytes);
        let ciphertexts: Vec<Vec<u8>> = (0..3u8).map(|i| vec![i; 272]).collect();
        let addresses: Vec<ContentAddress> = ciphertexts.iter().map(|c| address_of(c)).collect();
        let units: Vec<UnitLinkageSubject<'_>> = ciphertexts
            .iter()
            .zip(&addresses)
            .enumerate()
            .map(|(index, (ciphertext, address))| UnitLinkageSubject {
                unit_id: u64::try_from(index).expect("three units"),
                ciphertext,
                recorded_address: address,
            })
            .collect();

        let result = check_storage_linkage(
            &units,
            &ManifestLinkageSubject {
                manifest_bytes,
                nonce: &record_nonce(),
                k_m: &record_key(),
                recorded_address: &manifest_address,
            },
        );
        assert_eq!(
            result,
            StorageLinkageResult::Evaluated {
                units_matched: 3,
                units_mismatched: 0,
                manifest_matched: true,
            }
        );
    }

    /// One unit's recorded address is wrong; the manifest's is right.
    #[test]
    fn a_wrong_unit_address_is_counted_against_the_units_only() {
        let manifest_bytes = b"the plaintext manifest envelope".as_slice();
        let manifest_address = true_manifest_address(manifest_bytes);
        let first = vec![0xA1u8; 272];
        let second = vec![0xA2u8; 272];
        let good = address_of(&first);
        let bad = flip(&address_of(&second));

        let result = check_storage_linkage(
            &[
                UnitLinkageSubject {
                    unit_id: 0,
                    ciphertext: &first,
                    recorded_address: &good,
                },
                UnitLinkageSubject {
                    unit_id: 1,
                    ciphertext: &second,
                    recorded_address: &bad,
                },
            ],
            &ManifestLinkageSubject {
                manifest_bytes,
                nonce: &record_nonce(),
                k_m: &record_key(),
                recorded_address: &manifest_address,
            },
        );
        assert_eq!(
            result,
            StorageLinkageResult::Evaluated {
                units_matched: 1,
                units_mismatched: 1,
                manifest_matched: true,
            }
        );
    }

    /// The manifest's recorded address is wrong; every unit's is right —
    /// and the value differs from the unit-mismatch one above, which is the
    /// separation the arm's three fields exist for.
    #[test]
    fn a_wrong_manifest_address_is_counted_against_the_manifest_only() {
        let manifest_bytes = b"the plaintext manifest envelope".as_slice();
        let wrong = flip(&true_manifest_address(manifest_bytes));
        let ciphertext = vec![0xA1u8; 272];
        let address = address_of(&ciphertext);

        let result = check_storage_linkage(
            &[UnitLinkageSubject {
                unit_id: 0,
                ciphertext: &ciphertext,
                recorded_address: &address,
            }],
            &ManifestLinkageSubject {
                manifest_bytes,
                nonce: &record_nonce(),
                k_m: &record_key(),
                recorded_address: &wrong,
            },
        );
        assert_eq!(
            result,
            StorageLinkageResult::Evaluated {
                units_matched: 1,
                units_mismatched: 0,
                manifest_matched: false,
            }
        );
    }

    /// Every input to the manifest half is load-bearing: the right blob is
    /// reproduced only under the right key, the right nonce **and** the
    /// exact received plaintext.
    #[test]
    fn the_manifest_half_is_bound_to_key_nonce_and_plaintext() {
        let manifest_bytes = b"the plaintext manifest envelope".as_slice();
        let address = true_manifest_address(manifest_bytes);
        let other_key: ManifestKey = Key32::from_bytes([0x5D; 32]);
        let other_nonce = Nonce24::from_bytes([0x5B; 24]);
        let re_encoded = b"the plaintext manifest envelope!".as_slice();

        for (label, subject) in [
            (
                "wrong k_m",
                ManifestLinkageSubject {
                    manifest_bytes,
                    nonce: &record_nonce(),
                    k_m: &other_key,
                    recorded_address: &address,
                },
            ),
            (
                "wrong nonce",
                ManifestLinkageSubject {
                    manifest_bytes,
                    nonce: &other_nonce,
                    k_m: &record_key(),
                    recorded_address: &address,
                },
            ),
            (
                "one byte of plaintext",
                ManifestLinkageSubject {
                    manifest_bytes: re_encoded,
                    nonce: &record_nonce(),
                    k_m: &record_key(),
                    recorded_address: &address,
                },
            ),
        ] {
            assert_eq!(
                check_storage_linkage(&[], &subject),
                StorageLinkageResult::Evaluated {
                    units_matched: 0,
                    units_mismatched: 0,
                    manifest_matched: false,
                },
                "{label}: the manifest half agreed with an address it cannot produce"
            );
        }
    }

    /// No embedded ciphertexts — an untouched bundle proves the work exists
    /// and shows none of it, and the manifest half still speaks.
    #[test]
    fn a_bundle_with_no_reveals_still_checks_the_manifest() {
        let manifest_bytes = b"the plaintext manifest envelope".as_slice();
        let address = true_manifest_address(manifest_bytes);
        assert_eq!(
            check_storage_linkage(
                &[],
                &ManifestLinkageSubject {
                    manifest_bytes,
                    nonce: &record_nonce(),
                    k_m: &record_key(),
                    recorded_address: &address,
                },
            ),
            StorageLinkageResult::Evaluated {
                units_matched: 0,
                units_mismatched: 0,
                manifest_matched: true,
            }
        );
    }

    /// Over-cap content has no v1 address (D32), so it matches nothing —
    /// including an address that *is* BLAKE3 of those very bytes. The rule
    /// is "no address exists", not "the hash disagrees".
    #[test]
    fn over_cap_content_matches_nothing_not_even_its_own_hash() {
        let manifest_bytes = b"the plaintext manifest envelope".as_slice();
        let over = vec![0xABu8; crate::storage::MAX_CHUNK_SIZE + 1];
        let hash = ContentAddress::from_bytes(*blake3::hash(&over).as_bytes());

        let result = check_storage_linkage(
            &[UnitLinkageSubject {
                unit_id: 0,
                ciphertext: &over,
                recorded_address: &hash,
            }],
            &ManifestLinkageSubject {
                manifest_bytes,
                nonce: &record_nonce(),
                k_m: &record_key(),
                recorded_address: &true_manifest_address(manifest_bytes),
            },
        );
        assert_eq!(
            result,
            StorageLinkageResult::Evaluated {
                units_matched: 0,
                units_mismatched: 1,
                manifest_matched: true,
            }
        );
    }

    /// The stage never reports "not evaluated" about a run in which it
    /// evaluated — the one value it must never produce.
    #[test]
    fn the_stage_never_reports_not_evaluated() {
        let manifest_bytes = b"m".as_slice();
        let result = check_storage_linkage(
            &[],
            &ManifestLinkageSubject {
                manifest_bytes,
                nonce: &record_nonce(),
                k_m: &record_key(),
                recorded_address: &ContentAddress::from_bytes([0x00; 32]),
            },
        );
        assert_ne!(result, StorageLinkageResult::NotEvaluated);
    }
}
