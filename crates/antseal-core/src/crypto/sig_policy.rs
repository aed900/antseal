//! `sig_policy` validation and hybrid sign/verify orchestration (task C14;
//! MVP-SPEC.md lines 97, 98, 104).
//!
//! The policy is an ordered list of **registered algorithm ids** living in
//! the signed manifest body. It must be non-empty, duplicate-free, and
//! registered-only — otherwise a signature-less manifest could verify
//! vacuously — and at verify time the **present signature set must equal the
//! policy set**: every listed signature is validated, and a missing, invalid,
//! or *present-but-unlisted* signature is a hard failure. A hybrid manifest
//! therefore never passes on one good signature.
//!
//! # The algorithm-ID registry
//!
//! | id | algorithm | pubkey | signature |
//! | --- | --- | --- | --- |
//! | 0 | Ed25519 | 32 B | 64 B |
//! | 1 | ML-DSA-65 | 1952 B | 3309 B |
//! | 2–15 | reserved | — | — |
//!
//! Ed25519 is id 0 because the reserved fallback policy is `[0]` (spec
//! line 97). The numeric assignment is decision **D17**, proposed in the F4
//! registry and ratified here; it freezes with the wire format at Q14.
//! [`sig_alg_from_id`] / [`sig_alg_to_id`] are the semantic mapping this
//! module owns; F's wire registry
//! ([`crate::manifest::registry::sig_alg_from_wire`]) encodes the same
//! assignment, and `crypto_and_manifest_registries_agree` below pins the two
//! together so they can never drift.
//!
//! # Anti-downgrade
//!
//! The policy sits **inside the signed body**, so stripping ML-DSA from an
//! existing hybrid manifest changes the body bytes and breaks *both*
//! signatures — and, once anchored, the anchors too. A fresh Ed25519-only
//! forgery is therefore a different body, hence a different `work_id` with
//! its own (later) anchors, never a downgrade of the original work
//! (`downgrading_a_hybrid_policy_breaks_both_signatures`).
//!
//! # Fallback
//!
//! `sig_policy = [ed25519]` is a first-class shape, not a special case: it
//! runs the identical orchestration code and is exercised in CI regardless
//! of the C11 probe outcome (which came out in ML-DSA's favor, so hybrid is
//! what v1 ships — D14). The verification result carries [`PolicyLabel`] so
//! R can render "hybrid (PQ)" vs "Ed25519-only" unambiguously.

use super::error::{CryptoError, SigAlg, SigMaterialKind};
use super::material::MasterSecretRef;
use super::{sig_ed25519, sig_mldsa};

/// Wire id of Ed25519 in the `sig_policy` registry (D17).
pub const ID_ED25519: u64 = 0;
/// Wire id of ML-DSA-65 in the `sig_policy` registry (D17).
pub const ID_MLDSA65: u64 = 1;
/// First id reserved for future algorithms (D17: 2–15 reserved).
pub const FIRST_RESERVED_ID: u64 = 2;

/// The registered algorithm for a wire id, or `None` if unregistered.
#[must_use]
pub const fn sig_alg_from_id(id: u64) -> Option<SigAlg> {
    match id {
        ID_ED25519 => Some(SigAlg::Ed25519),
        ID_MLDSA65 => Some(SigAlg::MlDsa65),
        _ => None,
    }
}

/// The wire id of an algorithm. Wildcard-free: a new [`SigAlg`] variant
/// fails to compile until it is assigned an id.
#[must_use]
pub const fn sig_alg_to_id(alg: SigAlg) -> u64 {
    match alg {
        SigAlg::Ed25519 => ID_ED25519,
        SigAlg::MlDsa65 => ID_MLDSA65,
    }
}

/// Per-algorithm material in policy order: the shape of both the body's
/// `pubkeys` map and the envelope's `signatures` map as this module
/// consumes and produces them (F encodes them; R5 adapts from
/// [`crate::manifest::sigmap::SigAlgMap`]).
pub type AlgMaterial = Vec<(SigAlg, Vec<u8>)>;

/// Which policy a verification satisfied — the datum R turns into the
/// verdict label (spec line 97).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PolicyLabel {
    /// Every registered algorithm was required and verified: "hybrid (PQ)".
    Hybrid,
    /// The reserved Ed25519-only fallback shape.
    Ed25519Only,
    /// A registered-but-not-hybrid, not-Ed25519-only shape (e.g. a
    /// future ML-DSA-only policy). Named so R never has to guess.
    Other,
}

/// A validated `sig_policy`: non-empty, duplicate-free, registered-only.
///
/// The invariants hold by construction — there is no way to build one that
/// violates them, so downstream code never re-checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigPolicy(Vec<SigAlg>);

impl SigPolicy {
    /// Validate a policy given as algorithms (the seal-side entry point).
    ///
    /// # Errors
    ///
    /// - [`CryptoError::SigPolicyEmpty`] — no entries.
    /// - [`CryptoError::SigPolicyDuplicate`] — an algorithm listed twice.
    pub fn new(algorithms: impl IntoIterator<Item = SigAlg>) -> Result<Self, CryptoError> {
        let algorithms: Vec<SigAlg> = algorithms.into_iter().collect();
        if algorithms.is_empty() {
            return Err(CryptoError::SigPolicyEmpty);
        }
        for (index, alg) in algorithms.iter().enumerate() {
            if algorithms[..index].contains(alg) {
                return Err(CryptoError::SigPolicyDuplicate);
            }
        }
        Ok(Self(algorithms))
    }

    /// Validate a policy given as wire ids (the decode-side entry point).
    ///
    /// # Errors
    ///
    /// As [`Self::new`], plus [`CryptoError::SigPolicyUnknownAlg`] when an
    /// id is not registered — the parse-time reject of spec line 97, which
    /// is what stops an attacker listing an algorithm no verifier checks.
    pub fn from_ids(ids: impl IntoIterator<Item = u64>) -> Result<Self, CryptoError> {
        let mut algorithms = Vec::new();
        for id in ids {
            algorithms.push(sig_alg_from_id(id).ok_or(CryptoError::SigPolicyUnknownAlg)?);
        }
        Self::new(algorithms)
    }

    /// The frozen hybrid policy `[ed25519, ml-dsa-65]` — what v1 ships.
    #[must_use]
    pub fn hybrid() -> Self {
        Self(vec![SigAlg::Ed25519, SigAlg::MlDsa65])
    }

    /// The reserved Ed25519-only fallback policy `[ed25519]` (spec line 97).
    #[must_use]
    pub fn ed25519_only() -> Self {
        Self(vec![SigAlg::Ed25519])
    }

    /// The listed algorithms, in policy order.
    #[must_use]
    pub fn algorithms(&self) -> &[SigAlg] {
        &self.0
    }

    /// The wire ids, in policy order (F encodes these).
    #[must_use]
    pub fn ids(&self) -> Vec<u64> {
        self.0.iter().copied().map(sig_alg_to_id).collect()
    }

    /// Whether `alg` is required by this policy.
    #[must_use]
    pub fn requires(&self, alg: SigAlg) -> bool {
        self.0.contains(&alg)
    }

    /// The verdict label for this policy shape.
    #[must_use]
    pub fn label(&self) -> PolicyLabel {
        let has_ed = self.requires(SigAlg::Ed25519);
        let has_mldsa = self.requires(SigAlg::MlDsa65);
        match (has_ed, has_mldsa) {
            (true, true) => PolicyLabel::Hybrid,
            (true, false) => PolicyLabel::Ed25519Only,
            _ => PolicyLabel::Other,
        }
    }
}

/// The public keys this policy's algorithms derive from `W`, in policy
/// order — what the seal side writes into the body's `pubkeys` map.
#[must_use]
pub fn public_keys(w: MasterSecretRef<'_>, policy: &SigPolicy) -> AlgMaterial {
    policy
        .algorithms()
        .iter()
        .map(|alg| {
            let bytes = match alg {
                SigAlg::Ed25519 => sig_ed25519::public_key(w).as_bytes().to_vec(),
                SigAlg::MlDsa65 => sig_mldsa::public_key(w).as_bytes().to_vec(),
            };
            (*alg, bytes)
        })
        .collect()
}

/// Sign `body` with **every** algorithm the policy lists, in policy order.
///
/// Each algorithm binds the frozen context by its own rules (Ed25519 folds
/// `ctx ‖ 0x00` into the pre-image; ML-DSA uses the FIPS 204 `ctx`
/// parameter), and both sign the *exact* body bytes — never a re-encoding.
#[must_use]
pub fn sign_body(w: MasterSecretRef<'_>, policy: &SigPolicy, body: &[u8]) -> AlgMaterial {
    policy
        .algorithms()
        .iter()
        .map(|alg| {
            let bytes = match alg {
                SigAlg::Ed25519 => sig_ed25519::sign(w, body).as_bytes().to_vec(),
                SigAlg::MlDsa65 => sig_mldsa::sign(w, body).as_bytes().to_vec(),
            };
            (*alg, bytes)
        })
        .collect()
}

/// Verify a manifest body against its policy, enforcing
/// **present set == policy set**.
///
/// `pubkeys` and `signatures` are `(algorithm, bytes)` pairs as enumerated
/// from the body's `pubkeys` map and the envelope's `signatures` map. F's
/// schema already guarantees both are duplicate-free and exact-length (a
/// repeated map key dies as `cbor-duplicate-map-key` before decode
/// completes), and **both properties are independently re-checked here** —
/// duplicates by the scan below, lengths by each algorithm's
/// `try_from_slice` — so this function is safe to call on any input, not
/// only on schema-validated material. Without the duplicate re-check the
/// first-wins `lookup` would quietly verify one of two conflicting entries,
/// and a last-wins or duplicate-rejecting implementation would reach a
/// different verdict on the same input — the cross-implementation
/// divergence class MVP-SPEC.md line 73 names (C28).
///
/// Order of checks is fixed for deterministic first-error reporting:
/// duplicate entries first, pubkeys before signatures (a duplicated
/// algorithm makes "the entry for algorithm X" ambiguous, so nothing else
/// is adjudicated); then unlisted signatures (a present-but-unlisted entry
/// is a structural lie about the policy); then, per policy algorithm in
/// order, missing signature → missing key → the algorithm's own
/// verification.
///
/// # Errors
///
/// - [`CryptoError::SigMaterialDuplicate`] — the same algorithm appears
///   more than once in `pubkeys` or in `signatures` (listed or not).
/// - [`CryptoError::SignatureUnlisted`] — a signature for an algorithm the
///   policy does not list.
/// - [`CryptoError::SignatureMissing`] — a listed algorithm has no
///   signature (or no public key) present.
/// - [`CryptoError::NonCanonicalSignature`] — the signature (or key) is
///   the wrong length or a non-canonical encoding.
/// - [`CryptoError::SignatureInvalid`] — a well-formed signature that does
///   not verify.
pub fn verify_body(
    policy: &SigPolicy,
    pubkeys: &[(SigAlg, Vec<u8>)],
    signatures: &[(SigAlg, Vec<u8>)],
    body: &[u8],
) -> Result<PolicyLabel, CryptoError> {
    for (kind, entries) in [
        (SigMaterialKind::Pubkeys, pubkeys),
        (SigMaterialKind::Signatures, signatures),
    ] {
        if let Some(alg) = first_duplicate(entries) {
            return Err(CryptoError::SigMaterialDuplicate { kind, alg });
        }
    }

    for (alg, _) in signatures {
        if !policy.requires(*alg) {
            return Err(CryptoError::SignatureUnlisted { alg: *alg });
        }
    }

    for alg in policy.algorithms() {
        let signature =
            lookup(signatures, *alg).ok_or(CryptoError::SignatureMissing { alg: *alg })?;
        let pubkey = lookup(pubkeys, *alg).ok_or(CryptoError::SignatureMissing { alg: *alg })?;

        match alg {
            SigAlg::Ed25519 => {
                let key = sig_ed25519::Ed25519PublicKey::try_from_slice(pubkey)?;
                let sig = sig_ed25519::Ed25519Signature::try_from_slice(signature)?;
                sig_ed25519::verify(&key, body, &sig)?;
            }
            SigAlg::MlDsa65 => {
                let key = sig_mldsa::MlDsa65PublicKey::try_from_slice(pubkey)?;
                let sig = sig_mldsa::MlDsa65Signature::try_from_slice(signature)?;
                sig_mldsa::verify(&key, body, &sig)?;
            }
        }
    }

    Ok(policy.label())
}

/// First-wins by construction — which is exactly why [`verify_body`] runs
/// [`first_duplicate`] before any lookup: on duplicate-free input (the only
/// input that survives the scan) first-wins and last-wins are the same
/// function.
fn lookup(entries: &[(SigAlg, Vec<u8>)], alg: SigAlg) -> Option<&[u8]> {
    entries
        .iter()
        .find(|(entry_alg, _)| *entry_alg == alg)
        .map(|(_, bytes)| bytes.as_slice())
}

/// The first algorithm to appear twice in `entries`, if any — the C28
/// duplicate re-check backing [`verify_body`]'s any-input safety claim.
/// Quadratic in shape but constant in practice: with only
/// [`SigAlg::ALL`]`.len()` distinct algorithms, a duplicate exists within
/// the first three entries or not at all.
fn first_duplicate(entries: &[(SigAlg, Vec<u8>)]) -> Option<SigAlg> {
    entries.iter().enumerate().find_map(|(index, (alg, _))| {
        entries[..index]
            .iter()
            .any(|(seen, _)| seen == alg)
            .then_some(*alg)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const BODY: &[u8] = b"a manifest body, as received";

    /// Fixed, public, NON-SECRET test master secrets (project rule 6).
    const TEST_W: [u8; 32] = [0x11; 32];
    const OTHER_W: [u8; 32] = [0x22; 32];

    fn w() -> MasterSecretRef<'static> {
        MasterSecretRef::from_bytes(&TEST_W)
    }

    fn other_w() -> MasterSecretRef<'static> {
        MasterSecretRef::from_bytes(&OTHER_W)
    }

    fn signed(policy: &SigPolicy) -> (AlgMaterial, AlgMaterial) {
        (public_keys(w(), policy), sign_body(w(), policy, BODY))
    }

    // ── policy validation: three distinct parse-time rejects ──

    #[test]
    fn empty_duplicate_and_unregistered_policies_are_three_distinct_errors() {
        let empty = SigPolicy::new([]).expect_err("empty policy is rejected");
        let duplicate = SigPolicy::new([SigAlg::Ed25519, SigAlg::Ed25519])
            .expect_err("duplicate policy is rejected");
        let unknown = SigPolicy::from_ids([7]).expect_err("unregistered id is rejected");

        assert_eq!(empty, CryptoError::SigPolicyEmpty);
        assert_eq!(duplicate, CryptoError::SigPolicyDuplicate);
        assert_eq!(unknown, CryptoError::SigPolicyUnknownAlg);

        let codes = [empty.code(), duplicate.code(), unknown.code()];
        let mut unique = codes.to_vec();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(
            unique.len(),
            3,
            "policy rejects must be distinct: {codes:?}"
        );
    }

    #[test]
    fn every_reserved_id_is_rejected() {
        for id in FIRST_RESERVED_ID..=15 {
            assert_eq!(
                SigPolicy::from_ids([id]).expect_err("reserved ids are unregistered"),
                CryptoError::SigPolicyUnknownAlg,
                "id {id}"
            );
        }
        assert_eq!(
            SigPolicy::from_ids([u64::MAX]).expect_err("huge ids are unregistered"),
            CryptoError::SigPolicyUnknownAlg
        );
    }

    /// D17's numeric assignment, ratified here and pinned against F's wire
    /// registry so the two encodings can never drift apart.
    #[test]
    fn crypto_and_manifest_registries_agree() {
        use crate::manifest::registry::{sig_alg_from_wire, sig_alg_to_wire};

        assert_eq!(sig_alg_to_id(SigAlg::Ed25519), 0);
        assert_eq!(sig_alg_to_id(SigAlg::MlDsa65), 1);
        for alg in SigAlg::ALL {
            assert_eq!(sig_alg_to_id(alg), sig_alg_to_wire(alg));
            assert_eq!(sig_alg_from_id(sig_alg_to_id(alg)), Some(alg));
        }
        for id in 0..=20u64 {
            assert_eq!(sig_alg_from_id(id), sig_alg_from_wire(id), "id {id}");
        }
    }

    #[test]
    fn labels_name_the_policy_shape() {
        assert_eq!(SigPolicy::hybrid().label(), PolicyLabel::Hybrid);
        assert_eq!(SigPolicy::ed25519_only().label(), PolicyLabel::Ed25519Only);
        assert_eq!(
            SigPolicy::new([SigAlg::MlDsa65])
                .expect("valid policy")
                .label(),
            PolicyLabel::Other
        );
        // Policy order does not change the label.
        assert_eq!(
            SigPolicy::new([SigAlg::MlDsa65, SigAlg::Ed25519])
                .expect("valid policy")
                .label(),
            PolicyLabel::Hybrid
        );
    }

    // ── hybrid orchestration ──

    #[test]
    fn hybrid_round_trip_carries_the_hybrid_label() {
        let policy = SigPolicy::hybrid();
        let (keys, sigs) = signed(&policy);
        assert_eq!(sigs.len(), 2);
        assert_eq!(
            verify_body(&policy, &keys, &sigs, BODY).expect("hybrid verifies"),
            PolicyLabel::Hybrid
        );
    }

    /// The fallback shape runs the identical code path and is exercised in
    /// CI regardless of the probe outcome (C14 accept).
    #[test]
    fn ed25519_only_fallback_round_trips_through_the_same_path() {
        let policy = SigPolicy::ed25519_only();
        let (keys, sigs) = signed(&policy);
        assert_eq!(sigs.len(), 1);
        assert_eq!(
            verify_body(&policy, &keys, &sigs, BODY).expect("fallback verifies"),
            PolicyLabel::Ed25519Only
        );
    }

    #[test]
    fn a_removed_signature_is_missing_not_a_pass() {
        let policy = SigPolicy::hybrid();
        let (keys, mut sigs) = signed(&policy);
        sigs.retain(|(alg, _)| *alg != SigAlg::MlDsa65);

        assert_eq!(
            verify_body(&policy, &keys, &sigs, BODY).expect_err("one good signature is not enough"),
            CryptoError::SignatureMissing {
                alg: SigAlg::MlDsa65
            }
        );
    }

    #[test]
    fn a_corrupted_signature_is_invalid() {
        let policy = SigPolicy::hybrid();
        let (keys, sigs) = signed(&policy);

        // Re-sign the Ed25519 slot under a different W: well-formed, wrong.
        let mut tampered = sigs.clone();
        for entry in &mut tampered {
            if entry.0 == SigAlg::Ed25519 {
                entry.1 = sig_ed25519::sign(other_w(), BODY).as_bytes().to_vec();
            }
        }
        assert_eq!(
            verify_body(&policy, &keys, &tampered, BODY).expect_err("wrong key must fail"),
            CryptoError::SignatureInvalid {
                alg: SigAlg::Ed25519
            }
        );
    }

    #[test]
    fn an_unlisted_signature_is_rejected_even_when_valid() {
        // Policy lists only Ed25519, but a valid ML-DSA signature rides
        // along: the present set must EQUAL the policy set.
        let policy = SigPolicy::ed25519_only();
        let (keys, mut sigs) = signed(&policy);
        sigs.push((
            SigAlg::MlDsa65,
            sig_mldsa::sign(w(), BODY).as_bytes().to_vec(),
        ));

        assert_eq!(
            verify_body(&policy, &keys, &sigs, BODY).expect_err("unlisted entries are rejected"),
            CryptoError::SignatureUnlisted {
                alg: SigAlg::MlDsa65
            }
        );
    }

    #[test]
    fn a_wrong_length_signature_is_non_canonical_not_invalid() {
        let policy = SigPolicy::ed25519_only();
        let (keys, mut sigs) = signed(&policy);
        sigs[0].1.truncate(63);

        let err = verify_body(&policy, &keys, &sigs, BODY).expect_err("short signature");
        assert_eq!(
            err,
            CryptoError::NonCanonicalSignature {
                alg: SigAlg::Ed25519
            }
        );
    }

    #[test]
    fn a_body_mutation_invalidates_every_signature() {
        let policy = SigPolicy::hybrid();
        let (keys, sigs) = signed(&policy);
        let mut mutated = BODY.to_vec();
        mutated[0] ^= 0x01;

        assert_eq!(
            verify_body(&policy, &keys, &sigs, &mutated).expect_err("body is signed"),
            CryptoError::SignatureInvalid {
                alg: SigAlg::Ed25519
            }
        );
    }

    /// Anti-downgrade (spec line 97): the policy lives inside the signed
    /// body, so stripping ML-DSA from a hybrid manifest changes the body
    /// bytes and breaks **both** signatures. There is no way to present the
    /// original work as Ed25519-only.
    #[test]
    fn downgrading_a_hybrid_policy_breaks_both_signatures() {
        let hybrid = SigPolicy::hybrid();

        // A body that embeds its own policy — the real manifest shape, in
        // miniature: the ids are part of the signed bytes.
        let body_with = |policy: &SigPolicy| {
            let mut bytes = b"body|policy=".to_vec();
            for id in policy.ids() {
                bytes.push(u8::try_from(id).expect("registry ids are small"));
            }
            bytes
        };

        let signed_body = body_with(&hybrid);
        let keys = public_keys(w(), &hybrid);
        let sigs = sign_body(w(), &hybrid, &signed_body);
        verify_body(&hybrid, &keys, &sigs, &signed_body).expect("the original verifies");

        // The attacker strips ML-DSA: new policy, new body bytes, old
        // signatures. Both signatures now fail — the Ed25519 one is simply
        // over different bytes.
        let downgraded = SigPolicy::ed25519_only();
        let downgraded_body = body_with(&downgraded);
        assert_ne!(signed_body, downgraded_body);

        let kept: Vec<_> = sigs
            .iter()
            .filter(|(alg, _)| *alg == SigAlg::Ed25519)
            .cloned()
            .collect();
        assert_eq!(
            verify_body(&downgraded, &keys, &kept, &downgraded_body)
                .expect_err("a downgraded body is not signed"),
            CryptoError::SignatureInvalid {
                alg: SigAlg::Ed25519
            }
        );
    }

    // ── C28: duplicate entries in the material collections ──

    /// The adversarial-review input (2026-07-31 finding 5), verbatim:
    /// `[(Ed25519, valid), (Ed25519, garbage), (MlDsa65, valid)]`. Before
    /// the C28 re-check this returned `Ok(Hybrid)` — the duplicate passed
    /// the unlisted loop (`requires(Ed25519)` is true for it) and the
    /// first-wins `lookup` never inspected the garbage — while a last-wins
    /// or duplicate-rejecting implementation reached a different verdict
    /// on the same input, the cross-implementation divergence class
    /// MVP-SPEC.md line 73 names.
    #[test]
    fn a_duplicate_signature_entry_is_rejected_not_first_wins_verified() {
        let policy = SigPolicy::hybrid();
        let (keys, mut sigs) = signed(&policy);
        // Well-formed length, garbage content: a first-wins verifier
        // passes without ever looking at it.
        sigs.insert(1, (SigAlg::Ed25519, vec![0x99; 64]));

        assert_eq!(
            verify_body(&policy, &keys, &sigs, BODY)
                .expect_err("a duplicated listed algorithm must be rejected"),
            CryptoError::SigMaterialDuplicate {
                kind: SigMaterialKind::Signatures,
                alg: SigAlg::Ed25519
            }
        );
    }

    /// The pubkeys side of the same check — and with a **byte-identical**
    /// duplicate: the invariant being re-checked is F's map shape (a CBOR
    /// map cannot carry the same key twice), which does not care whether
    /// the two values happen to agree.
    #[test]
    fn a_duplicate_pubkey_entry_is_rejected_even_when_byte_identical() {
        let policy = SigPolicy::hybrid();
        let (mut keys, sigs) = signed(&policy);
        let duplicate = keys[0].clone();
        keys.insert(1, duplicate);

        assert_eq!(
            verify_body(&policy, &keys, &sigs, BODY).expect_err("a duplicated pubkey entry"),
            CryptoError::SigMaterialDuplicate {
                kind: SigMaterialKind::Pubkeys,
                alg: SigAlg::Ed25519
            }
        );
    }

    /// The documented first-error order: the duplicate scan adjudicates
    /// collection shape before any cross-collection comparison, so a
    /// duplicate of an *unlisted* algorithm reports the duplicate, not
    /// `SignatureUnlisted` — and pubkeys is scanned before signatures.
    #[test]
    fn duplicate_scan_precedes_the_unlisted_check_and_pubkeys_precede_signatures() {
        let policy = SigPolicy::ed25519_only();
        let (keys, mut sigs) = signed(&policy);
        let mldsa = sig_mldsa::sign(w(), BODY).as_bytes().to_vec();
        sigs.push((SigAlg::MlDsa65, mldsa.clone()));
        sigs.push((SigAlg::MlDsa65, mldsa));
        assert_eq!(
            verify_body(&policy, &keys, &sigs, BODY).expect_err("duplicate beats unlisted"),
            CryptoError::SigMaterialDuplicate {
                kind: SigMaterialKind::Signatures,
                alg: SigAlg::MlDsa65
            }
        );

        let policy = SigPolicy::hybrid();
        let (mut keys, mut sigs) = signed(&policy);
        let key = keys[0].clone();
        keys.insert(1, key);
        let sig = sigs[0].clone();
        sigs.insert(1, sig);
        assert_eq!(
            verify_body(&policy, &keys, &sigs, BODY).expect_err("pubkeys is scanned first"),
            CryptoError::SigMaterialDuplicate {
                kind: SigMaterialKind::Pubkeys,
                alg: SigAlg::Ed25519
            }
        );
    }

    #[test]
    fn public_keys_and_signatures_follow_policy_order() {
        let reversed = SigPolicy::new([SigAlg::MlDsa65, SigAlg::Ed25519]).expect("valid policy");
        let (keys, sigs) = signed(&reversed);
        assert_eq!(keys[0].0, SigAlg::MlDsa65);
        assert_eq!(sigs[0].0, SigAlg::MlDsa65);
        // Order is presentation only: verification is set-based.
        assert_eq!(
            verify_body(&reversed, &keys, &sigs, BODY).expect("verifies in any order"),
            PolicyLabel::Hybrid
        );
    }
}
