//! X.509 path validation to the pinned roots, with `genTime` long-term
//! validation (task **A9**) — stage **T3** of D53's per-artifact order.
//!
//! Runs only after [`super::tsa::verify_token`] (T2) has established that the
//! token is internally what it claims to be. That order is normative and
//! load-bearing: `internally-consistent-only` must mean *cryptographically
//! well-formed but not anchored to a pinned root*, so a token whose CMS
//! signature does not verify must never reach this module at all.
//!
//! # The six-way partition, not a coin flip
//!
//! D53 overturned the framing that "a chain that does not validate at
//! `genTime`" is one situation. It is six, and two of them were already ruled
//! the *opposite* way by MVP-SPEC.md lines 109 and 133. The partition
//! principle, which this module implements and does not re-derive:
//!
//! > An anchor renders `Invalid` iff the artifact makes a claim the verifier
//! > can **refute** from material it already trusts. It renders
//! > `InternallyConsistentOnly` iff it makes **no refutable claim and no
//! > confirmable one** — well-formed, and pointing at nothing we hold.
//!
//! So: temporal failure at `genTime` **in either direction**, a failed path
//! constraint, or a failed link signature, *on a chain that names a pinned
//! root* → [`AnchorState::Invalid`]. No pinned root reached at all —
//! **bundle-supplied roots included** → [`AnchorState::InternallyConsistentOnly`].
//!
//! The **not-yet-valid** direction is the half that appears in no spec line,
//! no task text and no matrix row, and it is the adversarially interesting
//! one: `notAfter < genTime` is mostly TSA sloppiness, while
//! `notBefore > genTime` is **back-dating** — a token asserting a time before
//! the signing key's certificate existed, which is the cheapest form of the
//! priority fraud antseal exists to make expensive.
//!
//! # Three path rulings that came out of real tokens, and one that ships broken without
//!
//! D57 measured five live TSAs. Each ruling below is implemented here and
//! **not** re-derived:
//!
//! - **P1 — stop at the first pinned match.** Two of five real chains
//!   (DigiCert→Assured ID, Sectigo→USERTrust) terminate at a
//!   **cross-certificate**: same subject DN and same SPKI as the self-signed
//!   root, different issuer. The natural implementation — walk the supplied
//!   chain to its end, then ask whether the terminal certificate is pinned —
//!   anchors on an *unpinned* certificate and renders **the production
//!   DigiCert default** as `internally-consistent-only`. Here a path
//!   terminates the moment it can close on a pinned root; certificates beyond
//!   that point are never consumed, never anchors, and their presence is not
//!   an error.
//! - **P2 — never anchor on a supplied self-signed certificate.** Enforced
//!   *structurally*: [`PathBuilder`] closes only on [`PinnedRoot`], and
//!   supplied certificates enter the search only as intermediates. There is
//!   no single certificate pool, which is the one-pool implementation D53
//!   §5(c) names as silently turning a sealer-written self-signed chain into
//!   `proven`. Three of the five real TSAs ship their own self-signed root in
//!   every token, so this path is exercised on every production verification,
//!   not only by a negative test.
//! - **P3 — no ordering assumption.** `certificates` is an ASN.1 SET and five
//!   real tokens showed **three** distinct orders. Nothing below reads a
//!   position: not element 0 as the leaf (DFN and SwissSign put a CA there),
//!   not the last element as the anchor.
//!
//! A24's test CA never cross-signs and never ships its own root in a token,
//! so **no synthetic fixture can reach P1's defect**. That is what A43's real
//! tokens are for, and they are in this module's own `#[cfg(test)]` suite
//! rather than under `tests/` so they run on `wasm32-unknown-unknown` too.
//!
//! # No clock, here or anywhere below
//!
//! `verify_at_unix` is a **parameter**. `antseal-core` reads no clock at all,
//! which is what makes the WASM verifier bit-match the native one. It is also
//! why the obvious `gen_time <= fetch_date` sanity check is unmakeable here:
//! the host that captured every committed fixture ran **129 s slow**, and that
//! check rejects all of them (A32 owns the prohibition on the capture side,
//! where a clock does exist).
//!
//! # No revocation checking, and what that costs
//!
//! Out of MVP scope by decision (A9's own note), and the framing "valid at
//! stamping" reads as stronger than it is, so the cost is stated here rather
//! than left to be inferred. **A TSA key compromised and its certificate
//! revoked *after* `genTime` still yields [`AnchorState::Proven`]**, because
//! nothing here consults a CRL or an OCSP responder — and under D53 §5(a) a
//! revoked *root* is not detected at all, since a trust anchor is an input to
//! path validation rather than a certificate to be validated. Fetching either
//! would also break the offline guarantee that MVP-SPEC.md line 38 makes for
//! this path. Q's threat model owns the exposure; the revisit trigger is any
//! v1.1 CRL/OCSP work, or a real TSA compromise.
//!
//! `verify_at` is additionally **one-sided** (D53 §5b): it can only separate
//! `proven` from `valid-at-stamping-cert-since-expired`, via
//! `notAfter < verify_at`. It is never a validity check, so a caller with a
//! wrong clock — or a WASM page passing a fixed value — gets `proven`, never a
//! failure. No path from `verify_at` to `Invalid` exists.

use std::collections::BTreeMap;

use der::Encode as _;
use x509_cert::Certificate;
use x509_cert::ext::pkix::{
    AuthorityKeyIdentifier, BasicConstraints, KeyUsage, KeyUsages, SubjectKeyIdentifier,
};

use crate::verify::report::AnchorState;

use super::alg::{self, Digest, SigFamily};
use super::caps::MAX_CHAIN_CERTS;
use super::error::AlgPosition;
use super::roots::{PinnedRoot, TsaRootStore};
use super::tsa::VerifiedToken;

/// Which temporal bound a certificate crossed at `genTime`.
///
/// Diagnostic payload only: **both directions carry the same error code**
/// (D53 §7), because both are the single predicate
/// `notBefore <= genTime <= notAfter` failing, and D85's rule is that a cause
/// belongs in rendering rather than in the code set. The direction is here so
/// R18 can say which, and so the back-dating half is nameable at all.
///
/// The ordering is deliberate and load-bearing for determinism:
/// `Expired < NotYetValid`, so when several certificates fail in different
/// directions the reported direction is a total function of the artifact
/// rather than of enumeration order. The code is identical either way, so no
/// verdict depends on the tie-break.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TemporalBound {
    /// `notAfter < genTime` — the certificate had already expired when the
    /// token says it was stamped.
    Expired,
    /// `notBefore > genTime` — **back-dating**. The token asserts a time
    /// before the certificate existed.
    NotYetValid,
}

/// The three ways a chain that *reaches* a pinned root can fail against it.
///
/// All three codes are ruled by D53 §7 and must not be respelled. They are
/// stage-T3 codes and live here rather than in [`super::error::AnchorError`],
/// whose domain is stages T1 and T2.
///
/// **These codes never enter [`crate::verify::report::VerificationReport`]**
/// (D53 §6). `AnchorResult` has exactly five fields and report v1 is frozen;
/// the obvious way to satisfy A9's "with a distinct error detail" is to add a
/// sixth field, which would bump `REPORT_VERSION` and re-emit all 21 pinned
/// report strings. The codes live in the verdict datum; R12 projects and
/// drops them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ChainFault {
    /// Some certificate on every otherwise-good path to a pinned root was
    /// outside its validity window at the token's `genTime` — **either**
    /// direction.
    CertNotValidAtGenTime {
        /// Which bound was crossed, for rendering.
        bound: TemporalBound,
    },
    /// Every signature-closed path to a pinned root violates
    /// `basicConstraints`, `keyUsage`, or `pathLenConstraint`.
    ChainConstraintViolation,
    /// Every name-chaining path to a pinned root contains a link whose
    /// signature does not verify.
    ChainSignatureInvalid,
}

impl ChainFault {
    /// The stable machine-readable name of this failure class.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::CertNotValidAtGenTime { .. } => "anchor-cert-not-valid-at-gentime",
            Self::ChainConstraintViolation => "anchor-chain-constraint-violation",
            Self::ChainSignatureInvalid => "anchor-chain-signature-invalid",
        }
    }
}

/// One value per distinct code, for the Q52 error-code universe.
///
/// Not wired into [`crate::error_universe::by_enumerator`] here: A38 owns
/// the roster change, exactly as [`super::error::all_code_exemplars`] is not
/// wired yet. Landing it from this lane would flip a test that exists to make
/// the roster change deliberate.
#[must_use]
pub fn all_code_exemplars() -> Vec<ChainFault> {
    vec![
        ChainFault::CertNotValidAtGenTime {
            bound: TemporalBound::Expired,
        },
        ChainFault::ChainConstraintViolation,
        ChainFault::ChainSignatureInvalid,
    ]
}

/// What T3 concluded about one TSA artifact.
///
/// The state is one of exactly four: [`AnchorState::Proven`],
/// [`AnchorState::ValidAtStampingCertSinceExpired`],
/// [`AnchorState::Invalid`], [`AnchorState::InternallyConsistentOnly`].
/// `Attested`, `Pending` and `Absent` belong to other artifact kinds and to
/// A18's stage T0, and none is reachable from here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChainVerdict {
    state: AnchorState,
    fault: Option<ChainFault>,
    suppressed: GradeSet,
    verified_time_unix: Option<u64>,
    anchor_label: Option<&'static str>,
    root_store_version: u32,
}

impl ChainVerdict {
    /// The per-anchor state.
    #[must_use]
    pub const fn state(&self) -> AnchorState {
        self.state
    }

    /// The diagnostic code class, present exactly when the state is
    /// [`AnchorState::Invalid`].
    #[must_use]
    pub const fn fault(&self) -> Option<ChainFault> {
        self.fault
    }

    /// Every refutation some candidate path exhibited that the precedence
    /// rule discarded — **task A39**.
    ///
    /// D53's `C1/C2 → C3` and `C3 → C4 → C5` are both best-evidence-wins, and
    /// both are chosen for a property rather than for taste: the `.sealproof`
    /// bundle is **unsigned** (D8), so any relay can append a certificate, and
    /// under the opposite rule one appended junk certificate would rewrite the
    /// state or the code of an honest anchor. The price D53 §12 records is
    /// that the discarded refutations become invisible in the state — *"a
    /// bundle with one expired path and fifteen forged ones reports the
    /// temporal code … and A39's anomaly list carries the rest"*. This is that
    /// list, at the chain layer.
    ///
    /// Only the three **fault** grades appear. `valid-at-genTime-but-expired`
    /// sitting under a `proven` path is a weaker success, not a refutation,
    /// and putting it here would report an anomaly on a wholly honest
    /// multi-path chain.
    ///
    /// Ordered worst-first (ascending [`Grade`]), so the list is a total
    /// function of the artifact and the store — never of enumeration order,
    /// exactly as the state and the code are.
    #[must_use]
    pub fn suppressed_faults(&self) -> Vec<ChainFault> {
        self.suppressed.iter().filter_map(Grade::fault).collect()
    }

    /// The independently proven stamping time, populated **only** for the two
    /// headline-eligible states.
    ///
    /// Never populated for `Invalid` or `InternallyConsistentOnly`.
    /// `aggregate_anchors` already ignores times on ineligible slots, so this
    /// is defence in depth — and therefore
    /// [`tests::no_ineligible_state_carries_a_verified_time`] is the only
    /// thing that can see the defect.
    #[must_use]
    pub const fn verified_time_unix(&self) -> Option<u64> {
        self.verified_time_unix
    }

    /// The label of the pinned root the chain closed at, when it closed at
    /// one. `None` for `InternallyConsistentOnly` by construction.
    #[must_use]
    pub const fn anchor_label(&self) -> Option<&'static str> {
        self.anchor_label
    }

    /// The version of the root store that produced this verdict (A6/A26
    /// Accept: "verification output carries the store version").
    #[must_use]
    pub const fn root_store_version(&self) -> u32 {
        self.root_store_version
    }

    /// Whether this state may carry the offline headline (MVP-SPEC.md lines
    /// 129–137). Exactly the two `[H]` states.
    #[must_use]
    pub const fn headline_eligible(&self) -> bool {
        matches!(
            self.state,
            AnchorState::Proven | AnchorState::ValidAtStampingCertSinceExpired
        )
    }
}

/// How good a path — or one step of one — is.
///
/// This is the whole of D53's `C1…C6` expressed as a lattice, and the shape
/// is chosen for a property rather than for brevity. Each of D53's guards
/// adds one conjunct to the one below it, so the guards are **nested**:
/// `C1 ⊂ C2 ⊂ C3 ⊂ C4 ⊂ C5`. A path's grade is therefore the **minimum** over
/// its steps, and the artifact's grade is the **maximum** over its paths.
///
/// Writing it this way makes three of D53's requirements structural instead
/// of special-cased:
///
/// - **Least-severe-wins** (`C3 → C4 → C5`) is just `max`. D53 chose it for
///   monotonicity under added certificates: the `.sealproof` bundle is
///   **unsigned** (D8), so any relay can append a certificate, and under
///   most-severe-wins one appended junk certificate would rewrite the
///   reported code of every anchor in the bundle.
/// - **A valid path is never demoted by a failing one** (`C1/C2 → C3`) is the
///   same `max`, one level up.
/// - **Permutation invariance** is automatic: `max` and `min` do not depend on
///   the order the paths are produced in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Grade {
    /// D53 C5 — a link's signature does not verify.
    SignatureInvalid,
    /// D53 C4 — `basicConstraints` / `keyUsage` / `pathLenConstraint`.
    ConstraintViolation,
    /// D53 C3 — outside the validity window at `genTime`.
    NotValidAtGenTime(TemporalBound),
    /// D53 C2 — valid at `genTime`, expired at `verify_at`.
    ValidAtGenTimeButExpired,
    /// D53 C1 — valid at `genTime` and unexpired at `verify_at`.
    Valid,
}

/// How many distinct [`Grade`] values exist. `NotValidAtGenTime` counts twice
/// because [`TemporalBound`] has two arms, and the bound is carried into the
/// diagnostic.
const GRADE_COUNT: u8 = 6;

impl Grade {
    /// Position in the lattice, `0` worst. The inverse of [`Self::from_rank`],
    /// pinned in both directions by
    /// [`tests::grade_ranks_round_trip_and_order_matches_the_lattice`].
    const fn rank(self) -> u8 {
        match self {
            Self::SignatureInvalid => 0,
            Self::ConstraintViolation => 1,
            Self::NotValidAtGenTime(TemporalBound::Expired) => 2,
            Self::NotValidAtGenTime(TemporalBound::NotYetValid) => 3,
            Self::ValidAtGenTimeButExpired => 4,
            Self::Valid => 5,
        }
    }

    const fn from_rank(rank: u8) -> Self {
        match rank {
            0 => Self::SignatureInvalid,
            1 => Self::ConstraintViolation,
            2 => Self::NotValidAtGenTime(TemporalBound::Expired),
            3 => Self::NotValidAtGenTime(TemporalBound::NotYetValid),
            4 => Self::ValidAtGenTimeButExpired,
            _ => Self::Valid,
        }
    }

    /// The refutation this grade names, or `None` for the two grades that
    /// refute nothing.
    const fn fault(self) -> Option<ChainFault> {
        match self {
            Self::SignatureInvalid => Some(ChainFault::ChainSignatureInvalid),
            Self::ConstraintViolation => Some(ChainFault::ChainConstraintViolation),
            Self::NotValidAtGenTime(bound) => Some(ChainFault::CertNotValidAtGenTime { bound }),
            Self::ValidAtGenTimeButExpired | Self::Valid => None,
        }
    }
}

/// The set of grades **some** candidate path achieved.
///
/// A39 needs more than the maximum: best-evidence-wins discards refutations,
/// and the discarded ones must not vanish. The set is at most six values, so
/// it is a bitmask and the DP carries it beside the maximum at no asymptotic
/// cost — the alternative, re-running the search once per grade, would be six
/// path builds over adversary-chosen input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct GradeSet(u8);

impl GradeSet {
    const EMPTY: Self = Self(0);

    fn single(grade: Grade) -> Self {
        Self(1 << grade.rank())
    }

    fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// `{ min(step, g) : g ∈ self }` — extending every completion in `self`
    /// through one more step whose own grade is `step`.
    ///
    /// This is the set-valued form of `step.min(rest)`, and it is what makes
    /// the DP's grade *set* mean the same thing its maximum already did: a
    /// path's grade is the minimum over its steps.
    fn capped_at(self, step: Grade) -> Self {
        let cap = step.rank();
        let mut out = 0_u8;
        let mut rank = 0_u8;
        while rank < GRADE_COUNT {
            if self.0 & (1 << rank) != 0 {
                out |= 1 << if rank < cap { rank } else { cap };
            }
            rank += 1;
        }
        Self(out)
    }

    /// Every grade below `ceiling`, in ascending (worst-first) order.
    fn below(self, ceiling: Grade) -> Self {
        let bound = ceiling.rank();
        let mask = if bound == 0 { 0 } else { (1 << bound) - 1 };
        Self(self.0 & mask)
    }

    fn iter(self) -> impl Iterator<Item = Grade> {
        (0..GRADE_COUNT)
            .filter(move |rank| self.0 & (1 << rank) != 0)
            .map(Grade::from_rank)
    }
}

/// What the search found above one node: the best completion, and the set of
/// grades **any** completion achieved.
///
/// The two are kept together rather than computed twice because they must
/// agree: `best` is exactly the maximum of `grades`, and
/// [`tests::the_best_grade_is_the_maximum_of_the_grade_set`] asserts it over
/// every fixture in this module.
#[derive(Debug, Clone, Copy, Default)]
struct Reach {
    best: Option<(Grade, &'static str)>,
    grades: GradeSet,
}

impl Reach {
    const NONE: Self = Self {
        best: None,
        grades: GradeSet::EMPTY,
    };

    fn union(self, other: Self) -> Self {
        Self {
            best: max_step(self.best, other.best),
            grades: self.grades.union(other.grades),
        }
    }

    /// Extend every completion through one step of grade `step`.
    fn capped_at(self, step: Grade) -> Self {
        Self {
            best: self.best.map(|(grade, label)| (grade.min(step), label)),
            grades: self.grades.capped_at(step),
        }
    }
}

/// Validate a verified token's certificate chain to the pinned root store.
///
/// `bundle_intermediates` are the `.sealproof`'s own `intermediates` field
/// (registry §7.9); the token's embedded certificates are taken from
/// `token`. Both are **untrusted** and both are consumed strictly as
/// intermediates — never as trust anchors, even when a supplied certificate's
/// bytes equal a pinned root's.
///
/// `verify_at_unix` is the caller's verification time. See the module doc:
/// it is one-sided, it is never compared to a system clock, and there is no
/// path from it to [`AnchorState::Invalid`].
#[must_use]
pub fn validate_token_chain(
    token: &VerifiedToken,
    bundle_intermediates: &[Certificate],
    store: &TsaRootStore,
    verify_at_unix: u64,
) -> ChainVerdict {
    let mut supplied: Vec<&Certificate> = Vec::new();
    supplied.extend(token.chain_material());
    supplied.extend(bundle_intermediates);
    validate_chain(
        token.signer(),
        &supplied,
        store,
        token.gen_time_unix(),
        verify_at_unix,
    )
}

/// The path-validation core, over an explicit certificate pool.
///
/// Exposed separately from [`validate_token_chain`] so A24's test CA and
/// A43's real-token fixtures can drive it without constructing a whole
/// `TimeStampResp`, and so the rulings can be tested one at a time.
#[must_use]
pub fn validate_chain(
    signer: &Certificate,
    supplied: &[&Certificate],
    store: &TsaRootStore,
    gen_time_unix: u64,
    verify_at_unix: u64,
) -> ChainVerdict {
    let mut builder = PathBuilder::new(signer, supplied, store, gen_time_unix, verify_at_unix);
    let reach = builder.reach();
    let version = store.version();

    let Some((grade, label)) = reach.best else {
        // D53 C6 — `NAMED` is empty. No pinned root is named by any candidate
        // path, so the artifact asserts nothing this verifier can refute. That
        // includes the case where the chain closes cleanly on a root the
        // bundle itself supplied: MVP-SPEC.md line 109, "bundle-embedded
        // chains supply intermediates only".
        //
        // Nothing is suppressed either: with no path reaching a pinned root
        // there is no refutation to discard (A39).
        return ChainVerdict {
            state: AnchorState::InternallyConsistentOnly,
            fault: None,
            suppressed: GradeSet::EMPTY,
            verified_time_unix: None,
            anchor_label: None,
            root_store_version: version,
        };
    };

    // A39 — every refutation the precedence rule discarded. Strictly below the
    // winner, so a path that *achieved* the reported grade is never reported
    // as an anomaly against itself.
    let suppressed = reach.grades.below(grade);

    match grade {
        Grade::Valid => ChainVerdict {
            state: AnchorState::Proven,
            fault: None,
            suppressed,
            verified_time_unix: Some(gen_time_unix),
            anchor_label: Some(label),
            root_store_version: version,
        },
        Grade::ValidAtGenTimeButExpired => ChainVerdict {
            state: AnchorState::ValidAtStampingCertSinceExpired,
            fault: None,
            suppressed,
            // The whole point of this state (MVP-SPEC.md line 130): it "still
            // carries its independently-proven stamping time". Aging bundles
            // must not silently rot.
            verified_time_unix: Some(gen_time_unix),
            anchor_label: Some(label),
            root_store_version: version,
        },
        Grade::NotValidAtGenTime(bound) => invalid(
            ChainFault::CertNotValidAtGenTime { bound },
            suppressed,
            label,
            version,
        ),
        Grade::ConstraintViolation => invalid(
            ChainFault::ChainConstraintViolation,
            suppressed,
            label,
            version,
        ),
        Grade::SignatureInvalid => invalid(
            ChainFault::ChainSignatureInvalid,
            suppressed,
            label,
            version,
        ),
    }
}

fn invalid(
    fault: ChainFault,
    suppressed: GradeSet,
    label: &'static str,
    version: u32,
) -> ChainVerdict {
    ChainVerdict {
        state: AnchorState::Invalid,
        fault: Some(fault),
        suppressed,
        // Never populated for an ineligible state (D53 §4).
        verified_time_unix: None,
        anchor_label: Some(label),
        root_store_version: version,
    }
}

/// A node in the search: the signer, or one supplied certificate.
///
/// `pub(super)` for its **size** and nothing else: [`super::caps`] derives the
/// DER path's structural allocation cost from `size_of::<Node>()` under D58
/// §10.3 rule 6, whose clause (a) requires the derivation to come from
/// `size_of` rather than from a transcribed number (D102 §6). Every field
/// stays private and nothing outside this module constructs one.
pub(super) struct Node<'a> {
    cert: &'a Certificate,
    /// DER of the certificate's `subject`, cached — this is compared once per
    /// candidate link and re-encoding it each time dominated the profile.
    subject_der: Vec<u8>,
    /// DER of the certificate's `issuer`, cached.
    issuer_der: Vec<u8>,
    /// The `authorityKeyIdentifier.keyIdentifier`, when present.
    aki: Option<Vec<u8>>,
    /// The `subjectKeyIdentifier`, when present.
    ski: Option<Vec<u8>>,
    /// Whether this certificate's own DER re-encodes; a node that does not is
    /// unusable and is simply never linked.
    der: Vec<u8>,
}

/// The bounded path search.
///
/// # Why this is a memoised DP and not a permutation generator
///
/// The bundle admits 16 intermediates and a token may contribute
/// [`MAX_CHAIN_CERTS`] more; **a hostile sealer can make them all mutually
/// name-chaining**, which is cheap to build. Enumerating simple paths over
/// that graph is factorial and would hang the verifier — D53 §3 names the
/// hazard and forbids a permutation generator.
///
/// The escape is a fact about the predicates: every conjunct in D53 §3 is a
/// property of a **single link or a single certificate at a known depth**, so
/// a path's grade is the minimum over its steps. That makes the search a DP
/// over `(node, depth)` with `O(V² · D)` link evaluations — at most a few
/// hundred here — instead of `O(V!)`.
///
/// **Dropping the "without repetition" rule is safe, and that is what makes
/// the DP legal.** D53 §3 draws intermediates without repetition. Under a
/// depth bound, allowing repetition changes no answer: any repeating path can
/// have its loop cut, and the result is a *shorter* path whose links are a
/// subset of the original's — so every conjunct that held still holds, and
/// `pathLenConstraint` is only relaxed by having fewer certificates below.
/// Every satisfying loopy path therefore has a satisfying simple sub-path, and
/// every simple path is trivially loopy-admissible, so the two search spaces
/// give the identical six-way classification.
struct PathBuilder<'a> {
    nodes: Vec<Node<'a>>,
    roots: Vec<Anchor<'a>>,
    gen_time_unix: u64,
    verify_at_unix: u64,
    /// `(node, depth) -> what any completion above it reaches`.
    memo: BTreeMap<(usize, usize), Reach>,
    /// `(child node, parent id) -> does the link signature verify?`
    ///
    /// Parent ids above [`usize::MAX`] / 2 are pinned roots. Memoised because
    /// the same link is reachable at several depths and each evaluation is an
    /// RSA-4096 verification.
    sig_memo: BTreeMap<(usize, ParentId), bool>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum ParentId {
    Supplied(usize),
    Root(usize),
}

/// One pinned root, parsed once per verification.
///
/// The store carries bytes plus fingerprints and nothing derivable (D57 §7),
/// so subject DN and `subjectKeyIdentifier` are read here rather than
/// duplicated into the const table where they could drift from the bytes.
struct Anchor<'a> {
    pinned: &'a PinnedRoot,
    cert: Certificate,
    subject_der: Vec<u8>,
    ski: Option<Vec<u8>>,
}

impl<'a> PathBuilder<'a> {
    fn new(
        signer: &'a Certificate,
        supplied: &[&'a Certificate],
        store: &'a TsaRootStore,
        gen_time_unix: u64,
        verify_at_unix: u64,
    ) -> Self {
        let mut nodes = Vec::with_capacity(supplied.len() + 1);
        nodes.push(Node::new(signer));
        for cert in supplied {
            let node = Node::new(cert);
            // The token's bag and the bundle's `intermediates` field routinely
            // carry the same certificate, and a duplicated node is duplicated
            // work in a search an adversary chooses the input to. Dropping the
            // duplicate cannot change a verdict: the two nodes are byte-equal,
            // so every predicate over them agrees.
            if nodes.iter().any(|n: &Node<'_>| n.der == node.der) {
                continue;
            }
            nodes.push(node);
        }
        // A pinned root that does not parse cannot anchor anything, and it
        // takes nothing else down with it (F2). `every_pinned_root_parses…`
        // makes that a build-time impossibility rather than a live risk.
        let roots = store
            .roots()
            .iter()
            .filter_map(|pinned| {
                let cert = pinned.parse().ok()?;
                let subject_der = cert.tbs_certificate().subject().to_der().ok()?;
                let ski =
                    extension::<SubjectKeyIdentifier>(&cert).map(|ski| ski.0.as_bytes().to_vec());
                Some(Anchor {
                    pinned,
                    cert,
                    subject_der,
                    ski,
                })
            })
            .collect();
        Self {
            nodes,
            roots,
            gen_time_unix,
            verify_at_unix,
            memo: BTreeMap::new(),
            sig_memo: BTreeMap::new(),
        }
    }

    /// What the artifact reaches: the maximum over every candidate path
    /// together with the label of the root that path closed at, **and** the
    /// set of grades any candidate path achieved (A39). Empty when no path
    /// reaches any pinned root (D53 C6).
    fn reach(&mut self) -> Reach {
        // The signer contributes only its own temporal checks: `constraints_ok`
        // covers issuer elements, and D60 measured why that matters —
        // **SwissSign's leaf carries no `basicConstraints` at all**, so
        // requiring it on the signer rejects a documented alternate.
        let signer_grade = self.temporal_grade(0);
        self.suffix(0, 0).capped_at(signer_grade)
    }

    /// What any completion strictly above `node` reaches, `node` sitting at
    /// `depth` (0 for the signer).
    fn suffix(&mut self, node: usize, depth: usize) -> Reach {
        if let Some(hit) = self.memo.get(&(node, depth)) {
            return *hit;
        }
        // Guard against a cycle in the memo table while it is being filled.
        // A repeated node at the same depth is impossible (depth strictly
        // increases), so this is belt-and-braces rather than load-bearing.
        self.memo.insert((node, depth), Reach::NONE);

        let mut best = Reach::NONE;

        // (a) Close on a pinned root. This is ruling P1: the moment a
        // certificate's issuer names a pinned root, the path may terminate
        // there. Nothing requires the supplied chain to be consumed, and a
        // trailing cross-certificate is simply never visited.
        let root_depth = depth + 1;
        if root_depth < MAX_CHAIN_CERTS {
            for idx in 0..self.roots.len() {
                if !self.chains_to_root(node, idx) {
                    continue;
                }
                let grade = self.root_step_grade(node, idx, root_depth);
                let label = self.roots[idx].pinned.label;
                best = best.union(Reach {
                    best: Some((grade, label)),
                    grades: GradeSet::single(grade),
                });
            }
        }

        // (b) Extend through a supplied certificate, which needs room for a
        // root above it as well.
        let next_depth = depth + 1;
        if next_depth <= MAX_CHAIN_CERTS - 2 {
            for parent in 1..self.nodes.len() {
                if self.nodes[parent].der == self.nodes[node].der {
                    continue;
                }
                if !self.name_chains(node, parent) {
                    continue;
                }
                let step = self.intermediate_step_grade(node, parent, next_depth);
                let rest = self.suffix(parent, next_depth);
                if !rest.grades.is_empty() {
                    best = best.union(rest.capped_at(step));
                }
            }
        }

        self.memo.insert((node, depth), best);
        best
    }

    /// Name chaining between two supplied certificates: issuer DN equals
    /// subject DN byte-exactly, and where **both** are present the child's
    /// `authorityKeyIdentifier.keyIdentifier` equals the parent's
    /// `subjectKeyIdentifier`.
    ///
    /// Byte-exact DN comparison is stricter than RFC 5280's name-matching
    /// rules, and the strictness is safe in exactly one direction: a stricter
    /// matcher can only *fail* to build a path, never build a wrong one, and
    /// failing to build renders `internally-consistent-only` rather than a
    /// false `proven`. All five real production chains close under it
    /// (verified in [`tests`]).
    fn name_chains(&self, child: usize, parent: usize) -> bool {
        if self.nodes[child].issuer_der != self.nodes[parent].subject_der {
            return false;
        }
        match (&self.nodes[child].aki, &self.nodes[parent].ski) {
            (Some(aki), Some(ski)) => aki == ski,
            _ => true,
        }
    }

    fn chains_to_root(&self, child: usize, root: usize) -> bool {
        if self.nodes[child].issuer_der != self.roots[root].subject_der {
            return false;
        }
        match (&self.nodes[child].aki, &self.roots[root].ski) {
            (Some(aki), Some(ski)) => aki == ski,
            _ => true,
        }
    }

    /// Grade of the step that introduces the pinned root at `depth`.
    ///
    /// No temporal check: D53 §5(a) excludes the trust anchor from
    /// `time_ok_at`. RFC 5280 §6.1 treats an anchor as an *input* to path
    /// validation rather than a certificate to be validated, and the
    /// project-specific reason is stronger — pinned roots are long-lived and
    /// will expire while sealed bundles are still being verified, so checking
    /// `R.notAfter` would flip every bundle anchored under a root to `Invalid`
    /// on that root's expiry date. That is precisely the silent rot
    /// MVP-SPEC.md lines 109 and 130 forbid. Root expiry is handled by A26
    /// **adding** roots, never by failing old evidence.
    fn root_step_grade(&mut self, child: usize, root: usize, depth: usize) -> Grade {
        if !self.link_signature_ok(child, ParentId::Root(root)) {
            return Grade::SignatureInvalid;
        }
        if !constraints_ok(&self.roots[root].cert, depth) {
            return Grade::ConstraintViolation;
        }
        Grade::Valid
    }

    /// Grade of the step that introduces a supplied intermediate at `depth`.
    fn intermediate_step_grade(&mut self, child: usize, parent: usize, depth: usize) -> Grade {
        if !self.link_signature_ok(child, ParentId::Supplied(parent)) {
            return Grade::SignatureInvalid;
        }
        if !constraints_ok(self.nodes[parent].cert, depth) {
            return Grade::ConstraintViolation;
        }
        self.temporal_grade(parent)
    }

    /// The temporal half of a certificate's grade: valid at `genTime`, and
    /// unexpired at `verify_at`.
    fn temporal_grade(&self, node: usize) -> Grade {
        let validity = self.nodes[node].cert.tbs_certificate().validity();
        let not_before = validity.not_before.to_unix_duration().as_secs();
        let not_after = validity.not_after.to_unix_duration().as_secs();
        if self.gen_time_unix < not_before {
            // Back-dating: the token claims a time before this certificate
            // existed. Nothing in MVP-SPEC.md, `tasks/A.md` or
            // `MATRIX.json` covers this direction; D53 rules it, and
            // `a_certificate_not_yet_valid_at_gentime_is_the_same_code` is the
            // only guard on it in the whole tree.
            return Grade::NotValidAtGenTime(TemporalBound::NotYetValid);
        }
        if self.gen_time_unix > not_after {
            return Grade::NotValidAtGenTime(TemporalBound::Expired);
        }
        // One-sided, deliberately: `notAfter < verify_at` and nothing else.
        // A `verify_at` earlier than `notBefore` — a caller with a wrong clock
        // — yields `Valid`, never a failure. The state name forces it:
        // "cert *since expired*" would be a lie for "not yet valid at your
        // clock".
        if not_after < self.verify_at_unix {
            return Grade::ValidAtGenTimeButExpired;
        }
        Grade::Valid
    }

    /// Does `child`'s signature verify under `parent`'s public key?
    fn link_signature_ok(&mut self, child: usize, parent: ParentId) -> bool {
        if let Some(hit) = self.sig_memo.get(&(child, parent)) {
            return *hit;
        }
        let ok = self.compute_link_signature(child, parent);
        self.sig_memo.insert((child, parent), ok);
        ok
    }

    fn compute_link_signature(&self, child: usize, parent: ParentId) -> bool {
        let child_cert = self.nodes[child].cert;
        let parent_cert = match parent {
            ParentId::Supplied(i) => self.nodes[i].cert,
            ParentId::Root(i) => &self.roots[i].cert,
        };

        // The outer `signatureAlgorithm` must equal the inner
        // `tbsCertificate.signature` (RFC 5280 §4.1.1.2). They are two
        // statements of the same fact and only the inner one is signed, so a
        // disagreement is an unsigned claim about which algorithm was used.
        let outer = child_cert.signature_algorithm();
        let inner = child_cert.tbs_certificate().signature();
        let (Ok(outer_der), Ok(inner_der)) = (outer.to_der(), inner.to_der()) else {
            return false;
        };
        if outer_der != inner_der {
            return false;
        }

        // `in_certificate = true` refuses bare `rsaEncryption`, which would
        // leave the digest unbound. Five of nine live TSAs emit it in
        // `SignerInfo.signatureAlgorithm`, and **none** of the 27 real
        // certificates emits it here, so the restriction costs no real TSA
        // anything (D60 §3.3).
        //
        // An algorithm outside the registry lands on `SignatureInvalid` and
        // therefore on D53's C5. That is a judgement inside D53's frame rather
        // than a claim of refutation: `NAMED` is defined by name chaining
        // alone, `sig_ok` is a predicate over it, and an algorithm we cannot
        // evaluate cannot make `sig_ok` true. Both candidate states are
        // non-headline, so nothing about the evidence turns on it, and the
        // code makes the reason visible.
        let Ok(sig_alg) = alg::signature(outer, AlgPosition::SignerSignature, true) else {
            return false;
        };
        let Some(digest) = sig_alg.digest else {
            return false;
        };
        let spki = parent_cert.tbs_certificate().subject_public_key_info();
        if alg::public_key_family(&spki.algorithm) != Ok(sig_alg.family) {
            return false;
        }
        let Some(key_bytes) = spki.subject_public_key.as_bytes() else {
            return false;
        };
        let Ok(tbs) = child_cert.tbs_certificate().to_der() else {
            return false;
        };
        let Some(sig) = child_cert.signature().as_bytes() else {
            return false;
        };
        match sig_alg.family {
            SigFamily::RsaPkcs1v15 => verify_rsa(digest, key_bytes, &tbs, sig),
            SigFamily::EcdsaP384 => verify_ecdsa_p384(digest, key_bytes, &tbs, sig),
        }
    }
}

impl<'a> Node<'a> {
    fn new(cert: &'a Certificate) -> Self {
        let tbs = cert.tbs_certificate();
        Self {
            subject_der: tbs.subject().to_der().unwrap_or_default(),
            issuer_der: tbs.issuer().to_der().unwrap_or_default(),
            aki: extension::<AuthorityKeyIdentifier>(cert)
                .and_then(|aki| aki.key_identifier)
                .map(|ki| ki.as_bytes().to_vec()),
            ski: extension::<SubjectKeyIdentifier>(cert).map(|ski| ski.0.as_bytes().to_vec()),
            der: cert.to_der().unwrap_or_default(),
            cert,
        }
    }
}

/// `max` over `Option<(Grade, label)>`, comparing on the grade only.
///
/// A tie keeps the incumbent, so the label reported for two equally graded
/// paths is the first the store declares — deterministic, and irrelevant to
/// the state and code.
fn max_step(
    a: Option<(Grade, &'static str)>,
    b: Option<(Grade, &'static str)>,
) -> Option<(Grade, &'static str)> {
    match (a, b) {
        (Some(x), Some(y)) => Some(if y.0 > x.0 { y } else { x }),
        (some, None) | (None, some) => some,
    }
}

/// Read one extension, treating a malformed one as absent.
///
/// A certificate whose `authorityKeyIdentifier` does not parse loses the
/// AKI/SKI half of name chaining and keeps the DN half — it does not take the
/// verification down. Adversarial input returns a verdict, never a panic.
fn extension<T>(cert: &Certificate) -> Option<T>
where
    T: for<'a> der::Decode<'a> + const_oid::AssociatedOid,
{
    cert.tbs_certificate()
        .get_extension::<T>()
        .ok()
        .flatten()
        .map(|(_critical, ext)| ext)
}

/// `constraints_ok` for one issuer element of a path, at `depth`.
///
/// Applied to **every element except the signer, including the pinned root**
/// (D53 §3). The signer's exclusion is not tidiness: **SwissSign's real leaf
/// carries no `basicConstraints` extension at all**, so requiring it on the
/// signer rejects a documented alternate (D60).
///
/// `pathLenConstraint` is read as RFC 5280 §4.2.1.9 states it — the maximum
/// number of intermediate certificates that may follow this one before the
/// leaf, which at `depth` is `depth - 1`. antseal counts **all** such
/// intermediates rather than only the non-self-issued ones, which is stricter
/// than RFC 5280 and matches D53 §3's wording. Strictness here can only
/// prevent a path from being built, never build a wrong one, and no real chain
/// is affected: the deepest real path is three certificates and every real
/// `pathLenConstraint` observed is satisfied with margin.
fn constraints_ok(cert: &Certificate, depth: usize) -> bool {
    let Some(bc) = extension::<BasicConstraints>(cert) else {
        return false;
    };
    if !bc.ca {
        return false;
    }
    if let Some(path_len) = bc.path_len_constraint {
        let below = depth.saturating_sub(1);
        if usize::from(path_len) < below {
            return false;
        }
    }
    // RFC 5280 §4.2.1.3: `keyUsage` is optional; when present it must permit
    // `keyCertSign`. "No keyUsage" is not a defect — it is the absence of a
    // restriction.
    match extension::<KeyUsage>(cert) {
        Some(ku) => ku.0.contains(KeyUsages::KeyCertSign),
        None => true,
    }
}

fn verify_rsa(digest: Digest, key: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    use rsa::pkcs1::DecodeRsaPublicKey as _;
    use rsa::signature::Verifier as _;
    use sha2::{Sha256, Sha384, Sha512};

    let Ok(key) = rsa::RsaPublicKey::from_pkcs1_der(key) else {
        return false;
    };
    let Ok(signature) = rsa::pkcs1v15::Signature::try_from(sig) else {
        return false;
    };
    match digest {
        Digest::Sha256 => rsa::pkcs1v15::VerifyingKey::<Sha256>::new(key)
            .verify(msg, &signature)
            .is_ok(),
        Digest::Sha384 => rsa::pkcs1v15::VerifyingKey::<Sha384>::new(key)
            .verify(msg, &signature)
            .is_ok(),
        Digest::Sha512 => rsa::pkcs1v15::VerifyingKey::<Sha512>::new(key)
            .verify(msg, &signature)
            .is_ok(),
    }
}

fn verify_ecdsa_p384(digest: Digest, key: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    use p384::ecdsa::signature::hazmat::PrehashVerifier as _;
    use sha2::{Digest as _, Sha256, Sha384, Sha512};

    let Ok(verifying_key) = p384::ecdsa::VerifyingKey::from_sec1_bytes(key) else {
        return false;
    };
    let Ok(signature) = p384::ecdsa::Signature::from_der(sig) else {
        return false;
    };
    // `verify_prehash` takes the full digest and applies FIPS 186-5 §6.4
    // leftmost-bits truncation itself, which is what makes SHA-512 on a P-384
    // key — FreeTSA's real pairing — work without truncating anything by hand.
    let prehash = match digest {
        Digest::Sha256 => Sha256::digest(msg).to_vec(),
        Digest::Sha384 => Sha384::digest(msg).to_vec(),
        Digest::Sha512 => Sha512::digest(msg).to_vec(),
    };
    verifying_key.verify_prehash(&prehash, &signature).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::anchor::tsa::verify_token;
    use der::Decode as _;
    use std::collections::BTreeSet;

    // ── The real material ───────────────────────────────────────────────
    //
    // `include_bytes!` rather than `fs::read`: the `wasm32-core-tests` lane
    // runs this crate's `--lib` tests on `wasm32-unknown-unknown`, which has
    // no filesystem. A43's Accept requires these rows in **both** suites, and
    // that is the only way to get them there — an integration test under
    // `tests/` is native-only.

    const FREETSA: &[u8] =
        include_bytes!("../../../../testdata/anchors/A25-bootstrap/roots-freetsa-token.tsr");
    const DIGICERT: &[u8] =
        include_bytes!("../../../../testdata/anchors/A25-bootstrap/roots-digicert-token.tsr");
    const DFN: &[u8] =
        include_bytes!("../../../../testdata/anchors/A25-bootstrap/roots-dfn-token.tsr");
    const SECTIGO: &[u8] =
        include_bytes!("../../../../testdata/anchors/A25-bootstrap/roots-sectigo-token.tsr");
    const SWISSSIGN: &[u8] =
        include_bytes!("../../../../testdata/anchors/A25-bootstrap/roots-swisssign-token.tsr");
    /// A TSA whose root is deliberately outside store v1 — the closure rule
    /// names no antseal endpoint that chains to GlobalSign.
    const GLOBALSIGN: &[u8] =
        include_bytes!("../../../../testdata/anchors/A25-bootstrap/D60-tsa-globalsign-resp.tsr");

    const SWISSSIGN_ROOT_DER: &[u8] = include_bytes!(
        "../../../../testdata/anchors/A25-bootstrap/roots-swisssign-signature-services-root-2020-2.der"
    );

    /// The digest every `roots-*-token.tsr` was stamped over: the D57 probe,
    /// `SHA-256("antseal/D57 roots-probe digest" ‖ W)` from the documented
    /// fixed test seed. Non-secret by construction.
    const PROBE: [u8; 32] = [
        0xc7, 0x6d, 0xb1, 0x1e, 0x7d, 0x95, 0xfb, 0x40, 0xc1, 0xec, 0xfe, 0x98, 0xb7, 0x4e, 0x4a,
        0x3a, 0x59, 0x90, 0x7d, 0x1f, 0x8d, 0xa6, 0xa2, 0xef, 0x10, 0xd3, 0x99, 0xf5, 0x01, 0x3b,
        0x69, 0x99,
    ];

    /// The digest the nine `D60-*` captures were stamped over.
    const D60_STAMPED: [u8; 32] = [
        0x08, 0x3f, 0x87, 0xdf, 0x00, 0xfd, 0x5c, 0x70, 0x3d, 0x35, 0xb8, 0x83, 0xd8, 0x35, 0x35,
        0x64, 0x4c, 0x68, 0x6f, 0x9e, 0x53, 0xf1, 0x58, 0x4d, 0x7d, 0xf1, 0x26, 0xab, 0xda, 0xbd,
        0x69, 0xdf,
    ];

    /// A verification time inside every real certificate's window: the day
    /// after the captures. **Never a clock** — a literal, so the suite is the
    /// same on every host and on wasm32.
    const AFTER_CAPTURE: u64 = 1_785_000_000; // 2026-08-03T…Z

    fn token(bytes: &[u8], digest: &[u8; 32]) -> VerifiedToken {
        verify_token(bytes, digest, None).expect("a real token passes T2")
    }

    fn certs(t: &VerifiedToken) -> Vec<&Certificate> {
        t.chain_material().iter().collect()
    }

    /// Build an injected store from owned DER. `Box::leak` is how a test
    /// obtains the `'static` the const-table API requires; it leaks a few
    /// kilobytes per test, which is the right trade for keeping the
    /// production type free of lifetimes.
    fn store_of(ders: Vec<(Vec<u8>, &'static str)>) -> TsaRootStore {
        use sha2::{Digest as _, Sha256};
        let roots: Vec<PinnedRoot> = ders
            .into_iter()
            .map(|(der, label)| {
                let cert = Certificate::from_der(&der).expect("test root parses");
                let spki = cert
                    .tbs_certificate()
                    .subject_public_key_info()
                    .to_der()
                    .expect("SPKI encodes");
                let cert_sha256: [u8; 32] = Sha256::digest(&der).into();
                let spki_sha256: [u8; 32] = Sha256::digest(&spki).into();
                PinnedRoot {
                    der: Box::leak(der.into_boxed_slice()),
                    cert_sha256,
                    spki_sha256,
                    label,
                }
            })
            .collect();
        TsaRootStore::from_static(Box::leak(roots.into_boxed_slice()))
    }

    fn empty_store() -> TsaRootStore {
        store_of(Vec::new())
    }

    fn der_of(cert: &Certificate) -> Vec<u8> {
        cert.to_der().expect("a parsed certificate re-encodes")
    }

    /// Flip the last byte of a certificate's DER.
    ///
    /// A certificate ends with its `signature` BIT STRING, so this breaks the
    /// signature and touches nothing else: subject, issuer, SKI, AKI,
    /// validity and extensions are all bit-identical, so name chaining still
    /// holds and the path is still *built*. That is what makes it a test of
    /// D53's C5 rather than of the parser.
    fn with_broken_signature(cert: &Certificate) -> Certificate {
        let mut der = der_of(cert);
        *der.last_mut().expect("non-empty DER") ^= 0x01;
        Certificate::from_der(&der).expect("only the signature changed")
    }

    /// Turn a certificate's `basicConstraints` `cA` flag off, in place, by
    /// flipping the one `0xFF` byte to `0x00`.
    ///
    /// Byte surgery rather than decode-modify-re-encode because
    /// `x509-cert 0.3` keeps `CertificateInner`'s fields private, and because
    /// this way the mutation is provably **one byte**: the length octets are
    /// untouched, so nothing but the flag under test can have changed.
    ///
    /// Legitimate as a **root** fixture and only as one. D53 §5(a) excludes
    /// the trust anchor from `time_ok_at` and nothing ever verifies an
    /// anchor's self-signature, so a root whose bytes no longer match its own
    /// signature behaves exactly like a real one everywhere except in the
    /// extension under test. The *child's* signature still verifies, because
    /// the root's SPKI is untouched — which is what makes this a test of C4
    /// rather than of C5.
    fn with_ca_false(cert: &Certificate) -> Vec<u8> {
        // OID 2.5.29.19 (`id-ce-basicConstraints`), then the extnValue's
        // `SEQUENCE { BOOLEAN TRUE }`.
        const OID: [u8; 5] = [0x06, 0x03, 0x55, 0x1D, 0x13];
        const CA_TRUE: [u8; 5] = [0x30, 0x03, 0x01, 0x01, 0xFF];
        let mut der = der_of(cert);
        let at = der
            .windows(OID.len())
            .position(|w| w == OID)
            .expect("every pinned root carries basicConstraints");
        let rel = der[at..]
            .windows(CA_TRUE.len())
            .position(|w| w == CA_TRUE)
            .expect("encoded as CA:TRUE");
        let flag = at + rel + 4;
        assert_eq!(der[flag], 0xFF);
        der[flag] = 0x00;
        der
    }

    // ── A43 / D57 §9 — the rulings only a real chain can reach ──────────

    /// **P1.** DigiCert's real chain terminates at a cross-certificate
    /// (`DigiCert Trusted Root G4` issued by `DigiCert Assured ID Root CA`).
    /// An implementation that walks the supplied chain to its end anchors on
    /// that unpinned certificate and returns `internally-consistent-only`
    /// here — for the **production default TSA**.
    #[test]
    fn real_digicert_token_reaches_proven_with_the_cross_cert_present() {
        let t = token(DIGICERT, &PROBE);
        assert_eq!(t.chain_material().len(), 3, "leaf + CA + cross-certificate");
        let v = validate_token_chain(&t, &[], TsaRootStore::pinned(), AFTER_CAPTURE);
        assert_eq!(v.state(), AnchorState::Proven, "fault: {:?}", v.fault());
        assert_eq!(v.anchor_label(), Some("digicert-trusted-root-g4"));
        assert_eq!(v.verified_time_unix(), Some(t.gen_time_unix()));
    }

    /// **P1's other side.** The same chain with the cross-certificate removed
    /// must also reach `proven`, which proves the trailing certificate is
    /// optional rather than load-bearing. An implementation that passes the
    /// test above by *requiring* the cross-certificate fails here.
    #[test]
    fn real_digicert_token_reaches_proven_with_the_cross_cert_removed() {
        let t = token(DIGICERT, &PROBE);
        let pinned_subject = {
            let root = TsaRootStore::pinned().roots()[1];
            Certificate::from_der(root.der)
                .expect("parses")
                .tbs_certificate()
                .subject()
                .to_der()
                .expect("encodes")
        };
        // Drop every supplied certificate whose SUBJECT is the pinned root's
        // — that is exactly the cross-certificate, located by what it is
        // rather than by its position in the bag (P3).
        let trimmed: Vec<&Certificate> = t
            .chain_material()
            .iter()
            .filter(|c| c.tbs_certificate().subject().to_der().expect("encodes") != pinned_subject)
            .collect();
        assert_eq!(trimmed.len(), 2, "the cross-certificate was located");
        let v = validate_chain(
            t.signer(),
            &trimmed,
            TsaRootStore::pinned(),
            t.gen_time_unix(),
            AFTER_CAPTURE,
        );
        assert_eq!(v.state(), AnchorState::Proven, "fault: {:?}", v.fault());
    }

    /// **P1, second hierarchy.** Sectigo's chain terminates at a
    /// USERTrust-issued cross-certificate. One TSA passing could be luck.
    #[test]
    fn real_sectigo_token_reaches_proven_with_the_cross_cert_present() {
        let t = token(SECTIGO, &PROBE);
        let v = validate_token_chain(&t, &[], TsaRootStore::pinned(), AFTER_CAPTURE);
        assert_eq!(v.state(), AnchorState::Proven, "fault: {:?}", v.fault());
        assert_eq!(
            v.anchor_label(),
            Some("sectigo-public-time-stamping-root-r46")
        );
    }

    /// **P2's positive twin.** FreeTSA and DFN ship their own self-signed
    /// root inside every token. An implementation that *rejects* a supplied
    /// self-signed certificate — rather than merely refusing to anchor on it
    /// — fails both of the spec's own TSAs.
    #[test]
    fn token_carrying_its_own_self_signed_root_still_reaches_proven() {
        for (name, bytes, label) in [
            ("freetsa", FREETSA, "freetsa-root-ca"),
            ("dfn", DFN, "dfn-verein-community-root-ca-2022"),
        ] {
            let t = token(bytes, &PROBE);
            // The token really does carry a self-signed certificate.
            assert!(
                t.chain_material().iter().any(|c| {
                    let tbs = c.tbs_certificate();
                    tbs.issuer().to_der().ok() == tbs.subject().to_der().ok()
                }),
                "{name}: fixture no longer carries its own root — the test would pass vacuously"
            );
            let v = validate_token_chain(&t, &[], TsaRootStore::pinned(), AFTER_CAPTURE);
            assert_eq!(v.state(), AnchorState::Proven, "{name}: {:?}", v.fault());
            assert_eq!(v.anchor_label(), Some(label), "{name}");
        }
    }

    /// **P2's negative, on real material.** The same FreeTSA token whose root
    /// travels *inside* it renders `internally-consistent-only` when that root
    /// is withheld from the store — and `proven` when it is injected. Neither
    /// direction can pass vacuously, because the two calls differ only in the
    /// store.
    #[test]
    fn self_signed_root_in_the_token_is_not_a_trust_anchor() {
        let t = token(FREETSA, &PROBE);
        let supplied = certs(&t);

        let withheld = validate_chain(
            t.signer(),
            &supplied,
            &empty_store(),
            t.gen_time_unix(),
            AFTER_CAPTURE,
        );
        assert_eq!(
            withheld.state(),
            AnchorState::InternallyConsistentOnly,
            "a self-signed certificate the sealer supplied is not a trust anchor"
        );
        assert_eq!(withheld.verified_time_unix(), None);
        assert_eq!(withheld.anchor_label(), None);

        let root_der = TsaRootStore::pinned().roots()[0].der.to_vec();
        let injected = store_of(vec![(root_der, "injected-freetsa")]);
        let admitted = validate_chain(
            t.signer(),
            &supplied,
            &injected,
            t.gen_time_unix(),
            AFTER_CAPTURE,
        );
        assert_eq!(
            admitted.state(),
            AnchorState::Proven,
            "the same fixture must pass once its root is pinned, or the negative is vacuous"
        );
        assert_eq!(admitted.anchor_label(), Some("injected-freetsa"));
    }

    /// A bundle-supplied **byte-identical copy of a pinned root** is consumed
    /// as an intermediate and never as an anchor.
    ///
    /// This catches the implementation that matches trust anchors by subject
    /// DN, or by membership in a merged certificate pool, rather than by store
    /// membership: under it a forged root with a copied DN would validate.
    #[test]
    fn a_bundle_copy_of_a_pinned_root_is_ignored_not_trusted() {
        let t = token(FREETSA, &PROBE);
        let pinned_der = TsaRootStore::pinned().roots()[0].der.to_vec();
        let copy = Certificate::from_der(&pinned_der).expect("parses");
        let mut supplied = certs(&t);
        supplied.push(&copy);
        let v = validate_chain(
            t.signer(),
            &supplied,
            &empty_store(),
            t.gen_time_unix(),
            AFTER_CAPTURE,
        );
        assert_eq!(v.state(), AnchorState::InternallyConsistentOnly);
    }

    /// **P3.** `certificates` is an ASN.1 SET; five real tokens showed three
    /// distinct orders. Every permutation of every real bag must yield the
    /// identical verdict — state, fault, time and anchor label.
    ///
    /// A naive depth-first "first path wins" implementation passes every
    /// fixture above and fails only here.
    #[test]
    fn certificate_order_in_the_set_does_not_affect_the_verdict() {
        for (name, bytes, digest) in [
            ("freetsa", FREETSA, &PROBE),
            ("digicert", DIGICERT, &PROBE),
            ("dfn", DFN, &PROBE),
            ("sectigo", SECTIGO, &PROBE),
            ("swisssign", SWISSSIGN, &PROBE),
            ("globalsign", GLOBALSIGN, &D60_STAMPED),
        ] {
            let t = token(bytes, digest);
            let pool = certs(&t);
            let expected = validate_chain(
                t.signer(),
                &pool,
                TsaRootStore::pinned(),
                t.gen_time_unix(),
                AFTER_CAPTURE,
            );
            let mut seen = 0usize;
            for order in permutations(pool.len()) {
                let permuted: Vec<&Certificate> = order.iter().map(|&i| pool[i]).collect();
                let got = validate_chain(
                    t.signer(),
                    &permuted,
                    TsaRootStore::pinned(),
                    t.gen_time_unix(),
                    AFTER_CAPTURE,
                );
                assert_eq!(got, expected, "{name}: verdict changed under {order:?}");
                seen += 1;
            }
            assert!(seen > 1, "{name}: fewer than two orders were tried");
        }
    }

    /// Every permutation of `0..n`, for the small `n` a real certificate bag
    /// has (2–4). Written out rather than pulled in so the suite stays
    /// dependency-free on wasm32.
    fn permutations(n: usize) -> Vec<Vec<usize>> {
        if n == 0 {
            return vec![Vec::new()];
        }
        let mut out = Vec::new();
        for i in 0..n {
            for mut rest in permutations(n - 1) {
                for x in &mut rest {
                    if *x >= i {
                        *x += 1;
                    }
                }
                let mut p = vec![i];
                p.extend(rest);
                out.push(p);
            }
        }
        out
    }

    /// FreeTSA's leaf is **EC P-384** and its chain link to the root is
    /// **RSA-4096 with SHA-512** — `sha512WithRSAEncryption`, not the SHA-384
    /// the P-384 pairing suggests. Both are needed to verify one FreeTSA
    /// token, so "supports ECDSA P-384" is not sufficient on its own.
    #[test]
    fn freetsa_p384_leaf_chains_under_an_rsa_sha512_link() {
        let t = token(FREETSA, &PROBE);
        assert_eq!(
            t.signer()
                .tbs_certificate()
                .subject_public_key_info()
                .algorithm
                .oid
                .to_string(),
            "1.2.840.10045.2.1",
            "FreeTSA's leaf is an EC key"
        );
        assert_eq!(
            t.signer().signature_algorithm().oid.to_string(),
            "1.2.840.113549.1.1.13",
            "and the ROOT signed that leaf with sha512WithRSAEncryption"
        );
        let v = validate_token_chain(&t, &[], TsaRootStore::pinned(), AFTER_CAPTURE);
        assert_eq!(v.state(), AnchorState::Proven, "fault: {:?}", v.fault());
    }

    /// SwissSign's leaf is **RSA-3072** and carries **no `basicConstraints`
    /// at all**. Requiring `basicConstraints` on the signer, or allow-listing
    /// RSA moduli to {2048, 4096}, rejects a documented alternate.
    ///
    /// Driven against an **injected** store because
    /// `swisssign-signature-services-root-2020-2` is quarantined from store
    /// v1 pending its C1 channel (`roots/PROVENANCE.md`). The chain
    /// mathematics is what this row tests, and it is unaffected by the
    /// admission decision.
    #[test]
    fn swisssign_rsa3072_leaf_without_basic_constraints_chains() {
        let t = token(SWISSSIGN, &PROBE);
        assert!(
            extension::<BasicConstraints>(t.signer()).is_none(),
            "fixture no longer exercises the missing-basicConstraints case"
        );
        let injected = store_of(vec![(SWISSSIGN_ROOT_DER.to_vec(), "injected-swisssign")]);
        let v = validate_token_chain(&t, &[], &injected, AFTER_CAPTURE);
        assert_eq!(v.state(), AnchorState::Proven, "fault: {:?}", v.fault());

        // And, as the store stands, it is `internally-consistent-only`
        // against the production store — the quarantine's user-visible
        // consequence, asserted rather than assumed.
        let production = validate_token_chain(&t, &[], TsaRootStore::pinned(), AFTER_CAPTURE);
        assert_eq!(production.state(), AnchorState::InternallyConsistentOnly);
    }

    /// Flip one bit inside a certificate's `authorityKeyIdentifier`.
    ///
    /// The AKI lives in the TBS, so this also breaks the signature — which is
    /// exactly what makes the test decisive. With the AKI/SKI rule the path is
    /// never *built* (D53 §3's name chaining) and the artifact is
    /// `internally-consistent-only`; without it the path is built and dies on
    /// the signature instead. Two different states from one mutation.
    fn with_wrong_aki(cert: &Certificate) -> Certificate {
        const OID: [u8; 5] = [0x06, 0x03, 0x55, 0x1D, 0x23];
        const KEYID: [u8; 2] = [0x80, 0x14];
        let mut der = der_of(cert);
        let at = der
            .windows(OID.len())
            .position(|w| w == OID)
            .expect("the fixture carries an authorityKeyIdentifier");
        let rel = der[at..]
            .windows(KEYID.len())
            .position(|w| w == KEYID)
            .expect("a 20-byte keyIdentifier");
        let last = at + rel + 2 + 19;
        der[last] ^= 0x01;
        Certificate::from_der(&der).expect("only the keyIdentifier changed")
    }

    /// Clear the `keyCertSign` bit in a certificate's `keyUsage`.
    ///
    /// One bit, no length change, and — as with [`with_ca_false`] — legitimate
    /// on a **root** only, because an anchor's own signature is never checked.
    fn without_key_cert_sign(cert: &Certificate) -> Vec<u8> {
        const OID: [u8; 5] = [0x06, 0x03, 0x55, 0x1D, 0x0F];
        const BITS: [u8; 2] = [0x03, 0x02];
        let mut der = der_of(cert);
        let at = der
            .windows(OID.len())
            .position(|w| w == OID)
            .expect("every pinned root carries keyUsage");
        let rel = der[at..]
            .windows(BITS.len())
            .position(|w| w == BITS)
            .expect("a two-octet BIT STRING");
        let value = at + rel + 3;
        assert_ne!(der[value] & 0x04, 0, "keyCertSign was set before the edit");
        der[value] &= !0x04;
        der
    }

    /// Move a certificate's `notAfter` year back to 2018, in place.
    ///
    /// `UTCTime` is fixed width, so this is two ASCII digits and no reshaping.
    /// Used only on a **root**, for the same reason as above.
    fn with_expired_not_after(cert: &Certificate) -> Vec<u8> {
        let mut der = der_of(cert);
        // Validity ::= SEQUENCE { notBefore UTCTime, notAfter UTCTime }
        let pat = [0x30u8, 0x1E, 0x17, 0x0D];
        let at = der
            .windows(pat.len())
            .position(|w| w == pat)
            .expect("two UTCTime validity fields");
        let not_after_year = at + 4 + 13 + 2;
        assert_eq!(&der[not_after_year..not_after_year + 2], b"38");
        der[not_after_year..not_after_year + 2].copy_from_slice(b"18");
        der
    }

    /// **D53 §5(a).** The trust anchor's own validity period is *not* checked.
    ///
    /// Pinned roots are long-lived and will expire while sealed bundles are
    /// still being verified. An implementation that checks `R.notAfter` flips
    /// every bundle anchored under a root to a worse state on that root's
    /// expiry date — the silent rot MVP-SPEC.md lines 109 and 130 forbid.
    ///
    /// Not reachable from an unmodified fixture: every real root outlives
    /// every certificate beneath it, so only a root whose `notAfter` has been
    /// moved can separate "the chain expired" from "the anchor expired".
    #[test]
    fn an_expired_pinned_root_still_yields_proven() {
        let t = token(DIGICERT, &PROBE);
        let real = Certificate::from_der(TsaRootStore::pinned().roots()[1].der).expect("parses");
        let expired = with_expired_not_after(&real);
        assert_eq!(expired.len(), der_of(&real).len());
        let store = store_of(vec![(expired, "root-expired-in-2018")]);
        let v = validate_chain(
            t.signer(),
            &certs(&t),
            &store,
            t.gen_time_unix(),
            AFTER_CAPTURE,
        );
        assert_eq!(
            v.state(),
            AnchorState::Proven,
            "an expired ANCHOR must not rot the evidence beneath it; fault {:?}",
            v.fault()
        );
        assert_eq!(v.verified_time_unix(), Some(t.gen_time_unix()));
    }

    /// D53 C4 through `keyUsage` rather than `basicConstraints`.
    ///
    /// A separate row because the two are separate conjuncts and a validator
    /// can implement one and skip the other: no real certificate in any
    /// captured chain is `CA:TRUE` *and* missing `keyCertSign`, so nothing
    /// else in the suite can see the omission.
    #[test]
    fn an_issuer_whose_key_usage_forbids_cert_signing_is_a_constraint_violation() {
        let t = token(DIGICERT, &PROBE);
        let real = Certificate::from_der(TsaRootStore::pinned().roots()[1].der).expect("parses");
        let crippled = without_key_cert_sign(&real);
        assert_eq!(
            crippled
                .iter()
                .zip(der_of(&real).iter())
                .filter(|(a, b)| a != b)
                .count(),
            1,
            "exactly one byte differs: the keyCertSign bit"
        );
        let store = store_of(vec![(crippled, "no-key-cert-sign")]);
        let v = validate_chain(
            t.signer(),
            &certs(&t),
            &store,
            t.gen_time_unix(),
            AFTER_CAPTURE,
        );
        assert_eq!(v.state(), AnchorState::Invalid, "fault {:?}", v.fault());
        assert_eq!(v.fault(), Some(ChainFault::ChainConstraintViolation));

        // Anti-vacuity: the same path with the bit set reaches `proven`.
        let ok = store_of(vec![(der_of(&real), "intact")]);
        assert_eq!(
            validate_chain(
                t.signer(),
                &certs(&t),
                &ok,
                t.gen_time_unix(),
                AFTER_CAPTURE
            )
            .state(),
            AnchorState::Proven
        );
    }

    /// **P3, with two paths of different grades in the pool.**
    ///
    /// The permutation row above cannot see a "first path wins"
    /// implementation, and that is worth stating rather than discovering
    /// later: a real token offers essentially one viable path, so every
    /// ordering finds the same one first. This row supplies a broken copy of
    /// every certificate alongside the real ones, so the pool holds a
    /// `Valid` path *and* a `SignatureInvalid` path, and asks that **every**
    /// ordering still return `proven`.
    ///
    /// It is also the ordering half of "an unsigned bundle lets any relay
    /// append a certificate": the relay chooses the order too.
    #[test]
    fn a_junk_intermediate_never_demotes_a_valid_chain_in_any_order() {
        let t = token(DIGICERT, &PROBE);
        let junk: Vec<Certificate> = t
            .chain_material()
            .iter()
            .map(with_broken_signature)
            .collect();
        let mut pool: Vec<&Certificate> = certs(&t);
        pool.extend(junk.iter());
        assert_eq!(pool.len(), 6);

        // 6! = 720 orderings; each is a full validation over a 7-node graph.
        let mut checked = 0usize;
        for order in permutations(pool.len()) {
            let permuted: Vec<&Certificate> = order.iter().map(|&i| pool[i]).collect();
            let v = validate_chain(
                t.signer(),
                &permuted,
                TsaRootStore::pinned(),
                t.gen_time_unix(),
                AFTER_CAPTURE,
            );
            assert_eq!(
                v.state(),
                AnchorState::Proven,
                "order {order:?} demoted an honest anchor to {:?}",
                v.fault()
            );
            checked += 1;
        }
        assert_eq!(checked, 720);
    }

    /// D53 §3's name chaining is **issuer DN *and* AKI/SKI where both are
    /// present**, not the DN alone.
    ///
    /// A certificate whose `authorityKeyIdentifier` names a different key
    /// builds no candidate path, so `NAMED` is empty and the artifact is
    /// `internally-consistent-only`. An implementation that matches on the DN
    /// alone builds the path and reports a signature failure instead — a
    /// different state, which is what makes this row able to fail.
    #[test]
    fn an_authority_key_identifier_naming_another_key_builds_no_path() {
        let t = token(DIGICERT, &PROBE);
        let root_subject = Certificate::from_der(TsaRootStore::pinned().roots()[1].der)
            .expect("parses")
            .tbs_certificate()
            .subject()
            .to_der()
            .expect("encodes");
        let rewritten: Vec<Certificate> = t
            .chain_material()
            .iter()
            .map(|c| {
                if c.tbs_certificate().issuer().to_der().expect("encodes") == root_subject {
                    with_wrong_aki(c)
                } else {
                    c.clone()
                }
            })
            .collect();
        let supplied: Vec<&Certificate> = rewritten.iter().collect();
        let v = validate_chain(
            t.signer(),
            &supplied,
            TsaRootStore::pinned(),
            t.gen_time_unix(),
            AFTER_CAPTURE,
        );
        assert_eq!(
            v.state(),
            AnchorState::InternallyConsistentOnly,
            "no candidate path names a pinned root; fault {:?}",
            v.fault()
        );
        assert_eq!(v.anchor_label(), None);
    }

    // ── D53 §9 — the six-way partition ──────────────────────────────────

    /// D53 C1.
    #[test]
    fn a_valid_chain_at_gentime_and_verify_at_is_proven() {
        let t = token(DIGICERT, &PROBE);
        let v = validate_token_chain(&t, &[], TsaRootStore::pinned(), AFTER_CAPTURE);
        assert_eq!(v.state(), AnchorState::Proven);
        assert!(v.headline_eligible());
        assert_eq!(v.fault(), None);
    }

    /// D53 C2 and the flip between it and C1, driven by **two `verify_at`
    /// values over one fixture**.
    ///
    /// Any implementation that reads a clock instead of the parameter returns
    /// the same state twice and fails here. Any implementation that validates
    /// at `verify_at` instead of at `genTime` renders the far-future call
    /// `invalid` — the aging-bundle rot MVP-SPEC.md lines 109 and 130 forbid.
    #[test]
    fn one_fixture_two_verify_times_flips_proven_and_since_expired() {
        let t = token(DIGICERT, &PROBE);
        let now = validate_token_chain(&t, &[], TsaRootStore::pinned(), AFTER_CAPTURE);
        assert_eq!(now.state(), AnchorState::Proven);

        // 2060 — past every certificate in the chain, and past the pinned
        // root's own 2038 expiry, which must NOT be checked (D53 §5a).
        let later = validate_token_chain(&t, &[], TsaRootStore::pinned(), 2_840_000_000);
        assert_eq!(later.state(), AnchorState::ValidAtStampingCertSinceExpired);
        assert!(later.headline_eligible());
        assert_eq!(
            later.verified_time_unix(),
            Some(t.gen_time_unix()),
            "the state exists precisely to keep carrying its proven stamping time"
        );
        assert_eq!(later.fault(), None);
    }

    /// D53 §5(b). `verify_at` is one-sided: a caller whose clock predates the
    /// certificates — or a WASM page passing a fixed value — still gets
    /// `proven`, never a failure. "Cert *since expired*" would be a lie for
    /// "not yet valid at your clock".
    #[test]
    fn verify_at_before_gentime_is_still_proven() {
        let t = token(DIGICERT, &PROBE);
        for verify_at in [0, 1, t.gen_time_unix() - 1_000_000] {
            let v = validate_token_chain(&t, &[], TsaRootStore::pinned(), verify_at);
            assert_eq!(
                v.state(),
                AnchorState::Proven,
                "verify_at={verify_at} must never produce a failure"
            );
        }
    }

    /// D53 C3, expired direction. The chain **names a pinned root**, so this
    /// is `invalid` — not `internally-consistent-only`, the option D53 §2a
    /// excludes.
    #[test]
    fn an_expired_at_gentime_chain_is_invalid_with_the_temporal_code() {
        let t = token(DIGICERT, &PROBE);
        // A genTime past the leaf's notAfter but inside nothing else's
        // business: 2060.
        let v = validate_chain(
            t.signer(),
            &certs(&t),
            TsaRootStore::pinned(),
            2_840_000_000,
            2_840_000_000,
        );
        assert_eq!(v.state(), AnchorState::Invalid);
        assert_eq!(
            v.fault(),
            Some(ChainFault::CertNotValidAtGenTime {
                bound: TemporalBound::Expired
            })
        );
        assert_eq!(
            v.fault().expect("set").code(),
            "anchor-cert-not-valid-at-gentime"
        );
        assert!(!v.headline_eligible());
    }

    /// D53 sub-case 3 — **the back-dating gap.** A token asserting a time
    /// before the signing certificate existed.
    ///
    /// This direction appears in no spec line, no task text and no
    /// `MATRIX.json` row. **This test is the only guard on it in the tree**;
    /// deleting it silently unguards the cheapest form of priority fraud.
    /// Any implementation checking only `notAfter < genTime` fails here.
    #[test]
    fn a_certificate_not_yet_valid_at_gentime_is_the_same_code() {
        let t = token(DIGICERT, &PROBE);
        // 2001 — before every certificate in the chain was issued.
        let v = validate_chain(
            t.signer(),
            &certs(&t),
            TsaRootStore::pinned(),
            1_000_000_000,
            AFTER_CAPTURE,
        );
        assert_eq!(v.state(), AnchorState::Invalid);
        assert_eq!(
            v.fault(),
            Some(ChainFault::CertNotValidAtGenTime {
                bound: TemporalBound::NotYetValid
            }),
            "back-dating must be caught, and must be distinguishable in the payload"
        );
        assert_eq!(
            v.fault().expect("set").code(),
            "anchor-cert-not-valid-at-gentime",
            "one code covers both directions (D53 §7); only the payload differs"
        );
    }

    /// D53 C4. Built by removing `basicConstraints` from the **pinned root**,
    /// which is legitimate precisely because a trust anchor's own signature is
    /// never checked (D53 §5a) — so the child's link still verifies and the
    /// only thing that changed is the constraint under test.
    ///
    /// This is the classic "any leaf can sign" hole, and a validator that
    /// omits `basicConstraints` returns `proven` here.
    #[test]
    fn an_issuer_that_is_not_a_ca_is_invalid_with_the_constraint_code() {
        let t = token(DIGICERT, &PROBE);
        let real = Certificate::from_der(TsaRootStore::pinned().roots()[1].der).expect("parses");
        let crippled = with_ca_false(&real);
        assert_eq!(
            crippled.len(),
            der_of(&real).len(),
            "one byte, no reshaping"
        );
        assert_eq!(
            crippled
                .iter()
                .zip(der_of(&real).iter())
                .filter(|(a, b)| a != b)
                .count(),
            1,
            "exactly one byte differs: the cA flag"
        );
        let store = store_of(vec![(crippled, "ca-false")]);
        let v = validate_chain(
            t.signer(),
            &certs(&t),
            &store,
            t.gen_time_unix(),
            AFTER_CAPTURE,
        );
        assert_eq!(v.state(), AnchorState::Invalid);
        assert_eq!(v.fault(), Some(ChainFault::ChainConstraintViolation));
        assert_eq!(
            v.fault().expect("set").code(),
            "anchor-chain-constraint-violation"
        );

        // Anti-vacuity: the identical path with the real root reaches
        // `proven`, so the failure is the extension and nothing else.
        let ok = store_of(vec![(der_of(&real), "intact")]);
        assert_eq!(
            validate_chain(
                t.signer(),
                &certs(&t),
                &ok,
                t.gen_time_unix(),
                AFTER_CAPTURE
            )
            .state(),
            AnchorState::Proven
        );
    }

    /// D53 C5. The intermediate's DER has one bit flipped in its trailing
    /// `signature` BIT STRING: name chaining is bit-identical, so the path is
    /// still *built* and still names a pinned root — only the link signature
    /// fails. A validator trusting name chaining alone returns `proven`.
    #[test]
    fn a_broken_link_signature_is_invalid_with_the_signature_code() {
        let t = token(DIGICERT, &PROBE);
        let pool = certs(&t);
        let broken: Vec<Certificate> = pool.iter().map(|c| with_broken_signature(c)).collect();
        let supplied: Vec<&Certificate> = broken.iter().collect();
        let v = validate_chain(
            t.signer(),
            &supplied,
            TsaRootStore::pinned(),
            t.gen_time_unix(),
            AFTER_CAPTURE,
        );
        assert_eq!(v.state(), AnchorState::Invalid, "fault: {:?}", v.fault());
        assert_eq!(v.fault(), Some(ChainFault::ChainSignatureInvalid));
        assert_eq!(
            v.fault().expect("set").code(),
            "anchor-chain-signature-invalid"
        );
    }

    /// D53 C6. A real, fully well-formed token from a TSA the closure rule
    /// does not name. A validator that falls back to `Invalid` when no anchor
    /// is found contradicts MVP-SPEC.md line 133 and this row.
    ///
    /// Asserts the token **passed T2** first, so it cannot pass vacuously
    /// against a token that was malformed for an unrelated reason.
    #[test]
    fn an_untrusted_root_is_internally_consistent_only() {
        let t = token(GLOBALSIGN, &D60_STAMPED);
        assert_eq!(t.chain_material().len(), 4, "T2 parsed the whole bag");
        let v = validate_token_chain(&t, &[], TsaRootStore::pinned(), AFTER_CAPTURE);
        assert_eq!(v.state(), AnchorState::InternallyConsistentOnly);
        assert_eq!(v.fault(), None);
        assert_eq!(v.verified_time_unix(), None);
        assert!(!v.headline_eligible());
    }

    /// The overlapping pair D53 §3 tabulates and the register's binary
    /// framing gets wrong: a chain that reaches **no** pinned root *and* is
    /// outside its validity window at `genTime`.
    ///
    /// `NAMED` is empty, so there is nothing to refute →
    /// `internally-consistent-only`. Any implementation that checks time
    /// before checking reachability returns `invalid`, and the natural check
    /// order does exactly that.
    #[test]
    fn an_untrusted_root_expired_before_gentime_is_internally_consistent_only() {
        let t = token(GLOBALSIGN, &D60_STAMPED);
        let v = validate_chain(
            t.signer(),
            &certs(&t),
            TsaRootStore::pinned(),
            2_840_000_000, // 2060: every certificate in the bag has expired
            2_840_000_000,
        );
        assert_eq!(v.state(), AnchorState::InternallyConsistentOnly);
        assert_eq!(v.fault(), None);
    }

    /// Best-evidence-wins (`C1/C2` over `C3–C5`). The `.sealproof` bundle is
    /// **unsigned** (D8), so any relay can append a certificate; under
    /// most-severe-wins one appended junk certificate would downgrade every
    /// honest anchor in the bundle.
    #[test]
    fn a_junk_intermediate_never_demotes_a_valid_chain() {
        let t = token(DIGICERT, &PROBE);
        let junk: Vec<Certificate> = t
            .chain_material()
            .iter()
            .map(with_broken_signature)
            .collect();
        let mut supplied = certs(&t);
        supplied.extend(junk.iter());
        let v = validate_chain(
            t.signer(),
            &supplied,
            TsaRootStore::pinned(),
            t.gen_time_unix(),
            AFTER_CAPTURE,
        );
        assert_eq!(
            v.state(),
            AnchorState::Proven,
            "a relay must not be able to demote an honest anchor"
        );
    }

    /// D53 §4, defence in depth. `aggregate_anchors` already ignores times on
    /// ineligible slots, so **only this test can see** an implementation that
    /// populates `verified_time_unix` from `genTime` unconditionally.
    #[test]
    fn no_ineligible_state_carries_a_verified_time() {
        let t = token(DIGICERT, &PROBE);
        let ineligible = [
            // C3 (back-dated), C5 (broken link), C6 (no pinned root).
            validate_chain(
                t.signer(),
                &certs(&t),
                TsaRootStore::pinned(),
                1_000_000_000,
                AFTER_CAPTURE,
            ),
            validate_chain(
                t.signer(),
                &certs(&t),
                &empty_store(),
                t.gen_time_unix(),
                AFTER_CAPTURE,
            ),
        ];
        for v in ineligible {
            assert!(!v.headline_eligible(), "{v:?}");
            assert_eq!(v.verified_time_unix(), None, "{v:?}");
        }
    }

    /// D53 §3's second bound. The bundle admits 16 intermediates and a
    /// hostile sealer can make them **mutually name-chaining** for free — a
    /// permutation-style enumerator is factorial on this input and hangs the
    /// verifier.
    ///
    /// The 16 certificates here are byte-mutations of one real self-signed
    /// root, so every one has the identical subject DN, issuer DN and
    /// `subjectKeyIdentifier`: every pair name-chains in both directions,
    /// which is the worst case. The assertion is on a **work budget** — the
    /// number of link-signature evaluations, which is what the DP bounds —
    /// and not merely that the call returns.
    #[test]
    fn sixteen_mutually_chaining_intermediates_terminate_promptly() {
        let t = token(DFN, &PROBE);
        let self_signed = t
            .chain_material()
            .iter()
            .find(|c| {
                let tbs = c.tbs_certificate();
                tbs.issuer().to_der().ok() == tbs.subject().to_der().ok()
            })
            .expect("DFN ships its own root")
            .clone();

        let mut hostile: Vec<Certificate> = Vec::new();
        for i in 0..16u8 {
            let mut der = der_of(&self_signed);
            let n = der.len();
            der[n - 1 - usize::from(i)] ^= 0x01;
            hostile.push(Certificate::from_der(&der).expect("only signature bytes changed"));
        }
        let mut supplied = certs(&t);
        supplied.extend(hostile.iter());
        assert!(supplied.len() >= 19);

        let mut builder = PathBuilder::new(
            t.signer(),
            &supplied,
            TsaRootStore::pinned(),
            t.gen_time_unix(),
            AFTER_CAPTURE,
        );
        let reach = builder.reach();
        // The honest path survives: the real chain is still in the pool.
        assert_eq!(
            reach.best.map(|(g, _)| g),
            Some(Grade::Valid),
            "the hostile padding must not change the verdict"
        );
        // `O(V^2)` distinct links, memoised — not `O(V!)` paths. With 20
        // nodes and 4 roots the ceiling is 20 * 24 = 480.
        assert!(
            builder.sig_memo.len() <= 480,
            "link evaluations blew the DP bound: {}",
            builder.sig_memo.len()
        );
        assert!(
            builder.memo.len() <= MAX_CHAIN_CERTS * (supplied.len() + 1),
            "memo states blew the (node, depth) bound: {}",
            builder.memo.len()
        );
        // The path-length bound is *reached* here, not merely declared. On
        // this graph every node chains to every other, so the search would
        // run forever without it — a cap that cannot be hit is the defect
        // class this project keeps finding, and this is where it is hit.
        let deepest = builder.memo.keys().map(|&(_, d)| d).max().expect("visited");
        assert_eq!(
            deepest,
            MAX_CHAIN_CERTS - 2,
            "the search must stop at the deepest position an intermediate can occupy"
        );
    }

    // ── A6 / A26 — store version and append stability ───────────────────

    /// A6/A26 Accept: the store version travels with the verdict, so R can
    /// display which trust store produced it.
    #[test]
    fn store_version_appears_in_verdict_data() {
        let t = token(DIGICERT, &PROBE);
        let v = validate_token_chain(&t, &[], TsaRootStore::pinned(), AFTER_CAPTURE);
        assert_eq!(
            v.root_store_version(),
            super::super::roots::TSA_ROOT_STORE_VERSION
        );
        assert_eq!(v.root_store_version(), 1);

        let injected = store_of(vec![(
            TsaRootStore::pinned().roots()[1].der.to_vec(),
            "injected",
        )]);
        let w = validate_token_chain(&t, &[], &injected, AFTER_CAPTURE);
        assert_eq!(
            w.root_store_version(),
            0,
            "an injected store must be distinguishable in verdict data"
        );
    }

    /// **A26's append-only property.** Adding a root leaves every existing
    /// verdict byte-identical except for the version field. Fails if root-set
    /// membership leaks into a verdict beyond that.
    #[test]
    fn appending_a_root_leaves_every_existing_verdict_unchanged() {
        let base: Vec<(Vec<u8>, &'static str)> = TsaRootStore::pinned()
            .roots()
            .iter()
            .map(|r| (r.der.to_vec(), r.label))
            .collect();
        let mut appended = base.clone();
        appended.push((SWISSSIGN_ROOT_DER.to_vec(), "appended-swisssign"));

        let before = store_of(base);
        let after = store_of(appended);

        for (name, bytes, digest) in [
            ("freetsa", FREETSA, &PROBE),
            ("digicert", DIGICERT, &PROBE),
            ("dfn", DFN, &PROBE),
            ("sectigo", SECTIGO, &PROBE),
            ("globalsign", GLOBALSIGN, &D60_STAMPED),
        ] {
            let t = token(bytes, digest);
            let a = validate_token_chain(&t, &[], &before, AFTER_CAPTURE);
            let b = validate_token_chain(&t, &[], &after, AFTER_CAPTURE);
            assert_eq!(a, b, "{name}: appending a root changed an existing verdict");
        }

        // And the append is real: the previously unanchored SwissSign token
        // now resolves. Without this the test above could pass vacuously
        // against an append that did nothing.
        let ss = token(SWISSSIGN, &PROBE);
        assert_eq!(
            validate_token_chain(&ss, &[], &before, AFTER_CAPTURE).state(),
            AnchorState::InternallyConsistentOnly
        );
        assert_eq!(
            validate_token_chain(&ss, &[], &after, AFTER_CAPTURE).state(),
            AnchorState::Proven
        );
    }

    // ── The code set ────────────────────────────────────────────────────

    /// D53 §7 spells all three codes; a rename is not a fix once anything
    /// binds to them. Also asserts the `anchor-` prefix (D91 §6.1) and
    /// disjointness from stage T1/T2's roster, which is the collision a
    /// copy-paste would produce.
    #[test]
    fn every_chain_code_is_pairwise_distinct_and_anchor_prefixed() {
        let exemplars = all_code_exemplars();
        assert_eq!(exemplars.len(), 3);
        let codes: BTreeSet<&'static str> = exemplars.iter().map(ChainFault::code).collect();
        assert_eq!(codes.len(), exemplars.len(), "two exemplars share a code");
        for ruled in [
            "anchor-cert-not-valid-at-gentime",
            "anchor-chain-constraint-violation",
            "anchor-chain-signature-invalid",
        ] {
            assert!(codes.contains(ruled), "D53 §7's code `{ruled}` is missing");
        }
        for code in &codes {
            assert!(code.starts_with("anchor-"), "`{code}` is off-prefix");
            assert!(
                code.chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
            );
        }
        let t1_t2: BTreeSet<&'static str> = super::super::error::all_code_exemplars()
            .iter()
            .map(super::super::error::AnchorError::code)
            .collect();
        assert!(!t1_t2.is_empty());
        assert!(
            codes.is_disjoint(&t1_t2),
            "a T3 code collides with a T1/T2 code: {:?}",
            codes.intersection(&t1_t2).collect::<Vec<_>>()
        );

        // Both directions of the temporal bound resolve to the same code —
        // D53 §7's ruling, which a later edit could quietly split.
        assert_eq!(
            ChainFault::CertNotValidAtGenTime {
                bound: TemporalBound::Expired
            }
            .code(),
            ChainFault::CertNotValidAtGenTime {
                bound: TemporalBound::NotYetValid
            }
            .code()
        );
    }

    /// `constraints_ok` against **real** certificates at real and hypothetical
    /// depths.
    ///
    /// The end-to-end C4 row above exercises one shape; this exercises the
    /// predicate directly, including `pathLenConstraint` arithmetic, which no
    /// real chain is deep enough to violate. Recorded plainly: a
    /// constraint-violating chain that is also *validly signed* cannot be
    /// built from real material, so the depth axis is only reachable here or
    /// from A24's test CA.
    #[test]
    fn constraints_ok_reads_real_certificates_correctly() {
        let t = token(DIGICERT, &PROBE);
        // The leaf: CA:FALSE. Never acceptable as an issuer element.
        assert!(!constraints_ok(t.signer(), 1));

        let ts_ca = t
            .chain_material()
            .iter()
            .find(|c| {
                extension::<BasicConstraints>(c)
                    .is_some_and(|bc| bc.ca && bc.path_len_constraint == Some(0))
            })
            .expect("DigiCert's TimeStamping CA has pathLen:0");
        // pathLen 0 permits zero intermediates below it: fine at depth 1,
        // refused at depth 2.
        assert!(constraints_ok(ts_ca, 1));
        assert!(!constraints_ok(ts_ca, 2));
        assert!(!constraints_ok(ts_ca, 7));

        // SwissSign's leaf carries no basicConstraints at all — accepted as a
        // *signer* (it is never passed here in production) and refused as an
        // issuer.
        let ss = token(SWISSSIGN, &PROBE);
        assert!(extension::<BasicConstraints>(ss.signer()).is_none());
        assert!(!constraints_ok(ss.signer(), 1));

        // Every pinned root is usable as an anchor at every reachable depth.
        for root in TsaRootStore::pinned().roots() {
            let cert = root.parse().expect("parses");
            for depth in 1..MAX_CHAIN_CERTS {
                assert!(
                    constraints_ok(&cert, depth),
                    "{} rejected at depth {depth}",
                    root.label
                );
            }
        }
    }

    // ── A39 — the refutations best-evidence-wins discards ───────────────

    /// The lattice's rank encoding is a bijection and it agrees with the
    /// derived `Ord`.
    ///
    /// [`GradeSet`] indexes by rank, so a rank that disagreed with `Ord`
    /// would make `capped_at` and `below` compute the wrong set while every
    /// *state* stayed correct — a defect no state assertion anywhere can see.
    #[test]
    fn grade_ranks_round_trip_and_order_matches_the_lattice() {
        let all = [
            Grade::SignatureInvalid,
            Grade::ConstraintViolation,
            Grade::NotValidAtGenTime(TemporalBound::Expired),
            Grade::NotValidAtGenTime(TemporalBound::NotYetValid),
            Grade::ValidAtGenTimeButExpired,
            Grade::Valid,
        ];
        assert_eq!(all.len(), usize::from(GRADE_COUNT));
        for (i, g) in all.iter().enumerate() {
            let rank = u8::try_from(i).expect("six grades");
            assert_eq!(g.rank(), rank);
            assert_eq!(Grade::from_rank(rank), *g);
        }
        for pair in all.windows(2) {
            assert!(pair[0] < pair[1], "{:?} !< {:?}", pair[0], pair[1]);
        }
        // The two grades that refute nothing, named rather than assumed.
        assert_eq!(Grade::Valid.fault(), None);
        assert_eq!(Grade::ValidAtGenTimeButExpired.fault(), None);
    }

    /// The invariant the whole extension rests on: the maximum of the grade
    /// **set** is the grade the verdict reports.
    ///
    /// If it ever failed, A39's list would be computed against a ceiling the
    /// state does not come from, and the anomaly list would silently include
    /// or exclude the wrong entries.
    #[test]
    fn the_best_grade_is_the_maximum_of_the_grade_set() {
        let t = token(DIGICERT, &PROBE);
        let junk: Vec<Certificate> = t
            .chain_material()
            .iter()
            .map(with_broken_signature)
            .collect();
        let mut pool: Vec<&Certificate> = certs(&t);
        pool.extend(junk.iter());

        for supplied in [certs(&t), pool] {
            for store in [TsaRootStore::pinned(), &empty_store()] {
                let mut builder = PathBuilder::new(
                    t.signer(),
                    &supplied,
                    store,
                    t.gen_time_unix(),
                    AFTER_CAPTURE,
                );
                let reach = builder.reach();
                let max = reach.grades.iter().max();
                assert_eq!(
                    reach.best.map(|(g, _)| g),
                    max,
                    "best and the grade set disagree"
                );
                assert_eq!(reach.best.is_none(), reach.grades.is_empty());
            }
        }
    }

    /// **A39 Accept row 1.** One valid path and one broken-signature path:
    /// the anchor is `proven` **and** the discarded refutation is recorded,
    /// exactly once, naming `anchor-chain-signature-invalid`.
    ///
    /// What makes it fail: an implementation that reports only the maximum
    /// (the state stays `proven`, so `a_junk_intermediate_never_demotes…`
    /// still passes and this is the only row that can see the loss); or one
    /// that records the *winning* grade as an anomaly too, which would put an
    /// anomaly on every honest chain.
    #[test]
    fn a_valid_chain_beside_a_broken_signature_path_records_the_suppression() {
        let t = token(DIGICERT, &PROBE);
        let junk: Vec<Certificate> = t
            .chain_material()
            .iter()
            .map(with_broken_signature)
            .collect();
        let mut pool: Vec<&Certificate> = certs(&t);
        pool.extend(junk.iter());

        let v = validate_chain(
            t.signer(),
            &pool,
            TsaRootStore::pinned(),
            t.gen_time_unix(),
            AFTER_CAPTURE,
        );
        assert_eq!(v.state(), AnchorState::Proven);
        assert_eq!(v.fault(), None);
        assert_eq!(
            v.suppressed_faults(),
            vec![ChainFault::ChainSignatureInvalid],
            "the appended broken path vanished from the verdict"
        );
    }

    /// The anti-vacuity twin, and it is the load-bearing half: an **honest**
    /// chain suppresses nothing.
    ///
    /// DigiCert's real token offers several candidate paths (the
    /// cross-certificate gives two routes to the pinned root), so this is not
    /// a degenerate single-path case. Without it, `suppressed_faults()`
    /// returning "every fault class, always" would pass the row above.
    #[test]
    fn a_real_honest_chain_suppresses_nothing() {
        for (bytes, digest) in [
            (DIGICERT, &PROBE),
            (FREETSA, &PROBE),
            (SECTIGO, &PROBE),
            (DFN, &PROBE),
        ] {
            let t = token(bytes, digest);
            let v = validate_token_chain(&t, &[], TsaRootStore::pinned(), AFTER_CAPTURE);
            assert_eq!(v.state(), AnchorState::Proven, "fault {:?}", v.fault());
            assert!(
                v.suppressed_faults().is_empty(),
                "an honest chain reported anomalies: {:?}",
                v.suppressed_faults()
            );
        }
    }

    /// D53 §12's residual risk, made visible: on a multi-defect artifact the
    /// reported code names the **best** path's failure, and A39 carries the
    /// rest.
    ///
    /// A constraint-violating root and a signature-broken copy of the same
    /// chain: the verdict is the *less* severe `anchor-chain-constraint-
    /// violation`, and the discarded `anchor-chain-signature-invalid` is in
    /// the list. The reported fault is never also in the list.
    #[test]
    fn least_severe_wins_reports_the_better_failure_and_records_the_worse() {
        let t = token(DIGICERT, &PROBE);
        let real = Certificate::from_der(TsaRootStore::pinned().roots()[1].der).expect("parses");
        let store = store_of(vec![(with_ca_false(&real), "ca-false")]);

        let junk: Vec<Certificate> = t
            .chain_material()
            .iter()
            .map(with_broken_signature)
            .collect();
        let mut pool: Vec<&Certificate> = certs(&t);
        pool.extend(junk.iter());

        let v = validate_chain(t.signer(), &pool, &store, t.gen_time_unix(), AFTER_CAPTURE);
        assert_eq!(v.state(), AnchorState::Invalid);
        assert_eq!(v.fault(), Some(ChainFault::ChainConstraintViolation));
        assert_eq!(
            v.suppressed_faults(),
            vec![ChainFault::ChainSignatureInvalid]
        );
        assert!(
            !v.suppressed_faults().contains(&v.fault().expect("invalid")),
            "the reported fault must not also be reported as suppressed"
        );
    }

    /// The suppressed list is invariant under permutation of the supplied
    /// certificates, exactly as the state and the code are (D53 §3).
    ///
    /// A "first path wins" implementation of the *set* — collecting only
    /// until the first path is graded — passes every row above and fails
    /// here.
    #[test]
    fn the_suppressed_list_is_invariant_under_permutation() {
        let t = token(DIGICERT, &PROBE);
        let junk: Vec<Certificate> = t
            .chain_material()
            .iter()
            .map(with_broken_signature)
            .collect();
        let mut pool: Vec<&Certificate> = certs(&t);
        pool.extend(junk.iter());

        let mut seen = BTreeSet::new();
        for order in permutations(pool.len()) {
            let permuted: Vec<&Certificate> = order.iter().map(|&i| pool[i]).collect();
            let v = validate_chain(
                t.signer(),
                &permuted,
                TsaRootStore::pinned(),
                t.gen_time_unix(),
                AFTER_CAPTURE,
            );
            seen.insert(format!("{:?}/{:?}", v.state(), v.suppressed_faults()));
        }
        assert_eq!(
            seen.len(),
            1,
            "permutation changed the anomaly list: {seen:?}"
        );
    }
}
