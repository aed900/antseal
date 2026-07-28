//! Golden-vector kind **`sig-reject`** (task C15): committed reject-vector
//! suites for both author-signature algorithms.
//!
//! Spec basis: "Verification MUST be strict/canonical and is a conformance
//! requirement for every verifier (CLI, WASM page, third parties) so they
//! cannot diverge on the same frozen bundle" (MVP-SPEC.md line 97), and the
//! M0 milestone's "hybrid sigs with strict Ed25519 (`verify_strict`) +
//! canonical ML-DSA and **reject-vectors**" (line 153).
//!
//! These vectors pin the *rejection* semantics C12/C13 implement, and — the
//! part a bare unit test cannot give — they pin them as **committed,
//! third-party-consumable artifacts**: a second implementation can take a
//! suite, rebuild each case's bytes from the recipe, and check it reaches
//! the same verdict. Every case is routed through **C14's full verification
//! path** ([`sig_policy::verify_body`]), not through the per-algorithm entry
//! points, so the suites also cover the policy layer's own length and
//! present-set checks.
//!
//! # Why a vector kind rather than a new `testdata/` category
//!
//! tasks/C.md C15 sketches `testdata/sig-reject/`. That predates Q2's
//! layout decision, which makes `testdata/vectors/<format-version>/` the
//! home of *all* committed vectors and a new top-level category a reviewed
//! layout change (`testdata/README.md`, contribution rule 5). Reject vectors
//! are golden vectors whose `expect` happens to be an error code, so they
//! slot into the Q4 envelope with no framework redesign — and inherit, for
//! free, the discovery contract, the NON-SECRET enforcement, the
//! misfiled-version check, and the WASM-safe execution path the Q5
//! native↔WASM bit-match lane reuses. The suites therefore live at
//! `testdata/vectors/v1/sig-reject/`.
//!
//! # Document shape
//!
//! Full field-by-field documentation, including the exact byte-building
//! rules an independent implementation must follow, is in
//! `testdata/vectors/v1/sig-reject/README.md`. In outline:
//!
//! ```text
//! inputs: { w, alg, ctx, body }
//! expect:
//!   base:  { public_key, signature }        # full hex, re-derived and compared
//!   cases: [ { id, class, why,
//!              public_key: <source>, signature: <source>,
//!              expect: "accept" | "<crypto-… error code>" } ]
//! ```
//!
//! A `<source>` names where the bytes come from (`base`, a signature made
//! under another `context`, the bare-body `raw-body` signature, or the
//! documented `alternate-signer`) and then applies an ordered list of byte
//! `edits`, an optional `truncate_to`, and an optional `append_hex`. Every
//! case is thus reproducible from `W`, the body, and the recipe — nothing is
//! an unexplained blob.
//!
//! # What the executor asserts
//!
//! 1. `inputs.w` is the documented fixed test seed and `inputs.ctx` is the
//!    frozen [`SIG_CONTEXT`] — a suite cannot quietly pin some other
//!    context or some other secret.
//! 2. `expect.base` re-derives byte-for-byte from `W` through the public
//!    API, so the base is itself a keygen + deterministic-signing golden.
//! 3. Class coverage: every class C15 enumerates for that algorithm is
//!    present (a suite cannot silently lose its `z`-bound or small-order
//!    case).
//! 4. Every reject case's expected code is a real, `crypto-`-prefixed
//!    [`CryptoError`](crate::crypto::error::CryptoError) code (typo guard,
//!    D30 contract §2).
//! 5. Each case's bytes, built from the recipe, produce exactly the
//!    expected outcome through [`sig_policy::verify_body`]; positive
//!    controls verify.

use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::crypto::SIG_CONTEXT;
use crate::crypto::error::{SigAlg, all_code_exemplars};
use crate::crypto::material::MasterSecretRef;
use crate::crypto::sig_policy::{self, SigPolicy};
use crate::crypto::{sig_ed25519, sig_mldsa};

use super::TEST_MASTER_SECRET_W;
use super::vectors::{VectorError, VectorSummary, decode_hex, hex};

/// The registered kind name.
pub const KIND: &str = "sig-reject";

/// Domain-separation label of the **alternate signer** used by `wrong-key`
/// cases. The alternate secret is
/// `W' = SHA-256(ALTERNATE_SIGNER_LABEL ‖ TEST_MASTER_SECRET_W)` — derived
/// from the documented fixed test seed, so it satisfies the secret-material
/// convention (`testdata/README.md`) while being a genuinely different
/// signer. It never appears in a committed file; only the public keys and
/// signatures it produces do.
pub const ALTERNATE_SIGNER_LABEL: &[u8] = b"antseal C15 alternate signer";

/// The alternate signer's master secret (see [`ALTERNATE_SIGNER_LABEL`]).
#[must_use]
pub fn alternate_signer_secret() -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(ALTERNATE_SIGNER_LABEL);
    hasher.update(TEST_MASTER_SECRET_W);
    hasher.finalize().into()
}

/// Every recognised case class. A class names *what kind of rejection rule*
/// the case exercises; the executor uses them for coverage, and readers use
/// them to see at a glance that a suite is complete.
pub const CLASSES: &[&str] = &[
    // shared
    "accept",
    "wrong-key",
    "wrong-context",
    "wrong-length",
    "bit-flip",
    "degenerate",
    "canonical-but-invalid",
    // Ed25519 (RFC 8032 strict verification)
    "s-out-of-range",
    "small-order-point",
    "non-canonical-point",
    // ML-DSA-65 (FIPS 204 canonical encoding)
    "hint-rule",
    "z-out-of-range",
];

/// Classes a suite for `alg` **must** contain — C15's enumerated reject
/// families, per algorithm.
#[must_use]
pub const fn required_classes(alg: SigAlg) -> &'static [&'static str] {
    match alg {
        SigAlg::Ed25519 => &[
            "accept",
            "s-out-of-range",
            "small-order-point",
            "non-canonical-point",
            "wrong-key",
            "wrong-context",
            "wrong-length",
        ],
        SigAlg::MlDsa65 => &[
            "accept",
            "hint-rule",
            "z-out-of-range",
            "wrong-length",
            "bit-flip",
            "wrong-key",
            "wrong-context",
        ],
    }
}

/// Classes a suite for `alg` **may** contain: the required ones plus the
/// algorithm-agnostic extras. A `hint-rule` case in an Ed25519 suite (or a
/// `small-order-point` case in an ML-DSA suite) is a misfiled vector.
#[must_use]
pub const fn applicable_classes(alg: SigAlg) -> &'static [&'static str] {
    match alg {
        SigAlg::Ed25519 => &[
            "accept",
            "s-out-of-range",
            "small-order-point",
            "non-canonical-point",
            "wrong-key",
            "wrong-context",
            "wrong-length",
            "bit-flip",
            "degenerate",
            "canonical-but-invalid",
        ],
        SigAlg::MlDsa65 => &[
            "accept",
            "hint-rule",
            "z-out-of-range",
            "wrong-key",
            "wrong-context",
            "wrong-length",
            "bit-flip",
            "degenerate",
            "canonical-but-invalid",
        ],
    }
}

/// The `expect` value meaning "this case must verify".
pub const ACCEPT: &str = "accept";

// ---------------------------------------------------------------------------
// payload schema
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Inputs {
    w: String,
    alg: String,
    ctx: String,
    body: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Expect {
    base: Base,
    cases: Vec<Case>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Base {
    public_key: String,
    signature: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Case {
    id: String,
    class: String,
    why: String,
    public_key: Source,
    signature: Source,
    expect: String,
    /// Optional expanded bytes. Present for the 32/64-byte Ed25519 values,
    /// where committing the result costs nothing and makes the file
    /// consumable without implementing the recipe; omitted for the
    /// kilobyte-scale ML-DSA values, which the documented edits reproduce.
    #[serde(default)]
    public_key_hex: Option<String>,
    #[serde(default)]
    signature_hex: Option<String>,
}

/// Where a case's bytes come from, and how they are then mutated.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Source {
    from: String,
    /// Context string for `from = "context"` (ASCII, as written).
    #[serde(default)]
    ctx: Option<String>,
    /// Byte edits applied in order, before `truncate_to`/`append_hex`.
    #[serde(default)]
    edits: Vec<Edit>,
    #[serde(default)]
    truncate_to: Option<usize>,
    #[serde(default)]
    append_hex: Option<String>,
}

/// One splice: either literal `hex` bytes at `offset`, or `repeat` copies of
/// the single byte `fill`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Edit {
    offset: usize,
    #[serde(default)]
    hex: Option<String>,
    #[serde(default)]
    fill: Option<String>,
    #[serde(default)]
    repeat: Option<usize>,
}

/// Which half of a case's material is being built (error messages only).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Role {
    PublicKey,
    Signature,
}

impl Role {
    const fn as_str(self) -> &'static str {
        match self {
            Self::PublicKey => "public_key",
            Self::Signature => "signature",
        }
    }
}

// ---------------------------------------------------------------------------
// execution
// ---------------------------------------------------------------------------

fn payload_err(problem: String) -> VectorError {
    VectorError::Payload {
        kind: KIND,
        problem,
    }
}

fn check_err(check: &'static str, problem: String) -> VectorError {
    VectorError::Check {
        kind: KIND,
        check,
        problem,
    }
}

/// Parse, validate, and execute one `sig-reject` document.
///
/// Called from [`super::vectors::execute_vector_bytes`]'s dispatch; the
/// envelope-level fields (schema, version, NON-SECRET marker) are already
/// checked there.
///
/// # Errors
///
/// Every failure class of [`VectorError`]: a malformed payload, an
/// expectation that does not reproduce, or a case whose verdict differs
/// from the committed one.
pub fn execute(
    inputs: serde_json::Value,
    expect: serde_json::Value,
    description: String,
) -> Result<VectorSummary, VectorError> {
    let inputs: Inputs =
        serde_json::from_value(inputs).map_err(|e| payload_err(format!("inputs: {e}")))?;
    let expect: Expect =
        serde_json::from_value(expect).map_err(|e| payload_err(format!("expect: {e}")))?;

    // 1. Fixture discipline: the documented test seed and the frozen ctx.
    let w_bytes = decode_hex(KIND, "inputs.w", &inputs.w)?;
    let w_array: [u8; 32] = w_bytes
        .try_into()
        .map_err(|_| check_err("w-length", "inputs.w must be exactly 32 bytes".to_owned()))?;
    if w_array != TEST_MASTER_SECRET_W {
        return Err(check_err(
            "w-is-documented-test-seed",
            "inputs.w is not the documented fixed test seed 0x00..0x1f (testdata/README.md)"
                .to_owned(),
        ));
    }
    let w = MasterSecretRef::from_bytes(&w_array);

    if inputs.ctx.as_bytes() != SIG_CONTEXT {
        return Err(check_err(
            "frozen-context",
            format!(
                "inputs.ctx is `{}`, but the frozen signature context is `{}` (MVP-SPEC.md line 97)",
                inputs.ctx,
                String::from_utf8_lossy(SIG_CONTEXT)
            ),
        ));
    }

    let alg = parse_alg(&inputs.alg)?;
    let body = decode_hex(KIND, "inputs.body", &inputs.body)?;

    // 2. The base is itself a golden: it must re-derive from W.
    let base_public_key = derive_public_key(alg, w);
    let base_signature = derive_signature(alg, w, &body);
    compare_bytes(
        "base-public-key",
        &base_public_key,
        &decode_hex(KIND, "expect.base.public_key", &expect.base.public_key)?,
    )?;
    compare_bytes(
        "base-signature",
        &base_signature,
        &decode_hex(KIND, "expect.base.signature", &expect.base.signature)?,
    )?;

    // 3/4. Structural checks over the case list.
    check_case_list(alg, &expect.cases)?;

    // 5. Every case reaches exactly its committed verdict.
    let policy = SigPolicy::new([alg]).map_err(|e| {
        check_err(
            "single-algorithm-policy",
            format!("a one-algorithm policy must validate, got {e}"),
        )
    })?;
    for case in &expect.cases {
        run_case(
            alg,
            w,
            &body,
            &policy,
            &base_public_key,
            &base_signature,
            case,
        )?;
    }

    Ok(VectorSummary {
        kind: KIND,
        description,
        items: expect.cases.len(),
    })
}

fn parse_alg(name: &str) -> Result<SigAlg, VectorError> {
    SigAlg::ALL
        .into_iter()
        .find(|alg| alg.to_string() == name)
        .ok_or_else(|| {
            check_err(
                "algorithm-registered",
                format!("`{name}` is not a registered signature algorithm"),
            )
        })
}

fn derive_public_key(alg: SigAlg, w: MasterSecretRef<'_>) -> Vec<u8> {
    match alg {
        SigAlg::Ed25519 => sig_ed25519::public_key(w).as_bytes().to_vec(),
        SigAlg::MlDsa65 => sig_mldsa::public_key(w).as_bytes().to_vec(),
    }
}

fn derive_signature(alg: SigAlg, w: MasterSecretRef<'_>, body: &[u8]) -> Vec<u8> {
    match alg {
        SigAlg::Ed25519 => sig_ed25519::sign(w, body).as_bytes().to_vec(),
        SigAlg::MlDsa65 => sig_mldsa::sign(w, body).as_bytes().to_vec(),
    }
}

fn compare_bytes(check: &'static str, actual: &[u8], expected: &[u8]) -> Result<(), VectorError> {
    if actual == expected {
        return Ok(());
    }
    Err(check_err(
        check,
        format!(
            "implementation produced {} bytes ({}…), vector pins {} bytes ({}…)",
            actual.len(),
            hex(&actual[..actual.len().min(8)]),
            expected.len(),
            hex(&expected[..expected.len().min(8)]),
        ),
    ))
}

/// Structural checks over the whole case list: unique ids, known and
/// applicable classes, required-class coverage, and expected codes that
/// really exist in the C4 taxonomy.
fn check_case_list(alg: SigAlg, cases: &[Case]) -> Result<(), VectorError> {
    if cases.is_empty() {
        return Err(check_err(
            "non-empty-suite",
            "a reject-vector suite with no cases proves nothing".to_owned(),
        ));
    }
    for (index, case) in cases.iter().enumerate() {
        if cases[..index].iter().any(|other| other.id == case.id) {
            return Err(check_err(
                "unique-case-ids",
                format!("case id `{}` appears twice", case.id),
            ));
        }
        if !CLASSES.contains(&case.class.as_str()) {
            return Err(check_err(
                "known-class",
                format!("case `{}`: unknown class `{}`", case.id, case.class),
            ));
        }
        if !applicable_classes(alg).contains(&case.class.as_str()) {
            return Err(check_err(
                "applicable-class",
                format!(
                    "case `{}`: class `{}` does not apply to {alg} (misfiled vector)",
                    case.id, case.class
                ),
            ));
        }
        if case.why.trim().is_empty() {
            return Err(check_err(
                "case-rationale",
                format!(
                    "case `{}`: `why` must state the rule being violated",
                    case.id
                ),
            ));
        }
        if case.expect == ACCEPT {
            if case.class != "accept" {
                return Err(check_err(
                    "accept-class",
                    format!(
                        "case `{}`: an accepting case must carry class `accept`",
                        case.id
                    ),
                ));
            }
        } else {
            if case.class == "accept" {
                return Err(check_err(
                    "accept-class",
                    format!("case `{}`: class `accept` must expect `{ACCEPT}`", case.id),
                ));
            }
            if !case.expect.starts_with("crypto-") {
                return Err(check_err(
                    "code-domain-prefix",
                    format!(
                        "case `{}`: expected code `{}` must carry C's `crypto-` prefix \
                         (docs/testing/error-code-contract.md §2)",
                        case.id, case.expect
                    ),
                ));
            }
            if !all_code_exemplars()
                .iter()
                .any(|exemplar| exemplar.code() == case.expect)
            {
                return Err(check_err(
                    "code-exists",
                    format!(
                        "case `{}`: `{}` is not a code any CryptoError variant emits",
                        case.id, case.expect
                    ),
                ));
            }
        }
    }
    for class in required_classes(alg) {
        if !cases.iter().any(|case| case.class == *class) {
            return Err(check_err(
                "class-coverage",
                format!("the {alg} suite has no `{class}` case (tasks/C.md C15)"),
            ));
        }
    }
    Ok(())
}

fn run_case(
    alg: SigAlg,
    w: MasterSecretRef<'_>,
    body: &[u8],
    policy: &SigPolicy,
    base_public_key: &[u8],
    base_signature: &[u8],
    case: &Case,
) -> Result<(), VectorError> {
    let public_key = build(
        alg,
        w,
        body,
        Role::PublicKey,
        &case.public_key,
        base_public_key,
        base_signature,
        &case.id,
    )?;
    let signature = build(
        alg,
        w,
        body,
        Role::Signature,
        &case.signature,
        base_public_key,
        base_signature,
        &case.id,
    )?;

    // Where the file also pins the expanded bytes, they must agree with the
    // recipe — the two representations can never drift apart.
    if let Some(pinned) = &case.public_key_hex {
        compare_bytes(
            "case-public-key-hex",
            &public_key,
            &decode_hex(KIND, "public_key_hex", pinned)?,
        )?;
    }
    if let Some(pinned) = &case.signature_hex {
        compare_bytes(
            "case-signature-hex",
            &signature,
            &decode_hex(KIND, "signature_hex", pinned)?,
        )?;
    }

    let outcome = sig_policy::verify_body(policy, &[(alg, public_key)], &[(alg, signature)], body);
    match (&outcome, case.expect.as_str()) {
        (Ok(_), ACCEPT) => Ok(()),
        (Ok(label), _) => Err(check_err(
            "case-verdict",
            format!(
                "case `{}`: the verifier ACCEPTED (label {label:?}) what must fail with `{}`",
                case.id, case.expect
            ),
        )),
        (Err(error), ACCEPT) => Err(check_err(
            "case-verdict",
            format!(
                "case `{}`: the positive control failed with `{}`",
                case.id,
                error.code()
            ),
        )),
        (Err(error), expected) => {
            if error.code() == expected {
                Ok(())
            } else {
                Err(check_err(
                    "case-verdict",
                    format!(
                        "case `{}`: expected `{expected}`, got `{}`",
                        case.id,
                        error.code()
                    ),
                ))
            }
        }
    }
}

/// Build one case's bytes: pick the source material, then apply the edits,
/// the truncation, and the append — in that order.
#[allow(clippy::too_many_arguments)]
fn build(
    alg: SigAlg,
    w: MasterSecretRef<'_>,
    body: &[u8],
    role: Role,
    source: &Source,
    base_public_key: &[u8],
    base_signature: &[u8],
    case_id: &str,
) -> Result<Vec<u8>, VectorError> {
    let where_ = |problem: String| {
        check_err(
            "case-source",
            format!("case `{case_id}`.{}: {problem}", role.as_str()),
        )
    };

    let mut bytes = match source.from.as_str() {
        "base" => match role {
            Role::PublicKey => base_public_key.to_vec(),
            Role::Signature => base_signature.to_vec(),
        },
        "alternate-signer" => {
            let alt = alternate_signer_secret();
            let alt_w = MasterSecretRef::from_bytes(&alt);
            match role {
                Role::PublicKey => derive_public_key(alg, alt_w),
                Role::Signature => derive_signature(alg, alt_w, body),
            }
        }
        "context" => {
            if role != Role::Signature {
                return Err(where_("`context` is a signature-only source".to_owned()));
            }
            let ctx = source
                .ctx
                .as_ref()
                .ok_or_else(|| where_("`context` requires a `ctx` field".to_owned()))?;
            sign_under_context(alg, w, body, ctx.as_bytes()).ok_or_else(|| {
                where_(format!(
                    "context is {} bytes, above the FIPS 204 limit of 255",
                    ctx.len()
                ))
            })?
        }
        "raw-body" => {
            if role != Role::Signature {
                return Err(where_("`raw-body` is a signature-only source".to_owned()));
            }
            if alg != SigAlg::Ed25519 {
                return Err(where_(
                    "`raw-body` applies to Ed25519 only: ML-DSA binds its context inside \
                     FIPS 204, so there is no prefix to omit"
                        .to_owned(),
                ));
            }
            sig_ed25519::test_signing::sign_raw_message(w, body)
                .as_bytes()
                .to_vec()
        }
        other => return Err(where_(format!("unknown source `{other}`"))),
    };

    if source.ctx.is_some() && source.from != "context" {
        return Err(where_(format!(
            "`ctx` is only meaningful for `from = \"context\"`, not `{}`",
            source.from
        )));
    }

    for edit in &source.edits {
        apply_edit(&mut bytes, edit).map_err(where_)?;
    }
    if let Some(len) = source.truncate_to {
        if len > bytes.len() {
            return Err(where_(format!(
                "truncate_to {len} exceeds the {} available bytes",
                bytes.len()
            )));
        }
        bytes.truncate(len);
    }
    if let Some(appended) = &source.append_hex {
        bytes.extend_from_slice(&decode_hex(KIND, "append_hex", appended)?);
    }
    Ok(bytes)
}

fn sign_under_context(
    alg: SigAlg,
    w: MasterSecretRef<'_>,
    body: &[u8],
    ctx: &[u8],
) -> Option<Vec<u8>> {
    match alg {
        SigAlg::Ed25519 => Some(
            sig_ed25519::test_signing::sign_with_context(w, ctx, body)
                .as_bytes()
                .to_vec(),
        ),
        SigAlg::MlDsa65 => sig_mldsa::test_signing::sign_with_context(w, body, ctx)
            .map(|sig| sig.as_bytes().to_vec()),
    }
}

/// Splice one edit into `bytes`. Out-of-range edits are a malformed vector,
/// never a panic.
fn apply_edit(bytes: &mut [u8], edit: &Edit) -> Result<(), String> {
    let patch: Vec<u8> = match (&edit.hex, &edit.fill, edit.repeat) {
        (Some(literal), None, None) => {
            decode_hex(KIND, "edits[].hex", literal).map_err(|e| e.to_string())?
        }
        (None, Some(fill), Some(repeat)) => {
            let byte = decode_hex(KIND, "edits[].fill", fill).map_err(|e| e.to_string())?;
            let [byte] = byte[..] else {
                return Err("`fill` must be exactly one byte of hex".to_owned());
            };
            vec![byte; repeat]
        }
        _ => {
            return Err(
                "an edit carries either `hex`, or `fill` together with `repeat`".to_owned(),
            );
        }
    };
    let end = edit
        .offset
        .checked_add(patch.len())
        .ok_or_else(|| "edit length overflows".to_owned())?;
    if end > bytes.len() {
        return Err(format!(
            "edit at offset {} spans {} bytes, past the {} available",
            edit.offset,
            patch.len(),
            bytes.len()
        ));
    }
    bytes[edit.offset..end].copy_from_slice(&patch);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The alternate signer really is a different signer, and it is derived
    /// from the documented test seed rather than being fresh secret material.
    #[test]
    fn alternate_signer_is_derived_and_distinct() {
        let alt = alternate_signer_secret();
        assert_ne!(alt, TEST_MASTER_SECRET_W);

        let mut expected = Sha256::new();
        expected.update(b"antseal C15 alternate signer");
        expected.update(TEST_MASTER_SECRET_W);
        let expected: [u8; 32] = expected.finalize().into();
        assert_eq!(alt, expected);

        let w = MasterSecretRef::from_bytes(&TEST_MASTER_SECRET_W);
        let alt_w = MasterSecretRef::from_bytes(&alt);
        assert_ne!(
            sig_ed25519::public_key(w).as_bytes(),
            sig_ed25519::public_key(alt_w).as_bytes()
        );
    }

    /// Every required class is a known class, and every required class is
    /// applicable — the three tables cannot drift apart.
    #[test]
    fn class_tables_are_consistent() {
        for alg in SigAlg::ALL {
            for class in required_classes(alg) {
                assert!(CLASSES.contains(class), "{class} missing from CLASSES");
                assert!(
                    applicable_classes(alg).contains(class),
                    "{class} required for {alg} but not applicable"
                );
            }
            for class in applicable_classes(alg) {
                assert!(CLASSES.contains(class), "{class} missing from CLASSES");
            }
        }
        // No duplicates in the master list.
        let mut sorted = CLASSES.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), CLASSES.len(), "CLASSES has duplicates");
    }

    fn edit(offset: usize, hex_bytes: &str) -> Edit {
        Edit {
            offset,
            hex: Some(hex_bytes.to_owned()),
            fill: None,
            repeat: None,
        }
    }

    #[test]
    fn edits_splice_and_reject_out_of_range() {
        let mut bytes = vec![0u8; 4];
        apply_edit(&mut bytes, &edit(1, "aabb")).expect("in range");
        assert_eq!(bytes, [0x00, 0xAA, 0xBB, 0x00]);

        let mut bytes = vec![0u8; 4];
        apply_edit(
            &mut bytes,
            &Edit {
                offset: 0,
                hex: None,
                fill: Some("ff".to_owned()),
                repeat: Some(3),
            },
        )
        .expect("in range");
        assert_eq!(bytes, [0xFF, 0xFF, 0xFF, 0x00]);

        let mut bytes = vec![0u8; 4];
        let err = apply_edit(&mut bytes, &edit(3, "aabb")).expect_err("past the end");
        assert!(err.contains("past the"), "{err}");

        let mut bytes = vec![0u8; 4];
        let err = apply_edit(
            &mut bytes,
            &Edit {
                offset: usize::MAX,
                hex: Some("aa".to_owned()),
                fill: None,
                repeat: None,
            },
        )
        .expect_err("overflow");
        assert!(err.contains("overflow"), "{err}");

        // Neither form, or a multi-byte `fill`, is malformed.
        let mut bytes = vec![0u8; 4];
        assert!(
            apply_edit(
                &mut bytes,
                &Edit {
                    offset: 0,
                    hex: None,
                    fill: None,
                    repeat: None,
                },
            )
            .is_err()
        );
        assert!(
            apply_edit(
                &mut bytes,
                &Edit {
                    offset: 0,
                    hex: None,
                    fill: Some("aabb".to_owned()),
                    repeat: Some(1),
                },
            )
            .is_err()
        );
    }
}
