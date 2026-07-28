//! C15 — the authoring side of the committed signature reject-vector suites.
//!
//! The suites themselves live at `testdata/vectors/v1/sig-reject/` and are
//! *executed* by the Q4 runner (`vector_runner.rs`, cross-OS + wasm lanes).
//! This file is their **generator**, committed beside its output per
//! `testdata/README.md` contribution rule 2 — and, per the same rule, it is
//! run to **verify**, never to silently regenerate:
//!
//! - [`sig_reject_committed_suites_match_the_generator`] rebuilds both
//!   documents and asserts the committed bytes are exactly what this code
//!   produces. A drifted fixture, a hand-edit, or a changed derivation all
//!   fail here.
//! - `sig_reject_regenerate_committed_suites` is `#[ignore]`d: regeneration
//!   is an explicit, opt-in act
//!   (`cargo test -p antseal-core --all-features -- --ignored sig_reject_regenerate`).
//!
//! Every mutation is derived from the *base* signature by an explicit byte
//! diff, so the recipe a vector file carries and the bytes it describes
//! cannot disagree by construction ([`source_from_diff`]).
//!
//! Test names deliberately avoid the reserved `vector_`/`corpus_` markers
//! (CONTRIBUTING.md): the cross-OS suite is the *runner*, not this
//! generator.

use std::fs;
use std::path::{Path, PathBuf};

use serde_json::{Value, json};

use antseal_core::crypto::material::MasterSecretRef;
use antseal_core::crypto::sig_ed25519::{
    self, PUBLIC_KEY_LEN as ED_PK_LEN, SIGNATURE_LEN as ED_SIG_LEN, point_encoding_is_canonical,
    scalar_is_canonical,
};
use antseal_core::crypto::sig_mldsa::{
    self, OFFSET_HINT_CUTS, OFFSET_HINT_INDICES, OFFSET_Z, OMEGA, PUBLIC_KEY_LEN as MLDSA_PK_LEN,
    SIGNATURE_LEN as MLDSA_SIG_LEN,
};
use antseal_core::test_util::TEST_MASTER_SECRET_W;
use antseal_core::test_util::vectors_sig_reject::alternate_signer_secret;

/// The committed suite directory.
const SUITE_DIR: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../testdata/vectors/v1/sig-reject"
);

/// The body both suites sign — the same fixture bytes C12/C13 pin their
/// round-trip answers over, so the base values here and there are the same
/// known answer viewed twice.
const BODY: &[u8] = b"antseal manifest body bytes (fixture)\n";

/// The frozen context, and the wrong one the reject vectors use.
const CTX: &[u8] = b"antseal-manifest-v1";
const WRONG_CTX: &str = "antseal-manifest-v2";

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

fn w() -> MasterSecretRef<'static> {
    MasterSecretRef::from_bytes(&TEST_MASTER_SECRET_W)
}

// ---------------------------------------------------------------------------
// RFC 8032 §5.1 constants, rebuilt from their definitions (not transcribed)
// ---------------------------------------------------------------------------

/// `L = 2^252 + 27742317777372353535851937790883648493`, little-endian.
fn order_l() -> [u8; 32] {
    const ADDEND: u128 = 27_742_317_777_372_353_535_851_937_790_883_648_493;
    let mut l = [0u8; 32];
    l[..16].copy_from_slice(&ADDEND.to_le_bytes());
    l[31] = 1 << 4; // bit 252
    l
}

/// `p = 2^255 − 19`, little-endian.
fn field_p() -> [u8; 32] {
    let mut p = [0xffu8; 32];
    p[0] = 0xed;
    p[31] = 0x7f;
    p
}

/// `y = 1` — the identity point, order 1.
fn y_one() -> [u8; 32] {
    let mut y = [0u8; 32];
    y[0] = 1;
    y
}

/// `y = p − 1` — the order-2 point.
fn y_p_minus_one() -> [u8; 32] {
    let mut y = field_p();
    y[0] = 0xec;
    y
}

/// Little-endian 32-byte addition without reduction (`s + L` fits for any
/// canonical `s`, which is exactly why the classic maul works).
fn add_le(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut carry = 0u16;
    for i in 0..32 {
        let v = u16::from(a[i]) + u16::from(b[i]) + carry;
        out[i] = (v & 0xff) as u8;
        carry = v >> 8;
    }
    assert_eq!(carry, 0, "s + L must fit in 32 bytes");
    out
}

fn add_one_le(a: &[u8; 32]) -> [u8; 32] {
    let mut one = [0u8; 32];
    one[0] = 1;
    add_le(a, &one)
}

fn sub_one_le(a: &[u8; 32]) -> [u8; 32] {
    let mut out = *a;
    for byte in &mut out {
        if *byte == 0 {
            *byte = 0xff;
        } else {
            *byte -= 1;
            break;
        }
    }
    out
}

// ---------------------------------------------------------------------------
// case model
// ---------------------------------------------------------------------------

struct CaseSpec {
    id: &'static str,
    class: &'static str,
    why: &'static str,
    public_key: Value,
    signature: Value,
    /// The bytes the recipe above must produce (used for the expanded-hex
    /// fields, and asserted by the executor when they are present).
    public_key_bytes: Vec<u8>,
    signature_bytes: Vec<u8>,
    expect: &'static str,
}

impl CaseSpec {
    fn to_json(&self, expand_hex: bool) -> Value {
        let mut value = json!({
            "id": self.id,
            "class": self.class,
            "why": self.why,
            "public_key": self.public_key,
            "signature": self.signature,
            "expect": self.expect,
        });
        if expand_hex {
            let object = value.as_object_mut().expect("case is an object");
            object.insert(
                "public_key_hex".to_owned(),
                json!(hex(&self.public_key_bytes)),
            );
            object.insert(
                "signature_hex".to_owned(),
                json!(hex(&self.signature_bytes)),
            );
        }
        value
    }
}

fn src_base() -> Value {
    json!({ "from": "base" })
}

fn src_context(ctx: &str) -> Value {
    json!({ "from": "context", "ctx": ctx })
}

fn src_raw_body() -> Value {
    json!({ "from": "raw-body" })
}

fn src_alternate() -> Value {
    json!({ "from": "alternate-signer" })
}

/// Derive the minimal `edits` recipe that turns `base` into `target`
/// (equal lengths). Because the recipe is *computed from* the bytes, the
/// two representations in a committed file can never drift apart.
fn source_from_diff(base: &[u8], target: &[u8]) -> Value {
    assert_eq!(base.len(), target.len(), "diff requires equal lengths");
    assert_ne!(base, target, "a mutation must actually mutate");
    let start = (0..base.len())
        .find(|&i| base[i] != target[i])
        .expect("bytes differ");
    let end = (0..base.len())
        .rev()
        .find(|&i| base[i] != target[i])
        .expect("bytes differ")
        + 1;
    json!({
        "from": "base",
        "edits": [ { "offset": start, "hex": hex(&target[start..end]) } ],
    })
}

/// A whole-buffer fill (kept compact rather than emitting a kilobyte of hex).
fn source_fill(len: usize, byte: u8) -> Value {
    json!({
        "from": "base",
        "edits": [ { "offset": 0, "fill": format!("{byte:02x}"), "repeat": len } ],
    })
}

fn source_truncate(len: usize) -> Value {
    json!({ "from": "base", "truncate_to": len })
}

fn source_append(byte: u8) -> Value {
    json!({ "from": "base", "append_hex": format!("{byte:02x}") })
}

// ---------------------------------------------------------------------------
// the Ed25519 suite
// ---------------------------------------------------------------------------

fn ed25519_document() -> Value {
    let pk = sig_ed25519::public_key(w()).into_bytes();
    let sig = sig_ed25519::sign(w(), BODY).into_bytes();
    let base_sig = sig.to_vec();
    let base_pk = pk.to_vec();

    let l = order_l();
    let p = field_p();
    let s: [u8; 32] = sig[32..].try_into().expect("64-byte signature splits");

    // Sanity on the constants before they become committed fixtures.
    assert!(scalar_is_canonical(&sub_one_le(&l)), "L−1 is canonical");
    assert!(!scalar_is_canonical(&l), "S == L is out of range");
    assert!(!scalar_is_canonical(&add_one_le(&l)), "S == L+1 is too");
    assert!(!point_encoding_is_canonical(&p), "y = p is non-canonical");

    let with_s = |value: [u8; 32]| {
        let mut bytes = sig;
        bytes[32..].copy_from_slice(&value);
        bytes.to_vec()
    };
    let with_r = |value: [u8; 32]| {
        let mut bytes = sig;
        bytes[..32].copy_from_slice(&value);
        bytes.to_vec()
    };

    let mut negative_zero = y_one();
    negative_zero[31] |= 0x80;
    let mut y_above_p = p;
    y_above_p[0] = 0xff;
    let mut off_curve = [0u8; 32];
    off_curve[0] = 2; // y = 2 has no square root on the curve

    // Small-order R is only attributable to R when S is in range; S = 0 is.
    let small_order_r = {
        let mut bytes = [0u8; ED_SIG_LEN];
        bytes[..32].copy_from_slice(&y_one());
        bytes.to_vec()
    };

    let alt = alternate_signer_secret();
    let alt_w = MasterSecretRef::from_bytes(&alt);
    let alt_sig = sig_ed25519::sign(alt_w, BODY).into_bytes().to_vec();
    let wrong_ctx_sig =
        sig_ed25519::test_signing::sign_with_context(w(), WRONG_CTX.as_bytes(), BODY)
            .into_bytes()
            .to_vec();
    let no_prefix_sig = sig_ed25519::test_signing::sign_raw_message(w(), BODY)
        .into_bytes()
        .to_vec();

    let non_canonical = "crypto-non-canonical-signature-ed25519";
    let invalid = "crypto-signature-invalid-ed25519";

    let mutated_sig = |target: Vec<u8>| source_from_diff(&base_sig, &target);
    let mutated_pk = |target: &[u8]| source_from_diff(&base_pk, target);

    let cases = vec![
        CaseSpec {
            id: "positive-control",
            class: "accept",
            why: "the untouched base signature over the frozen ctx must verify — without a \
                  passing control the whole suite could be green for the wrong reason",
            public_key: src_base(),
            signature: src_base(),
            public_key_bytes: base_pk.clone(),
            signature_bytes: base_sig.clone(),
            expect: "accept",
        },
        CaseSpec {
            id: "s-plus-l",
            class: "s-out-of-range",
            why: "S + L is the same scalar mod L, so a non-strict verifier accepts it: the \
                  classic Ed25519 malleability maul (RFC 8032 §5.1 requires 0 <= S < L)",
            public_key: src_base(),
            signature: mutated_sig(with_s(add_le(&s, &l))),
            public_key_bytes: base_pk.clone(),
            signature_bytes: with_s(add_le(&s, &l)),
            expect: non_canonical,
        },
        CaseSpec {
            id: "s-equals-l",
            class: "s-out-of-range",
            why: "the bound is strict: S == L is already out of range",
            public_key: src_base(),
            signature: mutated_sig(with_s(l)),
            public_key_bytes: base_pk.clone(),
            signature_bytes: with_s(l),
            expect: non_canonical,
        },
        CaseSpec {
            id: "s-equals-l-plus-one",
            class: "s-out-of-range",
            why: "one past the order, straddling L from above",
            public_key: src_base(),
            signature: mutated_sig(with_s(add_one_le(&l))),
            public_key_bytes: base_pk.clone(),
            signature_bytes: with_s(add_one_le(&l)),
            expect: non_canonical,
        },
        CaseSpec {
            id: "s-all-ones",
            class: "s-out-of-range",
            why: "the largest 32-byte scalar encoding, far above L",
            public_key: src_base(),
            signature: mutated_sig(with_s([0xff; 32])),
            public_key_bytes: base_pk.clone(),
            signature_bytes: with_s([0xff; 32]),
            expect: non_canonical,
        },
        CaseSpec {
            id: "s-equals-l-minus-one",
            class: "canonical-but-invalid",
            why: "L−1 IS a canonical scalar, so this must fail as `invalid`, not \
                  `non-canonical` — the pair that pins the bound at exactly L",
            public_key: src_base(),
            signature: mutated_sig(with_s(sub_one_le(&l))),
            public_key_bytes: base_pk.clone(),
            signature_bytes: with_s(sub_one_le(&l)),
            expect: invalid,
        },
        CaseSpec {
            id: "small-order-r-identity",
            class: "small-order-point",
            why: "R = the identity point (order 1) with S = 0 — the classic malleability \
                  handle RFC 8032 strict verification rejects",
            public_key: src_base(),
            signature: mutated_sig(small_order_r.clone()),
            public_key_bytes: base_pk.clone(),
            signature_bytes: small_order_r,
            expect: non_canonical,
        },
        CaseSpec {
            id: "small-order-a-identity",
            class: "small-order-point",
            why: "a small-order public key verifies almost every message; both dalek's \
                  verify_strict and C12's pre-validation layer reject it",
            public_key: mutated_pk(&y_one()),
            signature: src_base(),
            public_key_bytes: y_one().to_vec(),
            signature_bytes: base_sig.clone(),
            expect: non_canonical,
        },
        CaseSpec {
            id: "small-order-a-order-two",
            class: "small-order-point",
            why: "y = p−1 is the order-2 point — small-order too",
            public_key: mutated_pk(&y_p_minus_one()),
            signature: src_base(),
            public_key_bytes: y_p_minus_one().to_vec(),
            signature_bytes: base_sig.clone(),
            expect: non_canonical,
        },
        CaseSpec {
            id: "non-canonical-a-y-equals-p",
            class: "non-canonical-point",
            why: "y = p (= 0 mod p) is a non-canonical encoding that the pinned dalek ACCEPTS \
                  under ZIP-215 (curve25519-dalek#626) — the D16 conformance gap C12's \
                  pre-validation layer closes, pinned here so a pin bump cannot silently \
                  reopen it",
            public_key: mutated_pk(&p),
            signature: src_base(),
            public_key_bytes: p.to_vec(),
            signature_bytes: base_sig.clone(),
            expect: non_canonical,
        },
        CaseSpec {
            id: "non-canonical-a-negative-zero",
            class: "non-canonical-point",
            why: "the sign bit set on a point with x = 0 — recompression would emit sign 0, \
                  so the encoding is not canonical",
            public_key: mutated_pk(&negative_zero),
            signature: src_base(),
            public_key_bytes: negative_zero.to_vec(),
            signature_bytes: base_sig.clone(),
            expect: non_canonical,
        },
        CaseSpec {
            id: "non-canonical-r-y-above-p",
            class: "non-canonical-point",
            why: "the same rule applied to R: y > p is not a reduced field element",
            public_key: src_base(),
            signature: mutated_sig(with_r(y_above_p)),
            public_key_bytes: base_pk.clone(),
            signature_bytes: with_r(y_above_p),
            expect: non_canonical,
        },
        CaseSpec {
            id: "off-curve-a",
            class: "non-canonical-point",
            why: "y = 2 is canonically encoded but has no square root on the curve — an \
                  encoding fault, not a wrong signature",
            public_key: mutated_pk(&off_curve),
            signature: src_base(),
            public_key_bytes: off_curve.to_vec(),
            signature_bytes: base_sig.clone(),
            expect: non_canonical,
        },
        CaseSpec {
            id: "wrong-key",
            class: "wrong-key",
            why: "an impeccably encoded signature by the alternate signer, checked against \
                  the base public key",
            public_key: src_base(),
            signature: src_alternate(),
            public_key_bytes: base_pk.clone(),
            signature_bytes: alt_sig.clone(),
            expect: invalid,
        },
        CaseSpec {
            id: "wrong-context",
            class: "wrong-context",
            why: "signed over `antseal-manifest-v2 || 0x00 || body`: a signature can never be \
                  lifted between contexts (MVP-SPEC.md line 97)",
            public_key: src_base(),
            signature: src_context(WRONG_CTX),
            public_key_bytes: base_pk.clone(),
            signature_bytes: wrong_ctx_sig.clone(),
            expect: invalid,
        },
        CaseSpec {
            id: "no-context-prefix",
            class: "wrong-context",
            why: "signed over the bare body, with no `ctx || 0x00` prefix at all — the \
                  cross-protocol lift the prefix construction exists to stop",
            public_key: src_base(),
            signature: src_raw_body(),
            public_key_bytes: base_pk.clone(),
            signature_bytes: no_prefix_sig.clone(),
            expect: invalid,
        },
        CaseSpec {
            id: "signature-truncated",
            class: "wrong-length",
            why: "63 bytes is not a canonical encoding of anything (defense in depth behind \
                  F's exact-length bstr rule)",
            public_key: src_base(),
            signature: source_truncate(ED_SIG_LEN - 1),
            public_key_bytes: base_pk.clone(),
            signature_bytes: base_sig[..ED_SIG_LEN - 1].to_vec(),
            expect: non_canonical,
        },
        CaseSpec {
            id: "signature-over-length",
            class: "wrong-length",
            why: "65 bytes: an appended byte must not be ignored",
            public_key: src_base(),
            signature: source_append(0x00),
            public_key_bytes: base_pk.clone(),
            signature_bytes: {
                let mut bytes = base_sig.clone();
                bytes.push(0x00);
                bytes
            },
            expect: non_canonical,
        },
        CaseSpec {
            id: "public-key-truncated",
            class: "wrong-length",
            why: "31-byte public key — the length check fires before any curve arithmetic",
            public_key: source_truncate(ED_PK_LEN - 1),
            signature: src_base(),
            public_key_bytes: base_pk[..ED_PK_LEN - 1].to_vec(),
            signature_bytes: base_sig.clone(),
            expect: non_canonical,
        },
        CaseSpec {
            id: "all-zero-signature",
            class: "degenerate",
            why: "R = the y = 0 point (order 4) with S = 0: adversarial input must reject \
                  cleanly, never panic",
            public_key: src_base(),
            signature: source_fill(ED_SIG_LEN, 0x00),
            public_key_bytes: base_pk.clone(),
            signature_bytes: vec![0u8; ED_SIG_LEN],
            expect: non_canonical,
        },
        CaseSpec {
            id: "all-ones-signature",
            class: "degenerate",
            why: "y >= p in R and S >= L at once",
            public_key: src_base(),
            signature: source_fill(ED_SIG_LEN, 0xff),
            public_key_bytes: base_pk.clone(),
            signature_bytes: vec![0xffu8; ED_SIG_LEN],
            expect: non_canonical,
        },
    ];

    document(
        "ed25519",
        "Ed25519 strict-verification reject vectors (RFC 8032 verify_strict plus C12's D16 \
         pre-validation layer): S >= L straddling the order, small-order and non-canonical \
         R/A encodings, wrong key, wrong context, wrong lengths — each routed through C14's \
         full verification path.",
        &base_pk,
        &base_sig,
        &cases,
        true,
    )
}

// ---------------------------------------------------------------------------
// the ML-DSA-65 suite
// ---------------------------------------------------------------------------

fn ml_dsa_document() -> Value {
    let base_pk = sig_mldsa::public_key(w()).into_bytes().to_vec();
    let sig = sig_mldsa::sign(w(), BODY).into_bytes();
    let base_sig = sig.to_vec();

    // Hint-region mutations, each a line-by-line violation of FIPS 204
    // Algorithm 21 (hintBitUnpack) as transcribed in the C11 probe report §2.3.
    let duplicate_hints = {
        let mut bytes = sig;
        bytes[OFFSET_HINT_INDICES..].fill(0);
        bytes[OFFSET_HINT_INDICES] = 5;
        bytes[OFFSET_HINT_INDICES + 1] = 5;
        bytes[OFFSET_HINT_CUTS..].fill(2);
        bytes.to_vec()
    };
    let hints_above_omega = {
        let mut bytes = sig;
        bytes[OFFSET_HINT_INDICES..].fill(0);
        bytes[OFFSET_HINT_CUTS..].fill(u8::try_from(OMEGA + 1).expect("56 fits in u8"));
        bytes.to_vec()
    };
    let nonzero_hint_padding = {
        let mut bytes = sig;
        bytes[OFFSET_HINT_INDICES..].fill(0);
        bytes[OFFSET_HINT_INDICES] = 9;
        bytes.to_vec()
    };
    let decreasing_cuts = {
        let mut bytes = sig;
        bytes[OFFSET_HINT_INDICES..].fill(0);
        bytes[OFFSET_HINT_CUTS..].copy_from_slice(&[2u8, 1, 2, 2, 2, 2]);
        bytes.to_vec()
    };
    // The 20-bit z field value 0 decodes to the range endpoint gamma1, so
    // ||z||inf >= gamma1 - beta and Algorithm 27 rejects eagerly at decode.
    let z_out_of_range = {
        let mut bytes = sig;
        bytes[OFFSET_Z] = 0;
        bytes[OFFSET_Z + 1] = 0;
        bytes[OFFSET_Z + 2] &= 0xf0;
        bytes.to_vec()
    };
    // c_tilde is 48 opaque hash bytes: every value decodes, so a flip here
    // survives to the verification step and fails there instead.
    let c_tilde_flip = {
        let mut bytes = sig;
        bytes[0] ^= 0x01;
        bytes.to_vec()
    };

    let alt = alternate_signer_secret();
    let alt_w = MasterSecretRef::from_bytes(&alt);
    let alt_sig = sig_mldsa::sign(alt_w, BODY).into_bytes().to_vec();
    let wrong_ctx_sig = sig_mldsa::test_signing::sign_with_context(w(), BODY, WRONG_CTX.as_bytes())
        .expect("19-byte ctx is well under the FIPS 204 limit")
        .into_bytes()
        .to_vec();
    let empty_ctx_sig = sig_mldsa::test_signing::sign_with_context(w(), BODY, b"")
        .expect("the empty ctx is signable")
        .into_bytes()
        .to_vec();

    let non_canonical = "crypto-non-canonical-signature-ml-dsa-65";
    let invalid = "crypto-signature-invalid-ml-dsa-65";
    let mutated_sig = |target: &[u8]| source_from_diff(&base_sig, target);

    let cases = vec![
        CaseSpec {
            id: "positive-control",
            class: "accept",
            why: "the untouched deterministic (rnd = 0^32, decision D15) signature over the \
                  frozen FIPS 204 ctx must verify",
            public_key: src_base(),
            signature: src_base(),
            public_key_bytes: base_pk.clone(),
            signature_bytes: base_sig.clone(),
            expect: "accept",
        },
        CaseSpec {
            id: "duplicate-hint-indices",
            class: "hint-rule",
            why: "two equal indices inside one polynomial segment violate the strict `<` \
                  ordering of FIPS 204 Algorithm 21 step 9 — the exact rule whose `<=` \
                  regression was CVE-2026-24850",
            public_key: src_base(),
            signature: mutated_sig(&duplicate_hints),
            public_key_bytes: base_pk.clone(),
            signature_bytes: duplicate_hints.clone(),
            expect: non_canonical,
        },
        CaseSpec {
            id: "hint-count-above-omega",
            class: "hint-rule",
            why: "a cumulative cut of 56 exceeds omega = 55 for ML-DSA-65 (Algorithm 21 \
                  step 4; FIPS 204 Table 2)",
            public_key: src_base(),
            signature: mutated_sig(&hints_above_omega),
            public_key_bytes: base_pk.clone(),
            signature_bytes: hints_above_omega.clone(),
            expect: non_canonical,
        },
        CaseSpec {
            id: "nonzero-hint-padding",
            class: "hint-rule",
            why: "a nonzero index byte past the last cut violates the zero-padding rule \
                  (Algorithm 21 steps 16-18) — otherwise a signature would have spare bits \
                  to carry a second encoding",
            public_key: src_base(),
            signature: mutated_sig(&nonzero_hint_padding),
            public_key_bytes: base_pk.clone(),
            signature_bytes: nonzero_hint_padding.clone(),
            expect: non_canonical,
        },
        CaseSpec {
            id: "decreasing-hint-cuts",
            class: "hint-rule",
            why: "cumulative cuts must be non-decreasing (Algorithm 21 step 4)",
            public_key: src_base(),
            signature: mutated_sig(&decreasing_cuts),
            public_key_bytes: base_pk.clone(),
            signature_bytes: decreasing_cuts.clone(),
            expect: non_canonical,
        },
        CaseSpec {
            id: "z-out-of-range",
            class: "z-out-of-range",
            why: "the first z coefficient forced to gamma1, so ||z||inf >= gamma1 - beta; the \
                  pinned crate checks this norm bound eagerly at decode rather than in \
                  Verify step 13",
            public_key: src_base(),
            signature: mutated_sig(&z_out_of_range),
            public_key_bytes: base_pk.clone(),
            signature_bytes: z_out_of_range.clone(),
            expect: non_canonical,
        },
        CaseSpec {
            id: "c-tilde-bit-flip",
            class: "bit-flip",
            why: "c_tilde is 48 opaque hash bytes — every value is a legal encoding, so this \
                  mutation DECODES and fails only at verification: the layering the two \
                  distinct verdicts rest on",
            public_key: src_base(),
            signature: mutated_sig(&c_tilde_flip),
            public_key_bytes: base_pk.clone(),
            signature_bytes: c_tilde_flip.clone(),
            expect: invalid,
        },
        CaseSpec {
            id: "wrong-key",
            class: "wrong-key",
            why: "a well-formed signature by the alternate signer, checked against the base \
                  public key",
            public_key: src_base(),
            signature: src_alternate(),
            public_key_bytes: base_pk.clone(),
            signature_bytes: alt_sig.clone(),
            expect: invalid,
        },
        CaseSpec {
            id: "wrong-context",
            class: "wrong-context",
            why: "signed with the FIPS 204 ctx `antseal-manifest-v2`; the standard absorbs \
                  `0x00 || len(ctx) || ctx` before the message, so the context is part of \
                  what is signed",
            public_key: src_base(),
            signature: src_context(WRONG_CTX),
            public_key_bytes: base_pk.clone(),
            signature_bytes: wrong_ctx_sig.clone(),
            expect: invalid,
        },
        CaseSpec {
            id: "empty-context",
            class: "wrong-context",
            why: "the empty ctx is what the crate's `Signer`/`Verifier` trait impls silently \
                  use (C11 report §2.2) — this vector is the standing guard that antseal \
                  never takes that path",
            public_key: src_base(),
            signature: src_context(""),
            public_key_bytes: base_pk.clone(),
            signature_bytes: empty_ctx_sig.clone(),
            expect: invalid,
        },
        CaseSpec {
            id: "signature-truncated",
            class: "wrong-length",
            why: "3308 bytes: the exact-size conversion rejects before any decoding",
            public_key: src_base(),
            signature: source_truncate(MLDSA_SIG_LEN - 1),
            public_key_bytes: base_pk.clone(),
            signature_bytes: base_sig[..MLDSA_SIG_LEN - 1].to_vec(),
            expect: non_canonical,
        },
        CaseSpec {
            id: "signature-over-length",
            class: "wrong-length",
            why: "3310 bytes: a trailing byte must not be ignored",
            public_key: src_base(),
            signature: source_append(0x00),
            public_key_bytes: base_pk.clone(),
            signature_bytes: {
                let mut bytes = base_sig.clone();
                bytes.push(0x00);
                bytes
            },
            expect: non_canonical,
        },
        CaseSpec {
            id: "public-key-truncated",
            class: "wrong-length",
            why: "1951-byte public key — length-checked before decode",
            public_key: source_truncate(MLDSA_PK_LEN - 1),
            signature: src_base(),
            public_key_bytes: base_pk[..MLDSA_PK_LEN - 1].to_vec(),
            signature_bytes: base_sig.clone(),
            expect: non_canonical,
        },
        CaseSpec {
            id: "all-ones-signature",
            class: "degenerate",
            why: "every hint rule violated at once; adversarial input must reject cleanly, \
                  never panic",
            public_key: src_base(),
            signature: source_fill(MLDSA_SIG_LEN, 0xff),
            public_key_bytes: base_pk.clone(),
            signature_bytes: vec![0xffu8; MLDSA_SIG_LEN],
            expect: non_canonical,
        },
        CaseSpec {
            id: "all-zero-signature",
            class: "degenerate",
            why: "all-zero z fields decode to the range endpoint gamma1, so the norm bound \
                  rejects this at decode",
            public_key: src_base(),
            signature: source_fill(MLDSA_SIG_LEN, 0x00),
            public_key_bytes: base_pk.clone(),
            signature_bytes: vec![0u8; MLDSA_SIG_LEN],
            expect: non_canonical,
        },
    ];

    document(
        "ml-dsa-65",
        "ML-DSA-65 canonical-encoding reject vectors (FIPS 204 Algorithm 27 sigDecode as \
         enforced by the pinned ml-dsa 0.1.1): hint count/order/padding rules, the z norm \
         bound, wrong lengths, a decodable bit flip, wrong key and wrong ctx — each routed \
         through C14's full verification path.",
        &base_pk,
        &base_sig,
        &cases,
        false,
    )
}

// ---------------------------------------------------------------------------
// document assembly + the verify/regenerate pair
// ---------------------------------------------------------------------------

fn document(
    alg: &str,
    description: &str,
    base_pk: &[u8],
    base_sig: &[u8],
    cases: &[CaseSpec],
    expand_hex: bool,
) -> Value {
    json!({
        "schema": "antseal-golden-vector",
        "schema_version": 1,
        "format_version": "v1",
        "kind": "sig-reject",
        "non_secret": "NON-SECRET — every key here derives from the documented fixed test \
                       seed W = 00 01 .. 1f (testdata/README.md); the `wrong-key` cases use \
                       the alternate signer SHA-256(\"antseal C15 alternate signer\" || W). \
                       No real vault or wallet material.",
        "description": description,
        "inputs": {
            "w": hex(&TEST_MASTER_SECRET_W),
            "alg": alg,
            "ctx": String::from_utf8(CTX.to_vec()).expect("the frozen ctx is ASCII"),
            "body": hex(BODY),
        },
        "expect": {
            "base": { "public_key": hex(base_pk), "signature": hex(base_sig) },
            "cases": cases.iter().map(|case| case.to_json(expand_hex)).collect::<Vec<_>>(),
        },
    })
}

fn suites() -> Vec<(PathBuf, Value)> {
    vec![
        (
            Path::new(SUITE_DIR).join("ed25519.json"),
            ed25519_document(),
        ),
        (
            Path::new(SUITE_DIR).join("ml-dsa-65.json"),
            ml_dsa_document(),
        ),
    ]
}

/// Serialize exactly as the committed files are written: pretty-printed with
/// a trailing newline. `serde_json::Value` maps are `BTreeMap`s, so key
/// order — and therefore the bytes — are deterministic.
fn serialize(document: &Value) -> String {
    let mut text = serde_json::to_string_pretty(document).expect("documents serialize");
    text.push('\n');
    text
}

/// **The verify-only run** (`testdata/README.md` rule 2): the committed
/// suites must be byte-identical to what this generator produces. Any drift
/// — a hand-edited fixture, a changed derivation, a different signing mode —
/// fails here rather than silently regenerating.
#[test]
fn sig_reject_committed_suites_match_the_generator() {
    for (path, document) in suites() {
        let committed = fs::read_to_string(&path).unwrap_or_else(|e| {
            panic!(
                "{}: cannot read the committed suite ({e}); regenerate with \
                 `cargo test -p antseal-core --all-features -- --ignored sig_reject_regenerate`",
                path.display()
            )
        });
        assert_eq!(
            committed,
            serialize(&document),
            "{} has drifted from its generator",
            path.display()
        );
    }
}

/// Opt-in regeneration. Never runs in CI (`#[ignore]`); the committed files
/// are evidence, and rewriting them is a deliberate act.
#[test]
#[ignore = "regeneration is an explicit act: committed vectors are evidence"]
fn sig_reject_regenerate_committed_suites() {
    fs::create_dir_all(SUITE_DIR).expect("suite directory");
    for (path, document) in suites() {
        fs::write(&path, serialize(&document)).expect("write suite");
        println!("wrote {}", path.display());
    }
}
