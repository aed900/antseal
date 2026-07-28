# The independent cross-check — vehicle register and freeze report

MVP-SPEC.md line 5 mandates an independent cross-check before the M0 freeze.
This document is the evidence: which second implementation checks each
surface, how independent it actually is, and what it found.

**Q14's gate is that the discrepancy count below is zero.**

Two artifacts exist and they are not redundant, which is worth stating because
a later reader will be tempted to delete one (D31 §6):

- **This document** is the evidence *for* the freeze — dated, citable, naming
  vehicle versions and counts at a specific commit. It is never rewritten; a
  later run appends a new dated section.
- **The `cross-check` CI lane** is the guard *after* it. It answers "has
  anything drifted since", which a one-shot cannot. Its specific job is to
  catch a future regeneration of a committed vector from the Rust side —
  precisely the move that would make the vectors agree with the code while
  both drift from the spec.

F14's `docs/testing/cbor-cross-check.md` is the CBOR surface's detailed
contract. This document is the register across **all** surfaces.

## 1. What "independent" means here

Decision D31 §1 refuses to treat independence as one property, because "the
same code" hides three distinct failure modes and a vehicle that closes one
may close none of the others:

| tier | what it is | catches a shared misreading of the spec? |
| --- | --- | --- |
| **T0** | an **external oracle** — expected values originating outside this project *and* outside its language ecosystem: NIST ACVP, RFC known-answer tests, Unicode's own conformance data | **yes** — the only tier that does |
| **T1** | an **independent re-implementation**, written from the specification in another language, sharing no code | no — unless anchored by a T0 known-answer test |
| **T2** | **two implementations inside one ecosystem** (two Rust crates) | no, and it misses shared ecosystem idioms too |

Two consequences run through everything below:

1. **A T1 vehicle without a T0 anchor is half a check.** Where no T0 anchor
   can exist — because the construction is *ours* — T1 is the honest ceiling
   and is stated as such rather than dressed up.
2. **`ml-dsa` ↔ `fips204` is T2 and is not independence.** It is retained as
   D14's fallback-equivalence evidence and never counted here.

## 2. The vehicle register

| # | Surface | Vehicle | Version | Tier | T0 anchor | Where |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | Canonical CBOR encode (RFC 8949 §4.2.1) | **our own Python encoder written from the RFC** | in-repo | T1 | **RFC 8949 Appendix A**, 33 examples both directions | `testdata/vectors/v1/crosscheck_cbor.py` |
| 2 | CBOR decode + structural equality vs the in-file diagnostic sidecar | Python `cbor2`, **decode only** | `6.1.3` | T1 | RFC 8949 Appendix A | same |
| 3 | Rejection fixtures are genuinely non-canonical | our own §4.2.1 checks | in-repo | T1 | RFC 8949 §4.2.1 | same |
| 4 | HKDF-SHA256 + the length-prefixed info encoding | `reference.py::hkdf_sha256`, raw `hmac`/`hashlib` | CPython stdlib | T1 | **RFC 5869 A.1, A.2, A.3** | `testdata/vectors/v1/crypto/reference.py` |
| 5 | Domain-tagged salted commitments | `reference.py::tagged_sha256` | stdlib | T1 | **none possible — the construction is ours** | same |
| 6 | Unit padding (`padded_length`, zero-fill) | `reference.py::padded_length` / `apply_padding` | stdlib | T1 | **none possible — ours** | same |
| 7 | XChaCha20-Poly1305 AEAD | `reference.py`, from-scratch RFC 8439 + draft-irtf-cfrg-xchacha | stdlib | T1 | **RFC 8439 §2.3.2/§2.5.2/§2.8.2, cfrg-xchacha §2.2.1/A.3.1**; libsodium agreement when installed | same |
| 8 | Ed25519 keygen/sign, incl. `ctx ‖ 0x00 ‖ body` | `reference.py`, RFC 8032 §6 reference formulation | stdlib | T1 | **RFC 8032 §7.1, all five cases**; OpenSSL + libsodium when installed | same |
| 9 | GGM salt tree, `fine_root`, RFC 6962 Merkle, leaf-exact cover, boundary paths | `fine-tree/gen_vectors.py`, stdlib, MSB-first from spec lines 78/79/96 | stdlib | T1 | RFC 6962 §2.1 promotion rule only — **the GGM tree is ours** | `testdata/vectors/v1/fine-tree/gen_vectors.py` |
| 10 | Canonicalization v1 (BOM / EOL / NFC pipeline) | `gen_corpus.py`, stdlib `unicodedata` | CPython stdlib | T1 | **Unicode 17.0.0 `NormalizationTest.txt`**, 1 537 lines | `testdata/utf8-corpus/gen_corpus.py`, `testdata/unicode/` |
| 11 | `work_id` / `anchor_digest` | SHA-256 over the exact received bytes, by the row-1 checker | stdlib | T1 | FIPS 180-4 via `hashlib` | `crosscheck_cbor.py` |
| 12 | **ML-DSA-65 keyGen / sigGen / sigVer** | **NIST ACVP**, replayed against `ml-dsa` | ACVP `2972def`, `ml-dsa =0.1.1` | **T0** | *is* the oracle | `testdata/acvp/`, `crates/antseal-core/tests/acvp_ml_dsa.rs` |
| 13 | ML-DSA-65 `ctx` absorption (`M′ = 0x00 ‖ len(ctx) ‖ ctx ‖ M`) | **NIST ACVP external-interface groups** | same | **T0** | *is* the oracle | same |
| 14 | `fips204` byte-identity (D14's fallback claim) | `fips204` | `=0.4.6` | **T2 — excluded from the independence claim** | n/a | `crates/antseal-core/tests/mldsa_fallback_equivalence.rs` |

**Rows 1–13 are all present at T0 or T1. Row 14 is T2 and does not count.**

### Surfaces at T1 with no T0 anchor, named plainly

Rows **5** (domain-tagged salted commitments), **6** (unit padding) and **9**
(the GGM salt tree — its Merkle promotion rule is RFC 6962, but the tree
itself is not) have no external oracle **because the constructions are
antseal's own**. No published test vectors exist for them and none can. T1 —
a stdlib Python re-implementation written from the spec, sharing no code with
the Rust — is the honest ceiling, and it is what they have.

This is a real limit on what this report proves for those three rows: a
misreading of MVP-SPEC.md shared between the Rust and the Python would survive
it. The mitigations are elsewhere and are not cross-checks: the spec text
itself, the tamper matrix, and review.

## 3. Freeze report — 2026-07-28

Commit `788519b` (the Q11 landing). Ran on CPython 3.11.2, `unidata_version`
14.0.0, Linux x86-64.

| # | Surface | What ran | Count | Discrepancies |
| --- | --- | --- | --- | --- |
| — | reference.py known answers (T0, runs first) | published KAT assertions | **20** | **0** |
| — | third-party corroboration (optional) | libsodium, OpenSSL | 4 | 0 |
| 4 | HKDF label registry | committed vectors re-derived | 8 | **0** |
| 5 | Salted commitments | committed vectors re-derived | 12 | **0** |
| 6, 7 | Unit AEAD + padding | committed vectors re-derived | 9 | **0** |
| 7 | Manifest AEAD | committed vectors re-derived | 3 (+ `k_m`) | **0** |
| 8 | Ed25519 signatures | committed vector re-derived | 1 | **0** |
| 9 | GGM / fine-tree | committed cases re-derived | 4 | **0** |
| 10 | Canonicalization corpus | input/expected fixture pairs | 37 | **0** |
| 10 | Unicode NFC conformance (T0) | `NormalizationTest.txt` lines executed | **1 537** (70 skipped as unassigned in Unicode 14.0.0) | **0** |
| 1, 2 | RFC 8949 Appendix A (T0) | worked examples, both directions | 33 | **0** |
| 1, 2, 11 | CBOR encode/decode/`work_id`/`anchor_digest` | checks over 14 cases in 2 CBOR-committing vectors of 11 committed v1 vector files | **225** | **0** |
| 3 | Rejection fixtures genuinely non-canonical | `testdata/tamper/format/` fixtures | 13 non-canonical + 5 canonical-but-schema-invalid (2 out of scope) | **0** |
| 12 | ML-DSA-65 keyGen (T0) | NIST ACVP cases | 25 | **0** |
| 12 | ML-DSA-65 sigGen, internal interface (T0) | NIST ACVP cases | 30 | **0** |
| 13 | ML-DSA-65 sigGen, external interface + `ctx` (T0) | NIST ACVP cases | 30 | **0** |
| 12 | ML-DSA-65 sigVer, internal (T0) | NIST ACVP cases, incl. negatives | 15 | **0** |
| 13 | ML-DSA-65 sigVer, external + `ctx` (T0) | NIST ACVP cases, incl. negatives | 15 | **0** |
| 14 | `ml-dsa` ↔ `fips204` (**T2 — not independence**) | keygen + deterministic sign byte-identity, 3 seeds × 3 bodies, cross-verified both ways | 3 + 9 | **0** |

### Total discrepancies: 0

**No surface was skipped.** Every row 1–13 ran; the counts above are what
executed, not what was available.

### Vehicle versions

| vehicle | version | provenance |
| --- | --- | --- |
| CPython | 3.11.2, `unidata_version` 14.0.0 | dev machine; CI pins 3.12 |
| `cbor2` | **6.1.3**, hash-pinned | `requirements-crosscheck.txt`, `--require-hashes` |
| NIST ACVP | `usnistgov/ACVP-Server` **`2972def23bf9f3680c2c531561ed9bdd0f1086ad`** (v1.1.0.43, 2026-07-20) | `testdata/acvp/PROVENANCE.md` |
| Unicode conformance data | **17.0.0**, upstream SHA-256 `5019ffd5…38a87db` | `testdata/unicode/PROVENANCE.md` |
| `ml-dsa` (system under test) | `=0.1.1` | workspace pin |
| `fips204` (T2 only) | `=0.4.6` | workspace pin, dev-dependency since 2026-07-28 |

### Proven able to fail

A suite never observed failing proves nothing (D31 §11 item 6). Every surface
is proven able to go red, and the proof is a **standing part of the lane**
(`./scripts/cross-check.sh --self-test`), not a one-off note here. It stages a
copy of `testdata/` in a temp directory, plants a fault per surface, and
requires red-then-green:

| surface | planted fault | result |
| --- | --- | --- |
| `reference.py` known answers | RFC 5869 expand loop counter `1` → `2` | red, then green |
| `crypto/gen_vectors.py` | one hex digit flipped in `commitments.json` | red, then green |
| `fine-tree/gen_vectors.py` | one hex digit flipped in `fine-tree.json` | red, then green |
| `hkdf/gen_vectors.py` | one hex digit flipped in `hkdf-labels.json` | red, then green |
| `gen_corpus.py` corpus goldens | one bit flipped in `expected/lone-cr` | red, then green |
| `gen_corpus.py` Unicode anchor | one NFC expectation corrupted in the sample | red, then green |
| `crosscheck_cbor.py` | its own 8 planted faults + 1 control | red ×8, green ×1 |
| ACVP sigVer (Rust) | NIST's own 24 negative cases, standing permanently in the suite | must be refused |

The truncation guard was exercised separately: cutting the
`NormalizationTest` sample makes the anchor report 42 executed lines against
its 1 200 floor and exit non-zero, so a stale interpreter or a truncated
fixture cannot produce a vacuous pass.

## 4. Findings

Three, all recorded rather than quietly fixed.

### 4a. The existing T0 anchors were already real (good news)

D31 §11 item 2 asked whether `reference.py::selftest`'s RFC 5869 and RFC 8032
known answers actually existed or were aspirational, noting that if they had
to be added, **every C16 agreement predating this was T1-unanchored**. They
existed and passed: RFC 5869 A.1 + A.3 and RFC 8032 §7.1 TEST 2 landed with
C16. **No C16 agreement was ever unanchored.**

Q11 widened them from sampled to complete anyway — RFC 5869 A.2 (the only case
reaching a third HMAC block) and all five RFC 8032 §7.1 cases (TEST 1's empty
message and TEST 1024's 1023-byte message bracket the SHA-512 block boundary
that TEST 2's single byte cannot). 11 known-answer checks became 20. All
passed on the first run, which is itself evidence the reference was right.

### 4b. D31's Unicode version assertion was not satisfiable

D31 §3 required `assert unicodedata.unidata_version == '17.0.0'`, and §11 item
3 said to **stop** if the observed value differed, as a format-relevant
finding for G. The observed value is 14.0.0 — but the finding is not the one
D31 anticipated.

**No released CPython embeds Unicode 17.0.0.** 3.11 has 14.0.0, 3.12 has
15.0.0, 3.13 has 15.1.0, 3.14 has 16.0.0. D31 §6b pins the cross-check job to
Python 3.12. The assertion would have made the new lane permanently red on the
very runner D31 specifies for it.

It would also have discarded a better argument already in `gen_corpus.py`:
every NFC-sensitive fixture uses only characters assigned in Unicode ≤ 6.0
(`NFC_SAFE_FLOOR`), and the Unicode Normalization Stability Policy forbids
adding a canonical decomposition to an already-assigned character or changing
a combining class. G3 got this right.

**No format-relevant finding for G exists.** D25's pin is not compromised;
what D31 §3 diagnosed as an unverified claim was in fact a verified one
carrying a different, sound justification. What D31 was reaching for — an
actual external check of the NFC leg — was built instead: the
`NormalizationTest.txt` replay in row 10.

### 4c. D31's ACVP filter contradicted itself

D31 §4c Branch A says to filter `preHash == "pure"` while "keeping both
`signatureInterface` values". The acquisition probe shows internal-interface
groups carry `preHash == "none"`, so the literal filter drops every internal
group. Implemented as **drop `preHash == "preHash"`** (HashML-DSA, which
antseal does not implement), which is what the prose meant.

The probe verdict itself was **Branch A**: external-interface groups with a
populated `context` exist for ML-DSA-65 (60 sigGen cases, 56 with non-empty
context spanning 0–255 bytes; 30 sigVer cases). Row 13 is therefore **T0**,
not the T1 hand-derivation Branch B would have forced.

Row 13 is checked twice per external case, and the second is what makes it T0:
the crate's own `sign_deterministic(M, ctx)` reproduces NIST's bytes, **and**
our hand-derived `M′ = 0x00 ‖ len(ctx) ‖ ctx ‖ M` fed to `sign_internal`
reproduces the same bytes. The first says the crate read FIPS 204 Algorithm 2
correctly; the second says *we* did, checked against NIST rather than against
ourselves.

## 5. Known gaps

| gap | status |
| --- | --- |
| Rows 5, 6, 9 have no T0 anchor | **permanent and inherent** — the constructions are ours (§2). |
| The verification-report byte format (D29) has no cross-check at all | **out of Q11's scope**, registered as **Q38**. D29 freezes a v1 format at Q14 with 21 byte-pinned strings and no independent implementation checking any of it. Not a blocker for this report, but it is a hole in a v1 format. |
| `expect.mldsa65.public_key` / `.signature` in `signatures.json` are not re-derived by Python | **by design** — no Python ML-DSA exists. Those two fields are covered by row 12/13's ACVP replay at T0, which is strictly stronger. `gen_vectors.py --check` prints the scope so it cannot be silently overread. Every other field, `mldsa65.seed` included, is re-derived. |

## 6. Retention

The lane is permanent and unconditional, for the same reason the golden
vectors are retained forever (spec line 123, Q19): a v2 format will add
`testdata/vectors/v2/`, and the cross-check must extend to it rather than be
reasoned about again. `scripts/cross-check.sh` globs `testdata/vectors/v*/`
and `*/gen_vectors.py`, never a hard-coded version or component list, and
fails loudly if any surface class discovers nothing.

This document gains a **new dated section** at each format freeze. Earlier
sections are never rewritten — they are the record of what was true then.

The ACVP and Unicode fixtures are retained forever like any other frozen
fixture. A newer release may be *added* as a second pinned subset; the
existing one is never replaced, because it is the evidence that this freeze
was clean.
