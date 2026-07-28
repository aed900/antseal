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
| 15 | **Verification-report byte format** (D29 rules 1, 3, 5, 6, 7, 8) | stdlib `json` reader written from D29 | in-repo | **T1** | **none possible — the contract is ours** | `scripts/crosscheck-report.py` |
| 16 | ML-DSA-65 public key ↔ its HKDF seed (`ρ` leg), signature hint encoding | `hashlib.shake_256`, FIPS 204 Alg 6 + Alg 21 | stdlib | T1 | ACVP already covers the primitive at T0 (rows 12/13); this is completeness of the *checker* | `testdata/vectors/v1/crypto/gen_vectors.py::check_mldsa_half` |
| — | **Externally-sourced fixture integrity** | our own digest enforcer, reading the claims out of `PROVENANCE.md` | in-repo | **not a tier** | n/a | `scripts/crosscheck-provenance.py` |

**Rows 1–13 and 15–16 are all present at T0 or T1. Row 14 is T2 and does not
count.**

The last row is deliberately outside the tier scheme, because it is not a
second implementation of anything. It is what makes rows **10, 12 and 13**
mean what they say: those three are the T0 anchors, their expected values live
in bytes that came from outside this repository, and until wave 7 nothing
checked that those bytes were still the ones NIST and Unicode published. An
un-enforced oracle is not an oracle. It runs **first** in the lane for the same
reason `reference.py` does.

### Surfaces at T1 with no T0 anchor, named plainly

Rows **5** (domain-tagged salted commitments), **6** (unit padding), **9**
(the GGM salt tree — its Merkle promotion rule is RFC 6962, but the tree
itself is not) and **15** (the verification-report byte format) have no
external oracle **because the constructions are antseal's own**. No published
test vectors exist for them and none can. T1 — a stdlib Python
re-implementation written from the spec, sharing no code with the Rust — is
the honest ceiling, and it is what they have.

This is a real limit on what this report proves for those four rows: a
misreading of MVP-SPEC.md — or, for row 15, of D29 — shared between the Rust
and the Python would survive it. The mitigations are elsewhere and are not
cross-checks: the spec text itself, the tamper matrix, and review.

Row 15 carries a second, narrower limit worth stating in the register rather
than only in the script: **it cannot detect a key reordering.** Its
round-trip property re-serialises in the order the received bytes carried, so
a reordering applied uniformly across the format round-trips cleanly. An
*inconsistent* order is caught, and `report_version` leaving the front is
caught, but a global reorder would survive both. Detecting it would need a
reader that independently knew the Rust struct declaration order, and
regex-parsing that out of `report.rs` is the kind of brittleness that produces
a false red at a freeze gate. What actually holds the line there is not a
cross-check: reordering a field moves all 21 pinned strings at once, so
`vector-freeze` and the native↔WASM bit-match both go red.

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

## 3b. Freeze report — 2026-07-28, wave 7 addendum

A **new dated section**, per §6: the report above is the record of what was
true at commit `788519b` and is not rewritten. This one covers the three
surfaces wave 7 added before the Q14 freeze (Q38, Q41, C27). Same interpreter,
same host.

| # | Surface | What ran | Count | Discrepancies |
| --- | --- | --- | --- | --- |
| — | External-fixture provenance (runs first) | committed bytes vs their `PROVENANCE.md` digest + byte count | **4 fixtures**, 2 directories | **0** |
| 15 | Verification-report byte format (T1, no T0 anchor) | 9 byte-level properties + 3 envelope checks per pinned string | **21 strings** | **0** |
| 16 | ML-DSA-65 pk↔seed and hint encoding | 4 legs over `signatures.json`'s ML-DSA half | 1 vector | **0** |

### Total discrepancies: 0

### Proven able to fail

| surface | planted faults | result |
| --- | --- | --- |
| `crosscheck-report.py` | **17 faults + 1 control**, one per property: truncation, invalid UTF-8, duplicate key, non-compact separators, a space after a colon, a float, uppercase hex, odd-length hex, a kebab-case key, `report_version` demoted, `report_version` bumped, a non-kebab enum, one key set in two orders, a case missing `report_json`, uppercased envelope hex, a wrong `report_len`, a declared version disagreeing with the Rust constant | red ×17, green ×1 |
| `crosscheck-provenance.py` | **8 faults + 1 control** across 6 claim classes: a flipped fixture byte, an edited digest claim, an edited byte count, a deleted digest row, an unrecorded fixture, a stripped upstream URL, one deleted `PROVENANCE.md`, all deleted | red ×8, green ×1 |
| `gen_vectors.py` ML-DSA half (C27) | `mldsa65.public_key` and `.signature`, one nibble each | red ×2 — **and the byte-diff leg stays green**, which is the proof it is `check_mldsa_half` doing the catching |

Every one of these is a **standing** part of `./scripts/cross-check.sh
--self-test`, not a one-off note here.

### Findings

**3b-a. Q38's own task text specified a property that would have failed on
correct bytes.** Its key regex `^[a-z0-9]+(-[a-z0-9]+)*$` is D29 rule 7's
*enum* clause applied to *keys*. D29 rule 7 has two clauses and the second is
"Field names are the Rust snake_case names, unrenamed." Run as written the
regex rejects **20 of the 34 keys** in the committed reports. At a freeze
gate, with a checker asserting it and 21 vectors failing, the tempting fix is
the bytes. Split into two properties (snake_case keys, kebab-case enum
values); the planted-fault suite carries a kebab-case-key fault permanently.

**3b-b. Q41's claim held exactly.** The four externally-sourced fixtures'
digests appeared in one place each — the prose of their `PROVENANCE.md` — and
nowhere else in the tree. `FROZEN.sha256` does not and cannot cover them: it
is per-format-version and scoped to `testdata/vectors/v<n>/*.json`.

**3b-c. C27's claim held exactly, and is smaller than it sounds.**
`gen_vectors.py --check` read the two ML-DSA fields out of the committed file
and compared the result against that same file. Confirmed by planting a
fault: green. But `signatures.json` is frozen by `FROZEN.sha256` and ML-DSA-65
is covered at T0 by ACVP, so the tamper was never invisible to CI as a whole —
only to this checker. Completeness, not soundness, and the record should not
be read as more.

**3b-d. Discovery-by-marker had the failure mode it was guarding against.**
The provenance enforcer defines an external-fixture directory as one holding a
`PROVENANCE.md`. Its own self-test showed that **deleting** that file removes
the directory from discovery entirely, un-enforcing every fixture in it while
the lane stays green. Closed with a written-down must-exist list, the same
device `FROZEN.sha256` uses for deleted vectors: discovery may return a
superset, never a subset. Worth generalising — every discovery-by-marker
scheme in this repo has this shape, and only the ones with a separate
must-exist list are safe.

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
| Rows 5, 6, 9, 15 have no T0 anchor | **permanent and inherent** — the constructions are ours (§2). |
| ~~The verification-report byte format (D29) has no cross-check at all~~ | **CLOSED 2026-07-28 by Q38** (row 15). D29's contract is syntactic, so `scripts/crosscheck-report.py` asserts nine properties per pinned string with a stdlib JSON reader. What remains is the narrower limit in §2: it cannot see a key reordering applied uniformly across the format. |
| ~~`expect.mldsa65.public_key` / `.signature` in `signatures.json` are not re-derived by Python~~ | **CORRECTED 2026-07-28 by C27** (row 16). The old status read "by design", and the design was sound but the consequence was not stated: the two fields were read back from the committed file and re-emitted, so `--check` compared them against themselves and a tamper stayed green. Now checked in four legs — lengths, `ρ = SHAKE256(seed ‖ 06 ‖ 05, 128)[0:32]` from FIPS 204 Alg 6, `HintBitUnpack` from Alg 21, and a residue digest. The original point stands unchanged: **ACVP at T0 (rows 12/13) is the real vehicle**, and C27 is completeness of this checker, not a soundness fix. Full re-derivation is still impossible — there is no Python ML-DSA. |
| A directory of externally-sourced bytes with no `PROVENANCE.md` is invisible to the provenance enforcer | **permanent and inherent.** Nothing automatic distinguishes "fixture we generated" from "fixture we downloaded" by inspection. `REQUIRED_DIRS` stops a *known* record being deleted; a *new* undeclared one is a review matter, caught by `testdata/README.md`'s per-directory ownership table. |
| `requirements-crosscheck.txt`'s `cbor2` wheel hashes are not enforced offline | **out of scope, deliberately.** They are enforced by `pip --require-hashes` at install time and the wheel is not committed, so there is nothing offline to compare against. A locally-provisioned cache under `~/.cache/antseal/` is a dev-machine artifact, not committed test data. |

## 6. Retention

The lane is permanent and unconditional, for the same reason the golden
vectors are retained forever (spec line 123, **Q27** — the
format-stability policy; Q19 is the M3 playwright lane and was a
mis-numbering, corrected wave 7): a v2 format will add
`testdata/vectors/v2/`, and the cross-check must extend to it rather than be
reasoned about again. `scripts/cross-check.sh` globs `testdata/vectors/v*/`
and `*/gen_vectors.py`, never a hard-coded version or component list, and
fails loudly if any surface class discovers nothing.

The two repo-level checkers added in wave 7 are permanent on the same terms
and are version-general by construction: `crosscheck-report.py` walks
`testdata/vectors/v*/report/` and `crosscheck-provenance.py` walks
`testdata/*/PROVENANCE.md`, so neither needs a copy per format version and
neither needs wiring when new data lands. `scripts/cross-check.sh` finds them
by glob (`scripts/crosscheck-*.py`) rather than by name, so a third checker
cannot be added and silently left out of `--check` or `--self-test` — with the
two required ones written down as a must-exist list, because a glob can only
fail on what it finds.

This document gains a **new dated section** at each format freeze. Earlier
sections are never rewritten — they are the record of what was true then.

The ACVP and Unicode fixtures are retained forever like any other frozen
fixture. A newer release may be *added* as a second pinned subset; the
existing one is never replaced, because it is the evidence that this freeze
was clean.

---

## Freeze report — 2026-07-28, the `format-v1-freeze` commit

**Supersedes §3's report, which describes a different tree.** That section is
dated the same day but names commit `788519b`, the Q11 landing. Between
`788519b` and this freeze the vector set moved three times, each for a
recorded reason: **D83/G23** re-emitted `fine-tree/fine-tree.json` (the
canonical zero tail), **R32** rewrote all 21 pinned strings in
`report/verification-reports.json` (`REPORT_VERSION` 0 → 1), **G21** added the
`content-model` kind, which did not exist, and **G24** added two bundle cases.
§3's own count — *"11 committed v1 vector files"* — reads 12 here. Earlier
sections are never rewritten (§6); this one is appended beside them.

Recording this is the point of Q14's row N8, which requires a report **for the
freeze commit** and warns that a reader can otherwise tick it by agreeing with
a document instead of verifying the evidence it names.

**Tree verified:** `9d3ab16`. The `format-v1-freeze` tag lands on a later
commit that adds only this report, the CHANGELOG and the register updates —
no artifact this report verifies changes between the two, and
`FROZEN.sha256`, `docs/format/FROZEN.sha256` and `testdata/tamper/` are
byte-identical across them.

**Result: ZERO discrepancies**, every surface, first run.

### Per-surface

| # | surface | vehicle | version | scope | tier |
|---|---|---|---|---|---|
| 1 | Canonical CBOR (§4.2.1) | `crosscheck_cbor.py` — our own encoder; `cbor2` **decodes only** | `cbor2 ==6.1.3` | 255 checks over 16 cases in the 2 CBOR-committing vectors of 12 files | **T1**, on a **T0** anchor of 33 RFC 8949 Appendix A examples, both directions |
| 2 | Format tamper fixtures | same checker | as above | 17 confirmed non-canonical **for the reason claimed**, 9 confirmed canonical-but-schema-invalid, 4 out of scope | T1 |
| 3 | HKDF-SHA256 + the 8-label registry | `hkdf/gen_vectors.py` | stdlib | all committed cases | T1 on a **T0** anchor (RFC 5869 App. A) |
| 4 | Salted commitments, unit padding | `crypto/gen_vectors.py` | stdlib | all committed cases | **T1 with no T0 anchor and none possible** — the construction is ours |
| 5 | XChaCha20-Poly1305 | from-scratch Python cipher | stdlib | 12 ciphertexts | T1, corroborated against libsodium |
| 6 | Ed25519 | RFC 8032 §6 reference formulation | stdlib | keygen + signing over the committed `signatures.json` cases | T1 on a **T0** anchor (RFC 8032 §7.1) |
| 7 | ML-DSA-65 | **NIST ACVP**, replayed by `tests/acvp_ml_dsa.rs` | ACVP-Server `2972def` | 115 cases | **T0** |
| 8 | ML-DSA-65 vector file completeness | `gen_vectors.py::check_mldsa_half` (**C27**) | stdlib | ρ per FIPS 204 Alg 6, HintBitUnpack per Alg 21, lengths, residue | T1 — completeness, not soundness; row 7 is the soundness evidence |
| 9 | GGM fine tree | `fine-tree/gen_vectors.py` | stdlib | all committed cases | **T1 with no T0 anchor and none possible** |
| 10 | Canonicalization / NFC | `utf8-corpus/gen_corpus.py` | stdlib | 37 fixtures + **1 537 `NormalizationTest.txt` lines** | T1 on a **T0** anchor (Unicode's own conformance data) |
| 11 | Verification-report byte format (**Q38**) | `scripts/crosscheck-report.py` | stdlib `json` only | 21 pinned strings, 69 enum values, 9 properties + 3 envelope checks each | **T1 with no T0 anchor** — the contract is ours |
| 12 | External-fixture provenance (**Q41**) | `scripts/crosscheck-provenance.py` | stdlib | digests parsed from each `PROVENANCE.md`, offline | T1 |
| 13 | `ml-dsa` ↔ `fips204` | `tests/mldsa_fallback_equivalence.rs` | `fips204 =0.4.6` | keygen + deterministic sign | **T2 — does NOT count toward this row** (D14 fallback evidence, per D31 §10) |

| 14 | `sig-reject` vectors (21 Ed25519 + 15 ML-DSA-65 reject cases) | **none** | — | not read by any cross-check vehicle | **NO VEHICLE — recorded, not claimed** |
| 15 | `content-model` vectors | **none** | — | not read by any cross-check vehicle | **NO VEHICLE — recorded, not claimed** |

**Rows 14 and 15 are the honest entry this report would otherwise omit.** Two
of the eleven registered vector kinds have no independent vehicle at all.
Neither is unchecked — `sig-reject` is executed by
`crates/antseal-core/tests/sig_reject_suite.rs` and both are byte-pinned by
`FROZEN.sha256` and re-executed identically on wasm32 — but *this* document's
subject is independent agreement, and for these two there is none. Stating
them as rows rather than leaving them out is the difference between a report
that is complete and one that merely looks it. **Q54** owns making "every kind
has a named vehicle or a recorded reason" a checked property rather than a
thing a reader must notice.

A correction to row 6 while writing this: it first read *"21 reject cases +
keygen"*. `crypto/reference.py` never opens `sig-reject/*.json` — the reject
suites are Rust-side. The row now says what the vehicle actually reads.

### Environment, because two counts depend on it

`python 3.11.2`, `unicodedata.unidata_version = 14.0.0`. The NFC anchor
therefore reports **1 537 lines executed, 70 skipped as unassigned** — the
skips are scalars assigned after Unicode 14.0.0. On the CI runner (3.12) the
skip count differs. This is D31's recorded ceiling, not a defect: **no
released CPython embeds Unicode 17.0.0**, which is why D31's original
`unidata_version == '17.0.0'` assertion was found unsatisfiable and replaced
with Unicode's own conformance file. **Q42** is the tripwire for when CPython
catches up.

### What this report does not cover, stated plainly

- Rows 4 and 9 — salted commitments, unit padding, the GGM tree — are **T1
  with no external oracle, and none can exist**, because those constructions
  are this project's own. A shared misreading of our own spec is invisible to
  them. That is the honest ceiling of the whole exercise.
- Row 11 cannot detect a **uniform** key reordering of a report document: the
  checker re-serialises in the order it received. `vector-freeze` and the
  native↔wasm32 bit-match are what hold that line.
- The CBOR checker's schema branch inspects the outer layer only; it does not
  descend into embedded `bstr` layers the way its canonicality branch does
  (**F36**).
