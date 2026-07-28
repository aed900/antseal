# D31 — Independent cross-check vehicles for the non-CBOR surfaces, and their permanence

- **Status: RESOLVED — one named vehicle per surface across three evidence
  tiers (§2), every one of them a permanent always-on CI lane plus a one-shot
  frozen discrepancy report (§6). For ML-DSA-65 the answer to the register's
  question is: **`fips204` is not an independence vehicle at all** — NIST
  ACVP is, `fips204` is the D14 fallback-equivalence check, and conflating
  the two is what made the question look hard (§4).**
- **Date: 2026-07-28** (planning; Q11 executes, F14 builds the CBOR half,
  Q14 gates on the report)

## Context

MVP-SPEC.md line 5 mandates an independent cross-check before the M0 freeze;
line 73 names CBOR specifically. tasks/Q.md Q11 is that mandate, it is a Q14
blocker, and its Notes leave one thing open:

> Whether an ml-dsa↔fips204 cross-crate check counts as "independent" for
> ML-DSA (both Rust, shared ecosystem) is Open decision 1; ACVP KATs are the
> mitigation.

`docs/decisions/D7-cbor-crate.md` §D12 already decided the CBOR vehicle —
Python `cbor2 ==6.1.3`, dev-tool-only. This record decides every other
surface, and the permanence question the register raised for all of them.

**The state of play is better than Q11's task text implies.** C16 and G15
already landed independent Python references for most of the crypto surface,
and G3 landed one for canonicalization. §3 inventories what exists rather
than commissioning it again. What is genuinely missing is ML-DSA-65, the
CBOR half, and — a gap nobody registered — the report byte format (§7).

## 1. Attacking the framing: "independent" is not one property

Q11's value is that it is not the same code checking itself. But "the same
code" hides three distinct failure modes, and a vehicle that closes one may
close none of the others. Naming the tier is what makes the evidence
readable, so this record grades every vehicle:

- **T0 — external oracle.** Expected values originate outside this project
  *and* outside its language ecosystem: NIST ACVP files, RFC-published
  known-answer tests, Unicode's own `NormalizationTest.txt`, Wycheproof.
  This is the only tier that catches a **shared misreading of the
  specification** — the failure mode where our Rust and our Python both
  implement the same wrong thing because the same person read the same
  sentence twice.
- **T1 — independent re-implementation.** A second implementation written
  from the specification, in a different language and toolchain, sharing no
  code. Catches implementation bugs and transcription errors. Does **not**
  catch a shared misreading — unless it is *anchored* by a T0 known-answer
  test, which is why every T1 vehicle below must carry one where one exists.
- **T2 — cross-implementation agreement inside one ecosystem.** Two Rust
  crates. Catches neither a shared misreading nor a shared ecosystem idiom.
  **T2 is not independence** and this record never counts it as such.

Two consequences drop straight out:

1. **A T1 vehicle without a T0 anchor is only half a check**, and where no
   T0 anchor exists — because the construction is *ours* — T1 is the honest
   ceiling and should be stated as such rather than dressed up.
2. **`ml-dsa` ↔ `fips204` is T2.** That settles the register's question
   without further argument (§4).

## 2. The vehicle register

The authoritative table. Every surface Q11 must cover, its vehicle, its
tier, its T0 anchor, and where it lives.

| # | Surface | Vehicle | Tier | T0 anchor | Artifact |
| --- | --- | --- | --- | --- | --- |
| 1 | Canonical CBOR encode (RFC 8949 §4.2.1) | **our own Python encoder written from RFC 8949 §4.2.1** (~80 lines); `cbor2 ==6.1.3` used for **decode only** | T1 | RFC 8949 Appendix A examples | `testdata/vectors/v1/crosscheck_cbor.py` (new, F14) |
| 2 | CBOR decode + structural equality vs the in-file diagnostic sidecar | `cbor2 ==6.1.3` | T1 | RFC 8949 Appendix A | same file |
| 3 | Rejection fixtures are genuinely non-canonical | our own §4.2.1 checks (not `cbor2`'s notion of canonical) | T1 | RFC 8949 §4.2.1 text | same file |
| 4 | HKDF-SHA256 + the length-prefixed info encoding | `reference.py::hkdf_sha256` — RFC 5869 from raw `hmac`/`hashlib` | T1 | **RFC 5869 Appendix A** | `testdata/vectors/v1/crypto/reference.py` (exists) |
| 5 | Domain-tagged salted commitments | `reference.py::tagged_sha256` | T1 | none possible — the construction is ours | same file (exists) |
| 6 | Unit padding (`padded_length`, zero-fill) | `reference.py::padded_length` / `apply_padding` | T1 | none possible — ours | same file (exists) |
| 7 | XChaCha20-Poly1305 AEAD | `reference.py` from-scratch RFC 8439 §2.3/§2.5/§2.8 + draft-irtf-cfrg-xchacha §2.2/§3.1 | T1 | draft-irtf-cfrg-xchacha §A KATs; libsodium agreement (C16) | same file (exists) |
| 8 | Ed25519 keygen/sign/strict-verify, incl. `ctx ‖ 0x00 ‖ body` | `reference.py` RFC 8032 §6 reference formulation | T1 | **RFC 8032 §7.1 KATs** | same file (exists) |
| 9 | GGM salt tree, `fine_root`, RFC 6962 unbalanced Merkle, leaf-exact cover, boundary paths | `fine-tree/gen_vectors.py` — stdlib-only, MSB-first indexing written from spec lines 78/79/96 | T1 | RFC 6962 §2.1 promotion rule only; the GGM tree is ours | `testdata/vectors/v1/fine-tree/gen_vectors.py` (exists) |
| 10 | Canonicalization v1 (BOM / EOL / NFC pipeline) | `gen_corpus.py` — stdlib `unicodedata`, different NFC table lineage | T1 | **Unicode 17.0.0 `NormalizationTest.txt`** (see §5) | `testdata/utf8-corpus/gen_corpus.py` (exists) |
| 11 | `work_id` / `anchor_digest` | SHA-256 over exact received bytes, computed by the checker of row 1 from the envelope's key-0 `bstr` (F19's contract) | T1 | FIPS 180-4 KATs via `hashlib` | `crosscheck_cbor.py` (new) |
| 12 | **ML-DSA-65 keyGen / sigGen / sigVer** | **NIST ACVP `internalProjection.json`**, pinned to an exact `usnistgov/ACVP-Server` commit, replayed against **`ml-dsa =0.1.1`** | **T0** | *is* the T0 oracle | `testdata/acvp/` (new — **not** under `vectors/`, see §5) |
| 13 | ML-DSA-65 `ctx` absorption (`M′ = 0x00 ‖ len(ctx) ‖ ctx ‖ M`) | ACVP external-interface groups if present, else the FIPS 204 Algorithm 2 hand-derivation (§4c) | T0 / T1 | FIPS 204 Algorithm 2 | `crates/antseal-core/tests/acvp_ml_dsa.rs` (new) |
| 14 | `fips204 =0.4.6` byte-identity (D14's fallback claim) | `fips204` — **explicitly T2, explicitly not counted as independence** | T2 | n/a | `crates/antseal-core/tests/mldsa_fallback_equivalence.rs` (new) |
| 15 | Verification-report byte format (D29) | see §7 — **a gap, and out of Q11's scope as written** | — | — | Q38 |

Rows 4–10 already exist on disk. Q11's job for them is not to write them but
to (a) verify each carries its T0 anchor, (b) normalise their invocation
(§6a), and (c) put them behind one always-on lane.

## 3. What already exists, and the one thing each still owes

| artifact | owes |
| --- | --- |
| `testdata/vectors/v1/crypto/reference.py` | its docstring promises `selftest()` "checks every primitive against published known-answer vectors". Q11 must **confirm the RFC 5869 Appendix A and RFC 8032 §7.1 vectors are actually in it**, and add them if not. A T1 reference whose T0 anchor is aspirational is a T1 reference. |
| `testdata/vectors/v1/fine-tree/gen_vectors.py` | nothing — its ceiling is genuinely T1 and it says so. |
| `testdata/utf8-corpus/gen_corpus.py` | a T0 anchor: assert Python's `unicodedata.unidata_version == '17.0.0'` (matching D25's pinned descriptor `unicode-17.0.0`) and run a sample of Unicode's own `NormalizationTest.txt` NFC column. Without the version assertion the "different NFC table lineage" claim is unverified — a CI runner on an older Python would silently compare against Unicode 15 tables. |
| `testdata/vectors/v1/hkdf/gen_vectors.py`, `crypto/gen_vectors.py` | a uniform `--check` mode (§6a). |

## 4. ML-DSA-65 — the register's actual question

### 4a. `fips204` is not an independence vehicle

`ml-dsa =0.1.1` and `fips204 =0.4.6` are both Rust, both implement FIPS 204,
both live in the same small post-quantum-Rust community. Agreement between
them is T2: it cannot detect a shared misreading of FIPS 204, which is the
dominant risk for a 2024 standard with a non-trivial `ctx`/`Sign_internal`
split.

The register notes that `fips204` being D14's designated byte-identical
fallback "cuts both ways". It does, and the cut is decisive **in one
direction only**: because `fips204` is the fallback, an `ml-dsa`↔`fips204`
byte-equality check is **exactly the check D14's fallback claim needs**, and
it must exist. It is simply not the check line 5 mandates. **Two checks, two
purposes, and neither substitutes for the other.** Row 14 exists; it is
labelled T2 in the register and in the discrepancy report; it never appears
in the sentence "the independent cross-check is clean".

### 4b. ACVP is the vehicle, and it is stronger than a hand-written T1

There is no T1 option worth having here. Writing an ML-DSA-65 in Python from
FIPS 204 is weeks of work, would be slower than the vectors it checks, and —
being written by the same hands that read the same spec — would sit at T1
with no T0 anchor. NIST's ACVP files are generated by NIST's own reference
implementation from NIST's own text. That is T0, the strongest tier in §1,
and it means **ML-DSA ends up better covered than the surfaces with
hand-written Python references**, not worse.

Grounding facts, read from disk and from upstream:

- `fips204 =0.4.6` **vendors the ACVP files** at
  `tests/nist_vectors/{ML-DSA-keyGen,ML-DSA-sigGen,ML-DSA-sigVer}-FIPS204/internalProjection.json`,
  with provenance recorded in `tests/nist_vectors/mod.rs`:
  `usnistgov/ACVP-Server` commit `65370b861b96efd30dfe0daae607bde26a78a5c8`
  (2024-08-15, "HOTFIX/v1.1.0.35/ML-DSA-KeyGen"). That is *fips204* being
  ACVP-validated. **It says nothing about `ml-dsa`, which is our primary.**
- That 2024 sigGen file has 6 groups keyed only on
  `(parameterSet, deterministic)`; the deterministic ML-DSA-65 group has 10
  cases and no `rnd` field, which `fips204`'s harness reads as `rnd = 0³²` —
  **exactly D15's deterministic mode**. Its cases carry no `context` field,
  so it validates only the **internal** interface (`fips204` calls
  `_internal_sign`).
- Upstream `master` (commit `2972def23bf9f3680c2c531561ed9bdd0f1086ad`,
  release v1.1.0.43, 2026-07-20) has grown that file from 1.37 MB to 8.97 MB,
  and its `registration.json` declares
  `signatureInterfaces: ["external","internal"]`,
  `contextLength: {min 0, max 2040}`, `deterministic: [true,false]`,
  `preHash: ["pure","preHash"]`, `externalMu: [true,false]`.

### 4c. The acquisition probe — the one thing Q11 must verify before building

The registration declares capabilities; whether the current
`internalProjection.json` actually contains external-interface groups with a
`context` field is a fact about the file, and this record will not assert it
from a capability list. **Q11 runs a probe first and records the verdict**
(the C11 idiom):

> Fetch
> `https://raw.githubusercontent.com/usnistgov/ACVP-Server/2972def23bf9f3680c2c531561ed9bdd0f1086ad/gen-val/json-files/ML-DSA-sigGen-FIPS204/internalProjection.json`,
> record its SHA-256, and report the distinct
> `(parameterSet, signatureInterface, preHash, externalMu, deterministic)`
> tuples across `testGroups`, and whether ML-DSA-65 cases carry a `context`
> field.

- **Branch A — external groups with `context` exist (expected).** Filter to
  `parameterSet == "ML-DSA-65"`, `preHash == "pure"`, `externalMu` false or
  absent, keeping both `signatureInterface` values and both `deterministic`
  values. Row 13 is then T0: `sign_deterministic(M, ctx)` is checked directly
  against NIST.
- **Branch B — external groups absent.** Use the 2024 pin
  `65370b861b96efd30dfe0daae607bde26a78a5c8` (identical to what `fips204`
  vendors, so the bytes are independently corroborated on every dev machine).
  Row 13 falls back to the **FIPS 204 Algorithm 2 hand-derivation**: assert
  for every deterministic ACVP case that
  `esk.sign_deterministic(M, ctx) == esk.sign_internal(&[&[0x00, ctx.len() as u8], ctx, M], &B32::default())`
  for `ctx = SIG_CONTEXT` and for a second, different ctx. That ties our
  actual call to the ACVP-validated internal interface through one line of
  FIPS 204 that a human derived — T1, honestly labelled, and the strongest
  available substitute.

Either branch is buildable. Record which one ran.

### 4d. The exact `ml-dsa =0.1.1` API the harness drives

No design freedom here — these are the public entry points, verified against
the pinned source:

| ACVP mode | call | source |
| --- | --- | --- |
| keyGen | `SigningKey::<MlDsa65>::from_seed(&seed)` → compare encoded `pk` and `sk` | `ml-dsa-0.1.1/src/signing.rs:55`, "reflects `ML-DSA.KeyGen_internal`, Algorithm 6" |
| sigGen, internal interface | `ExpandedSigningKey::sign_internal(&[message], &rnd)` with `rnd = 0³²` for deterministic groups, else the case's `rnd` | `src/signing.rs:308`, "Algorithm 7 `ML-DSA.Sign_internal`" |
| sigGen, external interface | `ExpandedSigningKey::sign_deterministic(M, ctx)` | `src/signing.rs:428` |
| sigVer | `VerifyingKey::verify_internal(M, &sig)` — assert the boolean equals the case's `testPassed` | `src/verifying.rs` |

The sigVer group is the one that must not be skipped: it carries the
**negative** cases (`testPassed: false` with a `reason`), which is where
D14's "canonical rejection is complete at `Signature::decode`" claim gets
its external confirmation.

## 5. Where the artifacts live — and one trap

`testdata/vectors/README.md` states a hard directory contract for
`vectors/v<n>/`: `*.json` files under a component directory **are vector
files** and are validated against the antseal vector envelope schema
(`non_secret` marker, `inputs.w` equal to the documented test seed, and so
on). An ACVP file satisfies none of that and would fail the runner — the same
class of trap F19 documented for F14's sidecar.

**Ruling: ACVP data does not go under `testdata/vectors/`.**

```
testdata/acvp/                        # NEW — sibling of anchors/, fine-tree/, utf8-corpus/
  README.md                           # what this is, why it is not a vectors/ component
  PROVENANCE.md                       # upstream URL, commit SHA, upstream file SHA-256,
                                      #   retrieval timestamp, the filter expression used
  filter_acvp.py                      # re-derives the subsets from the upstream files
  ml-dsa-65-keyGen.json               # filtered subset
  ml-dsa-65-sigGen.json
  ml-dsa-65-sigVer.json
```

Size estimate from the 2024 file's ML-DSA-65 groups (25 keyGen, 20 sigGen,
15 sigVer cases; `sk` is 4 032 B ⇒ 8 064 hex chars): **≈ 750 KB total.**
Acceptable to commit; the full 8.97 MB upstream file is not, and is not
needed.

`filter_acvp.py` is what makes this reproducible rather than a blob of
trust: anyone can fetch the upstream file, check its SHA-256 against
`PROVENANCE.md`, run the filter, and diff. Q11 must make that a documented
one-liner in `README.md`.

New files elsewhere:

```
testdata/vectors/v1/crosscheck_cbor.py               # F14 — *.py directly under v1/ is an allowed aux
scripts/cross-check.sh                               # the single entry point (mirrors vector-freeze.sh)
requirements-crosscheck.txt                          # hash-pinned cbor2==6.1.3
docs/testing/cross-check.md                          # the frozen one-shot report + this register
crates/antseal-core/tests/acvp_ml_dsa.rs             # rows 12/13
crates/antseal-core/tests/mldsa_fallback_equivalence.rs  # row 14 (T2, labelled)
```

## 6. Permanence — per surface, with the reasoning

**Both**, as the register proposed, but the two are not redundant and the
distinction must be written down or a later reader will delete one:

- **The one-shot artifact** (`docs/testing/cross-check.md`) is the *evidence
  for the freeze*: at the freeze commit, N vectors, zero discrepancies,
  per-surface tier, named vehicle versions. Q14 references it. It is dated
  and never rewritten — a later run appends a new dated section.
- **The permanent CI lane** is the *guard after the freeze*: it answers "has
  anything drifted since", which the one-shot cannot. Its specific job is to
  catch a future regeneration of a committed vector from the Rust side —
  precisely the move that would make the vectors agree with the code while
  both drift from the spec.

### 6a. Normalisation Q11 must do first

The existing generators are invoked three different ways (`gen_corpus.py
--check`; `fine-tree/gen_vectors.py | diff - fine-tree.json`;
`crypto/reference.py` bare for selftest). One lane cannot depend on three
conventions. **Every reference generator grows a `--check` mode** that
re-derives, diffs against the committed bytes, prints a per-file verdict, and
exits non-zero on any difference. `--check` becomes the only thing CI calls.

### 6b. The lane

One new always-on job in `.github/workflows/ci.yml`, job id and `name:` both
`cross-check`, placed after `golden-vectors`. **No path filter** — no job in
this workflow has one, and a filter here would be a foot-gun the first time a
vector directory is renamed.

```yaml
  cross-check:
    name: cross-check
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.12'
      - name: Install the pinned independent CBOR implementation (D7 §D12, D31)
        run: pip install --require-hashes -r requirements-crosscheck.txt
      - name: Independent cross-check over every committed v1 vector
        run: ./scripts/cross-check.sh
```

`scripts/cross-check.sh` runs, in order, failing fast:

```
python3 testdata/vectors/v1/crypto/reference.py            # T0 self-test first: the references' own KATs
python3 testdata/vectors/v1/hkdf/gen_vectors.py --check
python3 testdata/vectors/v1/crypto/gen_vectors.py --check
python3 testdata/vectors/v1/fine-tree/gen_vectors.py --check
python3 testdata/utf8-corpus/gen_corpus.py --check
python3 testdata/vectors/v1/crosscheck_cbor.py --check
```

`reference.py` runs **first and unconditionally**: if the reference's own
known-answer tests fail, every downstream agreement is worthless, and that
ordering makes the failure legible instead of showing up as forty vector
diffs.

The ACVP and fallback-equivalence checks are Rust (they drive `ml-dsa`), so
they run in the existing `test` lane as ordinary `#[test]`s — no new job, no
network. `mldsa_fallback_equivalence.rs` needs `fips204` as a **dev**
dependency; D14 pins it declaration-only today, and a `[dev-dependencies]`
entry does not make it a consumed runtime dependency, so D14's
"pinned-unconsumed" property survives. Q11 must state that in the test's
module docs or a future reader will think the fallback shipped.

Python is currently **not installed in any CI lane**; `cross-check` is the
first. Note it in `docs/ci-verification.md` so the lane inventory stays true.

### 6c. Retention after M0

The lane is permanent and unconditional, for the same reason the golden
vectors are retained forever (spec line 123, Q19): a v2 format will add
`testdata/vectors/v2/`, and the cross-check must extend to it rather than be
reasoned about again. **`scripts/cross-check.sh` iterates over
`testdata/vectors/v*/`, not over a hard-coded `v1`.**

The one-shot report gains a new dated section at each format freeze. The ACVP
subset is retained forever like any other frozen fixture; a newer ACVP release
may be *added* (a second pinned subset) but the existing one is never
replaced, because it is the evidence that the freeze was clean.

## 7. A gap this decision found: the report byte format has no cross-check

Q11's scope is "CBOR + crypto". The **verification-report byte format** is
neither: D29 makes it byte-deterministic compact `serde_json`, R9 pinned 21
report strings, R32 bumps `REPORT_VERSION` 0 → 1 in this same wave, and D29
freezes it at Q14 — *with no independent implementation checking any of it.*

A full T1 vehicle is not sensible: reproducing a report means reproducing all
of verification. But D29's contract is a set of *syntactic* properties, and
those are cheap to check with an independent JSON reader over the committed
strings:

- every pinned string parses as JSON, and re-serialising the parsed value
  with Python's `json.dumps(..., separators=(',', ':'), ensure_ascii=False)`
  and the **original key order** reproduces the exact bytes (declaration
  order, compact separators);
- no value is a float anywhere in the tree (D29 forbids floats);
- every hex string is lowercase and even-length;
- every key matches `^[a-z0-9]+(-[a-z0-9]+)*$` (kebab-case wire names);
- `report_version` is the first key of every document and equals the pinned
  constant.

That is a real, independent check of the whole frozen contract, and it is
about 40 lines. It is **not** Q11's — Q11 is already L and a Q14 blocker.
Registered as **Q38**.

## 8. Losing options and their real costs

**A second Rust CBOR crate instead of `cbor2`.** Rejected by D7 §D12 already
("would share ecosystem idioms and the temptation to compare against the same
reference code") — i.e. T2. Reaffirmed here.

**Use `cbor2.dumps(canonical=True)` as the encoding authority.** Tempting,
one line, and wrong: D7 §D12 records that `cbor2`'s `canonical=True` is RFC
7049 length-first ordering, not RFC 8949 bytewise. The two coincide over the
registry's uint-only keys *today*, so it would pass — and would silently stop
being a check the moment a future key type broke the coincidence. Writing our
own §4.2.1 encoder is ~80 lines, is strictly stronger (a hand-written encoder
from the RFC is better evidence than a library call), and removes the caveat
instead of documenting it. **Rejected in favour of row 1's own encoder;
`cbor2` decodes only.**

**Write a Python ML-DSA-65.** Weeks of work for a T1-with-no-anchor result,
strictly worse than ACVP's T0. Rejected.

**Count `ml-dsa`↔`fips204` as the ML-DSA independence check.** T2; it cannot
see a shared FIPS 204 misreading. Rejected as independence, **retained as
row 14** for D14's fallback claim.

**One-shot artifact only, no lane.** The cheapest option and the one that
fails silently: it cannot catch a post-freeze regeneration, which is the
single most likely way the vectors and the spec drift apart. Rejected.

**Lane only, no frozen report.** Q14 needs a dated, citable artifact naming
vehicle versions and discrepancy counts at the freeze commit. A green CI badge
is not a record. Rejected.

**Path-filter the lane to `testdata/vectors/`.** Saves ~30 s per PR and
breaks the first time a directory moves. No other job in this workflow is
filtered. Rejected.

## 9. Buildable work breakdown

### F14 — the CBOR half (do this first; Q11 consumes it)

1. Read F19's contract: the diagnostic sidecar is **in-file** at
   `expect.cases[].diagnostic`, one rendered object per strict-decode layer,
   rendered per the fixed table in `testdata/vectors/README.md`
   § "The diagnostic sidecar". There is deliberately no `body_bytes` field.
2. Write `testdata/vectors/v1/crosscheck_cbor.py` with four checks per
   vector, per F19: render-and-compare per layer; **own** RFC 8949 §4.2.1
   re-encode and byte-compare to the committed bytes; `SHA-256` of the
   envelope key-0 `bstr` equals `work_id`; `SHA-256` of the whole envelope
   equals `anchor_digest`. Assert the `MAX_JSON_SAFE_INT` (2⁵³−1) refusal
   rather than assuming it.
3. Self-test (Q11's and F14's shared accept bullet): a deliberately
   non-shortest-int vector makes the checker **fail**. A checker never
   observed failing is not evidence.
4. Confirm `cbor2` preserves map order on load (it does, via `dict`
   insertion order) — the sidecar pins wire order, and a checker that sorts
   silently weakens to a set comparison.
5. Run it over the rejection fixtures in `testdata/tamper/format/` and
   confirm each is genuinely non-canonical by the checker's own §4.2.1 logic.
6. Add `--check`; add `requirements-crosscheck.txt` with the hash-pinned
   `cbor2==6.1.3`.

### Q11 — everything else, in landing order

1. **Normalise** (§6a): add `--check` to the four existing generators. No
   behaviour change, no vector bytes move. Land alone — it touches four files
   and must not be entangled with the new work.
2. **Anchor the existing T1 references** (§3): confirm/add RFC 5869
   Appendix A and RFC 8032 §7.1 KATs in `reference.py::selftest`; add the
   `unicodedata.unidata_version == '17.0.0'` assertion and a
   `NormalizationTest.txt` NFC sample to `gen_corpus.py`.
3. **Run the ACVP acquisition probe** (§4c) and record the verdict —
   Branch A or Branch B — in `testdata/acvp/PROVENANCE.md` before writing
   any harness.
4. **Land `testdata/acvp/`**: filtered subsets, `filter_acvp.py`,
   `PROVENANCE.md` (upstream URL, commit SHA, upstream file SHA-256,
   retrieval timestamp, filter expression), `README.md` with the
   re-derivation one-liner and the reason this is not under `vectors/`.
5. **`crates/antseal-core/tests/acvp_ml_dsa.rs`**: keyGen, sigGen (both
   interfaces per the probe branch), sigVer including negatives, driving the
   §4d API. `wasm32` is out of scope — it is a fixture-replay test, and the
   native/WASM bit-match is Q5's job.
6. **`crates/antseal-core/tests/mldsa_fallback_equivalence.rs`**: `fips204`
   as a **dev** dependency; byte-equality of keygen and deterministic sign
   against `ml-dsa`; module docs stating this is **T2, for D14's fallback
   claim, and is not counted as the independent cross-check**.
7. **`scripts/cross-check.sh`** iterating `testdata/vectors/v*/` (§6b), and
   the `cross-check` CI job.
8. **`docs/testing/cross-check.md`**: this register as a table, plus the
   dated one-shot report — per surface, vehicle, exact version, vector count,
   discrepancy count. Zero discrepancies is the Q14 gate.
9. **Q14 checklist row** (§10).

Steps 1–2 and 3–6 are independent and can run in parallel; 7–9 need both.

## 10. The Q14 checklist row, verbatim

> - [ ] **Independent cross-check clean (Q11/F14/D31).** `docs/testing/
>   cross-check.md` carries a dated report for this freeze commit with
>   **zero discrepancies**, naming per surface the vehicle, its exact version,
>   the vector count and the evidence tier (T0 external oracle / T1
>   independent re-implementation / T2 same-ecosystem agreement). Every
>   surface in D31 §2 rows 1–13 is present at T0 or T1. **Row 14
>   (`ml-dsa`↔`fips204`) is T2 and does not count toward this row** — it is
>   D14's fallback-equivalence evidence. The `cross-check` CI lane is green
>   and unconditional, and `scripts/cross-check.sh` iterates every retained
>   format version rather than a hard-coded `v1`.

## 11. What the implementer must report back

1. The ACVP probe verdict (§4c): which branch, the upstream file's SHA-256,
   and the distinct group tuples found. If Branch B, say so plainly — row 13
   drops from T0 to T1 and the report must show it.
2. Whether `reference.py::selftest` **already** contained the RFC 5869 and
   RFC 8032 KATs or whether they had to be added. If they had to be added,
   every C16 agreement predating this was T1-unanchored, and that belongs in
   the report as a finding, not a footnote.
3. `unicodedata.unidata_version` on the CI runner. If it is not `17.0.0`,
   stop: G3's cross-check has been comparing against a different Unicode
   version than D25 pins, and that is a format-relevant finding for G, not a
   CI detail.
4. The `--require-hashes` line for `cbor2==6.1.3` (the sha256 of the exact
   wheel or sdist installed), so the pin is reproducible and not just
   version-equal.
5. Per-surface vector counts and discrepancy counts. **Any non-zero
   discrepancy blocks Q14** — report it, do not adjust a vector to make it
   agree.
6. Confirmation that the F14 self-test (a non-canonical vector makes the
   checker fail) and the ACVP negative sigVer cases both actually fail when
   they should. Two "proofs of failure" — a suite that has never been
   observed failing proves nothing.
7. Whether `fips204` landing in `[dev-dependencies]` changed
   `Cargo.lock`, and confirmation it did not enter `antseal-core`'s normal
   dependency graph (the `core-dep-graph` lane must stay green).

## Consequences and open actions

1. **D7 §D12's ordering caveat is retired, not carried.** §8 removes the
   condition that produced it by writing our own §4.2.1 encoder. D7 is not
   edited — its caveat was correct for the design it described; this record
   supersedes that design choice.
2. **Q11's task text understates existing coverage and overstates the ML-DSA
   problem.** Its Notes call ACVP "the mitigation" for a cross-crate check;
   §4 inverts that — ACVP is the check, the cross-crate comparison is a
   separate claim about D14. `tasks/Q.md` Q11 should be re-read against §9
   before execution; the entry is not edited here beyond adding the D31
   pointer, because Q11 is mid-wave.
3. **Q37/Q38 registered** (`tasks/Q.md`): Q37 carries D84's freeze-boundary
   rows; **Q38** is §7's report-format syntactic cross-check, which is a
   genuine hole in a v1 format freezing this wave.
4. **`fips204` moves from declaration-only to a dev-dependency.** Small, but
   it is a change to a D14-recorded consumption shape and must be noted in
   D14 as a dated addendum, not silently.
5. **`docs/ci-verification.md` gains the `cross-check` lane** and the fact
   that it is the first lane requiring Python.
6. **The ACVP fixture is the first committed test data in this repo whose
   provenance is external and unverifiable from the tree alone.**
   `PROVENANCE.md` plus `filter_acvp.py` is what makes it auditable; treat a
   missing or stale `PROVENANCE.md` as a red lane, not a documentation nit.

## Outcome

**RESOLVED, 2026-07-28.** One vehicle per surface, tiered (§2). CBOR keeps
D12's `cbor2 ==6.1.3` for **decoding only**, with our own RFC 8949 §4.2.1
encoder as the encoding authority. The crypto, GGM/Merkle, padding and
canonicalization surfaces use the Python references C16/G15/G3 already
landed, each required to carry a T0 known-answer anchor. ML-DSA-65 uses
**NIST ACVP** replayed against `ml-dsa =0.1.1` — T0, and the only surface
where the strongest tier was available; **`fips204` is T2 and is explicitly
excluded from the independence claim**, retained as D14's fallback-equivalence
check. Permanence: **both** — a dated one-shot report gating Q14, and a
permanent, unconditional `cross-check` CI lane iterating every retained format
version. The report byte format is a newly found gap, out of Q11's scope, and
is registered as Q38.
