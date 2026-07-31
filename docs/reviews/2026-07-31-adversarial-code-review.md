# Adversarial code review — crypto primitives, verify pipeline, parser hardening

**Date**: 2026-07-31 · **Tree**: `main` at the post-freeze bookkeeping HEAD (clean), format tag `format-v1-freeze`
**Method**: 7 parallel review lanes + 8 refute-first verifiers (15 agents, ~2.6M tokens, 572 tool calls)

## Why this exists

The 2026-07-31 five-agent audit re-verified every *claim* the project makes: 1221 tests green,
255 independent cross-checks with 0 discrepancies, tamper matrix complete, freeze digests and
bit-match intact, every self-test proved able to fail. It explicitly did **not** re-derive the
source logic from first principles — it verified claims and re-executed checks.

This review is that missing piece. Its governing rule was that **the green suites count as zero
evidence**: lanes were forbidden to cite a passing test as proof of anything, and were pointed at
the project's own history (F30, Q52, Q66 — all real defects found behind fully green suites) as
proof that the harnesses do not model everything. Lanes re-derived the required behaviour from
RFC 8032, FIPS 204, RFC 8949 §4.2, RFC 6962 and `MVP-SPEC.md` *before* reading the implementation,
then checked the code against that derivation.

No build or test command was run (independence from the harness is the point, and the box has 2
cores). Nothing was modified. Several lanes wrote throwaway Python reimplementations to
machine-check the Rust against an independent model.

## Result

**33 unique findings. Zero critical. Three high, all one root cause.** No forgery, secrecy-loss,
false-PASS, or attacker-reachable panic was found on any surface. The three `high` findings are
three lanes independently converging on a single unenforced spec clause; the remainder are
hardening gaps, denial-of-service amplification, and — the largest single class — **recorded
claims that the code does not implement**.

| Verdict | Count | Meaning |
|---|---|---|
| CONFIRMED | 8 | A verifier independently traced input → wrong outcome |
| Unverified (below the verifier cap) | 25 | Reported by a lane, not independently re-checked |
| REFUTED | 0 | — |

The verifier cap was 8; five `medium` findings passed through unverified and are marked below.
All 8 findings sent to a refute-first verifier survived. Two were corrected downward in severity
by their verifier (marked `medium→low`).

---

## The one real defect: raw-mirror multiplicity (findings 1–3, `high`)

Three lanes — `verify-order`, `verify-file-stages`, `schema-parse` — found this independently
from different directions. Every element below was re-checked by hand against the tree.

**D23 clause 3** (`docs/decisions/D23-raw-mirror-placement.md:23`) decides: *"at most one mirror
per file (mirror existence is the per-file …)"*. `FileEntry::raw_mirror`'s own prose repeats it.

**Nothing enforces it.** `FileEntry::new` (`manifest/body.rs:694-743`) applies exactly three
rules: units non-empty, at least one `Normal` unit (D77), and per-unit coverage/binding
agreement. It never counts mirrors. `validate_unit_ordinals` accepts sequential ids. No decode
layer adds a count rule.

**Tiling does not catch it either.** `check_tiling` (`verify/structural.rs:277-283`) filters to
`kind == UnitKind::Normal`, so a second mirror's byte range is entirely unconstrained — mirrors
are exempt from tiling by `kind` alone, which R3's own entry records as deliberate.

**And the two consumers of the unenforced assumption disagree about which mirror is "the"
mirror:**

- `check_full_reveal_content` (`verify/file_stages.rs:1119`) resolves it with `.iter().find(…)` —
  **first wins**. Only that mirror gets row 9 (`raw_commit` opening) and row 10
  (`canonicalize_v(raw) == canonical`).
- `reveal_set` (`verify/pipeline.rs:930`) assigns `raw_mirror = Some(…)` inside a loop with no
  break — **last wins**. That is the one named in the report.

**Consequence.** A sealer hand-builds a file with units `{0: Normal (canonical bytes), 1:
RawMirror (the honest original), 2: RawMirror (an unrelated document B, with its own
sealer-computed `unit_commit`)}`. D77 is satisfied by unit 0; both mirrors are non-covered so both
legitimately carry a `unit_commit`; ordinals 0,1,2 are sequential; mirrors are tiling-exempt.
A full reveal of all three units verifies **clean**: rows 7–8 pass on the concatenated non-mirror
bytes, rows 9–10 bind mirror 1 only, and mirror 2 is bound by nothing but its own sealer-chosen
commitment — yet it is signed, anchored, and disclosed as part of the work, and **the report names
it as the file's original**.

This is precisely the attack `MVP-SPEC.md:121`'s raw-mirror↔canonical MUST exists to prevent: a
second, contradictory "original" co-timestamped inside a clean-verifying bundle.

**Why the suites never saw it**: every fixture and the proptest strategy generate 0 or 1 mirrors.

**Constraint on the fix**: enforcement needs an error code, and the 191-code universe is frozen —
but D30 §3 makes it **append-only** and `error_universe.rs:358` states adding is "routine and
unrestricted". So a new `manifest-…` code is legal; renaming is what is forbidden. Tightening
`FileEntry::new` rejects manifests that were never conformant, so this is spec-conformance, not a
format change. Recorded as **F40** (root fix) and **R53** (consumer reconciliation).

---

## Confirmed findings 4–8

### 4. `ManifestBodyV1` derives `Clone`, and three docs say it cannot (`medium`)
`manifest/body.rs:995-999` states *"**Not `Clone`, on purpose** … the 'verifiers never re-encode'
rule of spec line 74 is enforced by the borrow checker rather than by documentation"*. Line 1003
derives `Clone` unconditionally. The same false claim is repeated at `manifest/envelope.rs:13-16`
(*"re-encoding is a borrow-checker error, not a code-review finding"*), at `envelope.rs:163-164`,
and in `encode_body`'s own rustdoc. `encode_body(manifest.body().clone())` compiles today.

The danger is not present-tense: it is that the docs actively **disarm the review** that would
catch a future path computing `work_id` or a signature pre-image over re-encoded bytes instead of
`body_bytes()`. Spec line 74 makes never-re-encode a MUST precisely because it refuses to rely on
encode/decode being byte-exact. Recorded as **F41**.

### 5. `verify_body`'s claimed duplicate re-check does not exist (`medium→low`)
`crypto/sig_policy.rs:221-224` promises pubkeys/signatures are *"both already duplicate-free and
exact-length by F's schema, and re-checked here so this function is safe to call on any input"*.
Exact-length **is** re-checked; duplicate-freedom is **not**. `lookup` (lines 275-280) is
`Iterator::find` — strictly first-wins — and the unlisted-algorithm loop only tests
`policy.requires(alg)`, which a duplicate of a listed algorithm passes.

A third-party consumer of the pub API calling
`verify_body(hybrid, keys, [(Ed25519, valid), (Ed25519, garbage), (MlDsa65, valid)], body)` gets
`Ok(Hybrid)`; a last-wins or duplicate-rejecting implementation gets a different verdict on the
same input — the divergence class `MVP-SPEC.md:73` exists to kill. Not reachable through the
shipped pipeline (F's schema does reject duplicates), hence the downgrade. Recorded as **C28**.

### 6. Quadratic pre-authentication scans (`medium→low`)
`verify/structural.rs:277` and the stage-2/3 groups are nested linear scans over
adversary-controlled counts (files × units, units × reveals), and the signature stage is **stage
5** — none of that work is gated on any authenticator.

D10 itself states in bold that both count caps are simultaneously reachable inside
`MAX_MANIFEST_BYTES` (~10.2 MiB), and **nothing bounds their product**. A legal ~8 MiB bundle
declaring `MAX_FILE_COUNT` = 16384 and `MAX_UNIT_COUNT` = 65536 with *no reveals at all* forces
~10⁹ iterations in `check_tiling` plus ~10⁹ more in `check_manifest_refs` — the latter for a check
that cannot fail, since `flatten_units` derives `file_id` from the enumerate index rather than
from a wire field. In the browser verifier this is a hang.

Stage 5 running last is *correct* for this format (the manifest is self-signed, so an attacker can
always mint a valid signature over a forged body — an earlier signature check would gate nothing).
The fix is therefore indexing, not reordering. Findings U1 and U3 are the same class in
`file_stages.rs:746` and `bundle/schema.rs:1462`. Recorded as **R54**.

### 7. D28 rationale 3's totality claim is unsound (`medium`)
D28 rationale 3 — inherited verbatim by D74 rationale 3 and D74's wave-6 audit table — claims *"a
third party cannot alter a bundle's reveal shape undetected — strip units and the leak arm fires,
strip salts and the missing arm fires"*. A **consistent** strip fires neither: remove a file's
reveal entries, its `touched_files` entry and its `full_reveals` entry *together* and the bundle
verifies clean (D80 does not fire — no unit of that file is revealed; D82 does not fire — the file
has no touched entry; R4 classifies it `Untouched`).

This is **not a vulnerability** — the bundle is unsigned by design and stripping disclosures
yields a narrower but honest bundle; the verifier correctly reports less. The verifier noted the
stripped bundle is byte-identical to an honest narrower bundle. What is defective is the
**recorded security argument**, which is stated as a totality and is not one, and which two other
decisions now lean on. Recorded as **Q67** (correct the records, do not change code).

### 8. `raw_mirror` is reported for partial reveals that never checked it (`medium`)
`verify/report.rs:416-419` documents `FileReveal::raw_mirror` as a full-reveal-only datum whose
`raw_size` is *"the raw file size"*. Its only producer (`pipeline.rs:929-937`) gates it on
`revealed_ids.contains(unit_id)` alone — while `fully_revealed`, two lines below at 982, *does*
consult `summaries[index].is_full()`. The asymmetry is the bug.

`check_raw_mirror` (rows 9–10) is reachable only from `check_full_reveal_content`, which
`check_file_stages:1161-1163` invokes only for `FileRevealShape::Full`. So on a partial reveal the
report emits a `raw_mirror` whose bytes were never opened against `raw_commit` (no `file_salt`
exists) and never canonicalization-bound — a renderer following the documented meaning presents an
attacker-chosen document as "the original file". Recorded as **R53** with finding 3.

---

## Unverified findings (25)

Reported by a lane, **not** independently re-checked. The five `medium` entries fell below the
verifier cap, not below the bar.

| # | Sev | Location | Claim |
|---|---|---|---|
| U1 | medium | `verify/file_stages.rs:746` | Per-file loops rescan the work-global unit table; ~1.9e10 scans on a *valid* at-cap bundle (same class as finding 6) |
| U2 | medium | `verify/report.rs:276` | M0 anchor stub emits `absent` for anchors that are **present**, now byte-frozen in a `report_version: 1` golden vector — M2 cannot land without a bump or a freeze override |
| U3 | medium | `bundle/schema.rs:1462` | Tier-[X] cross-section rules are Θ(\|noncovered\|×\|covered\|) inside stage 1, which D10 §5 labels O(input) |
| U4 | medium | `bundle/schema.rs:1430` | `*::new` enforces none of the D10 count caps `decode` enforces — "constructible == decodable" is false; the seal side can emit an artifact no verifier can decode |
| U5 | medium | `manifest/body.rs:1003` | Same as finding 4 (`Clone` derive vs three docs) |
| U6 | low | `content/ggm.rs:273` | `NodeAddress` geometry accepts out-of-contract `depth`: overflowing shift (debug panic / masked release value). Unreachable from bundle input — every in-crate call site derives `depth <= 64` |
| U7 | low | `crypto/manifest_aead.rs:44` | The k_m-disclosure argument rests on W-freshness across abandoned→fresh seals, which no spec line mandates (spec:145 requires only a new `seal_id` + fresh nonces) |
| U8 | low | `crypto/disclosure.rs:132` | `unit_salt` disclosure has no structural witness tying it to shipped unit bytes, unlike `file_salt` — offline confirmation oracle if an M3 builder gets it wrong |
| U9 | low | `verify/pipeline.rs:877` | Same as U2, from the pipeline side |
| U10 | low | `verify/pipeline.rs:434` | `EvidenceLayerResult::passed` is hardcoded `true`; a registry-blessed zero-reveal bundle binds zero content bytes and reads as passed |
| U11 | low | `manifest/ids.rs:25` | The recorded no-domain-tag reason is self-contradictory: CBOR uint `0x00` is a canonical v1 item **and** equals `TAG_FINE_TREE_LEAF`; the namesake test asserts a false universal over three cherry-picked items |
| U12 | low | `manifest/body.rs:1197` | `sig_policy`'s no-cap justification is unsound — duplicate-freedom is validated *after* the array is fully materialised; ~16M elements fit inside `MAX_MANIFEST_BYTES` |
| U13 | low | `bundle/schema.rs:530` | Two decode paths silently fix an error precedence no record states (upgrade-group before required-key presence), so a third-party verifier built from registry §7.8 diverges on which code fires |
| U14 | note | `content/fine_tree/verify.rs:212` | Documented error precedence overstates itself: boundary-path shape faults are detected during the fold, i.e. *after* the D83 tail check |
| U15 | note | `crypto/unit_aead.rs:355` | Test-only over-padded mis-encryptor strands an unwiped padded plaintext on the heap (`resize` always exceeds capacity → realloc, old buffer freed unwiped) |
| U16 | note | `crypto/sig_policy.rs:256` | A missing **pubkey** is reported as `crypto-signature-missing-*`; two distinct mutations collapse onto one code |
| U17 | note | `verify/pipeline.rs:343` | `proof_unit_refs` is built from the covered reveals' own ids, so the "references revealed units only" check is a tautology and its `UnknownUnitRef` arm is unreachable |
| U18 | note | `verify/error.rs:642` | `VerifyError::Codec` carries `#[from]` while `Decode`/`Crypto`/`Canon` deliberately do not — one hole in the enum's own "wrapping must be explicit" rule |
| U19 | note | `codec/decode.rs:505` | Two RFC 8949 not-well-formed head classes report `cbor-simple-value`/`cbor-tag` rather than `cbor-malformed`. All still hard-rejected; classification only |
| U20 | note | `codec/decode.rs:626` | Safety comment says `peek_head` "consumed exactly the head bytes"; it consumes nothing (pure probe). Invariant holds for a different reason than stated |
| U21 | note | `codec/decode.rs:13` | Docs say `check_canonical` runs on production envelopes; no production path calls it — strictness comes from the typed pass |
| U22 | note | `codec/caps.rs:478` | Doc claims a `#[cfg(test)]`-private const is used by an integration test; it cannot be, so that test necessarily maintains an independent table |
| U23 | note | `bundle/schema.rs:714` | D78 opacity is stated one-directionally; nothing forbids the receipt payload from restating a registry-visible field with a divergent value |
| U24 | note | `manifest/body.rs:1134` | `ManifestBodyV1::decode` is public and unbounded; D10's no-cap justification holds only for inputs arriving through the envelope |
| U25 | note | `bundle/schema.rs:1193` | `touched_file.path` is unbounded unconstrained free text flowing verbatim into the report (traversal-looking paths, RTL overrides, megabyte strings); no record assigns the sanitisation obligation |

---

## What the lanes positively verified

A clean lane is only meaningful as a falsifiable claim, so each lane was required to state the
invariants it personally established. Condensed highlights:

**`ggm-cover` (14 invariants, no security-bearing finding).** The strongest lane. An independent
Python reimplementation with real SHA-256, exhaustive over all ranges for n ≤ 25–33, reproduced
the builder's `fine_root` end-to-end and confirmed: cover real-spans partition `[a,b)` in
ascending order; the derivable leaf closure of the disclosed seeds is **exactly** `[a,b)`
(puncturing completeness *and* secrecy — no ancestor of an unrevealed real leaf is ever emitted);
`|cover| ≤ max(1, 2⌈log₂ n⌉)`; `s_root` is in the cover iff the range is `[0,n)`. The streaming
binary-counter frontier equals RFC 6962's recursive split for all n in 1..129. The verifier
enforces canonicality by **recomputation-and-equality**, not validity checking, which structurally
excludes every over-broad, overlapping, extraneous, wrong-shape and wrong-set cover. The
ragged-right-edge allowance was re-derived (not taken from the record) and is provably usable only
when a range ends at n. Range/leaf-count inputs come from the **signed manifest**, never the
bundle.

**`aead-kdf` (14 invariants, nothing at medium or above).** All 8 HKDF golden vectors, the AAD
fixture, the padding table and the u128 overflow headroom recomputed independently and matched
bit-for-bit. Nonce single-use is **structural** — no nonce-accepting API exists anywhere (verified
by grep plus a `compile_fail` pin). Decrypt-failure collapse matches D81's recorded argument; the
wasm32 `true_length` saturation cannot flip a verdict; the D76 file-salt split conforms and its
reasoning survives re-derivation.

**`hybrid-sig` (11 invariants).** No false-PASS, downgrade, masking or cross-algorithm-confusion
path exists. The pinned upstream sources were read directly from the registry cache: dalek 3.0.0
`verify_strict` semantics and its ZIP-215 A-encoding gap, ml-dsa 0.1.1 decode-time canonical
rejection, deterministic signing. The D16 pre-validation layer is mathematically correct and fills
exactly the one conformance hole the pinned dalek leaves. Policy enforces present-set == policy-set
with the policy anchored **inside** the signed bytes. One dependence to keep visible: the
NonCanonical-vs-Invalid split rides on ml-dsa 0.1.1 checking the z-norm at decode — stricter than
FIPS 204's letter, which puts it in Verify — so a pin bump must re-check it.

**`verify-order` (15 invariants).** The frozen stage order matches first-principles derivation.
The two load-bearing orderings hold: structural-before-units (making `s_root`'s zero-disclosure
claim true) and units-before-files (R4 consumes verified bytes it never re-derives). Every
bundle-side byte is bound by something inside the signed body except the two named exempt regions
(the 88-byte storage record and, at M0, the anchor artifacts).

**`verify-file-stages` (14 invariants).** The shape predicate, the 2×2 material match, the D20
forced-mode recompute and the check ordering are enforced by control flow and types rather than
convention. No way was found to make a partial reveal open `file_salt`/`s_root`, to pass a
stripped or added material field, or to make the D20 recompute pick the wrong mode.

**`cbor-strict` (14 invariants, clean above `note`).** One shared head validator delivers
truncation-totality, shortest-form enforcement for both integer and length arguments,
indefinite/float/simple/tag rejection, and payload bounds computed in u64 **before** any usize
conversion. Map-key discipline is checked on **encoded bytes**. Recursion is hard-bounded at 10
frames. All schema-side allocations follow D10's frozen head→cap→clamp→elements order with the F30
element-width-aware clamp, traced to every one of the 19 cap constants' enforcement sites.

**`schema-parse` (14 invariants).** Registry pinning is exact in both directions (key/name mapping
re-derived independently against the JSON mirror). Unknown and reserved keys are two distinct
rejections with no lenient path; every conditional-presence rule has both arms. The D78 opacity
boundary is real and type-enforced, drawn in the one place that matters: the embedded manifest
bstr is parsed by exactly one parser over the exact slice that is also the `anchor_digest`
pre-image, with `finish()` on both inner layers, so no bytes hide inside it.

---

## The pattern worth naming

Excluding the mirror cluster, **the dominant defect class in this codebase is not wrong code — it
is recorded claims the code does not implement.** Findings 4, 5, 7, U4, U5, U11, U12, U14, U20,
U21 and U22 are all of this shape: a doc, a decision record, or a safety comment asserts a
structural guarantee (`not Clone`, "re-checked here", "constructible == decodable", "a third party
cannot alter the reveal shape undetected", "consumed exactly the head bytes") that is either false
or true for a different reason than stated.

For a project whose review culture leans this heavily on its own written records, that class is
more dangerous than it looks: each false claim silently disarms the future review that would catch
the corresponding bug. The mirror defect is what happens at the end of that road — D23 decided the
rule, `FileEntry::raw_mirror`'s prose repeated it as though it were enforced, and no layer ever
implemented it.

## Provenance

Workflow run `wf_c2901062-ccd`; per-agent transcripts in the session's
`subagents/workflows/wf_c2901062-ccd/journal.jsonl`. Findings 1–3 were additionally re-verified by
hand against the tree while writing this report (D23:23, `body.rs:694-743`,
`structural.rs:277-283`, `file_stages.rs:1119`, `file_stages.rs:1161-1163`, `pipeline.rs:930`,
`pipeline.rs:982`).
