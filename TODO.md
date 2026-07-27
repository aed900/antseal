# antseal MVP — Adaptive TODO

**Source of truth for scope**: `MVP-SPEC.md` (Revision 2, 2026-07-27 — frozen; `SPEC-REVIEW.md` already folded in). When this list and the spec disagree, the spec wins; flag the conflict, don't silently diverge.
**Source of truth for status**: this file. Full per-task detail (Do / Accept / Notes / spec line refs) lives in `tasks/{P,F,C,G,S,A,R,U,Q}.md` — one file per domain, task IDs are stable and permanent.

Generated 2026-07-27 by a 9-agent decomposition of the spec + 2-agent adversarial coverage/consistency verification. **219 tasks** (0 XL, ~27 L, rest S/M), **~73 open decisions**, 6 milestone gates.

| Domain | Prefix | Scope | Tasks |
|---|---|---|---|
| Setup & toolchain | P | naming, repo, workspace, pins, CI skeleton, devnets | 19 |
| Formats | F | deterministic CBOR, manifest/bundle codecs, parser hardening | 17 |
| Crypto primitives | C | HKDF, AEAD, salted commitments, hybrid signatures | 21 |
| Content model | G | canonicalization, units, raw mirror, GGM fine tree | 20 |
| Storage | S | StorageBackend, payments, journal/resume, restore | 20 |
| Anchors | A | OTS, RFC 3161, receipt classification, verdict states | 26 |
| Reveal & verify | R | bundle build, verification pipeline, verifier web page | 28 |
| CLI & vault | U | command surface, vault, config, UX | 32 |
| Quality & release | Q | test infra, CI, threat model, docs, release | 36 |

---

## How to use this list (the adaptive protocol)

1. **Statuses** on the checkbox lines here (never in `tasks/*.md`):
   - `- [ ]` todo · `- [x]` done (append `✅ YYYY-MM-DD`) · append `⏳ WIP` while in progress · append `⛔ <blocker>` when blocked.
   - Never delete a task: strike it through (`~~…~~`) with a one-line reason and date. Renumbering is forbidden — IDs are referenced everywhere.
2. **Discovering new work**: take the next free number in the owning domain (e.g. `F18`), write the full entry (Milestone/Size/Deps/Spec/Do/Accept) in `tasks/<domain>.md`, add its checkbox line under the owning milestone here.
3. **Decisions**: when a Decision-register entry (below) is resolved, check it, record the outcome + date inline, and update the blocked tasks' detail entries. Decisions are as first-class as tasks — an unresolved decision past its due milestone is a blocker.
4. **Milestone gates**: a milestone is done only when its gate checklist passes — the gate, not the task count, is the exit criterion. Run the gate, record evidence, then move the Current-focus block forward.
5. **Re-verification triggers** (adaptive part — these mutate the list):
   - any `ant-core`/`self_encryption` bump → re-run S1 survey + S9 pinning + devnet E2E; adapter changes confined per S20.
   - any RUSTSEC advisory on a pinned crypto crate → P13/Q10 lane red → decision entry + possible new tasks.
   - upstream weekly check (P19/Q36) findings → new tasks under the affected domain.
   - any spec revision → re-derive the affected section's tasks before coding against it.
6. **Milestone fidelity**: spec-assigned milestones are normative. Where a milestone was inferred (mostly U; noted per task), it may move with a recorded reason; spec-assigned ones may not.
7. **Deps discipline**: Deps lines in `tasks/*.md` list true predecessors only; consumer/interface mentions belong in Notes or carry an explicit "consumer, not a dep" annotation. Where prose and this file disagree on ordering, **the `after:` lists on the checkbox lines here are the authoritative build order** (verified acyclic).

---

## Current focus

> **Phase: M0 — wave 1 executed 2026-07-27** (6-agent run): P9 ✅ P10+F1 ✅ S1 ✅ C1–C4 ✅ G1 ✅ R1 ✅; Q1 ⏳ (workflow done + locally verified; remote run maintainer-blocked). D7/D11/D12/D25/D27 resolved; D29 recommended (freeze at Q14); D32/D33/D37 inputs captured. Full local gate green post-integration: fmt/clippy/test (54 tests)/wasm32/core-dep-graph.
> **Next wave (unblocked now)**: F2→F3 (canonical encode + strict decode on the minicbor pin) · C5 (needs zeroize + rand_core pins; getrandom wasm recipe interacts with P14) → C6→C7/C8/C9 · C11 probe (+P11/P12 pins, D13/D14) · G2 (needs D20/D21 frozen first — decision-first) · Q2/Q3/Q4 (testdata conventions, proptest, vector framework) · F4 registry drafting (address length now pinned: 32 B) · P13 (deny.toml — remember minicbor's BlueOak-1.0.0 allowlist entry) · R2 (lands the C/G wrapper arms in VerifyError).
> **D1 RESOLVED 2026-07-27: `antseal` maintainer-confirmed final** — P2/P3 are now executable and name-bearing work (C12/F4/U1) is unblocked on the name.
> **Maintainer actions**: (1) **P2 — promptly**: `cargo login` then `scripts/reserve-crates.sh --execute` (all 5 names re-verified FREE + dry-run green 2026-07-27 ~18:58Z; availability decays); (2) **P3 — promptly**: register antseal.org (primary) + antseal.dev (defensive), auto-renew on (both re-verified FREE ~18:58Z; docs/naming/P3-domain-registration.md); (3) `gh auth refresh -h github.com -s workflow` then `git push origin main` → confirm 13 CI lanes green (3-OS matrix) → wasm-guard probe → THEN branch protection per docs/ci-verification.md runbook (P8+Q1); (4) optional courtesy: file docs/naming/upstream-blessing-request.md at WithAutonomi/ant-client (nothing waits on it).

## Critical path

P1 → P4/P5/P6/P8 → **M0**: [P10+F1 CBOR pin] → F2→F3→F4/F5→F6→F7 · C11 probe → C12/C13→C14 · G1→G2 · C1/C2→C6 · G8→G9→G11→G12→G13 → R1→R5 → vectors (F12/F13, C16, G15, R9) → F14/Q11 independent cross-check → **Q14 format-v1 freeze** → **M1**: S2→S3/S4/S6 · U5→U6→U9 · S12/U13 pipeline → S17/S18/S19 E2E → **M2**: A5→A8→A9 · A11→A13→A14 · A18 → A21/A22 + A25 smoke · U22 gate → **M3**: R13→R16 · R17→R18 · R22→R23→R25→R26 · R27 → **M4**: Q30→Q31→Q32→Q33→**Q34 release**.

The M0 freeze (Q14) is the single most consequential gate: everything frozen there (formats, tags, labels, Unicode version, context string, sig-policy IDs) is permanent once the first real seal exists.

---

## Pre-M0 — naming, repo, toolchain (8 tasks)

Gate: name decided + propagation checklist owned; crates.io names reserved; verifier domain registered; repo pushed; workspace scaffold + toolchain pin + pin policy committed; CI skeleton green (fmt/clippy/test/wasm32).

- [x] **P1** (M) Finalize the product name — upstream blessing for `ant-` prefix or non-ant rename; propagation checklist (context string, format strings, binary/dir, crates, domain) ✅ 2026-07-27 — **`antseal` maintainer-confirmed FINAL** (third path: no upstream blessing — deviation + residual risk recorded in D1 doc; blessing request now optional courtesy; fallback retired); propagation checklist committed with owners (docs/naming/propagation-checklist.md)
- [ ] **P2** (S) Reserve crates.io names (placeholder publishes; re-verify availability) — after P1 ⛔ `cargo login` (maintainer) then `scripts/reserve-crates.sh --execute` — D1-final cleared 2026-07-27; availability re-verified same day ~18:58Z: all 5 names FREE + dry-run green (kit: docs/naming/P2-crates-reservation-runbook.md). **Execute promptly — availability decays**
- [ ] **P3** (S) Check and register the verifier domain — after P1 ⛔ registrar/payment (maintainer) — D1-final cleared 2026-07-27; antseal.org + antseal.dev re-verified FREE same day ~18:58Z (RDAP 404); plan: docs/naming/P3-domain-registration.md. **Register promptly — availability decays**
- [x] **P4** (S) Git init, initial commit (specs), remote hosting + platform decision ✅ 2026-07-27
- [x] **P5** (M) Cargo workspace scaffold exactly per Architecture tree (4 crates + verifier-web + testdata; lints; lockfile) — after P4 ✅ 2026-07-27
- [x] **P6** (S) Pin Rust toolchain, wasm32 target, edition/MSRV — after P4 ✅ 2026-07-27
- [x] **P7** (S) Dependency pin-governance policy + lockfile discipline (`--locked` CI; bump = deliberate event) — after P5 ✅ 2026-07-27
- [ ] **P8** (M) CI skeleton: fmt/clippy/test + wasm32 build lane + core dep-graph assertion — after P4,P5,P6 ⏳ WIP — workflow committed, all 5 lanes green locally 2026-07-27 (docs/ci-verification.md) ⛔ push rejected: gh token lacks `workflow` scope — maintainer: `gh auth refresh -h github.com -s workflow`, then `git push` + green run + wasm-guard probe

## M0 — Core formats & crypto (88 tasks) — ends at the **format-v1 freeze**

Gate = **Q14 checklist**: Definitions frozen (CBOR profile+pin, domain tags, id encodings, HKDF info encoding, Unicode version, signature context string); all M0 golden vectors committed + frozen (incl. empty-anchor + unbalanced n=6); independent cross-check (Q11) clean; M0 tamper registry (Q8) fully implemented; HKDF pairwise-distinctness test green; WASM bit-match green; ML-DSA probe decision recorded; Security-assumptions sign-off; traceability M0 rows filled; annotated `format-v1-freeze` tag.

### Pins & probes (P)
- [x] **P9** (S) Re-verify + land `ant-core = "=0.5.0"` pin at M0 start (spec-mandated) ✅ 2026-07-27 — KEEP 0.5.0 (crates.io newest, not yanked, upstream HEAD ≡ tag); self_encryption locks 0.36.0; pin = workspace declaration only, lock unchanged (docs/upstream/P9-ant-core-reverification.md)
- [x] **P10** (M) Select + exact-pin the deterministic-CBOR encoder crate (joint with F1) ✅ 2026-07-27 — `minicbor = "=2.3.0"` (D7); cross-check nominee `cbor2 ==6.1.3` (D12)
- [ ] **P11** (S) Decide + pin `ed25519-dalek` (2.x vs 3.0.0) — with C11
- [ ] **P12** (S) Pin `ml-dsa =0.1.1` + `fips204 =0.4.6` with RUSTSEC advisory assessment
- [ ] **P13** (S) RUSTSEC advisory tracking lane (cargo-deny/audit, weekly schedule)
- [ ] **P14** (M) WASM toolchain: getrandom js/wasm_js recipe, wasm-pack/wasm-bindgen pins, wasm32 test execution

### Formats & parser hardening (F)
- [x] **F1** (M) Evaluate + pin the CBOR crate against RFC 8949 §4.2.1 + strict-decode feasibility (joint P10) ✅ 2026-07-27 — every line-73 rejection class implementable on minicbor's public probes (13 live eval tests: crates/antseal-core/tests/cbor_pin_eval.rs); derive off, F5–F9 manual impls
- [ ] **F2** (M) Canonical CBOR encode layer (shortest forms, definite lengths, sorted integer keys) — after F1
- [ ] **F3** (L) Strict canonical decode layer — hard-reject every non-canonical class, distinct errors, outer+inner layers — after F1,F2
- [ ] **F4** (M) Frozen v1 wire-format registry: every map key, type, presence rule, byte length, reserved slots — with C/G/A/S inputs
- [ ] **F5** (M) Manifest body schema types + parse-time presence/shape validation (sig_policy, unit_commit-iff-not-covered, canon_commit/fine_root rules) — after F3,F4
- [ ] **F6** (M) Manifest envelope codec `{body: bstr, signatures}` — body-as-received, verifiers never re-encode — after F2,F3,F5
- [ ] **F7** (S) `work_id` + `anchor_digest` as two distinct functions/newtypes; `manifest_hash` identifier banned — after F6
- [ ] **F8** (L) `.sealproof` bundle schema types + parse-time shape validation (every line-112–114 content item; v1.1 slots reserved) — after F3,F4
- [ ] **F9** (M) Bundle codec with three-layer nested strict decoding, deterministic encode — after F6,F8
- [ ] **F10** (M) Version fields, per-version decode dispatch, reserved-slot mechanics, per-version vector layout — after F4,F5,F8,F9
- [ ] **F11** (M) Parser resource caps + allocation bounding (size/count/depth; clamp to remaining input) — after F3,F5,F8,F9
- [ ] **F12** (M) Manifest golden vectors (per-version, native/WASM bit-match) — after F6,F7,F10
- [ ] **F13** (M) Bundle golden vectors incl. the empty-anchor (UNANCHORED) vector — after F9,F10,F12
- [ ] **F14** (M) Independent-CBOR cross-check artifact (second implementation; freeze gate input) — after F4,F12,F13
- [ ] **F15** (M) Format-level tamper fixtures: 4 non-canonical-body rows + oversized/deep + full line-73 class coverage — after F3–F12
- [ ] **F16** (M) Codec property tests: round-trip, determinism, canonicality, mutation classes — after F5–F11
- [ ] **F17** (M) cargo-fuzz targets: manifest decode, bundle decode, round-trip — after F6,F9,F11–F15

### Crypto primitives (C)
- [x] **C1** (S) Hash domain-tag registry 0x00–0x06, single module, `tagged_sha256` helper ✅ 2026-07-27 — crypto/domain.rs; grep test enforces single tag site (bite verified)
- [x] **C2** (M) HKDF-SHA256 with length-prefixed injective info encoding + full 8-label registry + sentinel id ✅ 2026-07-27 — typed per-label API only; sha2 =0.11.0 / hkdf =0.13.0 / hmac =0.13.0 pinned; RFC 5869 reference cross-checked; W seam → C5 (`MasterSecretRef`)
- [x] **C3** (S) HKDF golden test: pairwise-distinct infos (spec-mandated) + derivation vectors — after C2 ✅ 2026-07-27 — pairwise test + 10k-case proptest injectivity; vectors from an independent Python impl matched byte-for-byte (testdata/vectors/hkdf/); vector test opted into the cross-OS lane; **rider**: wasm bit-match execution joins Q5's harness
- [x] **C4** (S) Crypto error taxonomy (thiserror, distinct variants, secret-redaction discipline) ✅ 2026-07-27 — exact 15-variant set; distinctness + no-byte-content Display tests; `#![deny(clippy::unwrap_used)]` over the crypto tree
- [ ] **C5** (S) `MasterSecret` (W) + `SealId` types: CSPRNG generation, ZeroizeOnDrop, redacted Debug — after C4
- [ ] **C6** (M) Four salted commitments (unit/path/raw/canon) + `Salt16`/`Seed32`/`NodeHash32` length-checked newtypes — after C1,C2,C4,C5
- [ ] **C7** (M) Type-system enforcement: `unit_commit` iff not-covered (`UnitBinding`); `file_salt` reachable only via full-reveal constructor — after C5,C6
- [ ] **C8** (S) Unit padding codec: `padded_length` formula, apply, length-first strip, two distinct rejections — after C4
- [ ] **C9** (M) Unit AEAD: k_u, XChaCha20-Poly1305, AAD = seal_id‖LE64(unit_id), internal fresh nonce, no caller-nonce API — after C2,C4,C5,C8
- [ ] **C10** (S) Manifest encryption k_m (sentinel label, empty AAD) + storage-record values — after C2,C5,C9
- [ ] **C11** (M) M0 signature-crate probe: ml-dsa wasm32 viability, ctx support, canonical-rejection evidence, dalek pin decision — gates C12–C16
- [ ] **C12** (M) Ed25519 strict signing/verification with frozen context prefix `ctx‖0x00‖body`; NonCanonical vs Invalid distinct — after C2,C4,C11
- [ ] **C13** (M) ML-DSA-65 signing/canonical-strict verification with FIPS-204 ctx; pre-validation layer if crate is lax — after C2,C4,C11
- [ ] **C14** (M) `sig_policy` validation + hybrid orchestration: present-set == policy-set, four hard-fail classes, Ed25519-only fallback path — after C12,C13
- [ ] **C15** (M) Committed reject-vector suites for both algorithms (S≥L, small-order, hint/z bounds, wrong-ctx…) — after C12–C14
- [ ] **C16** (L) Crypto golden vectors + independent-implementation cross-check (HKDF, commitments, AEAD, signatures) — after C2,C6,C8–C10,C14
- [ ] **C17** (M) M0 crypto tamper rows (wrong salt/key, lengths, 4 sig_policy rows, non-canonical sigs, over-padded) + distinctness meta-test — after C6–C9,C14,C15
- [ ] **C18** (M) Crypto property tests (injectivity, commitment exactness, padding, AEAD, hybrid round-trip) — after C2,C6,C8–C10,C14
- [ ] **C19** (S) Adversarial confirmation-attack doc-tests (unsalted-unit + unsalted-file-hash variants) — after C6
- [ ] **C20** (S) Author the frozen Security-assumptions block content (→ Q12 skeleton; sign-off recorded) — after C6,C8,C9,C14
- [ ] **C21** (S) Zeroization coverage audit + WASM browser-memory caveat — after C5,C9,C10,C12,C13

### Content model (G)
- [x] **G1** (M) Pin Unicode/NFC data version; ship normalization table in core; version-dispatch registry (retained forever) ✅ 2026-07-27 — `unicode-normalization =0.1.25` = Unicode 17.0.0 (verified from crate bytes, machine-asserted); descriptor string `unicode-17.0.0`; add-only registry + `UnknownUnicodeVersion` (D25)
- [ ] **G2** (M) Canonicalization v1: detection, BOM/EOL/NFC pipeline, `canonicalize_v`, idempotent, total under --force-text — after G1
- [ ] **G3** (M) UTF-8 corpus with golden canonical outputs (CRLF, NFD/NFC, BOM, emoji/ZWJ, mixed scripts) + cross-platform stability — after G2
- [ ] **G4** (S) Canonicalization descriptor struct + construction logic + cross-field validation — after G2
- [ ] **G5** (M) Unit model: work-global LE64 unit_id assignment, size semantics, `is_fine_tree_covered` predicate — after G4
- [ ] **G6** (M) `--split blank-lines` with frozen boundary semantics; sorted/non-overlapping/exact-tiling output — after G2,G5
- [ ] **G7** (M) Raw-mirror model: detection, entry construction, tiling/concat exemptions, bare-`--units` rejection rule — after G2,G5
- [ ] **G8** (M) GGM salt-tree derivation: 0x06 children, MSB-first indexing, 16-B leaf salts, node-address type — after G5
- [ ] **G9** (L) Streaming fine-tree construction O(log n) + `rebuild_fine_root`; 5–7 compressions/byte instrumented — after G2,G4,G8
- [ ] **G10** (S) Fine-tree cost estimator (for seal's printout) — after G9
- [ ] **G11** (M) Leaf-exact minimal GGM sub-cover; no-ancestor-of-unrevealed-leaf by construction; s_root iff full range — after G8
- [ ] **G12** (M) Range-proof generation; `prove_unit` = leaf-aligned range opening through the same machinery — after G9,G11
- [ ] **G13** (M) Range-proof verification against `fine_root`: leaf-exact cover enforcement, 7 distinct errors, defensive — after G8,G9,G11
- [ ] **G14** (M) Pure seal-side ContentModel assembly (files+flags → descriptors/units/mirrors/fine_roots) — after G2,G4–G7,G9
- [ ] **G15** (M) Fine-tree golden vectors: unbalanced n=6 pinning MSB-first + n=1/n=0/n-past-power-of-two — after G8,G9,G11,G12
- [ ] **G16** (S) Leaf-exact-cover disclosure test (n=6 reveal {2}; spec-mandated) — after G8,G11
- [ ] **G17** (M) E2E: leaf-aligned AND arbitrary byte-range openings both verify against fine_root; covered units carry no unit_commit — after G12,G13,G14
- [ ] **G18** (M) Perf/memory budget tests (structural O(log n) bound; compressions/byte envelope) — after G9,G10
- [ ] **G19** (S) Fine-tree tamper rows: covered-unit byte flip → RootMismatch; over-broad cover → OverBroadCover — after G13,G17
- [ ] **G20** (M) Consolidated content-model property suite (seeded, committed regressions) — after G2,G6,G9,G11–G13

### Storage survey (S)
- [x] **S1** (M) Re-verify ant-core 0.5.0 + survey exact payment/storage API shapes (written memo; feeds F4 address length, S2/S6/S7) ✅ 2026-07-27 — memo with source citations (docs/research/S1-ant-core-api-survey.md); address = 32 B BLAKE3 (D11); D32/D33/D37 inputs captured; external-signer flow recommended primary; GO on the pin

### Verification pipeline core (R)
- [x] **R1** (M) `VerificationReport` model + `VerifyError` taxonomy (deterministic serialization; every line-121 invariant a distinct variant) ✅ 2026-07-27 — 19 variants / 30 distinct stable codes; byte-deterministic JSON + pinned snapshot fixture; D27 resolved, D29 recommended; **rider**: C/G/F/A wrapper arms land with R2/F3/A-stage (documented extension point, compile-enforced)
- [ ] **R2** (M) Per-unit evidence stages: decrypt → padding verify/strip → true_length binding → content-binding dispatch (fine_root vs unit_commit) — after R1
- [ ] **R3** (M) Structural checks: exact lengths, referential integrity, tiling invariant (+mirror exemption), path_commit — after R1
- [ ] **R4** (L) Reveal-shape classification + file-level checks: partial-reveal isolation, full-reveal concat + fine-tree rebuild, raw-mirror canonicalize(raw)==canonical — after R2,R3
- [ ] **R5** (M) `verify_bundle` orchestration (decode → structural → units → files → sigs → anchors-stub) — after R1–R4
- [ ] **R6** (M) Test-only bundle fixture constructor (every M0 shape, seeded/deterministic) — after R1
- [ ] **R7** (L) M0 structural tamper-fixture suite — every line-121 row with its distinct error + positive leaf-exact-cover fixture — after R5,R6
- [ ] **R8** (M) Pipeline-integration tamper rows (flipped ciphertext, wrong key, swapped unit, altered manifest field both routes) — after R5–R7
- [ ] **R9** (M) Verification golden vectors: bundle → expected report, native/WASM bit-match, every M0 shape — after R5,R6
- [ ] **R10** (S) `verify_bundle` no-panic fuzz + property coverage — after R5,R6

### Shared infrastructure & freeze (Q)
- [ ] **Q1** (M) Extend CI skeleton to full M0 matrix + multi-OS corpus/vector lane (+ mount points for later lanes; branch protection) ⏳ WIP — workflow extended 2026-07-27: 13 lanes (3-OS `corpus_`/`vector_` suites + 5 mount points), locally verified; `.gitattributes` fixture guard ⛔ remote run + branch protection blocked on the P8 push blocker; protection deliberately deferred until after the first green remote run (runbook: docs/ci-verification.md)
- [ ] **Q2** (S) `testdata/` layout + fixture conventions + no-real-secrets CI guard — after Q1
- [ ] **Q3** (S) proptest conventions + shared strategy helpers — after Q2
- [ ] **Q4** (M) Golden-vector framework (schema, discovery, native runner) — after Q1,Q2
- [ ] **Q5** (M) WASM/native bit-match harness + required CI lane — after Q1,Q4
- [ ] **Q6** (S) Vector freeze + indefinite per-version retention (FROZEN.sha256; must-exist list) — after Q4
- [ ] **Q7** (M) Tamper-matrix harness: distinct-outcome assertion, no-panic rule, error-code contract — after Q1,Q2
- [ ] **Q8** (S) Tamper-matrix completeness registry vs the spec's M0 row list (CI-enforced 1:1) — after Q7
- [ ] **Q9** (M) cargo-fuzz infra: smoke lane per PR + nightly + corpus management — after Q1,Q2
- [ ] **Q11** (L) Independent-implementation cross-check (CBOR + crypto + GGM + Ed25519; ACVP for ML-DSA) — freeze blocker — after Q4,Q6
- [ ] **Q12** (S) Threat-model skeleton with frozen Security-assumptions block + sign-off — after C20
- [ ] **Q13** (M) Verification-coverage traceability matrix (spec lines 165–175 → test IDs; CI-checked) — after Q4,Q7,Q8
- [ ] **Q14** (S) Execute the M0 format-freeze gate; annotated `format-v1-freeze` tag — after Q5,Q6,Q8,Q11,Q12,Q13 + P9/P10 + C3/C11 + F4 + G1

## M1 — Storage (45 tasks)

Gate: scripted devnet E2E green (S17); kill/resume matrix green incl. real SIGKILL, no-double-pay Anvil-verified (S18); clean-tree restore from vault backup only (S19); UNANCHORED library-verify via A1; `init`/`seal --no-anchor`/`list`/`restore`/`vault export|import` working end-to-end; secret-hygiene harness (U21) green; `--no-anchor`×mainnet rejection proven at CLI and pipeline levels.

### Environments & pins (P)
- [ ] **P15** (S) Pin `self_encryption` to ant-core's exact locked version; verify WASM-safety — after P9,P14
- [ ] **P16** (M) Local devnet environment scripts (start-local-devnet: 25 nodes + Anvil) + machine-readable env surface — after P5,P9
- [ ] **P17** (M) Arbitrum-Sepolia devnet environment (chain 421614) + funding runbook — after P5,P9,P16

### Storage & pipeline (S)
- [ ] **S2** (M) Batch-first `StorageBackend` trait + Blob/CostQuote/PaymentReceipt/Address types; churn-boundary enforcement — after S1
- [ ] **S3** (M) `MockBackend` with fault injection + call-order logging — after S2
- [ ] **S4** (L) Deterministic self_encryption address recomputation in antseal-core (WASM-safe; seal-time + linkage-layer primitive) — after S1,P15
- [ ] **S5** (M) Network mapping arbitrum-one/arbitrum-sepolia/devnet → chain/contracts/RPC/peers + wallet keygen/import-validation/address ops (for U11) — after S1,P16
- [ ] **S6** (L) `AntCoreBackend` over prepare→pay→finalize in ONE adapter file; never data_upload/chunk_put — after S1,S2,S4,S5
- [ ] **S7** (M) PaymentReceipt completeness (tx hashes, block number, quote preimages, proof_bytes) + instant-capture semantics — after S1,S2,S6
- [ ] **S8** (M) ANT+ETH balance queries + preflight with distinct InsufficientAnt/InsufficientGas; true-complete-quote guarantee — after S2,S5,S6
- [ ] **S9** (M) Pin MAX_CHUNK_SIZE + self-encryption thresholds against the real API (size-ladder devnet test) — after S4,S6,P16
- [ ] **S10** (M) Seal journal: staged ciphertext BYTES + nonces + addresses before payment; state machine; durable ordering — after S2,S4,S7,U9
- [ ] **S11** (L) Resume: byte-identical re-upload, finalize with recorded receipt, abandon guard (never re-encrypt under a journaled nonce) — after S6,S10
- [ ] **S12** (L) Seal pipeline orchestration in exact normative order; ciphertext-only egress; fault-injection barriers — after S2,S4,S7,S8,S10 + G14/C/F
- [ ] **S13** (S) `--no-anchor` zero-anchor path + pipeline-level arbitrum-one rejection — after S12 + A1/F13
- [ ] **S14** (M) `restore` engine: fetch, decrypt, verify commitments, write originals (raw-mirror preferred) — after S5,S6
- [ ] **S15** (S) `--live` persistence primitive: re-fetch + byte-compare, structured per-blob report — after S6 (R11 consumes)
- [ ] **S16** (M) Mock-level pipeline invariant matrix (every barrier: ordering, idempotency, no-double-pay, abandon) — after S3,S10–S12
- [ ] **S17** (L) M1 E2E on devnet via library APIs: multi-file --split seal, restore, UNANCHORED verify, --live — after S6,S12–S15 + P16 + R5
- [ ] **S18** (L) M1 kill/resume matrix on devnet: pay/finalize kill, mid-upload kill, changed-source abandon, real SIGKILL — after S11,S16,S17
- [ ] **S19** (M) Clean-tree restore from vault backup only (E2E) — after S14,S17 + U12

### Anchor stub (A)
- [ ] **A1** (S) Zero-anchor seal contract + minimal `absent`/UNANCHORED aggregate path (pre-M2 state machine) — after F13

### Verify-side live check (R)
- [ ] **R11** (S) Library live-check wrapper over S15 (manifest-shaped for M1; bundle-shaped at M3) — after S15

### CLI & vault (U)
- [ ] **U1** (M) `antseal-cli` scaffold with the FULL canonical clap surface frozen day one (later commands stubbed) — after P5, P1
- [ ] **U2** (M) Exit-code scheme + thiserror CLI error taxonomy (distinct token/gas/anchor/vault/resume codes) — after U1
- [ ] **U3** (M) `--json` framework: one-document contract, schema registry per command, non-TTY rules — after U1,U2
- [ ] **U4** (M) Config file: network mapping + TSA/endpoint override slots; precedence flag>config>default — after U1,U5
- [ ] **U5** (M) Vault store layout, versioned header, atomic writes + lockfile — after U1
- [ ] **U6** (M) Vault encryption: Argon2id m≥256 MiB t=3 p=1 / scrypt N≥2²⁰, 16-B salt, KDF header bound as AAD (downgrade = auth failure) — after U5
- [ ] **U7** (M) Passphrase UX: no-echo prompts, strength floor, non-interactive supply, zeroizing buffers — after U6
- [ ] **U8** (M) Optional keyfile / OS-keystore wrap for W (recorded in AAD-bound header) — after U6,U7,U11
- [ ] **U9** (L) Per-work record store: W, journal area, receipts (atomic fsync write), anchors, paths, costs; read APIs — after U5,U6
- [ ] **U10** (S) Arbitrum wallet key under its own vault sub-key; narrow accessor — after U6,U9
- [ ] **U11** (M) `init`: vault create, wallet generate/import, address + funding instructions, network config — after U4,U6,U7,U9,U10
- [ ] **U12** (M) `vault export`/`import` (single encrypted backup; incomplete works survive) — after U5,U6,U9
- [ ] **U13** (L) `seal` orchestration in exact normative order (M1 scope: `--no-anchor` only; anchored path errors "arrives in M2") — after U2,U3,U9,U11,U14 + S12
- [ ] **U14** (M) Permanence-consent gate: file list, byte totals, true complete quote, both balances, exact permanence wording, --yes — after U2,U3,U13(interface) + S8
- [ ] **U15** (S) Seal warnings: title visibility, --no-fine-tree permanence, fine-tree cost estimate — after U13 + G10
- [ ] **U16** (S) `seal --dry-run`: all cheap steps + quote, zero side effects, zero vault mutation — after U13–U15
- [ ] **U17** (M) Resume/abandonment UX: resume plan, re-consent pre-pay, loud safety aborts — after U9,U13,U14 + S11
- [ ] **U18** (S) Vault loss/theft double nag + first-seal export nag — after U12,U13
- [ ] **U19** (M) `list`: states (complete/incomplete/abandoned/UNANCHORED), per-work cost — after U3,U9
- [ ] **U20** (M) `restore` CLI wiring (output dir policy, per-file verification report) — after U2,U3,U9 + S14
- [ ] **U21** (M) Secret-hygiene harness: sentinel secrets never appear in stdout/stderr/logs/JSON at any verbosity — after U2,U7,U9,U10,U13

### CI strategy (Q)
- [ ] **Q15** (M) Devnet E2E execution strategy (CI job vs scripted local gate; log capture) — after Q1 + S17

## M2 — Anchors (35 tasks)

Gate: anchor golden vectors + wasm32 bit-parity green (A22 — spec's explicit M2 exit criteria); all 7 anchor tamper rows implemented + registered (A21/Q18); real-endpoint smoke incl. two-day OTS pending→upgraded cycle complete (A25); minimum-anchor gate live in `seal` with abort-before-payment proven (U22/A20); `status --upgrade` + opportunistic hook + `list` nags working (U23–U25); DER/`.ots` fuzz targets in CI (A23/Q17).

### Pins (P)
- [ ] **P18** (S) Pin `opentimestamps = "=0.2.0"` scoped codec-only; wasm32 viability check — after P7,P14

### Anchors (A)
- [ ] **A2** (M) Anchor artifact + verdict data model (7 states, eligibility flags, OnlineEvidence inputs) — after A1
- [ ] **A3** (S) `antseal-anchor` crate scaffold + HTTP substrate (timeouts, retries, typed errors)
- [ ] **A4** (S) DER `TimeStampReq` constructor (messageImprint = anchor_digest, nonce, certReq) — after A2
- [ ] **A5** (M) Strict-DER parsing: TimeStampResp/CMS/TSTInfo/X.509 with hard caps; BER rejected distinctly — after A2 + D-A8 pins
- [ ] **A6** (M) Pinned TSA root store: versioned, compiled into core, injection API for tests — after A5 (built with test roots; real roots land via A7)
- [ ] **A7** (S) Collect real TSA root certs with verified provenance (FreeTSA P-384 chain, DigiCert, alternates per D-A5) — with A6
- [ ] **A8** (L) CMS SignedData verification: signed attrs, messageImprint, nonce, ESSCertID(v2), critical EKU; RSA + ECDSA P-384 — after A5
- [ ] **A9** (L) X.509 single-path validation to pinned roots with genTime LTV (valid-at-stamping-cert-since-expired distinct) — after A6,A8
- [ ] **A10** (M) TSA HTTP capture client with immediate in-core verification (only verifying tokens count toward the gate) — after A3,A4,A8,A9
- [ ] **A11** (M) `.ots` codec wrapper: strict limits, op execution, digest-commitment check — after A2,P18
- [ ] **A12** (S) Embedded Bitcoin header offline check → `attested` (never headline-eligible offline) — after A11
- [ ] **A13** (M) OTS calendar submission client (≥2 calendars, merged pending `.ots`) — after A3,A11
- [ ] **A14** (L) OTS upgrade polling + attestation merge + upgrade-time header embed (must-agree fetched) — after A11–A13,A16
- [ ] **A15** (M) Opportunistic upgrade engine (bounded budget, never fails host command) + `status` data backend — after A14
- [ ] **A16** (M) Must-agree two-endpoint primitive + esplora pair (blockstream.info + mempool.space) — after A3
- [ ] **A17** (M) Arbitrum two-RPC tx confirmation — advisory only, never an anchor — after A3,A16 + S7
- [ ] **A18** (M) Per-anchor verdict state machine `evaluate_anchors` (pure; verify_at parameter; per-anchor states + eligibility for R — aggregation is R17's) — after A2,A8,A9,A11,A12,A16,A17
- [ ] **A19** (S) Receipt classification: SupportingEvidence class, never headline, unaffected by online confirmation — after A2,A17,A18
- [ ] **A20** (M) Anchor submission orchestrator + minimum-anchor gate (≥1 verified TSA or abort pre-payment; --force-degraded; --no-anchor rules) — after A1,A10,A13
- [ ] **A21** (L) M2 anchor tamper matrix: all 7 rows with distinct outcomes — after A8,A9,A11,A12,A18,A24
- [ ] **A22** (M) Anchor golden vectors + wasm32 verification parity — the spec's M2 exit criteria — after A18,A21,A25
- [ ] **A23** (M) cargo-fuzz targets for TimeStampResp + `.ots` parsers — after A5,A11
- [ ] **A24** (M) Mock TSA / mock calendar / stub esplora+RPC servers for CI (no real endpoints in CI) — after A3,A6
- [ ] **A25** (M) Real-endpoint smoke runs + record canonical fixtures (two-day OTS cycle; FreeTSA P-384 + DigiCert proven) — after A10,A13,A14,A16,A17
- [ ] **A26** (S) TSA root-store versioning + update process (append-only; release checklist hook) — after A6,A7 → continuous

### Verify integration (R)
- [ ] **R12** (S) Wire the anchor stage into `verify_bundle` (replaces M0 stub; receipt → supporting-evidence slot) — after R5 + A18

### CLI (U)
- [ ] **U22** (M) Wire anchor stage into seal: ≥1-TSA-or-abort before pay, --force-degraded, degraded reporting — after U13 + A20
- [ ] **U23** (M) `status <work-id> [--upgrade]` — after U3,U9 + A15,A18
- [ ] **U24** (M) Opportunistic OTS upgrade hook on EVERY CLI invocation (never delays/fails host command; no prompt) — after U1,U5,U9,U23 + A15
- [ ] **U25** (S) `list` pending-anchor nags (only-strong-anchor-pending rule) — after U19,U23
- [ ] **U26** (S) TSA-list override from config into the anchor stage — after U4,U22

### CI (Q)
- [ ] **Q16** (M) Anchor CI lanes (mock-only; no-real-network policy) + real-smoke runbook — after Q1,Q13 + A24
- [ ] **Q17** (S) Fuzz lanes extended with DER + `.ots` targets — after Q9 + A23
- [ ] **Q18** (S) M2 anchor rows registered in the tamper-matrix tracker; combined distinctness re-run — after Q7,Q8 + A21

## M3 — Reveal + verifier (21 tasks)

Gate: R27 suite green — reveal subset verified offline via CLI AND page (playwright) with string-identical verdicts, zero-network page run, endpoint-disagreement case on both; verdict wording snapshot-frozen (R18); redaction view complete (R19); page reproducible build with published hash (R25) and deployed at the canonical URL (R26); `show`/`reveal`/`verify` commands complete (U27–U30).

### Reveal & page (R)
- [ ] **R13** (L) Bundle builder (pure, self-verifying; generation-side isolation by construction; exact per-shape content sets) — after R5,R6 + C7,G11,G12,F9
- [ ] **R14** (M) Builder property tests (isolation, mirror rules, path discipline; independent ancestor-checker) — after R13
- [ ] **R15** (S) Disclosure-preview computation (rows + totals + mirror-rides-along; consumed by reveal and `show`) — after C9 + U9
- [ ] **R16** (L) Reveal-flow library API: selection resolution, mirror-id rejection, ciphertext gathering, builder invocation (CLI wiring is U28/U29's) — after R13–R15
- [ ] **R17** (M) Verdict aggregation: [H] map, ONE headline (earliest), >48 h divergence, UNANCHORED, receipt class, claimed-time exclusion — after R12
- [ ] **R18** (M) Frozen authoritative verdict-wording set + snapshot tests (shared verbatim by CLI and page) — after R17
- [ ] **R19** (M) Redaction-view model + CLI renderer (position+size always; sized blackouts; committed placeholders) — after R5,R18
- [ ] **R20** (M) Storage-linkage stage: offline address recomputation (units + re-encrypted manifest); rendered distinctly — after R5,R18 + S4,C10
- [ ] **R21** (L) Verify orchestration library API: offline, --online must-agree overlay + promotion, --live composition (CLI wiring + exit codes are U30's) — after R11,R17–R20 + A16–A18
- [ ] **R22** (S) wasm-bindgen binding surface (verify → serialized report; online-evidence entry; build info) — after R5,R17–R20 + P14
- [ ] **R23** (L) Verifier page: plain HTML/JS, drag-and-drop, offline-first FULL verification, redaction DOM, all versions — after R22,R18,R19
- [ ] **R24** (M) Page online mode: browser-fetch must-agree overlay, user-overridable endpoints, no --live affordance — after R23 + A16,A18
- [ ] **R25** (M) Reproducible page build + published SHA-256 + footer self-hash + CLI cross-check advice — after R23 + P6,P14
- [ ] **R26** (S) Deploy page to chosen host at the ONE canonical URL (single shared constant) — after R25 + P3
- [ ] **R27** (L) M3 E2E suite: CLI+page parity, offline zero-network run, endpoint-disagreement, partial+full reveal shapes — after R16,R21,R23,R24 + Q19

### CLI (U)
- [ ] **U27** (M) `show <work-id>` unit preview (kinds marked, snippet provenance labeled) — after U3,U9 + R15
- [ ] **U28** (L) `reveal` command wiring over R16's library API (arg parsing, output, canonical URL print) — after U2,U3,U9,U27 + R15,R16
- [ ] **U29** (S) Reveal disclosure consent + receipt-exposure warning — after U28 + R15
- [ ] **U30** (M) `verify` CLI command (vault-less, never prompts; verdict exit-code mapping; --json fixture) — after U1–U4 + R21

### CI & copy (Q)
- [ ] **Q19** (M) Playwright page-verification CI lane (offline-enforced; artifacts on failure) — after Q1 + R23,R25
- [ ] **Q20** (M) Positioning-copy style guide + repo-wide lint (with U31) — after R18 + U31

## M4 — Hardening & release (16 tasks)

Gate = **Q34 evidence bundle**: Sepolia-mode E2E green; exactly ONE mainnet smoke seal verified end-to-end from a clean machine using only the released signature-checked binary + hosted page; disk-loss restore drill passed; release published with mainnet default; traceability matrix 100 % green.

- [ ] **Q21** (M) Finalize the threat-model document (all 8 mandated topics + assumptions + residuals) — after Q12,Q20
- [ ] **Q22** (M) README + install + product-limits/disclosure docs — after Q20,Q30,Q31
- [ ] **Q23** (S) "Funding your wallet" doc (ANT + ETH on Arbitrum One; dev networks) — after Q20
- [ ] **Q24** (S) Vault-loss AND vault-theft doc pages — after Q20,Q21
- [ ] **Q25** (S) Wallet-hygiene guidance (fresh address per work/client; receipt exposure) — after Q20,Q21,Q23
- [ ] **Q26** (S) TSA defaults-and-alternates doc with recorded caveats — after Q20 + A26
- [ ] **Q27** (S) Format-stability policy doc (versions verifiable forever; Unicode-table retention; bump criteria) — after Q6,Q14
- [ ] **Q28** (S) Full-corpus copy audit: positioning + single canonical URL everywhere — after Q20–Q27 + U31/R25
- [ ] **Q29** (S) License decision + files (≥ permissive for core + verifier-web) — recommend deciding pre-M0 (D6)
- [ ] **Q30** (M) Signing keys + binary-signing pipeline (sha256sums + minisign/cosign; custody doc) — after Q1
- [ ] **Q31** (L) Release workflow: signed artifacts, double reproducible wasm build, versioning scheme, release checklist — after Q1,Q30 + R25,R26
- [ ] **Q32** (L) Script the M4 gate: Sepolia E2E + clean-machine procedure + disk-loss drill — after Q22,Q30,Q31 + P17,S19,U12,R26,A25
- [ ] **Q33** (S) Fund the gate wallets (fresh addresses; external action) — after Q25,Q32
- [ ] **Q34** (M) Execute the M4 gate: mainnet smoke seal, clean-machine verify, drill, SHIP — after Q13,Q21,Q28,Q31–Q33
- [ ] **Q35** (S) ≥10-external-users success-metric plan + tracking — after Q22,Q34
- [ ] **U32** (M) CLI release freeze: exit codes/JSON schemas/help snapshots frozen; final hygiene + positioning audits; drill-feedback fixes — after U1–U30

## Continuous (6 tasks)

- [ ] **P19** (S) Weekly upstream-bump check (scheduled job + runbook; never auto-bump) — joint with Q36
- [ ] **Q36** (S) Weekly upstream-bump chore operation (report/issue; bump procedure doc) — joint with P19
- [ ] **Q10** (S) cargo-audit/deny RUSTSEC watch, permanent (extends P13; licenses completed by Q29)
- [ ] **S20** (S) ant-core churn watch: bump-impact procedure confined to the adapter file; E2E as bump gates
- [ ] **R28** (S) Per-released-format-version verification kept green (CLI + wasm + page) forever
- [ ] **U31** (S) Positioning/copy conformance: string catalog + banned-token lint (with Q20)

---

## Decision register

Unresolved decisions are blockers-in-waiting: each must land by its due milestone. On resolution: check it, record outcome + date, update the blocked tasks in `tasks/*.md`. (Merged from all nine domains; joint owners shown.)

### Due pre-M0
- [x] **D1** Product name: `antseal` with upstream written blessing vs non-ant rename (P — blocks P2, P3, C12 context string, F4 format strings, U1 binary/dir; gates the M0 freeze) — **Resolved 2026-07-27: `antseal`, maintainer-confirmed FINAL** (third path — no upstream blessing; deviation + residual risk recorded; blessing request downgraded to optional courtesy; `sealstone` fallback retired; availability re-verified at confirmation: 5 crates FREE + dry-run green, .org/.dev FREE). C12 `"antseal-manifest-v1"`, F4 format strings, U1 binary/vault-dir now UNBLOCKED on the name (frozen at Q14). History: provisional 2026-07-27 → deadline re-anchored (request unfiled at M0 start) → maintainer confirmation same day (docs/decisions/D1-product-name.md)
- [x] **D2** Repo hosting platform + CI provider (assumption: GitHub + Actions) (P — blocks P4, P8) — **Resolved 2026-07-27**: GitHub + GitHub Actions; private repo `aed900/antseal` (docs/decisions/D2-hosting-ci.md)
- [x] **D3** Repo root layout: `code0/` as workspace root vs `antseal/` subdir per the spec tree (P — blocks P4, P5) — **Resolved 2026-07-27**: repo root = workspace root = the spec tree's `antseal/`; no nested subdir (docs/decisions/D3-repo-layout.md)
- [x] **D4** Rust edition + MSRV policy (P — blocks P6) — **Resolved 2026-07-27**: edition 2024; toolchain pinned =1.92.0; MSRV = pinned toolchain, moves only via P7 bump procedure (docs/decisions/D4-edition-msrv.md)
- [x] **D5** CLI crate publish name: spec's `antseal-cli` vs bare `antseal` for `cargo install` (P — reserve both in P2; recorded spec-disagreement) — **Resolved 2026-07-27** as recorded deferral: spec tree stays normative (crate `antseal-cli`, binary `antseal`); both names reserved at P2; publish-name call at Q31 (docs/decisions/D5-cli-crate-name.md)
- [x] **D6** License choice — spec milestone is M4 (Q29) but P2's crates.io placeholders need a license: decide early, execute at M4 (Q/P) — **Resolved 2026-07-27**: per-crate — antseal-core/anchor/verifier-web `MIT OR Apache-2.0`; antseal-net/cli own code dual-licensed but distribution effectively GPL-3.0 while ant-core's mandatory `self_encryption` dep stays GPL-3.0; ⚠ P15 direct-dep plan would pull GPL into the permissive core/WASM page — options recorded, decide at P15/S4; files land Q29 (docs/decisions/D6-license.md) — **2026-07-27 (S1 finding)**: GPL exposure in ant-core's graph is TWO crates — `self_encryption` 0.36.0 AND `evmlib` 0.9.0 (ant-core itself MIT/Apache-2.0); P15/S4 assessment must cover both

### Due M0 (format-freeze relevant — permanent once frozen)
- [x] **D7** Deterministic-CBOR crate + exact pin; in-house-codec contingency trigger (P10/F1) — **Resolved 2026-07-27**: `minicbor = "=2.3.0"`, features `alloc` only, derive off; strict rejections live in F3 on native probes; contingency trigger recorded (docs/decisions/D7-cbor-crate.md)
- [ ] **D8** Complete v1 wire registry: key assignments, reserved ranges, signatures container, anchor-status enum values, byte-range representation, integer time encoding, explicit file_id in touched-file entries (F4, with C/G/A/S)
- [ ] **D9** GGM node-address representation ((level,index) vs bit-path) — co-frozen G8/F4
- [ ] **D10** Parser cap constants (bundle/manifest size, unit/file/anchor counts, list lengths, depth) (F11)
- [x] **D11** Autonomi address byte length pinned from ant-core source via S1 (F4/F5/F8) — **Resolved 2026-07-27**: **32 bytes** — `XorName = [u8; 32]`, BLAKE3-256 of chunk content (ant-protocol 2.3.0 src/chunk.rs:43; docs/research/S1-ant-core-api-survey.md)
- [x] **D12** Independent CBOR cross-check implementation (Python `cbor2` vs second Rust crate, dev-only) (F14/Q11) — **Resolved 2026-07-27**: Python `cbor2 ==6.1.3` dev-tool-only (independent lineage; boundary-value byte-identity proven; RFC 7049 ordering caveat recorded — moot for uint-only keys) (docs/decisions/D7-cbor-crate.md §D12)
- [ ] **D13** `ed25519-dalek` 2.x vs 3.0.0 (P11/C11)
- [ ] **D14** Primary ML-DSA crate (ml-dsa vs fips204) + whether the Ed25519-only `sig_policy` fallback ships (C11)
- [ ] **D15** ML-DSA signing mode: hedged vs deterministic (affects golden-vector shape) (C16)
- [ ] **D16** Non-canonical-Ed25519-S rejection mechanism: crate parse-time vs explicit pre-validation (C12)
- [ ] **D17** Registered `sig_policy` algorithm-ID numeric values + reserved slots (C14/F4)
- [ ] **D18** wasm-bindgen surface location: feature-gated in core vs thin wrapper crate (P14/R22; final by M3)
- [ ] **D19** cargo-deny vs cargo-audit (or both) (P13)
- [ ] **D20** `--force-text` semantics on invalid UTF-8 (lossy U+FFFD total transform vs descriptor flag) (G2)
- [ ] **D21** Canonicalization micro-semantics: lone-CR handling, single leading BOM, pipeline order (G2)
- [ ] **D22** Blank-line definition for `--split` (whitespace-only lines; separator attachment) (G6)
- [ ] **D23** Raw-mirror placement in manifest order (proposal: appended after the file's normal units) — frozen forever (G5/G7)
- [ ] **D24** `--no-fine-tree` × `--split` on one file: silent single-unit vs hard error (G5/G6/U13)
- [x] **D25** Normalization crate + exact Unicode data version + multi-version retention architecture (G1/P7) — **Resolved 2026-07-27**: `unicode-normalization = "=0.1.25"` = Unicode **17.0.0** (verified from crate bytes; machine-asserted); descriptor `unicode-17.0.0`; append-only registry, future versions vendored side-by-side, shipped tables retained forever (docs/decisions/D25-unicode-normalization.md)
- [ ] **D26** Perf/memory budget constants (C₁, corpus size, ceilings) (G18)
- [x] **D27** `verify_bundle` error mode: fail-fast (tamper-authoritative) vs collect-all (rendering) (R1/R5/R7) — **Resolved 2026-07-27**: hybrid — fail-fast typed first-error is the sole normative mode (tamper matrix/Q7 bind to it); `VerifyFailures` is rendering-only, primary-first, first element ≡ the fail-fast error (docs/decisions/D27-verify-error-mode.md)
- [ ] **D28** Full-reveal strictness: bundle revealing all non-mirror units MUST carry file_salt (+s_root if fine tree) or hard-fail (R4/R7)
- [ ] **D29** Deterministic verification-report byte format (the bit-match contract) (Q4/Q5/R1) — **2026-07-27 recommended** (freeze reserved to Q14 via Q4/Q5): byte-deterministic compact `serde_json` — declaration-order fields, Vec/BTreeMap only, no floats, lowercase-hex, kebab-case wire names; serde =1.0.229 / serde_json =1.0.151 exact-pinned; canonical-CBOR re-base option + forcing conditions recorded (docs/decisions/D29-report-byte-format.md)
- [ ] **D30** Stable machine-readable error-code contract across F/C/G/A/R (Q7/Q8)
- [ ] **D31** Independent cross-check vehicles for the non-CBOR surfaces + permanence (one-shot artifact vs CI lane; is ml-dsa↔fips204+ACVP "independent" for ML-DSA? — the CBOR vehicle is D12's) (Q11)

### Due M1
- [ ] **D32** Blob↔address model (data-map style vs per-chunk) per ant-core's real storage model (S2/S4/S6; informed by S1) — 2026-07-27 inputs captured in the S1 memo (recommended: blob = one chunk, 32-B BLAKE3 address; `get_data` ↦ `chunk_get`)
- [ ] **D33** Block-number acquisition locus: antseal-net pay() vs antseal-anchor RPC client (S7/A17) — 2026-07-27 inputs captured: no upstream payment API returns a block number; own `eth_getTransactionReceipt` mandatory (S1 memo)
- [ ] **D34** Seal-pipeline crate placement (CLI lib target vs orchestration module; must be library-drivable) (S12/S10)
- [ ] **D35** self_encryption in core: direct pinned dep vs vendored address-derivation subset (S4/P15)
- [ ] **D36** Pre-pay resume re-quote/re-consent policy on cost change (proposed: re-consent) (S11/U17)
- [ ] **D37** Multi-tx payment handling (per-tx chunk cap; plural tx hashes) (S6/S7) — 2026-07-27 inputs captured: 256 transfers/tx, 64-chunk waves, 256 merkle leaves; `PaymentReceipt` needs `Vec<TxHash>` (S1 memo)
- [ ] **D38** Test-ANT acquisition mechanism on Arbitrum Sepolia 421614 (P17)
- [ ] **D39** `init` interaction model: wizard vs flags (U1/U11)
- [ ] **D40** KDF selection mechanism + low-RAM (cannot allocate 256 MiB) behavior (U6/U11)
- [ ] **D41** Non-interactive passphrase supply channel (env var vs fd vs keystore) (U7/U13)
- [ ] **D42** Vault encryption-boundary partition (config/anchor artifacts inside vs beside the AEAD; hook-without-unlock consequence) (U5; affects U24 at M2)
- [ ] **D43** Staged-ciphertext retention after successful finalize (local cache vs prune) (U9/U27/U28)
- [ ] **D44** Wallet import formats (raw hex only vs +mnemonic) (U11)
- [ ] **D45** Resume detection keying + consent-on-resume rule (U17)
- [ ] **D46** Directory arguments to `seal`: recurse vs files-only error (U13)
- [ ] **D47** `vault export` format (verbatim archive vs re-encrypted single file) (U12)
- [ ] **D48** `restore` default output dir + overwrite policy (U20)
- [ ] **D49** `--dry-run` network semantics: real quote_batch (proposed) vs offline estimate (U16)
- [ ] **D50** OS-keystore platform scope for the W wrap (U8)
- [ ] **D51** `--json` × interactivity contract (hard-abort without --yes: proposed yes) (U3/U14)
- [ ] **D52** Devnet E2E venue: CI job vs self-hosted vs required local gate (Q15)

### Due M2
- [ ] **D53** State for chain-invalid-at-genTime: `invalid` (recommended) vs `internally-consistent-only` (A9/A18/A21 — "A-OD1")
- [ ] **D54** Default OTS calendar set (≥2; liveness-verified) (A13/A25 — "A-OD2")
- [ ] **D55** Default Arbitrum RPC endpoint pairs per network (A17 — "A-OD3")
- [ ] **D56** Reconcile spec lines 133 vs 108/168 on the OTS `internally-consistent-only` trigger (mismatch → `invalid`; align R wording) (A18/A21/R18 — "A-OD4")
- [ ] **D57** Pinned root-store scope: defaults only vs + documented alternates (recommended: include alternates) (A6/A7 — "A-OD5")
- [ ] **D58** `opentimestamps` 0.2.0 viability on stable + wasm32; vendor/fork fallback (A11/P18 — "A-OD6")
- [ ] **D59** Request-nonce persistence semantics (capture-time check; bundles carry no nonce) — sign off (A8/A10 — "A-OD7")
- [ ] **D60** DER/CMS/X.509/signature crate pins; P-256 TSA support beyond normative P-384+RSA? (A5/A8/A9 — "A-OD8")
- [ ] **D61** Long-run fuzz venue: nightly CI vs OSS-Fuzz (Q9)

### Due M3
- [ ] **D62** Verifier-page host (domain from P3; canonical URL constant) (R26/P3/Q)
- [ ] **D63** Footer build-hash mechanism + exact artifact set the published SHA-256 covers (R25)
- [ ] **D64** Online-overlay ↔ headline presentation layout (frozen by R18 snapshots) (R17/R18)
- [ ] **D65** `--json` verdict-report schema stability commitment (R21/U30)
- [ ] **D66** CORS viability of pinned esplora/Arbitrum endpoints from browsers; fallback policy (R24)
- [ ] **D67** Disclosure-preview snippet length + binary-snippet format (R15/U27)
- [ ] **D68** `--units` syntax (ranges in MVP?) + default bundle filename (U28)
- [ ] **D69** Verify exit-code mapping per verdict class (UNANCHORED = 0 or distinct nonzero?) (U2/U30)
- [ ] **D70** Raw-mirror auto-include on whole-file reveals: always automatic vs future opt-out (R13/R16)

### Due M4
- [ ] **D71** Signing mechanism (minisign vs cosign vs both) + key custody (Q30)
- [ ] **D72** Release target set (linux-only vs +macOS/+Windows), distribution channel, crates.io publish scope (Q31/Q22)
- [ ] **D73** Success-metric measurement method with zero telemetry (Q35)

---

## Joint/shared tasks (implement once — do not duplicate)

- **P10 ↔ F1** — one CBOR-crate evaluation+pin (P records the pin; F owns the technical evaluation + implementation).
- **P11/P12 ↔ C11** — C11's probe produces the evidence; P lands the pins.
- **P9 ↔ S1** — P9 re-verifies/lands the pin; S1 surveys the API surface. Both M0-start.
- **S15 ↔ R11** — one persistence primitive (S15 implements in antseal-net; R11 is the verify-side wrapper).
- **P19 ↔ Q36** — one weekly upstream-check job (P mechanics, Q operation).
- **P13 ↔ Q10** — one advisory lane (P stands it up; Q operates it permanently + licenses via Q29).
- **U31 ↔ Q20** — one copy lint (U owns CLI catalog, Q owns repo-wide guide; single lint implementation).
- **G19/C17/F15/A21/R7-R8 → Q7/Q8** — rows are domain-owned; the harness + completeness registry are Q's. Error-code names must be globally distinct — coordinate through Q7's contract before writing rows.

## Risk watchlist (spec §Risks → owning tasks)

| Risk | Standing mitigation tasks |
|---|---|
| ant-core churn (weekly-to-biweekly) | P7, P9, S2 (boundary), S20, P19/Q36 |
| Autonomi network youth / data-reset history | evidence never depends on storage: R5 layering, A-anchors; single mainnet exposure only at Q34 |
| Receipt not independently verifiable in MVP | A19 classification, S7 capture completeness (no reseal ever needed) |
| OTS pending window / calendar death; TSA churn + cert expiry | A20 gate, A15/U24 opportunistic upgrades, U25 nags, A6/A7/A26 pinned roots, A9 genTime LTV |
| PQC crate maturity (ml-dsa unaudited, 2 advisories) | P12, P13/Q10, C11 probe, C14 fallback slot |
| Vault loss AND theft | U6 KDF+AAD, U7 floor, U8 wrap, U12 export, U18 nags, Q24 docs, Q21 threat model |
| Wallet linkability | receipt opt-in (R13/U29), U10 sub-key, Q25 hygiene doc, Q21 |
| Malicious verifier host | R25 reproducible build + hash, R26 canonical URL, Q30 signing, footer + CLI cross-check |
| Hostile bundles (adversary CBOR/DER/.ots in the browser) | F3/F11 strict+caps, F17/A23/R10 fuzz, A5 strict DER, Q9 lanes |
| Sealer-as-adversary | R3/R4 structural invariants, R7 rows, C7/G11 by-construction guards, subordinate claimed time (R17/R18) |
| Free-TSA terms/rate limits | A10 spacing config, A24 mock-only CI, Q16 policy, Q26 caveats doc |

## Out of MVP scope — v1.1 parking lot (do not implement; capture obligations already covered)

Committed v1.1: arbitrary byte-range reveal *tooling* (`reveal --range` selection + rendering UX — the proof format + verification already ship in MVP via G12/G13; F8 reserves the bundle slots) · Arbitrum-receipt verification chain (capture is complete via S7 — no reseal will be needed) · heading-aware text splitting · grapheme-selection UX.

Later: eIDAS-qualified tier · hosted SaaS/org gateway · GUI/desktop app · C2PA export · Arweave mirror tier · ZK position-blinded reveals · key escrow/social recovery · re-anchoring service · public anchor-bundle uploads · external-signer wallets.

Scope discipline: if a task seems to require any of the above, stop and check the spec's Parking lot — the MVP obligation is only that these remain *possible* (reserved slots, complete capture), never that they ship.

## Change log

- 2026-07-27 — v1: initial list generated from MVP-SPEC.md Rev 2 (9-agent decomposition, 219 tasks). Nothing started; phase = pre-M0.
- 2026-07-27 — pre-M0 execution (3-agent run: research + scaffold/CI + decisions/docs): P4–P7 ✅; P8 committed with all 5 lanes verified green locally, remote run blocked on gh `workflow` scope (maintainer device-flow); P1 provisional decision + propagation checklist + blessing draft committed; P2/P3 execution kits ready (reserve script dry-run green ×5), execution maintainer-blocked; D2–D6 resolved, D1 provisional with fallback + M0-start deadline. Evidence: docs/decisions/, docs/naming/, docs/ci-verification.md. Notable finding: `self_encryption` (mandatory in ant-core) is GPL-3.0 → D6 per-crate split + P15 flag.
- 2026-07-27 — **D1 FINAL: `antseal`** — maintainer confirmed ("I confirm the name is antseal"); no upstream blessing (deviation + residual risk recorded in the D1 doc); blessing request → optional courtesy; `sealstone` fallback retired. P1 ✅. Availability re-verified at confirmation (~18:58Z): 5 crates FREE + dry-run green, antseal.org/.dev FREE → P2/P3 executable, flagged prompt (availability decays). C12/F4/U1 unblocked on the name; Q14's D1 gate satisfied.
- 2026-07-27 — M0 wave 1 (6 parallel worktree agents + orchestrated integration): P9/P10+F1/S1/C1–C4/G1/R1 ✅, Q1 ⏳ (remote-blocked). Pins landed: ant-core =0.5.0 (declaration-only), minicbor =2.3.0 (D7), unicode-normalization =0.1.25/Unicode 17.0.0 (D25), sha2 =0.11.0 + hkdf =0.13.0 + hmac =0.13.0, serde =1.0.229 + serde_json =1.0.151 (D29). D11 (32-B BLAKE3 address), D12 (cbor2 ==6.1.3), D27 (hybrid error mode) resolved; D1 fallback re-anchored (request unfiled at M0 start — clock not started). Notable findings: evmlib 0.9.0 is a second GPL-3.0 crate in ant-core's graph (D6); no upstream payment API returns block numbers (D33); CI needed .gitattributes to keep golden fixtures CRLF-safe on windows runners. Full local gate green; push still blocked on gh `workflow` scope.
- 2026-07-27 — v1.1: adversarial verification applied. Coverage audit: **0 gaps** against the spec. Consistency audit: 12 defect groups fixed — R16/R21 redefined as library APIs (U28/U30 are the sole CLI owners of `reveal`/`verify`); A18 cedes verdict aggregation to R17; C17↔R7 tamper-fixture ownership resolved (R owns committed fixtures, C owns primitives+helpers); wallet keygen/import/address ops added to S5 (was an orphaned U11 dependency); A6→A7 sequenced; U13⇄U14 and eight consumer-reference cycles annotated (Deps-discipline rule 7 added); A5/A11/A12 real-fixture bootstrap via early A25 capture noted; multi-OS corpus lane added to Q1 (G3 was unexecutable); D31 scoped against D12.
