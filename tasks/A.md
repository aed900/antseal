# A — Anchors: OpenTimestamps, RFC 3161, Arbitrum receipt, verdict states

> Part of the antseal MVP task breakdown (generated 2026-07-27 from MVP-SPEC.md Revision 2 by a 9-agent decomposition).
> **Status tracking lives in `../TODO.md`** — do not add checkboxes here. Treat Do/Accept as normative until deliberately revised; spec line references are into `MVP-SPEC.md` as of 2026-07-27.
> Dep prefixes: P=setup/toolchain/pins, F=CBOR+manifest/bundle codecs, C=crypto primitives, G=canonicalization+units+GGM fine tree, S=storage/payments/journal/restore, A=anchors, R=reveal/verification/web page, U=CLI/vault/config/UX, Q=test-infra/CI/threat-model/docs/release.
> Architecture rule (normative, spec lines 47–53, 106): network side lives in `antseal-anchor`; ALL anchor verification lives in `antseal-core` (WASM-safe).

### A1 — Define the zero-anchor seal contract and minimal `absent`/UNANCHORED path
- Milestone: M1
- Size: S
- Deps: F: empty-anchor manifest/bundle golden vectors (M0, F13); U: `--no-anchor` flag wiring + network gate (U13); R: UNANCHORED wording (M3, R18)
- Spec: CLI surface (MVP-SPEC.md lines 147–149), Milestones M1 (line 154), Verifier web page (line 137), Core user flows (line 34)
- Do: Specify the M1 contract for dev-only zero-anchor seals: with `--no-anchor` the anchor-submission step is a no-op producing an empty anchor set, and every anchor slot evaluates to `absent`. In `antseal-core`, implement the minimal aggregate over an empty anchor section ("zero headline-eligible anchors" flag) so M1's library-API verify of an UNANCHORED devnet seal works before the full M2 state machine exists. Document, as part of the contract U wires, that `--no-anchor` MUST be rejected when `--network arbitrum-one`, so no permanent mainnet seal can ever bypass the anchor gate.
- Accept:
  - Library verification of F's empty-anchor golden vector yields all-`absent` anchors plus a zero-headline-eligible aggregate flag; M1 E2E (line 154) consumes this path.
  - No code path can produce a headline time from an empty anchor set (test).
  - The `--no-anchor` × `arbitrum-one` rejection rule is stated in the contract and covered by a test on U's side (cross-referenced).
  - `antseal-core` still compiles for `wasm32-unknown-unknown`.

### A2 — Implement anchor artifact and verdict data model in `antseal-core`
- Milestone: M2
- Size: M
- Deps: A1; F: bundle/manifest CBOR encoding of anchor sections; C: SHA-256/hash utilities
- Spec: Architecture (lines 47–53), Anchoring (lines 106–110), Verifier web page (lines 127–137), Reveal bundle (line 114)
- Do: Create `antseal_core::anchor::model`: `OtsArtifact` (raw `.ots` bytes; per-calendar pending info; upgraded record = attested height + 80-byte block header + fetch date), `TsaArtifact` (token DER, intermediate certs, fetch date), `ReceiptArtifact` (classification-only view of S's captured receipt), the seven-variant `AnchorState` enum with headline-eligibility flags, and `OnlineEvidence` input structs (agreed esplora header result; Arbitrum RPC result) so any host — CLI or page JS — can feed online results into WASM-safe core. Also define the capture-record structs (request nonce used, fetch dates, calendar URLs) that U persists in the vault.
- Accept:
  - All seven states (`proven`, `valid-at-stamping-cert-since-expired`, `attested`, `pending`, `internally-consistent-only`, `invalid`, `absent`) plus eligibility flags are representable.
  - `OnlineEvidence` is constructible with no network access; no I/O or tokio in the crate graph.
  - Types compile for `wasm32-unknown-unknown`; doc comments cite the spec lines for each state.
  - F can encode/decode every artifact field the bundle must carry (status, `.ots`, height+header+fetch date, token+intermediates+fetch dates, optional receipt).

### A3 — Scaffold `antseal-anchor` crate with HTTP substrate
- Milestone: M2
- Size: S
- Deps: P: workspace scaffold + HTTP-client crate pin
- Spec: Architecture (lines 52–53, 60)
- Do: Create `antseal-anchor` as the sole home of anchor network I/O (OTS calendars, TSA HTTP, esplora, Arbitrum RPC — the churn-isolation boundary). Build a small HTTP substrate: per-request timeout (default ~10 s), bounded retries, and typed per-endpoint errors capturing endpoint URL + failure class, reused by all clients in this crate.
- Accept:
  - Crate builds; unit tests against a local stub server exercise timeout, retry, and each error class.
  - `antseal-core` has no HTTP/network dependency (dependency-graph assertion; CI enforcement wired by Q).
  - No anchor network code exists outside `antseal-anchor` (review checklist item).

### A4 — Build DER `TimeStampReq` constructor in `antseal-core`
- Milestone: M2
- Size: S
- Deps: A2; F: `anchor_digest` = SHA-256(full manifest bytes) available from the manifest path (F7); C: SHA-256
- Spec: Anchoring RFC 3161 (line 109), Core user flows (line 34)
- Do: Implement `build_timestamp_req(anchor_digest: &[u8; 32], nonce: &[u8]) -> Vec<u8>` producing a DER `TimeStampReq` v1 with `messageImprint` = SHA-256 AlgorithmIdentifier + `anchor_digest`, a caller-supplied random nonce (≥ 64 bits), and `certReq = true` (so responses carry the chain the bundle embeds as intermediates). Nonce generation stays in `antseal-anchor` (OS CSPRNG) so this function is deterministic and golden-vectorable.
- Accept:
  - Golden vector: fixed digest + fixed nonce → byte-exact request; round-trips through the A5 parser.
  - Output is strict DER (definite lengths, minimal encodings).
  - Compiles for `wasm32-unknown-unknown`.

### A5 — Implement strict-DER parsing for TimeStampResp/CMS/TSTInfo with hard caps
- Milestone: M2
- Size: M
- Deps: A2; **A27 (the limit contract — read `docs/format/anchor-artifact-limits.md` before choosing any number)**; P/A-OD8: der/cms/x509-cert crate pins
- Spec: Anchoring (line 109), Milestones M2 (line 155), Tamper matrix BER row (line 168), Risks — hostile bundles (line 187)
- Do: In `antseal-core`, parse `TimeStampResp` (PKIStatusInfo status/failInfo), CMS `ContentInfo`/`SignedData`, `TSTInfo`, and X.509 certificates with strict-DER-only decoding; BER constructs (indefinite lengths, non-minimal lengths) are rejected with a distinct DER-strictness error class. Adversarial input returns typed errors — never panics. **Limits split in two, per A27's contract (D84 §5) — do not mint a constant without checking which half it falls in.** (a) **Already frozen, consume by name, never redefine**: the certificate count over bundle-embedded intermediates is **`MAX_INTERMEDIATE_COUNT` = 16** (D10 row 8) and the per-element certificate size is **`MAX_CERT_BYTES` = 64 KiB** (D10 row 18); both already fire in verify stage 1 with their own error codes, so A5 adds no check over those fields. (b) **Genuinely open, chosen here at M2 against A25's recorded FreeTSA/DigiCert tokens**: max DER nesting depth, max certificate count *within a chain being validated* (a different quantity from the bundle field), max per-certificate size *within a validated chain*, max signed-attribute count. Every (b) limit obeys **F1–F4**: evaluated only in the anchor stage, never reachable from `SealProof::decode`; an over-limit artifact fails **that anchor alone** as `invalid`; raise-only afterwards; recorded in A27's F4 registry. The receive-side "max response size" over the network `TimeStampResp` is **A28's**, not this task's, and carries the derived constraint **`receive_cap <= MAX_TSA_TOKEN_BYTES`** (a token too large to embed is a seal that anchors and then cannot be revealed).
- Accept:
  - Real FreeTSA and DigiCert responses (recorded via the A25 runbook) parse successfully.
  - A BER-transcoded variant of a valid token fails with the distinct BER-where-DER-required error (feeds A21 row 7).
  - Every (b) limit has a rejection test with a distinct cap error, plus its F4 registry row (value, A25 fixture measured against, margin, `lowered: never`).
  - **F1 demonstrated, not asserted**: a test proves an over-limit token still yields a decodable bundle with a verified manifest and only its own anchor `invalid` (F2/F3).
  - No new constant duplicates `MAX_INTERMEDIATE_COUNT` or `MAX_CERT_BYTES` (grep-level review item).
  - Fuzz entry point exists for A23; 1 h local fuzz run clean; `wasm32-unknown-unknown` build passes.
- Notes: The real-response Accept bullets are bootstrapped by an early one-off capture (see A25's bootstrap note) and finally re-run at A25; evaluate the remaining bullets in dependency order. **Corrected 2026-07-28 (A27/D84 §5)**: this `Do` previously promised "max certificate count/size" as if unset — both are frozen D10 constants, and an implementer reading this file alone would have minted duplicates.

### A6 — Implement pinned TSA root store: versioned format, injection API, compiled into `antseal-core`
- Milestone: M2
- Size: M
- Deps: A5; A-OD5 (format defined and tested with generated test roots; A7 supplies the real cert data once the format exists — A6 precedes A7)
- Spec: Anchoring (line 109), Architecture (lines 47–51), Verifier web page (lines 129, 133), Risks (line 182)
- Do: Implement `TsaRootStore`: versioned const data (store version, build date, per-root DER + subject + SPKI SHA-256 fingerprint) compiled into `antseal-core` via const tables/`include_bytes!`. `TsaRootStore::pinned()` returns the compiled store; all verification APIs take `&TsaRootStore` so A24's mock-TSA CI tests can inject test roots while the production CLI and WASM page use only the pinned store. Bundle-embedded certificates are consumed strictly as intermediates — never as trust anchors.
- Accept:
  - `pinned()` exposes store version and root fingerprints; verification output carries the store version (for R's display).
  - Test: a chain that closes only against a bundle-supplied "root" can never reach `proven` (renders `internally-consistent-only` once A9 lands).
  - Injection API used by A24; page/CLI production paths provably use `pinned()` only.
  - `wasm32-unknown-unknown` build passes.

### A7 — Collect real TSA root certificates with verified provenance (upstream fetch)
- Milestone: M2
- Size: S
- Deps: A6 (store format); A-OD5
- Spec: Anchoring (line 109), Risks (lines 182, 189)
- Do: At execution time, fetch the root CA certificates anchoring the default TSAs' chains: the FreeTSA root CA (from freetsa.org, fingerprint cross-checked over a second channel) and the DigiCert timestamping root(s) (from DigiCert's official root repository), plus — per the A-OD5 decision — roots for the documented alternates (DFN-PKI/T-TeleSec for zeitstempel.dfn.de, Sectigo/USERTrust, SwissSign). Record provenance for each: source URL, fetch date, SHA-256 fingerprint matched against vendor-published values. Feed the certs into the A6 store build.
- Accept:
  - Real FreeTSA (ECDSA P-384, its 2026 cert chain) and DigiCert tokens chain-close against the collected roots (proven in A25 smoke).
  - Committed provenance record with per-root fingerprints and sources; review sign-off on each root.
  - Store builds reproducibly from the committed certs.
- Notes: Upstream verification is mandatory at execution time — fingerprints must not be trusted from a single HTTP fetch. FreeTSA's 2026 cert rotation is the reason ECDSA P-384 support is normative.

### A8 — Implement CMS SignedData verification: signed attributes, messageImprint, nonce, ESSCertID, EKU
- Milestone: M2
- Size: L
- Deps: A5, A2; P/A-OD8: rsa + p384 crate pins; A-OD7
- Spec: Anchoring (line 109), Core user flows (line 38)
- Do: Implement WASM-safe token verification over parsed SignedData: signed attributes MUST be present with correct content-type and message-digest attributes; the signature is verified over the DER `SET OF` re-encoding of signedAttrs; the eContent (TSTInfo) digest must match the message-digest attribute; `TSTInfo.messageImprint` must equal `anchor_digest` (SHA-256); nonce equality is checked when an expected nonce is supplied (capture path — bundle verification passes `None` per A-OD7); the signer cert is identified and bound via SigningCertificate/SigningCertificateV2 (ESSCertID and ESSCertIDv2 both supported); the TSA cert's EKU extension must be present, critical, and contain `id-kp-timeStamping` per RFC 3161 §2.3. Signature algorithms: RSA PKCS#1 v1.5 (SHA-256/384/512) and ECDSA P-384.
- Accept:
  - Real FreeTSA (ECDSA P-384) and DigiCert (RSA) fixtures verify.
  - Distinct-error tests: messageImprint for a different digest; stripped or altered signed attributes; message-digest mismatch; ESSCertID referencing a different cert; missing/non-critical/wrong EKU; wrong nonce on the capture path.
  - No panics on adversarial input; `wasm32-unknown-unknown` build passes.
- Notes: This plus A9 is the spec's explicitly budgeted "no turnkey pure-Rust CMS verifier" M2 work — `cms` parses only.

### A9 — Implement X.509 single-path validation to pinned roots with genTime LTV semantics
- Milestone: M2
- Size: L
- Deps: A6, A8; A-OD1
- Spec: Anchoring (line 109), Verifier web page (lines 129–130, 133), Core user flows (line 38), Risks (line 182)
- Do: Implement single-path chain building from the signer cert through bundle-supplied intermediates to a pinned root: per-link signature verification (RSA + ECDSA P-384), name chaining, BasicConstraints and KeyUsage checks. Temporal validity is evaluated at the token's genTime (long-term validation): chain valid at genTime and closing at a pinned root → candidate `proven`; valid at genTime but expired at the caller-supplied verification time → `valid-at-stamping-cert-since-expired` (headline-eligible); chain invalid at genTime → the A-OD1 state with a distinct error detail; well-formed chain closing only outside the pinned store → `internally-consistent-only`. Verification time is an explicit function parameter — core never reads a system clock (WASM determinism).
- Accept:
  - Test chains (A24 test CA) cover: fully valid; expired-after-genTime → `valid-at-stamping-cert-since-expired`; expired-at-genTime → distinct non-headline state per A-OD1; untrusted root → `internally-consistent-only`; broken chain signature → `invalid`.
  - Passing two different verification times over one fixture flips `proven` ↔ `valid-at-stamping-cert-since-expired` correctly (aging-bundle non-rot test).
  - TSA verification is fully offline — no online step exists in this path (line 38).
  - No revocation fetching (out of MVP scope; documented for Q's threat model); `wasm32-unknown-unknown` build passes.

### A10 — Build TSA HTTP capture client with immediate in-core verification
- Milestone: M2
- Size: M
- Deps: A3, A4, A8, A9; U: TSA-list config + vault persistence (U26/U9); A-OD7
- Spec: Anchoring (line 109), Core user flows (line 34), Risks (line 189)
- Do: In `antseal-anchor`, implement per-TSA capture: generate a random nonce (OS CSPRNG), build the request (A4), POST `application/timestamp-query` to each configured TSA (defaults `https://freetsa.org/tsr` and `http://timestamp.digicert.com`), parse the response, and immediately verify the token in `antseal-core` against the pinned roots, the expected nonce, and `anchor_digest` — only a fully verifying token counts as a success toward the seal gate. Emit per-TSA outcomes (token + fetch date + nonce, or a typed failure) for A20's policy and U's vault records; honor optional per-TSA minimum-interval config (Sectigo ~15 s, SwissSign ~10/day caveats).
- Accept:
  - Against A24's mock TSA: success path produces a complete capture record; a granted-but-unverifiable token counts as a failure; HTTP failure, timeout, and non-granted PKIStatus each produce distinct outcomes.
  - One TSA's failure never aborts or delays the others (independent attempts).
  - Both default endpoints exercised live once via A25.
- Notes: DigiCert's default endpoint is plain HTTP — acceptable because token validity is established cryptographically and the nonce prevents stale-token replay; record this rationale for Q's docs.

### A11 — Wrap `.ots` codec with strict limits, op execution, and digest-commitment check
- Milestone: M2
- Size: M
- Deps: A2; **A27 (the limit contract — read `docs/format/anchor-artifact-limits.md` before choosing any number)**; P: pin `opentimestamps = "=0.2.0"` (P18); A-OD6
- Spec: Anchoring (line 108), Milestones M2 (line 155), Tamper matrix (line 168), Risks (line 187)
- Do: In `antseal-core`, wrap the `opentimestamps` 0.2.0 crate (wire-format codec only) behind a hardened API: execute the op DAG from the stamped digest; require the stamped digest to equal `anchor_digest`, else a distinct "ops do not commit anchor_digest" `invalid` error; extract per-attestation results — pending {calendar URL, commitment} and Bitcoin {attested height, ops-derived merkle root}. Unknown ops/attestation types surface as typed unverifiable results, never crashes — and per **F3**, unknown is *not* over-limit, so that path keeps its own treatment and is not governed by a limit. **Limits split in two, per A27's contract (D84 §5) — do not mint a constant without checking which half it falls in.** (a) **Already frozen, consume by name, never redefine**: the "max file size" over a bundle-embedded `.ots` **is `MAX_OTS_BYTES` = 1 MiB** (D10 row 16), which already fires in verify stage 1 with its own error code; A11 adds no byte cap over that field. (b) **Genuinely open, chosen here at M2 against A25's recorded pending and upgraded `.ots`**: max op count, max append/prepend operand length, max branch depth/width, max attestation count. Every (b) limit obeys **F1–F4**: evaluated only in the anchor stage, never reachable from `SealProof::decode`; an over-limit artifact fails **that anchor alone** as `invalid`; raise-only afterwards; recorded in A27's F4 registry. The receive-side cap on A13's *merged* `.ots` is **A28's**, not this task's, and carries the derived constraint **`merge_cap <= MAX_OTS_BYTES`**.
- Accept:
  - Recorded real pending and upgraded `.ots` fixtures parse and classify correctly.
  - `.ots` stamping a different digest → distinct `invalid` error (A21 row 1).
  - Each (b) limit has a rejection test with a distinct error, plus its F4 registry row (value, A25 fixture measured against, margin, `lowered: never`).
  - **F1 demonstrated, not asserted**: a test proves an over-limit `.ots` still yields a decodable bundle with a verified manifest and only its own anchor `invalid` (F2/F3).
  - No new constant duplicates `MAX_OTS_BYTES` (grep-level review item).
  - Fuzz entry point for A23 runs 1 h clean; `wasm32-unknown-unknown` build passes (or the A-OD6 fallback is executed).
- Notes: `opentimestamps` 0.2.0 is from 2023 and dormant — verify at execution time that it compiles on current stable and wasm32; vendoring/forking the codec is the contingency (A-OD6). Real-fixture Accept bullets bootstrap from the early A25 capture and are finally re-run at A25. **Corrected 2026-07-28 (A27/D84 §5)**: this `Do` previously promised "max file size" as if unset — it is the frozen `MAX_OTS_BYTES`, and an implementer reading this file alone would have minted a duplicate.

### A12 — Implement embedded Bitcoin header offline check producing `attested`
- Milestone: M2
- Size: S
- Deps: A11, A2; F: bundle schema making height+header+fetch-date mandatory for upgraded OTS (F8)
- Spec: Anchoring (line 108), Verifier web page (line 131), Reveal bundle (line 114)
- Do: Implement offline evaluation of an upgraded OTS artifact: the embedded header must be exactly 80 bytes; parse its merkle-root field and require it to equal the ops-derived root for the attested height (byte order pinned empirically by a real upgraded fixture); on match, the state is `attested` — never headline-eligible offline (a lone header's PoW is self-referential; this deliberate online-gating closes the wholesale-forged-bundle attack) — carrying height, header, and fetch date as evidence for R. On mismatch → `invalid` (forged Bitcoin attestation/header class). A missing header on an upgraded artifact is an F-side schema decode error — assert that contract with a test.
- Accept:
  - Real upgraded fixture → `attested`; root-mismatched header → distinct `invalid` error; 79- and 81-byte headers rejected.
  - `attested` never carries the headline-eligible flag in offline evaluation (test; also A21 row 5).
  - Byte-order handling locked by golden vector; `wasm32-unknown-unknown` build passes.
- Notes: The real-upgraded-fixture byte-order pin bootstraps from the early A25 capture; final Accept re-run at A25.

### A13 — Build OTS calendar submission client (≥2 calendars, merged pending `.ots`)
- Milestone: M2
- Size: M
- Deps: A3, A11; A-OD2; U: vault persistence of `.ots` + calendar URLs (U9)
- Spec: Anchoring (line 108), Core user flows (line 34), Milestones M2 (line 155)
- Do: In `antseal-anchor`, implement submission: POST `anchor_digest` to ≥2 configured public calendars (defaults per A-OD2; verify endpoint liveness and exact submit API at execution time), collect each calendar's pending response, and merge them into a single stored `.ots` (DetachedTimestampFile with one pending attestation per calendar). Before recording, re-parse the merged file through A11 and confirm it commits `anchor_digest`. Per-calendar failures are independent: ≥1 success ⇒ a pending OTS anchor exists; total failure produces a degradation outcome for A20 but never aborts the seal by itself (the abort gate is TSA-based).
- Accept:
  - Mock-calendar test: two calendars → one `.ots` containing two pending attestations, A11-clean.
  - One-calendar-down still records the other; zero-success surfaces as a typed degradation outcome.
  - A25 smoke performs a real submission.
- Notes: The in-house calendar client (this + A14) is the spec's committed ~1–2-week M2 line item; the crate is codec-only.

### A14 — Build OTS upgrade polling, attestation merge, and upgrade-time header embed
- Milestone: M2
- Size: L
- Deps: A13, A11, A12, A16; U: vault record updates (U9)
- Spec: Anchoring (line 108), Core user flows (line 35), Milestones M2 (line 155), Anchor smoke tests (line 173)
- Do: For each pending attestation, GET the calendar's upgrade endpoint for its commitment; on receiving a Bitcoin attestation, merge the returned ops/attestation branches into the stored `.ots` (dedupe; retain other calendars' pending attestations until they upgrade) and re-validate via A11. On the first Bitcoin attestation, fetch the attested height's 80-byte header via the must-agree esplora primitive (A16), require the fetched header's merkle root to match the ops-derived root before recording, and store height + header + fetch date for bundle embedding (F encodes). Distinguish "not ready yet" from hard calendar errors for status/nag reporting.
- Accept:
  - Mock-calendar replay of a recorded real upgrade: merged `.ots` evaluates `attested` with embedded header via A12.
  - An injected wrong header is rejected before recording (never persisted).
  - Partial upgrade (one calendar upgraded, one still pending) is representable and re-pollable.
  - A25 two-day smoke passes against real calendars.
- Notes: Spec mandates must-agree esplora only for `--online` verification; reusing it for the upgrade-time fetch is a deliberate hardening choice — record it.

### A15 — Build opportunistic upgrade engine and `status` data backend
- Milestone: M2
- Size: M
- Deps: A14; U: every-CLI-invocation hook (U24), `status --upgrade` (U23), `list` nags (U25), vault iteration API
- Spec: Core user flows (line 35), Anchoring (line 108), Milestones M2 (line 155), Risks (line 182)
- Do: Implement `upgrade_pending(works, budget) -> UpgradeReport` in `antseal-anchor`: scan vault-provided works with pending OTS anchors, attempt upgrades within a bounded time budget (short timeouts, bounded per-calendar attempts) so the host CLI command is never meaningfully delayed, and never fail the host command on upgrade errors. Expose per-work, per-anchor status data (pending/attested/upgraded states, token presence, dates) for U's `status` and `list` rendering, including the "only strong anchor still pending" condition that drives `list` nags.
- Accept:
  - Hook contract documented and consumed by U (every invocation + `status --upgrade`).
  - Budget respected under a deliberately slow mock calendar (test); upgrade errors reported without affecting host-command exit status.
  - A successful upgrade transitions the vault record so the next `reveal`/`verify` embeds the upgraded artifact + header.
  - Status data covers everything line 35 requires U to display.

### A16 — Implement must-agree two-endpoint primitive and esplora header pair
- Milestone: M2
- Size: M
- Deps: A3; U: endpoint-override config (U4)
- Spec: Core user flows (line 38), Verifier web page (line 137), Milestones M2 (line 155), Verification M3 (line 174)
- Do: Implement a generic must-agree fetch in `antseal-anchor`: query two endpoints; both must succeed AND agree byte-for-byte, with typed outcomes distinguishing endpoint-unavailable (advisory/retryable) from disagreement (alarming — a lying endpoint). Implement the esplora pair over it (defaults blockstream.info + mempool.space, user-overridable): height → block hash → 80-byte raw header, returning the agreed header bytes for height H. Confirm the exact esplora API paths against both live services at execution time.
- Accept:
  - Stub-server tests: agreement passes; one endpoint down → unavailable outcome; differing headers → distinct disagreement outcome (the typed result R's M3 endpoint-disagreement case consumes).
  - Returned header is exactly 80 bytes; agreed result is byte-identical from both endpoints.
  - Defaults verified live once via A25; overrides flow from U's config.

### A17 — Implement Arbitrum two-RPC transaction confirmation (advisory only)
- Milestone: M2
- Size: M
- Deps: A3, A16 (primitive); A-OD3; S: `PaymentReceipt` contents (tx hashes, block number); U: per-network endpoint config; R: overlay rendering
- Spec: Core user flows (line 38), Anchoring (line 110), Verifier web page (line 137)
- Do: Implement `confirm_arbitrum_tx` over two public Arbitrum RPC endpoints (defaults per A-OD3, user-overridable) using `eth_getTransactionReceipt`: both must agree on tx presence, success status, blockNumber, and blockHash. The output is advisory `OnlineEvidence` feeding only the receipt's "supporting evidence" overlay — it never creates, promotes, or affects any anchor state and never yields a headline time. It runs only when a receipt is available (bundle built with `--include-receipt`, or the sealer's own vault).
- Accept:
  - Stub-RPC tests: agree / one-down / disagree / tx-absent each produce distinct typed outcomes.
  - Type-level or test-enforced separation: this result cannot enter the anchor state machine as an anchor.
  - Per-network endpoint sets (arbitrum-one vs arbitrum-sepolia; disabled on devnet) configurable; one live round via A25.

### A18 — Implement the per-anchor verdict state machine with aggregate summary data
- Milestone: M2
- Size: M
- Deps: A2, A8, A9, A11, A12, A16 (evidence types), A17 (evidence types); A-OD1, A-OD4; R: wording/rendering/headline selection (R17/R18)
- Spec: Verifier web page (lines 127–137), Anchoring (lines 106–110), Milestones M2 (line 155)
- Do: Implement pure `evaluate_anchors(artifacts, online_evidence, verify_at) -> AnchorVerdicts` in `antseal-core`, mapping every artifact to exactly one of the seven states with headline-eligibility flags: TSA → `proven` [H] / `valid-at-stamping-cert-since-expired` [H] / `internally-consistent-only` / `invalid` / `absent`; OTS → `pending` / `attested` / `proven` [H] (only when online evidence shows the embedded header equals the agreed fetched header for height H, taking the block timestamp as the proven time) / `invalid` (online header mismatch, or ops not committing `anchor_digest`) / `absent`. Emit wording-free PER-ANCHOR result data for R: state, verified time + source, headline-eligibility flag, and artifact metadata. Verdict AGGREGATION — earliest headline selection, the >48 h divergence flag, and the UNANCHORED outcome — is R17's (M3); A1's minimal zero-headline-eligible aggregate flag covers M1/M2 library use until R17 lands. Online evidence is pure input — core never fetches; CLI (via `antseal-anchor`) or page JS supplies it.
- Accept:
  - Exhaustive test: every one of the seven states reachable from a concrete fixture; `absent` covered by the empty-anchor vector.
  - `attested` is never [H] without online evidence; matching online evidence promotes to `proven` with the block-header timestamp; mismatch → `invalid`.
  - Empty artifact set → all `absent` (zero-eligible aggregate via A1's flag); no system-clock access (verify_at is a parameter); deterministic native-vs-wasm output (locked by A22).

### A19 — Enforce Arbitrum receipt classification: supporting evidence, never anchor, never headline
- Milestone: M2
- Size: S
- Deps: A2, A17, A18; S: receipt capture completeness (S7); R: "supporting evidence — no independently proven time" wording (R18)
- Spec: Anchoring (line 110), Verifier web page (line 137), Context/scope decision 3 (line 19), Risks (line 181)
- Do: Encode in the verdict model that the receipt occupies a separate `SupportingEvidence` class in ALL MVP verdicts: never an anchor, never headline-eligible, and unchanged by a successful two-RPC online confirmation (which only feeds the advisory overlay). No code path treats any receipt datum as committing `anchor_digest` (no on-chain datum does). Classification must not touch S's capture completeness — the v1.1 verification chain stays out of scope with no reseal ever needed.
- Accept:
  - Test: a bundle containing only a receipt (no anchors) → all anchors `absent` + UNANCHORED flag, receipt rendered data present as supporting evidence.
  - Test: receipt with successful two-RPC confirmation still contributes no headline and no anchor state.
  - Classification data feeds R's fixed wording; nothing in `antseal-core` parses receipt internals for time claims.

### A20 — Build anchor submission orchestrator and minimum-anchor seal policy
- Milestone: M2
- Size: M
- Deps: A10, A13, A1; U: seal-pipeline ordering (anchor gate strictly before `pay`), `--force-degraded`/`--no-anchor` flag wiring (U22), degradation-report rendering
- Spec: Context decision 3 (line 19), Core user flows (line 34), CLI surface (line 149), Milestones M2 (line 155), Risks (lines 182, 189)
- Do: Implement `submit_anchors(anchor_digest, config) -> AnchorSubmissionOutcome` in `antseal-anchor` (OTS calendar submits first, then TSA captures, matching the line-34 pipeline order) and the pure gate decision `evaluate_seal_gate(outcome, flags, network)`: proceed iff ≥1 TSA token passed full core verification; otherwise abort — before any payment, per U's pipeline ordering — with a typed error enumerating every per-endpoint failure. `--force-degraded` converts the abort into proceed-with-degradation; `--no-anchor` skips submission entirely (empty anchor set per A1) and MUST be rejected when network = arbitrum-one. Every outcome carries a degradation report (which anchors succeeded/failed and why) so anchor failures downgrade the seal report loudly, never silently.
- Accept:
  - Decision-table tests: 0 verified TSA + no flags → abort; 0 TSA + `--force-degraded` → proceed degraded; ≥1 verified TSA + total OTS failure → proceed with degradation note; `--no-anchor` + arbitrum-one → rejected; `--no-anchor` + devnet/sepolia → empty anchor set.
  - A gate-passing seal always holds ≥1 offline headline-eligible anchor (`proven` TSA) — the line-137 "normal seal never renders UNANCHORED offline" property, tested.
  - Abort path demonstrably precedes payment (asserted in U's E2E; cross-referenced).
  - Per-endpoint failures appear verbatim in the typed abort error and the degradation report.

### A21 — Build the M2 anchor tamper matrix: fixtures plus distinct-error tests
- Milestone: M2
- Size: L
- Deps: A8, A9, A11, A12, A18, A24 (test CA + mock infra); A-OD1; Q: CI retention (Q18)
- Spec: Verification — tamper matrix M2 rows (line 168), Milestones M2 (line 155)
- Do: Build committed fixtures and tests covering every M2 anchor row, each failing (or classifying) with a distinct error/state: (1) `.ots` stamping a different digest → `invalid`; (2) TSA token whose messageImprint is a different digest → `invalid`; (3) well-formed TSA token chaining to an untrusted root (test-CA root excluded from the injected store) → `internally-consistent-only`, not headline-eligible; (4) forged Bitcoin header that fails the `--online` block match → `invalid`; (5) positive control: an `attested` OTS anchor correctly withheld from offline headline eligibility; (6) expired-at-genTime chain (per A-OD1 state) vs expired-after-genTime (`valid-at-stamping-cert-since-expired` [H]) — distinct outcomes; (7) BER-where-DER-required → distinct DER-strictness error. Fixture generation is scripted and reproducible; test-CA keys are fixture-only material.
- Accept:
  - One test per row; no two rows share an error/state variant (distinctness asserted).
  - Rows execute in both native and wasm32 test suites.
  - Fixtures + generation script committed under `testdata/`; no vault/secret material in fixtures.

### A22 — Commit anchor golden vectors and wasm32 verification parity (M2 exit criteria)
- Milestone: M2
- Size: M
- Deps: A18, A21, A25 (recorded artifacts); F: vector envelope format; Q: CI lanes + forever-retention (Q5/Q6)
- Spec: Milestones M2 (line 155), Verification (lines 167, 169), Architecture (lines 47–51), Format stability (line 123)
- Do: Commit golden vectors for anchor verification: real recorded FreeTSA (ECDSA P-384) and DigiCert (RSA) tokens, a pending `.ots`, and an upgraded `.ots` with embedded header — each paired with the expected complete verdict output (state, eligibility, extracted times) at a fixed `verify_at`. Add a `wasm32-unknown-unknown` test run (wasm-bindgen-test or equivalent) asserting bit-identical verdict output against native over all vectors. These two artifacts are the spec's explicit M2 exit criteria.
- Accept:
  - Vectors committed under `testdata/anchors/`; retained forever in CI per format-stability policy (Q wiring).
  - Native and wasm runs produce byte-identical serialized verdicts for every vector.
  - M2 exit checklist references these passing tests; any wasm-incompatible dependency (A-OD6) resolved first.

### A23 — Write cargo-fuzz targets for the TimeStampResp and `.ots` parsers
- Milestone: M2
- Size: M
- Deps: A5, A11; Q: fuzz CI lane wiring (Q17)
- Spec: Milestones M2 (line 155), Verification (lines 168–169), Risks — hostile bundles (line 187)
- Do: Add two cargo-fuzz targets in `antseal-core`'s fuzz workspace: `fuzz_tsr` driving TimeStampResp/CMS/TSTInfo parse + verify (fixed digest + injected root store) and `fuzz_ots` driving `.ots` decode + op execution + limit enforcement. Seed corpora from the real recorded fixtures plus tamper-matrix mutants so the interesting branches are reached immediately.
- Accept:
  - Both targets build and run ≥1 h locally with zero crashes, hangs, leaks, or OOM (caps hold).
  - Seed corpora committed; any finding filed and fixed before M2 close.
  - Targets consumable by Q's CI fuzz lane without modification.

### A24 — Build mock TSA, mock calendar, and stub esplora/RPC servers for CI
- Milestone: M2
- Size: M
- Deps: A3, A6 (root-store injection); consumed by A10, A13, A14, A16, A17, A21
- Spec: Anchor smoke tests (line 173), Milestones M2 (line 155)
- Do: Build test-support servers (local HTTP, dev-dependencies/test-support crate): a mock TSA signing TimeStampResp with a generated test CA chain (RSA and ECDSA P-384 signer variants; controllable genTime, PKIStatus, and failure modes) verified via the injected test root store; a mock OTS calendar replaying recorded submit/upgrade exchanges; stub esplora and Arbitrum RPC pairs with controllable agree/disagree/down behavior. CI never touches real endpoints.
- Accept:
  - All anchor network-path tests pass fully offline in CI.
  - Test-CA generation is scripted; keys are fixture-only, never vault material.
  - Controllable failure modes cover every outcome variant defined by A10, A13, A14, A16, and A17.
  - Recorded-exchange fixtures committed.

### A25 — Run real-endpoint anchor smoke tests and record canonical fixtures
- Milestone: M2
- Size: M
- Deps: A10, A13, A14, A16, A17; Q: manual/nightly lane, excluded from gating CI (Q16)
- Spec: Anchor smoke tests (line 173), Anchoring (lines 108–109)
- Do: Script non-CI smoke runs against real services using a fixed test digest: (1) submit to the real default OTS calendars and store the pending `.ots`; (2) the next day, upgrade → verify `attested` offline, then `--online` promotion to `proven` via real blockstream.info + mempool.space; (3) obtain and fully verify real FreeTSA (ECDSA P-384) and DigiCert tokens against the pinned root store; (4) one live must-agree round each for esplora and the Arbitrum RPC pair. Record the artifacts (tokens, pending/upgraded `.ots`, header) as the committed fixtures A5/A8/A11/A12/A22 consume, and verify all default endpoint URLs/paths are live and correct. An early bootstrap capture (one TSA response per default endpoint + one pending `.ots`, upgraded the next day) may run as soon as A3/A4 exist, seeding A5/A11/A12 development fixtures; the full protocol re-runs at task completion.
- Accept:
  - Runbook + script committed; the two-day OTS protocol completed at least once before M2 close, results logged.
  - Both real TSA tokens reach `proven` against the pinned store.
  - Fixtures land in `testdata/` (test digest only — no secret material).
  - Endpoint liveness/caveat findings handed to Q for the alternates doc table.
- Notes: Execution-time upstream verification is inherent here (calendar endpoints, esplora paths, TSA URLs, FreeTSA's current cert). Respect TSA rate limits during the run.

### A26 — Define TSA root-store versioning and update process
- Milestone: M2 (process runs `continuous` thereafter)
- Size: S
- Deps: A6, A7 (Q26/Q31 at M4 consume the procedure — not ordering deps)
- Spec: Anchoring (line 109), Format stability (line 123), Risks (line 182)
- Do: Define and document the update process for the compiled-in root store: monotonically increasing store version + date; adding/rotating a root is a reviewed change requiring the A7 provenance procedure; roots are effectively append-only — removals need an explicit compatibility note because previously issued bundles must keep verifying under the format-stability policy; each release checks pinned-root validity windows. Verification output reports the store version in use.
- Accept:
  - Documented procedure committed and referenced by Q's release checklist.
  - Test: after appending a new root, all existing anchor golden vectors still verify unchanged (store version bumped, results stable).
  - Store version visible in verdict data for R's display.

### A27 — Write the anchor-artifact limit contract A5/A11 read at M2
- Milestone: M0 (the contract must exist before the Q14 freeze; A5/A11 consume it at M2)
- Size: S
- Deps: D84; D10 (the frozen envelope caps it points at); F11 (the constants exist)
- Spec: Format stability (MVP-SPEC.md line 123); Milestones M0/M2 (lines 153, 155); Anchoring (lines 108–109); Risks — hostile bundles (line 187)
- Discovered by: **D84** (2026-07-28). Precedent: **F19**, which handed F14 its sidecar contract for exactly this reason — a rule that lives only in a decision record is a rule the implementing task rediscovers or contradicts.
- Do: Commit `docs/format/anchor-artifact-limits.md` carrying, verbatim from `docs/decisions/D84-anchor-artifact-limits-permanence.md`: rules **F1–F4** (§4 — limits evaluated only in the anchor stage, never in stage 1 decode; an over-limit artifact fails **that anchor alone** as `invalid`; raise-only monotonicity after M2's first release); the §5 ruling that A5's and A11's promised byte/count caps over bundle-embedded artifacts **are** the existing D10 constants (`MAX_OTS_BYTES`, `MAX_TSA_TOKEN_BYTES`, `MAX_CERT_BYTES`, `MAX_INTERMEDIATE_COUNT`) and must be consumed by name, not re-minted; the §6 table of the eight limits genuinely left open at M2 with the real artifact each is measured against; and an empty **F4 registry** table (limit, initial value, date set, `lowered: never`) for A5/A11 to fill. Update A5's and A11's `Do` text in this file to point at the contract instead of promising caps that §5 rules already frozen.
- Accept:
  - The F1–F4 text in the doc is byte-identical to D84 §7's Q14 checklist row wording where they overlap — a paraphrase is how the two drift.
  - A5 and A11 in `tasks/A.md` name the D10 constants; A5's receive-side response cap carries the `≤ MAX_TSA_TOKEN_BYTES` derivation from D84 §5.
  - The F4 registry exists with its columns and a stated update rule, even though it is empty at M0.
  - Referenced from the Q14 freeze checklist row Q37 lands.
- Notes: This is documentation only — no code, no constants, no error codes at M0. The numbers themselves are deliberately absent; putting placeholders here is the failure mode D84 §8 rejects.

### A28 — Reconcile the receive-side anchor size caps with the frozen bundle-field caps
- Milestone: M2
- Size: S
- Deps: A27 (the contract), A3/A4 (the TSA request path), A13 (OTS submission/merge), D10 rows 16/17
- Spec: Anchoring (lines 108–109); Reveal bundle (line 114); Format stability (line 123)
- Discovered by: **D84** (2026-07-28). A5's promised "max response size" is the one cap in A's list that is *not* a duplicate of a D10 constant — it bounds the `TimeStampResp` read off the network, before any bundle exists. It is still not free: a token accepted from a TSA that cannot afterwards be embedded in a `.sealproof` is a seal that anchors and then cannot be revealed. The same trap exists for A13's merged `.ots`.
- Do: Set the receive-side caps in the network paths (`antseal-anchor`) with the derived constraint from D84 §5 recorded at the site: the TSA response cap MUST be `≤ MAX_TSA_TOKEN_BYTES`, and the merged-`.ots` cap MUST be `≤ MAX_OTS_BYTES`. Fail the *submission* with a distinct, actionable error when a received artifact exceeds the embeddable size, rather than storing it and discovering the problem at reveal time. Record both values in A27's F4 registry.
- Accept:
  - A mock TSA returning a token larger than `MAX_TSA_TOKEN_BYTES` produces a distinct submission-time error naming the embeddability limit, and no vault record is written for it.
  - A merged `.ots` that would exceed `MAX_OTS_BYTES` fails at merge, not at bundle build (test with a synthetic multi-calendar merge).
  - A compile-time or test-time assertion pins `receive_cap <= MAX_*_BYTES` for both, so a later loosening of one cannot silently outrun the other.
- Notes: The receive-side caps are **not** format surface (D84 §3) — they are network-path policy and may change freely, subject only to the `≤` constraint.

### A29 — Carry F2/F3 into R12's Accept criteria (the edit D84 flagged but could not make)
- Milestone: M2 (the edit to `tasks/R.md` may be made as soon as that file is free)
- Size: S
- Deps: A27 (the contract); R12 (the anchor stage that replaces the M0 `absent` stub); A5/A11 (the fixtures that make the case testable)
- Spec: Format stability (MVP-SPEC.md line 123); Verifier web page — verdict taxonomy (lines 127–137); Milestones M2 (line 155)
- Discovered by: **D84** §Consequences item 6 (2026-07-28), which states the requirement and then says plainly *"Flagged, not edited — `tasks/R.md` is another planner's this wave."* A requirement that lives only in a decision record's consequences list is a requirement the implementing task never sees; **F19 → F14 is the precedent that this needs a task with an owner**, and A owns the contract even though the edit lands in R's file.
- Do: Add to R12's Accept criteria the **F2/F3 blast-radius case**: an anchor artifact that exceeds one of A5's or A11's artifact-internal limits renders **`invalid`** for **that anchor alone** — the bundle still decodes, the manifest verdict is unchanged, the evidence layer is unchanged, and every other anchor renders exactly as it would have. Add the **F1** counterpart too: no artifact-internal limit is reachable from `SealProof::decode`, demonstrated rather than asserted. Cross-reference `docs/format/anchor-artifact-limits.md` from R12 so the anchor stage is implemented against the contract instead of against memory of it.
- Accept:
  - R12's entry names the F2/F3 case and the F1 non-reachability property, and cites the contract doc.
  - The case is implementable from A5/A11 fixtures alone (no new fixture family invented for it).
  - The edit is a `tasks/R.md` change only — no code, no format surface, no constants.
- Notes: This exists because the wave-6 file-ownership split made a cross-domain edit impossible in the wave that discovered it. If `tasks/R.md` is free when this is picked up, it is a five-minute task; the risk it guards against is that it is never picked up at all.

## Open decisions (A)
- **A-OD1 — State for a chain invalid at genTime** (expired-at-genTime): map to `invalid` (with a distinct error detail) or `internally-consistent-only`? Recommendation: `invalid`, keeping `internally-consistent-only` for structurally-untrusted-root closure; the tamper matrix only mandates distinctness from `valid-at-stamping-cert-since-expired`. Blocks: A9, A18, A21. Must land: early M2.
- **A-OD2 — Default OTS calendar set** (≥2; candidates alice.btc.calendar.opentimestamps.org, bob.btc.calendar.opentimestamps.org, finney.calendar.eternitywall.com), with execution-time liveness verification. Blocks: A13, A25. Must land: M2.
- **A-OD3 — Default two public Arbitrum RPC endpoints** per network (arbitrum-one pair; sepolia pair; devnet disabled). Blocks: A17. Must land: M2.
- **A-OD4 — Reconcile the OTS trigger for `internally-consistent-only`**: line 133 lists "not match online (OTS)" under `internally-consistent-only`, while lines 108/168 map an online header mismatch to `invalid`. Implementation follows 108/168 (mismatch → `invalid`); confirm the residual OTS `internally-consistent-only` trigger (if any) and align R's wording before the M3 snapshot tests. Blocks: A18, A21. Must land: M2.
- **A-OD5 — Pinned root-store scope**: defaults-only vs defaults + documented alternates' roots. Recommendation: include alternates (DFN, Sectigo, SwissSign) — a configured-but-unpinned TSA can never exceed `internally-consistent-only`, which would make the documented alternates useless. Blocks: A7, A6. Must land: M2.
- **A-OD6 — `opentimestamps` 0.2.0 viability**: verify it compiles on current stable and `wasm32-unknown-unknown`; if not, vendor/fork the codec (wire format only). Blocks: A11, A22. Must land: early M2.
- **A-OD7 — Request-nonce persistence semantics**: nonce checked at capture time (vault stores it); bundles do not carry request nonces (per the line-114 bundle contents list), so third-party verification checks messageImprint only. Record as a signed-off decision. Blocks: A8, A10. Must land: M2.
- **A-OD8 — DER/CMS/X.509/signature crate selection + exact pins** (`der`, `cms`, `x509-cert`, `rsa`, `p384`; whether to also support ECDSA P-256 TSA certs beyond the normative P-384+RSA), decided with P's pin process. Blocks: A5, A8, A9. Must land: early M2.

## Cross-domain expectations
- P: workspace scaffold; exact pins for `opentimestamps =0.2.0`, DER/CMS/X.509/signature crates, and the HTTP client; wasm32 CI target from M0; RUSTSEC tracking for pinned crypto deps.
- F: deterministic-CBOR manifest/bundle codecs for all anchor artifact sections (per-anchor status, `.ots` bytes, height + 80-byte header + fetch date, TSA token + intermediates + fetch dates, opt-in receipt), with the embedded header mandatory for upgraded OTS; empty-anchor golden vectors (M0); `anchor_digest` = SHA-256(full manifest bytes, signatures included) computed on the manifest path.
- C: SHA-256 and digest utilities (and the domain-tag registry context) reused by anchor verification code.
- S: complete `PaymentReceipt` capture (EVM tx hashes, block number, quote preimages, `proof_bytes`) journaled the instant `pay` lands, readable by A17/A19.
- U: seal-pipeline ordering (anchor submission + ≥1-TSA gate strictly before `pay`); flags `--force-degraded`, `--no-anchor` (with arbitrum-one rejection), `status --upgrade`, `--online`, TSA-list and endpoint-override config; vault persistence of anchor records (`.ots`, tokens, nonces, fetch dates, calendar URLs); the every-CLI-invocation opportunistic-upgrade hook; `status`/`list` rendering incl. pending-anchor nags; degradation-report display.
- R: all verdict wording, rendering, headline selection, >48 h divergence display, UNANCHORED banner, "supporting evidence — no independently proven time" receipt copy, claimed-time subordination; `--online` advisory-overlay UX for CLI and page (page-side online evidence fed into core's `OnlineEvidence` inputs); M3 endpoint-disagreement UX case built on A16's typed disagreement outcome.
- Q: fuzz CI lanes consuming A23's targets; TSA-alternates caveat doc table (zeitstempel.dfn.de terms, Sectigo spacing, SwissSign quota); threat-model anchor sections (forged-header/wholesale-forged-bundle closure via online gating, calendar death, TSA churn/expiry, wallet linkability); forever-retention of anchor golden vectors in CI; manual/nightly smoke lane for A25; release checklist referencing A26's root-store process.
