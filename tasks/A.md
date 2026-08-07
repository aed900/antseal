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
- Do: Create `antseal_core::anchor::model`: **`OtsArtifactView`** (raw `.ots` bytes; upgraded record = attested height + 80-byte block header + fetch date), **`TsaArtifactView`** (token DER, intermediate certs, fetch date), `ReceiptArtifact` (classification-only view of S's captured receipt), **consume** the frozen seven-variant `AnchorState` and A1's `headline_eligible` predicate, **Three corrections, 2026-08-02, all found by the A2 lane implementing this entry**: (a) the names read `OtsArtifact`/`TsaArtifact`, but **D58 §10.2 claims `OtsArtifact` for A11's parse output** (`anchor/ots/mod.rs`), so A2's bundle-side views are named distinctly — one name, two owners, is a collision that would only surface at A11; (b) *"per-calendar pending info"* was listed as a field of the artifact and **is not one A2 can expose** — inside a bundle the calendars are named by the `.ots` attestations, which only A11's parser reads, so the datum belongs to the **capture record** (`OtsCaptureRecord::calendars`), where it now is; (c) the `AnchorState` clause read as though A2 *creates* the enum — it exists at `crates/antseal-core/src/verify/report.rs:258`, is **frozen**, and is pinned to the wire enum by registry assertion C10, so A2 consumes it and may not redefine it. and `OnlineEvidence` input structs (agreed esplora header result; Arbitrum RPC result) so any host — CLI or page JS — can feed online results into WASM-safe core. **Added 2026-08-02 (D56)**: `OnlineEvidence` needs a **`NoSuchBlock`** arm — without it D56's refutation case O7 (the endpoints agree that block H does not exist) is unrepresentable — and it must carry **no "failure" variant at all**: `--online` attempted-but-unreachable and attempted-but-disagreeing both leave the anchor at `attested`, and D56 rules that this is enforced **structurally**, by the type being unable to express a failure, rather than by a branch someone can forget. Also define the capture-record structs (request nonce used, fetch dates, calendar URLs) that U persists in the vault.
- Accept:
  - All seven states (`proven`, `valid-at-stamping-cert-since-expired`, `attested`, `pending`, `internally-consistent-only`, `invalid`, `absent`) plus eligibility flags are representable.
  - `OnlineEvidence` is constructible with no network access; no I/O or tokio in the crate graph.
  - Types compile for `wasm32-unknown-unknown`; doc comments cite the spec lines for each state.
  - F can encode/decode every artifact field the bundle must carry (status, `.ots`, height+header+fetch date, token+intermediates+fetch dates, optional receipt).

### A3 — Scaffold `antseal-anchor` crate with HTTP substrate
- Milestone: M2
- Size: S
- Deps: **P29 (the `ureq =3.3.0` pin); D90** — *corrected 2026-08-02: this read "P: workspace scaffold + HTTP-client crate pin", naming a P task that **did not exist**. The gap was found at the start of the M2 wave and became **D90**, which also rules that the pin is A-domain rather than P-domain (nothing consensus-affecting flows through it).*
- Spec: Architecture (lines 52–53, 60)
- Do: Create `antseal-anchor` as the sole home of anchor network I/O (OTS calendars, TSA HTTP, esplora, Arbitrum RPC — the churn-isolation boundary). Build a small HTTP substrate: per-request timeout (default ~10 s), bounded retries, and typed per-endpoint errors capturing endpoint URL + failure class, reused by all clients in this crate. **Implement D90 exactly** — read `docs/decisions/D90-anchor-http-substrate.md` before writing a line. It pins `ureq = "=3.3.0"` (`default-features = false`, `features = ["rustls"]`), **blocking and ungated**, declared by this crate alone (default `--workspace` graph 129 → 144 names); no runtime is created, borrowed or required, the frozen `AnchorGate::run` `async fn` keeps its signature with a blocking body, and endpoint independence comes from `std::thread::scope`. Three measured `ureq` behaviours that no documentation states, and that a naive implementation gets wrong: `.limit(N)` accepts **N−1** bytes (so A28's `≤` silently becomes `<`); `max_redirects(0)` **returns** the 3xx rather than erroring; and `Config::default()` reads `HTTP_PROXY`/`ALL_PROXY`, **which would collapse A16's must-agree pair onto a single origin**. Transport rule (D90 §, previously unowned, now task A49): plain HTTP is safe for RFC 3161 (tokens are signed and nonce-bound) and is **required** — `timestamp.digicert.com:443` refuses connections, measured, so a TLS-only substrate cannot reach a default TSA — while HTTPS is **mandatory** for esplora and RPC, whose responses are unsigned and whose only integrity control is the transport.
- **Accept row 2 is review-enforced until Q74 lands** (added 2026-08-02, D90): "`antseal-core` has no HTTP/network dependency (dependency-graph assertion)" cannot be delegated to `lane_dep_graph` today, because that lane's nine-name regex is passed by `env_logger`, `libc`, `is-terminal`, `regex` and `termcolor` — verified independently by two planners, and a widened name list was measured **not** to close it. D90 formally withdraws "the lane will catch it" as an argument.
- Accept:
  - Crate builds; unit tests against a local stub server exercise timeout, retry, and each error class.
  - `antseal-core` has no HTTP/network dependency (dependency-graph assertion; CI enforcement wired by Q).
  - No anchor network code exists outside `antseal-anchor` (review checklist item).

### A4 — Build DER `TimeStampReq` constructor in `antseal-core`
- Milestone: M2
- Size: S
- Deps: A2; F: `anchor_digest` = SHA-256(full manifest bytes) available from the manifest path (F7); C: SHA-256
- Spec: Anchoring RFC 3161 (line 109), Core user flows (line 34)
- Do: Implement `build_timestamp_req(anchor_digest: &[u8; 32], nonce: &[u8]) -> Vec<u8>` producing a DER `TimeStampReq` v1 with `messageImprint` = SHA-256 AlgorithmIdentifier + `anchor_digest`, a caller-supplied random nonce of **exactly 8 bytes** (**corrected 2026-08-02, D59**: this said "≥ 64 bits", an open-ended floor on a value the TSA echoes into the signed `TSTInfo` of every token a bundle then carries forever — the length had to be fixed, not bounded), and `certReq = true` (so responses carry the chain the bundle embeds as intermediates). Nonce generation stays in `antseal-anchor` (OS CSPRNG) so this function is deterministic and golden-vectorable.
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
- Do: At execution time, fetch the root CA certificates anchoring the default TSAs' chains: the FreeTSA root CA (from freetsa.org, fingerprint cross-checked over a second channel) and the DigiCert timestamping root(s) (from DigiCert's official root repository), plus — per **D57 (2026-08-02: include the alternates)** — roots for the documented alternates. **Corrected 2026-08-02 (D57), both names were wrong**: this said "DFN-PKI/**T-TeleSec** for zeitstempel.dfn.de" — the live chain terminates at a self-signed **`DFN-Verein Community Root CA 2022`** with no T-Systems involvement (T-TeleSec anchors DFN's separate *Global* hierarchy); and "Sectigo/**USERTrust**" — we pin the self-signed **`Sectigo Public Time Stamping Root R46`**, USERTrust appearing only as the issuer of a cross-certificate we deliberately do **not** pin. Record provenance for each: source URL, fetch date, SHA-256 fingerprint matched against vendor-published values, over the multi-channel procedure D57 specifies. **No root may be compiled in ahead of its provenance** — D57 leaves three of the five roots with an incomplete channel set (DFN and Sectigo need C3; SwissSign needs C1 plus one of C2/C3 and currently rests on same-operator corroboration alone), and `crt.sectigo.com` **fails TLS from this host** and serves its root over plain HTTP only, so a second non-C4 channel is mandatory there, not elective. Feed the certs into the A6 store build.
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
- Do: Implement WASM-safe token verification over parsed SignedData: signed attributes MUST be present with correct content-type and message-digest attributes; the signature is verified over the DER `SET OF` re-encoding of signedAttrs; the eContent (TSTInfo) digest must match the message-digest attribute; `TSTInfo.messageImprint` must equal `anchor_digest` (SHA-256); nonce equality is checked when an expected nonce is supplied (capture path — bundle verification passes `None` per A-OD7); the signer cert is identified and bound via SigningCertificate/SigningCertificateV2 (ESSCertID and ESSCertIDv2 both supported); **the *signer* certificate's** EKU extension must be present, critical, and contain `id-kp-timeStamping` per RFC 3161 §2.3 — *corrected 2026-08-02 (D60): this said "the TSA cert's", and applying the criticality rule to the whole chain fails a real default, since **DigiCert's intermediate carries a non-critical EKU***. Signature algorithms — *corrected 2026-08-02 (D60), the original list was wrong in three ways, each measured against nine live TSAs*: RSA PKCS#1 v1.5 (SHA-256/384/512) **including bare `rsaEncryption` as the signature AlgorithmIdentifier, which 5 of 9 TSAs emit — DigiCert included**, and ECDSA P-384 **with SHA-512, not the SHA-384 the pairing suggests (FreeTSA, the normative ECDSA default, signs `ecdsa-with-SHA512`)**. **SHA-1 must be rejected as a signature digest** — it is nonetheless *required* in the graph, because ESSCertID **v1**'s `certHash` is SHA-1 by definition and FreeTSA emits v1 (verified identical across two independent captures). Read `docs/decisions/D60-der-cms-x509-pins.md` for the pin set and the boundary between what a crate does and what antseal writes by hand.
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
- Do: Implement chain building from the signer cert through bundle-supplied intermediates to a pinned root: per-link signature verification (**RSA PKCS#1 v1.5 with SHA-256/384/512 — the 384 and 512 variants were missing from this list, and every FreeTSA cert link is `sha512WithRSAEncryption`** — plus ECDSA P-384/SHA-512; corrected 2026-08-02, D60), name chaining, BasicConstraints and KeyUsage checks — **but BasicConstraints must NOT be required on the signer certificate** (added 2026-08-02, D60: **SwissSign's leaf has none**, so requiring it rejects a documented alternate; the constraint belongs on CA certificates in the path, which is what it means). **Clarified 2026-08-02 (D53 §11.6, applied 2026-08-03)**: "single-path" is correct about the *output* — one path is chosen and reported — and misleading about the *search*, which must consider every candidate path before grading. A9 implements this as a lattice (grade = min over a path's steps, max over paths), which makes least-severe-wins, junk-intermediate-immunity and permutation invariance fall out rather than being special cases, and turns the search into a memoised DP over `(node, depth)` instead of the factorial enumeration D53 forbids. **Three path rulings added 2026-08-02 (D57), each from a measured real chain — read `docs/decisions/D57-tsa-root-store-scope.md` for the derivations**: **P1** stop at the *first* pinned match, do not walk the supplied chain to its end; **P2** never anchor on a supplied self-signed certificate; **P3** assume no ordering of the supplied intermediates (five real tokens exhibited three distinct cert orders). **P1 is the one that would otherwise ship broken**: two of five real chains (DigiCert→Assured ID, Sectigo→USERTrust; SPKI equality proven byte-wise) terminate at a **cross-certificate**, so a builder that walks to the end terminates at an unpinned anchor and renders **the production DigiCert default** as `internally-consistent-only`. A24's single-hierarchy test CA never cross-signs, so **no synthetic fixture can reach this bug** — it is reachable only from a real chain. Temporal validity is evaluated at the token's genTime (long-term validation): chain valid at genTime and closing at a pinned root → candidate `proven`; valid at genTime but expired at the caller-supplied verification time → `valid-at-stamping-cert-since-expired` (headline-eligible); chain invalid at genTime → the A-OD1 state with a distinct error detail; well-formed chain closing only outside the pinned store → `internally-consistent-only`. Verification time is an explicit function parameter — core never reads a system clock (WASM determinism).
- Accept:
  - Test chains (A24 test CA) cover: fully valid; expired-after-genTime → `valid-at-stamping-cert-since-expired`; **expired-at-genTime → `AnchorState::Invalid`, code `anchor-cert-not-valid-at-gentime`** (code named 2026-08-03 per D53 §11.4, which this entry had left as bare prose) (**corrected 2026-08-02, D53**: this read "distinct non-headline state per A-OD1", which is satisfiable by `internally-consistent-only` — the option D53 *excluded* — so the Accept row could be passed by the wrong implementation); **not-yet-valid at genTime → `invalid`** (**added 2026-08-02, D53**: A9's `Do` omitted the back-dating direction entirely — it appears in no spec line, task or matrix entry, and it is the adversarially interesting half); untrusted root → `internally-consistent-only`; broken chain signature → `invalid`. Per D53 the partition is: `invalid` iff the chain **names a pinned root** and fails against it; `internally-consistent-only` iff no pinned root is reached at all, bundle-supplied roots included.
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

### A11 — Implement the `.ots` codec with strict limits, op execution, and digest-commitment check
- Milestone: M2
- Size: **L** (was M — raised 2026-08-02 by D58, which replaces "wrap a crate" with "write the codec")
- Deps: A2; **A27 (the limit contract — read `docs/format/anchor-artifact-limits.md` before choosing any number)**; **D58** (the codec ruling — read `docs/decisions/D58-opentimestamps-viability.md` first)
- Spec: Anchoring (line 108), Milestones M2 (line 155), Tamper matrix (line 168), Risks (line 187)
- Do: In `antseal-core`, implement an in-house `.ots` codec over the already-pinned `sha2 =0.11.0` (**D58, 2026-08-02: `opentimestamps =0.2.0` is adopted in no form** — not pinned, not wrapped, not vendored; +0 packages against the crate's +13): execute the op DAG from the stamped digest; require the stamped digest to equal `anchor_digest`, else a distinct "ops do not commit anchor_digest" `invalid` error; extract per-attestation results — pending {calendar URL, commitment} and Bitcoin {attested height, ops-derived merkle root}. **Unknown ops and unknown attestation types are two rules, not one** (corrected 2026-08-02, D58 §12.2 — the original single clause is *not implementable*): an unknown **attestation** payload is length-prefixed and therefore skippable, and surfaces as a typed unverifiable result; an unknown **op tag carries no length**, so it cannot be skipped at all and terminates that branch with its own typed outcome. Per **F3**, unknown is *not* over-limit either way, so both paths keep their own treatment and are not governed by a limit. **Limits split in two, per A27's contract (D84 §5) — do not mint a constant without checking which half it falls in.** (a) **Already frozen, consume by name, never redefine**: the "max file size" over a bundle-embedded `.ots` **is `MAX_OTS_BYTES` = 1 MiB** (D10 row 16), which already fires in verify stage 1 with its own error code; A11 adds no byte cap over that field. (b) **Genuinely open, chosen here at M2 against A25's recorded pending and upgraded `.ots`**: max op count, max append/prepend operand length, max branch depth/width, max attestation count, **max running-value length and max attestation-payload length** (the last two added 2026-08-02 by D58 — each corresponds to a *measured uncatchable abort* in the rejected crate: an unknown attestation tag drove `vec![0; attacker_varint]` to a 549 755 813 887-byte allocation failure, and `MAX_OP_LENGTH` capped the operand while nothing capped the running value, so a repeated hexlify doubled it. `docs/format/anchor-artifact-limits.md` §4 still says "these eight" and is short by these two — pending a dated D84 amendment, since that file is spliced programmatically from D84 and must not be hand-edited). **D58 §7 sets all seven values with their F4 rows and structural derivations — use them; do not re-derive.** Every (b) limit obeys **F1–F4**: evaluated only in the anchor stage, never reachable from `SealProof::decode`; an over-limit artifact fails **that anchor alone** as `invalid`; raise-only afterwards; recorded in A27's F4 registry. The receive-side cap on A13's *merged* `.ots` is **A28's**, not this task's, and carries the derived constraint **`merge_cap <= MAX_OTS_BYTES`**.
- Accept:
  - Recorded real pending and upgraded `.ots` fixtures parse and classify correctly.
  - `.ots` stamping a different digest → distinct `invalid` error (A21 row 1).
  - Each (b) limit has a rejection test with a distinct error, plus its F4 registry row (value, A25 fixture measured against, margin, `lowered: never`).
  - **F1 demonstrated, not asserted**: a test proves an over-limit `.ots` still yields a decodable bundle with a verified manifest and only its own anchor `invalid` (F2/F3).
  - No new constant duplicates `MAX_OTS_BYTES` (grep-level review item).
  - Fuzz entry point for A23 runs 1 h clean; `wasm32-unknown-unknown` build passes.
  - **Added 2026-08-02 (D58)**: the four executed aborts that condemned the rejected crate are regression tests here — the 80-byte unknown-attestation allocation abort, the 102-byte running-value abort, the 87-byte unbounded-shift case (which *panicked in debug and silently parsed to a different answer in release*), and the 90-byte case where the crate and `python-opentimestamps` reported **different attestation sets** from the same bytes. The last is the one that matters most: sealer-authored bytes showing different anchors to different verifiers is what antseal exists to deny.
- Notes: **Corrected 2026-08-02 (D58).** This entry previously read *"`opentimestamps` 0.2.0 is from 2023 and dormant — verify at execution time that it compiles on current stable and wasm32; vendoring/forking the codec is the contingency"*. **Both halves were wrong.** It *does* compile — `cargo check` and full codegen, native and `wasm32-unknown-unknown`, all green — so the stated test decides nothing and an implementer following this literally would have pinned on a green compile. And vendoring is not the cheaper contingency: the crate is **edition 2015** (`extern crate`, crate-relative `use`), built on `std::io::Read` and hashing via `bitcoin_hashes`, so every line needing change is a line; what survives is ~20 lines of protocol constants, recorded in D58 §7. Real-fixture Accept bullets bootstrap from the early A25 capture and are finally re-run at A25 — note that **no real *upgraded* `.ots` exists yet** (the two-day cycle started 2026-08-02T19:16Z), so four F4 rows are bootstrapped from the rust-opentimestamps `LARGE_TEST` mainnet proof with that provenance in the registry cell, and A25 must re-measure them. **Corrected 2026-07-28 (A27/D84 §5)**: this `Do` previously promised "max file size" as if unset — it is the frozen `MAX_OTS_BYTES`, and an implementer reading this file alone would have minted a duplicate.

### A12 — Implement embedded Bitcoin header offline check producing `attested`
- Milestone: M2
- Size: S
- Deps: A11, A2; F: bundle schema making height+header+fetch-date mandatory for upgraded OTS (F8)
- Spec: Anchoring (line 108), Verifier web page (line 131), Reveal bundle (line 114)
- Do: Implement offline evaluation of an upgraded OTS artifact: the embedded header must be exactly 80 bytes; parse its merkle-root field and require it to equal the ops-derived root for the attested height (byte order pinned empirically by a real upgraded fixture); on match, the state is `attested` — never headline-eligible offline (a lone header's PoW is self-referential; this deliberate online-gating closes the wholesale-forged-bundle attack) — carrying height, header, and fetch date as evidence for R. **`verified_time_unix` MUST be `None` for an `attested` anchor** (**added 2026-08-02, D56** — the rule this `Do` omitted, and the invariant *no existing test can see*, because `aggregate_anchors` already drops times on ineligible slots: a wrong time set here is currently invisible downstream). On mismatch → `invalid` (forged Bitcoin attestation/header class). A missing header on an upgraded artifact is an F-side schema decode error — assert that contract with a test.
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
- Do: For each pending attestation, GET the calendar's upgrade endpoint for its commitment; on receiving a Bitcoin attestation, merge the returned ops/attestation branches into the stored `.ots` (dedupe; retain other calendars' pending attestations until they upgrade) and re-validate via A11. On the first Bitcoin attestation, fetch the attested height's 80-byte header via the must-agree esplora primitive (A16), require the fetched header's merkle root to match the ops-derived root before recording, and store height + header + fetch date for bundle embedding (F encodes). Distinguish "not ready yet" from hard calendar errors for status/nag reporting. **The discriminator is three-way and body-separated, not status-code-based** (**added 2026-08-02, D58**, falsified against a live calendar rather than assumed): a real, not-yet-upgraded commitment returns **`404` with a 42-byte `Pending confirmation in Bitcoin blockchain` body**, while a one-byte-corrupted commitment returns **`404` with a 9-byte `Not found` body** — identical status codes, different bodies. The HTTP substrate must therefore expose response bodies on non-2xx responses; a client that collapses non-2xx into a status error cannot implement this task.
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
  - Returned header is exactly 80 bytes; agreed result is byte-identical from both endpoints. **This byte-identity rule is correct here and must NOT be generalised** (noted 2026-08-02, D90/D55): it holds because an esplora header is a fixed 80-byte object. A17's Arbitrum pair is the opposite case — the two ruled endpoints return **different JSON key sets for the same receipt** (`timeboosted` vs `blobGasUsed`) while the extracted tuple is identical, so a byte comparator there would report "lying endpoint" for two honest RPCs. D90 therefore ships **no** shared comparison helper.
  - Defaults verified live once via A25; overrides flow from U's config.

### A17 — Implement Arbitrum two-RPC transaction confirmation (advisory only)
- Milestone: M2
- Size: M
- Deps: A3, A16 (primitive); A-OD3; S: `PaymentReceipt` contents (tx hashes, block number); U: per-network endpoint config; R: overlay rendering
- Spec: Core user flows (line 38), Anchoring (line 110), Verifier web page (line 137)
- Do: Implement `confirm_arbitrum_tx` over two public Arbitrum RPC endpoints (defaults per A-OD3, user-overridable) using `eth_getTransactionReceipt`: both must agree on tx presence, success status, blockNumber, and blockHash. The output is advisory `OnlineEvidence` feeding only the receipt's "supporting evidence" overlay — it never creates, promotes, or affects any anchor state and never yields a headline time. It runs only when a receipt is available (bundle built with `--include-receipt`, or the sealer's own vault). Per **D33 (2026-08-01)**: this task **consumes the S7 receipt** — the tx hashes and block number are captured (and backfilled) inside `antseal-net::pay()` over the payment RPC; A17 never captures or backfills receipt fields, it only re-confirms them as verify-time advisory evidence.
- Accept:
  - Stub-RPC tests: agree / one-down / disagree / tx-absent / **`Lagging`** each produce distinct typed outcomes. **Corrected 2026-08-02 (D55)**: the first four are four names for a **five**-outcome space — the case where one endpoint returns `null` for a transaction the other has (an ordinary consequence of unsynchronised chains, not a fault) is neither "one-down" nor "disagree", and collapsing it into either reports a healthy pair as broken. Note also that "must agree" is over an **extracted tuple, never over bytes**: the two endpoints D55 ruled in return different JSON key sets for the same receipt (`timeboosted` vs `blobGasUsed`) while the extracted tuple is identical.
  - **Added 2026-08-02 (D55)**: the `eth_chainId` guard the payment path already carries (`ant_backend.rs:217`) applies here too — A17's `Do` omitted it, so a correctly-agreeing pair on the *wrong network* would confirm.
  - Type-level or test-enforced separation: this result cannot enter the anchor state machine as an anchor.
  - Per-network endpoint sets (arbitrum-one vs arbitrum-sepolia; disabled on devnet) configurable; one live round via A25.

### A18 — Implement the per-anchor verdict state machine with aggregate summary data
- Milestone: M2
- Size: M
- Deps: A2, A8, A9, A11, A12, A16 (evidence types), A17 (evidence types); A-OD1, A-OD4; R: wording/rendering/headline selection (R17/R18)
- Spec: Verifier web page (lines 127–137), Anchoring (lines 106–110), Milestones M2 (line 155)
- Do: Implement pure `evaluate_anchors(artifacts, online_evidence, verify_at) -> AnchorVerdicts` in `antseal-core`, mapping every artifact to exactly one of the seven states with headline-eligibility flags: TSA → `proven` [H] / `valid-at-stamping-cert-since-expired` [H] / `internally-consistent-only` / `invalid` / `absent`; OTS → `pending` / `attested` / `proven` [H] (only when online evidence shows the embedded header equals the agreed fetched header for height H, taking the block timestamp as the proven time) / `invalid` (online header mismatch, or ops not committing `anchor_digest`) / **`internally-consistent-only`** / `absent`. **The OTS route to `internally-consistent-only` was missing from this list** (**added 2026-08-02, D56** — an implementer following A18 alone would have shipped the state as TSA-only). Its trigger is D56's, taken from spec line 133's own definition: an `.ots` whose ops **do** commit `anchor_digest` while **every** branch ends in an op or attestation the verifier cannot evaluate. Precedence across a merged multi-branch `.ots` is **best-evidence-wins**, not refutation-wins — D56 §4: the bundle is unsigned, so under refutation-wins any relay could append one garbage branch and turn an honest anchor `invalid`, a downgrade-to-forgery-accusation primitive. Read `docs/decisions/D56-ots-internally-consistent-trigger.md` for the full ordered rule set (O1–O9); implement that order, not this summary. Emit wording-free PER-ANCHOR result data for R: state, verified time + source, headline-eligibility flag, and artifact metadata. Verdict AGGREGATION — earliest headline selection, the >48 h divergence flag, and the UNANCHORED outcome — is R17's (M3); A1's minimal zero-headline-eligible aggregate flag covers M1/M2 library use until R17 lands. Online evidence is pure input — core never fetches; CLI (via `antseal-anchor`) or page JS supplies it.
- Accept:
  - Exhaustive test: every one of the seven states reachable from a concrete fixture. **Corrected 2026-08-02 (D53 §4a)**: this said "`absent` covered by the empty-anchor vector" — **that clause passes vacuously**, because the empty-anchor vector produces *zero* anchor slots, so it witnesses nothing and would keep passing if the variant were deleted. `Absent` is what the evaluator returns for an anchor **kind with no artifact**, and R12 emits no slot for it; test it that way, and make the test fail if the variant is removed.
  - `attested` is never [H] without online evidence; matching online evidence promotes to `proven` with the block-header timestamp; mismatch → `invalid` — and the fixture must be one whose ops **commit** the embedded header; the uncommitted shape is already `invalid` offline through O8, so it discharges this clause **vacuously** (D93 §3, which measured exactly that).
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
- Do: Build committed fixtures and tests covering every M2 anchor row, each failing (or classifying) with a distinct error/state. **The row count is EIGHT, not seven** (**corrected 2026-08-02, D53**: spec line 168's M2 half is six semicolon clauses of which two are compound, expanding to eight cases — and the project reached "seven" twice by *different* routes, `MATRIX.json` splitting the expiry clause and this entry splitting the digest clause, so the two sevens were never the same seven. **Corrected again 2026-08-06 by the implementing lane**: the trailing clause here said *"the eighth is A9's not-yet-valid-at-genTime direction"*, and that is wrong in a way that would have cost the lane a row. D53 §8 had already ruled that direction a **named test**, not a row — `chain::tests::a_certificate_not_yet_valid_at_gentime_is_the_same_code`, which has been committed since A9 — because `TemporalBound` is diagnostic payload only (D85) and both directions carry the code `anchor-cert-not-valid-at-gentime`. A row for it would claim row 6's outcome key and `check_registry` would correctly refuse the pair. The eight are exactly the eight `MATRIX.json` enumerates, and the union of the two sevens is what makes them eight.) **Trap, recorded by D53 so the lane does not lose a day to it**: the `anchor-forged-header` fixture must be **single-branch** — built the obvious way, by forging the header of a real *merged* `.ots` from A25, the sibling pending branches survive, D56's rule O5 fires first and the row renders `pending`; the test then fails correctly and the temptation is to blame the rule. Rows: (1) `.ots` stamping a different digest → `invalid`; (2) TSA token whose messageImprint is a different digest → `invalid`; (3) well-formed TSA token chaining to an untrusted root (test-CA root excluded from the injected store) → `internally-consistent-only`, not headline-eligible; (4) forged Bitcoin header that fails the `--online` block match → `invalid`; (5) positive control: an `attested` OTS anchor correctly withheld from offline headline eligibility; (6) expired-at-genTime chain (per A-OD1 state) vs expired-after-genTime (`valid-at-stamping-cert-since-expired` [H]) — distinct outcomes; (7) BER-where-DER-required → distinct DER-strictness error. Fixture generation is scripted and reproducible; test-CA keys are fixture-only material. **Homing ruling, 2026-08-06 (orchestrator, resolving A90 before this task starts)**: the eight rows are registered and driven from the tamper harness natively, **and** each row's verdict assertion is *additionally* pinned as an in-module `#[cfg(test)]` test beside A18's, because the wasm32 lane runs `--lib` only and every integration target is a separate crate that never executes there. This is not a new pattern — **A18** already runs its 44 verdict rows native and wasm32 this way, and **A43** adopted it for the same stated reason. The rejected alternative is moving `anchor::testing`'s writer down to the `test-vectors` tier: `test-util ⊃ test-vectors`, only I/O-free zero-optional-dep code may sit on `test-vectors`, and that tier has broken the wasm32 build once already. Do not discover this mid-task: an A21 row that lives only under `crates/antseal-core/tests/` satisfies the wasm32 Accept row **in appearance only**. **Second trap, found at D93 §3 and worse than the first**: row 4's fixture must be single-branch **and** its ops must **COMMIT** the embedded header. The uncommitted forgery satisfies `verdict:invalid` today through O8 — offline, with the online gate never running — so a row built that way is green and blind. The mutation is the embedded header's `nTime` with bytes 36..68 untouched; the base renders `proven`, the mutant `invalid`, and the same mutant with the evidence withheld renders `attested`. **A80 must land first** (the machine cannot produce that outcome at the wave-4 head) and **A82 must land first** (the `.ots` builder is `#[cfg(test)]`-private to `anchor::verdicts::tests` and invisible to every home the matrix uses).
- Accept:
  - One test per row; no two rows share an error/state variant (distinctness asserted).
  - **Row 3 needs a positive twin** (**added 2026-08-02, D57**): the untrusted-root row is a negative with nothing opposite it, yet **three of the five real tokens ship their own root inside the chain** and must still reach `proven` while doing so. Without the twin, an implementation that rejects any chain containing a self-signed cert passes the whole matrix.
  - Row 5 returns `VerdictState("attested")` **only when `!is_headline_eligible()`**; a plain state name is blind to the rule the row is named after (D93 §9).
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
- Do: Script non-CI smoke runs against real services using a fixed test digest: (1) submit to the real default OTS calendars and store the pending `.ots`; (2) the next day, upgrade → verify `attested` offline, then `--online` promotion to `proven` via real blockstream.info + mempool.space; (3) obtain and fully verify real FreeTSA (ECDSA P-384) and DigiCert tokens against the pinned root store; (4) one live must-agree round each for esplora and the Arbitrum RPC pair. Record the artifacts (tokens, pending/upgraded `.ots`, header) as the committed fixtures A5/A8/A11/A12/A22 consume, and verify all default endpoint URLs/paths are live and correct. An early bootstrap capture may run as soon as A3/A4 exist, seeding A5/A11/A12 development fixtures; the full protocol re-runs at task completion. **Corrected and superseded 2026-08-02**: this scoped the bootstrap at "one TSA response per default endpoint + one pending `.ots`" and **it was under-scoped** — the M2 planning round needed, and captured, far more. What is already on disk under `testdata/anchors/A25-bootstrap/`, all captured 2026-08-02 with a `CAPTURE.log` per group: pending `.ots` timestamps for **two** committed golden-vector `anchor_digest`s at **three live calendars** (19:16Z — `finney.btc.calendar.opentimestamps.org` failed DNS resolution and is not in upstream's default list at all); a real FreeTSA request/response pair (`freetsa-D59-*`); **five TSA root certificates with a provenance record** (`roots-*`); and **nine live TSAs captured and dissected** for the pin decision (`D60-*` + `D60-CAPTURE.log`). The two-day OTS clock therefore started **2026-08-02T19:16Z**; the upgrade half is due **not before 2026-08-04**. A25's remaining work is the day-2 upgrade, the `--online` promotion, and the live must-agree rounds — not the TSA capture, which is done.
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

### A30 — Contain the D60 pin set: `from_ber`, SHA-1, and the recursive-walker ban
- Milestone: M2
- Size: S
- Deps: D60 (the pins); A5 (the first code that consumes them); Q1 (`scripts/ci-lanes.sh`)
- Spec: Architecture (MVP-SPEC.md lines 47–53, 106), Anchoring (line 109), Risks — hostile bundles (line 187)
- Discovered by: **D60** (2026-08-02). Three containment properties the decision depends on, none of which any existing lane asserts. Precedent and shape: the `dep_graph` lane's existing self_encryption and payment-stack rules — same command, same self-test-first discipline, same file.
- Problem: D60 measured three facts that are true today and silently reversible tomorrow. (1) `cms =0.3.0-pre.2` requires `der` with its **`ber`** feature, and cargo unifies it, so `Decode::from_ber` and `EncodingRules::Ber` are reachable from every antseal source file. D60 §2 proves this does not weaken `from_der` — but nothing stops a future implementer *calling* `from_ber` on a TSA token, which would accept exactly the artifacts A5's BER row exists to reject. (2) `sha1 =0.11.0` is now in `antseal-core`'s WASM-safe graph. It is admissible only because its single caller is the ESSCertID v1 `certHash` binding (D60 §3.4); a second caller — a signature digest, a `messageImprint` algorithm, a cert-link digest — turns a documented selector into a real cryptographic dependency on a broken hash, and would pass review because the crate is already there. (3) D60 §2.4 measured a hand-written recursive DER walk overflowing the stack and **aborting** (`fatal runtime error: stack overflow`, exit 134) at ~20 000 nesting levels — uncatchable by `catch_unwind`, a trap on wasm32, and a direct violation of A5's "never panics". `der`'s own `MAX_DEPTH = 64` guard does not cover code antseal writes.
- Do: add three rules to `lane_dep_graph` in `scripts/ci-lanes.sh`, each **self-tested first** against a planted violation before its verdict is trusted, exactly as the self_encryption and S23 rules already are. (a) The tokens `from_ber` and `EncodingRules::Ber` appear on **no code line** in any workspace crate (comment-leading lines are citations, per the existing S6 convention). (b) `sha1::` / `Sha1` appear on code lines only in the one module that implements the ESSCertID binding — a single-file allowlist, in the shape of S6's adapter allowlist. (c) The seven D60 pins (`der`, `const-oid`, `x509-cert`, `cms`, `p384`, `rsa`, `sha1`) are DECLARED by `antseal-core` and by no other crate, read from `cargo metadata --no-deps` so a feature-gated or renamed edge cannot hide — the S23 extractor is already written and takes the dependency-name regex as a parameter. Add the recursive-walker ban as a **test**, not a grep (a grep for recursion is not writable): `anchor_core_has_no_recursive_der_walker` reproduces D60's nesting generator at 200 000 levels and asserts the anchor stage returns a typed error rather than dying, which is the property that actually matters.
- Accept:
  - Each of (a), (b), (c) fails red against a planted violation, and the plant is in the shape `cargo metadata`/the source scanner really emits — the self-test runs on every invocation, before the real verdict.
  - Rule (b) proves both directions: the real ESSCertID module is NOT reported, and a `Sha1::digest` planted in a second module IS.
  - Rule (c) carries the S23 anti-vacuity check: the scan must still find `antseal-core der`, or the parse is broken rather than the tree clean.
  - `anchor_core_has_no_recursive_der_walker` passes with a 200 000-deep input and is demonstrated red against a deliberately recursive prototype (the red direction is the whole point; the D60 probe is committed evidence it can happen).
  - Lane runtime stays inside the existing `dep-graph` budget (no new cargo build).
- Notes: rule (a) is cheap to state and would be expensive to discover late — an accidental `from_ber` produces a *passing* verification of a BER token, i.e. a silent weakening with no failing test anywhere. If a future `cms` release drops the `ber` requirement, rule (a) becomes vacuous rather than wrong; the D60 `der_pin_rejects_indefinite_length` test is what keeps the real property witnessed.

### A31 — Two TSA endpoints that are one TSA count as one anchor
- Milestone: M2
- Size: S
- Deps: A10 (the capture client), A20 (the minimum-anchor gate), A26/Q26 (the alternates table)
- Spec: Anchoring (MVP-SPEC.md line 109), Context decision 3 (line 19), Milestones M2 (line 155), Risks (line 189)
- Discovered by: **D60** (2026-08-02), while surveying nine live TSAs for the P-256 question.
- Problem: `http://timestamp.entrust.net/TSS/RFC3161sha2TS` returned a token whose signer certificate is **byte-identical** to `http://timestamp.sectigo.com`'s — same issuer (`CN=Sectigo Public Time Stamping CA R41`), same serial (`0xE74EF255B0504FFADBA6DFF7FC8BA315`), same 1766-byte certificate. Entrust's timestamping service is served by Sectigo. Both fixtures are committed (`testdata/anchors/A25-bootstrap/D60-tsa-{entrust,sectigo}-resp.tsr`). Two consequences, in ascending severity. The mild one: A26/Q26's alternates table would list them as two independent choices, which is misleading documentation. The real one: a user who configures both and believes they hold two independent anchors holds one — a single TSA key compromise, a single CA revocation, a single outage takes out both. A20's gate only requires ≥1 verified token so nothing is currently *unsafe*, but the degradation report and the `list`/`status` rendering would overstate the evidence, and the spec's own framing is that anchors are independent (line 109's multi-TSA default exists for exactly that reason).
- Do: define TSA independence as an observable, not as a URL: two captured tokens are from the **same TSA** iff their signer certificates have the same `(issuer, serialNumber)` pair. Have A10's capture record carry that pair (it already parses the certificate), and have A20's degradation report and the `evaluate_seal_gate` outcome count **distinct** TSAs rather than distinct endpoints — the gate threshold stays "≥1 verified token", so this changes reporting and any future ≥2 policy, not today's abort rule. Add the fact and its measurement to the A26/Q26 alternates table so the documented caveat for Entrust is "served by Sectigo — not an independent second anchor".
- Accept:
  - A test over the two committed fixtures asserts they resolve to one TSA identity, and over the FreeTSA/DigiCert pair asserts they resolve to two.
  - A degradation report for a seal that captured both Sectigo and Entrust states "1 distinct TSA" and names the collapse; a report for FreeTSA + DigiCert states 2.
  - The alternates table carries the caveat with its measurement date.
  - No change to A20's gate threshold (asserted: the decision table's outcomes are unchanged by this task).
- Notes: the discovery generalises — TSA resale and white-labelling are ordinary in this market, so the check is worth having independently of this one instance. It deliberately keys on the signer certificate rather than on the CA, so two genuinely different TSAs under one root still count as two.

### A32 — A token's `genTime` is never invalid because a local clock says so
- Milestone: M2
- Size: S
- Deps: A10 (the capture client, which stamps `fetch_date`), A9/A18 (which take `verify_at` as a parameter)
- Spec: Anchoring (MVP-SPEC.md lines 108–109), Verifier web page (lines 128–130), Core user flows (line 38)
- Discovered by: **D60** (2026-08-02), from the capture host itself.
- Problem: the machine that captured every fixture in `testdata/anchors/A25-bootstrap/D60-*` had a clock running **129 s slow**, measured against three unrelated hosts' HTTP `Date` headers within one second of each other (freetsa.org +129 s, crates.io +128 s, blockstream.info +129 s) and consistent with the 128 s gap between the local POST time and FreeTSA's `genTime`. An implementer writing the obvious sanity check — "a timestamp cannot be from the future, so reject if `gen_time > fetch_date`" — would reject **every token in that directory**, and would reject real tokens on any user machine whose clock is behind by more than the TSA's response latency, which is a common and entirely benign condition. `antseal-core` cannot make this mistake by construction (it reads no clock; `verify_at` is a parameter — A9, A18), so the exposure is entirely in `antseal-anchor`'s capture path, which is the one component that both reads a local clock and holds a token.
- Do: state the rule where the code is — no capture-path or anchor-stage check may treat a token as invalid, unverifiable or suspect on the basis of a comparison between its `genTime` and a locally-read clock. `fetch_date` is recorded as **provenance metadata**, never as a validity input. If a future skew warning is wanted it is advisory-only, one-directional (large *positive* skew, i.e. a `genTime` far in the future), with a tolerance no smaller than a few minutes, and it never changes an anchor state. Add the regression test and the reason to the module's doc comment, citing the 129 s measurement so the next reader meets the evidence rather than a rule.
- Accept:
  - A test feeds a real committed token together with a `fetch_date` **earlier** than its `genTime` and asserts a complete, successful capture record with no warning-bearing state change.
  - A grep-level or test-level check proves no comparison between a `genTime` and a system-clock reading gates any outcome in `antseal-anchor`.
  - `antseal-core`'s clock-freedom is re-asserted (it already is, by the `core-dep-graph` lane and by `verify_at` being a parameter) so the rule is visibly scoped to the network side.
- Notes: this is the cheapest possible task and the most likely to be dismissed as obvious. It exists because the failure it prevents is invisible in CI — CI machines have good clocks — and appears only on a user's machine, as an anchor that mysteriously will not verify. The committed fixtures are themselves the permanent regression corpus: they cannot be made to satisfy a naive check without re-capturing them on a synchronised host.

### A33 — Rule what a critical unrecognised `TSTInfo` extension means
- Milestone: M2
- Size: S
- Deps: A5 (landed)
- Spec: Anchoring (line 109)
- Do: RFC 3161 §2.4.2 gives `TSTInfo` an `extensions [1] IMPLICIT Extensions
  OPTIONAL` field. A5 parses it for well-formedness and then **ignores it,
  criticality included** — which means a token carrying a *critical* extension
  antseal does not understand is currently accepted. No decision in the
  register rules on this, and inventing a rule against zero fixtures is
  precisely the defect D60 §4 refuses, so A5 recorded the measurement instead:
  `crates/antseal-core/tests/anchor_real_tokens.rs::no_live_tsa_sends_tst_info_extensions`
  asserts that **none of the nine live TSAs sends any**, and goes red the day
  one starts. Decide the rule (reject on unrecognised-and-critical, per the
  X.509 convention; or accept and record why) and either way keep the
  measurement test, since it is what makes the question observable.
- Accept:
  - A dated decision entry, or a recorded non-rule in `tasks/A.md` with its
    reason.
  - If reject-on-critical is chosen: a distinct `anchor-` code, a synthetic
    fixture, and a tamper row.
  - `no_live_tsa_sends_tst_info_extensions` still present and still asserting
    the corpus is empty of them.
- Notes: The same question exists for `TSTInfo.tsa`, which A5 also parses and
  never reads — RFC 3161 makes it informational and the signer certificate is
  what identifies the TSA, so that half is probably a one-line non-rule.

### A34 — Implement the `.ots` encoder with deterministic branch ordering
- Milestone: M2
- Size: S
- Deps: A11 (the codec, its limits and its error set); A13 (the sole consumer); D58 §7.3
- Spec: Anchoring (line 108), Reveal bundle (line 114), Milestones M2 (line 155)
- Do: In `antseal-core`, at `crates/antseal-core/src/anchor/ots/encode.rs`, implement the writer half of the in-house codec D58 rules in: emit the 65-byte container header (31-byte magic, version varuint `1`, digest-type `0x08`, 32-byte `anchor_digest`) followed by the timestamp body, with `0xff` preceding every branch except the last. **Branch order is imposed by this task, not by the format**: sort branches by their serialized op-stream bytes, lexicographically, so two seals of the same digest against the same calendar set produce byte-identical files. Encoding is the inverse of A11's parse for every artifact A11 accepts, and the encoder MUST NOT be used to re-emit a *received* file — D58 §4 shows a parse/re-serialize cycle can change attestation length fields, so A13 stores the bytes it assembled, and the encoder exists for assembly, not for normalization. The encoder is subject to the same limits as the parser: it refuses to emit an artifact that A11 would reject, so a merge bug surfaces as a typed error at write time rather than as an unparseable stored anchor.
- Accept:
  - Round-trip on the A25 merged fixture is **byte-identical** in both directions (`parse(encode(parse(bytes))) == parse(bytes)` and `encode(parse(bytes)) == bytes`).
  - Branch order is deterministic: encoding the same three calendar responses supplied in all 6 permutations yields one identical file. Fails if the sort is dropped.
  - Encoding an artifact that violates any D58 §9.1 limit returns that limit's error rather than writing bytes; test per limit.
  - `wasm32-unknown-unknown` build passes; native/wasm encode outputs bit-match.
- Notes: Discovered by D58 (2026-08-02). The `opentimestamps` crate supplied `DetachedTimestampFile::to_writer`, so no task ever owned encoding; D58 removes the crate and the gap becomes visible. D58 §3.4 also records why the rejected crate's writer could not have been used even if the crate were adopted — its serializer panics (index-out-of-bounds and subtraction overflow) on exactly the hand-built trees a merge produces.

### A35 — Cross-implementation `.ots` differential conformance harness
- Milestone: M2
- Size: M
- Deps: A11, A34, A25 (the recorded corpus); A23 (shares the corpus, not the mechanism)
- Spec: Verification — every mutation fails with a distinct error (line 168); Format stability (line 123); Verifier web page (line 131)
- Do: Build a differential harness that compares `antseal-core`'s `.ots` verdict against the reference implementation's over a corpus, and fails when they disagree in a way that is not an explicitly recorded, justified divergence. Corpus: A25's recorded real artifacts, every D58 §11 adversarial input, every §9.3 `cap + 1` witness, and the A23 fuzzer's saved crashers. Reference side runs **offline from committed recordings** — Q16 forbids real anchor endpoints in CI, and this harness must add no network dependency; capture the reference tool's per-input output once, by hand, into `testdata/anchors/conformance/`, and compare against the recording. Divergences are not automatically failures: maintain a committed allow-file of *intended* divergences, each with a one-line reason (D58 names two — antseal renders unimplemented-op subtrees `unverifiable` where the reference errors, and antseal accepts non-minimal varuints the reference also accepts but the crate mishandled). An unlisted divergence fails.
- Accept:
  - The harness runs in the existing test lane with no network access and no new CI context.
  - **Red direction proven, not assumed**: reintroduce D58 §4's defect (ignore the declared attestation payload length instead of sub-slicing) and the harness must go red naming the 90-byte input — a unit test cannot catch this class, because a unit test asserts what *we* think the bytes mean.
  - The allow-file is non-empty, every entry carries a reason, and an entry whose divergence no longer occurs fails as stale (an allow-file that can only grow is the same defect as a test that cannot fail).
  - Every corpus input is exercised; a corpus file present on disk but unread fails the run.
- Notes: Discovered by D58 (2026-08-02). Rationale is D58 §4: `opentimestamps` 0.2.0 and `python-opentimestamps` report **different attestation sets from an identical 90-byte input**, and neither implementation's own tests could see it, because agreement between implementations is not a property either one can assert alone. The in-house codec inherits that exposure the moment it exists.

### A36 — `docs/format/registry-v1.md` §7.9 key 1 names two ASN.1 types with one slash
- Milestone: M2
- Size: S
- Deps: A5 (landed)
- Spec: Format registry §7.9
- Do: The TSA anchor's `token` field is described as *"var — DER
  TimeStampResp/token, opaque"*. Those are two **different** ASN.1 types —
  `TimeStampResp ::= SEQUENCE { PKIStatusInfo, TimeStampToken OPTIONAL }` and
  `TimeStampToken` = a CMS `ContentInfo` — and the registry rules neither out.
  A capture client naturally stores what the TSA sent; other tooling commonly
  stores the bare token (what `openssl ts -reply -token_out` writes). A5
  therefore accepts **both**, dispatching **structurally** on the first inner
  tag (OID ⇒ `ContentInfo`, SEQUENCE ⇒ `TimeStampResp`) rather than by
  try-then-fall-back, which would report whichever error came second and make
  every malformed artifact look like the wrong shape. When the artifact is a
  response, its `PKIStatus` is enforced. Ratify that as the rule and say so in
  the registry, or narrow it to one shape and say which — but the current
  phrasing cannot be implemented twice the same way, and the field is frozen
  v1 surface.
- Accept:
  - §7.9's key-1 row states which shape(s) a v1 bundle may carry.
  - `both_registered_artifact_shapes_are_accepted` still passes, or is
    replaced by a test of whichever narrower rule is chosen.
- Notes: Narrowing is a **format decision**, not an implementation detail:
  a bundle already in the field carrying the other shape would stop verifying,
  which MVP-SPEC.md line 123 forbids. Ratifying "both" is the cheap answer and
  is what A5 implements today.

### A37 — Record the `digestAlgorithm` / `signatureAlgorithm` consistency **non-rule**
- Milestone: M2
- Size: S
- Deps: A8 (landed)
- Spec: Anchoring (line 109); D60 §3.2.6
- Do: When `SignerInfo.signatureAlgorithm` is an explicit
  `shaNNNWithRSAEncryption` or `ecdsa-with-SHAnnn`, it names a digest, and so
  does `SignerInfo.digestAlgorithm`. RFC 5754 expects them to agree. **A8 does
  not check that they do**, deliberately: D60 §3.2.6 says `digestAlgorithm`
  "is self-checking in both of its uses (a flipped value breaks the
  message-digest length comparison and the signature simultaneously) — but A8
  must take no other decision from it", and a consistency rule is another
  decision. A8 uses the signature OID's digest for the signature and
  `digestAlgorithm` for the message-digest attribute; both are covered by the
  signature. Write the non-rule down where an implementer will meet it, with
  the self-checking argument, or overturn it — but it must not stay an
  unexplained absence, because "add the obvious consistency check" is exactly
  the kind of hardening that passes review.
- Accept:
  - The non-rule (or the rule) is stated in `tasks/A.md` A8 with its reason.
  - If a rule is added: its own `anchor-` code and a synthetic fixture, plus a
    re-run of the nine-TSA suite to prove no real TSA is inconsistent.
- Notes: Measured today across the nine captures: every explicit-digest
  signature algorithm agrees with its `digestAlgorithm`. So the rule would
  cost nothing — which is an argument for it, and also the reason it can be
  added later at no compatibility cost.

### A38 — Register the `anchor-` error-code prefix and the A-domain code inventory
- Milestone: M2
- Size: S
- Deps: Q7 (the contract + harness); blocks A5 and A11 (the first tasks that mint an `anchor-` code)
- Discovered by: **D53/D56** (2026-08-02). `docs/testing/error-code-contract.md` §2's prefix table has rows for `cbor-`/`manifest-`/`bundle-` (F), `crypto-` (C), `content-` (G) and *(unprefixed)* (R). **It has no row for the A domain**, while §5 of the same document already anticipates M2 anchor rows and A5/A8/A9/A11/A12 each promise distinct error codes. Measured 2026-08-02: `testdata/error-codes/v1/CODES.txt` holds **194** codes and **zero** carry an `anchor-` prefix.
- Problem: §2 forbids the workaround — *"A domain never mints a code under another domain's prefix"* — so A cannot borrow `bundle-`, and the first `anchor-` code would land in a namespace the contract does not describe. Separately, §4b layer 4 (reverse coverage) works by walking a **per-domain exemplar enumerator** (F's `DecodeError`, R's `VerifyError`); with no A-domain enumerator, every `anchor-` code is unowned by construction and the layer cannot see it.
- Spec: Verification — tamper matrix (MVP-SPEC.md line 168); contract `docs/testing/error-code-contract.md` §2, §4a, §4b, §5
- Do: Add the §2 row verbatim — `| `anchor-` | A | anchor-artifact verification: strict DER/CMS, X.509 path validation, `.ots` op execution, embedded-header and online-header checks (A5–A18) |`. Add an A-domain exemplar enumerator over the anchor error enum on the pattern of `test_util::tamper_coverage`'s `CoverageDomain`, so §4b layer 4 sweeps `anchor-` codes, and wire the anchor error family into `crates/antseal-core/src/error_universe.rs` so §4a's additions-only snapshot covers it. Record in §7 (Status) the date and the code count at registration.
- Accept:
  - `docs/testing/error-code-contract.md` §2 names the A domain; a planted `bundle-`-prefixed anchor code fails a test that names the prefix rule.
  - Every `anchor-` code an anchor error family can emit is claimed by a tamper row, by a named row in an integration target, or by an entry naming the task that owes it (§4b layer 4) — planted-fault tested by adding an unowned variant.
  - `testdata/error-codes/v1/CODES.txt` contains the `anchor-` codes; removing or renaming one goes red naming it under its frozen name (§4a's three rows, planted-fault tested).
  - `antseal-core` still compiles for `wasm32-unknown-unknown`.
- Notes: pure infrastructure — it mints no code of its own. Landing it *after* A5 would mean re-homing codes that are already frozen by §4a's snapshot, which is why it is deps-before rather than deps-after.

### A39 — Emit the per-anchor suppressed-anomaly list that best-evidence-wins would otherwise discard
- Milestone: M2
- Size: S
- Deps: A18 (the state machine that produces it); A2 (the type it lands in)
- Discovered by: **D53 §3 / D56 §4** (2026-08-02), as the stated price of both decisions' precedence rule.
- Problem: both decisions rule **best-evidence-wins** — D53's C1/C2 beat C3–C5 (a junk intermediate never demotes a valid chain), D56's O3–O5 beat O6–O8 (a forged branch never demotes a confirmed or pending one) — because the `.sealproof` bundle is **unsigned** and refutation-wins would hand any relay a downgrade-to-`invalid` primitive. The cost is that a refuted certificate path or a forged Bitcoin branch, sitting beside a good one, becomes invisible in the anchor state. Nothing false is asserted and nothing becomes headline-eligible, but the evidence is silently dropped, which is the shape this project records rather than leaves unstated.
- Spec: Anchoring (MVP-SPEC.md lines 106–110); Verifier web page — advisory overlay distinct from the offline verdict (line 137)
- Do: Add a wording-free `suppressed: Vec<AnchorAnomaly>` to A18's per-anchor result inside `AnchorVerdicts` — each entry naming the stable code the suppressed refutation *would* have produced (`anchor-chain-signature-invalid`, `anchor-ots-online-header-mismatch`, …) plus the **branch** index for `.ots`; a chain refutation is reported against the artifact, because D53 §3 forbids a path enumerator and A9's DP materialises no path, so **there is no path index to report** (corrected 2026-08-05 at A39). **It must not enter `VerificationReport`**: `AnchorResult` has exactly five fields and report v1 is frozen (D29/R32; Q14), so R12 projects `AnchorVerdicts` into `Vec<AnchorResult>` and drops this list — the same boundary D86 drew for the decode layer. Assert the boundary with a test rather than a comment.
- Accept:
  - A TSA artifact with one valid path and one broken-signature path renders `proven` **and** carries exactly one suppressed entry naming `anchor-chain-signature-invalid`.
  - A merged `.ots` with one pending branch and one forged Bitcoin branch renders `pending` **and** carries one suppressed entry.
  - An artifact with nothing suppressed carries an **empty** list, not an absent field (so "no anomalies" and "not computed" are never confused).
  - A test asserts no serialized `VerificationReport` byte changes when the list is non-empty — run against the 21 pinned strings in `testdata/vectors/v1/report/verification-reports.json`, which must remain byte-identical.
  - `antseal-core` still compiles for `wasm32-unknown-unknown`.
- Notes: R61 renders it CLI-side. The verifier **page** cannot show it until a `report_version` bump — recorded as a residual risk in D53 §6, not worked around here.

### A40 — Evaluate anchor independence from verified identities, never from array length
- Milestone: M2
- Size: S
- Deps: A18 (verified identities exist only after it); consumed by A20 (the minimum-anchor gate) and R17 (M3 aggregation)
- Discovered by: **D53** (2026-08-02) while reading `docs/format/registry-v1.md` §8 for anchor list-ordering rules.
- Problem: §8 decides that **duplicate anchor artifacts are legal v1, deliberately** — *"a sealer wanting two 'independent' TSA anchors from one TSA simply requests two tokens — different bytes, same TSA, passes any byte-distinctness check"* — and discharges the resulting obligation by naming it: *"**anchor independence must be evaluated from verified identities, never from array length** — an obligation on A18/R17"*. That obligation is carried by **no task text**: A18's Do/Accept never mention independence, A20's minimum-anchor policy counts *"≥1 TSA token passed full core verification"* with no distinctness rule at all, and R17's divergence flag compares times across anchors that may all be one TSA. The registry is frozen prose asserting a guarantee nothing implements. §8 also records this is the **irreversible** direction — permissive now cannot be tightened after the freeze — so the check has to live in the verdict layer or nowhere.
- Spec: Anchoring — minimum-anchor policy (MVP-SPEC.md lines 19, 34, 149); Verifier web page — divergence flag (line 137); `docs/format/registry-v1.md` §8
- Do: Define anchor **identity** in `antseal-core`: for a TSA anchor, the verified signer identity established by the validated path (`AnchorResult::source`'s verified arm — never a bundle-recorded string, per D8 §1); for an OTS anchor, the **chain that proved it** — a single opaque Bitcoin identity shared by every headline-eligible OTS anchor whatever its block or calendars (**D92**; the calendar set was this task's original text and is overturned there, because a calendar URI is a sealer-chosen bundle-recorded string that D54 §4 shows is not a witness at all). Expose, from `AnchorVerdicts`, the count of **distinct verified identities** among headline-eligible anchors, and have R17's rendering read the identity count rather than `anchors.len()`. **A20's gate reads the TSA-scoped count, never the mixed scalar** (`distinct_verified_identities_of(AnchorKind::Tsa)`, or the seal-time `AnchorSubmission::verified_tsa_count`): D54 §3 rules that OTS contributes exactly zero to the minimum-anchor gate, so a `>= 1` test over the mixed scalar would pass a bundle with no TSA at all. R17's **divergence** rule compares times, not identities, and reads neither. State what identity means for the states that carry only a *claimed* identity (`internally-consistent-only`, `invalid`): they contribute **zero** identities, because a claimed identity is not verified.
- Accept:
  - Two `proven` TSA anchors from the same TSA count as **one** distinct identity (test); two from different TSAs count as two.
  - A bundle carrying a byte-identical duplicate `.ots` counts one identity, and still decodes and verifies (§8's legality is not walked back).
  - Two `proven` OTS anchors at different Bitcoin heights, or at one height through disjoint calendar sets, are **one** identity (D92; implemented at A67).
  - `internally-consistent-only` and `invalid` anchors contribute zero identities even when their claimed source strings differ.
  - No code path derives independence from `ots_anchors.len()` or `tsa_anchors.len()` (grep-level review item, plus a test over a duplicate-bearing fixture).
- Notes: this task does **not** change the minimum-anchor gate's threshold — that is A20/D-A's, and MVP-SPEC.md line 137's *"the minimum-anchor policy guarantees ≥1 TSA token"* is unaffected by counting identities instead of artifacts when the count is 1.

### A41 — Reconcile the two A-domain error-code prefixes before any anchor code is minted
- Milestone: M2
- Size: S
- Deps: none (**blocks A38, and through it A5 and A11**); reads
  `docs/decisions/D53-chain-invalid-at-gentime.md` §7,
  `docs/decisions/D56-ots-internally-consistent-trigger.md` §7,
  `docs/decisions/D58-opentimestamps-viability.md` §10.4,
  `docs/testing/error-code-contract.md` §2/§3
- Spec: Tamper matrix (MVP-SPEC.md line 168), Milestones M2 (line 155)
- Do: Two decisions resolved on 2026-08-02 mint A-domain error codes under
  **different prefixes**, and one check gets **two different codes**. Rule on
  both, then hand the result to A38 (which registers the prefix row) before A5
  or A11 mints a code — after that, `docs/testing/error-code-contract.md` §3
  makes every code permanent and `testdata/error-codes/v1/CODES.txt` is
  additions-only, so the wrong choice cannot be withdrawn, only accumulated.
  (a) **Prefix.** D53 §7 mints `anchor-cert-not-valid-at-gentime`,
  `anchor-chain-constraint-violation`, `anchor-chain-signature-invalid` and
  requires a single `anchor-` row whose scope it writes verbatim, explicitly
  covering *"`.ots` op execution"*; D56 §7 mints four `anchor-ots-*` codes on
  the same row. D58 §10.4 instead mints **sixteen `ots-*` codes** under a new
  `ots-` prefix and states *"A5 will want a sibling `tsa-`"*. One prefix or
  three — §2's *"a domain never mints a code under another domain's prefix"*
  makes the choice load-bearing for every later row, and §4b layer 4's
  reverse-coverage enumerator is written per family.
  (b) **The duplicated check.** D56 rule **O2** (*"artifact.stamped_digest !=
  anchor_digest"*) and D58 §10.3 step **5** (*"`start_digest ==
  anchor_digest`"*) are the same equality on the same field, and they carry
  `anchor-ots-digest-mismatch` and `ots-ops-do-not-commit-anchor-digest`
  respectively. D53 §8 binds tamper row 1 (`row_id`
  `anchor-ots-digest-mismatch`) to `ErrorCode("anchor-ots-digest-mismatch")`,
  so Q76's `MATRIX.json` edit **and** A11's implementation cannot both be
  right as written. Pick one code; correct the losing document at source; if
  the row id and the code diverge, say so in the row's `why`, because row ids
  are permanent handles and this one already reads like the code.
- Accept:
  - A single ruling covering (a) and (b), recorded as a decision-document
    amendment or a new short decision, naming which text in D53 §7 / D56 §7 /
    D58 §10.4 / §10.3 is superseded and quoting the replacement.
  - `docs/testing/error-code-contract.md` §2 gains exactly the row(s) the
    ruling authorises — no more, and none before it.
  - The 20 codes the three documents currently mint are pairwise distinct
    after the ruling, and none collides with the 194 in
    `testdata/error-codes/v1/CODES.txt` (measured, not assumed).
  - **Q76 runs after this, not before**: the `MATRIX.json` `expected` cell for
    `anchor-ots-digest-mismatch` is one of the two codes in dispute.
- Notes: Found at A2. A2 mints no code and therefore validates no prefix in
  `AnchorDiagnostic` — deliberately, and recorded in that type's doc comment:
  a constructor that checked for `anchor-` would have silently decided this.

`TODO.md` row:

```
- [ ] A41 — Reconcile the two A-domain error-code prefixes (D53/D56 `anchor-` vs D58 `ots-`/`tsa-`) and the two codes minted for the one digest-commitment check, before A38 registers a row or A5/A11 mints a code (M2, S)
```

---

### A42 — Implement the OTS upgrade-URI allowlist and per-response cap
- Milestone: M2
- Size: S
- Deps: A3 (HTTP substrate + the response-cap parameter D54 §9.1 adds), A13; D54
- Spec: Anchoring (line 108), Core user flows 2 (line 35), Risks — hostile input (line 187)
- Do: In `antseal-anchor`, implement the pinned upgrade-URI allowlist D54 rules: a pending attestation's URI may be contacted by A14/A15 only if, after lowercase normalization, its scheme is `https`, its path is empty, it carries no port/query/fragment, and its host ends with one of `OTS_UPGRADE_HOST_SUFFIXES` (`.calendar.opentimestamps.org`, `.calendar.eternitywall.com`, `.calendar.catallaxy.com`) **on a dot boundary** — or is exactly a user-configured calendar's host, or a subdomain of one. The allowlist is APPEND-ONLY: removing a suffix strands every already-stored `.ots` naming it, and the constant carries that as a doc-comment invariant. Also land `MAX_OTS_CALENDAR_RESPONSE_BYTES = 65_536` and pass it as the OTS request's `receive_cap_bytes` through **D90's** substrate — *not* `MAX_OTS_BYTES`, which D90 currently names and which is the merged-artifact cap, 4 766× the largest of 18 measured real responses (D54 §8b; F4 makes limits raise-only, so the measured value is the only reversible choice). The substrate must surface an over-cap response as D90's `OversizeBody` variant, **never by truncating** (upstream's own client truncates at 10 000 B and then fails deserialization — `python-opentimestamps/opentimestamps/calendar.py:70-72`). Add the F4 registry row to `docs/format/anchor-artifact-limits.md`.
- Accept:
  - Table-driven test over: each of the four real pending URIs recorded in D54 §1 (accepted); a bare suffix with no dot boundary, e.g. `https://calendar.catallaxy.com` (refused); an uppercase host (accepted — normalized); `http://` scheme (refused); a URI carrying a path, port, query or fragment (refused); `https://attacker.example` (refused).
  - A user-configured calendar widens the allowlist to that host and its subdomains only: `https://cal.example.com` does not admit `https://other.example.org` nor `https://cal.example.com.evil.net`.
  - An over-cap calendar response produces the size error variant, not a parse error — asserted on the variant, so a truncating implementation fails.
  - The F4 row records value, the fixture measured against, the margin and `lowered: never`; the margin figure is re-derived once A25 measures a real **upgrade** response (D54 §6.1).
- Notes: This closes an SSRF/deanonymization surface that the U24 hook makes reachable on *every* CLI invocation, from a vault artifact an attacker with disk access can edit. Discovered by D54.

### A43 — Cross-certificate and self-signed-in-token chain fixtures
- Milestone: M2
- Size: M
- Deps: A6, A8, A9; A24 (test-CA infrastructure); D57
- Spec: Anchoring (line 109), Verifier web page (lines 129, 133), Verification — tamper matrix (line 168)
- Do: Commit the five real TSA tokens captured for D57 (`testdata/anchors/A25-bootstrap/roots-*-token.tsr`) as chain-validation fixtures and build the suite that locks D57's rulings P1/P2/P3 into A9. P1: path building stops at the **first** certificate whose issuer DN matches a pinned root's subject DN and whose signature verifies under that root's SPKI; trailing certificates are ignored, never anchors, and their presence is not an error. P2: a token-supplied self-signed certificate is never a trust anchor even when byte-equal to a pinned root. P3: `certificates` is an ASN.1 SET and carries no ordering guarantee. Extend A24's test CA to emit a cross-certificate so the negative direction is reachable synthetically as well as from real tokens.
- Accept:
  - The real DigiCert token reaches `proven` **with its cross-certificate present** and again **with it removed** — an implementation that walks the supplied chain to its end fails the first and passes the second, so both directions are required.
  - The real Sectigo token reaches `proven` with its cross-certificate present (second hierarchy — one TSA passing could be luck).
  - The real FreeTSA, DFN and SwissSign tokens reach `proven` **while carrying their own self-signed root inside the token** (P2's positive twin), while an A24 token whose root is withheld from the injected store but present in the token renders `internally-consistent-only` (P2's negative). The same A24 fixture reaches `proven` when its root is injected, so neither direction can pass vacuously.
  - Every certificate SET is re-encoded in every permutation and each permutation yields the identical verdict (P3).
  - Rows execute in both native and wasm32 suites; no secret material in fixtures.
- Notes: None of these defects is reachable with A24's test CA alone — a single-hierarchy CA never cross-signs and never ships its own root in a token. Discovered by D57 §2/§3, which measured 2-of-5 chains terminating at a cross-certificate and 3 distinct certificate orders across 5 real tokens.

### A44 — Default-endpoint and pinned-root rot watch (scheduled, non-gating)
- Milestone: M2 (runs `continuous` thereafter)
- Size: S
- Deps: A6, A13, A17, A26; Q16 (the non-gating manual/scheduled lane)
- Spec: Anchoring (lines 108–109), Format stability (line 123), Risks (line 182)
- Do: Stand up one scheduled, **non-required** lane that detects rot in everything this project pins to a third party. (1) OTS calendars: per entry in `DEFAULT_OTS_CALENDARS`, resolve DNS and `GET <url>/`, asserting HTTP 200 and the literal marker `OpenTimestamps Calendar Server` in the body; record each calendar's reported pending-commitment count as a trend. Submit nothing — this is a liveness read, not an anchor operation (Q16). (2) Arbitrum RPCs: per entry in the D55 pairs, call **`eth_getTransactionReceipt` against a committed historical transaction** and `eth_chainId`, and read `Access-Control-Allow-Origin` off the **POST** response. A liveness probe with a cheaper method is explicitly forbidden — D55 §2 measured an endpoint that answers `eth_blockNumber` in 0.75 s and rejects `eth_getTransactionReceipt` outright. (3) Pinned roots: assert no root in `TsaRootStore::pinned()` is within 365 days of its `notAfter`. Two consecutive reds for one endpoint opens an issue; the fix is a reviewed constant change (calendars and RPCs) or a reviewed append (roots, per A26).
- Accept:
  - Lane runs on the fuzz-nightly schedule, is not a required context, and a red run never blocks a merge.
  - Red direction proven at landing: a planted dead hostname, a planted `eth_blockNumber`-only stub, and a planted root expiring in 100 days each turn the lane red, with a message naming which of the three checks failed.
  - The root-expiry check takes `now` as a **parameter** in `antseal-core` (never a system clock — A9's WASM-determinism rule) and is driven with the real clock only from this lane.
  - The lane's report distinguishes "endpoint down" from "endpoint up but wrong method policy" — the two need different fixes.
- Notes: The three decisions this serves have different permanence. The calendar and RPC lists are `antseal-anchor` constants and changing one is **not** a format event (D54 §5). The root store is compiled into `antseal-core`, is versioned and append-only, and changing it is an A26 event. Discovered by D54/D55/D57.

### A45 — Re-point A11's F1/F2 demonstration at the wired anchor stage
- Milestone: M2
- Size: **S**
- Deps: A18, R12, A11
- Spec: Anchoring (line 108); `docs/format/anchor-artifact-limits.md` F1–F3
- Do: `crates/antseal-core/tests/anchor_ots_blast_radius.rs` demonstrates F1
  end to end today — a bundle whose sole `.ots` is over-limit still decodes as
  a bundle, decodes as a `.sealproof`, verifies its manifest and content, keeps
  both TSA anchors, and yields a `VerificationReport` **equal to the
  control's**. What it *cannot* reach is the half of F2 that names a per-anchor
  **verdict**, because R12 has not replaced the M0 stub that renders every
  anchor `absent`: `an_over_limit_artifact_maps_to_invalid_and_carries_no_time`
  therefore composes `parse_ots`'s error with `AnchorVerdict::invalid` by hand
  instead of reading the pipeline's answer. When A18/R12 land, re-point it, and
  strengthen the control comparison from *"the reports are equal"* to *"the
  reports differ in exactly the one anchor slot"* — which is the assertion that
  actually distinguishes F2 from F1.
- Accept:
  - The over-limit bundle's report differs from the control's **only** in the
    OTS anchor's slot, and that slot is `invalid` with the artifact's own code.
  - The module docs' "What this test can and cannot reach today" section is
    deleted rather than edited, because the limitation is gone.
- Notes: The test is written to make this cheap — the hostile artifacts and the
  byte-level splice both stay.

### A46 — Prove the request nonce is verdict-inert on the bundle path, and pin the DER sign-byte case
- Milestone: M2
- Size: S
- Deps: A8 (the comparison it tests), A4 (the encoder it vectors), A2; D59
- Spec: Anchoring RFC 3161 (MVP-SPEC.md line 109), Reveal bundle contents (line 114), sealer-as-adversary (line 121)
- Discovered by: **D59 (2026-08-02, M2 planning round)**. A8's Accept list has a row for "wrong nonce on the capture path" and **no row for the `None` arm**, so nothing in the task set witnesses D59's central ruling — that with `expected_nonce = None` the `TSTInfo` nonce is parsed and then ignored, and its presence or absence may not move any verdict. An implementer could make presence meaningful and every listed Accept row would still pass.
- Do: Add `crates/antseal-core/tests/anchor_tsa_nonce.rs` with the three D59 §7 rows. (1) `nonce_presence_does_not_move_the_verdict`: two tokens over the same `anchor_digest` and the same chain, one whose `TSTInfo` carries a nonce and one that does not, verified with `expected_nonce = None`, must yield the identical `AnchorState` **and byte-identical report v1 output** for their `AnchorResult`. (2) `expected_nonce_some_requires_presence_and_equality`: the capture arm — matching nonce verifies; a different nonce and an **absent** nonce both yield `anchor-tsa-nonce-mismatch`. (3) `nonce_is_compared_as_bytes_not_as_a_bignum`: a token whose nonce INTEGER carries 1 024 content octets is rejected by A5's strict-DER/limit path with no allocation proportional to a decoded integer, asserted on the `parser_caps_alloc.rs` counting allocator. Separately, in `crates/antseal-core/tests/anchor_der_vectors.rs`, add golden vector `vector_tsa_request_nonce_high_bit`: `build_timestamp_req` over a fixed digest and the fixed nonce `0x8000000000000000` must emit the canonical DER INTEGER with the `0x00` sign prefix (9 content octets), byte-exact — A4's existing fixed-nonce vector uses a value whose high bit is clear and never exercises this.
- Accept:
  - Row (1) is non-vacuous, demonstrated: it goes **red** against a build whose `None` arm rejects a nonce-free token, and green after.
  - Row (2) covers absence and inequality as the **same** code (D59 §1) — a build that treats absence as "nothing to compare" fails.
  - The high-bit vector fails against an encoder that writes the 8 drawn bytes without the sign prefix.
  - `antseal-core` still compiles for `wasm32-unknown-unknown`; the rows execute in both native and wasm32 suites.
  - No new cap constant is introduced (D59 §1: the field is bounded by the already-frozen `MAX_TSA_TOKEN_BYTES`).
- Notes: This task exists because "sign off" was the register's instruction for D59 and a sign-off would have left the inertness claim untested. The three states-of-affairs it forbids are all reachable from A8's Do text as written.

### A47 — Re-home D56's endpoint-differential test: it cannot exist where D56 puts it
- Milestone: M2
- Size: S
- Deps: A16 (the typed outcomes), A2 (`OnlineEvidence`); consumed by A18's
  reachability suite
- Spec: Verifier web page (MVP-SPEC.md line 137), Core user flows (line 38)
- Do: `docs/decisions/D56-ots-internally-consistent-trigger.md` §9 lists
  `unreachable_and_disagreeing_endpoints_are_indistinguishable_to_core` with
  the claim *"§3's API constraint"* and the failure mode *"any core-side type
  able to tell them apart; the test constructs both `antseal-anchor` outcomes
  and asserts they produce the identical core input"*, under the section
  heading *"Location: `crates/antseal-core/src/anchor/ots.rs` (unit) and
  `crates/antseal-core/tests/anchor_ots_states.rs` (integration)"*. **That
  location is impossible for this one row.** The two outcomes are A16's typed
  results, which live in `antseal-anchor`, and `antseal-core` must never take
  a dependency on it (A3's Accept: *"`antseal-core` has no HTTP/network
  dependency"*, enforced by the `core-dep-graph` lane) — so the test cannot
  construct its own inputs. Move the row to `antseal-anchor`'s suite, where
  the projection `A16 outcome -> Option<OnlineBlockResult>` actually lives,
  and assert there that the unavailable outcome and the disagreement outcome
  both project to `None` for the queried height. The remaining nine rows of
  D56 §9's table are unaffected and stay in core.
- Accept:
  - The test exists in `antseal-anchor`, constructs both A16 outcomes, and
    asserts an identical `OnlineEvidence` results — including that neither
    inserts an entry at the queried height.
  - Its red direction is demonstrated: a projection that maps disagreement to
    an inserted entry (any entry) fails it.
  - D56 §9's location line is corrected at source to say which row lives
    where, so A18's implementer does not look for it in core and conclude the
    obligation is discharged by a weaker in-core test.
  - `antseal-core` still has no `antseal-anchor` dependency
    (`core-dep-graph`).
- Notes: Found at A2, which wrote the in-core half it *can* write
  (`absence_of_evidence_is_the_only_shape_a_failed_probe_can_take`) and
  deliberately did **not** name it after D56's row — a weaker test under the
  mandated name would have discharged the obligation on paper. A2's
  `BlockEvidence` is the type-level half of the same separation A17's Accept
  demands ("this result cannot enter the anchor state machine as an anchor"):
  the anchor rules take `&BlockEvidence`, which cannot name the receipt arm.
  **A18 must take `&BlockEvidence`, not `&OnlineEvidence`, in its per-anchor
  rules** or that property is lost silently.

`TODO.md` row:

```
- [ ] A47 — Re-home D56 §9's `unreachable_and_disagreeing_endpoints_are_indistinguishable_to_core` to `antseal-anchor` (it constructs A16 outcomes, which `antseal-core` may not depend on) and correct D56's location line (M2, S)
```

### A48 — Re-measure the bootstrapped F4 rows and pin A12's byte order for real
- Milestone: M2
- Size: **S**
- Deps: A25 (the two-day OTS pending → upgraded cycle, not before 2026-08-04)
- Spec: Anchoring (line 108); `docs/decisions/D58` §9.5, §13.1; `tasks/A.md` A12 `Do`
- Do: Two things the M2 wave could not do because no real upgraded `.ots` of
  this project's own existed. **(a)** Four F4 registry rows —
  `MAX_OTS_OPS`, `MAX_OTS_DEPTH`, `MAX_OTS_OPERAND_BYTES`,
  `MAX_OTS_VALUE_BYTES`, plus the binding half of `MAX_OTS_ATTESTATIONS` — are
  measured against `testdata/anchors/A25-bootstrap/upgraded/rust-opentimestamps-LARGE_TEST.ots`,
  the `LARGE_TEST` constant of the *rejected* crate (a genuine mainnet proof
  over blocks 449397/449399), with that provenance stated in the cell and in
  `.../upgraded/PROVENANCE.md`. Re-measure them against the real fixture with
  `anchor::ots::parse_ots_measured` — which exists so this is a call rather
  than a second parser — and append. The values do not change (F4 forbids
  lowering, every margin is ≥ 15×); the **provenance cell** must stop citing a
  third-party crate's test constant. **(b)** A12's `Do` asks for the
  merkle-root byte order to be *"pinned empirically by a real upgraded
  fixture"*. It is not: what A12 ships is the structural read at bytes 36..68
  with **no** reversal, guarded by a mutation test
  (`a_byte_reversed_merkle_root_does_not_match`). The empirical pin needs a
  **fetched mainnet header** compared against the ops-derived root — do it here,
  with the fetch recorded in `CAPTURE.log` like every other A25 capture.
- Accept:
  - The four `measured against` cells name an A25 fixture and no crate.
  - A committed test compares an ops-derived root against a **fetched** block
    header's bytes 36..68 and goes red under a reversal.
  - `rust-opentimestamps-LARGE_TEST.ots` is either deleted or demoted in
    `PROVENANCE.md` to "kept as a second, independent upgraded shape".
- Notes: Keep the bootstrap fixture at least until the real one parses, so the
  suite is never without an upgraded `.ots`.

### A49 — Enforce the transport requirement on unsigned online evidence (esplora + Arbitrum RPC)
- Milestone: M2
- Size: S
- Deps: A3 (the substrate and its `TlsPolicy`); consumed by A16, A17; U: endpoint-override config (U4)
- Spec: Core user flows (line 38), Verifier web page (line 137), Milestones M2 (line 155)
- Discovered by: **D90** (2026-08-02) §6.6. The must-agree primitive's whole security property is that two *independent* endpoints agree. D90 measured three separate ways that independence can be lost silently, none of which any task owned: a plain-`http://` endpoint (one on-path attacker forges both halves); a followed redirect (both endpoints land on one origin and genuinely agree); and an ambient `HTTP_PROXY` (ureq's `Config::default()` reads it — both halves traverse one intermediary). The asymmetry that makes this A-work rather than hygiene: RFC 3161 tokens are **signed and nonce-bound**, so transport buys them nothing and plain HTTP is safe (and unavoidable — `timestamp.digicert.com` has no port 443, measured 2026-08-02T19:35:51Z); esplora and `eth_getTransactionReceipt` replies are **unsigned**, so transport is their only integrity control.
- Do: Implement `TlsPolicy::RequiredExceptLoopback` in `antseal-anchor`'s `http::endpoint` module and require it on every A16 and A17 endpoint, including user-supplied overrides from U4's config: the URL scheme MUST be `https` unless the host is an IP literal in `127.0.0.0/8` or `::1`. **IP literals only — not the name `localhost`**, which is a name however conventionally it resolves; A24's stubs bind `127.0.0.1:0`, so the carve-out costs the test path nothing and widens nothing in production, where every endpoint is a public host. Reject at config-validation time with `AnchorHttpError::TlsRequired`, so a bad override fails before any seal or verify work. Record, in the same place, that A10/A13/A14 use `TlsPolicy::Optional` and why (D90 §6.6) — the two policies must not be reachable by accident from the wrong call site.
- Accept:
  - `http://` for a public host under `RequiredExceptLoopback` is `TlsRequired`; the same URL under `Optional` is accepted (both directions, so the policy is proven to *do* something).
  - `http://127.0.0.1:9/` and `http://[::1]:9/` pass; `http://localhost:9/` and `http://127.0.0.1.evil.example/` are `TlsRequired` (the carve-out cannot be widened by a hostname that merely contains a loopback literal).
  - A16's stub-server suites run unchanged against `http://127.0.0.1:<port>` — the rule is proven compatible with Q16's no-real-network policy rather than asserted to be.
  - A U4 config carrying an `http://` esplora override is rejected at load, naming the endpoint, before any network call.
  - Grep-level review item: no A16/A17 call site constructs a `TlsPolicy::Optional` client.
- Notes: This is one task, not three, because the three failure modes share one property and one test surface. The redirect half is already closed by the substrate (`max_redirects(0)` + D90's own 3xx classification) and the proxy half by `.proxy(None)`; this task owns the scheme half and the assertion that all three hold together for A16/A17.

### A50 — Validate the `[anchors] tsa_urls` slot through the substrate's endpoint parser
- Milestone: M2
- Size: S
- Deps: A3 (the `Endpoint` parser); U4 (the config slot); consumed by A10/U26
- Spec: Anchoring RFC 3161 (line 109), Core user flows (line 34)
- Discovered by: **A3/A49 implementation** (2026-08-02). A49 routed the two `[verify]` slots through `antseal_anchor::Endpoint::parse` at config load, so a bad must-agree endpoint fails before any work. The `[anchors] tsa_urls` slot beside it is still validated only by `http_url_shape` (`crates/antseal-cli/src/config.rs`), a `starts_with("http://")`/`starts_with("https://")` length check — so `http://` alone (no host), `https://user:pw@tsa.example/` (credentials in a pinned endpoint, and on the plain-HTTP path they travel in cleartext), and `http://tsa.example:notaport/` all load clean and fail later, at TSA submit time, inside the pre-pay gate. Deliberately **not** folded into A49: A49's rule is about *transport* on unsigned evidence, this is about *shape*, and widening the refusal set of a slot U26 already documents is a change that deserves its own row rather than riding in on a security task.
- Do: In `crates/antseal-cli/src/config.rs`, validate each `tsa_urls` entry with `antseal_anchor::Endpoint::parse(url, TlsPolicy::Optional)` — `Optional`, never `RequiredExceptLoopback`: `timestamp.digicert.com` has no port 443 at all (measured 2026-08-02) and RFC 3161 tokens carry their own integrity, so requiring TLS here would break a default TSA (D90 §6.6). Keep the failure shape the `[verify]` slots now use: the line number, the key, and the offending URL, at load.
- Accept:
  - `tsa_urls = ["http://timestamp.digicert.com"]` still loads — the plain-HTTP TSA path is proven *not* to have been broken, in the same test.
  - Each of `"http://"`, `"https://user:pw@tsa.example/"`, `"ftp://tsa.example/"` is refused at load naming the URL and the reason.
  - The refusal happens in `parse`, before any network call and before the anchor gate runs (assert on `parse`, not on a command).
- Notes: This narrows what an existing `config.toml` may contain. The slot has no consumer before M2's anchor stage, so nothing in the tree relies on the looser set; a user config carrying one of the newly-refused shapes would begin failing every command, which is the intended loudness (`docs/config.md` should gain the sentence).

### A51 — One tested endpoint fan-out, so A10/A13/A16/A17 cannot each re-derive independence
- Milestone: M2
- Size: S
- Deps: A3; consumed by A10, A13, A14, A16, A17
- Spec: Anchoring (line 109), Verifier web page (line 137), Core user flows (line 38)
- Discovered by: **A3 implementation** (2026-08-02). D90 §3.2 makes endpoint independence a property of `std::thread::scope` and proves it works (1.503 s wall for a 1.5 s-slow + fast pair), but it rules on no *shape* for it — so four separate tasks will each write their own fan-out, and A10's "one TSA's failure never aborts **or delays** the others", A13's per-calendar independence, A16's pair and A17's pair each get an independent chance to be a sequential `for` loop that passes every functional test it has. A3's `endpoints_run_concurrently_not_sequentially` proves the substrate *permits* concurrency; nothing makes a consumer use it. This is the "recorded guarantee nothing implements" shape, pre-empted: the guarantee is currently recorded four times and implemented zero times.
- Do: Add `http::fan_out<T>(client: &HttpClient, requests: &[HttpRequest<'_>], f: impl Fn(...) -> T + Sync) -> Vec<Result<T, AnchorHttpError>>` (or the smallest signature that serves all four call sites) over `std::thread::scope`, preserving input order in the output and never letting one endpoint's failure or stall affect another's. It performs **no** cross-endpoint comparison: D90 §6.9(a) rules that agreement is defined per source by the consumer over an *extracted* value, never over response bytes, and this helper must not become the place someone adds a byte comparator.
- Accept:
  - A slow endpoint (1.5 s) beside a fast one: total wall < 2.4 s **and** the fast endpoint's own elapsed < 900 ms — the second assertion being the non-vacuous half, since a sequential implementation that happens to query the fast one first passes a wall-clock check alone.
  - One endpoint returning a typed error leaves the others' results intact and in position.
  - Results are returned in request order regardless of completion order (a `HashMap`-shaped or completion-ordered result would silently pair A16's two endpoints wrongly).
  - Grep-level review item once A10/A13/A16/A17 land: no consumer iterates endpoints with a bare `for` loop.
- Notes: Deliberately not built speculatively inside A3 — it is minted here so the first consumer (A10) builds it once with these tests rather than four consumers building it four times. If A10 lands first it may absorb this row.

### A52 — Register the `anchor-ots-*` family
- Milestone: M2
- Size: **S**
- Deps: A38/Q80 (the `anchor-` §2 row), A11
- Spec: `docs/testing/error-code-contract.md` §2, §4a; D91 §7.1, §8
- Do: A11 mints **fifteen** `anchor-ots-*` codes and raises D56's
  `anchor-ots-digest-mismatch`, and **none of them is registered anywhere**:
  `docs/testing/error-code-contract.md` §2 has no `anchor-` row in the epsilon
  worktree, `error_universe::by_enumerator()` has no A-domain enumerator, and
  `testdata/error-codes/v1/CODES.txt` still holds 194 with zero `anchor-`
  entries. `anchor::ots::error::all_code_exemplars()` is already written to the
  same shape as its six siblings so the wiring is one entry. Add it, move
  `the_universe_is_exactly_the_registered_enumerators` 8 → **11** (D91 §8.2 — an
  enumerator with no `ENUMERATOR_PREFIXES` row must be a **failure, not a
  skip**, or the check goes green over exactly the domain D91 exists to
  constrain), and append the codes by §4a's additions-only path.
- Accept:
  - `CODES.txt` gains the fifteen; nothing is removed or renamed.
  - The roster assertion names the ninth enumerator.
  - `ots-ops-do-not-commit-anchor-digest` appears nowhere (D91 §6.2).
- Notes: D91 §12's residual risk — *"A5 or A11 landing a code before Q77 —
  acceptable once, not twice"* — is now **spent**: A11 has landed fifteen.

### A56 — Resolve the SwissSign root: execute C1 from an unblocked host, or amend D57
- Milestone: M2
- Size: S
- Deps: A7 (which quarantined it), D57
- Spec: Anchoring (line 109); D57 §C1–C4 (the provenance procedure)
- Discovered by: **the A7 lane** (2026-08-03), which held the root back rather than promoting a C3 snapshot to stand in for C1 — recorded at `crates/antseal-core/src/anchor/roots/PROVENANCE.md` under the QUARANTINED heading.
- Do: SwissSign is the one root A7 collected and did **not** admit. `www.swisssign.com` returns 403 to this host for **every** request, including a deliberately nonexistent path under the same prefix — so the block is on the client, not on the resource, and the bytes are almost certainly publishable. Two admissible routes, and only two: (a) execute D57's channel **C1** (the vendor's own URL) from a host SwissSign does not block, and admit the root under the unamended procedure; or (b) carry an **amendment to D57** as a reviewed decision that lets a C3 archive snapshot of the C1 URL stand in for C1, with C4 supplying currency. Route (b) is a decision, not an implementer's judgement call: A7 declined it precisely because taking it inside the gated task would have meant the task rewrote its own admission rule to admit the root it was evaluating.
- Accept:
  - Either the root is admitted with a complete C1 provenance record, or D57 carries a dated amendment and the root is admitted under it — never a silent promotion.
  - `PROVENANCE.md`'s QUARANTINED section is updated in whichever direction resolves, and the test that reads its headings and QUARANTINED lines still fails in both directions.
  - If neither route is executable, the root stays quarantined and that is recorded as the outcome — a quarantine that is never revisited is the failure mode this row exists to prevent.
- Notes: not gating for M2 — the store admits four roots and A20's gate needs one verifying token, so SwissSign is capability, not a blocker.

### A59 — The signing mock TSA, completing A24's second half
- Milestone: M2
- Size: M
- Deps: A24 (transport half), A6 (`TsaRootStore::from_static` injection), A30 (containment rule)
- Spec: Anchor smoke tests (line 173); Milestones M2 (line 155)
- Do: Build the token-minting half of A24: a mock TSA that **signs** a `TimeStampResp` from a generated test CA, with controllable `genTime`, validity window and `PKIStatus`, verified through the injected test root store. It lives in `antseal-core` behind the existing `test-util` feature rather than in a new crate, because A30(c)'s containment rule — the seven D60 pins are declared by `antseal-core` and by **no other crate**, read from `cargo metadata --no-deps`, which reports dev edges too — makes a separate `antseal-mock-tsa` crate a second declaration site.
- Accept:
  - Minted tokens verify through A8's `verify_token` and A9's chain validation against an injected store, and fail against the production store.
  - `genTime`, validity window and `PKIStatus` are all controllable, so A21's temporal rows are mintable rather than captured.
  - Zero new dependency declarations in any crate.
- Notes: **Registered retroactively 2026-08-06.** The work landed 2026-08-05 and is documented at `crates/antseal-core/src/anchor/testing.rs`; the ID was minted in a lane brief and cited in committed source, and no row was ever added here. That gap is what Q85 exists to make impossible.

### A63 — Assemble the real upgraded `.ots` from the committed upgrade responses
- Milestone: M2
- Size: S
- Deps: A14 (the merge primitive), A25's captured `upgraded/` responses
- Spec: D58 §9.5, §13.1
- Discovered by: **the A14 lane** (2026-08-03), recorded at `crates/antseal-core/src/anchor/ots/mod.rs` beside the `UPGRADED_LARGE_TEST` constant.
- Do: `testdata/anchors/A25-bootstrap/upgraded/` holds six real upgrade **response bodies** for this project's own golden-vector digests, captured 2026-08-03T09:03Z. D58 §9.5's four F4 rows must be re-measured against the *assembled* artifact, not against response bodies — and the assembly is a deterministic merge of files already in the tree, using A14's pure byte-insertion path re-validated through `parse_ots`. Produce and commit that artifact.
- Accept:
  - The assembled artifact round-trips through `parse_ots` and its attestation set matches what the response bodies name.
  - Assembly is reproducible from committed inputs by a committed script — two independent runs produce byte-identical output.
  - The borrowed third-party fixture `upgraded/rust-opentimestamps-LARGE_TEST.ots` is no longer the only upgraded artifact in the tree.
- Notes: A48 is the consumer — it re-measures D58 §9.5's four rows and retires the borrowed fixture, and it needs this artifact to exist first.

### A67 — Re-key the OTS half of anchor identity onto Bitcoin, not calendars
- Milestone: M2
- Size: S
- Deps: A40 (the type and both count accessors exist); blocks A20's degradation report and R17's aggregate reading the count
- Discovered by: **A40** (2026-08-05), which implemented its own `Do` literally and recorded the consequence rather than re-ruling it; registered as a row and resolved by **D92** (2026-08-06).
- Problem: A40's `Do` makes a `proven` OTS anchor's identity the set of calendars its attestations name. What proved it is Bitcoin. The calendar URI is a **bundle-recorded string** — the exact input A40's own `TsaSigner` rustdoc forbids — it is chosen by the sealer at submit time, and `antseal-anchor`'s merge *enforces* that upgrading never drops an attestation (`crates/antseal-anchor/src/ots/upgrade.rs:356-358`), so the value is byte-identical before and after the anchor becomes `proven`. It is also set-valued, so overlapping calendar sets count as distinct identities. The measured 2026-08-03 cycle produces the over-count with no adversary: one digest, three calendars, **three different Bitcoin blocks** (960767/960768/960771), which the calendar key and the block key both score as 3 against MVP-SPEC.md line 19's 1.
- Spec: Anchoring — OTS online promotion (MVP-SPEC.md lines 19, 108); verdict taxonomy and headline (lines 129–137); `docs/format/registry-v1.md` §8; `docs/decisions/D92-proven-ots-anchor-identity.md`; D54 §4 (a calendar is not a witness), D56 rule O3
- Do: Apply D92 §8. Replace `AnchorIdentity::OtsCalendars(Vec<String>)` with a unit `AnchorIdentity::BitcoinChain`; pass it at D56's O3 and O4 arms only and `None` at O5; keep `calendars_of`/`calendar_source` for the `pending`/`invalid`/`internally-consistent-only` source strings and amend their docs to say so. Add `AnchorVerdicts::distinct_verified_identities_of(kind: AnchorKind)`, whose rustdoc records that **A20's gate must read the TSA-scoped count, never the mixed scalar** (D54 §3). Rewrite `AnchorIdentity`'s and `distinct_verified_identities`'s rustdoc onto D92 §1/§5 and off A40's `Do`. Touch no wire byte, no vector, no error code, no crate but `antseal-core`.
- Accept:
  - Two `proven` OTS anchors at **different real Bitcoin heights** (449399 and 449397, both in the committed `LARGE_TEST` fixture) are **one** identity, with `headline_eligible_count() == 2` asserted first so the row is not vacuous (D92 §9 T1).
  - Two `proven` OTS anchors at **one height through disjoint calendar sets** are **one** identity, with the disjointness witnessed by evaluating the same bytes without an upgrade group and comparing the two `pending` source strings (D92 §9 T2). This row fails under the pre-D92 code.
  - An `attested` OTS anchor's `identity()` is `None` — the first OTS-side witness for the eligibility filter, which today is falsifiable only through the TSA path (D92 §9 T3).
  - A lone `proven` OTS establishes **one** identity and is not UNANCHORED; `distinct_verified_identities() == 0` iff `aggregate().is_unanchored()` (D92 §9 T4).
  - A `proven` TSA plus a `proven` OTS is **two**, asserted by matching **one of each enum arm**, not by cardinality alone (D92 §9 T5).
  - `distinct_verified_identities_of(AnchorKind::Ots) <= 1` over every combination of the module's OTS fixtures, and the total equals D92 §5.4's closed form (D92 §9 T6).
  - Every row states its planted fault in its own rustdoc (D92 §9's table is the source).
  - `cargo clippy` clean; `antseal-core` still builds for `wasm32-unknown-unknown`; no golden vector, report vector, `MATRIX.json` row or error code changes.
- Notes: `AnchorIdentity` is in-memory only — it appears in no wire format and in no report byte — so deleting an arm is a source change, never a format event. It also has **zero** consumers outside `verdicts.rs` and its tests today, which is why this is cheap now and expensive after R12 wires `evaluate_anchors` into the pipeline. A future Litecoin/Ethereum OTS attestation (D56 rule O9) gets its **own arm**, deliberately, with its own independence argument — never a payload on `BitcoinChain`.

### A68 — The Sectigo nonce-encoding regression fixture
- Milestone: M2
- Size: S
- Deps: A10 (which found the defect), A4 (the nonce encoder)
- Spec: D59 (request-nonce persistence); Anchoring (line 109)
- Discovered by: **the A10 lane** (2026-08-05).
- Do: A10 found that the nonce comparison's two operands were encoded differently — the drawn value is 8 raw bytes, the DER canonical form prepends `0x00` when the top bit is set — so **half of all real captures would have been rejected**, aborting before payment. The fix landed; the regression fixture did not. The committed FreeTSA fixture **cannot** catch it (its nonce's top bit is clear, so both encodings coincide); Sectigo's capture can. Commit a fixture whose nonce has the high bit set and assert the comparison succeeds, so the defect cannot return silently.
- Accept:
  - A fixture with a top-bit-set nonce is committed and asserted to verify.
  - Reverting the encoding fix makes that test **red** — planted and demonstrated, not assumed.
  - The FreeTSA fixture is asserted to have a top-bit-**clear** nonce, so the reason it cannot catch this is itself pinned rather than remembered.

### A70 — The RSA signer variant of the mock TSA, and the `deny.toml` premise it would falsify
- Milestone: M2
- Size: S
- Deps: A59, P23 (the `deny.toml` ignore that owns the premise)
- Spec: A24's Accept (controllable failure modes); `deny.toml` (RUSTSEC-2023-0071)
- Discovered by: **the A59 lane** (2026-08-05), recorded at `crates/antseal-core/src/anchor/testing.rs`.
- Do: A24 asks for RSA **and** ECDSA P-384 signer variants; A59 shipped P-384 only, deliberately. The mandatory `deny.toml` ignore for RUSTSEC-2023-0071 (Marvin) is justified on the stated premise that *antseal performs no RSA private-key operation*, and `deny.toml` scans with `all-features = true` — so an RSA signer here, **even feature-gated, even fixture-only**, falsifies the stated premise of a live security exception. Decide and record whether the variant ships at all: either it does not, and A24's Accept row is narrowed with this reason attached, or it does, and the ignore's premise is rewritten first.
- Accept:
  - The outcome is recorded in `deny.toml`'s ignore rationale and in A24's Accept, whichever way it goes.
  - If the variant does not ship, the compensating evidence is named: five real RSA tokens (DigiCert, Sectigo, Entrust, DFN, Certum) already exercise every branch A8 has for RSA, and what a mock uniquely supplies — controllable CA, `genTime`, validity window, `PKIStatus` — needs no RSA.
- Notes: this is the rare case where *not* building the test helper is the defensible outcome; the row exists so that stays a decision rather than an omission.

### A80 — Lift the online refutations above O4 in `evaluate_ots_artifact`
- Milestone: M2 — **blocks A21**
- Size: S
- Deps: A18 (the machine); D93
- Discovered by: **D93 §3** (2026-08-06)
- Problem: `verdicts.rs:680-692` returns `Attested` on `upgrade.is_some() && committed` without consulting `agreed`, so rules O6 and O7 can only ever produce a verdict when the artifact is *already* refutable offline through O8. A forged header the ops commit is unrefutable by the online gate, and an `.ots` claiming a height beyond the chain tip renders `attested` for ever — the defect D56 §3 states in those words as the reason O7 exists. A18's Accept row 2 (*"mismatch → `invalid`"*) and MVP-SPEC.md lines 108/168 are discharged vacuously.
- Do: Give O4 the guard in D93 §5 (`committed && !refuted_online`, where `refuted_online` covers O6 and O7 and **not** O8). Leave O0–O3, O5, O8, O9 and every offline path untouched. Invert and rename `a_self_consistent_forgery_refuted_online_is_attested_with_the_refutation_recorded`, and give `agreed_absence_of_the_block_is_invalid` a **committed** twin, keeping the existing `!committed` case as the O7-over-O8 ordering assertion. Update `ANCHOR_ONLINE`'s owner note in `test_util/tamper_coverage.rs`.
- Accept:
  - A single-branch committed `.ots` whose embedded header the agreed pair refutes renders `Invalid`/`anchor-ots-online-header-mismatch`; the **same artifact with the evidence removed** renders `Attested` — both directions, or the rule is untested.
  - A committed `.ots` at a height the agreed pair says does not exist renders `Invalid`/`anchor-ots-online-block-absent`.
  - A committed, online-refuted `.ots` **with** a pending branch renders `Pending` and carries the refutation as an A39 suppressed entry (D56 §4 preserved).
  - The eight tests D93 §5 lists as "must stay green" are green, unchanged.
  - `O4`'s `suppressed` list is asserted empty by construction.
  - Native and wasm32.

### A81 — Build the O7 tamper row (`anchor-ots-online-block-absent`)
- Milestone: M2
- Size: S
- Deps: A80, A21, A82, Q92
- Discovered by: **D93 §12** (2026-08-06)
- Problem: O7 is the one online refutation the spec never named, so D56 §8 gave it no row and its only instrument is a unit test — and D93 §3 measured that this test exercised the one corner where its own stated defect is invisible. A rule whose sole instrument was blind for a whole wave is the shape this project puts in the matrix.
- Do: Add the row as a `project_added[]` entry (the mechanism D56 §8 names) with `outcome_kind: "error"`, `expected: "anchor-ots-online-block-absent"` — distinct from every other claimed key. Fixture: A21's row-4 base with `OnlineBlockResult::NoSuchBlock` at the recorded height instead of a refuting header.
- Accept: the row is red when O7 is folded into "no evidence", and red when O4's D93 guard is reverted; native and wasm32.

### A82 — Promote the synthetic `.ots` writer into `anchor::testing`
- Milestone: M2 — **blocks A21**
- Size: S
- Deps: A11 (the container format), A24/A59 (`anchor::testing`)
- Discovered by: **D93 §9** (2026-08-06)
- Problem: `container`, `fork`, `bitcoin`, `pending`, `unknown`, `varuint`, `header_with` and `derived_root` live in `crates/antseal-core/src/anchor/verdicts/tests.rs` behind `#[cfg(test)]`. A21's rows cannot reach them from either home the matrix uses — `test_util` is not `cfg(test)`, and `crates/antseal-core/tests/` is a separate crate. The shapes no capture contains (a single-branch committed upgrade, an unknown attestation, a Bitcoin branch with no upgrade group) are exactly the ones A21 needs.
- Do: Move them to `anchor::testing` beside `MockTsa`, keeping every format constant imported by name from the parser so a format change breaks the build rather than silently minting bytes the parser rejects for the wrong reason. Re-point `verdicts/tests.rs` and `anchor::ots::tests`' private twin at the one copy.
- Accept: an integration target under `crates/antseal-core/tests/` mints a single-branch committed upgraded `.ots` and evaluates it; the builder is not reachable from non-test builds (feature- or `cfg`-gated as `MockTsa` is); no duplicate writer remains.

### A83 — Audit the A18 suite for rules asserted in the wrong corner
- Milestone: M2
- Size: M
- Deps: A80
- Discovered by: **D93 §3** (2026-08-06)
- Problem: `agreed_absence_of_the_block_is_invalid` names its defect in prose and cannot see it, because its fixture reaches the asserted state through O8 rather than through O7. It is the same defect class as the root-store lane's 25/25-green suite and the seven blind instruments of wave 4, and D56 §9 specifies ~22 such tests — two of which have now been found wrong by hand.
- Do: For every D56 §9 and D53 §9 test now committed, check that the fixture reaches the asserted outcome **through the rule the test names** and not through an earlier one. Where it does not, add the shape that does. Where a rule genuinely cannot be isolated, record why in the test's doc comment instead of implying it is.
- Accept: every such test either exercises its named rule in isolation or states why it cannot; at least one further planted fault per corrected test; no test's assertion is weakened to make it pass.

### A88 — A third `.ots` container writer, and the feature tier that makes consolidating it costly
- Milestone: M2
- Size: XS
- Deps: A82
- Discovered by: **the core lane** (2026-08-06) while executing A82.
- Do: `crates/antseal-core/tests/anchor_ots_blast_radius.rs` builds `.ots` containers with a hardcoded magic — a third writer beside `anchor::testing::ots_writer` (A82's) and `anchor::ots::tests`' deliberate independent copy. Re-pointing it at the promoted writer removes the duplicate, but pulls `test-util` into a target that today needs only `test-vectors` — the feature tier that has broken the wasm32 build once (`test-util ⊃ test-vectors`; only I/O-free zero-optional-dep code may sit on `test-vectors`, which is what wasm32 builds). Decide: pay the tiering cost, or record the copy as deliberate the way `anchor::ots::tests`' now is.
- Accept:
  - Either one writer remains and the wasm32 build is re-verified green, or the copy carries a recorded reason in its own module docs naming what it is independent *of* and why.
  - No outcome leaves three writers with no stated relationship between them.

### A89 — Pin that the minimum-anchor threshold is compared against a TSA-scoped count
- Milestone: M2
- Size: S
- Deps: A67 (which makes the correct call spellable); before U22/A20's degradation report
- Discovered by: **the core lane** (2026-08-06).
- Do: D92 §5.5 adds `distinct_verified_identities_of(AnchorKind)` so that A20's gate *can* read a TSA-scoped count, but **nothing prevents it reading the mixed scalar** — and D54 §3 rules that OTS contributes exactly zero to the minimum-anchor gate, so a `>= 1` test over the mixed value would pass a bundle with **no TSA at all**. Add the guard test that pins the comparison's operand, so A74's advertised "one-line change to a ≥2 policy" cannot silently become the wrong one-line change.
- Accept:
  - A bundle whose only headline-eligible anchor is a `proven` OTS does **not** satisfy the minimum-anchor gate — asserted, with the mixed-scalar implementation planted and proven red.
  - The guard names D54 §3 and A74 in its rustdoc, so the next reader of either finds it.

### A90 — A21's wasm32 Accept row is unsatisfiable from an integration target
- Milestone: M2
- Size: S
- Deps: A82; **before A21**
- Discovered by: **the core lane** (2026-08-06).
- Do: A21's Accept requires all eight tamper rows to execute in **both** the native and wasm32 suites. `anchor::testing` is gated `any(test, feature = "test-util")`, and the wasm32 dev edge enables `test-vectors` only — and the wasm32 lane runs `--lib`, so an integration test is a separate crate that does not run there at all. Any A21 row landing in `crates/antseal-core/tests/` therefore runs **natively only**, and would satisfy the Accept row in appearance only. Either move the writer's I/O-free, zero-optional-dep half down to the `test-vectors` tier, or rule that A21's rows are in-module `#[cfg(test)]` — the pattern A43 adopted for exactly this reason — and say so in A21's brief before the lane starts.
- Accept:
  - The ruling is recorded in A21's entry before A21 begins, not discovered by its lane.
  - Whichever route is taken, one A21 row is proven to execute on wasm32 by planting a fault and reading a non-zero exit — the runner discards libtest's count, so a green run alone does not show which rows ran (Q87).

---

## Returned unused

~~**A51**, **Q79** — no work found that needed them.~~ — **CORRECTED 2026-08-06 (orchestrator):** both were subsequently used and are live open rows in `TODO.md` — A51 is the `std::thread::scope` fan-out entry above, minted by the A3 lane, and Q79 is the scheduled-lane read. The note was true when written and was never retracted when the IDs were taken up.

> **Renumbered from A50, 2026-08-02 (orchestrator).** A50 and A51 were issued to two lanes by an allocation error of mine; the gamma lane merged first, so it keeps them and this later arrival is renumbered. IDs are permanent and cross-referenced — the protocol is to renumber the later arrival, never to reuse a number.

### A94 — A TSA-only configuration marks every seal degraded
- Milestone: M2
- Size: S
- Deps: A20, U22
- Discovered by: **the U22 lane** (2026-08-06).
- Do: `AnchorSubmission::is_degraded()` is true whenever `ots.outcome() != Complete`. A deliberate TSA-only configuration (zero calendars) therefore marks **every** seal degraded, with no way to express "no OTS wanted". Degradation is meant to be loud precisely so it is meaningful; a permanently-on warning trains the reader to ignore it. Decide whether zero configured calendars is a degradation or a configuration, and implement the answer.
- Accept: a TSA-only configuration produces an undegraded seal, or the report says explicitly that OTS was not requested; the D54 default path is unchanged and asserted.

### A95 — The gate duplicates the pipeline's `--no-anchor` skip, hiding the pipeline's own layer
- Milestone: M2
- Size: S
- Deps: A20, U22
- Discovered by: **the U22 lane** (2026-08-06), by measurement — deleting the pipeline's early return left the command-level row green.
- Do: S13 makes the `--no-anchor` skip the **pipeline's**, so that no injected gate — not even a real one — can submit for an unanchored work. `SubmitAnchorGate::run` checks the same flag again, which is harmless in production and corrosive in testing: with two independent guards, no product-level test can falsify either one alone. Consider making the gate's copy an **error**: a caller that reaches the gate with the flag set has a bug, and saying so makes both layers independently falsifiable.
- Accept: deleting either guard reddens at least one test that the other guard cannot rescue; the S13 property is still asserted at the pipeline layer.
- Notes: the isolating row today is `seal_pipeline.rs`'s refusing-gate double, which does redden. The point is that the *product* path cannot see it.

### A96 — `is_degraded()` is decided by whether a string came out non-empty
- Milestone: M2
- Size: S
- Deps: A20
- Discovered by: **the U22 lane** (2026-08-06).
- Do: `is_degraded()` is defined as `!degradation_report().is_empty() || …`, so the predicate depends on **string production**. A rewording that emitted no line for some failure class would silently turn a degraded seal clean — a rendering change altering a verdict, which is the coupling direction this project forbids everywhere else. Compute the predicate from the typed attempts and derive the report from it.
- Accept: a failure class that renders no text still reports degraded — planted and proven red against the current implementation.

### A97 — The minimum-anchor abort does not say the work is resumable
- Milestone: M2
- Size: XS
- Deps: A20, U22, D45
- Discovered by: **the U22 lane** (2026-08-06).
- Do: `AnchorGateError::MinimumAnchor` says *"Re-run when an endpoint recovers, or pass `--force-degraded`"* and never says the work is left `Staged` and that a re-run **auto-resumes** it rather than starting a second seal. A user who does not know that has no way to tell whether re-running is safe.
- Accept: the message names the resume behaviour; the claim is asserted against D45's actual resume path, not just spell-checked. Cross-domain — A owns the words, U owns resume.

### A100 — The `.ots` allocation guard and the `.ots` parser assert two different rules
- Milestone: M2
- Size: M
- Deps: A11 (the parser), A23 (the target); rules from D58 and D10 §4, with D84 on which applies
- Discovered by: **CI run 31086210534** (2026-08-06) — the first remote execution of A23's `anchor_ots` target, which found the disagreement in **3140 execs** of a `fuzz-smoke` run.
- Reproduced by: **CI run 31127730409** (2026-08-06, head `d82f72e`) — independently, under a different libFuzzer seed (4057948299), hitting it at **exec #476** on a **744-byte** input. Still the only red in that run (18/19 green).
- Problem: two committed rules give different answers for the same input, and nothing compared them until a fuzzer did.
  - **D58's rule** is absolute: `MAX_OTS_VALUE_BYTES = 32_768` (`anchor/ots/limits.rs`) bounds the op executor's running value, and `alloc_checked` (`anchor/ots/exec.rs`) reserves only after checking against it. That is deliberately absolute — it is D58 §3.2's fix for the upstream crate's unbounded `vec![0; attacker_varint]`.
  - **The target's rule** is relative: `assert_within_budget` (`fuzz/src/lib.rs`) asserts D10 §4's clamp — peak single allocation ≤ `input_len × MAX_CLAMPED_ELEMENT_BYTES(=1) + SLACK(=4096)`.
  - For the 248-byte reproducer the caps are **32 768 B** and **4 344 B**; the measured peak was **5 120 B** — legal under D58, illegal under the guard.
  - **The second witness sharpens the ruling.** The 744-byte input moved the *relative* cap to **4 840 B** (`744 × 1 + 4096`) but the measured peak was **again exactly 5 120 B** — unchanged across a 3× difference in input length. So the executor's peak here is **a constant, not a function of input length**: it is a fixed allocation step (5 120 = 5 × 1 024). Wherever that step is reached, the relative guard fails the input iff `5120 > len + 4096`, i.e. **iff `len < 1024`** — same allocator behaviour, verdict decided purely by which side of 1 024 B the input falls on. (Two witnesses, 248 B and 744 B, are consistent with a constant peak; they do not by themselves prove the step is constant on *all* paths — the ruling should confirm that against `alloc_checked`.) A rule whose verdict on identical allocator behaviour depends on the input's length is the wrong *shape* of rule for this parser — which is the direction D84 already pointed. This is evidence for the ruling, **not** authority to patch either side; A100 stays open until ruled.
- Do: rule which applies to `.ots`, and do **not** patch either side by reflex. The evidence leans one way: **D84 rules that anchor-artifact *internal* limits are "verifier policy over foreign formats", set at M2 against A25's real artifacts, and are explicitly *not* an exception to line 123 nor D10 format surface** — which says the target is asserting a format-level rule against a parser that was never built to it, and should use a budget bounded by `MAX_OTS_VALUE_BYTES`. The other option is live and must be argued rather than dismissed: tighten the executor so a running value cannot exceed the input that claimed it, which would make `.ots` obey the same clamp every other decoder does. Whichever wins, the losing rule's site gets a comment naming this task, because the next reader will otherwise re-derive the conflict.
- Accept:
  - One rule, stated once, with the other site referring to it.
  - The committed reproducer below is a regression case that is **red before the ruling lands and green after**, whichever way it goes.
  - If the executor is tightened, a real `.ots` from `testdata/anchors/A25-bootstrap/` still parses — the cap must not reject honest artifacts, which is the failure mode D54's "at least one calendar commits" rule already had to avoid once.
- Reproducer (248 B, sha1 `b5aec24c28e280a39dfba4027c750954fac646c3`; `fuzz/artifacts/` is gitignored, so it lives here):
  ```
  AE9wZW5UaW1lc3RhbXBzAABQcm9vZgC/ieLohOiSlAEIBpn9k0g/KGjTeVhD8AICAgICAgICAgICAgIC
  AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIC
  AgICAgICAgICApjTePAQ4uIkQ55/D92MHurHPqc42wjxIKV0REqlAAK2/lryRiZwCkv8lQ1h+BN8w52o
  LVMnbJ1mCGIlUjcUDpEb0B38XN7G3K/wIAkAAvMf1aLw/wj34HM4S0/1K8XsCAjxINVt8w4A71LI1MJ+
  led+oCY=
  ```
- Notes: the guard did exactly its job. This is the first defect the M2 fuzz targets have returned, and it arrived on the target's **first remote run** — which is the standing lesson that a lane never executed on the remote is not evidence, restated for fuzzing.

### A101 — TSA intermediates are never captured, and the M3 bundle inherits it
- Milestone: M3
- Size: S
- Deps: A10; D98
- Discovered by: **D98** (2026-08-06), in its residual-risk review.
- Problem: nothing in `antseal-cli` has ever populated `TsaAnchor::intermediates`, so antseal's own bundles will carry `[]`. That is harmless today, and harmless **by luck rather than by design**: all four pinned-root TSAs — FreeTSA, DigiCert, DFN and Sectigo — self-carry their chains, so `validate_token_chain` pools the token's own bag and reaches `proven` with an empty intermediates list. The error direction is monotone under-claiming, which is why it has never surfaced as a wrong verdict. The cost lands where it is hardest to see: not on `status`, which re-verifies locally, but on **third-party verifiers**, for whom a future TSA whose token does not ship its chain silently costs `proven` on every bundle that names it.
- Do: either store the responder's certificate bag at capture time, or record the reliance on self-carrying tokens as a decision with a test that fails when a configured endpoint stops self-carrying.
- Accept: either the capture path stores the bag, or the reliance is recorded and a configured endpoint that stops self-carrying reddens a named test.
- Notes: D98's revisit trigger is adding a TSA endpoint, or any root-store bump — the two events that can change the answer without anything in this repository changing.

### A102 — An unreadable `.ots` is folded into `AttestedOnly`, which does not nag
- Milestone: M2
- Size: S
- Deps: A15; U25
- Discovered by: **the U25 lane** (2026-08-07).
- Problem: `work_status` drops `Unreadable` artifacts **before** it tests for pending ones, then falls through — so a work whose only anchor is a corrupt or foreign `.ots` classifies as `NagState::AttestedOnly`, whose meaning is *"every OTS anchor is already attested"*, and `nags()` is therefore false. The work with no usable evidence at all goes **silent**, under a name that asserts its evidence is good. That is the same failure shape D97 §1.2 measured for the groupless upgrade: the machine goes quiet exactly when the news is worst. The behaviour is pinned as landed by `an_unreadable_ots_is_folded_into_attested_only_and_stops_nagging`, and it is why `list` refuses to render the word "attested" off that state at all.
- Do: give the state a home that tells the truth — a fifth `NagState`, or an `Unreadable` arm on the existing four that nags. Either way the classification must stop borrowing the name of a good outcome for a bad one; a taxonomy that has nowhere to put a bad input will put it somewhere reassuring.
- Accept: a work whose only anchor is unreadable nags, and renders under a name that does not claim attestation; the existing pin is **updated** in the same change rather than deleted, so the old behaviour stays visible as the thing that was fixed.

### A103 — `NagState` has no `name()`, so its kebab table lives in the CLI
- Milestone: M2
- Size: XS
- Deps: A15, U25; D98 rider 3b
- Discovered by: **the U25 lane** (2026-08-07).
- Problem: D98 rider 3b puts `NagState`'s kebab name into `list`'s `--json` output, and `NagState` has no `name()` — so the table (`anchored` / `only-pending-ots` / `attested-only` / `unanchored`) now lives in `listing.rs`, in a different crate from the enum it names. That is a **second table for one taxonomy**, which is precisely the shape D98 rejected its option (c) for: a projection maintained beside a definition desynchronises silently, because nothing compares them. Option (c) was killed at the level of *states*; this is the same defect at the level of *names*, and it is smaller only because a wrong name is easier to notice than a wrong verdict.
- Do: put `name()` on the enum in `antseal-anchor`, beside the variants, and have `listing.rs` call it. A new variant then cannot reach the JSON without being given a name.
- Accept: adding a `NagState` variant without giving it a name is a compile error, not a silently wrong string; `listing.rs` holds no spelling of any variant.

### A104 — A repeated upgrade re-splices the same attestation and grows the stored `.ots`
- Milestone: M2
- Size: S
- Deps: A14, A15; U23, U24
- Discovered by: **the U23 lane** (2026-08-07); fixed by **the U24 lane** the same day, because U24's hook is what turned it from a slow leak into a per-invocation one.
- Problem: a repeated `--upgrade` re-spliced the same attestation and grew the stored `.ots` **monotonically**, bounded only by `MAX_OTS_BYTES` (1 MiB). The mechanism, end to end: `splice_sibling_before` is a **pure insertion**, so the pending branch survives the merge; the next run's `pending_refs` therefore finds the same attestation again; `added_bitcoin` is a **multiset** difference (`upgrade.rs:413-432`), so the duplicate counts as *added* and `changed` goes true; and because `upgrade.is_some()` by then, `confirm_header` is skipped, so the old group is re-recorded beside a grown artifact. Nothing renders wrong — the state stays `attested` throughout — the artifact simply gains one spliced attestation per run. U24's hook would have made that **per invocation, on every work**, which is why the fix could not wait.
- Do: **the first proposed cut was wrong, and was not decidable from the artifact.** U23 suggested skipping the merge when the artifact is "already attested at all". `OtsArtifact` is a flat attestation list with **no parent links**, and a real upgrade body carries ops, so the Bitcoin attestation derives a *different* value from the pending commitment it descends from — the coarse test cannot even be evaluated. Worse, it is actively wrong: A14 deliberately permits a **second calendar's** attestation to merge later without a second header fetch, so "already attested" would discard real evidence for ever. It was planted as a fault and refuted by its first row.
- Accept: **DONE 2026-08-07 (U24 lane).** The landed fix keys on the **splice itself** rather than on the artifact's state: `splice_sibling_before` emits `0xff ‖ body` immediately before the attestation, so a repeat is that literal prefix and nothing else. `ots/upgrade.rs::already_merged(stored, target, body)` tests for exactly that, called in `upgrade_one_anchor` between `current_ref` and `merge_upgrade` — checked against `current`, because an earlier merge in the same loop has already moved the offsets — and emits `UpgradeNote::AlreadyMerged`. **A calendar answering with a different body still merges**: the rule refuses repetition, never evidence. Three unit rows over the real `MERGED_A` / `UPGRADE_A_ALICE` / `UPGRADE_A_BOB` fixtures; the characterisation test written at discovery turned green.
- Notes: the transferable lesson is the one the refuted cut teaches — a de-duplication rule must be keyed on the **operation that would be repeated**, not on the state that operation produces, because the state is reachable by other routes and those routes are the evidence the rule was meant to preserve. U59 records what this fix cannot reach: `already_merged` needs the poll's body, so it stops the growth without stopping the poll.
