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
  - **1.** Vectors committed as the **`anchor` kind** under
    `testdata/vectors/v1/anchor/`, registered in `INDEX.json` and in
    `KNOWN_KINDS`. Not `testdata/anchors/`, which is A25's capture area and
    carries no freeze, no retention rule and no wasm parity lane (D101 §2).
  - **2.** Frozen and retained: a `#! kind anchor A22` directive and one
    digest line per file appended to `testdata/vectors/v1/FROZEN.sha256`,
    retained forever per Q6's per-version retention policy.
  - **3.** Native and wasm runs produce byte-identical `recomputed_digest`
    for every vector — which, for this kind, is the whole `expect` object of
    D101 §3.5 as amended by D103 §6.
  - **4.** The M2 exit checklist references the `golden-vectors`,
    `vector-freeze` and `wasm-bitmatch` lanes' passing runs **and** A21's
    in-module wasm32 rows (D101 §6.3 — two mechanisms of different strength,
    one criterion); any wasm-incompatible dependency (A-OD6) resolved first.
- Notes:
  - **Accept replaced 2026-08-09 by D103 §7.1, and the rows are numbered because the defect class is *counting*.** The three rows this replaced read, verbatim: *"Vectors committed under `testdata/anchors/`; retained forever in CI per format-stability policy (Q wiring)."* / *"Native and wasm runs produce byte-identical serialized verdicts for every vector."* / *"M2 exit checklist references these passing tests; any wasm-incompatible dependency (A-OD6) resolved first."* Row 1 named the **refused** home — D101 RULING 1 put the vectors under `testdata/vectors/v1/anchor/` on five committed sources against one — and its semicolon is the compound clause D101 §2.2 measured as the origin of the "four Accept rows" miscount, the same expansion D53 had already caught once on A21. D101 §2.2 then corrected three documents to say **three** while D101 §2.3 rewrote the Accept as **four**; explicit numbers end that loop by making the count unnecessary rather than by adjudicating it (D103 RULING 6).
  - **What landed, 2026-08-09.** One document, `testdata/vectors/v1/anchor/anchor.json`, **seven cases over four recorded artifacts**, one top-level `anchor_digest` (digest A) and one top-level `verify_at_unix = 1786100000` (2026-08-07T10:53:20Z — after every `genTime`, every attesting `nTime` and every `fetch_date`, before every signer certificate's `notAfter`). Frozen at `c808381e16096f51a5d7195db9d6e5e6381dea00127d7987748c9b8064fe8ff0` under `#! kind anchor A22`; no existing digest moved and no existing vector was touched. Cases 4/5/6 carry the **three-way spliced upgraded `.ots`** — sha256 `c2bf8b2c22055061f7105c357459969d4bb62d397f95001a70f570fed88e0c68`, **3 808 B, 244 ops, depth 85, six attestations** — derived by `gen_vectors.py` from `merged-A.ots` plus the three committed `upgraded/A-*.upgrade` bodies in `pending_refs` document order, and deliberately **not** committed as an archive file (D103 RULING 3a: the vector copy is authoritative, the archive is provenance).
  - **Row 2's "one digest line per file" is scoped by the manifest's own standing rule.** `FROZEN.sha256:13-16` freezes only committed vector `*.json`; `README.md` and the `*.py` reference generators are deliberately unfrozen, because the generators are re-runnable cross-checks and the JSON they produced is what the format commits to. So the append is one digest line, for `anchor/anchor.json`, and that satisfies row 2 rather than falling short of it.
  - **A-OD6 is resolved, so row 4's trailing clause is already discharged.** D58 adopted the `opentimestamps` crate **in no form** — not pinned, not wrapped, not vendored — and `antseal-core` carries an in-house `.ots` codec instead, so no wasm-incompatible dependency remains to resolve. Recorded here because **`MVP-SPEC.md:155` still says *"OTS calendar client (in-house; `opentimestamps` crate as codec)"*** and is stale against D58; the spec is not this task's to edit, and a reader who takes line 155 at its word will go looking for a dependency that was never taken.
  - **No "M2 exit checklist" document exists.** `docs/` carries no such file, so the only artifact row 4 can reference today is the **Gate sentence in `TODO.md`'s M2 section**. Whoever mints a real checklist inherits row 4's two-mechanism requirement (the three vector lanes *and* A21's in-module wasm32 rows); until then, row 4 is discharged against the register and should say so rather than pointing at a document that has to be found first.

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
- Do: Script non-CI smoke runs against real services using a fixed test digest: (1) submit to the real default OTS calendars and store the pending `.ots`; (2) the next day, upgrade → verify `attested` offline, then `--online` promotion to `proven` via real blockstream.info + mempool.space; (3) obtain and fully verify real FreeTSA (ECDSA P-384) and DigiCert tokens against the pinned root store; (4) one live must-agree round each for esplora and the Arbitrum RPC pair. Record the artifacts (tokens, pending/upgraded `.ots`, header) as the committed fixtures A5/A8/A11/A12/A22 consume, and verify all default endpoint URLs/paths are live and correct. An early bootstrap capture may run as soon as A3/A4 exist, seeding A5/A11/A12 development fixtures; the full protocol re-runs at task completion. **Corrected and superseded 2026-08-02**: this scoped the bootstrap at "one TSA response per default endpoint + one pending `.ots`" and **it was under-scoped** — the M2 planning round needed, and captured, far more. What is already on disk under `testdata/anchors/A25-bootstrap/`, all captured 2026-08-02 with a `CAPTURE.log` per group: pending `.ots` timestamps for **two** committed golden-vector `anchor_digest`s at **three live calendars** (19:16Z — `finney.btc.calendar.opentimestamps.org` failed DNS resolution and is not in upstream's default list at all); a real FreeTSA request/response pair (`freetsa-D59-*`); **five TSA root certificates with a provenance record** (`roots-*`); and **nine live TSAs captured and dissected** for the pin decision (`D60-*` + `D60-CAPTURE.log`). The two-day OTS clock therefore started **2026-08-02T19:16Z**; the upgrade half is due **not before 2026-08-04**. **Corrected again 2026-08-07** — the sentence that stood here ("A25's remaining work is the day-2 upgrade, the `--online` promotion, and the live must-agree rounds") named three items of which none is outstanding, and it had been false for four days. The **day-2 upgrade** ran **2026-08-03T09:03Z** (six commitments, all `200`, `testdata/anchors/A25-bootstrap/upgraded/UPGRADE-CAPTURE.log`) — and it was not day 2: the wait was **13 h 47 m**, not the ~48 h the entry above predicts. The **live must-agree rounds** ran **2026-08-03T08:20Z–08:34Z** for both esplora and the Arbitrum pair (`testdata/anchors/A16-A17-live/CAPTURE.log`). The **`--online` promotion**'s last network-bound input landed **2026-08-07**: the 80-byte mainnet headers for the three attesting blocks 960767/960768/960771, from both esplora endpoints, twelve requests all `200`, byte-identical across endpoints on every header, each verified offline by `double-SHA256(header) == claimed block hash` (`testdata/anchors/A25-upgrade-headers/`). **A25 is no longer network-bound in any part.** What remains is entirely local: the `scripts/anchor-smoke` entry point (Accept row 1, and Q99's precondition) and the Q26 hand-off (Accept row 4). The `--online` promotion itself additionally waits on `antseal verify`, which is an **M3 stub** — `crates/antseal-cli/src/run.rs:50` maps `Command::Verify` to `Milestone::M3` and `run.rs:60` returns `CliError::NotImplemented` — so that step is blocked by a milestone, not by a network, and it is not A25's to unblock. **Ruled 2026-08-11 (D126 §3.1) — the closing clause "the full protocol re-runs at task completion" is DISCHARGED and STRUCK.** Discharged: at task completion the protocol has re-run as the `A25-wave16-cycle` campaign — day-1 submits of the two committed golden-vector digests at the product's four `DEFAULT_OTS_CALENDARS` (2026-08-11T12:46Z, 8/8 `200`, by hand under fresh recorded §1 consent), day-2 upgrade/TSA/must-agree THROUGH `scripts/anchor-smoke` and antseal's own A14/A10/A16/A17 clients (~17:55Z, its own fresh consent), findings logged per runbook §4. Struck: no Accept row replaces it, because every future re-run trigger already has a per-step owner — runbook §5 refreshes (fresh §1 consent, commit beside never over), A26 + `docs/anchors/root-store-update.md` for roots, A44's scheduled rot watch, A48 ✅ for re-measurement, D54 for the calendar set, the eternitywall re-polls recorded re-pollable — and a full-protocol row would have no trigger to state (the permanently-network-bound defect the 2026-08-07 adjudication named). The submit-path residue is deliberately NOT carried by this strike: it is `V7.1`'s and Q236's, disposition D127's.
- Accept:
  - Runbook + script committed; the two-day OTS protocol completed at least once before M2 close, results logged.
  - Both real TSA tokens reach `proven` against the pinned store.
  - Fixtures land in `testdata/` (test digest only — no secret material).
  - Endpoint liveness/caveat findings handed to Q for the alternates doc table.
- Notes: Execution-time upstream verification is inherent here (calendar endpoints, esplora paths, TSA URLs, FreeTSA's current cert). Respect TSA rate limits during the run.
- **Accept-row adjudication, verified 2026-08-07** (statuses are the orchestrator's; this records only what was checked and found):
  - **Row 1 — PARTIAL, and the script is the whole of what is missing.** The runbook is committed (`docs/anchors/real-smoke-runbook.md`) and the two-day OTS protocol has been completed once and logged end to end: submit **2026-08-02T19:16:18Z–19:16:26Z** (`testdata/anchors/A25-bootstrap/CAPTURE.log`), upgrade **2026-08-03T09:03:38Z–09:03:42Z**, six commitments, all `200` (`.../upgraded/UPGRADE-CAPTURE.log`). The **script does not exist**: `scripts/` holds 18 entries and none is `anchor-smoke`, and a tree-wide grep for `anchor-smoke` across `*.sh`/`*.rs`/`*.toml`/`*.yml` returns nothing. This row is the only one blocked on work A25 itself still owes, and Q99's Accept row 1 makes the same script the precondition for deleting the runbook's §0.
  - **Row 2 — SATISFIED, over real captured material.** FreeTSA reaches `proven` against `TsaRootStore::pinned()` at `crates/antseal-core/src/anchor/verdicts/tests.rs:1205-1208`; DigiCert at `:1313-1316`. Both read the real 2026-08-02 tokens (`D60-tsa-freetsa-resp.tsr` via `anchor::testing::tamper_rows::FREETSA`, `D60-tsa-digicert-resp.tsr` via the local `DIGICERT`), not synthetic ones. Caveat worth recording: **both assertions are the anti-vacuity arms of tamper tests**, so the property this row buys is pinned only as a side condition of tests named for something else. It is a real pin — the build goes red if either token stops reaching `proven` — but nothing in the tree is *named* for it.
  - **Row 3 — SATISFIED.** `testdata/anchors/` holds 88 files across three campaigns (`A25-bootstrap/` 61, `A25-upgrade-headers/` 14, `A16-A17-live/` 12, plus the directory README). The only digests ever stamped are the two committed golden-vector `anchor_digest`s A and B, both derived from the documented fixed test seed (`OTS-BOOTSTRAP.md`); the 2026-08-07 campaign sent no digest at all. No secret material.
  - **Row 4 — NOT SATISFIED, and not satisfiable as written yet.** Q26 is **M4** and its document does not exist — `docs/anchors/` holds only `real-smoke-runbook.md` and `root-store-update.md`. The findings themselves are recorded and citable; what is owed is a row apiece in Q26's table, and Q26's `Do` (`tasks/Q.md:456`) currently contains **none** of the following: (a) **`timestamp.entrust.net` is served by Sectigo** — one signer certificate signs both captures, issuer `CN=Sectigo Public Time Stamping CA R41`, serial `0xE74EF255B0504FFADBA6DFF7FC8BA315`, so the two are **one TSA behind two names and not two independent anchors** (`D60-CAPTURE.log:51-54`); (b) **DigiCert's port 443 refuses connections**, so plain HTTP is required rather than a shortcut (D90 §6.6); (c) **four live alternates Q26's five-TSA list omits entirely** — Apple `http://timestamp.apple.com/ts01`, GlobalSign `http://timestamp.globalsign.com/tsa/r6advanced1`, Certum `http://time.certum.pl`, Entrust `http://timestamp.entrust.net/TSS/RFC3161sha2TS`, all `200` with `PKIStatus: granted` and the nonce echoed (`D60-CAPTURE.log:36-46`); (d) **token `genTime` ran ~129 s *ahead* of the capture host's clock**, so the obvious `gen_time <= fetch_date` sanity check against a local clock rejects every token in the tree (`D60-CAPTURE.log:16-28`) — this belongs beside Q26's "expired ≠ invalid" LTV note; (e) **Sectigo's ~15 s spacing and SwissSign's ~10/day quota were never approached** at capture, so they are upstream-published claims and Q26 must not present them as measured (`D60-CAPTURE.log:47-49`); (f) **`finney.btc.calendar.opentimestamps.org` failed DNS resolution** and `catallaxy` answered `http=000` where alice and bob answered `404` (`upgraded/UPGRADE-CAPTURE.log:13`) — calendar rot, which is D54's and A14's rather than Q26's, and is listed here so the hand-off does not silently drop it.
  - **Three documents charge A25 with work that is A48's.** `docs/format/anchor-artifact-limits.md:251` says *"A25 owes that re-measurement"*, `:258` says *"**A25 must re-measure them against the real fixture and append**"*, and `upgraded/PROVENANCE.md` said the same — while **A48** exists precisely to do it, with A25 as its dependency and with Accept rows covering both halves. Five `measured against` cells (`:221-226`) still cite `rust-opentimestamps-LARGE_TEST.ots`, a third-party crate's test constant. **A25 does not owe this; A48 does**, and A48's blocker is gone: its `Deps` line still reads *"the two-day OTS pending → upgraded cycle, **not before 2026-08-04**"*, but that cycle completed **2026-08-03**, and A48(b)'s *"fetched mainnet header compared against the ops-derived root"* now has its header (2026-08-07). Corrected in `PROVENANCE.md` on 2026-08-07; the limits doc and A48's own `Deps` are outside this lane's files.
  - **The `Do`'s closing clause has no Accept row behind it.** "The full protocol re-runs at task completion" appears only in prose. Closing A25 on its four Accept rows is defensible; closing it on that clause is not, and that clause is the **only** thing that makes A25 look permanently network-bound — it would require a fresh real-endpoint campaign, under fresh §1 consent, every time the task is touched. All four rows are now either satisfied or blocked on **local** work (the script; a Q26 document that does not exist). If the re-run is genuinely wanted it needs an Accept row of its own, with a stated trigger; if it is not, the clause should go.
- **Finding recorded 2026-08-07 — two latencies, and the tree had measured the wrong one.** The `nTime` fields of the three attesting blocks read 2026-08-02T20:15:46Z (960767), 20:27:11Z (960768) and 20:59:44Z (960771), i.e. **59 to 103 minutes** after the 19:16Z submission: **Bitcoin confirmed the same evening**. The **13 h 47 m** figure `OTS-BOOTSTRAP.md` corrected its own "~48 h" draft down to is therefore the *calendar's* aggregation-and-serving cadence, not the chain's confirmation time. Anything reasoning about how long an anchor takes to become **provable** must cite the calendar; the block interval is the number that looks like an answer and is not. Read from the committed header bytes, not from endpoint JSON; the runbook's §3.1 step 2 now teaches both figures separately.
- **Script landed 2026-08-11 (wave 16): `scripts/anchor-smoke`, and the four A127 sites moved — or their reason for not moving is recorded here.** The script carries one subcommand per runbook §3 step — `submit`, `upgrade`, `tsa`, `must-agree` — plus a loopback-only `selftest`, and it drives **antseal's own clients**, never `curl` (the distinction D118 §1.5 measured and `V7.1` records): A13's `submit_to_calendars`, A14's `pending_refs` → `UpgradeTarget::from_pending_uri` (A42) → `poll_upgrade`, A10's `capture_one` fully verified against `TsaRootStore::pinned()`, and A16/A17's `fetch_agreed_header`/`confirm_arbitrum_tx`, all through the dev-only `anchor-smoke-driver` binary (`crates/antseal-anchor/src/bin/anchor_smoke_driver.rs`, `required-features = ["test-util"]`, absent from every default build, zero new dependencies). Selftested loopback-only, 12/12 arms green: eight green arms prove each mode's request-building and IO path against `python http.server` mocks fed committed capture bytes (the mock-observed submit body is the exact 32 digest bytes with the OTS `Accept` header; the arbitrum arm reproduces D55 §3's tuple-agreement over the two byte-different committed receipts), and four red arms are proven **by message**: a 31-byte digest refused before any request (mock saw 0), the `ANTSEAL_NO_REAL_ANCHOR_NETWORK=1` refusal naming the policy and `ci-lanes.sh anchor-net-policy`, the missing-`--consent` refusal citing runbook §1, and an incomplete log record making the run refuse to finish (runbook §4's four-field rule, executable). The four dependent sites (A127): (1) **runbook §0 deleted** in this same change per Q99 row 1's rule, its still-true second bullet (`antseal verify --online` is an M3 stub) relocated to §3.1 step 4 with its cross-reference rewritten; (2) **this row's Accept row 1: script half done, row stays open** — the two-day protocol has run three times by hand, but the script's own real-endpoint branch is unproven until the maintainer-consented day-2 run; (3) **Q99 Accept row 1 satisfied** (script committed + §0 deleted in one change), Q99 stays open on its row-2 clause that the script run the protocol against real endpoints; (4) **`V7.1` stays `gap` with the reason recorded in its note** — antseal's own path has still never spoken to a real calendar, and the script exists precisely so tomorrow's consented run closes that. **Day-2 plan (one sentence):** under fresh §1 consent per campaign, run script-driven upgrades of `testdata/anchors/A25-wave16-cycle`'s eight pendings (`anchor-smoke upgrade --campaign testdata/anchors/A25-wave16-cycle`), optionally fresh script-driven submits, the TSA proving run the day-1 log explicitly reserved for the script (`anchor-smoke tsa`, both defaults, tokens to `proven` against the pinned store), and one script-driven must-agree round each for esplora and the Arbitrum pair. Two honest log-format notes a later reader needs: successes record `http=2xx` (the typed client returns carry the response class, not the exact code — recording `200` unseen would be a fabrication), and outcomes whose bodies antseal's classifier consumed (D58 §7.4's two 404s, unverifiable TSA replies) record `bytes=- sha256=-`; both notations are explained in every log header and in runbook §4.
- **Day-2 executed 2026-08-11T17:55–17:56Z under fresh recorded §1 consent (the words: consent granted, in direct reply to the named request; recorded verbatim in all three capture logs), THROUGH THE SCRIPT.** `upgrade`: **6 of 8 upgraded** via antseal's own A14 path (`pending_refs` → `UpgradeTarget` → `poll_upgrade`) — alice/bob/catallaxy for both digests, upgraded artifacts stored beside the pendings with full four-field log lines; both `finney.calendar.eternitywall.com` pendings answered the pending-42-byte-404 class → `not-yet-confirmed`, kept re-pollable, never promoted (a re-poll needs its own fresh §1 consent). **Calendar cadence this cycle: ~5h09m** (submit 12:46Z → served 17:55Z) against the bootstrap's 13h47m — a third measured figure, still no interval to plan on (runbook §3.1 step 2). `tsa`: FreeTSA and DigiCert requests built and verified by A10's own path against `TsaRootStore::pinned()` — **both `state=Proven`, `root_store_version=1`** (`freetsa-root-ca`, `digicert-trusted-root-g4`), request/response pairs committed — the proving run the day-1 log reserved for the script, so Accept row 2's property is now ALSO pinned by a run named for it. `must-agree`: esplora pair **agreed** on the 80-byte header for 960767 (committed); Arbitrum One pair **agreed** over the extracted tuple (`status=1, block_number=490596171`) despite byte-different JSON — D55 §3 through A16/A17. **What this leaves**: antseal's SUBMIT path has still never spoken to a real calendar (day-1 was manual; today's consent scope excluded fresh submissions) — one consented script-driven submit pair closes V7.1's residue; the two eternitywall re-polls are optional evidence, not blockers. **Q99 closed on this run** (its submit-mode residue recorded there, owned by V7.1). A25's own closure awaits the in-session ruling on the Do's re-run clause and row 4's Q26 hand-off.
- **✅ CLOSED 2026-08-11 on the four Accept rows, per D126 (`docs/decisions/D126-a25-rerun-clause-and-row4-handoff.md`).** Row 1 measured true on every conjunct: runbook (`docs/anchors/real-smoke-runbook.md`) + script (`scripts/anchor-smoke`) committed; the two-day OTS protocol completed twice before M2 close (`CURRENT_MILESTONE` still `M1`; Q236 open) — the bootstrap cycle 2026-08-02T19:16Z → 2026-08-03T09:03Z, literally two days, and the wave16 cycle 12:46Z → 17:55Z with the upgrade half through the product's own client — results logged with runbook §4's four fields. Row 2 held since 2026-08-07 and now ALSO evidenced by a run named for the property (`TSA-CAPTURE.log`: both defaults `state=Proven root_store_version=1` via A10); the named-test half stays A105's. Row 3 held (four campaigns, golden-vector digests only, no secret material). Row 4 closed on the EXECUTED hand-off: findings (a)–(e) written into Q26's `Do` verbatim-by-citation and A25 added to Q26's `Deps` (D126 §3.2); (f) discharged by its standing homes — runbook §3.1's behaviour classes + finney note, D54, A14's four-way discriminator, A44's scheduled watch — named there so the exclusion is visible. **Boundary (D126 §4): the submit residue — antseal's submit path has never spoken to a real calendar — stands, single-homed in `V7.1` (`gap`) + Q236's gate, disposition D127's; no row here named it, and closing mirrors Q99's same-day precedent (qualification recorded, not a second home).**


### A26 — Define TSA root-store versioning and update process
- Milestone: M2 (process runs `continuous` thereafter)
- Size: S
- Deps: A6, A7 (Q26/Q31 at M4 consume the procedure — not ordering deps)
- Spec: Anchoring (line 109), Format stability (line 123), Risks (line 182)
- Do: Define and document the update process for the compiled-in root store: monotonically increasing store version + date; adding/rotating a root is a reviewed change requiring the A7 provenance procedure; roots are effectively append-only — removals need an explicit compatibility note because previously issued bundles must keep verifying under the format-stability policy; each release checks pinned-root validity windows. Verification output reports the store version in use. **Added 2026-08-09 (D101 §4.2, RULING 3a):** run the `golden-vectors` and `vector-freeze` lanes on the append commit; a moved `anchor` vector means the append introduced a **second valid path for a pinned token** and needs D101 §4.3's hand-off, not a regeneration.
- Accept:
  - Documented procedure committed and referenced by Q's release checklist.
  - Test: after appending a new root, every existing per-anchor verdict is byte-identical except for the store version — `chain::tests::appending_a_root_leaves_every_existing_verdict_unchanged`, with a non-vacuity guard showing the appended root promotes a previously unanchored token. The `anchor` golden vectors (A22) additionally re-run unchanged on the append commit, which is a *consequence* of the property, not its proof: a vector executor reaches only `TsaRootStore::pinned()` and cannot compare two stores (D101 §3.1).
  - Store version visible in verdict data for R's display.
- Notes:
  - **Accept row 2 amended 2026-08-09 by D101 §4.4 (RULING 3d).** The former wording was: *"Test: after appending a new root, all existing anchor golden vectors still verify unchanged (store version bumped, results stable)."* It described a mechanism that **cannot exist**: demonstrating "appending a root changes nothing" needs the same artifact evaluated against **two** stores, and a vector executor reaches exactly one, because `TsaRootStore::from_static` sits on the `test-util` feature while the executor sits on `test-vectors` (D101 §1.4). The property is nonetheless true, tested and non-vacuous today — `chain.rs:2116-2157` runs five real tokens through `pinned()`'s root set and that set plus SwissSign, asserts full `ChainVerdict` equality, and proves the append was real by showing SwissSign moves `internally-consistent-only` → `proven` across it. The row now names that test; A22's vectors re-running unchanged is a consequence, and the vector lanes are where the one shape that *would* move something gets detected (the `Do`'s added line).
  - **Still owed here and not written by this correction:** D101 RULING 3c wants a bullet in this `Do` naming the **three events that could ever need D94's verdict-event hatch** for a frozen `anchor` vector — an A26 root *removal*, a signer-DN *rendering* change, and a root append that gives a pinned token a second valid path. That bullet is **A108's**, which is open and scoped to exactly it, in this `Do` and in the freeze manifest's prose. The manifest half has landed with A22 (`FROZEN.sha256`, the paragraph beside `#! kind anchor A22`); this half has not.

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

### A71 — The `anchor_token` corpus cannot pass the imprint check on an unmutated seed
- Milestone: M2
- Size: S
- Deps: Q9 (the cargo-fuzz infrastructure and `TARGETS`), Q17 (which seeded both anchor targets and found the empty-corpus degradation)
- Spec: `docs/testing/fuzzing.md`; Anchoring — RFC 3161 token verification (MVP-SPEC.md line 109)
- Discovered by: **D109** (2026-08-10) §1.5, as the first finding of the `--task-citations` check Q85 lands. The caveat itself was written into `scripts/fuzz.sh:98-103` and names this id; the row was never created, so the id dangled in a committed gate script and was invisible to every lane. It was invisible to the decision half twice over: `scripts/` is not in `DECISION_SCAN` and `.sh` is not in `DECISION_SUFFIXES`, so the code Q85 was asked to mirror could not have found it. (Those two constants were **deleted** by Q133 on 2026-08-10 into `CITATION_SCAN`/`CITATION_SUFFIXES`, which now sweep `scripts/` and `.sh`; the sentence above records the state at discovery, not the state today — **Q151**.)
- Problem: `drive_anchor_token` calls `split_digest`, which takes the expected imprint off the **head** of the input (`crates/antseal-core/src/anchor/fuzz_entry.rs:61-64`). The seeds are the A25 bootstrap captures — whole `.tsr` files — so a seed's first 32 bytes are consumed as a digest that has nothing to do with the token it precedes, and what reaches the parser is a `.tsr` truncated by 32. On the *unmutated* seed the imprint comparison therefore fails by construction, and every seed's first contribution is a rejection rather than a walk. The target is not useless — the DER structure is still what libFuzzer mutates from — but the corpus buys strictly less than a reader of `TARGETS` would assume, and nothing in the tree says so except that comment.
- Do: Build a seed corpus of `real_imprint ‖ token` pairs from the committed A25 bootstrap captures: for each capture, prepend the imprint the token actually carries, so the concatenation satisfies `split_digest` and reaches the signature and certificate path on the unmutated seed. Generate it the way the rest of the seed tree is generated rather than hand-adding a directory — `codec_fuzz.rs`'s `the_seed_tree_holds_nothing_but_the_generated_corpora` compares `testdata/fuzz-seeds/`'s directory set against `codec_fuzz::all_corpora()` and turns the ordinary suite red on a stray one, so a new corpus must be registered there in the same change. Keep the existing raw-`.tsr` seeding: a head-short input is a legitimate reject-path seed and dropping it would narrow the search. Then rewrite `scripts/fuzz.sh:98-103`'s CAVEAT to record what the pair corpus reaches and what it still does not.
- Accept:
  - A seed built from a committed capture reaches **past** the imprint comparison on the unmutated input, asserted by driving `drive_anchor_token` over it in an ordinary test and requiring a verdict that is not the imprint mismatch. The claim is the depth reached, so a row that merely asserts `Err` proves nothing.
  - The raw-`.tsr` seeds still fail **at** the imprint comparison, asserted in the same test, so the two seed kinds are shown to exercise different paths rather than assumed to.
  - `the_seed_tree_holds_nothing_but_the_generated_corpora` is green with the new corpus registered, and red with the corpus directory present but unregistered — both directions executed.
  - `corpus_dirs anchor_token` still resolves the A25 bootstrap root alongside the new corpus, and its missing-directory `die` is unchanged: a missing seed root is a broken lane, not a target without seeds.
  - `scripts/fuzz.sh`'s caveat names **A71** against a row that now exists, and `python3 scripts/check-traceability.py --task-citations` stays green — that check is what found this.
- Notes: the work is cheap and the finding is not. This row exists because a committed gate script pointed at an id no register defined, which is the defect class Q85 was written to close, found by the check on its first run rather than by review. Its size is dominated by the generator wiring, not by the corpus itself. Seeds only — no new fuzz target, so D61's budget arithmetic does not move.

### A72 — Two disagreeing TSA identity notions, and the over-counting one is the one that prints
- Milestone: M2
- Size: S
- Deps: after A31, A40; before U22 renders `distinct_tsas`
- Discovered by: **the D92 planner** (2026-08-06).
- Problem: the tree holds two incompatible answers to "is this one TSA or two". A31's `TsaSignerIdentity { issuer_der, serial }` (`crates/antseal-core/src/anchor/tsa.rs`) keys on the **certificate**; A40's `AnchorIdentity::TsaSigner { subject_dn_der }` (`crates/antseal-core/src/anchor/verdicts.rs`) keys on the **name**. A TSA that rotates its signing key therefore reads **2** at seal time and **1** at verify time, and the seal-side number is both the one that over-counts and the one U22's degradation report prints. `distinct_tsas` itself exists twice in `antseal-anchor` (`src/tsa.rs`, `src/submit.rs`), so "the seal-side number" is not one site either.
- Do: **rule which notion is canonical for counting independent anchors** — A31's certificate key, A40's DN key, or a third — and record the ruling, with its reason, at both definitions and at the surface U22 prints. The row hints a direction (*"the seal-side number is the one that over-counts"*) and stops short of choosing; the choice is this row's work and must not be smuggled in by a later lane that merely needs a number.
- Accept:
  - The ruling is recorded with its reason at `TsaSignerIdentity`, at `AnchorIdentity::TsaSigner` and at the surface U22 renders, so a reader arriving at any one of the three finds the same answer rather than a third.
  - The consequence lands with the ruling: whichever notion loses is removed, or kept with its scope stated at its own definition (*"this is not the anchor-independence count"*), so the two numbers can no longer be read as the same number.
  - A **key-rotation** case is exercised — one TSA name, two signer certificates — and asserted to yield the ruled count. It is shown **red against the losing notion** before it is trusted: a rotation fixture both notions score alike pins nothing, which is the failure mode A40's OTS half already had once.
  - The count U22 renders and the count the seal side computes agree on that case, asserted rather than reasoned about.
- Notes: Q88 asks the neighbouring question (*are two signers under one pinned root two identities?*) and A74 records a third consumer of the same confusion — `MIN_VERIFIED_TSA_TOKENS` compares against captures, not identities. A ruling here that ignores those two will be reopened by them; whether they are folded in or explicitly left out is part of the ruling.
- **Entry authored 2026-08-10 under Q134 from `TODO.md`'s A72 row alone — no other source existed.** Transcribed from the row: `Milestone` (its M2 section), `Size`, `Deps`, `Discovered by`, and the `Problem`'s two identity shapes. **Authored here, not transcribed: the whole `Do`, the whole `Accept` and the `Notes`** — the row names a defect and hints a direction but makes no choice, and it names no acceptance criterion at all. Per D115 §3.6 the `Do` is therefore *to make the choice*, not to implement a guess. The criterion was chosen as the smallest thing that would have caught the defect — a key-rotation case shown red against the losing notion — not derived from any spec line; the row cites no path, and the four identifiers named above were confirmed present in the tree on 2026-08-10, including the second `distinct_tsas`, which the row does not mention.

### A74 — `MIN_VERIFIED_TSA_TOKENS`'s doc advertises a one-line change that is not sufficient
- Milestone: M2
- Size: XS
- Deps: after A20
- Spec: Format registry §8 (the obligation the row names); MVP-SPEC.md lines 19, 34, 137, which the constant's own doc cites.
- Discovered by: **the D92 planner** (2026-08-06).
- Problem: `MIN_VERIFIED_TSA_TOKENS` (`crates/antseal-anchor/src/submit.rs`) is compared against `verified_tsa_count()` — **captures** — and not against `distinct_tsas()` — **identities**. At the shipped threshold of `1` the two cannot disagree, so nothing observable turns on it today. The hazard is the doc's own next sentence: it says the constant is named *"so that a future ≥2 policy is a one-line change"*, and that one line would accept **two tokens from one TSA as two anchors**, which is registry §8's named defect verbatim.
- Do: choose between the two available fixes and land one — **the doc fix** (qualify the "one-line change" so that raising the threshold is stated to require re-pointing the comparison, and scope the §8 claim to what is actually applied) or **the gate fix** (compare against the identity count now, making the threshold change genuinely one line). Do not land both halves of the sentence uncorrected while calling the row done; the row states a defect and no fix, and picking the fix is the work.
- Accept:
  - The chosen fix lands, and the doc at the constant no longer promises a sufficient one-line change unless it has been made sufficient.
  - The **reason** for the choice is recorded where the constant is defined, because the next reader is the one who raises the threshold.
  - If the gate fix is chosen, a case where captures and identities differ (two endpoints, one signer certificate) is asserted to abort at a threshold of 2 — shown red against the capture count first.
  - If the doc fix is chosen, the entry says plainly that the gate still counts captures, and A89 remains open and un-discharged by this row.
- Notes:
  - **The row's characterisation is slightly stronger than the doc.** The doc does not claim §8's obligation is applied against identities; it claims it is applied *"at the only place it can currently bite"*, meaning `verified_tsa_count` rather than `attempts.len()` — which is true. The defect worth fixing is the *advertisement*, not a false statement of fact, and scoping it that way is what keeps this XS.
  - **An instrument for the equivalence already exists**, which the row does not know: `crates/antseal-anchor/src/submit/tests.rs`'s `at_a_threshold_of_one_the_two_counts_cannot_disagree` asserts `MIN_VERIFIED_TSA_TOKENS == 1` over an entrust+sectigo capture pair that reads `verified_tsa_count() == 2, distinct_tsas() == 1` — the §8 case exactly — and says in its own doc comment that it exists *"so that raising the threshold has to confront the question deliberately"*. **A89 is nonetheless still open** and asks for something stronger (nothing *prevents* the gate reading the mixed scalar); this row must not be recorded as closing it.
- **Entry authored 2026-08-10 under Q134 from `TODO.md`'s A74 row alone — no other source existed.** Transcribed from the row: `Milestone` (its M2 section), `Size`, `Deps`, `Discovered by`, the `Spec`'s registry reference, and the `Problem`'s statement of the mismatch. **Authored here, not transcribed: the whole `Do`, the whole `Accept` and both `Notes` bullets** — the row is a defect statement with no imperative and no acceptance criterion, and the fix could be the doc or the gate. Per D115 §3.6 the `Do` is to choose between them. The two `Notes` bullets are findings of reading the two files on 2026-08-10 and are **not** in the row: the doc's §8 claim is narrower than the row says, and the equivalence already has a named test whose fixture is the §8 case.

### A76 — The recorded Bitcoin height is merge order, not evidence
- Milestone: M2
- Size: S
- Deps: after A14
- Spec: MVP-SPEC.md line 137 — *"**One headline**: 'Existed no later than \<earliest headline-eligible time\> (source)'"* — the line the row names.
- Discovered by: **the D92 planner** (2026-08-06).
- Problem: which Bitcoin height reaches the D79 upgrade group is `merged.added.first()` (`crates/antseal-anchor/src/ots/engine.rs`) — **the order attestations were merged in**, not which of them is earliest. The measured 2026-08-03 cycle is the counter-example rather than a hypothetical: one digest's three calendars landed in **three different blocks** (960767 / 960768 / 960771), so a bundle can record a later provable time than its own evidence supports, against line 137's *earliest* headline.
- Do: decide whether the engine selects the **earliest committing height** rather than the first merged one, and **price the extra header fetch** that selection costs — the decision and its price together, since the row's whole tension is that the correct answer is not free.
- Accept:
  - The decision is recorded with its reason and its measured price: how many additional header fetches the earliest-height rule costs on the committed three-block artifact, and against which endpoint policy (A16's must-agree pair is two requests per header, not one).
  - Whichever way it goes, a test drives the **three-block** case and asserts the recorded height. If earliest is chosen it is shown red against `first()` first; if `first()` is kept, the test pins that choice and the entry says out loud that the recorded height is not guaranteed to be the earliest.
  - The rendered headline and the recorded height are shown to agree on that case — line 137 is about what is *displayed*, and a correct height that renders through a different path buys nothing.
  - No frozen `anchor` vector moves, or if one must, it is classified before it is touched: a change in which height is recorded is a verifier change over frozen bytes, which is A108's subject and has no legal mechanism today.
- Notes: the three heights are the committed 2026-08-03 material, so this row has its fixture already and needs no new capture. D92 §5.5 records `merged.added.first()` as the *second* reason the block key fails as an identity; this row is the first reason's separate consequence — the recorded *time*, not the identity count — and closing one does not close the other.
- **Entry authored 2026-08-10 under Q134 from `TODO.md`'s A76 row alone — no other source existed.** Transcribed from the row: `Milestone` (its M2 section), `Size`, `Deps`, `Discovered by`, the `Spec` line 137 the row names, the `Problem`, and the `Do` — which the row supplies in full (*"decide whether the engine selects the earliest committing height, and price the extra header fetch"*). **Authored here, not transcribed: the whole `Accept` and the `Notes`** — the row names no acceptance criterion. It was chosen as the pair of things a decision of this shape can be checked against later (a recorded price, and a test over the artifact that motivated it), plus the frozen-vector clause, which is a consequence of A22 the row predates. `merged.added.first()` was confirmed present in `ots/engine.rs` on 2026-08-10; the line number D92's own row gives for it has since moved, so it is cited by name here.

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
    - **Answered by D102 §1, and the arithmetic here is a coincidence.** It is not `alloc_checked` and the step is not constant: `5 120 = 128 x size_of::<Frame>()`, the sixth rung of the `walk.rest` ladder `160 320 640 1280 2560 5120 10240 20480 40960`, and `5 120 = 5 x 1 024` is a numerological accident of 40 B frames. The peak **is** a function of the input — of its *depth*, which no length-based rule can see — and it reaches **40 960 B** on a 1 145 B artifact the suite requires to parse. The last sentence of this bullet was right and was obeyed: nothing was patched until D102 ruled.
- **RULED by [D102](../docs/decisions/D102-parser-structural-allocation-cost.md) (2026-08-07): NEITHER rule applies.** The peak is `walk.rest`, the parser's iterative work stack (`parse.rs`), which is **count-bounded** by `MAX_OTS_DEPTH` and has no length header to clamp against. `Frame` is **40 B** (measured), `Vec` doubles from capacity 4, and the 65th push reserves `128 x 40 = 5 120 B` — the constant this entry recorded four times and could not explain. D10 §4's clamp is a rule about **length headers**, so it never governed this site; the third class had never been written down. D58 §10.3 gains **rule 6** and the fuzz budget is **scoped, not widened**. The `Do` below is corrected in place because it led the other way; the strikethrough is deliberate, so the next reader sees the refutation rather than a clean text that looks like it was always right.
- Do: rule which applies to `.ots`, and do **not** patch either side by reflex. ~~The evidence leans one way: **D84 rules that anchor-artifact *internal* limits are "verifier policy over foreign formats", set at M2 against A25's real artifacts, and are explicitly *not* an exception to line 123 nor D10 format surface** — which says the target is asserting a format-level rule against a parser that was never built to it, and should use a budget bounded by `MAX_OTS_VALUE_BYTES`. The other option is live and must be argued rather than dismissed: tighten the executor so a running value cannot exceed the input that claimed it, which would make `.ots` obey the same clamp every other decoder does.~~ **Both struck options are refuted, measured (D102 §4).** *(a)* A budget bounded by `MAX_OTS_VALUE_BYTES` is the **worst** option on the table: `exec::apply` allocates **32 bytes** on the reproducer path and already satisfies `len + 32`, so it fixes nothing — and 32 768 B would be a **flat constant exemption hiding the entire D58 §3.1/§3.2 class** the target was built to catch. *(b)* Tightening the executor changes nothing for the same reason: the executor is not the violator. *(c)* Bounding the work stack by the input is arithmetically dead — a frame costs **one** op byte, not two, so `frames <= L` (measured 0.89 frames/byte), and an `L/2` rule would reject a legal artifact `tests.rs`'s own green `parser_is_iterative_at_max_depth` requires to parse; `frames <= L` still gives `bytes <= 40 L`. What lands instead is a **derived** structural bound with a `const` clause `<= MAX_OTS_BYTES`, so a future raise fails `cargo build`. The losing rule's site keeps a comment naming this task, as this entry always required.
- Accept:
  - One rule, stated once, with the other site referring to it.
  - ~~The committed reproducer below is a regression case that is **red before the ruling lands and green after**, whichever way it goes.~~ **Unsatisfiable as written and replaced (D102 §7).** The base64 block this entry carried was **328 characters decoding to 245 bytes**, sha1 `08df86ba…`, against a record claiming **248 bytes** and sha1 `b5aec24c…` — four characters lost in transcription, and nothing in the tree can regenerate the bytes the record named. The blob still tripped the budget but terminated at **`anchor-ots-unknown-op`**, a different path from any the four CI inputs are known to take, so the row was **unverifiable, not dead**: *"it still reproduces, so the record is fine"* is the wrong conclusion, because we cannot know what the recorded 248-byte input did and never will. **The blob is deleted.** Standing rule, general beyond this entry: **reproducer bytes are never carried in prose** — a base64 block in Markdown has no checksum anything verifies, and this one was wrong in both its length and its digest for a full wave while three CI runs cited it. Bytes that must be retained go to `testdata/` under the Q7 procedure with a manifest digest (`docs/testing/fuzzing.md` §4 step 4's other arm).
  - **Replacement row: the regression case is generated, not transcribed.** The primary witness is a **142-byte, 65-op chain** built by `anchor::testing::ots_writer` — the minimal structural witness of the boundary, red at depth 65 and green at 64, whose construction states its own cause. Measured: **peak 5 120 B against the pre-ruling cap of 4 238 B (red), against rule 6's scoped cap of 22 528 B (green)**. It lives in `crates/antseal-core/tests/anchor_ots_alloc.rs`, which asserts **both** directions, so the row cannot go vacuous.
  - ~~If the executor is tightened, a real `.ots` from `testdata/anchors/A25-bootstrap/` still parses — the cap must not reject honest artifacts, which is the failure mode D54's "at least one calendar commits" rule already had to avoid once.~~ **Kept and strengthened (D102 §7).** The executor is *not* tightened, so parsing is no longer the bar: `rust-opentimestamps-LARGE_TEST.ots` must cost **exactly 5 120 B** — the identical allocation all four CI failures made — asserted at equality in the same test binary. That identity is the decisive measurement: the honest mainnet artifact and the hostile witness allocate the same bytes, and the pre-ruling guard's verdict differed between them only because 1 768 > 1 024.
- The four CI inputs, retained as what they are — run ids, lengths and the measured peak, never as bytes (D102 §7 row 2):

  | run | date | input | relative cap (`len + 4096`) | measured peak |
  | --- | --- | --- | --- | --- |
  | 31086210534 | 2026-08-06 | 248 B | 4 344 B | 5 120 B |
  | 31127730409 | 2026-08-06 (`d82f72e`) | 744 B | 4 840 B | 5 120 B |
  | 31128531727 | 2026-08-06 | 988 B | 5 084 B | 5 120 B |
  | 31167014974 | 2026-08-07 | 638 B | 4 734 B | 5 120 B |

  Four different inputs, four different caps, **one allocation**. libFuzzer minimises for crash preservation rather than for size, so every one of them is far above the real boundary — the smallest violator is **142 B**, and any future triage that starts from the 248-byte blob starts three layers away from the cause.
- Notes: the guard did exactly its job, and then the ruling found the guard was the thing in the wrong place — those are not in tension. This is the first defect the M2 fuzz targets have returned, and it arrived on the target's **first remote run**, which is the standing lesson that a lane never executed on the remote is not evidence, restated for fuzzing. `anchor_token` is the same class of site and was scoped in the same change **while still green** (D102 §6), because "it has never gone red" is exactly what was true of `anchor_ots` until it ran.

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
- Accept: a work whose only anchor is unreadable renders under `NagState::Unreadable`, whose `nags()` is **false** — D100 R7; the existing pin is **updated** in the same change rather than deleted, so the old behaviour stays visible as the thing that was fixed.
- **Accept row corrected 2026-08-07 by D100, in the doing.** The original row said the work *"nags"*, and that was wrong. `nags()` drives the two-line PENDING/`--upgrade` block: for a work whose only anchor is unreadable the count reads **0** and the instruction is **unsatisfiable**, which is exactly what the committed counter-argument at `engine/tests.rs:552-570` refuses — and it is right to refuse it. A102 needed the **name**, not the boolean. What the fix owes the user is a rendered line whose next step *is* satisfiable (`antseal status <id>`), which is what landed. Three of the counter-test's four assertions stand untouched; only `AttestedOnly` → `Unreadable` moved. `nags()` also stopped being a `matches!(…)` — a shape that silently defaults a new variant — and is now a wildcard-free `match`.
- **EXECUTED wave 9** (2026-08-07), same commit as A103 and U65.

### A103 — `NagState` has no `name()`, so its kebab table lives in the CLI
- Milestone: M2
- Size: XS
- Deps: A15, U25; D98 rider 3b
- Discovered by: **the U25 lane** (2026-08-07).
- Problem: D98 rider 3b puts `NagState`'s kebab name into `list`'s `--json` output, and `NagState` has no `name()` — so the table (`anchored` / `only-pending-ots` / `attested-only` / `unanchored`) now lives in `listing.rs`, in a different crate from the enum it names. That is a **second table for one taxonomy**, which is precisely the shape D98 rejected its option (c) for: a projection maintained beside a definition desynchronises silently, because nothing compares them. Option (c) was killed at the level of *states*; this is the same defect at the level of *names*, and it is smaller only because a wrong name is easier to notice than a wrong verdict.
- Do: put `name()` on the enum in `antseal-anchor`, beside the variants, and have `listing.rs` call it. A new variant then cannot reach the JSON without being given a name.
- Accept: adding a `NagState` variant without giving it a name is a compile error, not a silently wrong string; `listing.rs` holds no spelling of any variant; and `NagState::ALL` plus a reachability test prove every variant is actually **constructed** by the classifier.
- **Ordering and rationale corrected 2026-08-07 by D100.** This entry was credited with being the change that makes a fifth variant safe to add, and it is not — the compile-time forcing already existed at `listing.rs:293-301`, so A103 lands in the **same commit** as A102 rather than before it. The hazard A103 does close is different and worse: `work_status`'s classifier is an **if/else chain, not a match**, so a new variant can be *named and never constructed*, silently, with every naming test green. Hence `ALL` + the reachability row, whose planted fault (deleting the `has_unreadable` branch) reddens the reachability assertion while the naming assertion stays green — which is the hole, demonstrated.
- **EXECUTED wave 9** (2026-08-07).

### A104 — A repeated upgrade re-splices the same attestation and grows the stored `.ots`
- Milestone: M2
- Size: S
- Deps: A14, A15; U23, U24
- Discovered by: **the U23 lane** (2026-08-07); fixed by **the U24 lane** the same day, because U24's hook is what turned it from a slow leak into a per-invocation one.
- Problem: a repeated `--upgrade` re-spliced the same attestation and grew the stored `.ots` **monotonically**, bounded only by `MAX_OTS_BYTES` (1 MiB). The mechanism, end to end: `splice_sibling_before` is a **pure insertion**, so the pending branch survives the merge; the next run's `pending_refs` therefore finds the same attestation again; `added_bitcoin` is a **multiset** difference (`upgrade.rs:413-432`), so the duplicate counts as *added* and `changed` goes true; and because `upgrade.is_some()` by then, `confirm_header` is skipped, so the old group is re-recorded beside a grown artifact. Nothing renders wrong — the state stays `attested` throughout — the artifact simply gains one spliced attestation per run. U24's hook would have made that **per invocation, on every work**, which is why the fix could not wait.
- Do: **the first proposed cut was wrong, and was not decidable from the artifact.** U23 suggested skipping the merge when the artifact is "already attested at all". `OtsArtifact` is a flat attestation list with **no parent links**, and a real upgrade body carries ops, so the Bitcoin attestation derives a *different* value from the pending commitment it descends from — the coarse test cannot even be evaluated. Worse, it is actively wrong: A14 deliberately permits a **second calendar's** attestation to merge later without a second header fetch, so "already attested" would discard real evidence for ever. It was planted as a fault and refuted by its first row.
- Accept: **DONE 2026-08-07 (U24 lane).** The landed fix keys on the **splice itself** rather than on the artifact's state: `splice_sibling_before` emits `0xff ‖ body` immediately before the attestation, so a repeat is that literal prefix and nothing else. `ots/upgrade.rs::already_merged(stored, target, body)` tests for exactly that, called in `upgrade_one_anchor` between `current_ref` and `merge_upgrade` — checked against `current`, because an earlier merge in the same loop has already moved the offsets — and emits `UpgradeNote::AlreadyMerged`. **A calendar answering with a different body still merges**: the rule refuses repetition, never evidence. Three unit rows over the real `MERGED_A` / `UPGRADE_A_ALICE` / `UPGRADE_A_BOB` fixtures; the characterisation test written at discovery turned green.
- Notes: the transferable lesson is the one the refuted cut teaches — a de-duplication rule must be keyed on the **operation that would be repeated**, not on the state that operation produces, because the state is reachable by other routes and those routes are the evidence the rule was meant to preserve. U59 records what this fix cannot reach: `already_merged` needs the poll's body, so it stops the growth without stopping the poll.

### A105 — A25 Accept row 2 is pinned only as the anti-vacuity arm of two tamper tests
- Milestone: M2
- Size: XS
- Deps: after A25
- Spec: Anchor smoke tests (MVP-SPEC.md line 173) — reached through the matrix row that already exists for this property, `docs/testing/verification-matrix.md` V7.2, whose `spec line` cell reads 173; the row itself cites no spec line.
- Discovered by: **the A25 lane** (2026-08-07), in the per-Accept-row adjudication recorded in A25's entry.
- Problem: A25's Accept row 2 — *"Both real TSA tokens reach `proven` against the pinned store"* — has **no test named for it**. The two assertions the row cites are the *anti-vacuity arms* of tamper tests: `verdicts/tests.rs:1205-1208` (`FREETSA`, inside `a_token_whose_cms_signature_fails_never_reaches_chain_classification`) and `:1313-1316` (`DIGICERT`, inside `a_malformed_bundle_intermediate_is_invalid_with_a5s_der_code`). The pin is **real** — both go through `evaluate_tsa_artifact` against `TsaRootStore::pinned()` and the build reddens if either token stops reaching `proven` — but it is a side condition of tests named for something else, so a future tamper-test rewrite can drop an arm and take an M2 milestone criterion with it, silently. **The file built to answer "where is this tested?" says it is not**: matrix row `V7.2` (`docs/testing/verification-matrix.md:117`) restates Accept row 2 exactly, is owned by `A25 + A7` at M2, and its `tests / evidence` cell reads `NONE at M0` with status `deferred`.
- Do: give the property its own named home at the **verdict** level, and name it in `V7.2`. Do **not** write a chain-level test: `chain.rs` already names four over real tokens — `real_digicert_token_reaches_proven_with_the_cross_cert_present` (`:1230`), `..._with_the_cross_cert_removed` (`:1244`), `real_sectigo_token_reaches_proven_with_the_cross_cert_present` (`:1277`) and `token_carrying_its_own_self_signed_root_still_reaches_proven` (`:1292`, freetsa + dfn) — and they call `validate_token_chain`/`validate_chain`, not `evaluate_tsa_artifact`, so they cover T3 and neither T1 nor T2. Keep both anti-vacuity arms exactly where they are; they serve their own tests' non-vacuity and deleting them would weaken two tamper tests to buy nothing.
- Accept:
  - A test **named for the property** asserts that both real captures reach `AnchorState::Proven` through `evaluate_tsa_artifact` against `TsaRootStore::pinned()` at `AFTER_CAPTURE` — `FREETSA` (from `anchor::testing::tamper_rows`) and `DIGICERT` (`verdicts/tests.rs:59`), over the real 2026-08-02 tokens, not synthetic ones.
  - It is shown **red** by a planted fault before it is trusted — dropping a pinned root, or moving `verify_at` outside the chain's validity, must redden it. A test whose only evidence is that nothing broke is the shape this project keeps finding in other people's suites.
  - Both anti-vacuity arms at `:1205-1208` and `:1313-1316` are **still present and still asserting**, so the new test is an additional home and not a migration.
  - Matrix row `V7.2`'s `tests / evidence` cell names the new test **by name, never by line number**, and `python3 scripts/check-traceability.py --matrix` resolves it. **Corrected 2026-08-11.** The clause that stood here — *"Whether `V7.2`'s status may move `deferred` → `covered` depends on `A25`'s row-1 script, which is A25's, not this row's"* — named the **wrong Accept row**, and so told this row's executor it was blocked on work that does not block it. `V7.2` restates A25's Accept **row 2**, which **D118 §1.6 adjudicated SATISFIED** on its own evidence — the real 2026-08-02 FreeTSA and DigiCert captures against `TsaRootStore::pinned()` — with no dependence on the missing `scripts/anchor-smoke` entry point at all. That script is A25's Accept **row 1** (adjudicated PARTIAL) and it blocks **`V7.1`**, not this row; it is `A127`'s subject. `V7.2` already reads `covered`, with this row's asymmetry recorded as its limitation, so what this row owes the cell is the new test's **name**, not a status move — and nothing in A25 gates that. The clause was transcribed verbatim from D115 §4.1, which carried the same error and is corrected under D117 in the same act.
- Notes:
  - `V7.2` is one of **11** rows `--matrix --milestone M2` names as `deferred` at or before M2 (`V2.3`, `V3.5`, `V6.1`–`V6.6`, `V7.1`–`V7.3`), so this row does not by itself unblock the M2 matrix gate and must not be described as if it did. `ACCEPTED_NON_COVERED` is empty, so nothing is currently exempted. The lane runs `check-traceability.py` with no flags, and `--milestone` defaults to `CURRENT_MILESTONE`, which is **`"M0"`** — so today's green says nothing whatever about the M2 review, and will not until that constant moves.
  - **The row says "the two assertions" and there are more, on one side only.** Measured 2026-08-10 over every `AnchorState::Proven` assertion in `verdicts/tests.rs`: `DIGICERT` reaches `proven` through `evaluate_tsa_artifact` against the pinned store at **three** further places — `:1250` (the baseline arm of `one_capture_two_verify_times_flips_proven_and_since_expired`) and `:1349` (`a_tsa_anchor_records_the_chain_refutation_best_evidence_discarded`, with a recorded anomaly), plus the arm the row cites. **`FREETSA` reaches it at exactly one place, `:1205-1208`** — the arm the row cites. So the exposure is asymmetric: deleting the DigiCert arm would leave the DigiCert half asserted elsewhere, while deleting the FreeTSA arm removes the FreeTSA half from the tree entirely. That strengthens the row rather than weakening it, and it means the new test must carry **both** tokens even though only one of them is genuinely single-homed.
- **Entry authored 2026-08-10 under Q134 from `TODO.md`'s A105 row, D115 §4.1's reconstruction, and the files both name.** Transcribed from the row: `Milestone` (its M2 section), `Size`, `Deps`, `Discovered by`, and the `Problem`'s first two sentences. **Authored here, not transcribed: the whole `Do`, the whole `Accept`, the `Spec` line and both `Notes` bullets** — the row states a defect and a rationale and names no acceptance criterion at all. The criterion was chosen by finding where the tree already asks this question and finding it unanswered (`V7.2`), rather than by inventing a test shape; the "do not write a chain-level test" clause and the eleven-row caveat are findings of that search and are **not** in the row. **Two corrections to D115 §4.1, both measured here on 2026-08-10**: it says `chain.rs` names **three** chain-level `proven` tests over real tokens and the tree has **four** (`real_sectigo_token_reaches_proven_with_the_cross_cert_present` at `:1277` is of exactly the same shape and was missed); and its restatement of the row's *"the two assertions"* is an undercount, per the second `Notes` bullet. The two line citations the row gives, and A25's Accept row 2 wording, were re-verified against the working tree and are exact.

### A106 — The F4 registry misattributes A48's re-measurement to A25, and the fix landed in one file of two
- Milestone: M2
- Size: XS
- Deps: after A48
- Discovered by: **the A25 lane** (2026-08-07).
- Problem: `docs/format/anchor-artifact-limits.md` said the bootstrapped `.ots` rows were **A25's** to re-measure, in two places — `:251` (*"A25 owes that re-measurement"*) and `:258` (*"**A25 must re-measure them against the real fixture and append**"*). The task is **A48**, which was written for exactly that and lists A25 only as a dependency; A25's obligation was the *capture*, discharged 2026-08-03T09:03Z. Separately, five of the six rows at `:221-226` still cited `rust-opentimestamps-LARGE_TEST.ots`, a third-party crate's test constant, in their `measured against` cell — the citation A48 exists to retire. **The A25 lane corrected the attribution in `testdata/anchors/A25-bootstrap/upgraded/PROVENANCE.md` and nowhere else**, because the format document was another lane's file, so a reader arriving at the registry first was misdirected for three days.
- Do: correct both attributions in `docs/format/anchor-artifact-limits.md`, and re-point the `measured against` cells of the rows that cite the third-party crate. **Five of the six, not all six**: `MAX_OTS_BRANCH_WIDTH` cites `merged-A.ots` and is not in scope. Scoped from `TODO.md`, which names `:251`, `:258` and `:221-226`; two other rows describe A106 differently and neither is authoritative — `tasks/A.md` A109's Notes call it *"the §5a heading capture and the wasm32 asymmetry"* and `tasks/Q.md:1544` calls it *"scoped to two provenance citations"*.
- Accept:
  - Neither `:251` nor `:258` attributes the re-measurement to A25, and the correction states that it previously lived in `PROVENANCE.md` alone.
  - No `measured against` cell cites the third-party crate as a **bootstrap stand-in**; a cell that still cites it says why it is binding on its own merits.
  - `MAX_OTS_BRANCH_WIDTH`'s provenance is unchanged.
- **DONE 2026-08-10, executed with A48/A63/A113 in one pass** — the attribution repair is a rewrite of the same paragraph A48's re-measurement rewrites, and splitting them would have produced two lanes editing one paragraph. Both citations corrected and the three-day one-file asymmetry recorded in the document as the reason this was a row. Three rows moved off the crate fixture (ops 100 → **244**, depth 67 → **85**, attestations 4 → **6**); **two did not** — `MAX_OTS_OPERAND_BYTES` and `MAX_OTS_VALUE_BYTES` measure 174 B and 210 B here against antseal's own 89 B and 125 B, so the crate fixture is still the **binding** sample and is kept and demoted per A48's Accept row 3 rather than retired.
- Notes: the transferable half is the asymmetry, not the misattribution. A correction that lands in one of two places that state the same fact is a correction that has not happened, and it is *invisible* — the corrected file reads as authoritative to anyone who opens it, and nothing in the tree relates the two. **The §5a-heading and wasm32-asymmetry fallout named in A109's Notes is NOT covered here** and remains unowned; it is described as a candidate row by the wave-11 lane.

### A107 — Decide whether `anchor` vectors carry the recorded capture instant or a normalised one
- Milestone: M2
- Size: S
- Deps: before A22 (D101)
- Discovered by: **D101** (2026-08-07).
- Problem: `D60-CAPTURE.log` headlines a **129-second clock skew** on the capture host, and D101 puts `fetch_date` inside the frozen `expect`. Whichever value the first `anchor` vector carries is permanent, so the choice — recorded instant, normalised instant, or a synthetic constant — has to be made before the freeze rather than discovered after it.
- Do: rule which instant a vector's `fetch_date` carries, per artifact, and say so where the vector is read.
- Accept: the rule is stated in the vector kind's own README and the frozen document's `description`, and each case's value is traceable to a committed capture-log line.
- **RULED 2026-08-09 by [D103](../docs/decisions/D103-upgraded-ots-vector-provenance.md) RULING 8, and executed in A22's vector. Recorded instants, per artifact, from that artifact's own capture-log line — never normalised, never synthetic, never invented later.** The frozen values: cases 1 and 2 take **1 785 698 419** and **1 785 698 426** from the `D60-CAPTURE.log` freetsa and digicert rows; cases 4/5/6 take **1 786 098 992**, `utc_start` of the 2026-08-07 header campaign; cases 3 and 7 have no upgrade group and render `null`.
- **Three of this row's own premises were false, and the correction to the fourth would have entered a frozen file.**
  - **The skew is 128 s, not 129, for both tokens A22 freezes.** `openssl ts -reply -text` against each token, differenced against its own log row: freetsa `utc=2026-08-02T19:20:19Z` (1 785 698 419) vs `genTime` 19:22:27Z (1 785 698 547); digicert 19:20:26Z (1 785 698 426) vs 19:22:34Z (1 785 698 554). **128 s each.** The log's *"129 s slow"* is the **mode of three probe offsets** (+129/+128/+129) to unrelated hosts, quoted as though it were a property of the tokens. D101 §7.4 instructed the `description` to say *"~129 s"* — it carries **no `RULING` marker** (D101's markers run 6a → 6b → 6c → 7, and §7.4 sits inside Ruling 6's section), so this was genuinely open rather than pre-ruled, and the guidance that looked like a ruling would have put a wrong number in a forever-frozen file.
  - **No artifact carries a `fetch_date` at all.** It is a free constructor argument (`TsaArtifactView::from_parts`, `OtsUpgrade::new`), so nothing "inherits" a skew from the log; a case with no upgrade group renders `null` whatever the host clock did.
  - **`fetch_date_unix` appeared in zero `.rs` files** when this row was written — it was a proposed JSON key for a vector that did not yet exist.
- **Why normalisation is refused, and the reason D101 §7.4 did not have.** Normalising (+128 s) destroys the one committed artifact demonstrating that `gen_time <= fetch_date` is **false in reality**, which is A32's whole content. And decisively: **the raw HTTP `Date` headers were never retained.** Only the derived offsets survive, as prose at `D60-CAPTURE.log:21-23`, so a "normalised" value would be re-derived from a sentence — which is exactly what the vector regime exists to stop. The synthetic constant is refused twice over: `ots_writer::FETCH_DATE = 1_785_000_100` is **eight days before the tokens were issued**, it lives in `anchor::testing` which D103 RULING 7 forbids the executor to name, and it would make `fetch_date` the only field in a document of recorded artifacts that records nothing.
- **Cases 4/5/6 take the header campaign's instant, not the upgrade bodies'.** The group is a reconstruction from two campaigns (bodies 2026-08-03T09:03Z, headers 2026-08-07T10:36Z); D79 makes the upgrade group all-or-nothing and `OtsUpgrade::fetch_date` documents itself as *"when the upgrade/header was fetched"* — both — so the group did not exist until its last component did. Rejected: 1 785 747 818, which would date the group four days **before** the header it carries.
- Notes: **the capture log is not edited** (D103 §4.4) — a capture log records what was observed at capture time, and the per-token correction lives in the vector's `description` and in `testdata/vectors/v1/anchor/README.md`. Whether `D60-CAPTURE.log`'s headline sentence should be softened is explicitly **not** ruled and is nobody's yet.

### A108 — Name the three events that could need D94's verdict-event hatch, in A26's `Do`
- Milestone: M2
- Size: S
- Deps: after A22 (D101)
- Spec: Anchoring — RFC 3161, the pinned TSA root store (MVP-SPEC.md line 109); D101 §4.3 RULING 3b/3c; D94 Ruling 4's three-class event vocabulary (D94 §2 — the tree's existing citations, including `scripts/vector-freeze.sh` and `FROZEN.sha256`, spell it *"D94 §2a"*, which is the neighbouring subsection).
- Discovered by: **D101** (2026-08-07), §4.3.
- Problem: a frozen `anchor` vector **cannot legally move**. `verdict_event_ok` refuses anything without `/report/` in its path as its first check (`scripts/vector-freeze.sh`), so D94's verdict-event escape does not reach the `anchor` kind. D101 §4.3 lists the only three events that could ever require one — an **A26 root removal** (a compromised CA), a **signer-DN rendering** change, and a **root append that gives a pinned token a second valid path** — and RULING 3b deliberately declined to build the hatch, on D94's own finding that *"an unexercised instrument goes blind"*. RULING 3c instead requires the three be **named** in two places, so the event discovers the gap rather than a red lane discovering it at merge. One of the three is **not a store event at all** — a DN *rendering* change is a verifier change (D101 §3.4) — which is why it sits oddly in a root-store task's `Do` and why naming it there is the point rather than an oversight.
- Do: add the bullet RULING 3c asks for to **A26's `Do`**, beside the RULING 3a bullet already there, naming all three events, saying which of them A26 itself can cause (removal, append) and which it cannot (rendering), and pointing at D101 §4.3 as the list's home and at `verdict_event_ok` as where a hatch would be extended if one of them is ever proposed. **The freeze-manifest half is already done** — `testdata/vectors/v1/FROZEN.sha256:82-90`, the paragraph beside `#! kind anchor A22` at `:91`, landed with A22 and already names all three — so this row's remaining scope is the A26 bullet plus the correction below. A26 is a **closed** row (✅ 2026-08-03); amending its `Do` is correct here and precedented in that same `Do` (*"**Added 2026-08-09 (D101 §4.2, RULING 3a):**"*), and A26's milestone line marks it `continuous` thereafter.
- Accept:
  - A26's `Do` carries the bullet, naming all three events and distinguishing the two A26 can cause from the one it cannot.
  - The bullet cites **D101 §4.3** by section and `scripts/vector-freeze.sh`'s `verdict_event_ok` by name — **never by line number**, because both move. They have already moved: D101 §4.3 cites `:99-101` for that check and D115 §4.2 cites `:98-99`; measured 2026-08-10 the function opens at `:103` and its `/report/` refusal is `:114-117`. Two stale citations of one check are the argument for the rule.
  - The bullet does **not** cite `MVP-SPEC.md` line 123 as the authority for the vector's immutability. Line 123 is the ***released*-conditioned compatibility rule**; the freeze's authority is **Q6's own act**. Q132 closed four sites that got this wrong and **Q148** is open over at least nine more — this bullet must not become the tenth.
  - The blast-radius sentence is corrected wherever this row's own correction lands (see `Notes`): **one** frozen file moves, not two, and it is the one **without** a hatch.
  - `scripts/vector-freeze.sh` is **not** modified and `verdict_event_ok` is **not** extended — D101 RULING 3b stands, and this row names rather than builds. Zero frozen bytes move.
- Notes:
  - **This row's own blast-radius claim is false and was measured false on 2026-08-10.** The row says a signer-DN rendering change *"would move two frozen files, one with a hatch and one without"*, following D101 §3.4. Measured: `testdata/vectors/v1/anchor/anchor.json` renders signer DNs in `expect.cases[].source.identity` for its two `proven` TSA cases (`tsa-freetsa-p384`, `tsa-digicert-rsa`), and `testdata/vectors/v1/report/verification-reports.json`'s three anchor verdicts — its only ones, at `expect.cases[19].report.anchors[0..2]` — are **all** `"state": "invalid"` with `"source": null` and `"verified_time_unix": null`. The report vectors kept D94's synthetic bytes; synthetic bytes render `invalid`; an `invalid` anchor carries no identity (`verdicts/tests.rs:1199`, and `anchor.json`'s own `ots-wrong-seal` case, which is `invalid` with `source: null`). By the same mechanism a root removal and a root append cannot move an anchor that is already `invalid` before chain classification, so **all three events move exactly one frozen file and none moves a `report/` vector**. The asymmetry is not "one hatched, one not" — it is that **the only file that moves is unhatched**, which strengthens RULING 3c and leaves RULING 3b untouched.
  - **Correcting D101 §3.4's body is blocked by Q122**, which asks whether a *resolved* decision's body may take a dated correction or whether only its register row moves. Until Q122 rules, the correction lives here and in the A26 bullet. Do not silently edit D101.
  - **Size stays `S` as the row declares it.** Measured remainder after the manifest half landed is **XS** — one bullet plus the correction. Recorded, not applied: `Size` lives in the row and the entry both, and two homes disagreeing about one value is the defect class this tracker keeps finding.
- **Entry authored 2026-08-10 under Q134 from `TODO.md`'s A108 row, D115 §4.2's reconstruction, D101 §3.4/§4.3, A26's entry and the frozen files.** Transcribed from the row: `Milestone` (its M2 section), `Size`, `Deps`, `Discovered by`, and the `Do`'s opening imperative. **Authored here, not transcribed: the whole `Accept`, the `Spec` line and all three `Notes` bullets** — the row names no acceptance criterion and does not enumerate the three events it asks to have named. The three events are D101 §4.3's table verbatim, not a reconstruction. The "manifest half already landed" finding comes from A26's own `Notes` and was confirmed against `testdata/vectors/v1/FROZEN.sha256:82-90`; the blast-radius correction is a measurement of the two frozen documents. Re-verified against the working tree on 2026-08-10, which found two things D115 §4.2 did not: its `verdict_event_ok` line citation is stale (recorded in the `Accept`), and D94's three-class vocabulary is Ruling 4 in §2 rather than §2a, which is how every existing citation in the tree spells it.

### A109 — Decide the `MAX_OTS_DEPTH` lowering before F4's window closes at first release
- Milestone: M2
- Size: S
- Deps: before Q30/Q31 (D102)
- Discovered by: **D102** (2026-08-07).
- Problem: F4's raise-only monotonicity binds *after* M2's first release, so the window to **lower** `MAX_OTS_DEPTH` from 1 024 is open now and closes permanently at that point. D102 declined the lowering but recorded the option because it expires rather than because it was rejected. An expiring option that is never decided is decided by default, which is the one way it cannot be reviewed.
- Do: decide deliberately, before the first release that verifies real anchors, whether the constant is lowered — and record the decision either way, so the `lowered: never` cell is a statement rather than an omission.
- Accept: a dated ruling exists before Q30/Q31; if the constant moves, the F4 registry's `lowered` cell and §6 carry the note the Update rule prescribes; if it does not, the reason is recorded against the numbers rather than against a preference.
- **RULED 2026-08-09 by [D104](../docs/decisions/D104-max-ots-depth-lowering-window.md): KEEP 1 024, and the option was EMPTY rather than declined. No production constant moved.** The structural cost is `next_power_of_two(MAX_OTS_DEPTH) × size_of::<Frame>()`, so **every cap in (512, 1 024] reserves identical bytes on every target** while accepting strictly fewer artifacts — a strict loss. The first value that saves anything is **512**, and the tree's own committed margin discipline (`ots/tests.rs:280`, *"every measured quantity is far under its cap; that is what the F4 margins claim, asserted rather than trusted"*) demands `MAX_OTS_DEPTH ≥ 8 × deepest real artifact` = **680**. **The admissible band `[680, 1 024]` and the cost-effective band `≤ 512` are disjoint**, every admissible cap costs the identical 40 960 B, and **1 024 therefore weakly dominates every admissible value** — the cost-minimal admissible cap, not a generous guess. The conclusion is invariant to the depth dispute: it holds at 85, at 73 and at the discredited 67 (floor 536 > 512), and would move only if the deepest real artifact were ≤ 64.
- **The window is correctly filed, and this row's four load-bearing numbers were all wrong.**
  - **The filing survives.** F4 sentence 1 governs *when* a lowering is allowed: sentence 2 is the harm model and names a release, and sentence 3's *"format-version event"* would contradict **D84 §3** (*"the numeric limits are not format surface"*) if applied before any release exists. The `§5a` Update rule that reads like an unconditional prohibition is **A27's, commit `1620543`, 2026-07-28** — a registry-keeping *procedure*, not a permission — and D102's heading was inserted above it, filing two A27 paragraphs under a banner reading *"Added 2026-08-07 by D102"*.
  - **"the real mainnet proof is depth 67" is false twice.** 67 is `rust-opentimestamps-LARGE_TEST.ots`, a third-party crate's January-2017 test constant that **A48** exists to retire. Antseal's own upgrade fragments measure 67/70/73, and the artifact a verifier actually parses — the spliced merge A22 froze — is **depth 85**, because depth is *attachment depth plus fragment depth*. The margin is **12.05×**, not the registry's 15.28×.
  - **"40 960 B in a browser tab" applies the wrong number to the venue it invokes.** `OTS_FRAME_BYTES` is `size_of::<Frame>()`: 40 on x86-64, **24 on wasm32**. The browser costs **24 576 B** (32 768 B total against 53 248 B native) and `limits.rs:155-157` already says so — the tab is the **cheapest** place this parser runs, not the constrained one.
  - **The cost is a rejection threshold, not bookkeeping bytes**, and **D102's *"available today at no cost"* is refuted**: a lowering still spends Q27's ceremony and burns `lowered: never` permanently, in the one table whose stated purpose is answering *"has this ever been lowered?"*.
- Notes: the registry repairs were **handed off, not absorbed** — the depth-67 citation and the recomputed margin are **A48**'s (artifact from **A63**), the §5a heading capture and the wasm32 asymmetry are **A106**'s, cross-checking the `margin` column is **A113**, and §6's total changelog silence is **Q126**, which conditions any future exercise of the window this ruling leaves open. Also falsified in passing: A48's own `Do` (`"every margin is ≥ 15×"`) and `D102:517-519`'s claim that the alloc test binary runs on wasm32 — `scripts/wasm-tests.sh` is `--lib`.

### A110 — The DER half of the F4 registry has no rows at all
- Milestone: M2
- Size: S
- Deps: after A5 (D102)
- Discovered by: **the D102 lane** (2026-08-07).
- Problem: `MAX_CHAIN_CERTS`, `MAX_CHAIN_CERT_BYTES` and `MAX_SIGNED_ATTRS` are declared in `crates/antseal-core/src/anchor/caps.rs` and documented there as belonging to the F4 registry, but `docs/format/anchor-artifact-limits.md` §5 has **no rows for them**. Pre-existing; minting the rows is A5's.
- Do: add the missing §5 rows with every column the existing rows carry, and reconcile the paragraph that describes the gap with the gap it describes.
- Accept: every limit `caps.rs` names as an F4 limit has a §5 row; the `structural cost` cells are derived and asserted, not typed; and a limit declared without a row reddens something.
- **Scope corrected 2026-08-09 by the wave-10 recon; still open. Four findings, and the count in the title was one of them.**
  - **The gap is FOUR, not three.** `caps.rs:22-24` names the fourth itself — *"The F4 registry rows for these three, **and for the depth limit that is not declared here**, are in D60 §6"* — and §4's open-limits table lists four A5 leaves, all four without §5 rows.
  - **"the tie finding has no registry home" is false.** The registry already states it in prose at `:327-329`: *"its certificate-bag reservation is `8 x 512 = 4 096 B`, exactly the fuzz guard's fixed slack"*. What is missing is a **table row**, not a home.
  - **"D102's structural-cost column could not be applied to the DER half" is vacuous.** The column was added to all eight existing rows, every one an A11/A42 `.ots` row, so there were no DER rows to skip.
  - **The registry contradicts itself inside the cited paragraph**: `:323` says *"Two rows this table still owes"* and `:324-325` then names three.
- **Two constraints for whoever takes it.** The new rows must **not** copy the `next_pow2(limit) × size_of::<T>()` shape the `.ots` rows use: the DER containers reserve with `Vec::with_capacity` **after** the count check and never regrow, so their cells read plain `limit × size_of::<T>()`. Derived values: `MAX_CHAIN_CERTS` **4 288 B direct** (`8 × (512 + 24)`) **+ 3 200 B indirect**, because `MAX_PATH_NODES = MAX_CHAIN_CERTS + MAX_INTERMEDIATE_COUNT + 1` moves with it (`25 × 128`); `MAX_CHAIN_CERT_BYTES` **none**, checked after `to_der()`; `MAX_SIGNED_ATTRS` **none** — and that last is a *measured* finding recorded at `caps.rs:140-149`, not an omission, since the attribute set is already decoded inside `SignerInfo` when the count check rejects.
- Notes: **why three checkers all missed it**, which is the transferable half. The `traceability` CI job never reads `caps.rs` at all; `ots_limits_match_the_f4_registry` builds its needle as `| \`{name}\` | A11 | {value} |` and so **hardcodes the owner cell to `A11`**, which no DER row could ever match; and `caps.rs`'s own `f4_registry_values` compares the constants against literals **in the same file** while its doc claims the registry records them. That is A21's shape exactly — three instruments, none of which can see the thing they are collectively cited for.

### A111 — `chain_certificates` reserves per bag entry, not per certificate
- Milestone: M2
- Size: S
- Deps: after A5, A110 (D102)
- Discovered by: **the D102 lane** (2026-08-07).
- Problem: `tsa::chain_certificates` reserves `size_of::<x509_cert::Certificate>()` for every **bag entry**, including a `[3] other` entry whose wire form is ~8 bytes — 512 B of reservation for 8 bytes of input. Latent allocation amplification on the DER path.
- Do: reserve on the count of `CertificateChoices::Certificate(_)` rather than on the count of bag entries, and land an instrument that can see the difference.
- Accept: an 8-entry all-`[3] other` bag reserves ~0 rather than 4 288 B, asserted by a row that is red before the fix and green after; the existing worst case (8 real certificates) is unchanged.
- **Rationale corrected 2026-08-09 by the wave-10 recon; the defect is unchanged and still open.** This row's closing claim — *"one limit raise, or one added field in pre-1.0 `x509-cert`, reproduces A100 in `anchor_token`"* — is **false post-D102**. `anchor_token.rs:87-92` no longer uses the bare `len + SLACK` cap but `assert_within_budget_structural(..., tsa_structural_alloc_bytes(len))`, and the reservation and the exemption are now derived from the **same** constants (`caps.rs:180-183`), so a `MAX_CHAIN_CERTS` raise or a wider `Certificate` moves **both** and `fuzz-smoke` stays green. That is D102 §4.1's own objection — *"a derived bound moves with the limit it derives from"* — landing on the DER side. What actually reddens on such a raise is `cargo test` (`caps.rs`'s `f4_registry_values` and the DER structural-cost row), never the fuzz lane. The tie A100 exposed (`MAX_CHAIN_CERTS × size_of::<Certificate>()` = 8 × 512 = exactly `SLACK`) is now a **preserved historical fact, not the live mechanism**.
- **Consequence, and it is why this row needs a second deliverable.** The minimal fix **lands with NOTHING RED**: the worst case is still 8 real certificates = 4 096 B and `TSA_STRUCTURAL_ALLOC_BYTES` does not move. So the fix is **unverified by construction** unless it arrives with its own instrument — an allocation row over an 8-entry all-`[3] other` bag asserting the reservation is ~0 rather than 4 288 B. A repair whose only evidence is that nothing broke is the shape this project keeps finding in other people's tests.
- Notes: found in the same sweep and latent — `caps.rs`'s `FUZZ_SLACK` (`:303` at the time of writing) is a **hand-transcribed duplicate** of `fuzz/src/lib.rs:95`'s `SLACK`, with nothing cross-checking the two. That is a clause-(a)-shaped literal (*"a number typed by hand is a number that survives a raise"*) sitting in the very file clause (a) was applied to. Cheap to bind; cite it here so it is not rediscovered a third time.

### A112 — Wire the committed mainnet headers into `antseal-anchor`'s replay fixtures
- Milestone: M2
- Size: XS
- Deps: after A22 (D103 §10)
- Discovered by: **the D103 lane** (2026-08-09).
- Problem: the mainnet headers A25 captured and `6f69e1a` committed are consumed by **zero lines of code** — no `include_bytes!` anywhere names `testdata/anchors/A25-upgrade-headers/`, and `crates/antseal-anchor/src/testing/replay.rs`'s `fixtures` module still wires only `A16-A17-live/`'s height-**800000** header. So the transport stubs cannot replay a promotion round at any height this project actually attests.
- Do: wire the three `A25-upgrade-headers` height/header pairs into `testing::replay::fixtures` so a must-agree promotion round can be replayed offline at **960767 / 960768 / 960771**, the heights this project's own upgraded `.ots` attests. Both endpoints' copies are committed and byte-identical, which is what lets the must-agree path be exercised rather than simulated.
- Accept: a promotion round replays offline at one of the three real heights with no network and no new capture; the `include_bytes!` paths make a moved fixture a compile error, matching the module's existing rule.
- Notes: A22 **partly** closed the "consumed by nothing" rot — its generator reads three of those files and emits their 160 hex characters into the frozen vector, which is a stronger home than an `include_bytes!` would give them — but that is the *vector* half. Wiring `replay.rs` was explicitly ruled **not A22's** (D103 RULING 9): it is a stub-fixture job in the network crate.

### A113 — The F4 registry's `margin` column is cross-checked by nothing
- Milestone: M2
- Size: XS
- Deps: after A48 (D104 §4)
- Discovered by: **the D104 lane** (2026-08-09).
- Problem: `margin` is **the only numeric column in `docs/format/anchor-artifact-limits.md` §5 that no test reaches**. `ots_limits_match_the_f4_registry` matches on the `| name | owner | value |` prefix and stops there; `the_structural_cost_column_states_the_derivation_and_its_value` pins the structural-cost cells. Nothing pins margin — and the column stopped being decorative when `ots/tests.rs:280` and clause (c)'s headroom guard made it operational.
- Do: cross-check the column the way the value and structural-cost cells are cross-checked, or state in the document that it is unchecked prose. Either is honest; the current state is a number that reads like the others and is not.
- Accept: a wrong `margin` cell reddens a named test, or the document says the column is not machine-checked and names what is.
- Notes: this is not hypothetical — **it is precisely how A109 came to reason from a 15.28× figure** derived from a third-party fixture rather than from any antseal artifact. The real margin against the depth-85 spliced artifact is **12.05×**; A48 re-measures with `parse_ots_measured` against A63's artifact, and D104 §4 deliberately wrote **no number into the registry** because a planning round's Python is not the parser the registry's own rule names. *Minted as **A112** by the D104 planner and renumbered here: two concurrent planners claimed A112 the same afternoon for different work — the wave-8 collision repeating exactly as Q85 predicts.*

### A114 — A D102 banner over A27's paragraphs, and the wasm32 asymmetry the registry never states
- Milestone: M2
- Size: S
- Deps: after A106, A48
- Discovered by: **the A48/A106 lane** (2026-08-10), handed on from `tasks/A.md`'s A109 Notes.
- Problem: two separate defects, both fallout from A109 and both explicitly out of A106's scope. **(a)** `docs/format/anchor-artifact-limits.md`'s `### 5a.` heading carries *"Added 2026-08-07 by D102"* and was inserted **above** two paragraphs that `git log -S` dates to **A27's commit `1620543`, 2026-07-28** — four independent probes return that one commit. So a reader attributes A27's Update rule to D102, and that misattribution is not idle: it is what let A109 read a registry-*keeping* procedure as a *permission* rule. **(b)** `crates/antseal-core/src/anchor/ots/limits.rs:155-157` records that `Frame` is **40 B natively and 24 B on wasm32**, so the browser tab is the **cheapest** venue for the work stack, not the constrained one. That fact lives in code and appears **nowhere in the registry** — and A109's argument invoked the browser as its constrained venue, i.e. it was inverted on exactly this point.
- Do: move or re-word the §5a banner so authorship follows `git log -S` rather than adjacency, and state the wasm32 size asymmetry in the registry where the structural-cost column is defined, since that column's numbers are target-dependent and only one target is written down. **Governed by [D104](../docs/decisions/D104-max-ots-depth-lowering-window.md) §6 (RULING 5), which rules both halves**: the wasm32 figures go in the registry with the direction stated (the browser is the cheapest venue, not the tightest) and the headroom line target-qualified; and *"the `§5a` heading capture (§1.2) is the same owner and the same edit: end §5a before `**Update rule.**`, or re-title it so A27's two paragraphs are not filed under a D102 banner"*. §6 names its owner as **A106**, which closed having excluded this work — which is why nothing pointed here.
- Accept: the §5a heading attributes A27's text to A27; the registry states the native/wasm32 `Frame` asymmetry and names the cheaper venue; and a reader cannot derive A109's inverted premise from the document.
- Notes: this is the residue of a lane that was already corrected twice. A106 was scoped by `TODO.md` to two provenance citations and says so in its own entry; `tasks/Q.md:1544` says A106 is *"not"* this; `tasks/A.md:1191` hands it here. Three descriptions, one owner, and this row exists so the fourth reader does not have to re-derive which is authoritative. **Citation added 2026-08-10 under Q134: this entry named no governing decision while D104 §6 governed it throughout** — the omission A121 and Q145 were minted for. §6's remaining half, the 32-bit test arm that clause (a) makes inseparable from the numeric cells, is **A121's** and is not discharged here.

### A115 — The calendar-response margin is scaled against the submit reply, not the binding upgrade reply
- Milestone: M2
- Size: XS
- Deps: after A113, A42 (D54 §6.1)
- Discovered by: **the A113 lane** (2026-08-10), while cross-checking the margin column.
- Problem: `MAX_OTS_CALENDAR_RESPONSE_BYTES`' §5 margin is computed against the largest **submit** response, 220 B, giving 297.89x. The **binding** real reply is the **upgrade**, measured at **1 105 B** — margin **59.31x**, a fivefold reduction — and it has been pinned as `antseal_anchor::ots::MEASURED_MAX_UPGRADE_RESPONSE_BYTES` and asserted per file since 2026-08-03. The registry cell nevertheless claimed the upgrade *"has not been measured"* for seven days after it had been.
- Do: decide which reply this limit is scaled against, and make the cell say so. If the upgrade reply is binding — and the evidence is that it is — re-key the margin to 59.31x and state that the submit figure is the lesser of two measured shapes.
- Accept: the margin cell names which reply class it divides by, and the number matches a measurement pinned by a named test; no cell claims a measurement that exists is absent.
- Notes: A113 corrected the falsehood and the arithmetic and recorded the 59.31x **in the cell**, but deliberately did **not** re-key the column, because which reply a limit is scaled against is a substantive ruling about A42's limit that D54 §6.1 assigned, and a fivefold margin reduction is not a drive-by edit. The correct fix may also be that both are recorded — a limit with two measured reply classes arguably owes both numbers.

### A116 — An unused import warns on every wasm32 lane run
- Milestone: M2
- Size: XS
- Deps: after P14
- Discovered by: **the A48 lane** (2026-08-10).
- Problem: `crates/antseal-core/src/anchor/ots/mod.rs:70` imports `error::all_code_exemplars`, whose consumers are `test-util`-gated and therefore native-only. On `wasm32-unknown-unknown` the import is unused, so the `wasm32-core-tests` lane emits a warning on every run.
- Do: narrow the `#[cfg]` so the import follows its consumers.
- Accept: the wasm32 lib-test build is warning-free.
- Notes: pre-existing and cosmetic, and recorded only because of where it lives. This is a lane whose entire value is that a human reads its output closely — the wasm32/native bit-match is a format-correctness instrument — and a standing warning is exactly the kind of noise that trains a reader to skim. Cheap to close; it is filed rather than fixed in-lane because it was found outside the fixing lane's file scope.

### A117 — Two `A16-A17-live` captures no code names, and a hash the replay compares to itself
- Milestone: M2
- Size: XS
- Deps: after A112
- Discovered by: **the A112 lane** (2026-08-10), while wiring the A25 headers into the replay fixtures.
- Problem: `testdata/anchors/A16-A17-live/esplora-mempool-height-800000.txt` and `esplora-mempool-404-body.txt` are named by **zero lines of code** — their only occurrences repo-wide are the two size rows in that directory's own `CAPTURE.log`. `crates/antseal-anchor/src/testing/replay.rs` wires four of the six `A16-A17-live` captures: blockstream's height (`:55`), blockstream's header (`:59`), mempool's header (`:65`) and blockstream's 404 body (`:69`). The consequence is an asymmetry inside one replay. The **header** arm is genuine two-endpoint agreement — `crates/antseal-anchor/src/esplora/tests.rs:50-57` builds one stub from `BLOCKSTREAM_HEADER` and the other from `MEMPOOL_HEADER`, and says why: *"if the two live services had disagreed, this test would be red rather than comparing one file to itself."* The **hash** arm is not: `esplora()` serves the single `BLOCKSTREAM_HEIGHT` constant from all three of its arms (`:319`, `:336`, `:355`), so both stubs return the same file. Nor is the 404 arm, whose constant carries the doc comment *"esplora's 404 body for a height beyond the tip. Both services."* (`:68`) over blockstream's file alone.
- Do: wire the two unreferenced mempool captures the way A112 wired the A25 pairs, so the 800000 hash and 404 arms each read two independently captured files, and correct `ESPLORA_NO_SUCH_BLOCK`'s *"Both services"* to describe what the constant actually holds.
- Accept: no committed capture under `A16-A17-live/` is referenced by nothing; the 800000 hash and 404 arms each read two distinct files; and a doc comment claiming two services is backed by two files. Red direction: repointing one endpoint's fixture at the other's file leaves the agreement test green today, and must not after.
- Notes: A112's own wiring makes the asymmetry visible in one screen — it carries `MEMPOOL_HEIGHT_960767` / `_960768` / `_960771` beside the blockstream constants and records the rule at `replay.rs:86-90`: *"a pair built from one file agrees with itself by construction."* This is the same rot one directory over and the **older** half: the A25 captures were unreferenced for days, these since A16/A17. The exposure is bounded and that is why this is XS — `fetch_agreed_header` (`crates/antseal-anchor/src/esplora.rs:106-114`) agrees on the *header* only, so a shared hash file weakens the replay's independence rather than short-circuiting an assertion the code makes.

### A118 — A retired margin figure, wrong at both precisions, in four doc comments
- Milestone: M2
- Size: XS
- Deps: after A115
- Discovered by: **the D110 lane** (2026-08-10).
- Problem: `298x` is wrong twice over. The arithmetic is `65 536 / 220 = 297.8909…`, so it was never right at either precision this project prints — the identical defect A113's new checker found in the registry cell (`298.0x`) and corrected to `297.89x`. Then D110 **retired the divisor**: §5's row is keyed to the binding *upgrade* reply, `65 536 / 1 105`, and the cell now reads `59.31x (upgrade)`. Four live code sites still state the retired figure: `crates/antseal-anchor/src/ots/mod.rs:71` (*"a 298x margin"*), `:91` (*"the 298× margin"*), `:160` (a test comment added this wave), and `crates/antseal-anchor/src/http.rs:187` (*"64 KiB is a 298× margin"*). Two decision records carry it as history: `docs/decisions/D90-anchor-http-substrate.md:912` and `:1252`, and `docs/decisions/D54-default-ots-calendars.md:331` and `:386`. **A113's checker cannot reach any of them** — `the_margin_column_is_the_value_over_the_measurement` recomputes `value / measured` *inside the registry document* and rejects the spelling in a cell; nothing in the tree reaches a doc comment.
- Do: correct the four code sites to the figure §5 now states and name the reply class each divides by. Leave the two decision records as written or amend them dated per the decision-record protocol — they are statements about what was believed then, not claims about today's tree.
- Accept: no doc comment in `antseal-anchor` states a calendar-response margin that disagrees with §5's cell, and the reason no instrument caught it is either closed or filed (it is **Q144**, the missing `doc_pointer_liveness` sweep over this crate).
- Notes: **a line-count change above `crates/antseal-anchor/src/ots/mod.rs:126` moves a line another crate cites by hand.** `crates/antseal-core/tests/doc_pointer_liveness.rs:124-137` allowlists a cross-crate pointer whose text (`:126-127`) reads *"lives in the antseal-anchor crate at src/ots/mod.rs:126"*, unresolvable until Q70 widens the sweep and therefore verified by hand, not by machine. Both live sites at `:71` and `:91` sit above it, so an in-place word swap is safe and a re-wrap is not. Note also that the ASCII/`×` spelling is mixed — `:71` is `298x`, `:91` and `http.rs:187` are `298×` — so a grep for one form finds half of them, which is part of why they survived A113.

### A119 — Whether the `.ots` and DER halves of §5 owe separate margin disciplines
- Milestone: M2
- Size: XS
- Deps: after A115, A110
- Discovered by: **the D110 lane** (2026-08-10).
- Problem: §5's margin-band sentence in `docs/format/anchor-artifact-limits.md` had never been table-wide true. It named a floor of `MAX_OTS_DEPTH` while A110's four DER rows, added 2026-08-09, put `MAX_CHAIN_CERTS` at **2.0x** — a floor six times lower, in the same table, in a paragraph that spoke of *"this table"*. **A115 has already repaired the statement**: the band now reads *"over these eight `.ots` and receive-side rows, 12.05x to 178.09x, and the floor is `MAX_OTS_DEPTH`"*, is immediately followed by *"Across the whole table the floor is lower still … `MAX_CHAIN_CERTS` at 2.0x"*, and the section closes by recording that a *"≥ 15x"* discipline *"has never been true of it"*. What survives the repair is the question it exposed and does not answer: **two bands now stand side by side with no rule saying which governs a new row.**
- Do: decide it and record the answer in §5's Update rule, where a new row's author will read it — either state a floor per half and what a row below it owes, or state that the table records margins and imposes no floor, and retire the ≥ 15x expectation from the record for good.
- Accept: an author adding a row to either half can read §5 and know what margin discipline, if any, binds it; and no sentence in the section states a band without saying which rows it spans.
- Notes: not a correction — the falsehood is gone. This is a **policy** row, which is why it is separate from A115 and why its cost is the decision, not the edit. The evidence that the question is live and expensive: the ≥ 15x expectation reached A48's own `Do` (*"every margin is ≥ 15x"*) as an assertion about a table where it had never held, and D104 §4 records A109 reasoning from the retired 15.28x. Whichever answer is chosen stays prose unless it is given an instrument — A113's `the_margin_column_is_the_value_over_the_measurement` checks each cell's arithmetic and deliberately checks no floor.

### A120 — `replay.rs` bolds a population of 18 that six committed files can test
- Milestone: M2
- Size: XS
- Deps: after A25
- Discovered by: **the D110 lane** (2026-08-10).
- Problem: `crates/antseal-anchor/src/testing/replay.rs:172-176` documents `CALENDAR_CATALLAXY_A` as *"a real pending calendar attestation (catallaxy, digest A, 220 B) — **the largest of the 18 measured** submit replies"*. The bold reads as a pinned population; it is not. **Six** submit replies are committed — `testdata/anchors/A25-bootstrap/`, A/B × alice/bob/catallaxy at 207/170/220/207/170/185 B — and the other twelve exist only as a sentence in D54 §8b, which D110 re-measured and confirms as *"six committed of eighteen"*. So a reader who wants to check the superlative can check it over a third of the claimed set, and nothing at the constant says so.
- Do: state at the constant how many of the 18 are committed and where the other twelve are recorded, or restate the superlative over the committed six — which is the claim the tree can support.
- Accept: the doc comment's population is either committed or named as uncommitted, and a reader can tell which measurement backs the bold without opening a decision record.
- Notes: cosmetic alone, and filed because of what the same sentence now carries. D110 re-keyed A42's row to the *upgrade* reply, so this constant is explicitly *"the lesser of the cap's two reply classes"* and its 220 B is the divisor **A118**'s stale `298x` comments still use. A bolded claim about a population that six files can test is the shape A113 closed in the registry — a number that reads like the others and is not.

### A121 — D104 §6's 32-bit arm, orphaned by the owner it names
- Milestone: M2
- Size: S
- Deps: after A114 (D104 §6)
- Discovered by: **the A114/A115 lane** (2026-08-10), which found the governing decision only after implementing against a brief that said there was none.
- Problem: `docs/decisions/D104-max-ots-depth-lowering-window.md` §6 — *"RULING 5 — yes, the wasm32 asymmetry goes in the registry, and it is A106's"* — rules **two** things and only one has landed. A114 stated the asymmetry (§5a's two-target table) and target-qualified the headroom line, which was its file scope. The other half is untouched: *"Because clause (a) forbids adding a fourth unchecked number, the same edit gives `the_structural_cost_column_states_the_derivation_and_its_value` a 32-bit arm asserting the wasm32 cells, mirroring the split `caps.rs` adopted at `873a1cf`."* That test still gates its byte counts on `if core::mem::size_of::<usize>() == 8` (`crates/antseal-core/src/anchor/ots/limits.rs:361`), and A114's own §5a records the residual in the document: *"The 32-bit row is derived but not yet asserted, which is a gap rather than a decision."* **The owner §6 names is A106, which closed 2026-08-10 having explicitly excluded this work** — so the ruling lost its owner with no forwarding pointer, and A114's entry, its `TODO.md` row and the brief that implemented it all described A114(b) as having no governing decision while §6 governed it.
- Do: give the test a 32-bit arm asserting `OTS_STRUCTURAL_WORK_STACK_BYTES` and `OTS_STRUCTURAL_ATTESTATION_BYTES` on `wasm32`, in the shape `anchor/caps.rs` took at `873a1cf`; and settle §6's literal instruction that the **two numeric `structural cost` cells** carry the wasm32 figure beside the x86-64 one, which A114 discharged with a §5a table instead — a deviation nothing has adjudicated. No further document edit is needed for the arm: A114 wrote §5a's wasm32 row in `format_spaced`'s `**N NNN B**` spacing precisely so the existing needle construction matches (`**24 576 B**`, `**8 192 B**`, `**32 768 B**`).
- Accept: the wasm32 structural-cost figures are asserted by a named test that `scripts/wasm-tests.sh` actually runs — it runs `cargo test -p antseal-core --lib`, which is why the arm belongs in `limits.rs` and not in an integration target — shown red by mutating one figure in the document; §5a's *"derived but not yet asserted"* sentence is deleted because it has stopped being true; and the test's own doc comment stops saying the registry *"records the x86-64 measurement it says it records"*, which §5a's table has made stale.
- Notes: **one edit by D104 §6's own reasoning — the cells must not land without the arm**, because clause (a) forbids adding an unchecked number and the cells would be it. This row also closes the wasm32 figures A114 hand-typed into §5a, which are today exactly what D104 §6 calls *"a number typed by hand is a number that survives a raise"*. The instance matters less than its shape, filed separately as **Q145**: a resolved decision whose named owner closes without discharging it is invisible to every later reader, and this is the measured case.

### A122 — `caps.rs` describes the `.ots` side's target split, and A121 has just falsified it
- Milestone: M2
- Size: XS
- Deps: after A121
- Discovered by: **the A121/A118 lane** (2026-08-10), in the same pass that made the sentence false.
- Problem: `crates/antseal-core/src/anchor/caps.rs:541-546` explains its own target split by pointing at the `.ots` side as the precedent it copied — *"So it now splits the way the `.ots` side already did (`limits.rs`, `the_structural_cost_column_states_the_derivation_and_its_value`): the **derivation** is asserted everywhere … the **measured byte counts** are asserted on 64-bit only, because the registry records the x86-64 measurement it says it records."* The second half stopped being true when A121 landed. `limits.rs`'s test now selects the target's own label (`let target = if core::mem::size_of::<usize>() == 8 { "x86-64" } else { "wasm32" }`) and asserts the registry carries the measured figure **for whichever target is running**, plus a 32-bit-only inequality arm. So the measured counts are no longer 64-bit-only on the `.ots` side, and a reader of `caps.rs` who follows the citation to learn the house pattern is taught the pattern that was replaced.
- Do: correct the `caps.rs` doc comment's description of the `.ots` side to what `limits.rs` now does — per-target assertion of the measured figure, plus a 32-bit direction arm — and keep the *reason* for `caps.rs`'s own narrower choice, which is unchanged and is the point of the paragraph. `caps.rs` is deliberately **not** being re-scoped here: its subject is `size_of::<x509_cert::Certificate>()`, whose 32-bit value the registry does not record, so the asymmetry between the two files is real and should be stated as an asymmetry rather than erased.
- Accept: no sentence in `caps.rs` describes `limits.rs`'s behaviour in terms that `limits.rs` no longer exhibits, checked by reading the two side by side; and the paragraph says why the two files legitimately differ, so the next lane to touch either does not "fix" the difference.
- Notes: this is A106's shape exactly — *"a correction landed in one of two places is a correction that has not happened"* — arriving one file over and one wave later, which is the argument for the row rather than for care. Nothing is red: the sentence is a doc comment and no assertion reads it, so this is invisible until a human reads it for an unrelated reason. That is the same silence `doc_pointer_liveness` exists to break, and **Q144** is the row that would extend that sweep to cross-file prose claims — this instance is inside `antseal-core`, which the sweep already covers by path but not by content.
- **Row and entry authored 2026-08-10 by the wave-13 bookkeeping lane from the A121/A118 lane's report, verified against the tree before registering.** Verified here, not taken on report: `caps.rs:541-546` carries the quoted sentence at exactly those lines, and `limits.rs`'s `the_structural_cost_column_states_the_derivation_and_its_value` now runs its measured-figure loop on both targets with a `size_of::<usize>() != 8` arm below it. **Authored here, not reported: the whole `Do`, the whole `Accept`, and the `Notes`** — the report named the defect and its shape and named no remedy and no acceptance criterion. The `Do`'s refusal to re-scope `caps.rs` is this entry's choice, on the ground that the registry records no 32-bit certificate size for it to assert against.

### A123 — The structural-cost needle is a document-wide substring search and cannot tell a cell from prose
- Milestone: M2
- Size: S
- Deps: after A121
- Discovered by: **the A121 lane** (2026-08-10), by mutation rather than by reading.
- Problem: `the_structural_cost_column_states_the_derivation_and_its_value` asserts the F4 registry's structural-cost figures with `REGISTRY.contains(&needle)` over `include_str!`'d `docs/format/anchor-artifact-limits.md` — the **whole document**, not the cell. The lane proved it: mutating `**12 288 B**` inside the `MAX_OTS_ATTESTATIONS` cell alone leaves the test **green**, because §5a's two-target table still carries the string somewhere else in the file. So the test pins *"this number appears in this document"*, not *"this row states this number"*, and the registry cell it exists to protect can be edited without reddening it. A121 has just added a second target to the same needle, which doubles the number of places any given figure legitimately appears and therefore makes the substring search weaker, not stronger.
- Do: read the cell instead of the document. `registry_rows()` already parses the registry into rows and extracts the cells, and already discards the structural-cost column — so the parse exists and only the consumption is missing. Assert the figure against the named row's own structural-cost cell, per target, and leave the document-wide `contains` only for the derivation formulas, where "stated somewhere normative" is the actual claim.
- Accept: mutating the figure in the `MAX_OTS_ATTESTATIONS` cell alone turns the test **red** while every other row stays green — the exact mutation that is green today, run as the before/after; the derivation-formula assertions are unchanged; and no new parse of the registry is introduced, because `registry_rows()` is the one that already exists (adding a second would be the defect **Q157** files).
- Notes: the same weakness already applied to the 64-bit arm before A121 and nobody had planted a fault against it, which is the general lesson: an assertion whose subject is a whole file passes for reasons its author never intended. Cost is bounded — the mutation is one string in one cell and the parse is already written — but it is `S` and not `XS` because the per-target needle now has two legitimate homes and the test has to say which one it means.
- **Row and entry authored 2026-08-10 by the wave-13 bookkeeping lane from the A121/A118 lane's report, verified against the tree before registering.** Verified here, not taken on report: the assertion at `limits.rs` is `REGISTRY.contains(&needle)` against an `include_str!` of the whole registry document, and `registry_rows()` exists in the same file and returns parsed cells. **Not re-verified here: the lane's mutation result itself** — that `**12 288 B**` can be changed in the cell with the test staying green is taken from the lane's report, because reproducing it means editing a document this lane may not edit. The `Accept` makes that mutation the acceptance criterion, so the claim is checked by whoever executes the row rather than asserted here.

### A124 — Two §5a prose sites still print the x86-64 work-stack figure unqualified
- Milestone: M2
- Size: XS
- Deps: after A121
- Discovered by: **the A121 lane** (2026-08-10).
- Problem: `docs/format/anchor-artifact-limits.md` prints `40 960 B` at four places. Two are target-qualified and correct — the `MAX_OTS_DEPTH` registry cell at `:222` (*"**40 960 B** (x86-64) and **24 576 B** (`wasm32`)"*) and §5a's two-target table at `:396`, whose row is labelled `x86-64`. The other two sit in §5a prose with no target named: `:345` — *"it is **40 960 B** of bookkeeping from a 1 145-byte legal artifact — 35.77x the input"* — and `:404`, which is a **verbatim quotation of A109's lowering argument** and is deliberately unqualified, because the whole point of the surrounding paragraph is that A109 applied the x86-64 figure to the browser. So `:404` must not be touched; `:345` is an unmarked assertion in the document's own voice, and its `35.77x` ratio is x86-64-only too.
- Do: target-qualify `:345` — state the figure as the x86-64 measurement and give the `wasm32` counterpart, or point at the two-target table twelve lines below — and leave `:404` exactly as it is, with a word in the surrounding prose making clear that the quotation is being reported rather than asserted, if that is not already unambiguous.
- Accept: every unqualified `40 960 B` in `docs/format/anchor-artifact-limits.md` is either target-qualified or explicitly marked as a quotation of a superseded argument; `:404`'s bytes are unchanged; and A121's per-target needle still finds every figure it asserts, so `the_structural_cost_column_states_the_derivation_and_its_value` is green on both targets after the edit.
- Notes: this is the residue of D104 §6's *"the inversion must not be re-derivable from the registry alone"*. The document now states the inversion twice and states the x86-64 figure unqualified once in its own voice, which is enough for a reader who stops at §5a's first page to re-derive A109's premise. Filed `XS` and separately from A121 because A121's own `Accept` was the test arm and the cells, and widening it to a prose sweep after the fact would have been the scope creep D104 §6 was already suffering from.
- **Row and entry authored 2026-08-10 by the wave-13 bookkeeping lane from the A121 lane's report, verified against the tree before registering.** Verified here, not taken on report: `grep -n "40 960" docs/format/anchor-artifact-limits.md` returns exactly four lines — `:222`, `:345`, `:396`, `:404` — and their qualification status is as described. **One correction to the report, made here:** it named the A109 quotation as `:403`; the line carrying `40 960 B` is `:404` (`:403` is the sentence that introduces the quotation). **Authored here, not reported: the whole `Do`, the whole `Accept` and the `Notes`** — the report named the two sites and which was deliberate, and named no remedy.

### A125 — The `report` kind pins the D29 anchor surface only in its degenerate case
- Milestone: M2
- Size: S
- Deps: after A22, R12
- Discovered by: **D115** §8 (2026-08-10), while reconstructing A108's entry.
- Problem: all three anchor verdicts in the frozen `report` kind are `invalid` with `source: null` — the degenerate case, in which `source`, `state` and `verified_time_unix` have nothing to render. So the `report` vectors pin the D29 anchor surface only where that surface is empty. A change to how a **non-degenerate** anchor renders — a `proven` verdict's signer identity, its state spelling, its `verified_time_unix` — moves no `report` vector and is visible only to the `anchor` kind, which under D101 and A108 **cannot legally move**: `verdict_event_ok` refuses any path without `/report/` in it. The two kinds therefore cover disjoint halves of one surface with nothing saying so, and the half that can absorb a legitimate change is the half that does not exercise it.
- Do: rule which of the two available shapes governs, and record the reason where the freeze rule is read. The options are (i) state, in the freeze manifest's prose and in D101's terms, which kind pins which half of the D29 anchor surface, so a lane proposing a rendering change knows which file it is allowed to move and which it is not; or (ii) add a `report` case carrying a **non-degenerate** anchor, which puts the whole surface behind the kind that has a verdict-event hatch. (ii) is strictly more coverage and strictly more cost — a new frozen vector and a Q6/Q14 ceremony — and (i) is a paragraph.
- Accept: the ruling is recorded with its reason at the place a lane proposing an anchor-rendering change will read it — the freeze manifest's prose, `verdict_event_ok`'s comment, or both; if (ii) is ruled, the new case is frozen and `--check` is red before it and green after; and either way, a reader can answer *"if I change how a `proven` anchor renders, which frozen files move?"* without opening a decision record.
- Notes: filed as a decision-shaped row per D115 §3.6, because the row names a defect and offers a menu, and picking from the menu here would smuggle a ruling into the tree through a task entry. The instance is narrow; the shape is not — it is *"the covering fixture covers the empty case"*, which is the same family as **Q158** (a cross-check that only runs when its subject already succeeded), registered in the same act from a different lane.
- **Row and entry authored 2026-08-10 by the wave-13 bookkeeping lane from D115 §8's discovered-work list, verified against the decision text before registering.** Verified here: D115 §8 states the claim in the terms transcribed above, and D115's own index row repeats it. **Not verified here: the frozen vectors themselves** — that all three `report` anchor verdicts are `invalid` with `source: null` is D115's measurement, restated in A108's entry from the same source, and this lane did not re-read the frozen JSON. **Authored here, not transcribed: the whole `Accept`, the `Deps`, and the `Notes`** — D115 §8 named the defect and sketched the two options, which the `Do` transcribes; it named no acceptance criterion.

### A126 — A123's defect is live and already realised on the DER side, and is not A123's fix
- Milestone: M2
- Size: S
- Deps: after A123
- Discovered by: **the A123 lane** (2026-08-10), which fixed the `.ots` side and left this one deliberately, with its reason in the doc comment.
- Problem: A123 replaced the `.ots` side's document-wide `REGISTRY.contains()` with a per-row, per-target read out of the named §5 row's own `structural cost` cell. The DER side still has the old shape. `the_der_structural_cost_column_states_the_derivation_and_its_value` in `crates/antseal-core/src/anchor/caps.rs` asserts four derivation formulae, one negative pair, and **seven byte figures** — the last matched as `REGISTRY.contains(&format!("**{}**", …))` over an `include_str!` of the entire document. **The defect is already realised, not hypothetical**: `**4 288 B**` (the `MAX_CHAIN_CERTS` structural cost) appears **three** times in the document — §5's cell, §5a's per-container table and §5a's prose — so mutating §5's cell alone leaves the needle satisfied and the test green. `**3 200 B**` and `**1 024 B**` likewise have two homes each. **And it is not A123's fix one file over**: four of the seven figures — `**3 200 B**`, `**7 488 B**`, `**2 048 B**`, `**4 096 B**` — are **not in §5's structural-cost column at all**, so there is no cell to scope them to.
- Do: Rule where the four non-§5 figures normatively live before writing any assertion. Two shapes: move or mirror them into §5's structural-cost column, so one parse covers all seven and A123's fix applies unchanged; or accept that they live in §5a. **Corrected 2026-08-11.** This clause read *"or accept that they live in §5a and **build the parse §5a needs** — noting that **nothing in the tree parses §5a today**, since the existing `registry_rows` helper keys on §5's table header alone"*, and it is **refuted in execution, not merely on paper**: [D121](../docs/decisions/D121-der-structural-cost-figures-normative-home.md) ruled the seven split 3/4 with nothing moving, and the A126 lane closed the row with **no parse of §5a at all**. A123's fix turned out to be **three** arms and not one — document-wide `contains` for the formulae, a per-row read of §5's own cell for the figures that have a row, and `matches().count() == 1` for a figure that has none — and the four §5a figures take the third arm, which reads no table. The second half of the struck clause remains true and is left standing on its own: nothing in the tree parses §5a, and under this ruling nothing needs to. Then scope the seven needles to whatever the ruling makes authoritative. Do **not** copy the `.ots` side's per-target label mechanism: that works there because §5 records both targets for `Frame` and `OtsAttestation`, and it does not work here for the reason `caps.rs`'s own doc comment gives.
- Accept: Mutating any one of the seven figures at its authoritative home turns this test red; the mutation is demonstrated for at least the three needles that have multiple homes today; the ruling on where the four non-§5 figures live is recorded in the registry document itself; and no second parse of the registry is introduced without that ruling.
- Notes: **Decision-shaped, and that is why it is a row rather than a patch.** The engineering is small once the question *"which text is authoritative for these four figures?"* is answered, and unanswerable before. **Do not read A122's doc comment as this row's answer**: it says *"do not carry that shape back here"* about the **per-target label**, on the ground that §5a records `size_of::<x509_cert::Certificate>()` on x86-64 and nowhere else — a different argument from row scoping, and an executor who conflates the two will conclude wrongly that the whole A123 shape is refused here.
- **Row and entry authored 2026-08-10 by the wave-14 bookkeeping lane from the A123 lane's report, verified against the tree before registering.** Verified here, by counting occurrences in `docs/format/anchor-artifact-limits.md` rather than by reading the report: the test's exact name; its three needle groups (four derivation formulae, one negative pair, seven byte figures inside a 64-bit gate); the `include_str!` plus `REGISTRY.contains(&needle)` mechanism with no row scoping; **three** of the seven needles having multiple homes (`4 288 B` ×3, `3 200 B` ×2, `1 024 B` ×2) and **four** absent from §5's structural-cost column entirely; and that `registry_rows` keys on §5's table header, so §5a is parsed by nothing. **Taken on report, and not re-run here — no cargo was invoked: that the `4 288 B` → `4 289 B` mutation leaves all lib tests green.** The mechanism is verified by construction (the two §5a occurrences satisfy the needle independently, and `registry_rows` is a private helper in `ots/limits.rs` unreachable from this test module), but the run itself is the A123 lane's. **One correction to the report**: it says the cell-level fix needs a parse *"which Q157 files against"*; **Q157's subject is directory walks over `testdata/vectors/`** and it files nothing against a registry parse — the mis-citation is inherited from A123's own `Accept` and is defensible only as a class analogy. ~~**The report's *"1056 lib tests"* could not be verified**: no such figure exists anywhere in the tree, whose recorded totals are workspace-wide, so it is omitted from this entry rather than repeated.~~ — **Struck 2026-08-11 (wave-15 A/R bookkeeping): the claim is false, and it was false when it was written.** The figure is exact and was reproduced here directly — `cargo test -p antseal-core --lib --no-fail-fast` reports `test result: ok. 1056 passed; 0 failed; 1 ignored` — and D121 §12 (5) reports it reproduced twice more, with a structural second confirmation this entry did not have. **The premise is wrong too, and more sharply than D121 states it.** D121 corrects this as conflating *not recorded as a committed number* with *unverifiable*; measured, `1056 passed` **was** a committed number at the time, in `TODO.md`'s A116 row, present since `d23dccc` — three commits before `360ea2a`, the commit that authored this entry — and `TODO.md` is the file this entry's own row lives in. So *"no such figure exists anywhere in the tree"* was refuted by one `grep` of the tracker, and the defect was not an invalid inference from a true premise but a search that did not run. The figure is now also stated in `anchor/caps.rs`'s own gate comment, added by the A126 execution lane. **Authored here, not reported: the two shapes in the `Do`, the whole `Accept`, and the `Notes` warning about A122's different argument.**

### A127 — One missing script is the precondition for four artefacts and no row says so
- Milestone: M2
- Size: S
- Deps: after Q165
- Discovered by: **D118 §10 (iv)** (2026-08-10), while establishing that `V7.1` is the one genuine gap among the eleven deferred matrix rows.
- Problem: No file matching `anchor-smoke` exists under `scripts/`, and three committed documents already say so in their own words: `docs/anchors/real-smoke-runbook.md` §0 (*"**`scripts/` carries no `anchor-smoke` entry point.** A25 owns the capture script; Q99 owns deleting this section in the same change that commits it. The protocol has now been executed three times *without* it, by hand and one request at a time, which is precisely the repeatability the script is for"*), `tasks/A.md`'s A25 adjudication (*"**Row 1 — PARTIAL, and the script is the whole of what is missing.**"*), and `tasks/Q.md`'s Q99 Accept row 1 (*"§0 is deleted in the same change that commits the script, never before"*). D118 added a fourth site: `V7.1` in `docs/testing/verification-matrix.md` moved from `deferred` to **`gap`**, where it will block M2's review rather than be silently exempted. The scheduling fact nobody had written down is that these are not four independent pieces of work — they are one script with four dependents, and A25 is where it lives.
- Do: Record the coupling where a scheduler will see it: A25's entry names the four dependent sites and states that committing the script discharges or unblocks each. Do not create a fifth home for the script's specification — A25 owns it, and the value here is the dependency list, not a new task. When A25 lands, the same change deletes runbook §0 (Q99 row 1's rule) and re-adjudicates `V7.1`; note that A25's own Accept requires the two-day OTS protocol completed at least once *with* the script, so the script and a real run are one obligation, not two.
- Accept: A25's entry lists the four dependent sites; a reader scheduling A25 can see that it discharges runbook §0, Q99 Accept row 1 and `V7.1` as well as A25's own row; and when the script lands, all four move in the same change or the reason each did not is recorded.
- Notes: **The count is four sites and three independent obligations**, and the distinction matters for planning: Q99 Accept row 1 and runbook §0 are two faces of one coupling — the rule *is* that they move together — which D118 §10 (iv) itself treats as a pair one sentence earlier. `V7.1`'s `gap` is real and is the reason this is now visible at all, since a `deferred` row is invisible without a flag nobody types. **The deeper point D118 makes and this row carries**: the protocol has been executed three times by hand, so the missing artefact is *repeatability*, not evidence — which is exactly why it stayed missing.
- **Row and entry authored 2026-08-10 by the wave-14 bookkeeping lane from D118 §10 (iv), whose framing it corrects.** Verified here: no `anchor-smoke` file exists under `scripts/`, and the expected name is bare `anchor-smoke` with no extension in all three citing documents; runbook §0's clause, A25's PARTIAL adjudication and Q99's Accept row 1, each quoted above; and `V7.1`'s status cell now reading `gap` with a note naming the missing script. **Two corrections to the source's framing**: (1) they are four *sites* but **three** independent obligations, because Q99 row 1 and runbook §0 are coupled by their own rule; (2) *"separately committed"* does not hold for the fourth — `V7.1`'s `gap` is **uncommitted working-tree state**, as is D118 itself, while the other three are committed. **Authored here, not reported: the do-not-create-a-fifth-home instruction, the observation that A25's script and its real run are one obligation, the whole `Accept`, and the `Notes` repeatability-not-evidence point.**

### A128 — §5a's closing sentence is still false after its correction, and widening the assertions is the half that was deferred
- Milestone: M2
- Size: S
- Deps: after A126
- Discovered by: **D121 §12 (1)** (2026-08-11), and the A126 lane that applied §9.3's narrowing and reported the other half as separate work.
- Problem: §5a of `docs/format/anchor-artifact-limits.md` closed with *"Every number in this subsection is derived in `anchor/caps.rs` and asserted against this document, never transcribed."* A126 corrected it on 2026-08-11, narrowing the middle clause and adjudicating that *"its first and last clauses hold"*. **Measured here, all three are false, and the narrowed clause is false in the other direction.** (1) *Derived in `anchor/caps.rs`* — §5a's `.ots` figures are derived in `crates/antseal-core/src/anchor/ots/limits.rs` (`OTS_STRUCTURAL_WORK_STACK_BYTES`, `OTS_STRUCTURAL_ATTESTATION_BYTES`, `OTS_STRUCTURAL_ALLOC_BYTES`); `caps.rs` declares none of them. (2) *Never transcribed* — §5a's two-target table types `40 B`, `48 B`, `24 B`, `32 B`, `5.08 %` and `3.13 %` by hand, and its prose types `35.77x`, `2.51x` and the `1 145-byte` input; no constant produces any of them. (3) The replacement clause names **seven** figures asserted against this document, but **three of those seven are asserted at §5's `MAX_CHAIN_CERTS` row and not in §5a at all** — `**664 B**` occurs **zero** times in §5a, and §5a's `**4 288 B**` (twice) and `**1 024 B**` (once) are exactly the commentary arm 1 deliberately does not pin — while it **omits the two numbers in §5a that another test does pin**: `**53 248 B**` on x86-64 and `**32 768 B**` on `wasm32`, each required to occur exactly once by `anchor::ots::limits::tests::the_structural_cost_column_states_the_derivation_and_its_value`. So §5a's own text carries **six** asserted numbers, not seven, and the sentence names neither set correctly. Separately, the correction's list of what is unasserted — `2 176 B`, `3 008 B`, the signer's `128 B`, and `0.71 %`/`0.41 %`/`0.31 %` — **omits `5.08 %` and `3.13 %`**, which sit in §5a in the document's own voice and are asserted by nothing anywhere in the tree.
- Do: widen the assertions rather than narrow the claim a second time, then restate the sentence once from what is then true. The cost is measured and small: the signer's `128 B` **is** `anchor::caps::CHAIN_PATH_NODE_BYTES` exactly; `2 176 B` is **not** a constant — contrary to how the discovered-work report paraphrased it — but is one expression over two, `TSA_STRUCTURAL_PATH_NODE_BYTES - MAX_CHAIN_CERTS * CHAIN_PATH_NODE_BYTES`, equivalently `(MAX_INTERMEDIATE_COUNT + 1) * CHAIN_PATH_NODE_BYTES`; and all three DER percentages reproduce exactly under `format!("{:.2} %", …)` of `bytes * 100 / MAX_TSA_TOKEN_BYTES` in floating point, checked here for all three. Settle the `.ots` half in the same act or record why not — `5.08 %` and `3.13 %` are the identical ratio against `MAX_OTS_BYTES`, one file over, and leaving them is how §5a acquires the same finding again. **Do not widen by creating a second home for a figure arm 2 counts**: restating `2 048 B`, `4 096 B`, `7 488 B` or the joined `3 200 B` form in new prose, or spelling one by value inside a new assertion message, reddens `the_der_structural_cost_column_states_the_derivation_and_its_value` at `left: 2` — the trap D121 §9.2 walked the A126 lane into, which that lane escaped by naming the seven **by role, never by value**. `3 008 B` is A130's subject and not this row's.
- Accept: no clause of §5a's closing sentence is false of any number in §5a, checked clause by clause against the constants the numbers come from and against the tests that read them; every §5a figure the sentence calls asserted is asserted, and every figure it calls unasserted is either asserted or named — including `5.08 %` and `3.13 %`, or with a recorded reason for excluding them; each newly asserted figure is shown red by a mutation whose message names the subsection; and the existing needle census is unmoved, measured before and after — `**7 488 B**`, `**2 048 B**`, `**4 096 B**`, `**664 B**` and the joined path-node form (the figure followed by ` = ` and its `25 x size_of::<Node>()` derivation) at **1** occurrence document-wide, `**1 024 B**` at **2**, `**4 288 B**` at **3**.
- Notes: the judgement in the row is real and is why it is not a patch — *assert more, or claim less* — and the last lane to face it chose "claim less" under a decision that told it to. The percentages are the only figures here whose assertion needs a **rounding rule** stated with it; `{:.2}` is what reproduces the three committed values, and an assertion that does not say so is a number typed by hand wearing a formatter. **The general shape, and the reason this is worth the row**: a correction that narrows a false sentence rather than fixing what made it false leaves the sentence true only until the next figure is added, and §5a has now been corrected once and is still wrong in two clauses one day later.
- **Row and entry authored 2026-08-11 by the wave-15 A/R bookkeeping lane from D121 §12 (1) and the A126 execution lane's report, verified against the working tree before registering.** Verified here, not taken on report: §5a's closing correction paragraph and its exact enumeration; that `OTS_STRUCTURAL_*` are declared in `ots/limits.rs` and in no other file; the full occurrence census above, counted with a script over the document rather than by eye; that `**664 B**` occurs zero times inside §5a; that the `.ots` test asserts `**53 248 B**`/`**32 768 B**` against this document with `matches().count() == 1` while asserting its per-limit figures against §5's rows; that `5.08 %` and `3.13 %` are matched by no assertion in the tree; and that `{:.2}` of each ratio against `MAX_TSA_TOKEN_BYTES` yields `0.71`, `0.41`, `0.31`. **One correction to the report, made here**: it states that *"`2 176 B` and the signer's `128 B` are already constants in `caps.rs`"* — measured, `128 B` is `CHAIN_PATH_NODE_BYTES` and `2 176 B` is **not** a constant at all; D121 §12 (1)'s own wording (*"derivable from constants"*) is the accurate one and the report's paraphrase is what drifted. **Authored here, not reported: the three-clause refutation of the corrected sentence, the six-not-seven count, the `5.08 %`/`3.13 %` omission, the whole `Accept` and the whole `Notes`** — the report named only the widen-versus-narrow judgement.

### A129 — §5a's decomposition adds up today, and three of its four operands are invisible to the test that would keep it adding up
- Milestone: M2
- Size: S
- Deps: after A126
- Discovered by: **D121 §11 and §12 (2)** (2026-08-11) as the one residue the ruling knowingly left, with the operand-level answer added by the A126 execution lane.
- Problem: §5a states a decomposition in prose — *"Of that **3 200 B**, `MAX_CHAIN_CERTS` owns **1 024 B**, the signer owns 128 B, and **2 048 B** belongs to `MAX_INTERMEDIATE_COUNT`"* — and nothing verifies that `1 024 + 128 + 2 048 = 3 200`. Under D121's ruling that is not a general gap but a precisely uneven one, and **which operands are exposed is now measured**: restating `**1 024 B**` there is invisible, because arm 1 of `the_der_structural_cost_column_states_the_derivation_and_its_value` reads that figure out of §5's `MAX_CHAIN_CERTS` row with `starts_with` and never sees §5a; restating `**3 200 B**` there is invisible, because arm 2's needle is the figure **joined to its derivation** — the bolded figure followed by ` = ` and its `25 x size_of::<Node>()` derivation — a form only the per-container table above states; and the signer's `128 B` is invisible because it is not bolded and is asserted by nothing at all. Only `**2 048 B**` reddens, and only because that sentence is its **own** authoritative home under arm 2's exactly-once rule. So three of the four operands can be edited to any value and the suite stays green while the sentence stops adding up — and the one that does redden is the one a reader is least likely to touch.
- Do: assert the arithmetic, not the operands. A checker in the class of `anchor::ots::limits::tests::limit_change_log_violations` (`ots/limits.rs:734`), which already does this shape for §6, can read the decomposition sentence and require that the three parts sum to the total and that each part equals its derived constant — `MAX_CHAIN_CERTS * CHAIN_PATH_NODE_BYTES`, `CHAIN_PATH_NODE_BYTES`, `MAX_INTERMEDIATE_COUNT * CHAIN_PATH_NODE_BYTES`, `MAX_PATH_NODES * CHAIN_PATH_NODE_BYTES`. **Sequence this against A128 and say which lands first**: a naive implementation spells the four figures by value in its needles or its failure message, which gives `2 048 B` and the joined `3 200 B` a second home and reddens arm 2 at `left: 2` — build the needles from the constants, exactly as arm 2 does, and add no literal. If a parse is chosen instead of a scan, it is the second registry parse A126's `Accept` forbids without a ruling, and that ruling is A131's subject, not this row's licence.
- Accept: editing any single operand of the decomposition sentence — `1 024 B`, the signer's `128 B`, `2 048 B` or the total `3 200 B` — reddens a named test whose message states which part failed and against which constant; all four mutations are demonstrated, not just the one that reddens today; the existing seven needles' occurrence counts are unchanged after the addition, measured; and no figure gains a second home in the document or in an assertion message.
- Notes: **this is a document-consistency instrument, not a code-drift one**, and D121 §11 says so — the code-drift direction is already covered, because moving `MAX_INTERMEDIATE_COUNT` or `size_of::<Node>()` changes `**2 048 B**`'s derived value and takes arm 2's count to zero. What is uncovered is a human editing prose. That is the same class as A123 and A126 — an assertion that passes for a reason its author did not intend — arriving one paragraph down rather than one file over. The four operands are all products of a single constant, `CHAIN_PATH_NODE_BYTES` (measured 128 B on x86-64), which is why the sum is cheap to assert and why a drifting restatement is invisible: every operand is the same number times a small integer.
- **Row and entry authored 2026-08-11 by the wave-15 A/R bookkeeping lane from D121 §11/§12 (2) and the A126 execution lane's operand-level report, verified against the working tree before registering.** Verified here, not taken on report: the decomposition sentence's exact wording and bolding, including that the signer's `128 B` is the one operand that is not bold; that arm 1 selects §5's row with `starts_with("| `MAX_CHAIN_CERTS` |")` and asserts with `row.contains`, so §5a's copies are unreachable by it; that arm 2's path-node needle is the joined form and occurs once document-wide; that `**2 048 B**` occurs exactly once document-wide and that occurrence is this sentence; that `**1 024 B**` occurs twice and `**3 200 B**` twice; and that `limit_change_log_violations` exists at `ots/limits.rs:734` and is the shape the record cites. **Authored here, not reported: the whole `Do` including the build-needles-from-constants warning and the A131 boundary, the whole `Accept` including the demand that all four mutations be demonstrated, and the `Notes`** — the record named the gap and the class of instrument and no acceptance criterion.

### A130 — The fuzz-guard tie is the one DER figure §5a records on both targets, and its assertion is still 64-bit only
- Milestone: M2
- Size: S
- Deps: after A126,A122
- Discovered by: **D121 §12 (3)** (2026-08-11), which measured the ground and held the work back deliberately as A121/A122 territory.
- Problem: `the_der_structural_cost_column_states_the_derivation_and_its_value` runs both of its figure arms inside `if core::mem::size_of::<usize>() == 8`, so on `wasm32` none of the seven figures is asserted. For six of them that is forced — the registry records no 32-bit value to assert against, and `376 B`/`512 B` occur **zero** times in the document. For one of them it is not: §5a states the fuzz-guard tie on **both** targets — *"The certificate-bag reservation alone, `8 x size_of::<Certificate>()`, is **4 096 B** on x86-64 … on `wasm32` the same product is **3 008 B**"* — so a 32-bit arm asserting `**3 008 B**` is writable today, against a figure the document already carries, in the shape `caps.rs` itself adopted at `873a1cf` and `ots/limits.rs` adopted at A121. **This is not A121's or A122's work and does not duplicate either**: A121 is closed and its subject was the `.ots` test in `limits.rs`; A122 is closed and its subject is a `caps.rs` doc comment describing `limits.rs`. A122's `Do` declines to re-scope `caps.rs` on the ground that its subject *"is `size_of::<x509_cert::Certificate>()`, whose 32-bit value the registry does not record"* — which remains **true of the per-certificate size** and is **not** true of the product, and D121 §7 is where that narrowing is recorded.
- Do: give the 64-bit gate a 32-bit companion arm asserting the tie's `wasm32` value from `MAX_CHAIN_CERTS * CHAIN_CERTIFICATE_BYTES` under the same exactly-once rule arm 2 uses, so `scripts/wasm-tests.sh` reddens when §5a's `**3 008 B**` drifts. Do **not** widen the gate over the other six: `2 176 B`, `664 B`, `4 288 B`, `1 024 B`, `7 488 B`, `2 048 B` and the path-node figures have no recorded 32-bit counterpart, and adding one to the document to make an assertion writable is the *"editing a format document to suit a test"* D121 refuses. Say in the same edit that the remaining gate is an absence of recorded values and not a decision about targets, so the next reader does not read `size_of::<usize>() == 8` as a ruling.
- Accept: `scripts/wasm-tests.sh` reddens on a mutation of §5a's `**3 008 B**` and is green before it, both runs shown; the native lane is unchanged and `**4 096 B**` still occurs exactly once; the arm is built from constants and adds no literal, so `3 008` appears nowhere in the source; and `caps.rs`'s doc comment states which figures are asserted on which target and why the rest are not, without contradicting the A122 sentence it sits beside.
- Notes: **the reason this is `S` and not `XS`** is that the tie has two homes in one sentence on two targets and only one of them may be counted per target, so the arm has to pick its needle the way arm 2 picks the path-node one. **The A121 precedent is directly usable**: A121's `Do` records that A114 wrote §5a's `wasm32` row in `format_spaced`'s `**N NNN B**` spacing precisely so the existing needle construction matches, and `**3 008 B**` follows the same convention. This row's value is as much in the *statement* as the arm — a green `wasm32` lane currently vouches for none of the seven, and nothing says so; that is A132.
- **Row and entry authored 2026-08-11 by the wave-15 A/R bookkeeping lane from D121 §12 (3), verified against the working tree before registering, including the duplication check the brief required.** Verified here, not taken on report: both figure arms sit inside one `size_of::<usize>() == 8` block; `**3 008 B**` occurs once in §5a and once document-wide; `376 B` and `512 B` occur zero times in the document, so A122's clause holds for the per-certificate size; A121, A122 and A123 all read as closed in `TODO.md` and A121's arm is live in `limits.rs` as a per-target label plus a 32-bit inequality; and neither A121's nor A122's `Do` or `Accept` covers a 32-bit arm in `caps.rs`. **Authored here, not reported: the do-not-widen-the-gate instruction, the demand that the remaining gate be explained rather than left, the whole `Accept`, and the `Notes`** — the record named the possibility and its owner and stopped there.

### A131 — The registry parser is trapped two layers deep, and `caps.rs` has copied two formatting helpers rather than reach it
- Milestone: M2
- Size: S
- Deps: after A126
- Discovered by: **D121 §12 (4)** (2026-08-11), which measured the obstacle while refuting shape (a) of A126 and declined to fix it in the same act.
- Problem: `crates/antseal-core/src/anchor/ots/mod.rs:58` declares `mod limits;` **without `pub`**, so nothing outside `anchor::ots` can name `anchor::ots::limits`. That is what made A126's shape (a) cost a duplicated parser rather than a call, and it is the reason `anchor/caps.rs`'s test module carries its own `format_underscored` and its own `format_spaced` — its doc comment says so in its own words: *"Duplicated from `anchor::ots::limits::tests` rather than shared: `ots::limits` is a private module of `ots`, so nothing outside it can name its test helpers, and widening a module's visibility to share eight lines of formatting is the worse trade."* **Measured here, the obstacle is two layers and not one**: `limits.rs:270-271` declares `#[cfg(test)] mod tests` with no `pub` either, and `registry_rows` sits inside it — so making `mod limits` public would still not reach the parser, and any fix that stops at the outer declaration will look like it worked and change nothing. The parser is real work: `registry_rows` is **58 lines** on its own (`limits.rs:581-638`), before the `RegistryRow` type and the `unfenced` helper it consumes, and it is the only code in the tree that turns §5's table into cells.
- Do: decide whether a `#[cfg(test)]` registry-reading helper visible to both modules should exist — one parse with two consumers — and, if so, where it lives and what its visibility is, naming **both** layers so the change is complete. Weigh it as a standing question and not as A126's leftovers: today it is two formatting helpers and one refused parser duplication, and the argument only gets stronger if a third module needs to read the registry. If it is refused, record the refusal beside `caps.rs`'s existing doc comment so the next lane is not re-deriving the same trade. **Do not fold this into A129's checker**: a checker that parses §5a is the second registry parse A126's `Accept` forbids without a ruling, and this row is that ruling's home.
- Accept: the ruling is recorded where a lane about to copy a helper will read it — `caps.rs`'s duplication comment, `limits.rs`'s module head, or both; if a shared helper is adopted, `caps.rs` and `limits.rs` consume one implementation and the visibility change names both `mod limits;` and the inner `mod tests`, shown by the two files compiling with the duplicates deleted; if it is refused, the refusal states what would change the answer; and either way the two files stop disagreeing about how many helpers are duplicated and which.
- Notes: **D121 §12 (4) names the wrong pair.** It says `caps.rs` *"has now duplicated `format_underscored`/`group`"*; measured, the duplicated pair is **`format_underscored` and `format_spaced`** — both exist in both files — and `group` is `caps.rs`'s own local factoring of the two bodies, which `limits.rs` does not have at all. The count *two* in the discovered-work report is right; the names are not, and an executor grepping for `group` in `limits.rs` will find nothing and conclude the report is stale. **The transferable shape** is A106's again: the reason for a duplication is recorded in exactly one of the two files that carry it, so the file a reader opens first tells them nothing.
- **Row and entry authored 2026-08-11 by the wave-15 A/R bookkeeping lane from D121 §12 (4) and the A126 execution lane's report, verified against the working tree before registering.** Verified here, not taken on report: `ots/mod.rs:58` reads `mod limits;` with no `pub`, while the same file `pub use`s selected items from it; `limits.rs`'s `mod tests` is `#[cfg(test)]` and not `pub`; `registry_rows` is declared inside that module and spans 58 lines, counted by brace balance rather than by eye; `format_underscored` and `format_spaced` exist in both files; `group` exists only in `caps.rs`; and `caps.rs`'s duplication doc comment reads as quoted. **Two corrections to the sources, made here**: the two-layer visibility finding, which neither the record nor the report states and which changes what a fix has to touch; and the helper names in D121 §12 (4). **Authored here, not reported: the whole `Do` including the boundary against A129, the whole `Accept`, and the `Notes`.**

### A132 — On `wasm32` the DER structural-cost test reports `ok` while asserting none of the seven figures
- Milestone: M2
- Size: XS
- Deps: after A130
- Discovered by: **the A126 execution lane** (2026-08-11), reported as the fourth of its discovered items.
- Problem: `scripts/wasm-tests.sh` runs `cargo test -p antseal-core --lib --target wasm32-unknown-unknown` — the whole unit suite — and `the_der_structural_cost_column_states_the_derivation_and_its_value` runs there. Both of its figure arms are inside `if core::mem::size_of::<usize>() == 8`, so on `wasm32` the body reduces to the four derivation formulae and the negative `next_pow2` pair, and **all seven byte figures are asserted by nothing**. The test still reports `ok`, under a name that promises the column *"states the derivation **and its value**"*. That is a green that reads as coverage and is not — the same failure direction A123 and A126 filed, and the same one Q184 measured for absorbed self-test mutations: not a wrong answer, an answer to a smaller question than the name asks. Nothing in the file, the lane's output or the registry says the wasm32 half of this instrument is empty.
- Do: make the `wasm32` verdict say what it covers. The cheapest honest shape is a stated skip — an explicit branch that records, in the test's own output or in a comment the lane's reader meets, that the figure arms did not run on this target and why; a stronger one is to split the figure arms into their own `#[cfg]`-gated test so a target that cannot assert them does not report `ok` for them at all. **This is not "add the missing assertions"** — six of the seven have no 32-bit value recorded anywhere to assert against, and the one that does is A130. Settle A130 first so this row is written against the final shape of the gate rather than the current one.
- Accept: reading `scripts/wasm-tests.sh`'s output, or the test source at the gate, answers *"which of the seven figures did this run check?"* without opening a decision record; the native lane's verdicts are byte-identical before and after; and if the split shape is taken, the `wasm32` run's test list no longer contains a name asserting values it did not check.
- Notes: filed `XS` and separately from A130 because the two have different answers: A130 adds the one arm that can be added, and this row is about what the remaining gate **says**. An executor who does A130 and closes this one has left six figures silently unasserted under a green lane, which is the state that produced A126. The general shape is worth more than the instance — **a target-gated assertion inside an ungated test converts "cannot check here" into "checked here"**, and this project has now found it in `caps.rs` twice and in `ots/limits.rs` once, closed there by A121.
- **Row and entry authored 2026-08-11 by the wave-15 A/R bookkeeping lane from the A126 execution lane's report, verified against the working tree before registering.** Verified here, not taken on report: `scripts/wasm-tests.sh:52` runs `cargo test -p antseal-core --lib --target wasm32-unknown-unknown --locked`; the gate is a single `if core::mem::size_of::<usize>() == 8` enclosing both figure arms with no `else`; and the four formula assertions and the `next_pow2` negative pair sit above it and do run on both targets. **Not verified here: the `wasm32` run itself** — `scripts/wasm-tests.sh` was not executed by this lane, and the claim that the test reports `ok` there rather than being skipped follows from the gate being a runtime `if` inside the test body rather than a `#[cfg]` on the test, which is verified. **Authored here, not reported: both shapes in the `Do`, the ordering against A130, the whole `Accept`, and the `Notes`** — the report stated the gate and its consequence in one sentence and named no remedy.

### A133 — A105's `Notes` now contradicts A105's `Accept`, and its milestone constant is stale
- Milestone: M2
- Size: XS
- Deps: after Q203
- Discovered by: **the Q203 lane** (2026-08-11), which corrected A105's `Accept` bullet and reported the sibling bullet it was not scoped to touch.
- Problem: Q203's fix added to A105's `Accept` the measured statement *"`V7.2` already reads `covered`"*. A105's first `Notes` bullet, three lines below and untouched, still opens *"`V7.2` is one of **11** rows `--matrix --milestone M2` names as `deferred` at or before M2 (`V2.3`, `V3.5`, `V6.1`–`V6.6`, `V7.1`–`V7.3`)"*. **Measured against `docs/testing/verification-matrix.md` today: none of those eleven reads `deferred`.** Ten read `covered` and `V7.1` reads `gap`, and the number of rows at or before M2 with status `deferred` is **zero** — every remaining `deferred` row is M3 or M4. The same bullet ends *"`--milestone` defaults to `CURRENT_MILESTONE`, which is **`"M0"`**"*; `scripts/check-traceability.py:274` reads `CURRENT_MILESTONE = "M1"`, moved by D118's own commit. So one entry now tells its executor two incompatible things about the row it is written to serve, and the half a reader is likelier to trust — the `Notes` — is the wrong one.
- Do: correct the `Notes` bullet as a dated correction that quotes what stood there, not as a silent rewrite: the eleven-row claim and the `"M0"` value are **dated measurements** that were true when taken, and the record of their having been taken is worth keeping. State the current figures with their source and without a line number for the constant — the bullet carries none today and must not acquire one. Keep what still holds: `ACCEPTED_NON_COVERED` is still `{}`, and the bullet's conclusion — that a green run says nothing about the M2 review — survives its own reason changing, because the constant is `M1` and not `M2`.
- Accept: no two bullets of A105 disagree about `V7.2`'s status; the eleven-row claim either states today's statuses or is struck with its date; the constant's value is `M1` or is not stated at all; the bullet still carries no line-number citation; and a reader of the whole entry can say what blocks this row without opening the matrix.
- Notes: **registered rather than applied in the bookkeeping act, deliberately.** The Q203 lane scoped itself to the `Accept` bullet and said so; correcting the sibling here would make a bookkeeping lane the author of a measurement, which is the shape D115 §3.6 warns about from the other direction. The transferable point is that this is **propagation, not staleness**: the two halves agreed while both were wrong, and the correction of one is what made the disagreement visible — so a lane fixing one instance of a repeated claim owes a search for the others, which is A106's rule arriving inside a single entry.
- **Row and entry authored 2026-08-11 by the wave-15 A/R bookkeeping lane from the Q203 lane's report, verified against the working tree before registering.** Verified here, not taken on report: the `Accept` bullet's corrected text and the `Notes` bullet's uncorrected text, read side by side in the same entry; each of the eleven cited matrix rows' current milestone and status, parsed from the table rather than grepped; that zero rows at or before M2 read `deferred` and that all seven `deferred` rows are M3/M4; that `CURRENT_MILESTONE` is `"M1"`; and that `ACCEPTED_NON_COVERED` is still an empty dict. **One correction to the report, made here**: it describes the defect as *"stale line number AND stale `"M0"` value"* — measured, this bullet carries **no line number at all**, and the second half of the defect is not a locator but the eleven-row `deferred` claim, which the report does not mention and which is the larger error. **Authored here, not reported: the strike-not-rewrite instruction, the note that the bullet's conclusion survives its reason, the whole `Accept`, and the `Notes`.**

### A134 — A105's provenance exists in two places that disagree about its source, and the proposal is dated after the entry
- Milestone: M2
- Size: XS
- Deps: after Q203
- Discovered by: **the Q203 lane** (2026-08-11), while applying D117's REPLACE arm to the fenced copy in D115 §4.1.
- Problem: A105's provenance is stated twice. `tasks/A.md`'s live bullet reads *"Entry authored **2026-08-10** under Q134 from `TODO.md`'s A105 row, **D115 §4.1's reconstruction**, and the files both name"*; the copy inside D115 §4.1's fenced *"Proposed entry — paste into `tasks/A.md`"* block reads *"Entry authored **2026-08-11** under Q134 from `TODO.md`'s A105 row **alone — no other source existed**"*. They disagree on both facts. **The source claim is circular**: the live entry names §4.1's reconstruction as one of its sources, and §4.1's own copy asserts that no source but the row existed. **The date is inverted**: the block that proposes the entry is dated a day after the entry it proposes, so a reader reconstructing the history is told the paste preceded its own proposal. They also disagree about what was authored versus transcribed — the live bullet claims `Milestone`, the `Spec` line and both `Notes` bullets that the fenced copy does not mention — and about when the citations were re-verified (`2026-08-10` live, `2026-08-11` fenced).
- Do: rule which copy is authoritative for this entry's provenance before correcting either, and record the rule, because the same fenced-proposal shape exists for every entry D115 reconstructed. The likely answer is that the **live entry** is authoritative for what its author did and the fenced copy is a dated proposal that should say so rather than restate authorship — but that is a ruling, and the correction to D115 is a resolved decision's body under D117, which is not this row's file and not the A domain's to apply. Scope this row to `tasks/A.md`'s side and name the D115 side as the other half so it is not lost.
- Accept: A105's live provenance bullet and D115 §4.1's fenced copy do not assert different sources for the same entry; whichever is corrected quotes what it said and is dated; the inverted date is either explained or corrected; and the rule chosen is stated once, where the next reconstructed entry's author will meet it, rather than applied silently to this one.
- Notes: **the interesting half is not the date, it is the source.** *"From the row alone — no other source existed"* is the sentence D115 §4.1 uses to justify how much of A105 it had to author, and the live entry contradicts it by naming §4.1 itself as a source — so the two copies cannot both be describing the same act, and one of them is describing a reconstruction of the other. That is worth a rule, because D115 reconstructed twelve entries under Q134 and this is the first of them anyone has read side by side. Kept separate from A133 because the fix is different in kind: A133 is a stale measurement inside one file, this is an authorship question spanning two, one of which is a resolved decision.
- **Row and entry authored 2026-08-11 by the wave-15 A/R bookkeeping lane from the Q203 lane's report, verified against the working tree before registering.** Verified here, not taken on report: both provenance bullets read in full and compared clause by clause — the two dates, the two source claims, the differing lists of what was authored versus transcribed, and the two re-verification dates; and that D115 §4.1's block is fenced and headed as a proposed paste. **Not verified here: whether the other eleven entries D115 reconstructed carry the same disagreement** — the `Do` names the class on the strength of one instance, which is why it asks for a rule rather than eleven corrections. **Authored here, not reported: the circularity finding, the whole `Do` including the refusal to touch D115, the whole `Accept`, and the `Notes`** — the report named the date inversion and the disagreement and named no remedy.
