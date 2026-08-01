# S — Storage, payments, journal/resume, restore

> Part of the antseal MVP task breakdown (generated 2026-07-27 from MVP-SPEC.md Revision 2 by a 9-agent decomposition).
> **Status tracking lives in `../TODO.md`** — do not add checkboxes here. Treat Do/Accept as normative until deliberately revised; spec line references are into `MVP-SPEC.md` as of 2026-07-27.
> Dep prefixes: P=setup/toolchain/pins, F=CBOR+manifest/bundle codecs, C=crypto primitives, G=canonicalization+units+GGM fine tree, S=storage/payments/journal/restore, A=anchors, R=reveal/verification/web page, U=CLI/vault/config/UX, Q=test-infra/CI/threat-model/docs/release.

### S1 — Re-verify the ant-core =0.5.0 pin and survey the exact payment/storage API shapes
- Milestone: M0
- Size: M
- Deps: P: workspace scaffold with `ant-core = "=0.5.0"` pinned in `antseal-net` (P9 lands the pin; this task surveys the surface)
- Spec: Architecture — key external dependency; Risks & mitigations (MVP-SPEC.md lines 60–69, 179)
- Do: Against the pinned upstream (crates.io `ant-core` 0.5.0 source / docs.rs, WithAutonomi/ant-client repo at the released tag), confirm the pin is still the correct target (spec: re-verify at M0 start) and document the exact shapes of the prepare→pay→finalize surface: `prepare_chunk_payment`, `batch_pay`, `finalize_*`, the external-signer `PaymentIntent` → `finalize_upload(tx_hash_map)` flow, `data_download`, quote types (preimages), `PaidChunk.proof_bytes`, per-payment-tx chunk caps, and what `batch_pay`/tx confirmation returns (does block number come back without a separate RPC call?). Record the verified fact that `data_upload`/`chunk_put` results carry no payment data (`DataUploadResult = {data_map, chunks_stored, payment_mode_used}`) and are therefore excluded. Produce a written API-mapping memo (in-repo design note) that S2/S6/S7 implement against.
- Accept:
  - Memo cites file/line or docs.rs items in ant-core 0.5.0 for every function/type named above, including quote-preimage and `proof_bytes` shapes and multi-tx batching behavior
  - Explicit go/no-go on the 0.5.0 pin recorded (bump, if needed, is a deliberate reviewed event per project rules)
  - Decision inputs for Open decisions 1, 2, and 6 captured (blob/address model, block-number source, per-tx chunk cap)
  - Confirms which flow (native batch_pay vs external-signer PaymentIntent) is driven with the vault-held key, and that both capture tx hashes + quote preimages + proof_bytes
- Notes: Upstream-verification task — do not guess API shapes; read the pinned source. Weekly upstream release cadence means this memo is dated and version-stamped. Also supplies the Autonomi address byte length F4 needs at M0.

### S2 — Define the batch-first `StorageBackend` trait and Blob/CostQuote/PaymentReceipt/Address types
- Milestone: M1
- Size: M
- Deps: S1
- Spec: Architecture (MVP-SPEC.md lines 60–69)
- Do: In `antseal-net`, define `trait StorageBackend` with exactly the four batch-first operations: `quote_batch(&[Blob]) -> CostQuote`, `pay(&CostQuote) -> PaymentReceipt` (one Merkle-batch EVM tx), `finalize_batch(&PaymentReceipt, &[Blob]) -> Vec<Address>` (idempotent over already-stored addresses, resumable, issues no new payment), `get_data(Address) -> Bytes` (async, `thiserror` error enums per failure class: quote, payment, insufficient-ANT, insufficient-gas, finalize, not-found, network). Define `Blob` (ciphertext bytes to upload), `CostQuote` (with quote preimages and total ANT + gas estimate), `PaymentReceipt` (skeleton; contents finalized in S7), and `Address` (convertible to/from `antseal-core`'s plain 32-byte address type). Document the trait as the churn-isolation boundary: all Autonomi storage network use goes through it, and anchor network I/O (OTS/TSA/Arbitrum-receipt HTTP) is explicitly out of scope for this crate.
- Accept:
  - Trait compiles with the four signatures shaped as spec lines 63–66; rustdoc states the pay/finalize split contract (crash between pay and finalize never re-pays; finalize idempotent, issues no new payment)
  - Cargo dependency graph check (CI-enforced) proves only `antseal-net` depends on `ant-core`, and `antseal-net` has no OTS/TSA/esplora/eth-RPC anchor client code or deps
  - Insufficient-token and insufficient-gas are distinct error variants distinguishable by type, not string
  - `Address` round-trips with the `antseal-core` 32-byte representation used in the manifest unit table
- Notes: Blob↔address model (open decision 1) must be settled before freezing `Blob`/`Address`. — **[2026-08-01 planning round]** Settled: **D32** — `Blob` = exactly one chunk, `Address` = BLAKE3-256(ciphertext), `get_data` ↦ `chunk_get`, no data-map path in v1; the types carry the invariant **`Blob.len() ≤ MAX_CHUNK_SIZE` (4 MiB)**, enforced upstream at S12 plan validation before consent/anchor/quote (upstream quotes and pays for unstorable chunks without complaint, so pre-quote enforcement is ours). **D33** — the payment RPC is **in scope** for this crate (it is not anchor HTTP): `pay()` captures the block number from its awaited receipt and owns the `eth_getTransactionReceipt` backfill; the churn-boundary sentence excludes OTS/TSA/esplora anchor I/O, not the payment endpoint. **D37** — the `PaymentReceipt` skeleton is **map-shaped**: per-blob `{address, peer quotes, proof_bytes}` + `HashMap<QuoteHash, TxHash>` + per-tx block-number slots (contents finalized in S7); the error taxonomy reserves distinct slots for the **stranded-payment** and **proofs-expired** states; the Do's spec-quoted "(one Merkle-batch EVM tx)" is a recorded deviation — common case, not contract (`pay` emits ⌈n/256⌉ sequential txs).

### S3 — Implement `MockBackend` with fault injection and call-order logging
- Milestone: M1
- Size: M
- Deps: S2
- Spec: Architecture (MVP-SPEC.md line 69: "Tests run on `MockBackend`")
- Do: In-memory `StorageBackend` impl: deterministic quoting, simulated payment issuing synthetic receipts, per-address store with `finalize_batch` idempotency semantics (already-stored addresses skipped, partial-store supported), and `get_data` serving stored bytes. Fault injection: fail/abort at named points (after quote, after pay before any store, after storing k of n blobs, during get_data), simulate already-stored-by-third-party addresses (zero-cost quote lines), and network errors. Record a full call log (method, args-digest, order) so tests can assert pipeline ordering invariants (e.g. receipt journaled before first finalize call, pay never called twice).
- Accept:
  - All `antseal-net`/pipeline/CLI tests that need storage run on `MockBackend` with no live network
  - Fault injection can reproduce every S16/S18 kill point deterministically
  - Idempotency behavior matches the trait contract: double `finalize_batch` stores nothing twice and returns the same address vector; partial-store then re-finalize stores only missing blobs
  - Call log exposes ordering assertions used by at least one test
- Notes: Mirror any behavior learned in S1/S9 (e.g. zero-cost already-stored quotes) into the mock so mock-first tests stay faithful. — **[2026-08-01, D34 forced sub-finding]** `MockBackend` must be consumable **across a crate boundary**: the orchestration layer lives in `antseal_cli`'s lib target, whose tests drive the pipeline against this mock, and a `#[cfg(test)]` mock is invisible outside its own crate. Export it from `antseal-net` behind a non-default feature (e.g. `test-backend`) that downstream dev-dependencies enable — an S3 packaging note, not a D34 artifact.

### S4 — Deterministic Autonomi address recomputation (BLAKE3-256) inside `antseal-core`
*(re-scoped 2026-08-01 by D32/D35 — formerly "via `self_encryption`"; under D32 a blob is one chunk and its address is BLAKE3-256 of the ciphertext, so `self_encryption` is not involved and D35 forbids depending on it.)*
- Milestone: M1
- Size: L
- Deps: S1; P: the exact-pinned `blake3` workspace dep (P15, landed at this task's execution); C: AEAD ciphertext outputs are the input bytes
- Spec: Architecture crate layout; Core user flows step 1; Cryptography DAG; Reveal bundle storage-linkage layer (MVP-SPEC.md lines 47–51, 34, 90, 119); D32/D35
- Do: Implement, in `antseal-core` (WASM-safe: no I/O, no tokio, no non-deterministic deps), `compute_storage_address(blob_bytes) -> Address` = **BLAKE3-256 of the ciphertext bytes**, using the exact-pinned `blake3` crate alone (default-features off; P15). One blob = one chunk (D32), so there is no chunk-set derivation and no data-map path; an input over `MAX_CHUNK_SIZE` is **rejected by this function with a typed error** — the caller-facing rejection lives upstream at S12 plan validation, this is defense in depth. Called at seal time to compute all ciphertext addresses (every unit, every raw mirror, the encrypted manifest) before `quote_batch`, and the primitive R's offline storage-linkage layer (R20, M3) uses to check that a bundle's embedded ciphertext derives the manifest's recorded address. Note the spec's lines 34/51/110/119 say "via self_encryption" — the D32-recorded deviation covers this; do not restate self_encryption semantics anywhere.
- Accept:
  - Golden vectors: fixed input byte strings spanning tiny (smallest padded unit ciphertext, 272 B), mid, the max plaintext-derived ciphertext at the cap edge, and exactly `MAX_CHUNK_SIZE` map to committed expected addresses; **cap + 1 is a committed rejection case** (typed error, no address exists in v1)
  - `cargo build --target wasm32-unknown-unknown` for `antseal-core` still passes; native and WASM outputs bit-match on the vector set
  - Deterministic: same bytes → same addresses across runs/platforms (property test)
  - Address equality against real ant-core-assigned addresses is asserted later by S9/S17 (cross-referenced test IDs exist)
  - No I/O, tokio, or RNG reachable from this module (compile-target + dependency audit); no `self_encryption` anywhere in any antseal crate's direct deps (P15's CI prohibition)
- Notes: The address rule and cap are pinned against upstream source by S9 (`ant_protocol::MAX_CHUNK_SIZE = 4_194_304`, BLAKE3-256 per ant-protocol chunk.rs); F's M0 manifest golden vectors may use synthetic addresses until this lands. — **[2026-08-01 EXECUTED (lane δ)]** Landed as `antseal_core::storage` (`compute_storage_address`, `MAX_CHUNK_SIZE`, typed `ExceedsChunkCap`). Execution notes: (1) constant home — core owns `MAX_CHUNK_SIZE` (citation-pinned); `antseal-net::MAX_CHUNK_SIZE` is now an alias over net's existing core dep edge plus a cross-crate equality test in net's blob.rs, so the two cannot drift; (2) the golden vectors landed as a new Q4 kind `storage-address` — a post-freeze kind addition via the Q6 append flow (new `#! kind` line + new digest line, no existing digest moved; the same path reserved for M2's `anchor` kind); (3) the entry's "fixed input byte strings" are committed **generatively** (pattern `i % 251` — the official BLAKE3 test-vector input pattern — plus a length): literal 4 MiB rungs would put ~25 MiB of hex in the file and blow D87's 2 MiB embedded budget; the bytes are still fixed and independently reproducible; (4) ladder = 0 / 272 / 65 552 / 4 194 047 (max unit plaintext) / 4 194 064 (max plaintext-derived ciphertext) / 4 194 304 (cap edge) accepted, + 4 194 305 committed rejection — two rungs more than the entry asked; (5) native↔wasm32 bit-match rides the existing wasm-bitmatch harness with zero wiring (a kind executor is the harness's unit of coverage — the entry's lib-test fallback was not needed); (6) the no-RNG half of the dependency audit is a new `getrandom|rand|rand_chacha` ban in `scripts/ci-lanes.sh dep-graph` (`rand_core`, the pure trait crate, deliberately unbanned); (7) independent generation: `testdata/vectors/v1/storage/gen_vectors.py` is a pure-Python spec-derived BLAKE3 anchored to the official empty-input vector, agreeing byte-for-byte with the P15-validated crate on all rungs (~18 s in the cross-check lane — the slowest generator, noted in its README).

### S5 — Network selection mapping: arbitrum-one / arbitrum-sepolia / devnet
- Milestone: M1
- Size: M
- Deps: S1; P: devnet environment (P16/P17) available; U: `--network` CLI flag wiring
- Spec: MVP scope decision 4; CLI surface global flags (MVP-SPEC.md lines 20, 149)
- Do: In `antseal-net`, implement a `NetworkConfig` mapping the three network identities — `arbitrum-one` (default, mainnet), `arbitrum-sepolia` (Arbitrum Sepolia, chain 421614 — not Ethereum Sepolia), `devnet` (local 25-node + Anvil) — to EVM chain id, payment-token and data-payments contract addresses, EVM RPC endpoint, and Autonomi bootstrap/peer configuration for backend construction. Mainnet/sepolia values come from ant-core/evmlib's built-in network definitions (verify against pinned upstream); devnet reads the environment/config emitted by upstream's `start-local-devnet` example (verify the exact env-var/contract-discovery mechanism against the upstream example at execution time). Also implement the EVM wallet key operations U's `init` consumes (U11): secp256k1 keypair generation from the OS CSPRNG, private-key import validation (formats per D44), and wallet address derivation — over the same pinned evmlib/alloy stack ant-core uses, so generated/imported keys are valid for the payment path.
- Accept:
  - Wallet ops: a generated key derives a valid address and signs a devnet payment; malformed import material is rejected with a typed error; key bytes are only ever exposed via C's zeroizing types
  - Unit tests pin chain id 421614 for arbitrum-sepolia and the mainnet default; constructing a backend for each network yields the documented contract/RPC/peer config
  - Devnet config successfully connects the real backend in S17's E2E; sepolia config is exercised by Q's M4 gate without code change
  - Config values traced to pinned upstream sources (evmlib network definitions, devnet example scripts) in comments/docs
  - Unknown network name is a hard error; default is arbitrum-one
- Notes: Upstream-verification need: exact devnet env-var names and contract-address plumbing from the `start-local-devnet` example at ant-core 0.5.0 (per the P16 memo the example ships inside the pinned crate archive, and the environment surface is read from the repo-local `.devnet/` manifest). — **[2026-08-01] D44 resolved the import formats: raw hex private key only in v1** — 64 hex digits, optional `0x`, case-insensitive, k256 scalar-validated — with the accepted set defined as **"whatever the pinned evmlib/alloy parse accepts"** (evmlib wallet.rs:72-75 / alloy private_key.rs:224-230), so validation ≡ payment path by construction. Test set per D44: both `0x`-prefixed and bare forms accepted; rejected with typed errors — wrong length, non-hex, out-of-range scalar (≥ the k256 group order), zero scalar, surrounding whitespace, and a mnemonic phrase (distinct "not supported in this version" error whose copy U11 owns). Mnemonic import is a recorded v1 rejection with a revisit trigger, not a gap.

### S6 — Implement the ant-core `StorageBackend` over prepare→pay→finalize in one adapter file
- Milestone: M1
- Size: L
- Deps: S1, S2, S4, S5; U: vault-held Arbitrum wallet key handle (custody U's, U10)
- Spec: Architecture (lines 60–69); Milestones M1 (MVP-SPEC.md lines 60–69, 154)
- Do: Implement `AntCoreBackend` in a single impl file (churn containment): `quote_batch` via `prepare_chunk_payment`-class quoting over the chunk addresses derived from each Blob (consistent with S4; assert every blob ≤ `MAX_CHUNK_SIZE` at entry — plan validation upstream should make this unreachable, defense in depth per D32); `pay` via the external-signer flow as primary (per S1/D37), driven with the vault-held key, emitting **⌈blobs/256⌉ sequential EVM txs journaled per sub-batch as each lands** (D37) and capturing the block number from each awaited tx receipt (D33); **`Client::batch_pay` is forbidden even as the native fallback** — its error path discards the partial paid map, converting a mid-sequence failure into stranded payments; if the native path is ever used, drive `Wallet::pay_for_quotes` directly (D37 ruling 2); **merkle payment mode is excluded from the paid path** (its proofs/results carry no tx hashes, D37 ruling 1); `finalize_batch` via the `finalize_*` surface, uploading ciphertexts and skipping already-stored addresses with no new payment — it consumes the receipt's quote→tx **map** and errors on any gap; `get_data` via **`chunk_get`** returning the single chunk (D32: blob = one chunk; no `DataMap`, no reassembly). Explicitly do not use `data_upload`/`chunk_put` (their results carry no payment data). Map ant-core errors into the S2 taxonomy, including the stranded-payment and proofs-expired slots.
- Accept:
  - On local devnet: quote → pay → finalize → get_data round-trips a multi-blob batch; fetched bytes are byte-identical to uploaded blobs
  - `finalize_batch` called twice with the same receipt/blobs performs zero additional payment (Anvil tx count unchanged) and re-stores nothing already stored
  - Grep/CI check: no `data_upload`/`chunk_put`/`batch_pay` call sites; ant-core usage confined to the one adapter file
  - Batches exceeding the 256-transfer per-tx cap succeed as the sequential sub-batch protocol with **every** quote mapped to a tx hash (gap = typed error) and the per-sub-batch journal write ordered before the next sub-batch's submission (call-log asserted on the mock twin)
  - Addresses returned by `finalize_batch` equal S4's precomputed addresses for the same blobs (asserted in-test)
  - A blob over the plan-time cap is rejected at the adapter boundary with a typed error (defense-in-depth path tested)
- Notes: External-signer API is driven programmatically with the vault key — user-facing external-signer wallets stay parked per spec. D37's sub-batch journaling contract is what makes a kill between sub-batch txs recoverable (S16/S18 rows).

### S7 — PaymentReceipt content completeness and instant-capture semantics
- Milestone: M1
- Size: M
- Deps: S1, S2, S6; U: vault record persistence API (U9). *(The former "A: Arbitrum RPC client (if open decision 2 lands there)" dep is deleted — D33 landed capture in `antseal-net::pay()`; `antseal-anchor` gets zero M1 work and A17 is a consumer, never a capturer.)*
- Spec: Architecture; Anchoring — Arbitrum receipt; Core user flows step 1; Vault/journal (MVP-SPEC.md lines 69, 110, 34, 145); D33/D37
- Do: Finalize the `PaymentReceipt` type per **D37** to carry, from day one, everything the v1.1 receipt-verification chain needs so no reseal is ever required: per-blob `{address, peer quotes (full preimages), proof_bytes}`, the **quote_hash → tx_hash map** (`HashMap<QuoteHash, TxHash>` — what `finalize_batch_payment` consumes; a bare `Vec<TxHash>` can neither rebuild proofs nor resume finalize), and per-tx **block-number slots** — captured per **D33** inside `pay()`: in the primary external-signer flow from the very tx receipt `pay()` awaits; in the native-fallback and crash-backfill paths via `eth_getTransactionReceipt` over the payment RPC (`ant_protocol` `http_provider` re-export). Plus deterministic serde for per-work vault persistence (record layout itself is U's). Enforce the capture timing contract in the pipeline: the receipt is journaled **per sub-batch as each tx lands** (D37), strictly before any `finalize_batch` network call; the journal write of the tx-hash-bearing receipt must never be delayed or blocked by block-number enrichment (enrichment retries idempotently if the RPC read fails).
- Accept:
  - Round-trip serde test proves no field loss for multi-tx receipts; a completeness checklist test asserts all element classes (per-blob triple, quote→tx map, block-number slots) are populated after a devnet pay
  - Multi-tx test drives **≥ 2 sub-batches** (mock-forced sub-batch size) and asserts the map covers every quote across both txs, with per-sub-batch journal writes in submission order
  - Capture-consistency test: the journaled `proof_bytes` deserialize via upstream's own `deserialize_proof`-class surface and agree with what `finalize_batch` accepts — proving captured bytes are the bytes finalize needs, not a lookalike
  - Mock call-log test: receipt persisted (persistence hook invoked) before the first finalize call in every path, including resume
  - RPC-enrichment failure after pay still leaves a journaled receipt with tx hashes; a subsequent invocation backfills block number without any new payment
  - No receipt field appears in logs or error messages (wallet-linkability hygiene)
- Notes: Verification chain (recompute addresses ↔ quote preimages ↔ tx calldata) is v1.1 and out of scope; only capture completeness is MVP. Wallet-linkability doc treatment is A/Q's.

### S8 — ANT + ETH balance queries and payment preflight with distinct shortfall errors
- Milestone: M1
- Size: M
- Deps: S2, S5, S6; U: consent-screen rendering of balances beside the quote (U14)
- Spec: Core user flows step 1 — permanence consent (MVP-SPEC.md line 34)
- Do: In `antseal-net`, expose ANT (ERC-20) and ETH (gas) balance queries for the configured wallet/network, and a preflight that compares the complete `CostQuote` (storage ANT + estimated gas for the batch payment tx(s)) against both balances, returning the distinct `InsufficientAnt` vs `InsufficientGas` errors. Guarantee the quote handed to U's consent step is the true, complete cost: it covers every blob that will be finalized (all units, raw mirrors, encrypted manifest) with no post-consent payment ever exceeding it.
- Accept:
  - Devnet tests: draining ANT (resp. ETH) below the requirement yields the token (resp. gas) error variant; both are distinct types with actionable messages (no secrets, no key material)
  - Preflight-passed seal on devnet completes payment without further shortfall; actual paid amount ≤ quoted amount (asserted via Anvil balance deltas)
  - Balance/preflight results exposed as structured data consumable by U's consent UX and `--json`
- Notes: Gas estimation source (evmlib estimate vs static margin) verified against pinned upstream at execution time.

### S9 — Pin MAX_CHUNK_SIZE and the chunk-address rule against the real API
*(re-scoped 2026-08-01 by D32 — the self-encryption thresholds left the model with the data-map path; the constants that remain are the chunk cap and the BLAKE3-256 address rule.)*
- Milestone: M1
- Size: M
- Deps: S4, S6; P: devnet (P16)
- Spec: Milestones M1 (MVP-SPEC.md line 154); D32/D37
- Do: Write golden tests that freeze the storage-relevant constants and behaviors of the pinned upstream: **`ant_protocol::MAX_CHUNK_SIZE = 4_194_304`** (cited to the pinned source), the derived **max unit plaintext 4_194_047 B** (cap minus padding/AEAD overhead — assert the derivation, not just the number), the chunk address rule (BLAKE3-256 of content, = S4), and record **`QUOTE_MAX_AGE_SECS` (~24 h node-side proof validity, D37's resume time-box)** as a pinned constant with its source citation so an upstream change surfaces as a test diff. For a size ladder — 272 B (smallest padded-unit ciphertext), mid, the max-plaintext-derived ciphertext, the exact cap edge — store via the real `AntCoreBackend` on devnet and assert the network-assigned addresses byte-match S4's WASM-safe recomputation; assert **cap + 1 is rejected at plan validation** and never reaches the network.
- Accept:
  - Constants asserted in tests with citations to the ant-core/ant-protocol 0.5.0-pinned source (`MAX_CHUNK_SIZE`, the max-plaintext derivation, `QUOTE_MAX_AGE_SECS`); a deliberate upstream bump is the only way these tests change
  - Devnet address-equality test green across the full ladder (272 B / mid / max-plaintext ciphertext / cap edge); **cap + 1 asserted rejected** with the distinct plan-validation error, zero network calls
  - `get_data` on each stored size returns byte-identical blobs
  - Divergence between S4 recomputation and real network addresses fails CI with a distinct error naming the size class
- Notes: This is the M1-mandated upstream-verification task; execute against the real pinned API, never from memory.

### S10 — Seal journal: staged ciphertext bytes persisted before payment, with state machine
- Milestone: M1
- Size: M
- Deps: S2, S4, S7; U: encrypted vault record storage API (U9); C: unit ciphertexts + nonces from the encryption step
- Spec: Core user flows step 1; Vault — seal journal (MVP-SPEC.md lines 34, 145)
- Do: Define the journal record content and write points (vault layout/encryption is U's): before payment, persist the staged ciphertext bytes of every unit plus each unit's nonce and target address (and the encrypted-manifest blob + its address), together with the built plaintext manifest and `seal_id`. Per **D36**, the journal also gains a **consent record** `{total_ant_atto, gas_estimate, consent_time, channel: interactive|yes-flag}` written at every affirmative consent — a display-only baseline for resume renders (the journaled `CostQuote` is never a payment input: a journaled quote is never paid). Define the per-work state machine — staged → anchored → paid (receipt journaled per sub-batch, D37) → finalizing → complete, plus abandoned — with transition writes at each pipeline barrier: staged bytes durable before the anchor gate, receipt durable the instant each pay tx lands and before any finalize call. Per **D43**, the `complete` transition performs the explicit **journal → cache reclassification write** (state tag only, same bytes, no byte move); cache-state bytes are integrity-rechecked on use and their loss is never an error (journal-state bytes remain resume-critical). Expose journal state via a library API (`incomplete` works enumerable; rendering in `list` is U's).
- Accept:
  - Pipeline refuses to call `pay` unless staged bytes + nonces + addresses are durably journaled (mock-enforced ordering test)
  - Journal round-trip restores byte-identical staged ciphertexts; a staged-bytes integrity check (recompute address via S4, compare to journaled target) detects corruption and classifies the work as staged-bytes-unavailable
  - Receipt-journaled-before-finalize ordering asserted via mock call log
  - No plaintext unit bytes, `W`, `k_u`, or salts in the journal beyond what the spec mandates (staged ciphertexts, nonces, addresses); journal content never logged
- Notes: Nonces in the journal duplicate the manifest's authoritative copy for resume use only; single-use `(k_u, nonce)` enforcement is S11's guard.

### S11 — Resume: byte-identical re-upload, finalize with recorded receipt, and the abandon guard
- Milestone: M1
- Size: L
- Deps: S6, S10; S4 (integrity check); A: re-running the anchor gate for pre-anchor kills (A1 stub at M1; full gate A20 at M2); U: re-consent hook signature (U17 is the CLI consumer)
- Spec: Vault — seal journal; Milestones M1 (MVP-SPEC.md lines 145, 154)
- Do: Implement resume over the S10 state machine for every kill point: pre-anchor (re-run anchor submission via A, then continue), post-anchor/pre-pay (**always re-quote — a journaled quote is never paid — and unconditionally re-consent** via U against the fresh quote, per **D36**; the prior "if cost changed" conditional is overturned, and consent is a single-use spend authorization consumed by the `pay()` it immediately precedes in the same process invocation), post-pay/pre-finalize (call `finalize_batch(recorded_receipt, staged_blobs)` to store not-yet-stored chunks with no new payment — via the public API surfaces: re-prepare for any unpaid quotes and the `chunk_put_with_proof`-class path for paid ones, per D37), mid-finalize (same idempotent call). **Post-pay resume is time-boxed** (D37): node-side proofs expire after ~24 h (`QUOTE_MAX_AGE_SECS`) — an expired-proof resume surfaces the distinct **proofs-expired** state and requires re-consent before any re-payment (the D36 rule applied). Declining any resume consent leaves the work **incomplete, never abandoned** (decline ≠ abandon). Resume re-uploads only the byte-identical staged ciphertexts, never reads source files, never re-encrypts, and never rebuilds or re-signs the manifest (it is anchored pre-pay). If staged bytes are unavailable or fail the S4 integrity check, the seal is abandoned: the work is marked abandoned, any payment is forfeited, and a fresh seal starts with a new `seal_id` and freshly drawn nonces — the journaled nonce table is never reused (a `(k_u, nonce)` pair encrypts exactly one plaintext, ever).
- Accept:
  - Mock tests per kill point: resume completes the seal; `pay` is never invoked when a receipt is journaled; finalize issues no new payment; uploaded bytes equal staged bytes
  - Changed-source test: mutating source files after staging has zero effect on resumed uploads (source never read)
  - Abandon test: with staged bytes deleted/corrupted, resume returns a distinct abandoned error, marks the state, and no encryption call is ever made with a journaled nonce (asserted via C-layer instrumentation/test double)
  - Resume never invokes manifest build or signing code paths (call-log assertion)
  - Post-anchor/pre-pay resume **always** re-quotes and the consent hook **always** re-fires against the fresh quote; the quote object passed to `pay` is asserted identical to the one consent affirmed (pay-arg identity, D36)
  - Consent decline on resume → work stays incomplete (no abandon, no state loss); proofs-expired state surfaced distinctly with re-consent required before re-payment (mock clock)
- Notes: Abandonment forfeits payment by design (safety over cost, spec-mandated); requires disk loss of staged bytes after pay — document as rare. The ~24 h post-pay resume window is a user-facing fact (U19's nag carries it).

### S12 — Seal pipeline orchestration: normative order, complete blob set, ciphertext-only egress
- Milestone: M1
- Size: L
- Deps: S2, S4, S7, S8, S10; G: canonicalization + unit splitting outputs (G14); C: key derivation/AEAD/padding; F: manifest build/encode + encrypted-manifest blob; A: anchor-gate step (A20; stub interface for M1 via A1); U: consent-hook signature only (U13/U14 are the CLI consumers)
- Spec: Core user flows step 1; Cryptography — pipeline DAG; Milestones M1 (MVP-SPEC.md lines 34, 90–91, 154)
- Do: Implement the seal pipeline as library code in **`antseal_cli`'s `[lib]` target per D34** (orchestration over injected interfaces — StorageBackend, the A1 anchor gate, lib-defined ConsentHook/SealJournal; `main.rs` stays a thin driver; library-drivable for the M1 E2E by construction) enforcing the normative order — **plan validation** (per **D32**: every blob's projected ciphertext ≤ `MAX_CHUNK_SIZE`, hard error before consent/anchor/quote, and for an over-cap *text* file the error suggests `--split`; plus D46's argument checks on the CLI side) → canonicalize → encrypt units (journaled) → build + sign manifest → encrypt manifest → compute all ciphertext addresses via S4 → `quote_batch` over the full blob set → consent hook → anchor gate → `pay` → journal receipt instantly (per sub-batch, D37) → `finalize_batch` → return work-id + final cost (printing is U's). Every cheap failable step precedes the one irreversible paid step; anchor failure aborts with zero money spent. The blob set passed to the backend is exactly: all unit ciphertexts (including raw mirrors) + the encrypted manifest — nothing readable ever leaves the machine. Instrument named fault-injection barriers at every step boundary for S16/S18 kill tests, **including the D49 truncation barrier immediately after `quote_batch`** — dry-run is this same pipeline truncated at that barrier, not a parallel mode.
- Accept:
  - Ordering test (mock call log): quote covers the full blob set including the encrypted manifest; no backend call precedes journaling of staged bytes; pay precedes any finalize; receipt journal precedes finalize; anchor-gate failure aborts before pay with no EVM tx
  - Plan-validation test: an over-cap blob fails before any journal write, consent render, anchor submission, or backend call; the text-file variant names `--split` in the error
  - Type/test-level guarantee that only AEAD ciphertext blobs reach `StorageBackend` (no plaintext unit bytes, no plaintext manifest)
  - `--dry-run` executes through quoting with zero anchor submission, zero payment, zero upload — and zero journal writes (D49)
  - Addresses recorded in the manifest unit table equal the finalize-returned addresses (devnet assertion via S17)
  - Fault-injection barriers exist at: post-plan-validation, post-quote (the D49 truncation barrier), post-journal, post-anchor, post-pay-pre-receipt-journal (must be unreachable/atomic), post-receipt-journal-pre-finalize, mid-finalize
- Notes: The receipt-journal-then-finalize gap is the crash window the design exists for; the pay→journal step must be as atomic as the vault API allows. **[D49, 2026-08-01] Invariant scoping, rustdoc-mandated**: the journal-before-backend invariant is scoped to the **paid path** — under `--dry-run` the journal is disabled and `quote_batch` is the only backend call; the invariant's rustdoc must state this scoping explicitly so the S12↔U16 contradiction D49 found cannot be reintroduced by a literal reading.

### S13 — `--no-anchor` zero-anchor seal path with mainnet rejection guard
- Milestone: M1
- Size: S
- Deps: S12; U: `--no-anchor` flag surface (U13); F: UNANCHORED representable in manifest/bundle formats (empty-anchor vectors, F13); A: anchor-gate skip interface (A1)
- Spec: CLI surface; Milestones M1 (MVP-SPEC.md lines 149, 154)
- Do: Add the dev-only zero-anchor mode to the pipeline: it skips the minimum-anchor policy entirely (no OTS, no TSA, no gate) and produces a seal representable in all formats as UNANCHORED. Enforce at pipeline level (defense in depth beneath U's CLI check) that `--no-anchor` combined with network `arbitrum-one` is rejected before any quote/payment, so it can never mint a permanent mainnet seal bypassing the anchor gate.
- Accept:
  - Devnet/sepolia zero-anchor seal completes end-to-end and library-verifies as UNANCHORED (consumed by S17)
  - Pipeline-level test: no-anchor + arbitrum-one returns a distinct error with zero network side effects, even when invoked via library API (CLI bypass impossible)
  - No anchor-submission call occurs in no-anchor mode (mock/A-double call log)

### S14 — Implement `restore <work-id> [-o dir]`
- Milestone: M1
- Size: M
- Deps: S5, S6; C: `k_u`/`k_m` derivation, AEAD decrypt, padding strip; G: canonicalization descriptor semantics; F: manifest decode; U: vault records API (U9; U20 is the CLI consumer)
- Spec: Core user flows step 4; Vault (MVP-SPEC.md lines 37, 141–143)
- Do: Implement restore as library + pipeline code (orchestration home = the `antseal_cli` lib target per D34): resolve the work's manifest (vault copy, or fetch the encrypted manifest by journaled address and decrypt with `k_m`), fetch every unit ciphertext via `get_data` (↦ `chunk_get` — one blob is one chunk, no `DataMap`, per D32), decrypt with vault-derived keys, strip padding by manifest `true_length`, and verify content before writing: full-file concatenated non-mirror units against `canon_commit` (text) / `raw_commit` (binary), raw-mirror bytes against `raw_commit`. **Network-first with verified-cache fallback (D43 amendment, ratified at integration 2026-08-01)**: the fetch path stays normative — it is what the M4 disk-loss drill proves — but when a `get_data` fetch fails and a D43 cache copy exists, use the cache copy; commitment verification runs on every unit regardless of source, so the fallback costs no trust, and after an Autonomi data loss the cache is the only remaining copy. Write original files into `-o dir` using vault-recorded paths (default dir + lexical re-rooting + overwrite policy are U20's per D48), preferring raw-mirror bytes wherever one exists so the user gets exact original bytes (CRLF/BOM/NFD intact); fall back to canonical bytes otherwise. Per **D48**, the byte-aware collision comparison compares the existing file against **the exact bytes restore would write** — the raw-mirror-preferred output — never against canonical bytes when a mirror exists. Must work on a clean machine from a vault backup alone — no staged data, no local source tree (the M4 drill is Q's gate; the capability is this task).
- Accept:
  - Devnet round-trip: sealed files (including a CRLF/BOM file with raw mirror, a binary file, and a `--split` multi-unit text file) restore byte-identical to the originals
  - Commitment mismatch on any fetched unit yields a distinct error and the affected file is not written as verified output
  - Fetch-failure fallback test (MockBackend fault injection): with the network copy unavailable and a valid cache copy present, restore succeeds through the cache with full verification; with both unavailable, the not-found error surfaces
  - Restore succeeds with only `vault import`ed state on a clean tree (proven in S19 — note the export excludes cache, so the clean-tree path exercises pure network-first)
  - Not-found/network errors from `get_data` surface distinctly from decryption/commitment failures; no key material in errors or logs
- Notes: Restore verification consumes C/G recompute primitives — emit no commitment code here.

### S15 — `--live` persistence-check primitive: re-fetch and byte-compare
- Milestone: M1
- Size: S
- Deps: S6 (S3 for offline tests)
- Spec: Core user flows step 5; Reveal bundle — storage-linkage layer; Verification M1 (MVP-SPEC.md lines 38, 119, 172)
- Do: Provide a library primitive in `antseal-net` taking `[(Address, expected_ciphertext_bytes)]`, re-fetching each via `get_data`, and byte-comparing against the expected copies, returning a per-blob persistence report (present-and-identical / present-but-different / not-found / fetch-error). R's M3 `verify --live` orchestrates this over bundle-embedded ciphertexts (R11/R21); M1 E2E drives it directly via library API. CLI-only by design — the WASM page has no network layer.
- Accept:
  - Devnet test: freshly sealed blobs report present-and-identical; a never-uploaded address reports not-found; a corrupted expectation reports present-but-different
  - Report is structured data (usable by R's verdict rendering and `--json`)
  - Primitive lives behind `StorageBackend` only — compiles with `MockBackend` for offline tests
- Notes: R11 is the verify-side wrapper over this primitive — implement once here, consume there.

### S16 — Mock-level pipeline invariant matrix: ordering, idempotency, no-double-pay
- Milestone: M1
- Size: M
- Deps: S3, S10, S11, S12
- Spec: Architecture — payment-boundary split; Vault — seal journal (MVP-SPEC.md lines 69, 145)
- Do: A deterministic `MockBackend` test matrix (fast, CI-default, no devnet) covering every pipeline barrier from S12's fault-injection points: kill at each barrier → resume → assert exactly one simulated payment ever occurs, staged bytes re-uploaded byte-identical, finalize idempotency over partial stores, receipt-journal-before-finalize ordering, pay-never-repeated when a receipt exists, and abandon-on-missing-staged-bytes. **D37 row**: kill **between sub-batch txs** of a multi-tx payment → resume → each sub-batch paid exactly once, the quote→tx map complete at the end, per-sub-batch journal order preserved. **D36 rows (four)**: (i) a resumed invocation performs `quote_batch` before `pay` (call log); (ii) the consent-hook call sits between them in the same invocation; (iii) `pay`'s quote argument identity-matches that `quote_batch` return; (iv) consent-decline on resume → no `pay`, no state transition (work stays incomplete, never abandoned). **D49 row**: `--dry-run` performs zero journal writes and exactly one backend call (`quote_batch`) — the journal-before-backend invariant is scoped to the paid path. Property-test the resume state machine: any interleaving of kills and resumes ends in complete or abandoned, never in a re-encryption or double payment.
- Accept:
  - One test per fault-injection barrier plus the property test, all green in default CI with no network; the D37 sub-batch row, the four D36 rows, and the D49 dry-run row present and individually named
  - A seeded proptest shrink case is committed as a regression fixture for any failure found
  - Assertions read the mock call log (not timing) so the matrix is flake-free
- Notes: This is the cheap mirror of S18; both must exist (mock for CI determinism, devnet for reality).

### S17 — M1 E2E on local devnet: scripted happy path, UNANCHORED verify, `--live`
- Milestone: M1
- Size: L
- Deps: S6, S12, S13, S14, S15; P: `start-local-devnet` scripted/reachable (P16); R: M0 library verification entry (R5); F: manifest/bundle library APIs; Q: CI job wiring (Q15)
- Spec: Milestones M1; Verification M1 (MVP-SPEC.md lines 154, 172)
- Do: Build the scripted E2E harness that boots/attaches to the local devnet and drives everything via library APIs (the `verify` CLI, bundle builder, and page are M3 — do not depend on them): multi-file seal with `--split` (text multi-unit + binary + raw-mirror file), fetch back, `restore`, and library-verify; a zero-anchor `--no-anchor` seal that library-verifies as UNANCHORED; and the `--live` re-fetch check passing against the just-sealed work. Assert manifest-recorded addresses equal both S4 precomputation and finalize-returned addresses, and that total ANT spent equals the consented quote.
- Accept:
  - Single scripted entry point (per-test isolation, deterministic seeds where applicable) runs green against a fresh devnet
  - Uses only library APIs — grep proves no M3 CLI/bundle-builder invocation (per D34 the library being driven is `antseal_cli`'s lib target over injected interfaces — the same code path the CLI runs, minus `main.rs`)
  - UNANCHORED library verdict asserted on the no-anchor seal; anchored path stubbed/skipped (anchors are M2)
  - `--live` primitive reports present-and-identical for every blob of the sealed work
  - Runs per **D52** (resolves the former "Runs in CI (scheduled or gated job per Q's infra)" line): as the **required local gate** (`scripts/e2e-devnet.sh`, mandatory before merging storage-touching changes, scripted evidence per the Q14 pattern) plus Q15's **scheduled, non-required hosted lane** at reduced node count; documented local invocation for developers
- Notes: Anchor steps are stubbed via A's interface in M1 (real anchor smoke tests are M2/A's).

### S18 — M1 E2E kill/resume matrix on devnet: no-double-pay, byte-identical re-upload, changed-source abandon
- Milestone: M1
- Size: L
- Deps: S11, S16, S17
- Spec: Milestones M1; Verification M1; Vault — seal journal (MVP-SPEC.md lines 154, 172, 145)
- Do: Extend the S17 harness with the spec's kill tests against the real devnet: (1) kill between `pay` and `finalize_batch` → resume → verify no double payment by counting payment txs on Anvil and asserting the ANT balance delta equals the quote exactly once; (1b, **D37**) drive a batch large enough for **≥ 2 sub-batch txs** and kill **between sub-batch txs** → resume → **exactly one tx per sub-batch on Anvil**, no sub-batch ever re-paid, quote→tx map complete at the end; (2) kill mid-upload (partway through finalize) → resume → verify the network copies are byte-identical to the staged ciphertexts (fetch every address and compare); (3) the `(k_u, nonce)`-reuse guard: change the source files and make staged bytes unavailable → resume must abort/abandon with the distinct error, and instrumentation proves no encryption ever runs with a journaled nonce; additionally, changed source with staged bytes intact resumes successfully from staged bytes alone. Use both S12 fault-injection barriers (deterministic) and at least one real process SIGKILL (realism).
- Accept:
  - Anvil-verified: exactly one payment tx across kill+resume in case (1); resume path never constructs a second payment
  - Case (1b): tx count on Anvil equals the sub-batch count exactly across the kill+resume; the balance delta equals the quote once
  - Case (2): every fetched blob byte-equals its staged ciphertext; resumed run performed no re-encryption (call instrumentation)
  - Case (3): distinct abandoned error, journal state `abandoned`, fresh-seal path draws a new `seal_id` and fresh nonces (asserted ≠ journaled values)
  - Real-SIGKILL variant of at least case (1) passes (crash-consistency of the journal write itself is exercised, not just clean early-returns)
- Notes: **[D37]** post-pay resume is time-boxed by the ~24 h node-side proof validity (`QUOTE_MAX_AGE_SECS`, pinned at S9) — the devnet matrix runs well inside the window; the expired-window path (proofs-expired state + re-consent) is exercised at S16 with a mock clock, and the user-facing window is documented at U19/S11.

### S19 — M1 E2E clean-tree restore from vault backup only
- Milestone: M1
- Size: M
- Deps: S14, S17; U: `vault export`/`import` (U12)
- Spec: Core user flows step 4; Verification M1 (MVP-SPEC.md lines 37, 172)
- Do: In the E2E harness: seal a work on devnet, `vault export`, then simulate a clean machine (fresh HOME/config dir, empty working tree, no staged data, no source files), `vault import`, and run `restore` — everything must come from the vault backup plus the network. Verify restored files byte-match the originals recorded out-of-band by the harness (raw-mirror files restore their exact original bytes).
- Accept:
  - Restore succeeds with only the imported vault + devnet reachable; harness proves no other local state was read (isolated tmp dirs)
  - Byte-identical comparison passes for text (with CRLF/BOM original), binary, and multi-unit files
  - A second run with the vault absent fails with a clear no-vault error (negative control)
- Notes: This is the M1 capability proof; the M4 disk-loss drill against the released binary + real networks is Q's gate (Q32) and reuses this flow.

### S20 — Continuous churn watch: ant-core bump impact procedure for the adapter boundary
- Milestone: continuous
- Size: S
- Deps: S2, S6; P: pin/dependency mechanics and weekly bump-check cadence (P19); Q: CI
- Spec: Architecture; Risks — ant-core churn; Milestones M4 post-release chore (MVP-SPEC.md lines 60, 179, 157)
- Do: Establish and follow the deliberate-bump procedure for `ant-core` (and `self_encryption`) version changes: every proposed bump is a reviewed event that must confine code changes to the single adapter impl file (plus S1-memo/S9-constant updates), re-run the S9 threshold pinning and S17/S18 devnet E2E, and leave the `StorageBackend` trait and all `MockBackend`-based tests unchanged. Reject drive-by bumps.
- Accept:
  - Written procedure in-repo; CI dependency-graph and adapter-file-containment checks stay green across any bump PR
  - S9 constants tests and devnet E2E are mandatory bump-PR gates
  - Trait signature or mock-test changes in a bump PR require explicit spec-flagged justification
- Notes: P owns the pin itself and the weekly check cadence (P19/Q36); this task owns the storage-side impact assessment.

### S21 — Point `MockBackend`'s default address function at S4's real BLAKE3-256 rule
- Milestone: M1
- Size: S
- Deps: S3, S4
- Spec: Architecture — "Tests run on `MockBackend`" (MVP-SPEC.md line 69); D32 address rule
- Do: Replace the mock's documented non-cryptographic stand-in default (`standin_address` in `crates/antseal-net/src/test_util/mock.rs`) with S4's `compute_storage_address` (BLAKE3-256 of the blob bytes, D32) as the default `address_fn`, deleting the stand-in and the mock rustdoc's S21 seam paragraph; keep `with_address_fn` for tests that deliberately need a divergent rule. Rationale: S3 shipped the injectable-function seam because it executed in a wave-1 lane where S4 (and the P15 `blake3` workspace pin) had not landed; once both are merged the mock must be right-by-default, or every pipeline test comparing manifest-recorded addresses (S4-computed) against mock-returned ones (S12 ordering, S14 restore fetches, S16 matrix) needs per-test wiring that will eventually be forgotten.
- Accept:
  - `MockBackend::new()` addresses byte-equal S4's `compute_storage_address` for the same input bytes (equality test over a small size ladder including the 272 B smallest-unit shape)
  - The stand-in digest no longer serves as an address default anywhere (grep `standin_address` gone); the module docs cite the real rule instead
  - Existing S3 tests stay green unmodified (they compare addresses relationally, never against pinned stand-in values — verified at S3)
- Notes: Discovered by S3 (wave-1 lane β, 2026-08-01) — the mock↔S4 address-agreement requirement falls between S3's and S4's entries and neither owns it. Blocked on S4's merge; trivial after it. `mock_digest_tagged` itself stays (call-log args digests and synthetic quote/tx material are mock-internal and deliberately not address semantics).

## Open decisions (S)
- Blob↔address model: whether a Blob maps to one top-level address with an internal chunk set (data-map style) or requires explicit per-chunk address handling in `antseal-net`, per ant-core 0.5.0's actual storage model — blocks S2, S4, S6 — must land by M1 start (informed by S1). — **[2026-07-27]** inputs captured (S1 memo): recommended Blob = one chunk, single 32-B BLAKE3 address, offline-recomputable with blake3 alone; `data_download` takes a `DataMap` not an address, so `get_data(Address)` maps to `chunk_get`; 4 MiB chunk cap. Decision itself stays due M1. — **[2026-08-01]** RESOLVED (**D32**): chunk-level, no data-map path in v1; hard 4 MiB cap enforced at seal plan validation before consent/anchor/quote (docs/decisions/D32-blob-address-model.md).
- Block-number acquisition locus: from ant-core/evmlib's payment confirmation inside `antseal-net::pay`, vs A's `eth_getTransactionReceipt` Arbitrum client invoked by the pipeline (spec's architecture comment puts "Arbitrum receipt capture" in `antseal-anchor`; the churn-boundary rule keeps anchor HTTP out of `antseal-net`) — blocks S7 — M1. — **[2026-07-27]** inputs captured (S1 memo): NO ant-core/evmlib payment API returns a block number (`GasInfo` is gas-only; the native merkle handler reads the event then discards the tx hash) — own `eth_getTransactionReceipt` is mandatory; in the native flow tx hashes survive only inside `PaidChunk.proof_bytes`. Decision itself stays due M1. — **[2026-08-01]** RESOLVED (**D33**): `antseal-net::pay()` — the anchor-side framing overturned; the payment RPC is not anchor HTTP, capture is payment-coupled, backfill over S5's payment RPC via the `ant_protocol` `http_provider` re-export; `antseal-anchor` gets zero M1 work (docs/decisions/D33-block-number-locus.md).
- Pipeline crate placement: `antseal-cli` library target vs a dedicated orchestration module/crate (must be library-drivable for M1 E2E) — blocks S10, S12 — M1 start. — **[2026-08-01]** RESOLVED (**D34**): `antseal-cli` gains a `[lib]` target; the orchestration layer (S12/S10/S11/S14, and M3's R16 by symmetry) is `antseal_cli` library code over injected interfaces; core is structurally impossible, net violates its charter, a new crate breaks the publishability chain while D72 is open; MockBackend feature-export noted at S3 (docs/decisions/D34-seal-pipeline-placement.md).
- `self_encryption` dependency mode in `antseal-core`: direct pinned dependency (if WASM-clean) vs vendored minimal address-derivation — blocks S4 — early M1. — **[2026-08-01]** RESOLVED (**D35**): neither — the option space overturned; no antseal crate depends on `self_encryption` at all (S4 = `blake3` alone; P15 re-scoped to a CI prohibition; GPL flag discharged by deletion; 0.36.0 is wasm32-dead regardless of license) (docs/decisions/D35-self-encryption-dependency-mode.md).
- Pre-pay resume re-quote/re-consent policy when the cost changed since the original consent — blocks S11, S12 — M1. — **[2026-08-01]** RESOLVED (**D36**): always re-quote (a journaled quote is never paid) and re-consent unconditionally, per-invocation — S11's "if cost changed" conditional overturned, U17's unconditional wording ratified; "changed" is display-only over the new S10 consent record (docs/decisions/D36-prepay-resume-requote-reconsent.md).
- Multi-tx payment handling: upstream per-payment-tx chunk cap and whether `pay` may emit several EVM txs (receipt already allows plural hashes) — blocks S6, S7 — M1 (informed by S1). — **[2026-07-27]** inputs captured (S1 memo): caps = 256 transfers per EVM tx (`MAX_TRANSFERS_PER_TRANSACTION`), 64-chunk driver waves, 256 merkle leaves — all paths can emit multiple tx hashes, so `PaymentReceipt` needs `Vec<TxHash>`. Also: external-signer flow recommended primary (only flow with first-class tx-hash/receipt/nonce control; native auto-approves `U256::MAX`). Decision itself stays due M1. — **[2026-08-01]** RESOLVED (**D37**): ⌈blobs/256⌉ sequential txs journaled per sub-batch; the `Vec<TxHash>` conclusion overturned as insufficient — the receipt's core is the `HashMap<QuoteHash, TxHash>` map + per-blob proof_bytes + per-tx block-number slots; merkle mode excluded; `Client::batch_pay` forbidden; post-pay resume time-boxed ~24 h (`QUOTE_MAX_AGE_SECS`) with a proofs-expired re-consent state (docs/decisions/D37-multi-tx-payment.md).

## Cross-domain expectations
- P: Cargo workspace with `antseal-core`/`antseal-net`/`antseal-cli` scaffolding; `ant-core = "=0.5.0"` and `self_encryption` pinned; wasm32-unknown-unknown CI for `antseal-core`; `start-local-devnet` and `start-devnet-sepolia` environments scripted/reachable for M1 E2E and CI.
- U: encrypted vault with per-work record storage API (journal records, receipts, paths, addresses, costs — layout U's, content mine); vault-held Arbitrum wallet key handle for payment signing (keygen/import/address ops are S5's deliverable to U11); consent/confirmation and re-consent hooks; CLI flags (`--network`, `--no-anchor`, `--yes`, `--dry-run`, `-o`) wired to pipeline/restore; `list`/`show` rendering of `incomplete`/abandoned state and per-work cost; `vault export`/`import` for S19.
- C: WASM-safe primitives in `antseal-core` — HKDF (`k_u`, `k_m`), XChaCha20-Poly1305 encrypt/decrypt with AAD, padding formula + length-first strip, nonce drawing, salted commitment recompute (`raw_commit`/`canon_commit`) for restore verification.
- G: canonicalization + unit splitting delivering unit plaintext bytes, byte-ranges, raw-mirror detection, and canonicalization descriptors that feed staged encryption and restore.
- F: manifest build/encode/decode with the unit table (nonce, `true_length`, byte-range, ciphertext network address fields accepting S4 addresses), encrypted-manifest blob + manifest storage record, UNANCHORED/empty-anchor representability with M0 golden vectors (synthetic addresses acceptable until S4 lands).
- A: pre-pay anchor-gate step (≥1-TSA-or-abort, `--force-degraded`) invoked by the pipeline with a stub/skip interface for M1; Arbitrum RPC receipt client (`eth_getTransactionReceipt`) if open decision 2 lands in `antseal-anchor`.
- R: M0 library verification entry (structural/commitment/signature checks incl. absent-anchor → UNANCHORED verdict) callable by the M1 E2E; M3 storage-linkage and `verify --live` orchestration consuming S4's address recomputation and S15's persistence primitive; M3 `reveal` fetching missing ciphertexts via `get_data`.
- Q: CI jobs hosting the devnet E2E suites (S16 default, S17–S19 gated/scheduled); M4 release gate (Sepolia E2E, mainnet smoke seal, disk-loss restore drill) reusing S14/S19 capability; threat-model doc absorbing storage-side notes (journal-loss abandonment, wallet linkability of receipts).
