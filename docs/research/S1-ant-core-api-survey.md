# S1 — ant-core 0.5.0 payment/storage API survey

- **Date:** 2026-07-27. **Version stamp: ant-core 0.5.0** (with locked
  ant-protocol 2.3.0, evmlib 0.9.0, self_encryption 0.36.0, xor_name 5.0.0
  — lock evidence in the [P9 record](../upstream/P9-ant-core-reverification.md),
  which also holds the retrieval log and archive sha256s).
- **Sources:** crates.io source archives (`ant-core-0.5.0`,
  `ant-protocol-2.3.0`, `evmlib-0.9.0`, `self_encryption-0.36.0`). Citations
  are `crate/src/path.rs:line` into those archives. Nothing in this memo is
  from memory or docs alone; every shape was read from the pinned source.
- **Verdict: GO on `ant-core = "=0.5.0"`** (§10). Consumers: S2 (trait),
  S6 (AntCoreBackend), S7 (receipts), F4 (address length), D32/D33/D37.
- Upstream release cadence is weekly-to-biweekly; treat every claim below as
  valid **for 0.5.0 exactly** and re-survey on any bump (dependency-policy §4).

## 1. Address type and length (F4 / D11 input)

- `pub type XorName = [u8; 32];` — “Content-addressed identifier (32
  bytes)” — `ant-protocol-2.3.0/src/chunk.rs:43`, with
  `pub const XORNAME_LEN: usize = std::mem::size_of::<XorName>();` (= 32)
  at `chunk.rs:46`. This alias (re-exported as `ant_core::data::XorName`,
  `ant-core-0.5.0/src/data/mod.rs:22`) is the type of every chunk address
  in the client API (`PreparedChunk.address`, `PaidChunk.address`,
  merkle `addresses: &[[u8; 32]]`).
- Address function: `compute_address(content: &[u8]) -> XorName` =
  `*blake3::hash(content).as_bytes()` —
  `ant-protocol-2.3.0/src/data_types.rs:10-12`. **BLAKE3-256 of the chunk
  content bytes; 32 bytes.** (blake3 locked at 1.8.5.)
- Distinct type with the same name: evmlib and self_encryption use the
  `xor_name` crate's `XorName` struct (a `[u8; 32]` newtype,
  `XorName(*a)` construction at `ant-core-0.5.0/src/data/client/merkle.rs:500`).
  Conversion between the two is `.0` / constructor — no length ambiguity.
- **F4 answer: Autonomi chunk addresses are exactly 32 bytes.**
- Related caps: `MAX_CHUNK_SIZE = 4 * 1024 * 1024` (4 MiB,
  `ant-protocol-2.3.0/src/chunk.rs:19`); wire envelope
  `MAX_WIRE_MESSAGE_SIZE = 5 MiB` (`chunk.rs:26`); `CLOSE_GROUP_SIZE = 7`,
  `CLOSE_GROUP_MAJORITY = 4` (`chunk.rs:35,40`); `DATA_TYPE_CHUNK: u32 = 0`
  (`chunk.rs:29`).

## 2. Client lifecycle (both flows)

- `Client::connect(bootstrap_peers: &[std::net::SocketAddr], config: ClientConfig) -> Result<Client>`
  — `ant-core-0.5.0/src/data/client/mod.rs:410-433`. No wallet attached.
- Native-wallet driver: `.with_wallet(wallet: Wallet) -> Self`
  (`mod.rs:440-445`; also populates the EVM network from the wallet).
  `Wallet::new_from_private_key(network, private_key: &str)` builds one
  from a raw hex key (`evmlib-0.9.0/src/wallet.rs:72-75`) — this is how a
  vault-held key drives the native flow.
- External-signer driver: `.with_evm_network(network) -> Self`
  (`mod.rs:451-455`) — "for external-signer flows where the private key
  lives outside Rust". Payment methods gate on
  `require_wallet()` (`src/data/client/payment.rs:21-25`) vs
  `require_evm_network()` (`mod.rs:462-473`).

## 3. Prepare: `prepare_chunk_payment` and quote shapes

- `pub async fn prepare_chunk_payment(&self, content: Bytes) -> Result<Option<PreparedChunk>>`
  — `ant-core-0.5.0/src/data/client/batch.rs:354`. Computes
  `address = compute_address(&content)` (batch.rs:355), collects a
  witnessed quote plan, and returns **`Ok(None)` when the chunk is already
  stored** (batch.rs:364-367) — the "zero-cost already-stored quote".
  `AlreadyStored` is decided when `CLOSE_GROUP_MAJORITY` (4/7) peers report
  stored (`src/data/client/quote.rs:918` doc; majority logic
  quote.rs:1291-1312; a mis-voting peer is excluded by the bind-check
  first, quote.rs:2411-2415).
- `pub struct PreparedChunk` (batch.rs:139-158):
  `content: Bytes`, `address: XorName`,
  `quoted_peers: Vec<(PeerId, Vec<MultiAddr>)>` (ordered PUT targets),
  `payment: SingleNodeQuotePayment`,
  `peer_quotes: Vec<(EncodedPeerId, PaymentQuote)>` (for the proof),
  `commitment_sidecars: Vec<Vec<u8>>` (ADR-0004). **Not serializable**
  (upstream states `PreparedChunk` "contains non-serializable network
  types", `src/data/client/file.rs` `PreparedUpload` doc ~1016) — a
  pre-payment journal cannot persist it; pre-pay resume must re-quote
  (consistent with S11's plan).
- `pub struct SingleNodeQuotePayment { pub quotes: Vec<QuotePaymentInfo> }`
  (batch.rs:47-51): quotes sorted by price; the **median quote is paid 3×
  its price, all others amount 0** (batch.rs:59-95;
  `SINGLE_NODE_PAYMENT_MULTIPLIER: u64 = 3`,
  `src/data/client/payment.rs:17`). `QuotePaymentInfo` =
  `{quote_hash: QuoteHash, rewards_address: RewardsAddress, amount: Amount, price: Amount}`
  (`ant-protocol-2.3.0/src/payment/single_node.rs:43-53`).

### Quote preimage (`PaymentQuote`) — what the receipt must persist

`pub struct PaymentQuote` — `evmlib-0.9.0/src/data_payments.rs:75-115`
(serde; rmp/MessagePack on the wire):

| Field | Type |
| --- | --- |
| `content` | `XorName` (32 B, the paid chunk address) |
| `timestamp` | `SystemTime` |
| `price` | `Amount` = `U256` (`evmlib-0.9.0/src/common.rs:16`) |
| `rewards_address` | `RewardsAddress` = alloy `Address` (20 B, `common.rs:11`, `lib.rs:46`) |
| `pub_key` | `Vec<u8>` (node's ML-DSA-65 public key) |
| `signature` | `Vec<u8>` (ML-DSA-65 over `bytes_for_sig`) |
| `committed_key_count` | `u32` (ADR-0004; tail, `serde(default)`) |
| `commitment_pin` | `Option<[u8; 32]>` (ADR-0004; tail, `serde(default)`) |

- Signed-bytes layout (`bytes_for_signing`, data_payments.rs:146-171):
  `xorname ‖ u64-LE unix-secs ‖ price as 32-byte LE ‖ rewards_address ‖
  committed_key_count u32-LE ‖ pin-tag byte (0/1) ‖ [pin 32 B]`.
- `QuoteHash = FixedBytes<32>` (`common.rs:12,15`) =
  **Keccak-256**`(bytes_for_sig ‖ pub_key ‖ signature)`
  (data_payments.rs:130-135; hash fn `evmlib-0.9.0/src/cryptography.rs:15-17`,
  `alloy::primitives::keccak256`). This is the exact preimage relation the
  v1.1 receipt-verification chain re-derives, so the receipt must persist
  the full `PaymentQuote` structs (available as `PreparedChunk.peer_quotes`
  pre-pay, and recoverable from `proof_bytes` post-pay, §6).

## 4. Pay, native wallet flow: `batch_pay`

- `pub async fn batch_pay(&self, prepared: Vec<PreparedChunk>) -> Result<(Vec<PaidChunk>, String, u128)>`
  — batch.rs:417-420. Return = `(paid_chunks, storage_cost_atto (decimal
  string of the U256 total), gas_cost_wei: u128)` (batch.rs:416 doc,
  428-429, 461). Internally one
  `wallet.pay_for_quotes(all_payments)` call over **all** quote entries
  (batch.rs:432-452).
- `Wallet::pay_for_quotes<I: IntoIterator<Item = QuotePayment>>(…) -> Result<(BTreeMap<QuoteHash, TxHash>, GasInfo), PayForQuotesError>`
  — `evmlib-0.9.0/src/wallet.rs:145-148`; `QuotePayment = (QuoteHash,
  Address, Amount)` (`common.rs:17`). The implementation (wallet.rs:383+):
  filters zero-amount entries, then **splits into EVM transactions of at
  most `MAX_TRANSFERS_PER_TRANSACTION = 256` transfers**
  (`evmlib-0.9.0/src/contract/payment_vault/mod.rs:11`; chunking loop
  wallet.rs:438-455). Every quote in a sub-batch maps to that sub-batch's
  single `TxHash`. Failure mid-sequence returns
  `PayForQuotesError(Error, BTreeMap<QuoteHash, TxHash>)` **carrying the
  hashes already paid** (wallet.rs:454) — ant-core discards that map in its
  error string (batch.rs:450-452), a small capture gap of the native flow.
  Allowance handling auto-approves the vault for `U256::MAX`
  (wallet.rs pay_for_quotes: `approve_to_spend_tokens(…, U256::MAX, …)`)
  — unlimited-allowance note for U's wallet-hygiene docs.
- `GasInfo` (`evmlib-0.9.0/src/retry.rs:15-30`): `estimated_gas`,
  `gas_with_buffer`, `max_fee_per_gas`, `max_priority_fee_per_gas`,
  `actual_gas_used`, `effective_gas_price`, `gas_cost_wei`. **No tx hash,
  no block number** — evmlib reads the receipt internally for gas data and
  does not surface it.
- `pub struct PaidChunk` (batch.rs:162-175): `content: Bytes`,
  `address: XorName`, `quoted_peers`, **`proof_bytes: Vec<u8>`**
  (serialized `PaymentProof`).
- **Where the tx hashes live in this flow:** only inside each
  `PaidChunk.proof_bytes`. Recover with
  `ant_protocol::payment::deserialize_proof(bytes) -> (ProofOfPayment, Vec<TxHash>)`
  (`ant-protocol-2.3.0/src/payment/proof.rs:96-99`); the full struct
  (incl. sidecars) via `deserialize_single_node_proof` (proof.rs:110).

## 5. Pay, merkle batch flow (≥64-chunk batches)

- Mode selection: `PaymentMode { Auto (default), Merkle, Single }`
  (`src/data/client/merkle.rs:117-125`);
  `should_use_merkle`: Auto ⇒ `count >= DEFAULT_MERKLE_THRESHOLD = 64`,
  Merkle ⇒ `count >= 2` (merkle.rs:38, 310-316).
- Native: `pay_for_merkle_batch(&self, addresses: &[[u8; 32]], data_type: u32, data_size: u64) -> Result<MerkleBatchPaymentResult>`
  (merkle.rs:338-359). One EVM tx per sub-batch of at most
  **`MAX_LEAVES = 1 << MAX_MERKLE_DEPTH = 2^8 = 256` leaves**
  (`evmlib-0.9.0/src/merkle_payments/merkle_tree.rs:21`,
  `merkle_batch_payment.rs:26`); larger inputs auto-split
  (merkle.rs:351-355, 592-657) with **partial-success returns** (a failing
  sub-batch after a paid one returns the paid proofs, merkle.rs:627-646).
- `MerkleBatchPaymentResult` (merkle.rs:132-147):
  `proofs: HashMap<[u8; 32], Vec<u8>>` (address → tagged proof bytes),
  `chunk_count`, `storage_cost_atto: String`, `gas_cost_wei: u128`,
  `merkle_payment_timestamp: u64`. Serializable (designed for resume
  caching). Merkle payments expire on-chain after
  `MERKLE_PAYMENT_EXPIRATION = 7 days` (merkle_tree.rs:24).
- **Tx-hash opacity (native merkle):**
  `Wallet::pay_for_merkle_tree(depth, pool_commitments, ts) -> (PoolHash, Amount, GasInfo)`
  (`evmlib-0.9.0/src/wallet.rs:162-167`). Internally the handler submits
  the tx, gets `tx_hash`, reads the **`MerklePaymentMade` event** from the
  receipt to extract `winnerPoolHash`/`totalAmount` — and then **discards
  the tx hash** (`evmlib-0.9.0/src/contract/payment_vault/handler.rs:97-114`).
  Merkle proof bytes carry **no tx hashes** either (built from
  `MerklePaymentProof::new(xorname, address_proof, winner_pool)`,
  merkle.rs:1447; contrast §6). ⇒ the native merkle flow cannot satisfy
  antseal's receipt requirements; see §8/§9.
  (For later receipt verification, the on-chain record is queryable by
  winner pool hash: `get_completed_merkle_payment(network, PoolHash)`,
  `evmlib-0.9.0/src/contract/payment_vault/mod.rs:15-31`, reachable via
  `ant_protocol::evm::contract::payment_vault`.)

## 6. `proof_bytes` format (single-node) — receipt payload

`PaymentProof` — `ant-protocol-2.3.0/src/payment/proof.rs:17-34`:
`{ proof_of_payment: ProofOfPayment, tx_hashes: Vec<TxHash>, commitment_sidecars: Vec<Vec<u8>> (serde(default)) }`;
`ProofOfPayment { peer_quotes: Vec<(EncodedPeerId, PaymentQuote)> }`
(`evmlib-0.9.0/src/data_payments.rs:53-56`; `EncodedPeerId` = raw 32-byte
BLAKE3(ML-DSA-65 pubkey), data_payments.rs:21-25). Encoding: **1 tag byte
then rmp_serde (MessagePack)** — `PROOF_TAG_SINGLE_NODE = 0x01`,
`PROOF_TAG_MERKLE = 0x02` (`ant-protocol-2.3.0/src/chunk.rs:343,345`;
serializers proof.rs:63-90; `detect_proof_type` proof.rs:50-57).
Construction: `build_paid_chunks` (batch.rs:291-331) — per chunk, the tx
hashes of its non-zero quotes + full `peer_quotes` + sidecars.

So one persisted `proof_bytes` blob per chunk **contains the quote
preimages and the tx hashes** — everything §3's hash relation needs except
the block number.

## 7. External-signer flow (chunk/batch/file levels)

- Batch level (the shape S6 will drive):
  `PaymentIntent { payments: Vec<(QuoteHash, RewardsAddress, Amount)>, total_amount: Amount }`
  — serde Serialize/Deserialize — built by
  `PaymentIntent::from_prepared_chunks(&[PreparedChunk])` from the
  **non-zero** entries (batch.rs:256-283). Then
  `pub fn finalize_batch_payment(prepared: Vec<PreparedChunk>, tx_hash_map: &HashMap<QuoteHash, TxHash>) -> Result<Vec<PaidChunk>>`
  (free fn, batch.rs:337-342; errors if any non-zero quote hash lacks a tx
  hash, batch.rs:300-305). No wallet needed.
- Single chunk:
  `Client::finalize_chunk(prepared: PreparedChunk, tx_hash_map: &HashMap<QuoteHash, TxHash>) -> Result<XorName>`
  (`src/data/client/chunk.rs:1032-1055`) — builds the proof and stores to
  `CLOSE_GROUP_MAJORITY` peers.
- File/data level (spec's named flow):
  `data_prepare_upload(content) -> PreparedUpload` (`src/data/client/data.rs:229`),
  `file_prepare_upload(path)` (`src/data/client/file.rs:1408`);
  `PreparedUpload { data_map, payment_info: ExternalPaymentInfo, data_map_address, already_stored_addresses, total_chunks }`
  (file.rs:1022-1043, `#[non_exhaustive]`);
  `ExternalPaymentInfo::WaveBatch { prepared_chunks, payment_intent } | Merkle { prepared_batch, chunk_contents, chunk_addresses }`
  (file.rs:989-1007);
  **`Client::finalize_upload(prepared: PreparedUpload, tx_hash_map: &HashMap<QuoteHash, TxHash>) -> Result<FileUploadResult>`**
  (file.rs:1732) and
  `Client::finalize_upload_merkle(prepared, winner_pool_hash: [u8; 32])`
  (file.rs:1836). The merkle external phase 1/2 pair at chunk level:
  `prepare_merkle_batch_external` (merkle.rs:493, "Requires EvmNetwork but
  NOT a wallet") / `finalize_merkle_batch(prepared, winner_pool_hash)`
  (merkle.rs:1405). For external merkle, the signer must extract
  `winnerPoolHash` from the `MerklePaymentMade` event in its own tx
  receipt (handler.rs:101-104 shows the event fields: winnerPoolHash,
  depth, totalAmount, merklePaymentTimestamp).
- Calldata builders (what the vault-held key signs):
  `PaymentVaultHandler::pay_for_quotes_calldata` (handler.rs:57) and
  `pay_for_merkle_tree_calldata` (handler.rs:120-140), both public and
  reachable **without a direct evmlib dependency** via
  `ant_protocol::evm::contract::payment_vault::handler`
  (re-export `ant-protocol-2.3.0/src/lib.rs:117-119; ant-core does not
  re-export this module, so antseal-net will import `ant_protocol` — it is
  a direct dependency of ant-core and version-locked by it, or we add
  `ant-protocol = "=2.3.0"` to the workspace at M1 in lockstep, P15-style).
  evmlib's convenience wrappers
  (`external_signer::pay_for_quotes_calldata -> PayForQuotesCalldataReturnType { batched_calldata_map: HashMap<Calldata, Vec<QuoteHash>>, to, approve_spender, approve_amount }`,
  `external_signer.rs:64-96`; `pay_for_merkle_tree_calldata ->
  MerklePaymentCalldataReturn`, `external_signer.rs:98-146`) are **not**
  re-exported through ant-protocol — replicate their thin batching logic
  (chunk by 256, map each batch's quote hashes to its tx hash) in S6 if we
  drive raw calldata. The ERC-20 `approve` calldata builder is likewise
  not re-exported; the external flow needs its own approve step (exact
  allowance, not `U256::MAX`) via alloy or a one-time `Wallet` approval
  (`approve_token_spend`, `src/data/client/payment.rs:135`).

## 8. Confirmations and block number (D33 input)

- **No ant-core/evmlib payment API returns a block number.** `batch_pay`
  returns costs only (§4); `GasInfo` has gas data only (§4);
  `pay_for_merkle_tree` returns `(PoolHash, Amount, GasInfo)` (§5). evmlib
  internally awaits receipts (handler/retry) but surfaces neither receipt
  nor block number.
- Therefore the spec's `PaymentReceipt` block number **must** come from our
  own `eth_getTransactionReceipt` against the captured tx hash(es) — the
  spec's "one `eth_getTransactionReceipt`" (one per tx hash) is confirmed
  as both sufficient and necessary. Tx-hash capture per flow: native
  wave-batch — deserialize each `proof_bytes` (§6); external-signer — we
  submitted the tx, so hash + receipt (block number, status) are natively
  ours; native merkle — **not capturable** (§5), flow excluded.

## 9. Which flow does antseal drive with the vault-held key? (S6 input)

**Primary: the external-signer flow at the chunk/batch level** —
`prepare_chunk_payment` per blob → `PaymentIntent::from_prepared_chunks` →
build `payForQuotes` calldata (≤256 transfers per tx) → sign & submit with
the vault-held EVM key via our own alloy provider → collect
`HashMap<QuoteHash, TxHash>` → `finalize_batch_payment` →
`chunk_put_with_proof`/`chunk_put_to_close_group`-class stores (or
`finalize_chunk` for single blobs). Reasons:

1. It is the only flow where **tx hash, receipt (block number), nonce/gas
   control, and submission timing are first-class** — required by the
   journal's "record the receipt the instant the tx lands" rule and by S7.
2. It still yields byte-identical `proof_bytes` (same
   `finalize_batch_payment` builder the wallet flow uses, batch.rs:287-291).
3. The exact-allowance approve avoids the native flow's `U256::MAX`
   approval (§4).

**Fallback (kept viable, mock-tested):** native `batch_pay` with
`Client::with_wallet(Wallet::new_from_private_key(vault_key))` — tx hashes
recovered via `deserialize_proof` from each `proof_bytes`, block numbers via
our RPC. Acceptable capture, less control; partial-payment hash map is lost
in the error path (§4).

**Both flows capture** tx hashes + quote preimages + `proof_bytes`:
preimages pre-pay from `PreparedChunk.peer_quotes`/`payment.quotes`,
post-pay from `proof_bytes` (§6); intents/quotes are serde-serializable
(`PaymentIntent` batch.rs:255, `PaymentQuote` data_payments.rs:74) even
though `PreparedChunk` itself is not (§3). Merkle-mode payment is **out of
scope for antseal's paid path** in MVP: per-seal blob counts sit far below
the 64-chunk auto threshold, we can always force the wave/single path by
using the chunk-level API directly, and merkle proofs/results carry no tx
hashes (§5).

## 10. Reads, and the verified no-payment-data facts

- `Client::chunk_get(&self, address: &XorName) -> Result<Option<DataChunk>>`
  (`src/data/client/chunk.rs:632-636`; closest-peers query + cache with
  address integrity re-check, chunk.rs:653-666);
  `chunk_exists(&XorName) -> Result<bool>` (chunk.rs:1011-1013).
- `Client::data_download(&self, data_map: &DataMap) -> Result<Bytes>`
  (`src/data/client/data.rs:459`) — **takes a `DataMap`, not an address**;
  it fetches every chunk in the (root-resolved) map and self-decrypts
  (data.rs:459-512). Address-keyed retrieval of a DataMap exists via
  `data_map_fetch(&[u8; 32]) -> DataMap` (data.rs:400) for maps stored as
  public chunks (`data_map_store`, data.rs:380).
- **Verified fact (spec line ~66):**
  `DataUploadResult { data_map: DataMap, chunks_stored: usize, payment_mode_used: PaymentMode }`
  — `src/data/client/data.rs:27-34`, exactly as the spec states; it carries
  **no payment data** (no tx hashes, costs, or proofs). `chunk_put(content)
  -> XorName` likewise pays internally and returns only the address
  (chunk.rs:333-352). Both stay **excluded** from antseal's paid path, as
  the spec mandates. (`FileUploadResult` does carry `storage_cost_atto` /
  `gas_cost_wei`, file.rs:941-979 — but still no tx hashes, so the
  exclusion stands for it too.)

## 11. Blob ↔ address model (D32 input)

Two models exist in 0.5.0:

1. **Chunk-level (recommended for antseal blobs):** one AEAD-ciphertext
   blob = one chunk, `address = BLAKE3-256(ciphertext)` (§1), offline
   recomputable with `blake3` alone — no self_encryption, no DataMap to
   persist. Constraint: blob ≤ `MAX_CHUNK_SIZE` = 4 MiB (oversize is
   `ProtocolError::ChunkTooLarge`, ant-protocol chunk.rs:367-371; PUT via
   `chunk_put_with_proof`, ant-core chunk.rs:534-541). G's unit-splitting/padding must guarantee
   ciphertext ≤ 4 MiB (AEAD tag + padding included) or S must split
   pre-encryption.
2. **Data-level:** blob → ant-core-internal self_encryption
   (`encrypt(content)`, data.rs:50; convergent — safe here only because
   antseal inputs are already AEAD ciphertext) → ≥1 chunks + `DataMap`;
   retrieval needs the DataMap (§10). Note self_encryption 0.36.0's chunk
   cap is **compile-time env-overridable**
   (`MAX_CHUNK_SIZE = option_env!("MAX_CHUNK_SIZE") | 4_190_208`,
   `self_encryption-0.36.0/src/lib.rs:154-160`;
   `MIN_ENCRYPTABLE_BYTES = 3`, lib.rs:150) — an address-determinism
   hazard P15 must pin (recompute with the same effective constant).

Recommendation to D32: chunk-level, single 32-byte address per blob;
`StorageBackend::get_data(Address)` maps to `chunk_get`. The data-level
model stays available for oversized blobs if a later decision allows them.

## 12. Per-tx chunk caps and multi-tx handling (D37 input)

| Path | Cap per EVM tx | Multi-tx behavior |
| --- | --- | --- |
| `pay_for_quotes` (wave/single; what `batch_pay` and the external intent hit) | **256 transfers** (`MAX_TRANSFERS_PER_TRANSACTION`, payment_vault/mod.rs:11) ⇒ 256 chunks (one non-zero transfer per chunk after zero-filtering, wallet.rs:431-438) | auto-chunked; one `TxHash` per sub-batch; on mid-sequence failure the paid map is in `PayForQuotesError` (wallet.rs:454) |
| ant-core wave driver (`batch_upload_chunks*`) | 64 chunks per wave (`PAYMENT_WAVE_SIZE`, batch.rs:30) ⇒ one tx per wave | waves pipelined; per-wave proofs cached for resume (batch.rs:495-500) |
| merkle | **256 leaves** (`MAX_LEAVES` = 2^8, merkle_tree.rs:21) | auto sub-batched, one tx each; partial success returns paid proofs (merkle.rs:627-657) |

⇒ `PaymentReceipt` must hold `Vec<TxHash>` (the spec already says "tx
hash(es)"); S6 must map every quote hash to its sub-batch's tx before
finalize, and the journal must persist hashes per sub-batch as they land,
not only at the end.

## 13. Error taxonomy (S2 mapping source)

`ant_core::data::Error` (`src/data/error.rs:10-205`), key variants:
`Network`, `Storage`, `Payment(String)`, `Protocol`, `RemotePut{address,source}`,
`CloseGroupShortfall`, `InvalidData`, `NotFound`, `Serialization`, `Crypto`,
`Io`, `Config`, `Timeout`, `InsufficientPeers`, `SignatureVerification`,
`Encryption`, `Cancelled`, **`AlreadyStored`** (unit),
`BadQuoteBinding{peer_id,detail}`, `BadQuoteCommitment{..}`,
`InsufficientDiskSpace`, `CostEstimationInconclusive`,
`PartialUpload{stored, stored_count, failed, failed_count, total_chunks, spend, reason}`.
Note: insufficient-ANT/gas surface as `Payment(String)` from evmlib's
`InsufficientTokensForQuotes` (wallet.rs:35-36) — S2's
insufficient-ANT/insufficient-gas classes will need message-shape mapping
or (external flow) our own pre-flight balance checks; flag for S2 design.

## 14. Spec cross-check

| Spec assumption (MVP-SPEC.md ~lines 60-69) | Verdict |
| --- | --- |
| `prepare_chunk_payment` / `batch_pay` / `finalize_*` exist | Confirmed (batch.rs:354, 417; batch.rs:337 `finalize_batch_payment`, chunk.rs:1032 `finalize_chunk`, file.rs:1732/1836 `finalize_upload{,_merkle}`, merkle.rs:1405 `finalize_merkle_batch`) |
| External-signer `PaymentIntent` → `finalize_upload(tx_hash_map)` | Confirmed (batch.rs:256; file.rs:1732 exact name and `tx_hash_map` parameter) |
| `DataUploadResult = {data_map, chunks_stored, payment_mode_used}`, no payment data | Confirmed (data.rs:27-34) |
| `PaymentReceipt` = tx hash(es) + block number via one `eth_getTransactionReceipt` + quote preimages + `PaidChunk.proof_bytes` | Feasible and fully capturable — with the caveats: block number available **only** via own RPC (§8); native merkle flow leaks no tx hash (§5) so it is excluded; plural "hash(es)" is load-bearing (§12) |
| `data_download` serves reads | Signature nuance: `data_download(&DataMap)`, not by address (§10); antseal's `get_data(Address)` maps to `chunk_get` under the D32 recommendation |
| Devnet examples `start-local-devnet`, `start-devnet-sepolia` | Confirmed present (`ant-core-0.5.0/examples/`); `LocalDevnet` requires the non-default `devnet` cargo feature (`Cargo.toml.orig` [features]; `src/data/mod.rs:18-19`) — P16/P17 note |

## 15. Go/no-go

**GO — keep `ant-core = "=0.5.0"`** (P9 record §4). The 0.5.0 surface
supports the spec's architecture with no blocking gaps; the two flagged
nuances (merkle tx-hash opacity; `data_download`'s DataMap signature) are
design inputs, not blockers, and both are resolved by the S6
recommendation in §9 and the D32 recommendation in §11.
