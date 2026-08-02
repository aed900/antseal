# D37 — Multi-tx payment handling: `pay()` emits ⌈n/256⌉ sequential txs, journaled per sub-batch; the receipt's core is the quote→tx **map** plus per-blob `proof_bytes` — a flat `Vec<TxHash>` cannot resume a seal

- **Status: RESOLVED. The register's cap inputs are confirmed against source
  (256 transfers per EVM tx; 256 merkle leaves; ant-core's internal 64-chunk
  driver waves — the last correctly understood as upstream's driver shape,
  not a cap antseal ever hits). The register's receipt conclusion —
  "`PaymentReceipt` needs `Vec<TxHash>`" — is overturned as materially
  insufficient: `finalize_batch_payment` consumes a `HashMap<QuoteHash,
  TxHash>` and errors on any missing entry, and the store-usable artifact per
  blob is its `proof_bytes`; a bare list of hashes can neither rebuild proofs
  nor resume finalize. Three further rulings the register did not contain:
  (1) merkle payment mode is **excluded** from the paid path — its proofs and
  results carry no tx hashes at all, so the spec's "one Merkle-batch EVM tx"
  phrase is a recorded deviation; (2) `Client::batch_pay` is **forbidden** in
  the native fallback — its error path discards the partial paid map,
  converting a mid-sequence failure into stranded payments; drive
  `Wallet::pay_for_quotes` directly if the fallback is ever used; (3) a
  journaled receipt is PUT-usable only within the node-side proof-validity
  window (`QUOTE_MAX_AGE_SECS`, currently 24 h) — a post-pay resume is
  time-boxed, which S11/S18 and the user docs must carry.**
- **Date: 2026-08-01**
- **Owner: S7 (receipt contents) and S6 (pay/finalize implementation);
  S11/S16/S18 consume the resume semantics**
- **Blocks: S6, S7 (register "multi-tx payment handling", due M1)**
- Companion: D33 (block-number locus; per-tx enrichment slots), D32 (blob =
  chunk ⇒ one non-zero transfer per blob), S1 memo §3-§9/§12.

## Context

The spec shapes `pay(&CostQuote) -> PaymentReceipt` with the comment "one
Merkle-batch EVM tx" (MVP-SPEC.md lines 34, 64) and simultaneously requires
the receipt to capture "EVM tx hash(es)" — plural — "+ block number + quote
preimages + `PaidChunk.proof_bytes`", complete from day one so the v1.1
verification chain never needs a reseal (lines 69, 110, 181). S1 §5/§12
found the tension: upstream's merkle path is the one payment mode that
*cannot* satisfy capture, and the wave/single-node path caps transfers per
transaction, so `pay` may emit several txs. D37 fixes the multi-tx contract:
the caps, the sequencing, the journal timing, the receipt shape, and the
resume semantics that receipt must support.

## Evidence (all re-verified 2026-08-01; ant-core archive sha256 matches P9)

### Caps and tx multiplicity

| # | Fact | Citation |
| --- | --- | --- |
| 1 | `MAX_TRANSFERS_PER_TRANSACTION = 256` | `evmlib-0.9.0/src/contract/payment_vault/mod.rs:11` |
| 2 | `pay_for_quotes` filters zero-amount entries, then splits into `chunks(MAX_TRANSFERS_PER_TRANSACTION)` — one `TxHash` per sub-batch, all quotes of a sub-batch mapped to it | `evmlib-0.9.0/src/wallet.rs:432-460` |
| 3 | Exactly **one** non-zero transfer per chunk: quotes sorted by price, the median quote paid 3×, every other amount zero (`SINGLE_NODE_PAYMENT_MULTIPLIER = 3`) — so 256 transfers/tx ⇒ **256 blobs/tx** | `ant-core-0.5.0/src/data/client/batch.rs:59-95`; `src/data/client/payment.rs:17` |
| 4 | The external-signer calldata builder performs the same 256-chunking, returning `HashMap<Calldata, Vec<QuoteHash>>` per sub-batch tx | `evmlib-0.9.0/src/external_signer.rs:64-99` |
| 5 | `PAYMENT_WAVE_SIZE = 64` governs only ant-core's own `batch_upload_chunks*` driver (one `batch_pay` per 64-chunk wave) — a driver antseal never calls (no receipt capture); it is not a protocol cap | `ant-core-0.5.0/src/data/client/batch.rs:30,466-501` |
| 6 | Merkle path: ≤ `MAX_LEAVES = 2^8 = 256` leaves per tx, 7-day on-chain expiry | `evmlib-0.9.0/src/merkle_payments/merkle_tree.rs:19-24` |

### Capture and its failure modes

| # | Fact | Citation |
| --- | --- | --- |
| 7 | The merkle handler submits, reads the `MerklePaymentMade` event from its own receipt, returns `(PoolHash, Amount, GasInfo)` — **the tx hash is dropped**; `MerkleBatchPaymentResult` carries proofs/costs/timestamp, no hashes | `evmlib-0.9.0/src/contract/payment_vault/handler.rs:90-115`; `ant-core-0.5.0/src/data/client/merkle.rs:131-147` |
| 8 | `PayForQuotesError(pub Error, pub BTreeMap<QuoteHash, TxHash>)` — a mid-sequence failure **carries the already-paid map**; each loop iteration attaches the map-so-far | `evmlib-0.9.0/src/wallet.rs:378,449-455` |
| 9 | `Client::batch_pay` destroys that map: `.map_err(\|PayForQuotesError(err, _)\| Error::Payment(format!(…)))` — paid sub-batches become unidentifiable through this API's error path | `ant-core-0.5.0/src/data/client/batch.rs:446-452` |
| 10 | `build_paid_chunks` requires a tx hash for **every** non-zero quote, else errors; per blob it emits `proof_bytes` = tag `0x01` + rmp(`PaymentProof { peer_quotes, tx_hashes, commitment_sidecars }`) — the quote preimages and the blob's tx hash(es) travel inside | `ant-core-0.5.0/src/data/client/batch.rs:291-331`; `ant-protocol-2.3.0/src/payment/proof.rs:17-99` |
| 11 | `finalize_batch_payment(prepared, &HashMap<QuoteHash, TxHash>)` is pure (no wallet, no network) — proofs can be built the moment hashes exist | `ant-core-0.5.0/src/data/client/batch.rs:337-343` |
| 12 | `PreparedChunk` is not serializable ("contains non-serializable network types") — but its `peer_quotes: Vec<(EncodedPeerId, PaymentQuote)>` and sidecars are serde types, and `PaymentIntent` is serde | `ant-core-0.5.0/src/data/client/file.rs:1016-1021`; `evmlib-0.9.0/src/data_payments.rs:21-30,70-115`; `batch.rs:250-262` |

### Resume reality

| # | Fact | Citation |
| --- | --- | --- |
| 13 | Upstream's own crash-resume cache for single-node payments persists exactly `(chunk_address, proof_bytes)` per chunk "immediately after each wave's `batch_pay` confirms, before the wave's PUT phase" — without the proofs "the on-chain payment is 'stranded'" | `ant-core-0.5.0/src/data/client/cached_single.rs:1-37` (module docs) |
| 14 | **Proof-validity window**: "On-chain quote receipts have a finite validity window (`QUOTE_MAX_AGE_SECS` in `ant-node`, currently 24 h). After that, storers reject the proof even if the file is otherwise resumable" — upstream's cache expires at 24 h to match; "at worst the user re-pays" | `cached_single.rs:48-58` (module docs) |
| 15 | The store-with-proof surface available to a resumed process: `chunk_put_with_proof(content, proof, target_peer, addrs)` is public; `chunk_put_to_close_group` is `pub(crate)`; `finalize_chunk` needs a live `PreparedChunk`. PUT targets are re-derivable without payment: `prepare_chunk_payment` returns `Ok(None)` for already-stored blobs (skip) or a fresh quote plan whose `quoted_peers` serve as targets while its payment plan is discarded unpaid | `ant-core-0.5.0/src/data/client/chunk.rs:404,534-541,1032-1050`; `batch.rs:354-415` |

## The overturn, stated plainly

The register asked whether `pay` may emit several txs and answered the
receipt question with "`Vec<TxHash>`". Multi-tx: **yes, confirmed** —
⌈non-zero-transfers/256⌉ transactions, and by row 3 non-zero transfers =
blob count, so a seal of ≤ 256 blobs (units + raw mirrors + encrypted
manifest — the overwhelmingly common case) is one tx and the spec's "one tx"
survives as the common case, not the contract. But the receipt conclusion
fails a concrete test the register never ran: *crash after the tx lands,
before any store*. To complete that seal without re-paying, the journaled
receipt must reconstruct, for every blob, a proof the network will accept —
which needs the per-blob quote preimages and the quote→tx association
(rows 10-11), or the finished `proof_bytes` themselves (row 13). A flat
`Vec<TxHash>` retains neither; it cannot even tell which blob a hash paid
for. Upstream reached the same conclusion for its own resume path and
persists `(address, proof_bytes)` (row 13). "Plural hashes" was the visible
tip of the actual requirement: **the receipt is a proof-reconstruction
record, not a hash list.**

## Decision

1. **Payment mode charter**: the paid path uses chunk-level single-node
   payments exclusively (`prepare_chunk_payment` → intent → sub-batch txs →
   finalize). Merkle mode is excluded for MVP — rows 6-7: no tx hashes in
   handler returns, results, or proofs ⇒ receipt completeness (spec line
   110) is unsatisfiable through it. `PaymentMode::Auto`'s 64-chunk
   threshold is therefore irrelevant to antseal; S6 must never route through
   `data_upload_with_mode`/merkle surfaces (already excluded by D32's API
   charter).
2. **Multi-tx sequencing (external-signer primary flow)**: `pay()` builds
   per-sub-batch calldata (≤ 256 transfers each, row 4 semantics), then
   submits **sequentially**; as each sub-batch tx lands, `pay()` journals
   that sub-batch's record — `{tx_hash, block_number (D33), status,
   quote_hash set}` — **before submitting the next**. A crash mid-sequence
   can therefore lose at most the one tx currently inside the pay→journal
   atomicity window — the same window S12 already treats as the critical
   barrier in the single-tx case; sequencing adds no new loss class.
3. **Native fallback discipline**: if the wallet flow is ever driven, it
   calls `ant_protocol::evm`-re-exported `Wallet::pay_for_quotes` directly
   and handles `PayForQuotesError(err, partial_map)` — journaling the
   partial map before surfacing the error. `Client::batch_pay` is forbidden
   (row 9 — its error path erases the evidence of money spent). Post-error
   resume treats mapped quotes as paid and pays only the unpaid remainder.
4. **`PaymentReceipt` shape (S7 implements; deterministic serde per S7)**:
   - per blob: `{address, peer_quotes (preimages), commitment_sidecars,
     proof_bytes}` — `proof_bytes` built via the pure
     `finalize_batch_payment` immediately after the last needed hash exists
     (row 11), so the journaled receipt is store-ready with no live
     `PreparedChunk` (row 12/13);
   - payment-wide: the `quote_hash → tx_hash` map (BTreeMap for
     deterministic encoding), per-tx `{block_number?, status}` enrichment
     slots (D33), `storage_cost_atto`, gas summary;
   - the spec's four element classes (hashes, block number, preimages,
     proof_bytes) all present; hashes and preimages appear both flat and
     inside `proof_bytes` — redundancy accepted, since `proof_bytes` is
     opaque upstream-versioned bytes and the flat fields are what the v1.1
     chain and `--json` consumers read.
5. **Resume/finalize contract over public APIs** (row 15): for each blob —
   already stored? (`Ok(None)`/`chunk_exists`) skip; else re-resolve PUT
   targets via an unpaid quote round, then `chunk_put_with_proof` with the
   **journaled** `proof_bytes`. No new payment exists on this path by
   construction; the fresh quote plan's payment field is dropped unpaid.
6. **Time-boxed resume (new, from row 14)**: journaled proofs are
   network-acceptable for ~`QUOTE_MAX_AGE_SECS` (24 h, node-side policy).
   A post-pay resume attempted after the window may be rejected by storers;
   the payment is then stranded and completing the seal requires re-payment
   — surfaced as a distinct, consented error, never silent. This is a
   node-policy constant, not ours to freeze: S9/S18 pin the observed devnet
   behavior; S20 watches it across bumps.

## Spec conformance — recorded deviations

- **"one Merkle-batch EVM tx" (lines 34, 64)**: deviated. The phrase assumed
  upstream's merkle batching exposes capture; rows 6-7 prove the opposite,
  and line 110's completeness requirement ("captured in full at payment
  time … tx hashes") is the normative one — the same resolution S1 §9
  recommended and this record ratifies. `pay()`'s doc comment should read
  "one EVM tx per ≤256-blob sub-batch; single tx in the common case".
- **"one `eth_getTransactionReceipt`" (line 69)**: reads per tx hash under
  multi-tx (D33 Decision 1) — an interpretation, not a deviation.
- The receipt's plural "hash(es)" (line 69) is confirmed load-bearing,
  exactly as the S1 memo flagged.

## Consequences — task-text edits at integration

- **tasks/S.md S2**: `PaymentReceipt` skeleton note — map-shaped core +
  per-blob proof records (Decision 4), not a hash list; distinct error slot
  for the expired-proof stranded state.
- **tasks/S.md S6**: Do — replace "emitting one Merkle-batch EVM tx (or the
  upstream-capped multi-tx sequence, all hashes captured)" with Decision 2's
  sequential sub-batch contract; add the `batch_pay` prohibition (native
  fallback drives `Wallet::pay_for_quotes` directly, Decision 3); Accept —
  the ">cap batches succeed with all tx hashes surfaced" row stays, now with
  the per-sub-batch journal ordering asserted via mock call log.
- **tasks/S.md S7**: Do — contents finalized per Decision 4; instant-capture
  clause extended to **per sub-batch as each lands** (the memo §12 note,
  now normative); Accept — multi-tx round-trip test covers ≥ 2 sub-batches
  (257+ blobs) with per-tx enrichment slots.
- **tasks/S.md S11**: resume path re-specified over Decision 5's public-API
  sequence; **new abandon-adjacent state**: proofs-expired (row 14) →
  distinct error + re-consent before any re-payment; journaled-nonce rules
  unchanged (re-payment re-uploads the same staged ciphertexts — no
  re-encryption, so no `(k_u, nonce)` interaction).
- **tasks/S.md S16/S18**: kill matrix gains the mid-sequence barrier
  (between sub-batch txs) and the S18 devnet variant asserts exactly-once
  payment per sub-batch across kill+resume; S18 adds an expired-proof case
  if devnet node policy is practically testable (else S9 documents the
  constant's observed value).
- **tasks/S.md S9**: pin the observed `QUOTE_MAX_AGE_SECS` behavior note
  alongside the D32 cap constants.
- **tasks/U.md (docs/UX note)**: `list`/`status` should nag on
  post-pay-incomplete works with the 24 h clock in mind ("resume promptly");
  wallet-hygiene docs already planned (unchanged).
- **TODO.md register D37 row** — integration's edit.

## Residual risks

1. **`QUOTE_MAX_AGE_SECS` is upstream node policy** — invisible in the
   client crates, changeable in any node release, and devnet node versions
   may drift from mainnet's. Mitigation: S9 records the observed value with
   its source; S20/P19 watch; the resume path treats storer rejection of a
   valid-looking proof as the distinct stranded state rather than a generic
   network error.
2. **Redundant capture (flat fields + `proof_bytes`)** can theoretically
   disagree if upstream changes proof serialization across a bump; S7's
   completeness test should assert flat fields == fields parsed from
   `proof_bytes` via `deserialize_proof`
   (`ant-protocol-2.3.0/src/payment/proof.rs:96-110`) at capture time.
3. **Sequential submission lengthens the pay window** for very large seals
   (>256 blobs): more wall-clock between first and last tx, more exposure to
   the S12 atomicity barriers. Accepted: correctness (per-sub-batch capture)
   over latency; the common case is one tx.
4. **Fresh-quote PUT-target resolution on resume** (Decision 5) briefly
   re-contacts the quoting path; if upstream ever makes quote *collection*
   itself stateful or paid, the resume story must be re-decided (S20 bump
   gate).

---

## Correction — 2026-08-02 (S9, wave-2 lane θ): the proof-validity window is
## client-side policy, not a node rule

**What this record got wrong.** The summary above, Decision 6, evidence row
14 and residual risk 1 all state that a journaled receipt is PUT-usable only
within a **node-side** proof-validity window named `QUOTE_MAX_AGE_SECS`
(~24 h), described as "upstream node policy, not ours to freeze". S9 was
tasked with pinning that constant against the pinned source. **It does not
exist, and neither does the enforcement.**

**Evidence** (all from the pinned versions this workspace resolves):

| claim as recorded | pinned reality |
|---|---|
| `QUOTE_MAX_AGE_SECS` in `ant-node/src/payment/verifier.rs` | **0 occurrences** anywhere in `ant-node-0.15.0` |
| `QUOTE_FUTURE_SKEW_TOLERANCE_SECS = 300`, same file | **0 occurrences** |
| a storer-side `validate_quote_timestamps` call | **0 occurrences** |
| "storers reject the proof after 24 h" | the single-node verification path applies **no timestamp gate at any step** |

The path antseal actually uses — D37 Decision 2 excludes merkle mode — is
`verify_payment_inner` → `ProofType::SingleNode` → `verify_evm_payment`
(`ant-node-0.15.0/src/payment/verifier.rs:801`, `:835`, `:945`). Its steps,
documented at `verifier.rs:938-944` and confirmed against the body, are:
`validate_quote_structure`; `validate_quote_arithmetic`; median-candidate
selection; per candidate — content binding, peer binding, ML-DSA-65
signature, local K-closeness, and `completedPayments(quoteHash) ≥ 3×` the
median price; the receiver-side price floor; the ADR-0004 cross-check. No
timestamp is read. The one staleness gate the file mentions was deliberately
**retired** (`verifier.rs:966-971`: the price-binding check "RETIRES the
percentage-based own-quote price-staleness gate").

**Where the 24 h actually comes from.** Row 14 quoted
`ant-core-0.5.0/src/data/client/cached_single.rs:48-58` faithfully — but that
is ant-core describing its **own on-disk proof cache**, whose expiry is
`CACHED_PROOF_MAX_AGE_SECS = 24 * 60 * 60` (`batch.rs:1051-1058`). Its doc
comment claims to "mirror `QUOTE_MAX_AGE_SECS` in `ant-node`"; against the
pinned node, that reference is stale. And antseal does not use that cache at
all: it journals its own `proof_bytes` (Decision 4) and stores through
`chunk_put_with_proof`, so even the client-side expiry never fires on our
path.

**The only proof-age enforcement that exists in the pinned stack** is
`MERKLE_PAYMENT_EXPIRATION = 7 * 24 * 60 * 60` (7 days),
`evmlib-0.9.0/src/merkle_payments/merkle_tree.rs:24`, enforced at `:464` — on
the **merkle** path, which Decision 2 excludes. It is now pinned as the
watchpoint in `crates/antseal-net/tests/storage_constants.rs`, so a bump that
changes it, or that moves age enforcement onto the single-node path, surfaces
at the S20 review.

**What changes, and what does not.**

- **Nothing in the design changes.** `StorageError::ProofsExpired` stays;
  the ~24 h classifier window (`PROOF_VALIDITY_WINDOW_SECS`) stays; the
  re-consent-before-re-payment rule (supplied by D36) stays; "resume
  promptly" stays in the user docs. The window is used **only** to classify
  a storer's payment-class rejection, never to gate anything pre-emptively,
  so a conservative guess costs at most one re-pay of a cheap chunk — and
  the mechanism can return upstream in any weekly release.
- **The attribution changes.** It is antseal's own client-side policy, not a
  network rule, and it must not be described as one. Corrected at source in
  `crates/antseal-net/src/{error,receipt,backend,ant_backend}.rs`.
- **Residual risk 1 is re-framed**: the risk is no longer "an upstream
  constant we cannot see may drift" but its inverse — **there is currently
  no node-side expiry at all**, so a resume long after payment may simply
  succeed, and antseal must never *depend* on the window existing in either
  direction. S20's bump gate re-runs S9's constants suite; S16's mock-clock
  test continues to exercise the expired-window branch, which remains
  reachable by a storer rejecting on payment grounds for any reason.
- **D36 is unaffected in its conclusion.** Its "always re-quote" ruling rests
  primarily on "a journaled quote is never paid: nothing in the pay path
  checks age before moving tokens" — which is *reinforced* here. Only its
  secondary clause ("storers enforce ~24 h `QUOTE_MAX_AGE_SECS`") inherits
  this correction; a dated pointer is appended to that record.

---

## Amendment — 2026-08-02 (S31, lane m1-s31): Decision 2's per-sub-batch
## durability is now implemented, and Decision 5 is extended to the
## unpaid remainder

**What this record claimed without an implementation.** Decision 2 states
that `pay()` journals each sub-batch's record *before submitting the next*,
so "a crash mid-sequence can therefore lose at most the one tx currently
inside the pay→journal atomicity window". U36 built the seam that makes the
timing expressible — `SealBackend::connect` takes a `ReceiptSink` and
installs the hook itself — but until this amendment **no sink in the tree
wrote anything durable**. The three implementations were `ReadOnly` (logs an
error and drops the receipt), a counting double, and S18's in-memory
`CapturedReceipts`; the only durable write was the pipeline's own
`put_receipt`, which runs *after* `pay` returns. A crash between sub-batch
txs therefore lost every receipt so far and the resume re-paid every
already-paid sub-batch — the F41 class (a recorded guarantee the code did
not implement), recorded as S31 by S18 when its accept row 2 turned out to
be untestable.

### The decisive fact: where the hook fires, and who can run when it does

S31 offered (a) a sink owning its own store session behind a `Mutex`,
(b) a channel-backed sink drained by the pipeline between sub-batches, or
(c) narrowing the claim. **(b) is refuted, and the refutation is not about
where the hook fires.**

The hook fires in exactly the right place. `ant_backend.rs`'s sub-batch loop
runs `send_transaction` → `get_receipt` → `tx_map` update →
`finalize_ready_blobs` → `emit_capture` at the **end** of iteration `N`
(`:906-920`), and iteration `N+1` submits at `:816`. So the capture for
sub-batch `N` is delivered strictly after `N` lands and strictly before
`N+1` is submitted, exactly as Decision 2 requires.

What (b) gets wrong is *who is able to do anything about it*. `CaptureHook`
is `Arc<dyn Fn(&PaymentReceipt) + Send + Sync>` — **synchronous**, called
inline from `pay`'s own body, while the pipeline's future is suspended at
`self.backend.pay(quote).await` **in the same task**. A channel `send`
returns as soon as the value is queued, and the pipeline cannot dequeue it,
because the pipeline is the caller currently blocked inside the call that
fired the hook. To drain, the pipeline must run concurrently — and under
`select!` the drain branch is polled only when `pay` yields, whose next
yield point is *inside* `send_transaction` for tx `N+1`. **The write would
land after the next submission, not before it.** (b) narrows the window
probabilistically and never closes it.

The only way to make (b) close it is to have the hook **block** until a
drainer acknowledges the write. The drainer cannot be the same task
(guaranteed deadlock: the blocked hook is what the poll is inside), so it
must be another thread holding the journal behind a lock — which is
**option (a) plus a scoped thread and two channels**, with one extra failure
mode (a hook that hangs forever after money has moved). (a) strictly
dominates.

A fourth option the register did not name was weighed and rejected:
**(d) split `pay` into per-sub-batch calls the pipeline drives**, which
would put the write unambiguously on the pipeline's side with no `'static`
problem at all. It fails on containment: `MAX_TRANSFERS_PER_TRANSACTION`,
the transfer-vs-blob arithmetic and the sub-batch cursor would leave the one
adapter file (project rule 1), and S2's batch-first trait would change shape
— for a guarantee (a) already delivers without touching either.

### Decision 7 (new) — the durable sink

`pay()`'s per-sub-batch journal write is performed by
`antseal_cli::pipeline::VaultReceiptSink`: a `Send + Sync + 'static` sink
owning `Arc<UnlockedVault>` and, behind one `Mutex`, its own `WorkStore`
session plus an OS CSPRNG. `capture()` performs U9's atomic + fsync'd
`put_receipt` **inline**, so the hook returns only once the receipt-so-far
is on disk — and only then does the loop submit the next sub-batch. This is
Decision 2's ordering with no race in it.

Three properties the shape had to preserve, each checked rather than
assumed:

- **Secret lifetime (U6/U9).** The sink holds `Arc<UnlockedVault>`, not a
  copy of the vault key. `UnlockedVault` stays `!Clone`; there is still
  exactly one `VaultKey` in the process and it still zeroizes on the single
  drop — the change is stack ownership → one heap cell. The new obligation
  is that the `Arc` must not outlive the command, which is asserted
  (`Arc::strong_count` back to 1 once the backend and journal are dropped).
- **U5's single-writer lock.** The sink **never acquires** it. U5 refuses a
  same-process double-acquire by design (two open file descriptions), so a
  sink that tried would deadlock the command against itself. The command's
  existing hold covers the sink's writes, and sink-vs-pipeline concurrency
  is structurally impossible for the same reason (b) fails: the pipeline is
  suspended inside `pay` whenever a capture runs.
- **S10 keeps journal ownership.** The sink writes *the receipt record only*
  and nothing else — no state transitions, no plan, no staging. Which work
  it writes to is supplied by the pipeline through
  `SealJournal::arm_receipts`, a provided no-op that `VaultJournal`
  overrides, called immediately before `pay` on **every** path that can pay.

### Decision 5, extended: the resume pays only the unpaid remainder

Decision 3 already ruled that a post-error resume "treats mapped quotes as
paid and pays only the unpaid remainder" — but only for the native
fallback. The durable sink makes the same situation reachable on the
**primary** flow, and Decision 5 as written did not cover it: it assumed the
journaled receipt covers every blob. A partial receipt does not, and
`finalize_batch` correctly refuses one (`"no payment record for unstored
blob"` — it does *not* re-pay, so the pre-amendment failure was a hard stop,
not a second payment, once a partial receipt existed at all).

So Decision 5 gains: when the journaled receipt covers only some staged
blobs, the resume re-quotes **the uncovered blobs alone**, runs the D36
consent gate over that remainder quote, pays it, and journals the **merge**
of the durable prior and the fresh receipt — never the fresh receipt alone,
which would erase the records the sink paid for. The merged receipt is what
`finalize_batch` then consumes, so every blob is paid for exactly once
across the crash. The already-paid quote hashes are *not* re-quoted and *not*
re-paid; a fresh quote round mints fresh quote hashes, which is precisely
why the durable prior — not a re-derivation — is the only thing that can
identify what was already bought.

The proofs-expired re-payment path (Decision 6, as corrected) deliberately
does **not** merge: there the prior proofs are the thing being replaced, and
merging would leave `finalize_batch` matching a stale record first.

### What is now true, and what remains false

**True.** A `SIGKILL` between sub-batch txs of a multi-tx payment loses no
receipt: every landed sub-batch is on disk before the next is submitted, and
the resume pays only the remainder. Proven live on a 14-node devnet in both
directions — with the durable sink the kill+resume costs exactly one tx per
sub-batch, and with the same kill against a non-durable sink it re-pays
(S18's new rows).

**Still false / still owed.**

1. **The sink must be attached by the caller.** `VaultJournal::with_receipt_sink`
   can be forgotten, and a journal without one behaves exactly as it did
   before this amendment. The *arming* is structural (the pipeline arms on
   every paying path); the *attaching* is not. This is the residual S27
   class one level up, and it belongs to U13's `seal` command wiring, which
   does not exist yet — recorded as **S36**. Until it lands, only the M1
   devnet harness constructs the production pairing.
2. **A sink write that fails is recorded, not surfaced.** `capture()` must
   not panic (money has moved; it runs between two transactions), so an I/O
   or cipher failure is stored in the sink's fault slot and logged. The
   pipeline does not yet turn that into a user-visible error on the
   `pay`-errored path, where it is the one case that matters — recorded as
   **S37**.
3. **Nothing here changes what the sink does for non-paying commands.**
   `ReadOnly` remains correct for `restore`/`verify --live`/`status
   --upgrade`: those paths do not pay, and a receipt arriving there is a bug
   that should be loud.
