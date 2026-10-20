# D208 — The chain, not the error, says whether a payment transaction moved money: the adapter **signs first and resolves an unacknowledged broadcast by its own hash**, and the resume **resolves every `Submitted` transaction before it buys anything**

- **Status: RESOLVED. H2 fell (b): its direction survived and three of its premises fell. The
  orchestrator's challenge-round counter-lean (iii') fell (b) as well: its direction survived,
  two of its premises fell and one was sharpened.**
  - **H2 (`S51`)** — *"split the broadcast from the signing. Fill and sign the transaction
    locally first (any error there — gas estimation, nonce read, chain id, signing — moved
    nothing: Payment, exit 23, as today); then broadcast the signed bytes (eth_sendRawTransaction)
    with the tx hash already known. An RPC error RESPONSE (…) is a definitive refusal: Payment. Any
    OTHER broadcast failure (transport: timeout, reset, no/garbled reply) takes the existing
    unobserved-landing treatment (…). NOT the journal-before-broadcast shape (option a), because
    that (…) creates a `Submitted` record for a transaction that may never have left the machine,
    which only the 24-hour proof clock can resolve. No new exit code; no new error variant."* (b):
    - **What survives: the direction.** Sign first and know the hash before any byte leaves;
      never call an unknown outcome "before any ANT moved"; reuse the unobserved-landing shape;
      no new exit code or variant (§2 R1–R7).
    - **Premise 1 falls: an RPC error object is not a definitive refusal.** *"already known"* —
      the node holds the transaction — and *"nonce too low"* are the same `ErrorResp(-32000)`,
      executed (§1.2). The error cannot classify the outcome; the chain can (§1.3).
    - **Premise 2 falls: the unobserved-landing treatment protects no money.** The resume's
      remainder is keyed on blob records (`crates/antseal-cli/src/pipeline/resume.rs:669-678`),
      and that branch writes none. Executed at `HEAD`: 10 quotes paid for 5 blobs (§1.4). H2 would
      have changed words and evidence, not money.
    - **Premise 3 falls: the 24-hour clock cannot resolve a never-mined transaction.** A block
      time that cannot be read never counts as expired
      (`crates/antseal-net/src/put_policy.rs:34-36`), so a record over a hash that never lands
      loops on exit 23 (§1.5). Option (a) is refused on other grounds: it protects evidence, not
      money (§2 R7).
  - **The counter-lean (iii')** — the orchestrator's, sent to P1's challenge round: build the
    unobserved sub-batch's blob records over the local hash at the branch; then at the resume,
    through the key-less receipt reader and before finalize, resolve each `Submitted` hash —
    confirmed: carry on; reverted, or absent for the window: drop its records and unmap its
    quotes, then re-quote; unaskable: a retryable error that pays nothing. (b):
    - **What survives: the direction, and both halves of the mechanism.** Records over the local
      hash are buildable at the branch, and nodes verify the **quote** on the payment contract
      (`completedPayments(quoteHash)`, ant-node 0.15.0), not the transaction, so a proof over a
      mined `Submitted` hash is accepted as it stands. Resolution is required, or the never-mined
      case loops for good (§1.6; §2 R5, R9).
    - **Premise falls: the reader.** The pipeline holds one `StorageBackend`; the key-less
      `AntCoreReceiptReader` is a separate type that only `status` builds. The read becomes a
      `StorageBackend` method with a default body (§1.6; §2 R8).
    - **Premise falls: the place.** The step runs before the **money** branch
      (`resume.rs:189`), not merely before finalize: once records exist, the remainder counts the
      unresolved sub-batch as covered and buys nothing (§1.6; §2 R9).
    - **Sharpened: "absent", and what is kept.** No receipt now does not prove "never lands":
      absent also needs `eth_getTransactionByHash` to answer null. The pruned transaction's
      `TxRecord` is kept as evidence, and the pruned receipt goes through the remainder arm as its
      `prior`, never through the pre-pay arm (§2 R4, R9).
- **Date: 2026-10-20**
- Owner rows: **`S51`** (§2 R1–R7), **`S54`** (§2 R5, R8–R12), **`S57`** (§2 R13) and **`S58`**
  (§2 R14). `S51` was minted by wave 40's rulings (D204 §4). `S54` was minted by this wave's
  rulings, before this record was written, from P1's row A, which P2 executed independently as its
  row (B). `S57` and `S58` were minted during implementation from L-NET4's phase-1 report (its
  proposed rows A and B). This record mints no row.
- Related:
  - **D37** Decision 2 (each landed sub-batch is journaled before the next is submitted, and a
    crash loses at most the one transaction inside the pay→journal window, D37:102-109) and the
    S31 amendment's extension of Decision 5 (*"so every blob is paid for exactly once across the
    crash"*, D37:395-396); takes a dated addendum;
  - **D33** Decision 2 (D33:126-130) and residual risk 2 (*"hash journaled at submission"*,
    D33:191-194); takes a dated addendum;
  - **D204** (§1.7's `Payment` producers, D204:216-221; §2 R4's *"before any ANT moved"*; §4's
    `S51` item, D204:489-500); takes a dated addendum;
  - **D147** (§1.2's `StrandedPayment` sites, D147:151-159; R6's classes 23 and 28); takes a
    dated addendum;
  - **D203** (§1.4 and M1 on what a mapped quote protects, D203:187-188 and :393-396); takes a
    dated addendum;
  - **D186** (class 37, and the pipeline's 28/37 split at `resume.rs:510-528`, unchanged),
    **D179** §2 R3 (an unreadable block time is not expired), **D36** (a stale quote is never
    paid, and a fresh round mints fresh hashes), **D198** (the capture verdict and `S46`'s stop),
    **D134** §2 R3 (the exit-code table is append-only; nothing is appended);
  - **D209** (`S53`: the expired-proof arm's carry, which runs after this record's resolution
    step, D209 R5) and **D210** (`U114`, `U115`: the copy that reads `payment_recorded`);
  - **`S16`** (a journaled receipt, not the state tag, says money moved, `resume.rs:170-179`) and
    **`U32`** (no `--json` semantics move before it).

## 0. What was measured against

`HEAD` `ab7226f` (local `main`, one records-only commit ahead of `origin/main` `6f0b574`). The
tree was clean when planning began, on 2026-10-20.

Planning lane P1 (wave 41, 2026-10-20) measured `S51`. It EXECUTED the premise with a throwaway
crate built on evmlib's exact provider chain, against a loopback JSON-RPC stub, in a private
target, on the versions `Cargo.lock` pins (alloy-provider 1.8.3, evmlib 0.9.0): three builds and
three runs, every exit file 0, scenarios [A]–[M]. In the orchestrator's challenge round it EXECUTED
row A at `HEAD`: one in-process test (over `MockBackend`, no spawned binary) added to a
`git archive HEAD` shadow copy and built in a private target (*"1 passed"*, exit file 0). It read
the counter-lean against the pinned upstream sources (ant-core 0.5.0, ant-protocol 2.3.0,
ant-node 0.15.0, evmlib 0.9.0). Planning lane P2 EXECUTED the same shape independently as its row
(B): one in-process probe in its own shadow, exit file 0. Neither lane wrote the repository.

Before this record was written, the records lane re-read the load-bearing lines through
`git show ab7226f:<path>` and the pinned registry sources, because implementation lanes were
editing the tree (`crates/antseal-net/src/backend.rs`, `test_util/mock.rs` and
`crates/antseal-cli/src/pipeline/resume.rs` among them). Every figure below held, with these
refinements:
- the journaled receipt is read at `crates/antseal-cli/src/pipeline/resume.rs:185` (P1 and the
  rulings: `:186`); the money branch is `:189`, and the three lines between declare `paid_here`,
  `paid_atto` and `anchors`;
- the unreadable-time rule is `crates/antseal-net/src/put_policy.rs:34-36` (P1: `:35-36`, which
  starts mid-sentence);
- the Confirmed arm maps, then finalizes, at `crates/antseal-net/src/ant_backend.rs:779-790` (P1:
  `:779-787`);
- `list`'s "so far" cost arm is `crates/antseal-cli/src/listing.rs:857-859` (P1: `:856-858`), and
  the 28 bullet of `docs/user/funding-your-wallet.md` is `:271-279` (P1: `:271-282`, which runs
  into the 29 bullet);
- the wallet-hygiene document P1 cites as `wallet-hygiene.md:380` is
  `docs/user/wallet-hygiene.md:380`;
- §7.10 key 1's definition (R12) reads *"the Arbitrum One block number of the
  **earliest-confirmed** transaction in key 0"* (`docs/format/registry-v1.md:934`).

## 1. What was measured

### 1.1 The submission step at the pin

`AntCoreBackend::pay` (`crates/antseal-net/src/ant_backend.rs:564`) runs one iteration per
sub-batch. The file compiles only under `ant-backend`. At `ab7226f`:
- **One call fills, signs and broadcasts.** The request is built (`:707-710`) and handed to
  `self.provider.send_transaction(request)` (`:711`). Any error becomes
  `stranded_or_payment(txs.len(), "sub-batch tx submission failed: …")` (`:711-719`), which is
  `Payment` at a count of 0 (`:1747-1756`): exit 23, *"payment failed before any ANT moved"*. At
  k ≥ 1 the same error is `StrandedPayment { k }` with no capture of sub-batch k, so the defect is
  uniform in k; the row names the zero case.
- **The journaled hash is the node's echo.** `let submitted_hash =
  TxHash::from_bytes(pending.tx_hash().0);` (`:720`), where alloy builds the pending transaction
  from the node's answer: `PendingTransactionBuilder::new(self.root().clone(), tx_hash)`
  (alloy-provider 1.8.3, `src/provider/trait.rs:1032-1033`).
- **The provider is erased at connect.** `let provider = wallet.to_provider().erased();` (`:271`).
  `FillProvider::fill` (alloy-provider 1.8.3, `src/fillers/mod.rs:404-406`) is an inherent method,
  not on the `Provider` trait, so the erased provider cannot call it.
- **Nothing of the fix exists yet.** `command grep -cF` over the file at `ab7226f`: `.fill(` 0,
  `send_raw_transaction` 0, `with_timeout` 0 (control: `send_transaction(request)` 1).

### 1.2 The error cannot say what happened — executed

P1's probe drives evmlib's own chain (`ProviderBuilder::new().with_simple_nonce_management()
.wallet(…).connect_http(url)`, evmlib 0.9.0 `src/wallet.rs:265-269`) against a loopback stub.
Verbatim:
- **[A]** One `send_transaction` made exactly `eth_estimateGas, eth_feeHistory, eth_chainId,
  eth_getTransactionCount ×2, eth_sendRawTransaction`. With the reply dropped after the stub read
  the whole request: *"Err[Transport(Custom)] error sending request for url (…)"* and *"raw txs
  the node now HOLDS from this call: 1"*. At `HEAD` that is `Payment`, exit 23.
- **[D] and [D2]** *"Err[ErrorResp(code=-32000, message="already known")] … (node received 1 raw
  tx)"* and *"ErrorResp(code=-32000, message="nonce too low")"*: one variant and one code, for a
  transaction the node holds and for one it refused.
- **[K2]** A reverting estimate through today's single call: *"Err[ErrorResp(code=3,
  message="execution reverted")] …; eth_sendRawTransaction calls: 0"* — an `ErrorResp` that sent
  nothing.
- **[E] and [F]** A JSON-RPC error carried on a 502 is `Transport(HttpError(status=502))`; a
  garbled 200 is `DeserError`.
- **Upstream agrees.** alloy-transport 1.8.3, `src/layers/fallback.rs:580-581`: *"First node:
  submits tx → waits → returns receipt"* / *"Other nodes: tx already in mempool → return "already
  known" error"*.

### 1.3 The split is buildable, and the chain answers what the error cannot — executed

- **[B]** `fill` made the same pre-broadcast calls, and *"local hash known before broadcast:
  0x3789…3b56; keccak256(encoded_2718) == tx_hash(): true"*.
- **[C]** Re-broadcasting the same bytes was accepted under the same hash.
- **[J]** After a lost reply, `eth_getTransactionReceipt(local hash)` found the landing:
  *"Some(block Some(17), status true, hash matches true)"*.
- **[G]** *"first signed tx nonce 6; retry signs nonce 12"*. evmlib's `SimpleNonceManager` re-reads
  the pending count, so a retry never reuses a held transaction's nonce, and a held first
  transaction and the retry can both be mined. Today's double payment is exactly "the first
  broadcast was received".
- **[H] and [L]** Neither the await nor the broadcast has a deadline: *"get_receipt still waiting
  after 8.001564924s (33 receipt polls): no deadline"* (`PendingTransactionConfig::new` sets
  `timeout: None`, alloy-provider 1.8.3 `src/heart.rs:293-294`) and *"hung gateway:
  send_raw_transaction still waiting after 6.000495606s: no deadline"*. **[I]** `with_timeout(3 s)`
  returned an `Err` after 3.0096 s.
- **[M]** The stub in `crates/antseal-net/tests/storage_gate.rs` (`:388-390`, `:486-490`) cannot be
  the test base. It answers `null` to every method but `eth_chainId`, which stops fill before any
  broadcast (*"send_transaction Err[DeserError] … expected struct FeeHistory …;
  eth_sendRawTransaction calls: 0"*), and it lives in the integration-test crate, which reaches
  only the public API.

### 1.4 The unobserved-landing shape protects no money — executed at `HEAD`, twice

- **The branch** (`ant_backend.rs:721-756`) pushes a `TxStatus::Submitted` record (`:731`), maps
  the sub-batch's quotes to the hash (`:735-737`), delivers a capture (`:738-744`) and returns
  `StrandedPayment` (`:745-755`). It builds no blob record: finalize runs only in the Confirmed arm
  (`:779-790`), and `emit_capture` takes `blobs` from the records and sums the cost over them
  (`:1617-1622`). For a first sub-batch the capture holds mapped quotes, `txs = [Submitted]`, no
  record and a cost of 0.
- **The remainder is keyed on records.** `uncovered_blobs` (`resume.rs:669-678`) collects
  `receipt.blobs.iter().map(|record| record.address)`. `payment_recorded` is
  `!receipt.tx_map.is_empty()` (`crates/antseal-cli/src/pipeline/journal.rs:1166-1168`), true for
  a `Submitted`-only receipt, so the resume takes the remainder arm (`resume.rs:207`) and re-quotes
  every blob of that sub-batch (`:220-264`).
- **P1, executed** (a pay double that really pays through `MockBackend`, then captures exactly the
  branch's shape through the real `VaultReceiptSink`):
  - *"first run: exit 28 class PaymentStranded: … which re-pays no quote the receipt already
    maps"*;
  - *"after the strand: quotes paid on chain 5, journaled records 0, mapped quotes 5, txs
    [Submitted], storage_cost_atto 0, payment_recorded true"*;
  - *"resume: consents 2, resume consent total 22902 (first consent total 22902)"*;
  - *"after the resume: quotes paid on chain 10 (first run 5), … stored 5, double-paid hashes 0,
    … merged storage_cost_atto 22902, state Complete"*.

  Ten quotes were paid for five blobs, and the vault records 22 902 of the 45 804 paid.
- **P2, executed independently** (its row (B)). Before the resume, `list` printed *"cost: 0
  atto-ANT so far (from the payment receipt)"* beside *"RESUME PROMPTLY: a payment for this seal
  is recorded, and its payment proofs stay usable for uploading only about a day — …"*, though no
  proof existed. The resume asked `total_ant_atto=5517 blob_count=3 priced=3` and paid it
  (`payment_tx_count=2 double_paid=0`); the work completed with 5 517 recorded and 2 × 5 517
  spent.
- **The mock's own guard is blind to it.** `MockBackend::double_paid()`
  (`crates/antseal-net/src/test_util/mock.rs:319`) keys on quote hash, so a blob bought twice under
  two quote rounds reads 0. A per-address count is the guard that can redden.
- **Every surface that states 28's contract says the opposite for this shape.** Each is true per
  quote hash — no retry ever pays an old quote hash (D36) — and false per blob:
  - the CLI Display, `crates/antseal-cli/src/error.rs:779-785` (*"… which re-pays no quote the
    receipt already maps"*), and the exit-code doc, `:64-66`;
  - `docs/user/funding-your-wallet.md:246-250` (the Display, quoted) and `:271-279`;
  - abandon's rule 2, `crates/antseal-cli/src/seal_resume.rs:530-554` (*"no quote the receipt
    already maps is paid again, and the network's payment proofs stay usable for uploading only
    about a day"*), which also refuses the work, so a falsely flagged work cannot be abandoned;
  - the resume plan, `seal_resume.rs:945-947` (*"a payment is recorded"* / *"pay the rest, if
    any, then upload"*);
  - `payment_recorded`'s doc, `journal.rs:1153-1156`: "That is exactly the set of quotes a resume
    will not buy again (D37 Decision 5), and what exit 28 promises. A mapping to a `Submitted`
    transaction — an unobserved landing — counts, because money *may* have moved."

### 1.5 Neither the clock nor backfill resolves a never-mined transaction

- `put_policy.rs:34-36`: *"A time that cannot be read counts as **not** expired
  ([`payment_time`]): a failed read costs a retry, never a payment."* `verdict` (`:193-204`)
  returns `ProofsExpired` only when `paid_at_unix_secs.is_some_and(…)`.
- A `Submitted` record has `block_number: None`. On decisive declines the adapter reads the paying
  transactions' block times (`ant_backend.rs:1975-1983`); `paying_block_time` (`:2069-2087`) asks
  for the receipt by hash, gets none and answers `None`; the verdict is then `Retry`, which is
  `StorageError::Finalize` (`:1987-1989`): exit 23, on every run.
- `fill_block_numbers` (`:1265-1295`) fills a record only when the receipt read returns one
  (`:1282-1291`), so a transaction the chain never saw stays `Submitted`, with no block, for good.
  Its host is `status <work-id>` (`crates/antseal-cli/src/pipeline/receipt_backfill.rs:247-248`),
  not the resume.

### 1.6 What the network checks, and where the resume can ask (P1's challenge round)

- **Records over the local hash are buildable at the branch.** ant-core 0.5.0's
  `finalize_batch_payment` (`src/data/client/batch.rs:337-342`) calls `build_paid_chunks`
  (`:291`): per chunk it collects the hash of each non-zero quote and serialises the
  `PaymentProof`, with no receipt and no block number. `finalize_ready_blobs`
  (`ant_backend.rs:1535`) is callable in the branch exactly as in the Confirmed arm.
- **Nodes check the quote, not the transaction.** ant-node 0.15.0 (`src/payment/verifier.rs`)
  only logs a proof's transaction hashes (`:840-845`, *"Proof includes {} transaction
  hash(es)"*); acceptance is the payment contract's record of the quote (`:936-937`, *"A candidate
  is accepted only if `completedPayments(quoteHash)` is at least 3x the median price"*). A proof
  over a mined `Submitted` hash is therefore accepted as it stands, and a proof over a hash that
  never landed is refused by each peer (`:1104-1107`, *"Median-priced quote for peer {:?} was not
  paid enough …"*), which §1.5 turns into exit 23 for good.
- **So the resume must resolve, and before the money branch.** Once records exist,
  `uncovered_blobs` counts the unresolved sub-batch as covered, the remainder buys nothing, and
  finalize meets §1.5's loop. The step belongs between the receipt read (`resume.rs:185`) and the
  money branch (`:189`).
- **The read must be the backend's.** The pipeline holds one `B: StorageBackend`. The key-less
  receipt reader is a separate type that only `status` builds (`PaymentRpc`,
  `crates/antseal-cli/src/backend.rs:1366`). The payer that `seal` connects before every resume
  (`crates/antseal-cli/src/commands.rs:435-440`, `SealBackend::connect(…)`) already holds the
  provider and the receipt read. At `ab7226f`, `git grep` finds 19 `impl StorageBackend for`
  sites: `AntCoreBackend`, `AntCoreReader`, `MockBackend`, `NullBackend`, `SealBackend`, two test
  doubles in `resume.rs`, ten in `crates/antseal-cli/tests/` and two in `crates/antseal-net/tests/`.
  A default body spares all of them.

### 1.7 The options, priced (P1 §2 (c), §7.3)

| | Shape | Money, when the first broadcast reached the node and was mined | Other cost |
|---|---|---|---|
| O0 | `HEAD`: any send error → `Payment` | a re-run pays again, up to one sub-batch — for any seal of ≤ 256 blobs, its whole storage cost | the vault holds no trace of the first payment |
| O1 | H2 | as O0: the records-keyed remainder re-buys the sub-batch | *"money has already moved"* for every refusal H2 misfiles; an un-abandonable work; a `Submitted` record nothing resolves |
| O2 | sign first, deadlines, resolve by the local hash (§2 R1–R7) | no double payment whenever the RPC can be asked within the window | a definitive refusal waits up to the window before exit 23 |
| O3 | option (a): journal `Submitted` before the broadcast | as O0 | a durable write per sub-batch; a `Submitted` record for every transaction a kill stopped before sending |
| O4 | journal the signed raw transaction and the records before the broadcast; re-broadcast at the resume | closes D37 Decision 2's kill window for money too | a `TxRecord` field and a `JournalReceipt` format version; M–L |
| (ii) | a new class (38) for an unconfirmed payment | still paid twice; only the advice changes | D147 §1.7's eleven instruments |
| (ii') | 28's words admit the re-buy | still paid twice | weakens a promise that is true for every other 28; re-blesses `cli-errors.display.txt:87-88` |
| (iii'') | records at the branch, a resolution read, resolution before the money branch (§2 R5, R8–R11) | never paid twice, within R4's bounded residual | M; no new class; the six 28 surfaces unchanged |

O2 and (iii'') together are this record's ruling.

### 1.8 The deadlines, measured against ant-core's own payer (P1 §7.7)

evmlib 0.9.0 is ant-core 0.5.0's payer. antseal's `pay` does not ride it; its token approval does.
- **Broadcast:** `BROADCAST_TRANSACTION_TIMEOUT_MS: u64 = 5000` (`src/retry.rs:10`).
- **Confirmation:** `TX_TIMEOUT … from_secs(24); // Should differ per chain` (`src/lib.rs:50`) per
  watch, `MAX_RETRIES: u8 = 3` (`retry.rs:8`) and `WATCH_TIMEOUT_MS: u64 = 1000` with a quadratic
  backoff (`:11`): about 110 s before `TransactionFailedToConfirm`.
- **Upstream carries `S51`'s hazard itself.** A broadcast timeout returns
  `TransactionFailedToSend("timeout")` (`retry.rs:246-253`), whose arm does not pin the nonce
  (`:141-143`); only `TransactionFailedToConfirm` sets `previous_nonce` (`:144-147`). The retry
  re-fills a fresh pending nonce, so a held first transaction and the retry can both be mined. For
  an exact-allowance approval that costs gas at most — an approval sets the allowance, it does not
  add to it — but a payment would be made twice. antseal's `pay` therefore never re-sends blind.
- The ruled values follow (§2 R7): 30 s to broadcast (a slow acknowledgement costs a resolution,
  never a second transaction), 120 s to await (about upstream's ~110 s of watching), and a 120 s
  resolution window.

## 2. RULING

### `S51` — at the broadcast (lane L-NET4, `crates/antseal-net/src/ant_backend.rs`)

#### §2 R1 — Sign before sending

Each sub-batch transaction is filled and signed on the wallet's own filler stack —
`FillProvider::fill` on the concrete provider `Wallet::to_provider()` returns, built once per `pay`
or kept beside the erased one (the lane picks and states why) — and its hash is computed locally
before any byte leaves. A failure there (the gas estimate, where a would-revert lands; fee history;
nonce; chain id; signing) sent nothing: `stranded_or_payment(confirmed, "sub-batch tx could not be
prepared: …")`, which is `Payment` at 0, exit 23.

*Why:* only the split makes "nothing left the machine" a fact the adapter knows ([K2]), and `fill`
runs the fillers `send_transaction` runs, so no filler's behaviour changes ([B]).

#### §2 R2 — Broadcast the signed bytes under a deadline, and keep the local hash

`send_raw_transaction(&envelope.encoded_2718())` under `BROADCAST_DEADLINE` (30 s). An
acknowledgement whose echoed hash differs from the local one counts as no acknowledgement. The
journaled hash is always the local one.

*Why:* at `HEAD` the journaled hash is the node's echo (§1.1), and the broadcast can hang for good
([L]).

#### §2 R3 — An acknowledged broadcast is never `Payment`

An acknowledged broadcast is awaited by the local hash under `RECEIPT_DEADLINE` (120 s). A receipt
takes today's landed path unchanged (`settle_sub_batch`). A deadline or an await error is looked up
once more (R4's lookup) and otherwise takes the unobserved-landing shape (R5) — **never
`Payment`**: the node acknowledged the transaction.

*Why:* the await has no deadline at `HEAD` ([H]), and an acknowledged transaction may still be
mined.

#### §2 R4 — Resolve an unacknowledged broadcast by the hash, not by the error

After any **unacknowledged** broadcast — an error of any variant, the deadline, or a different
echoed hash — poll `eth_getTransactionReceipt(local hash)` for `RESOLVE_WINDOW` (120 s).
Re-broadcasting the identical bytes once is allowed: the same hash cannot pay twice. Outcomes:
- **a receipt** → the landed path (Confirmed or Reverted, through `settle_sub_batch`);
- **every lookup answered with no receipt, and `eth_getTransactionByHash(local hash)`, asked once
  at the end of the window, answered null** → `stranded_or_payment(confirmed, "the payment
  transaction was not accepted (…), and the chain did not show it within {W} s")`: `Payment` at 0,
  exit 23;
- **by-hash shows the transaction (held, unmined), or a lookup could not be answered** → the
  unobserved-landing shape (R5), `StrandedPayment { landed_tx_count: confirmed }`: 28, or 37 by
  the existing capture split.

No message-string classifier. It would be the first in the adapter: `command grep -n '\.contains("'`
over `ant_backend.rs` at `ab7226f` finds 17 hits, the first at `:2107`, all inside `mod tests`
(which opens at `:2093`). It cannot be checked offline against the RPC nodes antseal pays through,
and the by-hash check already covers *"already known"*. No error-variant classifier either.

*Why:* the chain resolves a lost reply ([J]) and the error cannot ([D], [D2]). The by-hash check
keeps a pooled but unmined transaction — the *"already known"* case — in the cautious arm wherever
the node exposes its pool; on the devnet's automining Anvil, by-hash null is receipt null. The
residual is a transaction mined after the window: at most one sub-batch paid twice, the bound D37
Decision 2 accepts for a kill. Whether an Arbitrum One (nitro) RPC returns a forwarded but not yet
sequenced transaction by hash is not established offline; first-come-first-served sequencing makes
that window rare either way.

#### §2 R5 — One seam for the unobserved landing, and it builds records

The unobserved-landing body becomes ONE helper that both producers call: the await failure and the
unresolved broadcast. Under `S54` it also builds the sub-batch's blob records over the local hash —
`finalize_ready_blobs(…)` exactly as the Confirmed arm does — **before** its capture, so the
capture carries records, a cost and proofs.

*Why:* two producers of one shape must not drift. The records make the capture's cost true, let
the resume's records-keyed remainder skip the sub-batch, and are what R9 resolves (§1.4, §1.6).

#### §2 R6 — Words (no Display moves; no snapshot)

- `StorageError::Payment`'s doc names its zero-ANT producers, R4's absent arm included.
- `StrandedPayment`'s doc: an unobserved first landing, or a first broadcast whose fate the chain
  could not be asked or that it still holds, reports 0.
- `TxStatus::Submitted`'s doc (`crates/antseal-net/src/receipt.rs:105-107`) says when it is
  journaled, and that a kill before the capture journals nothing (D37 Decision 2's window).
- The module doc's §Payment mechanics and §Provider notes (`ant_backend.rs:60-96`) describe
  sign-then-send and the three deadlines, at equal line count if possible: about 17 living
  citations sit at or below `:653`, and the citation lane re-points any that move.

*Why:* *"the hash is durable even if the receipt await is interrupted"* (`receipt.rs:105-106`)
overstates the code for a kill, and *"submission, receipt awaits, the chain-id guard, and the
payer's `eth_getTransactionReceipt` backfill all ride it"* (`ant_backend.rs:83-85`) becomes false
under R1.

#### §2 R7 — The deadlines are the adapter's constants, and three shapes are refused

`BROADCAST_DEADLINE`, `RECEIPT_DEADLINE` and `RESOLVE_WINDOW` (30 / 120 / 120 s) are adapter
constants, injectable as parameters so that tests use milliseconds. They are not config keys, so no
`U32` surface moves. Refused: journaling before the broadcast (it protects evidence, not money), a
new exit code or variant, and classifying by error text or variant.

*Why:* §1.8 sets the values. §1.7 prices the refused shapes: option (a) leaves the records-keyed
re-buy in place, and its full form (O4) needs a vault receipt format version.

### `S54` — at the resume (net half: lane L-NET4; resume half: lane L-RESUME3)

#### §2 R8 — One read on the backend trait, whose default could not ask

`trait StorageBackend` (`crates/antseal-net/src/backend.rs:203`) gains one method with a
**default** body that answers "could not ask" — e.g. `async fn payment_tx_state(&self, tx:
&TxHash) -> PaymentTxState`, with `enum PaymentTxState { Landed { block_number: Option<u64>,
confirmed: bool }, Pending, Absent, Unaskable }` (the names are the lane's; the variants are the
ruling):
- `Landed`: a receipt was read;
- `Pending`: no receipt, but the node returns the transaction by hash;
- `Absent`: no receipt, and by-hash null;
- `Unaskable`: a lookup could not be answered.

`AntCoreBackend` implements it over its provider; `AntCoreReader` keeps the default; `MockBackend`
answers from the transactions it mined, with fault modes for "submitted, never mined" and
"unaskable"; the CLI's `SealBackend` delegates (L-RESUME3). Every other implementor keeps compiling
on the default (19 at `ab7226f`, §1.6).

*Why:* the resume cannot reach the key-less reader, and the payer it already holds can ask (§1.6).

#### §2 R9 — The resume resolves before it buys

In `Pipeline::resume` (`crates/antseal-cli/src/pipeline/resume.rs`), between reading the journaled
receipt (`:185`) and the money branch (`:189`), every `Submitted` transaction in the receipt is
resolved through R8:
- **`Landed { confirmed }`** → its record's status becomes `Confirmed` and its block number is
  filled; `put_receipt`; carry on. Its blobs' records stand, and their proofs are valid, because
  nodes check the quote on the contract.
- **`Landed { !confirmed }` (reverted), or `Absent`** → that transaction's quote mappings and blob
  records are **pruned**, its `storage_cost_atto` share with them; its `TxRecord` is **kept** as
  evidence (status `Reverted` for a revert, `Submitted` for an absent one); the pruned receipt is
  journaled; and the remainder arm then re-quotes and asks for the pruned blobs with `prior:
  Some(pruned)` — **never the pre-pay arm**, which would erase the record that a transaction was
  sent.
- **`Pending` or `Unaskable`** → a retryable refusal that pays nothing (the exit-23 class):
  *"could not check whether the earlier payment transaction was mined ({reason}); nothing was paid
  — re-run when the payment RPC is reachable"*. The lane may tighten it; it must say that nothing
  was paid in this run, and why.

Every reader that **publishes** transaction hashes or counts — reveal's §7.10 receipt payload,
`status`, `list` — is measured for a kept-but-unmapped `Submitted` or `Reverted` record and must not
present it as a payment; the lane lists each reader and its verdict. R12 is the rule that census
produced.

*Why:* §1.4–§1.6. The pre-pay arm calls `consent_anchor_pay(…, None)`, which arms the sink bare
(`resume.rs:504`) and journals the fresh receipt alone (`:538-545`). A receipt pruned of its only
mapped transaction maps nothing, so at `HEAD` the branch at `:189`, which keys on
`payment_recorded`, would send it to the pre-pay arm: the ruling's "never" is that case.

#### §2 R10 — Legacy residue, recorded and not fixed

An unobserved-landing capture written before this wave holds mappings but **no** records, so a
transaction of that shape resolved as landed still cannot be finalized without re-buying: its
`PreparedChunk`s are gone. Developer vaults only: nothing is released (`Q31`).

*Why:* the records are built from the in-memory `PreparedChunk`s at the branch (§1.6), which no
resume can rebuild.

#### §2 R11 — 28's contract becomes true; none of its six surfaces is reworded for it

The six surfaces — the CLI Display (`crates/antseal-cli/src/error.rs:779-785`), the exit-code doc
(`:64-66`), `docs/user/funding-your-wallet.md:246-250` and `:271-279`, abandon's rule 2, the
resume plan, and `payment_recorded`'s doc — need no rewording for `S54`, and
`crates/antseal-cli/tests/snapshots/cli-errors.display.txt` is not re-blessed.

*Why:* after resolution a landed sub-batch is never re-bought and a never-landed one is no longer
mapped, so *"re-pays no quote the receipt already maps"* is true in substance, not only per quote
hash. D210 rewords two of the six — abandon's rule 2 and the resume plan — on its own grounds
(`U114`, `U115`); R11 asks nothing of them.

### §2 — rules added during implementation (2026-10-20, in place before first commit)

The orchestrator ruled these while the record's rows were being built: R12 from L-RESUME3's R9
reader census, while `S54`'s resume half was being built, and R13 and R14 from L-NET4's phase-1
report, whose two proposed rows it minted as `S57` and `S58` for the lane's phase 2. They bind as
the rules above do.

- **R12 — a transaction is published as part of the payment if and only if it paid a quote.** A
  transaction is published as part of the payment iff its hash is a value in the receipt's
  `tx_map`, that is, it paid at least one quote. One helper beside `payment_recorded` in
  `crates/antseal-cli/src/pipeline/journal.rs` serves every publishing reader:
  - reveal's `bundle_receipt_record` (`crates/antseal-cli/src/pipeline/reveal.rs:1179` at
    `ab7226f`): §7.10 key 0 holds the paying transactions' hashes in capture order, and key 1 the
    minimum block over them only;
  - `status`'s `ReceiptRow` (`crates/antseal-cli/src/status.rs:221-227`): `transactions` and
    `block_numbers`;
  - `receipt_backfill`'s `unfilled_block_numbers`
    (`crates/antseal-cli/src/pipeline/receipt_backfill.rs:239-245`): a kept never-mined record
    never makes a receipt read incomplete.

  **The census at `HEAD`.** reveal and `status` present a kept-but-unmapped record: each reads
  every `TxRecord` (`reveal.rs:1180-1196`; `status.rs:394-403`, `transactions:
  receipt.txs.len()`). So `S54` would add a never-mined `Submitted` hash to key 0, and could make a
  pruned first-sub-batch `Reverted` block §7.10's minimum. `list` reads no transaction field:
  `command grep -c` of `\.txs` and of `tx_hash` over `listing.rs` at `ab7226f` gives 0 and 0
  (control: `\.txs` over `status.rs`, 2).

  **It also corrects a record `HEAD` already writes.** A later sub-batch that reverts journals its
  `Reverted` record as gas evidence, unmapped (`S50`'s in-band arm, D204 §2 R3). For such works
  §7.10 key 0 and key 1 and the `status --json` values change; no key moves. Ruled acceptable
  before `U32`: the registry defines key 1 over key 0's transactions — *"the Arbitrum One block
  number of the **earliest-confirmed** transaction in key 0"* (`docs/format/registry-v1.md:934`)
  — so key 1 follows key 0. Lane: L-RESUME3, by scope grant. *(Added in place before first
  commit; see §6.)*
- **R13 (`S57`) — every payment-RPC error text that reaches a reason is redacted.** Every
  payment-RPC error text that reaches a reason in `crates/antseal-net/src/ant_backend.rs` passes
  `redact_rpc_error` (URLs, then 16+-hex runs): `chain_id_guard`, `fill_block_numbers`,
  `estimate_gas_wei`, `raw_balances` and any other site the lane's census finds; one test per site
  with a canary in the stub URL's path. Row `S57`, from L-NET4's finding. Lane: L-NET4 (phase 2).
  *(Added in place before first commit; see §6.)*
- **R14 (`S58`) — every payment-RPC read outside the submission step is bounded, and a deadline
  keeps the call's class.** Every payment-RPC read outside the submission step (connect's chain-id
  guard, the quote's gas price, the preflight balance and allowance reads, the backfill's receipt
  reads, finalize's proof-age read) is bounded by the adapter's deadline helper at
  `BROADCAST_DEADLINE`; a deadline maps to the call's **existing** class — a timed-out proof-age
  read is unreadable, i.e. not expired (D179 R3), a timed-out backfill read returns
  `fill_block_numbers`' **existing** failure (`StorageError::Network`, its documented contract)
  and the U67 host skips it silently as it skips every backfill error (clarified by message:
  L-NET4's option (b)), the others their current variant with a reason naming the deadline.
  Census additions accepted: `ensure_allowance`'s approve-failure reason (`S57`) and its
  approve-receipt read (`S58`; a timeout keeps the existing unreadable behaviour, gas counted 0).
  Row `S58`, from L-NET4's finding. Lane: L-NET4 (phase 2). *(Added in place before first commit;
  see §6.)*

### What no ruling here moves

- **No exit code is minted and no class is added.** 23, 28 and 37 keep their meaning, and D134
  §2 R3's append-only table is untouched. One producer changes class within the table: a first
  broadcast whose fate the chain could not be asked, or that it still holds, moves from 23 to 28
  (37 when the capture was not durable), as D204 moved the zero-count revert the other way. A lost
  reply resolved as a landing is no error at all, and answered-and-absent stays 23.
- **No `StorageError` or `CliError` Display, and no snapshot.** `cli-errors.display.txt` is not
  re-blessed (R11): its two 23 entries (`:55-58`) are a quote failure and a vault-local reveal, and
  its 28 entry (`:87-88`) carries a revert reason.
- **No `--json` key, config key, help line or user document.** `--json` values move only under
  R12. No user document quotes `Payment`'s text: `git grep -c 'before any ANT moved' ab7226f --
  docs/user` matches no file (control: `crates/antseal-net/src/error.rs`, 2).
- **No vault format change.** No `TxRecord` field is added; R9's pruned receipt and kept record use
  existing fields and states.
- **The gate.** This is the payment path. `crates/antseal-net/`, `crates/antseal-cli/src/pipeline/`
  and `crates/antseal-cli/src/backend.rs` are on `scripts/gate-features.sh`'s `HEAVY_TRIGGER_PATHS`
  (`:112-121`), so the close gate runs against `ANTSEAL_GATE_BASE=origin/main` with the heavy tier
  and the devnet E2E forced (`ANTSEAL_GATE_HEAVY=1 ANTSEAL_GATE_E2E=1`).

## 3. Fault plants

The implementing lanes owe these. Neither seam exists at `ab7226f`, so each green's red baseline is
the plant that puts `HEAD`'s behaviour back inside the new seam, run first. Every plant must
compile and is judged by its message; every restore is followed by a `touch` and a sha256 check
against the lane's final file.

**`S51` — the green tests, the load-bearing half.** In-crate, under `cargo test -p antseal-net
--features ant-backend --lib`, in a new module appended to `ant_backend.rs`'s `mod tests`. The
production wallet provider drives the seam with no ant-core `Client`: `WalletKey::import`, a devnet
`NetworkConfig` whose `rpc_url` is a loopback JSON-RPC stub (the shape of `devnet_base()`,
`ant_backend.rs:2275`), `evm_wallet`, then `Wallet::to_provider()`. The stub is generalised from
`mod s43_block_time`'s (`:2695`), whose own tests must not move. It answers `eth_chainId`,
`eth_getTransactionCount`, `eth_estimateGas` and `eth_feeHistory`, and switches
`eth_sendRawTransaction`, `eth_getTransactionReceipt` and `eth_getTransactionByHash` per test.
- **G1** — a lost reply whose transaction lands is a landing: the receipt's hash is the local
  hash, and the stub holds exactly the signed bytes.
- **G2** — a lost reply the chain never shows (receipt null, by-hash null) is `Payment`, and its
  reason names the window.
- **G3** — an unaskable chain after a lost reply is the unobserved shape: one `Submitted` record
  for the local hash, the batch's quotes mapped, the records built (`S54`), one capture (through a
  recording hook, as `recording_hook`, `:3113`, serves `settle_sub_batch`'s tests), and
  `StrandedPayment { landed_tx_count: 0 }`.
- **G4** — a refusal inside fill sends nothing: 0 `eth_sendRawTransaction`, and `Payment`.
- **G5** — an error object does not decide: `eth_sendRawTransaction` answers *"already known"*,
  receipts are served, and the outcome is the landing.
- **G6** — the broadcast and the await are bounded: with millisecond deadlines, a hung broadcast
  and null receipts return within the deadline plus slack.
- **G7** — the journaled hash is the local one, though the stub echoes a different hash.
- **G8** — by-hash shows a held transaction: the unobserved shape, not `Payment`.
- **Unchanged and green:** every `settle_sub_batch`, `S43`, `S46`, `S49` and `S50` test in the lib
  (the net crate's `ant-backend` lib suite is 146 at `ab7226f`, by L-NET4's subtraction and a
  static count; wave 40's checkpoint figure, 489, summed it with the CLI's), and, at the gate, the
  devnet suites `devnet_backend` and `e2e_kill_resume`: every devnet payment now goes through
  `fill` and `send_raw_transaction`, so the devnet E2E is the wiring witness. No devnet suite can
  drop a reply without a proxy; the in-crate stub is the seam's proof.

| Plant | What it puts back or breaks | Must redden |
|---|---|---|
| P51-a | `HEAD`'s rule: any send error → `Payment`, no resolution (the red baseline) | G1 (a landing expected, `Payment` got) and G5 |
| P51-b | classify by variant: `ErrorResp` → `Payment` with no lookup | G5 |
| P51-c | a deadline dropped | G6, by its own timeout message |
| P51-d | the echoed hash journaled | G7 |
| P51-e | the unaskable arm mapped to `Payment` | G3 (`StrandedPayment { landed_tx_count: 0 }` expected) |
| P51-f | the by-hash check dropped | G8 |

**`S54`, net half.** `MockBackend`'s resolution answers — landed, reverted, never mined,
unaskable — in its own unit tests.

**`S54`, resume half** (L-RESUME3), in-process over `MockBackend`:
- **The red baseline** is P1's §7.1 double turned into a test: with the resolution removed, the
  blobs are bought twice, asserted **per address**, not by `double_paid()` (§1.4).
- **Landed** → no consent is asked, finalize completes, and each blob is paid once.
- **Absent** → the pruned blobs are re-quoted and asked for, the `TxRecord` is kept, and the cost
  recorded equals what actually moved.
- **Reverted** → the same, with status `Reverted`.
- **Pending or unaskable** → the exit-23 class, no consent asked, nothing paid.
- **The reader census** (`S54`'s third Accept clause; R12): each publishing reader, given a
  kept-but-unmapped record, does not present it as a payment.

| Plant | What it breaks | Expected red, as ruled |
|---|---|---|
| P54-1 | the resolution skipped | a double purchase, per address |
| P54-2 | the resolution moved after the money branch | the remainder buys nothing, and finalize loops |
| P54-3 | a pruned transaction's `TxRecord` dropped | the absent case |
| P54-4 | the pruned receipt routed through the pre-pay arm | the absent case: the `TxRecord` vanishes |

**What P54-1 can redden — the records lane's reading, for the lane to settle by message.** With
R5's records in the capture, the remainder skips the sub-batch whether or not R9 runs, so a skipped
resolution cannot buy a landed sub-batch twice: the landed green stays green under P54-1, and the
plant shows on the absent and reverted cases (no consent is asked for blobs that were never paid
for). The per-address double purchase is `HEAD`'s capture shape — mappings and no records — which
R5's records cure; R9 cures the never-mined loop (§1.5) and lets the pruned blobs be bought once. A
double that captures no records also models R10's legacy shape, which re-buys even with R9. The
lane states which green each plant reddens.

**Venue.** `ant_backend.rs` compiles only under `ant-backend`, which no other lane builds in the
shared target, so its plants may run in the tree under the exclusive writer lock, with the restore,
`touch` and sha256 protocol. Plants in `backend.rs`, `test_util/mock.rs`, `receipt.rs` or
`error.rs`, which every lane compiles, and every L-RESUME3 plant, go in a shadow copy with a
private target. No lane builds `-p antseal-cli --features ant-backend` in the shared target.

## 4. What this record does NOT decide

- **D37 Decision 2's kill window.** A kill between the broadcast and the capture journals nothing
  at `HEAD`, under H2 and under this ruling; R4 widens the window only by the resolution window,
  and only after a failed broadcast. Only O4 closes it for money (M–L, with a vault receipt format
  version). Recorded, not ruled; no row.
- **R4's residual.** A transaction mined after the window is paid twice: at most one sub-batch,
  the bound D37 Decision 2 accepts for a kill. Whether nitro returns a forwarded but unsequenced
  transaction by hash is not established offline.
- **The contract's own predicate as a further guard.** Checking `completedPayments(quoteHash)` = 0
  for every mapped quote before anything is pruned (P1 §7.2 (4); the `IPaymentVault` interface is
  reachable as `ant_protocol::evm::contract::payment_vault::interface`) is optional, and not ruled.
- **Answered-and-absent as `Payment`.** P1 §5 put R4's middle arm to the maintainer as a question.
  The rulings took P1's recommendation (`Payment`, a 120 s window), hardened by P1 §7.7's by-hash
  check. Nothing is released (`U32` has not happened), so the arm can be revisited before `U32`
  without renumbering anything.
- **Legacy captures** (R10): recorded, not fixed.
- **`abandon` on an unresolved work.** `abandon` builds no backend, so it cannot ask the chain; a
  work stranded by R4's unaskable arm stays refused by rule 2 until a resume resolves it. D210
  words rule 2's two clauses.
- **What `S53`'s expired-proof arm carries.** D209 R5 rules how that arm treats what R9 leaves: a
  pruned, never-mined transaction is not money spent, and a replaced receipt's kept evidence
  records are not carried, because the arm runs only after R9 has resolved every `Submitted`
  transaction. That is D209's ruling, not this record's.
- **Instrument findings** (the orchestrator's, for `docs/instrument-ledger.md`): `S51`'s Accept
  clause *"(a retry does not pay a quote the vault records as possibly paid)"* cannot fail — D36
  never re-pays an old quote hash, and the blob is re-bought under a new one — so the orchestrator
  restates it (P1 §2 (g)); `crates/antseal-net/tests/devnet_backend.rs:472-483` proves backfill over
  a `Submitted` receipt the pipeline cannot produce (block numbers stripped from a complete
  receipt), while nothing covered the shape the branch does produce; `MockBackend::double_paid()`
  cannot see a re-purchase under fresh quotes (§1.4); and three records' prose, which this record's
  addenda answer (D203 §1.4 and M1, D37's S31 amendment, D33's residual risk 2).
- **New rows.** This record mints none. P1's row B (the missing deadlines) is folded into `S51` by
  R2, R3 and R7, and is not minted.

## 5. Edit list — per write scope, with the lane named before this record was written

### L-NET4 (round 2) — `S51`, then `S54`'s net half

Order: (1) the trait read, its result type and `MockBackend`'s support, with unit tests, then a
message to the orchestrator giving the exact signature, on which L-RESUME3 builds; (2) `S51`
(R1–R7, G1–G8, the P51 plants); (3) `S54`'s net half (R5's records at the branch, and
`AntCoreBackend`'s resolution over its provider, tested against the stub).
- `crates/antseal-net/src/ant_backend.rs`: `pay`'s submission (`:700-760` at `ab7226f`; the request
  build stays, and `send_transaction` becomes R1–R4); new private helpers (sign; broadcast, await
  and resolve; R5's lifted unobserved-landing helper, which also builds the records); the three
  deadline constants, after `stranded_or_payment` (`:1756`); `impl StorageBackend for
  AntCoreBackend`'s resolution method (`AntCoreReader` keeps the default); the module doc's
  §Payment mechanics and §Provider notes (`:60-96`, at equal line count if possible); and new test
  modules appended at the end of `mod tests`.
- `crates/antseal-net/src/backend.rs`: only `trait StorageBackend` (`:203`) — the new method and
  its default body — and the result type beside it, with a unit test.
- `crates/antseal-net/src/test_util/mock.rs`: only `impl StorageBackend for MockBackend` (`:364`)
  and the fault modes the resolution needs (never mined; unaskable), with unit tests.
- `crates/antseal-net/src/receipt.rs`: only `TxStatus::Submitted`'s doc (`:105-107`, at equal line
  count) and, optionally, a pure pruning helper on `PaymentReceipt` placed below `:162`, so that no
  living citation moves.
- `crates/antseal-net/src/error.rs`: only the docs of `Payment` (`:37-42`) and `StrandedPayment`
  (`:82-95`; R6's sentence is `:83-85`). No `#[error]` text moves.
- `crates/antseal-net/src/lib.rs`: only a re-export of the new result type, if the crate's pattern
  needs one.
- **Builds:** `cargo test -p antseal-net --features ant-backend --lib` and
  `cargo clippy -p antseal-net --features ant-backend --all-targets -- -D warnings` in the shared
  target under the lock, and the default-feature test and clippy. Plants per §3's venue.
- **Must not:** any `antseal-cli` file, `crates/antseal-net/tests/**` (if a devnet suite pins
  changed text, the lane stops and asks), `docs/**`, or any snapshot.

### L-RESUME3 (round 2; after its `S53` and `S55` work) — `S54`'s resume half, and R12

- `crates/antseal-cli/src/pipeline/resume.rs`: the resolution step between the receipt read
  (`:185`) and the money branch (`:189`), with its private helper, and tests appended at the end
  of its `mod tests`. (The lane's `S53` and `S55` edits in this file are D209's.)
- `crates/antseal-cli/src/backend.rs`: only `impl StorageBackend for SealBackend` (`:1855`), one
  delegation of the new method. It compiles only under `ant-backend`: the lane compiles it, if at
  all, in a private target, and the orchestrator's heavy checkpoint covers it.
- `crates/antseal-cli/src/pipeline/journal.rs`: R12's helper beside `payment_recorded`, and
  `payment_recorded`'s doc (`:1150-1164`) if R9 makes a sentence of it false.
- R12's readers, by scope grant: `crates/antseal-cli/src/pipeline/reveal.rs`
  (`bundle_receipt_record`, `:1179`), `crates/antseal-cli/src/status.rs` (`ReceiptRow`'s
  construction, `:394-403`) and `crates/antseal-cli/src/pipeline/receipt_backfill.rs`
  (`unfilled_block_numbers`, `:239-245`).
- `crates/antseal-cli/tests/seal_matrix.rs`, and `tests/seal_resume.rs` once the orchestrator hands
  it over: new tests appended at the end (or a new in-process test file of the lane's own).
- **Builds:** pipeline unit tests and in-process test files in the shared target under the lock;
  plants in a shadow with a private target.
- **Must not:** `crates/antseal-cli/src/seal_resume.rs` (L-MONEY2's), `listing.rs`, `commands.rs`,
  `crates/antseal-net/**`, snapshots or `docs/**`.

### L-MONEY2 — no edit for this record

D210's copy (abandon's rule 2, the resume plan, the proof clock) reads `payment_recorded`, which
this record does not change; R11 asks nothing of it.

### The citation lane (round 3) — living-doc citations

At `ab7226f` the living documents carry 14 prefixed `ant_backend.rs:N` tokens
(`docs/threat-model.md` 6, `docs/user/wallet-hygiene.md` 5, `docs/user/funding-your-wallet.md` 3;
about 17 with bare continuations and the two code comments in `antseal-anchor`,
`arbitrum/endpoints.rs:61` and `arbitrum/confirm.rs:55`, both citing `ant_backend.rs:243`). All sit
at or below `:653`, so they move only if a line is added above `:704`. `receipt.rs` has two
(`docs/threat-model.md:863`, `docs/user/wallet-hygiene.md:380`), which move only if R6's doc edit
changes the line count. The citation lane re-points them by meaning after the last code edit.

### RECORDS-1 — this record and dated addenda

D37, D33, D204, D147 and D203, each citing this record.

### Orchestrator — `TODO.md`, `tasks/S.md`, `docs/decisions/README.md`, `docs/instrument-ledger.md`

- `S51` and `S54`: their ticks, against §3; `S51`'s Accept restated (P1 §2 (g)); this record's index
  row and register rows.
- P1's instrument findings (its §3 and §7.6) for the ledger (§4).
- The close gate: `ANTSEAL_GATE_BASE=origin/main` with `ANTSEAL_GATE_HEAVY=1
  ANTSEAL_GATE_E2E=1`.

## 6. As built — wave 41, lanes L-NET4 and L-RESUME3 (recorded in place before this record was first committed)

### The adapter (lane L-NET4)

Every verdict below was read from an exit file, except the final `rustfmt --check` and
plant-marker verdicts, which have none; this records lane re-ran both, and both agree. Every red
was judged by its message, and every exit file and verdict line read back matches the report; the
one run the report omits is named below. L-NET4 measured against `ab7226f`. Phase 1 built `S51`
(R1–R7) and `S54`'s net half (R5's records and R8); phase 2 built `S57` and `S58` under R13 and
R14. Re-read for this section, the six files equal the lane's final sha256, and `git diff --stat`
over `crates/antseal-net` reads 6 files, +2966/−214, as reported. No manifest, `tests/**`,
`docs/**` or snapshot file was written.

- **Grants and rulings, from the orchestrator's dispatch log.** One scope grant (13:11Z):
  `Method::PaymentTxState` (`crates/antseal-net/src/test_util/mock.rs:99`), outside the `impl`
  block §5 named. The same entry accepted the std-only timer on four proofs (it bounds, it drops
  the loser without blocking, it leaks no thread, it holds on the CLI's runtime flavour), and
  preferred alloy's `with_timeout` for the receipt await if that bounded it. At phase 1's close
  (13:47Z) the orchestrator minted `S57` and `S58` from the lane's proposed rows A and B and ruled
  R13 and R14; at 13:49Z it answered phase 2's one question with option (b) for a timed-out
  backfill read and accepted two census additions (§2's added rules).
- **§2 R1.** `pay` (`crates/antseal-net/src/ant_backend.rs:564`) builds `let signer =
  self.wallet.to_provider();` once per payment (`:664`) and runs each sub-batch through
  `pay_sub_batch` (`:1817`), whose `sign_sub_batch` (`:1985`) calls `FillProvider::fill` and takes
  the hash from the signed envelope before a byte is sent; a failure there is `Payment` at 0 (the
  table's first row, below). The lane chose this over a field beside the erased provider: a field
  means a struct and `connect` edit above `:653`, moving about 17 living citations, and one
  `to_provider()` opens no socket. Over the file, `.fill(` now counts 1, `send_raw_transaction` 2
  and `send_transaction(request)` 0 (§1.1, at `ab7226f`: 0, 0 and 1).
  - **Deviation: preparing is bounded too**, by `BROADCAST_DEADLINE`, which R1 did not name. A
    fill that times out sent nothing, so it is `Payment` at 0.
- **§2 R2.** `submit_signed` (`:2032`) broadcasts the envelope's `encoded_2718()` bytes with
  `send_raw_transaction` under the broadcast deadline. An acknowledgement that echoes another hash
  counts as none, and the hash journaled is always the one computed from the signed bytes
  (`SignedTx`, `:1972`).
  - **Deviation: a receipt counts only for the hash that was asked** (`classify_receipt`,
    `:2177`): another transaction's receipt is a lookup not answered — R2's echo rule, applied to
    every read.
- **§2 R3.** `await_receipt` (`:2065`) polls by the local hash until `RECEIPT_DEADLINE`. A receipt
  takes the landed path, `settle_sub_batch` (`:1629`, byte-identical to `ab7226f`'s); no receipt
  by the deadline is the unobserved shape, never `Payment`.
  - **Deviation: the await is the adapter's own loop, not alloy's `with_timeout`.** The lane's
    probe (alloy =1.8.3, a private target, build and run exit files 0) found that it bounds only
    while lookups answer: null lookups ended after 620.99 ms at a 600 ms timeout, one dropped
    lookup ended the await after 0.87 ms, and a held one read *"STILL WAITING after
    6.001162601s: not bounded"*. `get_receipt` awaits each fetch after its `select!` with the
    watcher (alloy-provider 1.8.3, `src/heart.rs:251-260`), so §1.3's [I] holds only while every
    lookup answers. In the loop a failed lookup is not an answer, and R3's "looked up once more"
    is its last lookup, made before it checks the deadline.
  - **Deviation: a fourth constant**, `RECEIPT_POLL` = 1 s (`:1730`), the pause between lookups.
- **§2 R4.** `resolve_unacknowledged` (`:2103`) polls the receipt by the local hash for
  `RESOLVE_WINDOW`, re-broadcasts the identical bytes once after the first lookup that finds no
  receipt (its result ignored), and asks `eth_getTransactionByHash` once at the end
  (`transaction_by_hash`, `:2205`). A receipt is the landed path; every lookup answered empty and
  by-hash `null` is `Payment` at 0; a held transaction, or any lookup left unanswered
  (`could_not_check`, `:2155`), is the unobserved shape. No production line matches `.contains("`
  (the file's 23 matches sit in `mod tests`, which opens at `:2874`) or an error variant.
  - **Deviation: each lookup, inside the window too, is bounded by `BROADCAST_DEADLINE`**, and the
    window bounds the polling, not the lookup in flight, so a slow answer still counts; a first
    draft raced lookups against the window. Worst case for one unresolved sub-batch, per the
    lane's report: about 4.5 minutes (five 30 s bounds and the 120 s window); unbounded at
    `ab7226f`.
  - **Deviation: by-hash is read as `null` or not only** (`raw_request` into
    `Option<serde::de::IgnoredAny>`), so an RPC's extra fields cannot turn "held" into "could not
    be asked".
  - **Deviation: new reasons redact URLs as well as hashes.** `redact_rpc_error` (`:2272`)
    replaces every URL, then applies `redact_evm_error`'s 16+-hex rule: a transport error names
    the RPC URL, and a private endpoint can carry a credential in its path. R13 extends it.
- **§2 R5, with `S54`'s records.** `strand_unobserved` (`:1928`) is the one body both producers
  call. It pushes the `Submitted` record for the local hash, maps the sub-batch's quotes to it,
  builds the blobs' records over it with `finalize_ready_blobs` as the Confirmed arm does,
  delivers one capture, and only then returns `StrandedPayment` with the confirmed count. The G
  rows' shared check asserts one record, its proof and a `storage_cost_atto` of 300.
  - **Deviation: a proof that cannot be built** leaves its blob without a record (S49's rule), and
    the reason gains *"; and a proof could not be built: {detail}"*.
  - **Deviation: `pay`'s loop state moved into `PayLoop`** (`:1759`; `SubBatch`, `:1785`), so
    the stub tests drive `pay_sub_batch` with no Autonomi `Client`.
- **§2 R6**, at equal line counts. §Payment mechanics (`ant_backend.rs:65-68`): each tx *"is
  signed and its hash computed here before it is broadcast, and its receipt is read by that hash
  under three deadlines — the chain, not an RPC error, settles a broadcast's fate"*; §Provider
  notes (`:83-85`): `pay` *"signs on a fresh `to_provider()` first, whose `fill` the erased one
  lacks"*. `Payment`'s doc (`error.rs:37-42`) adds *"a broadcast that was not acknowledged never
  showed on the chain within the resolution window (D208)"*, and `StrandedPayment`'s (`:84-86`)
  *"or a first broadcast the chain could not settle or still holds (D208), reports 0"*; the
  reflow turned the next sentence's *"before this error surfaces"* into *"first"*.
  `TxStatus::Submitted` (`receipt.rs:105-107`) is *"journaled with its sub-batch's records when
  the landing went unseen or the broadcast's fate stayed unknown; a kill before that capture
  journals nothing (D37 Decision 2's window)"*. No `#[error]` text moved. Up to `ab7226f`'s
  `:653` every hunk is count-neutral except a +2 at `:471` and a −2 at `:476`, which cancel inside
  `ensure_allowance`; the first net change is +10 at `:659`. The living citations into that
  stretch (`:469`, `:469-471`, `:460-478`) still name the same code.
- **§2 R7.** `BROADCAST_DEADLINE` 30 s, `RECEIPT_DEADLINE` 120 s and `RESOLVE_WINDOW` 120 s
  (`:1718-1727`) feed `SubmitDeadlines::PAYMENT_RPC` (`:1735-1755`), which `pay` passes; the
  tests pass milliseconds (`FAST`: 1 500, 600 and 600 ms). They are not config keys, so no `U32`
  surface moved, and no journal-first write, exit code, variant or classifier was added.
  - **Deviation: the deadlines are a std-only helper-thread timer, not `tokio::time::timeout`.**
    P1's plan named `tokio::time::timeout` and *"no manifest change"*, which cannot both hold: the
    library takes no tokio edge (S6's recorded decision; tokio is a dev-dependency only,
    `crates/antseal-net/Cargo.toml:123-131`), and the manifest was outside the lane's scope.
    `Deadline` (`:2430`) starts one helper thread (`Alarm`, `:2471`) on its first pending poll;
    the thread waits on `recv_timeout`, then wakes the task, and dropping the deadline drops the
    channel's `Sender`, which ends the thread. A thread that cannot start leaves the deadline
    passed: the RPC counts as unanswered, which no outcome reads as "nothing moved". `within` and
    `race` (`:2295`, `:2304`) poll the future first, so an answer ready at the deadline counts.
  - **The four proofs** (timing runs, `--test-threads=1 --nocapture`, exit files 0; the final
    run's figures). On a current-thread runtime a never-finishing future *"ended after 50.46933ms
    (limit 50ms)"*; during a *"300ms wait: 300.340922ms, ticker ran 45 times meanwhile"* a 5 ms
    ticker on the same thread kept running and the losing future's drop flag was set; the helper
    thread ended *"1.113µs later"* after a passed deadline and *"2.249267ms later"* after a
    cancelled one, asserted per deadline through the alarm state's `Arc` count. The CLI's payer
    runtime is `new_multi_thread().enable_all()` (`backend::ant::runtime()`, D90 §3.3), not the
    current-thread runtime the grant's fourth ask assumed, so the G rows run multi-thread, and G6's
    hung half runs on both: *"[S51 G6] hung broadcast ended after 3.018900707s (broadcast 1500ms,
    window 600ms)"*, *"[S51 G6/current_thread] hung broadcast ended after 3.010122497s"*.
  - **Deviation: G6's process-wide count of helper threads is printed, not asserted** (*"0 before
    both runs, 0 after"*): libtest runs rows in parallel.
- **§2 R8, `S54`'s net half.** `StorageBackend::payment_tx_state(&self, tx_hash: &TxHash) ->
  PaymentTxState` (`crates/antseal-net/src/backend.rs:311`) is the trait's last method, and its
  default body answers `Unaskable { reason: "this backend has no payment RPC to ask" }`.
  `PaymentTxState` (`:332`) is `Landed { block_number: Option<u64>, confirmed: bool }`,
  `Pending`, `Absent` or `Unaskable { reason: String }`, has no serde (it is never journaled), and
  is re-exported as `antseal_net::PaymentTxState` (`lib.rs:124`, the same line). `AntCoreBackend`
  answers with `read_payment_tx_state(&self.provider, tx_hash, BROADCAST_DEADLINE)`
  (`ant_backend.rs:878-879`; the body at `:2228`), the receipt first, then by-hash;
  `AntCoreReader` keeps the default. `MockBackend` (`test_util/mock.rs:709`) answers from the
  transactions it mined, with no new `Inner` state, and has three fault modes:
  `Fault::Unobserved { sub_batch, chain: TxStatus }` (`:147`), `Fault::PaymentTxHeld` (`:156`,
  `Pending`) and the existing `Fault::NetworkOn(Method::PaymentTxState)` (`Unaskable`). The
  orchestrator relayed the signature to L-RESUME3 after step 1's two greens (13:11Z).
  - **Deviation: `Method::PaymentTxState`**, the granted lines outside the `impl` block, so the
    network fault can target the read and the call log stays complete.
  - **Deviation: `Fault::Unobserved` returns `Ok(receipt)`**, the capture-shaped receipt (the
    transaction `Submitted`, its quotes mapped, its records built), because the mock has no
    capture hook; a test double journals it and strands.
  - **Deviation (naming): `Unaskable` carries a redacted `reason`**, which R8's variants left open.
- **R13 (`S57`).** Every payment-RPC error text that reaches a reason passes `redact_rpc_error`,
  most through one body, `bounded_read(what, limit, read)` (`ant_backend.rs:2337`), which also
  applies R14's bound and the network class. The census as built: `chain_id_guard` (`:1181`),
  `gas_price_wei` (`:2353`, for `estimate_gas_wei`), `ant_balance` and `gas_balance` (`:2358`,
  `:2368`, for `raw_balances`), `standing_allowance` (`:2379`, for `ensure_allowance`),
  `fill_block_numbers` (`:1210`), and the census's addition, `approve_failure` (`:2395`, *"token
  approve failed: {redacted}"*, which had redacted hashes only). Checked and unchanged, per the
  lane's report: `to_evm_network` and `evm_wallet` (fixed texts with no URL; `EvmConfigError`'s
  names the network, `crates/antseal-net/src/evm.rs:123`), the offline calldata and proof
  failures, the Autonomi storage errors and the submission step. Six rows, `s57_…_names_no_url`,
  put the canary `canary-s57-zqpw` in the stub URL's path and assert that the reason holds no
  canary, no `://` and no `127.0.0.1`, but does hold *"error sending request for url (<url
  redacted>)"*: the transport error reached the reason and lost its URL.
  - **Deviation: the approve failure is pinned at its mapping**, fed a real transport error made
    against the canary stub inside evmlib's wrapping text, because evmlib retries a failed approve
    for about 56 s and its error types are not reachable from antseal-net. `ensure_allowance`
    calls it as `.map_err(|e| approve_failure(&e))` (`:478`).
  - **Deviation: the retried ERC-20 reads' redaction is reachable only past the deadline.**
    evmlib retries `balanceOf` and `allowance` three times, 4, 16 and 36 s apart, so under R14 a
    failing RPC ends those reads at 30 s. One slow row, `s57_the_retried_erc20_reads_name_no_url`
    (both reads at once, a 90 s limit, about 56 s), pins the redaction. Its first draft, at
    300 ms, passed vacuously (its reason was the deadline's) and was caught by timing each row
    alone; the replacement's two rows then took 56.39 s and 56.49 s, every other phase-2 row
    0.06–0.69 s, and the two became one row that runs both reads at once.
- **R14 (`S58`).** Each read outside the submission step is bounded at `BROADCAST_DEADLINE` and
  fails as its call always did. The chain-id guard (`connect`'s, `:275`, and the receipt
  reader's, `:1073`), the gas price, both balances and the allowance fail as `Network` with
  *"{what}: no answer within 30 s"*. `fill_block_numbers` fails as `Network` with
  *"eth_getTransactionReceipt failed: no answer within 30 s"*, option (b), and
  `AntCoreReceiptReader::backfill_block_numbers`' `# Errors` names the deadline (`:1097-1099`).
  The approve's receipt read, `approve_gas_wei` (`:2407`), counts 0 gas. Finalize's proof-age
  read, `paying_block_time_within` (`:2843`), answers `None` (unreadable, so not expired, D179 R3)
  when either of its two reads times out. Seven rows, `s58_…_is_bounded`, hold every stub method
  open for 30 s, inject 300 ms under a 20 s outer limit, and require each read to end within
  [300 ms, 3.3 s) with its exact class and reason. `status`'s U67 host keeps its own 10 s
  `PAYMENT_RPC_BUDGET` (`crates/antseal-cli/src/backend.rs`), so there the 30 s bound is defence
  in depth.
  - **Deviation: the approve itself is not bounded by antseal.** It is a write, which evmlib
    already bounds (a 5 s send timeout, a retried watch), and R14 lists reads.
  - **Deviation: signatures.** `chain_id_guard` and `fill_block_numbers` take a `limit` parameter
    (no existing test calls them), while `paying_block_time` keeps its signature, which the S43
    rows call, and delegates to `paying_block_time_within`.
  - **Deviation: three method bodies above `:653` keep their line counts with explanatory
    comments** (`estimate_gas_wei`, `:384`; `raw_balances`, `:405`; `ensure_allowance`, `:460`):
    the reads moved into free functions that a test can call without a live `Client`.

**The exit classes now**, the lane's table verbatim (the CLI's mapping is unchanged: `Payment` →
`network-failure`, 23; `StrandedPayment` → `payment-stranded`, 28, when the latest capture was
durable, else `payment-unrecorded`, 37, by `pipeline/resume.rs`'s split):

| producer (ant_backend.rs) | class | reason (verbatim; `{…}` redacted) |
|---|---|---|
| R1: fill / sign refused or timed out (nothing sent) | 23 at k = 0 (`stranded_or_payment(k, …)`: 28/37 at k ≥ 1) | `sub-batch tx could not be prepared: {e}` · `… : the payment RPC did not answer within 30 s` · `… : the wallet's fillers left the transaction unsigned` |
| R4: not acknowledged; every lookup answered without a receipt for 120 s; by-hash `null` | 23 at k = 0 (28/37 at k ≥ 1) | `the payment transaction was not accepted ({detail}), and the chain did not show it within 120 s` — `{detail}` ∈ `{e}`, `no acknowledgement within 30 s`, `the payment RPC acknowledged a different transaction hash` |
| R4: not acknowledged; a lookup unanswered (error, 30 s, or another hash's receipt) | 28 / 37, `landed_tx_count = k` (0 at k = 0) | `the payment transaction's broadcast was not acknowledged ({detail}), and whether it was mined could not be checked: {why}` |
| R4: not acknowledged; by-hash returns the transaction (held, unmined) | 28 / 37 | `the payment transaction's broadcast was not acknowledged ({detail}), and after 120 s the payment RPC still holds it unmined` |
| R3: acknowledged; no receipt within 120 s (polling through failed lookups) | 28 / 37 — never 23 | `sub-batch tx landing not observed: no receipt within 120 s` (+ ` (the last lookup: {why})`) |
| any unobserved shape whose proof could not be built | 28 / 37 | `{reason}; and a proof could not be built: {detail}` |
| a lost reply / an error object / another echo, and the chain SHOWS the receipt | no error — the landed path (`settle_sub_batch`) | — |
| unchanged: D36 stale quote; token approve failure; pre-pass proof failure; S50 first-sub-batch revert; calldata failure at k = 0 | 23 | as before |
| unchanged: S49 proof failure after a landing; S46 not-durable capture mid-sequence; S50 later revert; calldata failure at k ≥ 1 | 28 / 37 | as before |

The one producer whose class moved is the one "What no ruling here moves" names: an unaskable or
held first broadcast, 23 → 28/37. R13 and R14 moved no class.

- **Tests, by name and count.** `cargo test -p antseal-net --features ant-backend --lib`: 146 at
  `ab7226f` (by subtraction, per the lane's report; wave 40's L-NET3 reported 145 at its close,
  and a static count of the crate's test attributes gives 146 at `ab7226f` and 181 now), 153
  after step 1, 167 after phase 1's first build, 168 at phase 1's close (*"test result: ok. 168
  passed; 0 failed; … finished in 9.23s"*) and 181 at phase 2's close (*"… 181 passed; 0 failed;
  … finished in 62.16s"*). The default `cargo test -p antseal-net` passed every target in both
  phases: lib 123 (116 at `ab7226f`), `allowance_policy` 7, `devnet_backend` 0,
  `live_display_channel` 5, `live_section_bridge` 7, `no_upstream_peer_state` 6,
  `storage_constants` 6, `storage_gate` 1. Both clippys (`--all-targets -- -D warnings`, default
  and `ant-backend`) exited 0 in both phases, as did the personal-data and copy-style checks at
  phase 1's close.
  - In `mod tests::s51_submission` (`ant_backend.rs:4328`), appended at the end of `mod tests`,
    15: G1 `s51_a_lost_reply_whose_transaction_lands_is_a_landing`, G2
    `s51_a_lost_reply_the_chain_never_shows_is_a_payment_that_moved_nothing`, G3
    `s51_an_unaskable_chain_after_a_lost_reply_is_the_unobserved_shape`, G4
    `s51_a_refusal_inside_fill_sends_nothing`, G5 `s51_an_error_object_does_not_decide`, G6
    `s51_the_broadcast_and_the_await_are_bounded` and its twin
    `s51_the_broadcast_deadline_holds_on_a_current_thread_runtime`, G7
    `s51_the_journaled_hash_is_the_local_one`, G8
    `s51_a_transaction_the_chain_still_holds_is_the_unobserved_shape`; the k ≥ 1 row
    `s51_an_unobserved_later_sub_batch_strands_with_the_landed_count`; the read
    `s54_the_payment_rpc_reads_landed_reverted_pending_absent_or_unaskable`; the timer proofs
    `s51_a_deadline_bounds_a_future_that_never_finishes`,
    `s51_a_deadline_drops_the_loser_and_never_blocks_its_thread` and
    `s51_a_deadline_thread_ends_with_its_deadline`; and
    `s51_rpc_error_reasons_name_no_url_and_no_hash`. Their stub is a copy of the S43 stub,
    generalised to a stateful chain that serves each connection on its own thread; the only hunk
    in `ab7226f`'s `mod tests` is the append, so the S43 module and every earlier test are
    byte-unchanged.
  - In `mod s57_s58_reads` (`:5500`), inside it, 13: `s57_the_chain_id_guard_names_no_url`,
    `s57_the_gas_price_read_names_no_url`, `s57_the_gas_balance_read_names_no_url`,
    `s57_the_retried_erc20_reads_name_no_url`, `s57_a_failed_approve_names_no_url`,
    `s57_the_backfill_read_names_no_url`, `s58_the_chain_id_guard_is_bounded`,
    `s58_the_gas_price_read_is_bounded`, `s58_the_balance_reads_are_bounded`,
    `s58_the_allowance_read_is_bounded`, `s58_the_approve_gas_read_is_bounded`,
    `s58_the_backfill_read_is_bounded` and `s58_the_proof_age_reads_are_bounded`.
  - §3's "`S54`, net half", 7: `s54_the_default_resolution_read_could_not_ask` (`backend.rs:536`)
    and, in `test_util/mock.rs`, `s54_a_mined_payment_reads_as_landed_and_a_stranger_as_absent`,
    `s54_an_unobserved_landing_the_chain_mined_reads_as_landed`,
    `s54_an_unobserved_revert_reads_as_landed_unconfirmed_and_paid_nothing`,
    `s54_a_transaction_never_mined_reads_as_absent_or_held`,
    `s54_an_unaskable_read_is_one_shot_and_a_held_fault_waits_for_an_unmined_hash` and
    `s54_an_unobserved_later_sub_batch_carries_the_landed_ones`.
  - The G rows were green on their first run: they cannot compile at `ab7226f`, which has no seam,
    so their red baseline is plant P-a, which puts `ab7226f`'s rule back inside the seam.
  - **The run the report omits.** A `--nocapture` run between phase 1's two builds exited 124; its
    log is one line, *"Blocking waiting for file lock on build directory"*. It ran nothing.
- **The plants: 15, each red by message, none a compile check.**
  - In the tree, `ant_backend.rs` only, under the exclusive writer lock, each window restored by
    `cp` and `touch` and checked sha-equal (`6515f961…06bf` after phase 1's windows,
    `44426abd…3026` after phase 2's):
    - **W1 = P-a + P-g**, exit 101, *"7 passed; 8 failed"*. P-a (`ab7226f`'s rule: any
      unacknowledged broadcast is `Payment`, unresolved) reddened G1 (*"a broadcast whose reply
      was lost, and which the chain shows mined, must land"*, against `Err(Payment { … })`), G5
      (*"an `already known` error object is not a refusal: the chain shows the landing"*), G7
      (*"resolved by the local hash: a landing"*), G2 (*"the broadcast and one re-broadcast"*, 1
      against 2), G3 and G8 (*"D208 R5: money may have moved — expected StrandedPayment with no
      landing, got Err(Payment { … })"*) and the k ≥ 1 row (its capture count, 0 against 1). P-g
      (`S54` undone: no record built) reddened G6, *"S54: the sub-batch's record is built over the
      local hash before the capture"*.
    - **W2 = P-b, P-c, P-d, P-e, P-f and P-h**, exit 101, *"6 passed; 9 failed"*, each red
      attributed by its row and message, per the lane's report. P-b (an `ErrorResp` is a refusal,
      with no lookup) reddened G5 with the same message; P-c (no broadcast deadline), G6 and its
      twin, *"the submission step must end on its own deadlines; it was still running at the
      test's outer limit: Elapsed(())"*; P-d (the node's echo journaled), G7, now `left:
      Err(StrandedPayment { landed_tx_count: 0, reason: "sub-batch tx landing not observed: no
      receipt within 600 ms" })`; P-e (the unaskable arm is `Payment`), G3 and the k ≥ 1 row; P-f
      (no by-hash check), G8, and G2 with *"once, at the end"* (0 against 1); and P-h (the read
      calls a held transaction absent), the S54 read, *"pending: got Absent"*.
    - **Phase 2's window = P57 + P58a + P58b**, exit 101, *"10 passed; 3 failed"*. P57
      (`chain_id_guard`'s `{e}` unredacted, its bound kept) reddened
      `s57_the_chain_id_guard_names_no_url`, *"chain_id_guard: the reason names the RPC URL:
      payment RPC unreachable (eth_chainId): error sending request for url
      (http://127.0.0.1:39221/canary-s57-zqpw/)"*, while `s58_the_chain_id_guard_is_bounded`
      stayed green. P58a (the backfill read unbounded) reddened `s58_the_backfill_read_is_bounded`,
      *"fill_block_numbers: the read must end on its own deadline; it was still waiting at the
      test's outer limit"*. P58b (the proof-age block read unbounded) reddened
      `s58_the_proof_age_reads_are_bounded`, *"paying_block_time_within, the block read: …"*.
  - In a `git archive HEAD` shadow with a private target (baseline *"7 passed; … 116 filtered
    out"*, exit 0), each exit 101: M-a (the mock forgets a revert), `left: Absent` against `right:
    Landed { block_number: Some(1000001), confirmed: false }`; M-b (an unobserved landing the
    chain mined moves no money), *"the transaction was mined"* and *"the third was never
    submitted"*; M-c (the default body answers `Absent`), *"the default body must answer
    Unaskable, got Absent"*; M-d (the unobserved capture builds no records), four rows, *"the
    unobserved sub-batch's records are built over its hash (D208 R5)"* three times and *"the
    third sub-batch's blob has none"*. The shadow's files were restored sha-equal to the tree's.
  - Against §3's table, P51-a to P51-f are P-a to P-f, and each reddened at least the rows §3
    names. G4 has no plant, and §3 names none.
  - The plant-marker `git grep --untracked` exited 1 at each phase's close, with a positive
    control (per the lane's report); re-run here over `crates/antseal-net`: exit 1, and its
    positive control exit 0.
- **Left open.**
  - No unit test can run the three rewired method bodies, `connect`'s guard call or the payer's
    backfill delegation, because `AntCoreBackend` needs a live `Client`, so no plant covers those
    delegation lines; each site's free function is covered. The devnet suites `devnet_backend`
    and `e2e_kill_resume`, §3's wiring witness for `fill` and `send_raw_transaction`, run at the
    close gate (`ANTSEAL_GATE_HEAVY=1 ANTSEAL_GATE_E2E=1`); the lane ran neither.
  - evmlib's ~56 s retry of `balanceOf` and `allowance` is now cut at 30 s: a failing RPC ends
    those reads with *"… no answer within 30 s"*, where `ab7226f` returned evmlib's URL-bearing
    error after about 56 s, in the same class (`Network`). The `ant-backend` lib suite's wall time
    rose from about 9 s to about 62 s, because one row waits out that retry.
  - Found while writing this section, not in the lane's report:
    `crates/antseal-net/Cargo.toml:125-126` said that the library *"schedules no timers or tasks of
    its own"*, which `Deadline`'s helper thread falsified. The manifest was outside the lane's
    scope; the orchestrator rewrote the comment, line-neutral, to *"D208's deadlines run on a std
    helper thread, not a runtime timer"*.
  - The lane's instrument findings, for the ledger: P1's plan could not be built as written
    (`tokio::time::timeout` beside *"no manifest change"*; P1's probe was a binary with its own
    tokio); the grant's current-thread premise; alloy's `with_timeout` is no deadline when a
    lookup can hang; and `TxStatus::Submitted`'s doc against D33's residual risk 2, which D33's
    addendum answers.

### The resume (lane L-RESUME3)

Every verdict below was read from an exit file, except the lane's `rustfmt`, copy-style and
personal-data verdicts, which have none; this records lane re-ran `rustfmt --edition 2024 --check`
on the lane's fourteen files (each exit 0) and the plant-marker grep over `crates/antseal-cli`
(exit 1; positive control exit 0). Every red was judged by its message, and every exit file and
verdict line read back matches the lane's reports. L-RESUME3 measured against `ab7226f` and also
built D209's rows (`S53`, `S55`, `U120`); what follows is `S54`'s resume half (R9–R11) and R12.
Thirteen of its fourteen files equal its final sha256. `resume.rs` differs from the lane's final
copy only by the orchestrator's line-neutral rewrite of `resume()`'s doc (`:141-145`), which a
diff confirms.

- **Grants, from the orchestrator's dispatch log.** With R12 (12:51Z) came its three readers and
  a test at the end of each file. At 14:17Z came the bodies of four test helpers, for R12's
  fixture realism: nine existing lib tests (two in `pipeline/reveal.rs`, seven in
  `pipeline/receipt_backfill.rs`) went red under R12 because their helpers journaled transactions
  that mapped no quote, a receipt the pipeline never writes. Each helper transaction now pays one
  quote and each receipt maps it, as the adapter's Confirmed arm and the mock's `receipt_so_far`
  do. No hunk falls inside the nine tests, and the helpers alone, run against the pre-R12 readers,
  passed *"21 passed; 0 failed"* (exit 0).
- **§2 R9.** The step sits between the journaled receipt's read
  (`crates/antseal-cli/src/pipeline/resume.rs:185`) and the money branch, which now opens only
  `if !pruned && !payment_recorded(…) && !state.is_post_pay()` (`:209-211`): a pruned receipt
  always takes the remainder arm, which pays with `Some(partial)` as its `prior` (`:273-279`),
  never the pre-pay arm. `resolve_unobserved` (`:731`) asks `payment_tx_state` about each
  `Submitted` transaction that still pays a quote and reads every answer before it writes
  anything; it then applies them and journals the receipt once (`:798`):
  - `Landed { confirmed: true }`: `settle` (`:886`) writes `Confirmed` and the block, and the
    blob records stand.
  - `Landed { confirmed: false }`: `prune` (`:907`), then `settle` writes `Reverted` and the
    block. `Absent`: `prune`, and the record stays `Submitted`.
  - `Pending` or `Unaskable`: `StorageError::Network`, exit 23, before any write: *"the earlier
    payment transaction is not mined yet — the payment RPC still holds it, so it may still pay for
    its blobs; nothing was paid in this run — re-run once it is mined"*, and *"could not check
    whether the earlier payment transaction was mined ({reason}); nothing was paid in this run —
    re-run when the payment RPC is reachable"*.

  `prune` removes the transaction's quote mappings and the blob records they complete, and
  subtracts their cost rather than recomputing the total from the records left, because the
  total can also carry a replaced payment's cost (`S53`), which no record holds. The `TxRecord`
  stays, unmapped.
  - **Deviation: only a `Submitted` transaction that still maps a quote is asked** (through
    `paying_txs`): one pruned in an earlier run has nothing left to decide, and asking again
    would cost an RPC on every resume.
  - **Deviation: `Pending` or `Unaskable` refuses before any write, even when another
    transaction in the same pass landed**, so the vault never holds a half-resolved receipt; the
    next run asks again.
  - **Deviation: `Pending` has its own wording.** R9's suggested sentence serves `Unaskable`,
    with *"in this run"* added, as R9 required.
  - **Deviation: a revert resolved at the resume gets its block written**, as evidence only;
    R12 keeps it out of every published value.
  - **Deviation: that revert's gas is not added to the gas total**, because `PaymentTxState`
    carries no gas.
- **§2 R10.** Pinned as residue, not as a red:
  `residue_a_legacy_record_less_landing_is_still_bought_again`
  (`crates/antseal-cli/tests/seal_resume.rs:2920`) journals a pre-wave capture (mappings, no
  records) over a transaction the mock mined. The resume writes the chain's answer back
  (`Confirmed`) and still buys every blob again, per address `[2, 2, 2]`: *"D208 R10 residue: a
  legacy record-less landing is bought again (if this changed, the residue was fixed — update
  D208 R10 and this row together)"*.
- **§2 R11.** When this section was written, the user-facing texts of class 28 were byte-identical
  to `ab7226f`'s (`git diff --quiet ab7226f`, each): `crates/antseal-cli/src/error.rs` (the
  Display, `:779-785`, and the exit-code doc, `:64-66`), `docs/user/funding-your-wallet.md`
  (whose 28 lines are `:246-250` and `:271-279`) and
  `crates/antseal-cli/tests/snapshots/cli-errors.display.txt`. Abandon's rule 2 and the resume
  plan changed under D210 (L-MONEY2), not for `S54`: L-RESUME3 did not edit
  `crates/antseal-cli/src/seal_resume.rs`.
  - **Deviation, within §5's licence: `payment_recorded`'s doc, one of the six, was reworded**
    (`crates/antseal-cli/src/pipeline/journal.rs:1153-1159`). R9 made its promise false as it
    stood, so the doc now says that a resume asks the chain first and prunes, and only then that
    *"the mapped quotes left are exactly the ones it will not buy again (D37 Decision 5), and what
    exit 28 promises"*.
- **§2 R12.** `paying_txs` (`pipeline/journal.rs:1182`), beside `payment_recorded`, returns the
  transactions whose hash is a value in `tx_map`, in capture order; `resolve_unobserved` uses it
  too. Reveal's `bundle_receipt_record` (`pipeline/reveal.rs:1179`) takes key 0 from it and key 1
  as the minimum block over it alone (`:1183-1197`). A receipt with nothing paying takes the
  existing refusal, `ReceiptUnavailable` (*"no payment receipt can be embedded: the recorded
  receipt contains no payment transaction"*; `CliError::Usage`, exit 2), as a zero-cost seal did
  at `ab7226f`. `status`'s `ReceiptRow` (`crates/antseal-cli/src/status.rs:395-402`) counts and
  lists only paying transactions, at an equal line count. `unfilled_block_numbers`
  (`pipeline/receipt_backfill.rs:241-245`) counts only paying transactions, so a kept never-mined
  record cannot leave a receipt unfilled for good. `list` reads no transaction field. No snapshot
  moved: `status-report.txt` is byte-identical, and `json-envelopes.txt` changed only at `:36`
  (D210's re-bless), not at status's `:30`.
  - **The ruled value change.** For a work whose receipt holds an unmapped `Reverted` or
    `Submitted` record, §7.10 key 0 and key 1 and `status --json`'s `transactions` and
    `block_numbers` now leave it out, `ab7226f`'s own later-sub-batch revert (`S50`'s in-band arm)
    included. A T1-shaped work (D209 `S55`) publishes one more transaction, the remainder the
    expired arm carries. No key moves; ruled acceptable before `U32`.
  - Census tests: `a_transaction_is_part_of_the_payment_iff_it_paid_a_quote` (`journal.rs:1567`);
    `the_receipt_record_names_only_the_transactions_that_paid_a_quote` (`reveal.rs:1561`): beside
    two confirmed transactions it holds a never-mined `Submitted` record, a reverted first
    sub-batch whose block (100) is the earliest, and a later revert; key 0 is the two confirmed
    hashes, key 1 is 300, and an empty `tx_map` takes `ReceiptUnavailable`;
    `status_counts_only_the_transactions_that_paid_a_quote` (`tests/status_command.rs:1592`); and
    `only_a_paying_transaction_can_leave_a_receipt_unfilled` (`receipt_backfill.rs:1106`).
- **R8's CLI delegation.** `impl StorageBackend for SealBackend`
  (`crates/antseal-cli/src/backend.rs:1855`) forwards `payment_tx_state` to its inner backend
  (`:1880-1885`).
  - **Deviation: the lane never compiled it.** `mod ant` builds only under `ant-backend`, which no
    lane built in the shared target (§3's venue), so the orchestrator's heavy checkpoint is its
    first compile.
- **Tests and counts.** `mod d208` (`tests/seal_resume.rs:2363`), seven rows:
  `a_landing_nobody_saw_is_confirmed_by_the_chain_and_never_bought_again` (no consent, no money
  in the resume, each blob paid once per address, the landed payment's cost);
  `a_payment_the_chain_never_saw_is_pruned_kept_as_evidence_and_bought_again` and
  `a_payment_that_reverted_is_pruned_kept_as_reverted_and_bought_again` (re-quoted and asked,
  each blob paid once per address, the record kept, `Reverted` with its block for the revert, and
  only what moved recorded as cost);
  `pruning_an_absent_second_sub_batch_keeps_the_first_and_its_cost`;
  `a_payment_still_held_by_the_rpc_refuses_the_run_and_pays_nothing` and
  `a_payment_the_chain_cannot_be_asked_about_refuses_the_run_and_pays_nothing` (exit 23, no
  consent, nothing paid, the receipt untouched); and R10's row. Without the step (a shadow) the
  suite exited 101, *"0 passed; 7 failed"*; with it, `seal_resume` passed *"35 passed; 0
  failed"* (16 at `ab7226f`, 7 `d210`, 5 `d209`, 7 `d208`). At the lane's close the shared tree
  passed (exit 0): lib 343, `list_command` 27, `reveal_consent` 8, `reveal_flow` 20,
  `reveal_output` 11, `reveal_vault_local` 4, `seal_matrix` 17, `seal_resume` 35,
  `show_command` 14, `status_command` 15. The spawning suites passed in a shadow (exit 0):
  `machine_mode` 16, `receipt_backfill` 5, `reveal_lazy_backend` 7, `seal_command` 56. Clippy
  (`-p antseal-cli --all-targets -- -D warnings`) exited 0 in the tree.
- **The plant → red-test map, which replaces §3's P54 list.** Seven plants for this record's
  half, in a shadow with a private target, each restored sha-equal and each red by message:
  - **PS54-1, the resolution skipped (§3's P54-1)**: exit 101, all seven `d208` rows red, and none
    by a per-address double purchase. Landed: *"the chain's answer was not written back: a landed
    transaction is Confirmed with its block"*. Absent and reverted: *"the pruned blobs must be
    re-quoted and asked for (0 consent call(s))"*. The second-sub-batch row: *"the remainder buys
    exactly the pruned blob and the one never sent"* (it bought only the manifest). Pending and
    unaskable completed instead of refusing (*"a held payment refuses the run: SealOutcome
    {…}"*). R10's row: *"the chain's answer is still written back"*.
  - **PS54-2, the resolution after the money branch (P54-2)**: absent, reverted and the
    second-sub-batch row red with *"the resume finishes the seal: Storage(Finalize { reason: "no
    payment record for unstored blob at address …" })"*: the remainder bought nothing, then the
    prune left those blobs without a record, which on the network is a finalize that retries at
    exit 23 for good. The other four stayed green; pending and unaskable still refuse, later,
    having paid nothing.
  - **PS54-3, the record dropped (P54-3), and PS54-4, the pruned receipt sent through the pre-pay
    arm (P54-4)**: each reddened absent and reverted, with *"the never-mined transaction's record
    is kept as evidence"* and *"the reverted transaction's record is kept as evidence"*.
  - **PR12-1 to PR12-3, each reader unfiltered**: reveal, *"an unmapped evidence record was
    presented as a payment transaction"*; status, *"an unmapped evidence record was counted as a
    payment transaction"* (`left: (5, [100, 300, 400, 500])` against `right: (2, [300, 500])`);
    the backfill, *"a never-mined evidence record made the receipt read unfilled"* (1 against 0).
  - **Deviation: skipping the resolution never shows a per-address double purchase.** §3 expected
    one from P54-1; R5's records cover a landed sub-batch whether or not R9 runs, so that red
    belongs to R10's legacy shape alone, as §3's own reading predicted.
  - **Deviation: §3's red baseline became two things.** P1 §7.1's double, planned as the
    baseline, is R10's residue row, where that double still happens; the baseline is the `d208`
    suite run without the step.
- **Left open.**
  - `U123`, minted from the lane's proposed row, owns the proof-clock sentence that `list`, the
    resume plan and abandon's rule 2 print: it overstates for a receipt whose only paying
    transactions are unresolved `Submitted` ones, whose proofs are usable only if the chain later
    shows a landing (a legacy record-less capture has none). Those three render without asking
    the chain, so `S54` changes what the next resume does, not what they say.
  - R10's residue stands, pinned by its row.
  - `fill_block_numbers` still reads every empty slot, a kept never-mined record included,
    whenever a backfill pass runs; R12 decides only whether one runs.
  - The living citations the lane's edits moved (among them `pipeline/error.rs:203`,
    `tests/list_command.rs:2314`, `docs/user/funding-your-wallet.md:291` and
    `docs/user/timestamp-authorities.md:421`) are the citation lane's; per the lane's report, no
    living document's prose is falsified.
  - The lane's instrument finding, for the ledger: two more fixtures of D203 M9's class, the
    reveal and backfill test helpers that journaled transactions mapping no quote (nine tests on
    a receipt the pipeline never writes).

## Closing — this record is not consent

It changes how the payment adapter submits a sub-batch transaction and what it concludes when the
broadcast or the await fails, adds one default-bodied read to `StorageBackend`, adds a resolution
step to the resume, and narrows what three readers publish as the payment's transactions, inside
the wave's own commits. It also bounds the adapter's other payment-RPC reads with the same
deadline and keeps the RPC's URL out of every payment-RPC error it reports (R13, R14). Nothing in
it authorises a push, a workflow dispatch, a deploy or any other outward act; each of those needs
the maintainer's express consent naming the action, the destination and the account.
