# D179 — A payment refusal is **one peer's decline**, and the PUT moves on; a seal is **expired** only when **a declining majority** meets **a payment more than a day old by its block time**; and no sentence a user reads claims a node-side window

- **Status: RESOLVED. The row's defect holds at HEAD by reading; the fix the row suggested
  is necessary but not sufficient; its time source is replaced by one the journal already
  carries; and the venue it implied cannot see the defect.**
  - **Resume pays again — holds, by reading.** Any payment-class rejection, once the
    blob's oldest quote timestamp is past 24 h, is classified `ProofsExpired` and ends the
    PUT loop at once; a fresh seal exits 29; resume re-quotes, re-consents with *"a SECOND,
    ADDITIONAL payment"* and pays — once per invocation, and `--yes` pre-consents. The
    timestamp is the quoting peer's own field. §1.1.
  - **"Try the remaining targets" is upstream's own policy** — a payment-class reply means
    *"skip this peer, do not re-quote"* — **and it is not sufficient**: the verdict must
    also require that the declines **alone** make the majority unreachable, or a hostile
    minority still reaches the expensive branch once the payment is old. The loop already
    continues past a *fresh* decline; it aborts only once a decline is classed as expired.
    §1.1, §1.2.
  - **No new journal field is needed**: no receipt type holds a client time, but every
    `TxRecord` holds its paying transaction's `block_number` — so the **block timestamp**
    is a chain-anchored time that no peer supplies, available with no format change, and it
    covers in-flight journals written by older builds, which a new field would not. §1.3.
  - **MockBackend cannot see the defect**: it lives entirely inside the adapter that
    MockBackend replaces. A pure decision function over per-target replies, plus an adapter
    seam fed real `AntError` values, reaches it with no hostile devnet node. §1.4.
  - **The re-pay path must survive**: an honest node never rejects on quote age and never
    answers a proof-carrying PUT with `PaymentRequired`, but it **can** decline a proof
    whose paid issuer has left its K-closest view — churn, which correlates with time.
    §1.2.
  - **The copy claims a window that does not exist**: exit 29's message, the consent
    warning, resume's module documentation and the user's wallet page say a node-side
    window, or the network, refuses old proofs; D37's 2026-08-02 correction found no such
    gate. §1.5.
- **Date: 2026-10-16**
- Owner rows: **`S43`** (this record's subject).
- Related: **D37** Decision 6 and its 2026-08-02 correction (the window is antseal's own
  client-side policy); **D147** (exit 29, `payment-proofs-expired`; it takes a dated
  addendum for the sentence); **D36** (resume re-quotes and re-consents per invocation);
  **D33** (the block number's locus); **D176** (§2.11's known-defect paragraph, which this
  record's behaviour replaces); **`S24`** (the same PUT loop's keep-or-harden verdict, not
  decided here); **D178** (the other change to the same adapter file this wave).

## 0. What was measured against

`HEAD` `fbcee1e`. Planning lane P2 read the adapter's PUT loop and classifier, the receipt
and journal types, the resume and consent paths, pinned `ant-core` 0.5.0's chunk PUT policy
and error enum, `ant-protocol` 2.3.0's close-group constants, and `ant-node` 0.15.0's PUT
handler and payment verifier — and the same handler arms at 0.22.0. **No cargo run, no
devnet and no hostile node.** This record's lane re-read every citation in §1 at `fbcee1e`
and in the pinned crates before writing, and found the further sentences §1.5 lists.

## 1. What was measured

### 1.1 The chain at HEAD

- The PUT loop (`crates/antseal-net/src/ant_backend.rs:503-557`) stops at
  `CLOSE_GROUP_MAJORITY` stores; `:545-549` returns `ProofsExpired` the moment one reply is
  classified expired — *"every remaining PUT would be rejected the same way"*.
- `classify_put_error` (`:1827-1852`): a reply is payment-class when it is
  `RemotePut { PaymentFailed }` or `AntError::Payment`; it is `ProofsExpired` when the
  blob's **oldest quote timestamp** is more than 24 h old (`:1857-1859`, strict `>`; window
  `:178`), and otherwise a `Finalize` error whose detail is redacted. The oldest timestamp
  is the minimum of `pq.quote.timestamp_unix_secs` over the blob's quotes (`:943-948`) — the
  quoting peer's own signed field.
- A fresh seal: `pipeline/seal.rs:401`'s `?` → `pipeline/error.rs:350` → exit 29
  (`crates/antseal-cli/src/error.rs:421`). Resume: `pipeline/resume.rs:274-289` re-quotes,
  re-consents with *"Consenting here authorizes a SECOND, ADDITIONAL payment"*
  (`seal_consent.rs:173-180`), pays and finalizes — once per invocation; `--yes`
  pre-consents.
- On resume the targets are re-resolved by an unpaid quote round
  (`ant_backend.rs:950-977`) over the first `CLOSE_GROUP_SIZE` closest peers
  (`crates/antseal-net/src/quote.rs:708-713`), median voters first (`:881-905`).
  `CLOSE_GROUP_SIZE = 7` and `CLOSE_GROUP_MAJORITY = 4`
  (`ant-protocol-2.3.0/src/chunk.rs:35,40`).

### 1.2 What a decline means upstream, and when an honest node sends one

- `ant-core-0.5.0/src/data/client/chunk.rs:36-79`: `PaymentFailed` — including *"the
  proof's issuers are not close enough in this peer's view"* — and `PaymentRequired` both
  classify as `PriceFloor`: *"skip this peer, do not re-quote"*. `:580-581` turns
  `PaymentRequired { message }` into `Error::Payment("Payment required: …")`.
- `ant-node-0.15.0/src/storage/handler.rs:391-403`: `Ok(status) if status.can_store()`
  stores, `Ok(_)` answers `PaymentRequired`, `Err` answers `PaymentFailed`.
  `src/payment/verifier.rs:315-319`: `can_store` is `CachedAsVerified | PaymentVerified`,
  and `verify_payment_inner` (`:801-893`) returns only those two or `Err` — a missing proof
  is an `Err` (`:883-887`). So an honest node **never** answers a proof-carrying PUT with
  `PaymentRequired`: that arm is unreachable. 0.22.0 has the same handler arm and the same
  no-proof `Err`.
- No quote-age check exists: `QUOTE_MAX_AGE` and `validate_quote_timestamps` have zero hits
  in `ant-node` 0.15.0, `ant-protocol` 2.3.0 and `evmlib` 0.9.0, and
  `test_old_quote_uses_storage_delta_not_timestamp` (a quote 25 h old) asserts that the
  error does not say *"expired"*, in 0.15.0 and in 0.22.0. `ant-core` 0.5.0 reads a quote
  timestamp only in cache pruning, on the `batch_upload_*` path antseal does not drive.
- An honest node **can** decline: `validate_paid_quote_issuer_k_closest` rejects a proof
  whose paid issuer *"is not among this node's local K=… closest peers"*
  (`verifier.rs:1260` onwards) — churn, which correlates with time. A node that is not
  responsible answers `StorageFailed`, which is not payment-class (`handler.rs:370-377`).

### 1.3 The time the journal already holds

- `QuotePreimage`, `PeerQuote`, `BlobPaymentRecord`, `TxRecord` and `PaymentReceipt` hold
  no client time.
- Every `TxRecord` holds its paying transaction's `block_number`
  (`crates/antseal-net/src/receipt.rs:118-126`): `None` in the journal-first record
  (`ant_backend.rs:797`), the receipt's at landing (`:831`), backfilled later
  (`:1319-1343`). A blob's quote hash reaches its paying transaction through `tx_map`
  (`:731`).
- The journal is `serde_json` in a v1 envelope
  (`crates/antseal-cli/src/pipeline/receipt_sink.rs:79-99`;
  `RECEIPT_JOURNAL_VERSION: u16 = 1`, `crates/antseal-net/src/receipt.rs:206`), outside the
  registry-v1 freeze: a new field would be compatible, but none is needed.

### 1.4 Where the defect lives

`StorageError::ProofsExpired` is produced only inside the adapter
(`ant_backend.rs:503-557`, `:1827-1852`), which `MockBackend` replaces; the pipeline's
reaction to it is already tested (`crates/antseal-cli/tests/seal_resume.rs:167`, `:210`,
`:417`, `:448`). `ant-core-0.5.0/src/data/error.rs:10-42` is a public enum, not
`non_exhaustive`, with `Payment(String)` and `RemotePut { address, source }` — so real
replies can be constructed in a test.

### 1.5 The copy

The sentences that claim a node-side window, or a network that *"will no longer accept"*
the proofs:

- exit 29's message, `crates/antseal-cli/src/error.rs:709-714` — *"(the ~24 h node-side
  window has passed), so the storers reject them"* — frozen in
  `crates/antseal-cli/tests/snapshots/cli-errors.display.txt:92` and quoted in
  `docs/user/funding-your-wallet.md:255`;
- the consent warning, `crates/antseal-cli/src/seal_consent.rs:173-180` — *"the network will
  no longer accept them"*;
- resume's module documentation, `crates/antseal-cli/src/pipeline/resume.rs:37-45`.

**Found by this record's lane, beyond the ruling's list**: the wallet page's own bullet,
`docs/user/funding-your-wallet.md:272-275` (*"The payment proofs have a node-side window of
roughly 24 hours"*); the library's `StorageError::ProofsExpired` message,
`crates/antseal-net/src/error.rs:118-122` (*"the node-side proof-validity window (~24 h)
has passed"*); the classifier's doc comment (`ant_backend.rs:1822-1826`, *"outlived the
node-side validity window"*) and a test comment (`seal_resume.rs:650`); and the receipt
module's prose (`receipt.rs:44-50`), which states the old rule — one payment-class
rejection past the window.

D37's 2026-08-02 correction found `QUOTE_MAX_AGE_SECS` at **0 occurrences** in
`ant-node-0.15.0` and *"no timestamp gate at any step"* of the single-node verification
path.

## 2. RULING

### §2 R1 — A payment-class reply is one target's decline

A `PaymentFailed` or `PaymentRequired` reply declines **that target** only. The loop
continues to the next target, and stops at `CLOSE_GROUP_MAJORITY` stores or when the
targets run out — upstream's own policy (`ant-core-0.5.0/src/data/client/chunk.rs:36-79`).

### §2 R2 — Expired needs a declining majority and an old payment

`ProofsExpired` requires **both**:

- **the declines alone make the majority unreachable**: successes plus non-payment
  failures < `CLOSE_GROUP_MAJORITY` — with seven targets, at least four declines;
- **the payment is more than 24 hours old** (§2 R3; strict `>`, as today).

Otherwise the result is a typed `Finalize` error — **exit 23**; resume finalizes again and
pays nothing.

### §2 R3 — The age is the paying transaction's block time

The age is *now* minus the **block timestamp** of the blob's paying transaction — reached
through `tx_map` to the `TxRecord`'s `block_number`, or the receipt's when the
journal-first record is unfilled — and it is read only on this rare path, once the declines
alone have made the majority unreachable. A quote's `timestamp_unix_secs` is never used.
**An unreadable time means not expired.** No journal format change.

### §2 R4 — The verdict is a pure function

The verdict lives in `antseal-net`'s default graph, in a new `put_policy.rs`, over the
per-target replies and `paid_at`. The adapter only maps each `AntError` to a reply and
supplies `paid_at`.

### §2 R5 — The copy says what happens

The user-facing copy that claims a node-side window is corrected — exit 29's message
(`crates/antseal-cli/src/error.rs:709-714`), the consent warning
(`seal_consent.rs:173-180`), resume's module documentation (`pipeline/resume.rs:37-45`),
the wallet page (`docs/user/funding-your-wallet.md:255`) and the display snapshot
(`tests/snapshots/cli-errors.display.txt:92`, re-blessed through the real producer) — to
the substance:

> a majority of the storing peers refused this seal's payment proof, and the payment is
> more than 24 hours old by its block time

The class, `payment-proofs-expired`, and code 29 do not move. **D147** takes a dated
addendum for the exit-29 sentence its §2 R3 moved unchanged.

### §2 R6 — §2.11 states the ruled behaviour and the residual

Threat-model §2.11's known-defect paragraph is replaced by the ruled behaviour and the
threat that remains: **a hostile close-group majority** can still decline every PUT and,
once the payment is a day old by the chain's clock, put the user in front of one
re-payment consent per invocation (`--yes` pre-consents); **a minority can do neither**.

## 3. Fault plants

Owed by the implementing lane, baseline green first, judged by message, `touch` after
every restore; every plant compiles.

| # | case | plant | expected red | green |
|---|---|---|---|---|
| B1 | one `PaymentRequired` and six stores; quote timestamps −72 h, block −1 h | restore `return Err(ProofsExpired)` (`ant_backend.rs:547`) | *"one hostile decline aborted the PUT as ProofsExpired after 1 of 7 targets (S43)"* — **HEAD is red** at the adapter seam | `Ok`, exactly 5 PUTs |
| B2 | seven declines; block −1 h; quote timestamps −72 h | the age taken from the oldest quote timestamp | *"hostile majority expired at 1 h chain age (S43 R3)"* | `Finalize` |
| B3 | two declines and five dial failures; block −25 h | the threshold cut to `declines >= 1` | *"declines not decisive, yet re-pay"* | `Finalize` |
| B4 | four declines and three stores; block −25 h | — (the positive row) | — | `ProofsExpired` |
| B5 | `paid_at = None` | `None` read as expired | *"unreadable block time re-pays"* | `Finalize` |
| B6 | the boundary at exactly 24 h | `>=` | *"exactly 24 h counted expired"* | 24 h no; 24 h + 1 s yes |
| B7 | pipeline: one `Finalize`, then resume | `Finalize` added to the re-pay arm (`pipeline/resume.rs:278`) | *"resume paid again (2 pay calls) after a retryable finalize"* | `paid_here == false`, one pay |

B1–B6 run in the default build over the pure policy. B1 runs again in the feature build
through the adapter seam over real `AntError` values — that run is `S43`'s `Accept` row 1
witness, red at HEAD. `Accept` row 2 follows from B1 and B2 with B7, beside the existing
`seal_resume.rs:167` and `:210`; row 3 is §2 R6.

## 4. What this record does NOT decide

- **Whether one hostile quote that passes the client's pre-pay checks can still fail every
  honest storer.** If it can, §2 R1 does not help and only §2 R3 rate-limits the
  re-payment — **not established**.
- That `ant-node` 0.22.0's `verify_payment_inner` never returns `Ok(PaymentRequired)` — only
  its handler arm and its no-proof arm were read.
- The Sybil cost of being among a blob's first four targets.
- A devnet run against a hostile node — it needs a modified `ant-node`.
- Reading a block's time through the type-erased provider (`get_block_by_number`) — not
  compiled in planning.
- *Now* stays the local clock, as it is today; only the payment's side of the age moves to
  the chain.
- The keep-or-harden verdict on the sequential majority loop (`S24`).

## 5. Edit list — per write scope, with the lane named before this record was written

### L-NET (the network lane; `S42` before `S43`, one owner)
- **New** `crates/antseal-net/src/put_policy.rs` and its `lib.rs` line: the verdict, with
  B1–B6 in the default build (§2 R2–R4).
- `crates/antseal-net/src/ant_backend.rs`: the loop continues past declines (§2 R1); the
  adapter maps `AntError` to a reply and supplies `paid_at` from the block time, read on
  the rare path only (§2 R3, R4); the feature-build seam for B1 (`S43`'s `Accept` row 1).
- `crates/antseal-cli/src/error.rs:709-714`, `src/seal_consent.rs:173-180` (its in-file
  test asserts *"stranded"* and *"SECOND, ADDITIONAL payment"*, which the new wording
  keeps), `src/pipeline/resume.rs:37-45`, and `tests/snapshots/cli-errors.display.txt:92`
  (§2 R5).
- `crates/antseal-cli/tests/seal_resume.rs`: B7.
- `docs/user/funding-your-wallet.md:255` (§2 R5).
- **The further sentences §1.5 found** (same rule; found after the ruling): the wallet
  page's bullet at `:272-275`, whose paragraph's `error.rs` line citations are also stale
  at `HEAD`; the library's message at `crates/antseal-net/src/error.rs:118-122`; the
  classifier's doc comment (`ant_backend.rs:1822-1826`); the test comment
  (`seal_resume.rs:650`); and the receipt module's prose (`receipt.rs:44-50`).

### DOCS (the documentation lane)
- `docs/threat-model.md` §2.11: the known-defect paragraph replaced per §2 R6.

### Orchestrator (registrar) — `TODO.md`, `tasks/S.md`, `docs/decisions/README.md`, dated addenda
- `S43` Notes from planning lane P2; the `Accept` captures as they land.
- A dated addendum on **D147**: the exit-29 sentence its §2 R3 moved unchanged now says what
  §2 R5 rules.
- Index row and register row for this record.
- An `docs/instrument-ledger.md` entry for §1.4's finding: the adapter that produced the
  defect was replaced by `MockBackend` in every pipeline test, so no test could reach the
  one-decline abort.

## 6. As built — wave 37, lane L-NET (recorded in place before this record was first committed)

The lane built §2 R1–R6 as ruled. These are the points where the code says more than the
ruling did:

- **§2 R2's predicate has two conjuncts.** It reads `declined ≥ CLOSE_GROUP_MAJORITY` **and**
  `stored + failed < CLOSE_GROUP_MAJORITY` (`PutTally::declines_are_decisive`,
  `crates/antseal-net/src/put_policy.rs`). With upstream's seven targets the two are
  equivalent, and the eight-way split is pinned in
  `s43_declines_are_decisive_exactly_from_a_majority_of_seven`. The first conjunct keeps
  §2 R6's "a minority can do neither" true for a target list shorter than seven. At the
  pin that cannot happen: upstream refuses before payment with fewer than
  `CLOSE_GROUP_SIZE` PUT peers (`quote.rs:715-721`). It also stays safe for a longer list
  (`batch.rs:146-149`).
- **Every shortfall that is not expired is a typed `Finalize`.** That includes a round
  whose every target failed to dial, which `HEAD` returned as `StorageError::Network`.
  Both map to exit 23 (`pipeline/error.rs:360-366`), so no exit code moved. The reason
  carries the tally and the last non-payment failure, never a decline's own text; rows B2
  and B3 assert this hygiene.
- **§2 R3 — more than one paying transaction, and "now".** A blob paid by more than one
  transaction (not expected: one non-zero line per blob) takes its time from the
  **latest** paying block, and any unreadable one makes the time unreadable — the
  conservative direction. *Now* is this machine's clock, not the chain head. A clock more
  than a day fast makes a refused proof look expired early, at the cost of one re-payment
  the user must consent to.
- **The block time is read by `paying_block_time`.** It calls `eth_getTransactionReceipt`
  when the journal holds no block number, then `eth_getBlockByNumber`, on the payer's own
  provider. This is proven against a loopback JSON-RPC stub serving an Arbitrum-shaped
  block and receipt (`s43_block_time`, 3 rows), **not** against live Arbitrum One,
  Sepolia or Anvil. The devnet E2E never reaches the path, because honest nodes do not
  decline.
- **`S43`'s `Accept` row 1 was seen red before the fix.** `HEAD`'s loop was moved
  unchanged behind the seam `put_to_majority`, and the row failed by its message:
  *"one hostile decline (PaymentRequired) aborted the PUT as ProofsExpired after 1 of 7
  targets (S43)"*. After the fix it passes with exactly five PUTs and no chain read.
  `HEAD`'s classifier is gone: `classify_put_error`, `quote_age_exceeds_window` and their
  unit row `proof_expiry_classifier_uses_the_24h_window` were removed, and B6 replaces the
  row. The window constant moved to `put_policy`.
- **§2 R5's copy reached more sites than listed:**
  - exit table row 29 (`crates/antseal-cli/src/error.rs:39`);
  - the library variant's doc and message (`crates/antseal-net/src/error.rs:98-122`);
  - two trait-doc sentences (`crates/antseal-net/src/backend.rs`);
  - the receipt module's prose;
  - the wallet page's stale `error.rs` line citations (`:258`).

  Snapshot line 92 is the only snapshot line that moved. Under D65, `message` is human
  copy. The library's message is pinned by no test or snapshot.
- **Fault plants B1–B3 and B5–B7 were each seen red by their own message**, restored
  byte-exact and touched. The lane's report keeps the table.

## Closing — this record is not consent

It changes code, tests and documents in the tree, and authorises no network act: every new
case runs over constructed replies, and the pipeline row over the in-process mock. Nothing
here authorises a push, a dispatch, a payment or a settings write.
