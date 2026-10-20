# D204 — One pure `settle_sub_batch` decides what the payment loop does **after each awaited sub-batch receipt**: a landed sub-batch whose proofs fail is **captured, then stranded**; a first sub-batch that reverts moved no ANT, so it is **`Payment` and journals nothing**; and `Payment` now means **"before any ANT moved"**

- **Status: RESOLVED. H3 fell (c), on its mechanism. H4 fell (b): its direction survived and
  its premise fell.**
  - **H3 (`S49`)** — *"the Do as written: emit the capture first, then return StrandedPayment
    with the confirmed count (stranded_or_payment's rule); the in-crate test needs a seam to
    inject a finalize failure, which is buildable without touching upstream (a cfg(test) fault
    hook in the adapter)."* (c):
    - **The mechanism cannot reach the code it would test.** A `cfg(test)` fault hook compiles,
      but no in-crate test reaches `pay()`'s tail. An `AntCoreBackend` needs a `Client`, and a
      `Client` needs a saorsa-core node or bootstrap peers (§1.3). No test in the adapter's
      `mod tests` constructs one. A devnet cannot inject the fault either: integration tests
      cannot see `cfg(test)` items.
    - **The buildable seam is a refactor.** The decision taken after each awaited receipt
      becomes one pure function that takes the finalize result as data (§2 R1). `S49`, `S50`
      and `S46`'s stop live in it, and in-crate unit tests drive it directly.
    - **The direction survives, narrowed to the failure path.** "Capture first" on every
      landing would regress the success path. A capture taken before `finalize_ready_blobs`
      journals sub-batch k's quote→tx map with no records for k's blobs, so a crash before the
      next capture makes a resume re-buy all of k (§1.2). The ruling captures first only when a
      post-landing finalize fails (§2 R2).
  - **H4 (`S50`)** — *"a zero-count revert is StorageError::Payment (no ANT moved; resume pays
    everything), its Display amended to cover "a transaction reverted" (Payment's "before any
    transaction landed" is false for a mined-and-reverted tx); no new exit code."* (b):
    - **What survives: the class, the codes and amended words.** A first-sub-batch revert is
      `Payment` (exit 23). No exit code is minted or moved (§2 R3, R4).
    - **The premise falls: the class and its text are not the defect that does harm.** The
      revert branch captures before it chooses a class, and the vault sink writes every
      capture. So a first-sub-batch revert journals a receipt that maps no quote, and every
      money reader in the CLI takes that receipt as proof of payment. Executed by the planning
      lane (§1.5): `abandon` refuses with *"already been paid for"*, and a declined resume tags
      the work `Paid` though no ANT moved. A class change alone fixes the exit text and none of
      these. The ruling suppresses the capture (§2 R3).
    - **The amendment is restated.** *"Cover a reverted transaction"* becomes *"before any ANT
      moved"*, which is true of every `Payment` producer, the token approval included (§2 R4).
- **Date: 2026-10-20**
- Owner rows: **`S49`** (§2 R1, R2, R5) and **`S50`** (§2 R1, R3, R4, R5). This record names
  one new row, **`S51`**, which this wave's rulings minted (§4).
- Related:
  - **D37** Decision 2 (each landed sub-batch is journaled before the next is submitted,
    D37:102-109) and Decision 5's granularity caveat (D37:417-428). D37 takes no addendum
    (§2 R6);
  - **D147** (the money-moved class 28; R6's `Payment` row, D147:536; R11, D147:672-673, which
    froze `StorageError`'s own Display strings), which takes a dated addendum;
  - **D198** (`S46`: the capture verdict and the stop, whose code moves into the seam
    unchanged; its §6 minted `S49` and `S50`), which takes a dated addendum;
  - **D186** (class 37, and the pipeline's 28/37 split at
    `crates/antseal-cli/src/pipeline/resume.rs:500-517`, unchanged);
  - **D134** §2 R3 (1) (the exit-code table is append-only; refused option (iii) would have
    taken 38);
  - **D33** (the journal-first rule that `S51`'s fix shapes would extend to the broadcast);
  - **`S16`** (a journaled receipt, not the state tag, says money moved,
    `crates/antseal-cli/src/pipeline/resume.rs:170-180`) and **`S20`** (the bump review that
    `S49` guards).

## 0. What was measured against

`HEAD` `6e1cab3` (local `main`, one records-only commit ahead of `origin/main` `ab640ae`). The
tree was clean when planning began, on 2026-10-20.

Planning lane P1 (wave 40, 2026-10-20) measured `S49` and `S50`. It re-derived `S49`'s
reachability from the pinned upstream source (ant-core 0.5.0, ant-protocol 2.3.0, evmlib 0.9.0
and alloy-provider 1.8.3, the versions `Cargo.lock` pins). It EXECUTED `S50`'s CLI consequence
in a shadow copy with a private target: its probe journals exactly the receipt the revert branch
captures, then drives `list`, `abandon` and the exact re-run over it (window F: 1 passed, exit
file 0). The adapter's revert branch itself is code-traced: no in-crate test can reach it
(§1.3), and the devnet as built cannot produce a mined revert of the first sub-batch (§1.6).

Before this record was written, the records lane re-read the load-bearing lines through
`git show 6e1cab3:<path>`, because round-1 lanes were already editing the tree, `ant_backend.rs`
among them. Every figure below held, with four refinements:
- the reverted transaction's record is pushed at `crates/antseal-net/src/ant_backend.rs:760-769`
  (P1: `:759-769`), and the submission call is `:709-717` (P1: `:706-716`);
- the code's statement of D37 Decision 5's granularity caveat is
  `crates/antseal-cli/src/pipeline/resume.rs:619-634` (P1: `:617-626`, which starts two lines
  above the caveat's heading);
- **`finalize_ready_blobs` stops at the first blob whose proof fails** (the `?` at `:1581-1588`).
  Every ready blob of the same sub-batch that it had not yet reached has no record either. The
  rulings' stated limit names only the failing blob; §2 R2 states the limit as measured;
- no user document quotes `Payment`'s Display. `git grep -n 'before any transaction landed'
  6e1cab3` finds eight lines: `crates/antseal-net/src/error.rs:37` and `:41`,
  `crates/antseal-cli/src/pipeline/error.rs:485`, D147:58, :511 and :536, `TODO.md:1099` and
  `tasks/S.md:715`. None is under `docs/user/` (control: `payment stranded mid-sequence` → 1 line
  in `docs/user/funding-your-wallet.md`).

## 1. What was measured

### 1.1 The loop has three outcomes after an awaited receipt

`AntCoreBackend::pay` runs one iteration per sub-batch (`ant_backend.rs:676`): it builds the
calldata (`:693`), calls `send_transaction` (`:709`) and awaits the receipt (`:719`). The file
compiles only under `ant-backend` (`crates/antseal-net/src/lib.rs:85-86`). Then:
- **The landing is not observed** (`:719-753`). The hash is journaled as `Submitted` and its
  quotes are mapped (`:733`), the capture is delivered (`:735-741`), and `StrandedPayment` is
  returned with the confirmed count (`:742`). Money MAY have moved. This record does not move or
  change this branch.
- **The transaction reverted** (`:771-790`). The record is pushed with `TxStatus::Reverted`
  (`:760-769`) and its quotes are not mapped. `emit_capture` runs (`:776-782`), **then**
  `StrandedPayment { landed_tx_count: <the confirmed count> }` is returned (`:783-789`), with the
  reason *"a payment sub-batch transaction reverted on-chain"*. The count is 0 when the first
  sub-batch reverts.
- **The transaction confirmed** (`:792-832`). Sub-batch k's quotes are mapped (`:792-794`),
  `finalize_ready_blobs(…)?` runs (`:799-806`), then `emit_capture` (`:807-813`), then `S46`'s
  stop (`:819`, D198 §2 R2).

The helper that splits the two classes exists: `stranded_or_payment` (`:1663-1672`) returns
`Payment` at a count of 0 and `StrandedPayment` otherwise, with an in-crate test
(`stranded_split_matches_the_taxonomy`, `:2030-2042`). The revert branch does not call it.

### 1.2 `S49`: a proof failure after a landing is classed "no money moved", and the capture is skipped

- `finalize_ready_blobs` (`:1554-1617`) maps both of its failures to `Payment`:
  `finalize_batch_payment(…).map_err(|e| StorageError::Payment { reason: format!("proof
  construction failed: {}", …) })?` (`:1581-1588`), and the `paid.pop()` invariant breach
  (`:1589-1594`).
- **It has a second caller the row does not name.** The zero-transfer pre-pass (`:667-674`,
  `landed_index = usize::MAX`) runs before any sub-batch. There `Payment` is right.
- After a landing, the `?` returns before `emit_capture`. The vault never receives sub-batch k's
  map, `receipts_unrecorded()` stays `None`, and the CLI renders exit 23, *"network failure:
  payment failed before any transaction landed: …"* (`crates/antseal-cli/src/pipeline/error.rs:485-488`),
  which is false: sub-batch k landed. A re-run then re-buys k's blobs, because no receipt
  covers them (every blob, when k is the first sub-batch).
- **Why "capture first" on every landing is wrong.** `emit_capture` builds the receipt's `blobs`
  from `records` (`:1644`) and derives `storage_cost_atto` from them (`:1645-1650`), and only
  `finalize_ready_blobs` fills `records` (`:1609-1615`). A capture taken before finalize would
  journal k's quote→tx map with no records for k's blobs. A crash before capture k+1 would then
  make the resume's records-keyed `uncovered_blobs` (`resume.rs:642`) re-buy all of sub-batch k
  under fresh quotes, on the success path.
- **Why mapping the error through `stranded_or_payment` alone is wrong.** With no capture, the
  vault never sees tx k and the sink records no fault, so the pipeline's split
  (`resume.rs:500-517`) says 28, *"the journaled partial receipt is authoritative … re-pays no
  quote the receipt already maps"*, over a receipt that does not map k's quotes. That is D186's
  37 situation, mislabelled 28.

### 1.3 `S49` is unreachable at the pin, and no in-crate test reaches `pay()`'s tail

- **Upstream has exactly two error sites.** ant-core 0.5.0's `finalize_batch_payment`
  (`src/data/client/batch.rs:337-342`) is `build_paid_chunks` (`:291-331`): a non-zero quote
  missing from the map (`:300-305`, *"Missing tx hash for quote … — external signer did not return
  a receipt for this payment"*), and `serialize_single_node_proof` (`:320-321`), which is
  `rmp_serde::to_vec` of a `#[derive(Serialize)]` struct into a `Vec` (ant-protocol 2.3.0,
  `src/payment/proof.rs:16-17`, `:63-71`). It pushes one `PaidChunk` per input (`:323-328`).
- **The gap cannot occur.** `ready_after[slot]` is the last sub-batch holding one of the blob's
  transfers (`ant_backend.rs:652`). Every earlier sub-batch's hashes were inserted at its own
  landing, because a revert or an unobserved landing returns first, and this one's at
  `:792-794`, just before the call. `payment_lines_match` (`:1535-1546`) demands
  `lines.len() == staged.len()` and exact amounts. The serializer cannot fail into memory short of
  allocation failure, and the `pop()` breach cannot occur. The row's premise holds: `S49` guards
  a future ant-core bump.
- **No in-crate test can construct the backend.** `Client::from_node` takes an `Arc<P2PNode>`
  (ant-core 0.5.0, `src/data/client/mod.rs:373`) and `Client::connect` needs bootstrap peers
  (`:410`). `command grep -n -E 'AntCoreBackend\b|Client::'` over `mod tests`
  (`ant_backend.rs:2008-3002`) finds only three static `AntCoreBackend::check_blob_len` calls
  (`:2018-2020`) and one message string (`:2264`); the whole file has 14 `AntCoreBackend` hits
  (control). The S43 loopback JSON-RPC stub (`enum Serve` at `:2684`, `fn provider` at
  `:2727-2731`) shows a provider can be stubbed, but the `Client` still blocks construction.

### 1.4 `S50`: the revert branch captures before it chooses a class, and the CLI reads any receipt as payment

- **The capture fires before the class is chosen** (`ant_backend.rs:776-782`, then `:783`).
  `VaultReceiptSink::capture` (`crates/antseal-cli/src/pipeline/receipt_sink.rs:416-448`) writes
  every capture, merged with the armed prior when there is one (`:424-427`). It has no empty-map
  case. So a first-sub-batch revert journals the receipt
  `{blobs: [], tx_map: {}, txs: [Reverted], storage_cost_atto: 0}`.
- `git grep -n 'TxStatus::Reverted' 6e1cab3 -- crates/antseal-cli/src` finds 0 lines (control:
  `TxStatus::Confirmed` → 7). No CLI reader tells a revert-only receipt apart.
- **Every "did money move?" reader keys on a receipt existing:** `abandon_pre_pay`'s rule 2
  (`crates/antseal-cli/src/seal_resume.rs:498-500`, *"Rule 2: the receipt is the authority on
  whether money moved"*), `AbandonPreview::read` (`:652-653`), and the resume's receipt branch
  (`resume.rs:184`). That branch's repair sets `Paid` on a pre-pay tag (`:203-210`, `set_state`
  at `:209`) before the remainder's consent is asked.

### 1.5 What a zero-ANT revert's capture does in the CLI — executed

P1's window F journals that receipt with `put_receipt` on an `Anchored` work, then drives the
CLI (exit file `0`):
- **`abandon` refuses**, class `Usage`, exit 2: *"usage error: work … has already been paid for —
  a payment receipt is journaled for it. Abandoning it would forfeit that payment permanently …
  no further payment is needed …"*. Every clause is false: no ANT moved, nothing would be
  forfeited, and the full payment is still owed.
- **A declined resume** (*"consent declined: nothing was paid, anchored, uploaded, or
  disclosed"*, exit 10) **leaves `fine=Some(Paid) mirror=IncompletePostPay`.** From then on
  `list` prints `"time-boxed"`, *"RESUME PROMPTLY: this seal is paid for, …"*, and `abandon`
  refuses on every run, for a work on which no ANT moved.
- **A consented resume finishes correctly** (`Sealed resumed=true`, then
  `fine=Some(Complete) mirror=Complete`). The money is right; the state and every money message
  are wrong.
- **Exit 28's words, by their template.** The pipeline maps `StrandedPayment` to
  `CliError::PaymentStranded`, exit 28 (`pipeline/error.rs:470-476`), whose Display
  (`crates/antseal-cli/src/error.rs:779-785`) at a count of 0 reads *"payment stranded
  mid-sequence: 0 sub-batch transaction(s) landed before the failure and the journaled partial
  receipt is authoritative — this is not a transient network failure and money has already
  moved: … which re-pays no quote the receipt already maps …"*. *"Money has already moved"* is
  false (only gas was spent). *"Re-pays no quote the receipt already maps"* is vacuous: the
  receipt maps none, and the re-run charges the full price after consent.

### 1.6 The devnet as built cannot produce a mined revert of the first sub-batch

The payer's provider is `wallet.to_provider()` (`ant_backend.rs:271`), which evmlib 0.9.0 builds
with alloy's `ProviderBuilder::new()` (`src/wallet.rs:213-214`, `:267-271`). alloy-provider 1.8.3
documents that constructor as enabling the *"recommended fillers … that handle gas estimation, nonce management,
and chain-id fetching"* (`src/builder.rs:131-140`). `eth_estimateGas` fails for a call that would
revert, so on the devnet a would-be revert becomes a submission failure (`ant_backend.rs:709-717`,
`Payment` at a count of 0), not a mined revert. Forcing one would need Anvil with automine off and
a storage write to the token's allowance or balance slot between submission and mining:
layout-dependent, e2e-devnet-only and M-sized. Not proposed.

### 1.7 The words today, and the one Display this record rewords

- **`Payment`** (`crates/antseal-net/src/error.rs:37-41`). Doc: *"Payment submission failed
  **before any transaction landed** (no money moved). A failure after one or more sub-batch txs
  landed is [`StorageError::StrandedPayment`] instead — the distinction is the whole point of the
  split."* Display: `#[error("payment failed before any transaction landed: {reason}")]`. In
  this crate a landed count counts `Confirmed` transactions, but a user reads "landed" as
  "mined", so a mined-and-reverted transaction makes the sentence read false.
- **Every current `Payment` producer moves no ANT**, with the one possible exception that `S51`
  records (§4): the approval (`ant_backend.rs:476`), the two stale-quote checks (`:582`, `:591`),
  calldata and submission with no prior landing (`:694`, `:710`), the read-only backend
  (`:1084`), and finalize (`:1582`, `:1590`; after §2 R2, the pre-pass only). The approval runs
  before any sub-batch (`:637-641`), so gas may already be spent when a later step fails with
  `Payment`.
- **`StrandedPayment`'s doc** (`error.rs:80-91`, D198's text) opens *"Payment failed
  **mid-sequence with money already moved**: one or more sub-batch txs landed before the
  failure"*. Two producers return it at a count of 0: the first-sub-batch revert, and the
  unobserved first landing.
- **D147 §2 R11 froze these strings:** *"Do not reword `StorageError`'s own `Display` strings.
  The storage taxonomy is correct; only the CLI mapping was wrong."* (D147:672-673). For
  `Payment`, that premise stops holding once a mined revert produces it (§2 R3). §2 R4 therefore
  rewords this one Display, and D147 takes an addendum. `StrandedPayment`'s Display
  (`error.rs:92-96`) is untouched.
- **No snapshot carries `Payment`'s Display.** The 23 entry of
  `crates/antseal-cli/tests/snapshots/cli-errors.display.txt` (`:55-56`, *"network failure:
  quote_batch: no peers reachable"*) is built from a hand-written `CliError::NetworkFailure`
  (`crates/antseal-cli/tests/exit_codes.rs:383-385`), not from a `StorageError`. Its 28 entry
  (`:87-88`) uses n = 2 (`tests/exit_codes.rs:527-529`). All six *"a payment sub-batch
  transaction reverted on-chain"* fixtures use a count of at least 1 (`tests/exit_codes.rs:529`,
  `:581`; `pipeline/error.rs:583`, `:590`, `:712`, `:744`).

### 1.8 The options for `S50`, priced against `U32` and D134 §2 R3

- **(i) `Payment` with amended words (H4).** The class is right: no ANT moved, and a resume pays
  everything. No exit code changes. On its own it fixes only the exit text: the capture still
  journals the revert-only receipt, and every harm in §1.5 remains.
- **(i′) (i), plus no capture without a confirmed landing — ruled.** With no receipt, every
  reader is right by construction: the work is abandonable, `list`'s *"nothing was paid"* is
  true, and the resume is the full pre-pay path with fresh consent. Cost: `TxStatus::Reverted`'s
  doc (*"The record is journaled as evidence of the gas spend"*,
  `crates/antseal-net/src/receipt.rs:111-115`) is narrowed, and a first-sub-batch revert's hash
  and gas stay on-chain and in the wallet's history, not in the vault. No frozen surface moves.
- **(ii) Keep `StrandedPayment`, with true words at n = 0.** It needs a conditional Display in two
  crates and a new rendering of frozen 28 material (`cli-errors.display.txt:88`;
  `docs/user/funding-your-wallet.md:249`). It carves an exception into D147's money-moved class,
  and the receipt harms remain unless the capture is suppressed too — and then *"the journaled
  partial receipt is authoritative"* is false. Worst.
- **(iii) A new class, e.g. `payment-reverted` at exit 38**, the first free code outside 40–49
  (`command grep -c -E '=> 3[89],' crates/antseal-cli/src/error.rs` → 0; control `=> 37,` → 1;
  D134:308-312 keeps the table append-only). The most explicit, but it costs a class row, its
  docs, a snapshot entry, the exit-code tests and the user tables, for an XS row the devnet cannot
  reach (§1.6). The common revert causes (the allowance or balance changed between preflight and
  execution) are cured by the retry 23 implies, because preflight and the approval run again. Not
  worth it.
- **(iv) Keep the capture, and make "paid" mean "the receipt maps at least one quote" in the
  readers.** It rewrites `S16`'s money predicate in three or four CLI sites. Resume would take
  the pre-pay path with `prior: None`, and `put_receipt`'s last-write-wins would overwrite the
  revert record at the next payment anyway, so the gas evidence is lost all the same. Refused
  for this row. §2 R3 records how this wave's D203 adopts the reader half for other rows.

## 2. RULING

### §2 R1 — One pure seam decides what follows each awaited receipt

The decision taken after each awaited sub-batch receipt in `AntCoreBackend::pay` — the revert
branch, the confirmed branch's finalize result, the capture and `S46`'s stop
(`ant_backend.rs:756-832` at `6e1cab3`) — moves into a **pure** function beside `emit_capture`
(`:1636`). A sketch, whose names are the lane's:

`fn settle_sub_batch(outcome: SubBatchOutcome, hook: Option<&CaptureHook>, records, tx_map, txs,
gas_cost_wei, batch_index, sub_batch_count) -> Result<(), StorageError>`, with
`enum SubBatchOutcome { Reverted, Confirmed { finalized: Result<(), String> } }`.

- The loop calls it after every awaited receipt.
- `S46`'s `NotDurable` stop moves into it unchanged (D198 §2 R2): mid-sequence it returns D198's
  `StrandedPayment` and reason, and after the last sub-batch it stops nothing.
- **The unobserved-landing branch (`:719-753`) is not moved and not changed.** Money may have
  moved there, and 28 is right.

*Why:* no in-crate test can reach `pay()`'s tail (§1.3), so a fault hook inside `pay` would be
exercised by nothing, and a devnet cannot inject one. A pure function that takes the finalize
result as data is reachable by unit tests, and it puts `S49`, `S50` and `S46`'s stop in one
place. The devnet `S46` test becomes the witness that the loop really calls it (§3).

### §2 R2 — `S49`: a landed sub-batch whose proofs fail is captured, then stranded

- `finalize_ready_blobs` returns its failure as data (`Result<(), String>` or equivalent), and
  each caller classifies it.
- **The zero-transfer pre-pass** (`:667-674`, before any sub-batch) keeps `StorageError::Payment`
  exactly as today.
- **A failure after a confirmed landing** first delivers the capture of what exists: sub-batch
  k's quote→tx map, its tx record, the gas, and the records of any of k's blobs finalized before
  the failing one. **Then** it returns `stranded_or_payment(confirmed_count, reason)`, which is
  always `StrandedPayment` there, because the count is at least 1. The capture's verdict reaches
  the pipeline's existing 28/37 split (`resume.rs:500-517`): 28 when the capture became durable,
  37 when it did not.
- **Reason text:** *"proof construction failed after sub-batch {k} of {n} landed: {redacted
  upstream error}"*, redacted through `redact_evm_error` as the loop already does. Through exit 28
  it reads *"payment stranded mid-sequence: {n} sub-batch transaction(s) landed before the failure
  … ({reason})"*, which is true.
- **Refused: capturing before finalize on every landing.** It would journal k's map without k's
  records, so a crash before the next capture makes a resume re-buy sub-batch k (§1.2).

**The stated limit.** A blob that has no record when the failure surfaces is re-bought by a
resume under a fresh quote, although its transfer landed. That is the mechanism of D37 Decision
5's granularity caveat — coverage is per blob record, payment is per transfer
(`resume.rs:619-625`) — reached by a second cause. Like the caveat's own cause, it is
unreachable at the pin (§1.3). **As measured, the set is wider than the one blob the rulings
name.** `finalize_ready_blobs` stops at the first failure (§0), so the set is the failing blob
plus every ready blob of sub-batch k that the function had not yet reached: up to the rest of
the sub-batch, which holds up to 256 transfers at the default cap
(`ant_backend.rs:62-65`, one non-zero transfer per blob). Whether to finalize past a failing blob
is not decided here (§4).

*Why:* this is the row's Do, read as the failure path only. The class and the journal agree that
money moved, and the success path keeps journaling k's records together with k's map.

### §2 R3 — `S50`: a revert with no confirmed landing in this call is `Payment`, and journals nothing

- **A revert when this call has no confirmed landing** (`confirmed == 0`) returns
  `StorageError::Payment` and delivers **no** capture. Its reason: *"the first payment sub-batch
  transaction reverted on-chain: it moved no ANT, and the gas it used is spent"*. Through exit 23
  it renders *"network failure: payment failed before any ANT moved: the first payment sub-batch
  transaction reverted on-chain: it moved no ANT, and the gas it used is spent"*; the *"network
  failure:"* prefix is class 23's, for every `Payment` (D147:536).
- **A revert after at least one confirmed landing** is unchanged: capture, then
  `StrandedPayment { landed_tx_count: confirmed }` with the unchanged reason *"a payment sub-batch
  transaction reverted on-chain"*. The fixtures in `tests/exit_codes.rs` and `pipeline/error.rs`
  stay valid (§1.7).
- **Remainder rounds.** `confirmed` counts this call's landings. A remainder round whose first
  sub-batch reverts is `Payment` with no capture, and the prior round's durable receipt stays
  untouched and authoritative: the sink writes only when it is handed a capture, and it merges
  the armed prior into each one (`receipt_sink.rs:424-427`). The lane confirms this by reading the
  CLI's remainder path, and states it in its report.

*Why:* the executed defect is the capture (§1.5). Every money reader takes a revert-only receipt
as payment: `abandon` refuses with *"already been paid for"*, and a declined resume tags the work
`Paid`. With no capture, the journal says what happened — no ANT moved, only gas was spent — and
every reader is right without an edit to any reader.

**The reader half lands this wave under D203, for its own rows.** D203's money group keys
`abandon_pre_pay`'s rule 2, `AbandonPreview::read` and `resume.rs:184` on `payment_recorded` — a
journaled receipt that maps at least one quote (M1, M6, row `U110`) — and runs the early `Paid`
repair only when nothing remains to buy (M5). That predicate excludes a revert-only receipt,
because a `Reverted` transaction's quotes are never mapped, so it also cures window F in vaults
written before this record's fix (P1 §7.7, case (b)). The two rules are complementary: D204 stops
new revert-only receipts at the producer, and D203 makes the readers immune to old ones. Neither
depends on the other to be correct.

### §2 R4 — `Payment` means "before any ANT moved"

- **Display** (`crates/antseal-net/src/error.rs:41`): *"payment failed before any ANT moved:
  {reason}"*.
- **Doc** (`:37-40`): *"Payment failed before any ANT moved. Gas may have been spent — by a token
  approval, or by a first payment sub-batch that reverted on-chain (S50) — but no quote is paid
  and nothing is journaled, so a resume quotes and pays everything afresh. A failure after one or
  more sub-batch txs landed is [`StorageError::StrandedPayment`] instead — the distinction is the
  whole point of the split."*
- **`StrandedPayment`'s doc** (`:80-91`) gains: *"A revert reports at least one landing (S50);
  only an unobserved first landing reports 0, because there money may have moved."*
- **`TxStatus::Reverted`'s doc** (`crates/antseal-net/src/receipt.rs:111-115`): the record is
  journaled as gas evidence when an earlier sub-batch of the same payment landed; a first
  sub-batch that reverts journals nothing (S50).
- **The pipeline's comment** (`crates/antseal-cli/src/pipeline/error.rs:485`) becomes *"by its
  own definition, "before any ANT moved" — retry quotes and pays afresh."*
- **No exit code moves**: 23 and 28 keep their meaning. `cli-errors.display.txt` does not change
  (§1.7). The lane verifies both entries by rendering them and re-reading the snapshot; if any
  pinned text would change, it stops and reports.

*Why:* *"before any ANT moved"* is true of every `Payment` producer (§1.7), the approval
included, save the one `S51` records (§4), and it is the sense in which 23's retry is right: no
quote is paid, so a retry quotes and pays everything afresh. H4's *"cover a reverted transaction"* would have described one
producer. D147 §2 R11's premise — that the storage taxonomy's own strings are correct — fails for
this one string once a mined revert produces it, so R11 is superseded for `Payment`'s Display
alone.

### §2 R5 — The seam is tested in-crate; the devnet witnesses the wiring

The greens and plants are §3's. Both Accepts are met in-crate under `ant-backend`: `S49`'s asks
for an in-crate test that injects a proof failure after a landed sub-batch, and `S50`'s accepts
*"devnet or an in-crate double"*. The seam is that double.

*Why:* the seam is the only venue that reaches a proof failure after a landing or a mined
first-sub-batch revert (§1.3, §1.6).

### §2 R6 — Records

- **D147** takes a dated addendum: `Payment` means *"before any ANT moved"*; a first-sub-batch
  revert is `Payment` and journals nothing; R11 is superseded for `Payment`'s Display; R6's
  `Payment` row and R5's comment read under the new definition; and §1.2's revert site returns
  `StrandedPayment` only after a landing.
- **D198** takes a dated addendum: the stop now lives in `settle_sub_batch`, and §6's `S49` and
  `S50` entries are answered.
- **D37 takes no addendum**, because this record changes what neither Decision says:
  - Decision 2 journals each sub-batch that lands before the next is submitted (D37:102-109). R2
    makes that hold on the proof-failure path; it does not change it.
  - D37 has no word about reverts (`command grep -c -i revert` over D37 → 0; control
    `lands|landed` → 7), and the `Reverted` arm postdates it (`receipt.rs:100-102`, *"The
    reverted arm was added at S6"*). R3 decides a case Decision 2 does not address, and Decision
    2's bound is about money, which a zero-landing revert does not move.
  - Decision 5's granularity caveat (D37:417-428) stays true as written. R2's limit reaches the
    caveat's mechanism by a second cause, which this record states (§2 R2), and both causes are
    unreachable at the pin.

### What no ruling here moves

- **No exit code is minted** and no class is added. 23 and 28 are reused, and
  `PINNED_CLASS_COUNT` stays 36 (`crates/antseal-cli/tests/namespace_disjointness.rs:85`).
- **No `antseal-cli` Display template changes**, and no snapshot line moves. The one new
  rendering is a value inside 23's `{detail}`: under D65, `message` is human copy.
- **No `--json` key, help text or config key.** No `U32`-frozen surface moves.
- **Untouched by this record:** the unobserved-landing branch, `MockBackend`, the
  `StorageBackend` trait, `pipeline/receipt_sink.rs`, and the CLI's money readers (D203's lanes
  edit those this wave, §2 R3).
- **The gate.** This is the payment path. `crates/antseal-net/` and
  `crates/antseal-cli/src/pipeline/` are both on `scripts/gate-features.sh`'s
  `HEAVY_TRIGGER_PATHS` (`:112-121`), and the close gate runs with the heavy tier and the devnet
  E2E forced (`ANTSEAL_GATE_HEAVY=1 ANTSEAL_GATE_E2E=1`).

## 3. Fault plants

The implementing lane owes these. The seam does not exist at `6e1cab3`, so the red baselines of
G49-1, G50-1 and G50-3 are the plants that put `HEAD`'s behaviour back inside the seam (P49-1,
P50-1, P50-2, P50-3), run first. G49-2, G46-u and G50-2 pin behaviour `HEAD` already has: G46-u
and G50-2 redden under P46-u and P50-4, and G49-2 is a control against a fix that strands the
pre-pass. Every plant must compile and is judged by its message. Every restore is followed by a
`touch` and a sha256 check against the lane's final file.

**The green tests — the load-bearing half.** In-crate, under
`cargo test -p antseal-net --features ant-backend --lib`, unless stated otherwise:
- **G49-1** (e.g. `s49_a_proof_failure_after_a_landing_delivers_the_capture_and_strands`):
  `Confirmed { finalized: Err(…) }`, with sub-batch 1's quote mapped, `txs = [Confirmed]` and a
  recording hook. Exactly 1 capture, whose `tx_map` holds the landed quote and whose
  `txs.len() == 1`; `StrandedPayment { landed_tx_count: 1, .. }`; the reason contains *"proof
  construction failed after sub-batch"*.
- **G49-2** (e.g. `s49_the_pre_pass_failure_stays_payment`): the pre-pass mapping gives `Payment`
  and 0 captures.
- **G46-u**: `Confirmed { finalized: Ok(()) }` with a hook that answers `NotDurable`. Mid-sequence
  it gives D198's `StrandedPayment` and reason; on the last sub-batch, `Ok(())`. This is in-crate
  coverage of D198 §2 R2, which until now only the devnet had.
- **G50-1** (e.g. `s50_a_first_sub_batch_revert_is_a_payment_failure_and_journals_nothing`):
  `Reverted` at `batch_index 0`, `txs = [Reverted]`, an empty map and a recording hook.
  `Err(Payment { .. })`, `to_string()` equal to the exact R3/R4 text, and **0 captures**.
- **G50-2** (e.g. `s50_a_later_revert_keeps_the_stranded_class_and_its_capture`):
  `txs = [Confirmed, Reverted]`, the map `{q1 → tx1}`, `batch_index 1`.
  `StrandedPayment { landed_tx_count: 1 }` with the unchanged reason, and 1 capture with 2 txs and
  1 mapped quote.
- **G50-3** (default features, `cargo test -p antseal-cli --lib`, appended to
  `pipeline/error.rs`'s test module):
  `CliError::from(SealError::Storage(StorageError::Payment { reason: <the zero-count reason> }))`
  gives class `network-failure`, code 23, and the full message, compared as a whole string.
- **The wiring witness.** `devnet_s46_a_not_durable_capture_stops_the_next_sub_batch`
  (`crates/antseal-net/tests/devnet_backend.rs:1400`) and
  `devnet_s46_a_not_durable_last_capture_stops_nothing` (`:1505`) prove that the loop calls the
  seam. They run in the gate's e2e-devnet lane. Without `ANTSEAL_DEVNET_ENV` the target greens on
  its SKIP path (`:75-77`), so the heavy tier's count for it is not devnet evidence (D198 §6).
  The lane need not boot a devnet unless it chooses to.
- **Unchanged and green:** `stranded_split_matches_the_taxonomy` (`ant_backend.rs:2030-2042`);
  the `exit_codes.rs` snapshot test over the unchanged `cli-errors.display.txt`; and D186's
  `s37::*` tests, because the pipeline does not change.

**The plants — proof that those tests can fail**

| Plant | What it puts back or breaks | Must redden |
|---|---|---|
| P49-1 | the old order: `finalized.map_err(Payment)?` before the capture | G49-1, on its class (`Payment` where `StrandedPayment { landed_tx_count: 1 }` is expected) and its capture count (0) |
| P49-2 | `Payment` instead of `stranded_or_payment` after a landing | G49-1, on its class |
| P46-u | the `NotDurable` arm dropped | G46-u (the devnet G1 must still pass at the gate) |
| P50-1 | `HEAD`'s unconditional capture on a revert | G50-1, on its capture count (1 where 0 is expected) |
| P50-2 | `HEAD`'s `StrandedPayment { landed_tx_count: 0 }` | G50-1, on its class |
| P50-3 | the old Display | G50-1 and G50-3, by message |
| P50-4 | a revert after a landing takes the `Payment` path | G50-2 |

**Venue.** `ant_backend.rs` compiles only under `ant-backend`, which no other round-1 lane
builds, so its plants may be made in the tree under the exclusive writer lock, with the restore,
`touch` and sha256 protocol. A plant in `crates/antseal-net/src/error.rs` (P50-3), which every
lane compiles, goes in a shadow copy with a private target, or under the same exclusive lock.
No lane builds `-p antseal-cli --features ant-backend` in the shared target.

## 4. What this record does NOT decide

- **`S51`, minted by this wave's rulings: a first-sub-batch submission error that the node may
  have accepted.** `ant_backend.rs:709-717` maps any `send_transaction` error to
  `stranded_or_payment(txs.len(), "sub-batch tx submission failed: …")`: `Payment` (23, "retry")
  for the first sub-batch. A transport error after the node received the raw transaction leaves a
  signed transaction that can still be mined, so a retry can pay a second time, up to one
  sub-batch; the unobserved-landing branch treats *"money MAY have moved"* as stranded, the
  broadcast step does not. Code-traced only (P1's report, §4 item 2). Its fix shapes need a
  D37-level ruling: sign locally and journal the hash as `Submitted` before broadcasting (D33's
  journal-first rule, extended to the send), or classify post-broadcast transport errors as
  stranded and let backfill resolve them. **Until `S51` is ruled, this is the one producer for
  which §2 R4's new doc sentence can be false**: the ANT moves after the error, when the accepted
  transaction is mined. The old sentence had the same gap.
- **Finalizing past a failing blob.** `finalize_ready_blobs` stops at the first failure, so the
  ready blobs of sub-batch k after it get no record, and a resume re-buys them (§2 R2's limit).
  Continuing past the failure would narrow the re-buy to the blobs whose proofs actually failed.
  Not ruled: unreachable at the pin, and an `S20` bump-review item, like the caveat itself.
- **Revert-only receipts that an earlier build already journaled.** Not this record's: D203's
  money group (M6, row `U110`) keys the readers on `payment_recorded`, which excludes them
  (§2 R3).
- **`list`'s money clock and cost line after a stranded payment** (P1's report, §4 item 1). That
  is `U109`, ruled in D203 (M2, M3).
- **A class of its own for a reverted payment** (option (iii), §1.8). Refused. After `U32` it
  could only be appended (D134 §2 R3 (1)).
- **The gas evidence of a first-sub-batch revert.** After §2 R3 it lives on-chain and in the
  wallet's history, not in the vault. P1's report (§5) recommends accepting that, because option
  (iv) would lose the evidence at the next payment's receipt anyway; this record accepts it.
- **The CLI's description of class 23 as leaving the wallet untouched.**
  `crates/antseal-cli/src/error.rs:56-60` says that 20, 21 and 23 *"all three leave the wallet
  untouched by the failed attempt"*. That is true of ANT, which is the contrast the next sentence
  draws (*"28, 29 and 37 are the three where ANT has already left it"*). It was not true of gas
  before this record — a `Payment` after the approval (`ant_backend.rs:637-641`) has spent the
  approval's gas — and §2 R3 adds a second gas spender to 23. The file is outside every lane's
  write scope this wave (L-NET3 must not touch it). Recorded, not ruled.
- **`MockBackend`'s zero-count fault.** `Fault::AfterSubBatches(0)` would return
  `StrandedPayment { landed_tx_count: 0 }` for a kill before any sub-batch
  (`crates/antseal-net/src/test_util/mock.rs:457-461`), but no test arms it at 0 (0 of the 7
  `AfterSubBatches(` uses at `6e1cab3`). The mock models a kill; unchanged.
- **New rows.** This record mints none. `S51` is minted by the wave's rulings and named here;
  `git grep -n -w 'S51' 6e1cab3 -- TODO.md tasks` finds 0 lines (control `S50` → 5).

## 5. Edit list — per write scope, with the lane named before this record was written

### L-NET3 (round 1) — `S49` and `S50`

- `crates/antseal-net/src/ant_backend.rs`: `pay`'s loop (`:640-845` at `6e1cab3`),
  `finalize_ready_blobs` (`:1554-1617`), the new `settle_sub_batch` beside `emit_capture`
  (`:1636`), and new tests appended at the end of `mod tests` (`:2008-3002`) (R1–R3, R5).
- `crates/antseal-net/src/error.rs`: only the `Payment` variant's doc and `#[error]` (`:37-45`),
  `StrandedPayment`'s doc (`:80-91`), and any unit test in the file that pins the old `Payment`
  Display (R4). At `6e1cab3` none does: the old text is at `:37` and `:41` only.
- `crates/antseal-net/src/receipt.rs`: only `TxStatus::Reverted`'s doc (`:111-115`) (R4).
- `crates/antseal-cli/src/pipeline/error.rs`: only the comment at `:485` and one new unit test,
  G50-3, appended at the end of its test module (R4, R5).
- Any other file that pins *"payment failed before any transaction landed"*: the lane greps the
  whole repository and lists every hit. It edits a hit only under `crates/antseal-net/` or as one
  quoted sentence in `docs/user/funding-your-wallet.md`, and otherwise stops and asks the
  orchestrator. At `6e1cab3` the other hits are `TODO.md` and `tasks/S.md`, which are the
  orchestrator's, and D147's history, which its addendum answers (§0).
- **Must not:** any other `antseal-cli` file (`seal_resume.rs`, `listing.rs`, `resume.rs`,
  `receipt_sink.rs`, `backend.rs`, the CLI's `error.rs`, `commands.rs`), any snapshot,
  `crates/antseal-net/tests/devnet_backend.rs`, or any document beyond the one granted sentence.
- **Builds:** `cargo test -p antseal-net --features ant-backend --lib` and
  `cargo clippy -p antseal-net --features ant-backend --all-targets -- -D warnings` in the shared
  target under the lock, and G50-3 as a default-feature `antseal-cli` lib test there too. Never
  `-p antseal-cli --features ant-backend` in the shared target. Plants per §3's venue.

### L-RESUME2 and L-MONEY — D203's money group; no edit for this record

The readers' predicate (M1, M6) and the early repair (M5) are D203's: L-RESUME2 writes M1 and
L-MONEY M5 and M6 (round 2). Neither writes `pipeline/error.rs`, L-NET3's one `antseal-cli` file.

### L-LOC (round 3) — living-doc citations

Living documents cite `ant_backend.rs` by line, for example `docs/threat-model.md:899`
(`ant_backend.rs:1838-1907`, which lies after the edited region and will shift). L-LOC re-points
them after the last code edit.

### RECORDS-B — dated addenda

D147 and D198 (§2 R6). D37: none (§2 R6).

### Orchestrator — `TODO.md`, `tasks/S.md`, `docs/decisions/README.md`, `docs/instrument-ledger.md`

- `S49` and `S50`: their ticks, against §3; this record's index row and register rows.
- `S51`: its register row and its `tasks/S.md` entry (§4).
- P1's instrument findings (its report's §3) concern D106, which D203's addenda answer, and a
  wave-scratch locator; none needs an act from this record.

## 6. As built — wave 40, lane L-NET3 (recorded in place before this record was first committed)

Every verdict below was read from an exit file, per the lane's report, except the shadow runs of
its snapshot check, which the report gives as exit 0 without naming a file. Every red was judged
by its message. Re-read for this section, the lane's four files match its final sha256; the line
numbers below are the tree's.

- **§2 R1, the seam.** `enum SubBatchOutcome { Reverted, Confirmed { finalized: Result<(),
  String> } }` (`crates/antseal-net/src/ant_backend.rs:1637`) and `settle_sub_batch` (`:1680`)
  follow the ruling's sketch: eight inputs, pure, and the capture is its only effect. The loop
  builds the outcome (`:779-794`) and calls the seam after every awaited receipt (`:797-806`).
  `S46`'s stop moved in with its reason unchanged (`:1722-1732`; only the source wrap moved). The
  unobserved-landing branch is byte-identical: `HEAD`'s `:719-755` and the tree's `:721-757`
  compare equal (`cmp` exit 0).
  - **Deviation:** `settle_sub_batch` carries `#[allow(clippy::too_many_arguments)]` with its
    reason (`:1677-1679`): R1's eight inputs exceed clippy's limit of seven, and bundling them
    *"would move the same fields behind a name that explains nothing"*.
- **§2 R2 (`S49`).** `finalize_ready_blobs` (`:1535`) returns `Result<(), String>`, the redacted
  detail of the first proof it could not build (`:1563`). The pre-pass maps it to `Payment`
  through the new `pre_pass_proof_failure` (`:676`, `:1739`). After a confirmed landing the seam
  delivers the capture (`:1711`), then returns `stranded_or_payment(landed, …)` whatever the
  capture's verdict (`:1712-1721`), with the ruled reason *"proof construction failed after
  sub-batch {k} of {n} landed: {detail}"*. The pipeline's 28/37 split (`resume.rs:500-517` at
  `6e1cab3`) is outside the lane's scope, and the lane did not edit it.
  - **Deviation:** the pre-pass keeps `HEAD`'s upstream-error text byte for byte, but its
    unreachable *"no paid chunk"* breach now reads *"proof construction failed: upstream returned
    no paid chunk for one prepared chunk (invariant breach)"*: the function returns the bare
    detail and the caller adds the prefix. Nothing pins either text.
  - **The stated limit, as built.** The seam's rustdoc (`:1669-1670`) says that the blob whose
    proof failed has no record and is re-bought under a fresh quote. That is true, and narrower
    than §2 R2's measured set: `finalize_ready_blobs` stops at the first failure (`:1529-1530`),
    so the ready blobs it had not reached have no record either. G49-1's fixture has no such
    blob. On RECORDS-B's finding the orchestrator **ruled no change** to finalizing past a failing
    blob (unreachable at the pin, and within D37 Decision 2's one-sub-batch bound); §4 carries it.
- **§2 R3 (`S50`).** A revert with no confirmed landing in this call returns `Payment` with the
  ruled reason and delivers no capture (`:1695-1701`). A revert after a confirmed landing captures,
  then returns `StrandedPayment` with the unchanged reason (`:1702-1708`). The count is this call's
  `Confirmed` records: `txs` is a fresh local in `pay` (`:663`).
  - **Remainder rounds, confirmed by reading** (per the lane's report; no code changed). With no
    capture, `VaultReceiptSink::capture` (`crates/antseal-cli/src/pipeline/receipt_sink.rs:416-447`),
    the sink's only write and the only place the armed prior is merged (`:424-427`), never runs:
    the prior round's durable receipt stays as written. `Payment` takes the pipeline's plain error
    arm, not the 28/37 split, and returns before `put_receipt` and `set_state(Paid)`; a re-run
    re-quotes only the remainder. At `HEAD` the same event journaled the merged prior plus the reverted tx and
    exited 28: the same money, a different class, words and gas record.
  - No CLI test or mock models a zero-count revert, and every *"reverted on-chain"* fixture
    carries a count of at least 1, so all stay valid (per the lane's report).
- **§2 R4, the words.** `Payment`'s Display (`crates/antseal-net/src/error.rs:43`) is *"payment
  failed before any ANT moved: {reason}"*, and its doc (`:37-42`) is the ruled text, keeping
  `HEAD`'s bold on the defining phrase. `StrandedPayment`'s doc gains the ruled sentence
  (`:83-85`); its Display is untouched. `TxStatus::Reverted`'s doc
  (`crates/antseal-net/src/receipt.rs:111-117`) journals the record as gas evidence *"when an
  earlier sub-batch of the same payment landed; a FIRST sub-batch that reverts journals nothing
  (S50), because no quote is paid"*. The pipeline's comment
  (`crates/antseal-cli/src/pipeline/error.rs:485`) is the ruled text.
  - **The snapshot was rendered, not assumed.** In a shadow with a private target, an
    `ANTSEAL_BLESS=1` run of `display_output_matches_committed_snapshot` wrote a
    `cli-errors.display.txt` equal (`cmp`) to the tree's and to `HEAD`'s (sha256 `ec485336…`), and
    its 23 entry (`:55-56`) and 28 entry (`:87-88`) were re-read. No exit code moved.
  - **The old words.** `git grep --untracked -n 'before any transaction landed'` finds no line
    under `crates/` or `docs/user/`. It finds `TODO.md:1099` and `tasks/S.md:715` (the
    orchestrator's), D147's history and addendum, and this record.
  - **The producers.** The lane called the new words true of every other `Payment` producer (at
    `6e1cab3`: `:476`, `:582`, `:591`, `:694`, `:710`, `:1084`, and the CLI's `READ_ONLY_REFUSAL`).
    For the submission error (`:710`) that is too strong: §4's `S51` qualification stands.
- **The orchestrator's three acts**, all line-count neutral.
  - `crates/antseal-net/src/ant_backend.rs`, `settle_sub_batch`'s doc (the S49 bullet): it said
    only *"The blob whose proof failed has no record"*; it now says the failing blob *and every
    ready blob after it* get no record, which is §2 R2's measured limit. Applied after the lane
    reported, so that file's final sha256 differs from the lane's `3cd70185…` by this doc line
    alone.
  - `crates/antseal-net/src/backend.rs:231`, in `StorageBackend::pay`'s `# Errors`: *"(nothing
    landed)"*, the sense R4 retires, became *"(no ANT moved)"*. **Deviation:** "What no ruling
    here moves" lists the `StorageBackend` trait as untouched; its signatures are, and one line
    of its doc moved.
  - `crates/antseal-cli/src/error.rs:59-62`, the module doc §4 cites at `:56-60`: *"all three
    leave the wallet untouched by the failed attempt"* became *"in all three the failed attempt
    moved no ANT (gas at most — D204)"*. That answers §4's bullet on class 23; no Display changed.
- **§2 R5, the tests**, in `mod s49_s50_settle` (`ant_backend.rs:3096`): G49-1
  `s49_a_proof_failure_after_a_landing_delivers_the_capture_and_strands` (`:3273`), G49-2
  `s49_the_pre_pass_failure_stays_payment` (`:3349`), G46-u
  `s46_a_not_durable_capture_stops_mid_sequence_but_not_after_the_last` (`:3389`; four rows: not
  durable at 1 of 2 and at 2 of 2, durable, no hook), G50-1
  `s50_a_first_sub_batch_revert_is_a_payment_failure_and_journals_nothing` (`:3452`) and G50-2
  `s50_a_later_revert_keeps_the_stranded_class_and_its_capture` (`:3489`). G50-3 is
  `a_first_sub_batch_revert_is_the_retry_class_in_true_words` (`pipeline/error.rs:937`), built
  through `From<SealError>` and compared as one whole string.
  - **Deviation (stronger than ruled):** G49-1 and G49-2 drive the real `finalize_ready_blobs`
    over upstream's own `finalize_batch_payment` through an injected gap, and assert upstream's
    words *"Missing tx hash for quote <hex redacted>"*: an ant-core bump that rewords that error
    reddens them on purpose (`S20`). G49-1 also asserts that the unmapped quote's hash stays out
    of the reason and that the blob finalized before the failing one keeps its record.
  - **Deviation:** G49-2 counts no captures: the pre-pass is never handed the hook, so 0 holds by
    construction. It asserts the class, the exact reason, and that nothing is recorded or staged.
  - **Red first, in `HEAD`'s shape** (the seam built with `HEAD`'s revert branch and
    `finalized.map_err(Payment)?` before the capture): exit 101, *"3 passed; 2 failed"*. G49-1:
    *"S49: a proof failure after a landing must strand with the landed count — expected
    StrandedPayment { landed_tx_count: 1 }, got Err(Payment { reason: "proof construction failed:
    payment error: Missing tx hash for quote <hex redacted> — …" }); captures: 0"*. G50-1: *"S50:
    a first-sub-batch revert moved no ANT — expected Payment, got Err(StrandedPayment {
    landed_tx_count: 0, reason: "a payment sub-batch transaction reverted on-chain" }); captures:
    1"*. G46-u, G49-2 and G50-2 were green there, as they must be.
  - **Green:** exit 0, *"145 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out"* (140 at
    `HEAD`). The adapter's own test module holds 25 tests, against 20 at `HEAD` (recounted).
- **Plants, every one red by message.** P49-1, and P50-1 with P50-2, are the red-first shape
  above, as briefed. P49-1 and P50-2 were not re-run on top of D204; P50-1 was, alone, below.
  - **Deviation:** P50-1, P49-2, P46-u and P50-4 shared one in-tree exclusive window (166 s; exit
    101, *"1 passed; 4 failed"*), because contended builds took about 22 minutes each. Each
    changes a different arm of the seam, and each arm is reached by one test. G49-2 stayed ok.
    The restore was `cp`, `touch`, and a sha256 equal to the pre-plant `3cd70185…`.
    - P49-2 → G49-1: *"… got Err(Payment { reason: "proof construction failed after sub-batch 1
      of 2 landed: …" }); captures: 1"*.
    - P46-u → G46-u: *"not durable, sub-batch 1 of 2 / left: Ok(()) / right:
      Err(StrandedPayment { landed_tx_count: 1, … })"*.
    - P50-1 → G50-1: *"a zero-ANT revert journals nothing: 1 capture(s)"*, after the class and
      exact-Display assertions had passed, so the count is shown to bite on its own.
    - P50-4 → G50-2: *"captures: 0 / left: Err(Payment { reason: "a payment sub-batch transaction
      reverted on-chain" }) / right: Err(StrandedPayment { landed_tx_count: 1, … })"*.
  - P50-3, the old Display, in a shadow: exit 101 on G50-3, *"left: "network failure: payment
    failed before any transaction landed: …" / right: "network failure: payment failed before
    any ANT moved: …""*. **Deviation:** §3 lists G50-1 too, but an in-tree `error.rs` plant would
    force a rebuild on every lane, so it ran on G50-3 only. G50-1's exact-Display assertion has no
    red of its own; G50-3 carries that plant.
- **At the lane's close** (exit 0 each, per the lane's report): the default-feature
  `antseal-net` lib, 116 passed; `antseal-cli --lib -- pipeline::error`, 14 passed with G50-3 by
  name; `clippy -- -D warnings` over `antseal-net` with and without `ant-backend` and over
  `antseal-cli`, 0 warning lines; `rustfmt --check` on the four files; `check-personal-data.py`.
  It built `antseal-cli` with default features only. The plant-marker grep over the tree,
  untracked files included, exits 1 (positive control: 1 hit).
  - **A count to read with care.** The plant window's binary held 146 tests, the green's 145:
    L-INIT's ungated `random_source_failures_are_exactly_the_two_generate_variants` (`wallet.rs`)
    was in the window's build only. The close gate's heavy tier runs `cargo test -p antseal-net
    --features ant-backend` over the final tree (`scripts/gate-features.sh:231`).
- **What no ruling here moves, held.** `PINNED_CLASS_COUNT` is 36
  (`crates/antseal-cli/tests/namespace_disjointness.rs:85`). `test_util/mock.rs`,
  `receipt_sink.rs`, `tests/devnet_backend.rs` and `cli-errors.display.txt` are unchanged against
  `6e1cab3` (`git diff --quiet` exit 0). The trait's one doc line is the deviation above.
- **§2 R6.** RECORDS-B wrote the D147 and D198 addenda, and D37 takes none. The lane suggested a
  one-line D37 cross-reference; §2 R2 and §2 R6 already carry it.
- **Left open.**
  - **The wiring witness.** The lane booted no devnet. The two `devnet_s46_*` tests
    (`crates/antseal-net/tests/devnet_backend.rs:1400`, `:1505`, unchanged) witness that the loop
    calls the seam, and only the close gate's e2e-devnet lane makes them evidence: without
    `ANTSEAL_DEVNET_ENV` they green on their SKIP path. That lane also checks P46-u's *"the devnet
    G1 must still pass"*.
  - **`S51` owns** the submission error (§4). The lane minted no new row.
  - **The orchestrator owns** the seam's narrower limit sentence (`ant_backend.rs:1669-1670`) and
    `TODO.md:1091`, the ticked `S47`, whose `:1736-1770` was already stale at `6e1cab3`.
  - **L-LOC owns** the living-doc citations the edits moved (e.g. `docs/threat-model.md:899`).
    The lane's map: `finalize_ready_blobs` `:1554` → `:1535`, `emit_capture` `:1636` → `:1609`,
    `stranded_or_payment` `:1663` → `:1747`, `map_ant_error` `:1761` → `:1845`, `mod tests`
    `:2009` → `:2093`.

## Closing — this record is not consent

It changes the payment loop's handling of a failure after each awaited sub-batch receipt, one
`StorageError` Display, three rustdoc paragraphs and a comment, inside the wave's own commits.
Nothing in it authorises a push, a workflow dispatch, a deploy or any other outward act; each of
those needs the maintainer's express consent naming the action, the destination and the account.
