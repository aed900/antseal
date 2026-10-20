# D198 — A receipt capture **reports whether it became durable**, and the payment loop **submits no further sub-batch after one that did not**: D37's one-sub-batch loss bound holds under a failing vault, class 37 is reached through D186's unchanged predicate, and the pipeline does not change

- **Status: RESOLVED. H3 fell (b): its direction survived and three premises fell.**
  - **H3** — *"the capture hook reports durability; the payment loop stops after a
    non-durable capture and returns StrandedPayment with D186's predicate (class 37); the loss
    is bounded to one sub-batch; the Accept's devnet case ("exactly one sub-batch's payment is
    unrecorded, and the on-chain delta equals the receipt plus one sub-batch") is buildable in
    the existing devnet suites; the false rustdoc at antseal-net/src/error.rs:80-85 is
    corrected in the same act."*
  - **What survives: the direction, whole.** `antseal-net` owns the sub-batch loop, runs it
    sequentially and calls the hook synchronously before the next submission (§1.1), so a
    verdict the hook returns can stop sub-batch N+1: H3 is not mechanism-unbuildable (c).
    `StrandedPayment` reaches class 37 through D186's predicate with no pipeline edit (§1.4).
    The Accept's devnet case is buildable in `crates/antseal-net/tests/devnet_backend.rs` with
    no registry edit (§1.6), and the rustdoc is corrected in the same act (§2 R4).
  - **Premise 1 falls: D186's heal by a later capture.** D186 §1.4, R1's *Why*, §1.8's *"A
    healed run stays 28: yes"* and test 2 assume that the loop goes on after a failed capture.
    Once it stops at the first non-durable capture that has a successor, the loop no longer
    produces a mid-payment heal (§1.5). D186's predicate is unchanged and still right.
  - **Premise 2 falls: the `S18` harness's lossy rows rely on the loop not stopping.** Their
    sinks must answer *durable* by design, or those rows break (§1.7, §2 R3).
  - **Premise 3 falls: the false rustdoc is two sentences, and it cites the wrong decision.**
    The field doc (`crates/antseal-net/src/error.rs:92-93`) is false in the same way, and the
    variant doc cites D37 Decision 3, the native fallback the adapter does not drive; Decisions
    2 and 7 govern (§1.5). The row's trait locator (`crates/antseal-cli/src/backend.rs:1163`) is
    stale: the trait is at `:1192`.
- **Date: 2026-10-19**
- Owner row: **`S46`** (§2 R1–R6). This record mints no row.
- Related:
  - **D37** Decision 2 (the one-transaction loss bound, D37:102-109) and Decision 7 (the
    durable sink, D37:349-357); takes a dated addendum;
  - **D186** (`S37`'s predicate and class 37; §1.4, §1.8 and test 2; takes a dated addendum);
  - **D147** §2 R11 (`StorageError`'s own Display strings are not reworded);
  - **`S20`** (the bump-PR containment of `ant_backend.rs`) and **`S6`** (the machine check on
    upstream symbols outside the allowlist);
  - **`S47`** (ruled without a record this wave: the same lane and the same two files, in
    disjoint hunks, landing first);
  - **`S18`** (the kill-and-resume harness whose doubles §2 R3 rules), **`S31`** (the receipt
    sink), **`S37`** (class 37).

## 0. What was measured against

`HEAD` `07a170c` (local `main` = `origin/main`), tree clean, 2026-10-19.

Planning lane P1 (wave 39) worked read-only and ran no build; every claim it made was read from
code, tests and records, with the line quoted. The loop this row changes is `antseal-net`'s own
code (§1.1), so no upstream fact carries the ruling.

Before this record was written, the records lane re-read the load-bearing locators through
`git show 07a170c:<path>`, because round-1 lanes were starting to edit the tree. Every figure
below held, with three refinements:
- the default cap is upstream's `MAX_TRANSFERS_PER_TRANSACTION`, imported at
  `crates/antseal-net/src/ant_backend.rs:119` and documented as 256 at `:63` and `:306`; `:287`,
  P1's locator, is where the adapter assigns it as the default;
- the `S8` ANT reads are `crates/antseal-net/tests/devnet_backend.rs:558` and `:569`
  (`dev_wallet.balance_of_tokens()`); P1's `:556` is the section comment above them;
- P1 found *"upstream's loop"* in `pipeline/receipt_sink.rs`; `git grep` finds the wording at
  **seven** sites in `antseal-cli`, four calling the loop upstream's and three the hook type,
  which is `antseal-net`'s own (`ant_backend.rs:174`). §1.5 lists them.

## 1. What was measured

### 1.1 `antseal-net` owns the loop, runs it sequentially, and calls the hook synchronously

- **The external-signer flow is the adapter's.** `crates/antseal-net/src/ant_backend.rs:18`:
  *"`pay` | **external-signer flow**: per-sub-batch `payForQuotes` calldata …, signed and
  submitted over our own provider, each tx's receipt awaited"*. `Client::batch_pay` is
  forbidden (D37 Decision 3).
- **One iteration per sub-batch** (`:676`, `for (batch_index, batch) in
  sub_batches.iter().enumerate()`): build the calldata (`:693`), `send_transaction` (`:709`),
  await the receipt (`:719`), `finalize_ready_blobs` (`:799-806`), then `emit_capture` (`:807-813`).
  Only then does the next iteration submit.
- **The hook runs inline.** `emit_capture` (`:1616-1639`) calls `hook(&receipt);` (`:1638`) and
  returns `()`.

### 1.2 The hook cannot carry a verdict, and only one capture point has a successor

- **The type.** `ant_backend.rs:174`: `pub type CaptureHook = Arc<dyn Fn(&PaymentReceipt) + Send + Sync>;`
  It is `antseal-net`'s own type, re-exported only under `ant-backend`
  (`crates/antseal-net/src/lib.rs:121-122`). Its doc (`ant_backend.rs:167-173`) already promises
  that the hook runs *"strictly before the next sub-batch is submitted"*.
- **Three capture points.** `:735` (a landing not observed) and `:776` (a revert) are each
  followed by `return Err(StorageError::StrandedPayment { … })` (`:742`, `:783`), so a verdict
  is moot there. `:807` is the only capture followed by another submission, and the only site
  that needs the stop.

### 1.3 Who builds the hook, and who implements the sink

- **The production hook.** `crates/antseal-cli/src/backend.rs:1831-1833`
  `fn hook(receipts: Arc<dyn ReceiptSink>) -> CaptureHook`, whose body is
  `Arc::new(move |receipt: &PaymentReceipt| receipts.capture(receipt))` (`:1832`),
  installed by `SealBackend::connect` (`:1796`) and exposed to tests by `hook_for` (`:1825`). The
  only other hook is the `S7` closure at `devnet_backend.rs:707-711`.
- **The trait** is `backend.rs:1192`, with `fn capture(&self, receipt: &PaymentReceipt);` at
  `:1194`.
- **Five implementations:**
  - `VaultReceiptSink` — production; `backend.rs:1209-1213` delegates to
    `crates/antseal-cli/src/pipeline/receipt_sink.rs:400-437`;
  - `ReadOnly` — `backend.rs:1238-1245`; it logs `tracing::error!` and records nothing;
  - `Counting` — an in-crate test, `backend.rs:2606-2607`, under
    `#[cfg(feature = "ant-backend")]` (`:2596`);
  - `StallInPayAfter` — `crates/antseal-cli/tests/e2e_kill_resume.rs:313-334`;
  - `CapturedReceipts` — `crates/antseal-cli/tests/common/devnet.rs:298-305`.

### 1.4 The pipeline already turns a stranded payment with an unrecorded capture into 37

- `crates/antseal-cli/src/pipeline/resume.rs:500-517`: `Err(StorageError::StrandedPayment { … })`
  → `match self.journal.receipts_unrecorded()` → `Some(fault)` gives
  `SealError::PaymentUnrecorded`, `None` keeps the `StrandedPayment`.
- A failed capture sets that predicate (`receipt_sink.rs:257-260`,
  `self.unrecorded = Some(fault.clone());`), so a stop after a non-durable capture leaves exactly
  the state the predicate reads.
- 37's frozen Display (`crates/antseal-cli/src/error.rs:827-834`, *"… landed but the vault could
  not record all of them … everything the vault does not show as paid"*) stays true.

### 1.5 What the fix makes false or vacuous, in the code's docs and in two records

- **The variant's rustdoc.** `crates/antseal-net/src/error.rs:80-85`: *"(D37 Decision 3 — the
  partial quote→tx map is journaled *before* this error surfaces, so the evidence of money spent
  is never only in the error)"*. Decision 3 is the native fallback (`Wallet::pay_for_quotes`,
  D37:110-115), which the adapter does not drive. The field doc (`:92-93`), *"Sub-batch txs that
  landed (and were journaled) before the failure."*, is false in the same way. The Display
  (`:86-90`) is frozen by D147 §2 R11 and stays.
- **D37 Decision 7** (D37:349-357): *"`capture()` performs U9's atomic + fsync'd `put_receipt`
  **inline**, so the hook returns only once the receipt-so-far is on disk — and only then does
  the loop submit the next sub-batch."* On a failed write the hook returns and the loop submits
  anyway. `receipt_sink.rs:30-32` and `:391-395` repeat the sentence.
- **D186's heal.** §1.4 (D186:114-123): *"An earlier failed capture is therefore **healed** by
  any later durable one."* §1.8 (D186:166-174) credits option (iii), this row, with *"A healed
  run stays 28: yes"*. Test 2, `a_failed_capture_healed_by_a_later_capture_stays_payment_stranded`
  (`pipeline/resume.rs:1662`, script `(Some(2), |n| n == 1)` at `:1667`), runs through the test
  double `CapturesEachSubBatch` (`:1331`), which never stops. Once the loop stops at the first
  non-durable capture that has a successor, no later capture exists to heal it. The only heal
  left is the pipeline's own post-`pay` `put_receipt` after a failed **last** capture (D186
  §1.5; when that write fails too, D186 §2 R3's second point gives 37). Test 2 still reddens
  if the pipeline reads `fault()`, so it stays valid as a test of the pipeline's predicate
  choice; its input sequence is no longer one the loop produces.
- **"Upstream's" loop and hook, at seven sites** (`git grep` at `07a170c`): `backend.rs:1181`
  (the trait doc, *"The hook upstream accepts is …"*), `:1830` (`hook`'s doc), `:2595` (the
  `Counting` test's doc), `receipt_sink.rs:32` and `:394`, `tests/e2e_kill_resume.rs:326`, and
  `tests/seal_matrix.rs:167`. The type is `antseal-net`'s own (`ant_backend.rs:174`) and the
  loop is the adapter's (§1.1).

### 1.6 The reach, and the Accept's vehicle

- **Production reach is narrow.** The default cap is 256 transfers per transaction (§0), and
  there is *"one transfer per blob in the normal case"* (`ant_backend.rs:618-621`), so a second
  sub-batch needs a work with more than 256 non-zero transfers.
- **Devnet reaches it through forced caps.** `devnet_backend.rs:704-706`
  `with_max_transfers_per_tx(2)` over 5 blobs gives 3 transactions; `e2e_kill_resume.rs:129`
  `FORCED_CAP = 1` gives 5.
- **The vehicle.** The `S7` test `devnet_s7_multi_sub_batch_sequential_txs_with_capture_hook`
  (`devnet_backend.rs:689`), with the nonce read `wallet_nonce` (`:194`) and the ANT reads
  (`:558`, `:569`). The registry runs the whole `--test devnet_backend` target
  (`scripts/e2e-devnet.sh:90`), so a new test there needs no registry edit.
- **The sink's write-failure seam is out of a devnet harness's reach**: `fail_next_writes` is
  `#[cfg(test)] pub(crate)` (`receipt_sink.rs:386-389`). The devnet case therefore fails the
  **hook**, a closure at the adapter boundary.

### 1.7 The `S18` harness's lossy rows depend on the loop not stopping

- `StallInPayAfter` stalls only after `KILL_AFTER_SUB_BATCHES = 2` captures
  (`e2e_kill_resume.rs:125`, `:320-334`). In the lossy rows its inner sink is the in-memory
  `CapturedReceipts` (`observed`, the pipeline-direct row, `:529-532`) or `ReadOnly` (the CLI
  row, `:625-628`).
- If those answered not-durable, the loop would stop at capture 1, the stall would never come,
  and the child would reach `panic!("… the parent never killed it")` (`:583`, `:654`). The
  double's own comment (`:326-328`): letting the next submission happen *"would test a different
  scenario"*.
- Bare `CapturedReceipts` also drives multi-sub-batch rows (`S18` case 1b, `:897` onward, at
  `FORCED_CAP`).

### 1.8 Containment: `S20` and `S6`

- `S20` is a bump-PR rule (`tasks/S.md:312`: *"every proposed bump is a reviewed event that
  must confine code changes to the single adapter impl file"*); `S46` is not a bump.
- `S6`'s machine check (`scripts/ci-lanes.sh:678-734`) stays green: `S46` names no upstream
  symbol outside `ant_backend.rs`. The `StorageBackend` trait (`pay`'s signature) does not
  change.

### 1.9 The options

| Option | Transient write failure | Persistent write failure | D186 test 2 | Cost |
|---|---|---|---|---|
| Today | 0 lost (the next capture heals it) | **every remaining sub-batch** paid unrecorded | reachable | none |
| **A.** Stop at the first non-durable capture when sub-batches remain (**ruled**) | 1 sub-batch re-paid on resume | **1** | a predicate-input test; D186 addendum | M |
| **B.** A, plus one in-sink retry of a `Write` fault | usually 0 | 1 | stays reachable | M+: a new retry-policy surface; D186 test 1's injection (`fail_next_writes(1)` per capture) would be healed by the retry and flip from 37 to 28; and retrying a just-failed fsync'd write is not obviously meaningful |

## 2. RULING

### §2 R1 — One ungated outcome type, returned by the hook and by both sinks

`pub enum CaptureOutcome { Durable, NotDurable }` lives in `antseal_net::receipt`, the ungated
module that already hosts `PaymentReceipt` (`crates/antseal-net/src/lib.rs:106`), and is
re-exported unconditionally from `lib.rs`. It is **not** `#[must_use]`.
- `CaptureHook` becomes `Arc<dyn Fn(&PaymentReceipt) -> CaptureOutcome + Send + Sync>`.
- `ReceiptSink::capture` and `VaultReceiptSink::capture` return it: `Durable` exactly where the
  sink records durability (`state.durable()`, `receipt_sink.rs:432`), `NotDurable` on every
  `not_durable` path.

*Why:* ungated, so that the default lane compiles and tests the sink's verdict, where the sink
itself already lives (`backend.rs:1201-1208`). Not `#[must_use]`, so the 15 existing ungated
`VaultReceiptSink::capture` call sites in tests need no edit (`git grep -n '\.capture(&' 07a170c
-- crates/antseal-cli` finds 16, the 16th being `ReadOnly`'s at `backend.rs:2635`).

### §2 R2 — The loop stops before the next sub-batch after a non-durable capture

At `ant_backend.rs:807`, `emit_capture` returns `Option<CaptureOutcome>`. When it returns
`Some(NotDurable)` and sub-batches remain, `pay` returns
`StorageError::StrandedPayment { landed_tx_count: <the confirmed count>, reason }`, counting
confirmed transactions as the other two returns do (`:742-746`, `:783-787`). The reason (P1's
text; it appears inside 37's `({detail})`): *"the receipt-so-far could not be journaled after
sub-batch {k} of {n} landed, so no further sub-batch was submitted (D37 Decision 2)"*.
- **A non-durable capture of the last sub-batch stops nothing.** `pay` returns `Ok`, and the
  pipeline's own post-`pay` `put_receipt` is the second chance (D186 §1.5; D186 §2 R3's second
  point when it fails too).
- **`None` is not a verdict.** Only an `AntCoreBackend` built without `with_capture_hook` has no
  hook, and `SealBackend::connect` always installs one (`backend.rs:1796`).
- **The pipeline is unchanged.** D186's predicate already maps this return to class 37 (§1.4).

*Why:* `:807` is the only capture point with a successor (§1.2), and D37 Decision 2's bound is
*"at most the one tx currently inside the pay→journal atomicity window"* (D37:106-108). Stopping
there is what makes that bound hold when the journal write fails.

### §2 R3 — The non-production sinks answer by design

- `ReadOnly` → `NotDurable`. It records nothing, so a payment through it now stops after one
  sub-batch, which bounds the bug its own log line names.
- `CapturedReceipts` and `Counting` → `Durable`. They are in-memory doubles; durability is the
  vault sink's to report.
- `StallInPayAfter` → `Durable`, unconditionally, after delegating.

*Why:* the `S18` lossy rows deliberately emulate a non-durable sink with the loop running on
(§1.7). Their experiment is the stall; a stop before it would *"test a different scenario"*
(`e2e_kill_resume.rs:326-328`).

### §2 R4 — The rustdoc tells the truth about durability

- **`crates/antseal-net/src/error.rs:80-85`** (P1's text; the lane may tighten it): *"Payment
  failed **mid-sequence with money already moved**: one or more sub-batch txs landed before the
  failure. The adapter hands the partial quote→tx map to its capture hook before this error
  surfaces (D37 Decisions 2 and 7), but **whether that record became durable is the hook's to
  report, not this error's**: when the latest capture was not durable, the evidence of money
  spent may exist only on-chain, and `antseal-cli` surfaces that case as `payment-unrecorded`
  (exit 37, D186), not as this variant's own class. The loop also returns this variant when a
  capture reports not-durable, before submitting the next sub-batch (S46), so at most one
  sub-batch can be paid unrecorded. Resume treats journaled mapped quotes as paid and pays only
  the remainder. Carries counts, not hashes (hygiene)."*
- **The field doc, `:92-93`:** *"Sub-batch txs that landed before the failure — journaled only
  as far as the latest durable capture reached."*
- **The `CaptureHook` doc** (`ant_backend.rs:167-173`) gains the return contract; the
  **`ReceiptSink` trait doc** (`backend.rs:1179-1191`) and the **`receipt_sink.rs` docs**
  (`:30-32`, `:391-399`) say *"the adapter's loop"* and state the stop.
- **The Display (`error.rs:86-90`) is untouched**, by D147 §2 R11.

*Why:* the rustdoc cites Decision 3, which governs a flow the adapter does not drive, and claims
a durability that is the hook's to report (§1.5).

### §2 R5 — Records

- **D37** takes a dated addendum: Decision 7's *"only then does the loop submit the next
  sub-batch"* now holds on a failed write too, and Decision 2's bound holds under a failing sink.
- **D186** takes a dated addendum: §1.4's mid-payment heal is no longer produced by the loop;
  R1's predicate is unchanged and still right; test 2 is kept as a pipeline predicate-input test,
  and its double's rustdoc says so.

### §2 R6 — A retry inside the sink is refused

Option B (§1.9) is refused without a measured transient-failure case. It would add a retry-policy
surface and change the seam's meaning (D186 test 1 would flip from 37 to 28), and retrying a
just-failed fsync'd write is not obviously meaningful.

### What no ruling here moves

- **No exit code is minted**, and no class is added: 37 and 28 are reused, and
  `PINNED_CLASS_COUNT` stays 36 (`crates/antseal-cli/tests/namespace_disjointness.rs:85`).
- **No Display template changes.** The new reason is a value inside 37's `({detail})`, and the
  37 row of `cli-errors.display.txt` is built from a hand-written fault and detail in
  `tests/exit_codes.rs`, so it does not move.
- **No `--json` key, no help text, no config key.** `S46` touches no `U32`-frozen surface.
- **Untouched:** `pipeline/resume.rs`'s production code, `vault_journal.rs`, `seal_run.rs`,
  `commands.rs`, the `StorageBackend` trait and `MockBackend`.
- **The gate:** this is the payment loop, so the close gate runs with the heavy tier and the
  devnet E2E forced (`ANTSEAL_GATE_HEAVY=1 ANTSEAL_GATE_E2E=1`), and the Accept's only venue is
  the e2e-devnet lane.

## 3. Fault plants

The implementing lane owes these. The red baselines come first, on the unedited tree; each plant
is judged by its **message**; every restore is followed by a `touch`. Every `ant-backend` build
and test runs in a shadow copy with a private `CARGO_TARGET_DIR`; the devnet cases run against a
local devnet that the lane brings down when it is done.

**The green tests — the load-bearing half**

- **G1 — devnet, the Accept** (`devnet_backend.rs`, a new test modelled on the `S7` test at
  `:689`). Cap 2 over 5 blobs, so 3 sub-batches; the hook answers `Durable` for capture 1 and
  `NotDurable` for capture 2, recording both. ANT is read with `balance_of_tokens()` and the
  nonce with `wallet_nonce`. Assert:
  - `pay` returns `Err(StrandedPayment { landed_tx_count: 2, .. })`;
  - `captures.len() == 2`;
  - the nonce rose by **3** (the approval and two sub-batches), not 4;
  - `ant_before − ant_after == captures[1].storage_cost_atto`;
  - `captures[1].storage_cost_atto − captures[0].storage_cost_atto` equals sub-batch 2's
    transfers. That is the Accept's *"the on-chain delta equals the receipt plus one
    sub-batch"*, with `captures[0]` the last durable receipt.

  **Red baseline:** `Ok` after 3 transactions, nonce + 4.
- **G1b — devnet.** A hook that fails only the **last** capture: `pay` is `Ok`, with 3
  transactions.
- **G2 — heavy tier, in-crate.** `the_installed_hook_delivers_receipts_to_its_sink`
  (`backend.rs:2598`) is extended so the hook **returns** the sink's verdict: `Durable` from
  `Counting`, `NotDurable` from a second double, and a `ReadOnly` row (cheap; recommended).
- **G3 — default lane.** The `receipt_sink.rs` unit tests assert that `capture` returns
  `Durable` on a durable write (`a_capture_is_durable_by_the_time_it_returns`, `:557`),
  `NotDurable` on an injected `fail_next_writes(1)` (`a_failed_write_records_a_fault_and_never_panics`,
  `:716`), and `NotDurable` when the sink is not armed
  (`an_unarmed_capture_is_recorded_as_a_fault_not_swallowed`, `:673`).
- **G4.** D186's tests 1–4 stay green unchanged: the pipeline is untouched.

**The plants — proof that those tests can fail**

| Plant | Must redden |
|---|---|
| the stop check removed from the loop | G1 (`Ok`, nonce + 4) |
| the stop condition also fires after the last sub-batch (`<=`) | G1b (`Err` where `Ok` with 3 transactions is expected) |
| `hook` drops the verdict (always `Durable`) | G2 |
| `VaultReceiptSink::capture` returns `Durable` before writing | G3 (`:716`) |
| `ReadOnly` returns `Durable` | G2's `ReadOnly` row |

## 4. What this record does NOT decide

- **A retry inside the sink.** Refused (R6) until a transient write failure is measured; that
  measurement is the condition for reopening it.
- **An end-to-end devnet witness through the real sink's failing write.** Not built: the sink's
  failure seam is `#[cfg(test)]` (§1.6). The chain is witnessed link by link instead — the
  sink's verdict (G3), the hook's forwarding (G2), the loop's stop (G1, G1b) and the pipeline's
  mapping to 37 (G4).
- **The user page.** `docs/user/funding-your-wallet.md`'s money-moved section (its 37 block
  starts at `:258`) could say that the loss is now bounded to one sub-batch. Optional, not
  ruled, and no lane carries it this wave.
- **The net Display** (`crates/antseal-net/src/error.rs:86-90`). Untouched: D147 §2 R11 governs,
  as D186 §6 already recorded.
- **"Upstream's" at the sites R4 does not name.** `backend.rs:1830`, `:2595` and
  `tests/e2e_kill_resume.rs:326` lie inside L-NET2's regions (§5); `tests/seal_matrix.rs:167`
  lies in no lane's scope this wave. Recorded here (§1.5), not ruled.
- **Rebuilding a lost receipt from the wallet's on-chain transactions.** Still not explored
  (D186 §4).
- **`S47`.** Ruled without a record this wave: the registrar amends its row to cover
  `ErrContext::Get` as well, and D191 takes a dated addendum.
- **New rows.** This record mints none. P1's instrument findings (its report's §3: the stale
  `:1163` and `:1161` locators, D186 §1.8's vacuous cell, D37 Decision 7's overclaim) are the
  orchestrator's to record.

## 5. Edit list — per write scope, with the lane named before this record was written

### L-NET2 (round 1) — `S47` first, then this record

- `crates/antseal-net/src/receipt.rs`: `CaptureOutcome` (R1); `crates/antseal-net/src/lib.rs`:
  its unconditional re-export only.
- `crates/antseal-net/src/ant_backend.rs`: the `CaptureHook` type and doc (`:166-174`), the
  `with_capture_hook` doc (`:293-297`), `emit_capture` (`:1614-1639`) returning
  `Option<CaptureOutcome>`, and the loop tail (`:796-813`) (R1, R2, R4).
- `crates/antseal-net/src/error.rs`: only the `StrandedPayment` rustdoc (`:80-85`) and its field
  doc (`:92-93`) (R4). Not `:140-143`, which is L-VOCAB2's in round 2 (D199).
- `crates/antseal-net/tests/devnet_backend.rs`: the `S7` closure returns `Durable`
  (`:707-711`); G1 and G1b.
- `crates/antseal-cli/src/backend.rs`, only these regions: the `ReceiptSink` trait and its doc
  (`:1179-1195`); the `VaultReceiptSink` impl (`:1209-1213`); the `ReadOnly` impl
  (`:1238-1245`); `hook` (`:1825-1833`); the `Counting` test (`:2596-2625`, G2). `S47`'s
  regions in the same file are `degrade`'s comment and its test.
- `crates/antseal-cli/src/pipeline/receipt_sink.rs`: `capture` (`:400-437`) returns the outcome;
  the module and method docs (R4); G3.
- `crates/antseal-cli/src/pipeline/resume.rs`, its test module only: the `CapturesEachSubBatch`
  doc (`:1331`) says that it models the pipeline's predicate inputs, including the pre-`S46`
  heal sequence (R5).
- `crates/antseal-cli/tests/common/devnet.rs` (`CapturedReceipts`, `:298-305`) and
  `crates/antseal-cli/tests/e2e_kill_resume.rs` (`StallInPayAfter`, `:313-334`, and its doc)
  (R3).
- Not this lane's: any other `backend.rs` region, `seal_run.rs`, `seal_resume.rs`,
  `vault_journal.rs`, `journal.rs`, `commands.rs`, `verify_host.rs`, `docs/**`.
- Every `ant-backend` build and test runs in a shadow copy with a private target directory and
  `CARGO_BUILD_JOBS=1`; the devnet cases run against `scripts/devnet/local-up --nodes 14`,
  followed by `scripts/devnet/local-down`. The close gate runs with
  `ANTSEAL_GATE_HEAVY=1 ANTSEAL_GATE_E2E=1`.

### L-VOCAB2 (round 2, after L-NET2) — two shared files

`crates/antseal-net/src/error.rs:140-142` (D199's rewritten sentence) and `backend.rs`'s
`UnreachableBackend` region are L-VOCAB2's: disjoint hunks from this record's, edited after
L-NET2's have landed.

### RECORDS-B — dated addenda

- **D37:** Decision 7's ordering now holds on a failed write; Decision 2's bound holds under a
  failing sink (R5).
- **D186:** §1.4's mid-payment heal is no longer produced by the loop; §1.8's *"A healed run
  stays 28: yes"* cell is vacuous under the fix; R1's predicate is unchanged; test 2's role
  (R5).

### Orchestrator — `TODO.md`, `tasks/S.md`, `docs/decisions/README.md`, `docs/instrument-ledger.md`

- `S46`: its tick, against §3; the Accept's only venue is the e2e-devnet lane.
- This record's index row and register row.
- P1's instrument findings (its report's §3).

## 6. As built — wave 39, lane L-NET2 (recorded in place before this record was first committed)

Every verdict below was read from an exit file, per the lane's report, and every red was judged by
its message. Every `ant-backend` build and test ran in a shadow copy with a private target; the
default-feature runs went through the shared tree under the lock protocol.

- **`S47` first, for context (ruled without a record).** `map_ant_error`
  (`crates/antseal-net/src/ant_backend.rs:1761`) matches `Payment` and `AlreadyStored` per context
  with no `_` arm. A connect- or fetch-time error is `Network`, in P1's four texts; quote and
  finalize are byte-unchanged. At `HEAD` its G1 was red on 4 of 4 combinations (*"Connect +
  Payment: expected Network, got Quote { … }"*), and its three plants were red by message.
  - **Deviation:** `degrade`'s comment says *"every connect error is `Network`"*, which is broader
    than P1's wording. The lane measured it over all five production producers, and the comment
    stays at five lines. The row label is now *"a variant no production connect produces (S47);
    the arm stays total"* (`crates/antseal-cli/src/backend.rs:2371`), and `kinds.len() == 5` stays.
- **§2 R1 (`S46`).** `pub enum CaptureOutcome { Durable, NotDurable }` is at
  `crates/antseal-net/src/receipt.rs:333`, ungated and not `#[must_use]`, and `lib.rs:146-149`
  re-exports it unconditionally. `CaptureHook` is now `Arc<dyn Fn(&PaymentReceipt) ->
  CaptureOutcome + Send + Sync>` (`ant_backend.rs:174`). `ReceiptSink::capture` returns the outcome
  (`backend.rs:1209`), and `hook` forwards it (`:1848-1850`).
  - **Deviation: the verdict is structural.** `SinkState::not_durable()` and `durable()` return it
    (`crates/antseal-cli/src/pipeline/receipt_sink.rs:260`, `:270`). The answer and S37's predicate
    therefore come from one place, and R1's *"`Durable` exactly where the sink records durability"*
    holds by construction.
- **§2 R2.** `emit_capture` returns `Option<CaptureOutcome>`, and `None` (no hook) is no verdict
  (`ant_backend.rs:1633-1642`). The loop tail returns `StrandedPayment` when
  `captured == Some(CaptureOutcome::NotDurable) && batch_index + 1 < sub_batches.len()` (`:819`).
  It counts confirmed transactions and uses P1's reason verbatim: *"the receipt-so-far could not be
  journaled after sub-batch {k} of {n} landed, so no further sub-batch was submitted (D37 Decision
  2)"*. The pipeline is unchanged: the lane re-read `resume.rs:500-517`, where this return with
  `receipts_unrecorded()` set is `PaymentUnrecorded` (37).
- **§2 R3.** `ReadOnly` answers `NotDurable` (`backend.rs:1256-1262`). Its doc now says that *"such
  a payment submits no sub-batch after its first (S46)"*. Two doubles answer `Durable`:
  - `CapturedReceipts` (`crates/antseal-cli/tests/common/devnet.rs:299-308`);
  - `StallInPayAfter` (`crates/antseal-cli/tests/e2e_kill_resume.rs:314-340`). It delegates first,
    and its doc says why: forwarding the lossy rows' not-durable answer *"would stop the payment at
    capture 1, before the stall"*.
- **§2 R4.** The `StrandedPayment` rustdoc (`crates/antseal-net/src/error.rs:80-91`) is P1's text
  verbatim, and its field doc (`:98-99`) is the ruled sentence. The Display is untouched.
  - The `CaptureHook`, `ReceiptSink`, `hook` and `receipt_sink.rs` docs say *"the adapter's loop"*
    and state the stop.
  - All seven *"upstream's loop/hook"* sites are fixed. A filter for that wording finds 0 hits in
    `backend.rs`, `receipt_sink.rs`, `e2e_kill_resume.rs` and `seal_matrix.rs`, against 4 in
    `HEAD`'s `receipt_sink.rs`.
  - **Deviation: the `CaptureHook` doc was false before this wave.** It said the hook is invoked
    *"once more with the final receipt"*, but only `emit_capture` calls the hook, and S7 asserts 3
    captures for 3 transactions. The doc now says that the last payload equals the receipt `pay`
    returns (`ant_backend.rs:167-173`).
  - **Deviation (scope):** `tests/seal_matrix.rs:167` was in no lane's scope (§4). It was fixed
    under the orchestrator's one-comment extension. Three more sentences of the same class in
    `receipt_sink.rs` were fixed as well. `with_capture_hook`'s doc was left as it was, because it
    is still true.
- **§2 R5, the code half.** `CapturesEachSubBatch`'s doc
  (`crates/antseal-cli/src/pipeline/resume.rs:1332`) now opens *"A predicate-input double, not the
  adapter's loop (S46, D198)"*. It says that a failed capture healed by a later one is a sequence
  `pay` cannot produce. The records half is RECORDS-B's: D37 and D186 carry dated addenda.
- **§2 R6.** No retry was added.
- **§3, the green tests.**
  - **G1** is `devnet_s46_a_not_durable_capture_stops_the_next_sub_batch`
    (`crates/antseal-net/tests/devnet_backend.rs:1400`). It holds:
    - `StrandedPayment { landed_tx_count: 2 }`, *"after sub-batch 2 of 3 landed"*;
    - 2 captures, and the nonce up by 3, not 4;
    - capture 2 = capture 1 + sub-batch 2, with a positive control that sub-batch 2 moved ANT;
    - the Accept: *"the on-chain ANT delta is the durable receipt plus one sub-batch"*.
  - **G1b** is `devnet_s46_a_not_durable_last_capture_stops_nothing` (`:1505`): `pay` is `Ok` after
    3 transactions. The `S7` closure answers `Durable` (`:714`).
  - **G2**, `the_installed_hook_delivers_receipts_to_its_sink` (`backend.rs:2618`), keeps its name.
    It asserts `Durable` from `Counting`, `NotDurable` from a second double, and `ReadOnly`'s
    answer both directly and through the hook. **Deviation:** its old closing comment contradicted
    `ReadOnly`'s own doc, so it was replaced.
  - **G3** asserts the verdict in four `receipt_sink.rs` tests (`:568`, `:688`, `:735`, `:765`).
    **Deviation:** P1 placed the injected `fail_next_writes(1)` at `:716`. That test is the real
    store failure; the injected sequence is
    `the_predicate_follows_the_latest_capture_and_the_fault_keeps_the_first`.
  - **G4:** D186's five `s37::*` tests are unchanged and green.
- **The devnet session.** A 14-node devnet was booted from the shadow and was ready in 9 s. It was
  torn down by the unmodified `local-down` under a trap (exit 0, no residue). The user's upstream
  `client_adaptive.json` kept its inode and mtime. The test clients wrote theirs under the
  shadow's target instead, which is the positive control.
  - **G1's red baseline** is P46-1, the stop check removed, at exit 101: *"S46: a not-durable
    capture of sub-batch 2 of 3 must stop the payment with StrandedPayment { landed_tx_count: 2 } —
    pay → Ok with 3 tx(s); 3 capture(s); nonce +4"*. That is the ruled baseline.
  - **G1 and G1b**, `cargo test -p antseal-net --features ant-backend --locked --test
    devnet_backend -- devnet_s46`: exit 0, *"2 passed; 0 failed; … 8 filtered out"*.
  - **P46-2** (`<=`), exit 101 on G1b: *"… must not stop pay — pay → Err(payment stranded
    mid-sequence: 3 sub-batch transaction(s) landed …"*.
  - **The whole `devnet_backend` target**, unfiltered: exit 0, *"10 passed; 0 failed; 0 ignored;
    0 measured; 0 filtered out; finished in 128.93s"*. `S7`'s nonce + 4 still held after G1 ran.
  - **Deviation: G1 pays from a throwaway wallet funded from the dev wallet** (`S8`'s pattern).
    `allowance_to_approve` skips the approval when the allowance covers the total. A stopped
    payment's unspent allowance on the shared wallet could shift a later test's nonce arithmetic.
  - **Deviation: the devnet ran from a prebuilt launcher.** From the shadow, `local-up` means a
    cold release build under load. So the lane copied in the main tree's launcher
    (sha256-identical) and replaced only that build line with an existence check. No commit had
    touched the launcher's closure since 2026-10-16. The plant runs executed their saved binaries
    with cargo's `[env]` reproduced (D178 R3). The green runs used `cargo test`.
- **Plants: five for `S46`, every one red by message.**
  - P46-1 and P46-2 are as above, as distinct saved binaries.
  - P46-3 (`hook` drops the verdict) reddened G2: *"the hook forwards a not-durable verdict instead
    of replacing it"*.
  - P46-4 (the vault sink answers `Durable` on a failed write) reddened G3: *"a failed write answers
    NotDurable (S46)"*.
  - P46-5 (`ReadOnly` answers `Durable`) reddened G2: *"the read-only sink journals nothing"*.
  - **Deviation: two plant runs were combined:** P47-1 with P47-3, and P46-3 with P46-4. In each
    pair the plants redden different tests through disjoint code, and each message names its own
    plant.
  - P46-3's first build failed to compile (`error[E0433]`). That exit 101 came from rustc. It was
    caught by its message and not counted.
  - Restore: the finals were reinstalled and sha256-verified, and
    `git grep --untracked -n W39-PLANT` exits 1.
- **At the lane's close.**
  - Shadow, `ant-backend`, `--lib`: `antseal-net` passed 140. `antseal-cli` passed 33, filtered to
    `backend` and the receipt-sink and resume tests.
  - Shared tree, default features: `antseal-cli --lib` passed 324, and `seal_matrix` 15.
    `cargo test -p antseal-net` was all ok.
  - `clippy -- -D warnings` exited 0 four times: both crates, with `ant-backend` in the shadow and
    with default features in the shared tree. All eleven files pass `rustfmt --check`.
- **The tree, re-read for this section.** Nine of the eleven files match the lane's final hashes.
  `error.rs` and `backend.rs` differ only by D199's round-2 hunks, which lie outside L-NET2's
  regions: `error.rs:146-153`, and three doc hunks in `backend.rs` — two in `UnreachableBackend`'s
  docs, and one in `degrade`'s rustdoc, apart from `S47`'s comment in its body (`:784`).
- **Left open.**
  - **The live suites.** `S17`, `S18` and `S19` did not run on a devnet in the lane, because their
    doubles changed only to answer `Durable`, the pre-`S46` behaviour. The close gate runs the live
    suites with the heavy tier and the devnet E2E forced, and its e2e-devnet lane is the Accept's
    only venue (§2). `S46`'s tick is the orchestrator's (§5).
  - **Found, minted as rows: `S49` and `S50`.**
    - `S49`: after a sub-batch lands, a proof-construction failure in `finalize_ready_blobs`
      propagates before `emit_capture`. That sub-batch's capture is skipped, and the class says no
      money moved. It is unreachable at the pin, and the row guards an ant-core bump.
    - `S50`: a revert of the first sub-batch returns `StrandedPayment { landed_tx_count: 0 }`,
      whose doc and Display say money moved.

    `S49` and `S50` own them.
  - **`L-LOC` owns three findings:**
    - `docs/user/funding-your-wallet.md:193` cites `ant_backend.rs:293-296` for the 256-transfer
      cap. It was stale before this wave.
    - `journal.rs:722` still calls the hook *"a `Fn(&PaymentReceipt)`"*.
    - Living docs quote the `S6`–`S8` suite as 8 tests, but it now runs 10.
  - **A green that cannot fail without a devnet.** Without `ANTSEAL_DEVNET_ENV`, `devnet_backend`
    reports 10 passed in 0.02 s, on its SKIP path. So the heavy tier's count for that target is not
    devnet evidence; only the e2e-devnet lane is.

## Closing — this record is not consent

It changes the capture hook's type, what the payment loop does after a capture that did not
become durable, and two rustdoc paragraphs, inside the wave's own commits. Nothing in it
authorises a push, a workflow dispatch, a deploy or any other outward act; each of those needs
the maintainer's express consent naming the action, the destination and the account.

## Addendum — 2026-10-20 (D204 §2 R1–R3): the stop now lives in `settle_sub_batch`, and §6's `S49` and `S50` are answered

- **Where §2 R2's stop lives.** §2 R2 put the stop in the loop's tail (`ant_backend.rs:807` and
  `:819` at the time). D204 §2 R1 moves the decision taken after each awaited sub-batch receipt —
  the revert branch, the finalize result, the capture and this stop — into one pure function,
  `settle_sub_batch` (the implementing lane names it), which the loop calls after every awaited
  receipt. The stop moves unchanged: mid-sequence, a capture answered `NotDurable` returns
  `StrandedPayment` with §2 R2's reason, and after the last sub-batch it stops nothing. G1
  (`devnet_s46_a_not_durable_capture_stops_the_next_sub_batch`) and G1b stay the devnet witnesses
  and now also witness that the loop calls the seam. A new in-crate test (D204 §3, G46-u) covers
  the stop directly, which until now only the devnet did.
- **§6's `S49` is answered by D204 §2 R2.** A proof failure after a landing now delivers the
  capture of what exists — the landed sub-batch's quote→tx map, its tx record, the gas, and the
  records already built — and then returns `StrandedPayment`. The class and the journal agree
  that money moved, and the capture's verdict reaches D186's 28/37 split (§1.4). The pre-pass
  before any sub-batch keeps `Payment`.
- **§6's `S50` is answered by D204 §2 R3.** A revert with no confirmed landing in the same `pay`
  call returns `Payment` and delivers no capture; a revert after a landing keeps its capture and
  `StrandedPayment` with the unchanged reason. Of the two returns §2 R2 cites as counting
  confirmed transactions (`:742-746` and `:783-787` then), the unobserved landing is unchanged and
  the revert's now applies only after a landing.
- **The rustdoc §2 R4 wrote gains one sentence** (D204 §2 R4): *"A revert reports at least one
  landing (S50); only an unobserved first landing reports 0, because there money may have
  moved."* The Display stays untouched, as §2 R4 and §4 recorded; D204 rewords `Payment`'s Display
  only, superseding D147 §2 R11 for that one string.

The text above is history and stays as written.
