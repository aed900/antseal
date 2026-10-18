# D186 — A payment the vault could not record is **its own class**, `payment-unrecorded`, **exit 37**: it fires only when the **most recent** receipt capture did not become durable, 28's frozen line stays, and 28's contract narrows to the recorded case

- **Status: RESOLVED. H3 fell on its premise (a).** H3 read: *not* a new
  `SealError` class — carry the sink's fault as a field or sentence on the
  existing `StrandedPayment` error, so there is no error-universe event and no
  new exit code. Each premise was measured and none held:
  - **"No error-universe event."** There was never one to avoid. The Q52
    universe is antseal-core's roster (`antseal-core/src/error_universe.rs`);
    `SealError` and `CliError` are not in it. S37's *"error-universe event
    (194)"* (`TODO.md:531`) is a misattribution: 194 was that universe's
    committed snapshot count before A38/A52 took the roster from eight
    enumerators to eleven and the snapshot to 246 codes
    (`antseal-core/src/anchor/error.rs:528-530`). The CLI's classes never
    entered it.
  - **"A sentence on `StrandedPayment` is enough."** 28's documented contract
    tells scripts to branch on the code and promises that re-running is safe
    (§1.6). A sentence cannot reach a script's branch: a script that obeys the
    documentation re-runs with `--yes` and pays twice. D147 split 28 from 23
    for exactly this reason (`error.rs:689-691`, *"a caller retrying this the
    way it retries a peer timeout spends against a wallet that has already
    paid"*).
  - **"The harm lives on `StrandedPayment`."** The likelier case — `pay`
    succeeds, then the last capture **and** the post-pay `put_receipt` both
    fail — never produces it. It exits **4**, and the text never mentions
    money (§1.5).
  - **The row's question does not dissolve.** The harm is real: with the
    receipt lost, resume re-quotes and re-pays everything the vault does not
    show as paid (§1.3).
  - **The slot the row names answers the wrong question.** The sink's fault
    slot is first-fault-wins, so a run whose early capture failed and a later
    one healed would fire the new class. The predicate S37 needs is *"the most
    recent capture did not become durable"*, which the sink does not track
    today (§1.4).
- **Date: 2026-10-17**
- Owner row: **`S37`** (§2 R1–R7). Minted with this record, **not** this wave:
  **`S46`** (§4).
- Related:
  - **D37** (Decision 2's one-transaction loss bound, D37:102-109; S37's
    origin, D37:448-453);
  - **D147** (28 and 29, the money-moved pair; takes a dated addendum: the pair
    becomes a trio);
  - **D69** §5 (the "first free code" placement precedent, D69:99-101);
  - **D134** §2 R3(1) (the table is append-only; 44–49 reserved);
  - **D65** (`error.message` is human copy at every tier);
  - **`S31`** (the receipt sink), **`S16`** (the receipt, not the tag, is the
    money authority), **`S11`**.

## 0. What was measured against

`HEAD` `23f3093` (local `main`; `origin/main` = `cfd5868`). The tree was clean
when planning began.

Planning lane P1 (wave 38, 2026-10-17) worked read-only and ran no cargo build
or test; every claim below was read from code and docs with the line quoted.
Lane PS supplied the exit-code map (which codes are used, free and reserved).

Before this record was written, the records lane re-read every locator below at
`HEAD` through `git show 23f3093:<path>`, because implementing lanes had already
begun editing `crates/antseal-cli/src/error.rs` and
`crates/antseal-cli/tests/exit_codes.rs` in the shared tree. Every citation
held, with two locator refinements: the CLI's `ReceiptSink` trait is at
`crates/antseal-cli/src/backend.rs:1161` (P1 wrote `:1163`), and D37's S37
paragraph is at D37:448-453 (P1 wrote `:447-452`).

## 1. What was measured

### 1.1 The slot, and who reads it

`VaultReceiptSink::fault()` (`pipeline/receipt_sink.rs:318`) has no production
reader. Every call is a test: the sink's own module tests (`:498` onward),
`pipeline/resume.rs:903` and `:1071` (inside `mod tests`, which opens at
`:640`), `seal_session.rs:277`, `tests/e2e_kill_resume.rs:1211` and `:1500`,
and `tests/seal_matrix.rs:656`.

A capture that fails is stored and logged: `SinkState::note`
(`receipt_sink.rs:224-231`) emits `tracing::error!` and keeps the **first**
fault — *"the earliest failure is the one that explains the rest, and a later
success must not erase it"*. `ReceiptSinkFault` carries *"no receipt content and
no key material"* (`:163-164`). Its `Rearmed` arm still writes: *"The new target
wins, so the receipt in flight is still written"* (`:172-175`).

### 1.2 The error chain, and 28's frozen text

`StorageError::StrandedPayment { landed_tx_count, reason }`
(`antseal-net/src/error.rs:80-97`, *"Carries counts, not hashes (hygiene)"*,
`:85`) → `SealError::Storage` → `storage_to_cli` (`pipeline/error.rs:340-346`)
→ `CliError::PaymentStranded` (`error.rs:689-705`) → class `payment-stranded`,
exit 28 (`error.rs:420`). The Display (`error.rs:692-698`), frozen at
`cli-errors.display.txt:89-90`:

> payment stranded mid-sequence: {landed_tx_count} sub-batch transaction(s)
> landed before the failure and the journaled partial receipt is
> authoritative — this is not a transient network failure and money has already
> moved: re-run `antseal seal` with the same files and the same seal-shaping
> flags to finish it, which re-pays no quote the receipt already maps;
> `antseal list` prints the exact command ({detail})

### 1.3 The harm is real: with the receipt lost, resume pays again

- Resume decides "money moved" from the journaled receipt alone:
  `let journaled_receipt = self.journal.receipt(seal_id)?;` (`resume.rs:180`)
  and `if journaled_receipt.is_none() && !state.is_post_pay() {` (`:184`). That
  branch re-quotes the blobs (`self.backend.quote_batch(&blobs)`, `:194`) and
  pays through `consent_anchor_pay`.
- `resume.rs:218-222`: *"The already-paid quote hashes cannot be recovered by
  re-deriving them: a fresh quote round mints fresh hashes. The durable receipt
  is the only thing that can say what was already bought, which is the whole
  reason it has to be durable."*
- Nothing else recovers a lost receipt: `pipeline/receipt_backfill.rs` fills
  `TxRecord::block_number` on an **existing** receipt (D33's enrichment slot),
  and the error carries counts only. The
  re-consent prompt fires again, but `--yes` consents in advance.

### 1.4 First-fault-wins answers the wrong question

Captures are cumulative: capture `k` writes `prior + (sub-batches 1..=k)`
(`receipt_sink.rs:141-145`). The backend captures after every landing,
including the last (`antseal-net/src/ant_backend.rs:807`), and again just
before each stranded return (`:735`, `:776`). An earlier failed capture is
therefore **healed** by any later durable one. A predicate built on `fault()`
would fire on a healed run, where the receipt on disk is complete. The question
S37 needs answered is whether the **most recent** capture became durable, and
the sink does not track it.

### 1.5 Case B: `pay` succeeds and the record is still lost

When `pay` returns `Ok`, the pipeline writes the complete receipt itself:
`self.journal.put_receipt(seal_id, &receipt)?;` (`resume.rs:505`, after `pay` at
`:488`). If the sink's last capture failed **and** this write fails — the same
store on the same disk, milliseconds apart (disk full, device gone) — the error
travels `JournalError::Store` (`journal.rs:703`) → `CliError::Io`, *"work store
access at {path}"* (`vault/store.rs:305-308`), exit **4**. A re-run then
re-pays every sub-batch the vault does not show as paid: the whole seal when no
capture of this `pay` reached disk. S37's Accept 2 calls this case moot
(*"changes nothing (the complete receipt is durable regardless)"*); it is not.

### 1.6 Five places promise that 28 is safe to re-run

- `error.rs:38` (the table row): *"re-running `seal` finishes it and re-pays no
  quote the journaled receipt already maps"*.
- `error.rs:60-63`: *"28 is finished by re-running `antseal seal` on the same
  inputs (the journaled partial receipt is authoritative, so no mapped quote is
  re-paid)"*.
- `docs/user/funding-your-wallet.md:264-269` (*"**28 is finishable, and
  re-running is how you finish it.**"*) and `:280-282` (*"**Branch on the code,
  never on "something failed".** … Use the exit code, or `error.class` under
  `--json`."*).
- The CLI Display (§1.2).
- The net Display, `antseal-net/src/error.rs:86-90`: *"the journaled partial
  receipt is authoritative — resume will not re-pay mapped quotes"*.

Each is false for a payment whose receipt the vault could not record.

### 1.7 Codes

- `ErrorClass::ALL` is `[ErrorClass; 35]` (`error.rs:351`); the pin is
  `tests/exit_codes.rs:36`, and `codes_are_nonzero_distinct_and_avoid_reserved_ranges`
  (`:145`) refuses 44–49 (`:162`).
- The seal/payment/resume band 20–29 is full since D147 took 28 and 29
  (`error.rs:420-421`). The legal free codes are 5–9, 37–39 and 50–124 (PS's
  map). The 30–39 band holds restore (30, 31, 35), the vault-file classes
  (32–34, D47) and reveal (36).
- D69 §5's precedent: reveal went to *"**36**, the first free code after
  restore's band"* (D69:99-101). The next first free code is 37.

### 1.8 The options

| Option | Pay fails, record lost | Pay succeeds, both writes fail (exit 4 today) | A healed run stays 28 | A script can branch | Cost |
|---|---|---|---|---|---|
| (i) H3: a field or sentence on 28 | message only | no | only with the new predicate | **no** | XS |
| (ii) a new class at 37 | yes | yes | yes | yes | S |
| (iii) (ii), and stop the sub-batch loop after a non-durable capture | yes, loss bounded to one sub-batch | rarer | yes | yes | M, in `antseal-net`; devnet-only proof |

(iii) is `S46` (§4).

## 2. RULING

### §2 R1 — The predicate is the most recent capture's durability

The receipt sink tracks `unrecorded: Option<ReceiptSinkFault>`:
- a capture that does not become durable (`NotArmed`, `Encode`, `Write`) sets
  it;
- a durable write clears it;
- `Rearmed` alone does not set it, because the write still proceeds
  (`receipt_sink.rs:172-175`).

`fault()` stays first-fault-wins, for diagnostics only.

*Why:* captures are cumulative and a later durable capture heals an earlier
failure (§1.4). Only the last capture's outcome says whether the record on disk
covers what was paid.

### §2 R2 — A provided journal method beside `arm_receipts`

`SealJournal::receipts_unrecorded(&self) -> Option<ReceiptSinkFault> { None }`
is a provided method next to `arm_receipts` (`journal.rs:852`), overridden by
`VaultJournal` (next to `vault_journal.rs:274`). This is the shape S37's Do
names: *"A `SealJournal` provided method mirroring `arm_receipts`"*.

### §2 R3 — `consent_anchor_pay` consults it at exactly two points

1. `pay` returns `Err(StrandedPayment)` and the predicate is `Some` →
   `SealError::PaymentUnrecorded`.
2. `pay` returns `Ok`, then `put_receipt` fails, and the predicate is `Some` →
   the same variant.

Every other combination is unchanged: 28 when the last capture was durable; 4
when only the post-pay write failed and the predicate is `None`; a normal run
otherwise.

*Why:* these are the two ways money can move with nothing durable recording
it (§1.3, §1.5). Consulting the predicate anywhere else would let it fire on a
run whose record is complete.

### §2 R4 — Class `payment-unrecorded`, exit 37

- The seal/payment band 20–29 has been full since D147 (§1.7). 37 is the first
  free code, D69 §5's placement precedent, and the class is a failure to write
  a vault record: the 30–39 band already holds the vault-file classes (32–34)
  beside restore and reveal.
- D134 §2 R3(1) is satisfied: the table is appended to, nothing is renumbered,
  and 44–49 stay untouched.

*Why a class and not a sentence:* scripts branch on the code (§1.6). A
distinct code is the only signal that reaches the branch a documented script
already has, which is the D147 reason for splitting 28 from 23, one step
further.

### §2 R5 — The Display, and 28's narrowed contract

The lane may tighten the wording; every clause must stay true:

> payment not recorded: {n} sub-batch transaction(s) landed but the vault could
> not record them ({fault}) — money has moved and antseal no longer knows what
> it bought, so re-running `antseal seal` will quote, and charge again for,
> everything the vault does not show as paid; the ANT already spent on the
> unrecorded part cannot be recovered. Fix the vault's storage first (free
> space, permissions, the disk), then review the re-run's quote instead of
> passing --yes ({detail})

- `{fault}` is `ReceiptSinkFault`'s Display: paths and I/O classes only, never
  receipt content (`receipt_sink.rs:163-164`).
- 28's frozen line (`cli-errors.display.txt:89-90`) is **unchanged**: it stays
  true for its narrowed domain. 28's documented contract is narrowed to *"when
  the receipt was recorded; 37 when it was not"*.

### §2 R6 — The documents move with the class

- `error.rs`: module-doc table row 37, and the section *"28 and 29 are the
  money-moved pair (D147)"* (`:53-71`) becomes a trio.
- `docs/user/funding-your-wallet.md:238-282`: a third money-moved code, and the
  28 bullet qualified.
- `docs/testing/error-code-contract.md`: the class list.
- Optional: `antseal-net/src/error.rs:86-90`, so the net Display says the
  partial receipt is authoritative *"(when the caller journaled it)"*.

### §2 R7 — S37 Accept 2 is amended; D147 takes an addendum

- **S37 Accept 2** (the orchestrator amends it): *"A sink write failure during
  a `pay` that succeeds changes nothing **when the post-pay `put_receipt`
  succeeds**; when it also fails, the new class fires."*
- **D147** takes a dated addendum, written with this record: the money-moved
  pair becomes a trio.

## 3. Fault plants

The implementing lane owes these. Green baselines come first; each plant is
judged by its **message**; every restore is followed by a `touch`. The seam is a
`#[cfg(test)]`-only `fail_next_writes` counter in the sink, so a
fail-then-heal sequence can be scripted. Tests 1–4 are in-crate in
`pipeline/resume.rs` and spawn nothing; `tests/exit_codes.rs` spawns the binary
and runs in a private `CARGO_TARGET_DIR`.

**The green tests — the load-bearing half**

1. **The last capture failed, then the payment strands** → class 37; the
   Display names the transaction count and the fault. Positive control:
   `journal.receipt(id) == None`, which proves the injected failure really
   failed, so the test cannot pass vacuously.
2. **Capture 1 fails, capture 2 is durable, then the payment strands** → class
   **28**, and the receipt is durable.
3. **A successful `pay` with a failed capture** completes, and the receipt is
   durable (S37 Accept 2).
4. **A successful `pay` whose `put_receipt` fails while the predicate is
   `Some`** → 37, not 4. A wrapper `SealJournal` fails `put_receipt` and
   delegates `receipts_unrecorded`.
5. **`tests/exit_codes.rs`**: the `TABLE` row, distinctness and the snapshot,
   with the exemplar built through the real producer (`From<SealError>`).

**The plants — proof that those tests can fail**

| Plant | Must redden |
|---|---|
| The pipeline reads `fault()` instead of `unrecorded()` | test 2 (37 on a healed run) |
| The `pay`-error check is dropped | test 1 (28) |
| The `put_receipt` check is dropped | test 4 (4) |
| `unrecorded` is never cleared on a durable write | test 2 (37 on a healed run) |
| The class is placed at 44 | `codes_are_nonzero_distinct_and_avoid_reserved_ranges` |

Test 3 does not guard the never-cleared plant: the predicate is consulted only
when `put_receipt` fails, so test 2 is that plant's witness.

## 4. What this record does NOT decide

- **`S46` (minted with this record; not this wave): a failed capture does not
  stop the next sub-batch payment.** D37 Decision 2 promises that `pay()`
  journals each sub-batch's record *"before submitting the next"*, so a crash
  loses *"at most the one tx currently inside the pay→journal atomicity
  window"* (D37:102-109). The hook cannot report a failure: `CaptureHook =
  Arc<dyn Fn(&PaymentReceipt) + Send + Sync>` returns nothing
  (`antseal-net/src/ant_backend.rs:174`), so the loop submits sub-batch N+1
  after capture N failed. Under a persistent write failure every remaining
  sub-batch is paid unrecorded. The fix — the hook reports durability, and the
  loop stops after a non-durable capture — touches the `ReceiptSink` trait
  (`crates/antseal-cli/src/backend.rs:1161`) and its implementations, sits
  inside S20's containment of `ant_backend.rs`, and can be proven only on the
  devnet lane. `S46` is `after S37`: it reuses this record's predicate and
  class.
- **Rebuilding a lost receipt from the wallet's on-chain transactions.** Not
  explored. The Display's *"cannot be recovered"* states what antseal can do:
  a fresh quote round mints fresh hashes (§1.3).
- **A devnet witness for 37.** The class is proven in-crate with an injected
  write failure; `S46`'s loop change is the part that needs the devnet.

## 5. Edit list — per write scope, with the lane named before this record was written

### L-ERR2 (round 2, after the round-1 checkpoint) — this record first, then Q116, then D194

- `crates/antseal-cli/src/pipeline/receipt_sink.rs`: `SinkState`
  (`:209-221`), `note` and `capture`, the new `unrecorded()`, unit tests, and
  the `fail_next_writes` seam.
- `pipeline/journal.rs`: the provided method beside `arm_receipts` (`:852`).
- `pipeline/vault_journal.rs`: the override beside `:274`.
- `pipeline/resume.rs`: `consent_anchor_pay` at `:488` and `:505`, and tests
  1–4.
- `pipeline/error.rs`: `SealError::PaymentUnrecorded` and its
  `From<SealError> for CliError` arm.
- `crates/antseal-cli/src/error.rs`: the `CliError` variant and its Display;
  `ErrorClass::PaymentUnrecorded` with `ALL` 35 → 36, `exit_code` 37, its
  name, its `class()` arm and its `class_index`; the module-doc row 37 and the
  trio section. L-ERR1 edits this file in round 1; L-ERR2 starts after its
  checkpoint.
- `crates/antseal-cli/tests/exit_codes.rs` (`TABLE` +1 and one exemplar) and
  `tests/snapshots/cli-errors.display.txt` (+2 lines).
- `docs/user/funding-your-wallet.md` and
  `docs/testing/error-code-contract.md`.
- Optional: `crates/antseal-net/src/error.rs:86-90`, Display only.
- `pipeline/` is a heavy-tier trigger (`scripts/gate-features.sh:112-121`), so
  the close gate runs with `ANTSEAL_GATE_HEAVY=1 ANTSEAL_GATE_E2E=1`.

### RECORDS-A — dated addendum

D147: the money-moved pair becomes a trio.

### Orchestrator — `TODO.md`, `tasks/S.md`, `docs/decisions/README.md`

- `S37`: Accept 2 amended per §2 R7, and the tick.
- `S46`: the row and its `tasks/S.md` entry, per §4.
- This record's index row and register row.

## 6. As built — wave 38, lane L-ERR2 (recorded in place before this record was first committed)

Every verdict below was read from an exit file. The plants ran in the shared tree under the writer
protocol, in one batch, after an unplanted control (23 passed).

- **§2 R1, R2.** The sink's `SinkState` gains `unrecorded`. A failed capture (`NotArmed`,
  `Encode` or `Write`) sets it, a durable one clears it, and the first fault still wins in
  `fault()`. `SealJournal::receipts_unrecorded` is a provided method beside `arm_receipts`, and
  `VaultJournal` overrides it.
  - **Deviation:** `arm()` also resets the predicate. One invocation can pay twice: a
    proofs-expired re-payment follows the first `pay`. Without the reset, the first payment's
    last failed capture would survive into the second, although the pipeline's own `put_receipt`
    had since made that receipt durable. Guarded by
    `arming_starts_a_payment_with_no_unrecorded_capture`.
- **§2 R3.** `consent_anchor_pay` consults the predicate at the two ruled points:
  - a `pay` that strands with the predicate `Some` becomes `PaymentUnrecorded`;
  - a `put_receipt` that fails with the predicate `Some` becomes the same.

  With `None`, both convert as before (28 and 4). `landed_tx_count` is taken before the prior
  receipt's merge, because a prior's transactions were already durable.
- **§2 R4.** `ErrorClass::PaymentUnrecorded`, exit 37, name `payment-unrecorded`, sits after 36 in
  `ALL` (35 → 36). The module-doc table, `TABLE`, `class_index` and the snapshot (+2 lines) moved
  together. **A second pin moved with them:** `tests/namespace_disjointness.rs`'s
  `PINNED_CLASS_COUNT` (35 → 36) and its doc sentence. §1.7 named only `exit_codes.rs:36`; D147
  R13 had named this second pin when the count went from 33 to 35. The lane asked before touching
  it, its scope was extended, and its red was seen by message (plant P-ndj).
- **§2 R5, the Display, tightened so every clause is true by measurement.**
  - *"could not record them"* → *"could not record **all of** them"*: a fail-after-durable
    payment leaves an earlier capture on disk (test 1b).
  - *"no longer knows what it bought"* → *"does not know all of what it bought"*.
  - The storage remedy is conditional (*"If the vault's storage caused this … fix it first"*),
    because the fault can be `NotArmed` or `Encode`, which no storage fix cures.
  - 28's frozen text is unchanged; its doc gains a *"Narrowed by D186"* paragraph.
- **§2 R6.** `docs/user/funding-your-wallet.md` names three money-moved failures and their codes,
  with a 37 block and re-measured citations. `docs/testing/error-code-contract.md` §2 adds 37.
  **The optional `crates/antseal-net/src/error.rs` Display edit was not taken: D147 R11 says
  *"Do not reword `StorageError`'s own `Display` strings"*, and that earlier, specific ruling
  governs this record's optional item.** Separately, the rustdoc at that file's `:80-85` (*"the
  partial quote→tx map is journaled before this error surfaces, so the evidence of money spent is
  never only in the error"*) is false in this record's case. It was false before this wave too,
  and is recorded on `S46`, which reworks the same capture path.
- **Tests.**
  - Test 1: every capture fails, then the payment strands → 37, with positive controls that the
    receipt is really absent.
  - Test 1b: a capture fails after a durable one → 37.
  - Test 2: fail then heal → 28.
  - Test 3: a successful `pay` with failing captures → sealed, with the receipt durable.
  - Test 4: a failing `put_receipt` with the predicate `Some` → 37, and the same failing write
    after durable captures → 4.
  - Test 5: `exit_codes.rs`.

  Four existing sink tests gained predicate asserts.
- **Plants, every one red by message.**
  - P-i (reads `fault()`): *"a healed payment must stay payment-stranded, got PaymentUnrecorded"*.
  - P-ii (the `pay` check dropped): *"expected payment-unrecorded (37), got
    Storage(StrandedPayment …)"*.
  - P-iii (the `put_receipt` check dropped): `Journal(Store(Io …))`.
  - P-iv (never cleared): the healed test and *"a later durable capture heals the failed one"*.
  - P-vi (the reset dropped): *"a new payment starts with nothing unrecorded"*.
  - P-v (the class at 44): *"44–49 stay reserved"*.
- **At the lane's close.** `cargo test -p antseal-cli` (the whole crate, `--no-fail-fast`) passed
  847, 0 failed, and `clippy -D warnings` exited 0. **The whole-crate run caught what targeted
  runs did not:** the test journal's forwarded `put_anchor` made a fifth anchor-slot write site
  for `seal_journal.rs`'s source scan. The double now refuses that write.
- **The orchestrator's acts.** `S37`'s Accept 2 is amended per §2 R7, `S46`'s row and entry
  exist, and `S37` is ticked.

## Closing — this record is not consent

It adds an error class, an exit code and a predicate inside the wave's own
commits. Nothing in it authorises a push, a workflow dispatch, a deploy or any
other outward act; each of those needs the maintainer's express consent naming
the action, the destination and the account.
