# D209 — An expired-proof re-payment **carries the replaced payment's totals and every record-less mapping**, **keeps the records this run paid for**, and **re-buys only the rest**

- **Status: RESOLVED. H3 fell (b): its direction survived and two of its premises fell. The
  orchestrator's challenge-round counter-lean fell (c): its mechanism cannot be built as stated,
  and its direction survived through a rule that needs no block time. The challenge round also
  amended this record's first ruling (§2 R6 amends R1).**
  - **H3 (`S53`)** — *"the cumulative total belongs in ONE record that the readers already read,
    and the cheapest honest one is the receipt the journal writes: on the expired-proof arm the
    replacement receipt carries forward what the replaced receipt cost (a "replaced cost" carried
    into the new record), so `complete()` and `list` keep reading one record and the vault no
    longer forgets money it spent; no history list, and no new meta key (the meta schema is
    strict, so a new key would make every older binary read the vault as Corrupt unless the
    record version is bumped)."* (b):
    - **What survives: the direction.** The work's total belongs in the receipt, the one record
      `complete()` and `list` already read. No history list and no meta key (§2 R1, R3).
    - **Premise 1 falls: no "replaced cost" field is needed.** The receipt's `storage_cost_atto`
      is already the work's cumulative cost by `merge_receipts`' own definition. Carrying the
      replaced totals through the existing merge, in a prior that holds none of the replaced
      records, moves no field, version or schema (§1.4).
    - **Premise 2 falls: the receipt is shared with a bundle, and it is not frozen.** The lean said
      that either would make it fall (a). The receipt rides in the bundle's §7.10 record only as an
      opaque payload, which the schema declares outside the v1 wire registry; under this ruling not
      even the payload's layout moves, only a value in it (§1.5).
    - **And the lean's one writer is two.** The durable sink's captures write the receipt as well
      as the final `put_receipt`, so the carry has to reach every capture. Arming the sink with the
      carried prior does that with no change to the sink's code (§1.2).
  - **The counter-lean (`S55`)** — the orchestrator's, sent to P2's challenge round: *"Judge
    expiry per PAYMENT, not per work. On the expired arm, split the receipt's records by the age
    of the transaction that paid them (the same put_policy::payment_time rule D179 uses, applied
    per tx): records whose paying tx is a day old are the expired ones — re-quote and re-pay only
    their blobs; records paid by younger transactions (always including any paid in THIS run) are
    carried as the prior through the S53 merge, with the replaced records' totals. One consent,
    one payment, each blob bought at most once per run."* (c):
    - **The mechanism cannot be built as stated.** The arm holds block NUMBERS, never times. Every
      time read and every expiry verdict live inside the backend, and `ProofsExpired` names no
      transaction and no blob. Giving the arm per-transaction ages would grow antseal-net's API
      (§1.7).
    - **And age alone is not D179's rule.** D179 expires a blob only when a majority of its
      storing peers declined AND its payment is more than a day old by its block time. A split by
      age alone would re-buy day-old records whose peers were never asked (§1.7).
    - **What survives: the direction.** Keep the young records; one consent, one payment, each
      blob bought at most once per run. It is reached through a rule that needs no time: the
      records this invocation paid for are never expired (§2 R7).
    - **The round also corrected the `S53` ruling.** A records-free carry (`spent_only`, R1 as
      first ruled) drops a record-less `Submitted` mapping, which D208's resolution step must still
      be able to ask the chain about (executed, §1.8). The carry is `carry_forward` (§2 R6).
- **Date: 2026-10-20**
- Owner rows: **`S53`** (§2 R1–R5, R1 as amended by R6), **`S55`** (§2 R6, R7 and R8's warning)
  and **`U120`** (§2 R8's Upload line). This wave's rulings minted `S55` from P2's planning report,
  and `U120` and **`S56`** (§2 R9's residue, open for the next wave) from P2's challenge round,
  before this record was written. This record mints no row.
- Related:
  - **D37** Decision 5 as extended by the S31 amendment (the remainder's merge, D37:391-397, and
    the expired path's *"deliberately does **not** merge"*, D37:412-415) and Decision 6 (the
    proofs' one-day window and its consented re-payment); takes a dated addendum;
  - **D203** §2 R7 (the cost is the receipt's `storage_cost_atto`, *"accumulated across rounds by
    `merge_receipts`"*, D203:359-361), its §6 R7 deviation (D203:784-787) and §6's *"`S53` owns
    R7's expiry arm"* (D203:959); takes a dated addendum;
  - **D179** (expiry needs a declining majority and a day-old payment by its block time);
    `complete()`'s doc cites it for what is D37's rule (§1.1);
  - **D208** (`S54`: the resume resolves every `Submitted` transaction before its money branch,
    which §2 R5 relies on; and its R12, under which a transaction is published as part of the
    payment only if its hash maps a quote);
  - **D210** (`U114`, `U115`: the words the plan and rule 2 say over the expired shapes X-A and
    X-B; this record changes the arm's money, not those words);
  - **D36** (a resume re-quotes and re-consents; a fresh quote round mints fresh quote hashes),
    **D47** (export and import carry the receipt as opaque bytes) and **D146** (the consent
    screen; D146:84 quotes the Upload line as history);
  - **`S16`** (a journaled receipt, not the state tag, says money moved) and **`U32`** (no `--json`
    semantics move before it).

## 0. What was measured against

`HEAD` `ab7226f` (local `main`, one records-only commit ahead of `origin/main` `6f0b574`). The
tree was clean when planning began, on 2026-10-20.

Planning lane P2 (wave 41, 2026-10-20) measured `S53` together with `U114` and `U115` (D210),
then answered a challenge round on its own proposed row (A), which the rulings minted as `S55`.
It wrote nothing in the repository. Every probe ran in-process over `MockBackend`, with no
spawned binary, in a `git archive HEAD` shadow copy built in a private target. An expiring
`finalize_batch` double modelled on the suites' `ExpiringOnce` (it stores the first k blobs, then
returns `ProofsExpired`) puts the expiry verdict at the boundary where the pipeline observes it,
and the sink half writes through the real `VaultReceiptSink`. The runs:
- **`S53` at `HEAD`:** the probe run exited 0, and so did the sink half (*"1 passed"*).
- **Option A planted** (§1.6): the probe exited 0 (*"2 passed"*), the sink half exited 0, and the
  existing suites with the plant exited 0 — lib *"333 passed; 0 failed"*, `seal_matrix`
  *"15 passed"*, `seal_resume` *"16 passed"*.
- **The challenge round:** four probe tests, T1–T4, with a per-PAYMENT expiry double and a `pay`
  wrapper that counts every priced line by blob address, at `HEAD` (exit 0, *"4 passed"*) and with
  `carry_forward` planted (exit 0, *"4 passed"*). The existing suites with that plant: run 1
  printed five green verdict lines (lib 333, `seal_command` 56, `seal_journal` 29, `seal_matrix`
  15, `seal_resume` 16) but wrote no exit code, because the run wrapper's timeout killed the script
  after the last binary printed; run 2, over `seal_matrix` and `seal_resume`, exited 0 with 15 and
  16 passed.

Code-traced only: the adapter's own expiry path, `put_to_majority`'s decisive-decline branch.
`MockBackend` models neither peers nor blocks, so no probe reaches it.

Before this record was written, the records lane re-read every load-bearing line through
`git show ab7226f:<path>`, because implementation lanes were editing the tree (L-RESUME3 in this
record's own files), and re-read the quoted lines in P2's probe logs. Every figure held, with
these refinements:
- `MockBackend::double_paid`'s doc is `crates/antseal-net/src/test_util/mock.rs:315-317` (P2:
  `:315-318`, which takes in the `#[must_use]`); `git grep` finds 12 `double_paid()` call sites.
- Option B's price (§1.6), re-counted: `git grep -n 'PaymentReceipt {'` finds 45 lines. Removing
  the type, its `impl` and the functions that return one — four of which spell the return type
  `antseal_net::PaymentReceipt` — leaves 26 struct literals in 18 files, as P2 counted. P2's
  per-site locators `mock.rs:517`, `ant_backend.rs:814` and `:1628` are the literals'
  `storage_cost_atto` lines; the literals open at `:513`, `:810` and `:1624`.
- D37:412-415, the sentence this record extends, sits in the S31 amendment's *"Decision 5,
  extended"* subsection (D37:380), not in Decision 5 or 6 as first written.
- P2 wrote that D179's text *"never discusses the receipt"*. It does mention the receipt (14
  lines), but it never rules on what the re-payment does with it: `command grep -n -i
  'prior\|replac'` over D179 finds eight lines, none about the receipt. The ruling `complete()`'s
  doc attributes to D179 is D37's (§1.1).
- Three of P2's figures, re-measured: the importer's receipt arm is `export.rs:474-480` (P2:
  `:473-480`, whose first line closes the previous arm) and the strict work-key refusal is
  `:501` (P2: `:500`); and `deny_unknown_fields` appears in 11 `.rs` files under `crates/`, none
  in `crates/antseal-net/src` (P2: *"10 other files"*). None changes a conclusion.
- P2 §6.4's *"Existing suites with the plant: none changes"* held for P2's plant, which had no
  empty-candidate guard. Under R7's guard one existing test reddens; the implementing lane found
  it, and the orchestrator re-fixtured it by grant before this record was written (§1.8).

## 1. What was measured

### 1.1 The expired arm at `ab7226f`

- **The arm** is `crates/antseal-cli/src/pipeline/resume.rs:295-306`
  (`Err(SealError::Storage(StorageError::ProofsExpired)) => { … }`):
  - it re-quotes every staged blob, `self.backend.quote_batch(&blobs)` (`:296`), not the
    uncovered ones;
  - it pays with `prior: None` — `consent_anchor_pay(seal_id, &quote, None, identity.unanchored,
    true, None)` (`:301`) — under the comment *"the expired records are what is being replaced,
    not extended"* (`:298-299`);
  - it adds the replacement's receipt cost to the run's figure,
    `paid_atto = paid_atto.saturating_add(fresh.storage_cost_atto)` (`:303`).
- **D37's reason for `prior: None` is the records, not the totals** (D37:412-415): *"The
  proofs-expired re-payment path (Decision 6, as corrected) deliberately does **not** merge — at
  the captures or at the end: there the prior proofs are the thing being replaced, and merging
  would leave `finalize_batch` matching a stale record first."* The merge comment in
  `consent_anchor_pay` says the same (`resume.rs:539-542`).
- **`complete()` records the receipt's cost** (`:624-627`,
  `Some(receipt) => Some(receipt.storage_cost_atto)`), and its doc states the consequence:
  *"An expired-proof re-payment replaces the receipt instead of extending it (`prior: None`,
  D179), so after one the cost is the replacement's."* (`:604-606`).
- **The remainder arm is the precedent for the run's own spend.** After a remainder payment the
  run's figure is the quote's total, `paid_atto = quote.total_ant_atto;` (`:256`), not the merged
  receipt's cost.

### 1.2 Two writers overwrite the replaced receipt, not one

- **The final write.** `consent_anchor_pay` journals `match prior { Some(prior) =>
  merge_receipts(prior, receipt), None => receipt }` (`resume.rs:538-545`) through
  `self.journal.put_receipt(seal_id, &receipt)` (`:554`).
- **Every capture.** The sink is armed with the same prior before `pay` —
  `self.journal.arm_receipts(seal_id, prior.as_ref())` (`:504`) — and each capture writes
  `match &state.prior { Some(prior) => merge_receipts(prior.clone(), receipt.clone()), None =>
  receipt.clone() }` (`crates/antseal-cli/src/pipeline/receipt_sink.rs:424-427`) through
  `store.put_receipt` (`:442`). `arm`'s doc names the expired path as a deliberate `None`
  (`:333-338`).
- **So the replaced receipt is gone at the re-payment's first durable capture**, before the final
  write. Executed (the sink half; the re-payment strands after its first sub-batch):
  *"[SINK] seed (expired payment) cost=5517"* … *"vault receipt after the strand:
  storage_cost_atto=1839 blobs=1 tx_map=1 txs=1 fine=Some(Finalizing)"*.

### 1.3 The forgotten money, executed at `ab7226f`

| Shape | What moved | What the vault recorded |
|---|---|---|
| **S53-A** — a paid work; finalize stores blob 0, then the proofs expire | 5517 + 3678 = **9195** (the re-consent priced 2 of 3 blobs, blob 0 already stored) | meta `cost_atto=Some(3678)`; `list`: *"cost: 3678 atto-ANT"* |
| **S53-B** — a stranded partial (blob 0, 1839); one resume pays the remainder, then meets the expired partial | 1839 + 3678 + 5517 = **11 034** | meta `cost_atto=Some(5517)`; `list`: *"cost: 5517 atto-ANT"* |
| **Sink half** — the re-payment strands after its first sub-batch | 5517 + 1839 = **7356** | the capture on disk: `storage_cost_atto=1839` |

- **The expired money is spent.** `ProofsExpired` is returned only when `put_policy::verdict`
  gets a payment time (`crates/antseal-net/src/ant_backend.rs:1975-1986`), and
  `put_policy::payment_time` (`crates/antseal-net/src/put_policy.rs:260-267`) yields one only if
  every paying transaction's block time was read (`let time = (*time)?;`, `:263`) — a mined
  transaction. A time that cannot be read counts as not expired (`:34-36`).
- **Partly stored, then expired, is a real shape.** `finalize_batch` stores blob by blob and
  `put_to_majority(…).await?` (`ant_backend.rs:916`) returns at the first decisive blob, after the
  earlier blobs stored (code-traced; S53-A executes it through the mock's seam).
- **S53-B also bought two blobs twice in one run** — the remainder's two blobs were priced again
  by the expired re-consent (*"CONSENT#1: total_ant_atto=5517 blob_count=3 priced=3"*), with
  `double_paid=0`. That is `S55` (§1.8).

### 1.4 The receipt's cost is already defined as cumulative

`merge_receipts` (`receipt_sink.rs:151-164`) extends `blobs`, `tx_map` and `txs`, and
saturating-adds `storage_cost_atto` and the gas. Its doc defines the result (`:143-145`):
*"`storage_cost_atto` and the gas summary are sums: what this seal has cost in total, across
however many invocations paid for it."* On the remainder path that definition already holds. On
the expired path, `prior: None` makes it false: the receipt's total is the replacement's alone.

### 1.5 Who reads the cost, and what a carry would move

- **The readers of the forgotten total.** `complete()`'s cost becomes the meta's `cost_atto`,
  which `list` prints as its cost line and `list --json` emits as `cost_atto`
  (`crates/antseal-cli/src/listing.rs:1526`); `list`'s *"so far"* line reads the receipt's cost
  (`:702`). The meta field's documented meaning is *"Total storage cost paid, atto-ANT"*
  (`crates/antseal-cli/src/vault/store.rs:225-226`).
- **Nothing decides on it.** Rule 2 and the abandon preview read `payment_recorded`, which is true
  of the fresh receipt either way; the remainder rule reads the fresh records; `status` reads the
  transactions and their block numbers, never a cost; and the run report prints
  `outcome.paid_atto` (`crates/antseal-cli/src/seal_run.rs:549`), the run's own spend. The harm is
  the recorded and displayed cost.
- **The receipt's encoding is versioned but not strict.** `RECEIPT_JOURNAL_VERSION` is 1
  (`crates/antseal-net/src/receipt.rs:213`) and `open()` refuses any other (`:248-256`);
  `PaymentReceipt` carries no `deny_unknown_fields` (0 hits in `crates/antseal-net/src`; the
  control: the attribute is in 11 `.rs` files elsewhere under `crates/`).
- **It is shared with the bundle only as an opaque payload.** `bundle_receipt_record`
  (`crates/antseal-cli/src/pipeline/reveal.rs:1179`) puts the encoded receipt in §7.10's
  `payload` (`:1198`), and derives the wire values `tx_hashes` and `block_number` from
  `receipt.txs`. The payload is declared outside the registry
  (`crates/antseal-core/src/bundle/schema.rs:798-800`): *"Deliberately outside the wire registry:
  its internal layout is A/S's and is *not* a v1 wire format, so changing it is not a
  format-version event."*
- **Export and import copy it opaquely** (D47; `crates/antseal-cli/src/vault/export.rs:474-480`,
  `:1144-1146`), while the meta is strict: an unknown key is
  `corrupt("unknown meta key (strict schema)")` (`store.rs:1044`), and a newer record version is
  `NewerRecord` (`:959-961`).

### 1.6 The options, priced (P2 §2 `S53` (c))

| Option | What | Price |
|---|---|---|
| **A — carry the totals, not the records** (taken, as amended by §2 R6) | The expired arm passes `prior: Some(…)` holding the replaced receipt's `storage_cost_atto` and gas and none of its records; the existing merge writes fresh records plus cumulative totals at every capture and at `put_receipt` | XS–S. No field, version, schema, meta key or bundle wire value moves; built and run in the shadow (§0) |
| B — a "replaced cost" field in the receipt (H3 as written) | A new field on `PaymentReceipt` or `JournalReceipt` | 26 struct literals in 18 files, each a compile error until it names the field (no `Default`). Without a version bump an older binary silently drops the field on any rewrite (serde ignores unknown fields); with one, `decode_receipt` reads every receipt as `Corrupt` (`receipt_sink.rs:98-104`). Adds nothing A lacks |
| C — a cumulative meta key | Meta key 12, written at each `put_receipt` | An older binary reads the whole work as `Corrupt` (strict schema), or a `WORK_RECORD_VERSION` bump, *"a vault-format event"* (`store.rs:89-91`); and a new crash window, because the sink writes the receipt record and nothing else (`receipt_sink.rs:44-48`) |
| D — replaced receipts kept as history | A new record kind or journal entry | M–L, and an export format change (the work map is strict, `export.rs:501`). Its one gain over A — the replaced payment's transaction hashes survive — no Accept needs |
| A′ — carry the replaced `txs` too | — | Moves §7.10's wire values (`tx_hashes`, and `block_number` as the minimum over `txs`) and `status`'s transaction count, for evidence the verdict cannot use |

Under Option A, measured with the plant (§0): S53-A records `cost_atto=Some(9195)` with a receipt
of `blobs=2 tx_map=2` (the fresh records only) and `outcome: paid_atto=3678`; S53-B records
`Some(11034)` with `outcome: paid_atto=9195`; and the sink half's capture holds
`storage_cost_atto=7356` with `blobs=1 tx_map=1`.

### 1.7 Where per-transaction times are (the challenge round, P2 §6.1)

- **The receipt holds block numbers, not times.** `TxRecord::block_number: Option<u64>`
  (`crates/antseal-net/src/receipt.rs:128-133`) is D33's enrichment slot, filled at a confirmed
  landing or by backfill. No receipt field holds a timestamp.
- **Times are read only inside the backend**, by `paying_block_time` (`ant_backend.rs:2069-2086`),
  which asks the payment RPC for the block and returns `block.header.timestamp`.
- **Finalize reads a time on one path only:** for the blob whose round the declines alone decided
  (`if tally.declines_are_decisive() { … put_policy::payment_time(&block_times) }`, `:1975-1983`),
  and it returns at the first such blob (`:916`). Blobs after it are never asked, and no other
  transaction is timed.
- **Nothing crosses to the pipeline but a unit error.** `StorageError::ProofsExpired` has no fields
  (`crates/antseal-net/src/error.rs:142`).
- **The pipeline has no other door to the network.** `StorageBackend` has five methods at
  `ab7226f` — `quote_batch`, `pay`, `finalize_batch`, `get_data`, `balances`
  (`crates/antseal-net/src/backend.rs:217-294`) — and project rule 1 routes every network access
  through it. D208 R8 adds a sixth, `payment_tx_state`, which answers a block NUMBER
  (`Landed { block_number, confirmed }`), not a time.
- **A verdict per transaction needs antseal-net's API to grow:** a payload on the variant, which
  34 non-comment lines in 12 files build or match (15 files mention the token at all; P2 gave 15
  for the 34), and a finalize loop that goes on past an expired blob; or a new read on the trait,
  which 23 implementations in 14 files carry. Both are heavy-tier changes in the crate the
  `S51`/`S54` lane held this wave.
- **And D179's rule has two clauses.** A blob is expired only when the declines alone made its
  storing majority unreachable AND its payment is more than 24 hours old by its block time
  (`PROOF_VALIDITY_WINDOW_SECS = 24 * 60 * 60`, `put_policy.rs:76`; D37's 2026-10-16 addendum).
  *"No pinned node rejects a proof on age, so the window is antseal's own"* (`resume.rs:42`). A
  split by age alone would re-buy day-old records whose peers were never asked and would most
  likely have stored them — the re-purchase without a verdict that `S55` exists to remove, moved
  one step over.

### 1.8 This run's records, the record-less mapping and the residue — executed (P2 §6.2–§6.7)

The probe's per-PAYMENT expiry double refuses as expired a blob whose record's paying transaction
is in its expired set, and stores every other blob, one at a time through the mock. Pays are
counted per blob address; `double_paid()` is not used, because it keys on quote hashes and a
re-quote mints fresh ones.

| Shape | At `ab7226f` | With `carry_forward` and this run's records kept |
|---|---|---|
| **T1** — a stranded partial (unit0, its transaction expired); one resume pays the remainder (3678), then meets the expired partial | the expired re-consent prices `["unit0", "unit1", "manifest"]` (5517); per address `unit0=1 manifest=2 unit1=2`, *"max pays of one address in this run = 2"*; `cost_atto=Some(5517)` of 11 034 spent | it prices `["unit0"]` (1839); `unit0=1 manifest=1 unit1=1`, max 1; `cost_atto=Some(7356)` = 1839 + 3678 + 1839, the true total |
| **T2** — run A pays the remainder and fails retryably (exit 23); in run B the partial's transaction is expired | run B prices all three (5517); `cost_atto=Some(5517)` of 11 034 spent | run B prices all three (5517): the residue (§2 R9); `cost_atto=Some(11034)`, the true total |
| **T3** — T1's shape plus a record-less mapping to a `Submitted` transaction | *"the Submitted mapping survives: tx_map has it = false, txs has it = false"* | *"… tx_map has it = true, txs has it = true"*, with `txs=[Submitted, Confirmed, Confirmed]`; `cost_atto=Some(7356)` |
| **T4** — a paid work expires and nothing was paid in this run (`S53`'s case) | prices all three; `cost_atto=Some(5517)` of 11 034 spent | prices all three; `cost_atto=Some(11034)` |

- **After T1 the receipt holds** `records=[unit1,manifest,unit0] tx_map=3 txs=[Confirmed,
  Confirmed]`: the stale partial's record, its entry and its transaction are gone; the
  remainder's and the replacement's stay. T1, T3 and T4 reach `fine=Some(Complete)`.
- **Finalize then stores every blob — per blob, by address, first record wins.** `finalize_batch`
  (`ant_backend.rs:821-919`) checks the receipt-wide gap rule first (`covers_all_paid_quotes`,
  `:833-839`), which passes: every kept record keeps its quote→tx entries and the fresh records
  bring theirs. Then, per blob, it skips a stored one, takes the FIRST record with the blob's
  address (`:860-866`) and stores with that record's own proof. The kept and the fresh records are
  disjoint by construction, because the re-quote excludes every kept address, and neither can
  meet D179's age clause.
- **Disjointness also keeps a debug assertion quiet.** `finalize_batch` asserts that the staged
  proof equals the journaled record's proof (`:874-877`, *"staged proof and journaled proof must
  be the same bytes"*). Were a kept blob re-bought too, the backend's staged proof would be the
  replacement's while the merged receipt's first match — the prior comes first — is the kept
  record, and a debug build would panic.
- **The strand case improves too.** If the expired re-payment strands, every capture is the carry
  plus the so-far, because the sink merges whatever prior it is armed with
  (`receipt_sink.rs:424-427`). So this run's remainder records stay durable; at `ab7226f` the first
  capture dropped them (code-traced; the drop itself is §1.2's executed sink half).
- **One existing test changes, where P2 measured none.** `ExpiringOnce`'s two tests
  (`crates/antseal-cli/tests/seal_resume.rs:417`, `:448`) stage `Paid` over a seeded receipt, so
  this run's set is empty and the arm behaves as the totals-only carry. But
  `expired_proofs_exit_with_their_own_class_and_never_the_usage_code`
  (`crates/antseal-cli/tests/seal_matrix.rs:796`) stages `Anchored` with no receipt, so the resume
  pays in the same run, and its `AlwaysExpired` double then calls that minutes-old payment expired
  — a state D179 cannot produce. Under R7 every blob is this run's, the guard returns
  `ProofsExpired` with no re-consent, and the test's `consent.calls() >= 2` (`:820-824`) fails.
  P2's plant had no guard — its diff quotes the candidates with no emptiness check, so the test's
  second consent was asked over an empty quote — and its suites stayed green (§0). The
  implementing lane found it; the orchestrator re-fixtured the test by grant (§3, §5).
- **A record-less mapping is never timed, so it never "expires".** Expiry is judged per blob from
  its record's paying transactions (`put_policy::paying_txs(receipt, record)`,
  `put_policy.rs:233-253`), and a mapping that no record uses pays for no blob. But the carry
  decides whether the vault still remembers it, and a records-free carry forgets it (T3 at
  `HEAD`; `spent_only` by construction). D208 R9 asks the chain about every `Submitted`
  transaction before the resume buys anything; a mapping the expired arm dropped could never be
  asked about, and a payment that may have landed would vanish from the vault.
- **What the carry does not fix.** That mapping's blobs have no record, so the remainder and the
  arm both re-quote them (`uncovered_blobs`, `resume.rs:669-679`), and T3's total counts no
  unobserved payment. D208 owns that shape (§4).

### 1.9 The consent screen for a partial re-payment (P2 §6.5)

- **The warning** (`crates/antseal-cli/src/seal_consent.rs:176-184`): *"WARNING: this seal was
  already paid for, but a majority of the storing peers refused this seal's payment proof, and the
  payment is more than 24 hours old by its block time. That payment is stranded and cannot be
  recovered. Consenting here authorizes a SECOND, ADDITIONAL payment."* Its only pins are two
  needles, `"stranded"` and `"SECOND, ADDITIONAL payment"` (`:935-936`); no snapshot holds it.
  Once the quote prices only some blobs, a user who has just consented to a remainder would read
  *"That payment is stranded"* as that remainder.
- **The Upload line** (`:140-143`): *"Upload: {} blob(s) — every encrypted unit plus the
  encrypted manifest"*, filled from `blob_count`, which the resume sets to the quote's own count
  (`blob_count: quote.blobs.len()`, `resume.rs:468`). It is false on EVERY remainder consent at
  `ab7226f` (`U120`), and a partial expired re-consent would make it false there too. It is
  unpinned; D146:84 quotes it as history.
- **What the screen lacks.** The work's blob count is not on `ConsentRequest`
  (`crates/antseal-cli/src/pipeline/consent.rs:38-57`), whose literals are four:
  `resume.rs:465`, `seal_run.rs:620`, `seal_consent.rs:555` (a test helper) and
  `tests/machine_mode.rs:1025`. `seal --json`'s consent document already carries `blob_count` and
  `proofs_expired`, and P2 recommended adding no member before `U32`.

## 2. RULING

The orchestrator's rulings (2026-10-20). R1–R5 rule `S53` from P2's planning report; R6–R9 rule
`S55`, `U120` and the residue from P2's challenge round, and **R6 amends R1**. Names are the
implementing lane's unless the ruling fixes them.

### `S53` — the replaced payment's totals (lane L-RESUME3)

#### §2 R1 — The expired arm carries the replaced receipt's totals through the existing merge (as amended by R6)

On the expired arm (`crates/antseal-cli/src/pipeline/resume.rs:295-306` at `ab7226f`),
`consent_anchor_pay` receives `prior: Some(…)` built from the replaced receipt, not `None`. As
first ruled the prior was `spent_only(&receipt)`: a receipt with the replaced receipt's
`storage_cost_atto` and gas and NO `blobs`, `tx_map` or `txs`, from a helper beside
`merge_receipts` in `receipt_sink.rs`. R6 replaces it with `carry_forward`. Either way the existing
merge then writes the fresh records plus the cumulative totals at EVERY sink capture — the sink is
armed with `prior` (`:504`) — and at `put_receipt`. D37's reason for `prior: None`, never to
merge the expired RECORDS, is kept.

*Why:* §1.2–§1.4. The receipt's total already means *"across however many invocations paid for
it"*; only the expired path broke that, at its first capture as well as at its final write. A
prior that holds the totals and none of the replaced records restores the definition without the
stale-record hazard D37 names, and moves no field, version, schema or bundle wire value (§1.6,
Option A).

#### §2 R2 — `paid_atto` on that arm takes the quote's total

The arm adds `quote.total_ant_atto` to the run's `paid_atto`, not the returned receipt's
`storage_cost_atto`, which under R1 includes the carried totals. This is the remainder arm's
precedent (`:256`), and the run report stays the run's own spend.

*Why:* the run report (`seal_run.rs:549`) is about the run, and `paid_here` keeps that one job
(D203 R7). Executed under Option A (§1.6): S53-A reports `paid_atto=3678` beside a recorded
total of 9195, and S53-B reports 9195 — the remainder's 3678 plus the re-payment's 5517 — beside
a recorded 11 034.

#### §2 R3 — `list --json`'s `cost_atto` holding the cumulative total is its documented meaning

For an expired-and-re-paid work, `list --json`'s `cost_atto` — still the meta's value only, as
D203 M3 keeps it (D203:425-426) — now holds the work's cumulative total. RULED: that is its
documented meaning, *"Total storage cost paid"* (`crates/antseal-cli/src/vault/store.rs:225-226`),
and not a `U32` semantics move.

*Why:* the value stops contradicting its own documentation; no key, type or exit code moves; and
no snapshot pins an expired-and-re-paid work (`json-envelopes.txt` has no expired row).

#### §2 R4 — Docs

`consent_anchor_pay`'s `prior` doc (`resume.rs:450-455`) and the merge comment (`:538-545`);
`complete()`'s doc (`:600-608`), whose *"after one the cost is the replacement's"* becomes false
and whose citation for the replacement becomes D37's rule (D37:412-415) instead of D179; and, in
`receipt_sink.rs`, `arm`'s doc (`:333-338`) and `SinkState::prior`'s doc (`:216-222`).

*Why:* each states the old `prior: None` contract or its consequence (§1.1, §1.2).

#### §2 R5 — Interplay with `S54` (the same lane)

A transaction that D208's resolution prunes as never mined is NOT money spent: its records' cost
leaves the total when they are pruned, and it must never enter a carried total. A replaced
receipt's kept evidence records — the `TxRecord`s D208 R9 keeps for a reverted or never-mined
transaction after pruning its mappings — paid through no replaced record, so the carry keeps them
(R6), and D208 R12 keeps them out of every published value. *(Amended in place before first
commit, 2026-10-20, to the orchestrator's clarification to L-RESUME3; the first wording said they
were not carried.)*

*Why:* the carried total must be what moved (`S53`'s Accept; D208 §3's absent row: *"the cost
recorded equals what actually moved"*, D208 §3), and the arm sits after the resolution step
in `Pipeline::resume`, which runs before the money branch (D208 §2 R9).

### `S55` — the challenge round: what the arm keeps and what it re-buys (lane L-RESUME3)

#### §2 R6 — `carry_forward` replaces `spent_only` (amends R1)

The carry is `carry_forward(replaced, keep)`. It carries:
- every total (`storage_cost_atto` and the gas);
- the records of `keep`, with their quote→tx entries and their transactions;
- every mapping that NO record uses, together with its transaction.

It drops only the replaced records, their entries, and the transactions whose every quote belongs
to a replaced record. `keep = ∅` is `S53`'s case. A `TxRecord` that maps no quote at all — the
evidence D208 R9 keeps after pruning — paid through no replaced record, so it is carried *(amended
in place before first commit, 2026-10-20, as R5)*.

*Why:* a record-less `Submitted` mapping must survive the expired arm, so that D208's resolution
can still ask the chain about it. At `ab7226f` the arm drops it, and `spent_only` drops it too
(executed: T3, §1.8). With `keep = ∅` the carry gives the same records and totals as `spent_only`;
the one difference is the record-less mappings it keeps.

#### §2 R7 — This run's records are never expired

The resume remembers the blob addresses whose records THIS invocation bought: the pre-pay path's
receipt after `consent_anchor_pay` (`resume.rs:201-206` at `ab7226f`), and the remainder arm's
new records (`:246-262`). On `ProofsExpired` the arm keeps those records (`keep`), re-quotes ONLY
the staged blobs outside `keep`, and pays with `prior: Some(carry_forward(&receipt, &keep))`: one
consent, one payment.
- **Guard.** An empty candidate set, which D179's age clause makes unreachable, returns the
  original `ProofsExpired` rather than asking consent over nothing. Only a test double reaches it
  (§1.8).
- **Disjointness** (`keep ∩ candidates = ∅`) is asserted in a test. It is also what keeps
  `finalize_batch`'s debug assertion (staged proof == journaled proof) from firing (§1.8).

*Why:* it is honest to D179. A record paid minutes ago fails D179's age clause by construction, so
excluding it asserts nothing D179 has not already decided; every other record is treated exactly as
at `ab7226f`, re-bought under D37 Decision 6's generalisation from one refused blob to the whole
work. So the arm never re-buys anything `ab7226f` would not, and never skips anything D179 could
call expired. Executed on T1: the most pays of one address in the run fall from 2 to 1, and the
recorded total rises from 5517 to the true 7356 (§1.8).

#### §2 R8 — The consent screen says what is replaced and what is kept (`S55`, `U120`)

In `crates/antseal-cli/src/seal_consent.rs`, with one field on `ConsentRequest`
(`pipeline/consent.rs`) — the work's blob count — and its four literal sites (`resume.rs:465`,
`seal_run.rs:620`, the test helper at `seal_consent.rs:555`, and `tests/machine_mode.rs:1025`
after L-MONEY2 hands that file over):
- the proofs-expired WARNING says that the stranded payment is replaced for the {K} blob(s)
  priced here and, when this run paid for some, that the {M} blob(s) paid for in this run keep
  their payment;
- the Upload line says *"{K} of the seal's {N} blob(s)"* whenever K ≠ N. Its present text is false
  on EVERY remainder consent at `ab7226f`: that is row `U120`.

No `--json` member is added before `U32`, and no snapshot holds either sentence (the lane
verifies).

*Why:* §1.9. Once the re-consent prices a subset, *"That payment is stranded"* and *"every
encrypted unit plus the encrypted manifest"* would each misdescribe the money the user is asked to
authorise; `U120`'s spec is S8, under which consent shows exactly what will be paid.

#### §2 R9 — Residue, recorded and not fixed: a record that a previous run paid (row `S56`)

A record that a PREVIOUS run paid — an hour ago, say — is still re-bought when an older payment
expires in a later run (executed: T2, §1.8; this record's carry still records the true total
there, 11 034 against `ab7226f`'s 5517). The closer is to re-ask `finalize_batch` once per paying
transaction's blobs (size M), with a D37 Decision 6 addendum, and `ExpiringOnce`'s two tests move
to a per-transaction double. Row `S56`, for the next wave.

*Why:* R7 knows "young" only for the current invocation. The per-payment judgment the counter-lean
wanted is buildable with no block time and no antseal-net change: group the unstored blobs by their
records' paying transactions (`put_policy::paying_txs`, which needs only the receipt), call
`finalize_batch` per group, and re-buy only the groups it refuses as expired — D179's own verdict,
from inside the backend. Its price is one extra decline round per stale group, about 40 more lines
in the arm, and a change of meaning for `ExpiringOnce`, whose second call stores: under per-group
probing `expired_proofs_require_a_fresh_consent_before_re_payment` would see no re-payment
(P2 §6.8).

### Refused

- **B — a receipt field** (§1.6): 26 struct literals to touch, and either a silent drop by older
  binaries or, with a version bump, a vault every older binary reads as `Corrupt`.
- **C — a meta key:** the strict schema reads the work as `Corrupt`, or a vault-format bump; and a
  new crash window between the receipt write and the meta write.
- **D — replaced receipts kept as history:** an export format change, for a gain no Accept needs.
- **A′ — carrying the replaced `txs`:** it moves the §7.10 bundle's values and `status`'s count for
  evidence the verdict cannot use.
- **The counter-lean's per-transaction age** (§1.7): not buildable from the arm without growing
  antseal-net's API, and age alone is not D179's rule.

### What no ruling here moves

- **No format.** `RECEIPT_JOURNAL_VERSION` stays 1, and no receipt field, meta key, export key or
  bundle wire key moves. Values move, for expired-and-re-paid works only: the receipt's
  `storage_cost_atto`, and so `list`'s cost and `list --json`'s `cost_atto` (R3); and where this
  run paid records the arm keeps, the transactions that paid them stay in the receipt (§4).
- **No exit code, class, `CliError` variant, Display template, help line or user doc.** R8's two
  sentences are interactive-screen copy; `seal --json`'s consent document gains no member. Outside
  `seal_consent.rs` and the register, *"That payment is stranded"* appears nowhere, *"SECOND,
  ADDITIONAL"* only in D179's history, and the Upload line's words only in D146:84 and in
  `docs/user/funding-your-wallet.md:186-187`, which defines a blob by citing the line
  (`seal_consent.rs:140-142`) and stays true.
- **Heavy.** `crates/antseal-cli/src/pipeline/` is on `HEAVY_TRIGGER_PATHS`
  (`scripts/gate-features.sh:112-121`), so the heavy tier and the devnet E2E run at the gate.
- **Unchanged:** the sink's code (it merges whatever prior it is armed with), `merge_receipts`,
  `finalize_batch`, `put_policy`, D179's verdict and `payment_recorded`.

## 3. Fault plants

The implementing lane owes these. The red baselines come first, on the unedited tree: `S53`'s tests
are red at `ab7226f` (3678 recorded against 9195 spent, 5517 against 11 034, and a capture of 1839
against 7356; §1.3), and `S55`'s per-address test reads a maximum of 2 (T1, §1.8). Each plant
compiles and is judged by its **message**; plants run in a shadow copy with a private target, and
every restore is followed by a `touch` and a sha256 check against the lane's final file. The
pipeline's in-process tests (`--lib`, `--test seal_resume`, `--test seal_matrix`) spawn no binary
and run in the shared target under the lock.

**The green tests — the load-bearing half.**
- **G-S53a (`S53`'s Accept)** — `tests/seal_resume.rs`, through the expired-proof seam: a paid
  work whose seeded receipt cost C1; finalize stores blob 0, then reports the proofs expired; the
  re-payment costs C2. It asserts meta `cost_atto == Some(C1 + C2)`, the receipt's
  `storage_cost_atto == C1 + C2`, the receipt's `blobs` and `tx_map` exactly the fresh payment's
  (no stale record), `outcome.paid_atto == C2`, and `list`'s *"cost: {C1 + C2} atto-ANT"*.
- **G-S53b (remainder, then expiry)** — the S53-B shape: meta cost == partial + remainder +
  replacement.
- **G-S53c (the sink half)** — `tests/seal_matrix.rs`: the re-payment strands after its first
  sub-batch through the real `VaultReceiptSink`; the capture on disk holds C1 plus the landed
  partial's cost, and only the partial's records.
- **`carry_forward`'s unit tests:** `keep = ∅` carries the totals and no replaced record; kept
  records keep their entries and transactions; a record-less mapping and its transaction survive;
  a transaction that paid only replaced records is dropped. The fixtures' records carry their
  payment lines: a record with empty `payments` beside a mapping is a shape the pipeline never
  writes, and `carry_forward` would rightly read that mapping as record-less (P2 §6.9).
- **A per-transaction expiry double** — `ExpiringOnce` (`tests/seal_resume.rs:702-760`) expires
  its first call whatever was paid, so it cannot express T1 — and on it:
  - **the T1 shape (`S55`'s Accept):** the most pays of one address in the run == 1, asserted per
    ADDRESS and never by `double_paid()`, and the recorded cost == 7356, what moved;
  - **the T3 shape:** the record-less `Submitted` mapping and its transaction survive the arm;
  - **a strand during the re-payment:** every capture is the carry plus the so-far, so this run's
    remainder records stay durable;
  - **disjointness:** `keep ∩ candidates = ∅` (R7).
- **The consent copy (R8; `U120`'s Accept):** a remainder consent and a partial expired re-consent
  each print K of N with the true counts, a full first payment prints as before, and a partial
  expired re-consent's warning names the M blobs this run paid for.
- **Re-fixtured by grant, its assertions unchanged:**
  `expired_proofs_exit_with_their_own_class_and_never_the_usage_code` (`tests/seal_matrix.rs:796`)
  takes its first payment from an EARLIER run (killed at `PostReceiptJournalPreFinalize` through
  `CapturingBackend`), expects exactly 2 consent calls, and keeps its class, exit-29 and message
  assertions byte-unchanged. The guard gets its own test, appended at the end (§5).
- **Kept green:** `expired_proofs_require_a_fresh_consent_before_re_payment`,
  `declining_the_proofs_expired_consent_leaves_the_work_incomplete` and
  `a_retryable_finalize_failure_resumes_without_paying_again` (`tests/seal_resume.rs:417`, `:448`,
  `:478`); `merging_keeps_prior_records_first_and_sums_the_cost` (`resume.rs:1266`); and the
  warning's two needles (`seal_consent.rs:935-936`), green or re-pointed inside R8's grant.

**The plants — proof that those tests can fail**

| Plant | Must redden |
|---|---|
| PS53-1: `prior: None` restored on the arm | G-S53a and G-S53b (*"cost Some(C2), expected Some(C1+C2): the expired payment was forgotten (S53)"*), and G-S53c on the capture's cost |
| PS53-2: the whole replaced receipt carried (`Some(receipt.clone())`) | G-S53a's records clause (*"a replaced record survived into the receipt (D37: never merge expired records)"*). The mock does not model expiry, so this is asserted on the records, not on finalize |
| PS53-3: `paid_atto` taken from the merged receipt | G-S53a (*"outcome.paid_atto C1+C2: the run report claims money an earlier run paid"*) |
| `keep` left empty (`S53` alone) | the T1 test (*"max pays of one address in this run = 2"*) |
| the arm re-quoting `&blobs` again | the T1 test |
| `carry_forward` dropping record-less mappings (that is, `spent_only`) | the T3 test (*"the Submitted mapping survives: … false"*) |
| `prior: None` restored after R6 | `S53`'s tests (the cost) and the T1 test (the records) |
| the old Upload line restored | `U120`'s partial cases |
| the empty-candidate guard removed | the guard's own test |

## 4. What this record does NOT decide

- **`S56`, the cross-run residue (R9).** Minted by this wave's rulings and open for the next wave,
  with its closer and its price (per-group `finalize_batch` re-probing, size M, a D37 Decision 6
  addendum, and `ExpiringOnce`'s two tests moved to a per-transaction double).
- **The record-less mapping's blobs.** R6 keeps a record-less mapping so that it can still be
  resolved; buying its blobs only once is D208's (`S54`: R5 builds records at the branch, R9
  resolves before the money branch, and R10 records the pre-D208 captures as residue).
- **The transactions a T1-shaped work now publishes.** Its final receipt holds two transactions
  where `ab7226f`'s held one (§1.8): the remainder's, which pays for records the receipt keeps,
  beside the replacement's. So `status`'s transaction count and the §7.10 values derived from the
  paying transactions (D208 R12) name the remainder's transaction where `ab7226f`'s final receipt
  did not. No ruling here addresses those values; they are true of the records held, and the
  replaced payment's own transactions are not carried (A′). Recorded for the orchestrator's
  as-built (§6).
- **The replaced payment's evidence.** Its transactions, and any `TxRecord` D208 R9 kept as
  evidence, leave the vault when the arm replaces them (R5, R6), and the bundle's §7.10 names only
  transactions whose hashes map a quote (D208 R12) — supporting evidence only (`MVP-SPEC.md` line
  110). Keeping them is Option D's one gain; refused for now.
- **`MockBackend::double_paid()`'s blind spot.** It keys on quote hashes, so it cannot see a blob
  bought twice under a re-quote (S53-B: two blobs bought twice with `double_paid=0`); 12 call sites
  at `ab7226f` lean on it as a double-payment proof. An instrument finding for the ledger; this
  record's tests count per address instead.
- **The words over the expired shapes.** What the resume plan, `list` and rule 2 say over X-A and
  X-B is D210's; this record changes the arm's money, not those words.
- **New rows.** This record mints none. `S55`, `U120` and `S56` were minted by this wave's rulings:
  `git grep -n -w` at `ab7226f` over `TODO.md` and `tasks/` finds 0 lines for each, against 6 for
  `S53` (the control).

## 5. Edit list — per write scope, with the lane named before this record was written

### L-RESUME3 (round 2) — `S53`, then `S55` and `U120`: §2 R1–R8 (its `S54` work is D208's)

- `crates/antseal-cli/src/pipeline/resume.rs`: the expired arm (`:295-306` at `ab7226f`) with R7's
  guard; R7's this-run set where this invocation's payments land — the pre-pay path after
  `consent_anchor_pay` (`:201-206`) and the remainder arm (`:246-262`), which R7 places outside the
  regions the wave's write scopes name for this file; `consent_anchor_pay`'s `prior` doc
  (`:450-455`), its `ConsentRequest` literal (`:465`, R8) and its merge comment (`:538-545`);
  `complete()`'s doc (`:600-608`); and tests appended at the end of `mod tests`.
- `crates/antseal-cli/src/pipeline/receipt_sink.rs`: `carry_forward` beside `merge_receipts`
  (`:151-164`) with its unit tests; `arm`'s doc (`:333-338`) and `SinkState::prior`'s doc
  (`:216-222`). The sink's code does not change.
- By grant (R8): `crates/antseal-cli/src/pipeline/consent.rs` (`ConsentRequest` and its doc);
  `crates/antseal-cli/src/seal_consent.rs` (the WARNING, the Upload line and their in-file tests,
  `:140-184` and `:915-937`); `crates/antseal-cli/src/seal_run.rs`, ONLY its `ConsentRequest`
  literal (`:620`); and `crates/antseal-cli/tests/machine_mode.rs`, ONLY its `ConsentRequest`
  literal (`:1025`), after L-MONEY2 hands that file over.
- `crates/antseal-cli/tests/seal_matrix.rs`: new tests appended at the end (G-S53c and the
  guard's test); and, by a grant made during implementation, `:796-830` and `AlwaysExpired`'s doc
  (`:697-705`), for the re-fixture in §3.
- `crates/antseal-cli/tests/seal_resume.rs`: new tests appended at the end, only after the
  orchestrator hands it over (L-MONEY2 holds it); until then, in `resume.rs`'s `mod tests` or a new
  in-process test file of the lane's own.
- The module doc's D37 paragraph (`resume.rs:37-49`): P2 §6.6 proposed a wording change, but
  neither R4 nor the lane's scope names it, and its sentence *"the pipeline re-quotes and re-runs
  the consent gate"* (`:45-46`) stays true under R7. Not owed.
- **Builds:** the pipeline's unit tests and the in-process test files in the shared target under
  the lock; plants in a shadow with a private target.
- **Must not:** `crates/antseal-cli/src/seal_resume.rs` (L-MONEY2's), `listing.rs`, `commands.rs`,
  `crates/antseal-net/**` (L-NET4's), any snapshot, or `docs/**`.

### L-MONEY2 and L-NET4 — no edit for this record

L-MONEY2 holds `tests/seal_resume.rs` and `tests/machine_mode.rs` until it reports; D210's copy
reads `payment_recorded`, which this record does not change. L-NET4's trait read
(`payment_tx_state`, D208 R8) is what R5 and R6 rely on; this record adds nothing to
`antseal-net`, which is why the per-transaction age was refused (§1.7).

### The citation lane (round 3) — living-doc citations

At `ab7226f` the living documents cite `resume.rs:6` (`docs/threat-model.md:1852`),
`resume.rs:185-189` (`docs/user/funding-your-wallet.md:291`) and `resume.rs:189-202`
(`docs/user/timestamp-authorities.md:421`) — the last two move with D208's resolution step too —
and `receipt_sink.rs:84-87` three times (`docs/threat-model.md:856`,
`docs/user/wallet-hygiene.md:143`, `:379`), above any edit in that file;
`docs/user/funding-your-wallet.md:186-187` cites R8's Upload line (`seal_consent.rs:140-142`).
Code comments: `crates/antseal-cli/src/pipeline/error.rs:203` and `tests/seal_matrix.rs:700` cite
`resume.rs:288`, and `:701` the expired arm's `:305`; `tests/seal_command.rs:4766` cites
`resume.rs:185`; `tests/list_command.rs:2314` cites `resume.rs:554` and `:571`. All are re-pointed
by meaning after the last code edit.

### RECORDS-3 — this record and dated addenda

D37 (Decision 5's extension and Decision 6's re-quote) and D203 (§6's R7 deviation).

### Orchestrator — `TODO.md`, `tasks/S.md`, `tasks/U.md`, `docs/decisions/README.md`, `docs/instrument-ledger.md`

- `S53`, `S55` and `U120`: their ticks against §3, after L-RESUME3; `S56` stays open.
- This record's index row and register rows.
- The ledger: `double_paid()`'s blind spot (§4), and P2 §6.4's *"none changes"*, false under
  R7's guard for the seal_matrix test (§1.8).
- The hand-overs of `tests/seal_resume.rs` and `tests/machine_mode.rs` to L-RESUME3 after
  L-MONEY2 reports.
- §4's transaction values for a T1-shaped work, when filling §6.
- The close gate: the heavy tier and the devnet E2E (`pipeline/`).

## 6. As built — wave 41, lane L-RESUME3 (recorded in place before this record was first committed)

Every suite, plant and clippy verdict below was read from an exit file, and every red was judged by
its message. This records lane read the lane's exit files and verdict lines back, and each matches
its report, except the plant total and one omitted run, both named below. The rustfmt check has no
exit file (per the lane's report), and the copy-style and personal-data logs end in `ok` lines
without exit files. L-RESUME3 measured against `ab7226f`, ran its red baselines and plants in a
`git archive` shadow with a private target, and ran its in-process suites and clippy in the shared
tree under the locks. It built `S53` on `spent_only` first, then moved `carry_forward`, R7 and the
granted re-fixture into the tree together, then R8; its `S54` half and D208 R12 are D208's. Re-read
for this section, 13 of the lane's 14 files are byte-equal to its final copies, and `resume.rs`
differs from its final copy only by the orchestrator's act below (`:141`, `:143-145`). The
plant-marker `git grep` exits 1, with a positive control.

- **Grants and rulings during the lane** (the dispatch log and the lane's report). R6–R9 were ruled
  while the lane was on `S53`, with R8's grant (`pipeline/consent.rs`, `seal_consent.rs`, and only
  `seal_run.rs`'s literal); the guard's grant opened `tests/seal_matrix.rs:796-830` and
  `AlwaysExpired`'s doc; `tests/seal_resume.rs` was handed over after L-MONEY2's `mod d210`, its
  sha256 checked, so no fallback test file was made; and `tests/machine_mode.rs` was opened for its
  one literal line. The orchestrator's clarification of R6 and its ruling on §4's transactions
  follow.
- **§2 R1, as amended by R6.** `carry_forward`
  (`crates/antseal-cli/src/pipeline/receipt_sink.rs:166-217`, after `merge_receipts`) keeps the
  records whose address is in `keep`, collects the other records' payment-line quote hashes as
  `stale`, keeps each `tx_map` entry whose quote is not stale and each `TxRecord` for which
  `tx.quote_hashes.is_empty() || !tx.quote_hashes.iter().all(|q| stale.contains(q))`, and copies
  `storage_cost_atto` and `gas` whole: *"It drops only the replaced records, their entries, and the
  transactions that paid nothing else … With `keep` empty, it is S53's case."* The arm passes
  `Some(super::receipt_sink::carry_forward(&receipt, &keep))` (`resume.rs:354`) to
  `consent_anchor_pay(…, true, prior)`, which arms the sink with it (`:572`) and merges it at the
  final write (`:606-613`). The file's other hunks are R4's two docs and the tests: `merge_receipts`
  and the capture code are untouched, and the lane changed no `antseal-net` file.
  - **Deviation 1 (ruled): `spent_only` came first.** It was green in the shared tree (lib 336,
    `seal_matrix` 16, `seal_resume` 23) until `carry_forward`, R7 and the re-fixture replaced it.
  - **Deviation from R5's and R6's FIRST sentences on evidence records (both amended in place to
    match): a `TxRecord` that maps no quote is carried.** RECORDS-3 found that the two rules read two ways about one: R6 drops *"only … the
    transactions that paid only those"*, and its last sentence says such a record is not carried.
    The orchestrator clarified during the lane that `carry_forward` keeps every `TxRecord` that did
    not pay through a replaced record, the no-quote evidence records included. The `is_empty()`
    clause keeps one with no quote hashes, and a pruned transaction's record keeps hashes whose
    records are already gone, so none of them is stale.
    `carry_forward_drops_only_the_transactions_that_paid_only_replaced_records`
    (`receipt_sink.rs:1131`) pins it: of the transactions of a replaced record, a kept record, a
    record-less `Submitted` mapping and an unmapped `Reverted` one, the last three are carried, with
    the totals whole. Such a record rides on as evidence; `paying_txs` (`pipeline/journal.rs:1182`,
    D208 R12) keeps it out of every published value and out of the next resolution step.
- **§2 R2.** `paid_atto = paid_atto.saturating_add(quote.total_ant_atto);` (`resume.rs:359`), under
  *"The run report is this run's spend, not the merged total."* On the final code (PS53-3b's
  values) G-S53a's run report is 3678 beside a recorded 9195, as §1.6 measured. G-S53b's is 5517
  beside a recorded 7356, not R2's Option A figures (9195 beside 11 034): under R7 its shape is
  T1's, so the arm keeps the remainder's records and re-buys unit 0 alone (3678 + 1839).
- **§2 R3.** No code; `listing.rs` is unchanged. G-S53a and G-S53b assert `list`'s
  *"cost: {total} atto-ANT"*; no test reads `list --json`'s `cost_atto` for such a work.
- **§2 R4.** Rewritten: `consent_anchor_pay`'s `prior` doc (`resume.rs:506-515`), the merge comment
  (`:607-610`), `complete()`'s doc (`:668-678`), `SinkState::prior`'s doc
  (`receipt_sink.rs:269-276`) and `arm`'s (`:392-394`). `complete()`'s now reads *"An
  expired-proof re-payment replaces the receipt's expired records but carries its totals
  (`carry_forward`: D37 Decision 5, as extended by S31, keeps those records out; S53 keeps the money
  in), so after one the cost still counts the payment it replaced, and every other one made"*,
  citing D37 by name and D179 no longer. `arm`'s names the totals and this run's records, not the
  record-less mappings.
- **§2 R5.** `prune` (`resume.rs:900-928`) subtracts the pruned transaction's share (`:927`):
  *"The cost is subtracted, never recomputed from the records left: the total also carries what a
  replaced payment cost (S53), which no record holds, while a transaction that moved no ANT must
  leave it (D209 R5)."* The resolution step (`:185-198`) runs before the money branch (`:209-211`)
  and the arm (`:328`). It asks every `Submitted` transaction that still maps a quote, and refuses
  the run before any write on one the chain still holds or cannot answer for (the lane's
  deviations 5 and 6, which D208 records). Code-traced: no test combines a prune with an expiry.
- **§2 R7.** `let mut this_run: std::collections::BTreeSet<Address>` (`resume.rs:205`), under
  *"The blobs whose payment records THIS invocation bought: minutes old, so D179's age clause can
  never call them expired, and the proofs-expired arm below never buys them again (S55)."*, is
  filled from the receipt the pre-pay path's `consent_anchor_pay` returns (`:228`) and from the
  remainder's new records (`:284-290`). The arm (`:328-362`) takes as `keep` the receipt's record
  addresses in `this_run` (`:331-336`) and as candidates the staged blobs outside it (`:337-342`).
  Then it guards (`:343-348`), *"Unreachable by D179's age clause: every blob's payment is this
  run's. The verdict stands; consent over nothing is never asked."*, with
  `return Err(SealError::Storage(StorageError::ProofsExpired));`, and only then quotes
  `&candidates` (`:349`). T1 asserts the disjointness (`tests/seal_resume.rs:2113-2118`).
  - **Deviation 3:** the set is filled inside the pre-pay and remainder arms, outside the regions
    the write scopes list for the file, where R7 puts it (§5).
  - **Deviation 4: the guard reddened one existing test, re-fixtured by grant.** A run the report
    omits measured it: the shadow suites over `carry_forward` and R7, before the fix, exited 101
    (lib 335 and `seal_resume` 18 passed; `seal_matrix` 15 passed and 1 failed). The failure was
    `expired_proofs_exit_with_their_own_class_and_never_the_usage_code` at `:820`, *"the first
    expiry re-quotes and re-consents (1 consent call(s))"*. That test now takes its first payment
    from an earlier run, killed at `PostReceiptJournalPreFinalize` through `CapturingBackend`
    (`tests/seal_matrix.rs:808-821`), and asserts `assert_eq!(consent.calls(), 2, …)`
    (`:836-841`, was `>= 2`). `AlwaysExpired`'s doc (`:697-707`) now says the refused payment
    must be an earlier run's, and names the arm where it cited `resume.rs:288` and `:305`. Against
    `ab7226f` the file has four hunks: that doc (−6/+8), the 14-line setup, the count (−2/+3) and
    the appended tests (+284). So its class, exit-29 and message assertions are byte-unchanged.
    The file then passed 17 in the shadow, and under PG1 the re-fixtured test stayed green.
- **§2 R8 (`S55`, `U120`).** `ConsentRequest.work_blob_count` (`pipeline/consent.rs:47-51`) is
  *"How many blobs the whole seal holds"*. Its literals: `resume.rs:536`, read from the journaled
  plan (`plan.expected_slots()?.len()`, else `quote.blobs.len()`; `:525-531`), so neither
  `consent_anchor_pay`'s signature nor `pipeline/seal.rs` changes (every paying path journals the
  plan before it pays, per the lane's report); `seal_run.rs:624`, `work_blob_count:
  dry.blob_count`; the test helper (`seal_consent.rs:589`); and `tests/machine_mode.rs:1029`.
  `ConsentReport.work_blob_count` (`seal_consent.rs:84`) is *"Screen copy only: not a `--json`
  member."*
  - The Upload line (`seal_consent.rs:144-157`) keeps `ab7226f`'s text for a whole-seal quote and
    otherwise reads *"  Upload:      {K} of the seal's {N} blob(s) — the others are already paid
    for"*.
  - The WARNING (`:190-213`): *"  WARNING: a majority of the storing peers refused this seal's
    payment proof, and the payment is more than 24 hours old by its block time. The earlier payment
    for the {priced} blob(s) priced here is stranded and cannot be recovered{, while the {M}
    blob(s) paid for in this run keep their payment}. Consenting here authorizes a SECOND,
    ADDITIONAL payment for them."*, with the clause only when M is not 0.
  - **Deviation 11:** M is N − K, not a second field; on the expired arm that is the kept count.
  - **Deviation, not in the lane's list: the warning counts the quote's `Priced` lines, not K**
    (`:194-199`). A re-quote that finds a blob already stored therefore names fewer: in G-S53a's
    shape the consent covers K = 3 and the warning names the 2 that the re-payment buys.
  - `u120_the_upload_line_names_the_share_of_the_seal_a_partial_quote_covers` (`:1027`) and
    `d209_the_proofs_expired_warning_counts_what_it_replaces_and_what_this_run_keeps` (`:1070`)
    assert the exact lines (*"2 of the seal's 5 blob(s)"*; *"the 1 blob(s) priced here"* with
    *"while the 3 blob(s) paid for in this run keep their payment"*), the old words for a
    whole-seal quote, no clause when N = K, and no `work_blob_count` JSON member. The needles at
    `:966-967` are unchanged and green. Re-checked here: neither new sentence is in
    `tests/snapshots/` or in a document outside the decision records (0 hits; control: `atto-ANT`
    in three `list` snapshots), and `json-envelopes.txt` has no `work_blob_count` (0; control:
    `blob_count`, 2). The R8 shadow run passed `envelope_fixtures_match_the_committed_snapshot`
    among `machine_mode`'s 16.
- **§2 R9.** Not fixed, as ruled; `ExpiringOnce`'s two tests (`tests/seal_resume.rs:417`, `:448`)
  are unchanged and green.
- **§4's transactions, ruled.** T1's final receipt holds two transactions where `ab7226f`'s held
  one, *"this run's two transactions: the remainder's and the replacement's"*
  (`tests/seal_resume.rs:2150-2154`). Both map quotes, so `paying_txs` publishes both, and
  `status`'s count and §7.10's `tx_hashes` and `block_number` take the remainder's transaction in.
  The orchestrator ruled it acceptable before `U32` on D208 R12's precedent (values move, no key
  moves) and told the lane.
- **The tests: twelve new.** Three unit tests in `receipt_sink.rs` (`:982`, `:1065`, `:1131`) and
  the two consent tests above. In `tests/seal_matrix.rs`, G-S53c,
  `an_expired_re_payment_that_strands_keeps_what_the_expired_payment_cost` (`:1235`, over
  `ExpireThenStrand`), and the guard's test,
  `a_this_run_payment_refused_as_expired_keeps_the_verdict_and_asks_nothing_more` (`:1359`). And
  `mod d209` in `tests/seal_resume.rs` (`:1553-2343`, after `mod d210`): G-S53a
  `s53_an_expired_re_payment_records_both_payments_where_list_reads_them` (`:1895`), G-S53b
  `s53_a_remainder_then_an_expiry_in_one_run_records_every_payment` (`:1997`), T1
  `s55_a_remainder_paid_in_this_run_is_never_bought_again_when_an_older_payment_expires`
  (`:2078`), T3 `s55_a_mapping_no_record_uses_survives_the_expired_arm` (`:2170`) and the strand
  row `s55_a_stranded_re_payment_keeps_this_runs_records_on_disk` (`:2257`). Its doubles
  `ExpiringAfterStoring` (`:1691`) and `PerTxExpiry` (`:1758`) forward `payment_tx_state` to the
  mock, and `PerTxExpiry` counts priced lines per blob address (`:1778`), never through
  `double_paid()`.
  - **Red first**, over `ab7226f`'s sources: G-S53c *"the capture forgot what the expired payment
    cost (S53): 1071 on disk, 4284 spent"*, G-S53a *"cost Some(3678), expected Some(9195): the
    expired payment was forgotten (S53)"* and G-S53b *"cost Some(5517), expected Some(11034): …"*,
    the last two P2's figures. `mod d209` over `ab7226f`'s `resume.rs` and `receipt_sink.rs` (with
    L-NET4's `antseal-net`): 0 passed, 5 failed. G-S53a and G-S53b failed as above, T3 with *"no
    blob bought twice in the run"* (2 against 1), T1 with *"keep ∩ candidates must be empty: the
    re-quote priced 2 blob(s) this run had just paid for"*, and the strand row with *"the
    re-payment must not price the manifest this run just bought"*. The unit and consent tests do
    not compile against `ab7226f`; their plants are their proof.
  - **Deviation 2:** G-S53c's figures are 1071 against 4284, not §3's 1839 against 7356 (P2's
    probe, §1.3): this file's fixture prices 1071 a blob. Same shape, same message.
  - **T3 runs on a transaction the mock really mined**, its record stripped (D208 R10's legacy
    shape). P2's made-up hash would read `Absent` and be pruned by S54's resolution, which runs
    first (the lane's finding), so the mapping T3 carries is one that resolution has read as landed.
  - **Green.** In the shadow, `mod d209` passed 5, `seal_matrix` 17 and the unit tests 3. In the
    shared tree, lib 338, `seal_matrix` 17 and `seal_resume` 28 after `carry_forward` and R7.
    After R8 and D208's half, a ten-binary run passed lib 343, `seal_matrix` 17 and `seal_resume`
    35, and its log shows `ok` by name for each of the twelve, the re-fixtured test and §3's five
    kept-green tests. Clippy over all targets with `-D warnings` exited 0 in the tree; the spawning
    suites passed in the shadow (`machine_mode` 16, `receipt_backfill` 5, `reveal_lazy_backend` 7,
    `seal_command` 56).
- **The plants: thirteen for this record**, each with its own exit file (101) and its red read
  back from its log. The first four ran on `spent_only`; PS53-2b and PS53-3b re-ran PS53-2 and
  PS53-3 on the final code.

| Plant | Planted | Red, by message |
|---|---|---|
| PS53-1 | `prior: None` on the arm | G-S53c *"… 1071 on disk, 4284 spent"*; G-S53a *"cost Some(3678), expected Some(9195): the expired payment was forgotten (S53)"*; G-S53b *"cost Some(5517), expected Some(11034): …"*; the unit test green |
| PS53-2 | `Some(receipt.clone())` | G-S53c *"only the partial's record and transaction"*, (4, 2) against (1, 1); G-S53a *"a replaced record survived into the receipt (D37: never merge expired records): 5 records, 5 mappings, 2 txs"*; G-S53b by the same clause |
| PS53-3 | `paid_atto` from the merged receipt | G-S53a *"outcome.paid_atto 9195: the run report claims money an earlier run paid (expected 3678)"*; G-S53b *"outcome.paid_atto 14712: the run report is this run's spend"* (9195 expected); G-S53c green, as its run strands before `paid_atto` is set |
| PU1 | `spent_only` keeping the replaced records | the unit test *"an expired payment's records were carried (D37: never merge expired records)"*; G-S53c (4, 1) against (1, 1); G-S53a and G-S53b at their resume `expect`, *"quote→tx map gap for blob at address …: a non-zero quote has no tx hash"*, D37's stale-record hazard executed |
| PG1 | the guard removed | the guard's test *"a this-run payment refused as expired asked consent again (2 call(s)): the guard returns the verdict and never asks over nothing (S55)"*; the re-fixtured test green |
| PS55-1 | `keep` empty | T1 *"keep ∩ candidates must be empty: the re-quote priced 2 blob(s) this run had just paid for"*; T3 *"no blob bought twice in the run"* (2 against 1); the strand row *"the re-payment must not price the manifest this run just bought"*; G-S53a, G-S53b and G-S53c green |
| PS55-2 | the arm quoting `&blobs` | the same three, by the same messages |
| PS55-3 | record-less mappings marked stale | the first unit test *"only the record-less mapping is carried"*; the clarification's test *"exactly the kept record's, the record-less mapping's and the revert's transactions survive; the one that paid only a replaced record goes"*; T3 *"the record-less mapping and its transaction must survive the expired arm (D209 R6): only the chain can say what U paid for"* |
| PS55-4 | `prior: None`, final code | G-S53c *"… 1071 on disk, 4284 spent"*; G-S53a *"cost Some(3678), expected Some(9195): …"*; G-S53b, T1 and T3 at their resume `expect`, *"no payment record for unstored blob at address …"*; the strand row *"the strand's capture dropped the record this run had just paid for: 1 record(s)"* |
| PS53-2b | `Some(receipt.clone())`, final code | G-S53c (4, 2) against (1, 1); G-S53a *"… 5 records, 5 mappings, 2 txs"* and G-S53b by the D37 clause; T1 and T3 at their resume `expect` with `Storage(ProofsExpired)`, the carried stale record matched first and refused again; the strand row *"the manifest's and the landed sub-batch's"* |
| PS53-3b | `paid_atto` from the merged receipt, final code | G-S53a *"outcome.paid_atto 9195: … (expected 3678)"*; G-S53b *"outcome.paid_atto 11034: the run report is this run's spend"* (5517 expected); T1 *"the run report"*, 11034 against 5517 |
| PR8-1 | the Upload line forced to `ab7226f`'s text | `u120_…`: *"  Upload:      2 blob(s) — every encrypted unit plus the encrypted manifest"* against *"  Upload:      2 of the seal's 5 blob(s) — the others are already paid for"* |
| PR8-2 | the keep clause dropped | `d209_the_proofs_expired_warning_…`: the line lacks *", while the 3 blob(s) paid for in this run keep their payment"* |

- **The plant count, reconciled from the exit files.** The lane's directory holds 20 plant exit
  files, all 101: these thirteen and D208's seven. The lane's summary says 23, but its two reports
  name exactly these 20 plants, so none of the plants they name lacks an exit file, and the
  summary's other three are unaccounted for. The series logs record *"restored … sha ok"* for
  PS55-1–4, PS53-2b, PS53-3b, PR8-1 and PR8-2; the restores of the first four and PG1 are per the
  lane's report. Two of §3's predicted messages printed otherwise. With `keep` empty, T1 reddens at
  its disjointness clause, which it asserts before its per-address maximum, so the maximum of 2 is
  read in T3. And T3's survival clause speaks of *"the record-less mapping and its transaction"*.
- **The orchestrator's act after the lane reported.** `resume()`'s `# Errors` doc
  (`resume.rs:137-145`) said the first expiry *"is handled here (`:288`) and never reaches the
  caller"*, which the guard made false (the lane's finding). Line-neutral, it now names the guard's
  case, *"or if every staged blob was paid for in this run (`:347`, a state D179's age clause makes
  unreachable) — otherwise the first expiry is handled here (`:328`)"*, and its `:475` is `:554`.
  All three point where they should.
- **Left open.**
  - `S56` owns R9's residue: a record a previous run paid is re-bought when an older payment's
    proofs expire in a later run. Its row names the per-group `finalize_batch` closer.
  - `U123` owns the proof-clock sentence that `list`, the resume plan and rule 2 print over a
    receipt whose only paying transactions are unresolved `Submitted` ones. It was minted from the
    lane's proposed row, and is copy only.
  - G-S53c's doc (`tests/seal_matrix.rs:1223-1224`) still says the sink is armed
    *"(`spent_only`)"*, a helper the tree no longer has. With nothing kept and no record-less
    mapping in that fixture, `carry_forward` arms it the same way, so only the name is stale; the
    orchestrator owns it before the commit. The mention at `tests/seal_resume.rs:2167`, as the
    carry that reddens T3, stays true.
  - The citation lane owns the living citations these edits shift. The lane's list adds three to
    §5's: `docs/user/funding-your-wallet.md:63` (`seal_consent.rs:139-158`, `:236-242`), the
    `resume.rs:215-219` on `:292`, and `docs/threat-model.md:1626` (`seal_run.rs:705-707`, one line
    lower since R8's literal). None had moved when this section was written.

## Closing — this record is not consent

It changes what the expired-proof re-payment carries, keeps and re-buys, and two sentences of the
consent screen, inside the wave's own commits. Nothing in it authorises a push, a workflow
dispatch, a deploy or any other outward act; each of those needs the maintainer's express consent
naming the action, the destination and the account.
