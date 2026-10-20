# D203 — A reader takes each fact from its authority: a work's **state from its fine tag**, its **money from its receipt**; and `complete()` **writes the outcome — the work id and the receipt's cost — before the `Complete` tag**

- **Status: RESOLVED. H2 fell (b): its direction survived and its three premises fell. The
  orchestrator's challenge-round counter-lean fell (b) as well: its premise fell, and its
  direction survived for the cost.**
  - **H2 (`S48`)** — *"the READERS are the defect. D45's candidate scan (gather_candidates) and
    `list` (listing.rs) should take a work's state from the fine tag when one exists (D106 — as
    incomplete_works already does), so the window is harmless to them; AND set_state's
    idempotent branch should re-sync a stale mirror (one update_meta) so `antseal abandon`
    repairs the record and reports it truthfully. Both halves, one ruling."* (b):
    - **What survives: the direction.** The readers are the defect, and D106's rule — the fine
      tag when one exists — is the cure (§2 R1, R2).
    - **Premise 1 falls: the reader set is eleven sites in eight files, not two.**
      `abandon_pre_pay`'s rules, D185's preview, `status`, `show`, both `restore` gates, the
      `reveal` gate and the upgrade hook read the mirror as well (§1.3).
    - **Premise 2 falls: `S48` is one window of four, all of one lag.** The lag shows on every
      transition that changes the coarse value. The commonest is `Finalizing → Complete`,
      which every successful seal passes through: a kill there leaves a complete work that
      `list` calls incomplete and that `reveal`, `restore`, `abandon` and the exact re-run all
      refuse (§1.2).
    - **Premise 3 falls: the two halves cannot both be live.** Once abandon's rule 1 reads the
      effective state it returns `already: true` before `set_state`, and no other production
      path re-runs an idempotent `set_state` that changes the coarse value. The writer half is
      dead code, and it is refused (§2 R3).
  - **The counter-lean** (the orchestrator's, sent to P1's challenge round): a kill in window B
    — after `complete()`'s `Complete` tag, before its `record_outcome` — leaves the work with no
    work id, so `restore` and `reveal`, which find a work by its id (`resolve_work_id`), could
    never find it; `complete()` should write its outcome first. (b):
    - **The premise falls.** The work id is first written at **staging**
      (`crates/antseal-cli/src/pipeline/seal.rs:358`), so a single kill in window B keeps it.
      Executed: a work whose `complete()` never ran lists with its id (§1.5).
    - **The direction survives, for the cost.** `complete()` writes the cost only after the
      `Complete` tag, and only when the run itself paid (`if paid_here`). One ordinary upload
      failure and a resume leave a paid, complete work with no recorded cost, for good
      (executed; `S52`). The outcome is written before the tag, and the cost is the
      receipt's (§2 R7).
  - **The money group was not a lean.** P1 measured it in the same challenge round (§1.4), and
    the rulings placed it here as a second group under the same principle: the same readers,
    the same fixtures and the same lane.
- **Date: 2026-10-20**
- Owner rows: **`S48`** (§2 R1–R6), **`S52`** (§2 R7), **`U109`** (§2 M1–M3) and **`U110`**
  (§2 M4–M6). `S52`, `U109` and `U110` were minted by this wave's rulings from P1's findings
  before this record was written; this record mints no row.
- Related:
  - **D106** R4 (*"The fine tag is preferred when present"*, D106:564-568), §5's W4 and W6 rows
    (D106:640, :642) and §11 (iv) (D106:948-954); takes a dated addendum;
  - **D45** §2 (the candidate set, D45:54-55); takes a dated addendum;
  - **D152** R5 (the blocked-work copy's money clause); takes a dated addendum;
  - **D185** §2 R4 and §6 (the abandon preview, question and report); takes a dated addendum;
  - **D194** §1.3 (it quotes `list-report.txt:19-21`); takes a dated addendum;
  - **D197** (the restart predicate; window E is its own abandon's window; its §6 minted
    `S48`); takes a dated addendum;
  - **D204** (`S50`: a first sub-batch that reverts journals nothing, so no new revert-only
    receipt is written; M1's predicate is immune to the old ones);
  - **D36** (a resume re-quotes and re-consents), **D37** Decisions 5 and 6 (the unpaid
    remainder; the proofs' one-day window), **D43** (the cache exclusion), **D186** (class 37);
  - **`S16`** (a journaled receipt, not the state tag, says money moved,
    `crates/antseal-cli/src/pipeline/resume.rs:170-180`) and **`U32`** (no `--json` semantics
    move before it).

## 0. What was measured against

`HEAD` `6e1cab3` (local `main`, one records-only commit ahead of `origin/main` `ab640ae`). The
tree was clean when planning began, on 2026-10-20.

Planning lane P1 (wave 40, 2026-10-20) measured `S48`, then answered a challenge round on
window B and the money question. It EXECUTED both with an in-process probe test (over
`MockBackend`, no spawned binary) added to a `git archive HEAD` shadow copy and built in a
private target, with no repository write. The probe plants each window after a real
`set_state` with the seam the suites already use — load the meta, roll `record.state` back,
store it (`crates/antseal-cli/tests/seal_command.rs:2890-2895`) — and prints what every reader
then says. Every run exited 0 (windows A–E: 5 passed; window F: 1; the challenge round: four
tests in three runs). Code-traced only: the `ant-backend` `restore` handler in `commands.rs`,
and D185's preview in window A (the probe drove the engine).

Before this record was written, the records lane re-read the load-bearing lines through
`git show 6e1cab3:<path>`, because round-1 lanes were editing the tree. Every figure below held,
with these refinements:
- **M1's `recorded_receipt` already exists.** `crates/antseal-cli/src/pipeline/receipt_sink.rs:122`
  defines `pub fn recorded_receipt(store, seal_id)`, with production callers at
  `status.rs:389`, `pipeline/reveal.rs:944` and `pipeline/receipt_backfill.rs:332`, `:391` and
  `:463`. L-RESUME2 found it, and the orchestrator accepted reusing it before this record was
  written: `journal.rs` gains only `effective_work_state` and `payment_recorded` (§2 M1).
- `ResumeCandidate::state`'s doc is `crates/antseal-cli/src/seal_resume.rs:80-81` (the field is
  `:82`). R6's `:84-86`, P1's locator, is `journal_state`'s doc.
- `complete()` is `crates/antseal-cli/src/pipeline/resume.rs:582-604`: `set_state(Complete)` at
  `:597`, then `record_outcome` at `:598-602`, whose cost argument is
  `if paid_here { Some(paid_atto) } else { None }` (`:601`).
- Abandon's rule 2 is the comment at `seal_resume.rs:498` and the predicate at `:499-500`;
  `S16`'s comment is `resume.rs:170-179`, read at `:180`; and the receipt write in
  `consent_anchor_pay` is `resume.rs:544` (P1: `:498-499`, `:172-182`, `:543`).
- `WorkStore::set_state`'s two test callers are two-line calls (`tests/work_store.rs:243-244` and
  `tests/show_command.rs:226-227` — the second corrected in place by the orchestrator before first
  commit, measured by the wave-40 ledger lane), so a one-line `git grep` for `store\.set_state`
  finds only `mark_complete`'s caller (`:230`).
  Neither function has a production caller; the only other call is `mark_complete`'s own
  (`crates/antseal-cli/src/vault/store.rs:478`).

## 1. What was measured

### 1.1 The mirror can only trail the tag

- **The two writes.** `crates/antseal-cli/src/pipeline/vault_journal.rs:141-149`
  (`write_state`): the fine tag first (`put_journal_entry(seal_id, STATE_ENTRY, …)`, `:145-146`),
  then the coarse mirror (`update_meta(… record.state = state.work_state())`, `:148`), each the
  store's atomic, fsync'd write (`:4-8`). The comment above it (`:137-140`): *"A crash between
  them leaves the mirror one barrier stale, which no safety rule reads — whereas the reverse
  could show a work as paid before its receipt-bearing state record exists."*
- **The module doc already names the authority** (`:16-18`): *"if the two ever disagreed, the
  fine tag is authoritative and the mirror is what a repair would rewrite."*
- **`begin` is the one write in the other order** (`:153-178`): the meta record with the mirror
  `IncompletePrePay` (`:160`, `:172`), then the `Staged` tag (`:176-177`). That is D106's W2, a
  tag ABSENT over a pre-pay mirror, which the absent-tag fallback already reads correctly.
- **No production code writes the mirror alone** (§0). So a crash leaves "tag written, mirror
  stale", never the reverse. The vault lock does not change that: a killed process drops its
  lock and leaves the durable state for the next run, and `list` and `status` take no lock
  (D106).
- **Four coarse values, six fine ones.** `crates/antseal-cli/src/pipeline/journal.rs:232-239`:
  `Staged | Anchored => IncompletePrePay`, `Paid | Finalizing => IncompletePostPay`,
  `Complete => Complete`, `Abandoned => Abandoned`. The lag is visible only on the transitions
  that change the coarse value: `Anchored → Paid`, `Finalizing → Complete`, and every
  `→ Abandoned`.

### 1.2 Four windows of one lag, executed

Each window was planted after a real `set_state` (§0); P1 §2 `S48` (a2) quotes every printed
line.

| Window | Transition and producer | What the readers said at `6e1cab3` |
|---|---|---|
| **A** (`S48` exactly) | `Staged`/`Anchored → Abandoned`: S11's best-effort abandon (`resume.rs:330`), `antseal abandon` (`seal_resume.rs:520-522`), D197's restart (`seal_run.rs:530-533`) | `list` offers the resume (`re-quote`) and counts the work incomplete; the exact re-run prints *"Resuming the interrupted seal …"*, then exits 2, *"this work is abandoned and cannot be resumed"*; `antseal abandon` writes nothing (the whole-vault fingerprint is identical) and reports `already: false` beside `previous_state: "abandoned"`; an overlapping run exits 25 and a flag variant 26, each naming the command that exits 2 |
| **B** | `Finalizing → Complete`: `complete()` (`resume.rs:597`), i.e. **every** successful seal and resume | `list` calls the work incomplete, with *"RESUME PROMPTLY: this seal is paid for …"*; `abandon` exits 2, *"has already been paid for … Finish it instead by re-running …"*; that re-run exits 2, *"this work is complete and cannot be resumed"*; the restore and reveal engines refuse it (executed, P1 §7.3), and so does the `restore` handler, as `incomplete-post-pay` (code-traced). A permanent dead end |
| **C** | `Anchored → Paid`: `resume.rs:561`, the repair at `:209` | resume and abandon are right (they read the receipt); `list` says *"re-quote"*, *"nothing was paid; …"* for a paid work |
| **D** | `Paid → Abandoned`: S11 only | `list` says `RESUME PROMPTLY` for an abandoned work; `abandon` exits 2, *"already been paid for"*; its re-run exits 2, *"abandoned and cannot be resumed"* |
| **E** | D197's restart, killed inside its own abandon | `detect` returns `Resume`, not `Restart` (D197's clause 3 needs the tag absent or `Staged`, `seal_resume.rs:832-835`), and the exact re-run exits 2 on every run: D197's promise is defeated by its own abandon's window |

Rule 2 refuses windows B and D (`seal_resume.rs:499-500`) before `set_state`, so no writer-side
repair can reach them.

### 1.3 Eleven classifying readers in eight files read the mirror

P1's census (P1 §2 `S48`, "Census"), which L-RESUME2 re-ran at the same lines; the rows below
were spot-checked through `git show 6e1cab3`.

| # | Reader at `6e1cab3` | What it decides |
|---|---|---|
| 1 | `seal_resume.rs:217-220`, `gather_candidates`' filter (and `:230`, `state: record.state`) | D45's candidate set: the exact re-run, 25 and 26 |
| 2 | `seal_resume.rs:477-495`, `abandon_pre_pay` rule 1 | the complete-refusal and `already: true` |
| 3 | `seal_resume.rs:499-500`, rule 2's `\|\| meta.state == IncompletePostPay` | the paid-refusal (its receipt clause comes first) |
| 4 | `seal_resume.rs:652`, `AbandonPreview::read` | whether D185's preview and question are shown |
| 5 | `seal_resume.rs:877`, `resume_plan_lines` (`candidate.state`) | the "already paid for" line; follows row 1 |
| 6 | `seal_resume.rs:830`, `staging_never_finished` clause 1 | D197's restart; unreachable for a fine-terminal work once row 1 reads the tag |
| 7 | `listing.rs:612`, `WorkListing::gather` | `state`, the resume hint and its clock, `resume_refusal` (`:634-639`), `counts()` (`:676-681`) |
| 8 | `status.rs:410` | the badge and `--json` `state` |
| 9 | `show.rs:464` | the state line and `--json` `state` |
| 10 | `commands.rs:730`, the `#[cfg(feature = "ant-backend")]` `restore` handler (`:706-707`) | the `NotRestorable` pre-check |
| 11 | `pipeline/restore.rs:562` | `NotRestorable` |
| 12 | `pipeline/reveal.rs:591`, the only `.sealproof` producer | `NotRevealable` |
| 13 | `upgrade_hook.rs:412` | which works get opportunistic OTS upgrades |
| 14 | `vault/export.rs:551` (the import check) and `:777` (the export's cache exclusion) | D43's cache exclusion |

- **Only one field prefers the tag:** `listing.rs`'s `detail_state_name` (`:504-509`). The
  comment above the tag read (`:600-601`, *"The fine tag is preferred; its absence is a state,
  not a failure"*) is true of that field alone.
- **The one enumeration that prefers the tag has no production caller.**
  `VaultJournal::incomplete_works` (`vault_journal.rs:373`) reads the tag and falls back to the
  mirror only when it is absent (`:380-389`). `git grep -n 'incomplete_works()' 6e1cab3 --
  crates/` finds test files, a test's name inside `seal_resume.rs`'s `mod tests` (`:981`) and
  the test double at `resume.rs:1507` (inside `mod tests`, which opens at `:689`). D106 §11 (iv)
  recorded the duplication, and it was never minted. So D106's W4 justification — *"R4
  preserves it by preferring the fine tag whenever present"* (D106:640) — was true only of code
  that tests reach.
- **No reader relies on the mirror being authoritative.** Where a tag exists the mirror can only
  trail it (§1.1). Where none exists (D106 W2, an old import) the fallback is the mirror itself.
  The one place where trusting a tag was a real defect is the money question (`S16`), and that
  question is the receipt's (§1.4).

### 1.4 Money: the receipt is the authority, and three surfaces ask something else

- **`S16`'s rule.** `resume.rs:170-179`: *"A journaled receipt is what says money moved — not the
  state tag."* `resume` applies it (`:180`, `:184`), and so does abandon's rule 2
  (`seal_resume.rs:498-500`). `list` never reads a receipt: `listing.rs`'s only `receipt` hits
  are the doc lines `:37`, `:234` and `:1459`.
- **What a receipt's `tx_map` means.** A confirmed landing maps its quotes
  (`crates/antseal-net/src/ant_backend.rs:792-794`). An unobserved landing maps them to the
  submitted hash with status `Submitted` — *"money MAY have moved"* (`:722-734`). A revert maps
  nothing (`:771-775`). So the mapped quotes are exactly the ones a resume will not re-buy, and
  what exit 28 promises.
- **The stranded shape is the normal state after an exit 28 or 37 with at least one durable
  capture.**
  `resume.rs:500-517` returns before any `set_state(Paid)`, so the tag stays `Anchored` over a
  receipt that maps paid quotes. Executed (`[C-stranded]`): `list` prints *"re-quote"* and
  *"nothing was paid; the recorded quote is stale by design — resuming re-quotes at current
  prices and asks for consent again"*, and withholds `RESUME PROMPTLY`, while the landed
  sub-batches' proofs expire in about a day (D37 Decision 6).
- **The cases, executed** (P1 §7.7):
  - **(a) exit 37 with no durable capture** (tag `Anchored`, no receipt). **No vault record says
    that money moved.** The sink's fault lives in memory
    (`crates/antseal-cli/src/pipeline/receipt_sink.rs:214-237`), and its one disk write is
    `put_receipt` (`:442`). The consent record (`resume.rs:472-473`) is authorisation, and it is
    present identically after a `Payment` failure before any landing. Yet HEAD says *"nothing was
    paid"* (`list`), *"staged and anchored; nothing paid"* (the resume plan, `seal_resume.rs:859`),
    *"staged and past its anchor step; not paid"* (the preview, `:691`) and *"Nothing was paid
    for it and nothing was uploaded."* (the report, `:383`). Those are four claims the vault
    cannot back, and they contradict 37's own text (`crates/antseal-cli/src/error.rs:831`:
    *"everything the vault does not show as paid"*).
  - **(b) a revert-only receipt written before `S50`.** Abandon refuses *"already been paid
    for"* and the preview is suppressed, because both key on `receipt.is_some()`
    (`seal_resume.rs:499`, `:653`); `resume.rs:184` takes the receipt branch on it too.
  - **(c) stranded** (`Anchored` and a mapped receipt). `list` says *"re-quote"* and *"nothing
    was paid"*; the resume plan says *"staged and anchored; nothing paid"* and *"pay, upload"*.
  - **(c2) (c) and a DECLINED remainder.** The early repair (`resume.rs:203-210`,
    `set_state(Paid)`) runs before the remainder is quoted and consented (`:223-258`), and a
    decline returns with no transition (`:476`). The work is left tagged `Paid`
    (`[c2-after] fine=Some(Paid)`). The next plan says *"PAID — the payment receipt is
    journaled"*, *"upload only (no further payment)"* and *"This seal is already paid for.
    Finishing it needs no further payment"*, while the whole remainder is owed.
  - **(d) a normal `Paid` work.** The clock is right, but the row's cost line says *"cost: not
    recorded (nothing paid)"* (`listing.rs:748`): the meta's cost is written only at completion.
  - **(e) D197's pre-staging work.** No receipt; `detect` gives `Restart`, and the preview's
    *"staging was interrupted before it finished; not paid"* (`seal_resume.rs:687`) is true.
- **Not affected:** `status` (its money line reads the receipt, `status.rs:562`, *"paid in {}
  transaction(s)"*), `show` (no money claim), the run report (`paid_here`,
  `seal_run.rs:127-131`), and `cli-errors.display.txt`'s *"nothing was paid"* lines (`:10`,
  `:12`, `:46`, `:48`, `:98`: a declined or unobtainable consent, a funding shortfall and an
  entropy abort, all run-level truths).

### 1.5 `complete()`: the tag before the outcome, and a cost only for the run's own payment

- **The order.** `resume.rs:597` writes `set_state(seal_id, SealState::Complete)`; then
  `:598-602` calls `record_outcome(seal_id, Some(id), if paid_here { Some(paid_atto) } else {
  None })`. The id is computed before both (`:593-596`).
- **The outcome's one writer.** `VaultJournal::record_outcome` (`vault_journal.rs:357-371`) is
  the only code that assigns `work_id` and `cost_atto`, and it skips a `None`. It has two
  production callers: staging (`pipeline/seal.rs:358`, through `:202-204`, the id only) and
  `complete()`.
- **The work id is written at staging.** `seal.rs:358`, `sink.record_outcome(&seal_id,
  work_id_bytes)?;`, runs right after `put_plan` (`:351-357`) and before
  `Barrier::PostStagingJournal` (`:359`), on every run that journals (`:273-277`). Executed: a
  work whose run paid and then failed lists with its id (`[CC-after-run1]`, `state:
  finalizing`). Only a double kill — the staging gap `:357 → :358`, then `complete()`'s — or an
  import lacks it.
- **A work finished by a resume never records its cost.** Executed
  (`challenge_cost_of_a_resume_completed_work`): run 1 pays, then fails mid-upload (*"network
  failure … aborted after storing 1 blob(s)"*, exit 23), leaving the meta's cost `None` and the
  receipt's `storage_cost_atto` 18 498; `list` prints *"cost: not recorded (nothing paid)"*
  directly above *"RESUME PROMPTLY: this seal is paid for"*. Run 2 resumes and finishes; the
  meta's cost is still `None`, and `list` says *"complete … cost: not recorded (nothing paid)"*
  for good. The cause is `if paid_here` (`:601`): `paid_here` is the run's own payment.
- **The receipt holds the answer.** `merge_receipts` (`receipt_sink.rs:151-164`) accumulates
  `storage_cost_atto` across rounds with `saturating_add` (`:156-158`).
- **Window B's four variants** (P1 §7.3; each completed for real, then planted). With neither
  the id nor the cost (B1, B2), `resolve_work_id` — the only lookup from a work id to a work —
  fails, *"no work with this id exists in the vault"*. With the id and no cost (B1′, which is
  §1.2's window B, and B2′) it succeeds. After §2 R1, R2 and R7, B1, B2 and B2′ cannot arise, and
  B1′ is a complete work with its id and its cost.
- **The reorder reintroduces no hazard.** The hazard in `vault_journal.rs:137-140` concerns the
  order inside `write_state`, and `record_outcome` writes neither the tag nor the mirror.
  D106's W8 (`update_meta`'s lost update between two writers) is unchanged: the same two
  `update_meta` calls run under the same lock.

### 1.6 Export and import read the mirror together

`vault/export.rs:551` refuses to import a complete work that carries staged unit blobs (*"a
complete work carries staged unit blobs (the D43 cache is never exported)"*), and `:777`
decides the export's cache exclusion from `record.state == WorkState::Complete`. Switching only
the export side to the effective state would make the import refuse a window-B′ export.

### 1.7 The options (P1 §2 `S48` (c), §7.5)

- **W — the writer re-sync alone** (H2's second half). It reaches window A only, and only when
  the user happens to run `antseal abandon`: rule 2 refuses windows B and D before `set_state`,
  and the exact re-runs of A and E end in `NotResumable` with no `set_state`. The trap of exits
  2, 25 and 26 stays until the user guesses. Rejected.
- **X — reverse `write_state`'s two writes.** Two lines, but it inverts D106's principle: a
  crash would leave the derived mirror AHEAD of the authority, which makes
  `vault_journal.rs:16-18` false. It also leaves the readers that prefer the tag
  (`detail_state`, `resume_plan_lines`, `staging_never_finished` clause 3, `incomplete_works`)
  on a stale tag, and heals no vault already in a window. Second-best.
- **R — every classifying reader takes the effective state.** D106 R4's own rule, applied to
  production. It heals existing vaults with no write and leaves the money question on the
  receipt. Ruled (§2 R1, R2).
- **R and W together** — W is dead code under R. Refused (§2 R3).
- **For `complete()`.** Deriving the id from the plan's manifest when the meta lacks it would
  decrypt every id-less work's plan on every lookup, for a shape that only a double kill or an
  import produces: not worth it. Repairing on the next vault open is refused: `list` and
  `status` take no lock and must not write. **The reorder with the cost from the receipt** is
  S-sized and closes the defect at its source. Ruled (§2 R7).

## 2. RULING

The principle is one: **a reader takes each fact from its authority** — a work's state from its
fine tag (D106), its money from its receipt (`S16`). It is ruled in two groups.

### The state group (`S48`, `S52`; lane L-RESUME2)

#### §2 R1 — One function names the effective state

`pub fn effective_work_state(fine: Option<SealState>, mirror: WorkState) -> WorkState` (`const`
if it compiles) in `crates/antseal-cli/src/pipeline/journal.rs`, beside `recorded_state`
(`:1113`): `match fine { Some(s) => s.work_state(), None => mirror }`. Its doc says that the
mirror can only TRAIL the tag — `write_state` writes the tag first, and each write is atomic and
fsync'd — so where a tag exists it is the answer, and the mirror answers only for an absent tag
(D106 W2's `begin` window, old imports). It may be re-exported from `pipeline/mod.rs`.

*Why:* it is D106 R4's rule (D106:564-568), which ran only in a test-only enumeration (§1.3).
It needs no write, so it also heals a vault already caught in a window.

#### §2 R2 — Every classifying production reader takes the effective state

- `seal_resume.rs`: `gather_candidates`' filter and the candidate's `state`; `abandon_pre_pay`
  rule 1 and rule 2's mirror clause; `AbandonPreview::read`.
- `listing.rs`: `WorkListing::gather` — the state, the resume hint, `resume_refusal` and
  `counts()`.
- `status.rs` (`WorkStatus::gather`) and `show.rs` (its state read).
- `pipeline/restore.rs` (`:560-573`) and `pipeline/reveal.rs` (`:589-601`): their state gates.
- `commands.rs` (`:728-735`): the `#[cfg(feature = "ant-backend")]` `restore` handler only.
- `upgrade_hook.rs` (`:408-420`).

These are census rows 1, 2, 3, 4, 7, 8, 9, 10, 11, 12 and 13 (§1.3). Row 5 follows row 1 with no
edit of its own, and row 6 is unchanged.

*Why:* all four windows, and E, are readers' defects (§1.2). Fixing two of the eleven readers
would leave `reveal` refusing a complete work and `abandon` reporting a false `already: false`.

#### §2 R3 — No mirror repair anywhere

The writer-side re-sync is REFUSED: under R2 it is dead code (§1.7). `antseal abandon` over
window A reports `already: true` and `previous_state: "abandoned"`, writes nothing, and renders
the existing *"Work {id} was already abandoned; nothing changed."* (`seal_resume.rs:366`).

#### §2 R4 — The money question stays on the receipt

Abandon's rule 2 keeps its receipt clause first. Its predicate is M6's.

*Why:* trusting a tag about money is the defect `S16` fixed (§1.4); the effective state answers
where a work stands, not whether it was paid.

#### §2 R5 — Export and import stay on the mirror, together

`vault/export.rs:551` (the import check) and `:777` (the export's cache exclusion) are not
switched (§1.6). The residue is recorded: a window-B′ work exports its staged units (the D43
cache), and the export imports cleanly.

#### §2 R6 — Comments

- `vault_journal.rs:137-140`: *"which no safety rule reads"* gives way to R1's rule and to
  `S48`'s measurement.
- `ResumeCandidate::state`'s doc (`seal_resume.rs:80-81`, §0): the effective state.
- `listing.rs:600-601`.

*Why:* each states a rule the code did not follow (§1.3), and the first is the sentence `S48`
falsified.

#### §2 R7 — `complete()` writes its outcome before the `Complete` tag (`S48`, `S52`)

`complete()` (`pipeline/resume.rs:582-604`) writes the work id AND the cost before
`set_state(Complete)`.
- **The cost is the journaled receipt's `storage_cost_atto`** — the money authority,
  accumulated across rounds by `merge_receipts` — whenever a receipt is journaled, whatever
  `paid_here` says.
- **With no receipt, today's value stands:** `Some(paid_atto)` if `paid_here`, else `None`. The
  lane measures what a zero-payment completion journals and reports it.
- **`paid_here` keeps its one job:** the run report (`seal_run.rs:127-131`), which is about the
  run, not the work.
- **The reorder's own new crash point** — after `record_outcome`, before the tag — leaves
  `Finalizing` with the id and the cost. The resume finishes it, and its `complete()` records
  the same cost again.

*Why:* §1.5. The counter-lean's premise fell, because the id survives a single kill. The cost
does not: a single kill in window B loses it, and so does every work that is paid in one run
and finished by a resume, which needs no crash at all.

#### The residual this record owns, unfixed

After a kill in window B′ the effective state is `Complete`, so the exact re-run seals the files
afresh, as a new work, after the consent screen has shown its cost. That is D45 §2's rule for
every complete work (*"a finished seal never blocks re-sealing the same files"*,
`seal_resume.rs:46-48`), and this record does not introduce it: HEAD avoided the second payment
only by refusing the files for good. What a user needs after such a kill — the work id and a
proof bundle — `list` and `reveal` now give. A notice for an exact match to a complete work is
left open (§4).

### The money group (`U109` → L-RESUME2; `U110` → L-MONEY)

#### §2 M1 — One predicate, and one wording rule (L-RESUME2)

- **The predicate**, in `pipeline/journal.rs`: `payment_recorded(receipt) :=
  receipt.is_some_and(|r| !r.tx_map.is_empty())` — *"this vault holds a receipt that maps at
  least one quote to a transaction"*. The receipt is read with the existing `recorded_receipt`
  (`pipeline/receipt_sink.rs:122`). The rulings' second function, a `recorded_receipt` in
  `journal.rs` beside `recorded_state` and `recorded_plan`, is not added (§0).
- It is exactly the set of quotes a resume will not re-buy, and what exit 28 promises. It
  includes a `Submitted` mapping (money MAY have moved: conservative) and excludes `Reverted`
  transactions, which are never mapped, so a revert-only receipt written before `S50` does not
  satisfy it (§1.4).
- **The wording rule.** Where the vault holds no such receipt, copy says *"no payment is
  recorded"*, never *"nothing was paid"*. An exit 37 with no durable capture leaves no vault
  record that money moved — the sink's fault lives only in memory — and the consent record is
  authorisation, not payment.

*Why:* `S16`'s rule, applied to every money sentence (§1.4). The predicate lives in
`antseal-cli`, so it never collides with L-NET3's `antseal-net` files.

#### §2 M2 — `list`'s clock and its notes follow the receipt (`U109`, L-RESUME2)

The clock is `time-boxed` if and only if `payment_recorded`; otherwise it is `re-quote`. The
notes:
- `re-quote`: *"no payment is recorded for it; the recorded quote is stale by design — resuming
  re-quotes at current prices and asks for consent again"*;
- `time-boxed`: *"RESUME PROMPTLY: a payment for this seal is recorded, and its payment proofs
  stay usable for uploading only about a day — after that, finishing it costs a second
  payment"*.

`blocked_lines`' money clause (D152 R5's copy, `listing.rs:1488-1503`) follows the same
predicate and the same wording rule.

*Why:* stranded money, on a one-day clock, read *"re-quote"* and *"nothing was paid"*; and
*"this seal is paid for"* is false in case (c), where a remainder is owed (§1.4).

#### §2 M3 — `list`'s cost line (`U109`, L-RESUME2)

`cost: {meta cost} atto-ANT` when the meta records one; else, if `payment_recorded`,
`cost: {receipt.storage_cost_atto} atto-ANT so far (from the payment receipt)`; else
`cost: none (no payment recorded)`. `--json`'s `cost_atto` is UNCHANGED this wave (the meta's
value only): no JSON semantics move before `U32`.

*Why:* case (d) and the sequence in §1.5 printed *"cost: not recorded (nothing paid)"* for paid
works. The rule needs no write, so a vault already in that shape is corrected on read.

#### §2 M4 — The resume plan (`U110`, L-MONEY)

`resume_plan_lines` (`seal_resume.rs:849-885`; the resume consent screen and `seal --json`): an
`Anchored` work with `payment_recorded` → *"staged and anchored; partly paid — a payment receipt
is journaled"*, remaining *"pay the rest, upload"*; without → *"staged and anchored; no payment
recorded"*. The lane may tighten the wording, keeping every clause true.

*Why:* in case (c) the plan said *"nothing paid"* and *"pay, upload"* for a work with money on
the network, and in case (a) *"nothing paid"* is a claim the vault cannot back (§1.4).

#### §2 M5 — `Paid` again means "fully paid" (`U110`, L-MONEY)

The early repair (`resume.rs:203-210`, `set_state(Paid)` on a pre-pay tag with a journaled
receipt) runs ONLY when nothing remains to buy: no uncovered candidates, or a remainder quote
that priced nothing. Otherwise `consent_anchor_pay` sets `Paid` after paying the remainder
(`:560-562`), and a DECLINED remainder leaves the tag pre-pay. The lane proves that finalize
still runs on every path that reaches it: the repair's own comment says `Anchored → Finalizing`
is not a legal edge.

*Why:* case (c2) (§1.4). A predicate cannot correct lines keyed on the tag; the tag has to mean
what they say.

#### §2 M6 — Abandon and resume key on the predicate, and the abandon copy says what the vault knows (`U110`, L-MONEY)

- `abandon_pre_pay` rule 2 (`seal_resume.rs:499-500`), `AbandonPreview::read` (`:652-653`) and
  `resume.rs:184` key on `payment_recorded` instead of `receipt.is_some()`. That cures window F —
  a revert-only receipt — in vaults written before `S50`; D204 stops new ones being written.
- The copy: *"not paid"* → *"no payment recorded"*; *"Nothing was paid for it"* → *"No payment
  is recorded for it"*. At `6e1cab3` the second phrase occurs in the report (`:383`) and in the
  confirmation question (`:723`, inside `question()`, whose doc calls it *"verbatim from D185
  R4"*), and the preview type's doc quotes it (`:615`). The first occurs in all three progress
  arms (`:687`, `:689`, `:691`). P1 found the pre-staging and `Staged` arms true as they stand
  (§1.4 (e)), so whether those two change is the lane's to decide and report; D197 quotes the
  pre-staging arm (§4).

#### §2 M7 — Snapshots

`crates/antseal-cli/tests/snapshots/cli-errors.display.txt` is untouched: its *"nothing was
paid"* lines are run-level truths (§1.4). Regenerated deliberately, with every changed line
justified: `list-report.txt`, `list-blocked-work.txt`, `list-anchor-nags.txt`, and
`json-envelopes.txt` — its `:26` (the `list` note; L-RESUME2) and its `:36` (the `seal` resume
plan; L-MONEY).

### §2 — rules added during implementation (2026-10-20, in place before first commit)

The orchestrator ruled these while the money group was being built: M6a–M6c from RECORDS-A's
findings, as part of M6; M8 (`U113`), M9 and the residue check from L-RESUME2's report; and two
amendments to M4 at L-MONEY's first grant. They bind as the rules above do.

- **M6a — the question and the type doc.** The confirmation question and the type doc carry the
  same claim: `AbandonPreview::question` (`seal_resume.rs:723` at `6e1cab3`, D185 R4's text,
  asserted three times in `seal_command.rs`) and the type's doc (`:615`) say *"Nothing was paid
  for it"*, so the M1 wording rule applies (*"No payment is recorded for it"*), and the three
  assertions are updated. *(Added in place before first commit; see §6.)*
- **M6b — "not paid" only where the vault proves it.** *"not paid"* stays only where the vault
  proves that no payment could have started: no consent record exists for the work. A payment is
  made only after consent, and the consent record is `consent_anchor_pay`'s write
  (`resume.rs:472-473` at `6e1cab3`). D197's pre-staging line (*"staging was interrupted before
  it finished; not paid"*) is an example, if the lane measures that no consent can exist before
  staging finishes. Everywhere else the copy says *"no payment recorded"*. The lane measures where
  the consent record lives, applies the rule line by line, and lists each line's verdict in its
  report. *(Added in place before first commit; see §6.)*
- **M6c — rule 2's refusal.** Abandon's rule-2 refusal says *"… no further payment is needed"*
  (`seal_resume.rs:506-507` at `6e1cab3`), which is false for a stranded, partly paid work: it
  contradicts M4's *"pay the rest"*. Its way forward must be true of both a fully and a partly
  paid work, for example *"Finish it instead by re-running `…`: no quote the receipt already maps
  is paid again"*. Plant: the old string, red by message, on a partly paid fixture.
  *(Added in place before first commit; see §6.)*
- **M8 (`U113`, L-MONEY) — an undecodable receipt never fails the whole `list`.**
  `WorkListing::gather` turns one row's receipt read error into a per-row datum, like D100 R3's
  `damaged_anchors`. That row's money clause and cost line say that the receipt cannot be read —
  no payment claim either way, and no clock that implies one; the lane words it, every clause
  true — and every other row renders as before. Tests: a vault with one planted undecodable
  receipt lists every work, and the damaged row says so; the plant propagates the error, so the
  whole list fails, red by message.
  - **The boundary** (the second and third grants to L-MONEY). The datum,
    `WorkRow::damaged_receipt: Option<&'static str>`, holds decode refusals only (`Corrupt`,
    `NewerRecord`) and is never serialized; store and cipher failures still fail `list`, per D100
    R5. `listing.rs` mirrors `StoredAnchors::read`, so `decode_receipt` becomes `pub(crate)` (one
    token). An oversize receipt is the control test, and a string-match fallback is refused.
  - **The JSON ruling, option (a)**, which answers M8's *"`--json`: no new member this wave unless
    one already exists for damaged rows that fits"*. No new member and no new clock value before
    `U32`. An unfinished row with an undecodable receipt keeps `clock: "time-boxed"`, because a
    receipt exists only once `pay()` began, and its `note` is the sentence that says the receipt
    cannot be read. *(Added in place before first commit; see §6.)*
- **M9 (L-MONEY) — fixture realism.** `list_command.rs`'s anchor-fixture row *"anchored, killed
  before finalize"* is a pre-pay work with a recorded cost (11) and no receipt — a shape the
  pipeline never writes, because the meta's cost is written only by `complete()` — and its
  snapshot row reads *"cost: 11 atto-ANT"* above *"no payment is recorded for it"*. Drop the cost
  from that fixture row, or give it the receipt that would carry it — the lane picks the shape the
  pipeline produces and says which — and re-bless `list-anchor-nags.txt` for exactly the lines
  that move, justified. *(Added in place before first commit; see §6.)*
- **The residue to check after M6 (report, do not widen).** A post-pay tag over a revert-only
  receipt — reachable only through the pre-M5 early repair in a pre-`S50` vault — is still
  refused by rule 2's state clause while `list` says *"no payment is recorded"*. The lane records
  it as a legacy-vault residue unless a one-line fix in its own files makes both true.
  *(Added in place before first commit; see §6.)*
- **M4, amended — the data path (shape C).** `resume_plan_lines(candidate, receipt:
  Option<&PaymentReceipt>)`: `seal_run.rs` reads the matched work's receipt through
  `recorded_receipt` in one expression (`:381` at `6e1cab3`), `tests/machine_mode.rs` passes
  `None`, and `json-envelopes.txt:36` stays byte-identical, with no re-bless. P1's
  `ResumeCandidate` field is refused: it would read every same-network receipt in D45's scan,
  which is M8's failure class. *(Added in place before first commit; see §6.)*
- **M4, amended — the wording.** Accepted: *"staged and past its anchor step"* for *"staged and
  anchored"*, *"a payment is recorded"* for *"partly paid — a payment receipt is journaled"*, and
  *"pay the rest, if any, then upload"* for *"pay the rest, upload"*. Partly paid is false for a
  full receipt under an `Anchored` tag. *(Added in place before first commit; see §6.)*

### What no ruling here moves

- **No exit code, class, `CliError` variant or Display template.** `cli-errors.display.txt` stays
  byte-identical.
- **No `--json` key is added or removed.** Values change in three ways: inside a crash window,
  `list`'s `state`, `counts` and `resume`, `abandon`'s `already`, and `status`'s and `show`'s
  `state`; for a stranded work (case (c)), `list`'s `resume.clock`, `re-quote` → `time-boxed`;
  and everywhere, `list`'s note text and `seal`'s `resume_plan` lines. `cost_atto` keeps its
  meaning (M3).
- **Unchanged:** `vault/export.rs`, `vault/store.rs`, `resume`'s terminal check on the fine tag
  (`resume.rs:147-151`), `staging_never_finished` (census row 6), and every `antseal-net` file.
- **The gate:** HEAVY + E2E (`ANTSEAL_GATE_HEAVY=1 ANTSEAL_GATE_E2E=1`). The `restore` handler
  compiles only in the heavy tier, and the seal and resume path moves.

## 3. Fault plants

The implementing lanes owe these. The red baselines come first, on the unedited tree — P1's
probe is the red baseline for G1, G2 and GM1–GM5 — and each plant is judged by its **message**;
every restore is followed by a `touch`. In-process tests run in the shared target under the
lock; spawned tests and plants run in a shadow copy with a private `CARGO_TARGET_DIR`.

**The green tests — the load-bearing half**

The state group (L-RESUME2):
- **G1 — the Accept: window A exactly.** `detect(exact)` = `Fresh { incomplete_works: 0 }`; the
  exact re-run through `run_seal` seals under a NEW seal id; `WorkListing::gather` gives the row
  the state `Abandoned`, no resume, and counts `abandoned: 1, incomplete: 0`;
  `AbandonPreview::read` = `None`; `abandon_pre_pay` = `already: true`, with
  `IsolatedVault::fingerprint` unchanged; the overlapping run and the flag variant are `Fresh`.
  **Red baseline (the probe):** `detect` → `Resume(…)`, the re-run exits 2, `list` offers the
  resume, and abandon reports `already: false`.
- **G2 — windows B′, C, D and E** (P1 §2 `S48` (g)). B′ is excluded from the candidates, `list`
  says complete with no hint, the restore and reveal engines pass their gates, `status` and
  `show` say complete, and abandon gives the complete-refusal. C's clock is `time-boxed` and its
  candidate post-pay. D is excluded, `Abandoned` and `already: true`. E's exact re-run is
  `Fresh`.
- **G-R7a.** A `SealJournal` wrapper (the suites already wrap one, `resume.rs:1439`) fails
  `set_state(Complete)`; after the error, the meta holds `work_id` and `cost_atto`.
- **G-R7b — §1.5's sequence.** Pay, an ordinary upload failure (exit 23), a resume: it ends
  with `cost_atto` equal to the receipt's `storage_cost_atto`, and `list` prints it.
- The existing suites stay green unchanged: in every normal state the effective state equals
  the mirror.

The money group:
- **GM1** (L-RESUME2) — cases (a)–(e) through `WorkListing::gather`: the clock and the note in
  each case.
- **GM2** (L-RESUME2) — §1.5's sequence: run 1's `list` shows the receipt's cost *"so far"*.
- **GM3** (L-MONEY) — cases (c) and (c2): after a declined remainder the tag stays `Anchored`,
  and the plan says *"partly paid … pay the rest"*.
- **GM4** (L-MONEY) — case (a): the preview and the report say *"no payment recorded"*.
- **GM5** (L-MONEY) — case (b): `abandon` succeeds, and the resume takes the pre-pay path.

**The plants — proof that those tests can fail**

| Plant | Lane | Must redden |
|---|---|---|
| P1: `effective_work_state` returns `mirror` | L-RESUME2 | G1 and G2 (*"expected Fresh, got Resume(…)"*) |
| P2: `gather_candidates` filters on `record.state` again | L-RESUME2 | G1, on `detect` |
| P3: `listing.rs` back to `let state = record.state;` | L-RESUME2 | G1, on the row's hint |
| P4: `abandon_pre_pay` rule 1 on `meta.state` | L-RESUME2 | G1, on `already` |
| P5: `restore.rs`'s gate on the mirror | L-RESUME2 | G2, window B′ (`NotRestorable`) |
| P6: `reveal.rs`'s gate on the mirror | L-RESUME2 | G2, window B′ |
| P7: `AbandonPreview::read` on the mirror | L-RESUME2 | G1, on the preview |
| P-R7a: the two calls in `complete()` swapped back | L-RESUME2 | G-R7a (*"cost None after a failed Complete transition"*) |
| P-R7b: `if paid_here` restored | L-RESUME2 | G-R7b (`cost=None`) |
| PM1: the clock back on the mirror | L-RESUME2 | GM1, at case (c) |
| PM2: the cost line back on the meta only | L-RESUME2 | GM2, at run 1 |
| PM3: the early repair restored | L-MONEY | GM3 (`fine=Some(Paid)`) |
| PM4: the old strings | L-MONEY | GM4, by message |
| PM5: rule 2 back on `receipt.is_some()` | L-MONEY | GM5 |

The `restore` handler in `commands.rs` is `ant-backend` only: its proof is the heavy tier's
compile and a review, and P5 proves the engine behind it. Every snapshot test reddens until its
snapshot is regenerated; that regeneration is the copy change, reviewed line by line (M7).

## 4. What this record does NOT decide

- **A notice for an exact match to a complete work.** The window-B′ residual (§2 R7) is D45 §2's
  rule for every complete work. Whether D45 should say so when an invocation matches a complete
  work exactly is a question about every complete work, not about this record's windows.
- **Deleting `incomplete_works`** (D106 §11 (iv)). Not proposed: under R1 it agrees with
  production again, and deleting it is a refactor with no product effect.
- **`--json`'s `cost_atto` from the receipt.** Not this wave (M3): a value change before `U32` is
  a decision of its own.
- **Abandon's rule-2 refusal copy for a partly paid work.** At `6e1cab3` its text said *"Finish
  it instead by re-running `{}`: no further payment is needed"* (`seal_resume.rs:506-507`). For a
  stranded work (case (c)) M4's plan says *"pay the rest"*, and a remainder is owed. Found while
  this record was written, by reading the code (not executed). The orchestrator then ruled it
  (M6c, §2's rules added during implementation), and L-MONEY built it: the way forward now says
  *"no quote the receipt already maps is paid again"*, which is true of a fully and of a partly
  paid work (§6). *(Corrected in place before first commit; see D203 §6.)*
- **Rustdoc that equates an absent receipt with "not paid".** `recorded_receipt`'s doc says that
  `None` means *"not paid yet"* (`receipt_sink.rs:114`). M1's wording rule governs what users
  read, and that file is in no lane's scope this wave. (`listing.rs`'s module doc, *"pre-pay —
  nothing was paid"* at `:34`, is inside L-RESUME2's whole-file scope.) Both were answered before
  first commit: the orchestrator rewrote `recorded_receipt`'s doc line (*"no payment is
  recorded"*, D203 M1) and L-RESUME2 rewrote `listing.rs`'s module doc. *(Corrected in place
  before first commit; see D203 §6.)*
- **`S51`** (a first sub-batch's submission error classed as "no money moved"): D204 §4's.
- **New rows.** This record mints none. The rulings minted `S52`, `U109` and `U110` from P1's
  findings before it was written; `S48` was minted at wave 39.
- **D197's pre-staging quote.** D197 §6 quotes the preview's pre-staging arm verbatim,
  *"staging was interrupted before it finished; not paid"* (D197:487-488). P1 found that arm
  true, and M6 leaves it to the lane (§2 M6). D197's addendum says the quote stays true unless
  the lane rewrites the arm, and this record's §6 records which.

## 5. Edit list — per write scope, with the lane named before this record was written

### L-RESUME2 (round 1, dispatched after P1's challenge round) — `S48`, `S52`, `U109`: §2 R1–R7, M1–M3

- `crates/antseal-cli/src/pipeline/journal.rs`: `effective_work_state` and `payment_recorded`
  beside `recorded_state` (`:1113`), with their docs (R1, M1).
- `crates/antseal-cli/src/pipeline/mod.rs`: the re-export line only.
- `crates/antseal-cli/src/pipeline/vault_journal.rs`: the comment at `:137-140` only (R6).
- `crates/antseal-cli/src/pipeline/resume.rs`: `complete()` only (`:582-604`, R7) — not `:184`
  and not the repair at `:203-210`, which are L-MONEY's.
- `crates/antseal-cli/src/pipeline/restore.rs` (`:560-573`) and `pipeline/reveal.rs`
  (`:589-601`): the state gate only (R2).
- `crates/antseal-cli/src/seal_resume.rs`: `gather_candidates`, `ResumeCandidate::state`'s doc,
  `abandon_pre_pay` rule 1 and rule 2's mirror clause, and `AbandonPreview::read`'s state read
  only — not `resume_plan_lines`, rule 2's receipt clause, the preview's predicate and render, or
  `AbandonReport::render`, which are L-MONEY's.
- `crates/antseal-cli/src/listing.rs`: the whole file (R2, R6, M2, M3).
- `crates/antseal-cli/src/status.rs` and `show.rs`: the state read only.
- `crates/antseal-cli/src/upgrade_hook.rs`: `:408-420` only.
- `crates/antseal-cli/src/commands.rs`: `:728-735` only, the `ant-backend` `restore` handler.
- Tests: new tests appended at the end of `tests/seal_command.rs`, `list_command.rs`,
  `restore_engine.rs` and `reveal_flow.rs`; in `status_command.rs`, `seal_journal.rs` and
  `seal_matrix.rs`, needle updates only where M2's or M3's copy changes a pinned string. Granted
  before this record was written: one line, `receipt_cost_atto: None,`, in each of the four
  `WorkRow` literals in `tests/machine_mode.rs` (three, in `fixture_listing`) and
  `tests/work_state_word.rs` (one, in `row_in`), with a test that the field is never
  serialized.
- Snapshots: `list-report.txt`, `list-blocked-work.txt`, `list-anchor-nags.txt`, and
  `json-envelopes.txt`'s `list` note only (`:26`).
- `docs/user/**`: only a verbatim quote of `list` copy that M2 or M3 changes, with every hit
  reported.
- **Must not:** `pipeline/error.rs` (L-NET3's), `init.rs`, `config.rs`, `resume.rs` outside
  `complete()`, L-MONEY's regions of `seal_resume.rs`, `cli-errors.display.txt`, any other
  snapshot region, `docs/config.md`, or any decision record.
- **Builds:** in-process tests in the shared target under the lock; spawned tests and plants in
  a shadow copy with a private target. The `ant-backend` handler compiles at the orchestrator's
  checkpoint (the heavy clippy).

### L-MONEY (round 2, after L-RESUME2) — `U110`: §2 M4–M6

Dispatched only after L-RESUME2 is done and the orchestrator has re-run its tests; the final
list comes with the dispatch.
- `crates/antseal-cli/src/seal_resume.rs`: `resume_plan_lines`, rule 2's receipt clause,
  `AbandonPreview::read`'s predicate and render, and `AbandonReport::render`. M6's phrase also
  sits in `AbandonPreview::question` (`:723`) and the type's doc (`:615`), which the dispatch
  list should name.
- `crates/antseal-cli/src/pipeline/resume.rs`: `:184`'s predicate and the early repair
  (`:203-210`).
- Tests `seal_command.rs`, `seal_journal.rs` and `seal_matrix.rs`; `json-envelopes.txt`'s `:36`
  only; `docs/user/**` quotes of the changed copy.

### L-LOC (round 3) — living-doc citations

After the last code edit, the living documents' `path:line` citations into the edited files are
re-pointed by meaning.

### RECORDS-A — this record and dated addenda

D106 (W4 and W6), D45 (§2), D152 (R5's money clause), D185 (the preview, question and report),
D194 (§1.3's quote of `list-report.txt:19-21`) and D197 (§6's `S48` entry, whose *"D45's
candidate scan filters on the mirror"* R2 makes false; window E).

### Orchestrator — `TODO.md`, `tasks/S.md`, `tasks/U.md`, `docs/decisions/README.md`, `docs/instrument-ledger.md`

- `S48`, `S52` and `U109`: their ticks against §3, after L-RESUME2; `U110`'s after L-MONEY.
- This record's index row and register row.
- The ledger: P1's two instrument findings (its report's §3, on D106's W4 and W6) and the
  counter-lean's falsification are already entered in `docs/instrument-ledger.md`, attributed
  to D203 (three entries, written by the registrar before this record). The D106 addendum
  answers the two findings in the record itself.
- The close gate with `ANTSEAL_GATE_HEAVY=1 ANTSEAL_GATE_E2E=1`.

## 6. As built — wave 40, lanes L-RESUME2 and L-MONEY (recorded in place before this record was first committed)

Every verdict below was read from an exit file, per the lanes' reports, and every red was judged
by its message. This records lane read the exit files back: each matches its report, and the one
run a report omits is named below. Plants ran in shadow copies with private targets and were
restored sha-equal; in-tree runs used the shared target under the locks. L-RESUME2 (round 1)
built R1–R7 and M1–M3. L-MONEY (round 2) started from L-RESUME2's landed files (its start hashes
equal L-RESUME2's finals) and built M4–M6 and §2's rules added during implementation.

- **Grants and acts, from the orchestrator's dispatch log.** L-RESUME2 had four grants: the four
  `receipt_cost_atto: None,` literal lines (§5), with `recorded_receipt` reused (§0); a synthetic
  receipt before `Paid` in three existing `list_command.rs` walks, through a `fixture_receipt`
  helper; and, first in `restore_engine.rs` and `reveal_flow.rs` and then in `show_command.rs`,
  existing tests that drop the state tag, on condition that each engine gains a tag-present test.
  L-MONEY had three: M4's shape C, M8's datum with its JSON ruling, and `decode_receipt`'s one
  token (§2's added rules). After L-MONEY the orchestrator made three line-neutral acts that lanes
  had found outside their grants:
  - `pipeline/vault_journal.rs:14-18`, the module doc, said that `list`, `status` and D45's scan
    *"never decrypt a journal entry"* and that the mirror *"is what a repair would rewrite"*. It
    now says that the mirror *"can only trail the tag"*, that every classifying reader takes the
    tag when one exists, and that nothing repairs the mirror (R1–R3).
  - `pipeline/receipt_sink.rs:114`, `recorded_receipt`'s doc, now says *"`None` means *no payment
    is recorded* (D203 M1)"*, which answers §4's rustdoc bullet.
  - `tests/init_command.rs:1157` now cites `(D205 §1.4)` for `(P2 Log 8)`. That act is D205's; it
    is recorded here because it was part of the same act.
- **§2 R1.** `pub const fn effective_work_state` (`#[must_use]`) is at
  `crates/antseal-cli/src/pipeline/journal.rs:1143`, after `recorded_state` (`:1113`), and its doc
  (`:1122-1141`) says that the mirror can only trail the tag. `pipeline/mod.rs` is unchanged: there
  is no re-export, as R1 allowed.
  `d203_r1_the_effective_state_is_the_tags_and_the_mirrors_only_without_one` asserts 28 rows.
- **§2 R2.** Every census row that R2 names reads the effective state: `gather_candidates`
  (`seal_resume.rs:231`), which now filters on the network before it reads the tag;
  `abandon_pre_pay` (`:505-506`), for rule 1 and rule 2's state clause (`:533`);
  `AbandonPreview::read` (`:700-701`); `WorkListing::gather` (`listing.rs:666-668`);
  `status.rs:409`; `show.rs:465`; and `upgrade_hook.rs:419`, where a state record that will not read
  is a counted skip (`:432`), because the hook has no error path. Row 5 follows row 1, and row 6 is
  unchanged.
  - **Deviation: one gate for three readers.** `pub(crate) fn effective_state`
    (`pipeline/restore.rs:552`) gates the restore engine (`:597`), the reveal engine
    (`pipeline/reveal.rs:593`) and the `ant-backend` handler (`commands.rs:732`). Reason:
    `reveal.rs`'s own comment refuses a twin of restore's gate, and the handler then runs the code
    that the default-feature tests and plants exercise. A tag that will not decode is the caller's
    `MalformedRecord`; a store failure keeps its class. The lane did not compile the handler under
    `ant-backend`; the heavy checkpoint owns that compile.
  - **Deviation: a damaged tag now fails where the mirror used to answer (deliberate).** A
    same-network complete or abandoned work whose state record is corrupt or newer now fails D45's
    scan and `abandon`, where `6e1cab3` classified it by the mirror without reading the tag. Reason:
    the effective state is undefined without the tag, and `gather_candidates`' doc says *"a damaged
    vault is reported, never softened into a shorter candidate list"* (`seal_resume.rs:209-210`).
- **§2 R3–R6.** No repair code exists: over window A, `abandon` reports `already: true`, renders
  *"Work {id} was already abandoned; nothing changed."*, and leaves the vault's fingerprint
  unchanged (G1). Rule 2 keeps its receipt clause first (`seal_resume.rs:532-533`); the receipt
  clause is L-MONEY's and the state clause L-RESUME2's. `vault/export.rs` and `vault/store.rs` are
  unchanged, so R5's residue stands. R6: `write_state`'s comment (`vault_journal.rs:137-146`) now
  says that the window is *"safe only because every reader that classifies a work takes the tag
  whenever one exists"*; the other two are `ResumeCandidate::state`'s doc (`seal_resume.rs:82-87`)
  and the comment on `list`'s tag read (`listing.rs:661-665`).
- **§2 R7.** `complete()` (`pipeline/resume.rs:609-631`) takes the cost from the receipt's
  `storage_cost_atto` when a receipt is journaled, and `paid_here.then_some(paid_atto)` otherwise
  (`:623-626`), then calls `record_outcome` (`:628`) before `set_state(…, SealState::Complete)`
  (`:629`).
  - **The zero-payment completion, measured**
    (`u109_a_zero_payment_seal_records_no_payment_and_says_so`). A second seal of identical
    ciphertexts prices nothing, and its `pay` journals a receipt with an empty `tx_map` and
    `storage_cost_atto` 0. Refused at upload, the work sits at `Finalizing` on the re-quote clock
    with *"cost: none (no payment recorded)"*. Finished by a resume that buys nothing, it records
    `Some(0)`, and `list` prints *"cost: 0 atto-ANT"*.
  - **Deviation: "accumulated across rounds" is false on one arm** (code-traced; R7 was built as
    ruled). The expired-proof re-payment (`consent_anchor_pay(…, true, None)`) replaces the
    receipt (D179). If one resume pays a remainder and then re-pays on expiry, `6e1cab3` recorded
    the run's spend and R7 records the replacement's; neither is the work's total. `S53` owns it.
  - G-R7a (`s52_complete_records_its_outcome_before_the_complete_transition`, with a
    `FailsTheCompleteTransition` wrapper, `tests/seal_command.rs:3510`) and G-R7b
    (`s52_a_work_paid_in_one_run_and_finished_by_a_resume_records_its_cost`, `Some(18498)`) were red
    at `6e1cab3` and by P-R7a and P-R7b, with §3's messages: *"cost None after a failed Complete
    transition …"* and *"cost=None: a work paid in one run and finished by a resume must record
    its cost (D203 R7)"*.
- **§2 M1.** `pub fn payment_recorded` (`journal.rs:1166`) is
  `receipt.is_some_and(|receipt| !receipt.tx_map.is_empty())`, and `recorded_receipt` was reused
  (§0). `d203_m1_a_payment_is_recorded_iff_a_receipt_maps_a_quote` covers no receipt, a revert-only
  one, a confirmed mapping and a submitted one.
- **§2 M2 and M3.** The clock is `time-boxed` exactly when a payment is recorded
  (`listing.rs:725-729`). The notes (`:284-290`), verbatim: *"no payment is recorded for it; the
  recorded quote is stale by design — resuming re-quotes at current prices and asks for consent
  again"* and *"RESUME PROMPTLY: a payment for this seal is recorded, and its payment proofs stay
  usable for uploading only about a day — after that, finishing it costs a second payment"*. The
  cost line (`:852-861`) is `  cost: {N} atto-ANT`, else
  `  cost: {N} atto-ANT so far (from the payment receipt)`, else
  `  cost: none (no payment recorded)`. `blocked_lines`' paid branch opens *"a payment for this
  seal is recorded and cannot be recovered."* `--json`'s `cost_atto` is unchanged.
  - **Deviation: the no-payment blocked clause is more than a word swap.** *"…so only the local
    staged copy is lost"* kept an "only" that the vault cannot back after an exit 37. As built:
    *"no payment is recorded for it, so abandoning it loses no recorded payment — only the local
    staged copy."*
  - **Deviation: a new datum, never serialized.** `WorkRow::receipt_cost_atto` (`listing.rs:430`)
    carries the receipt's amount beside the meta's, and `list` reads a receipt only where it
    decides something — an unfinished row's clock, or a row with no recorded cost — by D100 R3's
    reporter rule. `d203::the_receipt_cost_is_rendered_for_humans_and_never_serialized`
    (`tests/list_command.rs:2369`) finds 777 777 777 777 777 on the human line and nowhere in
    `--json`, and pins each row's members (14 keys, and 4 under `resume`); PS reddened it.
  - The three fixture walks now journal a receipt before `Paid`; no snapshot line changed because
    of them. GM1 (`u109_list_states_money_from_the_receipt_in_every_case`, cases (a)–(e)) was red
    at `6e1cab3` (case (c): *"clock Some(ReQuote), expected TimeBoxed"*), and so was GM2
    (`u109_list_reads_the_cost_of_a_paid_incomplete_work_from_its_receipt`: *"cost: not recorded
    (nothing paid)"* above *"RESUME PROMPTLY: this seal is paid for, …"*). PM1 and PM2 reddened
    them.
- **§2 M4, as amended.** `resume_plan_lines(candidate, receipt: Option<&PaymentReceipt>)`
  (`seal_resume.rs:932-935`) applies `payment_recorded` itself. Its `Anchored` arms (`:945-951`)
  carry §2's amended texts, and the other arms are unchanged. `seal_run.rs:381-386` reads the
  matched work's receipt.
  - The data path costs one vault read: `seal --dry-run` over a resumable work now reads that
    receipt, with still no backend call and no vault write (D45's addendum). An undecodable receipt
    there exits 12 in the class, code and Display of the resume's own read (`resume.rs:185`), which
    `u110_a_dry_run_over_an_undecodable_receipt_fails_in_the_resumes_own_class` compares. A real
    resume now fails at that read one step earlier, in the same class.
  - Beyond §2's reason for the wording, the lane found two more: "paid" is not certain under a
    `Submitted` mapping, and the `Anchored` tag is written under `--no-anchor` too, hence "past its
    anchor step". So `U110`'s Accept is met in substance, not in its word "partly".
    `json-envelopes.txt:36` is byte-identical, with no re-bless.
  - GM3 (`u110_a_declined_remainder_leaves_the_tag_pre_pay_and_the_plan_says_the_rest_is_owed`) was
    red at `6e1cab3` with *"staged and anchored; nothing paid"* and *"pay, upload"*. PM4-plan
    reddened GM4; PM4-key, keyed on `receipt.is_some()`, reddened GM5; and PM4-wire, with
    `seal_run.rs` passing `None`, reddened the dry-run test and GM3.
- **§2 M5.** The repair moved to the tail of the receipt branch, after the remainder
  (`resume.rs:265-277`), and runs only if the tag is still pre-pay; a guard follows,
  `debug_assert!(state.is_post_pay(), "the pre-pay branches are exhaustive")` (`:281`). `finalize`
  is reached on every path that reaches it: a post-pay tag needs no repair; a covering receipt is
  repaired (`seal_matrix::barrier_post_pay_is_atomic_only_because_of_the_capture_hook`, existing);
  a remainder that prices nothing is repaired with nothing asked
  (`u110_a_remainder_that_prices_nothing_is_repaired_to_paid_and_finalized`, new; cost 4 200); and
  `consent_anchor_pay` tags a paid remainder `Paid` (`:571`). A declined remainder returns
  `ConsentDeclined` with the tag still `Anchored` (GM3). Code-traced: a remainder whose quote or
  `pay` fails now also leaves the tag pre-pay, where `6e1cab3` had already tagged it `Paid`. PM3
  reddened GM3 (*"fine=Some(Paid) after a declined remainder: …"*), and PM5-del the path-2b test
  (*"the pre-pay branches are exhaustive"*).
- **§2 M6.** Rule 2 (`seal_resume.rs:532`), `AbandonPreview::read` (`:702`) and the resume
  (`resume.rs:189`, called by path because the import block lay outside the grant) key on
  `payment_recorded`. The report reads *"No payment is recorded for it and nothing was uploaded."*
  (`seal_resume.rs:404`). A revert-only capture now takes the pre-pay path, and the payment made
  there replaces it (`prior: None`).
  - **Deviation: the zero-payment edge** (code-traced). An empty-mapping receipt on a pre-pay tag
    now takes the pre-pay path: a consent question over a zero quote, which machine mode passes
    only with `--yes`. `6e1cab3` finalized without asking. Nothing is paid either way, and D45 §4
    asks the same of every pre-pay work.
  - GM4 is `u110_with_no_payment_recorded_the_plan_and_the_abandon_screens_say_so`. GM5,
    `u110_a_revert_only_receipt_blocks_neither_abandon_nor_the_pre_pay_resume`, was red at
    `6e1cab3`: *"the preview was suppressed for a work whose only receipt maps no quote"*.
    PM4-report, PM5 (*"abandon refused a work whose only receipt maps no quote: …"*), PM5-preview
    and PM5-r (*"… the resume took the receipt branch, not the pre-pay path (D203 M6)"*) reddened
    them.
- **M6a–M6c** (§2's added rules).
  - **M6a.** The question (`seal_resume.rs:785-786`) and the type doc (`:644-655`) say *"No payment
    is recorded for it"*; the three assertions were updated, and PM4-question reddened GM4.
    **Deviation:** the question says so even where the progress line says *"not paid"*. Both are
    true, and the question is the weaker.
  - **M6b.** Measured: `WorkRecord::consent`'s one production writer is `VaultJournal::put_consent`
    (`vault_journal.rs:333`), reached only from `consent_anchor_pay`'s `Granted` arm; `begin`
    writes `consent: None` (`:174`); and the one production `pay` follows the consent write.
    **Deviation: a read, not a verdict per arm.** A private `consented: bool`
    (`seal_resume.rs:683`, filled at `:716`) picks the word in all three arms (`:737-741`), so
    *"not paid"* survives exactly where the vault holds no consent record: always before the plan
    write (D197's quote stays true); for a declined `Staged` seal (*"staged; not paid"*, the
    commonest preview); and for an `Anchored` work only in a hand-made fixture.
    `u110_the_previews_money_word_is_the_consent_records` asserts six rows; PM6b reddened it, and
    PM4-preview GM4. D185's addendum is corrected in place.
  - **M6c.** The refusal now ends *"… no quote the receipt already maps is paid again, and the
    network's payment proofs stay usable for uploading only about a day"*
    (`seal_resume.rs:542-546`).
    `u110_the_paid_refusal_offers_a_way_forward_true_of_a_partly_paid_work` runs on a partly paid
    fixture, with the exact re-run's question over a priced remainder as its control; PM6c reddened
    it. §4's bullet is corrected in place.
- **§2 M7.** `cli-errors.display.txt` is unchanged. L-RESUME2 re-blessed 8 lines, all M2 or M3
  copy: `list-report.txt:11`, `:18` and `:20`; `list-blocked-work.txt:6`, `:10` and `:13`;
  `list-anchor-nags.txt:23`; and `json-envelopes.txt:26`'s `note`. No line count changed. With the
  old notes planted back, the envelope test passed against `6e1cab3`'s file, so the granted
  literal lines move nothing. L-MONEY moved only `list-anchor-nags.txt:19` (M9). D194's
  `list-report.txt:19-21` still points at the same lines; `:20`'s text changed.
- **M8 (`U113`; §2's added rules).** `U113` was minted from L-RESUME2's report: its own U109 read
  made one undecodable receipt fail the whole `list`. The read now mirrors `StoredAnchors::read`
  (`listing.rs:683-701`): `store.get_receipt` propagates every I/O, record-cap (64 MiB) and AEAD
  failure, and only `decode_receipt`'s `JournalError::Corrupt` becomes the row's datum,
  `WorkRow::damaged_receipt` (`:443`). The row prints
  `  cost: unknown (the payment receipt cannot be read: {detail})` and, in place of its clock
  note, *"its payment receipt cannot be read ({detail}), so antseal cannot tell whether a
  payment for this seal is recorded, and resuming or abandoning it fails until the receipt can be
  read"* (`resume_note`, `:1504-1513`). In `--json` it keeps `clock: "time-boxed"` (`:721-729`),
  and its `note` is that sentence (`:1538`); `damaged_anchors` was measured and does not fit.
  - **Deviation: only `Corrupt` is a datum.** `decode_receipt` maps both of its refusals to
    `Corrupt` (`receipt_sink.rs:98-104`), so §2's `NewerRecord` cannot come from it today, and any
    other error propagates.
  - **Deviation: both money clauses.** A blocked work also gets a third `blocked_lines` clause
    (`listing.rs:1632-1639`), whose only way forward is the one that does not read the receipt:
    move or copy the files.
  - The Accept, `u113::one_undecodable_receipt_is_a_row_and_not_a_refusal`, lists all three works
    with every other row and the summary byte-identical, and checks the damaged row's `--json`
    clock, note, null `cost_atto` and member sets. It was red at `6e1cab3`: *"one undecodable
    receipt failed the whole `list`: vault authentication failed: …"*. The control,
    `u113::a_receipt_the_store_refuses_still_fails_the_whole_list`, gives `vault-auth-failure`
    for an oversize record and for a tampered AEAD. PM8-prop, PM8-wide (*"over the size cap: a
    store-layer refusal became a row (3 works listed)"*), PM8-note, PM8-clock and PM8-cost reddened
    them.
- **M9** (§2's added rules). The pipeline writes a work's id and cost together, only in
  `complete()`, so the "anchored, killed before finalize" row now records no cost
  (`tests/list_command.rs:810`). One snapshot line moved: `list-anchor-nags.txt:19`, from
  `  cost: 11 atto-ANT` to `  cost: none (no payment recorded)`. A receipt for the row would have
  made it a stranded payment instead.
- **Existing tests changed, each granted or in scope.** Three tests faked an incomplete work by
  rewriting only the mirror of a complete, tagged one, which R1 now rules complete (window B′):
  `an_incomplete_work_is_refused_with_its_state_named` (`restore_engine.rs`),
  `incomplete_and_unknown_works_are_refused_with_the_state_named` (`reveal_flow.rs`) and
  `an_incomplete_work_still_shows_its_units_and_says_it_is_incomplete` (`show_command.rs`). Each now
  drops the tag first, and each file gained a tag-present test from a real interrupted seal
  (`restore_engine.rs:814`, `reveal_flow.rs:1166`, `show_command.rs:881`). So §3's *"The existing
  suites stay green unchanged"* was false for every fixture that fakes a state with a mirror-only
  write. The rest were needles — five `list_command.rs` tests,
  `the_two_clocks_say_opposite_things`, four `seal_command.rs` assertions (M6a, M6c) and
  `resume_plan_lines`' unit test — and M9's fixture. The three *"not paid"* preview assertions
  (`seal_command.rs:1491`, `:1738`, `:2561`) are unchanged: none of those works holds a consent
  record.
- **The suites and plants.**
  - L-RESUME2's `mod d203` (`tests/seal_command.rs:2929`) holds 12 tests. Its red baseline exited
    101 with 9 of 9 failing (window A: *"expected Fresh { incomplete_works: 0 }, got
    Ok(Resume(…))"*), and its final run passed 12. An intermediate run that the report omits
    failed 1 of 12: the new zero-payment test expected the wrong tag (`left: Some(Finalizing)`,
    `right: Some(Paid)`) and was corrected to the measured one. Its 18 plants include P1–P7 (P5:
    *"a complete work restores: this work is `incomplete-post-pay`, not complete"*) and six of its
    own: P-status, P-show and P-hook on window B′; P-gate-restore and P-gate-reveal (*"an
    interrupted work is never restorable"*); and P-show-tagged (`left: Complete`, `right:
    IncompletePostPay`). The tree suite ran 633 passed and 3 failed over 31 binaries — the three
    tests above, before their grants — and those files then passed 14, 20 and 14.
  - L-MONEY's `mod u110` (`tests/seal_command.rs:4168`, 7 tests) and `mod u113`
    (`tests/list_command.rs:2454`, 2): its red baselines exited 101 with 6 of 7 and 1 of 2
    failing, the other two passing by design. Its 18 plants were each red by message. Its tree
    suite passed 642 over 31 binaries, and its 19 spawning suites passed 272. Each lane's clippy
    exited 0.
- **The tree, re-read for this section.** Ten of L-MONEY's eleven files match its final sha256.
  Twelve of L-RESUME2's 22 match its finals, and the eight that L-MONEY edited later match
  L-MONEY's. Three differ only by an orchestrator act, and reverting the act reproduces the lane's
  hash: `vault_journal.rs:14-18`, `receipt_sink.rs:114`, and `commands.rs:190-191` (D205's
  comment, apart from R2's hunk at `:730-737`). Each lane's plant-marker `git grep` exited 1, with
  a positive control.
- **Left open.**
  - `S53` owns R7's expiry arm.
  - `U114` owns the post-pay tags that older vaults can hold over a payment that does not cover
    the work — a pre-`S50` repair's `Paid` over a revert-only receipt (§2's residue check;
    L-MONEY found no one-line fix in its regions) and a pre-M5 `Paid` over a declined
    remainder. Rule 2's state clause refuses both, and their plan says that no further payment is
    needed.
  - `U115` owns two sentences: rule 2's *"has already been paid for"*, and the stranded plan's
    missing urgency line. `U113`'s tick is the orchestrator's.
  - Not minted, and recorded here: the re-quote note's *"asks for consent again"* is untrue of a
    zero-payment work at `Finalizing`, whose resume asks nothing (L-RESUME2); `list_command.rs`'s
    base fixture gives its `Paid` and `Abandoned` rows a cost and a work id, which the pipeline
    never writes and `list-report.txt` pins (L-MONEY); and the copy lint reads source copy only
    through committed snapshots, none of which holds a new M4, M6 or M8 sentence (L-MONEY).

## Closing — this record is not consent

It changes how eleven readers classify a work, what `complete()` writes first, and the money
sentences of `list`, the resume plan and the abandon screens, inside the wave's own commits.
Nothing in it authorises a push, a workflow dispatch, a deploy or any other outward act; each of
those needs the maintainer's express consent naming the action, the destination and the account.

## Addendum — 2026-10-20 (D210 §2 R1–R4): the post-pay plan arms follow the receipt too, rule 2 speaks per clause, and §6's `U114` and `U115` entries are answered

- **§2 M4 reaches the post-pay arms.** M4 made the plan's `Anchored` arms read the receipt, and
  `resume_plan_lines`' doc kept the post-pay arms on the tag: *"The post-pay tags need no
  receipt: `Paid` is written only once nothing remains to buy (D203 M5)"*
  (`crates/antseal-cli/src/seal_resume.rs:926-930` at `ab7226f`). D210 §2 R1 keys the `Paid`
  and `Finalizing` arms on `payment_recorded` as well. D210 §2 R2 deletes the coarse-state
  sentence *"This seal is already paid for. Finishing it needs no further payment, …"*
  (`:970-976`) and ends every arm that has a recorded payment — the stranded `Anchored` arm
  included — with `list`'s own clock note, `ResumeClock::TimeBoxed.note()` (M2's sentence).
- **Why M5 was not enough.** M5 holds for the first payment and for the remainder: `Paid` again
  means fully paid. But D37 Decision 6's expired-proof path leaves `Finalizing` over money that
  does not usably cover the work, at `ab7226f` and with production entropy: a declined
  proofs-expired re-consent (X-A), and a proofs-expired re-payment that strands (X-B). D210's
  planning lane executed both: the plan told them that no further payment was needed, while the
  next resume asked for 5517 and 3678 atto-ANT (D210 §1.3).
- **M6c's way forward is replaced.** *"no quote the receipt already maps is paid again"* is
  literally true and practically false for X-A, whose every blob is bought again under fresh
  quote hashes. D210 §2 R3 gives rule 2 one message per clause; the receipt clause says the
  re-run *"pays only for what the receipt does not cover"* and states the proof clock. Rule 2's
  predicate is unchanged.
- **§6's *"Left open"*, the `U114` entry.** Closed in code for the plan (D210 §2 R1, R2). For
  abandon and `list` it is recorded, not fixed: rule 2 still refuses a post-pay tag with no
  recorded payment, now with a sentence that claims no payment (D210 §2 R3); and `list`'s
  *"state: paid"* beside *"no payment is recorded"*, and `abandon`'s help line *"Discard an
  interrupted seal that nothing has been paid for"*, stay as they are for shapes with no
  production reach (D210 §2 R4).
- **§6's *"Left open"*, the `U115` entry.** Both sentences are ruled: rule 2's opening speaks per
  clause (D210 §2 R3), and the stranded plan's missing urgency line is `list`'s clock note
  (D210 §2 R2).
- **Correction: §6's *"Rule 2's state clause refuses both"* is wrong for the second shape.** It
  holds for the pre-`S50` `Paid` over a revert-only receipt: that receipt maps no quote, so only
  the state clause refuses it. It does not hold for the pre-M5 `Paid` over a declined remainder:
  that receipt maps the partial's quotes, so `payment_recorded` is true and rule 2 refuses it by
  its RECEIPT clause. D210's planning lane executed both (D210 §1.2, cases 1 and 2). The second
  refusal was right; only its words overstated the payment.

The text above this addendum is not edited.

## Addendum — 2026-10-20 (D208 §2 R5, R9): what a mapped quote protects was true of quote hashes and false of blobs for an unobserved landing; D208 makes it true of blobs

§1.4 says of a receipt's `tx_map` that an unobserved landing maps the sub-batch's quotes to the
submitted hash with status `Submitted`, *"So the mapped quotes are exactly the ones a resume will
not re-buy, and what exit 28 promises"* (D203:187-188). M1 says the same of `payment_recorded`:
*"It is exactly the set of quotes a resume will not re-buy, and what exit 28 promises. It includes
a `Submitted` mapping (money MAY have moved: conservative)"* (D203:393-394).

Both were true of quote HASHES — no resume pays an old quote hash (D36) — and false of BLOBS for an
unobserved landing. That branch mapped the quotes but built no blob record, and the resume's
remainder is keyed on records (`uncovered_blobs`), so a re-run re-quoted and re-bought every blob of
the sub-batch. D208 §1.4 records it executed twice at `ab7226f`: 10 quotes paid for 5 blobs with
22 902 of 45 804 atto-ANT recorded and, independently, `list` printing *"cost: 0 atto-ANT so far"*
beside M2's *"RESUME PROMPTLY … its payment proofs stay usable …"* for a receipt that held no
proof.

D208 makes both sentences true of blobs:
- §2 R5 builds the sub-batch's blob records over the locally computed hash at the branch, before
  its capture, so the capture carries records, a cost and proofs, and the remainder skips those
  blobs;
- §2 R9 resolves every `Submitted` transaction before the resume's money branch: a landed one keeps
  its records (nodes check the quote on the contract, not the transaction), and a reverted or
  never-mined one has its mappings and records pruned, its `TxRecord` kept as evidence, and its
  blobs bought once through the remainder arm.

M1's predicate does not change. For this shape M2's clock and M3's cost line become true with no
copy change from D208 (§2 R11). Unobserved-landing captures journaled before D208 keep mappings
without records and stay a recorded residue (D208 §2 R10). D208 §2 R12 adds one helper beside
`payment_recorded` in `pipeline/journal.rs`: a transaction is published as part of the payment
only if its hash maps a quote.

The text above is history and stays as written.

## Addendum — 2026-10-20 (D209 §2 R1, R6): §6's R7 deviation is closed — the expired-proof re-payment carries the replaced payment's totals, so R7's cost is the work's total on that arm too

§6 recorded a deviation from §2 R7 (D203:784-787): *"Deviation: "accumulated across rounds" is
false on one arm … The expired-proof re-payment (`consent_anchor_pay(…, true, None)`) replaces the
receipt (D179). If one resume pays a remainder and then re-pays on expiry, `6e1cab3` recorded the
run's spend and R7 records the replacement's; neither is the work's total. `S53` owns it."* §6's
*"Left open"* repeats it: *"`S53` owns R7's expiry arm"* (D203:959).

D209 closes it. Its §2 R1, as amended by its R6, passes the expired arm a prior built by
`carry_forward(replaced, keep)`: the replaced receipt's totals, every mapping that no record uses
with its transaction, and the records the current invocation paid for — never the replaced
records. The existing merge then writes the cumulative total at every capture and at the final
`put_receipt`, so R7's cost — the journaled receipt's `storage_cost_atto` — is the work's total on
this arm as on the remainder's, and `merge_receipts`' own definition (*"what this seal has cost in
total, across however many invocations paid for it"*) now holds on every path. D209's planning lane
executed the gap at `ab7226f` — 3678 atto-ANT recorded of 9195 spent, and 5517 of 11 034 for the
remainder-then-expiry shape this deviation describes — and its shadow build of the carry recorded
9195 and 11 034 (D209 §1.3, §1.6).

Three further points bear on this record:
- **The rule the deviation attributes to D179 is D37's** (D37:412-415, the S31 amendment's
  *"deliberately does **not** merge"*). D179 rules when a proof counts as expired, not what the
  re-payment does with the receipt. `complete()`'s doc carried the same attribution and is
  rewritten (D209 §2 R4).
- **`paid_here` keeps its one job.** On the expired arm the run's figure is the quote's total, not
  the merged receipt's cost (D209 §2 R2), so the run report stays the run's own spend, as R7 says.
- **M3 is kept.** `list --json`'s `cost_atto` stays the meta's value only (D203:425-426). For an
  expired-and-re-paid work that value is now the cumulative total, which D209 §2 R3 rules is its
  documented meaning (*"Total storage cost paid"*), not a `U32` semantics move.

The text above this addendum is not edited.
