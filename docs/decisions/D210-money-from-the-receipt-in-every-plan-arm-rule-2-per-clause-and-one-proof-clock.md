# D210 — Every resume-plan arm takes its **money from the receipt**, abandon's rule 2 **speaks per clause**, and **one proof-clock sentence** — `list`'s own — serves both `list` and the plan

- **Status: RESOLVED. H4 fell (a): the class it called legacy is reachable at `ab7226f`, though
  both of its sub-claims held. H5 fell (b): its direction survived and three of its premises
  fell.**
  - **H4 (`U114`)** — *"the question dissolves (d) — record why legacy vaults are out of scope
    and fix nothing in code: NOTHING has been released (Q31 is open; the only tag is
    format-v1-freeze), so only vaults written by a developer build before wave 40 (5546618) can
    hold either legacy shape; and in both shapes the money ACTION is already right (the resume
    quotes and asks for everything in case 1 and for the remainder in case 2), only the plan's
    and abandon's WORDS disagree with it."* (a):
    - **Both sub-claims hold, executed.** No document promises anything about a vault written by
      an unreleased build (§1.6), and in both legacy shapes the resume asks for exactly what is
      owed (§1.2).
    - **The premise falls: the class is not legacy-only.** Two shapes the pipeline itself
      produces at `ab7226f`, with production entropy, put a post-pay tag over money that does not
      usably cover the work: a declined proofs-expired re-consent (X-A) and a proofs-expired
      re-payment that strands (X-B). The plan tells both that no further payment is needed, while
      the next resume asks for 5517 and 3678 atto-ANT (§1.3). "Legacy, out of scope" cannot close
      `U114`.
    - **And "out of scope" does not beat the fix on the merits.** The fix is XS and lives in
      `resume_plan_lines`, which `U115` edits anyway (§1.7).
  - **H5 (`U115`)** — *"copy only, as the row says. Rule 2 opens with what the vault knows ("a
    payment is recorded for work …"), and the resume plan's payment-recorded arm (Anchored +
    payment_recorded — the stranded case) gains the proof-clock sentence `list` prints, taken
    from ONE shared constant so the two cannot drift."* (b):
    - **What survives: the direction.** The change is copy — `seal_resume.rs`, its tests and one
      snapshot line — with one source for the clock, so `list` and the plan cannot drift (§2
      R1–R3).
    - **Premise 1 falls: one opening cannot serve both clauses.** Rule 2 refuses on a recorded
      payment or on a post-pay tag, and its state clause fires exactly where no payment is
      recorded (cases 0 and 1). The message splits by clause (§1.5, §2 R3).
    - **Premise 2 falls: the stranded `Anchored` arm is not the only arm that needs the clock.**
      The post-pay arms' *"already paid for … no further payment"* is false at `ab7226f` (X-A,
      X-B), so the clock keys on `payment_recorded` in every arm and replaces the coarse-state
      sentence (§2 R2). That is where `U114` and `U115` became one edit.
    - **Premise 3 falls: the shared constant already exists.** `ResumeClock::TimeBoxed.note()`
      (`crates/antseal-cli/src/listing.rs:281-292`) is a `pub const fn` that returns the sentence
      `list` prints. No new item is needed (§1.4).
- **Date: 2026-10-20**
- Owner rows: **`U114`** (§2 R1, R4, R5) and **`U115`** (§2 R2, R3); §2 R6 holds both rows'
  tests. Both rows were minted at wave 40 from L-MONEY's findings, which recorded D203's residue;
  this record mints no row.
- Related:
  - **D203** §2 M1 (the predicate and the wording rule), M2 (`list`'s clock), M4 (the plan's
    `Anchored` arms), M5 (`Paid` means fully paid), M6 and M6c (rule 2 and its way forward), and
    §6's *"Left open"* (D203:958-966); takes a dated addendum;
  - **D185** §2 R3 (a paid work is refused through the surface) and R4 (the confirmation path);
    takes a dated addendum;
  - **D37** Decision 5 (the unpaid remainder) and Decision 6 (the proofs' one-day window, judged
    by the payment's block time since **D179**);
  - **D45** §5 (`seal --dry-run` over a resumable work returns the plan and writes nothing);
  - **D204** §1.4 (the revert-only receipt that case 1 holds);
  - **D208** (`S51`, `S54`: an unobserved landing's capture, and the resume resolving a
    `Submitted` transaction before it buys) and **D209** (`S53`: the expired arm keeps the
    replaced payment's totals) — the same wave and the same expired arm;
  - **`S16`** (a journaled receipt, not the state tag, says money moved) and **`U32`** (no
    `--json` key moves before it).

## 0. What was measured against

`HEAD` `ab7226f` (local `main`, one records-only commit ahead of `origin/main` `6f0b574`). The
tree was clean when planning began, on 2026-10-20.

Planning lane P2 (wave 41, 2026-10-20) measured `U114` and `U115` together with `S53` (D209).
It wrote nothing in the repository. Every executed probe ran in-process over `MockBackend`, with
no spawned binary, in a `git archive HEAD` shadow copy built in a private target. A probe test
plants each legacy shape through the store's own writers (`put_receipt`, `set_state`), or drives
the pipeline into the shape through an expiring backend double, then prints what the plan,
`list`, `abandon` and the next resume say. Both probe runs exited 0 (the cases and the stranded
shapes in one run; X-A and X-B in the other, *"2 passed"*). P2 then planted its proposed copy in
the shadow, and that run exited 101 with exactly the predicted pins red (§1.8). Code-traced only:
the consent screen itself — the probes drove the engine and the renderers, not the screen.

Before this record was written, the records lane re-read every load-bearing line through
`git show ab7226f:<path>`, because implementation lanes were editing the tree, and re-read the
quoted lines in P2's probe logs. Every figure held, with these refinements:
- `seal --dry-run`'s `--json` object is built at `crates/antseal-cli/src/seal_run.rs:321-326`
  (P2: `:323-328`), and `SealConsent::new` receives the plan at `:414-417` (P2: `:411-417`). The
  plan's vector is built once, at `:380-389`.
- `payment_recorded` is `crates/antseal-cli/src/pipeline/journal.rs:1166-1168`:
  `receipt.is_some_and(|receipt| !receipt.tx_map.is_empty())`.
- The expiring double the suites already use is `struct ExpiringOnce`
  (`crates/antseal-cli/tests/seal_resume.rs:708`, its doc from `:702`).

## 1. What was measured

### 1.1 The plan and rule 2 at `ab7226f`

- **The plan** is `resume_plan_lines` (`crates/antseal-cli/src/seal_resume.rs:903-978`). It is
  built from the recorded states alone, never from a staged-bytes walk (its doc, `:906-909`).
  - **The `Anchored` arms already read the receipt** (D203 M4): with `payment_recorded`,
    *"staged and past its anchor step; a payment is recorded"* / *"pay the rest, if any, then
    upload"* (`:945-948`); without, *"staged and past its anchor step; no payment recorded"* /
    *"pay, upload"* (`:949-952`).
  - **The post-pay arms read the tag alone.** `Paid`: *"PAID — the payment receipt is
    journaled"* / *"upload only (no further payment)"* (`:953-956`). `Finalizing`: *"PAID —
    upload was interrupted part-way"* / *"resume the upload (no further payment)"*
    (`:957-960`).
  - **The only clock sentence keys on the coarse state** (`:970-976`): when
    `candidate.state == WorkState::IncompletePostPay`, *"This seal is already paid for.
    Finishing it needs no further payment, and its payment proofs stay usable for uploading
    only about a day."*
  - **The doc records the residue** (`:926-930`): *"A vault written before M5 can hold the older
    early repair's `Paid` over a declined remainder; its resume still quotes and asks for that
    remainder, but this line cannot see it (D203's recorded residue)."*
- **Rule 2** (`abandon_pre_pay`, `seal_resume.rs:530-555`). The predicate (`:532-533`):
  `payment_recorded(journal.receipt(seal_id).map_err(CliError::from)?.as_ref())` `||`
  `state == WorkState::IncompletePostPay`.
  One message serves both clauses (`:540-554`): *"work {} has already been paid for — a payment
  receipt is journaled for it. Abandoning it would forfeit that payment permanently, and antseal
  will not do that on request. Finish it instead by re-running `{}`: no quote the receipt already
  maps is paid again, and the network's payment proofs stay usable for uploading only about a
  day"*.

### 1.2 The legacy shapes, executed: the money action is right, the words are not

Each shape was planted through the store's own writers, then read by every surface (P2 §2
`U114` (a)):

| Shape | The plan said | `list` said | Rule 2 refused by | The next resume asked |
|---|---|---|---|---|
| **Case 1** — `Paid` over a pre-`S50` revert-only receipt (D204 §1.4's shape: no blob record, no mapping, one `Reverted` transaction, cost 0) | the three post-pay lines (§1.1) | *"cost: none (no payment recorded)"*, *"state: paid"*, *"no payment is recorded for it; …"* | the **state** clause — no payment is recorded | `total_ant_atto=5517 blob_count=3 priced=3`: everything; consented, `Ok((5517, true))`, paid once |
| **Case 2** — `Paid` over a partial receipt whose remainder was declined (the pre-M5 early repair) | the same three lines | *"cost: 1839 atto-ANT so far (from the payment receipt)"*, *"state: paid"*, *"RESUME PROMPTLY: …"* | the **receipt** clause — a payment is recorded | `total_ant_atto=3678 blob_count=2 priced=2`: the remainder; consented, `Ok((3678, true))`, recorded cost 5517 = 1839 + 3678 |
| **Case 0** — `Finalizing` over an empty-mapping receipt (a zero-payment seal whose upload failed; D203 §6's measured shape) | the same three lines | *"cost: none (no payment recorded)"*, *"state: finalizing"*, the re-quote note | the **state** clause | nothing: `Ok((0, false))`, no consent asked |

- **So H4's sub-claim (ii) holds.** In both legacy shapes the resume asks for exactly what is
  owed: everything in case 1, the remainder in case 2. Only the plan, `list`'s `state: paid` and
  rule 2's words disagree with it.
- **Reach.** Case 1 needs a build before `S50` and case 2 a build before M5, both before wave 40
  (`5546618`). The suite reaches case 0 only with seeded RNGs
  (`u109_a_zero_payment_seal_records_no_payment_and_says_so`,
  `crates/antseal-cli/tests/seal_command.rs:4060-4105`, `rng(0xE1)` and `rng(0xE2)`); with
  production entropy every ciphertext is unique, so only a network that answers
  `AlreadyStored` for chunks it does not hold produces it.

### 1.3 The class is reachable at `ab7226f`: X-A and X-B, executed

Both shapes were built by the pipeline, through an expiring double of the `ExpiringOnce` kind,
with no hand-set tag (P2 §2 `U114` (a), E3):
- **X-A — a proofs-expired re-consent, declined.** This is the shape
  `declining_the_proofs_expired_consent_leaves_the_work_incomplete` builds
  (`tests/seal_resume.rs:448`); that test asserts only `is_incomplete()` (`:467`). After the
  decline the fine tag is `Finalizing` over the expired receipt (5517 atto-ANT, 3 blob records,
  3 mappings). The plan says *"PAID — upload was interrupted part-way"* / *"resume the upload
  (no further payment)"* / *"This seal is already paid for. Finishing it needs no further
  payment, …"*. The next resume asks `total_ant_atto=5517 blob_count=3 priced=3 …
  proofs_expired=true`: a second payment of everything. Rule 2's way forward, *"no quote the
  receipt already maps is paid again"*, is literally true and practically false here — the
  re-quote mints fresh quote hashes, and every blob is bought again.
- **X-B — a proofs-expired re-payment that strands after one sub-batch** (exit 28; through the
  real `VaultReceiptSink` the capture holds the landed partial alone). The fine tag is
  `Finalizing` over `storage_cost_atto=1839`, one blob record. The plan prints the same three
  lines; the next resume asks `total_ant_atto=3678 blob_count=2 priced=2`.
- **Neither needs a legacy binary, a seeded RNG or a lying network.** D37 Decision 6's path, as
  D179 judges it, produces both.
- **Where the lines are read.** The consent screen prints the plan above its quote
  (`crates/antseal-cli/src/seal_consent.rs:119-121`,
  `out.extend(self.resume_plan.iter().cloned())`), and a post-pay resume asks for consent only
  when it is about to charge (`crates/antseal-cli/src/pipeline/resume.rs:240-255`, the
  remainder; `:295-302`, the expired arm). So whenever the post-pay lines reach a consent screen,
  *"no further payment"* sits directly above a request for payment (code-traced). `seal
  --dry-run` returns the same vector (`seal_run.rs:402-404`) as `--json`'s `resume_plan`
  (`:321-326`; D45 §5).

### 1.4 The clock: three copies of one sentence, and `list` already holds the one source

- `list` prints `ResumeClock::TimeBoxed.note()` (`listing.rs:281-292`, a `pub const fn` that
  returns `&'static str`), keyed on `payment_recorded` (D203 M2): *"RESUME PROMPTLY: a payment
  for this seal is recorded, and its payment proofs stay usable for uploading only about a day —
  after that, finishing it costs a second payment"* (`:288-290`).
- The other two user-facing copies of *"about a day"* are rule 2's way forward
  (`seal_resume.rs:545-546`) and the plan's coarse-state sentence (`:972-973`). The sentence's
  other face, *"more than 24 hours old by its block time"*, is exit 29's Display
  (`crates/antseal-cli/src/error.rs:806`) and the proofs-expired consent warning
  (`seal_consent.rs:178-184`). Those are not copies of this sentence, and no ruling here moves
  them.
- **Executed:** a stranded `Anchored` partial, with a `Confirmed` and with a `Submitted` mapping,
  gets a three-line plan with no clock, while `list` prints *"RESUME PROMPTLY: …"* for the same
  work.

### 1.5 Rule 2's two clauses, and its coupling to D185 R4's question

- **One text, two clauses, executed.** The message of §1.1 was printed for the stranded
  `Confirmed` and `Submitted` partials, for X-A, X-B and case 2 (the receipt clause), and for
  cases 0 and 1 (the state clause), where no payment is recorded at all. So *"has already been
  paid for"* is false in every state-clause refusal — cases 0 and 1 hold a receipt that maps
  nothing, and a post-pay tag with no receipt holds none — and it overstates a partly paid work in
  the receipt clause.
- **Why the predicate cannot simply narrow.** `AbandonPreview::read` returns `None` unless the
  effective state is pre-pay and no payment is recorded (`seal_resume.rs:701-703`). `run_abandon`
  asks D185 R4's question only when a preview exists (`:841-859`), then calls `abandon_pre_pay`
  (`:860`). Drop the state clause alone, and a post-pay tag with no recorded payment would get no
  preview and no question, and the engine would abandon it: a destructive act with no
  confirmation. The preview's predicate would have to widen in the same act. The shapes that
  change would free have no production reach (§1.2), and refusing them costs no money: the resume
  asks before it charges (executed, §1.2).

### 1.6 Nothing promises compatibility for a vault an unreleased build wrote (H4's sub-claim (i))

- `README.md:27-29`: *"There is no release yet … Treat it as pre-release: the CLI surface is not
  frozen until U32"*.
- `docs/user/format-stability.md:36-39` (*"It is conditioned on *released*"*) is about bundle
  formats: at `ab7226f` the file says *"vault"* 0 times and *"bundle"* 19 times (case-insensitive
  line counts).
- P2's case-insensitive grep for older- or existing-vault phrases over `docs/user`, `README.md`,
  `MVP-SPEC.md`, `CONTRIBUTING.md` and `docs/threat-model.md` found 0 hits, while *"vault"*
  appears in six `docs/user` files. The vault-format rule lives in code comments and decisions
  only (`crates/antseal-cli/src/vault/store.rs:89-91`: *"Bumping it is a vault-format event"*).

### 1.7 The price of an exact coverage check

- **Exact coverage needs the staged blobs.** `uncovered_blobs` (`resume.rs:669-679`) takes
  `&[Blob]`, and only `load_staged` (`:329-344`) yields them. It decrypts and re-hashes every
  staged unit and, on any failure, WRITES `set_state(…, SealState::Abandoned)` (`:340`). That is
  unusable from a renderer, unusable from `seal --dry-run` (D45 §5: no vault write), and
  forbidden by `resume_plan_lines`' own doc (`seal_resume.rs:906-909`). `ResumeCandidate`
  (`:70-92`) holds no blob set.
- **A count proxy is cheap but blind where it matters.** Comparing the recorded plan's expected
  slots with `receipt.blobs.len()` needs one more record read in `seal_run.rs` and a parameter.
  It cannot see X-A — the expired receipt covers every blob by count — so it would not remove the
  need for the clock line. Not taken.

### 1.8 What the copy change reddens (executed, P2 E6)

P2 planted its proposed copy in the shadow's `seal_resume.rs` alone: both clause messages, the
receipt-keyed post-pay arms, the coarse-state sentence deleted, and the clock line in every arm
with a recorded payment. It ran `--lib` and seven integration targets
(`seal_command`, `machine_mode`, `seal_resume`, `list_command`, `work_state_word`,
`seal_journal`, `anchor_gate_resume`). The run exited 101 with *"3 targets failed"*:
- lib *"332 passed; 1 failed"*: `the_resume_plan_names_what_is_staged_and_whether_money_moved`,
  at the assertion `lines.contains("PAID")` (`seal_resume.rs:1177`; the same test pins
  *"no further payment"* and *"about a day"* at `:1178-1179`);
- `machine_mode` *"15 passed; 1 failed"*: `envelope_fixtures_match_the_committed_snapshot`, *"the
  JSON envelope drifted from the committed fixture"*;
- `seal_command` *"51 passed; 5 failed"*: four rule-2 tests, each printing the new opening
  (`a_paid_work_is_refused_and_the_receipt_is_the_authority_not_the_tag`,
  `a_paid_work_is_refused_through_the_abandon_surface_and_nothing_changes`,
  `d203::s48_window_c_a_paid_tag_over_a_pre_pay_mirror_is_post_pay_to_every_reader`,
  `u110::u110_the_paid_refusal_offers_a_way_forward_true_of_a_partly_paid_work`), and
  `u110::u110_a_declined_remainder_leaves_the_tag_pre_pay_and_the_plan_says_the_rest_is_owed`
  (`left: 4`, `right: 3` — the plan gained its clock line).
- Green: `anchor_gate_resume` 2, `list_command` 27, `seal_journal` 29, `seal_resume` 16,
  `work_state_word` 4. Every red was predicted and nothing else reddened.
- **The needles behind those failures** (`tests/seal_command.rs` at `ab7226f`): `:1354`,
  `:1355`, `:1359`, `:1615`, `:3353-3354`, `:4752`, `:4758`, and `mod u110`'s
  `PLAN_PAYMENT_RECORDED` (`:4184-4187`) with its `plan_c.len() == 3` (`:4374`).
- **The snapshot's fixture is a state no writer reaches.** `json-envelopes.txt:36` is rendered by
  `fixture_dry_run_resume()` (`crates/antseal-cli/tests/machine_mode.rs:1041-1066`) from
  `journal_state: Some(SealState::Paid)` with receipt `None`, but `consent_anchor_pay` writes the
  receipt (`resume.rs:554`) before it tags `Paid` (`:570-572`). Under the new arms that fixture
  would render the no-payment arm.
- **Phrase census:** 0 hits for *"already been paid for"*, *"PAID —"*, *"upload only"* and *"no
  further payment"* in `docs/user`, `README.md`, `MVP-SPEC.md` and `CONTRIBUTING.md` (positive
  control: *"antseal abandon"*, 3 hits in `docs/user/timestamp-authorities.md`). Rule 2's text is
  free `Usage` text and is in no snapshot; `cli-errors.display.txt` holds none of these sentences.

## 2. RULING

One lane, L-MONEY2, builds every rule below: they edit the same lines of `seal_resume.rs`.

### §2 R1 — The post-pay plan arms take money from the receipt (`U114`)

`resume_plan_lines` (`crates/antseal-cli/src/seal_resume.rs:903-978`): the post-pay arms take
money from the receipt, as the `Anchored` arms already do (D203 M4).
- `Paid` with `payment_recorded(receipt)`: staged *"a payment is recorded; the upload has not
  started"*, remaining *"pay the rest, if any, then upload"*.
- `Finalizing` with `payment_recorded(receipt)`: *"a payment is recorded; the upload was
  interrupted part-way"* / *"pay the rest, if any, then resume the upload"*.
- `Paid` or `Finalizing` without a recorded payment: *"past its payment step, but no payment is
  recorded"* / *"pay, if anything is priced, then upload"*. The lane may word the sub-case with no
  receipt at all, which the resume fails as `Corrupt` (`resume.rs:282-286`, *"a post-pay work
  has no journaled receipt"*).
- The lane may tighten any text. Every clause must stay TRUE of a fully paid, a partly paid, a
  `Submitted`-only and an expired payment, and the lane states which it checked for each.

*Why:* the arms keyed on the tag are false in cases 0, 1 and 2 and in X-A and X-B (§1.2, §1.3),
and the receipt is the money authority (`S16`; D203 M1). *"Pay the rest, if any"* is what the
resume does over any recorded payment: it quotes what the receipt's records do not cover and asks
only if that prices something (`resume.rs:220-255`). *"Pay, if anything is priced"* is what it
does where none is recorded: case 1 asks for everything, case 0 asks nothing (§1.2). The exact
alternative, a coverage check, is unaffordable in a renderer (§1.7).

### §2 R2 — One clock sentence, keyed on the receipt in every arm (`U115`, and `U114`'s expired shapes)

Whenever `payment_recorded(receipt)`, in ANY arm — the stranded `Anchored` arm included — the
plan's last line is `"    "` followed by `crate::listing::ResumeClock::TimeBoxed.note()`: the one
source `list` prints, so the two cannot drift. The coarse-state sentence (*"This seal is already
paid for. Finishing it needs no further payment, …"*, `seal_resume.rs:970-976`) is DELETED. The
function's doc (`:906-930`, including the *"recorded residue"* paragraph) is rewritten to what is
built.

*Why:* the plan and `list` then key the clock on the same predicate (D203 M2) and print the same
words by construction. The coarse-state sentence is false for X-A and X-B at `ab7226f`, and for
cases 0, 1 and 2 (§1.2, §1.3). Its cost, as P2 priced it: the *"RESUME PROMPTLY:"* imperative
also shows on a consent screen the user reached by resuming — redundant there, not false.

### §2 R3 — Rule 2 speaks per clause; its predicate is unchanged (`U115`)

Abandon's rule 2 (`abandon_pre_pay`, `seal_resume.rs:530-555`): the predicate is UNCHANGED
(`payment_recorded(…) || state == WorkState::IncompletePostPay`); the message splits by clause.
- **Receipt clause:** *"a payment is recorded for work {id} — its payment receipt maps quotes to
  transactions. Abandoning it would give that payment up for good, and antseal will not do that
  on request. Finish it instead by re-running `{cmd}`, which asks before any payment and pays
  only for what the receipt does not cover — but its payment proofs stay usable for uploading
  only about a day, and after that finishing it costs a second payment"*.
- **State clause** (a post-pay tag, no payment recorded): *"work {id} is past its payment step
  (the journal records `{tag}`), but no payment is recorded for it, and antseal does not abandon
  a work in that state on request. Finish it instead by re-running `{cmd}`, which quotes
  whatever is not yet stored and asks before any payment"*.

*Why:* one text cannot be true of both clauses (§1.5). The old way forward, *"no quote the
receipt already maps is paid again"*, is literally true and practically false for X-A, where
every blob is bought again under fresh quote hashes (§1.3). *"Pays only for what the receipt does
not cover"* is true of every shape — the unobserved-landing capture included, because a receipt
covers a blob only through a record (`uncovered_blobs`, `resume.rs:669-679`).

Refused: changing the predicate (P2's Option 2). It would have to widen `AbandonPreview::read`'s
predicate in the same act, or a destructive abandon would run with no D185 R4 confirmation
(§1.5); and the shapes it frees have no production reach (§1.2).

### §2 R4 — Recorded, not fixed: two legacy contradictions

Legacy, with no production reach (§1.2):
- `list` prints *"state: paid"* beside *"no payment is recorded"* for a pre-`S50` revert-only
  `Paid` vault (case 1). The word is the tag's name (D203 R1), and the state vocabulary is
  `--json`-visible.
- `abandon`'s help line, *"Discard an interrupted seal that nothing has been paid for"*
  (`crates/antseal-cli/tests/snapshots/cli-surface.help.txt:16`, `:410`), is contradicted by such
  a vault, which is refused, and by case 0, which has no production reach either.

*Why:* changing either moves a `U32` surface — the `--json` state vocabulary, or a help line —
for shapes with no production reach (§1.2).

### §2 R5 — The snapshot's fixture gets a state a writer produces (`U114`)

`fixture_dry_run_resume()` (`crates/antseal-cli/tests/machine_mode.rs:1041-1066`) gives its
`Paid` candidate a covering receipt — no writer produces `Paid` without one, because
`consent_anchor_pay` writes the receipt before `Paid` (§1.8). Then
`crates/antseal-cli/tests/snapshots/json-envelopes.txt:36` is re-blessed DELIBERATELY: only
`resume_plan` VALUES change, and no key is added or removed. The lane proves that with a key-set
diff and justifies every changed line in its report.

*Why:* D203 M9's fixture-realism rule. A frozen snapshot rendered from a writer-less state pins
words no user can see, and under R1 the `None` receipt would render the no-payment arm.

### §2 R6 — Tests

P2 §2 `U114` (g) and `U115` (g), detailed in §3: G-U114-1, G-U114-2 and G-U114-X (X-A and X-B
built by the PIPELINE, never with a hand-set tag), each asserting the plan AND what the next
resume asks; G-U115-1, G-U115-2 (one assertion over both surfaces) and G-U115-3. Plants PU114-1
to -3 and PU115-1 to -3, each red by message. The existing pins are re-pointed, not deleted:
`the_resume_plan_names_what_is_staged_and_whether_money_moved`, `seal_command.rs`'s rule-2
needles, and `mod u110`'s `PLAN_PAYMENT_RECORDED`, whose GM3 plan grows from 3 lines to 4 (the
clock); the lane states the new count.

### What no ruling here moves

- **Not heavy.** `seal_resume.rs` and the tests are off `HEAVY_TRIGGER_PATHS`
  (`scripts/gate-features.sh:112-121`).
- **`U32`:** `seal --json`'s `resume_plan` values only (`json-envelopes.txt:36`, re-blessed); no
  key is added or removed. D203 §2 already treats `resume_plan` lines as values that may change
  before `U32`.
- **No exit code, class, `CliError` variant, Display template, help line, config key, user doc
  or format surface.** `cli-errors.display.txt` and `cli-surface.help.txt` stay byte-identical.
- **Unchanged:** rule 2's predicate; `AbandonPreview` — D185 R4's question and D203 M6a–M6b's
  progress line; `list`'s note (the plan reuses it, and `listing.rs` is only read); and every
  file under `pipeline/`.

## 3. Fault plants

The implementing lane owes these. The red baselines come first, on the unedited tree — P2's
probes are the red baseline for G-U114-1, G-U114-2, G-U114-X and G-U115-1 to -3 (the lines quoted
in §1.2–§1.5) — and each plant is judged by its **message**; every restore is followed by a
`touch`. In-process tests (`--lib seal_resume::`, `--test seal_resume`) run in the shared target
under the lock. `seal_command.rs` and `machine_mode.rs` spawn the binary, so they, and every
plant, run in a shadow copy with a private `CARGO_TARGET_DIR`.

**The green tests — the load-bearing half.** Each `U114` test asserts the plan AND what the next
resume asks, read from `ScriptedConsent`'s `seen` record (`tests/common/mod.rs:288`).
- **G-U114-1 (case 1).** `Paid` over a revert-only receipt, written by production writers: the
  tag walk `stage_work` performs (what the pre-M5 repair wrote) and `put_receipt` (what the
  pre-`S50` sink wrote). The plan says *"no payment is recorded"* and *"pay, if anything is
  priced"*; abandon's refusal does not say a payment is recorded; a declining resume shows
  `blob_count == 3` and `priced == 3`.
- **G-U114-2 (case 2).** `Paid` over a partial receipt: the plan says *"a payment is recorded"*
  and *"pay the rest, if any"*, and its last line is the clock; the resume asks for the 2-blob
  remainder.
- **G-U114-X (reachable at `ab7226f`).** X-A and X-B built by the pipeline: `ExpiringOnce` with a
  declining consent (X-A), and an expire-then-strand double (X-B). No plan line contains *"no
  further payment"* or *"already paid for"*; the clock line is present; the next resume's
  consent has `proofs_expired == true` (X-A) or `blob_count == 2` (X-B).
- **G-U115-1.** On a partly paid fixture, abandon's refusal starts *"usage error: a payment is
  recorded for work"* and contains neither *"has already been paid for"* nor *"forfeit that
  payment permanently"*. The fixture is preferably built by the pipeline — an exit-28 strand
  through `CapturingBackend::crashing_after` (`tests/seal_matrix.rs:131`), whose capture goes
  through the real `VaultReceiptSink`. `mod u110`'s `anchored_with(…, Some(&fixture_receipt()))`
  (`tests/seal_command.rs:4245`, `:48`) is usable if the test says which writer it stands for:
  it is a hand-built `Confirmed` mapping with no blob record and a cost of 4 200.
- **G-U115-2.** For one work, the `seal --dry-run` plan's last line equals
  `format!("    {}", ResumeClock::TimeBoxed.note())`, and `list`'s note is the same string — one
  assertion over both surfaces, so drift is red.
- **G-U115-3.** A state-clause refusal (case 1) claims no payment.
- **Kept green:** the `u110_*` tests (`mod u110`, `tests/seal_command.rs:4168`), and GM3's
  equality once `PLAN_PAYMENT_RECORDED` gains the clock line.

**The plants — proof that those tests can fail**

| Plant | Must redden |
|---|---|
| PU114-1: the tag-only `Paid` and `Finalizing` arms restored | G-U114-1, G-U114-2 and G-U114-X (*"the plan promised no further payment while the resume asked for N blob(s)"*) |
| PU114-2: the `candidate.state == IncompletePostPay` sentence restored | G-U114-X (*"already paid for"* found) |
| PU114-3: the no-payment arm keyed on the tag | G-U114-1 |
| PU115-1: the old opening restored | G-U115-1 (*"has already been paid for"* found) |
| PU115-2: the clock line removed from the `Anchored` arm | G-U115-2 (*"the stranded plan carries no proof clock while list says RESUME PROMPTLY"*) |
| PU115-3: a hand-copied clock string with one word changed | G-U115-2 (drift) |

`envelope_fixtures_match_the_committed_snapshot` reddens until `json-envelopes.txt:36` is
re-blessed; the re-bless is the copy change, reviewed line by line with its key-set diff (§2 R5).

## 4. What this record does NOT decide

- **A computed coverage line.** The count proxy is not taken (§1.7). The plan says *"if any"* and
  *"if anything is priced"*, and the consent screen's quote below it carries the figure.
- **R4's residue** — `list`'s *"state: paid"* for case 1, and `abandon`'s help line. Recorded,
  not fixed, and no row is minted for it.
- **The expired arm's money.** `S53` (D209: the replaced payment's totals) and `S55` (a
  re-payment that re-buys blobs paid minutes earlier in the same run) belong to their own
  records. This record changes no `pipeline/` file.
- **The clock over a capture that holds no record.** P2 found the clock's *"its payment proofs
  stay usable for uploading only about a day"* untrue of a `Submitted`-only capture that maps
  quotes but holds no record — an unobserved landing's: no proof exists for it. `list` already
  printed the sentence for such a work at `ab7226f`, beside *"cost: 0 atto-ANT so far (from the
  payment receipt)"* (executed, P2 E7). D208 owns that shape (`S51`, `S54`): under D208 §2 R5
  the capture carries records and proofs, and D208 §2 R10 records the pre-wave residue. Because
  the plan now prints `list`'s own sentence, whatever D208 does to that shape reaches both
  surfaces at once.
- **`MockBackend::double_paid()`**, which cannot see a blob bought twice under a re-quote (P2 §3;
  12 call sites), is an instrument finding for the ledger. This record's tests do not lean on it:
  they assert what the next resume asks.
- **Abandoning a post-pay tag with no recorded payment** after a confirmation (Option 2). Refused
  in §2 R3; reopening it needs a production shape that reaches the refusal.
- **New rows.** This record mints none. D203 §6's misattribution of case 2's refusal is corrected
  by this record's addendum on D203.

## 5. Edit list — per write scope, with the lane named before this record was written

### L-MONEY2 (round 2) — `U114` + `U115`: §2 R1–R6

- `crates/antseal-cli/src/seal_resume.rs` — ONLY `resume_plan_lines` and its doc (`:903-978`),
  `abandon_pre_pay`'s rule-2 message (`:530-555`; the predicate stays byte-identical), the
  in-file unit test(s) that pin those texts (`:1141-1190`), and new unit tests appended at the
  END of its test module.
- `crates/antseal-cli/tests/seal_command.rs` — ONLY the rule-2 needles (`:1354`, `:1355`,
  `:1359`, `:1615`, `:3353-3354`, `:4752`, `:4758`) and `mod u110`'s `PLAN_PAYMENT_RECORDED`
  (`:4184-4187`) with its count assertion (`:4374`); new tests appended at the END.
- `crates/antseal-cli/tests/machine_mode.rs` — ONLY `fixture_dry_run_resume()` (`:1041-1066`).
- `crates/antseal-cli/tests/snapshots/json-envelopes.txt` — ONLY line 36, re-blessed by the
  file's own documented procedure.
- `crates/antseal-cli/tests/seal_resume.rs` — new tests appended at the END (G-U114-X).
  L-MONEY2 holds this file until it reports; L-RESUME3 (`S53`, D209) appends after it, once the
  orchestrator hands the file over.
- **Builds:** `seal_command.rs` and `machine_mode.rs` spawn the binary, so they run only in a
  shadow copy with a private `CARGO_TARGET_DIR`; `cargo test -p antseal-cli --lib seal_resume::`
  and `--test seal_resume` (in-process) may run in the shared target under the lock.
- **Must not:** `listing.rs` (read only: `ResumeClock` is already `pub`), `pipeline/**`
  (`resume.rs`, `receipt_sink.rs`, `journal.rs` — the `S53`, `S51` and `S54` lanes' area),
  `seal_run.rs`, `seal_consent.rs`, `commands.rs`, `crates/antseal-cli/src/error.rs`,
  `cli-errors.display.txt`, `cli-surface.help.txt`, or `docs/**`.

### The citation lane (round 3) — living-doc citations

After the last code edit, the living documents' `path:line` citations into `seal_resume.rs` and
the edited tests are re-pointed by meaning.

### RECORDS-2 — this record and dated addenda

D203 (the post-pay arms and the clock; §6's *"Left open"* entries for `U114` and `U115`, and its
misattribution of case 2's refusal) and D185 (§2 R3's paid-work refusal now speaks per clause;
R4's confirmation path is untouched).

### Orchestrator — `TODO.md`, `tasks/U.md`, `docs/decisions/README.md`, `docs/instrument-ledger.md`

- `U114` and `U115`: their ticks against §3, after L-MONEY2.
- This record's index row and register row.
- The ledger: P2 §3's findings that bear on this record — D203 §6's misattribution of case 2's
  refusal, the X-A test that pins none of its words (`tests/seal_resume.rs:448`), and the
  writer-less fixture behind `json-envelopes.txt:36` — and `double_paid()`'s blind spot (§4).
- The hand-over of `tests/seal_resume.rs` to L-RESUME3 after L-MONEY2 reports.
- The close gate: heavy and E2E for the wave's `pipeline/` rows (D208, D209); this record's
  files alone would not trigger them.

## 6. As built — wave 41, lane L-MONEY2 (recorded in place before this record was first committed)

Every verdict below was read from an exit file, except the `rustfmt` and personal-data checks
(per the lane's report), and every red was judged by its message. This records lane read the exit
files and verdict lines back, and each matches the report. L-MONEY2 measured against `ab7226f`,
ran its baseline, red runs, re-bless and plants in a `git archive HEAD` shadow with a private
target, then its tests and clippy in the shared tree under the locks. The dispatch log records
no scope grant and no ruling amendment during the lane. Re-read for this section,
`seal_resume.rs`, `seal_command.rs` and `json-envelopes.txt` equal the lane's final sha256 and
its shadow copies. The other two passed to L-RESUME3 when the lane reported and have moved since:
`machine_mode.rs` gained one line in its `ConsentRequest` literal (`:1029`, D209 R8), so the
fixture cited below sits one line lower than in the lane's files, and `tests/seal_resume.rs` grew
after `mod d210`, its first 1552 lines still byte-equal to L-MONEY2's final file. The lane's own
hunks all lie in §5's regions: `seal_resume.rs` +297/−54, `seal_command.rs` +23/−12,
`machine_mode.rs` +18/−1, `tests/seal_resume.rs` +740 (after `ab7226f`'s 812 lines) and
`json-envelopes.txt` +1/−1. The plant-marker `git grep` exits 1, with a positive control.

- **§2 R1 (`U114`).** `resume_plan_lines` (`crates/antseal-cli/src/seal_resume.rs:941-1035`, doc
  `:941-979`) binds `let recorded = payment_recorded(receipt);` (`:989`), and the post-pay arms
  key on it (`:1003-1018`); the `Staged`, `Anchored` and untagged arms keep their texts. `Paid`
  with a payment recorded reads *"a payment is recorded; the upload has not started"* / *"pay the
  rest, if any, then upload"*, and `Paid` or `Finalizing` over a receipt that maps nothing reads
  *"past its payment step, but no payment is recorded"* / *"pay, if anything is priced, then
  upload"*, as ruled.
  - **Deviation: "part-way" is dropped.** `Finalizing` with a payment recorded reads *"a payment
    is recorded; the upload was interrupted"* / *"pay the rest, if any, then resume the upload"*.
    `finalize()` writes `Finalizing` just before its first `finalize_batch` (`resume.rs:585-586`
    at `ab7226f`), so such a work may have uploaded nothing, and X-A and X-B stored no blob
    before they stopped (executed, per the lane's report). R1 let the lane tighten any text.
  - **Deviation: a post-pay work with no receipt gets its own words**, as R1 allowed: *"past its
    payment step, but no payment receipt is journaled"* / *"none — resuming fails without that
    receipt"*. G-U115-3 measures why: the resume fails with
    `SealError::Journal(JournalError::Corrupt { .. })` before any backend call (0 calls, 0
    consents), which reaches the user as exit 12, vault-auth-failure (`pipeline/error.rs:359`,
    `pipeline/journal.rs:689`, `error.rs:428`). No writer leaves that shape.
  - **The four shapes R1 names, as the lane checked them** (per its report): fully paid (X-A's
    pipeline-written receipt, 3 records), partly paid (case 2, and the sink captures of X-B and
    of G-U115-1's strand, 1 record each), `Submitted`-only (unit rows over `submitted_receipt()`)
    and expired (X-A). *"Pay the rest, if any"* asks nothing when fully paid, 2 of 2 priced in
    each partly paid case, every unrecorded blob of a `Submitted`-only batch (whether that is a
    second payment is D208's question), and 3 of 3 when expired, which the clock line names.
    *"The upload has not started"* is code-traced: `Paid` is written after the receipt
    (`resume.rs:570-572`) or by the repair (`:276`), before `finalize()` writes `Finalizing`.
- **§2 R2 (`U115`; `U114`'s expired shapes).** Whenever `recorded`, in any arm, the last line is
  `format!("    {}", crate::listing::ResumeClock::TimeBoxed.note())` (`:1028-1033`), `list`'s one
  source (`listing.rs:281-292`). Searched by phrase, the coarse-state sentence, the four tag-only
  arm texts and rule 2's old opening and way forward each held one line of `seal_resume.rs` at
  `ab7226f` and hold none now. The doc's residue paragraph became *"Money comes from the
  receipt, in every arm (D203 M4, D210 R1)"* (`:949`) and *"The proof clock is `list`'s own
  sentence (D210 R2)"* (`:970`). "Any arm" is literal: the `Staged` and untagged arms also close
  on the clock over a recorded payment, and
  `the_proof_clock_follows_the_receipt_in_every_arm` pins both. Residue (the lane's D6): over
  `Staged` with a recorded payment, *"anchor, pay, upload"* would be false, but no writer
  produces it — `consent_anchor_pay` writes `Anchored` before it arms the sink and pays
  (`resume.rs:495`, `:504`, `:510` at `ab7226f`).
- **§2 R3 (`U115`).** Rule 2 is `seal_resume.rs:530-593`. Its predicate (`:532-533`) is
  byte-identical to `ab7226f`'s, at the same lines, so the refused set is unchanged. The receipt
  clause (`:546-563`) and the state clause over a receipt that maps nothing (`:572-576`,
  `:587-590`) are R3's texts verbatim.
  - **Deviation: a third text, for a post-pay tag with no receipt** (`:577-586`). R3's way forward
    is false there, because the re-run fails as above, so the refusal ends *"Its journal holds no
    payment receipt, so re-running `{rerun}` cannot finish it either: a resume past the payment
    step needs that receipt"*.
  - **Deviation: *"(the journal records `{tag}`)"* only when a fine tag exists** (`:569-571`).
    The state clause can also fire on a post-pay mirror with no tag, where there is no tag to
    name; that shape is writer-less, because the mirror never leads the tag.
  - **Deviation: the refusal reads the receipt a second time** (`:539`; the comment at
    `:535-538`). Binding the predicate's read to a variable would have changed the predicate's
    text, which §5 keeps byte-identical. The cost is one more decrypt, on the refusal path only,
    and the vault lock the handler holds keeps it the same record.
- **§2 R4.** Recorded, not fixed: `listing.rs` and `cli-surface.help.txt` are unchanged against
  `ab7226f`, so `list`'s *"state: paid"* beside *"no payment is recorded"*, and `abandon`'s help
  line (`cli-surface.help.txt:16`, `:410`; its source `cli.rs:222`), stand.
- **§2 R5 (`U114`).** `fixture_dry_run_resume()` (`tests/machine_mode.rs:1042-1084`) passes
  `Some(&receipt)` (`:1082`): a real `MockBackend::pay` over a quote for one synthetic blob
  (`:1055-1060`), under the control
  `!receipt.blobs.is_empty() && receipt.covers_all_paid_quotes()` (`:1061-1064`). Unblessed,
  `envelope_fixtures_match_the_committed_snapshot` exited 101 (*"the JSON envelope drifted from
  the committed fixture …"*), and the file's `ANTSEAL_BLESS=1` procedure then exited 0. The
  lane's key-set diff reads *"changed line numbers (1-based): [36]"* and *"line 36: key paths
  old=21 new=21 equal=True"* (key names, leaf types and the array's length); values moved only at
  `/result/resume_plan[1]`, `[2]` and `[3]` — the `Paid` arm's two lines, and `list`'s clock in
  place of the deleted sentence, each true of a covering receipt. This records lane re-measured
  the line against `ab7226f`'s file with its own script: the same, with 9 key names on each side,
  the array still 4 long, and every other value equal. sha256 `39df256f…` → `1477683d…`.
- **§2 R6 — tests.** Nine new tests, each red first over `ab7226f`'s source (exit 101: lib
  *"FAILED. 8 passed; 3 failed"*, the third the re-pointed test; `seal_resume` *"FAILED. 0 passed;
  7 failed"*), then green.
  - Unit, at the end of `seal_resume.rs`'s tests: `every_arm_takes_its_money_from_the_receipt`
    (`:1347`; 9 rows, 14 checks, counted) and
    `the_proof_clock_follows_the_receipt_in_every_arm` (`:1446`; 5 arms by 4 shapes, 20 counted).
  - `mod d210` (`tests/seal_resume.rs:825`, one `IsolatedVault` per test): G-U114-1
    `u114_case_1_a_paid_tag_over_a_receipt_that_maps_nothing_is_not_called_paid` (`:1201`),
    G-U114-2 `u114_case_2_a_paid_tag_over_a_partial_payment_says_the_rest_is_owed` (`:1249`),
    G-U114-X `u114_x_a_a_declined_expired_proof_re_consent_is_not_called_paid` (`:1296`) and
    `u114_x_b_a_stranded_expired_proof_re_payment_is_not_called_paid` (`:1340`), G-U115-1
    `u115_abandon_refuses_a_partly_paid_work_by_what_its_receipt_records` (`:1383`), G-U115-2
    `u115_the_plans_proof_clock_is_the_sentence_list_prints` (`:1438`) and G-U115-3
    `u115_a_post_pay_tag_with_no_payment_recorded_is_refused_without_claiming_one` (`:1482`).
    The `U114` tests also assert the next ask: 3 blobs, 3 priced (case 1); 2 and 2 (case 2, X-B);
    3, 3 and `proofs_expired` (X-A). At `ab7226f` six of the seven were red by the messages their
    plants below reproduce, and G-U115-3 by *"usage error: work … has already been paid for — …"*.
  - Beyond R6 (the lane's D8, D10): X-A and X-B start from a payment the pipeline made (a resume
    killed at `PostReceiptJournalPreFinalize`); a new double, `StrandsAfterOneLine` (`:1056`),
    strands through the real `VaultReceiptSink`, for X-B and for the first-payment strand (exit
    28, the tag stays `Anchored`) that is G-U115-1's and G-U115-2's partly paid work. No
    assertion uses a value `S53` changes.
  - **Deviation: placement.** All seven run in-process in `tests/seal_resume.rs`, none in
    `seal_command.rs`, and those that read a plan take it from `run_seal`'s two reads (`detect`,
    then `recorded_receipt` into `resume_plan_lines`), not from `run_seal`. GM3's `dry_run_plan`
    still pins the production caller's plan literally, clock included.
  - **Deviation: G-U115-2's message** is *"the plan's proof clock and list's note for the same
    work drifted apart"*, for PU115-2 and PU115-3 alike; §3's table anticipated *"the stranded
    plan carries no proof clock while list says RESUME PROMPTLY"*.
  - **Re-pointed.** `the_resume_plan_names_what_is_staged_and_whether_money_moved`
    (`seal_resume.rs:1198`) pins the `Paid` arm's two lines, the absence of *"no further
    payment"*, and `ends_with(ResumeClock::TimeBoxed.note())` on the post-pay and stranded arms.
    The rule-2 needles in `seal_command.rs` (`:1355`, `:1359`, `:1366`, `:1622`, `:3361`,
    `:4763`, `:4769`) pin the receipt clause's words, and the comment at `:1362-1364` cites D210
    R3. `PLAN_PAYMENT_RECORDED` (`:4193`) is `[&str; 3]`, the clock spelled out as its third
    element (G-U115-2 is the same-source pin), and GM3's plan is 4 lines (`:4385`): header,
    staged, remaining, clock.
  - **Counts.** Shadow, `ab7226f` → final: lib 333 → 335, `seal_resume` 16 → 23; `seal_command`
    56, `machine_mode` 16 and `list_command` 27 unchanged. Shared tree, other lanes' `pipeline/`
    and `antseal-net` edits compiled in: lib 336 (one is another lane's) and `seal_resume` 23. On
    the final bytes, after the plants: lib 335, `seal_resume` 23, and
    `cargo clippy -p antseal-cli --locked --all-targets -- -D warnings` exit 0 with a
    `Checking antseal-cli` line. The shared clippy pass also exited 0, but from cache alone.
- **Plants**, in the shadow, each exit 101 and restored with `cp` and `touch` (sha256 before and
  after equal to the final file's, `6eb27ee0…`); counts are passed/failed:
  - PU114-1, the tag-only arms back (lib 9/2, `seal_resume` 2/5): G-U114-1 *"the plan promised no
    further payment ("no further payment") while the resume asked for 3 blob(s), 3 of them
    priced:"* over *"staged:    PAID — the payment receipt is journaled"*; G-U114-2 (*"2 blob(s),
    2 of them priced"*); X-A over *"PAID — upload was interrupted part-way"*; X-B; G-U115-3.
  - PU114-2, the `IncompletePostPay` sentence back (8/3, 2/5): X-A and X-B by the same message
    over the new receipt-keyed lines; cases 1 and 2; G-U115-3 (*"This seal is already paid for.
    …"* in `left`).
  - PU114-3, the `Paid` arm keyed on the tag alone (10/1, 5/2): G-U114-1 *"the plan claims a
    payment the vault does not record:"* over the revert-only receipt; G-U115-3.
  - PU115-1, rule 2's old opening back (11/0, 3/4): G-U115-1 printed *"usage error: work b1d5…
    has already been paid for — a payment receipt is journaled for it. Abandoning it would
    forfeit that payment permanently, …"*; G-U114-2, X-A and X-B through `assert_receipt_clause`.
  - PU115-2, no clock on the `Anchored` arm (8/3, 6/1): G-U115-2 *"the plan's proof clock and
    list's note for the same work drifted apart:"*, a 3-line plan against *"RESUME PROMPTLY: …"*.
  - PU115-3, a hand copy reading *"about one day"* (8/3, 3/4): G-U115-2 by the same message, and
    case 2, X-A and X-B at their exact-plan assertions.
- **What no ruling here moves, re-checked.** `cli-errors.display.txt`, `cli-surface.help.txt`,
  `listing.rs`, `seal_run.rs`, `README.md` and `docs/user` are unchanged against `ab7226f`;
  §1.8's phrase census, with the new phrases added, is still 0; and the living-doc citations into
  the edited files (`seal_command.rs:814-858`, `:1140-1217`; `machine_mode.rs:415-431`;
  `seal_resume.rs:52-56`, `:84-86`, `:85`, `:136`, `:498`) all lie above the line shifts.
- **Left open.**
  - Two stale test comments outside the lane's regions quote the old rule-2 opening:
    `seal_command.rs:2784` (`:2777` at `ab7226f`), *"not the engine's "already been paid
    for""*, and the *"Red at 6e1cab3"* note at `:3370-3371` (`:3363-3364`). The orchestrator
    fixes them before this record is first committed. This records lane also found `:4666`'s
    *"Red at L-RESUME2's tree"* note quoting it; that note stays true of the tree it names.
  - Rule 2's receipt clause carries its own copy of the clock words (*"its payment proofs stay
    usable for uploading only about a day, and after that finishing it costs a second payment"*,
    `seal_resume.rs:561-562`, R3's text). So a change D208 (`S54`) makes to the clock for a
    capture that holds no record has two text sites: that clause, and `listing.rs:288-290`,
    which the plan now prints. The predicate is one, `payment_recorded`, for `list`
    (`listing.rs:689`), the plan and rule 2. D208 (`S54`) owns that coordination.
  - R4's legacy residue stands, with no row (§4).
  - Not minted, and recorded here (the lane proposes no row): `seal --dry-run`'s trailer, *"…
    re-run without --dry-run to finish it."* (`seal_run.rs:296-304`), is false over the
    writer-less no-receipt arm; `abandon_pre_pay`'s doc (`seal_resume.rs:468-481`) names only the
    receipt as rule 2's authority (pre-existing); and `list` decides its clock inline
    (`listing.rs:725-729`) while the plan keys on `payment_recorded` — they agree wherever a plan
    renders, because an unreadable receipt fails `seal --dry-run` before any plan.

## Closing — this record is not consent

It changes the money words of the resume plan and of abandon's rule-2 refusal, one fixture and
one snapshot line, inside the wave's own commits. Nothing in it authorises a push, a workflow
dispatch, a deploy or any other outward act; each of those needs the maintainer's express consent
naming the action, the destination and the account.
