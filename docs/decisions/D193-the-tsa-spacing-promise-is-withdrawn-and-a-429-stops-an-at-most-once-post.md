# D193 — The per-TSA minimum-interval promise is **withdrawn** with a dated reason; within one seal the guarantee is stated **per URL, not per authority**; and an HTTP **429 is not retried** on an at-most-once POST

- **Status: RESOLVED. H7's direction — strike the promise with a dated reason — survived. Its
  stated reason fell (b), and it missed two facts inside a single seal.**
  - **H7 — *STRIKE the promise with a dated reason (the interval needs persisted vault state;
    caveats are published-not-measured)*.**
    - **"The state does not exist" was wrong.** Every verified capture is journaled per work
      with its `endpoint` and `fetch_date` (`crates/antseal-cli/src/pipeline/anchors.rs:343-356`),
      so a last *successful* contact per URL is derivable by a vault scan. What stands in the
      way is `A32`'s contract on that field — *"recorded, never compared"* (`:160-161`) — and the
      fact that refused attempts are recorded nowhere. Honouring an interval across runs would
      need either an `A32` contract change or a new vault-global record (a vault-format event),
      plus a config key the first release would freeze.
    - **"Caveats are published, not measured" holds** (`D60-CAPTURE.log:46-49`).
    - **Missed: the within-seal guarantee is per URL, not per authority.** Deduplication is by
      exact URL and the fan-out is concurrent, and Sectigo and Entrust are one authority
      (`A31`). A list naming both sends two simultaneous requests to Sectigo.
    - **Missed: a 429 is retried at +200 ms and +600 ms** (D90 §6.3) — three requests in under
      a second to an endpoint whose only recorded caveat is a ~15-second spacing. That is
      **`A140`**, minted with this wave's rulings and ruled here (§2 R5).
  - **`A139` rides with this record.** `A31`'s tests are executed by name and recorded, so
    `A31`'s `🟡` retracts once, with both of its residues discharged (§2 R4).
- **Date: 2026-10-17**
- Owner rows: **`A137`** (§2 R1–R3); **`A140`** (§2 R5); **`A139`** (§2 R4); **`A31`** (its
  `🟡` retracted by the orchestrator, §2 R6).
- Related:
  - **`A10`** (the `Do` whose clause is struck) and **`A32`** (`fetch_date`'s contract);
  - **D90** §6.3 (the retry table; takes a dated addendum);
  - **D54** §3 (no OTS outcome ever fails a seal, which bounds §2 R5's calendar half);
  - **`U34`** (the vault bookkeeping record, whose version bump is a vault-format event);
  - **`Q26`** (the page), **`Q31`** (the first release, which would freeze a config key —
    D180 §4);
  - **D192** (SwissSign counts zero while quarantined), **D189** §2 R3 (integers stay outside
    the config subset, since this record needs none);
  - **`U49`** (the row `tsa.rs:74` points at, which holds no pacing work).

## 0. What was measured against

`HEAD` `23f3093` (local `main`; `origin/main` `cfd5868`), tree clean, 2026-10-17.

Planning lane P4 (wave 38) worked read-only and built nothing; every claim it made comes from
reading code, tests and records. No TSA was contacted, so whether Sectigo refuses inside 15
seconds, and whether a refused request counts against SwissSign's quota, are **not
established**. The availability survey (PS) found `A137` available (`after A10, U22/U26,
A31`, all `[x]`; `A31` carries `🟡`, whose residues are `A137` and `A139`) and `A139` riding
`with A137`.

Before this record was written, the records lane re-read the load-bearing lines through
`git show 23f3093:<path>`, because round-1 lanes were already editing the tree. One locator
moved and one fact was added:
- The 429 arm of the classifier is `crates/antseal-anchor/src/http/retry.rs:131-135`
  (`429 | 503 => RetryVerdict::Retry` at `:132`). The planning report gives both `:129-133`
  and `:131-135`; the second is right.
- `Idempotency::AtMostOnceAfterSend` has **two** production call sites, the TSA POST and the
  OTS calendar submit (§1.5), so §2 R5 reaches both.

## 1. What was measured

### 1.1 The promise, and where it lives

- **Only `A10`'s `Do` promised it.** `tasks/A.md:123` ends: *"honor optional per-TSA
  minimum-interval config (Sectigo ~15 s, SwissSign ~10/day caveats)."*
- **The spec asks for less.** `MVP-SPEC.md:109`: *"documented alternates with recorded
  caveats: ... Sectigo (~15 s spacing), SwissSign (~10/day)"*; `:189`: *"**Free-TSA
  terms/rate limits** → defaults chosen with recorded caveats; configurable list; failures
  downgrade the seal report per the minimum-anchor policy rather than silently."* Both are met,
  so withdrawing `A10`'s clause is not a spec divergence.
- **No interval code exists.** `git grep -e min_interval -e minimum_interval -e MIN_INTERVAL
  -e last_contact 23f3093 -- crates/ scripts/` returns 0 lines (re-run by the records lane).
- **The prose that stands in for it.** `crates/antseal-anchor/src/tsa.rs:67-74`: *"Within one
  seal each *distinct* endpoint is contacted exactly once, so no spacing rule can be violated
  by this stage — provided the list really is distinct ... Honouring a spacing rule **across**
  invocations needs a persisted last-contact time, which is vault state this crate does not
  have; recorded as owed work (U49) rather than faked here."* `U49` (`tasks/U.md:761`) is the
  resume slot-overwrite row and holds no pacing work.

### 1.2 The caveats: published, never approached

- `testdata/anchors/A25-bootstrap/D60-CAPTURE.log:46-49`: *"All nine returned `PKIStatus:
  granted` and echoed the request nonce exactly. No TSA refused the request; no rate limit was
  hit; one request per endpoint, spaced >= 3 s (Sectigo's ~15 s spacing caveat and SwissSign's
  ~10/day quota were not approached)."*
- **Who is exposed.** The default list (`tsa.rs:102-103`, FreeTSA and DigiCert) carries
  neither caveat. SwissSign counts zero while quarantined (D192), so pacing it protects no
  evidence. A second seal on one vault cannot overlap the first, because the single-writer
  lock refuses it (`crates/antseal-cli/src/vault/lock.rs`, per P4). The realistic case under
  15 seconds is a scripted re-run after a gate abort against a Sectigo or Entrust list; its
  latency is not established.

### 1.3 The state that exists, and why it cannot be used

- **Successful contacts are recorded per work.** `artifacts_of`
  (`crates/antseal-cli/src/pipeline/anchors.rs:322`) journals each verified capture as a
  `tsa-<n>` artifact with `endpoint` and `fetch_date` (`:343-356`). The field's contract
  (`:160-161`): *"POSIX seconds at which this machine received the bytes (A32: recorded, never
  compared)"*; and `tsa.rs:44`: *"`fetch_date` is recorded as **provenance metadata and nothing
  else**"*. Refused attempts are not persisted at all.
- **The other vault-global slot** is `U34`'s bookkeeping record:
  `crates/antseal-cli/src/vault/bookkeeping.rs:53`, *"Record schema version. Bumping it is a
  vault-format event."*
- **A config key would cost a freeze.** An interval is an integer, which the config subset
  rejects (`docs/config.md`'s subset table), so it would need a string encoding or a parser
  extension, and config keys freeze at the first release (D180 §4: the measured deadline is
  `Q31`).

### 1.4 Within one seal: per URL, not per authority

- **Deduplication is by exact URL and the fan-out is concurrent.** `effective_tsa_urls`
  (`tsa.rs:127`) deduplicates strings; `capture_from_tsas` (`:375`) sends every request at once
  inside `std::thread::scope` (`:387`).
- **Two names can be one authority.** Sectigo and Entrust are one TSA behind two names
  (`A31`; `entrust_and_sectigo_count_as_one_tsa_and_the_report_says_so`,
  `crates/antseal-anchor/src/tsa/tests.rs:515`). `docs/anchors/real-smoke-runbook.md:83-85`:
  *"Sectigo's spacing constraint therefore applies across **both** names"*. A list naming both
  sends two simultaneous requests to one authority, inside its own published spacing.
- **The page contradicts itself.** `docs/user/timestamp-authorities.md:151` (§3): *"Sectigo's
  ~15 s spacing applies **across both names**"*; `:253-255` (§4): *"Within one seal each
  distinct endpoint is contacted exactly once, so no spacing rule can be broken by a single
  seal."* The same §4 paragraph (`:255-257`) also repeats H7's premise: *"would need a
  persisted last-contact time, which antseal does not keep"*.
- **The page already gives the operator cross-run pacing.** `:253` *"**It cannot space your
  requests across runs.**"*, `:259-260` *"antseal will not have paced it for you. Space them
  yourself."*, and §8 (`:454-455`) *"Sectigo is pinned too, at the cost of the spacing caveat
  that antseal will not enforce for you between runs."* So the withdrawal's documentation duty
  is met except for the within-seal sentence.

### 1.5 What a rate-limit refusal does today

- **Two production at-most-once POSTs.** The TSA POST (`tsa.rs:459`) and the OTS calendar
  submit (`crates/antseal-anchor/src/ots/submit.rs:348`) are
  `Idempotency::AtMostOnceAfterSend`, matching D90 §6.3's call-site assignment (*"A13 calendar
  submit, A10 TSA POST"*). Every other call site is `SafeToRepeat`.
- **The classifier retries a 429.** `retry.rs:131-135`: `429 | 503 => RetryVerdict::Retry`
  (`:132`), under the comment *"a 429/503 is the server saying it declined to act on it, which
  is as good as never having received it"* (`:128-130`). D90 §6.3's table row (`D90:692`):
  *"status `429`, `503` | no (server declined) | retry | retry"*.
- **The ladder.** `HTTP_MAX_ATTEMPTS = 3` (`crates/antseal-anchor/src/http.rs:120`) and
  `HTTP_BACKOFF = [200 ms, 600 ms]` (`:125`). No `Retry-After` handling exists: `git grep -i
  -e retry-after -e retry_after` over `crates/antseal-anchor/src/` returns 0 lines.
- **So a TSA answering 429 receives three requests inside about 0.8 seconds**, and the endpoint
  then fails with class `http`. A non-granted `PKIStatus` is `not-granted` and is not retried.
- **D90 priced repetition against these very caveats.** D90 §6.3 (`D90:678-679`): *"three
  attempts burns 30 % of SwissSign's daily quota on one failure"*. Its table nevertheless
  retries the one status whose meaning is *"too many requests"*.
- **The pin.** `the_classifier_reproduces_d90_table_6_3` (`retry.rs:158`) lists rows as
  `(error, SafeToRepeat, AtMostOnceAfterSend)`; `:267` is `(status(429), Retry, Retry)` and
  `:268` `(status(503), Retry, Retry)`.

### 1.6 `A139`: the four tests `A31`'s tick rests on

- `A31`'s `🟡` (`TODO.md:619`) stands on two residues: pacing (`A137`), and *"the four tests
  were read and their assertions verified **but not executed** at registration"* (`A139`).
- `A31`'s note names three tests: row 1, `entrust_and_sectigo_are_one_tsa_while_freetsa_and_digicert_are_two`
  (`crates/antseal-core/src/anchor/tsa.rs:970`); row 2, the assertion at
  `crates/antseal-anchor/src/submit/tests.rs:245` (*"1 distinct TSA(s)"*), inside
  `one_verified_tsa_with_total_ots_failure_proceeds_with_a_degradation_note` (`:231`); row 4,
  `collapsing_two_endpoints_to_one_tsa_does_not_change_the_gate_outcome` (`:531`). Its row 3 is
  the page, not a test. It names no different fourth, so the ruling's fourth stands:
  `at_a_threshold_of_one_the_two_counts_cannot_disagree` (`:593`), which asserts
  `MIN_VERIFIED_TSA_TOKENS == 1`, then `verified_tsa_count() == 2` and `distinct_tsas() == 1`
  for an Entrust token plus a Sectigo token.

## 2. RULING

### §2 R1 — `A10`'s minimum-interval clause is withdrawn (`A137`)

The orchestrator strikes the clause at `tasks/A.md:123` with its date and this reason: the spec
asks only that the caveats be recorded and that failures downgrade loudly (`MVP-SPEC.md:109`,
`:189`), and both are met; both caveats are published and were never measured
(`D60-CAPTURE.log:46-49`); the default list carries neither; SwissSign counts zero while
quarantined; and honouring an interval across runs would need either comparing `fetch_date`
(`A32`: recorded, never compared) or a new vault-global record (a vault-format event), plus a
config key `Q31` would freeze. **H7's stated reason, that the state does not exist, was wrong,
and is recorded as wrong** (§1.3).

The dated reason must not say that antseal never re-sends to a refusing TSA: a 503 is still
retried after §2 R5.

Refused, with their costs:
- **Keep the promise**: a config key (a string encoding or a parser extension, frozen at the
  first release), a new vault-global record that `vault export` and `import` must carry, a
  visible wait-or-skip in the seal stage, and an injected clock for a two-seal test — size M,
  for a default list with no caveat, no evidentiary value for SwissSign, and at most turning
  *"Sectigo refused, the seal is degraded"* into *"antseal waited about 15 s and said so"*.
- **Keep it narrowly**, by collapsing known aliases before sending (a static `entrust →
  sectigo` table): brittle, because it rests on one observation from 2026-08-02 while `A31`
  deliberately keys identity on the signer after the fact; a documented warning buys the same
  safety for a configuration the page already advises against.

### §2 R2 — `tsa.rs`'s rustdoc says what the stage guarantees (`A137`)

`crates/antseal-anchor/src/tsa.rs:67-74` is corrected: within one seal the guarantee is **per
URL, not per authority**, and two names of one authority (Sectigo and Entrust, `A31`) are both
sent, concurrently. The dangling *"(U49)"* at `:74` is re-pointed at `A137`, which withdrew the
promise, and at the page section that gives pacing to the operator. Rustdoc only; no code moves.

### §2 R3 — The page says the same (`A137`)

`docs/user/timestamp-authorities.md` §4 (around `:252-256`): the within-seal sentence becomes
per endpoint and states the alias consequence. §3 (around `:146-152`): the alias bullet gains
the same-instant consequence — configuring both names sends two requests to one authority at
once.

### §2 R4 — `A139` rides: `A31`'s tests are executed and recorded

The four tests are run by name and their result lines recorded in `A31`'s row, which retracts
`A31`'s `🟡` once, with both residues discharged:
- `antseal-core`: `entrust_and_sectigo_are_one_tsa_while_freetsa_and_digicert_are_two`
  (`anchor/tsa.rs:970`);
- `antseal-anchor`: `one_verified_tsa_with_total_ots_failure_proceeds_with_a_degradation_note`
  (`submit/tests.rs:231`), `collapsing_two_endpoints_to_one_tsa_does_not_change_the_gate_outcome`
  (`:531`) and `at_a_threshold_of_one_the_two_counts_cannot_disagree` (`:593`).

The ruling allowed `A31`'s own fourth if its note named a different one; it names none (§1.6).

### §2 R5 — A 429 stops an at-most-once POST (`A140`)

In `http/retry.rs`'s classifier, **status 429 under `AtMostOnceAfterSend` is `Stop`**. A 503 is
unchanged, the `SafeToRepeat` column is unchanged, and no `Retry-After` handling is added. The
table test's row flips from `(status(429), Retry, Retry)` to `(status(429), Retry, Stop)` —
the red-first witness — and a new stub-server test asserts that a TSA answering 429 receives
**one** request, not three. D90 §6.3 takes a dated addendum.

Reasons: a 429 is a pacing refusal. A repeat 200 ms later cannot satisfy a ~15-second spacing,
and it may count against a ~10/day quota (whether refused requests count is not established).
The classifier's existing reason — a declined request was never acted on, so repeating it
cannot double-submit — stays true, which is why a 503, an outage rather than a pacing
refusal, keeps its retry.

The rule is per column, so it reaches **both** production at-most-once call sites: the TSA
POST and the OTS calendar submit (§1.5). The calendar half's cost is bounded: a calendar that
answers 429 now gets one request instead of three, and no OTS outcome ever fails a seal (D54
§3, `D54:169`).

### §2 R6 — The orchestrator's acts

Reword `TODO.md:1300`'s risk cell, whose *"A10 spacing config"* names a mitigation that does
not exist, to what does: `A10`'s one-request-per-URL deduplication, `A137`'s withdrawal and
`Q26`'s page. Tick `A137`, `A139` and `A140`; retract `A31`'s `🟡`.

## 3. Fault plants

The implementing lane owes these. Green baselines come first; each plant is judged by its
message, and every restore is followed by a `touch`.

**`A137` (§2 R1–R3) changes no behaviour, so no new test is honest.**
- Green: `cargo test -p antseal-anchor --lib tsa::tests` stays green. The edited block is `//!`
  prose; confirm by reading that it holds no code fence before claiming doc-tests are
  unaffected.
- Green: `scripts/check-copy-style.py` exits 0, read back from a file, after the page edit.
- The withdrawal's premise, *no interval code exists*, is the zero-hit `git grep` of §1.1,
  re-run in the act and quoted into the row.
- The alias sentences rest on `entrust_and_sectigo_count_as_one_tsa_and_the_report_says_so`
  (`tsa/tests.rs:515`) and on `capture_from_tsas`'s concurrency (`tsa.rs:387`), cited by
  symbol.

**`A139` (§2 R4).** The four tests run green by name, and their result lines are quoted
verbatim into `A31`'s row: a run identifier alone is not evidence.

**`A140` (§2 R5).**
- **Red first.** Flip the table row to `(status(429), Retry, Stop)` before touching the
  classifier, and watch `the_classifier_reproduces_d90_table_6_3` go red against today's code,
  by its message. Then change the classifier and watch it go green.
- **Green.** The new stub-server test: a TSA answering 429 receives exactly one request (the
  stub's request count is 1), and the endpoint fails with class `http`.
- **Plant.** Restore `429 | 503 => RetryVerdict::Retry`. Expect red in the table test and in
  the stub test (three requests).
- The table test pins every cell, so an over-broad change — 503 moved too, or the
  `SafeToRepeat` column changed — reddens it as it stands.

Venue: every test above is in-process (`cargo test -p antseal-anchor`, `cargo test -p
antseal-core`); the stub server listens on loopback. No spawned binary is needed.

## 4. What this record does NOT decide

- **`A140` is not deferred.** It is minted by this wave's rulings and decided here: §2 R5 is
  its `Do`. What it leaves open follows.
- **`Retry-After`.** Not parsed today and not added here.
- **Whether a refused request counts against an authority's quota**, and whether Sectigo
  actually refuses inside 15 seconds. Neither was ever approached (§1.2).
- **A persisted pacing mechanism.** Refused under §2 R1; reviving it would be a vault-format
  event plus a config key, argued as such.
- **The page's `:255-257`.** It repeats H7's premise in the page's words (*"which antseal does
  not keep"*). §2 R3's range covers the paragraph; whether the lane aligns that sentence with
  §2 R1's reason (`fetch_date` exists per work under a never-compared contract; refused
  attempts are recorded nowhere) is left to its wording and the orchestrator's check.
- **503 and the `SafeToRepeat` column**, which keep their retries.
- Every build and test duration: the planning lane built nothing.

## 5. Edit list — per write scope, with the lane named before this record was written

### L-ANCHOR (round 1)

- `crates/antseal-anchor/src/tsa.rs` — **the module rustdoc only** (`~:60-80`), per §2 R2.
  Round 2's `L-ERR2` edits `~:194` for D194.
- `docs/user/timestamp-authorities.md` §3 (around `:146-152`) and §4 (around `:252-256`), per
  §2 R3. The lane owns the whole page this round (D192 edits the same two sections).
- `crates/antseal-anchor/src/http/retry.rs` — the classifier and its table test, per §2 R5.
- The stub-server test, wherever the TSA or HTTP tests live (`tsa/tests.rs` or the HTTP
  tests).
- `A139`: the four runs of §2 R4, with their result lines in the lane's report.

### RECORDS-B — the dated addendum on D90 §6.3 (§2 R5)

### Orchestrator — `tasks/A.md`, `TODO.md`, `docs/decisions/README.md`

- `tasks/A.md:123`: `A10`'s clause struck with its date and §2 R1's reason.
- `TODO.md:1300`: the risk cell reworded (§2 R6).
- `A140`'s register row written (`TODO.md`, `tasks/A.md`): the id is minted by this wave's
  rulings and has no row at `23f3093`.
- `A137`, `A139`, `A140` ticked; `A31`'s `🟡` retracted with `A139`'s result lines.
- The index row and the register row.

### Not touched

`docs/config.md` and the config reader, the vault, and `fetch_date`'s contract.

## 6. As built — wave 38, lane L-ANCHOR (recorded in place before this record was first committed)

Every verdict below was read from an exit file.

- **§2 R5 (`A140`).** `classify`'s `Status` arm (`crates/antseal-anchor/src/http/retry.rs:143-151`)
  now matches `429` on the idempotency class: `SafeToRepeat` → `Retry`, `AtMostOnceAfterSend` →
  `Stop`. The `503` arm and the `500..=599` arm are unchanged, and no `Retry-After` handling was
  added. The table test's row reads `(status(429), Retry, Stop)`.
  - New test `tsa::tests::a_tsa_answering_429_receives_exactly_one_request`. It first asserts
    `HttpPolicy::seal().max_attempts == 3`, so that one request cannot pass by default. A loopback
    stub that always answers `429` is then reached through the real `capture_one`; it gets
    exactly one request, and the endpoint fails with class `http`. A control stub that answers
    `503` gets three.
  - The production at-most-once callers measured as exactly two: the TSA POST (`tsa.rs:459`) and
    the calendar submit (`ots/submit.rs:348`).
- **§2 R2 (`A137`).** The module rustdoc `tsa.rs:67-74` was rewritten in the same eight lines, so
  the file stays 534 lines and no `tsa.rs:<n>` citation moves. The block holds no code fence.
  `(U49)` now names `A137` and the page's §4. Re-run in the act:
  - `command grep -rn 'min_interval\|minimum_interval\|MIN_INTERVAL\|last_contact' crates/
    scripts/` returned 0 lines;
  - `\bU49\b` over `crates/`, `scripts/`, `docs/user/` and `docs/anchors/` returned 0 lines.
- **§2 R3 (`A137`).** The page's §3 alias bullet (now `:154-158`) and §4 pacing paragraph (now
  `:273-285`) were corrected.
  - §4 settled this record's §4 open item. H7's premise (*"which antseal does not keep"*) became
    the measured fact: the fetch date is recorded, as provenance nothing compares.
  - §4's heading lost *"across runs"*, because the within-seal half was false per authority.
  - The evidence table gained a row for the attempt policy.
- **§2 R4 (`A139`).** The four tests ran by exact name before `Q89` touched `submit.rs`, both runs
  exit 0:
  - `antseal-core`: *"test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 1188 filtered
    out"*;
  - `antseal-anchor`: *"test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 207 filtered
    out"*.
- **§3's red-first order was not kept.** The lane's two requests for the exclusive tree lock
  (540 s and 900 s) both timed out before its script started: a long shared hold by another lane
  starved them (`docs/instrument-ledger.md`).
  - The fix and its tests therefore landed together.
  - The red-first observation ran as plant PA in a copy of the tree, with a private target
    directory; the tree itself was never written. An unplanted control in that copy ran first
    (6 passed).
  - PA restored today's `429 | 503 => RetryVerdict::Retry` arm and kept the flipped row and the
    stub test. Both went red by message: *"AtMostOnceAfterSend: Status { endpoint:
    \"http://e.example\", status: 429, body: [] } / left: Retry / right: Stop"* and *"a TSA that
    answered 429 was asked again / left: 3 / right: 1"*. Today's code was seen sending three
    requests to a TSA that said `429`.
- **At the lane's close.** `cargo test -p antseal-anchor` exited 0 (lib *"213 passed; 0 failed;
  1 ignored"*). `cargo clippy -p antseal-anchor --all-targets -- -D warnings` exited 0, and so did
  `scripts/check-copy-style.py`.
- **The orchestrator's acts (§2 R1, R6).** `tasks/A.md:123`'s clause is struck with its date and §2 R1's reason, and the reason does not claim that a refusing TSA is never asked again. `TODO.md`'s risk cell names what exists. `A137`, `A139` and `A140` are ticked. `A31`'s `🟡` is retracted, with `A139`'s result lines quoted on its row.

## Closing — this record is not consent

It changes code, tests, rustdoc and a user page in the tree. Nothing in it authorises a push,
a dispatch, a deploy or a request to any real TSA or calendar; every test it adds talks to a
stub on loopback.
