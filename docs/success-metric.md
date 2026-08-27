# The ≥10-external-users success metric — plan and instrument

- `n_evidenced` = **0**
- `n_claimed` = **0**
- `read_on` = **not yet set** — R8 fixes it at release + 90 days, written here as a calendar date on release day

Those are the first three lines of this file because `D73` §4 R1 puts them
there, and they are the only place either number is written. No release note,
no README and no post may quote a number this file does not carry.

**What this file is.** The plan for the `MVP-SPEC.md` line 157 success metric,
and the instrument that records it. It is **single-writer** — the maintainer —
and committed, so that every reading of the number is in version control with
the reading before it. It was created by task `Q35` before the release, with
every number at zero, because `D73` §7 item 7 requires the instrument to exist
before anything can be written into it.

**What this file is not.** It is not the execution. `D163` §2 R6/R7 split the
original row: `Q35` writes this plan and this instrument, and `Q264` runs the
cadence against it after the release ships. Every table below is empty on
purpose, and staying empty is a state `Q264` changes, not a defect of `Q35`.

---

## 1. What counts as one completion

The metric, quoted exactly from `MVP-SPEC.md` line 157:

> **MVP success metric: ≥10 external users complete seal → reveal → third-party page verification.**

`Q35`'s own `Do` expands it:

> completion = an external user seals their own work, reveals a subset, and an
> independent third party verifies the bundle on the hosted page.

**A completion is two people, not one person doing three things** (`D73` §1,
§4 R4). The sealer does legs 1 and 2 — seals their own work, then reveals a
subset of it from that same seal, from that same vault. Leg 3 is **someone
else**: a person the sealer names as not being themselves and as not having
received the bundle from this project. A sealer who opens their own bundle on
the hosted page has **not** completed the chain, and their row's leg-3 cell
reads `NOT CLAIMED`.

**One row per sealer**, counted once, however many third parties verified and
however many works were sealed. The metric counts people who completed a chain,
not chains.

**"External" is four tests, in order, all required** (`D73` §4 R3):

| # | test | who decides |
|---|---|---|
| 1 | not the maintainer, not an agent, not CI — a human holding a vault whose passphrase the maintainer has never held | maintainer declaration |
| 2 | **their own work** — content the participant chose, not project-supplied material, not a golden vector, not `testdata/`. Choosing content they are comfortable handing over is still choosing | maintainer declaration |
| 3 | **their own decision** — anyone paid, employed or directed by this project to complete the chain is recorded in `mode` = `directed` and is **not** in `n_evidenced` | maintainer declaration |
| 4 | the bundle's sealer public keys do not appear on the exclusion list in the header block below | **reader-checkable**, and falsifier X5 is its check |

Tests 1–3 are maintainer declarations and this file labels them as such. Test 4
is the only one a reader can re-run.

---

## 2. Recruitment

Named channels, what each one is blocked on today, and what every message must
say. This section is the plan; sending is `Q264`'s.

| # | channel | what it is | blocked on |
|---|---|---|---|
| C1 | direct outreach, one message at a time, to people already known to the maintainer who match the MVP-user profile at `MVP-SPEC.md` line 26 — technical-ish creators, researchers, inventors, and small legal or IP practices comfortable with a CLI | the primary channel, because it is the only one that works while the repository is private and because it is the only one where the disclosure warning below can be given in a conversation rather than in a footnote | nothing |
| C2 | the Autonomi and Saorsa Labs community channels the project already follows for upstream tracking | a short post describing what the tool does and asking for people willing to run the chain end to end | nothing technical; the message is written once and reused |
| C3 | a Show-HN-style post on a public link-aggregator, submitted by the maintainer | the widest-reach channel and the least targeted one | the repository being public, which is `Q65` |
| C4 | a GitHub issue or discussion thread as an intake point | a place for a participant to reach the project without email | `Q65`, the same blocker `D73` §3.3 measured |

**C3 and C4 cannot run while the repository is private.** That is measured, not
assumed: `D73` §3.3 recorded the same blocker and routed around it. The plan
therefore does **not** depend on either — C1 and C2 alone are the route to ten,
and C3/C4 are widening, not the mechanism.

**What every outreach message must contain**, in the message itself and never
as a footnote:

1. **"Reveal without `--include-receipt`."** `D73` §4 R6.1 makes this an
   element of the recruitment text. The receipt links a seal to the paying
   wallet and that wallet to an identity; asking a participant to include it
   would be asking them to hand this project a linkable identifier in exchange
   for helping us reach a number. If a receipt-bearing bundle arrives anyway,
   the row is accepted, the receipt group is not read, not recorded and never
   quoted, and the bundle is destroyed as soon as the checks below have run.
2. **What sending a bundle discloses.** A metric submission is an
   irreversible disclosure to the maintainer of exactly the units the bundle
   reveals — the same fact the CLI's own reveal prompt states. This project
   does not get to be quieter about that than its own program is.
3. **A pointer to the limits, not a restatement of them.** The message links
   [the README](../README.md) and says nothing about what a seal proves that
   the README does not already say. It must never call this tool a legal
   notary, and it must not claim that a seal establishes who created
   something — a seal is evidence of possession at a time.
4. **That participation is voluntary and unpaid**, so that test 3 above stays
   true of everyone recruited through it.

---

## 3. The guided onboarding path

The participant's on-ramp is the documentation `Q22` already wrote. This plan
**links** it and adds nothing that would have to be kept in step with it.

| step | page |
|---|---|
| 1. What the tool is, who it is for, and what a seal does and does not prove | [README](../README.md) — the "Who this is for" and "What a proof bundle shows its recipient" sections |
| 2. Getting a binary and checking it before running it | [Checking a download](signing/verifying-a-release.md) |
| 3. Putting funds where the seal will draw them from | [Funding your wallet](user/funding-your-wallet.md) |
| 4. What the payment links together in public before they spend anything | [Wallet hygiene](user/wallet-hygiene.md) |
| 5. Running the chain: init, seal, reveal | [README](../README.md) — the "Quickstart" section |
| 6. What is unrecoverable if the vault or its passphrase is lost | [Vault loss](user/vault-loss.md) |
| 7. What someone else holding the vault and its passphrase can read | [Vault theft](user/vault-theft.md) |
| 8. Which time anchors a seal carries | [Timestamp authorities](user/timestamp-authorities.md) |
| 9. Handing the bundle to the third party, who installs nothing and opens `https://antseal.org/` | [README](../README.md) — the "What a proof bundle shows its recipient" section |

**Nothing on this path is written for the metric.** A participant follows the
same pages any user follows, which is the point: the number is supposed to
measure whether the shipped documentation gets a stranger through the chain. A
special onboarding path written for participants would measure the path.

**The facilitated variant** is the same nine steps with the maintainer present.
It is a usability instrument, it is always marked `facilitated` in the `mode`
column, and it never enters `n_claimed` — see §5.

---

## 4. Measurement, with no telemetry anywhere

**The product ships no telemetry and this plan introduces none.** That is not a
preference; it follows from what the product is. The verifier page is
`antseal-core` compiled to WASM with no network layer and no backend
(`MVP-SPEC.md` lines 17 and 38), it is served as a static artifact, and a
static host runs nothing. There is no place a beacon could report to and this
plan does not create one.

**Nothing in the list below may ever be built under this metric** (`D73` §4
R10):

1. No beacon, pixel, counter or endpoint in the verifier page.
2. No backend behind the hosted page, and no third-party analytics on it.
3. No table mapping wallet addresses to participants.
4. No watching the chain to count users.
5. No download count quoted as a user count.
6. No screenshot of a verdict, and no pasted verdict string, treated as
   evidence — either one is a picture of a claim, and re-typing it is free.
7. No request for a receipt-bearing bundle.

**So what is the evidence?** Three instruments, and only one of them is
evidence:

| instrument | what it establishes | where it lands |
|---|---|---|
| **the submitted `.sealproof` bundle** | legs 1 and 2, **cryptographically**, offline, by the maintainer running the released signature-checked binary against it | the `legs_1_2` cell — the only cell in this file permitted to say `VERIFIED` |
| **self-report** | leg 3, as an assertion by the sealer that a named independent person opened the bundle on the hosted page | the `leg_3` cell, which may never say "verified" |
| **facilitated sessions** | that the chain *can* be completed, with the maintainer as a witness to leg 3 | the `mode` cell, `facilitated`; the `leg_3` cell may say `WITNESSED` |

**Leg 3 is unmeasurable, by design and not by accident.** The one actor the
metric hinges on is the counterparty, and `MVP-SPEC.md` line 26 deliberately
engineered that person to need no install, no account and no relationship with
this project. That is the product working. The honest response is to report leg
3 as asserted and never to dress an assertion up as a measurement — which is
why the number is two numbers.

**Transport is free; evidence is not.** A participant completes a row by
sending the bundle `reveal` already wrote for them — the same file they gave
their third party. How it arrives is unruled: email, an attachment, a link, a
chat message, a drive handed over at a meetup. A change of channel never
reopens this plan, because the channel was never the evidence.

**Facilitated sessions never inflate the number.** The headline is
`n_claimed (unaided + guided)` — the figure `MVP-SPEC.md` line 157 is read
against — with `n_total (incl. facilitated, directed)` printed beside it. No cap
is set on facilitated sessions, because any cap would be arbitrary; the
discipline is that they are counted separately and can never be quietly folded
in.

---

## 5. Schedule of the first outreach batch

`Q35`'s `Accept` requires the first batch to be **scheduled**, and `D163` §2 R7
states the rest of that sentence: **scheduling is not shipping.** Sending the
batch is `Q264`'s act, after the release. What follows is the schedule.

**The anchor.** `D0` is the day the release is published by `Q34`. No calendar
date for `D0` exists to fix today — the release has not happened — so the
schedule is written as fixed offsets from it. **Nothing further is decided
after `D0` is known**: every row below converts to a calendar date by
arithmetic, and the maintainer writes those dates into the `date` column on
release day, in the same act that fills the header block.

| batch | offset | date | channel | contents |
|---|---|---|---|---|
| **B1** | `D0` | — | C1 (direct outreach) | the first batch: individually addressed messages to people matching the MVP-user profile, carrying all four required elements from §2 |
| B2 | `D0 + 7` | — | C2 (community channels) | the reusable post, drafted before `D0` and held |
| B3 | `D0 + 21` | — | C1 | a second direct batch, sized by what the funnel table in §9 shows after B1 |
| B4 | `D0 + 45` | — | C3/C4 if `Q65` has landed by then, otherwise C1 again | widening, or another direct batch |
| **read** | `D0 + 90` | — | — | `read_on`: the numbers are read once, recorded whatever they are, and the first reading is never revised |

**Preparation that happens before `D0`, so that B1 can go out on the day**: the
C1 recipient list is assembled; the reusable C2 post is drafted; the metric
salt is generated (§7); and the exclusion list in the header block is seeded
from every vault used in the `Q34` gate and the mainnet smoke seal.

**The read date is the clause that makes this metric capable of failing.** A
success metric with no date on which it is read can never be *not met* — there
is always more counting to do, and "we are at seven, still going" is a state
that never resolves. `D0 + 90` is written into the header block as a concrete
calendar date on release day, the numbers are read on it, and whatever they say
is recorded permanently. Later readings may be appended below the first, dated.
They never overwrite it.

---

## 6. Header block

Every field is `D73` §4 R7's. Every one is empty or zero today, which is what
`D73` §7 item 7 asks of an instrument created before its first use.

| field | value today | filled by |
|---|---|---|
| `n_evidenced` | **0** | `Q264`, per row |
| `n_claimed` | **0** | `Q264`, per row |
| `n_total` | **0** | `Q264` — `n_claimed` plus `facilitated` and `directed` rows |
| `read_on` | **not set** | the maintainer, on release day, as `D0 + 90` in calendar form |
| `release_tag` | **not set** | the maintainer, on release day |
| `release_date` | **not set** | the maintainer, on release day — falsifier X4 compares every headline anchor time against it |
| `exclusion_list` | **empty** | seeded before `D0` with the sealer public keys of every vault used in the `Q34` gate and in the mainnet smoke seal; falsifier X5 reads it |
| `x7_planted_fault` | **NOT YET RUN** | see §8 — until this records a red, the count may not be declared met |
| `retention` | see below | fixed by this file |

**`retention` — the statement this file is required to make about itself.**
Submitted bundles are held until `read_on + 30 days` and are then destroyed.
**After that date, the correspondence between the rows in this file and real
submissions is no longer auditable by anyone**, including by the maintainer.
The two fingerprint columns are opaque by construction — the salt is secret —
so a reader can check that ten rows are ten *distinct* things, and cannot check
that they are ten *real* things. That is a deliberate trade: making the rows
re-derivable would let anyone holding a participant's bundle test whether that
participant appears in this table. Participant privacy wins, and the residue is
named here rather than hidden.

**Nothing identifying is committed to this file** — no bundle, no public key,
no work id, no wallet address, and no personal name unless the participant asks
to be named.

---

## 7. The rows

`D73` §4 R7's shape, exactly. **The table is empty. That is the correct state
for a file created before the release.**

| `id` | `submitted` | `vault_fp` | `work_fp` | `legs_1_2` | `leg_3` | `mode` | `struck` |
|---|---|---|---|---|---|---|---|
| | | | | | | | |

**Column legend**, so that a later writer cannot drift the vocabulary:

| column | permitted values |
|---|---|
| `id` | `01`, `02`, … — stable, never reused, even after a row is struck |
| `submitted` | the date the bundle arrived |
| `vault_fp` | 16 hex characters, opaque — falsifier X2's distinctness column |
| `work_fp` | 16 hex characters, opaque — falsifier X3's distinctness column |
| `legs_1_2` | `VERIFIED <date>, antseal <version>, offline` — the **only** cell in this file permitted to say `VERIFIED` — or `FAILED <X1>` |
| `leg_3` | `ASSERTED — NOT VERIFIED`, or `WITNESSED (facilitated, <date>)`, or `NOT CLAIMED`. This cell may **never** say "verified" |
| `mode` | `unaided`, `guided`, `facilitated`, or `directed` |
| `struck` | `—`, or a falsifier id and the date it fired |

**A row enters `n_claimed` only if it is already in `n_evidenced`.**
`n_claimed ≤ n_evidenced` always: an assertion about leg 3 from someone whose
seal could not be verified is not a completion of anything.

### The two fingerprints

`vault_fp` and `work_fp` are the only per-row identifiers this file carries.
Both are computed with a **single 32-byte random salt generated once for this
metric, held by the maintainer, and never committed** — not to this repository,
not to a log, not to a fixture. The label is `antseal-metric-fp-v1`. It is
**not** a wire-format domain tag and is deliberately absent from the frozen
domain-tag registry: this is project bookkeeping, not a format, and registering
it would be a format event for no reason.

`work_fp` is `SHA-256(salt ‖ work_id)`, truncated to 16 hex characters.

`vault_fp` is derived from the sealer public keys carried in the bundle's
manifest, with the same salt. **A divergence is recorded here rather than left
implicit**: `D73` §4 R7 writes `vault_fp = SHA-256(salt ‖ pubkeys-bytes)` and
never defines `pubkeys-bytes`, and it gives both fingerprints the **same salt**
— untagged, that would be one keyed function over two different value spaces.
The maintainer-side tool owed by `U76` therefore pins the encoding and prepends
a domain tag of its own. That is a dated-addendum candidate for `D73` and not a
silent change of the ruling; nothing is invalidated by it, because this file
has never existed before now and no `vault_fp` has ever been published.

A fingerprint collision **deflates** the count by merging two rows, which is
the direction a falsifier is supposed to be able to move a number. At sixteen
hex characters and ten rows the chance of an accidental one is about
`2.7e-18`.

---

## 8. How a row can be wrong

The number's job is to be capable of being wrong. Every row must be capable of
being struck, and each rule below names the field it reads and the observation
that fires it (`D73` §4 R5).

| id | reads | fires when | consequence |
|---|---|---|---|
| **X1** | the bundle, through `antseal verify` | a non-zero verdict class | legs 1 and 2 are false — the row is struck and counted nowhere |
| **X2** | the sealer public keys in the manifest | two rows claimed as distinct participants carry the **same** sealer public key | the two rows are one vault; they collapse to one row |
| **X3** | the work id in the report | a work id already present in the table | the same work resubmitted — no new row |
| **X4** | the report's headline anchor time | a headline earlier than `release_date` in the header block | a pre-release or maintainer seal, not a post-release external completion |
| **X5** | the sealer public keys against the exclusion list | a match | not external |
| **X6** | the calendar | `read_on` arrives with `n_claimed < 10` | **the metric is not met**, and that is recorded here permanently |
| **X7** | this instrument itself | X2 has never fired | the count may not be declared met — see below |

**X2 is the strongest of these, and its logical force is exactly one
direction.** Distinct sealer keys are an **upper** bound on distinct
participants, never a lower one: *k* distinct keys means *at most k* people,
because one person can hold many vaults. So X2 can only ever deflate an
inflated count and can never confirm a real one — which is the property a
falsifier should have, and precisely what "ten people said they did it" lacks.

**X7 is the planted-fault rule, and it is not optional.** Before the count is
declared met, X2 must have been run against a **deliberately duplicated
submission** — two bundles produced from a single vault, submitted as if from
two participants — and the check must be recorded here as having gone **red**.
Until that has happened, X2 has never been shown capable of firing, and a check
that has never fired is exactly the class this project keeps an instrument
ledger to catch. The planted run and its red are recorded in the
`x7_planted_fault` header field, dated.

**X7 cannot run today and the reason is recorded**: no shipped command prints
the sealer public keys, so X2 has no input. The maintainer-side route is owed
by task `U76` and is gated behind a test-only build so that it never reaches a
release binary or a user's `PATH`. It emits a fingerprint, never key bytes.
`U76` blocks the **first submission** and blocks **declaring the count met**;
it does not block this file existing, which is why this file exists.

---

## 9. If the count falls short

Recorded in advance, so that "the metric is a learning instrument" cannot
become a way of never being wrong.

On `read_on`, if `n_claimed < 10`:

1. **The shortfall is recorded here permanently, as a number.** X6 fires and
   the row stays.
2. **The funnel stage where it stopped is named**, from the table below. The
   bucket that ate the attrition **is** the finding, and it is a different
   finding in each case.
3. **The MVP is not retroactively declared a failure**, because
   `MVP-SPEC.md` line 157 names a success metric and not a ship gate, and the
   ship already happened.
4. **And the number is not restated as a success.** Release notes, the README
   and any public post may quote only what this file carries, and this file
   carries the shortfall.

| bucket | count | what a large number here means |
|---|---|---|
| not reached | **0** | a recruitment failure — the channels in §2 did not find the people |
| reached, did not install | **0** | a packaging failure — the download or the signature check turned people away |
| installed, did not seal | **0** | a usability failure — the funding step, the CLI or the docs stopped them |
| sealed, no third party verified | **0** | a **product-thesis** failure — people will seal but will not ask anyone to check. This is the one worth having a metric for |

**Release download counts are a funnel number and never a user count.** The
release host publishes them without any telemetry this project builds, so they
will be available and they will be tempting. A download is not a seal, a seal
is not a reveal, and none of them is leg 3. If quoted at all, a download count
belongs in the "not reached" row above and never beside `n_claimed`.

---

## 10. Provenance

| what | where |
|---|---|
| the metric | `MVP-SPEC.md` line 157 |
| the MVP-user profile and the zero-install counterparty | `MVP-SPEC.md` line 26 |
| no backend, no network layer in the page | `MVP-SPEC.md` lines 17 and 38 |
| the measurement method, the two numbers, the row shape, the falsifiers | [`D73`](decisions/D73-external-completions-without-telemetry.md) |
| the split that gave this file to `Q35` and the cadence to `Q264` | [`D163`](decisions/D163-clause-wise-after-and-the-missing-split.md) §2 R6/R7 |
| the participant's documentation | [the README](../README.md) and the pages under `docs/user/` linked from §3 |

**This file is the plan and the instrument. The count is not a release gate**
— the release ships whether or not ten people later complete a chain — and the
spec metric is not softened by saying so.
