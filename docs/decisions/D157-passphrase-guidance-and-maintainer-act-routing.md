# D157 — Both rows survive, and the 2026-08-22 act made one of them *harder*: the referent that appeared under Q259's pointer prescribes the opposite discipline for a secret that now guards three copies of the key, and Q258's deliverable is not a table — it is a row body with no time-varying sentence in it

- **Status: RESOLVED. The lean is OVERTURNED in both halves, and in the framing
  under each.** The lean was *"Q259 is now trivial — just delete the four
  analogies and point at `docs/user/vault-theft.md`; and Q258 is a straight
  re-brief that swaps `overdue` for `done` in a four-row table."*
  - **Pointing at the referent is REFUSED, and not on taste.**
    `docs/user/vault-theft.md:123-124` prescribes *"Written down and stored
    somewhere physically safe. A passphrase you forget is the* other *failure on
    `vault-loss.md`, and it is equally final."* For the **signing** passphrase
    that sentence is false — `key-custody.md:77-81` makes its loss the cheap
    failure — and it is false **in the direction that costs the most**: it pushes
    the maintainer toward *more copies of the passphrase*, which is the one
    replication that converts a wrapped key file into a key. The pointer is not
    merely a live mis-instruction; it is a live mis-instruction with a **known
    sign**. §1.2.
  - **The 2026-08-22 act did not relieve Q259. It reweighted it upward.** D71's
    2026-08-19 addendum (`:1341-1344`) rules that what bounds the uid-1000
    exposure is *"§2 R7.1's `-W` ban"* — i.e. the scrypt wrap, i.e. the
    passphrase. The two offline backups took the number of `Sc`-wrapped copies of
    `minisign.key` that the passphrase is the sole defence of from **one to
    three**, two of them in places the maintainer does not physically hold
    moment to moment. Q259 governs the strength of the only control over all
    three. §1.2, §1.6.
  - **The four sites are TWO defects, not one, and only one of them has a
    referent at all.** `maintainer-key-procedure.md:53-54` and
    `key-custody.md:55-56` say *generated and stored the way*; those now resolve
    to real, wrongly-signed guidance. `maintainer-key-procedure.md:76-77` and
    `key-custody.md:70-71` say *recorded where / by whatever means the vault
    passphrase is recorded* — and that referent **still does not exist and cannot
    be written**, because antseal deliberately never records the user's vault
    passphrase anywhere (`docs/user/vault-loss.md:163`, *"antseal does not hold
    it"*). Q259's `Do` says *"replace **both** analogies"* while its `Problem`
    names **four** sites; a lane can satisfy the letter by editing two. §1.3.
  - **Accept row 1's grep returns EIGHT, not five.** Measured: `key-custody.md:55`,
    `:70`; `maintainer-key-procedure.md:53`, `:76`, `:283`; **and
    `D71-…:560`, `:581`, `D153-…:745`**. The brief named the fifth and not the
    last three, and the last three are the dangerous ones: they are inside
    decision records, the one subtree this project never rewrites in place. §1.4.
  - **§7 — the single place status is allowed to live — carries a claim measured
    FALSE, and it was written on 2026-08-22.**
    `maintainer-key-procedure.md:283-284`: *"a referent that exists nowhere in
    this project"*. It exists, at `docs/user/vault-theft.md:117-126`, linked from
    `README.md:84-85`, and has since before the key was generated. §1.2.
  - **Q258's class vocabulary re-introduces the exact flattening D153 §2 R5 was
    written to remove.** `overdue / triggered / release-timed` fuses two
    independent axes — *what is stopping it* and *when to take it* — and the
    fusion is why §2 has no word. Worse, one word does opposite operational work
    on two rows: for §3, *release-timed* means **do not take it now** (D71 §A R5
    clause 4, *"not now and not after"*); read across to §2 it would mean **its
    deadline is the release**. The replacement is not a fourth word. It is two
    fields. §1.5.
  - **`ARMED` is wrong in DIRECTION, and the brief's own gloss shows how.** §2 is
    not waiting on an event. Its only predecessor is §1, which is done; it is a
    registrar action takeable today. What D71 §A R4 dates to first publication is
    the moment the pin's *value* begins, and §5 — the publication — is forbidden
    until §2 exists (`maintainer-key-procedure.md:188-193`). Calling §2 *armed*
    turns *"the one that should not be deferred"* into something to wait for.
    `maintainer-key-procedure.md:9` compounds it by writing the schedule as
    `§1 → §3 → §2`, which reads as a gate and is not one. §1.6.
  - **§5 is not a maintainer act and must not enter the table as one.**
    `maintainer-key-procedure.md:3-5` names exactly **three** external acts — the
    machine, the registrar, the calendar. §5 is three repo edits, performable by a
    lane once §2 and §3 exist, and it sits inside a page titled *"the acts only
    the maintainer can perform"*. It enters the table as the **consumer**. §1.7.
  - **The stale-site census is not three sites needing addenda. Two of the three
    the brief named are fenced `replace with exactly this` blocks and must NOT be
    touched** — `D153-…:496-506` (R4) and `D153-…:517-536` (R5). Editing a
    prescription block rewrites what the record *ruled*, not what it observed.
    And R5's block is **already superseded**: the 2026-08-22 act replaced the §7
    text R5 mandates, so a future lane checking the page against R5's block finds
    a mismatch and could "restore" the false text. Nothing records that. §1.8.
- **The unlisted arm this record takes, and it decides Q258's artifact: the
  tracker's two surfaces ALREADY disagree about Q258, and the gate is green.**
  The 2026-08-22 act rewrote `TODO.md`'s Q258 row to say §1a step 1 *"is **DONE
  2026-08-22**"* and left `tasks/Q.md`'s Q258 entry saying *"Name §1a step 1's
  two offline backups as **the one overdue act**"*. `check-traceability.py` ran
  flagless in this lane: **`REAL_EXIT=0`, eight of eight ok**, including
  `[task-entries] ok — 691 rows … against 691 entries`. That check is an
  **existence** check; nothing in the corpus compares a row's body to its
  entry's. So the answer to *"what artifact"* is settled by measurement rather
  than preference: **any act status duplicated across two tracker surfaces is
  already known to diverge silently.** §1.9.
- **Date: 2026-08-22**
- **Owning task: Q259**, with Q258 ruled in the same act because the two rows are
  recorded `with` each other and the 2026-08-22 act falsified a premise in each.
  Homing on Q258 would be wrong: every prose edit this record specifies lands in
  `docs/signing/`, which is Q259's write scope, and Q258's own deliverable
  shrinks to a pointer.
- **What it blocks:** nothing by row id — both rows are predecessors of nothing
  (`tasks/Q.md` Q258 `Deps`, Q259 `Deps`). What Q259 releases is
  **`maintainer-key-procedure.md` §1a step 2**, deferred on purpose by the
  2026-08-22 act (`maintainer-key-procedure.md:286`) and by `key-custody.md`
  §10's second row. What Q258 releases is nothing mechanical; its value is that
  the next readiness survey sees four acts and one authoritative status section.
- **Related: D153 §2 R1** (the order, and *"alongside §2"* removed), **§2 R2**
  (status in exactly one place — scoped to `docs/signing/` and `README.md`, and
  extended here by analogy rather than by fiat), **§2 R4** (the backups gate §3
  — **discharged 2026-08-22**), **§2 R5** (the §7 text the maintainer has since
  replaced — superseded, see R7), **§2 R6** (`key-custody.md` §11, the amendment
  venue), **§2 R9 item 3** (the mint that produced Q258 and named *three* acts),
  **§4.5** (the mint that produced Q259); **D71 §A R4** (the pin's clock and
  *"the one that should not be deferred"*), **§A R5 clauses 3–4**, **§2 R7.1**
  (the `-W` ban whose threat model is the passphrase), **§2 R11** (the four
  prohibitions the new copy obeys), and D71's **2026-08-19 addendum** (amended
  here by R6); **D150 §4.2** (asked for Q258 a wave before it existed);
  **D154 §2 R7** (timing words are not `after` edges — this record states one
  `with` and one `before` and no `after`); **D155** (the shape); **R96** (the
  page-footer write target, `with Q258`); **Q30** (whose Notes both rows drain),
  **Q65**, **Q31**, **Q254**.

---

## 1. What was measured

Every figure below was measured in this lane against the working tree at
`HEAD = 5c8d1ca` plus four uncommitted files. Where a row, a record or the brief
disagrees with the tree, the tree is quoted. Command statuses were written to a
file and read back.

### 1.1 The 2026-08-22 act, and the exact set of surfaces it touched

`git status --short` — four modified files: `TODO.md`, `tasks/Q.md`,
`docs/signing/key-custody.md`, `docs/signing/maintainer-key-procedure.md`.

`git diff --stat`: `TODO.md` **2 insertions / 2 deletions**; `tasks/Q.md`
**1 insertion / 1 deletion**. Read out by hunk, the act touched exactly:

| surface | what changed |
|---|---|
| `docs/signing/key-custody.md` §10 | one **appended** row, `2026-08-22 \| backup` (`:209`) |
| `docs/signing/maintainer-key-procedure.md` §7 | first bullet replaced; two new bullets (`:270-289`) |
| `TODO.md` Q30 row | Notes updated |
| `TODO.md` Q258 row (`:870`) | rewritten: *"was **overdue and blocking** and is **DONE 2026-08-22**"*, a fourth act added, the single-copy clause struck through |
| `tasks/Q.md` Q30 Notes (`:533`) | *"§4 no longer forbids signing and the key is no longer single-copy"* |

**Not touched, and carrying the falsified claim:** `tasks/Q.md` Q258 (`:3289-3303`),
`tasks/Q.md` Q259 (`:3305-3315`), `maintainer-key-procedure.md:87`,
`D71-…:1345-1346`, `D153-…:65`.

**So the brief's *"Neither row's `tasks/Q.md` entry has been updated"* is
correct, and its implied *"`tasks/Q.md` is untouched"* is not** — Q30's Notes
were updated in the same act. The act's real shape is: **four surfaces updated,
five left stale, and the split runs along what its author happened to have open.**

### 1.2 Q259's central premise is FALSE, and the referent is signed the wrong way

Q259 `Problem` (`tasks/Q.md:3310`): *"**Measured 2026-08-19, that guidance does
not exist**: no passphrase-storage procedure is written in `docs/`, `README.md`
or `MVP-SPEC.md`."*

Measured today at `docs/user/vault-theft.md:114-126`, under the heading *"What to
aim for instead"*:

- `:117-118` — *"**A long passphrase, generated rather than invented.** Five or
  six random words from a large list, or 20+ random characters from a password
  manager."*
- `:121-122` — *"**Unique to this vault.** Reuse means someone else's breach
  becomes your permanent disclosure, years later."*
- `:123-126` — *"**Written down and stored somewhere physically safe.** A
  passphrase you forget is the* other *failure on `vault-loss.md`, and it is
  equally final. Store the written copy apart from any export file."*

That is generation **and** storage guidance, and it is linked from
`README.md:84-85` (*"[Vault theft](docs/user/vault-theft.md) — what someone else
holding your vault and passphrase can read"*). The premise is false.

**The three bullets do not transfer alike, and the failure is signed.**

| bullet | for the signing passphrase | verdict |
|---|---|---|
| generated rather than invented | true, and load-bearing (see below) | **transfers** |
| unique to this vault | true; the signing key's own reuse rule is `key-custody.md` §3, about the **key**, not the passphrase | transfers weakly |
| written down… **equally final** | **false** — `key-custody.md:77-81`: *"Every previously published signature remains valid and checkable. A new keypair is generated and §6's rotation runs"* | **inverts** |

The inverted bullet is not a harmless surplus. A maintainer who reads *"equally
final"* about a secret whose loss is in fact cheap will do the rational thing for
finality: **make more copies of the passphrase.** And copies of the passphrase are
precisely what must not proliferate, because:

- D71's 2026-08-19 addendum (`:1341-1344`): *"**What bounds the exposure is §2
  R7.1's `-W` ban** — the key is `Sc`-wrapped, so possession of the file is not
  possession of the key."*
- `key-custody.md:65-71` §4 **requires** two offline backups of that file, and the
  2026-08-22 row records them made. So the number of `Sc`-wrapped copies whose
  sole defence is this passphrase went from **one** to **three**, two of them
  off-site.

**Therefore Q259 did not get easier on 2026-08-22; it got heavier.** The act that
discharged Q258's blocking item multiplied the population that Q259's subject
protects.

**And §7 itself is now wrong about this.** `maintainer-key-procedure.md:283-284`,
written 2026-08-22: *"a referent that exists nowhere in this project"*. Measured
false above. This is a status-adjacent claim in the one section D153 §2 R2 makes
authoritative, falsified on the day it was written, by a page three years' worth
of readers reach from the README's front matter.

### 1.3 The four sites are two distinct defects, and one referent is unwritable

Verbatim, with line numbers:

| # | site | text |
|---|---|---|
| A | `maintainer-key-procedure.md:53-54` | *"Use a strong, unique passphrase, generated and stored the way the antseal vault passphrase is. **It is not the vault passphrase.**"* |
| B | `maintainer-key-procedure.md:76-77` | *"2. Record the passphrase where the vault passphrase is recorded, **not** with the backups."* |
| C | `key-custody.md:55-56` | *"The passphrase is generated and stored the way the vault passphrase is, and it is **not** the vault passphrase."* |
| D | `key-custody.md:70-71` | *"- The **passphrase** recorded by whatever means the vault passphrase is recorded by, and not stored with either backup."* |

**A and C** point at *how it is generated and stored* — that referent now exists
(§1.2) and is signed the wrong way.

**B and D** point at *where / by what means it is recorded* — and **that referent
does not exist, cannot exist, and it is a deliberate product property that it
does not.** `docs/user/vault-loss.md:163`: *"The passphrase is half the backup,
and antseal does not hold it"*; `:169-172`: *"Nothing in antseal can help here:
there is no recovery question, no escrow, no key-splitting scheme in v1, and no
`change-passphrase` command."* There is no place the vault passphrase *is*
recorded; there is only advice that the user record it. Writing the referent
would mean inventing a maintainer passphrase store, which is the arm §3.2 refuses.

**B and D also each carry a clause that is correct and load-bearing** — *"not with
the backups"* / *"not stored with either backup"* — and the maintainer honoured
it (`key-custody.md:209`: *"The passphrase is **not** stored with either
backup"*). Any replacement must keep it.

**Q259's `Do` says *"replace **both** analogies"*** (`tasks/Q.md:3311`) while its
`Problem` names four sites. The generous reading is *both distinct analogies*,
which is exactly the A/C ÷ B/D split above — but a lane can satisfy the words by
editing two files and leaving two. R2 names all four.

### 1.4 Accept row 1's measurement returns eight lines and reaches the one subtree it must not

`grep -rn "vault passphrase is\|the way the antseal vault" docs/ README.md MVP-SPEC.md`
— **8 lines**:

```
docs/decisions/D153-key-generated-publication-not-due.md:745
docs/decisions/D71-binary-signing-mechanism-and-key-custody.md:560
docs/decisions/D71-binary-signing-mechanism-and-key-custody.md:581
docs/signing/key-custody.md:55
docs/signing/key-custody.md:70
docs/signing/maintainer-key-procedure.md:53
docs/signing/maintainer-key-procedure.md:76
docs/signing/maintainer-key-procedure.md:283
```

Four are the sites to replace. **`:283` is §7's quotation of the defect with the
correction attached** — a lane executing *"no site instructs by analogy"*
literally would delete the note that records why step 2 was deferred. **The other
three are decision records**, where in-place rewriting is forbidden outright
(D71's own banners at `:3`, `:12`: *"the body is left as written, because this
project amends by dated addendum and does not rewrite history"*).

An **absence-only** measurement has a second defect that is this project's named
failure class: it goes green if a lane deletes all four paragraphs. R3 pairs it
with a presence assertion.

### 1.5 Q258's counts and vocabulary, measured

- `Do` (`tasks/Q.md:3295`): *"Name §1a step 1's two offline backups as **the one
  overdue act**"*. §1a step 1 is **DONE 2026-08-22** (`key-custody.md:209`;
  `maintainer-key-procedure.md:270-281`). Nothing in the set is overdue.
- `Accept` row 1 (`:3298`): *"Each of the **three** acts…"*. The three came from
  D153 §2 R9 item 3, which bundles *"§1a steps 1–2"* as one. That bundle **split**
  on 2026-08-22: step 1 landed, step 2 was separately deferred. The live set is
  **four**.
- `Accept` row 4 (`:3301`): *"The single-copy-key exposure is stated with its
  bound (§2 R7.1's `-W` ban) and its unbound residue (**deletion**)."* False on
  both halves since 2026-08-22 — the key is recoverable from two verified
  off-site copies, so deletion of the live copy is bounded. The residue that
  remains unbounded is **loss of the passphrase**, which §1a step 2 addresses and
  Q259 gates.
- `Accept` row 4 cites *"§2 R7.1"* with **no document**. It is **D71** §2 R7.1.
  Row 3's own standard is *"a reader who has read no decision record can act on
  this row alone"*, which a bare `§2 R7.1` defeats — the reader cannot even find
  the record to disobey the standard.

**The vocabulary is the substantive defect.** `overdue / triggered /
release-timed` fuses two independent questions:

| act | what is stopping it | when to take it |
|---|---|---|
| §1a step 1 | nothing | immediately after §1 → **taken 2026-08-22** |
| §1a step 2 | **Q259** | after Q259 lands |
| §2 | **nothing** (§1 is done) | any time from now; **must** precede §5 |
| §3 | nothing (D153 §2 R4's gate discharged) | **a few days before the release date — not now and not after** |

No single word covers §2's row, which is why the brief reached for a fourth
(`ARMED`) and got the direction wrong (§1.6). And `release-timed` means *do not
take it yet* on §3's row while it would mean *its deadline is the release* on
§2's — one word, opposite instructions. D153 §2 R5's heading already names this
class: *"the timing claim that flattens §A R4"*. Q258 as written would put the
flattening back.

### 1.6 §2 is not waiting on anything

- `maintainer-key-procedure.md:9-11`: *"Order matters: **§1 → §3 → §2**."* The
  reason given is scheduling, not dependency: *"The key must exist before it can
  be anchored, and D71 §A R4 wants the anchor a few days ahead of the release
  while the `TXT` pin should be in place from the moment the key is first
  published."* The only hard predecessor stated anywhere is **§1**, which is done.
- `maintainer-key-procedure.md:92-116` §2 needs one input: the 56-character public
  key from §1a. It exists (`key-custody.md:208`, key id `3E5D46890F192F58`).
- `maintainer-key-procedure.md:188-193` §5: *"**After §1 and §3, and never before
  §2.** … writing the key into any location below **is** the first publication of
  the key."*
- D71 §A R4 (`:1065-1072`): *"**The DNS TXT pin's clock starts the moment the key
  is first published** … **It is the one that should not be deferred**, on
  asymmetry rather than on probability."*
- `dig +short TXT antseal.org` → **empty**, exit 0, re-measured in this lane. The
  key appears in **zero** publication locations: `README.md:50-54` holds the
  marker pair with the placeholder *"No key is published here yet."*

So the trigger D71 §A R4 dates to first publication is the trigger for the pin
**already being in place**, not the trigger for taking it. §2 is takeable today,
by the maintainer, at the registrar, under express in-the-moment consent naming
action, destination and account. **`ARMED` — "triggered by an event that has not
happened" — describes a thing to wait for, and §2 is the one act D71 says not to
wait on.** §7 gets this substantially right already (`:295-299`, *"§2, the `TXT`
pin, is **not** release-timed"*); what it lacks is a field that says *nothing is
stopping it*.

The `§1 → §3 → §2` arrow notation at `:9` is the surface that invites the wrong
reading, and it is the same shape as wave 27's phantom cycles: a schedule written
as an ordering and then consumed as a gate.

### 1.7 §5 is not a maintainer act

`maintainer-key-procedure.md:3-5`: *"**Three** acts here are **external**: they
touch the maintainer's own machine, the domain registrar account, and a public
timestamp calendar."* That is §1, §2, §3. §5's three items — `README.md`, the page
footer, `minisign.pub` as a release asset — are repository edits, and R96 exists
precisely because one of them has no write target yet.

The page is titled *"the acts only the maintainer can perform"* and §5 is inside
it. The contradiction is real and small; R5 resolves it by naming §5's performer
in the routing table rather than by re-titling the page.

### 1.8 The stale-site census — and the two that must NOT be edited

| site | what it says | class | disposition |
|---|---|---|---|
| `maintainer-key-procedure.md:87` | *"today the key has exactly one copy, on a machine that is not dedicated to it"* | **product copy carrying a status claim outside §7** | **in-place edit** (R6) |
| `maintainer-key-procedure.md:283-284` | *"a referent that exists nowhere in this project"* | §7, the status section, wrong on a fact | **in-place edit** (R6) |
| `D71-…:1345-1346` | *"§1a step 1's two offline backups do not yet exist, so the key is currently single-copy on a live account"* | ruling-adjacent, inside the 2026-08-19 addendum | **dated addendum** (R6) |
| `D153-…:65` | *"**Nothing bounds a delete, and there is no backup.**"* | **Status headline** — the most-read paragraph | **banner + dated addendum** (R6) |
| `D153-…:308-309` | §1.7's measurement | **a dated measurement in a §1** | **stands as written** |
| `D153-…:504-505` | inside the fence at `:496-506` | **R4's `append … exactly:` prescription block** | **must not be edited** |
| `D153-…:521-522` | inside the fence at `:517-536` | **R5's `Replace … with, exactly:` prescription block** | **must not be edited** — and already superseded |
| `docs/decisions/README.md:171` | *"nothing bounds a delete while no backup exists"*; *"`git log --follow` returns **one** commit"* | index summary of a dated record | **stands as written** (R6 clause 4) |
| `TODO.md:102` | the wave-27 banner, dated `2026-08-19` | dated banner | **stands as written** |
| `key-custody.md:208` (§10 row 1) | *"§4's two offline backups are **NOT** yet made"* | append-only custody log | **stands, superseded by `:209`** — confirmed correct, R8 |
| `tasks/Q.md` Q258 `Accept` row 4 | the single-copy exposure | tracker | **amended by R4** |

**The brief listed `:308-309`, `:504` and `:522` as three claims of one kind.
They are three different kinds, and two of them are quotations of mandated
replacement text.** Editing a fenced *"replace with, exactly"* block does not
correct a stale observation — it silently rewrites what the record **ruled**,
and the next lane comparing page to record can no longer tell which moved.

Fence boundaries, measured with `grep -n '^```'` on D153: `446 453 457 490 492
496 506 517 536 546`. `:504` lies in `496–506`; `:522` lies in `517–536`.

**The superseded-prescription hazard, which nothing records.** D153 §2 R5's block
(`:517-536`) is the exact §7 text the 2026-08-22 act replaced. A lane later
asked to *"verify §7 matches D153 §2 R5"* would find a mismatch and could restore
`"§1a step 1 is NOT complete"`. R7 records the supersession where a reader of R5
will meet it.

### 1.9 The tracker's two Q258 surfaces already disagree, and the gate is green

- `TODO.md:870` (rewritten 2026-08-22): *"**§1a step 1** … was **overdue and
  blocking** and is **DONE 2026-08-22**"*, plus *"**A fourth act is now visible
  and outstanding: §1a step 2**"*, plus the single-copy clause struck through and
  marked *"**SUPERSEDED 2026-08-22**"*.
- `tasks/Q.md:3295` (untouched): *"Name §1a step 1's two offline backups as **the
  one overdue act**"*, and `:3298`: *"Each of the **three** acts…"*.

`python3 scripts/check-traceability.py` (flagless — the check), status written to
a file and read back: **`REAL_EXIT=0`**, eight of eight ok, including
`[task-entries] ok — 691 rows (690 live + 1 struck) against 691 entries; no row
without an entry, no entry without a row, no duplicate, none misfiled`.

The `--task-entries` check is an **existence** check. Nothing compares a row's
body to its entry's body, and the divergence is live and invisible right now.
This is the same class as the ledger's 2026-08-19 entry
(`docs/instrument-ledger.md:212`, *"Nothing in the corpus can detect a status
claim written outside `maintainer-key-procedure.md` §7"*), reappearing one
surface further out.

**This is the measurement that decides Q258's artifact.** A four-row status table
is a thing that must be re-edited on every maintainer act, on two tracker
surfaces, with no check between them — and one such re-edit has already gone
half-done. The deliverable must instead be a row body **with no time-varying
sentence in it**, which cannot be falsified by an act at all.

### 1.10 Checker candidates, measured rather than asserted

**(a) "A status claim written outside §7", prose detector.** Pattern
`today the|currently|not yet|has not been|have not been|is NOT complete|are NOT|
does not exist|still returns|as of today|no key is published|nothing has been`
over `docs/signing/*.md` (734 lines):

- **16 hits. 1 true positive** (`maintainer-key-procedure.md:87`).
- 4 are legitimately inside §7; 11 are false positives — `key-custody.md:12` (the
  pointer D153 §2 R2 *mandates*), `:87` (*"withdrawal does not exist"*, a property
  of minisign), `:163` (*"not yet by Bitcoin"*, OTS mechanics), `:180` (the
  deliberate dated *"TODAY THERE IS NO INDEPENDENT PIN"* block), `:208`, `:209`
  (§10's dated rows, legitimate by design),
  `maintainer-key-procedure.md:146`, `:156`, `:206`,
  `verifying-a-release.md:10`, `:66`.

**(b) "Copy-count claim", tree-wide.** Pattern `single-copy|exactly one copy|
backups (do not|have not|are NOT)|no backup` over `docs/ README.md TODO.md tasks/
MVP-SPEC.md`: **33 hits, ~6 true positives**, **27 false** — almost all the
*vault* backup copy in `vault-loss.md`, `vault-theft.md`, `threat-model.md`,
D151, U88 and their tests.

**(c) `key-custody.md` §10 append-only.** §10 says *"Never edit a row"*
(`:204`) and nothing enforces it. Prototyped and measured in this lane:

- Against the working tree with `HEAD` as baseline:
  `baseline rows=1 current rows=2 violations=0`, **`REAL_EXIT=0`**.
  **Measured false positives: 0.**
- **Fault planted** — in a scratch copy, the 2026-08-19 row's
  *"§4's two offline backups are NOT yet made"* changed to *"…are made"*
  (a plant anchor assertion guarded the edit, so a silent no-op plant would have
  raised): `violations=1`, `::error:: row 1 EDITED`, **`REAL_EXIT=1`**. It goes
  red, and the message names the row rather than merely exiting nonzero.
- Against the log's **birth** commit `2cdf0fb` instead of `HEAD`:
  `birth rows = 1 … violations against BIRTH baseline = 1` — the placeholder row
  `| — | *(no key generated yet)* | … |` replaced in `5c8d1ca`, which
  `key-custody.md` §11's second entry (`:231-242`) already documents in advance,
  *"so a later reader should not try to 'repair' it"*. A birth-baselined variant
  therefore needs exactly **one** registered exception; a `HEAD`-baselined
  variant needs none.

`git log --follow --oneline -- docs/signing/key-custody.md` returns **two**
commits (`5c8d1ca`, `2cdf0fb`). D153's *"exactly one commit"* was true when
measured and is now stale; it is a §1 measurement and stands (§1.8).

---

## 2. Ruling

### R1 — Q259 takes **arm one**: self-contained guidance at all four sites. The referent is named only as a **contrast**, never as a pointer

**Who: an implementing lane**, write scope `docs/signing/` only.

Arm two (*write the referent*) is refused at §3.2; the brief's third arm (*link
and bound the existing referent*) is refused at §3.1; a fourth arm (*delete the
instruction, since loss is cheap*) is refused at §3.3.

The replacements below are **spliceable, not composable**: each is the exact
text. They obey D71 §2 R11 (no *verified*, no *revoked/expired/rollover*, no
independence claim, no legal claim) and touch none of `check-copy-style.py`'s
P1–P3 bans (`notary`, `priority`, `authorship`).

They **duplicate** `vault-theft.md`'s generation advice deliberately rather than
sharing a source. A shared source would be wrong: the two secrets' dials point
opposite ways (§1.2), so the sentence that must differ is the one a shared source
would unify. This is not a freeze-boundary-style drift-checked copy and must not
be made one.

**Site A — `maintainer-key-procedure.md:53-54`.** Replace both lines with, exactly:

```
Use a long passphrase, **generated rather than invented** — five or six random
words from a large list, or 20+ random characters from a password manager — and
used for nothing else. **It is not the vault passphrase, and it is not kept the
way one is.** Losing this one is the cheap failure (`key-custody.md` §5):
generate a new key, run `key-custody.md` §6's rotation, and every signature
already published stays valid and checkable. Losing a vault passphrase is
final. So the effort here
goes into **strength, not into copies** — this passphrase is the only thing
between a copy of the key file and the key itself (D71 §2 R7.1), and
`key-custody.md` §4 requires that copies of that file exist.
```

**Site B — `maintainer-key-procedure.md:76-77`.** Replace both lines with, exactly:

```
2. Write the passphrase down **once**, on paper, and keep it somewhere you
   control that is **neither** backup location from step 1 — a passphrase kept
   beside the key file it wraps is not a passphrase. Do not make a second copy
   for safety: losing it costs a rotation (`key-custody.md` §5), while a copy in
   the wrong place costs the key.
```

**Site C — `key-custody.md:55-56`.** Replace both lines with, exactly:

```
The passphrase is **generated rather than invented** — five or six random words
from a large list, or 20+ random characters — and is used for nothing else. It
is **not** the vault passphrase and is not held the way one is: §5 makes losing
this one the cheap failure, while [`vault-loss.md`](../user/vault-loss.md) makes
losing a vault passphrase final. The effort goes into strength rather than into
copies, because
this passphrase is the only thing between a copy of the key file and the key
itself, and §4 requires that copies of that file exist.
```

**Site D — `key-custody.md:70-71`.** Replace both lines with, exactly:

```
- The **passphrase** written down once, on paper, kept somewhere the maintainer
  controls that is neither backup location — never stored with either backup,
  and deliberately not duplicated for safety (§5: losing it costs a rotation, a
  copy in the wrong place costs the key).
```

Sites B and D each keep the *not with the backups* clause verbatim in substance;
that clause is the one part of the old text that was correct and that the
maintainer acted on (`key-custody.md:209`).

Site C's link to `../user/vault-loss.md` is the **first** structural
cross-link from `docs/signing/` to `docs/user/` — measured: the only existing
mention is the uncommitted code span at `maintainer-key-procedure.md:286`, which
is not a link, and R6 item 2 keeps that section's plain-code-span style rather
than linking. It is deliberate and it is a
contrast, not a referent: the sentence tells the reader the linked page describes
a **different** discipline. A lane must not add a second link that reads as
guidance to follow.

### R2 — All **four** sites, named individually, and §7's quotation left alone

Q259's `Do` says *"both analogies"*; the sites are four (§1.3). The lane edits
**A, B, C and D** and **nothing else in `docs/signing/`** except the two
corrections R6 mandates. In particular `maintainer-key-procedure.md:283-284` is
§7's record of why step 2 was deferred: R6 corrects one clause of it and the rest
stays.

### R3 — Q259's `Accept` is re-specified: three rows become four, and row 1 is bounded so it cannot red on a quotation and cannot green on a deletion

**Row 1.** Old (`tasks/Q.md:3312`):

> No site instructs by analogy to guidance that does not exist; measured by grep over `docs/` and `README.md`.

New, exactly:

> No instruction in the signing pages tells the maintainer to generate, store or record this passphrase by analogy to the vault's. **Measured as** `grep -nE 'vault passphrase is|the way the antseal vault' docs/signing/*.md README.md`, **excluding `maintainer-key-procedure.md` from its `## 7. What has and has not been run` heading to end of file** — expected count **0**. Both exclusions are the point of the measurement, not conveniences: `docs/decisions/` is out of scope because a record is amended by dated addendum and never rewritten (D157 §2 R6), and §7 is out of scope because it **quotes** the old instruction in order to record why §1a step 2 was deferred — a lane "fixing" that quotation would delete the note explaining the deferral. Baseline measured 2026-08-22: the unrestricted grep returns **8** lines — the 4 sites this row replaces, §7's quotation at `maintainer-key-procedure.md:283`, and 3 inside `D71` and `D153`.

The §7 boundary is stable: §7 is the last section of the file
(`## 7.` at `:258`, file ends at `:299`).

**Row 2 (new — the presence half).** Exactly:

> Each of the four sites — `maintainer-key-procedure.md` §1 (the passphrase paragraph) and §1a step 2, `key-custody.md` §2 (closing paragraph) and §4 (the passphrase bullet) — carries the replacement text of D157 §2 R1 **verbatim**. Stated as a presence assertion because row 1 alone is an absence check, and an absence check goes green if a lane deletes the paragraphs instead of replacing them.

**Row 3.** Old (`tasks/Q.md:3313`) — **unchanged**:

> The guidance states the signing key's own loss profile and cites `key-custody.md` §5 and §6 for it.

**Row 4.** Old (`tasks/Q.md:3314`):

> The distinction from the vault passphrase is stated rather than implied, so the two disciplines cannot be confused again.

New, exactly:

> The distinction from the vault passphrase is stated **with its direction**: losing this one is recoverable and losing a vault passphrase is not, so this one is defended by **strength** rather than by **copies**. `docs/user/vault-theft.md` is not cited as guidance to follow anywhere in `docs/signing/`; the single link to `docs/user/` introduced by this row is to `vault-loss.md`, in a sentence that marks it a contrast.

**`Problem` and `Do` are amended too.** `Problem`'s *"**Measured 2026-08-19, that
guidance does not exist**: no passphrase-storage procedure is written in `docs/`,
`README.md` or `MVP-SPEC.md`"* is replaced by: *"**Measured 2026-08-19 as absent;
re-measured 2026-08-22 and it exists** — `docs/user/vault-theft.md:117-126`,
linked from `README.md:84-85`, prescribes generation and storage for the vault
passphrase, and `:123-124` calls forgetting it 'equally final'. So the pointer is
a **live mis-instruction with a known sign**, not a dangling one: it pushes the
maintainer to replicate the one secret that must not be replicated. Sites B and D
point at a referent that additionally cannot be written — antseal deliberately
records the user's vault passphrase nowhere (`docs/user/vault-loss.md:163`,
`:169-172`)."*

`Do`'s *"— or write the referent the pointer assumes, and say explicitly which of
the two was done"* is **struck**: D157 §2 R1 rules the arm, and the alternative is
refused at §3.2. `Do` becomes: *"Splice D157 §2 R1's four exact replacements into
sites A–D. Compose nothing."*

### R4 — Q258's artifact is **not a table in the tracker**. §7 keeps status; §7 gains routing; the row keeps a body with no time-varying sentence

**Who: an implementing lane** for the `docs/signing/` half; **the registrar** for
the two tracker surfaces.

D153 §2 R2's rule is scoped to *"every other page in `docs/signing/` and
`README.md`"* and does not textually reach the tracker. Its **reason** does, and
§1.9 is the measurement: the tracker already carries two copies of this act
status, they already disagree, and the gate is green. Three parts:

**(a) `maintainer-key-procedure.md` §7 keeps status, and gains one table.** §7
already carries what has and has not been run, in prose, correctly as of
2026-08-22. It lacks the fact a readiness survey actually needs — *what does each
act release* — and that fact is **stable**: it does not change when an act lands.
§7 gains, immediately after its existing bullets, exactly:

```
### Which act releases what

Two fields, not one class word: what is *stopping* an act and when to *take* it
are independent, and one word for both is what D153 §2 R5 removed from this
section once already. Status stays in the bullets above; this table does not
restate it.

| act | who takes it | blocked by | take it when | releases |
|---|---|---|---|---|
| §1 generate | maintainer, own machine | — | — | §1a, and everything below it |
| §1a step 1 — two offline backups | maintainer | nothing | immediately after §1 | §3 and §4 (D153 §2 R4 moved this gate forward from §4 to §3) |
| §1a step 2 — record the passphrase | maintainer | **`Q259`** | after `Q259` lands, not before | nothing else; it closes the residue that a lost passphrase is a lost key |
| §2 — the registrar `TXT` pin | maintainer, at the registrar, **express in-the-moment consent naming action, destination and account** | **nothing — §1 is done** | any time from now. It must exist before §5, and D71 §A R4 calls it *"the one that should not be deferred"*; §A R5 clause 3's *"before first release"* is its outer deadline, not its schedule | §5, and with it `Q30` Accept row 1 |
| §3 — anchor the public key | maintainer, own machine + a public calendar | nothing (§1a step 1 discharged its gate) | **a few days before the release date — not now and not after** (D71 §A R5 clause 4) | §5 step 3's `minisign.pub.ots`; `Q30` Accept row 1 |
| §5 — publish the key in three places | **a lane, not the maintainer** — §5 is three repository edits, and the preamble above names only §1, §2 and §3 as external | §2 and §3 | after both | `Q30` Accept row 1; `R96` is the missing write target for step 2 |

`§1 → §3 → §2` at the top of this file is a **schedule**, not a dependency chain.
The only hard predecessor in the column above is §1.
```

**(b) `tasks/Q.md`'s Q258 entry keeps routing and delegates status by name.** Its
body must contain **no sentence that changes when an act lands** — that is the
acceptance test for the body itself, and R5's `Accept` states it.

**(c) `TODO.md`'s Q258 row is reduced to the same content.** Both tracker
surfaces say the same non-time-varying thing, so they cannot drift into
disagreement even though nothing checks them. In particular the row's
*"is **DONE 2026-08-22**"*, *"A fourth act is now visible and outstanding"* and
the struck-through single-copy clause all leave the row and live only in §7 and
in `key-custody.md` §10.

This is not a retreat from visibility. The failure Q258 exists to prevent was that
the acts were invisible *inside another row's Notes*; a row of their own naming
four acts, their owners, and what each releases is visible, and status is exactly
one hop away in a section that is authoritative and was in fact maintained.

### R5 — Q258's `Do` and all four `Accept` rows, amended with old text quoted

**`Do`.** Old (`tasks/Q.md:3295`):

> give the three acts a visible home that states, per act, **who** takes it, **what unblocks when it lands**, and **whether it is overdue, triggered, or release-timed** — never a single "pending maintainer" bucket. Name §1a step 1's two offline backups as the one overdue act, with D153 §2 R4's finding that it gates §3 and not merely §4.

New, exactly:

> Give the acts one visible home and **only one**. Status stays where D153 §2 R2 put it — `maintainer-key-procedure.md` §7 — which gains D157 §2 R4(a)'s routing table: per act, **who** takes it, **what is blocking it**, **when to take it**, and **what it releases**, by row id. This row's own body carries the same non-time-varying content and **no act status at all**, on both tracker surfaces, because `TODO.md`'s copy and `tasks/Q.md`'s copy of this row are already known to disagree with the traceability gate green (D157 §1.9). Do **not** introduce a class word: *overdue / triggered / release-timed* fuses two independent axes and means opposite things on §2's row and §3's (D157 §1.5).

**`Accept` row 1.** Old (`:3298`):

> Each of the three acts is stated with its class (overdue / triggered / release-timed) and the record that classifies it.

New, exactly:

> `maintainer-key-procedure.md` §7 carries D157 §2 R4(a)'s table with all **six** rows — §1, §1a step 1, §1a step 2, §2, §3 and §5 — each with its `blocked by` and `take it when` filled from the record that decides it (D71 §A R4 for §2, §A R5 clause 4 for §3, D153 §2 R4 for §1a step 1, D157 §2 R1 for §1a step 2). No single class word appears.

**`Accept` row 2.** Old (`:3299`):

> The row names what each act unblocks, by row id.

New, exactly:

> The `releases` column names row ids — `Q30` Accept row 1 for §2, §3 and §5, `R96` as §5 step 2's missing write target, `Q259` as §1a step 2's blocker — and §5 is marked **not a maintainer act**, since `maintainer-key-procedure.md:3-5` names exactly three external acts and §5 is not one of them.

**`Accept` row 3.** Old (`:3300`):

> A reader who has read no decision record can act on §1a step 1 from this row alone.

New, exactly:

> A reader who has read no decision record can act on **§2** — the only act with nothing blocking it — from §7's table alone, including that it needs the registrar account and express in-the-moment consent naming action, destination and account. Every decision cited in the table is cited as `D<id> §<section>`, never as a bare `§…`.

The subject moves from §1a step 1 to §2 because §1a step 1 is done: a
readiness-from-this-row-alone standard aimed at a completed act cannot fail.

**`Accept` row 4.** Old (`:3301`):

> The single-copy-key exposure is stated with its bound (§2 R7.1's `-W` ban) and its unbound residue (deletion).

New, exactly:

> The exposure is stated as it stands after 2026-08-22: the bound is **D71** §2 R7.1's `-W` ban — the key is `Sc`-wrapped, so possession of a copy is not possession of the key — and the residue is no longer deletion, which two verified off-site backups make recoverable, but **loss or disclosure of the passphrase**, which now defends **three** copies of the key file rather than one. §1a step 2 addresses the first and `Q259` gates it; `key-custody.md` §7 is the response to the second.

**`Accept` row 5 (new).** Exactly:

> No sentence in this row's body — on either tracker surface — changes when a maintainer act is taken. Read the body and name the sentence that would need editing the day §2 lands; if one exists, the row is not done.

`Problem`'s *"The three remaining maintainer acts"* becomes *"The remaining
maintainer acts — **four** as of 2026-08-22, since D153 §2 R9 item 3's bundled
'§1a steps 1–2' split when step 1 landed and step 2 was separately deferred"*.

### R6 — Stale-site disposition: two in-place edits, two dated addenda, four stand

**(1) In place — `maintainer-key-procedure.md:85-87`.** This is a **status claim
in product copy outside §7**, which is what D153 §2 R2 forbids independently of
whether it is stale. Replace *"§1.7 of D153 is the measurement that makes this
concrete rather than theoretical: today the key has exactly one copy, on a
machine that is not dedicated to it."* with, exactly:

```
D153 §1.7 measured what that costs concretely rather than theoretically, on a
key that was then single-copy on a shared-use machine. §7 records whether the
backups exist today; this section states only why they gate §3.
```

The reasoning §4 needs is preserved; the status is delegated. **This is the
site that proves the ledger's 2026-08-19 entry** — it is a status claim outside
§7, written by the same wave that made the rule.

**(2) In place — `maintainer-key-procedure.md:283-284`.** Replace *"a referent
that exists nowhere in this project"* with, exactly:

```
a referent that resolves, since it was written, to guidance for a different
secret with the opposite loss profile (`docs/user/vault-theft.md`) — so following
the pointer imports the wrong discipline rather than finding nothing
```

**(3) Dated addendum — `D71-…`, appended at end of file.** The stale sentence at
`:1345-1346` is inside the 2026-08-19 addendum and stays as written. Append,
exactly:

```
## Addendum — 2026-08-22 (D157 §2 R6 item 3). Appended; no ruling moves.

- **The 2026-08-19 addendum's *"Nothing bounds a delete"* is superseded.** The
  maintainer executed `maintainer-key-procedure.md` §1a step 1 on 2026-08-22:
  two offline backups on separate media, held off-site, each verified **from the
  backup copy** with `minisign -R` re-deriving key id `3E5D46890F192F58`
  (`key-custody.md` §10, second row). A delete of the live copy is now
  recoverable and the key is not single-copy. Media, locations and separateness
  are the maintainer's attestation and no record verifies them.
- **§2 R7.1's `-W` ban gained weight in the same act, and this is the part that
  is easy to read backwards.** The ban is what bounds the exposure, and the
  passphrase is what the ban means in practice. There were one `Sc`-wrapped copy
  of the key file before 2026-08-22 and three after. The passphrase's *strength*
  is therefore the control that scaled with the backups; its *replication* is
  the risk that scaled with them. D157 §2 R1 writes that into the two pages.
- **Nothing in §2 R1–R12 or §A R1–R6 moves.** The `-W` ban, the four pins, the
  four prohibitions and §A R4's timing all stand exactly as ruled.
```

**(4) Banner + dated addendum — `D153-…`.** `:65` is in the Status headline, the
most-read paragraph in the record, and it is now false. The body is left as
written. Insert, as a new line 3 (between the title and the first `- **Status:`
bullet), exactly:

```
> **AMENDED 2026-08-22 — READ THE ADDENDUM BEFORE THE FINAL STATUS BULLET AND
> BEFORE §1.7.** *"Nothing bounds a delete, and there is no backup"* was true
> when measured and is **superseded**: the maintainer executed §1a step 1 on
> 2026-08-22 and the key has two verified off-site backups (`key-custody.md`
> §10, second row). **§2 R4's ruling is unaffected and is discharged, not
> withdrawn** — the backups gate §3, and they now exist. §1.7's measurement
> stands as a dated measurement. The body is left as written; see the addendum.
```

And append at end of file, exactly:

```
## Addendum — 2026-08-22 (D157 §2 R6 item 4 / §2 R7). Appended; no ruling moves.

- **§2 R4 is DISCHARGED.** §1a step 1 was executed 2026-08-22; the precondition
  it created is satisfied and §3 is no longer blocked by it. The ruling is not
  withdrawn — it decided *where* the gate sits, and that finding stands for any
  future key.
- **§1.7's measurement stands and is dated.** A §1 records what was true when it
  was measured. Readers wanting today's state read
  `maintainer-key-procedure.md` §7, which §2 R2 makes authoritative.
- **§2 R5's replacement block is SUPERSEDED — see D157 §2 R7.** The §7 text it
  mandates was replaced by the maintainer on 2026-08-22 and is no longer what
  the page should say. **The block at §2 R5 is not edited**, because a
  *"replace with, exactly"* block records what this record ruled, not what the
  page says today. Do not restore it.
- **§4.5's finding survives its own premise.** The passphrase pointer's referent
  now exists (`docs/user/vault-theft.md:117-126`) and prescribes the opposite
  discipline, which makes the defect worse rather than smaller. D157 rules it.
```

**(5) Stands as written:** `D153-…:308-309` (a dated measurement in a §1);
`D153-…:504-505` and `:521-522` (fenced prescription blocks — see R7);
`docs/decisions/README.md:171` (an index summary of a dated record; adding
addenda to the index would double the maintenance surface for a reader who is one
click from the record — and its *"`git log --follow` returns **one** commit"* is
likewise a dated measurement, now two); `TODO.md:102` (a dated wave banner).

### R7 — A prescription block is never edited, and D153 §2 R5's is recorded as superseded where a reader of R5 meets it

**The rule, stated so it is not re-derived each time.** A fenced block introduced
by *"replace … with, exactly"* or *"append … exactly"* is the record's **operative
text**. Editing it changes what the record ruled and destroys the ability to tell
whether the page or the ruling moved. When the page it prescribes is later changed
by a legitimate act, the block is **superseded**, and the supersession is recorded
in a dated addendum — never by rewriting the fence.

Two blocks are affected: **D153 §2 R4's** (`:496-506`), whose final sentence the
page no longer carries once R6 item 1 lands, and **D153 §2 R5's** (`:517-536`),
whose whole content the 2026-08-22 act replaced. R6 item 4's addendum records
both. No lane may "reconcile" `maintainer-key-procedure.md` §4 or §7 against
those blocks.

### R8 — `key-custody.md` §10's 2026-08-19 row correctly stands and is superseded by the 2026-08-22 row. Confirmed, with the one wrinkle named

§10 says *"Never edit a row"* (`:204`); the masthead says the file is
*"**append-only** — a change is a dated entry at the bottom, never an edit to
what is above it"* (`:6-7`); §11 says *"§10's rows are never edited at all"*
(`:214`). The 2026-08-19 row's *"§4's two offline backups are **NOT** yet made;
nothing may be signed until they are"* was true when written and is superseded by
`:209`, which states the discharge explicitly. **That is right, and no §11 entry
is owed** — §11 exists for amendments to §1–§10's *rules*, and no rule changed.

The wrinkle worth naming: `key-custody.md` §11's second entry already had to
document that §10's first row *replaced* a placeholder, *"so a later reader should
not try to 'repair' it"* (`:231-242`). That is the precedent for R7's rule in the
custody file, one wave earlier, and it is why R9's checker needs a registered
exception if it is baselined at birth.

### R9 — Checkers (a) and (b) are REFUSED on measured yield. Checker (c) is ACCEPTED in principle and ROUTED to a new row, not to Q258 or Q259

**(a) the prose "status outside §7" detector: refused.** Measured **16 hits, 1
true positive, 11 false positives** over 734 lines (§1.10a). The false positives
include `key-custody.md:12` — the pointer D153 §2 R2 *requires* — and `:180`, the
deliberate `TODAY THERE IS NO INDEPENDENT PIN` block. A check that reddens on the
rule it enforces is not a check. D154 refused two on measured yield; this is the
third.

**(b) the copy-count detector: refused.** **33 hits, ~6 true, 27 false**
(§1.10b), almost all of it the *vault* backup vocabulary. The word this defect
uses is the same word the product's largest copy surface uses for an unrelated
thing.

**(c) `key-custody.md` §10 append-only: accepted, and routed.** Measured
(§1.10c): **0 false positives** on the real tree with `HEAD` as baseline,
`REAL_EXIT=0`; **red on the planted fault** — the 2026-08-19 row's *"NOT yet
made"* → *"made"*, giving `violations=1`, `::error:: row 1 EDITED`,
**`REAL_EXIT=1`**, a message naming the row rather than a bare nonzero exit. **The
fault I would plant to prove it can go red is exactly that one**, and it is the
fault a well-meaning lane would actually commit: "correcting" a superseded
custody row to match today. Against the birth commit `2cdf0fb` it reports **1**
violation — the placeholder row `key-custody.md` §11 already documents — so a
birth-baselined variant carries exactly one registered exception in the shape
`check-copy-style.py` already uses for P7 debts.

**It is routed, not folded in.** It is not Q259's subject and it is not Q258's
deliverable; it is a new instrument. §4 item 1 states what the registrar mints.
**This record assigns no id.**

**Nothing mechanical is proposed for the tracker divergence of §1.9.** Comparing
two prose bodies has no measurable specification. R4's answer is structural
instead: a body with no time-varying sentence cannot diverge on a state change,
so there is nothing for a checker to find.

### R10 — Timing words, stated once so no lane converts one into a dependency

- **`Q258` and `Q259` remain recorded `with` each other.** Neither is the other's
  predecessor. This record rules both; it creates **no `after` edge between
  them**.
- **R1's four splices land `before` R6 item 2's §7 correction** — the §7 bullet
  cites the defect R1 removes, so correcting §7 first would leave it describing
  a state the pages no longer have. `before`, not `after`: they may land in one
  act, and often should.
- **R4(a)'s §7 table has no ordering relation to R1 at all.** Different section,
  different subject; either may land first.
- **`§1a step 2` is taken `after` `Q259`.** This is a genuine `after` and the only
  one in this record: `maintainer-key-procedure.md:286` and `key-custody.md:209`
  both already say so, and §7's table restates it. **It is a maintainer act and
  this record does not take it, schedule it, or consent to it.**
- **`R96` is `with Q258`, unchanged.** §7's table naming R96 as §5 step 2's write
  target creates no edge.

---

## 3. What was refused and why

### 3.1 The brief's third arm — *"the referent needs linking and bounding, not writing"* — refused

Bounding it means writing the exception: *"follow that page except its third
bullet, which is false for this secret and false in the direction that will cost
you the key."* That is longer than stating the rule, and it leaves the reader one
click from a page whose frame (*what someone else holding your vault and
passphrase can read*) is a disclosure threat, while the signing key's threat is
substitution. A pointer that must be read with an exception attached is the
defect Q259 was minted for, one level of indirection further out.

### 3.2 Arm two — *"write the referent the pointer assumes"* — refused, and it is unwritable for two of the four sites

For sites B and D the referent is *where the vault passphrase is recorded*.
antseal records it **nowhere**, deliberately: `docs/user/vault-loss.md:163`
(*"antseal does not hold it"*), `:169-172` (*"no recovery question, no escrow, no
key-splitting scheme in v1, and no `change-passphrase` command"*). There is
nothing to point at because the product's design is that nothing exists.

Writing a *maintainer* passphrase store instead would be a new normative page
with exactly one reader, restating in a second place a discipline that fits in
four lines where it is needed. It would also be a third custody surface, in a
subtree that has spent two waves reducing the number of places custody facts live.

### 3.3 The fourth arm — *"say nothing, since §5 makes loss cheap"* — refused, and refusing it is what sets the guidance's shape

Deleting the instruction is coherent only if the passphrase were merely the cheap
secret. It is not. D71 §2 R7.1's `-W` ban is the sole bound on the uid-1000
exposure (D71's 2026-08-19 addendum, `:1341-1344`), and the ban's content **is**
the passphrase: an `Sc`-wrapped key is only as unwrapped as its passphrase is
weak. §4's mandated backups multiply the population that bound protects. So the
one dial that must be prescribed is **strength**, and the one that must be
*restrained* is **replication** — which is the exact opposite of what the
referent prescribes, and why R1's text says *"strength, not copies"* in both
pages.

### 3.4 A fourth class word (`ARMED`) — refused

It describes waiting for an event. §2 waits for nothing: its only predecessor is
§1, which is done (§1.6). The event D71 §A R4 names is the moment the pin must
**already exist**, and §5 — that moment — is forbidden until §2 exists. A word
that turns *"the one that should not be deferred"* into a queue entry is worse
than no word, which is why R4 replaces the class column with `blocked by` +
`take it when` rather than extending it.

### 3.5 A four-row status table in `TODO.md` and `tasks/Q.md` — refused on the measurement in §1.9

The two surfaces already carry this act status, already disagree, and
`check-traceability.py` is green (`REAL_EXIT=0`, `[task-entries] ok — 691 rows
… against 691 entries`). The proposal is to add a maintained duplicate of a
thing that has demonstrated, on this exact row, that it does not stay in sync.

### 3.6 Re-titling `maintainer-key-procedure.md` to resolve the §5 contradiction — refused

The page title says *"the acts only the maintainer can perform"*; `:3-5` says
three of them are external and §5 is not among them (§1.7). The contradiction is
real, and the cheap fix — naming §5's performer in R4(a)'s table — resolves it
where a reader meets it. Re-titling a Class P page to fix one row's ownership is
disproportionate and would ripple into every page that links to it.

### 3.7 Editing `D153-…:504` and `:522` — refused, and this is the brief's sharpest error

Both are inside fenced *"replace/append … exactly"* blocks (§1.8). Editing them
would rewrite what D153 **ruled** while presenting it as correcting what D153
**observed**, and it would erase the only evidence that the page and the ruling
have diverged. R7 states the general rule; R6 item 4's addendum records the
supersession.

---

## 4. Residue

1. **A `key-custody.md` §10 append-only check has no row.** Measured green with 0
   false positives and red on a planted row-edit (§1.10c, R9). It belongs to the
   instrument family, not to Q258 or Q259. **The registrar mints one row for it**,
   `with Q258`, capturing: `HEAD`-baselined form needs no exception,
   birth-baselined form needs exactly one (the placeholder replacement §11
   `:231-242` documents), and the plant that proves it red is the 2026-08-19 row's
   *"NOT yet made"* → *"made"*.
2. **Nothing compares a `TODO.md` row's body to its `tasks/*.md` entry's, and one
   live disagreement exists right now** (§1.9). R4 removes this instance by
   removing the time-varying content; it does not remove the class. **Ledger
   entry owed** — `docs/instrument-ledger.md`, alongside the 2026-08-19 entry at
   `:212` it extends.
3. **`README.md:50`/`:54`'s marker pair still has two readers and no test** — the
   ledger already records it (`:211`) and R96 is adjacent. Untouched here.
4. **`maintainer-key-procedure.md:9`'s `§1 → §3 → §2` reads as a gate and is a
   schedule.** R4(a)'s table says so in its closing line rather than rewriting
   `:9`, because the arrow is also a useful mnemonic. If a third reader mistakes
   it, that is the moment to rewrite it — recorded so the third reader is counted.
5. **D153's *"`git log --follow` returns exactly one commit for `key-custody.md`"*
   is now two** (`5c8d1ca`, `2cdf0fb`). It stands as a dated measurement (R6
   item 5) and is noted here so no lane "discovers" it as a defect.
6. **Not ruled, deliberately: whether `key-custody.md` §2's *"Never"* list should
   now name the uid-1000 case.** D153 §2 R9 item 2 routed it and answered it not;
   the 2026-08-22 backups change its weight (three copies, one on that account)
   without changing the question. It stays routed.
7. **No maintainer act is taken, scheduled, or consented to by this record.** §2,
   §3 and §1a step 2 are the maintainer's, and §2 additionally requires express
   in-the-moment consent naming action, destination and account.

---

## 5. Registrar's and lanes' edit set

Timing words are literal. The **only** `after` in this record is item 9.

| # | file | edit | who | timing |
|---|---|---|---|---|
| 1 | `docs/signing/maintainer-key-procedure.md` `:53-54` | splice R1 Site A | lane | `before` 3 |
| 2 | `docs/signing/maintainer-key-procedure.md` `:76-77` | splice R1 Site B | lane | `with` 1 |
| 3 | `docs/signing/maintainer-key-procedure.md` `:283-284` | R6 item 2, one clause | lane | `after` 1–2 in reading order only; may land in the same act |
| 4 | `docs/signing/maintainer-key-procedure.md` `:85-87` | R6 item 1, status out of §7 | lane | `with` 1 |
| 5 | `docs/signing/maintainer-key-procedure.md` §7 | append R4(a)'s *Which act releases what* table | lane | independent of 1–4 |
| 6 | `docs/signing/key-custody.md` `:55-56` | splice R1 Site C | lane | `with` 1 |
| 7 | `docs/signing/key-custody.md` `:70-71` | splice R1 Site D | lane | `with` 1 |
| 8 | `docs/decisions/D71-…` | append R6 item 3's dated addendum; **body untouched** | registrar | independent |
| 9 | `docs/decisions/D153-…` | insert R6 item 4's banner at line 3; append its addendum; **`:65`, `:308-309`, `:496-506`, `:517-536` untouched** | registrar | independent |
| 10 | `tasks/Q.md` Q259 | R3: `Problem`, `Do`, `Accept` rows 1–4 (row 3 unchanged, one row added) | registrar | independent |
| 11 | `tasks/Q.md` Q258 | R5: `Problem`, `Do`, `Accept` rows 1–4 + new row 5 | registrar | independent |
| 12 | `TODO.md` Q258 row | R4(c): strip all act status; match the entry's non-time-varying body | registrar | `with` 11 |
| 13 | `docs/decisions/README.md` | one index row for D157 | registrar | last |
| 14 | `docs/instrument-ledger.md` | §4 item 2's entry | registrar | independent |
| 15 | `TODO.md` register | D157 allocated and homed; §4 item 1's new row minted | registrar | last |

**Not edited by anything here:** `docs/user/vault-theft.md` and
`docs/user/vault-loss.md` (correct for their own secret; the defect was never
theirs), `docs/decisions/README.md:171`, `TODO.md:102`,
`docs/signing/key-custody.md` §10 rows, `docs/signing/key-custody.md` §11
(no rule changed — R8).

**Gate obligations.** `docs/signing/` is Class P: `scripts/check-copy-style.py`
must stay green — R1's text carries no P1–P3 token (`notary`, `priority`,
`authorship`) and obeys D71 §2 R11's four prohibitions.
`scripts/check-traceability.py` must stay green — new decision id, new index row,
and any minted row needs its `tasks/*.md` entry in the same act.
