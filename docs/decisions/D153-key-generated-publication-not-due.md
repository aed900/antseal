# D153 — The key exists and §5 does not fire: D71 §A R4 rules the `TXT` pin's clock starts *at first publication*, so publishing the key is what the pin gates rather than what follows it — and the file that declares itself append-only was wrong about where its own log lives on the day it was born

> **AMENDED 2026-08-22 — READ THE ADDENDUM BEFORE THE FINAL STATUS BULLET AND
> BEFORE §1.7.** *"Nothing bounds a delete, and there is no backup"* was true
> when measured and is **superseded**: the maintainer executed §1a step 1 on
> 2026-08-22 and the key has two verified off-site backups (`key-custody.md`
> §10, second row). **§2 R4's ruling is unaffected and is discharged, not
> withdrawn** — the backups gate §3, and they now exist. §1.7's measurement
> stands as a dated measurement. The body is left as written; see the addendum.

- **Status: RESOLVED. The lean is OVERTURNED in its operative half and REFUTED
  IN SCOPE, MECHANISM AND CONTENT in the half that survives.** The lean was
  *"the key exists, so §5 step 1 fires: put the 56-character key in the README
  anchor now, and correct the three statements in place."*
  - **§5 does not fire, and the record that decides it says so in words nobody
    quoted.** D71 §A R4, `:1065`: *"**The DNS TXT pin's clock starts the moment
    the key is first published**, which is the same moment the first user pins
    it"*, and `:1070`: *"**It is the one that should not be deferred**."*
    Publishing the key in `README.md` **is** that first publication. The pin is
    not a thing that happens after publication and before release; it is the
    thing publication waits on. `maintainer-key-procedure.md:8-10` already says
    the same in its own opening — *"the `TXT` pin should be in place **from the
    moment the key is first published**"* — and `dig +short TXT antseal.org`
    still returns **empty**, re-measured today.
  - **The brief's own framing is half wrong, and §A R4's heading is the proof.**
    It reads *"Timing: both deferrable items share one property, and it decides
    them **differently**"* (`:1047`). Only §3, the anchor, is release-timed
    (*"stamp a few days before the release date"*, `:1063`). §A R5 clause 3's
    *"before first release"* is the `TXT` pin's **outer deadline, not its
    schedule**. Three live sites flatten that distinction into *"deliberately
    release-timed, by D71 §A R5 clauses 3 and 4"* — `maintainer-key-procedure.md:242-244`,
    `tasks/Q.md` Q30's Notes, and `TODO.md:819` — all three written yesterday and
    today, and the brief inherited it from them.
  - **There are FOUR false product statements, not three, and the fourth is in
    the file the maintainer edited.** `maintainer-key-procedure.md:5` still
    reads *"**No agent performs any of them, and none has been performed.**"* —
    three lines above §1's new admonition and 231 lines above the §7 bullet that
    contradicts it.
  - **The append-only question does not arise for the wrong cross-reference,
    because the pointer was never true.** `git log --follow` returns **exactly
    one commit** for `key-custody.md` (`2cdf0fb`, wave 24), and in that commit
    §7 was already *Compromise response* and the log was already §10. There is
    no superseded state for append-only to protect: the sentence merged the log
    in this file with the run-status section in the *other* file and fitted
    neither. It is a defect present at birth, repaired in place.
  - **"Correct in place" is the wrong mechanism because updating a status is
    what guarantees the next wave repeats this one.** All three banners that
    went false key on **existence**; the one banner that keys on **publication**
    — `verifying-a-release.md:10-14`, *"antseal has not made its first release"*
    — passed straight through this state change untouched. The repair is to
    stop writing status outside the one section that owns it, not to write a
    newer status.
- **The unlisted arm this record takes: the README key line's publication moment
  is not the commit, it is `Q65`'s visibility flip — an act owned by a different
  row whose checklist has no idea a key is riding on it.** `Q254` (`TODO.md:845`)
  is the ordered flip procedure and names four settings items, `Q242`, `Q243`
  and `Q244`; it names no key. Writing the key into the README today would make
  a row about repository visibility the executor of D71 §A R4's *"moment the key
  is first published"*, with the independent-pin column still empty. That is not
  a scheduling preference; it is the one property `key-custody.md` §9's
  *"TODAY THERE IS NO INDEPENDENT PIN"* block exists to keep visible.
- **The sharpest defect found on the way is not in the copy at all.** `minisign`
  **is now installed on this host** — `command -v minisign` → `/usr/bin/minisign`,
  `dpkg -l` → `ii minisign 0.11-1 amd64`, installed `2026-08-19 12:31:18` — and
  `~/.minisign` exists at mode `0700`, owned by `deb`, **the same uid 1000 this
  lane runs as and the same account that owns the working tree**. Five tracked
  sites still assert it is not installed, including **D71 §2 R12's own premise**
  (`:669`). `key-custody.md` §2's *"Never"* row enumerates CI runners, GitHub
  secrets, KMS, tracked files and online backups; it does not contemplate *a
  machine on which autonomous agents execute under the key holder's account*,
  which is now the fact. What bounds it is exactly D71 §2 R7.1's `-W` ban — the
  key is `Sc`-wrapped — so the ban acquired a threat model nobody had stated.
  **Nothing bounds a delete, and there is no backup.**
- **Date: 2026-08-19**
- **Owning task: Q30.** Every ruling here either edits a page in
  `docs/signing/` — the set Q30's lane landed whole in wave 24 — or governs when
  Q30's own §5 fires. The single `README.md` edit is not Q22's: D150 §2 R1/R2
  already ruled that §5 step 1 is *"Q30's own procedure acting on Q22's file"*
  and made Q30 the **consumer**, and this record writes into the anchor D150
  §2 R3 required Q22 to leave. Homing it on Q22 would also be inert — Q22 cannot
  tick until Q28 and Q34 close (D150 §2 R6, §4.1), while every act here is due
  now. **No new id is assigned here**; §5 describes what the registrar mints.
- **What it blocks:** Q30's `Accept` row 1 (*"Public key published in ≥2
  places"*), which this record rules cannot begin before §2 exists; Q30's
  `Accept` rows 2 and 3 through the two offline backups, which §2 R4 moves
  forward to gate §3; and `Q254`, whose flip checklist gains a step it does not
  have. Through Q30 it reaches Q31/Q32 and the Q34 gate.
- Related: **D71 §A R4** (`:1047-1077`, the timing ruling this turns on),
  **§A R5** clauses 3–4 (`:1087-1091`), **§A R6** (the flip makes the README pin
  *readable*, not *independent*), **§2 R5** (`:475-500`, the four pins),
  **§2 R11** (`:653-664`, the four prohibitions), **§2 R7.1** (the `-W` ban whose
  threat model this record supplies), **§2 R12** (`:669`, premise now false);
  **D150 §2 R3** (the operand rule, re-tested and surviving), **§2 R1/R2** (the
  consumer relation, landed in the wrong place), **§1.2/§1.4/§4.2** (measurements
  one row of which has changed); **D72 §2 R6** (the channel is inoperative while
  the repository is private — re-measured 404 today); **D141 §2 R7** (nothing
  checks the recorded order for cycles).

---

## 1. What was measured

Every figure below was re-measured in this lane. Where the brief, a row or a
record disagrees with the tree, the tree is quoted. Commands whose status
matters were written to a file and the status read back.

### 1.1 Baseline

- `python3 scripts/check-copy-style.py` (flagless — the check; `--check` is not
  a flag, `--self-test` and `--inventory` are the only two) at HEAD:
  **`REAL_EXIT=0`**, one line, *"26 product-copy file(s) across 8 scan root(s)"*,
  **P7 with 0 registered debt(s)**, P8 with 23 entries. **The file count moved to
  27 during this lane** — a sibling lane landed
  `crates/antseal-cli/tests/snapshots/list-blocked-work.txt` inside a `COPY_SCAN`
  directory entry — and the re-run at the end of this lane is
  *"27 product-copy file(s)"*, still `REAL_EXIT=0`. Both figures are correct at
  their moment; neither is this tracker's count-drift class.
- `python3 scripts/check-traceability.py` (flagless — the check) at HEAD:
  **8 of 8 ok, `REAL_EXIT=0`** — *"687 rows (686 live + 1 struck) against 687
  entries"*, *"152 allocated decision ids … 146 records, 6 homed elsewhere, 0
  still open"*, *"146 index row(s) … against 146 record(s)"*.
- Working tree: four files modified and uncommitted on `main` — `TODO.md`,
  `tasks/Q.md`, `docs/signing/key-custody.md`,
  `docs/signing/maintainer-key-procedure.md`. HEAD is `28afe38` (wave 26).
- Class P partition: `COPY_SCAN` at `scripts/check-copy-style.py:73-105`,
  `DOCS_CLASSIFICATION` at `:115-183`. `README.md` and the whole `docs/signing/`
  subtree are **PRODUCT**.

External probes, unauthenticated from this host, which is what a stranger sees:

```
https://github.com/aed900/antseal           -> 404
https://github.com/aed900/antseal/releases  -> 404
https://antseal.org/                        -> 200   (2 516 397 bytes)
dig +short TXT antseal.org                  -> 0 lines
dig +short DS  antseal.org                  -> 0 lines
```

**One probe failed and is reported as a failure rather than as a confirmation.**
`dig +short TXT antseal.org @1.1.1.1` returned *"communications error to
1.1.1.1#53: connection refused"* four times — this host cannot reach an external
resolver, so the second-medium check on the `TXT` result **was not obtained**.
Naïvely counting its output lines returns **4**, which is worse than useless: it
would read as four `TXT` records. The system resolver's empty answer is the only
`TXT` measurement this record has, and it agrees with every previous one.

### 1.2 The four false statements, and the one that survived

| site | text | verdict |
| --- | --- | --- |
| `README.md:51-53` | *"No signing key exists yet, so none is published here…"* | **FALSE** — first clause |
| `docs/signing/key-custody.md:9-13` | *"**STATUS, 2026-08-18: no key exists yet.** Nothing in this document has been executed against a real project key…"* | **FALSE**, and 195 lines above the §10 row that contradicts it |
| `docs/signing/key-custody.md:12` | *"the first line of **§7's log**"* | **WRONG POINTER** — §7 is *Compromise response*; the log is §10 |
| `docs/signing/maintainer-key-procedure.md:5` | *"No agent performs any of them, and **none has been performed**."* | **FALSE** — the brief did not list it |
| `docs/signing/README.md:29-30` | *"No signing key exists yet, the `TXT` pin has not been created, and nothing has been anchored."* | first clause **FALSE**; other two **true** |
| `docs/signing/verifying-a-release.md:10-14` | *"**Not yet published.** antseal has not made its first release, so the key below is shown as a placeholder."* | **TRUE — and this is the finding** |

`git grep` over the whole tree for the key-absence family returns exactly these
sites in Class P copy and nothing else; `key-custody.md §9`'s **"TODAY THERE IS
NO INDEPENDENT PIN"** block (`:180-185`) is **still true** and is not swept up.

**Why the last row is the finding.** Five statements went stale or were wrong;
the sixth passed through untouched. The difference is not care, it is grammar:
the five assert what **exists** or what **has been done**, and existence changes
under an act the project does not perform. The sixth asserts what **this page
carries** and what **has been published**, and publication is an act the project
performs and therefore notices. That distinction decides §2 R2, R3 and R5.

### 1.3 D71 §A R4, quoted at length because three sites paraphrase it wrongly

`docs/decisions/D71-…:1047`, the heading:

> ### §A R4 — Timing: both deferrable items share one property, and it decides them **differently**

`:1060-1064`, the anchor:

> **The OTS anchor's clock starts when users appear.** … **Deferring it to first
> release costs almost nothing** … Concretely: **stamp a few days before the
> release date**, so the A14 upgrade completes and the release ships an upgraded
> proof rather than a pending one.

`:1065-1072`, the pin:

> **The DNS TXT pin's clock starts the moment the key is first published**, which
> is the same moment the first user pins it. It is the **only row in §2 R5's
> table with a different control plane**, and without it the "independent pin"
> column is empty — the scheme's security at first contact reduces to *trust
> GitHub* … **It is the one that should not be deferred**, on asymmetry rather
> than on probability: a one-time registrar action against an unbounded,
> retroactive, un-repairable downside.

§A R5 clause 3 (`:1087-1089`) then says *"**Take the DNS TXT record before first
release**"*. A deadline. Read together: the anchor has a **schedule** (a few days
before release); the pin has a **trigger** (first publication of the key) and a
**deadline** (before first release). Nothing in either licenses publishing the
key ahead of the pin, and §A R4 spends a paragraph saying why not.

`maintainer-key-procedure.md:8-10` is the second, independent site that already
had this right, in the document the lean would have had us act on:

> Order matters: **§1 → §3 → §2**. The key must exist before it can be anchored,
> and D71 §A R4 wants the anchor a few days ahead of the release while the `TXT`
> pin **should be in place from the moment the key is first published**.

**§5 is *"After §1 and alongside §2"* (`:177`) and publishes into three of the
four pins.** Put beside the ordering line, "alongside §2" cannot mean "before
§2" — and it is the only phrasing in the whole procedure that leaves room for
the reading the lean took.

### 1.4 The `§7`→`§10` pointer was never true, and the measurement settles the class

```
git log --follow --oneline -- docs/signing/key-custody.md      -> 1 commit (2cdf0fb)
git show 2cdf0fb:docs/signing/key-custody.md | grep '^## '     -> §7 Compromise response, §10 Log
git show 2cdf0fb:docs/signing/maintainer-key-procedure.md      -> §7 "What has and has not been run" (:220)
```

The file has had exactly one commit and the pointer was wrong inside it. So this
is **not** a stale reference that rotted as sections moved, and the append-only
rule has nothing to preserve: there is no earlier true state that an edit would
erase. The most likely cause is visible in the sentence itself — it wanted both
*the log* and *what has been run*, and those live in two different files (§10
here, §7 there). It named one section number for two things and matched neither.

### 1.5 D150 §2 R3's operand rule, re-tested against a tree where one operand changed

R3's rule (`D150:463-468`), verbatim:

> **A command block in product copy is a promise that it runs.** Where an operand
> of that command does not exist — an artifact, a signature, a key, a reachable
> page — the block is not written at all. … **A placeholder is permitted in a
> *procedure*; it is refused in a *pin*.**

D150 §1.4 measured four missing operands. Today:

| operand | 2026-08-18 | 2026-08-19 |
| --- | --- | --- |
| the artifact `antseal-x86_64-unknown-linux-gnu.tar.gz` | absent | **absent** (`README.md:34`, *"There is no released binary"*) |
| its `.minisig` | absent | **absent** |
| the 56-character key | absent | **exists — and is obtainable by nobody** |
| a reachable page for all three | 404 | **404**, re-measured |

The rule is a disjunction over operands, so three surviving absences forbid the
block by themselves. The key row needs one word of interpretation and this record
supplies it rather than leaving it to be re-derived: **the operative test for a
key in a command block is *obtainable by the reader*, not *in existence
somewhere*.** A block is *"a promise that it runs"*; a key the reader cannot get
is a block that does not run. Under that reading nothing about R3's application
changed today. Under the alternative reading — bare existence — one row flips and
the block is still forbidden by three. **R3 survives on either reading**, which
is why the narrowing is stated as a clarification rather than as a repair.

What did change is R3 item 3's mandated **sentence content**: *"with one sentence
between them stating that **no key exists yet**"* (`D150:483-484`). That clause is
now false and is the only part of R3 this record amends.

### 1.6 Two publication locations §5 does not name, both measured missing

`§5` names three places and `§6 step 4` names *"all four"* (`README.md`, the page
footer, the DNS `TXT` record, the release). Neither list is complete.

**(a) `verifying-a-release.md` carries the placeholder three times.**
`git grep -n 'RW<'` returns `:12`, `:35` and `:92` in that file — the command a
stranger runs (`:35`), the scripted form (`:92`), and the banner that explains
the placeholder (`:12`). D150 §2 R3 item 2 is precisely why it is *allowed* to
carry them: it is a procedure page, not one of the four pins. But nothing in §5,
§6 or D71 §2 R5 says who replaces them, and it is **the one page a stranger
actually follows**. A publication act that changes the four pins and not this
page leaves a fake key in the only place a reader is told to type one.

**(b) §5 step 2's target does not exist.** `verifier-web/` holds exactly one
file (`index.template.html`); `git grep -c -i minisign -- verifier-web/` returns
**zero files**, and the live page fetched from `https://antseal.org/` contains
the string `minisign` **0** times. The `<footer>` exists (`:130-147`) with three
`<p>` elements — `#build`, `#advice`, `#page-build` — and no key element and no
marker pair. So `README.md` has a named locus (D150 §2 R3 item 3) and the page
footer has none. `crates/antseal-wasm/tests/page_template.rs` asserts that
directory holds *exactly* `index.template.html`, so the element can only go into
that template.

### 1.7 The machine the key is actually on

```
command -v minisign        -> /usr/bin/minisign      (REAL_EXIT=0)
dpkg -l minisign           -> ii  minisign  0.11-1  amd64
/var/log/dpkg.log          -> "2026-08-19 12:31:19 status installed minisign:amd64 0.11-1"
ls -ld ~/.minisign         -> drwx------ deb deb  /home/deb/.minisign   (created 12:37)
id -un / id -u             -> deb / 1000
stat -c '%U' <working tree> -> deb
```

The key was **not** read and no `minisign` command was run by this lane; the
directory's own metadata and the package database are the whole measurement.
Three consequences, in order of how load-bearing they are:

1. **`maintainer-key-procedure.md` §6's tool pin was executed.** The installed
   package is `0.11-1` from the Debian archive — exactly §6's chosen version and
   source. That is the ruling working, and no site records it.
2. **Five tracked sites now assert something false**: `D71:174` and `:669`
   (*"No signing or verifying tool is installed on this machine"*, which is
   **§2 R12's stated premise**), `D150:15`, and the `Q22`/`Q30` rows at
   `TODO.md:811` and `:819`.
3. **`key-custody.md` §2's *"Never"* row does not describe this environment.**
   It forbids CI runners, GitHub Actions secrets, KMS, *"any file this
   repository tracks"* and online backups. The actual situation — the secret key
   in the home directory of the account that autonomous agents execute as, on
   the machine holding the working tree — is not in that list, and
   `maintainer-key-procedure.md:12-14`'s warning is about *pasting* a secret into
   an agent-readable terminal, which is a different act.

   **What bounds it is D71 §2 R7.1.** The key is `Sc`-wrapped at libsodium's
   `SENSITIVE` scrypt parameters, so a read yields a blob and not an identity —
   which is `key-custody.md` §2's own reason 1 (*"An unencrypted key is a
   plaintext Ed25519 secret at rest on the maintainer's machine"*) turning out to
   defend against a threat nobody had written down. **Nothing bounds a delete or
   an overwrite, and §1a step 1's two offline backups do not exist**, so today
   the project's signing identity has exactly one copy and it is on a shared-use
   machine. That is the concrete cost of the outstanding backup act, and it is
   larger than "a rule is unmet".

### 1.8 Records whose reasoning depends on the key's absence, one verdict each

| record | the dependence | verdict |
| --- | --- | --- |
| **D150 §1.2** (*"the 56-character public key \| DOES NOT EXIST"*), **§1.4**, **§3.2**, **§4.2** | measurements dated 2026-08-18 | **SURVIVES as dated narration.** One table row and the `minisign`-not-installed clause have since changed. Dated addendum at the site; no ruling moves. |
| **D150 §2 R3 item 3** (*"one sentence … stating that no key exists yet"*) | mandates copy that is now false | **AMENDED** by §2 R3 below. The rest of R3 — items 1, 2, 4, 5 and the rule itself — **survives**, re-tested in §1.5. |
| **D150 §1.3's gloss** (`:141-143`), *"performed **at the moment the key exists**"*, and **§2 R2's** *"When the key act is taken, §5 step 1 inserts the key"* | states the trigger for §5 step 1 | **FALLS.** This is the sentence the register's lean is made of. §5's trigger is not the key's existence; §A R4 makes it the `TXT` pin. D150 was reasoning about *ownership* (whose row edits the README) and its answer to that is untouched; its aside about *timing* was not measured and is wrong. |
| **D141 §2 R3** (`:231-233`), *"The one field Q22 genuinely cannot write before Q30 is that 56-character public key"* | a key is not a record | **SURVIVES.** The field still cannot be written — now because publication is gated, not because the datum is absent. The edge it preserved was struck by D150 §2 R1 on other grounds and stays struck. |
| **D71 §2 R12** (`:669`) and **§1.2** (`:174`) | *"No signing or verifying tool is installed on this machine"* | **PREMISE FALSE; RULING SURVIVES.** R12's instruction was *"Q30 must rule provisioning"*; Q30 did, and the pin has now been executed. Dated addendum. |
| **D71 §2 R7.1** (the `-W` ban) | none — it never depended on absence | **SURVIVES, STRENGTHENED.** §1.7 supplies the threat model. Dated addendum recording it. |
| **D71 §A R4 / §A R5 / §A R6** | none | **SURVIVE UNCHANGED.** §A R4 is what decides this record. |
| **D72 §2 R6** (*"R5 is INOPERATIVE while the repository is private"*) | repository visibility | **SURVIVES.** Re-measured 404 today. |

### 1.9 Defects found on the way, all measured, none of them this record's subject

1. **D150 §2 R2's mandated Notes text landed in no entry.** `tasks/Q.md:523`
   carries it, and `:522` is blank while `:524` is `### Q30 —`. It sits after
   Q29's bullet list, separated from it by a blank line, and immediately before
   Q30's heading — so an `awk` walk over `### `-delimited blocks attributes it to
   **Q29**, whose entry then has three `- Notes:` bullets, one of them entirely
   about Q30. R2's own text said *"in `tasks/Q.md` Q30's Notes (the entry, not
   the checkbox line — the wave-24 follow-up's own lesson)"*. `git blame` puts it
   in `28afe38`, this wave's predecessor.
2. **`maintainer-key-procedure.md:240` cites the wrong step and the wrong
   section.** It says *"**§1 step 3 is NOT complete**: the two offline backups
   have not been made, and §4 forbids signing until they are."* Measured against
   `:70-77`: the backups are **step 1**; step 2 is recording the passphrase;
   **step 3 is adding the `key-custody.md` §10 row, and step 3 IS complete**
   (`key-custody.md:208`). And a bare *"§4"* inside this file reads as its own §4,
   *Sign a release*, which forbids nothing; the prohibition is `:70`'s
   *"Then, before signing anything:"*, and `key-custody.md` §4 is the rule that
   defines the backups. The brief inherited this error verbatim.
3. **`maintainer-key-procedure.md:154` now reads as satisfied.** §4 opens
   *"Once §1 is done, this is the routine act"*. §1's generation is done; §1a's
   backups are not. The one sentence a maintainer would check before signing now
   says yes.
4. **`key-custody.md` §10's first row was written by replacing a row**, in a
   table whose own instruction is *"Never edit a row"* (`:204`). The replaced row
   was `| — | *(no key generated yet)* | — | This table's first row is written on
   the day … |` — scaffolding, not a custody event. The act was right and the
   git history now shows a row being replaced in an append-only log, which is
   the kind of thing a later reader "repairs".
5. **Nothing asserts the `README.md` marker pair still exists.** D150 §4.3 named
   this and §3.7 refused to mint a test for it under rule 8. It is now more
   load-bearing, not less: §5 step 1 writes into a locator nothing pins.

---

## 2. Ruling

### R1 — §5 does NOT fire. The order is §1 → §1a(1,2) → §3 → §2 → §5, and *"alongside §2"* is replaced with wording that cannot be read the other way

**Who: nobody executes §5 today.** The registrar makes the wording change.

The README key insertion is **not due**. Writing the key into any of §5's
locations is the first publication of the key, and D71 §A R4 rules that this is
the moment the `TXT` pin's clock starts and the moment a first user pins. §2
does not exist. The four publication locations change **in one act**
(`key-custody.md` §6 step 4), and that act begins with §2, not with §5.

`docs/signing/maintainer-key-procedure.md:177` — replace `After §1 and alongside §2:` with, exactly:

```
**After §1 and §3, and never before §2.** *"Alongside §2"* was the original
wording, and it is the ambiguity this section is now explicit about: writing the
key into any location below **is** the first publication of the key, and D71 §A
R4 rules that the `TXT` pin's clock *"starts the moment the key is first
published"*. The `TXT` record therefore exists before the first of these three
is written, rather than at the same time as an afterthought (D153 §2 R1).
```

**This changes no deadline and creates no new wait.** §3 is release-timed by §A
R4 and §2 follows it; §5 was already behind both. What it removes is the reading
under which §5 step 1 could be taken alone, today, by someone quoting *"After
§1"*.

### R2 — Status is written in exactly ONE place, and it is `maintainer-key-procedure.md` §7. Every other page in `docs/signing/` and `README.md` points at it and asserts none

**Who: the registrar.** Four replacements, all measured green in §1 of this
record's verification.

**The rule, stated so the next state change needs no decision:**

> A statement that carries its own date is true forever and is **appended**. A
> statement about *now* goes false silently and is **not written** outside the
> one section that owns it. In `docs/signing/`, that section is
> `maintainer-key-procedure.md` §7, *"What has and has not been run"*, which is
> **not** append-only and is edited in place each time an act is taken. A page
> may say what **its own copy** is — *"the key below is a placeholder"* — because
> that is a fact about the page. It may not say what the maintainer has or has
> not done.

Applied, the next three state changes cost one edit each and touch no other
page: **backups made** → §7; **`TXT` pin created** → §7, plus §2's own text;
**first release** → §7, plus the §5 cluster. That is the test this rule has to
pass and it passes it.

**(a) `docs/signing/key-custody.md:9-13`** — replace the banner with, exactly:

```
> **This document states rules, not progress.** Custody events — generation,
> rotation, backup verification, suspected compromise — are logged in §10 of
> this document, one appended dated row each. What the maintainer has and has
> not yet run is recorded in exactly one place, and it is not this file:
> [`maintainer-key-procedure.md`](maintainer-key-procedure.md) §7.
```

This repairs the false status **and** the `§7`→`§10` pointer in one act, because
the pointer's cause was conflating the two things this sentence now separates.

**(b) `docs/signing/README.md:29-32`** — replace with, exactly:

```
> **What has and has not actually been run is recorded in exactly one place:**
> [`maintainer-key-procedure.md`](maintainer-key-procedure.md) §7. No other page
> in this directory states it, so no other page goes stale when the maintainer
> takes an act.
```

The deleted *"Nothing here has been used on a real release"* is true today and
is dropped **deliberately**: it is a status claim that goes false at first
release with nobody assigned to notice, which is this record's whole subject.
The second sentence is not decoration — it tells the next editor why the page
carries no status.

**(c) `docs/signing/maintainer-key-procedure.md:3-6`** — replace with, exactly:

```
Three acts here are **external**: they touch the maintainer's own machine, the
domain registrar account, and a public timestamp calendar. **No agent performs
any of them**; §7 records which have been performed and which have not. Each
needs the maintainer's own terminal and, for §2, express in-the-moment consent
at the registrar.
```

The agent prohibition is permanent and stays; only the status clause goes.

**(d) `README.md:51-53`**, inside the anchor D150 §2 R3 item 3 mandates —
replace with, exactly:

```
No key is published here yet. The 56-character public key goes between these
two markers when it is published, alongside a pointer to
[checking a download](docs/signing/verifying-a-release.md).
```

The markers and the pointer are D150 §2 R3 item 3's and are preserved verbatim.
The sentence now states what **this file carries**, not what the maintainer has
done, so it survives the backups act and the `TXT` act untouched and changes
exactly once — when §5 fires.

### R3 — D150 §2 R3 is AMENDED in one clause and re-affirmed in the rest, with the key operand narrowed to *obtainable by the reader*

**Who: the registrar**, as a dated addendum at D150's own site — never an edit to
another record's §1 or §2 (D150 §3.8's own discipline).

1. **Item 3's mandated sentence** — *"stating that no key exists yet"* — is
   replaced by *"stating that no key is **published here** yet"*. §2 R2(d) is the
   copy that satisfies it.
2. **Items 1, 2, 4, 5 and the rule itself stand**, re-measured in §1.5. No
   `minisign -H -Vm …` block in `README.md`: three of four operands are still
   absent and the page a reader would be sent to still returns **404**.
3. **The key operand's test is *obtainable by the reader*, not bare existence.**
   R3's own first sentence — *"a command block in product copy is a promise that
   it runs"* — is what forces this: a key that exists on one machine and is
   published nowhere makes the promise false in the same way an absent key does.
   Recorded so no future wave re-derives it from the word "exists".
4. **D150 §1.3's gloss and §2 R2's closing sentence FALL** on their timing claim
   only (§1.8). Their ownership finding — §5 step 1 is Q30's act on Q22's file,
   both `after:` directions forbidden — is untouched and is re-affirmed here.

### R4 — The two offline backups gate §3, not merely §4, and the reason is the anchor rather than the signature

**Who: the maintainer** performs it; **the registrar** writes the precondition.

`docs/signing/maintainer-key-procedure.md:70` — replace `Then, before signing anything:` with, exactly:

```
Then — **step 3 immediately, and steps 1 and 2 before §3, not merely before §4**:
```

and append, after item 3 of that list, exactly:

```
**Why steps 1 and 2 gate §3 and not only §4** (D153 §2 R4): §3 anchors *this*
key, and an anchor cannot be transferred to a replacement. D71 §A R4 puts the
anchor in a narrow window — *"a few days before the release date"* — so a key
lost after §3 and before the release costs the anchor **and** the window on top
of the regeneration. Loss is the failure `key-custody.md` §5 calls the cheap one
*because* published signatures survive it; before §3 there is nothing to survive,
and the backups are what keep it cheap. §1.7 of D153 is the measurement that
makes this concrete rather than theoretical: today the key has exactly one copy,
on a machine that is not dedicated to it.
```

**This is a new precondition and it costs nothing**, because §3 is release-timed
and §5 is behind §2 which is behind §3. It moves an act the maintainer already
owes to the earliest point at which its absence becomes expensive.

### R5 — §7 is corrected: the wrong step number, the wrong section, and the timing claim that flattens §A R4

**Who: the registrar.** Replace both bullets of
`docs/signing/maintainer-key-procedure.md` §7 (`:236-244`) with, exactly:

```
- **§1 RUN 2026-08-19.** The project key exists — key id `3E5D46890F192F58`, KDF
  field `Sc`, at `~/.minisign/` on the maintainer's account, logged as the first row
  of [`key-custody.md`](key-custody.md) §10. The §1a checks were re-run there after
  the move described in §1 and all three pass. **§1a step 1 is NOT complete: the two
  offline backups have not been made**, and §1a's own preamble — *"Then, before
  signing anything"* — is what forbids §4 until they exist; `key-custody.md` §4 is
  the rule that defines them. **§1a step 3 (the `key-custody.md` §10 row) IS
  complete**, and §1a step 2 is the maintainer's to state.
- **Not run: §2 and §3.** `dig +short TXT antseal.org` still returns empty — the
  zone has no `TXT` records at all — and nothing has been anchored. **They are
  timed differently, and D71 §A R4 says so in its own heading**: *"both deferrable
  items share one property, and it decides them differently"*. §3, the anchor, is
  release-timed — *"stamp a few days before the release date"*, not now and not
  after. §2, the `TXT` pin, is **not** release-timed: §A R4 rules that its clock
  *"starts the moment the key is first published"* and calls it *"the one that
  should not be deferred"*, and §A R5 clause 3's *"before first release"* is its
  outer deadline rather than its schedule. Neither is overdue, because the key is
  published nowhere yet — and §5 may not publish it until §2 exists.
```

The same correction is owed at the two other sites that carry the flattened
claim — `TODO.md:819` and `tasks/Q.md` Q30's Notes — and §5 quotes the
replacement text for each.

### R6 — `key-custody.md` gains a §11, and the banner replacement is recorded there. Append-only binds §1–§10; the masthead is not normative

**Who: the registrar.** Append to `docs/signing/key-custody.md`, exactly:

```
## 11. Amendments to this document

§1–§10 are append-only: a normative rule changes by a dated entry here, never by
a silent edit above it, and §10's rows are never edited at all. Every amendment
is recorded below with the text it replaced.

- **2026-08-19 — the top-of-file status banner was replaced, and it is the last
  status this file will carry** (D153 §2 R2). It read: *"**STATUS, 2026-08-18: no
  key exists yet.** Nothing in this document has been executed against a real
  project key. The keypair is generated by the maintainer following
  `maintainer-key-procedure.md`, and the first line of §7's log records the day
  that happens. Until then every statement here is a rule, not a description."*
  Two defects with different causes. The first clause went **false** when the
  maintainer generated the key on 2026-08-19 (§10's first row). The pointer to
  *"§7's log"* was **never true**: this file has had exactly one commit, and in it
  §7 was already *Compromise response* and the log was already §10 — the sentence
  merged the log in this file with the run-status section in
  `maintainer-key-procedure.md` into one reference that fitted neither. The
  replacement names both, each in the file that owns it, and asserts no state of
  its own.
- **2026-08-19 — §10's first row replaced a placeholder row, and that is not an
  edit to a custody record.** The replaced row read
  `| — | *(no key generated yet)* | — | This table's first row is written on the
  day the maintainer runs `maintainer-key-procedure.md` §1. |`. It logged no
  custody event; it was table scaffolding. Recorded because the git history
  otherwise shows a row being replaced in a table whose §10 says *"Never edit a
  row"*, and a later reader should not try to "repair" it. **No placeholder row
  is written into this table again** — an empty log is an empty log.
```

**The scope ruling, stated generally:** append-only binds §1–§10 — the normative
rules and the log — and every change to them is a dated §11 entry. **The masthead
is outside it**, because a masthead describes the document rather than the key,
and under §2 R2 it now carries no state at all, so §11 is expected to hold these
two entries and no more until a normative rule changes.

### R7 — §5's list is completed with the two locations it does not name

**Who: the registrar** writes it; **the maintainer** executes it when §5 fires.

Insert into `docs/signing/maintainer-key-procedure.md` §5, immediately before
`**What the wording in those places may not say**`, exactly:

```
**Two locations this list does not name, both measured missing 2026-08-19.**

- **`verifying-a-release.md` carries the placeholder three times** (`:12`, `:35`,
  `:92`), behind its *"Not yet published"* banner at `:10-14`. It is not one of
  the four pins — which is why it may carry a placeholder at all (D150 §2 R3
  item 2) — but it is the one page a stranger actually follows, so replace all
  three and delete the banner in this same act.
- **The page footer has no key element and no marker to write into.**
  `verifier-web/` holds exactly one file and carries the word `minisign` zero
  times; the live page returns the same. The element is added to
  `verifier-web/index.template.html` and to nothing else, because
  `crates/antseal-wasm/tests/page_template.rs` asserts that directory holds
  exactly `index.template.html`.
```

**`verifying-a-release.md` is not otherwise changed by this record.** Its banner
is **true today** and is the one status statement in the corpus that survived
this state change, for the reason §1.2 gives. §4 names it, with its trigger.

### R8 — Q65's flip may not carry an unpublished key into publication, and Q254's checklist says so

**Who: the registrar**, in `Q254`'s entry.

While `README.md` carries no key this is a statement about a hazard rather than a
constraint; the moment §5 fires it becomes load-bearing, and `Q254` is the only
ordered procedure for the flip. Add to `Q254`'s `Do`, in substance:

> **[D153 §2 R8, 2026-08-19.]** Before the visibility flip, read
> `README.md`'s `<!-- BEGIN minisign-public-key -->` anchor. **If it carries a
> key, the flip is that key's first publication** and D71 §A R4's precondition
> applies to *this* step: `dig +short TXT antseal.org` must return the
> `antseal-minisign-key=` record first. If the anchor carries no key — its state
> on 2026-08-19 — record that read-back and proceed. This step exists because the
> publishing act and the key-publishing act are owned by different rows and only
> one of them knows about the pin.

### R9 — The environment the key is in is recorded at D71, and the outstanding maintainer acts get a visible marker

**Who: the registrar** writes the addendum and mints the rows; **the maintainer**
performs the acts.

1. **A dated addendum at `docs/decisions/D71-…`** recording §1.7: `minisign
   0.11-1` installed 2026-08-19 (so §1.2's and §2 R12's premise is stale and §6's
   tool pin has been executed); the secret key at `~/.minisign/` on the account
   agents execute as; and that **§2 R7.1's `-W` ban is what bounds it** — a threat
   model the ban did not state when it was written. It is an addendum, not an
   edit: no ruling in D71 moves.
2. **`key-custody.md` §2's *"Never"* row does not describe this machine, and
   whether it should is a question this record routes rather than answers** (§4).
   A custody rule written against an environment nobody measured is the class of
   defect this project keeps finding; the measurement is now on record and the
   rule can be written against it.
3. **The outstanding maintainer acts get a row of their own.** D150 §4.2 named
   this and left it to the registrar; it is still un-minted, and this wave is the
   second in which the tracker's only visible statement about them is prose
   inside another row's Notes. The three are: **§1a steps 1–2** (the two offline
   backups and the passphrase record — **now blocking §3 by §2 R4**, and
   therefore Q30 Accept rows 2 and 3), **§2** (the registrar `TXT` record,
   external, express consent), and **§3** (the OTS anchor, release-timed). §5
   describes what to mint; **this record assigns no id.**

---

## 3. What was refused and why

1. **The lean's operative half — "§5 step 1 fires, write the key now" — refused
   on D71 §A R4 and on `maintainer-key-procedure.md:8-10`, two independent
   sites, neither of which the lean quoted.** The pin's clock starts at first
   publication; publication is what it gates. Taking §5 today would put the key
   into the world with §2 R5's "different control plane" column empty, which is
   the exact condition `key-custody.md` §9's block exists to make impossible to
   overlook.
2. **"The repository is private, so writing the key publishes nothing" —
   refused, and this is the arm that decides it.** The README's publication
   moment is **`Q65`'s flip**, not the commit. `Q254` is the flip's ordered
   procedure and names no key. Writing the key today hands D71 §A R4's most
   consequential moment to a row that has no reason to check for it, with no
   marker anywhere. §2 R8 closes it for the case where a future wave writes the
   key first anyway.
3. **Deleting the `README.md` anchor rather than filling or correcting it —
   refused, though it is the arm most worth taking seriously.** The prose inside
   it *is* a status statement, which §2 R2's rule is otherwise hostile to. It
   survives because of the distinction that rule turns on: *"No key is published
   here yet"* is a fact about **this file's contents**, in the same class as
   `verifying-a-release.md:10`'s *"the key below is shown as a placeholder"* —
   not a claim about what the maintainer has done. Deleting it would also strip
   the pointer to `verifying-a-release.md` that D150 §2 R3 item 3 mandates, at
   the exact spot a reader looks for a key, and leave a bare comment pair that
   reads as a formatting artifact. **Refused on the rule, not on D150's
   authority** — an arm that only survives because an older record said so is an
   arm nobody re-tested.
4. **"The correct locus is `maintainer-key-procedure.md` §7 alone, and nothing
   else changes" — refused as half a ruling.** §7 *is* the locus, and §2 R2 makes
   that a rule rather than an accident. But four false statements stand in front
   of it, in files a reader meets first, and a reader who never reaches §7 is
   the reader the copy is for.
5. **Correcting the banners in place with a newer status — refused as the
   mechanism that guarantees a wave 28 of this.** Every corrected banner would go
   false again at the backups act, again at the `TXT` act and again at first
   release, in three files, with nobody assigned. The measured proof that the
   alternative works is `verifying-a-release.md:10-14`, which needed no edit
   today.
6. **Treating the `§7`→`§10` pointer as an append-only question — refused on
   measurement.** `git log --follow` returns one commit; the pointer was wrong
   inside it. Append-only protects a superseded state and there is none, so the
   repair is in place and §2 R6 records it for the reader who wonders why.
7. **Editing D150's or D71's §1/§2 in place — refused.** The project's
   discipline is amendment by dated addendum at the site, which D150 §3.8 states
   about this exact situation. §2 R3 and §2 R9 route addenda; no ruling in either
   record is rewritten.
8. **Calling the `TXT` pin "overdue" — refused, and so is calling it
   "release-timed".** It is neither. Its trigger has not occurred (nothing is
   published), and its deadline has not arrived (no release date). §A R4's
   heading is explicit that the two deferrable items are decided *differently*,
   and every wording in §2 R2 and §2 R5 keeps them apart.
9. **Minting a lint for "a status claim outside §7", or a test for the README
   marker pair — both refused under rule 8 / D125.** Their subject is the
   apparatus; neither blocks a ship-path acceptance; D150 §3.7 refused the second
   of them yesterday on the same grounds. The measurements go to §4 so an
   instrument wave starts from evidence.
10. **Reading, running or otherwise touching anything under `~/.minisign` beyond
    the directory's own mode and owner — refused as out of bounds.** §1.7's
    measurement is `command -v`, `dpkg`, `/var/log/dpkg.log` and `ls -ld`. No
    `minisign` invocation was made by this lane, and the key id in this record is
    quoted from `key-custody.md` §10, not derived.
11. **Asserting the `TXT` result from a second resolver — refused as
    unmeasured.** The probe failed to reach `1.1.1.1` at all. Reporting its line
    count would have claimed four `TXT` records where there are none.

---

## 4. Residue

1. **`docs/signing/verifying-a-release.md` is the last status claim outside §7,
   and it is left standing deliberately.** *"antseal has not made its first
   release"* is true, is the warning that makes its placeholder legible, and
   would be worse copy as a pointer into a maintainer-only document. **Its
   trigger is §5**: §2 R7 puts its three placeholders and its banner into the
   same act that publishes the key, so it cannot outlive its truth. Named here
   so it is not mistaken for an oversight.
2. **Whether `key-custody.md` §2's *"Never"* row should name the machine class
   §1.7 measured is a real question this record does not answer.** It is a
   normative custody rule, it would be a §11 amendment, and it wants the
   maintainer's own view of how the machine is used — not a planning lane's
   inference from `id -u`. §2 R9 routes it; the measurement is on record.
3. **The `README.md` marker pair is still unverified by any instrument** (D150
   §4.3). §2 R2(d) writes into it and §2 R8 makes `Q254` read it, so it now has
   two readers and still no test. Refused under rule 8, recorded a second time.
4. **`maintainer-key-procedure.md:154`'s *"Once §1 is done"*** (§1.9 item 3) is
   left unrepaired. §2 R5's replacement bullet states the backup gate two
   sections away, and §2 R4 states it at §1a, so the reader who follows either
   path is warned; the §4 sentence itself is narration and repairing it is a
   wording call the Q30 lane can take in the same act. Flagged, not ruled.
5. **The passphrase-storage instruction has no referent anywhere in the
   project** — *"generated and stored the way the antseal vault passphrase is"*
   (`key-custody.md:55-56`, `maintainer-key-procedure.md:52-53`). The maintainer
   found this while executing §1 and already recorded that it *"needs a row"*
   (`tasks/Q.md` Q30 Notes). **Not duplicated here**; §5 asks the registrar to
   mint it rather than leave it in prose, because §1a step 2 now sits inside §2
   R4's gate on §3.
6. **Nothing in this record establishes what a maintainer act's completion looks
   like to a reader who is not the maintainer.** §7 is a prose bullet the
   maintainer edits; no read-back command proves the backups exist, and none
   could without describing where they are. The gap is real and is not closed by
   any wording here.

---

## 5. Registrar's edit set

Quotable instructions with their targets. Items marked **(maintainer)** are
external acts no agent takes. **Every replacement below was verified against the
tree**: the fixture script asserts each quoted "before" string is present before
substituting, and it raised on none of them.

**Verification this record performed, reported as output rather than as a
claim.** Candidate copy was run through the **real** lint, not a paraphrase of
it. Per-string, on `check_banned` + `check_spellings` + `check_url`: **0
findings** across all six candidates, `PRODUCT_URL.findall()` returning `[]`
except for the one deliberate `<https://antseal.org/>`, which matched the
canonical value exactly. Then every edit in items 1–8 was applied to a staged
copy of the corpus outside the repository and the real `check()` run over it:

```
files scanned : 26
notices       : 0
FINDINGS      : 0
VERDICT: GREEN
```

**And the check was proven able to fail**, because a green that nothing could
redden is not a measurement: `notarises` planted inside the new anchor →
`[P1] README.md:51`, **1 finding, RED**; the `seal-before-you-share` clause
mutated → `[P7] README.md … does not state the required clause` plus a `[P2]`,
**2 findings, RED**; restored → **0, GREEN**. The four standalone plants (P1,
P2, P3, P6) each fired one finding. The real tree was not modified and
`python3 scripts/check-copy-style.py` at HEAD after all of it is still
`REAL_EXIT=0`, 26 files, 0 debts. **The implementer re-runs the flagless lint and
reports its output** (D139 §2 R6).

1. `README.md:51-53` — replace with §2 R2(d)'s exact text. The two marker
   comments at `:50` and `:54` are **not touched**; `README.md:7-9`'s positioning
   paragraph is **not touched** (D150 §2 R4's warning still stands).
2. `docs/signing/key-custody.md:9-13` — replace the banner with §2 R2(a)'s exact
   text.
3. `docs/signing/key-custody.md` — append §2 R6's `## 11. Amendments to this
   document` section, both entries, at the end of the file.
4. `docs/signing/README.md:29-32` — replace with §2 R2(b)'s exact text.
5. `docs/signing/maintainer-key-procedure.md:3-6` — replace with §2 R2(c)'s exact
   text.
6. `docs/signing/maintainer-key-procedure.md:177` — replace
   `After §1 and alongside §2:` with §2 R1's exact text.
7. `docs/signing/maintainer-key-procedure.md` §5 — insert §2 R7's block
   immediately before `**What the wording in those places may not say**`.
8. `docs/signing/maintainer-key-procedure.md` §1a — replace `:70`'s
   `Then, before signing anything:` and append the rationale after item 3, both
   per §2 R4.
9. `docs/signing/maintainer-key-procedure.md` §7 (`:236-244`) — replace both
   bullets with §2 R5's exact text.
10. **`tasks/Q.md:523` — MOVE the dangling `- Notes: **[D150 §2 R2, 2026-08-19.]**`
    bullet into Q30's entry**, after Q30's existing `Notes` bullets, and delete
    the now-doubled blank line. It currently sits between Q29's block and Q30's
    heading and belongs to neither (§1.9 item 1). **In the same act, amend its
    closing sentence** — *"When the key act is taken, §5 step 1 inserts the key
    into the anchor D150 §2 R3 requires Q22 to leave"* — to read, in substance:
    *"**[D153 §2 R1/R3, 2026-08-19.]** The trigger is **not** the key's existence,
    which arrived 2026-08-19 without §5 becoming due. §5 step 1 fires only after
    §2's `TXT` record exists (D71 §A R4: the pin's clock *'starts the moment the
    key is first published'*), and it writes into the anchor D150 §2 R3 requires
    Q22 to leave."*
11. `tasks/Q.md` Q30's Notes (the 2026-08-19 bullet) — two corrections: replace
    *"§1 step 3's two offline backups"* with **"§1a step 1's two offline backups
    (step 3, the `key-custody.md` §10 row, is complete)"**, and replace
    *"§2's `TXT` pin and §3's OTS anchor are held by D71 §A R5 clauses 3 and 4"*
    with **"§3's OTS anchor is release-timed by D71 §A R5 clause 4; §2's `TXT`
    pin is **not** — §A R4 starts its clock at the key's first publication and
    calls it *'the one that should not be deferred'*, with *'before first
    release'* as its outer deadline (D153 §2 R1/R5)"**. Add: **"`minisign 0.11-1`
    is now installed on this host (2026-08-19 12:31), executing §6's tool pin."**
12. `TODO.md:819` Q30's row — the same two corrections as item 11, plus striking
    *"`minisign` is **not installed** on this host (apt candidate `0.11-1`)"*,
    which is now false.
13. `TODO.md:811` Q22's row — it carries the clause too, measured: *"`dig +short
    TXT antseal.org` is empty, **`minisign` is not installed**, and
    `maintainer-key-procedure.md` records §1–§3 as not run"*. All three are now
    wrong or half-wrong: the first is still true, `minisign` **is** installed, and
    §1 **has** run. This passage is *narration of what D150 measured on
    2026-08-18*, so amend it by dated qualifier rather than rewriting it — the
    finding it supports (a key is not a record) is unaffected.
14. `TODO.md` decision register — add the **D153** row, ticked, naming Q30 as the
    owning task. `[decisions]` requires every allocated id to have a home in the
    same act.
15. `docs/decisions/README.md` — add the **D153** index row in ascending id
    order, four cells, with `RESOLVED` and `2026-08-19` copied from this record's
    own `- **Status`/`- **Date` lines. **Measured, not predicted:** with this
    record in the tree and no index row, `python3 scripts/check-traceability.py`
    is **`REAL_EXIT=1`, one problem** — `::error::check-traceability
    [decision-index] docs/decisions/README.md: D153 has a record … and no row in
    the index`. `[decisions]` stays **ok** at 152 allocated ids, because an
    unregistered id is not yet an allocation; it turns into the second stage the
    moment item 14 lands without item 15, and vice versa. **Items 14 and 15 are
    one act with the commit of this record**, which is D119 RULING 6 and what the
    error message itself says.
16. `docs/decisions/D150-q22-release-docs-preconditions.md` — **append** a dated
    addendum (never an edit to its §1 or §2): §1.2's key row and §1.4's key clause
    changed on 2026-08-19; §1.3's *"performed at the moment the key exists"* and
    §2 R2's closing sentence **fall** on their timing claim, ownership finding
    intact; §2 R3 item 3's mandated sentence is amended per D153 §2 R3; the rest
    of R3 is re-measured and stands; §3.2's *"minisign is not installed here"* is
    stale; §4.2's three untaken acts are now two-and-a-part.
17. `docs/decisions/D71-binary-signing-mechanism-and-key-custody.md` — **append** a
    dated addendum per §2 R9 item 1: §1.2's and §2 R12's *"No signing or verifying
    tool is installed on this machine"* is false as of 2026-08-19 12:31; §6's tool
    pin has been executed at the pinned version; the secret key is at
    `~/.minisign/` on the account that also owns the working tree, and **§2 R7.1's
    `-W` ban is what bounds that** — recorded because the ban did not state this
    threat model. No ruling moves.
18. `Q254`'s entry — add §2 R8's step, in substance, to its `Do`.
19. **Mint, ids assigned centrally:** (a) a row making the outstanding
    **maintainer-only** acts visible in the tracker rather than in another row's
    Notes — §1a steps 1–2 (blocking §3 by D153 §2 R4, and Q30 Accept rows 2–3),
    §2 (registrar `TXT`, external, express consent), §3 (OTS anchor,
    release-timed) — per §2 R9 item 3 and D150 §4.2, which asked for it a wave
    ago; (b) the passphrase-storage instruction with no referent (§4.5), which the
    maintainer has already asked for; (c) the page footer's missing key element
    and missing marker (§1.6b), owned wherever `verifier-web/index.template.html`
    is owned. **(maintainer)** for (a)'s acts.
20. `docs/instrument-ledger.md` — two findings, neither minted as a row under
    rule 8: the `README.md` marker pair has two readers and no test (§4.3); and
    nothing in the corpus can detect a status claim written outside
    `maintainer-key-procedure.md` §7, which is the rule §2 R2 establishes and
    which is enforced today only by this record.
21. `docs/signing/key-custody.md` §10 — **not touched.** Its first row is a dated
    custody record and is true as of its date; §2 R6's second §11 entry explains
    why the placeholder it replaced was not a row.

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
