# D139 — The M4 documentation venue, and how the copy lint admits it: one subtree, two register lines, and a threat-model promotion that cannot be built

> **AMENDED 2026-08-17 — READ THE ADDENDUM BEFORE §2 R10, AND BEFORE FOLLOWING
> ANY LINE NUMBER INTO `docs/threat-model.md`.** Two corrections, both produced
> by the same wave that wrote this record. **(1)** §2 R10's sentence *"the README
> edit that carries it is Q22's"* is **superseded by D140 §2 R1 and §2 R7**, ruled
> later the same day, which put the `## Documentation` section on the
> README-currency row (`Q248`, landed this wave) precisely because `Q22` is
> ordered *after* the publication a true front door has to survive. **(2)** Every
> one of this record's **28** line-number locators into `docs/threat-model.md` was
> invalidated by Q21, the work this record exists to enable — the file grew
> 595 → 2 088 lines. The rulings are untouched by both. See **§C**.

- **Status: RESOLVED. All three clauses of the briefed lean are OVERTURNED, each on a
  measurement taken against the real `scripts/check-copy-style.py` in this
  repository.** The lean was *"each page is a new depth-1 `docs/*.md` file; each is
  added individually to `COPY_SCAN` and classified `PRODUCT` in
  `DOCS_CLASSIFICATION`; `docs/threat-model.md` flips `ENG` → `PRODUCT` when Q21
  finalizes it."*
  - **Clause 3 is overturned hardest, and it decides the record.** Flipping
    `docs/threat-model.md` to `PRODUCT` today reds the lint on **three** rules
    (§1.2). Two of the three are Q21's to fix. **The third is not, and cannot be**:
    `docs/threat-model.md:393` reads *"**What breaks if it is false.** Authorship
    binding."* — a P3 with no disclaimer in its sentence — and line 393 sits inside
    the **byte-frozen** block at lines 39–408 that Q21's *own* `Accept` clause
    forbids it to touch (*"assumptions block still verbatim"*). Measured: repair the
    two fixable defects and the flip is **still RED** (§1.2, experiment E8). Under
    the lean's reading, **the two halves of Q21's own Accept clause — "Q20 lint
    passes" and "assumptions block still verbatim" — are mutually unsatisfiable.**
    The mechanism is unbuildable, not merely expensive.
  - **Clause 1 is overturned on a priced comparison, not a preference.** Both venues
    were built end-to-end in a scratch mini-repo and both pass `--self-test` with all
    six pages proven READ (§1.4). They differ in the register: **12 edits versus 2**,
    in a file six parallel lanes share — and in an **ordering trap that is two-sided
    and per-page** at depth 1 (`P0` if the entry lands first, `P8` if the file lands
    first) versus **one-time** for a subtree (§1.5).
  - **Clause 2 follows.** The venue is **`docs/user/`**: one `COPY_SCAN` directory
    entry, one `DOCS_CLASSIFICATION` subtree entry, and every page that lands in it
    afterwards is scanned from its first commit with **no register edit at all**
    (E4, E5, ORD-3).
- **A fourth finding the brief did not ask for, and the most expensive one to
  discover late: rules P4, P5 and P6 are fragile against ordinary markdown.**
  The two spec-dictated phrases red when a line wraps inside them (3 of 6 wrap
  positions for P4, 3 of 5 for P5) **and go silently blind to a genuine
  mis-spelling when the wrap falls inside the anchor** (3 of 3, 2 of 2). A live
  instance is in the tree today at `docs/threat-model.md:450`. P6 reds on a
  canonical URL followed by a sentence-ending period. Six documents that must all
  quote the receipt class and print the verifier URL would have met these one at a
  time; §2 R7 turns them into three writing rules instead.
- **Date: 2026-08-17.** *(Captures below are stamped 2026-08-18 in file mtimes: the
  measurement run crossed local midnight. The wave date is unchanged.)*
- **Owning task: Q20** — the lint and its two registers. Executed by **Q21, Q23–Q27**;
  the corpus is inherited by **Q28**.
- Related: D123 (the per-entry literal/directory rule this record applies, and the
  "a scan blind to the file its own row authors" defect), D62 §3 R8 (the canonical
  URL value), D84 §7 / Q37 (the freeze-boundary block Q27 becomes the third copy
  of), D116 (one vocabulary, one place it is written down), D126 §3.2 (the five TSA
  findings Q26's table must carry), D138 (the path-filter record, whose §3 R5
  "every matched file has a `.md` suffix" rule is the guard the copy lint does *not*
  have — §4.4), D109 §3.3 (a record's job includes proposing work), Q181 (the
  unswept-directory gap this venue interacts with), Q49 (gate state is not rule
  text — the same normalisation problem in the boundary lint).

---

## 1. The measurement

### 1.1 The apparatus, and why it is the real thing

Every finding below comes from **the committed `scripts/check-copy-style.py`**, not
from a paraphrase of its patterns. The probe copies the script into a scratchpad and
imports it, then calls its own `check_banned` / `check_spellings` / `check_url` /
`check` / `self_test`:

```
/tmp/.../scratchpad/probe/lint.py        <- byte copy of scripts/check-copy-style.py
/tmp/.../scratchpad/probe/probe.py       <- imports it; runs its rule functions
/tmp/.../scratchpad/mini/                <- a scratch mini-repo, 940 KB
/tmp/.../scratchpad/experiments.py       <- E0-E13, each on a fresh tree + fresh module
```

The probe prints the patterns it loaded, so a stale copy is visible rather than
assumed:

```
probe: NOTARY   = \bnotar(y|ies|ial|ially|is(e|es|ed|ing|ation)|iz(e|es|ed|ing|ation))\b
probe: PRIORITY = \bpriorit(y|ies)\b
probe: AUTHORSHIP = \bauthorship\b|\bexclusive\s+possession\b|\bexclusively\s+possess\w*|\bsole\s+possession\b
probe: PRIORITY_QUALIFIER = seal before you share|outrank
probe: DISCLAIMER = \b(not|never|no|none|nothing|neither|nor|isn't|cannot|can't|without|rejected|banned|forbidden|refused|refuses)\b
```

**The probe was fault-planted before any green was trusted.** A four-violation
specimen fires four distinct rules, each by its message:

```
=== FAULT.md (207 bytes, 10 lines) ===
    hits by rule: {'P1': 1, 'P2': 1, 'P3': 1, 'P6': 1}   total=4
    [P1] FAULT.md:3: 'notary' with no disclaimer in its sentence — …
    [P2] FAULT.md:5: 'priority' with no qualification in its block — …
    [P3] FAULT.md:7: 'authorship' with no disclaimer in its sentence — …
    [P6] FAULT.md:9: 'https://www.antseal.org/' is not the canonical verifier URL. …
```

**The mini-repo reproduces the real tree's verdict exactly**, so an experiment run on
it is evidence about the repository and not about a fixture. Both runs, same day:

```
$ python3 scripts/check-copy-style.py                     # the real tree
check-copy-style: ok — 14 product-copy file(s) across 5 scan root(s) … (P7, 2 registered
debt(s) above), the docs partition (P8, 21 entries) and R18's Class V vocabulary (P9).
REAL_EXIT=0

$ python3 /tmp/.../mini/scripts/check-copy-style.py        # the mini-repo
check-copy-style: ok — 14 product-copy file(s) across 5 scan root(s) … (P8, 21 entries) …
REAL_EXIT=0
```

Same 14 files, same 5 roots, same 21 entries, same 2 debts.

### 1.2 `docs/threat-model.md` today, rule by rule — the charter's sharpest question

The brief asked for a hit count with line numbers, measured rather than reasoned.
**Three findings.**

```
=== threat-model.md (31547 bytes, 595 lines) ===
    hits by rule: {'P2': 1, 'P3': 1, 'P4': 1}   total=3
    [P2] threat-model.md:14: 'priority' with no qualification in its block
    [P3] threat-model.md:393: 'Authorship' with no disclaimer in its sentence —
         Sentence: '**What breaks if it is false.** Authorship binding.'
    [P4] threat-model.md:450: 'no independently proven time' is not spelled as
         MVP-SPEC.md lines 110 and 137 dictates
```

And, run for comparison, `docs/security-assumptions.md` — **one** finding, the same
sentence, at its own line number:

```
=== security-assumptions.md (28427 bytes, 492 lines) ===
    hits by rule: {'P3': 1}   total=1
    [P3] security-assumptions.md:387: 'Authorship' … Sentence:
         '**What breaks if it is false.** Authorship binding.'
```

Placed against the frozen region (§1.3), the three findings split cleanly:

| hit | line | inside lines 39–408? | who can fix it |
|---|---|---|---|
| **P2** | 14 (`## Positioning`) | **no** | **Q21** — this is `docs/positioning-copy-style.md` §11 finding 3 |
| **P3** | **393** | **YES** | **nobody, under Q21's Accept** |
| **P4** | 450 (`## 2.3 Wallet linkability`, a Q21 stub) | **no** | **Q21** |

The whole ruling turns on row 2. **E7** flips the class with the file unchanged:

```
--- E7 threat-model.md flipped ENG -> PRODUCT, file UNCHANGED
    scanned=15  verdict=RED ['P2', 'P3', 'P4']  debts_reported=2
```

**E8** repairs the one defect the guide has already registered against Q21 — §11
finding 3, the unqualified priority claim at line 14 — and re-measures:

```
--- E8 threat-model.md PRODUCT with the §11-finding-3 P2 defect repaired
    scanned=15  verdict=RED ['P3', 'P4']  debts_reported=2
      P3 docs/threat-model.md:394: 'Authorship' with no disclaimer in its sentence
      P4 docs/threat-model.md:451: 'no independently proven time' is not spelled …
```

P4 is Q21's too (§2 R7 says how). **P3 survives every repair Q21 is permitted to
make.** That is the measurement the charter asked for, and it decides §2 R3.

**Answering the charter's sub-question directly: can Q21 discharge
`docs/positioning-copy-style.md` §11's registered defect, or does it survive?**
It has two halves and they part company.

- **The defect itself — dischargeable.** §11 finding 3 records that line 14 *"claims
  priority unqualified … its block never says an earlier seal outranks a later one"*
  and ends *"Q21 owns it."* Line 14 is outside the frozen block; adding the spec's own
  qualification to that block clears it. Measured — the specimen with the
  qualification added goes green:

  ```
  [Q21] the same claim with the spec's own qualification added          -> green
  ```

- **The conclusion §11 and §12 drew from it — does not survive.** Guide §12 item 3
  (`docs/positioning-copy-style.md:309-310`) reads *"`docs/threat-model.md`'s
  promotion to Class P once Q21 has written it"*. E8 refutes that. The defect goes;
  the promotion it was recorded as unblocking does not arrive.

### 1.3 What is actually frozen, and by what — because the register's stated reason is wrong

`DOCS_CLASSIFICATION`'s reason for `threat-model.md`
(`scripts/check-copy-style.py:101-106`, for the source doc) says a finding inside the
frozen block is *"unfixable without breaking that drift test"*. **Read literally that
is false, and the difference matters enough to state.**

`crates/antseal-core/tests/security_assumptions_drift.rs` pins the block by
**equality between the two copies**, not by a hash:

- markers `<!-- BEGIN frozen-security-assumptions -->` / `<!-- END … -->` declared at
  `:49-50`;
- `threat_model_carries_the_frozen_block_verbatim` (`:143-185`) compares
  `frozen_block(SOURCE_DOC) == frozen_block(THREAT_MODEL)` and `panic!`s with the
  first differing byte otherwise;
- `both_documents_delimit_a_substantial_frozen_block` (`:221-233`) asserts
  `block.len() > 4_000` on **both** sides, so emptying one cannot satisfy equality.

Searched for a digest pin; there is none:

```
$ grep -rn "frozen-security-assumptions" --include=*.rs --include=*.py --include=*.sh \
      --include=*.yml --include=*.toml .   | grep -v '^./docs/decisions/'
crates/antseal-core/tests/security_assumptions_drift.rs:17://! 1. **C20/Q12** — the text between the `frozen-security-assumptions`
crates/antseal-core/tests/security_assumptions_drift.rs:49:const BEGIN_MARKER: …
crates/antseal-core/tests/security_assumptions_drift.rs:50:const END_MARKER: …
```

So a **synchronised edit to both files** would keep the drift test green. What
forbids it is not the test — it is **Q21's own third Accept clause**, *"assumptions
block still verbatim"* (`tasks/Q.md`, Q21 Accept), and the M0 sign-off recorded at
`docs/threat-model.md:23`. The blocker is governance carried by a task row, and the
register should say that rather than blame a test that would not fire. §2 R4 rewrites
the reason.

**The exact frozen span, and a byte count that two independent readers got wrong in
two different directions.** Markers at `docs/threat-model.md:38` and `:409`; content
therefore lines **39–408**. Both copies are byte-identical. The size:

```
$ python3 -c '…'          # the marker-delimited slice, both files
marker slice bytes (utf-8): 21612   chars: 21465   newlines: 371
lines 39..408 bytes (utf-8): 21611  chars: 21464
byte-identical: True
'Authorship binding.' occurrences in the frozen block: 1
```

- `TODO.md:302` records *"21 465 bytes byte-identical"*. **21 465 is the CHARACTER
  count, not the byte count** — the block holds 147 non-ASCII characters (em dashes
  and friends). The true figure for the marker slice is **21 612 UTF-8 bytes**.
- A first pass of this record's own research reported **21 611** — the `sed -n
  '39,408p'` range, which is a *different span* (it omits the newline that ends the
  marker line) and was also labelled "bytes" while being compared against a character
  count.

Three readings, three numbers, one subject. Recorded here in full because the failure
mode is this project's own: **verify the field that carries the claim.** The
correction to `TODO.md:302` is a one-line ledger item, not a task.

### 1.4 Venue: both arms built and run end-to-end

Thirteen experiments, each on a fresh copy of the mini-repo with a fresh module
instance so register edits never leak between arms. Log:
`/tmp/.../scratchpad/experiments.log`.

| id | arm | result |
|---|---|---|
| **E0** | mini-repo unmodified | `scanned=14 GREEN`, 2 debts — the control |
| **E1** | six depth-1 pages, **no** register edits | **RED `['P8']` ×6** — *"is classified by nothing"* |
| **E2** | depth-1, 6 `COPY_SCAN` + 6 `DOCS_CLASSIFICATION` entries | `scanned=20 GREEN` |
| **E3a** | depth-1, a lane forgets the `COPY_SCAN` half | **RED `['P8']` ×6** — *"classified PRODUCT but is not a COPY_SCAN entry"* |
| **E3b** | depth-1, a lane forgets the `DOCS_CLASSIFICATION` half | **RED `['P8']` ×6**, `scanned=20` (read but unclassified) |
| **E4** | **subtree**, 1 `COPY_SCAN` + 1 `DOCS_CLASSIFICATION` entry | `scanned=20 GREEN` |
| **E5** | subtree, a **7th** page lands later with no register edit, carrying a P1 | **RED `['P1']`** — `docs/user/unreviewed-later-page.md:3` |
| **E5b** | subtree, a 7th **clean** page lands later with no register edit | `scanned=21 GREEN` — silently included |
| **E6** | subtree root declared **before** any page exists | **RED `['P0']`** — *"is a scan root that reads NOTHING"* |
| **E9** | six pages each state both owed clauses; README untouched | `GREEN`, 2 debts still reported (see §1.10) |
| **E10** | control: **README itself** satisfies both debts | **RED `['P7']` ×2** — *"Delete the entry"* |
| **E11** | the six pages added to `PRESENCE_SURFACES` | **RED `['P7']` ×18** (see §1.10) |
| **E12** | subtree, a `.py` carrying a P1 dropped in | `GREEN` — suffix filter (§4.4) |
| **E13** | control: a P1 planted inside an **ENG** subtree | `GREEN` — by design |

**Coverage is identical between the arms, and that was proven rather than assumed.**
The committed `self_test()` was run under both configurations, against the mini-repo,
including its per-file arm that plants a violation in every scanned file and requires
it to be reported *against that path*:

```
### arm=subtree  self_test rc=0  (PASS)
    control lines : ['control (staged, unmodified, 20 files) -> GREEN',
                     'control (staged tree restored)         -> GREEN']
    fault arms    : 20   errors: 0
    per-file READ arms: 20   UNREAD: 0
       docs/user/format-stability.md            -> READ
       docs/user/funding-your-wallet.md         -> READ
       docs/user/tsa-defaults-and-alternates.md -> READ
       docs/user/vault-loss.md                  -> READ
       docs/user/vault-theft.md                 -> READ
       docs/user/wallet-hygiene.md              -> READ

### arm=depth1   self_test rc=0  (PASS)
    per-file READ arms: 20   UNREAD: 0
       docs/vault-loss.md … docs/format-stability.md  -> READ (all six)
```

**Every one of the six pages is demonstrably read under both arms.** The subtree buys
its economy at zero cost in coverage — which is the only thing that would have
disqualified it.

### 1.5 The ordering trap, which is where the two arms really part

A doc lane does not land a file and a register edit atomically unless it is told to.
Measured (`/tmp/.../scratchpad/ordering.log`):

```
ORD-1 depth-1: COPY_SCAN entry lands BEFORE the file -> RED ['P0', 'P8']
    P0 docs/vault-theft.md: named in COPY_SCAN but is not a file — a renamed or
       deleted copy surface must be loud, never a silent skip
    P8 docs/vault-theft.md: is classified in DOCS_CLASSIFICATION but does not exist.

ORD-2 depth-1: the file lands BEFORE any register edit -> RED ['P8']
    P8 docs/vault-theft.md: is classified by nothing.

ORD-3 subtree: entry + first page in ONE commit -> GREEN  scanned=15

ORD-4 subtree classified ENG, page carries a P1 -> GREEN (unscanned)  scanned=14
```

**Depth 1 has a two-sided trap and pays it six times.** Every page must arrive in the
same commit as both of its register lines; any other order reds the shared tree for
every concurrently running lane. **The subtree pays it once**, at ORD-3, and never
again.

ORD-4 records a staging option this record deliberately **does not** take: classify
`user/` as `ENG` first, land the pages unscanned, promote at the end. It is green at
every step and it is wrong — it means six documents are written without the lint that
exists to shape them, and the promotion lands as one large red at the worst moment.

### 1.6 What P1–P3 do to the sentences these six documents must write

The charter's fourth question: are the mandated Accept clauses writable as `PRODUCT`?
Twenty-six specimens drawn from the six rows' own `Do`/`Accept` text, through the real
patterns (`/tmp/.../scratchpad/probe/specimens.log`, `specimens2.log`). **9 of 26 red.**
The reds are not random; they fall into four shapes, and every one of them is a
*phrasing* constraint rather than a *content* constraint.

**(a) A markdown heading is its own block, so P2 reds on a heading whose qualification
sits in the paragraph below it.** This is the single most actionable result in the
record:

```
RED ['P2']  heading + body in TWO blocks (blank line) — qualifier in the NEXT block
green       heading + body in ONE block (no blank line) — priority qualified in the body
RED ['P2']  bullet: - Priority: an earlier seal wins.
green       bullet: - Priority: an earlier seal outranks a later one.
RED ['P2']  a section HEADING containing the banned noun, alone in its block   (## Priority and precedence)
RED ['P2']  [Q26] why a timestamp matters, stated the natural way
            ("A timestamp token is what gives a seal its priority against a later claim.")
```

**(b) A table row and a list item are each their own *sentence*, so P3 reds on a cell
that names the limit without a negation in that cell:**

```
RED ['P3']  table row: | Authorship | the signature binds a key to bytes |
green       table row WITH a negation ('no longer')
RED ['P3']  heading: ## Exclusive possession
RED ['P3']  bullet: - Exclusive possession of the vault is what an attacker takes from you.
green       heading: ## What a seal does not prove: authorship
```

**(c) `DISCLAIMER` is a closed word list, and the natural negations are not in it.**
Measured, one word at a time:

```
   not / never / no / none / nothing / cannot / without
   rejected / banned / forbidden / refused          -> counts as a disclaimer
   out of scope / untrue / false / denies / excludes / beyond -> does NOT count
```

*"Authorship is out of scope for a seal"* reds. *"A seal does not prove authorship"*
passes. That is a writing rule, and §2 R7 states it as one.

**(d) The vocabulary a TSA page needs is not banned.** P9's Class V list —
`certify`, `certified`, `witness`, `certificate` — is explicitly **not** a Class P ban
(`docs/positioning-copy-style.md:226-228`), and the measurement confirms the lint
agrees with the guide:

```
green  [Q26] X.509 vocabulary the doc cannot avoid: certificate/certified/witness
green  [Q26] the alternates table, five rows        (freetsa.org / digicert.com URLs)
green  [Q26] the Entrust/Sectigo collapse finding
```

Non-antseal URLs do not trip P6: `PRODUCT_URL` requires `antseal\.[a-z]+`
(`scripts/check-copy-style.py:199`), so Q26's endpoint table is safe as written.

**Conclusion for the charter's question.** *No mandated Accept clause is unwritable as
`PRODUCT`.* Every red above clears with a rephrase that a reviewer would want anyway —
the qualification in the same block, the negation in the same cell. **The one place
the ban genuinely cannot be satisfied is `docs/threat-model.md:393`, and there the
obstacle is not the rule but the freeze** (§1.2, §1.3). That is the finding that
decides ruling 3, and it decides it on its own.

### 1.7 P4 and P5 are wrap-fragile in **both** directions

`check_spellings` finds an anchor substring and requires the canonical string inside a
window (`scripts/check-copy-style.py:380-404`). Both are literal, both contain spaces,
and markdown prose wraps. Measured by wrapping at every intra-phrase space in turn:

```
P4 canonical (50 chars): 'supporting evidence — no independently proven time'
P5 canonical (33 chars): 'asserted by sealer — NOT verified'

P4: 6 intra-phrase space positions; 3 of them RED when the line wraps there
    wrap at char 10  ...supporting⏎evidence — n...
    wrap at char 19  ...ing evidence⏎— no indepen...
    wrap at char 21  ...g evidence —⏎no independe...
P5: 5 intra-phrase space positions; 3 of them RED when the line wraps there
    wrap at char 18  ...ed by sealer⏎— NOT verifi...
    wrap at char 20  ... by sealer —⏎NOT verified...
    wrap at char 24  ...sealer — NOT⏎verified...

CONTROL P4 unwrapped -> GREEN      CONTROL P5 unwrapped -> GREEN
FAULT   P4 anchor-only -> RED      FAULT   P5 anchor-only -> RED
```

That is the **false-red** half: correctly spelled copy reds because an editor wrapped
it. `docs/threat-model.md:450` is a live instance in the tree today — the file spells
the phrase correctly for a *reader*, across a line break, and P4 sees the bytes.

The **blind** half is worse, and is this repository's dominant defect class in a new
suit. Wrap inside the *anchor* and the anchor is never found, so a genuinely
mis-spelled phrase reports nothing at all:

```
P4: MIS-SPELLED and UNWRAPPED  -> RED   (control: the rule can fire)
    wrapped inside anchor -> GREEN <-- BLIND   supporting evidence - no⏎independently proven time
    wrapped inside anchor -> GREEN <-- BLIND   … - no independently⏎proven time
    wrapped inside anchor -> GREEN <-- BLIND   … - no independently proven⏎time
P5: MIS-SPELLED and UNWRAPPED  -> RED
    wrapped inside anchor -> GREEN <-- BLIND   asserted⏎by sealer (not verified)
    wrapped inside anchor -> GREEN <-- BLIND   asserted by⏎sealer (not verified)
```

**3 of 3 and 2 of 2.** A page that hyphenates the em dash *and* wraps mid-anchor
passes P4 in silence. Six new documents all quote the receipt class; without §2 R7
this would have been met six times, once per lane, and diagnosed as six separate
puzzles.

### 1.8 P6 reds on a sentence-ending period

```
   https://antseal.org/             -> green
   (https://antseal.org/)           -> green
   https://antseal.org/,            -> green
   `https://antseal.org/`           -> green
   <https://antseal.org/>           -> green
   https://antseal.org/.            -> RED     <-- a sentence ending in the URL
   https://antseal.org              -> RED     (no trailing slash)
   http://antseal.org/              -> RED     (scheme)
   https://antseal.org/#verify      -> RED     (fragment)
   https://antseal.org/docs/        -> RED     (path)
   https://www.antseal.org/         -> RED     (D62's known case)
```

The tail character class at `scripts/check-copy-style.py:199` excludes
`space ) " ' < > ] , ` *` but **not `.`**, so a full stop is absorbed into the match.
Every one of the six pages will want to end a sentence with the verifier URL. §2 R7
makes it a writing rule; §5 hands the pattern question to Q28.

### 1.9 The unlisted arm: Q27's page becomes the **third** copy of the freeze boundary

The brief did not raise this and it could have been discovered only after Q27's page
was already `PRODUCT`. `scripts/check-traceability.py:65-67` says, in its own comment:

> Q27's format-stability policy doc joins this list at M4, in Q27's own commit — a
> copy added without its lint is exactly the drift this check exists to prevent.

```python
BOUNDARY_COPIES = [
    "tasks/Q.md",
    "docs/format/anchor-artifact-limits.md",
]
```

So Q27's page will carry a **byte-identical** copy of D84 §7's rows — the same shape
that makes `docs/threat-model.md` unpromotable. **Measured, before ruling Q27's page
`PRODUCT`:**

```
docs/format/anchor-artifact-limits.md: freeze-boundary block = 2179 bytes, 34 lines
    copy-rule findings: NONE — clean on P1-P6
tasks/Q.md: freeze-boundary block = 2179 bytes, 34 lines
    copy-rule findings: NONE — clean on P1-P6
```

**Clean, and identical at 2 179 bytes.** Q27's page is therefore safe as `PRODUCT` —
but the safety is *content-conditional*, exactly as D138 §2 R2 found for its excluded
paths, and §2 R8 records it so nobody has to rediscover it.

### 1.10 `OWED_PRESENCE`: no page this wave writes can trip it

The charter asks plainly. The answer is **no**, and it is structural rather than
lucky. `check_presence` iterates `PRESENCE_SURFACES`, which is
`("README.md",)` (`scripts/check-copy-style.py:202`), and every `OWED_PRESENCE` key
is `("README.md", …)` (`:138-149`). **E9** plants six pages that each state *both*
owed clauses in as many words:

```
    (PRESENCE_SURFACES = ('README.md',))
--- E9 six new pages each STATE both owed clauses; README untouched
    scanned=20  verdict=GREEN  debts_reported=2
```

Green, both debts still reported as owed. **E10** is the control that proves the
staleness check is live and would have fired had the subject been README:

```
--- E10 CONTROL — README itself satisfies both debts (must RED, demanding deletion)
    scanned=14  verdict=RED ['P7']  debts_reported=0
      P7 README.md: OWED_PRESENCE still carries 'compelled-disclosure' but the clause
         is now STATED. Delete the entry …
      P7 README.md: OWED_PRESENCE still carries 'limit-exclusive-possession' but …
```

**The one way this wave could trip it is by widening `PRESENCE_SURFACES`** — which
`docs/positioning-copy-style.md:140-142` invites in prose: *"Every positioning
surface — today `README.md`; at M4 the product-limits and disclosure pages Q22–Q25
write — must state, in its own words:"* all five clauses. **E11** obeys that sentence
literally:

```
--- E11 the six pages ADDED to PRESENCE_SURFACES (guide §6's reading)
    scanned=20  verdict=RED ['P7']  debts_reported=2      (18 findings)
      P7 docs/funding-your-wallet.md: does not state the required 'limit-authorship' clause
      P7 docs/funding-your-wallet.md: does not state the required 'limit-exclusive-possession' clause
      P7 docs/funding-your-wallet.md: does not state the required 'seal-before-you-share' clause
      … the same three for vault-loss, vault-theft, wallet-hygiene, tsa-defaults, format-stability
```

**Eighteen findings, and they are the guide over-reaching, not the pages failing.** A
funding-your-wallet page has no business saying *seal before you share*; a
format-stability policy has no business restating the authorship limit. §2 R9 keeps
`PRESENCE_SURFACES` at `README.md` for this wave and §5 hands the guide sentence to
Q22/Q28, which own the pages that genuinely are positioning surfaces.

### 1.11 What a shared register does under six concurrent writers

The depth-1 arm asks six lanes to edit two Python literals in one file. Two failure
modes, both measured:

- **A lost update is LOUD.** Losing the `COPY_SCAN` half gives E3a (`P8`,
  *"classified PRODUCT but is not a COPY_SCAN entry"*); losing the
  `DOCS_CLASSIFICATION` half gives E3b (`P8`, *"classified by nothing"*). Neither is
  silent. Good — but both red the tree for every other lane.
- **An interleaved write is a `SyntaxError`, not a finding.** Simulating one lane's
  line landing inside the other's tuple:

  ```
    File "…/broken.py", line 84
      "docs/user/
      ^
  SyntaxError: unterminated string literal (detected at line 84)
  REAL_EXIT=1
  ```

  The check does not run at all; `ci-always.yml:236` and `scripts/local-gate.sh:513`
  both go red with a traceback rather than a rule id. Loud, and it blocks all six
  lanes at once.

Twelve edits by six writers versus **two edits by one writer, once**. That is §2 R6.

### 1.12 Filenames are unclaimed, and the venue changes nothing structural

No surface in the tree already names a path for any of these pages:

```
$ grep -rn "vault-loss\|vault-theft\|wallet-hygiene\|funding-your-wallet\|tsa-defaults\
  \|timestamp-authorities\|format-stability\|docs/user/\|docs/guide/" \
  --include=*.rs --include=*.py --include=*.sh --include=*.yml --include=*.txt \
  --include=*.html README.md
(no hits)
```

So the names are this record's to rule. Two structural facts bound the choice:

1. **`docs/threat-model.md` must not move.** A rename breaks
   `security_assumptions_drift.rs:47` — four tests — and reds P8 twice. It stays where
   it is.
2. **A new `docs/` subtree costs exactly one register entry.** `check_docs_partition`
   (`:468-513`) walks `docs.iterdir()` at depth 1 only; a directory becomes the key
   `name + "/"` and its contents are never individually classified. Nothing else in
   the repository enumerates `docs/` at depth 1 — not `scripts/local-gate.sh`, not
   `scripts/check-ci-paths.py` (whose `DOCS_ONLY` is the three D138 entries), not any
   test, which walk `crates/` and `.rs` only.

One more asymmetry, which is a genuine argument the brief did not list.
`scripts/check-traceability.py`'s `CITATION_SCAN` names directories
(`"crates"`, `"docs/format"`, `"docs/testing"`, `"scripts"`, `"verifier-web"`) and
root files. **A `docs/user/` subtree could later join it as ONE directory entry**, on
the precedent `verifier-web` set at `:633`; six depth-1 pages could join only as six
literals, or by adding `"docs"` wholesale and dragging in 133 decision records. Today
neither venue is swept — that is Q181's known gap — but only one of them is cheap to
close.

Finally, the reader. `docs/` holds **11** depth-1 `.md` files today, of which exactly
one (`positioning-copy-style.md`) is Class P:

```
ci-verification.md config.md dependency-policy.md instrument-ledger.md
positioning-copy-style.md security-assumptions.md threat-model.md toolchain.md
vault-keyfile.md wasm-toolchain.md zeroization-audit.md
```

The depth-1 arm makes that **17 files, 6 product pages interleaved alphabetically
among 11 contributor documents**, with `funding-your-wallet.md` sorting between
`dependency-policy.md` and `instrument-ledger.md`. The subtree arm leaves the
contributor set at 11 and puts the user set behind one name. **The venue then mirrors
the Class P / Class E partition that `DOCS_CLASSIFICATION` currently carries entirely
by hand** — which is the argument, and it is the one the register itself has been
making since D123.

---

## 2. The ruling

### §2 R1 — The venue is `docs/user/`: one directory, one `COPY_SCAN` entry, one classification

All six new pages land under **`docs/user/`**. It is a **directory** entry in
`COPY_SCAN` (walked, suffix-filtered — D123's rule, reproduced at
`scripts/check-copy-style.py:62-72`) and a **single** `PRODUCT` entry in
`DOCS_CLASSIFICATION`.

Depth-1 `docs/*.md` is refused on §1.4, §1.5 and §1.11: identical coverage (both arms
pass `--self-test` with all six pages READ), 12 register edits against 2, a two-sided
per-page ordering trap against a one-time one, and six lanes serialised on one Python
file for no measured benefit.

The name is `user/` rather than `guide/` or `docs/product/` because it is the word the
register already uses: `scripts/check-copy-style.py:18-19` defines Class P as *"what a
**user** reads"*.

### §2 R2 — The exact filenames. Copy this table verbatim.

| Row | What it is | **Path** | Class | Scanned via | New? |
|---|---|---|---|---|---|
| **Q21** | threat model | **`docs/threat-model.md`** | **ENG** | *not scanned* — §2 R3 | no, exists |
| **Q23** | funding your wallet | **`docs/user/funding-your-wallet.md`** | PRODUCT | `docs/user/` | yes |
| **Q24** | vault **loss** | **`docs/user/vault-loss.md`** | PRODUCT | `docs/user/` | yes |
| **Q24** | vault **theft** | **`docs/user/vault-theft.md`** | PRODUCT | `docs/user/` | yes |
| **Q25** | wallet hygiene | **`docs/user/wallet-hygiene.md`** | PRODUCT | `docs/user/` | yes |
| **Q26** | TSA defaults and alternates | **`docs/user/timestamp-authorities.md`** | PRODUCT | `docs/user/` | yes |
| **Q27** | format-stability policy | **`docs/user/format-stability.md`** | PRODUCT | `docs/user/` | yes |

**Six new files. Q21 creates none.**

- **Q24 is TWO files, and that is read off its `Accept`, not its row title.** The row
  reads *"Write the vault-loss and vault-theft doc pages"* and its first Accept clause
  is *"**Both pages exist** and are linked from README and `init` output (U)"*. Two
  pages, two paths, and the `Do` gives them different content (loss: export/import and
  backup discipline; theft: retroactive permanent decryption, no rotation, passphrase
  floor, Argon2id hardening). They must not be merged.
- **Q26's file is named for its subject, not its row title.** `timestamp-authorities.md`
  is what a reader looks for; `tsa-defaults-and-alternates.md` was the alternative and
  is refused only because "TSA defaults-and-alternates" is register vocabulary. Nothing
  machine-reads the name (§1.12), so this is a free choice made once, here, so that six
  lanes do not each make it differently.
- **Q27's path is load-bearing beyond the copy lint** — it goes into `BOUNDARY_COPIES`
  (§2 R8). Change it and two files must change together.

### §2 R3 — `docs/threat-model.md` stays **ENG** after Q21 finalizes it. The promotion is refused on measurement.

The lean's third clause is **overturned**. The file is not promoted — not by Q21, not
by Q28 — while `docs/threat-model.md:393` sits inside the byte-frozen block.

The refusal is not a preference between two readings of Q21's `Accept`. Under the
promoting reading, Q21's `Accept` clause *"Q20 lint passes; assumptions block still
verbatim"* asks for two things that cannot both be true (§1.2 E8). Under the other
reading — the lint is green repo-wide when Q21 is done — both are satisfiable, and
they are satisfied **today**: `scripts/check-copy-style.py` exits 0 (§1.1). **The
non-contradictory reading is the correct one, and it is the one this record adopts.**
"Q20 lint passes" means the lint is green; it never meant this file joins the scan.

**Q21 still owns the two defects it can fix**, and they are not waived by the file
staying Class E — §11 of the guide calls the first *"a real defect in shipped text,
not a rule that is wrong"*:

1. **The P2 at `docs/threat-model.md:14`.** Its `## Positioning` block claims
   *existence, integrity and priority* and never says an earlier seal outranks a later
   one. Fix by adding the spec's own qualification **to that block**, not to the
   paragraph after it (§1.6 (a)). Verify with the probe, not by eye.
2. **The P4 at `docs/threat-model.md:450`.** `## 2.3` quotes the receipt class across
   a line break. Rewrap so the 50-character phrase sits on **one source line** (§2 R7).

Both are outside lines 39–408 and neither touches the frozen block.

### §2 R4 — The `threat-model.md` classification reason is rewritten to record the measurement

Its current reason (`scripts/check-copy-style.py:107-113`) will be **false** the moment
Q21 lands: it calls the file an "M0 SKELETON", and it says the Positioning section
*"carries a measured, registered defect"* which Q21 removes. Stale prose in a register
is a defect in this repository. Replace the entry with:

```python
    "threat-model.md": (
        "ENG",
        "stays Class E after Q21 finalizes it, and the reason is MEASURED (D139 §1.2, §2 R3): "
        "lines 39-408 are the byte-frozen copy of security-assumptions.md, asserted by "
        "crates/antseal-core/tests/security_assumptions_drift.rs:143-185, and one line inside "
        "that block reads '**What breaks if it is false.** Authorship binding.' - a live P3 with "
        "no disclaimer in its sentence. Promoting this file to PRODUCT therefore reds the lint on "
        "text Q21's own Accept clause ('assumptions block still verbatim') forbids it to touch; "
        "measured, the flip is still RED after every repair Q21 is permitted to make. The block is "
        "pinned by EQUALITY between the two copies, not by a digest - so the blocker is the M0 "
        "sign-off at docs/threat-model.md:23 and Q21's Accept, not the drift test. Q21 still owns "
        "the two FIXABLE defects outside the block: the P2 in its Positioning section "
        "(docs/positioning-copy-style.md §11 finding 3) and the P4 where §2.3 quotes the receipt "
        "class across a line break. The user-facing pages live in docs/user/",
    ),
```

### §2 R5 — The complete edit set. Two additions and one replacement, in one file, applied once.

**Edit 1 — `COPY_SCAN` (`scripts/check-copy-style.py:73-84`).** Insert one entry after
`"verifier-web/"`:

```python
    # The M4 user-facing documentation set (Q23-Q27; Q21's threat model is NOT here -
    # D139 §2 R3). A DIRECTORY entry under D123's rule: walked and suffix-filtered, so
    # every page that lands here is scanned from its first commit with no second
    # register edit. D139 §1.4/§1.5 prices that against one entry per page: identical
    # coverage under --self-test, 2 register edits instead of 12, and no per-page
    # ordering trap in a file six lanes share. What it costs is recorded at D139 §4.2.
    "docs/user/",
```

**Edit 2 — `DOCS_CLASSIFICATION`, subtree section (`:118-129`).** The subtree block is
alphabetical (`anchors/ decisions/ devnet/ format/ naming/ research/ reviews/ testing/
upstream/ waves/`); insert **between `"upstream/"` and `"waves/"`** and keep it sorted:

```python
    "user/": (
        "PRODUCT",
        "the M4 user-facing documentation set (Q23-Q27), scanned as the COPY_SCAN "
        "directory entry docs/user/ - D139 §2 R1. CLOSED VENUE: every file here is "
        "Class P by construction. An engineering document does not go in this "
        "directory; nothing mechanical enforces that (D139 §4.2)",
    ),
```

**Edit 3 — replace the `threat-model.md` entry (`:107-113`)** with the block in §2 R4.

**Nothing else changes.** `PRESENCE_SURFACES` is untouched (§2 R9). `OWED_PRESENCE` is
untouched (§2 R9). `COPY_SUFFIXES` is untouched.

### §2 R6 — The register edits are applied **centrally, once**, and no doc lane touches `scripts/check-copy-style.py`

**Mechanism, ruled:** the orchestrator (or one nominated lane, never two) applies all
three edits of §2 R5 in a **single commit, together with the first `docs/user/` page to
land**. Every subsequent page lands with **no register edit whatsoever**.

The ordering is not a nicety — E6 measured what happens if the `COPY_SCAN` entry
arrives first:

```
--- E6 subtree declared BEFORE any page lands (the ordering hazard)
    scanned=14  verdict=RED ['P0']
      P0 docs/user/: is a scan root that reads NOTHING — no file under it has a suffix
         in ['.css', '.htm', '.html', '.js', '.md', '.txt']. A root that reads nothing
         is D123's defect
```

**What happens if two lanes edit it simultaneously**, asked and answered by §1.11: a
lost update reds `P8` (loud, but it reds the shared tree for everyone), and an
interleaved write is a `SyntaxError` that stops the check from running at all —
`REAL_EXIT=1` with a traceback instead of a rule id, in `ci-always.yml:236` and
`local-gate.sh:513` alike. Under this ruling neither can happen, because exactly one
writer touches the file and touches it once.

**Per-lane report instead of per-lane edit.** Each doc lane reports, in its return: the
path it created, and the output of `python3 scripts/check-copy-style.py` after its page
landed. A lane that cannot get a green must report the finding, not edit the register
to make it go away.

### §2 R7 — Three writing rules, executable, that keep P4/P5/P6 from firing on correct copy

These are consequences of §1.7 and §1.8 and they apply to **every page in
`docs/user/`** and to `docs/threat-model.md`:

1. **Never wrap either dictated phrase.** `supporting evidence — no independently
   proven time` (50 chars) and `asserted by sealer — NOT verified` (33 chars) each sit
   on **one source line**, em dash included. Wrapping before the anchor reds a
   correctly spelled phrase; wrapping inside the anchor makes the rule **blind to an
   actual mis-spelling** (§1.7). If the line runs long, break *before* the phrase.
2. **Never end a sentence with the bare verifier URL.** `https://antseal.org/.` reds.
   Write it as `` `https://antseal.org/` ``, `<https://antseal.org/>`,
   `(https://antseal.org/)`, `[the verifier](https://antseal.org/)`, or followed by a
   comma — all measured green (§1.8). No path, no fragment, no `www`, trailing slash
   always.
3. **Put the qualifier where the rule looks for it.** P2's scope is the **block**: a
   heading containing `priority` is its own block and needs `outrank` or `seal before
   you share` *in the heading or in an unbroken continuation of it*. P3's scope is the
   **sentence**, and a table row and a list item are each a sentence: a cell naming
   `authorship` / `exclusive possession` needs `not`/`never`/`no`/`cannot`/`without` in
   **that cell**. `out of scope`, `false`, `untrue`, `excludes` do **not** count
   (§1.6 (c)).

**Verify, do not eyeball.** After writing, run `python3 scripts/check-copy-style.py`
and read the exit code back out of a file:

```
python3 scripts/check-copy-style.py > /tmp/copy.log 2>&1; echo "REAL_EXIT=$?" >> /tmp/copy.log
```

The harness's own "(exit code 0)" notification reports the last command in a wrapper,
not the one being measured.

### §2 R8 — Q27's page joins `BOUNDARY_COPIES` in Q27's own commit, and that is a **second** shared surface

`docs/user/format-stability.md` carries a byte-identical copy of D84 §7's rows, so
`scripts/check-traceability.py`'s `BOUNDARY_COPIES` (`:69-72`) gains:

```python
BOUNDARY_COPIES = [
    "tasks/Q.md",
    "docs/format/anchor-artifact-limits.md",
    "docs/user/format-stability.md",
]
```

in **the same commit as the page**, as that file's own comment at `:65-67` requires and
Q27's `Accept` clause 3 demands (*"byte-identical to Q14's block and A27's §2 —
asserted by the drift lint, not by review"*).

Two consequences the wave must not miss:

- **This is a different shared Python file from the copy lint's**, with a different
  owner (Q27, not the central register editor of §2 R6). The wave therefore has **two**
  shared-surface edits, not one. They must not be batched together by a lane that owns
  only one of them.
- **The block is clean on P1–P6 today (§1.9), which is why Q27's page can be `PRODUCT`
  at all — and that safety is content-conditional.** If D84 §7's rows ever gain a
  banned word, `docs/user/format-stability.md` acquires exactly
  `docs/threat-model.md`'s problem: a finding it cannot fix in place. Q27 runs **both**
  lints and reports both:
  `python3 scripts/check-copy-style.py` and
  `python3 scripts/check-traceability.py --freeze-boundary`.

### §2 R9 — `PRESENCE_SURFACES` and `OWED_PRESENCE` are **not touched** this wave

Measured answer to the charter's question: **no page this wave writes can trip the
`OWED_PRESENCE` staleness check**, because every debt key is `("README.md", …)` and
`check_presence` reads only `PRESENCE_SURFACES == ("README.md",)`. E9 proves it with
six pages that each state both owed clauses in as many words; E10 proves the check is
live by making README state them and watching it red (§1.10).

**Neither debt is discharged by this wave, and neither may be deleted by it.** They are
Q22's, and Q22 is not in this wave. A lane that finds itself wanting to delete an
`OWED_PRESENCE` entry has landed a change to `README.md` that is not its to make.

**`PRESENCE_SURFACES` stays at `("README.md",)`.** Widening it to the six pages
produces **18 P7 findings** demanding that a funding guide say *seal before you share*
(E11). The guide sentence that invites the widening
(`docs/positioning-copy-style.md:140-142`) over-reaches by naming Q23's and Q25's pages
as positioning surfaces; §5 hands that to Q22/Q28.

### §2 R10 — Q21's cross-links point at the ruled paths

Q21's second `Accept` clause is *"Every Risks-section row (lines 177–189) is addressed
here or explicitly delegated to a named doc page."* The **named doc pages** are §2 R2's,
spelled exactly, with the delegations fixed here so six lanes and one registrar agree:

| threat-model section | delegated to |
|---|---|
| §2.1 Vault theft | `docs/user/vault-theft.md` (Q24) |
| §2.2 Vault loss | `docs/user/vault-loss.md` (Q24) |
| §2.3 Wallet linkability | `docs/user/wallet-hygiene.md` (Q25) and `docs/user/funding-your-wallet.md` (Q23) |
| TSA selection / degraded anchoring | `docs/user/timestamp-authorities.md` (Q26) |
| format permanence / version bumps | `docs/user/format-stability.md` (Q27) |
| §2.4–§2.10 | retained in `docs/threat-model.md` |

Q24's second `Accept` clause — *"linked from README and `init` output (U)"* — is a
**link into `docs/user/`**, and the README edit that carries it is Q22's, not Q24's.
Q24 reports the two paths; it does not edit `README.md` (that file is a
`PRESENCE_SURFACE` and a `COPY_SCAN` literal, and editing it is how §2 R9's trap gets
sprung by accident).

---

## 3. Why this shape and not the obvious one

The lean was not careless — it is what the guide itself predicts. `docs/positioning-copy-style.md:302-306`
says the M4 docs *"join as they land. P8 makes that unmissable: each lands unclassified
and red."* That paragraph describes the depth-1 arm, and it was written before anyone
tried to land six pages at once from six lanes.

What changed the answer is the **medium of the measurement**. Reading the lint tells
you a subtree is one entry and six files are six entries; that is arithmetic and it
does not decide anything. **Running** both arms end-to-end — with `--self-test`, with a
concurrent-lane ordering model, with a seventh page landing later — is what produced
the three facts that decide it: coverage is identical (so the cheap arm costs nothing),
the ordering trap is two-sided and per-page (so the expensive arm costs six times), and
a lost register update is loud but blocks everyone (so the shared-file cost is real).
None of the three is visible from the source alone.

The same is true of ruling 3, and more sharply. The register's stated reason for
`threat-model.md` being Class E — *"~370 of its lines are the verbatim frozen copy"* —
is a reason to be **careful**, not a proof of anything. It does not say whether the
frozen block actually violates a rule. It might have been clean, in which case the
promotion would have been trivial and the lean right. **It is not clean: exactly one
line, `:393`, and the charter was correct to demand a count rather than an argument.**
One line decides the ruling, and no amount of reasoning about "~370 frozen lines"
would have found it or ruled it out.

Two smaller things worth naming, because both are this project's recorded failure
modes in fresh clothes:

- **§1.7's blind half is an assertion that cannot fail.** P4 and P5 are the only rules
  in this lint whose *failure to fire* is indistinguishable from a pass, and the
  condition that silences them — a line wrap — is produced by a text editor rather than
  by an adversary. Six documents were about to be written into that gap.
- **§1.3's byte count is "verify the field that carries the claim" in miniature.**
  Three readings of one block produced 21 465, 21 611 and 21 612, and two of them were
  labelled "bytes" while being characters or a different span. The number is not
  load-bearing; the habit is.

---

## 4. What this ruling does NOT cover

### 4.1 It does not rule the content of any page

Only the venue, the filename, the class, and the phrasing constraints the lint imposes.
Every `Do` clause — Q26's five A25 findings, Q21's eight mandated topics, Q27's
freeze-boundary reproduction — is the writing lane's, unchanged.

### 4.2 The subtree's real cost: a later page is included without anyone classifying it

Stated plainly because a guard whose limits are unwritten gets trusted past them. E5b:

```
--- E5b subtree — a 7th CLEAN page lands with NO register edit (silent inclusion?)
    scanned=21  verdict=GREEN  debts_reported=2
```

A page dropped into `docs/user/` after this wave becomes product copy with **no
classification act and no red**. This is the exact discipline D123 installed P8 to
provide, and the subtree trades it away for the pages inside one directory.

Three things bound the damage, and none of them is nothing:

- **Inclusion is the safe direction.** The included page *is* linted; E5 shows a
  violation inside an unreviewed seventh page reported by path and rule. What P8 exists
  to prevent — *"a copy surface no lint reads"* — cannot happen inside `docs/user/`.
- **The uncontrolled direction is the reverse**: an *engineering* document dropped into
  `docs/user/` is treated as product copy by a lint and as user documentation by a
  reader, and nothing says so. §2 R5's reason string calls the venue **CLOSED** and
  says explicitly that nothing mechanical enforces it. That is a review rule honestly
  labelled as one, not a guard.
- **A guard is possible and is NOT built here**, because this record cannot write to
  `scripts/`. Its shape is in §5 item 4, and whoever builds it must plant a fault and
  show it reds *by its message*.

### 4.3 It does not widen `CITATION_SCAN`

`docs/user/` will **not** be citation-swept when it lands
(`scripts/check-traceability.py:623-655` names `docs/format` and `docs/testing` only).
Neither would six depth-1 pages have been. The venue makes the future fix a
one-directory-entry change on the `verifier-web` precedent instead of six literals —
that is an argument recorded in §1.12, **not** a change ruled here. The gap is Q181's.

### 4.4 A non-markdown file in `docs/user/` is invisible, and that is true at depth 1 too

```
--- E12 subtree — a .py with a P1 violation dropped in (suffix filter)
    scanned=20  verdict=GREEN
```

`COPY_SUFFIXES` filters the walk; `check_docs_partition` skips any depth-1 child that
is neither a directory nor `.md`. So a `.py`, `.png` or `.svg` is unscanned and
unclassified under **either** venue — there is no delta between the arms and this
record claims none. What the subtree changes is only how visible the hole is: a
`PRODUCT` classification whose reason reads *"the M4 user-facing documentation set"*
invites a reader to assume it covers everything in the directory. D138 §3 R5 solved the
same problem for the CI path filter by asserting every matched file has a `.md` suffix;
the copy lint has no equivalent. §5 item 4.

### 4.5 It does not verify anything on the remote, or in a real gate run

Every measurement here is local, against a scratch mini-repo built from today's tree,
with the real script. **No lane in this record has run `scripts/local-gate.sh` or CI** —
both are forbidden to this lane, and the working tree is shared with concurrent
writers. The observable that would discharge this is specific: after §2 R5's edits and
the first `docs/user/` page land, `copy-style-selftest` and `copy-style`
(`scripts/local-gate.sh:512-513`) must both pass, and the check's summary line must
read **one more scan root and one more classification entry** — *"across 6 scan
root(s) … (P8, 22 entries)"* — with the file count risen by the number of pages
present.

### 4.6 It does not rule on `docs/vault-keyfile.md`

Its classification reason (`:115`) reads *"keyfile mechanism reference; Q24 writes the
user-facing pages"*. That becomes more accurate once §2 R2's paths exist, not less, so
no edit is required. Whether the keyfile reference should itself be linked from
`docs/user/vault-theft.md` is Q24's editorial call.

### 4.7 It does not settle whether `docs/threat-model.md` is ever promotable

§2 R3 refuses the promotion **while line 393 is inside the freeze**. It does not rule
that the freeze is permanent, nor that a future synchronised amendment to both copies
(which §1.3 shows the drift test would permit) is forbidden for ever. It rules that
**Q21 may not make it, and that no lane in this wave may make it**, because Q21's
`Accept` forbids it and the M0 sign-off at `docs/threat-model.md:23` is not this wave's
to reopen.

---

## 5. What this ruling owes

1. **`docs/positioning-copy-style.md` §12 is now wrong in two places, and it is
   scanned product copy.** Item 1 (`:302-306`) describes the per-page depth-1 arm this
   record refuses, and omits Q26 and Q27 from its list of M4 docs. Item 3
   (`:309-310`) promises `docs/threat-model.md`'s promotion, which §2 R3 refuses.
   §11 finding 3 (`:267-277`) becomes stale the moment Q21 fixes the line-14 defect.
   All three need amending by the lane that lands Q21, or by Q28. **Not done here:**
   that file is outside this lane's write scope.
2. **`docs/positioning-copy-style.md` §6 (`:140-142`) over-reaches** by naming Q23's
   and Q25's pages as positioning surfaces owing all five clauses; E11 measured the
   18 findings that reading produces. The sentence should name the surfaces that
   genuinely are positioning surfaces (README, and Q22's product-limits page). Q22/Q28.
3. **`TODO.md:302` labels a character count as a byte count** (21 465 characters;
   21 612 UTF-8 bytes). One-line correction, ledger not task.
4. **The two lint defects this record found but cannot fix**, both belonging to the
   apparatus rather than to any page:
   - **P4/P5 are wrap-fragile** — false red before the anchor, **silently blind**
     inside it (§1.7). The candidate fix is to normalise runs of whitespace in the
     window before comparing, on both the anchor search and the canonical match; it
     must be built with a planted fault for **each** half, because the blind half is
     precisely the kind that a check green over nothing would hide.
   - **P6 absorbs a trailing full stop** (§1.8) — `.` is missing from the tail
     exclusion class at `:199`. Excluding it would also stop `https://antseal.org/docs/`
     from being reported, so the fix is not a one-character change and needs its own
     measurement.
   A third, optional: **a `COPY_SUFFIXES` completeness guard** for `PRODUCT`
   directory entries, in D138 §3 R5's shape — every file under a `PRODUCT` subtree
   must have a scanned suffix, or red (§4.2, §4.4).
5. **A gate witness.** Nothing here has run in `scripts/local-gate.sh` or CI (§4.5).
   The first gate run after §2 R5's edits land is the witness, and the observable is
   the summary line's *"6 scan root(s)"* and *"P8, 22 entries"*.
6. **Q28 inherits the corpus, not a rewrite.** After this wave `COPY_SCAN` has 6 roots
   and the scan reads 14 + `|docs/user/*.md|` files. Q28's *"lint green repo-wide"* and
   *"exactly one canonical URL value found by grep across all surfaces"* are unchanged
   in kind; §2 R7 rule 2 is what keeps the second one true across six new pages.

---

## Addendum — 2026-08-17: §2 R10's README clause is superseded by D140 the same day, and every line number this record cites into `docs/threat-model.md` was invalidated by the work it exists to enable

Both corrections were produced **inside the wave that wrote this record**, by the
lanes it was written to unblock. **No ruling in §2 moves.** What moves is one
clause of §2 R10 about *which row* carries a README edit, and the currency of a
class of citation this record uses 28 times.

### §C R1 — §2 R10's *"the README edit that carries it is Q22's"* is SUPERSEDED by D140 §2 R1 and §2 R7

§2 R10 closes with:

> Q24's second `Accept` clause — *"linked from README and `init` output (U)"* — is a
> **link into `docs/user/`**, and the README edit that carries it is Q22's, not Q24's.
> Q24 reports the two paths; it does not edit `README.md` …

**D140, ruled later the same day, moves that edit to a different row and states
why in ordering terms this record did not have in front of it.** D140 §2 R7
requires `README.md` to gain a `## Documentation` section **this wave**, one line
per page D139 places, immediately before `## License`; D140 §2 R1 amends Q24's
`Accept` row 1 to name that section explicitly. The reason is not preference:

> Q24 is reachable this wave (`after Q20,Q21`, both in flight) while Q22 is not …
> `TODO.md` puts Q22 after Q30/Q31, and Q65 is a precondition of Q31 — so the row
> owning README is downstream of the publication a true README protects.

So the sentence *"the README edit that carries it is Q22's"* would have left six
pages written this wave unreachable from the front door at the exact moment the
repository goes public, and would have held Q24 — plus the README halves of Q23,
Q25, Q26 and Q27 — open until after the flip for a reason unconnected to their
own work.

**What governs, for the next reader of Q24:**

| clause | status |
|---|---|
| *"Q24 … does not edit `README.md`"* | **STANDS.** Both records agree; §2 R9's presence-surface trap is the reason, and D140 §2 R6 restates it as an executable prohibition on the lane that does edit the file. |
| *"the README edit that carries it is **Q22's**"* | **SUPERSEDED.** It is `Q248`'s — the README-currency row D140 §2 R5 mints and §2 R7 loads with the `## Documentation` section. `Q248` landed in this wave; `README.md`'s `## Documentation` section exists. |
| the delegation table (§2.1 → `vault-theft.md`, and so on) | **STANDS**, unchanged, and D140 §5 row 1 depends on it. |

Recorded rather than rewritten, because the paragraph was correct about the trap
and wrong only about the row — and a reader who meets the corrected sentence
without the reason will re-derive the same mistake the next time a README edit
needs an owner.

### §C R2 — Every line number this record cites into `docs/threat-model.md` is stale, and the work that invalidated them is this record's own subject

Q21 finalized `docs/threat-model.md` in this wave: **595 → 2 088 lines,
+1 522/−28**. No byte inside the frozen block changed; the mandated header and
sign-off rewrite added twelve lines *above* it, and §2's ten threat sections were
written below. That is enough to move everything.

**Measured at this addendum's own insertion — 28 locator instances on 27 lines,
20 in this record's prose and 8 inside captured command output:**

| what it points at | where it now is | this record's sites |
|---|---|---|
| the P3 inside the freeze, *"**What breaks if it is false.** Authorship binding."* — `:393` | **`:405`** | `:23`, `:24`, `:130`\*, `:393`, `:667`, `:904`, `:1002` |
| the P4 site, `## 2.3`'s receipt-class quote — `:450` | **`:699`** (Q21 rewrapped it; the P4 is **fixed**, not merely moved) | `:46`, `:132`\*, `:421`, `:685` |
| the P2 site, `## Positioning` — `:14` | **`:23`** (Q21 fixed the P2; the count went 1 → 0) | `:129`\*, `:162`, `:178`, `:681` |
| the M0 sign-off — `:23` | **`:30`** (the heading; a lane reported `:34` and central re-measurement gave `:30`) | `:224`, `:708`\*, `:1006` |
| the frozen block's BEGIN / END markers — `:38` / `:409` | **`:50` / `:421`** | `:229` (both, on one line) |
| the frozen block's content range — *"lines 39–408"* | **lines 51–420** | `:25`, `:148`, `:230`, `:235`\*, `:688`, `:701`\* |
| the second-run P3/P4 pair — `:394` / `:451` | moved with the rest | `:167`\*, `:168`\* |

\* inside a fenced capture. Those eight are **dated evidence and stay as
captured** — a capture rewritten to today's numbers stops being a capture. The
twenty in prose are the ones that mislead.

Two of the twenty are worth naming individually:

- **`:701`** is the classification reason §2 R4 specified **verbatim** for
  `scripts/check-copy-style.py`, with `lines 39-408` and `docs/threat-model.md:23`
  inside it. Q21's own mandated growth falsified both **inside the same wave**.
  The script's entry was corrected centrally and now cites the
  `<!-- BEGIN/END frozen-security-assumptions -->` **markers**, which are what the
  drift test actually reads; §2 R4's text here is left as ruled, with this
  addendum as the pointer.
- **`:1034`** is not in the table because it points at a different file, and it is
  stale in the same way: it cites `scripts/check-copy-style.py:199` for P6's
  tail-exclusion class, which is `:227` after the central `docs/user/` admission.

**The general rule this wave learned, and the reason it is written into a
decision record rather than left in a report:**

> **Cite the markers and the section numbers. They are stable. Do not cite line
> numbers into a file whose own mandated growth invalidates them — least of all
> from the record that mandates the growth.**

The markers are stable by construction (the drift test finds the block by them,
not by offset); `## 2.1`, `## 2.3` and `## Positioning` are stable because the
section list is asserted by `every_m4_threat_section_is_enumerated`. Line numbers
have neither property and nothing in the tree checks them: `CITATION_SCAN`
resolves decision and task **ids**, and no checker anywhere resolves a
`path:line`. This is not a rule invented for this addendum — the orchestrator
had already re-cited `scripts/check-copy-style.py`'s `threat-model.md` entry by
marker for exactly this reason, hours after §2 R4 specified it by line.

Whole-tree measurement, so the scope is on the record: **30 `path:line`
citations into `docs/threat-model.md` exist in the tree; 28 are stale and they
sit in 7 files** — this record, `D40`, `D42`, `D50`, `D73`,
`docs/format/Q14-freeze-gate-plan.md` and
`docs/reviews/pre-public-scrub-worktree.md`. The only two that resolve
(`TODO.md` and `tasks/R.md`, both at `:1958`) were written this wave, after the
growth. `D40`, `D42` and `D50` all cite `:419` for `## 2.1 Vault theft`, which is
now **`:441`**; `D73` cites `:447` for the wallet-linkability paragraph, which is
now inside `## 2.3` opening at **`:692`**.

**This addendum obeys its own rule, and says so rather than being caught at it.**
Every new number above is given as a **dated measurement taken 2026-08-17**, and
every one is paired with the stable handle that will still find the thing when
the number stops working — the marker pair for the frozen block, `## 2.1` /
`## 2.3` / `## Positioning` / `## Sign-off record` for the sections, and the
quoted sentence for the P3. A later reader who finds a number wrong should reach
for the handle beside it and **not** repair the number: the numbers are here to
show the size of the drift, not to be maintained.

### §C R3 — §1.2's file sizes are character counts labelled as bytes

Minor, and recorded because §1.3 of this same record documents exactly this
mistake about the frozen block. §1.2's capture headers read
`=== threat-model.md (31547 bytes, 595 lines) ===` and
`=== security-assumptions.md (28427 bytes, 492 lines) ===`. Measured against the
same blobs: **31 767 and 28 601 UTF-8 bytes**; 31 547 and 28 427 are the
**character** counts, and the ~0.7 % gap is em and en dashes. Nothing in §2
depends on either number — which is precisely why a record whose §1.3 is about
this distinction could carry it in its own header. The same defect is live in
`TODO.md`'s Q12 row (*"21 465 bytes"*, measured 21 612) and in
`scripts/check-traceability.py`'s freeze-boundary success message (*"2175 bytes
of rule text"*, measured 2 197); all three are on the instrument ledger.
