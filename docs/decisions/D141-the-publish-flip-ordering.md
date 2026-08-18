# D141 — The publish flip's ordering: the cycle is real, it is created by ONE wrong edge, and that edge is a misquotation of D72's own ruling sentence

- **Status: RESOLVED. The lean is OVERTURNED IN BOTH HALVES, and it is overturned
  by experiment rather than by preference.** The lean was *"split Q22 the way D140
  split the README out as Q248 … then invert the `after Q65` edges on
  Q242/Q243/Q244."* **Half one does not break the cycle**: re-pointing Q65 at a
  new pre-flip half of Q22 leaves `Q31 → Q65 → Q28 → Q22 → Q31` standing, because
  `TODO.md:814` makes **Q28** *"after … Q22 …"* too and the lean never names it —
  there are **two** paths from Q65 to Q31, not one, and Q22 sits on both.
  **Half two creates a NEW cycle**: inverting Q244 gives `Q31 → Q65 → Q244 → Q31`,
  since `TODO.md:829` already makes Q244 *"after Q1, Q65, Q31"*.
- **The arm nobody listed, and the one this record takes: the cycle is not a
  contradiction between two true facts — one of the four edges is WRONG AS
  RECORDED, and it has been wrong since the day it was written.** D72 §2 R6's
  ruling sentence reads, verbatim at `docs/decisions/D72-…:535-536`: *"Q65 is a
  **precondition** of **Q31's release execution** and Q34's gate."* **Q31 does not
  perform a release execution.** Its `Do` says *"publish a **draft** release"* and
  its `Accept` row 1 says *"A **dry-run** tag produces a complete signed **draft**
  release"* (`tasks/Q.md:537,539`). Every clause of Q31 was measured against the
  flip and **not one requires a party without repository access to obtain
  anything** — including the crates.io clause, which D72 §2 R8 itself rules to
  *"no real publish at M4"* (`:560`). The release *execution* — *"complete the
  Q31 checklist, **publish the release**"* — is **Q34's** (`tasks/Q.md:571`).
  Read as D72 actually ruled it, **the Q31 edge does not exist and there is no
  cycle at all**: no row split, no inversion, nothing.
- **The mechanism that flattened it is a citation whose range starts two lines
  after the words that scope it.** Both sites that carry the ruling forward —
  `TODO.md:822` and `tasks/Q.md:930` — cite `docs/decisions/D72-…:514,537-539`.
  Line **535** is where *"Q31's release execution"* is written; the cited range
  **begins at 537** and covers the trigger-firing clause and the alternatives
  lead-in instead. Two independent transcriptions of a ruling, both pointing at a
  range that excludes the qualifier, both reading *"precondition of Q31"*.
  D140 §1 then inherited it as an unqualified chain (`D140-…:9`).
- **`TODO.md:36` rule 7's *"(verified acyclic)"* is unverified and has been
  false for some time.** The string `acyclic` occurs **exactly once in the whole
  tree** (that parenthetical), it was written in the tracker's **first** commit
  `0efdeee` (2026-07-27, at 219 tasks), and **nothing has re-checked it since**:
  `check-traceability.py`'s seven checks (`:1552-1560`) never parse an `after`
  list, and no other reader of `TODO.md` does either. Built and run for this
  record over today's **678 live task rows / 1 279 edges**, the recorded order
  already contains **one live cycle**: `U13 → U14 → U13` (`TODO.md:401,402`).
  The tracker has been asserting a property nobody measured, at 3× the row count
  at which the assertion was made.
- **Date: 2026-08-18**
- **Owning task: Q65.** Rulings touch `TODO.md` rule 7 and the rows Q22, Q28,
  Q31, Q34, Q65, Q242, Q243, Q244, plus `tasks/Q.md`'s matching entries and a
  dated addendum on D72 §2 R6. **One new row is described in §2 R5 without an
  id — ids are assigned centrally.**
- Related: **D72 §2 R5/R6/R8** (the channel, the ruling amended here, the
  crates.io scope that makes Q31 flip-independent), **D71 §2 R3/R5** (the exact
  verify command Q22 copies rather than derives, and the README pin),
  **D140 §2 R5/R7** (Q248, the README precedent the lean invokes — and the
  103-minute false-window class that argues against splitting Q242),
  **D125 / rule 8** (why no acyclicity checker is minted here),
  **D138 / Q239** (the CI budget, examined and refused as a precondition in §1.6).

---

## 1. The measurement

Everything below was re-measured for this record. Where the brief I was given
disagrees with the tree, the tree is quoted and the brief is corrected at the site.

### 1.1 Rule 7's acyclicity claim has no verifier, and never had one

`TODO.md:36`, verbatim:

> 7. **Deps discipline**: … Where prose and this file disagree on ordering,
> **the `after:` lists on the checkbox lines here are the authoritative build
> order** (verified acyclic).

- `grep -rn "acyclic"` over the tree (excluding `target/`) returns **exactly one
  line**: `TODO.md:36`. No script, no test, no decision record contains the word.
- `git log --reverse -S "verified acyclic" -- TODO.md` returns a single commit:
  **`0efdeee`, 2026-07-27 14:49:59 +0100, "P4: task tracker (219 tasks…)"**. The
  claim is as old as the tracker and was made at **219** rows.
- `scripts/check-traceability.py` registers seven checks (`:1552-1560`:
  `freeze-boundary`, `matrix`, `decisions`, `task-citations`, `task-entries`,
  `decision-owners`, `decision-index`). `grep -n "after" scripts/check-traceability.py`
  returns eleven lines, **all** of them English prose in comments or the word
  *"afterwards"*. Nothing parses an ordering list.
- The complete set of files that open `TODO.md` at all is
  `scripts/{wasm-bitmatch.sh, check-traceability.py, local-gate.sh, check-ci-paths.py}`,
  `crates/antseal-core/tests/{manifest_schema.rs, tamper_completeness/mod.rs}`,
  `crates/antseal-cli/tests/seal_command.rs`, `.github/workflows/{ci.yml, ci-always.yml}`.
  In every one, `TODO.md` is a path constant, a comment, or a freeze-boundary
  subject. **No consumer of the ordering exists.**

### 1.2 The graph, built and run

Parser: match `^- \[( |x)\] (?:~~)?\*\*(ID)\*\*`, then extract every maximal run
after the token `after` composed only of ids, ranges (`–`/`-`) and separators
(`,` `/` `+` `;` `and`). Script preserved at
`docs/decisions/D141-…` §6 so a later wave does not rebuild it.

| figure | value |
| --- | --- |
| checkbox rows matched | **818** (678 task + 140 decision-register) |
| live task rows per `check-traceability.py` `task-entries` | **679 rows (678 live + 1 struck)** — the struck `~~**P18**~~` at `TODO.md:428` carries no checkbox and is correctly outside the parse |
| rows carrying an `after` run | 610 |
| rows carrying none | 208 |
| rows carrying more than one `after` run | 17 |
| edges | **1 279** |
| dangling predecessors | 3 — `A11→P18`, `P25→P18` (the struck row), `Q113→M2` (a milestone token, a parse artefact) |
| **cycles in the recorded order today** | **1** |

The live cycle is `U13 → U14 → U13`:

- `TODO.md:401` — `**U13** … — after U2,U3,U9,U11,**U14** + S12 ✅ 2026-08-02`
- `TODO.md:402` — `**U14** … — after U2,U3,**U13(interface)** + S8 ✅ 2026-08-02`

Both are ✅, so it blocks nothing; it is quoted because it **falsifies rule 7's
parenthetical as a live property** and because `U13(interface)` is the tracker
already hedging an `after:` entry that rule 7's own text says belongs in Notes.

### 1.3 The four edges, as actually recorded — two brief figures corrected

| row | `TODO.md` checkbox line | `tasks/Q.md` `Deps` |
| --- | --- | --- |
| Q22 | `:808` — *after Q20,Q30,Q31* | `:434` — *Q20, Q30 (verification instructions), Q31 (distribution channel)* |
| Q28 | `:814` — *after Q20,Q21,Q22,Q23,Q24,Q25,Q26,Q27 + R25,U31* | `:498` — *Q20, Q21–Q27* |
| Q30 | `:816` — *after Q1* | `:524` |
| Q31 | `:817` — *after Q1,Q30 **+ R25,R26*** | `:535` — *Q1, Q30; P: … (P2); R: … (R25/R26)* |
| Q34 | `:820` — *after Q13,Q21,Q28,**Q31–Q33*** | `:569` — *Q13, Q21, Q28, Q31, Q32, Q33* |
| Q65 | `:822` — *after Q22,Q28,Q27* | `:932` — *Q22 (README/install/product-limits), Q28 (copy audit), Q27 (format-stability policy)* |

**Two corrections to the brief.** It gives Q31 as *"after Q1,Q30"* — the row also
carries **`+ R25,R26`**. It gives Q34 as *"after Q13,Q21,Q28,Q31"* — the row reads
**`Q31–Q33`**, an en-dash range expanding to Q31, Q32, Q33, which is what makes it
agree with `tasks/Q.md:569`. Neither correction changes the ruling; both change
what a later reader will find when they look.

**Brief fact 4 is confirmed exactly.** `Q65` appears in **no** `after` list and
**no** `Deps` line of Q31 or Q34. The D72 R6 edge is recorded only *on Q65's own
row*, as a statement about Q65 — on the one row that cannot enforce it.

### 1.4 The cycle, and the fact that it has exactly one cause

Injecting D72 R6 as the two sites transcribe it (`Q31 after Q65`, `Q34 after Q65`):

```
D72 R6 written in on Q31 AND Q34 : 1 new cycle
    Q31 -> Q65 -> Q22 -> Q31
```

Enumerating **all** simple paths Q65 → Q31 in the recorded graph gives **two**,
and `Q22` lies on both:

```
Q65 -> Q22 -> Q31
Q65 -> Q28 -> Q22 -> Q31
```

Paths `Q65 → Q34`: **zero**. The Q34 half of D72 R6 can be written in today at no
cost:

```
D72 R6 on Q34 ONLY : 0 new cycles
```

So the entire contradiction is carried by **one** edge, and that edge is the one
D72's ruling sentence does not support.

### 1.5 Q31 measured against the flip, clause by clause

`tasks/Q.md:532-544`. For each clause: does discharging it require a party
**without repository access** to obtain something?

| Q31 clause | needs a public repo? |
| --- | --- |
| *"publish a **draft** release containing artifacts, hashes, the wasm build hash, and a release-notes template"* (`:538`) | **No.** A draft is not the distribution act; nobody is asked to fetch it. |
| Accept 1 — *"A **dry-run** tag produces a complete signed draft release; wasm hash identical across two independent builds"* (`:540`) | **No.** Both builds and the signature are the maintainer's; D71 §2 R1 (`:358`) puts signing **local** and keeps the secret key out of CI. |
| Accept 2 — versioning doc committed | **No.** A committed file. |
| Accept 3 — release checklist; *"crates.io decision recorded and **executed**"* | **No.** D72 §2 R8 (`:560`) rules **no `antseal*` crate is published to crates.io as part of the M4 release**, on four independent grounds — one of which is that a publish *"routes around Q65"*. Executing that decision is **recording** five placeholder names, their owner, date and `0.0.0` status, and setting a review date. Zero public acts. |
| Accept 4 — runner image pinned, glibc floor asserted | **No.** A CI property. |
| Accept 5 — *"Licence text reaches the DEPLOYED page artifact"* | **No.** The page is already public and live at `https://antseal.org/`; repository visibility is not in the path. |

**Not one clause needs the flip.** The clean-machine clause that *does* —
*"zero repo-checkout resources (released artifacts + hosted page only)"* — is
`tasks/Q.md` Q34 clause (b), and D72 §2 R6 quotes it from Q34, not from Q31.

**On the draft-visibility question the brief raises**: I did not measure GitHub's
draft-release semantics and I will not assert them. Creating a draft to observe
it is a write against the live repository, which is outside this lane's authority,
and hosted CI cannot be used to probe anything (§1.6). **The argument does not
need it**: whatever a draft's visibility is, no Q31 clause asks an outsider to
read one.

### 1.6 The CI-dispatch objection, examined and refused as a *precondition*

There is a real reason Q31 is hard today that D72 R6 never mentions, and it must
be dealt with rather than ignored: **hosted CI refuses every job.**
`tasks/Q.md:2911` (Q239): *"3 324 weighted Actions minutes were spent
2026-08-01→15 against a 3 000 allowance, and it is now exhausted"*; the refusal
signature is *"19/19 jobs, `steps == []`, `runner_name: ""`, 7 s wall"*.
`docs/decisions/D138-…:335` puts the post-fix cadence at **~2 900 against 3 000**,
so it recurs. Q31's Accept row 1 needs a runner. And
`docs/reviews/pre-public-scrub-github-side.md:481,615` measures that going public
makes *"Actions minutes … unmetered on standard runners"*.

**This does not make Q65 a precondition of Q31, and the distinction is the whole
of R1.** `docs/ci-verification.md:1827` names the remedies already:

> Restoring dispatch is a maintainer action: **raise the spending limit, wait for
> the monthly reset, or reduce what the workflow spends**.

Three remedies, none of them the flip; a fourth (the flip) was found later. A
precondition is what makes a successor **impossible**, not what makes it
**cheaper** — and that is exactly the test D72 R6 applies to Q34 (*"the gate
cannot be discharged as specified until the repository is public"*, `:529-530`).
Q34 meets it: a private repository cannot serve an anonymous third party at all.
Q31 does not: it is budget-blocked, monthly, with four exits. Recorded in R7 so
the next reader does not re-derive the edge from the budget and reintroduce the
cycle by a different door — and §1.9's margin test shows the ruled edit set stays
acyclic even if they do.

### 1.7 What Q22 still owes that genuinely needs Q30 or Q31

`tasks/Q.md:436` (`Do`) asks for install instructions *"including binary signature
verification (sha256sums + minisign/cosign steps)"* and *"the zero-install verifier
story with the canonical URL"*, plus the limits/disclosure model and *"Link every
other doc page"*.

- **The distribution channel is already decided**, not built: D72 §2 R5 (`:506`),
  *"The channel is GitHub Releases, single authoritative source"*. Q22 needs the
  fact; the fact exists. Q31 does not produce it.
- **The verify command is already written out**: D71 §2 R3 (`:407-425`) gives the
  exact human command, `-H` mandatory, `-P` inline, with the key itself as the
  placeholder `RW<...56 characters...>` and the expected output quoted verbatim
  from `minisign.c:556-557`. Q22 copies it.
- **The one field Q22 genuinely cannot write before Q30** is that 56-character
  public key. Q30 (`TODO.md:816`, *after Q1*) lies on no cycle path, so this
  record leaves the `Q30` edge exactly as it is.
- **The doc-linking half is already satisfiable**: `ls docs/user/` returns six
  pages (`format-stability`, `funding-your-wallet`, `timestamp-authorities`,
  `vault-loss`, `vault-theft`, `wallet-hygiene`), and Q248 already landed the
  README `## Documentation` section linking all six plus the threat model
  (`TODO.md:833`).
- **Q22's own `Accept` row 2 defers its proof downstream**: *"Install-and-verify
  instructions proven on a clean machine **during the Q34 gate**"* (`tasks/Q.md:439`).
  A clause verified by a successor is the textbook rule-7 *"consumer, not a dep"*
  case — the successor is Q34, and it is already `after Q31`.
- **The precedent for R3 is already in the tree, on Q31's own neighbour.**
  `tasks/Q.md:524` reads `Deps: Q1 (**Q31 is the consumer of the signing step**);
  **after Q245**`. The registrar who wrote Q30's `Deps` line applied rule 7's
  second clause to **Q31 by name** on the adjacent M4 row. R3 does to Q22 exactly
  what Q30's entry already does. *(That line also carries `after Q245` while
  `TODO.md:816` reads only `after Q1` — a live `Deps`/`after` divergence; benign,
  Q245 is ✅, routed in §5.)*

So the brief's suspicion is confirmed and sharpened: **Q22's `after Q31` was never
a build dependency.** It is an informational one, its subject was ruled in D72
five days ago, and rule 7's own second clause says where such a mention belongs.

### 1.8 What `OWED_PRESENCE` actually enforces: nothing red

Registered at `scripts/check-copy-style.py:166-179`; enforced at `:455-491`;
domain `PRESENCE_SURFACES = ("README.md",)` at `:230`.

Run flagless at HEAD (`REAL_EXIT=0`), the output is three lines, and the shape is
the finding:

```
check-copy-style: registered debt — README.md: 'limit-exclusive-possession' NOT YET STATED — owed by Q22 (M4) …
check-copy-style: registered debt — README.md: 'compelled-disclosure' NOT YET STATED — owed by Q22 (M4) …
check-copy-style: ok — 20 product-copy file(s) … the required positioning clauses (P7, 2 registered debt(s) above) …
```

At `:468-478` a missing clause that **is** registered appends to `notices`, not to
`found`. **A registered debt cannot redden anything.** The only red the register
can produce is the inverse, at `:482-491`: a debt whose clause has since been
*stated* and whose entry survives — a staleness guard on the register, not on the
debt.

**Consequence for this decision.** The two debts are not a mechanical gate on the
flip. Their force is entirely the prose of blocker **B2**
(`docs/reviews/pre-public-scrub-worktree.md:178`), whose own decisive argument is,
verbatim at `:205-208`:

> Second — and this is the decisive one — **Q65's own `Deps` line already gates
> it**: *"Q22 (README/install/product-limits), Q28 (copy audit), Q27
> (format-stability policy)"*. Q22 has not landed.

**B2's decisive reason is the edge under review.** It is not independent evidence
for the ordering; it is the ordering, quoted back. That does not make B2 wrong —
a README missing two of MVP-SPEC.md line 28's required clauses is a real defect on
the most-read file a public repository has — but it means the *ordering* claim
must stand on its own, and the only thing it needs is that **the two clauses be
written before the README is published**. That is one paragraph, and it does not
require Q22's install half, which is what §2 R3 acts on.

### 1.9 Q242, Q243 and Q244 are three different shapes, and "invert all three" is wrong for two of them

| row | recorded edge | what its own prose says | correct shape |
| --- | --- | --- | --- |
| **Q242** `TODO.md:827`, `tasks/Q.md:2959` | *after Q65* | *"the visibility flip this must land **with**, not after"*; *"Ordering is the whole row"*; and the mechanism *"**cannot be enabled before the flip and must be enabled as part of it**"* — GitHub's private-vulnerability-reporting endpoint returns **404** on a private repository | **co-timed** — not before, not after |
| **Q243** `TODO.md:828`, `tasks/Q.md:2974` | *after Q65* | *"the flip that makes the artifact publicly downloadable"*; the live `devnet-e2e-evidence` artifact is 52 269 B retained to 2026-11-10, public the moment visibility flips | **inverted** — strictly before |
| **Q244** `TODO.md:829`, `tasks/Q.md:2989` | *after Q1, Q65, Q31* | *"the mitigations that keep this from being urgent are exactly the ones Q65's flip removes"* | **inverted, and its Q31 edge is the wrong direction too** |

**Q243's edge is contradicted inside Q65's own entry.** `tasks/Q.md:939`, Q65
finding 4, verbatim: *"`devnet-e2e-evidence` (52 269 B, retained to
**2026-11-10**) becomes publicly downloadable the moment visibility flips,
**which is why Q243 must land first**"*. Q65 says Q243 precedes it; Q243 says it
follows Q65. Two entries in **one file** stating opposite directions for one edge.
This is stronger than the brief's framing, which located the contradiction in
Q243's own prose.

**Q242 cannot be inverted, and that is measurable rather than aesthetic.** Its
`Accept` row 2 is *"Private vulnerability reporting is **enabled**, verified by the
API returning enabled rather than 404, **in the same window as the visibility
change**"*. A `before Q65` edge makes that clause unsatisfiable by construction.
Nor should it be split: the pre-flip half would be a `SECURITY.md` naming a
reporting route that **returns 404 until the flip**, i.e. a front-door document
that is materially false for a window — precisely the class D140 measured at
**103 minutes** and priced as a blocker. Q242 is a genuine same-act row.

**Q244 carries a second wrong edge.** Its dependence on Q31 is annotated *"the
release workflow, whose actions are the highest-value targets"* — that is an
obligation **on** Q31 (pin the actions it adds), not a predecessor **of** Q244.
Today's subject is fully present: **9 distinct actions, 57 invocations across 8
workflow files**, none pinned. With the Q31 edge left in place, inverting Q244
produces `Q31 → Q65 → Q244 → Q31`.

**The experiments, run over the real graph. Cycle counts exclude the pre-existing
`U13↔U14`:**

```
0  BASELINE (as recorded today)                                        : 0
1  D72 R6 written in on Q31 AND Q34                                    : 1   Q31 -> Q65 -> Q22 -> Q31
2  D72 R6 on Q34 ONLY                                                  : 0
3  THE LEAN half one (split Q22; Q65 after the pre-flip half)          : 1   Q31 -> Q65 -> Q28 -> Q22 -> Q31
3b lean half one + Q28 ALSO repointed at the pre-flip half             : 0
4  THE LEAN half two (invert Q242/Q243/Q244) on top of the D72 edges   : 2   Q31 -> Q65 -> Q22 -> Q31
                                                                             Q31 -> Q65 -> Q244 -> Q31
5  THIS RECORD'S SET (R1-R6)                                           : 0
6  THIS RECORD'S SET + a future wave re-adds Q31 -> Q65 anyway         : 0
7  as 6, and Q242 inverted as well (worst case)                        : 0
```

Rows 5–7 are the margin: the ruled edit set is acyclic **and stays acyclic** if a
later wave re-derives the Q31 edge from the CI budget (§1.6) or decides to invert
Q242 after all. The lean has no such margin — row 3 shows it does not even solve
the stated problem, and row 4 shows it adds one.

### 1.10 The tracker can already express co-timing — the brief's hypothesis is false

The brief offers, as *"the more interesting finding"*, that a co-timed edge may be
*"an edge type the tracker may not be able to express"*. It is expressible, it is
already in use, and no vocabulary needs inventing:

- **`with/before`**, on checkbox lines, twice: `TODO.md:433` (`**P29** … — after
  P7, **with/before A3**`) and `TODO.md:482` (`**A51** … — after A3,
  **with/before A10**`).
- **`before <ID>`** — **57** occurrences of the token on checkbox lines. That is
  a raw count and the set is **unclassified**: a sample holds unmistakable
  ordering annotations *and* ordinary prose (`TODO.md:396`, *"was already false
  **before U8**"*). The ordering ones are not rare, e.g. `TODO.md:500`
  (`**A90** … — after A82, **before A21**`), `:469`
  (`**A38** … — **before A5,A11** (D53/D56)`), `:514` (`**A109** … — **before
  Q30/Q31** (D102)`), `:411` (`**U38** … — after U1; **before U11's wizard half**`).
- In `tasks/*.md` `Deps` lines the same forms plus *"**adjacent to Q74** … lands
  with or before A3"* (`tasks/Q.md:1270`) and *"**before Q30**"* (`tasks/Q.md:3004`,
  Q245 — a row that closed 2026-08-17 carrying a `before` edge).

**What is actually broken is rule 7, not the vocabulary.** Rule 7 grants authority
to *"the `after:` lists"* alone. Every `before` and `with/before` edge on a
checkbox line is therefore, on rule 7's own words, **outside the authoritative
build order** — 57 occurrences of ordering the protocol does not admit. That is a
gap in the rule's scope, and R7 closes it in the cheap direction.

### 1.11 Two re-measurements the ruling depends on being current

- **Q65's `/home/deb` scrub target is still growing.** `git grep -l "/home/deb"`
  → **24 tracked files**; `git grep -c` summed → **61 lines**. Q65's own entry
  (`tasks/Q.md:938`, re-measured 2026-08-17, *one day ago*) records **22 files, 53
  lines**, itself a correction of the scrub's 18/39 and the row's original 5. The
  series is 5 → 18/39 → 22/53 → **24/61**. It is not converging, which is an
  argument for R6's *"with a lint"* clause being the part that matters.
- **Q65's transitive upstream holds 94 rows, of which 7 are open**: `P3, Q1, Q22,
  Q28, Q30, Q31, U31`. **Q1 is the one worth naming.** `TODO.md:294` carries
  `⛔ BLOCKED BY PLAN … verified 2026-07-28: classic API and rulesets both 403
  "Upgrade to GitHub Pro or make this repository public" on a private repo on
  GitHub Free … **going public triggers Q65 first**`. Both premises are dead:
  the maintainer **upgraded the account to Pro** (`docs/ci-verification.md:2086-2088`)
  and Q65's own registrar note measures `rulesets` now returning **`200 OK []`**
  where it returned 403. So the row that transitively gates the flip is marked
  blocked-by-plan on a plan condition measured gone — and its blocker text states
  a **fourth** ordering loop (`Q1 ⛔→ going public → Q65 → Q22 → Q30 → Q1`) that
  the acyclicity claim also never saw. See §2 R8.

---

## 2. The rulings

### R1 — D72 §2 R6 is AMENDED: Q65 is a precondition of **Q34**, and NOT of Q31. The Q31 edge is refused and must never be written into an ordering surface.

**Authority:** D72 §2 R6's own ruling sentence, `docs/decisions/D72-…:535-536`,
*"Q65 is a **precondition** of **Q31's release execution** and Q34's gate"*, read
against `tasks/Q.md:537,539` (Q31 produces a **draft** on a **dry-run** tag),
`tasks/Q.md:571` (Q34 *"publish[es] the release"*) and D72 §2 R8 `:560` (no
crates.io publish at M4). §1.5 walks all six Q31 clauses.

**Edit — who: the registrar (or the D72 owner), in `docs/decisions/D72-release-targets-distribution-and-crates-io-scope.md`.**
Append a **dated addendum** under §2 R6 — do not rewrite the ruling, per this
project's amend-by-addendum discipline. It must say: the precondition attaches to
**Q34's gate** and to the **publication act Q34 performs**; it does **not** attach
to Q31, which builds the workflow and produces a draft; the flattened form
*"precondition of Q31 and Q34"* at `:37` and `:778` is superseded; and the reason
the flattening happened is that both downstream transcriptions cite `:514,537-539`,
a range that **excludes line 535**, where the scoping words are.

**Nobody may add `Q65` to Q31's `after:` list or `Deps` line.** If a future wave
believes Q31 needs the flip, the reason will be the **CI budget** (§1.6) and not
D72 R6 — and that reason has three recorded non-flip remedies
(`docs/ci-verification.md:1827`), so it is a *blocker note*, not an edge.

### R2 — Q34 gains the Q65 edge. It is the only new predecessor edge in this record.

**Who: the registrar.**
- `TODO.md:820` — `after Q13,Q21,Q28,Q31–Q33` becomes
  `after Q13,Q21,Q28,Q31–Q33,Q65`.
- `tasks/Q.md:569` — `Deps: Q13, Q21, Q28, Q31, Q32, Q33` becomes
  `Deps: Q13, Q21, Q28, Q31, Q32, Q33, **Q65 (D72 §2 R6 as amended by D141 §2 R1 — the clean-machine clause (b) cannot be discharged against a private repository)**`.

Measured cost: **zero cycles** (§1.4, experiment 2). Paths Q65 → Q34 in the
recorded graph: **zero**.

### R3 — Q22's `after Q31` is STRUCK. Q31 becomes a consumer annotation in Notes, per rule 7's own second clause.

**Who: the registrar.**
- `TODO.md:808` — `after Q20,Q30,Q31` becomes `after Q20,Q30`.
- `tasks/Q.md:434` — `Deps: Q20, Q30 (verification instructions), Q31 (distribution channel); …`
  becomes `Deps: Q20, Q30 (the 56-character public key — the one field this row cannot write without it; the command itself is D71 §2 R3); …` and the Q31 mention moves to a Notes line reading, in substance: *"**Q31 is a consumer, not a dep** (D141 §2 R3). The distribution channel this row documents is **ruled**, not built — D72 §2 R5, `docs/decisions/D72-…:506`, 'GitHub Releases, single authoritative source' — and the verify command is D71 §2 R3 verbatim, `:407-425`. This row's `Accept` row 2 is proven **downstream**, at the Q34 gate, which is already `after Q31`."*

This single edit removes **both** Q65 → Q31 paths (§1.4), because Q22 lies on both.
It is independent of R1: either alone breaks the cycle, and the record takes both
because each is separately true and the pair gives the margin in §1.9 rows 6–7.

**What this does NOT do:** it does not license publishing before the README's two
`OWED_PRESENCE` clauses are written. §1.8 measured that those clauses redden
nothing, so the obligation is carried by R4, not by an edge.

### R4 — Q65's dependence on Q22 is narrowed **in writing** to the two `OWED_PRESENCE` clauses, and no row is split.

**Who: the registrar.** `tasks/Q.md:932` — Q65's `Deps` entry `Q22
(README/install/product-limits)` becomes `Q22 (**narrowed by D141 §2 R4 to the two
registered `OWED_PRESENCE` clauses** — `limit-exclusive-possession` and
`compelled-disclosure` on `README.md`, `scripts/check-copy-style.py:166-179`; the
install-and-verify half of Q22 is **not** a precondition of the flip and is proven
at the Q34 gate)`. Mirror the narrowing in one sentence on `TODO.md:822`.

**Why narrowing rather than splitting.** Q22's problem is a wrong **edge**, not a
wrong **size** (§1.7). Splitting it mints a **third** row owning `README.md` after
Q248 and Q22 — D140 §2 R5's precedent was justified by a row that was *downstream
of its own subject*; that is not this. And §1.4 shows a split does not even solve
the problem unless Q28's edge is re-pointed too (experiment 3 vs 3b), so the lean's
instrument costs a row **and** an edit it never named. Narrowing costs one clause
and is checkable: the flip is permitted when
`grep 'registered debt' <(python3 scripts/check-copy-style.py)` returns **zero**
lines for `README.md`.

### R5 — Q243's edge is INVERTED. Q242's is NOT; it takes the tracker's existing `with/before` form. Q244's is inverted and its Q31 edge is re-homed.

**Who: the registrar**, except the Q31 `Accept` clause, which is Q31's owner.

**(a) Q243 — invert.** `TODO.md:828`: `after Q65, Q2` becomes `after Q2 · **before
Q65** (D141 §2 R5)`. `tasks/Q.md:2974`: `Deps: after Q65 (the flip that makes the
artifact publicly downloadable), Q2 …` becomes `Deps: after Q2 …; **before Q65**
— corrected by D141 §2 R5: Q65's own entry already says so at `tasks/Q.md:939`
(*"which is why **Q243** must land first"*), and this line said the opposite`.
Add `Q243` to Q65's `after:` list at `TODO.md:822`.

**(b) Q242 — co-timed, one row, no inversion and no split.** `TODO.md:827`:
`after Q65, Q21/Q23, Q22` becomes `after Q21/Q23,Q22 · **with/before Q65**`, the
form already used at `TODO.md:433` and `:482`. `tasks/Q.md:2959`: keep the
existing parenthetical — it is already correct — and add *"the `with/before` form
is deliberate and is D141 §2 R5(b): `Accept` row 2 requires the API to read
**enabled** *in the same window as the visibility change*, so `before Q65` is
unsatisfiable by construction, and a pre-flip split would publish a `SECURITY.md`
naming a route that 404s until the flip — the D140 §1 false-window class."*
**Q65's row gains no `after` entry for Q242**; the co-timing is recorded on Q65's
`Do` as an at-the-flip item beside finding 4's existing four.

**(c) Q244 — invert, and move the Q31 obligation onto Q31.** `TODO.md:829`:
`after Q1, Q65, Q31` becomes `after Q1 · **before Q65** (D141 §2 R5(c))`.
`tasks/Q.md:2989`: strike `Q31 (the release workflow, whose actions are the
highest-value targets)` from `Deps` and record that it is now a clause **on Q31**.
Add `Q244` to Q65's `after:` list. **Q31's owner adds one `Accept` row**: *"Every
`uses:` the release workflow introduces is SHA-pinned with a version comment at
the moment it is written, per Q244's rule — the release workflow never adds a
57th unpinned invocation."*

Measured: with the Q31 edge refused (R1), (a)+(c) are cycle-free; with it
**re-added**, they are still cycle-free (§1.9 rows 5–7). Under the lean's
formulation — inversion **with** the Q31 edge standing — (c) produces
`Q31 → Q65 → Q244 → Q31`.

### R6 — A new row: the flip's execution checklist. **Orchestrator assigns the id.**

Q65 today is a *decision* row wearing an *execution* row's clothes: its `Accept`
mixes a decision record, a scrub with a lint, a D61 §9 re-read and four
at-the-flip GitHub settings, and R5(b) now adds a co-timed sibling. The flip is a
**single irreversible act with a checklist**, and nothing in the tracker holds
that checklist in execution order.

**Description for the orchestrator.** Domain **Q**, milestone **M4**, size **S**.
*"The visibility flip's ordered execution checklist — the single act, its
pre-conditions, its at-the-flip items and its immediate-after items."*
`Deps: Q65 (this row IS Q65's execution half), Q242 (with), Q243 (before),
Q244 (before)`.
`Do`: one committed checklist, in execution order, naming for each item whether it
is **before**, **in the same act as**, or **immediately after** the visibility
change: the `/home/deb` scrub at HEAD with its lint (24 files / 61 lines and
growing, §1.11); the per-file `public`/`private`/`private-until-release` record;
the two `OWED_PRESENCE` clauses cleared (R4); Q243 landed; Q244's pins landed and
`sha_pinning_required` set; **then** the flip; **in the same act** Q242's private
reporting enabled and verified by API read-back, plus finding 4's four settings
(`homepage`, `topics`, fork-PR approval, the expiring artifacts); **immediately
after** the D61 §9 re-read and `git push main` **explicitly** — never
`--all`/`--mirror`, per Q65's own measurement that 35 local branches, a
`refs/original` backup and 61 unreachable commits stop being local the instant
either is run.
`Accept`: the checklist is committed **before** the flip; every item carries its
timing word; the post-flip audit records each item as done with its evidence; and
the flip itself is not taken until the checklist's pre-flip section is fully
ticked.

**Why a row and not a paragraph in Q65:** Q65's `Accept` is already five clauses
long and is the record of a *decision*; the irreversible act deserves an artefact
that exists **before** it and is auditable **after** it. The maintainer-consent
discipline is unchanged — this row does not authorise the flip, it sequences it.

### R7 — `TODO.md:36` rule 7's *"(verified acyclic)"* is STRUCK and replaced with the truth. No checker is minted this wave.

**Who: the registrar.** Replace the parenthetical with, in substance:

> …**the `after:` lists on the checkbox lines here are the authoritative build
> order**, together with the `before` and `with/before` forms used in the same
> position. **Nothing checks this order for cycles**; the claim *"verified
> acyclic"* stood from `0efdeee` (219 rows) to D141 (679 rows) unverified, and
> `U13`/`U14` (`:401`, `:402`) are a live 2-cycle, both closed. A ruling that
> creates an edge must state the cycle it does not create.

Two substantive changes: the false parenthetical goes, and the rule's **scope
widens** to admit the `before` / `with/before` forms it currently excludes
(§1.10). The widening is a statement about the **grammar**, not a claim that all
57 occurrences are edges — that set is unclassified, and §5 routes the sweep.

**A checker is refused here under rule 8 / D125.** Its subject is the
verification apparatus, it blocks no acceptance on the ship path, and this project
has measured what instrument-on-instrument waves cost. The finding, the parser and
the seven experiments go to `docs/instrument-ledger.md` (§5) so a later wave that
*is* pointed at instruments can build it in an hour rather than re-derive it.

### R8 — Q1's `⛔ BLOCKED BY PLAN` is stale on both of its premises and is amended, not carried.

**Who: the registrar.** `TODO.md:294` records the blocker as *"classic API and
rulesets both 403 'Upgrade to GitHub Pro or make this repository public' on a
private repo on GitHub Free"*. The account is **Pro** (`docs/ci-verification.md:2086-2088`)
and `rulesets` returns **`200 OK []`** (Q65's registrar note, 2026-08-17). Amend
the marker to state what is actually outstanding — **branch protection has not
been set, and whether a `PUT` succeeds is untested** (Q65's own words) — and
delete the *"going public triggers Q65 first"* clause, which is the fourth
ordering loop in §1.11 and is now false in its premise. **No new id**: this is a
status correction on an existing row.

### R9 — This document cannot land alone.

**Who: the orchestrator.** Creating `docs/decisions/D141-the-publish-flip-ordering.md`
puts `check-traceability.py` red until two files outside this lane's write scope
are edited in the same act:

1. **`docs/decisions/README.md`** needs a `| [D141](D141-the-publish-flip-ordering.md) | … | RESOLVED | 2026-08-18 |`
   row in ascending id order. `check_decision_index` (`:1383-1390`) takes the
   **glob** `docs/decisions/D*.md` as its domain and requires one index row per
   record; today it reads *"134 index row(s) against 134 record(s)"*.
2. **`TODO.md`'s decision register** needs a `- [x] **D141**` row, in the shape of
   `:1020` / `:1021` (D139/D140).

**Measured, not predicted.** Flagless `python3 scripts/check-traceability.py` was
**green at HEAD before this file was written** — all seven checks, *"134 index
row(s) against 134 record(s)"*, `REAL_EXIT=0`. Re-run after
writing it, the same command fails **by message**:

```
::error::check-traceability [decision-index] docs/decisions/README.md: D141 has a record
  (D141-the-publish-flip-ordering.md) and no row in the index. …
::error::check-traceability [decision-index] docs/decisions/README.md: D142 has a record
  (D142-d125-record-and-home.md) and no row in the index. …
check-traceability: FAILED with 2 problem(s).      REAL_EXIT=1
```

The other six checks stay green. **Note the second error is not this lane's**:
`D142-d125-record-and-home.md` is a parallel lane's record in the same shared
tree, and it needs its own two rows. Both records must be registered before the
wave's gate can be green, and neither lane can do the other's.

---

## 3. What was refused

1. **The lean's half one — splitting Q22 — is refused on experiment, not taste.**
   Executed exactly as briefed it leaves `Q31 → Q65 → Q28 → Q22 → Q31` standing
   (§1.9 row 3), because `TODO.md:814` makes **Q28** *after … Q22* and the lean
   never names Q28. To work it needs a second, unnamed edit (row 3b). It also
   mints a third row owning `README.md`, and Q22's actual defect is a wrong edge
   (§1.7), which R3 fixes with one strike.
2. **The lean's half two — inverting Q242/Q243/Q244 — is refused as a single
   instrument applied to three different shapes.** On top of the D72 edges it
   **adds** `Q31 → Q65 → Q244 → Q31` (§1.9 row 4). And for Q242 an inversion makes
   `Accept` row 2 unsatisfiable by construction: private vulnerability reporting
   **404s on a private repository**, so *"enabled … in the same window as the
   visibility change"* cannot be met by a row that must finish first. Inversion is
   right for Q243 and Q244 only, and R5 grants it there.
3. **Splitting Q242 into a pre-flip half is refused**, including as a
   consolation for (2). The pre-flip half would publish a `SECURITY.md` naming a
   route that 404s until the flip — a front-door document false for a window,
   which is the exact class D140 measured at **103 minutes** and this project has
   already paid for once.
4. **The brief's own hypothesis — that co-timing is an edge type the tracker
   cannot express — is refused as false.** `with/before` is in the ordering
   position on two checkbox lines today (`TODO.md:433`, `:482`) and `before <ID>`
   on 57. The defect is rule 7's **scope**, which admits neither; R7 fixes that
   instead of inventing vocabulary.
5. **Treating the exhausted Actions allowance as a Q65 precondition on Q31 is
   refused** (§1.6). `docs/ci-verification.md:1827` names three non-flip remedies;
   a precondition is what makes a successor impossible, which is the test D72 R6
   itself applies to Q34 and which Q31 fails.
6. **Any claim about GitHub draft-release visibility is refused as unmeasured.**
   Observing it needs a write against the live repository, and hosted CI refuses
   every job (a 3–5 s run with zero steps is a dispatch refusal and never a
   verdict). §1.5 is built so the ruling does not depend on the answer.
7. **An acyclicity checker is refused this wave** under rule 8 / D125 — its
   subject is the apparatus and it blocks no ship-path acceptance. The parser and
   the experiment harness go to the ledger so the refusal is cheap to reverse.
8. **Retiring the `U13 ↔ U14` cycle is refused as out of scope.** Both rows are
   ✅ and closed; unpicking a settled M1 ordering to satisfy a claim this record
   has just struck would be work created by bookkeeping. It is named in R7's
   replacement text as the known exception.

---

## 4. Falsifiers

1. **R1 falls** if any Q31 clause is shown to require a party without repository
   access to obtain something. The clause to watch is `Accept` row 3's *"crates.io
   decision recorded and **executed**"*: if D72 §2 R8 is ever reversed and a real
   `cargo publish` is ordered under Q31, that **is** an irreversible public source
   disclosure, the edge becomes real, and the cycle returns — at which point R3
   (already landed) is what keeps the graph acyclic.
2. **R1 also falls** if a release workflow cannot produce or hold a **draft** on a
   private repository at all, or if signing is moved into CI in a way that needs a
   public runner. Both are observable the first time Q31's dry-run tag is fired.
3. **R2 falls** if Q34's clean-machine clause (b) is ever relaxed — D72 §2 R6
   `:539-542` records that arm as available and **not chosen**; choosing it would
   dissolve the only surviving precondition and make Q65 an M4 row like any other.
4. **R3 falls** if Q22 is found to need something Q31 *produces* rather than
   something D71/D72 *ruled*. The likeliest candidate is the release-notes
   template or a versioned download URL shape; if either turns out to be text Q22
   must quote, the edge returns as a real one — and R1 is then what keeps the
   graph acyclic. **Both R1 and R3 would have to fall together** for the cycle to
   return, which is why this record takes both.
5. **R5(b) falls** if GitHub makes private vulnerability reporting configurable
   on private repositories, or if a `SECURITY.md` can name a route that is
   genuinely live pre-flip. Q242 then becomes an ordinary `before Q65` row.
6. **R7's replacement text goes stale** the moment a cycle other than `U13↔U14`
   enters the recorded order. The check is the §6 parser; anyone may run it in
   seconds, and a wave that lands ordering edits should.
7. **The whole record is falsified** if a `Deps`/`after` surface is found that
   this parse missed — in particular a `before`-form edge that is load-bearing and
   that §1.2's `after`-only graph therefore never saw. §1.10 counts 57 such
   occurrences and classifies none of them; **that is this record's largest
   unexamined surface**, and it is stated plainly rather than left implicit.

---

## 5. Found here, not this decision's subject

Routed per rule 8. Instrument-class findings take **no id** and go to
`docs/instrument-ledger.md`; product defects mint rows.

**To `docs/instrument-ledger.md` (no id):**

- **`TODO.md:36`'s *"(verified acyclic)"* is unverified and false.** One
  occurrence of `acyclic` in the tree; written in `0efdeee` at 219 rows; no
  reader of `TODO.md` parses an ordering list; `U13 ↔ U14` is a live 2-cycle at
  678 rows / 1 279 edges. Struck by §2 R7; the parser and the seven experiments
  are in §1.9 and §6 so a checker is an hour's work if a future instrument wave
  wants one. Pointer: `docs/decisions/D141-…` §1.1, §1.2, §2 R7.
- **Two downstream transcriptions of D72 §2 R6 cite a range that excludes the
  words that scope the ruling.** `TODO.md:822` and `tasks/Q.md:930` both cite
  `docs/decisions/D72-…:514,537-539`; *"Q31's release execution"* is at **:535**.
  This is the mechanism by which a scoped ruling became an unscoped one, and it
  is the stale-locator class. Pointer: §1 preamble, §2 R1.
- **`docs/reviews/pre-public-scrub-worktree.md`'s B2 table reports "785 task
  rows — 515 checked, 270 unchecked"** against `check-traceability.py`'s
  authoritative **679 (678 live + 1 struck)**. A fifth instance of the count-drift
  class, in the review that gates the flip. Pointer: `:186`, §1.2.
- **`docs/reviews/pre-public-scrub-worktree.md:205-208` makes B2's "decisive"
  argument circular**: it grounds the blocker in *"Q65's own `Deps` line already
  gates it"* — the edge D141 §2 R4 has just narrowed. B2's substantive half (two
  MVP-SPEC.md line 28 clauses missing from the README) is unaffected and stands.
  Pointer: §1.8.

**To the registrar as row amendments (no new id):**

- **`TODO.md:294` Q1's `⛔ BLOCKED BY PLAN` is stale on both premises** (account
  is Pro; `rulesets` returns `200 OK []`) and its text asserts a fourth ordering
  loop. Ruled at §2 R8 because Q1 sits in Q65's transitive upstream and the flip
  is a ship-path act — this is not instrument-class.
- **Q65's `/home/deb` figure has drifted again**: **24 files / 61 lines** today
  against the **22 / 53** recorded in the same entry one day ago. Fold the new
  measurement into Q65's finding 3 with its date; no new row. Pointer: §1.11.
- **Q30's two ordering surfaces disagree**: `tasks/Q.md:524` carries `after Q245`
  and `TODO.md:816` reads only `after Q1`. Benign today — Q245 is ✅ — but it is a
  live instance of the class rule 7 exists to arbitrate, found while measuring
  something else, and it is one row away from the ship path. Add `Q245` to
  `TODO.md:816`'s list, or record the omission. Pointer: §1.7.

**Time-sensitive, for the orchestrator this wave:**

- **A parallel lane is landing Q242's pre-flip artefacts while this record was
  being written** — `SECURITY.md` and `.github/ISSUE_TEMPLATE/` are untracked in
  the shared tree, alongside `scripts/sign-release.sh` and
  `scripts/verify-release.sh`. That makes §2 R5(b) operative **now** rather than
  next wave. At the moment I measured it, `SECURITY.md:11` reads *"**Use GitHub's
  private vulnerability reporting.** On this repository:"* and the file contains
  no occurrence of `404`, *"public repositor"*, *"once the repository"* or
  *"when the repository"* — i.e. as drafted it names a route that **returns 404
  until the flip**. **This is not a verdict on that lane**: the file is untracked,
  the lane is mid-work, and an interrupted lane's tree is not evidence. It is
  named because the sentence R5(b) exists to prevent is one edit away, and the fix
  is one clause — say when the route turns on. I did not touch the file; it is
  outside this lane's write scope.

**Named for the orchestrator, not routed:**

- **Q31 has no blocker marker although its `Accept` row 1 cannot be executed
  today** (hosted CI refuses every job, §1.6). Whether that warrants a `⛔` on
  `TODO.md:817` is a queue-management call, not a D141 ruling; it is named so the
  omission is deliberate rather than unnoticed.
- **57 `before`-position edges are unclassified** (§1.10, falsifier 7). Whether
  they are true ordering constraints, prose, or a mix has never been swept. If a
  wave ever builds the checker refused at §2 R7, this sweep is its first input.

---

## 6. The parser, preserved

Recorded so the measurements in §1.2 and §1.9 are reproducible without rebuilding
the tool, and so the checker refused at §2 R7 starts from working code.

```python
ROW   = re.compile(r'^- \[( |x)\] (?:~~)?\*\*([A-Z]{1,2}\d+)\*\*')
AFTER = re.compile(r'\bafter ((?:[A-Z]{1,2}\d+(?:\s*[–—-]\s*[A-Z]{0,2}\d+)?)'
                   r'(?:\s*(?:[,/+;]|and)\s*(?:[A-Z]{1,2}\d+(?:\s*[–—-]\s*[A-Z]{0,2}\d+)?))*)')
ID    = re.compile(r'([A-Z]{1,2})(\d+)(?:\s*[–—-]\s*([A-Z]{0,2})(\d+))?')
# edges[row] = set(predecessors); ranges F3–F12 expand within a domain;
# cross-domain "Q31–Q33"-style ranges expand, "A11→P18" style dangles are reported.
# Cycle detection: colour DFS, report stack[stack.index(v):] + [v] on a GREY hit.
```

**Known limits, stated so the next reader does not over-trust it.** It reads only
`after` runs, so the 57 `before`/`with/before` edges of §1.10 are invisible to it;
it treats `D<n>` references as non-task and drops them; and it accepts the `M2`
token at `TODO.md` Q113 as a dangling id rather than rejecting it. Three known
dangles, all benign, all listed in §1.2.
