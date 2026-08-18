# D140 — The README's front door, `init`'s output, and a Q22 that sits downstream of the publication it exists to protect

- **Status: RESOLVED. BOTH HALVES of the briefed lean are OVERTURNED, and the
  second is overturned as an ordering contradiction inside the register rather
  than as a matter of taste.** The lean was *"add a documentation-pointer line to
  `init`'s output to satisfy Q24, and leave `README.md` entirely to Q22."*
  **Half two cannot be executed as stated**: `TODO.md:801` makes Q22 *"after
  Q20,Q30,Q31"*, and `tasks/Q.md` Q65's Milestone line makes Q65 **a
  precondition of Q31**. The chain is therefore **Q65 → Q31 → Q22**: the row
  that owns `README.md` is *downstream of the publication event a true README is
  supposed to protect*. "Leave it to Q22" is operationally identical to
  "publish it false", which is exactly what the pre-public scrub's blocker **B2**
  forbade. **Half one is overturned on four measurements** — CLI nag copy is
  recorded as **U's, not Q's** (`tasks/U.md` U18 Notes, verbatim); **no
  resolvable pointer target exists** (zero `repository`/`homepage`/`documentation`
  fields in any manifest, the repository is private and 404s, and
  `https://antseal.org/` serves exactly one file); the insertion point's own
  header reads *"Two things to understand before you seal anything:"*; and
  `init` **already states** both facts in full rather than linking them.
- **The arm nobody listed, and the one this record takes: `init`'s human report
  has no committed golden rendering, and that is the finding.** None of the ten
  snapshots in `crates/antseal-cli/tests/snapshots/` contains it; every
  assertion over it is a substring or a shape. Adding a line today is free
  **because nothing watches it** — which also means **U32's freeze will not
  cover it**, since U32 freezes help text, `--json` schemas and exit codes by
  snapshot, and **`check-copy-style.py` reaches CLI copy only through the
  rendered golden snapshots by its own explicit design** (`:28-33`). So the
  loudest safety copy the product has — MVP-SPEC.md line 143's mandated
  loss/theft nag, on both of its venues — is outside the positioning lint
  entirely. **The snapshot is the precondition for any future edit to that
  text, including the lean's pointer.**
- **The measurement that prices the recurrence: 103 minutes.** `4cae455`
  (2026-08-17 00:04:06 +0100) wrote README's *"no LICENSE file exists yet and no
  manifest carries a `license` field … all rights reserved — until Q29 lands"*.
  `1830618` (2026-08-17 **01:47:05** +0100) landed Q29 — three licence-file
  pairs at the root, four in crates, `COPYRIGHT`, `license` on 7 of 7 crates,
  `deny.toml` un-stubbed — **did not touch `README.md`, and never named it in
  its commit message**. The paragraph was true for one hour and forty-three
  minutes. The same commit left **six further stale live claims in four other
  files**, and `dee7b2a` falsified README's *"648 tasks"* seven minutes later in
  a commit whose own subject line announces the new number.
- **Date: 2026-08-17**
- **Owning task: Q24** (whose Accept row 1 is amended here). The README work is
  ruled onto a **new row**, described in §2 R5 and §5 without an id — ids are
  assigned centrally.
- Related: D139 (venue and filenames for the six new pages — **not ruled here**;
  this record rules the links and deliberately names no filename), D65 (`--json`
  schema tiers — measured here to be `--json`-only), D134 §2 R3 (U32's three
  policy reservations, and the `message`-tier measurement this record had to
  re-take for a different surface), D6/Q29 (the licence set that falsified the
  front door), Q65 (the publish decision and the row that recorded B2), Q20
  (`scripts/check-copy-style.py`, its two registered debts and its scan design),
  U18 (*"CLI nag copy is U's"*), U32 (the CLI release freeze).

---

## 1. The measurement

### 1.1 What `init` actually prints

Run against the committed binary (`target/debug/antseal`, built 2026-08-17
00:46), `--network arbitrum-one`, passphrase on fd 0, `ANTSEAL_DIR` pointed at a
scratch vault. **Exit 0, stdout below, stderr empty.**

```
Vault created at <vault dir>.
Network: arbitrum-one.

Payment wallet address: 0x13d87ebf7900298Cd8E04fE191e461DA93F0bF71

To seal, this address needs two things:
  1. ANT tokens on Arbitrum One — they pay for the storage itself.
  2. A little ETH on Arbitrum One — it pays the gas for the payment transaction.

Acquire ANT on Arbitrum One and send it to the address above, then bridge or buy a small amount of Arbitrum One ETH for gas. Real funds move on this network, and a seal is permanent and paid once.

Two things to understand before you seal anything:
  LOSS  — lose this vault and its passphrase, and no one can ever reveal or restore your sealed works again. The sealed data itself stays safely unreadable. Run `antseal vault export` and keep the backup somewhere else.
  THEFT — whoever holds this vault (or an export) and the passphrase can decrypt every work you have ever sealed, retroactively and permanently. The ciphertexts are public and undeletable, and there is no key rotation. Treat the passphrase as a long-term, high-value key.

What a seal proves: that the holder of this vault possessed the content by the anchored time. Not authorship, and not exclusive possession — someone you shared with can seal the same work earlier and outrank you. Seal before you share.
```

Producers: `InitReport::render` (`crates/antseal-cli/src/init.rs:251-267`),
`funding_lines` (`:277-325`), `standing_warnings` (`:336-349`). The LOSS and
THEFT sentences are **not literals here** — they are
`crate::vault::bookkeeping::{LOSS_WARNING, THEFT_WARNING}`
(`crates/antseal-cli/src/vault/bookkeeping.rs:68-77`), shared with U18's
first-seal export nag so there is one author for both venues.

**Three observations that decide §2 R1 and §2 R2:**

1. **`init` does not link anything.** It *states* both failure modes in full.
2. The block's header is **`"Two things to understand before you seal anything:"`**
   (`init.rs:340`) and it is followed by exactly two items, a blank line, and a
   separate positioning paragraph. A third bullet under that header makes the
   header numerically false.
3. `init` prints **no URL and no path** of any kind. The only doc pointer
   precedent in the CLI's user copy is `crates/antseal-cli/src/error.rs:596`
   (`docs/config.md`), inside a config-parse error.

### 1.2 What freezes that text — per test, measured

| site | form | breaks if a line is added? |
|---|---|---|
| `tests/init_command.rs:693-705` | `text.contains(&report.address)`; a loop asserting every non-empty `funding_lines` entry is `contains`ed; `text.contains("LOSS") && text.contains("THEFT")`; `!text.to_lowercase().contains("notar")` | **no** — all substring/negative |
| `tests/init_command.rs:711-748` | `report.json()` key-by-key `assert_eq!`, plus a no-key-material scan | **no** — `render()` is not `json()` |
| `tests/init_command.rs:757-780` | spawned binary: `stdout.contains("Vault created at")`, `contains("Payment wallet address: 0x")` | **no** |
| `tests/init_command.rs:785-807` | spawned `--json`: stdout parses as one document; `stderr.contains("Payment wallet address")` | **no** |
| `tests/seal_command.rs:996-998` | `init::standing_warnings().join("\n")` contains both constants | **no** |
| `tests/machine_mode.rs:480,856-872` | `fixture_init_report().json()` feeds the committed `[init] result` envelope | **no** — JSON only |
| `src/vault/bookkeeping.rs:349-350` | unit test on the seal nag | **no** |

**No `assert_eq!` over the rendered human text exists anywhere, and no
`render().len()` or line-count assertion exists** (`grep -rn "render()\.len()"`
over `crates/antseal-cli/` returns nothing).

**The ten committed snapshots, and what each covers:**

`cli-errors.display.txt` (error display table) · `cli-surface.help.txt`
(`--help`) · `json-envelopes.txt` (`[init] error` at `:1` and `[init] result` at
`:25` — the **`--json` document**) · `list-anchor-nags.txt` · `list-report.txt`
(`list`) · `redaction-view.txt` (R19) · `reveal-consent.txt` (U29) ·
`seal-degraded-report.txt` · `show-units.txt` (U27) · `status-report.txt`.

Two greps establish the gap:

- `grep -rln "Vault created at\|Two things to understand\|To seal, this address needs"` over
  the tree matches **exactly two files**: `crates/antseal-cli/src/init.rs` and
  `crates/antseal-cli/tests/init_command.rs`. No snapshot.
- `grep -rn "LOSS \|THEFT\|lose this vault" crates/antseal-cli/tests/snapshots/`
  exits **1** — no match. So **neither** venue of the spec-mandated nag (`init`'s
  closing message, `seal`'s first-seal nag) appears in any golden rendering.

**`init --json` IS frozen by a committed snapshot. `init`'s human report is
not.** That asymmetry is the whole of §2 R2.

### 1.3 The tier question: D65 does not reach this surface

D134 §2 R3 measured that the error `message` sits in D65's freely-rewordable
tier. That measurement is about a **different member of a different document**
and does not transfer. The file:line that decides the present question:

- `crates/antseal-cli/src/machine.rs:49` — the section heading is
  **"Schema stability — the three tiers (D65 §3; **this is the M3 home**)"**, and
  `:51` opens *"The `--json` document has three regions…"*.
- `:63` tier A scope = `result.report` on `verify --json`.
  `:64` tier B scope = the wrapper keys plus `class`/`exit_code`/`message`
  inside `error`. `:65` tier C scope = *"everything else inside `result`"*.
- D65's own title is *"`--json` schema stability"*, and `grep -in "human"` over
  the record returns one hit — `:446`, about the error `message`.

**`init`'s human-readable stdout is in no tier, because D65 partitions the
`--json` document and nothing else.**

U32 is the other candidate freeze and it does not reach it either. `tasks/U.md`
U32's `Do`: *"freeze and document the exit-code table, every `--json` schema,
and all help text (snapshot baselines become compatibility promises)"*, and its
Accept row 3: *"release binary's `--help` snapshot matches the frozen canonical
surface exactly"*. `init`'s human report is not the exit-code table, not a
`--json` schema, and not help text — **and there is no snapshot baseline to
promote into a promise.**

**Therefore: adding a line to `init`'s human report today is FREE — not a
frozen-surface event, not snapshot churn, and it reddens no test.** It is free
because the surface is unobserved, which is a defect and not a licence.

**And the copy lint cannot see it either, by its own recorded design.**
`scripts/check-copy-style.py:28-33`: *"CLI copy is scanned through its
**rendered golden snapshots**, not through `crates/antseal-cli/src/**.rs` …
U31's single catalog module of user-facing strings does not exist yet — when it
lands it becomes a literal entry in `COPY_SCAN`."* The scan roots are
`README.md`, the guide, `verifier-web/`, and the two snapshot directories
(`:73-84`). The lint's own comment at `:66-68` states the principle it is
failing here: *"a lint whose own authored document is outside its scan is the
defect, not the exemption."*

### 1.4 MVP-SPEC.md line 143, read rather than paraphrased

The operative clause: **"Docs and CLI must nag on both failure modes"**: *loss*
(…) and *theft* (…). That is the whole of it.

Two precision points, both recorded because the code paraphrases it:

1. **The spec says "CLI", not "`init`".** `init.rs:327-328`'s rustdoc reads
   *"The two standing warnings MVP-SPEC.md line 143 requires `init` to give
   once"*. Line 143 names neither `init` nor "once". The choice of `init` as one
   of the two venues, and the once-only property, are **U18's** (`tasks/U.md`
   U18 `Do`, and its Notes item 1). The rustdoc over-attributes a design choice
   to the frozen spec. Minor, and reported rather than fixed.
2. **Line 143 is a floor, not a closed set.** It mandates the nag; it neither
   mandates nor forbids a pointer.

**No divergence is recorded.** §2 R2's refusal of the pointer is a *design*
ruling on measured grounds, not a spec constraint, and this record says so
explicitly so that no later reader believes MVP-SPEC.md forbids a third line.

### 1.5 `README.md` at HEAD, claim by claim

**Claim A — `README.md:39-41`, *"Not yet chosen in-tree … no LICENSE file exists
yet and no manifest carries a `license` field"*. FALSE, four ways:**

```
$ ls LICENSE* COPYRIGHT
COPYRIGHT   LICENSE-APACHE   LICENSE-MIT
$ git ls-files | grep -iE 'LICENSE|COPYRIGHT'
COPYRIGHT
LICENSE-APACHE            LICENSE-MIT
crates/antseal-anchor/LICENSE-{APACHE,MIT}
crates/antseal-cli/LICENSE-{APACHE,MIT}
crates/antseal-core/LICENSE-{APACHE,MIT}
crates/antseal-net/LICENSE-{APACHE,MIT}
$ grep -n '^license' Cargo.toml crates/*/Cargo.toml
Cargo.toml:49:license = "MIT OR Apache-2.0"
crates/antseal-anchor/Cargo.toml:6:license.workspace = true
crates/antseal-cli/Cargo.toml:6:license.workspace = true
crates/antseal-core/Cargo.toml:6:license.workspace = true
crates/antseal-net/Cargo.toml:6:license.workspace = true
crates/antseal-wasm/Cargo.toml:38:license.workspace = true
crates/devnet-launcher/Cargo.toml:32:license.workspace = true
crates/wasm-bitmatch/Cargo.toml:34:license.workspace = true
```

Root + four **publishable** crates carry the file pair (the three omissions are
exactly the three `publish = false` crates); `license` is inherited by **7 of 7**
crates; `deny.toml:121-141` carries 14 allow ids and `:146-170` five
`[[licenses.exceptions]]` (`saorsa-core` AGPL-3.0, `evmlib`, `self_encryption`,
`attohttpc`, `option-ext`).

**Claim B — `README.md:41-42`, *"the source is under default copyright — all
rights reserved — until Q29 lands"*. FALSE.** Q29 landed at `1830618`.

**Claim C — `README.md:42-43`, *"Do not assume redistribution rights from the
crates.io placeholder metadata"*. INVERTED.** `COPYRIGHT`'s own words: *"The
crates.io metadata is accurate but incomplete."* The placeholders' `MIT OR
Apache-2.0` correctly describes our source; what it does not describe is the
**distributed-binary** obligation (`antseal-net`/`antseal-cli` built with
`ant-backend` are a combined work whose distribution must satisfy **AGPL-3.0**).
The README today warns against trusting the metadata at all, which points a
reader away from the accurate half and says nothing about the inaccurate half.

**Claim D — `README.md:34`, *"648 tasks"*. FALSE.** `python3
scripts/check-traceability.py` (flagless — that run *is* the check; there is no
`--check` flag), exit 0:

```
[task-entries] ok — 661 rows (660 live + 1 struck) against 661 entries; no row
without an entry, no entry without a row, no duplicate, none misfiled
```

**Claim E — `README.md:30`, *"`verifier-web/` … (M3)"*.** This is B2's third
listed staleness row and it was **never fixed**: it still reads as a future
milestone tag over a page that is live. Lowest severity of the five.

**What is still TRUE and must not be "corrected":** the status paragraph
(`:11-20`) and the nine subcommands. Re-measured: the `Command` enum in
`crates/antseal-cli/src/cli.rs` has exactly **9** variants (`Init`, `Seal`,
`List`, `Show`, `Status`, `Restore`, `Reveal`, `Verify`, `Vault`).

### 1.6 The 103 minutes, and the six other sites the same landing falsified

```
4cae455  2026-08-17 00:04:06 +0100  pre-public scrub (worktree half)  → wrote README's License section
1830618  2026-08-17 01:47:05 +0100  Q29                                → falsified it
dee7b2a  2026-08-17 01:54:19 +0100  "Wave 22 bookkeeping: 648 to 659 rows"  → falsified README:34
```

`git show --stat 1830618` touches `Cargo.toml`, `deny.toml`, `COPYRIGHT`, the
ten licence files, seven crate manifests and `docs/decisions/D6-license.md`.
**It does not touch `README.md`**, and `git log -1 --format=%B 1830618 | grep -i
readme` returns nothing.

A sweep for **live present-tense promises naming Q29** finds the fallout is not
one file:

| site | text | state |
|---|---|---|
| `README.md:39-43` | the whole License section | **false** |
| `CONTRIBUTING.md:46` | *"(licenses stubbed until Q29)"* | **false** |
| `.github/workflows/ci.yml:703-704` | *"licenses STUBBED until Q29 — hence the explicit check list, never a bare `check`"* | **false** |
| `.github/workflows/ci.yml:730` | step `name:` *"cargo deny (advisories, bans, sources — licenses stubbed until Q29)"* | **false** |
| `.github/workflows/advisory-cron.yml:15` | *"(licenses stubbed until Q29 — see deny.toml)"* | **false** |
| `.github/workflows/advisory-cron.yml:70` | the same step `name:` | **false** |

**The behaviour is correct and only the labels lie**, which is worth stating
precisely because the opposite reading would be a much larger finding:
`scripts/ci-lanes.sh:1387` runs `cargo deny --locked check advisories bans
sources licenses` — **`licenses` is in the command** — and `:28`'s help line
already says *"advisories/bans/sources/licenses"*. So Q29's Accept row 2 is
genuinely satisfied; four CI labels and two prose lines describe a
configuration that no longer exists.

**The mechanism, stated plainly:** every falsifying commit was made by a lane
whose write scope excluded the file it falsified, and no commit message named
the falsified file. This is a **write-scope handoff gap**, not carelessness.

### 1.7 The two `OWED_PRESENCE` debts, and the exact trap

`scripts/check-copy-style.py:138-149` registers two debts against `README.md`,
both owed by Q22. `:132-137` states the rule: *"Each entry is asserted STILL
OWED: satisfy the clause without deleting its entry and this check goes RED
demanding the deletion."* `:454-464` is the code that does it.

The two patterns (`:203-212`), which is what an implementing lane must actually
avoid — the prose in the debt entry is a description, the regex is the check:

| clause | pattern (`re.I`) |
|---|---|
| `limit-exclusive-possession` | `\bnot?\s+\**\s*exclusive(ly)?\s*\**\s*(possession\|possess\w*)\b` |
| `compelled-disclosure` | `compelled\|forced to reveal\|coerc(e\|ed\|ion)` |

**`compelled` has no word boundary and no context guard.** Any occurrence of
the word anywhere in `README.md` — including in a licence paragraph, where it is
a natural word — flips the debt to satisfied and turns a green lint **RED**,
demanding an edit to `scripts/check-copy-style.py`, which is a different file
and usually a different lane's write scope.

Current state, measured (flagless run, exit 0):

```
check-copy-style: registered debt — README.md: 'limit-exclusive-possession' NOT YET STATED — owed by Q22 (M4) …
check-copy-style: registered debt — README.md: 'compelled-disclosure' NOT YET STATED — owed by Q22 (M4) …
check-copy-style: ok — 14 product-copy file(s) across 5 scan root(s) satisfy …
```

### 1.8 The ordering defect: Q22 is downstream of the publication it protects

- `TODO.md:801` — `- [ ] **Q22** (M) README + install + product-limits/disclosure docs — **after Q20,Q30,Q31**`
- `tasks/Q.md` Q22 `Deps` — *"Q20, Q30 (verification instructions), Q31 (distribution channel)"*
- `tasks/Q.md` Q65 Milestone line — *"**a PRECONDITION of Q31 and Q34**, not a row alongside Q22/Q28"* (D72 §2 R6)

**Q65 → Q31 → Q22.** The README's owning row cannot land until after the
repository is public. Q65's `Deps` line simultaneously lists *"Q22
(README/install/product-limits)"*, so the register contains a cycle whose only
consistent resolution is that **the README's factual currency at the flip is not
Q22's job**.

And Q65's own 2026-08-17 registrar Note contains the contradiction in one
sentence: *"**B1 is closed by Q29 this wave; B2 was fixed in `4cae455`.**"* — the
first clause names the commit that falsified the second clause's fix. Measured
against B2's five listed components (`docs/reviews/pre-public-scrub-worktree.md:178-217`):
`4cae455` fixed **two** (status line, task count), left the `(M3)` row and both
copy debts, and one of the two it fixed went stale seven minutes later while the
section it *added* went false in 103 minutes.

---

## 2. The ruling

### §2 R1 — Q24's Accept row 1 is AMENDED. Nothing new is owed in `init`'s output, and the README half moves to a row that can execute before the flip

`tasks/Q.md:454` today reads:

> - Both pages exist and are linked from README and `init` output (U)

**Replace with two clauses:**

> - Both pages exist and are linked from `README.md`'s `## Documentation`
>   section *(landed by the README-currency row, §2 R5 — **not** by Q22, which
>   `TODO.md:801` puts after Q30/Q31 and therefore after the publication a true
>   front door has to survive)*
> - **`init`'s closing message and the two pages state the same two facts from
>   the same author**: each page reproduces `LOSS_WARNING` / `THEFT_WARNING`
>   (`crates/antseal-cli/src/vault/bookkeeping.rs:68-77`) verbatim, or quotes
>   them and cites that file. **No new bytes are owed in `init`'s output** — it
>   states both failure modes in full already (§1.1), and a link is a way of
>   saying something you did not say. *(D140 §2 R2; if a pointer is ever wanted
>   it is a U-domain row with a precondition, §2 R3.)*

**Why the second clause is the honest one.** The original clause's `(U)` marker
is not decoration: `tasks/U.md` U18's Notes say, verbatim, *"Q24 (M4) later
harmonizes the doc pages with these nags — consumer, not a dep; **CLI nag copy
is U's**."* Q24 is a Q row. As written, its Accept row required a Q docs lane to
edit `crates/antseal-cli/src/init.rs`, which is U's surface — the clause was
untickable by its own owner.

### §2 R2 — A documentation-pointer line in `init`'s output is REFUSED for this wave, on the target rather than on the text

Four measurements, each independently sufficient:

1. **No resolvable target exists.** `grep -n '^repository\|^homepage\|^documentation'`
   over `Cargo.toml` and every `crates/*/Cargo.toml` returns **nothing** — the
   workspace declares no URL of any kind. The repository is private and
   `https://github.com/aed900/antseal` returns **HTTP 404** (D71:903, measured
   2026-08-16). `https://antseal.org/` serves **exactly one file** —
   `verifier-web/` holds only `index.template.html`, enforced by
   `crates/antseal-wasm/tests/page_template.rs:63-88` — and its URL is a
   single-value constant for the *verifier page*
   (`crates/antseal-cli/src/brand.rs:55`, D62 §3 R8). There is no docs path on
   the canonical domain and no row that creates one.
2. **A relative `docs/…` path is correct for exactly the population that is
   about to stop being the only one.** `README.md:17-18` — *"the only way to run
   it today is to build from source"*. M4's product is a **downloaded signed
   binary** (Q30/Q31), whose user has no `docs/` directory. A first-run message
   is the worst place to put a pointer that dies at the release it is being
   written for.
3. **The insertion point costs a true sentence.** `init.rs:340` opens the block
   with *"Two things to understand before you seal anything:"*. A third bullet
   makes it false; placing the pointer outside the block separates it from what
   it points at.
4. **It buys nothing.** `init` already states both failure modes verbatim from
   the same constants the pages will carry.

**This is a design refusal, not a spec constraint** — MVP-SPEC.md line 143 is a
floor (§1.4) and would permit the line.

### §2 R3 — If a pointer is ever added, the PRECONDITION is a committed golden rendering of `init`'s report. Land the snapshot regardless

**Do this even though nothing in this wave requires it**, as a U-domain row
(§5): add `crates/antseal-cli/tests/snapshots/init-report.txt`, generated from
`InitReport::render().join("\n")` over the three networks with the
`fixture_init_report()` address (`tests/machine_mode.rs:856-872` — the
secp256k1 generator's address, deliberately not a real wallet), compared
byte-for-byte in the house `ANTSEAL_BLESS=1` idiom the other ten use.

It pays for itself three times:

- it brings the loss/theft copy **inside `check-copy-style.py`'s corpus**, since
  the lint reaches CLI copy only through rendered snapshots (`:28-33`) and the
  snapshot directory is already a scan root (`:79`);
- it gives **U32 something to freeze** — today U32's snapshot-based freeze
  passes over this surface in silence;
- it converts any future edit (the pointer included) from *free and unobserved*
  into *reviewed snapshot churn*, which is the state every other user-facing
  report is already in.

**Fault-plant requirement, non-negotiable:** the new test must be proven red by
deleting one line from `standing_warnings()` and by reordering two lines of
`render()`, each verified **by the assertion's message**, not by a nonzero exit.
An added snapshot that nothing can redden is this repository's dominant defect
class in its purest form.

### §2 R4 — `init`'s human stdout is in NO stability tier, and this record is the citation for that

The deciding lines: `crates/antseal-cli/src/machine.rs:49` (*"The `--json`
document has three regions"*), `:63-65` (all three tier scopes are members of
that document), and `tasks/U.md` U32's `Do` (the freeze is exit codes, `--json`
schemas and help text). **`init --json` IS frozen** — `json-envelopes.txt:25`
carries the `[init] result` document. **`init`'s human report is not frozen and
is not tiered.**

An implementing lane may therefore treat a change to `init`'s human report as
**free today and reviewed after §2 R3 lands**. It must not cite D65 in either
direction: D65 does not reach this surface.

### §2 R5 — `README.md`'s false claims are corrected NOW, under a NEW row, and that row is a precondition of Q65's visibility flip

**Not Q22** (§1.8: downstream of the flip). **Not Q29** (closed this wave; its
own registrar Note already pushed the licence *story* to Q31/Q22). **Not
out-of-band by a review lane** — that is precisely how `4cae455` produced a
paragraph with no row, no Accept clause and no reader, which went false in 103
minutes.

The row is described in §5 with a proposed domain and **no id**. Its edit set is
exactly this, and nothing more:

**(a) `README.md:37-43` — replace the whole `## License` section:**

```markdown
## License

antseal's own source is dual-licensed **MIT OR Apache-2.0** at your option
([LICENSE-MIT](LICENSE-MIT), [LICENSE-APACHE](LICENSE-APACHE)), declared once in
`[workspace.package]` and inherited by every crate.

**That is not the whole picture for a distributed binary.** A CLI built with the
`ant-backend` feature — the only build that can actually seal — links copyleft
dependencies through `ant-core` and `ant-protocol`, so distributing such a
binary carries obligations our own permissive licence does not describe.
[COPYRIGHT](COPYRIGHT) names which crates, which licences and which builds;
[D6](docs/decisions/D6-license.md) rules it. Read COPYRIGHT before you
redistribute a binary.
```

**(b) `README.md:33-35` — replace, and delete the number rather than update
it:**

```markdown
Authoritative spec: [MVP-SPEC.md](MVP-SPEC.md). Task tracker:
[TODO.md](TODO.md), with per-domain detail under [tasks/](tasks/). This README
deliberately states no task count: it moves most weeks, and
`python3 scripts/check-traceability.py` is the only place it is ever right.
```

**Deleting the number is the ruling, not a shortcut.** The count has now been
wrong twice (219 → 648 → 661) under two different lanes, it has no mechanical
reader, and the sentence it sat in already pointed at the script. A restated
fact that another file owns is a staleness generator; a pointer to the owner
cannot go stale. The same principle is why (a) points at `COPYRIGHT` instead of
restating the copyleft table.

**(c) `README.md:30` — B2's third row, one clause:**

```markdown
| `verifier-web/` | Static offline verifier page: plain HTML/JS + antseal-core via wasm-bindgen — built, deployed and live at <https://antseal.org/> |
```

**(d) The six non-README sites §1.6 enumerates**, corrected in the same act
because they are the same fact: `CONTRIBUTING.md:46`,
`.github/workflows/ci.yml:703-704` and `:730`,
`.github/workflows/advisory-cron.yml:15` and `:70`. Replace *"licenses stubbed
until Q29"* with the truth — `scripts/ci-lanes.sh:1387` runs `check advisories
bans sources licenses`, so the step name and the two comments should say
*"advisories, bans, sources, licenses"*. **Note the write-scope spread**: this
touches `.github/workflows/`, and `scripts/check-ci-shell.py` has opinions about
those files — run it after editing.

**What (a)–(d) deliberately do NOT do**, so Q22 is not pre-empted: no install
instructions, no signature-verification steps, no quickstart, no limits section,
no compelled-disclosure note, no rewrite of the positioning paragraph. Q22 still
rewrites the whole file.

### §2 R6 — The lane editing `README.md` MUST NOT introduce either owed clause. Executable form

Before committing, the lane runs `python3 scripts/check-copy-style.py`
(**flagless — that run is the check; `--check` is not a flag on this script**)
and requires **exit 0 with both debt notices still printed**.

Concretely, the replacement text must contain **none** of:

- the substring `compelled` (any case, anywhere — the pattern has no word
  boundary);
- `coerce` / `coerced` / `coercion`;
- the phrase `forced to reveal`;
- anything matching `not/no + exclusive(ly) + possession/possess…` — e.g.
  *"not exclusive possession"*, *"no exclusively possessed"*.

The §2 R5 and §2 R7 text above was **run against the lint's own compiled
patterns**, imported from `scripts/check-copy-style.py` rather than retyped, with
three planted faults. Result:

| input | `compelled-disclosure` | `limit-exclusive-possession` | P1 | P2 | P3 | P6 |
|---|---|---|---|---|---|---|
| the proposed text | no match | no match | none | none | none | `['https://antseal.org/']`, all canonical |
| + *"You can be compelled to reveal."* | **MATCH `'compelled'`** | no match | none | none | none | ok |
| + *"It proves not exclusive possession."* | no match | **MATCH `'not exclusive possession'`** | none | none | **hit** | ok |
| trailing slash removed from the URL | no match | no match | none | none | none | **non-canonical `https://antseal.org`** |

Both debts and the URL rule are therefore proven red **by the value that fires**,
not by an exit code. **The trailing slash is load-bearing.**

**One thing the probe does not cover, and the lane must not undo**: the three
clauses that are already satisfied — `possession-language`, `limit-authorship`,
`seal-before-you-share` — live in `README.md:7-9`, which §2 R5 does **not**
touch. Deleting or rewording that paragraph turns three green clauses into three
unregistered failures, since only two debts are registered.

**If a future lane does want to satisfy either clause, it must delete the
matching `OWED_PRESENCE` entry (`scripts/check-copy-style.py:138-149`) in the
same commit**, or the lint goes red demanding it (`:454-464`). That is two files
in one write scope, and it is Q22's work, not this row's.

### §2 R7 — `README.md` gets a `## Documentation` section this wave, and that is the mechanism by which Q24 ticks

One new section, immediately before `## License`. Shape only — **D139 rules the
venue and the filenames and this record names none**:

```markdown
## Documentation

<one line per page: link, then one clause saying what it answers>
```

One line per page D139 places, ordered as D139 orders them, each a relative
link and a single clause. Nothing else — no prose introduction, no grouping, no
promises about install or verification. Q22's rewrite absorbs it.

**This is why the section is owed now rather than at Q22.** Q24's Accept names
`README.md` explicitly; Q24 is reachable this wave (`after Q20,Q21`, both in
flight) while Q22 is not (§1.8). Without the section, six pages written this
wave are unreachable from the front door at the exact moment the repository
becomes public, and Q24 — plus the README halves of Q23, Q25, Q26 and Q27 —
would sit open until after the flip for a reason that has nothing to do with
their own work.

### §2 R8 — The generalised "stale forward reference" lint is REFUSED on measurement; a registered variant is proposed instead

The obvious instrument for §1.6 is a lint: flag every *"until `<TASK>`"* /
*"`<TASK>` lands"* in a non-register file whose task row is ticked. **It was
built as a scratch probe and measured before being proposed, and it fails.**

Over every tracked `.md`/`.rs`/`.py`/`.toml`/`.sh`/`.yml`/`.html` outside
`docs/decisions/`, `docs/reviews/`, `docs/research/`, `docs/waves/`, `tasks/`,
`TODO.md` and `docs/instrument-ledger.md`:

```
total forward references to KNOWN rows: 117
of which the referenced row is ALREADY TICKED (stale): 98
```

**Nearly all 98 are correct past-tense narration**, not stale promises —
`crates/antseal-core/src/verify/report.rs:199` (*"it said … until R73 measured
the group"*), `crates/antseal-core/src/anchor/verdicts.rs:711` (*"were the OTS
identity until D92; they are not, because …"*),
`crates/antseal-cli/tests/exit_codes.rs:647-648` (four ids in two lines of
history). This project writes *"X until Y"* far more often as archaeology than
as a promise, so the unregistered lint is ~98 false positives out of 98 and
would be switched off within a wave.

**What is proposed instead** is the `OWED_PRESENCE` idiom, whose whole point is
that registration is the deliberation: a `LIVE_PROMISES` table of `(file,
pattern, task id)` triples, each asserted **still live**, going red the moment
that row ticks. Narration is never registered and therefore never fires. Priced
from the same measurement: **six entries today, every one of them Q29's, every
one currently red.** Proposed as a row in §5, not built here.

---

## 3. Why the README could not simply be left alone until Q22

Three things had to be true at once for this to be a decision rather than a
chore, and all three are measured above.

**It is false, at the front door, at the moment of publication.** Q65's trigger
has fired and the maintainer's 2026-08-16 call is to go public. `README.md` is
the single most-read file a public repository has, and the pre-public scrub said
why a *underclaiming* falsehood is still a blocker: *"a proof-of-existence tool
asking strangers to audit its verifier cannot open with 'nothing usable yet'
over a live verifier. A reader who checks one sentence and finds it wrong stops
checking"* (`docs/reviews/pre-public-scrub-worktree.md:193-196`). The current
falsehood is worse in kind than the one that argument was written about: *"the
source is under default copyright — all rights reserved"* tells every visitor
they may not use the code, over a tree that dual-licenses it MIT OR Apache-2.0
in ten committed files.

**The row that owns it cannot reach it in time.** §1.8. This is a defect in the
register, and naming it is more useful than routing around it once.

**The last out-of-band fix lasted 103 minutes.** §1.6. `4cae455` did the right
thing with no row behind it, and the fix had no Accept clause, no owner and no
reader; the next lane falsified it without ever seeing it. Repeating that shape
would produce the same result on the same timescale.

### 3.1 What the recurrence actually is, and what it is not

**It is not a checker gap in the sense of "a lint would have caught it."**
§2 R8 measures the naive lint at a 100 % false-positive rate on this corpus, and
a general "is this English true?" check does not exist.

**It is a write-scope handoff gap.** Every falsifying commit was made by a lane
that could not edit the file it falsified, and none named that file in its
message. The two durable answers are:

1. **Structural (this record's, §2 R5b/§2 R5a): stop restating facts another
   file owns.** A README that points at `COPYRIGHT` and at
   `check-traceability.py` cannot go stale when those change. This needs no
   instrument and it is why the count is deleted rather than updated.
2. **Registered (proposed, §2 R8): the promises that cannot be pointerised get
   an `OWED_PRESENCE`-shaped table** so that landing a row reddens every live
   promise naming it.

---

## 4. What this record does NOT cover

Stated here because a ruling whose limits are unwritten gets applied past them.

1. **The venue and filenames of the six new pages.** D139's, entirely. §2 R7
   rules the *shape* of the README section and deliberately names no file.
2. **Q22's rewrite.** Install instructions, signature verification, the
   quickstart, the limits-and-disclosure section, and both `OWED_PRESENCE`
   clauses remain Q22's and are untouched. §2 R5 is a correction, not a draft.
3. **Whether the AGPL/GPL obligations are *discharged* by the distribution
   channel.** Q29's registrar Note assigns that to Q31/Q22. §2 R5a points at
   `COPYRIGHT` and makes no claim about discharge.
4. **Licence text in the deployed page artifact.** Owed by Q31 per `COPYRIGHT`'s
   closing section; `verifier-web/` can never hold a licence file
   (`page_template.rs:63-88`).
5. **Whether `https://antseal.org/` serves anything beyond the one page.** The
   claim in §2 R2 is a tree measurement (`verifier-web/` holds exactly one
   file, asserted by a test), not an HTTP probe of the live host.
6. **The content of the loss/theft pages.** Q24's, and this record does not
   review copy it has not read.
7. **U32's three D134 reservations.** Untouched; §2 R4 adds no fourth. It
   observes only that U32's freeze mechanism does not reach `init`'s human
   report, which is §5's row to fix, not U32's to widen by implication.
8. **Anything about `seal`'s first-seal nag beyond the measurement** that it,
   too, has no golden rendering (§1.2). §2 R3's snapshot covers `init` only; a
   companion for the seal nag is not ruled here.
9. **Whether the row §5 proposes should block Q65 or merely precede it.** This
   record rules it a **precondition of the visibility flip**; the ordering
   against Q65's other outstanding items (the per-file public/private record,
   the `/home/deb` scrub, the D61 §9 re-read, finding 4's settings) is Q65's.

---

## 5. What this ruling owes

**Row proposals — domain and description only; ids are assigned centrally.**

1. **Domain Q, size S — "The README's front door is corrected before the
   visibility flip, and so are the five other sites Q29's landing falsified."**
   Executes §2 R5 (a)–(d) and §2 R7 verbatim. **A precondition of Q65's
   visibility change**, and explicitly **not** the Q22 rewrite: its Accept is
   (i) `README.md` states no fact that `COPYRIGHT`, `check-traceability.py` or
   the manifests own — it points at them; (ii) `python3
   scripts/check-copy-style.py` exits 0 **with both registered debts still
   printed**; (iii) `python3 scripts/check-traceability.py` exits 0; (iv) the
   six sites of §1.6 name the licences lane correctly, cross-checked against
   `scripts/ci-lanes.sh:1387`; (v) a `## Documentation` section exists with one
   line per page D139 places.

2. **Domain U, size S — "`init`'s human report has no committed golden
   rendering."** Executes §2 R3. Its own justification is the measurement, not
   the pointer: this is the CLI's first-run message, it carries MVP-SPEC.md line
   143's mandated nag, it is the only user-facing report of the nine
   subcommands with no snapshot, and both the copy lint and U32's freeze reach
   CLI text *through* snapshots. **Accept must include the two planted faults
   verified by assertion message** (§2 R3). Ordering: before U32, so the freeze
   has something to freeze.

3. **Domain Q, size S — "A `LIVE_PROMISES` register in the copy lint."**
   Executes §2 R8's registered variant. Its brief must carry the refusal
   evidence — 98 of 117 forward references in this tree are past-tense
   narration — so the unregistered version is not re-proposed. Six entries at
   birth, all Q29's, all currently red until item 1 lands.

4. **Domain Q, size S (or fold into item 1) — `crates/antseal-net/src/wallet.rs:52`
   is a dead absolute URL under the wrong org**:
   `https://github.com/antseal/antseal/blob/main/docs/decisions/D89-…` against
   this tree's own canonical `aed900/antseal` (`docs/decisions/D2-hosting-ci.md:16`).
   It is a rustdoc link, so it ships to docs.rs on publication, and it 404s for
   two independent reasons. It is the only absolute repository URL in crate
   source.

**Corrections owed to existing records (outside this lane's write scope):**

5. **`tasks/Q.md` Q65's registrar Note** — *"B1 is closed by Q29 this wave; B2
   was fixed in `4cae455`."* B2 is **not** fixed: two of its five components
   (both copy debts) were never addressed, a third (the `(M3)` row) was left,
   and the licence section `4cae455` added was falsified by the very commit the
   same sentence calls B1's closure. Amend by dated addendum.

6. **`crates/antseal-cli/src/init.rs:327-328`** — the rustdoc attributes to
   MVP-SPEC.md line 143 both the venue (`init`) and the *"once"*, neither of
   which line 143 contains (§1.4). U18 is the correct citation for both.

7. **`tasks/Q.md` Q24 Accept row 1** — replace per §2 R1. The registrar applies
   it; this lane may not.

8. **A remote witness for none of this.** Nothing here runs on the remote and
   nothing here needs to; the CI-label corrections in §2 R5(d) change `name:`
   strings only, and the first push that carries them is the only place they can
   be read. `scripts/check-ci-shell.py` should be run locally after that edit.
