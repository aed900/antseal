# D159 — The venue question is answered by an instrument that already occupies both venues. `cargo doc` could never have seen this defect; the check belongs in `check-traceability.py`'s existing sweep at **49 links over 457 files for 0.110 s and zero new contexts**; the doc build is refused in **both** venues and **armed at first publication**; and the ungated `crate::evm` links are **de-linked**, because six of them warn and the seventh proves the register's per-file reading wrong

- **Status: RESOLVED. The lean is OVERTURNED. Its re-framing — the one the brief
  offered in its place — is ALSO OVERTURNED, on the same defect it was meant to
  correct. Two of the brief's own measured premises are OVERTURNED, one of them
  in the register's favour and one against it.** The lean was *"a hosted doc
  context is too expensive; put it in the local gate."*
  - **`cargo doc` in any venue would not have caught the defect that raised this
    row.** rustdoc's doc-link lints govern **item paths**, not filesystem
    targets; a relative markdown link to a `.md` file is emitted verbatim as an
    href and validated by nothing. Two independent witnesses agree, and one of
    them is this row's own carriage: the Q248 lane's `cargo doc` reported
    *"twelve broken **intra-doc** links"* and `request.rs:2` is not among them —
    the lane found it *"while auditing the five relative decision links in crate
    sources"*, **by reading** (§1.2). The row's `Do` binds the fix and the doc
    build together (*"land a `cargo doc` check with the fix or the warnings
    return"*); they are two defects with two mechanisms and only one of them has
    a doc build in it.
  - **The brief's re-framing reads the symptom field, not the field that carries
    the claim.** *"A new hosted context costs zero minutes because no minutes are
    being spent"* inverts cause and effect. Measured today on the run the brief
    cites: `fuzz-long`, 3 s wall, `steps: 0`, and — the field D135 had to
    withdraw a correction over — **`runner_name: ""`** (§1.5). That triple is the
    **dispatch-refusal signature** `docs/ci-verification.md` diagnoses as *"an
    exhausted minute allowance or a reached spending limit"*, and D135 measured
    it across **45 jobs in three runs**. Minutes are not being spent **because
    the allowance is exhausted**. Zero spend is the constraint asserting itself,
    not its absence.
  - **The venue question is neither premature nor open: it is already answered,
    by an instrument nobody looked at.** `check-traceability.py` sweeps
    **`crates` and fourteen other roots** today, is **cargo-free**, runs in the
    **local gate** and rides **`ci-always.yml`'s `traceability` job** — one of
    the **19 existing required contexts**, on a workflow that carries **no path
    filter, ever**. A ninth check there adds **zero steps, zero contexts and zero
    hosted minutes**, so **D135 §3 R6 is not triggered at all** (§1.6, §2 R4).
  - **The gap is inside an existing check's own subject.** `--decisions` asserts
    that *"every decision cited in code … resolves to a record"*. Measured, it
    extracts `\bD(\d+)\b` and **never reads the link path** — so
    `[D59](../../../docs/decisions/D59-…md)` is green on the id while the path
    resolves to a directory that does not exist (§1.6). This is the
    *verify-the-field-that-carries-the-claim* failure in the checker itself.
  - **The corpus is 49, not 4, at no new scan root.** Restricting to links whose
    target is a relative `.md` path, over the roots `check-traceability.py`
    already walks: **49 links across 457 files, exactly 1 broken** — and the
    broken one is `request.rs:2`. `README.md` carries **19** and
    `CONTRIBUTING.md` **16**, neither swept by anything today; this check would
    have caught the wave-26 README defect the instrument ledger records as
    *"decidable only because R5 independently required `test -f`"* (§1.1).
  - **SEVEN is wrong; SIX are reachable — and the register's own source says so.**
    `wallet.rs:244`'s doc comment sits on `hex_str`, which is itself
    `#[cfg(feature = "ant-backend")]` at `wallet.rs:247`. **Gating is per-ITEM,
    not per-FILE.** Six links are reachable in a default build, and that
    reconciles **exactly** with the figure the row carries and disbelieves —
    the lane's `cargo doc` *"six of them `crate::evm`"*. The register
    re-measured a `cargo doc` result by reading module declarations and got a
    worse answer than the build it was correcting (§1.3).
  - **The `crate::evm` route is a third one, which the row's `Accept` did not
    list: de-link.** `[`crate::evm`]` becomes `` `crate::evm` ``. Zero warnings
    in **every** feature combination, verifiable by grep with **no doc build**,
    and the form is **already in the tree eleven lines away** — `network.rs:501`
    writes the plain span while `network.rs:14`/`:24` write the link (§2 R2).
    Both routes the row named are refused, one of them as an assertion that
    cannot fail (§3).
  - **The "pinned warning count" arm is circular and cannot be executed.** The
    only figure on record is *13 warnings / 12 broken intra-doc links*, taken
    once, **not re-run**, and **six of the twelve are unenumerated anywhere in
    this tree**. Pinning the count requires running the build; running the build
    is the question; and no lane may run it this wave (§1.4).
- **Date: 2026-08-22**
- **Owning task: Q249.** Rulings touch `scripts/check-traceability.py` (a ninth
  check and its self-test arms), `crates/antseal-core/src/anchor/request.rs`,
  `crates/antseal-net/src/wallet.rs`, `crates/antseal-net/src/network.rs`,
  `TODO.md`'s Q249 row and `tasks/Q.md`'s Q249 and Q250 entries, plus one
  `docs/instrument-ledger.md` line. **No new id is assigned and no row is
  minted** — §2 R9 states why under rule 8.
- **What it blocks:** `Q249` (closed by this record's edit set). Nothing else:
  `Q31`'s release workflow and `Q241`'s publish blocker are named as the
  **trigger** that arms the doc build (§2 R6), not as things this row waits on.
- Related: **D154 §2 R11** (the refusal-with-a-ledger-line shape this record
  reuses, one wave old), **§2 R10** (four surfaces, and the discipline of naming
  the clause), **§1.1** (the plant-the-parser discipline); **D135 §1** (the
  3 154-weighted-minute measurement, the 45 zero-step jobs and the
  `runner_name` correction it had to withdraw), **§3 R6** (raise-only by
  decision — measured here as **not triggered**), **§4 R2** (*"a lane that has
  never run on the remote"*); **D142 §2 R2** (print the fourth number, or the
  subtraction is available to a reader and performed by nobody), **§2 R4** (an
  allocated id gets one of three homes in the allocating commit); **D144 §2 R4**
  (*"there is no exemption list to add this file to"* — why the non-`.md`
  exclusion is a property of the target and not an allowlist), **§2 R8**
  (assert the COUNT, not merely the zero); **D116 §2 R2** (one scan set, two
  loop bodies at parity — now three); **D124/Q182** (the cargo-free property);
  **D123/Q190** (a directory entry is filtered, a named file is not);
  **Q69/Q70/Q144** (`doc_pointer_liveness.rs`, its scope and the two open rows
  that own its widening); **TODO.md rule 8** (why nothing is minted) and
  **rule 3** as amended by D142 §2 R4.

---

## 1. What was measured

**Provenance.** Measured 2026-08-22 against the **working tree**. `git status
--porcelain` reports `TODO.md`, `tasks/Q.md`, `docs/signing/key-custody.md` and
`docs/signing/maintainer-key-procedure.md` modified-uncommitted; other planners
are writing `docs/decisions/D156–D158` and `D160`.

**One concurrency fact this record's own ruling depends on, re-measured last.**
While this record was being written, another lane put
**`scripts/check-traceability.py` (+247 lines)** and **`CONTRIBUTING.md`
(+25 lines)** into the modified-uncommitted set. Re-measured after that landed:
**`CHECKS` still holds exactly eight entries** (`:2214-2223`) and the module
docstring still reads *"Eight checks live here"* (`:4`), so **R1's "ninth" is
still ninth** — the addition is not a check. Its lines all sit **below `:2100`**,
and every locator this record cites was re-verified live afterwards:
`check_decisions` `:952`, the `\bD(\d+)\b` extraction `:1021`, `CITATION_SCAN`
`:633`, `CITATION_SUFFIXES` `:676`, the per-arm self-test rule `:1886`,
`local-gate.sh:267`, `ci-lanes.sh:977`, `antseal-net/src/lib.rs:96`, and
`wallet.rs:244`'s doc comment above `:247`'s `#[cfg]`. **If `CHECKS` holds nine
entries when the implementing lane arrives, R1 is a TENTH check and nothing else
in it changes; if the docstring's count word has already moved, edit 5's
docstring clause is already done — read it, do not increment it.** The 49-link
and 457-file figures are dated 2026-08-22 and `CONTRIBUTING.md` (16 of the 49)
is one of the files moving; **the implementing lane re-measures the two floor
constants against its own tree before committing them**, exactly as §2 R1's
comment requires. Every edit in §5 is keyed to an **exact
old string** as well as a line number, per the discipline D154 §1 adopted after
rule 7's own locators went stale within one wave.

**Every premise in the brief was re-measured. Six hold; two do not.** The two
that do not are recorded first because the brief asked for exactly that.

| brief's premise | verdict |
|---|---|
| `request.rs:2` is broken; `http.rs:2` is its correct textual twin | **holds** (§1.1) |
| the filesystem-relative corpus in `crates/*/src` is four links, one broken | **holds as stated, and is the wrong corpus** — 49 links / 1 broken over roots already swept (§1.1) |
| nine `crate::evm` links, **seven** in ungated files | **links: holds. Reachable in a default build: SIX, not seven** (§1.3) |
| nothing builds docs anywhere: zero `cargo doc`, zero docs.rs metadata, zero `rustdoc::` attribute | **holds** (§1.4) |
| `TODO.md:847` ends mid-sentence | **holds — and the truncation is COMMITTED, born in `de71a09`, unchanged through six commits** (§1.9) |
| `tasks/Q.md` Q249 carries a second `- Notes:` belonging to Q250 | **holds, and it is a MOVE not a delete: Q250 does not have it** (§1.9) |
| hosted CI refuses every job; run `32331427651` is stepless | **holds** (§1.5) |
| *therefore* a hosted context costs zero minutes and D135's budget is not the live constraint | **OVERTURNED — the refusal is caused by the exhaustion** (§1.5) |

### 1.1 The corpus is 49 links over 457 files, exactly one is broken, and none of it needs a new scan root

The brief's corpus — filesystem-relative links under `crates/*/src` — is **four**,
and the resolution of each was taken by `realpath -m` against the tree rather
than by counting `../` by eye:

| file | target | resolves to | verdict |
|---|---|---|---|
| `crates/antseal-anchor/src/http.rs:2` | `../../../docs/decisions/D90-…md` | `docs/decisions/D90-anchor-http-substrate.md` | **OK** |
| `crates/antseal-anchor/src/arbitrum/confirm.rs:2` | `../../../../docs/decisions/D55-…md` | `docs/decisions/D55-arbitrum-rpc-pairs.md` | **OK** |
| `crates/antseal-anchor/src/arbitrum/endpoints.rs:2` | `../../../../docs/decisions/D55-…md` | `docs/decisions/D55-arbitrum-rpc-pairs.md` | **OK** |
| `crates/antseal-core/src/anchor/request.rs:2` | `../../../docs/decisions/D59-…md` | **`crates/docs/decisions/D59-…md`** | **BROKEN** |

**One character. The brief is right that there is no second instance to find in
that corpus — and the corpus is not the one to check.**

`check-traceability.py`'s `CITATION_SCAN` (`:633-696`) already walks fifteen
roots — `crates`, `docs/format`, `docs/testing`, `scripts`, `verifier-web`,
`docs/user`, and nine named root files — filtered by `CITATION_SUFFIXES`
(`:676`, `{.rs .md .json .py .sh .mjs .html}`). Swept with that exact scan set
and prune set, counting every markdown link whose target is a **relative path
ending `.md`** (optionally `#anchor`) and is not a URL:

```
files swept                              : 457
markdown links with a relative .md target: 49
  dot-prefixed (./ or ../)               : 14
  bare-relative (docs/foo.md)            : 35
  carrying a #anchor                     : 0
  site-root-absolute (/docs/foo.md)      : 0
BROKEN                                   : 1
  crates/antseal-core/src/anchor/request.rs:2 -> ../../../docs/decisions/D59-request-nonce-persistence.md
median wall over three runs              : 0.110 s
```

Per root: **`README.md` 19**, **`CONTRIBUTING.md` 16**, `crates` 5,
`docs/format` 5, `docs/testing` 4. `verifier-web`, `docs/user`, `MVP-SPEC.md`
and `CHANGELOG.md` carry none.

**Two consequences the brief's corpus hides.**

1. **`README.md` and `CONTRIBUTING.md` carry 35 of the 49 and are swept for this
   by nothing.** `docs/instrument-ledger.md` records the wave-26 instance
   verbatim — a ruling (D150 §2 R3 item 3) specified `../signing/verifying-a-
   release.md` from a file at the repo root, where `test -f` **fails**, and the
   entry states *"**Nothing in the tree validates a README markdown link** —
   `doc_pointer_liveness.rs` is rustdoc-only and `check-traceability.py`'s eight
   checks include no such check"*, closing with *"**Baseline banked for any
   future checker**"*. Q249 is the **second instance of one defect class**, in a
   different file, four days later. A check scoped to `crates/**/src/**` would
   have caught neither the first nor a third.
2. **Both spellings must be in scope.** The wave-26 defect was a `../`-form link
   that failed and was fixed to a **bare-relative** one that passes. Checking
   only dot-prefixed targets would cover 14 of 49 and would have graded the
   wave-26 repair without ever checking the repair.

### 1.2 `cargo doc` cannot see this defect, in any venue — two witnesses

This is the finding that dissolves the question the row asks, so it is measured
rather than asserted.

**Witness 1 — the mechanism.** rustdoc's doc-link lint family
(`rustdoc::broken_intra_doc_links` and its siblings) resolves **Rust item
paths**: `[`crate::evm`]`, `[`WalletKey::evm_wallet`]`. A markdown link whose
target is a **filesystem path** — `[D59](../../../docs/decisions/D59-…md)` — is
not an item path; rustdoc emits it verbatim as an `href` into the generated HTML
and validates nothing about it. No rustdoc lint reads the filesystem.

**Witness 2 — this row's own carriage, which contains the disproof and does not
notice.** The Q248 lane ran `cargo doc` and reported *"Thirteen rustdoc warnings
/ **twelve broken intra-doc links**, six of them `crate::evm`"*
(`tasks/Q.md:3159`). **Twelve intra-doc links. `request.rs:2` is not an intra-doc
link and is not among them.** And the row records how it *was* found —
`tasks/Q.md:3149`, `- Discovered by:` — *"**Q248's lane** (2026-08-17), **while
auditing the five relative decision links in crate sources** to choose an
idiom"*. It was found by **reading**, in the same wave and by the same lane whose
`cargo doc` run had already returned.

*(The "five" in that sentence is itself accurate and is worth pinning, because a
later reader will re-count and get four: the fifth relative link under
`crates/**/src/**` is `crates/antseal-core/tests/bundle_wire/mod.rs:13`'s
`[`crate::manifest_wire`](../manifest_wire/index.html)` — see §1.8.)*

**So the row's `Do` couples two defects that have two mechanisms.** *"Land a
`cargo doc` check **with the fix** or the warnings return — the Q27 precedent"*
is sound for the `crate::evm` half and **false for the link half**: the doc build
is not the lint that was missing, and adding it would leave `request.rs`
unguarded while reading as though it were guarded — which is
`doc_pointer_liveness.rs`'s own opening complaint, *"a pointer at nothing … reads
like **evidence**, which is worse than saying nothing at all."*

### 1.3 Six, not seven: gating is per-ITEM, and the register re-measured a build result by reading declarations

Nine bracketed `[`crate::evm…`]` intra-doc links exist. Measured with the `cfg`
attribute on the **item each doc comment is attached to**, not on the file:

| site | attached to | gate on the item | in a default `cargo doc`? |
|---|---|---|---|
| `ant_backend.rs:7` | module docs (`//!`) | module gated at `lib.rs:85-86` | **no — module not built** |
| `ant_backend.rs:189` | an item in that module | same | **no** |
| `network.rs:14` | module docs | module ungated (`lib.rs:100`) | **YES** |
| `network.rs:24` | module docs | ungated | **YES** |
| `network.rs:261` | `pub struct NetworkConfig` | ungated | **YES** |
| `wallet.rs:8` | module docs | module ungated (`lib.rs:107`) | **YES** |
| `wallet.rs:42` | module docs | ungated | **YES** |
| `wallet.rs:376` | `pub enum WalletOpsError` | ungated (only two *variants* are gated, `:393`, `:398`) | **YES** |
| **`wallet.rs:244`** | **`fn hex_str`** | **`#[cfg(feature = "ant-backend")]` at `wallet.rs:247`** | **NO** |

**6 reachable + 2 in a gated module + 1 on a gated item = 9.** The arithmetic
closes, and it closes on the number the row already carries and disbelieves:
the lane's `cargo doc` said *"six of them `crate::evm`"*.

**The register's re-measurement was the wrong medium.** `tasks/Q.md:3159` says
*"what is re-measured here is the link inventory — nine `crate::evm` links,
**seven reachable in a default build**"*. That re-measurement read `lib.rs`'s
module declarations and the containing filenames; the fact it needed is one
`#[cfg]` attribute three lines below one of the nine links. A `cargo doc` result
was "corrected" by a static read that could not see what the compiler sees —
the same shape as D135's withdrawn `runner_name` correction, and the same shape
as this project's standing note that *a probe from the wrong client can return
the opposite of the truth*.

Two further sites are **not** links and are correctly outside all counts:
`ant_backend.rs:95` (`use crate::evm::to_evm_network;`, real code, gated module)
and `network.rs:501` (a `//` comment — invisible to rustdoc — which writes the
module name as a **plain code span**, `` `crate::evm` ``; §2 R2 turns that into
the house form). `wallet.rs:395`'s `crate::evm::EvmConfigError` is real code
behind `#[cfg]` at `:393`.

### 1.4 Nothing builds docs, the remaining warnings are unenumerated, and `--all-features` would breach the gate's containment

- **Zero doc builds.** `grep -rn 'cargo doc\|cargo rustdoc\|RUSTDOCFLAGS\|rustdoc::'`
  over `scripts/`, `.github/`, `crates/` and `Cargo.toml` returns **nothing**.
- **Zero docs.rs metadata.** The only `[package.metadata]` in the tree is
  `fuzz/Cargo.toml:25`.
- **Publishable surface, confirmed.** `publish = false` appears in exactly three
  manifests — `antseal-wasm`, `wasm-bitmatch`, `devnet-launcher`. `antseal-core`,
  `antseal-net`, `antseal-anchor` and `antseal-cli` carry none, and
  `[workspace.package]` sets `edition`, `rust-version` and `license` only.
- **13 warnings, 12 broken links, 6 accounted for, 6 unknown.** After §2 R2
  removes the six `crate::evm` warnings, **six broken intra-doc links remain that
  are named nowhere in this tree.** No arm of Accept row 2 can be executed
  against them: pinning a count requires the build, the build is the question,
  and `cargo doc` is unavailable this wave (build lock; this lane is forbidden
  `cargo doc`/`build`/`test`).
- **`--all-features` is barred from the local gate on the gate's own terms.**
  `GATE_LIGHT_FEATURES` (`scripts/local-gate.sh:267`) is
  `antseal-anchor/test-util,antseal-core/test-util,antseal-core/test-vectors,antseal-net/test-util`
  — and **`ant-backend` is deliberately absent.** `crates/antseal-net/Cargo.toml`
  states the reason at the feature: *"the pinned `ant-core = "=0.5.0"` client
  stack … the ~600-package graph P16 measured … a default `cargo build/test
  --workspace` compiles NONE of it."* A `cargo doc --all-features` lane in the
  local gate would drag that graph into the one venue every contributor runs, to
  silence six warnings that §2 R2 removes at source for nothing.

### 1.5 The zero-minute reading is the symptom of the constraint, measured on the field that carries the claim

`gh run list --limit 8` returns **eight consecutive `conclusion: failure`**, the
newest 2026-08-20. The brief's exhibit, re-measured through the API rather than
through `gh run view`'s summary:

```
run 32331427651  fuzz-nightly  2026-08-20
  job fuzz-long   conclusion: failure
    started_at 04:18:54   completed_at 04:18:57   (3 s)
    steps:       0
    runner_name: ""
```

**`runner_name: ""` is the field D135 had to withdraw a correction over**, and it
is quoted here for that reason. Its §1 records: *"An earlier note here claimed
this record's 'never assigned a runner' was one word wrong because the 45 jobs
carry `started_at`/`completed_at` stamps. **That claim was itself wrong, and it
was wrong by measuring the wrong field.**"* The greppable signature it settles on
is **`runner_name == ""` or `steps == []`**. Today's job carries both.

D135 then names what produces that signature: **3 154 weighted minutes over
2026-08-01→15**, *"**158 %** of 2 000 and **105 %** of 3 000, with 16 days of the
month left"*, and *"**There is no headroom to spend.** Every push-tier arm is
refused on that number, not on plausibility."* `docs/ci-verification.md` had
already diagnosed the signature as *"an exhausted minute allowance or a reached
spending limit"*, and D135 records the failure mode as *"**every workflow in the
repository refusing to dispatch, including all 19 required contexts**."*

**So the inference the brief offered is backwards.** Minutes are not free; jobs
are refused **because** the bill exceeded the allowance. Reading "zero minutes
spent" as "a hosted context is free" measures the **symptom** and reports it as
the **cause** — the failure this project has recorded three times, once inside
D135 itself.

**And the second half of the brief's dichotomy — "worthless because it cannot be
witnessed" — is right, and the tree already says so in a rule.** `local-gate.sh`
carries Q43's rule twice: *"**a lane that has never run on the remote is not
evidence**, and neither is one that never runs locally"* (`:419-420`, `:72`).

### 1.6 The existing instrument sweeps these files today and reads the wrong field

`check_decisions` (`scripts/check-traceability.py:952`) opens with the exact
charter this row needs: *"Every decision cited in code or in a normative doc
resolves to a record, a registered alternative home, or an open register entry."*
Its extraction, measured at `:1021-1022`:

```python
for n in re.findall(r"\bD(\d+)\b", text):
    cited.setdefault(int(n), set()).add(rel)
```

**The id, and only the id.** `D59` resolves to
`docs/decisions/D59-request-nonce-persistence.md`, so the check prints
`ok` — while the **path** in the same link points at `crates/docs/decisions/`,
which does not exist. The claim *"this citation resolves"* is carried by the
path; the check audits the number.

**The venue this implies is not a new one.** Measured:

| property | value | where |
|---|---|---|
| `crates` already a scan root | yes | `check-traceability.py:634` |
| `README.md`, `CONTRIBUTING.md` already scan roots | yes (literal entries) | `:655`, `:656` |
| files already read by the existing checks | **457** | §1.1 |
| cargo-free | yes, asserted not stated | `cargo-free.sh`; D124/Q182 |
| local-gate seat | yes, via `ci-lanes.sh:977-984` | self-test then flagless run |
| hosted seat | `ci-always.yml`'s `traceability` job, ~19 s | `local-gate.sh:450` |
| that workflow's path filter | **none, ever** — its whole job | `ci-always.yml` |
| new required contexts | **zero; the set stays at 19** | `local-gate.sh:452-453`, `:461-462` |
| marginal cost of the link sweep | **0.110 s** median of 3 | §1.1 |

The house phrase for exactly this shape is already written twice in
`local-gate.sh`: *"Rides ci-always.yml's `traceability` job remotely; adds ZERO
required-status contexts, the set stays at 19."*

### 1.7 The other candidate home is already two open rows' business, and covers one of the four links

`crates/antseal-core/tests/doc_pointer_liveness.rs` is the nearest existing
instrument and it is a real one: its **Rule 2** already resolves a doc-comment
token against the filesystem (*"a test-file pointer is any `tests/<...>.rs` token
in a doc comment … It must exist relative to this crate root"*), and its module
docs state this row's thesis better than this row does — *"a pointer at nothing
compiles, renders, and reads exactly like a pointer at a live guard."*

It is nonetheless **not** the home, and the reason is scope rather than fit:

- Its `# Scope` section says *"**This crate only** (`src/` and `tests/`)"*, and
  `antseal-core` holds **one** of the four crate-source links. The other three are
  in `antseal-anchor`.
- Widening it is **already two open rows**: **`Q70`** (*"Widen Q69's doc-pointer
  sweep past `antseal-core` … Decide the home: a second test target per crate, or
  one workspace-level"*, `TODO.md:341`) and **`Q144`** (*"`crates/antseal-anchor`
  has **no `doc_pointer_liveness` sweep**"*, `:657`). Landing a third rule there
  would take a decision that belongs to Q70 and cover a quarter of the corpus.
- It is a `cargo test` target, so it is **not** cargo-free and cannot ride the
  `traceability` job.

### 1.8 The vacuity trap, and the one link that is correct on the surface it is written for and dead on disk

The brief names the trap correctly: a four-link corpus makes a mis-rooted glob
indistinguishable from a clean run. Measured, there is also a **second** trap
pointing the other way, and it is live in the tree:

```
crates/antseal-core/tests/bundle_wire/mod.rs:13
  //! [`crate::manifest_wire`](../manifest_wire/index.html)
```

That is a **rustdoc-HTML-output-relative** link. It resolves in generated docs
and **does not resolve on disk** — a checker that walks every relative link under
`crates/**` reds on a **correct** link on day one.

It is also, measured, **the only non-`.md` relative link in the entire 457-file
corpus** (`ALL relative links 15, .md targets 14, other 1`). So restricting the
subject to targets ending `.md` excludes it **by a property of the target**, one
for one, with **no allowlist** — the discipline `machine-paths` states in its own
failure text (*"There is no exemption list to add this file to (D144 §2 R4)"*).

**Two branches of the check will have zero live subjects and are therefore
assertions that cannot fail unless the self-test constructs them:** `#anchor`
stripping (**0** anchored links today) and site-root-absolute targets (**0**).
§2 R3 constructs both.

### 1.9 The two carriage defects

**(a) `TODO.md:847` is truncated, and the truncation is COMMITTED.** The row is
**1 669 bytes** and ends `…the link inventory and the zero-lane result were`.
Measured across every commit that touched `TODO.md` back to the row's birth:

| commit | length | tail |
|---|---|---|
| `5c8d1ca` (HEAD) | 1 669 | `…the zero-lane result were` |
| `28afe38`, `2eb03d7`, `dc0bac8`, `2cdf0fb` | 1 669 | identical |
| **`de71a09`** — *Wave 23 bookkeeping*, the commit that introduced the row | **1 669** | identical |

`diff` of HEAD's line 847 against the working tree's: **SAME**. The neighbouring
`Q248` row is 2 574 bytes, so no line-length limit is at work. **The row was born
truncated and has stood so through six commits. There is no complete version in
git to restore.**

**But there is a complete version in the tree.** `tasks/Q.md:3159` carries the
same sentence whole: *"…what is re-measured here is the link inventory — nine
`crate::evm` links, seven reachable in a default build — and the zero-lane
result, **both of which stand on their own**."* That is the reconstruction
source, and §2 R7 uses it — **with the `seven` corrected**, because restoring a
sentence verbatim would restore a measured falsehood (§1.3).

**(b) `tasks/Q.md:3160` is Q250's Notes block, filed under Q249.** Q249's entry
spans `:3145-3161` and carries **two** `- Notes:` lines, `:3159` and `:3160`. The
second opens *"**[Registrar, 2026-08-19 — wave 26 execution…]**"* and discusses
`wallet-hygiene.md §4`, `ant-protocol`, `build_paid_chunks`
(`ant-core-0.5.0/src/data/client/batch.rs:300-305`) and `ant-node-0.15.0`'s
`verifier.rs:836-853` — none of which appears in Q249's `Problem`, `Do` or
`Accept`. It quotes a `Do` string verbatim: *"cite `ant-protocol` by version and
line as the user page does"*. Measured, that string is **Q250's**, at
`tasks/Q.md:3170`.

**It is a MOVE, not a duplicate.** Q250's entry (`:3162-3176`) carries **one**
`- Notes:` line, `:3175`, and `grep -c 'wave 26 execution'` over Q250's span
returns **0**. The block exists in exactly one place and that place is the wrong
row. `Q250` is `[x]` at `TODO.md:848`; `Q249` is `[ ]` at `:847` while its detail
entry reads as executed.

---

## 2. Ruling

### R1 — The link check is a NINTH check inside `scripts/check-traceability.py`, named `doc-links`. **Who: the implementing lane.**

The venue arms as the brief framed them are all refused: **(a)** the local gate
alone leaves the hosted seat empty for a check that can occupy it free;
**(b)** a new hosted context cannot run and is not evidence (§1.5); **(c)** both,
as two new mechanisms, doubles the surface for one defect class; **(d)** none is
refused because a one-character fix without its lint is the drift the row's own
`Do` names by precedent (Q27).

**The arm taken is one the brief did not list: neither venue is raised, because
an instrument that already occupies both is extended.** `check-traceability.py`
runs in `local-gate.sh` and in `ci-always.yml`'s `traceability` job; it is
cargo-free; it already reads all 457 files; and the defect is a blind spot in
its own `--decisions` check (§1.6).

**Subject, normative and deliberately narrow** — the `doc_pointer_liveness.rs`
idiom, whose recognition rules were measured before being frozen:

> A **doc link** is a markdown inline link `](TARGET)` whose `TARGET`, with any
> `#fragment` removed, ends in `.md`, contains no `://`, and does not begin with
> `/`. It must resolve, relative to the **containing file's directory**, to an
> existing file.

Scan set and prune set: `CITATION_SCAN` and `CITATION_SUFFIXES`, unchanged, with
the loop body **at parity with `check_decisions`'s and `sweep_task_surfaces()`'s**
— D116 §2 R2's rule, which this record notes now has **three** copies (§4 item 1).

**Why each clause of the subject, with the measurement:**

- **`.md` only.** Excludes `bundle_wire/mod.rs:13`'s rustdoc-HTML-relative link,
  which is correct where it is written and dead on disk (§1.8). It is the **only**
  non-`.md` relative link in the corpus, so the exclusion is 1-for-1 and needs no
  allowlist.
- **Both spellings, dot-prefixed and bare-relative.** 14 and 35 respectively; the
  wave-26 defect was one form and its repair the other (§1.1).
- **`#fragment` stripped, and the fragment NOT validated.** A stated limit, not an
  oversight: zero anchored links exist today, so an anchor-validating rule would
  be an assertion with no subject, and the branch that strips is exercised only
  by R3's constructed fixture.
- **No `://`, no leading `/`.** Zero of each today; both branches constructed in
  R3 for the same reason.
- **Fenced code blocks and inline code spans are SKIPPED** — the
  `doc_pointer_liveness.rs` rule verbatim (*"their content is code, not prose
  about code"*). **Measured 2026-08-22: adding this clause changes the live
  corpus not at all** — 49 links with it and 49 without, **0** inside fences and
  **0** inside spans. It is therefore an assertion with **no live subject**, and
  R3 constructs one. It is added anyway because **the false positive it prevents
  is already demonstrable in this record**: §2 R3 and §2 R5 quote four
  link-shaped strings — `` `[x](./missing-page.md#section)` ``,
  `` `[x](./real-page.md#section)` `` and both spellings of the `request.rs`
  line — inside code spans, none of which is a link. A record about broken links
  necessarily quotes broken links, so **without this clause the widening routed
  in §4 item 5 could never go green** (§4 item 5).

**Anti-vacuity: two floors, both `>=`, both printed exactly.** The comparison is
stated because this project has had a live `>=` that three witnesses said must be
`>`.

```python
# Measured 2026-08-22 over CITATION_SCAN: 49 links across 457 files.
# LOWER-ONLY BY DECISION, never by an implementer needing a run to go green —
# the FUZZ_BUDGET_CEILING_MINUTES idiom (scripts/ci-lanes.sh:1351-1353 today;
# D135 §3 R6 cites :1162-1164, which has drifted — D159 §4 item 7).
DOC_LINK_TOTAL_FLOOR = 45   # >= ; catches the walk collapsing
DOC_LINK_CRATES_SRC_FLOOR = 4   # >= ; Q249's own subject, AT the boundary
```

- **`DOC_LINK_TOTAL_FLOOR = 45`, measured 49.** The headroom is **exactly four** —
  the size of the subject — so a walk that loses `crates/**/src/**` entirely trips
  it while an ordinary doc edit does not. `README.md` + `CONTRIBUTING.md` alone
  yield **35**, so a collapse to the two root literals reds.
- **`DOC_LINK_CRATES_SRC_FLOOR = 4`, measured 4 — deliberately at the boundary.**
  This is the brief's *"assert the count equals 4"* rendered as `>=` rather than
  `==`: a **fifth** correct link must not redden the gate, while losing any of the
  four must. It is the guard against the named trap — a glob rooted wrong finds
  **0**, and `0 >= 4` is false.
- **Print both exact counts and the per-root breakdown on the `ok` line**, in the
  form the neighbouring checks use — D142 §2 R2's rule that the number a reader
  needs must be *printed*, not left as a subtraction nobody performs. Printing is
  **not** the assertion: `machine-paths` printed *"ok — 0 … across 455 live
  file(s)"* over a live plant, and that entry is in the ledger (U87's lane).

### R2 — The seven ungated `crate::evm` links are DE-LINKED. Both routes the row named are refused. **Who: the implementing lane.**

`[`crate::evm`]` becomes `` `crate::evm` `` — bracket pair removed, backticks and
surrounding prose unchanged — at **seven sites**:

`crates/antseal-net/src/wallet.rs` **:8, :42, :244, :376**
`crates/antseal-net/src/network.rs` **:14, :24, :261**

`network.rs:261`'s `[`crate::evm::to_evm_network`]` becomes
`` `crate::evm::to_evm_network` `` — the path is kept, only the link is dropped.

**The two links inside `ant_backend.rs` (`:7`, `:189`) are LEFT AS LINKS.** They
live in a module that is only ever documented when `ant-backend` is on, so they
resolve in every build that renders them.

**Six of the seven warn today; the seventh is edited anyway, and that is stated
rather than folded in silently.** `wallet.rs:244` sits on a `#[cfg]`-gated item
(§1.3) and emits nothing in a default build. It is de-linked with the other six
because the rule *"an ungated file does not link into a gated module"* is
readable and the per-item exception is exactly the subtlety that produced a wrong
number in the register. **A rule whose subtlety already misled its own registrar
is a rule to simplify.**

**Why de-linking, over the two arms the row listed:**

- It is **already the house form, eleven lines away**. `network.rs:501` writes
  `` in `crate::evm`, behind the feature) `` as a plain span while `network.rs:14`
  and `:24` write it as a link. The same module is named two ways in one file;
  one warns and one does not.
- It is correct under **every** feature combination — default, `GATE_LIGHT_FEATURES`,
  `--all-features`, docs.rs — where every other arm is correct under one.
- It is **verifiable with no doc build**: after the edit,
  `grep -rc '\[`crate::evm' crates/antseal-net/src/` must total **2**, both in
  `ant_backend.rs`. That property is checkable in a wave where `cargo doc` is not.
- The reader loses a hyperlink that only ever worked in a build they are not
  doing. `antseal-net` is unpublished, the repository is private, and the
  developer who has `ant-backend` on has the source.

**The route is stated at the site** — Accept row 3's requirement. Append to
`wallet.rs`'s and `network.rs`'s module docs, once each:

> `//! **[D159 §2 R2, 2026-08-22]** `crate::evm` is named here as a plain code`
> `//! span and NOT as an intra-doc link: this module is ungated while `evm` is`
> `//! behind the non-default `ant-backend` feature (`lib.rs:95-96`), so a`
> `//! default-feature `cargo doc` resolved the link against a module that is`
> `//! not there — six such warnings across this file and `network.rs`/`wallet.rs`.`
> `//! `crate::ant_backend`'s own docs keep the link form, because that module is`
> `//! only ever rendered with the feature on. Nothing mechanical enforces this;`
> `//! the doc build that would is armed at first publication (D159 §2 R6).`

### R3 — The faults to PLANT: three reds and three greens, and the greens are not decoration. **Who: the implementing lane.**

Every arm goes in `check-traceability.py`'s `--self-test`, whose house form
already *"builds one … and requires a planted RED fixture per arm — an arm added
here without a fixture fails `--self-test` with its own message"* (`:1886-1892`).
**Subjects are CONSTRUCTED, never derived from tree state** — Q252's rule, and the
reason `plant_an_unrecorded_decision()` sits at module level (`:739-775`).

**RED 1 — the row's own `Accept` clause, and the message must name the file.**
Restore `../../../` at `crates/antseal-core/src/anchor/request.rs:2`. Required:
`[doc-links]` reds with a message naming **`crates/antseal-core/src/anchor/request.rs:2`**,
the target as written, and the path it resolved to
(`crates/docs/decisions/D59-request-nonce-persistence.md`). A message that says
only *"1 broken link"* does not discharge this.
**Restore by re-editing the character, never by `git checkout`/`stash`/`restore`**
— lanes share one working tree — and verify the restore by **re-reading line 2**
and re-running the check green, not by the absence of a failure.

**RED 2 — the vacuity plant the brief names.** Point the walk at a constructed
empty directory (a fixture root with zero `.md` links). Required: `[doc-links]`
reds with a message **naming the floor it fell below and both numbers**
(`0 < 45`, `0 < 4`) — **not** a silent `ok — 0 broken`. This is the arm that
would otherwise pass green forever; the U87 ledger entry is the proof that
printing a count without asserting it does not save a check.

**RED 3 — the fragment branch, which has no live subject.** A constructed file
containing `[x](./missing-page.md#section)`. Required: red, naming the file part
and not the fragment. Its purpose is to prove the strip is a strip and not a
truncation of the whole target.

**GREEN 1 — the `.md` restriction, asserted rather than assumed.** With
`crates/antseal-core/tests/bundle_wire/mod.rs:13`'s
`[`crate::manifest_wire`](../manifest_wire/index.html)` present and unchanged,
`[doc-links]` must be **green**. *"A double is evidence only once you have watched
it panic"* (U86's lane) — an exclusion is evidence only once you have watched it
exclude, and this one has a live subject sitting in the tree.

**GREEN 2 — the code-span and fence exclusion, which has no live subject.**
A constructed file whose only link-shaped strings are a broken `.md` link inside
an inline code span and another inside a fenced block must be **green**; the same
file with one of them moved *outside* the span must be **red**. Measured, nothing
in the live corpus exercises either branch (§2 R1), so this pair is the only
thing that can. Its subject is exactly this record's own §2 R3 and §2 R5 text.

**GREEN 3 — the fragment branch's positive half.** A constructed
`[x](./real-page.md#section)` pointing at a file that exists must be **green**.
Without it, RED 3 passes for a check that reds on every anchored link.

**And read `--help` before writing a flag into any brief:**
`check-traceability.py` has **no `--check` flag** — its **flagless run is the
check** — and `--self-test` **stages a full tree copy**, so it is banned mid-wave
exactly as `local-gate.sh` is. The implementing lane runs the flagless check
freely and schedules `--self-test` for a quiet tree.

### R4 — The venue's cost, stated; and D135 §3 R6 is measured NOT TRIGGERED. **Who: this record** (Accept row 4 is discharged by these numbers).

| | |
|---|---|
| new required status contexts | **0** — the set stays at **19** |
| new workflow files | **0** |
| new job steps, hosted | **0** — the check is a function inside a script two steps already invoke |
| new hosted weighted minutes | **0** |
| local cost, the sweep alone | **0.110 s** median of three runs, 457 files, 49 links |
| local cost, the self-test arms | **estimated** +6 × the per-arm cost of a ~0.42 s run ≈ **+2.5 s** on an 8.6 s pair. **An estimate, not a measurement** — `--self-test` stages the tree and may not be run mid-wave. The implementing lane records the real number. |

**D135 §3 R6 governs *"Promoting this to push tier"* and its precondition is a
measured monthly bill under the allowance.** Nothing here is promoted to push
tier: the job already runs on every push of every kind, on the workflow whose
defining property is that it carries no path filter. **The decision act R6
describes is not being taken**, and this row's Accept row 4 is discharged by
saying so with the numbers rather than by pricing a context nobody is raising.

*(And if it were being raised: it could not be witnessed. The allowance is
exhausted, measured on `runner_name` today (§1.5), and *"a lane that has never run
on the remote is not evidence"*.)*

### R5 — `request.rs:2`'s prefix is corrected. **Who: the implementing lane.**

`crates/antseal-core/src/anchor/request.rs:2`:

- old: `//! [D59](../../../docs/decisions/D59-request-nonce-persistence.md)).`
- new: `//! [D59](../../../../docs/decisions/D59-request-nonce-persistence.md)).`

One character. Verified by resolving the target against the filesystem —
`realpath -m` from the file's directory must yield
`docs/decisions/D59-request-nonce-persistence.md` and `test -e` must pass — **not**
by counting `../` segments, which is how it was written wrong.

**The three siblings are correct and are not touched**: `http.rs:2` at
`../../../` (one directory shallower) and both `arbitrum/*.rs` at `../../../../`.

### R6 — No documentation build is landed, in either venue. It is ARMED by first publication, not deferred and not overdue. **Who: this record.**

Refused in the **hosted** venue because it cannot run and would not be evidence if
it did (§1.5, and Q43's rule). Refused in the **local gate** because after R2
there is nothing in the `crate::evm` class left for it to catch; because the six
remaining broken intra-doc links are unenumerated and cannot be enumerated this
wave; and because catching them would need `--all-features`, which breaches the
containment `GATE_LIGHT_FEATURES` exists to hold (§1.4).

**It is not "deferred forever" and it is not overdue: it is a third state.** The
event that makes a documentation build load-bearing is **publication** — docs.rs
runs a default-feature `cargo doc` on upload, and until an `antseal-*` crate is
uploaded there is no reader for the output. That trigger is **`Q241`** (the
publish blocker) with **`Q31`** (the release workflow). **The doc build fires with
the first `cargo publish`, and `[package.metadata.docs.rs]` is decided in that
act, not this one** (§3 item 3, §4 item 2).

### R7 — `TODO.md:847`'s truncated tail is COMPLETED with the exact text below, reconstructed from `tasks/Q.md:3159` and corrected. **Who: the registrar.**

The row was born truncated in `de71a09` and is byte-identical in HEAD and the
working tree (§1.9), so nothing can be restored from git. The reconstruction
source is **`tasks/Q.md:3159`, Q249's first `- Notes:` block**, which carries the
same sentence whole.

**Old** (the row's final characters, exact):

> `(build lock); the link inventory and the zero-lane result were`

**New** — replace from `were` to end of line:

> `were re-measured centrally and stand on their own. **[D159, 2026-08-22 — this clause was committed TRUNCATED in `de71a09` and stood so through six commits; completed here from `tasks/Q.md`'s Q249 Notes, which carries the sentence whole, with one figure corrected rather than restored.]** **SIX, not seven, of the nine `crate::evm` links are reachable in a default build**: `wallet.rs:244`'s doc comment sits on `hex_str`, itself `#[cfg(feature = "ant-backend")]` at `wallet.rs:247`, so gating is per-**ITEM**, not per-**FILE** — which reconciles the register with the lane's own `cargo doc` figure of *"six of them `crate::evm`"* that the row records and disbelieves. **Resolved by D159**: the check is a ninth `check-traceability.py` check over **49 links / 457 files / 0.110 s**, zero new contexts; the seven ungated links are **de-linked**; **no doc build is landed**, and it is **armed by first publication** (Q241/Q31), not deferred.`

**Verification, and it is not an exit code.** After the edit, `awk 'NR==847'
TODO.md` must end with the literal `not deferred.` and no longer contain the
substring `result were` followed by end-of-line; and the row's byte length must
have moved from **1 669**. Read the value back out of the file.

### R8 — `tasks/Q.md:3160` is MOVED to Q250's entry, byte-preserved, with one clause of provenance. **Who: the registrar.**

Not deleted and not copied — Q250 does not have it (§1.9), so this is the block's
only home and it is under the wrong heading.

1. **Cut** `tasks/Q.md:3160` in full (the `- Notes: **[Registrar, 2026-08-19 —
   wave 26 execution…` line) from Q249's entry.
2. **Paste** it into Q250's entry, **after** Q250's existing `- Notes:` at
   `:3175`, unchanged except for its opening bracket, which becomes:

   > `- Notes: **[Registrar, 2026-08-19 — wave 26 execution. Refiled from Q249's entry 2026-08-22 by D159 §2 R8: it was written under Q249's heading and its whole subject is this row — `wallet-hygiene.md` §4, `ant-protocol`, `build_paid_chunks` — and it quotes this row's own `Do` string verbatim (*"cite `ant-protocol` by version and line as the user page does"*, `tasks/Q.md:3170`). Q249's entry consequently read as executed while its `TODO.md` row was `[ ]`. Text below is unchanged. One deviation from this row's `Do`, recorded rather than silently taken, and two upstream facts the row did not carry.]** …`

3. **Correct the surviving Notes block's number.** In `tasks/Q.md:3159`, apply the
   house strike-in-place form (D150 §2 R1 — a term deleted invites
   re-derivation; a term struck with its reason attached does not):

   - old: `nine `crate::evm` links, seven reachable in a default build`
   - new: `nine `crate::evm` links, ~~seven~~ **six** reachable in a default build *(corrected 2026-08-22 by D159 §2 R8 — `wallet.rs:244`'s doc comment is attached to `hex_str`, itself `#[cfg(feature = "ant-backend")]` at `wallet.rs:247`; gating is per-ITEM, not per-FILE, and the lane's `cargo doc` figure of "six" that this sentence sets aside was the correct one)*`

**Verification.** After the edit, Q249's entry span must contain **exactly one**
`- Notes:` line and Q250's **exactly two**; `grep -c 'wave 26 execution'` over the
whole file must still return **1**. Counts, read back from the file.

### R9 — No row is minted, no new script is created, one ledger line. **Who: the registrar.**

**Rule 8 governs and the promotion test is not met.** The finding that no
documentation build exists is an instrument finding — its subject is the
verification apparatus — and it does **not** block an acceptance on the ship
path: no `Accept` row of `Q34` (the M4 gate), `Q32` or `U32` names a doc build,
and the reader that makes one load-bearing arrives at publication (R6). It takes
**no ID and no row**; it takes the ledger line below. This is D154 §2 R11's shape,
one wave old and for the same reason.

**No new script.** A ninth function in a script that already sweeps these files,
already runs in both venues and is already cargo-free is strictly cheaper than a
new file that would need its own gate seat, its own CI seat, its own self-test
harness and its own entry in `check-ci-paths.py`'s reader set.

**Ledger line** (`docs/instrument-ledger.md`, house format):

> `2026-08-22 · D159's lane (wave 28) · **`cargo doc` could not have found the defect that raised Q249, and the check that could was a missing field in an existing one.** rustdoc's doc-link lints resolve **item paths**, never filesystem targets, so `[D59](../../../docs/…md)` is emitted verbatim and validated by nothing — corroborated by the Q248 lane's own run, which reported *"twelve broken **intra-doc** links"* with `request.rs:2` not among them and found it **by reading**. Meanwhile `check_decisions` extracts `\bD(\d+)\b` and **never reads the link path**, so the citation was green on the id while the path pointed at `crates/docs/decisions/`. Corpus re-measured over the roots already swept: **49 relative `.md` links across 457 files, exactly 1 broken, 0.110 s** — `README.md` **19** and `CONTRIBUTING.md` **16** among them, neither swept for this by anything, which is the wave-26 README defect's class recurring four days later. Two counting corrections: **six, not seven**, `crate::evm` links are reachable in a default build (`wallet.rs:244` sits on a `#[cfg]`-gated item, so gating is per-**ITEM**), which vindicates the `cargo doc` figure the register had "corrected"; and the **only** non-`.md` relative link in the tree (`bundle_wire/mod.rs:13` → `../manifest_wire/index.html`) is correct-as-rustdoc and dead-on-disk, so a checker walking every relative link reds on a correct one on day one. **Thirteen warnings / twelve broken intra-doc links stand as an unverified single measurement; six are accounted for and removed at source; SIX REMAIN UNENUMERATED ANYWHERE IN THIS TREE.** No doc build is landed and none is minted — it is **armed by first publication** (Q241/Q31), which is when docs.rs first renders any of it · scripts/check-traceability.py `check_decisions` · docs/decisions/D159 · TODO.md rule 8`

### R10 — Per-Accept-row disposition for `Q249`. **Who: the registrar** (the amended text lands in `tasks/Q.md`).

Vocabulary per D140 §2 R1, D143 §2 R5, D148 §2 R10.

**Row 1** — *"Every relative link in `crates/**/src/**` resolves on disk, asserted
by a check that reads the filesystem, with a planted broken link watched red **by
message naming the file**."*
→ **AMENDED (widened; the mechanism and the red are kept verbatim).** New text:

> Every markdown link whose target is a relative `.md` path resolves on disk
> across `check-traceability.py`'s existing `CITATION_SCAN` roots — **49 links
> over 457 files, measured 2026-08-22**, of which the **four** in
> `crates/**/src/**` are this row's subject and `README.md`'s 19 and
> `CONTRIBUTING.md`'s 16 are swept for this by nothing today — asserted by the
> ninth check `--doc-links` (D159 §2 R1), which prints both exact counts and
> holds two floors, `total >= 45` and `crates/**/src/** >= 4`. Watched red by
> **three** plants and green by **three** controls (D159 §2 R3): the
> `request.rs:2` prefix restored, red **by a message naming that file and the
> path it resolved to**; a constructed **zero-corpus** root, red **by a message
> naming the floor and both numbers**; a constructed `#anchor` link at a missing
> file, red; the live `index.html` link, green; a constructed `#anchor` link at a
> real file, green; a constructed broken link inside a code span and inside a
> fenced block, green — and red once moved outside. The last three branches have
> **no live subject** and are the only reason those arms can fail at all.

**Row 2** — *"A documentation build runs somewhere a human or a lane will see it,
and its warning count is asserted against a recorded number rather than
eyeballed."*
→ **AMENDED to INAPPLICABLE-AND-ARMED, with the reason on the record.** It is not
withdrawn as mistaken; it is measured to be aimed at a mechanism that could never
have caught this row's defect. New text:

> **No documentation build is landed by this row** (D159 §2 R6). `cargo doc`
> resolves **item paths**, never filesystem targets, so it could not have found
> `request.rs:2` in any venue — the Q248 lane's own run proves it, reporting
> *"twelve broken **intra-doc** links"* without it, while the lane found it by
> reading (D159 §1.2). Hosted: refused — the allowance is exhausted (measured
> `runner_name: ""`, `steps: 0`, 2026-08-20), and *"a lane that has never run on
> the remote is not evidence"*. Local: refused — after the de-link there is
> nothing in the `crate::evm` class left to catch, the six remaining broken
> intra-doc links are unenumerated and unmeasurable this wave, and reaching them
> needs `--all-features`, which breaches `GATE_LIGHT_FEATURES`' containment of
> the ~600-package `ant-core` graph. **The count `13 warnings / 12 broken
> intra-doc links / 6 of them `crate::evm`` stands as one unverified
> measurement**, recorded with its provenance in `docs/instrument-ledger.md`.
> The build is **ARMED by first publication** (Q241/Q31) — docs.rs is its first
> reader — and takes **no row** under rule 8 (D159 §2 R9).

**Row 3** — *"The `crate::evm` decision is recorded — gated links or a docs.rs
feature set — and the chosen route is stated at the site."*
→ **AMENDED: MET on its second half, and its enumeration is corrected.** The route
taken is **neither** of the two the row lists. New text:

> The route is **de-linking**: `[`crate::evm`]` → `` `crate::evm` `` at the
> **seven** sites in ungated files (`wallet.rs:8,42,244,376`;
> `network.rs:14,24,261`), the two inside `ant_backend.rs` left as links
> (D159 §2 R2). **Six of the seven warn in a default build; `wallet.rs:244` does
> not** — its doc comment is attached to `hex_str`, itself `#[cfg]`-gated at
> `:247` — and it is de-linked with the others so the rule reads *"an ungated
> file does not link into a gated module"* with no per-item exception, which is
> the subtlety that produced this row's own wrong count. Both listed arms are
> refused (D159 §3): gating the doc lines makes the rendered docs
> feature-dependent for no reader; a `[package.metadata.docs.rs]` key is inert
> until publication, which is blocked, and would be **an assertion that cannot
> fail**. The route is stated at both module-doc sites, with the note that
> nothing mechanical enforces it and that the doc build which would is armed at
> publication.

**Row 4** — *"The check's venue and its weighted-minute cost are stated, because
D135 §3 R6 makes raising a required context a decision act."*
→ **MET, and D135 §3 R6 is measured NOT TRIGGERED.** New text:

> Venue: a ninth check inside `scripts/check-traceability.py`, which already runs
> in `local-gate.sh` and rides `ci-always.yml`'s `traceability` job — a workflow
> that carries **no path filter, ever**. **Zero new required status contexts (the
> set stays at 19), zero new steps, zero new hosted weighted minutes.** Local
> cost **0.110 s** for the sweep (measured, 3 runs); the self-test arms are
> **estimated** at +2 s and re-measured by the implementing lane, because
> `--self-test` stages the tree and may not be run mid-wave. **D135 §3 R6 governs
> promoting a check to push tier; nothing is promoted**, so the decision act it
> describes is not taken. Recorded independently: were one raised, it could not
> be witnessed — the Actions allowance is exhausted (D159 §1.5).

---

## 3. What was refused and why

1. **Refused: the lean, *"a hosted doc context is too expensive; put it in the
   local gate."*** Both halves fail. A hosted context is not *expensive*, it is
   **unrunnable and unwitnessable**; and the local gate is the wrong home for a
   `cargo doc` that could not have found the defect and would need
   `--all-features` to find anything else.
2. **Refused: the brief's replacement framing, *"a new hosted context costs zero
   minutes because no minutes are being spent."*** The zero spend is produced by
   the exhausted allowance. Measured on the field that carries the claim —
   `runner_name: ""` — this is the signature D135 measured across 45 jobs and
   `docs/ci-verification.md` diagnoses. Reading it as headroom is the
   symptom-for-cause substitution D135 itself had to withdraw a correction over.
3. **Refused: `[package.metadata.docs.rs]`**, one of the two arms the row's own
   `Accept` names. It is **inert until publication**, which is blocked (`Q241`);
   it commits a docs.rs build to the ~600-package `ant-core` graph that has never
   been built there; and nothing in this repository could ever red on it being
   wrong. It is the **assertions-that-cannot-fail** class, added to a manifest.
   Routed to the publish act (§4 item 2), where it becomes verifiable.
4. **Refused: gating the doc lines** (`#[cfg_attr(…, doc = "…")]`), the other arm
   the row names. Six sites, and it makes the *rendered documentation* differ by
   feature for a reader who gains nothing either way. `#[doc(cfg)]` is refused
   separately: it needs `feature(doc_cfg)`, and the workspace pins
   `rust-version = "1.92.0"` stable.
5. **Refused: accepting the warnings with a pinned count.** Circular. The only
   count on record is a single unverified measurement; six of its twelve broken
   links are unenumerated anywhere; establishing the pin requires the build the
   venue question is about; and no lane may run it this wave.
6. **Refused: `crates/**/src/**` as the corpus.** It is 4 links where 49 are
   available at **no new scan root**, and it excludes the two files that carry 35
   of them — the files where this exact defect class was found in wave 26 and
   where the ledger explicitly banked a baseline *"for any future checker."*
7. **Refused: a checker over every relative link.** Measured to red on a
   **correct** link on day one — `bundle_wire/mod.rs:13`'s rustdoc-HTML-relative
   `../manifest_wire/index.html`. The `.md` restriction excludes it by a property
   of the target; an allowlist would have been the alternative, and D144 §2 R4's
   own failure text refuses that shape.
8. **Refused: a new script.** Nine functions in one script that already occupies
   both venues, versus a tenth file needing its own seats, self-test and reader
   set. `check-traceability.py`'s own docstring already names this subject class:
   *"something written down in prose asserts a fact about the repository, and
   nothing else verifies it."*
9. **Refused: `doc_pointer_liveness.rs` as the home.** Best thematic fit and wrong
   scope: `antseal-core` only, covering **one** of the four crate-source links,
   not cargo-free, and its widening is **already `Q70` and `Q144`**.
10. **Refused: `==` for the crates floor.** `>= 4` at the boundary, so a **fifth**
    correct link does not redden the gate while losing any of the four does. The
    comparison is written down because this project has had a live `>=` that
    three witnesses said must be `>`.
11. **Refused: restoring `TODO.md:847`'s tail verbatim from `tasks/Q.md`.** The
    source sentence contains the **`seven`** that §1.3 measures as wrong. The tail
    is completed **and corrected**, with both facts stated in the row.
12. **Refused: deleting the misfiled Notes block.** It is Q250's only copy and it
    carries two real upstream findings. It is **moved**, byte-preserved, with one
    clause saying why.
13. **Refused: minting a row for the doc build.** Rule 8: instrument-class
    subject, and it blocks no acceptance on the ship path. One ledger line, and a
    named trigger.

---

## 4. Routed, not ruled

1. **`check-traceability.py` now has THREE parallel loop bodies over one scan
   set.** D116 §2 R2 gave `check_decisions` and `sweep_task_surfaces()` one scan
   set and left two loop bodies *"at parity"*, with the comment at `:990` warning
   that *"having different prune sets afterwards is exactly the divergence R1
   exists to end."* R1 adds a third. Extracting one generator all three consume is
   the right repair and it is a **refactor of two currently-green checks**, which
   is more than this row should carry. **Instrument class under rule 8 — a ledger
   candidate, not a row.**
2. **`[package.metadata.docs.rs]` at the publish act.** When `Q241`/`Q31` make a
   `cargo publish` real, the docs.rs feature set must be decided **and** the
   resulting build read — including whether docs.rs can build the `ant-backend`
   graph at all within its limits. Named here so the publish lane does not
   re-derive it. **Recorded, not ruled.**
3. **The six unenumerated broken intra-doc links.** They exist by a measurement
   nobody has repeated. The first lane to hold no build lock can enumerate them in
   one `cargo doc` and append the list to the ledger; that is minutes of work and
   it is not this row's.
4. **`crates/antseal-wasm/README.md:9`'s relative link is in the corpus and
   resolves**, and it is the only link under `crates/` outside `src/`. It counts
   toward `DOC_LINK_TOTAL_FLOOR` and **not** toward `DOC_LINK_CRATES_SRC_FLOOR`.
   Recorded so a later reader does not "fix" the floor to 5.
5. **`docs/decisions/` is NOT in `CITATION_SCAN`,** so the **154** decision records —
   the densest cross-linking surface in the tree — are outside this check. The
   wave-26 defect was a **ruling** specifying a path that did not resolve, so this
   is the surface where the class was last found. Widening the scan root is a
   deliberate act with a measurable cost (D123's precedent: `.toml` moved 359 →
   377 files with 15 collateral findings) and it is **not** taken here.
   **And it is gated on one clause of §2 R1, not merely on cost**: a decision
   record about broken links necessarily **quotes** broken links, so without the
   code-span/fence exclusion the widening reds on the evidence — this record
   alone carries four such strings (§2 R3, §2 R5). Whoever takes the widening
   must first confirm that clause is implemented and that GREEN 2 covers it.
   **Next planning round, or the first row that needs it.**
6. **D135 §3 R6's own locator has drifted, and this record cites the live one.**
   R6 pins the *raise-only* idiom to `scripts/ci-lanes.sh:1162–1164`; measured
   2026-08-22, `FUZZ_BUDGET_CEILING_MINUTES` and its
   *"RAISE-ONLY BY DECISION, never by an implementer needing a build to go
   green"* comment are at **`:1351-1353`**. The **substance is intact** — the
   constant, the comment and the wording are all exactly as R6 quotes them — so
   this is a stale pointer, not a false claim, and it is recorded here rather
   than corrected in a record this row does not own. Same class as rule 7's two
   locators that went stale within one wave of being written. **Instrument class
   under rule 8 — a ledger candidate, not a row.**
7. **The `Do`'s coupling should not be copied.** *"Land a `cargo doc` check with
   the fix or the warnings return"* reads as one obligation and is two. Any future
   row pairing a fix with a lint should name **which lint sees which defect**
   before pricing a venue for it.

---

## 5. Edit set

**Timing words** per rule 7 as amended by D154 §2 R10: `after` is a precedence,
`with` is co-timing in one act, `before` is a precedence the other way. Collapsing
`with`/`before` to `after` invents a dependency.

### Implementing lane — `crates/` and `scripts/` only

1. **`crates/antseal-core/src/anchor/request.rs:2`** — `../../../` → `../../../../`
   (§2 R5). *Verify by `realpath -m` + `test -e`, never by counting segments.*
2. **`crates/antseal-net/src/wallet.rs`** `:8`, `:42`, `:244`, `:376` — drop the
   `[`…`]` brackets around `crate::evm`, keeping the backticked path (§2 R2).
   **with** edit 3.
3. **`crates/antseal-net/src/network.rs`** `:14`, `:24`, `:261` — same; `:261`
   keeps the full path `` `crate::evm::to_evm_network` `` (§2 R2). **with** edit 2.
4. **`crates/antseal-net/src/wallet.rs`** and **`network.rs`** module docs — append
   the §2 R2 *"named as a plain code span and not a link"* paragraph, once each.
   **with** edits 2 and 3 (same act, or the sites are unexplained).
5. **`scripts/check-traceability.py`** — the ninth check `doc-links` (§2 R1): the
   two floor constants with their measurement dates, the check function with its
   loop body **at parity** with `check_decisions`'s, the `CHECKS` dict entry, and
   the module docstring's *"Eight checks live here"* → **"Nine"** plus the new
   paragraph in its flag table. **The docstring count is a load-bearing number in
   a file whose comments this project has already found stale; change it in the
   same edit.** **after** edit 1 — the check must be able to run green on a fixed
   tree before its red arms are believed.
6. **`scripts/check-traceability.py`** `--self-test` — three red arms and three
   green controls (§2 R3), subjects **constructed**, not derived — three of the
   six branches have **no live subject** in the tree and exist only as fixtures.
   **with** edit 5.

### Registrar — `TODO.md`, `tasks/`, `docs/`

7. **`TODO.md`** Q249 row (`:847`) — replace the truncated tail with §2 R7's exact
   text. Old string: the line's final `the link inventory and the zero-lane result
   were`. **Read the new byte length back out of the file.**
8. **`tasks/Q.md:3160`** — **cut** the misfiled Notes block; **paste** into Q250's
   entry after `:3175` with §2 R8's amended opening bracket. **One move, one act**
   — never a delete followed by a later re-add.
9. **`tasks/Q.md:3159`** — strike `seven` → **six** with §2 R8's dated citation.
10. **`tasks/Q.md`** Q249 `- Accept:` — the four amended rows of §2 R10, replacing
    rows 1–4 in place.
11. **`docs/instrument-ledger.md`** — the §2 R9 line, appended.
12. **`docs/decisions/README.md`** and `TODO.md`'s decision register — one index
    row and one register row for **D159**, in the same commit that lands this
    file, per rule 3 as amended by **D142 §2 R4**. *(This file is itself one of the
    three homes, so the id is not homeless in the interim; D119 RULING 6's mid-act
    window applies.)*

**Post-edit verification, and none of it is an exit code.**

- `python3 scripts/check-traceability.py` (**flagless — that IS the check; there is
  no `--check` flag**) → **9 of 9 ok**, with `[doc-links]` printing **49** links,
  **457** files and the per-root breakdown, and `[decisions]`/`[decision-index]`
  staying green only if D159's index and register rows land in the same act.
- `grep -rc '\[`crate::evm' crates/antseal-net/src/` → **total 2**, both in
  `ant_backend.rs`. Any hit in `wallet.rs` or `network.rs` is a missed site.
- `realpath -m` from `crates/antseal-core/src/anchor/` on the new target →
  `docs/decisions/D59-request-nonce-persistence.md`, and `test -e` passes.
- `awk 'NR==847' TODO.md` ends with `not deferred.`; the row's byte length is no
  longer **1 669**.
- Q249's entry span holds **exactly one** `- Notes:`; Q250's holds **exactly two**;
  `grep -c 'wave 26 execution' tasks/Q.md` → **1**.
- `scripts/check-traceability.py --self-test` on a **quiet tree** (it stages a full
  copy; banned mid-wave) → every arm red on its plant, with **RED 1's message
  naming `crates/antseal-core/src/anchor/request.rs:2`** and **RED 2's naming the
  floor and both numbers**. A nonzero exit is not the evidence; **the message is**,
  and `$?` after a pipe reports the pipe.

**Availability delta, stated plainly so the next readiness survey does not
re-derive it:** **`Q249` closes** on this edit set. **Nothing is unblocked and
nothing new is blocked.** `Q241` and `Q31` gain a named consumer — the armed doc
build — which is a note in the ledger, not an edge in any `after` run.
