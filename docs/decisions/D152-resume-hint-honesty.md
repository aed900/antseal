# D152 — the hint is not the defect: a stranded work has *no exit at all*, three messages point at the one command that fails, and arm (a)'s stated mechanism is unbuildable — but the vault already recorded the answer it needed

- **Status: RESOLVED. The lean's DIRECTION survives; its MECHANISM is
  unbuildable as stated and is replaced; its two prescribed WORKAROUNDS are
  measured WRONG for the case they are printed on; and the defect is larger
  than the row.** The lean was *"suppress the hint for a stored shaping U82's
  predicate would refuse, and print the reason plus a workaround (D24's own
  two: seal it as a separate work without `--split`, or drop one flag)."*
  - **"evaluate U82's predicate in `list`" is UNBUILDABLE.** The predicate's
    decisive term is `file_is_text(&file.absolute, &file.as_given)?`
    (`crates/antseal-cli/src/seal_plan.rs:463`), which is
    `std::fs::File::open` (`:514-521`) over a **whole-file** UTF-8 test
    (D149 §1.5). `list` holds no `SealArgs`, no `cwd`, no `PlannedFile`, and
    — measured across `WorkListing::gather` (`listing.rs:524-583`) — opens no
    user file at all. The bytes it would have to read are today's bytes, not
    the sealed ones, so the answer would be an answer to a different
    question, would vary between two `list` runs with no vault change, and
    would put an unbounded read behind a read-only reporter. §1.4.
  - **The arm nobody listed, and it decides the record: the vault already
    holds the answer, exactly.** The journaled plaintext manifest records,
    per file, `kind` (Text iff `is_text(raw) || force_text` —
    `crates/antseal-core/src/content/assemble.rs:536`), `fine_tree_present`
    (`= !opt_out.is_requested() && size > 0` —
    `content/descriptor.rs:248`) and the size, and `listing.rs:937`
    **already reads that record** through `recorded_plan`. Those three fields
    are `refuse_split_on_no_fine_tree`'s three content terms, evaluated on
    the bytes that were actually sealed, with **zero filesystem access**.
    §1.6.
  - **The cheap "both flags are present" trigger is REFUSED, and its
    false-positive population is the *designed* use of the pair.** A work
    sealed `--split blank-lines --no-fine-tree '*.png'` over a real PNG is
    legal today, seals today, resumes today — D24 §1's G6 exemption is
    exactly that case — and the cheap trigger would tell its owner the work
    is dead. §1.5.
  - **The lean's two workarounds are wrong for the work they would be printed
    on.** *"Drop one of the two flags"* on the same paths lands on
    `CliError::ResumeFlagMismatch` → exit **26**, whose own message says
    *"re-run with the original flags to resume and finish it"* — the command
    that is refused. *"Seal it as a separate work"* over any overlapping path
    set lands on `ResumeOverlapNotExact` → exit **25**, whose message says
    *"`antseal list` shows … the exact command that finishes it"* — the same
    refused command. Both cycles close on the hint. §1.3.
  - **And the trap is total, because the exit does not exist.** `Command`
    (`crates/antseal-cli/src/cli.rs:113-185`) has nine subcommands and
    **none of them is `abandon`**; `VaultCommand` (`:463-480`) is `export`
    and `import`. `seal_resume::abandon_pre_pay` has **no production caller**
    — every call site is a test. So a stranded work cannot be finished,
    cannot be discarded, and both refusals that mention it point back at the
    command that fails. The one escape that works is not in any of the three
    messages as an instruction: **move or copy the files to different paths**.
    §1.3.
  - **U85's fixture claim is CONFIRMED, and there is a second site the row
    does not name.** `listing.rs:1747-1770` pins a `*.png` glob over
    `.txt`/`.md` paths, which `glob_matches` (`seal_plan.rs:672`) cannot
    match; the zero-match rule (`seal_plan.rs:239-250`) has refused that
    shaping since `442165e` (2026-08-02), sixteen days before U82, at exit
    **2** (D149 §1.1 CONTROL A). The same production-unreachable shaping is
    pinned a second time at `crates/antseal-cli/tests/list_command.rs:304-317`.
    §1.8.
- **Date: 2026-08-18**
- **Owning task: U85.** Blocks nothing; **U32** (the M4 golden-rendering
  freeze) consumes the copy this record rules, so it lands before U32's
  freeze or U32 freezes the dishonest rendering.

## 0. What was measured against

Tree clean at `c88d19f` (2026-08-18), branch `main`, no uncommitted changes at
lane start. Default features (`ant-backend` off). One suite executed:

```
$ cargo test -p antseal-cli --lib listing::
   Finished `test` profile ... in 4.32s
running 17 tests
... test listing::tests::the_resume_hint_reproduces_every_identity_flag ... ok
test result: ok. 17 passed; 0 failed; ... finished in 0.42s
REAL_EXIT=0
```

`REAL_EXIT` was written into a file and read back. The run is not vacuous: it
compiled the crate and ran 17 named tests, including the fixture this record
adjudicates. Everything else below is source measurement with `file:line`, or
a committed measurement quoted from D149 with its own execution record. No
Rust source was edited by this lane; the write scope was this file alone.

## 1. The measurement

### 1.1 The locators, re-measured — one correction to the row

U85's row cites `crates/antseal-cli/src/listing.rs:1128-1138` for
`seal_invocation`. Measured, that range is the **flag-reproduction band**
only:

| what | line |
| --- | --- |
| `pub fn seal_invocation(...)` | `listing.rs:1119` |
| `--split blank-lines` reproduction | `:1128-1131` |
| `--force-text` reproduction | `:1132-1134` |
| `--no-fine-tree` reproduction | `:1135-1138` |
| the two hint constructions in `gather` | `:542-549`, `:550-557` |
| the human render of the hint | `:670-674` |
| the `--json` `resume` object | `:1080-1084` |
| the unit fixture | `:1747-1770` |
| `refuse_split_on_no_fine_tree` | `seal_plan.rs:454-495` |
| its text read | `seal_plan.rs:463` → `file_is_text` `:514-521` |
| `build_plan`'s call of it | `seal_plan.rs:258` |

The row's file correction (`src/listing.rs`, not `src/pipeline/listing.rs`) is
right. The line range should read **`:1119-1150`** for the function, or
`:1128-1138` qualified as *the flag band*.

### 1.2 `seal_invocation` is printed at five sites, not one — and one of them
is attached to a *paid* work

```
$ rg -n 'seal_invocation' crates/antseal-cli/src crates/antseal-cli/tests
listing.rs:543, :551      the two resume hints (`list`)
listing.rs:1119           the definition
seal_resume.rs:208, :213  CliError::ResumeFlagMismatch detail  (exit 26)
seal_resume.rs:262        CliError::ResumeOverlapNotExact detail (exit 25)
seal_resume.rs:409        abandon_pre_pay's paid refusal
list_command.rs:308       the integration fixture
```

`seal_resume.rs:409` sits inside `abandon_pre_pay`, and §1.3 shows that
function has no production caller — so the **reachable** printers are
`list`'s two hints and `match_candidates`' two error details.

### 1.3 The trap: no exit exists, and both refusals point back at the hint

**Ordering.** `build_plan` is called once, at
`crates/antseal-cli/src/commands.rs:292` — **before** `open_layout` (`:350`),
the vault lock (`:352`), `NetworkConfig::select` (`:361`) and
`collect_passphrase` (`:370`). Resume detection runs far later, inside
`seal_run.rs:371` (`detect(&store, …)`), which needs `session.vault()` and is
therefore behind the unlock. **So a resume of a work carrying the pair aborts
at exit 27 before the vault is even opened**, and `build_plan` cannot know it
is looking at a resume.

**The three doors, measured.**

| the user does | lands on | what its message says |
| --- | --- | --- |
| re-runs the printed command | `refuse_split_on_no_fine_tree` → `invalid-seal-argument`, **27** | *"Seal it as a separate work without --split, or drop one of the two flags (D24)"* (`seal_plan.rs:488-490`) |
| re-runs the same paths with a flag dropped | `match_candidates` → `ResumeFlagMismatch`, **26** | *"re-run with the original flags to resume and finish it … sealing a copy under a different path"* (`error.rs:775-781`) |
| seals an overlapping subset | `match_candidates` → `ResumeOverlapNotExact`, **25** | *"`antseal list` shows the incomplete seal and the exact command that finishes it (D45)"* (`error.rs:763-769`) |

Door 2 sends the user back to the command door 1 refuses. Door 3 sends the
user to `list`, which prints the command door 1 refuses. **Both cycles close
on the hint, which is why `list` is the venue that has to break them.**

**And there is no fourth door.** `Command` at `cli.rs:113-185` is
`Init, Seal, List, Show, Status, Restore, Reveal, Verify, Vault`;
`VaultCommand` at `:463-480` is `Export, Import`.

```
$ rg -n 'abandon_pre_pay' crates/
src/seal_resume.rs:368        the definition
src/error.rs:758              a doc comment naming it
tests/seal_command.rs:1276, :1315, :1348, :1397   the only callers
```

`error.rs:755-762` states the situation in the tree already: *"the abandon
**mechanism** exists … but the surface token that would invoke it is D45's
deliberately-deferred decision (**U41**)"*, and `ResumeFlagMismatch`'s own
copy says *"This build has no way to discard a staged work"*. **U41 is
already open and its row already calls itself *"the only thing standing
between a user and the flag-mismatch trap"* (`TODO.md:416`). U85 is the second
trap U41 exits.**

**The escape that does work.** `match_candidates` matches on
`input_paths_absolute` (`seal_resume.rs:185-187`), and a path set disjoint
from every candidate falls through to `ResumeDecision::Fresh`
(`seal_resume.rs:271-273`). So moving or copying the files to different paths
and sealing them there is the one route that runs. It appears in exactly one
of the three messages, as a subordinate clause.

**The money.** For `IncompletePostPay` the payment has landed and the proofs
expire in about a day (`ResumeClock::TimeBoxed`, `listing.rs:256-259`).
That work cannot be finished, cannot be abandoned, and the current row tells
its owner to **RESUME PROMPTLY** by running the command that aborts.

### 1.4 Arm (a)'s stated mechanism, priced — it is unbuildable

`refuse_split_on_no_fine_tree` (`seal_plan.rs:454-495`) is a **private** `fn`
taking `&[PlannedFile]`. Its predicate (`:459-464`) is

```rust
file.flags.split().is_some()
    && file.flags.no_fine_tree_matched()
    && file.size > 0
    && (file.flags.force_text() || file_is_text(&file.absolute, &file.as_given)?)
```

Five measurements, each on its own, are fatal to calling it from `list`:

1. **`PlannedFile` does not exist outside a `build_plan` call.** It is built by
   `validate_arguments(&args.paths, cwd)` (`seal_plan.rs:205`) plus
   `base_flags(args)` (`:218`), from an argv struct and a current working
   directory. `list` has neither, and the *seal-time* cwd is not recorded —
   `WorkRecord` (`vault/store.rs:198-231`) carries
   `input_paths_as_given`, `input_paths_absolute`, `shaping`, `work_id`,
   `cost_atto`, `consent` and **no per-file size, no per-file kind, no cwd**.
2. **The decisive term is a file open.** `file_is_text` → `std::fs::File::open`
   (`seal_plan.rs:519`). `list` opens no user file anywhere:
   `WorkListing::gather` (`listing.rs:524-583`) touches `store.list_works`,
   `store.load_meta`, `recorded_state` and `anchor_nag`, and nothing else.
3. **The bytes are the wrong bytes.** `is_text` is whole-file strict UTF-8
   (`canon/pipeline.rs:269`, D149 §1.5); the file may have been deleted,
   moved, edited, or replaced since the seal. A verdict from today's bytes is
   a verdict about a different file.
4. **It would make `list` non-deterministic.** Two runs over an unchanged
   vault could print different rows, which breaks the committed snapshots
   (`tests/snapshots/list-report.txt`, `list-anchor-nags.txt`) and the
   `--json` document's meaning.
5. **The read is unbounded on the case that fires.** D149 §2 R2's bound is
   one-sided: a *positive* text verdict always reads the whole file. `list`
   would read every matched input of every incomplete work in full.

`input_paths_absolute` cannot rescue it: `vault/store.rs:216-219` records it
as *"lexically absolutized (cwd-joined, `.`/`//` cleaned, **NO** symlink or
existence resolution)"* — a string, not a resolved handle.

**Arm (a) as literally stated is dead. Its direction is not.**

### 1.5 The cheap trigger's false positives are the *designed* use of the pair

What *is* soundly decidable from `WorkRecord` alone is
`shaping.split_blank_lines && !shaping.no_fine_tree.is_empty()`. It is a true
**necessary** condition, and stronger than it looks: a stored work is one
`build_plan` accepted, and `build_plan` refuses a zero-match glob
(`seal_plan.rs:239-250`) while `base_flags` applies `with_split` to every file
— so in any stored work carrying both flags, **at least one file carries both
`split()` and `no_fine_tree_matched()`**.

It is not sufficient, and the gap is not exotic. The remaining terms are
`size > 0` and *is text*. A work sealed

```
antseal seal chapter.txt photo.png --split blank-lines --no-fine-tree '*.png'
```

is accepted by `build_plan` today, at HEAD, after U82 — because `photo.png` is
binary and D24 §1's G6 exemption is exactly that (`seal_plan.rs:459-464`; D149
§1.1 run **M2**, executed, exit 23 = the storage seam, i.e. no argument
refusal). **That is the flag pair's intended use**: opt a large binary out of
its fine tree while splitting the prose beside it. The cheap trigger tells its
owner the work is unfinishable when it is finishable, on an incomplete work
that may be paid for and on a clock. **Cost of a false positive: the user
believes a recoverable payment is lost and stops trying inside the one-day
window.** That is the worst error direction available here, so a
necessary-but-not-sufficient trigger is the wrong instrument.

### 1.6 The arm nobody listed: the vault recorded the answer, exactly

`recorded_plan(store, seal_id)` (`pipeline/journal.rs:1114-1122`, `pub`,
takes exactly the `&WorkStore<'_>` `gather` already holds) returns the
journaled plan, whose `manifest_bytes: Option<Vec<u8>>` is the **plaintext**
manifest. **`listing.rs` already calls it**, at `:937`, inside `anchor_nag`.
`status.rs:1032` and `show.rs:719` call it too, so a read-only command
reading this record is the established layering, not a new one.

Decoded (`show.rs:397` → `manifest.body()` → `body.files()`), each
`FileEntry` exposes:

| accessor | file:line | what it records |
| --- | --- | --- |
| `file.canon().kind()` | `manifest/body.rs:805` | Text iff `is_text(raw) \|\| flags.force_text()` (`content/assemble.rs:536`) |
| `file.fine_tree().is_present()` | `manifest/body.rs:819` | `!opt_out.is_requested() && size > 0` (`content/descriptor.rs:248`) |
| `file.size()` | `manifest/body.rs:813` | canonical bytes for text, raw bytes for binary |
| `file.raw_mirror()` | `manifest/body.rs:840` | the raw-mirror unit, present **iff `raw != canonical`** (`content/assemble.rs:24`, D23/spec line 92) |

So, per file:

- *is text by antseal's rule* ⟺ `kind() == Text` — and this **already folds
  `--force-text` in**, which is precisely the disjunct `build_plan` needs.
- *a `--no-fine-tree` glob matched it* ⟺ `!fine_tree_present && raw_size > 0`
  — because `fine_tree_present` is false for exactly two reasons and the size
  term separates them.
- *raw size* = `file.raw_mirror().map(UnitEntry::true_length).unwrap_or_else(|| file.size())`
  — exact in both branches, because a mirror exists iff the renditions
  differ and then carries the raw count (`UnitEntry::true_length`,
  `manifest/body.rs:540`). **This closes the one divergence a naive read of
  `size()` would have**: the lone-BOM class (raw 3, canonical 0) that D149 §6
  already records as over-refused.

Combined with `shaping.split_blank_lines` from the record, that is
`refuse_split_on_no_fine_tree`'s predicate, term for term, on the bytes that
were sealed, with **no filesystem access and no cwd dependence**.

The *pattern* that matched is recoverable too, and by the same function the
refusal uses: `pattern_matches` is `pub` (`seal_plan.rs:638`) and takes
`(pattern, as_given, absolute)` — both spellings are on the record. This is
exactly what `refuse_split_on_no_fine_tree:466-474` does for its own message:
verdict from the flag, pattern names recomputed.

### 1.7 What is *not* decidable, and why that branch carries no money

`manifest_bytes` is written by `sink.put_plan` at
`crates/antseal-cli/src/pipeline/seal.rs:351-356`. A work killed between
`journal.begin` (which already sets `WorkState::IncompletePrePay` —
`vault_journal.rs:116-130`, `SealState::Staged.work_state()`) and that line has
**no manifest**, so the verdict is undeterminable. `WorkRow::work_id`'s own
doc says so from the other side: *"absent until the manifest was built (a seal
killed during staging has none yet)"* (`listing.rs:279-281`).

The decisive fact about that branch:

```
seal.rs:351  put_plan (manifest journaled)
seal.rs:358  record_outcome
seal.rs:359  Barrier::PostStagingJournal
seal.rs:372  quote_batch
seal.rs:389-394  consent -> anchor gate -> pay -> journal the receipt
```

and the module's own header (`pipeline/seal.rs:22`): *"**Staged bytes are
journaled before the quote**, not after."* **Therefore a work with no
journaled manifest is necessarily pre-pay: nothing was quoted, consented or
paid.** Its owner's cost for an unqualified hint is one refused re-run that
aborts pre-passphrase, pre-network, in seconds, with a message that names the
file, both flags, the matched pattern and the workarounds — D24 rationale 1's
own accounting.

One asymmetry, recorded rather than built around: a plan record that is
present but **undecodable** also yields no verdict, and such a work may be
post-pay. It is already a visibly damaged vault by other instruments, and
`list` is a reporter (`listing.rs:913`: *"`list` is a reporter, so it takes
the reporting door"*), so it becomes the same undetermined value rather than a
fourth state or a refusal of the listing.

### 1.8 The fixture claim, re-measured — and the second site

`shaping()` at `listing.rs:1747-1755` is
`split_blank_lines: true, no_fine_tree: ["*.png"]`, driven at `:1759-1770`
against paths `chapter one.txt` and `notes.md`.

`pattern_matches` (`seal_plan.rs:638-643`) tries the pattern against
`as_given`, against the basename, and against `absolute`. `glob_matches`
(`:672-…`) has `*` and `?` as its only metacharacters, neither crossing `/`,
every other byte literal — so `*.png` requires the text to end in `.png`.
`chapter one.txt`, `notes.md` and any absolutization of them do not.
`matched_any` stays false, and `build_plan:236-249` refuses. **Confirmed: no
work with that shaping can ever have existed.** The rule that refuses it
landed in `442165e` (2026-08-02); the fixture landed in `1d39776` (2026-08-02);
U82 landed 2026-08-18. The refusal is not merely older — it is the *same day*
as the fixture and sixteen days older than the rule U85 is about. D149 §1.1
CONTROL A executed it: exit **2**, the zero-match message verbatim.

**The row names one site; there are two.**
`crates/antseal-cli/tests/list_command.rs:304-317` reads the fixture vault's
`seal_id(0x01)` record — built at `:129-140` with the same
`split_blank_lines: true` / `no_fine_tree: ["*.png"]` over `chapter one.txt`
and `notes.md` — and asserts

```
antseal seal 'chapter one.txt' notes.md --title 'thesis draft' --split blank-lines --no-fine-tree '*.png'
```

Same production-unreachable shaping, integration tier, and it is called *"the
resume hint reproduces the recorded invocation"* although the work it reads is
`Complete` and therefore has no hint.

Neither could have caught U85, and the reason is sharper than "the glob
matches nothing": **the pinned shaping is the one shape in which the two flags
never interact**, so it exercises `seal_invocation`'s concatenation and
nothing about the interaction the product now refuses.

### 1.9 D149 §6's zero-extent argument, re-measured

D149 §6 accepted the unresumability on *"Measured extent: pre-release, no such
works exist."* That is still true of the *unresumable* population —
`CHANGELOG.md:13-14` records *"nothing has been released yet, D104 §1.5"*, every
crate is `version = "0.0.0"`, and the two tags are `format-v1-freeze` and
`pre-trailer-strip-949dd9d`, neither a release.

Two things follow, and they point in opposite directions:

1. **It licenses nothing about the message.** Zero extent is an argument for
   not building a migration. It is not an argument for printing an
   instruction that fails, and D149 §6 does not claim to be one — it says the
   case is *"not migrated, not detected, not warned about"*, and U85 exists
   because the third clause has a visible face.
2. **It does not cover the population a trigger would fire on.** Works
   carrying both flags *legitimately* — §1.5's binary opt-out — are creatable
   at HEAD, today and forever. That population is unbounded and growing, and
   any instrument that keys on the flags rather than on the content will hit
   it.

**The relaxation arm is real and is not this record's to build.** On a resume
the granularity decision is already frozen in the staged blobs and the
journaled manifest, and `seal_run.rs:449-450` states it: *"S11: resume
re-uploads the byte-identical staged ciphertexts. **No source file is opened,
here or below.**"* So `refuse_split_on_no_fine_tree` refuses a future
contradiction that a resume cannot create. It cannot be relaxed at
`build_plan`, because resume detection needs the unlocked vault and
`build_plan` runs before the passphrase (§1.3) — the exact venue argument
D149 §1.4/§3.2 settled. Relaxing it therefore means a new gate, which is a
decision, not an implementation. §4 mints it.

## 2. The ruling

### R1 — The subject is the missing exit, not the wording of the hint

`list` is the only venue that knows a work is staged, so it is the only venue
that can give correct advice about one. Every rule below follows from that,
and from §1.3's measurement that the two neighbouring refusals delegate their
way-forward clause to `list`. **`list` must therefore not tell a stranded
user to do anything the build cannot do**, and specifically must not repeat
D24's two workarounds unqualified: measured, one lands on exit 26 and the
other on exit 25.

Verified by: R9's T5, which drives all three doors on one constructed work and
asserts the codes 27 / 26 / 25.

### R2 — The verdict comes from the journaled manifest. No filesystem access, ever

In `crates/antseal-cli/src/listing.rs`, add

```rust
/// Whether the recorded flags make this work's own resume command a
/// refusal, decided from what the vault recorded rather than from the
/// files as they are now (D152 §1.4: the current bytes answer a
/// different question, and `list` opens no user file).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResumeRefusal {
    /// D24 §1's pair, as recorded: the offending paths and the
    /// `--no-fine-tree` patterns that caught them, in `file_id` order.
    SplitOnNoFineTree { files: Vec<String>, patterns: Vec<String> },
    /// The flag pair is recorded but the work has no readable manifest,
    /// so no verdict exists. Necessarily a pre-pay work when the record
    /// is merely absent (D152 §1.7).
    Undetermined,
}
```

and a private function that computes `Option<ResumeRefusal>` for one work:

1. **Cheap gate first, and it is normative.** If
   `!(shaping.split_blank_lines && !shaping.no_fine_tree.is_empty())`,
   return `None` **without reading the plan record**. This is the same
   short-circuit discipline D149 §2 R1 made normative in `build_plan`, for
   the same reason: the expensive step must be unreachable when a free term
   settles it.
2. Read `recorded_plan(store, seal_id)`. **Absent record, absent
   `manifest_bytes`, a `JournalError`, an envelope that will not decode, a
   body that will not decode, or `input_paths_as_given.len() !=
   body.files().len()`** → `Some(Undetermined)`. None of these may propagate:
   `list` is a reporter (`listing.rs:913`) and a damaged record is a datum on
   the row, not a refusal of the listing (D100 R3). The length guard is the
   one `show.rs:412-423` already applies to the same pair of records.
3. For each `(index, file)` in `body.files()`, compute
   `raw_size = file.raw_mirror().map(UnitEntry::true_length).unwrap_or_else(|| file.size())`
   and call R3's shared predicate with
   `split = true`, `no_fine_tree_matched = !file.fine_tree().is_present()`,
   `size = raw_size`, `force_text = file.canon().kind() == DescriptorKind::Text`,
   and a text oracle that is **`unreachable` by construction** (R3).
4. Collect the offending `input_paths_as_given[index]` into `files`. If
   `files` is empty → `None`.
5. `patterns` = every `p` in `shaping.no_fine_tree` for which
   `seal_plan::pattern_matches(p, as_given, absolute)` holds for at least one
   offending file, in recorded order. **If that recomputation names none —
   which would mean the recorded flags and the recorded manifest disagree —
   use the whole recorded `no_fine_tree` list rather than an empty one**, so
   the message can never print a bare `--no-fine-tree` with nothing after it.

Note on the `force_text` argument: `kind() == Text` is *"text by antseal's
rule"*, which is exactly the disjunct `build_plan` computes as
`force_text() || file_is_text(...)`. Passing it as the `force_text` term is
not a lie about the flag; it is the recorded value of the whole disjunction,
which is why the oracle is unreachable.

Verified by: R9 T1–T4 (the four content shapes) and T6 (the differential).

### R3 — One author for the rule: `build_plan`'s predicate gains an injected text oracle

In `crates/antseal-cli/src/seal_plan.rs`, extract the per-file predicate:

```rust
/// D24 §1's per-file condition, with its text oracle injected — so the
/// CLI's refusal and `list`'s honesty check are the same rule read from
/// two different media (D152 §2 R3), rather than two rules that agree
/// until they do not.
///
/// # The term order is normative (D149 §2 R1)
///
/// `is_text` is `FnOnce` so that "reached only when nothing cheaper can
/// answer" is enforced by the type and observable by a test, instead of
/// being a property of the way the `&&` chain happens to be written.
pub(crate) fn split_conflicts_with_no_fine_tree<E>(
    split: bool,
    no_fine_tree_matched: bool,
    size: u64,
    force_text: bool,
    is_text: impl FnOnce() -> Result<bool, E>,
) -> Result<bool, E> {
    if !(split && no_fine_tree_matched && size > 0) {
        return Ok(false);
    }
    if force_text {
        return Ok(true);
    }
    is_text()
}
```

`refuse_split_on_no_fine_tree` calls it with
`|| file_is_text(&file.absolute, &file.as_given)`; R2 calls it with
`|| Err(never())` — an oracle that cannot be called, because every one of its
callers has already supplied `force_text = true` whenever the file is text.
**Behaviour of `build_plan` is unchanged, byte for byte**: same terms, same
order, same short-circuits, same errors.

This is D98's own discipline, applied a second time. `listing.rs:957-961`
already states it for the nag: *"The rule itself is **not** reimplemented
here: this assembles `PendingWork` and calls `work_status`, so `list` and
`status` cannot drift on what 'nag' means."*

Verified by: R9 T4 (the oracle is never called on the cheap-negative shapes)
and T6 (the differential against `build_plan` over real files).

### R4 — Three values, and only the flag pair pays for the read

`WorkRow` gains `pub resume_refusal: Option<ResumeRefusal>`, populated in
`gather` (`listing.rs:541-559`) for the two incomplete states only —
`Complete` and `Abandoned` keep `None`, exactly as `resume` does. The read of
the plan record happens only under R2 step 1's gate, so a vault of ordinary
works costs `list` nothing.

Verified by: R9 T7, which counts journal reads.

### R5 — The human render. Exact copy

Replace `listing.rs:670-674` with: when `resume_refusal` is
`Some(SplitOnNoFineTree { files, patterns })`, the `state:` line stays, the
clock note is **replaced**, and the hint is **re-labelled**. When it is
`None` or `Some(Undetermined)`, nothing changes at all.

The clock note is replaced and not merely preceded, because for a post-pay
work it currently reads `RESUME PROMPTLY: … finishing it costs a second
payment` — an instruction to do the impossible, on a deadline. Three lines,
verbatim:

```
  CANNOT BE FINISHED: chapter one.txt was selected for splitting by --split blank-lines and is also matched by --no-fine-tree '*.txt', and antseal refuses that pair (D24). D45 makes the recorded flags this work's identity, so no re-run can change them.
  nothing was paid, so only the local staged copy is lost. To seal this material, move or copy the file(s) to a different path and seal them there with either --split or --no-fine-tree dropped: re-running the recorded command is refused, and re-running the same paths with different flags is refused too. This build has no command that discards a staged work.
  recorded invocation, refused — do not re-run: antseal seal 'chapter one.txt' --title 'my thesis' --split blank-lines --no-fine-tree '*.txt'
```

The second line's opening clause is the only part that keys on the clock, and
it takes `ResumeClock`'s own two-way split:

- `ReQuote`: `nothing was paid, so only the local staged copy is lost.`
- `TimeBoxed`: `this seal is paid for and the payment cannot be recovered.`

Rules the copy obeys, each measured in §1.3:

- It never says *abandon* — there is no such command.
- It never says *drop one flag* without *at a different path* — the same
  paths with different flags is exit 26.
- It never says *seal it as a separate work* without *a different path* — an
  overlapping path set is exit 25.
- It keeps the invocation, labelled as a record rather than an instruction,
  because D45's identity is exactly the information a user needs in order to
  choose different flags for the copy — and because `seal_invocation`'s own
  rustdoc (`listing.rs:1105-1113`) already calls the reprinting of session
  flags *"advice rather than a record"*, i.e. this string is documented as a
  record.

Multi-file works name every offending file, comma-joined in `file_id` order —
D46's *"every offending argument named"*, the same rule
`refuse_split_on_no_fine_tree` follows.

Verified by: R9 T1, T2 and T8.

### R6 — The `--json` document

`listing.rs:1080-1084`'s `resume` object gains exactly one key, present
whenever the object is:

```json
"resume": {
  "invocation": "...",
  "clock": "...",
  "note": "...",
  "refusal": null
}
```

`refusal` is `null`, or

```json
{"rule": "split-x-no-fine-tree",
 "files": ["chapter one.txt"],
 "patterns": ["*.txt"]}
```

or `{"rule": "undetermined"}`.

`null` means **this rule does not refuse the recorded command** — not *the
resume will succeed*; the rustdoc on the field must say so, because a file
deleted since the seal makes any hint fail and nothing here measures that.
`note` keeps the clock note unchanged so a consumer keying on it does not
break; the blocked sentence is derivable from `rule` + `files` + `patterns`.
`invocation` stays, unchanged, for the R5 reason.

Three values rather than a nullable boolean, deliberately: this is the exact
`Some(0)`/`None` ambiguity U25 paid to remove and D100 R3 records at
`listing.rs:1089-1095`.

Verified by: R9 T3 pins the `undetermined` shape, T1 pins the populated shape,
and T2 pins `null` on a work that carries both flags.

### R7 — The fixture set

1. **`the_resume_hint_reproduces_every_identity_flag` (`listing.rs:1759-1770`)
   STAYS, and its `shaping()` glob CHANGES to one that matches.** Its subject
   is `seal_invocation`'s flag concatenation, which is legitimate and worth
   pinning; what is not legitimate is pinning it on the one shaping in which
   the two flags cannot interact. Change `no_fine_tree` from `"*.png"` to
   `"*.txt"`, which matches `chapter one.txt`. The asserted string changes by
   four characters. **A comment at the site records why**, naming D152 §1.8
   and stating that a zero-match glob describes no work that has ever
   existed — so the next reader does not "simplify" it back.
2. **`the_resume_hint_reproduces_the_recorded_invocation`
   (`list_command.rs:304-317`) takes the same change**, at the fixture that
   feeds it (`list_command.rs:133-137`), for the same reason. Its first half
   — the `big.bin` post-pay row — is untouched.
3. **The unit golden is not the venue for the refused shape.** After (1) the
   fixture *is* in a shape `build_plan` refuses, which is the shape a legacy
   work really has, and that is correct — but `seal_invocation` is a pure
   string builder and must keep reproducing the flags verbatim whatever they
   are. A comment records that the function is deliberately unaware of R2's
   verdict, and that the honesty lives one layer up.
4. **The blocked rendering gets a sixth work in `fixture_vault()`** and
   therefore a re-bless of `tests/snapshots/list-report.txt`. This is
   deliberate: `crates/antseal-cli/tests/snapshots/` is a `COPY_SCAN`
   directory entry (`scripts/check-copy-style.py:99-100`) with `.txt` in
   `COPY_SUFFIXES`, so a golden is how R5's new user-facing copy comes under
   the copy lint at all — U78's finding, applied. The count line and every
   test asserting `5 work(s)` move with it.

### R8 — What must NOT be touched

- **No help-text change**, for D149 §2 R11's reason unchanged: the surface is
  byte-frozen by U1 and editing it drags a freeze event.
- **No change to `refuse_split_on_no_fine_tree`'s message.** It is correct for
  a fresh invocation, which is the only kind `build_plan` can distinguish
  (§1.3). Its wrongness for a resume is §4's row, not this one's.
- **No new exit code and no new `CliError` variant.** Nothing here errors:
  `list` exits 0 on a stranded work, exactly as it does on a damaged one.
- **No core change.** `antseal-core` gains nothing; every accessor R2 uses is
  already `pub`.
- **No change to `seal_resume.rs`.** Its two error messages already delegate
  their way-forward clause to `list`, so R5 repairs their referent without
  touching them. Verified by R9 T5.
- **`abandon` is not added here.** It is U41, it is open, and adding a
  subcommand re-blesses the frozen help snapshot.

### R9 — Tests, and the planted fault that reddens each

Every one must be watched red **by its message**, not by an exit code, and
each fault reverted with the file re-verified against a sha256 taken before
planting.

The blocked and ordinary works are constructed the way the tree already
constructs a legacy work: `Pipeline::new(&MockBackend, …, &KillAt::new(
Barrier::PostStagingJournal))` + `pipeline.seal(request)` — the route
`show_command.rs:111-130` uses to build a shaping `build_plan` refuses, and
`seal_pipeline.rs:553` already uses that exact barrier. The barrier's contract
(`pipeline/error.rs:39-41`) is *"every staged blob and the plan record are
durable"*, so the work lands `Staged` with a real manifest — the production
shape, not a hand-built one.

| # | test | constructs / drives / asserts | planted fault that reddens it |
| --- | --- | --- | --- |
| T1 | **blocked, pre-pay, human** | one text file, non-empty, under `--split blank-lines` + a glob that matches it; kill at `PostStagingJournal`; `WorkListing::gather` + `render()` | assert the row contains `CANNOT BE FINISHED:`, the file name, `--split blank-lines`, the matched pattern, `move or copy`, `nothing was paid`, and `recorded invocation, refused`; and that it does **not** contain `resume with:` nor the `ReQuote` clock note | revert R5 to the bare hint → red on both halves, by message |
| T2 | **ordinary, same flag pair** (the false-positive control) | `[0xFF; 40]` under the *same* `--split` + a glob matching only it | assert the row contains `resume with: antseal seal …` and the clock note, and `refusal` is `null` | replace R2's verdict with the cheap `split && !no_fine_tree.is_empty()` trigger → T2 goes red naming the binary. **This is the test that kills the necessary-but-not-sufficient trigger** |
| T3 | **undetermined** | `journal.begin` with the flag pair and **no `put_plan`** (the `fixture_vault` route, `list_command.rs:116-142`) | `refusal` is `{"rule":"undetermined"}`, the human render is byte-identical to today's, and no `CANNOT BE FINISHED` appears | make an absent plan record default to blocked → T3 red; make it propagate the error → T3 red because `gather` returns `Err` |
| T4 | **the oracle is unreachable** | drive R3's predicate directly, over the three cheap-negative shapes (empty; not matched; not split) and the binary-matched shape, with an oracle that increments a counter and returns `Ok(true)` | counter == 0 on every one; and an **anti-vacuity** assert that the same oracle *is* invoked when called with `force_text = false` on a matched non-empty file, so a counter that can never move is impossible | move `is_text()` above the `size > 0` term → the counter fires on the empty case; make R2 pass `force_text = false` → the counter fires and R2's no-I/O property is gone |
| T5 | **the three doors, one work** | the T1 work; spawn the binary three times: the recorded command, the same paths minus `--split`, and a single-path subset | exit **27** / **26** / **25**, each identified by its class string in the message, not by the code alone | none needed for R5's copy — this test's job is to pin the facts the copy asserts. Plant: change R5's copy to say *"drop one of the two flags"* unqualified → a reviewer reading T5 beside R5 sees the contradiction; and if the copy is asserted against T5's captured messages, the assertion goes red directly |
| T6 | **differential: `list` agrees with `build_plan`** | a five-row matrix — (a) non-empty text matched, (b) `[0xFF; 40]` matched, (c) 0-byte file matched, (d) text **not** matched, (e) `--force-text` over (b) — each run twice: once through `build_plan` over real temp files, once through R2 over the manifest the pipeline built from the same bytes and flags | the two verdicts agree on all five; **plus an anti-vacuity assert that the verdict set contains both `true` and `false`**, without which agreement is trivially satisfiable | drop `kind() == Text` from R2 → (b) disagrees; use `file.size()` instead of the raw-mirror size → the lone-BOM row disagrees (add it as (f) if the class is to be pinned); drop `size > 0` from R3 → (c) disagrees in both callers at once, which is why the matrix drives both sides rather than one |
| T7 | **the cheap gate is load-bearing** | a vault of ordinary incomplete works (no `--no-fine-tree`), with a `WorkStore` wrapper counting `get_journal_entry(PLAN_ENTRY)` reads | zero plan reads for works without the flag pair; ≥ 1 for a work with it | remove R2 step 1's gate → the count rises on the ordinary vault |
| T8 | **multi-file, one offender** | three files: text unmatched, binary matched, text matched | the message names the third path and **neither** of the first two | return after collecting the first offending file, or collect all matched files rather than all *refused* ones → T8 red naming a file that must not appear |

T4's second clause and T6's anti-vacuity assert exist because this project's
dominant defect is a check nothing reachable can redden. T4 without it is a
counter asserted to be zero against an oracle that might be unreachable for
the wrong reason; T6 without it is `assert_eq!(x, x)` over an all-false
matrix.

### R10 — U85's Accept rows

Row 1 is met by R5 + T1. Row 2 is met by T1/T2 + the T1 plant. **Row 3 is met
by R7(1)/(3) and is amended in substance**: it asks whether the golden keeps a
refused-shape fixture; measured, the golden's fixture was refused for the
*wrong* reason, so the answer is neither "keep" nor "drop" but **"change it to
the shape that is actually refused, and record why at the site."**

### R11 — This record's own index row

`docs/decisions/README.md` gains one row, ascending, per §5.

## 3. What was refused and why

### 3.1 Arm (a) as stated — evaluate `build_plan`'s predicate in `list`

Refused as **unbuildable**: §1.4's five measurements, of which any one
suffices. The direction survives in R2 with a different medium.

### 3.2 Arm (b) — print the hint and precede it with the refusal it will hit

Refused. It keeps `resume with:` as an instruction on a command that cannot
run, and it leaves the post-pay clock note *"RESUME PROMPTLY … finishing it
costs a second payment"* standing above a work that cannot be finished at all
(§1.3). A caveat above an instruction is still an instruction; R5 replaces the
instruction and demotes the command to a record.

### 3.3 The cheap trigger — "both flags are present in the stored shaping"

Refused on §1.5: its false-positive population is the flag pair's *designed*
use (binary opt-out beside split prose), that population is creatable at HEAD
and unbounded, and the false positive tells the owner of a *paid, recoverable*
work that the payment is lost — inside the one-day window in which it is
still recoverable. Kept only as R2 step 1's **cheap gate**, where a false
positive costs one journal read and nothing else.

### 3.4 Print no shaping flags at all for a refused shape

Refused twice over. It would break `list_command.rs`'s and the unit fixture's
subject (D45 identity reproduction), it would remove from `--json` a key
consumers read, and it withholds the one datum a stranded user needs — which
flags to *avoid* when sealing the copy. R5 keeps the string and changes what
it is labelled as.

### 3.5 Relax `refuse_split_on_no_fine_tree` for a stored work

Refused **here**, and only here. The argument for it is strong and is recorded
in §1.9: on a resume no source file is opened
(`seal_run.rs:449-450`) and the granularity is already frozen, so the refusal
guards a contradiction the resume cannot create. But `build_plan` cannot know
it is a resume — detection needs the unlocked vault and `build_plan` runs
before the passphrase (§1.3) — so the relaxation means a new gate at a new
venue, which is D149 §1.4's question re-opened. §4 mints it as a row.

### 3.6 A fourth state for "plan record present but undecodable"

Refused. It is a damaged vault, D100 R3 already owns damaged records in this
module, and a fourth value buys a distinction no user acts on. Recorded in
§1.7 as the one asymmetry in the *"undetermined implies unpaid"* reading.

### 3.7 Add `abandon` in this row

Refused: it is **U41**, already open (`TODO.md:416`), and it re-blesses the
frozen help snapshot — an S-row's worth of freeze event dragged into an S row
about a rendering. R5's copy is written to be true both before and after U41
lands, except for its last sentence, which §4 flags for revision at that
point.

### 3.8 Reimplement the predicate over the manifest instead of sharing it

Refused on U82's own lesson — *"three artifacts agreeing on something none of
them checked"* — and on the module's stated precedent at `listing.rs:957-961`.
R3 shares the rule; T6 pins the two *media* against each other, which is the
only part sharing cannot cover.

## 4. Residue

1. **`refuse_split_on_no_fine_tree`'s two workarounds are wrong for a
   resume.** *"Seal it as a separate work without --split, or drop one of the
   two flags"* is correct for a fresh invocation and lands on exit 26 or 25
   for a staged one (§1.3). `build_plan` cannot tell them apart. **New row:
   should the refusal's message name the different-path qualifier
   unconditionally, or should the refusal become resume-aware?** The second
   half is §3.5's decision and needs a venue ruling; it is D149 §1.4's
   question with a new input.
2. **The relaxation arm (§1.9 / §3.5).** On a resume the flags are pure
   identity and no source file is read. A gate that knows it is a resume
   would let every stranded work finish. **New row**, dependent on (1).
3. **`abandon` (U41).** R5's last sentence — *"This build has no command that
   discards a staged work"* — becomes false the day U41 lands, and it is
   user-facing copy inside a `COPY_SCAN` golden. U41's row should carry the
   pointer; §5 supplies the edit.
4. **The lone-BOM class.** D149 §6 records that `build_plan` over-refuses a
   file whose raw bytes are a BOM and whose canonical rendition is empty.
   R2's raw-mirror size makes `list` **agree** with that over-refusal rather
   than correct it, which is right for honesty and wrong for the product. It
   is D149's residue, not this record's, and T6 row (f) is where a future
   lane pins it.
5. **`--json`'s `refusal: null` is not a promise of success.** A file deleted
   or moved since the seal makes any hint fail, and nothing here measures it.
   R6 requires the rustdoc to say so; no instrument enforces the distinction.
6. **The nine-line `list` row.** A blocked post-pay work now renders `state`,
   the blocked sentence, the way-out sentence and the recorded invocation —
   four lines where there were three, two of them long. If U32's freeze finds
   that unreadable, the way-out sentence is the one to shorten, not the
   `CANNOT BE FINISHED` line.
7. **Not executed by this lane.** No Rust source was edited; every `R` item is
   unexecuted. No gate, no `--self-test`, no `cargo fmt` — banned mid-wave
   with parallel lanes on one tree. The only execution was
   `cargo test -p antseal-cli --lib listing::` (§0).

## 5. Registrar's edit set

### `TODO.md`

**(a)** Decision register — append in ascending id order (the highest row
present at this record's writing is **D149** at `TODO.md:1038`; wave 26 may
have added rows above this one):

> - [x] **D152** *(minted 2026-08-18, up-front — U85's `Do` offers two arms and asks a third judgement, and the layering question had to be measured before an implementer could improvise)* U85 — how does `list` stay honest about a stored shaping `build_plan` now refuses, and where does the verdict come from? (U85/U41/U32; consumes D24, D45, D100 R3, D149 §6) — **Resolved 2026-08-18** ([record](docs/decisions/D152-resume-hint-honesty.md)): **the lean's direction survives, its mechanism is UNBUILDABLE, and the defect is larger than the row.** `list` cannot evaluate `build_plan`'s predicate — its decisive term is a whole-file read of bytes that are no longer the sealed bytes — but **the journaled manifest already records all three content terms** (`kind`, `fine_tree_present`, raw-mirror size), so the verdict is exact, vault-only and cwd-free, through a `recorded_plan` call `listing.rs:937` already makes. The cheap flag-pair trigger is **refused**: its false positives are the pair's *designed* use (binary opt-out beside split prose), on works that may be paid and on a one-day clock. And the lean's two workarounds are **measured wrong** — same paths with a flag dropped is exit **26**, an overlapping set is exit **25**, and both messages point back at the command exit **27** refuses. **There is no `abandon` subcommand** (`abandon_pre_pay` has only test callers), so a stranded work has no exit at all; the one route that works — move or copy to different paths — appears in none of the three messages as an instruction. The predicate gains an injected text oracle so one rule serves both media.

**(b)** U85's row (`TODO.md:852`) — append before the ` · discovered by` tail:

> ; **ruled by D152** — the hint is not the whole defect: the two neighbouring resume refusals (**25**, **26**) point back at the command **27** refuses, and no `abandon` subcommand exists, so a stranded work has no exit; verdict comes from the journaled manifest, not the filesystem; the covering fixture is production-unreachable at **two** sites, not one (`listing.rs:1747-1770` and `list_command.rs:304-317`)

**(c)** U41's row (`TODO.md:416`) — append to the row body:

> **D152 §4(3) adds a second trap this row exits, and a copy dependency**: `list`'s blocked-work rendering states *"This build has no command that discards a staged work"*, which is user-facing copy inside a `COPY_SCAN` golden and becomes false the day this row lands.

**(d)** The wave-26 registration paragraph should record: D152 overturned the
lean's mechanism as unbuildable, refused the trigger the brief proposed as a
fallback, found the escape-hatch absence (no `abandon`), and corrected U85's
fixture claim from one site to two.

### `tasks/U.md`

**(e)** U85's `Do` (`tasks/U.md:1224`) — replace with the ruled shape:

> - Do: **Per D152 §2.** `list` decides, from the **journaled manifest** and never from the filesystem, whether the recorded flags make its own resume command a refusal; on `SplitOnNoFineTree` it replaces the clock note and the `resume with:` line with D152 §2 R5's copy verbatim and demotes the invocation to a labelled record; on `Undetermined` (no readable manifest — necessarily a pre-pay work) it renders exactly as today. `refuse_split_on_no_fine_tree`'s predicate gains an injected `FnOnce` text oracle so the rule has one author (R3). `--json` gains one `refusal` key with three values (R6). The two production-unreachable fixtures change glob rather than being deleted (R7).

**(f)** U85's `Accept` row 3 (`tasks/U.md:1228`) — replace per R10:

> - `seal_invocation`'s unit golden is re-read after the change and its shaping is changed from the zero-match `*.png` to a glob that matches, with the reason recorded at the site — the committed fixture was refused for the *wrong* reason and could not have caught this (D152 §1.8); the second site, `crates/antseal-cli/tests/list_command.rs:304-317`, takes the same change.

**(g)** U85's `Accept` gains two rows:

> - The ordinary path is proven by a work carrying **both flags legitimately** — a non-empty binary matched by the glob under `--split` — whose row still prints `resume with:` and `refusal: null`; replacing the verdict with the cheap flag-pair trigger reddens it (D152 §2 R9 T2).
> - `list` performs **zero** plan-record reads for incomplete works whose recorded shaping lacks the flag pair, counted rather than argued (D152 §2 R9 T7).

**(h)** U85's `Deps` (`tasks/U.md:1220`) — add `U41` (the abandon surface, on
which R5's last sentence depends) and `D100 R3` (the reporter discipline R2
step 2 follows).

**(i)** U85's `Problem` — correct the locator: `seal_invocation` is
`listing.rs:1119-1150`; `:1128-1138` is its flag-reproduction band.

### `docs/decisions/README.md`

**(j)** Append one row, ascending:

> | [D152](D152-resume-hint-honesty.md) | U85 — `list`'s resume hint prints a command `build_plan` now refuses: suppress it, precede it, or something else? **The lean's direction survives and its mechanism is unbuildable.** `list` cannot evaluate `build_plan`'s predicate — the decisive term is a whole-file read (`seal_plan.rs:463` → `File::open`) of bytes that are no longer the sealed bytes, in a command that opens no user file — but the **journaled manifest already records all three content terms**: `kind` is Text iff `is_text \|\| force_text` (`assemble.rs:536`), `fine_tree_present` is `!opt_out && size > 0` (`descriptor.rs:248`), and the raw-mirror `true_length` gives the exact raw size, through a `recorded_plan` call `listing.rs:937` already makes. **The cheap "both flags present" trigger is refused**: its false-positive population is the pair's *designed* use — a binary opted out beside split prose, legal and resumable at HEAD — and the false positive tells the owner of a *recoverable* payment that it is lost, inside the one-day window. **The defect is larger than the row**: `Command` has nine subcommands and none is `abandon` (`abandon_pre_pay` has only test callers), the same paths with a flag dropped is exit **26** and an overlapping set is exit **25**, and both of those messages point back at the command exit **27** refuses — so a stranded work has **no exit at all** and the one route that works, moving the files to different paths, is in none of the three messages as an instruction. Ruled: three-valued verdict (`refused` / `undetermined` / not-refused), the clock note **replaced** rather than preceded because `RESUME PROMPTLY` is an instruction to do the impossible on a deadline, the invocation demoted to a labelled record, and `refuse_split_on_no_fine_tree`'s predicate given an injected `FnOnce` text oracle so one rule serves both media. U85's fixture claim confirmed and widened from one site to two | RESOLVED | 2026-08-18 |

### `docs/instrument-ledger.md`

**(k)** Append two entries:

> - 2026-08-18 · D152 lane (wave 26) · **A committed golden pinned the one shaping in which its subject's two flags cannot interact, and a second site pinned the same one.** `crates/antseal-cli/src/listing.rs:1747-1770` and `crates/antseal-cli/tests/list_command.rs:304-317` both assert a resume hint whose `--no-fine-tree '*.png'` matches neither `chapter one.txt` nor `notes.md`, so `build_plan`'s zero-match rule (`seal_plan.rs:239-250`, landed `442165e` 2026-08-02, the **same day** as the fixture) has always refused it — executed at exit **2** in D149 §1.1 CONTROL A. U85's row named one site; the sweep that found the second is `rg -n 'seal_invocation'`, five sites in `src` and one in `tests`. The class is sharper than "the glob matches nothing": a fixture that pins the shape in which the interaction under test cannot occur is green for a reason unrelated to its own name · docs/decisions/D152-resume-hint-honesty.md §1.8

> - 2026-08-18 · D152 lane (wave 26) · **A ruling's `Do` offered two arms, and the arm it did not offer was already half-built in the module it names.** `listing.rs:937` calls `recorded_plan` and reads the journaled plaintext manifest for the anchor digest, and treats an absent record as **data** (`nag: None`) rather than a failure — so both the mechanism and the three-valued discipline U85's honest path needs were already in the same function, forty lines from the hint. Propagate to briefs: before pricing a new read, grep the target module for the read you are about to describe · crates/antseal-cli/src/listing.rs:937 · :917

**(l)** No new checker, no new required context, and no `check-traceability.py`
change: R2–R7 are product behaviour and are policed by R9's tests and by the
existing `COPY_SCAN` reach into `crates/antseal-cli/tests/snapshots/`.
