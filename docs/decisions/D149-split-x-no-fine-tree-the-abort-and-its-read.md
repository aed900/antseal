# D149 — D24 §1's abort belongs exactly where D24 put it; what nobody costed is that its own *condition* is a whole-file read, and the second fixture encoding the refused outcome sits inside the very function that must raise the error

- **Status: RESOLVED. The lean's VENUE and DIRECTION survive on measurement —
  the "unbuildable at the point it names" hypothesis handed to this lane is
  REFUTED — and three of the lean's four specifics are overturned.** The lean was
  *"Implement layer 1 in plan validation: for each text file, if the split mode
  is active and the file matches a `--no-fine-tree` glob, abort with a distinct
  usage-class error naming the file and both flags."*
  - **"in plan validation" SURVIVES, and it is load-bearing rather than
    decorative.** The competing venues all sit *behind the passphrase prompt*:
    on an `ant-backend` build `seal_over_backend` runs `open_layout` (`:350`) →
    `VaultLock::acquire` (`:352`) → `NetworkConfig::select` (`:361`) →
    **`collect_passphrase` (`:370`)** → unlock (`:380`) → wallet key → connect →
    `run_seal` (`crates/antseal-cli/src/commands.rs:326-410`), and its own rustdoc
    at `:318-324` says *"the plan is already validated when
    this is entered"*. An abort in `run_seal` or in `Pipeline::seal` would make
    a two-flag typo cost a passphrase entry and a network connect. D24's
    rationale 1 — *"Re-running a failed command costs seconds"* — is a claim
    about `build_plan` and about nowhere else.
  - **The collision is REAL and it is NOT D139's shape.** Plan validation does
    read no bytes today (§1.2, verified end to end), and `is_text` is
    `str::from_utf8(raw).is_ok()` (`crates/antseal-core/src/canon/pipeline.rs:269`) —
    a **whole-file** predicate that no prefix, extension or `stat` can answer.
    But *unbuildable* does not follow: `build_plan` already `stat`s every
    argument and already carries `size` on `PlannedFile`
    (`crates/antseal-cli/src/seal_plan.rs:317-322`). D24 §1's condition is
    decidable there **at the price of a read whose bound is the condition's own
    bound**, and this record rules that read explicitly rather than moving the
    abort.
  - **"distinct usage-class error" is OVERTURNED.** `usage` (2) is the wrong
    class and a *new* class is refused outright. The sibling two-flag
    contradiction in the same function — `--no-anchor` × `arbitrum-one` — is
    already `CliError::InvalidSealArgument` → **27**, and 27's own table row
    reads *"pre-consent"* (`crates/antseal-cli/src/error.rs:37`). Reusing it
    costs **no new exit code** (D134 §2 R3 append-only; D147 is ruling the table
    this same wave), **no new `CliError` variant**, and therefore **no re-bless
    of `tests/snapshots/cli-errors.display.txt`**.
  - **"for each text file" is NARROWED by two measurements the lean does not
    contain.** (i) `--force-text` makes the predicate decidable from argv with
    **zero** reads, and that is the case that *silently passes today* (§1.3, run
    M3). (ii) A raw-empty file has no fine tree at any opt-out setting —
    `fine_tree_present = !opt_out.is_requested() && size > 0`
    (`crates/antseal-core/src/content/descriptor.rs:248`) — so `--no-fine-tree`
    costs it nothing and refusing it would be over-reach.
  - **The arm nobody listed, and the one that will actually go red:
    `show_command.rs` is not the only fixture encoding the refused outcome, and
    it is not the one that breaks.** `crates/antseal-cli/src/seal_plan.rs:801-803`
    — inside `build_plan`'s own test module — sets `split`, `force_text` **and**
    `no_fine_tree = "*.bin"` over a matching file and asserts the plan builds. It
    is green today (§1.6). `show_command.rs:113-118` never touches `build_plan`
    at all: it drives `Pipeline::new` + `pipeline.seal` directly, so U82's *"its
    fixture is now unconstructible through the CLI"* is true of the CLI and false
    of the fixture, which is constructible by exactly the route it uses.
- **Date: 2026-08-18**

## 0. What was measured against

Tree clean at `dc0bac8` (2026-08-18 14:40:21 +0100). `target/debug/antseal`
mtime 15:18:51, and `find crates -name '*.rs' -newer target/debug/antseal`
returns **nothing** — so the binary driven below is HEAD's, not a stale one.
Default features (`ant-backend` off), which is why `seal` answers the storage
seam rather than the network.

## 1. The measurement

### 1.1 The two-flag conflict is accepted silently through the CLI, today

Run against the fixture dir `notes.txt` (33 B of blank-line-separated prose),
`plain.md`, `blob.bin` (13 B, invalid UTF-8 at offset 3). Every run captured
`REAL_EXIT=$?` into a file and read it back.

```
### CONTROL A: zero-match glob (a known build_plan error)
$ antseal seal --split blank-lines --no-fine-tree nosuch.txt notes.txt
REAL_EXIT=2
error: usage error: --no-fine-tree nosuch.txt matched none of the 1 file(s) given: …

### CONTROL B: duplicate paths (a known D46 error)
$ antseal seal notes.txt notes.txt
REAL_EXIT=27
error: invalid seal argument: notes.txt is given twice (each file is sealed and paid for once)

### M1: both flags, TEXT file matched
$ antseal seal --split blank-lines --no-fine-tree notes.txt notes.txt plain.md
REAL_EXIT=23
error: network failure: `seal` needs a live Autonomi connection, and this build has no
storage backend compiled in …

### M2: both flags, BINARY file matched only
$ antseal seal --split blank-lines --no-fine-tree blob.bin notes.txt blob.bin
REAL_EXIT=23   (correct — D24 §1 exempts binary, G6)

### M3: both flags + --force-text, binary matched
$ antseal seal --split blank-lines --force-text --no-fine-tree blob.bin notes.txt blob.bin
REAL_EXIT=23   (WRONG — --force-text makes it text by argv; D24 §1 covers this and nobody named it)
```

**The two controls are the point.** A measurement that only showed M1 reaching
exit 23 would be an assertion that cannot fail — it would be equally consistent
with "`build_plan` errors never surface here". CONTROL A (exit **2**, the
zero-match message verbatim) and CONTROL B (exit **27**, the duplicate message
verbatim) prove that both of `build_plan`'s error classes reach stderr through
this exact invocation path. M1 therefore measures acceptance, not invisibility.

### 1.2 Where the first byte is read, and where consent is *invoked*

Re-taken line by line, because the brief's own framing needed correcting:

| claim | verified |
| --- | --- |
| `build_plan` reads no user bytes | `crates/antseal-cli/src/seal_plan.rs:169-228`; the only filesystem call is `std::fs::metadata` at `:301`, and `PlannedFile.size` comes from that same `stat` (`:320`) |
| the exclusion is recorded per file and nothing is refused | `:196-211`; the sole error in the loop's aftermath is the zero-match glob at `:215-224` |
| `base_flags` applies `with_split` unconditionally | `:408-417`, `with_split` at `:414` |
| first user byte enters the process | `read_all(plan)?` at `crates/antseal-cli/src/seal_run.rs:451`, `read_all` defined `:618-628` |
| the consent gate is **constructed** | `SealConsent::new` at `seal_run.rs:394-403`; handed to `Pipeline::new` at `:437` |
| the consent gate is **invoked** | `consent_anchor_pay(...)` at `crates/antseal-cli/src/pipeline/seal.rs:392`, reached from `pipeline.seal(&request, seal_rng)` at `seal_run.rs:475` |

**Correction to this lane's brief.** The comment at `seal_run.rs:362` —
*"── D45, before consent and before a single byte is read ──"* — scopes
**D45's resume detection at `:363`**, not plan validation. It is nonetheless the
comment a read in `build_plan` falsifies, because `build_plan` runs upstream of
it (`commands.rs:292`).

**And there is a window the brief did not name**: bytes are read at `:451` and
consent is not invoked until `pipeline/seal.rs:392`, so `run_seal` **does** have
a post-read pre-consent slot. It loses anyway, on §1.4's ordering.

### 1.3 What the model does today with both flags — and core raises nothing

`plan_file` (`crates/antseal-core/src/content/assemble.rs:530-596`):
`is_text_file = is_text(raw) || flags.force_text()` at `:536`; `opt_out` at
`:561`; and the unit plan at `:566-579` matches on
`(flags.split(), canonical.as_ref(), SplitEligibleText::of(&descriptor))`.
`SplitEligibleText::of` is `Some` **iff** the descriptor is text *and*
fine-tree-covered (`content/unit.rs:305-319`), so an opted-out file falls to the
`_ => FileUnitPlan::whole_file(...)` arm. Assembly is **total** — it has no error
type by design (`assemble.rs:29-58`) — and `content/error.rs` is a *decode-side*
taxonomy (`:5-16`). **Core raises nothing.** The row's *"silently forced
single-unit"* is confirmed exactly, and D24 layer 2 is confirmed as
*unrepresentable*, never *rejected*.

### 1.4 The venue test: what each candidate site costs

| venue | fires before passphrase? | before connect? | reads bytes? | covers library callers? |
| --- | --- | --- | --- | --- |
| `build_plan` (`seal_plan.rs`) | **yes** | **yes** | yes, bounded (§1.5) | no |
| `run_seal` after `read_all` (`:451`) | no | no | already read | no |
| `Pipeline::seal` plan validation (`pipeline/seal.rs:239-247`) | no | no | already read | yes |

`commands.rs:318-324` states the ordering rule in its own voice: *"Every step is
ordered so the expensive and the secret come last: the plan is already validated
when this is entered, the vault lock is taken before the passphrase …"*. Only
row 1 keeps a flag typo out of the passphrase prompt.

### 1.5 The read, bounded — and the experiment that decides its shape

The tempting cheap probe is *"read 8 KiB; if it is valid UTF-8 it is text"*.
**Measured, that is wrong in the direction that over-refuses.** A 10 240-byte
`tar` of one text file:

```
sample.tar:  len=10240   prefix VALID (undecided)   |  whole file VALID utf-8 -> is_text TRUE
blob.bin:    len=13      prefix INVALID at 3        |  whole file INVALID    -> is_text FALSE
target/debug/antseal: len=128438152  prefix INVALID at 40  |  whole file INVALID -> is_text FALSE
```

Two findings:

1. **A small `tar` is *text* under antseal's own rule.** NUL is a valid UTF-8
   scalar, so an archive of ASCII headers and NUL padding validates end to end.
   `--no-fine-tree '*.bin'`/`'*.tar'` therefore does **not** reliably select
   binary files, and the refusal will fire on files a user calls binary. The
   message must state antseal's rule, not assert a classification the user will
   dispute.
2. **The sound shortcut is one-sided.** `str::from_utf8` distinguishes a genuine
   invalid sequence (`error_len() == Some(_)`) from a truncated one
   (`error_len() == None`). A genuine invalid byte inside a prefix settles the
   **whole** file — appending bytes cannot repair it — so a *negative* may be
   taken from a prefix and a *positive* may not. A 128 MB ELF is decided at byte
   40; the `tar` correctly falls through to a full read.

Peak-memory context: `read_all` already collects `Vec<Vec<u8>>` over **every**
planned file simultaneously (`seal_run.rs:618-628`), so a transient single-file
read in plan validation adds no new memory class.

### 1.6 Two fixtures encode the refused outcome, not one — and the second is green

```
$ cargo test -p antseal-cli --lib seal_plan      # PIPESTATUS[0] read back from a file
test result: ok. 19 passed; 0 failed …
test seal_plan::tests::the_plan_records_sizes_flags_and_both_path_spellings ... ok
```

That test (`crates/antseal-cli/src/seal_plan.rs:794-829`) sets
`a.split = Some(SplitMode::BlankLines)` (`:801`), `a.force_text = true` (`:802`),
`a.no_fine_tree = Some("*.bin")` (`:803`) over `blob.bin` = `&[0u8; 40]` and
asserts `build_plan(...).expect("plan builds")`. Under R1 it becomes a refusal —
**twice over**: `--force-text` makes it text by argv, and 40 NUL bytes are valid
UTF-8 anyway.

A whole-tree sweep for the combination (`rg 'with_no_fine_tree'`,
`rg 'split *= *Some|with_split'`) finds exactly two sites that carry both:
`seal_plan.rs:801-803` and `crates/antseal-cli/tests/show_command.rs:113-118`.
Everything else is one flag or the other.

### 1.7 The exit class already exists and already means this

`crates/antseal-cli/src/pipeline/error.rs:265-271` maps
`NoAnchorOnMainnet | BlobExceedsChunkCap | EmptyWork` onto
`CliError::InvalidSealArgument { problems }` under the comment *"Plan-validation
failures are argument problems: every offending input is named, pre-consent,
pre-anchor, pre-quote."* `ErrorClass::InvalidSealArgument => 27`
(`error.rs:388`), name `invalid-seal-argument` (`:458`), table row `:37`.
`tests/exit_codes.rs`'s `TABLE` holds only `(class, code, name)` — no source
prose — and `docs/testing/error-code-contract.md` does not mention the class at
all (grepped: zero hits). **So the class costs one prose cell and nothing else.**

### 1.8 Two corrections to the row itself

- **Spec citation.** U82 cites *"MVP-SPEC.md lines 60–66, 121"*. Lines 58–66 are
  the `ant-core = "=0.5.0"` pin and the `StorageBackend` signature block. The
  content-model bullets are **83** (text detection = valid UTF-8 or
  `--force-text`), **84** (`--split blank-lines`, binary always single-unit) and
  **85** (`--no-fine-tree`, permanently whole-file-reveal only).
- **Accept row 1** demands *"a test that asserts zero backend calls"*. `build_plan`
  takes `(&SealArgs, NetworkId, &Path)` — no backend is in scope, so that
  assertion cannot fail. R10 replaces it with one that can.

## 2. The ruling

### R1 — Where the abort is raised, and its exact predicate

In `crates/antseal-cli/src/seal_plan.rs`, add a private function and call it from
`build_plan` **immediately after the zero-match refusal at `:215-224` and
immediately before `Ok(SealPlan { … })`**:

```rust
refuse_split_on_no_fine_tree(&planned, &shaping.no_fine_tree)?;
```

The predicate reads the **finished `PlannedFile`**, never argv — the flags a
file carries are the field that carries the claim, and `base_flags` is what
sets them:

```rust
file.flags.split().is_some()
    && file.flags.no_fine_tree_matched()
    && file.size > 0
    && (file.flags.force_text() || file_is_text(&file.absolute, &file.as_given)?)
```

The `&&` order is normative, not cosmetic: `size > 0` and `force_text()` are
free and short-circuit the read, so **`--force-text` costs no I/O and an empty
file costs no I/O**.

Justification for `size > 0`: `CanonDescriptor::describe_file` sets
`fine_tree_present = !opt_out.is_requested() && size > 0`
(`crates/antseal-core/src/content/descriptor.rs:248`), so an empty file is
split-ineligible with the opt-out *and without it*. The refusal exists to
catch granularity the opt-out destroyed; on an empty file it destroyed none.

### R2 — The read: bounded, one-sided, and `is_text` stays the sole authority

```rust
/// One buffer decides essentially every non-UTF-8 file; see D149 §1.5.
const TEXT_PROBE_BYTES: u64 = 8192;

fn file_is_text(absolute: &str, as_given: &str) -> Result<bool, CliError> {
    use std::io::Read as _;
    let io = |source| CliError::Io {
        context: format!("reading {as_given} to decide --split against --no-fine-tree (D24)"),
        source,
    };
    let file = std::fs::File::open(absolute).map_err(io)?;
    let mut head = Vec::new();
    file.take(TEXT_PROBE_BYTES).read_to_end(&mut head).map_err(io)?;
    if head.len() < TEXT_PROBE_BYTES as usize {
        // Short read from a `Take` is EOF: this IS the whole file.
        return Ok(antseal_core::canon::is_text(&head));
    }
    // A *decisive* invalid sequence inside the prefix settles the whole file:
    // appending bytes cannot repair it. `error_len() == None` means the prefix
    // merely ended mid-sequence and decides nothing (D149 §1.5).
    if let Err(e) = std::str::from_utf8(&head) {
        if e.error_len().is_some() {
            return Ok(false);
        }
    }
    Ok(antseal_core::canon::is_text(&std::fs::read(absolute).map_err(io)?))
}
```

**`antseal_core::canon::is_text` remains the only author of "this file is
text".** The prefix branch never returns `true` on its own; it only
short-circuits a `false` that `is_text` would have returned anyway. Do **not**
introduce a second detection rule (no extension test, no NUL scan, no
control-character ratio) — spec line 83 and `canon/pipeline.rs:263-268` state
there is no heuristic, and a cheaper probe answers a different question.

### R3 — The error class: reuse, do not mint

`CliError::InvalidSealArgument { problems }` → class `invalid-seal-argument` →
exit **27**. **Allocate no new exit code and add no new `CliError` variant.**
Grounds: D134 §2 R3 makes the table append-only and 44–49 is reserved; D147 is
ruling the exit-code table this same wave; 27 is already the class of the sibling
two-flag contradiction in this same function; and reusing it leaves
`tests/snapshots/cli-errors.display.txt` and `tests/exit_codes.rs`'s `TABLE`
untouched. **Dependency, stated:** if D147 renumbers, re-scopes or splits
`invalid-seal-argument`, this ruling follows D147 without a further decision.

### R4 — The message: one problem per offending file, D46's own form

Aggregate with the D46 pattern already in the file (`Problem` +
`report(problems)`), so every offender is named in one error rather than the
first one only. For each offending file, push:

```rust
format!(
    "{as_given} is selected for splitting by --split blank-lines and is also matched by \
     --no-fine-tree {patterns}: --no-fine-tree makes it permanently whole-file-reveal \
     only, so the sub-file units --split asks for could never be revealed from it, and \
     unit boundaries are frozen forever at seal time. It counts as text by antseal's \
     rule — valid UTF-8, or --force-text (MVP-SPEC.md line 83). Seal it as a separate \
     work without --split, or drop one of the two flags (D24)"
)
```

- `{patterns}` = the `--no-fine-tree` pattern(s) that **actually matched this
  file**, recomputed with `pattern_matches` — the same function that made the
  decision — joined by `", "`. Not the whole pattern list, and not a paraphrase.
- The two workarounds are D24 §1's own, quoted in substance: *"seal that file as
  a separate work, or drop one flag"*. Do not invent a third.
- The *"counts as text by antseal's rule"* clause is mandatory, not decoration:
  §1.5 measured a `tar` archive validating as UTF-8, so the user's own word for
  the file will often disagree with antseal's.
- **Deliberately absent**: a *"nothing was quoted, anchored, paid, or uploaded"*
  tail. No other `InvalidSealArgument` problem carries one, and repeating it per
  file would be noise. Recorded here so it is not read as an oversight.

### R5 — `--force-text` + `--split blank-lines` + a matching glob is unconditionally refused

A direct consequence of R1 worth stating once so nobody rediscovers it as a bug:
`--force-text` is global (`seal_plan.rs:409-411`), so it makes **every** file
text by argv. Therefore no single invocation can carry `--force-text`, `--split
blank-lines` and a `--no-fine-tree` glob that matches any non-empty file. R7's
test surgery follows from this and from nothing else.

### R6 — Disposition of `show_command.rs:113-118`: the flags STAY, the comments change

The fixture never calls `build_plan`; it constructs `SealFile` values and drives
`Pipeline::new` + `pipeline.seal` (`show_command.rs:130-131`). R1 cannot break
it and must not be made to. Its unit-row assertion at `:301-304` —
`(6, 3, "normal", 0, 24, 24)` under *"Opted out: one unit spanning the whole
file, whatever `--split` asked for (D24)"* — is the **only** exercise of D24
layer 2 through the pipeline and the `show` renderer;
`assemble.rs:825-838`'s unit test reaches neither. Deleting `.with_split(...)`
would delete that assertion's subject.

Edit the three comments to say what is now true, in this substance:

- `:114` (currently *"D24: the split request cannot apply to an opted-out file."*)
  → state that this combination is **refused by `seal` in plan validation
  (D24 §1, D149 R1)** and is constructed here at the library boundary **on
  purpose**, to prove D24 §2's structural reconciliation still holds for a
  caller that bypasses the CLI.
- `:60-63` (`OPTED_OUT`'s doc) and `:303` gain the same pointer, so a reader
  arriving at either one is not left believing the CLI can produce it.

**Do not delete the fixture.** U82 Accept row 4's *"corrected rather than
deleted, with the reason recorded"* is met by the comment edits.

### R7 — Disposition of `seal_plan.rs:794-829`: split the test in two

`the_plan_records_sizes_flags_and_both_path_spellings` goes red under R1 (§1.6).
By R5 no single invocation can carry all three flags with a matching glob, so
the test must split. Keep the existing test's name, its files, its
`no_fine_tree = "*.bin"`, its `force_text = true` and every one of its
assertions **except** the split half: remove `a.split = Some(SplitMode::BlankLines)`
(`:801`) and change the `SealShapingFlags` assertion's `split_blank_lines` to
`false` (`:823`).

Then add a sibling test that carries the removed coverage — `split_blank_lines:
true` reaching `shaping` and `with_split` reaching every file's `FileFlags` —
over a work with **no** `--no-fine-tree` glob. Name it so the reason is legible,
e.g. `split_reaches_the_shaping_record_and_every_file_when_no_glob_conflicts`.

Record at the site, in one line, **why** the flags were separated: a reader who
sees the split removed will otherwise restore it as an improvement (U80's
lesson, one file over).

### R8 — The two core comments stay, and gain the site they assert

`crates/antseal-core/src/content/unit.rs:34` (*"The matching hard / CLI error
(naming the file and both flags) is U's, per D24."*) and
`crates/antseal-core/src/content/split.rs:63` (*"The matching loud CLI error at
`--no-fine-tree` x `--split` is U's, per D24."*) become **true** under R1. Both
stay, and each gains the concrete site — `seal_plan.rs`'s
`refuse_split_on_no_fine_tree`, D24 §1, D149 — so the next reader can *verify*
the neighbour's obligation instead of trusting the sentence. That is the whole
remedy for U82's Notes: the sentences were not wrong to exist, they were wrong
to be uncheckable.

### R9 — Three comments become false the moment R2's read exists. Amend all three in the same act

A read in plan validation falsifies three sentences that are true today. Each is
a claim about *the process*, not about its own function, which is why grepping
the function that changes would miss two of them:

1. **`crates/antseal-cli/src/seal_run.rs:362`** — *"── D45, before consent and
   before a single byte is read ──"*. It scopes D45's `detect` at `:363`, which
   still runs before `read_all`; what breaks is the second clause, because
   `build_plan` now reads upstream of it (`commands.rs:292`). Amend to say what
   the comment means — that resume detection precedes consent and precedes the
   **work's** read — without claiming the process has read nothing.
2. **`crates/antseal-cli/src/seal_run.rs:447-450`** — *"The one place source
   bytes enter the process. Read after every refusal has had its chance (D46
   validation, resume detection, the balance read), so a rejected invocation
   never loads a gigabyte first."* Both sentences need work. It is no longer the
   *one* place, and a rejected invocation **can** now load a gigabyte first —
   exactly when the gigabyte is valid UTF-8, which is the case this refusal
   exists for. State the real bound (R2: the read stops at the first decisive
   invalid byte, so it is full only for files this run is about to refuse) rather
   than deleting the claim.
3. **`crates/antseal-cli/src/seal_plan.rs:93-94`** — `PlannedFile::size`'s doc,
   *"Size in bytes, from the same `stat` that validated the argument. Displayed
   by the consent gate (U14) before anything is read."* The first sentence stays
   true and is what R1's `size > 0` term relies on; the second stops being true
   of the process. Amend the second clause only.

This is U82's own defect class pointed at the fix: a doc comment that describes
the neighbourhood rather than the function it sits on, and that nothing checks.
None of the three is caught by any test, so the act that lands R1 is the only
place they can be caught.

### R10 — Tests, with the planted fault for each

Every one of these must be watched red **by its message**, not by its exit code.

| # | test | assertion | planted fault that must redden it |
| --- | --- | --- | --- |
| T1 | text file matched, `build_plan` | `Err`, `class() == ErrorClass::InvalidSealArgument`, `exit_code() == 27`; message contains the file name, `--split blank-lines`, `--no-fine-tree`, **and both workarounds** | delete `--split blank-lines` from R4's format string → T1 fails naming the missing flag |
| T2 | **binary negative control** — glob matches only a file that is *genuinely* invalid UTF-8 (e.g. `&[0xFFu8; 40]`, **not** a `.bin` name and **not** NUL padding, §1.5) | `Ok`, and the planned file still carries both `with_split()` and `with_no_fine_tree()` | drop the `is_text` term from R1's predicate → T2 fails with an unexpected refusal naming the binary |
| T3 | `--force-text` over that same binary | `Err`, 27, message names the file | drop `file.flags.force_text() ||` from R1 → T3 fails; **this is the case that passes silently today** (§1.3 run M3) |
| T4 | **empty negative control** — 0-byte text file matched by the glob under `--split` | `Ok` | drop `file.size > 0` → T4 fails with an unexpected refusal |
| T5 | **prefix-probe boundary** — a file whose first `TEXT_PROBE_BYTES` bytes are valid UTF-8 and whose next byte is `0xFF`, matched by the glob under `--split` | `Ok` (it is binary) | replace R2's fall-through with `return Ok(true)` — the naive prefix rule — → T5 fails with an unexpected refusal. **This is the sharpest test in the set**: T2 with a small binary cannot catch it |
| T6 | **early-exit control** — first byte `0xFF`, then ≥ 1 MiB of valid UTF-8 | `Ok`, and the test asserts it completes without reading past the probe (drive `file_is_text` through a byte-counting `Read` with a budget, or assert on a file large enough that a full read is observable) | remove the `error_len().is_some()` branch → the file is fully read; the budget assertion fails |
| T7 | **pre-consent, pre-vault, spawned binary** — `antseal seal --split blank-lines --no-fine-tree notes.txt notes.txt` into a HOME with **no vault at all** | exit **27** | move the check into `run_seal` or `Pipeline::seal` → the default build answers **23** (the storage seam) and the `ant-backend` build answers **2** (*"no vault exists"*, `open_layout()` at `commands.rs:350`, kept first by U73's note at `:343-349`) — both distinct from 27, so this test discriminates the venue and not merely the outcome |
| T8 | multiple offenders | two conflicting text files → **both** named in one message (D46's *"every offending argument named"*) | return after the first offender → T8 fails naming the file that went missing |

T7 replaces U82 Accept row 1's *"asserts zero backend calls"*, which cannot fail
against a function with no backend parameter (§1.8).

### R11 — What must NOT be touched

- **No help-text change.** `--split` and `--no-fine-tree` say nothing about each
  other today (`cli.rs:298-309`; snapshot `cli-surface.help.txt:115-128`) and
  they must keep saying nothing. The surface is byte-frozen by U1
  (`tests/cli_surface.rs:65-88`, `ANTSEAL_BLESS=1` only); editing it makes this
  an `S` row that drags a deliberate freeze event, which is exactly U80's defect
  in the opposite direction. The error message carries the guidance.
- **No core change.** Assembly stays total; `ContentError` gains nothing; D24
  layer 2 stays *unrepresentable*, never *rejected*.
- **No pipeline-level error.** `Pipeline::seal` gains no `SealError` variant for
  this (see §3.2).
- **No change to `docs/testing/error-code-contract.md`** — it does not mention
  `invalid-seal-argument` at all (§1.7). The one optional prose touch is the
  source cell of `crates/antseal-cli/src/error.rs:37`, which may gain *"; D24 §1
  `--split` × `--no-fine-tree`"*. `tests/exit_codes.rs`'s `TABLE` carries no
  source text and is unaffected.

### R12 — D24 gains a dated addendum. Exact text

Append to `docs/decisions/D24-no-fine-tree-split-conflict.md`, leaving every
existing line untouched (D24 is RESOLVED and is amended by addendum, never by
rewriting):

> ## Addendum — 2026-08-18 (D149)
>
> Layer 1 was never built; D149 rules it and sharpens three points this record
> left implicit or wrong.
>
> 1. **The venue in §1 holds.** The abort is raised in `build_plan`
>    (`crates/antseal-cli/src/seal_plan.rs`), before the consent gate, before any
>    derivation or payment — and, measured, before the vault lock, the passphrase
>    prompt and the network connect, which is what makes rationale 1's *"costs
>    seconds"* true.
> 2. **§1's condition is not free, and this record did not say so.** *"a **text**
>    file"* is `is_text` = strict UTF-8 validity over the whole file (spec line
>    83), which no `stat`, extension or prefix can answer. Plan validation
>    therefore **reads** the files that match a `--no-fine-tree` glob under an
>    active `--split`, bounded as D149 §2 R2 specifies. `--force-text` needs no
>    read: it makes a file text by argv, and such a file **is** covered by §1 even
>    when its bytes are not valid UTF-8.
> 3. **§1 is narrowed for empty files.** A raw-empty file has no fine tree at any
>    opt-out setting, so the opt-out costs it no granularity and it is **not** an
>    error. Refusing it would be over-reach of the same kind §1 already avoids for
>    binary files.
> 4. **The Consequences section's *"a distinct CLI error variant/exit code"* is
>    amended.** The error is the existing `CliError::InvalidSealArgument` → class
>    `invalid-seal-argument` → exit **27**, the class the sibling two-flag
>    contradiction (`--no-anchor` × `arbitrum-one`) already uses. No code is
>    minted: D134 §2 R3 makes the table append-only, and a new variant would force
>    a re-bless of `tests/snapshots/cli-errors.display.txt` for no gain in
>    distinctness.
> 5. **The Consequences section's *"Until U13 lands, the rule lives in G14's
>    assembly contract"* expired without being noticed.** U13/U15/U16 landed and
>    the rule did not move; U82 is the row that found it, and D149 is where it
>    moves.

### R13 — U82's Accept rows. Amendments, verbatim for the registrar

Rows 2 and 4 stand as written. Replace rows 1 and 3, and append rows 5–7:

> - `seal` aborts on the conflicting combination in **`build_plan`** — before the
>   consent gate, before any derivation or payment, and before the vault lock,
>   the passphrase prompt and the network connect. Proven by a spawned-binary test
>   that runs into a HOME with **no vault at all** and asserts exit **27**: a
>   check misplaced into `run_seal` or the pipeline answers 23 on the default
>   build and 2 on an `ant-backend` build, so the test discriminates the venue and
>   not merely the outcome. (*"Zero backend calls" is not asserted: `build_plan`
>   takes no backend, so that assertion could not fail.*)
> - Binary files matched by `--no-fine-tree` under `--split` remain **not** an
>   error, with a test for that direction so the fix does not over-reach — using a
>   file that is genuinely invalid UTF-8, since NUL padding and ASCII headers
>   validate as UTF-8 and a `.bin` name proves nothing. **`--force-text` is the
>   exception**: it makes a matched file text by argv, so that combination **is**
>   refused, and it has its own test.
> - A raw-**empty** matched file is **not** an error, with its own test: it has no
>   fine tree at any opt-out setting, so the opt-out destroyed no granularity.
> - The text decision reads the file, bounded as D149 §2 R2 specifies, and
>   `antseal_core::canon::is_text` stays the sole author of "text" — a prefix may
>   return a negative and never a positive. A test pins the boundary: valid UTF-8
>   through the probe, invalid immediately after, must classify **binary**.
> - `crates/antseal-cli/src/seal_plan.rs:794-829` is amended in the same act. It
>   is the **second** artifact encoding the refused outcome, it is inside the
>   function that must raise the error, and it is green today — this row's
>   original text named only `show_command.rs`.

Also correct the row's Spec citation from *"MVP-SPEC.md lines 60–66, 121"* to
**lines 83–85** (60–66 are the `ant-core` pin and the `StorageBackend`
signatures), and correct the `Do`'s *"its fixture is now unconstructible through
the CLI"* to *"its fixture never went through the CLI; only its comments change"*.

### R14 — This record's own index row

```
| [D149](D149-split-x-no-fine-tree-the-abort-and-its-read.md) | U82 — D24 §1's unbuilt hard error. **The venue survives and the "unbuildable" hypothesis is refuted**: plan validation reads no bytes today, but it already `stat`s and already carries `size`, and D24 §1's own condition — `is_text` = strict UTF-8 over the *whole* file — is decidable there for the price of a bounded read. Every rival venue sits **behind the passphrase prompt** (`commands.rs:326-386`), which is what rationale 1's *"costs seconds"* rules out. The lean's *"distinct usage-class error"* is **overturned**: exit 2 is wrong and a new code is refused — the sibling two-flag contradiction in the same function is already `invalid-seal-argument` (**27**), so the fix mints no code, no variant and no snapshot re-bless (D147-safe). Narrowed twice by measurement nobody had taken: **`--force-text` decides it with zero reads and passes silently today**, and a raw-empty file has no fine tree at any opt-out setting so refusing it would over-reach. **The arm nobody listed**: `show_command.rs` is not the fixture that breaks — it never calls `build_plan` — while `seal_plan.rs:801-803`, inside `build_plan`'s own test module, carries all three flags over a matching file and is **green**. And `--no-fine-tree '*.bin'` does not select binary files: a 10 KiB `tar` is valid UTF-8 end to end, so it is *text* to antseal | RESOLVED | 2026-08-18 |
```

## 3. The arms refused

### 3.1 Refuse the flag *combination* rather than the file (zero reads)

Refusing `--split` together with any matching `--no-fine-tree` glob needs no
bytes at all and would have closed the collision outright. **Refused by D24 §1
itself**: *"Binary files matched by `--no-fine-tree` are **not** an error under
`--split`: splitting never applies to binary files (G6)"*. `--split blank-lines
--no-fine-tree '*.jpg'` is the *intended* usage — split my prose, skip the fine
tree on my photographs — and this arm refuses it. U82 Accept row 3 exists
precisely to catch this over-reach.

### 3.2 Raise it in `Pipeline::seal`'s plan validation instead

Structurally attractive: it sits beside `validate_blob_caps`
(`pipeline/seal.rs:271`), whose comment already claims the exact property we
want (*"before any journal write, consent render, anchor submission or backend
call"*), and it would cover library callers too. **Refused on §1.4**: it fires
after `collect_passphrase` and after the network connect, so a two-flag typo
costs a passphrase entry — the opposite of D24 rationale 1. It would also break
`show_command.rs`'s fixture, whose *only* job is to prove D24 layer 2 holds for a
caller that bypasses the CLI, and D24 §2 deliberately chose *unrepresentable*
over *rejected* at that layer.

### 3.3 Raise it in `run_seal` between `read_all` (`:451`) and `pipeline.seal` (`:475`)

A real window the brief did not name, and free of any new read. **Refused on the
same ordering**: `run_seal` is entered only after the vault is unlocked and the
backend connected. It is strictly worse than §3.2 — later *and* blind to library
callers.

### 3.4 Decide text-ness from the file extension, a magic-byte table, or a NUL scan

**Refused on the medium of the measurement.** `canon/pipeline.rs:263-268` states
the rule has no heuristic; a second detection rule in the CLI would refuse files
the model would have split and pass files it would not — and §1.5 measured the
disagreement in the direction that matters (a `tar` is text). A probe from the
wrong medium here returns the opposite of the truth, not less of it.

### 3.5 Warn instead of erroring

**Refused by D24 rationale 2**, unchanged: the house style is loud, unit
boundaries are frozen forever, and a warning leaves the silent single-unit
outcome D24's status line says was not chosen.

### 3.6 Mint a new exit code / `CliError` variant for this refusal

**Refused on three counts**: D134 §2 R3 (append-only, 44–49 reserved), D147
ruling the table this same wave, and the re-bless of
`tests/snapshots/cli-errors.display.txt` that a new variant forces. 27 already
means *"invalid seal argument, pre-consent"* and already carries the sibling
two-flag contradiction.

### 3.7 Compute the *canonical* length instead of the raw length for the empty carve-out

`size_field()` for text is the **canonical** byte count, so the model-exact
counterfactual would canonicalize in plan validation. **Refused**: it spends a
full NFC pass on a path that exists to be cheap, to buy correctness on one input
class — a file whose raw bytes are non-empty and whose canonical rendition is
empty, which is a lone UTF-8 BOM. The residual is recorded in §6 rather than
paid for.

## 4. Falsifiers

This record is wrong if any of these turns out otherwise:

1. **A cheaper medium answers `is_text`.** If some `stat`-level or bounded-prefix
   property decides strict UTF-8 validity of a whole file, R2's read is
   unnecessary and R12's addendum item 2 is wrong. §1.5's `tar` is the standing
   counterexample.
2. **`build_plan` turns out not to be pre-passphrase.** If any future ordering
   change puts a secret or a network call ahead of `commands.rs:292`, the venue
   argument collapses and §3.2 becomes correct. T7 is the test that would notice.
3. **A third fixture carries the combination.** §1.6's sweep found two. A third
   would mean the sweep's method (`rg 'with_no_fine_tree'` × `rg 'with_split'`)
   missed a construction path — most plausibly one that builds `FileFlags` by
   `..Default::default()` or from a decoded journal record.
4. **27 is not distinct enough.** If a script needs to tell this refusal from a
   duplicate-path refusal by exit code alone, R3 is wrong and the class must
   split — a D147-shaped question, not this record's.

## 5. Defects found that are not this decision's subject

1. **`listing.rs`'s resume-hint fixture prints a command that `build_plan` already
   refuses, today.** `crates/antseal-cli/src/listing.rs:1747-1755` builds a
   `SealShapingFlags` with `split_blank_lines: true` and
   `no_fine_tree: vec!["*.png"]`, and `the_resume_hint_reproduces_every_identity_flag`
   (`:1758-1769`) asserts the hint `antseal seal 'chapter one.txt' notes.md
   --title 'my thesis' --split blank-lines --no-fine-tree '*.png' --no-anchor
   --network devnet`. `*.png` matches neither given file, so that hint is refused
   by the **zero-match** rule (`seal_plan.rs:215-224`) — a fixture asserting an
   unrunnable resume hint, unrelated to D24 and older than it.
2. **A `tar` archive is a *text* file to antseal.** It gets a canonical rendition
   (NFC + LF), a raw mirror, and `--split blank-lines` will cut it at blank
   lines. Restore is unaffected (the raw mirror preserves raw bytes, D23), so
   this is a surprise rather than a data-loss bug — but it is the kind of
   surprise that reaches a user through a `--no-fine-tree '*.tar'` refusal, and
   nothing in the docs prepares them for it.
3. **The pipeline generates `W` and the `seal_id` (`pipeline/seal.rs:247-248`)
   before `validate_blob_caps` (`:271`).** Nothing is persisted in between, so
   D24 §1's *"before any derivation"* is not violated in the sense that matters —
   but the pipeline's own section header calls `:239-247` *"the checks that need
   no content"* while `BlobExceedsChunkCap` lives after key generation, and a
   reader taking the headers at face value would place it wrongly.

## 6. What this record does NOT cover

- **The implementation.** No source file was edited by this lane; the write scope
  was this record alone. Every `R` item is unexecuted.
- **Works already staged with the conflicting flags.** D45 requires a resume to
  re-issue the identical shaping flags, and R1 refuses them — so a *legacy*
  incomplete work carrying the combination becomes unresumable. Measured extent:
  pre-release, no such works exist. Deliberate, recorded here so it is not
  rediscovered as a regression; not migrated, not detected, not warned about.
- **Reading the combination back.** `SealShapingFlags` decoded from a journal
  record (`vault/store.rs:1120`) may hold both flags and is **not** validated by
  this ruling — `list`, `show` and `status` must keep rendering legacy works.
- **A lone-BOM file.** Its raw bytes are non-empty and its canonical rendition is
  empty, so R1 refuses it although the opt-out costs it nothing (§3.7). Known,
  deliberate, exactly this one input class.
- **The `--json` rendering of the refusal.** It rides U2/U3's existing envelope
  for class 27 unchanged; no `--json`-specific assertion is ruled here.
- **D147's exit-code table.** R3 depends on `invalid-seal-argument` staying code
  27 with its current meaning. That is D147's to rule this wave; this record
  states the dependency and does not pre-empt it.
- **Whether `--no-fine-tree` should accept repeats.** `shaping.no_fine_tree` is a
  `Vec` while argv gives at most one occurrence (`seal_plan.rs:396-400`); R4 is
  written to survive the widening but does not rule on it.
- **`is_text`'s suitability as the text rule.** Spec line 83 freezes it; §1.5's
  `tar` finding is reported in §5 and not adjudicated.
- **Any re-run of the local gate, the traceability self-test, or `cargo fmt`** —
  all banned mid-wave with four lanes sharing one tree. `cargo test -p
  antseal-cli --lib seal_plan` (§1.6) and the spawned-binary runs (§1.1) are the
  only executions this lane performed.
