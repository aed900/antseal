# D160 — no pointer, and the row's premise is false six times over: the keyfile class is told its complete backup route on six shipped surfaces, `import` has no wrapped-class path in either direction, and every constructible pointer is already refused by D155 itself — recorded silence, and `U88` **closes**

- **Status: RESOLVED. The lean is OVERTURNED, and so is the row's framing.**
  The register's implicit lean was **arm (a) — a class-aware post-decode
  surface**. It is refused, on D155 §2 R1's ground **plus a new one that did not
  exist when §4.1 was written**. The row's stated ordering is also overturned:
  **arm (b) is not a candidate at all — it is already shipped**, and **arm (c),
  recorded silence, is the only arm left standing**, not the fallback the row's
  ordering implies.
  - **The row's headline is false, and D155 §4.1 says so in the same paragraph
    that routed it.** `U88` (`TODO.md:873`) says *"one vault class with no backup
    route mentioned anywhere in `init` or `import`"*. Measured: **six** shipped
    surfaces state the keyfile class's complete two-piece route, four of them in
    the CLI, one of them on **every seal, perpetually, by construction**. §4.1
    itself wrote *"only `BACKUP_BY_HAND` (D151 §2 R4) ever says so, at `init` time
    and on every seal"* — the row inverted its own parent record. §1.1.
  - **Half the row's scope does not exist. `import` has no wrapped-class path in
    either direction.** `export_vault` refuses a wrapped vault before writing
    (`vault/export.rs:745-756`) and `validate_payload` refuses a non-zero
    `wrap_mode` on the way in (`:520-536`), so no keyfile vault is ever an import
    **source**, and every vault `import` installs is mode 0. As a **target** the
    class appears only at the refusal that is preventing its destruction. §1.2.
  - **Arm (b) — `docs/user/vault-loss.md` — is MOOT, not chosen.**
    `docs/user/vault-loss.md:182-212` is a whole section titled *"If your vault
    uses a keyfile, `export` refuses"* that states the two-piece route as a
    numbered list (`:191-194`) and quotes `BACKUP_BY_HAND` **byte for byte**
    (`:207`). `docs/user/vault-theft.md:218-224` states it again. Both are under
    `check-copy-style.py`'s `docs/user/` scan root
    (`scripts/check-copy-style.py:98`). The row asks a lane to write a page that
    has been shipped since D151. §1.1 item 5.
  - **Arm (a) is no longer merely refused — it is mechanically forbidden by a
    test that post-dates §4.1 by one act.** `vault_keyfile.rs:750-759`
    (`the_class_blind_refusals_name_no_command_that_could_refuse_the_reader`,
    D155 §2 R8) asserts `messages[0].2 == messages[2].2` and
    `messages[1].2 == messages[3].2` — the two refusals, path-elided, must be
    **byte-identical across wrap classes**. Any class-aware pointer at either
    site reddens it by construction. The brief asked *"does arm (a) reopen a
    question D155 closed three days ago, and on what new ground?"* — the new
    ground runs the **other** way. §1.6.
  - **The fourth arm the brief hoped for is not constructible, and the arm space
    closes.** An unconditional pointer would clear the equality assertion, so it
    is mechanically admissible — but the fact §4.1 wants pointed at (*your
    keyfile is a second piece, outside this directory*) is **class-typed**. Every
    untyped rendering of it is either a conditional wearing a different hat
    (D155 §3.3's refused hedge), a doc/URL pointer (D155 §3.5, refused), or so
    general it carries no information. §1.7.
  - **The harm is thin and its floor is loud.** The worst measured outcome is a
    keyfile user who copies the moved directory to another machine without the
    keyfile and meets `CliError::VaultKeyfileMissing` — **a distinct class,
    created for exactly this** (`vault/keyfile.rs:196-203`: *"A user whose USB
    stick is unplugged must be told that, not told their passphrase is wrong"*).
    Nothing is destroyed and the remedy is copying one file. §1.8.
  - **The arm nobody listed, and it is the only edit this record authorises.**
    The silence is licensed by the six surfaces, so what matters is whether they
    are **pinned**. Measured: `export_nag`'s rendering appears in **no golden**
    — `init-report.txt` renders `standing_warnings`, not the nag — and its own
    unit test pins `LOSS_WARNING` and `THEFT_WARNING` **by identity**
    (`bookkeeping.rs:393-394`) while pinning the **class-keyed remedy** by the
    four characters `"BACK UP"` (`:397-400`). The single surface D155 §4.1 leans
    on hardest — *"on every seal"* — is the weakest-pinned line in the function
    that emits it, and rewriting its wrapped arm to any other string containing
    `BACK UP` leaves the whole suite green. **R8** closes that. §1.9.
- **Date: 2026-08-22**
- **Owning task: U88** (M4, size S)
- **What it blocks: nothing.** `U88` is `before U32` — **ordering, not a gate**.
  `U88` closes in this act, so the ordering is discharged rather than carried.

---

## 0. What was measured against

Read in full before anything was written: `docs/decisions/D155-class-blind-vault-refusal-copy.md`
(the parent record, §1.1-§1.10, §2 R1-R12, §3.1-§3.7, §4.1-§4.5, §5.1-§5.7),
`TODO.md:873` (`U88`'s row), `tasks/U.md:1267-1281` (`U88`'s entry).

Measured at source, not quoted from a record: `crates/antseal-cli/src/init.rs`,
`crates/antseal-cli/src/error.rs`, `crates/antseal-cli/src/vault/bookkeeping.rs`,
`crates/antseal-cli/src/vault/keyfile.rs`, `crates/antseal-cli/src/vault/export.rs`,
`crates/antseal-cli/src/vault/session.rs`, `crates/antseal-cli/src/seal_run.rs`,
`crates/antseal-cli/tests/vault_keyfile.rs`, `.../init_command.rs`,
`.../vault_export.rs`, `.../snapshots/init-report.txt`,
`.../snapshots/cli-errors.display.txt`, `.../snapshots/json-envelopes.txt`,
`docs/user/vault-loss.md`, `docs/user/vault-theft.md`,
`scripts/check-copy-style.py`, `scripts/check-traceability.py`.

No `cargo build`, no `cargo test`, no `scripts/local-gate.sh`, no
`--self-test`: other lanes hold the build lock and the tree. Every claim below
is a **static** measurement, and every claim that would need a run to settle is
labelled as a **prediction the implementing lane must watch**, not as a result.

---

## 1. What was measured

### 1.1 The row's headline is false. Six surfaces state the keyfile class's complete route

`U88` says *"no backup route mentioned anywhere in `init` or `import`"*.
Measured 2026-08-22:

| # | Surface | Source | Emitted from | Frozen at |
|---|---|---|---|---|
| 1 | `placement_guidance`'s fourth line — *"a copy of the keyfile, on different media from the vault, is the second half of this vault's backup"* | `vault/keyfile.rs:283-300` (line at `:294-298`) | `init.rs:261`, keyfile branch only | `tests/snapshots/init-report.txt:68` |
| 2 | `BACKUP_BY_HAND` — *"this vault has a keyfile, so it is backed up by hand, in two pieces kept apart: a copy of the vault directory and a copy of the keyfile"* | `vault/bookkeeping.rs:96-99` | `init.rs:266` → `standing_warnings(true)` `init.rs:368-388`, at `:377-381` | `tests/snapshots/init-report.txt:79` |
| 3 | the same constant, **on every seal, forever** | `vault/bookkeeping.rs:96-99` via `export_nag(true)` `:285-302`, at `:294-298` | `seal_run.rs:146-147`, gated by `seal_run.rs:523` | **nowhere** — §1.9 |
| 4 | the `vault export` refusal itself — *"Back up the vault directory and the keyfile separately by hand"* | `vault/export.rs:745-756` | the command the class actually reaches for | `tests/vault_keyfile.rs:472-475` |
| 5 | `docs/user/vault-loss.md:182-212` — a titled section, a numbered two-piece list at `:191-194`, `BACKUP_BY_HAND` byte for byte at `:207` | — | — | `docs/user/` is a `COPY_SCAN` root (`check-copy-style.py:98`) |
| 6 | `docs/user/vault-theft.md:218-224` — *"You back up the vault directory and the keyfile by hand, in two pieces kept apart."* | — | — | same scan root |

Also present but **not** product copy and therefore not counted in the six as a
user-facing statement: `docs/vault-keyfile.md:53`, classified `ENG` at
`check-copy-style.py:149` (*"keyfile mechanism reference; Q24 writes the
user-facing pages"*).

**Surface 3 is perpetual by construction, not by neglect.** `export_nag` fires
when `!ever_exported()` (`seal_run.rs:523`); `record_export` has exactly one
production caller (`commands.rs:811`), reached only after a successful
`vault export`, and that command refuses this class at `export.rs:745-756`. The
nag therefore never clears for a keyfile vault, and `bookkeeping.rs:279-283`
records that reasoning at the source. A keyfile user is told the complete
two-piece route **at vault creation, twice, and then on every seal they ever
make**.

D155 §4.1 knew this and wrote it: *"only `BACKUP_BY_HAND` (D151 §2 R4) ever says
so, at `init` time and on every seal."* The row's *"anywhere"* is not a
restatement of §4.1 — it is its negation.

### 1.2 `import` has no wrapped-class path in either direction

The row's scope is *"`init` or `import`"*. Measured, the second half is empty:

- **Out.** `export_vault` refuses before writing when
  `header_wrap != WRAP_MODE_NONE` (`vault/export.rs:744-756`). No keyfile vault
  ever produces an export file.
- **In.** `validate_payload` refuses any payload whose `wrap_mode` is non-zero
  (`vault/export.rs:520-536`), *"so neither happens"*. No import ever installs a
  wrapped vault.

So `import` is a mode-0 command end to end, and the keyfile class meets it only
as the **target** of `refuse_existing_target` (`vault/export.rs:1208-1213`) —
the gate whose entire job is to stop that vault being destroyed. Asking where
`import` should state the wrap-aware route asks about a code path that does not
exist.

### 1.3 What §4.1 asked, and what the row turned it into

§4.1's question, verbatim
(`docs/decisions/D155-class-blind-vault-refusal-copy.md`, §4.1):

> Whether a class-blind refusal should carry a *pointer* to that — without
> naming a command and without a hedge — is a copy question this record does not
> answer. **Needs a row.**

The subject is a **pointer inside the class-blind message**, bounded by two
constraints. The row's `Do` widens it to *"decide where the wrap-aware backup
route is stated"* and offers three venues, one of which (`vault-loss.md`) is not
in §4.1's question at all — §4.1 is not asking where the route lives, it is
asking whether the **refusal** should gesture at it.

**The tension the brief flags dissolves once both are read precisely.** §4.1
says *"without naming a command"*; `U88`'s `Do` says *"Do not re-introduce a
command name into the class-blind message"*. These are the **same constraint**,
not rival readings. The row's `Do` is not a rival question — it is a correct
restatement of one of §4.1's two bounds. **§4.1's question governs** (R2), and
the row's venue survey is narrowed to it.

### 1.4 The narrow residue, stated exactly

Everything in §1.1 that reaches a keyfile user at `init` reaches them on a
**successful** init: `standing_warnings` and `placement_guidance` are composed
by `InitReport::render` (`init.rs:260-267`), which is built only after
`run_init` returns `Ok`. The existing-vault gate returns at `init.rs:418-419`,
before section 2 of `run_init`, so **in that invocation** the user sees the
refusal and nothing else. The same holds at `refuse_existing_target`
(`vault/export.rs:1208-1213`), step 1 of `import_vault_impl` (`:1034`).

That is the whole of the real gap, and it is a gap in **one invocation**, not in
the product: the user standing at that refusal already owns a vault, therefore
already ran `init` successfully once, therefore already saw surfaces 1 and 2,
and sees surface 3 on every seal since.

### 1.5 *"a moved directory keeps everything"* is true for the keyfile class — measured three ways

R2's sentence (`init.rs:632`) and R3's (`error.rs:580`) are the claim the row
implies is incomplete for mode 1. Measured:

1. **The keyfile is not in the directory and is not touched by the move.**
   `default_keyfile_path` (`init.rs:655-663`) joins `antseal-keyfile.bin` to the
   vault root's **parent**, deliberately (`:648-654`).
2. **The moved vault still finds it.** `create_vault` records the keyfile path
   in the header (`vault/session.rs:242-253`, `record_path: true` at
   `init.rs:509-515`), key `2` of the v1 body (`vault/header.rs:11`, `:180`,
   `:238-239`). `keyfile::locate` (`vault/keyfile.rs:237-247`) resolves explicit
   → `ANTSEAL_KEYFILE` → recorded. Moving the root changes none of the three.
3. **The next command cannot clobber the old keyfile.** A user who moves the
   vault aside and re-runs `antseal init --wrap keyfile` is offered the *same*
   default path, which now holds the old vault's keyfile. `keyfile::generate`
   refuses on `path.exists()` (`vault/keyfile.rs:152-161`) with
   *"If that file is another vault's keyfile, replacing it would make that vault
   permanently unopenable. Choose a different path"*, and belts it with
   `create_new(true)` (`:172`). The obvious way for the refusal's advice to
   backfire is already closed.

R2's own reasoning had reached (1) and (2) — *"the keyfile is not in that
directory to begin with … and is not touched by the move either way"*. (3) is
new here and is the measurement that would have made the sentence dangerous if
it had gone the other way. It does not.

### 1.6 Arm (a) is mechanically forbidden by a test that post-dates §4.1

`the_class_blind_refusals_name_no_command_that_could_refuse_the_reader`
(`crates/antseal-cli/tests/vault_keyfile.rs:615-800`) landed **with** D155's own
act. Its step 3 collects each refusal per class, elides the vault path, and
asserts:

- `vault_keyfile.rs:750-755` — `messages[0].2 == messages[2].2`, with the failure
  text *"`init`'s refusal must be class-blind … a message that varies by wrap
  mode means the gate moved and D155 §2 R1 was overturned in silence"*;
- `vault_keyfile.rs:756-759` — the same for `import`.

Any per-class pointer at either site makes those two strings differ and reddens
the assertion. So arm (a) now costs everything D155 §3.1 priced (two more frozen
envelope lines, an I/O-and-parse step on a total refusal, a third message on the
surface U32 ratifies) **plus** overturning a shipped guard whose failure message
names the ruling it would be overturning. The brief asked what new ground has
arrived in three days; it has, and it is against the arm.

The `NeverPrompts` trap the brief warns about is **already repaired** and must
not be re-introduced: `passphrase_fd_in` (`vault_keyfile.rs:552-568`) exists
precisely because, without a real passphrase fd, `run_init` answers
`PassphraseUnavailable { NoChannel }` before any `InitPrompt` method is reached
and the double could never fire. The comment at `:664-676` records the
measurement. Nothing in this record uses a double.

### 1.7 The arm space of §4.1's question is closed, and the fourth arm is not constructible

§4.1 admits exactly four shapes of pointer. Each is disposed of by a standing
measurement:

| Shape | Verdict | By |
|---|---|---|
| **Class-aware branch** at the refusal | refused | D155 §2 R1 / §3.1 (a decode cannot classify `NewerVersion`, so the class-blind wording survives anyway) **+ §1.6 here** (now test-forbidden) |
| **Hedge** — *"(a keyfile vault is backed up by hand instead)"* | refused | D155 §3.3 — *"a parenthetical asking them to work out which kind of vault they have adds a decision at the moment when the product's job is to remove one"* |
| **Doc or URL pointer** | refused | D155 §3.5 — a CLI refusal cannot cite a repository path; the one canonical URL is pinned to the verifier (`check-copy-style.py:256`) |
| **Unconditional, class-free pointer** | **not constructible** | below |

The fourth shape is the one the brief asked to be looked for, and it is the only
one that clears §1.6's equality assertion — so it had to be tried rather than
dismissed. It fails on a different measurement: **the fact is class-typed.**
*Your keyfile is a second piece and it is outside this directory* is true of
mode 1 and meaningless for mode 0. Every untyped rendering collapses into one of
the three rows above:

- *"if this vault has a keyfile, it lives outside the directory"* — a hedge with
  `if` in it, D155 §3.3;
- *"see the backup guidance"* — a doc pointer, D155 §3.5;
- *"a moved directory keeps everything **that is inside it**"* — genuinely
  unconditional and genuinely hedge-free, but it **subtracts** rather than
  points: it weakens the sentence for the mode-0 reader (for whom the directory
  *is* everything) to hint at a fact it still does not state, on the one message
  in the product read by someone about to delete every sealed work's reveal keys.
  It is D155 §3.4's shape — repairing a sentence by removing its true part.

There is no fifth shape. §4.1's question therefore has exactly one available
answer, and the answer is **no pointer** — not as a preference, but as the
residue of an enumeration.

### 1.8 The harm, named: the user, the commands, and the floor

The brief requires a concrete user. The sharpest one constructible:

```
$ antseal init --wrap keyfile          # vault at ~/.antseal, keyfile at ~/antseal-keyfile.bin
                                       # → placement_guidance + BACKUP_BY_HAND (surfaces 1, 2)
$ antseal seal work.txt                # → export_nag(true): BACKUP_BY_HAND again (surface 3)
   … months pass …
$ antseal init                         # → REFUSED: "move ~/.antseal aside instead of deleting it:
                                       #    a moved directory keeps everything"
$ mv ~/.antseal /media/usb/antseal-old # reads "keeps everything" as "this is my backup"
   … the machine dies; the USB stick is all that survives …
$ ANTSEAL_DIR=/media/usb/antseal-old antseal list
```

The last command answers `CliError::VaultKeyfileMissing`, **naming the path it
looked for and all three channels it consulted** (`vault/session.rs:405-418`,
`vault/keyfile.rs:196-203`). That class exists for exactly this and its rustdoc
says so: *"one distinct class, never the generic vault-auth failure (U8 Accept).
A user whose USB stick is unplugged must be told that, not told their passphrase
is wrong."* Nothing was destroyed — the keyfile is still on the dead machine's
disk or in whatever backup surfaces 1-3 told them to make — and the remedy is
copying one 32-byte file.

That is the floor of the harm: **a named error with a path in it, at read time,
with the data intact.** Weigh it against what a pointer costs — reopening a
message that two frozen machine contracts, fourteen assertions and one
byte-for-byte doc quote depend on (§1.9), inside the freeze window `U32` is
about to close.

**And note which direction the pointer would push.** At the refusal, the user
has been told to do the thing that needs **no** backup. Appending *back up first*
to *move it aside* recommends a slower, more failure-prone action than the one
already given, at the moment D155 §3.3 identified as the wrong moment to add a
decision. The pointer is not merely unnecessary; it competes with the remedy.

### 1.9 Coverage census — **by parse, with counts**

Two censuses were run mechanically (script at
`/tmp/claude-1000/-home-deb-Documents-code0/.../scratchpad/census4.py`), because
D155 §2 R5 item 2 declared a field clear having read `vault_export.rs:520` while
`:534-546` asserted the same message twelve lines later.

**(a) What moves if either refusal's copy changes.** Every string literal in an
assertion inside a function that drives `existing_vault_refusal`,
`ImportRefusedExistingVault`, `refuse_existing_target`, or the real binary's
`init`, filtered to literals that occur in (or are asserted absent from) either
rendered message:

| File | Sites | Lines |
|---|---|---|
| `crates/antseal-cli/tests/init_command.rs` | 5 | `:591` `no --force`; `:597` `!contains("antseal vault export")`; `:602` `aside`; `:998` `already exists`; `:999` `no --force` |
| `crates/antseal-cli/tests/vault_export.rs` | 3 | `:535` `!contains("antseal vault export")`; `:540` `aside`; `:544` `unsupported` |
| `crates/antseal-cli/tests/vault_keyfile.rs` | 6 | `:737` length > 200; `:742` `<dir>`; `:746` `aside`; `:750` init class-blind equality; `:756` import class-blind equality; `:766` step 4's export-command biconditional |

**14 assertion sites across 3 test files.** Plus **3 frozen rendering lines in 2
snapshots** — `tests/snapshots/cli-errors.display.txt:14`,
`tests/snapshots/json-envelopes.txt:2`, `:20` — and **1 byte-for-byte doc
quote**, `docs/user/vault-loss.md:252`. **Total: 18 sites in 6 files.**

Two of the fourteen (`init_command.rs:998-999`) are reachable **only** through
the real binary and were missed by the first, function-scoped pass; they were
recovered by widening the driver set to process-level `init` tests. Stating that
because the first count was 12 and the correct count is 14.

**(b) What pins the six surfaces the silence is licensed by.** This is the census
that matters, and it is where the defect is:

| Surface | Existence pinned by | **Wording** pinned by |
|---|---|---|
| 1 `placement_guidance` backup line | nothing individually — `vault_keyfile.rs:497-500` is an OR over three producers | **`init-report.txt:68` only.** Its own unit test (`vault/keyfile.rs:423-429`) asserts the path, `ANTSEAL_KEYFILE`, and the **absence** of `antseal vault export` — never the backup sentence |
| 2 `BACKUP_BY_HAND` via `standing_warnings` | `init.rs:829-832` (`contains("BACK UP")`) | **`init-report.txt:79`** |
| 3 `BACKUP_BY_HAND` via `export_nag` | `bookkeeping.rs:397-400` (`contains("BACK UP")`) | **nothing.** `export_nag`'s rendering is in **no** golden — `grep 'NO BACKUP' tests/snapshots/` returns zero |
| 4 `vault export` refusal | — | `vault_keyfile.rs:472-475` (`contains("separately by hand")`) |
| 5, 6 `docs/user/*.md` | `COPY_SCAN` walk (`check-copy-style.py:98`) | nothing verifies the byte-quote at `vault-loss.md:207` still matches `bookkeeping.rs:96-99` — §4.2 |

**The finding.** Inside `the_nag_carries_both_failure_modes_and_no_positioning_overreach`
(`vault/bookkeeping.rs:389-412`), the two **class-blind** constants are asserted
by identity — `text.contains(LOSS_WARNING)` at `:393`,
`text.contains(THEFT_WARNING)` at `:394` — while the one **class-keyed**
constant, the remedy, is asserted by the four characters `"BACK UP"` at
`:397-400`. The export-command biconditional at `:401-405` catches a wrapped arm
that names the export, and `vault_keyfile.rs:507-520` catches the same thing
across producers. **Nothing catches a wrapped arm rewritten to any other string
containing `BACK UP`** — and `vault_keyfile.rs:400-409` already records, from
U84's lane, that the cross-producer test is an OR and that *"emptying only
`export_nag` leaves this test green"*.

So the single strongest surface licensing this record's silence — the one that
speaks on **every seal, perpetually, to exactly the class in question** — is the
weakest-pinned line in the function that emits it. **R8 closes that**, and it is
the only production-adjacent edit this record authorises.

**What does not police this, and must not be leaned on.** `check-copy-style.py`'s
`DISCLAIMER` heuristic (`scripts/check-copy-style.py:242-246`) admits
`not|never|no|none|nothing|neither|nor|isn't|cannot|can't|without|rejected|banned|forbidden|refused|refuses`,
so **a refusal satisfies the disclaimer test with its own refusal verb**. It is
not a witness for refusal copy in either direction. The witnesses here are the
goldens and the assertions above.

### 1.10 Verdicts on every locator the brief and the row supplied

| Locator as given | Verdict |
|---|---|
| `TODO.md:873` — `U88`'s row | **confirmed** |
| `docs/decisions/D155-…:1109-1111` — §4.1's question | **confirmed**, quoted verbatim at §1.3 |
| `crates/antseal-cli/src/vault/bookkeeping.rs:96-99` — `BACKUP_BY_HAND` | **confirmed** exactly |
| `crates/antseal-cli/src/init.rs:368-383` — `standing_warnings` | **short at the tail.** The fn is `:368-388`; the class-keyed selection is `:377-381` |
| `crates/antseal-cli/src/init.rs:418-419` — the gate | **confirmed** |
| `crates/antseal-cli/src/vault/export.rs:1208-1213` — `refuse_existing_target` | **confirmed** for the `ImportRefusedExistingVault` branch; the fn runs to `:1223` and its second branch (`:1214-1221`, *"exists but is not a vault"*) is a different message |
| `crates/antseal-cli/src/init.rs:626-637` — the U86 reword | **confirmed**; the `format!` body is `:628-635` |
| `crates/antseal-cli/src/init.rs:650-663` — `default_keyfile_path` | **off at both ends.** The fn is `:655-663`; `:648-654` is its doc comment. D155 §4.1 and §2 R2 cite `:654-662`, off by one at both ends in the other direction. The **fact** — parent, not root — is confirmed at `:656-660` |
| D155 §4.1's *"only `BACKUP_BY_HAND` … at `init` time and on every seal"* | **confirmed, and it refutes the row it routed** |
| The row's *"no backup route mentioned anywhere in `init` or `import`"* | **FALSE.** Six surfaces, §1.1; and `import` has no wrapped path at all, §1.2 |
| The row's arm ordering (a) > (b) > (c) | **inverted.** (b) is shipped, (a) is test-forbidden, (c) is what remains |

---

## 2. Ruling

**Owner: U88**

### R1 — §4.1's question is answered **no**. Neither class-blind refusal gains a pointer

*Executed by: nobody — this is the finding the rest of the act records.*

`crates/antseal-cli/src/init.rs:628-635` (`existing_vault_refusal`'s `format!`
body) and `crates/antseal-cli/src/error.rs:577-584`
(`ImportRefusedExistingVault`'s `#[error]` attribute) are **not touched**: not
one byte of either rendered string. `tests/snapshots/cli-errors.display.txt:14`,
`tests/snapshots/json-envelopes.txt:2` and `:20` stay **byte-identical**, and
that is this ruling's own verification (R9's plant B).

The ground is **§1.7**: §4.1's question admits four shapes of pointer; three are
refused by D155 §2 R1, §3.3 and §3.5, and the fourth is not constructible
because the fact is class-typed. This is a **closed enumeration**, not a
preference — which is what makes it a ruling rather than a deferral.

The supporting measurements, each of which would independently have changed the
answer had it gone the other way: the class is told its complete route on six
surfaces (§1.1), one of them perpetually; `import` has no wrapped path (§1.2);
the move preserves everything and cannot backfire into the old keyfile (§1.5);
and the floor of the harm is a named error with a path in it (§1.8).

### R2 — §4.1's question governs; the row's venue survey is narrowed to it

*Executed by: the registrar, in `tasks/U.md` and `TODO.md` (§5).*

Where `U88`'s `Do` (*"decide where the wrap-aware backup route is stated"*) and
D155 §4.1 (*"whether a class-blind refusal should carry a pointer"*) differ in
scope, **§4.1 governs**, because §4.1 is the record that routed the row and
`U88` exists to answer it.

The apparent tension the brief flags is not one. §4.1's *"without naming a
command"* and the row's *"do not re-introduce a command name into the class-blind
message"* are the **same constraint stated twice**, and R1 satisfies both by
adding nothing. The row's third venue (`vault-loss.md`) is outside §4.1's
question and is separately moot (R4).

### R3 — `U88`'s headline is corrected at source, and the row **closes**

*Executed by: the registrar (§5.2, §5.3).*

The row's problem statement is **overstated and is replaced**, not softened. The
replacement text is given verbatim at §5.3 so the registrar splices rather than
composes. In particular the row must stop asserting *"anywhere in `init` or
`import`"*, because (i) six surfaces say it, §1.1, and (ii) `import` has no
wrapped-class path, §1.2.

**The row closes — it does not shrink.** It closes with content: R8's pin lands,
R9's dispositions land, and the silence is recorded in the two places the next
reader will actually look (R7). A row that closes with a measured `No` and a
guard is not a row that was dropped.

### R4 — Arm (b) is **moot**, and this is a correction to the brief's arm list

*Executed by: nobody.*

`docs/user/vault-loss.md:182-212` already is arm (b), shipped, with a titled
section, a numbered two-piece list at `:191-194`, and `BACKUP_BY_HAND` quoted
byte for byte at `:207`; `docs/user/vault-theft.md:218-224` repeats it. **No
documentation is written by this act.** Any lane that reads `U88`'s `Do` and
starts writing a `vault-loss.md` section is duplicating D151's work.

### R5 — Arm (a) is refused, on D155 §2 R1's ground **plus** a new one

*Executed by: nobody — this is the constraint an implementing lane runs under.*

No `CliError` variant gains a wrap field; neither gate decodes; neither gate
moves. D155 §2 R1's ground stands unchanged (a decode cannot classify
`NewerVersion`, so the class-blind wording survives arm (a) anyway, making it
strictly additive).

**The new ground, and it is the answer to *"on what new ground?"*:**
`vault_keyfile.rs:750-755` and `:756-759` assert that each refusal is
**byte-identical across wrap classes** once its path is elided. Arm (a) is now
forbidden by a shipped mechanism whose own failure message reads *"D155 §2 R1 was
overturned in silence"*. Three days changed the price in the **opposite**
direction from the one the brief hypothesised.

Parked on the same terms D155 §3.1 set: if a future format event makes the wrap
readable without a fallible decode, R1's silence and D155 R2/R3's wording both
remain correct, and a class-aware branch becomes an addition — at which point
`vault_keyfile.rs:750-759` is the assertion that must be **deliberately**
re-ruled, never quietly relaxed.

### R6 — The fourth arm is recorded as **not constructible**, with its three collapses named

*Executed by: nobody.*

Recorded so the next reader does not re-derive it: an unconditional pointer
clears the class-blindness assertion but cannot carry a class-typed fact.
*"if this vault has a keyfile…"* is D155 §3.3's hedge; *"see the guidance"* is
D155 §3.5's doc pointer; *"keeps everything **that is inside it**"* is D155
§3.4's shape — repairing a sentence by deleting its true part, on the message
read by someone about to destroy every sealed work's reveal keys.

### R7 — The silence is recorded **where the next reader stands**, not only here

*Executed by: `U88`'s implementing lane, in `crates/antseal-cli/src/init.rs` and `crates/antseal-cli/src/error.rs` — **doc comments only**.*

D155's own ledger finding 3 is *"a refusal that binds a future row belongs in
that row's `Notes`, not only in the deciding record's §3"*. The same failure
mode applies to a **silence**: recorded only in `docs/decisions/`, it is
re-minted the next time someone reads either refusal and notices no backup
pointer. Both sites already carry a D155-citing rustdoc, so the sentence has a
home and no new surface is created.

**(a)** Append to the rustdoc above `existing_vault_refusal`
(`crates/antseal-cli/src/init.rs:616-624`), as the last paragraph before
`#[must_use]`, verbatim:

```rust
/// **It carries no backup pointer, and that is ruled rather than
/// overlooked (D160 §2 R1).** The keyfile class — the one whose backup is
/// two pieces — is told its complete route on six surfaces, including
/// `export_nag`'s perpetual first-seal nag, and a move preserves
/// everything at both sites anyway. Every constructible pointer here is
/// already refused: a class-aware one by D155 §2 R1 (and now by
/// `tests/vault_keyfile.rs:750-759`, which requires this message to be
/// byte-identical across wrap classes), a hedge by D155 §3.3, a doc or URL
/// pointer by D155 §3.5.
```

**(b)** Append to the rustdoc above `ImportRefusedExistingVault`
(`crates/antseal-cli/src/error.rs:567-576`), as the last paragraph before
`#[error(`, verbatim:

```rust
    /// **No backup pointer, ruled (D160 §2 R1).** `import` never carries a
    /// wrapped vault in either direction — `export_vault` refuses one at
    /// `vault/export.rs:745-756` and `validate_payload` refuses one at
    /// `:520-536` — so the class this silence is about reaches this gate
    /// only as the target it is protecting. The pointer arms are refused at
    /// D155 §2 R1, §3.3 and §3.5; `tests/vault_keyfile.rs:756-759` requires
    /// this message to be byte-identical across wrap classes.
```

Neither edit changes a rendered byte. **The verification is that the three
frozen lines in §1.9(a) do not move** — R9 plant B.

### R8 — The pin the silence needs: `export_nag`'s class-keyed remedy asserted by identity

*Executed by: `U88`'s implementing lane, in `crates/antseal-cli/src/vault/bookkeeping.rs:397-400`.*

**This is the only edit in this act that can change a test verdict, and it is
the arm nobody listed.** §1.9(b) measures that `export_nag`'s rendering is in no
golden and that its wrapped arm is pinned by four characters, while the two
class-blind constants beside it are pinned by identity. R1's silence is licensed
by that surface; an unpinned licence is not one.

Replace `vault/bookkeeping.rs:397-400` — currently:

```rust
            assert!(
                text.contains("BACK UP"),
                "wrapped={wrapped}: no remedy line: {text}"
            );
```

with, verbatim:

```rust
            assert!(
                text.contains("BACK UP"),
                "wrapped={wrapped}: no remedy line: {text}"
            );
            // The remedy is CLASS-KEYED, and until D160 it was the only
            // constant here pinned by four characters while `LOSS_WARNING`
            // and `THEFT_WARNING` above are pinned by identity. This
            // rendering is in NO golden (`init-report.txt` renders
            // `standing_warnings`, not this nag), so a wrapped arm rewritten
            // to any other string containing "BACK UP" was a silent
            // regression: it kept this assert, the export-command
            // biconditional below, and `tests/vault_keyfile.rs`'s
            // cross-producer test all green — and that nag is the surface
            // D160 §2 R1's recorded silence at the two existing-vault
            // refusals is licensed by.
            //
            // This is a ROUTING assertion — which constant the producer
            // selected — and NOT the banned shape `vault/keyfile.rs:418-422`
            // warns about, which compares a claim against the string that
            // makes it. The constants' own wording stays pinned by
            // `tests/snapshots/init-report.txt:68` and `:79`.
            let expected = if wrapped {
                BACKUP_BY_HAND
            } else {
                BACKUP_BY_EXPORT
            };
            let other = if wrapped {
                BACKUP_BY_EXPORT
            } else {
                BACKUP_BY_HAND
            };
            assert!(
                text.contains(expected),
                "wrapped={wrapped}: the nag's remedy is no longer this class's own \
                 constant. A keyfile vault's owner is told the two-piece backup route \
                 here on EVERY seal, perpetually, and that surface is what licenses the \
                 silence at both existing-vault refusals (D160 §2 R1/R8): {text}"
            );
            assert!(
                !text.contains(other),
                "wrapped={wrapped}: the nag emits the other class's remedy as well, so \
                 the assertion above passes for free: {text}"
            );
```

`BACKUP_BY_EXPORT` and `BACKUP_BY_HAND` are already in scope: the module is
`#[cfg(test)] mod tests { use super::*; }` (`vault/bookkeeping.rs:305-307`) and
both are `pub const` in the parent (`:87-89`, `:96-99`).

**Why the anti-vacuity `!text.contains(other)` earns its line, measured.** On the
**mode-1** row a stray `BACKUP_BY_EXPORT` is already caught by the
export-command biconditional at `:401-405`, because that constant names
`` `antseal vault export` ``. On the **mode-0** row it is not: a producer emitting
*both* constants satisfies `contains(expected)` and still contains the export
command, so the biconditional stays green. The guard is load-bearing for exactly
one of the two rows, which is why it is stated per-row rather than once.

### R9 — The plants. Two, with **four** predicted verdicts, three of them green

*Executed by: `U88`'s implementing lane. Every plant reverted, and after every
revert `touch` the file — `cp -p` preserves mtime and cargo will re-run the
already-built planted binary (wave 27's build-fingerprint trap). Read
`REAL_EXIT=` back out of a file; the harness's own exit-code notification reports
the last command in the wrapper, not the one being measured.*

**Plant A — proves R8's assertion can go red, and that it is the *only* witness.**
At `vault/bookkeeping.rs:295`, replace `BACKUP_BY_HAND` in `export_nag`'s wrapped
arm with a *different* string that still contains the token, e.g.
`"  BACK UP — see the documentation."`. Then run, and record each verdict
separately:

| # | Target | Predicted | What it proves |
|---|---|---|---|
| A1 | `bookkeeping::tests::the_nag_carries_both_failure_modes_and_no_positioning_overreach` | **RED**, on the `wrapped=true` row, message naming the rendered text | R8's assertion is reachable and fires |
| A2 | `init_command`'s `init-report.txt` golden test | **GREEN** | the golden renders `standing_warnings`, not this nag — the pin was genuinely absent |
| A3 | `vault_keyfile::the_backup_advice_matches_what_export_actually_does` | **GREEN** | the cross-producer test is an OR (`vault_keyfile.rs:400-409`) and cannot see this |
| A4 | `init::tests::standing_warnings_state_loss_and_theft_and_the_positioning_limit` | **GREEN** | the sibling producer is untouched |

**A2, A3 and A4 being green is the point.** A red-only plant would prove the
assertion fires; only the three greens prove it is not redundant with something
already shipped. If any of A2-A4 comes back **red**, R8 is redundant as written
and the lane must stop and report rather than land it.

The lane must also **measure and report** `copy.len()` in A3's `wrapped=true`
iteration on both sides of the plant, rather than assuming the `> 1_000` guard
at `vault_keyfile.rs:501-505` is unaffected. Assume nothing about a threshold
whose margin has not been read.

**Plant B — proves R1's "nothing moved" is machine-witnessed, not reviewed.**
Change **one byte** of `existing_vault_refusal`'s format string
(`init.rs:628-635`) — e.g. `aside` → `asid3`. Predicted: `json-envelopes.txt`'s
comparison goes **RED**. Revert; repeat on `error.rs:577-584` and predict
`cli-errors.display.txt` **and** `json-envelopes.txt` both red. This is what
licenses the sentence *"R7 changes no rendered byte"*: the frozen contracts, not
a reviewer's eye — and expressly **not** `check-copy-style.py`, whose
`DISCLAIMER` heuristic (`:242-246`) admits `refused|refuses|no|not|never`, so a
refusal message satisfies it with its own verb.

**Two traps designed around, explicitly.** (i) No assertion added by R8 sits
behind a mandatory verdict guard — the two new asserts are appended **after** the
existing `"BACK UP"` check and **before** the export-command biconditional, in a
loop body with no early return, so plant A cannot be short-circuited the way
D155 §2 R8's sketch short-circuited its own T1. (ii) No test double is
introduced; `export_nag` is a pure function of one `bool`, so there is no call
that can answer before the thing under test is reached.

### R10 — `U88`'s `Accept` rows, dispositioned verbatim for the registrar

*Executed by: the registrar, in `tasks/U.md` under `### U88`.*

Vocabulary per D140 §2 R1, D143 §2 R5, D148 §2 R10.

1. *"Every wrap class has one reachable statement of how to preserve its vault's
   contents, or the silence is recorded here with its reason."*
   → **MET, by BOTH disjuncts, and the first was already true before this act.**
   Mode 0 gets `BACKUP_BY_EXPORT` (`bookkeeping.rs:87-89`) at `init` and on every
   seal; mode 1 gets the complete two-piece route on **six** surfaces (D160
   §1.1), one perpetual by construction. The second disjunct is satisfied by D160
   §2 R1 and is recorded in the row itself by §5.3's replacement text and in the
   code by §2 R7.
2. *"Nothing added to the class-blind refusals names a command that may refuse
   the reader's vault — asserted by U86's existing test rather than by review."*
   → **MET.** Nothing is added at all (R1), and the assertion is standing and
   universally quantified: `vault_keyfile.rs:766-780` holds
   `rendered.contains(EXPORT_COMMAND) == runs_for_every_class` for both messages
   and both classes. **This row keeps its force after the row closes** — it is
   the guard any future edit at either site must clear — and R9 plant B is the
   proof it is not vacuous.
3. *"If a new user-facing string lands, it is reachable by `check-copy-style.py`
   through a committed snapshot (the U87 lesson), not merely hand-checked."*
   → **inapplicable, not met.** Its antecedent is false: no new user-facing
   string lands (R1), and R7's two edits are rustdoc, R8's is a test assertion.
   Recorded rather than ticked, and recorded with the standing mechanism so a
   future row does not re-litigate it: `crates/antseal-cli/tests/snapshots/` is
   already a `COPY_SCAN` root (`check-copy-style.py:100`), so any string that
   ever lands in either refusal is reached with **no script edit**, via
   `cli-errors.display.txt` and `json-envelopes.txt`.

**A fourth row is appended**, because R8's pin is a claim `U88` now carries and
nothing else states:

4. `export_nag`'s class-keyed remedy is asserted **by identity**, not by the
   token `"BACK UP"` — the surface that licenses the recorded silence is pinned
   at the byte level, and the pin is proven non-redundant by a plant whose three
   companion verdicts are green (D160 §2 R8, R9 plant A).

### R11 — What must **not** be touched in this act

*Executed by: everyone.*

1. **Neither refusal's rendered string** — `init.rs:628-635`,
   `error.rs:577-584`. Not one byte (R1).
2. **Neither gate** — `init.rs:417-420`, `vault/export.rs:1208-1223`: not the
   predicate, not the ordering, not the absence of a decode (R5).
3. **The three frozen lines** — `cli-errors.display.txt:14`,
   `json-envelopes.txt:2`, `:20`. This act is **not** a freeze event and no
   re-bless is authorised.
4. **`docs/user/vault-loss.md`, `docs/user/vault-theft.md`** — already correct
   (R4). In particular `vault-loss.md:252`'s byte-quote is current and must stay
   so; the check that it *stays* current is routed, not ruled (§4.2).
5. **`vault_keyfile.rs:750-759`** — the class-blindness equality. Relaxing it is
   overturning R5, and requires a decision.
6. **`docs/decisions/D155-…`** — not amended. Its §4.1 asked a question and this
   record answers it; §4.1's own parenthetical (*"at `init` time and on every
   seal"*) was **correct** and it is the row that departed from it.
7. **`tasks/Q.md` / `Q251`** — no clause. Nothing here diverges from
   MVP-SPEC.md; D155 §3.6's measurement applies unchanged.

---

## 3. What was refused and why

### 3.1 A class-aware post-decode surface at either refusal (the register's lean)

**Refused.** D155 §2 R1's ground stands — arm (a) is strictly additive because a
decode cannot classify `NewerVersion` — and §1.6 adds a second: the shipped
equality assertions at `vault_keyfile.rs:750-759` now forbid it mechanically.
Full disposition at R5.

### 3.2 An unconditional, class-free pointer inside the refusal (the brief's fourth arm)

**Refused — after construction was attempted, not before.** It is the only shape
that clears the equality assertion, and it fails because the fact is class-typed:
every rendering collapses into D155 §3.3, §3.5 or §3.4. Enumerated at §1.7, ruled
at R6.

### 3.3 Writing the route into `docs/user/vault-loss.md` (the row's arm (b))

**Refused as redundant.** Measured, it is already there:
`docs/user/vault-loss.md:182-212`, with `BACKUP_BY_HAND` quoted byte for byte at
`:207`. R4.

### 3.4 Adding the pointer to the *second* branch of `refuse_existing_target`

**Refused, and named so it is not mistaken for the ruled question.**
`vault/export.rs:1214-1221` (*"exists but is not a vault (no vault header
inside) — move it aside before importing"*) is a different message on a
directory that holds no vault, hence no `W` and no keyfile relationship. It is
outside §4.1's question, and D155 §4.4 already routes the D39 residual-risk
divergence that surrounds it.

### 3.5 Making `export_nag`'s wording a new golden snapshot

**Refused; R8 is cheaper and sufficient.** A new snapshot file is a new copy
surface under `COPY_SCAN`, a new blessing procedure, and a new document `U32`
would have to freeze — for a constant already byte-pinned at
`init-report.txt:79` through the sibling producer. What was actually missing is
the **routing** claim (which constant this producer selects), and that is one
identity assertion in a unit test that already asserts two constants that way.

### 3.6 Leaving the silence recorded only in `docs/decisions/`

**Refused, on D155's own ledger finding 3.** A refusal — or a silence — that
binds a future reader belongs where that reader stands. R7 puts one paragraph in
each of the two rustdocs that already cite D155, changing no rendered byte.

### 3.7 Keeping `U88` open as a shrunken row

**Refused.** After R3's correction there is no residue to carry: the question is
answered, the arms are enumerated and closed, arm (b) is shipped, and R8's pin
lands in this act. A row kept open on a `No` is a row that will be re-surveyed
every wave and re-explained every time. It closes, with its reason in the row.

---

## 4. Routed, not ruled

### 4.1 `placement_guidance`'s backup line is pinned by exactly one golden line

`vault/keyfile.rs:294-298` (*"the second half of this vault's backup"*) is
byte-pinned **only** at `tests/snapshots/init-report.txt:68`. Its own unit test
(`vault/keyfile.rs:423-429`) asserts the path, `ANTSEAL_KEYFILE`, and the absence
of `antseal vault export` — never the backup sentence — and
`vault_keyfile.rs:497-500` is an OR over three producers. That is not wrong (the
golden is a real pin) but it is a **single** pin on a surface D160 counts among
the six, and it is asymmetric with surface 2, which has three. Whether it wants
the same routing assertion R8 gives `export_nag` is a small question this record
does not answer, because R8's plant A2 is what measures it and that measurement
has not been run. **Ledger, and a candidate row.**

### 4.2 Nothing verifies that `vault-loss.md`'s byte-quotes still match their source

`docs/user/vault-loss.md:207` quotes `BACKUP_BY_HAND` byte for byte and `:252`
quotes `ImportRefusedExistingVault`'s rendering byte for byte; `:210-212` says so
in the page itself. Measured 2026-08-22, both are current. Measured also: no
check compares them to their sources — `check-copy-style.py` scans `docs/user/`
for **style**, not for quote fidelity, and `check-traceability.py` has no such
check. D155 §1.9 found the neighbouring failure of exactly this kind (`:249`
citing `error.rs:535-542`, which is `NotImplemented`) and fixed the instance
without adding the guard. A generic "quoted block matches its cited source"
checker is larger than this row and touches every user page. **Needs a row.**

### 4.3 The nag's two class-blind constants are identity-pinned and its class-keyed one was not

Recorded as a **shape**, beyond the instance R8 fixes: in a function whose whole
point is that one line is class-keyed, the class-**blind** lines got identity
assertions (`bookkeeping.rs:393-394`) and the class-**keyed** line got a
four-character substring (`:397-400`). The weaker assertion landed on the line
that actually varies. Worth a sweep of the other class-keyed renderings —
`standing_warnings` (`init.rs:377-381`) has the same shape at
`init.rs:829-832` — but a sweep is not this row's. **Ledger, and a candidate row.**

### 4.4 `U88`'s row inverted the record that routed it, and no check could see that

D155 §4.1 wrote *"only `BACKUP_BY_HAND` … ever says so, at `init` time and on
every seal"*; the row minted from it says *"no backup route mentioned anywhere in
`init` or `import`"*. The row was minted by U86's implementing lane on landing,
i.e. by the lane furthest from §4.1's text and closest to the code it had just
changed. `check_decision_owners` (`scripts/check-traceability.py:1486-1530`)
verifies that a row **names** its decision; nothing verifies that it **agrees**
with it. The general check is probably not buildable; the local lesson is.
**Ledger.**

---

## 5. Registrar's edit set

### 5.1 `docs/decisions/README.md`

Insert, in ascending id order:

```
| [D160](D160-keyfile-backup-route-refusal-silence.md) | U88 — where the keyfile class learns its backup route, after U86's honest reword left both existing-vault refusals class-blind. **Recorded silence: no pointer, and the row's premise is false six times over.** The row says *"no backup route mentioned anywhere in `init` or `import`"*; measured, **six** shipped surfaces state the complete two-piece route — `placement_guidance` (`keyfile.rs:294-298`), `BACKUP_BY_HAND` via `standing_warnings` and via `export_nag` **on every seal, perpetually by construction**, the `vault export` refusal itself, and two `docs/user/` pages — and **D155 §4.1 says so in the paragraph that routed the row**. `import` has **no wrapped-class path in either direction** (`export.rs:745-756` out, `:520-536` in), so half the row's scope does not exist. **Arm (b) is MOOT — already shipped** at `vault-loss.md:182-212`. **Arm (a) is now mechanically forbidden**, not merely refused: `vault_keyfile.rs:750-759` requires each refusal to be byte-identical across wrap classes, so the three days since D155 moved the price **against** the arm. The **fourth arm** — an unconditional class-free pointer — is the only shape that clears that assertion and is **not constructible**, because the fact is class-typed: it collapses into D155 §3.3's hedge, §3.5's doc pointer, or §3.4's delete-the-true-part. The arm space closes and the answer is the residue of an enumeration. **The arm nobody listed is where the ruling has teeth**: `export_nag`'s rendering is in **no golden** and its class-keyed remedy was pinned by the four characters `"BACK UP"` while `LOSS_WARNING`/`THEFT_WARNING` beside it are pinned by identity — so the single surface licensing the silence could be hollowed out with a green suite. R8 pins it by identity; R9's plant proves it red **and** proves the golden, the cross-producer test and the sibling producer all stay green, i.e. that the pin is not redundant. Coverage censused by parse: 14 assertion sites in 3 test files + 3 frozen snapshot lines + 1 byte-for-byte doc quote, and the first pass undercounted by 2 | RESOLVED | 2026-08-22 |
```

### 5.2 `TODO.md` — decision register

Add the D160 row in the same wording as §5.1, ticked (`- [x]`), and update the
header's decision figures **by script, never by increment**
(`python3 scripts/check-traceability.py`, flagless — that run *is* the check;
there is no `--check` flag, and `--self-test` stages a full tree copy and is
banned mid-wave).

### 5.3 `TODO.md` — `U88`'s row (`TODO.md:873`)

**Mandatory, not optional.** `check_decision_owners`
(`scripts/check-traceability.py:1486-1530`) reds when an `**Owner: <ID>**`
assignment sits in a **resolved** decision whose owner's row never names it; this
record carries `**Owner: U88**` at §2, so the row must name `D160`.

**(a) Replace the row's headline and problem statement.** The bolded headline
*"The honest reword left one vault class with no backup route mentioned anywhere
in `init` or `import`."* becomes, verbatim:

> **Where the keyfile class learns its backup route at the two class-blind
> existing-vault refusals — answered `no pointer`, and the premise was false.**

and the sentence beginning *"That is honest. It is also **silent**…"* through
*"…now neither is told anything about backing up before they move a directory
aside."* is replaced, verbatim, with:

> That is honest, and the *"silent"* framing this row was minted with is
> **false**: measured 2026-08-22, **six** shipped surfaces state the keyfile
> class's complete two-piece route — `placement_guidance`
> (`vault/keyfile.rs:294-298`), `BACKUP_BY_HAND` (`vault/bookkeeping.rs:96-99`)
> via `standing_warnings` at `init` **and** via `export_nag` **on every seal,
> perpetually by construction**, the `vault export` refusal itself
> (`vault/export.rs:745-756`), and `docs/user/vault-loss.md:182-212` /
> `vault-theft.md:218-224`. D155 §4.1 said so in the paragraph that routed this
> row (*"at `init` time and on every seal"*). `import` has **no wrapped-class
> path in either direction** (`export.rs:745-756` out, `:520-536` in), so half
> this row's stated scope does not exist. The real residue was one
> **invocation**: the gates return before `InitReport::render`, so that run says
> nothing — and at that moment the user has been told to do the thing that needs
> no backup.

**(b) Append before the tick:**

> · **ruled by D160** (2026-08-22): **arm (c), recorded silence** — no pointer in
> either refusal. Not a preference: §4.1's question admits four shapes and all
> four are closed — class-aware by D155 §2 R1 **and now mechanically** by
> `tests/vault_keyfile.rs:750-759` (each refusal must be byte-identical across
> wrap classes), hedge by D155 §3.3, doc/URL by D155 §3.5, and the unconditional
> fourth arm is **not constructible** because the fact is class-typed. **Arm (b)
> is MOOT — already shipped.** The act lands three things: two rustdoc
> paragraphs recording the silence where the next reader stands (D160 §2 R7),
> and **one real pin** — `export_nag`'s class-keyed remedy asserted **by
> identity** (D160 §2 R8), because that rendering is in no golden and was held
> by the four characters `"BACK UP"` while the two class-blind constants beside
> it are held by identity. **No rendered byte changes**, and the three frozen
> lines (`cli-errors.display.txt:14`, `json-envelopes.txt:2`, `:20`) staying
> byte-identical is the verification

**(c) Tick the row** (`- [x]`) once the lane has landed R7 and R8 and reported
R9's four verdicts. **Not before** — R8 is a live test edit, and D141's lesson is
that a *resolved* ruling is not an *executed* one.

**(d) The timing word is unchanged and is ordering, not a gate.** `U88` stays
`· **after U86** · **before U32**`. `before` is **ordering vocabulary**;
collapsing it to `after` would invent a dependency. `U88` closing in this wave
discharges the ordering; it never gated `U32` and `U32` is not edited here.

### 5.4 `tasks/U.md` — `U88`'s entry (`### U88`, `tasks/U.md:1267` onward)

1. **Title** — *"The honest reword leaves one vault class with no backup route
   named anywhere"* becomes *"Where the keyfile class learns its backup route at
   the class-blind existing-vault refusals — ruled: no pointer (D160)"*.
2. **`Problem`** — apply §5.3(a)'s replacement, and correct the two locators the
   entry inherits: `default_keyfile_path` is `init.rs:655-663` (the entry and
   D155 §4.1 both cite `:654-662`; the doc comment is `:648-654`), and
   `standing_warnings` is `init.rs:368-388` with the class-keyed selection at
   `:377-381`.
3. **`Do`** — replace the three-candidate survey with D160 §2 R1's answer and
   §2 R7/R8's two edits, and keep the *"do not re-introduce a command name"*
   sentence: D160 §2 R2 rules it identical to §4.1's *"without naming a
   command"*, not a rival reading.
4. **`Accept`** — apply R10 verbatim: rows 1-2 **MET** with their citations,
   row 3 **inapplicable, not met** with its reason and the standing mechanism,
   row 4 appended.
5. **`Notes`** — replace *"this must land before it or be recorded as
   deliberately unfixed"* with *"it is recorded as **deliberately unfixed**, by
   D160 §2 R1, with the arm space enumerated and closed; `U32` freezes two
   renderings that D160 leaves byte-identical."*
6. **`Deps`** — add *"consumes D155 §4.1 (the question) and D160 (the answer)"*.

### 5.5 What is **NOT** edited

- **`docs/decisions/D155-class-blind-vault-refusal-copy.md`** — not amended.
  §4.1 asked a question and is answered here; its parenthetical was correct and
  the row is what departed from it. Whether D155 gets a cross-reference addendum
  is the registrar's call, on D155 §5.5's own precedent.
- **`docs/user/vault-loss.md`, `docs/user/vault-theft.md`** — already correct
  (R4); the fidelity **check** they lack is routed at §4.2, not built here.
- **`tasks/Q.md` / `Q251`** — no clause (R11 item 7).
- **`TODO.md`'s `U32` row** — untouched. `U88`'s `before U32` is ordering.
- **No rendered string, no snapshot, no `.txt` contract.** This is a planning
  lane; `docs/decisions/D160-keyfile-backup-route-refusal-silence.md` is the only
  file it wrote.

### 5.6 `docs/instrument-ledger.md`

Four findings from this lane, none of them a task:

1. **A row that inverted the record which routed it.** D155 §4.1 wrote *"at
   `init` time and on every seal"*; `U88` was minted saying *"nowhere in `init`
   or `import`"*, by the lane that had just changed the code and was furthest
   from §4.1's text. `check_decision_owners` verifies a row **names** its
   decision; nothing verifies it **agrees** with it. *When a routing note is
   turned into a row, re-read the note at the note, not from the diff you just
   landed.*
2. **The class-keyed line was the weakest-pinned line in the function whose
   point is that it varies.** `bookkeeping.rs:393-394` pins `LOSS_WARNING` and
   `THEFT_WARNING` by identity; `:397-400` pinned the class-keyed remedy by four
   characters, and that rendering is in no golden. The strong assertions landed
   on the constants that cannot vary. §1.9(b), §4.3.
3. **A routed question can be answered by a *closed enumeration*, and that is a
   ruling.** §4.1 admitted four shapes of pointer; three were already refused in
   the parent record's own §3 and the fourth is not constructible. Recorded
   because a "no change" verdict reads as a deferral unless the arm space is
   shown to be exhausted — and because three of the four refusals were **already
   on record and simply had not been indexed against this question**.
4. **A survey's fourth pass found two sites the first three missed.** The
   wording census went 12 → 14 only when the driver set was widened from
   `run_init(...).expect_err` to include process-level tests
   (`init_command.rs:998-999`, inside `fn the_binary_inits_over_a_piped_passphrase`).
   D155 §2 R5 item 2's lesson repeats one level up: *a census scoped by how the
   subject is called misses every caller that calls it another way.*

### 5.7 What the registrar must **NOT** do

Assign ids to §4's routed items from inside this record (they are described, not
numbered); tick `U88` before the implementing lane has landed R7 and R8 and
reported R9's four verdicts; edit any Rust source, snapshot or user page; re-bless
`cli-errors.display.txt` or `json-envelopes.txt` (this act is not a freeze
event); or run `scripts/local-gate.sh` or any `--self-test` while other lanes
hold this tree.
