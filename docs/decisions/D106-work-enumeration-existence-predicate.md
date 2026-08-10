# D106 — U66: what a whole-store scan does with a work that is being created

- **Status: RESOLVED — the defect is not atomicity and not tolerance; it is
  that `WorkStore` holds TWO definitions of "this work exists" and only one
  of them is used to enumerate. The repair is to delete the disagreement in
  `list_works`, in one function, with no new type, no new door, no new error
  variant, no scan and no atomic publish.** The register's lean — *atomic
  publish under a dot-prefixed staging directory **plus** per-row tolerance on
  D100's `SlotMoved` model* — is **overturned in both halves**. The atomicity
  half dies on portability and on a circularity: `std::fs::rename` of a
  directory onto an existing directory is **not portable across the three
  required `cross-os` lanes** (Unix replaces an empty target, Windows refuses
  any existing target), so a uniform `AlreadyExists` needs a pre-check on
  **directory existence** — which is *precisely* the predicate that causes the
  bug. It also fixes the window U66's row does **not** name and leaves the one
  it does. The tolerance half dies on placement: put in `listing.rs` it fixes
  one of **six** production scan sites and, on recon's own `SlotMoved` model,
  would render a row for a thing that has no `work_id`, no title, no state and
  no date, because every column of a `WorkRow` is sourced from the record that
  does not exist yet. **Recon's central claim — that U66 "names a window no
  user can reach" — is right about the window and wrong about the defect's
  reach: there are TWO reachable commands, not one.** `antseal status
  <work-id>` resolves ids through `restore.rs:520-531`, which is the same
  `list_works` → `load_meta` scan, is equally lock-free, and produces the
  identical sentence — so a user who types a valid work id is told **that work
  does not exist**, which is strictly worse than `list`'s version because the
  id was theirs. **Measured on the real binary, not inferred**: five distinct
  on-disk shapes in `store/works/` produce **three** exit codes and the three
  that must be told apart collapse onto one false sentence. The silent-drop
  objection is answered **by construction rather than by policy**: `require_work`
  (`store.rs:748-754`) gates every journal, receipt and anchor write on the
  meta record, so a work directory with no meta and no non-dot content has
  **never held anything** — it is the writer's in-flight intermediate, exactly
  like the dot-prefixed `atomic_write` residue `list_works` already skips one
  line above. And **S38's Accept rests on a root cause that is false**:
  nothing in the antseal codebase removes a work directory, so the failure it
  was written from is a work **appearing**, not vanishing — and implementing
  S38 literally ("skip on `WorkNotFound`") would produce the silent data loss
  D100 R3/R4 forbids.
- **Date: 2026-08-09** (M2 wave 11 planning round; briefed to confirm
  atomicity-plus-tolerance, and both halves are refused)
- **Owning tasks: U66** (the defect; closed by this), **S34** (the same defect,
  recorded second), **S38** (the same defect, recorded third, with a false root
  cause), **U19** (execution note 6, third class), **U5** (the lock's scope
  statement), **S10** (`incomplete_works`' contract)
- **Amends**: `TODO.md` **U66**'s headline claim (replacement text in §2),
  **S34**'s *"Production-safe (read-only listing)"* (§9), `tasks/S.md` **S38**'s
  `Problem` and both `Accept` rows (§9);
  `crates/antseal-cli/src/vault/store.rs:29-34` (*"`list_works` is a readdir"*),
  `:61-66` (*"Readers are safe against a concurrent writer because every write
  is an atomic rename"* — a **per-file** claim being relied on as a
  **multi-file** one), `:474-480` (`list_works`' own doc);
  `crates/antseal-cli/src/pipeline/vault_journal.rs:242-251`'s neighbour
  comment; `tasks/U.md` U19 execution note 6. **Supersedes**: nothing.
  **Binds against**: D100 R1/R3/R4/R5, D42, D45, D47, D51, D99 R3/R6, D26,
  U5, U6, U19 note 2, S10, S11.

---

## The problem, in one sentence

`WorkStore` decides *"this work exists"* by asking whether its `meta` record is
present in three places — `create_work`, `store_meta`, `require_work` — and by
asking whether a 32-hex **directory name** is present in exactly one: the
enumeration every whole-store scan starts from; `create_work` is `create_dir_all`
then `write_meta`, so the two answers differ for the duration of one file write,
and in that interval `antseal list` and `antseal status` both exit 2 saying *"no
work with this id exists in the vault (see `antseal list`)"*.

---

## 1. What was measured

Read at `a68d9ea`. **§1.1 was executed against the real `antseal` binary**
(`target/debug/antseal`, no `ant-backend`), not inferred; everything else is
read at the cited line, and where a task entry or a doc comment disagrees with
the code, the code is recorded as the fact.

### 1.1 Five shapes, three exit codes, one false sentence — measured

A scratch vault (`ANTSEAL_DIR` outside the repo), `antseal init`, then one
entry planted in `store/works/` per row, then `antseal --passphrase-fd 0 list`:

| # | shape planted in `store/works/` | what antseal says today | exit |
| --- | --- | --- | --- |
| **A** | empty directory `00112233445566778899aabbccddeeff` — **`create_work`'s window, and its `SIGKILL` residue** | `usage error: no work with this id exists in the vault (see \`antseal list\`)` | **2** |
| **B** | same directory holding only `.meta.tmp.999.0` — **`atomic_write` mid-flight** | *identical* | **2** |
| **C** | same directory holding `journal/0` and **no `meta`** — out-of-band damage | *identical* | **2** |
| **D** | a **regular file** named `00112233445566778899aabbccddeeff` | `I/O error: work store access at …/works/00…ff/meta: Not a directory (os error 20)` | **4** |
| **E** | a regular file named `not-a-work` | `vault authentication failed: wrong passphrase, or the vault store or header has been modified or corrupted` | **12** |

Three findings fall straight out.

1. **A, B and C are indistinguishable, and the message is false for all
   three.** For A and B nothing is wrong at all. For C the work demonstrably
   exists on disk — the sentence denies the one thing the filesystem proves.
2. **`list` tells the user to run `list`.** And it names a seal id in neither
   mode, so the user cannot even find the entry the message is about.
3. **The radius is the whole vault, in both modes.** `--json` on shape A emits
   `{"command":"list","error":{"class":"usage","exit_code":2,…},"ok":false,…}`
   with **no `works` array at all** — the D100 §1.1 blast-radius shape, one
   error class over.

Shape **D** is a hole nobody had recorded: `parse_hex32` (`store.rs:1076-1087`)
tests only the *name*, so a hex-named regular file is admitted as a work, and
the error that follows leaks an absolute in-vault path at `ErrorClass::Io`.
`alien_entries_in_the_works_dir_are_loud` (`tests/work_store.rs:617-637`) plants
shape **E** and has never covered **D**, so `list_works`' own promise —
*"a corrupted or hand-edited store is loud, never skipped silently"*
(`store.rs:479-480`) — holds only for names that fail `parse_hex32`. §4 R2 makes
it hold for all of them, and it is **load-bearing for the ruling's safety**, not
a bonus: without it, "no meta and no content ⇒ skip" would silently swallow a
hex-named file.

### 1.2 The two definitions, and which one is the outlier

| site | predicate for *"this work exists"* | where |
| --- | --- | --- |
| `create_work`'s `AlreadyExists` guard | `meta_path(seal_id).exists()` | `store.rs:367-370` |
| `store_meta`'s guard | `meta_path(&record.seal_id).exists()` | `store.rs:389-391` |
| `require_work` — gates `put_journal_entry`, `put_receipt`, `put_anchor` | `meta_path(seal_id).exists()` | `store.rs:748-754`; callers `:530`, `:632`, `:677` |
| **`list_works`** | **a 32-hex directory name** | **`store.rs:501-502`** |

Three to one. **`list_works` is the outlier, and the repair is to make it agree
— not to bolt a second mechanism onto the disagreement.** `create_work`'s two
steps are only a *torn window* because two definitions exist; with one
definition there is no window, because `meta`'s arrival is a single `rename`
(`fs.rs:50-52`) and `rename` is atomic.

### 1.3 The invariant that makes the skip safe — enforced in code, today

`require_work` is `meta_path().exists()`, and it gates **every** write that can
put content inside a work directory: `put_journal_entry` (`:530`), `put_receipt`
(`:632`), `put_anchor` (`:677`). `write_meta` is the only write that does not
need it, and it *is* the meta record. Therefore:

> **A work directory can acquire a `journal/`, an `anchors/` or a `receipt`
> only after its `meta` record exists.**

Consequences, and they are the whole safety argument:

- **no `meta` + no non-dot content** ⟹ `create_work` in flight, or the residue
  of one killed between `create_dir_all` and `write_meta`. It has **never held
  a byte of anything**. There is nothing to drop.
- **no `meta` + non-dot content** ⟹ the `meta` record was removed **out of
  band**. That is genuine damage and must stay loud (R3).

This is why the silent-drop objection is answered by construction. It is not a
policy that damage will be marked; it is a structural impossibility that the
skipped population contains data.

### 1.4 Nothing removes a work — so the race is APPEARANCE, not disappearance

Grepped over `crates/antseal-cli/src/`: the only removals are `atomic_write`'s
own temp cleanup (`fs.rs:89`, `:123`), test-fixture `Drop` guards, `import`'s
temp-tree cleanup (`export.rs:1167`, `:1177`, `:1180`), and
`WorkStore::delete_journal_entry` (`store.rs:609-616`), which removes **one
journal entry file**. **No production path removes a work directory.** S11's
abandonment is a state transition plus staged-blob deletion (`resume.rs:29-34`,
`:305-307`), never a removal.

So the only way `list_works` can name an id that `load_meta` then refuses is a
work that has **just appeared**. §9 rules what that does to S38.

### 1.5 The reachable blast radius is TWO commands, and recon found one

Six production `list_works() → load_meta()` scans exist:

| scan | command | lock | reachable today? |
| --- | --- | --- | --- |
| `listing.rs:491-492` | **`list`** | **none** (`commands.rs:316-323`, deliberate) | **YES — measured, §1.1** |
| `restore.rs:524-525` (`resolve_work_id`) | **`status <work-id>`** (`commands.rs:369`), `restore` | **none** (`commands.rs:342-350`, deliberate) | **YES — measured, §1.1** |
| `seal_resume.rs:147-148` (`gather_candidates`) | `seal` / resume detection | **held** (`commands.rs:224-225`) | no live race; residue only |
| `export.rs:765-766` | `vault export` | **held** (`commands.rs:435-436`) | no live race; residue only |
| `export.rs:1243` | `import`'s post-install verify | private temp tree | no |
| `upgrade_hook.rs:375-397` | the U24 hook | polls unlocked | **already tolerant** — `Err ⇒ pass.excluded += 1` |

The `status` row is the one recon missed and it is the sharper of the two.
`resolve_work_id` scans **every** work looking for a `work_id`, in ascending
seal-id byte order (`store.rs:511`), and a single mid-`begin` directory sorting
before the user's work aborts the scan. The user typed a valid 64-hex work id
and is told *"no work with this id exists in the vault (see `antseal list`)"* —
and `list` is the other command that is broken. Measured at §1.1.

`upgrade_hook.rs:385-397` is the in-tree precedent recon cited, and it is
genuine: it already treats a per-work `load_meta` failure as `pass.excluded +=
1` with a `debug` line, under D99 R6. But note what it proves — the hook
tolerates because it is *opportunistic*, and it tolerates **every** `load_meta`
failure including real corruption. That is right for a hook and wrong for a
renderer, which is why R3 splits the two populations instead of copying the
hook.

### 1.6 What the tree says about concurrent processes — and the one false sentence

**MVP-SPEC.md says nothing.** It contains no "lock", "lockfile", "single-writer"
or "concurrent". U5's own note records the lock as *"inferred hygiene"*
(`tasks/U.md:79`). So *"is running two antseal processes on one vault
supported?"* has **no product answer**, and §3.5 rules what follows from that.

What does exist:

| statement | where |
| --- | --- |
| *"a single-writer lockfile prevents concurrent `antseal` processes from **corrupting the journal**"* | `tasks/U.md:73` (U5 `Do`) |
| *"second concurrent invocation fails fast with a clear lock-held message"* | `tasks/U.md:76` (U5 `Accept`) |
| exit **15** `vault-lock-held`, *"another antseal process … **retry when it finishes**"* | `error.rs:25`, `:484-489` |
| *"the vault lock is taken before the passphrase (**a second antseal mid-seal** should not first ask for a secret)"* | `commands.rs:200-204` |
| `list` / `status`: *"deliberately **not** under the U5 single-writer lock … The cost is that a listing taken during a seal may show that work mid-transition — **which is exactly what it is**"* | `commands.rs:316-323`, `:342-350` |
| **`"Readers are safe against a concurrent writer because every write is an atomic rename."`** | **`store.rs:65-66`** |
| *"Two antseal processes upgrading the same work could lose one write … **flagged as assumed**"* | `D97:485-490` |

**`store.rs:65-66` is the load-bearing false sentence in this whole area, and
it is false in a precise and instructive way: it is a *per-file* guarantee
offered as a *per-work* one.** Every individual write is old-or-new. A
*work* is many files, and no primitive in the tree makes a set of them appear
together (`fs.rs`: one file is the atomicity unit; there is no multi-file
transaction). U66, S34 and S38 are three recordings of that one gap. R6 rewrites
the sentence.

### 1.7 U66's row names one window; the failures are the other one

`begin` (`vault_journal.rs:114-140`) is two writes, and they open **two**
windows, not one:

- **W1 — `create_work`'s `create_dir_all` → `write_meta`** (`store.rs:372-376`).
  Directory without meta. Symptom: `StoreError::WorkNotFound` → `CliError::Usage`,
  exit **2**.
- **W2 — `create_work` → `put_journal_entry(STATE_ENTRY)`** (`vault_journal.rs:133`
  → `:137-138`). Meta without fine state tag. Symptom, *in `incomplete_works`
  only*: `state()` finds no `STATE_ENTRY`, `load_meta` succeeds, and it returns
  `Err(corrupt("work has no journal state record"))` (`vault_journal.rs:242-251`).

**U66's row describes W2. Every observed failure is W1.** S34 records
*"(`seal_journal::incomplete_works_are_enumerable_with_their_state`,
**`WorkNotFound`**)"*; S38 records *"the gate's failure is exactly that —
`enumerate: **WorkNotFound**`"*. `WorkNotFound` is W1's symptom; W2's is
`Corrupt`. The row attributed the observed red to the wrong write.

And recon is right that W2 reaches no user: production reads the fine tag
through `recorded_state` (`journal.rs:1075-1083`), which maps an absent
`STATE_ENTRY` to `Ok(None)` — U19 note 2's *"absent is a state, not a failure"*,
pinned by `a_work_without_its_fine_state_record_still_lists`
(`tests/list_command.rs:450-477`). `incomplete_works` is the **only** reader
that refuses it, and its four callers are all integration tests
(`seal_journal.rs:673`, `seal_pipeline.rs:565`, `anchor_gate_prepay.rs:252`,
`seal_matrix.rs:356`; the `incomplete_works` identifiers in `seal_resume.rs` are
an unrelated struct field). Verified independently.

Both windows must be closed. Closing W1 alone leaves the red test red — which
is the concrete reason the lean's `listing.rs`-only tolerance would not have
made the gate green either.

### 1.8 `state()` must stay hard, and that is why the fix is not there

`SealJournal::state`'s other production callers are `set_state`
(`vault_journal.rs:219`) and `pipeline/resume.rs:139`, `:261`, `:501` — the seal
pipeline, which runs **under the U5 lock**. A state machine that cannot read the
current state must not advance. So the repair goes into `incomplete_works`, not
into `state()` (R4).

---

## 2. Correcting U66's row

**What it got wrong.** (i) It names W2 and cites `vault_journal.rs:245-250`,
while every observed red is W1's `WorkNotFound`. (ii) It says *"a `list`, a
`status` or a resume … can be told the vault is **corrupt**"* — via
`incomplete_works`, which no production path calls; the true diagnosis is
`CliError::Usage` at exit **2**, not `VaultAuthFailure` at 12. (iii) It calls
the defect *"`VaultJournal::begin` is two non-atomic writes"*, which locates it
in the writer; it is in the reader's **definition of a work**, and `begin`'s
first write would be atomic already if the two definitions agreed. (iv) Its only
evidence is a load-based reproduction that did not reproduce on re-attempt
(27/27 green under 3 concurrent binaries and 2 CPU burners) — inherited from
recon, not re-run here; §7 replaces it with three deterministic instruments.

**What the defect actually is.** The exact replacement text for the row's
headline claim:

> **The work store has two definitions of an existing work, and `antseal list`
> and `antseal status` die on the difference.** `create_work`, `store_meta` and
> `require_work` define existence as *the `meta` record is present*
> (`store.rs:367-370`, `:389-391`, `:748-754`), and `require_work` gates every
> journal, receipt and anchor write. `list_works` alone defines it as *a 32-hex
> directory name exists* (`store.rs:501-502`). `create_work` is
> `create_dir_all` then `write_meta` (`store.rs:372-376`), so between them the
> two predicates disagree, and every whole-store scan —`listing.rs:491-492`
> (`list`), `restore.rs:524-525` (`status <work-id>`, `restore`),
> `seal_resume.rs:147-148`, `export.rs:765-766`, `vault_journal.rs:325` — reads
> the directory and then fails `load_meta` with `WorkNotFound`. **Measured on
> the real binary 2026-08-09**: with one empty 32-hex directory planted in
> `store/works/`, `antseal list` and `antseal status <work-id>` both exit **2**
> with *"usage error: no work with this id exists in the vault (see `antseal
> list`)"* — `list` telling the user to run `list`, and `status` denying the
> work id the user typed — and `list --json` emits an error envelope with **no
> `works` array at all**. Two lock-free commands, whole-vault radius.
> `begin`'s second window (meta written, `STATE_ENTRY` not yet) is real but
> reaches **no production caller** — `recorded_state` maps an absent state
> record to `Ok(None)`, U19 note 2 — and reaches only `incomplete_works`,
> whose four callers are all integration tests. That is the window this row
> named; it is not the window the observed reds are. **S34 and S38 are the same
> defect recorded twice more**; S38's stated root cause (a work removed
> mid-scan) is false — nothing in the codebase removes a work — D106 §9.

---

## 3. The options, and what kills each

### (a) Atomic publish in `create_work` — the lean's first half. Four kills.

Stage the work directory under a dot-prefixed name inside `works_dir`, write
`meta` into it, fsync, `std::fs::rename` into place.

**K1 — it is not portable, and Windows is a required lane.**
`.github/workflows/ci.yml:228-241` runs `cross-os` on `ubuntu-latest`,
`macos-latest` and `windows-latest`, `fail-fast: false`. `rename(2)` on
directories replaces an **empty** target on POSIX and fails `ENOTEMPTY` on a
non-empty one; Rust's Windows `fs::rename` is `MoveFileExW(…,
MOVEFILE_REPLACE_EXISTING)`, and that flag **cannot be used when either path
names a directory** — so an existing target fails there whatever it contains.
The `AlreadyExists` contract would therefore differ across three required
lanes. This is the exact class of defect that reddened `wasm32-core-tests` two
commits ago (`873a1cf`, a pointer-width assumption written as a universal).

**K2 — and the portable form is circular.** To get one `AlreadyExists` answer
on all three platforms you must pre-check that the target is absent — which is
what `import_vault` does (`refuse_existing_target(target)` immediately before
`std::fs::rename`, `export.rs:1173-1185`), and it is portable **only because
the target is guaranteed not to exist**. Doing that in `create_work` replaces
`meta.exists()` with `dir.exists()` — i.e. it *adopts the very predicate that
causes this bug* as the store's definition of existence, in the change meant to
fix it.

**K3 — it fixes the window U66's row does not name and leaves the one it
does.** An atomic `create_work` closes W1 and leaves W2 untouched, because
`begin` is `create_work` **then** `put_journal_entry(STATE_ENTRY)`. Closing W2
atomically means `create_work` taking S10's initial state bytes — coupling
`WorkStore` to the journal's entry-key namespace, breaking `import_vault`
(which installs an arbitrary entry set, `export.rs:1133-1139`) — or a
multi-file transaction primitive, which does not exist (`fs.rs`: one file is
the atomicity unit).

**K4 — its most important caller already has it, one level up.**
`import_vault` builds the whole vault under `temp_root` and publishes it with a
single `rename` onto an absent path (`export.rs:1173-1185`). Per-work staging
inside a tree that is itself invisible until one rename is dead weight. That is
the strongest single fact against (a): the one caller for whom a torn-free
publish genuinely matters solved it at the right layer, and the right layer is
not `create_work`.

**What (a) genuinely buys, recorded honestly**: it would remove the residue
class entirely (a killed `create_work` would leave a dot-prefixed directory
`list_works` already skips) rather than leaving an inert empty directory
forever. R7 records this as the one live residual and its trigger.

### (b) Tolerance in `listing.rs::gather` alone — the lean's second half. Three kills.

**K5 — one of six.** It fixes `list` and leaves `status <work-id>` broken with
the identical sentence (§1.5), plus the residue case in `gather_candidates` and
`export`, plus `incomplete_works`.

**K6 — on the `SlotMoved` model it must render a row it cannot build.** D100
R1's `SlotMoved` renders a line because *information was lost*: the slot
existed and this read could not have it. Here **nothing was lost** — the work
has never existed. And `WorkRow`'s every column (`work_id`, `title`,
`sealed_at_unix_secs`, `network`, `state`, `unanchored`, `degraded`,
`cost_atto`) is sourced from the record that is not there
(`listing.rs:524-540`), and `state: WorkState` is not an `Option`. A row would
have to be invented, and it would make `antseal list --json` non-deterministic
under concurrency for a row carrying no actionable field.

**K7 — it leaves the defect's home intact.** The next scan added anywhere in
the tree inherits it. Six sites is already the count; a per-caller fix is a
standing invitation to a seventh.

### (c) (a) + (b) — the lean. Inherits K1–K7 and pays a scan.

Under (c) `list_works` still returns ids that are not works, so the tolerance
half is still needed at every caller; and the atomicity half still cannot be
written portably. It also acquires the residual D100 R2 had to close with an
S36-shaped scan — a second door that a seventh caller can take without being a
reporter.

### (d) A two-door `WorkScan` mirroring U65 — considered, and refused on cost

`scan_works()` returning `{ works, unreadable }` with a `require_complete()`
hard door, restricted by an S36-shaped scan. It is the shape D100 R2 landed and
it is defensible. **Refused**: it mints a type, a door, a scan, and (for the
hard door's refusal) a `StoreError` variant with no non-passphrase `CliError`
to map onto — all to distinguish a population (§1.1 shape C) whose *current*
handling this ruling leaves **unchanged and correct-in-radius**, and whose bad
sentence is already D100 §9(i)'s registered family. Machinery is not free in a
tree that measures its own field-addition tax (U63).

### (e) Make `list` take a shared lock, or declare single-process — refused, §3.5

### (f) Delete the disagreement in `list_works` — **the ruling**

---

## 3.5 The product question: is concurrency supported?

This is the question everything else turns on, and it has **no product
answer**: MVP-SPEC.md never mentions the lock or concurrent processes, and U5's
own note calls the lockfile *"inferred hygiene"* (`tasks/U.md:79`).

**Ruling: it is supported, and the tree has already decided so four times
without saying it once.** The evidence is behavioural, not aspirational:

1. Exit code **15** exists and its message is *"retry when it finishes"*
   (`error.rs:484-489`) — an instruction that presumes a second process is
   normal.
2. `seal` takes the lock **before** the passphrase specifically so *"a second
   antseal mid-seal should not first ask for a secret"* (`commands.rs:200-204`).
3. `list` and `status` are **deliberately** lock-free so the diagnostic command
   does not fail behind a running seal (`commands.rs:316-323`, `:342-350`).
4. D99 R3 makes the hook poll unlocked and decline silently on contention,
   *"because holding it for a calendar round-trip would block every concurrent
   `seal`"*.
5. D100 R1 mints a user-visible sentence — *"another antseal may be running"* —
   and ships it (`listing.rs:823-824`, `status.rs:1062-1063`).

**Making `list` take the lock is refused.** `VaultLock::acquire` is a
**try-lock** (`vault/lock.rs:93-118`; D99:82 measured it, and Q117 records that
`list`'s own doc comment misdescribes the harm as *hanging* when it is
*failing*). So a locked `list` would not wait during a seal — it would exit
**15**, turning a false exit 2 into a systematic exit 15 for the entire duration
of every seal. That is strictly worse: it converts an occasional
microsecond-wide false error into a guaranteed multi-minute one.

**Declaring single-process is refused** for the same reason plus a stronger
one: the ruling is not a mitigation of concurrency, it is the removal of a
self-contradiction that is a defect **even single-process**. Shapes A and B in
§1.1 are `SIGKILL` residue, and a vault that has survived one killed `seal` is
permanently unlistable until the user finds and deletes an empty directory they
cannot see mentioned in the error.

**One product statement is owed, and it is one sentence** (R6): the U5 lock
serialises **writers**; readers run unlocked and see a consistent *record*
because every write is one atomic rename, but **not** a consistent *work*,
because a work is many records and nothing makes a set of them appear together.
That sentence is the honest replacement for `store.rs:65-66` and it is what a
future reader needs in order not to record U66 a fourth time.

---

## 4. Ruling

**`WorkStore::list_works` adopts the store's own existence predicate. A
directory entry in `works_dir` whose name parses as a seal id is enumerated as
a work if and only if (i) it is a directory and (ii) its `meta` record is
present **or** it holds at least one non-dot entry. Everything else about the
function is unchanged: its name, its signature, its ascending order, its
zero-decryption property, and its loudness on an alien name. Separately,
`SealJournal::incomplete_works` stops asking `state()` — whose refusal must stay
hard for the state machine — and reads the fine tag through `recorded_state`,
falling back to U9's coarse mirror exactly as `list` has done since
`a_work_without_its_fine_state_record_still_lists`. No atomic publish. No new
door, type, error variant, `ErrorClass` or source scan. No `listing.rs` change
at all.**

What carries it, in one line: **`create_work` is only "two writes" because two
definitions of a work exist; with one definition it is one write —
`meta`'s `rename` — and every other file in a work directory is already gated
on that write by `require_work`.**

And what makes it safe rather than merely kinder: the population the skip
removes is provably empty of data (§1.3), and the population that carries data
reaches exactly the code it reaches today.

### R1 — the skip, and why it is not a silent drop

A work directory with no `meta` and no non-dot entry is skipped **silently, and
rendered as nothing**, on four grounds:

1. **It is not a work.** The store's own writer says so three times (§1.2).
   `create_work` will happily create it again — its `AlreadyExists` guard is on
   `meta`, so nothing about the ruling changes what a re-run of the same seal id
   does.
2. **It has never held data** (§1.3, `require_work`). D100 R3/R4's *"visibly
   marked, never silently dropped"* is a rule about **works**; the skipped set
   contains none.
3. **The precedent is four lines above it.** `list_works` already skips
   dot-prefixed entries as *"inert atomic-write residue … expected and skipped"*
   (`store.rs:497-500`). Shape B in §1.1 **is** that residue, one directory
   level down, and shape A is the directory that was created to hold it. Same
   class, same treatment.
4. **A row is unbuildable** (K6), and a count is unactionable — by the time it
   printed, the work either exists or was killed, so the number is stale and it
   would make every `list` snapshot racy.

U19 execution note 6's rule — *"a damaged work may not pretend to be healthy"* —
is preserved exactly: nothing is rendered as healthy, because nothing is
rendered.

### R2 — the directory check, which is required rather than incidental

An entry whose name parses as a seal id but which is **not a directory** is
`StoreError::AlienEntry`. Two reasons, and the first is a safety obligation of
R1 itself:

- Without it, a hex-named regular file has no `meta` child and no content, so
  R1's rule would **skip it silently** — a new silent drop introduced by the fix.
- It closes §1.1 shape D, where today a hex-named file produces a raw `ENOTDIR`
  at `ErrorClass::Io` that leaks an absolute in-vault path, and makes
  `list_works`' documented promise (*"loud, never skipped silently"*) true for
  every entry rather than only for names that fail `parse_hex32`.

Symlinks are covered by the same line: `DirEntry::file_type` does not follow
them, the store never creates one, so a symlink in `works_dir` is a hand-edited
store and is alien. Say so in the doc comment.

### R3 — the damage case keeps today's behaviour, deliberately, and it is recorded

A directory with no `meta` **and** non-dot content is still enumerated, so
`load_meta` still fails and the caller behaves exactly as it does today
(§1.1 shape C: exit 2, *"no work with this id exists"*). **This is a scope
decision, not an oversight**, and the argument is the same one D100 R5 used to
keep the meta and plan records out of its own ruling — *they are the machinery
of a work rather than evidence about it*. Two things make it defensible:

1. **The change is a strict improvement in diagnosis quality even though the
   sentence does not move.** Today the false-positive population (A, B) and the
   real-damage population (C) are indistinguishable at that error. After, every
   occurrence of it is real damage. A wrong sentence that fires only on the
   right input is a smaller defect than the same sentence firing on a healthy
   vault.
2. Its repair is D100 §9(i)'s family — *"the meta and plan records have U65's
   defect"* — which **has never been given a task row** (§12). D106 does not
   silently inherit it; it names it.

### R4 — `incomplete_works`, and why `state()` is not touched

`incomplete_works` (`vault_journal.rs:323-332`) becomes:

```rust
fn incomplete_works(&self) -> Result<Vec<(SealId, Option<SealState>)>, JournalError> {
    let mut out = Vec::new();
    for seal_id in self.store.list_works()? {
        // The fine tag when it is there; its absence is a state, not a
        // failure (U19 note 2 / `recorded_state`) — and because `begin` is
        // two writes, the absence is *expected* under a concurrent seal.
        let fine = recorded_state(&self.store, &seal_id)?;
        let incomplete = match fine {
            Some(state) => state.is_incomplete(),
            // No fine tag: U9's coarse mirror carries it, which is the
            // fallback `list` has had since
            // `a_work_without_its_fine_state_record_still_lists`.
            None => matches!(
                self.store.load_meta(&seal_id)?.state,
                WorkState::IncompletePrePay | WorkState::IncompletePostPay
            ),
        };
        if incomplete {
            out.push((seal_id, fine));
        }
    }
    Ok(out)
}
```

Four points, each load-bearing:

1. **The fine tag is preferred when present**, so behaviour outside W2 is
   byte-identical to today — in particular a work mid-`set_state` (fine written,
   coarse mirror one barrier stale, `vault_journal.rs:229-232`) is still
   classified by the fine tag, and `!incomplete.any(done)` cannot start
   flapping.
2. **`Option<SealState>` is the honest return**, and it is the shape production
   already uses: `ResumeCandidate::journal_state` is exactly
   `recorded_state(...)`, an `Option` (`seal_resume.rs:167`).
3. **`state()` is NOT changed.** Its other callers are `set_state` and the seal
   pipeline (`resume.rs:139`, `:261`, `:501`), all under the U5 lock; a state
   machine that cannot read the current state must not advance. Its `corrupt(…)`
   for an *absent* record stays, and gains a comment saying why the enumeration
   no longer shares it.
4. It deletes the last production spelling of `JournalError::Corrupt` applied to
   a record that is **absent** — the third overload D100 §1.2 found at
   `status.rs:859` and R6 removed.

### R5 — where tolerance does **not** live

- **Not in `listing.rs`.** It is one of six callers (K5), and `gather` needs no
  edit at all under the ruling.
- **Not in a two-door API.** §3(d). U65's `intact_and_damaged` pattern applies
  where a *reporter* and an *evidence consumer* need different answers about the
  same object. Here every caller wants the same answer — *the works* — and only
  `list_works` was giving a different one.
- **Not in `gather_candidates` or `export_vault`.** Both hold the U5 lock, so
  neither can meet a live W1, and both have a completeness obligation that must
  **not** be softened: `seal_resume.rs:139-141` states it outright — *"a damaged
  vault is reported, never softened into a shorter candidate list — a silently
  dropped candidate is exactly the failure that makes a user pay twice"* — and
  `vault export` silently omitting a work is a backup that loses it. Under the
  ruling they keep that obligation for free, because the only thing removed
  from their input is a directory that has never held a byte.

  **This is the reason the ruling is placed in `list_works` and not in the
  callers**: the one call site whose safety property forbids softening is the
  one that most needs the enumeration corrected, and correcting the *definition*
  serves it while softening the *caller* would break it.

### R6 — the sentence the tree owes itself

`store.rs:61-66` becomes, in substance:

> Mutating APIs assume the caller holds the single-writer `VaultLock` (U5). A
> reader running unlocked sees each **record** whole — every write is one
> atomic rename — but **not each work whole**: a work is several records and
> nothing publishes a set of them together. Enumeration is therefore defined by
> the same predicate the writers use, the `meta` record (`create_work`,
> `store_meta`, `require_work`), so that a work under construction is simply not
> yet a work rather than a half-visible one. D106.

`store.rs:29-34`'s *"`list_works` is a readdir — zero decryption"* becomes *"a
readdir plus one `stat` per entry — zero decryption"*, and `list_works`' own doc
(`:474-480`) gains R1's and R2's rules.

### R7 — the residual the ruling deliberately keeps

A `create_work` killed between `create_dir_all` and `write_meta` leaves an empty
directory in `works_dir` **forever**; nothing cleans it up, and after the ruling
nothing reports it either. That is the honest price of refusing (a), which would
have left a dot-prefixed staging directory instead. It is invisible, inert,
costs one inode, and is skipped at the same cost as a dot-file.
**Trigger to revisit:** any report of `works_dir` accumulating entries, or the
arrival of a `vault fsck`-class command, which is where sweeping it belongs.

---

## 5. The torn windows, ruled one at a time

Recon enumerated W1–W6. Two more exist and are added.

| # | window | ruling |
| --- | --- | --- |
| **W1** | `create_work`: `create_dir_all` → `write_meta` (`store.rs:372-376`) | **Closed by definition-agreement** (R1). Not made atomic: K1–K4. |
| **W2** | `begin`: `create_work` → `put_journal_entry(STATE_ENTRY)` (`vault_journal.rs:133`→`:137`) | **Tolerated** (R4). Production already tolerates it (`recorded_state` → `Ok(None)`, pinned at `list_command.rs:450`); only `incomplete_works` refused. Not made atomic: it would put S10's entry namespace inside `WorkStore` and break `import_vault`'s arbitrary entry set. |
| **W3** | `put_journal_entry`: `require_work` → `create_dir_all(journal/)` → `atomic_write` (`store.rs:530-543`) | **Left, and the reason is recorded.** An empty `journal/` is indistinguishable from an absent one at **every** reader: `list_journal_entries` maps `NotFound` → `Ok(vec![])` and an empty dir → `Ok(vec![])` (`store.rs:571-599`); `get_journal_entry` is path-specific and maps absence to `Ok(None)`. **No reachable defect.** Write the invariant into the doc so a future reader that hard-fails on an empty `journal/` is a knowing choice. |
| **W4** | `set_state`: fine tag → coarse mirror (`vault_journal.rs:229-239`) | **Left — deliberate and already documented**: *"a crash between them leaves the mirror one barrier stale, which no safety rule reads — whereas the reverse could show a work as paid before its receipt-bearing state record exists."* R4 preserves it by preferring the fine tag whenever present. |
| **W5** | `put_anchor`: `require_work` → `create_dir_all(anchors/)` → `atomic_write` (`store.rs:677-688`) | **Left.** Same shape as W3 — `list_anchors` maps both `NotFound` and empty to `Ok(vec![])` (`store.rs:719-746`). The slot-level race above it is already ruled: D100 R1 `SlotMoved`, shipped. |
| **W6** | `resume.rs:493` `put_receipt` → `:501-503` `set_state(Paid)` | **Left — deliberate crash-safety ordering, under the U5 lock**, with a compare-and-set-shaped guard (`if !state.is_post_pay()`). It is a **crash** window, not a concurrency window: `seal` is the only writer and it holds the lock. A concurrent reader between them sees a receipt on a pre-pay work, which `list` renders honestly. |
| **W7** *(new)* | `import_vault`'s per-work `create_work` + N `put_journal_entry` + `put_receipt` + M `put_anchor` (`export.rs:1131-1148`) | **Already closed one level up** — the whole tree is built under `temp_root` and published by one `rename` onto a target re-checked absent (`export.rs:1173-1185`). This is K4: the caller that most needs per-work atomicity has vault-level atomicity instead, which is strictly stronger. Nothing to do. |
| **W8** *(new)* | `update_meta`'s read-modify-write (`vault_journal.rs:101-110`) | **Left, and it is D97's flagged residual, not D106's**: *"Two antseal processes upgrading the same work could lose one write … flagged as assumed"* (`D97:485-490`). Per-file it is torn-free; the lost update is a **writer-vs-writer** hazard and the U5 lock is its mitigation. D106 changes nothing about it. |

**A repair that closes `begin` and leaves `create_work` torn for `import` would
be partial**, and the ruling does not have that shape: it changes the *reader's
definition*, so W1 is closed identically for `begin`, for `import_vault`
(`export.rs:1133`) and for the fixture at `export.rs:1387`, with **no change to
`create_work` at all** and therefore no change to any caller's `AlreadyExists`
semantics. Recon's question — *"if atomicity lands in `create_work` it changes
all callers; if only in `begin`, `create_work` keeps a torn window for
everyone else"* — is dissolved rather than answered: the fix is at the one place
all of them are read.

**On `AlreadyExists`, explicitly**: it is untouched. `create_work` keeps
`meta.exists()` (`store.rs:367-370`) as its guard, so the exact condition that
returns `StoreError::AlreadyExists` before the change returns it after, on all
three OSes, with no `rename` and no `ENOTEMPTY`/`MOVEFILE_REPLACE_EXISTING`
divergence to reason about.

---

## 6. Edit set

Precise enough to implement without further judgement. **Two production files.**

### `crates/antseal-cli/src/vault/store.rs`

1. **`list_works` (`:481-512`)** — inside the loop, after the dot-prefix
   `continue` (`:497-500`) and after `parse_hex32` succeeds (`:501-502`):
   - **(R2)** `let file_type = entry.file_type().map_err(|source| StoreError::Io { path: dir.clone(), source })?;` and if `!file_type.is_dir()`, return
     `StoreError::AlienEntry { detail: format!("work-shaped entry {name:?} in the work store is not a directory") }`.
     Keep the existing `AlienEntry` arm for a name that does not parse.
   - **(R1)** if `!self.meta_path(&id).exists()`, then read the entry's own
     directory and `continue` when it holds no non-dot entry; otherwise
     `ids.push(id)` as today. A read error other than `NotFound` is
     `StoreError::Io`; `NotFound` (the directory vanished between readdir and
     this read) is treated as empty and skipped.
   - New private helper beside `require_work`, e.g.
     `fn work_dir_has_content(&self, dir: &Path) -> Result<bool, StoreError>`.
2. **Doc comments** — `:474-480` (`list_works`) gains R1's and R2's rules and
   the reason the predicate is `meta` and not the directory name, citing
   `create_work`/`store_meta`/`require_work` by line; `:29-34` *"is a readdir —
   zero decryption"* → *"a readdir plus one `stat` per entry — zero
   decryption"*; `:61-66` → R6's sentence.
3. **`require_work` (`:748-754`)** — gains one line of doc naming itself as the
   invariant `list_works` now relies on: content cannot exist before `meta`.
   No behaviour change.

### `crates/antseal-cli/src/pipeline/vault_journal.rs`

4. **`incomplete_works` (`:323-332`)** — R4's body. Return type
   `Result<Vec<(SealId, Option<SealState>)>, JournalError>`. Add
   `use crate::pipeline::journal::recorded_state;` and `WorkState` to the
   imports if not already present.
5. **`state` (`:242-251`)** — **no behaviour change**; add a comment recording
   that the enumeration no longer shares this refusal and why this one stays
   hard (R4 point 3).

### `crates/antseal-cli/src/pipeline/journal.rs`

6. **The `SealJournal` trait method (`:952`)** — signature and doc updated to
   `Option<SealState>`, stating that an absent fine tag is a state and that the
   coarse mirror decides membership. `VaultJournal` is the only impl
   (grepped).

### Tests that must change mechanically (no assertion text moves)

7. `crates/antseal-cli/tests/seal_journal.rs:673-687` — `(live,
   SealState::Anchored)` → `(live, Some(SealState::Anchored))`; the two
   `!any(|(id, _)| …)` rows are unchanged.
8. `crates/antseal-cli/tests/seal_pipeline.rs:565`,
   `crates/antseal-cli/tests/anchor_gate_prepay.rs:252`,
   `crates/antseal-cli/tests/seal_matrix.rs:356` — the same tuple change at
   whatever they destructure.

### New tests

9. §7's five rows, in `tests/work_store.rs`, `tests/list_command.rs`,
   `tests/status_command.rs` and `tests/seal_journal.rs`.

### Prose and task entries (orchestrator applies at source)

10. `TODO.md` **U66** — headline claim replaced with §2's block; closed by this
    decision.
11. `TODO.md` **S34** — closed with U66; *"Production-safe (read-only
    listing)"* struck and replaced (§9).
12. `tasks/S.md` **S38** (`:511-522`) — `Problem` root cause corrected and both
    `Accept` rows replaced (§9); `TODO.md:327`'s summary likewise.
13. `tasks/U.md` **U19 execution note 6** — append the third class: *"D106: a
    directory that is not yet a work is neither an enumeration failure nor a
    per-record one. It is the writer's intermediate, and `list_works` now uses
    the store's own existence predicate so it never becomes either."*
14. `docs/decisions/README.md` — the index row at the foot of this file.

**Explicitly NOT edited**: `crates/antseal-cli/src/listing.rs`,
`crates/antseal-cli/src/status.rs`, `crates/antseal-cli/src/seal_resume.rs`,
`crates/antseal-cli/src/vault/export.rs`, `crates/antseal-cli/src/upgrade_hook.rs`,
`crates/antseal-cli/src/pipeline/restore.rs`, `crates/antseal-cli/src/error.rs`,
`crates/antseal-cli/src/vault/fs.rs`, `crates/antseal-cli/src/commands.rs`. No
`ErrorClass`, no exit code, no `--json` key, no snapshot.

---

## 7. Instruments

Red-before-green, deterministic, no threads and no load. The intermediate state
is **constructed on disk directly**, which is legitimate here for the reason
`tests/work_store.rs:612-616` already gives for the alien test: a store-wide
plant *"in the shared one would race the parallel tests' enumerations"*.
Every new row therefore uses a private or `IsolatedVault` root.

| # | test | file | red before | green after |
| --- | --- | --- | --- | --- |
| **I1** | `a_work_directory_without_its_meta_record_is_not_yet_a_work` | `tests/work_store.rs` (private vault, the `alien_entries_…` pattern) | create one real work; `create_dir_all(works_dir/"00".repeat(16))`; `list_works()` returns **both** ids → `assert!(!ids.contains(&planted))` **fails today** | returns exactly the real id; the real work still round-trips through `load_meta` |
| **I2** | `a_work_directory_holding_records_without_its_meta_is_still_enumerated` | same | **does not redden — named so a green suite is not mistaken for coverage.** Plants `<hex>/journal/0` with arbitrary bytes and no `meta`, asserts `list_works()` **contains** it and that `load_meta` still errors. It is the anti-vacuity pin on R3: without it, R1 could be widened to "skip whenever `meta` is absent" and nothing would go red | unchanged |
| **I3** | `a_work_shaped_entry_that_is_not_a_directory_is_loud` | same | plants a **regular file** named 32-hex; today `list_works()` succeeds and the caller dies later with `ErrorClass::Io` *"Not a directory (os error 20)"* leaking an absolute path → `expect_err` + `matches!(err, StoreError::AlienEntry { .. })` **fails today** | `AlienEntry`, `ErrorClass::VaultAuthFailure`, no path in the message |
| **I4** | `a_work_being_created_right_now_does_not_break_the_listing` | `tests/list_command.rs` (`fixture_vault()`, an `IsolatedVault`) | plant an empty `works_dir/"00".repeat(16)`; `WorkListing::gather` returns `Err(CliError::Usage { message })` with `message == "no work with this id exists in the vault (see \`antseal list\`)"` — assert that verbatim today | `gather` succeeds; `works.len()` equals the fixture count; the rendered lines and the `--json` document contain no row for the planted id |
| **I5** | `a_concurrent_begin_does_not_make_status_deny_a_work_that_exists` | `tests/status_command.rs` (already `IsolatedVault`, already imports `WorkListing` for Q120's matrix) | plant `works_dir/"00".repeat(16)` — **all-zero, so it sorts first** under `list_works`' ascending byte order (`store.rs:511`), which is what makes this deterministic rather than racy — then `resolve_work_id(&store, &printed_work_id)` for a real work: `Err(RestoreError::WorkNotFound)` today | `Ok(real_seal_id)`; and `WorkStatus::gather` on it renders the same work `list` shows, extending Q120's cross-command matrix by one predicate |
| **I6** | `a_work_begun_but_not_yet_state_tagged_is_in_progress_not_corrupt` | `tests/seal_journal.rs`, in a **private** vault (not `shared_vault()`) | `journal.begin(&identity(id))`, then `store.delete_journal_entry(&id, STATE_ENTRY)` — which reconstructs W2's exact on-disk state deterministically — then `journal.incomplete_works()`: `Err` today, `JournalError::Corrupt { detail: "work has no journal state record" }` | `Ok`, containing `(id, None)`, filtered in by U9's coarse mirror |

**Two rows that must stay green and be named** (D100 R10.3's discipline):
`alien_entries_in_the_works_dir_are_loud` (`work_store.rs:617`) and
`enumeration_never_touches_journal_bodies` (`work_store.rs:487-533`, which
asserts `ids.contains(&id)` for a work whose *bodies* are garbage but whose
`meta` is intact — the ruling must not touch it).

### The four shared-vault scanning tests: they STAY, and that is a ruling

The brief asks whether `incomplete_works_are_enumerable_with_their_state` and
its three siblings must move off the `OnceLock` shared vault
(`seal_journal.rs:70-87`; the duplicate at `tests/common/mod.rs:100-116` feeds
`seal_pipeline.rs`, `anchor_gate_prepay.rs` and `seal_matrix.rs`). **They must
not, and S38's Accept row asking for it is overturned.**

1. **Their assertions are membership-only** over ids they own
   (`contains(&(live, …))`, `!any(|(id, _)| *id == done)`), so a neighbour's
   work appearing or disappearing in the result set cannot make them wrong.
   What made them fail was the scan **erroring**, not the scan's contents.
2. **After the ruling they are the tree's only witness that the scan is total
   under real concurrent mutation.** 27 tests run in parallel against one vault
   while `begin`, `set_state` and `put_anchor` execute; that is a property test
   nobody wrote and it costs nothing. Moving them to isolated vaults would
   convert a load-dependent red into a **permanently green vacuum** — exactly
   the *"vacuous, not red"* failure D100 R10.2 names, and A104's lesson (*a
   planted fault passed green in a brand-new suite until the row was widened*).
3. **A red there becomes diagnostic rather than noise.** After W1 and W2 are
   both closed there is no remaining window for them to hit, so a future red on
   those four means the totality property broke — which is information worth
   more than a quiet suite.

**Required with that ruling**: `incomplete_works_are_enumerable_with_their_state`
gains a docstring recording (a) that it is deliberately on the shared vault,
(b) that it is the tree's only concurrent whole-store-scan witness, and (c) that
a failure there means `list_works`/`incomplete_works` stopped being total, not
that the test is flaky — so the next lane does not "fix" it by isolating it.
The *new* rows (I1–I6) go in private roots, because they **plant** state and a
plant does race siblings.

---

## 8. What this does not do

- **It does not make any write atomic.** `create_work` is still two syscalls,
  `begin` is still two writes, `put_journal_entry` still creates `journal/`
  before filling it. §5 rules each; the ruling changes what a *reader* considers
  a work, not what a writer does.
- **It does not touch `create_work`, `store_meta`, `require_work` or
  `AlreadyExists`.** No caller of `create_work` — `begin`, `import_vault`
  (`export.rs:1133`), the fixture at `export.rs:1387`, or the twelve test sites
   — changes behaviour.
- **It does not fix the sentence a genuinely damaged work produces.** A work
  directory holding records with its `meta` record deleted still refuses `list`
  and `status` for the whole vault with *"no work with this id exists"* (§1.1
  shape C). R3 records why, and §12(i) names the follow-up.
- **It does not fix `AlienEntry` accusing the passphrase** (§1.1 shape E, exit
  12). That is D100 §9(ii), still unregistered (§12).
- **It does not give `list` a lock, and does not declare antseal
  single-process** (§3.5).
- **It does not mint an `ErrorClass`, move an exit code, add a `--json` key, or
  change a snapshot.**
- **It does not touch `listing.rs` or `status.rs`.** D100's damage rendering is
  untouched and its `SlotMoved` reason keeps exactly its current meaning: an
  **anchor slot** that moved. It is not extended to works.
- **It does not settle whether `incomplete_works` should exist.** It duplicates
  `seal_resume::gather_candidates`, has zero production callers, and the two
  disagreed about an absent fine tag until now. §12(iv).
- **It does not verify the U5 lock's own guarantees.** D97's flagged
  writer-vs-writer residual (`D97:485-490`) is untouched.
- **It ran no `cargo` command.** §1.1 was executed against the pre-built
  `target/debug/antseal`; nothing here was compiled or tested. The implementing
  lane confirms that the `Option<SealState>` change touches exactly the four
  integration call sites in §6 items 7–8 and no production code, and measures
  the added `stat` cost against D26 if any budget names `list` (none was found).

---

## 9. S34 and S38

**Both close with U66. Neither is distinct.**

**S34** (`TODO.md:325`) is W1, correctly identified in shape — *"an enumeration
interleaving with a starting seal can miss or half-see a work"* — and correctly
attributed to the missing lock. Its one wrong clause is load-bearing and must be
struck: **"Production-safe (read-only listing) but test-visible" is false.** Two
production commands are broken, measured at §1.1, and one of them denies a work
id the user typed. It is the only sentence in the tree ruling the lock-free read
path safe, it is unargued, and it is why the defect sat for seven days across
three recordings. **Evidence it needs**: I1 and I4 (`list`), I5 (`status`).

**S38** (`tasks/S.md:511-522`) is the same defect, and **its Accept rests on a
false root cause. Plainly: nothing in the antseal codebase removes a work
directory** (§1.4). S38's `Problem` says *"a work removed between the listing
and its state read"*, *"a user deleting one"*, and cites *"S11's abandon path
[as] the precedent for treating it as ordinary"* — but S11 abandons by writing a
state, not by deleting, and `delete_journal_entry` removes a single entry file.
**The corrected root cause**: `list_works` enumerates a work directory *before
its `meta` record exists*, because the store's enumeration predicate (a 32-hex
directory name) disagrees with the store's own existence predicate (the `meta`
record), which `create_work`, `store_meta` and `require_work` all use. The race
is a work **appearing**, not vanishing.

The correction is not cosmetic. **S38's Accept row would produce a
silent-data-loss bug if implemented literally.** *"Removing a work concurrently
with `incomplete_works()` yields a listing without it, never an error"* directs
the implementer to skip on any `WorkNotFound` — which swallows §1.1 shape C, a
work whose `meta` was deleted while its journal, receipt and anchors remain.
That is the exact D100 R3/R4 violation the brief asks about, and it arrives
*through the task entry*, not through carelessness. Replacement Accept rows:

- *An empty (or dot-only) work directory planted in `works_dir` is absent from
  `list_works()`, and `antseal list` and `antseal status <work-id>` both
  succeed with it present — asserted by constructing the directory, not by
  hoping for a race.*
- *A work directory holding records with no `meta` record is **still**
  enumerated and still refused, asserted in the same file, so the skip cannot be
  widened into a silent drop.*
- *A work-shaped entry that is not a directory is `AlienEntry`.*

S38's second Accept clause — *"give the test binary either a per-test vault or
an enumeration-safe fixture"* — is **overturned** by §7's last subsection, with
its reason recorded there.

---

## 10. Kill criteria

This record is wrong, and must be reopened, if any of these is measured:

1. **A production path is found that removes a work directory.** §1.4's grep is
   the basis for calling the race an appearance race and for refusing S38's
   framing; a removal path reopens the disappearance case and R1's skip would
   then need a second justification.
2. **A write into a work directory is found that does not go through
   `require_work`.** §1.3's invariant is the whole silent-drop argument. Any new
   `WorkStore` method that writes under `work_dir` without it breaks the ruling
   and must add the guard or the guard's equivalent.
3. **`DirEntry::file_type` is found to be materially expensive on a supported
   filesystem**, or a vault is measured where the added `stat` per work is a
   meaningful fraction of `list`. (Each work already costs one open + read +
   AEAD open in `load_meta`, so the expected marginal cost is under 1 %.)
4. **A released build ships before this lands.** Then §1.1 shapes A and B are a
   permanent unlistable-vault condition for anyone whose `seal` was ever killed,
   and the priority changes rather than the ruling.
5. **`std::fs::rename` of a directory onto an empty directory is found to be
   uniform across the three `cross-os` lanes.** K1 weakens; K2, K3 and K4 stand,
   so (a) is still refused, but the record must not stand claiming a portability
   fact that is not one.
6. **A second impl of `SealJournal` appears.** R4's return-type change is priced
   at one impl and four test call sites.

---

## 11. Discovered work — named, not registered

*(No IDs are minted here. Each is described so the wave owner can allocate.)*

**(i) A work whose `meta` record is absent while its records remain.** — M2 · S
· deps: D106 R3, D100 §9(i). `list` and `status` refuse the whole vault with
*"no work with this id exists"* for a work the filesystem proves exists (§1.1
shape C). This is D100 §9(i)'s family — *"the meta and plan records have U65's
defect"* — and **that item was never given a task row** (grepped: the U domain
tops out at U66 and none of D100's five discovered items appear in `TODO.md`).
Accept: either the work renders as a marked-damaged row, or the reason it must
refuse is recorded at `listing.rs` with the care D100 §1.9 applied to
`list_works`.

**(ii) D100 §9's five discovered items were never registered.** — M2 · XS.
Items (i)–(v) of `D100:924-968` are cited in prose and in `TODO.md:732`'s index
row and exist nowhere as rows. Q85's rule says a row can exist with no
`tasks/*.md` entry and nothing notices; this is the mirror — a decision's
discovered work with no row at all. Registering them is a bookkeeping action,
but item (i) above is blocked on it.

**(iii) `store.rs:65-66`'s reader-safety claim is the third recording's root
cause.** — M2 · XS · deps: D106 R6. Fixed by R6's sentence in the same change;
registered separately only if the orchestrator wants the audit of every other
place the tree states a concurrency guarantee it has not measured (`D97:485-490`
self-flags one; `TODO.md:325` asserts another).

**(iv) `incomplete_works` duplicates `seal_resume::gather_candidates`.** — M2 ·
S · deps: D106 R4, S10, D45. Two enumerations of the resume-candidate set, one
with zero production callers, which disagreed about an absent fine tag until
this ruling. Decide whether the trait method survives `resume`'s arrival or is
deleted with its four test call sites re-pointed at `gather_candidates`. Not
taken here because deleting a red test in the change that was supposed to make
it pass reads as hiding it, whatever the argument.

**(v) `works_dir` accumulates empty directories forever.** — M3 · XS · deps:
D106 R7. Nothing sweeps a killed `create_work`'s residue. Belongs to a
`vault fsck`-class command, which does not exist.

**(vi) `list` and `status`' lock rationale still names the wrong harm.** —
already **Q117**, open (`TODO.md:545`): the doc comments say *hangs*;
`VaultLock::acquire` is a try-lock, so it would *fail with exit 15*. §3.5 relies
on the corrected fact and the comments still carry the wrong one.

---

## 12. Open for the maintainer

**One item, and it is the product statement, not the code.**

§3.5 rules that concurrent antseal processes on one vault are a **supported
configuration**, and derives that from five behaviours the tree already has
rather than from any statement of intent. MVP-SPEC.md is silent — it never
mentions the lock, and U5 calls the lockfile *"inferred hygiene"*. The code
ruling in §4 stands either way, because §1.1 shapes A and B are reachable
single-process from any killed `seal`. What needs a human decision is whether
the supported-configuration statement is **written down**, and where:

- **(1) One sentence in MVP-SPEC.md's Vault section** (lines 141–145), beside
  the existing durability language: readers run unlocked and are safe; writers
  serialise on the lock; a second writer fails fast at exit 15. Cost: a spec
  edit, and MVP-SPEC.md is the authoritative document — an edit to it is a
  maintainer act, not a planner's.
- **(2) Nowhere in the spec; the sentence lives at `store.rs:61-66`** (R6) and
  in U5's entry only. Cost: the next lane rediscovers the question, as three
  lanes have.
- **(3) Declare single-process and make the read commands take the lock.**
  Refused on evidence in §3.5 (a try-lock turns an occasional false exit 2 into
  a guaranteed exit 15 for the whole duration of every seal), but it is the
  maintainer's to overrule.

**Recommendation: (1).** The behaviour is already shipped in five places
including a user-visible sentence (*"another antseal may be running"*), and a
shipped guarantee that the spec does not state is how `store.rs:65-66` came to
assert something false with nobody positioned to catch it. R6's in-code sentence
lands with the fix regardless; only the spec line waits on this call.

---

## Outcome

**RESOLVED, 2026-08-09.** The lean is overturned in both halves. The defect is
not that `begin` is two non-atomic writes; it is that `WorkStore` holds **two
definitions of an existing work** and enumerates by the one its three writers do
not use. Atomicity is refused on four grounds, the sharpest being that a
portable directory `rename` needs a pre-check on **directory existence** —
adopting, inside the fix, the predicate that causes the bug — with Windows a
required `cross-os` lane and `import_vault` already publishing atomically one
level up. Per-caller tolerance is refused because it fixes one of **six** scans
and, on the `SlotMoved` model, would render a row whose every column comes from
the record that does not exist. Recon's *"a window no user can reach"* is right
about the window and wrong about the reach: **two commands are broken, not one**
— `antseal status <work-id>` resolves through the same scan, equally lock-free,
and denies the id the user typed. Measured on the real binary: five on-disk
shapes, three exit codes, and the three that must be distinguished collapsing
onto one false sentence — including `list` telling the user to run `list`. The
silent-drop objection is closed **by construction**: `require_work` gates every
journal, receipt and anchor write on the `meta` record, so a work directory with
no meta and no non-dot content has never held a byte, and skipping it is the
same act as skipping the `atomic_write` residue four lines above. The repair is
one predicate in one function, plus `incomplete_works` reading the fine tag the
way production already does; two production files, no new type, door, error
variant, class, exit code, JSON key or scan. **S34 and S38 close with it**, and
S38's Accept — built on the false premise that something removes a work — would
have produced the silent data loss D100 R3/R4 forbids. The four shared-vault
scanning tests **stay where they are**, because after the fix they are the
tree's only witness that a whole-store scan is total under real concurrency, and
isolating them would trade a load-dependent red for a permanently green vacuum.

---

## Index row (orchestrator applies at merge)

| [D106](D106-work-enumeration-existence-predicate.md) | U66 — what a whole-store scan does with a work that is being created — **the defect is neither atomicity nor tolerance: `WorkStore` holds TWO definitions of an existing work and enumerates by the wrong one.** `create_work`, `store_meta` and `require_work` all define existence as *the `meta` record is present* (`store.rs:367-370`, `:389-391`, `:748-754`); `list_works` alone defines it as *a 32-hex directory name* (`:501-502`), and `create_work` is `create_dir_all` then `write_meta`. **Both halves of the lean are overturned.** Atomicity dies on four kills, the sharpest being **circularity**: `std::fs::rename` of a directory onto an existing directory is not portable (POSIX replaces an empty target; Windows `MOVEFILE_REPLACE_EXISTING` cannot name a directory at all) and **Windows is a required `cross-os` lane**, so a uniform `AlreadyExists` needs a pre-check on *directory existence* — the very predicate that causes the bug — while `import_vault` already publishes atomically **one level up** (`export.rs:1173-1185`), and an atomic `create_work` would fix the window U66's row does **not** name and leave the one it does. Per-caller tolerance dies on placement: it fixes **one of six** production scans, and on D100's `SlotMoved` model would render a row whose every `WorkRow` column comes from the record that does not exist. **Recon's "a window no user can reach" is right about the window and wrong about the reach: TWO commands are broken.** `antseal status <work-id>` resolves ids through `restore.rs:520-531` — the same `list_works`→`load_meta` scan, equally lock-free — so a user who types a valid work id is told *that work does not exist*. **Measured on the real binary**: five on-disk shapes in `store/works/` produce **three** exit codes, and the three that must be told apart (mid-`create_work`, `atomic_write` residue, and a genuinely meta-less work) collapse onto one sentence — *"no work with this id exists in the vault (see `antseal list`)"*, exit 2, `list` telling the user to run `list`, `--json` emitting **no `works` array at all**. A fourth shape nobody had recorded: a **regular file** named 32-hex passes `parse_hex32` and leaks an absolute in-vault path at `ErrorClass::Io`, so `list_works`' *"loud, never skipped silently"* has only ever held for names that fail the parse. **The silent-drop dilemma is dissolved by construction, not by policy**: `require_work` gates every journal, receipt and anchor write on the `meta` record, so a work directory with no meta and no non-dot content has **never held a byte** — it is the writer's intermediate, and skipping it is the same act as skipping the dot-prefixed `atomic_write` residue four lines above (`store.rs:497-500`). **Ruling**: `list_works` adopts the store's own predicate — enumerate iff the entry is a directory **and** (`meta` present **or** non-dot content present) — and `incomplete_works` stops asking `state()` (whose refusal must stay hard for the state machine) and reads the fine tag through `recorded_state` with U9's coarse mirror as the fallback `list` has had since `a_work_without_its_fine_state_record_still_lists`. Two production files; **no atomic publish, no new type, door, error variant, `ErrorClass`, exit code, JSON key, snapshot or source scan**, and `listing.rs` is not touched. **U66's row named the wrong window** — it describes `begin`'s meta→`STATE_ENTRY` gap while every observed red is `WorkNotFound` from the mkdir→meta gap — and its evidence, a load-based reproduction, did not reproduce; replaced by six deterministic instruments that construct the state on disk. **S34 and S38 close with it**: S34's *"Production-safe (read-only listing)"* is false and is the sentence that let this sit across three recordings, and **S38's root cause is false — nothing in the codebase removes a work directory**, so the race is a work *appearing*; implementing S38's Accept literally ("skip on `WorkNotFound`") would produce exactly the silent data loss D100 R3/R4 forbids. **The four shared-vault whole-store scanning tests STAY**, overturning S38's second Accept: after the fix they are the tree's only witness that a store-wide scan is total under real concurrent mutation, and isolating them trades a load-dependent red for a permanently green vacuum (D100 R10.2, A104). Also corrected: `store.rs:65-66`'s *"Readers are safe against a concurrent writer because every write is an atomic rename"* is a **per-file** guarantee offered as a **per-work** one, and is the root cause of all three recordings. Concurrency is ruled a **supported configuration** — derived from five shipped behaviours, since MVP-SPEC.md never mentions the lock and U5 calls it *"inferred hygiene"* — and a locked `list` is refused because `VaultLock::acquire` is a **try-lock** (Q117), so it would exit **15** for the whole duration of every seal rather than wait. Six items discovered, including that **D100 §9's five discovered items were never registered as rows at all** | RESOLVED (U66/S34/S38 execute) | 2026-08-09 |
