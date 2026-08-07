# D100 — What `list` and `status` do with an anchor record they cannot decode

- **Status: RESOLVED — the refusal stops being an ERROR and becomes a DATUM,
  and no new `ErrorClass` is minted.** `StoredAnchors::read` collects the slots
  it cannot decode instead of aborting; the artifact accessors move behind a
  type no caller can reach without having been handed the damage; `list` and
  `status` render it; `reveal` keeps whole-failure and gets it as one explicit
  line at the caller instead of as a side effect of the reader. **`list` exits
  0.** The register's lean — (d) = per-work isolation *plus* a new error class
  — is **overturned in half and inverted in the other half**. The error-class
  half dies on a measurement recon did not take: `status` already renders the
  *identical* user-visible damage one layer down — an `.ots` whose bytes do not
  parse renders `invalid` (D98's own cross-walk) — and it does so at **exit
  0**. A new class would put exit 0 and exit N on two sides of a boundary the
  user cannot see, that carries no difference in severity, and that D98 froze
  the vocabulary across. And recon's option (c) — per-record isolation inside
  the reader, which it recommended REFUSING — is the load-bearing half: its
  stated grounds are **measurably false for `status`**, **vacuous for the
  hook**, and **unmeasurable for `reveal`**, which does not exist. The sharpest
  finding is not in `list` at all: **`list` and `status` already disagree, in
  production, about the same vault state.** A work holding anchors with no
  journaled manifest renders as a soft *"anchors: unclassified"* row at exit 0
  under `list` (`listing.rs:616-619`) and exits **12 accusing the passphrase**
  under `status` (`status.rs:856-863`) — two lanes, days apart, each documenting
  its own answer as obviously correct. The "fail whole" rule therefore has no
  single authority to defend; it has two contradictory ones.
- **Date: 2026-08-07** (M2 wave 9 planning round)
- **Owning tasks: U65** (the defect), **A102** (the same missing class one layer
  down), **A103** (`NagState::name()`), **U19** (execution note 6), **U25** (the
  nag column), **U47** (the reader), **U23** (`status`), **U24** (the hook),
  **U63** (`WorkRow`'s field-addition tax)
- **Amends**: `tasks/U.md` U19 execution note 6 and U65's Accept row;
  `tasks/A.md` **A102's Accept row** (its literal word *"nags"* is overturned)
  and A103's ordering claim; the doc comment at
  `crates/antseal-cli/src/pipeline/anchors.rs:526-531` (*"A decode failure fails
  the whole read"*); `crates/antseal-cli/src/listing.rs:357-362` and `:371-375`;
  `crates/antseal-cli/src/status.rs:276-279` and `:844-847`; **D97 §2 K1** by
  rider (not by amendment — see §5). **Supersedes**: nothing. **Binds
  against**: D42, D51, D53 §4, D56 §6, D97, D98, D99 R6, U2, U6, U20 note 2.

---

## The problem, in one sentence

`StoredAnchors::read` refuses the whole read when one slot will not decode, and
`JournalError::Corrupt` collapses into `CliError::VaultAuthFailure` — so one
damaged slot in one work makes `list` refuse the **entire vault** with the
sentence *"wrong passphrase, or the vault store or header has been modified or
corrupted"*, for a CBOR schema refusal on plaintext the AEAD already accepted.

---

## 1. What was measured

Everything below was read from the tree at `09a81c2`. Nothing is inferred from
prose, and where a task entry or a doc comment disagrees with the code, **the
code is recorded as the fact**. No `cargo` command was run (§7).

### 1.1 The failure path — confirmed, and one count corrected

| Fact | Where |
| --- | --- |
| `list` aborts before it can render: `WorkListing::gather(...)?` | `commands.rs:330` |
| `gather`'s third read is the nag, propagated unsoftened | `listing.rs:376-377` |
| which calls the shared reader | `listing.rs:603` → `pipeline/anchors.rs:555-565` |
| which decodes each slot and propagates | `anchors.rs:561` (`AnchorArtifact::decode`) |
| `JournalError::Corrupt { detail }` carries a `&'static str`, documented *"Failure-class summary — never record bytes"* | `journal.rs:598-602` |
| and the mapping **throws `detail` away** | `journal.rs:688` (`JournalError::Corrupt { .. } => CliError::VaultAuthFailure`) |
| producing exit **12** and the sentence | `error.rs:460-464`; `error.rs:327` |
| Blast radius is the whole vault in **both** modes: plain prints `error: …` on stderr, `--json` prints one error envelope on stdout and no `works` array at all | `lib.rs:106-112` (`fail`) |

**Recon's "five `corrupt(...)` producers" is wrong.** Measured: **twelve**
textual `corrupt(` call sites in `pipeline/anchors.rs` (`:261`, `:265`, `:281`,
`:291`, `:292`, `:301`, `:306`, `:307`, `:308`, `:560`, `:576`, `:583`), and
`:281` is a three-way branch, so **fourteen distinct detail strings** — plus
`codec()`'s *"journal record is not canonical CBOR"* (`journal.rs:1023`) reached
from every `.map_err(codec)` inside `decode`, plus `open_envelope`'s two
(`journal.rs:1046`, `:1050`). Every one of them lands on the same sentence about
the passphrase. The count matters because §4 R5 has to classify them, and a
five-item list would have left nine unrouted.

### 1.2 The two rules the tree already has, and they contradict each other

This is the finding that changes the shape of the question. **The same vault
state — a work holding anchor artifacts whose interpretation cannot be
recovered — is handled in opposite ways by two commands, in production, today:**

| Command | Code | Behaviour | Exit |
| --- | --- | --- | --- |
| `list` | `listing.rs:616-619` | returns `Ok(None)` → row renders with *"anchors: unclassified — this work holds anchor artifacts but its journaled manifest is gone, so what they attest to cannot be recovered"* | **0** |
| `status` | `status.rs:856-863` | returns `JournalError::Corrupt { detail: "this work holds anchor artifacts but no journaled manifest…" }` | **12**, *"wrong passphrase"* |

Each documents itself as obviously right. `listing.rs:247-254`:

> *"`list` renders it as unclassified rather than guessing a class or failing
> the whole listing, **because a listing that refuses to run is the one thing a
> user on a damaged vault cannot work around.**"*

`status.rs:844-847`:

> *"A work *with* anchors and no manifest is an inconsistency this reader
> **refuses rather than papers over**."*

Both are committed, both are landed, both are tested
(`tests/list_command.rs:839` `a_work_whose_manifest_record_is_gone_lists_as_unclassified`),
and neither cites the other. So the premise the brief inherited — that a
"fail whole" rule holds, backed by three doc comments plus U19 execution
note 6 — is **half of a standing disagreement**, not a rule. Whatever D100
decides, it cannot decide `list` alone without leaving the divergence in place.

Note also that `status.rs:859` reaches for `JournalError::Corrupt` to describe a
record that is **absent**, not corrupt. That is a third overload of the class,
in the same twenty lines.

### 1.3 `status` already renders this damage at exit 0, one layer down

The kill for the error-class half of the lean.

| Fact | Where |
| --- | --- |
| `.ots` bytes that do not parse against the work's `anchor_digest` produce `AnchorVerdict::invalid` with a diagnostic code | `verdicts.rs:694-707` |
| D98 binds A15's `Unreadable` to exactly that verdict: *"`invalid` \| yes \| yes \| T1/T2 / O1–O2; **A15's `Unreadable` is the same call**"* | `D98…md`, §"The exact state vocabulary `status` emits" |
| The `status` handler returns `Ok(Outcome { .. })` unconditionally after `gather` — **there is no verdict → exit-code branch anywhere in it** | `commands.rs:390-402` |
| A landed test renders `invalid` / `anchor-der-malformed` in the committed snapshot | `tests/status_command.rs:421`; `tests/snapshots/status-report.txt:30-33` |

So today, for the same user on the same work:

- the `.ots` **bytes** are garbage → `status` prints `invalid`, **exit 0**;
- the CBOR **record** holding those bytes is garbage → `status` prints nothing,
  **exit 12**, *"wrong passphrase"*.

One layer of wrapping apart, and the exit codes are 0 and 12. No severity
difference exists between them: in both cases the work holds an anchor that
proves nothing, and in both cases the user's next step is identical.

### 1.4 The verdict vocabulary is frozen, and the kind is unknowable

| Fact | Where |
| --- | --- |
| `verdicts.rs` is *"the one place that puts an artifact into exactly one of the **seven frozen states**"* | `verdicts.rs:8` |
| `absent` is one of the seven and is **never an outcome** — *"a statement about a **kind** with no artifact, which `status` knows from its own enumeration and must print explicitly or not at all"* | `D98…md`, §"The exact state vocabulary" |
| The artifact's `kind` lives at **key 0 inside the record** | `anchors.rs:199`, `:291-292` |

Consequence, and it is decisive for §2: a damaged record cannot be rendered as
an eighth `AnchorState` (frozen), and it cannot be rendered as one of the seven
either, because **no verdict can be stated without naming a mechanism, and the
mechanism is inside the record that will not open**. A slot *name* gives a
family (`SlotFamily::parse`, `anchors.rs:488-494`) — but `anchors.rs:576` proves
the name itself can be outside both families. So the damage is not evidence
about a mechanism; it is a fact about the vault, and it belongs in its own
datum in both renderers.

### 1.5 The split point is the AEAD, and nothing observable crosses it

The security question, because U6's merge is a committed rule and
`error.rs:458-459` states it: *"bad passphrase, AAD-detected tamper, and corrupt
store share one code **insofar as distinguishing them is safe**."*

| Fact | Where |
| --- | --- |
| A genuine AEAD failure is `CipherError::AuthFailure` → `CliError::VaultAuthFailure` **directly**, never through `JournalError` | `cipher.rs:219-226` |
| A structurally-short blob collapses with it, by name (*"U6 insofar as safe"*) | `cipher.rs:222-225` |
| Every `corrupt(…)` in `pipeline/anchors.rs` runs on **plaintext `get_anchor` already returned** | `anchors.rs:558-561` |

So the two populations do not share a producer. An unauthenticated caller
**cannot reach** the schema-refusal branch at all: it lies behind Argon2id, the
header, and a per-record AEAD open with slot-bound AAD (`cipher.rs:119-125`).
Distinguishing it therefore leaks nothing to anyone who has not already
demonstrated the passphrase, which is exactly the scope of U6's *"insofar as
safe"*. **The merge buys nothing on the far side of authentication and costs a
sentence that is provably false there.**

Two committed precedents already draw this line, and both are in the exit-code
table's own module docs:

- **code 18, `vault-keyfile-missing`** — *"the keyfile factor is absent,
  unreadable or the wrong size — **NEVER the generic auth failure**"*
  (`error.rs` module docs), with `vault/keyfile.rs:356` asserting
  `assert_ne!(err.class(), ErrorClass::VaultAuthFailure)`;
- **code 19, `vault-wrap-mode-unsupported`** — *"the header names a
  **registered wrap mode this build does not implement**"*. That is structurally
  the same refusal as `ArtifactKind::from_wire`'s tag 2, and it was given its
  own class rather than 12.

### 1.6 The exit-code table, measured

| Fact | Where |
| --- | --- |
| 28 classes; codes 1–4, 10–27, 30–35 | `error.rs:286-315`, `:319-…`; `tests/exit_codes.rs:36-95` |
| 40–49 reserved for U30's bundle verdicts, asserted | `tests/exit_codes.rs:114-135` |
| Codes must be nonzero, distinct, `< 125`, asserted | same |
| **The vault band 12–19 is contiguous and FULL** | computed from the table |
| Free codes below 40: **5–9, 28, 29, 36–39** — none adjacent to 12 | computed |
| **U20 note 2 already ruled that numeric adjacency does not matter**: severity is *"an explicit `Ord`, never a comparison of numeric exit codes — which is what lets S14's `restore-verification-failed` live at 35 while U30's 40–49 band stays reserved"* | `tasks/U.md` U20 note 2; `error.rs` module docs |
| The table is length-pinned at 28 in three tests plus a snapshot | `tests/exit_codes.rs:46`, `:100`, `:399`, `:475`; `snapshots/cli-errors.display.txt:31-32` |

So recon's worry is answered in both directions: a new class would **not**
collide with 40–49 (the test would catch it) and would **not** be blocked by
U20 note 2 (which is the authority saying a non-adjacent code is fine). It
would simply cost four committed edits — and under the ruling it costs zero,
because none is minted.

### 1.7 `NagState`: no compile-time forcing where it matters

| Fact | Where |
| --- | --- |
| `NagState` is **not** `#[non_exhaustive]`; four variants | `ots/engine.rs:607-622` |
| `WorkRow::nag_name` is the **only** wildcard-free `match`, deliberately: *"written wildcard-free so a fifth state fails compilation at this line instead of acquiring a wrong name in a `_` arm"* | `listing.rs:288-301` |
| `NagState::nags` is `matches!(self, Self::OnlyPendingOts)` — **a fifth variant compiles silently and defaults to "does not nag"** | `ots/engine.rs:627-629` |
| `work_status`'s classifier is an **if/else chain, not a `match`** — a fifth variant needs a branch added by hand, with **no compiler help at all** | `ots/engine.rs:660-668` |
| `each_nag_class_has_its_own_name` enumerates a **hand-written five-element array**, so a sixth entry does not redden it — it silently under-covers | `listing.rs:1085-1107` |
| `PendingWork` is not `#[non_exhaustive]`: **2** production construction sites (`listing.rs:649`, `status.rs:705`) and 11 in the engine's test module | grep over `crates/` |
| `WorkRow` is not `#[non_exhaustive]`: **4** construction sites (`listing.rs:398`, `listing.rs:1144`, `tests/machine_mode.rs:724` and `:739`) — U63's tax, paid a third time | grep over `crates/` |

This corrects recon's premise directly. **A103 does not make a fifth variant
safe**, because the compile error that forces a name already exists at
`listing.rs:293-301` with or without A103, and because the thing A103 gives you
is a *name*, not a *producer*. Nothing in the tree forces the fifth variant to
ever be constructed: the classifier is an `if`/`else` chain. A variant added
without a branch is dead code that compiles clean and passes every test — which
is wave 8's own lesson, recorded at `tasks/A.md` A104 (*a planted fault passed
green in a brand-new suite until the row was widened*). See R7.

### 1.8 The wave-8 workaround, and the reference behaviour beside it

| Fact | Where |
| --- | --- |
| `Shape::renderable()` exists **only** to exclude the undecodable fixture from every spawned row, and its doc names this defect verbatim (*"so `list` exits 12 for the whole vault"*) | `tests/upgrade_hook.rs:130-145` |
| Four spawned tests are built on that exclusion and would become **vacuous, not red**, if the behaviour changed | `tests/upgrade_hook.rs:768`, `:916`, `:969`, `:1020` |
| The hook already does the right thing on the same input, per-work | `tests/upgrade_hook.rs:544` `an_unreadable_work_is_skipped_and_the_pass_continues` (`skipped == 3`, `considered == 1`, `applied == 1`) |
| **Exactly one** test in the tree plants bytes `AnchorArtifact::decode` refuses | `tests/upgrade_hook.rs:277-289` (`b"not an anchor-artifact record"`, sealed by the real record cipher so the AEAD opens) |

### 1.9 U19 execution note 6's consistency argument compares two different things

Note 6 justifies the fail-whole rule with *"`list_works` already fails
wholesale on an alien entry, so partial tolerance would have been inconsistent
anyway"* (`tasks/U.md` U19). Measured (`vault/store.rs:481-512`): `list_works`
is a `read_dir` that hard-errors `AlienEntry` on any name that is not 32 hex
bytes. That is an **enumeration** failure — after it, you do not know *which
works exist*, so no listing can be honest. A per-slot decode failure is the
opposite: the enumeration is intact, the work is identified, the slot is named,
and the count of what is missing is known exactly. The two are not the same
class, and the consistency the note appeals to is not there to be preserved.

---

## 2. The options, and what kills each

### (a) Fail whole, better message, own error class — the lean's first half. Three kills.

**K1 — it prices an *error* for something the same command already reports as
*data*, at exit 0, one layer down.** §1.3: `.ots` bytes that do not parse render
`invalid` at exit 0; the record wrapping them would render exit N. There is no
severity difference to justify the boundary and no way for a user to perceive
where it falls. This is the whole of the kill and it is a measurement, not a
preference.

**K2 — it leaves `list`'s blast radius intact.** U65's Accept has two clauses:
*"a vault with one undecodable anchor record still lists its other works"* and
*"the exit code and message are not `VaultAuthFailure`'s"*. (a) satisfies only
the second. A better sentence attached to the same total refusal is a fix for
the wording and not for the defect — and the defect the register calls the
sharpest of wave 8 is the **radius**.

**K3 — it re-decides §1.2's disagreement in the direction the tree has already
walked away from.** The one landed precedent for this exact user state
(`nag: None`, `tests/list_command.rs:839`) renders at exit 0 with a per-row
sentence. (a) would give the record-codec damage exit N and leave the
missing-manifest damage at exit 0 — two exit codes for two damage classes the
user cannot distinguish and both of which mean *"this row's anchors are
unknown"*.

**What (a) genuinely buys, recorded honestly:** a script that must fail loudly
on any vault damage gets one code to test. That is real, and R9 gives it back
without an error class: `--json` carries a machine-readable damaged-slot array
and a count, so a script tests `.counts.damaged_anchors > 0`. A script that
wants a nonzero exit about a *named* work already has one command for it —
`status <id>` — and that is the division of labour D99 R6 drew.

### (b) Per-work isolation with a damaged badge, alone — kill: it cannot say how much

A badge produced by catching the error at the work boundary can carry the
`detail` string and nothing else, because the abort happens **inside** `read`,
before the surviving slots exist as values. So the row can say *"damaged"* and
cannot say *"1 of 4"*. That is precisely the honesty failure the brief asks
about: on a work with three good anchors and one bad slot the badge over-claims
damage, and on a work with one slot it under-claims by looking like the same
event. It also needs the error class anyway — to catch schema refusals without
also swallowing I/O, AEAD failures and `NewerRecord` — so (b) alone is (a) plus
a badge, and inherits K1.

### (c) Per-record isolation inside `StoredAnchors` — recon recommends refusing. Its grounds are false.

Recon's stated reason: *"`status`/`reveal`/the U24 hook share the reader and
whole-failure is correct for them."* Taken one at a time:

- **`status`: measurably false.** D99 R6 assigns the loud reporting of a corrupt
  or future-versioned anchor record to `status` by name — *"that is a command
  the user ran **about that work**"*. Today `status <id>` answers it with exit
  12 and *"wrong passphrase"*, having successfully unlocked the vault, resolved
  the id, and read the meta record. `status`'s entire output is a per-anchor
  rendering; a row saying *"slot `tsa-1`: this record is malformed (…)"* is
  strictly more informative than a refusal, and it is the same shape as the
  `absent` row `status` already prints from its own enumeration (D98).
- **The hook: vacuous.** D99 R6 already lists *"`AnchorArtifact::decode` refuses"*
  as a **skip** row. Per-record isolation only narrows the skip from the whole
  work to the slot. `tests/upgrade_hook.rs:544` asserts `skipped == 3` and stays
  green (§6).
- **`reveal`: unmeasurable — it does not exist** (M3, U28). Whole-failure is
  right for it, and under the ruling it *gets* whole-failure, as one explicit
  call at the caller instead of as a side effect of a shared reader. That is
  strictly better for `reveal`: the refusal becomes a stated policy of the
  bundle builder rather than an inherited accident, and it can name the slot.

**The real objection to (c) is the doc comment at `anchors.rs:526-531`** —
*"a caller handed nine of ten artifacts would render a verdict about evidence it
does not have"* — and it is a good objection. It is answered in R2 by making the
acknowledgement a **type** rather than a discipline, which is the standard this
project already holds itself to (D97 §3: *"a property of the filesystem instead
of a property of a comment"*).

### (d) (a) + (b) — the lean. Kill: it inherits K1 and pays for (c) twice.

Under (d) the reader still aborts, so `list` still cannot name the slot or count
the survivors, and `status` — which needs exactly that — is left where it is or
grows its own second policy. (d) buys the radius fix for `list` and buys nothing
for `status`, at the cost of a class the exit-code table has no semantic room
for (§1.6) and four committed test edits.

### (e) Suppress the row — never considered seriously, recorded so it stays refused

Dropping a work that will not read is the one behaviour U65's Accept forbids by
name (*"never silently dropped"*), and it is how a vault silently loses a work.

### (f) The refusal becomes a datum; the whole-fail rule keeps a door — **the ruling**

---

## 3. Ruling

**A per-slot decode refusal stops being an error and becomes a value.
`StoredAnchors::read` collects damaged slots and returns them beside the intact
ones; the artifact accessors move onto a separate type reachable only through
two named doors, one of which is the whole-fail refusal the current behaviour
already is. `list` renders the damage per work and exits 0. `status` renders it
per slot and exits 0. `reveal` (M3) refuses through the whole-fail door,
explicitly. No `ErrorClass` is minted, no exit code moves, and `AnchorState`'s
frozen seven are not touched.**

What carries it, in one line: **the seven-state verdict vocabulary and the
exit-code taxonomy are both about evidence and severity, and an unopenable
record is neither — it is a fact about the vault, so it gets a field, not a
verdict and not a code.**

And what makes it safe rather than merely kinder: the hazard `anchors.rs:526-531`
names — a caller rendering a verdict about evidence it does not have — is
honoured **more strongly** than today, because today it is a comment and under
R2 it is a type.

---

## 4. Riders — normative, cite by number

### R1 — Three reasons, not one, and each has a different fault-holder

A damaged slot carries a **reason**, and the three are kept apart because they
demand three different actions and only one of them is anybody's fault:

| Reason | Produced by | Sentence | Action |
| --- | --- | --- | --- |
| `Undecodable { detail: &'static str }` | every `corrupt(…)` in `AnchorArtifact::decode`, `codec()`, `open_envelope`'s two shape refusals, and `assemble`'s two consistency refusals (R5) | *"this record is malformed"* + the `detail` verbatim | inspect / restore from a backup |
| `NewerRecord { found: u64 }` | `open_envelope`'s version ceiling (`journal.rs:1052-1054`) | *"written by a newer antseal (record format vN)"* | upgrade antseal |
| `SlotMoved` | `anchors.rs:560` — the slot vanished between the listing and the read | *"changed while it was being read (another antseal may be running)"* | re-run |

Collapsing these is the defect one level down. `anchors.rs:548-551` already
insists on the first split (*"'upgrade antseal' and 'your vault is damaged' are
different sentences and only one of them is the user's fault"*), and
`tests/seal_journal.rs:945` asserts it. The third is not damage at all: `list`
takes no lock by design (`commands.rs:318-323`), so a concurrent seal makes it
**expected**, and `apply_upgrade` already treats the same condition as benign
under the name `JournalError::AnchorSlotMoved` (D99 R3). Rendering a healthy
mid-seal vault as *damaged* would be a new false accusation replacing the old
one.

**Surfacing `detail` is safe by construction, not by review.** It is
`&'static str` on a variant whose own doc says *"Failure-class summary — never
record bytes"* (`journal.rs:598-602`), so no record content and no secret can
reach it. Project rule 6 is satisfied by the type.

### R2 — The acknowledgement is a type, not a discipline

```rust
// crates/antseal-cli/src/pipeline/anchors.rs
pub struct StoredAnchors { intact: IntactAnchors, damaged: Vec<DamagedSlot> }

impl StoredAnchors {
    pub fn read(store: &WorkStore<'_>, seal_id: &SealId) -> Result<Self, JournalError>;
    pub fn damaged(&self) -> &[DamagedSlot];
    /// The evidence door: refuses if anything is damaged (today's behaviour).
    pub fn require_intact(&self) -> Result<&IntactAnchors, JournalError>;
    /// The reporting door: the survivors AND the damage, together.
    pub fn intact_and_damaged(&self) -> (&IntactAnchors, &[DamagedSlot]);
}
```

`all()`, `ots()`, `tsa()`, `ots_slot()`, `ots_entry()` and `len()` **move onto
`IntactAnchors`**. There is no other path to an artifact. A caller that wants
evidence must call `require_intact()` and handle its `Err`; a caller that wants
to report must call `intact_and_damaged()` and receives the damage whether it
asked or not.

`read`'s signature is unchanged and it still fails — on **enumeration** and
**authentication**, never on a per-record schema refusal (R5). U47's *"one
reader, because two decoders of one versioned record drift"* is untouched:
there is still exactly one call to `AnchorArtifact::decode` in the workspace,
and R2 adds no second codec. What it adds is a second **policy**, and the
policies are named rather than implied.

**The residual, stated rather than hidden:** a caller can write
`let (intact, _) = stored.intact_and_damaged();`. That is an explicit `_`, which
is greppable and reviewable, unlike an absent call. Closed the same way D99 R2
and D97 R3 close their equivalents — an S36-pattern scan
(`production_files_naming`, proven red against a planted violation): production
sources of `crates/antseal-cli/src` may name `intact_and_damaged(` **only** in
`listing.rs`, `status.rs` and `upgrade_hook.rs`. A fourth file is a caller that
took the reporting door without being a reporter, and the assertion message says
so.

### R3 — `list`, exactly

**Exit code: 0. Always.** `list` succeeded; it produced the picture it was asked
for, and the picture includes the damage. Three grounds:

1. It is what the one landed precedent for this user state does
   (`nag: None`, exit 0, `tests/list_command.rs:839`). A nonzero exit for the
   record-codec class and zero for the missing-manifest class would be two codes
   for one indistinguishable condition.
2. A nonzero exit reintroduces the blast radius with a better message: every
   scripted `antseal list --json | jq` against a vault with one damaged slot
   would fail, which is the harm U65 records, one layer quieter.
3. U65's Accept — *"the exit code and message are not `VaultAuthFailure`'s"* —
   is satisfied literally, and the honesty burden moves to the row, the summary
   and the machine document, where it can carry detail an exit code cannot.

**Human output.** The damage block replaces the nag block for that row and is
**unconditional on damage** — this is the honesty guarantee, because
`NagState::Anchored` and `AttestedOnly` print nothing at all today, so without
it a damaged work would be visually identical to a clean one. Two lines, the
established `nag_lines` shape (marker, then next step):

```
  anchors: 1 of 3 slots unreadable — tsa-1: anchor slot family disagrees with the record kind
  the other anchors are counted as if it were absent; run antseal status <work-id>
```

```
  anchors: 1 of 3 slots written by a newer antseal (record format v3) — ots-pending
  upgrade antseal to read it; the others are counted as if it were absent
```

```
  anchors: 1 slot changed while it was being read — tsa-2 (another antseal may be running)
  re-run antseal list
```

`status <work-id>` is a **satisfiable** next step and `--upgrade` is not; R7
turns on the same distinction.

**Summary line.** A third orthogonal clause in the existing parenthetical
(`listing.rs:506-527`), beside `N UNANCHORED` and `N waiting on pending
anchors`: `N with unreadable anchors`. `ListingCounts` gains
`damaged_anchors: usize`, counting **works**, matching how `unanchored` and
`pending_anchor_nags` already count works.

**`--json`.** `WorkRow` gains one field; `row_json` gains one key:

```json
"damaged_anchors": [
  { "slot": "tsa-1", "reason": "undecodable",
    "detail": "anchor slot family disagrees with the record kind",
    "format_version": null }
]
```

Four keys, all always present, `reason` ∈ `{undecodable, newer-record,
slot-moved}` and `format_version` non-null only for `newer-record`. The array is
**empty, never `null`**, for a healthy work — deliberately, because `null`
would re-create the `Some(0)` / `None` ambiguity U25 had to disambiguate at
cost, and here there is no not-computable case: collecting the damaged set is
what the reader now does. `counts` gains `"damaged_anchors": N`.

Permitted at M2 on `listing.rs:56-59`'s own measurement: D65 is not in force,
and `ENVELOPE_VERSION` governs the wrapper, not the result document
(`machine.rs:66`).

### R4 — Row honesty: the damage is orthogonal, and it never enters `NagState` at this layer

`pending_anchors` and `nag` are computed over the **intact** set. A work with a
verified TSA token and one damaged slot renders `nag: "anchored"` — which is
**true**, because it does hold a headline-eligible anchor — and the damaged
array is what stops it being read as the whole story.

Suppressing `nag` to `null` on damage is **refused**: `null` already means *"no
recoverable `anchor_digest`"* (`listing.rs:245-254`), and putting a second fact
in one null is the A102 disease reappearing one level up. `listing.rs:62-78`
already establishes the house rule that orthogonal predicates get separate
columns and separate words; a fourth orthogonal fact gets a fourth column.

**The one case where it is not orthogonal** is a work whose *only* slots are
damaged. Then the intact set is empty, and today's `anchor_nag` would answer
`NagState::Unanchored` — *"No anchors at all: the `--no-anchor` seal"* — which
is a lie about a work that has anchors it cannot read. R7 is what closes it, and
it is why the two crates must land together.

### R5 — Which producers wire in, and the line that keeps U6 intact

**Become damaged-slot data (reason `Undecodable`), all fourteen strings:**
`anchors.rs:261` (header ≠ 80), `:265` (unknown key), `:281` ×3 (partial upgrade
group: height / header / date), `:291` (kind missing), `:292` (unregistered
kind), `:301` (group on a non-OTS record), `:306` (endpoint missing), `:307`
(fetch date missing), `:308` (bytes missing) — plus `journal.rs:1023`
(`codec()`, *"not canonical CBOR"*), `journal.rs:1046` (*"envelope must be
[version, body]"*), `journal.rs:1050` (*"version 0 is invalid"*); and from the
reader, `anchors.rs:576` (slot name outside both families) and `:583` (family
disagrees with kind).

**Becomes reason `NewerRecord`:** `journal.rs:1052-1054`.

**Becomes reason `SlotMoved`:** `anchors.rs:560`.

**Does NOT wire in — `read` still fails, and exit 12 is still correct:**

- everything `store.list_anchors` raises (I/O, `AlienEntry`, `InvalidSlotName`).
  This is the **enumeration** class of §1.9: if the listing is untrustworthy you
  do not know what you are missing, and a partial picture is dishonest by
  construction. Same rule as `list_works`.
- everything `store.get_anchor` raises from the **cipher** layer —
  `CipherError::AuthFailure`, `BlobTooShort` (`cipher.rs:219-226`). **This is
  the line that keeps U6 whole: the split is exactly at the AEAD boundary**
  (§1.5). Below it, one code. Above it, the truth.

**Explicitly out of scope, and named so it is not assumed:** the other three
record classes that ride `envelope`/`open_envelope` — `StagedBlob`, the state
record, the plan record (D97 §1.3) — keep exit 12 unchanged. They are the
machinery of a work rather than evidence about it, and a corrupt one does mean
the vault is damaged in a way the user must act on before anything else. The
symmetrical question for the **meta** and **plan** records is real and is
recorded in §8.

### R6 — `status`, exactly

`status` takes the reporting door and gains a **damaged-anchor section**,
rendered from its own enumeration exactly as D98 requires of `absent`
(*"which `status` knows from its own enumeration and must print explicitly or
not at all"*), and **outside** the frozen seven-state vocabulary — §1.4: no
verdict can be stated, because the mechanism is inside the record that will not
open. One row per damaged slot: the slot name, the reason, the detail. Exit
**0**, matching what `status` already does for an `invalid` verdict (§1.3).

`status.rs:856-863`'s no-manifest refusal is **converted in the same change** to
match `list`: `anchor_digest_of` returns `Option<[u8; 32]>`, and a work with
anchors and no manifest renders its anchors as unclassifiable rather than
exiting 12. Leaving it would preserve §1.2's divergence inside the decision that
found it. The doc at `:844-847` is rewritten to say why the reader now reports
rather than refuses, and to stop reaching for `JournalError::Corrupt` to
describe a record that is **absent**.

### R7 — A102: the fifth `NagState` lands, and A102's Accept row is overturned

**A102's Accept says a work whose only anchor is unreadable *"nags"*. That is
wrong, and the committed counter-argument at
`crates/antseal-anchor/src/ots/engine/tests.rs:552-570` is right — but it is
right about the **boolean**, not about the **name**, and A102 needs the name.**

`nags()` is what drives `nag_lines`' two-line block (`listing.rs:554-570`).
Implementing A102 literally would print, for a work with no readable evidence at
all:

```
  ANCHORS PENDING: 0 calendar attestation(s) not yet confirmed by Bitcoin, …
  run antseal status <id> --upgrade
```

— two false statements and one unsatisfiable instruction. Silence is better than
that, which is exactly what the committed test says. So:

**R7.1 — a fifth variant, `NagState::Unreadable`, whose `nags()` is `false`.**
Kebab `unreadable`, matching `OtsAnchorState::Unreadable`, which is the state it
is derived from. The committed test keeps three of its four assertions —
`state == Unreadable`, `pending_uris.is_empty()`, **`!status.nag.nags()`** — and
changes one, `AttestedOnly` → `Unreadable`. That the load-bearing line survives
untouched is the proof the counter-argument was satisfied rather than
overridden, and its doc comment gains the sentence saying so. A102's Accept
requirement that *"the existing pin is **updated** in the same change rather
than deleted"* is met exactly.

**R7.2 — the branch, and its position, which is an argument not a preference.**

```rust
} else if has_pending {            NagState::OnlyPendingOts
} else if has_unreadable {         NagState::Unreadable      // new
} else if has_any_anchor {         NagState::AttestedOnly
```

- **Below `has_verified_tsa`**: a work with a verified token genuinely holds a
  headline-eligible anchor. `Unreadable` there would over-claim damage and
  contradict A15's own rule. `list` renders no per-anchor state by design
  (`listing.rs:114-119`); the unreadable artifact is `status`'s to show.
- **Below `has_pending`**: a work with one pending `.ots` and one junk `.ots`
  should still nag, because `--upgrade` genuinely can help the pending one —
  satisfiable advice wins.
- **Above `has_any_anchor`**: that fall-through is A102's entire complaint.

**R7.3 — `PendingWork` gains `unreadable_records: usize`**, so the record-level
damage of R4's last paragraph reaches the classifier and the rule stays in A15.
`has_unreadable` becomes
`ots.iter().any(|s| s.state == Unreadable) || work.unreadable_records > 0`, and
`has_any_anchor` gains the same term. Deciding it in `listing.rs` instead would
be a second nag rule in the CLI — the shape D98 rejected its option (c) for.
Cost, measured: 2 production sites and 11 test constructions (§1.7).

**R7.4 — `list` renders `Unreadable` with a satisfiable next step**: one line
naming the state and one naming `antseal status <work-id>` — **without**
`--upgrade`. `status` shows it as `invalid` (D98's cross-walk), which is a real
answer to a real question.

### R8 — A103 lands in the same commit, not first, and gains `ALL`

**Recon's ordering claim is refuted** (§1.7): the compile error that stops a
fifth variant acquiring a wrong name already exists at `listing.rs:293-301` and
is there on purpose. A103 is not what makes R7 safe.

What A103 *is*: the removal of a second table for one taxonomy, and it is XS. It
lands in the same commit because splitting it means writing the fifth kebab
string in `listing.rs` and deleting it a day later.

**And A103 as written does not close the real hole.** `each_nag_class_has_its_own_name`
(`listing.rs:1085-1107`) enumerates a hand-written five-element array; with six
states it **passes while covering five**. A `name()` on the enum does not fix
that. So A103's scope is widened by one item: **`NagState::ALL`**, the
`ErrorClass::ALL` pattern already in this tree, with the enumeration test
rewritten over it — the shape
`tests/exit_codes.rs:100` (`the_exit_code_table_is_exactly_the_documented_one`)
already proves by comparing `ALL.len()` to the table.

**And one more, which nothing in A102 or A103 covers**: `work_status`'s
classifier is an `if`/`else` chain (§1.7), so a variant can exist, be named, and
**never be constructed**, silently. R10.4 is the test that closes it.

### R9 — What a script gets instead of an exit code

Recorded because it is what (a) was buying: `--json` carries
`counts.damaged_anchors` and a per-row `damaged_anchors` array with a
machine-branchable `reason`. A CI job that must fail on vault damage tests
`.counts.damaged_anchors > 0` — which is strictly more expressive than one exit
code, because it distinguishes *upgrade antseal* from *your vault is damaged*
from *something else is running*, and names the works.

### R10 — The tests, including the two that cannot redden

**R10.1 — must redden, semantically:**

| Test | Where | What changes |
| --- | --- | --- |
| `one_unreadable_slot_fails_the_whole_read` | `tests/seal_journal.rs:984` | re-pointed at `require_intact()`; **assertion text unchanged**, name changed to name the door. Its counterpart is new: `read` surfaces the damaged slot **and** the intact ones. |
| `a_newer_anchor_record_refuses_by_name_through_the_reader` | `tests/seal_journal.rs:945` | re-pointed at `require_intact()`; assertion unchanged, including `ErrorClass::VaultNewerVersion`. R1 keeps `NewerRecord` distinct, so this constrains the design and does not fight it. |
| `the_reader_refuses_a_slot_set_it_cannot_read_wholly` | `src/pipeline/anchors/tests.rs:620` | same re-pointing; the three rows and their messages stand verbatim. |
| `an_unreadable_artifact_is_reported_as_such` | `antseal-anchor/src/ots/engine/tests.rs:555-570` | one assertion of four (R7.1). |
| `an_unreadable_ots_is_folded_into_attested_only_and_stops_nagging` | `src/listing.rs:1069-1082` | reddens and is **renamed**, per A102's Accept. |
| `the_nag_appears_in_the_human_report` + `snapshots/list-anchor-nags.txt` | `tests/list_command.rs:853`; snapshot `:28-29` | a damaged work joins `anchor_fixture_vault`; the summary line at `:29` gains the third clause. |
| `the_nag_is_a_structured_field_in_the_json_document` | `tests/list_command.rs:891` | the new row key. |
| `envelope_fixtures_match_the_committed_snapshot` + `snapshots/json-envelopes.txt:24` | `tests/machine_mode.rs:822` | the new row key. |

**R10.2 — must be DELETED, and its death is the acceptance criterion for the
whole decision:** `Shape::renderable()` and `renderable_vault` at
`tests/upgrade_hook.rs:130-145`, with `Shape::UndecodableAnchor` rejoining the
four spawned rows at `:768`, `:916`, `:969`, `:1020`. Those four **do not redden
on their own** — they become vacuous — so re-pointing them is a required step
and not a consequence. If the workaround survives the change, the change did not
work.

**R10.3 — too narrow to redden at all; both are named because a green suite
would otherwise be mistaken for coverage:**

- **`tests/machine_mode.rs:715-759` `fixture_listing()`** — hand-builds
  `WorkListing` and two `WorkRow` literals and **never calls `gather`**, so no
  behavioural change can reach it. It will **fail to compile** on the new
  `WorkRow` field (U63), which is a different thing from reddening: it forces an
  edit and asserts nothing about the new behaviour. It needs a **third row**
  carrying a damaged slot, or `damaged_anchors` ships unsnapshotted.
- **`src/listing.rs:1085-1107` `each_nag_class_has_its_own_name`** — a
  hand-written five-element array; a sixth `NagState` does not redden it, it
  silently under-covers. `nag_name`'s wildcard-free match forces the
  *production* edit and this test then passes at 5-of-6. Rewritten over
  `NagState::ALL` (R8).

**R10.4 — the reachability test nothing else provides.** Because `work_status`
is an `if`/`else` chain (§1.7), assert that **every** variant of `NagState::ALL`
is produced by at least one fixture row of `work_status`. Plant the fault by
deleting R7.2's branch: the variant still exists, still has a name, still
compiles, and the row must go red. This is the wave-8 lesson (A104's *"a planted
fault passed green in a brand-new suite until the row was widened"*) applied
before it recurs.

**R10.5 — the tamper matrix is a guardrail, not a casualty.** Everything in
`src/pipeline/anchors/tests.rs:138`, `:299`, `:404`, `:433` tests `decode`
directly and is **unaffected**: the decoder must keep refusing exactly as it
does, with exactly the messages it does. Only the *caller* softens. Add rows
that a damaged slot's `reason` and `detail` are the decoder's own, verbatim, for
one representative of each of R1's three reasons.

### R11 — Ordering (normative; the checkpoints are the point)

1. **`antseal-anchor` alone**: R7's fifth variant + branch + `PendingWork` field,
   R8's `name()` and `ALL`, R10.4's reachability row. Self-contained, one
   committed assertion line changes, and it must be first — landing it after the
   CLI work means `nag_name`'s wildcard-free match breaks the CLI mid-stack.
2. **R2's restructure, behaviour-preserving.** Every current caller switches to
   `require_intact()`. **Acceptance: exactly two test call sites change
   (`tests/seal_journal.rs:945` and `:984`) plus `anchors/tests.rs:620`, all
   mechanical, and no assertion text moves.** That checkable claim is what
   proves the refactor is separable from the policy change. **The one place it
   can drift silently**: today `read` decodes every slot (aborting at the first
   failure in `list_anchors`' lexical order) and only then assembles, so
   *decode* failures precede *family* failures. `require_intact` must report in
   that same two-pass order or two vaults will swap their diagnoses.
3. **`status` adopts the reporting door** (R6), including the no-manifest
   conversion. Before `list`, because the diagnostic is worst there — the user
   named the work — and because `list`'s damage line points at `status`.
4. **`list` adopts it** (R3): `WorkRow` field, damage block, counts, summary
   clause, `--json`, snapshots.
5. **R10.2**: delete the workaround, re-point the four spawned rows.
6. **R10.5 and R2's scan**, with planted faults run before any green verdict.

---

## 5. What binds, what merely gestures — including the criterion this weakens

**D97 §2 K1 — addressed out loud, as the brief requires.** K1 kills option (a)
(a second `ots-upgrade` slot) partly *because* an unregistered `ArtifactKind`
yields `corrupt("unregistered anchor-artifact kind")` → `VaultAuthFailure`,
*"the same false-tamper diagnostic"*. **D100 removes that harm**: under R5 that
producer becomes a damaged-slot datum with an honest sentence.

**D97's ruling survives, and K1 survives on its other leg.** Three things:

1. **K1 was never decisive and D97 says so itself** — its status paragraph names
   *"the decisive one"* as **K2**, the ordinary resume path manufacturing a
   false `invalid`/`anchor-ots-header-uncommitted` on an honest work. K2 is
   about a stale group surviving a rewrite and has nothing to do with error
   classes. **K3** (crash-window order sensitivity) and **K4** (two falsified
   doc comments) are likewise untouched.
2. **K1 has a second leg D100 does not touch**: *"If it is a new record type, it
   is a second codec in the same area with its own version question."* And K1's
   headline claim — that (a)'s advertised "no schema change" is false because it
   *relocates* the change onto `from_wire` — stands unchanged. What D100 removes
   is only that the relocation produces a **lie**; it still produces a schema
   change.
3. **D97 §2(b)'s kill is weakened in severity and intact in direction.** (b) was
   killed because keys-at-v1 makes an older build say *"wrong passphrase"* for a
   merely-newer record. Under D100 that case is `corrupt("unknown
   anchor-artifact key")` → a damaged slot saying *"this record is malformed"* —
   better, but still not *"upgrade antseal"*. The version field remains the only
   thing that produces the right sentence, which is exactly what (b) was killed
   for not having.

**So D97 needs a rider, not an amendment** (§6 item 5), and it is recorded here
rather than left to be re-derived, because an unrecorded weakening of a
committed kill criterion is how a settled decision gets re-opened by accident.

- **D98 binds, twice.** Its seven-state vocabulary is frozen and forbids an
  eighth (§1.4), which is what forces R6's damaged section to sit *outside* the
  verdict rendering. And its ruling that A15 owns the per-work nag and A18 the
  per-artifact state — *"neither is projected into the other"* — is what forces
  R7.3 to put `unreadable_records` on `PendingWork` instead of deciding it in
  `listing.rs`.
- **D99 R6 binds and is completed rather than amended.** It divides the labour —
  hook silent at `debug`, `status` loud — and states that *"`status <work-id>`
  is the command that must report a corrupt or future-versioned anchor record
  **loudly**"*. Today `status` reports it as a wrong passphrase, so R6's
  assignment has never been executable. R6 adds `list` to that division as
  *visible but exit 0*, which is the rung R6 did not have a command for.
- **U6 binds and is preserved exactly.** §1.5: the split is at the AEAD boundary,
  the two populations do not share a producer, and no unauthenticated caller can
  observe the distinction. Codes 18 and 19 are the committed precedents for
  carving a distinguishable condition out of 12.
- **U20 note 2 gestures, and in the helpful direction**: it is the authority that
  a class need not be numerically adjacent to its band. The ruling mints no
  class, so it is never invoked — recorded because recon asked whether it
  collides, and it does not.
- **D51 is untouched.** Invariant 2 (same code in both modes) is trivially
  satisfied at 0, and no new prompt class arrives.
- **D42 is untouched.** Nothing here changes what is inside the AEAD. Slot names
  are already outside it, so putting a slot name in a rendered line and in
  `--json` publishes nothing new.
- **U63 is not resolved here, and is strengthened by measurement.** This is the
  **third** field addition to `WorkRow` (U25 paid for two), and §1.7 measures the
  sites: `listing.rs:398`, `listing.rs:1144`, `tests/machine_mode.rs:724` and
  `:739`. That last pair is an integration test in a different crate, which is
  the fact U63 asks to be decided — the type is **not** crate-internal in
  practice. R7.3 adds a second such struct (`PendingWork`, 13 sites). D100 pays
  the tax and records that it is now two types, not one.

---

## 6. Amendments (orchestrator applies at source)

1. **`crates/antseal-cli/src/pipeline/anchors.rs:526-531`** — the heading *"# A
   decode failure fails the whole read"* becomes *"# A decode failure is a
   value, and the whole-fail rule has a door"*, stating R2's two doors, why the
   hazard it names is now a type, and that R5's line is the AEAD boundary.
2. **`crates/antseal-cli/src/listing.rs:357-362` and `:371-375`** — both say a
   record that cannot be read fails the listing. Rewrite to R3, and cite §1.2:
   the same module already renders an uninterpretable anchor set at exit 0 twenty
   lines away, and the two paragraphs contradicted each other.
3. **`crates/antseal-cli/src/status.rs:276-279` and `:844-847`** — per R6. In
   particular `:844-847`'s *"an inconsistency this reader refuses rather than
   papers over"* is the exact sentence `listing.rs:247-254` refutes; the
   divergence is closed in favour of `list`'s answer, and the reason is recorded.
4. **`tasks/U.md` U19 execution note 6** — append: *"D100 §1.9: the
   `list_works` comparison this note rests on is between an **enumeration**
   failure (after which no honest listing exists) and a **per-record** failure
   (after which the work, the slot and the survivor count are all known). The
   rule the note states — a damaged work may not pretend to be healthy — is
   preserved by D100 R3/R4; the blast radius is not."*
5. **`docs/decisions/D97-ots-upgrade-group-vault-home.md` §2 K1** — append the
   rider drafted in §5: D100 removes the false-tamper half of K1's first leg;
   the relocation-of-the-schema-change claim, K1's second leg, and K2/K3/K4 are
   untouched; D97's ruling is unchanged.
6. **`tasks/A.md` A102, Accept row** — replace *"a work whose only anchor is
   unreadable **nags**"* with: *"a work whose only anchor is unreadable renders
   under `NagState::Unreadable`, whose `nags()` is **false** — D100 R7. The
   literal word 'nags' was wrong: `nags()` drives the two-line PENDING/`--upgrade`
   block, whose count would read 0 and whose instruction is unsatisfiable, which
   is what `engine/tests.rs:552-570` refuses and is right to refuse. A102 needed
   the **name**, not the boolean, and gets a rendered line with a satisfiable
   next step (`antseal status <id>`) instead."*
7. **`tasks/A.md` A103** — add `NagState::ALL` to its `Do` and note the ordering
   correction (same commit as A102, not before it), with the measured reason
   from §1.7: the compile-time forcing A103 was credited with already exists at
   `listing.rs:293-301`, and the hole A103 does **not** close is
   `each_nag_class_has_its_own_name`'s hand-written array.
8. **`tasks/U.md` U65** — its Accept row is satisfied and sharpened: add *"exit
   0, and the damage is a per-slot datum with three distinct reasons (D100 R1),
   not a badge"*, and add **A102**, **A103** and **U63** to its Deps.
9. **`crates/antseal-anchor/src/ots/engine/tests.rs:552-570`** — the doc comment
   gains: *"The fifth state is what let the other three assertions keep their
   meaning: `nags()` stays false, so the unsatisfiable nag this test refuses is
   still refused — what changed is only that the state no longer borrows the
   name of a good outcome (D100 R7.1)."*

---

## 7. Measured vs. assumed

**Measured** — read at the cited line in the tree at `09a81c2`: the full failure
path (§1.1) and the corrected producer count (12 sites, 14 strings, plus three
more in `journal.rs`); the `list`/`status` divergence on the identical
no-manifest state (§1.2) and both of its self-justifying doc comments;
`status`'s unconditional `Ok(Outcome)` and the landed `invalid` snapshot (§1.3);
the seven-state freeze and `absent`'s enumeration-only status (§1.4); the AEAD
producer split and codes 18/19 as committed carve-outs from 12 (§1.5); the
exit-code table, the full 12–19 band, the free set `{5–9, 28, 29, 36–39}`, and
U20 note 2 (§1.6); `NagState`'s non-`non_exhaustive`ness, its single wildcard-free
match, `nags()`'s silent-default `matches!`, `work_status`'s if/else chain, and
the construction-site counts for `PendingWork` (2 + 11) and `WorkRow` (4)
(§1.7); the wave-8 workaround and the hook's existing per-work skip (§1.8);
`list_works`' alien-entry enumeration failure (§1.9); the test and snapshot
inventory in R10.

**Assumed, and flagged:**

- **No `cargo` command was run.** This host is 2-core with other lanes staged,
  and the ruling rests on reading control flow, record schemas and the test
  inventory rather than on a build. The implementing lane confirms R11 step 2's
  acceptance claim (exactly three test call sites change, no assertion text
  moves) by running it, and confirms that `IntactAnchors` does not force a
  lifetime change on `ots_entry`'s borrow in `apply_upgrade`.
- **That `reveal` (U28, M3) wants whole-failure.** It does not exist. The ruling
  gives it `require_intact()` and a slot name; if M3 finds it wants to build a
  bundle from partial anchors and *say so in the bundle*, that is a decision of
  its own and R2 is the seam it would use.
- **That no consumer outside this workspace reads the `--json` row.** M2 has no
  released build, so a new key is additive to nobody. D65's absence is measured
  (`listing.rs:56-59`), not assumed.

---

## 8. Residual risks and revisit triggers

- **`list` exits 0 on a vault every one of whose works is unreadable.** The rows
  say why, per work, and `--json` counts it, but the process still succeeds. This
  is the sharpest cost of R3 and it is deliberate: the alternative is the blast
  radius, and R9 is the channel a script uses instead. **Trigger:** any report of
  damage going unnoticed in an automated run, or the arrival of a command whose
  contract is *"tell me if this vault is healthy"*.
- **The reporting door can be taken and its second element dropped** with an
  explicit `_` (R2). Closed by a scan, which is enforcement of a *shape* and not
  of an *intent*. **Trigger:** a fourth production file wanting
  `intact_and_damaged(`.
- **R11 step 2 can drift silently** on the decode-then-assemble ordering, which
  is the one place a "behaviour-preserving" refactor changes which of two
  damaged slots is named. **Trigger:** any edit to `StoredAnchors::assemble`'s
  pass structure.
- **`tests/vault_export.rs:185-188` plants a slot named `tsa-0.der`**, which
  `SlotFamily::parse` refuses. It is never routed through the reader today. Under
  the ruling, if D47's import path ever were, it would become a damaged slot
  rather than a hard export failure — safer, but a behaviour nobody has asked
  for. **Trigger:** any change routing export/import through `StoredAnchors`.
- **The meta and plan records have the same defect and are out of scope** (R5).
  A corrupt plan record still fails `list` for the whole vault with the
  passphrase sentence. The argument for keeping them fatal is real (they are the
  machinery, not the evidence) but it has not been tested against a user on a
  half-damaged vault. **Trigger:** the first report; and see §9.
- **U6's merge is narrowed by this decision even though its rule is intact.**
  §1.5's argument — that the far side of the AEAD is unobservable to an
  unauthenticated caller — is sound and is the same reason codes 18 and 19
  exist, but it is now being relied on by a third caller. **Trigger:** any
  proposal to distinguish error classes *below* the AEAD boundary, where the
  argument does not hold.

---

## 9. Discovered work

**No task IDs are minted here** (this planner was instructed not to); the
orchestrator allocates from the wave-9 block and registers each in `TODO.md`,
including those cited only in prose above (the Q85 rule).

**(i) The meta and plan records have U65's defect.** — M2 · S · deps: D100 R5,
U9, U19. `recorded_state`, `recorded_plan` and `load_meta` all propagate
`Corrupt` → `VaultAuthFailure` → exit 12 for the whole vault (`listing.rs:366`,
`:370`). D100 scopes itself to the anchor record and records the reason (they
are machinery, not evidence) as an **argument, not a measurement**. Decide
whether a work whose meta record is unreadable is a row that says so or a vault
that refuses, and whether the answer differs for the plan record. Accept: either
a per-work marker exists for them too, or the reason it must not is recorded at
`listing.rs` with the same care D100 §1.9 applies to `list_works`.

**(ii) `StoreError::AlienEntry` renders as a wrong passphrase.** — M2 · XS ·
deps: none. `vault/store.rs:286` folds `AlienEntry` into `VaultAuthFailure`, so a
stray file in `store/works/` produces *"wrong passphrase, or the vault store or
header has been modified or corrupted"*. It is the same overload D100 removes one
layer up, and unlike D100's case it genuinely is an enumeration failure — so the
fix is the **sentence**, not the radius. Accept: the message names the offending
entry class and does not accuse the passphrase; the exit code may stay 12 if that
is argued.

**(iii) The `nags()` boolean is overloaded.** — M2 · XS · deps: A102, D100 R7.
`NagState::nags()` decides *both* "flag this row" and "print the
PENDING/`--upgrade` copy", which is why R7 had to overturn A102's Accept rather
than implement it. With five states, three of them have something to say and only
one may print that copy. Accept: the render decision is per state (a small table
beside `NagState`, or a `hint()` returning the satisfiable next step), and adding
a state without choosing its copy is a compile error.

**(iv) `WorkRow` and `PendingWork` are the same U63 question, twice.** — M2 · XS
· deps: U63, D100 R7.3. U63 asks about `WorkRow`; §1.7 measures that
`PendingWork` has the identical shape (public fields, no `#[non_exhaustive]`, 13
construction sites) and that D100 breaks both in one change. Fold it into U63's
scope so the answer is given once rather than twice and differently.

**(v) `status`'s `--json` needs a damaged-anchor array too.** — M2 · XS · deps:
D100 R6, U23. R6 specifies the human rendering; the machine document's shape for
a damaged slot in `status` (as opposed to `list`) is not specified here and must
match R3's four keys, or the two commands will spell one fact two ways — A103's
defect at the document level.

---

## Index row (orchestrator applies at merge)

| [D100](D100-damaged-anchor-record-surface-behaviour.md) | What `list` and `status` do with an anchor record they cannot decode — **the refusal stops being an error and becomes a datum; no `ErrorClass` is minted and `list` exits 0.** The register's lean (d) is overturned in half and inverted in the other half. The error-class half dies on a measurement recon did not take: `status` **already renders the identical damage one layer down at exit 0** — `.ots` bytes that do not parse render `invalid` (D98's own cross-walk, `verdicts.rs:694-707`), and the `status` handler has **no verdict → exit-code branch at all** (`commands.rs:390-402`) — so a new class would put exit 0 and exit N on two sides of a boundary the user cannot see and that carries no severity difference. And recon's (c), which it recommended **refusing**, is the load-bearing half: its grounds are **measurably false for `status`** (D99 R6 assigns it the loud per-work report and it answers exit 12 *"wrong passphrase"* on a work the user named by id), **vacuous for the hook** (D99 R6 already lists the decode refusal as a per-work skip), and **unmeasurable for `reveal`**, which does not exist and which gets whole-failure back as one explicit call. **The decisive finding is not in `list`**: `list` and `status` already **contradict each other in production** on the same vault state — a work with anchors and no journaled manifest renders *"anchors: unclassified"* at exit 0 (`listing.rs:616-619`, tested at `list_command.rs:839`) and exits 12 accusing the passphrase (`status.rs:856-863`), each documenting itself as obviously correct and neither citing the other — so the "fail whole" rule has **two contradictory authorities, not one**. Recon's *"five `corrupt(…)` producers"* is measured wrong: **twelve** call sites, **fourteen** distinct strings, plus three in `journal.rs`. The split is placed **exactly at the AEAD boundary** — a genuine auth failure is `CipherError::AuthFailure` → `VaultAuthFailure` **directly** and never through `JournalError`, so no unauthenticated caller can observe the distinction and U6's *"insofar as safe"* is preserved; codes **18** (*"NEVER the generic auth failure"*) and **19** (an unimplemented registry tag) are the committed precedents. An eighth `AnchorState` is impossible (**frozen at seven**, D98) and a verdict is unstatable anyway because the artifact's **kind lives inside the record that will not open**, so the damage gets a field, not a verdict and not a code. Damage carries **three reasons** — `Undecodable` / `NewerRecord` / `SlotMoved` — because *"upgrade antseal"*, *"your vault is damaged"* and *"another antseal is running"* are three different sentences and only one is anyone's fault. **A102's Accept row is overturned**: its literal *"nags"* would print `ANCHORS PENDING: 0` and an unsatisfiable `--upgrade`, which is why the committed counter-argument at `engine/tests.rs:552-570` is **right about the boolean and silent about the name** — the fifth `NagState::Unreadable` keeps `nags() == false`, so three of that test's four assertions survive untouched and the surviving one is the load-bearing one. **A103's ordering claim is refuted**: the compile error that forces a name already exists at `listing.rs:293-301` by design; what A103 does *not* close is `each_nag_class_has_its_own_name`'s hand-written five-element array, and `work_status`'s classifier is an **if/else chain**, so a fifth variant can be named and **never constructed**, silently — hence `NagState::ALL` and a reachability test with a planted fault. **D97 K1 is weakened and survives**: D97 itself names K2 as decisive, K1's relocation-of-the-schema-change leg is untouched, and a rider records it rather than leaving it to be re-derived. Also corrected: **U19 execution note 6's `list_works` analogy compares an enumeration failure with a per-record one**; **the vault exit-code band 12–19 is full**, though U20 note 2 already ruled adjacency irrelevant. `tests/upgrade_hook.rs`'s `Shape::renderable` workaround **must die, and its death is the acceptance criterion**; `tests/machine_mode.rs:715` and `listing.rs:1085-1107` are named as **too narrow to redden**. Discovered five items (orchestrator allocates) | RESOLVED (U65/A102/A103 execute) | 2026-08-07 |
