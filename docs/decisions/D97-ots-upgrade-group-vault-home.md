# D97 — Where the OTS upgrade group lives in the vault, and what it costs

- **Status: RESOLVED — ONE RECORD, NOT TWO. The upgrade group becomes keys
  4/5/6 of the anchor-artifact record in the existing `ots-pending` slot, and
  `SEAL_JOURNAL_VERSION` goes 1 → 2 in the same commit.** The register's lean
  — a second `ots-upgrade` slot — is **overturned on four measured grounds**,
  the decisive one being that it is not a crash-window problem at all: the
  *ordinary* resume path leaves a stale group beside a fresh artifact, the
  engine reads that group, skips `confirm_header` because
  `upgrade.is_none()` is false, and the vault ends up holding a genuinely
  upgraded `.ots` paired with a **previous submission's** block header —
  which renders **`invalid` / `anchor-ots-header-uncommitted` on an honest
  work**. And (a)'s advertised advantage is false: it does not avoid a schema
  change, it relocates it onto `ArtifactKind::from_wire`, which is closed at
  wire tags 0/1 and refuses tag 2 as `Corrupt` — the same false-tamper-alarm
  it was chosen to avoid. Against that, (c) was measured and costs **two
  literal edits and zero regenerated artifacts**: no committed fixture,
  golden vector or snapshot pins a journal version byte, no test asserts
  `== 1`, there is no migration machinery to write, and **no vault exists to
  migrate.** The "whole-vault-format event" framing is measurably wrong —
  `SEAL_JOURNAL_VERSION` is one of **six** independent version constants and
  is not the vault header's.
- **Date: 2026-08-06** (M2 wave 8 planning round; **minted mid-execution** by
  the U23–U25 lane from a blocker its brief did not name)
- **Owning tasks: U23** (`status --upgrade`), **U24** (the hook), **U47** (the
  shared reader — now a hard predecessor), **U48**, **U49**
- **Amends**: `tasks/U.md` U48 and U49 (§6); the module docs of
  `crates/antseal-cli/src/pipeline/anchors.rs` (§6); the doc comment on
  `SEAL_JOURNAL_VERSION` (`pipeline/journal.rs:94-96`). **Supersedes**:
  nothing. **Binds against**: D79 (§2.4), D42, D47, D84 — see §5.

---

## The problem, in one sentence

`upgrade_pending` returns `AppliedUpgrade { artifact, upgrade: Option<OtsUpgrade> }`
whose own doc says the two are *"[r]ecorded **together** … or not at all"*
(`crates/antseal-anchor/src/ots/engine.rs:157-159`), and the vault has
nowhere to put the second half.

---

## 1. What was measured

Everything below was read from the tree at `740d7e6`. Nothing is inferred
from prose, and where a task entry disagrees with the code the code is
recorded as the fact.

### 1.1 The write side

| Fact | Where |
| --- | --- |
| `AnchorArtifact` is a strict 4-key map (0..3) that **refuses unknown keys** rather than skipping them | `crates/antseal-cli/src/pipeline/anchors.rs:127-175`, refusal at `:163` |
| That refusal message is asserted **verbatim** by a committed test | `crates/antseal-cli/src/pipeline/anchors/tests.rs:120-128` (`"unknown anchor-artifact key (strict v1 schema)"`) |
| `ArtifactKind::from_wire` is **closed at 0/1**; tag 2 is refused by name | `pipeline/anchors.rs:78-84`, `:170` (`"unregistered anchor-artifact kind"`) |
| Both refusals are `JournalError::Corrupt`, which maps to `CliError::VaultAuthFailure` — *"wrong passphrase, or the vault store or header has been modified or corrupted"*, exit code 12 | `pipeline/journal.rs:621`; `crates/antseal-cli/src/error.rs:460-464`, `:327` |
| A **version** mismatch maps instead to `VaultNewerVersion { found, supported }` — the correct sentence | `pipeline/journal.rs:622-625` |
| `put_anchor` is a single atomic write: `create_dir_all` → `seal_record` → `atomic_write` (temp + fsync + rename), no `create_new` guard, overwrite is the normal case | `crates/antseal-cli/src/vault/store.rs:669-690` |
| The slot name is bound into the record **AAD** (`RecordIdentity::Anchor { seal_id, slot }`), so a record cannot be replayed into a different slot | `crates/antseal-cli/src/vault/cipher.rs:119-125`, `:166-172` |
| The U9 slot grammar is `[a-z0-9][a-z0-9._-]{0,63}`, cap 64 — a new slot family needs no schema change | `vault/store.rs:95`, `:1111-1126` |
| `list_anchors` is a `read_dir` + `sort_unstable`, hard-erroring `AlienEntry` on any off-grammar name | `vault/store.rs:719-746` |
| The seal/resume path writes the OTS slot from `artifacts_of(submission, self.now_for_artifacts())` | `crates/antseal-cli/src/pipeline/resume.rs:382-384`, `:403-408` |

### 1.2 The read side — what an absent group actually costs

This is the half the brief's rider 1 turns on, and the answer is stronger
than "offline `status` degrades".

**`OtsUpgrade` is not derivable offline.** `block_height` is in the `.ots`,
but the 80-byte `block_header` comes from an esplora fetch
(`crates/antseal-anchor/src/ots/upgrade.rs:453` `confirm_header`) and
`fetch_date` is the moment of that fetch. Re-deriving it means re-running the
network step.

**An upgraded artifact with no group is strictly worse than the pending one
it replaced**, and it is unrescuable:

- `evaluate_ots_artifact` binds `let agreed = upgrade.and_then(|u| blocks.block(u.block_height()));`
  (`crates/antseal-core/src/anchor/verdicts.rs:735`). With `upgrade == None`,
  `agreed` is `None` **whatever online evidence the verifier holds** — so
  `--online` cannot promote it and cannot refute it.
- `committed` is false, every refutation rule is guarded on `upgrade.is_some()`,
  and a fully-upgraded artifact has no evaluable pending branch — so it falls
  to **O9, `internally-consistent-only`** (`verdicts.rs:903-913`). Before the
  upgrade the same work rendered `pending` (O5).
- On the U side it is worse than a downgrade, it is **silence**: `work_status`
  computes `has_pending` from `pending_uris`, which the upgrade emptied, so
  the work becomes `NagState::AttestedOnly` — *"`--upgrade` cannot help;
  `--online` verification can"* (`ots/engine.rs:545-548`). Both halves of that
  sentence are false for this work, and `list` stops nagging.

**The state already has a name, and its doc comment already forbids what (a)
would do.** `OtsAnchorState::AttestedHeaderMissing`
(`ots/engine.rs:511-514`), reached at `:628-632` by
`match (heights.is_empty(), anchor.upgrade.is_some())`:

> *A Bitcoin attestation but no recorded header group — the state a header
> fetch that failed after a merge would leave behind, **which the atomic
> recording rule makes unreachable from this engine**. Reported rather than
> assumed away, because a vault is editable by its owner.*

So the torn state **is** distinguishable — that part of the brief's worry is
already closed — but the committed doc asserts it is reachable only by a
vault owner editing files. A two-write representation makes it reachable from
the engine's own caller, which falsifies the comment.

**The bundle does not settle it, and the reason it does not is worth
recording.** `OtsAnchor::new(status, ots, upgrade: Option<OtsUpgrade>)`
(`crates/antseal-core/src/bundle/schema.rs:523-535`) takes an `Option`, so the
group is **not** mandatory for reveal. What makes persistence mandatory is
that a bundle built from a group-less vault would carry the *upgraded* `.ots`
bytes and render O9 offline for ever — permanent evidence loss inside a
format that freezes.

**`AppliedUpgrade.upgrade` is never `None` in a returned report.** Measured
by following the control flow: `upgrade` starts as `anchor.upgrade.clone()`
(`ots/engine.rs:371`); the only site that sets `changed = true` is preceded by
`if upgrade.is_none() { … confirm_header …  }` whose every failure arm
`continue`s (`:451-470`), and `changed` gates the push (`:476-484`). So
`changed ⟹ upgrade.is_some()`. The `Option` is a type-level possibility with
no reachable producer — and the second-calendar case means the value pushed
may be the **pre-existing** group beside **new** artifact bytes.

### 1.3 The version surface

| Fact | Where |
| --- | --- |
| Exactly **four** record classes ride `envelope`/`open_envelope` and therefore `SEAL_JOURNAL_VERSION`: `StagedBlob`, the state record, the plan record, `AnchorArtifact` | `pipeline/journal.rs:362`, `:997`, `:1032`, and `pipeline/anchors.rs:137` (encode); `:372`, `:1002`, `:1037`, `anchors.rs:148` (decode) |
| The receipt record does **not**: it is `serde_json` under `RECEIPT_JOURNAL_VERSION` | `pipeline/receipt_sink.rs:79-99`; `crates/antseal-net/src/receipt.rs:206` |
| The consent record does **not**: it is a sub-map of U9's meta record under `WORK_RECORD_VERSION` | `vault/store.rs:824-831`; `pipeline/vault_journal.rs:277-279` |
| There are **six** independent version constants, none derived from another, all at 1 | `journal.rs:97`, `vault/store.rs:84`, `vault/header.rs:65`, `vault/export.rs:182`, `vault/bookkeeping.rs:54`, `antseal-net/src/receipt.rs:206` |
| **No committed fixture, golden vector or snapshot pins a journal version byte.** The three `0x82 0x01` hits in the tree belong to `WORK_RECORD_VERSION`, `VAULT_FORMAT_VERSION` and `EXPORT_FORMAT_VERSION` respectively | `tests/work_store.rs:680`; `tests/vault_store.rs:113`; `tests/vault_export.rs:389-391` |
| **No test asserts `SEAL_JOURNAL_VERSION == 1`.** Both version tests are written relative to the constant and follow a bump automatically | `journal.rs:1199-1213`; `pipeline/anchors/tests.rs:166-179` |
| There is **no migration machinery**: the guard is a ceiling (`version > SEAL_JOURNAL_VERSION`), and `open_envelope` **throws the version away**, returning only the body | `journal.rs:951-966`, `:965` |
| **No vault exists to migrate.** No committed `.antseal` directory, no vault fixture; every test vault is minted fresh under `temp_dir()`, asserted by `zz_shared_vault_lives_in_temp_space` | `tests/common/mod.rs:100-118`; `tests/work_store.rs:790-794` |
| Export/import carry anchor slots **opaquely**: `list_anchors` → `get_anchor` with no filter and no allowlist, name-sorted, one AEAD, one atomic directory rename | `vault/export.rs:793-800`; import validation at `:490` |
| **The D43 cache exclusion does not touch anchors.** The `complete` guard is scoped to journal entry keys ≥ `UNIT_ENTRY_BASE`; the anchors loop that immediately follows has no guard, and anchors are a separate on-disk area (`anchors/<slot>` vs `journal/<entry>`) | `vault/export.rs:777-791` vs `:793-800`; proved by `tests/vault_export.rs:181-188` writing anchors **only** on `Complete` works and asserting they survive |

That last row corrects a standing note that U12 applies D43 §3's exclusion to
the anchor area. It does not.

---

## 2. The options, and what kills each

### (a) A new `ots-upgrade` slot family — the register's lean. Four kills.

**K1 — it does not avoid a schema change; it relocates it onto the mirror
rule.** A record in the new slot needs a shape. If it is an `AnchorArtifact`,
it needs a third `ArtifactKind`, and `from_wire` is closed at 0/1 — tag 2
yields `corrupt("unregistered anchor-artifact kind")` → `VaultAuthFailure`,
the *same* false-tamper diagnostic that (b) was rejected for. If it is a new
record type, it is a second codec in the same area with its own version
question. The strict-unknown-**kind** rule bites (a) exactly as hard as the
strict-unknown-**key** rule bites (b). (a)'s headline advantage is not real.

**K2 — the ordinary resume path manufactures a false `invalid`.** This is
U49's twin, and it is worse than U49. A work killed at `Staged` already has
its anchor slots filled (`journal.rs:812-816`), and resume re-runs the gate
and rewrites `ots-pending` from a *fresh* submission (`resume.rs:382-384`).
Under (a), `ots-upgrade` from an earlier hook survives that rewrite —
nothing clears the area. The next `--upgrade` then reads
`upgrade = anchor.upgrade.clone()` = `Some(stale)` (`ots/engine.rs:371`),
and `if upgrade.is_none()` is **false**, so `confirm_header` is skipped
entirely (`:451-470`). The vault ends up holding a genuinely upgraded
artifact paired with the **previous submission's** header: `committed` is
false, no pending branch survives, and the verdict is
**`Invalid` / `anchor-ots-header-uncommitted`** — a false accusation against
an honest sealer, produced by the storage layer. Under one record the state
is unrepresentable, because the group cannot outlive the artifact it was
written with.

K2 also falsifies a committed premise. `put_anchor`'s own doc
(`journal.rs:813-816`) justifies the resume overwrite with *"nothing
downstream has read them yet."* U24's hook reads and **rewrites** anchor slots
on every invocation, for any work, independent of seal state — so once U24
exists that premise is false, and the resume gate is overwriting slots another
subsystem has already advanced. Under the ruling the overwrite is at least
total and clean (whole record, group included). Under (a) it is the mixed
state above. The remaining loss — a completed Bitcoin attestation discarded by
a resume, and a fresh submission meaning a **new** commitment rather than a
re-pollable one — is real under both and is recorded as U57.

**K3 — the crash window is order-sensitive and one order is unrecoverable.**
Artifact-first, a crash between the two `put_anchor` calls lands exactly on
§1.2's un-nagged, un-rescuable `internally-consistent-only`. Group-first is
recoverable (the old artifact still carries its pending branch, so O5 fires
and the next poll re-merges). So (a) is *survivable*, but only under a
normative write order — a rule that lives in a comment and that a future
refactor breaks silently. One record needs no rule.

**K4 — it falsifies two committed doc comments.** `AppliedUpgrade.upgrade`'s
*"[r]ecorded **together** … or not at all"* (`ots/engine.rs:157-159`) cannot
be honoured by two writes; and `AttestedHeaderMissing`'s *"which the atomic
recording rule makes unreachable from this engine"* (`:511-514`) becomes
false.

**What (a) genuinely buys, recorded honestly:** a self-describing slot
listing — `ots-upgrade` present means "upgraded" without decrypting anything.
That is also a small **cost**: slot names are filenames and sit *outside* the
vault AEAD (D42 put "everything else inside"), so (a) publishes a new
anchor-*state* bit to anyone with filesystem read access. Incremental — the
`tsa-<n>` count already leaks — but the ruling adds no such bit at all.

**Cost neither option pays, contrary to the brief's premise:** (a) does
*not* ride export for free in the sense that matters. It rides the D47 path
for free (measured: no `EXPORT_FORMAT_VERSION` bump, grammar-only validation
on both sides, pairing preserved inside one AEAD under one atomic rename) —
but the two committed **exact-vector** slot-set assertions,
`tests/anchor_stage.rs:324` and `tests/vault_export.rs:278`, must be extended
by hand for any test that upgrades a work. Under the ruling the slot set never
changes and neither is touched.

### (b) New keys under `AnchorArtifact` at version 1 — kill: the wrong sentence

Adding keys 4/5/6 while leaving the version at 1 makes an older build report
*"vault authentication failed: wrong passphrase, or the vault store or header
has been modified or corrupted"* (exit 12) for a record that is merely newer.
That is the exact distinction the version field exists to draw, and the
decoder's own message would become a lie (`"strict v1 schema"`). (b) is not
wrong in substance; it is **incomplete without (c)**.

### (c) A version bump — not a kill: the measured price is two edits

The brief's framing — *"a whole-vault-format event by its own doc"* — is
measurably wrong twice. `SEAL_JOURNAL_VERSION` is **not** the vault format
version (`VAULT_FORMAT_VERSION`, `vault/header.rs:65`), and it is one of six
constants whose independence the tree states in source
(`export.rs:179-181`: *"Its OWN series, deliberately decoupled"*). A bump
does not invalidate the export format, the meta record, the bookkeeping
record or the receipt record.

The price, measured in full (§1.3): **zero committed artifacts regenerate,
zero tests fail, there is no migration to write, and there is no vault to
migrate.** The three record classes that get a version they did not need pay
nothing, because the refusal a v1 build would give is over-strict and
**has no victim** — no build has shipped, so the first release is at v2.

The one real hazard is not the bump but its invisibility: `open_envelope`
discards the version (`journal.rs:965`), so after a bump v1 bytes flow into
the v2 parser with nothing to branch on. For **this** change that is exactly
right — the added keys are optional and absent-means-`None`, which is the
correct v1 reading — but it is right by luck of shape, not by construction.
Rider 8 closes it.

### (d) Adopt `OtsCaptureRecord` — kill: it has no artifact field

`OtsCaptureRecord` is `{anchor_digest, calendars, upgrade}`
(`crates/antseal-core/src/anchor/model.rs:1030-1036`) — **there is nowhere to
put the `.ots` bytes.** Adopting it therefore means a second record beside
`ots-pending`, so (d) *is* (a) and inherits K2, K3 and K4 wholesale. It is not
the intended home; it is A2's model of the sealer's capture *log*. It is also
genuinely unused: zero production callers workspace-wide, constructed only in
`model.rs`'s own test module at `:1557`. Adopting its `upgrade` field would
put the same fact in three places (bundle `OtsAnchor`, vault record, capture
record). Recorded as discovered work (U55) rather than settled here.

### (e) One record: keys 4/5/6 on the anchor-artifact record, plus (c)

The ruling.

---

## 3. Ruling

**The upgrade group lives in the existing `ots-pending` slot, as three new
keys on the anchor-artifact record. `SEAL_JOURNAL_VERSION` goes 1 → 2 in the
same commit. No new slot name is minted, and D47 is untouched.**

What carries it, in one line: **`WorkStore::put_anchor` is already atomic
(temp + fsync + rename), so one record makes D79's "together or not at all"
a property of the filesystem instead of a property of a comment** — and every
torn, stale and unrescuable state enumerated in §1.2 and §2 becomes
unrepresentable rather than merely rare.

---

## 4. Riders — normative, cite by number

**R1 — the group is keys 4/5/6, all-or-nothing, and the rule is copied not
reinvented.** `4 = block_height (u64)`, `5 = block_header (bstr, exactly 80)`,
`6 = fetch_date (u64)`. Decode enforces all-three-or-none and reports the
**lowest-numbered absent** key, mirroring `OtsAnchor::decode`
(`bundle/schema.rs:585-601`) so the vault and the bundle agree on the D79
partial-group verdict. A wrong-length header is refused by length, as
`FixedLenField::BlockHeader` does. Reuse `antseal_core::bundle::schema::OtsUpgrade`
as the in-memory type — it is what the engine already produces and what the
bundle already consumes; do not mint a second struct.

**R2 — the group is legal only on `kind == OtsPending`.** A `TsaToken` record
carrying keys 4/5/6 is corrupt and is refused by its own message. The
kind and the group are in one record; that check costs one line and closes a
cross-family confusion the two-slot shape could not even express.

**R3 — one write site, and it is `pipeline/anchors.rs`.** The engine refuses
to touch the vault (*"The vault is U's"*, `ots/engine.rs:49-56`), so U owns
the write. It belongs in `pipeline/anchors.rs` because that module already
owns the slot names, the record codec, and `pub(super)` access to
`envelope`/`open_envelope`. Add one function there —
`pub fn apply_upgrade(journal: &dyn SealJournal, seal_id: &SealId, slot: &str, prior: &AnchorArtifact, applied: &AppliedUpgrade) -> Result<(), JournalError>`
— performing exactly **one** `put_anchor`. **U23 and U24 both call it and
neither writes an anchor slot by any other path.** A test enumerates the
`put_anchor` call sites and asserts there are exactly two (the seal/resume
loop and this one).

> **Amended twice on 2026-08-07, both by measurement.**
>
> 1. **The signature is wrong.** D99 R10 supersedes it: `apply_upgrade` takes
>    `&WorkStore<'_>` and `&mut R`, **not** `&dyn SealJournal`. U24's hook runs
>    at the end of `main_entry` and takes the vault lock itself; it has no
>    journal, and `VaultJournal::new(` is scan-restricted to `seal_session.rs`,
>    so a `&dyn SealJournal` parameter would make the hook literally unable to
>    call this function. Verified independently before complying.
> 2. **"exactly two" is false** — there are four textual sites, two of which
>    author records. See the correction under U56 in §7 for the enumeration and
>    for what the landed test asserts instead.
>
> The rest of R3 — one write site, one `put_anchor`, no other path to an anchor
> slot — stands, and is what D99 R3's compare-and-set was then layered onto.

**R4 — key 2 keeps the original submission's fetch date; the upgrade's date
is key 6.** They are different facts (A32 provenance for the capture vs. the
header fetch), and both are "recorded, never compared". The write is
therefore a **read-modify-write**: read the current record, replace the bytes
and set 4/5/6, keep key 0/1/2. This is why **U47 is a hard predecessor of
U23**, not merely a tidiness task — there is no correct blind write.

**R5 (brief rider 2) — the upgrade write must pin `fetch_date` and never read
a clock.** Use `applied.upgrade.fetch_date()` verbatim; it is a parameter all
the way down (`upgrade_pending(…, fetch_date)` → `confirm_header(…, fetch_date)`).
This **partially discharges U48 and sharpens the rest**: after this change one
record carries two fetch dates, key 6 pinnable and key 2 not
(`resume.rs:403-408` reads `SystemTime::now()`). That is a worse inconsistency
than U48 records, not a better one, and it is inside a single record a golden
vector would have to cover. **U48's remedy is narrowed to one of its two
options**: thread the pinned date through — `ctx.anchors.fetch_date` already
exists and already reaches the gate (`seal_run.rs:434-436`), and
`artifacts_of` already takes the date as a parameter (`anchors.rs:186-189`);
only `resume.rs:382` passes a clock read instead. Recording
`OtsCalendarSubmission::submitted_date` instead is **rejected** — it lives on
a record with no artifact field (§2(d)). **U48 blocks A22's OTS-slot vector.**

**R6 (brief rider 1) — the group must be persisted at M2. Yes, and the reason
is not the bundle.** `OtsAnchor::new` takes an `Option`, so reveal does not
require it. What requires it is that not persisting makes a *successful*
upgrade strictly destructive: `pending` → `internally-consistent-only`,
un-nagged (`NagState::AttestedOnly`), with `--online` structurally unable to
help because `agreed` is derived from `upgrade` (`verdicts.rs:735`). No
implementation may treat the group as optional-to-store, and no code path may
write the upgraded artifact without it.

**R7 — the slot set does not change, and the module docs must say why.**
`ots-pending` names the **family**, not the state; an upgraded artifact stays
in it. `pipeline/anchors.rs`'s module docs currently claim the names are
*"chosen so a slot listing is self-describing without decrypting anything"* —
amend that sentence to state that the OTS slot names the family only, and that
the upgrade state is deliberately **inside** the AEAD.

**R8 — the version bump lands with its own reasoning and its own test.**
`SEAL_JOURNAL_VERSION = 2`, and the decoder's doc records why v1 bytes are
safe under the v2 parser: the added keys are optional and absent-means-`None`,
which is the correct v1 semantics. Add the test that proves it —
a v1-envelope record with keys 0..3 decodes to `upgrade: None`. This is the
rider that stops the bump being invisible to CI (§1.3: there is no journal
golden vector, no fuzz target and no freeze-script coverage).

**R9 — the tamper matrix gains four rows and one message edit.** In
`pipeline/anchors/tests.rs`:
1. keys 4 and 5 present, 6 absent → the D79 partial-group error naming key 6;
2. keys 5 and 6 present, 4 absent → the same, naming key 4;
3. key 5 present at 79 and at 81 bytes → refused by length;
4. keys 4/5/6 on a `TsaToken` record → refused (R2).
   And the verbatim needle at `:124` changes from `"… (strict v1 schema)"`; pick
   a message that does not carry a version number, so the next bump does not
   silently invalidate the assertion. `a_future_version_refuses_distinctly`
   (`:166-179`) needs no edit — it is written against the constant.

**R10 — `anchor_index` is never re-resolved.** `AppliedUpgrade.anchor_index`
indexes into `PendingWork::ots`, a `Vec` the **reader** built; it is not a slot
name. The apply site must map index → slot through the *same ordered list the
read produced*, in one call, never by re-listing the directory. Today the list
is always length ≤ 1 (`ots-pending` is the only OTS slot), so this is
latent — assert the invariant rather than relying on it.

**R11 (brief rider 3, second half) — U49's remedy is now free of this
constraint, and gains one fact.** Under the ruling the OTS twin of U49 does
not exist: resume overwrites the whole record, group included. U49 may
therefore still choose either of its two remedies for the `tsa-<n>` family.
**Under (a) that would not have been true** — keying by endpoint would have
left `ots-upgrade` orphaned, so only "clear the area" would have worked.
Record the counterfactual in U49 so a later reversal of this decision does not
silently re-open it.

**R12 — the stale exemplar.** `tests/exit_codes.rs:274-278` hard-codes
`VaultNewerVersion { found: 2, supported: 1 }`, snapshot-pinned at
`tests/snapshots/cli-errors.display.txt:44`. It does **not** go red on a bump,
so it drifts from the shipped message (which reads `supported: SEAL_JOURNAL_VERSION`,
`journal.rs:624`). Update it in the same commit, or the reviewed error copy
stops describing the product.

---

## 5. What binds, what merely gestures

- **D79 gestures.** Its own §Scope says *"The parse rule only"* — it governs
  the **bundle** decoder, not the vault. What binds at the vault layer is the
  engine's `AppliedUpgrade` doc (`ots/engine.rs:157-159`) and
  `AttestedHeaderMissing`'s (`:511-514`). R1 nonetheless makes the vault rule a
  copy of D79's, so the two decoders cannot disagree about a partial group.
- **D42 binds.** Anchor artifacts are inside the AEAD and the hook runs iff the
  host command already holds an unlocked handle — so the upgrade write can
  never introduce a passphrase prompt, and R7's "state stays inside the AEAD"
  is D42's boundary applied to a new fact.
- **D47 is untouched.** The ruling mints no slot name and changes no export
  key, type or ordering. Measured for the counterfactual anyway: (a) would
  also have needed no `EXPORT_FORMAT_VERSION` bump.
- **D84 gestures.** It scopes *artifact-internal numeric limits*; the block
  header is a fixed 80 bytes, so no cap is minted and no freeze surface moves.
- **D45 binds only through the resume path**, which is where K2 lives.

---

## 6. Amendments (orchestrator applies at source)

1. **`tasks/U.md` U48** — replace *"Thread the stage's pinned date through, or
   record A2's per-calendar `submitted_date` instead"* with the first option
   only, per R5, and add: *"D97 R5: after the upgrade group lands, this record
   carries two fetch dates, one pinnable and one not. U48 blocks A22's OTS-slot
   vector."*
2. **`tasks/U.md` U49** — append R11's counterfactual.
3. **`tasks/U.md` U47** — append: *"D97 R4 makes this a hard predecessor of
   U23: the upgrade write is a read-modify-write, so there is no correct blind
   write without this reader."*
4. **`tasks/U.md` U23** — its `Do` says *"persisting upgraded `.ots` (with
   embedded header + fetch date) back into the record store"*. That is now
   specified: one record, one `put_anchor`, keys 4/5/6 (D97 §3, R1, R3).
5. **`crates/antseal-cli/src/pipeline/anchors.rs` module docs** — R7.
6. **`crates/antseal-cli/src/pipeline/journal.rs:94-96`** — the
   `SEAL_JOURNAL_VERSION` doc says *"Bumping it is a vault-format event."* Add
   the measured scope: it governs four record classes in two files, it is not
   `VAULT_FORMAT_VERSION`, and a bump invalidates neither the export format nor
   the meta, bookkeeping or receipt records.
7. **`crates/antseal-anchor/src/ots/engine.rs:511-514`** — after this
   decision, `AttestedHeaderMissing`'s *"unreachable from this engine"* is true
   of the whole write path, not only of the engine. Say so; it is now a
   structural claim rather than a hopeful one.
8. **`crates/antseal-cli/src/pipeline/journal.rs:813-816`** — *"nothing
   downstream has read them yet"* is the stated reason the resume overwrite is
   safe, and **U24 falsifies it**. Amend to: the overwrite replaces the whole
   record atomically, so no mixed state is reachable; what it may discard is a
   completed upgrade another subsystem recorded (U57).

---

## 7. Residual risks and revisit triggers

- **Read-modify-write under concurrency.** Two antseal processes upgrading the
  same work could lose one write. The vault lockfile (U9) is the mitigation;
  it was **not** re-verified for this decision and is flagged as assumed.
  Trigger: any report of a lost upgrade, or any change to the lock scope.
  Worst case is benign — a re-pollable artifact, never a torn record, because
  each write is individually atomic.
- **`AttestedHeaderMissing` becomes genuinely dead code** for engine-produced
  vaults. That is the intent (it stays as the owner-edited-vault reporter), but
  a state no path reaches is a state no test exercises. Keep the unit test that
  constructs it directly; do not delete the variant.
- **The bump is invisible to CI.** R8's test is the only thing standing between
  a v2 constant and a parser that never notices. Trigger: the next journal
  schema change — if it is not additive-optional, `open_envelope` must return
  the version first (U54).
- **`AppliedUpgrade.upgrade`'s unreachable `None`** (§1.2) is a control-flow
  property, not a type property. If the engine ever gains a path that pushes
  without a confirmed header, the write site must refuse rather than write an
  artifact with no group — R6 is what it would be violating. Trigger: any edit
  to `ots/engine.rs:451-484`.
- **Assumed, and flagged:** no `cargo` command was run for this decision. The
  machine is 2-core with other lanes staged, and the ruling rests on reading
  control flow and record schemas, not on a build. The implementing lane must
  confirm that the four record classes still round-trip at v2 and that the two
  version tests stay green unchanged.

---

## 8. Discovered work

Ids allocated from this planner's block: **U53–U57**, **Q116**. Six used.
All must be registered in `TODO.md`, including those cited only in prose
above (the Q85 rule).

### U53 — The `--upgrade` write path's kill-and-resume matrix
- Milestone: M2 | Size: S | Deps: U23, U47, D97
- Discovered by: **D97 §2 K2/K3** (2026-08-06)
- Problem: the ruling makes the torn state unrepresentable *by construction*.
  That claim is worth exactly as much as the test that plants the fault.
- Do: kill between the read and the write, and after the write; assert the
  record is either wholly old or wholly new, never mixed. Plant the fault by
  restoring a two-write representation (write the artifact, then the group)
  and prove the matrix goes red naming `internally-consistent-only`.
- Accept: the planted two-write fault reddens; the honest path never produces
  `OtsAnchorState::AttestedHeaderMissing`; native and wasm32 are irrelevant
  here (CLI-only), so native alone.

### U54 — `open_envelope` throws the version away
- Milestone: M2 | Size: XS | Deps: D97 R8
- Discovered by: **D97 §1.3** (2026-08-06)
- Problem: `journal.rs:965` returns only the body, so no decoder can branch on
  the version. Today that is safe because every schema change so far has been
  additive-optional; the guard is a ceiling, not a dispatch, and the first
  non-additive change will feed v1 bytes to a parser that cannot tell.
- Do: return `(version, body)` (or a small `Versioned<'_>`), and have each
  decoder state in one line why it accepts every version at or below the
  constant.
- Accept: a v1 record and a v2 record are distinguishable at the decoder; the
  four existing decoders compile unchanged in behaviour.

### U55 — `OtsCaptureRecord` has no production caller
- Milestone: M2 | Size: XS | Deps: none
- Discovered by: **D97 §2(d)** (2026-08-06)
- Problem: `anchor/model.rs:1030-1036` is constructed only by `model.rs`'s own
  test at `:1557`. Its `upgrade` field would, if ever adopted, make three
  homes for one fact.
- Do: decide — give it a caller (the per-calendar `submitted_date` is the one
  datum nothing else records) or delete it and fold `OtsCalendarSubmission`
  into whatever does record submissions. D97 rules only that it is **not** the
  home for the upgrade group.
- Accept: either a production caller exists, or the type is gone and A2's
  `Do` row is amended to say why.

### U56 — Nothing asserts the `put_anchor` call-site count
- Milestone: M2 | Size: XS | Deps: U23, D97 R3
- Discovered by: **D97 R3** (2026-08-06)
- Do: a test enumerating `put_anchor` call sites in `crates/antseal-cli/src`
  and asserting exactly two (the seal/resume loop and `apply_upgrade`). The
  single-write-site rule is the whole of the atomicity argument, and it is
  currently a comment.
- Accept: adding a third call site reddens the test by name.
- **Corrected 2026-08-07, by the lane that implemented R3**: "exactly two" is
  measured **false**, and was false before this decision. There are **four**
  textual `put_anchor` sites — the seal/resume loop, `apply_upgrade`,
  `vault_journal.rs`'s `SealJournal::put_anchor` trait impl forwarding to the
  store, and `vault/export.rs`'s D47 import reinstalling exported slots
  verbatim. §1.3 of this document *records that import path itself* and the
  rider still said two. The landed test therefore asserts the **classified
  four-element set**, not a count, so what U56 inherits is true. The semantic
  rule R3 was reaching for — exactly two sites that *author* a record — is
  intact and is what the classification encodes.

### U57 — A resume discards a completed OTS upgrade, and the calendar cannot re-issue it
- Milestone: M2 | Size: S | Deps: U22, U24, D45, D97
- Discovered by: **D97 §2 K2** (2026-08-06)
- Problem: the resume gate rewrites `ots-pending` from a **fresh** submission
  (`resume.rs:382-384`), and `put_anchor`'s stated justification — *"nothing
  downstream has read them yet"* (`journal.rs:813-816`) — is false once U24's
  hook exists, because the hook advances anchor slots on every invocation for
  any work regardless of seal state. A resume therefore throws away a Bitcoin
  attestation the hook already obtained, and the replacement submission carries
  a **new** commitment, so the discarded work is not re-pollable — it is a
  fresh multi-hour wait.
- Do: decide whether the hook skips works below `SealState::Paid` (their
  anchors are provisional and the gate will re-run them), or whether the
  resume gate reuses an existing verified submission instead of re-submitting.
  Either answer is a rule; the current behaviour is neither.
- Accept: the kill-then-resume matrix covers a work whose OTS anchor was
  upgraded between the kill and the resume, and asserts the chosen rule; the
  opposite behaviour is planted and proven red.
- Notes: D97 rules only that the overwrite is *clean* under one record. It does
  not rule the policy.

### Q116 — The `strict v1 schema` needle carries a version number
- Milestone: M2 | Size: XS | Deps: D97 R9
- Discovered by: **D97 R9** (2026-08-06)
- Problem: `pipeline/anchors/tests.rs:124` and `journal.rs:401` assert error
  strings containing the literal `v1`. Every future bump silently invalidates
  them, and the cheapest repair is editing the needle.
- Do: drop the version token from both messages, or assert it against the
  constant.
- Accept: a bump requires no edit to either needle.

---

## Index row (orchestrator applies at merge)

| [D97](D97-ots-upgrade-group-vault-home.md) | Where the OTS upgrade group lives in the vault — **one record, not two: keys 4/5/6 on the anchor-artifact record in the existing `ots-pending` slot, with `SEAL_JOURNAL_VERSION` 1 → 2 in the same commit.** The register's lean (a second `ots-upgrade` slot) is overturned on four measured grounds, and the decisive one is not the crash window: the **ordinary resume path** rewrites `ots-pending` from a fresh submission and leaves a stale group beside it, the engine then reads `upgrade = anchor.upgrade.clone()`, `if upgrade.is_none()` is false, `confirm_header` is **skipped**, and the vault holds a genuinely upgraded `.ots` paired with a previous submission's header — verdict **`invalid`/`anchor-ots-header-uncommitted` on an honest work**. (a)'s advertised "no schema change" is false: it relocates the change onto `ArtifactKind::from_wire`, closed at 0/1, whose tag-2 refusal is `Corrupt` → **`VaultAuthFailure`** ("wrong passphrase, or the vault … has been modified or corrupted", exit 12) — the same false-tamper diagnostic (b) was rejected for. (c) was measured rather than feared: **two literal edits, zero regenerated artifacts** — no committed fixture, golden vector or snapshot pins a journal version byte, no test asserts `== 1`, no migration machinery exists to write, and **no vault exists to migrate**; the "whole-vault-format event" framing is wrong twice, since `SEAL_JOURNAL_VERSION` is one of **six** independent constants and is not `VAULT_FORMAT_VERSION`. (d) dies on a fact: `OtsCaptureRecord` has **no artifact field**, so adopting it is (a) again — and it has zero production callers. **Rider 1 answered stronger than asked**: the group is not merely convenient but mandatory, because an upgraded artifact with no group renders `internally-consistent-only` (O9), is **un-nagged** (`NagState::AttestedOnly`, whose own hint says `--online` can help) and is **structurally unrescuable** — `agreed` is derived from `upgrade` (`verdicts.rs:735`), so no online evidence can ever reach it; `OtsAnchor::new`'s `Option` means reveal does not force it, which is why the bundle does not settle the question. **Rider 2**: the upgrade's `fetch_date` must be pinned from the parameter, which partially discharges U48 and **sharpens** the rest — one record, two fetch dates, one pinnable and one not — and narrows U48 to threading the pinned date (`ctx.anchors.fetch_date` already exists; only `resume.rs:382` reads a clock). **Rider 3**: one write site in `pipeline/anchors.rs`, a read-modify-write, which makes **U47 a hard predecessor of U23**. Also corrected: the D43 cache exclusion does **not** cover the anchor area (the `complete` guard is scoped to journal entry keys; `tests/vault_export.rs` writes anchors only on `Complete` works and asserts they survive), and `put_anchor`'s *"nothing downstream has read them yet"* premise for the resume overwrite is **falsified by U24's hook**, which advances anchor slots on every invocation regardless of seal state — so a resume discards a completed attestation whose replacement submission carries a new, un-re-pollable commitment (U57). Discovered U53–U57, Q116 | RESOLVED (U23/U24/U47 execute) | 2026-08-06 |
