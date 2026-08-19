# D151 — the copy is wrong and the refusal stands, but its stated authority is inverted: D47 mandates the opposite of what ships, and the false claim has eight source occurrences in four classes, not three

- **Status: RESOLVED. The lean's DIRECTION survives and its stated REASON is
  overturned, together with its site count.** The lean was *"the refusal stands
  (D47's format limit is sound), so fix the copy at all three sites and re-bless
  the golden."*
  - **"The refusal stands" SURVIVES**, on a measurement neither the row nor the
    lean contains: the wrap flag would have to live in the export **header**,
    which is read before any key exists, and the header body v1 is
    `map {0: kdf_block, 1: nonce}` with no slot for it. The payload *does* carry
    `wrap_mode` (key 1) — but the payload is inside the AEAD, so a reader cannot
    learn from it that a keyfile is needed without already holding the key the
    keyfile helps derive. Carrying the wrap is therefore a header event, i.e. a
    **D47 format event**, exactly as `export.rs:30-59` says.
  - **"D47's format limit" is OVERTURNED — D47 says the opposite.**
    `docs/decisions/D47-vault-export-format.md:78-86` reads *"**Keyfile factor
    preserved**: the exported wrap-mode record is carried as-is, so an export of a
    keyfile-wrapped vault requires the same keyfile at import"*, and its §Spec
    conformance (`:250-255`) says *"no divergence"*. The shipped refusal is a
    **deliberate overturn of D47**, recorded in U8's TODO row (`TODO.md:398`,
    deviation 1) and in `export.rs`'s module docs — and **never written into D47
    itself**, which still asserts the opposite in the tree today. The code comment
    at `export.rs:737-741` cites *"the module docs' overturned-U8 section"*, not
    D47; the row's *"it is D47's format limit"* is the row's own gloss and it is
    backwards.
  - **"all three sites" is OVERTURNED: there are eight source occurrences of
    `antseal vault export`, in four classes, and they do not share a scope, an
    audience or a freeze.** Three are class-aware (this act). Two are
    class-**blind** by construction and sit inside `json-envelopes.txt` and
    `cli-errors.display.txt` — moving them re-blesses the machine-mode contract,
    which must not ride an S-sized copy row. One is true by construction. One is
    unpinned by any test or snapshot. §1.3 is the census.
  - **The arm nobody listed: the fourth class-aware site is not copy, it is a
    behaviour defect.** `export_nag()` (`bookkeeping.rs:257-266`) opens *"NO
    BACKUP YET — this vault has never been exported"* and `exports` is
    incremented at exactly **one** production site (`commands.rs:810`), after a
    successful export, plus the import path (`export.rs:1120-1126`) which itself
    refuses wrapped payloads. So a keyfile-wrapped vault can **never** record a
    backup: the nag fires on **every seal, forever**, and instructs a command
    that refuses. That is the failure U18's own row named — *"a warning that
    cannot be satisfied teaches the reader that antseal's warnings are noise"*.
  - **MVP-SPEC.md line 143 dictates the OBLIGATION, not the words** (§1.2,
    quoted verbatim), so `LOSS_WARNING`'s wording is free and this is an ordinary
    copy change plus a freeze event — **not** a spec divergence. What *is* a spec
    divergence is the thing underneath: line 143 promises `vault export`/`import`
    **and** a keyfile wrap, and shipped antseal makes them mutually exclusive.
    That is flagged, not silently taken — **Q251** is the collector that already
    exists for line-143 divergences and it gains a fifth clause (R15).
- **Date: 2026-08-18**
- **Owning task: U84** (M4, size S). **Blocks: U32** — the release snapshot
  freeze, which U84 is ordered before precisely because U78's golden now pins the
  false sentence. Consumes U78 (the golden), U8/D50 (the wrap), U12/D47 (the
  export format), U18/U34 (the nag and its bookkeeping slot), D148 §3.5 and §4.3.

## 0. What was measured against

Tree at `2eb03d7`, clean at the start of this lane. No Rust source was modified
by this lane; nothing was built. Every locator below was re-measured with `awk`
line numbering or `grep -n` against HEAD, and the four the brief supplied are
reported with their verdict in §1.9.

---

## 1. What was measured

### 1.1 The refusal, its reasoning, and the record it silently overturns

`crates/antseal-cli/src/vault/export.rs:737-756` — locator **confirmed**:

```
737   // Refuse before a single record is read (the module docs' overturned-
738   // U8 section): a v1 export of a wrapped vault would be a
739   // passphrase-only backup of a two-factor vault, and a backup that is
740   // weaker than the thing it backs up is worse than no backup, because
741   // the user believes they are covered.
742   let header_wrap = VaultHeader::decode(vault.header_bytes())
745   if header_wrap != WRAP_MODE_NONE {
746       return Err(CliError::Usage { message: format!(
749          "... the v1 export format cannot carry a second factor — the backup file is
751           ... Back up the vault directory and the keyfile separately by hand until
753           the export format carries the wrap (nothing was written)" ) });
```

The import direction is the same rule at `:520-535`. The module docs state the
overturn outright (`export.rs:30-59`, *"# A keyfile-wrapped vault is refused, not
exported (U8, overturned)"*), and `TODO.md:398` records it as U8's deviation 1:
*"**U8's 'D47's export carries the keyfile factor unchanged' is overturned**"*.

**What no one wrote down.** `docs/decisions/D47-vault-export-format.md` still
says, in the normative §Format:

> - **Keyfile factor preserved**: the exported wrap-mode record is carried
>   as-is, so an export of a keyfile-wrapped vault requires the same keyfile at
>   import — U12's Accept verbatim […]. The keyfile is a portable file by design
>   (D50); nothing machine-bound exists at M1 […]

and in §Spec conformance: *"Option B satisfies all three; **no divergence**"*.
D47 carries one amendment (2026-08-02, S29) and it is about journal entries. So
the record that the shipped code cites as its constraint is, on this point, the
record the shipped code **contradicts**. `docs/decisions/D50-os-keystore-scope.md:60-61`
inherits the same false premise (*"D47's export preserves wrap factors; that is
only sound because the M1 keyfile is portable"*) — its **conclusion** (no
keystore at M1) is unaffected and is only strengthened by the refusal.

### 1.2 MVP-SPEC.md line 143, verbatim, and what it actually requires

`sed -n '143p' MVP-SPEC.md`, the two clauses that bear on this row:

> `vault export`/`import` for encrypted backup.

> **Docs and CLI must nag on both failure modes**: *loss* (lose the vault and
> backup = lose reveal/restore ability forever; the sealed data itself stays
> safely unreadable) and *theft* (retroactive decryption of permanently public
> ciphertexts — no rotation exists; treat the passphrase and any export as a
> long-term high-value key).

**Three findings.**

1. **It dictates the obligation and the content, never the words.** No sentence,
   no command name, no ordering is prescribed. `LOSS_WARNING`'s wording is
   therefore free, and changing it is an ordinary copy change — it is a **freeze
   event** (U78's golden), not a spec divergence. The parenthetical *is* the
   content the loss half must carry, and the replacement in R3 carries all of it.
2. **The line's own loss condition is *vault and backup*; the constant's is
   *vault and passphrase*.** Both are true failure conditions and the constant
   has never stated the spec's exact one. R3's third sentence brings the word
   *backup* into the constant for the first time, which moves it **toward** line
   143, not away.
3. **The divergence is elsewhere and is real.** The same line promises
   `vault export`/`import` **and** *"a high-entropy keyfile / OS-keystore wrap
   for `W`"*. Shipped antseal makes the two mutually exclusive: choose the wrap
   at `init` and the backup command refuses you for the life of the vault. That
   is a line-143 divergence and the protocol says flag it — see R15.
   `MVP-SPEC.md:184` (*"export nag on first seal"*) is the authority for the nag
   itself and is likewise an obligation, not a script.

### 1.3 The site census: eight source occurrences, four classes

`grep -rn "antseal vault export" --include=*.rs crates/ | grep -v tests/`:

| # | site | class in scope? | frozen where | class |
|---|------|-----------------|--------------|-------|
| 1 | `vault/bookkeeping.rs:70` (`LOSS_WARNING`) | **yes** — both render sites (§1.4) | `init-report.txt` ×4 | **A** |
| 2 | `vault/bookkeeping.rs:260` (`export_nag`) | **yes** — `seal_run.rs:519` holds `session.vault()` | — | **A** |
| 3 | `vault/keyfile.rs:287` (`placement_guidance`) | **yes** — printed only on the keyfile branch | `init-report.txt:65` | **A** |
| 4 | `init.rs:607` (`existing_vault_refusal`) | **no** — fires on `header.exists()` alone (`init.rs:393-396`), the header is never decoded | `json-envelopes.txt:2` | **B** |
| 5 | `error.rs:573` (`ImportRefusedExistingVault`) | **no** — a `thiserror` Display over a `PathBuf`; no vault exists in the type | `cli-errors.display.txt:14`, `json-envelopes.txt:20` | **B** |
| 6 | `commands.rs:384` (no wallet record) | yes (`session.vault()` at `:380`) | **nothing** — in no snapshot and no test | **B′** |
| 7 | `error.rs:819` (export self-verify failed) | n/a | `cli-errors.display.txt:76` | **C** — true by construction: only an export that ran can reach it, so the vault is mode 0 |
| 8 | `bookkeeping.rs:353` | test assertion | — | test |

**Class A** is U84's subject and is fixed in this act; its only freeze is
`init-report.txt`, which U84's Accept row 2 already contemplates. **Class B** is
the same defect through a different mechanism — the message is produced where no
vault is in scope, so the fix is wording that is true for every class, and it
moves the **machine-mode envelope** and the **error-display snapshot**. Riding
two machine-contract re-blesses on an S-sized copy row is precisely the silent
freeze event this project keeps finding; class B goes to its own row (R14).

For class B the harm is *higher*, not lower: sites 4 and 5 both tell a user
holding a possibly-wrapped vault to export it *before wiping the directory*.

### 1.4 Both render sites of `LOSS_WARNING` have the wrap mode in scope

The brief's sharp objection — *a conditional constant needs a vault loaded at the
moment the warning is rendered* — is **false at both sites**:

- `init`: `standing_warnings()` (`init.rs:352-365`) takes no argument, but its
  only caller is `InitReport::render()` (`init.rs:266`), which branches on
  `self.keyfile` four lines earlier (`:262`). The class is the field `render()`
  already reads.
- `seal`: `export_nag()` (`bookkeeping.rs:257-266`) is called from
  `SealReport::render()` (`seal_run.rs:142-143`), and the flag beside it is
  computed at `seal_run.rs:519` as
  `!bookkeeping::load(session.vault())?.ever_exported()` — **`session.vault()` is
  in hand**, one `VaultHeader::decode(vault.header_bytes()).wrap_mode()` away
  from the class. `SealReport` is constructed in exactly two places
  (`seal_run.rs:501`, `machine_mode.rs:659`), so the field costs two edits.

Docs quote the constant byte for byte with a locator at `vault-loss.md:25`
(`bookkeeping.rs:68-70`), the nag block at `vault-loss.md:41-42`
(`bookkeeping.rs:257-266`), and `vault-theft.md:314`.

### 1.5 The wrapped vault can never record a backup: the nag is perpetual and unsatisfiable

`record_export` has exactly one production caller: `commands.rs:810`, reached
only after `export_vault` returned `Ok` and self-verified. The one other writer
of the slot is the import path (`export.rs:1120-1126`, *"an import always ends
with at least one recorded export"*), which refuses a wrapped payload at
`:520-535` and in any case installs a **fresh** vault. There is no third writer.

Therefore, for a keyfile-wrapped vault, `ever_exported()` is false forever,
`export_nag` is true on **every** seal, and the user is told on every seal to run
the one command that will not run. That is a behaviour defect wearing copy's
clothes, and it is the fourth class-A site.

### 1.6 What making the export carry the wrap would actually cost

Measured against the format, not assumed:

- **The flag would have to be in the header.** The export header body v1 is
  `map { 0: kdf_block, 1: nonce }` (`export.rs:11-14`) and is the AAD. The
  payload *does* carry `wrap_mode` at key 1 (`export.rs:65-68`) — but the payload
  is **inside** the AEAD. A reader cannot learn from it that a keyfile is
  required without first deriving the key that the keyfile participates in. So
  the payload slot D47 promised exists and is **write-dead**: after the refusal
  at `:745`, the second decode at `:758` can only ever yield `WRAP_MODE_NONE`.
- **A second key-combine path in the backup format**, mirroring
  `keyfile.rs:260-267`'s `HKDF-SHA256(salt = keyfile, ikm = passphrase-derived
  key, info = label)` — new crypto in the one artifact whose failure is
  discovered at disaster time.
- **An import-side keyfile channel that the canonical surface forbids.**
  `MVP-SPEC.md:149` names `vault export|import` with **no flags**, echoed at
  `cli.rs:462` (*"single re-encrypted file, no flags (D47)"*) and pinned in
  `cli-surface.help.txt:354-406`. On the D47 clean-machine drill the keyfile
  would have to be located by `ANTSEAL_KEYFILE` or by a path recorded in a file
  the reader cannot yet decrypt — a new failure mode on the disaster path.
- **New golden vectors and tamper-matrix rows**, per the house checklist, plus a
  D47 format event, at M4, with U32's release freeze pending.

Against that: the copy fix is four constants, two signatures, one golden and one
test. **The refusal stands.** It is not, however, "cheap because D47 says so" —
D47 says the opposite, and R2 repairs that.

### 1.7 The docs already tell the truth; the CLI is the only surface that lies

- `docs/user/vault-loss.md:167-181` — an entire section, *"## If your vault uses
  a keyfile, `export` refuses"*, with the exit code and the by-hand two-piece
  procedure, cited to `export.rs:745-756` and `:520-535`.
- `docs/user/vault-theft.md:219-224` — *"**`vault export` and `vault import` both
  refuse a keyfile-wrapped vault**"*, priced as a cost of the wrap.
- `docs/vault-keyfile.md:47-51` — *"therefore **refuses to export a
  keyfile-wrapped vault at all**"*.
- `docs/user/vault-loss.md:301` — the claim table row, with both locators.

Three shipped pages document the refusal as a deliberate, priced trade. Reversing
the refusal would falsify all three; fixing the copy aligns the CLI with them.
This is the decisive asymmetry between the two arms.

### 1.8 The golden, and exactly how it is blessed

`crates/antseal-cli/tests/snapshots/init-report.txt`, 77 lines / 7 281 bytes,
four sections (`════ init report — <network> — <no keyfile|keyfile> ════`).

- Producer: `render_report_surface()` (`init_command.rs:747-770`) builds four
  **constructed** `InitReport`s and calls the real `render()`.
- Bless: `the_init_report_matches_its_committed_golden` (`init_command.rs:775-790`)
  writes the file when `ANTSEAL_BLESS` is set, and otherwise byte-compares.
- Identity guard: `the_golden_carries_the_standing_warnings_by_identity`
  (`init_command.rs:800-844`) requires a **whole line equal to** `LOSS_WARNING`
  and to `THEFT_WARNING` in each of the four sections, requires
  `WALLET_CUSTODY_NOTE` immediately after the address line (D148 §2 R3), and
  asserts the section count is exactly 4.
- Live cross-check: `the_report_prints_the_address_and_the_networks_funding_copy`
  (`init_command.rs:869-914`) runs the real `run_init` for the three networks and
  compares byte for byte after structural substitution — and asserts
  `report.keyfile.is_none()`. **The keyfile section has no live cross-check**;
  that is a pre-existing hole, named in §4.
- Reach of the copy lint: `COPY_SCAN` carries
  `"crates/antseal-cli/tests/snapshots/"` as a directory entry
  (`check-copy-style.py:100`) with `.txt` in `COPY_SUFFIXES`, so the golden is
  scanned with no script edit — proven in wave 25 by a planted `notarizes`.

The four lines that move, measured: `init-report.txt:15`, `:33`, `:51`, `:74`
(`LOSS_WARNING`) and `:65` (the `placement_guidance` sentence).

**Precedent for how a re-bless is recorded.** `cli_surface.rs:81-88` reads *"the
rendered CLI surface differs from the committed snapshot …The surface is frozen
(U1): if this change is deliberate, regenerate with `ANTSEAL_BLESS=1` and justify
the diff in review."* U80 moved that snapshot and did **not** write itself into
the message: the message names the **freeze** (U1), and the **mover** is named in
the row. `init_command.rs:785-788` already names its freeze (*"MVP-SPEC.md line
143 mandates this copy and U78 pins it"*). R9 follows that precedent exactly.

### 1.9 The proposed copy, linted before it was written into this record

`docs/positioning-copy-style.md`'s executable half was loaded as a module and its
own compiled patterns (`NOTARY`, `PRIORITY`/`PRIORITY_QUALIFIER`, `AUTHORSHIP`/
`DISCLAIMER`, `PRODUCT_URL`) run over all five replacement strings in R3, R4, R6
and R7: **CLEAN on P1, P2, P3 and P6, all five.** `PRESENCE_SURFACES` is
`("README.md",)` only (`check-copy-style.py:256`), so no P7 presence clause and
no `OWED_PRESENCE` debt touches any of this copy.

### 1.10 Corrections to the brief and to the row

| claim | verdict |
|---|---|
| `export.rs:745-756` is the refusal | **confirmed** (`:745` predicate, `:746-755` message) |
| `export.rs:749-753` "cites D47's format limit" | **wrong.** The comment cites the module docs' overturned-U8 section (`:737-741`); D47 mandates the opposite (§1.1) |
| `bookkeeping.rs:68-77` for `LOSS_WARNING` | **confirmed**, though `LOSS_WARNING` alone is `:68-70` and `:74-77` is `THEFT_WARNING` (the docs cite `:68-70`) |
| `keyfile.rs:286-290` for the sentence | **off by one at the head**: the `format!` opens at `:286`, the string at `:287-289`, the arm closes `:290`. Cite `keyfile.rs:287-289` |
| `keyfile.rs:404-414` for the guard | **confirmed** (`fn` at `:404`, the self-comparing assert at `:412`) |
| "one act covering all three sites" | **overturned** — eight occurrences, four classes (§1.3), and the class-aware set is four sites, not three |
| "the refusal … is sound" | **survives**, on §1.6's header/payload measurement rather than on D47 |

---

## 2. Ruling

**Owner: U84**

### R1 — The copy is wrong; the refusal stands, and its reason is restated

`vault export`'s and `vault import`'s wrap refusals (`export.rs:745-756`,
`:520-535`) are **not touched**: not the predicate, not the message, not the exit
class, not the tests that hold them. Carrying the wrap needs a **header** field,
a second key-combine and an import-side keyfile channel the canonical surface has
no room for (§1.6) — a D47 format event, out of scope at M4 and refused here
(§3.1).

Every remaining ruling changes copy, never behaviour, with the single exception
of R6's branch, which changes *which* honest sentence a wrapped vault is shown.

**Verified by**: the refusal's existing test
(`vault_keyfile.rs:328-356`) stays green and unmodified, and R10's new test
asserts the refusal's verdict per class before it looks at any copy.

### R2 — `docs/decisions/D47-vault-export-format.md` gains a dated addendum

D47 asserts in the tree today the opposite of what ships. Landed by the U84
implementing lane in the same commit (a record that documents a format the code
contradicts is a trap for the next reader), appended after the existing
2026-08-02 amendment, verbatim:

> ## Amendment (2026-08-18, U84 / D151 §2 R2): the keyfile factor is NOT preserved — it is refused
>
> The §Format bullet **"Keyfile factor preserved"** and the §Spec-conformance
> sentence **"no divergence"** are both false of the shipped code and have been
> since U8 landed on 2026-08-02. `vault export` refuses any vault whose header
> wrap mode is non-zero (`crates/antseal-cli/src/vault/export.rs:745-756`) and
> `vault import` refuses any payload whose wrap mode is non-zero (`:520-535`).
> The overturn was deliberate, was argued at the site
> (`crates/antseal-cli/src/vault/export.rs:30-59`) and was recorded in U8's
> register row (`TODO.md:398`, deviation 1) — **but never here**, so this record
> has been read as the refusal's authority when it is in fact the thing the
> refusal overturns.
>
> **Why the factor cannot be preserved in v1.** The export's AEAD key is
> `KDF(passphrase, fresh salt)` — the passphrase **alone**, as this record's own
> §Format block says. A v1 export of a two-factor vault would therefore be a
> one-factor backup of a two-factor vault: the weakest link, believed to be the
> strongest. The payload's `wrap_mode` slot (key 1) exists, but the payload sits
> **inside** the AEAD, so no reader can learn from it that a keyfile is required
> before deriving the key the keyfile participates in. Carrying the wrap means
> putting it in the **header**, whose v1 body is `map { 0: kdf_block, 1: nonce }`
> and which is the AAD. That is a format event, unchanged in status by this
> amendment: **not taken at MVP.**
>
> **Consequences.** (i) The §Format "Keyfile factor preserved" bullet is
> superseded by this amendment in its entirety. (ii) §Spec conformance's *"no
> divergence"* is corrected: the conjunction MVP-SPEC.md line 143 promises —
> `vault export`/`import` **and** a keyfile wrap — does not hold, and the
> divergence is collected by **Q251**. (iii) `D50-os-keystore-scope.md:60-61`'s
> premise *"D47's export preserves wrap factors"* is likewise false; D50's
> **conclusion** (no keystore at M1) is unaffected and is strengthened, and its
> binding constraint on a future keystore wrap stands unchanged. (iv) The
> user-facing statement of the refusal is already correct and needs no repair:
> `docs/user/vault-loss.md:167-181`, `docs/user/vault-theft.md:219-224`,
> `docs/vault-keyfile.md:47-51`.

### R3 — `LOSS_WARNING` keeps the fact and loses the instruction

`crates/antseal-cli/src/vault/bookkeeping.rs:68-70`. Replace the constant with,
verbatim:

```rust
pub const LOSS_WARNING: &str = "  LOSS  — lose this vault and its passphrase, and no one can \
     ever reveal or restore your sealed works again. The sealed data itself stays safely \
     unreadable. Keep a backup of this vault somewhere else.";
```

Rendered (this is the exact line that must appear in the golden, four times):

```
  LOSS  — lose this vault and its passphrase, and no one can ever reveal or restore your sealed works again. The sealed data itself stays safely unreadable. Keep a backup of this vault somewhere else.
```

Only the final sentence changes; the two leading spaces, the `LOSS  — ` prefix
with its two internal spaces, and the first two sentences are byte-identical to
today. The constant stays **unconditional** and stays **one author for one
fact** — because after this change it states only the fact, which is true for
every wrap mode. The instruction, which is not, moves to R4.

Its doc comment (`bookkeeping.rs:60-67`) gains one sentence: *"The remedy is
NOT here: how you make that backup depends on the vault's wrap mode, so it is
[`BACKUP_BY_EXPORT`] / [`BACKUP_BY_HAND`] and the renderer picks by class
(D151 §2 R3/R4). A command named here would be false for every wrapped vault."*

**Verified by**: `the_golden_carries_the_standing_warnings_by_identity`
(identity, four sections) after R9's re-bless, and R10's biconditional.

### R4 — Two class-keyed backup constants, one author each

Added beside `LOSS_WARNING` in `crates/antseal-cli/src/vault/bookkeeping.rs`,
verbatim:

```rust
/// How the backup is made for a passphrase-only vault (wrap mode 0). One
/// author for both venues that give it: `init`'s closing report and the
/// first-seal nag (D151 §2 R4).
pub const BACKUP_BY_EXPORT: &str = "  BACK UP — run `antseal vault export` and keep the file \
     on different media from the vault: another disk, another machine, a safe. The keys to \
     everything you seal live in this one directory.";

/// How it is made for a vault with a keyfile (wrap mode 1). It deliberately
/// does NOT name `antseal vault export`: that command refuses this vault
/// (`crate::vault::export`, the overturned-U8 section), and naming it would
/// be the defect U84 exists to fix. The prohibition is mechanical and is
/// asserted — see `tests/vault_keyfile.rs`.
pub const BACKUP_BY_HAND: &str = "  BACK UP — this vault has a keyfile, so it is backed up by \
     hand, in two pieces kept apart: a copy of the vault directory and a copy of the keyfile. \
     There is no single backup file for a two-factor vault: it would be encrypted under the \
     passphrase alone, which is weaker than the vault it backs up.";
```

Rendered:

```
  BACK UP — run `antseal vault export` and keep the file on different media from the vault: another disk, another machine, a safe. The keys to everything you seal live in this one directory.
  BACK UP — this vault has a keyfile, so it is backed up by hand, in two pieces kept apart: a copy of the vault directory and a copy of the keyfile. There is no single backup file for a two-factor vault: it would be encrypted under the passphrase alone, which is weaker than the vault it backs up.
```

`BACKUP_BY_EXPORT` is deliberately near-verbatim today's `export_nag()` second
line (`bookkeeping.rs:260-262`): the diff is *"Run … now and put the file
somewhere else"* → *"run … and keep the file on different media from the vault"*.
This is a **net reduction** in authors — today `init` says *"Run `antseal vault
export` and keep the backup somewhere else"* inside `LOSS_WARNING` and `seal`
says a second phrasing of the same instruction; after this there is exactly one
per class, shared by both venues, which is what `bookkeeping.rs:63-67`'s
one-author doctrine asks for.

### R5 — `init`: `standing_warnings` takes the class

`crates/antseal-cli/src/init.rs:352-365`. Signature becomes
`pub fn standing_warnings(wrapped: bool) -> Vec<String>`, and the vector becomes:

```
"Two things to understand before you seal anything, and one thing to do:"
LOSS_WARNING
THEFT_WARNING
if wrapped { BACKUP_BY_HAND } else { BACKUP_BY_EXPORT }
""                                     // unchanged
"What a seal proves: …"                // unchanged, byte for byte
```

The lead-in gains `, and one thing to do` so that *"Two things"* keeps governing
exactly LOSS and THEFT and the instruction is not miscounted into them. The
positioning paragraph is **not** touched (P2's qualifier lives there).

`InitReport::render()` (`init.rs:266`) becomes
`out.extend(standing_warnings(self.keyfile.is_some()));`.

**This is not the conditional D148 §3.5 refused.** §3.5 refused branching on
`wallet_source`, on the ground that *"a conditional block means the golden covers
one branch and leaves the other unpinned, or U78 grows a second golden"*. The
predicate here is `self.keyfile.is_some()` — **the condition the golden already
sections on**. `render_report_surface()`'s four sections remain the whole branch
set, the section count assertion stays `4`, and no branch is left unpinned. R11
requires this reasoning to be written at the site so the next reader does not
read §3.5 as forbidding it.

Callers to update: `init.rs:266`, the unit test at `init.rs:794-811`, and
`crates/antseal-cli/tests/seal_command.rs:1184`.

### R6 — `seal`: `export_nag` takes the class, and stops making a promise it cannot keep

`crates/antseal-cli/src/vault/bookkeeping.rs:257-266`. Signature becomes
`pub fn export_nag(wrapped: bool) -> Vec<String>`:

```rust
pub fn export_nag(wrapped: bool) -> Vec<String> {
    vec![
        if wrapped {
            "  NO BACKUP RECORDED — a keyfile-wrapped vault is backed up by hand, and antseal \
             cannot see that you did it, so this stays on every seal."
        } else {
            "  NO BACKUP YET — this vault has never been exported."
        }
        .to_owned(),
        if wrapped { BACKUP_BY_HAND } else { BACKUP_BY_EXPORT }.to_owned(),
        LOSS_WARNING.to_owned(),
        THEFT_WARNING.to_owned(),
    ]
}
```

The mode-0 first line is **byte-identical to today**, which keeps
`docs/threat-model.md:593` true and keeps `anchor_stage.rs:419`'s
`take_while(|line| !line.contains("NO BACKUP YET"))` trim working — measured: no
test renders a wrapped seal report, so the trim's mode-0 marker is sufficient.
The wrapped line says the true thing (§1.5): the record cannot be satisfied, so
the nag says why instead of pretending the user has neglected something.

`SealReport` (`seal_run.rs:79-111`) gains one field:

```rust
/// The vault's wrap mode is non-zero (U8/D50), so `vault export` refuses
/// it and the backup is by hand. Read from the header, not inferred:
/// the backup advice must match what the command actually does (D151).
pub wrapped: bool,
```

set at `seal_run.rs:501-520` from
`VaultHeader::decode(session.vault().header_bytes())?.wrap_mode() != WRAP_MODE_NONE`,
and read at `seal_run.rs:142-143` as `export_nag(self.wrapped)`.

**It does NOT ride `--json`.** `SealReport::json()` (`seal_run.rs:250`) keeps
`"export_nag": self.export_nag` and gains nothing, so
`crates/antseal-cli/tests/snapshots/json-envelopes.txt:34` stays **byte-identical**
and no machine-contract re-bless happens in this act. The consequence — a
scripted consumer cannot tell an actionable nag from an unactionable one — is
named in §4 and handed to the class-B row, where the envelope moves anyway.

Callers to update: `seal_run.rs:143`, `bookkeeping.rs:347-359` (unit test), and
the fixture `machine_mode.rs:659-721` (add `wrapped: false`; the exemplar keeps
`export_nag: true`, whose reason is recorded there and is unchanged).

### R7 — `placement_guidance`'s fourth line stops describing the export

`crates/antseal-cli/src/vault/keyfile.rs:286-290`. Replace the `format!` arm
with, verbatim:

```rust
        format!(
            "  Back it up separately too: a copy of the keyfile, on different media from the \
             vault, is the second half of this vault's backup. Override its location for a \
             single run with {KEYFILE_ENV}=<path>."
        ),
```

Rendered (this is `init-report.txt:65` after R9):

```
  Back it up separately too: a copy of the keyfile, on different media from the vault, is the second half of this vault's backup. Override its location for a single run with ANTSEAL_KEYFILE=<path>.
```

It now says only what is true of the **keyfile** and makes no claim about any
command. *"the second half of this vault's backup"* is what ties it to
`BACKUP_BY_HAND`'s *"two pieces kept apart"*, eleven lines below on the same
screen, which is where the vault-level instruction belongs.

### R8 — What must NOT be touched in this act

1. `export.rs:745-756` and `:520-535` — predicate, message, class, tests.
2. `SealReport::json()` and `crates/antseal-cli/tests/snapshots/json-envelopes.txt`.
3. `crates/antseal-cli/tests/snapshots/cli-errors.display.txt`, and therefore
   `error.rs:570-574` and `error.rs:817-819`.
4. `init.rs:602-611` (`existing_vault_refusal`) and `commands.rs:381-386` — class
   B, R14's row.
5. `THEFT_WARNING`, `WALLET_CUSTODY_NOTE`, `funding_lines`, and the positioning
   paragraph in `standing_warnings` — all byte-identical, so D148 §2 R3's
   positional assertion and every P-rule qualifier stay put.
6. `crates/antseal-cli/tests/snapshots/cli-surface.help.txt` — no surface changes.
7. `EXPORT_FORMAT_VERSION`, the export header, the payload schema. No format
   event.

### R9 — The golden re-bless: authority, procedure, record

**Authority**: this record, §2 R3/R5/R7, under U84's Accept row 2 (*"if it
changes, U78's golden is re-blessed in the same act and the diff is justified as
a deliberate freeze event naming its authority"*). U32 is the **release** freeze
and has not run, so no release freeze is broken. U78's own failure message
already licenses the move for a deliberate change.

**Procedure**, exactly:

1. `sha256sum crates/antseal-cli/tests/snapshots/init-report.txt` **before** —
   the committed value is `8588169a…9ffe` per U78's row; record the full digest.
2. Land R3–R7. Run the suite **without** the bless var first and capture the red:
   `cargo test -p antseal-cli --test init_command 2>&1 | tail -40; echo "REAL_EXIT=${PIPESTATUS[0]}"`
   — read `REAL_EXIT` back out; a red here proves the golden was actually
   pinning the changed lines rather than being unreachable.
3. `ANTSEAL_BLESS=1 cargo test -p antseal-cli --test init_command the_init_report_matches_its_committed_golden`.
4. Re-run step 2 **without** the var; require green, and require
   `the_golden_carries_the_standing_warnings_by_identity` green (it is the
   identity assert on the new `LOSS_WARNING`).
5. `sha256sum` **after**, and `git diff --stat` on the snapshot. The expected
   diff is **nine changed lines** — `:15`, `:33`, `:51`, `:74` (`LOSS_WARNING`),
   `:65` (`placement_guidance`), `:14`, `:32`, `:50`, `:73` (the lead-in) —
   **plus four inserted** `BACK UP` lines, one per section. Any other moved line is unintended and must be explained
   before the commit.
6. Run the bless a **second** time in a fresh process and require the same
   sha256 — U78's determinism proof by two runs, not by argument.
7. `python3 scripts/check-copy-style.py` (flagless; safe) → expect `0`; the
   golden is inside `COPY_SCAN`'s snapshot directory entry.

**Record**: the before/after sha256, the nine-line diff, and the two-run
determinism check go into **U84's `TODO.md` row** in the act that ticks it —
evidence belongs in the row, not in a transcript. Per the U80 precedent (§1.8)
the test's failure message keeps naming the **freeze** (U78) and is **not**
edited to name D151.

### R10 — The replacement test: a biconditional between the copy and the command

New test in `crates/antseal-cli/tests/vault_keyfile.rs`, immediately after
`a_wrapped_vault_is_refused_by_export_and_a_wrapped_payload_by_import` (that file
already owns the wrapped-vault fixture, already imports `export_vault`, and its
module doc already claims *"what `vault export` does with a two-factor vault"*).

**What it constructs**: for `wrapped` in `[false, true]`, a real vault via
`create_vault_with_wrap(&layout, &passphrase(), KdfSelection::Argon2id, &wrap,
&mut rng(..))` with `WrapChoice::None` / `WrapChoice::Keyfile { path, record_path:
true }` — both forms already used in this file (`:250`, `:338`).

**What it drives**: `export_vault(&vault, &passphrase(), &out, &mut rng(..))` —
the real command engine, per class.

**What it asserts**:

```rust
/// **U84 / D151 §2 R10.** The backup advice and the backup command,
/// measured against each other instead of against themselves.
///
/// What this replaces and why: `vault::keyfile`'s unit guard asserted that
/// `placement_guidance(...)` *contained the string* "does NOT contain the
/// keyfile" — the copy checked against its own words, green precisely
/// because the sentence existed, while the sentence was false. Do not
/// reintroduce a check whose expected value is the copy under test.
const EXPORT_COMMAND: &str = "antseal vault export";

#[test]
fn the_backup_advice_matches_what_export_actually_does() {
    for wrapped in [false, true] {
        // 1. What the product DOES, measured, not assumed.
        let export = export_vault(&vault, &passphrase(), &out, &mut rng(0x52));
        let succeeded = export.is_ok();
        assert_eq!(
            succeeded, !wrapped,
            "wrap mode {wrapped}: `vault export`'s own verdict moved. If that is \
             deliberate it is a D47 format event and D151 §2 R1 must be re-ruled \
             before this copy changes: {export:?}"
        );

        // 2. What the product SAYS to a user of this class, from the real
        //    producers — `init`'s whole report (which composes
        //    `placement_guidance` and `standing_warnings`) and `seal`'s nag.
        let copy = [
            report_for(wrapped).render().join("\n"),
            standing_warnings(wrapped).join("\n"),
            export_nag(wrapped).join("\n"),
        ]
        .join("\n");

        // Anti-vacuity: the class-keyed line was reached at all. Without
        // this, an empty `copy` would satisfy the wrapped row for free.
        assert!(copy.contains("BACK UP"), "wrap mode {wrapped}: no backup line rendered");
        assert!(copy.len() > 1_000, "wrap mode {wrapped}: copy is {} bytes", copy.len());

        // 3. The biconditional. Both directions are defects.
        assert_eq!(
            copy.contains(EXPORT_COMMAND), succeeded,
            "wrap mode {wrapped}: the CLI {} `{EXPORT_COMMAND}` while the command {}. \
             U84: no antseal output may name a command that refuses the vault it is \
             describing, and none may withhold the one that works.",
            if copy.contains(EXPORT_COMMAND) { "names" } else { "does not name" },
            if succeeded { "runs" } else { "refuses" },
        );
    }
}
```

**The redness seam — the faults that make it red, which the implementing lane
must plant and capture by message, one at a time, each reverted with a sha256
checked against a hash taken before planting:**

| # | planted fault | what goes red | why |
|---|---|---|---|
| T1 | delete the `if header_wrap != WRAP_MODE_NONE` block (`export.rs:745-756`) | assert 1, wrapped row | the behaviour changed under copy that assumed it |
| T2 | restore the old `placement_guidance` sentence (R7 reverted) | assert 3, wrapped row | copy names a command that refuses |
| T3 | put `antseal vault export` back into `LOSS_WARNING` (R3 reverted) | assert 3, **wrapped row only** — and the mode-0 row stays green, which is exactly why the old guard could not see the defect | |
| T4 | swap `BACKUP_BY_EXPORT` for `BACKUP_BY_HAND` in the mode-0 arm of R5/R6 | assert 3, mode-0 row | the working command was withheld from the class that can use it |
| T5 | make `standing_warnings`/`export_nag` ignore their argument (`let _ = wrapped;` and always take the mode-0 arm) | assert 3, wrapped row | proves the parameter is load-bearing, not decorative |
| T6 | return an empty `Vec` from `export_nag` | the anti-vacuity asserts | proves assert 3 is not passing on an empty string |

T3 and T5 are the two that a copy-versus-copy test cannot catch and are the
reason this test exists. **T1 is the one U84's Accept row 3 names by hand** — a
planted change to the claim's *truth*, not its wording.

**Two implementation notes.** (i) If `export_vault` on a bare mode-0 vault fails
for a reason unrelated to the wrap (no wallet record, no config), give the
fixture a wallet key with `store_wallet_key` as `tests/vault_export.rs` does —
**do not weaken assert 1 to a class check**; the point is that the export
actually ran. (ii) `report_for(wrapped)` builds an `InitReport` in
`init_command.rs:755-763`'s idiom with `network: NetworkId::Devnet`, an
all-zero address literal, `vault_dir: layout.root().to_path_buf()`, and
`keyfile: wrapped.then(|| keyfile.clone())`. `InitReport::render()` already calls
`standing_warnings`, so the second element of `copy` is redundant **by design**:
it pins the producer directly, so a future `render()` that stops calling it
cannot hide a false line behind the composition.

### R11 — The unit guard at `keyfile.rs:404-414`

Renamed and reduced to what a unit test can honestly hold — the assertions whose
expected value is **an input or a constant from elsewhere**, never a free
literal of the copy under test:

```rust
    /// The guidance echoes the caller's path and the env override. What it
    /// must not do — promise anything about `antseal vault export` — is
    /// asserted where the command can actually be driven
    /// (`tests/vault_keyfile.rs::the_backup_advice_matches_what_export_actually_does`).
    ///
    /// **What used to be here, and why it could not fail (U84).** This test
    /// asserted `text.contains("does NOT contain the keyfile")` — the copy
    /// compared to its own words. It was green *because* the sentence
    /// existed, while `vault export` refused the very vaults this text is
    /// printed for. Do not reintroduce a check whose expected value is the
    /// string under test; the wording is pinned by U78's golden and the
    /// claim is pinned by behaviour.
    #[test]
    fn the_placement_guidance_echoes_the_path_and_the_env_override() {
        let text = placement_guidance(Path::new("/media/usb/vault.key")).join("\n");
        assert!(text.contains("/media/usb/vault.key"), "{text}");
        assert!(text.contains(KEYFILE_ENV), "{text}");
        assert!(!text.contains("antseal vault export"), "{text}");
    }
```

The two free-literal wording asserts (`"REQUIRED alongside your passphrase"`,
`"different media"`) are **deleted**: U78's golden pins that section byte for
byte, and a second hand-copy of the same words is a place for them to drift.

The unit test at `init.rs:794-811` likewise loses `assert!(text.contains("vault
export"), "loss copy names the remedy")` — false for the wrapped class after R5 —
and becomes a two-arm check: `standing_warnings(false)` **contains** `antseal
vault export`, `standing_warnings(true)` **does not**. Same for
`bookkeeping.rs:347-359`, whose `assert!(text.contains("antseal vault export"))`
(`:353`) becomes the same two-arm pair over `export_nag(false)`/`export_nag(true)`.

### R12 — The three docs that quote this copy byte for byte

Re-synced in the same act, because U84's Accept row 4 requires both user pages
left true and a stale byte-quote is not true:

| file:line | what changes |
|---|---|
| `docs/user/vault-loss.md:25` | the `LOSS_WARNING` block → R3's rendering |
| `docs/user/vault-loss.md:28-34` | the surrounding prose says the constant is *"the same string the first-seal export nag carries (`bookkeeping.rs:263`)"* — re-verify both locators after the edit |
| `docs/user/vault-loss.md:41-42` | the nag block → R6's mode-0 rendering (first line unchanged; second line becomes `BACKUP_BY_EXPORT`), locator `bookkeeping.rs:257-266` re-verified |
| `docs/user/vault-loss.md:167-181` | already true; add the one fact it lacks — that a wrapped vault's first-seal nag says so and stays on, with `BACKUP_BY_HAND` quoted byte for byte |
| `docs/user/vault-theft.md:314-317` | the `LOSS_WARNING` block → R3's rendering, locator `bookkeeping.rs:68-70` re-verified |
| `docs/threat-model.md:593` | quotes the mode-0 nag opening, which is byte-identical; **re-verify only** |

`docs/vault-keyfile.md:47-51` is **true** and is not required to change (§4 item
5). `docs/decisions/D140:78` and `D148:55,733,745` quote the old strings inside
historical narration of what the tree said on their dates; they are **not**
amended (D148's own §4.3 is the row's origin and reads correctly as history).

After the edits: `python3 scripts/check-copy-style.py` flagless → 0.

### R13 — U84's Accept rows: dispositions, verbatim for the registrar

- **Row 1** (*"No `init` output tells a wrapped-vault user to run a command that
  refuses their vault"*) — **amended, not silently narrowed** (the D148 §2 R10 /
  U33 precedent). It is **met for `init`'s report** and **explicitly not met for
  `init`'s existing-vault refusal** (`init.rs:602-611`), which is class B: the
  message is produced from `header.exists()` alone (`init.rs:393-396`) with the
  header never decoded, and it is frozen in `json-envelopes.txt:2`. Replacement
  text: *"No line of `init`'s **report** tells a wrapped-vault user to run a
  command that refuses their vault, proven by a test that exercises the refusal
  rather than the wording. `existing_vault_refusal`'s naming of the same command
  is class B and is split to <new row> with its two machine-surface freezes."*
- **Row 2** — met by R9; the row must carry the sha256 pair, the nine-line diff
  and the two-run determinism check.
- **Row 3** — met by R10 + R11, with T1 as the truth-plant the row names.
- **Row 4** — met by R12, which makes "re-read and left true" concrete.
- **Row 5, appended**: *"`seal`'s first-seal nag is class-aware too: a
  keyfile-wrapped vault can never record an export (`record_export` has one
  production caller, after a successful export), so the nag is perpetual, and it
  says why instead of naming a command that refuses."*
- **Row 6, appended**: *"`docs/decisions/D47-vault-export-format.md` no longer
  asserts that the export preserves the keyfile factor (D151 §2 R2's addendum)."*

The row's `Do` sentence *"(it is D47's format limit, and the reasoning at
`export.rs:749-753` is sound)"* is **factually wrong** and is corrected at source
in §5.

### R14 — The class-B row (described, not numbered)

**U domain, size S**, ordered before U32.

*Two CLI messages name `antseal vault export` to a user whose vault may be
keyfile-wrapped, and both are produced where the wrap mode is not in scope.*
`init.rs:604-608` (existing-vault refusal — *"If you want a fresh vault, run
`antseal vault export` first when the contents matter, then move or remove …"*)
fires on `header.exists()` alone at `init.rs:393-396`, before the header is
decoded, and is frozen at `json-envelopes.txt:2`. `error.rs:570-574`
(`ImportRefusedExistingVault` — *"(after `antseal vault export` if you want its
contents)"*) is a `thiserror` Display over a `PathBuf`, so no vault exists in the
type at all; it is frozen at `cli-errors.display.txt:14` **and**
`json-envelopes.txt:20`. Both tell a user to back up before wiping a directory —
the highest-consequence moment in the product — and both can be following advice
that will not run. Because the class is unavailable at both sites, the fix is
**wording true for every class** (name the outcome, not the command), not a
branch; and because it re-blesses the machine-mode envelope and the error-display
snapshot it must not ride D151's copy act. Include in the same sweep
`commands.rs:381-386` (*"Restore from a `antseal vault export` backup"*), which
is reachable for a wrapped vault, has `session.vault()` in scope at `:380`, and —
measured — appears in **no snapshot and no test**. `error.rs:817-819` is
**excluded and the reason recorded**: only an export that ran can reach it, so
the vault is mode 0 and the sentence is true by construction.

### R15 — `Q251` gains clause (v)

Q251 collects MVP-SPEC.md line 143's divergences from shipped behaviour and holds
four. This is the fifth and it is the one none of them covers — (ii) is about the
keystore *half not shipping*, this is about the keyfile half **disabling** a
different clause of the same line:

> (v) Line 143 promises **both** *"`vault export`/`import` for encrypted
> backup"* **and** *"a high-entropy keyfile / OS-keystore wrap for `W`"*, and
> shipped antseal makes them **mutually exclusive**: `vault export` refuses any
> vault with a non-zero wrap mode and `vault import` refuses any such payload
> (`crates/antseal-cli/src/vault/export.rs:745-756`, `:520-535`; `usage`, exit
> **2**). A user who takes line 143's wrap loses line 143's backup command for
> the life of the vault and backs up by hand instead. Deliberate and argued
> (`export.rs:30-59`; `TODO.md:398` U8 deviation 1), user-documented
> (`docs/user/vault-loss.md:167-181`, `docs/user/vault-theft.md:219-224`), and
> **recorded in D47 only as of D151 §2 R2** — the record had asserted the
> opposite since 2026-08-01. Carrying the wrap is a D47 **header** format event
> (D151 §1.6) and is not taken at MVP.

No code change is licensed by this clause, exactly as Q251's row already says.

### R16 — This record's own index row

```
| [D151](D151-vault-export-backup-advice.md) | U84 — `init` and `seal` tell keyfile users to run a command that refuses their vault. **The refusal stands and its stated authority is inverted**: D47 §Format says the wrap factor IS preserved and §Spec-conformance says "no divergence", while shipped code has refused both directions since U8 — an overturn recorded in `TODO.md:398` and at the site but never in D47, which R2 amends. Carrying the wrap is a **header** event, not a payload one: the payload's `wrap_mode` slot exists but sits inside the AEAD, so no reader can learn a keyfile is needed before deriving the key — and `MVP-SPEC.md:149` gives `vault export\|import` no flags for the keyfile to arrive through. **"All three sites" is overturned**: eight source occurrences in four classes, of which the class-blind two are frozen in the machine-mode envelope and split to their own row. **The arm nobody listed** is not copy at all: `record_export` has one production caller, after a successful export, so a wrapped vault can NEVER record a backup and the first-seal nag is perpetual and unsatisfiable. **Line 143 dictates the obligation, not the words** (quoted verbatim), so `LOSS_WARNING` keeps the fact, loses the instruction, and a class-keyed backup constant carries the remedy — one author per class, at both venues, where two phrasings of one instruction stood before. The self-comparing guard is replaced by a biconditional between the copy and the command's measured verdict, red on six planted faults including the refusal's deletion | RESOLVED | 2026-08-18 |
```

---

## 3. What was refused and why

### 3.1 Make the export carry the wrap (fix the refusal, keep the copy)

The arm the brief asked to be tested hardest. **Refused on the format, not on
appetite.** The wrap flag must be readable *before* the key exists, so it must
live in the export **header** (`export.rs:11-14`: body v1 is
`map { 0: kdf_block, 1: nonce }`, and the header is the AAD). The payload slot
D47 promised exists (`export.rs:65-68`, key 1) and is write-dead — after the
refusal at `:745`, the second decode at `:758` can only yield `WRAP_MODE_NONE`.
So this is a D47 header format event, plus a second key-combine in the backup
format, plus an import-side keyfile channel that `MVP-SPEC.md:149`'s flagless
`vault export|import` has nowhere to put, plus new vectors and tamper rows — at
M4, with U32 pending. And it would falsify three shipped pages that document the
refusal as a priced trade (§1.7). Parked as a v1.1 format event, which is where
`export.rs:46-50` already put it.

### 3.2 Leave `LOSS_WARNING` alone because the refusal message is itself the correction

Genuinely arguable: a wrapped user who runs the command gets exit 2 and a message
that names the by-hand procedure. **Refused on §1.5.** The same constant is
rendered by the first-seal nag, which for a wrapped vault fires *forever* and can
never be satisfied — so the product would be repeating unactionable advice on
every seal and relying on the user to discover the correction by failing. That is
the exact posture U18's row was written against.

### 3.3 Make `LOSS_WARNING` unconditional and hedge the command inside it

*"Run `antseal vault export` and keep the backup somewhere else (a keyfile vault
is backed up by hand instead)."* One constant, no plumbing, no new field on
`SealReport`. **Refused**: it makes every user parse a branch they do not have,
and it still leaves the wrapped user without the instruction they need — *"by
hand"* is not a procedure. The measurement that kills it is §1.4: the class is in
scope at both render sites, so the hedge buys nothing that the branch does not
buy better.

### 3.4 Drop the command from `LOSS_WARNING` and add nothing

The minimal edit. **Refused**: it silently removes the only actionable backup
instruction `init` gives, for the ~100 % of vaults that are mode 0 (`--wrap`
defaults to none, `cli.rs:208-211`), in the copy MVP-SPEC.md line 143 mandates.
Fixing a false instruction by deleting the true one is not a fix.

### 3.5 Split `LOSS_WARNING` into two full constants, one per class

**Refused** on the one-author doctrine at `bookkeeping.rs:62-67`: the loss *fact*
is identical for both classes, and two constants stating it means two places for
it to drift, two byte-quotes in `vault-loss.md` and `vault-theft.md`, and two
identity assertions per golden section. The fact stays one constant; only the
**remedy**, which genuinely differs, is class-keyed. Each fact keeps exactly one
author.

### 3.6 Add the wrap class to `SealReport::json()`

**Refused for this act.** It re-blesses `json-envelopes.txt`, a machine contract
under D51/U18, for a benefit (a scripted consumer distinguishing an actionable
nag from an unactionable one) that is real but is not U84's subject. It is named
in §4 and belongs with R14's row, which moves that snapshot anyway.

### 3.7 Fix the class-B sites here, since Accept row 1 says "no `init` output"

**Refused** on §1.3's freeze measurement: `init.rs:607` is pinned in
`json-envelopes.txt:2` and `error.rs:573` in both `cli-errors.display.txt:14` and
`json-envelopes.txt:20`. Two machine-surface re-blesses inside an S-sized copy
row is the silent freeze event this project keeps catching. Accept row 1 is
amended and the gap is rowed (R13, R14) rather than dropped.

### 3.8 Make `init`'s existing-vault refusal class-aware by decoding the header

**Refused**: `init.rs:388-396` refuses on `header.exists()` and the comment above
it states the invariant — *"the refusal must happen before a passphrase is
collected"*, U11's *"first and absolute"*. Decoding the header there adds
pre-auth parsing of an attacker-suppliable file to the one path whose whole value
is that it does nothing first.

### 3.9 Suppress the first-seal nag entirely for wrapped vaults

**Refused**: the wrapped vault is the one that most needs the reminder, and
silence would mean the seal report never mentions backups to the class with the
hardest backup story. R6 keeps the nag and makes it honest about why it cannot go
away.

---

## 4. Residue

1. **A wrapped vault still cannot record that it was backed up.** R6 explains the
   perpetual nag; it does not remove it. A by-hand acknowledgement (a
   `vault backup --acknowledge`-shaped surface, or a bookkeeping field the user
   can set) is a **new CLI surface** and needs a decision — not taken, not
   scheduled, and named here so the next reader does not think R6 closed it.
2. **`--json` cannot distinguish an actionable nag from an unactionable one**
   (§3.6). Scripted consumers on a wrapped vault see `export_nag: true` forever
   with no way to know it is unsatisfiable. Handed to R14's row.
3. **The golden's keyfile section still has no live `run_init` cross-check.**
   `the_report_prints_the_address_and_the_networks_funding_copy` asserts
   `report.keyfile.is_none()` and loops only the three networks
   (`init_command.rs:869-914`), so the keyfile branch is pinned against a
   constructed fixture and R10's producers, never against a real `init --wrap
   keyfile`. Pre-existing (U78's own "does not cover"), unchanged by this act,
   worth a ledger line.
4. **`export.rs:742` and `:758` decode the same header twice**, and the second
   result is provably `WRAP_MODE_NONE` because of the refusal between them. Not a
   defect, but the payload's `wrap_mode` key is unreachable for any value but 0
   in the write direction, which makes `validate_payload`'s `:520` refusal a
   read-side-only guard. Ledger, not a fix.
5. **`docs/vault-keyfile.md:47-51` leads with the sentence this act is deleting**
   (*"`antseal vault export` does not contain the keyfile"*) and corrects itself
   in the next clause. It is **true** and is deliberately left alone; a tidy that
   leads with the refusal instead would read better and is a candidate, not a
   debt.
6. **`commands.rs:381-386`'s message is in no snapshot and no test** — a
   user-facing `Usage` string with no freeze at all, found while taking §1.3's
   census. Ledger; R14's row is its natural home.
7. **`D50-os-keystore-scope.md:60-61`'s premise is false** (§1.1). Its conclusion
   is unaffected and R2's addendum names it; whether D50 gets its own dated
   addendum is the registrar's call, not this record's.

---

## 5. Registrar's edit set

### 5.1 `docs/decisions/README.md`

Insert R16's row in ascending id order. **D150 (`D150-q22-release-docs-preconditions.md`) and D152 (`D152-resume-hint-honesty.md`) are sibling records from this same wave and are equally unrowed** — measured at this lane's close, `check-traceability.py` reds `[decision-index]` on all three. The `Status` word is
`RESOLVED` and the date is `2026-08-18`, matching this file's `- **Status`/
`- **Date` lines — the two fields `check_decision_index` parses. Until this row
lands, `docs/decisions/` holds one more record than the index has rows and
`decision-index` is red; that is the routine mid-act window.

### 5.2 `TODO.md` — decision register

Add the D151 row in the same wording as R16, ticked (`- [x]`), and update the
header's decision figures **by script, never by increment**
(`python3 scripts/check-traceability.py`).

### 5.3 `TODO.md` — U84's row

**Mandatory, not optional**: the row must contain the literal `D151`.
`check_decision_owners` (`scripts/check-traceability.py:1486-1530`) reds when a
`**Owner: U84**` assignment exists in a resolved decision whose owner's row never
names it — this file carries that assignment at §2. Append to the row, before the
tick:

> · **ruled by D151** (2026-08-18): the copy is wrong and the refusal stands, but
> **not** on D47's authority — D47 §Format mandates the opposite and is amended
> by D151 §2 R2. Four class-aware sites, not three; two class-blind sites split
> to <new row>; `LOSS_WARNING` keeps the fact and loses the instruction; U78's
> golden is re-blessed under D151 §2 R9

and correct the row's own sentence *"the same claim is made a second time by a
spec-mandated constant"* by appending *"— and a third time by `export_nag`
(`bookkeeping.rs:257-266`), whose premise a wrapped vault can never satisfy"*.

### 5.4 `tasks/U.md` — U84's entry (line 1200 onward)

1. **`Do`, first sentence** — replace *"(it is D47's format limit, and the
   reasoning at `export.rs:749-753` is sound)"* with *"(the reasoning at
   `export.rs:737-756` is sound, but it is **not** D47's limit — D47 §Format
   mandates the opposite and is amended by D151 §2 R2)"*.
2. **`Problem`** — correct the `placement_guidance` locator from
   `keyfile.rs:286-290` to **`keyfile.rs:287-289`** (the string; `:286`/`:290`
   are the `format!` delimiters), and add the fourth site: *"and a third rendering
   of the same false advice sits in `export_nag` (`bookkeeping.rs:257-266`),
   where it is not merely false but **unsatisfiable**: `record_export` has one
   production caller (`commands.rs:810`), reached only after a successful export,
   so a wrapped vault can never record a backup and the nag fires on every seal
   forever."*
3. **`Accept`** — apply R13 verbatim: amend row 1, append rows 5 and 6.
4. **`Spec`** — keep line 143 and 184; add *"and line 149 (the canonical
   `vault export|import` surface carries no flags — D151 §1.6)"*.
5. **`Deps`** — add *"consumes D148 §3.5 (the `init`-report conditional it
   refused was a different predicate) and D151"*.
6. **Mint R14's row** in the U domain with R14's text, ordered before U32, and
   add a `Discovered by: D151's lane (2026-08-18), §1.3's census` line.

### 5.5 `tasks/Q.md` / `TODO.md` — Q251

Add clause **(v)** verbatim from R15 to Q251's entry (`tasks/Q.md:3168`) and a
one-clause summary to its `TODO.md` row (`:840`), keeping the row's *"No code
change is licensed"* sentence intact.

### 5.6 `docs/instrument-ledger.md`

Four findings from this lane, none of them a task:

1. **A decision record asserting the opposite of shipped code, for 16 days.**
   D47 §Format's *"Keyfile factor preserved"* and §Spec-conformance's *"no
   divergence"* were falsified by U8 on 2026-08-02; the overturn was recorded in
   the U8 **row** and at the **site**, and the **record** was never touched. The
   row that inherited it (U84) then cited D47 as the refusal's authority. *A
   deviation recorded in the executing row is not recorded in the deciding
   record, and the next reader reaches for the record.*
2. **`export.rs`'s double header decode** and the write-dead payload `wrap_mode`
   slot (§4 item 4).
3. **`commands.rs:381-386`: a user-facing `Usage` message pinned by nothing**
   (§4 item 6).
4. **The golden's keyfile section has no live-run cross-check** (§4 item 3).

### 5.7 What the registrar must NOT do

Assign an id to R14's row from inside this record (it is described, not
numbered), tick U84 (this is a planning lane; nothing was implemented), or edit
any Rust source — no line of this ruling has been landed.
