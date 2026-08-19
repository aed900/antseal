# D155 — the reword is right and the gate stays, but for none of the reasons on record: D39 Decision 4 *prescribes* the false sentence, the gate's comment states a different invariant than the row quotes, arm (a) cannot remove the need for arm (b), and the third site is a different defect that is false for **every** class

- **Status: RESOLVED. Half and half. The lean's DIRECTION is CONFIRMED —
  arm (b), reword both sites, gate untouched. Its stated REASON is OVERTURNED,
  and so are three of U86's own framings.** The lean was *"arm (b) — reword both
  sites; moving a deliberately pre-decode gate is not worth it for a copy fix."*
  - **"a deliberately pre-decode gate" is NOT what the comment says.** The
    comment above `init.rs:418` (`init.rs:412-416`) states one invariant and it
    is about the **passphrase**, not the decode: *"the refusal must happen
    before a passphrase is collected, so it is checked here as well rather than
    relied on there."* Nothing at that gate forbids a decode. U86's Notes and
    `TODO.md:854` both say *"the comment above the gate states that invariant
    deliberately"* of the **pre-decode** invariant; measured, it does not. The
    only record that refuses a decode there is **D151 §3.8**, which U86's Notes
    say does not exist (*"D151 did not rule between those"*) — §1.5.
  - **And D151 §3.8's stated ground does not survive measurement either.** It
    refuses arm (a) because a decode *"adds pre-auth parsing of an
    attacker-suppliable file"*. `VaultHeader::decode` is **already** the
    binary's pre-auth parser: `unlock_vault_impl` (`vault/session.rs:374-391`)
    reads and decodes the header **before** any key is derived, necessarily,
    because the KDF parameters live in it. Arm (a) adds one more caller of an
    exposed parser, not a new exposure. §1.6.
  - **Arm (a) is refused on a ground nobody stated: it cannot remove the need
    for arm (b).** `VaultHeader::decode` has nine failure classes
    (`vault/header.rs:93-144`), and a header file can exist and not decode —
    `NewerVersion` (`:139`, raised at `:309-311`) is a vault written by a
    *newer* antseal, which is precisely the vault that must be refused and never
    touched. So a class-aware refusal still needs a class-**unknown** branch,
    and that branch's wording is exactly what arm (b) rules. Arm (a) is strictly
    **additive** to arm (b), never an alternative. **D39's own residual risk
    says so first**: `docs/decisions/D39-init-interaction-model.md:142-145`
    accepts that a *present-but-not-a-vault* directory refuses — *"refusing too
    much is recoverable, refusing too little is not."* §1.7, §3.1.
  - **The arm nobody listed, and it decides where the repair has to land:
    `D39-init-interaction-model.md:87-95` — Decision 4 itself — PRESCRIBES the
    false sentence.** Verbatim: *"the error names the vault path and tells the
    user to move/remove it manually **(after `vault export` if they want the
    contents)**"*. Both class-blind messages are renderings of that
    parenthetical, which is why they read alike. It was true when D39 was
    written and U8 falsified it on 2026-08-02. This is D151 §1.1's defect
    repeating in a second record — and D151's own lane wrote the lesson into
    `docs/instrument-ledger.md` (*"A deviation recorded in the executing row is
    not recorded in the deciding record, and the next reader reaches for the
    record"*) and then did not apply it to D39. **R7** amends D39 by dated
    addendum, in the same act. §1.2.
  - **U86's framing of the `import` half is right in its conclusion and wrong
    in its mechanism, and the wrong mechanism would have collapsed under
    arm (a).** D151 §1.3 classes `error.rs:573` blind because it is *"a
    `thiserror` Display over a `PathBuf`; no vault exists in the type"* — a
    property of the **type**, which arm (a) would simply change by adding a
    field. What actually makes it blind is its **construction site**:
    `refuse_existing_target` (`vault/export.rs:1208-1213`) refuses on
    `beside_path(BesideFile::Header).exists()` — the *same* predicate as
    `init.rs:418` — and `import_vault`'s rustdoc calls it *"(before anything is
    read)"* (`:1013`), confirmed by `import_vault_impl:1031-1034`, where the
    refusal is step 1 and `read_bounded` is step 2. So the two sites get the
    same treatment **for the same reason**, and that reason is on record for the
    import half and not for the init half. §1.4.
  - **`commands.rs:381-386` is a DIFFERENT defect wearing the same words, and
    it is worse: it is false for every class, not one.** *"Restore from a
    `antseal vault export` backup"* is reached with the vault **unlocked**
    (`commands.rs:380`), so its header exists, so the only command that consumes
    such a backup — `antseal vault import` — hits `refuse_existing_target` and
    refuses, **100 % of the time, for every wrap mode**. The advice can never be
    followed as written. It is not a class-conditional falsehood; it is a
    structural one, and it chains straight into the other message this record
    rewords. §1.8.
  - **A fourth surface moves that U86 never named, and it carries a stale
    locator.** `docs/user/vault-loss.md:252` quotes the import refusal **byte
    for byte**, and `:249` cites it to `crates/antseal-cli/src/error.rs:535-542`
    — which today is `NotImplemented` (`error.rs:536-541`), an unrelated
    variant. §1.9.
- **Date: 2026-08-19**
- **Owning task: U86** (M4, size S)
- **What it blocks: U32** — the release freeze, which U86 is ordered before
  because both renderings sit inside surfaces U32 ratifies as compatibility
  promises. U32's own `Accept` already carries the precedent sentence for U84:
  *"freezing this surface for release without dispositioning U84 freezes a false
  sentence"* (`tasks/U.md`, U32 Accept row 4). U86 is that argument for
  `json-envelopes.txt` and `cli-errors.display.txt`.
- **Related:** **D151** (U84; the class-aware sites, and §1.3's census that split
  U86 out), **D152** (the same defect shape ruled for `list`'s resume hint),
  **D39 Decision 4** (the absolute refusal — amended by R7), **D47** as amended
  by D151 §2 R2, **D51** (the prompt-class table the import refusal cites),
  **U8/D50** (the wrap), **U78** (the golden precedent for a deliberate
  re-bless), **R82** (the rule that a refusal a user reads cites no task id —
  routed, not ruled, at §4.2), **Q251** (the line-143 divergence collector; it
  gains nothing here, see §3.6).

## 0. What was measured against

Tree at `28afe38` with four files modified by other lanes (`TODO.md`,
`docs/signing/key-custody.md`, `docs/signing/maintainer-key-procedure.md`,
`tasks/Q.md`, plus `crates/antseal-cli/tests/list_command.rs` mid-lane). **No
Rust source, no snapshot and no task file was modified by this lane**; the only
file it writes is this record. Every locator below was re-measured with
`awk`-numbered output or `grep -n` against the working tree, and every locator
the brief and the row supplied is reported with its verdict in §1.10.

---

## 1. What was measured

### 1.1 The two class-blind sites, re-measured

`crates/antseal-cli/src/init.rs:626-636` — the row's `:626-636` is **confirmed**,
and the command is named at **`:631`**, confirmed:

```
626  pub fn existing_vault_refusal(root: &std::path::Path) -> CliError {
627      CliError::Usage {
628          message: format!(
629              "a vault already exists at {root} — antseal never overwrites a vault, and there is \
630               no --force flag: overwriting one destroys the reveal and restore keys of every \
631               work it holds, forever. If you want a fresh vault, run `antseal vault export` \
632               first when the contents matter, then move or remove {root} yourself.",
633              root = root.display(),
634          ),
635      }
636  }
```

`crates/antseal-cli/src/error.rs` — the row's `:570-574` is **off by two at the
tail**: the `#[error(...)]` attribute opens at `:570`, the message runs
`:571-574`, the format argument is `:575`, the attribute closes `:576` and the
variant is `:577`. The command is at **`:573`**, confirmed. Cite
**`error.rs:570-577`**.

The gate: `init.rs:418` `if header.exists() {` — **confirmed**, with the refusal
returned at `:419`.

### 1.2 D39 Decision 4 prescribes the sentence that is now false

`docs/decisions/D39-init-interaction-model.md:87-95`, verbatim:

> 4. **Existing-vault refusal is absolute in v1.** U11's "refuses by default"
>    (tasks/U.md:135) is resolved as: no override flag exists; the error names
>    the vault path and tells the user to move/remove it manually (after
>    `vault export` if they want the contents). Rationale: overwriting a vault
>    destroys `W` — every sealed work's reveal/restore ability, forever
>    (MVP-SPEC.md line 143 loss framing). A `--force` on the *creation* command
>    is a one-token irreversibility bypass; manual filesystem action is the
>    consent. `vault import` keeps its own confirm-to-overwrite (U12), which is
>    the supported restore-over path.

Three consequences, and the third is the one that changes the edit set.

1. **The parenthetical is the source of both messages.** `init.rs:631-632`'s
   *"run `antseal vault export` first when the contents matter"* and
   `error.rs:573-574`'s *"(after `antseal vault export` if you want its
   contents)"* are the same instruction with the same conditional; they read
   alike because they are two renderings of one decided sentence.
2. **It was true on its date and U8 falsified it.** Same shape as D151 §1.1,
   where D47 §Format still asserted *"Keyfile factor preserved"* 16 days after
   U8 refused it. D151 §2 R2 amended D47. **Nobody amended D39.**
3. **So the copy cannot be repaired at the code alone.** A record that mandates
   the false sentence outlives the commit that deletes it, and the next reader
   reaches for the record — this project has written that lesson down once
   already, in `docs/instrument-ledger.md` under D151 §5.6 item 1. R7 amends
   D39.

D39 also carries the *residual-risk* paragraph that governs arm (a) —
`:142-145`, verbatim:

> - Absolute refusal (Decision 4) means a wiped-but-present `~/.antseal/`
>   (e.g. an empty dir left by a failed manual cleanup) also refuses;
>   the error text must name the path so the fix is obvious. Accepted:
>   refusing too much is recoverable, refusing too little is not.

### 1.3 MVP-SPEC.md lines 143 and 149, quoted from the file

`sed -n '143p' MVP-SPEC.md`, the two clauses that bear on this row:

> `init` enforces a passphrase-strength floor and offers a high-entropy keyfile
> / OS-keystore wrap for `W`.

> `vault export`/`import` for encrypted backup. **Docs and CLI must nag on both
> failure modes**: *loss* (lose the vault and backup = lose reveal/restore
> ability forever; the sealed data itself stays safely unreadable) and *theft*
> (retroactive decryption of permanently public ciphertexts — no rotation
> exists; treat the passphrase and any export as a long-term high-value key).

`sed -n '149p' MVP-SPEC.md`, the clause that bears:

> … `verify <bundle> [--online] [--live]` · `vault export|import`. Global:
> `--network arbitrum-one(default)|arbitrum-sepolia|devnet` …

**D151 §1.2's answer transfers, and then goes further.** Line 143 dictates the
**obligation**, not the words — no sentence, no command name, no ordering is
prescribed — so the wording ruled here is free and this is an ordinary copy
change plus two freeze events, **not** a spec divergence. But the transfer is
*a fortiori*, on a measurement D151 did not need: line 143's nag clause governs
the **standing warnings**, and those are `LOSS_WARNING` / `THEFT_WARNING` /
`BACKUP_BY_*`, all fixed by D151 R3/R4/R6. **Neither message ruled here is a nag
surface at all** — one is `init`'s pre-flight refusal, the other is `import`'s.
Line 143 does not reach them, and removing a command name from them removes
nothing line 143 asked for.

Line 149 constrains this record only **negatively**: `vault export|import`
carries no flags, so no ruling here may propose a keyfile channel on either
command (this is the same constraint D151 §1.6 priced against carrying the wrap,
and it is why §3.2 refuses arm (c)'s "make export work" outright).

Line 28's positioning bans (P1/P2/P3) and line 139's canonical URL (P6) apply to
every string ruled here and are measured against the **real** lint in §1.9.

### 1.4 Both sites are blind for one reason, and it is the gate — not the type

| | `init` | `import` |
|---|---|---|
| gate | `init.rs:418` `if header.exists()` | `vault/export.rs:1209` `if target.beside_path(BesideFile::Header).exists()` |
| what is decoded first | nothing | nothing |
| invariant on record | `init.rs:412-416` — *"before a passphrase is collected"*, *"before anything else"* | `export.rs:1013` — *"(before anything is read)"*; `:1031-1034` — *"Refusal precedes everything — even reading the file"* |
| message author | `existing_vault_refusal` (`init.rs:626`) | `#[error]` on `ImportRefusedExistingVault` (`error.rs:570-576`) |

`refuse_existing_target` (`vault/export.rs:1208-1224`) is the construction site,
and it holds the target `VaultLayout`. Adding a `wrap: Option<u8>` field to the
error variant is a five-line change — so **D151 §1.3's stated reason for the
import half (*"no vault exists in the type"*) is a description of the type, not
a constraint.** The constraint is that the gate refuses before it reads. That is
the same constraint as `init`'s, which is why U86's *conclusion* — one treatment
for both — is right, and why its *mechanism* for the import half is not the one
that holds.

Note the second message in the same function, `export.rs:1214-1221`: *"{} exists
but is not a vault (no vault header inside) — **move it aside** before
importing"*. The tree already carries the class-independent instruction this
record rules; R2 and R3 bring the other two messages into line with it rather
than inventing a phrasing.

### 1.5 What the gate's comment actually protects

`crates/antseal-cli/src/init.rs:412-420`, verbatim and numbered:

```
412      // ── 1. Existing-vault refusal: absolute, and before anything else ──
413      //
414      // `create_vault` refuses too (the primitive owns its own invariant),
415      // but the refusal must happen before a passphrase is collected, so it
416      // is checked here as well rather than relied on there.
417      let header = layout.beside_path(BesideFile::Header);
418      if header.exists() {
419          return Err(existing_vault_refusal(layout.root()));
420      }
```

The stated invariant is an **ordering** invariant against the wizard: refuse
before a passphrase is collected, and refuse before `create_vault`'s own
duplicate check (`vault/session.rs:225-232`, a second author of the same refusal
with different words — §4.3). A `VaultHeader::decode` of a file already on disk
collects no passphrase and violates neither clause. **The row's claim that the
comment states a pre-decode invariant is false**, and the claim appears twice:
`tasks/U.md` U86 `Problem` and `Notes`, and `TODO.md:854`.

The only record that refuses arm (a) is **D151 §3.8**, which U86's Notes deny
exists:

> ### 3.8 Make `init`'s existing-vault refusal class-aware by decoding the header
>
> **Refused**: `init.rs:388-396` refuses on `header.exists()` and the comment
> above it states the invariant — *"the refusal must happen before a passphrase
> is collected"*, U11's *"first and absolute"*. Decoding the header there adds
> pre-auth parsing of an attacker-suppliable file to the one path whose whole
> value is that it does nothing first.

So D151 **did** rule between the arms; U86's *"D151 did not rule between those,
and neither should an implementer without a decision"* is wrong on its first
clause and right on its second — the ruling existed but sat in a refused-arms
section of a record whose owning row is `[x]`, which is exactly where a later
implementer would not find it. This record makes it findable and re-grounds it,
because §1.6 shows §3.8's stated ground is not the one that holds.

### 1.6 `VaultHeader::decode` is already the pre-auth parser

`crates/antseal-cli/src/vault/session.rs:367-391` — every unlock reads the
header with `read_bounded` and calls `VaultHeader::decode` **before** any key
exists, necessarily: the KDF parameters that derive the key are inside the
block being parsed. All six production call sites:

| site | pre-auth? |
|---|---|
| `vault/session.rs:391` (`unlock_vault_impl`) | **yes** — decode precedes derivation |
| `vault/export.rs:742`, `:758`, `:861` | no — an `UnlockedVault` is in hand |
| `seal_run.rs:530` (D151 R6's `wrapped` field) | no — same |

So the marginal cost of arm (a) is *one more caller of a parser already reachable
pre-auth on the routine path*, not a new attack surface. D151 §3.8's ground is
weaker than it reads, and this record does not rest on it.

### 1.7 What actually refuses arm (a): a decode cannot always answer

`crates/antseal-cli/src/vault/header.rs:290-345`. `decode` is *"defensive; total
over adversarial input"* and returns `Result<Self, HeaderError>`. The read-side
error classes, from the enum at `:93-144`:

`TooLarge` · `BadMagic` · `Codec` · `Schema` · `KdfBlockTooLarge` ·
`KeyfilePath` · `WrapModeUnknown` · `InvalidVersion` · **`NewerVersion`**

A header file therefore **exists and does not decode** in at least eight ways,
and `NewerVersion` (`:139`, raised at `:309-311` *"without parsing the future
body"*) is the decisive one: a vault written by a newer antseal is exactly the
vault whose reveal/restore keys must not be destroyed, and it cannot be
classified by construction. `header.exists()` covers it; a decode cannot.

Consequences, priced:

1. **Arm (a) needs three branches, not two** — wrapped, unwrapped, and
   *class-unknown*. The third branch's wording **is arm (b)**. Arm (a) does not
   replace this record's ruling; it would sit on top of it.
2. **Two extra frozen envelope lines.** `machine_mode.rs:405` registers exactly
   one exemplar, `existing_vault_refusal(Path::new("/home/user/.antseal"))`.
   Three messages means three registrations and three frozen lines, on a
   surface U32 is about to ratify as a compatibility promise.
3. **It makes an infallible refusal fallible.** Today `existing_vault_refusal`
   is `#[must_use] pub fn(&Path) -> CliError`: total, no I/O, no failure mode.
   Arm (a) puts a bounded read and a parse on the refusal path. D39:142-145 is
   the governing risk statement — *"refusing too little is not [recoverable]"* —
   and it was written about this exact predicate.

### 1.8 `commands.rs:381-386` is not U86's defect. It is a worse one

```
380      let session = SealSession::open(unlock_for_command(&layout, &passphrase, slot)?);
381      let handle = load_wallet_key(session.vault())?.ok_or_else(|| CliError::Usage {
382          message: "this vault holds no wallet key, so it cannot pay for a seal — it was \
383                    created by an older build, or the wallet record was removed. Restore from a \
384                    `antseal vault export` backup"
385              .to_owned(),
386      })?;
```

Measured, in order:

- **Reachability.** `init.rs:576` calls `store_wallet_key` unconditionally on
  every created vault, and `export.rs:1105` restores it on import. So the `None`
  arm is reachable only for a vault from an older build or one whose wallet
  record was removed — which is what the message says. Reachable, rare, correct
  about its cause.
- **The remedy is unreachable for every class.** Consuming a vault export means
  `antseal vault import`, and line 380 has just **unlocked** this vault, so its
  header exists, so `refuse_existing_target` (`export.rs:1208-1213`) refuses —
  unconditionally, for wrap mode 0 as much as for mode 1. The instruction as
  written cannot be executed by anyone.
- **It chains into the other message this record rewords.** The user who follows
  `commands.rs:383` lands on `ImportRefusedExistingVault`, i.e. on
  `error.rs:571-574`. This is D152's shape exactly — *"both cycles close on the
  hint"* — and it is why the two messages must be repaired in one act.
- **The class is in scope here** (`session.vault()` at `:380`), unlike the other
  two sites. It is therefore **not** class-blind, **not** U86's defect
  mechanism, and does not need U86's class-blind wording — it needs an
  instruction that names the missing step.
- **Pinned by nothing, and here is why.** `grep` over
  `crates/antseal-cli/tests/` returns no hit for this string, and none for
  `no wallet key`. The two committed message surfaces reach messages by
  different routes and neither route reaches an inline `CliError::Usage`:
  `cli-errors.display.txt` renders `exit_codes.rs::exemplars()`, a hand-listed
  set of **`CliError` variants**, and this message is a `Usage` payload built
  inline in a private module (`lib.rs:26` — `mod commands;`, **not** `pub`), so
  no test crate can even name it; `json-envelopes.txt` renders one registered
  exemplar per command (`machine_mode.rs:378-405`), and `seal`'s registered
  exemplar is the backend-unavailable arm, not this one. Nothing about it is
  greppable from either producer. **That is the freeze hole, stated as a
  mechanism rather than as an observation** — and R4 closes it without a third
  machine-contract re-bless.

### 1.9 The replacement strings, linted against the real functions before being written here

`scripts/check-copy-style.py` was **loaded as a module** (`importlib`, no edit,
no `--self-test`) and its own compiled rules — `check_banned` (P1 `NOTARY`,
P2 `PRIORITY`/`PRIORITY_QUALIFIER`, P3 `AUTHORSHIP`/`DISCLAIMER`),
`check_spellings` (P4/P5) and `check_url` (P6) — were run over the three
**rendered** strings R2/R3/R4 rule, with `root = /home/user/.antseal` (the
literal both snapshots already use). Actual output:

```
R2-init:      findings=0 len=415 single_line=True names_export=False
R3-import:    findings=0 len=384 single_line=True names_export=False
R4-nowallet:  findings=0 len=315 single_line=True names_export=False
ALL_CLEAN
```

**The harness was proven able to fire**, because a clean run over three strings
is otherwise the project's dominant defect class. Four faults were planted into
throwaway strings and each was caught, by rule:

```
P1-notary:     1 finding(s)   P1 'notary' with no disclaimer in its sentence
P2-priority:   1 finding(s)   P2 'priority' with no qualification in its block
P3-authorship: 1 finding(s)   P3 'authorship' with no disclaimer in its sentence
P6-url:        1 finding(s)   P6 'https://antseal.io/help' is not the canonical verifier URL
```

Reach is not in question: `COPY_SCAN` carries
`"crates/antseal-cli/tests/snapshots/"` as a **directory** entry
(`check-copy-style.py:100`) and `.txt` is in `COPY_SUFFIXES` (`:107`), so both
snapshots are scanned with no register edit. `PRESENCE_SURFACES` is
`("README.md",)` (`:260`), so no P7 clause and no `OWED_PRESENCE` debt touches
any of this copy. Baseline, flagless, before this lane: **exit 0** — *"ok — 26
product-copy file(s) across 8 scan root(s)"*.

Single-line discipline is a hard constraint on R3 specifically:
`exit_codes.rs:641-648` (`display_output_is_single_line_and_fully_rendered`)
rejects any `CliError` Display containing `'\n'`. All three strings are
single-line, measured above.

### 1.10 Verdicts on every locator the brief and the row supplied

| claim | verdict |
|---|---|
| `init.rs:626-636` is `existing_vault_refusal`, command at `:631` | **confirmed** |
| the gate is `init.rs:418`, on `header.exists()` alone, before any decode | **confirmed** |
| *"the comment above the gate states that invariant deliberately"* (pre-decode) | **FALSE.** `init.rs:412-416` states a pre-**passphrase** invariant; §1.5 |
| *"D151 did not rule between those"* | **FALSE.** D151 §3.8 refuses arm (a) by name; §1.5 |
| `error.rs:570-574` is `ImportRefusedExistingVault`, command at `:573` | **off by two at the tail** — the attribute closes `:576`, the variant is `:577`. Cite `error.rs:570-577`; `:573` confirmed |
| import site is blind because *"no vault exists in the type"* (D151 §1.3) | **wrong reason, right conclusion.** The gate is what blinds it; §1.4 |
| `json-envelopes.txt:2` freezes the init refusal | **confirmed** — the only other occurrence in that file is `:20` |
| `cli-errors.display.txt:14` **and** `json-envelopes.txt:20` freeze the import refusal | **confirmed** |
| `commands.rs:383` is *"Restore from a `antseal vault export` backup"*, in no snapshot and no test | **confirmed** — and it is a different defect; §1.8 |
| `error.rs:817-819` is excluded, true by construction | **confirmed and re-verified.** `ExportSelfVerifyFailed` is constructed only at `export.rs:967`, `:970`, `:973`, all **downstream** of the wrap refusal at `:745`, so only a mode-0 vault reaches it. `cli-errors.display.txt:76` does not move |
| MVP-SPEC.md line 143 governs this copy | **only negatively.** Line 143's nag clause governs the standing warnings, not either refusal; §1.3 |
| both sites get the same treatment | **confirmed**, on §1.4's gate measurement rather than on the row's |
| *(not in the brief)* `docs/user/vault-loss.md:252` byte-quotes the import message | **found.** And `:249` cites it to `error.rs:535-542`, which is `NotImplemented` today — a stale locator; §1.9 of the edit set, R6 |
| *(not in the brief)* `init_command.rs:592` asserts `rendered.contains("vault export")` | **found.** A live assertion that the false sentence is present; R5 |

---

## 2. Ruling

**Owner: U86**

### R1 — The gate does not move. Arm (a) is refused; arm (b) is taken

*Executed by: nobody — this is the constraint the rest of the act runs under.*

`init.rs:417-420` and `vault/export.rs:1208-1213` are **not touched**: not the
predicate, not the ordering, not the absence of a decode. No `CliError` variant
gains a wrap field. `existing_vault_refusal` keeps its signature
`fn(&std::path::Path) -> CliError` and stays total.

The ground is **§1.7**, not D151 §3.8's: a decode cannot classify a header that
does not decode, `NewerVersion` is exactly such a header and exactly the vault
that must not be overwritten, so a class-aware refusal still needs the
class-unknown wording this record rules — and would then add two frozen envelope
lines and an I/O-and-parse step to an infallible refusal, against D39:142-145's
*"refusing too little is not [recoverable]"*.

**Verified by**: R8's test, whose `NeverPrompts` double panics if any prompt is
reached, and which drives `import_vault` with a **path that does not exist** —
both refusals must fire before their inputs are consulted, and each becomes red
by message if the gate moves.

### R2 — `existing_vault_refusal`: the command becomes the action

*Executed by: U86's implementing lane, in `crates/antseal-cli/src/init.rs:628-634`.*

Replace the `format!` body with, verbatim:

```rust
        message: format!(
            "a vault already exists at {root} — antseal never overwrites a vault, and there is \
             no --force flag: overwriting one destroys the reveal and restore keys of every \
             work it holds, forever. If you want a fresh vault, move {root} aside instead of \
             deleting it: a moved directory keeps everything, and no antseal command has to \
             run first. Delete it only when you are certain nothing in it matters.",
            root = root.display(),
        ),
```

Rendered — **this is the exact text that must appear inside
`json-envelopes.txt:2` after R9's re-bless**, with the fixture's
`/home/user/.antseal`:

```
a vault already exists at /home/user/.antseal — antseal never overwrites a vault, and there is no --force flag: overwriting one destroys the reveal and restore keys of every work it holds, forever. If you want a fresh vault, move /home/user/.antseal aside instead of deleting it: a moved directory keeps everything, and no antseal command has to run first. Delete it only when you are certain nothing in it matters.
```

Only the third sentence onward changes; the first two sentences are
byte-identical to today.

**Why this wording and not a hedge.** *Moving the directory* is the one
instruction that is true for **every** wrap mode, needs no command, and cannot
be refused — a moved directory carries `W`, the works, the wallet record and the
config intact whatever the header says, and for a keyfile vault the keyfile is
not in that directory to begin with (`init.rs:654-662`, `default_keyfile_path`,
places it beside the vault's **parent**) and is not touched by the move either
way. D151 §3.3 refused a hedge — *"a keyfile vault is backed up by hand
instead"* — on the measurement that the class **was** in scope at its sites, so
a branch bought more; here the class is not in scope, and the hedge would still
make every reader parse a distinction they cannot act on. This is also not D151
§3.4 (*"drop the command and add nothing"*): the deleted instruction is
**replaced** by a stronger one, not removed.

`no antseal command has to run first` is load-bearing and deliberate: it is what
tells a reader who remembers the old sentence that the export step is gone
rather than merely unmentioned.

D39 Decision 4's own requirements are preserved — the error names the vault path
(twice) and tells the user to move or remove it manually. Only the parenthetical
R7 amends is dropped.

### R3 — `ImportRefusedExistingVault`: the same action, the same words

*Executed by: U86's implementing lane, in `crates/antseal-cli/src/error.rs:570-576`.*

Replace the `#[error(...)]` attribute with, verbatim:

```rust
    #[error(
        "refusing to import over the existing vault at {}: overwriting a vault \
         irreversibly destroys the reveal/restore keys of every work in it. Move that \
         directory aside yourself first — moving it keeps everything, and no antseal command \
         has to run first; delete it only when you are certain nothing in it matters. \
         Scripted overwrite-import is deliberately unsupported (D51)",
        .vault_dir.display()
    )]
    ImportRefusedExistingVault { vault_dir: PathBuf },
```

Rendered — **this is the exact text that must appear at
`cli-errors.display.txt:14` (after the two-space indent) and inside
`json-envelopes.txt:20`**:

```
refusing to import over the existing vault at /home/user/.antseal: overwriting a vault irreversibly destroys the reveal/restore keys of every work in it. Move that directory aside yourself first — moving it keeps everything, and no antseal command has to run first; delete it only when you are certain nothing in it matters. Scripted overwrite-import is deliberately unsupported (D51)
```

The first sentence and the trailing `(D51)` clause are byte-identical to today;
`yourself` is kept because it carries D39's consent framing (*"manual filesystem
action is the consent"*). `(D51)` is **deliberately not removed** — see §4.2,
which routes that question rather than answering it inside a minimal diff.

The doc comment at `error.rs:567-569` gains one sentence:

> The remedy names **no command**: this message is produced from
> `refuse_existing_target`'s `header.exists()` gate (`vault/export.rs:1208-1213`)
> with the header never decoded, so it cannot know whether `antseal vault
> export` would run for this vault — and moving the directory is the one
> instruction true for every wrap mode (D155 §2 R3).

### R4 — `commands.rs:381-386`: repaired as a different defect, and given the pin it lacks

*Executed by: U86's implementing lane, in `crates/antseal-cli/src/vault/wallet.rs` and `crates/antseal-cli/src/commands.rs:381-386`.*

Its disposition, ruled: **it is fixed in this act, on §1.8's ground, and it is
pinned by R8's test rather than by a third snapshot.**

1. **Extract the message to one author**, in
   `crates/antseal-cli/src/vault/wallet.rs` beside `load_wallet_key` — *not* in
   `commands.rs`, which is `mod commands;` and private (`lib.rs:26`), so nothing
   there can be reached by an integration test. This is `existing_vault_refusal`'s
   own precedent (`init.rs:616-617`, *"as one function so the message has
   exactly one author"*):

```rust
/// The `seal` refusal for a vault with no wallet record.
///
/// **The remedy names the step the old copy left out (D155 §2 R4).** *"Restore
/// from a `antseal vault export` backup"* could never be executed by anyone:
/// this message is reached with the vault unlocked, so its header exists, so
/// `vault::export::refuse_existing_target` refuses the import for **every**
/// wrap mode — the advice closed a cycle on the refusal it sent the reader to.
#[must_use]
pub fn no_wallet_key_refusal(root: &std::path::Path) -> CliError {
    CliError::Usage {
        message: format!(
            "this vault holds no wallet key, so it cannot pay for a seal — it was created by \
             an older build, or the wallet record was removed. There is no repair in place: \
             if you hold a vault export, move {root} aside and import into the empty path; \
             `antseal vault import` refuses to write over a vault that exists.",
            root = root.display(),
        ),
    }
}
```

Rendered:

```
this vault holds no wallet key, so it cannot pay for a seal — it was created by an older build, or the wallet record was removed. There is no repair in place: if you hold a vault export, move /home/user/.antseal aside and import into the empty path; `antseal vault import` refuses to write over a vault that exists.
```

2. **The call site becomes** `.ok_or_else(|| no_wallet_key_refusal(layout.root()))?`
   at `commands.rs:381`, with `layout` already in scope at `:380`.

3. **Why naming `antseal vault import` here is honest where naming
   `antseal vault export` was not**, and this is the general principle the act
   should be read for: the sentence is **conditioned on the artifact**
   (*"if you hold a vault export"*), not on the command. A keyfile-wrapped vault
   can never have produced an export — `vault export` refuses it
   (`export.rs:745-756`) and D151 §1.5 measured that `record_export` has one
   production caller, downstream of a successful export — so the condition is
   false for exactly the class the command would refuse, and the sentence
   promises that class nothing. Naming a command inside a false antecedent is
   safe; naming one in an imperative is not.

4. **No third re-bless.** It is not added to `exit_codes.rs::exemplars()` (that
   list holds `CliError` **variants**, and this is a `Usage` payload) and not
   registered in `machine_mode.rs` (`seal`'s registered exemplar is the backend
   arm, and displacing it would move `json-envelopes.txt:4`, which this act has
   no authority over). Its pin is R8's assertion, which now reaches it because
   `vault::wallet` is `pub mod` (`vault/mod.rs:111`).

### R5 — The two existing wording assertions that must move

*Executed by: U86's implementing lane.*

1. **`crates/antseal-cli/tests/init_command.rs:592`** —
   `assert!(rendered.contains("vault export"));` inside
   `init_over_an_existing_vault_refuses_absolutely`. It asserts the presence of
   the false sentence and **goes red on R2**, which is correct and is part of
   the red capture. Replace it with the negative form, which R8's own precedent
   (D151 §2 R11, `keyfile.rs`'s reduced guard) explicitly permits because its
   expected value is a constant from elsewhere and not the copy under test:

```rust
    // D155 §2 R2: the refusal is produced before the header is decoded, so it
    // cannot know whether `antseal vault export` would run for this vault. The
    // claim that it names no such command is held against the command's real
    // verdict in `tests/vault_keyfile.rs`; this is the local guard.
    assert!(
        !rendered.contains("antseal vault export"),
        "a class-blind refusal must not name a command that may refuse the reader's vault: \
         {rendered}"
    );
    assert!(rendered.contains("aside"), "the refusal names the action: {rendered}");
```

   `assert!(rendered.contains("no --force"))` at `:591` and the path assertion at
   `:587-590` are **kept unchanged** — both are D39 Decision 4 requirements.

2. **No other test asserts either message's wording.** Measured:
   `exit_codes.rs:248` and `:550` assert only class and exit code;
   `vault_export.rs:520` matches the variant. Nothing else greps.

### R6 — `docs/user/vault-loss.md`: the byte-quote moves and the stale locator is corrected

*Executed by: U86's implementing lane, in the same commit.* D151 §2 R12's
precedent: a doc that quotes copy byte for byte is re-synced in the act that
moves the copy, because a stale byte-quote is not true.

| file:line | change |
|---|---|
| `docs/user/vault-loss.md:252` | the fenced block → R3's rendering, with `<dir>` in place of the path exactly as today |
| `docs/user/vault-loss.md:249` | the locator `crates/antseal-cli/src/error.rs:535-542` is **stale** — that range is `NotImplemented` (`error.rs:536-541`). Correct it to **`crates/antseal-cli/src/error.rs:570-577`** and re-verify after the edit, since R3 changes the attribute's own line count |
| `docs/user/vault-loss.md:255` | *"Moving the old directory aside by hand *is* the consent."* — **already true, already the instruction R3 adopts.** Re-verify only; do not edit |

`docs/user/vault-loss.md:182-189` (*"If your vault uses a keyfile, `export`
refuses"*) and `docs/user/vault-theft.md:219-224` are unaffected: neither quotes
either message. No doc quotes `existing_vault_refusal` at all — measured,
`grep -rn "a vault already exists at" --include=*.md .` returns nothing.

After the edits, `python3 scripts/check-copy-style.py` (flagless) → **0**.

### R7 — `docs/decisions/D39-init-interaction-model.md` gains a dated addendum

*Executed by: U86's implementing lane, in the same commit* — a record that
mandates a sentence the code no longer emits is the trap D151 §5.6 item 1 named,
and this is its second instance. Appended at the end of the file, verbatim:

> ## Amendment (2026-08-19, U86 / D155 §2 R7): Decision 4's *"after `vault export`"* parenthetical is struck
>
> Decision 4 (`:87-95`) resolves the absolute refusal as *"the error names the
> vault path and tells the user to move/remove it manually **(after
> `vault export` if they want the contents)**"*. The parenthetical was true when
> this record was written and has been false since **U8** landed on 2026-08-02:
> `vault export` refuses any vault whose header wrap mode is non-zero
> (`crates/antseal-cli/src/vault/export.rs:745-756`), and both messages Decision
> 4 governs — `init::existing_vault_refusal` and
> `CliError::ImportRefusedExistingVault` — are produced from a `header.exists()`
> gate with the header never decoded (`init.rs:418`,
> `vault/export.rs:1208-1213`), so **neither can know whether the command it was
> naming would run**. The overturn of the export side was recorded in U8's
> register row and in `export.rs`'s module docs, and written into D47 only by
> D151 §2 R2; it was never written **here**, and this record is where an
> implementer of the refusal copy looks.
>
> **What replaces it.** The remedy is now *"move the directory aside instead of
> deleting it"*: the one instruction true for every wrap mode, requiring no
> command and refusable by none. The exact strings are D155 §2 R2 and §2 R3.
> Everything else in Decision 4 stands unchanged — no override flag exists, the
> error names the vault path, manual filesystem action is the consent, and
> `vault import` keeps its own refusal.
>
> **Not amended:** the Residual-risk paragraph (`:142-145`). Its verdict —
> *"refusing too much is recoverable, refusing too little is not"* — is the
> ground on which D155 §2 R1 keeps the `header.exists()` predicate and refuses
> to hang a fallible decode off it.

### R8 — The test: one message, every class, held against the command's measured verdict

*Executed by: U86's implementing lane. Home:
`crates/antseal-cli/tests/vault_keyfile.rs`, immediately after
`the_backup_advice_matches_what_export_actually_does` (`:408-520`)* — that file
already owns `Dir`, `create_vault_with_wrap`, `WrapChoice`, `export_vault` and
the `EXPORT_COMMAND` constant (`:361`), and its module doc already claims *"what
`vault export` does with a two-factor vault"*.

**Why it cannot be D151 R10's biconditional.** R10 compares *class-keyed* copy
against a *per-class* verdict. Here one string serves every class, so the
correct claim is universally quantified: **a class-blind message may name
`antseal vault export` only if the command runs for every class it could be
shown to.** That is what the assertion encodes, and it is strictly stronger than
"the message is true for the vault in this row".

**What it constructs**: for `wrapped` in `[false, true]`, a real vault via
`create_vault_with_wrap(&layout, &passphrase(), KdfSelection::Argon2id, &wrap,
&mut rng(0x55))` with `WrapChoice::None` / `WrapChoice::Keyfile { path,
record_path: true }` — both forms already used in this file (`:250`, `:334`).

**What it drives — all three real producers, never a hand-copied string**:

- `export_vault(&vault, &passphrase(), &out, &mut rng(0x56))` — the real command
  engine, per class, for the **verdict**.
- `run_init(&layout, &args, None, true, NetworkId::Devnet, &mut NeverPrompts,
  &mut rng(0x57))` against the vault that already exists — the real `init` gate,
  for the **init message**. `args` is built the way `init_command.rs` builds it,
  or by destructuring `Cli::parse_checked(["antseal", "init"])`'s
  `Command::Init(args)`; the wrap value is irrelevant because the gate at
  `init.rs:418` fires first.
- `import_vault(Path::new("<dir>/does-not-exist.sealvault"), &layout, ||
  panic!("the refusal must precede the passphrase"), &mut rng(0x58))` — the real
  `import` gate, for the **import message**. **The nonexistent path is
  deliberate**: `import_vault_impl:1031-1034` refuses at step 1 and reads at
  step 2, so a refusal that started reading first would surface `CliError::Io`
  instead, red by message.

**The prompt double, which is an assertion and not a stub**:

```rust
/// Every `InitPrompt` method panics: the existing-vault refusal fires at
/// `init.rs:418`, before the wizard, and the comment there says so
/// (*"the refusal must happen before a passphrase is collected"*). If the
/// gate is ever moved below the wizard to learn the wrap mode — D155 §2 R1's
/// refused arm (a) — this panics instead of returning a message.
struct NeverPrompts;

impl InitPrompt for NeverPrompts {
    fn ask_choice(&mut self, q: &str, _: &[&str], _: &str) -> Result<String, CliError> {
        panic!("the existing-vault refusal must precede every prompt; was asked: {q}")
    }
    fn read_secret_line(&mut self, q: &str) -> Result<SecretBuf, CliError> {
        panic!("the existing-vault refusal must precede every secret prompt; was asked: {q}")
    }
}
```

**What it asserts**:

```rust
/// **U86 / D155 §2 R8.** Two class-blind refusals, held against what
/// `vault export` actually does — for *every* class, because neither
/// message can see the one in front of it.
///
/// The claim is universally quantified and that is the whole point: a
/// message produced before the header is decoded may name
/// `antseal vault export` **only if** the command runs for every wrap mode
/// it could be shown to. Today it does not, so the honest text names no
/// command (D155 §2 R2/R3); if the export ever stopped refusing wrapped
/// vaults, this test would demand the command be named again rather than
/// silently accept copy written for the old world.
///
/// Do not reduce this to `assert!(!msg.contains(EXPORT_COMMAND))`. That
/// version is green for the wrong reason — it can never notice that the
/// product's behaviour moved, which is the exact fault U86's Accept row 3
/// requires to be watched.
#[test]
fn the_class_blind_refusals_name_no_command_that_could_refuse_the_reader() {
    let mut verdicts: Vec<bool> = Vec::new();
    let mut messages: Vec<(&'static str, String)> = Vec::new();

    for wrapped in [false, true] {
        // ... construct the vault of this class ...

        // 1. What `vault export` DOES for this class, measured.
        let export = export_vault(&vault, &passphrase(), &out, &mut rng(0x56));
        verdicts.push(export.is_ok());
        assert_eq!(
            export.is_ok(), !wrapped,
            "wrap mode {wrapped}: `vault export`'s verdict moved. That is a D47 format \
             event and D151 §2 R1 must be re-ruled before this copy changes: {export:?}"
        );

        // 2. The two refusals, driven for real, one per class. Both messages
        //    are class-blind, so both must be IDENTICAL across the two rows —
        //    asserted below, because a message that varied by class would mean
        //    the gate moved and D155 §2 R1 was overturned in silence.
        let init_err = run_init(/* ... */, &mut NeverPrompts, &mut rng(0x57))
            .expect_err("init over an existing vault refuses");
        assert_eq!(init_err.class(), ErrorClass::Usage, "{init_err:?}");
        let import_err = import_vault(&missing, &layout, || panic!("..."), &mut rng(0x58))
            .expect_err("import over an existing vault refuses");
        assert!(
            matches!(import_err, CliError::ImportRefusedExistingVault { .. }),
            "the import refusal must be the deliberate one, not an I/O error from \
             reading the file first: {import_err:?}"
        );

        messages.push(("init", init_err.to_string()));
        messages.push(("import", import_err.to_string()));
    }

    // 3. Anti-vacuity, all three arms. Without these an empty or truncated
    //    message satisfies step 4 for free.
    for (site, msg) in &messages {
        assert!(msg.len() > 200, "{site}: message is {} bytes: {msg}", msg.len());
        assert!(
            msg.contains(&layout_root_string),
            "{site}: the refusal must name the vault path (D39 Decision 4): {msg}"
        );
        assert!(msg.contains("aside"), "{site}: no remedy in the message: {msg}");
    }
    assert_eq!(messages[0].1, messages[2].1, "`init`'s refusal must be class-blind");
    assert_eq!(messages[1].1, messages[3].1, "`import`'s refusal must be class-blind");

    // 4. The claim. A class-blind message may name the command exactly when
    //    the command runs for EVERY class.
    let runs_for_every_class = verdicts.iter().all(|ok| *ok);
    for (site, msg) in &messages {
        assert_eq!(
            msg.contains(EXPORT_COMMAND), runs_for_every_class,
            "{site}: the refusal {} `{EXPORT_COMMAND}` while the command runs for {} of the \
             {} wrap modes measured ({verdicts:?}). U86: a message produced before the \
             header is decoded may name a command only if that command runs for every \
             vault it may be shown to.\n  message: {msg}",
            if msg.contains(EXPORT_COMMAND) { "names" } else { "does not name" },
            verdicts.iter().filter(|ok| **ok).count(), verdicts.len(),
        );
    }

    // 5. R4's site: the same rule, for a message whose remedy is an ARTIFACT
    //    and not an imperative. It may name `vault import` because its
    //    antecedent ("if you hold a vault export") is false for exactly the
    //    class that command refuses — but it may never name the export.
    let no_wallet = no_wallet_key_refusal(layout.root()).to_string();
    assert!(!no_wallet.contains(EXPORT_COMMAND), "{no_wallet}");
    assert!(no_wallet.contains("refuses to write over a vault that exists"), "{no_wallet}");
    assert!(no_wallet.contains(&layout_root_string), "{no_wallet}");
}
```

**The redness seam. Each fault is planted alone, the failure is verified *by its
message* (a crash exits nonzero too), and the file is restored and re-verified
by sha256 against a digest taken before planting.**

| # | planted fault | goes red at | why it is the fault that matters |
|---|---|---|---|
| **T1** | delete **both** wrap refusals — `export.rs:745-756` **and** `:520-535` | step 4, **both sites** | **The truth-plant U86's Accept row 3 names.** `verdicts` becomes `[true, true]`, `runs_for_every_class` flips to `true`, and the assertion demands the command be named — the message that is correct today becomes wrong, by message. **Deleting only `:745-756` does NOT work and must not be used:** `vault_keyfile.rs:449-457` records the measurement — the mandatory D47 self-verify re-reads the file through import-side validation, whose own wrap refusal fails it as `ExportSelfVerifyFailed`, so `is_ok()` stays `false` in both worlds. This is the project's dominant defect class, already caught once here; do not re-discover it |
| **T2** | revert R2 (put the old sentence back in `existing_vault_refusal`) | step 4, `init` | wording plant, init half |
| **T3** | revert R3 (put the old parenthetical back in the `#[error]`) | step 4, `import` ×2 rows | wording plant, import half |
| **T4** | move `init.rs:417-420` below the wizard (arm (a)'s first move) | `NeverPrompts::ask_choice` panics | proves R1's ordering invariant is held by a mechanism, not by a comment |
| **T5** | move `refuse_existing_target(target)?` below `read_bounded` in `import_vault_impl` | the `matches!(import_err, ImportRefusedExistingVault)` assert | the nonexistent path yields `CliError::Io` instead — proves *"before anything is read"* is witnessed |
| **T6** | make either message vary by class (e.g. thread a `wrapped` flag into `existing_vault_refusal` and branch) | step 3's two `assert_eq!(messages[..])` | proves R1 cannot be overturned silently |
| **T7** | return an empty `String` from either message | step 3's length / path / `aside` asserts | proves step 4 is not passing on an empty string |
| **T8** | revert R4 (restore *"Restore from a `antseal vault export` backup"*) | step 5's first assert | pins the third site, which no snapshot reaches |

T1 and T6 are the two a copy-versus-copy test cannot see, and they are why this
test exists. T1 is the one U86's Accept row 3 names by hand.

### R9 — `json-envelopes.txt`: authority, red first, determinism, and the exact authorised diff

*Executed by: U86's implementing lane.*

**Authority for the freeze event: this record, §2 R2 and §2 R3.** U32 is the
**release** freeze and has not run, so no release freeze is broken; the
snapshot's own failure message already licenses a deliberate move
(*"machine-interface changes are reviewed, versioned events (regenerate with
`ANTSEAL_BLESS=1`)"*, `machine_mode.rs:1321-1323`). Per the U80 precedent that
D151 §1.8 established, **the test's failure message is not edited to name D155**
— it names the freeze; the mover is named in the row.

**Baseline, measured by this lane before any edit:**

```
sha256  b4f073801a4132ced7c0d11ca78f1ff1c87aea018539f736ea150aa6a8801fd9
        crates/antseal-cli/tests/snapshots/json-envelopes.txt   (48 lines, 16 286 bytes)
```

**Procedure, exactly:**

1. `sha256sum crates/antseal-cli/tests/snapshots/json-envelopes.txt` **before**;
   require the digest above. A different digest means another lane moved the
   file and this procedure restarts.
2. Land R2, R3, R4, R5. Run **without** the bless var and capture the red:
   `cargo test -p antseal-cli --test machine_mode 2>&1 | tail -40; echo "REAL_EXIT=${PIPESTATUS[0]}" >> <file>`
   — read `REAL_EXIT` back **out of the file**. Require a **non-zero** exit
   **and** require the failure to be
   `envelope_fixtures_match_the_committed_snapshot` reporting the drift, not a
   compile error and not a panic elsewhere. A red here proves the snapshot was
   actually pinning both lines.
3. `ANTSEAL_BLESS=1 cargo test -p antseal-cli --test machine_mode envelope_fixtures_match_the_committed_snapshot`.
4. Re-run step 2 without the var; require green.
5. `sha256sum` **after**, and `git diff --numstat` on the snapshot.

**The authorised diff, stated per line — anything else is unintended and must be
explained before the commit:**

| line | change |
|---|---|
| `2` | `[init] error` envelope — the `message` field takes R2's rendering. **Modified, not added.** |
| `20` | `[vault import] error` envelope — the `message` field takes R3's rendering. **Modified, not added.** |

**`git diff --numstat` must read exactly `2	2	crates/antseal-cli/tests/snapshots/json-envelopes.txt`**, and the file must
still be **48 lines**. No line is inserted, deleted or reordered; no other
command's envelope moves. In particular `:4` (`seal`), `:18` (`vault export`)
and `:34` (the `seal` success envelope carrying `export_nag`) are
**byte-identical** — R4 deliberately registers no new exemplar (§2 R4 item 4),
and D151 §2 R6 already established that the `wrapped` field does not ride
`--json`.

6. **Determinism by two processes, not by argument**: run step 3 a **second**
   time in a fresh process and require the same `sha256sum`. Record both
   digests.
7. `python3 scripts/check-copy-style.py` (flagless; safe) → expect **0**. The
   snapshot is inside `COPY_SCAN`'s directory entry (`:100`) and both new
   strings were pre-linted against the real rules (§1.9).

### R10 — `cli-errors.display.txt`: the same discipline, one line

*Executed by: U86's implementing lane.*

**Authority: this record, §2 R3.**

**Baseline, measured by this lane before any edit:**

```
sha256  c45522a742843106da2a34e943e3ae98148c4605dfd644c74507c2692d70321b
        crates/antseal-cli/tests/snapshots/cli-errors.display.txt   (92 lines, 11 143 bytes)
```

Same seven steps as R9, with `--test exit_codes` and
`display_output_matches_committed_snapshot`.

**The authorised diff:**

| line | change |
|---|---|
| `14` | the `[import-refused-existing-vault]` body — R3's rendering, keeping the two-space indent `render_displays` emits (`exit_codes.rs:604-608`). **Modified, not added.** |

**`git diff --numstat` must read exactly `1	1	crates/antseal-cli/tests/snapshots/cli-errors.display.txt`**, and the file must still be **92 lines**. Line `13`
(`[import-refused-existing-vault] class=consent-not-obtained code=10`) does
**not** move — no class and no exit code changes in this act. **Line `76`
(`[export-self-verify-failed]`) does not move**: it is `error.rs:817-819`,
excluded because `ExportSelfVerifyFailed` is constructed only at
`export.rs:967`/`:970`/`:973`, all downstream of the wrap refusal at `:745`, so
only a mode-0 vault reaches it and the sentence is true by construction —
re-verified by this lane (§1.10).

Also required green, unchanged and unedited:
`display_output_is_single_line_and_fully_rendered` (`exit_codes.rs:640-648`) —
R3's string is single-line, measured at §1.9.

### R11 — U86's `Accept` rows: dispositions, verbatim for the registrar

- **Row 1** (*"No `init` or `import` refusal promises a command that refuses the
  reader's vault, proven by a test that exercises the refusal rather than the
  wording"*) — **met, and strengthened**: R8 drives `run_init` and
  `import_vault` for real, per class, and holds the claim against
  `export_vault`'s measured verdict rather than against the copy.
- **Row 2** (each re-bless captures its red first; determinism by two blessing
  processes producing one sha; the diff justified as a deliberate freeze event
  naming its authority) — **met by R9 and R10**, whose authority is this record,
  §2 R2 and §2 R3. The row must carry, for **each** snapshot, the before/after
  sha256 pair, the two-run determinism digest, and the `git diff --numstat`
  figure (`2	2` and `1	1`).
- **Row 3** (a planted change to the claim's **truth**, not its wording, watched
  red by message) — **met by R8's T1**, *with the correction that T1 must delete
  **both** wrap refusals*; the single-site plant is measurably inert
  (`vault_keyfile.rs:449-457`).
- **Row 4** (`commands.rs:383`'s disposition recorded either way) — **met by
  R4**, which fixes it as a **different** defect (§1.8), gives it one author,
  and pins it in R8 step 5.
- **Row 5, appended**: *"`docs/decisions/D39-init-interaction-model.md` no
  longer prescribes the false parenthetical (D155 §2 R7's addendum), and
  `docs/user/vault-loss.md`'s byte-quote and its stale `error.rs:535-542`
  locator are corrected (D155 §2 R6)."*

### R12 — What must NOT be touched in this act

1. `init.rs:417-420` and `vault/export.rs:1208-1213` — predicate, ordering,
   absence of a decode (R1).
2. `export.rs:745-756` and `:520-535` — the wrap refusals; predicate, message,
   class, tests. Unchanged since D151 §2 R1 and re-affirmed here.
3. `error.rs:817-819` and `cli-errors.display.txt:76` (R10).
4. `error.rs`'s **class** and **exit code** for `ImportRefusedExistingVault`:
   `ConsentNotObtained`, exit **10** (`error.rs:921`, `exit_codes.rs:549-555`).
   D51's mapping is untouched, so `cli-errors.display.txt:13` does not move.
5. `bookkeeping.rs`'s `LOSS_WARNING` / `THEFT_WARNING` / `BACKUP_BY_EXPORT` /
   `BACKUP_BY_HAND`, `init::standing_warnings`, `export_nag`,
   `placement_guidance`, and `crates/antseal-cli/tests/snapshots/init-report.txt`
   — all D151's, all landed, none in scope. `init-report.txt` must not move.
6. `crates/antseal-cli/tests/snapshots/cli-surface.help.txt` — no surface
   changes; no flag is added to `vault export|import` (MVP-SPEC.md line 149).
7. `scripts/check-copy-style.py` — not modified, and `--self-test` not run.
8. The two snapshot tests' **failure messages** (`machine_mode.rs:1321-1323`,
   `exit_codes.rs:631-634`): they name the freeze, not the mover (U80
   precedent, D151 §1.8).
9. `EXPORT_FORMAT_VERSION`, the export header, the payload schema, the vault
   header. **No format event.**

---

## 3. What was refused and why

### 3.1 Arm (a) — move the gate and decode the header to learn the wrap mode

**The arm the brief asked to be tested hardest. Refused — but on §1.7's ground,
not on D151 §3.8's, which §1.6 shows does not hold.**

The strongest form of the arm was constructed and tested: `unlock_vault_impl`
already decodes the header pre-auth on every unlock (`session.rs:391`), so the
parser is not a new exposure; `refuse_existing_target` holds the target
`VaultLayout` and could decode too; and the wrap mode is one `u8` away from
`beside_path(BesideFile::Header)`. On the parser argument alone, arm (a) is
affordable.

It fails on a different measurement: **a decode cannot answer for every vault
that must be refused.** `VaultHeader::decode` has eight read-side failure classes
(`header.rs:93-144`), and `NewerVersion` — a vault written by a newer antseal —
is both the case a decode provably cannot classify and the case where destroying
`W` is least recoverable. Arm (a) therefore needs a class-unknown branch whose
wording is R2 and R3 verbatim; it is **additive to this ruling, not an
alternative to it**, and what it adds is two more frozen envelope lines
(`machine_mode.rs:405` registers one exemplar), an I/O-and-parse step on a
refusal that is total today, and a third message on the surface U32 is about to
ratify. `D39:142-145` prices exactly this trade and answers it: *"refusing too
much is recoverable, refusing too little is not."*

Parked. If a future format event makes the wrap readable without a fallible
decode, R2/R3's wording remains correct and the branch becomes an addition, not
a correction.

### 3.2 Arm (c) — make `vault export` work for keyfile-wrapped vaults

**Refused, and not re-litigated.** D151 §3.1 measured it against the format: the
flag must be readable before the key exists, so it must live in the export
**header** (`export.rs:11-14`, body v1 `map { 0: kdf_block, 1: nonce }`, and the
header is the AAD); the payload's `wrap_mode` slot is inside the AEAD and is
write-dead; it needs a second key-combine in the one artifact whose failure is
discovered at disaster time; and it needs an import-side keyfile channel that
MVP-SPEC.md line 149's flagless `vault export|import` has nowhere to put
(re-quoted verbatim at §1.3). It would also falsify three shipped pages that
document the refusal as a priced trade (D151 §1.7). Nothing U86 measured moves
any of that. **It is a D47 header format event, at M4, with U32 pending.**

The one thing this record adds: U86 is **not** a reason to reopen it, because
U86's two messages are honest under R2/R3 whether or not the export ever carries
the wrap — R8's step 4 is written so that a future world where it does turns the
assertion around and demands the command be named again.

### 3.3 Hedge inside one unconditional sentence — *"(a keyfile vault is backed up by hand instead)"*

**Refused.** It is D151 §3.3's shape, and although §3.3's killing measurement
(*the class is in scope, so a branch buys more*) does **not** transfer — here the
class is genuinely unavailable — the hedge still fails on its own terms at these
two sites. The reader of an existing-vault refusal is about to delete a
directory; a parenthetical asking them to work out which kind of vault they have
adds a decision at the moment when the product's job is to remove one. R2's
*"move it aside"* is correct for both classes **without** the reader classifying
anything, which is strictly better than a hedge and is available only because
the remedy was changed from a command to an action.

### 3.4 Delete the remedy sentence and add nothing

**Refused**, on D151 §3.4's ground: fixing a false instruction by deleting the
true part of it is not a fix. These are the highest-consequence messages in the
product — both are read by someone about to remove a directory holding every
sealed work's reveal keys — and leaving them with *"move or remove it yourself"*
and no statement that moving preserves everything would drop the only fact that
makes the safe choice obvious.

### 3.5 Point the reader at the docs or at `https://antseal.org/`

**Refused.** A CLI refusal cannot cite a repository path, and adding the
canonical URL to an error message is a copy surface change this record has no
authority over (P6 pins one URL, `check-copy-style.py:256`, and it is the
verifier's). It also defers an action the reader can take immediately: moving a
directory needs no page.

### 3.6 Add a Q251 clause for this defect

**Refused — measured, not assumed.** Q251 collects **MVP-SPEC.md line 143's**
divergences, and D151 §2 R15 already added clause (v) for the one that underlies
this row (line 143 promises `vault export`/`import` **and** a keyfile wrap;
shipped antseal makes them mutually exclusive). U86 is a **consequence** of
clause (v), not a new divergence: §1.3 measures that line 143's nag clause does
not reach either refusal, so nothing here diverges from the spec. Adding a sixth
clause would double-count clause (v). **Q251 is not edited by this act.**

### 3.7 Remove `(D51)` from the import message while it is being re-blessed

**Refused, and routed instead (§4.2).** It is a free byte in a diff that is
already open, which is exactly why it should not ride here: the diff R10
authorises is one line and its justification is R3, and *"we were in there
anyway"* is how a freeze event acquires content nobody ruled. The question it
raises is real and larger than this string — routed.

---

## 4. Routed, not ruled

### 4.1 A wrapped vault's owner has no `init`/`import` path that mentions their backup at all

R2 and R3 make both refusals class-independent, which is correct and is also a
loss: a keyfile user standing at the delete-the-vault moment is told to move the
directory and is told nothing about the **keyfile**, which lives outside it
(`init.rs:654-662`). It is not being deleted by the operation in front of them,
so the messages are true — but the complete backup story for that class is two
pieces, and only `BACKUP_BY_HAND` (D151 §2 R4) ever says so, at `init` time and
on every seal. Whether a class-blind refusal should carry a *pointer* to that —
without naming a command and without a hedge — is a copy question this record
does not answer. **Needs a row.**

### 4.2 R82's rule is stated generally and its test scans four messages

`machine_mode.rs:1345-1405` (`the_refusal_messages_name_no_task_row`) states the
rule as *"A refusal a user reads cannot cite a task identifier: they cannot look
it up… no row-shaped token may appear at all"* and its `row_tokens` scanner
treats `D` as a row prefix (`PREFIXES` at `:1350`). Its **population**, however,
is `BackendArm::ALL × ["seal", "restore", "reveal", "verify"]` (`:1391-1392`) —
four messages. Outside that population, at least two shipped user-facing
messages cite decision ids: `error.rs:574` *"(D51)"* and `error.rs:819`
*"(D47)"*, both frozen in `cli-errors.display.txt` (`:14`, `:76`), and
`vault/session.rs:228` *"(D39)"*. Whether the rule should be widened to the
whole `exemplars()` set, or narrowed in its statement to match its scope, is a
decision — and widening it moves `cli-errors.display.txt` again, so it must be
taken deliberately and not as a side effect of this act. **Needs a row.** R3
keeps `(D51)` unchanged precisely so that this stays one decision.

### 4.3 `init`'s existing-vault refusal has two authors, not one

`init.rs:616-617` says the message exists *"as one function so the message has
exactly one author"*. `vault/session.rs:225-232` is a second author for the same
condition with different words — *"a vault already exists at {} — antseal never
overwrites a vault (D39)"* — reachable only as a defensive duplicate after
`run_init`'s gate (or on a TOCTOU race, or by a direct `create_vault` caller). It
does **not** name `vault export`, so it is not U86's defect and R12 leaves it
alone. But the one-author claim in the rustdoc above `existing_vault_refusal` is
false as written, and the second message is in no snapshot. **Ledger, and a
candidate row.**

### 4.4 D39:142-145 describes a predicate the code does not implement

D39's residual risk says *"a wiped-but-present `~/.antseal/` (e.g. an empty dir
left by a failed manual cleanup) **also refuses**"*. The shipped predicate is
`header.exists()` (`init.rs:418`, `session.rs:225`), so an empty
`~/.antseal/` does **not** refuse — `init` proceeds and creates the vault inside
it. The divergence is in the **safe** direction (an empty directory holds no `W`
to destroy) and R7 deliberately does not amend that paragraph, because its
verdict is what R1 rests on. Recording it so the next reader of D39 does not
take the parenthetical as a description of the code. **Ledger.**

### 4.5 The `import` refusal is exercised by no test either, before R8

`refuse_existing_target`'s message is constructed in three test files
(`exit_codes.rs:248`, `:550`, `machine_mode.rs:383`) and matched in one
(`vault_export.rs:520`), but before R8 nothing drove `import_vault` into it and
nothing drove `run_init` into `existing_vault_refusal` at all —
`init_command.rs:561-593` drives the gate but asserts only wording. Both
gates are now exercised by R8; noting that they were not, because the same
class-blind sentence sat in two machine contracts for the life of the project
with no test that made the product produce it. **Ledger.**

---

## 5. Registrar's edit set

### 5.1 `docs/decisions/README.md`

Insert, in ascending id order:

```
| [D155](D155-class-blind-vault-refusal-copy.md) | U86 — two class-blind `init`/`import` refusals name `antseal vault export` to users the command may refuse. **The reword stands and the gate stays, on none of the reasons on record.** `D39-init-interaction-model.md:87-95` — Decision 4 itself — **prescribes** the false parenthetical *"(after `vault export` if they want the contents)"*, true when written and falsified by U8 on 2026-08-02, which is D151 §1.1's defect repeating in a second record and is amended here by dated addendum (R7). The gate's comment (`init.rs:412-416`) states a **pre-passphrase** invariant, not the pre-decode one the row quotes; D151 §3.8 **did** rule arm (a) out, contrary to the row, and its stated ground does not hold — `VaultHeader::decode` is already the pre-auth parser on every unlock (`session.rs:391`). What actually refuses arm (a) is that **a decode cannot answer**: eight read-side failure classes, `NewerVersion` among them, so a class-aware refusal still needs the class-blind wording and is strictly additive. Both sites are blind for **one** reason — the `header.exists()` gate, not D151's *"no vault exists in the type"*. The remedy stops being a command and becomes an action, *"move it aside instead of deleting it"*, true for every wrap mode and refusable by none. **`commands.rs:383` is a different defect and worse**: *"Restore from a `antseal vault export` backup"* is reached with the vault unlocked, so `vault import` refuses for **every** class, 100 % of the time — advice that closes a cycle on the other message this record rewords. Two machine contracts re-blessed as deliberate freeze events with per-line authorised diffs; the truth-plant must delete **both** wrap refusals, because the single-site plant is measurably inert | RESOLVED | 2026-08-19 |
```

### 5.2 `TODO.md` — decision register

Add the D155 row in the same wording as §5.1, ticked (`- [x]`), and update the
header's decision figures **by script, never by increment**
(`python3 scripts/check-traceability.py`, flagless — that run *is* the check;
there is no `--check` flag).

### 5.3 `TODO.md` — U86's row (`TODO.md:854`)

**Mandatory, not optional.** `check_decision_owners`
(`scripts/check-traceability.py`) reds when an `**Owner: U86**` assignment exists
in a resolved decision whose owner's row never names it; this record carries that
assignment at §2. Append to the row, before the tick:

> · **ruled by D155** (2026-08-19): arm (b), reword both sites; the gate does
> **not** move. Its two premises are corrected — the comment at `init.rs:412-416`
> states a pre-**passphrase** invariant, not a pre-decode one, and **D151 §3.8
> did rule arm (a) out** (on a ground that does not hold; the real ground is that
> a decode cannot classify a header that does not decode). **D39 Decision 4
> prescribes the false sentence** and is amended by D155 §2 R7.
> `commands.rs:383` is a **different** defect — false for every class, because
> `vault import` always refuses over an existing vault — and is fixed by D155 §2
> R4. Two re-blesses at `2	2` and `1	1` lines; the truth-plant deletes
> **both** wrap refusals

and correct the row's own sentence *"fires on `header.exists()` **alone** at
`init.rs:418` — before any decode, so it cannot know the wrap mode, and **the
comment above the gate states that invariant deliberately**"* by replacing the
bolded clause with *"and the comment above the gate states a pre-**passphrase**
invariant, not a pre-decode one (D155 §1.5) — the arm is refused by D151 §3.8 and
re-grounded by D155 §2 R1"*.

### 5.4 `tasks/U.md` — U86's entry (`### U86`, `tasks/U.md:1241` onward)

1. **`Problem`** — apply the same correction as §5.3 to the *"the comment above
   the gate states that invariant deliberately"* clause; correct the
   `ImportRefusedExistingVault` locator from `error.rs:570-574` to
   **`error.rs:570-577`** (§1.1); and add the two sites the row does not name:
   *"and `docs/user/vault-loss.md:252` quotes the import message byte for byte
   under a **stale** locator (`:249` cites `error.rs:535-542`, which is
   `NotImplemented`), while `crates/antseal-cli/tests/init_command.rs:592`
   asserts the false sentence is present."*
2. **`Notes`** — replace *"**D151 did not rule between those**, and neither
   should an implementer without a decision"* with *"**D151 §3.8 did rule
   between those** — it refuses arm (a) by name, in a refused-arms section of a
   record whose owning row is `[x]`, which is why it was not found. D155 §2 R1
   re-grounds the refusal: D151 §3.8's stated reason (pre-auth parsing) does not
   hold, because `VaultHeader::decode` already runs pre-auth on every unlock
   (`vault/session.rs:391`)."*
3. **`Accept`** — apply R11 verbatim: rows 1-4 dispositioned, row 5 appended.
4. **`Spec`** — keep lines 143 and 149, and add *"— line 143 constrains this row
   only negatively: its nag clause governs the standing warnings (D151 R3/R4/R6),
   not either refusal (D155 §1.3)"*.
5. **`Deps`** — add *"consumes D39 Decision 4 (amended by D155 §2 R7) and D155"*.

### 5.5 What is NOT edited

- **`tasks/Q.md` / Q251** — no clause is added; §3.6 measures why (this is a
  consequence of D151 §2 R15's clause (v), not a sixth divergence).
- **`docs/decisions/D151-vault-export-backup-advice.md`** — not amended. Its
  §1.3 reason for the import half is superseded by D155 §1.4 and its §3.8 ground
  by D155 §1.6/§1.7, but D151 is `RESOLVED` and its **conclusions** all stand;
  the corrections live here and are indexed from §5.1. Whether D151 gets a
  cross-reference addendum is the registrar's call, not this record's — the same
  disposition D151 §4 item 7 gave D50.
- **No Rust source, no snapshot, no doc** — this is a planning lane and nothing
  was landed. `git diff --stat` at this lane's close shows only other lanes'
  files; `docs/decisions/` is otherwise untouched.

### 5.6 `docs/instrument-ledger.md`

Five findings from this lane, none of them a task:

1. **A second decision record prescribing what the code must stop saying.**
   D39 Decision 4's *"(after `vault export` if they want the contents)"* has been
   false since 2026-08-02 — the same shape as D151's D47 finding, recorded in
   this ledger 24 hours earlier and not applied to the sibling record. *When a
   deviation falsifies one record, sweep every record that prescribes the same
   sentence, not only the one the row cites.*
2. **A row and a register entry that both mis-quote a code comment.** U86's
   `Problem`/`Notes` and `TODO.md:854` say the gate's comment states a pre-decode
   invariant; it states a pre-passphrase one (§1.5). The claim travelled from
   D151 §3.8's paraphrase into two files without being read at the site.
3. **A refused-arms section is where a ruling goes to be lost.** D151 §3.8
   ruled arm (a) out; U86 was minted saying no ruling existed. *A refusal that
   binds a future row belongs in that row's `Notes`, not only in the deciding
   record's §3.*
4. **`docs/user/vault-loss.md:249` cites `error.rs:535-542`, which is
   `NotImplemented`** — a byte-quote in a user page anchored to an unrelated
   error variant, found only because this act had to move the quote (§1.9,
   §1.10).
5. **Two class-blind refusals in two machine contracts, exercised by no test.**
   Before R8 nothing drove `run_init` or `import_vault` into either gate; both
   were pinned by rendered fixtures only (§4.5).

### 5.7 What the registrar must NOT do

Assign an id to §4's routed rows from inside this record (they are described,
not numbered), tick U86 (this is a planning lane; nothing was implemented), edit
any Rust source or snapshot, or run `scripts/local-gate.sh` or any
`--self-test` while other lanes hold this tree.
