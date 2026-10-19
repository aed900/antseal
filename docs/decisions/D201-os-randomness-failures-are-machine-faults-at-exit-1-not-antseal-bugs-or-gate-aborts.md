# D201 — An unavailable OS random source is **a fault of the machine**, reported in class `internal` (exit 1) **in its own words**: the gate's `Entropy` refusal leaves class 22, every OS-CSPRNG failure routes through one `CliError` variant whose message names the machine and not antseal, and no such message offers a timestamp authority, `--force-degraded` or `antseal abandon`

- **Status: RESOLVED. H13, for `U103`, fell (a), on its premise. `U104` is minted by this
  wave's rulings and ruled here; no lean was sent for it.**
  - **H13 — *`Entropy` keeps class 22 with its own way-forward clause (no exit-code move
    before `U32`)*.** (a):
    - **"No exit-code move before `U32`" inverts the timing rule.** D134 §2 R3 (1) is a
      reservation that `U32` freezes: the exit-code table becomes append-only **at** `U32`. So
      before `U32` is exactly when a failure may change class.
    - **Class 22's definition is false for this arm on both of its clauses.**
      `crates/antseal-cli/src/error.rs:32` defines 22 as *"zero TSA tokens and no
      `--force-degraded`; aborts pre-payment"*. No TSA was asked
      (`crates/antseal-anchor/src/submit.rs:299-300`), and `--force-degraded` cannot avoid the
      refusal, because every TSA nonce is drawn before the gate evaluates (§1.2). Keeping 22
      keeps a class whose meaning is untrue for this arm.
    - **Keeping 22 costs more, not less.** It needs a discriminant on `AnchorGateAbort` or a
      second class-22 variant, and 22's definition widened in two documents so that one class
      means both *"the TSAs gave no token that counts"* and *"this machine has no randomness"*
      — the triage the arm's own doc forbids (`crates/antseal-anchor/src/gate.rs:219-222`).
  - **Found with it, and minted as `U104`: the class every other OS-CSPRNG failure already has
    carries a false clause.** Six CLI sites and core's crypto error already exit 1, and every
    one of them prints *"(this is a bug in antseal — please report it)"* (`error.rs:556`).
    An unavailable OS random source is not an antseal bug (§1.4). Moving `Entropy` into that
    class with that text would have added the false clause to a seventh message, so the two
    rows are ruled together: `U103` decides the class, `U104` the words.
- **Date: 2026-10-19**
- Owner rows: **`U103`** (§2 R1, R4, R5); **`U104`** (minted by this wave's rulings: *"An
  unavailable OS random source is reported as an antseal bug"*, at seven sites; §2 R2, R3, R5).
- Related:
  - **D194** (the gate abort's message; its §6 recorded `U103`'s discovery), which takes a dated
    addendum;
  - **D134** §2 R3 (1) (the table is append-only at `U32`), which takes a dated addendum for
    row 1's text;
  - **D147** §1.7 (D147:336-340: exemplars are append-ordered, so a new one goes at the end);
  - **D90** §6.6 (a request nonce never falls back to a weaker source; cited at
    `crates/antseal-anchor/src/nonce.rs:50-53`);
  - **D45** §1 and §2 (the exact command resumes a staged work);
  - **D65** (an error's `message` is human copy at every tier; the `--json` error object keeps
    its keys);
  - **`U32`** (the freeze this lands before).

## 0. What was measured against

`HEAD` `07a170c` (= `origin/main`). The tree was clean when planning began.

Planning lane P3 (wave 39, 2026-10-19) worked read-only and built nothing; every claim below
comes from reading code, tests and records, and the full message in §1.1 is derived from code.

Before this record was written, the records lane re-read the load-bearing lines through
`git show 07a170c:<path>`, because round-1 lanes were already editing the shared tree. Most
figures held. These did not, or needed stating more exactly:
- **The contract doc defines class 1 nowhere.** The rulings name
  `docs/testing/error-code-contract.md`'s class list as a home for row 1's widened text, but
  `git show 07a170c:docs/testing/error-code-contract.md | command grep -c -i 'internal'` → 0
  (positive control: `anchor-gate-abort` → 5). Its only class definition is 22's, quoted at
  `:373-374`; its enumeration of classes (`:343-359`) lists the storage outcomes only. §2 R3
  and §5 say what follows.
- **The OTS calendars are asked before the nonces are drawn.** `submit_anchors` sends the
  anchor digest to the calendars (`crates/antseal-anchor/src/submit.rs:310`) before it draws
  the TSA nonces (`:311-317`), and the calendar half's result is then discarded (`:299-302`).
  P3 did not state this. It bounds what the gate's message may say (§2 R2).
- Locators: `SealError::Crypto(inner) => CliError::Internal` is
  `crates/antseal-cli/src/pipeline/error.rs:345-347` (P3: `:342-344`); the consent write is
  `crates/antseal-cli/src/pipeline/resume.rs:472-473`, the gate `:484` and
  `set_state(seal_id, SealState::Anchored)` `:485` (P3: `:471-472`, `:484`).

## 1. What was measured

### 1.1 The arm, and what a user reads today

- **The arm.** `crates/antseal-anchor/src/gate.rs:219-224`: *"The OS CSPRNG is unavailable, so
  no timestamp request could be built. Its own arm, and deliberately: "this machine cannot
  produce randomness" must never be triaged as "the TSAs are down". No request was sent."*,
  then `#[error(transparent)]` (`:223`) and `Entropy(#[from] crate::nonce::NonceUnavailable)`
  (`:224`). `AnchorGateError` is `#[non_exhaustive]` (`:169`).
- **Its text** is `NonceUnavailable`'s (`crates/antseal-anchor/src/nonce.rs:43`): *"the
  operating system CSPRNG is unavailable, so no timestamp request can be built"*. Its one
  producer is `draw_request_nonce` (`:54-58`), when `getrandom::fill` fails (`:56`).
- **The mapping.** `crates/antseal-cli/src/pipeline/error.rs:319-322`:
  `SealError::AnchorGate(refusal) => CliError::AnchorGateAbort { failures:
  gate_refusal_lines(&refusal.error), seal_id: … }`. `gate_refusal_lines` (`:373-397`) sends
  every arm except `MinimumAnchor` through `other => vec![other.to_string()],` (`:395`).
- **What the user reads** (derived from code: `crates/antseal-cli/src/lib.rs:128` prints
  `error: {err}`, and the format is `error.rs:746-756`): *"error: no RFC 3161 timestamp token
  that counts toward the anchor gate was obtained, so the seal stopped before anything was paid
  or uploaded. What failed: the operating system CSPRNG is unavailable, so no timestamp request
  can be built. The work is left staged: running this exact command again resumes it — it
  quotes again and asks for your consent again — once a timestamp authority returns a token
  that counts. --force-degraded cannot be added to that re-run, because the flags are part of
  the recorded command; to seal with a loudly recorded degraded anchor set instead, discard the
  work with `antseal abandon <seal-id>` and run the command again with --force-degraded"* —
  exit 22, class `anchor-gate-abort`.
- **Nothing asserts it.** `git grep -n -E 'AnchorGateError::Entropy|Entropy\b' -- crates`, less
  `OsEntropy`, `EntropySource` and *"entropy source"*, finds only `gate.rs:224`: no test
  constructs or matches the arm, which is how a message with two inapplicable remedies shipped
  (D194 §6).

### 1.2 Neither remedy the message offers can apply

- **No timestamp authority can cure it.** No TSA is asked: `submit.rs:299-300`, *"no TSA
  request is sent at all in that case"*.
- **`--force-degraded` cannot route around it.** `SubmitAnchorGate::run` calls
  `submit_anchors(..)?` (`submit.rs:403-409`) **before** `evaluate_seal_gate` (`:410`), and
  `capture_from_tsas` draws every nonce first (`crates/antseal-anchor/src/tsa.rs:370-385`:
  *"Every nonce is drawn **before any request is sent**"*). So `antseal abandon` followed by
  `--force-degraded` ends in the same refusal, after discarding the staged work for nothing.
- **What is true at that moment.** Nothing was paid or uploaded: the gate runs after consent
  and strictly before `pay` (`resume.rs:480-485`). The work is left staged: the gate's `?`
  returns before `set_state(seal_id, SealState::Anchored)` (`:485`), the shape D194's
  three-part test proves for `MinimumAnchor`. The OTS calendars **were** sent the anchor
  digest (§0), so *"nothing left this machine"* would be false.

### 1.3 How narrowly `Entropy` can arise

On every path, the gate is preceded in the same invocation by `journal.put_consent`
(`resume.rs:472-473`, the gate at `:484`), a vault record write that draws its nonce from the
same OS source (`crates/antseal-cli/src/vault/cipher.rs:250-253`) and maps a failure to
`internal` (1) — through `StoreError::Cli`, which is `#[error(transparent)]`
(`crates/antseal-cli/src/vault/store.rs:279-281`), and `StoreError::Cli(inner) => *inner`
(`:309`); P3 read this chain and did not run it. So a **persistent** CSPRNG failure already
exits 1 a few milliseconds before the gate. `Entropy` (22) is reachable only by a
**transient** failure between the two draws.

### 1.4 Every OS-CSPRNG failure, and the clause they share (`U104`)

Six CLI sites and core's crypto error already map an unavailable OS random source to
`CliError::Internal`:

| site | what is drawn | today's mapping |
|---|---|---|
| `vault/cipher.rs:250-253` (map `:227-229`) | a vault record nonce | *"OS random source failed while drawing a record nonce"* |
| `vault/export.rs:870-872` | the export nonce | *"OS random source failed while drawing the export nonce"* |
| `vault/kdf.rs:261-262` and `:453-454` (map `:206-207`) | the KDF salt | *"OS random source failed while drawing the KDF salt"* |
| `vault/keyfile.rs:162-166` | a vault keyfile | *"the OS CSPRNG failed while generating a vault keyfile"* |
| `init.rs:539-541` | the wallet key, `WalletKey::generate()` | `e.to_string()` for **every** `WalletOpsError`; the entropy variant is `EntropySource` (`crates/antseal-net/src/wallet.rs:391-393`, produced at `:111-116`) |
| `pipeline/error.rs:345-347` | core's `CryptoError::RngFailure` (`crates/antseal-core/src/crypto/error.rs:295`) | `SealError::Crypto(inner) => CliError::Internal` for **every** `CryptoError` |

The seventh is the gate's `Entropy`, today in 22 (§1.1). None of the seven uses `io-error`
(4), whose row is *"ordinary filesystem I/O failure"* (`error.rs:19`). The gate is the lone
exception to `internal`.

**The clause they share is false.** `internal`'s Display is `#[error("internal error: {detail}
(this is a bug in antseal — please report it)")]` (`error.rs:556`), and the table's row 1 reads
*"unexpected failure (bug class)"* (`error.rs:16`). An operating system that cannot supply
randomness is a fault of the machine; no change to antseal cures it, and a report filed on
that advice is noise.

**The census, measured as a baseline for the lane.** `git grep -n -E
'RngFailure|try_fill_bytes|getrandom|OsRng' -- crates/antseal-cli/src` at `07a170c` → 28
lines in five files: `rng.rs` (12: the adapter and its own test), `vault/cipher.rs` (5),
`vault/export.rs` (1), `vault/kdf.rs` (8) and `vault/keyfile.rs` (2). The regex misses the
adapter's own name: the CLI's OS source is `OsEntropy` (`crates/antseal-cli/src/rng.rs:18`),
injected at 31 lines outside `rng.rs` (`commands.rs` 9, `pipeline/receipt_backfill.rs` 4,
`pipeline/receipt_sink.rs` 11, `pipeline/resume.rs` 1, `seal_session.rs` 4, `upgrade_hook.rs`
2). Those injections reach the user through the mapping sites above, except where a caller
re-renders the error — one such path is in §4. The wallet's draw lives in `antseal-net`, core's
in `antseal-core/src/crypto/`, and the gate's in `antseal-anchor/src/nonce.rs:54-58`, so a
census of `crates/antseal-cli/src` alone does not see where the three draws happen.

### 1.5 What the move touches, and what it does not

- **No class is added.** `crates/antseal-cli/tests/namespace_disjointness.rs:85`:
  `const PINNED_CLASS_COUNT: usize = 36;`. `crates/antseal-cli/tests/exit_codes.rs:36`:
  `const TABLE: [(ErrorClass, u8, &str); 36]`. `TABLE` maps each class to its code, and no
  class's code changes, so neither pin moves.
- **The snapshot.** `crates/antseal-cli/tests/snapshots/cli-errors.display.txt` holds 49
  exemplar blocks in 98 lines over 33 distinct classes at `07a170c` (`command grep -c '^\['`
  → 49). The 22 block is `:53-54`; it carries `A20`'s verbatim endpoint failures and stays
  byte-identical. The last block is `:97-98` (`payment-unrecorded`). `exemplars()`
  (`exit_codes.rs:192`) is append-ordered, not code-ordered (D147 §1.7, D147:336-340;
  `exit_codes.rs:512-516`), so a new exemplar goes at the end. This wave, D197 §2 R7 removes
  the block at `:95-96` first, so the count goes 49 → 48 → 49.
- **The snapshot is product copy.** `crates/antseal-cli/tests/snapshots/` is in
  `scripts/check-copy-style.py`'s `COPY_SCAN` (`:73-98`), so the new block is read by that
  check too.
- **`U103`'s Accept** — *"if the class moves, `exit_codes.rs`'s table and the snapshot move
  with it"* — is met by the appended exemplar and its snapshot block; `TABLE` has no row that
  could move (§2 R4).

## 2. RULING

### §2 R1 — `Entropy` leaves class 22 and joins `internal` (`U103`)

`AnchorGateError::Entropy` leaves class 22, whose definition is false for it on both clauses
(§1.2), and joins every other OS-CSPRNG failure in class `internal`, exit 1 (§1.4). Before
`U32` is exactly when a failure may change class: D134 §2 R3 (1) freezes the table **at**
`U32`. No class is added; `PINNED_CLASS_COUNT` and `TABLE` do not move; the exit-22 exemplar
stays byte-identical (§1.5).

The seam is `pipeline/error.rs`'s `From<SealError> for CliError`: a new arm ahead of the
existing `SealError::AnchorGate(refusal)` arm (`:319`) takes the `Entropy` refusal to §2 R2's
variant. `gate_refusal_lines`' doc (`:366-372`) then says that `Entropy` never reaches it, and
`gate.rs:219-222` may add that the CLI shows it in class `internal` (doc only).

*Why:* neither of 22's remedies can apply (§1.2); a persistent failure of the same source
already exits 1 a few milliseconds earlier (§1.3); and every other site is `internal` (§1.4).

Refused, with their costs:
- **Keep 22 with its own way-forward clause** (H13): see the status bullet.
- **`io-error` (4)**: its row is *"ordinary filesystem I/O failure"* (`error.rs:19`), 0 of the
  seven sites use it, and `CliError::Io` needs a `std::io::Error` source that
  `NonceUnavailable` discards (`nonce.rs:56`).
- **A new class** for the environment, in a free band: it reclassifies the other six sites
  and costs a D147 §1.7-sized instrument sweep (`ErrorClass`, `ALL`, `exit_code()`, `name()`,
  `class_index()`, `TABLE`, `PINNED_CLASS_COUNT`, the contract document).

### §2 R2 — One variant for an unavailable OS random source (`U104`)

- **One `CliError` variant, class `internal` (1), whose Display names the machine, not
  antseal.** The rulings' template, which the lane may tighten: *"the operating system's random
  source is unavailable, so {what} could not be done: {consequence} — this is a fault of this
  machine, not a bug in antseal; antseal cannot work here until the OS can supply
  randomness"*. Every clause must be true **by measurement** at each site that uses it.
- **Every OS-CSPRNG failure site routes through it**: the seven of §1.4 — the record nonce
  (`vault/cipher.rs`), the export nonce (`vault/export.rs`), the KDF salt (`vault/kdf.rs`), the
  keyfile (`vault/keyfile.rs`), the wallet key (`init.rs`, mapping **only**
  `WalletOpsError::EntropySource`; the other variants keep today's mapping), core's
  `CryptoError::RngFailure` through `SealError::Crypto` (**only** that variant), and the gate's
  `Entropy` — plus any further site the lane finds. The lane reports its census with its
  positive control over `RngFailure`, `try_fill_bytes`, `getrandom` and `OsRng` across
  `crates/antseal-cli/src`, and adds `OsEntropy`, the adapter's own name, which that pattern
  misses (§1.4).
- **No such message offers a timestamp authority, `--force-degraded` or `antseal abandon`.**
- **The gate's consequence clause**: no timestamp authority was asked, nothing was paid or
  uploaded, the work is left staged, and running this exact command again resumes it once the
  random source works. Measured bound (§0, §1.2): *"no timestamp authority was asked"* is true
  of the RFC 3161 authorities; the OTS calendars had already been sent the anchor digest, so no
  message may say that nothing left the machine.

*Why:* the shared clause is false at all seven sites (§1.4); one variant means one wording the
seven cannot drift apart from; and the class stays `internal`, so the six sites already there
change only their `message`, which D65 makes human copy at every tier.

### §2 R3 — Row 1's definition is widened; D134 and D194 take addenda

- **The exit-code table's row 1** (`error.rs:16`, the module table) reads: *"unexpected
  failure (bug class), or an unavailable OS random source (D201) — a fault of the machine that
  no other class covers"*.
- **`docs/testing/error-code-contract.md`.** The rulings name its class list as the second
  home, but measured at `07a170c` it defines class 1 nowhere (§0). Its 22 sentence
  (`:373-374`) becomes true again for every arm 22 still carries and needs no edit. If the lane
  finds no class-1 definition at its act, it records the absence in its report rather than
  inventing a class list. The orchestrator ruled on 2026-10-19, after this record was
  written (corrected in place; the record is uncommitted), that it gains none: the document is
  the contract for the core's rejection codes (`VerifyError::code()` and its domains), not for
  the CLI's exit classes, which the module table in `error.rs` alone defines.
- **D134** takes a dated addendum: row 1's definition text is widened before `U32`, and no code
  moves.
- **D194** takes a dated addendum: its §6 entry *"Found, minted as a row. `U103`: the gate's
  `Entropy` arm wears class 22 with a remedy that cannot apply"* is discharged.

### §2 R4 — One exemplar, appended through the real producer

**One** block is appended at the **end** of `cli-errors.display.txt` and of `exemplars()`
(D147 §1.7's append order), built through the real producer (D194 §2 R4):
`CliError::from(SealError::AnchorGate(GateRefusal { …, error:
AnchorGateError::Entropy(NonceUnavailable) }))`. The label is the lane's (P3 offered
`internal (anchor gate: no OS randomness)`). The block witnesses the shared variant's words
through the one site that changes class; the other six are witnessed by their own tests (§2
R5), not by six more blocks. This is what `U103`'s *"the snapshot move[s] with it"* means here
(§1.5).

### §2 R5 — Each site is asserted by its message, through its own seam

Each site's mapping is asserted **by message** through its own seam: a `From` arm, or the
function itself with a failing `TryCryptoRng` injected. The gate case asserts class
`internal`, exit 1, a single line, the resume clause, and the absence of *"timestamp authority
returns"*, *"--force-degraded"*, *"antseal abandon"* and *"bug in antseal"*. The existing
class-22 test for `MinimumAnchor` stays 22: it is the anti-plant.

## 3. Fault plants

The implementing lane owes these. Green baselines come first; each plant is judged by its
message, and every restore is followed by a `touch`.

**Green — the load-bearing half.**
- **The gate case**, a new test beside the existing gate test in `pipeline/error.rs`: class
  `internal`, exit 1, a single line, the resume clause present, and none of *"timestamp
  authority returns"*, *"--force-degraded"*, *"antseal abandon"* or *"bug in antseal"*.
- **The six other sites**, each through its own seam and by message: the record nonce, the
  export nonce, the KDF salt (both draws, `generate` and `with_fresh_salt`), the keyfile, the
  wallet key (`EntropySource` only — a non-entropy `WalletOpsError` keeps its mapping) and
  core's `RngFailure` (only that variant — another `CryptoError` stays a plain `internal`
  bug). Each asserts the machine-fault words and the absence of *"bug in antseal"*.
- **`exit_codes.rs`**: `display_output_matches_committed_snapshot` (re-blessed with
  `ANTSEAL_BLESS=1`, the new block read back), `display_output_is_single_line_and_fully_rendered`,
  `every_variant_maps_to_its_class_and_code` and `json_error_object_carries_class_code_and_message`.
- **The anti-plants, unchanged**: the existing class-22 test for `MinimumAnchor`; the 22 block
  (`cli-errors.display.txt:53-54`) byte-identical; `tests/anchor_gate_resume.rs`, D194's
  three-part test.
- `scripts/check-copy-style.py` after the re-bless (§1.5).

**Red — each watched red by its message.**

| Plant | Must redden |
|---|---|
| Delete the new `Entropy` arm | the gate case, on its class (`anchor-gate-abort` ≠ `internal`) and on *"once a timestamp authority returns a token that counts"*; the appended snapshot block |
| Route `MinimumAnchor` through the new arm by widening its pattern | the existing class-22 test, on its class |
| Restore one site's old `CliError::Internal { detail }` | that site's test, on *"bug in antseal"* |
| Put *"pass --force-degraded"* into the gate's consequence clause | the gate case's negative needle |

For the widening plant, write the new arm without a binding (`AnchorGateError::Entropy(_)`)
and render from the refusal, so that the widened `|` pattern still compiles; otherwise the
plant is a compile check, not a message check.

Venue: `cargo test -p antseal-cli --lib` filtered to `pipeline::error` and the vault and
`init` modules; `cargo test -p antseal-cli --test exit_codes` by name. `exit_codes.rs` spawns
the binary through `spawn::antseal()` (D194 §6 measured it), so a whole-file run goes under a
private `CARGO_TARGET_DIR`. `crates/antseal-cli/src/pipeline/` is on `scripts/gate-features.sh`'s
`HEAVY_TRIGGER_PATHS` (`:112-121`), so the heavy tier runs for this record's edit
automatically, and by `scripts/local-gate.sh:714-720` the same list calls for the devnet E2E.
P3's *"(j) no"* was a reading of the code, not of the trigger list. This wave's close gate
forces both tiers for other rows anyway.

## 4. What this record does NOT decide

- **`U104` is not deferred.** It is minted by this wave's rulings and decided here: §2 R2 is
  its `Do`. What it leaves open follows.
- **An RNG failure during a receipt capture.** The receipt sink turns a failed vault write into
  `ReceiptSinkFault::Write { detail: err.to_string() }`
  (`crates/antseal-cli/src/pipeline/receipt_sink.rs:430-435`), and `StoreError::Cli` is
  transparent (§1.3). So after this record, a capture that fails for want of randomness shows
  the machine-fault words inside class 37's `({fault})`. Measured, nothing to rule: the class
  is right — money moved and the vault could not record it — and 37's storage advice is
  conditional (*"If the vault's storage caused this (free space, permissions, the disk), fix
  it first"*, `crates/antseal-cli/src/error.rs:832-833`), so it stays true.
- **`WalletOpsError::KeyGenerationFailed`** (*"the system entropy source appears to be
  returning invalid data"*, `crates/antseal-net/src/wallet.rs:396-399`). It names the entropy
  source but is not an unavailable one; §2 R2 maps only `EntropySource`.
- **A class of its own for the environment.** Refused (§2 R1). After `U32` it could only be
  appended (D134 §2 R3 (1)).
- **The contract document's class list** (§2 R3): whether it gains a class-1 definition is
  the orchestrator's call.
- Every build and test duration: the planning lane built nothing.

## 5. Edit list — per write scope, with the lane named before this record was written

### L-ERR3 (round 2, after L-RESUME)

- `crates/antseal-cli/src/error.rs` — the new variant, and row 1's text in the module table
  (§2 R2, R3).
- `crates/antseal-cli/src/pipeline/error.rs` — the `Entropy` arm, the `RngFailure`-only
  mapping, `gate_refusal_lines`' doc and the new tests (§2 R1, R2, R5).
- `crates/antseal-cli/src/vault/cipher.rs`, `vault/export.rs`, `vault/kdf.rs` and
  `vault/keyfile.rs` — the RNG-failure mappings only (§2 R2).
- `crates/antseal-cli/src/init.rs` — the wallet key's entropy mapping only (§2 R2).
- `crates/antseal-anchor/src/gate.rs` — the `Entropy` arm's doc only (§2 R1).
- `crates/antseal-cli/tests/exit_codes.rs` — one exemplar appended at the end (§2 R4).
- `crates/antseal-cli/tests/snapshots/cli-errors.display.txt` — one block appended at the end,
  after L-RESUME's removal of `:95-96` (§2 R4).
- ~~`docs/testing/error-code-contract.md` — class 1's definition (§2 R3), measured absent at
  `07a170c` (§0).~~ Struck by the orchestrator on 2026-10-19 (corrected in place; the record is
  uncommitted): the document gains no class list (§2 R3), and the lane left it unedited.

### Orchestrator — `TODO.md`, `tasks/U.md`, `docs/decisions/README.md`

- `U104`'s register row and its `tasks/U.md` entry: the id is minted by this wave's rulings
  and has no row at `07a170c` (`git grep -n -w 'U104' -- TODO.md tasks` → 0 lines; control
  `U103` → 5).
- The contract document's class-1 question (§2 R3).
- `U103` and `U104` ticked when the lane's greens and plants are in its report; the index row
  and the register rows.

### RECORDS-C — dated addenda

D134 §2 R3 (1) and D194 §6 (§2 R3).

## 6. As built — wave 39, lane L-ERR3 (recorded in place before this record was first committed)

L-ERR3 ran after L-RESUME, on `HEAD` plus L-RESUME's eight final files. The verdicts are the
lane's, quoted with the exit codes its report gives. Every plant ran in a shadow copy, and none
touched the tree. The lane's ten files still hash as its report lists, and
`docs/testing/error-code-contract.md` and `crates/antseal-cli/src/rng.rs` are unchanged from
`HEAD`. The code facts were re-read in the tree.

- **§2 R1 (`U103`).** A new arm in `From<SealError> for CliError`
  (`crates/antseal-cli/src/pipeline/error.rs:324-333`) sits ahead of
  `SealError::AnchorGate(refusal)`, with no binding. It takes `AnchorGateError::Entropy(_)` to the
  new variant.
  - The exit code goes from 22 to 1, and the class from `anchor-gate-abort` to `internal`.
    `PINNED_CLASS_COUNT` stays 36 (`tests/namespace_disjointness.rs:85`).
  - `gate_refusal_lines`' doc says `Entropy` never reaches it (`:394-395`).
  - `crates/antseal-anchor/src/gate.rs:228-231` adds the paragraph §2 R1 allowed.
  - **Deviation: a false sentence in `gate.rs` was corrected** (the lane's deviation 8). `HEAD`'s
    `:222` said *"No request was sent."*, but the OTS calendars run first. It now reads
    (`:222-226`) *"No TSA request was sent: every TSA nonce is drawn before any request is … The
    OTS calendars run first, so they have already been sent the anchor digest"*. The sentence is
    inside the lane's scope, the arm's doc.
- **§2 R2 (`U104`).** One variant, `CliError::RandomSourceUnavailable { what, consequence }`
  (`crates/antseal-cli/src/error.rs:1094`), shares `Internal`'s arm in `class()` (`:1108`), the
  only exhaustive match over `CliError`. Its text (`:1090-1092`) is *"the operating system's
  random source is unavailable, so {what} could not be generated: {consequence}. This is a fault
  of this machine, not a bug in antseal, and antseal has no other source of randomness to fall
  back on"*.
  - **Deviation: the template's last clause was tightened** (deviation 1). *"antseal cannot work
    here until the OS can supply randomness"* is false, because offline `verify`, `list`, `show`,
    `restore` and `reveal` draw nothing. The clause as built holds at every site: every production
    draw is `getrandom`, core takes injected RNGs only, and nothing falls back (D90 §6.6).
  - **Deviation: *"could not be done"* became *"could not be generated"*** (deviation 2), since
    each failure is the generation of one random value.
  - **Deviation: two `&'static str` fields, not a reason enum** (deviation 5).
    `tests/exit_codes.rs:5` promises an exemplar for every reason of a reason enum, and §2 R4
    rules one exemplar. Static fields keep both promises, and only antseal's own text reaches the
    message.
  - **Deviation: appended at the end of the enum** (deviation 6), in D147 §1.7's order.
  - The seven sites. Each `what` / `consequence` was measured true at its site:
    - the gate: *"a timestamp request nonce"* / *"no timestamp authority was asked, nothing was
      paid or uploaded, and the work is left staged — running this exact command again resumes
      it, quoting again and asking for your consent again, once the random source works"*;
    - the record nonce: *"a vault record's nonce"* / *"that record was not written"*;
    - the KDF salt, both draws: *"a key-derivation salt"* / *"no key was derived from it and
      nothing that key would protect was written"*;
    - the keyfile: *"the vault keyfile"* / *"no keyfile was written"*;
    - the export nonce: *"the export file's nonce"* / *"no export file was written"*;
    - the wallet key, `EntropySource` only: *"the wallet key"* / *"no vault was created"*;
    - core's `RngFailure` only (`pipeline/error.rs:363-364`): *"a random value for this seal"* /
      *"nothing was quoted, paid or uploaded"*.
  - **Deviation: *"quoting again and asking for your consent again"* was added** (deviation 4).
    The refusal leaves the work in `MinimumAnchor`'s state, and D194's three-part test proves the
    re-quote and re-consent for that state. No message says that nothing left the machine.
  - **Deviation: the wallet key's mapping became a function** (deviation 7).
    `WalletKey::generate()` draws from the OS itself, so `fn wallet_generation_error`
    (`init.rs:677`) is the seam the test drives.
  - The core site's `what` covers all four draws (deviation 10). They are drawn before
    `quote_batch`, and the `consequence` says nothing about the vault.
  - **The census, with positive controls.**
    - The ruled pattern gives 28 lines in 5 files, as at `07a170c`.
    - `OsEntropy` gives 32 lines, against 31 at `07a170c`; the extra one is another lane's test.
    - Outside the CLI there are exactly two production draws: `antseal-anchor/src/nonce.rs:56` and
      `antseal-net/src/wallet.rs:114`.
    - **No further site was found.**
    - Every re-render was traced. Only §4's ruled one shows the words inside another class.
- **§2 R3.** Row 1 (`error.rs:16`) carries the ruled text verbatim. The contract document was
  left unedited, as ruled.
- **§2 R4.** One block is appended at `cli-errors.display.txt:97-98`,
  `[random-source-unavailable] class=internal code=1`. It is built through the real producer, as
  the last entry of `exemplars()` (`tests/exit_codes.rs:592`).
  - The re-bless diff is exactly `96a97,98`: 48 blocks became 49.
  - The 22 block (`:53-54`) is byte-identical, and the `--json` object keeps its three keys.
- **§2 R5.** There are seven new tests, each driven through its own seam and checked by message:
  - in `pipeline/error.rs`: the gate case at `:859` and the core case at `:903`;
  - one in each of `vault/cipher.rs:480`, `vault/kdf.rs:682`, `vault/keyfile.rs:471`,
    `vault/export.rs:1489` and `init.rs:895`.

  The keyfile and export tests also assert that nothing was written. The init and core tests
  keep a control whose text still ends *"(this is a bug in antseal — please report it)"*. The
  class-22 test (`:786`) stays 22.
  - **Deviation: the negative needle was narrowed** (deviation 3). *"bug in antseal"* lies inside
    the template's own *"not a bug in antseal"*. The needles are now *"this is a bug in antseal"*
    and *"please report it"*.
- **Red baseline.** The seven new tests on the old mappings gave `0 passed; 7 failed`.
  - The gate case failed on *"left: AnchorGateAbort right: Internal"*.
  - Each site failed on its old text, for example *"internal error: OS random source failed
    while drawing the export nonce (this is a bug in antseal — please report it)"*.
  - The snapshot failed on *"error Display drifted from the committed snapshot"*.
- **Plants, every one red by message.** No planted build had a compile error, and each restore
  was re-checked by sha256.
  - **P1, the arm deleted:** the gate case (*"left: AnchorGateAbort right: Internal"*) and the
    snapshot went red, while the class-22 test stayed `ok`.
  - **P2, the arm widened to `| AnchorGateError::MinimumAnchor { .. }`:** the class-22 test (*"left:
    Internal right: AnchorGateAbort"*) and the snapshot went red.
  - **P3, the KDF salt's old mapping restored:** *"… while drawing the KDF salt (this is a bug in
    antseal — please report it)"*.
  - **P4, *", or pass --force-degraded"* appended:** *"\"--force-degraded\" is offered: …"*.
  - **P5 (the lane's own), the old clause put back on the shared message:** all seven site tests
    failed, each on its negative check.
- **Found (instrument findings; no row).**
  - Three findings are about this record:
    - §2 R5's needle sits inside §2 R2's template;
    - the template's last clause was never checked against the census it commissions;
    - §4's receipt-sink locator `:430-435` is now `receipt_sink.rs:444-445`.
  - §5 named the contract document; the orchestrator has since struck it.
  - A census quoted from a shared tree must name its base.
  - `tests/exit_codes.rs:5`'s promise is not enforced by any test.
  - The lane's insertions moved living-doc citations, which its report lists. `L-LOC` owns them.
- **Not run: an `ant-backend` build** (about 100 minutes cold). The only feature-sensitive edit is
  the `WalletOpsError` match, whose `other =>` arm covers the gated variants. `pipeline/` is on
  the heavy-tier trigger list (§3), so the wave's close gate covers it.
- **At the lane's close.**
  - In the shadow:
    - `antseal-cli --lib`: 328 passed;
    - `exit_codes`: 8 passed, the spawned test included;
    - the init and vault integration tests: 85 passed;
    - clippy `-D warnings`: clean on both crates.
  - In the shared tree:
    - the targeted tests: 8 passed;
    - `exit_codes` in-process: 7 passed;
    - the whole `--lib`: 331 passed.
  - `check-copy-style.py`, `check-personal-data.py` and `rustfmt --check` exited 0.
- **Rows.** `U106` was minted from the lane's proposal: `WalletOpsError::KeyGenerationFailed`
  blames the machine's entropy source and calls itself an antseal bug, in one message. `U103` and
  `U104` are still open in `TODO.md` at this writing; the orchestrator ticks them (§5).

## Closing — this record is not consent

It changes code, tests, a frozen error snapshot and a document in the tree. Nothing in it
authorises a push, a dispatch, a deploy or any other outward act, and its tests open no socket.
