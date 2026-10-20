# D205 — `antseal init` refuses a directory that holds **no vault header but is not empty**: any file other than `vault.lock`, at any depth, stops it after D39's check and before a passphrase is asked, in the usage class (exit 2), with a text that names the directory and the first file found and says to move the directory aside

- **Status: RESOLVED. H6 survived, widened: its direction and its premises held by execution,
  and the same predicate defect reaches further than the row says.**
  - **H6** — *"refuse: an existing config.toml in a directory without vault.header stops init
    (no new exit code; the existing "vault exists"/usage class), the message naming the file and
    the way out; never overwrite a user's file."*
  - **What survives: all of it.** Planning lane P2 executed the premise on a copy of the binary:
    `init` over a directory holding only a hand-written `config.toml` exits 0, replaces the file,
    and prints a `--json` envelope that contradicts itself about the network (§1.3). No
    documented, tested or scripted flow writes `config.toml` before `init` (§1.5), so a refusal
    breaks none. The class is `usage` (exit 2), D39's own refusal class (§1.1).
  - **Widened: the defect is the predicate, not the file.** With only `vault.header` moved
    aside, `init` exits 0 and replaces `store/check` and `store/wallet`, the old vault's
    key-check record and wallet record, and the old header then fails with exit 12 (§1.4). So the
    refusal keys on any file other than `vault.lock`, not on `config.toml` alone (§2 R1).
  - **What it costs D155 §4.4.** D155 judged the header-only predicate's divergence from
    D39:142-145 to be *"in the **safe** direction"* (D155:1147-1148). That is true of an empty
    directory only (§1.7). D155 takes a dated addendum (§2 R6).
- **Date: 2026-10-20**
- Owner row: **`U105`** (§2 R1–R6). This record mints no row.
- Related:
  - **D39** Decision 4 (the absolute refusal, D39:87-95) and its residual-risk bullet
    (D39:142-145); takes a dated addendum;
  - **D155** §2 R1 (the `header.exists()` gate does not move, D155:431-450) and §4.4
    (D155:1141-1149); takes a dated addendum;
  - **D42** (the exhaustive beside-the-AEAD set, `crates/antseal-cli/src/vault/layout.rs:18-21`);
  - **D195** (a `[verify]` URL may carry an API key, so no refusal repeats a value);
  - **`U11`** (`init`), **`U4`** (`config.toml` and the network precedence) and **`U32`** (the
    frozen help text, which this record does not move).

## 0. What was measured against

`HEAD` `6e1cab3` (local `main`; `origin/main` is `ab640ae`, one records commit behind). The tree
was clean when planning began, 2026-10-20.

Planning lane P2 (wave 40) worked read-only on the repository and **executed** every premise of
`U105` against a byte-for-byte copy of `target/debug/antseal`, newer than every file under
`crates/`. Each case ran under `env -i` with its own `ANTSEAL_DIR`, `HOME` and `XDG_DATA_HOME`
(its Logs 2, 3 and 8). The probe vaults held throwaway keys and were deleted once their outputs
were captured. P2 ran one cargo command, `cargo test --offline -p antseal-cli --lib --
init::tests` (exit 0, no rebuild).

Before this record was written, the records lane re-read the load-bearing lines through
`git show 6e1cab3:<path>`, because round-1 lanes were editing the shared tree, `init.rs` among
them, and read P2's probe outputs for the executed cases. Every code line quoted below held.
These locators did not, and are given below as measured:
- the envelope's network is resolved at `crates/antseal-cli/src/lib.rs:154` (P2: `:152`); the
  load is `:140`, as P2 says;
- `scripts/stage0.sh`'s `mkdir -p "$w/vault" "$w/home" "$w/xdg"` is `:408` (P2: `:409`, the
  comment below it);
- `create_vault_with_wrap` is `crates/antseal-cli/src/init.rs:573` and `store_wallet_key` is
  `:574` (P2: `:572` and `:573`);
- P2's *"39 init sites"* in the tests counts the seven `.rs` files; the same pattern
  (`git grep -n -E '"init"|run_init\(' 6e1cab3 -- crates/antseal-cli/tests`) finds 41 lines with
  the two in `tests/snapshots/json-envelopes.txt`.

## 1. What was measured

### 1.1 The gate reads the header alone, and the handler makes the directory and its lock first

- **The gate.** `crates/antseal-cli/src/init.rs:417-419`:
  `let header = layout.beside_path(BesideFile::Header);` / `if header.exists() {` /
  `return Err(existing_vault_refusal(layout.root()));`. Step 1's comment (`:412-416`) says the
  refusal *"must happen before a passphrase is collected"*. The passphrase is obtained at
  `:458`; before it, machine mode without a passphrase fd returns `PassphraseUnavailable`
  (`:450-454`).
- **The refusal.** `existing_vault_refusal` (`init.rs:624-635`) is `CliError::Usage`, class
  `usage`, exit 2 (`crates/antseal-cli/src/error.rs:423`). A second author repeats the check in
  other words at `crates/antseal-cli/src/vault/session.rs:224-232`: *"a vault already exists at
  {} — antseal never overwrites a vault (D39)"* (D155 §4.3).
- **The handler runs first.** `crates/antseal-cli/src/commands.rs:189-197` creates the directory
  and takes the lock before `run_init` runs, and the lock writes its advisory pid into
  `vault.lock` (`crates/antseal-cli/src/vault/lock.rs:116-118`). So `vault.lock` is present on
  every `run_init` call. The comment at `commands.rs:190-191` says creating the directory
  *"leaves nothing behind if `init` refuses"*; executed, a refused `init` (machine mode, no
  passphrase fd, exit 11) leaves the directory and an 8-byte `vault.lock` holding the pid (P2
  Log 8).
- **What a failed or killed create leaves.** `create_vault_impl` makes the directories first and
  runs the fallible KDF after them, *"so a low-RAM machine leaves at most empty directories
  behind"* (`session.rs:234-238`). It writes the header **last** (`session.rs:15-17`), so a kill
  between the key-check write and the header write leaves `store/check` with no header.

### 1.2 What `init` writes, and what the process has already read

- **The write.** `init.rs:576-584`: `crate::vault::fs::atomic_write(&config_path,
  crate::config::initial_config_text(network).as_bytes())`, after `create_vault_with_wrap`
  (`:573`) and `store_wallet_key` (`:574`). Nothing in `run_init` reads the file.
- **`init`'s network ignores the file.** `init_network` (`init.rs:610-612`) is
  `effective_network(globals.network, &Config::default())`, and its doc (`:606-608`) says
  *"(so `config::load` cannot be consulted — there is no config yet)"*.
- **But dispatch has already read it.** `crates/antseal-cli/src/lib.rs:140`
  (`let config = match config::load() {`) fails every command on a malformed file, and
  `lib.rs:154` (`let network = config::effective_network(cli.globals.network, &config).as_str();`)
  is the envelope's top-level `network`.

### 1.3 Executed: `init` over a hand-written `config.toml` (P2 Log 2)

- **Case A.** The directory holds only a `config.toml` with a canary comment,
  `default_network = "arbitrum-sepolia"`, an `[anchors]` table with `tsa_urls`, and
  `opportunistic_upgrades = false`. `antseal --json --passphrase-fd 3 init` exits 0.
  - stdout: `{"command":"init","network":"arbitrum-sepolia","ok":true,"result":{…,"network":"arbitrum-one",…},"v":1}`.
    The top level and the result disagree in one document.
  - stderr: *"Network: arbitrum-one."* and *"Real funds move on this network"*.
  - The file afterwards is the three-line initial text ending `default_network = "arbitrum-one"`;
    the canary, `[anchors]` and both settings are gone.
- **Case B.** The same file under `--network devnet … init --wallet generate --kdf argon2id
  --wrap none` exits 0, and the file is replaced by `default_network = "devnet"`.
- **Case C.** A malformed file (an unquoted second `tsa_urls` entry) exits 17,
  `malformed-config`, and is left byte-identical; the directory holds only that file, because
  `lib.rs:140` refuses before the handler creates anything. So today a broken file is protected
  and a working one is destroyed.
- **Case D.** A file holding only an unknown key is warned about (*"unknown key
  `some_future_key` — ignored (newer antseal?)"*) and then replaced.

### 1.4 Executed: the same predicate overwrites a partly wiped vault (P2 Log 8)

- A complete vault is created (exit 0). Only `vault.header` is moved aside, `store/` is kept,
  and `init` runs again: **exit 0**. Before and after, `store/check`, `store/wallet`,
  `vault.header` and `vault.lock` all hash differently.
- With the old header put back, `list` exits **12**: *"vault authentication failed: wrong
  passphrase, or the vault store or header has been modified or corrupted"*. The vault key is
  derived from the passphrase and the header's KDF block (`session.rs:1-13`), and the key-check
  record it is checked against now belongs to the new vault, so antseal no longer opens the old
  one. The old wallet record is replaced: the old wallet key survives only where it was exported.
  The probe vault held no works, so what a works store would keep was not measured.
- **Control.** With the header and a `config.toml` both present, `init` exits 2 with D39's text,
  and the config's sha256 is unchanged.

### 1.5 Nothing writes `config.toml` before `init` (P2 Log 3)

- **Production writers.** `git grep -n 'BesideFile::Config' 6e1cab3 -- crates/antseal-cli/src`
  gives five lines: the loader (`config.rs:313`), `init`'s write (`init.rs:576`), `vault
  export` reading it (`vault/export.rs:714`), `vault import` writing it into a temporary
  directory that it then renames (`vault/export.rs:1103`), and the name (`vault/layout.rs:40`).
- **`vault import` never leaves a lone `config.toml`.** `refuse_existing_target`
  (`vault/export.rs:1213-1229`) refuses any existing target directory, with or without a header:
  *"{} exists but is not a vault (no vault header inside) — move it aside before importing"*
  (`:1220-1226`, class `usage`).
- **Tests.** The 39 `init` sites in seven `.rs` files under `crates/antseal-cli/tests` include
  none that writes `config.toml` before `init`. `anchor_stage.rs:983-990` writes
  `.antseal/config.toml` before a vault exists, then runs `seal`, not `init`;
  `peer_resolution.rs` writes its `config.toml` after `init` (`:191-196`, then `:406`, `:440`).
- **Scripts.** `scripts/stage0.sh:408` creates an **empty** vault directory and runs `init` in it
  at `:423`; the passphrase, the key and the smoke file go in its parent, not in the vault
  directory (`:412-416`). `scripts/e2e-sepolia.sh` uses a fresh home (`:265-269`). No script
  writes antseal's `config.toml`: `git grep -n config.toml 6e1cab3 -- scripts .github`, less
  `.cargo/config.toml`, finds only `scripts/reproducible-build.sh:399`, which copies Cargo's own
  `config.toml` into a second `CARGO_HOME`.
- **Docs.** `docs/config.md:11-12` and `docs/user/timestamp-authorities.md:216-217` both say
  *"`antseal init` writes the initial file; edit it by hand afterwards."* `README.md:153-154`
  says *"`init` refuses to overwrite an existing vault"*.

### 1.6 The vault's network lives only in `config.toml`

The header records no network: `git show 6e1cab3:crates/antseal-cli/src/vault/header.rs |
command grep -c -i network` → 0, against a positive control of 28 for `kdf`. The help text says
`init` *"writes it into config.toml as default_network"*
(`crates/antseal-cli/src/cli.rs:68-70`, in the frozen help snapshot), and the comment at
`cli.rs:85-88` says `init` *"has no config yet (flag, else the built-in default) and writes the
result as `default_network`"*. So a replaced `config.toml` loses the vault's only record of its
network, and a kept one would need `init` to read it (§1.9, K-keep).

### 1.7 What the records said

- **D39 Decision 4** (D39:87-95): existing-vault refusal is absolute, no override flag exists,
  and *"overwriting a vault destroys `W` — every sealed work's reveal/restore ability, forever"*.
- **D39's residual risk** (D39:142-145): *"Absolute refusal (Decision 4) means a
  wiped-but-present `~/.antseal/` (e.g. an empty dir left by a failed manual cleanup) also
  refuses; the error text must name the path so the fix is obvious. Accepted: refusing too much
  is recoverable, refusing too little is not."* D39's 2026-08-19 amendment left this paragraph
  unamended, as the ground D155 §2 R1 stands on (D39:175-178).
- **D155 §2 R1** (D155:431-450): the `header.exists()` gate does not move and no decode is hung
  off it.
- **D155 §4.4** (D155:1141-1149): the shipped predicate lets an empty `~/.antseal/` through, and
  *"The divergence is in the **safe** direction (an empty directory holds no `W` to destroy)"*
  (`:1147-1148`). It did not consider a directory holding a hand-written `config.toml`, nor a
  vault whose header alone was moved aside (§1.3, §1.4).

### 1.8 What a re-run must still be allowed to meet

- **`vault.lock`**, always: the handler creates it before `run_init` (§1.1). A predicate that
  counted it would refuse every `init`.
- **Empty directories**: `store/works/` after a KDF failure (`session.rs:234-238`), and the empty
  directory `stage0.sh:408` makes before `init`.
- **Not allowed under §2 R1, by design: a lone `store/check`** after a kill between the key-check
  write and the header write (`session.rs:15-17`). A re-run is refused and told to move the
  directory aside; D39:142-145 accepts refusing too much as recoverable.

### 1.9 The options

| option | cost | verdict |
|---|---|---|
| **R-narrow:** refuse when `config.toml` exists without a header | XS; `init.rs` only | closes the row as written; leaves §1.4's overwrite of `store/check` and `store/wallet` |
| **R-broad:** refuse when any file other than `vault.lock` exists without a header; directories alone do not count | XS–S; the same site plus a short-circuiting walk | closes the row and §1.4; matches D39:142-145 for a non-empty directory and keeps D155 §4.4's empty-directory allowance (§1.8) — **taken (§2 R1)** |
| **K-keep:** keep the file and take `init`'s network from it, warning on disagreement | `init` needs the loaded `Config` (`commands.rs:204`, or a second `config::load`); the help sentence *"init writes it into config.toml as default_network"* turns conditional (13 lines of `cli-surface.help.txt` and the needle at `tests/cli_surface.rs:173`, a `U32` surface); a merging write needs a TOML editor that does not exist, because the loader parses a subset and writes nothing | refused (§2 R3) |
| **S-say-so:** document the overwrite | docs only | refused: keeps the data loss and the envelope split (§2 R3) |
| **Back up in place** (`config.toml.bak`) | — | refused: a fourth beside file violates D42's exhaustive set; *"Adding a variant is a decision-register event"* (`vault/layout.rs:18-21`) (§2 R3) |

## 2. RULING

### §2 R1 — The predicate: any file other than `vault.lock`, after D39's check and before the passphrase

After the existing D39 check (`init.rs:417-419`, **unchanged**), `run_init` refuses when the
target directory holds **any file other than `vault.lock`, at any depth**. The check is a
short-circuiting walk that stops at the first file it meets; directories alone do not count, so
an empty `store/works/` left by a KDF failure and the empty directory `stage0.sh:408` makes stay
allowed. `config.toml` is checked **first**, so the row's case names it. The check runs
**before** the passphrase is obtained (`init.rs:458`), which plant P105-b proves (§3).

*Why:*
- **D39's check stays first and unchanged**, so an existing vault still gets D39's text, the
  registered `init` error exemplar still renders from `existing_vault_refusal`
  (`tests/machine_mode.rs:590`, `tests/snapshots/json-envelopes.txt:2`), and the gate-order test's
  citation of *"`init.rs:418`"* (`tests/vault_keyfile.rs:672`) still holds. D155 §2 R1 is kept:
  the header is still never decoded here.
- **Any file, not `config.toml` alone**, because the defect is the predicate: §1.4's partial
  wipe overwrites the old vault's key-check and wallet records through the same gap.
- **Directories and `vault.lock` do not count**, because a re-run must meet them (§1.8): the
  handler always creates the lock first, and the create sequence leaves at most empty
  directories when its KDF fails.
- **Before the passphrase**, because step 1's own rule is *"the refusal must happen before a
  passphrase is collected"* (`init.rs:412-416`).
- **What follows.** `config::load()` resolves the same vault directory as `init`'s handler
  (`config.rs:298-305`, against `commands.rs:185`), and a missing file loads as the defaults
  (`config.rs:316`). So under R1 every `init` that proceeds has no `config.toml` to read, the
  envelope's network (`lib.rs:154`) and `init_network` (`init.rs:610-612`) agree, and §1.3's
  split cannot arise. `init_network`'s *"there is no config yet"* becomes true by construction.

### §2 R2 — Class `usage`, exit 2, in words that name paths only

No new class or code: D39's refusal class. The text names paths, never contents, because a
`[verify]` URL may carry an API key (D195):

> *"{root} holds no vault (there is no vault.header) but is not empty — {found} is in it — and
> `antseal init` would replace what it finds there: config.toml is rewritten and the store's
> records are overwritten. Move {root} aside instead of deleting it — a moved directory keeps
> everything — then run `antseal init` again, and copy config.toml back afterwards if you want
> its settings."*

`{found}` is the first file the walk meets, as a path. The lane may tighten the wording, keeping
every clause true and the test's canary absent.

*Why:* *"move the directory aside instead of deleting it"* is D155 §2 R2's remedy, recorded in
D39's 2026-08-19 amendment as *"the one instruction true for every wrap mode, requiring no
command and refusable by none"* (D39:168-170), and `existing_vault_refusal` already prints it
(`init.rs:629-630`). *"config.toml is rewritten"* is `init.rs:576-584`; *"the store's records
are overwritten"* is §1.4. *"there is no vault.header"* holds by the order R1 fixes.

One reading for the lane, from the text against R1's predicate: `{found}` can be a file `init`
never writes, which `init` would leave in place. *"would replace what it finds there"* is true of
`config.toml` and of the store's records, not of every `{found}`; R2's licence to tighten covers
it.

### §2 R3 — Refused, for the record

- **Keep the file** (K-keep, §1.9): the merging write needs a TOML editor that does not exist,
  and the help's *"init writes it into config.toml as default_network"* would turn conditional on
  a `U32` surface (13 lines of `cli-surface.help.txt`, the needle at `tests/cli_surface.rs:173`).
- **Document the overwrite** (S-say-so): keeps the data loss and the envelope split.
- **An in-place backup** (`config.toml.bak`): a fourth beside file, against D42's exhaustive set
  (`vault/layout.rs:18-21`).

### §2 R4 — Docs and doc comments

- **`docs/config.md:11-12`**: one clause — `init` refuses a directory that holds files but no
  vault header; move it aside first. The wording must be true of R1–R2: an empty directory and a
  lone `vault.lock` are allowed.
- **`README.md:153`, `docs/user/wallet-hygiene.md:233-237` and `:392`, and
  `docs/user/timestamp-authorities.md:216-217`**: edited only where U105 makes a sentence false.
  The implementing lane reports a verdict on each.
- **`init.rs`'s own docs**: the module's order list (`:8`), `run_init`'s `# Errors` (`:396`) and
  `init_network`'s doc (`:606-608`).
- **The comment at `commands.rs:190-191`** (*"leaves nothing behind if `init` refuses"*, false:
  a refused `init` leaves `vault.lock`, §1.1) is corrected, comment lines only, with no code in
  `commands.rs` (§5 names who).

### §2 R5 — Tests

- **G105-1** `init_over_a_hand_written_config_toml_refuses_and_keeps_it`: machine mode ON with no
  passphrase fd, so a refusal placed too late surfaces as `PassphraseUnavailable` instead (the
  device `tests/init_command.rs:626-629` documents). Asserts class `Usage`, exit 2, a message
  naming the config path and *"aside"*, the file's canary (a key-in-path `rpc_endpoints` URL)
  absent, the bytes read back identical, and no `vault.header` and no `store/` afterwards.
- **G105-2**: a vault whose header was moved aside is refused, and the sha256 of `store/check`
  and `store/wallet` is unchanged.
- **G105-3**, the load-bearing control: `init` proceeds over an empty directory, its lockfile and
  empty store directories.
- Optional, once through the binary in a private target: a `config.toml` holding
  `default_network = "arbitrum-sepolia"` gives exit 2 and an unchanged file.
- The red baseline is recorded first; plants P105-a..e follow (§3).

### §2 R6 — Records

- **D39** takes a dated addendum: the absolute refusal now reaches a non-empty directory without
  a header.
- **D155** takes a dated addendum on §4.4: *"in the safe direction"* is true of an empty directory
  only.

### What no ruling here moves

- **No exit code and no class.** `usage` (2) is reused, and `PINNED_CLASS_COUNT` stays 36
  (`tests/namespace_disjointness.rs:85`).
- **No frozen surface.** `json-envelopes.txt:2` keeps `init`'s single registered error exemplar,
  `cli-errors.display.txt`'s `[usage]` exemplar is a different message, the help text is
  unchanged and its `--network` sentence stays true, and no `--json` key moves.
- **Untouched:** `vault/session.rs` (its second author stays, D155 §4.3), `config.rs`, and every
  storage or payment path.

## 3. Fault plants

The implementing lane owes these. The red baselines come first, on the unedited code; each plant
is judged by its **message**; every restore is followed by a `touch`. `tests/init_command.rs`
spawns the binary, so its spawned tests and every plant run in a shadow copy with a private
`CARGO_TARGET_DIR`; its in-process tests may run in the shared target.

**The green tests — the load-bearing half**

- **G105-1** (§2 R5). **Red baseline at `6e1cab3`:** `run_init` returns `Ok` and replaces the
  file (§1.3, Case A).
- **G105-2** (§2 R5). **Red baseline:** `Ok`, with `store/check` and `store/wallet` replaced
  (§1.4).
- **G105-3**, the control (§2 R5): green before and after. It is what keeps R1 from refusing
  every `init`.
- **Stay green, unchanged:**
  - `tests/init_command.rs:561` `init_over_an_existing_vault_refuses_absolutely`;
  - the gate-order test at `tests/vault_keyfile.rs:673`, whose comment cites `init.rs:418`;
  - `tests/init_command.rs:977` `the_binary_inits_over_a_piped_passphrase`;
  - `tests/peer_resolution.rs:191` `init_vault` (a fresh directory; `config.toml` written after
    `init`);
  - `tests/secret_hygiene.rs:683`'s `init` homes (`fresh_home`, `:379-383`, makes an empty home);
  - `tests/upgrade_hook.rs:798`'s `init` row, which runs over an existing vault and so meets
    D39's check first (measured by this records lane; P2's site list does not name it).

**The plants — proof that those tests can fail**

| Plant | Must redden |
|---|---|
| P105-a: delete the new check | G105-1 (*"must refuse"*) and G105-2 |
| P105-b: move the check below `obtain_passphrase` | G105-1, on its class (`passphrase-unavailable`, because `init.rs:450-454` returns first) |
| P105-c: the predicate becomes *"the directory exists"* | G105-3 |
| P105-d: count `vault.lock` as content | G105-3; through the binary every `init` would refuse, because the handler creates the lock first (§1.1) |
| P105-e: drop the path from the text | G105-1 |

## 4. What this record does NOT decide

- **An allowlist beyond `vault.lock`.** None is ruled. A file the user never meant as content
  (an operating system's folder metadata, say) is refused like any other and named as `{found}`;
  D39:142-145's *"refusing too much is recoverable"* is the ground for not widening the
  exception now.
- **How the walk treats a symbolic link, or a directory it cannot read.** Not ruled. The
  implementing lane states in its report what the walk does with each, and §6 records it.
- **`vault import`.** Unchanged: it already refuses any existing target directory
  (`vault/export.rs:1213-1229`).
- **`vault/session.rs`'s second author** of the existing-vault refusal (D155 §4.3). Untouched.
- **New rows.** This record mints none. P2 proposed a row for §1.4's overwrite only if the
  ruling were narrow; R1 is broad, so it is not minted.
- **The row's own locators and its ordering term.** `U105`'s row cites `docs/config.md:9`,
  `init.rs:412-419`, `:578-582`, `:612-613` and `session.rs:224-228`, now `:11-12`, `:417-419`,
  `:576-583`, `:610-611` and `:224-232` (P2 §3). Its *"after U2"* names the exit-code row, where
  `init` is `U11` (PS). Both are the orchestrator's, for the ledger.

## 5. Edit list — per write scope, with the lane named before this record was written

### L-INIT (round 1) — `U105`, then `U106` (D206)

- `crates/antseal-cli/src/init.rs`: the new check in step 1, after `:417-419` (R1); a new
  function beside `existing_vault_refusal`, after `:635`, and the short-circuiting walk (R1, R2);
  the docs at `:8`, `:396` and `:606-608` (R4).
- `crates/antseal-cli/tests/init_command.rs`: G105-1, G105-2 and G105-3, appended at the end
  (R5).
- `README.md`, `docs/user/wallet-hygiene.md` and `docs/user/timestamp-authorities.md`: only a
  sentence `U105` makes false, with a verdict reported on each (R4).
- Not this lane's: `docs/config.md` (L-CFG3's), `commands.rs` (the orchestrator's), `config.rs`,
  `crates/antseal-cli/src/error.rs`, any snapshot, any other source file.
- In-process tests run in the shared target under the lock; spawned tests and plants run in a
  shadow copy with a private target directory.

### L-CFG3 (round 1) — one clause

- `docs/config.md:11-12`: R4's clause, true of R1–R2 (an empty directory and a lone
  `vault.lock` are allowed).

### RECORDS-C — dated addenda

- **D39**: the absolute refusal reaches a non-empty directory without a header (R6).
- **D155 §4.4**: *"in the safe direction"* is true of an empty directory only (R6).

### Orchestrator — `TODO.md`, `tasks/U.md`, `docs/decisions/README.md`, `docs/instrument-ledger.md`, `commands.rs:190-191`

- The comment at `crates/antseal-cli/src/commands.rs:190-191`, comment lines only (R4), after
  the lanes. `commands.rs` is on `HEAVY_TRIGGER_PATHS` (`scripts/gate-features.sh:114`), so even
  a comment edit there classifies the change heavy; this wave's close gate forces the heavy tier
  and the devnet E2E for other rows anyway.
- `U105`'s tick against §3; this record's index row and register row; P2's §3 findings and PS's
  ordering-term finding (§4).
- **For L-LOC (round 3).** R1's insertion after `init.rs:419` moves every living-doc citation of
  `init.rs` below that line. At `6e1cab3` there are seven, outside `docs/decisions/` and the
  ledger (`git grep -n -o -E 'init\.rs:[0-9]+(-[0-9]+)?' 6e1cab3 -- docs README.md
  CONTRIBUTING.md`): `docs/threat-model.md:575`, `:1008` and `:1009`;
  `docs/user/funding-your-wallet.md:107`; `docs/user/wallet-hygiene.md:236`, `:320` and `:392`.
  P2 expected `wallet-hygiene.md:236` and `:392` (`:623-635`) to stay put if the new function
  goes after `:635`, but any line the step-1 check adds above `:623` moves them too. PS counted
  six, without `threat-model.md:1009`.

## 6. As built — wave 40, lane L-INIT (recorded in place before this record was first committed)

Every verdict from the lane below was read from an exit file, and every red was judged by its
message: this records lane read the lane's exit files back, and each matches its report. The
spawned tests and every plant ran in a shadow copy with a private target; the in-process tests also
ran in the shared target under the locks.

- **§2 R1, as ruled.** The check is `crates/antseal-cli/src/init.rs:421-427`. It sits directly
  after D39's unchanged check (`:417-420`; `:418` is still `if header.exists() {`, as
  `tests/vault_keyfile.rs`'s citation needs) and before the passphrase is obtained (`:465`).
  - The walk, `first_file_without_a_vault` (`:704-745`), looks at `config.toml` first, with
    `symlink_metadata`, and counts any non-directory there (`:705-708`). It then walks depth first
    in name order, each directory's files before its subdirectories, on an explicit stack
    (`:717-743`), and stops at the first file. Directories never count. The lockfile is exempt only
    at its top-level path (`:737`), so a nested `vault.lock` is content.
  - **§4's two open questions, as built** (code-traced; no test plants either). A symbolic link is
    content and is never followed: `entry.file_type()` does not follow links. A directory that
    cannot be read is `CliError::Io`, class `io-error`, exit 4 (`error.rs:425`, `:1113`), with the
    context *"reading {dir} to check that it holds no files before `antseal init` writes there"*
    (`init.rs:710-716`), never "empty". A directory that does not exist is empty (`:724`).
  - Every edit above `:420` keeps its line count (`:8`, `:396-402`), so every citation of
    `init.rs:1-419` holds.
- **§2 R2. Deviation: the text was tightened, under R2's licence.** The ruled *"would replace what
  it finds there: config.toml is rewritten and the store's records are overwritten"* and *"copy
  config.toml back"* are false in three of the four refused shapes. A lone `config.toml` has no
  store to overwrite. A lone `store/check` has no `config.toml` to rewrite or copy back. An
  unrelated file is left in place, as R2's last paragraph foresaw. As built (`init.rs:666-674`,
  after `CliError::Usage`'s *"usage error: "*, `error.rs:561`):

  > *"{root} holds no vault (there is no vault.header) but is not empty — {found} is in it — and
  > `antseal init` writes its own config.toml and store records there, replacing any it finds.
  > Move {root} aside instead of deleting it — a moved directory keeps everything — then run
  > `antseal init` again, and copy config.toml back afterwards if you want its settings."*

  The copy-back clause is printed only when `{found}` is `config.toml` (`:661-665`). The walk
  looks there first, so that is exactly when one exists; otherwise the text ends *"… then run
  `antseal init` again."* The class is `usage`, exit 2, and the text names paths, never contents
  (D195).
- **§2 R3.** Nothing R3 refused landed: no merge, no in-place backup, no fourth beside file.
- **§2 R4.**
  - `init.rs`'s docs: the order list (`:8`) reads *"existing-vault / stray-file refusal"*.
    `run_init`'s `# Errors` (`:396-402`, still seven lines) adds *"a non-empty directory without
    one (D205)"* and *"I/O errors from the directory walk"*. `init_network`'s doc (`:613-616`) says
    *"`config.toml` is not consulted because an `init` that goes ahead has none to read"*.
  - `docs/config.md:12-17` is L-CFG3's clause, in the tree before L-INIT's code landed. The lane
    re-checked it against the check as built and found it true (*"… Empty folders, and the
    `vault.lock` antseal itself creates there, do not count as files."*).
  - No other doc was edited. By the lane's verdicts `README.md:153-155`,
    `docs/user/wallet-hygiene.md:233-237` and `:392`, and
    `docs/user/timestamp-authorities.md:216-217` stay true; the three files are unchanged since
    `HEAD`.
  - **The orchestrator corrected the comment at `crates/antseal-cli/src/commands.rs:189-191`**,
    comment lines only, line-count neutral (one hunk, `-190,2 +190,2`). It now says creating the
    directory *"is idempotent, and a refused `init` leaves only `vault.lock` behind, which D205's
    check ignores (the header is the vault)"*. This records lane's binary probe (Left open) agrees:
    in its control, a refused `init` (exit 11) in an empty directory left exactly `vault.lock`.
- **§2 R5, the tests**, appended at the end of `crates/antseal-cli/tests/init_command.rs`
  (`:1054-1390`; 337 lines added, none removed).
  - **G105-1** `init_over_a_hand_written_config_toml_refuses_and_keeps_it` (`:1104`) is as ruled:
    machine mode, no passphrase fd. It also asserts *"copy config.toml back"*, and the absence of
    the canary, `arb1.example` and `arbitrum-sepolia`.
  - **G105-2** `init_over_a_vault_whose_header_was_moved_aside_refuses` (`:1167`) goes beyond R5.
    It compares bytes and keeps `config.toml` too. Its second run uses a differently seeded RNG.
    With the header put back, the old vault unlocks and its wallet key derives the first `init`'s
    address.
  - **G105-3** `init_proceeds_over_an_empty_directory_its_lockfile_and_empty_store_dirs`
    (`:1258`), the control: three residues, count asserted first (an empty directory, the lockfile
    alone, the lockfile beside an empty `store/works/`).
  - **G105-4, the lane's own:** `init_over_a_lone_nested_record_refuses_naming_it` (`:1307`), a
    create killed before the header (the lock, `store/works/`, `store/check`). The refusal names
    `store/check`, has no copy-back clause, and keeps the bytes. It is the only test that sees the
    walk descend.
  - **G105-5** `the_binary_refuses_init_over_a_hand_written_config_toml` (`:1351`) is R5's optional
    binary check, made a standing spawned test. `--json --passphrase-fd 0 init` exits 2 with
    `ok: false`, class `usage`, `exit_code` 2, the config path and *"aside"*. The canary is on
    neither stream, the file is unchanged, and there is no header and no store.
  - **The red baseline at `HEAD`** exits 101, *"1 passed; 3 failed"*, with G105-3 green. G105-1:
    `left: PassphraseUnavailable` / `right: Usage`. G105-2: *"init over a vault whose header was
    moved aside rewrote …/vault/store/check: the old vault's records are gone"*. G105-4: *"init
    rewrote the nested store/check it should have refused over"*.
  - **Deviation in §3's predictions, not in the design.** §3 expected G105-1's baseline to be `Ok`
    with the file replaced, and P105-a to redden it on *"must refuse"*. With no passphrase fd,
    `run_init` cannot return `Ok`, so G105-1 reddens on its class at `HEAD` and under P105-a. The
    data-loss reds come from G105-2 and G105-4, which supply an fd.
  - **Greens on the final files.** In the shadow, `--test init_command` with the spawned tests:
    *"25 passed; 0 failed"*; the whole `antseal-cli` lib: *"331 passed; 0 failed"*. G105-5's file
    must load at dispatch (`lib.rs:140`), so the spawned tests also ran against L-CFG3's
    `config.rs`: *"3 passed"*. In the shared tree, `--test init_command -- --skip the_binary_`:
    *"22 passed; 0 failed; … 3 filtered out"*, `init_over_an_existing_vault_refuses_absolutely`
    among them. `clippy -D warnings` (both crates), `rustfmt --check` and `check-personal-data.py`
    exit 0. A clippy `type_complexity` red in G105-3 (exit 101, shadow) was fixed with a local
    `type Residue`.
  - §3's other stay-greens (`vault_keyfile.rs`, `peer_resolution.rs`, `secret_hygiene.rs`,
    `upgrade_hook.rs`), `scripts/stage0.sh:408` and `scripts/e2e-sepolia.sh` were read, not run.
    By that reading no live flow is refused. The close gate's test lane runs those targets.
- **§3, the plants: the five ruled, plus the lane's P105-f.** They ran in the shadow against the
  five tests. Each exited 101, was red by message, and was restored by cp + `touch` with sha256
  equal.
  - **P105-a** (the check deleted): *"1 passed; 4 failed"*. G105-1 on its class, G105-2 and G105-4
    as at the baseline, and G105-5 `left: Some(0)` / `right: Some(2)`, *"Vault created at …"*.
  - **P105-b** (the check moved below `obtain_passphrase`): *"4 passed; 1 failed"*, only G105-1,
    on its class. It alone pins the position, because the others supply a passphrase.
  - **P105-c** ("the directory exists"): *"1 passed; 4 failed"*. G105-3: *"an empty directory:
    init must proceed, but refused: …"*. G105-1, -4 and -5 too, because the path found is the root.
  - **P105-d** (`vault.lock` counts): *"3 passed; 2 failed"*. G105-3, case 2: *"the lockfile alone:
    init must proceed, but refused: … vault/vault.lock is in it …"*. G105-4 too: the walk meets the
    lock before `store/check`.
  - **P105-e** (the path dropped from the text): *"2 passed; 3 failed"*. G105-1: *"the refusal
    names the file it found: … — a file is in it — …"*. G105-4 and G105-5 too.
  - **P105-f, the lane's own** (the walk never descends): *"4 passed; 1 failed"*, only G105-4,
    *"init rewrote the nested store/check it should have refused over"*. Without G105-4 and this
    plant, a walk that never descends survives every ruled test.
  - At the lane's close the plant-marker grep over the tree, untracked files included, exits 1 with
    a positive control. This pass finds no marker in the lane's three files.
- **The tree, re-read for this section.** The three files match the lane's final sha256 (`init.rs`
  `06ba852e…`, `tests/init_command.rs` `f96d49d4…`, `crates/antseal-net/src/wallet.rs`
  `2b8e9bb2…`). `git diff --numstat 6e1cab3` gives 187/50, 337/0 and 69/1: 593 insertions and 51
  deletions. The report's 591 predates its clippy fix, which added two lines to G105-3.
  `json-envelopes.txt:2` is byte-identical to `HEAD`'s, `cli-surface.help.txt` is untouched,
  `PINNED_CLASS_COUNT` is 36, and `vault/session.rs` and `vault/export.rs` are untouched.
- **Left open.**
  - **`U112`, minted from the lane's two odd entries; `U112` owns them.** (a) A dangling
    `vault.header` link fails D39's `header.exists()` and is then named by the walk, so the refusal
    contradicts itself. (b) An empty directory named `config.toml` passes the walk. This records
    lane ran both through a copy of the tree's debug binary, built after L-INIT landed, under
    `env -i` with no passphrase fd, and read the exit statuses directly. The control, an empty
    directory, reached the passphrase step: exit 11, `passphrase-unavailable`.
    - (a) exits 2 with *"… holds no vault (there is no vault.header) but is not empty —
      …/vault.header is in it — …"*, as the row says.
    - (b) never reaches `init`. Dispatch's `config::load()` (`lib.rs:140`) reads `config.toml`
      first and exits 4, *"I/O error: reading …/vault/config.toml: Is a directory (os error 21)"*,
      and the vault directory is left holding only that empty directory. So (b)'s *"`init`
      creates the vault and then fails writing `config.toml`"* holds only for an in-process
      `run_init` caller. The row's text is the orchestrator's.
  - **For L-LOC**, the lane's drift map, checked line by line in this pass: `HEAD`'s
    `init.rs:537-563` is now `:544-570` (+7), and `:623-635` is `:631-643` (+8, because
    `init_network`'s doc gained a line). These cover the seven living-doc citations §5 counted.
    P2's expectation that `wallet-hygiene.md:236` and `:392` stay put was false, as §5 warned.
  - `tests/init_command.rs:1157` still cites *"(P2 Log 8)"*, the planning log, in the form the
    lane removed from `init.rs`'s doc. It resolves through §1.4's heading. This lane has reported
    it to the orchestrator.

## Closing — this record is not consent

It adds one refusal to `init` and a clause to one document, inside the wave's own commits.
Nothing in it authorises a push, a workflow dispatch, a deploy or any other outward act; each of
those needs the maintainer's express consent naming the action, the destination and the account.
