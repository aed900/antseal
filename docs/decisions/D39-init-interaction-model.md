# D39 — `init` interaction model: wizard vs flags

- **Status: RESOLVED — the register's dichotomy is overturned as a false
  choice: `init` is a TTY wizard whose every question has a flag/fd
  equivalent (hybrid), because a pure wizard violates three committed
  M1 Accept criteria and a pure-flags `init` cannot carry the passphrase.
  The v1 `init` flag set is enumerated here as a deliberate amendment to
  U1's canonical surface. Existing-vault refusal is absolute (no `--force`).**
- **Date: 2026-08-01** (planning; U11 implements, U1 carries the surface)
- **Owning tasks:** U11 (init flow), U1 (canonical clap surface), U7
  (passphrase UX), U8 (wrap offer), S5 (wallet ops). Consumes D41
  (passphrase channel), D44 (import formats); leaves selector values to
  D40 (KDF) and D50 (keystore scope) — both in flight this wave.

## Context

Register entry D39 / U open decision 1 (tasks/U.md:388): "pure interactive
wizard vs convenience flags (canonical surface enumerates no `init`
flags)" — the spec's canonical CLI list gives `init` no flags at all
(MVP-SPEC.md line 149), and U1 freezes the surface "from day one" with a
snapshot that "enumerates exactly the canonical surface, nothing extra"
(tasks/U.md:13,15).

What `init` must collect (MVP-SPEC.md line 143; tasks/U.md:135): a
passphrase (entered twice interactively, strength-floor enforced), the
wallet source (**generate or import**, plus the key material on import),
the optional keyfile/OS-keystore wrap for `W` (spec: `init` "offers" it),
the KDF choice (D40's mechanism), and the network (already covered by the
global `--network`).

## Why both pure options are unwritable

**Pure wizard** contradicts three committed Accept criteria:

- U7 Accept (tasks/U.md:90): "non-interactive path drives a full scripted
  `init`+`seal` without a TTY".
- U11 Accept (tasks/U.md:137): "E2E: fresh machine → `init` → funded
  devnet wallet → U13 seal succeeds (feeds M1 devnet E2E)" — S17/S19 run
  this in CI (tasks/S.md:220-226, 241-251), where there is no TTY.
- U11 Accept (tasks/U.md:140): "`--json` fixture registered" — and under
  the D51 contract `--json` never prompts.

A wizard with no non-interactive equivalents makes the M1 E2E gate
unreachable. Not a taste question — a scheduling contradiction.

**Pure flags** (no prompts) fails on the passphrase: argv is
world-readable (`/proc/PID/cmdline` mode 444 — measured, D41 §evidence),
so a `--passphrase <str>` flag is forbidden by project rule 6 and U21's
harness, and *interactive entry with confirmation is the spec's own
model* (tasks/U.md:87 "entry + confirmation at creation"). The first-run
experience — the one command every user runs — cannot be flags-only.

So the register's two options are both dead on committed evidence; the
real decision is the *shape of the hybrid* and the exact flag set, which
is what U1's frozen surface needs.

## Decision

1. **Hybrid, prompt-fills-gaps.** With a TTY (stdin `isatty`, per D51),
   `init` runs a short wizard: passphrase entry + confirmation (no-echo),
   wallet source (generate / import, with no-echo paste on import), the
   U8 wrap offer, and D40's KDF question if D40 defines one. Any value
   already supplied by flag/fd is not asked again. Prompts write to
   stderr and read stdin (D51's stream contract).
2. **Every question has a non-interactive equivalent.** Without a TTY
   (or under `--json`), nothing prompts: missing required inputs abort
   with the dedicated codes (passphrase-unavailable per U7/D41; usage
   error for a missing choice), never hang — U3's contract
   (tasks/U.md:38) applied to `init`.
3. **The v1 `init` flag set — a deliberate U1 surface amendment:**
   - `--wallet <generate|import>` — default `generate` (spec order,
     MVP-SPEC.md:149 "generate or import"; generating is non-destructive,
     so a defaulted script gets the safe branch).
   - `--wallet-key-fd <n>` — import key material via the D41 fd
     mechanism (secret material never in argv/env; format per D44).
     Required when `--wallet import` runs non-interactively; must name a
     different fd than `--passphrase-fd` (equal fds are a usage error).
   - `--passphrase-fd <n>` — global, defined by D41 (listed here because
     `init` is its first consumer; on this channel the confirmation
     prompt is skipped, D41 §semantics).
   - One KDF selector slot (name/values owned by D40) and one wrap
     selector slot (`--wrap`, values owned by U8/D50, default = declined,
     which U8 Accept already requires to be byte-compatible with a
     passphrase-only vault, tasks/U.md:104).
   - No other `init` flags. Network is the existing global `--network`
     (written to config per U4); no `--force`, see 4.
4. **Existing-vault refusal is absolute in v1.** U11's "refuses by
   default" (tasks/U.md:135) is resolved as: no override flag exists;
   the error names the vault path and tells the user to move/remove it
   manually (after `vault export` if they want the contents). Rationale:
   overwriting a vault destroys `W` — every sealed work's reveal/restore
   ability, forever (MVP-SPEC.md line 143 loss framing). A `--force` on
   the *creation* command is a one-token irreversibility bypass; manual
   filesystem action is the consent. `vault import` keeps its own
   confirm-to-overwrite (U12), which is the supported restore-over path.

## Rationale

1. **The Accept criteria decide it** (§above). This is the D26 pattern:
   the register's framing, not its content, was the error.
2. **House precedent.** U1 already uses env-driven config (`RUST_LOG`
   filtering) precisely to avoid surface growth (tasks/U.md:13), and D41
   rejects env for secrets — so scripting `init` requires *declared*
   flags; smuggling choices through undocumented env vars would be a
   second, invisible surface.
3. **Flag-equivalents keep the wizard honest.** Every wizard answer is
   reproducible as a command line, so the S17/S19 scripts, the U21
   hygiene harness, and the docs exercise the same decision points a
   human sees — no interactive-only code path exists to drift untested.
4. **Defaulting `--wallet generate`** is safe in both directions: a
   script that forgot the flag gets a fresh, unfunded key and prints its
   address (recoverable, nothing spent); requiring the flag would add
   friction with no hazard averted.

## Consequences — task integration

- **U1**: canonical `init` surface becomes
  `init [--wallet generate|import] [--wallet-key-fd <n>] [--wrap …] [<D40 slot>]`
  plus the global `--passphrase-fd <n>` (D41). Help snapshots enumerate
  exactly this; the U1 Accept "nothing extra" clause now includes these.
- **U7**: confirmation prompt is TTY-path-only; fd path reads one value
  (D41); floor enforced on both paths (channel-independent).
- **U11**: wizard order fixed as passphrase → wallet → wrap → (KDF per
  D40); prints address + funding instructions for the active network;
  `--json` fixture per U3. Absolute refusal message per Decision 4.
- **U8/D50**: `--wrap` selector values land with U8's implementation
  under D50's platform scope; D39 only reserves the flag and the
  "declined by default" semantics.
- **D40**: whatever selection mechanism it chooses must be expressible
  as one `init` flag + one wizard question, or state explicitly that it
  is automatic (no user input) — D39 holds either way.
- **U21**: harness drives both the wizard (pty) and the flag/fd path
  with sentinel passphrase + sentinel wallet key, asserting neither
  appears in argv, stdout, stderr, logs, JSON, or persisted files.

## Residual risk

- The flag set is CLI surface frozen by U1's snapshot discipline, not
  format surface — extending it later (e.g. a future `--force-reinit`)
  is additive and legal; *removing* a flag breaks scripts. Kept minimal
  for exactly that reason.
- Absolute refusal (Decision 4) means a wiped-but-present `~/.antseal/`
  (e.g. an empty dir left by a failed manual cleanup) also refuses;
  the error text must name the path so the fix is obvious. Accepted:
  refusing too much is recoverable, refusing too little is not.
- D40 may yet need an interactive-only low-RAM fallback prompt
  (tasks/U.md:80). If so, its non-interactive equivalent must be a flag
  value, or non-TTY `init` on a low-RAM machine will abort — flagged to
  D40 rather than solved here.

## Amendment (2026-08-19, U86 / D155 §2 R7): Decision 4's *"after `vault export`"* parenthetical is struck

Decision 4 (`:87-95`) resolves the absolute refusal as *"the error names the
vault path and tells the user to move/remove it manually **(after
`vault export` if they want the contents)**"*. The parenthetical was true when
this record was written and has been false since **U8** landed on 2026-08-02:
`vault export` refuses any vault whose header wrap mode is non-zero
(`crates/antseal-cli/src/vault/export.rs:745-756`), and both messages Decision
4 governs — `init::existing_vault_refusal` and
`CliError::ImportRefusedExistingVault` — are produced from a `header.exists()`
gate with the header never decoded (`init.rs:418`,
`vault/export.rs:1208-1213`), so **neither can know whether the command it was
naming would run**. The overturn of the export side was recorded in U8's
register row and in `export.rs`'s module docs, and written into D47 only by
D151 §2 R2; it was never written **here**, and this record is where an
implementer of the refusal copy looks.

**What replaces it.** The remedy is now *"move the directory aside instead of
deleting it"*: the one instruction true for every wrap mode, requiring no
command and refusable by none. The exact strings are D155 §2 R2 and §2 R3.
Everything else in Decision 4 stands unchanged — no override flag exists, the
error names the vault path, manual filesystem action is the consent, and
`vault import` keeps its own refusal.

**Not amended:** the Residual-risk paragraph (`:142-145`). Its verdict —
*"refusing too much is recoverable, refusing too little is not"* — is the
ground on which D155 §2 R1 keeps the `header.exists()` predicate and refuses
to hang a fallible decode off it.
