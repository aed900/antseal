# D41 — Non-interactive passphrase supply channel

- **Status: RESOLVED — a global `--passphrase-fd <n>` (file-descriptor
  channel; stdin is the degenerate case `--passphrase-fd 0`). The env-var
  channel is rejected on a measured mechanism: on Linux the kernel serves
  `/proc/PID/environ` from the execve-time snapshot, which no userland
  unset or zeroize can wipe — an env passphrase contradicts the vault's
  zeroization mandate for the whole process lifetime. The OS keystore is
  not a scripting channel and stays with U8/D50.**
- **Date: 2026-08-01** (planning; U7 implements; U1 carries the flag)
- **Owning tasks:** U7 (passphrase UX), U1 (surface), U13 (scripted
  seal), U21 (hygiene harness), S17–S19 (CI E2E consumers). Interacts
  with D39 (init flags) and D51 (prompt matrix).

## Context

Register entry D41 / U open decision 3 (tasks/U.md:390): scripts and the
M1 devnet E2E must unlock the vault "without a TTY" (tasks/U.md:87,90);
`--yes` covers confirmations only, not passphrases. The channel must
satisfy, simultaneously:

- **project rule 6 / U21** — sentinel secrets never in stdout, stderr,
  logs, JSON, *or any inspectable process metadata*; the harness will be
  built to fail on leaks (tasks/U.md:251-260);
- **the zeroization mandate** — passphrase buffers in zeroizing types
  (MVP-SPEC.md line 143; tasks/U.md:87);
- **CI reality** — S17–S19 run non-interactively on the devnet
  (tasks/S.md:215-251), so the channel must work from a plain shell
  script with no desktop session.

## Options and evidence

### (a) Environment variable (`ANTSEAL_PASSPHRASE`) — REJECTED

Superficially attractive: zero clap-surface growth (U1's closed-surface
rule; env is already the sanctioned side-channel for log filtering,
tasks/U.md:13), and industry precedent exists (restic/borg-class backup
tools use env passphrases). Rejected on mechanism, measured on this
machine (Linux 6.1, 2026-08-01):

```
/proc/self/environ  mode 400   (owner + root readable)
/proc/self/cmdline  mode 444   (world readable)
after libc unsetenv(): /proc/self/environ still contains the value
```

The third line is the decisive one: `/proc/PID/environ` is the kernel's
view of the **execve-time environment block on the process stack**;
`unsetenv`/`std::env::remove_var` edit libc's heap copy only. A
passphrase supplied via env is therefore recoverable from procfs (by any
same-UID process, and root) for the *entire process lifetime*, and no
code we write can zeroize it — a standing contradiction of the line-143
zeroize mandate, of the same kind D88 refused to accept for HKDF state.
Secondary strikes, each individually survivable: environment is
inherited by any future child process (none today; one `Command::new`
away forever); `systemctl show`, CI "dump env" debug steps, and crash
tooling all print environments habitually; and in edition 2024
(`docs/toolchain.md`, D4) `std::env::set_var`/`remove_var` are `unsafe`,
so even the futile scrub would need an unsafe block.

### (b) File-descriptor flag `--passphrase-fd <n>` — **ADOPTED**

The gpg convention. The secret transits a pipe: never in argv (only the
fd *number* is), never in the environment, never on disk; read directly
into C's zeroizing buffer and wiped on drop. Composes with every
supply-side mechanism without antseal knowing about any of them:

- shell: `printf '%s' "$PASS" | antseal seal … --passphrase-fd 0` or
  `antseal … --passphrase-fd 3 3<secret.file`;
- systemd: `LoadCredential=` + redirect from `$CREDENTIALS_DIRECTORY`
  (credentials are files, so the fd channel needs no systemd-specific
  code path);
- CI: the S17–S19 harness pipes a fixture passphrase; U21 pipes a
  sentinel and scans everything else for it.

Cost: one **global** flag added to U1's canonical surface — declared
here as a deliberate amendment (same mechanism as D39's init flags).
Global rather than per-command because every vault-touching command can
need it; `verify` ignores it structurally (it never opens a vault and
never prompts, tasks/U.md:357).

### (c) OS keystore — REJECTED as the scripting channel

It is not a *channel*, it is a *wrap factor*: U8 owns the keystore wrap
for `W`, D50 (in flight) owns its platform scope, and headless CI needs
a mock keystore even for that (tasks/U.md:105). Provisioning a keystore
in an ephemeral CI job to deliver one string is strictly heavier than a
pipe, and does nothing for the "no trace in argv/env" requirement that
(b) already satisfies. No interaction: a keystore-wrapped vault still
takes its passphrase via prompt or fd.

### (d) `--passphrase-file <path>` — REJECTED (recorded, not needed)

Subsumed by (b) via redirection (`--passphrase-fd 3 3<file`), and a
path-taking flag invites committed-passphrase-file accidents. Revisit
trigger: if real systemd unit usage shows the `sh -c` redirect to be a
recurring footgun, add the file variant *additively* (legal surface
growth) — do not widen now.

## Byte semantics (frozen with U7 — channel parity rule)

The fd channel MUST accept exactly the passphrase space the interactive
prompt accepts, so a vault created either way unlocks either way:

1. Read fd `n` to EOF, hard cap 1 KiB (a documented U-constant, not
   format surface; the strength floor makes longer inputs pointless and
   the cap bounds a hostile pipe).
2. Strip **exactly one** trailing LF, or CRLF, if present (`echo`/heredoc
   friendliness; deterministic).
3. Reject: empty result, interior `0x00`, interior LF/CR — none of these
   is enterable at a no-echo prompt, and parity beats permissiveness.
4. Otherwise the bytes are the passphrase **verbatim**: no trimming of
   other whitespace, no Unicode normalization (normalizing would change
   KDF input for existing vaults — a compatibility trap; G's NFC
   machinery is for sealed content, never for credentials).
5. On the fd path at `init`, the confirmation prompt is skipped (a piped
   value has no typo channel; gpg semantics). The strength floor applies
   unchanged.
6. `--passphrase-fd 0` consumes stdin: for the remainder of the run
   stdin is treated as non-interactive under D51's matrix (consent then
   requires `--yes`). Deterministic, documented.

## Consequences — task integration

- **U1**: global `--passphrase-fd <n>` joins the canonical surface and
  its help snapshot; rejects non-numeric values at parse.
- **U7**: implements §semantics; the "no TTY and no non-interactive
  supply" abort (tasks/U.md:92) keys on *flag absence* + D51's TTY gate,
  and its dedicated exit code is distinct from consent-refused (D51).
- **U11/D39**: `--wallet-key-fd` reuses this mechanism for the second
  secret; the two fds must differ.
- **U13/S17–S19**: scripted seal/E2E invocations use the fd channel; the
  harness never exports the passphrase into its own environment (the
  probe above is why).
- **U21**: adds two assertions beyond the stdout/stderr/log scan — the
  sentinel does not appear in `/proc/self/cmdline`, and the harness's
  own env (as seen at `/proc/self/environ`) never contained it. The
  self-test leaky path should include a deliberate env-var variant to
  prove the scan would catch regression to (a).
- **D51**: rows for "passphrase needed, no TTY, no fd → abort
  (passphrase-unavailable class)" land in its matrix.

## Residual risk

- Same-UID malware can read a pipe's far end or ptrace the process
  regardless of channel — (b) is not a defense against a compromised
  account, and no channel is; the claim is strictly "no *residual* copy
  in argv/env/procfs after read".
- Supply-side hygiene remains the user's: a passphrase in a shell
  variable used with `3<<<"$PASS"` may transit a shell temp file
  (here-string implementation detail). Docs recommend the `printf | …
  --passphrase-fd 0` and file-redirect forms; that guidance is Q-doc
  copy, not enforceable by us.
- The 1 KiB cap and newline-strip are frozen as CLI behavior (scripts
  depend on them); changing them later is a compatibility event for
  scripts, though never for the vault format (the KDF sees only the
  resulting bytes).
