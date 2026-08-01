# D51 — `--json` × interactivity contract

- **Status: RESOLVED — the register's lean (hard-abort without `--yes`)
  is confirmed and widened: `--json` is machine mode and never prompts
  for *anything* — consent, passphrase, wizard questions, or
  destructive confirms — each prompt class having a declared
  non-interactive channel or a deliberate absence of one. Interactivity
  is gated on stdin `isatty` (matching U3's own wording); `/dev/tty` is
  rejected. Refused/unobtainable consent is one exit-code class,
  distinct from passphrase-unavailable and usage. Post-receipt resume
  is not consent-bearing and proceeds without `--yes`. `vault import`
  over an existing vault has no bypass flag by design — scripted
  overwrite-import is unsupported in v1.**
- **Date: 2026-08-01** (planning; U3 implements the framework)
- **Owning tasks:** U3 (tasks/U.md:33-43, incl. Notes "Open decision 15
  must close before U14"), U14 (consent gate), U7/D41 (passphrase),
  U17/D45 (resume), U12 (import confirm), U29 (M3 reveal consent), U2
  (exit classes), U1 (surface — none added).

## Context

Register entry D51 / U open decision 15 (tasks/U.md:402). U3 already
commits the skeleton: one JSON document on stdout, all human copy on
stderr, "confirmation prompts are TTY-only; a consent-bearing command
run with `--json` (or a non-TTY stdin) and without `--yes` aborts with
the dedicated exit code instead of hanging" (tasks/U.md:38). The
consent gate is a permanence gate — real money, permanent public
storage (MVP-SPEC.md line 34) — so the contract's failure modes are a
hung CI job on one side and an unreviewed irreversible spend on the
other.

## The one adversarial question, answered

**Should `--json` with a real TTY still prompt** (a human capturing JSON
through a pipe, confirming interactively)? No — and this is where the
contract earns its keep. TTY presence is routinely a lie in automation:
`docker run -t`, `ssh -t`, and CI pty wrappers all allocate a
controlling terminal nobody will ever answer. A contract in which
`--json` *sometimes* prompts converts each of those into a silent hang.
The value of `--json` to a script is precisely that its behavior is
independent of terminal circumstances: prompts never happen, inputs
arrive only via declared channels, and every outcome is a typed
document plus a mapped exit code. A human who wants JSON *and* a prompt
runs without `--yes` in plain mode and pipes stdout — nothing is lost.

`/dev/tty` as the prompt device (the gpg/ssh tradition) is rejected:
it is Unix-only (D72 has not yet fixed the release-platform set, and
the contract must not bake in a platform mechanism), and it buys no
robustness against the failure mode above — `docker -t` provides a
controlling terminal too. Detection is therefore **stdin `isatty`**,
exactly U3's phrasing; prompts write to stderr and read stdin. Per D41
§semantics, `--passphrase-fd 0` consumes stdin and the run is treated
as non-interactive thereafter.

**Machine mode** ⇔ `--json` present ∨ stdin is not a TTY ∨ stdin was
consumed by `--passphrase-fd 0`. In machine mode, no prompt of any
class is ever issued.

## Prompt classes and their channels

| Class | Prompts | Non-interactive channel | Unobtainable in machine mode → |
|---|---|---|---|
| consent | U14 permanence gate; pre-pay resume re-consent (U17/D45); U29 reveal disclosure (M3) | `--yes` | **consent-not-obtained** class |
| authentication | U7 passphrase (entry; +confirm at `init`) | `--passphrase-fd` (D41) | **passphrase-unavailable** class (U7's dedicated code, tasks/U.md:92) |
| configuration | D39 `init` wizard questions | D39 flags (`--wallet`, `--wallet-key-fd`, …) | usage-error class |
| destructive confirm | `vault import` over an existing vault (U12) | **none — deliberate** | consent-not-obtained class |

`vault import`'s overwrite confirm has no `--yes` in the canonical
surface (MVP-SPEC.md line 149) and D51 declines to add one: overwriting
a vault destroys `W` for every work in it, the same irreversibility
class as D39's absolute `init` refusal, and the scripted workaround
(move/remove the vault dir first) is itself the consent. Scripted
overwrite-import is thereby *unsupported in v1*, recorded here rather
than discovered in an incident.

Commands with **zero prompts by construction**: `verify` (vault-less,
never prompts — tasks/U.md:357), `restore` (D48 §5 — the per-file
overwrite policy replaces the y/n convention), `list`, `show`,
`status`. **Post-receipt resume** is not consent-bearing (D45 §4): it
proceeds in machine mode without `--yes`, printing its plan to stderr.

## The matrix (consent-bearing commands: `seal`, pre-pay resume; `reveal` at M3)

| stdin TTY | `--json` | `--yes` | Behavior |
|---|---|---|---|
| yes | no | no | render report → prompt on stderr/stdin; decline → consent-not-obtained exit |
| yes | no | yes | render report → proceed, no prompt |
| yes | yes | no | **no prompt**: report to stderr, error envelope on stdout, consent-not-obtained exit |
| yes | yes | yes | report to stderr, proceed, result envelope on stdout |
| no | any | no | no prompt: consent-not-obtained exit (plain: message on stderr; `--json`: error envelope) |
| no | any | yes | proceed |

Invariants riding every row:

1. **The report always renders.** `--yes` skips only the confirmation —
   the consent report (file list, byte totals, quote, balances, the
   permanence warning) prints regardless, on stdout in plain mode and
   on stderr under `--json` (U14 Accept, tasks/U.md:181). An automated
   spend leaves the same audit trail an interactive one does.
2. **Stdout purity under `--json`.** Exactly one JSON envelope per
   invocation, success or failure — a consent-not-obtained abort emits
   the error envelope (U3's `error` object) with the same exit code as
   plain mode (tasks/U.md:38-42).
3. **Declined ≡ unobtainable.** One consent-not-obtained class covers
   an interactive "no" and a machine-mode absence of `--yes` — U2
   already groups them (tasks/U.md:26); the message distinguishes, the
   code does not. Scripts branch on "did not consent", not on why.
4. **Class distinctness.** consent-not-obtained ≠ passphrase-unavailable
   ≠ usage ≠ vault-auth-failure ≠ verification classes. Numeric values
   are U2's table; D51 freezes the class partition and that each is
   nonzero.

## Rationale

1. **Hang-freedom is a contract, not a hope.** Every prompt site has a
   machine-mode disposition decided *here*, so no future command can
   introduce an undeclared prompt: U3's schema-registry pattern extends
   — a command registering a `--json` fixture must also declare its
   prompt classes (none / consent / auth / config), and the U3 harness
   drives each in machine mode asserting abort-not-hang.
2. **The permanence gate stays loud even when bypassed.** Invariant 1
   is D24's philosophy applied to automation: `--yes` is consent given
   in advance, not consent skipped — the report is the evidence of what
   was consented to.
3. **Uniformity beats carve-outs.** A single "machine mode ⇒ no
   prompts" rule is testable by enumeration (U1's subcommand walk ×
   machine-mode flags) and leaves no case where two rules disagree
   about one prompt.

## Consequences — task integration

- **U3**: implements machine-mode detection and the prompt-class
  registry; CI harness asserts abort-not-hang for every registered
  prompt in both `--json` and non-TTY plain mode (extends its Accept,
  tasks/U.md:40-42).
- **U14**: consent hook takes "machine mode" as an input, never probes
  the TTY itself (single detection point); report-on-stderr under
  `--json` per invariant 1.
- **U7/D41**: passphrase-unavailable abort is machine mode + no fd.
- **U17/D45**: pre-pay resume consent joins the matrix; post-receipt
  bypasses it (not consent-bearing).
- **U12**: overwrite confirm documented as TTY-only, no bypass;
  machine-mode import over an existing vault aborts consent-not-obtained.
- **U29 (M3)**: reveal disclosure consent inherits the matrix unchanged
  — recorded now so M3 makes no fresh decision.
- **U2**: class partition per invariant 4; numeric table remains U2's.
- **U1**: no surface change — `--yes` already exists exactly where
  consent does (`seal`, `reveal`, MVP-SPEC.md line 149), and D51
  deliberately adds none elsewhere.

## Residual risk

- **Plain mode + allocated-but-unattended TTY still hangs** (docker
  `-t` without `--json`/`--yes`): indistinguishable from a waiting
  human by any detection this side of a timeout, and a consent timeout
  (auto-decline after N seconds) was considered and rejected — it turns
  slow human deliberation at a permanence gate into a race. The
  documented rule is: automation passes `--json` or `--yes`, full stop
  (help text + Q docs).
- The prompt-class registry is only as complete as review keeps it; a
  prompt added outside the registry would bypass the harness. Mitigated
  by U3's fixture-required CI gate (a command cannot ship without
  registering) and U1's closed-surface snapshot.
- `--yes` in shared shell history authorizes real spends; nothing
  technical mitigates a leaked habit of `--yes` — wallet-hygiene docs
  carry the caution (Q).
