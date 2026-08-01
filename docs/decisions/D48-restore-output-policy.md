# D48 — `restore` default output directory + overwrite policy

- **Status: RESOLVED — default output is the work-scoped fresh directory
  `./antseal-restore-<work-id>/`; recorded paths are re-rooted under the
  output dir by a defensive lexical rule (absolute prefix stripped, `..`
  rejected); overwrite policy is per-file and byte-aware: an existing
  identical file counts as already-restored (idempotent re-run), an
  existing different file is a per-file refused-overwrite error and is
  never touched. Files failing verification are never written (S14).
  Restore never prompts. All-per-file processing continues on error;
  the exit code reports the most severe class present. In-place restore
  remains possible explicitly (`-o /`), never by default.**
- **Date: 2026-08-01** (planning; U20 wires, S14 executes)
- **Owning tasks:** U20 (CLI wiring + policy, tasks/U.md:240-249 "per
  open decision 10 — never silently clobber"), S14 (engine,
  tasks/S.md:178-189), U2 (exit classes), U9 (recorded paths). Feeds
  S19 (clean-tree E2E) and the M4 disk-loss drill.

## Context

Register entry D48 / U open decision 10 (tasks/U.md:397). `restore
<work-id> [-o dir]` (MVP-SPEC.md lines 37, 149) writes recovered
originals "by vault-recorded paths into `-o dir`" (S14,
tasks/S.md:183), preferring raw-mirror bytes so CRLF/BOM/NFD originals
come back exact. `-o` is optional in the canonical surface, so a default
must exist. Constraints already committed: never silently clobber
(register mandate), per-file verification with failing files not
written as verified output (S14, tasks/S.md:186), byte-identical
round-trip E2E (U20/S19), and restore is "the door of the permanent
vault" — the command the M4 disk-loss drill runs on a clean machine.

None of this is format surface; like D22 it is CLI policy, changeable
in a future app version without a format bump. It still deserves a
frozen record because the M4 drill and user muscle memory both build on
it.

## Decision

### 1. Default output directory

`./antseal-restore-<work-id>/` under the invocation cwd, `<work-id>` in
its printed form (64 lowercase hex — the D29 hex convention). Created
if absent (with parents), also for an explicit `-o`. Work-scoped naming
makes the default collision-free across works by construction and makes
a re-run of the *same* work land in the *same* directory — which is
exactly what §3's idempotency wants. Rejected defaults: bare cwd
(maximal clobber surface, mixes restored files into a live tree) and
original absolute locations (in-place restore as a *default* is the
definition of silent clobber risk; see §5 for the explicit path).

### 2. Re-rooting recorded paths (defensive, working principle 2)

For each recorded original path: lexically clean it (the shared D46
helper: `.` / `//` cleanup), strip any absolute-root prefix, **reject**
any remaining `..` component or empty result as a distinct
malformed-record error, then join under the output dir. The vault is
self-authored, but a hand-edited or bit-rotted record must degrade into
a clean error, never a write outside `-o` (library code returns errors
— project working principles). Before any write, all target paths are
computed; an intra-work target collision (two recorded paths mapping to
one target) aborts the whole run pre-write as a distinct error — no
half-ordering exists that is deterministic and safe.

### 3. Per-file overwrite policy + idempotent re-run

Per file, after S14 has fetched, decrypted, padding-stripped, and
**verified** the bytes (raw-mirror bytes where one exists — the
comparison bytes are always exactly what S14 would write):

| Target state | Behavior | Status reported |
|---|---|---|
| absent | write via temp file + rename (§4) | `restored` |
| exists, byte-identical to verified bytes | leave untouched (no rewrite, no mtime churn) | `already-restored` (success) |
| exists, differs | do not touch it; per-file error | `refused-overwrite` |
| verification failed (commitment mismatch) | never written (S14) | `verification-failed` |
| fetch/decrypt failure | never written | `fetch-failed` / distinct per S14's classes |

A re-run after a partial failure therefore completes the missing files,
confirms the done ones, and exits 0 iff every file is `restored` or
`already-restored` — restore is convergent without ever being
destructive.

### 4. Write discipline

Each file is written to a temp name inside the output directory and
atomically renamed into place, so a killed restore never leaves a
partial file at a final path — the on-disk statement "this file was
restored and verified" is all-or-nothing per file (S14's "not written
as verified output" made crash-safe). No fsync ceremony beyond the
rename: these are user files, not the vault journal.

### 5. No prompts; explicit in-place restore

`restore` asks nothing, ever (it is not consent-bearing and performs
nothing irreversible — D51 matrix: zero prompt rows). The overwrite
policy replaces the interactive "overwrite? y/n" convention.
Consequence of §2's prefix-strip worth stating: `-o /` reproduces
recorded absolute paths at their original locations — deliberate,
explicit, and still protected per-file by §3 (identical → confirmed,
different → refused). That is the supported "put my files back" flow;
the default never does it.

### 6. Exit code (single run, multiple files)

Any non-success → nonzero; when classes mix, the reported class follows
fixed severity: `verification-failed` (evidence problem) >
`refused-overwrite` (local conflict, user-fixable) > fetch/network
(transient). Per-file detail always available in output and in the
`--json` result (per-file status array; U20 fixture). U2 owns the
numeric table; D48 fixes the classes and their order.

## Rationale

1. **"Never silently clobber" is satisfiable without prompts or
   refusal-only.** Byte-aware skipping is stronger than a blanket
   refuse-if-exists (which would make re-runs after partial failure
   permanently stuck) and stronger than force-flags (which restore the
   clobber). The identical-file case is *proof of prior success*, not a
   conflict.
2. **Work-scoped default + convergent re-run is what the drills need.**
   S19 and the M4 disk-loss drill run restore on machines in unknown
   intermediate states; a policy under which "run it again" is always
   safe and always progress is the operationally correct one
   (tasks/S.md:241-251).
3. **Pre-computing targets** (§2) mirrors D46's validate-everything-
   before-acting shape: every path problem in the work surfaces before
   the first byte is written.

## Consequences — task integration

- **U20**: implements §1-§6; Accept's "existing-file collision behavior
  tested per chosen policy" becomes three tests (absent / identical /
  differing), plus the malformed-record and intra-work-collision
  errors; `--json` fixture carries the per-file status array.
- **S14**: engine returns verified bytes + per-file outcomes; the
  raw-mirror preference defines the §3 comparison bytes; its Accept's
  "affected file is not written" is row 4 verbatim.
- **U2**: new classes `refused-overwrite`, `malformed-restore-record`
  (the §2 rejections), ordered per §6 alongside the existing
  commitment-mismatch and network classes.
- **S19/Q32**: the clean-tree E2E asserts byte-identical restore into
  the default dir and a second-run `already-restored` pass.

## Residual risk / discovered work

- **Cross-form seal-time collisions (discovered work, U13 candidate):**
  D46 rule 3 rejects duplicate arguments in one lexical form, but two
  *distinct* recorded paths can still re-root to one target (e.g.
  absolute `/x/a.txt` sealed together with relative `x/a.txt`). §2
  catches it at restore time as a hard error — but that work is then
  permanently awkward to restore (no per-file restore selection exists
  in v1's surface). Proposed: U13 plan validation additionally computes
  §2 targets at *seal* time and hard-errors on collision, closing the
  trap before money is spent. Cheap (same shared helper), and exactly
  the D24 pattern. Until it lands, the trap is reachable and this
  record is its documentation.
- Restoring two *different works* into one explicit `-o dir` can
  interleave files; per-file byte-aware policy keeps it non-destructive
  (differing targets refuse). Not defended beyond that — the default
  dir's work-scoping is the guidance.
- Filesystems without atomic rename semantics (network mounts) weaken
  §4 to best-effort; accepted, undocumented-platform territory.
