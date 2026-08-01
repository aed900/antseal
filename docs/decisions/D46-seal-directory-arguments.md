# D46 — Directory arguments to `seal`: recurse vs files-only error

- **Status: RESOLVED — files only; a directory argument is a hard error
  at plan validation, before consent and payment (D24 pattern). Recursion
  is rejected for v1 not because it is unwanted but because every one of
  its sub-rules (iteration order, hidden files, symlinks, non-regular
  files) would be frozen per seal into a permanent paid artifact, and
  under `--yes` there is no human checkpoint left to catch a wrong
  default. Error-now → recursion-later is the additive, reversible
  direction. Duplicate and non-regular-file arguments are errors under
  the same rule.**
- **Date: 2026-08-01** (planning; U13 implements the validation)
- **Owning tasks:** U13 (seal plan validation, tasks/U.md:169 "Directory-
  argument handling per open decision 8"), U2 (error class), G14
  (receives only regular-file paths). Feeds D48 (restore re-rooting)
  and D49 (the same validation runs under `--dry-run`).

## Context

Register entry D46 / U open decision 8 (tasks/U.md:395). The spec says
only `seal <path>…` (MVP-SPEC.md line 149) and assigns directory
semantics nowhere. What a directory argument *would* determine is
permanent and paid: the file set (each file's bytes uploaded forever and
paid for), the manifest file-table order (arg order = `file_id` order,
MVP-SPEC.md line 76 — feeding every per-file salt derivation), the unit
set (= reveal granularity, frozen at seal time), and the visible
structure metadata every bundle recipient sees (line 95).

## The case for recursion, stated fairly, and why it fails

"Seal your work" naturally means "seal this project directory", and the
consent gate already lists every file with byte totals and cost before
anything is paid (U14, tasks/U.md:176-178) — so recursion's surprises
are, in principle, reviewable.

It fails on three points:

1. **`--yes` removes the checkpoint.** The consent gate is bypassable by
   design for scripts (MVP-SPEC.md line 34). A scripted
   `seal ./project --yes` would commit whatever the recursion rules
   swept up — `.env`, `.git/` objects, editor droppings — permanently
   and at cost, with zero human review. An interactive user scrolling a
   500-line file list is only marginally better protected.
2. **Every sub-rule is a frozen mini-decision.** Recursion forces
   simultaneous, permanent-per-seal answers to: iteration order (POSIX
   leaves `readdir` order unspecified, so unsorted traversal would make
   the same command on the same tree produce differently-ordered file
   tables across filesystems — sortable, but that is one more frozen
   rule), hidden-file inclusion, symlink traversal (loops, escapes
   outside the tree), `.gitignore`-style filtering or not, and
   non-regular files. Each default is defensible and each wrong default
   is discovered only after money is spent. D22's lesson applies: prefer
   the smallest frozen rule surface that solves the actual problem.
3. **The shell already provides recursion — user-visible and
   user-controlled.** `seal ./docs/**/*.md`, `seal $(find src -type f
   -name '*.rs' | sort)` — the expansion appears in argv, is chosen by
   the user, and bash sorts glob expansions deterministically. The
   workaround is not a degraded experience; it *is* the explicit file
   list the permanence model wants, and it keeps the per-file flag
   mappings (`--no-fine-tree <glob>`, `--split`) visually checkable
   against a visible file list. (ARG_MAX bounds this at roughly a
   couple of thousand files — far above the MVP's intended work size;
   noted, not mitigated.)

## Decision

At plan validation — before the consent gate, before any derivation,
quoting, anchoring, or payment, and identically under `--dry-run`
(D49) — `seal` hard-errors if any argument:

1. **is a directory** (after following the argument's own symlink, i.e.
   `stat` not `lstat`: a symlink explicitly naming a *file* is the
   user's deliberate act and is accepted; a symlink to a directory is a
   directory);
2. **is not a regular file** (FIFO, device, socket: reading one is
   non-deterministic or blocking — no permanent artifact may depend on
   it);
3. **duplicates another argument after lexical normalization**
   (cwd-join, `.` / `//` cleanup — `a.txt` vs `./a.txt` is one path
   named twice: paying twice for one file and deriving two file entries
   over identical bytes is never intent; this rule also removes the
   easiest restore-target collision, D48);
4. does not exist / is unreadable (ordinary I/O error, listed here only
   to fix that *all* argument validation completes before consent).

The error names every offending argument (not just the first), states
the rule, and suggests the glob/`find … | sort` recipe. Distinct U2
variant in the usage/plan-validation class, exit-code table owned by U2.
Error copy and help text carry the workaround (U31 catalog).

## Rationale beyond the rebuttal above

1. **Permanence asymmetry, verbatim from D24:** a hard error costs a
   re-run measured in seconds; a wrong recursion outcome is
   irreversible, public, and paid (docs/decisions/
   D24-no-fine-tree-split-conflict.md, Rationale 1-2 — "ambiguous
   permanent choices are errors, not defaults").
2. **Reversibility (the D28 direction argument):** files-only → v1.1
   `--recursive` with deliberately designed sub-rules is purely
   additive surface; shipping recursion now and changing its sub-rules
   later silently changes what identical commands seal. Under
   uncertainty about permanent behavior, take the direction that can be
   undone.
3. **Nothing in M1's committed scope needs recursion:** the E2E seals
   enumerated fixture files (S17, tasks/S.md:220); no Accept criterion
   anywhere passes a directory to `seal`.

## Consequences — task integration

- **U13**: implements checks 1-4 in plan validation; mock-ordered test
  asserts the error precedes any consent/backend/anchor call (same
  harness shape as D24's row). Notes line "Directory-argument handling
  per open decision 8" resolves to this record.
- **U2**: one new variant class (invalid-seal-argument) covering rows
  1-3; row 4 stays the ordinary I/O class.
- **U31**: workaround copy in the catalog; help for `seal <path>…`
  states "regular files only; use your shell's globbing to expand
  directories".
- **G14/G5**: unchanged — they may now *assume* regular files (assert,
  not re-check).
- **D48**: rule 3's normalization is the same lexical cleanup restore
  re-rooting uses; one shared helper.
- **D49**: `--dry-run` runs this validation verbatim (pipeline-prefix
  principle) — a dry-run is the cheap way to lint a file list.

## Residual risk / revisit trigger

- Hardlinks and distinct symlink spellings of one inode are *not*
  detected by rule 3 (lexical only); a user can still pay twice for one
  file's bytes via two genuinely different paths. Detecting it needs
  `stat` identity comparison — cheap, but it would also reject
  legitimate same-content-different-path intent, so it is left out; the
  consent report's file list is the net. Accepted.
- **Revisit trigger for recursion (v1.1 candidate):** real users
  repeatedly hand-building file lists for large works. The future
  `--recursive` design must then decide, deliberately and together:
  bytewise path sort order, hidden-file default (lean: excluded),
  symlink policy (lean: never followed), and an ignore-file story —
  none of which is prejudged here beyond "sorted, because `readdir`
  order must never reach a manifest".
