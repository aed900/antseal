# D45 — Resume detection keying + consent-on-resume

- **Status: RESOLVED — detection is automatic and keyed on the recorded
  invocation identity: (network, exact ordered input-path list, seal-
  shaping flag set). An exact match auto-resumes; any overlap that is
  not an exact match is a hard error before consent/payment (D24
  pattern); disjoint proceeds as a fresh seal with a notice. Interactive
  selection and a `--resume`/work-id flag are rejected. Consent:
  pre-pay resume re-fires the full U14 gate over a fresh quote
  (confirming the register's lean); post-receipt resume never re-consents
  and needs no `--yes`. The cost-change comparison rule is D36's — this
  record deliberately does not touch it.**
- **Date: 2026-08-01** (planning; U17 implements over S11; U9 records)
- **Owning tasks:** U17 (CLI resume UX), S11 (resume logic), S10/U9
  (journal + record store), U19 (`list` hint), U14 (gate). Cross-refs:
  **D36** (pre-pay re-quote/re-consent on cost change — sibling decision
  in flight; every cost-delta question defers there), D51 (`--json`
  behavior), D24 (hard-error precedent).

## Context

Register entry D45 / U open decision 7 (tasks/U.md:394): "match
incomplete work by input paths vs interactive selection… whether
resume-before-pay re-runs the consent gate (proposed: yes)". The spec's
own model is *implicit* resume: "Re-running `seal` on an interrupted
work re-uploads the byte-identical staged ciphertexts…" (MVP-SPEC.md
line 145) — no `resume` verb, no `--resume` flag exists in the canonical
surface (line 149), and U17 wires "re-running `seal` detects a matching
incomplete work" (tasks/U.md:211).

The asymmetry that decides the shape: **a missed detection is a double
payment** (the fresh seal quotes and pays again — the exact failure the
journal exists to prevent, tasks/S.md:139-151), while a false or fuzzy
match mis-attaches a user's new intent to an old work. Detection must
therefore be *conservative in both directions*: resume only on certain
identity, and refuse loudly in the gray zone rather than guessing.

## Decision

### 1. Recorded invocation identity (U9 record addition)

At seal start, the journal records: the effective network, the input
paths **exactly as they will drive the manifest file table** (arg order
= `file_id` order, MVP-SPEC.md line 76), each stored both as given and
lexically absolutized (cwd-joined, `.`/`//` cleaned, **no** symlink or
existence resolution — resume must key without touching source files,
which S11 never reads), plus the seal-shaping flag set:
`--title`, `--split`, `--force-text`, `--no-fine-tree`, `--no-anchor`,
`--force-degraded`. Session flags (`--yes`, `--json`, `--dry-run`,
`--passphrase-fd`) are *not* identity.

### 2. Matching rule, evaluated at plan validation (before consent)

Candidate set: works in state `incomplete` (any barrier), **excluding**
`abandoned` and `complete`, on the same network. Against the new
invocation's lexically absolutized path list:

| Relation to a candidate | Behavior |
|---|---|
| exact ordered path-list match ∧ shaping flags equal | **auto-resume** that work (print the resume plan: what is staged, whether a receipt is journaled, what remains — tasks/U.md:211) |
| exact ordered path-list match ∧ shaping flags differ | **hard error**, naming the work-id, both flag sets, and the recorded command line to re-run |
| path *sets* equal but order differs; or subset / superset / any overlap | **hard error**, naming the incomplete work and the recorded command line (resume never rebuilds the manifest — S11, tasks/S.md:144 — so only the exact list is even resumable; anything overlapping is presumed a garbled re-run, not new intent) |
| disjoint from every candidate | fresh seal; one-line stderr notice "N incomplete work(s) exist — `antseal list`" |

Uniqueness holds by construction: an exact-match resumable candidate is
auto-resumed rather than duplicated, so at most one can ever exist per
key; >1 matches is a defensive internal-error class, not a user prompt.

### 3. Rejected alternatives

- **Interactive selection** as the primary mechanism: the crash-re-run
  path is exactly where scripts and rattled humans live; it must be
  zero-interaction-safe, and D51 forbids prompts under `--json` anyway.
  (The near-miss *error text* replaces the would-be dialog.)
- **Explicit `--resume <work-id>`**: not in the canonical surface, and
  the user recovering from a crash typically does not know the work-id
  — the spec's re-run-the-same-command model needs no new surface.
  `list`'s resume hint (§5) covers the "which command was it" gap.

### 4. Consent-on-resume (the register's second half)

- **Pre-pay resume (no journaled receipt): the full U14 permanence gate
  re-fires, over a freshly obtained quote.** Confirming the register's
  lean — and it is mechanically forced anyway: upstream's
  `PreparedChunk` is not serializable, so "a pre-payment journal cannot
  persist it; pre-pay resume must re-quote"
  (`docs/research/S1-ant-core-api-survey.md` §3). Whether/how the gate
  treats a quote that *differs from the originally consented one* is
  **D36's decision** — D45 fixes only that the gate runs.
- **Post-receipt resume (receipt journaled): no consent, ever.** Ratifies
  U17's task text (tasks/U.md:211 "money already spent, finalize only").
  Economic argument, stated once: declining here forfeits payment and
  buys nothing — the staged ciphertexts are opaque randomized AEAD, so
  the upload discloses nothing readable (MVP-SPEC.md line 91); the only
  reachable outcomes are "complete the paid contract" and "strand it".
  Consequence under D51: post-receipt resume is **not consent-bearing**
  — it proceeds without `--yes`, non-TTY and `--json` included. The
  resume plan still prints (stderr under `--json`).
- S11's safety aborts (changed source with staged bytes intact → resume
  from staged bytes; staged bytes unavailable → abandon with forfeiture
  message) pass through U17 unchanged — D45 adds no state to that
  machine.

### 5. UX details fixed here

- `list`'s resume hint (tasks/U.md:234) prints the **recorded command
  line** (network + shaping flags + as-given paths), making the exact-
  match rule practically usable after history loss.
- `--dry-run` on an invocation that exact-matches a resumable work
  prints the resume plan and exits with zero side effects (composes
  D49's zero-mutation rule with U17's plan rendering).

## Rationale

1. **The dangerous direction is protected by default.** The spec's
   double-payment guard assumed "re-running seal" resumes; keying on the
   recorded invocation makes that true without new surface, and the
   near-miss hard error converts every fuzzy case into a re-run of the
   *recorded* command rather than a guess (D24: ambiguity about a
   permanent, paid outcome is an error, not a default).
2. **Flag identity prevents silent meaning drift.** Honoring a resumed
   `--title "new"` is impossible (the manifest is built and possibly
   anchored; resume never re-signs — S11), and ignoring it silently
   would ship a seal that contradicts the visible command line. Error +
   recorded-command-line is both safe and self-repairing.
3. **Lexical (not filesystem) path identity** keeps detection total: it
   works when sources are deleted (a legitimate post-receipt resume
   state) and never dereferences anything S11 promised not to read.

## Consequences — task integration

- **U9** (tasks/U.md:107-118): record schema gains the invocation
  identity block (§1); versioned-schema round-trip fixtures extend.
- **S11/S10**: no logic change; D45 names the CLI-side key their state
  machine is looked up by.
- **U17**: implements the §2 table; the two new hard-error classes
  (flag-mismatch, overlap-not-exact) join U2's taxonomy as distinct
  resume-safety usage errors, tested per U17 Accept.
- **U19**: hint format per §5.
- **U14/D36**: consent hook re-fires per §4; D36 plugs in the
  cost-delta rule without touching this record.
- **Q (docs/help)**: `seal` help documents implicit resume and the
  exact-match rule (U17 Notes requires it).

## Residual risk / discovered work

- **Alias-path blindness (accepted):** lexical identity cannot see that
  `./a` and `/same/dir/a` (or a symlinked spelling) are one file; such a
  re-run lands in the *disjoint* row and starts a fresh seal. The stderr
  incomplete-works notice is the net. Filesystem resolution was rejected
  because it requires source files to exist, which resume must not.
- **The flag-mismatch trap needs an exit (discovered work).** A user
  with a *pre-pay* incomplete work who genuinely wants different flags
  (e.g. add `--split`) currently has no supported way to discard the
  staged work — abandonment exists only as S11's safety outcome
  (tasks/U.md:215). Nothing is spent pre-pay, and a fresh seal draws a
  new `seal_id` + fresh nonces by construction (S11), so a **user-
  initiated abandon** is safe and needed for the §2 error text to offer
  a real way forward. Proposed as new U-domain work (CLI verb or flag —
  surface addition to be decided deliberately, not smuggled in here);
  until it lands, the error message can only point at `list` and the
  recorded command.
- Two works sealing the same paths *on different networks* are distinct
  keys by design (network is in the identity); the notice row keeps the
  user informed. Deliberate: a devnet rehearsal must never capture a
  mainnet re-run.
