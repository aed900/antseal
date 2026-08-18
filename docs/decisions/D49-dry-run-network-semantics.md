# D49 — `--dry-run` network semantics: real `quote_batch` vs offline estimate

- **Status: RESOLVED — real `quote_batch`, confirming the register's lean
  and S12's Accept, with four sharpenings the record-as-proposed lacked:
  (1) dry-run is the real pipeline truncated after quoting — a prefix,
  not a parallel mode; (2) a discovered conflict between S12's
  journal-before-backend invariant and U16's zero-vault-mutation rule is
  resolved by scoping the invariant to the paid path; (3) dry-run runs
  the S8 preflight and exits with the real insufficient-ANT/-gas codes,
  making it a scriptable preflight gate; (4) the quoted cost is labeled
  indicative — a fresh-nonce argument proves a dry-run leaks nothing
  linkable to a later real seal, but the same argument means the real
  seal re-quotes different addresses from different peers.**
- **Date: 2026-08-01** (planning; U16 implements over S12)
- **Owning tasks:** U16 (tasks/U.md:194-204), S12 (pipeline,
  tasks/S.md:153-165), S16 (invariant matrix), U14/S8 (report +
  preflight), U2 (codes). Cross-refs: D45 §5 (dry-run on a resumable
  work), D46 (validation runs identically), D24/S13 (guards fire in
  dry-run).

## Context

Register entry D49 / U open decision 11 (tasks/U.md:398): "call
`quote_batch` for a true cost (proposed) vs fully offline estimate".
S12's Accept already commits "`--dry-run` executes through quoting with
zero anchor submission, zero payment, zero upload" (tasks/S.md:162);
U16 defines the rest: every cheap failable local step, full consent
report + warnings, no consent prompt, **zero vault mutation** (vault
byte-hashed before/after in test; MockBackend records only
`quote_batch`) (tasks/U.md:199-203). The register asks whether that
proposal survives adversarial reading: what does dry-run mean offline
or pre-init, does a quote leak anything, does it cost anything?

## Interrogating the lean

**Pre-init / locked vault:** dry-run cannot be a vault-less linter even
in principle — unit encryption keys, salts, and the signing keys all
derive from `W` (MVP-SPEC.md line 90), and the manifest is built and
signed before addresses exist. So `--dry-run` with no vault fails with
the ordinary no-vault/auth error, exactly like `seal`. No special mode.

**Does a quote cost anything?** No. Quoting is collection of signed
per-peer price quotes (`prepare_chunk_payment`,
`docs/research/S1-ant-core-api-survey.md` §3); no EVM transaction, no
chain write, no payment approval. The only spend is network round
trips.

**Does a quote leak anything?** The quoted peers learn (address, size)
pairs and the requester's transport identity — the same exposure class
the spec already accepts for real seals (MVP-SPEC.md line 91's
traffic-correlation note). The sharper question is linkage to a *later
real seal*, and the answer is a clean no, by construction: dry-run
performs zero vault mutation (U16), so the nonces drawn for its
in-memory encryption are discarded; the later real seal draws a fresh
`seal_id` and fresh nonces (the journal/resume rules never reuse nonce
tables — MVP-SPEC.md line 145), producing different ciphertexts and
therefore different BLAKE3 addresses. A dry-run's quoted address set
shares nothing with any future upload. (Corollary: a dry-run address
can never collide with already-stored data, so the zero-cost
`AlreadyStored` path is unreachable from fresh randomized ciphertext.)

**Why not an offline estimate?** There is no local price oracle to be
right with: prices are per-peer market quotes (median-of-quotes × 3
payment model, S1 §3), vary by peer set and time, and antseal has no
pinned tariff to compute from. An invented number rendered inside a
consent-shaped report is worse than an error — it teaches users to
trust a figure with no source. The one thing an offline mode would
genuinely provide (a no-network lint of arguments and canonicalization)
is not worth a second semantics; and the S12 Accept text has already
bound the meaning to quoting.

The lean stands. What was missing is the following precision.

## Decision

1. **Prefix principle.** `--dry-run` executes the real S12 pipeline —
   canonicalize → encrypt units (in memory) → build + sign manifest →
   encrypt manifest → compute all addresses → `quote_batch` over the
   full blob set (encrypted manifest included) → run the S8 preflight →
   render the full U14 consent report + all U15 warnings — then stops.
   No consent prompt, no anchor submission, no `pay`, no
   `finalize_batch`, no journal write, no work record. It is the same
   code path truncated, never a reimplementation: every plan-validation
   error (D24's flag conflict, D46's directory/duplicate rules, S13's
   `--no-anchor`×`arbitrum-one` rejection) fires identically, which is
   the flag's rehearsal value.
2. **Journal carve-out (discovered conflict, resolved).** S12's Accept
   "no backend call precedes journaling of staged bytes"
   (tasks/S.md:160) and U16's "zero vault mutation" (tasks/U.md:201)
   contradict each other for a dry-run that calls `quote_batch`. Ruling:
   the journal-before-backend invariant exists to make staged bytes
   durable before anything *paid or anchored* can happen; a dry-run
   reaches neither, so it runs with journaling disabled (in-memory
   staging) and the invariant is **scoped to the paid path**. S12/S16
   must assert the dry-run variant separately: call log contains
   exactly one backend call class (`quote_batch`), and the vault hash
   is unchanged — not exempt the mode from assertion.
3. **Preflight semantics (script-usable).** Dry-run displays balances
   beside the quote (full U14 report) and runs the S8 comparison. On
   shortfall it still prints the complete report, then exits with the
   *same* distinct insufficient-ANT-token / insufficient-ETH-gas codes
   a real seal would use (tasks/U.md:26-29) — so `seal --dry-run` is
   the documented CI gate for "could this machine seal this work right
   now". Quote or balance-query failure is the ordinary network-class
   error (no degraded half-report; one meaning per invocation).
   Success: exit 0, report on stdout (plain) or as the single `--json`
   result document (files, byte totals, per-unit table, quote, both
   balances, warnings flagged; human copy on stderr per U3).
4. **Indicative-cost labeling.** Because the real seal re-encrypts
   under fresh nonces, its quote comes from *different addresses,
   different peer sets, and a later time*. The report labels the figure
   as an indicative quote and states that the real seal re-quotes and
   re-consents. This is not a weakness of the real-quote option — an
   offline estimate would be strictly less accurate — but claiming
   "true cost" (the register's phrase) would overstate; "true *pricing
   mechanism*, indicative figure" is the honest contract.
5. **Composition.** `--dry-run --yes` / `--force-degraded` /
   `--no-anchor`: still zero side effects (U16 Accept, ratified) — the
   flags participate in validation and report content only. On an
   invocation exact-matching a resumable work (D45): pre-pay, dry-run
   prints the resume plan *and* the fresh quote (what re-consent would
   show); post-receipt, it prints the finalize-only plan and performs
   no quote (nothing left to price). Zero mutation in both.

## Consequences — task integration

- **U16**: implements 1-5; Accept additions: shortfall exit-code test;
  indicative-cost wording snapshot; resume-plan dry-run cases (with
  D45).
- **S12**: rustdoc scopes the ordering invariant per Decision 2; the
  fault-barrier list gains "dry-run truncation point" after quote.
- **S16**: matrix gains the dry-run row (only-quote + vault-hash-
  unchanged), closing the loophole where the mode escapes the
  invariant harness entirely.
- **U14/S8**: report renderer and preflight callable without a consent
  continuation (pure function over quote+balances — S8 already exposes
  structured results, tasks/S.md:110).
- **U2**: no new codes — dry-run reuses insufficient-*/network/no-vault
  classes. (Deliberate: a "dry-run failed" umbrella code would erase
  the preflight signal.)
- **U31**: help text documents the semantics (U16 Notes requires it)
  including the indicative label.

## Residual risk

- A dry-run is a real network fingerprint (peer contact, quoted sizes)
  even though unlinkable to later uploads; users rehearsing highly
  sensitive works on the public network should know a dry-run is
  visible activity. One threat-model sentence (Q-docs).
- Quote variance between dry-run and real seal can surprise (price
  moved, peers changed). Mitigated by labeling (Decision 4) and by the
  fact that the binding consent always re-renders at the real seal —
  the dry-run figure authorizes nothing.
- The in-memory staging of Decision 2 doubles peak memory relative to a
  journaled seal for large works (ciphertexts held rather than flushed)
  — bounded by the same work sizes M1 already handles; note for G/S
  perf budgets if works grow.

## Addendum — 2026-08-18 (D146, U79)

**§3's first sentence was never implemented, and is now.** From
2026-08-01 to this addendum, a dry run that failed the S8 preflight
returned the typed error and printed **nothing**: `seal_run.rs`'s `DryRun`
arm ran `report.preflight()?` and the `?` preempted the render, which
happens only from the `Ok` value. Measured on the wire (D146 §1.1): the
same wallet state produced 1 064 bytes of report on the real-seal path and
0 bytes on the dry-run path. D146 §2 R1 implements the emit.

**Three clauses §3 lacked, ruled by D146 and binding here:**

1. **The emit is conditional on the preflight refusing.** On the success
   path the caller renders the same screen (`commands.rs:423-425`), so an
   unconditional emit — a literal mirror of the gate at
   `seal_consent.rs:441` — prints it twice. §3's "still prints the complete
   report" describes the *shortfall* path only.
2. **Channel and mode.** The complete report goes to the human channel
   (stdout in plain mode, stderr under `--json`, D51 invariant 2), and under
   `--json` stdout carries **exactly one document: the error envelope**.
   **There is no `result` document on the shortfall path** — §3's
   "single `--json` result document" clause describes success only, and a
   script must gate on the exit code and on `error.class`, not on `result`.
   The error names required and available for the **first** short asset
   only (ANT before gas, `backend.rs:89-100`); the report names both.
3. **The D69 third arm is refused here.** D69 §3 R1 (2026-08-12, after this
   record resolved) made `ok` mean "a result document is present" rather
   than "the exit code is 0", so a dry-run shortfall *could* now emit
   `ok:true` + `result` at exit 20/21. It does not: the real seal reports
   the same condition as `ok:false` + `error`, and D49 §1's prefix
   principle makes dry-run the real pipeline truncated, not a mode with its
   own envelope shape. A funding shortfall is not a verdict.

**§3's "documented CI gate" claim stands, and is now true rather than
aspirational.** The gate is: exit 0 = fundable; 20 = acquire ANT; 21 =
bridge ETH; the screen on the human channel explains it to a person.
