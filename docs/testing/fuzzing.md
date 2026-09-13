# Fuzzing: targets, corpora, cadence, triage

Normative for everything under `fuzz/` and `testdata/fuzz-seeds/`. Owner
tasks: **F17** (the codec targets), **Q9** (this infrastructure), **R10**
(the `verify_bundle` target), **A23** (DER/`.ots` targets, M2).

MVP-SPEC.md line 153 makes parser hardening and CBOR fuzzing an M0 exit
criterion; line 169 lists CBOR fuzzing under Verification; line 187 names
hostile bundles as a risk. This document is how that obligation is
discharged and, more importantly, how it stays discharged.

## 1. The targets

| target | owner | input is | drives | asserts |
| --- | --- | --- | --- | --- |
| `manifest_decode` | F17 | a manifest envelope | `Manifest::decode` (layers 2+3) | no panic · F11 allocation budget |
| `bundle_decode` | F17 | a `.sealproof` | `SealProof::decode` (layers 1–3) | no panic · F11 allocation budget |
| `codec_round_trip` | F17 | either of the above | `codec_fuzz::round_trip` | decode ⇒ re-encode is byte-identical and re-decodes equal |
| `verify_bundle` | R10 | **entropy** (see §3) | `verify_bundle` via R10's mutators | no panic anywhere in the evidence pipeline |

Three of the four take the **document itself** as the fuzz input. R10's
takes entropy, because its job is to get *past* the decoder — random bytes
essentially never do — so it interprets its input as `(seed selector,
mutation selector, parameters)` and mutates a real bundle. The asymmetry is
deliberate and is written down at both ends
(`antseal_core::test_util::codec_fuzz` module docs).

Every target's logic lives in `antseal-core` behind the `test-util` feature,
not in the fuzz crate. A target that carries its own logic is exercised only
when someone runs the fuzzer, so it rots between runs and a crash it finds
may not reproduce under the test suite. Here the two halves share one code
path: `crates/antseal-core/tests/codec_fuzz.rs` and
`crates/antseal-core/tests/verify_fuzz.rs` run the identical functions on
**every CI build**, and a libFuzzer crash reproduces as a plain unit test.

### What is asserted per input

- **No panic.** The assertion is that the target returns. There is
  deliberately no `catch_unwind` anywhere — swallowing the panic would
  defeat the property.
- **No allocation beyond the F11 budget.** `fuzz/src/lib.rs` installs a
  counting global allocator and asserts, for every input:
  `peak_single ≤ 1 · len(input) + 4 KiB` and
  `total ≤ 1024 · len(input) + 4 KiB`. This generalizes
  `crates/antseal-core/tests/parser_caps_alloc.rs`, which asserts the same
  thing on hand-picked hostile inputs, to every input libFuzzer can
  invent — and **the generalization immediately corrected the claim**; see
  below. (The peak factor was 256 between the finding and F30's fix.)
- **…except for a *count-bounded* container, which has its own derived bound**
  (added 2026-08-07 by
  [D102](../decisions/D102-parser-structural-allocation-cost.md), task A100).
  The peak bound above states D10 §4's clamp rule, which is a rule about
  **length headers**: *"every element of a definite-length array costs at
  least one wire byte"*. A container bounded instead by a **count limit** has
  no claimed length to clamp against, and one input byte buys
  `size_of::<Element>()` reserved bytes rather than one — by arithmetic, on
  legal input, with no parser change able to alter it. The two anchor targets
  therefore assert

  ```
  peak_single ≤ max( 1 · len(input) + 4 KiB , structural(len) )
  ```

  where `structural` is derived in `antseal-core` from the limit constants and
  `size_of` (`ots_structural_alloc_bytes`, `tsa_structural_alloc_bytes`) and is
  a **function of the input**, not a constant — every frame and every
  attestation costs at least one wire byte, so an artifact that never goes deep
  gets almost none of it. `MAX_CLAMPED_ELEMENT_BYTES` is **unchanged at 1** and
  every site the clamp rule was ever about keeps the sharp bound; what changed
  is that it stopped being applied to a site it was never about. The four
  remaining targets are untouched.

  The honest cost, stated rather than buried: at an 80-byte `.ots` input the
  window a hostile allocation can hide in widens from 4 176 B to 11 264 B, and
  it is widest — 53 248 B — for inputs at or above `MAX_OTS_DEPTH` bytes.
  Closing that further needs **per-site attribution**, which a
  `#[global_allocator]` cannot give; it is registered, not done. What the
  change buys instead is three places the guard is now **strictly stronger**:
  a `const` assertion that fails `cargo build` if a raised count limit
  outgrows `MAX_OTS_BYTES`; an input-derived exemption, so a *new* allocation
  site in either parser is red on its first input; and an equality assertion
  (`crates/antseal-core/tests/anchor_ots_alloc.rs`) on a cost that was green
  and silent before.
- **No hang.** `-timeout=25` — a single input taking longer is a finding.
  libFuzzer's default (1200 s) would let a quadratic parser look merely
  slow.

### The 256× that was not a fudge factor (finding 2026-07-28, fixed by F30)

`parser_caps_alloc.rs` stated decision D10 §4's consequence as

> an attacker can never make the parser allocate more than the attacker's
> own bytes — modulo a small constant … which is what `SLACK` covers

and that was **not true in general**. The clamp was
`Vec::with_capacity(min(claimed, remaining_input))` where the left side
counts *elements* and the right side counts *bytes*, so the real bound was
`remaining_input × size_of::<Element>()`. That test passed only because both
of its inputs were under 32 bytes, so the multiplier vanished inside a 4 KiB
`SLACK`.

The first fuzz run over the committed corpus surfaced it in seconds: a
**152-byte** manifest whose `signatures` map head claims 59 638 entries
drove a **4 704-byte** single allocation (147 × `(SigAlg, Vec<u8>)`, 32 B
each). Scaled to the cap, a 16 MiB manifest (`MAX_MANIFEST_BYTES`) could
drive a ~512 MiB reservation *before a single map entry was read*, and the
entry that followed then failed — a 32× memory amplification that mattered
most in the WASM verifier page, where the ceiling is a browser tab.

Nothing here was a verdict change: capacity is a hint, and no input's
accept/reject outcome moved. That is exactly why it stood.

**Resolved by task F30 (M0 wave 7).** `clamped_capacity` is generic in the
element type and divides the remaining bytes by its width, so the
reservation is bounded in *bytes* by the remaining input:

```
capacity × size_of::<T>() ≤ remaining ≤ input.len()
```

Measured before/after on the counting allocator, at the two worst sites
(`crates/antseal-core/tests/parser_caps_alloc.rs`,
`the_reservation_never_exceeds_the_input_that_drove_it` — run red against
the old clamp before it was run green):

| site | element | input | peak before | peak after |
| --- | --- | --- | --- | --- |
| `signatures` (uncapped map) | `(SigAlg, Vec<u8>)` 32 B | 65 549 B | 2 097 152 B (**32.0×**) | 65 536 B (**1.00×**) |
| `files` (capped at 16 384) | `FileEntry` 192 B | 20 005 B | 3 145 728 B (**157.2×**) | 19 968 B (**1.00×**) |

No cap constant changed value and no error code moved: F30 is an allocation
fix, not a limit change. `MAX_CLAMPED_ELEMENT_BYTES` is therefore now **1**
and the fuzz assertion states the strong claim literally. `TOTAL_FACTOR` was
decoupled from it (it was `4 ×`) because the total bound is about payload
copies and re-encoding, not about the clamp, and F30 produced no evidence
about that side.

## 2. Running it

`scripts/fuzz.sh` is the only place run commands are written down; CI calls
it and so should you.

```
scripts/fuzz.sh lint                  # fmt + clippy the fuzz crate (stable toolchain)
scripts/fuzz.sh build                 # build the instrumented binaries
scripts/fuzz.sh smoke [seconds]       # per-PR budget per target (default 90 s)
scripts/fuzz.sh long  [seconds]       # interactive long budget (default 900 s;
                                      #   the SCHEDULED lane passes 600 — D61 §3)
scripts/fuzz.sh runs  <n> [target...] # a fixed ITERATION count — deterministic
scripts/fuzz.sh selftest              # prove a crash becomes an artifact
scripts/fuzz.sh classify-failure      # D61 §7: crash vs infrastructure red
scripts/fuzz.sh cmin                  # coverage-minimize the working corpus
scripts/fuzz.sh repro <target> <file> # re-run one crashing input
```

**Toolchain.** cargo-fuzz needs nightly (`-Z sanitizer`, libFuzzer
instrumentation); the workspace pins stable 1.92.0 and must not move for
this. The nightly pin therefore lives in `fuzz/rust-toolchain.toml`, and
`scripts/fuzz.sh` runs cargo with `fuzz/` as its working directory so rustup
resolves it there and nowhere else — `fuzz/` is not an ancestor of
`crates/`, so no ordinary build can pick it up, and **no version literal
appears in a workflow or a script**. It is a dated pin rather than a
floating `nightly` because docs/dependency-policy.md §5 puts
verdict-bearing dev-tools under the same exact-pin rule as dependencies: a
floating nightly would make "the fuzzer found nothing" a statement about
whatever compiler CI downloaded that morning. `ANTSEAL_FUZZ_TOOLCHAIN=nightly`
overrides it locally; CI never sets it.

`cargo-fuzz` itself is exact-pinned (`=0.13.2`, dependency-policy §5). The
script **checks** the version and refuses to run on a different one; it never
installs, because installing a tool behind the operator's back is how an
unreviewed version ends up producing the verdict.

## 3. Corpora

```
testdata/fuzz-seeds/            committed, generated, drift-checked
  MANIFEST.json                 per-seed id/len/sha256 + per-corpus totals
  manifest_decode/*.bin         manifest envelopes
  bundle_decode/*.bin           .sealproof documents
  verify_bundle/*.bin           ENTROPY strings (see below)
fuzz/corpus/<target>/           working corpus — GITIGNORED, libFuzzer writes here
fuzz/artifacts/<target>/        crash reproducers — GITIGNORED
```

The committed seeds are **generated, never hand-written**: the generator is
`antseal_core::test_util::codec_fuzz::all_corpora`, the emitter is

```
cargo test -p antseal-core --features test-util --test codec_fuzz \
    -- --ignored emit_fuzz_seed_corpora
```

and `crates/antseal-core/tests/codec_fuzz.rs` fails if the committed tree and
the generator disagree by so much as a byte, an id, or a stray file. Seeds
come from R6's fixture catalogue (every M0 shape) and F15's committed tamper
fixtures (`testdata/tamper/format/`) — near-misses are the highest-value
seeds a decoder fuzzer can start from, since one mutation reaches a *second*
rejection inside a pass that has already found one.

Two consequences worth stating so they are not rediscovered:

- **`codec_round_trip` has no corpus of its own.** Its input space is the
  union of the two decode corpora, so `scripts/fuzz.sh` passes both seed
  directories rather than committing the same bytes twice.
- **`verify_bundle`'s corpus is entropy, not documents.** R10's target reads
  byte 0 as a seed selector and byte 1 as a mutation selector, so committing
  *bundle bytes* there — which `fuzz/README.md` originally suggested — would
  produce a corpus that is neither a bundle nor a meaningful entropy string,
  and libFuzzer's coverage feedback would be about the indirection rather
  than about the pipeline. The committed entries are
  `[seed + 1, mutation kind, params…]`; the `--identity` ones are
  `[seed + 1, 0]`, i.e. "this real bundle, unmutated", which is the highest
  value entry there is.

### Seeds are derived artifacts, not frozen ones

Q6's `FROZEN.sha256` covers `testdata/vectors/` only. A deliberate format
change **re-blesses** the seeds as a matter of course — that is not a freeze
violation. It is still a reviewed event: a byte change here means a fixture,
a shape, or the wire format moved, and the reviewer should be able to say
which.

### Minimization cadence

Two different operations, often confused:

1. **Content dedup** — done by the generator, on every regeneration. No two
   committed seeds share bytes. This is the whole of the "minimization" a
   *deterministic* generator can honestly promise.
2. **Coverage minimization** (`scripts/fuzz.sh cmin`, i.e. libFuzzer
   `-merge=1`) — depends on an instrumented binary and therefore on the
   toolchain, the target and the day. It runs against the **working**
   corpus, not the committed one.

Cadence: run `cmin` on the working corpus **monthly**, and after any run that
grew it by more than ~20%. Its output is *reviewed*, never folded back
blind — if `cmin` shows a committed seed is redundant, the fix is to remove
it from the generator (a source change, reviewed) and regenerate, not to
delete a file the drift check will immediately restore.

Baseline measurement (2026-07-28, after 4 × 100 000 iterations from the
committed seeds):

| | files | size |
| --- | --- | --- |
| working corpus before `cmin` | 827 | 4.3 MB |
| after `cmin` | 557 | 3.0 MB |

Per target afterwards: `manifest_decode` 155, `bundle_decode` 252,
`verify_bundle` 150, `codec_round_trip` **0**. That zero is correct, not a
failure: the round-trip target returns `Corpus::Reject` for inputs that
decode as neither format, so it only ever keeps documents that reached the
law — and the committed seeds already cover those, so 100 000 iterations
added no new coverage of its own. Its useful corpus *is* the two decode seed
directories, which is exactly why it has none of its own.

The nightly lane caches its working corpus between runs (see §5), so
coverage found overnight is not thrown away, while the committed tree stays
deterministic.

## 4. Crash triage

**A crash is release-blocking.** No exceptions at M0: these are the parsers
that stand between a user and an adversary's `.sealproof`.

1. **Reproduce.** `scripts/fuzz.sh repro <target> fuzz/artifacts/<target>/<file>`.
   Confirm it is not the self-test tripwire (§6) — those messages say so
   explicitly.
2. **Move it into the ordinary suite.** The fuzz engine is library code, so
   the reproducer is a unit test, not a fuzzing chore: add the bytes as a
   case in `crates/antseal-core/tests/codec_fuzz.rs` (or `verify_fuzz.rs`)
   and watch it fail on the stable toolchain, with no sanitizer and no
   nightly. If it does not reproduce there, the finding is in the harness,
   not the parser — say so in the fix.
3. **Classify.**
   - A **panic** or an allocation-budget violation is a parser bug. Fix the
     parser.
   - A **round-trip violation** is a *format* bug — the decoder and encoder
     disagree about what a document means — and is therefore also a
     format-freeze event (Q14/Q27). Escalate rather than patching quietly.

   > **This step is not amended by D102, and the exception it granted is not
   > a precedent for softening it.** A100 was an allocation-budget violation
   > that reproduced on the stable toolchain, and it was still a **harness**
   > finding rather than a parser bug — a route step 2 did not anticipate.
   > The reasoning, in full at D102 §3.3: step 3 presupposes that the budget
   > states a property the parser is supposed to have, and
   > `MAX_CLAMPED_ELEMENT_BYTES`' own doc comment says which property — *"one
   > input byte buys at most one reserved byte."* For a count-bounded work
   > stack one input byte buys forty, and **no reachable parser change makes
   > it one** (§4.3 measured the only candidate). The work stack was never a
   > member of the class that constant is about; applying it there was a
   > default argument reaching an unchecked call site. **Anything that is a
   > member of the class is still a parser bug, and step 3 still says so.**
   > The test of whether a future claim of this kind is honest is D102's own:
   > the fix must leave the guard **strictly stronger somewhere**, not merely
   > weaker here.
4. **Retain the input.** Either as a committed seed (add it to the generator
   so it is regenerated, never dropped in by hand) or, when it maps onto a
   distinct rejection class, as a row in `testdata/tamper/` under the Q7
   procedure. Every fixed crash leaves a permanent regression case behind.
5. **Record it.** A crash that reached `main` gets a line in the task's
   entry and, if it changed a frozen format, a decision record.

## 5. CI lanes

| lane | trigger | budget | required |
| --- | --- | --- | --- |
| `fuzz-smoke` (`.github/workflows/ci.yml`) | every PR + push to main | self-test, then 90 s per target | intended-required — see the note below |
| `fuzz-nightly` (`.github/workflows/fuzz-nightly.yml`) | scheduled **twice weekly** (Mon/Thu 03:41 UTC) + manual | 600 s per target, corpus persisted | no (not a PR context) |
| `fuzz-budget` (a step of ci.yml's `traceability` job) | every PR + push to main | reads four committed literals; no network, and cargo-free by that job's asserted property (D124/Q182) rather than by this cell | no new context — folded into an existing job |

**Corrected 2026-08-02 (D61).** The "required" column said `fuzz-smoke` was
a *branch-protection context*. **No context is enforced on this repository**
— branch protection 403s on a private repo on GitHub Free (D52 §E1, verified
twice; `docs/ci-verification.md`), so `fuzz-smoke` is required by convention
and by the local gate, not by any enforcement GitHub is applying. It is in
the 19-context payload that would be applied *if* protection ever becomes
available. **[20 since D168 §2 R1 (2026-09-13); `fuzz-smoke` is still one of
them.]** Stating it as enforced overstates what stops a red lane merging.

`fuzz-smoke` runs `scripts/fuzz.sh selftest` **before** it fuzzes, every
run: the tripwire (§6) makes each target crash on its first input, and the
lane fails if the crash is not caught or no artifact is written. Only then
is a clean fuzz run treated as evidence. This is the same discipline
`secret-guard` (planted fakes) and `wasm-bitmatch` (injected divergence)
already apply — green must mean something.

Both lanes upload `fuzz/artifacts/` on failure.

## 6. The self-test tripwire

`ANTSEAL_FUZZ_SELFTEST=<target>` makes exactly that target panic on its first
input (`fuzz/src/lib.rs::selftest_tripwire`). It is **permanent**, not a
temporary edit, and that is a deliberate departure from F17's accept text
("a temporarily injected panic … then removed"): a demonstration that is
deleted afterwards proves the pipeline worked once, on someone's laptop, at
a commit that no longer exists. As a permanent, env-gated tripwire it is
re-proven on every CI run and by any contributor in one command.

It exists only in the fuzz crate. Nothing in `antseal-core` reads an
environment variable, and nothing that ships can panic on demand.

## 7. Long-run venue (decision D61 — RESOLVED 2026-08-02)

**Resolved: scheduled CI (`fuzz-nightly.yml`), twice weekly, with a named
minutes ceiling — see `docs/decisions/D61-fuzz-venue.md`.** Two corrections
to what this section said before that ruling:

- it called D61 **"due M3 — deliberately not resolved here"**. D61 is and
  was **due M2** (`TODO.md`, Due-M2 register block), which made it a
  milestone blocker, not a deferral;
- it said OSS-Fuzz is "gated on the same publication decisions as the
  release lane". Public is **necessary but not sufficient**: OSS-Fuzz's
  stated criterion is a significant user base or criticality to global IT
  infrastructure, so flipping the repo public (Q65) does **not** make
  antseal eligible. D61 rules OSS-Fuzz not applicable on that ground.

The portability properties below are still true and still worth keeping —
they are what would make a venue change cheap, and they cost nothing:

- targets are ordinary `libfuzzer-sys` binaries with no antseal-specific
  driver, which is exactly what an OSS-Fuzz `build.sh` expects to compile;
- seed corpora are plain files under a stable path, so an OSS-Fuzz build
  copies `testdata/fuzz-seeds/<target>/` into `$OUT/<target>_seed_corpus.zip`
  with no generator involvement;
- run parameters (budget, timeout, RSS limit) live in `scripts/fuzz.sh` as
  flags, not baked into the targets, so a venue that supplies its own is
  unaffected;
- **nothing in a target reads a corpus from disk itself** — the corpus is
  libFuzzer's, which is the property that makes the targets portable to a
  venue with its own corpus management.

### When this is re-read, and by whom

D61 is **resolved**, not deferred, so no wave inherits it as an open
decision. The OSS-Fuzz arm is closed *with a condition attached*, and the
condition has two halves — stating only the first is the error this section
made before, and the one with an operational cost:

> **D61 is re-read when, and only when, BOTH hold: (a)** `aed900/antseal` is
> public — the Q65-gated flip; **and (b)** the project can point to use by
> parties other than its maintainer, sufficient to argue OSS-Fuzz's own
> *"significant user base and/or critical to the global IT infrastructure"*
> criterion.

**(a) alone does not reopen the OSS-Fuzz arm.** It reopens only the *budget*
half — standard GitHub-hosted runners are free on public repositories, so
the cadence of §5 and the 700 min/month ceiling become re-openable on their
own merits at that moment, while eligibility does not move at all. Until
both hold, OSS-Fuzz is **not applicable** rather than **pending**.

The trigger has a **named owner** so it is a mechanism and not a hope: it is
an Accept row of **Q65**, which fires the re-read in the same wave it
resolves to *public*, and the re-read records which of (a)/(b) hold. Two
costs to weigh **then** rather than assume away now: the required
engineering contact must be an established committer's address *and* a
Google account — the only email in this tree is the canonical noreply, so
this is a new personal disclosure — and OSS-Fuzz publishes issues on a
90-day disclosure clock.

## 8. Cross-references

- `fuzz/README.md` — target registry, ownership, and what each target does
- `antseal_core::test_util::codec_fuzz` — F17's engine and the round-trip law
- `antseal_core::test_util::bundle_mutators` — R10's mutation engine
- `docs/decisions/D10-parser-caps.md` §4 — the clamp rule the budget asserts
- `docs/decisions/D102-parser-structural-allocation-cost.md` — the class the
  clamp rule was **not** about, and the derived bound the two anchor targets
  assert instead (D58 §10.3 rule 6)
- `crates/antseal-core/tests/anchor_ots_alloc.rs` — rule 6 clause (b): the same
  costs at **equality**, on the pinned stable toolchain
- `docs/testing/error-code-contract.md` — the codes a rejection reports
- `testdata/fuzz-seeds/MANIFEST.json` — the committed corpora, machine-readable
