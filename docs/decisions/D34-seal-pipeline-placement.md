# D34 — Seal-pipeline placement: `antseal-cli` gains a library target; the orchestration layer (seal, resume, restore — and M3's reveal flow) is `antseal_cli` lib code over injected backend/gate/journal/consent interfaces

- **Status: RESOLVED — option (a), the `antseal-cli` library target. The
  register's lean (first-listed in `tasks/S.md:268` and the D34 row) is
  confirmed, but on grounds the register never stated — it recorded no
  rationale at all. The adversarial pass found the real discriminators:
  (d) pipeline-in-`antseal-core` is structurally impossible without
  relocating the churn boundary into the WASM crate (the pipeline's
  argument types — `CostQuote`, `PaymentReceipt` with upstream-versioned
  `proof_bytes` — are churn surface, and core may never depend on net);
  (c) pipeline-in-`antseal-net` violates the storage crate's spec-written
  charter (anchor/consent/journal-shaped surface in the crate whose task
  text explicitly excludes anchor concerns); and (b) a dedicated
  orchestration crate would be the workspace's first *product* member
  outside the spec's Architecture tree — cargo's publishability chain
  means `antseal-cli` could never publish unless that crate published
  first, minting a permanent public API + name + license surface while
  D72 (crates.io publish scope) is still open, for exactly zero
  additional consumers. Two forced sub-findings are recorded: the
  `MockBackend` must be consumable across a crate boundary under EVERY
  option (an S3 note, not a D34 artifact), and M3's reveal-flow API
  (R16) is forced out of `antseal-core` by the same dependency
  direction — so this record names the orchestration home once, for
  both milestones.**
- **Date: 2026-08-01** (M1 Storage planning wave)
- **Owner: S12 (pipeline), S10 (journal state machine); U1/U13 (the
  scaffold and the CLI consumer), S17–S19 (the library-driving E2E)**
- **Blocks: S10, S12 (register "Seal-pipeline crate placement", due M1;
  `tasks/S.md:268` "blocks S10, S12 — M1 start")**
- Companion: D32 (blob = chunk; the plan-validation step S12 hosts),
  D37 (the receipt shape whose churn-coupling kills option d), D52 (the
  E2E venue the harness placement composes with), P16 §5–§7 (graph
  sizes; the runner/harness split).

## Context

S12 must implement the seal pipeline "as library code (placement per
open decision 3; must be drivable without the CLI for M1 E2E)"
(`tasks/S.md:158`), and the M1 milestone requires the E2E to drive
sealing, restore, and verification "**via library APIs** (the `verify`
CLI, bundle builder, and page arrive in M3)" (MVP-SPEC.md line 154).
The spec's Architecture tree (MVP-SPEC.md lines 44–58) assigns the
pipeline to no crate: `antseal-core` is "pure logic, WASM-safe (no I/O,
no tokio)" (line 47), `antseal-net` is "Autonomi storage behind a
batch-first `StorageBackend`; ant-core impl + mock" (line 54),
`antseal-cli` is "binary `antseal` (clap, tokio)" (line 55). So *some*
crate must export the pipeline as a library, and the tree never says
which. The candidates:

- (a) `antseal-cli` gains a `[lib]` target; the binary becomes a thin
  `main.rs` over it;
- (b) a new orchestration crate (workspace member outside the spec tree);
- (c) a module inside `antseal-net`;
- (d) a module inside `antseal-core` (sans-io, generic over the backend).

What the pipeline consumes fixes the shape of the answer. Per S12
(`tasks/S.md:156-158`) it orchestrates: G canonicalization + C
encryption + F manifest build (all `antseal-core`), S4 addresses
(`antseal-core`), `quote_batch`/`pay`/`finalize_batch` (the
`StorageBackend` trait, defined in `antseal-net` per `tasks/S.md:25`),
the anchor gate (A1's interface, `antseal-anchor` side), the consent
hook (U14 implements; S12 needs "consent-hook signature only"), and the
journal (record content owned by S10, substrate owned by U9's vault
store, which is `antseal-cli` code — "layout documented in-crate",
`tasks/U.md:64`, over U5's `~/.antseal/` design).

## Evidence (verified 2026-08-01)

| # | Fact | Citation |
| --- | --- | --- |
| 1 | Live dependency direction: every member's sole internal edge is `antseal-core`; nothing depends on `antseal-cli` | `cargo metadata --no-deps` probe 2026-08-01; `crates/{antseal-net,antseal-anchor,antseal-cli,wasm-bitmatch}/Cargo.toml` |
| 2 | The `StorageBackend` trait and `Blob`/`CostQuote`/`PaymentReceipt`/`Address` are defined **in `antseal-net`**, and CI must prove "only `antseal-net` depends on `ant-core`" | `tasks/S.md:25,28` |
| 3 | `antseal-core`'s normal dep graph is CI-forbidden from containing `tokio`/`hyper`/`reqwest`/`mio`/`socket2` etc. | `scripts/ci-lanes.sh:75-88`; `.github/workflows/ci.yml:199-214` |
| 4 | The `PaymentReceipt` the pipeline journals carries upstream-versioned opaque `proof_bytes` + `peer_quotes` preimages — churn surface by construction | D37 Decision 4 (`docs/decisions/D37-multi-tx-payment.md`) |
| 5 | `antseal-net`'s charter explicitly excludes anchor concerns: "anchor network I/O (OTS/TSA/Arbitrum-receipt HTTP) is explicitly out of scope for this crate" | `tasks/S.md:25`; MVP-SPEC.md line 60 |
| 6 | The vault record store (journal substrate, `W`, receipts, costs) is U-domain code living in the CLI crate | `tasks/U.md:107-118` (U9), `tasks/U.md:62-64` (U5 "layout documented in-crate") |
| 7 | The only extra-tree workspace member is explicitly "NOT A PRODUCT CRATE … never published (`publish = false`), never depended on by any product crate, and deliberately NOT named `antseal-*`" | `crates/wasm-bitmatch/Cargo.toml:1-15` |
| 8 | P16's recommended devnet launcher crate is framed in the same class: "`publish = false`, not `antseal-*`, precedent: `crates/wasm-bitmatch`" | `docs/research/P16-devnet-feasibility.md:251-254` |
| 9 | The crates.io reservation family is closed at five names: `antseal`, `antseal-core`, `antseal-anchor`, `antseal-net`, `antseal-cli` | `scripts/reserve-crates.sh:7-8,28` |
| 10 | crates.io publish scope is an OPEN M4 decision (D72) | `TODO.md:558` |
| 11 | Consuming `ant-core` at all grows the lock by ~570 packages (652 resolved for the base graph); any `StorageBackend`-consuming crate compiles it transitively once `antseal-net` hosts the impl | `docs/research/P16-devnet-feasibility.md:192-203` |
| 12 | S-domain tasks already span crates: S4 is titled "…via `self_encryption` inside `antseal-core`" | `tasks/S.md:46` |
| 13 | M3's reveal flow (R16) is a **library** API with `MockBackend` tests and journal/staged-bytes + `W` inputs — "this task ships no CLI surface", "no CLI involvement" | `tasks/R.md:189-200` |
| 14 | S17's accept requires "Uses only library APIs — grep proves no M3 CLI/bundle-builder invocation" | `tasks/S.md:223` |
| 15 | The CLI crate today is a stub binary, "a thin shell over antseal-core" | `crates/antseal-cli/src/main.rs:1-9` |

## The adversarial pass — each option pushed to its strongest form

### (d) Module in `antseal-core` — structurally dead

The steelman: a sans-io pipeline, generic over an async backend trait,
needs no tokio (`async fn` in traits is edition-2024 stable), and would
put the normative order next to the DAG it implements (MVP-SPEC.md
line 90). It fails on dependency direction, not on async: the pipeline's
signatures are `quote_batch(&[Blob]) -> CostQuote`,
`pay(&CostQuote) -> PaymentReceipt`, `finalize_batch(&PaymentReceipt, …)`
— and those types live in `antseal-net` (row 2), whose whole point is
that upstream churn stays contained there. Core cannot depend on net, so
(d) requires re-homing the trait and its types into core — moving
`PaymentReceipt`, which D37 just shaped around upstream-versioned
`proof_bytes` and `peer_quotes` (row 4), into the WASM-safe,
permanent-format crate whose graph the `core-dep-graph` lane keeps
I/O-free (row 3). That inverts the architecture's one load-bearing
isolation decision to save a crate boundary. Additionally the
`wasm32-core-tests` lane executes core's lib tests on
wasm32-unknown-unknown (`crates/antseal-core/Cargo.toml`, target-split
notes), so pipeline tests would need target-splitting for a pipeline
that can never run in the page. Rejected.

### (c) Module in `antseal-net` — charter violation

The steelman: S10–S12 are S-domain tasks; the S domain's home crate is
`antseal-net`; the crate boundary already carries the CI assertion that
only it touches `ant-core` (row 2), and pipeline-in-net keeps that
assertion true. It fails on the crate's spec-written charter: the tree
comment defines the crate's entire content as "Autonomi storage behind a
batch-first `StorageBackend`; ant-core impl + mock" (MVP-SPEC.md line
54), and S2's own text narrows it further — anchor I/O "is explicitly
out of scope for this crate" (row 5). The pipeline *orchestrates the
anchor gate* and the consent hook and the journal: hosting it in net
puts anchor-shaped, UX-shaped, and vault-shaped interfaces inside the
storage crate. It also couples product orchestration into the compile
unit that every `ant-core` bump rebuilds, diluting the reason the
boundary exists (churn stays contained in one impl file). And it has no
M3 story: the reveal flow (row 13) needs vault inputs (`W`, staged
journal bytes) that net has no business touching. S-domain-ness is task
bookkeeping, not crate placement — S4 already lives in core by its own
title (row 12). Rejected.

### (b) A dedicated orchestration crate — the genuine contender, killed by the product-crate publishability chain

The steelman: a `seal-pipeline` crate depending on core + net + anchor,
exporting `ConsentHook`/`SealJournal` traits, would make "the pipeline
cannot reach into UX" a compiler-enforced fact instead of module
discipline, and gives S16/S17 a clap-free consumer. Precedent exists for
extra members (rows 7–8) and the spec tree has already been deviated
from once.

It fails on what kind of member it would be. Both precedents define
themselves by **not** being product crates: `wasm-bitmatch` is
"never depended on by any product crate" (row 7) and the P16 launcher is
dev tooling in the same class (row 8). A pipeline crate is the seal
command's engine — `antseal-cli` depends on it in production. That
single edge triggers the chain: cargo refuses to publish a crate whose
normal dependencies are not published versions (path-only deps are
rejected at publish; path+version deps must resolve on the registry), so
**`antseal-cli` becomes unpublishable until the pipeline crate publishes
first** — a new permanent public API surface, a new name outside the
closed five-name reservation family (row 9), a new per-crate license
decision (D6), all frozen at first publish — while D72, which decides
whether any of this ever publishes, is an open M4 decision (row 10).
Choosing (b) today forecloses or taxes an open decision; choosing (a)
leaves it free.

And the benefit it buys is smaller than it looks. The compile-hygiene
argument dissolves against row 11: any crate consuming `StorageBackend`
transitively compiles the ~652-package `ant-core` graph once net hosts
the real impl, so separating the pipeline from clap + the vault saves
noise, not the dominant cost. The layering argument is real but thin:
the pipeline's UX-facing needs are already forced through injected
interfaces under every option (the consent hook must be injectable for
library drive to auto-affirm in tests; the journal must be a trait for
S16's fault injection) — (b) adds compiler enforcement only for
"pipeline must not import clap", a one-line lane check if it ever
matters (candidate 2 below). Consumer count of the pipeline API is
exactly two — U13 and the S17 harness — and both consume a cli lib
target just as well. Rejected for v1; the module boundary (a) creates is
exactly the extraction seam if a real external library consumer ever
materializes (residual 1).

### (a) The `antseal-cli` library target — confirmed

Nothing depends on `antseal-cli` today (row 1), so adding `[lib]`
breaks nobody. The journal substrate the pipeline writes through lives
in this crate already (row 6), the CLI consumer is this crate (U13),
and the E2E harness becomes ordinary integration tests under
`crates/antseal-cli/tests/` — satisfying S17's "library APIs only"
accept (row 14: the grep target is M3 CLI/bundle-builder *invocation*,
which linking a lib is not) and composing with D52's local-gate venue
and P16 §7's runner/harness split (the harness links the client graph,
not the node stack). M3 lands in the same home for free: R16 is forced
out of core by its `MockBackend`/S-fetch dependency (core cannot depend
on net) and needs the same vault inputs (row 13) — under (a) it is the
adjacent module, not a new decision.

## Decision

1. **`antseal-cli` gains a `[lib]` target.** The package keeps
   `[[bin]] name = "antseal"`; `main.rs` becomes a thin shell over the
   library (arg parsing, tracing init, process exit codes). The library
   (default name `antseal_cli`) is the **orchestration layer**: the seal
   pipeline (S12), the journal state machine + library API (S10), resume
   (S11), restore (S14), and — at M3, absent a contrary decision — the
   reveal flow (R16) and `verify`/`--live` drivers. Module naming inside
   the lib is S12's/implementation's; this record fixes only the crate
   and target.
2. **Interface boundaries (dependency-direction rules, frozen):**
   - the pipeline consumes `antseal-net::StorageBackend` generically —
     the trait and its types stay in net (S2 unchanged);
   - the anchor-gate interface is defined on the A side (A1's contract)
     and consumed by the pipeline; `antseal-cli` depends on
     `antseal-anchor`, never the reverse;
   - the consent-hook signature and the `SealJournal` API are defined in
     the lib beside the pipeline; U14 implements the interactive consent
     impl, U9's vault store implements the journal, tests implement
     doubles. `antseal-core` and `antseal-net` never learn either
     exists.
3. **The E2E home**: S16 (mock matrix) and S17–S19 (devnet) drive
   `antseal_cli`'s library APIs — integration tests of this package (or
   a harness consuming it, per S17/Q15's wiring under D52). No test
   spawns the `antseal` binary to seal.
4. **Dependency edges added at M1** (all already implied by U1/U13):
   `antseal-cli` → `antseal-net`, `antseal-anchor`, clap, tokio,
   tracing. No new workspace member, no new external dependency beyond
   what U1's task text already pins.

## Rationale

- **The spec forces a library home and forbids two of the four.** Line
  154 requires library-API drive; lines 47 and 54 define core and net
  narrowly enough to exclude the pipeline (evidence rows 2–5). The
  remaining choice is (a) vs (b), and (b)'s costs are governance-real
  while its benefits are compile-time noise (the adversarial pass).
- **The pipeline sits with the state it owns.** Journal write points at
  every pipeline barrier (S10) against a vault substrate that is already
  this crate's code (row 6) — under (a) the two halves of the journal
  contract live side by side with one trait between them for testing,
  not a cross-crate API frozen for no consumer.
- **One home, two milestones.** R16's constraints are identical to
  S12's (row 13); deciding (a) now is also the M3 symmetry answer, which
  the register asked D34 to weigh.
- **Reversible in the cheap direction.** A module with a disciplined
  interface extracts into a crate mechanically if D72 ever creates a
  real external consumer; a prematurely published crate cannot be
  un-published (`scripts/reserve-crates.sh:16-18`'s own permanence
  warning). Under uncertainty, take the direction that can be undone —
  the same principle D28 rationale 4 recorded.

## Spec conformance — interpretation, flagged

The Architecture tree's comment for the crate is "binary `antseal`
(clap, tokio)" (MVP-SPEC.md line 55), and P5 scaffolded the tree
"exactly per" the spec. Adding a `[lib]` target changes no tree entry,
no crate list, and no binary name; it implements line 154's own
"via library APIs" requirement, which the tree assigns to no crate. This
is recorded as an **interpretation** (the tree names crates, not cargo
target kinds), not a deviation — but it is flagged here per the house
rule, and the spec text remains the maintainer's to amend. A new
workspace member, by contrast, *would* have been a recorded deviation
(the standard both existing extra members meet only by being
non-product infra — evidence rows 7–8).

No format, vector, or tamper-matrix impact: this decision moves no
wire byte and mints no error code.

## Consequences — task-text edits at integration

- **tasks/S.md S12**: "(placement per open decision 3…)" → "(placement
  per D34: `antseal_cli` library module; drivable without the CLI by
  construction)".
- **tasks/S.md S10**: note the journal library API and state machine
  live in the `antseal_cli` lib beside U9's substrate, separated by the
  `SealJournal` interface D34 Decision 2 names.
- **tasks/S.md:268** (S-domain open-decisions line): resolved per this
  record.
- **tasks/S.md S3**: add the note this pass forced: `MockBackend` must
  be consumable from `antseal-cli`'s dev-dependency edge — export it
  behind a non-default feature of `antseal-net` (the `test-util`
  pattern precedent, `crates/antseal-core/Cargo.toml`), since pipeline
  tests live outside net under every placement option.
- **tasks/S.md S17**: harness = integration tests consuming the
  `antseal_cli` lib (compose with D52's venue text edit already owed).
- **tasks/U.md U1**: scaffold text gains "add the `[lib]` target; keep
  `main.rs` thin" (U1 is not yet started — cheap).
- **tasks/U.md U13**: "driving the exact normative order" → "wiring the
  `antseal_cli` pipeline library (D34) into the `seal` command; the
  order lives in S12's pipeline, U13 owns flags/printing/exit codes".
- **tasks/R.md R16 (M3, note only)**: placement defaults to the same
  `antseal_cli` lib per D34; no new decision needed at M3 unless R
  objects.
- **TODO.md register D34 row** — integration's edit.

## Residual risks

1. **`antseal-cli` becomes the heaviest compile unit** (clap + tokio +
   vault + pipeline + the transitive ~652-package `ant-core` graph) on a
   2-core machine. Bounded: the graph cost is net's to carry regardless
   (row 11); incremental builds amortize; and the module boundary is the
   extraction seam if iteration cost ever bites. Revisit trigger: D72
   resolves to publishing `antseal-cli` **and** a real external library
   consumer appears → extract the pipeline crate then, with a
   deliberately designed public API.
2. **Module discipline is not compiler-enforced** inside one crate: the
   pipeline could grow a clap import nobody intended. Cheap mitigation
   if it ever occurs: a grep lane in the ci-lanes style (candidate 2).
3. **S-domain tasks now span two crates** (S2–S9 in net; S10–S12/S14
   orchestration in the cli lib). Bookkeeping only; precedent row 12.
4. **A future `--json` machine consumer of pipeline events** might
   tempt someone to expose lib internals as CLI output contract;
   D65/U30 own that surface — the lib API is NOT a stability-committed
   interface until D72 says otherwise (state this in the lib's crate
   docs at U1).

## New decision candidates surfaced (not resolved here)

1. **Feature-gate the `ant-core` adapter inside `antseal-net`** (mock +
   trait by default; adapter behind a feature) so default
   `cargo test --workspace` lanes compile without the 652-package graph
   until a lane genuinely needs it — the base-graph sibling of P16 §5's
   devnet-subtree containment. Owner S2/S6 with P7's lock event; decide
   at S2 landing, not drive-by.
2. **A `pipeline-purity` grep lane** asserting the pipeline modules
   import no clap/terminal crates. Q domain, low priority; only if
   residual 2 materializes.
