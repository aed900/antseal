# D26 — Perf/memory budget constants for the fine tree (G18)

- **Status: RESOLVED — the budgets are **exact closed forms**, not tolerance
  constants: `C₁` does not exist and must not be introduced. Corpus sizes are
  set from measurement, not from the task entry's guess. **No D26 constant is
  format-permanent; none of them freeze at Q14.** G18 is an M0 milestone item,
  not a Q14 gate dependency.**
- **Date: 2026-07-28** (planning; G18 implements, G26 lands the closed-form
  accessors it asserts against)
- **Owner: G (the budgets and the tests) + Q (lane placement); milestone M0**

## Context

tasks/G.md G18 — "Perf/memory budget tests for streaming construction" — is
the last unscheduled M0 task in the G domain: it appears in no previous
wave's plan and reached the freeze gate unnoticed. Its accept bullets need
numbers that only a decision can supply, and its entry names them as
"Open decision 8 … C₁ and the corpus size".

MVP-SPEC.md line 85 is the requirement: *"`seal` prints an estimated
fine-tree cost for large files (~5–7 SHA-256 compressions per byte;
construction must stream with O(log n) memory)"*, and line 153 lists "a
perf/memory budget" among M0's deliverables.

Two pieces already exist and constrain everything below:

1. **G9's instrumentation.** `FineTreeStats { leaf_hashes, node_hashes,
   ggm_derivations, peak_frontier_len, peak_seed_stack_len }`, always
   collected, readable **mid-stream** via `FineTreeBuilder::stats()` — the
   accessor whose doc comment already says "which is how G18 asserts the peak
   bound at a size too large to buffer".
2. **G10's estimator.** `estimate_fine_tree_cost(n)` is not an estimate but
   an **identity**: `CostEstimate::matches_measured` is asserted equal to
   G9's counters over `n ∈ 1..=400` as a proptest, and the module docs say so
   in terms.

So the honest question is not "what tolerances", but "what is actually left
for G18 to assert, and how large a corpus can CI afford".

## 1. Everything in this decision was measured, not assumed

**Reference machine** (the development box; deliberately the *slow* end of
the range these numbers must survive):

| | |
| --- | --- |
| CPU | Intel Pentium G4400 @ 3.30 GHz (Skylake, 2 cores) |
| SHA extensions | **none** — `/proc/cpuinfo` has no `sha_ni`, no `avx2`, no `bmi2` |
| toolchain | the repo pin, `rustc 1.92.0` |

### 1.1 Streaming fine-tree throughput (`FineTreeBuilder`, 1 MiB feed chunks)

| `n` | release | dev (`cargo test`'s profile) | MiB/s (release) |
| --- | --- | --- | --- |
| 1 MiB | **1.81 s** | **50.85 s** | 0.55 |
| 4 MiB | 7.83 s | ≈ 220 s | 0.51 |
| 16 MiB | 46.42 s | ≈ 1 300 s | 0.34 |
| 64 MiB | **202.31 s** | ≈ 5 680 s | 0.32 |
| 256 MiB *(the task entry's suggestion)* | **≈ 810 s (13.5 min)** | **≈ 6.3 hours** | — |

The dev-to-release ratio, measured at 1 MiB, is **28.1×**.

### 1.2 The two facts that follow, and that no record contains

**Fact A — CI runs the dev profile.** `.github/workflows/ci.yml:119` is
`cargo test --workspace --locked`; the workspace `Cargo.toml` has **no
`[profile]` section at all**. Every test in the suite runs unoptimized.
G18's headline assertion therefore cannot be a large-corpus measurement in
the default lane at any size worth measuring.

**Fact B — G18's task entry proposes an impossible size.** "≥ 256 MiB
streamed in chunks" is 13.5 minutes in release and over six hours in dev on
the reference box. The suggestion is off by roughly two orders of magnitude
and must not be implemented as written.

### 1.3 Where the time goes — and why there is no easy win

Raw `sha2 = "=0.11.0"` on the same machine, one-shot `new/update/finalize`:

| message | ns/call |
| --- | --- |
| 26 B (leaf preimage, 1 block) | **539** |
| 65 B (node preimage, 2 blocks) | **959** |

Per content byte the construction performs ≈ 1 leaf hash, ≈ 1 node hash and
≈ 2 GGM derivations (34 B, 1 block), predicting
`539 + 959 + 2·539 ≈ 2.6 µs/byte ≈ 0.38 MiB/s` — against 0.32–0.55 MiB/s
measured. **The fine tree runs at the pinned primitive's ceiling on this
hardware**; the overhead above raw SHA-256 is in the noise. Toggling `sha2`'s
default features changes nothing (539 → 619 ns, within variance), so this is
not a pin misconfiguration. It is a CPU without SHA-NI hashing five tiny
messages per input byte.

A CI runner or a modern desktop **with** SHA-NI is plausibly 5–20× faster.
That spread is itself an argument, and §4 uses it.

### 1.4 The product fact this surfaces

At 0.32 MiB/s, fine-tree construction alone takes:

- **≈ 5 minutes** for the spec's own worked case `n = 10⁸` (95.4 MiB,
  MVP-SPEC.md line 96);
- **≈ 12.5 minutes** for D10's largest fully revealable binary work
  (≈ 239 MiB).

On SHA-NI hardware, minutes become tens of seconds. Either way the answer to
"how long does sealing a large file take" is **minutes, not seconds**, which
is exactly why MVP-SPEC.md line 85 requires `seal` to *print* an estimate
before committing. That print is a UX necessity, not a nicety — and it
currently prints a compression *count*, which no user can convert into time.
Recorded as **G25**.

## 2. The framing correction: `C₁` does not exist

G18's entry asks for a structural memory bound `≤ C₁·⌈log₂ n⌉`. Both halves
of that are wrong:

1. **The form is wrong at the corners.** At `n = 1`, `d = 0`, so
   `C₁·⌈log₂ n⌉ = 0` for every `C₁`, while the real peak is 1. Any bound of
   that shape is false at the smallest input.
2. **A tolerance constant is not available to be chosen, because the
   quantities are exact.** Both instrumented peaks are deterministic
   functions of `n`. Verified exhaustively for **`n = 1..=4096`, zero
   mismatches**:

```text
peak_seed_stack_len == d + 1                       where d = ⌈log₂ n⌉
peak_frontier_len   == bit_width(n) == 64 − n.leading_zeros()
```

The two differ, and both are needed: at `n = 2^k` they coincide at `k + 1`,
but at `n = 6` (`d = 3`) the stack peaks at 4 while the frontier peaks at 3.
G9's existing tests assert only `≤ depth + 1` for each, which is true but
loose.

**Decision: G18 asserts equality, not a bound, and mints no `C₁`.** A
multiplicative slack constant would license precisely the regression the test
exists to catch — a change that doubled the frontier would pass a `C₁ = 2`
bound and fail an equality. If a future change makes the equality wrong, that
is a design change that must be reviewed, not absorbed by slack.

**The byte figure, for the record.** Each entry of both structures is 32
bytes, so the structural working set is
`32 · (peak_frontier_len + peak_seed_stack_len)`, bounded for **any**
representable file (`d ≤ 64`) by `32 · (65 + 65) = 4 160 bytes`. That number
— not a `C₁` — is what "O(log n) memory" means in this codebase, and it is
what G18 should state in prose.

## 3. The compressions budget

### 3.1 The `[5, 7]` envelope as written would fail

G18's entry says "measured SHA-256 compressions/byte within the **[5, 7]**
envelope". The measured value is **4.999** (4 999 milli-units) at every size
from 1 MiB to 64 MiB. A `5_000 ..= 7_000` assertion is red on first run.

This is not a measurement artefact: the asymptote is exactly 5 and is
approached **from below**, because there are `n − 1` interior nodes, not `n`.
Both G9 and G10 already work around it with `4_990..=7_000` and
`4_900..=7_000` bands.

### 3.2 The exact identities

```text
compressions(n) = n·1  +  (n − 1)·2  +  G(n)·1
G(n)            = ( Σ_{l=0..d} ⌈n / 2^(d−l)⌉ ) − 1
```

with block weights `FineTreeStats::{LEAF_BLOCKS = 1, NODE_BLOCKS = 2,
GGM_BLOCKS = 1}` fixed by the frozen preimages (`0x00‖salt16‖LE64‖byte` =
26 B; `0x01‖L‖R` = 65 B; `0x06‖seed‖b` = 34 B).

For `n` a power of two this collapses to a closed form worth pinning as a
KAT — **`compressions(2^k) = 5·2^k − 4`** — verified against the measured
counters at `n = 2^20, 2^22, 2^24, 2^26` (5 242 876 / 20 971 516 /
83 886 076 / 335 544 316) and for every power of two up to 4096.

### 3.3 Decision

**The primary assertion is the identity, not the envelope.**

1. `estimate_fine_tree_cost(n).matches_measured(&stats)` — exact, already
   available, machine-independent, and the tie that makes a change to either
   accounting break loudly.
2. `stats.sha256_compressions() == n + 2(n−1) + G(n)` for the sizes in §4,
   and `== 5n − 4` at the power-of-two sizes.
3. The spec envelope survives only as a **sanity band**, with the floor at
   the value the code actually produces:

```text
COMPRESSIONS_PER_BYTE_MILLI_MIN = 4_990        // for n >= 2^12
COMPRESSIONS_PER_BYTE_MILLI_MAX = 7_000        // MVP-SPEC.md line 85's "~7"
```

The `n ≥ 2^12` qualifier is load-bearing: at `n = 6` the ratio is 4 500, and
at `n = 1` it is 1 000. The band is a statement about *large files*, which is
where line 85 makes it.

## 4. Corpus sizes

Two lanes, because §1.2 Fact A leaves no alternative.

### 4.1 Default lane — `cargo test --workspace` (dev profile, runs on wasm32 too)

```text
G18_SPREAD = [1, 2, 3, 6, 7, 8, 9, 255, 256, 257, 4_096, 65_536]
G18_SPREAD_WASM_MAX = 4_096          // entries above this are cfg'd off wasm32
```

Every entry asserts, at **exact equality**: the two peak closed forms
(§2), the compression identity (§3.3 items 1–2), and streamed-equals-one-shot
`fine_root`.

- **Cost**: the 65 536-byte case dominates at ≈ **3.2 s** dev on the
  reference box (≈ 0.11 s release), everything else is noise. On CI hardware,
  well under a second.
- **Why this spread and not something bigger**: `d` runs 0 → 16 across it,
  so the peaks run 1 → 17 while `n` grows 65 536×. Any O(n), O(√n) or
  O(n/log n) memory regression is excluded by four orders of magnitude. The
  power-of-two/±1 triples are where the ragged right edge and the GGM padding
  interact, which is where an off-by-one lives.
- **wasm32**: the lane is `cargo test -p antseal-core --lib
  --target wasm32-unknown-unknown` (ci.yml:166), which is a *correctness*
  lane. Entries above `G18_SPREAD_WASM_MAX` are compiled out with
  `#[cfg(not(target_arch = "wasm32"))]` so the wasm job does not inherit a
  multi-second hash loop. This discharges G18's "wasm32 run at reduced size,
  or documented native-only rationale" in the first form.

### 4.2 Large-corpus lane — `#[ignore]`d, run explicitly, release profile

```text
G18_LARGE_LEAF_COUNT      = 33_554_432          // 2^25 = 32 MiB
G18_LARGE_CHUNK_BYTES     = 1_048_576           // 1 MiB feed chunks
G18_LARGE_WALL_CLOCK_CEIL = 600                 // seconds; hang detector only
```

- **Never materializes the content.** One 1 MiB chunk is fed 32 times, and
  `FineTreeBuilder::stats()` is read **mid-stream** to assert the peaks —
  the use G9 built that accessor for. Peak process memory is the chunk, not
  the file.
- **Why 32 MiB.** Measured ≈ **94 s** release on the reference box; on a
  SHA-NI runner, comfortably under 20 s. 256 MiB is 13.5 min on the same box
  (§1.1) for **no additional information**: `d = 25` already reaches 39 % of
  the maximum representable depth (64), and the peaks are exact closed forms
  that a larger `n` cannot falsify differently.
- **Invocation** (Q owns lane placement):
  `cargo test -p antseal-core --release --locked -- --ignored g18_large_corpus --nocapture`.
- **Native only.** A wasm32 run here would measure the wasm runtime, not
  antseal, and the correctness content is identical to §4.1's.

## 5. Wall clock

**Decision: no wall-clock assertion in the default lane, at any size.**

A timing threshold on shared CI hardware is a flake generator, and the
project's third working principle is determinism. What G18 must protect is
the *shape* — memory peaks and compression counts — which is deterministic
and machine-independent. Throughput is neither: §1.3 shows a plausible
5–20× spread between this box and a SHA-NI runner, so any number tight enough
to catch a 2× regression is loose enough to be useless, or tight enough to
flake.

The large-corpus lane keeps **one** number, `G18_LARGE_WALL_CLOCK_CEIL =
600 s`, explicitly labelled a **hang detector** (6.4× headroom over the
measured 94 s), overridable by the environment variable
`ANTSEAL_G18_WALL_CLOCK_CEIL` so a slow runner is a configuration matter and
never a red build. The measured throughput is **printed** (`--nocapture`),
never asserted, so a regression is visible in the log without being a gate.

## 6. Permanence — the question this decision exists to answer

### 6.1 The answer

**No constant in this document is format-permanent. None of them freeze at
Q14. Every one is a test-lane constant, revisable by an ordinary reviewed
PR at any time, before or after the freeze.**

The test: *does the constant decide whether a given `.sealproof` is valid
v1?* For every value here the answer is no. `C₁`/the peak forms describe
*our* implementation's working set — a third-party verifier that buffers the
whole file in RAM produces byte-identical verdicts. Corpus sizes, the
wall-clock ceiling and the wasm cutoff are lane engineering. Nothing here is
read by an encoder, a decoder, or a verifier.

This is the opposite of D10, whose caps *are* permanent precisely because a
receiver rejecting a bundle a sealer produced is a compatibility break under
MVP-SPEC.md line 123. D26 has no such coupling. The register entry sits in
the same decision file as format decisions and reads as though it inherits
their permanence; **it does not**, and stating that is half the value of this
round.

### 6.2 What *is* permanent, and where it is already frozen

The **identities** the budgets check are format-coupled, and they are already
frozen — by the golden vectors, not by D26:

| quantity | why it is fixed | already pinned by |
| --- | --- | --- |
| `LEAF_BLOCKS = 1`, `NODE_BLOCKS = 2`, `GGM_BLOCKS = 1` | consequences of the frozen preimages `0x00‖salt16‖LE64‖byte` (26 B), `0x01‖L‖R` (65 B), `0x06‖seed‖b` (34 B) | `testdata/vectors/v1/fine-tree/fine-tree.json`, registry §2 |
| `compressions(n) = n + 2(n−1) + G(n)` | a consequence of the tree shape (RFC 6962 promotion) and MSB-first GGM indexing | the same vectors + `estimate_matches_measured_counts` |
| `peak_seed_stack_len = d + 1`, `peak_frontier_len = bit_width(n)` | consequences of the same two shapes | this decision → G18/G26 |

A change to any of them is a **format event** that the committed vectors
catch on their own. That is exactly why D26 does not need to freeze anything
itself, and why G18's budgets can stay adjustable without weakening the
freeze.

### 6.3 Consequence for wave 6's schedule

**G18 is not a Q14 dependency.** Q14's dependency list (tasks/Q.md) is
`Q5, Q6, Q8, Q11, Q12, Q13` plus P9/P10, C3/C11, F4 and G1 — G18 does not
appear, and nothing in Q14's freeze checklist (Definitions frozen, vectors
frozen, cross-check clean, tamper registry complete, HKDF distinctness, WASM
bit-match, security sign-off, traceability) touches a perf budget.

G18 must still land for **M0 completeness** (spec line 153 lists the budget
among M0's deliverables), but it may land *after* the format-freeze tag
without invalidating it. Wave 6 should schedule it with the non-format work,
not with the format events that must precede the gate.

## 7. What G18 must contain, concretely

`crates/antseal-core/src/content/fine_tree/cost.rs` (tests module) or a new
`crates/antseal-core/tests/fine_tree_budgets.rs` — placement is the
implementer's, the content is not:

1. `budgets_hold_across_the_spread` — §4.1's spread; for each `n`, assert
   the two peak equalities, `matches_measured`, and the compression identity.
2. `power_of_two_compression_closed_form` — `5n − 4` at
   `n ∈ {1, 2, 4, …, 4096}` (KAT for §3.2).
3. `compressions_per_byte_stays_in_the_spec_band` — `4_990 ..= 7_000` for
   `n ≥ 4096` only, with the reason for the floor in the doc comment.
4. `streamed_equals_one_shot` — at the spread's top, `FineTreeBuilder` fed in
   awkward chunk sizes equals `rebuild_fine_root`.
5. `#[ignore] g18_large_corpus` — §4.2: 32 MiB, one reused chunk, mid-stream
   `stats()` assertions, printed throughput, env-overridable hang ceiling.
6. Every constant a named `const` with the measured figure from §1.1 in its
   doc comment, and a one-line statement that **these are test-lane
   constants, not frozen format values** (§6.1), so the next reader does not
   treat them as untouchable.

The closed-form helpers those tests assert against belong next to the
instrumentation that produces them, not restated in a test file — that is
**G26**.

## 8. What the implementer must report back

Amend **this file** with a dated entry — not a task report — if:

1. **Any closed form fails.** §2's peaks and §3.2's compression identity were
   verified exhaustively only to `n = 4096`, plus spot checks at
   `2^20..2^26`. A single counterexample invalidates §2's "assert equality"
   decision and must be recorded here with the `n` that broke it.
2. **The default-lane cost is unacceptable.** 3.2 s dev on the reference box
   is the measurement; if the real suite budget cannot absorb it, drop
   `G18_SPREAD`'s top entry to `16_384` (≈ 0.8 s) — that is a *legal*
   change under §6.1, and it should be made by editing this section rather
   than silently.
3. **The large lane needs a different size.** Report the machine and the
   measurement, not just the new number.
4. **A `[profile.dev.package]` opt-level bump lands** (see the cross-domain
   note below). It would shrink §1.1's dev column by ~28×, at which point
   `G18_SPREAD`'s top entry can rise by roughly an order of magnitude and
   §4.2's lane may no longer need `#[ignore]`. That is a welcome change;
   re-derive the sizes here when it happens.
5. **`FineTreeBuilder::stats()` turns out not to expose a peak mid-stream
   that equals the final peak** for the large lane's assertion — the
   mid-stream read is the whole basis for not materializing 32 MiB.

### Cross-domain note (P, not actionable here)

`cargo test --workspace` runs everything unoptimized (§1.2 Fact A) and the
workspace has no `[profile]` section. A `[profile.dev.package]` block raising
`opt-level` for the hash-heavy pinned dependencies — `sha2`,
`chacha20poly1305`, `ed25519-dalek`, `ml-dsa` — would speed the whole M0 test
suite by roughly the 28× measured here, at negligible compile cost, without
touching any crate's own build. This affects far more than G18 (R6's corpus,
C's AEAD tests, the fuzz lanes) and belongs to whoever owns the workspace
manifest. Recorded here because D26's numbers are the evidence for it.
