# wasm-bitmatch — the native↔WASM bit-match harness (Q5)

**Test infrastructure, not a product crate.** Never published
(`publish = false`), never depended on by `antseal-core`/`-anchor`/`-net`/
`-cli`, and deliberately not named `antseal-*` so it cannot be mistaken for
one of the four crates in the MVP-SPEC Architecture tree.

## The contract it enforces

> "Verification must succeed fully offline, and **the WASM build must
> bit-match native verification**." — MVP-SPEC.md lines 167/169 (also
> `crates/antseal-core/src/lib.rs` module docs).

Concretely: executing **every committed golden vector** under
`testdata/vectors/` through `antseal_core::test_util::vectors` produces a
**byte-identical** transcript natively and under
`wasm32-unknown-unknown`. The lane compares the two byte strings and their
SHA-256, and fails loudly on any difference. Task: `tasks/Q.md` **Q5**;
CI context: `wasm-bitmatch`.

## Run it

```sh
./scripts/wasm-bitmatch.sh              # the lane — must be GREEN
./scripts/wasm-bitmatch.sh --self-test  # test-of-the-test — must go RED
cargo test -p wasm-bitmatch --locked    # the native guards (also in `test`)
```

Requires the pinned toolchain (which installs the wasm32 target) and node ≥
18. No wasm-pack, no wasm-bindgen-cli, no browser.

## How it works

| Piece | Role |
| --- | --- |
| `build.rs` | Walks `testdata/vectors/` — **no hardcoded lists** — and emits an `include_bytes!` table. `cargo::rerun-if-changed` on the tree keeps it fresh. Enforces the same discovery contract as the Q4 runner (`testdata/vectors/README.md`); a stray or misfiled file fails the **build**. Also enforces D87's budget: **2 MiB of embedded bytes per `v<n>/` directory**, over which the build fails with the reason and the sanctioned fix. |
| `src/lib.rs` | `transcript()` executes every embedded vector through `antseal_core`'s executor and serialises the outcomes; `transcript_bytes()` is the byte contract. Failures are **recorded** (`status: "failed"` + error text), never raised, so the function is total and a divergence is a diffable byte difference rather than a trap. |
| `src/bin/bitmatch-emit.rs` | Native side: writes `transcript_bytes()` to a file. |
| wasm exports | `bitmatch_len()`, `bitmatch_ptr()`, `bitmatch_transcript_version()` — a raw C ABI over two integers. The module has **zero imports** (asserted by the runner). |
| `scripts/wasm-bitmatch.mjs` | Instantiates the module with plain `WebAssembly.instantiate`, reads the transcript out of the exported memory, byte-compares it against the native file, and prints the first differing byte with context. |
| `tests/bitmatch.rs` | Native guards: the embedded table equals the committed tree (staleness), embedded bytes equal file bytes, the transcript is deterministic, non-vacuous, path-sorted, total over malformed input, and obeys the D29 serialization rules. |

### Why a separate crate

Two reasons, both structural:

1. The wasm side needs a module with a **custom export**. Putting that export
   in `antseal-core` would mean giving it a `crate-type` and an exported
   surface — edging into decision **D18** (feature-gated wasm-bindgen surface
   in core vs a thin wrapper crate), which is not due until M3. Nothing here
   uses wasm-bindgen at all, so **D18 stays entirely free**.
2. It is a **workspace member**, not a standalone crate like
   `probes/sig-probe`: a bit-match between two builds resolved from different
   lockfiles would prove nothing. Sharing the root `Cargo.lock` guarantees
   both sides compile the same pinned dependency versions.

It depends on `antseal-core` with `features = ["test-vectors"]` — the
WASM-safe tier, which activates **zero** optional dependencies, so this edge
cannot perturb `antseal-core`'s audited normal dependency graph.

### Transcript byte format

Compact JSON under the **D29** determinism rules
(`docs/decisions/D29-report-byte-format.md`): declaration-order fields, no
maps, no floats, no conditional presence (absent values are `null`),
lowercase hex for binary. D29 is **recommended, not frozen** — this crate
*consumes* the recommendation; the freeze belongs to Q14.

`TRANSCRIPT_VERSION` stays `0` through that freeze. It versions the
transcript **envelope**, not the report: the transcript carries no report
field, aggregates the recomputed digests of all seven vector kinds rather
than the report alone, and is never committed or frozen (it is written to
`target/`). R32 bumped `antseal_core`'s `REPORT_VERSION` to `1` and left
this at `0` deliberately — see the constant's own docs for the evidence.
It moves when a transcript field is added, removed, renamed or reordered,
and never for a change in what the fields contain.

Each entry carries the vector's path, format version, size, status, kind,
description, item count, and — the substantive part — the **recomputed
digest**: `VectorSummary::recomputed_digest`, a SHA-256 over every byte the
executor recomputed (length-prefixed and domain-separated). That is Q5's
"report bytes **plus recomputed digests**": a platform divergence anywhere in
the recomputation changes the digest even where it would not (yet) flip a
pass/fail verdict. Only the digest is ever surfaced — the recomputed key
material never leaves the executor (project rule 6).

### Why the vectors are embedded rather than read at run time (D87)

Measured at `aa169ac`: the embedded vectors are **2.32 %** of the 25.5 MB
debug artifact (whose 83.7 % is DWARF) and **0.73 %** of the lane's
13.71 s, while *executing* them is **90.1 %**. Reading the tree through
the Node host would buy back 0.10 s and cost the three properties this
harness is built on — zero imports, zero unsafe operations, and "both
sides execute identical bytes" as a link-time fact rather than a claim
about the runner's plumbing. The budget is per **format version**, not
global: Q6 retains every released version forever, so v2 arriving beside
v1 is the contract working.

## Adding vectors, kinds, and format versions

Nothing here changes. Drop a vector file anywhere under
`testdata/vectors/<version>/`; `build.rs` picks it up, the transcript grows
an entry, and both sides must still agree. New *kinds* (manifest, bundle,
report, anchor, fine-tree) register in
`antseal_core::test_util::vectors` — one dispatch arm — and flow through
untouched, which is exactly what the **M2 exit criterion** ("anchor
verification … golden vectors + a wasm32 build") needs.

## The red-lane self-test

`./scripts/wasm-bitmatch.sh --self-test` rebuilds **only** the wasm32 side
with `--cfg antseal_bitmatch_inject_divergence`, which makes the wasm
transcript reverse its entry order *and* uppercase its hex digests — the two
classic platform-divergence shapes (container iteration order, which is Q5's
own "HashMap-ordered serialization" example, and platform-dependent
formatting). Both are injected so the self-test stays effective at any vector
count. The lane must go red; the script inverts the exit code, so a
correctly-failing lane is a *passing* self-test, and it rebuilds a clean
artifact before reporting. Recorded evidence: `docs/ci-verification.md`.
