# D87 — How the bit-match harness carries the vector tree

- **Status: RESOLVED — option (a): keep `include_bytes!` embedding, with a
  ceiling of 2 MiB of embedded bytes **per format-version directory**,
  enforced by a `build.rs` panic and a second, testable assertion.** The
  measurements reframe the question: embedding costs **2.32 %** of the
  wasm artifact and **0.73 %** of the lane's wall time, while executing
  the vectors costs **90.1 %** — and options (b) and (c) do not touch the
  90 %, while each destroys a structural property the lane depends on.
  This **overturns** F21's framing, which treated the growth as a cost to
  be engineered away.
- **Date: 2026-07-28**
- **Owning task: F21** (harness is Q5's; retention is Q6's; multiplication
  is R28's)
- Index note: `docs/decisions/README.md` (which other planners are editing
  concurrently) gains its row at merge — the verbatim row is in §8.

## Context

`crates/wasm-bitmatch/build.rs` walks `testdata/vectors/` and emits an
`include_bytes!` table, so every committed vector travels inside the
wasm32 artifact. F21 (raised by F13) observes that this was decided when
the tree was ~98 kB, that F12/F13 took it to ~520 kB, and that the growth
is **structural**: a byte-level format freeze commits the bytes twice
(artifact + sidecar), and Q6 retains vectors **per version, forever**
(MVP-SPEC.md line 123), so v2 arrives *beside* v1 rather than replacing
it.

F21's history is exactly right. §1 confirms it from git. What §2 refutes
is the inference drawn from it.

## 1. Measurements

All taken on the main tree at `aa169ac`, Linux x86-64, pinned toolchain
1.92.0, node v24.12.0, warm cargo cache. Every number below was measured,
not estimated; the two derived numbers are marked.

### 1.1 The tree, and how it got here

Embedded set = `testdata/vectors/**/*.json` **less** `INDEX.json` (F10's
roster is an auxiliary the executor cannot run, excluded by `build.rs` and
independently by `tests/bitmatch.rs`).

| commit / event | embedded bytes | files |
| --- | --- | --- |
| Q5 lands the harness | 2 646 | 1 |
| wave-5 merge base (pre-F12/F13) | 100 263 | 8 |
| after R9 (report vectors) | 170 976 | 9 |
| after F12 (manifest vectors) | 225 125 | 9 |
| after F13 (bundle vectors) | 519 567 | 10 |
| **today (`aa169ac`)** | **590 280** | **11** |

F21's "~98 kB → ~520 kB" is confirmed to the byte (100 263 → 519 567).
The whole tree including READMEs, generators, `FROZEN.sha256` and
`INDEX.json` is 771 598 B in 25 files; only the 11 files above are
embedded.

### 1.2 The artifact

`target/wasm32-unknown-unknown/debug/wasm_bitmatch.wasm` —
**25 461 350 B**. Section breakdown, parsed from the module:

| section | bytes | share |
| --- | --- | --- |
| `custom:.debug_str` | 11 272 237 | 44.27 % |
| `custom:.debug_info` | 6 152 371 | 24.16 % |
| `code` | 3 209 456 | 12.61 % |
| `custom:.debug_line` | 1 808 490 | 7.10 % |
| `custom:name` | 1 347 446 | 5.29 % |
| **`data`** | **918 355** | **3.61 %** |
| `custom:.debug_ranges` | 555 582 | 2.18 % |
| `custom:.debug_abbrev` | 180 990 | 0.71 % |
| all others (`function`, `type`, `element`, `export`, …) | 16 423 | 0.06 % |

- Debug + `name` custom sections: **21 319 785 B = 83.7 %** of the file.
  The same module with those sections removed measures **4 141 565 B**.
- The 590 280 B of vectors are **64.3 % of the `data` section** but
  **2.32 % of the artifact** as the lane actually builds it, and
  **14.25 %** of a hypothetical stripped module.

The lane only ever builds `debug`. The artifact is never shipped: the
crate is `publish = false`, is depended on by nothing, and is not
`verifier-web`'s wasm (that is M3/R23 via wasm-bindgen, `verifier-web/index.html`
is a 484-byte placeholder). **Artifact size has no product consequence
whatsoever** — it is a number on a CI runner's disk.

### 1.3 Wall time

`./scripts/wasm-bitmatch.sh`, warm, no source change: **13.71 s**. Split,
each stage timed independently:

| stage | seconds | note |
| --- | --- | --- |
| 1 — `cargo build --target wasm32`, after `touch` of a vector file | **0.73** | build.rs re-runs, crate relinks |
| 2 — `cargo run --bin bitmatch-emit` | 8.69 | = 0.60 rebuild + 7.75 execution + cargo overhead |
| 2a — native rebuild after the same `touch` | **0.60** | |
| 2b — native **execution** only (`./target/debug/bitmatch-emit`) | **7.75** | |
| 3 — `node scripts/wasm-bitmatch.mjs` | 4.62 | |

Stage 3, instrumented inside node:

| step | ms |
| --- | --- |
| `readFileSync` of the 25 MB artifact | 54.9 |
| `WebAssembly.compile` | **45.0** |
| `WebAssembly.instantiate` | 0.8 |
| `bitmatch_len()` — executes all 11 vectors | **4 604.5** |

Transcript: 7 312 B, identical on both sides.

**Attribution of the 13.71 s:**

- **executing the vectors: 12.35 s = 90.1 %** (7.75 native + 4.60 wasm) —
  dominated by debug-build Ed25519/ML-DSA-65 over the `sig-reject` and
  `crypto` suites;
- **carriage, byte-proportional: 0.10 s = 0.73 %** (reading and compiling
  the whole 25 MB module in node);
- **rebuild triggered by any tree change: 1.33 s = 9.7 %** (0.73 + 0.60)
  — and this is per *change*, essentially independent of tree size, since
  the linker copies a data blob.

### 1.4 The projection, from these numbers

| scenario | embedded | artifact | node compile |
| --- | --- | --- | --- |
| today | 590 280 | 25 461 350 | 45.0 ms |
| + v2 at parity *(derived)* | 1 180 560 | ≈ 26 051 630 (+2.3 %) | ≈ 47 ms |
| 4 versions retained *(derived)* | 2 361 120 | ≈ 27 232 190 (+7.0 %) | ≈ 51 ms |

R28's per-version multiplication is real and it is **also negligible**.

## 2. Decision — (a), keep embedding

The property that makes the lane meaningful is not that the two sides read
the same *file*; it is that they execute the same *bytes* through the same
*executor*, and that this is true **by construction rather than by
plumbing**. Today one `build.rs`, run twice by cargo, emits one
`EMBEDDED_VECTORS` table from one tree, and both the native binary and the
wasm module link it. "Identical bytes" is a link-time fact.

Options (b) and (c) trade that fact for 0.73 % of the lane's wall time.
Both are rejected; §5 gives their costs in full.

### 2.1 The ceiling, and what it is a ceiling on

**`MAX_EMBEDDED_BYTES_PER_VERSION = 2 097 152` (2 MiB), applied
independently to each `testdata/vectors/v<n>/` directory.**

Three deliberate choices:

1. **Per version, not global.** Q6 retains every released version forever
   (line 123). v2 arriving beside v1 is the retention contract *working*,
   not a regression, and a check that goes red for it would be a check
   that fights a spec commitment — and would therefore be bumped
   reflexively, which is how a ceiling becomes a comment. What this
   bounds is one version's tree.
2. **On the embedded bytes, not the artifact.** Artifact size is
   dominated 83.7 % by DWARF (§1.2) and moves with rustc version, profile
   and debug settings — a ceiling on it would be flaky and would measure
   the toolchain rather than our decisions. Embedded bytes are
   project-controlled, deterministic, platform-independent, and already
   walked by `build.rs`.
3. **No per-*file* sub-ceiling.** `bundle.json` is legitimately 294 442 B
   and `manifest.json` 124 862 B; a per-file limit would have to be set
   above them and would then catch nothing.

**Why 2 MiB.** Today v1 uses **28.15 %** of it. The realistic remaining
v1 growth is M2's real anchor artifacts — `.ots` blobs, RFC 3161 tokens
and cert chains swapped into the bundle vectors "without schema change"
(registry §7.8), hex-doubled into JSON — plausibly a few hundred kB, so
v1 lands near ~1 MB by M4 with ~2× headroom still in hand. The ceiling is
not sized to be tight; it is sized so that a **4×-scale surprise trips
it**. The concrete surprise it guards against is named in R9's own
record: the report vectors *name* their bundle by R6 shape "rather than
embedding ~7 kB of ciphertext per case". Reverse that choice anywhere and
a suite grows by hundreds of kB at a stroke. That is the event this check
exists to make loud.

### 2.2 Enforcement — leg 1, `crates/wasm-bitmatch/build.rs`

The build script already walks every entry; it gains the file length and a
per-version accumulator. **A ceiling breach fails the build**, so it
cannot be skipped by not running a test.

Add near the top of the file:

```rust
/// D87: ceiling on the embedded bytes of any ONE format-version directory.
///
/// Not a ceiling on the whole tree: Q6 retains every released version
/// forever (MVP-SPEC.md line 123), so v2 arriving beside v1 is the
/// retention contract working, not a regression. What this bounds is one
/// version's tree — the growth that is inside our control.
///
/// Raising it is a reviewed, recorded change (D87 §2.1), not a chore. The
/// wrong fix is deleting or shrinking a committed vector: they are
/// retained forever.
const MAX_EMBEDDED_BYTES_PER_VERSION: u64 = 2_097_152;
```

`walk_version_dir` records the length alongside the path (`found` becomes
`Vec<(String, String, PathBuf, u64)>`, the fourth element from
`fs::metadata(&entry).len()`; the existing `found.sort()` is unaffected
because `String` path remains the leading key). After `found.sort()` and
before the emptiness check:

```rust
    // D87: per-version budget, enforced here because this is where the
    // total is already known and because a breach must fail the BUILD.
    let mut by_version: BTreeMap<String, u64> = BTreeMap::new();
    for (_, version, _, len) in &found {
        *by_version.entry(version.clone()).or_default() += len;
    }
    for (version, total) in &by_version {
        assert!(
            *total <= MAX_EMBEDDED_BYTES_PER_VERSION,
            "testdata/vectors/{version}/ embeds {total} B, over the D87 ceiling of \
             {MAX_EMBEDDED_BYTES_PER_VERSION} B for ONE format version. Every committed \
             vector is retained forever (Q6), so the fix is NOT to delete or shrink one: \
             either a vector is embedding payload bytes it should be naming (see R9's \
             bundle-by-shape precedent), or the ceiling needs a reviewed raise in \
             build.rs and docs/decisions/D87-bitmatch-vector-carriage.md."
        );
    }
```

Both constants are then emitted into the generated table so leg 2 and any
future reader share **one** definition:

```rust
    let _ = writeln!(
        out,
        "\n/// The D87 per-format-version ceiling on embedded bytes.\n\
         pub const MAX_EMBEDDED_BYTES_PER_VERSION: u64 = {MAX_EMBEDDED_BYTES_PER_VERSION};\n"
    );
    out.push_str(
        "/// Embedded bytes per format-version directory, ascending by version (D87).\n\
         pub static EMBEDDED_BYTES_BY_VERSION: &[(&str, u64)] = &[\n",
    );
    for (version, total) in &by_version {
        let _ = writeln!(out, "    ({version:?}, {total}),");
    }
    out.push_str("];\n");
```

`crates/wasm-bitmatch/src/lib.rs` re-exports them beside the existing
table:

```rust
pub use embedded::{
    EMBEDDED_BYTES_BY_VERSION, EMBEDDED_VECTORS, EmbeddedVector, MAX_EMBEDDED_BYTES_PER_VERSION,
};
```

### 2.3 Enforcement — leg 2, `crates/wasm-bitmatch/tests/bitmatch.rs`

The build-script assertion is authoritative but not observable: it can
only ever say "no". Leg 2 makes the number **visible before it bites** and
gives the ceiling a testable home, in the same two-independent-layers
style as `scripts/vector-freeze.sh`. Append:

```rust
/// D87: the embedded-vector budget is enforced, not documented.
///
/// `build.rs` is the authoritative leg — it panics, so the crate cannot
/// build at all. This is the second, *testable* leg: it recomputes the
/// per-version totals from the linked table (so the generated
/// `EMBEDDED_BYTES_BY_VERSION` cannot drift from the bytes actually
/// embedded) and prints the utilisation, so a reviewer sees the tree
/// approaching the ceiling instead of discovering it as a red build.
#[test]
fn bitmatch_embedded_bytes_stay_under_the_per_version_ceiling() {
    let mut recomputed: std::collections::BTreeMap<&str, u64> = std::collections::BTreeMap::new();
    for vector in EMBEDDED_VECTORS {
        *recomputed.entry(vector.format_version).or_default() += vector.bytes.len() as u64;
    }

    let declared: std::collections::BTreeMap<&str, u64> =
        EMBEDDED_BYTES_BY_VERSION.iter().copied().collect();
    assert_eq!(
        recomputed, declared,
        "the generated per-version byte totals disagree with the embedded bytes"
    );

    for (version, total) in &recomputed {
        let pct = (*total as f64) * 100.0 / (MAX_EMBEDDED_BYTES_PER_VERSION as f64);
        println!("D87: {version} embeds {total} B — {pct:.1}% of the per-version ceiling");
        assert!(
            *total <= MAX_EMBEDDED_BYTES_PER_VERSION,
            "{version}: {total} B embedded, over the D87 ceiling of \
             {MAX_EMBEDDED_BYTES_PER_VERSION} B (see build.rs and D87 §2.1)"
        );
    }
    assert!(!recomputed.is_empty(), "no format versions embedded");
}
```

The `f64` here is a print, not a serialized value: D29's no-floats rule
governs the transcript, and this test touches neither the transcript nor
any committed byte.

### 2.4 What must NOT change

The property F21's Accept clause protects, restated so an implementer
cannot trade it away:

- **No per-vector wiring, anywhere.** `build.rs` keeps walking the tree
  with no hardcoded list; dropping a new vector file into
  `testdata/vectors/` stays a zero-change event for the harness, the
  runner and CI (`.github/workflows/ci.yml`'s `wasm-bitmatch` comment
  states this as an explicit M2 exit criterion for the anchor vectors).
  The ceiling is a *total*, never a roster.
- **The module keeps zero imports**, asserted by
  `scripts/wasm-bitmatch.mjs`.
- **The crate keeps zero `unsafe` blocks and zero unsafe operations** —
  the only `unsafe` token stays the `unsafe(no_mangle)` attribute, per the
  documented opt-out in `src/lib.rs`.
- **`tests/bitmatch.rs`'s independent walk stays independent.** It is the
  cross-check on `build.rs`'s discovery; the new test must not be folded
  into it.

## 3. Committed artifacts to re-emit

**None.** D87 changes no vector, no fixture, no golden byte, and no
transcript field. `scripts/vector-freeze.sh` must stay green with no
`--update`, and `TRANSCRIPT_VERSION` / `EXPECTED_TRANSCRIPT_VERSION` are
untouched by this decision (see §6 for a separate trap in that area).

## 4. Documentation rows

### 4.1 `crates/wasm-bitmatch/README.md` — "How it works" table

Replace the `build.rs` row with exactly:

```
| `build.rs` | Walks `testdata/vectors/` — **no hardcoded lists** — and emits an `include_bytes!` table. `cargo::rerun-if-changed` on the tree keeps it fresh. Enforces the same discovery contract as the Q4 runner (`testdata/vectors/README.md`); a stray or misfiled file fails the **build**. Also enforces D87's budget: **2 MiB of embedded bytes per `v<n>/` directory**, over which the build fails with the reason and the sanctioned fix. |
```

And append to that section:

```
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
```

### 4.2 `testdata/vectors/README.md` — under "Retention: per version, indefinite"

Append exactly:

```
**Budget (D87).** `crates/wasm-bitmatch/build.rs` embeds every vector into
the bit-match artifact and enforces a ceiling of **2 MiB of embedded bytes
per `v<n>/` directory** (`*.json` less `INDEX.json`). It is per version on
purpose — retention is per version, so a new version gets its own budget
and never competes with an older one's. A breach fails the build; the fix
is a reviewed raise in `build.rs` and D87, never deleting or shrinking a
committed vector. Today `v1` uses 590 280 B, 28.15 % of its budget.
```

### 4.3 `docs/format/registry-v1.md` / `registry-v1.json` — not affected

Checked: the registry describes wire formats, not test infrastructure. No
row changes; the JSON mirror is not re-emitted.

## 5. Losing options, with their real costs

**(b) Read the tree at run time through the Node host.**

1. The module has **zero imports today**, and
   `scripts/wasm-bitmatch.mjs` fails the lane if that ever stops being
   true ("the bit-match module has imports, so it is no longer
   self-contained"). Feeding vectors in needs either imports or an
   inbound copy ABI — an exported allocator plus JS writing into
   `exports.memory.buffer`.
2. That ABI is the crate's **first raw-pointer operation**. Today there is
   no `unsafe` block and no unsafe operation anywhere in it, and
   `src/lib.rs` documents that as a standing property with a scoped
   `#[allow]` on one attribute. (b) deletes it.
3. **It converts the lane's central fact into a claim.** Native would read
   its bytes one way and wasm receive them another; a truncation, an
   encoding slip or an ordering bug in the JS copy path would present as a
   *bit-match failure* — the signal this lane reserves for a real platform
   divergence. The lane would stop meaning "the code diverged" and start
   meaning "something diverged".
4. It buys **0.10 s of 13.71 s** and does not touch the 12.35 s of vector
   execution.

**(c) Embed a manifest of digests and stream the vectors in.** Every cost
of (b), plus: the digest manifest is a *second* description of the tree
that can disagree with it — today
`bitmatch_embedded_table_equals_the_committed_tree` proves the table **is**
the tree, and with digests you must additionally prove the digests are of
the tree; and verifying streamed bytes against digests puts new code
inside the module, executing before the executor, in the trust base of a
lane whose whole value is having none. (c) is the design one reaches for
when **module size** is the binding constraint; §1.2 measures that it is
not, and that the module is never shipped.

**(a′) Keep embedding with a ceiling on the artifact size.** Rejected in
§2.1: 83.7 % DWARF makes it a measurement of the toolchain.

**(a″) Keep embedding with a comment.** This is the status quo and is what
F21's Accept clause explicitly refuses.

## 6. One thing this decision did not fix, and must be routed (see report)

`wasm_bitmatch::TRANSCRIPT_VERSION` is `0` and its doc says "*Q14 freezes
the report byte format and this becomes `1`*";
`scripts/wasm-bitmatch.mjs`'s `EXPECTED_TRANSCRIPT_VERSION` must move in
the same commit ("*Bumping it there without bumping it here is caught
immediately, by design*"). **R32's task text names neither.** That is the
same shape of Q14 trap R32 itself was created to close, one file over. It
is Q/R-domain, so D87 records it rather than fixing it.

## 7. Permanence

Nothing here freezes at Q14. The ceiling is a project budget on test
infrastructure, deliberately raisable by a reviewed one-line change in
`build.rs` plus a dated note in this record. The embedding *strategy* is
likewise revisitable — the forcing conditions that would reopen it are:
`WebAssembly.compile` of the artifact exceeding ~1 s (measured 45 ms, so
~20× away), a CI runner failing on artifact size or link memory, or the
harness gaining a reason to ship the artifact to a user (it has none —
the M3 verifier page is a separate wasm-bindgen build, D18).

## 8. Register row (for `docs/decisions/README.md`) — applied

**Applied — this section holds no row.** D87's index row is in
`docs/decisions/README.md` and has been since `3a72933` (2026-07-28), which is
**not a merge**: `git rev-list --parents -n 1 3a72933` returns two words, one
commit and one parent. The verbatim copy that stood here is deleted rather than
re-headed, because once the index is checked a hand-written row in a body is a
second home for a fact the check already guarantees.

Demoted in place on 2026-08-11 under
[D119](D119-decision-index-identity-and-the-index-row-sections.md) RULING 4,
which measured **zero** rows applied at a merge across 83 merges. The heading
keeps its number — D117 §2.4 forbids moving a section identifier, and this
record's own front-matter `Index note` cites this section by number; D119 §5
step 8 reserves the five `Index note` prose sites for a separate act, so that
bullet still describes the old hand-off and is deliberately untouched here.

## 9. What the implementer must report back

1. **Re-measure and report the four headline numbers after the change**:
   embedded bytes per version, artifact size, `./scripts/wasm-bitmatch.sh`
   wall time, and node `WebAssembly.compile` ms. They must match §1 within
   noise — if the artifact moved by more than a few percent, the build
   script is doing something it should not.
2. **The `println!` output of the new test**, verbatim (the utilisation
   line). It is the number this decision exists to keep visible.
3. **Proof the ceiling bites**: temporarily lower
   `MAX_EMBEDDED_BYTES_PER_VERSION` (e.g. to `1024`), confirm the **build**
   fails with the intended message, restore it, and report both. A ceiling
   nobody has seen fire is a comment.
4. **`./scripts/wasm-bitmatch.sh --self-test` still goes red**, and the
   real lane green. The build script now runs more code; a mistake there
   presents as a lane that cannot build in either mode.
5. **`git diff --stat` contains no path under `testdata/`.** D87 re-emits
   nothing.
6. **Confirm the four invariants of §2.4** are intact — in particular
   that no vector is named anywhere in `build.rs`, the runner, or CI.
7. Whether `BTreeMap` needed importing in `build.rs` and whether
   `found`'s new tuple shape disturbed the existing `found.sort()`
   ordering guarantee (it must not: `path` stays the leading key, and
   `EMBEDDED_VECTORS` must remain sorted by `path` — `tests/bitmatch.rs`
   asserts it).
