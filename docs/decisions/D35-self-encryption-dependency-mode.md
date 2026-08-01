# D35 — `self_encryption` in `antseal-core`: neither direct dep nor vendored subset — no antseal crate depends on it at all

- **Status: RESOLVED — option (d), absent from the register's option space.
  The register poses a binary — "direct pinned dep vs vendored
  address-derivation subset" — and both options are rejected on evidence;
  so is the intermediate (c), confining a `self_encryption` dependency to
  `antseal-net`. Under D32 (blob = one chunk, address = BLAKE3-256 of the
  ciphertext), no antseal crate needs `self_encryption` for anything:
  S4's `compute_storage_address` is `blake3` alone; `antseal-net` obtains
  addresses from ant-core's own returns and cross-checks them against S4.
  `self_encryption` remains exactly what it is today — a transitive,
  never-invoked-by-us dependency inside ant-core's graph, linked only into
  net/cli binaries. D6's CRITICAL P15 flag is discharged: no GPL code
  approaches `antseal-core` or the WASM page.**
- **Date: 2026-08-01**
- **Owner: P15 (re-scoped) with S4; consumed by R20 (M3 linkage layer)**
- **Blocks: S4 (register "`self_encryption` dependency mode", due early M1)**
- Companion: D32 (the model that dissolves the need), D6 (license posture),
  P9 record §3 (locked graph facts).

## Context

S4 must implement `compute_storage_address(blob_bytes) -> Address` in
`antseal-core` — WASM-safe, deterministic, offline — used at seal time
(pre-quote address computation, S12) and at M3 by the verifier's
storage-linkage layer (R20; MVP-SPEC.md line 119), which runs **in the
browser page**. P15 planned to pin `self_encryption` to ant-core's locked
version and verify wasm-safety, escalating to vendoring if unsafe. D6
recorded the license trap: `self_encryption` 0.36.0 is GPL-3.0, and a direct
`antseal-core` dependency — or vendored GPL source — would pull copyleft into
the permissive core and the redistributable verifier page ("never vendor GPL
code — vendoring keeps GPL", D6 option ii note).

The question is decidable now, from the pinned sources, without building
anything.

## Evidence

### 1. `self_encryption` 0.36.0 is disqualified from `antseal-core` on three independent grounds

All from `~/.cargo/registry/src/…/self_encryption-0.36.0` (archive sha256
recorded in P9 §3), re-read 2026-08-01.

| Ground | Fact | Citation |
| --- | --- | --- |
| **License** | `license = "GPL-3.0"` — no linking exception | `self_encryption-0.36.0/Cargo.toml` (`[package] license`); D6 evidence block |
| **Project rule (tokio/I-O)** | Mandatory, non-optional normal deps: **`tokio` (features `["rt"]`)**, **`tempfile`**, **`rayon`**, **`rand`/`rand_chacha`** — `[features] default = []` offers no way to shed them; the only optional dep is `pyo3` | `self_encryption-0.36.0/Cargo.toml` `[dependencies.tokio]`, `[dependencies.tempfile]`, `[dependencies.rayon]`, `[dependencies.rand]`, `[features]` |
| **wasm32** | The same deps are wasm32-unknown-unknown-hostile (threads, filesystem, OS RNG); P5's rule for `antseal-core` — "no I/O, no tokio in its normal-dependency graph" — is violated at the manifest level before any code is compiled | same |

P15's "verify the pinned version compiles for wasm32 … with no I/O/rand
baggage" has a manifest-level answer: **no**. No probe needed.

### 2. Vendoring or clean-rooming the "address-derivation subset" is not a subset

The derivation a data-map address would need (the only reason to want
self_encryption in core) is the full pipeline, verified by reading it:

- per-chunk **brotli compression** at `COMPRESSION_QUALITY = 6` before
  encryption — `self_encryption-0.36.0/src/encrypt.rs:15,28`
  (`BrotliCompress`), `src/lib.rs:166`;
- convergent keying of each chunk from sibling source hashes
  (`get_pad_key_and_nonce`, reached from `encrypt_with_child_level`,
  `src/lib.rs:174-240`), ≥3 chunks always (`lib.rs:186-191`,
  `MIN_ENCRYPTABLE_BYTES = 3`, lib.rs:150);
- a chunk-size constant that is **compile-time env-overridable**
  (`MAX_CHUNK_SIZE = option_env!("MAX_CHUNK_SIZE") | 4_190_208`,
  `lib.rs:154-160`) — the recomputation would have to mirror the *effective*
  constant of whatever binary uploaded, an unpinnable degree of freedom;
- DataMap serialization for the stored root map via **rmp_serde/MessagePack**
  of upstream's struct layout (`ant-core-0.5.0/src/data/client/data.rs:381`),
  plus the shrink/root-map recursion (`self_encryption-0.36.0/src/lib.rs:381,
  415`).

There is no specification of this behavior other than the implementation.
"Clean-room" is therefore unavailable in the meaningful sense: byte-exact
address agreement requires the same compression crate at the same version
producing the same bytes — a reimplementation would either link the same
`brotli` (and inherit its version-fragility) or diverge. And a *vendored*
subset carries GPL with it (D6). The register's option (b) is not a smaller
option (a); it is option (a) with worse provenance.

### 3. D32 removes the need; ant-core supplies every address `antseal-net` handles

- Chunk address function: `compute_address(content) =
  *blake3::hash(content).as_bytes()` —
  `ant-protocol-2.3.0/src/data_types.rs:10-12`. This is the entire v1
  derivation.
- `PreparedChunk.address` and `PaidChunk.address` carry it
  (`ant-core-0.5.0/src/data/client/batch.rs:139-158,162-175`);
  `chunk_put_with_proof` recomputes it from content
  (`src/data/client/chunk.rs:534-541`); `chunk_get` re-checks it on read
  (`chunk.rs:632-666`). S6's accept ("finalize-returned addresses equal S4's
  precomputed addresses") becomes a cross-check of two independent BLAKE3
  computations — ours in core, upstream's in net.
- No path antseal drives touches self_encryption at runtime: chunk-level
  quoting/paying/storing and `chunk_get` reads never call it (it is invoked
  only by the `data_*`/file-level surfaces D32 excludes,
  `data.rs:19` import site).

### 4. What remains true about the license (unchanged from D6)

`self_encryption ^0.36` stays a mandatory dep **of ant-core**
(`ant-core-0.5.0/Cargo.toml` `[dependencies.self_encryption] version =
"0.36"`; P9 §3 locks 0.36.0), so distributed `antseal-net`/`antseal-cli`
binaries still contain GPL-3.0 code (dead to our call graph, alive to the
linker) and D6's net/cli distribution note stands as written. Nothing in this
decision worsens or improves that; it keeps the GPL boundary exactly at the
crate D6 drew it around.

## Decision

1. **No antseal crate declares `self_encryption`** — not `antseal-core`
   (register option a: rejected — license + tokio/I-O rule + wasm32, table
   §1), not vendored (option b: rejected — GPL travels with source, and §2
   shows the subset is the whole pipeline), not `antseal-net` (option c:
   rejected as unnecessary — §3; adding an unused direct dep would only
   create a second version-pin surface for zero calls).
2. **S4 = BLAKE3-256.** `antseal-core::compute_storage_address(bytes) ->
   ContentAddress` is `blake3::hash` (32 B), with golden vectors and the
   native↔wasm bit-match obligation intact. The "underlying chunk-set
   derivation" and "data-map path" phrases in S4's Do text die with D32.
3. **New workspace dependency: `blake3`, exact-pinned** (dependency-policy §1
   hygiene; ant-core's lock has 1.8.5 — matching it is tidy but explicitly
   **not** load-bearing: BLAKE3 is a fixed function and the golden vectors,
   not the crate version, are the determinism authority). `default-features =
   false` for the wasm build; enable nothing that pulls rayon/std detection
   into the core graph.
4. **P15 re-scopes from a pin to a prohibition.** Its deliverable becomes:
   (a) a CI dependency-graph assertion that `self_encryption` appears in
   `cargo tree` **only** under `ant-core` and is a direct dependency of no
   workspace crate; (b) the blake3 pin landing with rationale; (c) the
   lockstep clause ("this pin may only move with ant-core") applies to
   nothing — recorded as retired. The escalation path P15 reserved
   ("vendor the minimal subset") is closed by this record, not exercised.
5. **R20's M3 linkage layer** verifies `BLAKE3-256(embedded ciphertext) ==
   manifest address` and, for the manifest blob, `BLAKE3-256(AEAD(k_m,
   nonce, manifest bytes)) == storage-record address` — no other machinery.

## Rationale

- The register's two options were the two ways to bring self_encryption *in*;
  every axis of evaluation — license, project rules, wasm32, determinism,
  even upstream's own usage (chunk addresses are BLAKE3 at the protocol
  layer, §3) — pointed *out*. The genuine break-attempt was §2's hybrid need
  (argued in D32's overturn section); once that fell, no consumer of
  self_encryption remained anywhere in antseal.
- Keeping even a confined net-side dep (option c) would imply antseal *calls*
  it somewhere; a dependency that exists to be never-called is a standing
  invitation for drift (someone "helpfully" using `data_upload`) — the CI
  prohibition is the stronger, cheaper invariant, and S6's existing
  no-`data_upload`/no-`chunk_put` grep enforces the call-site half.
- Discharging D6's CRITICAL flag by *deletion* (no GPL anywhere near core)
  beats discharging it by *management* (a carefully-fenced GPL dep) in a
  project whose verifier page ships to arbitrary static hosts — distribution
  in the fullest sense.

## Consequences — task-text edits at integration

- **tasks/P.md P15**: Do/Accept rewritten per Decision 4 (prohibition + blake3
  pin + retired lockstep); title accordingly ("Prohibit self_encryption
  outside ant-core's graph; pin blake3 for address recomputation").
- **tasks/S.md S4**: Do — "replicating exactly how ant-core 0.5.0 derives the
  network address(es) … via `self_encryption` — including small-blob behavior
  … and the data-map path" → "BLAKE3-256 of the blob bytes
  (`compute_address`, ant-protocol data_types.rs:10-12; D32/D35)";
  Deps — P15 reference updated; Accept — the ">MAX_CHUNK_SIZE → committed
  address" vector becomes D32's rejection case; wasm bit-match, determinism
  property, and the S9/S17 cross-reference stand.
- **tasks/S.md S9**: drop "minimum self-encryptable size" and
  "self-encryption-threshold" rows; pin `ant_protocol::MAX_CHUNK_SIZE` and
  the D32 plan-time rejection instead (see D32 consequences).
- **tasks/R.md R20 + R cross-domain expectations**: wording
  "deterministic self_encryption address recomputation" → "S4 BLAKE3-256
  recomputation (D32/D35)".
- **Workspace `Cargo.toml`**: add `blake3 = "=1.8.5"` (or current-verified
  patch of 1.8.x at execution) with a comment naming D35; core consumes with
  `default-features = false`.
- **docs/dependency-policy.md** (P-owned, at P15 execution): note the
  self_encryption prohibition and that the blake3 pin has no lockstep
  semantics.
- **TODO.md register D35 row** and the D6 cross-reference (CRITICAL flag
  discharged) — integration's edits.

## Residual risks

1. **The prohibition is only as strong as its CI check.** A future
   contributor adding `self_encryption` (or calling a `data_*` API) must trip
   the P15 graph assertion and S6's grep. Both are named acceptance items;
   neither exists yet.
2. **ant-core could someday *require* a self_encryption call on a path we
   need** (e.g. moving chunk-level quoting behind a data-map API). That is a
   bump-review event by definition (S20/P19); the D32 model would need
   re-decision before any such bump lands.
3. **blake3 crate compromise/bug** would affect address computation — bounded
   by golden vectors (a wrong hash fails vectors immediately) and by S6's
   independent cross-check against upstream's own computation.

## Revisit triggers (recorded so the door has a handle, not a hole)

- **Upstream relicense/republish** (D6 option iii): WithAutonomi republishing
  self_encryption under MIT OR Apache-2.0 — watched via P19's weekly
  upstream report — removes the license leg. The tokio/rayon/tempfile and
  determinism legs would still need an upstream wasm-safe refactor before any
  core dependency is thinkable.
- **A v1.1 large-blob decision** (D32's candidate) reopens this record as a
  prerequisite, in the order: license leg, wasm leg, determinism leg — all
  three, not any one.
