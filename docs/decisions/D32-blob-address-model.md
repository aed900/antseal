# D32 — Blob↔address model: one blob = one chunk, BLAKE3-256 address, hard 4 MiB cap — no data-map path in v1

- **Status: RESOLVED — chunk-level. Every antseal blob (unit ciphertext, raw-mirror
  ciphertext, encrypted manifest) is exactly one Autonomi chunk; its address is
  BLAKE3-256 of the ciphertext bytes; `get_data(Address)` maps to `chunk_get`.
  The S1 lean is confirmed on its own terms, but the register entry was
  incomplete in the one place it could have failed: it left the oversize
  question open ("the data-level model stays available for oversized blobs if a
  later decision allows them"). This record closes that door for v1 — there is
  no data-map path; a blob whose ciphertext exceeds `MAX_CHUNK_SIZE` is a
  seal-time plan-validation error, rejected before consent, before anchors,
  before quote. The pre-quote enforcement duty is not optional: upstream's
  client quotes and pays for unstorable chunks without complaint.**
- **Date: 2026-08-01**
- **Owner: S2 (Blob/Address freeze); consumed by S4, S6, S9, S12, S14, R20**
- **Blocks: S2, S4, S6 (register "Blob↔address model", due M1)**
- Companion: D35 (the self_encryption dependency question this model dissolves),
  D11 (32-B BLAKE3 address, resolved M0), S1 memo §1/§10/§11.

## Context

ant-core 0.5.0 exposes two storage models (S1 memo §11):

1. **Chunk-level**: content = one chunk, `address = BLAKE3-256(content)`,
   `MAX_CHUNK_SIZE` cap, retrieval by `chunk_get(&XorName)`.
2. **Data-level**: content → `self_encryption::encrypt` → ≥3 convergently
   encrypted chunks + a `DataMap`; retrieval needs the DataMap
   (`data_download(&DataMap)`); an address-keyed identity exists only if the
   serialized DataMap is itself stored as a public chunk
   (`data_map_store` → `data_map_fetch(&[u8;32])`).

The register lean (S1 §11) recommends chunk-level. The manifest unit table —
frozen at M0 — carries exactly **one** 32-byte address per unit
(`crates/antseal-core/src/manifest/body.rs:487`, documented at body.rs:126-128
as "BLAKE3-256 of the stored chunk (decision D11)"), and the manifest storage
record is one address + nonce + `k_m` (the 88-byte unauthenticated region,
R-graft note). So whatever model wins must produce **one 32-byte,
network-fetchable identifier per blob**. The decision therefore reduces to:
what happens when a blob is big, and what does the verifier's offline
storage-linkage recomputation (MVP-SPEC.md line 119, R20 at M3) have to be
able to compute?

## The overturn attempt — the case for the data-level (hybrid) model, argued honestly

The strongest form of the anti-lean case: S4's and S9's own task texts assume
it. S4's Do text requires "the data-map path above it [the threshold]" and a
golden vector "> MAX_CHUNK_SIZE"; S9's ladder includes "a > 3×MAX_CHUNK_SIZE
blob" (tasks/S.md S4/S9). Units can genuinely exceed 4 MiB: binary files are
single-unit **by spec** (MVP-SPEC.md line 84), so a 10 MB PDF or dataset is
one blob; a `--split`-less text manuscript is one blob. A hybrid — chunk
address ≤ cap, DataMap-chunk address above it — would seal those.

It fails on four independent grounds, each verified against pinned source:

1. **The linkage layer would have to replicate self_encryption bit-exactly in
   the WASM page.** The v1 verifier invariant (MVP-SPEC.md line 119) is that
   the embedded ciphertext *derives* the manifest's recorded address, offline,
   in `antseal-core`. Under the hybrid, that derivation for an oversized blob
   is: brotli-compress each slice at `COMPRESSION_QUALITY = 6`
   (`self_encryption-0.36.0/src/lib.rs:166`; `src/encrypt.rs:15,28`
   `BrotliCompress`), convergently key each chunk from sibling source hashes
   (`get_pad_key_and_nonce`, lib.rs:212 region), hash chunks, build the
   `DataMap` struct, serialize it with **rmp_serde/MessagePack**
   (`ant-core-0.5.0/src/data/client/data.rs:381`), and BLAKE3 the result. Every
   link is version-fragile (brotli byte-output is not a standardized encoding;
   the chunk cap itself is a **compile-time env-overridable constant**,
   `MAX_CHUNK_SIZE = option_env!("MAX_CHUNK_SIZE") | 4_190_208`, lib.rs:154-160),
   and the crate that defines the behavior is GPL-3.0 with mandatory `tokio`,
   `rayon`, `tempfile`, `rand` dependencies (see D35's evidence table) — it
   cannot enter `antseal-core` as a dep, cannot be vendored without GPL, and
   cannot be clean-roomed because its behavior includes a specific compression
   crate's byte output. The hybrid makes the permanent v1 verification
   semantics hostage to all of that.
2. **Economics: ~4× chunk multiplication for the small blobs antseal actually
   produces.** self_encryption refuses inputs that produce fewer than 3 chunks
   (`lib.rs:186-191`), so a 272-B unit ciphertext becomes 3 stored chunks plus
   a paid DataMap chunk — four paid chunks where the chunk model pays one.
   Most antseal blobs are small (default one unit per file; padded 256-B
   buckets).
3. **The paid path doesn't cleanly exist for it.** `data_map_store` persists
   the map via `chunk_put` (`data.rs:390`), which pays internally and returns
   no payment data — the exact API class the spec excludes (MVP-SPEC.md line
   69, verified S1 §10). The file-level `PreparedUpload`/`finalize_upload`
   surface does include a paid `data_map_address`
   (`ant-core-0.5.0/src/data/client/file.rs:1022-1043`), but it is per-content,
   `#[non_exhaustive]`, non-serializable, and shaped around upstream's own
   file driver — driving it batch-first across N blobs per seal means N
   parallel prepared-upload lifecycles merged by hand, with the same receipt
   opacity problems S1 §5 found in merkle mode.
4. **It would silently change the frozen threat-model story.** The spec's
   size-fingerprint analysis (line 91) reasons about the 256-B-bucketed unit
   ciphertext as *the stored object*. Under the hybrid, oversized blobs
   fragment into ~⅓-size convergent chunks with different observables. The
   chunk model keeps the documented story exactly true.

Against this, the hybrid's sole benefit is sealing >4 MiB single-unit files in
v1. That is a real product limitation (recorded below as a residual with a
revisit trigger), but it is a *scope* cost, while the hybrid's costs are
*correctness and license* costs bound into a permanent format.

## Evidence (all re-verified 2026-08-01 against pinned sources)

ant-core 0.5.0 citations are into the crates.io archive re-fetched this date;
its sha256 (`c3f3c2…c85a39`) matches the P9 record
(`docs/upstream/P9-ant-core-reverification.md` §1). ant-protocol 2.3.0,
evmlib 0.9.0, self_encryption 0.36.0 read from the cargo registry sources.

| # | Fact | Citation |
| --- | --- | --- |
| 1 | `pub type XorName = [u8; 32]` — every chunk address is 32 B | `ant-protocol-2.3.0/src/chunk.rs:43` |
| 2 | `compute_address(content) = *blake3::hash(content).as_bytes()` | `ant-protocol-2.3.0/src/data_types.rs:10-12` |
| 3 | `MAX_CHUNK_SIZE = 4 * 1024 * 1024` (= 4 194 304) | `ant-protocol-2.3.0/src/chunk.rs:19` |
| 4 | `prepare_chunk_payment` computes the address and quote plan with **no size check** — an oversized blob is quoted and paid without client-side complaint | `ant-core-0.5.0/src/data/client/batch.rs:354-415` (whole body read; no `MAX_CHUNK_SIZE` reference) |
| 5 | Oversize is enforced by the protocol/node side: `ProtocolError::ChunkTooLarge` exists (`chunk.rs:367-371`); node replication rejects `data.len() > MAX_CHUNK_SIZE`; wire decode caps at 5 MiB | `ant-protocol-2.3.0/src/chunk.rs:19,26,367`; `ant-node-0.14.3/src/replication/mod.rs:2304` (node version indicative, not pin-matched) |
| 6 | `chunk_get(&XorName) -> Result<Option<DataChunk>>`, `chunk_exists(&XorName)` — address-keyed reads exist at chunk level | `ant-core-0.5.0/src/data/client/chunk.rs:632-636,1011-1013` |
| 7 | `data_download(&DataMap)` takes a DataMap, **not** an address; address-keyed data-level identity requires `data_map_store`/`data_map_fetch` | `ant-core-0.5.0/src/data/client/data.rs:459,380-410` |
| 8 | `data_map_store` serializes with `rmp_serde` and stores via the excluded `chunk_put` | `data.rs:381,390` |
| 9 | self_encryption minimum: ≥ 3 chunks always; `MIN_ENCRYPTABLE_BYTES = 3` | `self_encryption-0.36.0/src/lib.rs:150,186-191` |
| 10 | self_encryption chunk cap is env-overridable at compile time (`4_190_208` default — a **different** constant from row 3) | `self_encryption-0.36.0/src/lib.rs:154-160` |
| 11 | Already-stored chunks quote as `Ok(None)` (zero-cost skip) — the idempotency primitive finalize relies on | `ant-core-0.5.0/src/data/client/batch.rs:361-368` |
| 12 | The frozen unit-table entry holds exactly one 32-B `ContentAddress`, already documented "BLAKE3-256 of the stored chunk (decision D11)" | `crates/antseal-core/src/manifest/body.rs:126-128,487,563-566` |

## Decision

1. **Blob = chunk.** `antseal-net::Blob` is one AEAD-ciphertext byte string
   that becomes exactly one Autonomi chunk. `Address = BLAKE3-256(blob bytes)`
   = `XorName`, converting losslessly to/from `antseal-core::ContentAddress`.
2. **Hard cap, enforced before money.** Invariant: `blob.len() ≤ 4_194_304`
   (`ant_protocol::MAX_CHUNK_SIZE`). Enforced three-deep:
   - S12 plan validation — the authoritative check, before consent, before
     anchor submission, before `quote_batch` (fail cheap; evidence row 4 is
     why this cannot be left to upstream: the client would quote and **pay**
     for an unstorable chunk, burning ANT);
   - S2 `Blob` constructor — the type refuses oversized bytes (distinct error
     variant), so no backend impl can receive one;
   - S6 adapter debug-assert (defense in depth at the boundary).
3. **Derived seal-time size arithmetic** (normative for S12's error message
   and G/U guidance): ciphertext = `padded_length + 16` (XChaCha20-Poly1305
   tag); `padded_length = ⌈(true_length+1)/256⌉·256` (MVP-SPEC.md line 91);
   the largest storable padded length is `16 383 · 256 = 4_194_048`, so the
   **maximum unit plaintext is `4_194_047` bytes** (4 MiB − 257 B) and the
   maximum ciphertext is `4_194_064` ≤ cap. The encrypted manifest blob obeys
   the same cap (in practice bounding honest per-seal unit counts well below
   D10's adversarial verify-side cap of 65 536 — no conflict; D10 caps bound
   hostile inputs, not honest output).
4. **Reads**: `StorageBackend::get_data(Address)` ↦ `chunk_get`;
   already-stored probes ↦ `chunk_exists`/`prepare_chunk_payment → Ok(None)`.
   `data_upload`/`data_download`/`chunk_put`/`data_map_*` remain excluded.
5. **No data-map path exists in v1.** An over-cap blob is
   `SealPlanError::BlobExceedsChunkCap { .. }`-class: seal aborts with zero
   network side effects, suggesting `--split blank-lines` for eligible text.
   Over-cap binary files are unsupported in v1 — a recorded product limit,
   not an implicit one.
6. **v1 address semantics are thereby fixed** for the M3 storage-linkage
   layer: recompute = BLAKE3-256 over the embedded ciphertext bytes, compare
   32 bytes. Nothing else. (D35 records what this dissolves.)

## Rationale

- **One authoritative identity per blob, offline-recomputable with one pure
  hash.** The linkage layer (R20) and the seal pipeline's pre-quote address
  computation (S12) become the same 5-line function with golden vectors —
  wasm-safe, license-clean, version-insensitive (BLAKE3 is a fixed function;
  evidence row 2 shows upstream computes exactly this).
- **The frozen format already pointed here.** One 32-B address per unit
  (row 12); the storage record's single address; D11's doc text. A data-map
  semantic would not change any wire byte but would change what the bytes
  *mean* for oversized blobs — a size-branched meaning in a permanent format,
  verified by code we cannot host.
- **Failure containment.** Under this model the only irreversible-money
  hazard tied to blob shape — paying for an unstorable chunk (row 4) — is
  closed at plan time by construction.
- **The spec's deeper requirement wins over its parenthetical.** See Spec
  conformance.

## Spec conformance — recorded deviation (flagged, not silently diverged)

MVP-SPEC.md lines 34 and 51 say ciphertext addresses are computed "via
`self_encryption`", line 110 says the v1.1 receipt chain will "recompute chunk
addresses … via deterministic `self_encryption`", and line 119 names
"deterministic `self_encryption` address recomputation inside `antseal-core`".
Under this decision the mechanism is **BLAKE3-256, the chunk address function
of ant-core's own storage model** — `self_encryption` is not invoked anywhere
in antseal. The spec's *requirements* behind those phrases — addresses
computed before quoting; deterministic, offline, WASM-safe recomputation in
`antseal-core`; the linkage layer needing no network — are all satisfied,
strictly more robustly. The parenthetical named the mechanism the spec author
assumed the storage model would force; S1's survey showed the chunk-level
model is native to ant-core 0.5.0 and D32 selects it. Line 154's M1 exit
criterion "MAX_CHUNK_SIZE / self-encryption-threshold behavior pinned against
the real API" narrows to pinning the **chunk cap and its enforcement locus**
(S9). The spec text itself is the maintainer's to amend; this record is the
required flag.

## Consequences — task-text edits at integration

- **tasks/S.md S2**: Notes — open decision 1 resolved (this record). `Blob`
  gains the constructor-enforced `≤ MAX_CHUNK_SIZE` invariant with a distinct
  error; `Address` = BLAKE3-256 chunk address; `get_data` documented as
  `chunk_get`-backed.
- **tasks/S.md S4**: Do/Accept rewritten per D35 (blake3-only; the
  "> MAX_CHUNK_SIZE → committed address" vector becomes a rejection case).
- **tasks/S.md S6**: `get_data` via `chunk_get` (not `data_download`); adapter
  drives chunk-level APIs only; add the plan-time size assert.
- **tasks/S.md S9**: ladder re-specified: 272 B / mid / max-plaintext
  4 194 047 (stores; address matches) / cap-edge 4 194 304-byte blob
  (stores) / cap+1 (rejected at plan, zero payment, distinct error). Constants
  test pins `ant_protocol::MAX_CHUNK_SIZE = 4_194_304` and notes
  self_encryption's distinct env-overridable 4 190 208 constant is
  **irrelevant** to antseal under D32.
- **tasks/S.md S12**: plan validation step named: per-blob cap check before
  consent/anchor/quote; `--split` guidance in the error.
- **tasks/S.md S14**: restore fetches via `get_data`(= `chunk_get`); no
  DataMap handling.
- **tasks/R.md R20 (and the R cross-domain S-expectation line)**: "deterministic
  self_encryption address recomputation" → "S4 BLAKE3-256 address
  recomputation (D32)".
- **TODO.md register D32 row**: resolved per this record (integration's edit).
- **G/U (notes only)**: seal-time size error surfaces through U's error
  rendering; G14's unit outputs feed the S12 check (no G behavior change).

## Residual risks

1. **>4 MiB single-unit content is unsealable in v1.** Bounded: text has
   `--split`; the limit is loud at plan time with zero cost. Revisit trigger:
   real demand for large binary sealing → new decision (v1.1 data-map path
   behind a format version bump; see D35's contingency for why that decision
   is hard today).
2. **Upstream cap drift.** A future ant-protocol bump could move
   `MAX_CHUNK_SIZE`; S9's frozen-constant test + S20's bump procedure make
   that a deliberate event. Addresses themselves are version-immune (BLAKE3).
3. **Node-side enforcement is the backstop, not the contract.** Between the
   4 MiB rule and the 5 MiB wire cap enforcement lives node-side (row 5, node
   version not pin-matched here); antseal never relies on it — the plan-time
   check is authoritative on our side.

## New decision candidate (not resolved here)

- **v1.1 large-blob path**: if demand materializes, decide between (a) an
  upstream-relicensed/wasm-safe self_encryption derivation (see D35 triggers)
  and (b) an antseal-defined deterministic split under a new, format-versioned
  address-semantic field. Owner S/F with R; explicitly out of v1.
