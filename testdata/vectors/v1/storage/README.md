# `storage-address` vectors (S4) — the D32 address rule, pinned

**What these pin.** Under decision D32 an antseal blob (unit ciphertext,
raw-mirror ciphertext, or the encrypted manifest blob) is exactly **one**
Autonomi chunk, and its storage address is **BLAKE3-256 of the blob
bytes** — upstream's own chunk-address function (`compute_address` =
`blake3::hash`, `ant-protocol-2.3.0/src/data_types.rs:10-12`; `XorName =
[u8; 32]`, `chunk.rs:43`). `storage-address.json` commits that rule as
byte-exact addresses over the S4 size ladder, and commits the cap rule with
it: content over `MAX_CHUNK_SIZE = 4_194_304` (`chunk.rs:19`) has **no v1
address at all** — the cap+1 case pins a typed *rejection*
(`antseal_core::storage::ExceedsChunkCap`), not a hash (D32 decision 5; the
spec's former "via `self_encryption`" phrasing is the D32-recorded
deviation).

Executor: `crates/antseal-core/src/test_util/vectors_storage_address.rs`,
which recomputes the whole `expect` object through
`antseal_core::storage::compute_storage_address` and additionally enforces
ladder coverage (272, the exact cap edge, and an over-cap rejection must
all be present). Spec basis: seal-time pre-quote address computation
(MVP-SPEC.md line 34) and the M3 offline storage-linkage recomputation
(line 119).

## The ladder

| case | `len` | why this length |
| --- | --- | --- |
| `empty-0` | 0 | the official BLAKE3 empty-input vector — anchors both implementations to the published value |
| `smallest-unit-ciphertext-272` | 272 | smallest padded-unit ciphertext: one 256-byte padding bucket + 16-byte XChaCha20-Poly1305 tag (MVP-SPEC.md line 91) |
| `mid-64k-ciphertext-65552` | 65 552 | mid rung (65 536-byte padded plaintext + tag); 65 BLAKE3 chunks, so the tree layer is exercised, not just single-chunk hashing |
| `max-unit-plaintext-4194047` | 4 194 047 | the maximum unit plaintext under D32 decision 3 (4 MiB − 257) |
| `max-unit-ciphertext-4194064` | 4 194 064 | the maximum plaintext-derived ciphertext (16 383 · 256 + 16) |
| `cap-edge-4194304` | 4 194 304 | exactly `MAX_CHUNK_SIZE` — the largest addressable input |
| `over-cap-4194305` | 4 194 305 | **committed rejection**: `rejected: "exceeds-chunk-cap"` — over the cap there is no address in v1 |

## Generative inputs, not literal bytes

Every input is the **official BLAKE3 test-vector pattern** `byte[i] = i %
251` at the stated length. Committing the 4 MiB rungs literally would put
~25 MiB of hex into this directory and blow D87's 2 MiB embedded-bytes
budget for the whole version (`crates/wasm-bitmatch/build.rs`); the pattern
+ length reproduce the bytes exactly, and — being the official pattern —
every case can be independently validated against any third-party BLAKE3
tool (`b3sum`, the reference implementation, the official
`test_vectors.json` for lengths it covers).

## Provenance / independent generation

`gen_vectors.py` is a **pure-Python BLAKE3 (hash mode) written from the
BLAKE3 specification** — stdlib only, no Rust code path shared (D31 tier
T1). Its self-test pins `BLAKE3("")` to the official published value before
deriving anything. The committed addresses are therefore agreed byte-for-
byte by two independently written implementations: this generator, and the
exact-pinned `blake3 = "=1.8.5"` crate (itself verified against the
complete official test-vector suite at P15 — see the workspace `Cargo.toml`
blake3 pin comment). Verify any time with:

```sh
python3 gen_vectors.py --check   # ~20 s: it really rehashes the 4 MiB rungs
```

(The runtime note is deliberate: this is the slowest reference generator in
the cross-check lane, because pure-Python BLAKE3 over ~12.6 MiB of ladder
input is honest work. The Rust side executes the same cases in
milliseconds.)

**Everything here is NON-SECRET** (project rule 6): storage addresses hash
AEAD *ciphertext* in production; these public pattern bytes stand in for
ciphertext of the same lengths. Nothing derives from any secret, including
the fixed test seed `W`.
