# `antseal-wasm` — the verifier page's wasm-bindgen boundary (R22)

The only place in this workspace where a `#[wasm_bindgen]` attribute exists.
It contributes **a boundary and no verification logic**: every decision the
page renders is computed by `antseal-core`, whose report already carries R18's
final display strings, so page JS does layout only.

Where this surface lives was decided by
[`docs/decisions/D18-wasm-bindgen-surface-location.md`](../../docs/decisions/D18-wasm-bindgen-surface-location.md).
Read it before changing anything here; the crate **name** in particular is
frozen by §5 R1, because `wasm-pack` derives the emitted filename from it and
the name is a byte-level input to the SHA-256 the page footer publishes.

## Build it

```sh
./scripts/wasm-pack-build.sh            # build + import allow-list + boundary comparison
./scripts/wasm-pack-build.sh --self-test  # prove both checks can go red
```

Output lands in `target/wasm-pack/antseal-wasm/` — never in this directory, so
the artifact set R25 computes sums over is exactly what `wasm-pack` wrote.

The build is **hermetic**: `--mode no-install --no-opt`. Both flags are
load-bearing, and the reason is measured rather than assumed — see
`docs/ci-verification.md`, "R22/D18". Short version: with egress blocked,
`wasm-pack build --release` still downloaded an unpinned `wasm-opt` (binaryen
117, dated 2024-02-28) and ran it over the artifact.

## The closed export list

Four entries plus a panic hook, and **additions are a decision, not a code
change** (D18 §5 R4):

| export | returns |
| --- | --- |
| `verify(bundle_bytes)` | the full report's canonical bytes, as a JS string |
| `verify_online(bundle_bytes, evidence_json)` | the advisory online overlay's canonical bytes |
| `verdict_class(bundle_bytes, evidence_json?)` | D69's rung datum — **not** a report field, which is why this export exists |
| `build_info()` | the identity D63 §5 R3's footer renders |

Everything returns **`to_canonical_json()`'s bytes**, never a structured JS
value: `serde_wasm_bindgen`, `JsValue::from_serde` and wasm-bindgen's own
`serde-serialize` feature are all prohibited, because each is a second
serialization path and D29/D65 require one path everywhere so the bit-match
contract covers user-facing output. Page JS may `JSON.parse` the string; what
it must never receive is a report that was serialized twice.

There is deliberately **no self-hash entry point**. A digest of a file cannot
live inside that file (D63 §4), so the page's published sum arrives by
build-time injection.

## The online-evidence document (R24's contract with this module)

`verify_online` and the optional second argument of `verdict_class` take one
JSON string. The page performs the `fetch()` calls; **this module performs the
must-agree comparison**, so the page never decides what "agreement" means.

```json
{
  "schema": "antseal.online-evidence.v1",
  "endpoints": { "identities": ["https://a.example", "https://b.example"], "overridden": false },
  "blocks": [
    { "height": 800000, "responses": [
        { "outcome": "header", "header_hex": "…160 hex characters…" },
        { "outcome": "header", "header_hex": "…160 hex characters…" } ] }
  ],
  "receipt": { "responses": [
      { "outcome": "confirmed", "status": 1, "block_number": 123, "block_hash": "…64 hex…" },
      { "outcome": "not-on-chain" } ] }
}
```

Each `responses` array is a **must-agree pair — exactly two entries**; a pair of
one agrees with itself and proves nothing. Every entry is one of
`header` / `no-such-block` / `failed` (blocks) or
`confirmed` / `not-on-chain` / `failed` (receipt), where `failed` carries
`endpoint` and a `class` of `transport`, `payload` or `wrong-chain`. Omit
`receipt` entirely when no probe was attempted.

The fold mirrors the CLI's `must_agree` exactly, because R27's parity gate
compares the two renderings: **failure first** (either endpoint failed → the
outcome is a failure and no comparison happens), then equal → agreed, then
unequal → disagreement. Only agreement crosses into the verdict path; a
disagreeing or failed pair is the *absence* of evidence, and the probe log is
the only place that absence has a reason.

Unknown keys, a wrong schema token, a pair that is not two, a duplicate height
and a non-hex string are all **refused**, not read leniently — a
silently-ignored key is a page that believes it disclosed something it did not.

## "No I/O inside the WASM module", enforced twice

| check | where it runs | what it decides |
| --- | --- | --- |
| `scripts/ci-lanes.sh dep-graph` | `core-dep-graph` job | this package's wasm32 normal graph is exactly `antseal-core`'s reviewed set plus six named wasm-bindgen packages; `js-sys`, `web-sys`, `wasm-bindgen-futures`, `web-time` and `getrandom` are refused **by name** |
| `scripts/wasm-imports.mjs` | `wasm-bitmatch` job, and `wasm-pack-build.sh` | the built module's import table matches a committed allow-list |

Neither alone is the property: a graph says what **can** be reached, an import
table says what **is** reachable. Neither adds a required CI context.

Every other wasm artifact in this repository asserts **zero** imports. The
shipped page module cannot — a typed JS error object and a panic hook both need
a host — so the property changes from "asserts nothing" to "asserts exactly
this list", and the list is reviewed on every change like any other allow-list
here. As shipped it is three names: throw a string, construct an `Error`, and
initialise the module's own externref table.

## Layout

```
src/lib.rs        module docs + the module tree
src/boundary.rs   the #[wasm_bindgen] items — cfg(target_arch = "wasm32") ONLY
src/api.rs        what the exports do, with no wasm-bindgen in sight
src/online.rs     the pre-fetched online-evidence document + the must-agree fold
src/build_info.rs what the module can honestly know about itself
src/error.rs      the boundary's refusals (it mints no error code of its own)
build.rs          stamps ANTSEAL_SOURCE_COMMIT; runs no process
examples/         boundary-emit — the native side of Accept row 2
tests/            the same behaviour, natively, in the ordinary test gate
```

`wasm-bindgen` is declared only under
`[target.'cfg(target_arch = "wasm32")'.dependencies]`, so `cargo clippy
--workspace --all-targets` and `cargo test --workspace` compile none of it —
and still type-check and execute everything in `src/api.rs`.
