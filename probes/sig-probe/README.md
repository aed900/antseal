# sig-probe — C11 M0 signature-crate probe

Standalone probe harness for task **C11** (tasks/C.md): establishes crate
reality for the hybrid Ed25519 + ML-DSA-65 author signature
(MVP-SPEC.md line 97) and produces the evidence behind decisions
**D13** (ed25519-dalek pin) and **D14** (ML-DSA crate choice).
Findings report: `docs/research/C11-signature-probe.md`.

Deliberately **not** a member of the root workspace (empty `[workspace]`
table): it depends on both `ed25519-dalek` majors at once and must never
influence the root `Cargo.lock`. Its own `Cargo.lock` is committed so the
probe is reproducible. It is excluded from the root gate; run it explicitly.

## Crates probed (the exact root pins)

- `ml-dsa = "=0.1.1"` (RustCrypto) — primary ML-DSA-65 candidate
- `fips204 = "=0.4.6"` (integritychain) — fallback candidate
- `ed25519-dalek = "=2.2.0"` and `= "=3.0.0"` — both candidates, via
  package rename (semver-incompatible majors coexist in one graph)

Feature selection removes every RNG path (`getrandom` never enters the
lockfile): keys derive from fixed 32-byte seeds, ML-DSA signs with the
FIPS 204 deterministic variant, Ed25519 is deterministic by construction.

## Run

```sh
cargo test                                          # native probes + golden
cargo build --release --target wasm32-unknown-unknown
node run-wasm.mjs target/wasm32-unknown-unknown/release/sig_probe.wasm
```

The wasm module has no imports (no wasm-bindgen, no getrandom backend), so
plain `WebAssembly.instantiate` executes it; the runner compares the wasm
selfcheck bitmask and transcript SHA-256 against the native golden pinned
in `tests/transcript.rs`.

## Recorded results (2026-07-27, toolchain 1.92.0, x86_64 linux + node v24.12.0)

- native: 27/27 selfcheck invariants pass; transcript SHA-256
  `92354c8d75efdc6dfd26cea301243e35ba0776753c61127846b77c8a3cffa298`
  (10714 bytes)
- wasm32-unknown-unknown (executed in node): selfcheck `0x07ffffff`,
  transcript SHA-256 **identical** — real bit-match, not compile-only
- `sig_probe.wasm` (all four crates, `opt-level = "s"`): 257,971 bytes
- probe `Cargo.lock`: **zero** `getrandom` entries

The fixture seeds in `src/lib.rs` are counting patterns (`00 01 02 …`) —
probe fixtures, not secrets; nothing here derives from any vault material.
