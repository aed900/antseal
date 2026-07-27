#!/usr/bin/env node
// C11 probe: execute the sig-probe wasm artifact and byte-compare its
// deterministic transcript against the native golden.
//
//   cargo build --release --target wasm32-unknown-unknown
//   node run-wasm.mjs target/wasm32-unknown-unknown/release/sig_probe.wasm
//
// The module is pure computation with no imports (no wasm-bindgen, no JS
// glue, no getrandom backend — the probe's dependency selection needs no
// RNG), so plain WebAssembly.instantiate suffices. Exit code 0 iff the
// selfcheck bitmask AND the transcript SHA-256 both match the native
// expectations.

import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";

// Must mirror sig_probe::EXPECTED_SELFCHECK ((1 << 27) - 1).
const EXPECTED_SELFCHECK = 0x07ff_ffff;
// Must mirror tests/transcript.rs GOLDEN_TRANSCRIPT_SHA256.
const GOLDEN_TRANSCRIPT_SHA256 = "92354c8d75efdc6dfd26cea301243e35ba0776753c61127846b77c8a3cffa298";

const path = process.argv[2] ?? "target/wasm32-unknown-unknown/release/sig_probe.wasm";
const bytes = readFileSync(path);

const { instance } = await WebAssembly.instantiate(bytes, {});
const ex = instance.exports;

const selfcheck = ex.probe_selfcheck() >>> 0;
const len = ex.probe_out_len() >>> 0;
const ptr = ex.probe_out_ptr() >>> 0;
const transcript = Buffer.from(new Uint8Array(ex.memory.buffer, ptr, len));
const hash = createHash("sha256").update(transcript).digest("hex");

console.log(`wasm selfcheck        = 0x${selfcheck.toString(16).padStart(8, "0")}`);
console.log(`wasm transcript len   = ${len}`);
console.log(`wasm transcript sha256 = ${hash}`);

let ok = true;
if (selfcheck !== EXPECTED_SELFCHECK) {
  console.error(
    `FAIL: selfcheck != 0x${EXPECTED_SELFCHECK.toString(16)} — behavioral divergence on wasm32`,
  );
  ok = false;
}
if (hash !== GOLDEN_TRANSCRIPT_SHA256) {
  console.error("FAIL: transcript hash != native golden — wasm/native byte divergence");
  ok = false;
}
if (ok) console.log("OK: wasm32 output bit-matches the native golden");
process.exit(ok ? 0 : 1);
