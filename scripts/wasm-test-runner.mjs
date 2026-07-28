#!/usr/bin/env node
// Headless wasm32-unknown-unknown test runner (P14).
//
// Wired as cargo's runner for the target in `.cargo/config.toml`, so
//
//     cargo test -p antseal-core --lib --target wasm32-unknown-unknown
//
// builds the libtest binary and hands it here. Usage when invoked by hand:
//
//     node scripts/wasm-test-runner.mjs <path-to-libtest.wasm> [libtest args]
//
// Why this and not wasm-bindgen-test: a Rust libtest binary built for
// wasm32-unknown-unknown has **zero imports** and exports `main` plus
// `memory`, so `WebAssembly.instantiate` runs it with no JS glue, no
// wasm-bindgen crate/CLI pin, and no browser — and therefore commits
// nothing about D18 (wasm-bindgen surface location, due M3). The same
// technique is the C11 probe's executed native<->wasm bit-match
// (docs/research/C11-signature-probe.md §5). Full rationale, including what
// this runner can and cannot observe: docs/wasm-toolchain.md.
//
// Observable outcomes on this target:
//   * `main` returns 0            -> every test passed
//   * the module traps            -> a test failed (panic = abort here)
//   * stdout                      -> DISCARDED by std; libtest's report is
//                                    unreadable, hence the witness below
//
// Non-vacuity: `main` returning 0 would look identical if the binary had
// lost all its tests. The runner therefore scans linear memory for the
// execution witness written by `antseal_core::tests::wasm_lane_execution_witness`
// — absent before `main`, present after. Both halves are asserted.

import { readFileSync } from "node:fs";

// Node is the wasm *host*, not a build tool: it never contributes a byte to
// a published artifact (unlike wasm-pack/wasm-bindgen, which are exact-pinned
// under docs/dependency-policy.md §5 precisely because they do). Only stable
// APIs are used — `WebAssembly`, `node:fs`, `node:crypto` — so the version is
// not pinned; a floor is asserted instead, and the version is logged.
const NODE_MAJOR_FLOOR = 18;

// Little-endian image of the u64 assembled in the witness test from its two
// u32 halves (WITNESS_LO = 0x3057414d, WITNESS_HI = 0x314e414c).
// Kept as bytes, never as a string literal, so nothing here can be mistaken
// for the pattern itself.
const WITNESS = Uint8Array.from([0x4d, 0x41, 0x57, 0x30, 0x4c, 0x41, 0x4e, 0x31]);

/** Count non-overlapping occurrences of `needle` in `haystack`. */
function countPattern(haystack, needle) {
  let hits = 0;
  outer: for (let i = 0; i + needle.length <= haystack.length; i += 1) {
    for (let j = 0; j < needle.length; j += 1) {
      if (haystack[i + j] !== needle[j]) continue outer;
    }
    hits += 1;
    i += needle.length - 1;
  }
  return hits;
}

function fail(message) {
  console.error(`::error::wasm32 test runner: ${message}`);
  process.exit(1);
}

const nodeMajor = Number.parseInt(process.versions.node.split(".")[0], 10);
if (!Number.isFinite(nodeMajor) || nodeMajor < NODE_MAJOR_FLOOR) {
  console.error(
    `::error::wasm32 test runner: node ${process.versions.node} is below the v${NODE_MAJOR_FLOOR} floor`,
  );
  process.exit(1);
}

const [wasmPath, ...passthrough] = process.argv.slice(2);
if (!wasmPath) fail("usage: node scripts/wasm-test-runner.mjs <path-to.wasm> [args]");
if (passthrough.length > 0) {
  // libtest reads its options from argv, which is empty on this target: we
  // cannot forward filters, so silently "honouring" them would be a lie.
  fail(
    `libtest arguments are NOT forwarded on wasm32-unknown-unknown (got: ${passthrough.join(" ")}). ` +
      "Run the unfiltered suite, or use the native target for filtered runs.",
  );
}

const bytes = readFileSync(wasmPath);
const module = await WebAssembly.compile(bytes);

// A non-empty import list means the module grew a dependency on JS glue —
// the runner would then be silently instantiating a different program than
// the one the lane promises. Fail rather than synthesise stubs.
const imports = WebAssembly.Module.imports(module);
if (imports.length > 0) {
  fail(
    "the test binary has imports, so it is no longer self-contained: " +
      imports.map((i) => `${i.module}.${i.name}`).join(", "),
  );
}

const instance = await WebAssembly.instantiate(module, {});
const { main, memory } = instance.exports;
if (typeof main !== "function") fail("the test binary exports no `main`");
if (!(memory instanceof WebAssembly.Memory)) fail("the test binary exports no `memory`");

const before = countPattern(new Uint8Array(memory.buffer), WITNESS);
if (before !== 0) {
  fail(
    `execution witness already present in linear memory BEFORE main() (${before} hit(s)) — ` +
      "the witness is compromised (constant-promoted into the data section?) and proves nothing; " +
      "fix antseal_core::tests::wasm_lane_execution_witness before trusting this lane",
  );
}

let rc;
try {
  rc = main(0, 0);
} catch (error) {
  fail(
    `the test binary trapped: ${error?.message ?? error}. ` +
      "On wasm32-unknown-unknown a failing test aborts the module — this IS a test failure. " +
      "Reproduce natively with: cargo test -p antseal-core --lib",
  );
}
if (rc !== 0) fail(`main() returned ${rc} (expected 0)`);

const after = countPattern(new Uint8Array(memory.buffer), WITNESS);
if (after === 0) {
  fail(
    "main() returned 0 but the execution witness is absent — the suite ran ZERO tests. " +
      "A green lane here would assert nothing (P14 non-vacuity check).",
  );
}

console.log(
  `wasm32 test runner (node ${process.versions.node}): ${wasmPath} — main() = 0, ` +
    `execution witness present (${after} hit(s)); imports: 0; ` +
    `memory: ${memory.buffer.byteLength} B`,
);
