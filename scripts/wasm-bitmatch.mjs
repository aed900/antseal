#!/usr/bin/env node
// The wasm32 side of the Q5 native<->WASM bit-match.
//
//     node scripts/wasm-bitmatch.mjs <wasm-bitmatch.wasm> <native-transcript>
//
// Normally invoked by ./scripts/wasm-bitmatch.sh, which produces the native
// transcript first. Exit 0 iff the wasm32 module's transcript is
// BYTE-IDENTICAL to the native one.
//
// The module is pure computation with zero imports (asserted below): the
// golden vectors are embedded at build time, so nothing flows in and the
// only ABI is `bitmatch_len()` / `bitmatch_ptr()` into the exported memory.
// Same technique as scripts/wasm-test-runner.mjs and the C11 probe —
// docs/wasm-toolchain.md.

import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";

// Must equal wasm_bitmatch::TRANSCRIPT_VERSION. Bumping it there without
// bumping it here is caught immediately, by design.
//
// It versions the transcript ENVELOPE — the field set of the JSON this
// runner parses — and nothing else. In particular it is NOT coupled to
// antseal_core's REPORT_VERSION: R32 bumped that to 1 and this stayed 0,
// because the transcript carries no report field, aggregates all seven
// vector kinds rather than the report alone, and is never frozen (it lives
// in target/, in no FROZEN.sha256). Move it when a transcript field is
// added, removed, renamed or reordered — never for a change in what the
// fields contain. See crates/wasm-bitmatch/src/lib.rs.
const EXPECTED_TRANSCRIPT_VERSION = 0;
const NODE_MAJOR_FLOOR = 18;

function fail(message) {
  console.error(`::error::wasm-bitmatch: ${message}`);
  process.exit(1);
}

const nodeMajor = Number.parseInt(process.versions.node.split(".")[0], 10);
if (!Number.isFinite(nodeMajor) || nodeMajor < NODE_MAJOR_FLOOR) {
  fail(`node ${process.versions.node} is below the v${NODE_MAJOR_FLOOR} floor`);
}

const [wasmPath, nativePath] = process.argv.slice(2);
if (!wasmPath || !nativePath) {
  fail("usage: node scripts/wasm-bitmatch.mjs <wasm-bitmatch.wasm> <native-transcript>");
}

const native = readFileSync(nativePath);
const module = await WebAssembly.compile(readFileSync(wasmPath));

const imports = WebAssembly.Module.imports(module);
if (imports.length > 0) {
  fail(
    "the bit-match module has imports, so it is no longer self-contained: " +
      imports.map((i) => `${i.module}.${i.name}`).join(", "),
  );
}

const { exports } = await WebAssembly.instantiate(module, {});
for (const name of ["bitmatch_len", "bitmatch_ptr", "bitmatch_transcript_version"]) {
  if (typeof exports[name] !== "function") fail(`the module exports no \`${name}\``);
}
if (!(exports.memory instanceof WebAssembly.Memory)) fail("the module exports no `memory`");

const version = exports.bitmatch_transcript_version() >>> 0;
if (version !== EXPECTED_TRANSCRIPT_VERSION) {
  fail(
    `transcript_version ${version} != ${EXPECTED_TRANSCRIPT_VERSION} expected by this runner — ` +
      "update EXPECTED_TRANSCRIPT_VERSION together with wasm_bitmatch::TRANSCRIPT_VERSION",
  );
}

const length = exports.bitmatch_len() >>> 0;
const pointer = exports.bitmatch_ptr() >>> 0;
if (length === 0) fail("the wasm transcript is empty");
if (pointer + length > exports.memory.buffer.byteLength) {
  fail(`transcript (ptr ${pointer}, len ${length}) lies outside the exported memory`);
}
const wasm = Buffer.from(new Uint8Array(exports.memory.buffer, pointer, length));

const nativeHash = createHash("sha256").update(native).digest("hex");
const wasmHash = createHash("sha256").update(wasm).digest("hex");

console.log(`wasm-bitmatch (node ${process.versions.node})`);
console.log(`  native transcript: ${native.length} bytes, sha256 ${nativeHash}`);
console.log(`  wasm32 transcript: ${wasm.length} bytes, sha256 ${wasmHash}`);

if (!wasm.equals(native)) {
  // Locate and show the first difference — a bit-match failure is a
  // debugging task, so the lane must hand over evidence, not just a verdict.
  const limit = Math.min(wasm.length, native.length);
  let at = limit;
  for (let i = 0; i < limit; i += 1) {
    if (wasm[i] !== native[i]) {
      at = i;
      break;
    }
  }
  const from = Math.max(0, at - 40);
  const to = at + 40;
  console.error(`  first difference at byte ${at} (of ${native.length} native / ${wasm.length} wasm)`);
  console.error(`  native …${native.subarray(from, to).toString("utf8")}…`);
  console.error(`  wasm32 …${wasm.subarray(from, to).toString("utf8")}…`);
  fail(
    "wasm32 transcript differs from native — the WASM build does NOT bit-match native " +
      "verification (MVP-SPEC.md lines 167/169). Diff the two transcripts to find the diverging vector.",
  );
}
if (wasmHash !== nativeHash) fail("bytes compared equal but hashes differ — impossible; hasher broken");

// A vacuously-green lane is the failure mode a bit-match must never have.
let parsed;
try {
  parsed = JSON.parse(wasm.toString("utf8"));
} catch (error) {
  fail(`the transcript is not valid JSON: ${error?.message ?? error}`);
}
if (!Number.isInteger(parsed.vector_count) || parsed.vector_count < 1) {
  fail(`the transcript covers ${parsed.vector_count} vector(s) — a bit-match over nothing asserts nothing`);
}
const failed = (parsed.entries ?? []).filter((e) => e.status !== "executed");
if (failed.length > 0) {
  fail(
    `${failed.length} vector(s) did not execute on BOTH sides (identically, hence not a divergence — ` +
      `a real vector failure): ${failed.map((e) => `${e.path}: ${e.error}`).join(" | ")}`,
  );
}

console.log(
  `  OK: byte-identical over ${parsed.vector_count} vector(s), all executed; ` +
    `transcript_version ${version}`,
);
for (const entry of parsed.entries) {
  console.log(`     ${entry.path} — ${entry.items} item(s), recomputed ${entry.recomputed_digest}`);
}
