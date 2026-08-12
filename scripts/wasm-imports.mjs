#!/usr/bin/env node
// The import ALLOW-LIST over a built wasm module — the structural half of
// R22's "No I/O inside the WASM module" (decision D18 §5 R7).
//
//     node scripts/wasm-imports.mjs <module.wasm>
//     node scripts/wasm-imports.mjs --self-test
//
// Exit 0 iff every import in the module's import table matches a rule below.
//
// ── Why an import table is the right thing to check ────────────────────────
//
// A WebAssembly module can call exactly the host functions it IMPORTS, and
// imports are generated only from declared `extern` bindings. There is no
// ambient capability: no syscall, no clock, no socket, no `fetch` reaches the
// module unless it appears in this table BY NAME. So an enumerated import
// table is a complete statement of everything the module can ask the browser
// to do — which is what makes this decidable from the artifact rather than
// argued from the source.
//
// The sibling rule (`scripts/ci-lanes.sh dep-graph`, D18 §5 R6) decides the
// same property from the dependency graph. Neither alone is the property:
// a graph says what CAN be reached, a table says what IS reachable.
//
// ── What changed, and what did not ─────────────────────────────────────────
//
// Every other wasm artifact in this repository asserts ZERO imports
// (`scripts/wasm-test-runner.mjs`, `scripts/wasm-bitmatch.mjs`). The shipped
// page module cannot: a typed JS error object and a panic hook both need a
// host, which is exactly why D18 §4.1 refused the glue-free raw-C-ABI arm.
// The honest description is that the property changes from "asserts nothing"
// to "asserts exactly this list" (D18 §10) — and the list is reviewed on every
// change like any other allow-list here.
//
// ── Two artifact shapes, one list ──────────────────────────────────────────
//
// The same module is checked at two points in its life and its import table
// is spelled differently at each:
//
//   * as `cargo build` emits it — imports sit in the wasm-bindgen PLACEHOLDER
//     modules and the CLI has not yet rewritten them;
//   * as `wasm-pack`/`wasm-bindgen-cli` emits it — the placeholders have been
//     resolved to the generated `./<pkg>_bg.js` glue module.
//
// Both are enumerated, because both are checked: the first rides
// `wasm-bitmatch` (cargo only, no new tool in CI), the second runs inside
// `scripts/wasm-pack-build.sh` against the artifact the page actually loads.

import { readFileSync } from "node:fs";

// ── THE ALLOW-LIST ─────────────────────────────────────────────────────────
//
// Every entry states the host capability it grants. Adding one is a review
// event: if a new name cannot be described in that column, it does not belong
// in a module whose contract is that it does no I/O.
const ALLOWED = [
  {
    module: /^\.\/[a-z0-9_]+_bg\.js$/,
    name: /^__wbg___wbindgen_throw_[0-9a-f]{16}$/,
    why: "throw a JS exception carrying a string — how a Rust panic and a typed error leave the module",
  },
  {
    module: /^\.\/[a-z0-9_]+_bg\.js$/,
    name: /^__wbg_Error_[0-9a-f]{16}$/,
    why: "construct a JS `Error` — R22 Accept row 3's typed error object",
  },
  {
    module: /^\.\/[a-z0-9_]+_bg\.js$/,
    name: /^__wbindgen_init_externref_table$/,
    why: "initialise the module's OWN externref table; touches nothing outside the instance",
  },
  {
    module: /^__wbindgen_placeholder__$/,
    name: /^__wbindgen_describe$/,
    why: "pre-CLI type-description shim; wasm-bindgen resolves it away — never present in a shipped module",
  },
  {
    module: /^__wbindgen_placeholder__$/,
    name: /^__wbg___wbindgen_throw_[0-9a-f]{16}$/,
    why: "pre-CLI form of the throw shim above",
  },
  {
    module: /^__wbindgen_placeholder__$/,
    name: /^__wbg_Error_[0-9a-f]{16}$/,
    why: "pre-CLI form of the Error constructor above",
  },
  {
    module: /^__wbindgen_externref_xform__$/,
    name: /^__wbindgen_externref_table_(grow|set_null)$/,
    why: "pre-CLI form of the module's own externref table management",
  },
];

// The names this check exists to refuse. Kept as a separate, EARLIER layer for
// the reason `ci-lanes.sh`'s denylist is: "you imported fetch" is a more useful
// failure than "an unlisted import arrived". A capability that reaches the
// module under one of these names is not a review question.
const CAPABILITY_SHAPED = [
  /fetch/i,
  /XMLHttpRequest/i,
  /WebSocket/i,
  /localStorage/i,
  /sessionStorage/i,
  /indexedDB/i,
  /\bDate\b/,
  /now/i,
  /random/i,
  /crypto/i,
  /^env\./,
  /wasi/i,
];

function fail(message) {
  console.error(`::error::wasm-imports: ${message}`);
  process.exit(1);
}

/// Every import of `bytes`, as `{module, name, kind}`.
function importsOf(bytes, label) {
  let module;
  try {
    module = new WebAssembly.Module(bytes);
  } catch (error) {
    fail(`${label} is not a valid WebAssembly module: ${error?.message ?? error}`);
  }
  return WebAssembly.Module.imports(module);
}

/// The verdict for one module. Returns an array of complaints (empty = pass).
function check(imports) {
  const complaints = [];
  for (const entry of imports) {
    const spelled = `${entry.module}.${entry.name}`;
    const capability = CAPABILITY_SHAPED.find((pattern) => pattern.test(spelled));
    if (capability) {
      complaints.push(
        `${spelled} (${entry.kind}) — a HOST CAPABILITY import matching ${capability}. ` +
          "R22's contract is that the module does no I/O; an import is the only way one could.",
      );
      continue;
    }
    const rule = ALLOWED.find(
      (candidate) => candidate.module.test(entry.module) && candidate.name.test(entry.name),
    );
    if (!rule) {
      complaints.push(
        `${spelled} (${entry.kind}) — not on the allow-list. Every import is a host function ` +
          "the module can call: either it is wasm-bindgen runtime plumbing (add it above WITH the " +
          "capability it grants) or it is a capability this module must not have.",
      );
    }
  }
  return complaints;
}

// ── The test of the test ───────────────────────────────────────────────────
//
// A green allow-list proves nothing until the list has been seen to reject
// something, so `--self-test` builds two modules by hand — no cargo, no
// toolchain, milliseconds — and requires one to pass and the other to fail.
// Both directions, because a checker that rejects everything is as useless as
// one that rejects nothing.
function handcraftedModule(importModule, importName) {
  const bytes = [0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];
  // type section: one type, () -> ()
  bytes.push(0x01, 0x04, 0x01, 0x60, 0x00, 0x00);
  const mod = [...Buffer.from(importModule, "utf8")];
  const nam = [...Buffer.from(importName, "utf8")];
  const payload = [0x01, mod.length, ...mod, nam.length, ...nam, 0x00, 0x00];
  bytes.push(0x02, payload.length, ...payload);
  return new Uint8Array(bytes);
}

function selfTest() {
  let failed = 0;

  // (a) the planted capability MUST be refused, and the refusal must name it.
  const planted = handcraftedModule("env", "fetch");
  const plantedComplaints = check(importsOf(planted, "the planted module"));
  if (plantedComplaints.length === 0) {
    console.error("::error::wasm-imports self-test FAILED: a planted `env.fetch` import PASSED the allow-list");
    failed = 1;
  } else if (!plantedComplaints[0].includes("env.fetch")) {
    console.error(
      `::error::wasm-imports self-test FAILED: the planted import was refused but the message does not name it: ${plantedComplaints[0]}`,
    );
    failed = 1;
  } else {
    console.log(`  planted import: env.fetch                       -> REFUSED (${plantedComplaints[0].slice(0, 72)}…)`);
  }

  // (b) a real allow-listed import MUST pass — otherwise the list rejects
  //     everything and (a) proves nothing about it.
  const legitimate = handcraftedModule("./antseal_wasm_bg.js", "__wbindgen_init_externref_table");
  const legitimateComplaints = check(importsOf(legitimate, "the control module"));
  if (legitimateComplaints.length > 0) {
    console.error(
      `::error::wasm-imports self-test FAILED: an allow-listed import was refused, so the list refuses everything: ${legitimateComplaints[0]}`,
    );
    failed = 1;
  } else {
    console.log("  control import: ./antseal_wasm_bg.js.__wbindgen_init_externref_table -> ALLOWED");
  }

  // (c) anti-vacuity: the allow-list must not be empty, and the capability
  //     layer must not be either. An emptied list would make (b) pass and (a)
  //     fail loudly, so this is belt-and-braces — but a list is exactly the
  //     kind of thing that gets emptied during a refactor.
  if (ALLOWED.length === 0 || CAPABILITY_SHAPED.length === 0) {
    console.error("::error::wasm-imports self-test FAILED: an empty rule list asserts nothing");
    failed = 1;
  }

  if (failed) process.exit(1);
  console.log("wasm-imports self-test PASS — the allow-list refuses a planted capability and admits the runtime shims");
}

const [target] = process.argv.slice(2);
if (!target) {
  fail("usage: node scripts/wasm-imports.mjs <module.wasm> | --self-test");
}
if (target === "--self-test") {
  selfTest();
  process.exit(0);
}

let bytes;
try {
  bytes = readFileSync(target);
} catch (error) {
  fail(`cannot read ${target}: ${error?.message ?? error}`);
}

const imports = importsOf(bytes, target);
const complaints = check(imports);

console.log(`wasm-imports: ${target}`);
console.log(`  ${imports.length} import(s):`);
for (const entry of imports) {
  console.log(`    ${entry.module}.${entry.name} (${entry.kind})`);
}
if (complaints.length > 0) {
  for (const complaint of complaints) {
    console.error(`::error::wasm-imports: ${complaint}`);
  }
  fail(
    `${complaints.length} import(s) are not on the allow-list — the module can ask the host for ` +
      "something R22 says it must not (D18 §5 R7)",
  );
}
console.log("  OK: every import is allow-listed wasm-bindgen runtime plumbing; no host capability is reachable.");
