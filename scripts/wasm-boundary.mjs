#!/usr/bin/env node
// R22's Accept rows, executed against the artifact the page actually loads.
//
//     node scripts/wasm-boundary.mjs <pkg-dir> <native-corpus.json>
//
// Normally invoked by ./scripts/wasm-pack-build.sh, which produces both.
// Exit 0 iff every row below holds.
//
// ── The comparison ─────────────────────────────────────────────────────────
//
// `crates/antseal-wasm/examples/boundary-emit.rs` rebuilds every case of R9's
// committed `report` vector document and runs `verify_bundle` NATIVELY under
// `VerifyOptions::new()`. This script feeds the same bundle bytes through the
// module's `verify()` export and requires the two report byte strings to be
// identical.
//
// Native ≡ wasm32 FOR ONE INPUT — not binding ≡ vector file. The committed
// `report_json` values pin the storage-linkage-SUPPRESSED tuple (D128 §3 R3,
// stated at `vectors_report::build_expect`), while R22's export takes no
// options and therefore always runs the layer; comparing against the file
// would fail for a reason that says nothing about the boundary. R22's Accept
// row 2 was corrected in place to say exactly this.
//
// ── Why the module is copied to .mjs ───────────────────────────────────────
//
// `wasm-pack --target web` emits an ES module named `.js`, and this repository
// has no `package.json`, so node reads a bare `.js` as CommonJS and refuses
// its `export` statements. The copy is made in a SEPARATE directory so the
// published artifact set stays exactly what `wasm-pack` wrote — D63 §5 R4
// computes its sums over that directory and requires byproducts to be absent
// from it.

import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { pathToFileURL } from "node:url";

const NODE_MAJOR_FLOOR = 18;

function fail(message) {
  console.error(`::error::wasm-boundary: ${message}`);
  process.exit(1);
}

const nodeMajor = Number.parseInt(process.versions.node.split(".")[0], 10);
if (!Number.isFinite(nodeMajor) || nodeMajor < NODE_MAJOR_FLOOR) {
  fail(`node ${process.versions.node} is below the v${NODE_MAJOR_FLOOR} floor`);
}

const [pkgDir, corpusPath] = process.argv.slice(2);
if (!pkgDir || !corpusPath) {
  fail("usage: node scripts/wasm-boundary.mjs <pkg-dir> <native-corpus.json>");
}

const glue = resolve(pkgDir, "antseal_wasm.js");
const wasmPath = resolve(pkgDir, "antseal_wasm_bg.wasm");
const harnessDir = resolve(dirname(resolve(pkgDir)), "node-harness");
mkdirSync(harnessDir, { recursive: true });
const harnessGlue = join(harnessDir, "antseal_wasm.mjs");
writeFileSync(harnessGlue, readFileSync(glue));

const module_ = await import(pathToFileURL(harnessGlue).href);
module_.initSync({ module: readFileSync(wasmPath) });
console.log(`wasm-boundary (node ${process.versions.node}) — module loaded from ${pkgDir}`);

let failures = 0;
function check(label, condition, detail) {
  if (condition) {
    console.log(`  OK   ${label}`);
  } else {
    console.error(`::error::wasm-boundary: ${label} — ${detail}`);
    failures += 1;
  }
}

function hexToBytes(hex) {
  return Buffer.from(hex, "hex");
}

// ── 1. the closed export list (D18 §5 R4) ──────────────────────────────────
//
// Four entries plus the panic-hook start function, and NOTHING ELSE. The
// upper bound is the half that matters: additions are a decision, not a code
// change, and a fifth export is how that rule would quietly stop holding.
const EXPECTED_EXPORTS = ["verify", "verify_online", "verdict_class", "build_info", "start"];
const actualExports = Object.keys(module_).filter((name) => typeof module_[name] === "function");
const unexpected = actualExports.filter(
  (name) => !EXPECTED_EXPORTS.includes(name) && !["initSync", "default"].includes(name),
);
const missing = EXPECTED_EXPORTS.filter((name) => !actualExports.includes(name));
check(
  "the JS surface is the closed export list",
  unexpected.length === 0 && missing.length === 0,
  `unexpected: [${unexpected}] missing: [${missing}] — D18 §5 R4 closes the surface at four entries plus the panic hook`,
);

// ── 2. build info (D63 §5 R3) ──────────────────────────────────────────────
const info = JSON.parse(module_.build_info());
check(
  "build_info() carries the core version, the supported format versions and a commit",
  typeof info.core_version === "string" &&
    info.core_version.length > 0 &&
    Array.isArray(info.supported_format_versions) &&
    info.supported_format_versions.length > 0 &&
    typeof info.source_commit === "string" &&
    info.source_commit.length > 0,
  `got ${JSON.stringify(info)} — R27/Q19 compare the rendered footer against this export`,
);
check(
  "build_info() carries no self-digest",
  !Object.keys(info).some((key) => /sha|digest|hash/i.test(key)),
  `D63 §4 refuses the fixed point and §11.3 forbids a self-hash entry point; got keys [${Object.keys(info)}]`,
);
console.log(`       build info: ${JSON.stringify(info)}`);

// ── 3. R9 vectors through the JS boundary (Accept row 2) ───────────────────
const corpus = JSON.parse(readFileSync(corpusPath, "utf8"));
if (!Array.isArray(corpus.cases) || corpus.cases.length === 0) {
  fail("the native corpus carries no cases — a comparison over nothing asserts nothing");
}

let identical = 0;
for (const entry of corpus.cases) {
  const bundle = hexToBytes(entry.bundle_hex);
  const expected = hexToBytes(entry.report_hex);
  let actual;
  try {
    actual = Buffer.from(module_.verify(bundle), "utf8");
  } catch (error) {
    console.error(
      `::error::wasm-boundary: ${entry.shape} — the module threw for a bundle that verifies natively: ${error?.message ?? error}`,
    );
    failures += 1;
    continue;
  }
  if (actual.equals(expected)) {
    identical += 1;
    continue;
  }
  const limit = Math.min(actual.length, expected.length);
  let at = limit;
  for (let i = 0; i < limit; i += 1) {
    if (actual[i] !== expected[i]) {
      at = i;
      break;
    }
  }
  console.error(
    `::error::wasm-boundary: ${entry.shape} — the report differs from native at byte ${at} ` +
      `(native ${expected.length} bytes, wasm32 ${actual.length})\n` +
      `  native …${expected.subarray(Math.max(0, at - 40), at + 40).toString("utf8")}…\n` +
      `  wasm32 …${actual.subarray(Math.max(0, at - 40), at + 40).toString("utf8")}…`,
  );
  failures += 1;
}
check(
  `all ${corpus.cases.length} R9 vectors produce reports byte-identical to native`,
  identical === corpus.cases.length,
  `${identical}/${corpus.cases.length} matched — MVP-SPEC.md lines 167/169 require the WASM build to bit-match native verification`,
);

// ── 4. the storage-linkage layer runs (D128, R22's fourth Accept row) ──────
const firstReport = JSON.parse(module_.verify(hexToBytes(corpus.cases[0].bundle_hex)));
check(
  "verify() runs the storage-linkage layer",
  Object.prototype.hasOwnProperty.call(firstReport, "storage_linkage") &&
    JSON.stringify(firstReport.storage_linkage).includes("evaluated"),
  `storage_linkage is ${JSON.stringify(firstReport.storage_linkage)} — the export takes no options, so the page has nothing to opt in with (D128 §3 R5)`,
);

// ── 5. malformed input is a typed JS error, never a trap (Accept row 3) ────
const HOSTILE = [
  ["empty input", new Uint8Array(0)],
  ["random bytes", new Uint8Array([0xde, 0xad, 0xbe, 0xef, 0x00, 0x01, 0x02])],
  ["truncated bundle", hexToBytes(corpus.cases[0].bundle_hex).subarray(0, 32)],
  ["a flipped byte", (() => {
    const bytes = Buffer.from(hexToBytes(corpus.cases[0].bundle_hex));
    bytes[bytes.length - 1] ^= 0xff;
    return bytes;
  })()],
];
for (const [label, bytes] of HOSTILE) {
  let thrown = null;
  try {
    module_.verify(bytes);
  } catch (error) {
    thrown = error;
  }
  check(
    `malformed input (${label}) throws a typed Error`,
    thrown instanceof Error && typeof thrown.message === "string" && thrown.message.length > 0,
    `got ${thrown === null ? "NO THROW — the module accepted a bundle it must refuse" : Object.prototype.toString.call(thrown)}`,
  );
  if (thrown instanceof Error) {
    check(
      `malformed input (${label}) names a stable rejection code`,
      /^[a-z0-9]+(-[a-z0-9]+)+: /.test(thrown.message),
      `message was ${JSON.stringify(thrown.message)} — antseal-core's frozen code belongs in front of the sentence`,
    );
  }
}

// ── 6. the rung datum (D18 §5 R4 entry 4 / D69) ────────────────────────────
const verdict = JSON.parse(module_.verdict_class(hexToBytes(corpus.cases[0].bundle_hex)));
check(
  "verdict_class() exposes the rung and its counts",
  Object.prototype.hasOwnProperty.call(verdict, "rung") &&
    typeof verdict.unanchored === "boolean" &&
    typeof verdict.total_anchors === "number",
  `got ${JSON.stringify(verdict)} — the page must state the rung from the module, never recompute it in JS`,
);
check(
  "the rung is NOT a field of the report",
  !Object.prototype.hasOwnProperty.call(firstReport, "rung"),
  "if the rung were a report field the fourth export would not exist (D18 §5 R4 entry 4)",
);

// ── 7. the online entry accepts a PRE-FETCHED document ─────────────────────
const emptyEvidence = JSON.stringify({
  schema: "antseal.online-evidence.v1",
  endpoints: { identities: ["https://one.example", "https://two.example"], overridden: false },
  blocks: [],
});
const overlay = JSON.parse(
  module_.verify_online(hexToBytes(corpus.cases[0].bundle_hex), emptyEvidence),
);
check(
  "verify_online() returns an overlay document",
  typeof overlay.framing_line === "string" && overlay.framing_line.length > 0,
  `got ${JSON.stringify(overlay).slice(0, 200)}`,
);
check(
  "the online run leaves the offline report bytes untouched (D64 §3)",
  Buffer.from(module_.verify(hexToBytes(corpus.cases[0].bundle_hex)), "utf8").equals(
    hexToBytes(corpus.cases[0].report_hex),
  ),
  "the overlay is a sibling document and may never move a report byte",
);
let evidenceError = null;
try {
  module_.verify_online(hexToBytes(corpus.cases[0].bundle_hex), "{\"schema\":\"wrong\"}");
} catch (error) {
  evidenceError = error;
}
check(
  "a malformed online-evidence document throws rather than being read leniently",
  evidenceError instanceof Error && /online-evidence document/.test(evidenceError.message),
  `got ${evidenceError === null ? "NO THROW" : JSON.stringify(evidenceError.message)}`,
);

if (failures > 0) {
  fail(`${failures} boundary row(s) failed`);
}
console.log(
  `  OK: ${corpus.cases.length} vector(s) byte-identical through the JS boundary, ` +
    `typed errors for hostile input, closed export list, build info present.`,
);
