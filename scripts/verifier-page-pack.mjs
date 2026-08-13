#!/usr/bin/env node
// R25 — package the verifier page into the ONE file D129 §5 R1 rules, and
// assert the eight properties of D129 §5 R9 against the built artifact.
//
//   node scripts/page-build.mjs <pkg-dir> <template> <out-dir>
//   node scripts/page-build.mjs --self-test
//
// The ordering is D129 §5 R8's and is not free: glue -> base64 -> footer
// digest -> compute the script and style hashes over the FINAL text -> CSP
// hashes -> SHA256SUMS. There is no fixed point, because the <meta> lives in
// <head>, outside every <script> and <style>, so no hashed text ever contains
// a hash of itself.
//
// Substitution is NOT idempotent (D63 §5 R1): running this over an already
// injected file is a hard error, never a silent no-op, for all four tokens.
import { readFileSync, writeFileSync, mkdirSync, rmSync, readdirSync } from "node:fs";
import { createHash } from "node:crypto";
import { resolve, join } from "node:path";

const TOKENS = {
  glue: "__ANTSEAL_GLUE__",
  base64: "__ANTSEAL_MODULE_BASE64__",
  digest: "__ANTSEAL_MODULE_SHA256__",
  scriptHashes: "__ANTSEAL_CSP_SCRIPT_HASHES__",
  styleHash: "__ANTSEAL_CSP_STYLE_HASH__",
};

function die(message) {
  console.error(`::error::page-build: ${message}`);
  process.exit(1);
}

const sha256Base64 = (text) => createHash("sha256").update(text, "utf8").digest("base64");
const sha256Hex = (bytes) => createHash("sha256").update(bytes).digest("hex");

// Text between the open and close of the element whose open tag matches `open`.
// The CSP hashes cover the EXACT text content of each element, so this must be
// the element's bytes and nothing around them.
function elementText(html, open, close, from = 0) {
  const start = html.indexOf(open, from);
  if (start < 0) return null;
  const textStart = start + open.length;
  const end = html.indexOf(close, textStart);
  if (end < 0) return null;
  return { text: html.slice(textStart, end), start: textStart, end };
}

function build(pkgDir, templatePath, outDir) {
  const template = readFileSync(templatePath, "utf8");
  const glue = readFileSync(resolve(pkgDir, "antseal_wasm.js"), "utf8");
  const wasm = readFileSync(resolve(pkgDir, "antseal_wasm_bg.wasm"));

  // ── R9.5 (half) — no re-injection, over all four tokens ──────────────────
  for (const [name, token] of Object.entries(TOKENS)) {
    if (!template.includes(token)) {
      die(`the template does not carry the ${name} token ${token} — either it was already injected (D63 §5 R1 makes that a hard error, never a no-op) or the template is not the one this script packages`);
    }
  }

  // ── R9.4 — textual safety, asserted rather than assumed (D129 §1 p) ──────
  for (const needle of ["</script", "<script", "<!--", "-->", "<!"]) {
    if (glue.includes(needle)) {
      die(`the wasm-pack glue contains ${JSON.stringify(needle)}, so inlining it into a <script> element is not textually safe. This is code this project does not author; D129 §5 R9 assertion 4 exists because it can change under us`);
    }
  }
  // D131 §5 R6 — ONE LINE, unwrapped, and asserted so. Not on the silent-skip
  // hazard (measured real but inert) and not on runtime (atob accepts newlines
  // in both engines), but on determinism: a wrap width is a free parameter of a
  // step whose output is hashed into the published CSP, and five plausible
  // encoders split two ways on it. Buffer's base64 takes no wrap argument at
  // all, which is the property being relied on — so it is checked, not assumed.
  const base64 = wasm.toString("base64");
  if (base64.includes("\n") || base64.includes("\r")) {
    die("the base64 token carries a line break: the wrap width would enter the hashed script text and therefore the published CSP hash (D131 §5 R6)");
  }
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(base64)) {
    die("the base64 encoding left the standard alphabet — atob() decodes standard base64 only, and D129 §5 R9 assertion 4 admits no newline");
  }

  const moduleDigest = sha256Hex(wasm);

  // ── D129 §5 R8 item 2 — the ordering, fixed so the injector cannot be
  //    written wrong. The base64 is ONE line: a wrapped blob would put ~1 in
  //    4096 interior lines behind the wording scan's `//` comment skip.
  let html = template
    .replace(TOKENS.glue, () => glue)
    .replace(TOKENS.base64, () => base64)
    .replace(TOKENS.digest, () => moduleDigest);

  // Hashes are computed over the FINAL text of each element, after every
  // substitution above and before the CSP tokens are filled.
  const style = elementText(html, "<style>", "</style>");
  if (!style) die("the built page carries no <style> element to hash");
  const dataScript = elementText(html, "<script>", "</script>");
  if (!dataScript) die("the built page carries no inline classic <script> to hash");
  const moduleScript = elementText(html, '<script type="module">', "</script>", dataScript.end);
  if (!moduleScript) die("the built page carries no inline module <script> to hash");

  const h1 = sha256Base64(dataScript.text);
  const h2 = sha256Base64(moduleScript.text);
  const h3 = sha256Base64(style.text);

  html = html
    .replace(TOKENS.scriptHashes, () => `'sha256-${h1}' 'sha256-${h2}'`)
    .replace(TOKENS.styleHash, () => `'sha256-${h3}'`);

  assertBuilt({ html, glue, wasm, base64, moduleDigest, template, h1, h2, h3 });

  rmSync(outDir, { recursive: true, force: true });
  mkdirSync(outDir, { recursive: true });
  const pagePath = join(outDir, "index.html");
  writeFileSync(pagePath, html);

  // ── R7 — SHA256SUMS covers the served closure, which is one line ─────────
  //
  // The sums list IS the deploy list (D63 §5 R4), and after D129 §5 R1 the
  // closure is one file — so a second line here would oblige R26's host to
  // serve an artifact the page never loads. The pre-packaging module is a
  // RELEASE artifact (Q30/Q31), not a served one.
  const pageDigest = sha256Hex(readFileSync(pagePath));
  writeFileSync(join(outDir, "SHA256SUMS"), `${pageDigest}  index.html\n`);

  // Assert against the DIRECTORY, not against the string just built. Checking
  // that a one-line literal has one line is an assertion that cannot fail —
  // exactly the class D131 was written to repair, and it was in this file.
  // The property that can actually break is set equality: the sums list IS the
  // deploy list (D63 §5 R4), so a byproduct appearing in the output directory
  // must redden here rather than travel to the host unlisted.
  const listed = readFileSync(join(outDir, "SHA256SUMS"), "utf8")
    .split("\n").filter(Boolean).map((row) => row.slice(row.indexOf("  ") + 2)).sort();
  const present = readdirSync(outDir).filter((name) => name !== "SHA256SUMS").sort();
  if (listed.length !== 1 || listed.join("\0") !== present.join("\0")) {
    die(`SHA256SUMS and the deploy directory disagree — listed [${listed}], present [${present}]. ` +
      `After D129 §5 R1 the served closure is ONE file, and D63 §5 R4 makes the sums list the deploy list, ` +
      `so an unlisted artifact here is one R26 would oblige the host to serve`);
  }
  for (const [name, digest] of [["index.html", pageDigest]]) {
    if (sha256Hex(readFileSync(join(outDir, name))) !== digest) {
      die(`SHA256SUMS records a digest that is not ${name}'s own bytes`);
    }
  }

  return { pagePath, pageDigest, moduleDigest, bytes: Buffer.byteLength(html), h1, h2, h3 };
}

// ── D129 §5 R9 — the assertions, against the BUILT artifact ────────────────
function assertBuilt({ html, glue, wasm, base64, moduleDigest, template, h1, h2, h3 }) {
  // 1. verbatim glue — the line between concatenation and bundling, and what
  //    makes R23's "no framework or bundler" checkable rather than asserted.
  if (!html.includes(glue)) {
    die("the built page does not contain the wasm-pack glue as a contiguous substring — something transformed it, which is bundling (spec line 137)");
  }

  // 2. round-trip module, and the footer digest is its digest.
  const decoded = Buffer.from(base64, "base64");
  if (!decoded.equals(wasm)) die("the base64 token does not decode to the wasm-pack module byte-for-byte");
  if (sha256Hex(decoded) !== moduleDigest) die("the injected footer digest is not the digest of the module the page carries");
  if (!html.includes(moduleDigest)) die("the footer digest is absent from the built page");

  // 3. decomposition — page minus the two large tokens is the reviewable
  //    residue, and it is the committed template again.
  const residue = html.replace(glue, TOKENS.glue).replace(base64, TOKENS.base64);
  const restored = residue
    .replace(moduleDigest, TOKENS.digest)
    .replace(`'sha256-${h1}' 'sha256-${h2}'`, TOKENS.scriptHashes)
    .replace(`'sha256-${h3}'`, TOKENS.styleHash);
  if (restored !== template) {
    die("the built page does not decompose back to the committed template — the authored residue is not what was reviewed (D129 §5 R9 assertion 3)");
  }

  // 4. textual safety of what actually landed.
  const scriptOpens = html.split("<script").length - 1;
  if (scriptOpens !== 2) die(`the built page carries ${scriptOpens} <script elements; D129 §5 R6 hashes exactly two`);

  // 5. no residual placeholder.
  for (const [name, token] of Object.entries(TOKENS)) {
    if (html.includes(token)) die(`the ${name} token ${token} survived into the built page`);
  }

  // 6. no fetch path to the module. `fetch` of an ENDPOINT is R24's and is
  //    unaffected; what is refused is a fetch of a page resource and any
  //    reachable call to the glue's default init.
  for (const forbidden of ["XMLHttpRequest", "importScripts(", "new Worker("]) {
    if (html.includes(forbidden)) die(`the built page contains ${forbidden}, which can reach for a resource the served closure does not contain`);
  }
  // The glue DEFINES the default init and must keep doing so — it is inlined
  // verbatim (assertion 1). What is refused is a call to it from the page's
  // own code, so the glue's bytes are removed before looking.
  const pageCode = html.replace(glue, "");
  if (/\b__wbg_init\s*\(|\bdefault\s*\(/.test(pageCode)) {
    die("the page's own code calls the glue's default init, whose module_or_path === undefined branch derives a URL and fetches it (D129 §5 R2)");
  }
  if (/\bfetch\s*\(\s*(?!["'`]https:)/.test(pageCode) && !/verify_online/.test(pageCode)) {
    die("the page's own code calls fetch() for something that is not an https: endpoint — the served closure is one file and nothing in it may be fetched (D129 §5 R1)");
  }
  if (!/initSync\s*\(\s*\{\s*module/.test(html)) {
    die("the built page never calls initSync({ module }), so it is not loading the module it carries");
  }

  // 7. CSP present and correct.
  const meta = /<meta http-equiv="Content-Security-Policy" content="([^"]+)">/.exec(html);
  if (!meta) die("the built page carries no Content-Security-Policy <meta> (D129 §5 R6; the ruled host emits no headers at all)");
  const policy = meta[1];
  for (const required of [
    "default-src 'none'",
    `script-src 'sha256-${h1}' 'sha256-${h2}' 'wasm-unsafe-eval'`,
    `style-src 'sha256-${h3}'`,
    "connect-src https:",
    "base-uri 'none'",
    "form-action 'none'",
  ]) {
    if (!policy.includes(required)) die(`the policy is missing ${JSON.stringify(required)}; it reads ${JSON.stringify(policy)}`);
  }
  for (const refused of ["'unsafe-inline'", "'unsafe-eval'"]) {
    // 'wasm-unsafe-eval' contains 'unsafe-eval' as a substring; match the token.
    if (new RegExp(`(^|[\\s;])${refused.replace(/'/g, "'")}`).test(policy)) {
      die(`the policy carries ${refused}, which D129 §6 refuses`);
    }
  }
  // connect-src must be scheme-only: a host allowlist blocks the user override
  // spec line 137 mandates, and blocks it undiagnosably (D129 §1 m).
  if (/connect-src[^;]*https:\/\//.test(policy)) {
    die("connect-src names hosts; D129 §5 R6 rules it scheme-only so a user-supplied https: override is not blocked undiagnosably");
  }
  cspPermitsThePinnedOrigins(policy);
}

// R23's Accept row, D66 §7's guard test, run offline against the built artifact
// so neither an R25 build nor an R26 deploy can introduce the regression unseen.
const PINNED_ORIGINS = [
  "https://blockstream.info",
  "https://mempool.space",
  "https://arb1.arbitrum.io",
  "https://arbitrum.drpc.org",
  "https://sepolia-rollup.arbitrum.io",
  "https://arbitrum-sepolia.drpc.org",
];

function cspPermitsThePinnedOrigins(policy) {
  const directives = new Map(
    policy.split(";").map((part) => {
      const [name, ...values] = part.trim().split(/\s+/);
      return [name, values];
    }),
  );
  // The fallback case D66 named: with no connect-src, `default-src 'none'`
  // (or `'self'`) governs, and every fetch dies with the same opaque TypeError.
  const connect = directives.get("connect-src") ?? directives.get("default-src");
  if (!connect) die("the policy has neither connect-src nor default-src, so what governs a fetch is unstated");
  if (!directives.has("connect-src")) {
    die("connect-src is absent, so it falls back to default-src — which is 'none' here, and R24's online mode would die with the same opaque TypeError a CORS rejection produces (D66)");
  }
  const permits = (origin) =>
    connect.includes("https:") || connect.includes("*") || connect.some((source) => origin.startsWith(source));
  for (const origin of PINNED_ORIGINS) {
    if (!permits(origin)) die(`the policy forbids the pinned origin ${origin}; R24's online mode cannot reach it and the page may not say why (D66 §3 R4)`);
  }
  // The half that would have caught a host allowlist: spec line 137 mandates
  // user-overridable endpoints, so a NON-pinned https: origin must be permitted
  // too (D129 §5 R6).
  if (!permits("https://an-endpoint-no-one-pinned.example")) {
    die("the policy permits the pinned origins but forbids other https: origins — that is a host allowlist, and it breaks spec line 137's user-overridable endpoints undiagnosably (D129 §5 R6)");
  }
}

// ── the test of the test ───────────────────────────────────────────────────
//
// A green assertion set proves nothing until it has been seen to refuse
// something, and a nonzero exit is not the evidence: each arm matches on its
// own message.
function selfTest(pkgDir, templatePath) {
  const template = readFileSync(templatePath, "utf8");
  const glue = readFileSync(resolve(pkgDir, "antseal_wasm.js"), "utf8");
  const wasm = readFileSync(resolve(pkgDir, "antseal_wasm_bg.wasm"));
  const base64 = wasm.toString("base64");
  const moduleDigest = sha256Hex(wasm);
  const good = { html: "", glue, wasm, base64, moduleDigest, template, h1: "H1", h2: "H2", h3: "H3" };

  const arms = [
    // The module's first bytes are the `\0asm` magic, so its base64 always
    // begins "AGFz" — an arm that forced the first character to "A" would be a
    // no-op, and the self-test caught exactly that. Flip to a character the
    // payload cannot already have there.
    ["a one-byte edit to the payload", (s) => { s.base64 = `${s.base64[0] === "B" ? "C" : "B"}${s.base64.slice(1)}`; }, /does not decode to the wasm-pack module/],
    ["a transformed (bundled) glue", (s) => { s.glue = s.glue.replace("initSync", "initSync2"); }, /does not contain the wasm-pack glue as a contiguous substring/],
    ["a footer digest that is not the module's", (s) => { s.moduleDigest = "0".repeat(64); }, /is not the digest of the module the page carries|footer digest is absent/],
  ];

  let failures = 0;
  for (const [label, corrupt, expected] of arms) {
    const state = { ...good };
    state.html = buildFor(state);
    corrupt(state);
    let message = null;
    const realExit = process.exit;
    const realError = console.error;
    process.exit = () => { throw new Error("__exited__"); };
    console.error = (m) => { message = m; };
    try { assertBuilt(state); } catch { /* expected */ }
    process.exit = realExit;
    console.error = realError;
    if (message === null) {
      console.error(`::error::page-build self-test: the assertions stayed GREEN with ${label} — they are not checking anything`);
      failures += 1;
    } else if (!expected.test(message)) {
      console.error(`::error::page-build self-test: ${label} went red for the WRONG reason: ${message}`);
      failures += 1;
    } else {
      console.log(`  planted fault: ${label.padEnd(42)} -> RED (${message.slice(15, 80)}…)`);
    }
  }
  return failures;
}

function buildFor({ template, glue, base64, moduleDigest, h1, h2, h3 }) {
  return template
    .replace(TOKENS.glue, () => glue)
    .replace(TOKENS.base64, () => base64)
    .replace(TOKENS.digest, () => moduleDigest)
    .replace(TOKENS.scriptHashes, () => `'sha256-${h1}' 'sha256-${h2}'`)
    .replace(TOKENS.styleHash, () => `'sha256-${h3}'`);
}

// ── entry ──────────────────────────────────────────────────────────────────
const args = process.argv.slice(2);
if (args[0] === "--self-test") {
  const failures = selfTest(args[1] ?? "target/wasm-pack/antseal-wasm", args[2] ?? "verifier-web/index.template.html");
  if (failures > 0) process.exit(1);
  console.log("self-test PASS — each assertion goes red for its own reason");
} else {
  const [pkgDir, templatePath, outDir] = args;
  if (!pkgDir || !templatePath || !outDir) die("usage: page-build.mjs <pkg-dir> <template> <out-dir>");
  const result = build(pkgDir, templatePath, outDir);
  console.log(`  ${result.pagePath} — ${result.bytes} bytes`);
  console.log(`  module sha256 ${result.moduleDigest}`);
  console.log(`  page   sha256 ${result.pageDigest}`);
  console.log(`  csp    script 'sha256-${result.h1}' 'sha256-${result.h2}' · style 'sha256-${result.h3}'`);
}
