#!/usr/bin/env node
// R27 / Q19 — what the verifier page RENDERS, asserted in a real browser.
//
//   node scripts/verifier-page-browser.mjs --page <page.html> [options] <bundle …>
//
// Normally invoked by ./scripts/verifier-page-browser.sh, which builds the page,
// materialises the fixtures and captures the native side of every comparison.
//
// ── Why raw CDP and not playwright/puppeteer ───────────────────────────────
//
// The repo has no `package.json` and no `node_modules`, and D129 drove both
// engines over the DevTools Protocol from a raw WebSocket — node has had a
// global `WebSocket` since v22. A driver with no dependency is a driver that
// cannot pull 150 MB of browser binaries into a metered CI minute, and Q19's
// lane is local-only for exactly that reason. D133 §5.2 makes it a ruling and
// a correction to R27's own `Do`: *"there is no playwright in this repository
// and none is to be added"* — route interception is `Fetch.enable` +
// `Fetch.requestPaused` + `Fetch.fulfillRequest`/`failRequest` over the same
// CDP session.
//
// ── What this file asserts that nothing else can ───────────────────────────
//
// 1. **The offline run fetches NOTHING.** `Network.requestWillBeSent` fires for
//    every request the page attempts, including ones the CSP then blocks —
//    which is what makes it the right instrument for "fetches nothing". A page
//    that asked and was refused has still asked.
// 2. **PARITY** — for each fixture, the strings the page puts in the DOM are the
//    strings `antseal verify` printed for the same bytes. Both surfaces fold
//    over ONE assembly (`verify_rendered`'s document; D130 §3 R3), so a
//    difference is a defect and not a rendering opinion. Until R27 this file
//    asserted only `RESULT`/`FAILURE`/`TIMEOUT` per bundle — D133 §8 item 6
//    recorded that the twelve-bundle green *"must not be read as parity"*, and
//    it was right.
// 3. **The four online cases**, over the one fixture that verifies offline to
//    `attested`, differing ONLY in the mocked response, all of it real captured
//    mainnet (D133 §3 R8).
// 4. **The probe set on the wire**, against the heights the *frozen upgrade
//    group* records. Both surfaces derive their probe set from
//    `ProbePlan::from_bundle`, so a defect in it is a defect in both and is
//    invisible to a rendering comparison (D132 §7.4, D133's obligation 1).
//    This row and `antseal-cli`'s `verify_host/tests.rs` are the only two
//    instruments in the tree that can see one.
// 5. **The two receipt cases** (`--receipt`, R85 / D137 §5), over the
//    receipt-bearing twin: what `#overlay-receipt` says when the chain-id
//    guard passes and when it refuses — and, on the wire, that a refused
//    guard issues no receipt query at all.
//
// ── What it deliberately does NOT do ───────────────────────────────────────
//
// It computes no digest of the module and restates no verdict wording. The
// module digest arrives by `--module-sha256` from the caller that built it; the
// advice sentence is pulled out of `MVP-SPEC.md` at run time, following
// `crates/antseal-wasm/tests/page_template.rs:145`'s own reasoning — *"a
// literal copied into this file would be a second source of truth that agrees
// on the day it is written"*; the two online tokens it matches on are read out
// of the Rust constants that define them.
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, join, resolve } from "node:path";
import { pathToFileURL } from "node:url";

const NODE_MAJOR_FLOOR = 22; // global WebSocket

function fail(message) {
  console.error(`::error::verifier-page-browser: ${message}`);
  process.exit(1);
}

const nodeMajor = Number.parseInt(process.versions.node.split(".")[0], 10);
if (!Number.isFinite(nodeMajor) || nodeMajor < NODE_MAJOR_FLOOR) {
  fail(`node ${process.versions.node} is below the v${NODE_MAJOR_FLOOR} floor (global WebSocket)`);
}

const BROWSER = process.env.ANTSEAL_BROWSER ?? "chromium";
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// `--disable-dev-shm-usage` is load-bearing, not cargo cult: on a host with a
// small /dev/shm the browser starts and then never brings DevTools up, with an
// empty stderr — measured here, where its absence hung for the full timeout.
const FLAGS = [
  "--headless",
  "--disable-dev-shm-usage",
  "--disable-gpu",
  "--no-sandbox",
  "--no-first-run",
  "--disable-extensions",
  "--disable-component-update",
  "--disable-background-networking",
  "--disable-sync",
];

// ── the row register ───────────────────────────────────────────────────────
//
// Every assertion below belongs to a NAMED row, and the name is printed in
// front of its own failure. Two things depend on that:
//
//   * D136 §2 R13's seeded failure is `ANTSEAL_PAGE_SEED_FAILURE=<row>`, whose
//     harness matches the log on `::error::verifier-page-browser: [<row>]`
//     rather than on the exit status — a crash exits nonzero too;
//   * a reader of a red CI log gets the row name before the sentence.
//
// A seed naming a row that does not exist is a HARD ERROR, and so is a seed
// whose row never fired: a typo that made the harness silently green would be
// worth less than no harness, and a row that was ALREADY failing proves nothing
// when it fails again (Q234's lesson, enforced in the instrument as well as in
// the harness around it).
const ROWS = new Set([
  "boot",
  "receipt",
  "network",
  "csp",
  "bundle",
  "parity",
  "format-version",
  "shape",
  "page-build",
  "advice",
  "page-sums",
  "probe-plan",
  "online",
]);

// An EMPTY value is "no seed", not a seed named "". The workflow sets this
// variable unconditionally from a `workflow_dispatch` input
// (`.github/workflows/verifier-page.yml`), so on every ordinary run it arrives
// as the empty string; treating that as a row name would turn the hard error
// below into the lane's default outcome.
const SEED_RAW = process.env.ANTSEAL_PAGE_SEED_FAILURE ?? "";
const SEED = SEED_RAW.trim() === "" ? null : SEED_RAW.trim();
if (SEED !== null && !ROWS.has(SEED)) {
  fail(
    `ANTSEAL_PAGE_SEED_FAILURE=${JSON.stringify(SEED)} names no row. ` +
      `Rows are: ${[...ROWS].join(", ")}. A seed that matched nothing would make the ` +
      `seeded-failure harness green over a plant that never fired (D136 §2 R13).`,
  );
}

let failures = 0;
let seedFired = false;
function check(row, label, condition, detail) {
  let ok = Boolean(condition);
  let suffix = "";
  if (SEED === row && ok) {
    // D136 §2 R13: the plant forces exactly the named row to fail with its own
    // real message. The marker is appended, never substituted, so a harness
    // matching the real sentence still matches and a human reading the log is
    // not sent hunting a defect that was asked for.
    ok = false;
    seedFired = true;
    suffix = "  [SEEDED by ANTSEAL_PAGE_SEED_FAILURE]";
  }
  if (ok) {
    console.log(`  OK   [${row}] ${label}`);
  } else {
    console.error(`::error::verifier-page-browser: [${row}] ${label} — ${detail}${suffix}`);
    failures += 1;
  }
}

// ── arguments ──────────────────────────────────────────────────────────────

const argv = process.argv.slice(2);
const opts = {
  page: null,
  sums: null,
  moduleSha256: null,
  spec: null,
  expect: null,
  diagnosis: null,
  online: null,
  receipt: null,
  captures: null,
  wording: null,
  verdicts: null,
  selfTest: false,
  bundles: [],
};
for (let i = 0; i < argv.length; i += 1) {
  const arg = argv[i];
  const value = () => {
    i += 1;
    if (i >= argv.length) fail(`${arg} needs a value`);
    return argv[i];
  };
  switch (arg) {
    case "--page": opts.page = value(); break;
    case "--sums": opts.sums = value(); break;
    case "--module-sha256": opts.moduleSha256 = value(); break;
    case "--spec": opts.spec = value(); break;
    case "--expect": opts.expect = value(); break;
    case "--diagnosis": opts.diagnosis = value(); break;
    case "--online": opts.online = value(); break;
    case "--receipt": opts.receipt = value(); break;
    case "--captures": opts.captures = value(); break;
    case "--wording": opts.wording = value(); break;
    case "--verdicts": opts.verdicts = value(); break;
    case "--self-test": opts.selfTest = true; break;
    default:
      if (arg.startsWith("--")) fail(`unknown flag ${arg}`);
      opts.bundles.push(arg);
  }
}
if (opts.page === null) {
  fail(
    "usage: verifier-page-browser.mjs --page <page.html> [--module-sha256 <hex>] " +
      "[--sums <SHA256SUMS>] [--spec MVP-SPEC.md] [--expect <dir>] [--online <fixture>] " +
      "[--receipt <receipt-bearing fixture>] " +
      "[--captures <dir>] [--wording <wording.rs>] [--verdicts <verdicts.rs>] " +
      "[--diagnosis <dir>] [--self-test] <bundle …>",
  );
}
const pagePath = resolve(opts.page);
if (!existsSync(pagePath)) {
  fail(`${pagePath} does not exist — build it with scripts/verifier-page-build.sh`);
}
const pageUrl = pathToFileURL(pagePath).href;
const sumsPath = resolve(opts.sums ?? join(dirname(pagePath), "SHA256SUMS"));
const expectDir = opts.expect === null ? null : resolve(opts.expect);
const diagnosisDir = opts.diagnosis === null ? null : resolve(opts.diagnosis);

// ── one browser session ────────────────────────────────────────────────────

async function session(url, drive, { intercept = false } = {}) {
  const profile = mkdtempSync(join(tmpdir(), "antseal-page-"));
  const port = 9500 + Math.floor(Math.random() * 400);
  const browser = spawn(
    BROWSER,
    [...FLAGS, `--user-data-dir=${profile}`, `--remote-debugging-port=${port}`, "about:blank"],
    { stdio: ["ignore", "pipe", "pipe"] },
  );
  let stderr = "";
  browser.stderr.on("data", (d) => { stderr += d.toString(); });

  // 60 s, not 15: on a loaded host (a parallel cargo build is enough) the
  // browser takes appreciably longer to bring DevTools up, and a short wait
  // turns that into a spurious red that reads like a page defect.
  let wsUrl = null;
  for (let i = 0; i < 600 && wsUrl === null; i += 1) {
    try {
      wsUrl = (await (await fetch(`http://127.0.0.1:${port}/json/version`)).json()).webSocketDebuggerUrl ?? null;
    } catch { await sleep(100); }
  }
  if (wsUrl === null) {
    browser.kill("SIGKILL");
    rmSync(profile, { recursive: true, force: true });
    fail(`${BROWSER} never brought DevTools up on ${port}\n${stderr}`);
  }

  const ws = new WebSocket(wsUrl);
  await new Promise((res, rej) => { ws.onopen = res; ws.onerror = () => rej(new Error("devtools websocket refused")); });
  let id = 0;
  const pending = new Map();
  const events = [];
  const listeners = new Map();
  const handlerErrors = [];
  ws.onmessage = (m) => {
    const msg = JSON.parse(m.data);
    if (msg.id !== undefined) {
      const p = pending.get(msg.id);
      pending.delete(msg.id);
      if (msg.error) p.rej(new Error(JSON.stringify(msg.error))); else p.res(msg.result);
    } else {
      events.push(msg);
      const handler = listeners.get(msg.method);
      // A handler that throws must not take the socket down silently: the run
      // would hang to its timeout and report a driver bug as a page defect.
      if (handler) Promise.resolve(handler(msg.params)).catch((e) => handlerErrors.push(String(e)));
    }
  };
  const send = (method, params = {}, sessionId) => {
    id += 1;
    const payload = { id, method, params };
    if (sessionId) payload.sessionId = sessionId;
    ws.send(JSON.stringify(payload));
    return new Promise((res, rej) => pending.set(id, { res, rej }));
  };
  const { targetId } = await send("Target.createTarget", { url: "about:blank" });
  const { sessionId } = await send("Target.attachToTarget", { targetId, flatten: true });
  const S = (method, params) => send(method, params, sessionId);
  const on = (method, handler) => listeners.set(method, handler);
  for (const domain of ["Runtime", "Log", "Page", "Network", "DOM"]) await S(`${domain}.enable`);

  const evaluate = async (expression) =>
    (await S("Runtime.evaluate", { expression, returnByValue: true, awaitPromise: true })).result.value;

  // Interception is armed BEFORE navigation and scoped to `https://*`, so the
  // `file://` document itself is never paused. Scoping it that way is also what
  // keeps the request count honest: an unscoped pattern would pause the page
  // document too and change what this run says about it.
  if (intercept) {
    await S("Fetch.enable", { patterns: [{ urlPattern: "https://*", requestStage: "Request" }] });
  }

  await S("Page.navigate", { url });
  let result;
  let screenshot = null;
  try {
    result = await drive({ S, evaluate, events, on });
    try {
      screenshot = (await S("Page.captureScreenshot", { format: "png" })).data;
    } catch { screenshot = null; }
  } finally {
    ws.close();
    browser.kill("SIGKILL");
    await sleep(150);
    // SIGKILL is asynchronous and chromium's helper processes outlive the
    // parent by a few hundred milliseconds, still writing into the profile.
    // A bare recursive remove then throws ENOTEMPTY — `force` covers ENOENT
    // and nothing else — and it throws OUT of a `finally`, killing the whole
    // driver mid-suite with a node stack trace rather than a row.
    // MEASURED here on a loaded host (a parallel cargo build is enough): the
    // run died at the first online case with
    // `Error: ENOTEMPTY, Directory not empty: /tmp/antseal-page-…`.
    // `maxRetries` retries exactly this errno class (EBUSY/EMFILE/ENFILE/
    // ENOTEMPTY/EPERM), which is the right shape: wait for the writers, then
    // remove.
    rmSync(profile, { recursive: true, force: true, maxRetries: 20, retryDelay: 100 });
  }
  return { ...result, events, screenshot, handlerErrors };
}

// `#build` is populated by the page's own boot() from the module's build_info()
// export, so a non-empty value means the wasm instantiated and ran.
async function waitForBoot(evaluate) {
  for (let i = 0; i < 300; i += 1) {
    await sleep(100);
    try {
      const built = await evaluate("(document.getElementById('build')||{}).textContent || ''");
      if (built) return built;
    } catch { /* mid-navigation */ }
  }
  return null;
}

// ── what the page rendered, as the CLI would have printed it ───────────────
//
// The comparison's subject is `RenderedVerdict`/`RenderedRedaction` — the ONE
// assembly both surfaces fold over (D130 §3 R3). The CLI's fold is
// `VerifyRun::render()` plus `redaction_out::render_block()`; this expression
// is that fold read back out of the DOM, so the two arrays are two readings of
// one document.
//
// Two places where the surfaces lay the SAME atoms out differently, and both
// take the CLI's shape here because the CLI's stdout is what this is compared
// against:
//
//   * the anchor row. The CLI prints `"{slot}: {state_line}{tag}"` as one line
//     (`verify_out.rs`); the page puts `"{slot} {tag}"` in one <p> and
//     `state_line` in the next. **This is a correction to D130 §7.3 clause 1**,
//     which says the two agree "string for string after the CLI's indentation
//     is stripped": indentation is not the only difference, and a lane that
//     took that sentence literally would build a gate that reddens on a
//     correct page.
//   * `#format-version` is the page's own line and has no CLI counterpart
//     (D130 §5 R23.2 — R18 froze no sentence for it), so it is excluded here
//     and asserted separately by the `format-version` row.
const EXTRACT_RENDER = `(() => {
  const $ = (id) => document.getElementById(id);
  const result = $("result");
  if (!result || result.hidden) return null;
  const out = [];
  const put = (el) => { if (el && !el.hidden) out.push(el.textContent); };
  put($("headline"));
  put($("divergence"));
  out.push($("evidence-label").textContent);
  for (const item of $("anchors").children) {
    const ps = [...item.querySelectorAll("p")];
    const head = ps[0].textContent;
    const cut = head.indexOf(" ");
    const slot = cut === -1 ? head : head.slice(0, cut);
    const tag = cut === -1 ? "" : head.slice(cut + 1);
    out.push(slot + ": " + ps[1].textContent + tag);
    for (let i = 2; i < ps.length; i += 1) out.push(ps[i].textContent);
  }
  put($("claimed"));
  if (!$("supporting").hidden) {
    out.push($("supporting-class").textContent);
    out.push($("supporting-detail").textContent);
  }
  out.push($("scheme").textContent);
  out.push($("storage-label").textContent);
  out.push($("storage-line").textContent);
  out.push($("redaction-label").textContent);
  out.push($("redaction-note").textContent);
  for (const article of $("redaction-files").children) {
    for (const el of article.querySelectorAll("p, li")) out.push(el.textContent);
  }
  for (const item of $("redaction-withheld").children) out.push(item.textContent);
  out.push($("redaction-totals").textContent);
  out.push($("redaction-withheld-totals").textContent);
  out.push($("meaning").textContent);
  return out;
})()`;

// Element counts the text comparison above cannot make: parity flattens the
// view to strings, so it can no longer say that a blackout row IS an element or
// that the raw mirror rides its own node.
const EXTRACT_SHAPE = `(() => {
  const $ = (id) => document.getElementById(id);
  const files = [...$("redaction-files").children];
  return {
    files: files.length,
    blockLines: files.reduce((n, a) => n + a.querySelectorAll("ol > li").length, 0),
    mirrors: files.reduce((n, a) => n + a.querySelectorAll("p.mirror").length, 0),
    withheld: $("redaction-withheld").children.length,
    formatVersion: $("format-version").textContent,
  };
})()`;

const EXTRACT_OVERLAY = `(() => {
  const $ = (id) => document.getElementById(id);
  return {
    hidden: $("overlay").hidden,
    refusal: $("online-refusal").hidden ? null : $("online-refusal").textContent,
    framing: $("overlay-framing").textContent,
    impact: $("overlay-impact").textContent,
    outcomes: [...$("overlay-outcomes").children].map((li) => ({
      line: li.textContent,
      className: li.className,
    })),
    receipt: $("overlay-receipt").hidden ? null : $("overlay-receipt").textContent,
    endpoints: $("overlay-endpoints").textContent,
    deltas: [...$("overlay-deltas").children].map((li) => li.textContent),
  };
})()`;

const EXTRACT_BASES = `JSON.stringify([
  document.getElementById("esplora-0").value,
  document.getElementById("esplora-1").value,
])`;

// The Arbitrum pair, read out of the page's own inputs for the same reason as
// the esplora pair above: the driver mocks the endpoints the page decided to
// use, and never a URL it invented.
const EXTRACT_ARBITRUM_BASES = `JSON.stringify([
  document.getElementById("arbitrum-0").value,
  document.getElementById("arbitrum-1").value,
])`;

// ── the drop, and the reset that has to precede it ─────────────────────────
//
// **This reset is load-bearing and its absence was a live defect.** The page
// unhides `#result` when a bundle verifies and never hides it again, so a
// driver that polls "is #result visible?" after the SECOND drop is reading the
// FIRST bundle's DOM: it returns `RESULT` immediately, before the new
// verification has begun, and every per-bundle row after the first is green
// over a rendering that belongs to another file. Measured here at R27 — the
// parity row for `covered-unit-partial-reveal` reported the anchor block of
// `attested-plus-invalid-ots`, which is how the staleness was found. The
// pre-R27 driver had the same poll and therefore the same hole; its
// twelve-bundle green asserted one bundle twelve times.
//
// The reset hides BOTH sections and blanks the headline, so the wait is for a
// state the page must re-establish rather than one it may have left behind.
const RESET_BEFORE_DROP = `(() => {
  document.getElementById("result").hidden = true;
  document.getElementById("failure").hidden = true;
  document.getElementById("headline").textContent = "";
  return true;
})()`;

async function dropBundle({ S, evaluate }, bundlePath) {
  // depth:0, deliberately: depth:-1 serialises every inline-script text node of
  // a 2.4 MB page over the protocol and kills the connection.
  const { root } = await S("DOM.getDocument", { depth: 0 });
  const { nodeId } = await S("DOM.querySelector", { nodeId: root.nodeId, selector: "input[type=file]" });
  if (!nodeId) fail("the page exposes no input[type=file]; R23's file-picker fallback is part of its Do");
  if ((await evaluate(RESET_BEFORE_DROP)) !== true) {
    fail("the page exposes no #result/#failure/#headline to reset before a drop — the wait below would read the previous bundle's DOM");
  }
  await S("DOM.setFileInputFiles", { files: [resolve(bundlePath)], nodeId });
  for (let i = 0; i < 600; i += 1) {
    await sleep(50);
    const state = await evaluate(
      "document.getElementById('result').hidden ? (document.getElementById('failure').hidden ? 'WAIT' : 'FAILURE') : 'RESULT'",
    );
    if (state === "WAIT") continue;
    if (state !== "RESULT") return { state };
    return {
      state,
      rendered: await evaluate(EXTRACT_RENDER),
      shape: await evaluate(EXTRACT_SHAPE),
    };
  }
  return { state: "TIMEOUT" };
}

function networkRequests(events) {
  return events
    .filter((e) => e.method === "Network.requestWillBeSent")
    .map((e) => e.params.request.url);
}

function violations(events) {
  const out = [];
  for (const e of events) {
    if (e.method === "Log.entryAdded" && /Content Security Policy|Refused to/i.test(e.params.entry.text ?? "")) {
      out.push(e.params.entry.text);
    } else if (e.method === "Runtime.exceptionThrown") {
      out.push(e.params.exceptionDetails.text ?? "exception");
    }
  }
  return out;
}

// ── values pulled from their one source of truth ───────────────────────────

function readSpecAdvice(specPath) {
  const spec = readFileSync(specPath, "utf8");
  const line = spec.split("\n").find((l) => l.includes("for high-stakes verification"));
  if (line === undefined) {
    fail(`${specPath} carries no "for high-stakes verification" sentence — MVP-SPEC.md line 139 is the advice line's ONLY source of truth (D63 §5 R6)`);
  }
  const start = line.indexOf('"for high-stakes verification');
  if (start === -1) fail(`${specPath}: the advice sentence is not double-quoted, so it cannot be extracted verbatim`);
  const rest = line.slice(start + 1);
  const end = rest.indexOf('"');
  if (end === -1) fail(`${specPath}: the advice sentence's closing quote is missing`);
  // The spec spells the command in markdown code ticks and the page in a
  // <code> element; textContent carries neither, so compare the sentences.
  return rest.slice(0, end).replaceAll("`", "");
}

function rustStrConst(path, name) {
  if (path === null) return null;
  const src = readFileSync(path, "utf8");
  const found = new RegExp(`const\\s+${name}\\s*:\\s*&(?:'static\\s+)?str\\s*=\\s*"([^"]*)"`).exec(src);
  if (found === null) {
    fail(
      `${path}: could not read \`const ${name}\`. This driver matches the rendered overlay against the ` +
        `constant that DEFINES the token and never against a literal of its own; if the constant moved, ` +
        `the assertion must follow it rather than silently keep matching an old spelling.`,
    );
  }
  return found[1];
}

// ── on-disk rows (no browser involved) ─────────────────────────────────────

const pageDigest = createHash("sha256").update(readFileSync(pagePath)).digest("hex");

// D136 §2 R10.1: BOTH sides read from disk after the build, never taken from
// the build step's stdout — those are two different reads and only the second
// speaks about the bytes that were driven. The failure message names WHICH
// comparison failed and prints both sides.
{
  let detail = null;
  if (!existsSync(sumsPath)) {
    detail = `there is no SHA256SUMS beside the page at ${sumsPath}`;
  } else {
    const entries = readFileSync(sumsPath, "utf8")
      .split("\n")
      .map((l) => l.trim())
      .filter((l) => l.length > 0)
      .map((l) => {
        const m = /^([0-9a-f]{64})\s+\*?(.+)$/.exec(l);
        return m === null ? { raw: l } : { digest: m[1], name: m[2] };
      });
    if (entries.length !== 1) {
      detail = `${sumsPath} carries ${entries.length} entr(ies); D129 §5 R7 publishes exactly one — the page`;
    } else if (entries[0].digest === undefined) {
      detail = `${sumsPath}'s only line does not parse as "<64 hex>  <name>": ${JSON.stringify(entries[0].raw)}`;
    } else if (entries[0].name !== basename(pagePath)) {
      detail =
        `NAME mismatch — the sum names ${JSON.stringify(entries[0].name)} but the driver loaded ` +
        `${JSON.stringify(basename(pagePath))}, so the published digest is about a different file`;
    } else if (entries[0].digest !== pageDigest) {
      detail =
        `DIGEST mismatch for ${basename(pagePath)}\n` +
        `    on disk:     ${pageDigest}\n` +
        `    SHA256SUMS:  ${entries[0].digest}`;
    }
  }
  check(
    "page-sums",
    "sha256(the page file the driver loaded) equals the sole SHA256SUMS entry beside it",
    detail === null,
    `${detail} — Q19's Accept says the lane CONSUMES the reproducible build output; an echoed hash ` +
      `nobody compares is not evidence (D136 §2 R10.1)`,
  );
}

const specAdvice = opts.spec === null ? null : readSpecAdvice(resolve(opts.spec));
const attributionMarker = rustStrConst(opts.wording, "ONLINE_ATTRIBUTION_MARKER");
const headerMismatchCode = rustStrConst(opts.verdicts, "OTS_ONLINE_HEADER_MISMATCH_CODE");

// ── the expected CLI renderings ────────────────────────────────────────────
//
// One file per fixture, written by the caller from `antseal verify <fixture>`'s
// own stdout. Compared with leading whitespace stripped: the CLI's indentation
// is layout it owns alone (D130 §7.3 clause 1).
//
// **A second options divergence, beyond the one D130 §7.3 (ii) names.** That
// rider is about `storage_linkage`: the export takes no options so the layer
// always runs (D128 §3 R5), which is why this compares against a live CLI run
// and never against the committed vector file. Measured here at R27, the two
// sides also differ in a way D130 does not name — `commands.rs` builds
// `VerifyOptions::new().with_verify_at_unix(now)` while the export passes
// `VerifyOptions::new()`, whose `verify_at_unix` is `None`. It reaches the TSA
// certificate-chain validator. Over this corpus it is inert and measured so:
// every committed TSA artifact is a schema-opaque placeholder that fails to
// parse long before a validity window is consulted, and all thirteen fixtures
// compare identical. A fixture carrying a REAL TSA token would put a clock on
// one side of this comparison and not the other, and the gate would then go red
// for a reason that is not a defect.
function cliLines(bundlePath) {
  if (expectDir === null) return null;
  const path = join(expectDir, `${basename(bundlePath)}.cli.txt`);
  if (!existsSync(path)) return { missing: path };
  return {
    path,
    lines: readFileSync(path, "utf8").replace(/\n+$/, "").split("\n").map((l) => l.replace(/^\s+/, "")),
  };
}

function firstDifference(a, b) {
  const n = Math.max(a.length, b.length);
  for (let i = 0; i < n; i += 1) {
    if (a[i] !== b[i]) return i;
  }
  return -1;
}

// D130 §7.3 (i), made enforceable rather than remembered. The CLI's escape
// (`escape_for_terminal`) and the page's (`escape_for_dom`) differ on EXACTLY
// two code points — U+2028 and U+2029, which `escape_for_dom`'s own header
// names as its only additions — so on any string containing neither, the two
// surfaces render the same bytes and `redaction.files[].header_line` needs no
// exclusion. This is the check that says the corpus is still that corpus.
const SURFACE_DIVERGENT = /[\u2028\u2029]/u;

// ── shapes (R27 Accept row 4) ──────────────────────────────────────────────
//
// Element counts, per fixture, chosen so each row is true ONLY of the shape it
// names: a fully revealed single file has exactly one block line, so three or
// more is a partial reveal and nothing else; a `.mirror` node exists only for a
// full reveal carrying the raw file; `#redaction-withheld` items are the
// path-withheld placeholders and exist only where a file is wholly unrevealed.
const SHAPES = new Map([
  ["covered-unit-partial-reveal.sealproof", {
    why: "a partial reveal — one file, three unit rows (blackout, reveal, blackout), no mirror",
    files: 1, blockLinesAtLeast: 3, mirrors: 0, withheld: 0,
  }],
  ["leaf-level-cover-partial-reveal.sealproof", {
    why: "a leaf-level partial reveal — one file, three unit rows, no mirror",
    files: 1, blockLinesAtLeast: 3, mirrors: 0, withheld: 0,
  }],
  ["full-file-reveal-with-mirror.sealproof", {
    why: "a full reveal carrying the raw mirror, which rides its own node",
    files: 1, blockLinesAtLeast: 1, mirrors: 1, withheld: 0,
  }],
  ["nothing-revealed.sealproof", {
    why: "three wholly unrevealed files — each a path-withheld placeholder, and no file block at all",
    files: 0, blockLinesAtLeast: 0, mirrors: 0, withheld: 3,
  }],
]);

// ── the offline run ────────────────────────────────────────────────────────

const started = Date.now();
const run = await session(pageUrl, async (ctx) => {
  const build = await waitForBoot(ctx.evaluate);
  const footer = await ctx.evaluate(
    "JSON.stringify({pageBuild:(document.getElementById('page-build')||{}).textContent||''," +
      "advice:(document.getElementById('advice')||{}).textContent||''})",
  );
  const drops = [];
  for (const bundle of opts.bundles) drops.push([bundle, await dropBundle(ctx, bundle)]);
  return { build, footer: JSON.parse(footer ?? "null"), drops };
});

console.log(`verifier-page-browser (${BROWSER}, node ${process.versions.node}) — ${pageUrl}`);

check(
  "boot",
  "the page boots from a file:// origin and instantiates the module",
  Boolean(run.build),
  "the footer's build line never populated, so initSync({ module }) did not complete — D129 §5 R2's inlined module is what makes this work without a server",
);
if (run.build) console.log(`       ${run.build}`);

const requests = networkRequests(run.events);
const foreign = requests.filter((url) => url !== pageUrl);
check(
  "network",
  "the offline run fetches NOTHING but the page itself",
  foreign.length === 0,
  `the page attempted ${foreign.length} further request(s): ${foreign.slice(0, 5).join(", ")} — R23's Accept row is that a file:// or no-network context completes verification with no external resource`,
);
console.log(`       ${requests.length} request(s) total, all accounted for`);

const csp = violations(run.events);
check(
  "csp",
  "the page runs with zero Content-Security-Policy violations",
  csp.length === 0,
  `the browser reported:\n    ${csp.slice(0, 4).join("\n    ")}`,
);

// ── R12's two DOM rows (R25 Accept row 3, as corrected by D136 §2 R11) ─────

if (opts.moduleSha256 !== null) {
  const text = run.footer?.pageBuild ?? "";
  // The row is written against the ID and the hex run, never the label: D136
  // §2 R12's last paragraph repairs the visible text from "page build" to one
  // that names the MODULE, and an assertion on the label would have to be
  // edited in the same act for no gain.
  const runs = text.match(/[0-9a-f]{8,}/g) ?? [];
  check(
    "page-build",
    "the footer's #page-build carries sha256(module) as its ONLY hex run",
    runs.length === 1 && runs[0] === opts.moduleSha256,
    `#page-build reads ${JSON.stringify(text)} → ${runs.length} hex run(s) ${JSON.stringify(runs)}; ` +
      `the module the caller built hashes to ${opts.moduleSha256}. The static half of this is already ` +
      `asserted by verifier-page-build.sh --self-test; what THIS row adds is that the value survives ` +
      `into the DOM — boot() runs after injection and could blank or overwrite the footer (D136 §2 R12)`,
  );
}

if (specAdvice !== null) {
  const advice = (run.footer?.advice ?? "").trim();
  check(
    "advice",
    "the footer's #advice renders MVP-SPEC.md line 139's sentence verbatim, after CSP and after JS",
    advice === specAdvice,
    `rendered ${JSON.stringify(advice)}\n    spec     ${JSON.stringify(specAdvice)}\n` +
      `    page_template.rs:145 asserts the TEMPLATE; this row asserts the BUILT PAGE's DOM (D136 §2 R12)`,
  );
}

// ── per-bundle: it rendered, and it rendered what the CLI printed ──────────

let parityCompared = 0;
let shapesChecked = 0;
for (const [bundle, drop] of run.drops) {
  const name = basename(bundle);
  check(
    "bundle",
    `a real bundle dropped through the file picker renders a verdict (${name})`,
    drop.state === "RESULT",
    `the page reached '${drop.state}' — RESULT means the verdict block rendered, FAILURE means a typed error was displayed, TIMEOUT means neither`,
  );
  if (drop.state !== "RESULT") continue;

  const expected = cliLines(bundle);
  if (expected === null) {
    console.log(`  ..   [parity] ${name}: no --expect directory, nothing compared`);
  } else if (expected.missing) {
    check("parity", `the CLI's rendering of ${name} was captured`, false,
      `${expected.missing} does not exist — the caller must run \`antseal verify\` for every fixture it drives, or the parity gate silently covers fewer bundles than the run claims`);
  } else {
    const page = drop.rendered ?? [];
    const at = firstDifference(page, expected.lines);
    const hostile = page.filter((s) => SURFACE_DIVERGENT.test(s));
    check(
      "parity",
      `CLI and page render string-identical verdicts (${name}, ${expected.lines.length} line(s))`,
      at === -1,
      `first difference at index ${at} of ${Math.max(page.length, expected.lines.length)}\n` +
        `    CLI   ${JSON.stringify(expected.lines[at])}\n` +
        `    page  ${JSON.stringify(page[at])}\n` +
        `    (page rendered ${page.length} line(s), CLI ${expected.lines.length}; both surfaces fold ` +
        `over ONE assembly — D130 §3 R3 — so a difference here is a defect, not a rendering opinion)`,
    );
    check(
      "parity",
      `${name} carries no code point the two surfaces escape differently`,
      hostile.length === 0,
      `${hostile.length} rendered string(s) carry U+2028/U+2029 — the ONLY code points on which ` +
        `escape_for_terminal and escape_for_dom differ. D130 §7.3 (i) forbids extending parity to such a ` +
        `fixture without excluding redaction.files[].header_line; the first is ${JSON.stringify(hostile[0])}`,
    );
    parityCompared += 1;
  }

  check(
    "format-version",
    `${name} renders the page's own bundle-format line (no CLI counterpart)`,
    /^bundle format version \d+$/.test(drop.shape?.formatVersion ?? ""),
    `#format-version reads ${JSON.stringify(drop.shape?.formatVersion)} — it is the one datum the page ` +
      `takes from the report member rather than from the rendered block (D130 §5 R23.2), so parity cannot see it`,
  );

  const shape = SHAPES.get(name);
  if (shape !== undefined) {
    const got = drop.shape;
    const bad = [];
    if (got.files !== shape.files) bad.push(`files ${got.files} != ${shape.files}`);
    if (got.blockLines < shape.blockLinesAtLeast) bad.push(`block lines ${got.blockLines} < ${shape.blockLinesAtLeast}`);
    if (got.mirrors !== shape.mirrors) bad.push(`mirror nodes ${got.mirrors} != ${shape.mirrors}`);
    if (got.withheld !== shape.withheld) bad.push(`withheld placeholders ${got.withheld} != ${shape.withheld}`);
    check(
      "shape",
      `${name} renders ${shape.why}`,
      bad.length === 0,
      `${bad.join("; ")} — R27's Accept row 4 asks for the blackouts, the placeholder file and the raw ` +
        `mirror to be VISIBLE IN THE DOM. Parity flattens the view to strings and can no longer say that a ` +
        `blackout row is an element; these are the counts that can`,
    );
    shapesChecked += 1;
  }
}

// The two aggregate rows exist because the per-bundle loops above CANNOT fail
// for a bundle they never saw: a fixture that failed to materialise leaves the
// run green over less than it claims, which is exactly what R84 measured when a
// relative emit path put two fixtures somewhere else. They are gated on there
// being bundles at all so that `--self-test`, whose job is the network
// instrument's positive control and which drives none, does not report
// under-coverage of a suite it is not running.
if (opts.bundles.length > 0) {
  check(
    "shape",
    `every reveal shape R27 Accept row 4 names was driven (${shapesChecked} of ${SHAPES.size})`,
    shapesChecked === SHAPES.size,
    `not driven: ${[...SHAPES.keys()].filter((k) => !run.drops.some(([b]) => basename(b) === k)).join(", ")} — ` +
      `a suite that silently covers fewer shapes than it claims is the defect this count exists to prevent`,
  );
  if (expectDir !== null) {
    check(
      "parity",
      `parity compared every bundle driven (${parityCompared} of ${opts.bundles.length})`,
      parityCompared === opts.bundles.length,
      `${opts.bundles.length - parityCompared} bundle(s) reached no comparison. The count is asserted ` +
        `because the loop above cannot fail for a bundle it never saw`,
    );
  }
}

// ── the online cases (R27 Do (d); D133 §5.2; D132 §5 R27) ─────────────────

// The four cases differ ONLY in the mocked response, and every byte of it is a
// real captured mainnet answer (D133 §3 R8). The wrong-block answers come from
// a DIFFERENT REAL BLOCK rather than a synthetic fill, deliberately: it
// exercises rule O6 with bytes an attacker could actually produce, and it needs
// no new capture.
function captureFor(endpointBase, height, kind) {
  // The page's own pinned URLs name the endpoint and the capture files name it
  // the same way. Nothing here invents an endpoint identity.
  const which = endpointBase.includes("blockstream")
    ? "blockstream"
    : endpointBase.includes("mempool")
      ? "mempool"
      : null;
  if (which === null) fail(`the page's pinned esplora endpoint ${endpointBase} matches neither committed capture set`);
  const path = join(opts.captures, `esplora-${which}-${kind}-${height}.txt`);
  if (!existsSync(path)) fail(`${path} does not exist — R27's online cases replay committed A25 captures and capture nothing themselves`);
  return readFileSync(path, "utf8").trim();
}

function capturedHeights() {
  const out = new Set();
  for (const file of readdirSync(opts.captures)) {
    const m = /^esplora-blockstream-header-(\d+)\.txt$/.exec(file);
    if (m !== null) out.add(Number.parseInt(m[1], 10));
  }
  return [...out].sort((a, b) => a - b);
}

// Serve one intercepted esplora request from the committed captures.
//
// `answerHeight` is the block the endpoint ANSWERS WITH, which is not always
// the one the page asked about: making them differ is the whole of the mismatch
// and disagreement cases, and the endpoint then returns a real, self-consistent
// answer for the wrong block — the shape a substituted or lagging endpoint
// actually produces.
function esploraAnswer(base, url, answerHeight) {
  const rest = url.slice(base.replace(/\/+$/, "").length);
  if (/^\/block-height\/\d+$/.test(rest)) return captureFor(base, answerHeight, "height");
  if (/^\/block\/[0-9a-f]{64}\/header$/.test(rest)) return captureFor(base, answerHeight, "header");
  return null;
}

// The Arbitrum half of the mock (D137 §5 point 3).
//
// `chainIdHex` is what BOTH RPCs answer `eth_chainId` with, and it is the whole
// of the case: `0xa4b1` is the pinned 42161 and the guard passes, anything else
// is the `wrong-chain` class and the guard returns before the receipt query
// (`probeReceipt`). `eth_getTransactionReceipt` always answers `null` here —
// the twin's `e1e1…e1` hash is 32 repetitions of one byte and points at nothing
// on any chain, which after D137 §3 R1 is a fixture that demonstrates the fix
// rather than the defect.
//
// A JSON-RPC POST carrying `Content-Type: application/json` is NOT a
// CORS-safelisted request, so the browser preflights it. The OPTIONS is
// answered here too; if it were not, the guard would fail `transport` and the
// case would silently become a different case.
// Two URLs are the same request target. `new URL()` normalises the empty path
// to `/`, which string equality does not.
function sameUrl(a, b) {
  try {
    return new URL(a).href === new URL(b).href;
  } catch {
    return false;
  }
}

function arbitrumAnswer(request, chainIdHex) {
  if (request.method === "OPTIONS") {
    return { code: 204, headers: [
      { name: "Access-Control-Allow-Origin", value: "*" },
      { name: "Access-Control-Allow-Methods", value: "POST, OPTIONS" },
      { name: "Access-Control-Allow-Headers", value: "content-type, accept" },
      { name: "Access-Control-Max-Age", value: "0" },
    ], body: "" };
  }
  let call;
  try {
    call = JSON.parse(request.postData ?? "");
  } catch {
    return null;
  }
  const result =
    call.method === "eth_chainId"
      ? chainIdHex
      : call.method === "eth_getTransactionReceipt"
        ? null
        : undefined;
  if (result === undefined) return null;
  return { code: 200, headers: [
    { name: "Access-Control-Allow-Origin", value: "*" },
    { name: "Content-Type", value: "application/json" },
  ], body: JSON.stringify({ jsonrpc: "2.0", id: call.id ?? 1, result }) };
}

async function onlineCase(bundlePath, { answerFor, failingIndex, chainIdHex = null }) {
  const asked = [];
  let bases = [];
  let arbBases = [];
  const result = await session(pageUrl, async (ctx) => {
    ctx.on("Fetch.requestPaused", async (params) => {
      const { requestId, request } = params;
      // `postData` is kept so the receipt rows below can count JSON-RPC calls
      // BY METHOD: "the guard returns before the receipt query" is a claim
      // about which requests were made, and only the wire can settle it.
      asked.push({ url: request.url, method: request.method, postData: request.postData ?? null });

      // The Arbitrum pair, when the case asked for one. Matched on the page's
      // OWN endpoint values, so a driver that mocked a URL the page does not
      // use would fall through to the refusal below rather than pass.
      //
      // Compared as PARSED URLs, not as strings. `https://arbitrum.drpc.org`
      // is an origin with no path, and the request that leaves the browser is
      // `https://arbitrum.drpc.org/` — string equality mocks one endpoint of
      // the pair and silently turns the other into a transport failure.
      // Measured here: the first run of these rows reported `eth_chainId was
      // called 1 time(s)` and rendered `https://arbitrum.drpc.org: transport
      // failure`, which is the defect the two wire rows below exist to catch.
      if (arbBases.some((b) => sameUrl(request.url, b))) {
        const answer = chainIdHex === null ? null : arbitrumAnswer(request, chainIdHex);
        if (answer === null) {
          await ctx.S("Fetch.failRequest", { requestId, errorReason: "ConnectionRefused" });
          return;
        }
        await ctx.S("Fetch.fulfillRequest", {
          requestId,
          responseCode: answer.code,
          responseHeaders: answer.headers,
          body: Buffer.from(answer.body, "utf8").toString("base64"),
        });
        return;
      }

      const base = bases.find((b) => request.url.startsWith(b.replace(/\/+$/, "")));
      if (base === undefined || (failingIndex !== null && base === bases[failingIndex])) {
        // ConnectionRefused is the shape of a real unreachable endpoint, and
        // the page cannot tell it from a CORS rejection, a failed preflight or
        // a DNS failure — which is D66 §3 R2's point, and why the rendered line
        // names `transport` and diagnoses nothing.
        await ctx.S("Fetch.failRequest", { requestId, errorReason: "ConnectionRefused" });
        return;
      }
      const body = esploraAnswer(base, request.url, answerFor(base, bases));
      if (body === null) {
        await ctx.S("Fetch.failRequest", { requestId, errorReason: "AddressUnreachable" });
        return;
      }
      await ctx.S("Fetch.fulfillRequest", {
        requestId,
        responseCode: 200,
        responseHeaders: [
          { name: "Access-Control-Allow-Origin", value: "*" },
          { name: "Content-Type", value: "text/plain" },
        ],
        body: Buffer.from(body, "utf8").toString("base64"),
      });
    });

    await waitForBoot(ctx.evaluate);
    bases = JSON.parse(await ctx.evaluate(EXTRACT_BASES));
    arbBases = JSON.parse(await ctx.evaluate(EXTRACT_ARBITRUM_BASES));
    const drop = await dropBundle(ctx, bundlePath);
    if (drop.state !== "RESULT") {
      return { drop, before: null, after: null, overlay: null, bases, arbBases };
    }
    const before = drop.rendered;
    await ctx.evaluate("document.getElementById('confirm-online').click()");
    let overlay = null;
    for (let i = 0; i < 300; i += 1) {
      await sleep(100);
      overlay = await ctx.evaluate(EXTRACT_OVERLAY);
      if (!overlay.hidden || overlay.refusal !== null) break;
    }
    return { drop, before, overlay, after: await ctx.evaluate(EXTRACT_RENDER), bases, arbBases };
  }, { intercept: true });

  return { ...result, asked };
}

if (opts.online !== null) {
  if (opts.captures === null) fail("--online needs --captures <the A25 capture directory>");
  if (!existsSync(opts.online)) fail(`${opts.online} does not exist — the online cases need the fixture that verifies OFFLINE to attested`);

  // The plan, and ONLY the plan, decides what is intercepted (D132 §5 R27 item
  // 1; D133 §5.2: "never a hard-coded height"). It is emitted beside the
  // fixture by the same test that emits the fixture, out of the same
  // `ProbePlan::from_bundle` the page's document carries, so the fixture and
  // the intercepts cannot drift. `vector_heights` beside it is the INDEPENDENT
  // half — the upgrade heights read straight out of the frozen anchor vector —
  // and the `probe-plan` row below is what compares them.
  const planPath = join(expectDir ?? dirname(opts.online), `${basename(opts.online)}.plan.json`);
  if (!existsSync(planPath)) {
    fail(`${planPath} does not exist — the online cases route off the emitted probe plan and never off a hard-coded height (D133 §5.2)`);
  }
  const planned = JSON.parse(readFileSync(planPath, "utf8"));
  const heights = capturedHeights();
  const right = planned.blocks[0];
  const wrong = heights.find((h) => h !== right);
  if (planned.blocks.length !== 1 || right === undefined || wrong === undefined) {
    fail(
      `the online fixture's plan is ${JSON.stringify(planned.blocks)} and the captures cover ` +
        `${JSON.stringify(heights)} — R27's four cases need exactly one planned height and at least one ` +
        `OTHER captured real block to answer with`,
    );
  }
  console.log(`\n--- online cases over ${basename(opts.online)} (plan ${JSON.stringify(planned.blocks)}, wrong-block answers replayed from ${wrong}) ---`);

  const specs = [
    ["agreement → promotion", { answerFor: () => right, failingIndex: null }],
    // Not "→ refuted": see the correction to D133 beside the assertion below.
    ["mismatch → refutation recorded", { answerFor: () => wrong, failingIndex: null }],
    ["disagreement", { answerFor: (base, bases) => (base === bases[0] ? right : wrong), failingIndex: null }],
    ["one endpoint failed", { answerFor: () => right, failingIndex: 1 }],
  ];
  const observed = [];
  for (const [label, spec] of specs) observed.push([label, await onlineCase(opts.online, spec)]);
  const [promotion, mismatch, disagreement, oneDown] = observed.map(([, r]) => r);
  const bases = promotion.bases ?? [];

  // The premise, asserted rather than assumed: the wrong block's header must be
  // a DIFFERENT real header, or the mismatch case is a promotion in disguise.
  check(
    "online",
    `block ${wrong}'s captured header differs from block ${right}'s`,
    bases.length === 2 && captureFor(bases[0], right, "header") !== captureFor(bases[0], wrong, "header"),
    `the two captured headers compare equal, so the mismatch and disagreement cases would be serving the ` +
      `right answer under a wrong name and every row below them would be vacuous`,
  );

  // The probe set the page put ON THE WIRE, against the heights the frozen
  // upgrade group records. Both sides are independent: the left is a
  // measurement of the browser's traffic, the right is committed data read out
  // of testdata/vectors. A defect in `ProbePlan::from_bundle` is a defect in
  // BOTH surfaces and is invisible to a rendering comparison (D132 §7.4) — this
  // row and antseal-cli's `the_collector_asks_about_exactly_the_plans_heights`
  // are the only two instruments in the tree that can see one.
  const askedHeights = (r) => [
    ...new Set(
      r.asked
        .map((a) => /\/block-height\/(\d+)$/.exec(a.url))
        .filter((m) => m !== null)
        .map((m) => Number.parseInt(m[1], 10)),
    ),
  ].sort((a, b) => a - b);

  check(
    "probe-plan",
    "the page asks about exactly the heights the FROZEN upgrade group records — measured on the wire",
    JSON.stringify(askedHeights(promotion)) === JSON.stringify(planned.vector_heights),
    `the page asked about ${JSON.stringify(askedHeights(promotion))}; the committed anchor vector's ` +
      `upgrade group names ${JSON.stringify(planned.vector_heights)}. This is the page-surface half of ` +
      `D132 §7.4's warning: both surfaces derive the probe set from ProbePlan::from_bundle, so nothing ` +
      `that compares the two renderings can see a defect in it`,
  );
  check(
    "probe-plan",
    "and it makes exactly two GETs per planned height, and nothing else",
    promotion.asked.length === 2 * planned.blocks.length * 2 &&
      promotion.asked.every((a) => a.method === "GET"),
    `the page issued ${promotion.asked.length} request(s) for ${planned.blocks.length} planned height(s) ` +
      `across ${bases.length} endpoint(s): ${promotion.asked.map((a) => `${a.method} ${a.url}`).join(", ")} — ` +
      `one height is one height→hash and one hash→header PER ENDPOINT, and a receipt-free plan must ` +
      `produce no JSON-RPC POST at all`,
  );

  const outcomesOf = (r) => r.overlay?.outcomes ?? [];
  const soleLine = (r) => (outcomesOf(r).length === 1 ? outcomesOf(r)[0].line : `<${outcomesOf(r).length} outcome rows>`);
  const soleClass = (r) => (outcomesOf(r).length === 1 ? outcomesOf(r)[0].className : "");
  const noPromotion = (r) =>
    outcomesOf(r).every((o) => !o.className.includes("promoted")) &&
    attributionMarker !== null &&
    !outcomesOf(r).some((o) => o.line.includes(attributionMarker));

  for (const [label, r] of observed) {
    check(
      "online",
      `${label}: the interception handler itself did not throw`,
      (r.handlerErrors ?? []).length === 0,
      `the driver's own Fetch.requestPaused handler raised ${JSON.stringify(r.handlerErrors)} — a paused ` +
        `request that is never fulfilled, failed or continued hangs until the poll below times out, and ` +
        `the result reads like a page that would not render`,
    );
    check(
      "online",
      `${label}: the overlay renders`,
      r.overlay !== null && !r.overlay.hidden,
      `the overlay stayed hidden${r.overlay?.refusal ? `; the page refused with ${JSON.stringify(r.overlay.refusal)}` : ""} — ` +
        `every row about this case asserts over something that never appeared`,
    );
    check(
      "online",
      `${label}: the OFFLINE block is byte-identical before and after the online check (D64 §2)`,
      r.before !== null && JSON.stringify(r.before) === JSON.stringify(r.after),
      `the advisory overlay moved the cryptographic verdict's rendering; before/after first differ at ` +
        `index ${firstDifference(r.before ?? [], r.after ?? [])}`,
    );
  }

  check(
    "online",
    "agreement → promotion: one outcome row, promoted, carrying the online-attribution marker",
    outcomesOf(promotion).length === 1 &&
      soleClass(promotion).includes("promoted") &&
      attributionMarker !== null &&
      soleLine(promotion).includes(attributionMarker) &&
      soleLine(promotion).includes(String(right)),
    `row ${JSON.stringify(soleLine(promotion))} class ${JSON.stringify(soleClass(promotion))}; expected one ` +
      `promoted row naming block ${right} and carrying ${JSON.stringify(attributionMarker)} ` +
      `(wording::ONLINE_ATTRIBUTION_MARKER, read from the constant rather than restated here)`,
  );
  // ── the mismatch case, and a correction to D133 ──────────────────────────
  //
  // D133 §3 R8's table and §5.2's both say this case yields *"overlay row
  // `Refuted` with code `anchor-ots-online-header-mismatch`"*. **Measured here,
  // it does not, and it cannot** — with the fixture D133 itself specifies:
  //
  //   ots-1: agreed online evidence contradicts the embedded header
  //   (anchor-ots-online-header-mismatch), but a pending attestation
  //   out-votes the refutation; recorded, not promoted
  //
  // The artifact is A25's MERGED `.ots` — `merged-A.ots` spliced with the
  // alice, bob and catallaxy `.upgrade` bodies (the frozen vector's own
  // `provenance` string) — so it carries evaluable PENDING calendar branches
  // beside its Bitcoin-attested one. `classify_ots`'s rule **O5 out-ranks
  // O6/O7** and says so in as many words: *"a committed artifact that agreed
  // evidence refutes still renders `pending` when it has a pending branch, and
  // the refutation is carried as an A39 anomaly."* The overlay class is then
  // `NotPromoted{RefutationSuppressed}`, not `Refuted`.
  //
  // The frozen corpus already recorded the mechanism and D133 did not notice:
  // `ots-upgraded-online-block-absent` — the same artifact under rule O7 — is
  // pinned at `state: pending, suppressed: ["anchor-ots-online-block-absent"]`.
  // And it is not fixable by choosing a different fixture: the anchor vector
  // holds exactly ONE upgraded OTS artifact, so no committed material can make
  // an agreed refutation reach `invalid` at the bundle layer.
  //
  // What is asserted is therefore what D56's rules actually promise, and it is
  // not weaker in the direction that matters: the refutation is RECORDED (the
  // code reaches the rendered row) and NOTHING is promoted. The differential
  // row below keeps "carries the code" from being something every non-promoted
  // outcome does.
  console.log(`       mismatch case renders: ${JSON.stringify(soleLine(mismatch))}`);
  check(
    "online",
    "mismatch: the agreed contradicting header is RECORDED by its code, and nothing is promoted",
    outcomesOf(mismatch).length === 1 &&
      headerMismatchCode !== null &&
      soleLine(mismatch).includes(headerMismatchCode) &&
      noPromotion(mismatch),
    `row ${JSON.stringify(soleLine(mismatch))} class ${JSON.stringify(soleClass(mismatch))}; both endpoints ` +
      `returned block ${wrong}'s REAL header for height ${right}, so rule O6 must fire and its code ` +
      `${JSON.stringify(headerMismatchCode)} must reach the rendered row — as a refutation when the ` +
      `artifact has no pending branch, and as an A39 suppressed anomaly when it has (D56 §4, D93 §5)`,
  );
  check(
    "online",
    "and the code is NOT something every non-promoted outcome carries",
    headerMismatchCode !== null &&
      !soleLine(disagreement).includes(headerMismatchCode) &&
      !soleLine(oneDown).includes(headerMismatchCode),
    `the disagreement row ${JSON.stringify(soleLine(disagreement))} or the one-endpoint-failed row ` +
      `${JSON.stringify(soleLine(oneDown))} also carries ${JSON.stringify(headerMismatchCode)}, which would ` +
      `make the row above true of any case that failed to promote`,
  );
  check(
    "online",
    "disagreement: no promotion, no refutation, and the line names NO endpoint",
    outcomesOf(disagreement).length === 1 &&
      !soleClass(disagreement).includes("promoted") &&
      !soleClass(disagreement).includes("refuted") &&
      bases.length === 2 &&
      !bases.some((b) => soleLine(disagreement).includes(b)),
    `row ${JSON.stringify(soleLine(disagreement))} class ${JSON.stringify(soleClass(disagreement))}; the two ` +
      `endpoints answered with different REAL headers (${right} and ${wrong}), which suppresses promotion ` +
      `for this anchor alone and is never a per-endpoint failure — the discriminator is that a failure ` +
      `line names the endpoint that failed and a disagreement line names neither`,
  );
  check(
    "online",
    "one endpoint failed: the line names THAT endpoint, and there is no promotion on the survivor (D66)",
    outcomesOf(oneDown).length === 1 &&
      bases.length === 2 &&
      soleLine(oneDown).includes(bases[1]) &&
      !soleLine(oneDown).includes(bases[0]) &&
      noPromotion(oneDown) &&
      !soleClass(oneDown).includes("refuted"),
    `row ${JSON.stringify(soleLine(oneDown))} class ${JSON.stringify(soleClass(oneDown))}; endpoint 2 ` +
      `(${bases[1]}) had every request failed while endpoint 1 replayed the real captures. One endpoint ` +
      `agreeing with itself is not corroboration, so a promotion here would be the exact defect D66 forbids`,
  );

  // The four cases must differ in their VERDICT and not only in their input:
  // four green rows over four identical overlays would be four readings of one
  // case.
  const distinct = new Set(observed.map(([, r]) => soleLine(r)));
  check(
    "online",
    "the four cases produce four DIFFERENT overlay rows",
    distinct.size === 4,
    `${distinct.size} distinct row(s) across four cases:\n      ${[...distinct].map((l) => JSON.stringify(l)).join("\n      ")}\n` +
      `    if two cases render the same line, one of them is not testing what it says`,
  );

  // D132 §5 R27 item 3, kept and now with a non-empty counterpart: an online
  // confirmation over an empty-plan bundle makes ZERO fetches and still renders
  // the overlay. It is the cheapest available proof that the plan-driven path
  // invents no work.
  const emptyPlanBundle = opts.bundles.find((b) => basename(b) === "empty-anchor-unanchored.sealproof");
  if (emptyPlanBundle === undefined) {
    check("online", "the empty-plan zero-fetch counterpart was driven", false,
      "empty-anchor-unanchored.sealproof was not among the bundles, so D132 §5 R27 item 3's row could not run");
  } else {
    const zero = await onlineCase(emptyPlanBundle, { answerFor: () => right, failingIndex: null });
    check(
      "online",
      "an online confirmation over an empty-plan bundle makes ZERO fetches and still renders the overlay",
      zero.asked.length === 0 && zero.overlay !== null && !zero.overlay.hidden && outcomesOf(zero).length === 0,
      `${zero.asked.length} request(s) were intercepted and the overlay was ` +
        `${zero.overlay?.hidden ? "hidden" : "shown"} with ${outcomesOf(zero).length} outcome row(s) — ` +
        `D132 §5 R27 item 3 wants exactly this: the cheapest available proof that the plan-driven path ` +
        `does not invent work`,
    );
  }
}

// ── the receipt cases (R85; D137 §5 point 3, §7) ───────────────────────────
//
// The page had NO browser assertion on `#overlay-receipt` at all: D133 recorded
// that R27's four cases are block cases and *"none needs a receipt"*, so the
// element R85's defect lives in was never looked at in a browser. These two
// cases are that, over D137 §7's receipt-bearing twin.
//
// They differ in ONE mocked byte string — what both RPCs answer `eth_chainId`
// with — and that is the whole design:
//
//   * `0xa4b1` (42161) — the guard passes, both endpoints answer `null` for the
//     twin's `e1e1…e1` hash, and the module renders the CHAIN-SCOPED absence
//     line. Before D137 this said *"is not on chain"*, asserting absence from
//     every chain from a measurement that reached one. That sentence is R85.
//   * `0x66eee` (421614) — the guard refuses both endpoints, `wrong-chain`, and
//     the module renders the FAILURE line, which names the endpoints and no
//     chain at all.
//
// What is asserted is the DISCRIMINATOR rather than either sentence: an absence
// line names the chain and no endpoint, a failure line names the endpoints and
// no chain. That is D137 §3 R1's dividing rule, checkable without this file
// restating a frozen string — the same discipline the block rows use for
// disagreement-versus-failure, and the reason `--wording` is read for the two
// tokens this driver does match on.
//
// **What these rows cannot see, recorded so it is not over-read.** On the page
// the measured chain id can only ever be 42161 — the guard makes it so — so
// "the line names 42161" here would also be satisfied by a page that
// interpolated its own `ARBITRUM_CHAIN_ID` constant instead of the value it
// read off the wire. D137 §2 (c) names that trap; the assertion with teeth
// against it is `wording/tests.rs`'s two-chain differential, on the surface
// where the datum genuinely varies.

if (opts.receipt !== null) {
  if (opts.captures === null) fail("--receipt needs --captures <the A25 capture directory>");
  if (!existsSync(opts.receipt)) fail(`${opts.receipt} does not exist — D137 §7's receipt-bearing twin is emitted by crates/antseal-core/tests/page_fixtures.rs`);
  const planPath = join(expectDir ?? dirname(opts.receipt), `${basename(opts.receipt)}.plan.json`);
  if (!existsSync(planPath)) fail(`${planPath} does not exist — the receipt cases route off the emitted probe plan, never off a hard-coded hash`);
  const twinPlan = JSON.parse(readFileSync(planPath, "utf8"));

  console.log(`\n--- receipt cases over ${basename(opts.receipt)} (plan ${JSON.stringify(twinPlan.blocks)}, tx ${String(twinPlan.receipt_tx_hash).slice(0, 12)}…) ---`);

  // The premise, asserted before anything is driven: without a receipt in the
  // plan, D64 §3's presence rule suppresses the echo entirely and BOTH cases
  // below would be green over an element that never rendered.
  check(
    "receipt",
    "the twin's emitted plan carries a receipt target, so an echo can render at all",
    typeof twinPlan.receipt_tx_hash === "string" && /^[0-9a-f]{64}$/.test(twinPlan.receipt_tx_hash),
    `the plan sidecar's receipt_tx_hash is ${JSON.stringify(twinPlan.receipt_tx_hash)}; the fixture ` +
      `this drives must be the RECEIPT-BEARING twin (D137 §7 R13), not the block-only fixture beside it`,
  );

  const height = twinPlan.blocks[0];
  const absent = await onlineCase(opts.receipt, {
    answerFor: () => height,
    failingIndex: null,
    chainIdHex: "0xa4b1",
  });
  const wrongChain = await onlineCase(opts.receipt, {
    answerFor: () => height,
    failingIndex: null,
    chainIdHex: "0x66eee",
  });

  const arb = absent.arbBases ?? [];
  const rpcCalls = (r, method) =>
    r.asked.filter((a) => a.method === "POST" && (a.postData ?? "").includes(`"${method}"`)).length;
  const receiptLine = (r) => r.overlay?.receipt ?? null;

  for (const [label, r] of [["chain 42161", absent], ["wrong chain", wrongChain]]) {
    check(
      "receipt",
      `${label}: the module ACCEPTED the page's evidence document (the R6 wire row)`,
      (r.handlerErrors ?? []).length === 0 && r.overlay !== null && !r.overlay.hidden && r.overlay.refusal === null,
      `the overlay is ${r.overlay?.hidden ? "hidden" : "shown"} and the page reported ` +
        `${JSON.stringify(r.overlay?.refusal ?? null)}; handler errors ${JSON.stringify(r.handlerErrors ?? [])}. ` +
        `D137 §3 R6 adds a REQUIRED \`receipt.chain_id\` to that document and the module is ` +
        `deny_unknown_fields throughout, so a template that did not send it — or sent it under ` +
        `another name — fails exactly here, loudly, which is the failure D137 §11 risk 3 wants`,
    );
    check(
      "receipt",
      `${label}: #overlay-receipt renders a line`,
      typeof receiptLine(r) === "string" && receiptLine(r).length > 0,
      `the receipt element is ${JSON.stringify(receiptLine(r))} — the twin carries a receipt and it ` +
        `was probed, so D64 §3's presence rule says it must render, and every row below is about ` +
        `its contents`,
    );
  }

  // Printed, as the mismatch case prints its row: the sentence a third party
  // actually sees is the subject of this record, and a green tick that never
  // shows it is a worse log than one that does.
  console.log(`       guard passes  -> ${JSON.stringify(receiptLine(absent))}`);
  console.log(`       guard refuses -> ${JSON.stringify(receiptLine(wrongChain))}`);

  // D137 §3 R1's dividing rule, as a two-sided differential. Neither half is a
  // frozen sentence: one is the chain id this driver itself mocked, the other
  // is the pair of endpoint URLs the page itself chose.
  check(
    "receipt",
    "chain 42161: the absence line names the chain that was probed, and names no endpoint",
    typeof receiptLine(absent) === "string" &&
      receiptLine(absent).includes("42161") &&
      arb.length === 2 &&
      !arb.some((b) => receiptLine(absent).includes(b)),
    `the receipt line is ${JSON.stringify(receiptLine(absent))}. Both RPCs answered that they hold ` +
      `no receipt for the twin's hash, having each positively answered eth_chainId with 42161 — so ` +
      `the sentence must say WHICH chain it is absent from. An unqualified "is not on chain" is a ` +
      `claim about every chain, drawn from a measurement of one (R85)`,
  );
  check(
    "receipt",
    "wrong chain: the failure line names BOTH endpoints, and names no chain (the negative control)",
    typeof receiptLine(wrongChain) === "string" &&
      arb.length === 2 &&
      arb.every((b) => receiptLine(wrongChain).includes(b)) &&
      !receiptLine(wrongChain).includes("42161"),
    `the receipt line is ${JSON.stringify(receiptLine(wrongChain))}. Both endpoints reported chain ` +
      `421614 against the page's pinned 42161, so nothing was ever asked about the transaction: the ` +
      `line must report the PROBE (which endpoints failed, and how) and must NOT carry the absence ` +
      `sentence, which would assert a measurement that never happened`,
  );
  check(
    "receipt",
    "and the two cases render two DIFFERENT lines",
    receiptLine(absent) !== null && receiptLine(absent) !== receiptLine(wrongChain),
    `both cases rendered ${JSON.stringify(receiptLine(absent))}; one mocked byte string apart, they ` +
      `must not read the same, or one of the two rows above is passing on the other's evidence`,
  );

  // D137 §5 point 1 — "the guard returns before the receipt query" — measured
  // on the wire rather than read off the source. This is the fail-closed claim
  // R85's Accept row 2 makes, and it is the only instrument that can see it on
  // the page surface.
  check(
    "receipt",
    "the guard runs on BOTH endpoints in both cases — eth_chainId is asked twice each",
    rpcCalls(absent, "eth_chainId") === 2 && rpcCalls(wrongChain, "eth_chainId") === 2,
    `eth_chainId was called ${rpcCalls(absent, "eth_chainId")} time(s) in the 42161 case and ` +
      `${rpcCalls(wrongChain, "eth_chainId")} in the wrong-chain case; a pair is two endpoints and ` +
      `each must be guarded, or one of them contributed an answer nobody checked the chain of`,
  );
  check(
    "receipt",
    "and a refused guard makes ZERO receipt queries, where a passed guard makes two (fail-closed, on the wire)",
    rpcCalls(wrongChain, "eth_getTransactionReceipt") === 0 &&
      rpcCalls(absent, "eth_getTransactionReceipt") === 2,
    `eth_getTransactionReceipt was called ${rpcCalls(wrongChain, "eth_getTransactionReceipt")} time(s) ` +
      `after the guard refused and ${rpcCalls(absent, "eth_getTransactionReceipt")} time(s) after it ` +
      `passed. The first number is R85 Accept row 2 and D137 §5 point 1: an endpoint serving another ` +
      `chain must never be asked about the transaction. The second is what keeps the first from ` +
      `being true of a page that asks nothing at all`,
  );

  // The block half is untouched by either case, which is what makes them
  // receipt rows rather than "the online path broke" rows.
  for (const [label, r] of [["chain 42161", absent], ["wrong chain", wrongChain]]) {
    const rows = r.overlay?.outcomes ?? [];
    check(
      "receipt",
      `${label}: the ANCHOR half still promotes — the receipt outcome moved nothing`,
      rows.length === 1 && rows[0].className.includes("promoted"),
      `the outcome rows are ${JSON.stringify(rows)}; both endpoints replayed the real captured header ` +
        `for block ${height}, so the anchor must promote exactly as it does in the block cases. A ` +
        `receipt echo is supporting evidence and may not reach an anchor outcome (D64 §5)`,
    );
    check(
      "receipt",
      `${label}: the OFFLINE block is byte-identical before and after (D64 §2)`,
      r.before !== null && JSON.stringify(r.before) === JSON.stringify(r.after),
      `the advisory overlay moved the cryptographic verdict's rendering; before/after first differ ` +
        `at index ${firstDifference(r.before ?? [], r.after ?? [])}`,
    );
  }
}

// ── the instrument's own planted fault ─────────────────────────────────────

if (opts.selfTest) {
  // A green run proves nothing until the instrument has been seen to refuse
  // something. The zero-network assertion is the one every other row leans on,
  // so it is the one planted against: a page that fetches must go red HERE.
  //
  // This is a POSITIVE control — its success path is green, so it can never
  // make the job red. The seeded failure that CAN is D136 §2 R13's
  // ANTSEAL_PAGE_SEED_FAILURE, driven by
  // `scripts/verifier-page-browser.sh --seed-test`.
  console.log("\n--- self-test: a page that fetches must fail the network row ---");
  const probe = join(mkdtempSync(join(tmpdir(), "antseal-selftest-")), "fetches.html");
  writeFileSync(
    probe,
    `<!doctype html><meta charset="utf-8"><p id="build">planted</p>` +
      `<script>fetch("https://example.invalid/probe").catch(()=>{});</script>`,
  );
  const probed = await session(pathToFileURL(probe).href, async (ctx) => {
    await waitForBoot(ctx.evaluate);
    await sleep(600);
    return {};
  });
  const probeForeign = networkRequests(probed.events).filter((u) => !u.startsWith("file://"));
  if (probeForeign.length === 0) {
    console.error("::error::verifier-page-browser self-test: a page that calls fetch() produced NO observed request — the network instrument is blind and every green row above is worthless");
    failures += 1;
  } else {
    console.log(`  planted fault: a page that calls fetch()        -> SEEN (${probeForeign[0]})`);
  }
  rmSync(probe, { force: true });
}

// ── the diagnosis set (D136 §2 R14's inputs) ───────────────────────────────
//
// Written ONLY when the job is red, which is what makes the workflow's
// `if: failure()` artifact branch causal rather than decorative — and what
// gives R13's negative control something to observe: with no seed, the same
// invocation is green and leaves nothing to upload.
if (diagnosisDir !== null && failures > 0) {
  mkdirSync(diagnosisDir, { recursive: true });
  if (run.screenshot !== null) {
    writeFileSync(join(diagnosisDir, "screenshot.png"), Buffer.from(run.screenshot, "base64"));
  }
  writeFileSync(join(diagnosisDir, "events.ndjson"), run.events.map((e) => JSON.stringify(e)).join("\n"));
  console.error(`::notice::verifier-page-browser: diagnosis written to ${diagnosisDir}`);
}

const seconds = ((Date.now() - started) / 1000).toFixed(1);
if (SEED !== null && !seedFired) {
  fail(
    `ANTSEAL_PAGE_SEED_FAILURE=${SEED} was set but that row never fired. Either it was ALREADY failing ` +
      `for a real reason — in which case seeding it proves nothing, which is the pre-image rule D136 §2 ` +
      `R13 states — or this invocation never reached it.`,
  );
}
if (failures > 0) fail(`${failures} browser row(s) failed in ${seconds}s`);
console.log(
  `\n  OK: booted offline, ${requests.length} request(s) (the page only), zero CSP violations, ` +
    `${run.drops.length} bundle(s) rendered, ${parityCompared} compared string-for-string against ` +
    `\`antseal verify\`, ${shapesChecked} reveal shape(s) asserted in the DOM` +
    `${opts.online === null ? "" : ", 4 online cases + the empty-plan counterpart"}` +
    `${opts.receipt === null ? "" : ", 2 receipt cases"} — ${seconds}s.`,
);
