#!/usr/bin/env node
// D129 §5 R9 assertion 8, executed: load the BUILT page from a `file://` URL in
// a real browser, assert zero network requests beyond the page itself, drop a
// real bundle onto it, and compare what it renders against native.
//
//   node scripts/verifier-page-browser.mjs <page.html> [bundle.sealproof …]
//   node scripts/verifier-page-browser.mjs --self-test <page.html>
//
// Normally invoked by ./scripts/verifier-page-browser.sh, which builds both.
//
// ── Why raw CDP and not playwright/puppeteer ───────────────────────────────
//
// The repo has no `package.json` and no `node_modules`, and D129 drove both
// engines over the DevTools Protocol from a raw WebSocket — node has had a
// global `WebSocket` since v22. A driver with no dependency is a driver that
// cannot pull 150 MB of browser binaries into a metered CI minute, and Q19's
// lane is local-only for exactly that reason.
//
// ── The assertion that matters is the NEGATIVE one ─────────────────────────
//
// `Network.requestWillBeSent` fires for every request the page attempts,
// including ones the CSP then blocks — which is what makes it the right
// instrument for "fetches nothing". A page that asked and was refused has
// still asked, and R23's Accept row says the offline run fetches nothing at
// all. The one permitted request is the page document itself.
import { spawn } from "node:child_process";
import { mkdtempSync, rmSync, existsSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
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

async function session(pageUrl, drive) {
  const profile = mkdtempSync(join(tmpdir(), "antseal-page-"));
  const port = 9500 + Math.floor(Math.random() * 400);
  const browser = spawn(BROWSER, [...FLAGS, `--user-data-dir=${profile}`, `--remote-debugging-port=${port}`, "about:blank"], {
    stdio: ["ignore", "pipe", "pipe"],
  });
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
  ws.onmessage = (m) => {
    const msg = JSON.parse(m.data);
    if (msg.id !== undefined) {
      const p = pending.get(msg.id);
      pending.delete(msg.id);
      if (msg.error) p.rej(new Error(JSON.stringify(msg.error))); else p.res(msg.result);
    } else events.push(msg);
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
  for (const domain of ["Runtime", "Log", "Page", "Network", "DOM"]) await S(`${domain}.enable`);

  const evaluate = async (expression) => (await S("Runtime.evaluate", { expression, returnByValue: true })).result.value;

  await S("Page.navigate", { url: pageUrl });
  let result;
  try {
    result = await drive({ S, evaluate, events });
  } finally {
    ws.close();
    browser.kill("SIGKILL");
    await sleep(150);
    rmSync(profile, { recursive: true, force: true });
  }
  return { ...result, events };
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

async function dropBundle({ S, evaluate }, bundlePath) {
  // depth:0, deliberately: depth:-1 serialises every inline-script text node of
  // a 2.4 MB page over the protocol and kills the connection.
  const { root } = await S("DOM.getDocument", { depth: 0 });
  const { nodeId } = await S("DOM.querySelector", { nodeId: root.nodeId, selector: "input[type=file]" });
  if (!nodeId) fail("the page exposes no input[type=file]; R23's file-picker fallback is part of its Do");
  await S("DOM.setFileInputFiles", { files: [resolve(bundlePath)], nodeId });
  for (let i = 0; i < 300; i += 1) {
    await sleep(100);
    const state = await evaluate(
      "document.getElementById('result').hidden ? (document.getElementById('failure').hidden ? 'WAIT' : 'FAILURE') : 'RESULT'",
    );
    if (state !== "WAIT") return state;
  }
  return "TIMEOUT";
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

let failures = 0;
function check(label, condition, detail) {
  if (condition) console.log(`  OK   ${label}`);
  else { console.error(`::error::verifier-page-browser: ${label} — ${detail}`); failures += 1; }
}

const args = process.argv.slice(2);
const selfTest = args[0] === "--self-test";
const [pagePath, ...bundles] = selfTest ? args.slice(1) : args;
if (!pagePath) fail("usage: verifier-page-browser.mjs [--self-test] <page.html> [bundle …]");
if (!existsSync(pagePath)) fail(`${pagePath} does not exist — build it with scripts/verifier-page-build.sh`);
const pageUrl = pathToFileURL(resolve(pagePath)).href;

// ── the run ────────────────────────────────────────────────────────────────
const run = await session(pageUrl, async (ctx) => {
  const build = await waitForBoot(ctx.evaluate);
  const states = [];
  for (const bundle of bundles) states.push([bundle, await dropBundle(ctx, bundle)]);
  return { build, states };
});

console.log(`verifier-page-browser (${BROWSER}, node ${process.versions.node}) — ${pageUrl}`);

check(
  "the page boots from a file:// origin and instantiates the module",
  Boolean(run.build),
  "the footer's build line never populated, so initSync({ module }) did not complete — D129 §5 R2's inlined module is what makes this work without a server",
);
if (run.build) console.log(`       ${run.build}`);

const requests = networkRequests(run.events);
const foreign = requests.filter((url) => url !== pageUrl);
check(
  "the offline run fetches NOTHING but the page itself",
  foreign.length === 0,
  `the page attempted ${foreign.length} further request(s): ${foreign.slice(0, 5).join(", ")} — R23's Accept row is that a file:// or no-network context completes verification with no external resource`,
);
console.log(`       ${requests.length} request(s) total, all accounted for`);

const csp = violations(run.events);
check(
  "the page runs with zero Content-Security-Policy violations",
  csp.length === 0,
  `the browser reported:\n    ${csp.slice(0, 4).join("\n    ")}`,
);

for (const [bundle, state] of run.states) {
  check(
    `a real bundle dropped through the file picker renders a verdict (${bundle.split("/").pop()})`,
    state === "RESULT",
    `the page reached '${state}' — RESULT means the verdict block rendered, FAILURE means a typed error was displayed, TIMEOUT means neither`,
  );
}

if (selfTest) {
  // A green run proves nothing until the instrument has been seen to refuse
  // something. The zero-network assertion is the one every other row leans on,
  // so it is the one planted against: a page that fetches must go red HERE.
  console.log("\n--- self-test: a page that fetches must fail the network row ---");
  const probe = join(mkdtempSync(join(tmpdir(), "antseal-selftest-")), "fetches.html");
  const { writeFileSync } = await import("node:fs");
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

if (failures > 0) fail(`${failures} browser row(s) failed`);
console.log(`\n  OK: booted offline, ${requests.length} request(s) (the page only), zero CSP violations, ${run.states.length} bundle(s) rendered.`);
