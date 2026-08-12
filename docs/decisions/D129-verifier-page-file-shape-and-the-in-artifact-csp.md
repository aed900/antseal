# D129 — The verifier page's file shape, the packaging step, and the Content-Security-Policy that decides it

- **Status: RESOLVED — the published page is ONE FILE, `index.html`, with the
  wasm-bindgen glue and the base64-encoded module inlined into a single inline
  `<script type="module">`, built from `wasm-pack --target web` — the target the
  R22 gate already builds and already exercises. `--target no-modules` is
  REFUSED. R23's offline Accept row is KEPT VERBATIM: measured, a single-file
  page under a real `file://` origin completes verification of a real
  `.sealproof` — anchors evaluated — and returns a report BYTE-IDENTICAL to
  native, in Chromium 150 and in Firefox 140.13.0esr, with drag-and-drop and the
  file-picker both working and exactly one network request (the page itself).
  The published `SHA256SUMS` therefore covers a served closure of ONE file; the
  pre-packaging `.wasm` D63 §5 R2 names is published as a separately-named
  artifact of the SIGNED RELEASE, never as a line in the served manifest. The
  CSP is `default-src 'none'` with `script-src` locked to the two inline scripts
  by SHA-256 hash plus `'wasm-unsafe-eval'`, and `connect-src https:` — not the
  six pinned hosts.** The wave owner's lean — *single-file via
  `--target no-modules`* — **survives in its conclusion and is OVERTURNED in
  every one of its reasons**: `no-modules` is not needed, because what `file://`
  blocks is *fetching* a sibling script, not the module script *type*, and the
  `--target web` glue contains **no static `import` at all** (measured: six
  `export` declarations, one `import.meta.url` in an unreached branch), so
  inlining it into an inline module script is a pure textual embedding that
  works under `file://` in two engines. `no-modules` is then refused on two
  measurements the lean did not contain: it **silently drops the Safari
  `TextDecoder` guard** the `web` glue emits, on the one function every report
  string crosses, and it is glue **no committed check in this repository has
  ever run**. **The weakness the wave owner saw INVERTS on measurement.** An
  all-inline page does *not* force `'unsafe-inline'`: hashes work, for classic
  and module inline scripts, in both engines, from `file://` — and because the
  module is *inside* the hashed script, the hash covers **99.4 % of the payload
  that Subresource Integrity structurally cannot** (D63 §4 way 5: SRI does not
  apply to instantiated wasm). A one-byte edit anywhere in the artifact's
  payload makes the browser **refuse to run the page at all**, which turns
  D63 §2.2's third job — *catching accident, the likely failure* — from a number
  nobody compares into a hard fail-closed. It is still **no defence against a
  malicious host** (D63 §2.1 stands, unweakened, and this record does not
  pretend otherwise). Two things the enumeration missed decide details of their
  own: a `connect-src` naming the six pinned hosts **silently breaks spec line
  137's mandated user-overridable endpoints** — measured, and the page cannot
  even say why (D66 §2.3) — and D63 §5 R5's *"template→artifact is a one-token
  diff"* clause is broken in letter by any inlining, so it is **narrowed here
  and replaced by a stronger mechanical check**: the artifact decomposes into a
  **2 858-byte authored residue** plus two verbatim tokens, verifiable in 29 ms.
- **Date: 2026-08-12** (wave 19 planning round, D129 lane; briefed to overturn
  the single-file-via-`no-modules` lean. The conclusion survives, both of its
  stated mechanisms die, the CSP objection inverts into the strongest argument
  *for* the ruling, and one arm nobody supplied — inline-compressing the module
  to erase the wire cost — is refused on a measured compressor non-determinism
  rather than on taste. Every browser claim below is accompanied by the
  browser's own message.)
- **Owning tasks: R23** (authors the page, owns the CSP by the registrar's
  2026-08-12 ruling on its `Notes`, and owns the file shape — this record is the
  answer to D63 §10 (ii), which flagged the question as unowned), **R25** (the
  build script, the packaging step, `SHA256SUMS`, the footer), **R26** (deploys
  the set; its set-equality check now runs over one file), **R27/Q19** (loads the
  built artifact; the parity gate), **R22** (supplies the glue and the closed
  export list; unedited by this ruling), **R24** (its overrides are what
  `connect-src` must not break), **Q31** (publishes the pre-packaging module as a
  release artifact).
- **Amends**: `tasks/R.md` R23 (`Do` + `Notes`), R25 (`Notes`), R26 (`Notes`),
  and **`docs/decisions/D63-…` §5 R5** — one clarifying rider on the closed
  operation list and one recorded narrowing of its *"one-token diff"* clause,
  both quoted in §11 for the registrar. **Supersedes**: nothing.
  **Corrects**: nothing in code. Two instrument findings are reported in §10,
  one of which is a claim in **D66 §1 (d)** about Firefox that this lane
  falsified by driving Firefox successfully.

---

## 1. What was measured

**Method note.** Every browser arm below ran in **Chromium 150.0.7871.181**
(the build D66 used) driven over the DevTools Protocol from a raw WebSocket —
no puppeteer — so console text, `Log.entryAdded`, `Network.requestWillBeSent`
and `securitypolicyviolation` events are the browser's own and are quoted
verbatim. The cross-engine arm is **Firefox 140.13.0esr**. Toolchain:
`wasm-pack 0.15.0`, `wasm-bindgen 0.2.126`, `node v24.12.0`, `rustc` per the
committed pins. **No repository file was modified**; every build wrote to
`target/d129/`, and the artifact the R22 gate uses
(`target/wasm-pack/antseal-wasm/antseal_wasm_bg.wasm`,
`d68204122d56aaf600e4830f1ae9c9f845ba447cf66df47a791497cd2b2daba9`) is
byte-unchanged.

### (a) The two facts the brief supplied — both confirmed

```
$ wasm-pack build --help | grep -- '--target'
  -t, --target <TARGET>  Sets the target environment.
      [possible values: bundler, nodejs, web, no-modules, deno] [default: bundler]

$ stat -c '%s' target/wasm-pack/antseal-wasm/antseal_wasm_bg.wasm
1841981
$ base64 -w0 target/wasm-pack/antseal-wasm/antseal_wasm_bg.wasm | wc -c
2455976
```

`no-modules` is a supported value; the module is **1 841 981 B** and its base64
is **2 455 976 chars** (2.46 MB). Both as briefed.

### (b) The `.wasm` is byte-identical across the two targets — so the target choice does not move D63's digest

Built at the same `HEAD` (`551eb04d8310a1aa5959c2efa4eb71186f0ddfc3`), with the
same hermetic flags `scripts/wasm-pack-build.sh` uses
(`--release --no-pack --no-opt --mode no-install`):

```
$ sha256sum target/d129/web/antseal_wasm_bg.wasm target/d129/no-modules/antseal_wasm_bg.wasm
8c0d3a12aa6a7617ad11eb657fcd1df5d29d15463c537408a27c87dea47fc286  …/web/…
8c0d3a12aa6a7617ad11eb657fcd1df5d29d15463c537408a27c87dea47fc286  …/no-modules/…
```

`--target` changes only the JS glue. **D63 §5 R2's subject is invariant under
this decision**, which is a stronger form of the shape-independence D63 claimed
for itself. (The pre-existing artifact differs from these only in the 40-byte
`ANTSEAL_SOURCE_COMMIT` string at offset 1 418 077 — `cmp -l` reports exactly
**38** differing bytes, all inside it.)

### (c) The `--target web` glue has NO static import — this is what the lean got wrong

```
$ grep -n "^import \|^export \|import\.meta\|import(" target/d129/web/antseal_wasm.js
11:export function build_info() {
42:export function start() {
57:export function verdict_class(bundle_bytes, evidence_json) {
89:export function verify(bundle_bytes) {
125:export function verify_online(bundle_bytes, evidence_json) {
346:        module_or_path = new URL('antseal_wasm_bg.wasm', import.meta.url);
359:export { initSync, __wbg_init as default };
```

Six `export` declarations, **zero `import` statements**, and the one
`import.meta.url` sits inside `__wbg_init`'s `module_or_path === undefined`
branch — unreached when the caller supplies bytes. So the glue's text can be
pasted into an inline module script and there is **nothing left to resolve and
nothing left to fetch**. The lean's premise — *"ES module scripts from `file://`
are blocked outright"* — conflates the script *type* with the *fetch*: what
`file://` blocks is retrieving a sibling resource, and an inline script is not
retrieved. §1 (f) measures both halves.

### (d) `no-modules` drops the Safari `TextDecoder` guard, on the path every report string crosses

```
$ grep -c "MAX_SAFARI_DECODE_BYTES" target/d129/web/antseal_wasm.js
2
$ grep -c "MAX_SAFARI_DECODE_BYTES" target/d129/no-modules/antseal_wasm.js
0
```

`--target web` emits:

```js
const MAX_SAFARI_DECODE_BYTES = 2146435072;
let numBytesDecoded = 0;
function decodeText(ptr, len) {
    numBytesDecoded += len;
    if (numBytesDecoded >= MAX_SAFARI_DECODE_BYTES) {
        cachedTextDecoder = new TextDecoder('utf-8', { ignoreBOM: true, fatal: true });
        cachedTextDecoder.decode();
        numBytesDecoded = len;
    }
    return cachedTextDecoder.decode(getUint8ArrayMemory0().subarray(ptr, ptr + len));
}
```

`--target no-modules` emits the same function **without the guard**.
`decodeText` is reached from `getStringFromWasm0`, i.e. from **every string the
module returns** — every report, every overlay, every typed error. The guard
exists for a Safari-specific cumulative-decode failure, and Safari is precisely
the engine this project cannot test. Choosing the target whose glue omits a
workaround for the untestable engine is the wrong direction, and no arm of the
lean priced it.

### (e) `no-modules` DOES preserve R22's full export surface — measured, so this is not the reason to refuse it

The `no-modules` glue loaded into a `node:vm` context and driven against the
same corpus `scripts/wasm-boundary.mjs` uses:

```
typeof wasm_bindgen: function
keys: build_info, initSync, start, verdict_class, verify, verify_online
missing: []  unexpected: []
R9 vectors byte-identical to native through no-modules glue: 21/21
hostile input -> Error: cbor-unexpected-type: bundle: expected map, found unsigned i…
```

D18 §5 R4's closed list is intact, all 21 R9 vectors are byte-identical, and
hostile input still yields a typed error carrying the frozen code. **The brief
expected "real limitations — find them" in the export surface; there are none.**
The real ones are (d) above and (k) below.

One scoping subtlety, recorded so it is not rediscovered: `no-modules` emits
`let wasm_bindgen = (function(exports){…})({__proto__: null})`. That is a
lexical binding, **not** a property of `globalThis` — `window.wasm_bindgen` is
`undefined`. And its wasm-URL fallback is
`new URL(document.currentScript.src, location.href)`, which for an *inline*
script resolves to the page's own URL: a page that called the default init
instead of `initSync` would try to instantiate its own HTML as WebAssembly.

### (f) The multi-file arm under `file://`, with both browsers' own error text

A page loading `--target web` glue as a sibling, opened at a real `file://`
origin. **Chromium 150** (`Log.entryAdded`, verbatim):

> Access to script at
> `'file:///…/arm-multi-web/antseal_wasm.js'` from origin `'null'` has been
> blocked by CORS policy: Cross origin requests are only supported for protocol
> schemes: chrome, chrome-extension, chrome-untrusted, data, http, https,
> isolated-app.

and the page's own catch:

> `TypeError: Failed to fetch dynamically imported module: file:///…/antseal_wasm.js`

with `Network.loadingFailed → net::ERR_FAILED`. **Firefox 140.13.0esr**, same
page, its own text:

> `TypeError: error loading dynamically imported module: file:///…/antseal_wasm.js`

Two engines, two messages, one refusal. The multi-file arm cannot satisfy
R23's Accept row under `file://`, and this is not a Chromium policy that a flag
could relax — Firefox reaches the same place by its own route.

### (g) The single-file arm under `file://`, verifying a real bundle end to end

A single `index.html` carrying the `--target web` glue and the base64 module in
one inline `<script type="module">`, opened at a `file://` origin, with a real
`.sealproof` (`multi-file-anchored/mixed`, 7 981 B) driven into the file input
by `DOM.setFileInputFiles` — the same CDP call playwright's `setInputFiles`
makes, which is what R27's `Do` already specifies:

```
=== window.__D129 ===
{ "done": true, "fileDone": true, "errors": [],
  "b64len": 2455976, "tDecodeAtob": 15, "moduleBytes": 1841981,
  "moduleSha": "8c0d3a12aa6a7617ad11eb657fcd1df5d29d15463c537408a27c87dea47fc286",
  "tInstantiate": 7, "tVerify": 30, "reportLen": 1224,
  "buildInfo": "{\"core_version\":\"0.0.0\",…,\"source_commit\":\"551eb04d…\"}",
  "verdictClass": "{\"rung\":\"verify-anchor-refuted\",…,\"total_anchors\":3}" }
=== console + log entries === (none)
=== network requests ===
  GET file:///…/single-web.html
```

**One request — the page itself.** And the report the page produced was
compared byte-for-byte against the native corpus entry:

```
expected(native) bytes: 1224   page bytes: 1224
BYTE-IDENTICAL: true
```

The anchors block of that report carries three evaluated anchor verdicts
(`ots`/`tsa`, all `invalid` for these fixtures — §10 (iii) prices that
coverage), so *"completes verification incl. anchor checks"* is satisfied in
its own terms. The in-page `moduleSha` equals the on-disk `.wasm` digest, so
D63 §5 R2's extract-decode-hash reader check reproduces the footer's number
from the page alone.

### (h) Both affordances R23's `Do` names work from `file://`

- **File picker**: §1 (g) — `DOM.setFileInputFiles` produced a genuine `File`
  and the verification ran.
- **Drag-and-drop**, driven as a real drag (`Input.setInterceptDrags` +
  `Input.dispatchDragEvent` `dragEnter`/`dragOver`/`drop` carrying the file
  path), not a synthesized event:

```
dragErr: null
result: {"dropDone":true,"dropReportLen":1224,"hasDataTransfer":true,"errors":[]}
```

`FileReader` and `DataTransfer` are both present at a `null` origin.

### (i) The cross-engine arm — Firefox 140.13.0esr runs the ruled page from `file://`

D66 §1 (d) recorded Firefox as attempted-and-failed in this environment. It
runs, with `gfx.webrender.software=true` in the profile and a POST beacon
instead of DOM inspection — it still prints
`[GFX1-]: RenderCompositorSWGL failed mapping default framebuffer`, and its JS
engine is unaffected:

```
Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0
{"done":true,"errors":[],"b64len":2455976,"tDecodeNative":35,"tDecodeAtob":75,
 "moduleBytes":1841981,
 "moduleSha":"8c0d3a12aa6a7617ad11eb657fcd1df5d29d15463c537408a27c87dea47fc286",
 "tInstantiate":84,"tTotal":300,
 "buildInfo":"{…\"source_commit\":\"551eb04d…\"}",
 "hasDataTransfer":true,"hasFileReader":true}
```

Same module digest, same inline-module-script mechanism, second engine.
§10 (i) reports the D66 correction.

### (j) CSP is enforced from a `file://` origin, and `'wasm-unsafe-eval'` is required

Seven policies, same page, same origin. Chromium's own text where it refused:

| `script-src` | wasm instantiates? | the browser's message / event |
| --- | --- | --- |
| *(no CSP)* | **yes** | — |
| `'unsafe-inline'` | **no** | `CompileError: WebAssembly.Module(): Compiling or instantiating WebAssembly module violates the following Content Security policy directive because 'unsafe-eval' is not an allowed source of script in the following Content Security Policy directive: "script-src 'unsafe-inline'".` · event `directive=script-src blocked=wasm-eval` |
| `'unsafe-inline' 'wasm-unsafe-eval'` | **yes** | — |
| `'unsafe-inline' 'unsafe-eval'` | **yes** | — (broader than needed; refused in §5) |
| `'sha256-…' 'sha256-…'` | **no** | same `CompileError`, quoting the hash list |
| `'sha256-…' 'sha256-…' 'wasm-unsafe-eval'` | **yes** | — |
| `'sha256-AAAA…' ×2 'wasm-unsafe-eval'` (wrong hashes) | scripts never run | `Executing inline script violates the following Content Security Policy directive '…'. Either the 'unsafe-inline' keyword, a hash ('sha256-O9uLlKmTOd7wIsgMKD0IVyAjvC0KDJ3a5O/krXS/eew='), or a nonce ('nonce-…') is required to enable inline execution. The action has been blocked.` |

Three things follow. **CSP is live under `file://`** — D62 §3 R6's
*policy-inside-the-hashed-artifact* rule pays off in exactly the mode a header
could never reach. **`'wasm-unsafe-eval'` is required and sufficient** —
R23's Accept row already said to verify this against real browsers rather than
assume it; it is now verified, in two engines (§1 l). And **hashes work for
inline scripts, including the inline `<script type="module">`** — the arm the
whole ruling rests on.

### (k) The hash makes the artifact fail closed on a one-byte edit to its own payload

Correct hashes, then one byte flipped 200 000 chars into the base64 module —
i.e. a corrupted payload, not a corrupted policy:

> `Executing inline script violates the following Content Security Policy
> directive 'script-src 'sha256-O9uLlKmTOd7w…' 'sha256-0R59UggBwCBJ…'
> 'wasm-unsafe-eval''. … The action has been blocked.`

The page does not run at all (`runError: "ReferenceError: B64 is not defined"`
from the second script, which is itself then blocked). Compare the counterfactual
for a multi-file page: D63 §4 way 5 measured that SRI covers a `<script>` and
**does not apply to instantiated WebAssembly**, so the 1 841 981-byte module —
**99.40 %** of the 1 853 162-byte payload — would carry no in-artifact integrity
at all. §3 draws the consequence.

And the trap, measured so nobody adds it later as a "fallback":

> `Note that 'unsafe-inline' is ignored if either a hash or nonce value is
> present in the source list.`

### (l) Firefox agrees on the whole policy

Firefox 140.13.0esr, `file://`, `default-src 'none'; script-src 'sha256-…'
'sha256-…' 'wasm-unsafe-eval'; …`:

```
{"policy":"ship","done":true,"errors":[],"tDecode":67,"moduleBytes":1841981,
 "tInstantiate":101,"wasmOk":true,"buildInfo":"{…}"}
```

Zero violations — both inline-script hashes matched, including the module
script — and `'wasm-unsafe-eval'` honoured.

### (m) A `connect-src` naming the six pinned hosts silently breaks spec line 137's overrides

Two policies, same page, same origin; the override probe is a **non-pinned
`https:` origin on a dead port**, so no network is reached and the CSP decision
is isolated:

| `connect-src` | pinned host | non-pinned `https:` override | `securitypolicyviolation` |
| --- | --- | --- | --- |
| the six pinned hosts | allowed | `TypeError: Failed to fetch` | **`CSP connect-src -> https://127.0.0.1:9/override-probe`** |
| `https:` | allowed | `TypeError: Failed to fetch` | *(none)* |

The page sees the **identical** `TypeError` either way. So a host allowlist does
not merely forbid the override spec line 137 mandates — *"two pinned default
endpoints per source, results must agree … **user-overridable**"* — it forbids
it **undiagnosably**, because D66 §2.3 already established the page may never
name a cause. A user would type a valid endpoint and be told nothing. §5 R6
rules it.

Two further style measurements from the same arms: `style-src 'sha256-…'`
applies a `<style>` element (`rgb(1, 2, 3)` computed), and an inline `style=`
attribute is **blocked** (`rgb(0, 0, 0)`, event
`CSP style-src-attr -> inline`) — so "no `style=` attributes" is enforced by
the policy rather than by discipline.

And one arm run because §5 R10 was about to assert a mechanism instead of
measuring one. Under `default-src 'none'; script-src 'sha256-…' 'sha256-…'
'wasm-unsafe-eval'`, constructing a `blob:` Worker is refused — but **not** by
`default-src`. Chromium names the chain itself:

> Creating a worker from `'blob:null/529f387f-…'` violates the following Content
> Security Policy directive: `"script-src 'sha256-2x1B2izmaejDr0tADIEnxhUFyvE+qnvfySxEsPnvNis='
> 'sha256-ZDszr796IW3H93uHu+mAdCpRygTVqDZvCTz4U3f7Xcs=' 'wasm-unsafe-eval'"`.
> **Note that `'worker-src'` was not explicitly set, so `'script-src'` is used
> as a fallback.** The action has been blocked.

(violation event: `CSP worker-src -> blob`). The `new Worker(…)` call itself
does not throw — the constructor returns and the worker is killed — so a page
that grew one would fail silently rather than loudly, which is the second reason
§5 R10 forbids it outright rather than leaving it to be discovered.

### (n) The costs, measured rather than estimated

| quantity | single file | multi-file (5) |
| --- | --- | --- |
| served closure, raw | **2 470 000 B** (1 file) | 1 855 534 B (3 loaded files) |
| served closure, `gzip -9` | **846 607 B** | 590 127 B |
| base64 decode, Chromium | `atob` loop **13–22 ms** (`Uint8Array.fromBase64` 3 ms) | n/a |
| base64 decode, Firefox | `atob` loop **67–75 ms** (`fromBase64` 35 ms) | n/a |
| instantiate | 6–13 ms (Cr) · 84–101 ms (Fx) | 104 ms incl. two fetches (Cr) |
| `domContentLoaded`, warm | 102–148 ms (http) · 123–198 ms (`file://`) | 83–135 ms (http) |
| JS heap (`Runtime.getHeapUsage`) | 3.2 MB used / 4.1 MB total | 0.9 / 1.8 MB |
| `verify()` of a 7 981 B bundle | 30–46 ms | 23 ms |

**The honest cost is the wire: +256 480 B gzipped, +43 %.** Base64 costs 33 %
raw and rather more after compression, because it destroys byte alignment.
Everything else is noise: decode is ~15 ms on the fast engine and ~70 ms on the
slow one, the heap delta is ~2.3 MB, and page load is within tens of
milliseconds of the multi-file arm. (`performance.memory.usedJSHeapSize`
reports a quantized 14 MB / 1 MB and is **not** the figure to use;
`Runtime.getHeapUsage` is.)

### (o) The packaging step is deterministic, and the artifact decomposes mechanically

Three packs of the same inputs, plus a fourth over a **second** `wasm-pack` run
of the same commit:

```
81dc60e27e9b7f54aae31ff3e2d81a549c99a04ce56434eedf680a50fe0231cf  repro-1.html
81dc60e27e9b7f54aae31ff3e2d81a549c99a04ce56434eedf680a50fe0231cf  repro-2.html
81dc60e27e9b7f54aae31ff3e2d81a549c99a04ce56434eedf680a50fe0231cf  repro-3.html
81dc60e27e9b7f54aae31ff3e2d81a549c99a04ce56434eedf680a50fe0231cf  repro-4.html   # second wasm-pack run
```

and the two wasm-pack runs themselves produced byte-identical `.wasm` **and**
byte-identical glue. So the brief's worry — *base64 of a reproducible input is
reproducible only if the packaging step is* — is measured true and the step is
measured deterministic: base64, template substitution and SHA-256 are all
total, deterministic functions of their inputs. **This does not discharge
R25's Accept row 1** (§9).

And the decomposition:

```
glue appears VERBATIM as a contiguous substring : true
base64 token decodes to the module byte-for-byte: true
authored residue after removing both tokens     : 2853 chars   (2858 bytes on disk)
cost of extract + decode + sha256               : 29 ms
sha256(extracted) = 8c0d3a12…daba9 = the footer's number
```

A **2 858-byte** human-readable residue out of 2 470 000. §4 turns this into
the replacement for D63 §5 R5's *"one-token diff"* clause.

### (p) Inlining is textually safe today — and that must be a checked property, not an assumption

```
web glue        '</script': 0   '<script': 0   '<!--': 0   '-->': 0   '<!': 0
no-modules glue '</script': 0   '<script': 0   '<!--': 0
base64 alphabet outside [A-Za-z0-9+/=]: none
```

A base64 string cannot contain `<`, so the module half is safe by construction.
The glue half is safe **today**, as a property of generated code this project
does not control — so §5 R9 makes it an assertion of the packaging step rather
than a fact of this record.

---

## 2. The lean, dismantled — the conclusion survives, all three mechanisms die

The lean was: *single self-contained HTML, built with
`wasm-pack --target no-modules`*, on five arguments.

**2.1 *"`--target no-modules` … so there is no `import`, no `import.meta.url`
and no module-script CORS rule to trip"* — the premise is false.** §1 (c): the
`--target web` glue has **no `import` statement at all**, and its one
`import.meta.url` is in an unreached branch. §1 (g): the `web` glue inlined into
an inline `<script type="module">` runs from `file://` in Chromium and (§1 i) in
Firefox, verifying a real bundle byte-identically to native. There is no
"module-script CORS rule" to trip because there is no fetch: what §1 (f) measures
being blocked is the *retrieval of a sibling file*, and an inline script is not
retrieved. The lean reached for a different target to solve a problem the
inlining had already solved.

**2.2 *"`wasm_bindgen(bytes)` takes the module directly so nothing is
fetched"* — true, and true of `--target web` too.** Both glues export
`initSync({ module })`; §1 (g) and §1 (i) exercise it. This argument does not
distinguish the targets.

**2.3 *"D63 §5 R5's closed operation list already permits substituting
pre-declared tokens … so choosing this reopens nothing"* — half right, and the
half it misses is the one that bites.** R5's list does cover the operations
(§4.1). But R5's own purpose clause reads *"so template→artifact is a
**one-token diff** any reviewer can eyeball"*, and a 2.47 MB artifact is not a
one-token diff by any reading. The lean asserted the fence was clear; it is not,
and §4 rules the narrowing explicitly rather than gliding past it.

**2.4 *"a page the user downloads once and keeps is a stronger answer to spec
line 186 than one they must re-fetch"* — correct, and it is the lean's one
surviving argument.** §1 (f) makes it structural rather than rhetorical: a
multi-file page **cannot be kept**. Saved to disk and reopened it does not run,
in either engine. A verifier whose offline mode requires a web server is not
offline in the sense a counterparty holding a bundle and a saved file needs.

**2.5 *"R25's artifact set collapses to a closure of one"* — true, and §5 R7
rules what that does to the manifest, which is not what the lean assumed.**

**2.6 What the lean did not contain, and what refuses `no-modules`.** Two
measurements, neither of them about `file://`:

- §1 (d): `no-modules` ships `decodeText` **without** the Safari cumulative-decode
  guard, on the function every report, overlay and typed error crosses.
- The `--target web` glue is the one `scripts/wasm-pack-build.sh` builds
  (`--target web`, at its `build()`) and the one `scripts/wasm-boundary.mjs`
  drives for R22's Accept rows. Shipping `no-modules` would publish glue that
  **no committed check in this repository has ever executed** — or force a
  second build and a second gate, for a target that buys nothing §1 (g) did not
  already have.

§1 (e) is recorded because the brief predicted the opposite: `no-modules`
preserves the closed export list intact, 21/21 vectors byte-identical. It is
refused on what it drops and on what it is not tested by, not on what it cannot
do.

---

## 3. The weakness the wave owner saw, inverted

The brief's sharpest question: *an all-inline page forces its CSP either to
allow `'unsafe-inline'` — weakening the very thing D62 insisted be in-artifact —
or to carry per-script `'sha256-…'` hashes, a mechanism nobody has ruled.*

**The dilemma's first horn does not exist.** §1 (j): hashes work, for classic
and module inline scripts, in Chromium and Firefox, from `file://` and from
`https://`. Nothing forces `'unsafe-inline'`.

**The second horn is the ruling, and it is stronger than what the multi-file arm
could have had.** Compare the two policies honestly:

| | multi-file | single file |
| --- | --- | --- |
| `script-src` | `'self' 'wasm-unsafe-eval'` | `'sha256-…' 'sha256-…' 'wasm-unsafe-eval'` |
| what that permits | **any** script under the origin — and on GitHub Pages the origin is the whole site | **exactly two byte strings**, and nothing else |
| meaning under `file://` | `'self'` is an opaque origin; the page cannot load its siblings anyway (§1 f) | unchanged — hashes are origin-free |
| in-artifact integrity of the payload | SRI covers the 11 181 B glue; **D63 §4 way 5 measured SRI does not apply to instantiated wasm**, so 1 841 981 B — **99.40 %** — is uncovered | the hash covers glue **and** module, because the module is inside the hashed script |
| a one-byte payload corruption | the page runs and verifies with a corrupted module | **the page refuses to run** (§1 k) |

That last row is the substantive gain, and it must be stated with its limit.
**Against a malicious host it is worth nothing** — the host edits the `<meta>`
in the same breath as the script, exactly as D63 §2.1 says of the footer, and
this record adds no defence there and claims none. What it does is convert
**D63 §2.2's third job** — *"catches accident, which is the likely failure:
stale CDN object, half finished deploy, a `.wasm` from one build beside JS from
another"* — from a number displayed for a reader who probably will not compare
it into a **structural fail-closed enforced by the browser**. The half-finished
deploy and the mismatched-pair accidents cannot even occur in a one-file
closure; the truncated-or-rewritten-transfer accident is caught by the hash and
the page dies loudly instead of verifying with corrupted bytes.

So the arm that survives the CSP is the **single file**, and the CSP is the
strongest argument for it rather than the objection to it.

---

## 4. D63 §5 R5, read precisely — one rider and one recorded narrowing

### 4.1 Where the packaging step sits in the closed operation list

D63 §5 R5's permitted operations: *"(i) invoke `wasm-pack` at the pinned
versions with `--locked`; (ii) copy files; (iii) compute digests; (iv)
substitute pre-declared tokens in committed templates; (v) emit `SHA256SUMS`
and delete non-served byproducts."* Prohibited: *"minifying, bundling,
transpiling, templating languages, generating page code, and any network access
during the build."*

The packaging step ruled here performs exactly: read two build inputs
(**ii**), compute the module's SHA-256 and the inline scripts' SHA-256 hashes
(**iii**), base64-encode the module, substitute four pre-declared tokens
(**iv**), emit `SHA256SUMS` and delete byproducts (**v**).

**Base64 is not literally on the list, and this record adds it by rider rather
than by reading.** It belongs beside (iii) rather than as a new class: it is a
deterministic textual encoding of a build input, in the same family as a digest,
and it is *strictly more reviewable* than one because it is exactly invertible
(§1 o: 29 ms to recover the module byte-for-byte). The fence's purpose is
untouched — base64 resolves no module graph, rewrites no identifier, generates
no code, and reaches no network. §11.4 supplies the rider.

**None of the prohibitions is engaged, and the distinction is testable rather
than rhetorical.** A bundler resolves a graph, rewrites import specifiers, and
emits code the author did not write. This step copies the glue **verbatim** —
measured, §1 (o): the built page contains the glue file's bytes as a contiguous
substring — which is exactly the line between concatenation and bundling, and
§5 R9 makes it an assertion.

### 4.2 The *"one-token diff"* clause — narrowed, and replaced by something stronger

R5's closing sentence is the one clause a single-file page cannot honour in
letter: *"The committed template must be a valid, loadable page on its own, with
the placeholder visible, so template→artifact is a one-token diff any reviewer
can eyeball."*

The clause's **purpose** is that a reviewer can confirm the artifact is the
template plus declared substitutions, without trusting the build script. §1 (o)
shows that purpose is preserved and sharpened:

- The **authored text** — the wording, the footer, the CSP, the DOM — remains a
  one-token-per-substitution diff. It is **2 858 bytes**, and that is the part a
  human was ever going to read.
- The **two large tokens** are reviewed **mechanically instead of visually**, by
  a check that is strictly stronger than eyeballing: base64-decode the token and
  require byte-equality with the `wasm-pack` output; require the glue file's
  bytes to appear verbatim. Nobody was ever going to eyeball 1.8 MB of
  WebAssembly; a byte-equality assertion is not a weaker review of it, it is the
  only real one.
- The committed template stays **loadable**: it renders its chrome and shows its
  placeholders. It does not verify — `<script>__ANTSEAL_GLUE__</script>` is a
  `ReferenceError` — and "loadable" is what R5 asked for, not "functional".

So the clause is honoured in substance and **narrowed in letter, on the record**
(§11.4), rather than quietly stretched.

---

## 5. The ruling

Ten rules. "Module" = the `.wasm` `wasm-pack` emits. "Page" = the published
`index.html`. "Packaging step" = the operations §4.1 enumerates.

**R1 — The published page is ONE FILE: `index.html`.** The served closure is
that file and nothing else. Nothing the page loads is fetched at load time: no
`<script src>`, no `<link href>`, no `@import`, no `fetch`, no `XMLHttpRequest`
of any resource the page needs to function. Any icon is a `data:` URI. Any CSS
is one inline `<style>` element. Refused shapes and their reasons are in §6.

**R2 — The module is inlined as base64 in one inline `<script>`; the glue is
inlined VERBATIM into one inline `<script type="module">`; the page calls
`initSync({ module })` and never the default init.** The default init
(`__wbg_init` / the module's default export) exists in the glue and its
`module_or_path === undefined` branch derives a URL and fetches it (§1 c, §1 e).
It must be unreachable in the shipped page, and §5 R9's checks assert it. There
is no fallback path that fetches the module — not for `file://`, not for
`https://`, not as an optimisation.

**R3 — The target is `wasm-pack --target web`, not `--target no-modules`.**
Both work under `file://` when inlined (§1 g), both preserve the closed export
list (§1 e), and both produce the **byte-identical** module (§1 b), so D63 §5 R2
is unaffected by this choice. `web` wins on two measurements: it is the glue the
R22 gate builds and drives (`scripts/wasm-pack-build.sh`,
`scripts/wasm-boundary.mjs`), so the published bytes are the tested bytes; and
`no-modules` **drops the Safari `TextDecoder` guard** on the function every
report string crosses (§1 d), for the one engine this project cannot test. The
build flags stay exactly R22's: `--release --no-pack --no-opt --mode no-install`.

**R4 — Base64 decoding uses the portable `atob` path, once, with no feature
detection.** `Uint8Array.fromBase64` exists in both engines measured and is
~5× faster, and the portable path costs **13–22 ms** (Chromium) / **67–75 ms**
(Firefox) for 2.46 MB (§1 n) — which is not a budget worth a second code path.
One path means one script text, one hash, one behaviour across engines, and one
thing for R27 to assert. The decoded array and the base64 string may be released
after `initSync`; it is worth ~2.3 MB of heap (§1 n) and is not required.

**R5 — R23's Accept row is KEPT VERBATIM.** *"Works fully offline: `file://` or
a no-network browser context completes verification incl. anchor checks"*
stands unedited, because it is **measured true** of the ruled shape: §1 (g) —
a real `.sealproof` verified at a `file://` origin, report byte-identical to
native, anchors evaluated, **one network request, which was the page itself** —
in Chromium, and §1 (i) in Firefox. The row required no narrowing and gets
none. R23's *"No external resources fetched in offline mode"* Accept becomes
structurally true rather than merely tested, because after R1 there is nothing
external to fetch.

**R6 — The Content-Security-Policy, literally.** It lives in
`<meta http-equiv="Content-Security-Policy">` inside `index.html` (D62 §3 R6,
the registrar's R23 ruling), and it is:

```
default-src 'none';
script-src 'sha256-<H1>' 'sha256-<H2>' 'wasm-unsafe-eval';
style-src 'sha256-<H3>';
img-src data:;
connect-src https:;
base-uri 'none';
form-action 'none'
```

where `<H1>` and `<H2>` are the SHA-256 hashes, base64-encoded, of the **exact
text content** of the two inline `<script>` elements — the base64 data script
and the module script — and `<H3>` of the one inline `<style>`. Each directive,
with the measurement that put it there:

- **`default-src 'none'`** — the floor. Everything else is an exception, and
  each exception below is one the page provably needs. It also closes workers,
  though by a route worth recording because it is not the obvious one; see the
  rider in §5 R10 and its measurement.
- **`script-src 'sha256-…' 'sha256-…'`** — §1 (j): hashes admit inline classic
  and inline module scripts in both engines. This is what makes the page's
  entire payload hash-covered (§3) and it is what an injected `<script>` from a
  DOM-XSS bug in the rendering of **sealer-authored** bundle text — spec line
  187's named threat, *"adversary-authored CBOR/DER/`.ots` parsed in the
  counterparty's browser"* — would fail to match. `'unsafe-inline'` is **not**
  present: §1 (j) measured it is ignored when a hash is present anyway, so it
  would buy compatibility only with engines that predate CSP2 and therefore
  predate WebAssembly.
- **`'wasm-unsafe-eval'`** — required: without it `WebAssembly.Module()` is
  refused with the `CompileError` quoted in §1 (j), in both engines (§1 l).
  **`'unsafe-eval'` also works and is refused**: it additionally re-enables
  `eval`/`Function`, which this page never needs.
- **`style-src 'sha256-…'`** — §1 (m): a `<style>` element hash applies, and
  inline `style=` attributes are blocked by the same policy (`style-src-attr`),
  so "no style attributes" is enforced rather than remembered.
- **`img-src data:`** — the only image the page may carry is a `data:` icon
  (R1). If it carries none, this becomes `img-src 'none'`.
- **`connect-src https:` — scheme-only, NOT the six pinned hosts.** §1 (m)
  measured that a host allowlist blocks a user-supplied override with a
  `connect-src` violation the page **cannot report**, because D66 §3 R4 forbids
  naming a cause and §1 (m) shows the JS-visible error is the same
  `TypeError: Failed to fetch` either way. Spec line 137 mandates
  *"user-overridable"* endpoints; a host allowlist forbids them undiagnosably.
  `https:` is exactly congruent with the predicate the code already enforces —
  D66 §3 R5.1's `https://`-only override rule, itself the page-side form of
  A49/`docs/config.md:94` — so the policy and the validator state the same
  thing. D66 §7's guard test
  (`page_csp_permits_connect_to_the_pinned_origins`) is satisfied by
  construction and should additionally assert that a **non-pinned `https:`
  origin is permitted**, which is the half that would have caught the host
  allowlist.
- **`base-uri 'none'`, `form-action 'none'`** — the page has no `<base>` and no
  form; both close a rewrite that `script-src` does not.

**Not deliverable by `<meta>`, and therefore residual, unchanged from D62 §3 R6:**
`frame-ancestors`, `sandbox`, `report-uri`/`report-to`. Clickjacking of the
verifier page stays open on the ruled host.

**R7 — `SHA256SUMS` covers the served closure, which is now one line; the
pre-packaging module is a RELEASE artifact, not a served one.** D63 §5 R4 is
applied, not amended:

- **In the served set**: `index.html`, post-packaging, post-injection. That is
  the whole closure (R1), so the manifest has one entry.
- **Out**: `SHA256SUMS` itself; every `wasm-pack` byproduct (`antseal_wasm.d.ts`,
  `antseal_wasm_bg.wasm.d.ts`, `.gitignore`, and now `antseal_wasm.js` and
  `antseal_wasm_bg.wasm`, which have become build *inputs* rather than served
  artifacts) — deleted before the sums are computed, so D63 R4's *"the sums list
  **is** the deploy list"* invariant is preserved exactly; and host furniture.
- **The wave owner's question — list the raw `.wasm` in `SHA256SUMS` as a
  separately-named convenience artifact — is answered in two parts.** It is
  **not** D63 §4 way 2's refused "two numbers": that refusal is of *two digests
  of the same object shown to one reader in one footer*, and these are digests
  of **two different objects**, one of which the footer names and the other of
  which it does not. So *two names for two things* is the right description.
  **But it may not go in the served `SHA256SUMS`**, on a different and
  measurable ground: R26's Accept requires **set equality both ways** (D62 §3
  R3 rule 4), so a line in the manifest obliges the host to serve that file —
  which would put a 1.84 MB artifact at the origin that the page never loads,
  break D63 R4's deploy-list invariant, and invite a reader to believe the page
  fetches it. **It belongs to the signed release** (Q30/Q31), where D63 §5 R4
  already locates authority, published as `antseal_wasm_bg.wasm` beside the
  page. Its digest **is** the footer's value, by construction, and the reader
  then has two independent routes to the same number: extract-decode-hash from
  the page (§1 o, 29 ms) or `sha256sum` the release artifact.

**R8 — What the footer names is unchanged, and the packaging order is fixed.**
D63 §5 R2's digest is `SHA-256(the module as `wasm-pack` produced it, before
packaging)` — invariant under this ruling and, per §1 (b), even under the target
choice. Two orderings are ruled so the injector cannot be written wrong:

1. The **footer digest is substituted into HTML text, never into script text**.
   It renders as the text content of an element; the page's JS reads the module's
   own identity fields from R22's `build_info()` export (D63 §5 R3) and never the
   digest. This makes the digest substitution and the script-hash computation
   **independent**, with no ordering hazard at all.
2. The packaging order is nonetheless fixed and asserted: substitute glue →
   substitute base64 → substitute footer digest → **compute the script and style
   hashes over the final text** → substitute the CSP hashes → emit `SHA256SUMS`.
   There is no fixed point: the `<meta>` lives in `<head>`, outside every
   `<script>` and `<style>` element, so no hashed text ever contains a hash of
   itself. Measured (§1 j, §1 l): the resulting page runs with zero violations.
   D63 §5 R1's *"substitution is not idempotent by design — running the injector
   over an already-injected file is a hard error"* extends to **all four**
   tokens.

**R9 — The packaging step's assertions.** Each is offline, deterministic, and
runs against the **built artifact**, in the discipline D18 §5 R7 and R23's CSP
Accept row already use:

1. **Verbatim glue**: the built page contains the `wasm-pack` glue file's bytes
   as a contiguous substring. This is the line between concatenation and
   bundling, and it is what makes R23's *"no framework or bundler in the repo"*
   Accept checkable rather than asserted.
2. **Round-trip module**: the base64 token decodes to bytes byte-equal to the
   `wasm-pack` module, and its SHA-256 equals the injected footer digest.
3. **Decomposition**: page minus the two tokens equals the committed template
   with its placeholders restored, modulo the two small substitutions. The
   residue is the reviewable object (§1 o: 2 858 B).
4. **Textual safety**: the glue contains no `</script`, `<script`, `<!--`,
   `-->`, or `<!`, and the base64 uses only `[A-Za-z0-9+/=]`. True today
   (§1 p) of code this project does not author, so it is asserted, not assumed.
5. **No residual placeholder** and **no re-injection** (D63 §5 R1), over all four
   tokens.
6. **No fetch path to the module**: the built page contains no reachable call to
   the glue's default init and no `fetch`/`XMLHttpRequest`/`import()` of any page
   resource. (`fetch` of an *endpoint* is R24's and is unaffected.)
7. **CSP present and correct**: the `<meta>` exists, `script-src` carries exactly
   the hashes of the scripts actually present plus `'wasm-unsafe-eval'`, and
   `'unsafe-inline'`/`'unsafe-eval'` appear nowhere.
8. **The page loads and verifies**, headless, from a `file://` URL, with **zero**
   network requests and a report byte-identical to native for at least one R9
   vector. This is R27/Q19's venue and it is the assertion that would have caught
   every failure mode in §1.

**R10 — What this ruling does not permit.**

- **No hybrid** (§6, and the argument in full): multi-file hosted plus
  single-file download is refused.
- **No inline compression** of the module (§6).
- **No Web Worker in v1** — and the mechanism is measured, not inferred. A
  `blob:` worker is refused, and Chromium names the fallback chain itself:

  > Creating a worker from `'blob:null/…'` violates the following Content
  > Security Policy directive: `"script-src 'sha256-…' 'sha256-…'
  > 'wasm-unsafe-eval'"`. **Note that `'worker-src'` was not explicitly set, so
  > `'script-src'` is used as a fallback.** The action has been blocked.

  So it is the **hash-locked `script-src`** that closes workers, not
  `default-src` — which is the sharper form of the point: a `blob:` worker's
  script text is generated at runtime and can never match a build-time hash, so
  under §5 R6 there is no worker shape that is admissible at all. R23's R54
  progress/busy affordance therefore stays on the main thread. Recorded because
  R23's `Notes` already anticipate multi-second wasm verifies on slow devices
  and a Worker is the obvious reach; taking it would require reopening §5 R6.
- **No nonce.** A nonce in a static file is a constant, publicly readable and
  identical on every load — i.e. `'unsafe-inline'` that an attacker can spell.
- **No second policy at the host.** Unchanged from D62/R26: there is no host
  configuration surface, and a second policy would intersect with this one
  silently.

---

## 6. Refused shapes

| shape | refused on |
| --- | --- |
| multi-file page (`index.html` + glue + `.wasm` + …) | fails R23's `file://` Accept in **two engines**, each with its own message — Chromium: *"blocked by CORS policy: Cross origin requests are only supported for protocol schemes: chrome, chrome-extension, chrome-untrusted, data, http, https, isolated-app"*; Firefox: *"error loading dynamically imported module"* (§1 f). A verifier that cannot be saved and reopened is not offline in the sense a counterparty needs |
| narrowing R23's Accept to http-served offline contexts | unnecessary — the row is **measured satisfied verbatim** by the ruled shape (§1 g, §1 i). A narrowing would trade a spec-privileged mode (line 127 *"Offline-first: full local verification"*) for a file layout |
| `wasm-pack --target no-modules` | drops the Safari `TextDecoder` guard on the path every report string crosses (§1 d); ships glue no committed check has ever run (`scripts/wasm-pack-build.sh` builds `--target web`); and buys nothing — the `web` glue has no static import and inlines identically (§1 c, §1 g) |
| `script-src 'unsafe-inline'` | unnecessary — hashes work for inline classic and module scripts in both engines (§1 j, §1 l) — and it would forfeit the one real gain of the shape: an injected script from a DOM-XSS bug in rendering sealer-authored text would run (spec line 187) |
| `script-src 'unsafe-eval'` for wasm | `'wasm-unsafe-eval'` is sufficient and measured (§1 j); `'unsafe-eval'` additionally re-enables `eval`/`Function`, which this page never uses |
| `'unsafe-inline'` alongside the hashes as a "fallback" | measured ignored — Chromium: *"Note that 'unsafe-inline' is ignored if either a hash or nonce value is present in the source list"* (§1 j) — and every engine old enough to need it lacks WebAssembly |
| a CSP nonce | a static file's nonce is a constant, published with the page, identical on every load |
| `connect-src` naming the six pinned hosts | blocks the user override spec line 137 mandates, and blocks it **undiagnosably** — the page sees the identical `TypeError` and D66 §3 R4 forbids it from naming a cause (§1 m) |
| listing the raw `.wasm` in the **served** `SHA256SUMS` | not the "two numbers" refusal (they are two objects), but it obliges the host to serve a 1.84 MB artifact the page never loads, breaking D63 §5 R4's *"the sums list is the deploy list"* and R26's set-equality-both-ways (§5 R7). Its home is the **signed release** |
| **hybrid**: multi-file hosted + single-file download | two byte sequences both claiming to be the antseal verifier, at one canonical URL (R26/D62 §3 R1), needing two signing entries, two CSPs (`'self'` vs hashes) and two R27 parity runs — and, because D63 §5 R2 names the *pre-packaging* module, **both would display the same footer digest**, so a reader comparing footers could not tell which artifact they hold. That is D63 §4 way 2's refusal in mirror image: one number, two artifacts. It is also unnecessary — the served single file **is** the downloadable one, so the hybrid's only benefit is already bought by R1 |
| inline-compressing the module (base64 of gzip + `DecompressionStream`) | it would erase the wire cost exactly — transfer 591 156 B against the ruled 837 471 B, i.e. parity with multi-file — but `gzipSync(level 9) ≠ gzipSync(level 6)` on the same input, so a **compressor version and level become inputs to the published artifact's identity**: precisely the class D63 §7 rule 1 fences off for `wasm-opt`, and R25's `Notes` already carry the binaryen lesson. The host's own `Content-Encoding` delivers the same saving without entering the artifact |
| a Web Worker for the verify call | measured blocked, and by the hash-locked `script-src` rather than by `default-src` — Chromium: *"Note that `'worker-src'` was not explicitly set, so `'script-src'` is used as a fallback. The action has been blocked."* A `blob:` worker's script is generated at runtime and can never match a build-time hash (§5 R10) |
| `Uint8Array.fromBase64` with an `atob` fallback | two code paths means two behaviours and one of them is untested in whichever engine takes the other; the portable path costs 13–75 ms (§1 n) |
| the page computing or comparing its own digest | already forbidden outright by D63 §5 R1; nothing here reopens it, and §5 R8's ordering exists partly so no code path needs to |

---

## 7. What R23 and R25 must implement

**R23** — authors `verifier-web/index.html.template` (name is R23's) as a
loadable page carrying four visible placeholders: the glue token, the base64
token, the footer-digest token, and the CSP-hash token. It authors the CSP of
§5 R6 verbatim, one inline `<style>`, no `style=` attributes, a `data:` icon or
none, drag-and-drop plus the file-picker (both measured working from `file://`,
§1 h), and the `initSync({ module })` call — never the default init (§5 R2).
All bundle-derived text reaches the DOM by `textContent`, extending D66 §3
R5.3's rule from endpoint strings to every sealer-authored string the page
renders; the CSP is the second line, not the first.

**R25** — implements the packaging step of §4.1 with the ordering of §5 R8 and
the eight assertions of §5 R9, emits a one-line `SHA256SUMS` (§5 R7), hands the
pre-packaging `antseal_wasm_bg.wasm` to Q31 as a named release artifact, and
keeps every precondition D63 §7 rule 1 still names — the remaining one being the
**optimizer**, which R25's own `Notes` record as actively exercised (`wasm-pack
build --release` fetching an unpinned binaryen 117). Nothing in this record
relaxes that: §1 (o)'s determinism is the *packaging* step's, and R25's Accept
row 1 remains unmet until the module's own preconditions are.

**R26** — its set-equality check now runs over a closure of one, and its
`Content-Type` assertion is `text/html` for that one file. Two riders: the
`Accept-Encoding` tripwire (D62 §3 R3 rule 3) matters *more* here, since one
2.47 MB text file is exactly what a transform-happy intermediary would rewrite;
and a browser's automatic `GET /favicon.ico` is **not** an artifact in the
closure — it 404s (§10 (ii)) and the set-equality check must not read a 404 as a
served extra.

**R27/Q19** — §5 R9's assertion 8 is this row's: load the built artifact from a
`file://` URL, assert zero network requests, drop an R9 vector, and compare the
rendered strings to the CLI's. The measurement in §1 (g) is that test, written
by hand; R27 owns making it permanent, and Q19's page-under-test is now one
file.

---

## 8. Spec conformance

- **Line 127 — *"Plain HTML/JS + `antseal-core` WASM … Offline-first: full local
  verification"*** — realized in the strongest available form: the offline mode
  now needs no server at all, in two engines.
- **Line 137 — *"No framework, no build beyond `wasm-pack`"*** — held by
  §4.1's fence and §5 R9's verbatim-glue assertion, which makes R23's own
  *"no framework or bundler in the repo"* Accept mechanically checkable.
  Line 137's *"user-overridable"* clause is what §5 R6's `connect-src https:`
  protects, against a policy that would have looked tighter and silently broken
  it (§1 m).
- **Line 139 — page provenance** — untouched. The footer's digest is still
  D63 §5 R2's, still of the module, still 64 ungrouped lowercase hex; the
  published SHA-256 is still a manifest over the served closure, which is now
  one line; the canonical URL is still D62's.
- **Line 186 — malicious verifier host** — the residual is **unchanged**, and
  this record refuses to claim otherwise. The hashed CSP is computed by the same
  party that serves the page (§3). What it moves is the **accident** class,
  which is D63 §2.2's third job and the likely failure.
- **Line 187 — hostile bundles** — the one place the ruling does buy security:
  `script-src` hashes give the page a second line against a DOM-XSS bug in its
  rendering of adversary-authored text, which a multi-file `'self'` policy would
  not (§3).
- **Line 123 — format stability** — untouched. **Zero frozen bytes**: no
  registry key, error code, HKDF label, domain tag, golden vector, or wording
  snapshot moves. `MVP-SPEC.md` is not edited; note that the spec never names a
  file count (line 56 says only *"static page: plain HTML/JS + antseal-core
  compiled via wasm-bindgen"*), so "a single static page" in R23's `Do` is
  satisfied by one file more literally than by five.

---

## 9. Residual risk

- **+43 % on the wire, permanently.** 846 607 B gzipped against 590 127 B
  (§1 n). Paid on every cold load, and Pages' fixed `max-age=600` (D62 §1 d)
  means "cold" is common. Accepted: it buys the only shape in which R23's
  offline Accept is true, and the alternative that would erase it (§6, inline
  compression) puts a compressor into the artifact's identity.
- **The CSP is no defence against the host.** Stated in §3, restated here so no
  reader of the ruling alone infers otherwise. The host edits the `<meta>`.
- **Clickjacking stays open** — `frame-ancestors` cannot be delivered by
  `<meta>` (D62 §3 R6), and one file does not change that.
- **A hand-edit of the published page kills it silently-ish.** Any post-build
  edit to script text invalidates the hash and the page stops running. That is
  the intended fail-closed direction, but it means the artifact is not
  hand-patchable in an incident; the fix is always a rebuild. §5 R9's assertion 8
  is what stops a dead artifact reaching the canonical URL.
- **Browser "Save page as" may not preserve bytes.** Chromium's *Webpage,
  Complete* rewrites HTML; a reader hashing that copy gets a mismatch. The
  byte-preserving routes are `curl`, and right-click → *Save link as*. This is a
  docs obligation for R25's §7 rule 6 wording, not a fixable property.
- **R25's Accept row 1 is still unmet.** §1 (o) proves the *packaging* step adds
  no non-determinism; the module's own preconditions — path remapping and the
  optimizer — stand exactly as D63 §7 rule 1 and R25's `Notes` leave them.
- **The `file://` measurements are two engines, not all.** Safari and WebKit are
  untested here, which is exactly why §5 R3 refuses the target that drops the
  Safari workaround.

---

## 10. Discovered work — described, not registered

No ids are minted here.

**(i) D66 §1 (d)'s Firefox note is an artefact of its observation method, not of
Firefox.** That record states the harness *"was attempted under Firefox
140.13.0esr headless and did not run — its GFX initialisation failed in this
environment (`RenderCompositorSWGL failed mapping default framebuffer`) and no
beacon was returned."* This lane drove the same Firefox, in the same
environment, successfully (§1 i, §1 l): the GFX line is still printed and the JS
engine is unaffected. What made the difference was a profile with
`gfx.webrender.software=true` (plus `LIBGL_ALWAYS_SOFTWARE=1`) and enough wall
time before termination. **Instrument material** — it changes what a record says
about a tool, not what any product code does — and it matters ahead of R27,
whose parity gate would otherwise inherit a belief that this project has one
testable engine when it has two. D66's *ruling* is untouched: its
indistinguishability finding was established **within** one browser and does not
depend on the second.

**(ii) A browser's automatic `GET /favicon.ico` is outside the SHA256SUMS
closure.** Observed on the multi-file arm over http: `GET /favicon.ico → 404
(File not found)`. R26's Accept asserts *"no artifact is served under the page's
own paths that is absent from SHA256SUMS"*; a 404 is not a served artifact, so
nothing is violated — but a check written naively over *requests* rather than
over *served responses* would go red on it. Recorded so R26's scripted check is
written the right way round the first time. R23 declaring a `data:` icon removes
the request entirely.

**(iii) The R9 corpus exercises exactly one anchor-state class.** Across all 21
committed cases the report anchors are `{"ots/invalid": 1, "tsa/invalid": 2}`.
So R23's *"completes verification incl. anchor checks"* is demonstrable today
only against anchors that evaluate to `invalid` — the anchor path runs and
produces verdicts, which is what the row asks, but `pending`/`attested`/
`proven`/`valid-at-stamping-cert-since-expired` reach the page for the first
time with **R27**'s A25 fixtures (its own `Deps` already name them). Recorded so
nobody reads §1 (g) as broader coverage than it is, and so R27 knows it owns the
first exercise of the richer states through the page.

**(iv) `verifier-web/index.html` is still the 484-byte, 16-line placeholder**
and is still `verdict_wording.rs:710`'s ban scan root. D63 §10 (iv)'s question —
what CI does with the directory, and where the injector, drift and packaging
tests live — is untouched by this record and lands on R23/R25 with one addition:
the **committed template** now joins it in that directory, and the template is
what the R18 ban scan will actually be scanning from R23 onward.

---

## 11. Quoted entry notes (registrar's to apply)

### 11.1 `tasks/R.md` R23 — append a `Notes` line

> - Notes: **[D129, 2026-08-12]** File shape ruled
>   (docs/decisions/D129-verifier-page-file-shape-and-the-in-artifact-csp.md):
>   the page is **ONE FILE**, `index.html`, with the `wasm-pack --target web`
>   glue inlined **verbatim** into one inline `<script type="module">` and the
>   module inlined as base64 in one inline `<script>`; the page calls
>   `initSync({ module })` and **never** the glue's default init, so no fetch
>   path to the module exists. **`--target no-modules` is refused**: it drops
>   the Safari `TextDecoder` guard the `web` glue emits on the function every
>   report string crosses, and it is glue no committed check runs — and it is
>   unnecessary, because the `web` glue has **no static `import` at all**, so
>   inlining it needs no different target. **This row's offline Accept is kept
>   verbatim**: measured, a real `.sealproof` verified at a `file://` origin in
>   **Chromium 150 and Firefox 140.13.0esr**, report **byte-identical to
>   native**, anchors evaluated, drag-and-drop and file-picker both working, and
>   **one network request — the page itself**. The multi-file arm fails in both
>   engines with their own words (Chromium: *"blocked by CORS policy: Cross
>   origin requests are only supported for protocol schemes: chrome, …, data,
>   http, https, isolated-app"*; Firefox: *"error loading dynamically imported
>   module"*). **The CSP this row owns is, literally**: `default-src 'none';
>   script-src 'sha256-<script1>' 'sha256-<script2>' 'wasm-unsafe-eval';
>   style-src 'sha256-<style>'; img-src data:; connect-src https:; base-uri
>   'none'; form-action 'none'`. Measured: CSP **is** enforced from `file://`;
>   `'wasm-unsafe-eval'` is required and sufficient (without it
>   `WebAssembly.Module()` throws a `CompileError` naming the directive);
>   hashes admit inline **module** scripts in both engines; `'unsafe-inline'` is
>   ignored when a hash is present, so it is omitted. **`connect-src` is
>   scheme-only, NOT the six pinned hosts** — a host allowlist blocks the
>   user override spec line 137 mandates, and blocks it undiagnosably, since the
>   page sees the same `TypeError` and D66 §3 R4 forbids naming a cause.
>   Because the module is inside the hashed script, the hash covers **99.4 % of
>   the payload SRI structurally cannot** (D63 §4 way 5) and a one-byte payload
>   edit makes the browser refuse to run the page — an **accident** detector
>   (D63 §2.2 job 3), never a defence against the host (D63 §2.1 stands). No Web
>   Worker in v1: `default-src 'none'` blocks it and a `blob:` worker cannot be
>   hash-pinned, so R54's busy affordance stays on the main thread. All
>   bundle-derived text reaches the DOM by `textContent`, extending D66 §3 R5.3
>   from endpoint strings to every sealer-authored string (spec line 187).

### 11.2 `tasks/R.md` R25 — append a `Notes` line

> - Notes: **[D129, 2026-08-12]** The artifact set is **one file**
>   (docs/decisions/D129-…): `SHA256SUMS` has a single entry, `index.html`
>   post-packaging, and `antseal_wasm.js`/`antseal_wasm_bg.wasm` become build
>   **inputs**, deleted with the other byproducts before the sums are computed —
>   so D63 §5 R4's *"the sums list is the deploy list"* invariant is preserved
>   exactly. The **pre-packaging `antseal_wasm_bg.wasm` is published as a named
>   artifact of the SIGNED RELEASE** (Q30/Q31), never as a line in the served
>   manifest: that is *two names for two things*, not D63 §4 way 2's refused
>   *two numbers* — but a served line would oblige the host to serve a 1.84 MB
>   file the page never loads and would break R26's set-equality-both-ways. Its
>   digest **is** the footer's value, so the reader has two routes to one number
>   (`sha256sum` the release artifact, or extract-decode-hash from the page — 29
>   ms, measured). **Packaging order is fixed**: glue → base64 → footer digest
>   (into **HTML text**, never into script text, so the two substitutions stay
>   independent) → compute script/style hashes over the final text → CSP hashes
>   → `SHA256SUMS`. No fixed point exists: the `<meta>` is outside every hashed
>   element. D63 §5 R1's non-idempotence rule extends to all four tokens.
>   **Eight assertions ride the built artifact** (D129 §5 R9): glue present
>   verbatim as a contiguous substring (this is the testable line between
>   concatenation and *bundling*, and it is what makes this row's sibling Accept
>   *"no framework or bundler in the repo"* checkable); base64 round-trips to
>   the module byte-for-byte and its SHA-256 equals the injected digest;
>   decomposition to the committed template (authored residue measured at
>   **2 858 B** of a 2 470 000 B artifact); no `</script`/`<script`/`<!--` in the
>   glue and a clean base64 alphabet (true today of code we do not author, so
>   asserted); no residual or double-injected token; no reachable default-init or
>   `fetch` of the module; the CSP present with exactly the right hashes and
>   neither `'unsafe-inline'` nor `'unsafe-eval'`; and a headless `file://` load
>   that verifies an R9 vector with **zero** network requests. **The packaging
>   step is measured deterministic** — four packs, including one over a second
>   `wasm-pack` run of the same commit, all `81dc60e2…` — but this does **not**
>   discharge Accept row 1: the module's own preconditions (path remapping, and
>   the unpinned binaryen this row's own `Notes` record) are untouched. Cost
>   recorded rather than hidden: **846 607 B gzipped against 590 127 B**, +43 %.

### 11.3 `tasks/R.md` R26 — append a `Notes` line

> - Notes: **[D129, 2026-08-12]** The served closure is **one file**
>   (docs/decisions/D129-…), so this row's set-equality check runs over a
>   single `index.html` with `Content-Type: text/html`. Two riders. The
>   two-encoding tripwire (D62 §3 R3 rule 3) matters **more** under this ruling,
>   not less: one 2.47 MB text file is exactly what a transform-happy
>   intermediary rewrites, and the whole payload is inside it. And a browser's
>   automatic `GET /favicon.ico` is **not** a served artifact — it 404s
>   (measured) — so the check must be written over served *responses*, never
>   over requests, or it reddens on a 404 that violates nothing. The page's CSP
>   is R23's `<meta>`; **this row still adds none at the host**, and there is
>   still no host surface to add one at.

### 11.4 `docs/decisions/D63-footer-build-hash-and-artifact-set.md` §5 R5 — one rider, at the site

> **[D129, 2026-08-12 — rider, no ruling of D63 is changed.]** Two clarifications
> that D129 needed and this list did not settle.
> **(1) Scope of operation (iii).** *"compute digests"* is read as *"compute
> digests and deterministic textual encodings of build inputs"*, with
> **base64** named. Base64 sits beside a digest rather than forming a new class:
> it is total, deterministic, and — unlike a digest — exactly invertible, so it
> is strictly more reviewable. The fence is untouched: it resolves no module
> graph, rewrites no identifier, generates no code, and reaches no network.
> **(2) The *"one-token diff"* clause is NARROWED.** R23's ruled single-file
> shape (**D129 §5 R1**) makes the template→artifact diff 2.47 MB, so the clause
> cannot be honoured in letter. Its **purpose** — a reviewer can confirm the
> artifact is the template plus declared substitutions, without trusting the
> build script — is preserved and strengthened: the **authored** text remains a
> one-token-per-substitution diff and measures **2 858 bytes**, while the two
> large tokens are reviewed **mechanically** (base64 round-trips to the
> `wasm-pack` module byte-for-byte; the glue appears verbatim as a contiguous
> substring — D129 §5 R9), which is a stronger review of 1.8 MB of WebAssembly
> than eyeballing it was ever going to be. **§5 R1–R6 are otherwise unchanged**,
> and §5 R2's digest is unaffected — measured, it is invariant even under the
> `--target web`/`no-modules` choice (D129 §1 b).

---

## Registrar's edit set

**This lane wrote one file: this one.** Everything below is instruction.

1. `TODO.md` decision register, the **D129** line → the resolved form supplied
   in the lane's closing report.
2. `docs/decisions/README.md` → one index row for this record, in ascending id
   order, status/date taken from this record's own `- **Status`/`- **Date`
   lines (D119 RULING 1/3; the row rides this record's commit per D119
   RULING 6).
3. `tasks/R.md` → R23 gains the `Notes` line in §11.1, R25 §11.2, R26 §11.3.
   **R23's `Do` also gains one clause**: after *"a single static page (plain
   HTML/JS/CSS, no framework, no build step beyond `wasm-pack`)"*, add
   *"— published as **one file**, `index.html`, with the glue and the base64
   module inlined (D129 §5 R1–R2)"*. **R23's Accept rows are unchanged** — the
   offline row is kept verbatim by ruling.
4. `docs/decisions/D63-footer-build-hash-and-artifact-set.md` → the rider in
   §11.4, placed at §5 R5, in the same at-the-site style D63 already carries for
   its §7 rule 1 discharge (D117 §2.1 (a): the original wording survives
   verbatim).
5. `docs/instrument-ledger.md` → §10 (i) (D66's Firefox note is an artefact of
   its observation method — Firefox 140.13.0esr runs headless here with
   `gfx.webrender.software=true` and a POST beacon) and, at the registrar's
   discretion, §10 (ii) (the favicon 404) and §10 (iii) (the R9 corpus exercises
   only `invalid` anchor states, so R27 owns the first page-side exercise of the
   richer states).
6. **No edits** to `MVP-SPEC.md`, `docs/format/registry-v1.md`, the frozen
   registry, `wording.rs`, any snapshot, any code, any fixture, or any golden
   vector are requested by this ruling. **Zero frozen bytes.**

---

## Outcome

The register asked whether the verifier page may be more than one file, and the
wave owner's five-minute lean got the answer right and every reason wrong. The
page is one file — but not because ES module scripts are blocked from `file://`,
and not because `--target no-modules` was needed to escape them. What `file://`
blocks is *retrieving a sibling*, and an inline script is not retrieved: the
`--target web` glue turns out to contain no static `import` at all, so pasting
it into an inline module script is pure text, and that page verifies a real
`.sealproof` from a `file://` origin, byte-identically to native, in two
independent browser engines, with one network request, which is the page. The
target the lean reached for is then refused on its own merits: it silently drops
a Safari workaround on the one function every report string crosses, and it is
glue that nothing in this repository has ever run.

The wave owner's own doubt was the best thing in the brief, and it inverted. An
all-inline page does not force `'unsafe-inline'`; it makes SHA-256 script hashes
available, and because the module lives *inside* the hashed script, the hash
covers the ninety-nine per cent of the payload that Subresource Integrity
structurally cannot. One byte changed anywhere in that payload and the browser
refuses to run the page at all — which is not a defence against a lying host,
and this record says so as plainly as D63 did, but it converts the accident case
D63 named as the likely failure from a number nobody compares into a hard stop.
A multi-file page could never have had it. The objection was the argument.

Two things nobody had enumerated decided details of their own. A `connect-src`
listing the six pinned endpoints looks tighter and silently forbids the
user-overridable endpoints spec line 137 mandates — undiagnosably, because the
page is forbidden to name a cause and the browser gives it the same `TypeError`
either way; so the policy says `https:`, which is exactly the predicate the
override validator already enforces. And D63's fence, which permits the
substitutions this shape needs, also promised that the template-to-artifact diff
would be one token a reviewer could eyeball. That promise cannot survive
inlining, and rather than stretch it, this record narrows it and pays for the
narrowing: the artifact decomposes, in twenty-nine milliseconds, into a
2 858-byte authored residue plus two tokens that must equal the build inputs
byte-for-byte. Nobody was ever going to read 1.8 MB of WebAssembly. A machine
comparing it to the file `wasm-pack` wrote is the review that clause wanted, and
it is the same check the reader performs, on the same bytes, to recover the
number the footer shows.
