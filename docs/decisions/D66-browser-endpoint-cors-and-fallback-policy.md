# D66 — Browser CORS viability of the pinned endpoint sets, and the fallback policy when a fetch fails

- **Status: RESOLVED — all six pinned endpoints are browser-usable today, and
  the register's "compatibility checkbox a quick probe answers yes/no" lean is
  OVERTURNED ON MEASUREMENT, in a real browser.** The two esplora endpoints
  have **no `OPTIONS` route at all** — the preflight returns **404** with the
  router's generic `endpoint does not exist "…"` body — so `blockstream.info`
  and `mempool.space` are reachable from a page **if and only if the page never
  triggers a preflight**, i.e. sends only CORS-safelisted request headers.
  Measured live in Chromium 150: the real `blockstream.info` GET **succeeds**
  with `Accept: text/plain` and **fails** with one extra header `X-Antseal: 1`.
  A curl probe reading `Access-Control-Allow-Origin` off the GET answers "yes"
  in both cases, so the checkbox framing is not merely coarse — **it returns
  the wrong answer for a page that adds a header**, and the header set belongs
  to code R24 has not written. The Arbitrum half is the mirror image: its
  `Content-Type: application/json` is **not** a safelisted value, so a
  preflight is **mandatory** — and it works on all four D55 endpoints (204,
  `Allow-Methods: POST`, `Allow-Headers: content-type`, `max-age 600`),
  re-confirmed today. One source is viable because preflight is *avoided*; the
  other because preflight *succeeds*; a single "yes" hides that they break
  under opposite changes. Arm (ii) is **measured true, four ways**: CORS
  rejection, preflight failure, connection-refused and DNS failure are the
  *identical* `TypeError` / `"Failed to fetch"` / `cause: undefined`, so the
  page **may never name CORS as a cause** — the fallback renders "could not be
  checked" and nothing more. A thrown fetch is therefore `Transport` and can
  **never** become `NoSuchBlock`, which is fail-closed by construction: D56
  rule O7's refutation needs a 404 **body**, and a throw has none. **The pinned
  defaults do not change** and no browser-safe sibling pin is needed. Arm (iii)
  is **refused as an overturn and adopted as a constraint**: spec line 137
  mandates "user-overridable", so overrides stay — but they gain the CLI's own
  A49 https rule, which the page's "simple inputs" did not have. The residual
  the framing hid: **nothing watches**. A44 — the only rot watch, still open —
  probes Arbitrum POST CORS **by name** and has **no esplora check of any
  kind**, so the watch covers the pair that can never change a verdict and
  omits the pair that is the sole route to `proven` **and** the sole route to
  `invalid`.
- **Date: 2026-08-12** (wave 18, Act 1, D66 planning lane; briefed to overturn
  the checkbox lean. The lean is overturned by a live browser arm; sub-arm
  (iii) is refused as stated and re-cast as a constraint; and R18's frozen
  three-class failure vocabulary **survives ON MEASUREMENT** — it turns out to
  be page-populatable in all three classes, which was not previously known.)
- **Owning tasks: R24** (the consumer — its Notes carry the open question and
  its Accept carries "one-endpoint-down"), **A16** (owns
  `DEFAULT_ESPLORA_ENDPOINTS` and the request shape), **A17/D55** (the
  Arbitrum half, re-confirmed here), **A44** (the watch — gains an esplora
  arm), **R22** (the binding the page's probe outcomes cross), **R23** (the
  page's own CSP, which does not exist yet), **R25/R26/D62** (the deploy that
  can introduce that CSP).
- **Amends**: `tasks/R.md` R24 `Notes` (the open-decision sentence is
  discharged; replacement quoted in the Registrar's edit set), `tasks/A.md`
  A44 `Do` (esplora arm), and the `DEFAULT_ESPLORA_ENDPOINTS` doc comment.
  **Supersedes**: nothing. **Corrects**: nothing. D55 §8 finding 5 predicted
  the method-and-POST rule would govern this record's esplora measurement; it
  did, and §2.1 records where esplora departs from the Arbitrum shape.

---

## 1. What was measured

**Method note.** Every probe below is a read-only GET or a read-only JSON-RPC
query against an endpoint **already pinned in the product**, per the wave-18
standing rule ("Read-only CORS/liveness probes of already-pinned public
endpoints are D66's measurement and are not submissions"). No calendar, no
TSA, no project data, nothing outside the pinned set. `curl 7.88.1`,
Chromium 150.0.7871.181, one Linux host.

**Clock disclosure.** This host's clock is **135 s behind** the endpoints'
own `Date` headers, measured directly at `00:52:03Z` local against
`Wed, 12 Aug 2026 00:54:18 GMT` from `blockstream.info`, and consistently
(±2 s round trip) across both esplora operators and both HTTP versions.
Local probe times are given below because they order the events; where an
absolute time matters, the server's `Date` header is the better witness and
is quoted with it. A CORS measurement without a timestamp is not evidence,
and a timestamp from a skewed clock should say so.

### (a) The pinned constants, and the exact request A16 makes

`crates/antseal-anchor/src/esplora.rs:83-84`:

```rust
pub const DEFAULT_ESPLORA_ENDPOINTS: [&str; 2] =
    ["https://blockstream.info/api", "https://mempool.space/api"];
```

with the path segments at `:87`, `:89`, `:91` and the no-such-block body at
`:95`. The Arbitrum constants are D55's, at
`crates/antseal-anchor/src/arbitrum/endpoints.rs` (`ARBITRUM_ONE_VERIFY_RPCS`,
`ARBITRUM_SEPOLIA_VERIFY_RPCS`, and the CLI-only reserve at `:35` whose doc
already records the `1rpc.io/arb` CORS finding).

**A16 issues two GETs per endpoint, resolved independently** (`esplora.rs:134`
`header_at_height` → `:179` `block_hash_at_height` → the header GET at `:143`),
and the request is built at `esplora.rs:261-272`:

```rust
let request = HttpRequest {
    endpoint, method: HttpMethod::Get, content_type: None,
    accept: Some("text/plain"), body: &[],
    receive_cap_bytes: ESPLORA_RESPONSE_CAP_BYTES,
    idempotency: Idempotency::SafeToRepeat,
};
```

So the production request is **`GET`, `Accept: text/plain`, no `Content-Type`,
no body** — and step 2's URL is built from step 1's endpoint-supplied hash,
validated to 64 lowercase hex characters *before* interpolation (`:201-210`).
Both steps were probed; a probe of step 1 alone would not have shown that
step 2 is on the same CORS footing.

### (b) esplora — the real GETs, with `Origin`

`curl -sS -D - -o /dev/null -H 'Origin: https://antseal.org' -H 'Accept: text/plain' <url>`,
height **960767** (a real attested height already committed under
`testdata/anchors/A25-upgrade-headers/`). Local `2026-08-12T00:38:56Z`.

**Step 1 — `GET https://blockstream.info/api/block-height/960767`:**

```
HTTP/1.1 200 OK
Date: Wed, 12 Aug 2026 00:41:09 GMT
Content-Type: text/plain
Content-Length: 64
Connection: keep-alive
Vary: Accept-Encoding
cache-control: public, max-age=157784630
Access-Control-Allow-Origin: *
Access-Control-Expose-Headers: x-total-results
X-Frame-Options: SAMEORIGIN
Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-eval'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; font-src 'self' data:; object-src 'none'
Strict-Transport-Security: max-age=31536000; includeSubDomains
X-XSS-Protection: 1; mode=block
X-Content-Type-Options: nosniff
Referrer-Policy: no-referrer
X-Cache-Status: HIT
```

**Step 1 — `GET https://mempool.space/api/block-height/960767`:**

```
HTTP/2 200
server: nginx
date: Wed, 12 Aug 2026 00:41:10 GMT
content-type: text/plain
content-length: 64
cache-control: max-age=1
x-powered-by: mempool-electrs 3.4.0-dev-bf622e5
access-control-allow-origin: *
x-bitcoin-version: /Satoshi:30.0.0(@wiz)/
expires: Wed, 12 Aug 2026 00:41:11 GMT
onion-location: http://mempoolhqx4isw62xs7abwphsq7ldayuidyx2v2oethdhhj6mlo2r6ad.onion/api/block-height/960767
strict-transport-security: max-age=63072000; includeSubDomains; preload
content-security-policy: frame-ancestors 'self'
pragma: public
cache-control: public
vary: Accept-Language
vary: Cookie
```

Both returned the same hash —
`00000000000000000000553c93eb174557abe089e9c59a7e8f3eb7d116eb803e` — so A16's
must-agree round agreed live, incidentally.

**Step 2 — `GET {base}/block/00000000…803e/header`**, local `00:39:10Z`. Both
`200`, `Content-Length: 160`, and both carry
**`Access-Control-Allow-Origin: *`** (blockstream `Date: 00:41:23 GMT` with the
identical header block as above; mempool `date: 00:41:24 GMT`,
`cache-control: max-age=2592000`, same `access-control-allow-origin: *`).

**The 404 refutation arm — `GET {base}/block-height/99999999`**, local
`00:39:57Z`. This is the arm D56 rule O7 turns into `AnchorState::Invalid`, so
it matters that a browser can read its **body**:

```
HTTP/1.1 404 Not Found          |  HTTP/2 404
Date: Wed, 12 Aug 2026 00:42:10 |  date: Wed, 12 Aug 2026 00:42:12 GMT
Content-Type: text/plain        |  content-type: text/plain
Content-Length: 15              |  content-length: 15
Access-Control-Allow-Origin: *  |  access-control-allow-origin: *
…                               |  …
Block not found                 |  Block not found
```

**ACAO is present on the 404 on both**, so the refutation path survives in a
browser. (Measured again through a real browser in (d), arm 9.)

### (c) esplora — the preflight, which does not exist

`curl -X OPTIONS -H 'Origin: https://antseal.org'
-H 'Access-Control-Request-Method: GET' -H 'Access-Control-Request-Headers: accept'`,
local `00:39:24Z`:

```
HTTP/1.1 404 Not Found                |  HTTP/2 404
Date: Wed, 12 Aug 2026 00:41:38 GMT   |  date: Wed, 12 Aug 2026 00:41:38 GMT
Content-Type: text/plain              |  content-type: text/plain
Content-Length: 46                    |  content-length: 46
Vary: Accept-Encoding                 |  x-powered-by: mempool-electrs 3.4.0-dev-bf622e5
Access-Control-Allow-Origin: *        |  access-control-allow-origin: *
X-Frame-Options: SAMEORIGIN           |  x-bitcoin-version: /Satoshi:30.0.0(@wiz)/
…                                     |
```

and the 46-byte body, on **both**, is

```
endpoint does not exist "/block-height/960767"
```

Three things follow, and none is a matter of policy:

1. **There is no `Allow-Methods` and no `Allow-Headers` on either.** A CORS
   preflight succeeds only if its response is an ok status *and* names the
   method; a 404 is neither.
2. **This is not a CORS decision — the router simply has no `OPTIONS`
   route.** The body is byte-for-byte the same generic string
   `esplora.rs:33` already documents for a *mistyped base URL*, which A16
   deliberately refuses to read as "no such block". The preflight is not
   being denied; it is not being recognised.
3. **So the operators are unlikely to "fix" it, because from their side
   nothing is broken.** A revisit trigger that waits for a preflight to start
   working would wait indefinitely.

### (d) The browser — the measurement that overturns the lean

curl shows headers; it does not enforce CORS. Only a browser can answer
"viable from a browser", so the arms below ran in **Chromium 150.0.7871.181
headless**, local `2026-08-12T00:44:19Z`, from an origin at
`http://127.0.0.1:8801`. Arms 1–6 use local servers, one of which reproduces
the esplora shape measured in (b)/(c) exactly — `GET` → 200 + `ACAO: *`,
`OPTIONS` → 404 + `endpoint does not exist "…"` + `ACAO: *`, no
allow-methods/headers. Arms 7–11 hit the **real pinned endpoints**. Verbatim
DOM output:

```
1 same-origin control
    OK       status=200 type=basic ok=true body="<!doctype html>\n<html><head><meta charse"
2 cross-origin, ACAO:* , safelisted Accept
    OK       status=200 type=cors ok=true body="00000000000000000000553c93eb174557abe089"
3 cross-origin, NO ACAO
    THREW    ctor=TypeError name="TypeError" message="Failed to fetch" cause="undefined"
4 esplora-shaped + NON-safelisted header (forces preflight)
    THREW    ctor=TypeError name="TypeError" message="Failed to fetch" cause="undefined"
5 connection refused (nothing listening)
    THREW    ctor=TypeError name="TypeError" message="Failed to fetch" cause="undefined"
6 DNS failure
    THREW    ctor=TypeError name="TypeError" message="Failed to fetch" cause="undefined"
7 REAL blockstream.info (pinned)
    OK       status=200 type=cors ok=true body="00000000000000000000553c93eb174557abe089"
8 REAL mempool.space (pinned)
    OK       status=200 type=cors ok=true body="00000000000000000000553c93eb174557abe089"
9 REAL blockstream 404 arm (beyond tip)
    OK       status=404 type=cors ok=false body="Block not found"
10 REAL arb1 POST (D55 pair)
    OK       status=200 type=cors ok=true body="{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":\"0xa4b1"
11 REAL blockstream + NON-safelisted header (preflight)
    THREW    ctor=TypeError name="TypeError" message="Failed to fetch" cause="undefined"
```

**Arms 2 and 4 are a controlled experiment**: same URL, same local server, same
method — the *only* difference is `Accept: text/plain` versus `X-Antseal: 1`.
Arm 2 succeeds, arm 4 throws. That isolates the CORS-safelisted-header rule as
the whole of the mechanism, with no appeal to documentation.

**Arms 7 and 11 repeat it against the real, pinned `blockstream.info`** — the
same URL succeeds with a safelisted header and throws with a non-safelisted
one. This is the falsifier for the register's lean, and it is live.

**Arms 3, 4, 5, 6 and 11 are byte-identical error surfaces.** CORS rejection
(no ACAO), preflight failure (local), connection refused, DNS failure, and
preflight failure against a real endpoint all produce
`TypeError` / `"Failed to fetch"` / `cause: undefined`. There is no status, no
`type`, no header, no cause channel. Arm (ii) of the brief is measured true,
and measured *within one browser*, which is the stronger form: a page cannot
even sniff the message string, because the string does not vary by cause.

**Arm 9 is the refutation path, confirmed in a browser**:
`status=404 type=cors ok=false body="Block not found"` — a 404 with ACAO is a
*successful* fetch whose body the page reads, which is exactly what D56 O7
requires and what `esplora.rs:220` `is_no_such_block` compares.

*(Cross-browser: the same harness was attempted under Firefox 140.13.0esr
headless and did not run — its GFX initialisation failed in this environment
(`RenderCompositorSWGL failed mapping default framebuffer`) and no beacon was
returned. Recorded as attempted-and-failed rather than omitted. The ruling does
not depend on it: the indistinguishability is already established **within**
one browser across four causes, so string-sniffing is dead regardless of what
another engine's string is.)*

### (e) The `file://` case R23's Accept names

R23's Accept requires the page to work from `file://`, whose origin serialises
to `null`. Probed with `-H 'Origin: null'`, local `00:42:03Z`:

| endpoint | request | status | ACAO |
| --- | --- | --- | --- |
| `blockstream.info/api` | GET block-height | 200 | `*` |
| `mempool.space/api` | GET block-height | 200 | `*` |
| `arb1.arbitrum.io/rpc` | POST | 200 | `*` |
| `arb1.arbitrum.io/rpc` | OPTIONS | 204 | `*` |
| `arbitrum.drpc.org` | POST | 200 | `*` |
| `arbitrum.drpc.org` | OPTIONS | 204 | **`null`** (echoes) |

All pass: a wildcard matches a null origin, and DRPC's echoed `null` matches
it too. Noted rather than relied on — §3 R6 keeps `file://` online mode
out of the promised surface for a different reason.

### (f) Arbitrum — D55 re-confirmed, and one thing that moved

Local `00:40:16Z`–`00:41:26Z`, `Origin: https://antseal.org`, POST with
`Content-Type: application/json` and `eth_getTransactionReceipt` — **D55's own
production method**, against D55's own committed transactions
(`0xf74f5e8c…bfd22` on One, `0xf014eab8…126e` on Sepolia):

| endpoint | `OPTIONS` preflight | POST |
| --- | --- | --- |
| `https://arb1.arbitrum.io/rpc` | 204, `ACAO: *`, `Allow-Methods: POST`, `Allow-Headers: content-type`, `max-age: 600` | 200, **`ACAO: *`** |
| `https://arbitrum.drpc.org` | 204, `ACAO: https://antseal.org` (echoes), `max-age: 600` | 200, **`ACAO: *`** |
| `https://sepolia-rollup.arbitrum.io/rpc` | 204, `ACAO: *`, `Allow-Methods: POST`, `Allow-Headers: content-type` | 200, **`ACAO: *`** |
| `https://arbitrum-sepolia.drpc.org` | 204, `ACAO: https://antseal.org` (echoes) | 200, **`ACAO: *`** |

**D55's Arbitrum ruling holds unchanged**, and arm 10 above confirms one of
them through a real browser and a real preflight.

**One thing moved, and it is not CORS.** The *first*
`eth_getTransactionReceipt` to `arbitrum.drpc.org` returned **HTTP 408** —
carrying `access-control-allow-origin: *` and
`x-drpc-owner-tier: free`. Five immediate retries all returned **200** in
0.63–1.12 s with a 1 721-byte body, and `eth_chainId` returned `0xa4b1`. So:
transient, ~1 in 6 in this session, and **CORS-visible either way**. It is
recorded because the brief asked whether a re-check was even necessary — ten
days after D55 measured this endpoint healthy, the first production-method
call to it failed. That is the shelf-life argument made by the data rather
than asserted. (Also: arb1's receipt body is **1 722 B**, matching D55
exactly; drpc's is 1 721 B. A one-byte envelope difference between operators,
which is precisely why D55 ruled the comparison is over an extracted tuple and
never over bytes.)

### (g) Nothing in the tree watches, and A44 watches the wrong pair

`grep -rn "CORS\|Access-Control"` over the repo, excluding `target/`, returns
**no hit in `scripts/` and no hit in `.github/`** — there is no CORS-aware
tooling anywhere. The only watch that exists is **A44**, and it is **still
open** (`TODO.md:443`). Its `Do` (`tasks/A.md:703`) has exactly three checks:
(1) OTS calendars, (2) **Arbitrum RPCs**, whose text names the requirement by
name — *"read `Access-Control-Allow-Origin` off the **POST** response"* — and
(3) pinned roots. **There is no esplora check of any kind** in A44: not CORS,
not liveness, not the production request.

The stakes are inverted by that omission. The Arbitrum pair is advisory-only
and *never* an anchor (spec line 137: "not an anchor … never
headline-eligible"). The esplora pair is the **sole** route by which an OTS
anchor becomes `proven` (D56 O3) **and** the sole route by which one is
refuted to `invalid` (D56 O6/O7). The watch covers the pair that cannot move a
verdict and omits the pair that is the only thing that can.

### (h) The page's own CSP — the self-inflicted twin, which does not exist yet

`verifier-web/index.html` is a **484-byte placeholder** ("Offline verifier
page — arrives at M3 (R23)"), and `grep -rn "connect-src\|Content-Security-Policy"`
over the repo returns **nothing** outside `target/`. So the page has no CSP,
and the deploy that will give it one (R25/R26, host per D62) is queued for
wave 19.

A `default-src 'self'` policy makes `connect-src` fall back to `'self'` and
kills online mode outright — and it is exactly the hardening a static-host
deploy invites. It is not hypothetical: **`blockstream.info` itself serves
`default-src 'self'; …` on the very responses measured in (b).** And the
failure mode is identical to the third-party one — a `TypeError` the page
cannot explain. This half is **ours**, it can be regressed by our own deploy,
and unlike the third-party half it is testable offline.

### (i) R18's frozen failure vocabulary is page-populatable — measured, not assumed

R18 landed 2026-08-11 (`TODO.md:716`), so the wording is **already frozen** and
`tasks/R.md` R18 makes it *"shared verbatim by CLI and page (renderers receive
final strings, never compose their own)"*. The CLI's own failure type is rich:
`EndpointFailure` has three arms (`agree.rs:70-107`) over an `AnchorHttpError`
with **thirteen** endpoint-carrying arms (`agree.rs:139-151` —
`Resolve`, `Connect`, `Tls`, `SendTimeout`, `ReceiveTimeout`, `Status`,
`Redirected`, `OversizeBody`, …). The browser has **one**. If R18 had frozen a
per-endpoint *cause*, the page could not have populated it truthfully and the
shared table would have been broken on arrival.

It did not. `crates/antseal-core/src/verify/wording.rs:687-695`:

```rust
pub const fn probe_failure_class_label(class: ProbeFailureClass) -> &'static str {
    match class {
        ProbeFailureClass::Transport => "transport failure",
        ProbeFailureClass::Payload => "unusable reply",
        ProbeFailureClass::WrongChain => "wrong chain",
    }
}
```

Three classes, core-owned, **public fields, constructible from literals**
(`verify/overlay.rs:90-120`), rendered through `endpoint_failures_line`
(`wording.rs:665`) as *"online check for block H failed (…) — no promotion;
the offline state stands"*. All three are reachable from a page:
`Transport` for a thrown fetch, `Payload` for a 200 whose body is not 64
lowercase hex or 160 hex, `WrongChain` for the `eth_chainId` guard on a
readable response. **This lean survives ON MEASUREMENT** — and what sharpened
it is that the survival is *load-bearing*: R18's coarseness is the only reason
the shared table works at the page's resolution, and §3 R3 now pins that
coarseness rather than leaving it a happy accident.

---

## 2. The overturn

### 2.1 "A quick probe answers it yes/no" — refuted, by arm 11

The lean's implicit model is that CORS viability is a **property of an
endpoint**, discoverable by asking it once. Measurement says it is a **joint
property of the endpoint and the request**, and the request half is unwritten.

- The cheap probe — `curl` the GET, read `Access-Control-Allow-Origin` —
  returns `*` for `blockstream.info` (§1 b). It returns `*` whether the page
  will send `Accept: text/plain` or `X-Antseal: 1`.
- **Arm 11 measured the second case in a real browser against that real
  endpoint: it throws.** So the cheap probe does not merely under-describe the
  answer; on a page that adds one header it reports the opposite of the truth.
- The reason is structural and will not go away: the preflight route **does not
  exist** on either operator (§1 c), and from the operator's side nothing is
  broken, so there is no fix to wait for.

This is D55's own lesson one layer up. D55 §2 ruled that *"every endpoint in a
must-agree pair is liveness-verified with the exact JSON-RPC method the
consuming code calls … never with a cheaper method"*, because
`publicnode` passed `eth_blockNumber` and failed the only method A17 calls.
Here the "production method" for the *page* is a request R24 has not written —
so D66 cannot be discharged by measurement alone. It has to be discharged by
measurement **plus a constraint on R24**, which is §3 R1, and by a test that
holds that constraint, which is §7.

### 2.2 The two sources are viable for opposite reasons

Stated plainly because a single "yes" hides it:

| source | preflight | why it is viable | what breaks it |
| --- | --- | --- | --- |
| esplora ×2 | **404 — does not exist** | the page never triggers one (safelisted headers only) | adding any non-safelisted request header, on our side |
| Arbitrum ×4 | **204, correct** | `application/json` forces one and it succeeds | the operator removing `Allow-Methods`/`Allow-Headers`, on their side |

A "CORS is fine" note in a task entry would cover both and warn about neither.

### 2.3 Arm (ii) — a CORS rejection is indistinguishable from a network failure — **measured true**

The brief asked for verification, not repetition. §1 (d) arms 3/4/5/6/11:
four distinct causes, one error object, no cause channel, **within a single
browser**. The consequence is not stylistic. It decides what the page may
honestly render (§3 R4) and it decides the classification (§3 R2), and the
classification lands on the safe side by construction rather than by choice:
`NoSuchBlock` requires reading a 404's body, and a throw has no body, so the
one outcome that could turn an anchor `invalid` is *physically unreachable*
from a failed fetch.

### 2.4 Arm (iii) — refused as an overturn, adopted as a constraint

The brief's third candidate: overrides push a security decision onto the user
at exactly the wrong moment. **The concern is real and the overturn is
refused**, for one reason that ends it: *"user-overridable"* is **spec line
137**, verbatim, and this lane has no warrant to delete a spec-mandated
affordance. What survives is the shape of the concern, and it is worth stating
because it is sharper than R24's one-line "overrides are the mitigation":

- The user is asked to substitute an endpoint **at the moment the page has
  just failed**, with a message that (§2.3) cannot say why.
- The substituted endpoint enters the one path that can turn an anchor
  `invalid` (D56 O7).
- The CLI already refuses non-`https` `bitcoin_endpoints`/`arbitrum_endpoints`
  **at config load**, naming the endpoint before any network call
  (`docs/config.md:94`, A49), *because these replies are unsigned and
  transport is their only integrity control*. R24's Do specifies the page's
  override as **"simple inputs"** with no validation stated at all.

So the mitigation does not need removing; it needs the rule the CLI already
has. §3 R5.

### 2.5 The thing the framing hid: the alarm a hostile endpoint can silence

Falls straight out of §2.3, and no arm of the brief anticipated it.
`Agreement::Disagreed` is the alarming outcome — `agree.rs:157-161` says so:
*"`Disagreed` is alarming — it means one of two endpoints that should not be
able to coordinate is wrong or lying"*. `Unavailable` is the benign one.

An endpoint that is lying, and that would be caught by the pair, can
**downgrade its own `Disagreed` to `Unavailable` on the page alone** by
omitting `Access-Control-Allow-Origin` for browser origins — a header it fully
controls, that costs it nothing, and that the page cannot see through. The CLI,
which does not enforce CORS, still renders `Disagreed`.

Bounded honestly: this is **suppression of an advisory alarm, not forgery**.
The page still never promotes (§3 R2), the offline cryptographic verdict is
untouched by construction (R24's byte-identity Accept; D64 §2), and no false
time can be produced. But it means **the page's overlay is strictly weaker
than the CLI's against a hostile endpoint, and the difference is invisible on
the page**.

The mitigation already exists and needs no new surface: R25's footer carries
the exact advice line *"for high-stakes verification, run `antseal verify` and
compare verdicts"*. D66's contribution is to record **why** that sentence is
load-bearing here, so it is never treated as boilerplate — §3 R7.

---

## 3. The ruling

**R1 — The esplora request is preflight-free, and that is a pinned constraint
on R24, not an implementation detail.**

The page's esplora fetches use **`GET`**, with **at most `Accept: text/plain`**
and **no other request header**. `Accept: text/plain` is measured
preflight-free (§1 d, arms 2 vs 4, and 7 vs 11) and is byte-identical to
A16's CLI request (`esplora.rs:266`), so the two surfaces ask the same
question. Additionally, and for the same reason:

- `credentials` must be `'omit'` — `ACAO: *` is invalid for a credentialed
  request, so `credentials: 'include'` would break all four wildcard endpoints
  at once;
- `mode` stays the default `'cors'` — `'no-cors'` yields an opaque response
  the page cannot read, which is a silent version of the same failure;
- no `Content-Type` (there is no body), no custom headers, ever.

**The constraint is the ruling.** Because a violation is invisible to a curl
probe and fatal in a browser, §7's first test asserts the header set is a
subset of the safelist, statically and with no network.

**R2 — Classification: a thrown fetch is `Transport`, always, and can never
refute.**

```text
fetch threw                       -> ProbeFailureClass::Transport
2xx, body unusable                -> ProbeFailureClass::Payload
readable reply, wrong chain id    -> ProbeFailureClass::WrongChain
404 + body "Block not found"      -> OnlineBlockResult::NoSuchBlock   (D56 O7)
200 + 160 hex                     -> OnlineBlockResult::Header(..)     (D56 O3/O6)
any other readable non-2xx        -> ProbeFailureClass::Transport
```

A throw may **never** produce `NoSuchBlock`, and the page must not infer a
block's absence from a failure of any kind. This is fail-closed **by
construction, not by discipline**: O7's evidence is a 404's *body*
(`esplora.rs:220`, trimmed and case-insensitive), a thrown fetch has no body,
and so the refuting outcome is unreachable from the failing path. `Transport`
is truthful for a CORS rejection without naming it: at the Fetch layer a
failed CORS check *is* a network error — no response was delivered — which is
exactly what `ProbeFailureClass::Transport`'s own doc already covers ("the
request itself failed: transport, timeout, non-2xx, over-cap").

**R3 — R18's three-class vocabulary is confirmed, and its coarseness is now
pinned.**

No wording change. `probe_failure_class_label` (`wording.rs:687`) stays three
classes, and **that coarseness is now a requirement rather than a
convenience**: the shared table is renderable by both surfaces *only* while no
class names a cause the browser cannot observe. Any future proposal to split
`Transport` into `dns` / `refused` / `tls` / `timeout` is refused for the page
and, because the table is shared verbatim (R18 `Do`), refused outright — the
CLI may render its richer `AnchorHttpError` detail in its **own** additional
line, never in the shared row.

**R4 — The fallback: what the page does, and what it may say.**

When one or both endpoints of a source fail:

- **Does**: no promotion for that anchor; no refutation; the offline block
  is untouched, byte-identical (R24's Accept, D64 §2). The overlay **still
  renders** — D64 §3 makes the per-probed-anchor outcome lines
  *always-rendered* — carrying `NotPromoted{endpoint-failures}` (D64 §6.2)
  through `endpoint_failures_line`, with `endpoints_line` disclosing which
  endpoints were used and whether they were overridden.
- **May say**: the frozen sentence and nothing else —
  *"`<slot>`: online check for block `<height>` failed (`<endpoint>`:
  transport failure) — no promotion; the offline state stands"*
  (`wording.rs:665`, with the class word from `:690`).
- **May NOT say**: anything naming CORS, blocking, browser policy,
  cross-origin, DNS, TLS, refusal, or the endpoint's configuration as the
  cause; anything advising the user that the endpoint "blocks browsers"; and
  any diagnosis phrased as fact. Measured: the page holds one indistinguishable
  error for four causes (§1 d). A page that named one would be presenting a
  guess as a finding on the one surface whose purpose is not guessing.
- **May offer**, as chrome outside the wording table: a retry affordance and
  the override input, neither carrying a diagnosis.

**R5 — The override keeps the CLI's rule.**

Overrides stay (spec line 137, verbatim). They gain, in the page:

1. **`https://` only**, refused at input with the endpoint named, before any
   fetch — the page-side equivalent of `docs/config.md:94` / A49. The browser's
   mixed-content blocking is *not* the mitigation: it produces the same opaque
   `TypeError`, and it does not apply from `file://`.
2. **Exactly two entries per source**, replacing the pinned pair wholesale —
   D55 §6's rule, for D55 §6's reason: one endpoint cannot satisfy "must
   agree", and A16 has no single-endpoint outcome on purpose
   (`esplora.rs:61-64`: *"one esplora instance is exactly the trust level A16
   exists to avoid"*).
3. **Rendered as text, never as markup.** The override value flows into
   `endpoint_failures_line` and `endpoints_line`, i.e. user-controlled text
   reaching the DOM of the verification surface. `textContent`, never
   `innerHTML`. (D67 minted the CLI's analogous escape discipline for the
   consent screen; this is the page's, and it is narrower because the DOM
   needs no control-character policy — only a no-markup one.)
4. Session-scoped and labelled as departing from the pinned defaults — already
   R24's Accept and D64 §8 edit 5; restated here only to say the label is
   `endpoints_line`'s and is not composed by the page.

**R6 — No fallback to a surviving endpoint, and none to a third.**

A CORS-hostile endpoint fails **100 % of the time**, not intermittently — so
"one-endpoint-down" stops being a transient and becomes a permanent single
endpoint. It is exactly then that promoting on the survivor is tempting, and
it is refused: one endpoint is not corroboration, and A16 has deliberately no
`Lagging` arm. Nor does the page silently try a third endpoint: the pair is
what the user was told was used (`endpoints_line`), and substituting one
without saying so would make that line false.

**R7 — `file://` online mode is not promised, and the footer line is
load-bearing.**

Online mode is offered when the page has an origin that can carry it. §1 (e)
measured all six endpoints answering a `null` origin today, so `file://` is
**permitted and not blocked** — but it is not an R24 Accept row and not a
snapshot case, because its viability rests on wildcard behaviour toward an
opaque origin that no operator has promised. R23's offline `file://` guarantee
is unaffected: it covers offline verification, which is the whole cryptographic
verdict.

And the R25 footer line — *"for high-stakes verification, run `antseal verify`
and compare verdicts"* — is hereby recorded as this decision's mitigation for
§2.5, not as generic advice. The CLI sees endpoint failures the page cannot
distinguish and sees `Disagreed` where the page may be shown `Unavailable`.

**R8 — The pinned defaults do not change, and no sibling pin is minted.**

All six endpoints are viable (§1 b, d, f). `DEFAULT_ESPLORA_ENDPOINTS` and
D55's two pairs stand unedited; `1rpc.io/arb` stays the CLI-only reserve it
already is (`arbitrum/endpoints.rs:35`). What the esplora constant gains is a
**doc comment** recording the preflight-absence and R1's constraint — because
one constant now has two consumers with different obligations, and only one of
them is written down (§Registrar's edit set, item 3).

**R9 — The watch, and the honest residual.**

- **A44 gains an esplora arm** — the same shape its Arbitrum arm already has:
  per entry in `DEFAULT_ESPLORA_ENDPOINTS`, run **A16's production request**
  (both steps, height → hash → header, against a committed historical height),
  assert `Access-Control-Allow-Origin` on **each GET** and on the **404 arm**,
  and **record** the `OPTIONS` status as a trend rather than assert it — the
  preflight is expected to 404 (§1 c), so a preflight that starts *working* is
  news, not a red, while a GET that loses ACAO is a red.
- **It cannot be a required CI gate, and must not become one.** Q16's Accept
  is *"CI anchor lane green with zero external anchor-network calls (verified
  via sandbox or endpoint blocklist)"*, enforced in code by
  `AnchorHttpError::RealNetworkDenied` (`crates/antseal-anchor/src/http.rs:770`).
  A44 is already specified non-required. Correct, and unchanged.
- **The residual, named**: **A44 is open** (`TODO.md:443`). Until it lands and
  gains this arm, **nothing in the tree watches any of this**, and this
  record's answer has a shelf life measured in whatever the operators do next.
  §1 (f) shows ten days was enough for one endpoint's behaviour to move.
- **What CAN be gated, and should be, is the half that is ours.** The failure
  arm 11 actually exhibited is caused by *our* header set, and the CSP failure
  in §1 (h) is caused by *our* deploy. Both are offline, deterministic and
  red-capable (§7 tests 1 and 2). The sharpest thing this decision produces is
  that the condition most likely to break online mode is **not** the
  third-party one nobody can gate.

---

## 4. Refused shapes

| shape | refused on |
| --- | --- |
| answering "yes, CORS works" and closing the row | arm 11: the same real endpoint succeeds and fails on a header the answer never mentions (§2.1) |
| a liveness/ACAO probe of step 1 only | step 2 is a different path on the same host and is the request whose bytes A12 checks; both measured (§1 b) |
| naming CORS in any rendered failure line | four causes, one `TypeError`, no cause channel — measured in-browser (§1 d, §2.3) |
| inferring `NoSuchBlock` from a failed fetch | O7 refutation needs a 404 **body**; a throw has none — the safe direction is structural, and this would invert it (§3 R2) |
| splitting `Transport` into dns/tls/refused/timeout | the browser cannot observe the distinction and the table is shared verbatim; the CLI may add its own detail line instead (§3 R3) |
| promoting on the surviving endpoint when one is CORS-blocked | a CORS-hostile endpoint fails 100 % of the time; A16 has no single-endpoint arm on purpose (§3 R6) |
| silently substituting a third endpoint on failure | falsifies `endpoints_line`, which is the page's disclosure of what it used (§3 R6) |
| dropping user overrides to avoid arm (iii) | "user-overridable" is spec line 137 verbatim (§2.4) |
| overrides as unvalidated "simple inputs" | the CLI refuses non-https for these two keys at config load because the replies are unsigned (A49, `docs/config.md:94`); the page's input reaches the same path (§3 R5) |
| switching Arbitrum to `Content-Type: text/plain` to dodge the preflight | the preflight works on all four (§1 f); it misdescribes the body; and it would diverge from A17's production request, breaking D55 §2's own rule. Recorded as the escape lever **if** an Arbitrum preflight ever breaks — not taken now |
| a browser-safe sibling pin beside `DEFAULT_ESPLORA_ENDPOINTS` | unnecessary — the pinned pair is viable; the constraint is on the request, not the host (§3 R8) |
| making the CORS watch a required CI context | Q16 forbids third-party network in CI and enforces it in code (`http.rs:770`); A44 is non-gating by design (§3 R9) |
| treating the R25 footer line as boilerplate | it is the only mitigation for the alarm-suppression asymmetry in §2.5 (§3 R7) |

---

## 5. The D66/D55/D64 edges, drawn explicitly

**D55 owns the Arbitrum endpoint set**; this record re-measured it and changed
nothing. D55 §8 finding 5 handed D66 the **method-and-POST rule** and it
governed: the esplora probe used A16's exact two-step request. Where esplora
departs from Arbitrum is the preflight's *direction* (§2.2), which D55 could
not have anticipated because its source has a mandatory preflight and this one
has none.

**D64 owns the overlay's structure**; this record supplies no layout. Every
outcome D66 produces was already a D64 §6.2 class
(`NotPromoted{endpoint-failures(per-endpoint)}`), every sentence is already
R18's, and the always-rendered probe line means a CORS failure has a place to
appear without any new surface. **D66 rules only the mapping into those
classes** (§3 R2) and **what may not be said inside them** (§3 R4).

**D56 owns the online rules O3/O6/O7**; untouched. What D66 adds is that the
browser can reach all of them — arm 9 measured the O7 input readable — and
that the failing path cannot reach O7 at all.

**A16 owns the request**; D66 constrains only the page's copy of it, and
constrains it *toward* A16's (§3 R1 keeps `Accept: text/plain` precisely so
the two surfaces ask the same question).

---

## 6. Consumed rows and inputs

- **`tasks/R.md` R24** — the `Notes` sentence *"Verify CORS availability of the
  pinned endpoints from browsers early in M3; overrides are the mitigation if a
  default becomes CORS-hostile (open decision)"* is discharged by this record;
  its Accept row **"one-endpoint-down"** is the venue for §3 R4/R6.
- **`tasks/R.md`** Open-decisions row (`:680`) — the register entry itself.
- **`tasks/A.md` A16** (the request), **A17/D55** (Arbitrum), **A44** (the
  watch), **A49/D90 §6.6** (the https rule and its reason).
- **`tasks/R.md` R18** (frozen wording, §1 i), **R22** (the probe-outcome
  carriage), **R23** (the page and its absent CSP), **R25** (the footer line),
  **R27** (playwright venue for §7).
- **`MVP-SPEC.md` line 137**, quoted verbatim for the two clauses this record
  turns on: *"Online mode: **two pinned default endpoints per source, results
  must agree** (esplora-style: blockstream.info + mempool.space; two public
  Arbitrum RPCs), user-overridable, rendered as an advisory overlay distinct
  from the offline cryptographic verdict."*
- **D55** (§2 rounds 2–3, §6, §8), **D56** (O3/O6/O7), **D64** (§3, §5, §6.2,
  §6.3), **D67** (the user-controlled-text-reaching-a-surface precedent),
  **D90** (`RealNetworkDenied`, the transport asymmetry), **Q16** (the CI
  no-real-network policy).

---

## 7. Tests that must exist, and what makes each fail

| test | lives in | fails when |
| --- | --- | --- |
| `page_esplora_fetch_uses_only_cors_safelisted_headers` | page/R24 unit, **no network** | the page's esplora request builder emits any header outside `{Accept: text/plain}`, or sets `credentials: 'include'`, or `mode: 'no-cors'`. **This is the test for the failure arm 11 actually exhibited**, it is offline and deterministic, and it is the one CI thing that can prevent this decision from silently expiring. Asserted on the constructed request, never on a live response. |
| `page_csp_permits_connect_to_the_pinned_origins` | R23/R25 build check, **no network** | the deployed page's `Content-Security-Policy` (meta or header) restricts `connect-src` such that the six pinned origins are not permitted — including the `default-src 'self'` fallback case (§1 h). Runs against the built artifact so an R26 deploy cannot introduce it unseen. |
| `thrown_fetch_maps_to_transport_and_never_to_no_such_block` | `antseal-core` overlay unit + R22 binding | a failed probe produces `OnlineBlockResult::NoSuchBlock`, or any outcome that can reach D56 O7. Asserted on the **variant**, so a shared "could not be checked" string would not rescue it. |
| `endpoint_failure_wording_names_no_cause` | `antseal-core` wording test (extends R18's positioning sweep) | any string reachable from `endpoint_failures_line` / `probe_failure_class_label` contains `CORS`, `cross-origin`, `blocked`, `DNS`, `TLS`, `refused`, or `policy`. Table-driven over `ProbeFailureClass::ALL`, so a fourth class cannot ship unswept. |
| `one_endpoint_permanently_unreachable_never_promotes` | R21/R24 mocked-endpoint (R27 playwright routes) | the page promotes, or renders corroboration, on one endpoint when the other's fetch throws every time. The **permanent** variant of R24's existing "one-endpoint-down" row — the transient one does not exercise §3 R6. |
| `overlay_absence_leaves_the_offline_bytes_identical` | R21 (already D64's L1 / R21's Accept) | a failed or blocked online probe moves a byte of the offline verdict. Named here because a CORS failure is the most likely *real-world* trigger of it. |
| `page_override_rejects_non_https_and_single_entry` | R24 unit | an `http://` override is accepted, or a one-entry override runs the overlay unpaired (§3 R5). |
| `page_renders_endpoint_strings_as_text_not_markup` | R24/R27 DOM assertion | an override containing markup reaches the DOM as markup through `endpoints_line` or `endpoint_failures_line` (§3 R5.3). |
| `a44_esplora_arm_red_direction` | A44's scheduled lane | a planted esplora stub that answers 200 **without** ACAO does not turn the lane red, or a planted 404 arm without ACAO does not. Proves the red direction at landing, per A44's own Accept. **Non-gating, and never a required context** (Q16). |

Fixtures: the verbatim header blocks of §1 (b), (c), (f) are this record's
evidence and need no `testdata/` home — they contain no antseal data, name only
public third-party endpoints, and the live values they record are exactly what
A44 exists to re-check. **No test in this table contacts a real endpoint**
except A44's, which is scheduled and non-gating.

---

## 8. Discovered work — described, not registered

No ids are minted here.

**(i) A44 has no esplora check at all** — not CORS, not liveness, not the
production request (`tasks/A.md:703`, three checks: calendars, Arbitrum RPCs,
pinned roots). The pair it omits is the only one that can move an anchor to
`proven` or to `invalid`; the pair it covers is advisory-only and never an
anchor. Registrar's edit set item 2 supplies the arm. **A44 is itself still
open**, so this is a gap in a task that is a gap.

**(ii) The verifier page has no CSP and no owner for one.**
`verifier-web/index.html` is a 484-byte placeholder and the repo has no
`connect-src` or `Content-Security-Policy` anywhere (§1 h). A page that
verifies hostile input in a browser wants a CSP; a page that must reach six
third-party origins wants a *specific* one. Nothing in R23/R25/R26/D62
currently says who writes it. This is the one failure mode in this record we
can inflict on ourselves, and §7's second test is the guard — but the policy
itself needs an owner.

**(iii) A lying endpoint can suppress its own `Disagreed` on the page alone**
by withholding `ACAO` from browser origins (§2.5). Bounded — suppression of an
advisory alarm, never a forgery, and the offline verdict is untouched — and
already mitigated by R25's footer line, which this record elevates from advice
to named mitigation (§3 R7). Recorded so the asymmetry is a known property
rather than a surprise, and so nobody later "simplifies" the footer line away.

**(iv) `arbitrum.drpc.org` returned a transient 408** on the first
production-method call, ten days after D55 measured it healthy (§1 f); five
retries were clean. Below any threshold for action, above the threshold for
recording, and precisely the trend datum A44's Arbitrum arm exists to
accumulate.

---

## Registrar's edit set

**This lane wrote one file: this one.** Everything below is instruction.

1. **`TODO.md` decision register, D66 line** (Due M3 block) — replace with the
   resolved line quoted in the lane's closing report.
2. **`docs/decisions/README.md`** — one index row for this record, in id
   order, status/date from this record's own lines (D119 conventions; the row
   rides this record's commit per D119 RULING 6).
3. **`tasks/R.md` R24 `Notes`** — replace the open-decision sentence with §9.1
   below.
4. **`tasks/A.md` A44 `Do`** — insert the esplora arm, §9.2 below, renumbering
   the existing (3) to (4).
5. **`tasks/R.md` R23** — one `Notes` line, §9.3 below (the CSP owner
   question; discovered item (ii)).
6. **No edits** to `MVP-SPEC.md`, the frozen registry, `wording.rs`, any
   endpoint constant's **value**, or any fixture are requested by this ruling.
   The one code-adjacent change is a **doc comment** on
   `DEFAULT_ESPLORA_ENDPOINTS` (`crates/antseal-anchor/src/esplora.rs:77-84`),
   for the implementing lane, not the registrar:

   > Browser note (D66, measured 2026-08-12): both operators return **404** on
   > the `OPTIONS` preflight — there is no `OPTIONS` route, and the body is the
   > generic `endpoint does not exist "…"` — while both carry
   > `Access-Control-Allow-Origin: *` on every GET **and on the 404 arm**. The
   > pair is therefore browser-usable **only for preflight-free requests**: the
   > page (R24) sends `GET` with at most `Accept: text/plain` and no other
   > header. Adding one non-safelisted header breaks online mode on both
   > endpoints at once, invisibly to a curl probe — measured live.

### 9.1 `tasks/R.md` R24 — replace the `Notes` open-decision sentence

> - Notes: CORS ruled 2026-08-12 by **D66**
>   (docs/decisions/D66-browser-endpoint-cors-and-fallback-policy.md): all six
>   pinned endpoints are browser-usable, **conditionally**. esplora has **no
>   `OPTIONS` route** (preflight 404s on both), so the page's esplora fetch is
>   `GET` with at most `Accept: text/plain`, no other header, `credentials:
>   'omit'`, `mode: 'cors'` — one extra header breaks both endpoints at once
>   and a curl probe cannot see it (measured in Chromium against the real
>   `blockstream.info`). Arbitrum's preflight is **mandatory** and works on all
>   four (D55 re-confirmed). A thrown fetch is `ProbeFailureClass::Transport`,
>   never `NoSuchBlock` — D56 O7 needs a 404 body a throw has none of — and the
>   rendered line **may not name CORS or any cause**: the browser returns the
>   identical `TypeError: Failed to fetch` for CORS rejection, preflight
>   failure, connection refused and DNS failure. One endpoint permanently
>   unreachable is `Unavailable` → `NotPromoted{endpoint-failures}` (D64 §6.2),
>   **never** a promotion on the survivor and never a silent third endpoint.
>   Overrides stay (spec line 137) and gain the CLI's A49 rule: `https://` only,
>   exactly two entries, rendered as text and never as markup.
>   **[D64, 2026-08-11]**: the endpoint-override label is the overlay's
>   endpoints-disclosure line from the shared R18 table — the page composes no
>   wording of its own for it.

### 9.2 `tasks/A.md` A44 `Do` — insert as check (3), renumbering roots to (4)

> (3) **esplora pair (D66)**: per entry in `DEFAULT_ESPLORA_ENDPOINTS`, run
> **A16's production request** — both steps, height → hash → header, against a
> committed historical height — and assert `Access-Control-Allow-Origin` is
> present on **each GET** and on the **404 "Block not found" arm** (the D56 O7
> input, which a browser must be able to read). **Record**, without asserting,
> the `OPTIONS` preflight status: both operators 404 it today because they have
> no `OPTIONS` route, so a preflight that starts working is a trend datum, not
> a red, while a GET that loses ACAO is a red. A liveness probe with a cheaper
> request is forbidden here for D55 §2's reason and for D66's: the page's
> viability depends on the exact request, not on the host.

### 9.3 `tasks/R.md` R23 — append a `Notes` line

> - Notes: **[D66, 2026-08-12]** The page has no Content-Security-Policy and
>   the repo has no `connect-src` anywhere. A `default-src 'self'` policy —
>   which is what `blockstream.info` itself serves, and what a static-host
>   deploy invites — makes `connect-src` fall back to `'self'` and kills R24's
>   online mode with the **same opaque `TypeError`** a third-party CORS
>   rejection produces. Who authors the page's CSP (R23, R25's build, or R26's
>   host config) is unowned; D66 §7 supplies the guard test
>   (`page_csp_permits_connect_to_the_pinned_origins`, offline, against the
>   built artifact) but not the policy.

---

## Outcome

The register filed D66 as a compatibility checkbox, and the checkbox has an
answer: today, 2026-08-12, all six pinned endpoints serve
`Access-Control-Allow-Origin` to a browser, and no default changes. What the
framing got wrong is that the answer is not the endpoints'.

Both esplora operators have no `OPTIONS` route at all, so their preflight
404s — which means the pair is reachable **only** by a request that never
triggers one. Measured in a real browser against the real
`blockstream.info`: the fetch succeeds with `Accept: text/plain` and throws
with one extra header. A curl probe reads `ACAO: *` in both cases. So the
cheap probe the lean assumed does not under-describe the answer; on a page
that adds a header it reports the opposite of it — and the header set belongs
to code that has not been written. Meanwhile the Arbitrum half is viable for
the *opposite* reason: its preflight is mandatory and works. One "yes" would
have covered both and warned about neither.

The rest follows from a second measurement. A browser hands JavaScript the
same `TypeError: Failed to fetch`, `cause: undefined`, for a CORS rejection, a
failed preflight, a refused connection and a DNS failure — four causes, one
object, no channel. So the page cannot say why, and this record forbids it
from pretending: the fallback renders "could not be checked" and nothing more.
That opacity also makes the safe direction structural rather than
disciplinary — D56's refutation needs a 404's body, a throw has none, and so
the one outcome that could call an anchor forged is unreachable from the
failing path. It costs something too, and the record says so: a lying endpoint
can silence its own disagreement on the page, and only on the page, with a
header it controls — which is why R25's footer sentence about comparing
verdicts with the CLI is named here as a mitigation instead of left as advice.

The residual is the part the checkbox framing hid entirely. Nothing watches.
The one rot watch that exists probes Arbitrum's POST CORS by name and has no
esplora check of any kind — covering the pair that can never move a verdict
and omitting the pair that is the only route to `proven` and the only route to
`invalid` — and that watch is still an open task. It also cannot ever be a
required gate, because CI is forbidden third-party network and enforces it in
code. So the honest close is that the third-party half of this ruling expires
on someone else's schedule and can only be watched, not gated; while the half
that actually broke under measurement — our own header set, and the
Content-Security-Policy the page does not yet have — is ours, is offline, and
is the thing to put a test around.
