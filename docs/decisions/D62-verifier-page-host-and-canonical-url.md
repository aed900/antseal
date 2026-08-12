# D62 — Verifier-page host, the one canonical URL, and what R26's scripted check actually checks

- **Status: RESOLVED — the canonical URL is exactly `https://antseal.org/`
  (apex, `https`, trailing slash, no `www`, no subdomain, no path), served by
  **GitHub Pages** from the existing private `aed900/antseal` repo via an
  Actions publishing source; `antseal.dev` is **not** registered and **not**
  needed; the URL constant's home is `antseal-cli` and it lands **now**, ahead
  of the deploy; **R26's scripted check hashes the DECODED body**, never the
  transferred bytes; and every security property the page relies on must live
  **inside the hashed artifact**, never in host configuration.** The
  register's lean — *a straightforward vendor pick whose only content is the
  vendor name* — is **OVERTURNED on four independent measurements**: (1) the
  vendor is not open, it is **forced** by D2 — GitHub already holds the
  source, the CI that builds the artifact and the release channel that
  publishes its hash, so every other host **adds a party** to the exact threat
  spec line 186 names, and none removes one; (2) "point antseal.org at it" is
  not a no-op — the domain **today** answers `200 OK` over **plaintext HTTP**
  with a third party's **scripted** parking page and has **no working HTTPS at
  all**, while the CLI begins printing that URL at **U28, in this wave**;
  (3) the TLD and host decisions are **not independent**, because P3 adopted
  *"serve HSTS with `preload` from day one"* as the explicit compensation for
  choosing `.org` over `.dev`, and the ruled host **structurally cannot emit
  that header** (measured on two Pages sites with Enforce-HTTPS on) — so a
  real choice existed and is made here, not inherited; (4) the Accept the lean
  treats as trivially satisfiable is **ill-defined as written** — one Pages
  resource yields **two different served-byte hashes** depending on
  `Accept-Encoding` and exactly **one** decoded hash. What survives of the
  lean, stated honestly: **the host choice moves spec line 186's residual
  essentially not at all**, and this record says so rather than dressing a
  convenience as a mitigation.
- **Date: 2026-08-12** (wave 18 Act 1, D62 planning lane; briefed to overturn
  the vendor-pick framing. All live measurements taken 2026-08-12T00:41Z–01:0xZ
  and reproduced in §1 with their commands.)
- **Owning tasks: R26** (owns the constant and the deploy), **U28** (prints
  it — `tasks/U.md:480`, `:485`), **P3** (supplies the name; its acceptance
  record is still unfilled — §9), **Q22/Q28** (docs carry it; Q28 audits
  value-identity, `tasks/Q.md:481`), **R25/D63** (the artifact set this check
  runs over), **R23** (the in-artifact policy §3 R6 pushes into the page).
- **Amends**: `tasks/R.md` R26 `Do` and `Accept` (two clauses are
  unexecutable/unsatisfiable as written — §7.4, §7.5), the `tasks/R.md:673`
  open-decisions row (wrong consumers — §1 k). **Supersedes**: the
  HSTS-with-preload requirement adopted at `docs/naming/P3-domain-registration.md:46-51`
  and repeated at `:82`, and the `antseal.dev` recommendation at `:34`/`:52-54`
  (§3 R4, §3 R5). **Corrects**: `docs/waves/wave-18-brief.md:13`'s consumer
  list, and `TODO.md:64` maintainer-action item 5's stated cause (§1 j).

---

## 1. What was measured

Every probe below is read-only. Nothing was registered, configured, deployed,
or authenticated.

**(a) `antseal.org` is registered, on a ONE-year term, with transfer lock on
and update lock off.**

```
$ curl -sSL https://rdap.org/domain/antseal.org           # 2026-08-12T00:41Z
ldhName:  antseal.org
status:   ['client delete prohibited', 'client transfer prohibited', 'add period']
event:    registration 2026-08-11T12:38:53.156Z
event:    expiration   2027-08-11T12:38:53.156Z
ns:       maceio/curitiba/salvador/fortaleza .ns.porkbun.com
entity:   roles ['registrar'] handle 1861          # Porkbun LLC
```

The fact the brief supplied is confirmed, and three things it did not:
the term is **one year**, against P3 step 3's *"multi-year (2+ years) to push
the first renewal event out past release"*
(`docs/naming/P3-domain-registration.md:66`); `client transfer prohibited` is
present (P3 step 4's transfer lock — satisfied) but `client update prohibited`
is **not**; and the domain is inside its 5-day `add period`.

**(b) `antseal.dev` is still unregistered.** `rdap.org/domain/antseal.dev` →
`404`. Confirmed, same session.

**(c) The canonical URL today serves a stranger's scripted page over
plaintext, and has no HTTPS at all.** *(Re-measured 16 minutes later —
`502 Bad Gateway`; see "Amendment — the canonical URL re-measured, and the host
confirmed, 2026-08-12" below. The observation here stands; what it shows is not
a fixed quantity.)*

```
$ curl -sSI https://antseal.org/
curl: (35) OpenSSL/3.0.20: error:0A000410:SSL routines::sslv3 alert handshake failure   # rc=35

$ curl -sSI http://antseal.org/
HTTP/1.1 200 OK
Server: openresty
Date: Wed, 12 Aug 2026 00:42:46 GMT
X-Powered-By: PHP/8.0.25
Set-Cookie: AWSALB=…; AWSALBCORS=…
X-Service: pixie-default

$ curl -sS http://antseal.org/ | grep -o -m1 '<title>[^<]*</title>'
<title>porkbun.com | parked domain</title>          # 2109 bytes, 5 script/iframe occurrences
```

DNS: `A 207.207.210.107, 207.207.210.229`; `www` is a CNAME to
`pixie.porkbun.com`; **no AAAA**; **no CAA**; no TXT. So the name that is about
to become a trust point currently: answers `200` on a channel with no
confidentiality or integrity, from a party that is not the maintainer, with
script tags in the body, setting load-balancer cookies on the future origin,
and is reachable by no IPv6 client. *(rc read from an unpiped `curl`, per the
standing rule — a piped `$?` would have reported `head`.)*

**(d) GitHub Pages emits no HSTS — and no security header of any kind — even
with Enforce-HTTPS on.** Two Pages custom domains that *do* enforce HTTPS,
against a non-Pages control:

| host | `http://` | `server` | `strict-transport-security` | `cache-control` |
| --- | --- | --- | --- | --- |
| `cli.github.com` (Pages) | `301` → https | `GitHub.com` | **absent** | `max-age=600` |
| `bundler.io` (Pages) | `301` → https | `GitHub.com` | **absent** | `max-age=600` |
| `sass-lang.com` (Netlify, control) | `301` → https | `Netlify` | **`max-age=31536000`** | `public,max-age=0,must-revalidate` |

A full header grep over a Pages response for
`strict|content-security|x-frame|x-content-type|referrer|permissions` returns
**nothing**. This is a platform property, not a misconfiguration: GitHub's own
`cli.github.com` does not get one either. `cache-control: max-age=600` is
likewise fixed and not configurable.

**(e) The served-bytes / decoded-bytes distinction is real, measurable, and
decides R26's Accept.** One Pages resource, three fetches:

```
$ curl -H 'Accept-Encoding: identity' https://jekyllrb.com/
  content-length: 10393   etag: "6a3960e0-2899"   sha256(body) = 88649f79f3b5…46b3

$ curl -H 'Accept-Encoding: gzip, br' https://jekyllrb.com/
  content-length: 3449    etag: W/"6a3960e0-2899"  content-encoding: gzip
                                                    sha256(body) = 64a9a27312bc…d2be

$ curl --compressed https://jekyllrb.com/
  sha256(decoded body) = 88649f79f3b5…46b3
```

**Two transferred hashes, one decoded hash.** "Served bytes hash-match the
published SHA-256SUMS" (`tasks/R.md:323`) is therefore not a predicate until
this record picks a side. Corroborating detail: the strong ETag's size half is
`0x2899` = **10393** = the identity `content-length`, i.e. the origin serves
the stored file's exact length — evidence that Pages' origin does not rewrite
the body, and that the *only* transformation in play is the content-coding.

**(f) GitHub Pages serves `.wasm` correctly.**

```
$ curl -sSI https://webassembly.github.io/wabt/demo/libwabt.wasm
HTTP/2 200 · server: GitHub.com · content-type: application/wasm
```

So `WebAssembly.instantiateStreaming` is available and R23 needs no
arrayBuffer fallback for MIME reasons.

**(g) Pages supports the apex, with IPv6.** GitHub's custom-domain doc gives
four A records (`185.199.108-111.153`) and four AAAA
(`2606:50c0:800{0,1,2,3}::153`), and states of Enforce HTTPS: *"It can take up
to 24 hours before this option is available."* The apex is therefore usable and
the current AAAA gap closes as a side effect of the deploy.

**(h) Pages on a **private** repo requires GitHub Pro or above — and the
account is on Pro.** GitHub's plan doc: *"GitHub Pages is available in public
repositories with GitHub Free … and in public and private repositories with
GitHub Pro, GitHub Team, GitHub Enterprise Cloud, and GitHub Enterprise
Server."* The repo is private (D2). The upgrade is recorded in this project's
own tree: `docs/ci-verification.md:1978` — *"The maintainer upgraded the
account to Pro"* — corroborated at `:2264` (*"dispatched normally in under a
minute on the Pro plan"*). So Pages is available **without** making the repo
public, which matters because going public triggers **Q65** first
(`TODO.md:262`) and is an M4-era step by D2's own Consequences.

**(i) A Pages site published from a private repo is a PUBLIC site.** Private
Pages requires an organization on Enterprise Cloud. Deploying the page
publishes the page and nothing else about the repo — which is exactly the
wanted shape, and is stated here so nobody assumes the site inherits the
repo's privacy.

**(j) `TODO.md:64` item 5's stated cause is stale, and it reads as a
Pages blocker.** It says branch protection *"remains ⛔ BLOCKED BY PLAN (403 on
a private repo on **GitHub Free**)"* — while **item 4 of the same line** says
*"The account is on Pro"*, and `docs/ci-verification.md:1978` records the
upgrade. The 403 was real (`:1177`, verbatim API body: *"Upgrade to GitHub Pro
or make this repository public to enable this feature."*) and its cause is
gone. A reader taking item 5 at face value would conclude Pages is
plan-blocked. It is not.

**(k) The register's own consumer list for this decision is wrong, twice,
and R16's row refutes it in its own text.** `tasks/R.md:673` says the URL
constant is *"consumed by R16/R25"*; `docs/waves/wave-18-brief.md:13` says
*"the constant R16/U28/Q consume"*. But R16's `Do` ends
(`tasks/R.md:198`):

> The canonical verifier-page URL constant is owned by R26 and printed by U28.

— and R16's own opening clause is *"this task ships no CLI surface"*. R25's
`Do`/`Accept` (`tasks/R.md:310-314`) never mention the URL; its subject is the
build, the SHA-256SUMS and the footer. The actual consumers are **U28** (the
only Rust consumer), **Q22/Q28** (docs), with **R26** owning the definition.

**(l) The tree carries ZERO verifier-URL literals — there is no shipped
placeholder.**

```
$ rg -e 'antseal\.(org|dev|net|io|app|com)' -e 'https?://[a-z0-9.-]*antseal' \
     crates/ scripts/ verifier-web/ testdata/ .github/ Cargo.toml
$ echo $?
1                      # zero matches
```

Every `antseal.org` / `antseal.dev` occurrence in the tree is prose in `docs/`
or `TODO.md` *about* this decision. `verifier-web/index.html` is a 16-line
placeholder with **no URL, no external reference, and no CSP meta**. So R26's
grep test starts from a clean slate and this ruling lands before any code — the
branch where a shipped placeholder would have constrained the value does not
exist.

**(m) Defensive registration cannot be completed, and the dominant confusion
path is already lost.** RDAP, same session:

| name | RDAP | state |
| --- | --- | --- |
| `antseal.com` | 200 | **TAKEN** — third party since 2004-07-07 (`P3-domain-registration.md:21`); today `HTTP/1.1 502 Bad Gateway`, `nginx/1.14.2`, no HTTPS |
| `antseal.net`, `antseal.io`, `antseal.app`, `antseal.page`, `antseal.xyz`, `antseal.info`, `ant-seal.org`, `antsea1.org` | 404 | **all free** |

Eight near-neighbours stand open right now, and the single highest-probability
mistyping of a `.org` — the `.com` — is unobtainable at any price and currently
serves a 502. Registering `antseal.dev` would close hole 7 of ≥9 while hole 1
stands open permanently.

**(n) `.dev` is genuinely HSTS-preloaded, and P3's own plan would have made it
a second working URL.** `hstspreload.org/api/v2/status?domain=dev` →
`"status": "preloaded"`. The TLD property is real. But P3's plan was to *use*
the name: *"antseal.dev → antseal.org redirect"*
(`docs/naming/P3-domain-registration.md:83`, `:53-54`). **A redirect that works
is a URL that works** — the defensive registration was going to mint the second
canonical URL that spec line 139's *"one canonical URL"* and R26/Q28's grep
exist to prevent.

**(o) Spec line 3's pre-M0 obligation was met; the registration timing is not
a divergence.** Line 3's pre-M0 task is *"check the verifier domain"* — done
2026-07-27 (`P3-domain-registration.md:17-26`) and re-verified at D1-final
(`TODO.md:1031`). Registration is not what line 3 asked for pre-M0. Recorded so
this is not re-raised.

**(p) Nothing in the wire format carries a URL.** A grep for
`http|\.org|\.dev|url` across `docs/format/registry-v1.md` returns **nothing**;
the bundle top-level key table (§7.6) has no such slot and §9's named-reserved
list (key 10 `range_reveals`, receipt key 3 `chain_inputs`, `sig_alg` 2–15)
contains none. **The canonical URL enters no `.sealproof` byte, ever.** Its
freeze-weight is therefore *documentary*, not format-permanent — a correction
to the "provenance incident" framing at `docs/naming/propagation-checklist.md:28`
in one direction (no frozen bytes move if it changes) and a confirmation in the
other (what breaks is people's memory and printed advice, which no version bump
can repair).

---

## 2. The lean, and why it is overturned

The register files D62 as *"pick a static host, point antseal.org at it"*,
content = the vendor name. Four measurements refuse it, and a fifth thing the
framing gets backwards.

**2.1 The vendor is not open — D2 already picked it, and every alternative
makes the named threat worse.** Spec line 186's risk is *"Malicious verifier
host"*. D2 put the source, the CI that produces the reproducible artifact, and
(via Q31) the release channel that publishes its SHA-256 **inside GitHub**. A
host that is not GitHub does not replace that trust; it **adds to it** — the
page's bytes would then be alterable by GitHub *or* by the new host, and a
GitHub compromise still poisons the artifact upstream of any host. Choosing
Netlify/Cloudflare/Vercel buys header configurability at the price of a second
party with standing capability to serve lying JS to the very page whose threat
model is exactly that. **Party count is the metric, and GitHub Pages is the
only option that adds zero.** The "vendor beauty contest" the lean imagines is
the wrong frame: the question is not *whom do we trust* but *do not add a
second one*.

**2.2 "Point antseal.org at it" describes an act that has a live hazard
window, and the window opens this wave.** §1 (c): the URL answers `200` on
plaintext with a stranger's scripted page and has no HTTPS. U28 — *"Print the
closing lines: bundle path + the canonical verifier page URL"*
(`tasks/U.md:480`) — is in **wave 18's Act 2 queue**; R26 is queued behind
R25 in **wave 19** (`docs/waves/wave-18-brief.md:31`). So between U28 and R26
the product prints a URL that resolves to somebody else's page. The lean's
framing contains no such object as a sequencing hazard; §3 R7 rules it, and
§7.6 gives the maintainer the one-line action that closes it today.

**2.3 The TLD and host decisions are entangled, and P3 spent the HSTS argument
in advance.** `docs/naming/P3-domain-registration.md:46-51` chose `.org` over
`.dev` and paid for it with an **adopted requirement**:

> **HSTS note**: the runner-up argument for .dev/.app is that both TLDs are
> HSTS-preloaded … Mitigation on .org, adopted as a requirement here:
> **serve HSTS with `preload` from day one** on antseal.org and submit it to
> the browser preload list (R's M3 deploy work).

§1 (d) measures that the ruled host cannot do it — not now, not with Enforce
HTTPS on, not on GitHub's own Pages sites. So the compensation P3 promised is
undeliverable, and D62 inherits a genuine three-way choice the lean does not
contain: drop the requirement, move the TLD, or add a proxy. §3 R4 makes it.

**2.4 The Accept is not a predicate yet.** §1 (e): two transferred hashes, one
decoded hash, same resource, same second. `tasks/R.md:323`'s *"served bytes
hash-match"* is satisfiable or unsatisfiable depending on a request header
nobody has ruled. §3 R3 rules it, and turns the ambiguity into a **tripwire**.

**2.5 What survives, and the direction the framing had backwards.** The lean's
implicit claim — *this choice mitigates the malicious-host risk* — is the part
to refuse most plainly: **it does not**. §8 states the residual without
softening. But the lean is *right* that the durable content is small — it is
just wrong about which part is durable. The **vendor** is the least durable
thing here (swappable behind DNS in an afternoon, no format bytes, §1 p); the
**URL's exact spelling**, the **host-conformance contract**, and the **rule
that policy lives in the hashed bytes** are what must not move.

---

## 3. The ruling

**R1 — The canonical URL is exactly `https://antseal.org/`.**
One byte string, apex, `https`, **trailing slash**, no `www`, no subdomain, no
path segment. Reasons, each measured or structural:

- **Apex, not a subdomain.** `verify.antseal.org` adds a DNS record that can be
  repointed independently of the name people remember, adds typing surface to a
  string a counterparty may transcribe from a terminal, and creates a live
  `antseal.org` that must then either serve the page too (two working URLs) or
  fail (a broken shortest form). `www.antseal.org` is the same objection plus a
  measured one: it currently CNAMEs to Porkbun's parking host (§1 c).
- **No path.** A trailing segment (`/verify/`, `/v/`) is droppable; a dropped
  path lands on the apex, which must then serve *something* — either the page
  (two working URLs) or a 404 (the shortest, most-guessed form of the project's
  own name is broken). The apex-only form has no drop.
- **Trailing slash.** It is what a browser normalizes an apex navigation to, so
  the CLI's printed string is character-identical to what the reader sees in
  the URL bar, and Q28's *"exactly one canonical URL value"* has exactly one
  spelling to find. (`https://antseal.org` and `https://antseal.org/` denote
  the same resource; the constant fixes the spelling the project emits, and
  §3 R8's checker enforces it in-tree.)
- **The URL names the project, never the host.** No `github.io` form is
  admissible even transitionally: a vendor-bearing URL welds D62's least
  durable component into the one string that must never change. This is what
  keeps the host swappable and keeps this record cheap to revisit.

**R2 — The host is GitHub Pages, from `aed900/antseal`, published by GitHub
Actions.**

- **Available**: private-repo Pages needs Pro; the account is on Pro (§1 h).
  No repo visibility change, so **Q65 is not triggered** and D2's M4-era
  going-public step is untouched.
- **Chosen on party count, not features** (§2.1). It adds no trust party that
  D2 has not already added.
- **Publishing source = GitHub Actions**, not a branch. R25's reproducible
  build must be the thing that produces the deployed bytes; a branch source
  invites a hand-copied artifact between the build that was hashed and the
  bytes that are served. The deploy workflow is **manually triggered**
  (`workflow_dispatch`) — R26 is an external, consent-gated act, and CI minutes
  are a stated wave constraint (`docs/waves/wave-18-brief.md:65`).
- **Enforce HTTPS ON**, so `http://antseal.org/…` `301`s and never `200`s
  (measured achievable — §1 d). Provisioning may take up to 24 h (§1 g); the
  deploy is not complete until it succeeds.
- **The site is public though the repo is private** (§1 i) — intended, stated.

**R3 — R26's scripted check hashes the DECODED body, and runs both encodings
as a transform tripwire.** The check, per published artifact:

1. Fetch over `https://antseal.org/…`; require a valid TLS chain.
2. **Hash the decoded representation** — content-codings removed. Rationale, on
   §1 (e): the decoded body is the *only* stable quantity (compression
   algorithm and level are host/CDN choices that change without notice, so a
   transferred-byte hash makes R26 flake for reasons that have nothing to do
   with page integrity), **and it is exactly the byte sequence the browser
   parses and instantiates** — which is what the threat model is about. A
   transferred-byte hash would answer a question no adversary asks.
3. **Run the fetch twice** — `Accept-Encoding: identity` and
   `Accept-Encoding: gzip, br` — and require **both decoded hashes to be equal
   to each other and to the published sum**. This is the transform detector: it
   catches a proxy that rewrites only the compressed path or only the
   uncompressed one, for the cost of one extra request. It exists because §1 (e)
   showed the two paths are genuinely different objects.
4. **Set equality both ways**: every SHA-256SUMS entry resolves `200`, and no
   artifact is served under the page's own paths that is absent from
   SHA-256SUMS. A one-way check cannot see an injected extra file.
5. **Content-Type assertion** per artifact (`text/html`, `application/wasm`,
   `application/javascript`) — a wrong `.wasm` type is a silent page break, and
   §1 (f) makes the expectation concrete.
6. **`http://` must `301`, never `200`.**
7. **Cache rule — mandatory, not optional.** Pages sends a fixed
   `cache-control: max-age=600` (§1 d) and R26's `Do` cannot change it (§7.4).
   The check therefore sends `Cache-Control: no-cache`, records each response's
   `age:` header in its evidence, and on mismatch **re-polls with backoff over
   a window strictly greater than 600 s before reporting red**. A mismatch
   inside the window is `INCONCLUSIVE`, not `FAIL`. Without this, R26's own
   Accept flakes on every redeploy and the project learns to ignore it.

**R4 — The HSTS-with-preload requirement is REPLACED, and the replacement is
named.** P3's adopted requirement (§2.3) is undeliverable on the ruled host and
is retired here rather than left to rot as an unmet promise. What replaces it:

- **Kept**: Enforce HTTPS on, so the plaintext form `301`s (R2).
- **Lost, sized honestly**: the header, and with it preload eligibility. The
  residual is a first-visit downgrade by an on-path attacker against a browser
  that does not already upgrade navigations. Real; small and shrinking; **not
  zero**.
- **Added, and stronger than what was lost — a CAA record.** §1 (c) measured
  `antseal.org has no CAA record`, i.e. *any* CA may currently mint a
  certificate for the project's trust point. HSTS stops a downgrade; **CAA
  stops a mis-issuance**, which is the stronger attack on a name whose whole
  job is to be the one place a counterparty goes. It costs one DNS record, is
  entirely in the maintainer's hands, and survives a host change. It carries a
  real operational hazard — pinning the wrong CA breaks Pages' automatic
  renewal — so it is a **maintainer question** (§9), never a silent mandate.
- **Refused: fronting the site with a TLS-terminating proxy to obtain the
  header.** It would add exactly the party §2.1 exists to avoid, and the
  cheapest such proxy ships **HTML-rewriting features on by default** (email
  obfuscation, script rewriting) that R3's byte-equality check would then have
  to fight. Trading a first-visit downgrade for a standing lying-JS capability
  is the wrong direction on the one risk spec line 186 names.

**R5 — `antseal.dev` is NOT registered and NOT needed. P3's defensive
recommendation is retired.** Refused on measurement, not on cost:

- **Defensive registration here is provably incomplete** (§1 m): eight
  near-neighbours are free today, and the dominant one — `antseal.com`, the
  habitual mistyping of any `.org` — has been third-party-held since 2004 and
  is unobtainable. Buying one of ≥9 open holes while the largest stands open
  forever is not a mitigation; it is the appearance of one.
- **The plan for it contradicted the spec sentence it served** (§1 n): a
  working `.dev → .org` redirect *is* a second working URL, against line 139's
  *"one canonical URL"* and against the grep R26/Q28 run.
- **It would not have delivered the HSTS property to the canonical URL
  anyway** — TLD preload attaches to the name being visited; a redirect *from*
  `.dev` protects the redirect hop, not `antseal.org`.
- **Residual, accepted and recorded**: an attacker can register `antseal.dev`
  for ~$12 and serve a lying verifier. The mitigations are the ones that
  already exist and do not scale with the number of TLDs: docs and CLI print
  exactly one URL (R8), a lookalike cannot produce the published SHA-256, and
  **a counterparty needs no page at all** — `antseal verify` on the bundle they
  already hold is the spec's own advice line and reaches the same verdict
  offline.

**R6 — Policy lives inside the hashed artifact, never in host configuration.**
This is the ruling's general rule, and it is *forced* by §1 (d): the ruled host
sends no configurable header at all. What follows is not a workaround but the
better shape:

- Host configuration is **unhashed, unversioned, unsigned, and absent from
  every offline copy**. R25 publishes a SHA-256 over the artifact; a header is
  outside it. A counterparty who saves the page, receives it on a USB stick, or
  re-hosts it keeps every property expressed in the bytes and loses every
  property expressed in the config.
- Therefore the page's Content-Security-Policy is a
  `<meta http-equiv="Content-Security-Policy">` **inside `index.html`**, which
  makes it part of what R25 hashes and R3 checks, and makes R23's Accept
  (*"No external resources fetched in offline mode"*) **structurally enforced**
  rather than merely tested.
- Two riders for R23, recorded here so they are not rediscovered:
  `frame-ancestors`, `sandbox` and `report-uri` **cannot** be delivered by
  meta, so clickjacking of the verifier page is a residual the ruled host
  cannot close (a framed page can be overlaid); and WebAssembly instantiation
  under a CSP requires `'wasm-unsafe-eval'` in `script-src` on current
  Chromium — **R23 must verify the directive set against real browsers**, this
  record asserts it as a constraint to check, not as a measured fact.
- The **directive set and the artifact set are D63's and R23's**, not ruled
  here (§5).

**R7 — The constant lands NOW, before the deploy; the exposure window is
closed by a maintainer action, not by delaying the constant.**

- **Permitted.** P3's embargo is *"Until M3, nothing may print or embed any URL
  on these domains"* (`docs/naming/P3-domain-registration.md:83-84`) and the
  phase **is** M3 (`docs/waves/wave-18-brief.md:3`). The name is registered to
  the maintainer with transfer lock on (§1 a), so no third party can take it
  out from under the constant. Delaying would instead block U28 — a wave-18
  row — on R26, a wave-19 external act.
- **The rider that actually binds**: no release tag may exist while R26 is
  unchecked. Q31's release checklist already gates publication on *"the
  deployed page's hash matching the published one"* (`tasks/Q.md:512`); this
  record adds nothing new, it names the existing gate as the one that covers
  the window.
- **The window is closed today, cheaply**: the maintainer removes the parking
  A records so `https://antseal.org/` **fails to connect** rather than serving
  a stranger's scripted page over plaintext (§1 c). *Failing closed on a name
  that is about to become a trust point beats serving somebody else's page from
  it.* One registrar action, no cost, immediately reversible by the deploy
  itself.
- **R27/Q19 must not fetch the canonical URL.** R27 serves the page from a
  local static server by its own design (`tasks/R.md:333`); nothing in the test
  suite may acquire a dependency on the live host, or the M3 gate starts
  failing for network reasons. R26's scripted check is the **only** thing that
  touches `https://antseal.org/`, and it is a deploy-time check, not a CI lane.

**R8 — The constant's home is `antseal-cli`; the docs half is enforced by a
checker, not by the type system.**

- **Home**: `crates/antseal-cli/src/brand.rs`,
  `pub const VERIFIER_URL: &str = "https://antseal.org/";` — its own small
  module rather than hidden inside U28's renderer, because unlike D67's
  `SNIPPET_UNAVAILABLE` (`crates/antseal-cli/src/preview.rs:130`) this constant
  has **three** surfaces (CLI output, docs, page) and a grep for the concept
  must land in one obvious place.
- **Not `antseal-core`**, explicitly and for the record: core is the
  verification library the page itself links through WASM and that third
  parties may link. A deployment fact does not belong in a WASM-safe crypto
  crate; a URL change must not be a core version bump; and the page must never
  render its own address out of the library that produces its verdicts (§8's
  self-attestation point). U28 is the only Rust consumer, measured — R16
  disclaims it in its own `Do` (§1 k).
- **The docs half cannot import a Rust `const`.** `tasks/R.md:321`'s *"single
  shared constant consumed by U (reveal output) and Q (docs)"* is achievable
  for U and impossible for Q as literally stated; markdown gets **value
  identity enforced by a check**, which is what Q28 already asks for.
- **The check's predicate** — fixing `tasks/R.md:325`'s
  *"no other verifier URL literal in the repo"*, which is **unsatisfiable as
  written** because spec line 139 requires the URL *"used in all docs"*:
  1. **Exactly one Rust definition** of the value exists.
  2. **Every occurrence anywhere in the tree is byte-equal to it** — this is
     Q28's already-correct formulation (`tasks/Q.md:481`, *"Exactly one
     canonical URL value found by grep across all surfaces"*).
  3. The scan is **anchored on the pattern, not on the string**:
     `antseal\.[a-z]+` and any `https?://` bearing the product name, so a stray
     `www.antseal.org`, `antseal.dev` or `http://` form is *caught* rather than
     merely *not matched*.
  4. A **named allow-list** for prose that legitimately discusses other names:
     this record, `docs/naming/P3-domain-registration.md`,
     `docs/decisions/D1-product-name.md`, and the wave briefs. Without it the
     checker reddens on exactly the documents that justify the choice — the
     D123 lesson (a literal entry is read as itself) applied to a second scan.
  5. **Home**: a mode of `scripts/check-traceability.py`, which already owns
     tree-wide literal scanning; naming the file is R26/Q28's call, the
     predicate is this record's.

---

## 4. Refused shapes

| shape | refused on |
| --- | --- |
| any non-GitHub host (Netlify / Cloudflare Pages / Vercel / S3+CDN) | adds a party to the exact threat spec line 186 names, and removes none — D2 already put source, CI and release channel inside GitHub (§2.1) |
| Cloudflare (or any proxy) in front of Pages to obtain HSTS | same party-count objection, plus default HTML-rewriting features that R3's byte-equality check would have to fight; trades a first-visit downgrade for a standing lying-JS capability (§3 R4) |
| a `*.github.io` URL, even transitionally | welds the vendor — this decision's least durable component — into the one string that must never change (§3 R1) |
| `verify.antseal.org` / any subdomain | independently repointable, more transcription surface, and forces the apex to serve a second page or a 404 (§3 R1) |
| `www.antseal.org` | second name for one resource; measured today as a CNAME to the registrar's parking host (§1 c) |
| any path segment (`/verify/`, `/v/`) | droppable — the drop must then serve the page (two working URLs) or 404 on the shortest guess of the project's own name (§3 R1) |
| registering `antseal.dev` (canonical or defensive) | 8 near-neighbours free and `.com` unobtainable → provably incomplete; and P3's redirect plan would mint the second working URL line 139 forbids (§1 m, §1 n, §3 R5) |
| hashing the transferred body in R26's check | one resource, two transferred hashes, same second — the quantity is host-variable and is not what the browser executes (§1 e, §3 R3) |
| a single-encoding fetch in R26's check | cannot see a proxy that rewrites only one of the two paths; the second fetch costs one request (§3 R3) |
| failing R26 on the first hash mismatch | Pages' fixed `max-age=600` guarantees a post-redeploy stale window; a check that flakes is a check that gets ignored (§3 R3) |
| putting `VERIFIER_URL` in `antseal-core` | deployment fact in a WASM-safe crypto crate; URL change becomes a core version bump; invites the page to render its own address from the verifier (§3 R8) |
| expressing CSP/HSTS/security policy in host configuration | unhashed, unversioned, and absent from every offline copy of the page — the host cannot send headers at all (§3 R6) |
| withholding the constant until R26 deploys | blocks a wave-18 row on a wave-19 external act; M3 has begun and the name is locked to the maintainer; the real gate is the release checklist (§3 R7) |
| letting R27/Q19 fetch the canonical URL | acquires a live-network dependency for the M3 gate; R27 serves the page locally by design (§3 R7) |
| `tasks/R.md:325` as literally written ("no other verifier URL literal") | unsatisfiable — spec line 139 requires the URL in all docs; Q28 already has the right predicate (§3 R8) |

---

## 5. Edges with adjacent decisions, drawn explicitly

- **D62 / D63.** D62 rules *where the bytes are served, at what name, and what
  the served-bytes check means*. **D63 owns the artifact set** the SHA-256
  covers and the footer-hash mechanism. Two constraints D62 hands D63, both
  measured: (i) the check in §3 R3 is **file-count agnostic** but requires **set
  equality both ways**, so D63's artifact set must be exactly enumerable;
  (ii) §3 R6 means any policy the page depends on must be *inside* an artifact
  D63's sum covers, which makes the HTML's meta-CSP hash-covered by
  construction. A single-file page (WASM inlined) would additionally make
  `file://` use and counterparty re-hosting trivial and reduce §3 R3 to one
  hash — **that is D63's call and is not made here**, only handed over.
- **D62 / D2.** D2 chose GitHub for hosting and CI; D62 does not re-open it,
  it *derives* from it (§2.1). D62 explicitly does **not** move D2's
  "making it public is a release-era (M4) step" — §1 (h) is why it need not.
- **D62 / P3.** P3 secures the name; D62 spends it. This record supersedes two
  P3 recommendations (§3 R4, R5) and reports P3's own acceptance record as
  unfilled (§9). It does **not** re-open the TLD: `.org` stays, for P3's
  registry-stability reason, now that the HSTS argument that would have moved
  it is retired on measurement.
- **D62 / R18.** R18 owns wording. Any sentence the page or CLI prints *about*
  the URL is R18's; D62 rules only the value and its identity. One constraint
  handed over (§8): the page may state the canonical URL as provenance beside
  the build hash, but never as an **authenticity claim** — a lying copy copies
  the claim verbatim, so "this is the official page" is a string that
  authenticates nothing and misleads by construction.
- **D62 / Q28.** Q28's `tasks/Q.md:481` predicate is the correct one and D62
  adopts it verbatim; Q28's `Do` also lists the **page footer** as a URL
  surface, which spec line 139 does not (it says *"used in all docs and printed
  by the CLI in `reveal` output"*). Harmless under value-identity — noted so it
  is not read as a spec citation.

---

## 6. Consumed rows and inputs

- **`MVP-SPEC.md`** lines **3** (pre-M0 domain check — met, §1 o), **123**
  (format stability — untouched, §1 p), **125–139** (verifier page; **139** is
  the canonical-URL and page-provenance sentence), **186** (malicious verifier
  host), **156** (M3 lists the deploy).
- **`tasks/R.md`** R23 (`:284-290`), R25 (`:305-314`), **R26** (`:316-326`),
  R27 (`:333`), R16 `Do` (`:198`), open-decisions row (`:673`).
- **`tasks/U.md`** U28 (`:480`, `:485`), and `:694`'s R-interface line.
- **`tasks/Q.md`** Q22 (`:415`), Q28 (`:473-481`), Q31 (`:512`).
- **`tasks/P.md`** P3 (`:36`, `:41`); `docs/naming/P3-domain-registration.md`
  (`:17-26`, `:34`, `:46-54`, `:63-66`, `:77-84`, `:86-96`);
  `docs/naming/propagation-checklist.md:28`.
- **`docs/decisions/D2-hosting-ci.md`** (hosting + CI + the amendment's
  single-account rule); **D1** (name, domain evidence); **D34** via R16's Notes
  (crate placement precedent); **D67 §R8** (constant-placement precedent);
  **D123** (literal-scan roots; the allow-list lesson in §3 R8).
- **`docs/ci-verification.md`** `:1177`, `:1184`, `:1189`, `:1978`, `:2264`.
- **`docs/format/registry-v1.md`** §7.6 and §9 — cited by section, **no
  registry change requested** (§1 p).
- **External, read-only, 2026-08-12**: rdap.org (9 domains), `antseal.org`
  DNS/HTTP, `cli.github.com`, `bundler.io`, `jekyllrb.com`,
  `webassembly.github.io`, `sass-lang.com` (control), `hstspreload.org`,
  GitHub Pages documentation (plans, custom domains).

---

## 7. What R26 must implement, and the two clauses of its own row that must change

1. **Deploy** the R25 artifact set to GitHub Pages from `aed900/antseal` via a
   manually-triggered Actions publishing workflow; custom domain
   `antseal.org`; **Enforce HTTPS on**; apex A + AAAA records per §1 (g),
   replacing the parking records.
2. **Define** `VERIFIER_URL` per §3 R8 and land the checker with its
   allow-list.
3. **Run the scripted check** exactly per §3 R3 (decoded body; both encodings;
   set equality both ways; `Content-Type`; `http`→`301`; the cache-window
   re-poll rule), and commit its evidence — including each response's `age:` —
   the way anchor evidence is committed.
4. **`Do` amendment — `tasks/R.md:321`'s *"configure … cache headers sane for a
   hash-published artifact"* is UNEXECUTABLE on the ruled host.** Pages sends a
   fixed `cache-control: max-age=600` with no configuration surface (§1 d). The
   clause becomes: *record* the host's cache behaviour and make the check
   tolerate it (§3 R3 rule 7). This is a task-prose correction, not a
   deliverable being dropped.
5. **`Accept` amendment — `tasks/R.md:323` and `:325` are both under-specified
   as written.** `:323`'s *"served bytes"* → **decoded body, both encodings**
   (§3 R3). `:325`'s *"no other verifier URL literal in the repo"* →
   **exactly one value, everywhere, with a named allow-list** (§3 R8), which is
   Q28's existing formulation.
6. **Maintainer prerequisite, today, independent of the deploy**: remove the
   parking A records so the URL fails closed instead of serving a third party's
   scripted page over plaintext (§3 R7).

---

## 8. Residual risk — stated without softening

- **The host choice does not move spec line 186's residual.** Whoever holds the
  deploy credential can serve lying JS on any host, GitHub Pages included. What
  this ruling buys is *not adding a second party* (§2.1) and *making the
  integrity check meaningful* (§3 R3). It buys nothing against a compromised
  GitHub or a compromised maintainer account, and the record does not pretend
  otherwise.
- **The published hash lives in the same trust domain as the page.** R25's
  SHA-256SUMS is published through GitHub (Q31), the page is served by GitHub,
  the source is on GitHub. So the hash check catches **host misconfiguration,
  CDN transforms, partial deploys and accidental drift** — it does **not**
  catch a GitHub compromise, because the same party would sign both halves. The
  genuinely independent checks are (i) verification is offline and
  deterministic, so any two independently-obtained copies must agree on every
  R9 vector, and (ii) the spec's own advice line: *"for high-stakes
  verification, run `antseal verify` and compare verdicts"*. §10 (i) describes
  the one cheap move that would break the shared-domain dependency.
- **No HSTS, therefore a first-visit downgrade window** on browsers that do not
  upgrade navigations by default (§3 R4). Small, real, and now the *only* piece
  of P3's adopted requirement that is simply gone.
- **Clickjacking is not closable on this host** — `frame-ancestors` needs a
  header (§3 R6). A framed verifier page can be overlaid.
- **Lookalike domains are open and unbounded** — 8 measured free right now, and
  the `.com` permanently lost (§1 m). This is accepted, not mitigated.
- **A one-year registration term** with unverified auto-renew (§1 a): the
  first renewal event lands 2027-08-11, inside the project's life, on a name
  whose loss is a provenance incident. This is the highest-probability failure
  mode in this record and it is not a technical one.
- **Self-attestation is worthless and must not be written as if it were**
  (§5, R18 edge): a page saying "this is the official antseal verifier" is
  copied verbatim by the page that is lying.

---

## 9. What could NOT be verified without maintainer credentials

Stated as gaps, not guesses:

1. **Whether `aed900`'s plan is currently Pro.** The evidence is this repo's
   own narrative (`docs/ci-verification.md:1978`, corroborated `:2264`); no
   billing endpoint was queried. §3 R2 depends on it. — **Answered
   2026-08-12** (maintainer, in session: Pages on the private `aed900/antseal`
   confirmed, account on Pro); see the Amendment below.
2. **Whether Pages is enabled, or enable-able, on `aed900/antseal`**
   (`gh api repos/aed900/antseal/pages` needs the token).
3. **Whether GitHub's certificate provisioning succeeds for `antseal.org`** —
   unknowable until the DNS records change (§1 g's 24-hour note).
4. **The registrar account's custody state.** P3's own acceptance record
   (`docs/naming/P3-domain-registration.md:86-96`) has **all nine fields still
   `_(pending)_`** — date, registrar, account identifier, auto-renew, transfer
   lock, 2FA method and backup-code location, renewal term, custody, handoff —
   while the domain is registered. RDAP supplies four of them from outside
   (registrar = Porkbun, registered 2026-08-11, expires 2027-08-11, transfer
   lock on). **Auto-renew, 2FA and custody are unobservable from here and are
   the ones that matter.**
5. **Whether branch protection now works post-Pro** — the 403's stated cause is
   gone (§1 j) but nothing has re-measured it. Out of D62's scope; it is why
   §1 (j) is reported as an instrument finding rather than ruled.

---

## 10. Discovered work — described, not registered

No ids are minted here.

**(i) The project can seal its own verifier page, and that is the one move
that breaks §8's shared-trust-domain dependency.** antseal already owns
independent anchoring — OTS submission and upgrade (A13/A14) and TSA tokens,
exercised for real on 2026-08-11 (`testdata/anchors/A25-wave17-cycle/`). Anchoring
the **SHA-256SUMS file itself** yields a commitment to the page's hash that
GitHub cannot retroactively forge, published through Bitcoin and a TSA rather
than through the party that serves the page. A second, near-free out-of-band
publication point exists in the same breath: a **DNS TXT record on
`antseal.org`**, controlled by the registrar — a different party from GitHub.
Zero new cryptography, existing commands, and the product would be its own
first customer. Natural owners: **D63** (what the sum covers) and **Q31**
(release pipeline). Described, not registered.

**(ii) `tasks/R.md:673`'s consumer list is wrong and the wave brief inherited
it.** Measured against R16's own `Do` (§1 k). Doc-prose only — §12's entry
notes supersede it in practice. Ledger material.

**(iii) `TODO.md:64` item 5's stated cause is stale and reads as a Pages
blocker.** §1 (j): the same line says "on Pro" four clauses earlier, and
`docs/ci-verification.md:1978` records the upgrade. Ledger material; the
branch-protection *status* is unmeasured (§9.5) and this record does not rule
it.

**(iv) P3's registration record is empty while the domain is registered, and
the term is one year.** §1 (a), §9.4. This is not a code defect and not an
instrument defect — it is an **unfinished acceptance criterion on P3**
(`docs/naming/P3-domain-registration.md:70-74` makes custody documentation the
acceptance) on the item this record most depends on. The registrar decides
whether it becomes a row or a P3 note; the lane reports it.

**(v) `verifier-web/index.html` carries no CSP meta.** Correct today — it is a
16-line placeholder with no script (§1 l) — and recorded only so R23 lands
§3 R6's meta-CSP with the page rather than after it, when adding it would move
a hashed artifact.

---

## 11. Registrar's edit set

**This lane wrote one file: this one.** Everything below is instruction.

1. `TODO.md` decision register, D62 line (Due M3 block, `:908`) → the resolved
   line quoted in the lane's closing report; D70's line (`:916`) is the model.
2. `docs/decisions/README.md` → one index row for this record, in id order,
   status/date taken from this record's own `- **Status`/`- **Date` lines
   (D119 conventions).
3. `tasks/R.md` R26 (`:316-326`) → the `Do` and `Accept` amendments in §12.1,
   plus the `Notes` line in §12.2.
4. `tasks/R.md:673` open-decisions row → resolution pointer with the corrected
   consumer list (§12.3).
5. `tasks/U.md` U28 (`:480-485`) → the `Notes` line in §12.4.
6. `tasks/Q.md` Q28 → optional one-liner (§12.5); Q28 needs no behavioural
   change, its predicate is already the ruled one.
7. `docs/naming/P3-domain-registration.md` → superseded-recommendation notes
   (§12.6) for the HSTS requirement and the `.dev` recommendation, and the
   registration record's four RDAP-observable fields. **`TODO.md:80`'s P3 row**
   → `.dev` is ruled unnecessary.
8. `docs/instrument-ledger.md` → §10 (ii) and §10 (iii); §10 (iv) is the
   registrar's call between a row and a P3 note.
9. **No edits** to `MVP-SPEC.md`, `docs/format/registry-v1.md`, any code, any
   fixture, or any golden vector are requested by this ruling. **Zero frozen
   bytes.**

---

## 12. Quoted entry notes (registrar's to apply)

### 12.1 `tasks/R.md` R26 — `Do` and `Accept`

> - Do: Deploy the reproducible-build artifacts to **GitHub Pages** from
>   `aed900/antseal` via a manually-triggered Actions publishing workflow, at
>   the one canonical URL **`https://antseal.org/`** (apex, trailing slash);
>   Enforce HTTPS on; apex A + AAAA records per D62 §1 (g). **The host sends no
>   configurable headers** — record its cache behaviour (`max-age=600`, fixed)
>   rather than configuring it, and put every policy the page relies on
>   **inside the hashed artifact** (D62 §3 R6). Record the deploy procedure so
>   releases redeploy deterministically. Export the canonical URL as a single
>   Rust constant (`antseal-cli`, D62 §3 R8) consumed by U28, and enforce
>   value-identity across docs and page by checker, not by import.
> - Accept:
>   - Canonical URL serves the page; the **decoded** body of every published
>     artifact hash-matches the published SHA-256SUMS, fetched **twice**
>     (`Accept-Encoding: identity` and `gzip, br`) with both decoded hashes
>     equal; set equality both ways over SHA-256SUMS; `Content-Type` asserted
>     per artifact; `http://` `301`s and never `200`s; a mismatch inside the
>     host's 600 s cache window is INCONCLUSIVE and re-polled, not red
>     (D62 §3 R3)
>   - Drag-and-drop verification of a real bundle succeeds against the hosted page
>   - **Exactly one canonical URL value** exists across all surfaces — one Rust
>     definition, every other occurrence byte-equal, pattern-anchored scan with
>     a named allow-list for the records that discuss other names (D62 §3 R8;
>     Q28's `tasks/Q.md:481` predicate)

### 12.2 `tasks/R.md` R26 — `Notes`

> - Notes: **[D62, 2026-08-12]** Host + URL ruled
>   (docs/decisions/D62-verifier-page-host-and-canonical-url.md):
>   `https://antseal.org/` on **GitHub Pages** — chosen because D2 already put
>   source, CI and release channel inside GitHub, so every other host **adds** a
>   party to spec line 186's threat and none removes one; Pages on the private
>   repo needs Pro and the account is on Pro (docs/ci-verification.md:1978), so
>   **no visibility change and Q65 is not triggered**. The host emits no
>   security headers at all (measured on `cli.github.com`/`bundler.io` with
>   Enforce-HTTPS on), so **P3's HSTS-with-preload requirement is retired and
>   replaced** by Enforce HTTPS + an optional CAA record (maintainer question —
>   a wrong CA pin breaks renewal). `antseal.dev` is **not needed**: 8
>   near-neighbours are free and `.com` is unobtainable, and P3's `.dev → .org`
>   redirect would have minted the second working URL line 139 forbids. **The
>   host choice does not move line 186's residual** and the published hash sits
>   in the same trust domain as the page — say so in the docs. Pre-deploy
>   maintainer action: **remove the parking A records** so the URL fails closed
>   instead of serving a third party's scripted page over plaintext (measured
>   2026-08-12T00:42Z).

### 12.3 `tasks/R.md:673` open-decisions row — replace

> - Verifier-page host + domain (one canonical URL) — **[2026-08-12] RESOLVED
>   (D62)**: `https://antseal.org/` on GitHub Pages from the private repo
>   (Pro-enabled), constant in `antseal-cli`, decoded-body hash check with a
>   two-encoding tripwire, `.dev` refused
>   (docs/decisions/D62-verifier-page-host-and-canonical-url.md). **Consumer
>   list corrected**: the constant is owned by **R26** and consumed by **U28**
>   (the only Rust consumer) and **Q22/Q28** (docs) — *not* by R16, which
>   disclaims it in its own `Do` (`tasks/R.md:198`), and *not* by R25, whose
>   subject is the build, the SHA-256SUMS and the footer.

### 12.4 `tasks/U.md` U28 — append a `Notes` line

> - Notes: **[D62, 2026-08-12]** The URL U28 prints is
>   `antseal_cli::brand::VERIFIER_URL` = **`https://antseal.org/`** — exact
>   spelling including the trailing slash, no `www`, no subdomain, no path
>   (docs/decisions/D62-verifier-page-host-and-canonical-url.md §3 R1/R8). The
>   constant **lands with U28, ahead of R26's deploy** (M3 has begun; the name
>   is registered to the maintainer with transfer lock on), and the gate that
>   covers the gap is the existing release checklist (Q31), not a delay here.
>   Until R26 deploys, the URL does not serve the page — **no test may fetch
>   it**, and U28's own fixtures assert the printed string, never a live
>   response.

### 12.5 `tasks/Q.md` Q28 — optional one-liner

> - Notes: **[D62, 2026-08-12]** This row's *"exactly one canonical URL value"*
>   Accept is the **ruled** predicate and D62 adopts it verbatim over R26's
>   looser *"no other verifier URL literal"* phrasing. The value is
>   `https://antseal.org/`; the scan is pattern-anchored (`antseal\.[a-z]+`
>   plus any product-name-bearing `https?://`) with a named allow-list for the
>   records that legitimately discuss other names (D62 §3 R8).

### 12.6 `docs/naming/P3-domain-registration.md` — superseded notes

> **[D62, 2026-08-12 — superseded]** The *"serve HSTS with `preload` from day
> one"* requirement adopted above (and repeated in the R handoff) is
> **retired**: the chosen host emits no configurable headers at all (measured
> on two GitHub Pages custom domains with Enforce-HTTPS on), so the requirement
> is undeliverable on `antseal.org`. Replaced by Enforce HTTPS (plaintext
> `301`s) plus an optional CAA record — which addresses mis-issuance, the
> stronger attack on a trust point, and which HSTS never addressed. The
> **`antseal.dev` recommendation is also retired**: 8 near-neighbours are free
> and `antseal.com` is unobtainable, so defensive registration is provably
> incomplete, and the planned `.dev → .org` redirect would have created the
> second working URL spec line 139 forbids. See
> docs/decisions/D62-verifier-page-host-and-canonical-url.md §3 R4/R5.
> **Registration record, from RDAP 2026-08-12T00:41Z**: registrar **Porkbun**
> (IANA 1861); registered **2026-08-11T12:38:53Z**; expires
> **2027-08-11** — a **one-year** term, against step 3's *"multi-year (2+
> years)"*; transfer lock **ON** (`client transfer prohibited`), update lock
> **off**. **Auto-renew, 2FA method, backup-code location and custody remain
> unfilled and are unobservable from outside** — they are the fields that
> matter and the acceptance above is not met until they are recorded.

---

## Outcome

The register filed D62 as a vendor pick, and the vendor turned out to be the
one thing that was never open: D2 settled it on 2026-07-27 by putting the
source, the CI that builds the artifact and the channel that publishes its hash
inside one trust boundary, and every alternative the market offers would have
*added* a party to the single risk spec line 186 names. What the framing hid is
everything else. The domain that is about to become a trust point answers
`200` today, over plaintext, with a stranger's scripted page and no HTTPS at
all — and the CLI starts printing that address **this wave**. The TLD choice
had already been paid for with an HSTS promise the chosen host structurally
cannot keep, which means `.org`-versus-`.dev` was still live and had to be
settled rather than assumed. The Accept that looked like arithmetic —
*served bytes hash-match* — turned out to name two different quantities, and a
single `Accept-Encoding` header decides which. And the host's inability to send
any header at all, which reads at first as the ruling's weakest point, is the
thing that produced its best rule: **policy belongs inside the hashed bytes**,
because only the hashed bytes are published, versioned, checked, and carried by
every offline copy of a page whose whole design is that it need not be online
at all. The defensive `.dev` registration dies on a count — eight neighbours
free, the `.com` lost since 2004 — and on the observation that P3 meant to
*use* it, which would have made it a second canonical URL. What the ruling
honestly does not do is move the malicious-host residual: the page's bytes and
the hash that attests them are published by the same party, and the only real
defences remain that verification is offline, deterministic, and reproducible
by a binary the counterparty already holds. The one move that would change
that is the one the product is already built to make — anchor the page's own
hash with the project's own timestamps — and it is described here for D63
rather than smuggled into a hosting decision.

---

## Amendment — the canonical URL re-measured, and the host confirmed, 2026-08-12

**Authority**: the wave-18 registrar, in session 2026-08-12, folding one further
measurement and one maintainer answer into this record at registration time.
**Same-act disclosure (D117 §2.1 (c))**: this section lands in the same act as
the record it amends, so it is *not* a diff against a published record and must
not be read as one. It **adds** no ruling — §3 R1–R8 stand unchanged — and
D117 §2.2's "a correction may not contain a new ruling" is respected.

### 1. A second observation of the canonical URL, 16 minutes after §1 (c)'s

The sentence this concerns, quoted verbatim from §1 (c):

> **(c) The canonical URL today serves a stranger's scripted page over
> plaintext, and has no HTTPS at all.**

with its measurement at `Date: Wed, 12 Aug 2026 00:42:46 GMT` — `HTTP/1.1 200
OK`, `Server: openresty`, `porkbun.com | parked domain`. **That measurement
stands**: it was true at 00:42:46Z and nothing here contradicts it. Re-probed
by the registrar at **2026-08-12T00:58:47Z**:

```
$ curl -sSI http://antseal.org/                     # 2026-08-12T00:58:47Z
HTTP/1.1 502 Bad Gateway
Server: openresty
Set-Cookie: AWSALB=…; AWSALBCORS=…

$ curl -sSI https://antseal.org/
curl: (35) OpenSSL/3.0.20: error:0A000410:SSL routines::sslv3 alert handshake failure

$ dig +short antseal.org A
207.207.210.107
207.207.210.229
```

Same A records, same operator, `https://` still failing the handshake — and a
**different answer** on the plaintext port sixteen minutes later.

**This sharpens the finding rather than weakening it, and the record should say
so.** §1 (c) is sometimes readable as *"the URL currently serves a parked
page"*, which invites the reply *"a parked page is harmless"*. The pair of
observations says something stronger and less comfortable: **what the canonical
URL serves is not a fixed quantity at all.** A third party's unstable endpoint
answers there, over a channel with no confidentiality or integrity, and its
response class changed inside one hour without anyone touching the domain. A
name that is about to become a trust point is currently a variable controlled
by someone else. §3 R7's maintainer action — remove the parking A records so the
name **fails closed** — is the ruling this strengthens, and §8's
*"lookalike/host residuals are accepted, not mitigated"* is unchanged.

### 2. The host is confirmed: §9's gap 1 closes, gap 2 narrows

§9 lists as its first gap:

> 1. **Whether `aed900`'s plan is currently Pro.** The evidence is this repo's
>    own narrative (`docs/ci-verification.md:1978`, corroborated `:2264`); no
>    billing endpoint was queried. §3 R2 depends on it.

**Answered by the maintainer in session, 2026-08-12**: GitHub Pages on the
private `aed900/antseal` is confirmed as the host, and **the account is on
Pro**. So §3 R2's availability premise no longer rests on this repository's own
narrative about itself, and the derived consequences hold as written — **no
repository-visibility change, Q65 not triggered, D2's M4-era going-public step
untouched**. §9's gap 2 (*whether Pages is enabled or enable-able on the repo*)
narrows to the mechanical step and remains for R26 to execute and record; gaps
3–5 are untouched.

**Which rulings stand**: every one. Both facts run in the direction that
strengthens the ruling — the URL's live behaviour is worse than §1 (c) alone
suggests, which raises the value of failing closed; and the host's availability
is now confirmed rather than inferred, which removes the one premise §3 R2
depended on that this lane could not measure.
