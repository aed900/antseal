# P3 — Verifier-domain registration plan

> **EXECUTION BLOCKED** on two things:
> 1. **D1-final** — the product name is still provisional
>    ([`docs/decisions/D1-product-name.md`](../decisions/D1-product-name.md));
>    registering `antseal.*` before the name is final wastes the fee at
>    best and leaks the deliberation at worst.
> 2. **Registrar account + payment** — registration is a maintainer (user)
>    action with their own registrar account and payment method; nothing
>    here can or should be automated.

The registered domain is the substrate for the **one canonical URL** of the
static verifier page (MVP-SPEC.md line 139) — a long-lived trust point
(malicious-host mitigation). The canonical-URL string itself and page
hosting/deploy are **R's M3 work**; P3 only secures the ground under it.

## Availability evidence (research memo, rdap.org, retrieved 2026-07-27T13:46:06Z–13:46:11Z)

| domain | RDAP HTTP | verdict |
| --- | --- | --- |
| antseal.com | 200 | **REGISTERED** since 2004-07-07 (registrar "Register.com - Network Solutions, LLC", expires 2027-07-07, last changed 2026-06-07) — long-standing unrelated party, **not** squatting on this project; permanently unavailable in practice; **non-blocking** |
| antseal.org | 404 | likely unregistered |
| antseal.net | 404 | likely unregistered |
| antseal.io | 404 | likely unregistered |
| antseal.dev | 404 | likely unregistered |
| antseal.app | 404 | likely unregistered |

Re-verify at execution: `curl -sSL https://rdap.org/domain/<domain>` (404 =
likely free, 200 = registered) — availability decays (the memo caught
`sealproof.dev` registered the day before research).

## Recommendation

**Primary: `antseal.org`. Defensive second: `antseal.dev`.**

Rationale (memo recommendation (b)):

- The canonical URL is a **permanence trust point** for a permanence
  product — **.org** (Public Interest Registry) has the strongest
  neutral/institutional connotation and decades of registry stability.
- **.io is disqualified** for a permanence product: ccTLD with genuine
  long-term political/registry uncertainty (post-Chagos).
- **.com is taken** (2004, unrelated party) — a mild brand-confusion point,
  mitigated by never printing anything but the canonical URL in docs/CLI.
- .net reads dated; .app skews mobile.
- **HSTS note**: the runner-up argument for .dev/.app is that both TLDs are
  HSTS-preloaded (browsers refuse plaintext HTTP — a real anti-SSL-strip
  property for a verifier page). Mitigation on .org, adopted as a
  requirement here: **serve HSTS with `preload` from day one** on
  antseal.org and submit it to the browser preload list (R's M3 deploy
  work). — **Superseded 2026-08-12 by [D62](../decisions/D62-verifier-page-host-and-canonical-url.md) §3 R4**; see the block below.
- Registering **antseal.dev** too is cheap, closes the closest-lookalike
  hole, and inherits TLD-level HSTS preload; it 301-redirects to the .org
  canonical URL. — **Superseded 2026-08-12 by [D62](../decisions/D62-verifier-page-host-and-canonical-url.md) §3 R5**; see the block below.

**[D62, 2026-08-12 — superseded]** The *"serve HSTS with `preload` from day
one"* requirement adopted above (and repeated in the R handoff) is
**retired**: the chosen host emits no configurable headers at all (measured
on two GitHub Pages custom domains with Enforce-HTTPS on), so the requirement
is undeliverable on `antseal.org`. Replaced by Enforce HTTPS (plaintext
`301`s) plus an optional CAA record — which addresses mis-issuance, the
stronger attack on a trust point, and which HSTS never addressed. The
**`antseal.dev` recommendation is also retired**: 8 near-neighbours are free
and `antseal.com` is unobtainable, so defensive registration is provably
incomplete, and the planned `.dev → .org` redirect would have created the
second working URL spec line 139 forbids. See
docs/decisions/D62-verifier-page-host-and-canonical-url.md §3 R4/R5.
**Registration record, from RDAP 2026-08-12T00:41Z**: registrar **Porkbun**
(IANA 1861); registered **2026-08-11T12:38:53Z**; expires
**2027-08-11** — a **one-year** term, against step 3's *"multi-year (2+
years)"*; transfer lock **ON** (`client transfer prohibited`), update lock
**off**. **Auto-renew, 2FA method, backup-code location and custody remain
unfilled and are unobservable from outside** — they are the fields that
matter and the acceptance above is not met until they are recorded.

## Registration steps (maintainer, at D1-final)

1. Re-verify availability (RDAP command above) for antseal.org +
   antseal.dev. If the natural domain is gone → **P1 forced re-decision**
   (P3 accept).
2. Choose a registrar under maintainer control. Selection criteria: strong
   account 2FA (TOTP/passkey, not SMS), domain transfer lock, WHOIS
   privacy, reliable auto-renew, multi-year terms. (.dev requires a
   Google-Registry-accredited registrar; most majors qualify.)
3. Register **antseal.org** (primary) and **antseal.dev** (defensive) —
   multi-year (2+ years) to push the first renewal event out past release.
4. Immediately: **auto-renew ON** for both; transfer lock ON; registrant
   email = a maintainer-controlled address that outlives any single inbox;
   payment method with expiry alerting.
5. **Custody documentation (P3 acceptance):** record in this file's
   registration record below — registrar name, account identifier (never
   the password), 2FA method + backup-code storage location, renewal dates,
   who holds access. Losing the domain later is a **provenance incident**
   (spec line 139/186); renewal ownership must be unambiguous.
6. DNS: park with the registrar until M3; no hosting decisions here.

## Handoff to R (M3 canonical URL — R26/D62)

On completion, hand R the registration record below. R's M3 deliverables
built on it: the one canonical URL string (printed by `antseal reveal`,
used in all docs), page hosting/deploy, reproducible-build hash publication,
HSTS-with-preload from day one (+ preload-list submission), and the
antseal.dev → antseal.org redirect. Until M3, nothing may print or embed
any URL on these domains.

**[D62, 2026-08-12]** Of that handoff list: the canonical URL string is ruled
(`https://antseal.org/`, constant in `antseal-cli`, R26-owned and printed by
U28); hosting/deploy is GitHub Pages from the private `aed900/antseal` via a
manually-triggered Actions workflow; hash publication is D63's. The last two
items are **retired** — HSTS-with-preload is undeliverable on the ruled host
(§3 R4) and the `.dev` redirect would have minted a second working URL (§3 R5).
The embargo's condition is **met**: the phase is M3, and the constant lands with
U28 ahead of the deploy, with Q31's release checklist — not a delay — as the
gate that covers the window in between.

## Registration record (fill at execution)

Four fields below are filled from **RDAP, 2026-08-12T00:41Z** (observable from
outside, no credentials); the rest are unobservable from here and are the ones
that decide whether the domain survives a renewal event — this acceptance is
**not met** until they are recorded (D62 §9.4).

- Date registered: **2026-08-11T12:38:53Z** _(RDAP)_
- Domains: **antseal.org** only — **antseal.dev is ruled unnecessary**, D62 §3 R5 (2026-08-12)
- Registrar + account identifier: **Porkbun LLC** (IANA handle 1861) _(RDAP)_; account identifier _(pending)_
- Auto-renew: _(pending — must be ON; the maintainer's stated next step, not yet done)_
- Transfer lock: **ON** — `client transfer prohibited` _(RDAP)_; `client update prohibited` is **not** set
- 2FA method + backup-code location: _(pending)_
- Renewal dates / term: expires **2027-08-11** — a **one-year** term, against step 3's *"multi-year (2+ years) to push the first renewal event out past release"*; extending it is a stated maintainer next step, not yet done _(RDAP)_
- Custody (who holds access): _(pending)_
- Handed to R (R26/D62): **2026-08-12 — D62 ruled the host and the canonical URL on this registration.** DNS state, as of that date: the two Porkbun **parking A records** (`207.207.210.107`, `207.207.210.229`) are still live and still answer `http://antseal.org/` — measured `200` with a parked page at 00:42:46Z and `502 Bad Gateway` from `openresty` at 00:58:47Z, with `https://` failing the TLS handshake at both. The maintainer will remove them so the name **fails closed** (D62 §3 R7); **Pages DNS records and any CAA record are deliberately deferred to R26**, so certificate issuance is verified end to end rather than pre-staged. None of this is done.
