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
  work).
- Registering **antseal.dev** too is cheap, closes the closest-lookalike
  hole, and inherits TLD-level HSTS preload; it 301-redirects to the .org
  canonical URL.

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

## Registration record (fill at execution)

- Date registered: _(pending)_
- Domains: _(pending — expected antseal.org, antseal.dev)_
- Registrar + account identifier: _(pending)_
- Auto-renew: _(pending — must be ON, both)_
- Transfer lock: _(pending)_
- 2FA method + backup-code location: _(pending)_
- Renewal dates / term: _(pending)_
- Custody (who holds access): _(pending)_
- Handed to R (R26/D62): _(pending)_
