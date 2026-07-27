# D1 — Product name

- **Status: OPEN (provisional)**
- **Date: 2026-07-27** (provisional state recorded; final resolution due by M0 start)

## Context

The spec's working name is `antseal` (MVP-SPEC.md line 3), used for the CLI
binary, the `antseal-*` crate prefix, the vault dir, and — permanently, once
M0 freezes — the signature context string `"antseal-manifest-v1"`. The
`ant-` prefix reads as official Autonomi tooling (upstream's binaries are
`ant`/`antnode`), so P1 requires either upstream's written blessing or a
non-ant rename, decided before P2/P3 execute and before the M0 Definitions
freeze.

## Decision (provisional state + deadline policy)

1. **The working name stays `antseal`.** No reservation (crates.io publish,
   domain registration) executes until this decision is final.
2. **Upstream written blessing is still required** for the `ant-` prefix.
   The request is drafted at
   [`docs/naming/upstream-blessing-request.md`](../naming/upstream-blessing-request.md)
   and is **to be filed by the maintainer (user)** at
   <https://github.com/WithAutonomi/ant-client/issues> — Discussions are
   disabled on that repo, so an issue is the on-platform channel. Upstream's
   reply gets archived in `docs/naming/` per P1 acceptance.
3. **Deadline policy:** if upstream has not replied by **M0 start**, the
   project unilaterally falls back to **`sealstone`** (research-verified
   fully free: crates.io `sealstone` + `sealstone-core`, domains
   sealstone.org/.dev; a proper trademark search is still due at fallback
   execution). Silence is treated as "not blessed".
4. **Sensitivity:** keep name deliberations out of public channels until
   reservations execute. (The public blessing-request text deliberately does
   not name the fallback candidate.) Motivating signal: `sealproof.dev` was
   registered 2026-07-26 — the day before the availability research — a mild
   squat signal showing availability decays.

## Evidence (research memo, 2026-07-27)

- **crates.io** (retrieved 13:44:34Z–13:44:39Z): all five names FREE (HTTP
  404): `antseal`, `antseal-core`, `antseal-anchor`, `antseal-net`,
  `antseal-cli`. `seal-core`/`seal-cli` confirmed TAKEN by an unrelated
  event-sourcing/SCM project (user `bobisme`, newest 0.27.1, 2026-04-25) —
  the spec's stated reason for the `antseal-*` prefix holds.
- **GitHub** (13:46:24Z–13:46:26Z): user `antseal` 404, org `antseal` 404 —
  both free (404 caveat: could also mean suspended/hidden).
- **Domains** (rdap.org, 13:46:06Z–13:46:11Z): antseal.org/.net/.io/.dev/.app
  all 404 (likely unregistered). **antseal.com REGISTERED since 2004-07-07**
  (Register.com/Network Solutions, expires 2027-07-07) — a long-standing
  unrelated party, permanently unavailable for practical purposes,
  **non-blocking** (canonical verifier URL lives on another TLD; see D-P3
  plan).
- **Upstream channel** (13:45:44Z): ant-core's repository resolves to org
  `WithAutonomi`, repo `ant-client` — active, `has_issues: true`,
  `has_discussions: false`.
- **Fallback screen** (13:46:42Z–13:51:25Z): `sealstone`/`sealstone-core`
  free on crates.io; sealstone.org 404 free; sealstone.dev 404 free (after
  transport flakes, clean RDAP 404 at 13:51:25Z). Ranked above `waxseal`
  (also fully free) and `sealproof` (crates + .org free, but .dev registered
  2026-07-26 — squat-adjacent). `permaseal`/`everseal` were dropped:
  collision with real-world sealant brands.

## Consequences

- **P2 (crates reservation) and P3 (domain registration) are blocked on
  D1-final.** Both have execution-ready preparation:
  `docs/naming/P2-crates-reservation-runbook.md` + `scripts/reserve-crates.sh`,
  and `docs/naming/P3-domain-registration.md`.
- **C12 — signature context string** `"antseal-manifest-v1"` embeds the name
  and is **frozen permanently at M0** (MVP-SPEC.md line 97). D1-final must
  precede the M0 Definitions freeze; a post-M0 rename cannot touch it.
- **F4 — format identifier strings**: any F-minted format/domain string that
  embeds the product name must take the final name before M0 freeze. (The
  spec's HKDF labels and hash domain tags are NOT name-bearing — verified;
  see `docs/naming/propagation-checklist.md`.)
- **U1 — CLI binary name + vault dir** (`antseal`, `~/.antseal/`) take the
  final name.
- Full identifier-by-identifier propagation map with owning domains and
  freeze points: [`docs/naming/propagation-checklist.md`](../naming/propagation-checklist.md).
- On fallback: `sealstone` re-runs the availability checks + trademark
  search, and the whole checklist propagates `sealstone` instead; the
  `.sealproof` bundle extension stays regardless (not ant-coupled).
