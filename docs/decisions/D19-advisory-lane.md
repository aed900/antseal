# D19 — RUSTSEC advisory lane: cargo-deny vs cargo-audit

- **Status: RESOLVED**
- **Date: 2026-07-27**

## Context

P13 stands up the permanent RUSTSEC advisory tracking lane (spec lines 97,
183: "pin exact, track RUSTSEC"), operated forever as Q10. The open decision
(D19) is which tool backs it: `cargo-audit`, `cargo-deny`, or both.

## Decision

**cargo-deny only.**

- Both tools consume the same RUSTSEC advisory database; running both adds
  no advisory coverage.
- P13's required config shape — an advisories section, a bans section
  (duplicate-version awareness), a sources section (crates.io only), and a
  licenses section stubbed until the Q29 license decision — is exactly
  cargo-deny's `deny.toml`. cargo-audit has no bans/sources/licenses
  checking at all.
- One tool = one pinned version (P7), one config file, one CI lane
  (per-PR + weekly schedule).

Known allowlist requirements for the licenses section when Q29 activates it
(recorded now so they are not rediscovered): `minicbor` is
**BlueOak-1.0.0** licensed; ant-core's graph carries two GPL-3.0 crates
(`self_encryption`, `evmlib` — see D6). The licenses section ships stubbed
(commented baseline) with a pointer to D6/Q29.

## Amendment (2026-07-27, from the C11 probe)

The C11 advisory assessment found that of the three ml-dsa advisories,
**only one carries a RUSTSEC ID** — the other two exist only as
GHSA/osv.dev entries (GHSA-5x2r-hc65-25f9, GHSA-h37v-hp6w-2pp8). A
RUSTSEC-DB-only lane would have missed both, including the
verification-malleability one squarely in our threat class. Consequence:
cargo-deny remains the lane's tool, but **P13/Q10's weekly operation MUST
additionally sweep GHSA/osv.dev for the pinned crypto crates** (documented
in the lane runbook; a scripted osv.dev API query over the exact-pin list
is the recommended mechanism).

## Consequences

- P13 commits `deny.toml` (advisories/bans/sources active; licenses
  stubbed) + a pinned cargo-deny in CI, per-PR and weekly scheduled.
- Ignored/accepted advisories (starting with the two Jan-2026 `ml-dsa`
  advisories, per P12's assessment) each carry a written justification and
  a review date in the config.
- Q10 operates this lane permanently; Q29 completes the licenses section.
