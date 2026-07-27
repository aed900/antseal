# D2 — Repo hosting platform + CI provider

- **Status: RESOLVED**
- **Date: 2026-07-27**

## Context

P4 (remote hosting) and P8 (CI skeleton) needed the platform decision; P13
(cargo-deny advisory lane) and P19 (weekly upstream-bump check) need
scheduled/cron CI lanes on the same platform. The working assumption in
tasks/P.md was GitHub + Actions (`gh` tooling available, Actions cron for
the scheduled lanes).

## Decision

**GitHub for hosting, GitHub Actions for CI.** Implemented: private repo
**`aed900/antseal`** (`origin` = <https://github.com/aed900/antseal.git>),
default branch `main`. The P8 workflow lives at
`.github/workflows/ci.yml`.

## Evidence

- Working assumption confirmed by implementation on 2026-07-27 (P4 initial
  commits pushed; repo exists as private).
- Research memo (13:46:26Z): `GET api.github.com/repos/aed900/antseal`
  → 404 unauthenticated and `users/aed900` → 404 — consistent with a
  **private** repo/account, which unauthenticated API calls cannot see.
- Actions supports `schedule:` cron triggers, satisfying P13's weekly
  advisory run and P19's weekly upstream-bump check.

## Consequences

- P4 done (remote configured, pushed through the P7 commit). P8 done
  locally; **remote CI verification is currently blocked**: pushes
  containing `.github/workflows/` are rejected because the available OAuth
  tokens lack the `workflow` scope — status, unblock procedure, and the
  pending P8 acceptance steps live in
  [`docs/ci-verification.md`](../ci-verification.md).
- P13/P19 scheduled lanes will be Actions `schedule:` jobs added alongside
  the existing named jobs (extension points documented in `ci.yml`).
- The repo being private is compatible with all pre-M0 work; making it
  public is a release-era (M4) step and interacts with D1 (repo/org rename
  follows the final name; GitHub renames leave redirects).
