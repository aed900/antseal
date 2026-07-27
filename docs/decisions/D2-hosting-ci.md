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

## Amendment (2026-07-27, late) — relocated to `aed900/antseal`

The maintainer directed that the project has no association with the
`aed900` account. Actions taken before any history was published:

- New private repo **`aed900/antseal`** created; `origin` repointed to
  `https://github.com/aed900/antseal.git`. Everything above referring to
  `aed900/antseal` is historical evidence of the original decision,
  retained verbatim.
- **Full commit-identity rewrite** executed pre-first-push: all commits'
  author and committer set to `aed900
  <129773515+aed900@users.noreply.github.com>` (noreply chosen so GitHub
  attribution cannot fall back to any email-to-account mapping). Content
  trees verified byte-identical; commit hashes changed — no external
  references existed yet.
- Repo-local `git config` user.name/user.email set to the same identity
  for all future commits.
- The old `aed900/antseal` repo (content ends pre-M0-wave-1) is
  **deprecated; its deletion is a maintainer action on the aed900
  account** (needs that account's auth + `delete_repo` scope, or the web
  UI). Nothing references it any more.
- The push blocker is unchanged in kind but now applies to the **aed900**
  token: `gh auth refresh -h github.com -s workflow` must be completed for
  aed900 before `git push origin main` succeeds.
