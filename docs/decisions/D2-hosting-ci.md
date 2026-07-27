# D2 — Repo hosting platform + CI provider

- **Status: RESOLVED** (amended 2026-07-27 — see below)
- **Date: 2026-07-27**

## Context

P4 needs a remote hosting platform and P8 (plus P13/P19) needs
scheduled/cron CI lanes on the same platform. The working assumption in
tasks/P.md was GitHub + Actions (`gh` tooling available, Actions cron for
the scheduled lanes).

## Decision

**GitHub for hosting, GitHub Actions for CI.** Implemented: private repo
**`aed900/antseal`** (`origin` = <https://github.com/aed900/antseal.git>),
default branch `main`. The P8 workflow lives at
`.github/workflows/ci.yml`.

## Evidence

- Working assumption confirmed by implementation on 2026-07-27 (private
  repo created under the maintainer account; the full local history awaits
  the first push — see the amendment and
  [`docs/ci-verification.md`](../ci-verification.md)).
- Research memo (13:46:26Z): unauthenticated `GET`s of the then-current
  repo and owner API endpoints returned 404 — consistent with a
  **private** repo, which unauthenticated API calls cannot see.
- Actions supports `schedule:` cron triggers, satisfying P13's weekly
  advisory run and P19's weekly upstream-bump check.

## Consequences

- P4 done (remote configured). P8 done locally; **remote CI verification
  is currently blocked**: pushes containing `.github/workflows/` are
  rejected because the available OAuth token lacks the `workflow` scope —
  status, unblock procedure, and the pending P8 acceptance steps live in
  [`docs/ci-verification.md`](../ci-verification.md).
- P13/P19 scheduled lanes will be Actions `schedule:` jobs added alongside
  the existing named jobs (extension points documented in `ci.yml`).
- The repo being private is compatible with all pre-M0 work; making it
  public is a release-era (M4) step and interacts with D1 (repo/org rename
  follows the final name; GitHub renames leave redirects).

## Amendment (2026-07-27, late) — hosting consolidated under `aed900`

The maintainer directed that the project be associated **solely** with the
maintainer account `aed900`, with no references to any other account or
personal email anywhere in the project, its history, or its metadata.
Actions taken before any history was published to the current remote:

- Private repo **`aed900/antseal`** created; `origin` points at
  `https://github.com/aed900/antseal.git`. A short-lived earlier hosting
  location under a different stored credential was retired; nothing in the
  project references it, and its removal is a maintainer action on its
  owning account.
- **Full commit-identity rewrite** executed pre-first-push: every commit's
  author and committer set to `aed900
  <129773515+aed900@users.noreply.github.com>` (noreply chosen so GitHub
  attribution cannot fall back to any email-to-account mapping). Content
  trees verified byte-identical; commit hashes changed — no external
  references existed yet.
- **Full history content scrub** executed pre-first-push: every historical
  blob and commit message filtered so the retired account name and the
  maintainer's personal email occur nowhere in any reachable object;
  pre-rewrite refs and objects purged from the repo and the offline
  backup. The crates-reservation tooling's repository URL and HTTP
  User-Agent contact were repointed to `https://github.com/aed900/antseal`
  (nothing name-bearing ever reached crates.io — P2 has not executed).
- Repo-local `git config` user.name/user.email set to the same noreply
  identity for all future commits. **Standing rule: no other account name
  or personal email may appear in commits, docs, scripts, or published
  metadata.**
- The push blocker is unchanged in kind and applies to the **aed900**
  token: `gh auth refresh -h github.com -s workflow` must be completed for
  aed900 before `git push -u origin main` succeeds.
