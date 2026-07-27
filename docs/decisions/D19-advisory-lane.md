# D19 — Advisory lane: cargo-deny only

- **Status: RESOLVED (FROZEN)**
- **Date: 2026-07-27**
- **Owning task: P13** (permanent operation + licenses completion: Q10/Q29)
- Decides the `tasks/P.md` open decision "cargo-deny vs cargo-audit (or
  both) for the advisory lane" (also listed in TODO.md as D19).

## Decision

**cargo-deny, alone.** No cargo-audit anywhere in CI or the docs.

- cargo-deny's `advisories` check consumes the **same RUSTSEC advisory DB**
  (<https://github.com/rustsec/advisory-db>) cargo-audit reads — a second
  tool adds a second version pin, a second install cost in two workflows,
  and zero additional advisory coverage.
- cargo-deny additionally provides the `bans`/`sources`/`licenses` checks
  P13/Q10/Q29 need anyway; one tool, one config (`deny.toml`), one verdict.
- The Q1 mount-point job name **`audit-deny` is kept verbatim** — it is a
  reserved required-status context and contexts are never renamed — even
  though the content is deny-only.

**Tool pin**: the CI-executed cargo-deny version is exact-pinned per
[dependency-policy §5](../dependency-policy.md) (dev-tools whose verdict
gates merges): **`cargo-deny =0.19.8`** at P13. Bumps follow §4.

## deny.toml shape (frozen at P13)

Committed at the workspace root; the check list is explicit because the
licenses section is stubbed:

```
cargo deny --locked check advisories bans sources
```

- **`[advisories]` — active.** RUSTSEC DB; defaults kept (vulnerability /
  unmaintained / unsound / yanked all surface). **Every `ignore` entry
  carries a written justification and a review date** in its `reason`
  string; an entry past its review date is expired — re-assess and re-date,
  or remove. Expected first residents: the two Jan-2026 `ml-dsa`
  advisories, entering **with P12's applicability assessment** when the
  `ml-dsa =0.1.1` pin lands (not pre-ignored while the crate is absent
  from the graph — dead config lies). Advisory watchlist (Q10): `ml-dsa`,
  `fips204`, `ed25519-dalek`, `ant-core`, `minicbor`.
- **`[bans]` — active.** `multiple-versions = "warn"` (recorded P13
  choice: today's three duplicate pairs are dev/proc-macro tier — syn 2+3
  via thiserror-vs-serde_derive, getrandom 0.3+0.4 inside proptest's
  dev-only tree, target-gated r-efi — and ant-core's ~38-dep graph at M1
  would make a `deny`+skip-list a maintenance treadmill with no security
  payoff on top of the exact-pin class + committed lockfile; duplicates
  stay visible in every run; Q10 revisits at M1). `wildcards = "deny"`
  with `allow-wildcard-paths = true`; internal path deps carry an explicit
  `version` in `[workspace.dependencies]` so no implicit `*` exists.
- **`[sources]` — active.** crates.io only; unknown registries/git denied.
- **`[licenses]` — STUBBED** (commented out; the licenses check is not
  run). Completion is **Q29 (M4)** per [D6](D6-license.md). The stub
  records what Q29 must encode: an explicit **BlueOak-1.0.0** allowlist
  entry for the pinned `minicbor` codec, and a **GPL-3.0** exception
  **scoped to the antseal-net/antseal-cli graph only** once `ant-core`
  (mandatory `self_encryption ^0.36`, GPL-3.0) lands at M1 — never
  extended to antseal-core/verifier-web (see the D6 CRITICAL flag on P15).

## Triggers (frozen at P13)

1. **Per-PR**: the `audit-deny` job in `.github/workflows/ci.yml` (a
   required-status context; also runs on push to `main`).
2. **Weekly schedule**: `.github/workflows/advisory-cron.yml`
   (`cron: "17 6 * * 1"`, plus `workflow_dispatch` for manual sweeps and
   the red-lane demonstration) — a new advisory surfaces even with zero
   pushes. Schedules run against the default branch only, so the cron is
   inert until the workflow lands on `main`
   ([ci-verification](../ci-verification.md) tracks remote status).

Both triggers install the same pinned binary (cached on the exact version
string) and run the same command; a divergence between the two files is a
bug.

## Red-lane demonstration (P13 accept, pending remote CI)

To be executed once after the remote-push blocker clears, on a throwaway
branch: add a synthetic `[advisories].ignore` entry (or temporarily ignore
then un-ignore a real advisory), run `workflow_dispatch`, and record the
red run URL in [ci-verification](../ci-verification.md). Until then the
local equivalent stands: `cargo deny check advisories` exits non-zero on
any DB hit not covered by an ignore (verified locally 2026-07-27; the lane
inherits libtest-style loud failure from the tool's exit code).

## Consequences

- Q10 owns permanent operation (new-advisory → tracking issue workflow),
  the licenses completion after Q29, and the level review of
  `multiple-versions` once the M1 graph is real.
- P19/Q36's weekly upstream-bump report folds in this lane's scheduled
  advisory delta rather than running its own advisory scan.
- Any future desire for cargo-audit-specific features (e.g. `cargo audit
  bin`) reopens this record as a dated addendum, not a silent tool swap.
