# P9 — ant-core `=0.5.0` pin re-verification (M0 start)

- **Date of verification:** 2026-07-27 (all retrievals 18:14–18:24 UTC)
- **Verifier:** P9 execution agent, per the spec mandate (MVP-SPEC.md "Network"
  decision, "Key external dependency", "Risks & mitigations — ant-core churn":
  re-verify the pin at M0 start; it was published 4 days before Revision 2)
- **Governing policy:** [docs/dependency-policy.md](../dependency-policy.md)
  §1 (exact-pin class), §4 (deliberate bumps)
- **Decision: KEEP `ant-core = "=0.5.0"`.** Rationale in §4.

Companion API survey (S1): [docs/research/S1-ant-core-api-survey.md](../research/S1-ant-core-api-survey.md).

## 1. crates.io state (retrieved 2026-07-27T18:14:32Z)

Source: `https://crates.io/api/v1/crates/ant-core` (JSON API).

| Fact | Value |
| --- | --- |
| Newest / max version | **0.5.0** (also `max_stable_version`) |
| 0.5.0 published | 2026-07-23T22:36:35Z (4 days before this check) |
| 0.5.0 yanked | **no** |
| License (crate metadata + `Cargo.toml.orig` line 6) | MIT OR Apache-2.0 |
| Repository | https://github.com/WithAutonomi/ant-client |
| Previous releases | 0.4.0 (2026-07-09), 0.3.1 (2026-07-08), 0.3.0 (2026-07-03), 0.2.9 (2026-07-02), … — none yanked |

Observed cadence confirms the spec's risk note: 12 releases Apr→Jul 2026,
roughly weekly-to-biweekly.

Source archive used for all source citations in this record and in the S1
memo: `https://static.crates.io/crates/ant-core/ant-core-0.5.0.crate`
(retrieved 2026-07-27T18:14:48Z),
sha256 `c3f3c2f61e3c16437b12133d697d22619835f8bd41fa249979459023c4c85a39`.

## 2. Upstream repo delta 0.5.0 → HEAD (retrieved 2026-07-27T18:15:23–39Z)

Source: GitHub API,
`repos/WithAutonomi/ant-client/compare/ant-core-v0.5.0...HEAD`.

- Release tag: `ant-core-v0.5.0`.
- HEAD is **1 commit ahead, 0 behind**: merge commit `5cec8579db9d`
  (2026-07-25, "Merge pull request #159 … chore(release): promote
  rc-2026.7.3") — the release-promotion merge itself, with an **empty file
  delta** (`files: []` in the compare response).
- Therefore upstream `main` is **content-identical to the 0.5.0 tag**. There
  are no post-0.5.0 storage/payment-surface changes
  (`prepare→pay→finalize`, external-signer flow) and no unreleased critical
  fixes to weigh. The GitHub release object for the tag has no notes body
  (`releases/tags/ant-core-v0.5.0` → empty, retrieved 2026-07-27T18:16:10Z);
  the changelog delta reviewed is the commit compare above.

## 3. Locked dependency graph facts (input to P15 / D6 / S1)

Read from the `Cargo.lock` **packaged inside the ant-core 0.5.0 crate
archive** (the ant-client repo's lockfile at packaging time), cross-checked
against crates.io dependency metadata
(`/api/v1/crates/ant-core/0.5.0/dependencies`, retrieved 2026-07-27T18:14:45Z)
and per-crate license metadata (retrieved 2026-07-27T18:24:25Z):

| Crate | Requirement in ant-core 0.5.0 | Locked version | License |
| --- | --- | --- | --- |
| **`self_encryption`** | `^0.36` | **0.36.0** | **GPL-3.0** |
| `ant-protocol` | `^2.3.0` | 2.3.0 | MIT OR Apache-2.0 |
| `evmlib` (via ant-protocol; the single version-pin point per upstream policy) | — | 0.9.0 | **GPL-3.0** |
| `xor_name` | `^5` | 5.0.0 | MIT OR BSD-3-Clause |
| `saorsa-core` (via ant-protocol) | — | 0.26.2 | (not needed by antseal directly) |
| `blake3` | `^1` | 1.8.5 | (address hash function) |

- **P15 record: `self_encryption` = 0.36.0.** Resolution is currently
  unambiguous: `^0.36` and crates.io newest is also 0.36.0 (published
  2026-05-13, not yanked; repo `maidsafe/self_encryption`). P15 must
  re-verify with `cargo tree` at its own execution time (a 0.36.x patch
  release would still satisfy `^0.36`).
- **License concern (feeds D6/P15):** `self_encryption` is **GPL-3.0**
  (crates.io metadata and `Cargo.toml` line 27 of the 0.36.0 archive,
  sha256 `47ab904569f88dcbde4f0feadb693c184577dc81e8243f96bb725e72a779c637`).
  Additionally noted during verification: **`evmlib` 0.9.0 is also
  GPL-3.0** (crates.io metadata; every source file header). So ant-core
  0.5.0, itself MIT OR Apache-2.0, transitively links two GPL-3.0 crates.
  This does not change P9's outcome (the pin is about version, not license)
  but it widens the D6 question from "self_encryption is GPL" to "the
  ant-core graph carries GPL-3.0 components (self_encryption, evmlib)" —
  D6/P15 must assess antseal's license posture against both. Note the
  transitivity boundary: only `antseal-net` (M1) links ant-core; the
  offline verifier and `antseal-core` must stay clear of the GPL graph
  unless D6 decides otherwise (P15 evaluates vendoring vs linking for
  address recomputation).
- Cross-verification: the evmlib 0.9.0 archive we fetched hashes to
  `8da0d9ad5b5cab92cc92ddac9afb884f86b226340caf17f6e5c41d51175dcaa1`,
  byte-identical to the checksum in ant-core 0.5.0's packaged `Cargo.lock`.

## 4. Decision: keep `=0.5.0`

Per dependency-policy §4, a bump needs a reason; there is none and there is
nothing to bump to:

1. 0.5.0 is the **newest published version** on crates.io and is not yanked.
2. Upstream `main` is content-identical to the release tag (§2): no pending
   critical fixes, no storage/payment-surface drift.
3. The spec's API-surface assumptions were re-verified against the 0.5.0
   source in the S1 survey (all names/shapes confirmed; see the S1 memo,
   which also flags two nuances — merkle-mode tx-hash opacity and the
   `data_download(DataMap)` signature — neither of which a version bump
   would change).

Landed as `ant-core = "=0.5.0"` in `[workspace.dependencies]` (root
`Cargo.toml`). **No member crate consumes it until M1** (`antseal-net`,
S2/S6/S7), so `Cargo.lock` does not grow an ant-core tree yet; the entry is
the declared pin the M1 work inherits via `ant-core.workspace = true`.

Next scheduled re-check: the weekly upstream report (P19) and, per policy
§4, a full checklist PR if any bump is ever proposed. If at M1
consumption time crates.io newest has moved past 0.5.0, that alone is NOT a
reason to bump — the pin holds until a deliberate P7-§4 review says
otherwise.

## 5. Retrieval log

| What | URL | Retrieved (UTC) |
| --- | --- | --- |
| Crate metadata + version list | `https://crates.io/api/v1/crates/ant-core` | 2026-07-27T18:14:32Z |
| 0.5.0 dependency metadata | `https://crates.io/api/v1/crates/ant-core/0.5.0/dependencies` | 2026-07-27T18:14:45Z |
| ant-core 0.5.0 source archive | `https://static.crates.io/crates/ant-core/ant-core-0.5.0.crate` | 2026-07-27T18:14:48Z |
| self_encryption metadata | `https://crates.io/api/v1/crates/self_encryption` | 2026-07-27T18:15:05Z |
| Tag list | GitHub API `repos/WithAutonomi/ant-client/tags` | 2026-07-27T18:15:23Z |
| Compare tag…HEAD | GitHub API `…/compare/ant-core-v0.5.0...HEAD` | 2026-07-27T18:15:39Z |
| Release notes (empty) | GitHub API `…/releases/tags/ant-core-v0.5.0` | 2026-07-27T18:16:10Z |
| ant-protocol 2.3.0 source archive | `https://static.crates.io/crates/ant-protocol/ant-protocol-2.3.0.crate` | 2026-07-27T18:17:51Z |
| evmlib 0.9.0 source archive | `https://static.crates.io/crates/evmlib/evmlib-0.9.0.crate` | 2026-07-27T18:18:14Z |
| self_encryption 0.36.0 source archive | `https://static.crates.io/crates/self_encryption/self_encryption-0.36.0.crate` | 2026-07-27T18:22:06Z |
| ant-protocol / evmlib / xor_name license metadata | `https://crates.io/api/v1/crates/{ant-protocol,evmlib,xor_name}` | 2026-07-27T18:24:25Z |
