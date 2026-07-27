# D6 — Licensing

- **Status: RESOLVED** (decision recorded now; LICENSE files + `license`
  manifest fields land at **M4 / Q29** per the spec's "license chosen" M4
  deliverable — which is why the workspace manifests carry no `license`
  field yet)
- **Date: 2026-07-27**

## Context

MVP-SPEC.md line 157 requires "at minimum permissive/open for
`antseal-core` + `verifier-web`" ('hostable on any static host' presumes
redistribution rights). The complication: `antseal-net`/`antseal-cli` link
`ant-core`, and ant-core's dependency graph contains GPL-3.0 code.

## Decision — per-crate licensing

| Component | Own-code license | Distribution reality |
| --- | --- | --- |
| `antseal-core` | **MIT OR Apache-2.0** | permissive (must stay so — WASM verifier page) |
| `antseal-anchor` | **MIT OR Apache-2.0** | permissive |
| `verifier-web` | **MIT OR Apache-2.0** | permissive ("hostable on any static host") |
| `antseal-net` | own code **MIT OR Apache-2.0** | binaries/distribution **effectively GPL-3.0** while the GPL dep remains (below) |
| `antseal-cli` | own code **MIT OR Apache-2.0** | binaries/distribution **effectively GPL-3.0** while the GPL dep remains (below) |

Why the net/cli split: `ant-core` itself is `MIT OR Apache-2.0`, but its
**MANDATORY** dependency `self_encryption ^0.36` is **GPL-3.0** (no linking
exception in the SPDX expression). Any distributed binary linking ant-core —
i.e. `antseal-cli` via `antseal-net` — is a combined work containing
GPL-3.0 code, so its distribution must satisfy GPL-3.0 regardless of the
license on our own crates. Dual-licensing our own code keeps it reusable
and makes the whole arrangement collapse to plain permissive the moment the
GPL dep goes away.

## CRITICAL flag — P15 would break the permissive core

**P15 plans `self_encryption` as a DIRECT `antseal-core` dependency** for
offline ciphertext-address recomputation (spec lines 47–51, 119). That
would pull GPL-3.0 into the permissive core **and therefore into the WASM
verifier page**, destroying the split above. Options recorded for P15/S4
execution (recheck upstream state at P9 and P15):

1. **(i)** Accept GPL-3.0 for the whole project.
2. **(ii)** Keep the core permissive: **clean-room reimplement** the
   datamap/address derivation in-core — **never vendor GPL code** (vendoring
   keeps GPL) — and confine `self_encryption` to `antseal-net`.
3. **(iii)** Upstream relicense/republish inquiry: WithAutonomi has moved
   ant-core/ant-protocol/ant-node to `MIT OR Apache-2.0`, but the published
   `self_encryption` crate still points at `maidsafe/self_encryption` and
   remains GPL-3.0 as of 0.36.0 (2026-05-13); MaidSafe historically offered
   commercial dual licensing. A relicensed or WithAutonomi-republished
   self_encryption dissolves the whole issue.

## Evidence (research memo, 2026-07-27)

- `ant-core` 0.5.0 license **`MIT OR Apache-2.0`** (13:44:55Z; same back to
  0.2.3-rc.1); its 38 normal deps include **`self_encryption ^0.36`,
  normal + non-optional** (deps endpoint, 13:45:43Z).
- `self_encryption` 0.36.0: license **`GPL-3.0`**, published 2026-05-13,
  repository `maidsafe/self_encryption` (13:45:16Z–13:45:21Z) — not (yet)
  republished under WithAutonomi as of retrieval (13:45:44Z adjacent check).
- `ant-protocol` 2.3.0 **MIT OR Apache-2.0** (13:46:54Z, mandatory dep);
  `ant-node` 0.15.0 **MIT OR Apache-2.0** (13:50:52Z, optional dep) —
  neither is a GPL source; self_encryption is the sole copyleft source in
  the mandatory graph.
- Housekeeping: `minicbor` 2.3.0 is **BlueOak-1.0.0** — permissive but
  uncommon; needs an explicit deny.toml allowlist entry if chosen at P10.
  `ciborium` 0.2.2 is Apache-2.0 but **dormant since 2024-01-24** (a P10
  tradeoff to record). `ed25519-dalek` is BSD-3-Clause (fine).
  (13:45:16Z–13:45:21Z.)

## Consequences

- **Q29 / P13 (deny.toml licenses section)**: no single workspace-wide
  license allowlist is possible — it needs a GPL-3.0 exception scoped to
  the net/cli dependency graph, plus a BlueOak-1.0.0 entry if minicbor wins
  P10. The licenses section stays stubbed until Q29 per P13.
- **P15**: carries the CRITICAL flag above; executing P15 as specced
  without choosing option (i)/(ii)/(iii) is a license incident. S4 (address
  computation at seal time, via ant-core in antseal-net) is unaffected.
- **M4 / Q29**: LICENSE-MIT + LICENSE-APACHE files, per-crate `license`
  fields, and the net/cli distribution note land then. Adding the fields is
  a deliberate, recorded event (see workspace `Cargo.toml` note).
- **P2 placeholders**: publish with `license = "MIT OR Apache-2.0"` for all
  five — placeholders contain only our own (empty) code and no ant-core
  dependency, so the GPL effect does not attach to them; the net/cli
  distribution note attaches at first real publish.
