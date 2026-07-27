# Decision register

Numbered records of project-shaping decisions. One file per decision;
statuses here mirror the files. A decision is changed by editing its file
with a new dated entry, never by silently rewriting history.

Evidence convention: several records cite the pre-M0 naming & pin research
memo (2026-07-27, retrievals 13:44Z–13:51Z via crates.io API / rdap.org /
api.github.com). The memo itself was working material; every load-bearing
finding is quoted inline in the records with its retrieval timestamp.

| ID | Title | Status | Date |
| --- | --- | --- | --- |
| [D1](D1-product-name.md) | Product name — `antseal` pending upstream blessing; fallback `sealstone` | **OPEN (provisional)** | 2026-07-27 |
| [D2](D2-hosting-ci.md) | Hosting + CI — GitHub + GitHub Actions | RESOLVED | 2026-07-27 |
| [D3](D3-repo-layout.md) | Repo layout — repo root IS the workspace root (no `antseal/` subdir) | RESOLVED | 2026-07-27 |
| [D4](D4-edition-msrv.md) | Edition 2024; toolchain pinned =1.92.0; MSRV = the pin | RESOLVED | 2026-07-27 |
| [D5](D5-cli-crate-name.md) | CLI crate name — spec tree normative (`antseal-cli` crate, `antseal` binary); bare-name publish deferred | RESOLVED (recorded deferral) | 2026-07-27 |
| [D6](D6-license.md) | Licensing — per-crate dual MIT/Apache-2.0; GPL-3.0 effect on net/cli via `self_encryption`; P15 flag | RESOLVED (files land M4/Q29) | 2026-07-27 |
