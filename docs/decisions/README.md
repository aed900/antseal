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
| [D1](D1-product-name.md) | Product name — **`antseal`, maintainer-confirmed final** (no upstream blessing — recorded deviation; blessing request now optional courtesy; fallback retired) | RESOLVED | 2026-07-27 |
| [D2](D2-hosting-ci.md) | Hosting + CI — GitHub + GitHub Actions | RESOLVED | 2026-07-27 |
| [D3](D3-repo-layout.md) | Repo layout — repo root IS the workspace root (no `antseal/` subdir) | RESOLVED | 2026-07-27 |
| [D4](D4-edition-msrv.md) | Edition 2024; toolchain pinned =1.92.0; MSRV = the pin | RESOLVED | 2026-07-27 |
| [D5](D5-cli-crate-name.md) | CLI crate name — spec tree normative (`antseal-cli` crate, `antseal` binary); bare-name publish deferred | RESOLVED (recorded deferral) | 2026-07-27 |
| [D6](D6-license.md) | Licensing — per-crate dual MIT/Apache-2.0; GPL-3.0 effect on net/cli via `self_encryption`; P15 flag | RESOLVED (files land M4/Q29) | 2026-07-27 |
| [D7](D7-cbor-crate.md) | Deterministic-CBOR crate — `minicbor = "=2.3.0"`; strictness lives in F3 on native probes; in-house-codec contingency trigger; D12 cross-check nominee `cbor2==6.1.3` (dev-only) | RESOLVED | 2026-07-27 |
| [D13](D13-ed25519-dalek-pin.md) | `ed25519-dalek` pin — **`=3.0.0`** over 2.2.0 (identical strict-verify semantics probe-proven; single signature-3/sha2-0.11/getrandom-0.4 stack shared with ml-dsa); ZIP-215 pubkey gap → C12 pre-validation | RECOMMENDED | 2026-07-27 |
| [D14](D14-mldsa-crate.md) | ML-DSA crate — primary **`ml-dsa =0.1.1`** (wasm32 probe PASSED, executed native↔wasm bit-match; canonical rejection at decode), fallback `fips204 =0.4.6` (pinned, unconsumed, byte-compatible); Ed25519-only sig_policy fallback NOT shipped (trigger did not fire); 3 advisories assessed, all patched in pin | RECOMMENDED | 2026-07-27 |
| [D25](D25-unicode-normalization.md) | Unicode/NFC — `unicode-normalization =0.1.25`, data version 17.0.0, descriptor string `unicode-17.0.0`; add-only version registry, shipped tables retained forever | RESOLVED | 2026-07-27 |
