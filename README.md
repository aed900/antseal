# antseal

Seal your work into permanent encrypted public storage with independently
verifiable timestamps; later, reveal all of it — or any chosen part — to
anyone, with proof it belongs to what you sealed.

**Positioning:** a seal proves *possession by time T* — NOT authorship.
"Seal before you share." antseal is proof of existence, integrity and
priority; it is not a legal notary.

**Status:** the M0, M1, M2 and M3 gates have passed; **M4 (hardening and
release) is in progress**. The verifier page is live at
<https://antseal.org/>, and the `antseal` binary has nine subcommands
(`init`, `seal`, `list`, `show`, `status`, `restore`, `reveal`, `verify`,
`vault`).

**There is no release yet** — no signed binaries are published, so the only
way to run it today is to build from source. Treat it as pre-release: the CLI
surface is not frozen until U32, and the one accepted mainnet exposure has not
been performed.

## Workspace map

| Path | Purpose |
| --- | --- |
| `crates/antseal-core` | Pure logic, WASM-safe (no I/O, no tokio): canonicalization, crypto, manifest/bundle formats, FULL verification including all anchor verification |
| `crates/antseal-anchor` | Network side of anchoring: OTS calendar submit/upgrade polling, RFC 3161 TSA HTTP, Arbitrum receipt capture |
| `crates/antseal-net` | Autonomi storage behind the batch-first `StorageBackend` (ant-core impl + `MockBackend`) |
| `crates/antseal-cli` | Binary `antseal` (clap + tokio): the nine subcommands above |
| `verifier-web/` | Static offline verifier page: plain HTML/JS + antseal-core via wasm-bindgen — built, deployed and live at <https://antseal.org/> |
| `testdata/` | Golden vectors, UTF-8 corpus, tamper matrix, fine-tree range-proof fixtures |

Authoritative spec: [MVP-SPEC.md](MVP-SPEC.md). Task tracker:
[TODO.md](TODO.md), with per-domain detail under [tasks/](tasks/). This README
deliberately states no task count: it moves most weeks, and
`python3 scripts/check-traceability.py` is the only place it is ever right.

## Documentation

- [Funding your wallet](docs/user/funding-your-wallet.md) — what the payment
  address needs before you can seal.
- [Vault loss](docs/user/vault-loss.md) — what is unrecoverable once the vault
  or its passphrase is gone.
- [Vault theft](docs/user/vault-theft.md) — what someone else holding your
  vault and passphrase can read.
- [Wallet hygiene](docs/user/wallet-hygiene.md) — what the payment wallet links
  together on a public chain.
- [Timestamp authorities](docs/user/timestamp-authorities.md) — which time
  anchors a seal uses, and how to change them.
- [Format stability](docs/user/format-stability.md) — what the sealed formats
  promise across future versions.
- [Threat model](docs/threat-model.md) — what a seal defends against and what
  it does not.
- [Security policy](SECURITY.md) — how to report a flaw privately, and what
  this project treats as a security issue.

## License

antseal's own source is dual-licensed **MIT OR Apache-2.0** at your option
([LICENSE-MIT](LICENSE-MIT), [LICENSE-APACHE](LICENSE-APACHE)), declared once in
`[workspace.package]` and inherited by every crate.

**That is not the whole picture for a distributed binary.** A CLI built with the
`ant-backend` feature — the only build that can actually seal — links copyleft
dependencies through `ant-core` and `ant-protocol`, so distributing such a
binary carries obligations our own permissive licence does not describe.
[COPYRIGHT](COPYRIGHT) names which crates, which licences and which builds;
[D6](docs/decisions/D6-license.md) rules it. Read COPYRIGHT before you
redistribute a binary.
