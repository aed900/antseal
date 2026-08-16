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
| `verifier-web/` | Static offline verifier page: plain HTML/JS + antseal-core via wasm-bindgen (M3) |
| `testdata/` | Golden vectors, UTF-8 corpus, tamper matrix, fine-tree range-proof fixtures |

Authoritative spec: [MVP-SPEC.md](MVP-SPEC.md). Task tracker: [TODO.md](TODO.md)
(648 tasks; per-domain detail under [tasks/](tasks/)). Counts here are a
script's parse — `python3 scripts/check-traceability.py` — never an increment.

## License

**Not yet chosen in-tree.** [D6](docs/decisions/D6-license.md) rules the
intended set (permissive for `antseal-core` and `verifier-web`), but no LICENSE
file exists yet and no manifest carries a `license` field, so **the source is
under default copyright — all rights reserved — until Q29 lands**. Do not
assume redistribution rights from the crates.io placeholder metadata.
