# antseal

Seal your work into permanent encrypted public storage with independently
verifiable timestamps; later, reveal all of it — or any chosen part — to
anyone, with proof it belongs to what you sealed.

**Positioning:** a seal proves *possession by time T* — NOT authorship.
"Seal before you share." antseal is proof of existence, integrity and
priority; it is not a legal notary.

**Status:** pre-M0 scaffold — nothing usable yet.

## Workspace map

| Path | Purpose |
| --- | --- |
| `crates/antseal-core` | Pure logic, WASM-safe (no I/O, no tokio): canonicalization, crypto, manifest/bundle formats, FULL verification including all anchor verification |
| `crates/antseal-anchor` | Network side of anchoring: OTS calendar submit/upgrade polling, RFC 3161 TSA HTTP, Arbitrum receipt capture |
| `crates/antseal-net` | Autonomi storage behind the batch-first `StorageBackend` (ant-core impl + `MockBackend`) |
| `crates/antseal-cli` | Binary `antseal` (clap + tokio arrive with U1) |
| `verifier-web/` | Static offline verifier page: plain HTML/JS + antseal-core via wasm-bindgen (M3) |
| `testdata/` | Golden vectors, UTF-8 corpus, tamper matrix, fine-tree range-proof fixtures |

Authoritative spec: [MVP-SPEC.md](MVP-SPEC.md). Task tracker: [TODO.md](TODO.md)
(219 tasks; per-domain detail under [tasks/](tasks/)).
