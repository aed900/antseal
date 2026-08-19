# antseal

Seal your work into permanent encrypted public storage with independently
verifiable timestamps; later, reveal all of it — or any chosen part — to
anyone, with proof it belongs to what you sealed.

**Positioning:** a seal proves *possession by time T* — NOT authorship.
"Seal before you share." antseal is proof of existence, integrity and
priority; it is not a legal notary.

**What a seal does not prove, and what it cannot protect you from.** A seal
shows that the holder of key X possessed this content by time T — that is
not exclusive possession, and it is no evidence that nobody else held the
same bytes. And the vault holder can always be compelled to reveal what they
sealed: selective disclosure limits what a *recipient* learns, never what a
court, an employer or anyone else with leverage can extract; destroying the
vault and every backup of it is the only, irreversible opt-out.
[The threat model](docs/threat-model.md) sets out the compulsion case in
full, including why no deniability feature exists and none is claimed.

**Status:** the M0, M1, M2 and M3 gates have passed; **M4 (hardening and
release) is in progress**. The verifier page is live at
<https://antseal.org/>, and the `antseal` binary has nine subcommands
(`init`, `seal`, `list`, `show`, `status`, `restore`, `reveal`, `verify`,
`vault`).

**There is no release yet** — no signed binaries are published, so the only
way to run it today is to build from source. Treat it as pre-release: the CLI
surface is not frozen until U32, and the one accepted mainnet exposure has not
been performed.

## Install

There is no released binary and no signed artifact to check, so building from
a source checkout is the only way to run antseal today.

When the first release ships, the channel will be **GitHub Releases** as the
single authoritative source — no package managers, no third-party mirrors —
and every artifact will carry a `SHA256SUMS` entry and a minisign signature
([D72](docs/decisions/D72-release-targets-distribution-and-crates-io-scope.md),
[D71](docs/decisions/D71-binary-signing-mechanism-and-key-custody.md)). That
channel is inoperative while this repository is private, so no instruction to
go and fetch something is written here yet.

[Checking a download](docs/signing/verifying-a-release.md) is the page that
will tell you what to run, how to read its output, and what a good signature
does and does not mean: it says the key holder released those bytes — never
that the bytes are safe, correct, or the newest.

<!-- BEGIN minisign-public-key (docs/signing/maintainer-key-procedure.md §5 step 1) -->
No signing key exists yet, so none is published here; when one is generated
its 56-character public key goes between these two markers, alongside a
pointer to [checking a download](docs/signing/verifying-a-release.md).
<!-- END minisign-public-key -->

A key published in this file is served from the same account as the binaries
it signs, so it is not an independent check on them; the copy that does not
share that control plane is a `TXT` record on `antseal.org`, and
[how the signing key is looked after](docs/signing/key-custody.md) records
what each copy is worth.

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
- [Checking a download](docs/signing/verifying-a-release.md) — how to check a
  release signature before you run it, and what a good result does not mean.
- [Release signing](docs/signing/README.md) — how releases are signed, and how
  the signing key is held, backed up and lost.
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
