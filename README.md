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

## Who this is for

The CLI is for **technical-ish creators, researchers, inventors and small
legal/IP practices comfortable with a terminal** — people with work they want
dated, who would rather hold the evidence themselves than trust a service to
still be running when they need it. Sealing is paid, permanent and
irreversible, so the tool is built to be read before it is run.

**The person you send a proof to installs nothing.** A `.sealproof` bundle is
self-contained: the manifest, the revealed bytes and the timestamp tokens all
travel inside the one file. A counterparty opens <https://antseal.org/>, drops
the bundle onto the page and reads the result — the checking happens in their
browser, on their machine, with no account and nothing uploaded. For people who
would rather not use a browser, `antseal verify` runs the same `antseal-core`
code natively. Neither route contacts Autonomi, and neither needs anything from
you after you have sent the file.

**One planned use is not built yet: releasing sealed material after death** —
the "digital will" idea, in function though never in law. Wallet keys or
login credentials can be sealed today, and a reveal bundle is a
self-contained file a chosen person could one day be handed; but nothing in
antseal watches for your absence or delivers anything on its own, and sealed
data is ciphertext on a permanent public network, so everything rests on who
holds keys and bundles, and on when they let go. Weigh what sealing a secret
costs before you do it: the ciphertext is permanent and public, so anyone who
ever obtains your vault decrypts it retroactively, and there is no rotation
and no recall ([vault theft](docs/user/vault-theft.md)). That release layer —
a dead-man switch, delivering prepared reveal bundles only after missed
check-ins, resettable until it fires — is registered as a **later-tier**
feature ([TODO.md](TODO.md)'s dead-man entry). It adds a trust layer the MVP
deliberately has none of; until it lands, do not plan an estate around this
tool.

## Install

There is no released binary and no signed artifact to check, so building from
a source checkout is the only way to run antseal today.

### Build from source

The toolchain is pinned in the checkout, so `rustup` fetches and selects it
without being told; the MSRV is that same **1.92.0**, not a lower floor.

```sh
cargo build -p antseal-cli              # ./target/debug/antseal
cargo build -p antseal-cli --release    # ./target/release/antseal, optimised
./target/debug/antseal --version
```

That default build does everything except reach Autonomi: it reads and
writes vaults, it checks proof bundles, and it reaches the timestamp
network — `verify --online` probes a bundle's anchors, `status --upgrade`
polls the calendars to complete pending attestations, and an opportunistic
pass does the same after any command that opened a vault. The timestamp
side is deliberately not feature-gated; only the Autonomi side is.
**The build that can seal is a different one**, opt-in because it pulls in
a much heavier dependency graph:

```sh
cargo build -p antseal-cli --features ant-backend
```

Read [COPYRIGHT](COPYRIGHT) before redistributing that second binary — it links
copyleft dependencies our own permissive licence does not describe (see
[License](#license)).

When the first release ships, the channel will be **GitHub Releases** as the
single authoritative source — no package managers, no third-party mirrors —
and every artifact will carry a `SHA256SUMS` entry and a minisign signature
([D72](docs/decisions/D72-release-targets-distribution-and-crates-io-scope.md),
[D71](docs/decisions/D71-binary-signing-mechanism-and-key-custody.md)). No
release has been published on that channel yet, so no instruction to go and
fetch one is written here.

[Checking a download](docs/signing/verifying-a-release.md) is the page that
will tell you what to run, how to read its output, and what a good signature
does and does not mean: it says the key holder released those bytes — never
that the bytes are safe, correct, or the newest.

<!-- BEGIN minisign-public-key (docs/signing/maintainer-key-procedure.md §5 step 1) -->
No key is published here yet. The 56-character public key goes between these
two markers when it is published, alongside a pointer to
[checking a download](docs/signing/verifying-a-release.md).
<!-- END minisign-public-key -->

A key published in this file is served from the same account as the binaries
it signs, so it is not an independent check on them; the copy that does not
share that control plane is a `TXT` record on `antseal.org`, and
[how the signing key is looked after](docs/signing/key-custody.md) records
what each copy is worth.

## Quickstart

Every step below runs on a machine with no wallet, no funds and no network —
except the one step that cannot, which is named rather than faked.

**1. See the surface.** Nine subcommands, and `--help` on any of them:

```sh
./target/debug/antseal --help
./target/debug/antseal init --help
```

Three globals work on every subcommand:
`--network <arbitrum-one|arbitrum-sepolia|devnet>`, `--json` for one
machine-readable document on stdout, and `--passphrase-fd <FD>` (below).

**2. Create a vault.** `init` is purely local: it writes the vault, the wallet
key and the config, prints the payment address with its funding instructions,
costs nothing and contacts nothing.

```sh
./target/debug/antseal init
```

It asks for a passphrase and stretches it with **Argon2id at 256 MiB, about a
second** — on this run and on every later vault unlock. That is deliberate, and
worth knowing before you run it on a small machine. `--kdf scrypt` is not the
low-memory escape it looks like; it wants roughly 1 GiB. `--wallet import`
takes existing key material instead of generating some, and `--wrap keyfile`
adds a second factor. There is no `--force`: `init` refuses to overwrite an
existing vault, because overwriting one destroys every sealed work's reveal
ability for good.

**3. Open the empty vault.** `list` unlocks — so it asks for the passphrase and
spends that second — and then has nothing to show yet:

```sh
./target/debug/antseal list
# No sealed works in this vault yet.
```

**4. Check a bundle someone sent you.** `verify` is the one command with no
prerequisites at all: no vault, no passphrase prompt, no wallet, no network.

```sh
./target/debug/antseal verify their-work.sealproof
```

Offline is simply what `verify` does; there is no `--offline` flag to remember.
No sample bundle ships in this repository, so this step needs a file somebody
actually sent you — or that same file dropped onto <https://antseal.org/>,
which is what your counterparty will do with it.

**5. Sealing is the step this page will not pretend at.** `antseal seal` quotes
the upload, asks you to confirm a permanent, public and irreversible purchase,
and pays on Arbitrum One. It needs a funded wallet, a live network and the
`--features ant-backend` build, so there is no offline demonstration of it and
no command block for it here. On the default build `seal` stops with an error
naming the build feature it is missing rather than implying an outage;
`restore` and `verify --live` are not available in either build yet.
[Funding your wallet](docs/user/funding-your-wallet.md) is the page that gets
you to where `seal` will run.

### Passphrases in scripts

`--passphrase-fd` reads the vault passphrase from a file descriptor, never from
`argv` or the environment — so the secret is not in `ps` output and not in a
shell history. `--passphrase-fd 0` is stdin and works everywhere; any other
descriptor is reached by opening `/dev/fd/<n>`, which is the mechanism behind
shell process substitution (`<(…)`). Windows has no file-descriptor namespace,
so a non-stdin descriptor fails there with a read error — a recorded limit of
this gpg-convention design, not a bug.

```sh
./target/debug/antseal list --passphrase-fd 0 < vault-passphrase.txt
```

## What a proof bundle shows its recipient

Selective disclosure decides which *content* a recipient sees. It does not hide
the shape of the work, and these travel in every bundle whether you reveal any
content or not.

- **The title.** `seal --title "…"` writes the title into the **plaintext**
  manifest, and every proof bundle carries that manifest — so anyone you send a
  bundle to reads the title, including for a work whose contents you revealed
  none of. `seal` warns about this when you seal. Pick a title you are willing
  to hand over.
- **The structure.** The manifest's file and unit tables carry how many files
  there are, how large each one is, and where the unit boundaries fall.
  Unrevealed units render as sized blackout blocks and unrevealed files as
  placeholders with a size but no path: the withheld *shape* is deliberately
  visible, because a redaction that hides its own extent is how a partial
  reveal gets quoted out of context. Every reveal displays position and total
  size for the same reason. File paths themselves are committed, not disclosed.

Two limits on granularity are worth knowing before you seal rather than after.

- **`--no-fine-tree <glob>` is permanent.** Files matched by that glob get no
  fine-grained byte tree, which makes them **whole-file-revealable only, for
  the life of the seal**. That seal can never be opened at finer granularity
  afterwards — the commitment is what was anchored, and sealing the same bytes
  again would be a new work with a new time. `seal` says so when you use it.
- **Reveal granularity today is the whole work or a chosen unit.** A unit is
  one file by default, or one blank-line-separated block with
  `--split blank-lines`. Arbitrary byte-range reveal (`reveal --range`) is a
  **v1.1** command. The commitment it needs is in every manifest sealed today
  — the byte tree is built from day one — so no seal you make now is locked
  out of it; what is deferred is the selection and its rendering, not the
  proof.

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
- [Versioning](docs/user/versioning.md) — why the program's version number and
  your bundle's format version are different numbers with different promises.
- [Checking a download](docs/signing/verifying-a-release.md) — how to check a
  release signature before you run it, and what a good result does not mean.
- [Release signing](docs/signing/README.md) — how releases are signed, and how
  the signing key is held, backed up and lost.
- [The release checklist](docs/user/release-checklist.md) — the gate a release
  passes before it reaches you, published so that you can check it.
- [Threat model](docs/threat-model.md) — what a seal defends against and what
  it does not.
- [Positioning copy style](docs/positioning-copy-style.md) — the rules this
  project's own copy is held to about what a seal does and does not prove.
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
