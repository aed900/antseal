# The antseal configuration file

`config.toml` lives **in the vault directory** (`~/.antseal/config.toml`,
or `$ANTSEAL_DIR/config.toml`), beside the encrypted store — one of
exactly three plaintext files there (decision D42: this file, the vault
header, and the lockfile; everything else is encrypted at rest).

It carries **operator preferences only** — never secrets, never per-work
data. `antseal init` writes the initial file; edit it by hand afterwards.
`vault export` embeds it in the backup and `vault import` restores it
(D47).

- A **missing** file means built-in defaults.
- A **malformed** file is a hard error on every command (exit code 17,
  `malformed-config`), naming the line and the problem. A config that
  cannot be read is never silently ignored — silently dropped overrides
  are worse than a loud stop.
- **Unknown keys and sections are warnings**, printed to stderr and
  otherwise ignored, so a config written by a newer antseal still loads.
  Invalid **values** for recognized keys are hard errors. One recognized
  key is an error in the wrong table: `bootstrap` under
  `[networks.arbitrum-sepolia]` or `[networks.devnet]` (see "Bootstrap
  peers"); outside the `[networks.*]` tables it is an unknown key, warned
  and ignored like any other. One retired key is an error in every
  `[networks.*]` table: `rpc_url` (see "The payment RPC").

## Precedence

```
--network flag   >   config.toml default_network   >   arbitrum-one
```

That rule decides the **invocation's** network: the network new work is
sealed on, the network `verify --online` and `--live` read from, and the
top-level `network` member of every `--json` envelope (D174 §2 R11). It is
resolved once, before any command runs. It does **not** decide the network
a command acting on an already sealed work uses — that work was stored on
one network and is readable only there. `restore` reads the network
recorded in the vault, never `default_network`, and refuses a `--network`
naming a different one as a usage error (exit code 2); `reveal` enforces
the same rule lazily, at its first needed fetch (D175); `status`'s receipt
read uses the recorded network and reads no flag. The same shape applies to
every future override: an explicit flag always wins, the config supplies
the ambient preference, and the built-in default is the fallback.
`arbitrum-one`'s bootstrap peers follow it with no flag:
`[networks.arbitrum-one] bootstrap` when present, otherwise the built-in
list — for `restore` too, which reads `config.toml` for that one key.

## Schema (v1)

```toml
# Effective network when --network is not passed.
# One of: arbitrum-one, arbitrum-sepolia, devnet.
default_network = "arbitrum-sepolia"

# Per-network table. Chain ids, contract addresses, and the payment RPC
# endpoints are compiled-in constants (kept byte-identical to the pinned
# evmlib) and are deliberately NOT configurable — a hand-edited contract
# address is an evidence-downgrade hazard, not a preference. There is no
# RPC override: `rpc_url` under any [networks.<id>] is REFUSED when the
# file is read (exit 17, malformed config; U94), naming the key, the table
# and the line but never the value. The payer dials the compiled-in public
# endpoint for arbitrum-one and arbitrum-sepolia, and the RPC_URL of the
# export ANTSEAL_DEVNET_ENV names for devnet.
[networks.arbitrum-one]
# Storage-network bootstrap peers, arbitrum-one ONLY. A present list
# REPLACES the built-in list wholesale and is never merged with it.
# Validated at load; see "Bootstrap peers" below. (These two are RFC 5737
# documentation addresses, never routed: replace them, never copy them.)
bootstrap = ["192.0.2.10:10000", "198.51.100.20:10000"]

# RFC 3161 TSA list override for the seal-time anchor stage. LIVE: `seal`
# contacts exactly these authorities. A non-empty list REPLACES the
# built-in defaults wholesale; empty or absent = the defaults (FreeTSA +
# DigiCert). The >= 1-verified-token-or-abort gate applies to whatever this
# list resolves to, so a list of unreachable endpoints aborts the seal
# before any payment rather than sealing without a timestamp.
[anchors]
tsa_urls = ["https://freetsa.org/tsr", "http://timestamp.digicert.com"]

# Pinned online endpoints for `verify --online` (two independent,
# must-agree sources per evidence class). Reserved slot: validated now,
# consumed when online verification lands (M3).
# These MUST be https. Unlike a timestamp token, an esplora or RPC reply
# carries no signature of its own — it is believed only because two
# independent endpoints agree — so the transport is its only integrity
# control, and one plain-http endpoint would let a single on-path attacker
# supply both halves of a "must agree" pair.
[verify]
bitcoin_endpoints = ["https://a.example", "https://b.example"]
arbitrum_endpoints = ["https://c.example", "https://d.example"]
```

## The accepted TOML subset

antseal reads a deliberate, documented subset of TOML — everything the
schema above needs and nothing more. Anything outside it is a precise
per-line error, never a misparse:

| accepted | rejected (with a precise error) |
| --- | --- |
| blank lines, `#` comments | escape sequences in `"…"` strings |
| `[section]`, `[section.sub]` headers | multi-line strings and arrays |
| `key = "basic string"` | integers, booleans, dates |
| `key = 'literal string'` | inline tables `{ … }` |
| `key = ["a", "b"]` (one line) | array-of-tables `[[…]]` |
| | duplicate keys or sections |

URLs in `tsa_urls`, `bitcoin_endpoints`, and `arbitrum_endpoints` must start
with `http://` or `https://`.

`tsa_urls`, `bitcoin_endpoints` and `arbitrum_endpoints` are additionally
parsed as real endpoints when the file is read, so a URL with no host
(`http:///tsr`), an unusable scheme, or embedded credentials
(`http://user:pw@host/`) is refused at load — naming the entry and the
line — rather than surfacing as a failed anchor midway through a seal.

`bitcoin_endpoints` and `arbitrum_endpoints` must additionally be
**`https://`**, and the file is refused at load if one is not — naming the
endpoint, before any network call. The only exemption is a loopback **IP
literal** (`127.0.0.0/8` or `::1`), which exists so the project's own
stub-server tests can run; the *name* `localhost` is not exempt, and neither
is a hostname that merely contains a literal (`127.0.0.1.evil.example`).

`tsa_urls` is deliberately not subject to that rule. An RFC 3161 timestamp
token is signed by the authority and bound to a nonce we chose, so plain
HTTP cannot let anyone forge, replay or substitute one — and one of the two
default authorities, `timestamp.digicert.com`, offers no HTTPS at all. What
plain HTTP does cost there is privacy: a passive observer learns that this
machine timestamped a particular 32-byte digest. If that matters to you,
drop DigiCert from the list; nothing else changes.

## Bootstrap peers

A client joins the Autonomi storage network by dialing a few known peers
first. For `arbitrum-one`, antseal carries a built-in list: a byte-identical
copy of `resources/bootstrap_peers.toml` as upstream (`WithAutonomi/ant-client`)
published it at the pinned `ant-core`'s release tag, `ant-core-v0.5.0`,
embedded when antseal is built
([D173](decisions/D173-mainnet-peers-are-upstreams-published-bytes-and-no-test-can-dial-them.md)).
What is checked about that list is exactly this: a test recomputes its
recorded sha256 and upstream's git blob id over the embedded bytes and
compares the parsed addresses with an independent transcription, and the
list is compared with upstream's on the weekly upstream check. Nothing establishes that any listed peer is
live, who operates it, or that it is authentic. The claim is only *these are
the bytes upstream published at the pin*.

`bootstrap` under `[networks.arbitrum-one]` replaces that list:

- **Replace, never merge.** A present list is the whole peer set. It is never
  combined with the built-in list, with a peer cache, or with anything else,
  so the set has one source. An override exists to stop dialing seeds you do
  not want dialed, and a merge would keep dialing them.
- **Validated when the file is read.** A bad list is a malformed config
  (exit code 17), raised before any command runs, so before any passphrase is
  asked for. The list must have at least one entry. Every entry must be an IP
  address with a port (`"ip:port"`); a hostname such as `example.org:10000` is
  refused. No entry may repeat, be an unspecified address (`0.0.0.0` or `::`),
  use port 0, or be a loopback address, so neither an all-loopback list nor
  one mixing loopback and public addresses loads.
- **An empty list is refused, not read as "use the defaults".** This is where
  `bootstrap` differs from `tsa_urls`: `bootstrap = []` is a malformed config.
  To go back to the built-in list, delete the key.
- **`arbitrum-one` only.** The same key under `[networks.arbitrum-sepolia]`
  or `[networks.devnet]` is a malformed config (exit code 17), and the error
  names `ANTSEAL_DEVNET_ENV`: the devnet export it names is those networks'
  only peer source, because their peers belong to one run of a devnet.
- **No flag and no environment variable.** This key is the only way to
  override peers.

## The payment RPC

antseal has no payment-RPC override. Every payment call — the balance and
allowance reads, the token approval, the payment transaction and its receipt —
goes to the compiled-in public RPC endpoint for `arbitrum-one` and
`arbitrum-sepolia`, and to the `RPC_URL` of the devnet export
`ANTSEAL_DEVNET_ENV` names for `devnet`. `status`'s block-number backfill
reads receipts from the same endpoint.

Earlier builds parsed `rpc_url` under `[networks.<id>]` and never read it, so
a configured endpoint was silently not used. The key is now refused when the
file is read — a malformed config (exit code 17), raised before any command
runs, naming the key, the table and the line. The error never repeats the
value: an RPC URL usually carries an API key, and error messages end up in
terminals, logs and `--json` output. Delete the line.

## Files outside the vault

antseal keeps what it writes under the vault directory (`ANTSEAL_DIR`, default
`~/.antseal`) with one exception it does not control: the pinned Autonomi
client library (`ant-core` 0.5.0) keeps a small state file of its own.

| | |
|---|---|
| File | `client_adaptive.json` |
| Directory | Linux and other Unix: `$XDG_DATA_HOME/ant`, else `$HOME/.local/share/ant` (`$USERPROFILE` when `HOME` is unset). macOS: `$HOME/Library/Application Support/ant`. Windows: `%APPDATA%\ant`, else `%HOME%\AppData\Roaming\ant` (`%USERPROFILE%` when `HOME` is unset) |
| Written | by every command that connects to the storage network — `seal`, `restore`, `reveal` when it must fetch, `verify --live` — when the connection closes |
| Read | by the same commands when they connect |
| Contents | a schema number and three concurrency starting values (quote, store, fetch). No peers, keys or addresses, and nothing about your works |

It is the directory upstream's own `ant` command-line tool uses, so the two
share the file. Deleting it is harmless: it is recreated with default values.

To move it, set `XDG_DATA_HOME` (Linux and other Unix) or `APPDATA` (Windows)
to an absolute directory. antseal refuses to connect — a network-failure
error, exit 23, naming the variables — where the library would otherwise crash
or write the file into the current directory: when none of `XDG_DATA_HOME`
(`APPDATA` on Windows), `HOME` and `USERPROFILE` holds a usable value (one
that is not valid Unicode does not count), or when the one it would use is
empty or a relative path. On macOS, with no home set, the library writes no
file and antseal does not refuse.
