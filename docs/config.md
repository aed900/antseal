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
  otherwise ignored, so a config written by a newer antseal still loads:
  an unknown key's value is never read, so it cannot fail the file
  whatever it holds.
  Invalid **values** for recognized keys are hard errors. One recognized
  key is an error in the wrong table: `bootstrap` under
  `[networks.arbitrum-sepolia]` or `[networks.devnet]` (see "Bootstrap
  peers"); outside the `[networks.*]` tables it is an unknown key, warned
  and ignored like any other. One retired key is an error in every
  `[networks.*]` table: `rpc_url` (see "The payment RPC"). Another is an
  error under `[verify]`: `arbitrum_endpoints`, whose pair now lives in a
  per-network table — and `[verify.devnet]` is an error whatever it holds
  (see "Online-verification endpoints").

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
# before any payment rather than sealing without a timestamp. Only
# authorities whose root is compiled into antseal count toward the anchor
# gate: FreeTSA, DigiCert, zeitstempel.dfn.de and Sectigo (Entrust is
# Sectigo); SwissSign, GlobalSign and Certum return tokens that verify but
# never count, and Apple is refused — see docs/user/timestamp-authorities.md
# §1 and §3.
[anchors]
tsa_urls = ["https://freetsa.org/tsr", "http://timestamp.digicert.com"]

# OpenTimestamps calendars for the seal-time anchor stage. LIVE: `seal`
# submits to exactly these calendars. A non-empty list REPLACES the built-in
# four (the OpenTimestamps client's own defaults) wholesale; empty or absent
# = the defaults; a calendar listed twice is used once. Fewer than two
# calendars answering marks the seal's anchor set degraded, and never stops
# a seal. This list is also the only way past the three pinned calendar
# domains when antseal upgrades a pending attestation: keep a calendar listed
# until the works stamped with it no longer show a pending OpenTimestamps
# anchor in `antseal status` — remove it earlier and its attestations can no
# longer be upgraded. Plain http is accepted for stamping, but upgrades are
# fetched over https only. See "OpenTimestamps calendars" below.
ots_calendars = ["https://a.pool.opentimestamps.org", "https://b.pool.opentimestamps.org"]

# The opportunistic upgrade pass. After any command that unlocked the vault,
# antseal asks the OpenTimestamps calendars whether pending attestations have
# reached Bitcoin. It runs after the command's output is printed but before
# the process exits, so a script waiting on the process waits for it too — a
# few seconds, longer when a calendar or block explorer is slow. false turns
# the pass off; pending attestations then upgrade only when you run
# `antseal status <work-id> --upgrade`. Absent = true. Write a bare true or
# false: "false" in quotes, off and False are refused (exit 17).
opportunistic_upgrades = false

# Online endpoints: two independent sources per evidence class, whose
# answers must agree. These MUST be https. Unlike a timestamp token, an
# esplora or RPC reply carries no signature of its own — it is believed only
# because two independent endpoints agree — so the transport is its only
# integrity control, and one plain-http endpoint would let a single on-path
# attacker supply both halves of a "must agree" pair.
# bitcoin_endpoints: the esplora pair. LIVE: `verify --online` confirms
# Bitcoin block headers against it, and so do `status --upgrade` and the
# opportunistic upgrade pass when they upgrade an attestation.
[verify]
bitcoin_endpoints = ["https://a.example", "https://b.example"]

# The Arbitrum receipt check is per network: a pair for arbitrum-one and a
# pair for arbitrum-sepolia, each exactly two endpoints at different origins,
# each REPLACING that network's built-in pair. LIVE: `verify --online` uses
# the pair of the network it runs on. devnet has no pair (its chain lives for
# one run) and [verify.devnet] is refused. The older single
# `arbitrum_endpoints` key under [verify] is refused when the file is read
# (exit 17): move its two URLs under the table for the network they serve.
[verify.arbitrum-one]
rpc_endpoints = ["https://c.example", "https://d.example"]
```

## The accepted TOML subset

antseal reads a deliberate, documented subset of TOML — everything the
schema above needs and nothing more. Anything outside it is a precise
per-line error, never a misparse:

| accepted | rejected (with a precise error) |
| --- | --- |
| blank lines, `#` comments | escape sequences in `"…"` strings |
| `[section]`, `[section.sub]` headers | multi-line strings and arrays |
| `key = "basic string"` | integers, floats, dates |
| `key = 'literal string'` | inline tables `{ … }` |
| `key = ["a", "b"]` (one line) | array-of-tables `[[…]]` |
| `key = true`, `key = false` (bare, lowercase) | duplicate keys or sections |

Only a recognized key's value is held to this subset, and each key takes one
kind of value: a key that takes a string or a list refuses `true`, and the
one key that takes a boolean refuses `"false"`. An unknown key's value is
not read at all — the key is warned about and ignored — so a config written
by a newer antseal, whose values may use more of TOML, still loads.

URLs in `tsa_urls`, `ots_calendars`, `bitcoin_endpoints` and
`rpc_endpoints` must start with `http://` or `https://`.

They are additionally parsed as real endpoints when the file is read, so a
URL with no host (`http:///tsr`), an unusable scheme, or embedded
credentials (`http://user:pw@host/`) is refused at load — naming the line
and the entry — rather than surfacing as a failed anchor midway through a
seal. An `rpc_endpoints` entry is named by its position (`entry 0`,
`entry 1`), never by its URL (see "Online-verification endpoints").

`bitcoin_endpoints` and `rpc_endpoints` must additionally be **`https://`**,
and the file is refused at load if one is not, before any network call. The
only exemption is a loopback **IP literal** (`127.0.0.0/8` or `::1`), which
exists so the project's own stub-server tests can run; the *name*
`localhost` is not exempt, and neither is a hostname that merely contains a
literal (`127.0.0.1.evil.example`).

`tsa_urls` and `ots_calendars` are deliberately not subject to that rule.
An RFC 3161 timestamp token is signed by the authority and bound to a nonce
we chose, so plain HTTP cannot let anyone forge, replay or substitute one —
and one of the two default authorities, `timestamp.digicert.com`, offers no
HTTPS at all. An OpenTimestamps calendar cannot forge a time either, even
one an attacker controls completely (D54 §4). What plain HTTP does cost is
privacy: a passive observer learns that this machine timestamped a
particular 32-byte digest. If that matters to you, drop DigiCert from the
TSA list and list only https calendars; nothing else changes.

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

## OpenTimestamps calendars

`[anchors] ots_calendars` is the list of calendars `seal` submits to, and the
same list decides which calendars antseal may ask, later, to upgrade a
pending attestation to a Bitcoin one:

- **Replace, never merge.** A non-empty list replaces the four built-in
  calendars (the OpenTimestamps client's own defaults); an empty or absent
  list uses them. A calendar listed twice is used once.
- **OpenTimestamps never stops a seal.** Fewer than two calendars answering
  marks the seal's anchor set degraded — so a list of one marks every seal
  degraded — and none answering leaves the seal with no OpenTimestamps
  anchor. The seal proceeds either way: the check that can stop a seal
  before payment counts timestamp-authority tokens only (D54 §3).
- **Keep a calendar listed while its attestations are pending.** antseal
  upgrades a pending attestation by asking the calendar that issued it, and
  it asks only calendars under three pinned domains or on this list (that
  calendar's host and its subdomains). Remove a calendar while works stamped
  with it still show a pending OpenTimestamps anchor in `antseal status`,
  and those attestations can no longer be upgraded.
- **Upgrades are fetched over https only.** Stamping accepts a plain-http
  calendar, but a calendar whose attestations name it by an `http://`
  address is never upgraded.
- **A longer list upgrades over more commands.** The opportunistic upgrade
  pass that follows a command asks at most four calendars — one work's worth
  with the built-in list — so with a longer list a work's attestations are
  upgraded over several commands. `antseal status <work-id> --upgrade` is
  not limited to four.

## Online-verification endpoints

`verify --online` checks two kinds of evidence against two independent
sources each, and reports agreement only when both give the same answer:

- **`[verify] bitcoin_endpoints`** — the esplora pair Bitcoin block headers
  are confirmed against. `status --upgrade` and the opportunistic upgrade
  pass confirm headers against the same pair. It must name exactly two
  endpoints at different origins, which is checked when the pair is used: a
  list of another size is a usage error (exit code 2) from `verify --online`,
  and from `status --upgrade` when it has an attestation to upgrade, and it
  makes the opportunistic pass skip silently.
- **`[verify.arbitrum-one] rpc_endpoints` and
  `[verify.arbitrum-sepolia] rpc_endpoints`** — the Arbitrum RPC pair a
  payment receipt is confirmed against, one pair per network. A pair you set
  replaces that network's built-in pair, and `verify --online` uses only the
  pair of the network it runs on. Each must name exactly two endpoints at
  different origins, which is checked when the file is read: anything else
  is a malformed config (exit code 17). devnet has no pair — its chain is a
  fresh local chain for each run, so `verify --online` confirms no receipt
  there — and `[verify.devnet]` is a malformed config.
- **These refusals never repeat an RPC URL.** An Arbitrum endpoint that
  serves old receipts usually needs an API key, and providers put the key in
  the URL. A refusal names the key, the table, the line and the entry's
  position instead. `verify --online` itself does print every endpoint it
  consulted, by full URL, on its `endpoints:` line and in `--json` output,
  so a key in one of these URLs appears there: treat that output as you
  would the key.
- **The older `arbitrum_endpoints` key is refused.** Earlier builds read one
  `arbitrum_endpoints` list under `[verify]` and applied it to whichever
  network a command ran on. It is now a malformed config (exit code 17),
  raised before any command runs, naming the key and the two tables that
  replace it but never its value. Move its two URLs under the table of the
  network they serve.

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
