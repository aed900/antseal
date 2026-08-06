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
  Invalid **values** for recognized keys are hard errors.

## Precedence

```
--network flag   >   config.toml default_network   >   arbitrum-one
```

The same rule will apply to every future override: an explicit flag
always wins, the config supplies the ambient preference, and the built-in
default is the fallback.

## Schema (v1)

```toml
# Effective network when --network is not passed.
# One of: arbitrum-one, arbitrum-sepolia, devnet.
default_network = "arbitrum-sepolia"

# Per-network payment-RPC endpoint override. Chain ids, contract
# addresses, and the default RPC endpoints are compiled-in constants
# (kept byte-identical to the pinned evmlib) and are deliberately NOT
# configurable — a hand-edited contract address is an evidence-downgrade
# hazard, not a preference. Consumed by the payment backend; validated
# at load either way.
[networks.arbitrum-one]
rpc_url = "https://my-own-node.example/rpc"

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

URLs in `rpc_url`, `tsa_urls`, `bitcoin_endpoints`, and
`arbitrum_endpoints` must start with `http://` or `https://`.

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
