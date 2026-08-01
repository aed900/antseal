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

# RFC 3161 TSA list override for the seal-time anchor stage.
# Reserved slot: validated now, consumed when anchoring lands (M2).
# Empty or absent = the built-in defaults (FreeTSA + DigiCert).
[anchors]
tsa_urls = ["https://freetsa.org/tsr", "http://timestamp.digicert.com"]

# Pinned online endpoints for `verify --online` (two independent,
# must-agree sources per evidence class). Reserved slot: validated now,
# consumed when online verification lands (M3).
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
