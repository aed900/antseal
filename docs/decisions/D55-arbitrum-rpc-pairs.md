# D55 — The default Arbitrum RPC endpoint pairs, per network

- **Status: RESOLVED — `arbitrum-one` = `https://arb1.arbitrum.io/rpc` +
  `https://arbitrum.drpc.org`; `arbitrum-sepolia` =
  `https://sepolia-rollup.arbitrum.io/rpc` +
  `https://arbitrum-sepolia.drpc.org`; `devnet` = **no pair, the overlay is
  disabled**. The pair was decided by two measurements that a liveness
  probe would have missed. (1) **`eth_blockNumber` is the wrong probe**:
  `arbitrum-one-rpc.publicnode.com` answers `eth_blockNumber` and
  `eth_chainId` perfectly and then rejects the only method A17 calls —
  `eth_getTransactionReceipt` → `-32602 "Archive requests require a personal
  token"` — even for a transaction in the current head block. A default
  requiring a key is not a default, and only probing with the production
  method exposed it. (2) **CORS must be measured on the POST, not the
  preflight**: `1rpc.io/arb` returns `Access-Control-Allow-Origin: *` on the
  `OPTIONS` preflight and **no ACAO at all** on the actual POST, so a
  browser passes preflight and then discards the response. Both survivors
  return `ACAO: *` on the POST for both networks, so **D66's Arbitrum half
  is answered affirmatively today, by measurement.** "Must agree" is
  defined over an extracted four-field tuple — `(present, status,
  blockNumber, blockHash)` — with **zero tolerance and never over response
  bytes or the whole object**: the two ruled mainnet endpoints return
  *different key sets* for the same receipt (`timeboosted` vs
  `blobGasUsed`, measured) while the tuple is identical, so an
  object-equality implementation would report disagreement on every single
  call. Head-height agreement, which the brief posed as the hard case, is
  not part of A17's comparison at all and could not be: five endpoints
  spanned 3 blocks inside a 0.878 s window. Disagreement is an
  **advisory-degraded rendering, never an error**, and the offline verdict
  is byte-identical whether the overlay ran, succeeded, failed or
  disagreed.**
- **Date: 2026-08-02** (M2 planning round; register `TODO.md:567`, "A-OD3")
- **Owning task: A17**; consumed by R (overlay rendering) and **U44**
  (config slot, which as landed cannot express a per-network pair)
- **Blocks: A17, U30 (M3), D66 (evidence supplied)**

## Context — the register's question, and the two premises that failed

The register entry (`TODO.md:567`) carries no lean, only the requirement.
The spec's rule is line 137: "two pinned default endpoints per source,
results must agree … user-overridable, rendered as an advisory overlay
distinct from the offline cryptographic verdict", and A17 is "advisory
only, never an anchor" (spec line 110).

Two premises that framed the work did not survive measurement:

- **"Must agree" is about block heights.** It is not. A17 compares
  `eth_getTransactionReceipt` results for a *specific, long-since-confirmed*
  transaction (`tasks/A.md`, A17 Do). A confirmed receipt is immutable;
  chain head is not, and cannot be compared. §3 gives the measurement and
  the residual form the question does take.
- **Liveness can be established with `eth_blockNumber`.** It cannot. §2.

## 1. What already exists, and the boundary this must not cross

`crates/antseal-net/src/network.rs` pins the **payment** RPCs, transcribed
verbatim from the pinned evmlib:

```rust
pub const ARBITRUM_ONE_RPC_URL: &str = "https://arb1.arbitrum.io/rpc";        // line 75
pub const ARBITRUM_SEPOLIA_RPC_URL: &str = "https://sepolia-rollup.arbitrum.io/rpc"; // line 91
```

D33 (2026-08-01) drew the line: "the payment RPC is not anchor HTTP", the
payment RPC lives in `antseal-net`, and `antseal-anchor` gets zero M1 work.
This record does not move that line — **the advisory endpoint constants are
new constants in `antseal-anchor`**, even though one of the four is
textually identical to a payment constant. They are separately overridable,
separately timed out and separately capped, because they answer a different
question at a different time in a different process.

Reusing the chain operator's own endpoint as the *first* member of the pair
is deliberate and worth stating plainly: it is the source most likely to
say "yes, your transaction landed", because it is where the transaction was
submitted. The second member is the corroborator, and it is chosen for
independence of infrastructure. A pair of two aggregators would be more
independent of Offchain Labs and less likely to be authoritative; a pair
containing the operator plus one independent aggregator is the shape the
spec's "results must agree" is actually asking for.

`--network` resolves to three identities (`NetworkId::{ArbitrumOne,
ArbitrumSepolia, Devnet}`, `network.rs:206-219`). A17's Accept already
requires "per-network endpoint sets (arbitrum-one vs arbitrum-sepolia;
disabled on devnet)"; this record supplies them and §6 fixes the config
surface that cannot currently hold them.

## 2. Candidate survey — measured, and why `eth_blockNumber` was not enough

All probes `2026-08-02T19:22:04Z` – `19:55:06Z`, from a single Linux host,
`curl 7.88.1`.

### Round 1 — `eth_blockNumber` (the naive liveness probe)

| endpoint | HTTP | result | latency |
| --- | --- | --- | --- |
| `https://arb1.arbitrum.io/rpc` | 200 | `0x1d3b4eef` | 1.560 s |
| `https://sepolia-rollup.arbitrum.io/rpc` | 200 | `0x1186e1d2` | 0.481 s |
| `https://arbitrum-one-rpc.publicnode.com` | 200 | `0x1d3b4f01` | 0.746 s |
| `https://arbitrum-one.public.blastapi.io` | 200 | `0x1d3b4f05` | 0.788 s |
| `https://1rpc.io/arb` | 200 | `0x1d3b4f0f` | 1.000 s |
| `https://arbitrum.drpc.org` | 200 | `0x1d3b4f14` | 0.459 s |
| `https://rpc.ankr.com/arbitrum` | 200 | **JSON-RPC error −32000: "Unauthorized: You must authenticate your request with an API key"** | 0.339 s |
| `https://arb-mainnet.g.alchemy.com/v2/demo` | **429** | — | 0.504 s |
| `https://arbitrum.llamarpc.com` | — | **NXDOMAIN** | — |
| `https://endpoints.omniatech.io/v1/arbitrum/sepolia/public` | — | **`error code: 521`** | — |
| `https://arbitrum-sepolia.public.blastapi.io` | 200 | **−32000 "Blast API is no longer available. Please update your integration to use Alchemy's API instead"** | — |

Six candidates eliminated here. Ankr and Alchemy fail the brief's own rule —
*a default that requires a key is not a default*. Blast API is
**decommissioning**: its Sepolia endpoint already returns the retirement
message while its mainnet endpoint still serves, so pinning it would be
pinning a service with a published end date.

### Round 2 — `eth_getTransactionReceipt`, the method A17 actually calls

Transaction `0xf74f5e8c78de18cebe1db566935fa81131b868f3e0da8204031758e5d59bfd22`,
Arbitrum One block `0x1d3b6012` — the *current head block* at probe time.
`2026-08-02T19:41:25Z`:

| endpoint | outcome |
| --- | --- |
| `https://arb1.arbitrum.io/rpc` | OK — `blockNumber=0x1d3b6012 blockHash=0x05a7ba97e9f4… status=0x1 logs=1`, 1 722 B |
| `https://1rpc.io/arb` | OK — identical tuple, 1 722 B |
| `https://arbitrum.drpc.org` | OK — identical tuple, 1 722 B |
| `https://arbitrum-one.public.blastapi.io` | OK — identical tuple, 1 722 B |
| `https://arbitrum-one-rpc.publicnode.com` | **ERROR −32602: "Archive requests require a personal token. Get one at: https://www.allnodes.com/publicnode"** |

**This is the finding that decided the mainnet pair.** PublicNode classifies
`eth_getTransactionReceipt` as an archive request and gates it behind an
account. It passed every liveness probe the brief suggested —
`eth_blockNumber` 200 in 0.746 s, `eth_chainId` `0x66eee` on Sepolia — and
is unusable for A17's one job. Any endpoint list validated with
`eth_blockNumber` would have shipped it.

*Method rule, generalised:* **every endpoint in a must-agree pair is
liveness-verified with the exact JSON-RPC method the consuming code calls,
against a real historical transaction — never with a cheaper method.** A44
enforces it as a scheduled check.

### Round 3 — CORS on the **actual POST** (`19:41:54Z`)

`Content-Type: application/json` makes the request non-simple, so a browser
sends an `OPTIONS` preflight *and* requires ACAO on the response to the
POST. Measuring only the preflight is insufficient:

| endpoint | `OPTIONS` preflight | **POST response** | browser-usable |
| --- | --- | --- | --- |
| `https://arb1.arbitrum.io/rpc` | 204, `ACAO: *`, allow-methods `POST`, allow-headers `content-type`, max-age 600 | 200, **`ACAO: *`** | **yes** |
| `https://sepolia-rollup.arbitrum.io/rpc` | 204, `ACAO: *`, same | 200, **`ACAO: *`** | **yes** |
| `https://arbitrum.drpc.org` | 204, `ACAO: https://antseal.example` (echoes origin), max-age 600 | 200, **`ACAO: *`** | **yes** |
| `https://arbitrum-sepolia.drpc.org` | 204, echoes origin | 200, **`ACAO: *`** | **yes** |
| `https://1rpc.io/arb` | 200, `ACAO: *`, max-age 86400 | 200, **no ACAO header at all** | **NO** |
| `https://arbitrum-one-rpc.publicnode.com` | 204, `ACAO: *` + credentials | (moot — round 2) | n/a |
| `https://arbitrum-sepolia.public.blastapi.io` | **403** | — | no |

`1rpc.io/arb` is therefore eliminated for M3's page while remaining
perfectly serviceable from the CLI. It is recorded as a **CLI-only
documented reserve**, with that asymmetry stated, rather than silently
dropped.

### Round 4 — chain-id confirmation of the four survivors (`19:55:06Z`)

| endpoint | `eth_chainId` | decimal | matches the pinned constant |
| --- | --- | --- | --- |
| `https://arb1.arbitrum.io/rpc` | `0xa4b1` | 42 161 | `ARBITRUM_ONE_CHAIN_ID` ✓ |
| `https://arbitrum.drpc.org` | `0xa4b1` | 42 161 | ✓ |
| `https://sepolia-rollup.arbitrum.io/rpc` | `0x66eee` | 421 614 | `ARBITRUM_SEPOLIA_CHAIN_ID` ✓ |
| `https://arbitrum-sepolia.drpc.org` | `0x66eee` | 421 614 | ✓ |

### Sepolia round 2 (`19:42:01Z`)

Transaction `0xf014eab826d131700cc9735994ef31997c2c315cc1e6d08fb660eb61d358126e`,
block `0x1186f45d`:

| endpoint | outcome |
| --- | --- |
| `https://sepolia-rollup.arbitrum.io/rpc` | OK — `0x1186f45d / 0x9e0f761c3927… / 0x1`, 8 logs, 6 947 B |
| `https://arbitrum-sepolia-rpc.publicnode.com` | OK — identical tuple, 6 947 B |
| `https://arbitrum-sepolia.drpc.org` | OK — identical tuple, 6 946 B |

PublicNode *does* serve receipts on Sepolia. It is still rejected, for a
reason that is a policy judgement and should be visible as one: the same
operator gates the same method behind an account on mainnet, so the Sepolia
behaviour is one policy change away from matching. Choosing DRPC on both
networks also makes the two pairs structurally identical (chain operator +
the same independent aggregator), which is what makes the A17 test matrix
transferable between networks.

## 3. "Must agree" — the definition, and the tolerance ruling

### Head height is not compared, and could not be

Five endpoints, one **concurrent** batch, `2026-08-02T19:22:34.117Z` →
`19:22:34.994Z` (a 0.878 s window):

| endpoint | `eth_blockNumber` |
| --- | --- |
| `arb1.arbitrum.io/rpc` | `0x1d3b4f61` |
| `arbitrum-one-rpc.publicnode.com` | `0x1d3b4f63` |
| `arbitrum-one.public.blastapi.io` | `0x1d3b4f63` |
| `arbitrum.drpc.org` | `0x1d3b4f63` |
| `1rpc.io/arb` | `0x1d3b4f64` |

Spread **3 blocks** (derived: `0x1d3b4f64 − 0x1d3b4f61 = 3`) inside one
second. The earlier *sequential* sweep over the same five (`19:22:04Z`,
~4 s of wall clock) spread **37 blocks** (derived: `0x1d3b4f14 − 0x1d3b4eef
= 0x25 = 37`). Head-height equality is not a condition two honest endpoints
can satisfy, and the spec's "results must agree" cannot mean it.

**A17 never asks.** It compares receipts for a transaction that was
confirmed at payment time and is being re-checked at verify time,
arbitrarily long afterwards — so pre-finality flux is out of scope by
construction.

### The comparison tuple, and why it is not the whole object

Same Sepolia receipt, both ruled endpoints, `2026-08-02T19:49:30Z`:

- raw bodies **6 947 B vs 6 946 B — not byte-identical**;
- keys only from `sepolia-rollup.arbitrum.io`: `timeboosted`;
- keys only from `arbitrum-sepolia.drpc.org`: `blobGasUsed`;
- differing shared keys: **none**;
- `(blockNumber, blockHash, status, transactionHash)`: **equal**.

A byte comparison or a whole-object equality would therefore report
disagreement on *every honest call*, permanently. The comparison is over an
extracted, normalised tuple and nothing else:

```
(receipt_present: bool, status: u8, block_number: u64, block_hash: [u8; 32])
```

with hex fields parsed to integers/bytes before comparison, so `0x1` and
`0x01` cannot disagree either.

### Outcomes — five, not four

`tasks/A.md` A17 Accept names four ("agree / one-down / disagree /
tx-absent"). Measurement adds a fifth that is not any of them:

| outcome | condition | rendering |
| --- | --- | --- |
| `Agreed` | both present, tuples equal | "corroborated by 2 of 2 endpoints" |
| `Disagreed` | both present, any tuple field differs | **advisory-degraded**: "endpoints disagree — not corroborated"; both values shown |
| `Lagging` | one present, one `null` result | **advisory-degraded**: "corroborated by 1 of 2"; explicitly NOT presented as corroboration |
| `Absent` | both return `null` | "transaction not found by either endpoint" |
| `Unavailable(n)` | `n ∈ {1,2}` endpoints errored, timed out, or failed the chain-id guard | "could not be checked" |

`Lagging` is separated from `Disagreed` because their causes are opposite
and only one is alarming: a lagging endpoint is a benign sync artifact,
while a single endpoint asserting a receipt the other cannot see is exactly
the shape of a lying endpoint. Collapsing them would render an attack as a
routine condition.

**Tolerance: exactly zero, on all four fields.** No block-number window, no
"within N blocks". A confirmed receipt's block number and hash do not drift
between honest endpoints; any drift is a reorg or a lie, and both are worth
showing. A tolerance would suppress precisely the signal the two-endpoint
rule exists to produce.

### Disagreement is advisory-degraded, never an error

`Disagreed` (and every other non-`Agreed` outcome) changes the overlay
only. Three reasons, in descending order of force:

1. **Spec line 110 / A17**: the receipt is "supporting evidence — no
   independently proven time", never an anchor. A datum that cannot create
   evidence must not be able to destroy it.
2. **Spec line 137** separates the online overlay from "the offline
   cryptographic verdict". If a third-party RPC outage could change a
   verdict, a bundle's verifiability would depend on a service the spec
   spent its whole architecture removing from the trust path.
3. It is testable as an invariant, not a promise — see
   `overlay_outcome_never_changes_the_offline_report` in §7.

### Chain-id guard

Each endpoint is guarded with `eth_chainId` before its receipt is trusted,
matching the payment path's existing rule
(`crates/antseal-net/src/ant_backend.rs:217`: "the RPC's `eth_chainId` must
equal…"). Without it, a mistyped or hostile override silently answers about
a different chain, and a transaction hash replayed across chains would
confirm on the wrong one. A mismatch is `Unavailable`, with a message that
names the expected and reported ids. A17's `Do` does not currently mention
this; §8 hands it over.

## 4. Constants the implementer uses

### `crates/antseal-anchor/src/arbitrum/endpoints.rs`

```rust
use antseal_net::network::NetworkId;

/// Advisory receipt-confirmation endpoints for Arbitrum One, in the order
/// they are queried. Slot 0 is the chain operator's own endpoint — the same
/// URL as the *payment* RPC constant (`antseal_net::network::ARBITRUM_ONE_RPC_URL`)
/// but a deliberately separate constant: different question, different
/// process, separately overridable (D33's boundary; D55 §1).
/// Slot 1 is the independent corroborator.
pub const ARBITRUM_ONE_VERIFY_RPCS: [&str; 2] = [
    "https://arb1.arbitrum.io/rpc",
    "https://arbitrum.drpc.org",
];

/// Advisory receipt-confirmation endpoints for Arbitrum Sepolia
/// (chain 421614 — NOT Ethereum Sepolia).
pub const ARBITRUM_SEPOLIA_VERIFY_RPCS: [&str; 2] = [
    "https://sepolia-rollup.arbitrum.io/rpc",
    "https://arbitrum-sepolia.drpc.org",
];

/// Documented reserves, never contacted by default. `1rpc.io/arb` serves
/// receipts correctly but returns NO `Access-Control-Allow-Origin` on the
/// POST response, so it is CLI-only and must never be promoted into a
/// default pair while M3's page shares these constants (D55 §2 round 3).
pub const ARBITRUM_ONE_RESERVE_RPCS_CLI_ONLY: [&str; 1] = ["https://1rpc.io/arb"];

/// Per-request wall-clock bound (A3's substrate default, restated for the
/// advisory path so a slow endpoint cannot stall `verify --online`).
pub const ARBITRUM_VERIFY_REQUEST_TIMEOUT_SECS: u64 = 10;

/// Per-response body cap for one JSON-RPC exchange. Largest real receipt
/// measured: 6 947 B (8 logs, arbitrum-sepolia). 37x margin.
pub const MAX_ARBITRUM_RPC_RESPONSE_BYTES: usize = 262_144;

/// The pair for a network, or `None` for `devnet` (A17 Accept: "disabled
/// on devnet"). Returning `None` rather than an empty slice makes
/// "there is no overlay here" unrepresentable as "the overlay found
/// nothing".
#[must_use]
pub const fn verify_rpcs(network: NetworkId) -> Option<&'static [&'static str; 2]> {
    match network {
        NetworkId::ArbitrumOne => Some(&ARBITRUM_ONE_VERIFY_RPCS),
        NetworkId::ArbitrumSepolia => Some(&ARBITRUM_SEPOLIA_VERIFY_RPCS),
        NetworkId::Devnet => None,
    }
}

/// Expected chain id for the guard, or `None` for devnet (run-scoped —
/// it comes from `DevnetEnv`, and the overlay is disabled there anyway).
#[must_use]
pub const fn expected_chain_id(network: NetworkId) -> Option<u64> {
    match network {
        NetworkId::ArbitrumOne => Some(antseal_net::network::ARBITRUM_ONE_CHAIN_ID),
        NetworkId::ArbitrumSepolia => Some(antseal_net::network::ARBITRUM_SEPOLIA_CHAIN_ID),
        NetworkId::Devnet => None,
    }
}
```

The chain-id constants are **consumed by name** from
`antseal_net::network`, never re-typed — the same discipline D84 rule F4
applies to limits, for the same reason.

*On that dependency*: `antseal-anchor` takes `antseal-net`'s **default**
features only, for `NetworkId` and the two chain-id constants.
`crates/antseal-net/src/network.rs:6-16` states that module is "pure data …
no `ant-core`, no evmlib, no network I/O", compiled in the default feature
set precisely so consumers can use it without the heavy graph, and U4's
execution note records `antseal-cli` already doing exactly this with a
containment assertion. No new precedent is set and the `ant-backend` gate
is not touched.

### The comparison type

```rust
/// The only four fields compared between the two endpoints. Constructed
/// by parsing hex to integers/bytes, so textual variation cannot cause a
/// false disagreement (D55 §3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReceiptFacts {
    pub status: u8,
    pub block_number: u64,
    pub block_hash: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArbitrumConfirmation {
    Agreed(ReceiptFacts),
    Disagreed { first: ReceiptFacts, second: ReceiptFacts },
    Lagging { seen_by: usize, facts: ReceiptFacts },
    Absent,
    Unavailable { failed: usize },
}
```

`ArbitrumConfirmation` is produced in `antseal-anchor` and reaches
`antseal-core` only as A2's `OnlineEvidence` receipt arm. **It must not be
constructible into any anchor state**; A17's Accept already demands
"type-level or test-enforced separation", and the type-level form is that
`evaluate_anchors` takes the receipt evidence in a field that no
`AnchorState` arm reads.

## 5. Devnet

No pair, no overlay, no config slot. `verify_rpcs(NetworkId::Devnet)` is
`None`, and the renderer shows the receipt class without an online line.
Justification: a devnet chain is a fresh Anvil instance per run
(`network.rs:31-34`), so there is no second endpoint to agree with and no
persistence to confirm against — and devnet seals are not evidence.

## 6. Config — the landed slot cannot express this ruling

`crates/antseal-cli/src/config.rs:486-488` and `docs/config.md:59` reserve a
**single flat** key:

```toml
[verify]
arbitrum_endpoints = ["https://c.example", "https://d.example"]
```

A17's Accept requires "per-network endpoint sets (arbitrum-one vs
arbitrum-sepolia; disabled on devnet) configurable". **A flat list cannot
hold two networks' pairs**, and applying one list to whichever network a
bundle's receipt came from is unsound — a Sepolia endpoint asked about a
mainnet transaction returns `null`, which this ruling classifies as
`Lagging`, i.e. a misconfiguration rendered as a sync artifact.

**Ruling: reshape the slot before it is wired.** It is reserved, unwired
(the `Do` says "wired M3, U30"), unreleased, and nothing consumes it.

```toml
[verify]
bitcoin_endpoints = ["https://a.example", "https://b.example"]   # unchanged — Bitcoin has one network

[verify.arbitrum-one]
rpc_endpoints = ["https://c.example", "https://d.example"]

[verify.arbitrum-sepolia]
rpc_endpoints = ["https://e.example", "https://f.example"]
```

Parser arms (the existing matcher is over a path array, so this is
expressible without changing its shape):

```rust
(["verify", network_name], "rpc_endpoints") => { … }   // network_name parsed via NetworkId::from_str
```

with the same `expect_url_array` validation, the same
`NetworkConfigError::UnknownNetwork` message the `[networks.<id>]` arm
already produces (`config.rs:454`), and a hard error if `network_name` is
`devnet` (there is no overlay to configure). The flat `[verify]
arbitrum_endpoints` key is **removed**; because the parser's fallthrough
warns on unknown keys rather than failing (`config.rs:490-494`), an early
adopter's config degrades to a warning, not an exit-17 hard error. That
property is why the removal is safe and is worth asserting in a test.

An override **replaces** the built-in pair wholesale (U26's `tsa_urls`
semantics) and must supply exactly two entries — a one-entry override
cannot satisfy "results must agree" and is a config error at load, not a
silent single-endpoint overlay. Precedence is U4's: flag > config >
built-in. No CLI flag is added.

Wired by **U44**.

## 6b. Verbatim row to add

**`docs/format/anchor-artifact-limits.md` §5 (the F4 registry):**

| limit | initial value | date set | fixture measured against | margin | lowered |
| --- | --- | --- | --- | --- | --- |
| `MAX_ARBITRUM_RPC_RESPONSE_BYTES` | 262 144 | 2026-08-02 | largest real `eth_getTransactionReceipt` measured, 6 947 B / 8 logs (arbitrum-sepolia, tx `0xf014eab8…126e`); derived worst case for a 256-transfer antseal payment tx ≈ 188 328 B | 37× measured / **1.4× derived worst case** | never |

The two margins are given separately on purpose: the 37× is against an
arbitrary third-party receipt and is not the binding constraint; the 1.4×
against this project's own maximum payment shape is (§7b).

## 7. Tests that must exist, and what makes each fail

| test | lives in | fails when |
| --- | --- | --- |
| `default_pairs_are_exactly_two_per_live_network_and_none_on_devnet` | `antseal-anchor` unit | a constant is edited without updating this record; `verify_rpcs(Devnet)` becomes `Some`. |
| `receipt_facts_ignore_unknown_and_extra_keys` | `antseal-anchor` unit | fed the two **real committed** Sepolia responses from §3 (one with `timeboosted`, one with `blobGasUsed`) the comparison reports `Disagreed`. This is the test that catches an object-equality implementation, and it cannot pass vacuously because the two fixtures differ in bytes by construction. |
| `hex_case_and_leading_zero_variants_do_not_disagree` | `antseal-anchor` unit | `"0x1"` vs `"0x01"`, `"0xA4B1"` vs `"0xa4b1"` produce `Disagreed`. |
| `one_absent_is_lagging_not_disagreed` | `antseal-anchor` unit, stub | the `null`-result case collapses into `Disagreed` — asserted on the **variant**, so a shared "not corroborated" string would not rescue it. |
| `differing_block_hash_is_disagreed_with_both_values` | `antseal-anchor` unit, stub | identical `blockNumber` with differing `blockHash` is accepted as agreement (a reorg rendered as corroboration). |
| `chain_id_mismatch_is_unavailable_not_agreed` | `antseal-anchor` unit, stub | a stub reporting `0x66eee` while the network is `arbitrum-one` still contributes to a tuple. |
| `overlay_outcome_never_changes_the_offline_report` | `antseal-core` + `antseal-anchor` integration | **the load-bearing invariant.** One bundle, verified five times — overlay absent, `Agreed`, `Disagreed`, `Lagging`, `Unavailable(2)` — and the D29 report v1 bytes must be **byte-identical** across all five. Fails the instant any advisory outcome leaks into a verdict. |
| `receipt_confirmation_cannot_construct_an_anchor_state` | `antseal-core` unit | A17's Accept, made structural: `evaluate_anchors` is called with every `ArbitrumConfirmation` variant and the returned `AnchorState` set is asserted unchanged. |
| `response_over_cap_is_a_typed_error` | `antseal-anchor` unit, stub | the client truncates and then fails JSON parsing instead of returning the size error. |
| `flat_verify_arbitrum_endpoints_key_warns_and_does_not_hard_error` | `antseal-cli` config suite | the removed key becomes exit 17 for an early adopter, or is silently accepted as a per-network override. |
| `single_entry_override_is_a_config_error` | `antseal-cli` config suite | a one-endpoint override loads and the overlay silently runs unpaired. |
| `vector_arbitrum_receipt_replay` | CI replay lane (Q16) | the committed real receipts stop parsing. **No real endpoint is contacted in CI.** |

Committed fixtures: the four real responses of §2/§3 land under
`testdata/anchors/` with their transaction hashes, endpoint URLs and
retrieval timestamps. They contain no secret material — public mainnet and
testnet transactions belonging to third parties, chosen from head blocks
and not related to antseal.

## 7b. Conflict with D90 (same wave) — the RPC response cap is too small by this project's own payment shape

D90, resolved concurrently, lands the HTTP substrate and sets
`RPC_RESPONSE_CAP_BYTES = 64 * 1024`. **That is below the receipt size
antseal's own payment path can produce**, and the arithmetic comes from
this project's own decisions:

- Measured, from the real Sepolia receipt of §3: raw 6 947 B, **8 logs**,
  logs 5 851 B compact, envelope ≈ 1 096 B → **≈ 731 B per log**.
- D37 established that `pay()` emits ⌈blobs/256⌉ **sequential** transactions
  with **up to 256 transfers each**. A 256-transfer payment transaction is
  one receipt with on the order of 256 log entries.
- Derived: `1 096 + 731 × 256 ≈ 188 328 B`. D90's 64 KiB caps out at
  **≈ 88 logs**; `MAX_ARBITRUM_RPC_RESPONSE_BYTES = 262 144` caps out at
  **≈ 356**.

So a large seal's own payment receipt would exceed D90's cap, and A17 would
report `Unavailable` for the very transactions the feature exists to
corroborate. Because F4 makes limits **raise-only**, shipping 64 KiB means
that failure reaches a user before the raise can.

Resolution for the orchestrator: keep D90's substrate; set the Arbitrum
request's `receive_cap_bytes` to `MAX_ARBITRUM_RPC_RESPONSE_BYTES = 262_144`.
D90's esplora cap is untouched by this — an 80-byte block header has
nothing to do with a payment receipt.

*(Caveat on the derivation: 731 B/log is measured from one real receipt
whose logs are ordinary ERC-20 `Transfer` events; a payment-vault event with
more topics would be larger, which strengthens rather than weakens the
conclusion. A25 should measure a real antseal payment receipt and record it
in the F4 row.)*

## 8. Findings handed to other tasks

1. **`tasks/A.md` A17 Accept** — "agree / one-down / disagree / tx-absent"
   is four outcomes for a space that has five; `Lagging` (one endpoint
   returns `null`) is neither "one-down" (that is transport failure) nor
   "tx-absent" (that is both). Add it.
2. **`tasks/A.md` A17 Do** — add the `eth_chainId` guard per endpoint,
   matching `ant_backend.rs:217`'s existing rule. Without it a mistyped
   override confirms against the wrong chain.
3. **`tasks/A.md` A3** — the HTTP substrate has no response-size cap (see
   also D54 §9.1); `MAX_ARBITRUM_RPC_RESPONSE_BYTES` needs one to bind to.
4. **`tasks/U.md` U4 execution note item 4** — records `[verify]
   arbitrum_endpoints` as a landed reserved slot with "a validated shape".
   The shape is wrong for its named consumer; §6 replaces it. The note
   should be amended rather than left to contradict U44.
5. **D66 (M3, `TODO.md`)** — its Arbitrum half is answered: all four ruled
   endpoints return `Access-Control-Allow-Origin: *` on the POST response
   for `eth_getTransactionReceipt` with `Content-Type: application/json`,
   measured `2026-08-02T19:41:54Z`/`19:49:30Z`, and both preflights
   succeed. The **method-and-POST rule** (§2 rounds 2–3) is the transferable
   part and should govern D66's esplora measurement too — `blockstream.info`
   and `mempool.space` must be probed with the exact block-header request
   A16 issues, and the ACAO read off that response.
6. **`MVP-SPEC.md` line 137** — "two public Arbitrum RPCs" is satisfied, but
   the sentence's "results must agree" reads naturally as an agreement over
   whatever the source returns. §3 shows that is unimplementable for a
   whole receipt object and impossible for a head height. A spec
   clarification to "results must agree on the compared fields" would
   prevent the next reader re-deriving §3.

## Revisit triggers

- DRPC gating `eth_getTransactionReceipt` or dropping `ACAO: *` → the
  reserve list is consulted, but only after re-running rounds 2 and 3.
- PublicNode removing the archive-token requirement → eligible again;
  re-measure, do not assume.
- Arbitrum One's operator retiring `arb1.arbitrum.io/rpc` → this changes
  the **payment** constant too (`network.rs:75`) and is a joint
  D33/D55 event, not a drive-by edit to one of them.
- A17 ever needing a method beyond `eth_getTransactionReceipt` and
  `eth_chainId` → re-probe every endpoint with it before shipping (§2's
  whole lesson).

## Index row (orchestrator applies at merge)

| [D55](D55-arbitrum-rpc-pairs.md) | Default Arbitrum advisory-RPC pairs — **one = `arb1.arbitrum.io/rpc` + `arbitrum.drpc.org`; sepolia = `sepolia-rollup.arbitrum.io/rpc` + `arbitrum-sepolia.drpc.org`; devnet disabled**. Two measurements decided it and a liveness probe would have missed both: `publicnode` answers `eth_blockNumber` in 0.75 s and then rejects `eth_getTransactionReceipt` with **"Archive requests require a personal token"** (so endpoints are probed with the production method, never a cheaper one), and `1rpc.io/arb` returns `ACAO: *` on the **preflight** and none on the **POST** (so CORS is measured on the POST — which also answers D66's Arbitrum half affirmatively for all four ruled endpoints). "Must agree" is over an extracted tuple `(present, status, blockNumber, blockHash)` with **zero tolerance** and never over bytes or the whole object: the two ruled endpoints return different key sets for the same receipt (`timeboosted` vs `blobGasUsed`) while the tuple is identical. Head-height agreement — the brief's hard case — is not in A17's comparison and could not be (5 endpoints, **3 blocks apart inside 0.878 s**). Disagreement is **advisory-degraded, never an error**, locked by a test requiring the D29 report bytes to be identical across all five overlay outcomes. Adds a fifth outcome `Lagging` A17 lacks, an `eth_chainId` guard it lacks, and **overturns the landed `[verify] arbitrum_endpoints` config slot as unable to hold a per-network pair** | RESOLVED (A17 + new U44 implement) | 2026-08-02 |
