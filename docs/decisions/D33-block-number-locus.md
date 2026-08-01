# D33 — Block-number acquisition locus: `antseal-net::pay()`, over the payment RPC it already holds — `antseal-anchor` never touches receipt capture

- **Status: RESOLVED — `antseal-net`. The block number is captured inside
  `pay()`: in the primary external-signer flow it is a field of the very
  transaction receipt `pay()` must await to know the tx landed; in the native
  fallback and in the crash-backfill path, `antseal-net` reads
  `eth_getTransactionReceipt` over the payment RPC endpoint its own
  `NetworkConfig` (S5) already defines — via the
  `ant_protocol::evm::utils::http_provider` re-export, adding no dependency
  beyond the alloy `Provider` trait `pay()`'s own submission machinery
  already needs. The register's
  anchor-side framing ("the spec's architecture comment puts 'Arbitrum
  receipt capture' in `antseal-anchor`; the churn-boundary rule keeps anchor
  HTTP out of `antseal-net`") is overturned: the payment RPC is not anchor
  HTTP, capture is payment-coupled and time-critical, and an anchor-side
  locus would drag A-work into M1 and thread S7's instant-journal contract
  across a crate boundary for a value `pay()` already holds in hand.
  `antseal-anchor`'s A17 (M2) remains the verify-time, advisory, two-RPC
  must-agree confirmation — it consumes the receipt, never produces it.**
- **Date: 2026-08-01**
- **Owner: S7 (receipt completeness); S6 implements inside `pay()`;
  A17 unaffected consumer**
- **Blocks: S7 (register "block-number acquisition locus", due M1)**
- Companion: S1 memo §8/§9, D37 (receipt shape), A-OD3 (A17's endpoint
  defaults, M2).

## Context

The spec's `PaymentReceipt` carries "EVM tx hash(es) + block number (one
`eth_getTransactionReceipt`) + quote preimages + `PaidChunk.proof_bytes`"
(MVP-SPEC.md line 69), captured in full at payment time (line 110) and
journaled the instant the tx lands, strictly before any `finalize_batch`
call, with block-number enrichment permitted to retry idempotently (S7).
S1 §8 established the forcing fact: **no ant-core/evmlib payment API returns
a block number**, so somebody must make the RPC read. The register's open
question is *which crate*. Two spec lines pull opposite directions:

- line 52-53 (architecture tree comment): `antseal-anchor` — "network side
  only: OTS calendar submit/upgrade polling, TSA HTTP, **Arbitrum receipt
  capture**";
- line 110 (Anchoring): "**Arbitrum receipt**: captured in full **at payment
  time via the batch APIs** … and stored in the vault" — the batch APIs live
  behind `antseal-net::StorageBackend`.

S1's finding makes the two lines impossible to satisfy simultaneously as
written: the batch APIs cannot deliver the block number, and payment-time
capture cannot happen in a crate the payment doesn't flow through. The
decision resolves the conflict.

## Evidence (re-verified 2026-08-01 against the pinned sources)

| # | Fact | Citation |
| --- | --- | --- |
| 1 | `batch_pay` returns `(Vec<PaidChunk>, storage_cost_atto, gas_cost_wei)` — no tx receipt, no block number | `ant-core-0.5.0/src/data/client/batch.rs:417-462` |
| 2 | `GasInfo` carries gas fields only (evmlib reads the receipt internally for `actual_gas_used`/`effective_gas_price` and surfaces neither receipt nor block number) | `evmlib-0.9.0/src/retry.rs:14-31` |
| 3 | The merkle payment handler extracts the `MerklePaymentMade` event from its own receipt and **discards the tx hash** — the native merkle path leaks neither hash nor block number | `evmlib-0.9.0/src/contract/payment_vault/handler.rs:90-115` |
| 4 | In the native wallet flow, tx hashes surface as `BTreeMap<QuoteHash, TxHash>` from `pay_for_quotes` and end up inside each chunk's `proof_bytes`; block number appears nowhere | `evmlib-0.9.0/src/wallet.rs:145-148,383-460`; `ant-core-0.5.0/src/data/client/batch.rs:291-331` |
| 5 | `ant_protocol::evm` re-exports the full payment-RPC toolset: `utils::{http_provider, TransactionConfig}`, `wallet::{Wallet, PayForQuotesError}`, `contract::payment_vault` (calldata builders), and the common types (`TxHash`, `QuoteHash`, `Amount`, `Network`) — all version-locked by ant-core's own dependency | `ant-protocol-2.3.0/src/lib.rs:80-125` |
| 6 | A17 is M2, advisory-only, two public must-agree endpoints, and **consumes** S7's receipt ("Deps: … S: `PaymentReceipt` contents (tx hashes, block number)"); its endpoint defaults are A-OD3, also M2 | `tasks/A.md` A17 (lines 204-213), Open decisions A-OD3 |
| 7 | S2's churn-boundary acceptance excludes "OTS/TSA/esplora/**eth-RPC anchor client** code or deps" from `antseal-net` — the qualifier is *anchor client*, and S5 (in `antseal-net`) already owns "EVM RPC endpoint" configuration for backend construction and payment signing | `tasks/S.md` S2 Accept, S5 Do |
| 8 | The external-signer flow is the S1-recommended primary precisely because "tx hash, receipt (block number), nonce/gas control, and submission timing are first-class" — `pay()` submits the tx and awaits its landing itself | S1 memo §9; calldata surface `evmlib-0.9.0/src/external_signer.rs:55-146` via row-5 re-exports |

## The overturn attempt — the honest case for `antseal-anchor`, and why it fails

The anchor-side case: (i) spec line 52's comment names it; (ii) the
churn-boundary rule wants network I/O other than Autonomi storage out of
`antseal-net`; (iii) A17 will need an Arbitrum RPC client at M2 anyway —
build it once, in anchor, and let the pipeline call it for enrichment.

It fails on four grounds:

1. **The value arrives in-band in the primary flow.** `pay()` submits the
   signed calldata and must await mining to satisfy "journaled the instant
   the EVM tx lands" (MVP-SPEC.md line 145) — and the response to that await
   *is* the transaction receipt, block number included. Moving block-number
   acquisition elsewhere means throwing away a field `pay()` is holding and
   re-fetching it from another crate. There is no version of the primary
   flow in which anchor-side acquisition is not strictly extra work.
2. **Timing contract.** S7 requires the tx-hash-bearing receipt journaled
   before any finalize call, with block-number enrichment idempotent and
   never blocking. The component that knows a sub-batch landed — per-tx, mid
   `pay()`, under D37's multi-tx sequencing — is `pay()` itself. An
   anchor-side enrichment would either be called from inside `pay()`
   (creating the very net→anchor coupling the crate split exists to avoid)
   or run after `pay()` returns (giving up per-sub-batch capture).
3. **Milestone integrity.** A17 and A-OD3 are M2 (row 6). S7 needs block
   numbers at M1. An anchor locus mints a new M1 A-task for a single RPC
   read — discovered work with a crate boundary attached — while the net
   locus needs **nothing it does not already have**: `http_provider` is
   re-exported through ant-protocol (row 5), `antseal-net` already configures
   the endpoint (row 7, S5), and the one import the read call needs — the
   alloy `Provider` trait, since evmlib exposes the concrete provider type
   but does not re-export the trait (`evmlib-0.9.0/src/utils.rs:184-196`) —
   is required by `pay()`'s own external-signer submission path regardless.
4. **Trust-posture separation argues *for* net, not against it.** Seal-time
   capture is informational, single-endpoint, over the same RPC the user
   already trusts to move their money — the captured block number is vault
   data rendered as "supporting evidence", never verdict input. Verify-time
   confirmation (A17) is adversarial: two pinned public endpoints,
   must-agree, feeding an advisory overlay (A19 keeps it out of anchor
   state). Housing both in one anchor-side client would invite exactly the
   conflation A19 exists to prevent. Two different jobs, two crates, and the
   seal-time job sits with the payment.

Ground (ii) dissolves on reading S2's actual wording: the exclusion is
"eth-RPC **anchor client**" (row 7). The payment RPC — submission,
confirmation, and receipt backfill of the payment transaction — is part of
driving the payment, which is `antseal-net`'s entire reason to exist. The
churn boundary keeps *anchor evidence* I/O out of net; it was never a rule
that net may not speak JSON-RPC to the chain it pays on.

## Decision

1. **Locus: `antseal-net`, inside `pay()`.**
   - *External-signer flow (primary, per S1 §9)*: `pay()` submits each
     sub-batch tx and awaits its receipt; on landing it journals
     `{tx_hash, block_number, status}` for that sub-batch immediately
     (D37's per-sub-batch instant capture). The block number is read from
     the awaited receipt object — no separate RPC call.
   - *Native fallback and backfill*: `antseal-net` calls
     `eth_getTransactionReceipt(tx_hash)` on the S5-configured payment RPC
     endpoint via the `ant_protocol::evm::utils::http_provider` provider
     (row 5). One call per tx hash — the spec's "one
     `eth_getTransactionReceipt`" reads per-hash under D37's plural-tx
     reality.
2. **Failure semantics (S7's contract, now with an owner)**: if the receipt
   read fails or the await is interrupted, the journal keeps the tx-hash
   record with block number absent; every subsequent invocation of the
   pipeline retries enrichment idempotently in `antseal-net`, with no
   payment-path side effects. Enrichment never gates finalize.
3. **`antseal-anchor` receives no M1 work from this decision.** A17 (M2)
   stays the only Arbitrum RPC code in anchor: advisory two-endpoint
   confirmation over A-OD3 defaults, consuming the vault receipt. It never
   writes receipt fields.
4. **Dependency accounting**: the provider construction and all common types
   come through ant-protocol's re-exports (row 5), which ant-core
   version-locks. Calling methods on the returned provider requires the alloy
   `Provider` trait in scope — evmlib returns the concrete
   `FillProvider<…, RootProvider, Ethereum>` but re-exports no trait
   (`evmlib-0.9.0/src/utils.rs:184-200`) — so `antseal-net` carries a direct
   `alloy`(-provider/-signer) dependency, exact-pinned in lockstep with
   evmlib's locked alloy version. That dependency is mandated by the primary
   flow's sign-and-submit machinery (S1 §9, S6) irrespective of this
   decision; D33 adds no crate S6 would not already add, and the pin's
   lockstep rule lands with S6/P's normal pin governance.

## Spec conformance — recorded resolution of an internal spec conflict

Lines 52-53 and 110 conflict once S1 §8's finding is applied (Context). This
record resolves it in favor of line 110's normative capture text: **capture
(payment-time, including block number) = `antseal-net`; anchor-class handling
of the receipt (classification A19, advisory confirmation A16/A17) =
`antseal-anchor`**. The line-52 comment's phrase "Arbitrum receipt capture"
should be read — and at the maintainer's next spec pass, amended — as
"Arbitrum receipt *confirmation*". Flagged here per the ground-truth rule; no
spec edit is made by this record.

## Consequences — task-text edits at integration

- **tasks/S.md S7**: Deps — drop "A: Arbitrum RPC client for
  `eth_getTransactionReceipt` (if open decision 2 lands there)". Do — replace
  "obtained via one `eth_getTransactionReceipt` per open decision 2, or
  directly from the payment confirmation if ant-core returns it" with the
  resolved wording (from `pay()`'s awaited receipt in the external flow;
  net-side `eth_getTransactionReceipt` per tx hash in fallback/backfill,
  D33).
- **tasks/S.md S2**: Accept — scope note on the graph check: the exclusion
  covers anchor-evidence clients (OTS/TSA/esplora/**two-endpoint Arbitrum
  confirmation**); the payment RPC (submit/confirm/backfill of payment txs
  over the S5 endpoint) is in-scope for `antseal-net`. Without this note the
  CI check D33 relies on would be specified against the decision.
- **tasks/S.md S6**: Do — note `pay()` owns receipt-await + per-sub-batch
  journal callbacks (with D37).
- **tasks/A.md A17**: one clarifying line — consumes the S7 receipt; never
  captures or backfills it; devnet-disabled per its own text (unchanged
  otherwise).
- **tasks/S.md S5**: no change (already owns the endpoint); optionally name
  the receipt-read as a consumer of the configured RPC.
- **TODO.md register D33 row** — integration's edit.

## Residual risks

1. **Single-endpoint capture can journal a wrong/reorged block number** (a
   lying or lagging payment RPC). Bounded three ways: the tx *hash* is the
   load-bearing capture (block number is re-derivable from the hash forever);
   the stored value is rendered only as "supporting evidence — no
   independently proven time" (A19, MVP-SPEC.md line 110/137); v1.1's
   verification chain and A17's overlay re-verify it against independent
   endpoints. Arbitrum reorg depth in practice is shallow; enrichment
   retrying on later invocations self-heals a pre-reorg read.
2. **`pay()` gains RPC-availability failure modes** (receipt await timeout on
   a live tx). Covered by S7's mandated split: hash journaled at submission,
   landing/enrichment retried — the failure mode existed regardless of locus;
   the locus decision just names its owner.
3. **Upstream re-export / version drift**: `ant_protocol::evm::utils::
   http_provider` disappearing in a bump would push provider construction
   onto net's own alloy dep (already present, Decision 4); an evmlib bump
   moving its alloy major forces the lockstep alloy re-pin. Both are
   contained by S20's bump procedure to the adapter crate; the trait
   boundary and mock tests are unaffected.
