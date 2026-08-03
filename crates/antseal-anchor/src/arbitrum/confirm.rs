//! Two-RPC Arbitrum receipt confirmation — **advisory only** (task **A17**;
//! decision [D55](../../../../docs/decisions/D55-arbitrum-rpc-pairs.md)).
//!
//! The output feeds the receipt's supporting-evidence overlay and nothing
//! else. It never creates, promotes or affects an anchor state and never
//! yields a headline time (MVP-SPEC.md line 110; A19). It consumes the
//! receipt `antseal-net::pay()` captured (D33) and only re-confirms it.
//!
//! # Agreement is over an extracted tuple, never over bytes
//!
//! Measured on both networks, and the two measurements fail a byte comparator
//! for **two different reasons** — which is why the ruling is about the
//! comparison and not about one vendor's quirk:
//!
//! | network | why the bodies differ | tuple |
//! | --- | --- | --- |
//! | arbitrum-sepolia (D55 §3; reproduced 2026-08-03) | result key sets differ: `timeboosted` on one, `blobGasUsed` on the other, zero differing shared keys | **equal** |
//! | arbitrum-one (2026-08-03) | result key sets *identical*; the JSON-RPC **envelope** is ordered differently — `{"jsonrpc",…,"id",…}` against `{"id",…,"jsonrpc",…}` | **equal** |
//!
//! A byte or whole-object comparison would therefore report `Disagreed` — the
//! alarming outcome, "a lying endpoint" — for two honest endpoints on every
//! call, permanently. The comparison is
//! [`ReceiptFacts`](antseal_core::anchor::model::ReceiptFacts) and nothing
//! else, with hex parsed to integers and bytes first so `0x1` and `0x01`
//! cannot disagree either.
//!
//! **Tolerance is exactly zero on every field.** No block-number window, no
//! "within N blocks". A confirmed receipt's block number and hash do not drift
//! between honest endpoints; any drift is a reorg or a lie, and a tolerance
//! would suppress precisely the signal the two-endpoint rule exists to
//! produce.
//!
//! # Five outcomes, not four
//!
//! `tasks/A.md` A17 named four — agree / one-down / disagree / tx-absent — and
//! that is four names for a five-outcome space. The case where one endpoint
//! returns `null` for a transaction the other has is
//! [`ArbitrumConfirmation::Lagging`]: an ordinary consequence of chains that
//! sync independently, not a fault. It is separated from
//! [`ArbitrumConfirmation::Disagreed`] because their causes are **opposite**
//! and only one is alarming — a single endpoint asserting a receipt the other
//! cannot see is the shape of a lying endpoint, while a lagging endpoint is a
//! benign artifact. Collapsing them renders an attack as a routine condition,
//! or a healthy pair as broken.
//!
//! The five are derived from [`Agreement`]'s three by extracting
//! `Option<ReceiptFacts>` rather than `ReceiptFacts`, so the shared primitive
//! is genuinely shared and the split is a projection rather than a second
//! implementation.
//!
//! # The chain-id guard
//!
//! A17's `Do` omits it; D55 §3 adds it, because without it a correctly
//! agreeing pair on the **wrong network** confirms. The payment path already
//! carries the same rule (`crates/antseal-net/src/ant_backend.rs:217`). Each
//! endpoint is asked `eth_chainId` before its receipt is read, and a mismatch
//! makes that endpoint [`ArbitrumConfirmation::Unavailable`] with a message
//! naming the expected and reported ids — never a contribution to a tuple.

use antseal_core::anchor::model::{ReceiptConfirmation, ReceiptFacts};
use antseal_net::network::NetworkId;
use serde_json::Value;

use super::endpoints::{
    METHOD_CHAIN_ID, METHOD_GET_TRANSACTION_RECEIPT, RPC_CONTENT_TYPE, expected_chain_id,
};
use crate::agree::{Agreement, EndpointFailure, EndpointPair, fetch_and_agree};
use crate::http::{
    Endpoint, HttpClient, HttpMethod, HttpRequest, Idempotency, RPC_RESPONSE_CAP_BYTES,
};

/// What the two RPC endpoints jointly said about one transaction.
///
/// Produced here and projected into `antseal-core` only through
/// [`Self::into_receipt_confirmation`], which keeps every non-agreed outcome
/// on this side of the boundary. That is A17's "type-level or test-enforced
/// separation": core's [`ReceiptConfirmation`] has no failure variant, so no
/// verdict rule can branch on one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArbitrumConfirmation {
    /// Both endpoints returned a receipt and the tuples are equal.
    /// Renders as "corroborated by 2 of 2 endpoints".
    Agreed(ReceiptFacts),
    /// Both returned a receipt and some field differs. **Advisory-degraded**:
    /// "endpoints disagree — not corroborated", with both values shown.
    Disagreed {
        /// The first endpoint's facts.
        first: ReceiptFacts,
        /// The second endpoint's facts.
        second: ReceiptFacts,
    },
    /// One endpoint returned a receipt and the other returned `null`.
    /// **Advisory-degraded**: "corroborated by 1 of 2", explicitly not
    /// presented as corroboration.
    Lagging {
        /// Index of the endpoint that saw the transaction: 0 or 1.
        seen_by: usize,
        /// What that endpoint said.
        facts: ReceiptFacts,
    },
    /// Both endpoints agreed the transaction is not on chain.
    Absent,
    /// One or both endpoints errored, timed out, or failed the chain-id
    /// guard. Renders as "could not be checked".
    ///
    /// Carries the failures rather than D55 §4's bare `failed: usize`: §3 of
    /// the same decision requires the chain-id mismatch to be reported "with
    /// a message that names the expected and reported ids", which a count
    /// cannot do. [`Self::failed`] recovers the count.
    Unavailable {
        /// Per-endpoint failures, in endpoint order. Never empty.
        failures: Vec<EndpointFailure>,
    },
}

impl ArbitrumConfirmation {
    /// How many endpoints failed: 0, 1 or 2.
    #[must_use]
    pub fn failed(&self) -> usize {
        match self {
            Self::Unavailable { failures } => failures.len(),
            _ => 0,
        }
    }

    /// Project into the only receipt type `antseal-core` accepts.
    ///
    /// Agreement — including agreed absence — crosses; nothing else does.
    /// `Disagreed`, `Lagging` and `Unavailable` are the *absence* of evidence
    /// and are represented as `None`, so a renderer that wants to say
    /// "corroborated by 1 of 2" reads this type and core never sees a partial
    /// corroboration it might treat as a whole one.
    #[must_use]
    pub const fn into_receipt_confirmation(&self) -> Option<ReceiptConfirmation> {
        match self {
            Self::Agreed(facts) => Some(ReceiptConfirmation::Agreed(*facts)),
            Self::Absent => Some(ReceiptConfirmation::NotOnChain),
            Self::Disagreed { .. } | Self::Lagging { .. } | Self::Unavailable { .. } => None,
        }
    }
}

/// Confirm `tx_hash` against `network`'s RPC pair.
///
/// `tx_hash` is the 32-byte transaction hash from the S7 payment receipt.
/// Both endpoints are queried concurrently; each is chain-id guarded before
/// its receipt is read.
pub fn confirm_arbitrum_tx(
    client: &HttpClient,
    pair: &EndpointPair,
    network: NetworkId,
    tx_hash: &[u8; 32],
) -> ArbitrumConfirmation {
    let agreement = fetch_and_agree(client, pair, |client, endpoint| {
        receipt_facts(client, endpoint, network, tx_hash)
    });
    project(agreement)
}

/// The three-outcome primitive, mapped onto A17's five.
///
/// Separated from [`confirm_arbitrum_tx`] so every one of the five is
/// reachable in a test from constructed inputs, including the two a live pair
/// almost never produces.
#[must_use]
pub fn project(agreement: Agreement<Option<ReceiptFacts>>) -> ArbitrumConfirmation {
    match agreement {
        Agreement::Agreed(Some(facts)) => ArbitrumConfirmation::Agreed(facts),
        Agreement::Agreed(None) => ArbitrumConfirmation::Absent,
        Agreement::Disagreed {
            first: Some(first),
            second: Some(second),
        } => ArbitrumConfirmation::Disagreed { first, second },
        Agreement::Disagreed {
            first: Some(facts),
            second: None,
        } => ArbitrumConfirmation::Lagging { seen_by: 0, facts },
        Agreement::Disagreed {
            first: None,
            second: Some(facts),
        } => ArbitrumConfirmation::Lagging { seen_by: 1, facts },
        // `Disagreed { None, None }` is unrepresentable: `must_agree` builds
        // that arm only when the two values differ, and `None == None`.
        Agreement::Disagreed {
            first: None,
            second: None,
        } => ArbitrumConfirmation::Absent,
        Agreement::Unavailable { failures } => ArbitrumConfirmation::Unavailable { failures },
    }
}

/// One endpoint's answer: chain-id guard, then receipt.
fn receipt_facts(
    client: &HttpClient,
    endpoint: &Endpoint,
    network: NetworkId,
    tx_hash: &[u8; 32],
) -> Result<Option<ReceiptFacts>, EndpointFailure> {
    guard_chain_id(client, endpoint, network)?;

    let params = format!("[\"0x{}\"]", hex(tx_hash));
    let result = rpc(client, endpoint, METHOD_GET_TRANSACTION_RECEIPT, &params)?;
    if result.is_null() {
        return Ok(None);
    }
    let receipt = result
        .as_object()
        .ok_or_else(|| EndpointFailure::payload(endpoint, "receipt result is not an object"))?;

    // The endpoint must be answering about the transaction we asked about.
    // Not part of the compared tuple — it is a per-endpoint validity check,
    // because an endpoint that answers about a *different* transaction is
    // malformed, and letting that reach the comparison would turn one
    // endpoint's substitution into a `Disagreed` rendered as "the other one
    // might be lying".
    let echoed = hex_bytes32(receipt.get("transactionHash")).ok_or_else(|| {
        EndpointFailure::payload(endpoint, "receipt has no usable transactionHash")
    })?;
    if &echoed != tx_hash {
        return Err(EndpointFailure::payload(
            endpoint,
            "receipt is for a different transaction than the one requested",
        ));
    }

    let status = hex_u64(receipt.get("status"))
        .and_then(|value| u8::try_from(value).ok())
        .ok_or_else(|| EndpointFailure::payload(endpoint, "receipt has no usable status"))?;
    let block_number = hex_u64(receipt.get("blockNumber"))
        .ok_or_else(|| EndpointFailure::payload(endpoint, "receipt has no usable blockNumber"))?;
    let block_hash = hex_bytes32(receipt.get("blockHash"))
        .ok_or_else(|| EndpointFailure::payload(endpoint, "receipt has no usable blockHash"))?;

    Ok(Some(ReceiptFacts {
        status,
        block_number,
        block_hash,
    }))
}

/// `eth_chainId` must equal the network's own id before anything this
/// endpoint says about a receipt is used.
fn guard_chain_id(
    client: &HttpClient,
    endpoint: &Endpoint,
    network: NetworkId,
) -> Result<(), EndpointFailure> {
    let Some(expected) = expected_chain_id(network) else {
        // Devnet: `verify_rpcs` is `None` and no pair exists, so this is
        // unreachable through `confirm_arbitrum_tx`. Refused rather than
        // waved through, because "no expected id" must never mean "any id".
        return Err(EndpointFailure::payload(
            endpoint,
            "this network has no advisory RPC overlay",
        ));
    };
    let reported = hex_u64(Some(&rpc(client, endpoint, METHOD_CHAIN_ID, "[]")?))
        .ok_or_else(|| EndpointFailure::payload(endpoint, "eth_chainId reply is not a quantity"))?;
    if reported == expected {
        return Ok(());
    }
    Err(EndpointFailure::WrongChain {
        endpoint: endpoint.url().to_owned(),
        expected,
        reported,
    })
}

/// One JSON-RPC round trip, returning the `result` member.
fn rpc(
    client: &HttpClient,
    endpoint: &Endpoint,
    method: &str,
    params: &str,
) -> Result<Value, EndpointFailure> {
    let body = format!(r#"{{"jsonrpc":"2.0","id":1,"method":"{method}","params":{params}}}"#);
    let request = HttpRequest {
        endpoint,
        method: HttpMethod::Post,
        content_type: Some(RPC_CONTENT_TYPE),
        accept: Some(RPC_CONTENT_TYPE),
        body: body.as_bytes(),
        receive_cap_bytes: RPC_RESPONSE_CAP_BYTES,
        // A POST by transport, a read by semantics: repeating
        // `eth_getTransactionReceipt` has no server-side effect.
        idempotency: Idempotency::SafeToRepeat,
    };
    let response = client.send(&request).map_err(EndpointFailure::Http)?;

    // Default recursion limit (128), so adversarial nesting is an error and
    // not a stack overflow.
    let envelope: Value = serde_json::from_slice(&response.body)
        .map_err(|_| EndpointFailure::payload(endpoint, "reply is not JSON"))?;
    if envelope.get("error").is_some_and(|error| !error.is_null()) {
        // A JSON-RPC error is a *200 with an error member* — the substrate
        // never sees it as a failure, so it is classified here or it is
        // silently read as a missing result.
        return Err(EndpointFailure::payload(
            endpoint,
            "the endpoint returned a JSON-RPC error",
        ));
    }
    envelope
        .get("result")
        .cloned()
        .ok_or_else(|| EndpointFailure::payload(endpoint, "reply carries no result member"))
}

/// A `0x`-prefixed EVM quantity as a `u64`.
///
/// Leading zeros and mixed case are accepted, which is what makes `0x1` and
/// `0x01` and `0xA4B1` and `0xa4b1` compare equal after extraction (D55 §3).
fn hex_u64(value: Option<&Value>) -> Option<u64> {
    let text = value?.as_str()?;
    let digits = text
        .strip_prefix("0x")
        .or_else(|| text.strip_prefix("0X"))?;
    if digits.is_empty() || digits.len() > 16 {
        return None;
    }
    u64::from_str_radix(digits, 16).ok()
}

/// A `0x`-prefixed 32-byte hash.
fn hex_bytes32(value: Option<&Value>) -> Option<[u8; 32]> {
    let text = value?.as_str()?;
    let digits = text
        .strip_prefix("0x")
        .or_else(|| text.strip_prefix("0X"))?;
    if digits.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (byte, pair) in out.iter_mut().zip(digits.as_bytes().chunks_exact(2)) {
        let high = (pair[0] as char).to_digit(16)?;
        let low = (pair[1] as char).to_digit(16)?;
        *byte = u8::try_from(high * 16 + low).ok()?;
    }
    Some(out)
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from_digit(u32::from(byte >> 4), 16).unwrap_or('0'));
        out.push(char::from_digit(u32::from(byte & 0x0f), 16).unwrap_or('0'));
    }
    out
}

#[cfg(test)]
mod tests;
