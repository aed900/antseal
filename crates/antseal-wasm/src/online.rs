//! The pre-fetched online-evidence document, and the must-agree fold over it.
//!
//! # Why the page hands data in rather than the module fetching it
//!
//! `antseal-core`'s [`VerifyHost`] seam takes **already-collected** data: both
//! its methods are synchronous pure accessors, because a browser `fetch()` is
//! asynchronous and core cannot be. R24's page performs the fetches and feeds
//! the raw answers here; this module turns them into the typed values core
//! accepts. Nothing in this file opens anything — it is a parser and a
//! comparison.
//!
//! # The must-agree rule, mirrored rather than re-invented
//!
//! `antseal-anchor`'s `must_agree` cannot be reused: that crate carries an
//! HTTP client and may never enter this module's graph. Its rule is
//! reproduced exactly, because R27's parity gate compares this page's
//! rendering against the CLI's:
//!
//! * both endpoints answered and their values are **equal** → agreed, and the
//!   value crosses into the evidence path;
//! * both answered and the values **differ** → disagreement. Nothing crosses:
//!   `OnlineBlockResult` has no failure variant by construction (D56 §3), so a
//!   disagreeing pair is the *absence* of evidence and the probe log is the
//!   only place that absence has a reason;
//! * **failure first** — if either endpoint failed, that is the outcome and no
//!   comparison happens. One endpoint's answer is not evidence; the whole
//!   premise of a must-agree pair is that a single endpoint is not trusted, so
//!   "one succeeded, use its value" would quietly delete the property.
//!
//! [`VerifyHost`]: antseal_core::verify::orchestration::VerifyHost

use antseal_core::anchor::model::{
    OnlineBlockResult, OnlineEvidence, ReceiptConfirmation, ReceiptFacts,
};
use antseal_core::bundle::registry::BLOCK_HEADER_LEN;
use antseal_core::verify::orchestration::OnlineInputs;
use antseal_core::verify::overlay::{
    BlockProbe, EndpointProbeFailure, ProbeEndpoints, ProbeFailureClass, ProbeLog, ReceiptProbe,
};
use serde::Deserialize;

use crate::error::BindingError;

/// The document's schema token. A page built against a later shape must say
/// so rather than being parsed leniently into a different meaning.
pub const SCHEMA: &str = "antseal.online-evidence.v1";

/// How many answers a must-agree pair carries. Not a parameter: a pair of one
/// endpoint agrees with itself and proves nothing.
const PAIR: usize = 2;

/// The document page JS supplies to the online entry point.
///
/// `deny_unknown_fields` throughout, on purpose: this arrives as text from a
/// page that may be stale, and a silently-ignored key is a page that believes
/// it disclosed something it did not.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Document {
    /// Must equal [`SCHEMA`].
    schema: String,
    /// The endpoints consulted, for the overlay's disclosure line.
    endpoints: Endpoints,
    /// One entry per probed block height.
    #[serde(default)]
    blocks: Vec<BlockEntry>,
    /// The receipt probe, when the bundle carries a receipt and the page
    /// attempted it. Absent means not attempted.
    #[serde(default)]
    receipt: Option<ReceiptEntry>,
}

/// Which endpoints answered, and whether the page departed from the pinned
/// defaults. `overridden` is **disclosed, never inferred** (D64 §8).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Endpoints {
    identities: Vec<String>,
    overridden: bool,
}

/// One block height and the pair of answers about it.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BlockEntry {
    height: u64,
    responses: Vec<BlockResponse>,
}

/// What one endpoint said about one block.
#[derive(Debug, Deserialize)]
#[serde(tag = "outcome", rename_all = "kebab-case", deny_unknown_fields)]
enum BlockResponse {
    /// The 80-byte header, hex-encoded (160 characters).
    Header { header_hex: String },
    /// The endpoint answered, negatively: there is no such block.
    NoSuchBlock,
    /// The fetch or the parse failed at the page.
    Failed {
        endpoint: String,
        class: FailureClass,
    },
}

/// The receipt pair.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReceiptEntry {
    responses: Vec<ReceiptResponse>,
}

/// What one endpoint said about the receipt transaction.
#[derive(Debug, Deserialize)]
#[serde(tag = "outcome", rename_all = "kebab-case", deny_unknown_fields)]
enum ReceiptResponse {
    /// Confirmed, with the facts the RPC returned.
    Confirmed {
        status: u8,
        block_number: u64,
        /// The block hash, hex-encoded (64 characters).
        block_hash: String,
    },
    /// The endpoint answered, negatively: not on chain.
    NotOnChain,
    /// The fetch or the parse failed at the page.
    Failed {
        endpoint: String,
        class: FailureClass,
    },
}

/// The page's classification of its own fetch failure — A's three classes,
/// spelled as the overlay spells them.
#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum FailureClass {
    Transport,
    Payload,
    WrongChain,
}

impl From<FailureClass> for ProbeFailureClass {
    fn from(class: FailureClass) -> Self {
        match class {
            FailureClass::Transport => Self::Transport,
            FailureClass::Payload => Self::Payload,
            FailureClass::WrongChain => Self::WrongChain,
        }
    }
}

/// Malformed input is an error, never a verdict.
fn malformed(detail: impl Into<String>) -> BindingError {
    BindingError::OnlineEvidence {
        detail: detail.into(),
    }
}

/// Parse the document and fold it into the two things core wants: the agreed
/// evidence, and the probe log the overlay renders its reasons from.
///
/// # Errors
///
/// [`BindingError::OnlineEvidence`] for every malformed shape — an unknown
/// key, a wrong schema token, a pair that is not two, a duplicate height, an
/// unparsable hex string. No input reaches a panic.
pub fn parse(document: &str) -> Result<OnlineInputs, BindingError> {
    let document: Document =
        serde_json::from_str(document).map_err(|error| malformed(error.to_string()))?;

    if document.schema != SCHEMA {
        return Err(malformed(format!(
            "schema is {:?}, expected {SCHEMA:?}",
            document.schema
        )));
    }

    let mut evidence = OnlineEvidence::new();
    let mut probes = ProbeLog::new(ProbeEndpoints::new(
        document.endpoints.identities,
        document.endpoints.overridden,
    ));

    let mut seen: Vec<u64> = Vec::with_capacity(document.blocks.len());
    for entry in &document.blocks {
        if seen.contains(&entry.height) {
            return Err(malformed(format!(
                "block height {} appears twice; one height is one probe",
                entry.height
            )));
        }
        seen.push(entry.height);

        let (agreed, probe) = fold_block(entry)?;
        if let Some(result) = agreed {
            evidence = evidence.with_block(entry.height, result);
        }
        probes = probes.with_block(entry.height, probe);
    }

    if let Some(entry) = &document.receipt {
        let (agreed, probe) = fold_receipt(entry)?;
        if let Some(confirmation) = agreed {
            evidence = evidence.with_receipt(confirmation);
        }
        probes = probes.with_receipt(probe);
    }

    Ok(OnlineInputs::new(evidence, probes))
}

/// The must-agree fold for one block height.
fn fold_block(entry: &BlockEntry) -> Result<(Option<OnlineBlockResult>, BlockProbe), BindingError> {
    let responses = pair(&entry.responses, "block")?;

    // Failure first: one answer is not evidence.
    let failures: Vec<EndpointProbeFailure> = responses
        .iter()
        .filter_map(|response| match response {
            BlockResponse::Failed { endpoint, class } => Some(EndpointProbeFailure {
                endpoint: endpoint.clone(),
                class: (*class).into(),
            }),
            _ => None,
        })
        .collect();
    if !failures.is_empty() {
        return Ok((None, BlockProbe::Failed(failures)));
    }

    let first = block_value(responses[0])?;
    let second = block_value(responses[1])?;
    if first == second {
        Ok((Some(first), BlockProbe::Agreed))
    } else {
        Ok((None, BlockProbe::Disagreed))
    }
}

/// One endpoint's block answer as the value core compares.
fn block_value(response: &BlockResponse) -> Result<OnlineBlockResult, BindingError> {
    match response {
        BlockResponse::Header { header_hex } => {
            let mut header = [0u8; BLOCK_HEADER_LEN as usize];
            decode_hex(header_hex, &mut header, "block header")?;
            Ok(OnlineBlockResult::Header(header))
        }
        BlockResponse::NoSuchBlock => Ok(OnlineBlockResult::NoSuchBlock),
        // Unreachable: `fold_block` returns on any failure before this runs.
        BlockResponse::Failed { .. } => Err(malformed("a failed endpoint has no block value")),
    }
}

/// The must-agree fold for the receipt.
fn fold_receipt(
    entry: &ReceiptEntry,
) -> Result<(Option<ReceiptConfirmation>, ReceiptProbe), BindingError> {
    let responses = pair(&entry.responses, "receipt")?;

    let failures: Vec<EndpointProbeFailure> = responses
        .iter()
        .filter_map(|response| match response {
            ReceiptResponse::Failed { endpoint, class } => Some(EndpointProbeFailure {
                endpoint: endpoint.clone(),
                class: (*class).into(),
            }),
            _ => None,
        })
        .collect();
    if !failures.is_empty() {
        return Ok((None, ReceiptProbe::Failed(failures)));
    }

    let first = receipt_value(responses[0])?;
    let second = receipt_value(responses[1])?;
    if first == second {
        Ok((Some(first), ReceiptProbe::Agreed(first)))
    } else {
        Ok((None, ReceiptProbe::Disagreed))
    }
}

/// One endpoint's receipt answer as the value core compares.
fn receipt_value(response: &ReceiptResponse) -> Result<ReceiptConfirmation, BindingError> {
    match response {
        ReceiptResponse::Confirmed {
            status,
            block_number,
            block_hash,
        } => {
            let mut hash = [0u8; 32];
            decode_hex(block_hash, &mut hash, "receipt block hash")?;
            Ok(ReceiptConfirmation::Agreed(ReceiptFacts {
                status: *status,
                block_number: *block_number,
                block_hash: hash,
            }))
        }
        ReceiptResponse::NotOnChain => Ok(ReceiptConfirmation::NotOnChain),
        // Unreachable: `fold_receipt` returns on any failure before this runs.
        ReceiptResponse::Failed { .. } => Err(malformed("a failed endpoint has no receipt value")),
    }
}

/// Exactly two answers, or a named refusal.
fn pair<'a, T>(responses: &'a [T], what: &str) -> Result<[&'a T; PAIR], BindingError> {
    match responses {
        [first, second] => Ok([first, second]),
        other => Err(malformed(format!(
            "a {what} probe carries {} response(s); a must-agree pair is exactly {PAIR} — one \
             endpoint agrees with itself and proves nothing",
            other.len()
        ))),
    }
}

/// Lowercase-or-uppercase hex into a fixed-size buffer, exact length required.
///
/// Hand-written rather than pulled from a crate: it is fifteen lines, and the
/// alternative is a dependency in a graph whose whole point is that every name
/// in it was argued for.
fn decode_hex(text: &str, out: &mut [u8], what: &str) -> Result<(), BindingError> {
    let expected = out.len() * 2;
    if text.len() != expected {
        return Err(malformed(format!(
            "the {what} is {} characters, expected {expected}",
            text.len()
        )));
    }
    for (byte, pair) in out.iter_mut().zip(text.as_bytes().chunks_exact(2)) {
        match (nibble(pair[0]), nibble(pair[1])) {
            (Some(high), Some(low)) => *byte = (high << 4) | low,
            _ => return Err(malformed(format!("the {what} is not hexadecimal"))),
        }
    }
    Ok(())
}

/// One hex digit's value.
const fn nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}
