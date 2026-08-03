//! The esplora block-header pair (task **A16**).
//!
//! Two independent esplora instances are asked, concurrently, for the raw
//! 80-byte header of Bitcoin block height *H*. The agreed bytes are what A12's
//! embedded header is checked against, and a match is what promotes an OTS
//! anchor from `attested` to `proven` (A18/D56 rules O3/O6/O7).
//!
//! # The API, confirmed against both live services 2026-08-03
//!
//! Recorded in `testdata/anchors/A16-A17-live/CAPTURE.log` and replayed by
//! A24's stubs; CI contacts neither (Q16).
//!
//! | request | reply |
//! | --- | --- |
//! | `GET {base}/block-height/{H}` | `200`, **64 B**, lowercase hex block hash, no trailing newline |
//! | `GET {base}/block/{hash}/header` | `200`, **160 B**, lowercase hex, the 80 raw header bytes |
//! | `GET {base}/block-height/{beyond tip}` | `404`, body exactly `Block not found` |
//! | `GET {base}/no-such-path/…` | `404`, body `endpoint does not exist "…"` |
//! | `GET {base}/block-height/notanumber` | `400`, body `Invalid number` |
//!
//! Both services answered identically on every row, and the two 160-byte
//! headers were **byte-identical**.
//!
//! # Three rules that are not in A16's `Do`, each closing a real hole
//!
//! **1. A 404 is only "no such block" when its body says so.** D56 rule O7
//! makes an agreed absence *refute* an `.ots` that claims a height — it turns
//! an anchor `invalid`. So mapping every 404 to
//! [`OnlineBlockResult::NoSuchBlock`](antseal_core::anchor::model::OnlineBlockResult::NoSuchBlock)
//! hands a **downgrade-to-forgery-accusation** primitive to anyone who can
//! change the endpoint list — or to a plain typo, since a mistyped base URL
//! makes *both* endpoints answer 404 and agree. The bodies are genuinely
//! distinguishable (`Block not found` against `endpoint does not exist "…"`),
//! and the check compares **trimmed content**, never length and never a
//! byte-exact literal, per D90's own caution about calendar 404 bodies.
//! Anything else 404-shaped is an endpoint failure — which renders as "could
//! not be checked" and refutes nothing, the direction D56 §O5 requires.
//!
//! **2. The hash from step 1 is validated before it is put in a URL.** It is
//! an endpoint-controlled string that this code interpolates into the next
//! request path. Sixty-four lowercase hex characters exactly; anything else is
//! a payload failure. Without it an endpoint can steer our second GET at a
//! path of its choosing on its own origin.
//!
//! **3. Each endpoint resolves height → hash → header entirely on its own.**
//! The pair is never asked "here is A's hash, B, what is its header?" — that
//! would let one endpoint choose the other's question, and two headers fetched
//! for one endpoint-supplied hash agree by construction. It costs one extra
//! round trip and it is the difference between corroboration and an echo.
//!
//! # What `Disagreed` means here, and why there is no `Lagging`
//!
//! A17 separates `Lagging` (one endpoint has not caught up) from `Disagreed`
//! because an Arbitrum receipt is re-checked at an arbitrary later time
//! against chains that sync independently. Here the analogous case —
//! `Some(header)` from one endpoint and `NoSuchBlock` from the other —
//! is reported as [`Agreement::Disagreed`], and that is deliberate: the
//! heights A12 asks about come from a Bitcoin attestation that is already
//! buried under confirmations, so a height near enough to the tip for two
//! esplora instances to differ is not a case A12 produces. If A25's live
//! rounds ever observe one, it is the *heights* that need a floor, not this
//! outcome that needs a fourth arm — because a fourth arm would have to be
//! rendered as "corroborated by 1 of 2", and one esplora instance is exactly
//! the trust level A16 exists to avoid.

use antseal_core::anchor::model::OnlineBlockResult;
use antseal_core::bundle::registry::BLOCK_HEADER_LEN;

use crate::agree::{Agreement, EndpointFailure, EndpointPair, fetch_and_agree};
use crate::http::{
    ESPLORA_RESPONSE_CAP_BYTES, Endpoint, HttpClient, HttpMethod, HttpRequest, Idempotency,
};

/// The 80-byte raw Bitcoin block header, as both endpoints returned it.
pub type BlockHeader = [u8; BLOCK_HEADER_LEN as usize];

/// esplora base URLs A16 queries by default, in order.
///
/// Two independent operators, both `https` (their replies are unsigned, so
/// transport is their only integrity control — A49/D90 §6.6). Overridable
/// through U4's `[verify] bitcoin_endpoints`; an override replaces the pair
/// wholesale and must supply exactly two.
pub const DEFAULT_ESPLORA_ENDPOINTS: [&str; 2] =
    ["https://blockstream.info/api", "https://mempool.space/api"];

/// Path segment for the height → hash lookup.
pub const ESPLORA_BLOCK_HEIGHT_PATH: &str = "block-height";
/// Path segment for the hash → header lookup.
pub const ESPLORA_BLOCK_PATH: &str = "block";
/// Trailing segment of the header lookup.
pub const ESPLORA_HEADER_SUFFIX: &str = "header";

/// The 404 body both services return for a height with no block. Compared as
/// trimmed, case-insensitive content — see rule 1 in the module docs.
pub const ESPLORA_NO_SUCH_BLOCK_BODY: &str = "Block not found";

/// A hex block hash is exactly this many characters.
const BLOCK_HASH_HEX_LEN: usize = 64;

/// Fetch the agreed raw header for `height` from both endpoints.
///
/// `Agreed(Some(header))` is the 80 bytes both endpoints returned;
/// `Agreed(None)` is an agreed absence (D56 rule O7). Everything else is
/// [`Agreement::Disagreed`] or [`Agreement::Unavailable`], and neither may be
/// projected into core — see [`into_online_block_result`].
pub fn fetch_agreed_header(
    client: &HttpClient,
    pair: &EndpointPair,
    height: u64,
) -> Agreement<Option<BlockHeader>> {
    fetch_and_agree(client, pair, |client, endpoint| {
        header_at_height(client, endpoint, height)
    })
}

/// Project an agreement into the one type `antseal-core` accepts.
///
/// Only agreement crosses the boundary: A2's `OnlineBlockResult` has no
/// failure variant *by construction* (D56 §3), so a disagreeing or
/// unreachable pair is represented by the absence of the entry and a verdict
/// rule cannot branch on it. The richer outcome stays here, for the overlay.
#[must_use]
pub fn into_online_block_result(
    agreement: &Agreement<Option<BlockHeader>>,
) -> Option<OnlineBlockResult> {
    match agreement.agreed()? {
        Some(header) => Some(OnlineBlockResult::Header(*header)),
        None => Some(OnlineBlockResult::NoSuchBlock),
    }
}

/// One endpoint's own answer: height → hash → header, with no input from the
/// other endpoint at any step.
fn header_at_height(
    client: &HttpClient,
    endpoint: &Endpoint,
    height: u64,
) -> Result<Option<BlockHeader>, EndpointFailure> {
    let Some(hash) = block_hash_at_height(client, endpoint, height)? else {
        return Ok(None);
    };

    let url = join(
        endpoint,
        &format!("{ESPLORA_BLOCK_PATH}/{hash}/{ESPLORA_HEADER_SUFFIX}"),
    );
    let target = reparse(endpoint, &url)?;
    let body = get(client, &target)?;

    // A 404 here is NOT an absent block: step 1 just told us this hash exists
    // at this height, so the endpoint has contradicted itself. Reported as the
    // failure it is, which refutes nothing.
    let hex = as_ascii(&body, endpoint, "header reply is not ASCII")?;
    let hex = hex.trim();
    if hex.len() != BLOCK_HEADER_LEN as usize * 2 {
        return Err(EndpointFailure::payload(
            endpoint,
            "header reply is not 160 hex characters",
        ));
    }
    let mut header = [0u8; BLOCK_HEADER_LEN as usize];
    for (byte, pair) in header.iter_mut().zip(hex.as_bytes().chunks_exact(2)) {
        let (high, low) = (hex_nibble(pair[0]), hex_nibble(pair[1]));
        match (high, low) {
            (Some(high), Some(low)) => *byte = (high << 4) | low,
            _ => {
                return Err(EndpointFailure::payload(
                    endpoint,
                    "header reply is not hexadecimal",
                ));
            }
        }
    }
    Ok(Some(header))
}

/// Step 1. `Ok(None)` is an *attested* absence — a 404 whose body says the
/// height holds no block — and nothing else reaches it.
fn block_hash_at_height(
    client: &HttpClient,
    endpoint: &Endpoint,
    height: u64,
) -> Result<Option<String>, EndpointFailure> {
    let url = join(endpoint, &format!("{ESPLORA_BLOCK_HEIGHT_PATH}/{height}"));
    let target = reparse(endpoint, &url)?;

    let body = match get(client, &target) {
        Ok(body) => body,
        Err(EndpointFailure::Http(crate::http::AnchorHttpError::Status {
            status: 404,
            body,
            ..
        })) if is_no_such_block(&body) => return Ok(None),
        Err(other) => return Err(other),
    };

    let hash = as_ascii(&body, endpoint, "height reply is not ASCII")?
        .trim()
        .to_owned();
    // Validated before it is interpolated into the next request path.
    if hash.len() != BLOCK_HASH_HEX_LEN
        || !hash
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(EndpointFailure::payload(
            endpoint,
            "height reply is not a 64-character lowercase hex block hash",
        ));
    }
    Ok(Some(hash))
}

/// Whether a 404 body is the "this height holds no block" one.
///
/// Trimmed and case-insensitive. `endpoint does not exist "…"` — what a
/// mistyped base URL produces on both real services — is deliberately not
/// matched, because treating it as an agreed absence would let a typo refute
/// an honest anchor.
fn is_no_such_block(body: &[u8]) -> bool {
    core::str::from_utf8(body)
        .is_ok_and(|text| text.trim().eq_ignore_ascii_case(ESPLORA_NO_SUCH_BLOCK_BODY))
}

fn as_ascii<'a>(
    body: &'a [u8],
    endpoint: &Endpoint,
    reason: &'static str,
) -> Result<&'a str, EndpointFailure> {
    core::str::from_utf8(body).map_err(|_| EndpointFailure::payload(endpoint, reason))
}

const fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// `base` + `/` + `path`, with exactly one separator however the base was
/// written. A configured base with a trailing slash is a normal thing for a
/// human to type and must not produce `//block-height/…`.
fn join(endpoint: &Endpoint, path: &str) -> String {
    format!("{}/{path}", endpoint.url().trim_end_matches('/'))
}

/// Re-validate the derived URL under esplora's own transport policy.
///
/// The base was already validated; this exists so the *derived* string is
/// checked as a URL rather than assumed to be one, and under the strict
/// policy rather than whichever one the caller happened to parse the base
/// with — an `Endpoint` obtained under [`TlsPolicy::Optional`] must not be
/// able to smuggle plain HTTP into A16's unsigned-reply path (A49).
fn reparse(_endpoint: &Endpoint, url: &str) -> Result<Endpoint, EndpointFailure> {
    Endpoint::parse(url, crate::http::TlsPolicy::RequiredExceptLoopback)
        .map_err(|error| EndpointFailure::Http(error.into()))
}

fn get(client: &HttpClient, endpoint: &Endpoint) -> Result<Vec<u8>, EndpointFailure> {
    let request = HttpRequest {
        endpoint,
        method: HttpMethod::Get,
        content_type: None,
        accept: Some("text/plain"),
        body: &[],
        receive_cap_bytes: ESPLORA_RESPONSE_CAP_BYTES,
        // A GET against a read-only API: repeating it has no server-side
        // effect, so a pre-send or ambiguous failure may both be retried.
        idempotency: Idempotency::SafeToRepeat,
    };
    client
        .send(&request)
        .map(|response| response.body)
        .map_err(EndpointFailure::Http)
}

#[cfg(test)]
mod tests;
