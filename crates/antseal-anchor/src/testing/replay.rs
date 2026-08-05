//! A24's recorded-exchange servers: mock TSA, mock calendar, stub esplora and
//! stub Arbitrum RPC, all replaying **real committed captures** over
//! [`StubServer`](super::stub::StubServer).
//!
//! # Why replay rather than synthesise
//!
//! A stub that answers with bytes this project wrote tests the code against
//! its own assumptions. Every reply below is a byte-for-byte capture from a
//! live endpoint, recorded with a `CAPTURE.log` naming the URL, the status,
//! the size and the retrieval time:
//!
//! - `testdata/anchors/A25-bootstrap/` — nine real TSA `TimeStampResp`s, six
//!   pending calendar timestamps from three calendars over two digests, five
//!   root certificates (A25's bootstrap capture, 2026-08-02);
//! - `testdata/anchors/A16-A17-live/` — both esplora services' height, header
//!   and not-found replies, and four Arbitrum receipts across two networks
//!   (2026-08-03).
//!
//! That is what makes the CI lane evidence rather than theatre, and it is why
//! the fixtures are committed rather than fetched: **CI contacts nothing**
//! (Q16), and a loopback listener cannot.
//!
//! # The signing half, and where it went (A59, 2026-08-05)
//!
//! A24's *signing* mock TSA is **not in this module**, and the earlier note
//! here was right about why: `cms`, `x509-cert`, `rsa` and `p384` are declared
//! by `antseal-core` and nowhere else (A30's containment rule), so a
//! token-minting crate is not this one. Two things that note got wrong, both
//! corrected here:
//!
//! - *"It also needs A6's root-store injection API, which has not landed."* —
//!   it **has**: `TsaRootStore::from_static`, gated on the same `test-util`.
//! - A30's rule reads as a *blocker* and is a **placement constraint**. It
//!   does not stop the mock existing; it says where it must live, which is
//!   `antseal_core::anchor::testing` — the one crate already declaring the
//!   pins. Reading it as a blocker is what kept A59 filed rather than done.
//!
//! What lives here is the transport half that reaches it:
//! [`signing_tsa`], over [`StubReply::Computed`]. Replay covers the recorded
//! shapes A16/A17/A42 need; a *signed* answer to a *live* nonce needs the
//! minter, and the two meet at a closure.

use std::time::Duration;

use super::stub::{StubMatch, StubReply, StubScript};

/// The committed captures, as bytes. Paths are relative to this file so a
/// moved fixture is a compile error rather than a runtime skip.
pub mod fixtures {
    /// esplora: height → block hash, block 800000 (64 ASCII hex, no newline).
    pub const BLOCKSTREAM_HEIGHT: &[u8] = include_bytes!(
        "../../../../testdata/anchors/A16-A17-live/esplora-blockstream-height-800000.txt"
    );
    /// esplora: the 80-byte header as 160 ASCII hex, from blockstream.info.
    pub const BLOCKSTREAM_HEADER: &[u8] = include_bytes!(
        "../../../../testdata/anchors/A16-A17-live/esplora-blockstream-header-800000.txt"
    );
    /// The same header from mempool.space. **Byte-identical** to
    /// [`BLOCKSTREAM_HEADER`]; committed separately so the test that asserts
    /// that has two files to compare rather than one file compared to itself.
    pub const MEMPOOL_HEADER: &[u8] = include_bytes!(
        "../../../../testdata/anchors/A16-A17-live/esplora-mempool-header-800000.txt"
    );
    /// esplora's 404 body for a height beyond the tip. Both services.
    pub const ESPLORA_NO_SUCH_BLOCK: &[u8] = include_bytes!(
        "../../../../testdata/anchors/A16-A17-live/esplora-blockstream-404-body.txt"
    );

    /// arbitrum-one receipt from `arb1.arbitrum.io` (1786 B).
    pub const ARBONE_RECEIPT_ARB1: &[u8] =
        include_bytes!("../../../../testdata/anchors/A16-A17-live/arbone-arb1-receipt.json");
    /// The same receipt from `arbitrum.drpc.org` (1785 B) — same key set,
    /// different envelope key order, so the bodies differ and the tuple does
    /// not.
    pub const ARBONE_RECEIPT_DRPC: &[u8] =
        include_bytes!("../../../../testdata/anchors/A16-A17-live/arbone-drpc-receipt.json");
    /// arbitrum-sepolia receipt carrying `timeboosted` and not `blobGasUsed`.
    pub const SEPOLIA_RECEIPT_ROLLUP: &[u8] =
        include_bytes!("../../../../testdata/anchors/A16-A17-live/sepolia-rollup-receipt.json");
    /// The same receipt carrying `blobGasUsed` and not `timeboosted` —
    /// D55 §3's key-set finding, as two committed files.
    pub const SEPOLIA_RECEIPT_DRPC: &[u8] =
        include_bytes!("../../../../testdata/anchors/A16-A17-live/sepolia-drpc-receipt.json");

    /// A real pending calendar attestation (alice, digest A, 207 B).
    pub const CALENDAR_ALICE_A: &[u8] =
        include_bytes!("../../../../testdata/anchors/A25-bootstrap/A-alice.timestamp");
    /// A real pending calendar attestation (bob, digest A, 170 B).
    pub const CALENDAR_BOB_A: &[u8] =
        include_bytes!("../../../../testdata/anchors/A25-bootstrap/A-bob.timestamp");
    /// A real pending calendar attestation (catallaxy, digest A, 220 B) —
    /// **the largest of the 18 measured**, and the fixture the F4 row for
    /// `MAX_OTS_CALENDAR_RESPONSE_BYTES` is measured against.
    pub const CALENDAR_CATALLAXY_A: &[u8] =
        include_bytes!("../../../../testdata/anchors/A25-bootstrap/A-catallaxy.timestamp");

    /// The same three calendars over the second golden-vector digest, whose
    /// arithmetic differs (170/207/185 B, merging to 629 B not 664 B).
    pub const CALENDAR_ALICE_B: &[u8] =
        include_bytes!("../../../../testdata/anchors/A25-bootstrap/B-alice.timestamp");
    /// See [`CALENDAR_ALICE_B`].
    pub const CALENDAR_BOB_B: &[u8] =
        include_bytes!("../../../../testdata/anchors/A25-bootstrap/B-bob.timestamp");
    /// See [`CALENDAR_ALICE_B`].
    pub const CALENDAR_CATALLAXY_B: &[u8] =
        include_bytes!("../../../../testdata/anchors/A25-bootstrap/B-catallaxy.timestamp");

    /// The 3-calendar merged pending `.ots` for digest A, committed by A11
    /// and rebuilt byte-identically by A13's writer.
    pub const MERGED_A: &[u8] =
        include_bytes!("../../../../testdata/anchors/A25-bootstrap/merged-A.ots");
    /// The same for digest B.
    pub const MERGED_B: &[u8] =
        include_bytes!("../../../../testdata/anchors/A25-bootstrap/merged-B.ots");

    /// Golden-vector `anchor_digest` A — what `MERGED_A` stamps.
    pub const DIGEST_A: [u8; 32] =
        *include_bytes!("../../../../testdata/anchors/A25-bootstrap/digest-A.bin");
    /// Golden-vector `anchor_digest` B.
    pub const DIGEST_B: [u8; 32] =
        *include_bytes!("../../../../testdata/anchors/A25-bootstrap/digest-B.bin");

    // ── the day-2 upgrade capture (2026-08-03T09:03Z) ──────────────────────
    //
    // Real Bitcoin attestations for the same six pending stamps, retrieved
    // 13 h 47 m after submission — the estimate said "not before
    // 2026-08-04". These are the bodies of `200` responses to
    // `GET <calendar>/timestamp/<hex-commitment>`; each is a timestamp body
    // rooted at that pending attestation's commitment, NOT a `.ots` file.

    /// alice's upgrade for digest A — **1000 B**.
    pub const UPGRADE_A_ALICE: &[u8] =
        include_bytes!("../../../../testdata/anchors/A25-bootstrap/upgraded/A-alice.upgrade");
    /// bob's upgrade for digest A — **1036 B**.
    pub const UPGRADE_A_BOB: &[u8] =
        include_bytes!("../../../../testdata/anchors/A25-bootstrap/upgraded/A-bob.upgrade");
    /// catallaxy's upgrade for digest A — **1105 B**, the largest of the six
    /// and the figure A42's F4 margin is completed from.
    pub const UPGRADE_A_CATALLAXY: &[u8] =
        include_bytes!("../../../../testdata/anchors/A25-bootstrap/upgraded/A-catallaxy.upgrade");
    /// alice's upgrade for digest B.
    pub const UPGRADE_B_ALICE: &[u8] =
        include_bytes!("../../../../testdata/anchors/A25-bootstrap/upgraded/B-alice.upgrade");
    /// bob's upgrade for digest B.
    pub const UPGRADE_B_BOB: &[u8] =
        include_bytes!("../../../../testdata/anchors/A25-bootstrap/upgraded/B-bob.upgrade");
    /// catallaxy's upgrade for digest B.
    pub const UPGRADE_B_CATALLAXY: &[u8] =
        include_bytes!("../../../../testdata/anchors/A25-bootstrap/upgraded/B-catallaxy.upgrade");

    /// The **9-byte** body a calendar returns with `404` for a commitment it
    /// does not know — captured 2026-08-03T09:04Z against a deliberately
    /// one-byte-corrupted commitment, identical from alice and bob.
    ///
    /// The hard-error half of D58 §7.4's three-way discriminator, as bytes.
    pub const CALENDAR_NOT_FOUND: &[u8] =
        include_bytes!("../../../../testdata/anchors/A25-bootstrap/upgraded/notfound-alice.body");

    /// The **42-byte** body the same `404` carries for a real commitment that
    /// is not yet in a block (D58 §7.4, measured 2026-08-02T19:34:10Z).
    ///
    /// Not a captured file: by the time this lane ran, every committed
    /// commitment had upgraded, so the pending response for these six can
    /// never be re-observed. D58 recorded it verbatim and this is that
    /// transcription — which is why the classifier compares **trimmed
    /// content** and never a length: D90 measured the same body at 9 and 10
    /// bytes from different calendars, one with a trailing newline.
    pub const CALENDAR_PENDING_BODY: &[u8] = b"Pending confirmation in Bitcoin blockchain";

    /// A real granted `TimeStampResp` (FreeTSA, ECDSA P-384).
    pub const TSA_FREETSA: &[u8] =
        include_bytes!("../../../../testdata/anchors/A25-bootstrap/D60-tsa-freetsa-resp.tsr");
    /// A real granted `TimeStampResp` (DigiCert, RSA).
    pub const TSA_DIGICERT: &[u8] =
        include_bytes!("../../../../testdata/anchors/A25-bootstrap/D60-tsa-digicert-resp.tsr");
    /// The request that produced [`TSA_FREETSA`], for a stub that asserts it
    /// was asked the right question.
    pub const TSA_FREETSA_REQ: &[u8] =
        include_bytes!("../../../../testdata/anchors/A25-bootstrap/D60-tsa-freetsa-req.tsq");
}

/// The block height the committed esplora captures are for.
pub const RECORDED_HEIGHT: u64 = 800_000;

/// The request line of a recorded request, for tests that assert which
/// question an endpoint was asked.
#[must_use]
pub fn request_line(request: &[u8]) -> String {
    let end = request
        .windows(2)
        .position(|window| window == b"\r\n")
        .unwrap_or(request.len());
    String::from_utf8_lossy(&request[..end]).into_owned()
}

/// What a stub esplora endpoint does.
#[derive(Debug, Clone)]
pub enum EsploraBehaviour {
    /// Serve the recorded hash and the given header hex — pass
    /// [`fixtures::BLOCKSTREAM_HEADER`] for the honest answer, or any other
    /// 160-character hex string to make the pair disagree.
    Header(Vec<u8>),
    /// 404 `Block not found` at the height step: the agreed-absence case.
    NoSuchBlock,
    /// 404 `endpoint does not exist "…"` — what a **mistyped base URL**
    /// produces on both real services. Distinct from [`Self::NoSuchBlock`]
    /// and must never be read as one: an agreed absence refutes an `.ots`.
    WrongPath,
    /// Serve a header that is not 160 hex characters.
    ShortHeader,
    /// Answer the height query with something that is not a block hash — the
    /// shape that would let an endpoint steer the second GET's path.
    HostileHash(&'static str),
    /// Accept and close without answering: the endpoint-down case.
    Down,
    /// Answer, but only after `Duration` — a slow but healthy endpoint.
    Slow(Duration),
}

/// Build a routed script for one stub esplora endpoint.
///
/// Routed rather than sequential, because the client issues two different
/// GETs and a sequential script would hand back the wrong body if the client
/// ever retried one of them (see [`super::stub`]).
#[must_use]
pub fn esplora(behaviour: &EsploraBehaviour) -> StubScript {
    let height_target = format!("/block-height/{RECORDED_HEIGHT}");
    match behaviour {
        EsploraBehaviour::Header(hex) => StubScript::new()
            .route(
                StubMatch::target(height_target),
                text(200, fixtures::BLOCKSTREAM_HEIGHT.to_vec()),
            )
            .route(StubMatch::target("/header"), text(200, hex.clone())),
        EsploraBehaviour::NoSuchBlock => StubScript::new().route(
            StubMatch::target(height_target),
            text(404, fixtures::ESPLORA_NO_SUCH_BLOCK.to_vec()),
        ),
        EsploraBehaviour::WrongPath => StubScript::new().route(
            StubMatch::target(height_target),
            text(
                404,
                br#"endpoint does not exist "/api/block-height/800000""#.to_vec(),
            ),
        ),
        EsploraBehaviour::ShortHeader => StubScript::new()
            .route(
                StubMatch::target(height_target),
                text(200, fixtures::BLOCKSTREAM_HEIGHT.to_vec()),
            )
            .route(
                StubMatch::target("/header"),
                text(200, b"00601d34".to_vec()),
            ),
        EsploraBehaviour::HostileHash(hash) => StubScript::new()
            .route(
                StubMatch::target(height_target),
                text(200, hash.as_bytes().to_vec()),
            )
            .route(
                StubMatch::target("/"),
                text(200, b"the endpoint chose this path".to_vec()),
            ),
        EsploraBehaviour::Down => StubScript::new().always(StubReply::DropConnection),
        EsploraBehaviour::Slow(delay) => StubScript::new()
            .route(
                StubMatch::target(height_target),
                slow(*delay, fixtures::BLOCKSTREAM_HEIGHT.to_vec()),
            )
            .route(
                StubMatch::target("/header"),
                slow(*delay, fixtures::BLOCKSTREAM_HEADER.to_vec()),
            ),
    }
}

/// The recorded header, with one hex digit changed — a disagreeing endpoint
/// that is otherwise perfectly well-formed.
#[must_use]
pub fn tampered_header() -> Vec<u8> {
    let mut hex = fixtures::BLOCKSTREAM_HEADER.to_vec();
    // The last nibble of the nonce field: still valid hex, still 160
    // characters, so nothing but the comparison can catch it.
    let last = hex.len() - 1;
    hex[last] = if hex[last] == b'6' { b'7' } else { b'6' };
    hex
}

/// What a stub Arbitrum RPC endpoint does.
#[derive(Debug, Clone)]
pub enum RpcBehaviour {
    /// Report `chain_id_hex` and serve `receipt` verbatim.
    Receipt {
        /// The `eth_chainId` result, e.g. `"0xa4b1"`.
        chain_id_hex: &'static str,
        /// A full recorded JSON-RPC envelope.
        receipt: Vec<u8>,
    },
    /// Report `chain_id_hex` and answer `"result":null` — the transaction is
    /// not on this endpoint's chain view.
    Absent {
        /// The `eth_chainId` result.
        chain_id_hex: &'static str,
    },
    /// Report a chain id and never get asked about a receipt, because the
    /// guard refuses first.
    WrongChain {
        /// The `eth_chainId` result the endpoint reports.
        chain_id_hex: &'static str,
    },
    /// Accept and close: the endpoint-down case.
    Down,
    /// A well-formed JSON-RPC **error** member on a 200, which the HTTP
    /// substrate cannot see as a failure.
    JsonRpcError {
        /// The `eth_chainId` result.
        chain_id_hex: &'static str,
    },
}

/// Build a routed script for one stub Arbitrum RPC endpoint.
///
/// Routed on the **body**, because `eth_chainId` and
/// `eth_getTransactionReceipt` arrive at the same path — a sequential script
/// could not tell them apart, and would answer whichever came second with the
/// other one's body.
#[must_use]
pub fn rpc(behaviour: &RpcBehaviour) -> StubScript {
    let chain = |hex: &str| {
        json(
            200,
            format!(r#"{{"jsonrpc":"2.0","id":1,"result":"{hex}"}}"#),
        )
    };
    match behaviour {
        RpcBehaviour::Receipt {
            chain_id_hex,
            receipt,
        } => StubScript::new()
            .route(StubMatch::body(b"eth_chainId"), chain(chain_id_hex))
            .route(
                StubMatch::body(b"eth_getTransactionReceipt"),
                json_bytes(200, receipt.clone()),
            ),
        RpcBehaviour::Absent { chain_id_hex } => StubScript::new()
            .route(StubMatch::body(b"eth_chainId"), chain(chain_id_hex))
            .route(
                StubMatch::body(b"eth_getTransactionReceipt"),
                json(200, r#"{"jsonrpc":"2.0","id":1,"result":null}"#.to_owned()),
            ),
        RpcBehaviour::WrongChain { chain_id_hex } => StubScript::new()
            .route(StubMatch::body(b"eth_chainId"), chain(chain_id_hex))
            .route(
                StubMatch::body(b"eth_getTransactionReceipt"),
                // Deliberately a perfectly good answer: the test proves the
                // guard refused *before* this could be used, which a stub
                // that returned an error here could not distinguish.
                json_bytes(200, fixtures::ARBONE_RECEIPT_ARB1.to_vec()),
            ),
        RpcBehaviour::Down => StubScript::new().always(StubReply::DropConnection),
        RpcBehaviour::JsonRpcError { chain_id_hex } => StubScript::new()
            .route(StubMatch::body(b"eth_chainId"), chain(chain_id_hex))
            .route(
                StubMatch::body(b"eth_getTransactionReceipt"),
                json(
                    200,
                    r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"archive data unavailable"}}"#
                        .to_owned(),
                ),
            ),
    }
}

/// What a stub OpenTimestamps calendar does.
///
/// Every variant answers **both** legs — the submit POST and the upgrade GET —
/// because A15 polls a calendar it never submitted to in the same process, and
/// a script that only answered one leg would make the other leg's failure look
/// like the behaviour under test.
#[derive(Debug, Clone)]
pub enum CalendarBehaviour {
    /// Accept the submit with `pending`, and answer every upgrade poll with
    /// the `404` + 42-byte body a real calendar returns for a commitment it
    /// knows but has not yet buried.
    PendingSubmit(Vec<u8>),
    /// Accept the submit with `pending`, and answer upgrade polls with `200`
    /// and `upgrade` — the day-2 transition.
    Upgraded {
        /// The submit response.
        pending: Vec<u8>,
        /// The upgrade response body.
        upgrade: Vec<u8>,
    },
    /// Answer every upgrade poll with the `404` + 9-byte `Not found` body:
    /// the calendar does not know this commitment. A **hard** error — the
    /// submission was lost or the commitment was derived wrongly, and
    /// re-polling forever will not fix it.
    NotFound,
    /// A `404` whose body is neither discriminator — the shape that must not
    /// be read as either one, exactly as A16 refuses to read a mistyped-path
    /// 404 as an absent block.
    UnknownFourOhFour(&'static str),
    /// Accept and close without answering: the endpoint-down case, and the
    /// third behaviour the live capture found (catallaxy answered *nothing*
    /// to a corrupted-commitment poll, `http=000`).
    Down,
    /// A 500 on the submit leg.
    ServerError,
    /// Answer the submit, slowly. For budget tests.
    Slow(Duration, Vec<u8>),
    /// Answer the submit with more bytes than
    /// [`MAX_OTS_CALENDAR_RESPONSE_BYTES`](crate::ots::MAX_OTS_CALENDAR_RESPONSE_BYTES)
    /// admits, so the cap is exercised as a typed error rather than a
    /// truncation.
    Oversize,
    /// Answer the submit with a well-formed 200 whose body is not a timestamp
    /// at all.
    Garbage(Vec<u8>),
}

/// Build a routed script for one stub calendar.
///
/// Routed rather than sequential: submit and upgrade are different paths on
/// one host, and a sequential script would hand an upgrade poll the submit
/// body if the client ever retried.
#[must_use]
pub fn calendar(behaviour: &CalendarBehaviour) -> StubScript {
    let submit = |bytes: Vec<u8>| StubReply::Body {
        status: 200,
        content_type: "application/vnd.opentimestamps.v1",
        bytes,
    };
    let pending_404 = || text(404, fixtures::CALENDAR_PENDING_BODY.to_vec());

    match behaviour {
        CalendarBehaviour::PendingSubmit(pending) => StubScript::new()
            .route(StubMatch::target("digest"), submit(pending.clone()))
            .route(StubMatch::target("timestamp/"), pending_404()),
        CalendarBehaviour::Upgraded { pending, upgrade } => StubScript::new()
            .route(StubMatch::target("digest"), submit(pending.clone()))
            .route(
                StubMatch::target("timestamp/"),
                StubReply::Body {
                    status: 200,
                    content_type: "application/vnd.opentimestamps.v1",
                    bytes: upgrade.clone(),
                },
            ),
        CalendarBehaviour::NotFound => StubScript::new().route(
            StubMatch::target("timestamp/"),
            text(404, fixtures::CALENDAR_NOT_FOUND.to_vec()),
        ),
        CalendarBehaviour::UnknownFourOhFour(body) => StubScript::new().route(
            StubMatch::target("timestamp/"),
            text(404, body.as_bytes().to_vec()),
        ),
        CalendarBehaviour::Down => StubScript::new().always(StubReply::DropConnection),
        CalendarBehaviour::ServerError => StubScript::new()
            .route(StubMatch::target("digest"), text(500, b"boom".to_vec()))
            .route(StubMatch::target("timestamp/"), text(500, b"boom".to_vec())),
        CalendarBehaviour::Slow(delay, pending) => StubScript::new()
            .route(StubMatch::target("digest"), slow(*delay, pending.clone()))
            .route(StubMatch::target("timestamp/"), pending_404()),
        CalendarBehaviour::Oversize => StubScript::new().route(
            StubMatch::target("digest"),
            StubReply::StreamUntilClosed {
                status: 200,
                content_length: crate::ots::MAX_OTS_CALENDAR_RESPONSE_BYTES * 2,
                chunk_len: 4096,
                stop_after_bytes: crate::ots::MAX_OTS_CALENDAR_RESPONSE_BYTES * 2,
            },
        ),
        CalendarBehaviour::Garbage(bytes) => StubScript::new()
            .route(StubMatch::target("digest"), submit(bytes.clone()))
            .route(StubMatch::target("timestamp/"), pending_404()),
    }
}

/// A mock TSA replaying a recorded `TimeStampResp`.
///
/// Replay answers the nonce of the request it was *recorded* from, so a client
/// that draws a fresh one is always refused. Use [`signing_tsa`] when the test
/// needs the capture to succeed.
#[must_use]
pub fn tsa(response: &[u8]) -> StubScript {
    StubScript::new().always(StubReply::Body {
        status: 200,
        content_type: "application/timestamp-reply",
        bytes: response.to_vec(),
    })
}

/// A mock TSA that **signs**, answering whatever request arrives (A59/A24).
///
/// The `signer` is `antseal_core::anchor::testing::MockTsa`, taken as a
/// closure so this transport module keeps no RFC 3161 knowledge. What it buys
/// over [`tsa`] is the one thing a recording can never do: echo a nonce the
/// client drew a millisecond ago, so a test can drive the whole capture path —
/// fresh CSPRNG draw, real request, real signature, real core verification —
/// to a *success* rather than to a predetermined failure.
///
/// A request the signer cannot answer becomes an empty 200 body, which the
/// capture path reports as an unverifiable token: a broken test never looks
/// like a broken endpoint.
#[must_use]
pub fn signing_tsa(
    signer: impl Fn(&[u8]) -> Option<Vec<u8>> + Send + Sync + 'static,
) -> StubScript {
    StubScript::new().always(StubReply::computed(
        "application/timestamp-reply",
        move |request| signer(request_body(request)).unwrap_or_default(),
    ))
}

/// The body of a raw HTTP request, i.e. everything after the blank line.
///
/// Empty when the request has no head terminator, which is what a truncated
/// read looks like.
#[must_use]
pub fn request_body(request: &[u8]) -> &[u8] {
    match request.windows(4).position(|w| w == b"\r\n\r\n") {
        Some(end) => &request[end + 4..],
        None => &[],
    }
}

/// A correct `200 text/plain` reply, delayed. Used for the concurrency test,
/// where an endpoint must be slow across its **whole** exchange.
fn slow(delay: Duration, bytes: Vec<u8>) -> StubReply {
    StubReply::SlowBody {
        delay,
        status: 200,
        content_type: "text/plain",
        bytes,
    }
}

fn text(status: u16, bytes: Vec<u8>) -> StubReply {
    StubReply::Body {
        status,
        content_type: "text/plain",
        bytes,
    }
}

fn json(status: u16, body: String) -> StubReply {
    json_bytes(status, body.into_bytes())
}

fn json_bytes(status: u16, bytes: Vec<u8>) -> StubReply {
    StubReply::Body {
        status,
        content_type: "application/json",
        bytes,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The captures are what the `CAPTURE.log` says they are. A fixture that
    /// was re-recorded, truncated or swapped fails here rather than three
    /// tests later with a confusing message.
    #[test]
    fn the_committed_captures_have_their_recorded_shapes() {
        assert_eq!(fixtures::BLOCKSTREAM_HEIGHT.len(), 64);
        assert_eq!(fixtures::BLOCKSTREAM_HEADER.len(), 160);
        assert_eq!(fixtures::MEMPOOL_HEADER.len(), 160);
        assert_eq!(fixtures::ESPLORA_NO_SUCH_BLOCK, b"Block not found");
        assert_eq!(fixtures::CALENDAR_CATALLAXY_A.len(), 220);
        assert_eq!(fixtures::ARBONE_RECEIPT_ARB1.len(), 1786);
        assert_eq!(fixtures::ARBONE_RECEIPT_DRPC.len(), 1785);
        assert_eq!(fixtures::SEPOLIA_RECEIPT_ROLLUP.len(), 6975);
        assert_eq!(fixtures::SEPOLIA_RECEIPT_DRPC.len(), 6974);
    }

    /// The property A16's byte-identity rule rests on, asserted against the
    /// two independently captured files rather than against a comment.
    #[test]
    fn the_two_services_returned_the_identical_header() {
        assert_eq!(
            fixtures::BLOCKSTREAM_HEADER,
            fixtures::MEMPOOL_HEADER,
            "two esplora instances must return the same 80 bytes for one height"
        );
    }

    /// The two Arbitrum bodies differ while carrying the same facts — the
    /// measurement that forbids a byte comparator. Asserted on the *fixtures*
    /// so it holds independently of the comparison code.
    #[test]
    fn the_recorded_receipt_pairs_differ_in_bytes() {
        assert_ne!(fixtures::ARBONE_RECEIPT_ARB1, fixtures::ARBONE_RECEIPT_DRPC);
        assert_ne!(
            fixtures::SEPOLIA_RECEIPT_ROLLUP,
            fixtures::SEPOLIA_RECEIPT_DRPC
        );
        // …and the Sepolia pair differs in key set, not merely in ordering.
        let rollup = core::str::from_utf8(fixtures::SEPOLIA_RECEIPT_ROLLUP).expect("utf8");
        let drpc = core::str::from_utf8(fixtures::SEPOLIA_RECEIPT_DRPC).expect("utf8");
        assert!(rollup.contains("timeboosted") && !rollup.contains("blobGasUsed"));
        assert!(drpc.contains("blobGasUsed") && !drpc.contains("timeboosted"));
    }

    /// The tampered header is still well-formed: 160 hex characters, so only
    /// the comparison can reject it. A tamper fixture that was obviously
    /// malformed would test the parser instead of the agreement rule.
    #[test]
    fn the_tampered_header_is_well_formed_and_different() {
        let tampered = tampered_header();
        assert_eq!(tampered.len(), 160);
        assert_ne!(tampered, fixtures::BLOCKSTREAM_HEADER);
        assert!(tampered.iter().all(u8::is_ascii_hexdigit));
    }
}
