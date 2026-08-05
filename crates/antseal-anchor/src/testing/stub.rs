//! A24's stub HTTP server: a hand-rolled `std::net::TcpListener` with zero
//! dependencies (D90 Decision 7).
//!
//! No stub-server crate is nominated, and the reason is **capability** rather
//! than package count. The tests this substrate needs are mostly tests of
//! things a correct HTTP server cannot do:
//!
//! - A3 needs a **timeout** — a server that accepts and never answers, and
//!   separately one that sends headers and then stalls;
//! - A5/A21 need **malformed framing** — a truncated body, a `Content-Length`
//!   that lies, a BER-transcoded token;
//! - A16 needs **disagreement** and **one-endpoint-down** — two listeners with
//!   scripted, differing replies, one of them dropping the connection;
//! - A10 needs an **oversized** reply to exercise A28's cap.
//!
//! A raw listener writes the bytes. It also satisfies Q16's
//! no-real-endpoints-in-CI policy *by construction*: it binds
//! `127.0.0.1:0`, and a loopback listener cannot reach a real endpoint.
//!
//! Every connection is served **in a thread of its own** — see [`serve`] for
//! the test that could not fail before that was true — and the reply for a
//! connection is chosen either by position in the script or, for a
//! [`StubScript::route`]d script, by matching the request. Every scripted
//! reply sets `Connection: close`, so `ureq` cannot pool a connection and the
//! recorded request count is the true number of round trips.
//!
//! # Two ways to choose a reply, and why both exist
//!
//! - **Sequential** ([`StubScript::then`] / [`StubScript::always`]) — the
//!   reply is chosen by acceptance order. This is what a retry/backoff test
//!   needs, because "the second attempt sees a different answer" is a
//!   statement about order and nothing else.
//! - **Routed** ([`StubScript::route`]) — the reply is chosen by matching the
//!   request target and/or body. A16's esplora endpoint answers two different
//!   paths in one exchange (height, then header) and A17's RPC endpoint
//!   answers two different JSON-RPC methods on one path, so neither can be
//!   expressed as a fixed sequence: a client that issued the calls in the
//!   other order, or retried one of them, would silently be handed the wrong
//!   body and the test would assert against a fiction.
//!
//! The two modes are mutually exclusive, asserted at [`StubServer::spawn`].

use std::collections::VecDeque;
use std::fmt;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread::{self, JoinHandle};
use std::time::Duration;

/// The largest request the stub will buffer. Larger ones are read and
/// discarded down to this bound, so a send-body test cannot exhaust memory.
const MAX_RECORDED_REQUEST_BYTES: usize = 64 * 1024;

/// What the stub does with one connection.
///
/// The first six arms are D90 Decision 7's; the last two are additions, each
/// tied to a verification obligation the first six cannot express — noted on
/// the variant.
#[derive(Debug, Clone)]
pub enum StubReply {
    /// A well-formed response with a body.
    Body {
        /// Status line code.
        status: u16,
        /// `Content-Type` header value.
        content_type: &'static str,
        /// Body bytes.
        bytes: Vec<u8>,
    },
    /// Byte-exact output, for malformed framing (a lying `Content-Length`, a
    /// truncated body, a bad status line).
    Raw(Vec<u8>),
    /// Read the whole request, then stall for the given duration, then send a
    /// bare `200 OK` with an empty body.
    ///
    /// Two uses, deliberately one variant: with a stall longer than the
    /// client's `recv_response` timeout it produces a receive-phase timeout
    /// *after* the request was delivered (the ambiguous class); with a stall
    /// shorter than it, it is simply a slow endpoint that answers — which is
    /// what the concurrency test needs.
    StallBeforeHeaders(Duration),
    /// Read the request, send the response head announcing a 16-byte body,
    /// stall, then send the 16 bytes. Same two uses as
    /// [`StubReply::StallBeforeHeaders`], one phase later.
    StallAfterHeaders(Duration),
    /// **Addition.** Read the request, stall, then send a full reply.
    ///
    /// [`StubReply::StallBeforeHeaders`] answers with an *empty* body, so a
    /// client that needs the body fails at the first request and never issues
    /// the second — which makes it useless for timing a multi-request
    /// exchange. This one stalls and then answers properly, so a routed
    /// endpoint's whole exchange is slow rather than only its first leg.
    SlowBody {
        /// How long to stall before answering.
        delay: Duration,
        /// Status line code.
        status: u16,
        /// `Content-Type` header value.
        content_type: &'static str,
        /// Body bytes.
        bytes: Vec<u8>,
    },
    /// Accept and close immediately, without reading.
    DropConnection,
    /// A redirect, which this substrate refuses rather than follows.
    Redirect {
        /// 3xx status code.
        status: u16,
        /// `Location` header value.
        location: String,
    },
    /// **Addition.** Accept, read nothing, hold the connection open for the
    /// given duration. The only way to stall a client in the *send* phase:
    /// with a request body larger than the socket buffers, the client's write
    /// blocks and `Timeout(SendBody)` fires.
    AcceptWithoutReading(Duration),
    /// **Addition (A59).** Compute the body **from the request**.
    ///
    /// Every other arm decides its whole body before the connection exists,
    /// which is exactly what a *replaying* stub can do and a *signing* one
    /// cannot: an RFC 3161 token must echo the nonce the client just drew, and
    /// a recording can only ever echo the nonce of the request it was recorded
    /// from. This arm is what lets A24's mock TSA answer a live request, and
    /// therefore what lets a test exercise the nonce comparison end to end
    /// instead of asserting that it fails.
    ///
    /// The closure is supplied by the caller, so this module learns nothing
    /// about RFC 3161 — it stays a transport.
    Computed {
        /// `Content-Type` header value.
        content_type: &'static str,
        /// Request bytes (headers and body, as received) to response body.
        responder: Responder,
    },
    /// **Addition.** Announce `content_length` and then stream `chunk_len`
    /// bytes at a time until the client hangs up or `stop_after_bytes` have
    /// been written, counting every byte into
    /// [`StubServer::bytes_written`].
    ///
    /// D90's `receive_cap_is_enforced_before_the_body_is_buffered` requires
    /// the cap to be observed "by the stub's own write accounting" — which
    /// none of the six variants above can do, because each of them decides
    /// its whole body up front.
    StreamUntilClosed {
        /// Status line code.
        status: u16,
        /// The `Content-Length` to announce — deliberately allowed to be a
        /// lie, since the point is that the client must not trust it.
        content_length: u64,
        /// Bytes per write.
        chunk_len: usize,
        /// Give up after this many bytes, so a client that never closes
        /// cannot hang the test.
        stop_after_bytes: u64,
    },
}

/// The function a [`StubReply::Computed`] arm calls: request bytes in,
/// response-body bytes out.
pub type ResponderFn = dyn Fn(&[u8]) -> Vec<u8> + Send + Sync;

/// A request-to-response-body function, wrapped so [`StubReply`] can keep its
/// `Debug` and `Clone` derives.
#[derive(Clone)]
pub struct Responder(Arc<ResponderFn>);

impl Responder {
    /// Wrap a responder function.
    #[must_use]
    pub fn new(f: impl Fn(&[u8]) -> Vec<u8> + Send + Sync + 'static) -> Self {
        Self(Arc::new(f))
    }
}

impl fmt::Debug for Responder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Responder(<fn>)")
    }
}

impl StubReply {
    /// A reply whose body is computed from the request (A59).
    #[must_use]
    pub fn computed(
        content_type: &'static str,
        f: impl Fn(&[u8]) -> Vec<u8> + Send + Sync + 'static,
    ) -> Self {
        Self::Computed {
            content_type,
            responder: Responder::new(f),
        }
    }

    /// A body reply with a neutral content type.
    #[must_use]
    pub fn body(status: u16, bytes: Vec<u8>) -> Self {
        Self::Body {
            status,
            content_type: "application/octet-stream",
            bytes,
        }
    }
}

/// Which requests a [`StubScript::route`] answers.
///
/// Substring matching rather than exact equality, deliberately: a test that
/// pinned the full request line would break on a client that legitimately
/// changed its `Host` header or query ordering, and the property under test is
/// never "the request line is exactly this" — it is "this endpoint was asked
/// *this question*".
#[derive(Debug, Clone)]
pub enum StubMatch {
    /// The request target (the second token of the request line) contains
    /// this substring. A16's `/api/block-height/800000` vs
    /// `/api/block/<hash>/header`.
    Target(String),
    /// The request body contains these bytes. A17's `"eth_chainId"` vs
    /// `"eth_getTransactionReceipt"`, which arrive at the same path.
    Body(Vec<u8>),
    /// Both.
    TargetAndBody(String, Vec<u8>),
}

impl StubMatch {
    /// A target-substring match.
    #[must_use]
    pub fn target(needle: impl Into<String>) -> Self {
        Self::Target(needle.into())
    }

    /// A body-substring match.
    #[must_use]
    pub fn body(needle: impl AsRef<[u8]>) -> Self {
        Self::Body(needle.as_ref().to_vec())
    }

    fn matches(&self, request: &[u8]) -> bool {
        match self {
            Self::Target(needle) => request_target(request).contains(needle.as_str()),
            Self::Body(needle) => contains(request, needle),
            Self::TargetAndBody(target, body) => {
                request_target(request).contains(target.as_str()) && contains(request, body)
            }
        }
    }
}

/// The replies a [`StubServer`] will give.
#[derive(Debug, Clone, Default)]
pub struct StubScript {
    replies: Vec<StubReply>,
    tail: Option<StubReply>,
    routes: Vec<(StubMatch, StubReply)>,
    unmatched: Option<StubReply>,
}

impl StubScript {
    /// An empty script: the server accepts and closes.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Append one reply, used for the next connection.
    #[must_use]
    pub fn then(mut self, reply: StubReply) -> Self {
        self.replies.push(reply);
        self
    }

    /// Use `reply` for every connection after the scripted ones — including
    /// the first, if none were scripted.
    #[must_use]
    pub fn always(mut self, reply: StubReply) -> Self {
        self.tail = Some(reply);
        self
    }

    /// Answer any request matching `when` with `reply`.
    ///
    /// Routes are tried in the order they were added and the first match
    /// wins. A request matching none is answered with [`Self::unmatched`], or
    /// — if that was not set — with a `404` naming the request target, so a
    /// mis-built client fails with a legible message instead of a parse error
    /// against an empty body.
    #[must_use]
    pub fn route(mut self, when: StubMatch, reply: StubReply) -> Self {
        self.routes.push((when, reply));
        self
    }

    /// The reply for a request no route matched.
    #[must_use]
    pub fn unmatched(mut self, reply: StubReply) -> Self {
        self.unmatched = Some(reply);
        self
    }

    /// Whether this script chooses replies by matching rather than by order.
    #[must_use]
    pub fn is_routed(&self) -> bool {
        !self.routes.is_empty()
    }
}

/// The request line's target, as far as the first CRLF.
fn request_target(request: &[u8]) -> &str {
    let line_end = request
        .windows(2)
        .position(|window| window == b"\r\n")
        .unwrap_or(request.len());
    let line = core::str::from_utf8(&request[..line_end]).unwrap_or("");
    line.split(' ').nth(1).unwrap_or("")
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    needle.is_empty()
        || (haystack.len() >= needle.len() && haystack.windows(needle.len()).any(|w| w == needle))
}

#[derive(Debug, Default)]
struct StubState {
    stop: AtomicBool,
    connections: AtomicUsize,
    bytes_written: AtomicU64,
    requests: Mutex<Vec<Vec<u8>>>,
}

/// A loopback HTTP stub. Shuts down and joins its thread on drop.
#[derive(Debug)]
pub struct StubServer {
    addr: SocketAddr,
    state: Arc<StubState>,
    handle: Option<JoinHandle<()>>,
}

impl StubServer {
    /// Bind `127.0.0.1:0` and start serving `script`.
    ///
    /// # Panics
    ///
    /// If the loopback listener cannot be bound — which in a test process
    /// means the environment, not the code, is broken — or if the script
    /// mixes routed and sequential replies, which has no well-defined
    /// meaning: the routed reply would win and the sequential one would be
    /// silently unreachable, so a test asserting on the latter would pass
    /// against a server that never sent it.
    #[must_use]
    pub fn spawn(script: StubScript) -> Self {
        assert!(
            !(script.is_routed() && (!script.replies.is_empty() || script.tail.is_some())),
            "a StubScript is either routed or sequential, never both"
        );
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind 127.0.0.1:0");
        let addr = listener.local_addr().expect("local_addr");
        listener
            .set_nonblocking(true)
            .expect("a non-blocking listener is what makes shutdown prompt");

        let state = Arc::new(StubState::default());
        let thread_state = Arc::clone(&state);
        let handle = thread::spawn(move || serve(&listener, &thread_state, script));

        Self {
            addr,
            state,
            handle: Some(handle),
        }
    }

    /// `http://127.0.0.1:<port>` — always plain HTTP to a loopback **IP
    /// literal**, which is exactly the shape A49's carve-out admits.
    #[must_use]
    pub fn base_url(&self) -> String {
        format!("http://{}", self.addr)
    }

    /// The raw bytes of every request the stub read, in order.
    #[must_use]
    pub fn requests(&self) -> Vec<Vec<u8>> {
        self.state
            .requests
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// How many connections were accepted. Distinct from
    /// [`StubServer::requests`]: a dropped or unread connection is counted
    /// here and recorded nowhere else.
    #[must_use]
    pub fn connections(&self) -> usize {
        self.state.connections.load(Ordering::SeqCst)
    }

    /// How many body bytes the stub actually wrote — the write accounting a
    /// streaming cap test measures against.
    #[must_use]
    pub fn bytes_written(&self) -> u64 {
        self.state.bytes_written.load(Ordering::SeqCst)
    }
}

impl Drop for StubServer {
    fn drop(&mut self) {
        self.state.stop.store(true, Ordering::SeqCst);
        if let Some(handle) = self.handle.take() {
            // Stalls are served in interruptible slices, so this joins
            // promptly however long a scripted stall was.
            let _ = handle.join();
        }
    }
}

/// Accept connections, handing each the next scripted reply **in a thread of
/// its own**.
///
/// One connection per thread, not one at a time, and the reason is a test
/// that could not fail. A stalling reply holds its connection for as long as
/// the script says; served serially, a client's *retry* would sit unaccepted
/// in the kernel backlog, never be read, and never be recorded — so
/// `requests().len()` would report **1** whether or not the substrate
/// retried, and D90's `post_is_not_retried_after_the_request_was_delivered`
/// would pass against an implementation that retried three times. The reply
/// is still taken from the script in acceptance order, so scripted sequences
/// remain deterministic.
fn serve(listener: &TcpListener, state: &Arc<StubState>, script: StubScript) {
    let routed = script.is_routed();
    let routes = Arc::new(script.routes);
    let unmatched = Arc::new(script.unmatched);
    let mut queued: VecDeque<StubReply> = script.replies.into();
    let mut connections: Vec<JoinHandle<()>> = Vec::new();

    while !state.stop.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((socket, _)) => {
                state.connections.fetch_add(1, Ordering::SeqCst);
                let state = Arc::clone(state);
                if routed {
                    let routes = Arc::clone(&routes);
                    let unmatched = Arc::clone(&unmatched);
                    connections.push(thread::spawn(move || {
                        handle_routed(socket, &state, &routes, unmatched.as_ref().as_ref());
                    }));
                    continue;
                }
                let Some(reply) = queued.pop_front().or_else(|| script.tail.clone()) else {
                    continue;
                };
                connections.push(thread::spawn(move || handle(socket, &state, &reply)));
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(2));
            }
            Err(_) => break,
        }
    }

    for connection in connections {
        let _ = connection.join();
    }
}

/// Read first, then choose. A routed script cannot know which reply a
/// connection wants until the request is on the wire, so the read is
/// unconditional here — which is also why no routed reply may be
/// [`StubReply::DropConnection`] or [`StubReply::AcceptWithoutReading`]:
/// those two are defined by *not* reading, and reaching them through a route
/// would already have read.
fn handle_routed(
    mut socket: TcpStream,
    state: &StubState,
    routes: &[(StubMatch, StubReply)],
    unmatched: Option<&StubReply>,
) {
    let _ = socket.set_read_timeout(Some(Duration::from_secs(5)));
    let _ = socket.set_write_timeout(Some(Duration::from_secs(5)));
    let _ = socket.set_nodelay(true);

    let request = read_request(&mut socket, state);
    let matched = routes
        .iter()
        .find(|(when, _)| when.matches(&request))
        .map(|(_, reply)| reply);

    let fallback;
    let reply = match matched.or(unmatched) {
        Some(reply) => reply,
        None => {
            fallback = StubReply::Body {
                status: 404,
                content_type: "text/plain",
                bytes: format!("no stub route matched {}", request_target(&request)).into_bytes(),
            };
            &fallback
        }
    };
    write_reply(&mut socket, state, reply, &request);
}

fn handle(mut socket: TcpStream, state: &StubState, reply: &StubReply) {
    let _ = socket.set_read_timeout(Some(Duration::from_secs(5)));
    let _ = socket.set_write_timeout(Some(Duration::from_secs(5)));
    let _ = socket.set_nodelay(true);

    let request = match reply {
        StubReply::DropConnection | StubReply::AcceptWithoutReading(_) => Vec::new(),
        _ => read_request(&mut socket, state),
    };

    write_reply(&mut socket, state, reply, &request);
}

fn write_reply(socket: &mut TcpStream, state: &StubState, reply: &StubReply, request: &[u8]) {
    match reply {
        StubReply::Body {
            status,
            content_type,
            bytes,
        } => {
            let mut out = head(*status, Some(content_type), bytes.len() as u64);
            out.extend_from_slice(bytes);
            write_all(socket, state, &out);
        }
        StubReply::Raw(bytes) => write_all(socket, state, bytes),
        StubReply::Computed {
            content_type,
            responder,
        } => {
            let body = (responder.0)(request);
            let mut out = head(200, Some(content_type), body.len() as u64);
            out.extend_from_slice(&body);
            write_all(socket, state, &out);
        }
        StubReply::SlowBody {
            delay,
            status,
            content_type,
            bytes,
        } => {
            sleep_interruptible(state, *delay);
            let mut out = head(*status, Some(content_type), bytes.len() as u64);
            out.extend_from_slice(bytes);
            write_all(socket, state, &out);
        }
        StubReply::StallBeforeHeaders(delay) => {
            sleep_interruptible(state, *delay);
            let out = head(200, None, 0);
            write_all(socket, state, &out);
        }
        StubReply::StallAfterHeaders(delay) => {
            let out = head(200, Some("application/octet-stream"), 16);
            write_all(socket, state, &out);
            sleep_interruptible(state, *delay);
            write_all(socket, state, &[0x5A; 16]);
        }
        StubReply::DropConnection => {}
        StubReply::AcceptWithoutReading(hold) => sleep_interruptible(state, *hold),
        StubReply::Redirect { status, location } => {
            let mut out = head(*status, None, 0);
            // Splice the Location header in ahead of the blank line that ends
            // the head, so the reason phrase stays honest for 301/302/307/308.
            let terminator = out.len().saturating_sub(2);
            out.splice(
                terminator..terminator,
                format!("Location: {location}\r\n").into_bytes(),
            );
            write_all(socket, state, &out);
        }
        StubReply::StreamUntilClosed {
            status,
            content_length,
            chunk_len,
            stop_after_bytes,
        } => {
            let out = head(*status, Some("application/octet-stream"), *content_length);
            write_all(socket, state, &out);
            let chunk = vec![0x5A; *chunk_len];
            let mut written: u64 = 0;
            while written < *stop_after_bytes && !state.stop.load(Ordering::SeqCst) {
                if socket.write_all(&chunk).is_err() {
                    break;
                }
                written = written.saturating_add(chunk.len() as u64);
                state
                    .bytes_written
                    .fetch_add(chunk.len() as u64, Ordering::SeqCst);
            }
        }
    }
    let _ = socket.flush();
}

/// Read one HTTP request: the head, plus a `Content-Length` body if it
/// declares one. Recorded verbatim so tests can assert on the raw bytes —
/// which headers were sent, and which were not.
fn read_request(socket: &mut TcpStream, state: &StubState) -> Vec<u8> {
    let mut buffer = Vec::new();
    let mut scratch = [0u8; 4096];
    let mut expected: Option<usize> = None;

    loop {
        if let Some(total) = expected {
            if buffer.len() >= total {
                break;
            }
        } else if let Some(head_end) = find_head_end(&buffer) {
            let head = String::from_utf8_lossy(&buffer[..head_end]).to_ascii_lowercase();
            let body_len = head
                .lines()
                .find_map(|line| line.strip_prefix("content-length:"))
                .and_then(|value| value.trim().parse::<usize>().ok())
                .unwrap_or(0);
            expected = Some(head_end.saturating_add(body_len));
            continue;
        }
        if buffer.len() >= MAX_RECORDED_REQUEST_BYTES {
            break;
        }
        match socket.read(&mut scratch) {
            Ok(0) => break,
            Ok(n) => buffer.extend_from_slice(&scratch[..n]),
            Err(_) => break,
        }
    }

    state
        .requests
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .push(buffer.clone());
    buffer
}

fn find_head_end(buffer: &[u8]) -> Option<usize> {
    buffer
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|start| start + 4)
}

/// A response head. The reason phrase is cosmetic to `ureq` — it parses the
/// code — but a stub that answered `HTTP/1.1 404 OK` would mislead the next
/// person to read a captured exchange, so it is at least not a lie.
fn head(status: u16, content_type: Option<&str>, content_length: u64) -> Vec<u8> {
    let reason = match status {
        200 => "OK",
        301 => "Moved Permanently",
        302 => "Found",
        307 => "Temporary Redirect",
        308 => "Permanent Redirect",
        400 => "Bad Request",
        404 => "Not Found",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        503 => "Service Unavailable",
        _ => "Status",
    };
    let mut out = format!("HTTP/1.1 {status} {reason}\r\n");
    if let Some(content_type) = content_type {
        out.push_str(&format!("Content-Type: {content_type}\r\n"));
    }
    out.push_str(&format!(
        "Content-Length: {content_length}\r\nConnection: close\r\n\r\n"
    ));
    out.into_bytes()
}

fn write_all(socket: &mut TcpStream, state: &StubState, bytes: &[u8]) {
    if socket.write_all(bytes).is_ok() {
        state
            .bytes_written
            .fetch_add(bytes.len() as u64, Ordering::SeqCst);
    }
}

fn sleep_interruptible(state: &StubState, total: Duration) {
    let slice = Duration::from_millis(10);
    let mut left = total;
    while left > Duration::ZERO && !state.stop.load(Ordering::SeqCst) {
        let step = if left < slice { left } else { slice };
        thread::sleep(step);
        left -= step;
    }
}
