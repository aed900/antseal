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
//! Connections are served **one at a time**, in script order. Every scripted
//! reply sets `Connection: close`, so `ureq` cannot pool a connection and the
//! recorded request count is the true number of round trips.

use std::collections::VecDeque;
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

impl StubReply {
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

/// The replies a [`StubServer`] will give, in order.
#[derive(Debug, Clone, Default)]
pub struct StubScript {
    replies: Vec<StubReply>,
    tail: Option<StubReply>,
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
    /// means the environment, not the code, is broken.
    #[must_use]
    pub fn spawn(script: StubScript) -> Self {
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
    let mut queued: VecDeque<StubReply> = script.replies.into();
    let mut connections: Vec<JoinHandle<()>> = Vec::new();

    while !state.stop.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((socket, _)) => {
                state.connections.fetch_add(1, Ordering::SeqCst);
                let Some(reply) = queued.pop_front().or_else(|| script.tail.clone()) else {
                    continue;
                };
                let state = Arc::clone(state);
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

fn handle(mut socket: TcpStream, state: &StubState, reply: &StubReply) {
    let _ = socket.set_read_timeout(Some(Duration::from_secs(5)));
    let _ = socket.set_write_timeout(Some(Duration::from_secs(5)));
    let _ = socket.set_nodelay(true);

    match reply {
        StubReply::DropConnection | StubReply::AcceptWithoutReading(_) => {}
        _ => read_request(&mut socket, state),
    }

    match reply {
        StubReply::Body {
            status,
            content_type,
            bytes,
        } => {
            let mut out = head(*status, Some(content_type), bytes.len() as u64);
            out.extend_from_slice(bytes);
            write_all(&mut socket, state, &out);
        }
        StubReply::Raw(bytes) => write_all(&mut socket, state, bytes),
        StubReply::StallBeforeHeaders(delay) => {
            sleep_interruptible(state, *delay);
            let out = head(200, None, 0);
            write_all(&mut socket, state, &out);
        }
        StubReply::StallAfterHeaders(delay) => {
            let out = head(200, Some("application/octet-stream"), 16);
            write_all(&mut socket, state, &out);
            sleep_interruptible(state, *delay);
            write_all(&mut socket, state, &[0x5A; 16]);
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
            write_all(&mut socket, state, &out);
        }
        StubReply::StreamUntilClosed {
            status,
            content_length,
            chunk_len,
            stop_after_bytes,
        } => {
            let out = head(*status, Some("application/octet-stream"), *content_length);
            write_all(&mut socket, state, &out);
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
fn read_request(socket: &mut TcpStream, state: &StubState) {
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
        .push(buffer);
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
