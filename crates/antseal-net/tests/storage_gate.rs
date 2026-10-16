//! The no-real-storage-network gate's two witnesses (D173 §2 R10).
//!
//! # 1. Shape, in the default feature set
//!
//! The adapter is compiled only under `ant-backend`, and no required CI job
//! builds that feature — so the wiring D173 §2 R10 rules on would otherwise be
//! checked by nothing CI runs. The shape scan reads
//! `crates/antseal-net/src/ant_backend.rs` as text, in every
//! `cargo test -p antseal-net`, and asserts:
//!
//! - exactly two code lines call `Client::connect` — one in each storage
//!   constructor (the payer's and the reader's) — and no code line anywhere else
//!   under `crates/` does;
//! - each of those constructors consults the storage gate as its **first
//!   fallible step**, before its first `.await`;
//! - each then refuses an environment in which upstream would panic or write
//!   its state file under the current directory (`consult_upstream_state`,
//!   S42, D178 R1) — after the gate, and still before its first `.await`;
//! - the receipt reader's constructor opens no storage session, builds the
//!   key-less provider (D173 §2 R14), and consults neither check.
//!
//! It is a shape proof only: a gate call that did nothing would pass it. The
//! behaviour proof is the second half.
//!
//! # 2. Behaviour, in the heavy tier (`ant-backend`)
//!
//! The real constructors, driven with peers that must be refused:
//!
//! - the reader, id `arbitrum-one`, bootstrap `[100::1]:9` — RFC 6666's
//!   discard-only prefix, never a routable host — refused by message, fast;
//! - the payer, id `devnet`, a loopback listener as its payment RPC, the same
//!   peer — refused with **zero** connections accepted by that listener.
//!   `devnet` deliberately: for a public id the payer's `eth_chainId` reaches
//!   evmlib's compiled-in public RPC whatever the configuration says, so a
//!   public-id payer row could never be pointed at a loopback listener;
//! - controls, both without a storage session: the payer over a single
//!   loopback peer is admitted and reaches the listener (so the zero above can
//!   see a connection), and sets no transport mode can dial pass the gate and
//!   are refused by the transport-mode derivation instead (so the gate is not
//!   refusing everything);
//! - the receipt reader over a loopback JSON-RPC stub: its constructor's one
//!   call is `eth_chainId`, it consults no storage gate, and it backfills over
//!   the same provider.
//!
//! These rows are armed by the build profile — a `cargo test` build has debug
//! assertions, and the gate arms itself there when the variable is unset — and
//! each row **refuses to run** in a process where the gate is disarmed, because
//! a disarmed row would dial the peer it exists to refuse. Nothing here dials
//! anything but loopback.

use std::fs;
use std::path::{Path, PathBuf};

/// The call the shape scan counts — assembled, so this file does not contain
/// the text it hunts for.
const CONNECT: &str = concat!("Client", "::connect(");
/// The adapter's gate call, as each storage constructor must spell it.
const GATE: &str = concat!("consult_storage", "_gate(config)?");
/// The S42 refusal (D178 R1), as each storage constructor must spell it.
const STATE: &str = concat!("consult_upstream", "_state()?");
/// The first suspension point a constructor may reach only after the gate.
const AWAIT: &str = concat!(".", "await");

/// A line whose first non-blank characters are not `//` — the convention the
/// S6 containment lane uses for "code line".
fn is_code_line(line: &str) -> bool {
    !line.trim_start().starts_with("//")
}

/// The code lines of `text`, joined.
fn code_of(text: &str) -> String {
    text.lines()
        .filter(|line| is_code_line(line))
        .collect::<Vec<_>>()
        .join("\n")
}

/// The text of `impl <type_name> {`'s `pub async fn connect(`, from the `fn`
/// through the line before the one that closes it.
fn constructor_body<'a>(adapter: &'a str, type_name: &str) -> &'a str {
    let header = format!("\nimpl {type_name} {{");
    let start = adapter
        .find(&header)
        .unwrap_or_else(|| panic!("ant_backend.rs has no `{}` block", header.trim()));
    let block = &adapter[start + header.len()..];
    let constructor = block
        .find("pub async fn connect(")
        .unwrap_or_else(|| panic!("`impl {type_name}` has no `pub async fn connect(`"));
    if let Some(next_impl) = block.find("\nimpl ") {
        assert!(
            constructor < next_impl,
            "the first `pub async fn connect(` after `impl {type_name}` belongs to a later impl \
             block — the scan is not reading `{type_name}`'s constructor"
        );
    }
    let body = &block[constructor..];
    let end = body.find("\n    }\n").unwrap_or_else(|| {
        panic!("`{type_name}::connect` has no closing brace at method indentation")
    });
    &body[..end]
}

fn collect_rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let entries =
        fs::read_dir(dir).unwrap_or_else(|error| panic!("cannot list {}: {error}", dir.display()));
    for entry in entries {
        let path = entry
            .unwrap_or_else(|error| panic!("cannot read an entry of {}: {error}", dir.display()))
            .path();
        let skip = path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name == "target" || name == ".git");
        if skip {
            continue;
        }
        if path.is_dir() {
            collect_rust_files(&path, out);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            out.push(path);
        }
    }
}

/// **D173 §2 R10, shape witness.** Exactly one `Client::connect` per storage
/// constructor, none elsewhere under `crates/`, and the storage gate as the
/// first fallible step of both.
#[test]
fn the_storage_gate_is_the_first_step_of_both_storage_constructors() {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let adapter_path = manifest.join("src").join("ant_backend.rs");
    let adapter = fs::read_to_string(&adapter_path)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", adapter_path.display()));

    // 1. The whole adapter file.
    let sites: Vec<usize> = adapter
        .lines()
        .enumerate()
        .filter(|(_, line)| is_code_line(line) && line.contains(CONNECT))
        .map(|(index, _)| index + 1)
        .collect();
    assert_eq!(
        sites.len(),
        2,
        "ant_backend.rs has {} Client::connect call sites (code lines {sites:?}); each storage \
         constructor must have exactly one and consult the storage gate before it (D173 §2 R10)",
        sites.len()
    );

    // 2. Each storage constructor.
    for type_name in ["AntCoreBackend", "AntCoreReader"] {
        let code = code_of(constructor_body(&adapter, type_name));
        assert_eq!(
            code.matches(CONNECT).count(),
            1,
            "`{type_name}::connect` must make exactly one Client::connect call (D173 §2 R10)"
        );
        let gate = code.find(GATE).unwrap_or_else(|| {
            panic!(
                "`{type_name}::connect` never consults the storage gate: no `{GATE}` on a code \
                 line of its body (D173 §2 R10)"
            )
        });
        let first_await = code.find(AWAIT).unwrap_or_else(|| {
            panic!("`{type_name}::connect` awaits nothing — the scan is not reading a constructor")
        });
        assert!(
            gate < first_await,
            "`{type_name}::connect` awaits before it consults the storage gate — the gate must \
             come before every socket (D173 §2 R10)"
        );
        let first_fallible = code
            .find(")?")
            .unwrap_or_else(|| panic!("`{type_name}::connect` has no `?` at all"));
        assert_eq!(
            first_fallible + 2,
            gate + GATE.len(),
            "`{type_name}::connect` has a fallible step before the storage gate — the gate must be \
             its FIRST fallible step (D173 §2 R10)"
        );
        // S42 (D178 R1): the upstream-state refusal, once, after the gate and
        // before every socket.
        assert_eq!(
            code.matches(STATE).count(),
            1,
            "`{type_name}::connect` must consult upstream's state directory exactly once — no \
             `{STATE}` on a code line of its body, or more than one (S42, D178 R1)"
        );
        let state = code.find(STATE).unwrap_or_default();
        assert!(
            gate < state,
            "`{type_name}::connect` refuses an unresolvable upstream dir before it consults the \
             storage gate — the gate must stay its first fallible step (D178 R1)"
        );
        assert!(
            state < first_await,
            "`{type_name}::connect` awaits before refusing an unresolvable upstream dir (S42)"
        );
    }

    // 3. The receipt reader: a chain read, no storage session (D173 §2 R14).
    let receipts = code_of(constructor_body(&adapter, "AntCoreReceiptReader"));
    assert!(
        !receipts.contains(CONNECT),
        "the receipt reader's constructor calls Client::connect — a receipt read must open no \
         storage session (D173 §2 R14)"
    );
    assert!(
        receipts.contains(concat!("http", "_provider(")),
        "the receipt reader's constructor must build the key-less provider (D173 §2 R14)"
    );
    assert!(
        !receipts.contains(concat!("consult_storage", "_gate")),
        "the receipt reader consults the storage gate, which guards storage sessions it never \
         opens (D173 §2 R14)"
    );
    assert!(
        !receipts.contains(concat!("consult_upstream", "_state")),
        "the receipt reader consults upstream's state directory, which only a storage client \
         touches — and it builds none (S42, D173 §2 R14)"
    );

    // 4. Nowhere else under crates/.
    let crates = manifest
        .parent()
        .expect("the crate sits directly under crates/");
    let mut files = Vec::new();
    collect_rust_files(crates, &mut files);
    assert!(
        files.len() > 300,
        "the walk found only {} Rust files under {} — it is not reading the tree",
        files.len(),
        crates.display()
    );
    assert!(
        files.contains(&adapter_path),
        "the walk never reached ant_backend.rs — it is not reading what it thinks"
    );
    let mut elsewhere = Vec::new();
    for file in files.iter().filter(|file| **file != adapter_path) {
        let text = fs::read_to_string(file)
            .unwrap_or_else(|error| panic!("cannot read {}: {error}", file.display()));
        for (index, line) in text.lines().enumerate() {
            if is_code_line(line) && line.contains(CONNECT) {
                let relative = file.strip_prefix(crates).unwrap_or(file);
                elsewhere.push(format!("{}:{}", relative.display(), index + 1));
            }
        }
    }
    assert!(
        elsewhere.is_empty(),
        "Client::connect is called outside the adapter's two gated constructors: {elsewhere:?} \
         (D173 §2 R10)"
    );
}

/// The behaviour rows (module docs, part 2).
#[cfg(feature = "ant-backend")]
mod heavy {
    use std::collections::BTreeMap;
    use std::io::{Read, Write};
    use std::net::{Ipv6Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::thread::JoinHandle;
    use std::time::{Duration, Instant};

    use antseal_core::crypto::secrets::SecretBuf;
    use antseal_core::test_util::alternate_test_secret;
    use antseal_net::network::storage_gate;
    use antseal_net::wallet::WalletKey;
    use antseal_net::{
        AntCoreBackend, AntCoreReader, AntCoreReceiptReader, EvmAddress20, GasSummary,
        NetworkConfig, NetworkId, PaymentReceipt, StorageError, TxHash, TxRecord, TxStatus,
    };

    /// How long any one call here may take before the row fails as a hang.
    const CALL_CAP: Duration = Duration::from_secs(30);

    /// RFC 6666's discard-only prefix `100::/64`: an address no host answers.
    fn discard_only_peer() -> SocketAddr {
        SocketAddr::from((Ipv6Addr::new(0x100, 0, 0, 0, 0, 0, 0, 1), 9))
    }

    /// A loopback UDP port nothing listens on: bound, then released.
    fn dead_loopback_peer() -> SocketAddr {
        let probe = UdpSocket::bind("127.0.0.1:0").expect("bind a loopback probe socket");
        probe.local_addr().expect("the probe socket's address")
    }

    /// Every row here would dial the peer it exists to refuse if the gate were
    /// disarmed in this process, so a disarmed process refuses to run the row.
    fn require_armed_gate() {
        assert!(
            storage_gate::arming().is_some(),
            "the storage gate is DISARMED in this test process ({}=0, or a build without debug \
             assertions): these rows would dial a non-loopback peer, so they refuse to run",
            storage_gate::ENV
        );
    }

    /// A key-shaped value derived per the house fixture convention, never a
    /// committed literal (testdata/README.md; project rule 6).
    fn test_wallet_key() -> WalletKey {
        let hex: String = alternate_test_secret(b"antseal-net/D173 storage gate payer rows")
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        WalletKey::import(&SecretBuf::new(hex.into_bytes()))
            .expect("the derived fixture scalar is a valid key — pick another label if not")
    }

    /// A `devnet` configuration over `rpc_url` and `bootstrap`; the contracts
    /// are inert (nothing here pays).
    fn devnet_config(rpc_url: String, bootstrap: Vec<SocketAddr>) -> NetworkConfig {
        NetworkConfig {
            id: NetworkId::Devnet,
            evm_chain_id: 31_337,
            rpc_url,
            payment_token: EvmAddress20::from_bytes([0x11; 20]),
            payment_vault: EvmAddress20::from_bytes([0x22; 20]),
            bootstrap,
        }
    }

    /// A loopback TCP listener standing in for a payment RPC. It counts the
    /// connections it accepts and closes each at once, so an RPC call through
    /// it fails fast instead of waiting for a reply.
    struct CountingRpc {
        address: SocketAddr,
        accepted: Arc<AtomicUsize>,
        stop: Arc<AtomicBool>,
        thread: Option<JoinHandle<()>>,
    }

    impl CountingRpc {
        fn start() -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").expect("bind a loopback listener");
            let address = listener.local_addr().expect("the listener's address");
            let accepted = Arc::new(AtomicUsize::new(0));
            let stop = Arc::new(AtomicBool::new(false));
            let thread = {
                let accepted = Arc::clone(&accepted);
                let stop = Arc::clone(&stop);
                std::thread::spawn(move || {
                    for stream in listener.incoming() {
                        if stop.load(Ordering::SeqCst) {
                            break;
                        }
                        if let Ok(stream) = stream {
                            // Counted before the close the client observes, so
                            // a count read after the client's call has returned
                            // is complete.
                            accepted.fetch_add(1, Ordering::SeqCst);
                            drop(stream);
                        }
                    }
                })
            };
            Self {
                address,
                accepted,
                stop,
                thread: Some(thread),
            }
        }

        fn url(&self) -> String {
            format!("http://{}/", self.address)
        }

        fn accepted(&self) -> usize {
            self.accepted.load(Ordering::SeqCst)
        }
    }

    impl Drop for CountingRpc {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::SeqCst);
            // Wake the blocking accept so the thread reads the flag.
            drop(TcpStream::connect(self.address));
            if let Some(thread) = self.thread.take() {
                drop(thread.join());
            }
        }
    }

    /// A loopback JSON-RPC stub: `eth_chainId` answers `chain_hex`; every other
    /// method (here, `eth_getTransactionReceipt`) answers `null` — "not yet
    /// visible". It records each method name in the order asked.
    struct JsonRpcStub {
        address: SocketAddr,
        methods: Arc<Mutex<Vec<String>>>,
        stop: Arc<AtomicBool>,
        thread: Option<JoinHandle<()>>,
    }

    impl JsonRpcStub {
        fn start(chain_hex: &'static str) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").expect("bind a loopback listener");
            let address = listener.local_addr().expect("the listener's address");
            let methods = Arc::new(Mutex::new(Vec::new()));
            let stop = Arc::new(AtomicBool::new(false));
            let thread = {
                let methods = Arc::clone(&methods);
                let stop = Arc::clone(&stop);
                std::thread::spawn(move || {
                    for stream in listener.incoming() {
                        if stop.load(Ordering::SeqCst) {
                            break;
                        }
                        if let Ok(mut stream) = stream {
                            // A malformed exchange only fails the row that
                            // caused it, through the method log.
                            drop(answer(&mut stream, chain_hex, &methods));
                        }
                    }
                })
            };
            Self {
                address,
                methods,
                stop,
                thread: Some(thread),
            }
        }

        fn url(&self) -> String {
            format!("http://{}/", self.address)
        }

        fn methods(&self) -> Vec<String> {
            match self.methods.lock() {
                Ok(methods) => methods.clone(),
                Err(poisoned) => poisoned.into_inner().clone(),
            }
        }
    }

    impl Drop for JsonRpcStub {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::SeqCst);
            drop(TcpStream::connect(self.address));
            if let Some(thread) = self.thread.take() {
                drop(thread.join());
            }
        }
    }

    /// Serve one HTTP/1.1 JSON-RPC request on `stream`, echoing its id.
    fn answer(
        stream: &mut TcpStream,
        chain_hex: &str,
        methods: &Mutex<Vec<String>>,
    ) -> std::io::Result<()> {
        stream.set_read_timeout(Some(Duration::from_secs(5)))?;
        let mut buffer = Vec::new();
        let mut chunk = [0u8; 4096];
        let header_end = loop {
            let read = stream.read(&mut chunk)?;
            if read == 0 {
                return Ok(());
            }
            buffer.extend_from_slice(&chunk[..read]);
            if let Some(at) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
                break at + 4;
            }
        };
        let head = String::from_utf8_lossy(&buffer[..header_end]).to_ascii_lowercase();
        let length = head
            .lines()
            .find_map(|line| line.strip_prefix("content-length:"))
            .and_then(|value| value.trim().parse::<usize>().ok())
            .unwrap_or(0);
        while buffer.len() < header_end + length {
            let read = stream.read(&mut chunk)?;
            if read == 0 {
                break;
            }
            buffer.extend_from_slice(&chunk[..read]);
        }
        let body_end = (header_end + length).min(buffer.len());
        let request: serde_json::Value =
            serde_json::from_slice(&buffer[header_end..body_end]).unwrap_or_default();
        let method = request["method"].as_str().unwrap_or_default().to_owned();
        let result = if method == "eth_chainId" {
            serde_json::Value::from(chain_hex)
        } else {
            serde_json::Value::Null
        };
        match methods.lock() {
            Ok(mut seen) => seen.push(method),
            Err(poisoned) => poisoned.into_inner().push(method),
        }
        let reply = serde_json::json!({
            "jsonrpc": "2.0",
            "id": request["id"].clone(),
            "result": result,
        })
        .to_string();
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\
             Connection: close\r\n\r\n{reply}",
            reply.len()
        )?;
        stream.flush()
    }

    /// A refusal that must come from the transport-mode derivation (D173 §2
    /// R8) and not from the storage gate.
    fn assert_refused_by_the_transport_mode(who: &str, outcome: Result<(), StorageError>) {
        match outcome {
            Ok(()) => panic!(
                "{who} connected: a set no transport mode can dial must be refused before \
                 Client::connect (D173 §2 R8)"
            ),
            Err(StorageError::Network { reason }) => {
                assert!(
                    !reason.starts_with(storage_gate::REFUSAL),
                    "{who} was refused by the storage gate, which admits a set holding no \
                     non-loopback peer: {reason}"
                );
                assert!(
                    reason.starts_with("refusing to connect over the"),
                    "{who} was refused somewhere other than the transport-mode derivation: \
                     {reason}"
                );
            }
            Err(other) => panic!("{who} was refused in the wrong class: {other}"),
        }
    }

    /// **D173 §2 R10, the reader.** A non-loopback peer, id `arbitrum-one`:
    /// refused by the gate's message, before any socket.
    #[tokio::test(flavor = "multi_thread")]
    async fn the_reader_is_refused_over_a_non_loopback_peer_before_any_socket() {
        require_armed_gate();
        let config = NetworkConfig {
            bootstrap: vec![discard_only_peer()],
            ..NetworkConfig::arbitrum_one()
        };
        let started = Instant::now();
        let outcome = tokio::time::timeout(CALL_CAP, AntCoreReader::connect(&config))
            .await
            .unwrap_or_else(|_| panic!("the reader's connect did not return within {CALL_CAP:?}"));
        let elapsed = started.elapsed();
        match outcome {
            Ok(_) => panic!(
                "the reader connected over a non-loopback bootstrap with the storage gate armed — \
                 the gate is not consulted before Client::connect (D173 §2 R10)"
            ),
            Err(StorageError::Network { reason }) => assert!(
                reason.starts_with(storage_gate::REFUSAL),
                "the reader was refused, but not by the storage gate: {reason}"
            ),
            Err(other) => panic!("the reader was refused in the wrong class: {other}"),
        }
        assert!(
            elapsed < Duration::from_secs(1),
            "the refusal took {elapsed:?}; a refusal before any socket takes microseconds"
        );
    }

    /// **D173 §2 R10, the payer.** A non-loopback peer, id `devnet`, a loopback
    /// listener as the payment RPC: refused by the gate's message with zero
    /// connections accepted. CONTROL: the same listener sees the connection
    /// when the gate admits a loopback peer.
    #[tokio::test(flavor = "multi_thread")]
    async fn the_payer_is_refused_before_its_payment_rpc_socket() {
        require_armed_gate();
        let rpc = CountingRpc::start();
        let key = test_wallet_key();

        let refused = devnet_config(rpc.url(), vec![discard_only_peer()]);
        let outcome = tokio::time::timeout(CALL_CAP, AntCoreBackend::connect(&refused, &key))
            .await
            .unwrap_or_else(|_| panic!("the payer's connect did not return within {CALL_CAP:?}"));
        let accepted = rpc.accepted();
        assert_eq!(
            accepted, 0,
            "the payer opened {accepted} payment-RPC connection(s) before the storage gate \
             refused — the refusal must precede every socket (D173 §2 R10)"
        );
        match outcome {
            Ok(_) => panic!(
                "the payer connected over a non-loopback bootstrap with the storage gate armed \
                 (D173 §2 R10)"
            ),
            Err(StorageError::Network { reason }) => assert!(
                reason.starts_with(storage_gate::REFUSAL),
                "the payer was refused, but not by the storage gate: {reason}"
            ),
            Err(other) => panic!("the payer was refused in the wrong class: {other}"),
        }

        // CONTROL: a single loopback peer passes the gate and the transport-mode
        // derivation, and the payer goes on to its payment RPC — which this
        // listener fails by closing the connection. It never reaches
        // Client::connect.
        let admitted = devnet_config(rpc.url(), vec![dead_loopback_peer()]);
        let outcome = tokio::time::timeout(CALL_CAP, AntCoreBackend::connect(&admitted, &key))
            .await
            .unwrap_or_else(|_| {
                panic!("CONTROL: the payer's connect did not return within {CALL_CAP:?}")
            });
        assert!(
            rpc.accepted() >= 1,
            "CONTROL: the gate admitted a loopback peer, yet the listener saw no connection — so \
             the zero above proves nothing"
        );
        match outcome {
            Ok(_) => panic!(
                "CONTROL: the payer connected through a payment RPC that closes every connection"
            ),
            Err(StorageError::Network { reason }) => assert!(
                reason.contains("eth_chainId") && !reason.starts_with(storage_gate::REFUSAL),
                "CONTROL: the admitted payer must fail at its payment RPC, not before it: {reason}"
            ),
            Err(other) => panic!("CONTROL: the payer failed in the wrong class: {other}"),
        }
    }

    /// **D173 §2 R8, the adapter's own defence.** Sets that hold no non-loopback
    /// peer pass the armed gate, and the ones no transport mode can dial are
    /// refused next — before any socket. The payer rows run first and use id
    /// `devnet`, so even a skipped refusal could reach only the loopback
    /// listener, which counts it.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_set_no_transport_can_dial_passes_the_gate_and_is_refused_before_any_socket() {
        require_armed_gate();
        let rpc = CountingRpc::start();
        let key = test_wallet_key();
        let loopback = dead_loopback_peer();

        for (label, bootstrap) in [
            ("an empty set", Vec::new()),
            ("a repeated loopback peer", vec![loopback, loopback]),
        ] {
            let config = devnet_config(rpc.url(), bootstrap);
            let outcome = tokio::time::timeout(CALL_CAP, AntCoreBackend::connect(&config, &key))
                .await
                .unwrap_or_else(|_| {
                    panic!("the payer over {label} did not return within {CALL_CAP:?}")
                });
            let accepted = rpc.accepted();
            assert_eq!(
                accepted, 0,
                "the payer over {label} reached its payment RPC ({accepted} connection(s)) — a \
                 set no transport mode can dial must be refused before any socket (D173 §2 R8)"
            );
            assert_refused_by_the_transport_mode(
                &format!("the payer over {label}"),
                outcome.map(|_| ()),
            );
        }

        for (label, config) in [
            ("an empty set", devnet_config(rpc.url(), Vec::new())),
            (
                "a repeated loopback peer",
                devnet_config(rpc.url(), vec![loopback, loopback]),
            ),
            (
                "loopback peers under arbitrum-one",
                NetworkConfig {
                    bootstrap: vec![loopback],
                    ..NetworkConfig::arbitrum_one()
                },
            ),
        ] {
            let outcome = tokio::time::timeout(CALL_CAP, AntCoreReader::connect(&config))
                .await
                .unwrap_or_else(|_| {
                    panic!("the reader over {label} did not return within {CALL_CAP:?}")
                });
            assert_refused_by_the_transport_mode(
                &format!("the reader over {label}"),
                outcome.map(|_| ()),
            );
        }
    }

    /// **D173 §2 R14.** The receipt reader's constructor makes one RPC call —
    /// the chain-id guard — whatever the bootstrap set holds, because it opens
    /// no storage session and consults no storage gate; it backfills over the
    /// same provider; and it refuses a chain the configuration does not pin.
    #[tokio::test(flavor = "multi_thread")]
    async fn the_receipt_reader_guards_the_chain_and_consults_no_storage_gate() {
        require_armed_gate();
        let rpc = JsonRpcStub::start("0x7a69");
        let config = devnet_config(rpc.url(), vec![discard_only_peer()]);
        assert!(
            storage_gate::check(&config.bootstrap).is_err(),
            "PRECONDITION: the armed gate refuses this bootstrap set for a storage session"
        );

        let reader = tokio::time::timeout(CALL_CAP, AntCoreReceiptReader::connect(&config))
            .await
            .unwrap_or_else(|_| {
                panic!("the receipt reader's connect did not return within {CALL_CAP:?}")
            })
            .unwrap_or_else(|error| {
                panic!(
                    "the receipt reader must build over a chain-matching RPC whatever the \
                     bootstrap set holds — it opens no storage session (D173 §2 R14): {error}"
                )
            });
        assert_eq!(
            rpc.methods(),
            ["eth_chainId"],
            "the constructor's one RPC call is the chain-id guard"
        );
        assert_eq!(reader.network_config(), &config);

        let mut receipt = PaymentReceipt {
            blobs: Vec::new(),
            tx_map: BTreeMap::new(),
            txs: vec![TxRecord {
                tx_hash: TxHash::from_bytes([0xAB; 32]),
                block_number: None,
                status: TxStatus::Submitted,
                quote_hashes: Vec::new(),
            }],
            storage_cost_atto: 0,
            gas: GasSummary { gas_cost_wei: 0 },
        };
        let before = receipt.clone();
        let filled = tokio::time::timeout(CALL_CAP, reader.backfill_block_numbers(&mut receipt))
            .await
            .unwrap_or_else(|_| panic!("the backfill did not return within {CALL_CAP:?}"))
            .expect("a receipt the RPC does not show yet is not an error");
        assert_eq!(filled, 0);
        assert_eq!(
            receipt, before,
            "a receipt the RPC does not show yet leaves the record untouched"
        );
        assert_eq!(
            rpc.methods(),
            ["eth_chainId", "eth_getTransactionReceipt"],
            "the backfill reads the receipt over the same provider"
        );

        let wrong_chain = NetworkConfig {
            evm_chain_id: 42_161,
            ..config.clone()
        };
        let outcome = tokio::time::timeout(CALL_CAP, AntCoreReceiptReader::connect(&wrong_chain))
            .await
            .unwrap_or_else(|_| {
                panic!("the receipt reader's connect did not return within {CALL_CAP:?}")
            });
        match outcome {
            Ok(_) => panic!(
                "the receipt reader accepted an RPC reporting chain 31337 for a configuration \
                 pinning 42161"
            ),
            Err(StorageError::Network { reason }) => assert!(
                reason.starts_with("chain-id mismatch"),
                "the receipt reader refused, but not with the chain-id guard: {reason}"
            ),
            Err(other) => panic!("the receipt reader refused in the wrong class: {other}"),
        }
    }
}
