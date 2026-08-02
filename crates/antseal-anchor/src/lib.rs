//! Network side of anchoring for antseal.
//!
//! This crate is the sole home of anchor *acquisition* I/O (MVP-SPEC.md,
//! Architecture): OpenTimestamps calendar submit + upgrade polling,
//! RFC 3161 TSA HTTP requests, esplora header checks, and the advisory
//! two-endpoint Arbitrum receipt *confirmation* (A17 — it consumes S7's
//! captured receipt, never produces it; capture itself is payment-coupled
//! and lives in `antseal-net::pay()`, decision D33). Anchor
//! *verification* (`TimeStampResp`/`TSTInfo`, `.ots` op execution,
//! receipt checks) lives in `antseal-core` so `.sealproof` bundles verify
//! fully offline.
//!
//! # What exists at M1 (task A1)
//!
//! The [`gate`] module: the pre-pay [`AnchorGate`] interface the seal
//! pipeline injects (D34), the [`NoAnchorGate`] skip implementation, and
//! the normative **zero-anchor seal contract** — including the rule that
//! `--no-anchor` MUST be rejected on `arbitrum-one` (see the module
//! docs).
//!
//! # What arrived at M2 (task A3, decision D90)
//!
//! The [`http`] module: the substrate every client in this crate sends
//! through — one configured agent, per-phase timeouts, bounded and
//! idempotency-aware retries, streaming receive ceilings, and typed
//! per-endpoint errors. It is **blocking**, and deliberately so:
//! `antseal-anchor` creates no async runtime, borrows none, and requires no
//! async context, which is what lets A15/U24's opportunistic upgrade hook run
//! on every CLI invocation in builds where `tokio` is not compiled in at all.
//! [`AnchorGate::run`] keeps its frozen `async fn` signature regardless — a
//! blocking body completes on the first poll.
//!
//! One coupling the other side of the seam must keep (D90 §3.3, task Q84):
//! blocking inside `antseal-cli`'s `rt.block_on` is safe **only because**
//! that runtime is `new_multi_thread`. On a `new_current_thread` runtime,
//! ant-core's spawned tasks would starve while this crate sat on a socket.
//!
//! This crate is **never** compiled to wasm32: the verifier web page performs
//! its own online fetches in JS and feeds the results to WASM-safe core
//! through A2's `OnlineEvidence`. The dependency edge runs anchor → core and
//! never the reverse, which is what keeps `antseal-core` free of any HTTP
//! dependency.
//!
//! [`AnchorGate`]: gate::AnchorGate
//! [`AnchorGate::run`]: gate::AnchorGate::run
//! [`NoAnchorGate`]: gate::NoAnchorGate

pub mod gate;
pub mod http;

#[cfg(any(test, feature = "test-util"))]
pub mod testing;

pub use gate::{AnchorGate, AnchorGateError, AnchorSubmissionOutcome, NoAnchorGate};
pub use http::{
    AnchorHttpError, Endpoint, EndpointError, HttpClient, HttpMethod, HttpPolicy, HttpRequest,
    HttpResponse, HttpTimeouts, Idempotency, RetryVerdict, TlsPolicy,
};
