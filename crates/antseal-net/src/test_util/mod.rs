//! Test-support surface of `antseal-net` (feature `test-util`,
//! non-default — see the feature comment in this crate's `Cargo.toml`).
//!
//! Home of [`MockBackend`] (S3) — the in-memory [`StorageBackend`] every
//! storage-touching test runs on (MVP-SPEC.md line 69: "Tests run on
//! `MockBackend`") — and of [`block_on`], the std-only executor that
//! drives the trait's futures without a runtime dependency.
//!
//! Exported across the crate boundary deliberately: the seal/restore
//! orchestration lives in `antseal_cli`'s library (D34), whose tests
//! drive the pipeline against this mock through a dev-dependency edge — a
//! `#[cfg(test)]` mock would be invisible there (D34's forced
//! sub-finding, recorded on S3).
//!
//! [`StorageBackend`]: crate::StorageBackend

mod mock;

// `DEFAULT_MAX_TRANSFERS_PER_TX` is re-exported so S9's constants suite
// can assert it equals upstream's `MAX_TRANSFERS_PER_TRANSACTION` — the
// mock's sub-batch shape must stay linked to the real one (D37).
pub use mock::{CallRecord, DEFAULT_MAX_TRANSFERS_PER_TX, Fault, Method, MockBackend};

use std::future::Future;
use std::pin::pin;
use std::task::{Context, Poll, Waker};

/// Drive a future to completion on the current thread — a minimal,
/// std-only `block_on` (sanctioned by the S2 task note: ~a dozen lines
/// hand-rolled rather than an async-runtime dependency, per pin
/// governance; `antseal-cli` brings tokio at U1 for production).
///
/// Suitable for exactly this crate's backends: their futures never park
/// on external events, so polling with the no-op waker terminates. Do
/// not use it for futures that need a real reactor.
pub fn block_on<F: Future>(future: F) -> F::Output {
    let mut context = Context::from_waker(Waker::noop());
    let mut future = pin!(future);
    loop {
        match future.as_mut().poll(&mut context) {
            Poll::Ready(output) => return output,
            Poll::Pending => std::thread::yield_now(),
        }
    }
}
