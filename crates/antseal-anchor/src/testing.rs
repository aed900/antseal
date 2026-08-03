//! Test infrastructure exported for other crates' tests, the way
//! `antseal-net` exports `MockBackend`.
//!
//! Compiled under `#[cfg(any(test, feature = "test-util"))]`. The feature
//! activates **no optional dependency** — it only compiles this module — so
//! turning it on costs the dependency graph nothing.
//!
//! Q16's policy is absolute: no test in this workspace contacts a real
//! endpoint. Everything here binds `127.0.0.1:0`, which cannot.

pub mod replay;
pub mod stub;
