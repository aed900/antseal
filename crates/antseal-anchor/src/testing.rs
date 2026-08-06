//! Test infrastructure exported for other crates' tests, the way
//! `antseal-net` exports `MockBackend`.
//!
//! Compiled under `#[cfg(any(test, feature = "test-util"))]`. The feature
//! activates **no optional dependency** — it only compiles this module — so
//! turning it on costs the dependency graph nothing.
//!
//! Q16's policy is absolute: no test in this workspace contacts a real
//! endpoint. Everything here binds `127.0.0.1:0`, which cannot.
//!
//! That last sentence is an argument about *these stubs*, not about the
//! tests — a test is not obliged to use one, and one once did not
//! ([`crate::ots::engine`]'s `upgrade_pending_with` seam). The policy is
//! **enforced** by [`crate::http::offline`], which refuses any non-loopback
//! endpoint inside the substrate itself; `docs/testing/anchor-ci-policy.md`
//! is the whole story.

pub mod replay;
pub mod stub;
