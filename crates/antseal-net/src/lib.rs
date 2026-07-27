//! Autonomi storage boundary for antseal — stub only (implementation lands
//! at M1).
//!
//! Will own the batch-first `StorageBackend` trait (`quote_batch` / `pay` /
//! `finalize_batch` / `get_data`), its ant-core implementation, and the
//! `MockBackend` all tests run on (MVP-SPEC.md, Architecture). This crate is
//! the churn-isolation boundary: ALL Autonomi storage network use goes
//! through here, so upstream ant-core churn stays contained in one impl file.

// Intentional dependency edge, unused until M1: blob/address types are
// defined by antseal-core.
use antseal_core as _;
