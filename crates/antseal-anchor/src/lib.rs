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
//! docs). The HTTP substrate and the real submission clients arrive at
//! M2 (A3 onward); until then this crate performs no network I/O at all.
//!
//! [`AnchorGate`]: gate::AnchorGate
//! [`NoAnchorGate`]: gate::NoAnchorGate

// Intentional dependency edge, mostly unused until M2: anchor evidence
// types are defined by antseal-core (A2), and A1's core half (the
// UNANCHORED aggregate) lives in `antseal_core::verify::aggregate`.
use antseal_core as _;

pub mod gate;

pub use gate::{AnchorGate, AnchorGateError, AnchorSubmissionOutcome, NoAnchorGate};
