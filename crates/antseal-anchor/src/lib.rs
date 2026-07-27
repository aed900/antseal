//! Network side of anchoring for antseal — stub only (implementation lands
//! at M2).
//!
//! Will own exactly the anchor *acquisition* I/O (MVP-SPEC.md, Architecture):
//! OpenTimestamps calendar submit + upgrade polling, RFC 3161 TSA HTTP
//! requests, and Arbitrum payment-receipt capture. Anchor *verification*
//! (`TimeStampResp`/`TSTInfo`, `.ots` op execution, receipt checks) lives in
//! `antseal-core` so `.sealproof` bundles verify fully offline.

// Intentional dependency edge, unused until M2: anchor evidence types are
// defined by antseal-core.
use antseal_core as _;
