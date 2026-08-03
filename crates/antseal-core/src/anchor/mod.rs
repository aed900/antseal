//! Anchor verification — **all of it**, and all of it WASM-safe.
//!
//! MVP-SPEC.md line 47–53 and line 106 put the network side in
//! `antseal-anchor` and **every** anchor *verification* step in
//! `antseal-core`: RFC 3161 `TimeStampResp`/`TSTInfo` parse + verify against
//! a pinned TSA root store, `.ots` parse + op execution + embedded-header
//! check, and the per-anchor verdict. Nothing under this module may read a
//! clock, a socket or a file: verification time is an explicit parameter and
//! online results arrive as data ([`model::OnlineEvidence`]).
//!
//! At M2 the module holds:
//!
//! - [`model`] (task **A2**) — the artifact and verdict data model: what a
//!   verifier is entitled to read out of a bundle's anchor sections, the
//!   per-anchor verdict datum over the frozen seven states, the online
//!   evidence a host feeds in, and the capture records U persists in the
//!   vault.
//! - [`ots`] (tasks **A11**, **A12**) — the in-house `.ots` codec: iterative
//!   op-DAG execution, the digest-commitment check inside the parser, the
//!   seven D58 limits, and the embedded Bitcoin header check that yields
//!   `attested`.
//! - [`caps`] (task **A5**) — the three anchor-stage structural limits D60 §6
//!   ruled, plus the reason the DER nesting depth is consumed from `der`
//!   rather than minted here.
//! - [`error`] (tasks **A5**, **A8**) — the `anchor-` error taxonomy: one
//!   distinct code per rejection class, all under the single prefix D91 §6.1
//!   registered to the A domain.
//! - [`request`] (task **A4**) — the DER `TimeStampReq` constructor: the one
//!   request shape antseal sends, deterministic and golden-vectorable
//!   because the nonce arrives as a parameter and is drawn on the network
//!   side (D59 §4).
//! - [`rfc3161`] (task **A5**) — the hand-written RFC 3161 shell. No crate in
//!   the pinned closure defines `TimeStampResp`, `TSTInfo`, `MessageImprint`
//!   or `PKIStatusInfo`; `cms` and `x509-cert` stop at RFC 5652 and RFC 5280.
//! - [`alg`] (task **A8**) — D60 §3.3's accepted-algorithm registry, as data.
//! - [`ess`] (task **A8**) — the `SigningCertificate` / `SigningCertificateV2`
//!   attribute types and the signer-certificate binding.
//! - [`tsa`] (task **A8**) — CMS `SignedData` verification over a timestamp
//!   token: signed attributes, `messageImprint`, nonce, ESSCertID, EKU.
//! - [`roots`] (tasks **A6**, **A7**, **A26**) — the pinned TSA root store:
//!   versioned const data, `include_bytes!`-compiled DER, the test-only
//!   injection API, and the A7 provenance record that gates what may be
//!   compiled in at all.
//! - [`chain`] (tasks **A9**, **A43**) — X.509 path validation to those
//!   roots at the token's `genTime`, implementing D53's six-way partition and
//!   D57's rulings P1/P2/P3.
//! - [`fuzz_entry`] (task **A5**, run by **A23**) — the fuzz driver, kept in
//!   the crate so the ordinary suite compiles and exercises it.

pub mod alg;
pub mod caps;
pub mod chain;
pub mod error;
pub mod ess;
pub mod fuzz_entry;
pub mod model;
pub mod ots;
pub mod request;
pub mod rfc3161;
pub mod roots;
pub mod tsa;

pub use error::{AlgPosition, AnchorError, DerFault, DerSite, SignedAttrId};
