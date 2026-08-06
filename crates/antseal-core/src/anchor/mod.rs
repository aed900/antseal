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
//! - [`verdicts`] (tasks **A18**, **A19**, **A39**, **A40**, **A67**, **A80**)
//!   — the per-anchor verdict state machine over D53's `T1–T3` and D56's
//!   `O1–O9` (with D56 §5's rule order as amended by **D93 §5**: O4 is
//!   guarded by the online refutations rather than sitting above them), the
//!   receipt's separate supporting-evidence class, the suppressed-anomaly list
//!   best-evidence-wins would otherwise discard, and anchor identity counted
//!   from verified identities rather than from array length — one identity arm
//!   per independent *mechanism*, so a headline-eligible `.ots` contributes
//!   Bitcoin-the-chain and not its calendars (**D92**).
//! - `testing` (tasks **A59** completing **A24**, and **A82**) — the signing
//!   mock TSA and its test CA, plus the synthetic `.ots` writer for the shapes
//!   no capture contains, compiled only under `test`/`test-util`. It lives
//!   here rather than in a crate of its own because A30(c) makes
//!   `antseal-core` the sole declaration site of the seven D60 pins, and
//!   `cargo metadata --no-deps` sees dev edges too; the module's own docs
//!   carry the argument.

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
#[cfg(any(test, feature = "test-util"))]
pub mod testing;
pub mod tsa;
pub mod verdicts;

pub use error::{AlgPosition, AnchorError, DerFault, DerSite, SignedAttrId};
