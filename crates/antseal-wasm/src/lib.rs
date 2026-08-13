//! The verifier page's wasm-bindgen boundary (R22).
//!
//! This crate contributes **a boundary and no verification logic**. Every
//! decision the page renders is computed by `antseal-core`, and every sentence
//! it displays is composed by `antseal-core` too — so page JS does layout only
//! (MVP-SPEC.md lines 56, 127; tasks/R.md R22/R23).
//!
//! The route those sentences take is `verify_rendered`, **not** the report.
//! The claim this doc made until D130 — *"whose report already carries R18's
//! final display strings"* — was false and is struck: measured, all 21
//! committed report cases carry **zero** rendered prose, the only multi-word
//! strings in any of them being the sealer's own fixture titles (D130 §1 a.2).
//! The report carries the machine-readable verdict; the rendered document
//! carries the words.
//!
//! # The closed export list
//!
//! D18 §5 R4 closes the public JS surface at **five entries plus a panic
//! hook** (four until D130 opened it by one and closed it again there), and
//! additions are a decision rather than a code change:
//!
//! | export | returns |
//! | --- | --- |
//! | `verify(bundle_bytes)` | the full report's canonical bytes |
//! | `verify_online(bundle_bytes, evidence_json)` | the advisory overlay's canonical bytes |
//! | `verdict_class(bundle_bytes, evidence_json?)` | D69's rung datum, which is **not** a report field |
//! | `build_info()` | the identity D63 §5 R3's footer renders |
//! | `verify_rendered(bundle_bytes)` | the offline document the page displays, plus what an online confirmation would fetch: `plan`, `redaction`, `rendered`, `report` (verbatim), `verdict` |
//!
//! There is deliberately **no self-hash entry point**: a digest of a file
//! cannot live inside that file (D63 §4), so the page's published sum arrives
//! by build-time injection and the closed list makes the alternative
//! unbuildable rather than merely forbidden.
//!
//! # No I/O, and how that is enforced rather than asserted
//!
//! Two mechanical checks ride jobs that already exist, so the required-context
//! count stays where it was (D18 §5 R6/R7/R8):
//!
//! * **the graph** — `scripts/ci-lanes.sh dep-graph` asserts this package's
//!   `wasm32-unknown-unknown` normal graph is exactly `antseal-core`'s
//!   reviewed set plus six named wasm-bindgen-side packages, with `js-sys`,
//!   `web-sys`, `wasm-bindgen-futures`, `web-time` and `getrandom` on a
//!   denylist that names them in the diagnosis;
//! * **the artifact** — `scripts/wasm-imports.mjs` asserts the built module's
//!   import table matches a committed allow-list. A module's imports are
//!   precisely the host functions it can call, and a `fetch` or a `Date.now`
//!   capability cannot enter without appearing there by name.
//!
//! The shipped module *has* imports and cannot not have them: a typed JS error
//! and a panic hook both need a host. What the other wasm artifacts in this
//! repository assert — an empty import table — becomes here an **enumerated**
//! one, which is still a complete statement of everything the module can ask
//! the browser to do (D18 §10).
//!
//! # Target gating
//!
//! `wasm-bindgen` is declared only under
//! `[target.'cfg(target_arch = "wasm32")'.dependencies]`, and the exports live
//! in a `cfg`-gated module. On the host this crate is an ordinary library, so
//! `cargo clippy --workspace --all-targets` and `cargo test --workspace`
//! compile no `wasm-bindgen` and still type-check and execute everything
//! behind the boundary.

pub mod api;
pub mod build_info;
pub mod error;
pub mod escape;
pub mod online;

#[cfg(target_arch = "wasm32")]
mod boundary;

pub use build_info::{BuildInfo, build_info};
pub use error::BindingError;
pub use escape::escape_for_dom;
