//! OpenTimestamps calendar acquisition (tasks **A13**, **A14**, **A15**,
//! **A42**; decision D54).
//!
//! At the moment this module holds **A42**'s half: the upgrade-URI allowlist
//! and the per-response byte ceiling. A13's submit client and the calendar
//! defaults land in `calendars.rs` beside it.
//!
//! # Two byte ceilings, and the next reader will assume one number serves both
//!
//! They are different quantities and they are not interchangeable:
//!
//! | constant | bounds | value |
//! | --- | --- | --- |
//! | [`MAX_OTS_CALENDAR_RESPONSE_BYTES`] | **one HTTP reply from one calendar** | 65 536 |
//! | `antseal_core::codec::caps::MAX_OTS_BYTES` | the **merged `.ots` artifact** a bundle embeds — every calendar, every upgrade, accumulated | 1 048 576 |
//!
//! Passing `MAX_OTS_BYTES` as a request's `receive_cap_bytes` would let four
//! calendars hand this crate 4 MiB per seal against a measured worst case of
//! **220 bytes**, and under `docs/format/anchor-artifact-limits.md` rule F4
//! (limits are raise-only after M2's first release) a 1 MiB ceiling could
//! never be walked back. The measured value is the only reversible choice.
//! The strict inequality between the two is asserted at compile time in
//! `crate::http`.

pub mod upgrade_uri;

pub use upgrade_uri::{
    OTS_UPGRADE_HOST_SUFFIXES, UpgradeUriRefusal, classify_upgrade_uri, upgrade_uri_allowed,
};

/// The per-response body ceiling for **one** calendar HTTP exchange (submit
/// or upgrade), in bytes. Task **A42**; decision D54 §6.1/§8b.
///
/// This is the name the F4 registry row carries and the name D54 §6.1
/// specifies. It is an **alias for the substrate's own constant**
/// ([`crate::http::OTS_CALENDAR_RESPONSE_CAP_BYTES`]) rather than a second
/// literal, for the reason D84 §5 gives about limits generally: two constants
/// holding one value is how they stop holding one value. The substrate needed
/// its own name because it is where `receive_cap_bytes` is applied; this is
/// where the F4 row points.
///
/// `u64`, not D54 §6.1's `usize`: `HttpRequest::receive_cap_bytes` is `u64`,
/// and a `usize` spelling would need a cast at every call site — one of which
/// would eventually be the wrong cast on a 32-bit target.
///
/// Measured 2026-08-02 across 18 real calendar submit responses: the largest
/// was **220 B** (`testdata/anchors/A25-bootstrap/A-catallaxy.timestamp`),
/// a 298x margin. The *upgrade* response is larger — it carries a Bitcoin
/// merkle path — and has not been measured; A25's day-2 run must record it and
/// complete the F4 row's margin figure.
pub const MAX_OTS_CALENDAR_RESPONSE_BYTES: u64 = crate::http::OTS_CALENDAR_RESPONSE_CAP_BYTES;

const _: () = {
    assert!(MAX_OTS_CALENDAR_RESPONSE_BYTES == 65_536);
    // The distinction this module's docs exist to preserve, as a compile-time
    // fact rather than a sentence: strict, because equality *is* the
    // conflation.
    assert!(MAX_OTS_CALENDAR_RESPONSE_BYTES < antseal_core::codec::caps::MAX_OTS_BYTES);
};
