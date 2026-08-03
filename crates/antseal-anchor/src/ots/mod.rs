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

pub mod calendars;
pub mod container;
pub mod engine;
pub mod submit;
pub mod upgrade;
pub mod upgrade_uri;

pub use calendars::{
    DEFAULT_OTS_CALENDARS, OTS_ACCEPT_HEADER, OTS_MIN_DISTINCT_CALENDARS, OTS_SUBMIT_DEADLINE_SECS,
    OTS_SUBMIT_PATH, OTS_UPGRADE_PATH_PREFIX, effective_calendars,
};
pub use container::{ContainerError, OTS_HEADER_LEN, assemble, container_header};
pub use engine::{
    AppliedUpgrade, NagState, OtsAnchorState, OtsAnchorStatus, PendingWork, StoredOtsAnchor,
    StoredTsaAnchor, UpgradeBudget, UpgradeNote, UpgradeReport, WorkAnchorStatus, upgrade_pending,
    work_status,
};
pub use submit::{
    CalendarAttempt, CalendarFailure, OtsSubmission, OtsSubmitOutcome, PendingRecord,
    submit_to_calendars,
};
pub use upgrade::{
    HeaderError, MergeError, MergedUpgrade, PendingRef, UpgradePoll, UpgradeTarget, confirm_header,
    merge_upgrade, pending_refs, poll_upgrade,
};
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
/// a 298x margin.
///
/// # The upgrade-response half of the F4 row, measured 2026-08-03
///
/// A42 left this margin **deliberately blank**: the upgrade response carries a
/// Bitcoin merkle path, is therefore larger than a submit response, and no
/// upgraded response existed anywhere in the tree. The A25 day-2 poll
/// completed on 2026-08-03T09:03Z — 13 h 47 m after stamping, not the 48 h the
/// estimate assumed — and the six real bodies measure:
///
/// | calendar | bytes | digest A | digest B |
/// | --- | --- | --- | --- |
/// | `alice.btc.calendar.opentimestamps.org` | **1 000** | ✓ | ✓ |
/// | `bob.btc.calendar.opentimestamps.org` | **1 036** | ✓ | ✓ |
/// | `btc.calendar.catallaxy.com` | **1 105** | ✓ | ✓ |
///
/// Identical per calendar across both digests, which is what a fixed-shape
/// merkle path predicts. **The governing figure is the largest: 1 105 B, a
/// 59.3× margin** against this 65 536-byte cap — and it is the figure the F4
/// row takes, because the row bounds one HTTP reply and an upgrade reply is
/// 5.02× larger than the submit reply the 298× margin was computed from.
///
/// The cap holds with room either way; what changed is that the number is now
/// measured rather than absent. `MAX_OTS_BYTES` in this slot would have been a
/// 949× ceiling against the true worst case, permanent under F4's raise-only
/// rule. [`tests::the_measured_upgrade_response_sizes_are_the_f4_row`] pins
/// all three against the committed captures, so a re-recorded fixture moves
/// the documented margin or fails.
pub const MAX_OTS_CALENDAR_RESPONSE_BYTES: u64 = crate::http::OTS_CALENDAR_RESPONSE_CAP_BYTES;

/// The largest real calendar **upgrade** response measured (catallaxy,
/// 2026-08-03). A25's day-2 figure, pinned as a constant so the F4 margin
/// above is arithmetic over named values rather than a sentence.
pub const MEASURED_MAX_UPGRADE_RESPONSE_BYTES: u64 = 1_105;

const _: () = {
    assert!(MAX_OTS_CALENDAR_RESPONSE_BYTES == 65_536);
    // The measured worst case, with the margin the F4 row records.
    assert!(MAX_OTS_CALENDAR_RESPONSE_BYTES > MEASURED_MAX_UPGRADE_RESPONSE_BYTES * 59);
    // The distinction this module's docs exist to preserve, as a compile-time
    // fact rather than a sentence: strict, because equality *is* the
    // conflation.
    assert!(MAX_OTS_CALENDAR_RESPONSE_BYTES < antseal_core::codec::caps::MAX_OTS_BYTES);
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::replay::fixtures;

    /// A42's F4 margin, against the bytes rather than against the note.
    ///
    /// The sizes are asserted per file, so a re-recorded or truncated capture
    /// fails here rather than silently moving a documented margin.
    #[test]
    fn the_measured_upgrade_response_sizes_are_the_f4_row() {
        assert_eq!(fixtures::UPGRADE_A_ALICE.len(), 1_000);
        assert_eq!(fixtures::UPGRADE_A_BOB.len(), 1_036);
        assert_eq!(fixtures::UPGRADE_A_CATALLAXY.len(), 1_105);
        // Identical per calendar across both digests — a fixed-shape merkle
        // path. If this ever stops holding, the "largest" figure has to be
        // re-derived rather than assumed.
        assert_eq!(
            fixtures::UPGRADE_B_ALICE.len(),
            fixtures::UPGRADE_A_ALICE.len()
        );
        assert_eq!(fixtures::UPGRADE_B_BOB.len(), fixtures::UPGRADE_A_BOB.len());
        assert_eq!(
            fixtures::UPGRADE_B_CATALLAXY.len(),
            fixtures::UPGRADE_A_CATALLAXY.len()
        );

        let largest = [
            fixtures::UPGRADE_A_ALICE,
            fixtures::UPGRADE_A_BOB,
            fixtures::UPGRADE_A_CATALLAXY,
            fixtures::UPGRADE_B_ALICE,
            fixtures::UPGRADE_B_BOB,
            fixtures::UPGRADE_B_CATALLAXY,
        ]
        .iter()
        .map(|body| body.len() as u64)
        .max()
        .unwrap_or(0);
        assert_eq!(largest, MEASURED_MAX_UPGRADE_RESPONSE_BYTES);

        // The margin the F4 row records, as arithmetic.
        assert_eq!(MAX_OTS_CALENDAR_RESPONSE_BYTES / largest, 59);
        // …and the upgrade reply really is the governing case: 5.02x the
        // largest submit reply, which is what made the submit-derived 298x
        // margin the wrong number to leave in the row.
        assert_eq!(fixtures::CALENDAR_CATALLAXY_A.len(), 220);
        assert!(largest > fixtures::CALENDAR_CATALLAXY_A.len() as u64 * 5);
    }

    /// The two 404 discriminator bodies, as bytes, from the live capture.
    ///
    /// The 9-vs-42 length difference is *not* what the classifier uses — see
    /// [`crate::ots::upgrade`] — but the fixtures must still be the shapes the
    /// measurements recorded, or the classifier tests are asserting against a
    /// fiction.
    #[test]
    fn the_discriminator_bodies_are_the_measured_ones() {
        assert_eq!(fixtures::CALENDAR_NOT_FOUND, b"Not found");
        assert_eq!(fixtures::CALENDAR_NOT_FOUND.len(), 9);
        assert_eq!(
            fixtures::CALENDAR_PENDING_BODY,
            b"Pending confirmation in Bitcoin blockchain"
        );
        assert_eq!(fixtures::CALENDAR_PENDING_BODY.len(), 42);
    }
}
