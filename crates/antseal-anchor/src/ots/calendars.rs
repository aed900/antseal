//! The default calendar set and the wire constants of the calendar protocol
//! (task **A13**; decision D54 §6.1).
//!
//! # These are aggregator aliases, not calendar hostnames
//!
//! [`DEFAULT_OTS_CALENDARS`] are the four endpoints upstream's own client
//! stamps at (`otsclient/cmds.py:186-189`). They are **not** the
//! `*.btc.calendar.opentimestamps.org` hosts the A25 bootstrap capture used,
//! and that distinction is the whole of D54: the pool names are the
//! operator-controlled indirection layer that lets a calendar be retired
//! without every client learning about it. `finney.btc.calendar.opentimestamps.org`,
//! whose NXDOMAIN motivated the decision, was never in upstream's default set
//! — it was a host this project chose.
//!
//! So the *submit* list is freely mutable and replacing a dead entry is not a
//! format event; the *upgrade* allowlist ([`super::OTS_UPGRADE_HOST_SUFFIXES`])
//! is append-only, because a stored `.ots` names its own calendar and cannot
//! be rewritten. The two lists are deliberately different objects with
//! different rules, and they are deliberately not the same strings.

/// The four default calendar endpoints, in upstream's own order
/// (`opentimestamps-client/otsclient/cmds.py:186-189`, retrieved
/// 2026-08-02T19:23:37Z; mirrored by `DEFAULT_AGGREGATORS` in
/// `python-opentimestamps/opentimestamps/calendar.py:156-160`).
///
/// Liveness re-verified for D54 across 2026-08-02T19:22:59Z–19:30:32Z: all
/// four answered.
pub const DEFAULT_OTS_CALENDARS: [&str; 4] = [
    "https://a.pool.opentimestamps.org",
    "https://b.pool.opentimestamps.org",
    "https://a.pool.eternitywall.com",
    "https://ots.btc.catallaxy.com",
];

/// Submission path appended to a calendar base URL
/// (`python-opentimestamps/opentimestamps/calendar.py:62`). The body is the
/// **32 raw digest bytes**, not hex.
pub const OTS_SUBMIT_PATH: &str = "digest";

/// Upgrade path prefix; the lowercase hex commitment is appended
/// (`calendar.py:80-81`).
pub const OTS_UPGRADE_PATH_PREFIX: &str = "timestamp/";

/// `Accept` header upstream's client sends (`calendar.py:55`), and the one
/// the A25 captures were taken with.
pub const OTS_ACCEPT_HEADER: &str = "application/vnd.opentimestamps.v1";

/// `Content-Type` for a submit body.
///
/// Upstream sends none at all; the A25 capture sent none either and the
/// calendars accepted it. It is set here because a POST with a body and no
/// declared type is the shape an intermediary is most likely to rewrite, and
/// `application/octet-stream` says exactly what the 32 bytes are.
pub const OTS_SUBMIT_CONTENT_TYPE: &str = "application/octet-stream";

/// Distinct pending-attestation URIs required for a non-degraded OTS outcome.
///
/// **Never a seal precondition.** A20's gate is TSA-only: at seal time an OTS
/// anchor is `pending`, `pending` is not headline-eligible (spec line 133),
/// and gating a paid irreversible seal on evidence that carries no time would
/// trade a permanent cost for zero evidentiary gain (D54 §3).
pub const OTS_MIN_DISTINCT_CALENDARS: usize = 2;

/// Wall-clock bound on the whole concurrent submission stage, in seconds.
/// ~11× the worst of 18 measured real submissions (2.619 s) — D54 §3.
pub const OTS_SUBMIT_DEADLINE_SECS: u64 = 30;

/// The effective calendar list: a config override replaces the defaults
/// **wholesale** (matching U26's `tsa_urls` semantics), an absent or empty
/// override falls back to [`DEFAULT_OTS_CALENDARS`], and the result is
/// **deduplicated**, first occurrence kept (U44, D188 R2).
///
/// An empty override falling back rather than disabling OTS is deliberate:
/// `ots_calendars = []` in a config file is far more likely to be a mistake
/// than a considered decision to stamp nowhere, and the way to stamp nowhere
/// is `--no-anchor`, which is loud and refused on mainnet.
///
/// The deduplication is [`crate::tsa::effective_tsa_urls`]' rule, for the
/// calendar family's own reason: a calendar listed twice would be POSTed to
/// twice and then counted once, because D54 §3 counts distinct pending URIs —
/// so a user who wrote two lines would get the one-calendar degradation they
/// did not ask for, from a list that looks like two. The comparison is
/// exact-string, as there.
///
/// This is the one list both calendar roles read (U52, U64): the submit
/// targets of the seal-time stage, and the hosts an upgrade may contact
/// beyond [`super::OTS_UPGRADE_HOST_SUFFIXES`].
#[must_use]
pub fn effective_calendars(config: Option<&[String]>) -> Vec<String> {
    let source: Vec<String> = match config {
        Some(list) if !list.is_empty() => list.to_vec(),
        _ => DEFAULT_OTS_CALENDARS
            .iter()
            .map(|url| (*url).to_owned())
            .collect(),
    };
    let mut out: Vec<String> = Vec::with_capacity(source.len());
    for url in source {
        if !out.contains(&url) {
            out.push(url);
        }
    }
    out
}

/// `base` + `/` + `path`, with exactly one separator however the base was
/// written — the same rule A16's esplora join applies, for the same reason: a
/// configured base with a trailing slash is a normal thing for a human to
/// type and must not produce `//digest`.
#[must_use]
pub fn join(base: &str, path: &str) -> String {
    format!("{}/{path}", base.trim_end_matches('/'))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// D54's named test. It pins all four literals **and their order**, so a
    /// reorder, addition, removal or typo is a deliberate edit here as well as
    /// in the constant.
    #[test]
    fn default_calendar_list_is_upstreams_verbatim() {
        assert_eq!(
            DEFAULT_OTS_CALENDARS,
            [
                "https://a.pool.opentimestamps.org",
                "https://b.pool.opentimestamps.org",
                "https://a.pool.eternitywall.com",
                "https://ots.btc.catallaxy.com",
            ]
        );
        assert!(DEFAULT_OTS_CALENDARS.len() >= OTS_MIN_DISTINCT_CALENDARS);
    }

    /// The submit list and the upgrade allowlist are different objects.
    ///
    /// Not a tautology: the obvious implementation of "the calendars we
    /// trust" is one list used for both, and that list would be append-only
    /// (the upgrade rule) *and* freely mutable (the submit rule) at once. The
    /// assertion that no default submit host is admitted by the upgrade
    /// allowlist is the observable consequence — the pool aliases are not
    /// calendar hostnames, so a `.ots` naming one would be refused, and any
    /// future edit that "helpfully" unified the two lists fails here.
    #[test]
    fn the_submit_list_and_the_upgrade_allowlist_are_not_the_same_list() {
        for calendar in DEFAULT_OTS_CALENDARS {
            assert_eq!(
                crate::ots::classify_upgrade_uri(calendar, &[]),
                Err(crate::ots::UpgradeUriRefusal::HostNotAllowed),
                "{calendar} is a submit alias, not a pending-attestation host"
            );
        }
    }

    #[test]
    fn a_config_override_replaces_the_defaults_wholesale() {
        let override_list = vec!["https://cal.example.com".to_owned()];
        assert_eq!(
            effective_calendars(Some(&override_list)),
            vec!["https://cal.example.com".to_owned()]
        );
        assert_eq!(effective_calendars(None).len(), DEFAULT_OTS_CALENDARS.len());
        // An empty override is a mistake, not a way to disable OTS.
        assert_eq!(
            effective_calendars(Some(&[])).len(),
            DEFAULT_OTS_CALENDARS.len()
        );
    }

    /// D188 R2: a repeated entry is one calendar, kept where it first
    /// appeared — and nothing else in the list moves. Two distinct entries
    /// around the repeat, so a "dedup" that sorted, or kept the LAST
    /// occurrence, would fail on order rather than pass on length.
    #[test]
    fn an_override_is_deduplicated_keeping_first_occurrence_order() {
        let configured = vec![
            "https://cal-b.example.com".to_owned(),
            "https://cal-a.example.com".to_owned(),
            "https://cal-b.example.com".to_owned(),
            "https://cal-c.example.com".to_owned(),
        ];
        assert_eq!(configured.len(), 4, "the fixture carries one repeat");
        assert_eq!(
            effective_calendars(Some(&configured)),
            vec![
                "https://cal-b.example.com".to_owned(),
                "https://cal-a.example.com".to_owned(),
                "https://cal-c.example.com".to_owned(),
            ],
            "a calendar listed twice must be one calendar, kept where it first appeared"
        );
        // Exact-string: two spellings of one host are two entries here.
        let spellings = vec![
            "https://cal.example.com".to_owned(),
            "https://cal.example.com/".to_owned(),
        ];
        assert_eq!(effective_calendars(Some(&spellings)), spellings);
        // The defaults carry no repeat, so the fallback is unchanged by it.
        assert_eq!(effective_calendars(None), DEFAULT_OTS_CALENDARS.to_vec());
    }

    #[test]
    fn join_produces_one_separator_however_the_base_was_written() {
        assert_eq!(
            join("https://cal.example.com", OTS_SUBMIT_PATH),
            "https://cal.example.com/digest"
        );
        assert_eq!(
            join("https://cal.example.com/", OTS_SUBMIT_PATH),
            "https://cal.example.com/digest"
        );
        assert_eq!(
            join("https://cal.example.com///", OTS_SUBMIT_PATH),
            "https://cal.example.com/digest"
        );
    }
}
