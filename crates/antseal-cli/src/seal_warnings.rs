//! The three seal-time warning moments (U15): what the title costs in
//! privacy, what `--no-fine-tree` costs permanently, and what a fine tree
//! costs in work.
//!
//! # All three are pure functions of the plan
//!
//! Nothing here reads a file, opens a vault or touches the network:
//! [`warnings_for`] takes a validated [`SealPlan`] and returns lines. That
//! is what makes "these surface before the consent prompt" structurally
//! true rather than a matter of where a `println!` happens to sit — the
//! lines are handed to the U14 gate as data and it renders them at the top
//! of the one pre-consent screen, above the quote (MVP-SPEC.md line 85's
//! "before the quote", in reading order).
//!
//! # One author, one render — deliberately not a second emitter
//!
//! The obvious alternative was to `eprintln!` these from
//! [`run_seal`](crate::seal_run::run_seal) at the top of the invocation,
//! ahead of the encryption pass. It was rejected: a second place that
//! prints pre-consent copy is a second place that can drift from the
//! first, and the U13 lane has already paid for that lesson once (the
//! resume plan silently vanished from the merged render because two
//! layers disagreed about which flag meant "this is a resume"). Folding
//! the warnings into the [`ConsentReport`](crate::seal_consent::ConsentReport)
//! means the rehearsal screen (`--dry-run`), the real screen, and the
//! `--json` document all carry them by construction, and there is exactly
//! one function to test.
//!
//! The cost of that choice, stated plainly: for a very large file the
//! fine-tree estimate is read *after* the trees were built rather than
//! before, because the consent gate sits downstream of encryption in the
//! normative order. What the number is actually for is the decision in
//! front of the user — whether this work is worth its cost and whether
//! `--no-fine-tree` is the better trade — and that decision is made on the
//! consent screen.
//!
//! # Why the `--no-fine-tree` warning is worded as permanence
//!
//! `docs/decisions/D24` made a shaping-flag conflict a hard error rather
//! than a warning on exactly this argument: what a seal records about a
//! file is frozen into a permanent, paid, public artifact and can never be
//! revised for that work. `--no-fine-tree` is the same class of decision —
//! the descriptor records the opt-out, every future bundle from this work
//! is whole-file-reveal only for those files, and the only remedy is to
//! seal the file again as a *different* work with a different `work_id`
//! and a different date. D24 could make its conflict an error because the
//! two flags were contradictory; this one is a legitimate choice, so it
//! gets the loudest thing short of a refusal.

use antseal_core::content::estimate_fine_tree_cost;

use crate::seal_plan::SealPlan;

/// Files at or above this size get the fine-tree cost line (U15's Notes:
/// the threshold is a U-owned constant, documented here).
///
/// **1 MiB**, and the number is chosen against
/// [`MAX_CHUNK_SIZE`](antseal_core::storage::MAX_CHUNK_SIZE) rather than
/// against a feeling about what "large" means. Autonomi caps one blob at
/// 4 MiB (D32/D10), so a binary file — always a single unit — is
/// *unsealable* above 4 MiB, and any threshold near that ceiling would
/// leave the line unreachable for exactly the case where `--no-fine-tree`
/// is the relevant lever. A quarter of the cap gives four visible steps
/// below the largest single-unit file there can be.
///
/// At ~5 SHA-256 compressions per byte
/// ([`estimate_fine_tree_cost`]) 1 MiB is ≈ 5.2 M compressions — around
/// where the fine-tree build becomes a noticeable share of seal time, and
/// therefore around where a user might reasonably want to trade byte-range
/// reveal for speed. Below it the line would be noise on the one screen
/// that must not be skimmed.
///
/// It is a constant rather than a config key on purpose: a threshold that
/// only decides whether an *advisory* line prints is not worth a
/// permanent, frozen entry in the config surface (U4), and a user who
/// wants the number for a smaller file can read the ratio off a larger
/// seal.
pub const FINE_TREE_ESTIMATE_THRESHOLD_BYTES: u64 = 1024 * 1024;

/// Every warning this invocation earns, in the order they render.
///
/// Order is deliberate: the two **permanent consequences** first (title
/// visibility, then lost reveal granularity), the **cost advisory** last.
/// A user who reads one line reads the one that cannot be undone.
#[must_use]
pub fn warnings_for(plan: &SealPlan) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(line) = title_warning(plan.shaping.title.as_deref()) {
        out.push(line);
    }
    out.extend(no_fine_tree_warning(&plan.no_fine_tree_matches()));
    out.extend(fine_tree_cost_lines(plan));
    out
}

/// MVP-SPEC.md line 34: "The title *is* embedded in the (plaintext)
/// manifest that every proof bundle carries, and `seal` warns it will be
/// visible to bundle recipients."
///
/// The warning quotes the title back. A user who typed
/// `--title "Q3 layoffs — draft for Legal"` needs to see those exact words
/// beside the sentence saying they travel with every bundle; naming the
/// flag alone lets someone confirm the mechanism while still mis-
/// remembering what they wrote.
///
/// An empty or whitespace-only title earns no warning: there is nothing to
/// disclose.
#[must_use]
pub fn title_warning(title: Option<&str>) -> Option<String> {
    let title = title?;
    if title.trim().is_empty() {
        return None;
    }
    Some(format!(
        "  WARNING: the title \"{title}\" is stored in the manifest as PLAINTEXT — it is \
         not encrypted. Every proof bundle produced from this work carries that manifest, \
         so everyone you ever show a bundle to can read the title, including someone shown \
         a single-unit reveal of one paragraph. It cannot be edited or removed after \
         sealing."
    ))
}

/// MVP-SPEC.md line 85: files a `--no-fine-tree` pattern matched "are
/// permanently whole-file-reveal only, and `seal` warns".
///
/// Names every matched file (U15 Accept row 2) rather than repeating the
/// pattern: the pattern is what the user typed, the file list is what it
/// did, and the gap between those two is the whole reason
/// [`build_plan`](crate::seal_plan::build_plan) refuses a pattern that
/// matches nothing.
#[must_use]
pub fn no_fine_tree_warning(matched: &[&str]) -> Option<String> {
    if matched.is_empty() {
        return None;
    }
    Some(format!(
        "  WARNING: --no-fine-tree matched {} file(s) — {}. These are sealed with no \
         byte-range commitment, so they are PERMANENTLY whole-file-reveal only: revealing \
         any part of one of them means revealing all of it, forever. The opt-out is \
         recorded in the manifest and can never be changed for this work — the only remedy \
         is to seal the file again later, as a different work with a different date.",
        matched.len(),
        matched.join(", ")
    ))
}

/// G10's estimate for every file large enough to be worth mentioning
/// (MVP-SPEC.md line 85: "`seal` prints an estimated fine-tree cost for
/// large files").
///
/// Two exclusions, both structural rather than cosmetic:
///
/// - a file a `--no-fine-tree` pattern matched builds **no** fine tree, so
///   quoting a cost for it would be false;
/// - the figure is derived from the on-disk size, which for a text file is
///   the size of its *raw* bytes while the tree is built over the
///   *canonical* rendition (NFC, LF, no BOM). Those differ, so the line
///   says "about" and names the byte count it used — an estimate that
///   silently claimed exactness it cannot have would be worse than none.
#[must_use]
pub fn fine_tree_cost_lines(plan: &SealPlan) -> Vec<String> {
    plan.files
        .iter()
        .filter(|f| !f.flags.no_fine_tree_matched())
        .filter(|f| f.size >= FINE_TREE_ESTIMATE_THRESHOLD_BYTES)
        .map(|f| {
            format!(
                "  Note: building the byte-range (fine) tree for {} costs about {} — \
                 estimated from its {} bytes on disk, before canonicalization. \
                 `--no-fine-tree` skips it, permanently.",
                f.as_given,
                estimate_fine_tree_cost(f.size),
                f.size
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::store::SealShapingFlags;
    use antseal_core::content::FileFlags;

    fn plan(files: Vec<crate::seal_plan::PlannedFile>, title: Option<&str>) -> SealPlan {
        SealPlan {
            files,
            shaping: SealShapingFlags {
                title: title.map(str::to_owned),
                no_anchor: true,
                ..SealShapingFlags::default()
            },
            network: antseal_net::NetworkId::Devnet,
            dry_run: false,
            yes: false,
        }
    }

    fn file(name: &str, size: u64, no_fine_tree: bool) -> crate::seal_plan::PlannedFile {
        crate::seal_plan::PlannedFile {
            as_given: name.to_owned(),
            absolute: format!("/w/{name}"),
            size,
            flags: if no_fine_tree {
                FileFlags::new().with_no_fine_tree()
            } else {
                FileFlags::new()
            },
        }
    }

    #[test]
    fn the_title_warning_says_plaintext_quotes_the_title_and_names_every_recipient() {
        let line = title_warning(Some("Q3 layoffs")).expect("a title earns a warning");
        // The spec's own claim: plaintext, in the manifest, in every bundle.
        assert!(line.contains("PLAINTEXT"), "{line}");
        assert!(line.contains("manifest"), "{line}");
        assert!(line.contains("Every proof bundle"), "{line}");
        // The words the user actually typed, quoted back.
        assert!(line.contains("\"Q3 layoffs\""), "{line}");
        // A partial reveal discloses it too — the case a user is most
        // likely to assume is safe.
        assert!(line.contains("single-unit reveal"), "{line}");
        assert!(line.contains("cannot be edited or removed"), "{line}");

        // No title, or a blank one, discloses nothing and says nothing.
        assert_eq!(title_warning(None), None);
        assert_eq!(title_warning(Some("   ")), None);
    }

    #[test]
    fn the_no_fine_tree_warning_names_the_matched_files_and_says_permanent() {
        let line = no_fine_tree_warning(&["blob.bin", "data/big.bin"]).expect("matches warn");
        assert!(line.contains("matched 2 file(s)"), "{line}");
        // U15 Accept row 2: it names the files, not just the pattern.
        assert!(line.contains("blob.bin"), "{line}");
        assert!(line.contains("data/big.bin"), "{line}");
        // The D24 irreversibility framing, in the loudest form short of a
        // refusal.
        assert!(line.contains("PERMANENTLY"), "{line}");
        assert!(line.contains("can never be changed"), "{line}");
        assert!(line.contains("whole-file-reveal only"), "{line}");

        assert_eq!(no_fine_tree_warning(&[]), None);
    }

    #[test]
    fn the_cost_estimate_appears_above_the_threshold_and_is_absent_below_it() {
        let below = plan(
            vec![file(
                "small.bin",
                FINE_TREE_ESTIMATE_THRESHOLD_BYTES - 1,
                false,
            )],
            None,
        );
        assert!(
            fine_tree_cost_lines(&below).is_empty(),
            "below the threshold the line is noise"
        );

        let at = plan(
            vec![file("big.bin", FINE_TREE_ESTIMATE_THRESHOLD_BYTES, false)],
            None,
        );
        let lines = fine_tree_cost_lines(&at);
        assert_eq!(lines.len(), 1, "the threshold is inclusive");
        assert!(lines[0].contains("big.bin"), "{}", lines[0]);
        // G10's own Display, not a re-implementation of its arithmetic.
        assert!(
            lines[0]
                .contains(&estimate_fine_tree_cost(FINE_TREE_ESTIMATE_THRESHOLD_BYTES).to_string()),
            "{}",
            lines[0]
        );
        assert!(lines[0].contains("SHA-256 compressions"), "{}", lines[0]);
        // Honest about what it measured.
        assert!(lines[0].contains("before canonicalization"), "{}", lines[0]);
    }

    /// A file with no fine tree has no fine-tree cost — quoting one would
    /// be a number for work that will never happen.
    #[test]
    fn a_no_fine_tree_file_gets_no_cost_estimate_however_large() {
        let p = plan(
            vec![
                file("huge.bin", 4 * FINE_TREE_ESTIMATE_THRESHOLD_BYTES, true),
                file(
                    "also-huge.bin",
                    4 * FINE_TREE_ESTIMATE_THRESHOLD_BYTES,
                    false,
                ),
            ],
            None,
        );
        let lines = fine_tree_cost_lines(&p);
        assert_eq!(lines.len(), 1);
        assert!(lines[0].contains("also-huge.bin"), "{}", lines[0]);
        assert!(!lines[0].contains("huge.bin  "), "{}", lines[0]);
        assert!(
            !lines
                .iter()
                .any(|l| l.starts_with("  Note: building the byte-range (fine) tree for huge.bin")),
            "{lines:?}"
        );
    }

    #[test]
    fn all_three_render_together_permanent_consequences_first() {
        let p = plan(
            vec![
                file("notes.txt", 10, false),
                file("blob.bin", 4 * FINE_TREE_ESTIMATE_THRESHOLD_BYTES, true),
                file("scan.tiff", 4 * FINE_TREE_ESTIMATE_THRESHOLD_BYTES, false),
            ],
            Some("thesis draft"),
        );
        let lines = warnings_for(&p);
        assert_eq!(lines.len(), 3, "{lines:#?}");
        assert!(lines[0].contains("PLAINTEXT"), "{}", lines[0]);
        assert!(lines[1].contains("--no-fine-tree"), "{}", lines[1]);
        assert!(lines[2].contains("Note: building"), "{}", lines[2]);
    }

    #[test]
    fn a_plain_seal_of_small_files_earns_no_warnings_at_all() {
        let p = plan(
            vec![file("a.txt", 10, false), file("b.txt", 20, false)],
            None,
        );
        assert!(warnings_for(&p).is_empty());
    }
}
