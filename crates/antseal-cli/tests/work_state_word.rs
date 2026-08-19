//! U70 acceptance suite: **one** production of the coarse work-state word,
//! and one of the finer pre-pay/post-pay pair.
//!
//! `WorkState` has four variants, and `antseal-cli` used to render it
//! through **four private functions in three vocabularies**, so the same
//! vault state answered in different words depending on which command was
//! typed: `status` said `incomplete`, and the same work under `restore` said
//! `incomplete (paid, not finalized)`. That is the D100 §1.2 class exactly —
//! one fact, several homes, each documented as obviously right and none
//! citing the others — and the citation is not decorative: D100 §1.2 is the
//! finding that a divergence cannot be fixed in one of its homes without
//! leaving the disagreement standing.
//!
//! The four were `status::work_state_name`, `listing::WorkRow::state_name`,
//! and byte-identical twins in `pipeline/restore.rs` and
//! `pipeline/reveal.rs`. The census in `status.rs`'s own doc was **off by
//! one** — it named the restore spelling and the listing one and called a
//! new one "a fourth", not knowing the reveal engine already carried one —
//! and that doc is corrected in the same change.
//!
//! # What this suite owns, and what it does not
//!
//! It owns the **count**. The exact copy is U31/Q20's catalogue-and-lint
//! work, which is far cheaper against one production than against four, and
//! a rewording that left four producers would not have satisfied U70. R18's
//! frozen wording table is **not** the home for any of this: it freezes
//! *verdict* wording for `verify` and the page, and a vault work state is
//! neither.
//!
//! NON-SECRET: source text only.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use antseal_cli::listing::{AnchorDamage, WorkRow};
use antseal_cli::status::{detail_state_name, work_state_name};
use antseal_cli::vault::store::WorkState;
use antseal_core::crypto::secrets::SealId;

/// Every `WorkState` variant, wildcard-free at this site too — a fifth
/// variant must break this list rather than be silently unexercised.
const EVERY_STATE: [WorkState; 4] = [
    WorkState::IncompletePrePay,
    WorkState::IncompletePostPay,
    WorkState::Complete,
    WorkState::Abandoned,
];

// ─────────────────────────────────────────────────────────────────────
// Accept row 1: exactly one producer, and a second one reddens
// ─────────────────────────────────────────────────────────────────────

/// **U70 accept row 1**: exactly one function in `antseal-cli` maps a
/// `WorkState` to a user-visible coarse state word, and a second one fails
/// this check.
///
/// # Why an agreement assertion would not do
///
/// A test that the four words currently *agree* goes green again the moment
/// somebody adds a fifth that happens to agree — which is precisely how this
/// row's subject arrived: `pipeline/reveal.rs`'s copy was written to agree
/// with `pipeline/restore.rs`'s, said so in its own doc, and agreed with
/// nothing else in the tree. So what is asserted is the **count of
/// productions**, not the equality of their outputs.
///
/// # What counts as a production
///
/// A source line matching a `WorkState` variant to a string literal:
/// `WorkState::Complete => "…"`. That is the shape all four had. The scan is
/// over `crates/antseal-cli/src/` only — the state's own wire encoding in
/// `vault/store.rs` maps to integers, not to words, and tests may spell
/// whatever they assert.
///
/// The two admitted sites are the coarse word and the finer pair, both in
/// `status.rs` and adjacent by design, so a reader looking for "how is a
/// work state spelled" finds one file with two answers and their
/// distinction, rather than four files with three.
#[test]
fn exactly_one_production_maps_a_work_state_to_a_word() {
    /// `(path, arms, warrant)` — the closed list.
    const PRODUCTIONS: [(&str, usize, &str); 1] = [(
        "crates/antseal-cli/src/status.rs",
        7,
        "the ONE coarse production (`work_state_name`, 3 arms) beside the ONE finer production \
         (`detail_state_name`, 4 arms) — U70",
    )];
    /// The variant→literal form, assembled so this scan's own source does
    /// not contain what it hunts for.
    const MARKER: &str = concat!("WorkState", "::");

    fn collect(dir: &Path, out: &mut Vec<PathBuf>) {
        let entries =
            std::fs::read_dir(dir).unwrap_or_else(|e| panic!("cannot list {}: {e}", dir.display()));
        for entry in entries {
            let path = entry
                .unwrap_or_else(|e| panic!("cannot read an entry under {}: {e}", dir.display()))
                .path();
            if path.is_dir() {
                collect(&path, out);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                out.push(path);
            }
        }
    }

    /// A line that maps a variant to a string literal — `WorkState::X => "…"`
    /// or `WorkState::X | WorkState::Y => "…"`.
    fn is_production(line: &str) -> bool {
        let trimmed = line.trim();
        if !trimmed.contains(MARKER) || !trimmed.contains("=>") {
            return false;
        }
        let Some((left, right)) = trimmed.split_once("=>") else {
            return false;
        };
        left.contains(MARKER) && right.trim_start().starts_with('"')
    }

    // The detector must be able to see one, or it proves nothing about the
    // tree it is scanning.
    assert!(
        is_production(r#"        WorkState::Complete => "complete","#),
        "the detector cannot see a production"
    );
    assert!(
        is_production(r#"WorkState::IncompletePrePay | WorkState::IncompletePostPay => "x","#),
        "the detector cannot see a multi-variant production"
    );
    assert!(
        !is_production("        if record.state != WorkState::Complete {"),
        "a comparison is not a production"
    );
    assert!(
        !is_production(r#"            1 => Some(WorkState::IncompletePrePay),"#),
        "the wire decode is not a production"
    );

    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    collect(&src, &mut files);
    assert!(
        files.len() > 20,
        "the walker found only {} files under src/ — it is not reaching the tree",
        files.len()
    );

    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("the crate sits two levels under the workspace root")
        .to_path_buf();
    let mut found: BTreeMap<String, usize> = BTreeMap::new();
    for file in &files {
        let text = std::fs::read_to_string(file)
            .unwrap_or_else(|e| panic!("cannot read {}: {e}", file.display()));
        let count = text.lines().filter(|line| is_production(line)).count();
        if count > 0 {
            let relative = file
                .strip_prefix(&root)
                .expect("under the root")
                .to_string_lossy()
                .replace('\\', "/");
            found.insert(relative, count);
        }
    }

    let listed: std::collections::BTreeSet<&str> =
        PRODUCTIONS.iter().map(|(path, _, _)| *path).collect();
    let strays: Vec<&String> = found
        .keys()
        .filter(|path| !listed.contains(path.as_str()))
        .collect();
    assert!(
        strays.is_empty(),
        "a second production of the work-state word appeared: {strays:?}. One vault state must \
         have one spelling — four producers in three vocabularies is what U70 removed, and a \
         fifth arrives by being written next to a fourth. Call \
         `status::work_state_name` (coarse) or `status::detail_state_name` (pre-pay/post-pay), \
         and never re-spell the coarse word with a parenthetical."
    );
    for (path, arms, why) in PRODUCTIONS {
        let seen = found.get(path).copied().unwrap_or(0);
        assert_eq!(
            seen, arms,
            "`{path}` has {seen} state→word arm(s), not {arms}. Listed as: {why}"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────
// Accept row 2: asserted at the RENDER sites, not at the definition
// ─────────────────────────────────────────────────────────────────────

/// **U70 accept row 2**: every command that renders a work state renders it
/// through the one function — asserted where each command actually renders,
/// not where the function is defined.
///
/// A definition-side assertion proves the table is right and says nothing
/// about who reads it, which is the whole failure mode: the four producers
/// were each individually correct.
///
/// `list` is the surface with its own type, so it is checked through
/// [`WorkRow`]; `status` and `show` share the crate-internal function
/// directly and are covered by the source scan above plus the committed
/// report snapshots; `restore` and `reveal` no longer render the coarse word
/// at all — their refusals wanted the finer one, which is the next row.
#[test]
fn the_list_row_renders_the_one_coarse_word() {
    for state in EVERY_STATE {
        let row = row_in(state);
        assert_eq!(
            row.state_name(),
            work_state_name(state),
            "`list` must render {state:?} through the one production"
        );
    }
}

/// A bare `list` row in one state — every other field is irrelevant to the
/// word, and is set to the shape a work with no journal tag has, which is
/// the arm `detail_state_name` answers for.
fn row_in(state: WorkState) -> WorkRow {
    WorkRow {
        work_id: Some([0xA1; 32]),
        seal_id: SealId::from_bytes([0xE1; 16]),
        title: None,
        sealed_at_unix_secs: None,
        network: "devnet".to_owned(),
        state,
        fine_state: None,
        unanchored: false,
        degraded: false,
        cost_atto: None,
        resume: None,
        // U85/D152 R4: irrelevant to the word this suite is about, and a
        // work with no resume hint can never carry one.
        resume_refusal: None,
        pending_anchors: None,
        nag: None,
        damaged_anchors: AnchorDamage::default(),
    }
}

// ─────────────────────────────────────────────────────────────────────
// Accept row 4: the coarse and fine words are one fact each, not two
//               spellings of one
// ─────────────────────────────────────────────────────────────────────

/// **U70 accept row 4**: the pre-pay/post-pay distinction survives, with
/// exactly one production of its own, and it is **not** a second spelling of
/// the coarse word.
///
/// The distinction is real and the reason `restore` and `reveal` reach for
/// it: the difference between *"you owe nothing"* and *"you have paid and
/// the proofs expire"* is, at the moment those commands refuse, the
/// actionable fact. What U70 forbids is carrying it by re-spelling the
/// coarse word with a parenthetical — `incomplete (paid, not finalized)` —
/// which is how four producers happened. It is carried by `detail_state`'s
/// kebab pair instead: the shipped machine form, which `list --json` already
/// publishes, so the word an error names is the word a script reads.
#[test]
fn the_finer_word_is_the_shipped_kebab_pair_and_differs_from_the_coarse_one() {
    let coarse: Vec<&str> = EVERY_STATE.into_iter().map(work_state_name).collect();
    let fine: Vec<&str> = EVERY_STATE.into_iter().map(detail_state_name).collect();

    assert_eq!(
        coarse,
        ["incomplete", "incomplete", "complete", "abandoned"],
        "the coarse word collapses both incomplete arms"
    );
    assert_eq!(
        fine,
        [
            "incomplete-pre-pay",
            "incomplete-post-pay",
            "complete",
            "abandoned"
        ],
        "the finer word is `detail_state`'s shipped kebab pair, byte-unchanged"
    );
    assert_ne!(
        coarse[0], fine[0],
        "the two are different facts, not two spellings of one"
    );

    // And no production anywhere carries the parenthetical form the four
    // producers used — the specific shape U70 removed.
    for word in coarse.iter().chain(fine.iter()) {
        assert!(
            !word.contains('('),
            "`{word}` re-spells the coarse word with a parenthetical, which is what created U70"
        );
    }

    // The `list --json` wire value is the finer word for a row with no
    // journal tag — the shipped machine form, unmoved.
    for state in EVERY_STATE {
        let row = row_in(state);
        assert_eq!(
            row.detail_state_name(),
            detail_state_name(state),
            "`detail_state`'s fallback arm is the one finer production"
        );
    }
}

/// **U70 accept row 2, the other four surfaces**: `status`, `show`,
/// `restore` and `reveal` each reach the one production, asserted at the
/// **call site** in each renderer rather than at the definition.
///
/// [`the_list_row_renders_the_one_coarse_word`] covers `list` behaviourally,
/// because `WorkRow` is constructible from outside the crate. The other four
/// are not reachable that cheaply — `status` and `show` need a vault with a
/// gathered work, and `restore`/`reveal` need an *incomplete* one, which is
/// three vault creations and three seals to assert a word — so they are
/// pinned the way U71 pins its own call site: a closed table of call sites
/// with the count per file.
///
/// A definition-side assertion would prove the table is right and say
/// nothing about who reads it, which is the exact failure mode U70 is about:
/// the four producers were each individually correct.
#[test]
fn every_renderer_calls_the_one_production() {
    /// `(path, `work_state_name(` hits, `detail_state_name(` hits, warrant)`.
    ///
    /// The counts are of the **token**, so a file that also *defines* or
    /// *declares* one counts it — each warrant says what its number is made
    /// of, exactly as D128 §3 R2's model does. What the check buys is that a
    /// count which moves reddens, whichever half of it moved.
    const RENDERERS: [(&str, usize, usize, &str); 5] = [
        (
            "src/status.rs",
            3,
            1,
            "the two definitions, plus `status`'s own two renders: the badge line and the \
             --json `state` key",
        ),
        (
            "src/show.rs",
            2,
            0,
            "`show`'s two renders (header line and `state`); it imports the name, so neither \
             hit is a definition",
        ),
        (
            "src/listing.rs",
            1,
            4,
            "`list`: WorkRow::state_name's one call, and for the finer word its own method \
             declaration, the fallback call into the one production, and the method's two \
             render sites (the human `state:` line and the `detail_state` --json key)",
        ),
        (
            "src/pipeline/restore.rs",
            0,
            1,
            "`restore`: NotRestorable names the FINER word and never the coarse one — at that \
             refusal, pre-pay vs post-pay is the actionable fact",
        ),
        (
            "src/pipeline/reveal.rs",
            0,
            1,
            "`reveal`: NotRevealable, for restore's reason (this file used to hold a \
             byte-identical twin of restore's own table)",
        ),
    ];
    const COARSE: &str = concat!("work_state_name", "(");
    const FINE: &str = concat!("detail_state_name", "(");

    let crate_root = Path::new(env!("CARGO_MANIFEST_DIR"));
    for (relative, coarse, fine, why) in RENDERERS {
        let path = crate_root.join(relative);
        let text = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
        let coarse_seen = text.matches(COARSE).count();
        let fine_seen = text.matches(FINE).count();
        assert_eq!(
            (coarse_seen, fine_seen),
            (coarse, fine),
            "{relative} names the coarse production {coarse_seen} time(s) and the finer one \
             {fine_seen} time(s), not ({coarse}, {fine}). Listed as: {why}. A renderer that \
             stopped calling has grown a spelling of its own, which is U70's subject."
        );
    }
}
