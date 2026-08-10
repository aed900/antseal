//! **Q50 — the wire-registry freeze digest.**
//!
//! `docs/format/registry-v1.md` *is* format v1 — the normative text a
//! third-party verifier implements from — and `registry-v1.json` is its
//! machine mirror. Until this gate existed, both sat outside every freeze
//! mechanism in the project: `scripts/vector-freeze.sh` covers
//! `testdata/vectors/v<n>/*.json` only, and nothing pinned a byte of the
//! registry.
//!
//! # Why a consistency check is not a pin
//!
//! `format_registry_freeze.rs` asserts, in both directions, that the code
//! agrees with the mirror — 19 D10 caps, 68 map keys and their names, 13
//! scalar lengths, 5 enums, 3 tuple arities, version dispatch. Every one of
//! those is *"code and JSON must agree"*, and a coordinated edit of both
//! sides in one commit passes the whole suite, forever. Post-freeze that is
//! a silent format change: the caps alone decide whether a given
//! `.sealproof` is a valid v1 bundle, and D84 §7 puts them explicitly inside
//! the freeze.
//!
//! A digest is the thing a coordinated edit cannot satisfy quietly. It does
//! not say the values are *right* — the cross-checks do that — it says they
//! are *the ones that were signed off*, and that changing them is a visible
//! act with a diff in a committed file.
//!
//! # Semantics
//!
//! The same append-only / refuse-on-change contract the Q6 vector freeze
//! implements, over the same manifest format and the same directive parser
//! ([`freeze_manifest`]). While `#! status pre-freeze` an entry may be
//! re-blessed as a recorded, justified change; under `#! status frozen`
//! (set at Q14) `scripts/format-freeze.sh --update` refuses to modify or
//! drop one, and the only legal change is an **addition** — a
//! `registry-v2.*` pair, under a new format version, beside v1's rather
//! than replacing it (MVP-SPEC.md line 123: every released version stays
//! verifiable forever).
//!
//! # Discovery, so a v2 registry cannot land unfrozen
//!
//! The must-freeze set is not a hand-written list of two paths: it is every
//! `registry-v<n>.md` / `registry-v<n>.json` in `docs/format/`. A future
//! `registry-v2.md` that nobody adds to the manifest turns this red, which
//! is the same one-sided-guarantee argument Q6 makes for vectors — a
//! checker can only fail on files it knows about.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

/// The freeze-manifest format — model, directive parser, digest helper —
/// shared with `vector_freeze.rs` (Q6), so `#! status frozen` has exactly
/// one meaning in this repo and one set of tests-of-the-test behind it.
#[path = "freeze_manifest/mod.rs"]
mod freeze_manifest;

use freeze_manifest::{EntryPolicy, Status, hex_sha256, parse_manifest};

/// The directory holding the normative registry and its mirror.
const FORMAT_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../docs/format");

/// This manifest's file name — the same name the vector freeze uses, so the
/// convention is recognisable rather than per-directory trivia.
const MANIFEST_NAME: &str = "FROZEN.sha256";

/// Which files this manifest may freeze. `docs/format/` also holds working
/// documents — the Q14 gate plan, the anchor-artifact-limits note — and
/// those are deliberately outside the freeze: they are *about* the format,
/// not the format.
const REGISTRY_ENTRIES: EntryPolicy = EntryPolicy {
    required_name_prefix: "registry-v",
    allowed_suffixes: &[".md", ".json"],
    excluded_paths: &[MANIFEST_NAME],
    subject: "the wire-registry freeze",
};

/// Every file that must be frozen: the normative document and the mirror of
/// each format version present in the directory.
fn must_be_frozen(dir: &Path) -> Result<BTreeSet<String>, String> {
    let mut found = BTreeSet::new();
    let entries = fs::read_dir(dir).map_err(|e| format!("{}: cannot list ({e})", dir.display()))?;
    for entry in entries {
        let entry = entry.map_err(|e| format!("{}: cannot read an entry ({e})", dir.display()))?;
        let name = entry.file_name().to_string_lossy().into_owned();
        let Some(stem) = name
            .strip_suffix(".md")
            .or_else(|| name.strip_suffix(".json"))
        else {
            continue;
        };
        // `registry-v<n>` and nothing else. A working note in this directory
        // is about the format, not the format.
        if let Some(version) = stem.strip_prefix("registry-v")
            && !version.is_empty()
            && version.bytes().all(|b| b.is_ascii_digit())
        {
            found.insert(name);
        }
    }
    if found.is_empty() {
        return Err(format!(
            "{}: no `registry-v<n>.{{md,json}}` found — the freeze would be vacuous",
            dir.display()
        ));
    }
    Ok(found)
}

/// Run the whole gate over one `docs/format`-shaped directory. Returns every
/// failure rather than the first, so one run names the whole problem.
fn check_dir(dir: &Path) -> Result<usize, Vec<String>> {
    let manifest_path = dir.join(MANIFEST_NAME);
    let text = match fs::read_to_string(&manifest_path) {
        Ok(text) => text,
        Err(err) => {
            return Err(vec![format!(
                "{}: cannot read the freeze manifest ({err}) — without it the wire registry is \
                 unfrozen, and a post-freeze edit to it would pass unnoticed (Q50)",
                manifest_path.display()
            )]);
        }
    };
    let origin = manifest_path.display().to_string();
    let manifest = parse_manifest(&text, &origin, &REGISTRY_ENTRIES).map_err(|e| vec![e])?;

    let mut failures = Vec::new();

    // Entries are byte-sorted and duplicate-free: the manifest is a diffable
    // inventory, and a duplicate path could pin two different digests.
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    let mut previous: Option<&str> = None;
    for entry in &manifest.entries {
        if !seen.insert(entry.path.as_str()) {
            failures.push(format!("{origin}: `{}` listed twice", entry.path));
        }
        if previous.is_some_and(|prev| prev >= entry.path.as_str()) {
            failures.push(format!(
                "{origin}: `{}` is out of order — entries are byte-sorted by path so the \
                 manifest diffs cleanly (`scripts/format-freeze.sh --update` sorts them)",
                entry.path
            ));
        }
        previous = Some(entry.path.as_str());
    }

    // The freeze itself: every listed file exists and hashes to its pin.
    for entry in &manifest.entries {
        match fs::read(dir.join(&entry.path)) {
            Err(err) => failures.push(format!(
                "{origin}: frozen registry file `{}` is MISSING ({err}) — a released format \
                 version stays verifiable forever (MVP-SPEC.md line 123), so deleting its \
                 normative text is never a legal change",
                entry.path
            )),
            Ok(bytes) => {
                let actual = hex_sha256(&bytes);
                if actual != entry.digest {
                    failures.push(format!(
                        "{origin}: frozen registry file `{}` CHANGED\n      pinned {}\n      \
                         actual {}\n    the wire registry IS format v1 — a byte change to it is \
                         a format-version event, not an edit (MVP-SPEC.md line 123; procedure \
                         Q27). If the change is editorial, it still needs a recorded, reviewed \
                         re-bless via `scripts/format-freeze.sh --update`.",
                        entry.path, entry.digest, actual
                    ));
                }
            }
        }
    }

    // The other direction: nothing that must be frozen sits outside the
    // manifest. Without this a `registry-v2.*` could land unfrozen and the
    // gate would stay green, which is the failure mode Q6 exists to prevent
    // one directory over.
    match must_be_frozen(dir) {
        Err(err) => failures.push(err),
        Ok(required) => {
            for path in &required {
                if !seen.contains(path.as_str()) {
                    failures.push(format!(
                        "{origin}: `{path}` is a registry document but is NOT frozen — every \
                         `registry-v<n>.{{md,json}}` must be pinned, or a format version could \
                         ship outside the freeze"
                    ));
                }
            }
        }
    }

    if manifest.status != Status::Frozen {
        failures.push(format!(
            "{origin}: status is `{:?}`, but the wire registry froze at Q14 — a manifest that \
             still calls itself pre-freeze permits a silent re-bless",
            manifest.status
        ));
    }

    if failures.is_empty() {
        Ok(manifest.entries.len())
    } else {
        Err(failures)
    }
}

fn render(failures: &[String]) -> String {
    let mut out = format!("{} format-freeze failure(s):\n", failures.len());
    for failure in failures {
        out.push_str("  - ");
        out.push_str(failure);
        out.push('\n');
    }
    out
}

// ---------------------------------------------------------------------------
// the gate
// ---------------------------------------------------------------------------

/// **The Q50 gate**: the normative wire registry and its mirror are pinned
/// at their exact bytes, still present, and nothing that defines a format
/// version sits outside the freeze.
#[test]
fn format_freeze_pins_the_wire_registry() {
    match check_dir(Path::new(FORMAT_DIR)) {
        Ok(count) => assert!(
            count >= 2,
            "v1 alone contributes two entries (the document and its mirror)"
        ),
        Err(failures) => panic!("{}", render(&failures)),
    }
}

// ---------------------------------------------------------------------------
// tests-of-the-test: every failure class turns the gate red, and the one
// legal change stays green
// ---------------------------------------------------------------------------

/// A scratch `docs/format`-shaped directory with a frozen v1 pair.
fn scratch_dir(test: &str) -> PathBuf {
    let root = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join("format_freeze")
        .join(test);
    if root.exists() {
        fs::remove_dir_all(&root).expect("scratch cleanup");
    }
    fs::create_dir_all(&root).expect("scratch dir");
    fs::write(root.join("registry-v1.md"), b"# registry\n").expect("write doc");
    fs::write(root.join("registry-v1.json"), b"{\"registry_version\":1}\n").expect("write mirror");
    // A working note in the same directory, which must stay outside the
    // freeze — otherwise every edit to a plan would read as a format event.
    fs::write(root.join("some-plan.md"), b"working notes\n").expect("write note");
    write_manifest(&root, HEADER, &["registry-v1.json", "registry-v1.md"]);
    root
}

const HEADER: &str = "#! manifest-version 1\n\
     #! format-version v1\n\
     #! status frozen\n\
     #! freeze-gate Q14\n";

/// Rewrite the manifest with freshly computed digests for the given paths.
fn write_manifest(root: &Path, header: &str, paths: &[&str]) {
    let mut text = header.to_owned();
    for path in paths {
        let bytes = fs::read(root.join(path)).expect("read for hashing");
        text.push_str(&format!("{}  {path}\n", hex_sha256(&bytes)));
    }
    fs::write(root.join(MANIFEST_NAME), text).expect("write manifest");
}

/// A gate outcome must be red, and must *say why* — a red assertion that
/// does not name its failure class passes on the next failure too.
#[track_caller]
fn expect_failure(outcome: Result<usize, Vec<String>>, needle: &str) {
    match outcome {
        Err(failures) => {
            let rendered = render(&failures);
            assert!(
                rendered.contains(needle),
                "failure must mention `{needle}`, got:\n{rendered}"
            );
        }
        Ok(_) => panic!("the check must fail (expected `{needle}`), but it passed"),
    }
}

#[track_caller]
fn expect_success(outcome: Result<usize, Vec<String>>) {
    if let Err(failures) = outcome {
        panic!("{}", render(&failures));
    }
}

#[track_caller]
fn expect_red(root: &Path, needle: &str) {
    expect_failure(check_dir(root), needle);
}

#[track_caller]
fn expect_green(root: &Path) {
    expect_success(check_dir(root));
}

/// The positive control. Without it every red assertion below could be
/// passing for the wrong reason.
#[test]
fn format_freeze_scratch_baseline_is_green() {
    expect_green(&scratch_dir("baseline"));
}

/// **The assertion Q50 exists for.** One byte changed in the normative
/// registry turns the gate red.
#[test]
fn format_freeze_red_on_a_mutated_registry_document() {
    let root = scratch_dir("mutated_doc");
    fs::write(root.join("registry-v1.md"), b"# registry\n\n(edited)\n").expect("mutate");
    expect_red(&root, "CHANGED");
}

/// The same for the mirror — which is where the 19 caps and every key
/// number actually live, so this is the case a coordinated edit would
/// otherwise have slipped through.
#[test]
fn format_freeze_red_on_a_mutated_mirror() {
    let root = scratch_dir("mutated_mirror");
    fs::write(root.join("registry-v1.json"), b"{\"registry_version\":2}\n").expect("mutate");
    expect_red(&root, "CHANGED");
}

/// Deletion is invisible to any checker that only reads files it finds, so
/// the manifest is also the must-exist list.
#[test]
fn format_freeze_red_on_a_deleted_registry_document() {
    let root = scratch_dir("deleted");
    fs::remove_file(root.join("registry-v1.md")).expect("delete");
    expect_red(&root, "is MISSING");
}

/// A v2 registry that nobody froze must not pass. This is the direction a
/// manifest cannot enforce by itself — it needs directory discovery.
#[test]
fn format_freeze_red_on_an_unfrozen_registry_version() {
    let root = scratch_dir("unfrozen_v2");
    fs::write(root.join("registry-v2.md"), b"# registry v2\n").expect("write v2");
    expect_red(&root, "is NOT frozen");
}

/// …and freezing it is the legal change: additions are always allowed.
#[test]
fn format_freeze_green_on_an_added_registry_version() {
    let root = scratch_dir("added_v2");
    fs::write(root.join("registry-v2.md"), b"# registry v2\n").expect("write v2");
    fs::write(root.join("registry-v2.json"), b"{\"registry_version\":2}\n").expect("write v2");
    write_manifest(
        &root,
        HEADER,
        &[
            "registry-v1.json",
            "registry-v1.md",
            "registry-v2.json",
            "registry-v2.md",
        ],
    );
    expect_green(&root);
}

/// A working note in the same directory is not part of the format and must
/// not be freezable — otherwise editing a plan would read as a format event
/// and the freeze would be ignored as noise.
///
/// **This is the rule [`ERRATA_NAME`] is named for** (D108 R4). A reading
/// note *about* frozen text must never become frozen itself, or it would be
/// as unamendable as the sentence it exists to scope — so the second half of
/// this test asserts the name really is outside the policy, rather than
/// leaving that as a claim in the errata file's own prose.
#[test]
fn format_freeze_red_on_freezing_a_working_note() {
    let root = scratch_dir("frozen_note");
    write_manifest(
        &root,
        HEADER,
        &["registry-v1.json", "registry-v1.md", "some-plan.md"],
    );
    expect_red(&root, "is not part of the wire-registry freeze");

    write_errata(&root, &[("registry-v1.md", "# registry")]);
    write_manifest(
        &root,
        HEADER,
        &[ERRATA_NAME, "registry-v1.json", "registry-v1.md"],
    );
    expect_red(&root, "is not part of the wire-registry freeze");
}

/// A manifest that still calls itself pre-freeze permits a silent re-bless.
#[test]
fn format_freeze_red_on_a_pre_freeze_status() {
    let root = scratch_dir("pre_freeze");
    write_manifest(
        &root,
        "#! manifest-version 1\n\
         #! format-version v1\n\
         #! status pre-freeze\n\
         #! freeze-gate Q14\n",
        &["registry-v1.json", "registry-v1.md"],
    );
    expect_red(&root, "still calls itself pre-freeze");
}

/// An empty manifest asserts nothing and must fail loudly rather than pass
/// vacuously — the shared parser's rule, exercised here so this consumer
/// inherits it in fact and not only in principle.
#[test]
fn format_freeze_red_on_an_empty_manifest() {
    let root = scratch_dir("empty");
    fs::write(root.join(MANIFEST_NAME), HEADER).expect("write manifest");
    expect_red(&root, "zero frozen entries");
}

/// A missing manifest is a failure, not a skip.
#[test]
fn format_freeze_red_without_a_manifest() {
    let root = scratch_dir("no_manifest");
    fs::remove_file(root.join(MANIFEST_NAME)).expect("delete manifest");
    expect_red(&root, "cannot read the freeze manifest");
}

/// Entries are byte-sorted so the manifest diffs cleanly.
#[test]
fn format_freeze_red_on_unsorted_entries() {
    let root = scratch_dir("unsorted");
    write_manifest(&root, HEADER, &["registry-v1.md", "registry-v1.json"]);
    expect_red(&root, "is out of order");
}

// ---------------------------------------------------------------------------
// the errata gate (Q129, ruled by D108 R4 / §6)
// ---------------------------------------------------------------------------
//
// A frozen document cannot point at anything: every one of its bytes is
// pinned, so a sentence that will be over-read cannot carry its own
// correction. D108 records two such sentences — registry §7.6 key 3's `len/shape`
// cell and the same claim, differently worded, in the mirror's `notes`
// for that key — as errata in
// `docs/format/frozen-registry-errata.md`, and refuses the in-place edit
// (§3.1 C1–C3: the price is a re-bless *plus* a tag event, since
// `format-v1-freeze` now exists).
//
// The danger of a note about frozen text is that it outlives or drifts from
// the text. So each entry is **pinned to its own sentence**: the erratum
// quotes it byte-verbatim, and this gate proves the quotation is still
// byte-present in a file the manifest actually freezes. That couples the two
// in both directions. If §8's option B is ever taken and the sentence is
// re-blessed, the quotation stops matching and this gate goes red — forcing
// the erratum to be retired in the same commit rather than surviving as a
// note about text that no longer exists.

/// The errata file, checked here and frozen nowhere.
///
/// The name is chosen so a mistake is impossible rather than unlikely.
/// Not `registry-v1-errata.md`: [`must_be_frozen`] would not *require* that
/// name (it collects `registry-v<digits>` only), but [`REGISTRY_ENTRIES`]
/// would **accept** it into the manifest, so a later lane could freeze a
/// reading note by accident and make it as unamendable as the text it
/// annotates. This name the manifest parser cannot take at all —
/// `format_freeze_red_on_freezing_a_working_note` is that rule's red case.
const ERRATA_NAME: &str = "frozen-registry-errata.md";

/// One entry of [`ERRATA_NAME`], reduced to what this gate reads.
struct Erratum {
    /// The `### ` heading, so a failure names the entry a reader can find.
    heading: String,
    /// `- file:` — the frozen document this entry reads against.
    file: String,
    /// `- quotes:` — the sentence, byte-verbatim.
    quotes: String,
}

/// The value of a `- <field>:` line: the bytes between its outer backticks.
///
/// A backtick span rather than bare text, because the whole instrument is a
/// byte comparison: without delimiters, trailing whitespace or a stray
/// markdown period would join or leave the quotation silently and the pin
/// would fail for a reason no reader could see.
fn backtick_span(value: &str) -> Option<&str> {
    let inner = value.strip_prefix('`')?.strip_suffix('`')?;
    (!inner.is_empty()).then_some(inner)
}

/// Read one backtick-span field into `slot`, refusing an absent span and a
/// second occurrence.
fn take_span(
    slot: &mut Option<String>,
    field: &str,
    value: &str,
    heading: &str,
    origin: &str,
    failures: &mut Vec<String>,
) {
    let value = value.trim();
    let Some(inner) = backtick_span(value) else {
        failures.push(format!(
            "{origin}: erratum `{heading}`'s `- {field}:` must be a non-empty backtick span \
             (got `{value}`) — the backticks bound the value so neither whitespace nor \
             surrounding prose can join a quotation this gate compares byte-for-byte"
        ));
        return;
    };
    if slot.is_some() {
        failures.push(format!(
            "{origin}: erratum `{heading}` gives `- {field}:` twice — one entry corrects one \
             sentence"
        ));
        return;
    }
    *slot = Some(inner.to_owned());
}

/// An entry under construction, before its required fields are known present.
struct PendingErratum {
    heading: String,
    file: Option<String>,
    quotes: Option<String>,
    /// `- scope:` is required and non-empty, but its prose is for the reader,
    /// not for this gate: an erratum without a scope note is a complaint.
    scope: bool,
}

/// Close one entry: either a complete [`Erratum`], or a failure naming every
/// field it lacks.
fn close_erratum(
    pending: Option<PendingErratum>,
    origin: &str,
    entries: &mut Vec<Erratum>,
    failures: &mut Vec<String>,
) {
    let Some(PendingErratum {
        heading,
        file,
        quotes,
        scope,
    }) = pending
    else {
        return;
    };
    let mut missing: Vec<&str> = Vec::new();
    if file.is_none() {
        missing.push("`- file:`");
    }
    if quotes.is_none() {
        missing.push("`- quotes:`");
    }
    if !scope {
        missing.push("`- scope:`");
    }
    if let (Some(file), Some(quotes)) = (file, quotes)
        && scope
    {
        entries.push(Erratum {
            heading,
            file,
            quotes,
        });
    } else {
        failures.push(format!(
            "{origin}: erratum `{heading}` is missing {} — every entry names the frozen file it \
             reads against, quotes its sentence byte-verbatim, and states the scope (D108 R4)",
            missing.join(", ")
        ));
    }
}

/// Parse the errata file. **Every `### ` heading is an entry** — the file
/// says so in its own §1 — so a `###` used for prose fails loudly here rather
/// than adding a silent, fieldless entry.
///
/// An entry runs from its heading to the **next heading of the same level or
/// above**, never to end-of-file. The errata file is mostly free prose by
/// design (§2 is a bulleted list), and without that boundary a `- scope:`
/// written in a later section would retroactively complete an entry that
/// never gave one — the parser's only fail-open path.
/// [`errata_red_on_a_field_borrowed_from_a_later_section`] is its red case.
fn parse_errata(text: &str, origin: &str) -> (Vec<Erratum>, Vec<String>) {
    let mut entries = Vec::new();
    let mut failures = Vec::new();
    let mut pending: Option<PendingErratum> = None;

    for line in text.lines() {
        if let Some(heading) = line.strip_prefix("### ") {
            close_erratum(pending.take(), origin, &mut entries, &mut failures);
            pending = Some(PendingErratum {
                heading: heading.trim().to_owned(),
                file: None,
                quotes: None,
                scope: false,
            });
            continue;
        }
        if line.starts_with("# ") || line.starts_with("## ") {
            close_erratum(pending.take(), origin, &mut entries, &mut failures);
            continue;
        }
        let Some(entry) = pending.as_mut() else {
            continue;
        };
        let trimmed = line.trim_start();
        if let Some(value) = trimmed.strip_prefix("- file:") {
            take_span(
                &mut entry.file,
                "file",
                value,
                &entry.heading,
                origin,
                &mut failures,
            );
        } else if let Some(value) = trimmed.strip_prefix("- quotes:") {
            take_span(
                &mut entry.quotes,
                "quotes",
                value,
                &entry.heading,
                origin,
                &mut failures,
            );
        } else if let Some(value) = trimmed.strip_prefix("- scope:") {
            entry.scope |= !value.trim().is_empty();
        }
    }
    close_erratum(pending.take(), origin, &mut entries, &mut failures);

    (entries, failures)
}

/// Byte-containment. The pin is over bytes, not over `str` — a quotation is
/// the sentence as the frozen file encodes it.
fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && needle.len() <= haystack.len()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

/// Run the errata gate over one `docs/format`-shaped directory: every entry
/// reads against a **frozen** file and quotes a sentence still byte-present
/// in it. Returns every failure rather than the first.
fn check_errata(dir: &Path) -> Result<usize, Vec<String>> {
    let manifest_path = dir.join(MANIFEST_NAME);
    let manifest_origin = manifest_path.display().to_string();
    let manifest_text = fs::read_to_string(&manifest_path).map_err(|err| {
        vec![format!(
            "{manifest_origin}: cannot read the freeze manifest ({err}) — without it there is no \
             frozen set to hold an erratum against"
        )]
    })?;
    let manifest =
        parse_manifest(&manifest_text, &manifest_origin, &REGISTRY_ENTRIES).map_err(|e| vec![e])?;
    let frozen: BTreeSet<&str> = manifest
        .entries
        .iter()
        .map(|entry| entry.path.as_str())
        .collect();

    let errata_path = dir.join(ERRATA_NAME);
    let origin = errata_path.display().to_string();
    let text = match fs::read_to_string(&errata_path) {
        Ok(text) => text,
        Err(err) => {
            return Err(vec![format!(
                "{origin}: cannot read the errata file ({err}) — D108 R4 records two frozen \
                 sentences here and this gate is what keeps them pinned, so an absent file is a \
                 vacuous green rather than a clean one. When the last erratum is retired (the \
                 next registry version), retire this gate in the same act"
            )]);
        }
    };

    let (entries, mut failures) = parse_errata(&text, &origin);

    // Anti-vacuity: an emptied errata file must not make this gate pass while
    // asserting nothing (D108 §6).
    if entries.is_empty() {
        failures.push(format!(
            "{origin}: zero errata entries — every `### ` heading is an entry carrying `- file:`, \
             `- quotes:` and `- scope:`, and a file with none asserts nothing (D108 §6)"
        ));
    }

    for erratum in &entries {
        // An erratum against an unfrozen file is a note smuggled into policy:
        // the file it annotates could then be edited freely, and the entry
        // would read as a standing rule nobody pinned.
        if !frozen.contains(erratum.file.as_str()) {
            failures.push(format!(
                "{origin}: erratum `{}` reads against `{}`, which is NOT a frozen entry of \
                 {MANIFEST_NAME} — an erratum corrects text that cannot be corrected in place, so \
                 an unfrozen subject means the sentence should simply be fixed (D108 §6)",
                erratum.heading, erratum.file
            ));
            continue;
        }
        match fs::read(dir.join(&erratum.file)) {
            Err(err) => failures.push(format!(
                "{origin}: erratum `{}` reads against `{}`, which cannot be read ({err})",
                erratum.heading, erratum.file
            )),
            Ok(bytes) => {
                if !contains_bytes(&bytes, erratum.quotes.as_bytes()) {
                    failures.push(format!(
                        "{origin}: erratum `{}` quotes\n      {}\n    which does NOT appear in \
                         `{}` — an erratum is pinned to the sentence it corrects, so a re-blessed \
                         or reworded sentence reddens here instead of leaving a note about text \
                         that no longer exists (D108 §6)",
                        erratum.heading, erratum.quotes, erratum.file
                    ));
                }
            }
        }
    }

    if failures.is_empty() {
        Ok(entries.len())
    } else {
        Err(failures)
    }
}

/// **The Q129 gate (D108 R4/§6)**: every erratum still quotes its frozen
/// sentence byte-for-byte, against a file the manifest really freezes.
#[test]
fn every_erratum_quotes_its_frozen_sentence_verbatim() {
    match check_errata(Path::new(FORMAT_DIR)) {
        Ok(count) => assert!(
            count >= 1,
            "the errata file records D108's two frozen sentences; zero entries is the vacuous \
             green this gate exists to refuse"
        ),
        Err(failures) => panic!("{}", render(&failures)),
    }
}

// ---- tests-of-the-test for the errata gate --------------------------------

/// Write a scratch errata file: one entry per `(file, quotation)` pair, in
/// the shape §1 of the real file documents.
fn write_errata(root: &Path, entries: &[(&str, &str)]) {
    let mut text = String::from("# scratch errata\n\n## 1. Entries\n\n");
    for (file, quotes) in entries {
        text.push_str(&format!(
            "### {file} — a scratch entry\n- file: `{file}`\n- quotes: `{quotes}`\n- scope: a \
             scratch entry\n- queued for: nothing\n\n"
        ));
    }
    fs::write(root.join(ERRATA_NAME), text).expect("write errata");
}

/// The positive control, without which every red assertion below could be
/// passing for the wrong reason.
#[test]
fn errata_scratch_baseline_is_green() {
    let root = scratch_dir("errata_baseline");
    write_errata(&root, &[("registry-v1.md", "# registry")]);
    expect_success(check_errata(&root));
}

/// **The assertion D108 §6 exists for.** A quotation the frozen document does
/// not contain — a stale erratum, or a re-blessed sentence — is red.
#[test]
fn errata_red_on_a_quotation_the_frozen_document_does_not_contain() {
    let root = scratch_dir("errata_stale_quote");
    write_errata(&root, &[("registry-v1.md", "# registry v9")]);
    expect_failure(check_errata(&root), "does NOT appear");
}

/// An erratum against a file outside the freeze is refused by name: the
/// sentence would simply be editable, and the note would be policy nobody
/// pinned.
#[test]
fn errata_red_on_an_erratum_against_an_unfrozen_file() {
    let root = scratch_dir("errata_unfrozen_subject");
    write_errata(&root, &[("some-plan.md", "working notes")]);
    expect_failure(check_errata(&root), "is NOT a frozen entry");
}

/// Anti-vacuity: an emptied errata file asserts nothing and must not pass.
#[test]
fn errata_red_on_a_file_with_no_entries() {
    let root = scratch_dir("errata_empty");
    fs::write(root.join(ERRATA_NAME), "# scratch errata\n").expect("write errata");
    expect_failure(check_errata(&root), "zero errata entries");
}

/// A deleted errata file is a failure, not a skip — the same one-sided
/// guarantee `must_be_frozen` exists for one gate over.
#[test]
fn errata_red_without_an_errata_file() {
    let root = scratch_dir("errata_missing");
    expect_failure(check_errata(&root), "cannot read the errata file");
}

/// An entry that names no sentence is a complaint, not an erratum.
#[test]
fn errata_red_on_an_entry_missing_its_required_fields() {
    let root = scratch_dir("errata_fieldless");
    fs::write(
        root.join(ERRATA_NAME),
        "# scratch errata\n\n### registry-v1.md — a heading and nothing else\n\nprose\n",
    )
    .expect("write errata");
    expect_failure(check_errata(&root), "is missing");
}

/// An entry **ends at the next heading**, so prose in a later section cannot
/// satisfy a field the entry itself never gave.
///
/// The real errata file carries its two entries under `## 1. Entries` and
/// then two further `## ` sections of free prose — §2 of it is a bulleted
/// list — and §1 invites exactly that. Without a boundary the field scan
/// runs to end-of-file and a `- scope:` written anywhere below the last
/// entry retroactively completes it. That is the one **fail-open** path in
/// this parser, and a gate whose whole value is that it cannot be satisfied
/// quietly does not get to have one.
#[test]
fn errata_red_on_a_field_borrowed_from_a_later_section() {
    let root = scratch_dir("errata_section_bleed");
    fs::write(
        root.join(ERRATA_NAME),
        "# scratch errata\n\n## 1. Entries\n\n\
         ### registry-v1.md — an entry with no scope of its own\n\
         - file: `registry-v1.md`\n\
         - quotes: `# registry`\n\n\
         ## 2. Prose, which is not an entry\n\n\
         - scope: this line belongs to the section, not to the entry above\n",
    )
    .expect("write errata");
    expect_failure(check_errata(&root), "is missing");
}
