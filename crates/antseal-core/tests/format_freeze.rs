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

#[track_caller]
fn expect_red(root: &Path, needle: &str) {
    match check_dir(root) {
        Err(failures) => {
            let rendered = render(&failures);
            assert!(
                rendered.contains(needle),
                "failure must mention `{needle}`, got:\n{rendered}"
            );
        }
        Ok(_) => panic!("check_dir must fail (expected `{needle}`), but the directory passed"),
    }
}

#[track_caller]
fn expect_green(root: &Path) {
    if let Err(failures) = check_dir(root) {
        panic!("{}", render(&failures));
    }
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
#[test]
fn format_freeze_red_on_freezing_a_working_note() {
    let root = scratch_dir("frozen_note");
    write_manifest(
        &root,
        HEADER,
        &["registry-v1.json", "registry-v1.md", "some-plan.md"],
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
