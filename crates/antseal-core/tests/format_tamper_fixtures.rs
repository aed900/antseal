//! F15 — the **consumer** of the format-level fixture→expected-error
//! mapping table (`testdata/tamper/format/FIXTURES.json`), and its emitter.
//!
//! The fixture *constructors* are WASM-safe and live in the library
//! ([`antseal_core::test_util::tamper_rows_format`]); the committed bytes and
//! the machine-readable mapping live under `testdata/tamper/format/`. This
//! file is the seam, and it is deliberately strict in both directions:
//!
//! 1. **The table describes the fixture set exactly** — same ids, same
//!    order, same base, mutation, surface, expected `(code, layer)` and row.
//!    A fixture added to the library without a table row (or the reverse)
//!    fails here, so the mapping can never drift into decoration.
//! 2. **The committed bytes are the constructor's bytes** — length and
//!    SHA-256 as recorded, byte-for-byte as built. A committed fixture is
//!    therefore reproducible by anyone with the crate, and readable by
//!    anyone without it.
//! 3. **The committed bytes still fail as mapped** — every fixture is read
//!    *from disk* and fed to its strict surface, which is what makes this a
//!    test of the committed artifact rather than of the constructor that
//!    produced it.
//! 4. **The bases really are the golden vectors** — both base files are
//!    diffed against the F12/F13 committed vector documents, so "derived
//!    from the golden vectors" fails loudly the day it stops being true.
//!
//! Test names deliberately avoid the reserved `corpus_`/`vector_` markers
//! (CONTRIBUTING.md, "Cross-OS suite naming"): this suite belongs to the
//! `tamper-matrix` lane, not to the cross-OS golden-vector one.
//!
//! # Regenerating
//!
//! ```text
//! cargo test -p antseal-core --features test-util --test format_tamper_fixtures \
//!     -- --ignored emit_format_tamper_fixtures
//! ```
//!
//! It rewrites every committed fixture **and** the mapping table. Nothing
//! under `testdata/tamper/` is covered by Q6's `FROZEN.sha256` (that guard is
//! `testdata/vectors/` only), so no freeze update is needed — but a byte
//! change to a committed tamper fixture is still a reviewed event: it means a
//! mutation, a base, or a code changed.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use antseal_core::codec::caps::MAX_BUNDLE_BYTES;
use antseal_core::test_util::tamper_rows_format::{
    FormatFixture, Surface, all_fixtures, base_bundle, base_manifest, run_surface,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

/// The committed fixture directory (workspace-relative via the crate
/// manifest dir, so it resolves on every OS and checkout location).
const FORMAT_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../testdata/tamper/format");

/// The F12 manifest golden vector, and the case both bases derive from.
const MANIFEST_VECTOR: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../testdata/vectors/v1/manifest/manifest.json"
);
/// The F13 bundle golden vector.
const BUNDLE_VECTOR: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../testdata/vectors/v1/bundle/bundle.json"
);

/// The golden case each base is byte-identical to.
const MANIFEST_CASE: &str = "minimal-binary-ed25519-only";
const BUNDLE_CASE: &str = "empty-anchor-unanchored";

/// The mapping table's schema discriminator and version.
const SCHEMA: &str = "antseal-format-tamper-fixtures";
const SCHEMA_VERSION: u64 = 1;

/// The two committed base files, as `(table id, relative path)`.
const BASES: [(&str, &str); 2] = [
    ("manifest", "base/manifest.cbor"),
    ("bundle", "base/bundle.cbor"),
];

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

fn dir() -> PathBuf {
    PathBuf::from(FORMAT_DIR)
}

fn table_path() -> PathBuf {
    dir().join("FIXTURES.json")
}

fn read(path: &Path) -> Vec<u8> {
    fs::read(path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()))
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn unhex(text: &str) -> Vec<u8> {
    assert!(text.len().is_multiple_of(2), "odd-length hex");
    (0..text.len() / 2)
        .map(|i| {
            u8::from_str_radix(&text[i * 2..i * 2 + 2], 16)
                .unwrap_or_else(|e| panic!("bad hex at {i}: {e}"))
        })
        .collect()
}

fn digest(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex(&hasher.finalize())
}

/// The mapping table, parsed.
fn table() -> Value {
    let path = table_path();
    let text =
        fs::read_to_string(&path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("{} does not parse: {e}", path.display()))
}

fn entries<'a>(root: &'a Value, key: &str) -> &'a Vec<Value> {
    root.get(key)
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("FIXTURES.json: `{key}` must be an array"))
}

fn field<'a>(entry: &'a Value, key: &str, ctx: &str) -> &'a str {
    entry
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("{ctx}: field `{key}` must be a string"))
}

/// One case's hex field from a committed golden-vector document.
fn golden_case_bytes(vector: &str, case_name: &str, field_name: &str) -> Vec<u8> {
    let text = fs::read_to_string(vector).unwrap_or_else(|e| panic!("cannot read {vector}: {e}"));
    let document: Value =
        serde_json::from_str(&text).unwrap_or_else(|e| panic!("{vector} does not parse: {e}"));
    let cases = document
        .get("expect")
        .and_then(|e| e.get("cases"))
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("{vector}: no expect.cases"));
    let case = cases
        .iter()
        .find(|c| c.get("name").and_then(Value::as_str) == Some(case_name))
        .unwrap_or_else(|| panic!("{vector}: no case `{case_name}`"));
    unhex(field(case, field_name, case_name))
}

/// Build a fixture or fail loudly — a construction failure is never a skip.
fn built(fixture: &FormatFixture) -> Vec<u8> {
    (fixture.build)().unwrap_or_else(|| panic!("fixture `{}` failed to build", fixture.id))
}

/// The recipe a **synthesized** fixture follows, by id.
///
/// A length-valued mutation is expressed as a recipe so the length it names
/// never enters the repository (tasks/F.md F22). Keyed by fixture id rather
/// than carried on [`FormatFixture`] deliberately: the recipe is prose about
/// the mutation, it is read only here, and the fixture struct is edited by
/// every task that adds a fixture — so a field would put a per-fixture diff
/// on a shared declaration for a string only the emitter uses.
///
/// A `committed: false` fixture with no recipe fails the emitter loudly.
fn recipe_for(id: &str) -> &'static str {
    match id {
        "bundle-oversized" => "the base bundle, zero-padded to MAX_BUNDLE_BYTES + 1 bytes",
        "manifest-oversized" => {
            "the base manifest envelope, zero-padded to MAX_MANIFEST_BYTES + 1 bytes"
        }
        "bundle-cert-over-cap" => {
            "the every-anchor-kind bundle (R6 `AnchorSet::EveryKind`, receipt excluded, over the \
             `single binary` ed25519-only work), with `tsa_anchors[0].intermediates[0]` replaced \
             by a bstr of MAX_CERT_BYTES + 1 zero bytes"
        }
        other => panic!(
            "fixture `{other}` is not committed and has no recipe — a synthesized fixture must \
             say how to rebuild it, or nobody can"
        ),
    }
}

/// The JSON entry for one fixture (the emitter's row, and the shape every
/// check below reads).
fn table_entry(fixture: &FormatFixture) -> Value {
    let bytes = built(fixture);
    let source = if fixture.committed {
        json!({
            "kind": "file",
            "file": format!("{}.cbor", fixture.id),
            "len": bytes.len(),
            "sha256": digest(&bytes),
        })
    } else {
        json!({
            "kind": "synthesized",
            "recipe": recipe_for(fixture.id),
            "len": bytes.len(),
        })
    };
    json!({
        "id": fixture.id,
        "base": fixture.base,
        "mutation": fixture.mutation,
        "surface": fixture.surface.name(),
        "source": source,
        "expected": {
            "code": fixture.code,
            "layer": fixture.layer,
        },
        "row": fixture.row,
    })
}

/// The whole mapping table, rebuilt from the library's fixture set.
fn build_table() -> Value {
    let mut bases = Vec::new();
    for (id, file) in BASES {
        let bytes = if id == "manifest" {
            base_manifest()
        } else {
            base_bundle()
        };
        let (vector, case, vector_field) = if id == "manifest" {
            (
                "vectors/v1/manifest/manifest.json",
                MANIFEST_CASE,
                "manifest_bytes",
            )
        } else {
            ("vectors/v1/bundle/bundle.json", BUNDLE_CASE, "bundle_bytes")
        };
        bases.push(json!({
            "id": id,
            "file": file,
            "len": bytes.len(),
            "sha256": digest(&bytes),
            "golden_vector": vector,
            "golden_case": case,
            "golden_field": vector_field,
        }));
    }
    json!({
        "schema": SCHEMA,
        "schema_version": SCHEMA_VERSION,
        "format_version": "v1",
        "task": "F15",
        "non_secret": "NON-SECRET — every byte derives from the documented fixed test seed (testdata/README.md)",
        "_readme": [
            "F15 — the format-level tamper fixtures: one single mutation each,",
            "applied to bytes derived from the F12/F13 golden vectors, mapped to",
            "the exact (code, layer) pair the strict surface must report.",
            "",
            "Consumer: crates/antseal-core/tests/format_tamper_fixtures.rs.",
            "Constructors: antseal_core::test_util::tamper_rows_format (WASM-safe).",
            "Codes: docs/testing/error-code-contract.md (D30).",
            "",
            "`row` names the Q7 tamper-matrix row this fixture is evidence for, or",
            "null when the fixture's code is ALREADY claimed by another row. That",
            "is not an omission: a wrapped codec rejection surfaces its inner code",
            "unchanged at every layer (error-code contract §2, F6/F9), so one",
            "canonicality fault in the body, the envelope, the bundle map and the",
            "embedded manifest is FOUR fixtures and ONE code. Q7 would correctly",
            "refuse four rows; the layer is what separates them, and `expected.layer`",
            "is checked alongside `expected.code` for exactly that reason.",
            "",
            "`expected.layer` is null IFF the surface is not a layered decoder —",
            "which is only `check_canonical`, the schema-agnostic strict pass.",
            "`Manifest::decode` and `SealProof::decode` always report one of the",
            "three layers of registry section 7.6.3, for canonicality and schema",
            "rejections alike (decision D86)."
        ],
        "bases": bases,
        "fixtures": all_fixtures().into_iter().map(table_entry).collect::<Vec<_>>(),
    })
}

// ---------------------------------------------------------------------------
// 1. the table describes the fixture set exactly
// ---------------------------------------------------------------------------

/// The committed table is exactly what the library's fixture set generates —
/// same ids in the same order, same mutation text, same expectations.
///
/// A whole-document comparison rather than a field walk: a missing, extra or
/// reordered field fails like a wrong value would, which is the discipline
/// the golden-vector regenerators already use.
#[test]
fn the_committed_mapping_table_regenerates() {
    let committed = table();
    let rebuilt = build_table();
    if committed != rebuilt {
        let committed_ids: Vec<&str> = entries(&committed, "fixtures")
            .iter()
            .filter_map(|f| f.get("id").and_then(Value::as_str))
            .collect();
        let rebuilt_ids: Vec<&str> = all_fixtures().iter().map(|f| f.id).collect();
        panic!(
            "testdata/tamper/format/FIXTURES.json is stale.\n  committed ids: \
             {committed_ids:?}\n  library ids:   {rebuilt_ids:?}\nRegenerate with:\n  cargo test \
             -p antseal-core --features test-util --test format_tamper_fixtures -- --ignored \
             emit_format_tamper_fixtures"
        );
    }
    assert_eq!(
        committed.get("schema").and_then(Value::as_str),
        Some(SCHEMA)
    );
    assert_eq!(
        committed.get("schema_version").and_then(Value::as_u64),
        Some(SCHEMA_VERSION)
    );
}

/// Nothing under `testdata/tamper/format/` is unaccounted for: every `.cbor`
/// on disk is named by the table, and every table `file` exists.
///
/// Without this a fixture could be deleted (or a stray one left behind) and
/// the mapping would still look complete — the same must-exist obligation
/// Q6's freeze manifest carries for vectors.
#[test]
fn the_committed_files_and_the_table_name_the_same_set() {
    let root = table();
    let mut expected: BTreeSet<PathBuf> = BTreeSet::new();
    for base in entries(&root, "bases") {
        expected.insert(dir().join(field(base, "file", "bases[]")));
    }
    for fixture in entries(&root, "fixtures") {
        let source = fixture
            .get("source")
            .unwrap_or_else(|| panic!("fixtures[]: no `source`"));
        if source.get("kind").and_then(Value::as_str) == Some("file") {
            expected.insert(dir().join(field(source, "file", "source")));
        }
    }
    let mut found: BTreeSet<PathBuf> = BTreeSet::new();
    let mut walk = vec![dir()];
    while let Some(path) = walk.pop() {
        let read_dir =
            fs::read_dir(&path).unwrap_or_else(|e| panic!("cannot list {}: {e}", path.display()));
        for entry in read_dir {
            let entry = entry.unwrap_or_else(|e| panic!("cannot read a directory entry: {e}"));
            let child = entry.path();
            if child.is_dir() {
                walk.push(child);
            } else if child.extension().is_some_and(|e| e == "cbor") {
                found.insert(child);
            }
        }
    }
    assert_eq!(
        found, expected,
        "the committed `.cbor` set and the mapping table disagree — a fixture was added, deleted \
         or renamed without the table"
    );
}

// ---------------------------------------------------------------------------
// 2 + 3. the committed bytes are the constructor's, and still fail as mapped
// ---------------------------------------------------------------------------

/// Every committed fixture is byte-identical to what its constructor
/// produces, with the recorded length and SHA-256.
#[test]
fn every_committed_fixture_matches_its_constructor() {
    let root = table();
    for (entry, fixture) in entries(&root, "fixtures").iter().zip(all_fixtures()) {
        let source = entry.get("source").expect("source");
        if source.get("kind").and_then(Value::as_str) != Some("file") {
            continue;
        }
        let path = dir().join(field(source, "file", fixture.id));
        let committed = read(&path);
        let constructed = built(fixture);
        assert_eq!(
            committed, constructed,
            "committed bytes of `{}` differ from the constructor's",
            fixture.id
        );
        assert_eq!(
            source.get("len").and_then(Value::as_u64),
            Some(committed.len() as u64),
            "`{}`: recorded length is wrong",
            fixture.id
        );
        assert_eq!(
            source.get("sha256").and_then(Value::as_str),
            Some(digest(&committed).as_str()),
            "`{}`: recorded digest is wrong",
            fixture.id
        );
    }
}

/// **F15's headline accept**: every fixture fails with exactly its mapped
/// error variant — read from disk, so this tests the committed artifact.
///
/// The layer is asserted alongside the code, which is what makes the
/// inner-body and outer-layer variants of one canonicality class
/// distinguishable even though (by the error-code contract's design) they
/// share a code.
#[test]
fn every_fixture_fails_with_its_mapped_error() {
    let root = table();
    for (entry, fixture) in entries(&root, "fixtures").iter().zip(all_fixtures()) {
        let source = entry.get("source").expect("source");
        let bytes = if source.get("kind").and_then(Value::as_str) == Some("file") {
            read(&dir().join(field(source, "file", fixture.id)))
        } else {
            built(fixture)
        };
        let observed = run_surface(fixture.surface, &bytes);
        let expected = entry.get("expected").expect("expected");
        assert_eq!(
            observed.code.as_deref(),
            expected.get("code").and_then(Value::as_str),
            "`{}` did not fail with its mapped code",
            fixture.id
        );
        assert_eq!(
            observed.layer.as_deref(),
            expected.get("layer").and_then(Value::as_str),
            "`{}` did not fail at its mapped layer",
            fixture.id
        );
        assert!(
            observed.code.is_some(),
            "`{}` was ACCEPTED — a tamper fixture must always be rejected",
            fixture.id
        );
    }
}

/// **D86 §4.5, as an invariant rather than a per-fixture coincidence.**
///
/// `expected.layer` is null **iff** the fixture's surface is not a layered
/// decoder, and exactly one surface qualifies: `check_canonical`, the
/// schema-agnostic strict pass. `every_fixture_fails_with_its_mapped_error`
/// only checks each declaration against that fixture's own observation, so
/// a whole class of fixtures could drift together without it noticing; this
/// pins the rule the two READMEs state.
///
/// It is also what keeps the rule cheap to state. The pre-D86 rule —
/// "null means a schema rejection inside the manifest" — was not
/// expressible as a property of the surface at all, which is why it needed
/// restating in three places.
#[test]
fn a_null_layer_means_the_surface_is_not_layered() {
    let root = table();
    for (entry, fixture) in entries(&root, "fixtures").iter().zip(all_fixtures()) {
        let layered = !matches!(fixture.surface, Surface::Canonical);
        assert_eq!(
            fixture.layer.is_some(),
            layered,
            "`{}`: a layer is declared iff the surface is a layered decoder",
            fixture.id
        );
        let declared = entry
            .get("expected")
            .and_then(|e| e.get("layer"))
            .expect("expected.layer");
        assert_eq!(
            !declared.is_null(),
            layered,
            "`{}`: the committed table disagrees with the surface rule",
            fixture.id
        );
    }
    // Both halves of the "iff" are witnessed, so the test cannot pass by
    // vacuity if a future edit leaves only one kind of surface behind.
    assert!(
        all_fixtures()
            .iter()
            .any(|f| matches!(f.surface, Surface::Canonical)),
        "no unlayered-surface fixture is left to witness the null case"
    );
    assert!(
        all_fixtures()
            .iter()
            .any(|f| !matches!(f.surface, Surface::Canonical)),
        "no layered-surface fixture is left to witness the non-null case"
    );
}

// ---------------------------------------------------------------------------
// 4. the bases really are the golden vectors
// ---------------------------------------------------------------------------

/// Both bases are byte-identical to the committed F12/F13 golden vectors,
/// so F15's "derived from the golden vectors" is a checked claim.
#[test]
fn the_bases_are_the_committed_golden_vectors() {
    let manifest = base_manifest();
    assert_eq!(
        manifest,
        golden_case_bytes(MANIFEST_VECTOR, MANIFEST_CASE, "manifest_bytes"),
        "the base manifest is no longer the `{MANIFEST_CASE}` golden vector"
    );
    let bundle = base_bundle();
    assert_eq!(
        bundle,
        golden_case_bytes(BUNDLE_VECTOR, BUNDLE_CASE, "bundle_bytes"),
        "the base bundle is no longer the `{BUNDLE_CASE}` golden vector"
    );

    let root = table();
    for base in entries(&root, "bases") {
        let id = field(base, "id", "bases[]");
        let expected = if id == "manifest" { &manifest } else { &bundle };
        let committed = read(&dir().join(field(base, "file", id)));
        assert_eq!(&committed, expected, "committed base `{id}` is stale");
        assert_eq!(
            base.get("sha256").and_then(Value::as_str),
            Some(digest(expected).as_str()),
            "base `{id}`: recorded digest is wrong"
        );
    }
}

// ---------------------------------------------------------------------------
// 5 + 6. the two accept clauses stated over the committed table
// ---------------------------------------------------------------------------

/// F15 accept, read off the committed table rather than the library: the
/// four spec-named body mutations are four separate fixtures with four
/// distinct errors, all at the body layer.
#[test]
fn the_four_named_body_mutations_are_four_table_rows_with_four_codes() {
    const NAMED: [&str; 4] = [
        "body-duplicate-map-key",
        "body-non-shortest-int",
        "body-indefinite-length",
        "body-trailing-bytes",
    ];
    let root = table();
    let fixtures = entries(&root, "fixtures");
    let mut codes = BTreeSet::new();
    for id in NAMED {
        let entry = fixtures
            .iter()
            .find(|f| f.get("id").and_then(Value::as_str) == Some(id))
            .unwrap_or_else(|| panic!("the table has no fixture `{id}`"));
        let expected = entry.get("expected").expect("expected");
        assert_eq!(
            expected.get("layer").and_then(Value::as_str),
            Some("manifest body"),
            "`{id}` must fail at the body layer"
        );
        assert!(
            codes.insert(field(expected, "code", id)),
            "`{id}` shares a code with another named body mutation"
        );
    }
    assert_eq!(codes.len(), 4);
}

/// F15 accept: `oversized != over-deep` — two fixtures, two errors.
#[test]
fn oversized_and_over_deep_are_two_table_rows_with_two_errors() {
    let root = table();
    let fixtures = entries(&root, "fixtures");
    let code_of = |id: &str| -> String {
        let entry = fixtures
            .iter()
            .find(|f| f.get("id").and_then(Value::as_str) == Some(id))
            .unwrap_or_else(|| panic!("no fixture `{id}`"));
        field(entry.get("expected").expect("expected"), "code", id).to_owned()
    };
    let over = code_of("bundle-oversized");
    let deep = code_of("body-nesting-too-deep");
    assert_eq!(over, "bundle-too-large");
    assert_eq!(deep, "cbor-nesting-too-deep");
    assert_ne!(over, deep);
}

/// The one length-valued mutation stays a *recipe*: 256 MiB never enters the
/// repository, and the table says so out loud (tasks/F.md F22).
#[test]
fn the_oversized_fixture_is_a_recipe_not_a_file() {
    let root = table();
    let entry = entries(&root, "fixtures")
        .iter()
        .find(|f| f.get("id").and_then(Value::as_str) == Some("bundle-oversized"))
        .expect("the oversized fixture");
    let source = entry.get("source").expect("source");
    assert_eq!(
        source.get("kind").and_then(Value::as_str),
        Some("synthesized")
    );
    assert!(source.get("file").is_none(), "a recipe has no file");
    assert_eq!(
        source.get("len").and_then(Value::as_u64),
        Some(MAX_BUNDLE_BYTES + 1),
        "the recipe's length must be MAX_BUNDLE_BYTES + 1"
    );
    // Nothing anywhere near that size is committed.
    let biggest = entries(&root, "fixtures")
        .iter()
        .filter_map(|f| f.get("source"))
        .filter(|s| s.get("kind").and_then(Value::as_str) == Some("file"))
        .filter_map(|s| s.get("len").and_then(Value::as_u64))
        .max()
        .unwrap_or(0);
    assert!(
        biggest < 64 * 1024,
        "a committed format fixture grew past 64 KiB ({biggest} B) — the fixture set is meant to \
         stay hand-readable"
    );
}

// ---------------------------------------------------------------------------
// the emitter (module docs)
// ---------------------------------------------------------------------------

/// Write every committed fixture and the mapping table. `--ignored`, and the
/// only sanctioned way to regenerate them.
#[test]
#[ignore = "emitter: writes testdata/tamper/format/ (see the module docs)"]
fn emit_format_tamper_fixtures() {
    let base_dir = dir().join("base");
    fs::create_dir_all(&base_dir).unwrap_or_else(|e| panic!("cannot create {base_dir:?}: {e}"));

    for (id, file) in BASES {
        let bytes = if id == "manifest" {
            base_manifest()
        } else {
            base_bundle()
        };
        let path = dir().join(file);
        fs::write(&path, &bytes).unwrap_or_else(|e| panic!("cannot write {path:?}: {e}"));
        println!("wrote {} ({} B)", path.display(), bytes.len());
    }

    for fixture in all_fixtures() {
        if !fixture.committed {
            println!("skipped {} (synthesized: a length, not bytes)", fixture.id);
            continue;
        }
        let bytes = built(fixture);
        let path = dir().join(format!("{}.cbor", fixture.id));
        fs::write(&path, &bytes).unwrap_or_else(|e| panic!("cannot write {path:?}: {e}"));
        println!("wrote {} ({} B)", path.display(), bytes.len());
    }

    let mut text = serde_json::to_string_pretty(&build_table()).expect("serialize the table");
    text.push('\n');
    let path = table_path();
    fs::write(&path, text).unwrap_or_else(|e| panic!("cannot write {path:?}: {e}"));
    println!("wrote {}", path.display());
}
