//! G3 — the UTF-8 canonicalization corpus suite.
//!
//! Executes every committed fixture pair under `testdata/utf8-corpus/` —
//! `input/<name>` (exact input bytes) against `expected/<name>` (exact
//! canonical bytes) — through `antseal_core::canon`, the frozen D20 + D21
//! pipeline (MVP-SPEC.md lines 83, 121, 170).
//!
//! The goldens were produced by an **independent** reference implementation
//! (`testdata/utf8-corpus/gen_corpus.py`, Python stdlib `unicodedata`, a
//! different NFC table lineage), so a passing run is a cross-implementation
//! agreement result, not a self-consistency check. In particular every
//! invalid-UTF-8 fixture is an executed cross-check that CPython's and
//! Rust's UTF-8 decoders agree on Unicode §3.9 maximal subparts — the rule
//! D20 froze.
//!
//! Discovery walks the corpus directories — **no hardcoded file lists** —
//! so adding a fixture pair requires no change here. A `REQUIRED_PINS`
//! guard additionally fails the run if a load-bearing corner fixture is
//! deleted (`corpus_coverage_guard`).
//!
//! Test names carry the reserved `corpus_` marker so the three-OS CI lane
//! (`cross-os-*`) runs this suite on linux, macOS, and Windows, proving the
//! cross-platform byte stability G3 requires (CONTRIBUTING.md, "Cross-OS
//! suite naming"; `.gitattributes` keeps the fixture bytes checkout-stable).

use std::fs;
use std::path::{Path, PathBuf};

use antseal_core::canon::{CanonicalizeError, TextMode, UNICODE_17_0_0, canonicalize_v, is_text};

/// The committed corpus (workspace-relative via the crate manifest dir, so
/// it holds on every OS and checkout location).
const CORPUS_ROOT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../testdata/utf8-corpus");

/// Corner fixtures whose deletion must fail the suite rather than silently
/// shrink coverage: each pins a specific frozen decision.
const REQUIRED_PINS: &[&str] = &[
    "empty",
    // D21 stage 2 — strip the whole contiguous leading BOM run, never
    // exactly one, and never an interior U+FEFF.
    "bom-double",
    "bom-only",
    "bom-interior",
    "bom-interior-blocks-composition",
    // D21 stage 3 — one-pass EOL folding.
    "cr-cr-lf",
    "lone-cr",
    // D20 — lossy maximal subparts, and the truncated-BOM corner G2 flagged.
    "invalid-truncated-bom",
    "invalid-maximal-subparts",
    // Convergence pairs (the NFC leg of the pipeline).
    "pair-latin-nfd",
    "pair-hangul-nfd",
    "pair-vietnamese-nfd",
    "pair-hebrew-reorder-nfd",
];

/// A corpus fixture: an input and the canonical bytes it must produce.
struct Fixture {
    name: String,
    input: Vec<u8>,
    expected: Vec<u8>,
}

impl Fixture {
    /// Canonicalize this fixture's input in the mode its bytes call for.
    ///
    /// Valid UTF-8 is canonicalized in **both** modes and the two results
    /// must agree — D20's load-bearing "lossy ≡ strict on valid UTF-8"
    /// property, the reason `kind = Text` alone determines verifier
    /// recompute semantics and no descriptor mode flag exists.
    /// Invalid UTF-8 must be refused by `Detected` with the distinct
    /// `InvalidUtf8` error (never a panic) and canonicalized by `Forced`.
    fn canonicalize(&self) -> Vec<u8> {
        let forced = canonicalize_v(UNICODE_17_0_0, TextMode::Forced, &self.input)
            .expect("forced-text canonicalization is total and cannot fail");

        if is_text(&self.input) {
            let detected = canonicalize_v(UNICODE_17_0_0, TextMode::Detected, &self.input)
                .expect("detected mode accepts valid UTF-8");
            assert_eq!(
                detected.as_bytes(),
                forced.as_bytes(),
                "{}: detected and forced modes disagree on valid UTF-8 (D20 equivalence)",
                self.name
            );
        } else {
            match canonicalize_v(UNICODE_17_0_0, TextMode::Detected, &self.input) {
                Err(CanonicalizeError::InvalidUtf8 { .. }) => {}
                other => panic!(
                    "{}: invalid UTF-8 must be refused by detected mode with InvalidUtf8, got {other:?}",
                    self.name
                ),
            }
        }

        forced.into_bytes()
    }
}

/// Load every fixture pair, failing loudly on any pairing defect.
fn load_corpus() -> Vec<Fixture> {
    let root = Path::new(CORPUS_ROOT);
    let inputs = fixture_names(&root.join("input"));
    let expected = fixture_names(&root.join("expected"));

    let missing_golden: Vec<_> = inputs.iter().filter(|n| !expected.contains(n)).collect();
    assert!(
        missing_golden.is_empty(),
        "corpus inputs without a golden output: {missing_golden:?} \
         (every input/<name> needs expected/<name>; regenerate with gen_corpus.py)"
    );
    let stray_golden: Vec<_> = expected.iter().filter(|n| !inputs.contains(n)).collect();
    assert!(
        stray_golden.is_empty(),
        "golden outputs without an input: {stray_golden:?} (stray goldens are never ignored)"
    );

    inputs
        .into_iter()
        .map(|name| Fixture {
            input: read_fixture(&root.join("input").join(&name)),
            expected: read_fixture(&root.join("expected").join(&name)),
            name,
        })
        .collect()
}

/// Sorted fixture file names in one corpus directory (deterministic order on
/// every platform; the directory holds fixture files only).
fn fixture_names(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(dir)
        .unwrap_or_else(|err| panic!("{}: cannot read corpus directory: {err}", dir.display()))
        .map(|entry| {
            let path = entry
                .unwrap_or_else(|err| panic!("{}: cannot read entry: {err}", dir.display()))
                .path();
            assert!(
                path.is_file(),
                "{}: corpus directories contain fixture files only",
                path.display()
            );
            path.file_name()
                .and_then(|n| n.to_str())
                .unwrap_or_else(|| panic!("{}: non-UTF-8 fixture name", path.display()))
                .to_owned()
        })
        .collect();
    names.sort();
    names
}

fn read_fixture(path: &PathBuf) -> Vec<u8> {
    fs::read(path).unwrap_or_else(|err| panic!("{}: cannot read fixture: {err}", path.display()))
}

/// Every fixture's canonicalization must equal its committed golden bytes.
#[test]
fn corpus_golden_outputs_match() {
    let corpus = load_corpus();
    for fixture in &corpus {
        let actual = fixture.canonicalize();
        assert_eq!(
            actual,
            fixture.expected,
            "{}: canonical output does not match the committed golden\n  input:    {}\n  expected: {}\n  actual:   {}",
            fixture.name,
            hex(&fixture.input),
            hex(&fixture.expected),
            hex(&actual)
        );
    }
    assert!(
        !corpus.is_empty(),
        "the corpus is empty — discovery is broken"
    );
}

/// Canonicalization is idempotent: every golden is a fixed point (spec line
/// 170), checked from both directions.
#[test]
fn corpus_idempotence() {
    for fixture in load_corpus() {
        let once = fixture.canonicalize();
        let twice = canonicalize_v(UNICODE_17_0_0, TextMode::Forced, &once)
            .expect("forced-text canonicalization is total")
            .into_bytes();
        assert_eq!(
            twice, once,
            "{}: canonicalize(canonicalize(x)) != canonicalize(x)",
            fixture.name
        );

        let golden_again = canonicalize_v(UNICODE_17_0_0, TextMode::Forced, &fixture.expected)
            .expect("forced-text canonicalization is total")
            .into_bytes();
        assert_eq!(
            golden_again, fixture.expected,
            "{}: the committed golden is not a fixed point",
            fixture.name
        );
    }
}

/// `pair-<base>-nfd` and `pair-<base>-nfc` must differ as inputs and
/// converge to identical canonical bytes.
#[test]
fn corpus_nfd_nfc_pairs_converge() {
    let corpus = load_corpus();
    let bases: Vec<String> = corpus
        .iter()
        .filter_map(|f| f.name.strip_prefix("pair-")?.strip_suffix("-nfd"))
        .map(str::to_owned)
        .collect();
    assert!(!bases.is_empty(), "no NFD/NFC convergence pairs found");

    for base in bases {
        let find = |suffix: &str| {
            let name = format!("pair-{base}-{suffix}");
            corpus
                .iter()
                .find(|f| f.name == name)
                .unwrap_or_else(|| panic!("convergence pair {base} is missing its {suffix} half"))
        };
        let (nfd, nfc) = (find("nfd"), find("nfc"));

        assert_ne!(
            nfd.input, nfc.input,
            "pair {base}: the two halves have identical input bytes, so convergence is vacuous"
        );
        assert_eq!(
            nfd.canonicalize(),
            nfc.canonicalize(),
            "pair {base}: NFD and NFC halves do not converge to identical canonical bytes"
        );
    }

    // The reverse pairing (an -nfc half with no -nfd half) is a coverage
    // defect too.
    for fixture in &corpus {
        if let Some(base) = fixture
            .name
            .strip_prefix("pair-")
            .and_then(|n| n.strip_suffix("-nfc"))
        {
            let nfd = format!("pair-{base}-nfd");
            assert!(
                corpus.iter().any(|f| f.name == nfd),
                "convergence pair {base} is missing its nfd half"
            );
        }
    }
}

/// Coverage guard: pairing is complete, load-bearing corners still exist,
/// and the corpus has not silently shrunk.
#[test]
fn corpus_coverage_guard() {
    let corpus = load_corpus();
    let names: Vec<&str> = corpus.iter().map(|f| f.name.as_str()).collect();

    for pin in REQUIRED_PINS {
        assert!(
            names.contains(pin),
            "required corner fixture `{pin}` is missing — it pins a frozen decision (D20/D21); \
             deleting it must be a deliberate, justified format event"
        );
    }
    assert!(
        corpus.len() >= REQUIRED_PINS.len(),
        "corpus shrank below its required-pin count"
    );
}

/// Every golden satisfies the canonical-form invariant: valid UTF-8, no CR
/// anywhere, never starting with a BOM (D21).
#[test]
fn corpus_canonical_form_invariant() {
    for fixture in load_corpus() {
        let golden = &fixture.expected;
        let text = std::str::from_utf8(golden)
            .unwrap_or_else(|err| panic!("{}: golden is not valid UTF-8: {err}", fixture.name));
        assert!(
            !golden.contains(&b'\r'),
            "{}: golden contains CR — canonical form is LF-only",
            fixture.name
        );
        assert!(
            !text.starts_with('\u{FEFF}'),
            "{}: golden begins with U+FEFF — canonical form never starts with a BOM",
            fixture.name
        );
    }
}

/// Forced-text canonicalization is **total**: no input — including every
/// truncation of every fixture, which manufactures split multi-byte
/// sequences — may panic or error.
#[test]
fn corpus_forced_mode_is_total_on_truncations() {
    for fixture in load_corpus() {
        for end in 0..=fixture.input.len() {
            let prefix = &fixture.input[..end];
            let out =
                canonicalize_v(UNICODE_17_0_0, TextMode::Forced, prefix).unwrap_or_else(|err| {
                    panic!(
                        "{}: forced-text canonicalization failed on the {end}-byte prefix: {err}",
                        fixture.name
                    )
                });
            assert!(
                std::str::from_utf8(out.as_bytes()).is_ok(),
                "{}: forced-text output on the {end}-byte prefix is not valid UTF-8",
                fixture.name
            );
        }
    }
}

/// Lowercase hex for assertion messages (fixtures are public, non-secret
/// text — printing them is safe and makes failures diagnosable).
fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut acc, b| {
        let _ = write!(acc, "{b:02x}");
        acc
    })
}
