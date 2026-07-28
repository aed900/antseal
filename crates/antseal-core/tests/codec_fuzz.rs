//! **F17's in-suite half**, and the emitter for `testdata/fuzz-seeds/`.
//!
//! The fuzz *engine* is WASM-safe library code
//! ([`antseal_core::test_util::codec_fuzz`]); the committed corpora live
//! under `testdata/fuzz-seeds/<target>/`. This file is the seam, and like
//! F15's it is strict in both directions:
//!
//! 1. **The committed corpora are the generator's corpora** — same targets,
//!    same ids, same order, same bytes, same recorded length and SHA-256. A
//!    seed added to the library without a committed file (or the reverse)
//!    fails here, so the corpus cannot rot into decoration.
//! 2. **The committed bytes still do what the corpus claims** — every seed
//!    is read *from disk* and driven through its target's engine function,
//!    which makes this a test of the committed artifact rather than of the
//!    constructor that produced it.
//! 3. **The invariants hold on inputs no generator would build** — the R10
//!    mutation engine is pointed at the committed seeds, and every resulting
//!    byte string must still decode-or-reject and satisfy the round-trip
//!    law. This is the half that runs on **every CI build**, so the
//!    properties the fuzzer checks cannot silently stop being checked
//!    between fuzz runs.
//!
//! # Why this is not `cargo fuzz`
//!
//! It complements it. `cargo fuzz` needs a nightly toolchain, a sanitizer,
//! and a time budget; this suite needs none of those and runs in the
//! ordinary `test` lane. What it cannot do is *search* — libFuzzer's
//! coverage-guided mutation reaches shapes a fixed grid never will. The two
//! halves share one code path exactly so that a crash the fuzzer finds
//! reproduces as a plain unit test here.
//!
//! Test names deliberately avoid the reserved `corpus_`/`vector_` markers
//! (CONTRIBUTING.md, "Cross-OS suite naming"): this suite belongs to the
//! `fuzz-smoke` lane's family, not to the cross-OS golden-vector one.
//!
//! # Regenerating
//!
//! ```text
//! cargo test -p antseal-core --features test-util --test codec_fuzz \
//!     -- --ignored emit_fuzz_seed_corpora
//! ```
//!
//! It rewrites every committed seed **and** the manifest. Seeds are
//! *derived* artifacts, not frozen ones: nothing under `testdata/fuzz-seeds/`
//! is covered by Q6's `FROZEN.sha256` (that guard is `testdata/vectors/`
//! only), so a format change re-blesses them as a matter of course. A byte
//! change is still a reviewed event — it means a fixture, a shape, or the
//! wire format moved.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::slice;

use antseal_core::test_util::bundle_mutators::{Mutation, decode_mutation};
use antseal_core::test_util::codec_fuzz::{
    CodecOutcome, RoundTripped, Seed, all_corpora, drive_bundle, drive_manifest, round_trip,
};
use antseal_core::test_util::proptest::prelude::*;
use antseal_core::test_util::strategies;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

/// The committed seed root (workspace-relative via the crate manifest dir,
/// so it resolves on every OS and checkout location).
const SEED_ROOT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../testdata/fuzz-seeds");

/// The manifest's schema discriminator and version.
const SCHEMA: &str = "antseal-fuzz-seed-corpora";
const SCHEMA_VERSION: u64 = 1;

/// Committed proptest regressions for this suite (Q3 §5).
const REGRESSIONS: &str = "proptest-regressions/codec_fuzz.txt";

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

fn root() -> PathBuf {
    PathBuf::from(SEED_ROOT)
}

fn manifest_path() -> PathBuf {
    root().join("MANIFEST.json")
}

fn seed_path(target: &str, id: &str) -> PathBuf {
    root().join(target).join(format!("{id}.bin"))
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .fold(String::new(), |mut s, b| {
            use std::fmt::Write as _;
            let _ = write!(s, "{b:02x}");
            s
        })
}

/// R10's mutation corpus, built **once per process**.
///
/// `bundle_mutators::seed_bytes()` rebuilds seventeen R6 fixtures (ML-DSA
/// keygen + sign + AEAD each), so calling it per seed turns a 100-entry
/// corpus walk into ~1 700 signings. It is deterministic, so one build is
/// exactly as good as many — the same reasoning R10's own fuzz target
/// applies with its `OnceLock`.
fn r10_corpus() -> &'static [Vec<u8>] {
    static CORPUS: std::sync::OnceLock<Vec<Vec<u8>>> = std::sync::OnceLock::new();
    CORPUS.get_or_init(antseal_core::test_util::bundle_mutators::seed_bytes)
}

/// Which engine function a target's seeds are driven through.
///
/// The corpus and its driver are named together in exactly one place, so a
/// target cannot acquire seeds without acquiring the assertion that they are
/// the right seeds.
fn drive(target: &str, bytes: &[u8]) -> CodecOutcome {
    use antseal_core::test_util::bundle_mutators::{Outcome, fuzz_once};

    match target {
        "manifest_decode" => drive_manifest(bytes),
        "bundle_decode" => drive_bundle(bytes),
        // R10's target reads entropy, not documents: driving it means
        // running one full fuzz iteration.
        "verify_bundle" => match fuzz_once(bytes, r10_corpus()) {
            Outcome::Verified => CodecOutcome::Decoded,
            Outcome::Rejected(code) => CodecOutcome::Rejected(code),
        },
        other => panic!("unknown fuzz target `{other}` — add it to `drive`"),
    }
}

/// The manifest document the generator would emit right now.
fn generate_manifest() -> Value {
    let corpora: Vec<Value> = all_corpora()
        .iter()
        .map(|(target, seeds)| {
            let entries: Vec<Value> = seeds
                .iter()
                .map(|seed| {
                    json!({
                        "file": format!("{target}/{}.bin", seed.id),
                        "id": seed.id,
                        "len": seed.bytes.len(),
                        "sha256": sha256_hex(&seed.bytes),
                    })
                })
                .collect();
            json!({
                "bytes": seeds.iter().map(|s| s.bytes.len()).sum::<usize>(),
                "count": seeds.len(),
                "seeds": entries,
                "target": target,
            })
        })
        .collect();

    json!({
        "_readme": [
            "F17/Q9 — the committed cargo-fuzz seed corpora, one directory per",
            "target. Generated, never hand-edited: the generator is",
            "antseal_core::test_util::codec_fuzz::all_corpora and the emitter is",
            "crates/antseal-core/tests/codec_fuzz.rs (see its module docs for the",
            "regeneration command).",
            "",
            "`codec_round_trip` has no corpus of its own: its input space is the",
            "union of manifest_decode's and bundle_decode's, and scripts/fuzz.sh",
            "passes both directories to it rather than committing the same bytes",
            "twice.",
            "",
            "Seeds are DERIVED artifacts, not frozen ones. Q6's FROZEN.sha256",
            "covers testdata/vectors/ only, so a deliberate format change",
            "re-blesses these as a matter of course — a byte change here means a",
            "fixture, a shape or the wire format moved, and is reviewed as such.",
            "",
            "NON-SECRET fixtures only: every byte derives from the documented",
            "test seed W (testdata/README.md; project rule 6).",
        ],
        "corpora": corpora,
        "schema": SCHEMA,
        "schema_version": SCHEMA_VERSION,
    })
}

/// Canonical rendering: `serde_json` pretty-print, sorted keys (the crate's
/// `BTreeMap`-backed maps sort by construction), trailing newline — the same
/// shape `testdata/tamper/format/FIXTURES.json` uses, so a diff of either
/// reads the same way.
fn render(document: &Value) -> String {
    let mut text = serde_json::to_string_pretty(document).expect("render");
    text.push('\n');
    text
}

// ---------------------------------------------------------------------------
// 1. the committed corpora are the generated ones
// ---------------------------------------------------------------------------

#[test]
fn the_committed_manifest_regenerates() {
    let committed = fs::read_to_string(manifest_path())
        .unwrap_or_else(|e| panic!("cannot read {:?}: {e}", manifest_path()));
    let generated = render(&generate_manifest());
    assert_eq!(
        committed, generated,
        "testdata/fuzz-seeds/MANIFEST.json is stale — regenerate with \
         `cargo test -p antseal-core --features test-util --test codec_fuzz -- \
         --ignored emit_fuzz_seed_corpora`"
    );
}

#[test]
fn every_committed_seed_is_the_generated_one() {
    for (target, seeds) in all_corpora() {
        for seed in seeds {
            let path = seed_path(target, &seed.id);
            let committed = fs::read(&path).unwrap_or_else(|e| panic!("cannot read {path:?}: {e}"));
            assert_eq!(
                committed.len(),
                seed.bytes.len(),
                "{path:?}: committed {} B, generated {} B",
                committed.len(),
                seed.bytes.len()
            );
            assert_eq!(
                sha256_hex(&committed),
                sha256_hex(&seed.bytes),
                "{path:?} differs from the generator's bytes"
            );
        }
    }
}

/// No stray files in the seed tree. A corpus directory is exactly the
/// generator's output: a leftover from a deleted seed would be fed to the
/// fuzzer forever, silently claiming coverage nothing produces any more.
#[test]
fn the_seed_tree_holds_nothing_but_the_generated_corpora() {
    let expected_dirs: BTreeSet<String> = all_corpora()
        .iter()
        .map(|(target, _)| (*target).to_owned())
        .collect();

    let mut found_dirs = BTreeSet::new();
    for entry in fs::read_dir(root()).expect("read seed root") {
        let entry = entry.expect("dir entry");
        let name = entry.file_name().to_string_lossy().into_owned();
        if entry.file_type().expect("file type").is_dir() {
            found_dirs.insert(name);
        } else {
            assert!(
                name == "README.md" || name == "MANIFEST.json",
                "stray file in testdata/fuzz-seeds/: {name}"
            );
        }
    }
    assert_eq!(found_dirs, expected_dirs, "seed directories differ");

    for (target, seeds) in all_corpora() {
        let expected: BTreeSet<String> = seeds.iter().map(|s| format!("{}.bin", s.id)).collect();
        let found: BTreeSet<String> = fs::read_dir(root().join(target))
            .unwrap_or_else(|e| panic!("read {target}: {e}"))
            .map(|e| {
                e.expect("dir entry")
                    .file_name()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect();
        assert_eq!(found, expected, "stray or missing seeds in {target}/");
    }
}

// ---------------------------------------------------------------------------
// 2. the committed bytes still do what the corpus claims
// ---------------------------------------------------------------------------

/// Every committed seed, read from disk, drives its target without a panic
/// and satisfies the round-trip law.
#[test]
fn every_committed_seed_drives_its_target_from_disk() {
    let mut decoded = 0usize;
    let mut total = 0usize;
    for (target, seeds) in all_corpora() {
        for seed in seeds {
            let path = seed_path(target, &seed.id);
            let bytes = fs::read(&path).unwrap_or_else(|e| panic!("cannot read {path:?}: {e}"));
            // The assertion is that this returns at all.
            let outcome = drive(target, &bytes);
            total += 1;
            if outcome == CodecOutcome::Decoded {
                decoded += 1;
            }
            let law = round_trip(&bytes);
            assert!(law.is_ok(), "{path:?}: {law:?}");
        }
    }
    assert!(total > 0, "no committed seeds at all");
    assert!(
        decoded > 0,
        "not one committed seed decodes — the corpora would be pure rejection fodder"
    );
}

/// The two decode corpora reach both round-trip arms. A corpus that only
/// ever produced `Neither` would satisfy the law vacuously.
#[test]
fn the_corpora_reach_both_round_trip_arms() {
    let arms: BTreeSet<String> = all_corpora()
        .iter()
        .flat_map(|(_, seeds)| seeds.iter())
        .filter_map(|seed: &Seed| round_trip(&seed.bytes).ok())
        .filter(|arm| *arm != RoundTripped::Neither)
        .map(|arm| format!("{arm:?}"))
        .collect();
    assert_eq!(
        arms,
        ["Bundle".to_owned(), "Manifest".to_owned()]
            .into_iter()
            .collect::<BTreeSet<_>>()
    );
}

// ---------------------------------------------------------------------------
// 3. the invariants under mutation — the R10 engine, pointed at F17
// ---------------------------------------------------------------------------

/// The always-on deterministic sweep: R10's mutation set applied to every
/// committed decode seed, driven through both decoders and the round-trip
/// law.
///
/// Cheap enough to run unconditionally, so the invariant holds even where
/// proptest is skipped — the same reasoning as R10's
/// `no_entropy_makes_verify_bundle_panic`.
#[test]
fn r10_mutations_of_committed_seeds_never_break_an_invariant() {
    let mut still_decodes = 0usize;
    let mut total = 0usize;

    for (target, seeds) in all_corpora() {
        if *target == "verify_bundle" {
            continue; // entropy, not documents — R10's own suite owns it.
        }
        for seed in seeds {
            for kind in 0u8..7 {
                for pattern in [0x00u8, 0x01, 0x7F, 0xFF] {
                    let mutation = decode_mutation(kind, &[pattern; 16]);
                    // The seed is its own donor pool: `SpliceFromDonor`
                    // then splices a document over itself, which is the
                    // cheap in-suite stand-in for the cross-document
                    // splicing libFuzzer does with a real corpus.
                    let mutated = mutation.apply(&seed.bytes, slice::from_ref(&seed.bytes));
                    // No panic: reaching the next line is the assertion.
                    let manifest = drive_manifest(&mutated);
                    let bundle = drive_bundle(&mutated);
                    let law = round_trip(&mutated);
                    assert!(
                        law.is_ok(),
                        "{target}/{} under {mutation:?}: {law:?}",
                        seed.id
                    );
                    total += 1;
                    if manifest == CodecOutcome::Decoded || bundle == CodecOutcome::Decoded {
                        still_decodes += 1;
                    }
                }
            }
        }
    }

    assert!(total > 0);
    // Without this the property could be satisfied by a mutation set that
    // destroys every document at byte 0 — the round-trip law would then be
    // vacuously true for the whole sweep.
    assert!(
        still_decodes > 0,
        "not one of {total} mutated documents still decoded; the round-trip law is vacuous here"
    );
}

proptest! {
    #![proptest_config(strategies::integration_test_config(0x5EED_F170, REGRESSIONS))]

    /// **Arbitrary bytes.** Neither decoder panics, and whatever decodes
    /// obeys the round-trip law.
    #[test]
    fn arbitrary_bytes_never_panic_and_always_round_trip(
        bytes in prop::collection::vec(any::<u8>(), 0..2048)
    ) {
        let _ = drive_manifest(&bytes);
        let _ = drive_bundle(&bytes);
        let law = round_trip(&bytes);
        prop_assert!(law.is_ok(), "{law:?}");
    }

    /// **Mutations of real documents**, which is where inputs that still
    /// decode actually come from: a flipped bit inside a signature or a
    /// ciphertext leaves a canonical, schema-valid document.
    #[test]
    fn mutated_documents_never_panic_and_always_round_trip(
        (target, index) in (0usize..2, 0usize..64),
        kind in 0u8..7,
        params in prop::array::uniform16(any::<u8>()),
    ) {
        let corpora = all_corpora();
        let seeds = &corpora[target].1;
        let seed = &seeds[index % seeds.len()];
        let mutation: Mutation = decode_mutation(kind, &params);
        let mutated = mutation.apply(&seed.bytes, slice::from_ref(&seed.bytes));

        let _ = drive_manifest(&mutated);
        let _ = drive_bundle(&mutated);
        let law = round_trip(&mutated);
        prop_assert!(
            law.is_ok(),
            "{}/{} under {mutation:?}: {law:?}",
            corpora[target].0,
            seed.id
        );
    }
}

// ---------------------------------------------------------------------------
// 4. the diagnosis is usable
// ---------------------------------------------------------------------------

/// A violated law must *say which one*. The round-trip law is unfalsifiable
/// from valid inputs by construction — that is the point of it — so the
/// executable "can this harness fail?" proof lives on the fuzz side, where a
/// panic really is injectable (`scripts/fuzz.sh selftest`, whose tripwire is
/// permanent and CI-exercised rather than a temporary edit). What *is*
/// checkable here is that every violation renders a distinct, non-empty
/// diagnosis, so a crash message identifies the broken law without a
/// backtrace.
#[test]
fn every_round_trip_violation_renders_a_distinct_diagnosis() {
    use antseal_core::codec::EncodeError;
    use antseal_core::test_util::codec_fuzz::RoundTripViolation as V;

    let violations = [
        V::CanonicalDisagreement {
            decoder: "Manifest::decode",
            code: "cbor-non-shortest-int",
        },
        V::EncodeFailed {
            what: "manifest body",
            source: EncodeError::DuplicateMapKey { key: 3 },
        },
        V::ByteIdentityBroken {
            what: "bundle",
            at: 17,
            input_len: 900,
            output_len: 901,
        },
        V::ReDecodeFailed {
            what: "bundle",
            code: "cbor-trailing-bytes",
        },
        V::ReDecodeDiffers {
            what: "manifest envelope",
        },
        V::EnvelopeNotWholeInput {
            covered: 370,
            total: 371,
        },
        V::EmbeddedManifestIsACopy,
        V::DigestChanged { what: "work_id" },
    ];

    let rendered: BTreeSet<String> = violations.iter().map(ToString::to_string).collect();
    assert_eq!(
        rendered.len(),
        violations.len(),
        "two violations render identically: {rendered:#?}"
    );
    for text in &rendered {
        assert!(!text.is_empty());
        assert!(
            !text.contains("  "),
            "double space in a diagnosis: {text:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// the emitter (ignored by default; the only sanctioned way to regenerate)
// ---------------------------------------------------------------------------

/// Rewrites every committed seed and the manifest.
///
/// `#[ignore]` so an ordinary `cargo test` never mutates the checkout — the
/// same shape F15's `emit_format_tamper_fixtures` uses.
#[test]
#[ignore = "emitter: rewrites testdata/fuzz-seeds/ (see the module docs)"]
fn emit_fuzz_seed_corpora() {
    for (target, seeds) in all_corpora() {
        let dir = root().join(target);
        // Remove stale seeds first: a corpus is exactly the generator's
        // output, and a leftover file would be fuzzed forever.
        if dir.exists() {
            for entry in fs::read_dir(&dir).expect("read corpus dir") {
                let path = entry.expect("dir entry").path();
                if path.is_file() {
                    fs::remove_file(&path).unwrap_or_else(|e| panic!("rm {path:?}: {e}"));
                }
            }
        } else {
            fs::create_dir_all(&dir).unwrap_or_else(|e| panic!("mkdir {dir:?}: {e}"));
        }
        for seed in seeds {
            let path = seed_path(target, &seed.id);
            fs::write(&path, &seed.bytes).unwrap_or_else(|e| panic!("write {path:?}: {e}"));
        }
        eprintln!(
            "wrote {} seeds ({} B) to {}",
            seeds.len(),
            seeds.iter().map(|s| s.bytes.len()).sum::<usize>(),
            dir.display()
        );
    }

    let path = manifest_path();
    fs::write(&path, render(&generate_manifest()))
        .unwrap_or_else(|e| panic!("write {path:?}: {e}"));
    eprintln!("wrote {}", path.display());
}

/// The seed root really is where this file thinks it is — a wrong constant
/// would make every check above pass against nothing.
#[test]
fn the_seed_root_resolves() {
    let root = root();
    assert!(
        Path::new(&root).join("README.md").is_file(),
        "{root:?} does not look like testdata/fuzz-seeds/"
    );
}
