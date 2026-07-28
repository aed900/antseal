//! **The shared CBOR-parser fuzz engine** (task F17): the drivers, the
//! round-trip predicate, and the seed corpora behind the `manifest_decode`,
//! `bundle_decode` and `codec_round_trip` cargo-fuzz targets.
//!
//! MVP-SPEC.md line 153 makes parser hardening and CBOR fuzzing an M0 exit
//! criterion; line 169 names CBOR fuzzing under Verification; line 187 names
//! hostile bundles as a risk. Three invariants carry that here, and each is
//! stated as an executable predicate rather than as prose:
//!
//! > 1. **No panic.** For every byte string, [`Manifest::decode`] and
//! >    [`SealProof::decode`] return a typed error or a value.
//! > 2. **No allocation beyond the F11 budget.** Peak allocation stays
//! >    within the *attacker's own input length* (times one element) plus a
//! >    fixed constant — the observable form of decision D10 §4's clamp
//! >    rule. Measured by the fuzz targets' counting allocator
//! >    (`fuzz/src/lib.rs`), which generalizes
//! >    `tests/parser_caps_alloc.rs`'s two hand-picked inputs to arbitrary
//! >    bytes — and, in generalizing it, corrected it: the clamp counts
//! >    *elements*, so the bound carries a `size_of::<Element>()` factor
//! >    that the two-input version hides inside its slack (task F30).
//! > 3. **Decode success implies canonical-byte identity.** Whatever
//! >    strict-decodes, re-encodes to the *same bytes* and re-decodes to the
//! >    *same value* — [`round_trip`].
//!
//! # Why the engine lives here and not in the fuzz crate
//!
//! Identically to R10's [`super::bundle_mutators`], and for the same reason:
//! a fuzz target that carries its own logic is exercised only when someone
//! runs the fuzzer, so it rots between runs and a crash it finds may not
//! reproduce under the test suite. Everything testable is on this side of
//! the boundary, so `crates/antseal-core/tests/codec_fuzz.rs` runs the exact
//! code the fuzzer runs, on every CI build.
//!
//! No fuzzing dependency enters this crate: nothing here needs `arbitrary`,
//! and the `core-dep-graph` lane's verdict is untouched.
//!
//! # The input **is** the document (unlike R10)
//!
//! R10's `verify_bundle` target reads its input as *entropy* — a seed
//! selector, a mutation selector, and parameters — because its job is to get
//! **past** the decoder and stress the evidence stages, which random bytes
//! essentially never do.
//!
//! F17's job is the opposite, so the encoding is the opposite: a fuzz input
//! **is** the candidate CBOR document, byte for byte. Three consequences,
//! all of them wanted:
//!
//! - libFuzzer's mutators operate directly on the wire format, so its
//!   coverage feedback is about *the format* rather than about an
//!   indirection layer;
//! - a committed corpus entry is a real `.cbor` artifact, readable by any
//!   CBOR tool and diffable against `testdata/tamper/format/`;
//! - the target needs **no per-process setup at all** — no fixture build, no
//!   `OnceLock`, no signing or encryption on the hot path. Every iteration is
//!   a decode and nothing else.
//!
//! # What this does **not** duplicate
//!
//! - [`super::bundle_mutators`] (R10) drives `verify_bundle`, i.e. the
//!   evidence pipeline behind the codec. Same formats, different machine.
//! - `crates/antseal-core/tests/codec_properties.rs` (F16) states the same
//!   round-trip laws over **generated schema-valid values**. This module
//!   states them over **arbitrary bytes conditioned on decode success**,
//!   which is the strictly harder direction: F16 cannot reach a document a
//!   generator would never build, and that is exactly where an adversary
//!   lives.
//!
//! [`Manifest::decode`]: crate::manifest::Manifest::decode
//! [`SealProof::decode`]: crate::bundle::SealProof::decode

use thiserror::Error;

use crate::bundle::{SealProof, encode_bundle};
use crate::codec::EncodeError;
use crate::codec::decode::check_canonical;
use crate::manifest::{Manifest, anchor_digest, encode_body, encode_envelope, work_id};

use super::bundle_fixtures::{Selection, build, shapes};
use super::tamper_rows_format::{FIXTURES, base_bundle, base_manifest};

// ---------------------------------------------------------------------------
// drivers
// ---------------------------------------------------------------------------

/// What a strict decoder did with one input.
///
/// The absence of a "panicked" variant is not an omission — it *is* the
/// invariant. A harness that observes a panic reports it as a failure, never
/// as an outcome, which is why nothing here uses `catch_unwind`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodecOutcome {
    /// The input strict-decoded.
    Decoded,
    /// A typed rejection, reported by its stable code
    /// (`docs/testing/error-code-contract.md`).
    Rejected(&'static str),
}

impl CodecOutcome {
    /// The stable code, or `None` when the input decoded.
    #[must_use]
    pub const fn code(self) -> Option<&'static str> {
        match self {
            Self::Decoded => None,
            Self::Rejected(code) => Some(code),
        }
    }
}

/// Drive one input through the **manifest** decoder — layers 2 and 3 of
/// registry §7.6.3 in one call (`Manifest::decode` decodes the body itself).
///
/// The assertion is the return: a panic inside the decoder aborts the
/// process and the fuzzer records the crash.
#[must_use]
pub fn drive_manifest(bytes: &[u8]) -> CodecOutcome {
    match Manifest::decode(bytes) {
        Ok(_) => CodecOutcome::Decoded,
        Err(err) => CodecOutcome::Rejected(err.code()),
    }
}

/// Drive one input through the **`.sealproof`** decoder — all three strict
/// layers (`SealProof::decode`).
#[must_use]
pub fn drive_bundle(bytes: &[u8]) -> CodecOutcome {
    match SealProof::decode(bytes) {
        Ok(_) => CodecOutcome::Decoded,
        Err(err) => CodecOutcome::Rejected(err.code()),
    }
}

// ---------------------------------------------------------------------------
// the round-trip predicate
// ---------------------------------------------------------------------------

/// Which decoder accepted an input, for the round-trip report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoundTripped {
    /// Neither decoder accepted it — the overwhelmingly common case, and
    /// vacuously fine.
    Neither,
    /// Decoded as a manifest envelope and survived every manifest law.
    Manifest,
    /// Decoded as a `.sealproof` and survived every bundle law.
    Bundle,
}

/// A **violated** round-trip law.
///
/// Every variant is a real finding: it means an input strict-decoded and
/// then failed to reproduce itself, which would make "the bytes I received"
/// and "the bytes I would produce" confusable — precisely what
/// MVP-SPEC.md line 74's never-re-encode rule exists to prevent, and what
/// `work_id = SHA-256(manifest body)` depends on.
///
/// It is a **value**, not a panic, so the in-suite half can assert on it and
/// a fuzzer crash carries the diagnosis in its message rather than in a
/// backtrace.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum RoundTripViolation {
    /// A typed decoder accepted bytes the schema-agnostic canonical pass
    /// rejects. The two must never disagree: the typed pass is the strict
    /// profile *plus* a schema, so it can only ever accept less.
    #[error("{decoder} accepted input that check_canonical rejects with `{code}`")]
    CanonicalDisagreement {
        /// Which typed decoder accepted it.
        decoder: &'static str,
        /// The code the generic pass reported.
        code: &'static str,
    },

    /// Re-encoding a decoded value failed. [`EncodeError`] reports *caller
    /// bugs* the F2 layer detects, none of which is reachable from a value
    /// that just decoded — so reaching this arm means the decoder built a
    /// value the encoder cannot express, which is a format bug either way.
    ///
    /// [`EncodeError`]: crate::codec::EncodeError
    #[error("re-encoding a decoded {what} failed: {source}")]
    EncodeFailed {
        /// What was being re-encoded (`manifest body`, `manifest envelope`,
        /// `bundle`).
        what: &'static str,
        /// The encoder's own error. It carries no stable code by design:
        /// the code contract covers *rejection* classes, and an encoder
        /// failure is not one (`docs/testing/error-code-contract.md`).
        #[source]
        source: EncodeError,
    },

    /// A decoded value re-encoded to **different bytes**.
    #[error(
        "re-encoded {what} differs from the input at byte {at} ({input_len} B in, {output_len} B out)"
    )]
    ByteIdentityBroken {
        /// Which artifact.
        what: &'static str,
        /// First differing offset, or the shorter length when one is a
        /// prefix of the other.
        at: usize,
        /// Length of the received bytes.
        input_len: usize,
        /// Length of the re-encoded bytes.
        output_len: usize,
    },

    /// The re-encoded bytes did not decode again.
    #[error("re-encoded {what} no longer decodes: {code}")]
    ReDecodeFailed {
        /// Which artifact.
        what: &'static str,
        /// The rejection code.
        code: &'static str,
    },

    /// The re-decoded value differs from the first one.
    #[error("re-decoded {what} is not equal to the first decode")]
    ReDecodeDiffers {
        /// Which artifact.
        what: &'static str,
    },

    /// `Manifest::encoded_bytes()` is not the whole input. The outer pass
    /// rejects trailing bytes, so a shorter answer would mean the decoder
    /// silently ignored a suffix — and `anchor_digest` would then be taken
    /// over a different pre-image than the one that arrived.
    #[error("the decoded envelope covers {covered} of {total} input bytes")]
    EnvelopeNotWholeInput {
        /// Bytes the decoded envelope claims.
        covered: usize,
        /// Bytes supplied.
        total: usize,
    },

    /// The embedded manifest is not a sub-slice of the bundle's own buffer.
    /// Asserted by address range, not by value: equal contents would not
    /// prove it, and the zero-copy seam is what makes `anchor_digest` a
    /// digest of *received* bytes (registry §7.6.3).
    #[error("the embedded manifest is a copy, not a sub-slice of the bundle input")]
    EmbeddedManifestIsACopy,

    /// The digests derived from the received bytes changed across a
    /// round-trip. Implied by byte identity, and asserted anyway because it
    /// is the property anybody actually depends on.
    #[error("{what} changed across the round-trip")]
    DigestChanged {
        /// `work_id` or `anchor_digest`.
        what: &'static str,
    },
}

/// First differing offset of two byte strings, or the shorter length when
/// one is a prefix of the other.
fn first_difference(a: &[u8], b: &[u8]) -> usize {
    a.iter()
        .zip(b.iter())
        .position(|(x, y)| x != y)
        .unwrap_or_else(|| a.len().min(b.len()))
}

/// Compare two byte strings, reporting the first divergence.
fn same_bytes(what: &'static str, input: &[u8], output: &[u8]) -> Result<(), RoundTripViolation> {
    if input == output {
        return Ok(());
    }
    Err(RoundTripViolation::ByteIdentityBroken {
        what,
        at: first_difference(input, output),
        input_len: input.len(),
        output_len: output.len(),
    })
}

/// **The round-trip law**, over arbitrary bytes.
///
/// For any input:
///
/// - if it does not decode, there is nothing to prove ([`RoundTripped::Neither`]);
/// - if it decodes as a manifest envelope: the decoded envelope covers the
///   whole input; re-encoding the body reproduces the embedded body bytes;
///   re-wrapping reproduces the whole envelope; the result decodes again to
///   an equal `Manifest`; and `work_id`/`anchor_digest` are unchanged;
/// - if it decodes as a `.sealproof`: re-encoding reproduces the input
///   bytes; the embedded manifest is a sub-slice of the input rather than a
///   copy; and the re-encoding decodes again with an unchanged
///   `anchor_digest`.
///
/// A manifest envelope and a bundle are mutually exclusive by construction —
/// the envelope's key 0 is a `bstr` (`body`) and the bundle's key 0 is a
/// `uint` (`format_version`) — so at most one arm ever fires. Both are tried
/// anyway rather than dispatched on a peek: a dispatcher would be a second
/// parser, and F10's cross-parser guard exists because two parsers of the
/// same bytes eventually disagree.
///
/// # Errors
///
/// [`RoundTripViolation`] — every variant is a finding, never an expected
/// outcome.
pub fn round_trip(input: &[u8]) -> Result<RoundTripped, RoundTripViolation> {
    if let Ok(manifest) = Manifest::decode(input) {
        if let Err(err) = check_canonical(input) {
            return Err(RoundTripViolation::CanonicalDisagreement {
                decoder: "Manifest::decode",
                code: err.code(),
            });
        }

        // The envelope claims the whole input, so `anchor_digest`'s
        // pre-image is everything that arrived.
        if manifest.encoded_bytes().len() != input.len() {
            return Err(RoundTripViolation::EnvelopeNotWholeInput {
                covered: manifest.encoded_bytes().len(),
                total: input.len(),
            });
        }

        // Layer 3, then layer 2.
        let body = encode_body(manifest.body().clone()).map_err(|source| {
            RoundTripViolation::EncodeFailed {
                what: "manifest body",
                source,
            }
        })?;
        same_bytes("manifest body", manifest.body_bytes(), &body)?;

        let envelope = encode_envelope(&body, manifest.signatures()).map_err(|source| {
            RoundTripViolation::EncodeFailed {
                what: "manifest envelope",
                source,
            }
        })?;
        same_bytes("manifest envelope", input, &envelope)?;

        let again =
            Manifest::decode(&envelope).map_err(|e| RoundTripViolation::ReDecodeFailed {
                what: "manifest envelope",
                code: e.code(),
            })?;
        if again != manifest {
            return Err(RoundTripViolation::ReDecodeDiffers {
                what: "manifest envelope",
            });
        }
        if work_id(again.body_bytes()) != work_id(manifest.body_bytes()) {
            return Err(RoundTripViolation::DigestChanged { what: "work_id" });
        }
        if anchor_digest(again.encoded_bytes()) != anchor_digest(manifest.encoded_bytes()) {
            return Err(RoundTripViolation::DigestChanged {
                what: "anchor_digest",
            });
        }
        return Ok(RoundTripped::Manifest);
    }

    let Ok(proof) = SealProof::decode(input) else {
        return Ok(RoundTripped::Neither);
    };

    if let Err(err) = check_canonical(input) {
        return Err(RoundTripViolation::CanonicalDisagreement {
            decoder: "SealProof::decode",
            code: err.code(),
        });
    }

    // Zero-copy seam, by address range. `input.as_ptr()` and the embedded
    // slice's pointer are compared as integers only — no dereference, no
    // provenance claim — which is why this needs no `unsafe`.
    let embedded = proof.anchor_digest_preimage();
    let base = input.as_ptr() as usize;
    let inner = embedded.as_ptr() as usize;
    if inner < base || inner.saturating_add(embedded.len()) > base.saturating_add(input.len()) {
        return Err(RoundTripViolation::EmbeddedManifestIsACopy);
    }

    let bytes =
        encode_bundle(proof.bundle()).map_err(|source| RoundTripViolation::EncodeFailed {
            what: "bundle",
            source,
        })?;
    same_bytes("bundle", input, &bytes)?;

    let again = SealProof::decode(&bytes).map_err(|e| RoundTripViolation::ReDecodeFailed {
        what: "bundle",
        code: e.code(),
    })?;
    if anchor_digest(again.anchor_digest_preimage()) != anchor_digest(embedded) {
        return Err(RoundTripViolation::DigestChanged {
            what: "anchor_digest",
        });
    }
    Ok(RoundTripped::Bundle)
}

// ---------------------------------------------------------------------------
// seed corpora
// ---------------------------------------------------------------------------

/// One committed corpus entry.
///
/// `id` is the committed file's stem and the name that reaches crash triage;
/// it is stable, so renaming one is a corpus edit rather than a refactor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Seed {
    /// Stable id — filesystem-safe by construction (see [`sanitize`]).
    pub id: String,
    /// The corpus entry's exact bytes.
    pub bytes: Vec<u8>,
}

/// Map a fixture handle onto a filesystem-safe corpus-file stem.
///
/// R6's catalogue names are `"<shape>/<selection>"`; everything else is
/// already `[a-z0-9-]`. Only `/` is rewritten, and the caller asserts
/// uniqueness afterwards, so the mapping cannot silently collide two seeds
/// into one file.
fn sanitize(name: &str) -> String {
    name.replace('/', "--")
}

/// Push `bytes` under `id`, skipping an entry byte-identical to one already
/// present.
///
/// Content deduplication is the whole of the corpus "minimization" that
/// belongs in a *deterministic* generator: coverage-based minimization
/// (`cargo fuzz cmin`) depends on an instrumented binary, so folding its
/// output back in is a reviewed cadence step (`docs/testing/fuzzing.md`),
/// never something the generator does behind the reviewer's back.
fn push_unique(seeds: &mut Vec<Seed>, id: String, bytes: Vec<u8>) {
    if bytes.is_empty() || seeds.iter().any(|s| s.bytes == bytes) {
        return;
    }
    seeds.push(Seed { id, bytes });
}

/// Seed corpus for the **`manifest_decode`** target: every distinct manifest
/// envelope R6 builds, plus F15's manifest-family tamper fixtures.
///
/// The manifest is a function of the work alone — not of what a reveal shows
/// — so the catalogue's 21 cases collapse to far fewer distinct envelopes,
/// and [`push_unique`] does that collapsing rather than a hand-maintained
/// list that would drift the day a shape is added.
#[must_use]
pub fn manifest_seeds() -> Vec<Seed> {
    let mut seeds = Vec::new();
    for case in shapes::catalogue() {
        let built = build(&case.spec, &case.selection);
        push_unique(&mut seeds, sanitize(case.name), built.manifest);
    }
    // The F13 every-anchor-kind work: anchors live in the bundle, but its
    // file table and sig policy are still a distinct manifest shape.
    for (name, spec) in [
        ("every-anchor-kind", shapes::multi_file_every_anchor_kind()),
        (
            "every-anchor-kind-no-receipt",
            shapes::multi_file_every_anchor_kind_no_receipt(),
        ),
    ] {
        push_unique(
            &mut seeds,
            name.to_owned(),
            build(&spec, &Selection::nothing(3)).manifest,
        );
    }
    push_unique(&mut seeds, "f15-base".to_owned(), base_manifest());
    push_fixture_seeds(&mut seeds, "manifest");
    seeds
}

/// Seed corpus for the **`bundle_decode`** target: every R6 catalogue
/// `.sealproof`, the two every-anchor-kind shapes, and F15's bundle-family
/// tamper fixtures.
#[must_use]
pub fn bundle_seeds() -> Vec<Seed> {
    let mut seeds = Vec::new();
    for case in shapes::catalogue() {
        let built = build(&case.spec, &case.selection);
        push_unique(&mut seeds, sanitize(case.name), built.bytes);
    }
    for (name, spec) in [
        ("every-anchor-kind", shapes::multi_file_every_anchor_kind()),
        (
            "every-anchor-kind-no-receipt",
            shapes::multi_file_every_anchor_kind_no_receipt(),
        ),
    ] {
        push_unique(
            &mut seeds,
            name.to_owned(),
            build(&spec, &Selection::all(3)).bytes,
        );
    }
    push_unique(&mut seeds, "f15-base".to_owned(), base_bundle());
    push_fixture_seeds(&mut seeds, "bundle");
    seeds
}

/// Append F15's committed tamper fixtures for one base.
///
/// Near-misses are the highest-value seeds a *decoder* fuzzer can start
/// from: each is a valid document with exactly one thing wrong, so a single
/// libFuzzer mutation reaches a second, different rejection inside a pass
/// that has already found one — the region random bytes never reach.
///
/// `committed: false` fixtures are skipped. There is exactly one
/// (`bundle-oversized`, whose mutation is a *length*: `MAX_BUNDLE_BYTES + 1`
/// bytes), and materializing 256 MiB into a corpus directory would be
/// absurd — the O(1) length check D10 §5 makes the first statement of
/// `BundleV1::decode` is already covered by `tests/parser_caps.rs` and by
/// F15's synthesized row.
fn push_fixture_seeds(seeds: &mut Vec<Seed>, base: &str) {
    for fixture in FIXTURES.iter().filter(|f| f.base == base && f.committed) {
        if let Some(bytes) = (fixture.build)() {
            push_unique(seeds, format!("f15-{}", fixture.id), bytes);
        }
    }
}

/// Seed corpus for R10's **`verify_bundle`** target, which reads its input
/// as *entropy* rather than as a document
/// ([`super::bundle_mutators::mutate_from_entropy`]).
///
/// # The correction this makes to R10's seeding note
///
/// `fuzz/README.md` (R10) said to "write `seeds/` from `seed_corpus()`",
/// i.e. to commit the **bundle bytes**. That is wrong for this target and
/// the mismatch is worth recording rather than quietly fixing: fed a bundle
/// as entropy, `mutate_from_entropy` reads byte 0 (`0xa4`, a CBOR map head)
/// as a *seed selector* and byte 1 as a *mutation selector*, so the corpus
/// would neither be the bundle nor a meaningful entropy string — and
/// libFuzzer's coverage feedback would be about the indirection rather than
/// about the pipeline.
///
/// The corpus this builds is entropy in R10's documented layout:
/// `[seed + 1, mutation kind, params…]`. Entry `(i, 0)` is "seed `i`,
/// unmutated", which is the highest-value entry there is — it drives a real
/// bundle all the way through the evidence pipeline — and the parameterized
/// entries give libFuzzer one starting point per mutation family.
#[must_use]
pub fn verify_bundle_seeds() -> Vec<Seed> {
    /// Mutation-parameter patterns: little-endian words plus a fill byte,
    /// chosen to land inside a real bundle rather than past its end (the
    /// mutators reduce out-of-range offsets modulo the length, so any value
    /// is *valid* — these are merely the ones worth starting from).
    const PARAMS: [[u8; 16]; 2] = [
        [
            0x10, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0xFF, 0x00,
            0x00, 0x00,
        ],
        [
            0x01, 0x01, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x5A, 0x00,
            0x00, 0x00,
        ],
    ];

    let corpus = super::bundle_mutators::seed_corpus();
    let mut seeds = Vec::new();
    for (index, (name, _)) in corpus.iter().enumerate() {
        // Selector is 1-based: 0 means "no seed, raw bytes".
        let Ok(selector) = u8::try_from(index + 1) else {
            break;
        };
        push_unique(&mut seeds, format!("{name}--identity"), vec![selector, 0]);
        for (kind, params) in (1u8..7).zip(PARAMS.iter().cycle()) {
            let mut entropy = vec![selector, kind];
            entropy.extend_from_slice(params);
            push_unique(&mut seeds, format!("{name}--mutation-{kind}"), entropy);
        }
    }
    seeds
}

/// Generate every corpus from scratch. Pure and deterministic; the cached
/// [`all_corpora`] is what callers should use.
fn generate_all() -> Vec<(&'static str, Vec<Seed>)> {
    vec![
        ("manifest_decode", manifest_seeds()),
        ("bundle_decode", bundle_seeds()),
        ("verify_bundle", verify_bundle_seeds()),
    ]
}

/// Every committed corpus, as `(target name, seeds)` — **built once per
/// process**.
///
/// The single enumeration point: the emitter, the drift check and the
/// stray-file check all read it, so a new target's corpus is one entry here
/// rather than three edits that can disagree.
///
/// Memoized because generation is *expensive and deterministic*: R6 signs
/// (ML-DSA-65) and encrypts for every catalogue shape, which in an
/// unoptimized test build dominates any property suite that calls this per
/// case. One build is exactly as good as many — [`generate_all`] is pure —
/// and the determinism the cache relies on is itself asserted
/// (`corpus_generation_is_deterministic`).
///
/// `codec_round_trip` deliberately has **no corpus of its own**: its input
/// space is the union of the other two, so the driver script passes both
/// decode corpora to it instead of committing the same bytes twice
/// (`scripts/fuzz.sh`, `docs/testing/fuzzing.md`).
#[must_use]
pub fn all_corpora() -> &'static [(&'static str, Vec<Seed>)] {
    static CORPORA: std::sync::OnceLock<Vec<(&'static str, Vec<Seed>)>> =
        std::sync::OnceLock::new();
    CORPORA.get_or_init(generate_all)
}

/// One cached corpus by target name.
///
/// # Panics
///
/// If `target` names no corpus — a caller bug (the target list is a
/// compile-time constant), not adversarial input.
#[must_use]
pub fn corpus(target: &str) -> &'static [Seed] {
    all_corpora()
        .iter()
        .find(|(name, _)| *name == target)
        .map_or_else(
            || panic!("no fuzz corpus named `{target}`"),
            |(_, seeds)| seeds.as_slice(),
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_corpus_is_non_empty_and_uniquely_named() {
        for (target, seeds) in all_corpora() {
            assert!(!seeds.is_empty(), "corpus `{target}` is empty");
            let mut ids: Vec<&str> = seeds.iter().map(|s| s.id.as_str()).collect();
            ids.sort_unstable();
            let before = ids.len();
            ids.dedup();
            assert_eq!(before, ids.len(), "corpus `{target}` has duplicate ids");
            for seed in seeds {
                assert!(!seed.bytes.is_empty(), "`{target}/{}` is empty", seed.id);
                assert!(
                    !seed.id.contains('/') && !seed.id.contains('\\'),
                    "`{target}/{}` is not a safe file stem",
                    seed.id
                );
            }
        }
    }

    /// The corpus is content-deduplicated, which is what makes the committed
    /// set minimal in the only sense a deterministic generator can promise.
    #[test]
    fn no_two_seeds_in_a_corpus_share_bytes() {
        for (target, seeds) in all_corpora() {
            for (i, a) in seeds.iter().enumerate() {
                for b in &seeds[i + 1..] {
                    assert_ne!(a.bytes, b.bytes, "`{target}`: {} == {}", a.id, b.id);
                }
            }
        }
    }

    /// Generation is deterministic: the same call twice gives the same
    /// corpus. Without this the committed-vs-generated drift check would be
    /// flaky rather than meaningful.
    #[test]
    fn corpus_generation_is_deterministic() {
        assert_eq!(generate_all(), generate_all());
        assert_eq!(generate_all().as_slice(), all_corpora());
    }

    /// Each decode corpus is aimed at its own decoder: the manifest seeds
    /// are envelopes and the bundle seeds are `.sealproof`s, so a corpus
    /// swap would be caught rather than merely making the fuzzer useless.
    ///
    /// The two formats are mutually exclusive at the **first key**, which is
    /// why [`round_trip`] may try both decoders without a dispatcher: an
    /// envelope's key 0 is a `bstr` and a bundle's is a `uint`, so each
    /// decoder rejects the other's documents on the very first value.
    #[test]
    fn the_seeds_are_aimed_at_the_decoder_they_seed() {
        for seed in corpus("manifest_decode") {
            assert!(
                matches!(drive_bundle(&seed.bytes), CodecOutcome::Rejected(_)),
                "manifest seed `{}` must not decode as a bundle",
                seed.id
            );
        }
        for seed in corpus("bundle_decode") {
            assert!(
                matches!(drive_manifest(&seed.bytes), CodecOutcome::Rejected(_)),
                "bundle seed `{}` must not decode as a manifest",
                seed.id
            );
        }
    }

    /// The valid seeds decode and the F15 fixtures do not — otherwise a
    /// "tamper" seed could quietly be a second copy of a valid one, and the
    /// corpus would claim coverage it does not have.
    #[test]
    fn the_seeds_are_what_their_names_say() {
        for seed in corpus("manifest_decode") {
            let outcome = drive_manifest(&seed.bytes);
            if seed.id.starts_with("f15-") && seed.id != "f15-base" {
                assert!(
                    matches!(outcome, CodecOutcome::Rejected(_)),
                    "`{}` must be rejected",
                    seed.id
                );
            } else {
                assert_eq!(outcome, CodecOutcome::Decoded, "`{}` must decode", seed.id);
            }
        }
        for seed in corpus("bundle_decode") {
            let outcome = drive_bundle(&seed.bytes);
            if seed.id.starts_with("f15-") && seed.id != "f15-base" {
                assert!(
                    matches!(outcome, CodecOutcome::Rejected(_)),
                    "`{}` must be rejected",
                    seed.id
                );
            } else {
                assert_eq!(outcome, CodecOutcome::Decoded, "`{}` must decode", seed.id);
            }
        }
    }

    /// Every valid seed satisfies the round-trip law, and the arm it reports
    /// is the one its corpus is for.
    #[test]
    fn valid_seeds_round_trip() {
        for seed in corpus("manifest_decode") {
            if drive_manifest(&seed.bytes) == CodecOutcome::Decoded {
                assert_eq!(
                    round_trip(&seed.bytes),
                    Ok(RoundTripped::Manifest),
                    "`{}`",
                    seed.id
                );
            }
        }
        for seed in corpus("bundle_decode") {
            if drive_bundle(&seed.bytes) == CodecOutcome::Decoded {
                assert_eq!(
                    round_trip(&seed.bytes),
                    Ok(RoundTripped::Bundle),
                    "`{}`",
                    seed.id
                );
            }
        }
    }

    /// R10's entropy corpus really is entropy in the documented layout: the
    /// identity entries reproduce the mutation engine's own seeds exactly.
    #[test]
    fn the_verify_bundle_corpus_is_entropy_not_documents() {
        let bundles = super::super::bundle_mutators::seed_bytes();
        let identity: Vec<&Seed> = corpus("verify_bundle")
            .iter()
            .filter(|s| s.id.ends_with("--identity"))
            .collect();
        assert_eq!(identity.len(), bundles.len());
        for (index, seed) in identity.iter().enumerate() {
            assert_eq!(seed.bytes.len(), 2, "an identity entry is two bytes");
            assert_eq!(
                super::super::bundle_mutators::mutate_from_entropy(&seed.bytes, &bundles),
                bundles[index],
                "`{}` must select seed {index} unmutated",
                seed.id
            );
        }
    }

    /// Degenerate inputs are handled without a panic and without claiming a
    /// round trip.
    #[test]
    fn degenerate_inputs_are_total() {
        for input in [
            &[][..],
            &[0x00],
            &[0xa0],
            &[0xff; 64],
            &[0x5b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
        ] {
            let _ = drive_manifest(input);
            let _ = drive_bundle(input);
            assert_eq!(round_trip(input), Ok(RoundTripped::Neither), "{input:02x?}");
        }
    }

    /// `first_difference` reports the offset a reader would look at, and the
    /// shorter length when one input is a prefix of the other.
    #[test]
    fn first_difference_reports_a_usable_offset() {
        assert_eq!(first_difference(b"abc", b"abd"), 2);
        assert_eq!(first_difference(b"abc", b"abcd"), 3);
        assert_eq!(first_difference(b"", b"a"), 0);
        assert_eq!(first_difference(b"abc", b"abc"), 3);
    }
}
