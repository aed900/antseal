# `fuzz/` — cargo-fuzz targets

Registered targets:

| target | owner | input is | what it drives |
| --- | --- | --- | --- |
| `manifest_decode` | F17 | a manifest envelope | `Manifest::decode` — layers 2+3 of registry §7.6.3 |
| `bundle_decode` | F17 | a `.sealproof` | `SealProof::decode` — all three strict layers |
| `codec_round_trip` | F17 | either of the above | `codec_fuzz::round_trip` — decode ⇒ byte-identical re-encode |
| `verify_bundle` | R10 | **entropy** | `verify::verify_bundle`, over structure-aware mutations of valid R6 bundles |

A23's `TimeStampResp` and `.ots` targets join at M2 (Q17). Adding a target
means three edits — `Cargo.toml`, `scripts/fuzz.sh`'s `TARGETS` list, and
this table — which is deliberate: a target nothing runs is worse than no
target at all.

**Everything about running these lives in
[`docs/testing/fuzzing.md`](../docs/testing/fuzzing.md)**: run commands,
corpus policy, minimization cadence, crash triage, CI lanes, and the D61
long-run-venue note. This file is the registry and the design notes.

## The invariants, and where they are actually asserted

| invariant | asserted by |
| --- | --- |
| no panic | the target returning at all — there is deliberately no `catch_unwind` anywhere |
| no allocation beyond the F11 budget | `src/lib.rs`'s counting global allocator, per input |
| no hang | libFuzzer `-timeout=25` (`scripts/fuzz.sh`) |
| decode ⇒ canonical-byte identity | `codec_round_trip`, via `codec_fuzz::round_trip` |

The allocation budget is worth spelling out because it is the one invariant
a fuzzer cannot observe for itself, and because generalizing it corrected
the claim. Decision D10 §4's clamp rule says every pre-allocation is clamped
to `min(claimed_length, remaining_input)` — in **elements**. So the true
bound is `remaining_input × size_of::<Element>()`, not `remaining_input`,
and `crates/antseal-core/tests/parser_caps_alloc.rs`'s stated consequence
("never more than the attacker's own bytes") holds there only because its
inputs are under 32 bytes and the multiplier hides inside a 4 KiB `SLACK`.
The first fuzz run found a 152-byte input driving a 4 704-byte reservation.
Details, numbers and the proposed fix (task **F30**):
[`docs/testing/fuzzing.md`](../docs/testing/fuzzing.md) §1.

`src/lib.rs` therefore asserts the *true* bound, on **every** input any
target ever sees — which is still the generalization that test's own docs
anticipate ("the invariant F17's fuzz target will restate"), and still
catches every realistic failure: `claimed` is a `u64`, so the gap between
`len × 256` and `u64::MAX × 256` is the entire hazard.

## Why the targets are nearly empty

Everything interesting — the drivers, the round-trip law, the mutation set,
the seed corpora — lives in `antseal-core` behind the `test-util` feature
(`test_util::codec_fuzz`, `test_util::bundle_mutators`) and is exercised by
the ordinary test suite on every CI build.

A fuzz target carrying its own logic is only ever exercised when someone runs
the fuzzer, so it rots between runs and a crash it finds may not reproduce
under the test suite. Here the two halves share one code path, so a libFuzzer
crash reproduces as a plain unit test — on the *stable* toolchain, with no
sanitizer and no nightly.

It also means no crate here needs an `Arbitrary` impl: every target
interprets raw bytes itself, so `antseal-core` gains no fuzzing dependency.

## Two input encodings, on purpose

F17's three targets take the **document itself** — the fuzz input *is* the
candidate CBOR, byte for byte. R10's `verify_bundle` takes **entropy** —
byte 0 selects a seed bundle, byte 1 a mutation, the rest are parameters —
because its job is to get *past* the decoder into the evidence stages, which
random bytes essentially never do.

The consequence for corpora is easy to get wrong, so it is stated in both
places: `testdata/fuzz-seeds/verify_bundle/` holds **entropy strings**, not
bundles. (This README previously said to seed it from `seed_corpus()`, i.e.
from bundle bytes. That would have produced a corpus that is neither a
bundle nor a meaningful entropy string — fed a bundle, `mutate_from_entropy`
reads `0xa4`, a CBOR map head, as a seed selector. Corrected at Q9;
`codec_fuzz::verify_bundle_seeds` builds the right thing and a unit test
pins that the `--identity` entries reproduce R10's own seeds.)

## Dependencies, flagged

`libfuzzer-sys` and its transitive `arbitrary`/`cc` subtree are third-party
dependencies, and `docs/dependency-policy.md` makes that a deliberate
reviewed event. Two things contain the blast radius:

- `Cargo.toml` carries an empty `[workspace]` table, cargo-fuzz's standard
  detach idiom, so this crate has its **own** lockfile and nothing here
  enters the workspace `Cargo.lock` or the audited normal dependency graph.
  The `core-dep-graph` lane's verdict is therefore structurally unaffected,
  not merely unaffected today;
- the targets use neither crate's API beyond `fuzz_target!`.

`Cargo.lock` **is committed**, following the `probes/*` precedent (root
`.gitignore`: "their `Cargo.lock` files ARE committed (reproducible probes)
— only build output is ignored").

## The `unsafe` here, and why `antseal-core` still has none

`src/lib.rs` installs a `#[global_allocator]`, and `GlobalAlloc` is an
`unsafe trait` whose four methods are `unsafe fn` by definition — there is no
safe API that observes allocation. The workspace's sanctioned opt-out is an
`#![allow(unsafe_code)]` at a crate root with a written justification, which
is what that file carries; the precedent is
`crates/antseal-core/tests/parser_caps_alloc.rs`, whose three invariants
(forward unchanged to `System`; allocation-free and lock-free additions;
observation-only counters) are the same three.

`antseal-core`'s library remains entirely `unsafe`-free, and this crate is
detached from the workspace and ships nothing. `Cargo.toml` restates
`unsafe_code = "deny"` rather than inheriting it, since a detached crate
inherits no `[workspace.lints]`.

## The half that runs without a fuzzer

Both engines are covered by the ordinary suite, which is what keeps them
honest between fuzz runs:

- `crates/antseal-core/tests/codec_fuzz.rs` — F17: committed corpora driven
  from disk, R10's mutations applied to them, and both properties over
  arbitrary bytes;
- `crates/antseal-core/tests/verify_fuzz.rs` — R10: the no-panic property
  over its mutation set, plus the pinned equality recording which regions of
  a bundle legitimately still verify at M0 (the storage record and the
  anchor artifacts), so a crash-free fuzz run is not mistaken for
  "everything is authenticated".
