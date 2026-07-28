# fuzz-seeds/ — committed fuzz seed corpora (F17/Q9)

One directory per cargo-fuzz target, plus `MANIFEST.json` recording every
seed's id, length and SHA-256. Normative doc:
[`../../docs/testing/fuzzing.md`](../../docs/testing/fuzzing.md).

| directory | target | entries are |
| --- | --- | --- |
| `manifest_decode/` | F17 | manifest **envelope** bytes |
| `bundle_decode/` | F17 | `.sealproof` bytes |
| `verify_bundle/` | R10 | **entropy strings**, not documents (see below) |

A23's DER/`.ots` parsers add their directories at M2 (Q17).

`codec_round_trip` has no directory of its own: its input space is the union
of the two decode corpora, so `scripts/fuzz.sh` passes both to it rather
than committing the same bytes twice.

`verify_bundle`'s target reads byte 0 as a seed selector and byte 1 as a
mutation selector (`bundle_mutators::mutate_from_entropy`), so its corpus is
`[seed + 1, mutation kind, params…]`. Committing *bundle bytes* there would
produce a corpus that is neither a bundle nor a meaningful entropy string.

## Generated, never hand-edited

The generator is `antseal_core::test_util::codec_fuzz::all_corpora`; the
emitter is `crates/antseal-core/tests/codec_fuzz.rs`:

```
cargo test -p antseal-core --features test-util --test codec_fuzz \
    -- --ignored emit_fuzz_seed_corpora
```

That same test file fails if the committed tree and the generator disagree by
a byte, an id, or a stray file — so a seed can neither drift nor be added by
hand. Seeds come from R6's fixture catalogue (every M0 shape, which is what
the golden vectors in `../vectors/` are also built from) and from F15's
committed tamper fixtures (`../tamper/format/`).

## Derived artifacts, not frozen ones

Q6's `FROZEN.sha256` covers `../vectors/` only. A deliberate format change
**re-blesses** these as a matter of course; that is not a freeze violation.
It is still a reviewed event — a byte change here means a fixture, a shape,
or the wire format moved.

Minimization: the generator content-deduplicates on every regeneration.
Coverage minimization (`scripts/fuzz.sh cmin`) runs against the *working*
corpus under `fuzz/corpus/` (gitignored) and its output is reviewed, never
folded back blind — cadence in the fuzzing doc §3.

## Crash triage

A crash is release-blocking. Its reduced reproducer is retained either here
(by adding it to the generator, so it is regenerated rather than dropped in
by hand) or as a `../tamper/` regression row. Full workflow: fuzzing doc §4.

NON-SECRET fixtures only (see `../README.md`): every byte derives from the
documented test seed `W`. Seed bytes are exact — covered by the
`testdata/** -text` checkout guard like everything else here.
