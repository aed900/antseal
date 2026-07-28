# tamper/format/ — the format-level tamper fixtures (F15)

Twenty single mutations of the F12/F13 golden vectors' own bytes, each
mapped to the exact `(code, layer)` pair the strict decode surface must
report. Committed so a third-party verifier can be checked against them
without running any antseal code.

| File | What it is |
| --- | --- |
| `FIXTURES.json` | the machine-readable fixture→expected-error mapping table |
| `base/manifest.cbor` | the base manifest envelope — byte-identical to `vectors/v1/manifest/manifest.json` case `minimal-binary-ed25519-only` |
| `base/bundle.cbor` | the base `.sealproof` — byte-identical to `vectors/v1/bundle/bundle.json` case `empty-anchor-unanchored` (the UNANCHORED bundle) |
| `*.cbor` | one mutated artifact per fixture; the file stem **is** the fixture id |

Everything here is NON-SECRET under `../../README.md`'s secret-material
convention: both bases are built by R6's deterministic constructor from the
documented fixed test seed, and a tampered fixture is still committed
material.

## Reading the table

Each `fixtures[]` entry is `{id, base, mutation, surface, source, expected,
row}`.

- **`surface`** is the entry point the bytes are fed to: `check_canonical`,
  `Manifest::decode` (layers 2–3) or `SealProof::decode` (all three layers
  of registry §7.6.3).
- **`expected.code`** is the stable machine-readable code
  (`../../docs/testing/error-code-contract.md`, D30).
- **`expected.layer`** is which of the three strict layers the failure is
  attributed to. It is `null` for a manifest **schema** rejection, which
  names its own map rather than a layer — but *not* for a bundle schema
  rejection, because a layer-1 failure is layer 1 by construction. That
  asymmetry is two recorded decisions rather than a defect; the practical
  reading is that `layer: null` means "schema rejection inside the
  manifest".
- **`source.kind`** is `file` (bytes committed here) or `synthesized` (a
  recipe). Exactly one fixture is synthesized — see below.
- **`row`** names the Q7 tamper-matrix row this fixture is evidence for, or
  `null`.

## Why only seven of the twenty are rows

A **fixture** says "these bytes, this surface, this outcome". A **row**
additionally claims *distinctness*: Q7's `check_registry` refuses two rows
expecting the same outcome, because that would mean two mutations are one
observable failure (MVP-SPEC.md line 168).

F6 and F9 decided — deliberately — that a wrapped codec rejection
**surfaces its inner code unchanged** at every layer, and that the layer is
pipeline context rather than a rejection class (error-code contract §2). So
a duplicate map key in the manifest body, in the manifest envelope, in the
bundle map and in the embedded manifest are four different fixtures that all
report `cbor-duplicate-map-key`. Minting `cbor-duplicate-map-key-in-body`
and friends to make them four rows would fork one taxonomy into four, which
§3 of the contract forbids outright.

The resolution is that the *fixture* is the finer instrument: it is checked
on `(code, layer)`, which **is** pairwise informative across the layer
variants, while a row is registered only where the code is not already
claimed. The seven rows are `cbor-non-shortest-length`,
`manifest-unknown-key`, `manifest-reserved-key`, `bundle-unknown-key`,
`bundle-reserved-key`, `cbor-oversized` (code `bundle-too-large`) and
`cbor-nesting-too-deep`.

The four mutations MVP-SPEC.md line 168 names by hand — duplicate key,
non-shortest int, indefinite length, trailing bytes — keep the rows Q7
seeded for them and gain a **real manifest-body fixture** here: four
separate fixtures, four distinct errors, all at the body layer.

## The one fixture that is a recipe, not a file

`bundle-oversized`'s mutation is a *length*: `MAX_BUNDLE_BYTES + 1` =
268 435 457 bytes. Committing 256 MiB to pin an `O(1)` comparison would be
absurd, so the table records the recipe — "the base bundle, zero-padded to
`MAX_BUNDLE_BYTES + 1` bytes" — and the harness synthesizes it. The buffer
is zero-allocated and `BundleV1::decode`'s first statement is the length
check (decision D10 §5), so nothing past the copied prefix is ever read. A
test asserts that no *committed* fixture here exceeds 64 KiB, so the recipe
cannot quietly become a file.

## Regenerating

```
cargo test -p antseal-core --features test-util --test format_tamper_fixtures \
    -- --ignored emit_format_tamper_fixtures
```

That emitter is the only sanctioned way to rewrite these bytes. Nothing
under `tamper/` is covered by Q6's `FROZEN.sha256` (that guard is
`vectors/` only), but a byte change here is still a reviewed event: it means
a mutation, a base, or a code changed.

The consumer — `crates/antseal-core/tests/format_tamper_fixtures.rs` —
checks all four directions every run: the table describes the fixture set
exactly, the committed bytes are the constructor's bytes at the recorded
length and digest, the committed bytes still fail as mapped when read back
from disk, and both bases are still byte-identical to the golden vectors.
