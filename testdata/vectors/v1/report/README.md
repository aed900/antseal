# `report` vectors (R9) — canonical bundles → expected report bytes

`verification-reports.json` maps every M0 shape's canonical `.sealproof`
bundle to the **byte-exact serialized `VerificationReport`** that
`verify_bundle` produces for it (MVP-SPEC.md lines 153, 167, 169). It is the
medium the native↔WASM bit-match lane compares: the same executor runs under
`wasm32-unknown-unknown` and the transcripts must be byte-identical
(`scripts/wasm-bitmatch.sh`).

The byte format is `docs/decisions/D29-report-byte-format.md`: compact JSON,
struct-declaration field order, lowercase-hex binary, kebab-case enum names,
no floats, no conditional field presence, `report_version` first.

## One case

| field | pins |
| --- | --- |
| `shape` | the R6 `shapes::catalogue()` handle this case builds (`crates/antseal-core/src/test_util/bundle_fixtures.rs`) |
| `bundle_len`, `bundle_sha256` | the **input**: R6's constructor bytes for that shape |
| `revealed_unit_ids` | the work-global units the reveal shows |
| `report_len`, `report_json` | the **output**, byte-exact: lowercase hex of `VerificationReport::to_canonical_json()` |
| `report` | the same bytes decoded, as an object — the review surface |

`report` and `report_json` cannot drift: the executor decodes the hex and
requires the two to agree. **Only `report_json` pins field order.** A JSON
object compares order-insensitively, and `serde_json` writes object keys
alphabetically, so the object form deliberately does *not* look like the wire
bytes — D29 rule 1 makes struct declaration order the wire order, and the hex
is the only field that records it.

## Why the bundle is named rather than embedded

R6's constructor sits on the `test-vectors` feature tier precisely so the
wasm32 lane can build bundles **in-process**. Both lanes therefore construct
the identical bytes, and `bundle_sha256` proves they did. Embedding ~7 kB of
ciphertext and post-quantum signature per case would have made the document
unreviewable and put a second definition of "a valid bundle" in the tree, for
no coverage gained.

The consequence worth stating plainly: **a change to what a shape means is a
vector event.** Retiling a file, reseeding the fixture RNG, or renaming a
catalogue handle all move `bundle_sha256` and turn this file red. That is the
intent — a golden vector whose input can be swapped silently pins nothing.

## How the unbalanced n = 6 cases pin MSB-first indexing *through the pipeline*

`unbalanced-n6/unit-0`, `/unit-1` and `/unit-2` each reveal one two-byte unit
of a six-byte fine-tree file, opening the depth-1 GGM subtrees over leaves
{0,1}, {2,3} and {4,5} respectively — between them, every non-palindromic
path of the `d = 3` grid.

The report itself carries no seed or cover (it must not — see the hygiene
note below), so the pin is structural rather than textual, and it holds in
two independent ways:

1. the disclosed cover seed is part of the bundle, so flipping the bit order
   in the **builder** moves `bundle_sha256`;
2. the vector requires the bundle to *verify*, and `verify_bundle` rebuilds
   the cover and checks it against `fine_root`, so flipping the bit order in
   the **verifier** fails the case outright.

An implementation that flipped both consistently would still be caught, by
(1). `v1/fine-tree/` pins the same rule at the tree layer, with every
intermediate exposed; these cases pin that the pipeline actually uses it.

## Secret hygiene

A report vector legitimately discloses whatever its bundle discloses and no
more. Reports carry only public statement data — ids, sizes, spans, states,
already-public digests — and the executor enforces it: for every file and
unit of every work it re-derives `k_u`, `unit_salt`, `path_salt`, `file_salt`
and `s_root` from the documented test seed and requires none of them to
appear anywhere in the pinned bytes (project rule 6; the secret-material
policy in `crates/antseal-core/src/verify/report.rs`). The values are
re-derived rather than read off the fixture, so the check does not depend on
what the builder chose to keep, and a caught leak is reported by name without
echoing the value.

## Regenerating

Deliberate act, with a freeze consequence — never a side effect of running
the suite:

```sh
cargo test -p antseal-core --features test-util --test report_vectors \
    -- --ignored emit_report_vector_document
./scripts/vector-freeze.sh --update      # then justify the digest diff
```

`crates/antseal-core/tests/report_vectors.rs` holds the emitter, the
regenerate-and-diff test, and the checks that the emitter's case list and the
committed file have not drifted apart. There is deliberately **no** Python
cross-implementation here as there is for `fine-tree`: reproducing a report
means reproducing the whole evidence pipeline, and a second pipeline would be
a second product rather than a cross-check. What stands in for it is the
input side — the commitments, AEAD, HKDF and fine-tree material these bundles
are built from are each pinned against an independent implementation by the
`commitments`, `unit-aead`, `signatures` and `fine-tree` vectors.

## Retention

Frozen by `../FROZEN.sha256` and rostered in `../INDEX.json` under the slug
`verification-reports`. Retained indefinitely per the format-stability policy
(`../../README.md`): R28's multi-version suite extends the roster with one
`report` vector per released format version and keeps running all of them.
