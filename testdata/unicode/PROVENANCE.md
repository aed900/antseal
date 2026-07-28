# Provenance — Unicode NormalizationTest conformance data

External test data. Its provenance is not verifiable from this tree alone, so
it is recorded here in full. D31's consequence 6 applies: **a missing or stale
PROVENANCE.md is a red lane, not a documentation nit.**

## Upstream

| field | value |
| --- | --- |
| source | Unicode Consortium, Unicode Character Database |
| URL | `https://www.unicode.org/Public/17.0.0/ucd/NormalizationTest.txt` |
| Unicode version | **17.0.0** (released 2025-09-09) |
| upstream size | 2 827 429 bytes |
| upstream SHA-256 | `5019ffd530751a741900c849c0e010332f142a3612234639bd200b82138a87db` |
| retrieved | **2026-07-28T14:37:55Z** |
| retrieved by | Q11 (D31 §9 step 2), read-only public fetch |

Unicode 17.0.0 is the version D25 pins for antseal's canonicalization
(descriptor string `unicode-17.0.0`, crate `unicode-normalization =0.1.25`).
The conformance data therefore matches the pin exactly, which is the whole
reason to take the sample from this release rather than from whatever release
the CI interpreter happens to embed.

## Committed derivative

| field | value |
| --- | --- |
| file | `NormalizationTest-17.0.0-sample.txt` |
| size | 286 374 bytes |
| SHA-256 | `cd73a72c1ba2f73911e720eeabb31ed56f28ea2996b7ef632d1480d221f2ecf0` |
| data lines | 1 607 |
| derived by | `filter_normalization_test.py` (committed beside it) |

### Filter expression

Parts 0, 3, 4 and 5 are kept whole; parts 1 and 2 keep every 32nd data line.
Comment and blank lines are dropped, `@PartN` markers are preserved and
normalised to their bare form. Exactly:

```python
FULL_PARTS = ("Part0", "Part3", "Part4", "Part5")
STRIDE = 32
```

Rationale for the split is in the script's module docstring: parts 0/3/4/5 are
the curated corners (specific cases, PRI #29 composition exclusions, canonical
closures, chained primary composites) where normalizers actually break, and
they are small; parts 1 and 2 are mechanical bulk where a stride loses little.

## Re-deriving the committed bytes

```sh
curl -O https://www.unicode.org/Public/17.0.0/ucd/NormalizationTest.txt
sha256sum NormalizationTest.txt   # must equal the upstream SHA-256 above
python3 testdata/unicode/filter_normalization_test.py \
        --source NormalizationTest.txt --check
```

`--check` exits 0 on byte equality with the committed sample and non-zero
otherwise. That is what makes this a reproducible derivative rather than a
blob of trust.

## What consumes it

`testdata/utf8-corpus/gen_corpus.py --check`, via `scripts/cross-check.sh`.
It runs the **NFC column only** (column 2 of the upstream five-column format),
which is the single stage of D21's pipeline that depends on a Unicode table.

### The interpreter-version caveat, stated plainly

The runner skips any line containing a scalar that is unassigned in the
*running* interpreter's `unicodedata` table, and reports how many it skipped.
This is required for correctness, not a convenience: a character assigned in
Unicode 17.0 but not in the interpreter's older table has no decomposition
there, so its expected NFC form legitimately differs and asserting it would be
asserting a falsehood.

For every character the interpreter *does* know, the Unicode Normalization
Stability Policy guarantees the 17.0.0 expected value is correct — the policy
forbids adding a canonical decomposition to an already-assigned character and
freezes combining classes. So the skip is sound and the remainder is exact.

The runner enforces a floor on the number of lines actually executed
(`NORMALIZATION_TEST_MIN_LINES` in `gen_corpus.py`), so an ancient interpreter
or a truncated file fails the lane instead of passing it vacuously.

Observed on the development interpreter (CPython 3.11.2, `unidata_version`
**14.0.0**): **1 537 lines executed, 70 skipped**, zero disagreements. A newer
interpreter executes strictly more (its table knows strictly more scalars), so
14.0.0 is the worst case and the floor is set against it.
