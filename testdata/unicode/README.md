# `testdata/unicode/` — Unicode's own NFC conformance data

The **T0 external oracle** for antseal's canonicalization (decision D31,
vehicle register row 10). One file of external test data, the script that
derived it, and its provenance.

| file | what |
| --- | --- |
| `NormalizationTest-17.0.0-sample.txt` | filtered sample of Unicode 17.0.0's `NormalizationTest.txt` |
| `filter_normalization_test.py` | re-derives that sample from the upstream file |
| `PROVENANCE.md` | upstream URL, version, SHA-256, retrieval time, filter expression |

## Why this exists

D31 §1 grades cross-check vehicles:

- **T0** — an external oracle, values originating outside this project *and*
  outside its language ecosystem. The only tier that catches a **shared
  misreading of the specification**.
- **T1** — an independent re-implementation. Catches transcription and
  implementation bugs; does *not* catch a shared misreading.
- **T2** — two implementations in one ecosystem. Catches neither.

`testdata/utf8-corpus/gen_corpus.py` is a T1 vehicle for canonicalization v1:
Python stdlib against Rust, no shared code. Its NFC stage, though, is only as
good as the Unicode table behind `unicodedata.normalize`, and "our Python and
our Rust both normalize the same way" says nothing about whether either
matches Unicode. `NormalizationTest.txt` is the Consortium's own conformance
data for precisely that question, which makes the NFC leg T1-anchored-by-T0
rather than T1-unanchored.

## Why not under `testdata/vectors/`

Same trap F19 documented for F14's sidecar and D31 §5 rules on for the ACVP
fixture: `testdata/vectors/README.md` states a hard directory contract, and
files under a `vectors/v<n>/` component directory are validated against the
antseal vector envelope schema (`non_secret` marker, `inputs.w` equal to the
documented test seed, and so on). Unicode's conformance data satisfies none of
that and would fail the runner. External fixtures live outside `vectors/`.

## Running it

The consumer is the corpus generator's `--check`, reached through the lane:

```sh
./scripts/cross-check.sh              # everything
python3 testdata/utf8-corpus/gen_corpus.py --check    # just this surface
```

It prints one verdict line with the executed and skipped counts and the
running interpreter's Unicode table version, e.g.

```
OK    NormalizationTest NFC anchor: 1537 line(s) executed, 70 skipped as
      unassigned in Unicode 14.0.0 (T0, Unicode 17.0.0 conformance data)
```

## Re-deriving the committed sample

See PROVENANCE.md for the one-liner. In short: fetch upstream, check its
SHA-256, run `filter_normalization_test.py --source … --check`. That is what
makes this a reproducible derivative rather than a blob of trust.

## Retention

Frozen and retained forever, like every other committed fixture
(`docs/dependency-policy.md` §4, Q6, D31 §6c). A newer Unicode release may be
*added* as a second pinned sample; this one is never replaced, because it is
the evidence that the v1 freeze was clean against the version D25 pins.

## The interpreter-version caveat

Real and stated up front, because it bounds what this anchor proves: the
runner skips lines containing scalars unassigned in the *running* interpreter,
and enforces a floor on the lines actually executed so it cannot pass
vacuously. The full argument, including why the executed remainder is exact
under the Unicode Normalization Stability Policy, is in PROVENANCE.md.

**Note that D31 §3 asked for a `unicodedata.unidata_version == '17.0.0'`
assertion here. It is deliberately not implemented — no released CPython
embeds Unicode 17.0.0 — and `gen_corpus.py`'s module docstring records why,
and what was built instead.**
