# Provenance — NIST ACVP ML-DSA-65 test vectors

D31 consequence 6: **this is the first committed test data in the repo whose
provenance is external and unverifiable from the tree alone.** PROVENANCE.md
plus `filter_acvp.py` is what makes it auditable, and **a missing or stale
PROVENANCE.md is a red lane, not a documentation nit.**

## The acquisition probe (D31 §4c) — verdict

D31 refused to assert from a capability list whether the current
`internalProjection.json` actually contains external-interface groups with a
`context` field, and required a probe first.

**Verdict: BRANCH A.** External-interface groups with a populated `context`
field exist for ML-DSA-65, in both sigGen and sigVer. Row 13 (`ctx`
absorption) is therefore **T0**, checked directly against NIST rather than
against the FIPS 204 Algorithm 2 hand-derivation that Branch B would have
required. Branch B was not taken and is not needed.

Probe run 2026-07-28T14:35Z. Distinct
`(parameterSet, signatureInterface, preHash, externalMu, deterministic)`
tuples found for ML-DSA-65, with case counts:

| file | signatureInterface | preHash | externalMu | deterministic | cases | kept |
| --- | --- | --- | --- | --- | --- | --- |
| keyGen | – | – | – | – | 25 | yes |
| sigGen | external | pure | false | **true** | 15 | yes |
| sigGen | external | pure | false | false | 15 | yes |
| sigGen | external | preHash | false | true/false | 30 | no — HashML-DSA |
| sigGen | internal | none | false | true | 15 | yes |
| sigGen | internal | none | false | false | 15 | yes |
| sigGen | internal | none | **true** | true/false | 30 | no — externalMu |
| sigVer | external | pure | false | – | 15 | yes |
| sigVer | external | preHash | false | – | 15 | no — HashML-DSA |
| sigVer | internal | none | false | – | 15 | yes |
| sigVer | internal | none | **true** | – | 15 | no — externalMu |

ML-DSA-65 `context` field: **present on all 60 external sigGen cases** (56
non-empty, lengths spanning 0 to 255 bytes) and **all 30 external sigVer
cases** (28 non-empty). Absent from internal-interface cases, as expected.

### One correction to D31's filter

D31 §4c Branch A says to filter `preHash == "pure"` while "keeping both
`signatureInterface` values". Those two clauses contradict each other: the
probe shows internal-interface groups carry `preHash == "none"`, not
`"pure"`, so the literal filter would have dropped every internal group. The
filter implemented is **drop `preHash == "preHash"`** (HashML-DSA, which
antseal does not implement), which is what the prose meant.

## Upstream

| field | value |
| --- | --- |
| repository | `usnistgov/ACVP-Server` |
| commit | **`2972def23bf9f3680c2c531561ed9bdd0f1086ad`** (release v1.1.0.43, 2026-07-20) |
| path | `gen-val/json-files/ML-DSA-<mode>-FIPS204/internalProjection.json` |
| retrieved | **2026-07-28T14:35Z**, read-only public fetch over HTTPS |

URL template:

```
https://raw.githubusercontent.com/usnistgov/ACVP-Server/2972def23bf9f3680c2c531561ed9bdd0f1086ad/gen-val/json-files/ML-DSA-<mode>-FIPS204/internalProjection.json
```

| mode | upstream bytes | upstream SHA-256 |
| --- | --- | --- |
| keyGen | 882 437 | `e67ee6540d40e11506c3c4e3b1f79fc1cefcd49820db99fc61f87cc8ba463baf` |
| sigGen | 8 971 659 | `72dcaf5f69853ca267ccd16af9cb40949786aca0fcfbf05d1ebeba132b93af22` |
| sigVer | 4 498 843 | `a41362abd3391b4858cf5d04556b6662881b0ac90eebf886c5c7271b0baf69d5` |

### Why this pin and not the one `fips204` vendors

`fips204 =0.4.6` vendors ACVP files pinned to `usnistgov/ACVP-Server` commit
`65370b861b96efd30dfe0daae607bde26a78a5c8` (2024-08-15). That pin is
deliberately **not** reused, for two reasons D31 §4a and §4b set out:

1. Those files validate *`fips204`*. Our primary is **`ml-dsa =0.1.1`**, and
   `fips204` agreeing with NIST says nothing about `ml-dsa`. That distinction
   is the entire point of the decision.
2. The 2024 file has no external-interface groups and no `context` field, so
   it can only validate `Sign_internal`. Row 13 — antseal's actual call,
   `sign_deterministic(M, ctx)` — would have dropped to T1. The 2026 pin is
   what makes Branch A available.

## Committed derivatives

| file | bytes | SHA-256 | ML-DSA-65 cases |
| --- | --- | --- | --- |
| `ml-dsa-65-keyGen.json` | 304 369 | `7757961205de79774093e6afd8fcd5a5d51fcf864edb8a707bf93b9ea69499e9` | 25 |
| `ml-dsa-65-sigGen.json` | 1 365 574 | `106ee7ea7e1b31393ef9ec060ab3853382d70bd491e05e6f86c8902d067b954f` | 60 |
| `ml-dsa-65-sigVer.json` | 573 329 | `fec5a9308461c08d41331638d133c6c12d2954f7ac615d595c822138e481fc1a` | 30 |

**115 cases, 2 243 272 bytes total**, derived 2026-07-28T14:50Z.

### Filter expression

```python
keep  = parameterSet == "ML-DSA-65"
        and preHash != "preHash"      # not HashML-DSA
        and externalMu is not True    # message, not precomputed mu
drop  = {"sigGen": ("pk",), "sigVer": ("sk",)}   # provably unused by the harness
```

No case is dropped — all 115 for the interfaces antseal uses are committed.
Two fields are, both redundant; `filter_acvp.py`'s docstring gives the full
reasoning and the size arithmetic behind it. D31 §5 estimated ≈750 KB from the
smaller 2024 file; the 2026 file is richer, which is why the real figure is
2.2 MB.

## Re-deriving the committed bytes

```sh
mkdir -p /tmp/acvp && cd /tmp/acvp
BASE=https://raw.githubusercontent.com/usnistgov/ACVP-Server/2972def23bf9f3680c2c531561ed9bdd0f1086ad/gen-val/json-files
for m in keyGen sigGen sigVer; do
  curl -sSL -o "ML-DSA-$m-FIPS204.internalProjection.json" \
       "$BASE/ML-DSA-$m-FIPS204/internalProjection.json"
done
sha256sum *.json      # must match the upstream SHA-256 column above
python3 "$REPO"/testdata/acvp/filter_acvp.py --source-dir /tmp/acvp --check
```

`--check` exits 0 on byte equality with all three committed subsets.

## What consumes it

`crates/antseal-core/tests/acvp_ml_dsa.rs`, in the ordinary `test` lane — no
new CI job and no network, because the subsets are committed. D31 §6b.

## Retention

Retained forever, like any other frozen fixture. A newer ACVP release may be
*added* as a second pinned subset; this one is never replaced, because it is
the evidence that the v1 freeze was clean.
