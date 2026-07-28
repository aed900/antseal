#!/usr/bin/env python3
"""Derive the committed NormalizationTest sample from Unicode's own file.

Decision D31 grades cross-check vehicles into three tiers, and the point of
this directory is tier **T0**: an external oracle whose expected values
originate outside this project *and* outside its language ecosystem. Our
canonicalization reference (`testdata/utf8-corpus/gen_corpus.py`) is a T1
re-implementation of D21's pipeline; its NFC stage is only as trustworthy as
the table behind `unicodedata.normalize`. `NormalizationTest.txt` is the
Unicode Consortium's own conformance data for exactly that stage, so running
it turns the NFC leg from T1-unanchored into T1-anchored-by-T0.

## Why a sample and not the whole file

Upstream is 2 827 429 bytes. D31 section 5 sets the size discipline for
committed external fixtures — a filtered subset with recorded provenance and
a re-derivation script, never a multi-megabyte blob of trust — and asks for
"a sample of Unicode's own NormalizationTest.txt NFC column". The rule below
is deterministic and stated so anyone can reproduce the committed bytes:

- **Parts 0, 3, 4 and 5 are kept whole** (45 + 194 + 735 + 38 = 1 012 lines).
  These are the curated parts: specific cases, the PRI #29 composition
  corners, canonical closures, and chained primary composites. They are where
  a normalizer actually breaks, and together they are small.
- **Parts 1 and 2 are sampled every `STRIDE`-th line** (the mechanical
  character-by-character and canonical-order bulk, 19 022 lines).

That yields 1 607 lines / ~279 KiB, against 2.7 MiB for the whole file.

## Usage

    python3 filter_normalization_test.py --source /path/to/NormalizationTest.txt

writes `NormalizationTest-17.0.0-sample.txt` next to this script. To audit the
committed bytes: fetch the upstream file, check its SHA-256 against
PROVENANCE.md, re-run with `--check`, and see the verdict.

This script is **not** run by CI. It needs the upstream file, which means the
network; the committed sample is what the always-on lane consumes. See
`testdata/utf8-corpus/gen_corpus.py --check`, which is the consumer.
"""

import argparse
import hashlib
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent

UNICODE_VERSION = "17.0.0"
SAMPLE = HERE / f"NormalizationTest-{UNICODE_VERSION}-sample.txt"

# Parts kept in full — the curated, high-value, small ones.
FULL_PARTS = ("Part0", "Part3", "Part4", "Part5")
# Sampling stride for the bulk parts (Part1, Part2).
STRIDE = 32


def filter_lines(text: str) -> "list[str]":
    """Apply the documented rule, preserving the `@PartN` section markers."""
    out: list[str] = []
    part: "str | None" = None
    bulk_index = 0
    for raw in text.splitlines():
        stripped = raw.strip()
        if stripped.startswith("@"):
            part = stripped.split("#")[0][1:].strip()
            bulk_index = 0
            out.append(f"@{part}")
            continue
        if not stripped or stripped.startswith("#"):
            continue
        if part is None:
            raise SystemExit("malformed source: a data line before any @Part marker")
        if part in FULL_PARTS:
            out.append(raw)
            continue
        if bulk_index % STRIDE == 0:
            out.append(raw)
        bulk_index += 1
    return out


def render(source_path: pathlib.Path, source_text: str) -> str:
    digest = hashlib.sha256(source_text.encode("utf-8")).hexdigest()
    kept = filter_lines(source_text)
    data_lines = sum(1 for line in kept if not line.startswith("@"))
    header = [
        f"# NormalizationTest.txt sample — Unicode {UNICODE_VERSION}",
        "#",
        "# DERIVED FILE. Do not hand-edit; re-derive with",
        f"#   python3 filter_normalization_test.py --source {source_path.name}",
        "# Provenance (upstream URL, SHA-256, retrieval time) is in PROVENANCE.md.",
        "#",
        f"# upstream SHA-256: {digest}",
        f"# filter: parts {'/'.join(FULL_PARTS)} whole; parts Part1/Part2 every "
        f"{STRIDE}th data line",
        f"# kept: {data_lines} data lines",
        "#",
        "# Format is upstream's (Unicode UAX #15 conformance data):",
        "#   source ; NFC ; NFD ; NFKC ; NFKD ;  # comment",
        "# antseal consumes the NFC column only (column 2), per D31 row 10.",
        "#",
        "# NON-SECRET external test data (project rule 6): Unicode Consortium",
        "# conformance vectors, not antseal key material.",
        "",
    ]
    return "\n".join(header + kept) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description="Derive the NormalizationTest sample.")
    parser.add_argument(
        "--source",
        required=True,
        type=pathlib.Path,
        help="upstream NormalizationTest.txt (see PROVENANCE.md for the URL)",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="compare the derived bytes against the committed sample instead of writing",
    )
    args = parser.parse_args()

    if not args.source.exists():
        print(f"error: no such source file: {args.source}", file=sys.stderr)
        return 2
    produced = render(args.source, args.source.read_text(encoding="utf-8"))

    if args.check:
        if not SAMPLE.exists():
            print(f"FAIL  {SAMPLE.name}: committed sample is missing", file=sys.stderr)
            return 1
        if SAMPLE.read_text(encoding="utf-8") == produced:
            print(f"OK    {SAMPLE.name} re-derives from {args.source.name}")
            return 0
        print(
            f"FAIL  {SAMPLE.name}: re-derived bytes differ from the committed sample "
            "— the source is a different Unicode release, or the filter changed",
            file=sys.stderr,
        )
        return 1

    SAMPLE.write_text(produced, encoding="utf-8")
    print(f"wrote {SAMPLE.name} ({len(produced.encode('utf-8'))} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
