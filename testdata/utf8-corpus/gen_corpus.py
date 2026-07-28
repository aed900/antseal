#!/usr/bin/env python3
"""Regenerate the UTF-8 canonicalization corpus (tasks/G.md G3).

Independent reference implementation of canonicalization v1: the frozen
five-stage pipeline of decisions D20 + D21 (docs/decisions/), built from
Python stdlib `unicodedata` only — no Rust code path shared, a different NFC
table lineage — so the committed goldens double as a cross-implementation
check of `antseal_core::canon` (MVP-SPEC.md lines 83, 121, 170).

ALL FIXTURES ARE NON-SECRET, FIXED, PUBLIC TEST DATA (project rule 6):
public text only, no secret material of any kind.

Writes `input/<name>` (exact input bytes) and `expected/<name>` (exact
canonical bytes) pairs. Consumed by
`crates/antseal-core/tests/utf8_corpus.rs`, whose test names carry the
reserved `corpus_` marker so the three-OS CI lane proves cross-platform byte
stability (`.github/workflows/ci.yml`; `.gitattributes` keeps the bytes
checkout-stable).

Committed fixtures are frozen at Q6 and retained forever
(docs/dependency-policy.md §4): a byte change here is a format event,
justified explicitly, never a silent regeneration. Run only to *verify*:

    python3 gen_corpus.py --check

## Fixture-authoring rule

**Every non-ASCII scalar is written as an explicit `\\uXXXX` / `\\UXXXXXXXX`
escape.** Frozen fixtures must be byte-unambiguous in source: a literal BOM,
ZWJ, or combining mark is invisible in review, may be silently normalized by
an editor, and would make the intended input unverifiable.

## Independent-oracle provenance

Stage 4 (NFC) uses this interpreter's `unicodedata` table, which is NOT
Unicode 17.0.0 (the pinned crate's version, D25) on most interpreters. That
is sound *because* every NFC-sensitive fixture uses only characters assigned
in Unicode <= 6.0: the Unicode Normalization Stability Policy guarantees the
NFC form of an already-assigned character can never change in a later version
(no canonical decomposition may be added to an assigned character, and
combining classes are immutable). Characters assigned after this
interpreter's table would be unsafe here — see NFC_SAFE_FLOOR.

### The T0 anchor (D31 row 10)

The paragraph above is a *reasoned* argument that this interpreter's table is
an exact oracle. D31 section 1 is blunt about what a reasoned argument is
worth: a T1 re-implementation catches transcription bugs but never a shared
misreading, and only an external oracle closes that gap. So `--check` also
replays the Unicode Consortium's own conformance data — the NFC column of
`NormalizationTest.txt` 17.0.0, the exact version D25 pins — from
`testdata/unicode/`. See that directory's PROVENANCE.md.

**D31 section 3 asked for `assert unicodedata.unidata_version == '17.0.0'`
here. That assertion is not satisfiable and is deliberately not implemented.**
No released CPython embeds Unicode 17.0.0: 3.11 has 14.0.0, 3.12 has 15.0.0,
3.13 has 15.1.0, 3.14 has 16.0.0 — and D31's own CI job pins Python 3.12. The
assertion would have made the cross-check lane permanently red on the very
runner D31 specifies for it, and it would have thrown away the stability-policy
argument above, which is the thing that actually makes the oracle sound.

What D31 was reaching for — "without the version assertion the different-NFC-
table-lineage claim is unverified" — is met the right way instead:

- NFC_SAFE_FLOOR still bounds the fixtures (a genuinely ancient table fails);
- the running `unidata_version` is *recorded* in every verdict line, so the
  table lineage is never a silent variable;
- and the conformance replay is the real anchor. It skips lines whose scalars
  the running interpreter does not know (their expected NFC legitimately
  differs there) and enforces NORMALIZATION_TEST_MIN_LINES on the number
  actually executed, so a stale interpreter or a truncated file fails the lane
  rather than passing it vacuously.

Stage 1 (lossy decode) relies on CPython's UTF-8 `replace` handler emitting
one U+FFFD per *maximal subpart* (Unicode section 3.9) — the same rule D20
froze and Rust's `String::from_utf8_lossy` implements. Verified class by
class against the pinned crate by the Rust suite: every invalid-UTF-8 golden
is an executed cross-check of the two decoders, not an assumption.
"""

import argparse
import pathlib
import sys
import unicodedata

# Every NFC-sensitive fixture stays at or below this Unicode version, so the
# Normalization Stability Policy makes this interpreter's table an exact
# oracle for the pinned Unicode 17.0.0 table (see module docstring).
NFC_SAFE_FLOOR = (6, 0)

HERE = pathlib.Path(__file__).resolve().parent

# The T0 anchor: Unicode's own NFC conformance column (D31 row 10). Provenance,
# the filter that produced the sample, and the interpreter-version caveat are
# in testdata/unicode/PROVENANCE.md.
NORMALIZATION_TEST = HERE.parent / "unicode" / "NormalizationTest-17.0.0-sample.txt"

# A floor on lines actually executed. The runner skips lines whose scalars the
# running interpreter does not know, which is correct but is also exactly how
# this check could rot into a no-op: a very old table, or a truncated sample,
# would skip everything and report a cheerful zero failures. 1 200 is
# comfortably under the 1 537 executed on the oldest interpreter this project
# supports (CPython 3.11, Unicode 14.0.0 — the worst case, since a newer table
# knows strictly more scalars and so skips strictly fewer) and far above zero.
NORMALIZATION_TEST_MIN_LINES = 1200

BOM = "\ufeff"  # leading run stripped (D21), interior preserved as ZWNBSP
ZWJ = "\u200d"  # zero-width joiner (emoji sequences)


def canonicalize(raw: bytes) -> bytes:
    """Canonicalization v1 over arbitrary bytes — D21's frozen pipeline.

    Total, deterministic, idempotent. Mirrors
    `antseal_core::canon::canonicalize`: strict decode when the input is
    valid UTF-8, else the lossy (D20 `--force-text`) decode — which on valid
    input is byte-identical, so one function covers both modes.
    """
    # Stage 1 — decode (strict when possible; lossy U+FFFD maximal subparts
    # otherwise, D20).
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        text = raw.decode("utf-8", "replace")

    # Stage 2 — strip ALL leading U+FEFF (the contiguous leading run, D21).
    # Interior U+FEFF is content (ZWNBSP) and survives.
    text = text.lstrip(BOM)

    # Stage 3 — EOL, one pass: CR LF -> LF, then any remaining lone CR -> LF
    # (so CR CR LF -> LF LF, D21).
    text = text.replace("\r\n", "\n").replace("\r", "\n")

    # Stage 4 — NFC under the recorded Unicode version (D25; see the
    # provenance note on why this interpreter's table is an exact oracle).
    text = unicodedata.normalize("NFC", text)

    # Stage 5 — encode UTF-8, no BOM prepended.
    return text.encode("utf-8")


# ---------------------------------------------------------------------------
# NFD/NFC convergence pairs: (basename, NFD-side text, NFC-side text).
#
# The Rust suite requires both halves of every pair to exist and to share one
# golden — that shared golden IS the convergence assertion. All scalars are
# assigned in Unicode <= 6.0 (oracle-safety, above).
# ---------------------------------------------------------------------------
_PAIRS: list[tuple[str, str, str]] = [
    # Latin: e + COMBINING ACUTE (ccc 230), i + COMBINING DIAERESIS (ccc 230).
    (
        "latin",
        "cafe\u0301 nai\u0308ve\n",
        "caf\u00e9 na\u00efve\n",
    ),
    # Hangul: conjoining jamo <-> precomposed syllables. NFC composes these
    # algorithmically (Unicode 3.12), a different code path from the
    # composition table exercised by the other pairs.
    #   HAN  = U+1112 HIEUH + U+1161 A + U+11AB NIEUN   -> U+D55C
    #   GEUL = U+1100 KIYEOK + U+1173 EU + U+11AF RIEUL -> U+AE00
    (
        "hangul",
        "\u1112\u1161\u11ab\u1100\u1173\u11af\n",
        "\ud55c\uae00\n",
    ),
    # Vietnamese stacked diacritics with DIFFERENT combining classes. The
    # second syllable presents them in non-canonical order (U+0302 ccc 230
    # before U+0323 ccc 220), so canonical ordering must reorder them before
    # composition can reach U+1EC7 — this pair pins canonical ordering, not
    # just composition.
    #   b + e+0302+0301 (both ccc 230, order significant) -> U+1EBF
    #   l + e+0302+0323 (must reorder to 0323, 0302)      -> U+1EC7
    (
        "vietnamese",
        "be\u0302\u0301p le\u0302\u0323\n",
        "b\u1ebfp l\u1ec7\n",
    ),
    # Hebrew points presented out of canonical order: SHIN + SHIN DOT
    # (U+05C1, ccc 24) + QAMATS (U+05B8, ccc 18) must reorder to QAMATS then
    # SHIN DOT. No composition applies (the Hebrew presentation form U+FB2A
    # is a composition exclusion), so this isolates reordering alone.
    (
        "hebrew-reorder",
        "\u05e9\u05c1\u05b8\u05dc\u05d5\u05dd\n",
        "\u05e9\u05b8\u05c1\u05dc\u05d5\u05dd\n",
    ),
]


# ---------------------------------------------------------------------------
# Fixtures: (name, input bytes, what this fixture pins).
# ---------------------------------------------------------------------------
FIXTURES: list[tuple[str, bytes, str]] = [
    # --- degenerate / identity ---
    ("empty", b"", "zero-length input -> zero-length canonical output"),
    (
        "already-canonical",
        b"First line.\nSecond line.\n",
        "input already at the canonical fixed point -> identity",
    ),
    (
        "no-trailing-newline",
        b"no newline at end of file",
        "an unterminated final line stays unterminated (no newline invented)",
    ),
    (
        "whitespace-only-lines",
        b"a\n   \n\t\n \t \nb\n",
        "canonicalization never trims whitespace (D22 blankness is G6's rule, not the pipeline's)",
    ),
    (
        "nul-and-controls",
        b"a\x00b\x0bc\x0cd\x7fe\n",
        "NUL/VT/FF/DEL are ordinary valid-UTF-8 content: detection is UTF-8 validity alone, "
        "and only CR/CRLF are EOL-normalized (VT and FF are not)",
    ),
    # --- EOL (D21 stage 3) ---
    ("crlf", b"line one\r\nline two\r\n", "CRLF -> LF"),
    ("lone-cr", b"old mac line one\rline two\r", "lone CR -> LF"),
    (
        "cr-cr-lf",
        b"a\r\r\nb\n",
        "D21 pin: CR CR LF -> LF LF (one pass; a CR consumes only an immediately following LF)",
    ),
    (
        "eol-mixed",
        b"crlf\r\nlf\nlone-cr\rtrailing-crlf\r\n\r\n",
        "all three EOL forms mixed, including an empty CRLF line",
    ),
    ("lf-then-cr", b"a\n\rb\n", "LF CR (not CRLF) -> two LFs"),
    # --- BOM (D21 stage 2) ---
    ("bom-leading", (BOM + "title\n").encode(), "a single leading BOM is stripped"),
    (
        "bom-double",
        (BOM * 2 + "title\n").encode(),
        "D21 pin: ALL leading BOMs are stripped, not exactly one (the idempotence requirement)",
    ),
    (
        "bom-triple",
        (BOM * 3 + "title\n").encode(),
        "the whole contiguous leading BOM run is stripped",
    ),
    ("bom-only", BOM.encode(), "G2 corner: a BOM-only file canonicalizes to empty"),
    (
        "bom-interior",
        ("text" + BOM + "more\n").encode(),
        "interior U+FEFF is content (ZWNBSP) and is preserved",
    ),
    (
        "bom-after-lf",
        ("line\n" + BOM + "next\n").encode(),
        "a BOM after a newline is interior, not leading — preserved",
    ),
    (
        "bom-interior-blocks-composition",
        ("e" + BOM + "\u0301\n").encode(),
        "order pin: interior U+FEFF survives stage 2 AND blocks NFC composition "
        "(e + FEFF + COMBINING ACUTE does not become U+00E9)",
    ),
    (
        "bom-run-then-crlf-nfd",
        (BOM * 2 + "cafe\u0301\r\n").encode(),
        "whole pipeline in one fixture: BOM run stripped, CRLF folded, NFD composed",
    ),
    # --- invalid UTF-8: D20 lossy maximal subparts (forced-text mode) ---
    (
        "invalid-lone-continuation",
        b"a\x80b\n",
        "a lone continuation byte -> exactly one U+FFFD",
    ),
    (
        "invalid-overlong-c0-af",
        b"\xc0\xaf\n",
        "overlong 2-byte form: invalid lead byte + stray continuation -> two U+FFFD",
    ),
    (
        "invalid-surrogate-ed-a0-80",
        b"\xed\xa0\x80\n",
        "CESU-style surrogate encoding: ED forbids an A0 second byte -> three U+FFFD",
    ),
    (
        "invalid-truncated-4byte",
        b"\xf0\x9f\x98\n",
        "a truncated 4-byte sequence is ONE maximal subpart -> one U+FFFD",
    ),
    (
        "invalid-truncated-bom",
        b"\xef\xbb",
        "G2 corner: a truncated BOM (EF BB) is one maximal subpart -> a LEADING U+FFFD, "
        "which is not a BOM and so is never stripped",
    ),
    (
        "invalid-bom-then-truncated-bom",
        b"\xef\xbb\xbf\xef\xbb",
        "the leading BOM is stripped; the truncated BOM survives as U+FFFD",
    ),
    (
        "invalid-maximal-subparts",
        b"\xe1\x80\x41\xf5\x80\x80\x80\xe0\x80\x80ok\n",
        "Unicode 3.9 showcase: E1 80 (truncated, one subpart) then 'A'; F5 (invalid lead) "
        "plus three strays; E0 80 (forbidden second byte) plus a stray",
    ),
    (
        "invalid-then-crlf-and-nfd",
        b"\xffcafe\xcc\x81\r\nmore\xc2\n",
        "forced-text mode composes with the rest of the pipeline: U+FFFD, NFC composition, "
        "CRLF folding, and a truncated 2-byte sequence at line end",
    ),
    # --- scripts, emoji, breadth ---
    (
        "emoji-zwj",
        (
            "\U0001f468" + ZWJ + "\U0001f469" + ZWJ + "\U0001f467" + ZWJ + "\U0001f466"
            " \U0001f44d\U0001f3fd \U0001f1fa\U0001f1f8 \u2764\ufe0f\n"
        ).encode(),
        "ZWJ family sequence, skin-tone modifier, regional-indicator flag, VS16 heart — "
        "none have canonical decompositions, so NFC is identity and the bytes must survive exactly",
    ),
    (
        "mixed-scripts",
        (
            "\u0645\u0631\u062d\u0628\u0627 "  # Arabic (RTL)
            "\u05e9\u05b8\u05dc\u05d5\u05dd "  # Hebrew with a point (RTL)
            "\u65e5\u672c\u8a9e "  # CJK
            "\u0928\u092e\u0938\u094d\u0924\u0947 "  # Devanagari with virama
            "caf\u00e9\n"  # Latin, precomposed
        ).encode(),
        "RTL Arabic + pointed Hebrew + CJK + Devanagari + Latin on one line",
    ),
    (
        "mixed-everything",
        (BOM + "Title\r\n\r\n").encode()
        + ("Para one with cafe\u0301 and \u1112\u1161\u11ab.\r\n").encode()
        + b"Para two with a lone CR\rand \xff invalid bytes.\r\n"
        + ("Tail: \U0001f468" + ZWJ + "\U0001f469 " + BOM + " interior BOM\n").encode(),
        "breadth regression: leading BOM, CRLF, blank line, NFD Latin + Hangul jamo, lone CR, "
        "invalid byte, emoji ZWJ and an interior BOM in one realistic document",
    ),
]


def build() -> dict[str, tuple[bytes, bytes, str]]:
    """Return {name: (input bytes, expected canonical bytes, note)}."""
    fixtures = list(FIXTURES)
    for base, nfd, nfc in _PAIRS:
        fixtures.append(
            (f"pair-{base}-nfd", nfd.encode(), f"NFD half of the {base} convergence pair")
        )
        fixtures.append(
            (
                f"pair-{base}-nfc",
                nfc.encode(),
                f"NFC half of the {base} convergence pair (already canonical)",
            )
        )

    built: dict[str, tuple[bytes, bytes, str]] = {}
    for name, raw, note in fixtures:
        if name in built:
            raise SystemExit(f"duplicate fixture name: {name}")
        expected = canonicalize(raw)
        # Every golden must be a fixed point (the normative idempotence
        # property, spec line 170) — asserted here too, so a broken oracle
        # cannot mint a non-idempotent golden.
        if canonicalize(expected) != expected:
            raise SystemExit(f"oracle bug: golden for {name} is not idempotent")
        built[name] = (raw, expected, note)

    for base, _, _ in _PAIRS:
        if built[f"pair-{base}-nfd"][1] != built[f"pair-{base}-nfc"][1]:
            raise SystemExit(f"oracle bug: pair {base} does not converge")
    return built


def _scalars(field: str) -> str:
    """Decode one upstream column ('0044 0307') into a Python string."""
    return "".join(chr(int(cp, 16)) for cp in field.split())


def normalization_test_anchor() -> "tuple[int, int, list[str]]":
    """Replay the NFC column of Unicode's own conformance data (D31 row 10).

    UAX #15's conformance statement for the five-column format
    `c1;c2;c3;c4;c5` gives, for the NFC leg:

        c2 == NFC(c1) == NFC(c2) == NFC(c3)
        c4 == NFC(c4) == NFC(c5)

    Returns (executed, skipped, failures). A line is skipped when any of its
    scalars is unassigned in the running interpreter — there its expected NFC
    form legitimately differs, so asserting it would assert a falsehood. See
    testdata/unicode/PROVENANCE.md for why the remainder is exact.
    """
    if not NORMALIZATION_TEST.exists():
        return 0, 0, [f"missing conformance sample: {NORMALIZATION_TEST}"]

    executed = 0
    skipped = 0
    failures: list[str] = []
    part = "?"
    for lineno, raw in enumerate(
        NORMALIZATION_TEST.read_text(encoding="utf-8").splitlines(), start=1
    ):
        line = raw.strip()
        if line.startswith("@"):
            part = line[1:]
            continue
        if not line or line.startswith("#"):
            continue
        columns = line.split("#")[0].strip().rstrip(";").split(";")
        if len(columns) != 5:
            failures.append(f"line {lineno}: expected 5 columns, got {len(columns)}")
            continue
        try:
            c1, c2, c3, c4, c5 = (_scalars(col) for col in columns)
        except ValueError:
            failures.append(f"line {lineno}: malformed scalar list")
            continue

        if any(unicodedata.category(ch) == "Cn" for ch in c1 + c2 + c3 + c4 + c5):
            skipped += 1
            continue

        executed += 1
        for label, source, want in (
            ("NFC(c1)", c1, c2),
            ("NFC(c2)", c2, c2),
            ("NFC(c3)", c3, c2),
            ("NFC(c4)", c4, c4),
            ("NFC(c5)", c5, c4),
        ):
            got = unicodedata.normalize("NFC", source)
            if got != want:
                failures.append(
                    f"{part} line {lineno}: {label} = "
                    f"{' '.join(f'{ord(ch):04X}' for ch in got)}, expected "
                    f"{' '.join(f'{ord(ch):04X}' for ch in want)}"
                )
    return executed, skipped, failures


def run_normalization_test_anchor() -> int:
    """Report the T0 anchor's verdict. 0 = pass, 1 = fail."""
    executed, skipped, failures = normalization_test_anchor()
    version = unicodedata.unidata_version
    if failures:
        for problem in failures[:20]:
            print(f"  {problem}", file=sys.stderr)
        print(
            f"FAIL  NormalizationTest NFC anchor: {len(failures)} disagreement(s) "
            f"over {executed} executed line(s) (interpreter Unicode table {version})",
            file=sys.stderr,
        )
        return 1
    if executed < NORMALIZATION_TEST_MIN_LINES:
        print(
            f"FAIL  NormalizationTest NFC anchor executed only {executed} line(s), "
            f"below the {NORMALIZATION_TEST_MIN_LINES} floor — the sample is "
            f"truncated or this interpreter's Unicode table ({version}) is too old "
            "for the anchor to mean anything",
            file=sys.stderr,
        )
        return 1
    print(
        f"OK    NormalizationTest NFC anchor: {executed} line(s) executed, "
        f"{skipped} skipped as unassigned in Unicode {version} "
        "(T0, Unicode 17.0.0 conformance data)"
    )
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Regenerate or verify the G3 UTF-8 corpus.")
    parser.add_argument(
        "--check",
        action="store_true",
        help="verify committed fixtures byte for byte instead of writing them",
    )
    args = parser.parse_args()

    if tuple(int(p) for p in unicodedata.unidata_version.split(".")[:2]) < NFC_SAFE_FLOOR:
        print(
            f"error: interpreter Unicode table {unicodedata.unidata_version} is older than the "
            f"fixtures' {NFC_SAFE_FLOOR[0]}.{NFC_SAFE_FLOOR[1]} floor",
            file=sys.stderr,
        )
        return 2

    built = build()
    input_dir, expected_dir = HERE / "input", HERE / "expected"

    if args.check:
        # The T0 anchor runs first and unconditionally, for D31 section 6b's
        # reason applied one level down: if the NFC oracle itself disagrees
        # with Unicode, every fixture agreement below is worthless, and this
        # ordering makes that failure legible instead of showing up as 37
        # mismatched fixtures.
        bad = run_normalization_test_anchor()
        for name, (raw, expected, _) in sorted(built.items()):
            for path, want in ((input_dir / name, raw), (expected_dir / name, expected)):
                got = path.read_bytes() if path.exists() else None
                if got != want:
                    bad += 1
                    print(f"MISMATCH {path.relative_to(HERE)}", file=sys.stderr)
        on_disk = {p.name for p in input_dir.iterdir()} | {p.name for p in expected_dir.iterdir()}
        for stray in sorted(on_disk - set(built)):
            bad += 1
            print(f"STRAY {stray}", file=sys.stderr)
        if bad:
            print(f"{bad} problem(s)", file=sys.stderr)
            return 1
        print(f"OK — {len(built)} fixtures match (Unicode table {unicodedata.unidata_version})")
        return 0

    input_dir.mkdir(exist_ok=True)
    expected_dir.mkdir(exist_ok=True)
    for name, (raw, expected, note) in sorted(built.items()):
        (input_dir / name).write_bytes(raw)
        (expected_dir / name).write_bytes(expected)
        print(f"{name:38s} {len(raw):5d} -> {len(expected):5d}  {note[:56]}")
    print(f"\n{len(built)} fixtures written (Unicode table {unicodedata.unidata_version})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
