#!/usr/bin/env python3
"""Q41 — enforce the provenance digests of externally-sourced fixtures, offline.

Some committed test data did not originate in this repository: the NIST ACVP
ML-DSA-65 subsets and the Unicode ``NormalizationTest`` sample. D31
consequence 6 calls that out as a distinct hazard — *"the first committed test
data in the repo whose provenance is external and unverifiable from the tree
alone"* — and requires that **a missing or stale PROVENANCE.md is a red lane,
not a documentation nit.**

Q11 wrote the provenance records and the re-derivation scripts. It did not
wire anything that checks them. Until this file existed, every one of those
digests lived in prose that nothing read: the fixtures were the T0 anchors
under `docs/testing/cross-check.md` rows 10, 12 and 13, and an edit to any of
them would have changed what "checked against NIST" meant while every lane
stayed green.

Why the digests are read out of the prose
-----------------------------------------
The obvious alternative — a second ``EXTERNAL.sha256`` manifest beside the
fixtures — puts the same fact in two places, and the failure it invites is the
manifest and the prose disagreeing while both look authoritative.

So this checker **parses the digests out of PROVENANCE.md itself**. The
consequence is the one D31 asked for, in all three directions:

* fixture edited, prose not → red (the bytes no longer match the claim);
* prose edited, fixture not → red (same comparison, other operand);
* both edited together → green, and the diff shows a provenance change
  explicitly, which is what a reviewed, deliberate update should look like.

Offline by construction. Upstream is never contacted: what is enforced is that
the committed bytes are the bytes the record claims they are. The *upstream*
digests in those same documents cannot be checked without the network and are
deliberately not — they are the audit trail for a human re-derivation
(``filter_acvp.py --check``, ``filter_normalization_test.py --check``), and
this checker only asserts that such a trail is present.

Discovery, not wiring
---------------------
An external-fixture directory is **defined** as a directory under ``testdata/``
containing a ``PROVENANCE.md``. There is no hard-coded list, so
``testdata/anchors/`` — reserved for M2's recorded OTS and TSA material — is
enforced the moment it gains a provenance record, with no edit here.

That definition has one hole, and closing it is what ``REQUIRED_DIRS`` is for:
**deleting a ``PROVENANCE.md`` would remove its directory from discovery
entirely**, un-enforcing every fixture in it while the lane stayed green. The
self-test found exactly that. So discovery may return a *superset* of
``REQUIRED_DIRS`` — a new external directory needs no wiring — but never a
subset. It is the same must-exist device ``FROZEN.sha256`` uses: a checker can
only fail on what it finds, so the set of things it must find is written down
separately.

Within such a directory every regular file is either an auxiliary
(``PROVENANCE.md``, ``README.md``, ``*.py`` derivation scripts) or a
**fixture**, and every fixture must carry a digest claim. That roster rule is
the part that actually holds: without it this would enforce only what someone
remembered to register, and a fourth ACVP subset dropped in beside the other
three would be unguarded.

What this cannot do
-------------------
A directory of externally-sourced bytes with no ``PROVENANCE.md`` at all is
invisible to discovery — it simply is not an external-fixture directory as far
as this checker knows. Nothing automatic can distinguish "fixture we generated"
from "fixture we downloaded" by inspection. That remains a review matter, and
``testdata/README.md``'s per-directory ownership table is where it is caught.

When an external source legitimately changes
--------------------------------------------
**Never in place.** Both provenance records and ``docs/testing/cross-check.md``
§6 already state the retention rule: the committed subset is *the evidence that
this freeze was clean*, so a newer upstream release is **added** as a second
pinned subset, never substituted for the first. Concretely:

1. Fetch the new upstream and check its digest by hand against the new
   record's upstream row (network, one-off, outside CI).
2. Re-run the directory's filter script to derive the new subset under a
   **new filename** that names its version.
3. Append rows to ``PROVENANCE.md`` for the new file: its SHA-256 and its
   byte count. Leave every existing row and file untouched.
4. Point the consumer at whichever subset it should use. This lane then
   enforces both, forever.

The single case where an existing row may move is a **correction** — the
recorded digest never matched the committed bytes. That is a reviewed commit
on its own, and its message has to say which of the two was wrong, because
"the digest was updated to match" and "the fixture was restored to match" are
opposite events that look identical in a diff.

Exit codes: ``0`` every claim held · ``1`` a mismatch, a missing claim, or a
self-test breach.
"""

from __future__ import annotations

import argparse
import hashlib
import pathlib
import re
import shutil
import sys
import tempfile

PROVENANCE = "PROVENANCE.md"

# The must-exist list. Discovery finds external-fixture directories by their
# PROVENANCE.md, which means deleting one would silently retire its fixtures
# from enforcement — a checker cannot fail on what it does not find. These
# must be discovered every run.
#
# ADDING a directory here is optional (discovery picks new ones up on its
# own). REMOVING one is a deliberate edit, and the only legitimate reason is
# that the fixtures themselves are gone — which the retention rule in
# `docs/testing/cross-check.md` §6 says never happens to a frozen fixture.
REQUIRED_DIRS = ("testdata/acvp", "testdata/unicode")

# Files that are *about* the fixtures rather than fixtures themselves. A file
# that is none of these must carry a digest claim.
AUXILIARY_NAMES = frozenset({PROVENANCE, "README.md"})
AUXILIARY_SUFFIXES = frozenset({".py"})

SHA256_TOKEN = re.compile(r"\b([0-9a-f]{64})\b")

# "304 369" and "1 365 574" — the records group thousands with an ordinary
# ASCII space, so a size cell is digits and spaces only.
SIZE_CELL = re.compile(r"^\s*([0-9][0-9 ]*)\s*(?:bytes)?\s*$")

# A provenance record must say where the bytes came from. Any https URL
# satisfies it: the ACVP raw.githubusercontent template, the unicode.org path,
# or (at M2) a TSA endpoint for a recorded token.
ORIGIN_URL = re.compile(r"https://\S+")


class Mismatch(Exception):
    """One provenance claim failed. `kind` identifies it for the self-test."""

    def __init__(self, kind: str, where: str, detail: str) -> None:
        super().__init__(f"{where}: {detail}")
        self.kind = kind
        self.where = where
        self.detail = detail


# ── parsing PROVENANCE.md ──────────────────────────────────────────────────


def _cells(line: str) -> list[str]:
    """The cells of a markdown table row, or [] if the line is not one."""
    stripped = line.strip()
    if not stripped.startswith("|"):
        return []
    return [cell.strip() for cell in stripped.strip("|").split("|")]


def _unbacktick(cell: str) -> str:
    return cell.replace("`", "").replace("*", "").strip()


def _table_block(lines: list[str], index: int) -> list[str]:
    """The contiguous run of table rows containing line `index`."""
    start = index
    while start > 0 and _cells(lines[start - 1]):
        start -= 1
    end = index
    while end + 1 < len(lines) and _cells(lines[end + 1]):
        end += 1
    return lines[start : end + 1]


def claim_for(text: str, basename: str, where: str) -> tuple[str, int | None]:
    """Find `basename`'s digest claim, and its size claim if one is recorded.

    Two table shapes are recognised, because the two existing records use
    both and a checker that only understood one would quietly enforce half
    the tree:

    * **row-per-file** (``testdata/acvp/``) — one row carrying the filename,
      its byte count and its digest;
    * **key/value** (``testdata/unicode/``) — a table whose rows are
      ``| file | … |``, ``| size | … |``, ``| SHA-256 | … |``.

    A record that uses neither shape fails loudly rather than passing with no
    claim found. Restructuring a provenance document so its digest is no
    longer locatable is a provenance regression, not a formatting choice.
    """
    lines = text.splitlines()
    found: list[tuple[str, int | None]] = []

    for index, line in enumerate(lines):
        cells = _cells(line)
        if not cells:
            continue
        if not any(_unbacktick(cell) == basename for cell in cells):
            continue

        # Shape A: the digest is on this very row.
        same_row = SHA256_TOKEN.findall(line)
        if same_row:
            found.append((same_row[0], _size_on_row(cells)))
            continue

        # Shape B: look through the rest of this table block for labelled
        # rows. "upstream" rows are explicitly refused — they describe bytes
        # we do not hold and cannot check offline.
        digest: str | None = None
        size: int | None = None
        for row in _table_block(lines, index):
            row_cells = _cells(row)
            if len(row_cells) < 2:
                continue
            label = _unbacktick(row_cells[0]).lower()
            if "upstream" in label:
                continue
            value = row_cells[1]
            if "sha-256" in label or "sha256" in label:
                token = SHA256_TOKEN.search(value)
                if token:
                    digest = token.group(1)
            elif label in ("size", "bytes"):
                size = _parse_size(value)
        if digest is not None:
            found.append((digest, size))

    if not found:
        raise Mismatch(
            "unclaimed",
            f"{where}::{basename}",
            "no SHA-256 claim in PROVENANCE.md. Every non-auxiliary file in an "
            "external-fixture directory must be pinned there — a fixture whose bytes "
            "came from outside this repo and whose digest is recorded nowhere is a "
            "fixture an edit can change silently.",
        )
    digests = {digest for digest, _ in found}
    if len(digests) > 1:
        raise Mismatch(
            "ambiguous",
            f"{where}::{basename}",
            f"PROVENANCE.md records {len(digests)} different digests for one file "
            f"({sorted(digests)}) — the record contradicts itself",
        )
    return found[0]


def _size_on_row(cells: list[str]) -> int | None:
    for cell in cells[1:]:
        if SHA256_TOKEN.search(cell):
            continue
        parsed = _parse_size(cell)
        if parsed is not None:
            return parsed
    return None


def _parse_size(cell: str) -> int | None:
    match = SIZE_CELL.match(_unbacktick(cell))
    if match is None:
        return None
    digits = match.group(1).replace(" ", "")
    return int(digits) if digits else None


# ── the enforcement pass ───────────────────────────────────────────────────


def external_dirs(root: pathlib.Path) -> list[pathlib.Path]:
    return sorted(p.parent for p in root.glob(f"testdata/*/{PROVENANCE}"))


def is_fixture(path: pathlib.Path) -> bool:
    return path.name not in AUXILIARY_NAMES and path.suffix not in AUXILIARY_SUFFIXES


def check_dir(directory: pathlib.Path, root: pathlib.Path, verbose: bool = True) -> tuple[int, int]:
    """Enforce one external-fixture directory. Returns (fixtures, upstream refs)."""
    where = _rel(root, directory)
    record = directory / PROVENANCE
    try:
        text = record.read_text(encoding="utf-8")
    except OSError as exc:
        raise Mismatch("missing-record", where, f"cannot read {PROVENANCE}: {exc}") from exc

    # A record that never says where the bytes came from is not a provenance
    # record. D31 consequence 6: this is the whole reason the file exists.
    origins = ORIGIN_URL.findall(text)
    if not origins:
        raise Mismatch(
            "no-origin",
            where,
            f"{PROVENANCE} records no https:// source. External fixtures must name "
            "where they came from, or the digests below pin bytes of unknown origin.",
        )

    fixtures = sorted(p for p in directory.iterdir() if p.is_file() and is_fixture(p))
    if not fixtures:
        raise Mismatch(
            "empty",
            where,
            f"{PROVENANCE} exists but the directory holds no fixture — a provenance "
            "record guarding nothing is rot, not coverage",
        )

    for path in fixtures:
        claimed, claimed_size = claim_for(text, path.name, where)
        data = path.read_bytes()
        actual = hashlib.sha256(data).hexdigest()
        if actual != claimed:
            raise Mismatch(
                "digest",
                f"{where}/{path.name}",
                f"SHA-256 is {actual}\n"
                f"        but {PROVENANCE} claims {claimed}.\n"
                "        Either the committed bytes changed or the record did. Decide which "
                "is wrong before\n"
                "        touching either — see this script's header for the update procedure.",
            )
        if claimed_size is not None and claimed_size != len(data):
            raise Mismatch(
                "size",
                f"{where}/{path.name}",
                f"is {len(data)} bytes but {PROVENANCE} claims {claimed_size}",
            )
        if verbose:
            print(f"OK    {where}/{path.name}: {len(data)} bytes, sha256 {actual[:16]}…")

    return len(fixtures), len(origins)


def _rel(root: pathlib.Path, path: pathlib.Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


def run_check(root: pathlib.Path, quiet: bool = False) -> int:
    directories = external_dirs(root)
    if not directories:
        if not quiet:
            print(
                f"FAIL  no testdata/*/{PROVENANCE} found. Either discovery is broken or the "
                "external-fixture\n"
                "      records were deleted; in both cases this checker would pass "
                "vacuously.",
                file=sys.stderr,
            )
        return 1

    # The must-exist guard, before anything is hashed: a directory that lost
    # its PROVENANCE.md is invisible to discovery, so its absence has to be
    # detected against the written-down list rather than against the tree.
    discovered = {_rel(root, d) for d in directories}
    missing = [name for name in REQUIRED_DIRS if name not in discovered]
    if missing:
        if not quiet:
            print(
                f"FAIL  required external-fixture director(ies) not discovered: {missing}\n"
                f"      Each must hold a {PROVENANCE}. Without one its fixtures are "
                "un-enforced and this\n"
                "      lane cannot see them at all. If the fixtures were genuinely "
                "retired, remove the entry\n"
                "      from REQUIRED_DIRS in this script and say why in the commit.",
                file=sys.stderr,
            )
        return 1

    fixtures = 0
    origins = 0
    for directory in directories:
        try:
            count, urls = check_dir(directory, root, verbose=not quiet)
        except Mismatch as exc:
            if not quiet:
                print(f"FAIL  {exc}", file=sys.stderr)
            return 1
        fixtures += count
        origins += urls

    if not quiet:
        print(
            f"\nprovenance OK: {fixtures} externally-sourced fixture(s) across "
            f"{len(directories)} directory(ies) match their PROVENANCE.md digests, "
            f"{origins} recorded upstream reference(s) (not checked — offline lane)"
        )
    return 0


# ── --self-test ────────────────────────────────────────────────────────────
#
# D31 §11 item 6. Every enforced claim gets its own planted fault, in a copy
# of testdata/ under a temp directory — the working tree is never written to,
# because a self-test that can leave the repo dirty on a crash is a worse
# hazard than the one it guards.


def _plant_mutate_fixture(stage: pathlib.Path) -> None:
    victim = _first_fixture(stage)
    data = bytearray(victim.read_bytes())
    data[0] ^= 0x01
    victim.write_bytes(bytes(data))


def _plant_edit_size(stage: pathlib.Path) -> None:
    """Break only the SIZE claim.

    Truncating the fixture would move the digest too, and `digest` would fire
    first — which is correct behaviour but proves nothing about the size
    claim. The isolating fault is on the record's side.
    """
    victim = _first_fixture(stage)
    record = victim.parent / PROVENANCE
    text = record.read_text(encoding="utf-8")
    size = len(victim.read_bytes())
    grouped = f"{size:,}".replace(",", " ")
    for rendering in (grouped, str(size)):
        if rendering in text:
            record.write_text(text.replace(rendering, "1", 1), encoding="utf-8")
            return
    raise AssertionError(f"no size cell for {victim.name} to corrupt in {record}")


def _plant_edit_digest(stage: pathlib.Path) -> None:
    """Edit the digest CLAIMED FOR A COMMITTED FIXTURE, not the first in the file.

    `testdata/acvp/PROVENANCE.md` records the *upstream* digests first, and
    those are deliberately unenforceable offline — flipping one is correctly
    green, and a self-test aimed there would prove nothing. This bug was real
    and the self-test caught it.
    """
    victim = _first_fixture(stage)
    record = victim.parent / PROVENANCE
    text = record.read_text(encoding="utf-8")
    claimed, _ = claim_for(text, victim.name, str(record))
    flipped = ("1" if claimed[0] == "0" else "0") + claimed[1:]
    record.write_text(text.replace(claimed, flipped, 1), encoding="utf-8")


def _plant_drop_claim(stage: pathlib.Path) -> None:
    victim = _first_fixture(stage)
    record = victim.parent / PROVENANCE
    kept = [
        line
        for line in record.read_text(encoding="utf-8").splitlines()
        if not (SHA256_TOKEN.search(line) and victim.name in line)
    ]
    record.write_text("\n".join(kept) + "\n", encoding="utf-8")


def _plant_unclaimed_file(stage: pathlib.Path) -> None:
    (_first_record(stage).parent / "smuggled.json").write_bytes(b"{}\n")


def _plant_strip_origin(stage: pathlib.Path) -> None:
    record = _first_record(stage)
    text = record.read_text(encoding="utf-8")
    record.write_text(ORIGIN_URL.sub("REDACTED", text), encoding="utf-8")


def _plant_delete_record(stage: pathlib.Path) -> None:
    _first_record(stage).unlink()


def _plant_delete_everything(stage: pathlib.Path) -> None:
    for record in stage.glob(f"testdata/*/{PROVENANCE}"):
        record.unlink()


# `must-exist` and `discovery` faults are caught by run_check's guards rather
# than by a Mismatch, so they are dispatched differently below.
FAULTS = (
    ("digest", "one fixture byte flipped", _plant_mutate_fixture),
    ("digest", "the recorded digest edited instead", _plant_edit_digest),
    ("size", "the recorded byte count edited", _plant_edit_size),
    ("unclaimed", "a fixture's digest row deleted", _plant_drop_claim),
    ("unclaimed", "an unrecorded fixture added", _plant_unclaimed_file),
    ("no-origin", "the upstream URL stripped", _plant_strip_origin),
    ("must-exist", "one PROVENANCE.md deleted", _plant_delete_record),
    ("discovery", "every PROVENANCE.md deleted", _plant_delete_everything),
)

WHOLE_RUN_FAULTS = frozenset({"must-exist", "discovery"})


def _first_record(stage: pathlib.Path) -> pathlib.Path:
    return sorted(stage.glob(f"testdata/*/{PROVENANCE}"))[0]


def _first_fixture(stage: pathlib.Path) -> pathlib.Path:
    directory = _first_record(stage).parent
    return sorted(p for p in directory.iterdir() if p.is_file() and is_fixture(p))[0]


def run_self_test(root: pathlib.Path) -> int:
    if run_check(root, quiet=True) != 0:
        print(
            "FAIL  self-test: the unmutated tree already fails, so every red below "
            "would be noise. Run --check for the reason.",
            file=sys.stderr,
        )
        return 1
    print("OK    control: the committed tree passes")

    status = 0
    seen: set[str] = set()
    for kind, label, plant in FAULTS:
        with tempfile.TemporaryDirectory() as tmp:
            stage = pathlib.Path(tmp)
            shutil.copytree(root / "testdata", stage / "testdata")
            plant(stage)

            if kind in WHOLE_RUN_FAULTS:
                # A deleted record removes its directory from discovery
                # altogether, so no per-directory check can ever see it.
                # run_check's must-exist / discovery guards are what must
                # fire, and they raise no Mismatch to inspect.
                if run_check(stage, quiet=True) == 0:
                    print(f"FAIL  {kind} {label}: stayed GREEN", file=sys.stderr)
                    status = 1
                else:
                    print(f"OK    {kind} {label}: caught")
                    seen.add(kind)
                continue

            try:
                for directory in external_dirs(stage):
                    check_dir(directory, stage, verbose=False)
            except Mismatch as exc:
                if exc.kind == kind:
                    print(f"OK    {kind} {label}: caught")
                    seen.add(kind)
                else:
                    print(
                        f"FAIL  {kind} {label}: caught as {exc.kind} instead — {exc.detail}",
                        file=sys.stderr,
                    )
                    status = 1
            else:
                print(
                    f"FAIL  {kind} {label}: stayed GREEN — that claim is not enforced",
                    file=sys.stderr,
                )
                status = 1

    required = {kind for kind, _, _ in FAULTS}
    missing = sorted(required - seen)
    if missing:
        print(f"FAIL  self-test: nothing proved {missing}", file=sys.stderr)
        status = 1
    if status == 0:
        print(
            f"\nself-test PASSED: {len(required)} claim classes each observed failing on "
            "their own planted fault, in a temp copy; the working tree was never written to"
        )
    return status


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--check", action="store_true", help="enforce every provenance digest (the default)"
    )
    parser.add_argument(
        "--self-test", action="store_true", dest="self_test", help="prove the checker can go red"
    )
    args = parser.parse_args()

    root = pathlib.Path(__file__).resolve().parent.parent
    if args.self_test:
        return run_self_test(root)
    return run_check(root)


if __name__ == "__main__":
    raise SystemExit(main())
