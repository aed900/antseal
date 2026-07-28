#!/usr/bin/env python3
"""Checks that a documented claim is still true of the tree.

Two checks live here, and they are the same shape: something written down in
prose asserts a fact about the repository, and nothing else verifies it.

    --freeze-boundary   The D84 §7 v1-freeze-boundary rows are byte-identical
                        across every file that carries a copy (Q37).
    --matrix            Every test named by the verification-coverage
                        traceability matrix actually resolves (Q13).
    --decisions         Every decision cited in code or in a normative doc
                        resolves to a record, a registered alternative home,
                        or an open register entry; and nothing cites the
                        frozen wire registry by line number (Q57, Q58).

Run with no arguments to run every check.

Python standard library only, by deliberate choice: this runs in a CI lane
that must not acquire dependencies to tell you a document has drifted.
"""

from __future__ import annotations

import argparse
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent

# ── failure reporting ───────────────────────────────────────────────────────
# Every failure prints a GitHub-Actions error annotation AND a human sentence.
# A check that fails quietly is worse than no check, because it is trusted.


class Failures:
    def __init__(self) -> None:
        self.messages: list[str] = []

    def add(self, check: str, message: str) -> None:
        self.messages.append(f"{check}: {message}")
        print(f"::error::check-traceability [{check}] {message}", file=sys.stderr)

    def __bool__(self) -> bool:
        return bool(self.messages)


# ── check 1: the freeze-boundary rows have not drifted (Q37 / D84 §7) ───────

BEGIN = "<!-- FREEZE-BOUNDARY:BEGIN"
END = "<!-- FREEZE-BOUNDARY:END -->"

# Every file that carries a copy of D84 §7's rows. Q27's format-stability
# policy doc joins this list at M4, in Q27's own commit — a copy added
# without its lint is exactly the drift this check exists to prevent.
BOUNDARY_COPIES = [
    "tasks/Q.md",
    "docs/format/anchor-artifact-limits.md",
]

# The source of truth. Both copies are cut from here; if this section moves,
# the copies are stale by definition and the check must say so.
BOUNDARY_SOURCE = "docs/decisions/D84-anchor-artifact-limits-permanence.md"


# Q49 — a checkbox marker is gate state, not rule text.
#
# Q14's Accept requires BOTH this lint green AND every normative row ticked,
# and rows N1/N2 live *inside* the markers. `- [ ]` → `- [x]` is a byte change,
# so as written the two criteria were mutually exclusive and the gate could not
# be run at all. What this lint exists to protect is the rule *text*; the tick
# records whether the gate has verified that rule, which is per-copy state and
# legitimately differs between the decision record (which never ticks) and the
# checklist (which must).
#
# So the marker — and only the marker, and only at the head of a list item — is
# blanked on both sides before comparison. Every other byte still compares
# exactly: change one word and the check goes red. `--self-test` proves both
# halves, because a normalisation that quietly widened to "compare nothing"
# would leave this lint green forever.
CHECKBOX_MARKER = re.compile(r"^(\s*)- \[[ xX]\] ", re.MULTILINE)


def blank_gate_state(block: str) -> str:
    """Blank every checkbox marker; leave every other byte untouched."""
    return CHECKBOX_MARKER.sub(r"\1- [ ] ", block)


def extract_boundary(path: pathlib.Path) -> str | None:
    """The text between the markers, exclusive, stripped of blank edges."""
    text = path.read_text(encoding="utf-8")
    start = text.find(BEGIN)
    if start < 0:
        return None
    # Skip past the end of the BEGIN comment, wherever it closes.
    open_end = text.find("-->", start)
    if open_end < 0:
        return None
    stop = text.find(END, open_end)
    if stop < 0:
        return None
    return text[open_end + len("-->") : stop].strip("\n").strip()


def extract_source_block(path: pathlib.Path) -> str | None:
    """D84 §7's blockquote, unquoted — what the copies must equal."""
    lines = path.read_text(encoding="utf-8").splitlines()
    try:
        heading = next(
            i
            for i, line in enumerate(lines)
            if line.startswith("## 7.") and "freeze boundary" in line.lower()
        )
    except StopIteration:
        return None
    quoted: list[str] = []
    for line in lines[heading + 1 :]:
        if line.startswith(">"):
            quoted.append(line[2:] if line.startswith("> ") else line[1:])
        elif quoted and not line.strip():
            break
        elif quoted:
            break
    if not quoted:
        return None
    return "\n".join(quoted).strip()


def check_freeze_boundary(failures: Failures) -> None:
    check = "freeze-boundary"

    source_path = ROOT / BOUNDARY_SOURCE
    if not source_path.is_file():
        failures.add(check, f"the source record {BOUNDARY_SOURCE} does not exist")
        return
    source = extract_source_block(source_path)
    if source is None:
        failures.add(
            check,
            f"could not find the §7 freeze-boundary blockquote in {BOUNDARY_SOURCE} — "
            "the section was renamed or reformatted, so every copy below is unverified",
        )
        return

    seen: dict[str, str] = {}
    for relative in BOUNDARY_COPIES:
        path = ROOT / relative
        if not path.is_file():
            failures.add(check, f"{relative} does not exist but is registered as a copy")
            continue
        block = extract_boundary(path)
        if block is None:
            failures.add(
                check,
                f"{relative} has no FREEZE-BOUNDARY:BEGIN/END block — "
                "the markers were removed or renamed",
            )
            continue
        seen[relative] = block

    # Compare with gate state blanked on BOTH sides (Q49). The reported
    # difference is computed on the same blanked forms, so the message can
    # never point at a tick the comparison deliberately ignored.
    source_text = blank_gate_state(source)
    for relative, block in seen.items():
        block_text = blank_gate_state(block)
        if block_text != source_text:
            failures.add(
                check,
                f"{relative} has drifted from {BOUNDARY_SOURCE} §7. "
                "Re-cut the copy from the record; do not edit the copy in place. "
                f"First difference: {first_difference(source_text, block_text)}",
            )

    if not failures and len(seen) < 2:
        failures.add(
            check,
            f"only {len(seen)} copy of the freeze boundary was found; the check is "
            "vacuous below two copies",
        )

    if seen and all(block == source for block in seen.values()):
        print(
            f"[{check}] ok — {len(seen)} copies byte-identical to "
            f"{BOUNDARY_SOURCE} §7 ({len(source)} bytes)"
        )


def first_difference(expected: str, actual: str) -> str:
    left = expected.splitlines()
    right = actual.splitlines()
    for index in range(max(len(left), len(right))):
        want = left[index] if index < len(left) else "<missing>"
        got = right[index] if index < len(right) else "<missing>"
        if want != got:
            return f"line {index + 1}: expected {want!r}, found {got!r}"
    return "<no line differs; trailing whitespace or line endings>"


# ── check 2: every test the matrix names actually resolves (Q13) ────────────

MATRIX = "docs/testing/verification-matrix.md"

# A row's `tests` cell holds zero or more references in one of these shapes:
#   path/to/file.rs::test_name          a Rust test function
#   path/to/file.rs (doctest: line 67)  a doc-test at a known line
#   path/to/file                        a file, script or directory that must exist
REFERENCE = re.compile(r"`([^`]+)`")
RUST_TEST = re.compile(r"^(?P<path>[\w./\-]+\.rs)::(?P<name>[A-Za-z_][A-Za-z0-9_]*)$")
DOCTEST = re.compile(r"^(?P<path>[\w./\-]+\.rs) \(doctest: line (?P<line>\d+)\)$")
PLAIN_PATH = re.compile(r"^[\w./\-]+$")

ROW = re.compile(r"^\|\s*(?P<cells>.+)\s*\|$")

# Q51 — the status column is now read, not merely parsed.
#
# `--matrix` resolved every reference a row named and never looked at whether
# the row claimed to be covered at all. So a row could sit at `gap` through a
# milestone review with the lint green — which is exactly what happened: V3.4
# read `gap` for a full wave after F17/Q39/Q9 landed, and Q14's normative row
# N7 reproduced the stale claim and declared the freeze blocked by work that
# was already done.
#
# The gate: at the milestone under review, and at every milestone before it,
# every row must read `covered`. Later milestones are unconstrained — their
# crates are stubs and `deferred` is the correct answer, not a gap.
MILESTONE_ORDER = ("M0", "M1", "M2", "M3", "M4")

# The milestone under review. **This is the line a milestone review bumps.**
# It is a constant rather than a required flag on purpose: a gate that only
# runs when someone remembers to pass `--milestone` is the same unenforced
# prose this check exists to replace. `--milestone` overrides it for a one-off
# question ("would M1 pass today?").
CURRENT_MILESTONE = "M0"

# The full vocabulary, per the matrix's own "Status vocabulary" note. Anything
# else is a typo, and a typo'd status at a not-yet-gated milestone would
# otherwise be invisible until that milestone's review.
STATUS_VOCABULARY = ("covered", "gap", "deferred")

# Rows allowed to sit at a non-`covered` status inside a gated milestone, as
# `id -> (status, reason)`. Empty, and it should stay that way: an entry here
# is a milestone shipping with a known hole, which is a decision worth writing
# down rather than a lint to be silenced. Stale entries are themselves a
# failure — see `check_matrix` — so this cannot rot into a permanent mute.
ACCEPTED_NON_COVERED: dict[str, tuple[str, str]] = {}


def split_row(line: str) -> list[str] | None:
    line = line.strip()
    if not ROW.match(line):
        return None
    return [c.strip() for c in line.strip("|").split("|")]


def is_separator(cells: list[str] | None) -> bool:
    return bool(cells) and all(set(c) <= {"-", ":"} for c in cells if c is not None)


def parse_matrix(path: pathlib.Path) -> list[dict[str, str]]:
    """Every table in the file, keyed by its OWN header.

    The file holds one table per milestone section. A header is recognised by
    the separator row that must follow it, so a new table resets the header
    instead of inheriting the previous one — inheriting it is how the second
    table's header silently becomes a data row.
    """
    rows: list[dict[str, str]] = []
    header: list[str] | None = None
    lines = path.read_text(encoding="utf-8").splitlines()

    for number, line in enumerate(lines, 1):
        cells = split_row(line)
        if cells is None:
            header = None  # a non-table line ends the current table
            continue
        if is_separator(cells):
            continue
        following = split_row(lines[number]) if number < len(lines) else None
        if is_separator(following):
            header = [c.lower() for c in cells]
            continue
        if header is None or len(cells) != len(header):
            continue
        row = dict(zip(header, cells))
        row["_line"] = str(number)
        rows.append(row)
    return rows


def gated_milestones(under_review: str) -> tuple[str, ...]:
    """Every milestone at or before `under_review`.

    Cumulative on purpose: at the M1 review, M0's rows must *still* read
    covered. A gate that only looked at the current milestone would let an
    earlier one silently regress to `gap` the moment its own review passed.
    """
    if under_review not in MILESTONE_ORDER:
        raise ValueError(
            f"unknown milestone {under_review!r}; known: {', '.join(MILESTONE_ORDER)}"
        )
    return MILESTONE_ORDER[: MILESTONE_ORDER.index(under_review) + 1]


def check_matrix(failures: Failures, under_review: str = CURRENT_MILESTONE) -> None:
    check = "matrix"
    path = ROOT / MATRIX
    if not path.is_file():
        failures.add(check, f"{MATRIX} does not exist")
        return

    rows = parse_matrix(path)
    if not rows:
        failures.add(check, f"{MATRIX} contains no table rows — the check would be vacuous")
        return

    try:
        gated = gated_milestones(under_review)
    except ValueError as error:
        failures.add(check, str(error))
        return

    milestones: dict[str, int] = {}
    checked = 0
    bullets: set[str] = set()
    gate_rows = 0
    exemptions_seen: set[str] = set()

    for row in rows:
        milestone = row.get("milestone", "").strip("*` ").upper()
        milestones[milestone] = milestones.get(milestone, 0) + 1
        bullet = row.get("spec bullet", "")
        if bullet:
            bullets.add(bullet)

        # ── the status gate (Q51) ──────────────────────────────────────────
        identifier = row.get("id", "?").strip("*` ")
        status = row.get("status", "").strip("*` ").lower()
        if status not in STATUS_VOCABULARY:
            failures.add(
                check,
                f"{MATRIX}:{row['_line']} row {identifier!r} has status {status!r}, which is "
                f"not one of {', '.join(STATUS_VOCABULARY)} — see the file's own "
                "'Status vocabulary' note. A status nobody recognises is a status no gate "
                "can read.",
            )
        elif milestone in gated:
            gate_rows += 1
            accepted = ACCEPTED_NON_COVERED.get(identifier)
            if accepted is not None:
                exemptions_seen.add(identifier)
            if status != "covered" and accepted is None:
                failures.add(
                    check,
                    f"{MATRIX}:{row['_line']} row {identifier!r} ({milestone}) reads "
                    f"{status!r}, but {under_review} is under review and every row at or "
                    f"before it must read 'covered'. Either the work is genuinely missing "
                    f"— in which case the milestone is not done — or the row is stale and "
                    f"has not been updated since the work landed. Resolving it by "
                    f"registering the row in ACCEPTED_NON_COVERED needs a written reason: "
                    f"that is a milestone shipping with a known hole.",
                )
            elif accepted is not None and status == "covered":
                failures.add(
                    check,
                    f"{MATRIX}:{row['_line']} row {identifier!r} now reads 'covered' but is "
                    f"still registered in ACCEPTED_NON_COVERED as {accepted[0]!r} "
                    f"({accepted[1]}). Drop the entry — a stale exemption is how a gate "
                    "decays into a permanent mute.",
                )
            elif accepted is not None and status != accepted[0]:
                failures.add(
                    check,
                    f"{MATRIX}:{row['_line']} row {identifier!r} reads {status!r} but is "
                    f"registered in ACCEPTED_NON_COVERED as {accepted[0]!r} ({accepted[1]}). "
                    "The exemption was written for a different state; re-decide it.",
                )

        cell = row.get("tests / evidence", "")
        references = REFERENCE.findall(cell)

        # A row with no reference is only legal when it says so out loud.
        if not references:
            if "NONE" not in cell.upper():
                failures.add(
                    check,
                    f"{MATRIX}:{row['_line']} row {row.get('id', '?')!r} names no test and "
                    "does not say NONE — a blank cell reads as covered",
                )
            continue

        for reference in references:
            checked += 1
            problem = resolve(reference)
            if problem:
                failures.add(
                    check,
                    f"{MATRIX}:{row['_line']} row {row.get('id', '?')!r}: {problem}",
                )

    # A registered exemption for a row that no longer exists is as stale as one
    # for a row that is now covered, and less visible.
    for identifier, (status, reason) in ACCEPTED_NON_COVERED.items():
        if identifier not in exemptions_seen:
            failures.add(
                check,
                f"ACCEPTED_NON_COVERED registers row {identifier!r} as {status!r} "
                f"({reason}) but no such row exists at a gated milestone in {MATRIX}. "
                "Remove it.",
            )

    if not gate_rows:
        failures.add(
            check,
            f"no rows at or before {under_review} — the status gate would be vacuous. "
            "Either the milestone column stopped parsing or CURRENT_MILESTONE names a "
            "milestone this matrix has no rows for.",
        )

    if not failures:
        summary = ", ".join(f"{k}={v}" for k, v in sorted(milestones.items()))
        print(
            f"[{check}] ok — {len(rows)} rows over {len(bullets)} spec bullets, "
            f"{checked} references resolved ({summary}); status gate: all {gate_rows} "
            f"row(s) at or before {under_review} read 'covered'"
        )


def resolve(reference: str) -> str | None:
    """None if the reference resolves; a human sentence if it does not."""
    match = RUST_TEST.match(reference)
    if match:
        path = ROOT / match.group("path")
        if not path.is_file():
            return f"`{reference}` names a file that does not exist"
        name = match.group("name")
        # Match `fn name(` so a substring of a longer test name never counts.
        if not re.search(rf"\bfn\s+{re.escape(name)}\s*\(", path.read_text(encoding="utf-8")):
            return f"`{reference}` names a test that is not defined in that file"
        return None

    match = DOCTEST.match(reference)
    if match:
        path = ROOT / match.group("path")
        if not path.is_file():
            return f"`{reference}` names a file that does not exist"
        lines = path.read_text(encoding="utf-8").splitlines()
        index = int(match.group("line")) - 1
        if not 0 <= index < len(lines):
            return f"`{reference}` names line {index + 1}, past the end of the file"
        # rustdoc names a doctest by the line of its opening fence.
        if "```" not in lines[index]:
            return (
                f"`{reference}` does not point at a doc-test fence "
                f"(line {index + 1} reads {lines[index].strip()!r})"
            )
        return None

    if PLAIN_PATH.match(reference):
        if not (ROOT / reference).exists():
            return f"`{reference}` does not exist"
        return None

    return f"`{reference}` is not a recognised reference shape"


# ── entry point ─────────────────────────────────────────────────────────────


# ── check 3: cited decisions resolve, and nobody cites the registry by line ──
# Q57 + Q58. Two failures with one shape: a pointer whose target nothing
# verifies. A decision cited as normative in code with no record is an argument
# a third party cannot read; a line-number citation into a document that just
# froze is a pointer that rots on the next edit and says nothing when it does.

DECISION_DIR = "docs/decisions"

# Where the sweep looks. Normative surfaces only — TODO.md is the register
# itself and tasks/*.md are working notes, so neither is a citation site.
DECISION_SCAN = ["crates", "docs/format", "docs/testing"]
DECISION_SUFFIXES = {".rs", ".md", ".json", ".py"}

# Decisions that are recorded, but not in a file of their own. Each entry is
# the home, so "no file" is a recorded fact rather than an omission. Adding to
# this list is a deliberate act; leaving a decision out of it is a failure.
DECISIONS_HOMED_ELSEWHERE = {
    11: "docs/research/S1-ant-core-api-survey.md (address length, pinned from ant-core source)",
    12: "docs/decisions/D7-cbor-crate.md §D12 (the cross-check nominee)",
    16: "docs/research/C11-signature-probe.md §9 (the probe that decided it)",
}

# A citation is only a decision reference if the number is an allocated id.
# Without this bound the sweep reports Unicode surrogate D800 in a comment as a
# missing decision — which is how a lint teaches people to ignore it.
def allocated_decision_ids() -> set[int]:
    todo = (ROOT / "TODO.md").read_text(encoding="utf-8")
    return {int(n) for n in re.findall(r"^- \[[ x]\] \*\*D(\d+)\*\*", todo, re.M)}


def open_decision_ids() -> set[int]:
    todo = (ROOT / "TODO.md").read_text(encoding="utf-8")
    return {int(n) for n in re.findall(r"^- \[ \] \*\*D(\d+)\*\*", todo, re.M)}


def check_decisions(failures: Failures) -> None:
    check = "decisions"

    recorded = set()
    for path in (ROOT / DECISION_DIR).glob("D*.md"):
        m = re.match(r"D(\d+)-", path.name)
        if m:
            recorded.add(int(m.group(1)))

    allocated = allocated_decision_ids()
    if not allocated:
        failures.add(check, "no decision ids found in TODO.md's register — the bound is vacuous")
        return
    still_open = open_decision_ids()

    cited: dict[int, set[str]] = {}
    line_citations: list[str] = []
    for sub in DECISION_SCAN:
        base = ROOT / sub
        if not base.exists():
            continue
        for path in base.rglob("*"):
            if not path.is_file() or path.suffix not in DECISION_SUFFIXES:
                continue
            if "target" in path.parts:
                continue
            try:
                text = path.read_text(encoding="utf-8")
            except (UnicodeDecodeError, OSError):
                continue
            rel = str(path.relative_to(ROOT))
            for n in re.findall(r"\bD(\d+)\b", text):
                cited.setdefault(int(n), set()).add(rel)
            # Q58: the registry froze; a line number into it rots on any edit.
            for hit in re.findall(r"registry-v1\.(?:md|json):\d+", text):
                line_citations.append(f"{rel}: {hit}")

    for number in sorted(cited):
        if number > max(allocated):
            continue  # not an allocated id — see the bound above
        if number in recorded or number in DECISIONS_HOMED_ELSEWHERE or number in still_open:
            continue
        where = ", ".join(sorted(cited[number])[:3])
        failures.add(
            check,
            f"D{number} is cited as normative ({where}) but has no record, no "
            f"registered home in DECISIONS_HOMED_ELSEWHERE, and no open entry "
            f"in TODO.md's register",
        )

    for hit in line_citations:
        failures.add(
            check,
            f"{hit} cites the frozen wire registry by LINE NUMBER. Cite the "
            f"section instead (e.g. `registry §7.14 key 1`): the registry is "
            f"frozen, its line numbers are not, and a rotted pointer is silent",
        )

    if not failures:
        homed = len(DECISIONS_HOMED_ELSEWHERE)
        in_bound = [n for n in cited if n <= max(allocated)]
        print(
            f"[{check}] ok — {len(in_bound)} distinct decisions cited, all "
            f"resolve ({len(recorded)} have records, {homed} homed elsewhere, "
            f"{len(still_open)} still open in the register); "
            f"no line-number citations into the registry"
        )


CHECKS = {
    "freeze-boundary": check_freeze_boundary,
    "matrix": check_matrix,
    "decisions": check_decisions,
}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in CHECKS:
        parser.add_argument(f"--{name}", action="store_true", help=f"run the {name} check")
    parser.add_argument(
        "--milestone",
        default=CURRENT_MILESTONE,
        choices=MILESTONE_ORDER,
        help=(
            "milestone under review for the --matrix status gate: every row at or "
            f"before it must read 'covered' (default: {CURRENT_MILESTONE}, the constant "
            "a milestone review bumps)"
        ),
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="prove the checks can fail: corrupt a copy in a scratch tree and require red",
    )
    args = parser.parse_args()

    if args.self_test:
        return self_test()

    selected = [name for name in CHECKS if getattr(args, name.replace("-", "_"))]
    if not selected:
        selected = list(CHECKS)

    failures = Failures()
    for name in selected:
        if name == "matrix":
            check_matrix(failures, args.milestone)
        else:
            CHECKS[name](failures)

    if failures:
        print(
            f"\ncheck-traceability: FAILED with {len(failures.messages)} problem(s).",
            file=sys.stderr,
        )
        return 1
    print(f"check-traceability: ok ({', '.join(selected)})")
    return 0


def self_test() -> int:
    """Prove both checks are able to fail. A check never seen red proves nothing."""
    import shutil
    import tempfile

    ok = True
    with tempfile.TemporaryDirectory() as scratch:
        tree = pathlib.Path(scratch) / "tree"
        shutil.copytree(
            ROOT,
            tree,
            ignore=shutil.ignore_patterns(".git", "target", "node_modules"),
        )

        # (check, file, mutation, expect) where expect is "red" or "green".
        #
        # The two "green" cases are Q49's: a ticked checkbox is gate state and
        # must be tolerated. They are not decoration — without them the
        # normalisation could widen to "compare nothing" and no case would
        # notice. The "red" cases bound it from the other side: change a word,
        # or delete the marker instead of ticking it, and the check still bites.
        cases = [
            (
                "freeze-boundary",
                "docs/format/anchor-artifact-limits.md",
                lambda t: t.replace(
                    "an over-limit artifact fails that",
                    "an over-limit artifact fails THE WHOLE BUNDLE and that",
                    1,
                ),
                "red",
            ),
            (
                "freeze-boundary",
                "tasks/Q.md",
                lambda t: t.replace("- [ ] **Anchor-artifact freeze scope", "- **Anchor-artifact freeze scope", 1),
                "red",
            ),
            (
                "freeze-boundary",
                "tasks/Q.md",
                lambda t: t.replace("- [ ] **Anchor-artifact freeze scope", "- [x] **Anchor-artifact freeze scope", 1),
                "green",
            ),
            (
                "freeze-boundary",
                "tasks/Q.md",
                lambda t: t.replace("- [ ] **Report-version evolution", "- [X] **Report-version evolution", 1),
                "green",
            ),
            (
                "decisions",
                "crates/antseal-core/src/bundle/error.rs",
                lambda t: t.replace("D78", "D77000", 1),
                "green",
            ),
            (
                # The Q57 failure, faithfully: a decision marked RESOLVED in the
                # register whose record was never written. D18 is cited in
                # crates/wasm-bitmatch and is legitimately open today, so
                # flipping its checkbox is exactly "resolved, no record".
                "decisions",
                "TODO.md",
                lambda t: t.replace("- [ ] **D18**", "- [x] **D18**", 1),
                "red",
            ),
            (
                "decisions",
                "docs/testing/error-code-contract.md",
                lambda t: t + "\n\nSee `docs/format/registry-v1.md:1097` for the rule.\n",
                "red",
            ),
            (
                "matrix",
                MATRIX,
                lambda t: t.replace(
                    "::", "::this_test_does_not_exist_", 1
                ),
                "red",
            ),
            # Q51 — the status gate. The red case is the exact regression that
            # motivated it: an M0 row back at `gap`, in the `**gap**` spelling
            # the file actually used, so the marker stripping is exercised too.
            (
                "matrix",
                MATRIX,
                lambda t: t.replace(
                    "| M0 | F17 + Q39 + Q9 | covered |",
                    "| M0 | F17 + Q39 + Q9 | **gap** |",
                    1,
                ),
                "red",
            ),
            # And the bound from the other side. A *later* milestone's row at
            # `gap` must stay GREEN: M1's crates are stubs and gating them
            # would make the check unrunnable until M4, which is how a gate
            # gets switched off. Without this case the rule could quietly
            # widen to "every row must be covered" and nothing would notice.
            (
                "matrix",
                MATRIX,
                lambda t: t.replace("| M1 | S17 + Q15 | deferred |", "| M1 | S17 + Q15 | gap |", 1),
                "green",
            ),
            # A status outside the vocabulary is a typo, and a typo at a
            # not-yet-gated milestone would otherwise be invisible until that
            # milestone's review.
            (
                "matrix",
                MATRIX,
                lambda t: t.replace("| M1 | S17 + Q15 | deferred |", "| M1 | S17 + Q15 | defered |", 1),
                "red",
            ),
        ]

        for check, relative, mutate, expect in cases:
            path = tree / relative
            if not path.is_file():
                # Never a skip. A self-test that quietly opts out of a case is
                # how a check stops being able to fail without anyone noticing.
                print(
                    f"self-test: FAILED — {check} has no target: {relative} is missing",
                    file=sys.stderr,
                )
                ok = False
                continue
            original = path.read_text(encoding="utf-8")
            mutated = mutate(original)
            if mutated == original:
                # A mutation that changed nothing would make its case vacuous —
                # green for a reason that has nothing to do with the check.
                print(
                    f"self-test: FAILED — the {expect}-case mutation of {relative} "
                    "matched nothing, so the case proves nothing",
                    file=sys.stderr,
                )
                ok = False
                continue
            path.write_text(mutated, encoding="utf-8")
            result = subprocess.run(
                [sys.executable, str(tree / "scripts/check-traceability.py"), f"--{check}"],
                capture_output=True,
                text=True,
            )
            path.write_text(original, encoding="utf-8")
            went_red = result.returncode != 0
            if went_red != (expect == "red"):
                print(
                    f"self-test: FAILED — {check} went "
                    f"{'red' if went_red else 'green'} on the {expect}-case "
                    f"mutation of {relative}",
                    file=sys.stderr,
                )
                ok = False
            elif expect == "red":
                print(f"self-test: ok — {check} goes red when {relative} is corrupted")
            else:
                print(f"self-test: ok — {check} stays green where it must, on {relative}")

    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
