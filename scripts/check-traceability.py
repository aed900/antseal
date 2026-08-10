#!/usr/bin/env python3
"""Checks that a documented claim is still true of the tree.

Six checks live here, and they are the same shape: something written down in
prose asserts a fact about the repository, and nothing else verifies it.

    --freeze-boundary   The D84 §7 v1-freeze-boundary rows are byte-identical
                        across every file that carries a copy (Q37).
    --matrix            Every test named by the verification-coverage
                        traceability matrix actually resolves (Q13).
    --decisions         Every decision cited in code or in a normative doc
                        resolves to a record, a registered alternative home,
                        or an open register entry; and nothing cites the
                        frozen wire registry by line number (Q57, Q58).
    --task-citations    Every task id cited in code, in a normative doc or in
                        a gate script resolves to a row in TODO.md's register
                        (Q85).
    --task-entries      Every row in TODO.md has a detail entry in
                        tasks/<domain>.md, and every entry has a row (Q85).
    --decision-owners   Every `**Owner: <ID>**` assignment in a RESOLVED
                        decision names a registered task whose TODO.md row
                        names that decision back (Q145).

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

    if seen and all(blank_gate_state(b) == source_text for b in seen.values()):
        print(
            f"[{check}] ok — {len(seen)} copies identical to "
            f"{BOUNDARY_SOURCE} §7 ({len(source_text)} bytes of rule text; "
            f"checkbox state excluded, Q49)"
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
#
# It names the last milestone whose review has PASSED, not the one being
# built. The rule is cumulative, so `M1` gates M0's rows and M1's forever
# while leaving M2's — a milestone still in progress — free to read `gap`
# honestly. Setting it to the in-progress milestone instead would force every
# not-yet-done row into ACCEPTED_NON_COVERED, and that register's entries are
# for a milestone shipping with a known hole, not for work in flight; it would
# also mute those rows at the one review that is supposed to read them.
#
# M0 -> M1 on 2026-08-10 (Q165 / D118). It sat at "M0" from the freeze until
# then — through all of M1 and half of M2 — so the status gate was green over
# sixteen M0 rows and blind to eighteen others, and six M1 rows sat at
# `deferred` for eight days after their work landed. Bumping this line is the
# durable half of that fix: it is what makes the next such drift visible to
# the ordinary flagless run that every lane actually performs.
CURRENT_MILESTONE = "M1"

# The full vocabulary, per the matrix's own "Status vocabulary" note. Anything
# else is a typo, and a typo'd status at a not-yet-gated milestone would
# otherwise be invisible until that milestone's review.
STATUS_VOCABULARY = ("covered", "gap", "deferred")

# Rows allowed to sit at a non-`covered` status inside a gated milestone, as
# `id -> (status, reason)`. Empty, and it should stay that way: an entry here
# is a milestone shipping with a known hole, which is a decision worth writing
# down rather than a lint to be silenced. Stale entries are themselves a
# failure — see `check_matrix` — so this cannot rot into a permanent mute.
#
# Still empty after Q165 / D118, deliberately. Eleven rows read `deferred` at
# or before M2 and this register was the obvious place to put the survivor
# (`V7.1`, whose real calendar cycle was run by hand with curl rather than by
# antseal). It is the wrong place: M2 has not shipped, so there is no known
# hole to accept yet, and an entry here would silence `V7.1` at the M2 review
# — the one moment it exists to speak. `V7.1` reads `gap` at an ungated
# milestone instead, which is loud in `--milestone M2` and silent in the
# flagless run, exactly as intended.
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

# Where BOTH sweeps look — the decision half here and the task half below.
# Normative surfaces only: TODO.md is the register itself and tasks/*.md are
# working notes, so neither is a citation site.
#
# `scripts/` is in because the gate is committed code and a dangling pointer
# there is as normative as one in `crates/`; it is the surface that hid `A71`
# in `scripts/fuzz.sh:98-103` from the task half and every `D<n>` in
# `scripts/*.sh` from the decision half (D116 §1.1).
# `docs/decisions/` is deliberately OUT — D109 §3.3: a record's job includes
# PROPOSING work the orchestrator may number, renumber or decline, and
# sweeping it fails 13 rows for ids that D92 and D93 merely proposed. It is
# also where the captured evidence of these decisions lives, which contains a
# `registry-v1.md:<n>` literal on purpose (D116 §1.3).
# `.github/` is deliberately OUT and it is a close call — see D116 §2 (c).
#
# ROOT-LEVEL FILES (Q176). Every entry above is a directory, and both sweeps
# used to walk `ROOT/<sub>` only — so no root-level file was ever a citation
# site, and `CHANGELOG.md`, the one externally-facing document in the project,
# was swept by NOTHING anywhere in the tree. That is exactly why its line-123
# misquotation drifted unobserved until D114 found it by hand as site S10.
# They are listed here rather than in a second constant, and a scan root of
# `"."` was refused: `"."` reaches `target/`, `testdata/`, every dot-directory
# and — fatally — `TODO.md` itself, turning the register into a citation
# surface that reports every id it allocates.
#
# The four that are IN are live normative documents. The line is drawn at
# *live* versus *preserved*, which is `docs/decisions/`'s distinction one
# directory up:
#   `MVP-SPEC.orig.md` is OUT — it is the reviewed ORIGINAL, kept verbatim so
#   that `SPEC-REVIEW.md`'s line references still resolve (`MVP-SPEC.md:5`).
#   Sweeping a preserved artifact asserts its ids must resolve for ever, and
#   the only way to satisfy that is to edit the thing whose whole job is to be
#   unedited.
#   `SPEC-REVIEW.md` is OUT for the same reason — a dated 2026-07-27 review of
#   that original, recording what was found then.
# Both were MEASURED green before being excluded (2026-08-10), so this is a
# rule about what a citation surface is, not a suppression of a failure.
# `TODO.md` and `tasks/*.md` stay out for the reason stated at the top.
#
# HAZARD when adding to this list: an entry is filtered by CITATION_SUFFIXES
# like any other path, so naming a root file whose suffix is not in that set
# (`deny.toml`, `.gitattributes`) adds a scan root that reads nothing at all.
#
# ONE pair, not two (D116 R1). Two constants held in step by a comment is the
# defect D112 spent a wave on, one file over; the only honest comment on two
# here would be "these are the same, one is stale". Q176 kept it one pair for
# that reason: root files went INTO this list, and the loop in both sweeps
# gained the same two-branch line, rather than a second list only one sweep
# might learn to read.
CITATION_SCAN = [
    "crates",
    "docs/format",
    "docs/testing",
    "scripts",
    # Root-level files, swept as themselves (Q176).
    "CHANGELOG.md",
    "README.md",
    "CONTRIBUTING.md",
    "MVP-SPEC.md",
]
CITATION_SUFFIXES = {".rs", ".md", ".json", ".py", ".sh", ".mjs"}

# This file names task AND decision ids as literals in its registers and plants
# them in `--self-test`. Sweeping it reports its own fixtures.
#
# NOT because of `D77000`, the decision check's GREEN self-test case, which
# stays silent under every widening because the ceiling rule holds — that is
# the fixture working as designed, and it is measured (D116 §1.2). What
# actually turns the lane red is the `docs/format/registry-v1.md:<line>`
# literal carried by the Q58 RED case a few cases further down the same
# `cases` list, whose whole job is to be a line-number citation. That class has
# no ceiling, no allocation bound and no suppression register, so it fires the
# moment `scripts/` joins the scan. Check THAT literal before ever deciding
# this exclusion is unnecessary: reasoning from `D77000` alone concludes,
# wrongly, that it can be deleted. Measured as this landed: deleting the two
# lines below reports this file against itself, once per literal. D116 §1.2
# found one such literal; R4's new case adds a second, so the exclusion covers
# strictly more than the record that mandated it. This comment states the
# citation as `registry-v1.md:<line>` on purpose, so that documenting the trap
# does not lay another one.
CITATION_SCAN_SELF = "scripts/check-traceability.py"

# Decisions that are recorded, but not in a file of their own. Each entry is
# the home, so "no file" is a recorded fact rather than an omission. Adding to
# this list is a deliberate act; leaving a decision out of it is a failure.
DECISIONS_HOMED_ELSEWHERE = {
    11: "docs/research/S1-ant-core-api-survey.md (address length, pinned from ant-core source)",
    12: "docs/decisions/D7-cbor-crate.md §D12 (the cross-check nominee)",
    16: "docs/research/C11-signature-probe.md §9 (the probe that decided it)",
    # Added at the Q14 freeze, 2026-07-28 — and this check is what noticed.
    # Both were ratified in artifacts rather than in a record file, so while
    # their register entries were OPEN the check let them pass on that basis.
    # Closing the entries at the freeze removed their only home and turned this
    # lane red, correctly: a resolved decision with no home is exactly what the
    # check exists to catch. Their homes are named here instead.
    17: "docs/format/registry-v1.md §6.2 + crypto::sig_policy (ratified in code at C14/F5, frozen at Q14)",
    30: "docs/testing/error-code-contract.md (the contract IS the record; frozen at Q14, mechanism in Q52)",
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
    n_files = 0
    # Loop body at parity with `sweep_task_surfaces()` (D116 R2). The two
    # sweeps were given one scan set; having different prune sets afterwards is
    # exactly the divergence R1 exists to end. `scripts/__pycache__/` exists in
    # this tree today, so the prune is defence in depth rather than decoration.
    for sub in CITATION_SCAN:
        base = ROOT / sub
        if not base.exists():
            continue
        # Q176 — an entry may be a directory (swept recursively) or a single
        # FILE (swept as itself). Without this branch a filename in
        # CITATION_SCAN is a silent no-op: `Path.rglob` on a non-directory
        # yields nothing at all, so the constant would look widened and read
        # nothing. Both sweeps carry this line identically; see the note at
        # CITATION_SCAN.
        for path in ([base] if base.is_file() else base.rglob("*")):
            if not path.is_file() or path.suffix not in CITATION_SUFFIXES:
                continue
            if {"target", "node_modules", "__pycache__"} & set(path.parts):
                continue
            rel = str(path.relative_to(ROOT))
            if rel == CITATION_SCAN_SELF:
                continue
            try:
                text = path.read_text(encoding="utf-8")
            except (UnicodeDecodeError, OSError):
                continue
            n_files += 1
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
        # The file count is reported for the reason the task half reports it
        # (D116 R3): without it, a scan that silently narrowed back to the
        # three doc/code roots would be invisible in a green log — a green
        # lane saying nothing about how much it read.
        print(
            f"[{check}] ok — {len(in_bound)} distinct decisions cited across "
            f"{n_files} files, all resolve ({len(recorded)} have records, "
            f"{homed} homed elsewhere, {len(still_open)} still open in the "
            f"register); no line-number citations into the registry"
        )


# ── checks 4 and 5: task ids resolve, in both directions (Q85, ruled by D109) ─
# Q85 asked for ONE check mirroring `check_decisions()` — "the same twenty lines
# pointed at the other kind of pointer". D109 §1.4 refuses that on a
# measurement: the D namespace is DENSE (D1–D108, zero holes) and the nine task
# domains are 71 unallocated numbers wide inside `1..max`. `check_decisions()`'s
# only bound, `n > max(allocated) → skip`, is therefore equivalent to "n is
# allocated" for a dense namespace and is a 71-number-wide false-positive
# surface for a sparse one — every unresolved hit this sweep returns lands in a
# hole, which is the mechanism, not a coincidence.
#
# So: two checks, two flags. They share no code path beyond
# `allocated_task_ids()`. The citation half reads TODO.md and the scan
# surfaces; the entry half reads TODO.md and tasks/*.md and never touches the
# scan surfaces. They are different questions with different inputs and — the
# operative reason — different backlogs that must be able to fail
# independently (D109 §3.1).

TASK_DOMAINS = "PFCGSARUQ"

# Where task citations are swept: `CITATION_SCAN` / `CITATION_SUFFIXES` /
# `CITATION_SCAN_SELF`, the same three constants the decision half uses. They
# used to be two pairs that happened to agree on three of four roots; D116 R1
# collapsed them, and `DECISION_SCAN`, `DECISION_SUFFIXES`, `TASK_SCAN`,
# `TASK_SUFFIXES` and `TASK_SCAN_SELF` were deleted rather than aliased — an
# alias is a second name for one thing and the next reader has to prove they
# are equal.

# Both row shapes. `- ~~**P18**` carries NO checkbox: protocol rule 1 says a
# retired task is struck, never deleted, so this shape is mandated and will
# recur. A checkbox-only regex reports P18 as an entry with no row — the false
# positive on the one row the protocol most wants preserved (D109 §1.2). The
# "known standing offset" of one between the P domain's header count and a
# grep is this regex bug, in every ad-hoc script that has measured the file.
TASK_ROW = re.compile(r"^- (?:\[[ xX]\]|~~)\s*\*\*([" + TASK_DOMAINS + r"])(\d+)\*\*", re.M)

# An entry is a level-3 heading, exactly. `tasks/Q.md`'s
# `#### Q14 freeze checklist — normative rows` is a sub-heading OF the Q14
# entry, not a second entry, and sub-headings are permitted: the level is the
# whole discriminator.
#
# Measured correction to D109 §1.3, which says a detector keyed on `^#{2,4}`
# reports Q14 twice. It does not — that line puts " freeze checklist " between
# the id and the em-dash, so it fails this pattern at BOTH levels, and keying
# on `^#{2,4}` leaves the tree green at an unchanged entry count. The
# tolerance still has to be pinned, because a `#### ` sub-heading written in
# the `<ID> — <title>` grammar would be double-counted; self-test case (i)
# plants exactly that, and so bites where the tree's own sub-heading does not.
TASK_ENTRY = re.compile(r"^### ([" + TASK_DOMAINS + r"])(\d+) — ")

TASK_BARE = re.compile(r"\b([" + TASK_DOMAINS + r"])(\d{1,3})\b")
TASK_MARKED = re.compile(
    r"`([" + TASK_DOMAINS + r"])(\d{1,3})`|\*\*([" + TASK_DOMAINS + r"])(\d{1,3})\*\*"
)

# Tokens that match a task id and are not citations. Keyed by (id, PATH) so a
# suppression in one file can never mute a real citation of the same id
# elsewhere. A stale entry is itself a failure — see check_task_citations.
#
# The growth brake is the key: silencing a new false positive means naming the
# exact file, which is reviewable in a diff in a way that adding a bare id is
# not. `A71` was deliberately NOT put here — it is real, described,
# unregistered work in a committed gate script, and registering it as noise
# would make this check's first run certify a dangling pointer instead of
# finding one (D109 §3.4). It got a row.
TASK_ID_NOT_A_CITATION: dict[tuple[str, str], str] = {
    ("R46", "crates/antseal-core/src/anchor/roots/mod.rs"):
        "'Sectigo Public Time Stamping Root R46' — a CA subject DN. 46 is a "
        "hole in R (R has 12), so no numeric bound can separate it.",
    ("R46", "crates/antseal-core/src/anchor/roots/PROVENANCE.md"):
        "Same DN, in the provenance table that records where the root came "
        "from.",
    ("Q72", "docs/testing/error-code-contract.md"):
        "Mention, not use: :215-219 RECORDS that Q72 was never issued — "
        "'Q72 is named by neither, so D60 points a reader at nothing' and "
        "'A38 = Q80 = Q72 = the work this section is'. Failing on the "
        "sentence that documents the defect is not the check working.",
}

# ROWS_PENDING_ENTRY and BACKLOG_FROZEN_ON lived here and are DELETED
# 2026-08-10 (Q135), together with the staleness rule below and self-test case
# (k), because the register is drained: it opened at 21 rows (D109 §3.5), lost
# Q130 to an entry that landed in the same wave, lost the twelve OPEN rows to
# Q134, and lost its last eight — Q124, S27, S29, S34, U36, U37, U38, U40 — to
# Q135. It may only ever have SHRUNK, and it only ever did.
#
# The four pieces went in one change deliberately. An empty dict beside a frozen
# date is an invitation to reopen a register that was closed, so `--self-test`
# refused to run against one: "ROWS_PENDING_ENTRY is empty, so case (k) cannot
# show the staleness rule bites … delete the constant, BACKLOG_FROZEN_ON, the
# rule and this case together". That assertion was the mechanism that forced
# this deletion, and it is recorded here rather than merely removed.
#
# What survives without it: a TODO.md row with no `### <ID> — ` entry is now
# unconditionally a failure, which is the state D109 §8 was driving at. There is
# no exemption surface left, so there is nothing to keep dated.


def task_id_key(tid: str) -> tuple[str, int]:
    """Sort key: A105 sorts after A71, which string order gets backwards."""
    return (tid[0], int(tid[1:]))


def task_rows() -> list[tuple[str, bool]]:
    """Every row in TODO.md's register as `(id, is_struck)`, in file order.

    A list rather than a set because the entry half's success line reports the
    live/struck split, which is what proves the struck shape is parsed at all.
    """
    todo = (ROOT / "TODO.md").read_text(encoding="utf-8")
    return [
        (m.group(1) + m.group(2), m.group(0).startswith("- ~~"))
        for m in TASK_ROW.finditer(todo)
    ]


def allocated_task_ids() -> dict[str, set[int]]:
    """Every allocated task number, keyed by domain letter, from both shapes.

    The bound for the citation half, exactly as `allocated_decision_ids()` is
    for the decision half. The count is measured, never pinned: rows are added
    mid-wave by design and a hardcoded total would be red for most of every
    wave. What is guarded is only the vacuous case — see each caller.
    """
    allocated: dict[str, set[int]] = {}
    for tid, _struck in task_rows():
        allocated.setdefault(tid[0], set()).add(int(tid[1:]))
    return allocated


def task_id_ceiling(allocated: dict[str, set[int]]) -> dict[str, int]:
    """The highest allocated number per domain — tier 1's upper bound."""
    return {domain: max(numbers) for domain, numbers in allocated.items() if numbers}


def task_detail_entries() -> dict[str, list[tuple[str, int]]]:
    """Every `### <ID> — ` entry, as `id -> [(filename, line)]`.

    A list, not a scalar, so a duplicate entry is reportable rather than
    silently collapsed onto whichever copy was read last.
    """
    entries: dict[str, list[tuple[str, int]]] = {}
    for path in sorted((ROOT / "tasks").glob("*.md")):
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            match = TASK_ENTRY.match(line)
            if match:
                entries.setdefault(match.group(1) + match.group(2), []).append(
                    (path.name, number)
                )
    return entries


def sweep_task_surfaces() -> tuple[dict[str, set[str]], dict[str, set[str]], int]:
    r"""`(every occurrence, marked occurrences, files read)` over CITATION_SCAN.

    Both maps are `id -> {relative path}`. Marked hits are a strict subset of
    all hits: a backtick and an asterisk are both non-word characters, so
    TASK_BARE's `\b` matches inside `` `A71` `` and `**A71**` too. That is what
    lets the register's staleness rule be keyed on the one map.
    """
    cited: dict[str, set[str]] = {}
    marked: dict[str, set[str]] = {}
    files = 0
    for sub in CITATION_SCAN:
        base = ROOT / sub
        if not base.exists():
            continue
        # Q176 — an entry may be a directory (swept recursively) or a single
        # FILE (swept as itself). Without this branch a filename in
        # CITATION_SCAN is a silent no-op: `Path.rglob` on a non-directory
        # yields nothing at all, so the constant would look widened and read
        # nothing. Both sweeps carry this line identically; see the note at
        # CITATION_SCAN.
        for path in ([base] if base.is_file() else base.rglob("*")):
            if not path.is_file() or path.suffix not in CITATION_SUFFIXES:
                continue
            if {"target", "node_modules", "__pycache__"} & set(path.parts):
                continue
            relative = str(path.relative_to(ROOT))
            if relative == CITATION_SCAN_SELF:
                continue
            try:
                text = path.read_text(encoding="utf-8")
            except (UnicodeDecodeError, OSError):
                continue
            files += 1
            for domain, number in TASK_BARE.findall(text):
                cited.setdefault(domain + number, set()).add(relative)
            for tick_d, tick_n, bold_d, bold_n in TASK_MARKED.findall(text):
                domain, number = (tick_d, tick_n) if tick_d else (bold_d, bold_n)
                marked.setdefault(domain + number, set()).add(relative)
    return cited, marked, files


def check_task_citations(failures: Failures) -> None:
    check = "task-citations"

    allocated = allocated_task_ids()
    if not allocated:
        failures.add(check, "no task ids found in TODO.md's register — the bound is vacuous")
        return
    ceiling = task_id_ceiling(allocated)
    cited, marked, n_files = sweep_task_surfaces()

    for tid in sorted(cited, key=task_id_key):
        domain, number = tid[0], int(tid[1:])
        if number in allocated.get(domain, ()):
            continue
        if number < 1:
            # The floor. No domain allocates 0, and `A0`/`C0`/`F0` in this tree
            # are hex byte values in UTF-8 prose ("E0 requires A0..=BF next"),
            # not labels — so one rule kills them and every future hex byte of
            # that shape, where a register would name them one at a time.
            continue

        if number <= ceiling.get(domain, 0):
            paths = sorted(cited[tid])
            unsuppressed = [p for p in paths if (tid, p) not in TASK_ID_NOT_A_CITATION]
            if not unsuppressed:
                continue
            where = ", ".join(unsuppressed[:3])
            failures.add(
                check,
                f"{tid} is cited ({where}) but has no row in TODO.md's register. Either the "
                f"id was minted in a brief and never registered — add the row and its "
                f"tasks/{domain}.md entry — or the token is not a task citation at all, in "
                f"which case register it in TASK_ID_NOT_A_CITATION keyed by (id, path) with "
                f"the reason.",
            )
            continue

        # Above the ceiling there is no allocation evidence at all, so the
        # citation must assert itself typographically: only a MARKED occurrence
        # counts — the id as the whole content of a backtick or bold span.
        #
        # The blind spot, named. A newly minted, unregistered id written BARE
        # and above its domain's ceiling is not reported. This is deliberate:
        # bare tokens above the ceiling are where every curve name (`P384`),
        # integer width (`U256`) and codec discriminant (`F64`) in this tree
        # lives, and widening the rule to bare would report all of them. What
        # covers it instead: (i) ids are conventionally written marked here, so
        # a real citation almost always is; (ii) the moment the domain's
        # ceiling advances past that number for any reason, the citation drops
        # into tier 1 and fires; (iii) `--task-entries` catches the same defect
        # from the other side the instant a row is added. Widening this branch
        # to bare occurrences turns the self-test's green case (d) red, which
        # is what forces a re-decision rather than a quiet edit.
        if tid not in marked:
            continue
        where = ", ".join(sorted(marked[tid])[:3])
        failures.add(
            check,
            f"{tid} is cited in marked form ({where}) and is above domain {domain}'s "
            f"highest allocated number ({ceiling.get(domain, 0)}), so no row for it can "
            f"exist. That is what a freshly minted, never-registered id looks like. Add "
            f"the row, or unmark the citation if it is not a task id.",
        )

    # A suppression is a claim about the tree, and it can rot in two
    # directions: the token it names can leave, or the id can gain a row.
    for (tid, path), reason in sorted(TASK_ID_NOT_A_CITATION.items()):
        if path not in cited.get(tid, set()):
            failures.add(
                check,
                f"TASK_ID_NOT_A_CITATION registers ({tid}, {path}) as not-a-citation "
                f"({reason}) but no occurrence of {tid} was swept there. Remove it — a stale "
                f"suppression is how a lint decays into a permanent mute.",
            )
        if int(tid[1:]) in allocated.get(tid[0], ()):
            failures.add(
                check,
                f"TASK_ID_NOT_A_CITATION suppresses {tid} at {path}, but {tid} now has a row "
                f"in TODO.md. The suppression asserts something false about an allocated id; "
                f"remove it and let the citation resolve.",
            )

    if not failures:
        resolved = [t for t in cited if int(t[1:]) in allocated.get(t[0], ())]
        print(
            f"[{check}] ok — {len(resolved)} distinct task ids cited across {n_files} files, "
            f"all resolve ({len(TASK_ID_NOT_A_CITATION)} registered as not-citations); no "
            f"unregistered id cited in marked form above its domain ceiling"
        )


def check_task_entries(failures: Failures) -> None:
    check = "task-entries"

    rows = task_rows()
    entries = task_detail_entries()
    if not rows or not entries:
        failures.add(
            check,
            f"TODO.md yielded {len(rows)} rows and tasks/*.md yielded {len(entries)} "
            "entries — the entry check would be vacuous. Either a heading style changed "
            "or the row grammar stopped matching.",
        )
        return

    row_ids = {tid for tid, _struck in rows}
    n_live = sum(1 for _tid, struck in rows if not struck)
    n_struck = sum(1 for _tid, struck in rows if struck)

    for tid, _struck in rows:
        if tid in entries:
            continue
        domain = tid[0]
        failures.add(
            check,
            f"TODO.md row {tid} has no `### {tid} — ` entry in tasks/{domain}.md. A lane "
            f"that opens tasks/{domain}.md to read this task's Do/Accept finds nothing "
            f"and improvises. Write the entry. There is no exemption register: the "
            f"D109 §3.5 backlog was drained and deleted at Q135 (2026-08-10).",
        )

    for tid in sorted(entries, key=task_id_key):
        places = entries[tid]
        domain = tid[0]
        if tid not in row_ids:
            name, line = places[0]
            failures.add(
                check,
                f"tasks/{name}:{line} defines `### {tid} — ` but TODO.md has no row for "
                f"{tid}, in either the checkbox form or the struck form `- ~~**{tid}**`. "
                f"Statuses live only in TODO.md (protocol rule 1), so an entry with no row "
                f"has no status and no milestone.",
            )
        if len(places) > 1:
            where = ", ".join(f"tasks/{name}:{line}" for name, line in places)
            failures.add(
                check,
                f"{tid} has {len(places)} `### {tid} — ` entries ({where}). An entry is the "
                f"single home of a task's Do/Accept. A sub-heading inside an entry must be "
                f"`#### `, not `### `.",
            )
        for name, _line in places:
            if name != f"{domain}.md":
                failures.add(
                    check,
                    f"{tid}'s entry is in tasks/{name} but domain {domain} is homed in "
                    f"tasks/{domain}.md — one file per domain, per TODO.md's header table.",
                )

    if not failures:
        print(
            f"[{check}] ok — {len(rows)} rows ({n_live} live + {n_struck} struck) against "
            f"{sum(len(p) for p in entries.values())} entries; no row without an entry, no "
            f"entry without a row, no duplicate, none misfiled"
        )


# ── check 6: a resolved ruling's owner is reachable from the row it names ────
# (Q145, ruled by D113)
#
# Q145 proposed a join over data this file already holds: resolved decision +
# owner whose row is ticked. D113 §2 refuses it on the identical two-assignment
# domain — D104 §4 (executed) and D104 §6 (not) — where the ticked clause fires
# on both and separates nothing. What separates them is the BACK-citation: A48's
# row names D104, A106's row named no decision at all.

DECISION_OWNER = re.compile(
    r"^\*\*Owner: ([" + TASK_DOMAINS + r"]\d{1,3})\*\*", re.M
)


def decision_owner_assignments() -> list[tuple[int, str, str, int]]:
    """`(decision number, owner id, filename, line)` per per-ruling assignment.

    Anchored and bold on purpose. The bare string `Owner:` occurs 20 times in
    the corpus and 2 of those are D8 quoting a tail it is DELETING; the
    front-matter `- **Owner: ...**` bullet is prose that names domains, gates
    and consumers as often as owners (D113 §1.2 measures 2 parse artifacts in
    12). This is the only form that is unambiguously one ruling assigned to one
    registered task, and D113 RULING 2 makes writing it the author's part.
    """
    found: list[tuple[int, str, str, int]] = []
    for path in sorted((ROOT / DECISION_DIR).glob("D*.md")):
        match = re.match(r"D(\d+)-", path.name)
        if not match:
            continue
        number = int(match.group(1))
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        for line_no, line in enumerate(text.splitlines(), 1):
            hit = DECISION_OWNER.match(line)
            if hit:
                found.append((number, hit.group(1), path.name, line_no))
    return found


def row_text() -> dict[str, str]:
    """`id -> the whole TODO.md row`. `task_rows()` returns the struck flag and
    drops the text, and this check's question is about the text."""
    todo = (ROOT / "TODO.md").read_text(encoding="utf-8")
    found: dict[str, str] = {}
    for line in todo.splitlines():
        match = TASK_ROW.match(line)
        if match:
            found[match.group(1) + match.group(2)] = line
    return found


def check_decision_owners(failures: Failures) -> None:
    check = "decision-owners"

    allocated = allocated_decision_ids()
    if not allocated:
        failures.add(check, "no decision ids in TODO.md's register — the bound is vacuous")
        return
    resolved = allocated - open_decision_ids()
    rows = row_text()
    if not rows:
        failures.add(check, "TODO.md yielded no task rows — the check would be vacuous")
        return

    assignments = decision_owner_assignments()
    if not assignments:
        # The domain is small (D113 §1.2: one document today), so vacuity is
        # this check's likeliest failure and it must be loud, not green.
        failures.add(
            check,
            "no `**Owner: <ID>**` assignment exists in any decision document. Either the "
            "mandated form (D113 RULING 2) stopped being written or this regex stopped "
            "matching it; a check over an empty domain proves nothing.",
        )
        return

    checked = 0
    for number, owner, name, line_no in assignments:
        if number not in resolved:
            continue  # an unresolved decision has assigned nothing yet
        checked += 1
        if owner not in rows:
            failures.add(
                check,
                f"{name}:{line_no} assigns a ruling to {owner}, which has no row in "
                f"TODO.md's register. A ruling owned by an unregistered id is owned by "
                f"nobody. Add the row, or name an id that exists.",
            )
            continue
        if not re.search(rf"\bD{number}\b", rows[owner]):
            failures.add(
                check,
                f"{name}:{line_no} assigns a ruling to {owner}, and {owner}'s TODO.md row "
                f"never names D{number}. A lane that opens {owner}, or the row that succeeds "
                f"it, cannot learn that D{number} governs the work — which is how a resolved "
                f"ruling outlives its owner's closure unexecuted and unseen (Q145). Put "
                f"`D{number} §<n>` in {owner}'s row: if the ruling is done say so there, and "
                f"if it is not, the row must name the task carrying the remainder.",
            )

    # The second vacuity guard, and D113 §3.1 does not have it. Its guard fires
    # only when the corpus holds NO assignment at all; a corpus whose every
    # assignment sits in an UNRESOLVED decision passes the first guard and then
    # checks nothing, printing a green "ok — 0 assignment(s)". On a domain of
    # two, both in one document, reopening that document alone would do it.
    # `check_matrix` sets the precedent by guarding `gate_rows`, its own
    # post-filter count, for the same reason (D113 §3.1, corrected).
    if not checked:
        failures.add(
            check,
            f"{len(assignments)} `**Owner: <ID>**` assignment(s) exist but not one is in a "
            f"RESOLVED decision, so this check verified nothing. An unresolved decision has "
            f"assigned no work yet — but a check that silently reports success over an empty "
            f"domain is worse than no check.",
        )
        return

    if not failures:
        print(
            f"[{check}] ok — {checked} per-ruling owner assignment(s) in resolved "
            f"decisions, every one named by the row it assigns"
        )


CHECKS = {
    "freeze-boundary": check_freeze_boundary,
    "matrix": check_matrix,
    "decisions": check_decisions,
    "task-citations": check_task_citations,
    "task-entries": check_task_entries,
    "decision-owners": check_decision_owners,
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
    import time

    ok = True
    with tempfile.TemporaryDirectory() as scratch:
        tree = pathlib.Path(scratch) / "tree"

        # Q150 — this copy races every other writer under ROOT, and it used to
        # lose. `copytree` lists a directory with one `scandir` and copies the
        # entries afterwards; anything that vanishes in between makes `copy2`
        # raise, and `copytree` collects those into a `shutil.Error` it raises
        # at the end. Exit 1, a traceback rather than this file's own
        # annotation, and the offending path already gone by the time anyone
        # reads it. In a parallel-lane wave that reddens the `traceability`
        # required context for a reason that has nothing to do with
        # traceability — the worst shape a flaky failure can take.
        #
        # Two guards, because they cover different things.
        #
        # (1) `*.tmp.*` is THIS project's atomic-write shape — `vault/fs.rs:59`
        #     writes `.<name>.tmp.<pid>.<seq>` beside its target and renames it
        #     away, and the tracker's own writers use `<name>.tmp.<pid>.<hash>`.
        #     `fnmatch` does not special-case a leading dot, so the one pattern
        #     covers both spellings. Ignoring the shape removes the race at its
        #     source rather than retrying through it. It hides no committed
        #     file: no path in `git ls-files` contains `.tmp.`, and a temp file
        #     that IS present is by construction a half-written one, so copying
        #     it would give the mutation harness a tree that is not the tree.
        # (2) A bounded retry, because the glob only names the transients we
        #     already know about. `__pycache__/*.pyc` is written and replaced by
        #     any concurrent `python3 scripts/…` run and is NOT ignored here,
        #     and an editor `.swp` has been observed appearing under
        #     `testdata/vectors/v1/` from a gate script. Those cost one retry
        #     each instead of a red lane.
        #
        # The retry is bounded and reports rather than raising: a copy that
        # fails three times is an environment fault, not a transient, and it
        # must say so in a sentence instead of a stack trace. It is NOT a
        # silent swallow — the last failure is printed with its cause.
        copy_attempts = 3
        for attempt in range(1, copy_attempts + 1):
            try:
                shutil.copytree(
                    ROOT,
                    tree,
                    ignore=shutil.ignore_patterns(
                        ".git", "target", "node_modules", "*.tmp.*"
                    ),
                )
                break
            except (shutil.Error, OSError) as exc:
                # A failed copytree leaves a partial tree behind; the next
                # attempt needs a clean destination.
                shutil.rmtree(tree, ignore_errors=True)
                if attempt == copy_attempts:
                    print(
                        f"self-test: FAILED — could not stage a copy of the tree in "
                        f"{copy_attempts} attempts; the last failure was: {exc}",
                        file=sys.stderr,
                    )
                    return 1
                time.sleep(0.25 * attempt)

        # Q66 — the gate-state fixtures derive their mutation from whatever
        # state the row is in, never from a hardcoded `- [ ]` literal. The
        # first fixtures wrote the literals out, so the moment Q14's execution
        # ticked the normative rows all three mutations matched nothing and
        # this self-test failed vacuous — red from the gate commit onward,
        # invisible until the lane first ran locally (`local-gate.sh` gained
        # the lane in the same commit as this fix).
        def strip_marker(row: str):
            """Delete the checkbox marker ahead of `row`, whatever its state."""
            pattern = re.compile(r"- \[[ xX]\] (\*\*" + re.escape(row) + ")")
            return lambda t: pattern.sub(r"- \1", t, count=1)

        def flip_tick(row: str):
            """Tick an unticked `row`, untick a ticked one — always a real change."""
            pattern = re.compile(r"- \[([ xX])\] (\*\*" + re.escape(row) + ")")
            return lambda t: pattern.sub(
                lambda m: ("- [x] " if m.group(1) == " " else "- [ ] ") + m.group(2),
                t,
                count=1,
            )

        def retick_upper(row: str):
            """Rewrite `row`'s marker to the uppercase `[X]` form (to `[ ]` if
            already uppercase) — the case-insensitivity bound."""
            pattern = re.compile(r"- \[([ xX])\] (\*\*" + re.escape(row) + ")")
            return lambda t: pattern.sub(
                lambda m: ("- [ ] " if m.group(1) == "X" else "- [X] ") + m.group(2),
                t,
                count=1,
            )

        # ── Q85's fixtures (D109 R8) ────────────────────────────────────────
        # Q66's rule, and harder here: not one of these may hard-code a task
        # id, a count or a line number. Every id below is READ from the scratch
        # tree at fixture time, and every helper RAISES rather than returning a
        # literal when the tree yields nothing — a regex that stops matching
        # has to make the fixture fail loudly instead of vacuously.

        def scratch_rows() -> dict[str, set[int]]:
            text = (tree / "TODO.md").read_text(encoding="utf-8")
            found: dict[str, set[int]] = {}
            for match in TASK_ROW.finditer(text):
                found.setdefault(match.group(1), set()).add(int(match.group(2)))
            if not found:
                raise AssertionError(
                    "self-test: TASK_ROW matched no row in the scratch TODO.md, so every "
                    "task fixture below would be built from nothing"
                )
            return found

        def scratch_entries() -> dict[str, list[tuple[str, int]]]:
            found: dict[str, list[tuple[str, int]]] = {}
            for path in sorted((tree / "tasks").glob("*.md")):
                lines = path.read_text(encoding="utf-8").splitlines()
                for number, line in enumerate(lines, 1):
                    match = TASK_ENTRY.match(line)
                    if match:
                        key = match.group(1) + match.group(2)
                        found.setdefault(key, []).append((path.name, number))
            if not found:
                raise AssertionError(
                    "self-test: TASK_ENTRY matched no heading under the scratch tasks/, so "
                    "the entry fixtures would be built from nothing"
                )
            return found

        def first_hole(domain: str) -> str:
            """The lowest unallocated number in `domain`, read from the scratch tree."""
            taken = scratch_rows()[domain]
            for number in range(1, max(taken) + 1):
                if number not in taken:
                    return f"{domain}{number}"
            raise AssertionError(
                f"self-test: domain {domain} is dense, so it has no hole to plant a tier-1 "
                "citation in; the case needs a domain that has one"
            )

        def above_ceiling(domain: str) -> str:
            """`domain` + (its highest allocated number + 1), read from the scratch tree."""
            return f"{domain}{max(scratch_rows()[domain]) + 1}"

        def a_row_with_entry() -> tuple[str, str, str]:
            """`(id, tasks/<file>, the heading line)` for the first TODO.md row
            that has an entry — computed, never named."""
            entries = scratch_entries()
            todo = (tree / "TODO.md").read_text(encoding="utf-8")
            for match in TASK_ROW.finditer(todo):
                key = match.group(1) + match.group(2)
                if key in entries:
                    name, number = entries[key][0]
                    lines = (tree / "tasks" / name).read_text(encoding="utf-8").splitlines()
                    return key, f"tasks/{name}", lines[number - 1]
            raise AssertionError("self-test: no TODO.md row has an entry to build a case from")

        def a_live_row_with_entry() -> str:
            """The exact TODO.md line of the first LIVE row that has an entry."""
            entries = scratch_entries()
            for line in (tree / "TODO.md").read_text(encoding="utf-8").splitlines():
                match = TASK_ROW.match(line)
                if match and not line.startswith("- ~~"):
                    if match.group(1) + match.group(2) in entries:
                        return line
            raise AssertionError("self-test: no live TODO.md row has an entry")

        def drop_token(token: str):
            """Delete EVERY bare occurrence of `token`, and the space ahead of it.

            Every occurrence, not the first: an id cited more than once at a
            path would leave the suppression fresh and the case would prove
            nothing.
            """
            pattern = re.compile(r" ?\b" + re.escape(token) + r"\b")
            return lambda t: pattern.sub("", t)

        def an_owner_assignment() -> tuple[int, str, str]:
            """`(decision number, owner id, decision filename)` for the first
            per-ruling assignment whose owned row ALREADY names the decision —
            so case (l)'s deletion is a real removal and not a no-op."""
            rows: dict[str, str] = {}
            for line in (tree / "TODO.md").read_text(encoding="utf-8").splitlines():
                match = TASK_ROW.match(line)
                if match:
                    rows[match.group(1) + match.group(2)] = line
            for path in sorted((tree / DECISION_DIR).glob("D*.md")):
                head = re.match(r"D(\d+)-", path.name)
                if not head:
                    continue
                number = int(head.group(1))
                for owner in DECISION_OWNER.findall(path.read_text(encoding="utf-8")):
                    if owner in rows and re.search(rf"\bD{number}\b", rows[owner]):
                        return number, owner, path.name
            raise AssertionError(
                "self-test: no per-ruling owner assignment has a back-citing row, so the "
                "decision-owners cases would be built from nothing"
            )

        hole_a, hole_q = first_hole("A"), first_hole("Q")
        minted_a, minted_q = above_ceiling("A"), above_ceiling("Q")
        entry_id, entry_file, entry_heading = a_row_with_entry()
        live_row = a_live_row_with_entry()
        struck_row = "- ~~" + re.sub(r"^- \[[ xX]\] ", "", live_row) + "~~"
        other_file = next(
            f"tasks/{p.name}"
            for p in sorted((tree / "tasks").glob("*.md"))
            if p.stem != entry_id[0]
        )
        if not TASK_ID_NOT_A_CITATION:
            raise AssertionError(
                "self-test: TASK_ID_NOT_A_CITATION is empty, so case (e) cannot show the "
                "register is non-vacuous. When the last suppression goes, delete the "
                "register, its two staleness rules and this case together."
            )
        suppressed_id, suppressed_path = sorted(TASK_ID_NOT_A_CITATION)[0]
        owner_dnum, owner_id, owner_doc = an_owner_assignment()
        ghost_owner = above_ceiling(owner_id[0])

        # (check, file, mutation, expect) where expect is "red" or "green".
        #
        # The two "green" cases are Q49's: a checkbox marker is gate state and
        # must be tolerated in either direction and either case. They are not
        # decoration — without them the normalisation could widen to "compare
        # nothing" and no case would notice. The "red" cases bound it from the
        # other side: change a word, or delete the marker instead of ticking
        # it, and the check still bites.
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
                strip_marker("Anchor-artifact freeze scope"),
                "red",
            ),
            (
                "freeze-boundary",
                "tasks/Q.md",
                flip_tick("Anchor-artifact freeze scope"),
                "green",
            ),
            (
                "freeze-boundary",
                "tasks/Q.md",
                retick_upper("Report-version evolution"),
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
            # (o) The `scripts/` surface really is swept by the DECISION half
            # too. Without this case, D116 R1's widening is unproven and a
            # later edit could narrow CITATION_SCAN back to the three doc/code
            # roots with nothing noticing — which is the state that hid every
            # `D<n>` in `scripts/*.sh` until D116.
            #
            # It plants the Q58 line-citation rather than an unresolvable
            # `D<n>` DELIBERATELY, and the reason is measured (D116 §1.4):
            # D1-D112 is dense with ZERO holes and every id resolves, so no
            # single-file mutation can make a `D<n>` citation fail — and this
            # harness applies exactly one mutation to exactly one file. The
            # existing class-1 red case above works only because it mutates
            # TODO.md and lets an EXISTING citation in crates/ do the naming,
            # so it does not pin this surface. The Q58 half needs no allocation
            # to fail, and it exercises the SAME sweep, the same suffix set and
            # the same file list. Do not "improve" it into a class-1 case by
            # adding a hole to the D namespace: the density is a property of
            # the register, not a deficiency.
            #
            # `scripts/fuzz.sh` is the target for the same reason case (b) uses
            # it: it is the file whose real `A71` citation proved the surface
            # matters.
            (
                "decisions",
                "scripts/fuzz.sh",
                lambda t: t + "\n# key layout: docs/format/registry-v1.md:1097\n",
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
            # `gap` must stay GREEN: a not-yet-reviewed milestone's crates may
            # still be stubs, and gating them would make the check unrunnable
            # until M4, which is how a gate gets switched off. Without this
            # case the rule could quietly widen to "every row must be covered"
            # and nothing would notice.
            #
            # **Retargeted M1 -> M4 on 2026-08-10 (Q165 / D118), because the
            # fixture had inherited its row's lifetime.** Both cases below used
            # to mutate `| M1 | S17 + Q15 | deferred |`, which is V6.1's cell.
            # M1 was reviewed, CURRENT_MILESTONE moved to M1 and V6.1 became
            # `covered` — so the string vanished, both mutations matched
            # nothing, and the no-op guard in `self_test` failed both cases
            # loudly. (Loudly is right: had it not, the green case would have
            # been green for no reason at all.) V9.2 is the one small real
            # mainnet seal. It cannot be covered before the release, and at
            # the release Q34 requires this whole matrix green, so this
            # fixture's expiry now lands on a review somebody must attend
            # anyway. Any status-gate fixture must be pinned to a row that
            # outlives the constant it is testing against.
            (
                "matrix",
                MATRIX,
                lambda t: t.replace("| M4 | Q34 | deferred |", "| M4 | Q34 | gap |", 1),
                "green",
            ),
            # A status outside the vocabulary is a typo, and a typo at a
            # not-yet-gated milestone would otherwise be invisible until that
            # milestone's review.
            (
                "matrix",
                MATRIX,
                lambda t: t.replace("| M4 | Q34 | deferred |", "| M4 | Q34 | defered |", 1),
                "red",
            ),
            # ── Q85 / D109 R8 ────────────────────────────────────────────────
            # (a) tier 1 bites at all: an id in one of the domain's holes,
            # cited in a normative source file.
            (
                "task-citations",
                "crates/antseal-core/src/anchor/mod.rs",
                lambda t: t + f"\n// follow-up: `{hole_a}`\n",
                "red",
            ),
            # (b) `scripts/` and `.sh` really are swept by the TASK half.
            # Without this case the surface widening that found the one genuine
            # dangling pointer (D109 §1.5) is unproven, and a later edit could
            # narrow CITATION_SCAN back to the three doc/code roots with
            # nothing noticing. Case (o) below is its decision-half twin.
            (
                "task-citations",
                "scripts/fuzz.sh",
                lambda t: t + f"\n# follow-up: `{hole_q}`\n",
                "red",
            ),
            # (b2) Q176's twin of (b): a ROOT-LEVEL file really is swept by the
            # task half. `CHANGELOG.md` is the target because it is the file
            # the row is about — the only externally-facing document in the
            # project, swept by nothing anywhere until this landed, which is
            # how its line-123 misquotation drifted to D114's site S10.
            #
            # This case does three jobs at once, and the third is the one worth
            # naming: (i) it proves the widening bites; (ii) a later narrowing
            # of CITATION_SCAN turns it red instead of silently un-sweeping the
            # document; and (iii) because the harness treats a missing target
            # as a FAILURE and never a skip, RENAMING `CHANGELOG.md` also goes
            # red. Without (iii) a scan root that names a file — unlike one
            # that names a directory — could vanish under `base.exists()` with
            # nothing to say so.
            (
                "task-citations",
                "CHANGELOG.md",
                lambda t: t + f"\n<!-- follow-up: `{hole_q}` -->\n",
                "red",
            ),
            # (o2) …and by the DECISION half. Both halves are proven on the new
            # surface for the reason Q156 states: Q133 collapsed five constants
            # into one pair precisely so the two sweeps could not disagree, and
            # a widening proven on one half only re-opens that gap from the
            # test side even when the constant is shared.
            #
            # It plants the Q58 line-citation rather than an unresolvable
            # `D<n>` for case (o)'s measured reason: the D namespace is dense
            # with zero holes, so no single-file mutation can make a `D<n>`
            # citation fail.
            (
                "decisions",
                "CHANGELOG.md",
                lambda t: t + "\n<!-- see `docs/format/registry-v1.md:1097` -->\n",
                "red",
            ),
            # (c) tier 2 — the newly-minted-id case. A fresh id is above its
            # domain's ceiling by definition, which is the hole the decision
            # half still has.
            (
                "task-citations",
                "crates/antseal-core/src/anchor/mod.rs",
                lambda t: t + f"\n// follow-up: `{minted_a}`\n",
                "red",
            ),
            # (d) GREEN ARM. The same id, BARE, above the ceiling: the blind
            # spot named in check_task_citations is a decision, not an
            # oversight. Widening tier 2 to bare occurrences turns this case
            # red and forces a re-decision — the idiom of the matrix's "a later
            # milestone's row at gap stays green" case.
            (
                "task-citations",
                "crates/antseal-core/src/anchor/mod.rs",
                lambda t: t + f"\n// follow-up: {minted_a}\n",
                "green",
            ),
            # (e) the suppression register is not vacuous: remove the token it
            # names from the path it names and the entry goes stale. Without
            # this, green could be coming from "that file is not swept at all".
            (
                "task-citations",
                suppressed_path,
                drop_token(suppressed_id),
                "red",
            ),
            # (f) the entry half bites. The heading deleted is one the fixture
            # FOUND, so the case cannot pass if the finder is broken (D109 §6.3).
            (
                "task-entries",
                entry_file,
                lambda t: t.replace(entry_heading + "\n", "", 1),
                "red",
            ),
            # (g) a NEW row without an entry fails. This was the case that
            # proved ROWS_PENDING_ENTRY was closed rather than a blanket; with
            # the register deleted (Q135) it is the unconditional rule, and it
            # is now the only case standing between a row and a missing entry.
            (
                "task-entries",
                "TODO.md",
                lambda t: t + f"\n- [ ] **{minted_q}** (S) fixture\n",
                "red",
            ),
            # (h) GREEN ARM. The struck shape protocol rule 1 mandates is
            # parsed. Under a checkbox-only regex this row disappears, its
            # entry becomes an entry-with-no-row and the case goes red — this
            # is what pins D109 §1.2 and kills the "known standing offset".
            (
                "task-entries",
                "TODO.md",
                lambda t: t.replace(live_row, struck_row, 1),
                "green",
            ),
            # (i) GREEN ARM. A `#### ` sub-heading inside an entry is permitted.
            # Note the fixture is stronger than the tree: it plants the
            # sub-heading in the `<ID> — <title>` grammar, so keying TASK_ENTRY
            # on `^#{2,4}` counts the id twice and this case goes red. The
            # tree's own sub-heading (`#### Q14 freeze checklist — …`) would
            # NOT — see the correction at TASK_ENTRY — so without this planted
            # form the heading level could widen with nothing noticing.
            (
                "task-entries",
                entry_file,
                lambda t: t.replace(
                    entry_heading + "\n",
                    entry_heading + f"\n#### {entry_id} — fixture sub-heading\n",
                    1,
                ),
                "green",
            ),
            # (j) duplicate AND misfiled, in one mutation: the same entry
            # heading copied into another domain's file.
            (
                "task-entries",
                other_file,
                lambda t: t + "\n" + entry_heading + "\n",
                "red",
            ),
            # (k) was the ROWS_PENDING_ENTRY staleness case. Deleted 2026-08-10
            # with the register it exercised (Q135) — see the note at the old
            # constant's site. Case (g) above is what now carries the property
            # it protected: a row without an entry is red, unconditionally.
            # ── Q145 / D113 §6 ───────────────────────────────────────────────
            # (l) red — the row stops naming the decision that assigned it.
            # This is Q145's motivating instance reconstructed: the fixture
            # picks an assignment whose row ALREADY back-cites, so the deletion
            # is a real removal rather than a no-op, and then removes it.
            (
                "decision-owners",
                "TODO.md",
                lambda t: re.sub(
                    r"^(- (?:\[[ xX]\]|~~)\s*\*\*" + owner_id + r"\*\*.*)$",
                    lambda m: re.sub(rf"\bD{owner_dnum}\b", "", m.group(1)),
                    t, count=1, flags=re.M,
                ),
                "red",
            ),
            # (m) red — the assignment names an id that has no row at all. The
            # adjacent defect the same parse catches for free: a ruling owned
            # by an unregistered id is owned by nobody.
            (
                "decision-owners",
                f"{DECISION_DIR}/{owner_doc}",
                lambda t: t.replace(
                    f"**Owner: {owner_id}**", f"**Owner: {ghost_owner}**", 1
                ),
                "red",
            ),
            # (n) GREEN ARM. The four prose `Owner:` shapes the corpus really
            # contains (D113 §1.2) must not be parsed as assignments: the
            # front-matter bullet with a consumer list, D8's quotation of a
            # tail it is DELETING inside an open correction item, D92's
            # domain-letter form, and an indented bold form. Each is planted
            # naming an id that has NO row, so if the regex ever widened to
            # reach one, this case goes red and forces a re-decision instead of
            # a quiet edit — the idiom of green arms (d) and (h).
            (
                "decision-owners",
                f"{DECISION_DIR}/{owner_doc}",
                lambda t: t + (
                    f"\n- **Owner: {ghost_owner} (freeze); consumed by {ghost_owner}**\n"
                    f'and the trailing "Owner: {ghost_owner} with F8/F9/R" removed.\n'
                    f"Size S. Owner: A domain, M2 (before a report renders it).\n"
                    f"   **Owner: {ghost_owner}** (indented, so not an assignment)\n"
                ),
                "green",
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

            # A non-zero exit is NOT enough to call a red case proven. A
            # mutation that makes the script CRASH also exits non-zero, so a
            # red case can pass while the branch it was written for no longer
            # exists. Measured, on this file: delete check 6's
            # unregistered-owner branch and case (m) still "went red" — via a
            # KeyError traceback on the very lookup that branch guards, not via
            # a finding. Under exit-code-only validation that case pinned
            # nothing. So a red case must see the check's OWN annotation, and a
            # traceback fails the harness in either direction.
            annotated = f"::error::check-traceability [{check}]" in result.stderr
            crashed = "Traceback (most recent call last)" in result.stderr

            if crashed:
                print(
                    f"self-test: FAILED — {check} CRASHED on the {expect}-case mutation "
                    f"of {relative}. A traceback is not a finding; the check must report "
                    f"the defect, not fall over on it.",
                    file=sys.stderr,
                )
                ok = False
            elif went_red != (expect == "red"):
                print(
                    f"self-test: FAILED — {check} went "
                    f"{'red' if went_red else 'green'} on the {expect}-case "
                    f"mutation of {relative}",
                    file=sys.stderr,
                )
                ok = False
            elif expect == "red" and not annotated:
                print(
                    f"self-test: FAILED — {check} exited non-zero on the red-case mutation "
                    f"of {relative} but printed no [{check}] annotation, so the exit code "
                    f"came from somewhere other than this check finding the defect",
                    file=sys.stderr,
                )
                ok = False
            elif expect == "red":
                print(f"self-test: ok — {check} goes red when {relative} is corrupted")
            else:
                print(f"self-test: ok — {check} stays green where it must, on {relative}")

        # D109 R7 bullet 3 — the floor and the ceiling are ASSERTED, not
        # observed once. Every token below is real, is in the swept tree, and
        # must never be reported: `A0`, `C0` and `F0` are hex byte values in
        # UTF-8 prose ("Overlong 3-byte encoding: E0 requires A0..=BF next"),
        # killed by the `n >= 1` floor; `P384` is a NIST curve, `U256` an EVM
        # integer width and `F64` minicbor's IEEE-754 discriminant, all killed
        # by the marked-form rule above their domain's ceiling.
        #
        # They are literals on purpose and Q66's derive-it-from-the-tree rule
        # does not reach them: they are precisely NOT task ids, so there is
        # nothing in the register to derive them from. What IS derived, and is
        # asserted first, is their PRESENCE — a token that had left the tree
        # would otherwise let its own case pass by absence.
        #
        # D109 R7 lists `S310` here too. It is not in the swept tree: it lives
        # in `testdata/vectors/v1/crosscheck_cbor.py` and CITATION_SCAN does not
        # include `testdata/`, so it is killed by not being swept at all rather
        # than by the ceiling. Asserting it here would fail.
        present, _marked, _files = sweep_task_surfaces()
        not_citations = ("A0", "C0", "F0", "P384", "U256", "F64")
        for token in not_citations:
            if token not in present:
                print(
                    f"self-test: FAILED — {token} is no longer present in the swept tree, "
                    "so the floor/ceiling assertion would pass by absence",
                    file=sys.stderr,
                )
                ok = False
        clean = subprocess.run(
            [sys.executable, str(tree / "scripts/check-traceability.py"), "--task-citations"],
            capture_output=True,
            text=True,
        )
        output = clean.stdout + clean.stderr
        reported = [t for t in not_citations if re.search(rf"\b{t}\b", output)]
        if clean.returncode != 0:
            print(
                "self-test: FAILED — --task-citations is not green on the unmutated tree, "
                "so the floor/ceiling assertion cannot run; fix the check first",
                file=sys.stderr,
            )
            ok = False
        elif reported:
            print(
                f"self-test: FAILED — {', '.join(reported)} reported as task citations; "
                "they are hex bytes, a curve name, an integer width and a codec "
                "discriminant, and the floor/ceiling rules exist to skip them",
                file=sys.stderr,
            )
            ok = False
        else:
            print(
                "self-test: ok — task-citations skips all "
                f"{len(not_citations)} non-citation tokens, each asserted present first"
            )

    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
