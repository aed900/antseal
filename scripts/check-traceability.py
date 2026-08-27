#!/usr/bin/env python3
"""Checks that a documented claim is still true of the tree.

Ten checks live here, and they are the same shape: something written down in
prose asserts a fact about the repository, and nothing else verifies it.

    --freeze-boundary   The D84 §7 v1-freeze-boundary rows are byte-identical
                        across every file that carries a copy (Q37).
    --matrix            Every test named by the verification-coverage
                        traceability matrix actually resolves (Q13).
    --decisions         Every decision cited in code or in a normative doc
                        resolves to a record, a registered alternative home,
                        or an open register entry; every decision ALLOCATED
                        in TODO.md's register has one of those three homes
                        whether or not anything cites it; and nothing cites
                        the frozen wire registry by line number (Q57, Q58,
                        D142).
    --task-citations    Every task id cited in code, in a normative doc or in
                        a gate script resolves to a row in TODO.md's register
                        (Q85).
    --task-entries      Every row in TODO.md has a detail entry in
                        tasks/<domain>.md, and every entry has a row (Q85).
    --decision-owners   Every `**Owner: <ID>**` assignment in a RESOLVED
                        decision names a registered task whose TODO.md row
                        names that decision back (Q145).
    --decision-index    Every `docs/decisions/D*.md` record has exactly one
                        row in the decision index, whose link resolves to that
                        record and whose status word and date are the
                        record's, in ascending id order (Q180, D119).
    --machine-paths     No LIVE surface names a developer's machine: an
                        absolute home path in a scanned file must use a
                        reserved placeholder name, and MVP-SPEC.md's one
                        registered divergence is pinned present rather than
                        exempted (Q65, D144).
    --doc-links         Every markdown link whose target is a relative `.md`
                        path resolves, from the containing file's own
                        directory, to a file that exists; and the corpus has
                        not silently collapsed, asserted by two floors
                        (Q249, D159).
    --decision-ledger-debt
                        Every decision record whose edit list names
                        docs/instrument-ledger.md has at least one ledger
                        entry attributed to it in a `·`-delimited field, so
                        a resolved ruling whose ledger edits were never
                        executed is visible instead of being found by hand
                        two waves later; the subject count is floored so a
                        drifted heading regex cannot pass vacuously
                        (D162 §2 R6).

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
    "docs/user/format-stability.md",
]

# The source of truth. Every copy in BOUNDARY_COPIES is cut from here; if this
# section moves, the copies are stale by definition and the check must say so.
# ("Both" until 2026-08-17, when Q27's page made it three — the word was a
# count in disguise, which is why it went stale the moment the list grew.)
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

# The last milestone whose review has PASSED — not the one being built, and
# not "the milestone under review", which is the reading that sent Q165 to M2
# (D118 §5). **What moves it is the milestone-gate row for the milestone that
# just passed**: TODO.md rule 4 lists the acts that close a passing gate and
# this is one of them. Q14 was M0's gate row; Q34 is M4's.
#
# Nothing compares this line to TODO.md's Current-focus block, and D122
# refuses such a check on measurement, not taste: the block names the
# milestone IN PROGRESS ("M2" today) where this names the last one PASSED
# ("M1"), so equality is red against a correct constant; and across this
# project's history that line has used five grammars, in which the same token
# position means the current milestone in three and the finished one in two.
#
# It is a constant rather than a required flag on purpose: a gate that only
# runs when someone remembers to pass `--milestone` is the same unenforced
# prose this check exists to replace. `--milestone` overrides it for a one-off
# question ("would M1 pass today?").
#
# The rule is cumulative, so `M1` gates M0's rows and M1's forever
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
# M1 -> M2 on 2026-08-11 (Q236 / D127) — the first bump owned by a gate row,
# landed in the same change as the register's first ACCEPTED_NON_COVERED
# entry, because the checker reds either half without the other
# (bump-atomic by construction, D127 §1e).
# M2 -> M3 on 2026-08-16 (Q237) — the second bump owned by a gate row, and
# the first that exempts nothing: every row at or before M3 already read
# `covered` when the review ran, so ACCEPTED_NON_COVERED is empty on both
# sides of this move and no cell was re-read to make the bump possible. It
# gates M3's four rows forever alongside M0's, M1's and M2's; M4's three
# stay free to read `deferred` until Q34's review, which is the cumulative
# rule doing exactly what it is for.
CURRENT_MILESTONE = "M3"

# The full vocabulary, per the matrix's own "Status vocabulary" note. Anything
# else is a typo, and a typo'd status at a not-yet-gated milestone would
# otherwise be invisible until that milestone's review.
STATUS_VOCABULARY = ("covered", "gap", "deferred")

# Rows allowed to sit at a non-`covered` status inside a gated milestone, as
# `id -> (status, reason)`. An entry here is a milestone shipping with a
# known hole - a decision worth writing down rather than a lint to be
# silenced - so every entry requires a recorded ruling (D118 §5) and carries
# its closure trigger. Stale entries are themselves a failure - see
# `check_matrix` - so this cannot rot into a permanent mute.
#
# It stayed empty through Q165 / D118, deliberately: eleven rows read
# `deferred` at or before M2 and this register was the obvious place to put
# the survivor (`V7.1`, whose real calendar cycle was run by hand with curl
# rather than by antseal). It was the wrong place THEN: M2 had not shipped,
# so there was no known hole to accept yet, and an entry would have silenced
# `V7.1` at the M2 review - the one moment it exists to speak. That moment
# arrived at Q236's review, the row spoke, and D127 (2026-08-11) answered it
# on the record. The entry below is the register's first, at the price D118
# §5 set: a decision document, a named closure trigger, and machine-enforced
# removal. That price is the precedent - an entry for work the project can
# perform itself is not covered by it (D127 §3 iii).
# EMPTY AGAIN AS OF 2026-08-12, and the register's first entry lasted one
# day. `V7.1` was entered here at the M2 review (D127, 2026-08-11) because
# antseal's A13 submit path had never spoken to a real calendar; D127 §5 set
# the closure predicate - submits accepted through the client AND >=1
# CLIENT-SUBMITTED commitment upgraded through the client - and required the
# cell's flip and this entry's removal to land in ONE change, which is what
# removed it.
#
# Both halves ran under separate, freshly recorded maintainer consent, and
# the composed cycle D127 §2 said had never run is the thing that closed it:
# 2026-08-11T23:39-23:40Z, 8 of 8 pending-accepted through A13's own
# `submit_to_calendars` at all four DEFAULT_OTS_CALENDARS pool hosts - the
# set D127 measured the product had never contacted in any mode - and
# 2026-08-12, 6 of those same 8 upgraded through A14's `poll_upgrade`
# (alice, bob, catallaxy for both golden-vector digests; the two eternitywall
# pendings honestly `not-yet-confirmed` and left re-pollable). Captures:
# `testdata/anchors/A25-wave17-cycle/` and its `upgraded/` subdirectory.
#
# The mechanism outlived its first use, which was the point of paying D118
# §5's price for it: a decision document, a named closure trigger, and
# machine-enforced removal. An entry for work the project can perform itself
# is still not covered by that precedent (D127 §3 iii).
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


def gated_milestones(gated_through: str) -> tuple[str, ...]:
    """Every milestone at or before `gated_through`.

    Cumulative on purpose: at the M1 review, M0's rows must *still* read
    covered. A gate that only looked at the current milestone would let an
    earlier one silently regress to `gap` the moment its own review passed.
    """
    if gated_through not in MILESTONE_ORDER:
        raise ValueError(
            f"unknown milestone {gated_through!r}; known: {', '.join(MILESTONE_ORDER)}"
        )
    return MILESTONE_ORDER[: MILESTONE_ORDER.index(gated_through) + 1]


def check_matrix(failures: Failures, gated_through: str = CURRENT_MILESTONE) -> None:
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
        gated = gated_milestones(gated_through)
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
                    f"{status!r}, but {gated_through}'s review has passed and every row at or "
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
            f"no rows at or before {gated_through} — the status gate would be vacuous. "
            "Either the milestone column stopped parsing or CURRENT_MILESTONE names a "
            "milestone this matrix has no rows for.",
        )

    if not failures:
        summary = ", ".join(f"{k}={v}" for k, v in sorted(milestones.items()))
        print(
            f"[{check}] ok — {len(rows)} rows over {len(bullets)} spec bullets, "
            f"{checked} references resolved ({summary}); status gate: all {gate_rows} "
            f"row(s) at or before {gated_through} read 'covered'"
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
# SUFFIXES ARE A DIRECTORY RULE (Q190/D123, 2026-08-11). A literal file entry
# above is read as itself and is NOT filtered by CITATION_SUFFIXES; a
# directory entry is walked and filtered. This paragraph replaces a HAZARD
# note written by Q176 in the same act that created the hazard — "an entry is
# filtered by CITATION_SUFFIXES like any other path, so naming a root file
# whose suffix is not in that set adds a scan root that reads nothing at all"
# — which was TRUE of the old semantics and named two of the three files then
# in that state. Measured before the change: naming the files with the suffix
# set unchanged moved the swept count 359 -> 359. Adding .toml instead reached
# SIX crates/*/Cargo.toml and NOT deny.toml, because a root-level file is
# reached only by being named; and no suffix can ever reach a dotfile, whose
# suffix is the empty string. Do NOT "simplify" this back to one filter.
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
    # R23 lands the first citation-bearing file here: the page template cites
    # the decisions that shaped it, and before this entry nothing checked those
    # citations resolve (D131 §5 R7.4 — the fourth unswept directory Q210
    # observed). A DIRECTORY entry, so D123's per-entry rule filters it by
    # suffix; measured cost of the pair of additions is 420 -> 421 files with
    # zero collateral, against D123's refused .toml route at 359 -> 377 with 15.
    "verifier-web",
    # Q23-Q27 land the M4 user-facing documentation set here, and those pages
    # cite decision and task ids as their evidence. D139 §2 R1 admitted
    # docs/user/ to the COPY lint; without this entry it would be admitted to
    # nothing else, so a decision id that stops resolving on a page a stranger
    # reads would be caught by no check at all. Same shape and same reason as
    # the verifier-web entry above. A DIRECTORY entry, so D123's per-entry rule
    # filters it by suffix.
    "docs/user",
    # Root-level files, swept as themselves (Q176).
    "CHANGELOG.md",
    "README.md",
    "CONTRIBUTING.md",
    "MVP-SPEC.md",
    # Root-level files whose suffix is outside CITATION_SUFFIXES, reachable
    # only under the literal-entry rule above (Q190/D123). Measured 2026-08-11:
    # 57/7/2 distinct task ids and 19/4/3 decision ids in the three with
    # suffixes, 6 and 6 in the two dotfiles; all resolve.
    #
    # R7 — the asymmetry these five create, stated where it is created: the
    # ROOT manifest is swept because it is NAMED here, and the six MEMBER
    # manifests under crates/ are not, because .toml is not a directory-walk
    # suffix. That looks arbitrary and is not: whether crates/ should gain
    # .toml is a separate question with its own measurement (62 distinct task
    # ids across the six, all allocated, none above ceiling), deliberately not
    # answered as a side effect of this one.
    "Cargo.toml",
    "deny.toml",
    "requirements-crosscheck.txt",
    ".gitattributes",
    ".gitignore",
]
CITATION_SUFFIXES = {".rs", ".md", ".json", ".py", ".sh", ".mjs", ".html"}

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
    # D125 was ruled in session and given no record DELIBERATELY, which is a
    # fact on the record rather than an inference: `5a21ced` wrote TODO.md,
    # docs/instrument-ledger.md and docs/waves/wave-16-brief.md and touched
    # docs/decisions/ not at all, and the register row it wrote says "the
    # operative text lives in protocol rule 8 + docs/instrument-ledger.md +
    # docs/waves/wave-16-brief.md rather than a decision doc — deliberately,
    # under its own rule". This entry is where that fact becomes readable by
    # the check instead of only by a human reading TODO.md:990. The first
    # entry whose home is a section of TODO.md; see D142 §2 R1 for why that
    # is the honest home and not a shortcut.
    125: "TODO.md protocol rule 8 — the starvation rule's normative text — executed in docs/instrument-ledger.md; ruled in session 2026-08-11 (5a21ced), deliberately recordless",
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


# ── the self-test's decision subject, constructed rather than found ──────────
#
# These three live at module level, not inside `self_test()`, for a reason the
# harness has paid for twice: a fixture whose correctness cannot be exercised
# against a CONSTRUCTED state can only ever be exercised against the state the
# tree happens to be in, and `--self-test` may not be run mid-wave (it stages a
# full copy of a tree other lanes are writing). `prove_lowest_unhomed_mint()`
# below builds its states on disk and can be called directly.


def decision_homes(tree: pathlib.Path) -> tuple[set[int], set[int]]:
    """`(allocated, recorded)` as `tree` states them: the ids its register
    allocates, and the ids its record directory carries as files.

    `tree` is a parameter and not `ROOT` because the subject is a staged copy —
    and because a helper that can only read the live tree cannot be shown
    correct on a tree that does not exist yet.
    """
    register = (tree / "TODO.md").read_text(encoding="utf-8")
    allocated = {int(n) for n in re.findall(r"^- \[[ x]\] \*\*D(\d+)\*\*", register, re.M)}
    recorded = {
        int(head.group(1))
        for path in (tree / DECISION_DIR).glob("D*.md")
        if (head := re.match(r"D(\d+)-", path.name))
    }
    return allocated, recorded


def lowest_unhomed_decision_id(tree: pathlib.Path) -> int:
    """The LOWEST id above `tree`'s register ceiling that no home claims.

    ══ WHAT THIS EXISTS TO SURVIVE ═════════════════════════════════════════
    `plant_an_unrecorded_decision()` needs an id with three properties, and
    each one is load-bearing for a different arm:

      P1  `minted > max(allocated)` — `check_decisions` skips any cited number
          above the register's ceiling, so the planted citation is INERT in the
          baseline and arms only when the mutation adds a row for it.
      P2  `minted` has no record and no `DECISIONS_HOMED_ELSEWHERE` entry — or
          the RED arm's resolved row would be green for a perfectly legitimate
          reason and would prove nothing.
      P3  every id BETWEEN the ceiling and `minted` is claimed by a record or a
          home — because the mutation RAISES the ceiling to `minted`, and any
          id in that window that is cited and unresolved would come into bound
          with it. The RED arm would still pass (a delta only needs one added
          finding) but the GREEN arm asserts the findings do NOT change, and it
          would fail on a finding that has nothing to do with the case.

    The shipped fixture minted `max(allocated) + 1` and RAISED when that id
    already carried a record. That guard fires in exactly the window
    `D119 RULING 6` declares ROUTINE — a record file landing before the
    registrar applies its index row, i.e. every planning wave — so on
    2026-08-18, with `D141`–`D144` on disk and the register allocating through
    `D140`, `--self-test` raised before a single arm ran, `ci-lanes.sh`'s
    `lane_traceability` returns on that failure, and the `traceability`
    required context went red by traceback.

    THIS IS THE Q252 SHAPE ONE GUARD OVER. Q252 stopped the fixture SEARCHING
    the register for a subject, because draining the register is the goal and a
    fixture may not depend on the tree staying unhealthy. The repair then
    CONSTRUCTED the subject — and left a collision guard that depends on the
    tree not being mid-act. Registering `D141`–`D144` would clear it today and
    would not fix it: the next planning wave reopens the same window.

    ══ THE TWO DESIGNS THAT WERE REFUSED, AND WHY ══════════════════════════
    **Scope the guard to allocated ids.** Refused twice over. `max(allocated) +
    1` is never in `allocated`, so a guard scoped that way can never fire —
    this project's dominant defect class, written into a repair for it. Worse,
    it does not remove the collision, it SILENCES it: with a record already on
    disk for the minted id, the red arm's row is legitimately green and the
    harness reports *"decisions added no finding on the red-case mutation of
    TODO.md"* — a message that blames the check for the fixture's collision. A
    loud raise traded for a wrong-arm failure is not an improvement.

    **Mint above `max(allocated ∪ recorded ∪ homed)`.** Satisfies P1 and P2 and
    breaks P3. One hand-written record far above the ceiling — `D900` in a
    tree whose register stops at `D140` — pushes the mint to `D901` and opens
    a 760-wide window in which any cited, unrecorded id changes the green
    arm's findings. Correct in the common case, silently fragile in the
    uncommon one.

    ══ WHAT IS TAKEN ═══════════════════════════════════════════════════════
    The lowest free id above the ceiling. P1 by the starting point, P2 by the
    loop's exit condition, and P3 by its MINIMALITY: every number the loop
    steps over is a number some home claimed, which is precisely the set
    `check_decisions` skips. The window the mutation opens is therefore
    provably inert however many unregistered records are on disk, and it is one
    id wide whenever the tree is clean.

    Proven, not asserted: `prove_lowest_unhomed_mint()` constructs four
    register/record states on disk — four unregistered records, none, a record
    far above the ceiling, and a HOMED id above it — and requires P1, P2 and
    P3 on each.
    """
    allocated, recorded = decision_homes(tree)
    if not allocated:
        raise AssertionError(
            "self-test: TODO.md's register allocates no decision id, so there is "
            "no ceiling to mint above. `check_decisions` reports that state "
            "itself — 'the bound is vacuous' — and it is a register failure, not "
            "a fixture failure"
        )
    claimed = allocated | recorded | set(DECISIONS_HOMED_ELSEWHERE)
    number = max(allocated) + 1
    while number in claimed:
        number += 1
    return number


def prove_lowest_unhomed_mint(scratch: pathlib.Path) -> list[tuple[bool, str]]:
    """Require `lowest_unhomed_decision_id()`'s three properties on four
    CONSTRUCTED register/record states. Returns `(passed, sentence)` per state.

    Every state is WRITTEN here and none is read from the live tree, which is
    the whole point: a fixture that measures whatever the tree happens to be
    can only prove what the tree happens to be, and the state that broke this
    fixture — records on disk the register has not allocated yet — is a state
    the tree occupies for a few hours per wave.

    The ceiling sits above `DECISIONS_HOMED_ELSEWHERE`'s highest id in the
    first three states so that the homed set cannot quietly decide their
    answers; the fourth puts it below, so that it does.
    """
    homed = set(DECISIONS_HOMED_ELSEWHERE)
    if not homed:
        return [(False, "DECISIONS_HOMED_ELSEWHERE is empty, so states 1 and 4 cannot be built")]
    high = max(homed) + 15
    low = min(homed) - 1

    #  (name, allocated ceiling, extra recorded ids, the fact that makes the
    #   state the state it claims to be)
    states: list[tuple[str, int, set[int], str]] = [
        (
            "four unregistered records on disk (the mid-act window, D119 RULING 6)",
            high,
            {high + 1, high + 2, high + 3, high + 4},
            "ceiling+1 is already recorded — this is the live failure of 2026-08-18",
        ),
        ("no unregistered record anywhere", high, set(), "ceiling+1 is claimed by nothing"),
        (
            "a hand-written record far above the ceiling",
            high,
            {high + 760},
            "the far record must NOT drag the mint up with it",
        ),
        (
            "a HOMED id immediately above the ceiling",
            low,
            set(),
            "ceiling+1 is claimed by DECISIONS_HOMED_ELSEWHERE, not by a file",
        ),
    ]

    results: list[tuple[bool, str]] = []
    for index, (name, ceiling, extra, why) in enumerate(states, 1):
        tree = scratch / f"mint-state-{index}"
        (tree / DECISION_DIR).mkdir(parents=True, exist_ok=True)
        (tree / "TODO.md").write_text(
            "".join(
                f"- [x] **D{n}** constructed by prove_lowest_unhomed_mint, state {index}.\n"
                for n in range(1, ceiling + 1)
            ),
            encoding="utf-8",
        )
        # Records for the two ids below the ceiling exist so `recorded` is never
        # empty by accident; the interesting members are `extra`.
        for n in {ceiling - 1, ceiling} | extra:
            (tree / DECISION_DIR / f"D{n}-constructed.md").write_text("", encoding="utf-8")

        allocated, recorded = decision_homes(tree)
        claimed = recorded | homed
        try:
            minted = lowest_unhomed_decision_id(tree)
        except AssertionError as exc:
            results.append((False, f"state {index} ({name}): raised — {exc}"))
            continue

        problems = []
        if minted <= max(allocated):
            problems.append(f"P1 violated: D{minted} is not above the ceiling D{max(allocated)}")
        if minted in claimed:
            problems.append(f"P2 violated: D{minted} already has a record or a registered home")
        dragged = sorted(n for n in range(max(allocated) + 1, minted) if n not in claimed)
        if dragged:
            problems.append(
                "P3 violated: the ceiling bump would drag "
                + ", ".join(f"D{n}" for n in dragged[:5])
                + " into bound, and an unresolved citation of any of them changes the "
                "green arm's findings"
            )
        # The state must actually BE the state it claims, or its verdict is
        # vacuous — the assertion-that-cannot-fail rule applied to fixtures.
        naive = max(allocated) + 1
        if index in (1, 4) and naive not in claimed:
            problems.append(f"state is vacuous: D{naive} is claimed by nothing, so the shipped mint would not have collided")
        if index == 2 and (naive in claimed or minted != naive):
            problems.append(f"state is vacuous or the healthy case moved: D{naive} vs minted D{minted}")
        if index == 3 and max(recorded) <= minted:
            problems.append("state is vacuous: the far-above record is not above the mint")

        if problems:
            results.append((False, f"state {index} ({name}): " + "; ".join(problems)))
        else:
            results.append(
                (
                    True,
                    f"state {index} ({name}): ceiling D{max(allocated)}, "
                    f"{len(recorded)} record(s) on disk, minted D{minted} — {why}",
                )
            )
    return results


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

    # The property the constant above claims for itself — "leaving a decision
    # out of it is a failure" — asserted independently of what anything
    # cites. Until D142 this check could only see an id a swept file
    # mentioned, so D125 sat allocated, unrecorded, unhomed and closed for
    # seven days while this lane printed ok; the three numbers on that ok
    # line sum to one less than the register allocates, and nothing
    # subtracted them. Set difference, never `len(a) - len(b) - len(c)`: the
    # counts are equal today and a count is the artefact this project keeps
    # watching go stale.
    for number in sorted(allocated - recorded - set(DECISIONS_HOMED_ELSEWHERE) - still_open):
        failures.add(
            check,
            f"D{number} is ALLOCATED in TODO.md's register and has no home: no "
            f"record under {DECISION_DIR}/, no entry in DECISIONS_HOMED_ELSEWHERE, "
            f"and no open row. Nothing needs to cite it for this to be wrong — "
            f"give it a record, or name its real home in the constant.",
        )

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
        # Q176 + Q190/D123 — an entry may be a directory (swept recursively
        # and filtered by CITATION_SUFFIXES) or a single FILE (swept as
        # itself, UNFILTERED). Two branches because they answer different
        # questions: a tree walk has no opinion about what it finds, so it
        # needs the suffix set; a named file was already deliberated in a
        # reviewed constant, so a second gate is owed to nobody. Filtering a
        # named file is what made deny.toml, .gitattributes and .gitignore
        # scan roots that read nothing at all. Without the branch at all, a
        # filename here is a silent no-op: `Path.rglob` on a non-directory
        # yields nothing. Both sweeps carry these lines identically (D116 R2);
        # see the note at CITATION_SCAN.
        literal = base.is_file()
        for path in ([base] if literal else base.rglob("*")):
            if not path.is_file() or (not literal and path.suffix not in CITATION_SUFFIXES):
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
        # D142 R2 — the shipped line printed three of the four numbers and
        # never the fourth, so the subtraction that finds an allocated id with
        # no home was available to a reader on every green run and performed
        # by nobody. `recorded & allocated` and not `recorded`: the glob also
        # counts records whose id the register has not allocated yet (the
        # routine mid-act window, D119 RULING 6), and printing those against
        # an allocation total is what made the sum unreadable. `homed` is NOT
        # intersected, which is the same hazard one set over: D142 §1.1
        # MEASURED `homed - allocated = []` and every falsifier re-checks it,
        # but nothing ENFORCES it, so an entry for an unallocated id would put
        # this sum above `len(allocated)` with no check saying so. Left as
        # D142 §2 R2 specified it; the repair is `len(set(...) & allocated)`
        # here plus an arm, and it is a decision, not an edit.
        print(
            f"[{check}] ok — every one of {len(allocated)} allocated decision ids "
            f"has a home ({len(recorded & allocated)} records, {homed} homed "
            f"elsewhere, {len(still_open)} still open); {len(in_bound)} distinct "
            f"decisions cited across {n_files} files, all resolve; no line-number "
            f"citations into the registry"
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
        # Q176 + Q190/D123 — an entry may be a directory (swept recursively
        # and filtered by CITATION_SUFFIXES) or a single FILE (swept as
        # itself, UNFILTERED). Two branches because they answer different
        # questions: a tree walk has no opinion about what it finds, so it
        # needs the suffix set; a named file was already deliberated in a
        # reviewed constant, so a second gate is owed to nobody. Filtering a
        # named file is what made deny.toml, .gitattributes and .gitignore
        # scan roots that read nothing at all. Without the branch at all, a
        # filename here is a silent no-op: `Path.rglob` on a non-directory
        # yields nothing. Both sweeps carry these lines identically (D116 R2);
        # see the note at CITATION_SCAN.
        literal = base.is_file()
        for path in ([base] if literal else base.rglob("*")):
            if not path.is_file() or (not literal and path.suffix not in CITATION_SUFFIXES):
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


# ── check 7: the decision index says what the records say (Q180, D119) ──────
# `docs/decisions/README.md` opens by claiming, in one sentence, that it
# carries exactly one row per record, in ascending id order, with each row's
# status and date taken from that record. Nothing verified any of it, and every
# clause of it was false when D119 measured: 29 records had no row at all, and
# one row diverged from its record in both status and date — in the direction
# nobody expects, the INDEX right and the RECORD stale for fourteen days, which
# is why RULING 2 had to name the record authoritative before this check could
# mean anything. A claim a document makes about itself, with no instrument, is
# the shape every check in this file exists to end.
#
# ══ THE DOMAIN IS THE GLOB, AND IT IS THE ONE THING THIS CHECK COULD GET
#    CATASTROPHICALLY WRONG (D119 §1.4 and RULING 3) ═══════════════════════
# The natural phrasing — "every id in TODO.md's Decision register has an index
# row" — is written over the wrong artefact, and it is the phrasing Q180's `Do`
# gestures at. The register's domain is the ID SPACE: it ALLOCATES, so it
# legitimately carries ids that have no file. Measured when D119 ruled: 18 of
# its ids had no file, 5 homed in `DECISIONS_HOMED_ELSEWHERE` and **13 still
# open for decisions nobody has written**. A check over that id space is red on
# 47 ids and demands index rows for documents that do not exist.
#
# So `allocated_decision_ids()` is deliberately NOT read here — and neither is
# `open_decision_ids()`, which is the subtler half. Being open in the register
# is exactly what lets `check_decisions()` stay silent about an id, and
# importing that rule here would make an unwritten decision's missing row
# unfalsifiable in a check whose whole subject is which files exist.
#
# Three artefacts, three domains, each authoritative over its own: the register
# holds the id space, the RECORD holds the decision, and this index holds the
# FILES ON DISK. This check reads the third and compares it to the second.
#
# It does not reopen D109 §3.3. `docs/decisions/` stays out of `CITATION_SCAN`
# and nothing here reads a citation: it reads the index table's structure and
# each record's `- **Status`/`- **Date` lines, nothing else. A record stays
# free to PROPOSE ids the orchestrator may renumber or decline.

INDEX = f"{DECISION_DIR}/README.md"

# A row of the index table: `| [D<n>](<file>) | <title> | <status> | <date> |`.
INDEX_ROW = re.compile(r"^\| \[D(\d+)\]\(([^)]*)\) \|")

# Cell boundaries — NOT `str.split("|")`, and not `split_row()` above.
# Measured on the table this landed against: 5 of its 106 rows carry `\|`
# INSIDE a cell (a shell `||`, a JSON `string \| object`, a CLI
# `generate\|import`, and a needle that is itself a table row), and Markdown
# renders a backslash-escaped pipe as content, not as a boundary. A plain split
# reads those five rows as 7, 7, 10, 7 and 8 fields, shifts their status and
# date cells left, and reports every one of them — a check red on arrival, on
# five rows nobody wrote wrong. The lookbehind is what makes the escape its
# author wrote mean what it renders as; an UNescaped pipe still shifts the
# cells, and that is the defect this check is entitled to report.
INDEX_PIPE = re.compile(r"(?<!\\)\|")

# The leading word of a status, upper-cased: `RESOLVED` out of `RESOLVED
# (recorded deferral)`, `RESOLVED — …` and `RESOLVED. The register's lean …`
# alike. Whole-cell equality is not the property: the index summarises in a
# terse cell what the record spends a paragraph on, so whole-cell equality
# would be red on all 106 rows and the check would have to be deleted. What has
# to agree is the VERDICT. The trailing-period form is not hypothetical — D36
# and D37 carry it, and a first-whitespace-token split reports both.
INDEX_STATUS_WORD = re.compile(r"[A-Za-z][A-Za-z-]*")

# Both status-block spellings, on purpose. D119 §1.9 measured 98 records in the
# house form and 2 in `- **Status**:`, and §5 step 2 normalised those two — so
# the corpus is uniform today and this could be strict. It is not, because
# minting a spelling rule here is exactly what RULING 5 refuses to do twice:
# the `Owner`/`Owning task(s)` field already has four coexisting spellings and
# no rule, Q162 owns that question, and a Status-field rule invented as a side
# effect of a row-mirroring check is how the fifth spelling of the next field
# gets born. This check's subject is whether the index tells the truth about a
# record, not how the record spells its own front matter.
RECORD_STATUS = re.compile(r"^- \*\*Status\*{0,2}:\s*(.*)$", re.M)
RECORD_DATE = re.compile(r"^- \*\*Date\*{0,2}:\s*(\d{4}-\d{2}-\d{2})", re.M)


def index_cells(line: str) -> list[str] | None:
    """The cells of one index row, stripped, or None if `line` is not a row."""
    if not INDEX_ROW.match(line):
        return None
    return [cell.strip() for cell in INDEX_PIPE.split(line.rstrip())[1:-1]]


def status_word(text: str) -> str:
    """The leading status word of `text`, upper-cased; `""` if it has none."""
    match = INDEX_STATUS_WORD.search(text)
    return match.group(0).upper() if match else ""


def check_decision_index(failures: Failures) -> None:
    check = "decision-index"

    records: dict[int, pathlib.Path] = {}
    for path in sorted((ROOT / DECISION_DIR).glob("D*.md")):
        match = re.match(r"D(\d+)-", path.name)
        if match:
            records[int(match.group(1))] = path
    if not records:
        # The glob IS the domain (see the note above), so a glob that matches
        # nothing is not a green tree — it is a check with no subject, and the
        # likeliest cause is that `DECISION_DIR` moved.
        failures.add(
            check,
            f"no decision record matched {DECISION_DIR}/D*.md, so this check has no "
            f"domain at all. The glob is the domain — see the note above the check.",
        )
        return

    index = ROOT / INDEX
    if not index.is_file():
        failures.add(check, f"{INDEX} does not exist, so {len(records)} record(s) are indexed by nothing")
        return
    text = index.read_text(encoding="utf-8")

    rows: list[tuple[int, int, str, list[str], str]] = []
    for line_no, line in enumerate(text.splitlines(), 1):
        cells = index_cells(line)
        head = INDEX_ROW.match(line)
        if cells is None or head is None:
            continue
        rows.append((line_no, int(head.group(1)), head.group(2), cells, line))
    if not rows:
        failures.add(
            check,
            f"{INDEX} holds no parseable index row. Either the table was emptied or "
            f"its row shape changed under this check, and both are silent otherwise.",
        )
        return

    # (a) one row per record, in both directions.
    seen: dict[int, list[int]] = {}
    for line_no, number, _target, _cells, _line in rows:
        seen.setdefault(number, []).append(line_no)

    for number in sorted(set(records) - set(seen)):
        failures.add(
            check,
            f"{INDEX}: D{number} has a record ({records[number].name}) and no row in "
            f"the index. Every record gets exactly one row, in ascending id order, and "
            f"the act that commits the record is the act that adds it (D119 RULING 6).",
        )
    for number in sorted(set(seen) - set(records)):
        failures.add(
            check,
            f"{INDEX}:{seen[number][0]}: the row for D{number} names a decision with no "
            f"record under {DECISION_DIR}/. The index never carries an id without a file "
            f"— allocating ids is TODO.md's register's job, not this file's "
            f"(D119 RULING 1).",
        )
    for number, at in sorted(seen.items()):
        if len(at) > 1:
            failures.add(
                check,
                f"{INDEX}: D{number} has {len(at)} rows (lines "
                f"{', '.join(str(n) for n in at)}); exactly one is the rule, and two rows "
                f"are two statuses waiting to disagree",
            )

    # (c) ascending id order. Strictly less, so an adjacent duplicate is
    # reported once, by the branch above, and not twice.
    previous: int | None = None
    for line_no, number, _target, _cells, _line in rows:
        if previous is not None and number < previous:
            failures.add(
                check,
                f"{INDEX}:{line_no}: D{number}'s row follows D{previous}'s, so the table "
                f"is not in ascending id order. Insert by id — a reader scanning for a "
                f"decision stops at the first id past the one they want.",
            )
        previous = number

    for line_no, number, target, cells, _line in rows:
        # (b) the link resolves, and it resolves to the record it names.
        if len(cells) != 4:
            failures.add(
                check,
                f"{INDEX}:{line_no}: D{number}'s row splits into {len(cells)} cells, not "
                f"4 (ID, Title, Status, Date). An unescaped `|` inside a cell renders as "
                f"a column break and shifts every cell after it; write it `\\|`.",
            )
            continue
        destination = ROOT / DECISION_DIR / target
        if not destination.is_file():
            failures.add(
                check,
                f"{INDEX}:{line_no}: D{number}'s link target `{target}` does not exist "
                f"under {DECISION_DIR}/. This is the page GitHub renders at the "
                f"directory URL, so a dead link here is a dead link on the front page.",
            )
            continue
        if number in records and destination.resolve() != records[number].resolve():
            failures.add(
                check,
                f"{INDEX}:{line_no}: D{number}'s link resolves to `{target}`, which is "
                f"not D{number}'s record ({records[number].name}). It resolves, so link "
                f"existence alone never sees it, and the row then annotates one decision "
                f"while pointing at another.",
            )
            continue

        # (d) the status token and the date are the record's. The RECORD
        # decides (D119 RULING 2) — including when the index is the correct one
        # and the record is the stale one, which is the case that produced this
        # check. Correcting the record, in D117's form, is the repair; editing
        # the row to agree with a wrong record is how the defect gets laundered.
        record = records[number]
        try:
            body = record.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError) as exc:
            failures.add(check, f"{record.name} could not be read to check D{number}'s row: {exc}")
            continue
        status_line = RECORD_STATUS.search(body)
        date_line = RECORD_DATE.search(body)
        if status_line is None or not status_word(status_line.group(1)):
            failures.add(
                check,
                f"{record.name}: no parseable `- **Status: <word> …**` line, so D{number}'s "
                f"index row is checked against nothing. A record whose status cannot be "
                f"read is a record whose row cannot be wrong.",
            )
            continue
        if date_line is None:
            failures.add(
                check,
                f"{record.name}: no parseable `- **Date: YYYY-MM-DD**` line, so D{number}'s "
                f"index row date is checked against nothing",
            )
            continue
        recorded_status = status_word(status_line.group(1))
        row_status = status_word(cells[2])
        if row_status != recorded_status:
            failures.add(
                check,
                f"{INDEX}:{line_no}: D{number}'s row reads status `{row_status or '(none)'}` "
                f"where {record.name} reads `{recorded_status}`. The RECORD decides "
                f"(D119 RULING 2): correct it there under D117's form and let the row "
                f"follow, and if the record is the stale one, correct the record first.",
            )
        if cells[3] != date_line.group(1):
            failures.add(
                check,
                f"{INDEX}:{line_no}: D{number}'s row is dated {cells[3] or '(empty)'} where "
                f"{record.name} reads {date_line.group(1)}. Same rule: the record decides.",
            )

    if not failures:
        # Both counts, per D116 R3: a check that silently narrowed its glob — the
        # one mistake this check's domain makes expensive — would otherwise be
        # invisible in a green log, which is a green lane saying nothing about
        # how much it read.
        print(
            f"[{check}] ok — {len(rows)} index row(s) in {INDEX} against {len(records)} "
            f"record(s) matching {DECISION_DIR}/D*.md, one apiece and in ascending id "
            f"order; every link resolves to its own record, and every status word and "
            f"date is the record's"
        )


# ── check 8: no LIVE instruction names a developer's machine (Q65, D144) ────
#
# D144 §2 R2 draws the class boundary this check enforces, and §2 R4 states the
# rule. Inside the LIVE surface — text that instructs a reader about the
# repository as it is now — an absolute home path may name only a RESERVED
# PLACEHOLDER. Outside it the same string is captured evidence: of the 61 lines
# carrying `/home/deb` on 2026-08-18, **50** are transcripts, `file(1)` output,
# stack traces, dated measurement tables and decision records, and **8** more
# are the register rows that MANDATE this scrub — six of which record this very
# work. A lint over those would demand the deletion of its own mandate, and
# rewriting them would not remove a disclosure, it would falsify a measurement
# (D144 §1.2). Exactly ONE line was a live instruction, and the scrub was one
# edit, not 61.
#
# THIS IS NOT A PRIVACY CONTROL and no row may be ticked on one. `/home/deb` is
# in the published history at the initial commit `01cdc83`, at the pushed
# `format-v1-freeze` tag and at HEAD; 21 commits on `main` change it; a rewrite
# is ruled not warranted (`docs/reviews/pre-public-scrub-history.md`). Scrubbing
# HEAD moves the string from "visible in `git grep`" to "visible in `git log
# -S`, one command later". What the rule buys is MACHINE-INDEPENDENCE of live
# instructions — real, durable, and the honest claim (D144 §1.6, §2 R1).
#
# WHY A RESERVED VOCABULARY AND NOT AN EXEMPTION LIST (D144 §2 R4, §3). An
# exemption list whose remedy is "add your file to it" grows once per violation,
# is always edited by the person whose change made it necessary, and is this
# project's dominant defect class wearing a register's clothes — the same
# reasoning `check-copy-style.py`'s OWED_PRESENCE, `check-ci-shell.py`'s
# ALLOWED_INLINE and `verdict_wording.rs`'s RESIDUE already carry: *a debt that
# cannot go stale is an exemption, and exemptions rot*. A reserved vocabulary's
# remedy is in the CONTRIBUTOR'S OWN FILE — write `/home/user`, never touch this
# script — and it grows only when a genuinely new placeholder ROLE appears,
# which has happened five times in a year: O(roles), not O(files). Measured as
# this landed: the five names below already covered 27 of the 29 in-scan
# occurrences with zero edits to any of them.
#
# There is deliberately NO exemption list in this implementation. A reviewer may
# grep for one and find nothing (D144 §2 R8 Accept).
#
# REFUSED, and named so it is not re-proposed: a lint on the literal
# `/home/deb`. It protects exactly one machine, is green for every other
# contributor from the day it lands, and is therefore a check that cannot fail
# for anyone but its author (D144 §2 R4).

# The complete set. Adding a sixth name is guarded: `--self-test` builds one
# GREEN fixture per name FROM THIS TUPLE, so a name cannot land without its own
# fixture in the same act (Q245's derived-count discipline, one level up from
# where Q245 applied it).
RESERVED_PLACEHOLDER_NAMES = ("user", "fixture", "runner", "u", "x")

# Q257 — the vocabulary above is a RULE contributors must obey, so it is stated
# where they meet it BEFORE the lint does, and pinned to the tuple here. D144
# §2 R8 owed this half; the row it minted is Q257. A name added or removed
# above without the matching edit to the document is a red, and so is a name
# documented but not reserved.
#
# WHY THE DELIMITED, ANCHORED FORM IS LOAD-BEARING. The obvious arm — substring
# -search each reserved name in the document — is GREEN BY CONSTRUCTION for two
# of the five: `u` and `x` are single letters occurring in thousands of English
# words, so neither could ever be reported missing. This project's dominant
# defect class, and it would have been written into the check that documents
# the rule against it. So: read only what follows the anchor ON ONE LINE,
# require each name inside BACKTICKS, and assert the documented sequence EQUALS
# the tuple — a COUNT in both directions, not a "none failed". The count is not
# implied by the two set comparisons: a line naming `user` twice and `x` never
# has an empty `missing` under a set test and is still wrong.
PLACEHOLDER_DOC = "CONTRIBUTING.md"
PLACEHOLDER_DOC_ANCHOR = "Reserved placeholder names:"
PLACEHOLDER_DOC_TOKEN = re.compile(r"`([^`]+)`")

# The three platform spellings, as a TABLE rather than one opaque regex, so the
# self-test can read the arms off it and require a planted RED fixture per arm.
# An arm added here without a fixture fails `--self-test` with its own message
# instead of letting the totals balance. Values are REGEX SOURCE, not literals.
#
# `/Users/` and `C:\Users\` have ZERO live occurrences in this tree, which is
# exactly why they are planted rather than trusted: an arm no live text
# exercises is an assertion that cannot fail unless the self-test constructs its
# subject (D144 §2 R7, faults 2 and 3).
#
# `C:` tolerates ONE OR TWO separators, and that is not tidiness: a Windows path
# inside a Rust or JSON string literal is ESCAPED on disk — the bytes of
# `"C:\\Users\\alice"` are what a source file actually contains — so a pattern
# spelling a single backslash reads straight past every real occurrence. The
# forward-slash form matches too.
MACHINE_PATH_ARMS = {
    "posix-home": r"/home/",
    "macos-users": r"/Users/",
    "windows-users": r"C:[\\/]{1,2}Users[\\/]{1,2}",
}

# The name that follows a prefix. Group 1 is the name; group 0 is what the
# failure quotes.
#
# WHERE A NAIVE PATTERN GOES WRONG, and where the anchoring actually lives
# (D144 §2 R4): `/homework/`, a bare `/home`, `$HOME/…` and `~/…` must not
# match. All four are killed by the PREFIX — `/home/` requires the trailing
# separator after `home`, and `$HOME`/`~` are neither, case-sensitively. A
# trailing-boundary LOOKAHEAD would add nothing: `+` is greedy, so the match
# cannot end mid-token and the lookahead could never fail — an assertion that
# cannot fail, this project's dominant defect class, written into the very check
# that exists to refuse one. So the end-of-token half of the rule is satisfied
# by construction and the separator half by the prefix, and all four near misses
# are planted as GREEN controls anyway (D144 §2 R7 fault 5).
MACHINE_PATH = re.compile(
    "(?:" + "|".join(MACHINE_PATH_ARMS.values()) + r")([A-Za-z0-9._-]+)"
)

# The scan boundary is NOT a new list. It is `CITATION_SCAN`, whose thirty-line
# comment already draws the line this check needs — *"the line is drawn at LIVE
# versus PRESERVED"* — with every exclusion reasoned and ruled in place (D109
# §3.3, D116 §1.3, Q176, Q190/D123). `docs/decisions/`, `docs/reviews/`,
# `docs/research/`, `TODO.md`, `tasks/*.md`, `MVP-SPEC.orig.md` and
# `SPEC-REVIEW.md` are all already OUT of it, which is precisely the RECORD
# class above. Two constants held in step by a comment is the defect D116 R1
# ended; the only honest comment on a second copy would be "these are the same,
# one is stale" (D144 §2 R6).
#
# It also buys the property D139 §1.4 measured for a directory entry over
# per-file registration: any new file in a scanned root is covered from its
# first commit.
#
# `MVP-SPEC.md` is the one place the reuse is not verbatim. It is a
# `CITATION_SCAN` literal entry because a citation INTO it must resolve — which
# is correct — but its CONTENT is preserved, so it is excluded here and PINNED
# below instead.
PATH_SCAN_EXCLUDES = {"MVP-SPEC.md"}

# The coupling guard, and the answer to the obvious objection that reusing
# another check's constant lets an edit made for citation reasons silently
# shrink path coverage. WIDENING `CITATION_SCAN` is always safe (more surface).
# NARROWING it is not — so each root below is asserted still present and this
# check reds BY NAME if one is removed (D144 §2 R6, falsifier f2).
#
# What it does NOT guard, stated where someone might otherwise assume it does:
# a narrowing of `CITATION_SUFFIXES`. Dropping `.rs` would blind this check to
# every test fixture while leaving all seven roots present. That is why the ok
# line below reports the SCANNED FILE COUNT and not merely the zero — the count
# is the only thing that moves when a suffix leaves (D144 f2).
PATH_SCAN_REQUIRED = {"crates", "scripts", "verifier-web", "docs/user",
                      "README.md", "CONTRIBUTING.md", "CHANGELOG.md"}

# A machine path that is present ON PURPOSE and may not be removed, with the
# reason it may not and the row that owns the divergence. This is a PIN, not
# an exemption: the check asserts the text is STILL THERE, verbatim and
# exactly once. Repair the line and the check goes RED demanding this entry
# be deleted in the same act; delete the entry while the line stands and it
# goes RED the other way. A debt that cannot go stale is an exemption, and
# exemptions rot (check-copy-style.py OWED_PRESENCE, check-ci-shell.py
# ALLOWED_INLINE, verdict_wording.rs RESIDUE — the same discipline, third
# instrument).
#
# Anchored on TEXT, never on a line number: D139's 28 locators into
# docs/threat-model.md died inside the wave that wrote them. The anchor is a
# WHOLE LINE, matched by equality — a substring anchor would survive an append
# to its own line and the pin would stop noticing the edit it exists to notice.
#
# The registered file is scanned for OTHER machine paths too, with only the
# anchor line skipped, so this entry can never widen into a blanket file
# exemption — which is exactly what an allow-list entry would have been.
KNOWN_MACHINE_PATH_DIVERGENCE: dict[str, tuple[str, str]] = {
    "MVP-SPEC.md": (
        "Cargo workspace, greenfield in `/home/deb/Documents/code0`:",
        "Q65 / D144 §2 R5 — the spec is frozen (TODO.md:3: the spec wins, the "
        "conflict is FLAGGED, not silently diverged). MVP-SPEC.md has one commit "
        "in its life (01cdc83, 189 lines added, zero changed since), 1 707 "
        "line-number citations point into it and F44 measures that NOTHING "
        "verifies one of them, and line 42 sits inside six cited ranges "
        "(lines 40-58, lines 44-58). Amending the spec is an M4 event "
        "(tasks/P.md:62's RECORDED DEVIATION took the flag over the edit for "
        "the same reason). If a spec amendment is ever taken, it is an "
        "IN-PLACE, EQUAL-LINE-COUNT replacement on line 42 or it corrupts all "
        "six ranges silently.",
    ),
}


def machine_path_scan_roots() -> list[str]:
    """The roots this check reads: `CITATION_SCAN` minus what is pinned or
    self-excluded. One place, so the check and its self-test cannot disagree."""
    return [sub for sub in CITATION_SCAN if sub not in PATH_SCAN_EXCLUDES]


def placeholder_doc_evidence(failures: Failures, check: str) -> str:
    """Q257 — hold `PLACEHOLDER_DOC`'s declaration of the reserved vocabulary
    equal to `RESERVED_PLACEHOLDER_NAMES`, and return the ok line's evidence
    clause. One finding per divergence; the constants above say why the names
    are read delimited and COUNTED rather than substring-searched."""
    expected = ", ".join("`" + name + "`" for name in RESERVED_PLACEHOLDER_NAMES)
    form = "**" + PLACEHOLDER_DOC_ANCHOR + "** " + expected

    try:
        lines = (ROOT / PLACEHOLDER_DOC).read_text(encoding="utf-8").splitlines()
    except (UnicodeDecodeError, OSError) as exc:
        failures.add(
            check,
            f"{PLACEHOLDER_DOC} could not be read ({type(exc).__name__}), so the "
            f"reserved vocabulary this check enforces is stated on no surface a "
            f"contributor reads before the lint fires. Restore the file and the "
            f"line: {form} (Q257, D144 §2 R8).",
        )
        return "vocabulary UNDOCUMENTED"

    hits = [n for n, line in enumerate(lines, 1) if PLACEHOLDER_DOC_ANCHOR in line]
    if len(hits) != 1:
        failures.add(
            check,
            f"{PLACEHOLDER_DOC} holds {len(hits)} line(s) containing "
            f'"{PLACEHOLDER_DOC_ANCHOR}", not exactly 1. The vocabulary is '
            f"declared on ONE line so that line can be held equal to "
            f"RESERVED_PLACEHOLDER_NAMES; a rewrap or a second copy makes the "
            f"pin unable to identify its subject. Restore it as: {form} (Q257).",
        )
        return "vocabulary NOT declared exactly once"

    number = hits[0]
    where = f"{PLACEHOLDER_DOC}:{number}"
    tail = lines[number - 1].split(PLACEHOLDER_DOC_ANCHOR, 1)[1]
    documented = PLACEHOLDER_DOC_TOKEN.findall(tail)

    missing = [name for name in RESERVED_PLACEHOLDER_NAMES if name not in documented]
    if missing:
        absent = ", ".join("`" + name + "`" for name in missing)
        failures.add(
            check,
            f"{where}: the declaration does not name {absent}, so this check "
            f"reserves {len(missing)} name(s) a contributor cannot read about "
            f"anywhere before their commit goes red. Names are matched INSIDE "
            f"BACKTICKS and on this line only — a bare occurrence in prose does "
            f"not count, which is what keeps single-letter names falsifiable. "
            f"Restore the line as: {form} (Q257).",
        )

    extra = [token for token in documented if token not in RESERVED_PLACEHOLDER_NAMES]
    if extra:
        surplus = ", ".join("`" + token + "`" for token in extra)
        failures.add(
            check,
            f"{where}: the declaration names {surplus}, which "
            f"RESERVED_PLACEHOLDER_NAMES does not reserve. A contributor who "
            f"uses it will be refused by a lint their own guide told them to "
            f"trust. Restore the line as: {form} (Q257).",
        )

    if len(documented) != len(RESERVED_PLACEHOLDER_NAMES):
        failures.add(
            check,
            f"{where}: the declaration states {len(documented)} name(s) against "
            f"{len(RESERVED_PLACEHOLDER_NAMES)} in RESERVED_PLACEHOLDER_NAMES. "
            f"This is a COUNT, deliberately separate from the two comparisons "
            f"above: it is the arm that fires when the tuple grows a name the "
            f"document never gained, and the only arm that sees a duplicate. "
            f"Restore the line as: {form} (Q257).",
        )

    return (
        f"the vocabulary is declared for contributors at {where}, naming "
        f"exactly the {len(RESERVED_PLACEHOLDER_NAMES)} reserved name(s)"
    )


def check_machine_paths(failures: Failures) -> None:
    check = "machine-paths"
    reserved = ", ".join(RESERVED_PLACEHOLDER_NAMES)
    # THIS CHECK COUNTS ITS OWN FAILURES. The other seven end with `if not
    # failures:`, which reads the SHARED object, so any earlier check's finding
    # suppresses every later ok line — visible today, where four
    # `[decision-index]` findings would silence this line on a tree with zero
    # machine-path problems. That is a real defect and it is NOT repaired here:
    # repairing it edits seven checks that are not this record's subject. New
    # code simply declines to reproduce it.
    before = len(failures.messages)

    # (M4) The coupling guard, first: if a required root has left the scan,
    # every count below is measured over less surface than it claims.
    roots = machine_path_scan_roots()
    for required in sorted(PATH_SCAN_REQUIRED):
        if required not in CITATION_SCAN:
            failures.add(
                check,
                f"CITATION_SCAN no longer contains `{required}`, so this check "
                f"silently stopped scanning it. Restore the root, or give this "
                f"check its own root list in the same act (D144 §2 R6).",
            )

    # (M4/Q257) The DOC-side coupling guard, here and for the same reason as the
    # root guard above: this check enforces the vocabulary, and PLACEHOLDER_DOC
    # is where a contributor meets it before the lint does. If the two have
    # drifted, every refusal below cites a rule nobody can read.
    doc_evidence = placeholder_doc_evidence(failures, check)

    # (M2/M3) The pin, in both directions.
    for relative in sorted(KNOWN_MACHINE_PATH_DIVERGENCE):
        anchor, _reason = KNOWN_MACHINE_PATH_DIVERGENCE[relative]
        path = ROOT / relative
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            text = ""
        lines = text.splitlines()
        present = sum(1 for line in lines if line == anchor)
        if present != 1:
            if present == 0:
                failures.add(
                    check,
                    f"{relative}: the registered divergence text is no longer "
                    f"present verbatim — the file was edited or the anchor moved. "
                    f"If the edit was deliberate, delete the "
                    f"KNOWN_MACHINE_PATH_DIVERGENCE entry in the same act; if it "
                    f"was not, revert it. The spec is frozen and the protocol "
                    f"FLAGS divergences rather than editing them (TODO.md:3, "
                    f"D144 §2 R5).",
                )
            else:
                failures.add(
                    check,
                    f"{relative}: the registered divergence text occurs {present} "
                    f"times, not once — the pin cannot identify its subject "
                    f"(D144 §2 R5).",
                )
        # The rest of a pinned file is scanned like any other live surface: the
        # entry pins ONE LINE, never a file.
        for number, line in enumerate(lines, 1):
            if line == anchor:
                continue
            for match in MACHINE_PATH.finditer(line):
                if match.group(1) in RESERVED_PLACEHOLDER_NAMES:
                    continue
                failures.add(
                    check,
                    f"{relative}:{number}: absolute home path `{match.group(0)}` "
                    f"in a live surface. Live instructions must not name a "
                    f"developer's machine — use a reserved placeholder name "
                    f"({reserved}) or a $HOME-relative path. There is no "
                    f"exemption list to add this file to. The vocabulary, and why no "
                    f"exemption list exists, are in {PLACEHOLDER_DOC} under "
                    f"'{PLACEHOLDER_DOC_ANCHOR}' (D144 §2 R4, Q257).",
                )

    # (M1) The live surface. Loop body at parity with `check_decisions` and
    # `sweep_task_surfaces` (D116 R2): an entry may be a DIRECTORY (walked,
    # filtered by CITATION_SUFFIXES) or a single FILE (read as itself,
    # UNFILTERED) — D123's per-entry rule, reused verbatim rather than restated.
    #
    # This file excludes itself, as it does from the citation sweep and for the
    # same reason: it carries the pin's anchor text and every banned pattern as
    # literals. `CITATION_SCAN_SELF` already exists for exactly this, and
    # `check-copy-style.py` and `ci-lanes.sh` (`--exclude='ci-lanes.sh'`) do the
    # same — third instrument, same shape. Documenting the trap does not lay
    # another one.
    skip = set(PATH_SCAN_EXCLUDES) | set(KNOWN_MACHINE_PATH_DIVERGENCE) | {CITATION_SCAN_SELF}
    scanned = 0
    for sub in roots:
        base = ROOT / sub
        if not base.exists():
            continue
        literal = base.is_file()
        for path in ([base] if literal else base.rglob("*")):
            if not path.is_file() or (not literal and path.suffix not in CITATION_SUFFIXES):
                continue
            if {"target", "node_modules", "__pycache__"} & set(path.parts):
                continue
            rel = str(path.relative_to(ROOT))
            if rel in skip:
                continue
            try:
                text = path.read_text(encoding="utf-8")
            except (UnicodeDecodeError, OSError):
                continue
            scanned += 1
            for number, line in enumerate(text.splitlines(), 1):
                for match in MACHINE_PATH.finditer(line):
                    if match.group(1) in RESERVED_PLACEHOLDER_NAMES:
                        continue
                    failures.add(
                        check,
                        f"{rel}:{number}: absolute home path `{match.group(0)}` "
                        f"in a live surface. Live instructions must not name a "
                        f"developer's machine — use a reserved placeholder name "
                        f"({reserved}) or a $HOME-relative path. There is no "
                        f"exemption list to add this file to. The vocabulary, and why no "
                        f"exemption list exists, are in {PLACEHOLDER_DOC} under "
                        f"'{PLACEHOLDER_DOC_ANCHOR}' (D144 §2 R4, Q257).",
                    )

    if len(failures.messages) == before:
        # The COUNT, not merely the zero (D144 §2 R8 Accept, falsifier f2): a
        # suffix leaving CITATION_SUFFIXES moves nothing except this number.
        print(
            f"[{check}] ok — 0 absolute home paths outside the reserved "
            f"vocabulary ({reserved}) across {scanned} live file(s) in "
            f"{len(roots)} scan root(s); "
            f"{len(KNOWN_MACHINE_PATH_DIVERGENCE)} registered divergence(s) "
            f"still present verbatim and exactly once "
            f"({', '.join(sorted(KNOWN_MACHINE_PATH_DIVERGENCE))}); "
            f"{doc_evidence}"
        )


# ── check 9: every relative `.md` link resolves on disk (Q249, D159 §2 R1) ──
#
# WHY HERE AND NOT IN A DOCUMENTATION BUILD, which is what the row asked for.
# rustdoc's doc-link lints resolve Rust ITEM PATHS — `[`crate::evm`]`,
# `[`WalletKey::evm_wallet`]`. A markdown link whose target is a FILESYSTEM
# path is not an item path: rustdoc emits it verbatim as an href and validates
# nothing about it, so `cargo doc` could not have found the defect that raised
# Q249 in any venue. The second witness is the row's own carriage — the Q248
# lane's `cargo doc` reported "twelve broken INTRA-DOC links" with
# `request.rs:2` NOT among them, and the lane found that link by READING
# (D159 §1.2).
#
# AND THE GAP IS INSIDE `check_decisions`' OWN SUBJECT, which is what answers
# the venue question rather than deferring it. That check asserts "every
# decision cited in code or in a normative doc resolves to a record" and
# extracts `\bD(\d+)\b` — the ID, and only the ID. A citation whose id resolved
# and whose PATH pointed at a directory that does not exist was green for as
# long as it existed. The claim is carried by the path; the check audited the
# number.
#
# COST, measured 2026-08-22 (D159 §2 R4). This script already reads every one
# of these files, is cargo-free, runs in `local-gate.sh` and rides
# `ci-always.yml`'s `traceability` job — the workflow whose defining property
# is that it carries no path filter, ever. ZERO new required status contexts
# (the set stays at 19), zero new workflow files, zero new job steps, zero new
# hosted weighted minutes; 0.110 s for the sweep itself.

# THE SUBJECT, normative and deliberately narrow. A DOC LINK is a markdown
# inline link `](TARGET)` whose TARGET, with any `#fragment` removed, ends in
# `.md`, contains no `://`, and does not begin with `/`. It must resolve,
# relative to the CONTAINING FILE'S DIRECTORY, to an existing file.
#
# Every clause is a measurement rather than a taste:
#
#   `.md` ONLY — because `crates/antseal-core/tests/bundle_wire/mod.rs:13`
#   writes a rustdoc-HTML-OUTPUT-relative link at `../manifest_wire/`, correct
#   where it is written and dead on disk. Measured: it is the ONLY non-`.md`
#   relative link in the corpus, so this restriction excludes it ONE FOR ONE by
#   a property of the target, and there is no exemption list to add a file to
#   (D144 §2 R4's own failure text; D159 §3 item 7).
#
#   BOTH SPELLINGS, dot-prefixed and bare-relative — 14 and 35 of the 49. The
#   wave-26 defect was a `../` link that failed and its repair was a
#   bare-relative one that passes, so a check restricted to the dot form would
#   have graded that repair without ever checking it (D159 §1.1).
#
#   `#fragment` STRIPPED, AND THE FRAGMENT NOT VALIDATED — a STATED LIMIT, not
#   an oversight. Zero anchored links exist in the tree today, so an
#   anchor-validating rule would be an assertion with no subject; the branch
#   that strips is exercised only by a constructed fixture.
#
#   NO `://`, NO LEADING `/` — a URL is nobody's filesystem claim and a
#   site-root-absolute path is a web server's, not a tree's. Zero of each live
#   today; both branches are constructed in `prove_doc_link_arms()`.
#
#   FENCED BLOCKS AND INLINE CODE SPANS ARE SKIPPED — `doc_pointer_liveness.rs`'s
#   rule verbatim, "their content is code, not prose about code". Measured
#   2026-08-22, this clause changes the live corpus NOT AT ALL: 49 links with
#   it and 49 without, 0 inside fences and 0 inside spans. It is added anyway
#   because the false positive it prevents is already demonstrable — a record
#   ABOUT broken links necessarily QUOTES broken links, and D159 §2 R3/§2 R5
#   carry four such link-shaped strings inside code spans. Without this clause
#   the widening routed in D159 §4 item 5 (admitting `docs/decisions/` to the
#   scan) could never go green. Whoever takes that widening confirms this
#   clause first.
DOC_LINK = re.compile(r"\]\(\s*<?([^)\s>]+)>?[^)]*\)")

# A fence opens and closes on a line whose first content — after an optional
# RUST DOC-COMMENT PREFIX, because a third of the corpus is `//!` prose — is a
# run of backticks or tildes. Without the prefix branch every ```text block in
# a Rust module doc would stay in scope, which is where this tree's link-shaped
# code samples actually live.
DOC_LINK_FENCE = re.compile(r"^\s*(?://[/!]?)?\s*(?:```|~~~)")

# `crates/<crate>/src/**` — Q249's OWN subject, and deliberately not "anything
# under crates/". `crates/antseal-wasm/README.md:9` carries a relative link
# that resolves; it counts toward the TOTAL floor and must NOT count toward
# this one, or a later reader "fixes" the floor to 5 (D159 §4 item 4).
DOC_LINK_CRATES_SRC = re.compile(r"^crates/[^/]+/src/")

# ANTI-VACUITY, and the COMPARISON IS WRITTEN DOWN because this project has
# had a live `>=` that three witnesses said must be `>` (wave 17).
#
# D159 §2 R1 SETS BOTH NUMBERS; they are not re-derived here. What IS
# re-measured, because §1's provenance requires it of the implementing lane,
# is the corpus they are measured against: 53 links across 461 files, 4 of
# them under crates/*/src/ (2026-08-22, this lane). D159 §1.1 recorded 49 over
# 457 the same morning, and BOTH differences are accounted for — the parity
# loop below excludes this file exactly as `check_decisions` does, and
# `README.md` grew from 19 links to 23 under a concurrent lane WHILE THIS
# CHECK WAS BEING WRITTEN. The corpus is a moving number. The floors are not,
# which is the whole point of having them.
# LOWER-ONLY BY DECISION, never by an implementer needing a run to go green —
# the FUZZ_BUDGET_CEILING_MINUTES idiom (scripts/ci-lanes.sh:1351-1353 today;
# D135 §3 R6 cites :1162-1164, which has drifted — D159 §4 item 7).
#
# TOTAL: measured 53 against a floor of 45. R1 set 45 when the corpus was 49
# and reasoned "the headroom is EXACTLY FOUR — the size of Q249's own
# subject". That headroom is EIGHT today, and 45 is deliberately NOT raised to
# restore it: raising a ruled constant is a decision and not an edit, and the
# trap R1 aimed the headroom at — losing `crates/**/src/**` — is owned by the
# OTHER floor, which sits at the boundary and cannot miss it. What 45 still
# buys is measured rather than argued: `README.md` and `CONTRIBUTING.md` alone
# yield 39 today, so a collapse back to the two root literals reds (39 < 45).
# That is the property the total floor exists for, and it still holds.
# CRATES-SRC: measured 4 and set AT the boundary. This is "the count equals 4"
# rendered as `>=` rather than `==` on purpose: a FIFTH correct link must not
# redden the gate, while losing any of the four must. It is the guard against
# the named trap — a glob rooted wrong finds 0, and `0 >= 4` is false.
DOC_LINK_TOTAL_FLOOR = 45   # >= ; catches the walk collapsing
DOC_LINK_CRATES_SRC_FLOOR = 4   # >= ; Q249's own subject, AT the boundary


def blank_code(text: str) -> str:
    """`text` with fenced blocks and inline code spans replaced by spaces.

    NEWLINES ARE PRESERVED, so every line number a finding reports is still the
    file's own. Blanking rather than deleting is what buys that.
    """
    chars = list(text)

    def blank(start: int, stop: int) -> None:
        for index in range(start, stop):
            if chars[index] != "\n":
                chars[index] = " "

    offset = 0
    fenced = False
    for line in text.splitlines(keepends=True):
        end = offset + len(line)
        marker = bool(DOC_LINK_FENCE.match(line))
        if marker or fenced:
            blank(offset, end)
        if marker:
            fenced = not fenced
        offset = end

    # Inline spans, over what the fences left. CommonMark: a run of N backticks
    # opens a span that the next run of EXACTLY N closes. An unclosed run is
    # not a span and must not swallow the rest of the file, so it is stepped
    # over rather than blanked.
    body = "".join(chars)
    index = 0
    while index < len(body):
        if body[index] != "`":
            index += 1
            continue
        open_end = index
        while open_end < len(body) and body[open_end] == "`":
            open_end += 1
        run = open_end - index
        cursor = open_end
        closed = None
        while cursor < len(body):
            if body[cursor] != "`":
                cursor += 1
                continue
            close_end = cursor
            while close_end < len(body) and body[close_end] == "`":
                close_end += 1
            if close_end - cursor == run:
                closed = close_end
                break
            cursor = close_end
        if closed is None:
            index = open_end
            continue
        blank(index, closed)
        index = closed
    return "".join(chars)


def tree_relative(directory: str, target: str) -> str:
    """Where `target` lands, as a path relative to the tree root.

    Normalised by hand rather than by `Path.resolve()`, because `resolve()`
    returns an ABSOLUTE path and a finding that prints one would name the
    developer's machine in a CI log — the surface `machine-paths` exists to
    keep clean. A target that climbs out of the tree keeps its leading `../`,
    which is the honest rendering of what it did.
    """
    parts: list[str] = []
    for piece in (directory.split("/") if directory else []) + target.split("/"):
        if piece in ("", "."):
            continue
        if piece == "..":
            if parts and parts[-1] != "..":
                parts.pop()
            else:
                parts.append("..")
        else:
            parts.append(piece)
    return "/".join(parts)


def doc_link_sweep(tree: pathlib.Path) -> tuple[list[tuple[str, int, str, str, bool]], dict[str, int], int]:
    """`(links, per-root counts, files read)` over `tree`.

    Each link is `(relative file, line number, target as written, where it
    lands relative to the tree, does that file exist)`.

    `tree` is a PARAMETER and not `ROOT` for the same reason `decision_homes()`
    takes one: three of this check's branches have NO live subject, so the only
    thing that can exercise them is a CONSTRUCTED tree, and a helper that can
    only read the live tree cannot be shown correct on a tree that does not
    exist yet.
    """
    links: list[tuple[str, int, str, str, bool]] = []
    per_root: dict[str, int] = {}
    n_files = 0
    # Loop body at parity with `check_decisions` and `sweep_task_surfaces()`
    # (D116 R2, now THREE copies — D159 §4 item 1 routes the extraction of one
    # generator all three consume, and it is a refactor of two currently-green
    # checks rather than this row's work). One scan set; having different prune
    # sets afterwards is exactly the divergence that rule exists to end.
    for sub in CITATION_SCAN:
        base = tree / sub
        if not base.exists():
            continue
        # Q176 + Q190/D123 — an entry may be a DIRECTORY (swept recursively and
        # filtered by CITATION_SUFFIXES) or a single FILE (swept as itself,
        # UNFILTERED). Two branches because they answer different questions: a
        # tree walk has no opinion about what it finds, so it needs the suffix
        # set; a named file was already deliberated in a reviewed constant, so
        # a second gate is owed to nobody. Both other sweeps carry these lines
        # identically; see the note at CITATION_SCAN.
        literal = base.is_file()
        for path in ([base] if literal else base.rglob("*")):
            if not path.is_file() or (not literal and path.suffix not in CITATION_SUFFIXES):
                continue
            if {"target", "node_modules", "__pycache__"} & set(path.parts):
                continue
            rel = str(path.relative_to(tree))
            # This file excludes itself, as it does from the citation sweep and
            # for the same reason one register over: `prove_doc_link_arms()`
            # below writes link-shaped fixtures as literals, so sweeping this
            # file would report its own fixtures. Documenting the trap does not
            # lay another one.
            if rel == CITATION_SCAN_SELF:
                continue
            try:
                text = path.read_text(encoding="utf-8")
            except (UnicodeDecodeError, OSError):
                continue
            n_files += 1
            directory = str(path.parent.relative_to(tree))
            if directory == ".":
                directory = ""
            for number, line in enumerate(blank_code(text).splitlines(), 1):
                for target in DOC_LINK.findall(line):
                    bare = target.split("#", 1)[0]
                    if "://" in target or bare.startswith("/") or not bare.endswith(".md"):
                        continue
                    per_root[sub] = per_root.get(sub, 0) + 1
                    # `is_file()`, not `exists()`: R1 says "to an existing
                    # FILE", and a directory that happens to be named `x.md`
                    # would satisfy `test -e` while satisfying no reader.
                    landed = (path.parent / bare).is_file()
                    links.append((rel, number, target, tree_relative(directory, bare), landed))
    return links, per_root, n_files


def doc_link_findings(
    tree: pathlib.Path,
    total_floor: int = DOC_LINK_TOTAL_FLOOR,
    crates_src_floor: int = DOC_LINK_CRATES_SRC_FLOOR,
) -> tuple[list[str], dict[str, int], int, int, int]:
    """`(messages, per-root counts, files, total links, crates-src links)`.

    Everything the check would report over `tree`, returned AS STRINGS so a
    constructed state can be asserted against THE MESSAGE and never against an
    exit code — `scripts/lib/red-arm.sh`'s rule, one venue over.

    The two floors are PARAMETERS so that a constructed three-file tree can
    exercise the RESOLUTION rules without the floors drowning them, while the
    zero-corpus arm passes the real ones and asserts they fire. `check_doc_links`
    below always passes the constants; nothing else may.
    """
    links, per_root, n_files = doc_link_sweep(tree)
    total = len(links)
    crates_src = sum(1 for rel, *_ in links if DOC_LINK_CRATES_SRC.match(rel))

    messages: list[str] = []
    for rel, number, target, landing, landed in links:
        if landed:
            continue
        messages.append(
            f"{rel}:{number}: the link target `{target}` does not resolve — "
            f"relative to this file's own directory it lands at `{landing}`, "
            f"and no such file exists. Fix it by resolving the target against "
            f"the filesystem (`realpath -m` from the file's directory), NEVER "
            f"by counting `../` segments, which is how this class of defect "
            f"gets written wrong in the first place (D159 §2 R5)."
        )

    # The floors are asserted AFTER the resolution rule and independently of
    # it, so a walk that collapsed to nothing reports the collapse rather than
    # a clean `0 broken`. Printing a count is not asserting it: `machine-paths`
    # printed "ok — 0 ... across 455 live file(s)" over a live plant, and that
    # entry is in the instrument ledger (U87's lane).
    if total < total_floor:
        messages.append(
            f"the sweep found {total} doc link(s) where DOC_LINK_TOTAL_FLOOR "
            f"requires at least {total_floor}: {total} < {total_floor}. A count "
            f"below the floor means the WALK collapsed, not that the tree got "
            f"tidier — check CITATION_SCAN and CITATION_SUFFIXES first. This "
            f"floor is LOWER-ONLY BY DECISION (D159 §2 R1); an implementer "
            f"needing a run to go green is exactly who it is written against."
        )
    if crates_src < crates_src_floor:
        messages.append(
            f"the sweep found {crates_src} doc link(s) under crates/*/src/ "
            f"where DOC_LINK_CRATES_SRC_FLOOR requires at least "
            f"{crates_src_floor}: {crates_src} < {crates_src_floor}. This is "
            f"Q249's own subject and the floor sits AT the measured count, so a "
            f"glob rooted wrong finds 0 and reds here instead of passing as a "
            f"clean run. A FIFTH correct link is fine; losing one of the four "
            f"is not. LOWER-ONLY BY DECISION (D159 §2 R1)."
        )
    return messages, per_root, n_files, total, crates_src


def prove_doc_link_arms(scratch: pathlib.Path) -> list[tuple[bool, str]]:
    """Require `doc-links`' branches on CONSTRUCTED trees. `(passed, sentence)`.

    D159 §2 R3's arms, and the module-level home is the same one
    `prove_lowest_unhomed_mint()` has, for a reason this harness has paid for
    twice: THREE of the six branches below — `#fragment` stripping, the
    code-span/fence exclusion, and the site-root-absolute and `://` rejections —
    have NO LIVE SUBJECT ANYWHERE IN THE TREE. An arm no live text exercises is
    an assertion that cannot fail unless the self-test constructs its subject,
    and `--self-test` stages a full copy of a tree other lanes are writing, so
    it may not be run mid-wave. Everything below builds its own state on disk
    and can be called directly.

    Nothing here is derived from ROOT, so no amount of tree health or tree
    sickness can decide a verdict (Q252, and Q234's general form).
    """
    results: list[tuple[bool, str]] = []

    def build(name: str, files: dict[str, str]) -> pathlib.Path:
        tree = scratch / name
        for relative, body in files.items():
            path = tree / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(body, encoding="utf-8")
        return tree

    def record(passed: bool, sentence: str) -> None:
        results.append((passed, sentence))

    # ── RED 1: the message must NAME the file, the target and where it landed.
    # Q249's own defect, reconstructed rather than borrowed: a doc link one
    # `../` short of its target, in a file at Q249's own depth. "1 broken link"
    # does not discharge this arm.
    short = build(
        "red-1-short-prefix",
        {
            "docs/decisions/D59-constructed.md": "constructed target\n",
            "crates/c/src/anchor/request.rs": (
                "//! Constructed by prove_doc_link_arms.\n"
                "//! [D59](../../../docs/decisions/D59-constructed.md)).\n"
            ),
        },
    )
    messages, _roots, _files, total, _src = doc_link_findings(short, 0, 0)
    wanted = (
        "crates/c/src/anchor/request.rs:2",
        "../../../docs/decisions/D59-constructed.md",
        "crates/docs/decisions/D59-constructed.md",
    )
    missing = [part for part in wanted if not any(part in message for message in messages)]
    if total != 1:
        record(False, f"RED 1 (a link one `../` short): the state is vacuous — {total} link(s) swept, not 1")
    elif len(messages) != 1:
        record(False, f"RED 1 (a link one `../` short): expected one finding, got {len(messages)}: {messages}")
    elif missing:
        record(False, f"RED 1 (a link one `../` short): the finding never says {missing}")
    else:
        record(True, "RED 1 (a link one `../` short): red, naming the file:line, the target as written, and where it landed")

    # ── RED 2: THE VACUITY PLANT. A fixture root with zero `.md` links, and the
    # REAL floors. This is the arm that would otherwise pass green for ever —
    # a mis-rooted glob and a clean tree are indistinguishable without it.
    empty = build(
        "red-2-zero-corpus",
        {"docs/testing/prose.md": "No link-shaped text lives in this file at all.\n"},
    )
    messages, _roots, _files, total, crates_src = doc_link_findings(empty)
    both = all(
        any(number in message for message in messages)
        for number in (f"0 < {DOC_LINK_TOTAL_FLOOR}", f"0 < {DOC_LINK_CRATES_SRC_FLOOR}")
    )
    if (total, crates_src) != (0, 0):
        record(False, f"RED 2 (a zero-link corpus): the state is vacuous — swept {total}/{crates_src}, wanted 0/0")
    elif len(messages) != 2 or not both:
        record(False, f"RED 2 (a zero-link corpus): both floors must fire naming both numbers; got {messages}")
    else:
        record(True, f"RED 2 (a zero-link corpus): red on BOTH floors, saying 0 < {DOC_LINK_TOTAL_FLOOR} and 0 < {DOC_LINK_CRATES_SRC_FLOOR}")

    # ── RED 3: the `#fragment` branch, which has NO live subject. Its purpose
    # is to prove the strip is a STRIP and not a truncation of the whole
    # target: the finding must name the FILE part and must not carry the
    # fragment into the path it says it resolved.
    anchored = build(
        "red-3-fragment-missing",
        {"docs/testing/page.md": "[x](./missing-page.md#section)\n"},
    )
    messages, _roots, _files, total, _src = doc_link_findings(anchored, 0, 0)
    landed_clause = [m for m in messages if "docs/testing/missing-page.md`" in m]
    if total != 1:
        record(False, f"RED 3 (an anchored link at a missing file): the state is vacuous — {total} link(s) swept, not 1")
    elif not landed_clause:
        record(False, f"RED 3 (an anchored link at a missing file): no finding names the file part without its fragment: {messages}")
    elif any("missing-page.md#section`" in m.split("lands at")[-1] for m in landed_clause):
        record(False, "RED 3 (an anchored link at a missing file): the fragment survived into the resolved path, so the strip is a truncation")
    else:
        record(True, "RED 3 (an anchored link at a missing file): red, naming the file part and not the fragment")

    # ── GREEN 3: the fragment branch's POSITIVE half. Without it, RED 3 passes
    # for a check that reds on every anchored link ever written.
    real = build(
        "green-3-fragment-real",
        {
            "docs/testing/page.md": "[x](./real-page.md#section)\n",
            "docs/testing/real-page.md": "constructed target\n",
        },
    )
    messages, _roots, _files, total, _src = doc_link_findings(real, 0, 0)
    if total != 1:
        record(False, f"GREEN 3 (an anchored link at a real file): the state is vacuous — {total} link(s) swept, not 1")
    elif messages:
        record(False, f"GREEN 3 (an anchored link at a real file): must be green, got {messages}")
    else:
        record(True, "GREEN 3 (an anchored link at a real file): green — the strip resolves the file and ignores the anchor")

    # ── GREEN 2: the code-span and fence exclusion, which has NO live subject,
    # plus its RED other half. A record ABOUT broken links necessarily QUOTES
    # broken links; without this pair the widening routed in D159 §4 item 5
    # could never go green, and the exclusion could widen to "skip everything"
    # with nothing noticing.
    quoted = (
        "A record that quotes a dead link: `[x](./quoted-in-a-span.md)`.\n"
        "\n"
        "```\n"
        "[x](./quoted-in-a-fence.md)\n"
        "```\n"
    )
    spans = build("green-2-quoted", {"docs/testing/page.md": quoted})
    messages, _roots, _files, total, _src = doc_link_findings(spans, 0, 0)
    if total or messages:
        record(False, f"GREEN 2 (a dead link inside a span and inside a fence): must be green and sweep 0, got {total} link(s) {messages}")
    else:
        record(True, "GREEN 2 (a dead link inside a span and inside a fence): green — neither is a link")

    escaped = build(
        "green-2-unquoted",
        {"docs/testing/page.md": quoted.replace("`[x](./quoted-in-a-span.md)`", "[x](./quoted-in-a-span.md)")},
    )
    messages, _roots, _files, total, _src = doc_link_findings(escaped, 0, 0)
    if total != 1 or len(messages) != 1 or "quoted-in-a-span.md" not in messages[0]:
        record(False, f"GREEN 2's red half (the SAME link moved outside the span): must be red on exactly that link, got {total} link(s) {messages}")
    else:
        record(True, "GREEN 2's red half (the SAME link moved outside the span): red — the exclusion is the span, not the text")

    # ── GREEN 1: the `.md` restriction, asserted rather than assumed, together
    # with the two branches R1 states have zero live subjects — `://` and a
    # leading `/`. All three targets below are dead on disk; all three must be
    # invisible to this check. An exclusion is evidence only once you have
    # watched it exclude.
    excluded = build(
        "green-1-non-md",
        {
            "docs/testing/page.md": (
                "[`crate::manifest_wire`](../manifest_wire/index.html)\n"
                "[x](https://example.invalid/docs/nowhere.md)\n"
                "[x](/docs/site-root/nowhere.md)\n"
            )
        },
    )
    messages, _roots, _files, total, _src = doc_link_findings(excluded, 0, 0)
    if total or messages:
        record(False, f"GREEN 1 (a rustdoc-HTML link, a URL and a site-root path): must be green and sweep 0, got {total} link(s) {messages}")
    else:
        record(True, "GREEN 1 (a rustdoc-HTML link, a URL and a site-root path): green — excluded by a property of the target, with no allowlist")

    return results


def check_doc_links(failures: Failures) -> None:
    check = "doc-links"
    # THIS CHECK COUNTS ITS OWN FAILURES, for the reason `check_machine_paths`
    # states one check up: `if not failures:` reads the SHARED object, so any
    # earlier check's finding would suppress this ok line. New code declines to
    # reproduce that.
    before = len(failures.messages)

    messages, per_root, n_files, total, crates_src = doc_link_findings(ROOT)
    for message in messages:
        failures.add(check, message)

    if len(failures.messages) == before:
        # BOTH exact counts AND the per-root breakdown, printed (D142 §2 R2 —
        # the number a reader needs must be printed, not left as a subtraction
        # that is available to everyone and performed by nobody). The per-root
        # split is what makes a collapsed walk readable BEFORE it reaches a
        # floor: `README.md` and `CONTRIBUTING.md` carry 35 of the 49 and are
        # swept for this by nothing else in the tree.
        breakdown = ", ".join(
            f"{root} {count}"
            for root, count in sorted(per_root.items(), key=lambda item: (-item[1], item[0]))
        )
        silent = len(CITATION_SCAN) - len(per_root)
        print(
            f"[{check}] ok — {total} markdown link(s) with a relative .md target "
            f"across {n_files} file(s) in {len(CITATION_SCAN)} scan root(s), every "
            f"one resolving on disk ({breakdown}; {silent} root(s) carry none); "
            f"{crates_src} of them under crates/*/src/, against floors "
            f"total >= {DOC_LINK_TOTAL_FLOOR} and crates-src >= "
            f"{DOC_LINK_CRATES_SRC_FLOOR}"
        )

# ── check 10: a record's ledger edits actually landed (Q?/D162 §2 R6) ───────
#
# WHAT THIS IS FOR, and it is not "does the ledger look tidy". D162 §1.2
# measured a cohort effect: three of wave 28's five resolved records shipped a
# ruling whose edit set had not been executed, and one of them was found only
# two waves later, by hand. *Resolved is not executed* — and nothing in this
# repository could see the gap, because the surfaces that record a resolution
# (the record file, the index row, the register) are all written by the act
# that resolves, while the edits are written by acts that follow.
#
# WHY THE LEDGER AND NOTHING ELSE. D162 §1.3 tested the checker hypothesis
# against every file class an edit set names and it failed 15–1: the general
# form ("every file named in an edit set mentions the record's id") flags 159
# targets against a hand-verified true rate near 2, and D162 §2 R7 REFUSED it
# on those counts — a 35 % flag rate against a <5 % true rate is noise with a
# threshold, and it trains lanes to ignore the check. The ledger is the one
# target with a machine-decidable contract: rule 8 fixes ONE line per finding
# and the entry format pins an attribution field between `·` separators, so
# "did this record's ledger edits land" is answerable by a regex rather than by
# reading prose. The second refused candidate ("every resolved record's edit
# set is executed") is not parseable at all — items are prose carrying verbatim
# quotes — and D161 §2 R6 governs: a decision is not made checkable by wrapping
# a constant in a script.
#
# THE MID-ACT WINDOW IS EXPECTED AND IS NOT A DEFECT. Like `decision-index`,
# this check reds on a record that exists before its edits land: D119 RULING 6
# splits those halves across actors, and the registrar closes the window at
# wave end. Measured at registration: `subject=18 findings=3`, naming D158
# (a real two-wave-old debt) and D162/D163 (wave 30's own records, mid-act).
# A LANE MUST NOT "FIX" THIS BY NARROWING THE SUBJECT — the narrowing is the
# defect, and the red is the instrument working.

DECISION_LEDGER = "docs/instrument-ledger.md"

# D162 §2 R6 fixes both halves of the section grab, and they are deliberately
# different levels. The OPENING regex takes any depth (`##`, `###`, `####`)
# because records spell the heading at whatever depth their §-numbering has
# reached; the CLOSING regex takes only `#` and `##`, so a `###` sub-heading
# INSIDE an edit list (a per-lane split, which D162 §4 itself uses) does not
# truncate the section and hide the ledger item that follows it.
EDIT_SECTION_HEADING = re.compile(r"^#+ .*([Ee]dit list|[Ee]dit set)")
EDIT_SECTION_END = re.compile(r"^#{1,2} ")

# THE VACUITY GUARD, and it is mandatory (D162 §2 R6, on D159 §2 R1's floor
# discipline). Either regex above drifting — a heading reworded, a `#` level
# changed — yields subject 0 and a silent, permanent, vacuous pass, which is
# this project's dominant defect class. The floor is a FLOOR, not an equality:
# the subject was 18 when this was written and grows with every record that
# names the ledger. LOWER-ONLY BY DECISION; an implementer who needs a run to
# go green is exactly who this is written against.
DECISION_LEDGER_SUBJECT_FLOOR = 16

# The filename shape that carries a decision id. `README.md` is the index, not
# a record, and does not match.
DECISION_RECORD_NAME = re.compile(r"^D(\d+)-")


def decision_ledger_attribution(number: int) -> re.Pattern[str]:
    """The ledger line shape that discharges `D<number>`, per D162 §2 R6.

    `^- .*·[^·]*\\bD<n>\\b[^·]*·` — an ENTRY line (rule 8's `- ` bullet, so
    ledger prose and the format block above `## Entries` are not entries)
    whose id sits inside a `·`-delimited field that is FOLLOWED BY ANOTHER `·`.

    What that excludes, stated precisely rather than generously: the TRAILING
    field. Nothing after the last `·` can discharge anything, and the trailing
    field is the POINTER — which is exactly where entries cite records other
    than their own (`· docs/decisions/D67-….md §4`, `· D67 §9(i)`). What it
    does NOT exclude is a mention in the finding body, which is also a
    non-trailing field; the rule is "in a delimited field, not at the end",
    not "in the finder field". D162 §2 R6 measured that looser rule at **0**
    false positives across 67 record-tree observations on five trees, and
    §1.3 measured the alternative general form at a 35 % flag rate against a
    <5 % true rate; this is the shape that survived, and its exact boundary is
    pinned by the self-test arms below rather than left to this paragraph.

    `\\b` on both sides is load-bearing in one direction that matters: `\\bD16\\b`
    does not match `D162`, so no record is ever discharged by a longer id that
    merely starts with its digits.
    """
    return re.compile(rf"^- .*·[^·]*\bD{number}\b[^·]*·", re.MULTILINE)


def decision_ledger_debt_findings(
    tree: pathlib.Path,
    subject_floor: int = DECISION_LEDGER_SUBJECT_FLOOR,
) -> tuple[list[str], int, int, int]:
    """`(messages, subject, records, entries)` for one tree. Never raises.

    A PURE FUNCTION over a tree root, for the reason `doc_link_findings` states:
    the self-test arms must exercise it on CONSTRUCTED trees where the live
    subject cannot reach them, and a check that can only be run against ROOT is
    a check whose red half is never seen. `subject_floor` is a PARAMETER so a
    three-file fixture can exercise the attribution rule without the floor
    drowning it — `check_decision_ledger_debt` below always passes the
    constant, and nothing else may.
    """
    records = 0
    subject: list[int] = []
    messages: list[str] = []

    ledger_path = tree / DECISION_LEDGER
    try:
        ledger = ledger_path.read_text(encoding="utf-8")
    except OSError:
        ledger = ""
    entries = sum(1 for line in ledger.splitlines() if line.startswith("- "))

    for path in sorted((tree / "docs/decisions").glob("D*.md")):
        named = DECISION_RECORD_NAME.match(path.name)
        if not named:
            continue
        records += 1
        number = int(named.group(1))
        try:
            body = path.read_text(encoding="utf-8")
        except OSError:
            continue

        section: list[str] = []
        inside = False
        for line in body.splitlines():
            if inside:
                if EDIT_SECTION_END.match(line):
                    inside = False
                    continue
                section.append(line)
            elif EDIT_SECTION_HEADING.match(line):
                inside = True
        if DECISION_LEDGER not in "\n".join(section):
            continue

        subject.append(number)
        if decision_ledger_attribution(number).search(ledger):
            continue
        messages.append(
            f"docs/decisions/{path.name}: this record's edit set names "
            f"`{DECISION_LEDGER}`, and the ledger carries no entry attributed "
            f"to D{number} — no line matches `^- .*·[^·]*\\bD{number}\\b[^·]*·`, "
            f"so the id appears in no `·`-delimited field of any entry. Either "
            f"the ruling's ledger edits were never executed (D162 §1.2: three "
            f"of wave 28's five records shipped a ruling whose edit set had not "
            f"been made, and one was found two waves later by hand), or this is "
            f"the routine mid-act window — a record landing before the "
            f"registrar writes its entries, exactly as `decision-index` reds "
            f"between the two halves D119 RULING 6 splits across actors. Fix it "
            f"by WRITING THE LEDGER LINES, attributed `· D{number}'s lane (wave "
            f"N) ·` per rule 8's entry format. NEVER by narrowing this check's "
            f"subject, which is the defect it exists to catch (D162 §2 R6)."
        )

    if len(subject) < subject_floor:
        messages.append(
            f"the sweep found {len(subject)} record(s) whose edit set names "
            f"`{DECISION_LEDGER}` where DECISION_LEDGER_SUBJECT_FLOOR requires "
            f"at least {subject_floor}: {len(subject)} < {subject_floor}. A "
            f"count below the floor means the SECTION GRAB collapsed, not that "
            f"the records got tidier — check EDIT_SECTION_HEADING and "
            f"EDIT_SECTION_END first, and note that {records} record file(s) "
            f"were read to produce it. Without this assertion a reworded "
            f"heading gives subject 0 and a green run for ever, which is the "
            f"defect class D159 §2 R1 minted floors against. LOWER-ONLY BY "
            f"DECISION (D162 §2 R6)."
        )
    return messages, len(subject), records, entries


def prove_decision_ledger_debt_arms(scratch: pathlib.Path) -> list[tuple[bool, str]]:
    """Require `decision-ledger-debt`'s branches on CONSTRUCTED trees.

    D162 §4 item 3, and the constructed subject is the POINT rather than a
    convenience. This check's live red half is D158 — a debt the registrar
    discharges inside the same wave that mints the check, after which the live
    subject is green for ever and the red arms would be proving nothing on a
    tree that can no longer produce them. Every fixture below is written by
    this function; nothing is derived from ROOT, so no amount of tree health or
    tree sickness can decide a verdict (Q252, and Q234's general form).

    Called before the staged copy for the same reason `prove_doc_link_arms` is:
    `--self-test` stages a full copy of a tree other lanes are writing, so it
    may not be run mid-wave, and these arms can be called directly instead.
    """
    results: list[tuple[bool, str]] = []

    # Constructed ids, deliberately outside the allocated range, so no arm can
    # be quietly satisfied by a real ledger line about a real record.
    ABSENT, PRESENT, FLOOR_ONLY = 901, 902, 903

    def record_text(number: int) -> str:
        return (
            f"# D{number} — constructed by prove_decision_ledger_debt_arms\n"
            "\n"
            "## 4. Edit list — per file, with the timing word\n"
            "\n"
            f"1. `{DECISION_LEDGER}` — one dated line for this record's finding.\n"
            "\n"
            "## 5. Something after the edit list\n"
        )

    def entry(number: int) -> str:
        return (
            f"- 2026-08-22 · D{number}'s lane (wave 30) · a constructed finding "
            f"· docs/decisions/D{number}-constructed.md\n"
        )

    def build(name: str, ledger: str, records: dict[int, str]) -> pathlib.Path:
        tree = scratch / name
        path = tree / DECISION_LEDGER
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(ledger, encoding="utf-8")
        for number, body in records.items():
            target = tree / "docs/decisions" / f"D{number}-constructed.md"
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(body, encoding="utf-8")
        return tree

    def record(passed: bool, sentence: str) -> None:
        results.append((passed, sentence))

    # ── RED 1: a record whose edit set names the ledger, and a ledger with
    # entries but none attributed to it. D162 §2 R6's first plant (delete
    # D157's ledger lines → RED naming D157), reconstructed rather than
    # borrowed. The green record beside it is what makes this arm say
    # "attribution", not "the ledger is short".
    mixed = build(
        "red-1-attribution-absent",
        entry(PRESENT),
        {ABSENT: record_text(ABSENT), PRESENT: record_text(PRESENT)},
    )
    messages, subject, records_read, entries = decision_ledger_debt_findings(mixed, 0)
    if (subject, records_read, entries) != (2, 2, 1):
        record(False, f"RED 1 (one record attributed, one not): the state is vacuous — subject/records/entries {(subject, records_read, entries)}, wanted (2, 2, 1)")
    elif len(messages) != 1 or f"D{ABSENT}" not in messages[0]:
        record(False, f"RED 1 (one record attributed, one not): expected exactly one finding naming D{ABSENT}, got {messages}")
    elif f"D{PRESENT}-constructed.md" in messages[0]:
        record(False, f"RED 1 (one record attributed, one not): the finding names the DISCHARGED record too, so it is not reading attribution: {messages}")
    else:
        record(True, f"RED 1 (one record attributed, one not): red on D{ABSENT} alone, naming the record file and the pattern it wanted")

    # ── RED 2: the whole subject, against an EMPTY ledger. D162 §2 R6's second
    # plant (empty the ledger → RED 16). This is the arm that separates "no
    # entry for this record" from "no ledger at all": the failure must be per
    # record, so a registrar reading it knows how many lines to write.
    emptied = build(
        "red-2-empty-ledger",
        "# Instrument-finding ledger\n\n## Entries\n",
        {ABSENT: record_text(ABSENT), PRESENT: record_text(PRESENT)},
    )
    messages, subject, _records, entries = decision_ledger_debt_findings(emptied, 0)
    named = all(any(f"D{n}-constructed.md" in m for m in messages) for n in (ABSENT, PRESENT))
    if (subject, entries) != (2, 0):
        record(False, f"RED 2 (an empty ledger): the state is vacuous — subject {subject} entries {entries}, wanted 2 and 0")
    elif len(messages) != 2 or not named:
        record(False, f"RED 2 (an empty ledger): the whole subject must red, one finding each; got {messages}")
    else:
        record(True, "RED 2 (an empty ledger): red on the WHOLE subject, one finding per record rather than one for the ledger")

    # ── GREEN CONTROL: the same two records, both attributed. Without this the
    # two arms above are satisfied by a check that reds on everything for ever,
    # which is the failure mode a red-only harness cannot see.
    both = build(
        "green-control-attributed",
        entry(ABSENT) + entry(PRESENT),
        {ABSENT: record_text(ABSENT), PRESENT: record_text(PRESENT)},
    )
    messages, subject, _records, entries = decision_ledger_debt_findings(both, 0)
    if (subject, entries) != (2, 2):
        record(False, f"GREEN CONTROL (both records attributed): the state is vacuous — subject {subject} entries {entries}, wanted 2 and 2")
    elif messages:
        record(False, f"GREEN CONTROL (both records attributed): must be green, got {messages}")
    else:
        record(True, "GREEN CONTROL (both records attributed): green — so the red arms above are a property of the state, not of the check")

    # ── THE FLOOR GUARD, and it is the arm this check exists to keep honest.
    # The subject here is FULLY DISCHARGED — every record has its line — so the
    # attribution rule is silent and the ONLY thing that can speak is the
    # floor. A heading regex that drifts yields subject 0 and, without this,
    # a permanent vacuous green. Note the REAL constant is passed: an arm that
    # invented its own floor would prove a parameter, not the shipped check.
    below = build(
        "floor-below",
        entry(FLOOR_ONLY),
        {FLOOR_ONLY: record_text(FLOOR_ONLY)},
    )
    messages, subject, _records, _entries = decision_ledger_debt_findings(below)
    wanted = f"1 < {DECISION_LEDGER_SUBJECT_FLOOR}"
    if subject != 1:
        record(False, f"FLOOR GUARD (a discharged subject of 1 against the real floor): the state is vacuous — subject {subject}, wanted 1")
    elif len(messages) != 1 or wanted not in messages[0]:
        record(False, f"FLOOR GUARD (a discharged subject of 1 against the real floor): expected one finding saying {wanted!r}, got {messages}")
    else:
        record(True, f"FLOOR GUARD (a discharged subject of 1 against the real floor): red on the floor alone, saying {wanted}")

    # ── FLOOR GUARD's other half. The same tree, the same discharged subject,
    # with the floor lowered to what the tree actually carries: it must go
    # GREEN. Without this, the arm above is satisfied by a floor that reds at
    # every count, and "the floor fired" would mean nothing.
    messages, subject, _records, _entries = decision_ledger_debt_findings(below, 1)
    if subject != 1:
        record(False, f"FLOOR GUARD's green half (the floor lowered to the count): the state is vacuous — subject {subject}, wanted 1")
    elif messages:
        record(False, f"FLOOR GUARD's green half (the floor lowered to the count): must be green at subject == floor, got {messages}")
    else:
        record(True, "FLOOR GUARD's green half (the floor lowered to the count): green at subject == floor, so the floor is a threshold and not a constant red")

    # ── THE BOUNDARY the docstring claims, pinned rather than asserted in
    # prose: an id in the TRAILING (pointer) field discharges NOTHING, because
    # that is the field in which entries cite records other than their own. The
    # same id moved one field left discharges. Two builds, one difference.
    pointer_only = (
        f"- 2026-08-22 · some other lane · an unrelated finding "
        f"· docs/decisions/D{ABSENT}-constructed.md\n"
    )
    trailing = build("boundary-trailing-field", pointer_only, {ABSENT: record_text(ABSENT)})
    messages, subject, _records, _entries = decision_ledger_debt_findings(trailing, 0)
    if subject != 1:
        record(False, f"BOUNDARY (the id in the trailing pointer field): the state is vacuous — subject {subject}, wanted 1")
    elif len(messages) != 1:
        record(False, f"BOUNDARY (the id in the trailing pointer field): a pointer citing another record must not discharge it; got {messages}")
    else:
        record(True, "BOUNDARY (the id in the trailing pointer field): red — a trailing citation of a record is not an entry attributed to it")

    moved = build(
        "boundary-field-moved-left",
        pointer_only.replace("some other lane", f"D{ABSENT}'s lane (wave 30)"),
        {ABSENT: record_text(ABSENT)},
    )
    messages, subject, _records, _entries = decision_ledger_debt_findings(moved, 0)
    if subject != 1:
        record(False, f"BOUNDARY's green half (the SAME id one field left): the state is vacuous — subject {subject}, wanted 1")
    elif messages:
        record(False, f"BOUNDARY's green half (the SAME id one field left): must be green, got {messages}")
    else:
        record(True, "BOUNDARY's green half (the SAME id one field left): green — the rule is the delimited field, not the substring")

    return results


def check_decision_ledger_debt(failures: Failures) -> None:
    check = "decision-ledger-debt"
    # THIS CHECK COUNTS ITS OWN FAILURES, for the reason `check_doc_links`
    # states one check up: `if not failures:` reads the SHARED object, so any
    # earlier check's finding would suppress this ok line.
    before = len(failures.messages)

    messages, subject, records, entries = decision_ledger_debt_findings(ROOT)
    for message in messages:
        failures.add(check, message)

    if len(failures.messages) == before:
        # Every number a reader needs is PRINTED, not left as a subtraction
        # available to everyone and performed by nobody (D142 §2 R2). The
        # subject count is here even when green, because "0 problems" and "0
        # records examined" print the same word otherwise.
        print(
            f"[{check}] ok — {subject} record(s) of {records} name "
            f"`{DECISION_LEDGER}` in an edit list, and every one of them "
            f"carries at least one `·`-attributed line among the {entries} "
            f"ledger entries; subject {subject} >= floor "
            f"{DECISION_LEDGER_SUBJECT_FLOOR}"
        )


CHECKS = {
    "freeze-boundary": check_freeze_boundary,
    "matrix": check_matrix,
    "decisions": check_decisions,
    "task-citations": check_task_citations,
    "task-entries": check_task_entries,
    "decision-owners": check_decision_owners,
    "decision-index": check_decision_index,
    "machine-paths": check_machine_paths,
    "doc-links": check_doc_links,
    "decision-ledger-debt": check_decision_ledger_debt,
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
            "last milestone whose review has passed; the --matrix status gate "
            "requires every row at or before it to read 'covered' "
            f"(default: {CURRENT_MILESTONE}, moved by the milestone-gate row for "
            "the milestone that just passed — TODO.md rule 4)"
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
    import fnmatch
    import shutil
    import tempfile
    import time

    ok = True
    with tempfile.TemporaryDirectory() as scratch:
        tree = pathlib.Path(scratch) / "tree"

        # ── the mint fixture's own proof, before anything is staged ─────────
        # `lowest_unhomed_decision_id()` decides the subject of two `decisions`
        # arms, and its predecessor RAISED on a state this tree occupies for
        # part of every planning wave — records on disk the register has not
        # allocated yet — taking `--self-test` and with it a required status
        # context red before a single arm ran. Its three properties are
        # therefore required against CONSTRUCTED states, on disk, before the
        # live tree is read at all. Nothing below is derived from ROOT, so no
        # amount of tree health or tree sickness can decide the verdict (Q252,
        # and Q234's general form: a derived fixture is only as safe as the
        # surface it derives from).
        for passed, sentence in prove_lowest_unhomed_mint(pathlib.Path(scratch) / "mint-proof"):
            if passed:
                print(f"self-test: ok — the decisions mint holds on a constructed {sentence}")
            else:
                print(
                    f"self-test: FAILED — the decisions mint does not hold on a "
                    f"constructed {sentence}",
                    file=sys.stderr,
                )
                ok = False

        # ── the doc-link arms, also before anything is staged ───────────────
        # D159 §2 R3. FIVE of this check's seven branches have NO LIVE SUBJECT
        # anywhere in the tree — `#fragment` stripping in both directions, the
        # code-span/fence exclusion in both directions, and the site-root and
        # `://` rejections — so they can only ever be exercised against a
        # CONSTRUCTED state. They are therefore proven here, on trees this
        # function writes itself, before the live tree is read at all; the two
        # branches that DO have live subjects ride the delta harness below
        # instead. Nothing in the loop is derived from ROOT.
        for passed, sentence in prove_doc_link_arms(pathlib.Path(scratch) / "doc-link-arms"):
            if passed:
                print(f"self-test: ok — doc-links holds on a constructed {sentence}")
            else:
                print(
                    f"self-test: FAILED — doc-links does not hold on a constructed "
                    f"{sentence}",
                    file=sys.stderr,
                )
                ok = False

        # ── the ledger-debt arms, also before anything is staged ───────────
        # D162 §4 item 3. This check's ONE live red half is D158, a debt the
        # registrar discharges inside the very wave that mints the check —
        # after which the live subject is green for ever and a delta harness
        # could never produce a red again. So every arm builds its own state
        # on disk, with constructed ids outside the allocated range, and none
        # of it is derived from ROOT (Q252, and Q234's general form). The one
        # arm that DOES read a real constant is the floor guard, and it reads
        # the shipped `DECISION_LEDGER_SUBJECT_FLOOR` rather than a fixture
        # copy of it, because a floor proven at an invented value is a proof
        # about a parameter.
        for passed, sentence in prove_decision_ledger_debt_arms(
            pathlib.Path(scratch) / "ledger-debt-arms"
        ):
            if passed:
                print(f"self-test: ok — decision-ledger-debt holds on a constructed {sentence}")
            else:
                print(
                    f"self-test: FAILED — decision-ledger-debt does not hold on a "
                    f"constructed {sentence}",
                    file=sys.stderr,
                )
                ok = False

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
        # WHICH TREE, and the trade-off recorded rather than assumed (Q191 /
        # D120 R1). This stages the WORKING tree — every uncommitted edit
        # included — because the arms must exercise the tree the contributor is
        # about to push, which is the same tree the flagless half checks. A
        # `git archive HEAD` snapshot was measured head to head and refused: on
        # one working tree carrying an uncommitted edit that had already killed
        # a fixture, the snapshot exited 0 and printed twenty-eight lines of
        # "ok". It would prove the checks can bite committed content while
        # leaving the thing being checked unproven — and in CI it is a no-op,
        # because the runner's checkout IS `HEAD`, so its only real effect is
        # to move fixture-rot detection off the developer's machine.
        #
        # WHAT of that tree, and it is git that decides (D120 R2). The staged
        # set is `git ls-files` ∪ `git ls-files --others --exclude-standard`.
        # The reason for excluding what git ignores is not tidiness: NO CHECK
        # CAN OPEN IT. `fuzz/corpus` and `fuzz/artifacts` alone were 922 files
        # — 46.5% of the staged entries — outside every citation scan root,
        # outside the register and outside the matrix, and rewritten
        # continuously by `cargo fuzz` while this copy runs. Measured, the old
        # tuple staged 1,983 files where at most 474 are readable by any check.
        # Git also knows the residue a hand-written tuple never will, including
        # the entries in `.git/info/exclude` that a `.gitignore` parser cannot
        # see — `.claude/scheduled_tasks.lock` was staged on every local run.
        #
        # Two guards, because they cover different things, and NEITHER closes
        # the class alone.
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
        #     KEPT ON TOP OF GIT'S SET, and measured (D120 R3): `git
        #     check-ignore` reports BOTH spellings of this shape as NOT
        #     ignored, so git's knowledge does not subsume this glob any more
        #     than this glob subsumes git's.
        # (2) A bounded retry, because the glob only names the transients we
        #     already know about. `__pycache__/*.pyc` is written and replaced by
        #     any concurrent `python3 scripts/…` run and is NOT ignored here,
        #     and an editor `.swp` has been observed appearing under
        #     `testdata/vectors/v1/` from a gate script. Those cost one retry
        #     each instead of a red lane. Both are now git-ignored and gone
        #     before the retry sees them; the retry stays as the BACKSTOP for
        #     what R4 does not cover — a tracked file genuinely removed
        #     mid-stage, or an I/O fault.
        #
        # The retry is bounded and reports rather than raising: a copy that
        # fails three times is an environment fault, not a transient, and it
        # must say so in a sentence instead of a stack trace. It is NOT a
        # silent swallow — the last failure is printed with its cause.
        def git_paths(*selectors: str) -> list[str]:
            """One `ls-files` listing, NUL-separated, relative to ROOT.

            Raises `OSError` on a git failure so the retry below sees it
            through its existing `except` clause rather than through a new one.
            """
            listing = subprocess.run(
                ["git", "-C", str(ROOT), "ls-files", "-z", *selectors],
                capture_output=True,
                text=True,
            )
            if listing.returncode != 0:
                raise OSError(
                    f"git ls-files {' '.join(selectors)} failed: {listing.stderr.strip()}"
                )
            return [entry for entry in listing.stdout.split("\0") if entry]

        def stage_as_git_sees_it() -> int:
            """Copy git's view of ROOT into `tree`; return the skipped count.

            D120 R4, and the asymmetry is measured rather than assumed: under a
            continuous writer the tracked list lost nothing across three runs
            while the untracked list lost 1, 31 and 49 entries. A tracked path
            cannot vanish under an atomic-write discipline — `rename` never
            leaves the name absent — so its disappearance is a real event and
            is re-raised into the retry. An untracked one disappearing is the
            definition of transient: counted, skipped, and announced.
            """
            listed = [(entry, True) for entry in git_paths()]
            listed += [
                (entry, False) for entry in git_paths("--others", "--exclude-standard")
            ]
            skipped = 0
            for entry, tracked in listed:
                if fnmatch.fnmatch(entry, "*.tmp.*"):
                    continue
                destination = tree / entry
                try:
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(ROOT / entry, destination)
                except (FileNotFoundError, NotADirectoryError):
                    if tracked:
                        raise
                    skipped += 1
            return skipped

        def git_can_see_this_tree() -> bool:
            """D120 R8. `git` is not a Python dependency and the CI job cannot
            exist without it — `actions/checkout` IS git — but a source tarball
            has no work tree, and the docstring's standard-library-only
            commitment has to survive that. When this is false the old
            `copytree` stages the tree instead, and the run says which
            mechanism it used, so a run's provenance is never ambiguous."""
            try:
                probe = subprocess.run(
                    ["git", "-C", str(ROOT), "rev-parse", "--is-inside-work-tree"],
                    capture_output=True,
                    text=True,
                )
            except OSError:
                return False
            return probe.returncode == 0 and probe.stdout.strip() == "true"

        from_git = git_can_see_this_tree()
        vanished = 0
        copy_attempts = 3
        for attempt in range(1, copy_attempts + 1):
            try:
                if from_git:
                    tree.mkdir(parents=True, exist_ok=True)
                    vanished = stage_as_git_sees_it()
                else:
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

        # Provenance, always printed (D120 R8): a reader must never have to
        # guess which of the two mechanisms produced the tree an arm exercised.
        print(
            "self-test: staged "
            + (
                "git's view of the working tree (ls-files + others, "
                "--exclude-standard), minus the atomic-write shape"
                if from_git
                else "a full copy of the working tree — git could not see this "
                "tree, so the pre-D120 copytree staged it"
            )
        )
        if vanished:
            # R4's announced skip. Silence here would make a shrinking tree
            # indistinguishable from a stable one.
            print(
                f"self-test: note — {vanished} untracked path(s) vanished between "
                "listing and copy and were skipped; a tracked path doing the same "
                "is an error and would have gone to the retry above"
            )

        # Q66 — the gate-state fixtures derive their mutation from whatever
        # state the row is in, never from a hardcoded `- [ ]` literal. The
        # first fixtures wrote the literals out, so the moment Q14's execution
        # ticked the normative rows all three mutations matched nothing and
        # this self-test failed vacuous — red from the gate commit onward,
        # invisible until the lane first ran locally (`local-gate.sh` gained
        # the lane in the same commit as this fix).
        # Q184 — and every pattern below is anchored at the START OF A LINE.
        # Unanchored, `sub(..., count=1)` takes the first match ANYWHERE, and a
        # sentence *about* one of these fixtures contains the fixture's own
        # literal: `tasks/Q.md` carries a backticked marker-plus-title copy of
        # the pair these three are aimed at, inside the prose of the entry that
        # records why they exist. It sorts below the block today and above it
        # after any edit that moves either. The anchor makes the ordering
        # irrelevant, because a quotation is indented, fenced or mid-sentence
        # and a row is not. See the fixture rule above `cases`.
        def strip_marker(row: str):
            """Delete the checkbox marker ahead of `row`, whatever its state."""
            pattern = re.compile(r"^- \[[ xX]\] (\*\*" + re.escape(row) + ")", re.M)
            return lambda t: pattern.sub(r"- \1", t, count=1)

        def flip_tick(row: str):
            """Tick an unticked `row`, untick a ticked one — always a real change."""
            pattern = re.compile(r"^- \[([ xX])\] (\*\*" + re.escape(row) + ")", re.M)
            return lambda t: pattern.sub(
                lambda m: ("- [x] " if m.group(1) == " " else "- [ ] ") + m.group(2),
                t,
                count=1,
            )

        def retick_upper(row: str):
            """Rewrite `row`'s marker to the uppercase `[X]` form (to `[ ]` if
            already uppercase) — the case-insensitivity bound."""
            pattern = re.compile(r"^- \[([ xX])\] (\*\*" + re.escape(row) + ")", re.M)
            return lambda t: pattern.sub(
                lambda m: ("- [ ] " if m.group(1) == "X" else "- [X] ") + m.group(2),
                t,
                count=1,
            )

        def rewrite_line(line: str, replacement: str):
            """Rewrite `line` — matched as a WHOLE line — once, wherever it sits.

            The anchored form of `t.replace(x, y, 1)`, and the reason is Q184's
            second rule: a first-occurrence replacement over a whole file is
            taken by the first COPY of the literal, which is routinely a
            sentence describing the fixture rather than the thing the check
            reads. Measured in this tree, three such copies exist and one of
            them has already absorbed a mutation and reported its case green.
            `replacement` carries its own newline; pass "" to delete the line.
            """
            pattern = re.compile("^" + re.escape(line) + "\n", re.M)
            return lambda t: pattern.sub(lambda _match: replacement, t, count=1)

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

        def an_owner_assignment() -> tuple[int, str, str, str]:
            """`(decision number, owner id, decision filename, the whole
            assignment line)` for the first per-ruling assignment whose owned
            row ALREADY names the decision — so case (l)'s deletion is a real
            removal and not a no-op.

            The line comes back with the id (Q184) because case (m) rewrites it
            and must do so anchored: the bold `Owner:` form also occurs
            INDENTED in this corpus (D113 §1.2 counts it among the four prose
            shapes), and an indented copy earlier in the same document would
            take an unanchored replacement while the assignment the check
            parses stayed put.
            """
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
                for line in path.read_text(encoding="utf-8").splitlines():
                    hit = DECISION_OWNER.match(line)
                    if not hit:
                        continue
                    owner = hit.group(1)
                    if owner in rows and re.search(rf"\bD{number}\b", rows[owner]):
                        return number, owner, path.name, line
            raise AssertionError(
                "self-test: no per-ruling owner assignment has a back-citing row, so the "
                "decision-owners cases would be built from nothing"
            )

        # ── Q184's fixtures ─────────────────────────────────────────────────
        # Q66's rule applied to the four checks it never reached. Everything
        # below reads the scratch tree and RAISES rather than returning a
        # literal, for the reason Q85's helpers do: a fixture built from a
        # borrowed sentence, status or checkbox state has that value's
        # lifetime, and the values a project edits every wave are exactly the
        # ones it borrows most readily.

        def a_boundary_rule_line(relative: str) -> str:
            """A line of RULE TEXT from inside `relative`'s freeze-boundary
            block, unique in that file.

            Rule text, not a checkbox row: the marker cases below already own
            gate state, and this one has to prove that an ordinary byte inside
            the block still bites. Uniqueness is computed rather than assumed —
            this file mirrors the same rules by hand OUTSIDE the markers a few
            dozen lines above, so a reworded mirror is one edit away from
            standing in front of an unanchored replacement.
            """
            text = (tree / relative).read_text(encoding="utf-8")
            block = extract_boundary(tree / relative)
            if block is None:
                raise AssertionError(
                    f"self-test: {relative} has no freeze-boundary block, so the drift "
                    "fixture would be built from nothing"
                )
            for line in block.splitlines():
                if not line.strip() or CHECKBOX_MARKER.match(line):
                    continue
                if text.count(line + "\n") == 1:
                    return line
            raise AssertionError(
                f"self-test: no rule-text line inside {relative}'s freeze-boundary block "
                "occurs exactly once in the file, so no drift mutation can be anchored"
            )

        def boundary_checkbox_titles(relative: str) -> list[str]:
            """The bold lead-in of every checkbox row inside `relative`'s
            freeze-boundary block, in order.

            These titles used to be spelled out here. They are prose inside a
            frozen block — safe against ordinary edits, but not against the
            re-cut that any amendment of D84 §7 requires, and a re-cut is
            precisely the event these three cases exist to survive.
            """
            block = extract_boundary(tree / relative)
            if block is None:
                raise AssertionError(
                    f"self-test: {relative} has no freeze-boundary block, so the marker "
                    "fixtures would be built from nothing"
                )
            titles = re.findall(r"^- \[[ xX]\] \*\*(.+?)\*\*", block, re.M)
            if len(titles) < 2:
                raise AssertionError(
                    f"self-test: {relative}'s freeze-boundary block holds {len(titles)} "
                    "checkbox row(s); the marker cases need two distinct rows, one for the "
                    "red arm and one for the case-insensitivity arm"
                )
            return titles

        def scratch_matrix_rows() -> list[tuple[str, str, str, int]]:
            """`(milestone, status, whole line, index of the status field)` for
            every matrix row whose status cell can be located unambiguously and
            whose line occurs exactly once in the file.

            Both filters are Q184's: a row whose status text also appears in
            another of its own cells cannot be restatused by field index, and a
            line with a second copy cannot be rewritten by anchor alone. The
            file carries a backticked copy of one row's milestone/task/status
            cells in the prose recording D118's retarget, which is what a
            fixture pinned to that fragment would collide with.
            """
            path = tree / MATRIX
            text = path.read_text(encoding="utf-8")
            lines = text.splitlines()
            found: list[tuple[str, str, str, int]] = []
            for row in parse_matrix(path):
                status = row.get("status", "").strip("*` ").lower()
                milestone = row.get("milestone", "").strip("*` ").upper()
                line = lines[int(row["_line"]) - 1]
                fields = line.split("|")
                hits = [i for i, f in enumerate(fields) if f.strip("*` ").lower() == status]
                if len(hits) != 1 or text.count(line + "\n") != 1:
                    continue
                found.append((milestone, status, line, hits[0]))
            if not found:
                raise AssertionError(
                    "self-test: no matrix row yielded an unambiguous status cell, so the "
                    "status-gate fixtures would be built from nothing"
                )
            return found

        def restatus(line: str, field: int, status: str) -> str:
            """`line` with its status field replaced, every other byte kept."""
            fields = line.split("|")
            fields[field] = f" {status} "
            return "|".join(fields)

        def a_unique_rust_test_reference() -> str:
            """The first `path.rs::name` reference in the matrix that occurs
            exactly once in the file, backticks included.

            The reference is mutated whole. The case used to replace the first
            `::` in the document, which is a two-byte literal with 66 hits
            here: it landed on a reference cell only because no prose above the
            first table happened to contain one, and Q185 is rewriting exactly
            that prose.
            """
            text = (tree / MATRIX).read_text(encoding="utf-8")
            for row in parse_matrix(tree / MATRIX):
                for reference in REFERENCE.findall(row.get("tests / evidence", "")):
                    if RUST_TEST.match(reference) and text.count(f"`{reference}`") == 1:
                        return reference
            raise AssertionError(
                "self-test: no Rust-test reference in the matrix occurs exactly once, so "
                "the unresolvable-reference mutation cannot be aimed"
            )

        def scratch_decision_citations() -> dict[int, set[str]]:
            """`D<n> -> the swept files naming it`, over the scratch tree.

            Reads `CITATION_SCAN`/`CITATION_SUFFIXES` rather than restating
            them, so a narrowing of either moves this fixture with the check
            instead of leaving it aimed at a surface nothing reads any more.

            COST, recorded rather than hidden (Q184): this is a THIRD copy of
            the two-branch scan loop `check_decisions` and
            `sweep_task_surfaces` already share, and D116 R1/R2 collapsed five
            constants into one pair precisely so those two could not disagree.
            The constants are shared, so the surfaces cannot drift; the prune
            set and the file/directory branch are now spelled three times and
            can. The consolidation belongs with whoever next rules on that
            constant, and this comment is the pointer to it.

            AND THE BILL ARRIVED IN THE SAME WAVE (D123 §7.1 E1b). The next
            ruling on that constant changed the loop, and this copy had to take
            the change by hand: under D123 a LITERAL entry is read UNFILTERED
            and only a DIRECTORY entry is suffix-filtered. Sharing the
            constants while copying the filter is exactly what would have
            defeated the intent stated two paragraphs up — the surfaces cannot
            drift, because the constants are shared, but the SEMANTICS can, and
            an unpatched copy here would have aimed this fixture at a narrower
            surface than the check reads while still claiming to follow it.
            """
            found: dict[int, set[str]] = {}
            for sub in CITATION_SCAN:
                base = tree / sub
                if not base.exists():
                    continue
                literal = base.is_file()
                for path in [base] if literal else base.rglob("*"):
                    if not path.is_file() or (not literal and path.suffix not in CITATION_SUFFIXES):
                        continue
                    if {"target", "node_modules", "__pycache__"} & set(path.parts):
                        continue
                    rel = str(path.relative_to(tree))
                    if rel == CITATION_SCAN_SELF:
                        continue
                    try:
                        text = path.read_text(encoding="utf-8")
                    except (UnicodeDecodeError, OSError):
                        continue
                    for number in re.findall(r"\bD(\d+)\b", text):
                        found.setdefault(int(number), set()).add(rel)
            return found

        def plant_an_unrecorded_decision() -> str:
            """Mint `D<ceiling+1>`, plant a normative citation of it in a swept
            file, and return the id. The two `decisions` arms below then build
            the Q57 failure — "RESOLVED, record never written" — by adding a
            register row for it, and its exemption by adding an open one.

            ══ WHY THE SUBJECT IS CONSTRUCTED AND NO LONGER FOUND (Q252) ══════
            This helper used to SEARCH the register for a decision that was
            open, cited, unrecorded and unhomed, and return its line for the
            arm to tick. That search was itself a repair, and its reasoning is
            kept because it is still right as far as it goes: before it, the
            case NAMED one decision and thereby pinned that decision's
            UNRESOLVED STATE, so the day it resolved the line the mutation
            spelled would no longer exist in that form and the case would
            disarm itself at the exact moment its subject stopped being
            hypothetical. Deriving the subject fixed that. Three decisions
            qualified when it was written.

            It fixed the wrong half. The dependency it removed was on ONE
            decision staying open; the dependency it kept was on SOME decision
            staying open — and on 2026-08-17, commit 985ad05 closed D71, D72,
            D73 and D134 in one round and took the register to ZERO open
            decisions for the first time in the project's life. The search
            found nothing and raised, `--self-test` exited 1 before a single
            arm ran, `ci-lanes.sh lane_traceability` runs this half FIRST and
            returns on its failure, and `traceability` is one of 19 required
            status contexts. A drained register — the healthiest state the
            bookkeeping can reach — took a required context red. Measured, not
            inferred: `git worktree add --detach` at 59c47ad reproduces it with
            REAL_EXIT=1, so it predates the wave that found it.

            The assertion it raised offered its own remedy — *"if the register
            really is in that state, the case has nothing left to prove and
            goes with it"* — and that is REFUSED. What the case proves is that
            `check_decisions` bites a decision cited as normative, allocated,
            and holding no record, no registered home and no open row. That
            property does not stop mattering when the register is clean; it
            matters most on the next decision minted whose record is forgotten,
            which is precisely when nobody is looking. A case that disarms
            itself whenever the tree is healthy is the assertion-that-cannot-
            fail class, and Q234 is the same shape one fixture over: *the
            self-test's TODO.md red arm is defeated by exactly the state
            bookkeeping creates*. Q234's general form is the rule here — a
            derived fixture is only as safe as the surface it derives from, and
            THE REGISTER'S OPEN SET IS NOT A SAFE SURFACE, because draining it
            is the goal.

            So the subject is neither named nor found. It is BUILT, out of an
            id the register does not allocate, and the register's state cannot
            reach it.

            ══ WHY THE PLANT IS SAFE, AND WHY IT IS THE CITATION AND NOT THE
            ROW ══════════════════════════════════════════════════════════════
            The defect needs two halves in two files — a citation in a swept
            file and a row in `TODO.md` — and the harness applies exactly ONE
            mutation to ONE file per case. So one half must exist before the
            baseline is measured, and the obvious reading ("stage an open row
            plus a citation, then tick the row") puts the ROW in the staged
            tree. Refused, measured: `check_decision_index` compares the
            register against `docs/decisions/README.md` and `--decisions` is
            not the only check that reads `TODO.md`, so a pre-staged row
            reddens OTHER checks' baselines and makes `--self-test` print a
            contaminated-tree note on a clean tree — training the reader to
            ignore the one note that means something.

            The CITATION is the safe half, and what makes it safe is the
            check's own allocation bound (`n > max(allocated) -> skip`, the
            rule that stops the sweep reporting surrogate D800). An id one
            above the ceiling is read by the sweep and discarded by the bound:
            visible, inert, and invisible to every other check, which read task
            ids, matrix rows, index rows and boundary blocks and not this. It
            arms only when a row for it appears — which is the mutation. So the
            fixture is armed BY the case, not by its setup, and the baseline
            stays exactly as clean as the tree is.

            MEASURED, not argued (2026-08-17, on a staged copy of the live
            tree): run all seven checks with the plant present and with it
            absent, and the output is identical but for the swept FILE COUNT on
            two ok lines, 451 -> 452. Zero findings either way, exit 0 either
            way, and `findings()` reads only `::error::` lines, so the delta
            harness sees nothing at all. `132 distinct decisions cited` is
            unchanged in both — the allocation bound holding the plant inert,
            watched directly rather than reasoned about.

            Two things are asserted and two are now CONSTRUCTED, and the
            difference is the 2026-08-18 repair. Asserted, because each would
            otherwise let an arm pass for the wrong reason: the register
            allocates something (else there is no ceiling to mint above — the
            raise lives in `lowest_unhomed_decision_id`), and the minted id is
            cited NOWHERE in the staged tree already (else the arm's finding is
            not attributable to the plant). Constructed, because a guard on
            them fired on ordinary tree states rather than on defects: the
            minted id has no record and no registered home, and the window the
            mutation's ceiling bump opens contains nothing unresolved. A third
            assertion remains for the plant's LOCATION: `CITATION_SCAN` still
            names a directory that exists. The plant location is DERIVED from
            `CITATION_SCAN`/`CITATION_SUFFIXES` for the reason
            `scratch_decision_citations()` states: a narrowing of either must
            move this fixture with the check rather than leave it aimed at a
            surface nothing reads.
            """
            # The id is the LOWEST above the ceiling that no home claims
            # (`lowest_unhomed_decision_id`, whose docstring carries the full
            # reasoning and the two refused designs). Three properties come
            # with it BY CONSTRUCTION and are therefore no longer guarded here:
            # it is above the ceiling, it carries no record and no registered
            # home, and every id the mint stepped over is claimed by one or the
            # other — so the ceiling bump the register-row mutation performs
            # drags nothing unresolved into bound with it. The guard that used
            # to stand here fired on a record the register had not allocated
            # yet, which is the routine mid-act window (D119 RULING 6), i.e.
            # every planning wave.
            minted = lowest_unhomed_decision_id(tree)
            allocated, recorded = decision_homes(tree)
            cited = scratch_decision_citations()
            if minted in cited:
                raise AssertionError(
                    f"self-test: D{minted} is already cited in the staged tree "
                    f"({', '.join(sorted(cited[minted])[:3])}), so the planted citation "
                    "would not be the only one: the red arm's finding would not be "
                    "attributable to the plant, and the green arm's ceiling bump could "
                    "drag that other citation into bound and change findings for a "
                    "reason the case is not about"
                )
            directory = next((sub for sub in CITATION_SCAN if (tree / sub).is_dir()), None)
            if directory is None or ".md" not in CITATION_SUFFIXES:
                raise AssertionError(
                    "self-test: CITATION_SCAN names no directory present in the staged "
                    "tree, or .md has left CITATION_SUFFIXES, so there is nowhere to "
                    "plant a citation the decision sweep would read"
                )
            plant = tree / directory / "self-test-planted-decision-citation.md"
            # No token of the form <PFCGSARUQ><digits> and no
            # `registry-v1.md:<line>`, or this plant would redden the task-
            # citation half or the decision half's frozen-registry rule and
            # contaminate the very baseline it is built to leave alone.
            plant.write_text(
                "Planted by `--self-test`, inside its scratch copy only. A normative "
                f"citation of D{minted}, an id the register does not allocate: the sweep "
                "reads it and the allocation bound holds it inert until a register row "
                "arms it.\n",
                encoding="utf-8",
            )
            # The mint's provenance, printed rather than inferred: the gap
            # between the ceiling and the minted id IS the mid-act window, and
            # a reader who sees it non-zero is looking at the state that used
            # to raise here.
            above = sorted(n for n in recorded if n > max(allocated))
            print(
                f"self-test: note — planted a citation of D{minted} at "
                f"{plant.relative_to(tree)}; inert until a register row arms it. "
                f"The register's ceiling is D{max(allocated)} and "
                f"{len(above)} record(s) sit above it"
                + (f" ({', '.join(f'D{n}' for n in above[:6])})" if above else "")
            )
            return f"D{minted}"

        def a_cited_decision_in(relative: str) -> str:
            """The first `D<n>` token in `relative`, read at fixture time.

            The green ceiling case replaces it with an id far above the
            register's own ceiling. Which real id is standing there does not
            matter to the case and never did, so it is read rather than named:
            a decision id in a source file is a citation, and citations move.
            """
            text = (tree / relative).read_text(encoding="utf-8")
            match = re.search(r"\bD\d+\b", text)
            if not match:
                raise AssertionError(
                    f"self-test: {relative} cites no decision, so the ceiling case has "
                    "nothing to replace"
                )
            return match.group(0)

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
        owner_dnum, owner_id, owner_doc, owner_line = an_owner_assignment()
        ghost_owner = above_ceiling(owner_id[0])

        # ── Q184's derived values ───────────────────────────────────────────
        # The freeze-boundary cases follow BOUNDARY_COPIES instead of naming
        # files, so a renamed copy moves them with the check rather than
        # leaving them aimed at a path that no longer exists.
        if len(BOUNDARY_COPIES) < 2:
            raise AssertionError(
                "self-test: fewer than two registered boundary copies, so the drift and "
                "marker cases cannot be aimed at different files — and the check itself "
                "is vacuous below two"
            )
        marker_copy, drift_copy = BOUNDARY_COPIES[0], BOUNDARY_COPIES[1]
        drift_line = a_boundary_rule_line(drift_copy)
        marker_titles = boundary_checkbox_titles(marker_copy)

        matrix_rows = scratch_matrix_rows()
        gated = gated_milestones(CURRENT_MILESTONE)
        gate_target = next(
            (
                (line, field)
                for milestone, status, line, field in matrix_rows
                if milestone in gated and status == "covered"
            ),
            None,
        )
        if gate_target is None:
            raise AssertionError(
                "self-test: no row at a gated milestone reads 'covered', so the status "
                "gate's red case has nothing to regress"
            )
        gate_line, gate_field = gate_target
        later_target = next(
            (
                (status, line, field)
                for milestone, status, line, field in matrix_rows
                if milestone not in gated and status in STATUS_VOCABULARY and status != "gap"
            ),
            None,
        )
        if later_target is None:
            raise AssertionError(
                "self-test: no row at a milestone past the gate carries a status other "
                "than 'gap', so the ungated arms have nothing to move"
            )
        later_status, later_line, later_field = later_target
        # A non-vocabulary token, TRUNCATED from the row's own status rather
        # than spelled here: a spelled misspelling is one vocabulary change
        # away from being a legal status, and this case would then read green
        # for a reason no one would look for.
        not_a_status = later_status[:-1]
        if not_a_status in STATUS_VOCABULARY or not not_a_status:
            raise AssertionError(
                f"self-test: {not_a_status!r} is a legal status, so the typo case would "
                "mutate one valid status into another and prove nothing"
            )
        unresolvable_reference = a_unique_rust_test_reference()
        minted_decision = plant_an_unrecorded_decision()

        # The one target path a Q184 fixture and its case BOTH need. Named once
        # so the two cannot drift apart: a fixture reading one file while the
        # harness mutates another is a case that proves nothing and says
        # nothing, because both halves are individually well-formed.
        ceiling_target = "crates/antseal-core/src/bundle/error.rs"
        ceiling_id = a_cited_decision_in(ceiling_target)
        # Left a literal on purpose, unlike everything else here: the comment
        # at CITATION_SCAN_SELF reasons about this exact id by name, and a
        # derived one would silently falsify a record of why this file is
        # excluded from its own sweep. What the case actually needs of it is
        # asserted instead of assumed.
        ghost_decision = "D77000"
        register_ceiling = max(
            (
                int(n)
                for n in re.findall(
                    r"^- \[[ x]\] \*\*D(\d+)\*\*",
                    (tree / "TODO.md").read_text(encoding="utf-8"),
                    re.M,
                )
            ),
            default=0,
        )
        if int(ghost_decision[1:]) <= register_ceiling:
            raise AssertionError(
                f"self-test: {ghost_decision} is at or below the register's ceiling "
                f"(D{register_ceiling}), so the green ceiling case would plant an id the "
                "check is entitled to report and the case would be red for a real reason"
            )

        # ── D119's fixtures — the index-row shape is AMBIENT ────────────────
        # All three decision-index cases name `docs/decisions/README.md` as
        # their target and assert their pre-image is IN THAT FILE before
        # mutating. The reason is a hazard D119 §8(v) MEASURED rather than
        # imagined: 36 decision BODIES each carried a line of exactly the
        # index-row shape — a hand-written row awaiting application to the index
        # — under the convention RULING 6 now writes down. That census is 0 in
        # this tree, because D119 §5 step 6 emptied those sections in the same
        # act, and it returns to 1 the moment the next planner writes a decision
        # with its row pre-written, which is precisely what RULING 6 tells them
        # to do. A fixture resting on today's census has a one-decision
        # lifetime, so these are built for the shape coming back.
        #
        # The harness mutates exactly one file, the one the case names, so a
        # copy of the literal in a decision body cannot absorb the mutation.
        # What the pre-image assertion adds is the other half — that the literal
        # is present, and present ONCE, in the file being mutated. Without it a
        # reworded row falls through to the no-op guard, which can say the
        # mutation matched nothing but not whether the harness was even looking
        # at the right file; with it, the failure names the path. Uniqueness is
        # computed, never assumed, as in `scratch_matrix_rows()` and
        # `a_boundary_rule_line()`.

        def an_index_row(plain: bool) -> tuple[str, list[str]]:
            """`(the whole line, its four cells)` for a row of the decision
            index, asserted present EXACTLY ONCE in `INDEX` itself.

            `plain` additionally demands a row carrying no escaped pipe, so its
            status cell can be addressed by `split("|")` field index. Five rows
            of this table do carry one, and on those the naive splitter and the
            check's escape-aware `INDEX_PIPE` disagree about which field the
            status is — which is the whole reason `INDEX_PIPE` exists. The
            removal case does not need the property and does not ask for it.
            """
            path = tree / INDEX
            if not path.is_file():
                raise AssertionError(
                    f"self-test: {INDEX} is not in the staged tree, so no decision-index "
                    "fixture can be aimed at the file that carries the table"
                )
            text = path.read_text(encoding="utf-8")
            for line in text.splitlines():
                cells = index_cells(line)
                if cells is None or len(cells) != 4:
                    continue
                if plain and len(line.split("|")) != len(cells) + 2:
                    continue
                if text.count(line + "\n") != 1:
                    continue
                return line, cells
            raise AssertionError(
                f"self-test: no {'escape-free ' if plain else ''}index row occurs exactly "
                f"once in {INDEX}, so a decision-index mutation cannot be aimed inside the "
                "one file that carries the table"
            )

        index_row_any, _index_cells_any = an_index_row(plain=False)
        index_row_plain, index_row_cells = an_index_row(plain=True)
        # Field 3 of `['', ID, Title, Status, Date, '']`, and ASSERTED against
        # the cells the check itself parsed rather than trusted: the two
        # splitters agree only while the row carries no escaped pipe, and the
        # cost of being wrong is a fixture that rewrites the Title column and a
        # case that goes red for the wrong reason.
        index_status_field = 3
        if index_row_plain.split("|")[index_status_field].strip() != index_row_cells[2]:
            raise AssertionError(
                f"self-test: field {index_status_field} of the escape-free index row is not "
                "the status cell the check parses, so the status fixtures would rewrite the "
                "wrong column"
            )
        index_status = status_word(index_row_cells[2])
        # A status word that is NOT the record's, TRUNCATED from the row's own
        # rather than spelled here — the device `not_a_status` uses above, for
        # the same reason: a spelled status is one house-vocabulary change away
        # from being a legal status for that record, and the red case would
        # then read green for a reason nobody would look for.
        diverged_status = index_status[:-1]
        if not diverged_status or diverged_status == index_status:
            raise AssertionError(
                f"self-test: {index_status!r} does not truncate to a different status word, "
                "so the divergence case would rewrite the status cell into itself"
            )

        # ── D144's fixtures — the machine-path lint ─────────────────────────
        # Nine faults (D144 §2 R7), every subject CONSTRUCTED in the staged
        # copy and none of them found in it (Q252): the probe file does not
        # exist in the tree, the pin's two mutations are applied to a staged
        # copy of a file that has never been edited, and the scan-root fault is
        # planted in a staged copy of this script. Draining the tree of machine
        # paths — which is the entire point of the rule — can therefore never
        # disarm any of them.
        #
        # TWO OF THE THREE PLATFORM ARMS HAVE ZERO LIVE OCCURRENCES in this
        # tree (`/Users/…` and `C:\Users\…`, measured 2026-08-18). Without
        # their plants they are assertions that cannot fail — this project's
        # dominant defect class — so they are planted first and the arm table
        # is read for the count, not written down.
        def append_text(addition: str):
            """Append `addition`. The no-op guard cannot fire on an append — the
            text always changes — so the expectation does all the work and
            there is no first-occurrence hazard to anchor against."""
            return lambda t: t + addition

        machine_root = next(
            (sub for sub in CITATION_SCAN
             if sub in PATH_SCAN_REQUIRED and (tree / sub).is_dir()),
            None,
        )
        if machine_root is None or ".rs" not in CITATION_SUFFIXES:
            raise AssertionError(
                "self-test: no PATH_SCAN_REQUIRED root is a directory in the staged tree, "
                "or .rs has left CITATION_SUFFIXES, so there is nowhere to plant a file "
                "the machine-path scan would read"
            )
        machine_probe = f"{machine_root}/__machine_path_probe.rs"
        (tree / machine_probe).write_text(
            "// Written by `--self-test` inside its scratch copy only. It carries NO\n"
            "// machine path at baseline; each machine-paths arm appends its own, and\n"
            "// the harness restores this file between arms.\n",
            encoding="utf-8",
        )

        # One planted violation per PATTERN ARM, keyed by the arm it exercises,
        # so an arm added to MACHINE_PATH_ARMS without a fixture fails here with
        # its own message instead of letting the totals balance (Q245).
        machine_violations = {
            "posix-home": "/home/nonesuch/work/a.txt",
            "macos-users": "/Users/nonesuch/work/a.txt",
            # Escaped exactly as a Rust or JSON source file carries it — which is
            # the spelling a single-backslash pattern reads straight past.
            "windows-users": "C:\\\\Users\\\\nonesuch\\\\work",
        }
        unfixtured = sorted(set(MACHINE_PATH_ARMS) - set(machine_violations))
        if unfixtured:
            raise AssertionError(
                f"self-test: MACHINE_PATH_ARMS gained {', '.join(unfixtured)} with no "
                "planted fault, so that arm of the pattern would be an assertion that "
                "cannot fail. An arm gets its fixture in the act that adds it (D144 §2 R7)"
            )
        unarmed = sorted(set(machine_violations) - set(MACHINE_PATH_ARMS))
        if unarmed:
            raise AssertionError(
                f"self-test: {', '.join(unarmed)} is planted but is no longer an arm of "
                "MACHINE_PATH_ARMS, so the case would prove something the check does not "
                "claim"
            )

        def rust_literal(name: str, value: str) -> str:
            """A line a real source file would carry, not a comment: the Windows
            arm's whole point is that the escaping is what reaches disk."""
            return f'const _{re.sub(r"[^A-Za-z0-9]", "_", name).upper()}: &str = "{value}";\n'

        machine_fragments: dict[str, str] = {}
        for arm in sorted(machine_violations):
            violation = machine_violations[arm]
            if not re.search(MACHINE_PATH_ARMS[arm], violation):
                raise AssertionError(
                    f"self-test: the fault planted for arm {arm} ({violation!r}) does not "
                    f"match that arm's own pattern {MACHINE_PATH_ARMS[arm]!r}, so the case "
                    "would go red through a different arm and prove nothing about this one"
                )
            hit = MACHINE_PATH.search(violation)
            if hit is None or hit.group(1) in RESERVED_PLACEHOLDER_NAMES:
                raise AssertionError(
                    f"self-test: {violation!r} is not a violation of the machine-path rule, "
                    "so the check would be green over it for a legitimate reason and the "
                    "red case would prove nothing"
                )
            machine_fragments[arm] = f"absolute home path `{hit.group(0)}`"

        # The GREEN half of the vocabulary rule, one path per RESERVED NAME and
        # the set read off the constant: a sixth name cannot land without its
        # own fixture in the same act (D144 §2 R4).
        machine_reserved = [f"/home/{name}/work/a.txt" for name in RESERVED_PLACEHOLDER_NAMES]
        machine_reserved_line = (
            f"const _RESERVED: [&str; {len(machine_reserved)}] = ["
            + ", ".join(f'"{path}"' for path in machine_reserved)
            + "];\n"
        )
        exercised = {m.group(1) for m in MACHINE_PATH.finditer(machine_reserved_line)}
        if exercised != set(RESERVED_PLACEHOLDER_NAMES):
            raise AssertionError(
                f"self-test: the reserved-vocabulary fixture exercises "
                f"{sorted(exercised)} where the vocabulary is "
                f"{sorted(RESERVED_PLACEHOLDER_NAMES)}. Either a name has no fixture, or "
                "the pattern cannot see one of them and its green arm would pass BY "
                "ABSENCE rather than by the vocabulary being honoured (D144 §2 R4)"
            )

        # The near-miss set: the four spellings a separator-blind pattern eats.
        machine_near_misses = ["/homework/notes", "/home", "$HOME/x", "~/x"]
        machine_near_miss_line = (
            f"const _NEAR: [&str; {len(machine_near_misses)}] = ["
            + ", ".join(f'"{path}"' for path in machine_near_misses)
            + "];\n"
        )
        if MACHINE_PATH.search(machine_near_miss_line):
            raise AssertionError(
                f"self-test: the near-miss control line matches the machine-path pattern "
                f"({MACHINE_PATH.search(machine_near_miss_line).group(0)!r}), so its green "
                "arm would be red for a real reason. The pattern lost its separator "
                "anchoring (D144 §2 R4)"
            )

        # The PIN, in both directions. The anchor is a WHOLE LINE and is
        # asserted unique in the staged copy before either arm is built.
        if not KNOWN_MACHINE_PATH_DIVERGENCE:
            raise AssertionError(
                "self-test: KNOWN_MACHINE_PATH_DIVERGENCE is empty, so the pin's two arms "
                "have no subject. When the last registered divergence is repaired, the "
                "register, the pin and these two cases go together"
            )
        machine_pinned = sorted(KNOWN_MACHINE_PATH_DIVERGENCE)[0]
        machine_anchor = KNOWN_MACHINE_PATH_DIVERGENCE[machine_pinned][0]
        pinned_lines = (tree / machine_pinned).read_text(encoding="utf-8").splitlines()
        if pinned_lines.count(machine_anchor) != 1:
            raise AssertionError(
                f"self-test: the registered divergence text occurs "
                f"{pinned_lines.count(machine_anchor)} time(s) as a whole line in staged "
                f"{machine_pinned}, not once. The pin is already red on the unmutated "
                "tree, so its two arms would be measured against a contaminated baseline"
            )

        # The CITATION_SCAN coupling fault: a REQUIRED root removed from the
        # scan list. Planted in the constant itself rather than through a
        # parameter, so the arm also proves the shipped call path reads it.
        machine_dropped = next(
            (sub for sub in CITATION_SCAN
             if sub in PATH_SCAN_REQUIRED and sub != machine_root),
            None,
        )
        if machine_dropped is None:
            raise AssertionError(
                "self-test: PATH_SCAN_REQUIRED names no second root to drop, so the "
                "coupling arm cannot distinguish a removed root from the probe's own"
            )
        machine_root_line = f'    "{machine_dropped}",'
        self_source = (tree / CITATION_SCAN_SELF).read_text(encoding="utf-8")
        if self_source.count(machine_root_line + "\n") != 1:
            raise AssertionError(
                f"self-test: {machine_root_line.strip()!r} occurs "
                f"{self_source.count(machine_root_line + chr(10))} time(s) as a whole line "
                f"in staged {CITATION_SCAN_SELF}, not once, so deleting it would not "
                "reliably remove the scan root this arm is about"
            )

        # The PRESERVED classes, out of scan BY ASSERTION rather than by nobody
        # having looked (D144 §2 R7 fault 9, §2 R2). This is the arm this
        # project would otherwise skip, and it is what makes the class boundary
        # a measured property instead of a paragraph.
        machine_preserved: list[str] = []
        for directory in ("docs/decisions", "docs/reviews", "tasks"):
            first = next(iter(sorted((tree / directory).glob("*.md"))), None)
            if first is None:
                raise AssertionError(
                    f"self-test: {directory}/ holds no .md file in the staged tree, so the "
                    "preserved-class control has nothing to plant a violation in"
                )
            machine_preserved.append(str(first.relative_to(tree)))
        for literal in ("TODO.md", "MVP-SPEC.orig.md"):
            if not (tree / literal).is_file():
                raise AssertionError(
                    f"self-test: {literal} is not in the staged tree, so its "
                    "preserved-class control has no subject"
                )
            machine_preserved.append(literal)
        for relative in machine_preserved:
            if relative in CITATION_SCAN or any(
                relative.startswith(f"{sub}/") for sub in CITATION_SCAN
            ):
                raise AssertionError(
                    f"self-test: {relative} is INSIDE CITATION_SCAN, so its control would "
                    "be green only because the check is entitled to be red there. The "
                    "live/preserved boundary moved and D144 §2 R2 needs re-reading before "
                    "this case is re-armed"
                )
        machine_preserved_line = (
            f"\n<!-- self-test: {machine_violations['posix-home']} -->\n"
        )
        if MACHINE_PATH.search(machine_preserved_line) is None:
            raise AssertionError(
                "self-test: the preserved-class control plants no machine path at all, so "
                "every one of its arms would be green BY ABSENCE"
            )

        # (check, file, mutation, expect, required message fragment). Built,
        # not written out, and the counts below are DERIVED from the list
        # (Q245): a fixture added or lost moves them without anyone editing a
        # number.
        machine_cases: list[tuple] = []
        for arm in sorted(machine_violations):
            machine_cases.append(
                (
                    "machine-paths",
                    machine_probe,
                    append_text(rust_literal(arm, machine_violations[arm])),
                    "red",
                    machine_fragments[arm],
                )
            )
        machine_cases.append(
            ("machine-paths", machine_probe, append_text(machine_reserved_line), "green", None)
        )
        machine_cases.append(
            ("machine-paths", machine_probe, append_text(machine_near_miss_line), "green", None)
        )
        machine_cases.append(
            (
                "machine-paths",
                machine_pinned,
                rewrite_line(machine_anchor, machine_anchor + " AND ONE WORD MORE\n"),
                "red",
                "the registered divergence text is no longer present verbatim",
            )
        )
        machine_cases.append(
            (
                "machine-paths",
                machine_pinned,
                rewrite_line(machine_anchor, machine_anchor + "\n" + machine_anchor + "\n"),
                "red",
                "the registered divergence text occurs 2 times, not once",
            )
        )
        machine_cases.append(
            (
                "machine-paths",
                CITATION_SCAN_SELF,
                rewrite_line(machine_root_line, ""),
                "red",
                f"CITATION_SCAN no longer contains `{machine_dropped}`",
            )
        )
        for relative in machine_preserved:
            machine_cases.append(
                ("machine-paths", relative, append_text(machine_preserved_line), "green", None)
            )

        # ── Q257: the DOCUMENT side of the vocabulary (D144 §2 R8's owed half) ─
        #
        # THE ARM THESE CASES EXIST FOR IS THE ONE THAT IS GREEN BY CONSTRUCTION
        # IF WRITTEN NAIVELY. `u` and `x` are single letters, so "grep the guide
        # for each reserved name" can never report either of them missing —
        # two of five permanently unfalsifiable. Case (b) is the discriminator:
        # it leaves the name present as BARE TEXT on the very line the check
        # reads, and any substring implementation stays green on it.
        #
        # The subject is READ from the staged file, never reconstructed: a
        # cosmetic reword of the sentence must not silently disarm a case, and
        # a mutation that matches nothing already fails the harness loudly.
        if not RESERVED_PLACEHOLDER_NAMES:
            raise AssertionError(
                "self-test: RESERVED_PLACEHOLDER_NAMES is empty, so the document arm has "
                "no name to plant and every case below would be green BY ABSENCE"
            )
        # The SHORTEST name on purpose: it is the one a substring search is
        # blindest to, so the cases bite where the defect actually lives.
        machine_vocab_name = min(RESERVED_PLACEHOLDER_NAMES, key=len)
        machine_vocab_token = "`" + machine_vocab_name + "`"
        machine_doc_lines = [
            line
            for line in (tree / PLACEHOLDER_DOC).read_text(encoding="utf-8").splitlines()
            if PLACEHOLDER_DOC_ANCHOR in line
        ]
        if len(machine_doc_lines) != 1:
            raise AssertionError(
                f"self-test: staged {PLACEHOLDER_DOC} holds {len(machine_doc_lines)} line(s) "
                f"containing {PLACEHOLDER_DOC_ANCHOR!r}, not one, so the document cases have "
                "no unambiguous subject to corrupt"
            )
        machine_vocab_cut = next(
            (
                form
                for form in (machine_vocab_token + ", ", ", " + machine_vocab_token)
                if form in machine_doc_lines[0]
            ),
            None,
        )
        if machine_vocab_cut is None:
            raise AssertionError(
                f"self-test: the staged declaration does not carry {machine_vocab_token!r} in "
                "a removable form, so both document cases would mutate nothing"
            )
        machine_tuple_marker = "RESERVED_PLACEHOLDER_NAMES = ("
        machine_tuple_lines = [
            line for line in self_source.splitlines() if line.startswith(machine_tuple_marker)
        ]
        if len(machine_tuple_lines) != 1 or not machine_tuple_lines[0].endswith(")"):
            raise AssertionError(
                f"self-test: staged {CITATION_SCAN_SELF} holds "
                f"{len(machine_tuple_lines)} single-line definition(s) of "
                "RESERVED_PLACEHOLDER_NAMES, not one, so the constant-side case cannot "
                "widen the tuple it is about"
            )
        machine_vocab_extra = "planted"
        if machine_vocab_extra in RESERVED_PLACEHOLDER_NAMES:
            raise AssertionError(
                f"self-test: {machine_vocab_extra!r} is already reserved, so widening the "
                "tuple with it would be a no-op and the count case would prove nothing"
            )

        def declaration_mutation(needle: str, replacement: str):
            """Rewrite the ONE anchored declaration line in `PLACEHOLDER_DOC`."""

            def mutate(text: str) -> str:
                lines = text.splitlines(keepends=True)
                for index, line in enumerate(lines):
                    if PLACEHOLDER_DOC_ANCHOR not in line or needle not in line:
                        continue
                    lines[index] = line.replace(needle, replacement, 1)
                    return "".join(lines)
                return text

            return mutate

        def widen_reserved_tuple(name: str):
            """Append a sixth reserved name to the staged constant."""

            def mutate(text: str) -> str:
                lines = text.splitlines(keepends=True)
                for index, line in enumerate(lines):
                    stripped = line.rstrip("\n")
                    if not stripped.startswith(machine_tuple_marker):
                        continue
                    if not stripped.endswith(")"):
                        break
                    lines[index] = stripped[:-1] + ', "' + name + '")\n'
                    return "".join(lines)
                return text

            return mutate

        machine_vocab_missing = "the declaration does not name " + machine_vocab_token
        machine_vocab_count = (
            "against " + str(len(RESERVED_PLACEHOLDER_NAMES) + 1)
            + " in RESERVED_PLACEHOLDER_NAMES"
        )
        # (a) the name is deleted from the guide.
        machine_cases.append(
            (
                "machine-paths",
                PLACEHOLDER_DOC,
                declaration_mutation(machine_vocab_cut, ""),
                "red",
                machine_vocab_missing,
            )
        )
        # (b) the name is still THERE, just no longer delimited. This is the
        # case a substring implementation passes and this one must not.
        machine_cases.append(
            (
                "machine-paths",
                PLACEHOLDER_DOC,
                declaration_mutation(machine_vocab_token, machine_vocab_name),
                "red",
                machine_vocab_missing,
            )
        )
        # (c) the CONSTANT grows a name the guide never gained — the direction
        # a presence-only check is blind to, caught by the COUNT.
        machine_cases.append(
            (
                "machine-paths",
                CITATION_SCAN_SELF,
                widen_reserved_tuple(machine_vocab_extra),
                "red",
                machine_vocab_count,
            )
        )
        print(
            f"self-test: note — {len(machine_cases)} machine-path fixture(s) constructed "
            f"({sum(1 for c in machine_cases if c[3] == 'red')} red, "
            f"{sum(1 for c in machine_cases if c[3] == 'green')} green) over "
            f"{len(MACHINE_PATH_ARMS)} pattern arm(s), "
            f"{len(RESERVED_PLACEHOLDER_NAMES)} reserved name(s), "
            f"{len(KNOWN_MACHINE_PATH_DIVERGENCE)} pinned divergence(s) and "
            f"{len(machine_preserved)} preserved surface(s)"
        )

        # (check, file, mutation, expect) where expect is "red" or "green", and
        # an OPTIONAL fifth element: the sentence a red arm's planted fault must
        # produce. `scripts/lib/red-arm.sh`'s rule — "A RED ARM MUST MATCH ON
        # THE MESSAGE THE CHECK PRINTS WHEN IT FINDS THE PLANTED FAULT, NOT ON
        # THE EXIT STATUS ALONE" — is only half kept by a delta: a delta proves
        # the check ADDED a finding, not that it added THE finding, so a
        # mutation that trips a neighbouring rule passes an arm written for
        # this one. Where the fifth element is absent the arm is a delta only,
        # which is what every case above has always been; supplying one asserts
        # BOTH (D144 §2 R7).
        #
        # The two "green" cases are Q49's: a checkbox marker is gate state and
        # must be tolerated in either direction and either case. They are not
        # decoration — without them the normalisation could widen to "compare
        # nothing" and no case would notice. The "red" cases bound it from the
        # other side: change a word, or delete the marker instead of ticking
        # it, and the check still bites.
        #
        # ══ THE FIXTURE RULE (Q184) ═════════════════════════════════════════
        # Every mutation here is a string replacement, so every case embeds a
        # literal. Each literal is in exactly one of three classes, and the
        # class decides what may be written:
        #
        #   (1) SCRIPT-OWNED — one of this file's own constants, or a token the
        #       check's own regex defines. Stable by construction: the only
        #       thing that can change it is the thing under test, and that
        #       change is supposed to be visible.
        #   (2) FIXTURE-BUILT — the case plants the text it later mutates, or
        #       derives it from the scratch tree at fixture time. The helpers
        #       above are this class, and every one of them RAISES rather than
        #       returning a literal, so a tree that stops yielding one fails in
        #       a sentence instead of vacuously.
        #   (3) BORROWED — copied out of live tree content: a status, a
        #       checkbox state, a title, a sentence. A borrowed literal has the
        #       lifetime of whatever ordinary work may edit it, and the day it
        #       expires the mutation matches nothing.
        #
        # Class 3 is permitted ONLY with the reason it outlives the case
        # written beside it. Where the borrowed value is a STATUS or a CHECKBOX
        # STATE, do not write a reason — derive it or retarget: those are the
        # values the project is in the business of changing, and both of this
        # harness's recorded vacuous-fixture incidents were exactly that. Q66:
        # three fixtures hard-coded an unticked marker and died the moment Q14
        # ticked the rows. D118: two status-gate fixtures pinned one row's
        # status cell and died together the moment that row went covered.
        #
        # ══ AND THE SECOND RULE, about WHERE a literal matches ══════════════
        # A mutation that takes the FIRST occurrence over a whole file must be
        # anchored (`rewrite_line`, or `^` with re.M), or its target shown
        # unique at fixture time. Not a hypothetical: prose that DESCRIBES a
        # fixture necessarily contains that fixture's literal, and it sorts
        # wherever it sorts. Three such copies are in this tree today — one in
        # the register, one in a task file, one in the matrix — and the
        # register's copy has already absorbed a mutation and reported its case
        # green over a file that was never mutated where the check reads.
        # A corollary for whoever writes ABOUT these fixtures: spell the
        # literal apart in prose. A sentence is allowed to describe a fixture;
        # it is not allowed to be one.
        #
        # The target PATHS are the lesser half and stay literal on purpose:
        # several cases exist precisely to pin one surface (`scripts/`, a
        # root-level file), so the path IS the assertion. A path that stops
        # existing is a hard failure in the loop below and never a skip.
        cases = [
            (
                "freeze-boundary",
                drift_copy,
                rewrite_line(drift_line, drift_line + " AND ONE WORD MORE\n"),
                "red",
            ),
            (
                "freeze-boundary",
                marker_copy,
                strip_marker(marker_titles[0]),
                "red",
            ),
            (
                "freeze-boundary",
                marker_copy,
                flip_tick(marker_titles[0]),
                "green",
            ),
            (
                "freeze-boundary",
                marker_copy,
                retick_upper(marker_titles[1]),
                "green",
            ),
            # The ceiling bound from the green side: an id above the register's
            # highest allocated number is not a decision citation, so the sweep
            # must stay silent about it. The id being REPLACED is read from the
            # file (Q184), and the substitution is word-bounded — unbounded, a
            # two-digit id would eat the prefix of a three-digit one and mutate
            # this case into a different case entirely.
            (
                "decisions",
                ceiling_target,
                lambda t: re.sub(rf"\b{ceiling_id}\b", ghost_decision, t, count=1),
                "green",
            ),
            # The Q57 failure, faithfully: a decision marked RESOLVED in the
            # register whose record was never written.
            #
            # The subject is CONSTRUCTED (Q252), not found — see
            # `plant_an_unrecorded_decision()` for the full reasoning and the
            # measurement that forced it. In one line: the previous spelling
            # ticked a row the fixture SEARCHED for, and 985ad05 drained the
            # register to zero open decisions, so the search raised and the
            # whole harness exited 1 before any arm ran. The register's open
            # set is not a surface a fixture may depend on, because emptying it
            # is the point of the work.
            #
            # It APPENDS rather than replaces, joining the Q58 line-citation
            # cases below under their reasoning: the no-op guard cannot fire on
            # an append — the text always changes — so the expectation is doing
            # all the work, and there is no first-occurrence hazard to anchor
            # against. That retires this case's anchoring note, which is worth
            # keeping in view because it recorded a real incident: prose about
            # the fixture sat ABOVE the row it aimed at, an unanchored
            # replacement ate the prose, and the harness called the check green
            # over a register whose row was never touched. Nothing here can
            # reproduce it — the mutation matches no existing text at all — but
            # the rule at the head of this list still holds for every case that
            # does replace.
            (
                "decisions",
                "TODO.md",
                lambda t: t
                + f"\n- [x] **{minted_decision}** minted by `--self-test`; no record was "
                "ever written for it, which is the whole defect.\n",
                "red",
            ),
            # And the same subject from the green side. `check_decisions`
            # exempts an id that is STILL OPEN in the register — it counts them
            # on its own ok line — and that exemption is the only thing between
            # a freshly minted decision and a red lane on the day it is minted.
            #
            # The old red arm did cover it, but CONTINGENTLY and BY SIDE
            # EFFECT, which is why this is now its own arm. Its pre-image was
            # an open unrecorded row, so deleting the exemption would have put
            # the finding into the BASELINE and the arm would then have failed
            # with "added no finding" — a true signal wearing the wrong
            # message, and available only while such a row existed. With the
            # register drained it is worth nothing at all.
            #
            # Here it is direct and available in every register state: the same
            # minted id, the same planted citation, an OPEN row instead of a
            # ticked one, and the findings must not move. Measured — deleting
            # `or number in still_open` fails THIS arm, by its own message,
            # with every other decisions arm still green.
            (
                "decisions",
                "TODO.md",
                lambda t: t
                + f"\n- [ ] **{minted_decision}** minted by `--self-test`; still open, so "
                "the sweep must stay silent about it.\n",
                "green",
            ),
            # Q58 — a line-number citation into the frozen registry. The three
            # cases carrying this literal (here, `scripts/fuzz.sh` below, and
            # the root-file twin) are class 1 under the rule above: what they
            # spell is the check's OWN regex, not tree content, and neither the
            # registry file nor that line has to exist for the mutation to
            # fire. The literal therefore has the lifetime of the rule being
            # tested, which is the definition of a fixture that cannot rot —
            # and note the direction, because it is the opposite of a borrowed
            # one: if the check's regex is narrowed, these cases go green and
            # fail loudly rather than quietly matching nothing.
            #
            # They also APPEND rather than replace, so the no-op guard can
            # never fire for them and the expectation is doing all the work.
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
            # A reference that no longer resolves. The mutation renames the
            # test a row cites; the row still points at it, and nothing else
            # in the tree does.
            #
            # It used to replace the first `::` in the document — a two-byte
            # literal with 66 occurrences, which landed inside a reference cell
            # only because no prose above the first table happened to contain
            # one. Q185 is rewriting exactly that prose. The reference is now
            # read from the parsed matrix and shown to occur exactly once
            # before it is used (Q184).
            (
                "matrix",
                MATRIX,
                lambda t: t.replace(
                    f"`{unresolvable_reference}`",
                    f"`{unresolvable_reference}_this_test_does_not_exist`",
                    1,
                ),
                "red",
            ),
            # Q51 — the status gate. The red case is the exact regression that
            # motivated it: a row at or before the milestone under review back
            # at `gap`, in the `**gap**` spelling the file actually used, so the
            # marker stripping is exercised too.
            #
            # The row is chosen at fixture time — the first gated row reading
            # `covered` — and its status FIELD is located by index, so no other
            # byte of the row moves. Which row it is does not matter to the
            # case and never did; what mattered was that the previous spelling
            # pinned one row's id list and status together, so an ordinary
            # edit to either could silently retire the fixture.
            (
                "matrix",
                MATRIX,
                rewrite_line(gate_line, restatus(gate_line, gate_field, "**gap**") + "\n"),
                "red",
            ),
            # And the bound from the other side. A *later* milestone's row at
            # `gap` must stay GREEN: a not-yet-reviewed milestone's crates may
            # still be stubs, and gating them would make the check unrunnable
            # until M4, which is how a gate gets switched off. Without this
            # case the rule could quietly widen to "every row must be covered"
            # and nothing would notice.
            #
            # **Retargeted twice, and the second time was the last.** Both
            # cases below used to mutate one named row's milestone/task/status
            # cells. On 2026-08-10 (Q165 / D118) the row they named went
            # `covered`, the string vanished, both mutations matched nothing,
            # and the no-op guard failed both cases loudly. (Loudly is right:
            # had it not, the green case would have been green for no reason at
            # all.) They were retargeted to a row whose status expires only at
            # the release gate — a longer lease, but still a lease, and the
            # replacement row's cells were then quoted verbatim in the prose of
            # this very file, one screen below the row, where any reordering
            # would have put a second copy in front of an unanchored
            # first-occurrence replacement.
            #
            # So Q184 stopped choosing a row: the fixture takes the first row
            # PAST the gate that is not already at `gap`, moves its status
            # field alone, and rewrites the line anchored. The rule that was
            # written here — "a status-gate fixture must be pinned to a row
            # that outlives the constant it is testing against" — generalises
            # to the rule now stated at the head of this list, of which this is
            # the worked instance: derive a status, never borrow one.
            (
                "matrix",
                MATRIX,
                rewrite_line(later_line, restatus(later_line, later_field, "gap") + "\n"),
                "green",
            ),
            # A status outside the vocabulary is a typo, and a typo at a
            # not-yet-gated milestone would otherwise be invisible until that
            # milestone's review. The token is truncated from the row's own
            # status and checked against STATUS_VOCABULARY at fixture time, so
            # a vocabulary that grew to admit it fails here rather than turning
            # this case quietly green.
            (
                "matrix",
                MATRIX,
                rewrite_line(later_line, restatus(later_line, later_field, not_a_status) + "\n"),
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
            # (b3) Q190/D123's twin of (b2), one layer down: a literal root
            # entry whose suffix is OUTSIDE CITATION_SUFFIXES really is read,
            # and read UNFILTERED. This is the only case that can prove it.
            # Every other scan root — (b2)'s CHANGELOG.md included — has an
            # in-set suffix, so silently reverting the per-entry rule to one
            # filter leaves (b), (b2), (o) and (o2) all green and says
            # nothing; this pair goes red instead.
            #
            # The id is planted BARE, not marked, and the reason is the
            # fixture rule applied to a surface rather than to a literal: all
            # 29 citation occurrences across the five root files this ruling
            # named are bare, so a marked fixture would leave the only form
            # these files actually use unproven. Bare below the domain ceiling
            # is tier 1 and fires.
            #
            # deny.toml is the target rather than one of the other four
            # because its ids sit inside RUSTSEC advisory-suppression `reason`
            # strings that carry a dated review obligation — a rotted id there
            # makes the justification for silencing a security advisory
            # unverifiable at the exact moment somebody tries to verify it.
            # And by the harness's missing-target rule — never a skip —
            # deleting or renaming deny.toml goes red here too, which is the
            # only thing standing between a named scan root and a silent
            # `base.exists()` miss.
            (
                "task-citations",
                "deny.toml",
                lambda t: t + f"\n# follow-up: {hole_q}\n",
                "red",
            ),
            # (o3) …and by the DECISION half, for (o2)'s reason: a widening
            # proven on one half only re-opens from the test side the gap
            # D116 R1 collapsed five constants to close, even when the
            # constant is shared. It plants the Q58 line-citation rather than
            # an unresolvable `D<n>` on case (o)'s measured ground — the D
            # namespace is dense with zero holes, so no single-file mutation
            # can make a `D<n>` citation fail.
            #
            # Both of these are TOML-comment-shaped, so the staged fixture
            # leaves valid TOML behind while it is in place; the harness
            # restores the original bytes either way.
            (
                "decisions",
                "deny.toml",
                lambda t: t + "\n# see `docs/format/registry-v1.md:1097` for the key layout\n",
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
            # Deleted as a whole anchored line (Q184): the finder reads headings
            # at line start, `str.replace` reads them anywhere, and a quoted or
            # indented copy earlier in the file would separate the two.
            (
                "task-entries",
                entry_file,
                rewrite_line(entry_heading, ""),
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
                rewrite_line(live_row, struck_row + "\n"),
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
                rewrite_line(
                    entry_heading,
                    entry_heading + f"\n#### {entry_id} — fixture sub-heading\n",
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
                rewrite_line(
                    owner_line,
                    owner_line.replace(f"**Owner: {owner_id}**", f"**Owner: {ghost_owner}**", 1)
                    + "\n",
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
            # ── Q180 / D119 §5 step 5 ────────────────────────────────────────
            # (o) red — a record loses its row. This is Q180's Accept verbatim
            # ("red on a deliberately removed row and green with it restored")
            # and the direction the index drifted for fifteen days: 29 records
            # with no row at all, growing by one per decision written, with
            # nothing in the tree able to say so.
            (
                "decision-index",
                INDEX,
                rewrite_line(index_row_any, ""),
                "red",
            ),
            # (p) red — the row's status word stops being its record's. The
            # OTHER direction, and the one that decided D119: (o) is the index
            # falling behind, this is a row and its record disagreeing while
            # both exist, which is where D29 sat for fourteen days with the row
            # correct and the record stale. Presence alone never sees it — Q180
            # arm (a)'s own Accept quantified over presence only, and would have
            # been satisfiable with this defect still standing.
            (
                "decision-index",
                INDEX,
                rewrite_line(
                    index_row_plain,
                    restatus(index_row_plain, index_status_field, diverged_status) + "\n",
                ),
                "red",
            ),
            # (q) GREEN ARM, pinning the two tolerances the red arms bound from
            # the other side, both of them load-bearing on the live table.
            #
            #   1. Only the leading status WORD is compared. The index is a
            #      terse annotated listing and the records are paragraphs, so a
            #      cell tightened to whole-string equality against the record
            #      would be red on all 106 rows — and the tempting repair, "then
            #      generate the table", is refused in D119 §4.3 because
            #      generation would have overwritten a correct audit finding
            #      with a stale record's status. This arm makes that tightening
            #      a re-decision instead of an edit.
            #   2. `\|` inside a cell is CONTENT. Five rows carry one today; a
            #      `split("|")` here reads this row as five cells and reports it.
            #      The escape is planted in the STATUS cell, where the tree has
            #      none, so the case is stronger than the corpus that motivated
            #      it — the idiom of green arms (i) and (n).
            (
                "decision-index",
                INDEX,
                rewrite_line(
                    index_row_plain,
                    restatus(
                        index_row_plain,
                        index_status_field,
                        f"{index_status} (fixture detail, with a \\| escaped pipe in it)",
                    )
                    + "\n",
                ),
                "green",
            ),
        ]
        # D144's arms carry a fifth element and are appended rather than
        # inlined, so the thirty-three above keep their reviewed four-tuple
        # shape and no proven case is touched to add a new one.
        cases += machine_cases

        # ── D159 §2 R3's two LIVE-SUBJECT arms, appended for D144's reason ──
        # The thirty-three-tuple list above keeps its reviewed shape and its
        # hand-counted split; this block DERIVES and prints its own, which is
        # the form to prefer. Both literals below are FIXTURE-BUILT (Q184
        # class 2): each is read out of the staged file and RAISES — here,
        # fails in a sentence — if the subject has moved, rather than
        # silently matching nothing.
        doc_link_cases: list[tuple] = []

        # RED 1 — Q249's own defect, restored: one `../` short. "1 broken
        # link" does not discharge this arm, so the fifth element pins the
        # WHOLE message shape — the file and line, the target AS WRITTEN, and
        # the path it resolved to. `:<line>` is not a wildcard: `findings()`
        # below collapses every `:\d+` in an annotation so an unrelated line
        # shift is not counted as a change, and the fragment is written in the
        # form that survives it.
        doc_link_subject = "crates/antseal-core/src/anchor/request.rs"
        doc_link_path = tree / doc_link_subject
        doc_link_written = None
        if doc_link_path.is_file():
            doc_link_written = re.search(
                r"\]\(((?:\.\./)+docs/decisions/D\d+-[^)\s]*\.md)\)",
                doc_link_path.read_text(encoding="utf-8"),
            )
        if doc_link_written is None:
            print(
                f"self-test: FAILED — {doc_link_subject} carries no relative decision "
                "link to shorten, so D159 §2 R3's RED 1 has no subject to build from",
                file=sys.stderr,
            )
            ok = False
        else:
            written = doc_link_written.group(1)
            shortened = written[len("../") :]
            landing = tree_relative(
                str(doc_link_path.parent.relative_to(tree)), shortened
            )
            if (doc_link_path.parent / shortened).is_file():
                # The vacuity guard, and it is not hypothetical: if the file
                # ever moves one directory deeper, dropping a `../` lands on a
                # real file and the red arm goes green for a reason that has
                # nothing to do with the check.
                print(
                    f"self-test: FAILED — dropping one `../` from {written} still "
                    f"resolves (to {landing}), so RED 1 would be green by construction",
                    file=sys.stderr,
                )
                ok = False
            else:
                doc_link_cases.append(
                    (
                        "doc-links",
                        doc_link_subject,
                        lambda text, w=written, s=shortened: text.replace(
                            f"]({w})", f"]({s})", 1
                        ),
                        "red",
                        f"{doc_link_subject}:<line>: the link target `{shortened}` "
                        f"does not resolve — relative to this file's own directory it "
                        f"lands at `{landing}`",
                    )
                )

        # GREEN 1 — the `.md` restriction, watched EXCLUDING rather than
        # assumed to exclude. `bundle_wire/mod.rs` carries the tree's only
        # non-`.md` relative link, a rustdoc-HTML-OUTPUT-relative one that is
        # correct where it is written and DEAD ON DISK; a checker over every
        # relative link reds on it on day one. Both facts are asserted at
        # fixture time, because the arm means nothing if the link has been
        # "repaired" away. The mutation appends a second such link plus a URL
        # and a site-root path — the three exclusion branches with no live
        # subject — so the arm is a real delta and not a no-op.
        doc_link_control = "crates/antseal-core/tests/bundle_wire/mod.rs"
        control_path = tree / doc_link_control
        control_link = None
        if control_path.is_file():
            control_link = re.search(
                r"\]\((\.\./[^)\s]*\.html)\)", control_path.read_text(encoding="utf-8")
            )
        if control_link is None:
            print(
                f"self-test: FAILED — {doc_link_control} no longer carries a "
                "rustdoc-output-relative link, so GREEN 1 asserts an exclusion with "
                "nothing to exclude",
                file=sys.stderr,
            )
            ok = False
        elif (control_path.parent / control_link.group(1)).exists():
            print(
                f"self-test: FAILED — {doc_link_control}'s {control_link.group(1)} "
                "now resolves on disk, so GREEN 1 would pass whether the .md "
                "restriction exists or not",
                file=sys.stderr,
            )
            ok = False
        else:
            doc_link_cases.append(
                (
                    "doc-links",
                    doc_link_control,
                    lambda text: text
                    + "\n// Planted by --self-test (D159 §2 R3, GREEN 1): a second\n"
                    "// rustdoc-output-relative link [x](../manifest_wire/index.html),\n"
                    "// a URL [x](https://example.invalid/nowhere.md) and a site-root\n"
                    "// path [x](/docs/nowhere.md). None of the three is a doc link,\n"
                    "// and all three are dead on disk.\n",
                    "green",
                )
            )

        print(
            f"self-test: note — {len(doc_link_cases)} doc-link fixture(s) constructed "
            f"({sum(1 for c in doc_link_cases if c[3] == 'red')} red, "
            f"{sum(1 for c in doc_link_cases if c[3] == 'green')} green) over the two "
            f"branches that have a live subject; the other five are proven on "
            f"constructed trees above"
        )
        cases += doc_link_cases

        # ── D120 R6: every arm is a DELTA, not an absolute verdict ──────────
        # The failure this replaces was never in the red arms. 23 of the 33
        # cases in the literal list above are red and 10 are green, and D144's
        # 13 appended arms add 6 and 7 — counts in the prose, so RECOUNT them
        # when either list moves rather than trusting this sentence. The
        # appended block DERIVES and prints its own split on every run, which
        # is the form to prefer; the literal list's is still by hand.
        # It read "23 of the 32 … and 9 are green" until Q252 replaced the
        # decisions red arm with a red/green pair; the same wave found
        # `BOUNDARY_SOURCE`'s "Both copies" stale for exactly this reason, and
        # the first draft of this correction got the new split wrong by
        # arithmetic rather than by measurement. Every one of the seven
        # checks has at least one GREEN arm — so under exit-code validation
        # `--self-test` contained a complete second run of the entire check
        # suite that nobody declared and nobody could see, and it inherited
        # every unrelated red in the staged tree. Measured twice: a sibling
        # lane registering a row before writing its entry — the most ordinary
        # act in a wave — reddened this harness with two messages naming
        # green-case mutations of two files it had never touched and never
        # naming the row; and the D120 lane reddened it a second time by
        # leaving two scratch `.py` files in `scripts/`, a swept surface since
        # D116. At the gate it was worse than noisy: `lane_traceability` runs
        # this half FIRST and returns on failure, so the flagless half — which
        # names the real cause in one exact sentence — never ran at all.
        #
        # A baseline makes the tree's own state incapable of producing a
        # verdict, which is what a snapshot was proposed to buy and buys it
        # WITHOUT making the harness blind to the contributor's uncommitted
        # work. Note the direction: a green arm now asserts that the findings
        # do not CHANGE, which is strictly stronger than exit 0 — a widening
        # that made a check report FEWER findings now fails a green arm, where
        # under exit-code validation it would not. That is deliberate; do not
        # "simplify" it back to a truthiness test.
        def findings(check_name: str) -> set[str] | None:
            """That check's OWN annotations over the staged tree, or None on a
            crash.

            Line numbers are collapsed, so an unrelated shift — a sibling lane
            adding a paragraph above a finding's line — is not counted as a
            change. Only this check's annotation prefix is collected, which is
            what folds the old separate `annotated` test into the delta: a
            non-zero exit from anywhere else can no longer be mistaken for the
            check biting.
            """
            run = subprocess.run(
                [sys.executable, str(tree / "scripts/check-traceability.py"), f"--{check_name}"],
                capture_output=True,
                text=True,
            )
            if "Traceback (most recent call last)" in run.stderr:
                return None
            prefix = f"::error::check-traceability [{check_name}] "
            return {
                re.sub(r":\d+", ":<line>", line[len(prefix) :])
                for line in run.stderr.splitlines()
                if line.startswith(prefix)
            }

        baseline: dict[str, set[str]] = {}
        # `case[0]`, not a four-tuple unpack: D144's arms carry an optional
        # fifth element and an unpack here would raise on the first of them —
        # before any baseline exists, so every arm below would report the same
        # crash and none of them would be a delta against anything.
        for check_name in dict.fromkeys(case[0] for case in cases):
            measured = findings(check_name)
            if measured is None:
                print(
                    f"self-test: FAILED — {check_name} CRASHED on the UNMUTATED staged "
                    "tree, so no arm of it can be a delta against anything. Every case "
                    "below will report the same crash.",
                    file=sys.stderr,
                )
                ok = False
                measured = set()
            elif measured:
                # Printed, never suppressed: a contaminated tree must be
                # visible rather than silent. It is not a failure — the arms
                # are indifferent to it — but a reader who sees an arm behave
                # oddly is owed the fact that the tree was not clean.
                print(
                    f"self-test: note — {check_name} already reports {len(measured)} "
                    "finding(s) on the unmutated tree; the arms below are measured as "
                    "changes against that, and the flagless run is what names them"
                )
            baseline[check_name] = measured

        for case in cases:
            check, relative, mutate, expect = case[:4]
            fragment = case[4] if len(case) > 4 else None
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
            after = findings(check)
            path.write_text(original, encoding="utf-8")

            # A non-zero exit is NOT enough to call a red case proven. A
            # mutation that makes the script CRASH also exits non-zero, so a
            # red case can pass while the branch it was written for no longer
            # exists. Measured, on this file: delete check 6's
            # unregistered-owner branch and case (m) still "went red" — via a
            # KeyError traceback on the very lookup that branch guards, not via
            # a finding. Under exit-code-only validation that case pinned
            # nothing. So a red case must see the check's OWN annotation, and a
            # traceback fails the harness in either direction.
            if after is None:
                print(
                    f"self-test: FAILED — {check} CRASHED on the {expect}-case mutation "
                    f"of {relative}. A traceback is not a finding; the check must report "
                    f"the defect, not fall over on it.",
                    file=sys.stderr,
                )
                ok = False
                continue

            added = after - baseline[check]
            removed = baseline[check] - after

            if expect == "red" and not added:
                print(
                    f"self-test: FAILED — {check} added no finding on the red-case "
                    f"mutation of {relative}. The mutation applied and the check read "
                    f"the file, so either the check no longer bites this defect or it no "
                    f"longer reads this surface.",
                    file=sys.stderr,
                )
                ok = False
            elif expect == "red" and fragment and not any(fragment in f for f in added):
                print(
                    f"self-test: FAILED — {check} went red on the red-case mutation of "
                    f"{relative}, but no added finding says {fragment!r}. Going red is "
                    f"not proof the PLANTED fault is the one found — a neighbouring rule "
                    f"biting the same mutation looks identical to a delta. Added: "
                    f"{sorted(added)[:2]}",
                    file=sys.stderr,
                )
                ok = False
            elif expect == "green" and (added or removed):
                print(
                    f"self-test: FAILED — {check}'s findings CHANGED on the green-case "
                    f"mutation of {relative}: {len(added)} added, {len(removed)} removed. "
                    f"This arm exists to pin a tolerance, so a check that starts biting "
                    f"here — or stops biting something else — is a re-decision, not an "
                    f"edit.",
                    file=sys.stderr,
                )
                ok = False
            elif expect == "red":
                print(
                    f"self-test: ok — {check} goes red when {relative} is corrupted"
                    + (f", saying {fragment!r}" if fragment else "")
                )
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
        # Under Q184's rule this is the one BORROWED fixture left in the
        # harness, and it discharges the rule by a third route: not by being
        # derived and not by an argument that it is stable, but by a GUARD that
        # fails loudly the moment it stops being true. Where a borrowed literal
        # is unavoidable, that is the form to copy — a reason written beside a
        # fixture is a claim about the future, and a guard is a measurement
        # taken every run.
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
        # D120 R7 — a TRACEBACK gate, not an exit-code gate. This block used to
        # refuse to run at all unless the citation check was green on the
        # unmutated tree, which made the closing assertion the last inheritor
        # of the whole-suite coupling R6 removed everywhere else: a sibling
        # lane's unrelated finding turned it red. The assertion's real question
        # is whether these six tokens appear in the report, and that is
        # answerable whatever ELSE the check found. What it cannot survive is
        # an EMPTY report, so the crash still fails — see the message.
        if "Traceback (most recent call last)" in clean.stderr:
            print(
                "self-test: FAILED — --task-citations CRASHED on the unmutated staged "
                "tree, so this assertion would pass BY ABSENCE: a check that fell over "
                "names no token at all, and 'none of the six was reported' then means "
                "'nothing was reported'. An unrelated finding here is fine and is no "
                "longer a failure; a traceback is not, because it is what makes the "
                "absence meaningless.",
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
