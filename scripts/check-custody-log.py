#!/usr/bin/env python3
"""Q261 — enforce `docs/signing/key-custody.md` §10's own rule: *"Never edit a row."*

§10 is the record of what was done to the project signing key and when. Its
entire evidentiary value rests on rows never changing, and the file says so in
terms. Nothing checked it. The failure is silent by construction: a row edited
to say an act was taken reads exactly like a row that always said so, and the
log is the only place that history lives (D157 §2 R9).

WHAT IS PINNED, AND AGAINST WHAT
--------------------------------
The baseline is the file's BIRTH COMMIT (`BIRTH` below), and the check walks
every commit that touched the file from there to `HEAD`, then to the working
tree. Between each adjacent pair the invariant is *prefix-extension*: the
earlier revision's §10 rows must appear, unchanged and in order, at the front
of the later revision's. An append adds to the tail and passes; anything that
disturbs an already-written row reds.

WHY THE WALK, AND NOT BIRTH-VERSUS-TODAY. D157 §2 R9 measured both. A direct
birth-versus-today comparison reports one violation — the placeholder row §11
documents — and once that single exception is registered the baseline is
EMPTY, so the comparison asserts nothing at all and can never redden. That is
this project's dominant defect class (a check green because nothing reachable
could redden it), so it is refused here. The walk starts at the same birth
commit, registers the same one exception, and still pins every row written
since: `pinned` below is the count of row comparisons actually performed, and
a run that pins zero rows is a hard error rather than a pass.

THE EXCEPTIONS ARE DERIVED, NOT HARDCODED
-----------------------------------------
§11 says: *"Every amendment is recorded below with the text it replaced."* It
records the one §10 amendment — the 2026-08-19 replacement of the placeholder
row — by quoting the replaced row VERBATIM in a fenced block. So the exception
set is read out of §11's fenced blocks at run time. A hardcoded list would
drift from the document it exists to track; this way, retiring a row requires
writing its text into §11, which is the act §11 already demands. An exception
that matches no row in any revision is an error, not a silent no-op: it can
only mean §11's quote has drifted from the row it quotes, and a drifted quote
stops protecting the thing it names.

FOUR VIOLATION CLASSES, KEPT DISTINCT ON PURPOSE
------------------------------------------------
`EDITED`, `DELETED`, `REORDERED`, `INSERTED`. They are separate because
collapsing two failure classes under one message is how a broken branch hides
behind a working neighbour: `--self-test` plants one fault per class and
requires all four to come back with DIFFERENT kinds, so a classifier that
folded two together reds.

Exit: 0 pass · 1 violation or malformed input. No network. Reads the signing
log; never the key.
"""

from __future__ import annotations

import hashlib
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SUBJECT = "docs/signing/key-custody.md"

# The file's birth commit: `git log --diff-filter=A -- docs/signing/key-custody.md`.
# Pinned in full, and asserted to be the first commit the walk finds — if
# history is rewritten or the file is deleted and recreated, this reds rather
# than quietly re-baselining onto whatever is oldest today.
BIRTH = "2cdf0fb48ea72858786c4276371b93a774c30828"

LOG_SECTION = 10          # `## 10. Log` — the append-only custody table
AMENDMENTS_SECTION = 11   # `## 11. Amendments to this document` — the register

# Every class of disturbance to an already-written row. `--self-test` plants
# one fault per entry and asserts each comes back under its own name; the arm
# that checks coverage reads THIS tuple, so a fifth class cannot be added
# without a fault to exercise it.
VIOLATION_KINDS = ("EDITED", "DELETED", "REORDERED", "INSERTED")

MAX_SHOWN = 110  # row text is truncated in messages; the full text is in the file


class LogFormatError(Exception):
    """The subject file does not have the shape this check knows how to read.

    Raised rather than returning an empty row list: "no rows found" and "no
    §10" must not be the same outcome, or deleting the section would read as
    a clean append-only log.
    """


def _section(text: str, number: int) -> list[str] | None:
    """The body lines of `## <number>. ...`, or None if there is no such heading.

    Runs to the next `## ` heading or to end of file — at the birth commit §10
    WAS the last section (there was no §11), so a terminator-required parse
    would have read the baseline as empty.
    """
    want = f"## {number}."
    out: list[str] = []
    inside = False
    seen = False
    for line in text.split("\n"):
        if line.startswith("## "):
            if inside:
                break
            inside = line.startswith(want)
            seen = seen or inside
            continue
        if inside:
            out.append(line)
    return out if seen else None


def log_rows(text: str, origin: str) -> list[str]:
    """§10's DATA rows, stripped, in file order. Header and separator removed."""
    body = _section(text, LOG_SECTION)
    if body is None:
        raise LogFormatError(
            f"{origin}: no `## {LOG_SECTION}.` section. The custody log is the "
            f"subject of this check; its absence is a failure, not an empty log"
        )
    table = [ln.strip() for ln in body if ln.strip().startswith("|")]
    if len(table) < 2:
        raise LogFormatError(
            f"{origin}: `## {LOG_SECTION}.` carries no markdown table (found "
            f"{len(table)} pipe line(s), need at least a header and a separator)"
        )
    header, separator = table[0], table[1]
    if not header.startswith("| date | event | key id |"):
        raise LogFormatError(
            f"{origin}: §{LOG_SECTION}'s table header changed shape — expected it "
            f"to begin `| date | event | key id |`, found {header[:MAX_SHOWN]!r}. "
            f"The column layout is what the row comparison below is written against"
        )
    if set(separator) - set("|-: ") or "-" not in separator:
        raise LogFormatError(
            f"{origin}: §{LOG_SECTION}'s table separator is not a separator: "
            f"{separator[:MAX_SHOWN]!r}"
        )
    return table[2:]


def registered_exceptions(text: str, origin: str) -> list[str]:
    """The §10 rows §11 records as replaced, quoted verbatim in its fenced blocks."""
    body = _section(text, AMENDMENTS_SECTION)
    if body is None:
        raise LogFormatError(
            f"{origin}: no `## {AMENDMENTS_SECTION}.` section. §{AMENDMENTS_SECTION} "
            f"IS the exception register — without it there is nowhere to record a "
            f"retired row, and reading that as 'zero exceptions' would hide the loss"
        )
    out: list[str] = []
    fenced = False
    for line in body:
        stripped = line.strip()
        if stripped.startswith("```"):
            fenced = not fenced
            continue
        if fenced and stripped.startswith("|"):
            out.append(stripped)
    if fenced:
        raise LogFormatError(
            f"{origin}: §{AMENDMENTS_SECTION} has an unclosed code fence, so the "
            f"registered-exception set cannot be read"
        )
    return out


class Violation:
    __slots__ = ("row", "kind", "earlier", "later", "was", "now")

    def __init__(self, row: int, kind: str, earlier: str, later: str,
                 was: str | None, now: str | None) -> None:
        self.row, self.kind = row, kind
        self.earlier, self.later = earlier, later
        self.was, self.now = was, now

    def headline(self) -> str:
        return f"::error:: row {self.row} {self.kind}"

    def detail(self) -> list[str]:
        def show(v: str | None) -> str:
            if v is None:
                return "(absent)"
            return v if len(v) <= MAX_SHOWN else v[:MAX_SHOWN] + " …"
        return [
            f"    between {self.earlier} and {self.later}",
            f"    was: {show(self.was)}",
            f"    now: {show(self.now)}",
        ]


def classify(earlier_rows: list[str], later_rows: list[str], i: int) -> str:
    """Name the disturbance at index `i`, where the two sequences first differ.

    Kept as four distinct answers rather than one `CHANGED`: a message that
    cannot tell a deletion from a rewrite cannot tell a broken branch from a
    working one either.
    """
    was, now = earlier_rows[i], later_rows[i]
    was_survives = was in later_rows      # the pinned row still exists, elsewhere
    now_is_known = now in earlier_rows    # this slot now holds an older row
    if was_survives and now_is_known:
        return "REORDERED"
    if was_survives:
        return "INSERTED"                 # something new pushed a pinned row down
    if now_is_known:
        return "DELETED"                  # the pinned row is gone; the tail shifted up
    return "EDITED"                       # the pinned row was rewritten in place


def audit(states: list[tuple[str, list[str]]],
          exceptions: list[str]) -> tuple[list[Violation], int, int]:
    """Walk adjacent revisions. Returns (violations, pinned comparisons, exceptions consumed).

    `pinned` is the vacuity guard: it counts row comparisons that were actually
    performed, so a caller can tell "nothing was wrong" from "nothing was checked".
    """
    violations: list[Violation] = []
    pinned = 0
    consumed = 0
    for (earlier_label, earlier_raw), (later_label, later) in zip(states, states[1:]):
        earlier: list[str] = []
        for row in earlier_raw:
            if row in exceptions:
                consumed += 1     # registered in §11 as replaced: retired from the pin
            else:
                earlier.append(row)
        hit = False
        for i in range(min(len(earlier), len(later))):
            pinned += 1
            if earlier[i] != later[i]:
                violations.append(Violation(i + 1, classify(earlier, later, i),
                                            earlier_label, later_label,
                                            earlier[i], later[i]))
                hit = True
                break
        if not hit and len(later) < len(earlier):
            # No mismatch in the overlap, but the tail was truncated. A separate
            # branch from the loop above, and it has its own planted fault.
            violations.append(Violation(len(later) + 1, "DELETED",
                                        earlier_label, later_label,
                                        earlier[len(later)], None))
    return violations, pinned, consumed


def unused_exceptions(states: list[tuple[str, list[str]]],
                      exceptions: list[str]) -> list[str]:
    """Registered exceptions that match no row in any revision.

    A §11 quote that matches nothing has drifted from the row it documents, so
    it exempts nothing and protects nothing. Extracted as its own function
    because `--self-test` has to be able to REACH this branch: an arm that only
    ever runs it through `run()` cannot tell a working detector from a deleted
    one.
    """
    return [q for q in exceptions
            if not any(q in rows for _, rows in states)]


def _git(*args: str) -> str:
    proc = subprocess.run(("git", *args), cwd=ROOT, capture_output=True, text=True)
    if proc.returncode != 0:
        raise LogFormatError(
            f"git {' '.join(args)} failed ({proc.returncode}): "
            f"{proc.stderr.strip()[:400]}"
        )
    return proc.stdout


def revisions() -> list[str]:
    """Every commit that touched the subject, oldest first, starting at BIRTH."""
    out = _git("rev-list", "--reverse", "HEAD", "--", SUBJECT).split()
    if not out:
        raise LogFormatError(
            f"no commit in HEAD's history touches {SUBJECT} — the baseline cannot "
            f"be established, so nothing below would be pinned"
        )
    if out[0] != BIRTH:
        raise LogFormatError(
            f"baseline drift: the oldest commit touching {SUBJECT} is {out[0]}, but "
            f"this check is pinned to birth commit {BIRTH}. Either history was "
            f"rewritten or the file was deleted and recreated; re-establish the "
            f"baseline deliberately rather than letting it follow the tree"
        )
    return out


def collect_states() -> list[tuple[str, list[str]]]:
    states: list[tuple[str, list[str]]] = []
    for sha in revisions():
        text = _git("show", f"{sha}:{SUBJECT}")
        states.append((sha[:7], log_rows(text, f"{SUBJECT}@{sha[:7]}")))
    worktree = (ROOT / SUBJECT).read_text(encoding="utf-8")
    states.append(("worktree", log_rows(worktree, f"{SUBJECT} (working tree)")))
    return states


def run() -> int:
    try:
        states = collect_states()
        worktree_text = (ROOT / SUBJECT).read_text(encoding="utf-8")
        exceptions = registered_exceptions(worktree_text, f"{SUBJECT} (working tree)")
    except LogFormatError as exc:
        print(f"::error::check-custody-log: {exc}")
        return 1

    problems = 0

    # A §11 quote that matches no row in any revision has drifted from the row
    # it names, and a drifted quote protects nothing.
    for quoted in unused_exceptions(states, exceptions):
        print(f"::error::check-custody-log: §{AMENDMENTS_SECTION} registers a "
              f"replaced row that appears in NO revision of §{LOG_SECTION} — the "
              f"quote has drifted from the row it documents, so it exempts "
              f"nothing and hides nothing: {quoted[:MAX_SHOWN]} …")
        problems += 1

    violations, pinned, consumed = audit(states, exceptions)
    for v in violations:
        print(v.headline())
        for line in v.detail():
            print(line)
        problems += 1

    # The vacuity guard. `pinned == 0` means every comparison was exempted or
    # skipped, which is exactly how a birth-versus-today variant of this check
    # would pass while asserting nothing (D157 §2 R9).
    if pinned == 0:
        print(f"::error::check-custody-log: the walk pinned ZERO row comparisons "
              f"across {len(states)} revision(s) — this run asserted nothing, so a "
              f"green verdict would be meaningless")
        problems += 1

    if problems:
        print(f"check-custody-log: FAILED with {problems} problem(s). "
              f"§{LOG_SECTION} says 'Never edit a row'; record a genuine amendment "
              f"in §{AMENDMENTS_SECTION} with the text it replaced, or restore the row.")
        return 1

    today = states[-1][1]
    print(f"check-custody-log: ok — {SUBJECT} §{LOG_SECTION} is append-only across "
          f"{len(states)} state(s) walked from birth {BIRTH[:7]}; {len(today)} dated "
          f"row(s) today, {pinned} pinned row-comparison(s), "
          f"{len(exceptions)} registered exception(s) in §{AMENDMENTS_SECTION} "
          f"(consumed {consumed}), {len(violations)} violation(s)")
    return 0


# ── self-test ─────────────────────────────────────────────────────────────
#
# Every arm plants ONE fault and requires it to be caught BY ITS MESSAGE, not
# by a nonzero exit; every mutation asserts it actually applied first, because
# a plant that fails to apply returns the same 0 a working check does.
#
# The faults are applied to IN-MEMORY copies of the real states. The subject
# file is never written — the final arm hashes it before and after and reds if
# a byte moved.

def _sub(rows: list[str], i: int, old: str, new: str) -> list[str]:
    out = list(rows)
    if old not in out[i]:
        raise AssertionError(f"plant did not apply: {old!r} is not in row {i + 1}")
    out[i] = out[i].replace(old, new, 1)
    if out[i] == rows[i]:
        raise AssertionError("plant did not apply: the row is unchanged")
    return out


def _with_last(states: list[tuple[str, list[str]]],
               rows: list[str]) -> list[tuple[str, list[str]]]:
    return states[:-1] + [(states[-1][0], rows)]


SYNTHETIC = ("| 2099-01-01 | rotation | `SELFTESTSELFTEST` | self-test row, "
             "never written to the file |")


def self_test() -> int:
    subject_path = ROOT / SUBJECT
    before = hashlib.sha256(subject_path.read_bytes()).hexdigest()
    text = subject_path.read_text(encoding="utf-8")
    states = collect_states()
    exceptions = registered_exceptions(text, SUBJECT)
    today = states[-1][1]
    if len(today) < 2:
        print(f"::error::check-custody-log self-test: §{LOG_SECTION} carries "
              f"{len(today)} row(s); the plants below need at least 2")
        return 1

    seen_kinds: dict[str, str] = {}   # kind -> the arm that produced it
    failures: list[str] = []
    # Every arm records its own class here as it runs, so the tally printed at
    # the end is DERIVED from what happened rather than written down beside it.
    # `ci-lanes.sh`'s lane comment quotes this line; if an arm is added and the
    # comment is not, the two visibly disagree.
    ledger: list[tuple[str, str]] = []

    def ok(name: str, kind: str, msg: str) -> None:
        ledger.append((name, kind))
        print(f"  {name:<26} -> {msg}")

    def arm(name: str, got: tuple[list[Violation], int, int],
            want_kind: str | None, want_row: int | None,
            note: str) -> None:
        violations, pinned, _ = got
        if want_kind is None:
            if violations:
                failures.append(f"{name}: expected GREEN ({note}) but got "
                                f"{len(violations)}: {violations[0].headline()}")
            elif pinned == 0:
                failures.append(f"{name}: GREEN but pinned 0 comparisons — the arm "
                                f"proves nothing ({note})")
            else:
                ok(name, "green-control", f"GREEN ({pinned} pinned) — {note}")
            return
        if len(violations) != 1:
            failures.append(f"{name}: expected exactly 1 violation ({note}), got "
                            f"{len(violations)}")
            return
        v = violations[0]
        if v.kind != want_kind or v.row != want_row:
            failures.append(f"{name}: expected `::error:: row {want_row} {want_kind}` "
                            f"({note}), got `{v.headline()}`")
            return
        seen_kinds.setdefault(v.kind, name)
        ok(name, "planted-fault", f"{v.headline()} — {note}")

    # 1. The real tree, unplanted. The control every other arm is read against.
    arm("real-tree", audit(states, exceptions), None, None,
        "the committed log, with §11's exception registered")

    # 2. D157 §2 R9's named plant: the fault a well-meaning lane would actually
    #    commit — "correcting" a superseded custody row to match today.
    try:
        plant = _sub(today, 0, "NOT yet made", "made")
    except AssertionError as exc:
        print(f"::error::check-custody-log self-test: {exc} — §{LOG_SECTION}'s first "
              f"row no longer carries the text D157 §2 R9's plant patches. Re-choose "
              f"the plant deliberately; do not drop the arm.")
        return 1
    arm("d157-edit-plant", audit(_with_last(states, plant), exceptions),
        "EDITED", 1, "the 2026-08-19 row's 'NOT yet made' flipped to 'made'")

    # 3. THE GREEN CONTROL. A genuine append must pass, or the check is just a
    #    lock on the file and the log can never grow.
    arm("append-green", audit(_with_last(states, today + [SYNTHETIC]), exceptions),
        None, None, "a new dated row appended to the tail")

    # 4. Deletion of a pinned row, caught by the mismatch branch.
    arm("delete-first-row", audit(_with_last(states, today[1:]), exceptions),
        "DELETED", 1, "the first dated row removed")

    # 5. Truncation of the tail, caught by the LENGTH branch — a different
    #    branch from arm 4, and it would pass if that branch were dropped.
    arm("truncate-tail", audit(_with_last(states, today[:-1]), exceptions),
        "DELETED", len(today), "the last dated row removed (length branch)")

    # 6. Reordering: every row still present, none rewritten.
    arm("reorder-rows", audit(_with_last(states, list(reversed(today))), exceptions),
        "REORDERED", 1, "the dated rows swapped, none rewritten")

    # 7. Insertion ahead of a pinned row — an append-only log grows at the tail.
    arm("insert-before-row-1", audit(_with_last(states, [SYNTHETIC] + today), exceptions),
        "INSERTED", 1, "a new row spliced in FRONT of a pinned row")

    # 8. The exception is LOAD-BEARING, not decorative: drop §11's register and
    #    the real tree must go red at the birth step. If this stays green, the
    #    walk is not actually pinning the baseline it claims to.
    unregistered = audit(states, [])
    if not unregistered[0]:
        failures.append("exception-load-bearing: the real tree stayed GREEN with the "
                        "§11 register emptied — the birth baseline is not being pinned, "
                        "so the registered exception exempts nothing")
    else:
        ok("exception-load-bearing", "planted-fault",
           f"{unregistered[0][0].headline()} — real tree with §11's register emptied")

    # 9. A §11 quote that drifts by one character stops matching the row it
    #    documents. The drifted quote must be NAMED, not silently ignored.
    if not exceptions:
        failures.append("exception-drift: §11 registers no replaced row, so this arm "
                        "cannot run; the real tree needs exactly the one §10 amendment "
                        "§11 documents")
    else:
        drifted = [exceptions[0].replace("no key generated yet", "no key generated Yet", 1)]
        if drifted == exceptions:
            failures.append("exception-drift: the plant did not apply — §11's quoted "
                            "row no longer carries the text this arm patches")
        else:
            matched = any(drifted[0] in rows for _, rows in states)
            if matched:
                failures.append("exception-drift: the drifted quote still matches a "
                                "row, so the arm proves nothing")
            elif not audit(states, drifted)[0]:
                failures.append("exception-drift: the real tree stayed GREEN with §11's "
                                "quote drifted by one character — the exception is not "
                                "being matched against the row at all")
            elif unused_exceptions(states, drifted) != drifted:
                failures.append("exception-drift: the drifted quote was NOT reported as "
                                "unregistered — the detector in `run()` cannot go red, "
                                "so a §11 quote could rot unnoticed")
            else:
                ok("exception-drift", "planted-fault",
                   f"{audit(states, drifted)[0][0].headline()} + unregistered-quote "
                   f"— §11's quote altered by one character")

    # 9b. ... and its GREEN control: on the real tree every registered quote
    #     must match a real row, or the arm above would pass on a detector that
    #     simply reports everything.
    if unused_exceptions(states, exceptions):
        failures.append("exception-drift-control: the UNMODIFIED §11 register was "
                        "reported as unregistered — the detector reports everything and "
                        "so distinguishes nothing")
    else:
        ok("exception-drift-control", "green-control",
           "every §11 quote matches a real row")

    # 10. The branch test. Four plants, four kinds: if any two classes collapsed
    #     under one message, a broken branch would be covered by its neighbour
    #     and every arm above would still pass.
    if len(set(seen_kinds)) != len(seen_kinds) or len(seen_kinds) < 4:
        failures.append(f"kinds-distinct: the plants produced {len(seen_kinds)} "
                        f"distinct kind(s) ({sorted(seen_kinds)}), not 4 — two failure "
                        f"classes have collapsed under one message")
    else:
        ok("kinds-distinct", "property",
           f"4 plants, 4 distinct kinds {sorted(seen_kinds)}")

    # 11. Coverage read off VIOLATION_KINDS itself, so a fifth class cannot be
    #     added without a fault to exercise it (the Q245 lesson).
    uncovered = [k for k in VIOLATION_KINDS if k not in seen_kinds]
    if uncovered:
        failures.append(f"kind-coverage: violation class(es) with NO planted fault: "
                        f"{', '.join(uncovered)} — an unexercised branch is an "
                        f"assertion that cannot fail")
    else:
        ok("kind-coverage", "property",
           f"all {len(VIOLATION_KINDS)} declared kind(s) exercised by name")

    # 12-14. The parser must REFUSE malformed input, never read it as an empty
    #        log. "No §10" and "§10 with no rows" reaching the same answer is
    #        how deleting the section would read as a clean append-only history.
    for name, mutate, needle in (
        ("parse-no-section-10", lambda t: t.replace("## 10. Log", "## 10x Log", 1), None),
        ("parse-no-table", lambda t: "\n".join(
            ln for ln in t.split("\n") if not ln.strip().startswith("|")), None),
        ("parse-no-section-11",
         lambda t: t.replace("## 11. Amendments to this document", "## 11x", 1), "11"),
    ):
        mutated = mutate(text)
        if mutated == text:
            failures.append(f"{name}: the plant did not apply — the file no longer has "
                            f"the shape this arm patches")
            continue
        try:
            if needle:
                registered_exceptions(mutated, "self-test")
            else:
                log_rows(mutated, "self-test")
        except LogFormatError as exc:
            ok(name, "planted-fault", f"refused: {str(exc)[:78]} …")
        else:
            failures.append(f"{name}: the parser ACCEPTED malformed input instead of "
                            f"raising — a missing section would read as an empty log")

    # 15. The self-test must not have written to the subject it audits.
    after = hashlib.sha256(subject_path.read_bytes()).hexdigest()
    if before != after:
        failures.append(f"no-writes: {SUBJECT} changed during the self-test "
                        f"({before[:12]} -> {after[:12]}) — the check modified the "
                        f"record it exists to protect")
    else:
        ok("no-writes", "hygiene",
           f"{SUBJECT} byte-identical (sha256 {before[:12]}…)")

    # A self-test made only of red arms passes on a check that reddens on
    # everything, so the green controls are counted and required by name.
    greens = [n for n, k in ledger if k == "green-control"]
    if len(greens) < 2:
        failures.append(f"green-controls: {len(greens)} green control(s) "
                        f"({greens or 'none'}) — a suite of red arms alone cannot tell "
                        f"a working check from one that reddens on everything")

    if failures:
        for f in failures:
            print(f"::error::check-custody-log self-test: {f}")
        print(f"check-custody-log self-test FAILED with {len(failures)} problem(s) — "
              f"a green run below would prove nothing")
        return 1
    tally: dict[str, int] = {}
    for _, kind in ledger:
        tally[kind] = tally.get(kind, 0) + 1
    print(f"check-custody-log self-test PASS — {len(ledger)} arm(s): "
          + ", ".join(f"{v} {k}" for k, v in sorted(tally.items())))
    return 0


def main(argv: list[str]) -> int:
    if len(argv) > 1 and argv[1] == "--self-test":
        return self_test()
    if len(argv) > 1:
        print(f"usage: {Path(argv[0]).name} [--self-test]", file=sys.stderr)
        return 2
    return run()


if __name__ == "__main__":
    sys.exit(main(sys.argv))
