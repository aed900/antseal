#!/usr/bin/env python3
"""Every `deny.toml` advisory ignore carries ONE review date, and none has passed (D183, task Q277).

D19 made it a rule that every `[advisories].ignore` entry carries a written
justification AND a review date in its `reason`, and that an entry past its
date is expired: re-assess and re-date it, or remove it. Nothing enforced the
second half. Five entries fell due on 2026-11-01 with no row owning them, and
cargo-deny cannot help: `reason` is free text to it, and it goes on honouring
an ignore whose date passed long ago. A deadline nothing reads is a comment.

So this reads deny.toml with `tomllib` (standard library, Python 3.11+, so it
rides the cargo-free `traceability` job) and applies three rules:

  R0  the ignore list parses and is not empty. A missing, renamed or emptied
      list is RED: a check over zero entries is green for no reason.
  R1  every entry is a table whose `reason` carries exactly ONE
      `Review by YYYY-MM-DD`, and that date is a real calendar date. A bare
      string entry (no reason at all) is RED; so are zero dates, or two.
  R2  today is not after the date. On the date itself and in the fourteen
      days before it the check WARNS and stays green — the
      scripts/check-action-pins.py P6 shape, where the warn tier exists only
      inside a rule whose other tier is red.

"Today" is the UTC date, so a hosted runner and a contributor's machine agree
on which day it is. A deadline written "Review by 2027-01-15 or at the next
ant-core pin move, whichever comes first" carries one date; the event half is
the reviewer's to honour, and no check here can see a pin move coming.

Measured yield on arrival (D183 R3, 2026-10-16): at fbcee1e, six dated entries,
five of them due 2026-11-01 — warning from 2026-10-19, red from 2026-11-02 —
and zero false positives. The self-test's date-injection arms replay exactly
that day without waiting for it.

VENUES: scripts/local-gate.sh; the `traceability` job of
.github/workflows/ci-always.yml (every push, docs-only ones included); and
.github/workflows/advisory-cron.yml — the weekly schedule, and the only venue
that runs when nothing is pushed, which is exactly when a date passes unseen.

Usage:
    scripts/check-deny-reviews.py              check deny.toml
    scripts/check-deny-reviews.py --self-test  plant every rule in memory; each must go red by its tag
Exit: 0 pass (warnings allowed), 1 failure, 2 bad usage.
"""

from __future__ import annotations

import re
import sys
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import NamedTuple

try:
    import tomllib
except ModuleNotFoundError:  # Python < 3.11: say so, rather than die in a traceback
    print("::error::check-deny-reviews: needs Python 3.11+ for the standard-library `tomllib`")
    raise SystemExit(1)

REPO = Path(__file__).resolve().parent.parent
DENY_TOML = REPO / "deny.toml"

# How many days before a review date the check starts saying so.
WARN_WINDOW_DAYS = 14

REVIEW_RE = re.compile(r"Review by (\d{4}-\d{2}-\d{2})(?![\d-])")


class Result(NamedTuple):
    errors: list[str]
    warnings: list[str]
    dated: list[tuple[str, date]]  # (advisory id, review date) for every entry that has one


def today_utc() -> date:
    return datetime.now(timezone.utc).date()


def check(text: str, today: date) -> Result:
    """The verdict over one deny.toml text on one day. Pure, so every arm plants in memory."""
    errors: list[str] = []
    warnings: list[str] = []
    dated: list[tuple[str, date]] = []
    try:
        cfg = tomllib.loads(text)
    except tomllib.TOMLDecodeError as e:
        return Result([f"[R0] deny.toml does not parse as TOML ({e}), so no ignore entry can "
                       f"be checked"], [], [])
    advisories = cfg.get("advisories")
    entries = advisories.get("ignore") if isinstance(advisories, dict) else None
    if not isinstance(entries, list) or not entries:
        return Result(["[R0] deny.toml has no `[advisories].ignore` entries to check. A missing, "
                       "renamed or emptied list is RED, because a check over zero entries is "
                       "green for no reason; if every ignore really was removed, remove this "
                       "check's three venues in the same commit."], [], [])
    for n, entry in enumerate(entries, 1):
        if not isinstance(entry, dict):
            errors.append(f"[R1] ignore entry {n} ({entry!r}) is a bare string: it carries no "
                          f"`reason`, so no justification and no review date (D19)")
            continue
        ident = str(entry.get("id") or entry.get("crate") or f"ignore entry {n}")
        reason = entry.get("reason")
        if not isinstance(reason, str):
            errors.append(f"[R1] {ident}: no `reason` string, so no justification and no review "
                          f"date (D19)")
            continue
        found = REVIEW_RE.findall(reason)
        if len(found) != 1:
            errors.append(f"[R1] {ident}: its reason carries {len(found)} `Review by YYYY-MM-DD` "
                          f"date(s); D19 needs exactly one")
            continue
        try:
            due = date.fromisoformat(found[0])
        except ValueError:
            errors.append(f"[R1] {ident}: `Review by {found[0]}` is not a calendar date")
            continue
        dated.append((ident, due))
        if today > due:
            errors.append(
                f"[R2] {ident}: its review was due {due} and today is {today} (UTC), "
                f"{(today - due).days} day(s) past. An ignore past its review date is expired "
                f"(D19; deny.toml header): re-assess it with today's measurements and re-date "
                f"it, or remove it."
            )
        elif today > due - timedelta(days=WARN_WINDOW_DAYS):
            warnings.append(
                f"[R2] {ident}: its review falls due {due}, in {(due - today).days} day(s) "
                f"(today {today}, UTC). Not red yet: re-assess and re-date it, or remove it, "
                f"before then."
            )
    return Result(errors, warnings, dated)


def self_test() -> int:
    """Every rule planted in memory, judged by its tag and the names its message must carry.

    The arms are built from the live file, never from a frozen copy: the first
    dated entry is the victim, and the injected days are counted from the
    earliest review date found, so no arm disarms itself when the dates move.
    A plant that changes nothing is reported NOT APPLIED, never counted.
    """
    text = DENY_TOML.read_text(encoding="utf-8")
    today = today_utc()
    control = check(text, today)
    ok = True
    print(f"  control: deny.toml today ({today}, UTC){'':18s} -> "
          f"{'RED' if control.errors else 'GREEN'} ({len(control.dated)} dated, "
          f"{len(control.warnings)} warning(s))")
    if control.errors or not control.dated:
        print("    ::error:: the control is red or found no dated entry; fix deny.toml before "
              "trusting any arm")
        for e in control.errors:
            print(f"      {e}")
        return 1
    victim, victim_due = control.dated[0]
    first = victim_due.isoformat()
    earliest = min(due for _, due in control.dated)
    at_earliest = sorted(i for i, due in control.dated if due == earliest)

    def all_dates(day: str) -> str:
        return REVIEW_RE.sub(f"Review by {day}", text)

    # `ignore = [ … ]` replaced by `ignore = []`: the list is there and empty.
    start = text.find("\nignore = [")
    end = text.find("\n]\n", start)
    emptied = (text[:start] + "\nignore = []\n" + text[end + 3:]) if start >= 0 <= end else text

    # (label, planted text, injected day, tag, required substrings, errors wanted, warnings wanted)
    arms: list[tuple[str, str, date, str, tuple[str, ...], int, int | None]] = [
        ("R1 the victim's date removed", text.replace(f"Review by {first}", "Review later", 1),
         today, "[R1]", (victim, "carries 0"), 1, None),
        ("R1 a second date in the victim's reason",
         text.replace(f"Review by {first}", f"Review by {first}. Review by {first}", 1),
         today, "[R1]", (victim, "carries 2"), 1, None),
        ("R1 a bare-string entry (no reason at all)",
         text.replace("\nignore = [", '\nignore = [\n    "RUSTSEC-0000-0000",', 1),
         today, "[R1]", ("RUSTSEC-0000-0000", "bare string"), 1, None),
        ("R1 a date that is not a calendar date",
         text.replace(f"Review by {first}", "Review by 2027-02-30", 1),
         today, "[R1]", (victim, "not a calendar date"), 1, None),
        ("R0 the ignore list emptied (`ignore = []`)", emptied,
         today, "[R0]", ("no `[advisories].ignore` entries",), 1, None),
        ("R0 the ignore list renamed away", text.replace("\nignore = [", "\nignore_off = [", 1),
         today, "[R0]", ("no `[advisories].ignore` entries",), 1, None),
        ("R0 the [advisories] table renamed away",
         text.replace("\n[advisories]\n", "\n[advisories_off]\n", 1),
         today, "[R0]", ("no `[advisories].ignore` entries",), 1, None),
        ("R0 deny.toml no longer parses", text + "\n[advisories\n",
         today, "[R0]", ("does not parse",), 1, None),
        # DATE INJECTION — the arms that replay a deadline without waiting for it.
        (f"R2 the day after the earliest date ({earliest})", text,
         earliest + timedelta(days=1), "[R2]", (at_earliest[0], "1 day(s) past"),
         len(at_earliest), None),
        ("R2 every date at 2026-11-01, checked on 2026-11-02 (the fbcee1e deadline)",
         all_dates("2026-11-01"), date(2026, 11, 2), "[R2]",
         (victim, "due 2026-11-01", "1 day(s) past"), len(control.dated), None),
        # GREEN arms: warnings print, the verdict stays green.
        ("R2 seven days before the earliest date (WARN, green)", text,
         earliest - timedelta(days=7), "[R2]", (at_earliest[0], "in 7 day(s)"), 0, None),
        ("R2 ON the earliest date (WARN, green)", text,
         earliest, "[R2]", (at_earliest[0], "in 0 day(s)"), 0, None),
        ("R2 every date at 2026-11-01, checked on 2026-10-19 (WARN, green)",
         all_dates("2026-11-01"), date(2026, 10, 19), "[R2]", (victim, "in 13 day(s)"), 0,
         len(control.dated)),
        ("R2 every date at 2026-11-01, checked on 2026-10-18 (outside the window)",
         all_dates("2026-11-01"), date(2026, 10, 18), "", (), 0, 0),
    ]
    for label, planted, day, tag, needles, want_errors, want_warnings in arms:
        if planted == text and day == today:
            print(f"  planted fault: {label:62s} -> NOT APPLIED")
            ok = False
            continue
        got = check(planted, day)
        pool = got.errors if want_errors else got.warnings
        found = bool(not tag or any(m.startswith(tag) and all(s in m for s in needles)
                                    for m in pool))
        good = (len(got.errors) == want_errors and found
                and (want_warnings is None or len(got.warnings) == want_warnings))
        verdict = ("RED" if got.errors else "GREEN") + (f", {len(got.warnings)} warning(s)"
                                                       if got.warnings else "")
        print(f"  planted fault: {label:62s} -> {verdict}{'' if good else '  WRONG'}")
        if not good:
            ok = False
            print(f"    ::error:: wanted {want_errors} error(s) tagged {tag or '(none)'} carrying "
                  f"{needles!r}" + ("" if want_warnings is None else
                                    f" and {want_warnings} warning(s)") + "; got:")
            for m in got.errors + got.warnings or ["(nothing)"]:
                print(f"      {m}")
    return 0 if ok else 1


def main() -> int:
    args = sys.argv[1:]
    if args == ["--self-test"]:
        rc = self_test()
        print("check-deny-reviews self-test " + ("PASS" if rc == 0 else "FAIL"))
        return rc
    if args:
        print(f"usage: {sys.argv[0]} [--self-test]", file=sys.stderr)
        return 2
    today = today_utc()
    result = check(DENY_TOML.read_text(encoding="utf-8"), today)
    for warning in result.warnings:
        print(f"::warning::check-deny-reviews: {warning}")
    for error in result.errors:
        print(f"::error::check-deny-reviews: {error}")
    if result.errors:
        return 1
    due, ident = min((due, ident) for ident, due in result.dated)
    print(
        f"check-deny-reviews: {len(result.dated)} `[advisories].ignore` entr"
        f"{'y' if len(result.dated) == 1 else 'ies'} in deny.toml, each with exactly one review "
        f"date; the next falls due {due} ({ident}), in {(due - today).days} day(s); today is "
        f"{today} (UTC)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
