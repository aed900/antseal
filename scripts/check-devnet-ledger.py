#!/usr/bin/env python3
"""D167 — the devnet promote trigger's evidence, in a committed append-only ledger.

WHY A LEDGER, AND WHY THIS FILE WRITES IT
-----------------------------------------
`devnet-e2e-scheduled` may be promoted to a required context only after **20
consecutive clean scheduled runs** (D167 §2 R4). Twenty weekly runs span 133
days; a public repository's retention ceiling is 90 days and this workflow's
artifacts live 30 (D167 §1.2), so no GitHub-side store can hold the evidence.
It lives in `docs/testing/devnet-e2e-ledger.tsv`, one line per completed run
attempt, appended by THIS script's `--append` at wave close from read-only GETs
(§2 R2). No workflow writes it: a workflow commit would be the repository's
first `contents: write` grant, would trigger no CI, and would move `HEAD`, which
is a wasm build input (§1.5).

THE LINE
--------
Tab-separated, header first, fourteen columns:

  workflow run_id attempt event head_sha started_at conclusion class secs
  markers compile_secs noncompile_secs clean verdict

* `workflow` keys every record on the workflow FILE (§4), so a later ruling can
  widen the ledger to another schedule without a format change.
* `attempt` is not in §2 R1's list, and the key is (workflow, run_id, attempt)
  rather than the run id alone. A GitHub run has attempts. Keyed on the run id,
  an append-only ledger could never record a re-run made after its first append,
  and a red first attempt re-run BEFORE the append would vanish behind the green
  one — the flake this count exists to measure. So every attempt gets a line,
  and only attempt 1 of a scheduled run can count (a re-run is a manual act,
  like a dispatch).
* `class` is `executed` iff the job was assigned a runner (`runner_name`
  non-empty), else `refused` — never read from `steps`, which also empties
  when a log expires (§1.6).
* `verdict` is the `e2e-devnet:` line VERBATIM from the job log, or `-` for a
  refused run, `absent` for an executed run whose log carries no verdict (a
  timeout, a cancel), `log-expired` for one whose log answered 410.
* `secs` repeats the verdict's `secs=`. `markers` is `found/expected` cargo
  `Finished … in` lines, `compile_secs` their sum, and `noncompile_secs` is
  `secs - compile_secs` (§2 R3). Durations are summed in centiseconds, so the
  two decimals are exact arithmetic on what cargo printed — cargo truncates a
  duration >= 60 s to whole seconds, so each such marker can under-read by up
  to 1 s and `secs=` itself by up to 1 s.

THE RUNTIME DERIVATION IS FAIL-CLOSED (§2 R3)
---------------------------------------------
Markers are counted ONLY inside the job log's `Run ./scripts/e2e-devnet.sh`
step and before its verdict line, so a cargo invocation in any other step can
never be subtracted from a clock it was not inside. The lane's known compile
invocations are `1 + suites_run`: `scripts/devnet/local-up` runs one
`cargo build --release` and `scripts/e2e-devnet.sh` runs one `cargo test` per
live suite, and `suites_run=` is that count. Fewer markers than that — a suite
that failed to compile, a toolchain whose cargo prints a new format, a `--plan`
run that compiled nothing — writes `unmeasured`, and so does MORE (stricter
than the ruling's "fewer": a surplus marker is time this derivation cannot place
inside or outside the clock). An `unmeasured` run is never clean.

CLEAN, AND THE STREAK (§2 R4)
-----------------------------
Clean = executed, verdict `PASS`, `nodes >= 14`, `failed=[]`, `pending=[]`,
`suites_run >= 1`, `secs > 0`, non-compile runtime measured and <= 900 s — AND
job conclusion `success`. That last condition is STRICTER THAN §2 R4 AS
WRITTEN, deliberately: a run GitHub shows red (its redaction scan refused the
upload, say) must not be counted green here, because D52's triage rule counts
reds by the run's conclusion. The streak walks records in `started_at` order:
a refused run neither extends nor breaks it, any executed non-clean attempt
(of any event) resets it, and only a clean `schedule` attempt 1 extends it.

TWO HALVES (§2 R5)
------------------
OFFLINE — the flagless run. No network. Walks every commit that touched the
ledger, oldest first, then the working tree; between each adjacent pair the
earlier revision's lines must survive unchanged, in order, at the front of the
later one. Tags, each with its own planted fault in `--self-test`:

  EDITED     a line present in an earlier revision was rewritten, deleted,
             reordered or pushed down, or the file was deleted
  DUPLICATE  two lines share (workflow, run_id, attempt)
  COUNT      a line's `clean` disagrees with the §2 R4 recomputation — in the
             ruled direction ("counted clean but is not") or the other
  FORMAT     a line or the file does not parse, or a line's fields contradict
             each other (secs vs the verdict, markers vs suites_run, the
             non-compile arithmetic, the verdict's commit vs head_sha)
  UNBORN     no commit in HEAD's history adds the ledger, or the walk pinned
             ZERO line comparisons. The birth commit is DERIVED, never pinned:
             a pinned SHA is an input to every history rewrite (Q261). A ledger
             present in the working tree but never committed — the state of
             the wave that creates it — is still content-checked (FORMAT,
             DUPLICATE, COUNT) as an uncommitted addition, and still RED,
             because nothing about its history has been asserted.
  SHALLOW    the repository is a shallow clone: its grafted root reads as the
             ledger's birth, so the walk would re-baseline silently

There is NO exception register (custody-log's §11 has one; D167 rules none).
An EDITED that reaches a commit reds this check on every later run, because
history keeps the edit; clearing it is a ruling and a code change, never an
edit to the ledger.

ONLINE — `--against-api`, GET only, run at wave close, never in a CI lane or
the offline gate:

  LAG             a completed run attempt of the workflow has no line
  STALE-SCHEDULE  the newest `schedule` run is older than 7 days + 12 hours, or
                  no scheduled run exists at all (a public repository's
                  schedule auto-disables after 60 days without activity). The
                  ruling's floor is 5 h against measured 4 h 16 m / 4 h 28 m
                  delays; across the five recorded runs the delay spread is
                  22 m .. 4 h 28 m, which 5 h clears by under an hour, and a
                  genuinely missed week still fires with 6.5 days to spare.
  MISMATCH        a recorded line disagrees with the API on a field the run
                  list carries (event, head_sha; and, for the latest attempt,
                  conclusion and started_at). Not in the ruling: it is the only
                  instrument that can see a line forged before its first commit.

WHAT THIS CANNOT SEE — read before trusting a green:
  1. A rewrite of history that alters a line consistently in EVERY revision.
     Deriving the birth instead of pinning it is the ruling's trade (Q261).
  2. A forged verdict line after its log has expired: MISMATCH checks only the
     fields the run list carries, and nothing can re-read an expired log.
  3. A history simplified away by merges: the walk follows `git rev-list`'s
     default simplification, as `check-custody-log.py` does.
  4. Whether the tests a PASS ran were meaningful — that is the suite
     registry's subject (`scripts/e2e-devnet.sh --self-test`), not this one's.

Usage:
  scripts/check-devnet-ledger.py                offline check (the gate lane)
  scripts/check-devnet-ledger.py --self-test    planted faults on synthetic
                                                repositories and recorded fixtures
  scripts/check-devnet-ledger.py --against-api  online check (wave close)
  scripts/check-devnet-ledger.py --append       append every completed, unrecorded
                                                run attempt (wave close)
Exit: 0 pass · 1 finding, or an `--append` refusal (nothing is written) ·
2 usage · 3 could not run (git or gh unavailable, the API unreachable, or a run
list missing the fields this reads) — never a verdict.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, replace
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LEDGER = "docs/testing/devnet-e2e-ledger.tsv"

HEADER = ("workflow", "run_id", "attempt", "event", "head_sha", "started_at",
          "conclusion", "class", "secs", "markers", "compile_secs",
          "noncompile_secs", "clean", "verdict")
HEADER_LINE = "\t".join(HEADER)

# Keyed on workflow FILE (D167 §4). `job` is the one job whose runner and log
# the line is built from; `step` is the job-log group header that bounds the
# runtime clock (`scripts/e2e-devnet.sh`'s timer starts inside that step).
WORKFLOWS: dict[str, dict[str, str]] = {
    "devnet-e2e-cron.yml": {
        "job": "devnet-e2e-scheduled",
        "step": "Run ./scripts/e2e-devnet.sh",
    },
}
WORKFLOW = "devnet-e2e-cron.yml"

MIN_NODES = 14                       # §2 R4 — P16's evidence-backed working size
MAX_NONCOMPILE_CS = 900 * 100        # §2 R3 — 15 min, in centiseconds
REQUIRED_STREAK = 20                 # §2 R4
STALE_AFTER = dt.timedelta(days=7, hours=12)   # §2 R5 — see the docstring

OFFLINE_TAGS = ("EDITED", "DUPLICATE", "COUNT", "FORMAT", "UNBORN", "SHALLOW")
ONLINE_TAGS = ("LAG", "STALE-SCHEDULE", "MISMATCH")

NONE = "-"
UNMEASURED = "unmeasured"
ABSENT = "absent"
LOG_EXPIRED = "log-expired"

CONCLUSIONS = frozenset({"success", "failure", "cancelled", "skipped", "timed_out",
                         "action_required", "neutral", "stale", "startup_failure"})

# The verdict grammar, from `verdict()` in scripts/e2e-devnet.sh. A line that
# LOOKS like a verdict (VERDICT_LIKE) but fails the grammar is a format this
# script does not know, and `--append` refuses rather than write `absent` for
# a verdict that existed.
VERDICT_RE = re.compile(
    r"e2e-devnet: (?P<state>PASS|FAIL|PENDING) commit=(?P<commit>\S+) "
    r"nodes=(?P<nodes>\S+) suites_run=(?P<suites>[0-9]+) "
    r"failed=\[(?P<failed>[^\]\s]*)\] pending=\[(?P<pending>[^\]\s]*)\] "
    r"secs=(?P<secs>[0-9]+) anvil=(?P<anvil>\S+) evidence=(?P<evidence>\S(?:.*\S)?)")
VERDICT_LIKE = re.compile(r"e2e-devnet: (?:PASS|FAIL|PENDING) commit=")

# cargo's own `util::elapsed`: `{m}m {ss}s` at or over a minute, `{s}.{cc}s`
# under it. Matched on the ANSI-stripped, whitespace-stripped line.
FINISHED_RE = re.compile(
    r"Finished `[^`]+` profile \[[^\]]*\] target\(s\) in "
    r"(?:(?P<min>[0-9]+)m (?P<minsec>[0-9]{2})s|(?P<sec>[0-9]+)\.(?P<cs>[0-9]{2})s)")

LOG_PREFIX = re.compile(r"^\ufeff?(?:[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:"
                        r"[0-9]{2}(?:\.[0-9]+)?Z ?)?")
ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")

TIMESTAMP_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")
DECIMAL_RE = re.compile(r"(?P<whole>[0-9]+)\.(?P<frac>[0-9]{2})")
MARKERS_RE = re.compile(r"(?P<found>[0-9]+)/(?P<expected>[0-9]+)")

MAX_SHOWN = 120

# Variables that would point `git -C <repo>` at some other repository — set,
# for instance, when this runs inside a git hook.
GIT_LOCATION_VARS = ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE",
                     "GIT_OBJECT_DIRECTORY", "GIT_ALTERNATE_OBJECT_DIRECTORIES",
                     "GIT_COMMON_DIR", "GIT_NAMESPACE")


class CouldNotRun(Exception):
    """A tool or service this mode needs is unavailable. Exit 3, never a verdict."""


class Refusal(Exception):
    """`--append` will not write a permanent line from an answer it cannot trust."""

    def __init__(self, kind: str, message: str) -> None:
        super().__init__(message)
        self.kind = kind


@dataclass(frozen=True)
class Finding:
    tag: str
    where: str
    message: str

    def render(self) -> str:
        return f"::error::check-devnet-ledger [{self.tag}] {self.where}: {self.message}"


def shown(text: str | None) -> str:
    """A line for a message: tabs made visible, long lines cut."""
    if text is None:
        return "(absent)"
    text = text.replace("\t", " | ")
    return text if len(text) <= MAX_SHOWN else text[:MAX_SHOWN] + " …"


def fmt_cs(cs: int) -> str:
    return f"{cs // 100}.{cs % 100:02d}"


def parse_cs(text: str) -> int | None:
    m = DECIMAL_RE.fullmatch(text)
    return int(m["whole"]) * 100 + int(m["frac"]) if m else None


# ── the runtime derivation (§2 R3) ──────────────────────────────────────────

@dataclass(frozen=True)
class Derived:
    verdict: str
    secs: str
    markers: str
    compile_secs: str
    noncompile_secs: str


REFUSED_FIELDS = Derived(NONE, NONE, NONE, NONE, NONE)


class LogShapeError(Exception):
    """The job log does not have the shape this derivation is written against."""


def derive_from_log(text: str, step_header: str) -> Derived:
    """The verdict line and the runtime fields, from one job log.

    Raises LogShapeError instead of guessing: whatever this returns becomes a
    line that can never be edited.
    """
    raws: list[str] = []
    plains: list[str] = []
    for line in text.split("\n"):
        raw = LOG_PREFIX.sub("", line.rstrip("\r"), count=1)
        raws.append(raw)
        plains.append(ANSI_RE.sub("", raw).strip())

    want = "##[group]" + step_header
    starts = [i for i, p in enumerate(plains) if p == want]
    if len(starts) != 1:
        raise LogShapeError(f"expected exactly one `{want}` step header in the job "
                            f"log, found {len(starts)}")
    start = starts[0]
    end = next((j for j in range(start + 1, len(plains))
                if plains[j].startswith("##[group]Run ") or plains[j] == "Post job cleanup."),
               len(plains))

    candidates = [j for j in range(start + 1, end) if VERDICT_LIKE.match(raws[j])]
    if len(candidates) > 1:
        raise LogShapeError(f"the step carries {len(candidates)} verdict-shaped lines; "
                            f"exactly one is written by scripts/e2e-devnet.sh")
    if candidates and not VERDICT_RE.fullmatch(raws[candidates[0]]):
        raise LogShapeError(f"a verdict-shaped line does not match the grammar this "
                            f"script knows: {shown(raws[candidates[0]])}")

    stop = candidates[0] if candidates else end
    marker_cs: list[int] = []
    for j in range(start + 1, stop):
        m = FINISHED_RE.fullmatch(plains[j])
        if m is None:
            continue
        if m["min"] is not None:
            marker_cs.append((int(m["min"]) * 60 + int(m["minsec"])) * 100)
        else:
            marker_cs.append(int(m["sec"]) * 100 + int(m["cs"]))

    if not candidates:
        return Derived(ABSENT, NONE, NONE, NONE, UNMEASURED)
    verdict = raws[candidates[0]]
    v = VERDICT_RE.fullmatch(verdict)
    if v is None:                      # unreachable: the grammar was checked above
        raise LogShapeError(f"verdict line stopped matching its grammar: {shown(verdict)}")
    secs = int(v["secs"])
    expected = 1 + int(v["suites"])
    compile_cs = sum(marker_cs)
    noncompile_cs = secs * 100 - compile_cs
    measured = len(marker_cs) == expected and noncompile_cs >= 0
    return Derived(verdict, str(secs), f"{len(marker_cs)}/{expected}", fmt_cs(compile_cs),
                   fmt_cs(noncompile_cs) if measured else UNMEASURED)


# ── one ledger line ─────────────────────────────────────────────────────────

@dataclass(frozen=True)
class Record:
    lineno: int
    workflow: str
    run_id: int
    attempt: int
    event: str
    head_sha: str
    started_at: str
    conclusion: str
    klass: str
    secs: str
    markers: str
    compile_secs: str
    noncompile_secs: str
    clean: str
    verdict: str

    @property
    def key(self) -> tuple[str, int, int]:
        return (self.workflow, self.run_id, self.attempt)

    def line(self) -> str:
        return "\t".join((self.workflow, str(self.run_id), str(self.attempt), self.event,
                          self.head_sha, self.started_at, self.conclusion, self.klass,
                          self.secs, self.markers, self.compile_secs,
                          self.noncompile_secs, self.clean, self.verdict))


def parse_record(line: str, lineno: int) -> tuple[Record | None, list[str]]:
    """A Record, or None with every reason the line is not one (FORMAT)."""
    fields = line.split("\t")
    if len(fields) != len(HEADER):
        return None, [f"{len(fields)} tab-separated field(s), the header has {len(HEADER)}: "
                      f"{shown(line)}"]
    (workflow, run_id, attempt, event, head_sha, started_at, conclusion, klass,
     secs, markers, compile_secs, noncompile, clean, verdict) = fields
    bad: list[str] = []
    if any(f != f.strip() or not f for f in fields):
        bad.append("a field is empty or carries surrounding whitespace")
    if workflow not in WORKFLOWS:
        bad.append(f"workflow {workflow!r} is not one this checker knows how to judge "
                   f"(D167 §4: widening the ledger is a ruling)")
    if not re.fullmatch(r"[1-9][0-9]{0,19}", run_id):
        bad.append(f"run_id {run_id!r} is not a positive integer")
    if not re.fullmatch(r"[1-9][0-9]{0,3}", attempt):
        bad.append(f"attempt {attempt!r} is not a positive integer")
    if not re.fullmatch(r"[a-z_]{1,40}", event):
        bad.append(f"event {event!r} is not a GitHub event name")
    if not re.fullmatch(r"[0-9a-f]{40}", head_sha):
        bad.append(f"head_sha {head_sha!r} is not a full 40-hex commit id")
    if not TIMESTAMP_RE.fullmatch(started_at):
        bad.append(f"started_at {started_at!r} is not YYYY-MM-DDTHH:MM:SSZ")
    else:
        try:
            dt.datetime.strptime(started_at, "%Y-%m-%dT%H:%M:%SZ")
        except ValueError:
            bad.append(f"started_at {started_at!r} is not a real instant")
    if conclusion not in CONCLUSIONS:
        bad.append(f"conclusion {conclusion!r} is not a GitHub run conclusion")
    if clean not in ("yes", "no"):
        bad.append(f"clean {clean!r} is neither `yes` nor `no`")

    if klass == "refused":
        if (secs, markers, compile_secs, noncompile, verdict) != (NONE,) * 5:
            bad.append("a refused line carries runtime or verdict fields; a job no "
                       "runner took has none")
    elif klass == "executed":
        if verdict in (ABSENT, LOG_EXPIRED):
            if (secs, markers, compile_secs, noncompile) != (NONE, NONE, NONE, UNMEASURED):
                bad.append(f"verdict `{verdict}` must carry secs/markers/compile_secs "
                           f"`-` and noncompile_secs `{UNMEASURED}`")
        else:
            v = VERDICT_RE.fullmatch(verdict)
            if v is None:
                bad.append(f"verdict is not a verbatim `e2e-devnet:` line, `{ABSENT}` or "
                           f"`{LOG_EXPIRED}`: {shown(verdict)}")
            else:
                if secs != v["secs"]:
                    bad.append(f"secs {secs!r} differs from the verdict's secs={v['secs']}")
                mk = MARKERS_RE.fullmatch(markers)
                comp = parse_cs(compile_secs)
                if mk is None:
                    bad.append(f"markers {markers!r} is not found/expected")
                elif int(mk["expected"]) != 1 + int(v["suites"]):
                    bad.append(f"markers expects {mk['expected']} compile invocation(s); "
                               f"suites_run={v['suites']} means {1 + int(v['suites'])}")
                if comp is None:
                    bad.append(f"compile_secs {compile_secs!r} is not a two-decimal number")
                if mk is not None and comp is not None and re.fullmatch(r"[0-9]+", secs):
                    non = int(secs) * 100 - comp
                    measured = int(mk["found"]) == int(mk["expected"]) and non >= 0
                    want = fmt_cs(non) if measured else UNMEASURED
                    if noncompile != want:
                        bad.append(f"noncompile_secs {noncompile!r} is not what secs and "
                                   f"compile_secs derive ({want})")
                commit = v["commit"]
                if not re.fullmatch(r"[0-9a-f]{7,40}", commit) or not head_sha.startswith(commit):
                    bad.append(f"the verdict's commit={commit} is not a prefix of head_sha "
                               f"— this verdict line belongs to another run")
    else:
        bad.append(f"class {klass!r} is neither `executed` nor `refused`")

    if bad:
        return None, bad
    return Record(lineno, workflow, int(run_id), int(attempt), event, head_sha, started_at,
                  conclusion, klass, secs, markers, compile_secs, noncompile, clean,
                  verdict), []


def unclean_reasons(r: Record) -> list[str]:
    """Every §2 R4 condition the record fails. Empty means clean.

    One function, called by `--append` to WRITE `clean` and by the check to
    AUDIT it, so the two can only disagree through a hand edit.
    """
    why: list[str] = []
    if r.klass != "executed":
        why.append("refused (no runner was ever assigned)")
    if r.conclusion != "success":
        why.append(f"conclusion={r.conclusion}")
    v = VERDICT_RE.fullmatch(r.verdict)
    if v is None:
        why.append({ABSENT: "no verdict line in the log",
                    LOG_EXPIRED: "the job log expired before the append"}.get(r.verdict,
                                                                              "no verdict"))
    else:
        if v["state"] != "PASS":
            why.append(f"verdict {v['state']}")
        if not re.fullmatch(r"[0-9]+", v["nodes"]) or int(v["nodes"]) < MIN_NODES:
            why.append(f"nodes={v['nodes']} (clean needs >= {MIN_NODES})")
        if v["failed"]:
            why.append(f"failed=[{v['failed']}]")
        if v["pending"]:
            why.append(f"pending=[{v['pending']}]")
        if int(v["suites"]) < 1:
            why.append("suites_run=0")
        if int(v["secs"]) <= 0:
            why.append("secs=0")
    non = parse_cs(r.noncompile_secs)
    if non is None:
        why.append("non-compile runtime unmeasured")
    elif non > MAX_NONCOMPILE_CS:
        why.append(f"non-compile runtime {r.noncompile_secs} s > {MAX_NONCOMPILE_CS // 100} s")
    return why


def streak(records: list[Record]) -> tuple[int, list[Record]]:
    """The current run of consecutive clean scheduled attempt-1 runs (§2 R4)."""
    count, members = 0, []
    for r in sorted(records, key=lambda x: (x.started_at, x.run_id, x.attempt)):
        if r.klass == "refused":
            continue                       # neither extends nor breaks
        if unclean_reasons(r):
            count, members = 0, []         # any executed non-clean attempt resets
            continue
        if r.event == "schedule" and r.attempt == 1:
            count += 1
            members.append(r)
        # a clean dispatch or re-run is recorded and does not count
    return count, members


def split_lines(text: str) -> list[str]:
    lines = text.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    return lines


def check_content(text: str, where: str) -> tuple[list[Finding], list[Record]]:
    """FORMAT, DUPLICATE and COUNT over one revision of the ledger."""
    findings: list[Finding] = []
    records: list[Record] = []
    if text.startswith("\ufeff"):
        findings.append(Finding("FORMAT", where, "the file starts with a byte-order mark"))
    if "\r" in text:
        findings.append(Finding("FORMAT", where, "the file carries a carriage return; "
                                                 "lines end in LF only"))
    if "\ufffd" in text:
        findings.append(Finding("FORMAT", where, "the file is not valid UTF-8 (it carries "
                                                 "U+FFFD, the mark of an undecodable byte)"))
    if text and not text.endswith("\n"):
        findings.append(Finding("FORMAT", where, "the file does not end with a newline, so "
                                                 "an append would fuse two lines"))
    lines = split_lines(text)
    if not lines:
        findings.append(Finding("FORMAT", where, "the file is empty; line 1 must be the header"))
        return findings, records
    if lines[0].lstrip("\ufeff") != HEADER_LINE:
        findings.append(Finding("FORMAT", f"{where}:1", f"line 1 is not the header "
                                                        f"{HEADER_LINE!r}: {shown(lines[0])}"))
    seen: dict[tuple[str, int, int], int] = {}
    for lineno, line in enumerate(lines[1:], start=2):
        rec, problems = parse_record(line, lineno)
        for p in problems:
            findings.append(Finding("FORMAT", f"{where}:{lineno}", p))
        if rec is None:
            continue
        if rec.key in seen:
            findings.append(Finding("DUPLICATE", f"{where}:{lineno}",
                                    f"run {rec.run_id} attempt {rec.attempt} of {rec.workflow} "
                                    f"is already recorded at line {seen[rec.key]}"))
        else:
            seen[rec.key] = lineno
        why = unclean_reasons(rec)
        if rec.clean == "yes" and why:
            findings.append(Finding("COUNT", f"{where}:{lineno}",
                                    f"run {rec.run_id} attempt {rec.attempt} is COUNTED CLEAN "
                                    f"but is not: {'; '.join(why)}"))
        elif rec.clean == "no" and not why:
            findings.append(Finding("COUNT", f"{where}:{lineno}",
                                    f"run {rec.run_id} attempt {rec.attempt} is marked NOT "
                                    f"clean but meets every §2 R4 condition — the writer and "
                                    f"this checker disagree, which only a hand edit explains"))
        records.append(rec)
    return findings, records


# ── the offline walk (§2 R5) ────────────────────────────────────────────────

def git_env(extra: dict[str, str] | None = None) -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if k not in GIT_LOCATION_VARS}
    env["GIT_TERMINAL_PROMPT"] = "0"
    if extra:
        env.update(extra)
    return env


def git(repo: Path, *args: str, env: dict[str, str] | None = None) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(("git", "-C", str(repo), *args), capture_output=True,
                              env=env or git_env())
    except FileNotFoundError as exc:
        raise CouldNotRun("git is not installed") from exc


def classify_edit(earlier: list[str], later: list[str], i: int) -> str:
    was, now = earlier[i], later[i]
    was_survives, now_is_known = was in later, now in earlier
    if was_survives and now_is_known:
        return "REORDERED"
    if was_survives:
        return "INSERTED ahead of it"
    if now_is_known:
        return "DELETED"
    return "REWRITTEN"


def walk(states: list[tuple[str, list[str] | None]],
         rel: str = LEDGER) -> tuple[list[Finding], int]:
    """Prefix-extension between adjacent states. Returns (EDITED findings, pinned)."""
    findings: list[Finding] = []
    pinned = 0
    for (el, earlier), (ll, later) in zip(states, states[1:]):
        if earlier is None:
            continue
        if later is None:
            findings.append(Finding("EDITED", rel,
                                    f"the ledger was DELETED between {el} and {ll}: all "
                                    f"{len(earlier)} of its line(s) are gone"))
            continue
        hit = False
        for i in range(min(len(earlier), len(later))):
            pinned += 1
            if earlier[i] != later[i]:
                findings.append(Finding(
                    "EDITED", f"{rel}:{i + 1}",
                    f"line {i + 1} {classify_edit(earlier, later, i)} between {el} and {ll} "
                    f"— was: {shown(earlier[i])} — now: {shown(later[i])}"))
                hit = True
                break
        if not hit and len(later) < len(earlier):
            findings.append(Finding(
                "EDITED", f"{rel}:{len(later) + 1}",
                f"line {len(later) + 1} DELETED (truncated) between {el} and {ll} — was: "
                f"{shown(earlier[len(later)])}"))
    return findings, pinned


def check_offline(repo: Path, rel: str = LEDGER,
                  env: dict[str, str] | None = None) -> tuple[list[Finding], dict]:
    findings: list[Finding] = []
    stats: dict = {"states": 0, "birth": None, "pinned": 0, "records": []}

    shallow = git(repo, "rev-parse", "--is-shallow-repository", env=env)
    if shallow.returncode != 0:
        raise CouldNotRun(f"`git rev-parse` failed in {repo}: "
                          f"{shallow.stderr.decode('utf-8', 'replace').strip()[:300]}")
    if shallow.stdout.decode().strip() == "true":
        findings.append(Finding("SHALLOW", rel,
                                "this is a shallow clone: its grafted root reads as the "
                                "ledger's birth, so the walk would silently re-baseline onto "
                                "whatever history was fetched. Check from a full clone "
                                "(`fetch-depth: 0` on a runner)"))

    has_head = git(repo, "rev-parse", "--verify", "--quiet", "HEAD^{commit}",
                   env=env).returncode == 0
    revs: list[str] = []
    if has_head:
        # --topo-order: a parent always precedes its child in the walk, even
        # where commit dates are skewed — the comparison is between REVISIONS,
        # so their order is structural, never chronological.
        listed = git(repo, "rev-list", "--reverse", "--topo-order", "HEAD", "--", rel, env=env)
        if listed.returncode != 0:
            raise CouldNotRun(f"`git rev-list` failed: "
                              f"{listed.stderr.decode('utf-8', 'replace').strip()[:300]}")
        revs = listed.stdout.decode().split()

    path = repo / rel
    worktree: list[str] | None = None
    if path.is_file():
        text = path.read_bytes().decode("utf-8", "replace")   # U+FFFD reds as FORMAT
        content, records = check_content(text, rel)
        findings.extend(content)
        stats["records"] = records
        worktree = split_lines(text)

    if not revs:
        if worktree is None:
            findings.append(Finding("UNBORN", rel, "the ledger does not exist and no commit in "
                                                   "HEAD's history adds it"))
        else:
            checked = len([f for f in findings if f.tag in ("FORMAT", "DUPLICATE", "COUNT")])
            findings.append(Finding(
                "UNBORN", rel,
                f"no commit in HEAD's history adds this file, so the append-only walk pinned "
                f"ZERO line comparisons and nothing about its history is asserted. Its "
                f"{len(worktree)} working-tree line(s) were checked as an UNCOMMITTED ADDITION: "
                f"FORMAT, DUPLICATE and COUNT reported {checked} problem(s). It stays red "
                f"until a commit adds the ledger (D167 §2 R5: pinned == 0 is a hard error)"))
        return findings, stats

    states: list[tuple[str, list[str] | None]] = []
    for sha in revs:
        exists = git(repo, "cat-file", "-e", f"{sha}:{rel}", env=env).returncode == 0
        if not exists:
            states.append((sha[:7], None))
            continue
        blob = git(repo, "show", f"{sha}:{rel}", env=env)
        if blob.returncode != 0:
            raise CouldNotRun(f"`git show {sha[:7]}:{rel}` failed")
        states.append((sha[:7], split_lines(blob.stdout.decode("utf-8", "replace"))))
    states.append(("the working tree", worktree))
    stats["states"] = len(states)
    stats["birth"] = revs[0]

    edited, pinned = walk(states, rel)
    findings.extend(edited)
    stats["pinned"] = pinned
    if pinned == 0 and not edited:
        findings.append(Finding(
            "UNBORN", rel,
            f"the walk pinned ZERO line comparisons across {len(states)} state(s) from birth "
            f"{revs[0][:7]} — a committed revision with no lines pins nothing, so a green "
            f"verdict would assert nothing"))
    return findings, stats


def run_offline() -> int:
    try:
        findings, stats = check_offline(ROOT)
    except CouldNotRun as exc:
        print(f"::error::check-devnet-ledger: could not run: {exc}")
        return 3
    for f in findings:
        print(f.render())
    if findings:
        tags = sorted({f.tag for f in findings})
        print(f"check-devnet-ledger: FAILED with {len(findings)} finding(s) "
              f"[{', '.join(tags)}]. The ledger is append-only (D167 §2 R1-R5): add lines "
              f"with --append, never edit one.")
        return 1
    records = stats["records"]
    executed = sum(1 for r in records if r.klass == "executed")
    count, members = streak(records)
    newest = f"; newest counted run {members[-1].run_id}" if members else ""
    print(f"check-devnet-ledger: ok — {LEDGER} is append-only across {stats['states']} "
          f"state(s) walked from derived birth {stats['birth'][:7]}; {len(records)} record(s) "
          f"({executed} executed, {len(records) - executed} refused); {stats['pinned']} pinned "
          f"line comparison(s); streak {count}/{REQUIRED_STREAK} consecutive clean scheduled "
          f"run(s){newest}")
    return 0


# ── the API (GET only) ──────────────────────────────────────────────────────

class GhApi:
    """Every request is `gh api --method GET`. Nothing in this file can write to GitHub."""

    # A transport failure or a 5xx is asked again, twice, before it is reported.
    # A retry that answers 200 is as durable as a first answer; one that keeps
    # failing still reaches the caller as "no status", which `--append` refuses
    # to write. Measured need: this lane's own first real append lost one log to
    # a connection failure on the blob-storage hop.
    TRIES = 3
    PAUSE_SECS = 5

    def __init__(self, slug: str, runner=subprocess.run, sleeper=time.sleep) -> None:
        self.slug = slug
        self.runner = runner          # both injectable, so --self-test exercises get() itself
        self.sleeper = sleeper

    def get(self, endpoint: str) -> tuple[int | None, bytes, str]:
        for attempt in range(1, self.TRIES + 1):
            status, body, detail = self._once(endpoint)
            if status is not None and status < 500:
                return status, body, detail
            if attempt < self.TRIES:
                self.sleeper(self.PAUSE_SECS * attempt)
        return status, body, f"{detail} (after {self.TRIES} tries)"

    def _once(self, endpoint: str) -> tuple[int | None, bytes, str]:
        try:
            proc = self.runner(("gh", "api", "--method", "GET", endpoint),
                               capture_output=True, timeout=180)
        except FileNotFoundError as exc:
            raise CouldNotRun("gh is not installed") from exc
        except subprocess.TimeoutExpired:
            return None, b"", "timed out after 180 s"
        if proc.returncode == 0:
            return 200, proc.stdout, ""
        err = scrub_detail(proc.stderr.decode("utf-8", "replace").strip())
        m = re.search(r"HTTP ([0-9]{3})", err)
        return (int(m.group(1)) if m else None), proc.stdout, err[:300]


# A job-log GET is answered by a redirect to a SIGNED blob-storage URL, and when
# the second hop fails, gh's error text quotes that URL — signature and all.
# Measured 2026-09-13 on this lane's own first `--append`: a transient failure
# fetching one log printed a `sig=` token into the refusal. Every query string is
# cut before any API detail reaches a message, a log or a terminal.
SIGNED_QUERY_RE = re.compile(r"(https?://[^\s?\"']+)\?[^\s\"')]*")


def scrub_detail(text: str) -> str:
    return SIGNED_QUERY_RE.sub(r"\1?<query redacted>", text)


def origin_slug() -> str:
    proc = git(ROOT, "remote", "get-url", "origin")
    url = proc.stdout.decode().strip()
    m = re.fullmatch(r"(?:https://github\.com/|git@github\.com:|ssh://git@github\.com/)"
                     r"([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+?)(?:\.git)?/?", url)
    if proc.returncode != 0 or m is None:
        raise CouldNotRun("the `origin` remote is not a github.com repository URL, so there "
                          "is no API to ask")
    return f"{m.group(1)}/{m.group(2)}"


def get_json(api, endpoint: str) -> dict:
    status, body, detail = api.get(endpoint)
    if status != 200:
        raise CouldNotRun(f"GET {endpoint} answered {status or 'no HTTP status'}: {detail}")
    try:
        data = json.loads(body)
    except ValueError as exc:
        raise CouldNotRun(f"GET {endpoint} did not answer JSON") from exc
    if not isinstance(data, dict):
        raise CouldNotRun(f"GET {endpoint} answered a JSON {type(data).__name__}, not an object")
    return data


def _require_run_shape(run: object, endpoint: str) -> dict:
    ok = (isinstance(run, dict)
          and isinstance(run.get("id"), int) and run["id"] > 0
          and isinstance(run.get("event"), str)
          and isinstance(run.get("status"), str)
          and isinstance(run.get("head_sha"), str)
          and re.fullmatch(r"[0-9a-f]{40}", run["head_sha"]) is not None
          and isinstance(run.get("run_attempt"), int) and run["run_attempt"] >= 1
          and isinstance(run.get("created_at"), str)
          and TIMESTAMP_RE.fullmatch(run["created_at"]) is not None
          and isinstance(run.get("run_started_at"), str)
          and TIMESTAMP_RE.fullmatch(run["run_started_at"]) is not None
          and (run.get("status") != "completed" or run.get("conclusion") in CONCLUSIONS))
    if not ok:
        raise CouldNotRun(f"GET {endpoint} returned a run without the fields this check reads "
                          f"(id, event, status, conclusion, head_sha, run_attempt, created_at, "
                          f"run_started_at): {shown(json.dumps(run)[:400])}")
    return run


def list_runs(api, workflow: str) -> list[dict]:
    runs: list[dict] = []
    page = 1
    while True:
        endpoint = f"repos/{api.slug}/actions/workflows/{workflow}/runs?per_page=100&page={page}"
        data = get_json(api, endpoint)
        batch, total = data.get("workflow_runs"), data.get("total_count")
        if not isinstance(batch, list) or not isinstance(total, int):
            raise CouldNotRun(f"GET {endpoint} carries no workflow_runs/total_count")
        runs.extend(_require_run_shape(r, endpoint) for r in batch)
        if not batch or len(runs) >= total:
            break
        page += 1
        if page > 200:
            raise CouldNotRun(f"the run list for {workflow} did not end after 200 pages")
    return runs


def completed_attempts(run: dict) -> range:
    """Attempts that have finished. A re-run can only be made of a completed run,
    so every attempt before the latest is complete whatever the run's status."""
    last = run["run_attempt"] if run["status"] == "completed" else run["run_attempt"] - 1
    return range(1, last + 1)


def build_record(api, workflow: str, run: dict, attempt: int, lineno: int) -> Record:
    """One permanent line, or a Refusal. Never a guess."""
    spec = WORKFLOWS[workflow]
    rid = run["id"]
    if attempt == run["run_attempt"]:
        att = run
    else:
        endpoint = f"repos/{api.slug}/actions/runs/{rid}/attempts/{attempt}"
        att = _require_run_shape(get_json(api, endpoint), endpoint)
        if att["id"] != rid or att["run_attempt"] != attempt or att["status"] != "completed":
            raise Refusal("API-SHAPE", f"run {rid} attempt {attempt}: the attempt endpoint "
                                       f"answered a different or unfinished attempt")
    endpoint = f"repos/{api.slug}/actions/runs/{rid}/attempts/{attempt}/jobs?per_page=100"
    jobs = get_json(api, endpoint).get("jobs")
    if not isinstance(jobs, list) or len(jobs) > 1 or any(
            not isinstance(j, dict) or j.get("name") != spec["job"] for j in jobs):
        raise Refusal("JOB-SHAPE", f"run {rid} attempt {attempt}: expected at most one job "
                                   f"named {spec['job']!r}; the line format is built from "
                                   f"exactly one job's runner and log")
    runner = (jobs[0].get("runner_name") or "") if jobs else ""
    if not isinstance(runner, str):
        raise Refusal("JOB-SHAPE", f"run {rid} attempt {attempt}: runner_name is not a string")
    # §1.6: `runner_name`, never `steps` — a real red whose log expired shows
    # `steps == []` with a runner, exactly like a refusal without one.
    klass = "executed" if runner else "refused"

    if klass == "refused":
        derived = REFUSED_FIELDS
    else:
        job_id = jobs[0].get("id")
        status, body, detail = api.get(f"repos/{api.slug}/actions/jobs/{job_id}/logs")
        if status == 200:
            try:
                derived = derive_from_log(body.decode("utf-8"), spec["step"])
            except (UnicodeDecodeError, LogShapeError) as exc:
                raise Refusal("LOG-SHAPE", f"run {rid} attempt {attempt}, job {job_id}: {exc}") \
                    from exc
        elif status == 410:
            derived = Derived(LOG_EXPIRED, NONE, NONE, NONE, UNMEASURED)
        else:
            raise Refusal("LOG-UNAVAILABLE",
                          f"run {rid} attempt {attempt}, job {job_id}: its log answered "
                          f"{status or 'nothing'} ({detail or 'no detail'}). Only 410 Gone is a "
                          f"durable answer; anything else may be transient, and a transient "
                          f"answer must never become a permanent line. Re-run --append later")
        if derived.verdict == ABSENT and att["conclusion"] == "success":
            raise Refusal("LOG-SHAPE", f"run {rid} attempt {attempt}: the job concluded success "
                                       f"but its log carries no verdict line — a contradiction "
                                       f"this script will not record")

    draft = Record(lineno, workflow, rid, attempt, att["event"], att["head_sha"],
                   att["run_started_at"], att["conclusion"], klass, derived.secs,
                   derived.markers, derived.compile_secs, derived.noncompile_secs, "no",
                   derived.verdict)
    clean = "no" if unclean_reasons(draft) else "yes"
    rec = replace(draft, clean=clean)
    _, problems = parse_record(rec.line(), lineno)
    if problems:
        raise Refusal("SELF-CHECK", f"run {rid} attempt {attempt}: the line this script built "
                                    f"fails its own FORMAT check: {'; '.join(problems)}")
    return rec


def plan_append(ledger_text: str, api, workflow: str = WORKFLOW) -> list[Record]:
    """The lines `--append` would add, oldest first. Raises Refusal or CouldNotRun."""
    content, records = check_content(ledger_text, LEDGER)
    if content:
        raise Refusal("LEDGER", "the ledger fails its own content checks, so nothing is "
                                "appended to it: " + " | ".join(f.render() for f in content[:5]))
    recorded = {r.key for r in records}
    next_line = len(split_lines(ledger_text)) + 1
    new: list[Record] = []
    for run in sorted(list_runs(api, workflow), key=lambda r: (r["created_at"], r["id"])):
        for attempt in completed_attempts(run):
            if (workflow, run["id"], attempt) in recorded:
                continue
            new.append(build_record(api, workflow, run, attempt, 0))
    new.sort(key=lambda r: (r.started_at, r.run_id, r.attempt))
    return [replace(r, lineno=next_line + i) for i, r in enumerate(new)]


# ── the online check (§2 R5) ────────────────────────────────────────────────

def check_online(ledger_text: str, api, now: dt.datetime,
                 workflow: str = WORKFLOW) -> tuple[list[Finding], dict]:
    content, records = check_content(ledger_text, LEDGER)
    stats: dict = {"runs": 0, "completed": 0, "in_flight": [], "newest": None,
                   "records": records, "unlisted": []}
    if content:
        return content, stats          # a ledger failing its own checks is not judged
    findings: list[Finding] = []
    by_key = {r.key: r for r in records}
    runs = list_runs(api, workflow)
    stats["runs"] = len(runs)
    listed = {r["id"] for r in runs}
    for run in sorted(runs, key=lambda r: (r["created_at"], r["id"])):
        if run["status"] == "completed":
            stats["completed"] += 1
        else:
            stats["in_flight"].append(run["id"])
        for attempt in completed_attempts(run):
            rec = by_key.get((workflow, run["id"], attempt))
            if rec is None:
                findings.append(Finding(
                    "LAG", LEDGER,
                    f"completed run {run['id']} attempt {attempt} ({run['event']}, created "
                    f"{run['created_at']}, head {run['head_sha'][:7]}"
                    + (f", conclusion {run['conclusion']}" if attempt == run["run_attempt"]
                       else "")
                    + ") has no line — run --append at wave close"))
                continue
            diffs = []
            if rec.event != run["event"]:
                diffs.append(f"event {rec.event} vs API {run['event']}")
            if rec.head_sha != run["head_sha"]:
                diffs.append(f"head_sha {rec.head_sha[:12]} vs API {run['head_sha'][:12]}")
            if attempt == run["run_attempt"]:
                if rec.conclusion != run["conclusion"]:
                    diffs.append(f"conclusion {rec.conclusion} vs API {run['conclusion']}")
                if rec.started_at != run["run_started_at"]:
                    diffs.append(f"started_at {rec.started_at} vs API {run['run_started_at']}")
            if diffs:
                findings.append(Finding("MISMATCH", f"{LEDGER}:{rec.lineno}",
                                        f"run {rec.run_id} attempt {rec.attempt} disagrees with "
                                        f"the API: {'; '.join(diffs)}"))
    stats["unlisted"] = sorted({r.run_id for r in records if r.run_id not in listed})

    scheduled = [r for r in runs if r["event"] == "schedule"]
    if not scheduled:
        findings.append(Finding(
            "STALE-SCHEDULE", workflow,
            "the API lists NO scheduled run of this workflow at all. A public repository's "
            "schedule auto-disables after 60 days without activity, and a schedule that never "
            "fires extends no streak"))
    else:
        newest = max(scheduled, key=lambda r: (r["created_at"], r["id"]))
        created = dt.datetime.strptime(newest["created_at"], "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=dt.timezone.utc)
        age = now - created
        stats["newest"] = (newest["id"], newest["created_at"], age)
        if age > STALE_AFTER:
            findings.append(Finding(
                "STALE-SCHEDULE", workflow,
                f"the newest scheduled run, {newest['id']}, was created {newest['created_at']} "
                f"— {_age(age)} before {now.strftime('%Y-%m-%dT%H:%M:%SZ')}, past the weekly "
                f"cadence's {_age(STALE_AFTER)} allowance. Is the schedule disabled?"))
    return findings, stats


def _age(delta: dt.timedelta) -> str:
    total = int(delta.total_seconds())
    sign = "-" if total < 0 else ""
    total = abs(total)
    return f"{sign}{total // 86400} d {total % 86400 // 3600} h {total % 3600 // 60} m"


def utc_now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0)


def read_ledger_text() -> str | None:
    """The ledger's text, or None if it does not exist. Bytes that are not
    UTF-8 decode to U+FFFD, which check_content() names as FORMAT."""
    path = ROOT / LEDGER
    return path.read_bytes().decode("utf-8", "replace") if path.is_file() else None


def run_against_api() -> int:
    text = read_ledger_text()
    if text is None:
        print(f"::error::check-devnet-ledger: {LEDGER} does not exist; create it with exactly "
              f"the header line before asking the API what it lags")
        return 1
    now = utc_now()
    try:
        api = GhApi(origin_slug())
        findings, stats = check_online(text, api, now)
    except CouldNotRun as exc:
        print(f"::error::check-devnet-ledger --against-api: could not run: {exc}")
        return 3
    for f in findings:
        print(f.render())
    for rid in stats["unlisted"]:
        print(f"note: recorded run {rid} is not in the API's run list (a deleted run?) — "
              f"its line stays; the ledger is append-only")
    if stats["in_flight"]:
        print(f"note: {len(stats['in_flight'])} run(s) not yet completed, not judged: "
              f"{', '.join(map(str, stats['in_flight']))}")
    records = stats["records"]
    newest = stats["newest"]
    fresh = (f"newest scheduled run {newest[0]} created {newest[1]}, {_age(newest[2])} before "
             f"{now.strftime('%Y-%m-%dT%H:%M:%SZ')} (stale after {_age(STALE_AFTER)})"
             if newest else "no scheduled run listed")
    count, _ = streak(records)
    summary = (f"{stats['runs']} run(s) listed by the API ({stats['completed']} completed), "
               f"{len(records)} record(s) in the ledger; {fresh}; streak "
               f"{count}/{REQUIRED_STREAK}")
    if findings:
        tags = sorted({f.tag for f in findings})
        print(f"check-devnet-ledger --against-api: FAILED with {len(findings)} finding(s) "
              f"[{', '.join(tags)}] — {summary}")
        return 1
    print(f"check-devnet-ledger --against-api: ok — {summary}")
    return 0


def run_append() -> int:
    text = read_ledger_text()
    if text is None:
        print(f"::error::check-devnet-ledger --append: {LEDGER} does not exist. Create it "
              f"containing exactly this header line and a newline, then append:\n{HEADER_LINE}")
        return 1
    try:
        offline, _ = check_offline(ROOT)
        blocking = [f for f in offline if f.tag != "UNBORN"]
        if blocking:
            for f in blocking:
                print(f.render())
            print("check-devnet-ledger --append: refused — the ledger fails its offline check; "
                  "nothing is appended on top of a disturbed history")
            return 1
        api = GhApi(origin_slug())
        new = plan_append(text, api)
    except CouldNotRun as exc:
        print(f"::error::check-devnet-ledger --append: could not run: {exc}")
        return 3
    except Refusal as exc:
        print(f"::error::check-devnet-ledger --append: refused [{exc.kind}]: {exc}")
        return 1
    if not new:
        print(f"check-devnet-ledger --append: nothing to append — every completed run attempt "
              f"of {WORKFLOW} already has a line")
        return 0
    result = text + "".join(r.line() + "\n" for r in new)
    content, records = check_content(result, LEDGER)
    if content:
        for f in content:
            print(f.render())
        print("check-devnet-ledger --append: refused — the appended ledger would fail its own "
              "content checks; nothing was written")
        return 1
    tmp = (ROOT / LEDGER).with_name((ROOT / LEDGER).name + ".tmp")
    tmp.write_bytes(result.encode("utf-8"))
    os.replace(tmp, ROOT / LEDGER)
    for r in new:
        print(f"appended line {r.lineno}: run {r.run_id} attempt {r.attempt} {r.event} "
              f"{r.started_at} {r.klass} conclusion={r.conclusion} secs={r.secs} "
              f"markers={r.markers} compile_secs={r.compile_secs} "
              f"noncompile_secs={r.noncompile_secs} clean={r.clean}")
        if r.verdict != NONE:
            print(f"    {r.verdict}")
    count, _ = streak(records)
    print(f"check-devnet-ledger --append: appended {len(new)} line(s); {len(records)} record(s); "
          f"streak {count}/{REQUIRED_STREAK}. Commit {LEDGER} in the wave-close commit — the "
          f"offline check pins these lines only once a commit carries them")
    return 0


# ── recorded fixtures ───────────────────────────────────────────────────────
#
# THE REAL RUNS of devnet-e2e-cron.yml, as `GET .../workflows/devnet-e2e-cron.yml/
# runs` and each run's jobs answered on 2026-09-13, trimmed to the fields this
# file reads. The 40-hex values are FIXTURE LITERALS, NOT PINS: nothing here
# resolves them in git, so a history rewrite changes nothing this self-test
# asserts.
#   (run_id, conclusion, head_sha, created_at, job_id, runner_name, steps)
REAL_RUNS = (
    (31571938292, "failure", "3c8095a8f7819c0a9cb1d5d5f2de3de623ef2404",
     "2026-08-12T06:56:32Z", 94035605439, "GitHub Actions 1000000629", 9),
    (32221569300, "failure", "dc0bac80964172ea3a458cc1a495f003a32cd6f0",
     "2026-08-19T05:59:57Z", 95972874731, "", 0),
    (32936547060, "failure", "c2709ea5510f7589138e9db54565d0b2f60eb68c",
     "2026-08-26T06:03:52Z", 98078726504, "", 0),
    (33616516399, "success", "ae4e1673569952df1fbce8809b2c91721b9aed49",
     "2026-09-02T09:52:51Z", 100203493109, "GitHub Actions 1000000919", 11),
    (34338263485, "success", "34378906c36ca19a7d45a72e04cef56c09ad368b",
     "2026-09-09T10:04:44Z", 102422688930, "GitHub Actions 1000000964", 11),
)

# VERBATIM EXCERPTS of the three executed jobs' logs, same date: every
# non-checkout step header, the env echo, every compile marker, every test
# summary and the verdict line with its framing. The ~2 100 compiler and test
# lines between them are elided; the derivation reads none of them.
# job 94035605439: 27 of its 2178 log lines, verbatim
LOG_RED_20260812 = "\n".join((
    "\ufeff2026-08-12T06:56:37.7310382Z Current runner version: '2.336.0'",
    '2026-08-12T06:56:39.1242936Z ##[group]Run actions/checkout@v4',
    '2026-08-12T06:56:41.4621571Z ##[group]Run rustup show active-toolchain || rustup toolchain install',
    '2026-08-12T06:56:51.5297678Z ##[group]Run foundry-rs/foundry-toolchain@v1',
    '2026-08-12T06:56:56.4014648Z ##[group]Run ./scripts/e2e-devnet.sh',
    '2026-08-12T06:56:56.4061913Z   ANTSEAL_DEVNET_NODES: 5',
    '2026-08-12T06:56:56.4327801Z \x1b[36m==>\x1b[0m booting a devnet: 5 nodes (scripts/devnet/local-up)',
    '2026-08-12T07:10:03.6834667Z \x1b[1m\x1b[92m    Finished\x1b[0m `release` profile [optimized] target(s) in 13m 07s',
    '2026-08-12T07:17:18.0075681Z \x1b[1m\x1b[92m    Finished\x1b[0m `test` profile [unoptimized + debuginfo] target(s) in 7m 12s',
    '2026-08-12T07:17:24.5826553Z test result: FAILED. 0 passed; 6 failed; 0 ignored; 0 measured; 0 filtered out; finished in 6.53s',
    '2026-08-12T07:18:53.4132112Z \x1b[1m\x1b[92m    Finished\x1b[0m `test` profile [unoptimized + debuginfo] target(s) in 1m 28s',
    '2026-08-12T07:19:01.7893484Z test result: FAILED. 1 passed; 2 failed; 0 ignored; 0 measured; 0 filtered out; finished in 8.34s',
    '2026-08-12T07:19:08.4180648Z \x1b[1m\x1b[92m    Finished\x1b[0m `test` profile [unoptimized + debuginfo] target(s) in 6.58s',
    '2026-08-12T07:19:13.8683551Z test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 10 filtered out; finished in 1.72s',
    '2026-08-12T07:19:19.1421206Z test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 10 filtered out; finished in 1.97s',
    '2026-08-12T07:19:23.0329365Z test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 10 filtered out; finished in 2.56s',
    '2026-08-12T07:19:27.1484079Z test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 10 filtered out; finished in 2.80s',
    '2026-08-12T07:19:31.1700081Z test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 10 filtered out; finished in 2.70s',
    '2026-08-12T07:19:39.8965227Z test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 10 filtered out; finished in 2.40s',
    '2026-08-12T07:19:42.7259577Z test result: FAILED. 1 passed; 10 failed; 0 ignored; 0 measured; 0 filtered out; finished in 34.17s',
    '2026-08-12T07:19:47.6396523Z \x1b[1m\x1b[92m    Finished\x1b[0m `test` profile [unoptimized + debuginfo] target(s) in 4.86s',
    '2026-08-12T07:19:50.5010306Z test result: FAILED. 2 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 2.80s',
    '2026-08-12T07:19:50.5317003Z ',
    '2026-08-12T07:19:50.5318134Z e2e-devnet: FAIL commit=3c8095a nodes=5 suites_run=4 failed=[S6-S8,S17,S18,S19] pending=[] secs=1374 anvil=1.7.1 evidence=/home/runner/work/antseal/antseal/target/e2e-devnet/20260812T065656Z-3c8095a',
    '2026-08-12T07:19:52.5557718Z ##[error]Process completed with exit code 1.',
    '2026-08-12T07:19:52.5732461Z ##[group]Run actions/upload-artifact@v4',
    '2026-08-12T07:19:54.3747874Z Post job cleanup.',
)) + "\n"

# job 100203493109: 22 of its 2103 log lines, verbatim
LOG_GREEN_20260902 = "\n".join((
    "\ufeff2026-09-02T09:52:57.8270007Z Current runner version: '2.336.0'",
    '2026-09-02T09:53:01.6180097Z ##[group]Run rustup show active-toolchain || rustup toolchain install',
    '2026-09-02T09:53:17.0550742Z ##[group]Run ./scripts/e2e-devnet.sh --self-test',
    '2026-09-02T09:53:17.5825707Z   control (committed registry)                              -> e2e-devnet: PASS',
    '2026-09-02T09:53:17.5899316Z ##[group]Run ./scripts/e2e-devnet.sh',
    '2026-09-02T09:53:17.5938171Z   ANTSEAL_DEVNET_NODES: 14',
    '2026-09-02T09:53:17.6204144Z \x1b[36m==>\x1b[0m booting a devnet: 14 nodes (scripts/devnet/local-up)',
    '2026-09-02T10:06:27.6827348Z \x1b[1m\x1b[92m    Finished\x1b[0m `release` profile [optimized] target(s) in 13m 10s',
    '2026-09-02T10:13:52.4055414Z \x1b[1m\x1b[92m    Finished\x1b[0m `test` profile [unoptimized + debuginfo] target(s) in 7m 18s',
    '2026-09-02T10:15:26.2072773Z test result: ok. 6 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 93.76s',
    '2026-09-02T10:16:58.8351504Z \x1b[1m\x1b[92m    Finished\x1b[0m `test` profile [unoptimized + debuginfo] target(s) in 1m 32s',
    '2026-09-02T10:17:49.8660763Z test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 50.99s',
    '2026-09-02T10:17:56.3991342Z \x1b[1m\x1b[92m    Finished\x1b[0m `test` profile [unoptimized + debuginfo] target(s) in 6.48s',
    '2026-09-02T10:21:36.0172007Z test result: ok. 11 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 219.58s',
    '2026-09-02T10:21:41.0101887Z \x1b[1m\x1b[92m    Finished\x1b[0m `test` profile [unoptimized + debuginfo] target(s) in 4.93s',
    '2026-09-02T10:22:22.2217435Z test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 41.18s',
    '2026-09-02T10:22:22.2794328Z ',
    '2026-09-02T10:22:22.2802932Z e2e-devnet: PASS commit=ae4e167 nodes=14 suites_run=4 failed=[] pending=[] secs=1745 anvil=1.8.1 evidence=/home/runner/work/antseal/antseal/target/e2e-devnet/20260902T095317Z-ae4e167',
    '2026-09-02T10:22:22.2805198Z \x1b[32me2e-devnet: PASS — the D52 gate is discharged for this commit.\x1b[0m',
    '2026-09-02T10:22:23.3718987Z ##[group]Run ./scripts/e2e-devnet.sh --scan-evidence',
    '2026-09-02T10:22:23.4968132Z e2e-devnet: scan-evidence: dir=/home/runner/work/antseal/antseal/target/e2e-devnet files=8 findings=0 verdict=CLEAN',
    '2026-09-02T10:22:25.3051766Z Post job cleanup.',
)) + "\n"

# job 102422688930: 22 of its 2108 log lines, verbatim
LOG_GREEN_20260909 = "\n".join((
    "\ufeff2026-09-09T10:04:48.3044081Z Current runner version: '2.337.0'",
    '2026-09-09T10:04:51.6462253Z ##[group]Run rustup show active-toolchain || rustup toolchain install',
    '2026-09-09T10:05:06.8509246Z ##[group]Run ./scripts/e2e-devnet.sh --self-test',
    '2026-09-09T10:05:07.4120605Z   control (committed registry)                              -> e2e-devnet: PASS',
    '2026-09-09T10:05:07.4199086Z ##[group]Run ./scripts/e2e-devnet.sh',
    '2026-09-09T10:05:07.4240137Z   ANTSEAL_DEVNET_NODES: 14',
    '2026-09-09T10:05:07.4525290Z \x1b[36m==>\x1b[0m booting a devnet: 14 nodes (scripts/devnet/local-up)',
    '2026-09-09T10:17:49.3545437Z \x1b[1m\x1b[92m    Finished\x1b[0m `release` profile [optimized] target(s) in 12m 41s',
    '2026-09-09T10:24:54.8751256Z \x1b[1m\x1b[92m    Finished\x1b[0m `test` profile [unoptimized + debuginfo] target(s) in 6m 59s',
    '2026-09-09T10:26:28.7391492Z test result: ok. 6 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 93.82s',
    '2026-09-09T10:27:58.5547133Z \x1b[1m\x1b[92m    Finished\x1b[0m `test` profile [unoptimized + debuginfo] target(s) in 1m 29s',
    '2026-09-09T10:28:52.9257477Z test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 54.32s',
    '2026-09-09T10:28:59.6193251Z \x1b[1m\x1b[92m    Finished\x1b[0m `test` profile [unoptimized + debuginfo] target(s) in 6.64s',
    '2026-09-09T10:32:59.0972065Z test result: ok. 11 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 239.43s',
    '2026-09-09T10:33:04.2247273Z \x1b[1m\x1b[92m    Finished\x1b[0m `test` profile [unoptimized + debuginfo] target(s) in 5.08s',
    '2026-09-09T10:33:48.5219592Z test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 44.25s',
    '2026-09-09T10:33:48.5742177Z ',
    '2026-09-09T10:33:48.5743815Z e2e-devnet: PASS commit=3437890 nodes=14 suites_run=4 failed=[] pending=[] secs=1721 anvil=1.8.1 evidence=/home/runner/work/antseal/antseal/target/e2e-devnet/20260909T100507Z-3437890',
    '2026-09-09T10:33:48.5746309Z \x1b[32me2e-devnet: PASS — the D52 gate is discharged for this commit.\x1b[0m',
    '2026-09-09T10:33:49.6190494Z ##[group]Run ./scripts/e2e-devnet.sh --scan-evidence',
    '2026-09-09T10:33:49.7069554Z e2e-devnet: scan-evidence: dir=/home/runner/work/antseal/antseal/target/e2e-devnet files=8 findings=0 verdict=CLEAN',
    '2026-09-09T10:33:50.7882434Z Post job cleanup.',
)) + "\n"

REAL_LOGS = {94035605439: LOG_RED_20260812, 100203493109: LOG_GREEN_20260902,
             102422688930: LOG_GREEN_20260909}

# The lines `--append` must write for REAL_RUNS, byte for byte.
GOLDEN = tuple("\t".join(fields) for fields in (
    (WORKFLOW, "31571938292", "1", "schedule", "3c8095a8f7819c0a9cb1d5d5f2de3de623ef2404",
     "2026-08-12T06:56:32Z", "failure", "executed", "1374", "5/5", "1318.44", "55.56", "no",
     "e2e-devnet: FAIL commit=3c8095a nodes=5 suites_run=4 failed=[S6-S8,S17,S18,S19] "
     "pending=[] secs=1374 anvil=1.7.1 evidence=/home/runner/work/antseal/antseal/target/"
     "e2e-devnet/20260812T065656Z-3c8095a"),
    (WORKFLOW, "32221569300", "1", "schedule", "dc0bac80964172ea3a458cc1a495f003a32cd6f0",
     "2026-08-19T05:59:57Z", "failure", "refused", "-", "-", "-", "-", "no", "-"),
    (WORKFLOW, "32936547060", "1", "schedule", "c2709ea5510f7589138e9db54565d0b2f60eb68c",
     "2026-08-26T06:03:52Z", "failure", "refused", "-", "-", "-", "-", "no", "-"),
    (WORKFLOW, "33616516399", "1", "schedule", "ae4e1673569952df1fbce8809b2c91721b9aed49",
     "2026-09-02T09:52:51Z", "success", "executed", "1745", "5/5", "1331.41", "413.59", "yes",
     "e2e-devnet: PASS commit=ae4e167 nodes=14 suites_run=4 failed=[] pending=[] secs=1745 "
     "anvil=1.8.1 evidence=/home/runner/work/antseal/antseal/target/e2e-devnet/"
     "20260902T095317Z-ae4e167"),
    (WORKFLOW, "34338263485", "1", "schedule", "34378906c36ca19a7d45a72e04cef56c09ad368b",
     "2026-09-09T10:04:44Z", "success", "executed", "1721", "5/5", "1280.72", "440.28", "yes",
     "e2e-devnet: PASS commit=3437890 nodes=14 suites_run=4 failed=[] pending=[] secs=1721 "
     "anvil=1.8.1 evidence=/home/runner/work/antseal/antseal/target/e2e-devnet/"
     "20260909T100507Z-3437890"),
))

# D167's OWN figures — the witness the derivation is held to, independent of
# GOLDEN (which this file wrote). §1.1: each evidence.txt is 183 B with sha256
# `a44aaaba…7407` / `18ed8527…ba05`; §1.3: non-compile runtime 413.6 s / 440.3 s,
# printed to 0.1 s, so the tolerance is 5 centiseconds.
#   job_id: (sha256 head, sha256 tail, non-compile centiseconds)
D167_WITNESS = {
    100203493109: ("a44aaaba", "7407", 41360),
    102422688930: ("18ed8527", "ba05", 44030),
}

FIXTURE_SLUG = "OWNER/REPO"
FIXTURE_NOW = dt.datetime(2026, 9, 13, tzinfo=dt.timezone.utc)

# Commits in synthetic repositories carry this identity and no address.
SELFTEST_GIT = {"GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_AUTHOR_NAME": "selftest", "GIT_AUTHOR_EMAIL": "selftest",
                "GIT_COMMITTER_NAME": "selftest", "GIT_COMMITTER_EMAIL": "selftest"}


def _run(rid: int, event: str, conclusion: str | None, sha: str, created: str,
         attempt: int = 1, status: str = "completed") -> dict:
    return {"id": rid, "event": event, "status": status, "conclusion": conclusion,
            "head_sha": sha, "run_attempt": attempt, "created_at": created,
            "run_started_at": created, "path": f".github/workflows/{WORKFLOW}"}


def _job(job_id: int, conclusion: str, runner: str, steps: int) -> dict:
    return {"id": job_id, "name": WORKFLOWS[WORKFLOW]["job"], "status": "completed",
            "conclusion": conclusion, "runner_name": runner,
            "steps": [{"number": n + 1} for n in range(steps)]}


class FixtureApi:
    """Answers GETs from recorded bodies and remembers every endpoint asked."""

    def __init__(self, runs: list[dict], jobs: dict, logs: dict,
                 attempts: dict | None = None) -> None:
        self.slug = FIXTURE_SLUG
        self.asked: list[str] = []
        base = f"repos/{self.slug}/actions"
        self.routes: dict[str, tuple[int, str]] = {
            f"{base}/workflows/{WORKFLOW}/runs?per_page=100&page=1":
                (200, json.dumps({"total_count": len(runs), "workflow_runs": runs}))}
        for (rid, attempt), js in jobs.items():
            self.routes[f"{base}/runs/{rid}/attempts/{attempt}/jobs?per_page=100"] = (
                200, json.dumps({"total_count": len(js), "jobs": js}))
        for (rid, attempt), run in (attempts or {}).items():
            self.routes[f"{base}/runs/{rid}/attempts/{attempt}"] = (200, json.dumps(run))
        for job_id, (status, text) in logs.items():
            self.routes[f"{base}/jobs/{job_id}/logs"] = (status, text)

    def get(self, endpoint: str) -> tuple[int | None, bytes, str]:
        self.asked.append(endpoint)
        status, body = self.routes.get(endpoint, (404, '{"message": "Not Found"}'))
        return status, body.encode("utf-8"), "" if status == 200 else f"HTTP {status}"


def real_fixture(extra_runs: tuple = (), no_runs: bool = False) -> FixtureApi:
    runs = [] if no_runs else [_run(rid, "schedule", c, sha, t)
                               for (rid, c, sha, t, _job_id, _runner, _steps) in REAL_RUNS]
    jobs = {} if no_runs else {(rid, 1): [_job(job_id, c, runner, steps)]
                               for (rid, c, _sha, _t, job_id, runner, steps) in REAL_RUNS}
    logs = {job_id: (200, text) for job_id, text in REAL_LOGS.items()}
    # The API lists newest first.
    return FixtureApi(list(extra_runs) + runs[::-1], jobs, logs)


def with_fields(line: str, **changes: str) -> str:
    fields = line.split("\t")
    for name, value in changes.items():
        fields[HEADER.index(name)] = value
    return "\t".join(fields)


def ledger_text(lines) -> str:
    return "".join(line + "\n" for line in [HEADER_LINE, *lines])


class Synth:
    """A throwaway repository inside the self-test's temporary directory."""

    def __init__(self, path: Path, commits: int = 0) -> None:
        self.path = path
        self.commits = commits

    @classmethod
    def init(cls, path: Path) -> "Synth":
        path.mkdir()
        repo = cls(path)
        repo.git("-c", "init.defaultBranch=main", "init", "-q")
        return repo

    @classmethod
    def shallow_clone(cls, origin: "Synth", path: Path) -> "Synth":
        repo = cls(path, origin.commits)
        repo.git_in(origin.path.parent, "clone", "-q", "--depth", "1",
                    f"file://{origin.path}", str(path))
        return repo

    def copy(self, path: Path) -> "Synth":
        shutil.copytree(self.path, path, symlinks=True)
        return Synth(path, self.commits)

    def env(self) -> dict[str, str]:
        stamp = f"2026-09-13T00:{self.commits // 60:02d}:{self.commits % 60:02d}Z"
        return git_env({**SELFTEST_GIT, "GIT_AUTHOR_DATE": stamp, "GIT_COMMITTER_DATE": stamp})

    def git_in(self, where: Path, *args: str) -> None:
        proc = git(where, *args, env=self.env())
        if proc.returncode != 0:
            raise CouldNotRun(f"self-test `git {' '.join(args[:2])}` failed: "
                              f"{proc.stderr.decode('utf-8', 'replace').strip()[:200]}")

    def git(self, *args: str) -> None:
        self.git_in(self.path, *args)

    def write(self, lines) -> "Synth":
        target = self.path / LEDGER
        if lines is None:
            target.unlink()
            return self
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes("".join(line + "\n" for line in lines).encode("utf-8"))
        return self

    def commit(self, message: str) -> "Synth":
        self.commits += 1
        self.git("add", "-A")
        self.git("commit", "-q", "--allow-empty", "-m", message)
        return self

    def check(self) -> tuple[list[Finding], dict]:
        return check_offline(self.path, env=git_env(SELFTEST_GIT))


def self_test() -> int:
    ledger_path, script_path = ROOT / LEDGER, Path(__file__).resolve()

    def digest(path: Path) -> str | None:
        return hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None

    before = (digest(ledger_path), digest(script_path))
    arms: list[tuple[str, str]] = []
    produced: dict[str, str] = {}
    failures: list[str] = []

    def ok(name: str, kind: str, message: str) -> None:
        arms.append((name, kind))
        print(f"  {name:<44} {message}")

    def red(name: str, findings: list[Finding], want: list[str],
            needle: str | None = None, forbid: str | None = None) -> None:
        got = {f.tag for f in findings}
        if got != set(want):
            failures.append(f"{name}: expected exactly {want}, got "
                            f"{sorted(got) if got else 'GREEN'}"
                            + "".join(f" | {f.render()[:160]}" for f in findings[:3]))
            return
        if needle is not None and not any(needle in f.message for f in findings):
            failures.append(f"{name}: {want} fired, but no message says {needle!r}")
            return
        if forbid is not None and any(forbid in f.message for f in findings):
            failures.append(f"{name}: {want} fired, but for the wrong reason ({forbid!r})")
            return
        for tag in want:
            produced.setdefault(tag, name)
        first = next(f for f in findings if f.tag == want[-1])
        ok(name, "planted-fault", f"-> RED [{'+'.join(want)}] {shown(first.message)[:96]}")

    def green(name: str, findings: list[Finding], note: str) -> None:
        if findings:
            failures.append(f"{name}: expected GREEN ({note}), got "
                            + " | ".join(f.render()[:160] for f in findings[:3]))
        else:
            ok(name, "green-control", f"-> GREEN — {note}")

    def holds(name: str, kind: str, condition: bool, yes: str, no: str) -> None:
        if condition:
            ok(name, kind, f"-> {yes}")
        else:
            failures.append(f"{name}: {no}")

    def planned(name: str, text: str, api) -> list[Record] | None:
        """plan_append for an arm that expects lines: a refusal is THAT arm's failure,
        never an exception escaping the self-test (a traceback is not a red)."""
        try:
            return plan_append(text, api)
        except Refusal as exc:
            failures.append(f"{name}: refused unexpectedly [{exc.kind}]: {shown(str(exc))}")
            return None

    step = WORKFLOWS[WORKFLOW]["step"]
    header, full = [HEADER_LINE], [HEADER_LINE, *GOLDEN]
    golden_text = ledger_text(GOLDEN)

    try:
        # ── OFFLINE: synthetic repositories ─────────────────────────────────
        with tempfile.TemporaryDirectory(prefix="check-devnet-ledger-") as tmp:
            work = Path(tmp)
            base = Synth.init(work / "base")
            base.write(header + list(GOLDEN[:3])).commit("birth")
            base.write(header + list(GOLDEN[:4])).commit("append one")

            def arm_repo(name: str, worktree, commits=()) -> Synth:
                repo = base.copy(work / name)
                for lines in commits:
                    repo.write(lines).commit("history")
                return repo.write(worktree)

            findings, stats = arm_repo("green", full).check()
            green("offline-control-real-lines", findings,
                  f"{stats['states']} states from derived birth, {stats['pinned']} pinned, "
                  f"streak {streak(stats['records'])[0]}")
            holds("offline-control-not-vacuous", "property",
                  stats["pinned"] == 9 and streak(stats["records"])[0] == 2,
                  "pinned == 9 (4 + 5 comparisons) and streak == 2",
                  f"pinned {stats['pinned']} (want 9), streak "
                  f"{streak(stats['records'])[0]} (want 2)")

            edited = with_fields(GOLDEN[1], started_at="2026-08-19T05:59:58Z")
            findings, _ = arm_repo("edit-wt", [HEADER_LINE, GOLDEN[0], edited,
                                               *GOLDEN[2:]]).check()
            red("offline-edit-in-working-tree", findings, ["EDITED"], "REWRITTEN")

            history = [HEADER_LINE, *GOLDEN[:2], with_fields(GOLDEN[2], conclusion="cancelled"),
                       GOLDEN[3]]
            findings, _ = arm_repo("edit-commit", history + [GOLDEN[4]], [history]).check()
            red("offline-edit-between-commits", findings, ["EDITED"], "REWRITTEN",
                forbid="the working tree")

            findings, _ = arm_repo("delete-line", [HEADER_LINE, *GOLDEN[1:]]).check()
            red("offline-delete-committed-line", findings, ["EDITED"], "DELETED between")

            # The LENGTH branch, not the mismatch branch above: the last committed
            # line removed leaves no differing index to find.
            findings, _ = arm_repo("truncate", [HEADER_LINE, *GOLDEN[:3]]).check()
            red("offline-truncate-committed-tail", findings, ["EDITED"], "DELETED (truncated)")

            spliced = with_fields(GOLDEN[4], run_id="34338263497")
            findings, _ = arm_repo("insert", [HEADER_LINE, spliced, *GOLDEN]).check()
            red("offline-insert-ahead-of-committed-line", findings, ["EDITED"], "INSERTED")

            findings, _ = arm_repo("reorder", [HEADER_LINE, GOLDEN[1], GOLDEN[0],
                                               *GOLDEN[2:]]).check()
            red("offline-reorder-committed-lines", findings, ["EDITED"], "REORDERED")

            findings, _ = arm_repo("delete-file", None).check()
            red("offline-delete-ledger-file", findings, ["EDITED"], "was DELETED between")

            findings, _ = arm_repo("duplicate", full + [GOLDEN[4]]).check()
            red("offline-duplicate-run", findings, ["DUPLICATE"], "already recorded at line 6")

            over = with_fields(GOLDEN[0], run_id="31571938299", clean="yes")
            findings, _ = arm_repo("count-over", full + [over]).check()
            red("offline-count-overclaim", findings, ["COUNT"], "COUNTED CLEAN but is not")

            under = with_fields(GOLDEN[4], run_id="34338263499", clean="no")
            findings, _ = arm_repo("count-under", full + [under]).check()
            red("offline-count-underclaim", findings, ["COUNT"], "marked NOT clean")

            findings, _ = arm_repo("format-short", full + [GOLDEN[4].rsplit("\t", 1)[0]]).check()
            red("offline-format-short-line", findings, ["FORMAT"], "13 tab-separated field(s)")

            arithmetic = with_fields(GOLDEN[4], run_id="34338263498", noncompile_secs="400.28")
            findings, _ = arm_repo("format-arith", full + [arithmetic]).check()
            red("offline-format-runtime-arithmetic", findings, ["FORMAT"],
                "is not what secs and compile_secs derive")

            foreign = with_fields(GOLDEN[4], run_id="33616516398", head_sha=REAL_RUNS[3][2])
            findings, _ = arm_repo("format-foreign", full + [foreign]).check()
            red("offline-format-foreign-verdict", findings, ["FORMAT"], "belongs to another run")

            lone = Synth.init(work / "unborn")
            (lone.path / "README").write_text("unrelated\n", encoding="utf-8")
            lone.commit("unrelated").write(full)
            findings, _ = lone.check()
            red("offline-unborn-uncommitted-ledger", findings, ["UNBORN"],
                "UNCOMMITTED ADDITION: FORMAT, DUPLICATE and COUNT reported 0 problem(s)")

            lone_bad = lone.copy(work / "unborn-bad").write(full + ["not a ledger line"])
            findings, _ = lone_bad.check()
            red("offline-unborn-still-content-checked", findings, ["FORMAT", "UNBORN"],
                "reported 1 problem(s)")

            vacuous = Synth.init(work / "vacuous")
            (vacuous.path / LEDGER).parent.mkdir(parents=True)
            (vacuous.path / LEDGER).write_bytes(b"")
            vacuous.commit("empty birth").write(full)
            findings, _ = vacuous.check()
            red("offline-unborn-vacuous-birth", findings, ["UNBORN"],
                "pinned ZERO line comparisons across")

            findings, _ = lone.copy(work / "absent").write(None).check()
            red("offline-unborn-no-ledger", findings, ["UNBORN"], "does not exist")

            findings, _ = Synth.shallow_clone(base, work / "shallow").check()
            red("offline-shallow-clone", findings, ["SHALLOW"], "shallow clone")

        # ── CONTENT RULES: one planted fault per rule, no git needed ───────
        for name, text, needle in (
            ("format-file-bom", "\ufeff" + golden_text, "byte-order mark"),
            ("format-file-crlf", golden_text.replace("\n", "\r\n"), "carriage return"),
            ("format-file-not-utf8",
             HEADER_LINE + "\n" + b"\xff\n".decode("utf-8", "replace"), "not valid UTF-8"),
            ("format-file-no-final-newline", golden_text[:-1], "does not end with a newline"),
            ("format-file-wrong-header", golden_text.replace("noncompile_secs", "noncompile", 1),
             "line 1 is not the header"),
            ("format-file-empty", "", "the file is empty"),
        ):
            findings, _ = check_content(text, LEDGER)
            red(name, findings, ["FORMAT"], needle)

        verdict = GOLDEN[4].split("\t")[-1]
        for name, plant, needle in (
            ("format-run-id", with_fields(GOLDEN[1], run_id="0123"), "is not a positive integer"),
            ("format-attempt", with_fields(GOLDEN[1], run_id="32221569301", attempt="0"),
             "attempt '0'"),
            ("format-event", with_fields(GOLDEN[1], run_id="32221569302", event="Schedule"),
             "is not a GitHub event name"),
            ("format-head-sha", with_fields(GOLDEN[1], run_id="32221569303", head_sha="dc0bac8"),
             "full 40-hex"),
            ("format-started-at", with_fields(GOLDEN[1], run_id="32221569304",
                                              started_at="2026-02-30T05:59:57Z"),
             "not a real instant"),
            ("format-conclusion", with_fields(GOLDEN[1], run_id="32221569305", conclusion="green"),
             "not a GitHub run conclusion"),
            ("format-clean-value", with_fields(GOLDEN[1], run_id="32221569306", clean="maybe"),
             "neither `yes` nor `no`"),
            ("format-class", with_fields(GOLDEN[1], run_id="32221569307", **{"class": "skipped"}),
             "neither `executed` nor `refused`"),
            ("format-refused-with-runtime", with_fields(GOLDEN[1], run_id="32221569308", secs="10"),
             "a refused line carries"),
            ("format-unknown-workflow", with_fields(GOLDEN[1], run_id="32221569309",
                                                    workflow="fuzz-nightly.yml"),
             "is not one this checker knows"),
            ("format-surrounding-whitespace", with_fields(GOLDEN[1], run_id="32221569310",
                                                          event=" schedule"),
             "surrounding whitespace"),
            ("format-secs-vs-verdict", with_fields(GOLDEN[4], run_id="34338263401", secs="1722"),
             "differs from the verdict's secs=1721"),
            ("format-markers-vs-suites", with_fields(GOLDEN[4], run_id="34338263402", markers="5/4"),
             "suites_run=4 means 5"),
            ("format-compile-secs-syntax", with_fields(GOLDEN[4], run_id="34338263403",
                                                       compile_secs="1280.7"),
             "is not a two-decimal number"),
            ("format-verdict-not-verbatim", with_fields(GOLDEN[4], run_id="34338263404",
                                                        verdict="PASS"),
             "is not a verbatim"),
            ("format-absent-verdict-with-runtime", with_fields(GOLDEN[0], run_id="31571938201",
                                                               verdict=ABSENT),
             "must carry secs/markers/compile_secs"),
        ):
            findings, _ = check_content(ledger_text([*GOLDEN, plant]), LEDGER)
            red(name, findings, ["FORMAT"], needle)

        # Each §2 R4 condition planted ALONE — the line fails exactly one clean
        # condition — so deleting any one condition from unclean_reasons() turns
        # exactly one arm green. `executed` and "has a verdict" have no arm of
        # their own: FORMAT already forbids a refused or verdict-less line from
        # carrying a measured runtime, so neither can be the only failed condition.
        for name, plant, needle in (
            ("count-conclusion-not-success",
             with_fields(GOLDEN[4], run_id="34338263411", clean="yes", conclusion="failure"),
             "conclusion=failure"),
            ("count-verdict-not-pass",
             with_fields(GOLDEN[4], run_id="34338263412", clean="yes",
                         verdict=verdict.replace("PASS", "FAIL")), "verdict FAIL"),
            ("count-nodes-below-14",
             with_fields(GOLDEN[4], run_id="34338263413", clean="yes",
                         verdict=verdict.replace("nodes=14", "nodes=13")), "nodes=13"),
            ("count-failed-suite",
             with_fields(GOLDEN[4], run_id="34338263414", clean="yes",
                         verdict=verdict.replace("failed=[]", "failed=[S17]")), "failed=[S17]"),
            ("count-pending-suite",
             with_fields(GOLDEN[4], run_id="34338263415", clean="yes",
                         verdict=verdict.replace("pending=[]", "pending=[S99]")), "pending=[S99]"),
            ("count-no-suite-run",
             with_fields(GOLDEN[4], run_id="34338263416", clean="yes", secs="1000", markers="1/1",
                         compile_secs="761.00", noncompile_secs="239.00",
                         verdict=verdict.replace("suites_run=4", "suites_run=0")
                         .replace("secs=1721", "secs=1000")), "suites_run=0"),
            ("count-zero-secs",
             with_fields(GOLDEN[4], run_id="34338263417", clean="yes", secs="0",
                         compile_secs="0.00", noncompile_secs="0.00",
                         verdict=verdict.replace("secs=1721", "secs=0")), "secs=0"),
            ("count-runtime-unmeasured",
             with_fields(GOLDEN[4], run_id="34338263418", clean="yes", markers="4/5",
                         noncompile_secs=UNMEASURED), "runtime unmeasured"),
            ("count-runtime-over-900",
             with_fields(GOLDEN[4], run_id="34338263419", clean="yes", compile_secs="820.99",
                         noncompile_secs="900.01"), "900.01 s > 900 s"),
        ):
            rec, problems = parse_record(plant, 7)
            if rec is None or len(unclean_reasons(rec)) != 1:
                failures.append(f"{name}: the plant is not a single-condition fault "
                                f"(format {problems}, reasons "
                                f"{unclean_reasons(rec) if rec else '-'})")
                continue
            findings, _ = check_content(ledger_text([*GOLDEN, plant]), LEDGER)
            red(name, findings, ["COUNT"], needle)

        boundary = with_fields(GOLDEN[4], run_id="34338263420", compile_secs="821.00",
                               noncompile_secs="900.00")
        findings, _ = check_content(ledger_text([*GOLDEN, boundary]), LEDGER)
        green("count-runtime-exactly-900-is-clean", findings,
              "non-compile 900.00 s counted clean (the clause is <= 15 min)")

        # ── THE RUNTIME DERIVATION: recorded logs ──────────────────────────
        for job_id, (head, tail, want_cs) in D167_WITNESS.items():
            d = derive_from_log(REAL_LOGS[job_id], step)
            sha = hashlib.sha256((d.verdict + "\n").encode("utf-8")).hexdigest()
            non = parse_cs(d.noncompile_secs)
            holds(f"derive-d167-witness-job-{job_id}", "green-control",
                  sha.startswith(head) and sha.endswith(tail) and len(d.verdict) + 1 == 183
                  and d.markers == "5/5" and non is not None and abs(non - want_cs) <= 5,
                  f"GREEN — verdict {len(d.verdict) + 1} B sha256 {head}…{tail} (D167 §1.1); "
                  f"non-compile {d.noncompile_secs} s vs §1.3's {want_cs / 100:.1f} s",
                  f"verdict sha256 {sha[:8]}…{sha[-4:]} / {len(d.verdict) + 1} B, markers "
                  f"{d.markers}, non-compile {d.noncompile_secs} — D167 printed "
                  f"{head}…{tail} / 183 B / 5/5 / {want_cs / 100:.1f}")

        lines = REAL_LOGS[102422688930].split("\n")
        tests = [i for i, line in enumerate(lines) if "Finished" in line and "`test`" in line]
        removed = "\n".join(line for i, line in enumerate(lines) if i != tests[1])
        d = derive_from_log(removed, step)
        rec = Record(0, WORKFLOW, 1, 1, "schedule", REAL_RUNS[4][2], REAL_RUNS[4][3],
                     "success", "executed", d.secs, d.markers, d.compile_secs,
                     d.noncompile_secs, "no", d.verdict)
        holds("derive-marker-removed-fails-closed", "planted-fault",
              len(tests) == 4 and removed != REAL_LOGS[102422688930] and d.markers == "4/5"
              and d.noncompile_secs == UNMEASURED
              and "non-compile runtime unmeasured" in unclean_reasons(rec),
              f"RED — one `Finished` removed: markers {d.markers}, noncompile_secs "
              f"{d.noncompile_secs}, clean=no ({'; '.join(unclean_reasons(rec))})",
              f"one marker removed gave markers {d.markers}, noncompile {d.noncompile_secs}, "
              f"unclean reasons {unclean_reasons(rec)}")

        verdict_at = next(i for i, line in enumerate(lines) if "e2e-devnet: PASS commit=" in line)
        surplus = "\n".join(lines[:verdict_at] + [lines[tests[0]]] + lines[verdict_at:])
        d = derive_from_log(surplus, step)
        holds("derive-marker-surplus-fails-closed", "planted-fault",
              d.markers == "6/5" and d.noncompile_secs == UNMEASURED,
              f"RED — one `Finished` duplicated inside the step: markers {d.markers}, "
              f"noncompile_secs {d.noncompile_secs}",
              f"a surplus marker gave markers {d.markers}, noncompile {d.noncompile_secs}")

        selftest_at = next(i for i, line in enumerate(lines)
                           if line.endswith("##[group]Run ./scripts/e2e-devnet.sh --self-test"))
        elsewhere = "\n".join(lines[:selftest_at + 1] + [lines[tests[0]]]
                              + lines[selftest_at + 1:])
        d = derive_from_log(elsewhere, step)
        holds("derive-marker-in-other-step-ignored", "green-control",
              d.markers == "5/5" and d.noncompile_secs == "440.28",
              f"GREEN — a `Finished` in the --self-test step is not counted: markers "
              f"{d.markers}, noncompile_secs {d.noncompile_secs}",
              f"a marker in another step changed the derivation: markers {d.markers}, "
              f"noncompile {d.noncompile_secs}")

        unknown = REAL_LOGS[102422688930].replace("nodes=14 suites_run=4",
                                                  "nodes=14 branch=main suites_run=4")
        try:
            derive_from_log(unknown, step)
        except LogShapeError as exc:
            holds("derive-unknown-verdict-format-refused", "planted-fault",
                  unknown != REAL_LOGS[102422688930], f"RED — LogShapeError: {shown(str(exc))[:80]}",
                  "the plant did not apply")
        else:
            failures.append("derive-unknown-verdict-format-refused: a verdict line with an extra "
                            "field was accepted, so a new format would be recorded as `absent`")

        # The step's END boundary: a verdict-shaped line in a LATER step is not
        # a second verdict. Without the boundary this raises "2 verdict-shaped lines".
        scan_at = next(i for i, line in enumerate(lines)
                       if line.endswith("##[group]Run ./scripts/e2e-devnet.sh --scan-evidence"))
        later = "\n".join(lines[:scan_at + 1] + [lines[verdict_at]] + lines[scan_at + 1:])
        try:
            d = derive_from_log(later, step)
            holds("derive-verdict-in-later-step-ignored", "green-control",
                  d.verdict == GOLDEN[4].split("\t")[-1] and d.noncompile_secs == "440.28",
                  "GREEN — a verdict copy inside the --scan-evidence step is outside the clock "
                  "step and ignored",
                  f"a verdict copy in a later step changed the derivation: {d}")
        except LogShapeError as exc:
            failures.append(f"derive-verdict-in-later-step-ignored: the step's end boundary is "
                            f"not honoured: {exc}")

        headless = "\n".join(line for line in lines
                             if not line.endswith("##[group]Run ./scripts/e2e-devnet.sh"))
        try:
            derive_from_log(headless, step)
        except LogShapeError as exc:
            holds("derive-missing-step-header-refused", "planted-fault",
                  headless != REAL_LOGS[102422688930] and "found 0" in str(exc),
                  f"RED — LogShapeError: {shown(str(exc))[:80]}",
                  f"the refusal does not name the missing header: {exc}")
        else:
            failures.append("derive-missing-step-header-refused: a log without the clock step "
                            "was accepted")

        silent = "\n".join(line for i, line in enumerate(lines) if i != verdict_at)
        d = derive_from_log(silent, step)
        holds("derive-no-verdict-is-absent", "green-control",
              d == Derived(ABSENT, NONE, NONE, NONE, UNMEASURED),
              f"GREEN — no verdict line -> verdict `{d.verdict}`, noncompile `{d.noncompile_secs}`",
              f"a log without a verdict derived {d}")

        # ── --append: recorded API answers ─────────────────────────────────
        api = real_fixture()
        new = planned("append-reproduces-golden-lines", ledger_text([]), api)
        got = tuple(r.line() for r in new or [])
        logs_asked = [a for a in api.asked if a.endswith("/logs")]
        refused_asked = [a for a in logs_asked if "/jobs/95972874731/" in a
                         or "/jobs/98078726504/" in a]
        diff = next((f"line {i + 2}: got {shown(g)} want {shown(w)}"
                     for i, (g, w) in enumerate(zip(got, GOLDEN)) if g != w),
                    f"{len(got)} line(s) vs {len(GOLDEN)}")
        holds("append-reproduces-golden-lines", "green-control",
              got == GOLDEN and len(logs_asked) == 3 and not refused_asked,
              "GREEN — 5 lines byte-identical to GOLDEN; 3 job logs read, the 2 refused "
              "jobs' logs never requested",
              f"{diff}; logs asked {len(logs_asked)}, refused logs asked {refused_asked}")

        again = planned("append-idempotent", golden_text, real_fixture())
        holds("append-idempotent", "green-control", again is not None and again == [],
              "GREEN — a ledger holding every completed attempt appends nothing",
              "a complete ledger still planned new lines")

        rid, job = 36000000001, 96000000001
        api = FixtureApi([_run(rid, "schedule", "failure", REAL_RUNS[0][2], "2026-09-10T09:00:00Z")],
                         {(rid, 1): [_job(job, "failure", "GitHub Actions 1000000001", 0)]},
                         {job: (410, "")})
        new = planned("append-steps-empty-with-runner-executed", ledger_text([]), api) or []
        holds("append-steps-empty-with-runner-executed", "planted-fault",
              len(new) == 1 and new[0].klass == "executed" and new[0].verdict == LOG_EXPIRED
              and new[0].clean == "no",
              f"RED — steps=[] with a runner and a 410 log -> class={new[0].klass if new else '?'}, "
              f"verdict={new[0].verdict if new else '?'}, clean=no (§1.6)",
              f"steps=[] with a runner gave {[(r.klass, r.verdict, r.clean) for r in new]}")

        rid, job = 36000000002, 96000000002
        api = FixtureApi([_run(rid, "schedule", "failure", REAL_RUNS[1][2], "2026-09-10T10:00:00Z")],
                         {(rid, 1): [_job(job, "failure", "", 7)]}, {})
        new = planned("append-steps-without-runner-refused", ledger_text([]), api) or []
        holds("append-steps-without-runner-refused", "green-control",
              len(new) == 1 and new[0].klass == "refused"
              and not any(a.endswith("/logs") for a in api.asked),
              "GREEN — seven steps but no runner -> class=refused, no log requested",
              f"steps without a runner gave {[(r.klass, r.verdict) for r in new]}, "
              f"asked {api.asked}")

        rid, job = 36000000003, 96000000003
        api = FixtureApi([_run(rid, "schedule", "failure", REAL_RUNS[0][2], "2026-09-10T11:00:00Z")],
                         {(rid, 1): [_job(job, "failure", "GitHub Actions 1000000003", 9)]},
                         {job: (404, "BlobNotFound")})
        try:
            plan_append(ledger_text([]), api)
        except Refusal as exc:
            holds("append-log-404-refused", "planted-fault", exc.kind == "LOG-UNAVAILABLE",
                  f"RED [{exc.kind}] {shown(str(exc))[:88]}",
                  f"a 404 log was refused as {exc.kind}, not LOG-UNAVAILABLE")
        else:
            failures.append("append-log-404-refused: an executed job's 404 log became a line; "
                            "a transient answer must never be written permanently")

        # The shape this lane's first real --append produced: gh fails on the
        # redirect's second hop and quotes the signed URL. The token below is a
        # FIXTURE, not a signature.
        signed = ('Get "https://fixture.blob.core.windows.net/actions-results/job-logs.txt'
                  '?rsct=text%2Fplain&se=2099-01-01T00%3A00%3A00Z&sig=FIXTURExNOTxAxSIGNATURE'
                  '%3D": read tcp: connection reset by peer')

        def failing_gh(argv, **_kwargs):
            if tuple(argv[:4]) != ("gh", "api", "--method", "GET"):
                raise AssertionError(f"GhApi issued a non-GET command: {argv}")
            return subprocess.CompletedProcess(argv, 1, b"", signed.encode("utf-8"))

        pauses: list[int] = []
        status, _, detail = GhApi(FIXTURE_SLUG, runner=failing_gh,
                                  sleeper=pauses.append).get("repos/x/actions/jobs/1/logs")
        holds("api-detail-signed-url-redacted", "planted-fault",
              status is None and "sig=" not in detail and "se=" not in detail
              and "fixture.blob.core.windows.net/actions-results/job-logs.txt?<query redacted>"
              in detail and "after 3 tries" in detail and pauses == [5, 10],
              f"RED — no status after 3 tries (paused {pauses} s); gh's signed URL cut to: "
              f"{shown(detail)[:48]}",
              f"a failing GET gave status {status}, pauses {pauses}, detail {detail!r}")

        calls: list[int] = []

        def flaky_gh(argv, **_kwargs):
            calls.append(1)
            if len(calls) < 3:
                return subprocess.CompletedProcess(argv, 1, b"", b"gh: HTTP 502")
            return subprocess.CompletedProcess(argv, 0, b"log text", b"")

        status, body, _ = GhApi(FIXTURE_SLUG, runner=flaky_gh,
                                sleeper=lambda _s: None).get("repos/x/actions/jobs/1/logs")
        holds("api-5xx-retried-then-answered", "green-control",
              status == 200 and body == b"log text" and len(calls) == 3,
              "GREEN — 502, 502, then 200: the third answer is returned",
              f"a flaky GET gave status {status} after {len(calls)} call(s)")

        calls.clear()

        def gone_gh(argv, **_kwargs):
            calls.append(1)
            return subprocess.CompletedProcess(argv, 1, b"", b"gh: HTTP 410")

        status, _, _ = GhApi(FIXTURE_SLUG, runner=gone_gh,
                             sleeper=lambda _s: None).get("repos/x/actions/jobs/1/logs")
        holds("api-410-answered-once", "green-control", status == 410 and len(calls) == 1,
              "GREEN — a 410 is a durable answer and is not asked again",
              f"a 410 gave status {status} after {len(calls)} call(s)")

        no_verdict = "\n".join(line for line in LOG_GREEN_20260909.split("\n")
                               if "e2e-devnet: PASS commit=" not in line)
        for name, conclusion, rid, job in (
                ("append-cancelled-run-without-verdict-recorded", "cancelled", 36000000005,
                 96000000005),
                ("append-success-without-verdict-refused", "success", 36000000006, 96000000006)):
            api = FixtureApi([_run(rid, "schedule", conclusion, REAL_RUNS[4][2],
                                   "2026-09-10T12:00:00Z")],
                             {(rid, 1): [_job(job, conclusion, "GitHub Actions 1000000005", 11)]},
                             {job: (200, no_verdict)})
            try:
                new = plan_append(ledger_text([]), api)
            except Refusal as exc:
                holds(name, "planted-fault", conclusion == "success" and exc.kind == "LOG-SHAPE",
                      f"RED [{exc.kind}] {shown(str(exc))[:88]}",
                      f"a {conclusion} run without a verdict was refused as {exc.kind}: {exc}")
            else:
                holds(name, "green-control",
                      conclusion != "success" and len(new) == 1 and new[0].verdict == ABSENT
                      and new[0].noncompile_secs == UNMEASURED and new[0].clean == "no",
                      f"GREEN — a {conclusion} run with no verdict line is recorded as "
                      f"`{new[0].verdict if new else '?'}`, clean=no",
                      f"a {conclusion} run without a verdict gave "
                      f"{[(r.verdict, r.clean) for r in new]} instead of the LOG-SHAPE refusal")

        rid, job = 36000000009, 96000000009
        stranger = _job(job, "success", "GitHub Actions 1000000009", 11)
        stranger["name"] = "some-other-job"
        api = FixtureApi([_run(rid, "schedule", "success", REAL_RUNS[4][2], "2026-09-10T13:00:00Z")],
                         {(rid, 1): [stranger]}, {job: (200, LOG_GREEN_20260909)})
        try:
            plan_append(ledger_text([]), api)
        except Refusal as exc:
            holds("append-unknown-job-refused", "planted-fault", exc.kind == "JOB-SHAPE",
                  f"RED [{exc.kind}] {shown(str(exc))[:88]}",
                  f"a job of another name was refused as {exc.kind}, not JOB-SHAPE")
        else:
            failures.append("append-unknown-job-refused: a line was built from a job this "
                            "workflow does not define")

        rid, sha, t1 = 36000000004, REAL_RUNS[0][2], "2026-09-11T05:37:00Z"
        latest = _run(rid, "schedule", "success", sha, t1, attempt=2)
        latest["run_started_at"] = "2026-09-11T09:00:00Z"
        api = FixtureApi(
            [latest],
            {(rid, 1): [_job(96000000041, "failure", "GitHub Actions 1000000041", 9)],
             (rid, 2): [_job(96000000042, "success", "GitHub Actions 1000000042", 11)]},
            {96000000041: (200, LOG_RED_20260812),
             96000000042: (200, LOG_GREEN_20260909.replace("commit=3437890", "commit=3c8095a"))},
            attempts={(rid, 1): _run(rid, "schedule", "failure", sha, t1, attempt=1)})
        new = planned("append-rerun-cannot-inflate-count", ledger_text([]), api) or []
        holds("append-rerun-cannot-inflate-count", "planted-fault",
              [(r.attempt, r.clean) for r in new] == [(1, "no"), (2, "yes")]
              and streak(new)[0] == 0,
              "RED — a red attempt 1 re-run green: both attempts recorded, streak 0 (the "
              "re-run neither erases the red nor counts)",
              f"re-run gave {[(r.attempt, r.clean) for r in new]}, streak {streak(new)[0]}")

        # ── --against-api: recorded API answers ────────────────────────────
        findings, stats = check_online(golden_text, real_fixture(), FIXTURE_NOW)
        green("online-control-real-runs", findings,
              f"5 runs, 5 lines, newest scheduled {_age(stats['newest'][2])} old at 2026-09-13")

        extra = _run(35000000001, "workflow_dispatch", "success", REAL_RUNS[4][2],
                     "2026-09-12T12:00:00Z")
        findings, _ = check_online(golden_text, real_fixture(extra_runs=(extra,)), FIXTURE_NOW)
        red("online-lag-extra-run", findings, ["LAG"], "completed run 35000000001 attempt 1")

        findings, _ = check_online(ledger_text([]), real_fixture(), FIXTURE_NOW)
        named = all(any(f"run {r[0]} " in f.message for f in findings) for r in REAL_RUNS)
        red("online-lag-header-only-ledger", findings, ["LAG"],
            None if named and len(findings) == 5 else "every one of the five real run ids")

        nine = dt.datetime(2026, 9, 18, 10, 4, 44, tzinfo=dt.timezone.utc)
        findings, _ = check_online(golden_text, real_fixture(), nine)
        red("online-stale-newest-nine-days-old", findings, ["STALE-SCHEDULE"],
            "34338263485, was created 2026-09-09T10:04:44Z — 9 d 0 h 0 m")

        findings, _ = check_online(ledger_text([]), real_fixture(no_runs=True), FIXTURE_NOW)
        red("online-stale-no-runs-at-all", findings, ["STALE-SCHEDULE"], "NO scheduled run")

        edge = (dt.datetime(2026, 9, 9, 10, 4, 44, tzinfo=dt.timezone.utc) + STALE_AFTER
                - dt.timedelta(minutes=1))
        findings, _ = check_online(golden_text, real_fixture(), edge)
        green("online-stale-edge-one-minute-early", findings,
              f"newest scheduled run {_age(STALE_AFTER - dt.timedelta(minutes=1))} old")

        forged = golden_text.replace(GOLDEN[2], with_fields(GOLDEN[2], conclusion="cancelled"))
        findings, _ = check_online(forged, real_fixture(), FIXTURE_NOW)
        red("online-mismatch-forged-conclusion", findings, ["MISMATCH"],
            "conclusion cancelled vs API failure")

        for field, value, needle in (
            ("event", "workflow_dispatch", "event workflow_dispatch vs API schedule"),
            ("head_sha", REAL_RUNS[2][2], "head_sha c2709ea5510f vs API dc0bac809641"),
            ("started_at", "2026-08-19T05:59:58Z",
             "started_at 2026-08-19T05:59:58Z vs API 2026-08-19T05:59:57Z"),
        ):
            forged = golden_text.replace(GOLDEN[1], with_fields(GOLDEN[1], **{field: value}))
            findings, _ = check_online(forged, real_fixture(), FIXTURE_NOW)
            red(f"online-mismatch-forged-{field.replace('_', '-')}", findings, ["MISMATCH"],
                needle)

        running = _run(35000000002, "schedule", None, REAL_RUNS[4][2], "2026-09-12T10:00:00Z",
                       status="in_progress")
        findings, stats = check_online(golden_text, real_fixture(extra_runs=(running,)),
                                       FIXTURE_NOW)
        green("online-in-flight-run-not-lagged", findings,
              f"an in-progress run is not LAG (in flight: {stats['in_flight']})")

        dispatch = _run(35000000003, "workflow_dispatch", "success", REAL_RUNS[4][2],
                        "2026-09-17T12:00:00Z")
        findings, _ = check_online(golden_text, real_fixture(extra_runs=(dispatch,)), nine)
        red("online-stale-dispatch-does-not-refresh", findings, ["LAG", "STALE-SCHEDULE"],
            "34338263485, was created")

        findings, _ = check_online(ledger_text(["not a ledger line"]), real_fixture(),
                                   FIXTURE_NOW)
        red("online-refuses-malformed-ledger", findings, ["FORMAT"], "tab-separated")

        # ── the streak rule (§2 R4) ─────────────────────────────────────────
        def records(*lines: str) -> list[Record]:
            out = [parse_record(line, i)[0] for i, line in enumerate(lines, start=2)]
            if any(r is None for r in out):
                raise AssertionError("a streak plant is not a well-formed line")
            return out

        a = with_fields(GOLDEN[3], run_id="37000000001", started_at="2026-10-07T09:00:00Z")
        b = with_fields(GOLDEN[1], run_id="37000000002", started_at="2026-10-14T09:00:00Z")
        c = with_fields(GOLDEN[0], run_id="37000000003", started_at="2026-10-14T09:00:00Z")
        e = with_fields(GOLDEN[4], run_id="37000000004", started_at="2026-10-21T09:00:00Z")
        f_ = with_fields(GOLDEN[4], run_id="37000000005", event="workflow_dispatch",
                         started_at="2026-10-28T09:00:00Z")
        holds("streak-refused-neither-extends-nor-breaks", "property",
              streak(records(a, b, e))[0] == 2, "clean, refused, clean -> 2",
              f"clean, refused, clean gave {streak(records(a, b, e))[0]}")
        holds("streak-executed-red-resets", "property",
              streak(records(a, c, e))[0] == 1, "clean, executed red, clean -> 1",
              f"clean, red, clean gave {streak(records(a, c, e))[0]}")
        holds("streak-dispatch-does-not-count", "property",
              streak(records(a, e, f_))[0] == 2, "clean, clean, clean dispatch -> 2",
              f"a clean dispatch changed the streak to {streak(records(a, e, f_))[0]}")
    except CouldNotRun as exc:
        print(f"::error::check-devnet-ledger self-test: could not run: {exc}")
        return 3
    except Exception as exc:  # a crash is a red with a location, never a bare traceback
        last = arms[-1][0] if arms else "(no arm yet)"
        failures.append(f"CRASHED after arm {last}: {type(exc).__name__}: {shown(str(exc))}")

    # ── properties of the self-test itself ─────────────────────────────────
    uncovered = [t for t in OFFLINE_TAGS + ONLINE_TAGS if t not in produced]
    holds("tag-coverage", "property", not uncovered,
          f"all {len(OFFLINE_TAGS + ONLINE_TAGS)} declared tags reddened by a planted arm",
          f"declared tag(s) no planted arm produced: {uncovered} — an unexercised branch is "
          f"an assertion that cannot fail")
    greens = [name for name, kind in arms if kind == "green-control"]
    holds("green-controls", "property", len(greens) >= 2,
          f"{len(greens)} green controls — a suite of red arms alone cannot tell a working "
          f"check from one that reddens on everything",
          f"only {len(greens)} green control(s)")
    after = (digest(ledger_path), digest(script_path))
    holds("no-writes-to-the-real-tree", "hygiene", before == after,
          f"{LEDGER} and this script byte-identical before and after",
          f"the self-test changed a real file: {before} -> {after}")

    if failures:
        for failure in failures:
            print(f"::error::check-devnet-ledger self-test: {failure}")
        print(f"check-devnet-ledger self-test FAILED with {len(failures)} problem(s) — a green "
              f"run of the check proves nothing until these are fixed")
        return 1
    tally: dict[str, int] = {}
    for _, kind in arms:
        tally[kind] = tally.get(kind, 0) + 1
    print(f"check-devnet-ledger self-test PASS — {len(arms)} arm(s): "
          + ", ".join(f"{n} {k}" for k, n in sorted(tally.items())))
    return 0


def main(argv: list[str]) -> int:
    modes = {"--self-test": self_test, "--against-api": run_against_api,
             "--append": run_append}
    if len(argv) == 1:
        return run_offline()
    if len(argv) == 2 and argv[1] in modes:
        return modes[argv[1]]()
    print(f"usage: {Path(argv[0]).name} [--self-test | --against-api | --append]",
          file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
