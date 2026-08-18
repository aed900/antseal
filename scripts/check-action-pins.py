#!/usr/bin/env python3
"""Every GitHub Action this repository calls is pinned to the commit the ledger
names, and the ledger has not gone stale (D143, task **Q244**).

`.github/action-pins.tsv` is the AUTHORITY. The workflows are checked against
it; never the reverse. That direction is the whole design: a rule of the form
"every `uses:` is a 40-hex" has no subject a script can be wrong about, while
"which actions deserve a pin" is a judgement no script can make (D143 §2 R1).

── WHAT A PIN IS, AND WHAT IT IS NOT ──────────────────────────────────────────

Read D143 §1.4 before writing a comment about this. A 40-hex in a `uses:` line
is **not a checksum anything verifies**. The runner sends `{owner, repo, ref}`
to a closed-source Actions service, receives a server-supplied tarball URL, and
extracts whatever comes back with no digest, no checksum and no signature; the
`ResolvedSha` it is handed back is logged and never compared to anything
(`actions/runner` v2.336.0, `ActionManager.cs`). What the pin buys is that the
REQUEST IS SPECIFIC — a maintainer with write access to an action repository can
no longer re-point a tag under us. It buys nothing against GitHub itself, which
is the party holding the `pages: write` credential. Pinning is ruled on COST
(six of the nine major tags have not moved in 328-923 days, so freezing them
forfeits a stream of updates that does not exist), not as a security claim.

── THE TRAP THIS CHECKER EXISTS FOR ───────────────────────────────────────────

`gh api repos/Swatinem/rust-cache/git/ref/tags/v2` returns
`49a0bdc70d2e1b713ca9e2869b211fcce03d3c1c`. That is forty lowercase hex
characters, it is a real object in the real repository, and it is **not the
commit** — `v2` is an ANNOTATED tag, so the naive call yields the tag object and
the commit is `6323deb102c322ba6fcbdcafc7e3dddab59af2b6` one dereference away.
The one action where the obvious resolution method produces a wrong-but-
well-shaped answer is the genuinely third-party one that runs 19 times,
including in the only job with write scope.

So **P1 alone is a check that cannot fail**: `^[0-9a-f]{40}$` is green on
`49a0bdc7…`. P2 — the 40-hex must EQUAL the ledger's `sha` — is the rule that
carries the weight, and `49a0bdc70d2e1b713ca9e2869b211fcce03d3c1c` is its
mandatory planted fault (D143 §1.7, §2 R8). It may not be replaced with a
synthetic `deadbeef…`, which would exercise a different, easier fault.

Re-resolve with `gh api repos/<owner>/<action>/commits/<tag>`, which peels
annotated tags. Never with `git/ref/tags/<tag>`.

── THE RULES ──────────────────────────────────────────────────────────────────

  P1   every `uses:` ref is `^[0-9a-f]{40}$`
  P2   that 40-hex equals the ledger's `sha` for that action
  P3   the trailing comment is `# v<semver>` and equals the ledger's `version`
  P4a  every action a workflow uses has a ledger row
  P4b  every ledger row is used by at least one workflow
  P5   each row's `invocations` equals the count in the workflows
  P6   `today > next_review_utc` is RED; inside 14 days is a WARNING that
       still exits 0. The 90-day cadence in the ledger header is the renewal
       mechanism (D143 §2 R7) and this is what makes it a deadline rather than
       an intention: nothing hosted can run (every hosted job is refused with
       `steps: 0` since the allowance went), so the only venue that reddens is
       the local gate.
  P7   each `residual` line's parent action is still at the version the
       residual was recorded against. `actions/upload-pages-artifact@v3.0.1`
       is a COMPOSITE action whose own `action.yml:77` reads
       `uses: actions/upload-artifact@v4` — a bare moving tag one level below
       anything this repository can pin, inside the only job with `pages:
       write` (D143 §1.6). The residual line is committed so the hole is named
       where a checker can see it stop matching reality; P7 is what stops the
       parent being upgraded out from under it.

── SHAPE ──────────────────────────────────────────────────────────────────────

`check()` is a PURE FUNCTION OF TEXT. It takes the workflow contents, the
ledger content and a date; it opens nothing. `main()` reads the files and calls
it; `--self-test` plants each fault by string substitution on an in-memory copy
and calls it again. **Nothing in the self-test writes to the working tree.**

That is `scripts/check-anchor-net.py`'s shape (`read_tree`/`check`/in-memory
faults), deliberately and not `scripts/check-ci-paths.py`'s, which mutates and
reverts four TRACKED files in place — a live race on a tree several lanes write
at once. A pin checker has no such excuse (D143 §2 R8, §5.3).

Every arm matches on the RULE TAG of the returned failure, in-process, per
`scripts/lib/red-arm.sh`: a crash propagates and fails the harness instead of
satisfying an arm.

Usage:
    scripts/check-action-pins.py              check
    scripts/check-action-pins.py --self-test  prove every rule can go red
"""

from __future__ import annotations

import re
import sys
from datetime import date, timedelta
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
WORKFLOW_DIR = REPO / ".github" / "workflows"
LEDGER_PATH = REPO / ".github" / "action-pins.tsv"

# How many days before `next_review_utc` the check starts saying so. The warn
# tier exists only INSIDE a rule whose other tier is red (D143 §3.10); a
# warn-only checker is a checker that cannot fail.
WARN_WINDOW_DAYS = 14

# A `uses:` step. The `- ` marker is optional because a step may carry `id:` or
# `name:` first, and the indentation is preserved by whoever edits the line —
# this scan only reads.
#
# LIMIT, stated rather than hidden: this is a LINE scan, not a YAML parse. It
# agrees with a parse today because no `uses:` line is commented out and none
# appears inside a `run:` block scalar (D143 §1.1, falsifier 7). If those ever
# disagree the fix is to parse, not to widen this regex.
USES_RE = re.compile(
    r"^(?P<lead>\s*(?:-\s+)?)uses:\s*(?P<spec>\S+)(?P<rest>.*)$"
)
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
SEMVER_RE = re.compile(r"^v[0-9]+\.[0-9]+\.[0-9]+$")
COMMENT_RE = re.compile(r"^\s*#\s*(?P<comment>\S+)\s*$")

LEDGER_COLUMNS = ("action", "sha", "version", "tier", "invocations", "resolved_utc", "next_review_utc")


class Failures:
    """The check's verdict.

    Truthiness and length are the ERRORS alone, so a P6 warning prints without
    making the run red — which is exactly what the P6-warn arm asserts
    ("the warning text AND `Failures` empty").
    """

    def __init__(self) -> None:
        self.errors: list[str] = []
        self.warnings: list[str] = []

    def error(self, message: str) -> None:
        self.errors.append(message)

    def warn(self, message: str) -> None:
        self.warnings.append(message)

    def __bool__(self) -> bool:
        return bool(self.errors)

    def __len__(self) -> int:
        return len(self.errors)

    def __iter__(self):
        return iter(self.errors)


class Row:
    __slots__ = LEDGER_COLUMNS + ("lineno",)

    def __init__(self, fields: list[str], lineno: int) -> None:
        for name, value in zip(LEDGER_COLUMNS, fields):
            setattr(self, name, value)
        self.lineno = lineno

    @property
    def major_tag(self) -> str:
        """`v4.4.0` -> `v4`. The tag the review act re-resolves (D143 §2 R7)."""
        return self.version.split(".")[0]

    @property
    def reresolve(self) -> str:
        return f"gh api repos/{self.action}/commits/{self.major_tag}"


class Residual:
    """A transitive reference this repository cannot pin (D143 §1.6)."""

    __slots__ = ("parent", "version", "reference", "where", "lineno")

    def __init__(self, fields: list[str], lineno: int) -> None:
        self.parent, self.version, self.reference, self.where = fields[:4]
        self.lineno = lineno


# ── parsing ────────────────────────────────────────────────────────────────


def parse_ledger(text: str) -> tuple[list[Row], list[Residual], list[str]]:
    """Rows, residuals and structural complaints. Never raises on bad input."""
    rows: list[Row] = []
    residuals: list[Residual] = []
    problems: list[str] = []
    for lineno, line in enumerate(text.split("\n"), 1):
        if not line.strip():
            continue
        if line.startswith("#"):
            body = line[1:].lstrip(" ")
            fields = body.split("\t")
            if fields[0].strip() == "residual":
                if len(fields) < 5:
                    problems.append(
                        f"[P7] .github/action-pins.tsv:{lineno}: a `# residual` line needs "
                        f"5 tab-separated fields (residual, parent action, parent version, "
                        f"the transitive reference, where it lives); found {len(fields)}."
                    )
                else:
                    residuals.append(Residual(fields[1:], lineno))
            continue
        fields = line.split("\t")
        if len(fields) != len(LEDGER_COLUMNS):
            problems.append(
                f"[P4a] .github/action-pins.tsv:{lineno}: expected "
                f"{len(LEDGER_COLUMNS)} tab-separated fields "
                f"({', '.join(LEDGER_COLUMNS)}); found {len(fields)}: {line!r}"
            )
            continue
        rows.append(Row(fields, lineno))
    return rows, residuals, problems


def invocations(workflows: dict[str, str]) -> list[tuple[str, int, str, str | None]]:
    """Every `uses:` in the tree as (file, line, spec, trailing comment)."""
    found: list[tuple[str, int, str, str | None]] = []
    for name in sorted(workflows):
        for lineno, line in enumerate(workflows[name].split("\n"), 1):
            match = USES_RE.match(line)
            if not match:
                continue
            rest = match.group("rest")
            comment: str | None = None
            if rest.strip():
                comment_match = COMMENT_RE.match(rest)
                comment = comment_match.group("comment") if comment_match else rest.strip()
            found.append((name, lineno, match.group("spec"), comment))
    return found


def split_spec(spec: str) -> tuple[str, str]:
    """`owner/action@ref` -> (`owner/action`, `ref`). Never raises."""
    action, _, ref = spec.rpartition("@")
    return (action, ref) if action else (spec, "")


# ── the check ──────────────────────────────────────────────────────────────


def check(workflows: dict[str, str], ledger: str, today: date) -> Failures:
    """Pure function of text. Opens nothing, writes nothing, fetches nothing."""
    failures = Failures()
    rows, residuals, problems = parse_ledger(ledger)
    for problem in problems:
        failures.error(problem)
    by_action = {row.action: row for row in rows}

    for row in rows:
        if not SHA_RE.match(row.sha):
            failures.error(
                f"[P2] .github/action-pins.tsv:{row.lineno}: {row.action}'s ledger `sha` "
                f"{row.sha!r} is not a 40-hex lowercase commit SHA. Re-resolve with "
                f"`{row.reresolve}` — NOT with `git/ref/tags/`, which returns the TAG "
                f"OBJECT for an annotated tag (D143 §1.7)."
            )
        if not SEMVER_RE.match(row.version):
            failures.error(
                f"[P3] .github/action-pins.tsv:{row.lineno}: {row.action}'s ledger `version` "
                f"{row.version!r} is not an exact `vX.Y.Z`. A major-only version re-encodes "
                f"in the ledger the mutable pointer the pin exists to remove (D143 §2 R3)."
            )

    seen = invocations(workflows)

    # Anti-vacuity. Every rule below is a walk over `seen`; a scan that
    # collapsed would report a clean tree rather than a broken parser, and a
    # green verdict that means nothing is this project's dominant defect class.
    if not seen:
        failures.error(
            f"[P1] the `uses:` scan found ZERO invocations across "
            f"{len(workflows)} workflow file(s). This repository has 57, so the scan is "
            f"broken rather than the tree empty, and every verdict below is vacuous."
        )

    counted: dict[str, int] = {}
    for name, lineno, spec, comment in seen:
        action, ref = split_spec(spec)
        counted[action] = counted.get(action, 0) + 1
        row = by_action.get(action)

        # P4a first: everything after it reads the row.
        if row is None:
            failures.error(
                f"[P4a] {name}:{lineno}: {action} is used here but has no row in "
                f"`.github/action-pins.tsv`. Every action this repository calls is in the "
                f"ledger, or the ledger is not the authority. Resolve it with "
                f"`gh api repos/{action}/commits/<tag>` and add the row in this same commit "
                f"(D143 §2 R4)."
            )
            continue

        # P1 — shape. On its own this rule CANNOT FAIL on the fault that
        # matters: see the module docstring.
        if not SHA_RE.match(ref):
            failures.error(
                f"[P1] {name}:{lineno}: {action} is pinned to ref '{ref}' — not a "
                f"40-hex lowercase commit SHA. A tag is a pointer its owner can re-aim; "
                f"the ledger says this action is {row.sha} ({row.version}). "
                f"Re-resolve with `{row.reresolve}` (D143 §2 R3)."
            )
        elif ref != row.sha:
            # P2 — the rule that carries the weight.
            failures.error(
                f"[P2] {name}:{lineno}: {action} is pinned to {ref} but the ledger says "
                f"{row.sha}. The ledger is the authority; the workflow is checked against "
                f"it, never the reverse. If this is a deliberate bump, move the ledger row "
                f"in the same commit. If it came from `git/ref/tags/{row.major_tag}`, it is "
                f"the ANNOTATED TAG OBJECT rather than the commit — re-resolve with "
                f"`{row.reresolve}` (D143 §1.7)."
            )

        # P3 — the trailing comment.
        if comment is None:
            failures.error(
                f"[P3] {name}:{lineno}: {action} carries no trailing version comment. "
                f"It must read `# {row.version}` — the exact semver the ledger records, so "
                f"a reader can see WHICH release the 40-hex is without a network call "
                f"(D143 §2 R3)."
            )
        elif not SEMVER_RE.match(comment):
            failures.error(
                f"[P3] {name}:{lineno}: {action}'s trailing comment is {comment!r}, which is "
                f"not an exact `# vX.Y.Z`. `# {row.major_tag}` re-encodes in a comment the "
                f"mutable pointer the pin exists to remove; the ledger says "
                f"{row.version} (D143 §2 R3)."
            )
        elif comment != row.version:
            failures.error(
                f"[P3] {name}:{lineno}: {action}'s trailing comment says {comment} but the "
                f"ledger says {row.version} for {row.sha}. One of the two is stale, and a "
                f"comment that names the wrong release is worse than none — it is read and "
                f"believed (D143 §2 R3)."
            )

    # P4b — an unused row.
    for row in rows:
        if row.action not in counted:
            failures.error(
                f"[P4b] .github/action-pins.tsv:{row.lineno}: {row.action} has a ledger row "
                f"but is used by no workflow — an unused pin. A stale row is how a ledger "
                f"stops meaning anything: delete it, or restore the `uses:` that justified "
                f"it (D143 §2 R4)."
            )

    # P5 — the counts. This is the project's own "recount by script, never
    # increment" applied to the one inventory Q244 exists to hold: the row goes
    # wrong the moment a step is added or removed.
    for row in rows:
        if row.action not in counted:
            continue  # already reported by P4b
        try:
            declared = int(row.invocations)
        except ValueError:
            failures.error(
                f"[P5] .github/action-pins.tsv:{row.lineno}: {row.action}'s `invocations` "
                f"field {row.invocations!r} is not an integer."
            )
            continue
        actual = counted[row.action]
        if declared != actual:
            failures.error(
                f"[P5] .github/action-pins.tsv:{row.lineno}: {row.action} declares "
                f"{declared} invocation(s) but the workflows contain {actual}. Recount and "
                f"write the measured number — never increment a header count (D143 §2 R4). "
                f"Note that `grep`ping the action NAME over the workflow files gives a "
                f"different, larger number: three mentions of Swatinem/rust-cache are prose."
            )

    # P6 — the renewal deadline.
    for row in rows:
        try:
            due = date.fromisoformat(row.next_review_utc)
        except ValueError:
            failures.error(
                f"[P6] .github/action-pins.tsv:{row.lineno}: {row.action}'s "
                f"`next_review_utc` {row.next_review_utc!r} is not an ISO `YYYY-MM-DD` date."
            )
            continue
        if today > due:
            failures.error(
                f"[P6] .github/action-pins.tsv:{row.lineno}: {row.action}'s pin review was "
                f"due {due.isoformat()} and today is {today.isoformat()} — "
                f"{(today - due).days} day(s) overdue. Re-resolve it: `{row.reresolve}`. "
                f"Read the diff between {row.sha} and whatever comes back BEFORE adopting "
                f"it, then move the workflow lines, `sha`, `version`, `resolved_utc` and "
                f"`next_review_utc` together in one commit (D143 §2 R7)."
            )
        elif today > due - timedelta(days=WARN_WINDOW_DAYS):
            failures.warn(
                f"[P6] .github/action-pins.tsv:{row.lineno}: {row.action}'s pin review falls "
                f"due {due.isoformat()}, in {(due - today).days} day(s). Not red yet. "
                f"Re-resolve with `{row.reresolve}` (D143 §2 R7)."
            )

    # P7 — the residual's parent has not moved out from under it.
    for residual in residuals:
        row = by_action.get(residual.parent)
        if row is None:
            failures.error(
                f"[P7] .github/action-pins.tsv:{residual.lineno}: the residual names parent "
                f"{residual.parent}, which has no ledger row. The residual records that "
                f"{residual.reference} is resolved at run time inside "
                f"{residual.parent}'s own {residual.where} — if the parent is gone, say so "
                f"by deleting the residual, deliberately (D143 §1.6)."
            )
            continue
        if row.version != residual.version:
            failures.error(
                f"[P7] .github/action-pins.tsv:{residual.lineno}: the residual was recorded "
                f"against {residual.parent} {residual.version}, but the ledger now pins that "
                f"action at {row.version}. Re-read {residual.where} at the NEW commit before "
                f"touching this line: {residual.reference} is a bare moving tag resolved at "
                f"run time one level below anything this repository can pin, inside the only "
                f"job with `pages: write`. GitHub SHA-pinned that reference in its own "
                f"v5.0.0, so an upgrade may retire the residual — confirm it at the commit "
                f"being adopted and delete the line in that same act, never on the strength "
                f"of a record (D143 §1.6, §2 R6)."
            )

    return failures


# ── I/O, kept out of check() ───────────────────────────────────────────────


def read_tree() -> tuple[dict[str, str], str]:
    workflows = {
        path.name: path.read_text(encoding="utf-8")
        for path in sorted(WORKFLOW_DIR.glob("*.yml"))
    }
    return workflows, LEDGER_PATH.read_text(encoding="utf-8")


# ── self-test ──────────────────────────────────────────────────────────────


def self_test() -> int:
    """Nine planted faults and one green control, all in memory.

    Every fault is applied to an in-memory copy of the real tree, so this can
    never leave damage behind on a working tree other lanes are writing, and
    can never be skipped because a scratch directory was not writable.

    Every arm matches on the RULE TAG and on the substrings D143 §2 R8
    mandates, read out of the RETURNED failure list in-process. A traceback,
    an unplantable mutation or an unrelated red therefore fails the harness
    instead of satisfying an arm (scripts/lib/red-arm.sh).
    """
    workflows, ledger = read_tree()
    today = date.today()

    control = check(dict(workflows), ledger, today)
    print(f"  control (unmodified tree){'':44s} -> {'RED' if control else 'GREEN'}")
    for warning in control.warnings:
        print(f"    ::warning:: {warning}")
    if control:
        for failure in control:
            print(f"    ::error:: control run is RED: {failure}")
        return 1

    ok = True

    def arm(label: str, mutate, tag: str, must_contain: tuple[str, ...], expect_red: bool = True) -> None:
        """Plant one fault; require the named rule to fire with its own words."""
        nonlocal ok
        state = [dict(workflows), ledger, today]
        if not mutate(state):
            print(f"  planted fault: {label:56s} -> NOT APPLIED")
            print("    ::error:: the mutation did not change anything — the arm proves nothing")
            ok = False
            return
        result = check(state[0], state[1], state[2])
        pool = result.errors if expect_red else result.warnings
        matches = [m for m in pool if tag in m and all(s in m for s in must_contain)]
        verdict = "RED" if result else "GREEN"
        print(f"  planted fault: {label:56s} -> {verdict} {tag}{'' if matches else ' (NO MATCH)'}")
        if expect_red and not result:
            print("    ::error:: the check stayed GREEN over a planted fault")
            ok = False
        if not expect_red and result:
            print(f"    ::error:: a WARN-tier fault made the check RED: {result.errors}")
            ok = False
        if not matches:
            print(
                f"    ::error:: no {'failure' if expect_red else 'warning'} carried {tag} "
                f"together with all of {must_contain!r}"
            )
            for message in pool:
                print(f"      got: {message}")
            ok = False

    # ── P1: a bare major tag where a 40-hex belongs. The line is
    # `pages.yml:85`, the deploy step of the only job with write scope.
    def plant_a_bare_tag(state) -> bool:
        before = state[0]["pages.yml"]
        state[0]["pages.yml"] = before.replace(
            "uses: actions/deploy-pages@d6db90164ac5ed86f2b6aed7e0febac5b3c0c03e # v4.0.5",
            "uses: actions/deploy-pages@v4",
            1,
        )
        return state[0]["pages.yml"] != before

    # ── P2: THE MANDATORY FAULT (D143 §1.7, §2 R8). `49a0bdc7…` is the
    # ANNOTATED TAG OBJECT of Swatinem/rust-cache@v2 — forty lowercase hex
    # characters, a real object, and not the commit. It is what
    # `git/ref/tags/v2` returns and what any implementer using the obvious
    # resolution writes. P1 is GREEN on it. It may not be replaced with a
    # synthetic `deadbeef…`: that would exercise a different, easier fault.
    def plant_the_annotated_tag_object(state) -> bool:
        before = state[0]["pages.yml"]
        state[0]["pages.yml"] = before.replace(
            "Swatinem/rust-cache@6323deb102c322ba6fcbdcafc7e3dddab59af2b6",
            "Swatinem/rust-cache@49a0bdc70d2e1b713ca9e2869b211fcce03d3c1c",
            1,
        )
        return state[0]["pages.yml"] != before

    # ── P3: a trailing comment naming a release the SHA is not.
    def plant_a_stale_version_comment(state) -> bool:
        before = state[0]["pages.yml"]
        state[0]["pages.yml"] = before.replace("# v2.9.2", "# v2.9.1", 1)
        return state[0]["pages.yml"] != before

    # ── P4a: an action used with no ledger row. The victim is the
    # third-party one, whose whole reason for being in the ledger is that it
    # is not GitHub's.
    def delete_the_foundry_row(state) -> bool:
        before = state[1]
        state[1] = re.sub(r"^foundry-rs/foundry-toolchain\t.*\n", "", before, count=1, flags=re.MULTILINE)
        return state[1] != before

    # ── P4b: a ledger row no workflow uses.
    def add_an_unused_row(state) -> bool:
        before = state[1]
        state[1] = before.replace(
            "# RESIDUAL",
            "actions/stale\t"
            "28ca1036281a5e5922ead5184a1bbf96e5fc984e\tv9.1.0\tgithub-owned\t1\t"
            "2026-08-18\t2026-11-16\n# RESIDUAL",
            1,
        )
        return state[1] != before

    # ── P5: a step deleted without the ledger count moving. 19 -> 18.
    def delete_one_rust_cache_step(state) -> bool:
        before = state[0]["verifier-page.yml"]
        state[0]["verifier-page.yml"] = before.replace(
            "      - uses: Swatinem/rust-cache@6323deb102c322ba6fcbdcafc7e3dddab59af2b6 # v2.9.2\n",
            "",
            1,
        )
        return state[0]["verifier-page.yml"] != before

    overdue = (today - timedelta(days=1)).isoformat()
    due_soon = (today + timedelta(days=7)).isoformat()

    # ── P6 red: the review deadline has passed. The date is CONSTRUCTED from
    # `today`, never derived from what happens to be in the ledger, so the arm
    # cannot disarm itself as the real dates drift past.
    def plant_an_overdue_review(state) -> bool:
        before = state[1]
        state[1] = before.replace(
            "actions/checkout\t11d5960a326750d5838078e36cf38b85af677262\tv4.4.0\tgithub-owned\t23\t2026-08-18\t2026-11-16",
            f"actions/checkout\t11d5960a326750d5838078e36cf38b85af677262\tv4.4.0\tgithub-owned\t23\t2026-08-18\t{overdue}",
            1,
        )
        return state[1] != before

    # ── P6 warn: inside the window. This arm is GREEN and must still print —
    # a tier that produces no output is a tier nobody will ever act on.
    def plant_a_review_due_soon(state) -> bool:
        before = state[1]
        state[1] = before.replace(
            "Swatinem/rust-cache\t6323deb102c322ba6fcbdcafc7e3dddab59af2b6\tv2.9.2\tthird-party\t19\t2026-08-18\t2026-11-16",
            f"Swatinem/rust-cache\t6323deb102c322ba6fcbdcafc7e3dddab59af2b6\tv2.9.2\tthird-party\t19\t2026-08-18\t{due_soon}",
            1,
        )
        return state[1] != before

    # ── P7: the residual's parent upgraded out from under the residual line.
    def bump_the_residual_parent(state) -> bool:
        before = state[1]
        state[1] = before.replace(
            "actions/upload-pages-artifact\t56afc609e74202658d3ffba0e8f6dda462b719fa\tv3.0.1",
            "actions/upload-pages-artifact\t56afc609e74202658d3ffba0e8f6dda462b719fa\tv5.0.0",
            1,
        )
        return state[1] != before

    arm("P1  pages.yml:85 reverted to the bare tag `@v4`", plant_a_bare_tag,
        "[P1]", ("pages.yml:85", "deploy-pages", "'v4'"))
    arm("P2  rust-cache pinned to its ANNOTATED TAG OBJECT", plant_the_annotated_tag_object,
        "[P2]", ("49a0bdc70d2e1b713ca9e2869b211fcce03d3c1c",
                 "6323deb102c322ba6fcbdcafc7e3dddab59af2b6", "ledger"))
    arm("P3  a trailing comment saying v2.9.1", plant_a_stale_version_comment,
        "[P3]", ("v2.9.1", "v2.9.2"))
    arm("P4a an action used with no ledger row", delete_the_foundry_row,
        "[P4a]", ("foundry-rs/foundry-toolchain",))
    arm("P4b a ledger row no workflow uses", add_an_unused_row,
        "[P4b]", ("actions/stale", "unused"))
    arm("P5  a step deleted, the count left at 19", delete_one_rust_cache_step,
        "[P5]", ("Swatinem/rust-cache", "19", "18"))
    arm("P6  a review deadline one day past", plant_an_overdue_review,
        "[P6]", ("actions/checkout", overdue,
                 "gh api repos/actions/checkout/commits/v4"))
    arm("P6  a review deadline seven days out (WARN, green)", plant_a_review_due_soon,
        "[P6]", ("Swatinem/rust-cache", due_soon,
                 "gh api repos/Swatinem/rust-cache/commits/v2"),
        expect_red=False)
    arm("P7  the residual's parent bumped to v5.0.0", bump_the_residual_parent,
        "[P7]", ("upload-pages-artifact", "v3.0.1", "v5.0.0"))

    return 0 if ok else 1


def main() -> int:
    if "--self-test" in sys.argv[1:]:
        rc = self_test()
        print("check-action-pins self-test " + ("PASS" if rc == 0 else "FAIL"))
        return rc

    workflows, ledger = read_tree()
    result = check(workflows, ledger, date.today())
    for warning in result.warnings:
        print(f"::warning::check-action-pins: {warning}")
    for failure in result:
        print(f"::error::check-action-pins: {failure}")
    if result:
        return 1

    rows, residuals, _ = parse_ledger(ledger)
    total = sum(int(row.invocations) for row in rows)
    third_party = [row.action for row in rows if row.tier == "third-party"]
    due = min(date.fromisoformat(row.next_review_utc) for row in rows)
    print(
        f"check-action-pins: {total} `uses:` invocation(s) across {len(workflows)} workflow(s) "
        f"are each pinned to the 40-hex COMMIT `.github/action-pins.tsv` names, with the exact "
        f"`# vX.Y.Z` it records; {len(rows)} ledger row(s), every one used, "
        f"{len(third_party)} third-party ({', '.join(sorted(third_party))}); "
        f"{len(residuals)} residual transitive reference(s) still at the recorded parent "
        f"version; next pin review {due.isoformat()}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
