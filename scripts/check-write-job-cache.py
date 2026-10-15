#!/usr/bin/env python3
"""A job that publishes or signs bytes restores no Actions cache (D171 §2 R5; task Q274).

── THE PROPERTY ───────────────────────────────────────────────────────────────

  Any job granted `pages: write`, `contents: write` or `id-token: write`
  contains no step using `Swatinem/rust-cache` or an action from the
  `actions/cache` repository (`actions/cache`, `actions/cache/restore`,
  `actions/cache/save`).

It is stated for the CLASS, not for one file, because `Q31`'s release job is
the next member (D171 §2 R5). Today exactly one job is in the class:
`pages.yml`'s `publish`, whose cache step D171 §2 R3 removed.

── WHY (D171 §1) ──────────────────────────────────────────────────────────────

Every job that runs on `main` holds the runtime token that creates Actions
cache entries, whatever its `GITHUB_TOKEN` scope, and a restore key's prefix
fallback returns the newest partial match. Cargo 1.92.0 re-verifies nothing
already on disk: a poisoned `registry/cache/*.crate`, an extracted source tree
marked `.cargo-ok`, and a dependency artifact in `target/` were each compiled
or linked silently, exit 0, under `--locked`, `--frozen` and `--offline`
(D171 §1.1). So a cache restored inside a job whose bytes are served or signed
is a channel from any live `main` job into those bytes, and the deploy's
two-environment comparison cannot see two of the four layers (D171 §1.4).
With nothing restored, every crate is downloaded and checked against
`Cargo.lock`'s checksum.

`actions/cache/save` restores nothing, so it cannot reach the job's own bytes.
It is matched anyway, deliberately: the rule stays one sentence a reviewer can
hold ("no action from the cache family in a write-scoped job"), and a job that
publishes has no reason to seed a cache that other jobs restore.

── HOW A JOB'S GRANT IS WORKED OUT ────────────────────────────────────────────

GitHub's rule, as this file models it:
  * a job-level `permissions:` REPLACES the workflow-level block for that job.
    It is not merged, and every scope it does not name is `none`;
  * a job with no `permissions:` of its own inherits the workflow-level block;
  * a job with neither runs under the REPOSITORY DEFAULT, which is a setting
    and not a file. This repository's is `read` (D143 §1.2), but the
    permissive default grants `contents: write`, so such a job cannot be shown
    to be outside the class. Rule W2 fails a job whose grant is undeclared AND
    that uses a cache action; an undeclared job that restores nothing is not
    this rule's business;
  * `write-all` is in the class; `read-all` and `{}` are not.

── THE RULES ──────────────────────────────────────────────────────────────────

  W1  a job granted pages, contents or id-token write uses no cache action
  W2  a job whose grant is declared at neither level uses no cache action
  W3  anti-vacuity: at least one job is in the class. Zero is a failure, not a
      pass (D171 §2 R5) — a scan that stopped seeing workflow-level grants
      would otherwise report a clean tree
  W4  every workflow parses inside the modelled YAML subset; anything else is
      REFUSED with its line, never guessed at
  W5  a job in the class calls no reusable workflow: the called workflow's
      jobs run under the caller's grant, and this checker does not follow calls

── WHAT IT CANNOT SEE. READ THIS BEFORE QUOTING A GREEN ───────────────────────

  1. A cache restored by any OTHER action. The match is by action name, so a
     `setup-*` action's `cache` input, `foundry-rs/foundry-toolchain`'s RPC
     cache, and a composite action (third-party, or local under `./`) that
     wraps `actions/cache` are all invisible. None runs in a write-scoped job
     today.
  2. A `run:` step that reaches the cache service itself (an `sccache` GHA
     backend, a `docker buildx` `type=gha` cache, a script using the cache
     toolkit). `run:` text is the wrong observable for that — the reason
     D124 RULING 2 refused a `run:`-text predicate for cargo.
  3. The repository's default permission and any organisation policy. They are
     settings, not files; W2 is the fail-closed answer, not a reading of them.
  4. A reusable workflow in this tree is judged by its own file. If its jobs
     declare no `permissions:`, they run under the CALLER's grant: W2 catches
     one only when it uses a cache action, and W5 fails the calling side when
     the caller is in this tree. A caller in another repository is invisible.
  5. Workflows anywhere but directly in `.github/workflows/` (GitHub loads none
     from subdirectories), and GitHub-managed dynamic workflows such as CodeQL
     default setup, which are not in the tree at all (D169 §2 R4).
  6. YAML beyond the modelled subset: anchors, aliases, merge keys, tags,
     flow-style jobs or steps, a second document. These are REFUSED (W4), not
     skipped, so this is a limit on what may be written, not a hole.

Every `*.yml` and `*.yaml` directly in the directory is read, dot-prefixed
names included, because GitHub's documented rule names no exception for them.
That is the fail-closed direction: `check-ci-shell.py --self-test` writes a
dot-prefixed copy of `ci.yml` there while it runs, and a copy of `ci.yml`
grants no write, so the most it can move is the job and file counts on the
ok line. Run the two in sequence, never together.

── SHAPE ──────────────────────────────────────────────────────────────────────

`check()` is a pure function of text: the `check-action-pins.py` and
`check-anchor-net.py` shape. `--self-test` plants every fault in an in-memory
copy or inside a `tempfile.TemporaryDirectory` it asserts is outside the
repository, so it writes nothing into the working tree. Each arm matches on its
RULE TAG and on the names the message must carry, never on exit status
(scripts/lib/red-arm.sh).

Python standard library only, deliberately: this runs on `ci-always.yml`'s
`traceability` job, which carries no toolchain, no cache and no `pip`, and in
`scripts/local-gate.sh`.

Usage:
    scripts/check-write-job-cache.py              check
    scripts/check-write-job-cache.py --self-test  prove every rule can go red
Exit: 0 pass, 1 failure.
"""

from __future__ import annotations

import re
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
WORKFLOW_DIR = REPO / ".github" / "workflows"

# The scopes that make a job one that publishes or signs bytes (D171 §2 R5):
# `pages: write` deploys the site, `contents: write` pushes refs and uploads
# release assets, and `id-token: write` mints the OIDC token that keyless
# signing and attestation exchange for a credential.
WRITE_SCOPES = ("contents", "id-token", "pages")
LEVELS = ("read", "write", "none")

# The cache family, compared lowercased: GitHub resolves `owner/repo` without
# regard to case, so `swatinem/Rust-Cache@…` runs the same action.
CACHE_ACTIONS = ("swatinem/rust-cache", "actions/cache")

KEY_RE = re.compile(r"""^(?P<q>["']?)(?P<key>[A-Za-z0-9_.-]+)(?P=q)\s*:(?:\s+(?P<value>\S.*?))?\s*$""")
SEQ_ITEM = re.compile(r"^-(?:\s+|$)")
DASHES = re.compile(r"^(?:-(?:\s+|$))+")
BLOCK_INDICATOR = re.compile(r"^[|>](?:[1-9][+-]?|[+-][1-9]?)?(?:\s+#.*)?$")


class Refused(Exception):
    """A construct outside the modelled subset, with the line it sits on."""

    def __init__(self, lineno: int, message: str) -> None:
        super().__init__(f"line {lineno}: {message}")
        self.lineno = lineno
        self.message = message


@dataclass
class Line:
    no: int
    indent: int
    text: str


@dataclass
class Grant:
    lineno: int
    form: str  # "scoped", "read-all" or "write-all"
    scopes: dict[str, str] = field(default_factory=dict)

    def writes(self) -> list[str]:
        if self.form == "write-all":
            return ["write-all"]
        return [f"{scope}: write" for scope, level in self.scopes.items()
                if scope in WRITE_SCOPES and level == "write"]


@dataclass
class Step:
    index: int
    lineno: int
    uses: str | None
    label: str


@dataclass
class Job:
    name: str
    lineno: int
    grant: Grant | None
    uses: str | None
    uses_lineno: int
    steps: list[Step]


@dataclass
class Result:
    workflows: int
    jobs: int = 0
    errors: list[str] = field(default_factory=list)
    # (workflow, job, "the write scopes, from where") for every job in the class
    examined: list[tuple[str, str, str]] = field(default_factory=list)


# ── parsing: a hand-rolled YAML subset that REFUSES what it does not model ─────


def significant_lines(text: str) -> list[Line]:
    """Every line that carries structure: comments, blanks and the BODIES of
    block scalars removed. A `uses:` inside a `run: |` body is text, never a
    step, and must not be read as one."""
    out: list[Line] = []
    floor: int | None = None
    for no, raw in enumerate(text.lstrip("\ufeff").split("\n"), 1):
        line = raw.rstrip()
        body = line.lstrip(" \t")
        lead = line[: len(line) - len(body)]
        if floor is not None:
            if not body or len(lead) > floor:
                continue
            floor = None
        if not body or body.startswith("#"):
            continue
        if "\t" in lead:
            raise Refused(no, "a TAB in the indentation, which YAML forbids")
        if body == "---" or body.startswith("--- "):
            if out:
                raise Refused(no, "a second YAML document (`---`)")
            continue
        if body == "...":
            raise Refused(no, "a YAML document end marker (`...`)")
        indent = len(lead)
        out.append(Line(no, indent, body))
        dashes = DASHES.match(body)
        width = dashes.end() if dashes else 0
        rest = body[width:]
        if width and BLOCK_INDICATOR.match(rest):
            floor = indent + body.rfind("-", 0, width)
        else:
            key = KEY_RE.match(rest)
            if key and key.group("value") and BLOCK_INDICATOR.match(key.group("value")):
                floor = indent + width
    return out


def mapping(lines: list[Line], col: int, where: str) -> list[tuple[Line, str, str | None, list[Line]]]:
    """The entries of a block mapping whose keys sit at column `col`, each as
    (its line, key, inline value or None, the lines of its nested value). A
    `- ` item at the key column belongs to the key above it (an indentless
    sequence, legal YAML)."""
    entries: list[tuple[Line, str, str | None, list[Line]]] = []
    for line in lines:
        if line.indent > col or (line.indent == col and entries and SEQ_ITEM.match(line.text)):
            if not entries:
                raise Refused(line.no, f"{line.text!r} is indented deeper than any key of {where}")
            entries[-1][3].append(line)
            continue
        if line.indent < col:
            raise Refused(line.no, f"{line.text!r} is indented less than the keys of {where}")
        match = KEY_RE.match(line.text)
        if not match:
            raise Refused(
                line.no,
                f"{line.text!r} where {where} holds `key:` entries (a flow mapping, a merge "
                f"key, a complex key or a stray scalar)",
            )
        value = match.group("value")
        if value is not None and value.startswith("#"):
            value = None
        entries.append((line, match.group("key"), value, []))
    return entries


def scalar(value: str, lineno: int, what: str) -> str:
    v = value.strip()
    kinds = {"&": "an anchor", "*": "an alias", "!": "a tag", "{": "a flow mapping",
             "[": "a flow sequence", "|": "a block scalar", ">": "a block scalar"}
    if v[:1] in kinds:
        raise Refused(lineno, f"{what} is {kinds[v[0]]} ({v!r}), which this checker does not model")
    if v[:1] in ("'", '"'):
        end = v.find(v[0], 1)
        if end < 0:
            raise Refused(lineno, f"{what} is a quoted scalar that does not close on its line")
        return v[1:end]
    return re.sub(r"\s+#.*$", "", v)


def add_scope(scopes: dict[str, str], scope: str, level: str, lineno: int, what: str) -> None:
    if level not in LEVELS:
        raise Refused(lineno, f"scope `{scope}` in {what} is {level!r}, not read, write or none")
    if scope in scopes:
        raise Refused(lineno, f"scope `{scope}` appears twice in {what}")
    scopes[scope] = level


def parse_permissions(line: Line, value: str | None, nested: list[Line], where: str) -> Grant:
    what = f"the `permissions:` of {where}"
    if value is None:
        if not nested:
            raise Refused(line.no, f"{what} is empty (a YAML null), which GitHub does not define")
        scopes: dict[str, str] = {}
        for entry, scope, level, deeper in mapping(nested, nested[0].indent, what):
            if level is None or deeper:
                raise Refused(entry.no, f"scope `{scope}` in {what} has a nested value, not read, write or none")
            add_scope(scopes, scope, scalar(level, entry.no, what), entry.no, what)
        return Grant(line.no, "scoped", scopes)
    v = value.strip()
    if not v.startswith("{"):
        word = scalar(v, line.no, what)
        if nested:
            raise Refused(nested[0].no, f"{what} has both an inline value and an indented block")
        if word in ("read-all", "write-all"):
            return Grant(line.no, word)
        raise Refused(line.no, f"{what} is {value!r}; only `read-all`, `write-all` or a mapping of scopes is modelled")
    if nested:
        raise Refused(nested[0].no, f"{what} has both a flow mapping and an indented block")
    body = re.sub(r"\s+#.*$", "", v)
    if not body.endswith("}"):
        raise Refused(line.no, f"{what} is a flow mapping that does not close on its line")
    inner = body[1:-1].strip()
    scopes = {}
    if inner:
        if any(c in inner for c in "{}[]&*!"):
            raise Refused(line.no, f"{what} nests a collection, anchor, alias or tag inside a flow mapping")
        for pair in inner.split(","):
            scope, colon, level = pair.partition(":")
            if not colon:
                raise Refused(line.no, f"{what} has a flow entry {pair.strip()!r} with no `:`")
            add_scope(scopes, scope.strip().strip("\"'"), level.strip().strip("\"'"), line.no, what)
    return Grant(line.no, "scoped", scopes)


def parse_steps(line: Line, value: str | None, nested: list[Line], job: str) -> list[Step]:
    if value is not None:
        raise Refused(line.no, f"`steps:` of job `{job}` is written inline ({value!r}); only a block sequence is modelled")
    if not nested:
        raise Refused(line.no, f"`steps:` of job `{job}` has no items")
    col = nested[0].indent
    items: list[list[Line]] = []
    for entry in nested:
        if entry.indent == col and SEQ_ITEM.match(entry.text):
            items.append([entry])
        elif entry.indent > col and items:
            items[-1].append(entry)
        else:
            raise Refused(entry.no, f"{entry.text!r} inside `steps:` of job `{job}`, where a `- ` item belongs")
    steps: list[Step] = []
    for index, item in enumerate(items, 1):
        first = item[0]
        dash = SEQ_ITEM.match(first.text)
        assert dash is not None  # every item was opened on a SEQ_ITEM line above
        rest = first.text[dash.end():]
        where = f"step {index} of job `{job}`"
        if rest:
            content_col = first.indent + dash.end()
            content = [Line(first.no, content_col, rest)] + item[1:]
        elif len(item) > 1:
            content_col = item[1].indent
            content = item[1:]
        else:
            raise Refused(first.no, f"{where} is empty")
        uses: str | None = None
        uses_lineno = first.no
        name = ident = ""
        for entry, key, kvalue, _deeper in mapping(content, content_col, where):
            if key == "uses":
                if kvalue is None:
                    raise Refused(entry.no, f"the `uses:` of {where} has no value")
                if uses is not None:
                    raise Refused(entry.no, f"{where} has two `uses:` keys")
                uses, uses_lineno = scalar(kvalue, entry.no, f"the `uses:` of {where}"), entry.no
            elif key == "name" and kvalue is not None:
                name = kvalue.strip().strip("\"'")
            elif key == "id" and kvalue is not None:
                ident = kvalue.strip().strip("\"'")
        steps.append(Step(index, uses_lineno, uses, name or ident))
    return steps


def parse_workflow(text: str) -> tuple[Grant | None, list[Job]]:
    lines = significant_lines(text)
    if not lines:
        raise Refused(1, "the file holds no YAML structure at all")
    grant: Grant | None = None
    jobs_entry: tuple[Line, str | None, list[Line]] | None = None
    seen: set[str] = set()
    for line, key, value, nested in mapping(lines, 0, "the workflow's top level"):
        if key in ("permissions", "jobs"):
            if key in seen:
                raise Refused(line.no, f"a second top-level `{key}:`")
            seen.add(key)
        if key == "permissions":
            grant = parse_permissions(line, value, nested, "the workflow")
        elif key == "jobs":
            jobs_entry = (line, value, nested)
    if jobs_entry is None:
        raise Refused(1, "no top-level `jobs:` — GitHub runs no such workflow, so the parser is wrong until shown otherwise")
    jobs_line, jobs_value, jobs_nested = jobs_entry
    if jobs_value is not None or not jobs_nested:
        raise Refused(jobs_line.no, "`jobs:` is not a block mapping")
    jobs: list[Job] = []
    names: set[str] = set()
    for jline, jname, jvalue, jnested in mapping(jobs_nested, jobs_nested[0].indent, "`jobs:`"):
        if jvalue is not None or not jnested:
            raise Refused(jline.no, f"job `{jname}` is not a block mapping ({jvalue!r})")
        if jname in names:
            raise Refused(jline.no, f"job `{jname}` is defined twice")
        names.add(jname)
        job = Job(jname, jline.no, None, None, 0, [])
        keys: set[str] = set()
        for kline, key, kvalue, knested in mapping(jnested, jnested[0].indent, f"job `{jname}`"):
            if key in ("permissions", "uses", "steps"):
                if key in keys:
                    raise Refused(kline.no, f"job `{jname}` has two `{key}:` keys")
                keys.add(key)
            if key == "permissions":
                job.grant = parse_permissions(kline, kvalue, knested, f"job `{jname}`")
            elif key == "uses":
                if kvalue is None:
                    raise Refused(kline.no, f"the `uses:` of job `{jname}` has no value")
                job.uses, job.uses_lineno = scalar(kvalue, kline.no, f"the `uses:` of job `{jname}`"), kline.no
            elif key == "steps":
                job.steps = parse_steps(kline, kvalue, knested, jname)
        jobs.append(job)
    return grant, jobs


def is_cache_action(uses: str | None) -> bool:
    if not uses:
        return False
    path = uses.split("@", 1)[0].lower()
    return any(path == name or path.startswith(name + "/") for name in CACHE_ACTIONS)


# ── the check ──────────────────────────────────────────────────────────────


def check(workflows: dict[str, str]) -> Result:
    """Pure function of text. Opens nothing, writes nothing, fetches nothing."""
    result = Result(workflows=len(workflows))
    for name in sorted(workflows):
        try:
            workflow_grant, jobs = parse_workflow(workflows[name])
        except Refused as refusal:
            result.errors.append(
                f"[W4] {name}:{refusal.lineno}: {refusal.message}. That is outside the YAML subset "
                f"this checker models, so it REFUSES rather than guess at a grant or a step. Write it "
                f"in plain block style, or teach parse_workflow() the construct together with a "
                f"self-test arm (D171 §2 R5)."
            )
            continue
        for job in jobs:
            result.jobs += 1
            if job.grant is not None:
                grant, source = job.grant, f"job-level `permissions:` at {name}:{job.grant.lineno}"
            elif workflow_grant is not None:
                grant, source = workflow_grant, f"workflow-level `permissions:` at {name}:{workflow_grant.lineno}"
            else:
                grant, source = None, ""
            cache_steps = [step for step in job.steps if is_cache_action(step.uses)]

            if grant is None:
                for step in cache_steps:
                    result.errors.append(
                        f"[W2] {name}:{step.lineno}: job `{job.name}` declares no `permissions:` and "
                        f"neither does its workflow, so it runs under the repository default, a "
                        f"setting this checker cannot read, and its step {step.index}"
                        f"{describe_label(step)} uses `{step.uses}`, an Actions cache action. Under "
                        f"a permissive default that job holds `contents: write`, the class D171 §2 R5 "
                        f"forbids a cache. Declare `permissions:` at the workflow or the job so the "
                        f"grant is visible in the tree."
                    )
                continue

            writes = grant.writes()
            if not writes:
                continue
            granted = ", ".join(writes)
            result.examined.append((name, job.name, f"{granted}, from the {source}"))
            for step in cache_steps:
                result.errors.append(
                    f"[W1] {name}:{step.lineno}: job `{job.name}` is granted {granted} (the "
                    f"{source}) and its step {step.index}{describe_label(step)} uses "
                    f"`{step.uses}`, an Actions cache action. A job that publishes or signs bytes "
                    f"restores no cache: any live job on `main` can create entries, and cargo "
                    f"re-checks nothing it restores against `Cargo.lock` (D171 §1.1, §2 R3, §2 R5). "
                    f"Remove the step."
                )
            if job.uses is not None:
                result.errors.append(
                    f"[W5] {name}:{job.uses_lineno}: job `{job.name}` is granted {granted} (the "
                    f"{source}) and calls the reusable workflow `{job.uses}`. The called jobs run "
                    f"under this grant and this checker does not follow the call, so it cannot show "
                    f"they restore no cache (D171 §2 R5). Inline the steps, or teach this checker to "
                    f"follow the call, with a self-test arm."
                )

    if not result.examined:
        result.errors.append(
            f"[W3] examined 0 jobs granted pages, contents or id-token write, among {result.jobs} "
            f"job(s) in {result.workflows} workflow file(s). This repository deploys from one "
            f"(`pages.yml` `publish`), so the scan is broken or the workflow set is wrong, and a "
            f"green here would be vacuous: a count of zero is a failure, not a pass (D171 §2 R5)."
        )
    return result


def describe_label(step: Step) -> str:
    return f" (`{step.label}`)" if step.label else ""


# ── I/O, kept out of check() ───────────────────────────────────────────────


def read_tree(directory: Path) -> dict[str, str]:
    """Every `*.yml` and `*.yaml` directly in `directory`, dot-prefixed names
    included (see the docstring for why)."""
    found: dict[str, str] = {}
    for pattern in ("*.yml", "*.yaml"):
        for path in directory.glob(pattern):
            if path.is_file():
                found[path.name] = path.read_bytes().decode("utf-8", errors="replace")
    return dict(sorted(found.items()))


# ── self-test ──────────────────────────────────────────────────────────────

RUST_CACHE_STEP = "      - uses: Swatinem/rust-cache@6323deb102c322ba6fcbdcafc7e3dddab59af2b6 # v2.9.2\n"

RESTORE_STEP = (
    "      - name: planted restore\n"
    "        uses: actions/cache/restore@0057852bfaa89a56745cba8c7296529d2fc39830 # v4.3.0\n"
    "        with:\n"
    "          path: ~/.cargo/registry\n"
    "          key: planted\n"
)

# A tag-triggered release workflow of the shape `Q31` may write: `.yaml`, and
# its steps as an INDENTLESS sequence, so the arms that use it also prove the
# glob reads that extension and the parser reads that legal YAML shape.
RELEASE_FIXTURE = (
    "name: release\n"
    "on:\n"
    "  push:\n"
    "    tags: ['v*']\n"
    "permissions:\n"
    "  contents: write\n"
    "jobs:\n"
    "  build:\n"
    "    runs-on: ubuntu-latest\n"
    "    steps:\n"
    "    - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4.4.0\n"
    "    - uses: actions/cache@0057852bfaa89a56745cba8c7296529d2fc39830 # v4.3.0\n"
    "      with:\n"
    "        path: target\n"
    "        key: planted\n"
)


def after(state: dict[str, str], name: str, anchor: str, text: str) -> bool:
    """Insert `text` after the first line that is exactly `anchor`."""
    before = state.get(name, "")
    state[name] = re.sub(rf"(?m)^({re.escape(anchor)})\n", lambda m: m.group(1) + "\n" + text, before, count=1)
    return state[name] != before


def swap(state: dict[str, str], name: str, old: str, new: str) -> bool:
    before = state.get(name, "")
    state[name] = before.replace(old, new, 1)
    return state[name] != before


def append(state: dict[str, str], name: str, text: str) -> bool:
    before = state.get(name, "")
    if not before:
        return False
    state[name] = before + ("" if before.endswith("\n") else "\n") + text
    return True


def self_test() -> int:
    """Fourteen planted faults in memory or in a temporary directory, two of
    them required to stay GREEN, and one control over the real tree.

    D171 §3's four plants are the first four arms: the `rust-cache` step
    re-added to `publish`, `actions/cache/restore` in its place, `contents:
    write` granted to a cache-restoring job in a temporary copy of the
    workflows, and an empty workflow set. The rest exercise the parser paths a
    green verdict depends on.
    """
    workflows = read_tree(WORKFLOW_DIR)
    ok = True

    control = check(dict(workflows))
    members = {(wf, job) for wf, job, _ in control.examined}
    print(f"  control (the real tree){'':45s} -> {'RED' if control.errors else 'GREEN'}, "
          f"examined {len(control.examined)} write-scoped job(s)")
    if control.errors:
        for failure in control.errors:
            print(f"    ::error:: control run is RED: {failure}")
        return 1
    # The one job this rule was written for must be SEEN, or the parser has
    # stopped reading workflow-level grants and every arm below proves nothing.
    # Asserted by membership rather than by count, so Q31's release job joins
    # the class without disarming this.
    if ("pages.yml", "publish") not in members:
        print(f"    ::error:: the control did not examine pages.yml `publish`; it examined {sorted(members)}")
        return 1

    def judge(label: str, result: Result | None, tag: str | None, must: tuple[str, ...]) -> None:
        nonlocal ok
        if result is None:
            print(f"  planted fault: {label:62s} -> NOT APPLIED")
            print("    ::error:: the mutation changed nothing, so the arm proves nothing")
            ok = False
            return
        if tag is None:  # a GREEN arm: nothing may fire, and the class must not move
            moved = sorted((wf, job) for wf, job, _ in result.examined) != sorted(members)
            print(f"  planted green: {label:62s} -> {'RED' if result.errors else 'GREEN'}"
                  f"{' (EXAMINED SET MOVED)' if moved else ''}")
            if result.errors or moved:
                for failure in result.errors:
                    print(f"      got: {failure}")
                if moved:
                    print(f"    ::error:: examined {sorted((wf, job) for wf, job, _ in result.examined)}, "
                          f"not {sorted(members)}")
                ok = False
            return
        matches = [m for m in result.errors if m.startswith(tag) and all(s in m for s in must)]
        print(f"  planted fault: {label:62s} -> {'RED' if result.errors else 'GREEN'} {tag}"
              f"{'' if matches else ' (NO MATCH)'}")
        if not result.errors:
            print("    ::error:: the check stayed GREEN over a planted fault")
        if not matches:
            print(f"    ::error:: no failure began {tag} and carried all of {must!r}")
            for failure in result.errors:
                print(f"      got: {failure}")
            ok = False

    def in_memory(label: str, mutate, tag: str | None, must: tuple[str, ...] = ()) -> None:
        state = dict(workflows)
        judge(label, check(state) if mutate(state) else None, tag, must)

    def in_tempdir(label: str, build, tag: str, must: tuple[str, ...]) -> None:
        with tempfile.TemporaryDirectory(prefix="check-write-job-cache-") as tmp:
            directory = Path(tmp).resolve()
            if directory == REPO or REPO in directory.parents:
                raise SystemExit(f"refusing to plant in {directory}: it is inside the repository")
            judge(label, check(read_tree(directory)) if build(directory) else None, tag, must)

    def copy_with(directory: Path, mutate) -> bool:
        state = dict(workflows)
        applied = mutate(state)
        for filename, text in state.items():
            (directory / filename).write_text(text, encoding="utf-8")
        return applied

    permissions_line = workflows.get("pages.yml", "").split("\n").index("permissions:") + 1 \
        if "permissions:" in workflows.get("pages.yml", "").split("\n") else 0

    # ── D171 §3, plant 1: the step §2 R3 removed, put back.
    in_memory("D171 §3: Swatinem/rust-cache re-added to pages.yml `publish`",
              lambda s: after(s, "pages.yml", "    steps:", RUST_CACHE_STEP),
              "[W1]", ("pages.yml:", "`publish`", "pages: write, id-token: write", "workflow-level",
                       "step 1", "Swatinem/rust-cache"))
    # ── D171 §3, plant 2: the class, not one action.
    in_memory("D171 §3: actions/cache/restore added to `publish` instead",
              lambda s: after(s, "pages.yml", "    steps:", RESTORE_STEP),
              "[W1]", ("pages.yml:", "`publish`", "`planted restore`", "actions/cache/restore"))
    # ── D171 §3, plant 3: a job-level grant, through the file-reading path.
    in_tempdir("D171 §3: contents: write on a cache-restoring job, temp copy",
               lambda d: copy_with(d, lambda s: after(
                   s, "reproducible-build.yml", "  reproducible-build:",
                   "    permissions:\n      contents: write\n")),
               "[W1]", ("reproducible-build.yml:", "`reproducible-build`", "contents: write",
                        "job-level", "Swatinem/rust-cache"))
    # ── D171 §3, plant 4: nothing to examine.
    in_tempdir("D171 §3: an empty workflow set",
               lambda d: not any(d.iterdir()),
               "[W3]", ("examined 0 jobs", "in 0 workflow file(s)"))

    # ── W3 over a FULL tree: the class emptied while every file still parses.
    in_memory("every write scope removed from pages.yml",
              lambda s: swap(s, "pages.yml", "  pages: write\n  id-token: write\n", ""),
              "[W3]", ("examined 0 jobs", f"in {len(workflows)} workflow file(s)"))
    # ── `write-all`, a quoted action, and the name in another case.
    in_memory("write-all, and 'swatinem/RUST-CACHE@…' quoted",
              lambda s: swap(s, "reproducible-build.yml", "permissions:\n  contents: read\n",
                             "permissions: write-all\n")
              and swap(s, "reproducible-build.yml", "- uses: Swatinem/rust-cache@6323deb102c322ba6fcbdcafc7e3dddab59af2b6",
                       "- uses: 'swatinem/RUST-CACHE@6323deb102c322ba6fcbdcafc7e3dddab59af2b6'"),
              "[W1]", ("reproducible-build.yml:", "write-all", "swatinem/RUST-CACHE"))
    # ── a flow-mapping grant at job level.
    in_memory("a job-level flow mapping granting id-token: write",
              lambda s: after(s, "verifier-page.yml", "  browser:",
                              "    permissions: { contents: read, id-token: write }  # planted\n"),
              "[W1]", ("verifier-page.yml:", "`browser`", "id-token: write", "job-level"))
    # ── GREEN: a job-level block REPLACES the workflow's. A merging parser
    # would hand `probe` the workflow's pages/id-token write and red here.
    in_memory("a read-only job-level block overrides a write workflow",
              lambda s: append(s, "pages.yml",
                               "  probe:\n    runs-on: ubuntu-latest\n    permissions:\n"
                               "      contents: read\n    steps:\n" + RUST_CACHE_STEP),
              None)
    # ── GREEN: a `run: |` body is shell text. The `uses:` lines alone could not
    # redden this arm — they sit deeper than any step key, so a parser with no
    # block-scalar handling would skip them too. The `---` line and the
    # TAB-indented line are what make it able to fail: both are legal inside a
    # block scalar and both are refused as structure, so deleting the
    # block-scalar skip in significant_lines() turns this arm RED with [W4].
    in_memory("a run: block scalar holding uses:, `---` and a TAB line",
              lambda s: after(s, "pages.yml", "    steps:",
                              "      - name: planted prose\n        run: |\n"
                              "          cat <<'EOF'\n"
                              "          ---\n"
                              "          uses: actions/cache@v4\n"
                              "          - uses: Swatinem/rust-cache@v2\n"
                              "          \tindented with a tab\n"
                              "          EOF\n"),
              None)
    # ── W2: the grant declared nowhere, on a job that restores a cache.
    in_memory("no permissions: at either level on a cache-restoring job",
              lambda s: swap(s, "reproducible-build.yml", "permissions:\n  contents: read\n", ""),
              "[W2]", ("reproducible-build.yml:", "`reproducible-build`", "declares no `permissions:`",
                       "Swatinem/rust-cache"))
    # ── W5: a write-scoped caller of a reusable workflow.
    in_memory("a write-scoped job calling a reusable workflow",
              lambda s: append(s, "pages.yml", "  call:\n    uses: ./.github/workflows/reproducible-build.yml\n"),
              "[W5]", ("pages.yml:", "`call`", "./.github/workflows/reproducible-build.yml"))
    # ── W4: an anchor where the grant is read. Refused, never guessed at.
    in_memory("an anchor on pages.yml's permissions block",
              lambda s: permissions_line > 0 and swap(s, "pages.yml", "\npermissions:\n", "\npermissions: &grant\n"),
              "[W4]", (f"pages.yml:{permissions_line}:", "an anchor"))
    # ── the `.yaml` extension and an indentless steps sequence.
    in_tempdir("a release.yaml with indentless steps restoring a cache",
               lambda d: (d / "release.yaml").write_text(RELEASE_FIXTURE, encoding="utf-8") > 0,
               "[W1]", ("release.yaml:12:", "`build`", "step 2", "actions/cache@", "contents: write"))
    # ── a dot-prefixed file is read (the docstring's claim, measured).
    in_tempdir("the same workflow under a dot-prefixed name",
               lambda d: (d / ".release.yml").write_text(RELEASE_FIXTURE, encoding="utf-8") > 0,
               "[W1]", (".release.yml:12:", "`build`"))

    return 0 if ok else 1


def main() -> int:
    if "--self-test" in sys.argv[1:]:
        rc = self_test()
        print("check-write-job-cache self-test " + ("PASS" if rc == 0 else "FAIL"))
        return rc

    result = check(read_tree(WORKFLOW_DIR))
    for failure in result.errors:
        print(f"::error::check-write-job-cache: {failure}")
    if result.errors:
        return 1
    members = "; ".join(f"{wf} `{job}` ({grant})" for wf, job, grant in result.examined)
    print(
        f"check-write-job-cache: examined {len(result.examined)} job(s) granted pages, contents or "
        f"id-token write [{members}] among {result.jobs} job(s) in {result.workflows} workflow "
        f"file(s); none uses Swatinem/rust-cache or an actions/cache action, and no job whose grant "
        f"is undeclared uses one either (D171 §2 R5)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
