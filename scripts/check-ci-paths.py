#!/usr/bin/env python3
"""A CI path filter is an assertion that cannot fail. This is the thing that can (D138/Q239).

`on.push.paths-ignore` has no failure mode. When it is wrong the job simply
does not run, and the absence of a red is indistinguishable from a green. Every
other guard in this repository fails loudly when its subject drifts; a path
filter fails **silently, in the direction of running less**, which is the one
direction nothing downstream can observe. So the filter needs an instrument that
lives outside it and re-derives, on every push, that the excluded set is still
unread by the workflow it excludes.

── WHAT IS EXCLUDED, AND WHY IT IS SO SMALL ────────────────────────────────

`DOCS_ONLY` below is the whole exclusion. It is three entries, not `docs/**`,
and the smallness is the finding rather than caution:

  * `docs/decisions/**` CANNOT be excluded. `docs/decisions/D18-wasm-bindgen-
    surface-location.md` carries `wasm-bindgen-cli --version 0.2.126` at lines
    752 and 976, and `scripts/wasm-toolchain-audit.sh:161-162` greps
    `.github/workflows scripts docs` for exactly that literal to assert the CLI
    pin equals the crate pin. Those two lines in a decision record are live
    inputs to ci.yml's `wasm32-core-tests` job. Measured 2026-08-16.
  * `docs/**` CANNOT be excluded for the same reason, plus a dozen others:
    `docs/format/**`, `docs/testing/error-code-contract.md`,
    `docs/security-assumptions.md`, `docs/threat-model.md`,
    `docs/zeroization-audit.md`, `docs/dependency-policy.md` and
    `docs/testing/cbor-cross-check.md` are all read by tests in the `test` job.
  * `MVP-SPEC.md` CANNOT be excluded: four runtime readers, three of them in
    ci.yml (`crates/antseal-wasm/tests/page_template.rs:153`,
    `crates/antseal-core/tests/tamper_completeness/mod.rs:86`,
    `crates/antseal-core/src/anchor/model.rs:1630`).

── WHAT THIS CHECKS ────────────────────────────────────────────────────────

R1  DOCS_ONLY is byte-equal, and in order, to ci.yml's `on.push.paths-ignore`.
    One definition, mirrored once, held in step here — the BOUNDARY_COPIES
    idiom of scripts/check-traceability.py, not two lists and a comment.
R2  No workflow filters `pull_request` by path, and a filtered `push` uses
    `paths-ignore` and never `paths`. See "the two are not complements" below.
R3  The per-event required-context sets are exactly REQUIRED_CONTEXTS and
    REQUIRED_CONTEXTS - PUSH_EXEMPT, with no context produced twice on the
    same event by two workflows.
R4  THE LOAD-BEARING RULE. No excluded path is read by anything the filtered
    workflow runs. Three detectors, because no one of them is complete:
      R4a a whole-string path literal, on a non-comment line, in a reader;
      R4b `include_str!`/`include_bytes!`, resolved against the source file;
      R4c a registered `grep -r` surface whose PATTERN matches an excluded
          file's CONTENT — the D18 class above, which is content-conditional
          and therefore has to be re-run rather than reasoned about once.
R5  Anti-vacuity: every pattern matches at least one tracked file, the
    exclusion does not match everything, and every file it matches has a
    suffix on ALLOWED_EXCLUDED_SUFFIXES — so a `.py` dropped into `tasks/`
    reds instead of quietly becoming unbuilt code.
R6  The cheap checkers that must survive a docs push are in a workflow whose
    `push` carries no path filter at all.

── WHAT IT CANNOT CATCH. READ THIS BEFORE TRUSTING A GREEN ─────────────────

  1. A read whose path is COMPUTED and never appears as a literal —
     `root.join("TO" + "DO.md")`, `glob("*.md")` over the repo root, a path
     assembled from a variable. R4a sees string literals; it does not execute
     the program. `tasks/**` is defensible today because R5 pins the suffix set
     and the directory has one shape; a repo-wide `**/*.md` walk in a new test
     would be invisible to every rule here.
  2. A read by a THIRD-PARTY action rather than by a committed script. The
     reader set is derived from `run:` blocks (Q43 guarantees each is a script
     call), so `uses:` steps are opaque. Today none reads repo docs.
  3. SEMANTIC dependence without a read: a test asserting a number that a
     human keeps in step with a sentence in an excluded file. Nothing
     mechanical can see that.
  4. The filter being too NARROW. Everything here guards against excluding too
     much. Excluding too little only costs minutes, and is not an error.
  5. GitHub's own matching. This file models a documented subset of the glob
     syntax and REFUSES the rest (see `translate_pattern`) rather than
     guessing; it does not observe what GitHub actually did with a push.

── THE TWO ARE NOT COMPLEMENTS (the shape this ruling refused) ─────────────

The obvious design is two mirrored workflows — one on `paths: DOCS`, one on
`paths-ignore: DOCS` — so that exactly one fires and the cheap lanes keep their
context names. It cannot work, and the reason is in GitHub's semantics rather
than in this repository: both filters quantify EXISTENTIALLY over the changed
set. `paths-ignore: [D]` runs iff some changed file is outside D; `paths: [D]`
runs iff some changed file is inside D. A push touching one doc and one source
file satisfies BOTH, so both workflows fire and every shared context appears
twice. R3's duplicate check is what stops that shape being rebuilt by accident.

Usage:
    scripts/check-ci-paths.py              check
    scripts/check-ci-paths.py --self-test  plant faults; each must go red BY ITS
                                           OWN MESSAGE, not by exit status
    scripts/check-ci-paths.py --inventory  print the reader set and the excluded
                                           file set (diagnostic, not a gate)
Exit: 0 pass, 1 failure, 2 bad usage.

Python standard library only, deliberately: this runs on the `traceability`
job, which carries no toolchain, no cache and no `pip` — and which
`scripts/cargo-free.sh` asserts invokes no cargo.
"""

from __future__ import annotations

import functools
import posixpath
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
WORKFLOWS_DIR = REPO / ".github" / "workflows"

# ── The exclusion. THE definition; ci.yml mirrors it and R1 holds them equal ──
#
# Each entry is here because a measurement says nothing ci.yml runs reads it,
# and each is a FILE or a one-level directory rather than a tree, because a
# tree exclusion is the thing that grows silently. Adding an entry is a
# decision: run `--inventory`, then this check, and expect R4 to have an
# opinion.
DOCS_ONLY: list[str] = [
    # The task register. Read by scripts/check-traceability.py only, which
    # runs on `ci-always` — never by anything ci.yml starts. 8 of the 10
    # docs-only pushes measured over 2026-08-01..16 touched it.
    "TODO.md",
    # The per-domain task detail files, same reader, same workflow.
    "tasks/**",
    # The CI runbook and branch-protection payload. Read by NOTHING — it is
    # cited in three comments (scripts/local-gate.sh:62,130 and
    # scripts/wasm-tests.sh:6) and opened by no program. 5 of the 10.
    "docs/ci-verification.md",
]

# R5. A file the exclusion matches whose suffix is not here is a file that
# might be code, and code that no lane compiles is the failure this guards.
ALLOWED_EXCLUDED_SUFFIXES = {".md"}

# ── The context set (R3) ────────────────────────────────────────────────────
#
# Nineteen, unchanged by D138: the split MOVED jobs between workflows and
# removed none, so branch protection's payload (docs/ci-verification.md) is
# untouched. NEVER shrink this list to make a check pass — a context that
# stops being produced is a required check that hangs a PR for ever.
REQUIRED_CONTEXTS = {
    "fmt", "clippy", "test", "wasm32-core", "wasm32-core-tests", "core-dep-graph",
    "cross-os-linux", "cross-os-macos", "cross-os-windows", "golden-vectors",
    "cross-check", "vector-freeze", "format-freeze", "wasm-bitmatch",
    "tamper-matrix", "fuzz-smoke", "audit-deny", "secret-guard", "traceability",
}

# Contexts deliberately NOT produced on a push, each with the reason. They are
# still produced on `pull_request`, which is what keeps them safe to require.
PUSH_EXEMPT = {
    "cross-os-macos": "bills 10x (13.2 weighted min/run); weekly on cross-os-extended.yml",
    "cross-os-windows": "bills 2x (9.7 weighted min/run); weekly on cross-os-extended.yml",
}

# R6. A docs push that changes TODO.md and gets no traceability check is
# strictly worse than no filter at all.
MUST_RUN_ON_EVERY_PUSH = {"traceability", "secret-guard"}

# ── R4c: grep surfaces ──────────────────────────────────────────────────────
#
# A reader that greps a whole DIRECTORY for a pattern makes every file under it
# a conditional input: the file feeds the job only when its bytes match. A
# directory-level rule cannot express that, so the pattern is registered and
# re-run here against the excluded files on every push. The literal is asserted
# to still be present in the named script, so the copy cannot go stale
# unnoticed; if it moves, this reds and names the file.
GREP_SURFACES: list[tuple[str, str, tuple[str, ...], str]] = [
    (
        "scripts/wasm-toolchain-audit.sh",
        r"wasm-bindgen-cli[^\n]*--version [0-9]+\.[0-9]+\.[0-9]+",
        (".github/workflows", "scripts", "docs"),
        "wasm-bindgen crate/CLI pin equality, ci.yml `wasm32-core-tests`. This is "
        "the surface that makes docs/decisions/** unexcludable: D18 carries two "
        "matching lines.",
    ),
]

# ── R4a: mentions that are provably NOT reads ───────────────────────────────
#
# The check-ci-shell.py ALLOWED_INLINE idiom, including its best half: an entry
# nothing uses is a failure, because a stale exemption is how an allowlist stops
# meaning anything. Keys are `(reader, excluded-path)`.
INERT_MENTIONS: dict[tuple[str, str], str] = {
    ("scripts/wasm-bitmatch.sh", "TODO.md"):
        "a NEGATIVE control in `--trigger-self-test` ARM 3 (:328): the heredoc lists "
        "paths that must NOT select the bit-match lane. It is the opposite of a read — "
        "the arm fails if the lane reacts to this path at all.",
    ("scripts/wasm-bitmatch.sh", "tasks/Q.md"):
        "the same heredoc, one line down (:329). Same reason.",
}

# ── The script closure (R4a's reader set) ───────────────────────────────────
#
# A lane's real reader is usually two calls deep — `ci.yml` -> `wasm-tests.sh`
# -> `wasm-toolchain-audit.sh` is where the D18 grep surface lives — so the
# reader set has to follow edges. But it must NOT follow them blindly, and the
# reason is measured rather than theoretical: `scripts/ci-lanes.sh` is a
# nine-lane dispatcher, ci.yml calls it with seven subcommands, and NONE of
# them is `traceability`. A blind closure therefore drags
# `scripts/check-traceability.py` into ci.yml's reader set, and since that file
# opens TODO.md 14 times, every exclusion in this file becomes unprovable. That
# is D124 RULING 2's trap in a new suit: reading one level into a multi-lane
# callee attributes every lane's behaviour to every lane.
#
# So every edge is CLASSIFIED, one of the two dicts below, with its reason, and
# an edge in neither is a hard failure. Adding a `scripts/x` reference to a
# script ci.yml runs is thereby a reviewed event rather than a silent widening
# of what this check believes. Both dicts carry a stale-entry rule.
FOLLOW_EDGES: dict[tuple[str, str], str] = {
    ("scripts/wasm-tests.sh", "scripts/wasm-toolchain-audit.sh"):
        "unconditional in cmd_check (:54) — and it is THE surface that makes "
        "docs/decisions/** unexcludable (see GREP_SURFACES).",
    ("scripts/wasm-tests.sh", "scripts/wasm-test-runner.mjs"):
        "cargo's `runner` for the wasm32 target; executes on every --check.",
    ("scripts/wasm-bitmatch.sh", "scripts/wasm-bitmatch.mjs"):
        "the comparator the lane's only real step invokes.",
    ("scripts/wasm-bitmatch.sh", "scripts/wasm-imports.mjs"):
        "the import-surface assertion, run by the same lane.",
    ("scripts/cross-check.sh", "scripts/crosscheck-provenance.py"):
        "runs FIRST on every --check/--self-test (D31 §6b ordering).",
}
# Edges that exist in the file but are NOT reachable from the arguments ci.yml
# actually passes. Each names why. If ci.yml ever gains the subcommand named
# here, move the entry to FOLLOW_EDGES in the same commit.
UNREACHED_EDGES: dict[tuple[str, str], str] = {
    ("scripts/ci-lanes.sh", "scripts/check-traceability.py"):
        "reached only from lane_traceability. ci.yml calls ci-lanes.sh with "
        "--self-test, audit-deny, cbor-drift-guard, dep-graph, golden-vectors, "
        "tamper-matrix and cross-os — never `traceability`, which lives on "
        "ci-always.yml. THIS IS THE LOAD-BEARING ENTRY: check-traceability.py "
        "opens TODO.md and tasks/*.md, and following this edge would make every "
        "exclusion in DOCS_ONLY unprovable.",
    ("scripts/ci-lanes.sh", "scripts/check-anchor-net.py"):
        "reached only from lane_anchor_net_policy, a ci-always.yml step.",
    ("scripts/ci-lanes.sh", "scripts/check-ci-shell.py"):
        "reached only from lane_ci_shell, a ci-always.yml step.",
    ("scripts/ci-lanes.sh", "scripts/cargo-free.sh"):
        "named in prose about the traceability job's arming; not invoked.",
    ("scripts/ci-lanes.sh", "scripts/cross-check.sh"):
        "named in a comment about the sibling lane; ci-lanes.sh does not run it. "
        "cross-check.sh is a level-0 reader in its own right anyway.",
    ("scripts/ci-lanes.sh", "scripts/vector-freeze.sh"):
        "named in a comment; also a level-0 reader in its own right.",
    ("scripts/ci-lanes.sh", "scripts/fuzz.sh"):
        "reached from lane_fuzz_budget (`fuzz.sh targets`), a ci-always.yml step. "
        "fuzz.sh is a level-0 reader in its own right anyway.",
    ("scripts/ci-lanes.sh", "scripts/e2e-devnet.sh"):
        "named in prose about the devnet-e2e-cron.yml lane; not invoked here.",
    ("scripts/ci-lanes.sh", "scripts/local-gate.sh"):
        "named in prose about the local gate; not invoked.",
    ("scripts/ci-lanes.sh", "scripts/sign-release.sh"):
        "named in lane_secret_guard's comment explaining WHY rule (4b) is "
        "anchored on `untrusted comment: ` — sign-release.sh emits the "
        "SHA256SUMS.minisig and per-artifact signatures the un-anchored Q245 "
        "pattern falsely reported. Not invoked, and it never can be: D71 §2 "
        "R1/R7 forbid the signing key on any runner, so sign-release.sh is a "
        "local-only act by ruling. scripts/verify-release.sh is the half a "
        "runner may call, and it is not named here.",
    ("scripts/ci-lanes.sh", "scripts/wasm-imports.mjs"):
        "named in prose about the bitmatch lane; not invoked from here.",
    ("scripts/cargo-free.sh", "scripts/check-ci-shell.py"):
        "cited in the header's refusal note (D124 RULING 2); not invoked.",
    ("scripts/cargo-free.sh", "scripts/gate-features.sh"):
        "cited as the near-miss that produced the row; not invoked.",
    ("scripts/gate-features.sh", "scripts/local-gate.sh"):
        "READ as data (`sed` of GATE_LIGHT_FEATURES), not executed — and it is "
        "already covered as a reader by the `test` job, which opens it at "
        "crates/antseal-core/tests/feature_pins.rs:581.",
    ("scripts/gate-features.sh", "scripts/e2e-devnet.sh"):
        "named in the HEAVY_TRIGGER_PATHS list as a path, not invoked.",
    ("scripts/wasm-tests.sh", "scripts/gate-features.sh"):
        "cited in a comment about lane placement; not invoked. gate-features.sh "
        "is a level-0 reader in its own right anyway.",
    ("scripts/wasm-tests.sh", "scripts/local-gate.sh"):
        "cited in a comment about the local dual; not invoked.",
    ("scripts/wasm-bitmatch.sh", "scripts/wasm-tests.sh"):
        "named in the trigger asymmetry arm as a PATH that must not select this "
        "lane; not invoked. Level-0 reader in its own right anyway.",
    ("scripts/wasm-bitmatch.sh", "scripts/wasm-toolchain-audit.sh"):
        "same asymmetry arm, same reason; reached via wasm-tests.sh regardless.",
    ("scripts/wasm-bitmatch.sh", "scripts/wasm-test-runner.mjs"):
        "same asymmetry arm; reached via wasm-tests.sh regardless.",
    ("scripts/wasm-bitmatch.sh", "scripts/wasm-pack-build.sh"):
        "cited in a comment about the page lane (verifier-page.yml); not invoked.",
    # The two .mjs modules cite their siblings in header comments only. Node
    # modules here never shell out: they are given their inputs by the shell
    # script that invokes them, so an outbound edge from one is always prose.
    ("scripts/wasm-imports.mjs", "scripts/ci-lanes.sh"):
        "header comment naming the sibling rule (:20); this module runs no shell.",
    ("scripts/wasm-imports.mjs", "scripts/wasm-bitmatch.mjs"):
        "header comment listing the other node hosts (:27); not invoked.",
    ("scripts/wasm-imports.mjs", "scripts/wasm-test-runner.mjs"):
        "same comment, same line (:27); not invoked.",
    ("scripts/wasm-imports.mjs", "scripts/wasm-pack-build.sh"):
        "header comment about the page artifact (:46); not invoked.",
    ("scripts/wasm-bitmatch.mjs", "scripts/wasm-bitmatch.sh"):
        "header comment naming its own CALLER (:6) — the edge points backwards.",
    ("scripts/wasm-bitmatch.mjs", "scripts/wasm-test-runner.mjs"):
        "header comment citing the shared technique (:13); not invoked.",
}

# Reader files are scanned for path literals; these suffixes are the ones that
# can carry one. `.md` is absent on purpose — a doc citing a doc is not a read,
# and including it would make every rule here fire on prose.
READER_SUFFIXES = {".rs", ".py", ".sh", ".mjs", ".js", ".toml", ".json", ".html"}

# Directories never walked: build output and VCS internals.
PRUNE_DIRS = {".git", "target", "node_modules", "__pycache__", ".venv", "dist", ".devnet"}

# A `run:` block that compiles or tests the workspace makes every crate a
# reader. Over-approximating the reader set is the SAFE direction: it can only
# make R4 stricter.
WORKSPACE_READER_ROOTS = ("crates", "fuzz", "verifier-web", "probes")
WORKSPACE_TOKENS = ("cargo test", "cargo build", "cargo clippy", "cargo fmt")

SCRIPT_CALL = re.compile(r"(?:^|\s|\|\||&&|;)(?:bash\s+|sh\s+|python3\s+|node\s+|\./)?(scripts/[\w.-]+)")
# A comment line is one whose FIRST non-space token is a comment marker.
# Trailing comments are deliberately NOT stripped: over-reporting is safe,
# under-reporting is a hole. scripts/check-anchor-net.py's docstring records
# what a cleverer stripper did to that check.
COMMENT_LINE = re.compile(r"^\s*(//|///|//!|#|\*|/\*|--)")
QUOTED = re.compile(r"""(['"`])([^'"`\n]{1,200}?)\1""")
INCLUDE_MACRO = re.compile(r"""include_(?:str|bytes)!\s*\(\s*"([^"\n]+)"\s*\)""")
# A bare (unquoted) shell token that looks like a repo path.
SHELL_BARE = re.compile(r"(?<![\w./$-])((?:tasks|docs|testdata|scripts|crates)/[\w./+-]+|TODO\.md)")


# `--self-test` runs the whole check 19 times over the same tree, and the check
# reads 422 files. Without a cache that is 8 000 opens and the self-test cost
# 21.9 s measured; with it, 2.7 s. Keyed on (mtime_ns, size) so the arms that
# MUTATE a file in the tree still see the mutation — a cache keyed on path
# alone would have made nine of the eighteen arms green-by-staleness, which is
# the assertion-that-cannot-fail class this whole file is about.
_TEXT_CACHE: dict[str, tuple[int, int, str]] = {}


def read_cached(path: Path) -> str:
    key = str(path)
    stat = path.stat()
    hit = _TEXT_CACHE.get(key)
    if hit is not None and hit[0] == stat.st_mtime_ns and hit[1] == stat.st_size:
        return hit[2]
    text = path.read_text(encoding="utf-8", errors="replace")
    _TEXT_CACHE[key] = (stat.st_mtime_ns, stat.st_size, text)
    return text


class Failures:
    """Rule-tagged findings, so a self-test arm can match on WHICH rule fired."""

    def __init__(self) -> None:
        self.items: list[tuple[str, str]] = []

    def add(self, rule: str, message: str) -> None:
        self.items.append((rule, message))

    def rules(self) -> set[str]:
        return {rule for rule, _ in self.items}

    def __bool__(self) -> bool:
        return bool(self.items)

    def __len__(self) -> int:
        return len(self.items)


# ── Glob translation ────────────────────────────────────────────────────────

@functools.lru_cache(maxsize=None)
def translate_pattern(pattern: str) -> re.Pattern[str]:
    """GitHub's path-filter glob, for the subset this file models.

    REFUSES the rest by raising, rather than guessing. `!` negation in
    particular is order-sensitive in GitHub's evaluation, and a matcher that
    quietly mis-models it would report a green exclusion that GitHub reads
    differently — the exact silent failure this whole file exists to prevent.
    """
    for bad in ("!", "[", "]", "{", "}", "+", "?"):
        if bad in pattern:
            raise ValueError(
                f"path pattern {pattern!r} uses `{bad}`, which this matcher does not "
                f"model. Either express the exclusion without it, or teach "
                f"translate_pattern() the semantics AND plant a self-test arm for it. "
                f"Guessing here produces a filter that reads one way to this check and "
                f"another way to GitHub."
            )
    out, i = [], 0
    while i < len(pattern):
        if pattern.startswith("**", i):
            out.append(".*")
            i += 2
        elif pattern[i] == "*":
            out.append("[^/]*")
            i += 1
        else:
            out.append(re.escape(pattern[i]))
            i += 1
    return re.compile("^" + "".join(out) + "$")


def matches_any(path: str, patterns: list[str]) -> bool:
    for pattern in patterns:
        if translate_pattern(pattern).match(path):
            return True
        # `tasks/**` must also match the directory entry `tasks/x.md` when the
        # pattern is written `tasks/**`; GitHub treats `**` as "and everything
        # below", including the zero-segment case for a directory prefix.
        if pattern.endswith("/**") and (path == pattern[:-3] or path.startswith(pattern[:-2])):
            return True
    return False


# ── Tree ────────────────────────────────────────────────────────────────────

def tracked_files(root: Path) -> list[str]:
    """Every repo-relative file path, git-free (this lane asserts no cargo and
    has no need of git either; `os.walk` sees a plain checkout identically)."""
    out: list[str] = []
    stack = [root]
    while stack:
        directory = stack.pop()
        for entry in sorted(directory.iterdir()):
            if entry.is_symlink():
                continue
            if entry.is_dir():
                if entry.name not in PRUNE_DIRS:
                    stack.append(entry)
            elif entry.is_file():
                out.append(entry.relative_to(root).as_posix())
    return sorted(out)


# ── Workflow parsing (hand-rolled, stdlib-only, refuses what it cannot model) ─

def workflows(root: Path) -> list[Path]:
    directory = root / ".github" / "workflows"
    return sorted(p for p in directory.glob("*.yml") if not p.name.startswith("."))


def _block(lines: list[str], start: int, indent: int) -> tuple[list[str], int]:
    """Lines strictly more indented than `indent`, from `start`."""
    body, i = [], start
    while i < len(lines):
        line = lines[i]
        if line.strip() and (len(line) - len(line.lstrip())) <= indent:
            break
        body.append(line)
        i += 1
    return body, i


def parse_triggers(text: str) -> dict[str, dict[str, list[str]]]:
    """`{event: {"paths": [...], "paths-ignore": [...]}}` for each `on:` event.

    An event with no filters maps to empty lists, which is what R2/R3 read as
    "unfiltered" — distinct from the event being absent from the dict at all.
    """
    lines = text.splitlines()
    out: dict[str, dict[str, list[str]]] = {}
    for i, line in enumerate(lines):
        if not re.match(r"^on:\s*$", line):
            continue
        body, _ = _block(lines, i + 1, 0)
        j = 0
        while j < len(body):
            m = re.match(r"^  ([a-z_]+):\s*(\S.*)?$", body[j])
            if not m:
                j += 1
                continue
            event = m.group(1)
            out.setdefault(event, {"paths": [], "paths-ignore": []})
            sub, j = _block(body, j + 1, 2)
            key = None
            for entry in sub:
                km = re.match(r"^    (paths|paths-ignore):\s*$", entry)
                if km:
                    key = km.group(1)
                    continue
                im = re.match(r"^      - (\S.*)$", entry)
                if im and key:
                    out[event][key].append(im.group(1).strip().strip("\"'"))
                    continue
                if entry.strip() and re.match(r"^    \S", entry):
                    key = None
        return out
    raise ValueError("no `on:` block found — the workflow parser is broken, not the workflow")


def parse_contexts(text: str, name: str) -> list[str]:
    """Every check-run name a workflow produces, matrix arms expanded."""
    lines = text.splitlines()
    start = None
    for i, line in enumerate(lines):
        if re.match(r"^jobs:\s*$", line):
            start = i + 1
            break
    if start is None:
        raise ValueError(f"{name}: no `jobs:` block")
    body, _ = _block(lines, start, 0)
    out: list[str] = []
    i = 0
    while i < len(body):
        m = re.match(r"^  ([\w-]+):\s*$", body[i])
        if not m:
            i += 1
            continue
        job_body, i = _block(body, i + 1, 2)
        job_text = "\n".join(job_body)
        nm = re.search(r"^    name:\s*(\S.*)$", job_text, re.M)
        if not nm:
            raise ValueError(
                f"{name}: job `{m.group(1)}` has no `name:`. Every job's name is a "
                f"required status context; an unnamed job produces one this check "
                f"cannot see"
            )
        template = nm.group(1).strip().strip("\"'")
        labels = re.findall(r"^\s+- label:\s*(\S+)\s*$", job_text, re.M)
        if "${{" in template:
            if "${{ matrix.label }}" not in template or not labels:
                raise ValueError(
                    f"{name}: job name {template!r} interpolates an expression this "
                    f"check cannot expand. Only `${{{{ matrix.label }}}}` over a "
                    f"`- label:` matrix is modelled; anything else must be taught "
                    f"here, with a self-test arm, before it lands"
                )
            out.extend(template.replace("${{ matrix.label }}", label) for label in labels)
        else:
            out.append(template)
    if not out:
        raise ValueError(f"{name}: parsed zero jobs — the parser is broken")
    return out


# ── Reader set ──────────────────────────────────────────────────────────────

def run_bodies(text: str) -> list[str]:
    """Every `run:` body. Shares check-ci-shell.py's shape deliberately: that
    file is the authority on what a `run:` block is, and this one only needs to
    know which scripts are named."""
    out: list[str] = []
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        m = re.match(r"^(\s*)-?\s*run:\s*(\S.*)?$", lines[i])
        if not m:
            i += 1
            continue
        indent, inline = m.group(1), m.group(2)
        if inline is None:
            i += 1
            continue
        if inline not in ("|", ">", "|-", ">-"):
            out.append(inline)
            i += 1
            continue
        body, i = [], i + 1
        while i < len(lines):
            if lines[i].strip() and not lines[i].startswith(indent + " "):
                break
            body.append(lines[i])
            i += 1
        out.append("\n".join(body))
    return out


SCRIPT_LITERAL = re.compile(r"scripts/[\w.-]+\.(?:sh|py|mjs|js)")


def reader_set(
    root: Path, workflow_text: str, files: list[str], failures: Failures | None = None
) -> list[str]:
    """Every committed file whose CONTENT can decide this workflow's verdict.

    Closed over the CLASSIFIED edges only (FOLLOW_EDGES). Every other
    `scripts/x` literal found in a script already in the set must be in
    UNREACHED_EDGES with its reason; an unclassified one is reported through
    `failures` so a new edge is a reviewed event rather than a silent change of
    what this check believes it is looking at.

    If any `run:` block compiles or tests the workspace, every crate joins the
    set — over-approximating THERE is the safe direction, since it can only
    make R4 stricter.
    """
    seen: set[str] = set()
    frontier: list[str] = []
    workspace = False
    used_follow: set[tuple[str, str]] = set()
    used_unreached: set[tuple[str, str]] = set()
    for body in run_bodies(workflow_text):
        frontier.extend(SCRIPT_CALL.findall(body))
        if any(token in body for token in WORKSPACE_TOKENS):
            workspace = True
    while frontier:
        script = frontier.pop()
        if script in seen or Path(script).name.startswith("."):
            continue
        path = root / script
        if not path.is_file():
            continue
        seen.add(script)
        text = read_cached(path)
        for nested in sorted(set(SCRIPT_LITERAL.findall(text))):
            if nested == script or Path(nested).name.startswith("."):
                continue
            edge = (script, nested)
            if edge in FOLLOW_EDGES:
                used_follow.add(edge)
                frontier.append(nested)
            elif edge in UNREACHED_EDGES:
                used_unreached.add(edge)
            elif failures is not None:
                failures.add(
                    "R4e",
                    f"{script} names {nested} and that edge is classified in neither "
                    f"FOLLOW_EDGES nor UNREACHED_EDGES. Decide which: if the filtered "
                    f"workflow can reach {nested}, its reads count and the edge must be "
                    f"followed; if it cannot, say so and say why. Leaving it unclassified "
                    f"means this check silently guesses at the reader set it is asserting "
                    f"over.",
                )
    if failures is not None:
        for edge in sorted(set(FOLLOW_EDGES) - used_follow):
            failures.add("R4e", f"FOLLOW_EDGES carries {edge}, which no longer exists; delete it")
        for edge in sorted(set(UNREACHED_EDGES) - used_unreached):
            failures.add("R4e", f"UNREACHED_EDGES carries {edge}, which no longer exists; delete it")
    if workspace:
        seen.update(
            f for f in files
            if f.startswith(tuple(r + "/" for r in WORKSPACE_READER_ROOTS))
            and Path(f).suffix in READER_SUFFIXES
        )
    return sorted(f for f in seen if Path(f).suffix in READER_SUFFIXES)


# ── R4a/R4b: literals ───────────────────────────────────────────────────────

def crate_root(root: Path, reader: str) -> str:
    """The nearest ancestor of `reader` holding a Cargo.toml — i.e. what
    `env!("CARGO_MANIFEST_DIR")` expands to for that source file.

    This exists because the FIRST version of this check missed
    `MVP-SPEC.md` entirely, and its own `--self-test` is what said so. Both
    readers spell the path as an offset from the crate manifest, not from the
    source file:

        crates/antseal-wasm/tests/page_template.rs:153
            fs::read_to_string(PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../MVP-SPEC.md"))
        crates/antseal-core/tests/tamper_completeness/mod.rs:86
            concat!(env!("CARGO_MANIFEST_DIR"), "/../../MVP-SPEC.md")

    Anchoring on the source file's directory resolves the first to
    `crates/MVP-SPEC.md` and the second to an absolute path, and neither
    matches anything — so the rule reported GREEN over a genuine read. Do not
    "simplify" this back to one anchor.
    """
    directory = posixpath.dirname(reader)
    while directory:
        if (root / directory / "Cargo.toml").is_file():
            return directory
        directory = posixpath.dirname(directory)
    return ""


def _candidates(reader: str, literal: str, manifest_dir: str) -> set[str]:
    """Repo-relative paths a string literal in `reader` could name."""
    out: set[str] = set()
    if not literal or " " in literal or literal.startswith(("http", "//")):
        return out
    values = {literal}
    # `"$repo/TODO.md"` / `"${root}/tasks/Q.md"` — drop one leading expansion.
    values.add(re.sub(r"^\$\{?\w+\}?/", "", literal))
    # `concat!(env!("CARGO_MANIFEST_DIR"), "/../../MVP-SPEC.md")` — the literal
    # half begins with the separator that joined it.
    if literal.startswith("/"):
        values.add(literal[1:])
    for value in values:
        if not value or not re.fullmatch(r"[A-Za-z0-9_.+@/-]+", value):
            continue
        for anchor in {"", posixpath.dirname(reader), manifest_dir}:
            out.add(posixpath.normpath(posixpath.join(anchor, value)))
    return {c for c in out if c and not c.startswith(("..", "/")) and c != "."}


def scan_reader(root: Path, reader: str, excluded: list[str]) -> list[tuple[int, str, str]]:
    """`(line, excluded-path, evidence)` for every apparent read of an
    excluded path in one reader file."""
    try:
        text = read_cached(root / reader)
    except OSError:
        return []
    hits: list[tuple[int, str, str]] = []
    is_shell = reader.endswith(".sh")
    manifest_dir = crate_root(root, reader)
    for lineno, line in enumerate(text.splitlines(), 1):
        # R4b first: an include_ macro is a read even on a line that also
        # carries a comment, and its path is relative to the SOURCE FILE (that
        # anchor is fixed by the compiler, unlike the runtime cases below).
        for rel in INCLUDE_MACRO.findall(line):
            resolved = posixpath.normpath(posixpath.join(posixpath.dirname(reader), rel))
            if matches_any(resolved, excluded):
                hits.append((lineno, resolved, "include_str!/include_bytes!"))
        if COMMENT_LINE.match(line):
            continue
        for _, literal in QUOTED.findall(line):
            for candidate in _candidates(reader, literal, manifest_dir):
                if matches_any(candidate, excluded):
                    hits.append((lineno, candidate, f"string literal {literal!r}"))
        if is_shell:
            for token in SHELL_BARE.findall(line):
                for candidate in _candidates(reader, token, manifest_dir):
                    if matches_any(candidate, excluded):
                        hits.append((lineno, candidate, f"unquoted shell token {token!r}"))
    return hits


# ── The check ───────────────────────────────────────────────────────────────

def check(root: Path, docs_only: list[str] | None = None) -> Failures:
    failures = Failures()
    docs_only = DOCS_ONLY if docs_only is None else docs_only
    files = tracked_files(root)
    texts = {p.name: read_cached(p) for p in workflows(root)}
    if not texts:
        failures.add("R0", "no workflows found at all — the scan is vacuous")
        return failures

    try:
        triggers = {name: parse_triggers(text) for name, text in texts.items()}
        contexts = {name: parse_contexts(text, name) for name, text in texts.items()}
    except ValueError as exc:
        failures.add("R0", str(exc))
        return failures

    # ── R1: one definition, mirrored once ──────────────────────────────────
    filtered = [
        name for name, events in triggers.items()
        if events.get("push", {}).get("paths") or events.get("push", {}).get("paths-ignore")
    ]
    if filtered != ["ci.yml"]:
        failures.add(
            "R1",
            f"expected exactly one push-filtered workflow (`ci.yml`), found {filtered or 'none'}. "
            f"Every added filter needs its own reader-set derivation; this check models one.",
        )
    mirror = triggers.get("ci.yml", {}).get("push", {}).get("paths-ignore", [])
    if mirror != docs_only:
        failures.add(
            "R1",
            f"ci.yml's `on.push.paths-ignore` is {mirror!r} but DOCS_ONLY is {docs_only!r}. "
            f"They are one list in two places and must be equal, in order — edit both in "
            f"the same commit or the filter and its guard are describing different repos.",
        )

    # ── R2: pull_request unfiltered; a filtered push uses paths-ignore ─────
    for name, events in sorted(triggers.items()):
        pr = events.get("pull_request")
        if pr is not None and (pr["paths"] or pr["paths-ignore"]):
            failures.add(
                "R2",
                f"{name}: `pull_request` carries a path filter. A required status "
                f"context whose workflow is SKIPPED by path filtering never reports, "
                f"and the pull request stays pending for ever — GitHub does not treat a "
                f"never-started workflow as a passing check. Filter `push` only.",
            )
        push = events.get("push")
        if push and push["paths"]:
            failures.add(
                "R2",
                f"{name}: `push` uses `paths:`. Use `paths-ignore:`. The two are not "
                f"complements — both quantify existentially over the changed set, so a "
                f"push touching one doc and one source file matches BOTH and every "
                f"shared context is produced twice.",
            )

    # ── R3: contexts, per event ────────────────────────────────────────────
    for event, expected in (
        ("pull_request", set(REQUIRED_CONTEXTS)),
        ("push", set(REQUIRED_CONTEXTS) - set(PUSH_EXEMPT)),
    ):
        produced: dict[str, list[str]] = {}
        for name, events in triggers.items():
            if event not in events:
                continue
            for context in contexts[name]:
                produced.setdefault(context, []).append(name)
        for context, owners in sorted(produced.items()):
            if len(owners) > 1:
                failures.add(
                    "R3",
                    f"context `{context}` is produced on `{event}` by {owners} — two "
                    f"workflows claiming one required check. GitHub shows two check "
                    f"runs of the same name and branch protection cannot tell them "
                    f"apart.",
                )
        missing = expected - set(produced)
        extra = set(produced) - expected
        if missing:
            failures.add(
                "R3",
                f"on `{event}` these required contexts are produced by no workflow: "
                f"{sorted(missing)}. On `pull_request` that hangs a protected PR for "
                f"ever; on `push` it means a lane silently stopped running.",
            )
        if extra:
            failures.add(
                "R3",
                f"on `{event}` these contexts are produced but are not in "
                f"REQUIRED_CONTEXTS: {sorted(extra)}. A new context is a "
                f"branch-protection change (docs/ci-verification.md), never a "
                f"side effect — register it here in the same commit.",
            )

    # ── R6: the cheap checkers survive a docs push ─────────────────────────
    unfiltered_push_contexts = {
        context
        for name, events in triggers.items()
        if "push" in events and not (events["push"]["paths"] or events["push"]["paths-ignore"])
        for context in contexts[name]
    }
    for context in sorted(MUST_RUN_ON_EVERY_PUSH - unfiltered_push_contexts):
        failures.add(
            "R6",
            f"`{context}` is not produced by any workflow whose `push` is unfiltered. "
            f"A docs push that edits TODO.md and gets no `{context}` check is strictly "
            f"worse than no path filter at all — that lane's inputs ARE the docs.",
        )

    # ── R5: anti-vacuity ───────────────────────────────────────────────────
    try:
        excluded_files = [f for f in files if matches_any(f, docs_only)]
    except ValueError as exc:
        failures.add("R5", str(exc))
        return failures
    if not excluded_files:
        failures.add("R5", f"DOCS_ONLY {docs_only!r} matches no file in the tree — the filter is inert")
    if len(excluded_files) == len(files):
        failures.add("R5", "DOCS_ONLY matches EVERY file — ci.yml would never run on a push")
    for pattern in docs_only:
        if not [f for f in files if matches_any(f, [pattern])]:
            failures.add(
                "R5",
                f"DOCS_ONLY entry {pattern!r} matches no file. A pattern matching nothing "
                f"is a stale exemption; delete it or fix the spelling — it is silently "
                f"buying nothing while reading as protection.",
            )
    for path in excluded_files:
        if Path(path).suffix not in ALLOWED_EXCLUDED_SUFFIXES:
            failures.add(
                "R5",
                f"{path} is excluded from ci.yml's push trigger but its suffix is not on "
                f"ALLOWED_EXCLUDED_SUFFIXES {sorted(ALLOWED_EXCLUDED_SUFFIXES)}. A "
                f"non-document under an excluded path is code that no lane compiles.",
            )

    # ── R4: the load-bearing rule ──────────────────────────────────────────
    used_inert: set[tuple[str, str]] = set()
    readers = reader_set(root, texts.get("ci.yml", ""), files, failures)
    if len(readers) < 50:
        failures.add(
            "R4",
            f"the ci.yml reader set resolved to only {len(readers)} file(s). It should "
            f"be several hundred (every crate, plus the script closure). A collapsed "
            f"reader set makes every rule below vacuously green.",
        )
    for reader in readers:
        for lineno, path, evidence in scan_reader(root, reader, docs_only):
            key = (reader, path)
            if key in INERT_MENTIONS:
                used_inert.add(key)
                continue
            failures.add(
                "R4a",
                f"{reader}:{lineno} names `{path}` ({evidence}), and `{path}` is EXCLUDED "
                f"from ci.yml's push trigger — but {reader} is run by ci.yml. Editing "
                f"`{path}` would not start the job that reads it, and the absence of that "
                f"job looks exactly like a pass. Either drop the exclusion, or register "
                f"the mention in INERT_MENTIONS with the reason it is not a read.",
            )
    for key in sorted(set(INERT_MENTIONS) - used_inert):
        failures.add(
            "R4a",
            f"INERT_MENTIONS carries {key} but nothing found that mention any more; "
            f"delete the entry. A stale exemption is how an allowlist stops meaning "
            f"anything.",
        )

    for script, pattern, roots, why in GREP_SURFACES:
        source = root / script
        if not source.is_file():
            failures.add("R4c", f"GREP_SURFACES names {script}, which does not exist")
            continue
        text = read_cached(source)
        if pattern not in text:
            failures.add(
                "R4c",
                f"the registered grep pattern for {script} is no longer present in it "
                f"verbatim. The copy here has drifted from the source; re-read "
                f"{script} and update GREP_SURFACES, because until then this rule is "
                f"guarding a surface that no longer exists. ({why})",
            )
            continue
        compiled = re.compile(pattern)
        for path in excluded_files:
            if not any(path == r or path.startswith(r.rstrip("/") + "/") for r in roots):
                continue
            body = read_cached(root / path)
            if compiled.search(body):
                failures.add(
                    "R4c",
                    f"{path} is excluded from ci.yml's push trigger, but its CONTENT now "
                    f"matches the pattern {script} greps for over {list(roots)} — so it "
                    f"has just become an input to a ci.yml job that this push will not "
                    f"run. Remove the matching text or remove the exclusion. ({why})",
                )
    return failures


# ── Self-test ───────────────────────────────────────────────────────────────

def self_test(root: Path) -> int:
    """Plant a fault per rule and require the check to go red BY ITS RULE TAG.

    scripts/lib/red-arm.sh: an arm that judges on exit status alone certifies a
    surface it never exercised. Every arm below matches on the tag of the
    failure `check()` RETURNS, in-process, so a crash propagates and fails the
    harness rather than satisfying an arm — and a finding unrelated to the
    planted fault cannot pass for the planted one.
    """
    ok = True
    control = check(root)
    print(f"  control (unmodified tree){'':44s} -> {'RED' if control else 'GREEN'}")
    if control:
        for rule, message in control.items:
            print(f"    ::error:: control is RED [{rule}]: {message}")
        return 1

    def arm(label: str, want: str, docs_only: list[str] | None = None,
            mutate: tuple[str, str, str] | None = None) -> None:
        """`mutate` = (repo-relative file, old, new), applied and reverted."""
        nonlocal ok
        target = original = None
        if mutate:
            rel, old, new = mutate
            target = root / rel
            original = target.read_text(encoding="utf-8")
            if old not in original:
                print(f"    ::error:: self-test fault {label!r} did not apply: {old!r} absent from {rel}")
                ok = False
                return
            target.write_text(original.replace(old, new, 1), encoding="utf-8")
        try:
            found = check(root, docs_only)
        finally:
            if target is not None and original is not None:
                target.write_text(original, encoding="utf-8")
        got = found.rules()
        verdict = "RED" if want in got else "GREEN"
        print(f"  planted fault: {label:52s} -> {verdict} {sorted(got)}")
        if want not in got:
            print(
                f"    ::error:: expected rule {want} to fire and it did not "
                f"(rules that did: {sorted(got) or 'none'}). The check cannot see this "
                f"fault, so its green says nothing about this class."
            )
            ok = False

    # R4a — the fault this file exists for: exclude a path that ci.yml reads.
    # MVP-SPEC.md is read by crates/antseal-wasm/tests/page_template.rs:153 and
    # two others, all under `test`.
    arm("exclude MVP-SPEC.md, which ci.yml's `test` reads", "R4a",
        docs_only=DOCS_ONLY + ["MVP-SPEC.md"])
    # R4a via include_str! resolution, which no string-literal-only scan sees
    # as a repo path: the literal is `../../../../docs/format/...`.
    arm("exclude docs/format/**, reached only by include_str!", "R4a",
        docs_only=DOCS_ONLY + ["docs/format/**"])
    # R4a must not be fooled by comment-stripping: plant a read on a CODE line
    # in a file ci.yml runs, and require it to be seen.
    arm("a genuine read of an excluded path on a code line", "R4a",
        mutate=("scripts/ci-lanes.sh", "lane_secret_guard() {",
                'lane_secret_guard() {\n  cat "$repo/TODO.md" >/dev/null'))
    # ...including when the code line also carries a TRAILING comment, which a
    # cleverer stripper would have eaten along with the read.
    arm("a read on a code line with a trailing comment", "R4a",
        mutate=("scripts/ci-lanes.sh", "lane_secret_guard() {",
                'lane_secret_guard() {\n  cat "$repo/tasks/Q.md" >/dev/null  # trailing'))
    # R4c — the content-conditional class. Writing a pinned CLI version into an
    # excluded file makes it an input to `wasm32-core-tests` on that very push.
    arm("an excluded file gains a wasm-bindgen-cli pin literal", "R4c",
        mutate=("docs/ci-verification.md", "\n", "\nwasm-bindgen-cli --version 0.2.126\n"))
    # R4c drift — the registered pattern no longer matching its source script.
    arm("the registered grep pattern drifts from its script", "R4c",
        mutate=("scripts/wasm-toolchain-audit.sh", "wasm-bindgen-cli[^\\n]*--version",
                "wasm-bindgen-cli[^\\n]*--ver-sion"))
    # R1 — the mirror. The whole point is that these two cannot drift.
    arm("DOCS_ONLY and ci.yml's paths-ignore disagree", "R1",
        docs_only=[p for p in DOCS_ONLY if p != "TODO.md"])
    arm("ci.yml's paths-ignore loses an entry", "R1",
        mutate=(".github/workflows/ci.yml", "      - TODO.md\n", ""))
    # R2 — the required-context trap, built the way it is usually built.
    arm("a path filter on pull_request", "R2",
        mutate=(".github/workflows/ci.yml", "  pull_request:\n",
                "  pull_request:\n    paths-ignore:\n      - TODO.md\n"))
    arm("push filtered with `paths:` instead of `paths-ignore:`", "R2",
        mutate=(".github/workflows/ci.yml", "    paths-ignore:\n", "    paths:\n"))
    # R3 — a context that stops being produced, and one produced twice.
    arm("a required context stops being produced anywhere", "R3",
        mutate=(".github/workflows/ci-always.yml", "    name: secret-guard",
                "    name: secret-guard-renamed"))
    arm("two workflows produce the same context", "R3",
        mutate=(".github/workflows/ci-always.yml", "    name: secret-guard", "    name: fmt"))
    # R5 — the exclusion growing a suffix that is not a document, and a pattern
    # that matches nothing.
    arm("a non-document lands under an excluded path", "R5",
        docs_only=DOCS_ONLY + ["scripts/**"])
    arm("a DOCS_ONLY pattern matches nothing", "R5",
        docs_only=DOCS_ONLY + ["docs/no-such-file.md"])
    # R6 — the constraint that a docs push still gets its cheap checks.
    arm("traceability moves under the path filter", "R6",
        mutate=(".github/workflows/ci-always.yml", "    name: traceability",
                "    name: traceability-moved"))
    # A pattern the matcher does not model must be REFUSED, not guessed at.
    arm("a glob syntax this matcher does not model", "R5",
        docs_only=DOCS_ONLY + ["!docs/keep.md"])
    # R4e — a NEW edge out of a script ci.yml runs. This is the arm that keeps
    # the reader set honest: the first version of this check followed every
    # edge blindly, dragged check-traceability.py in, and could prove nothing.
    arm("an unclassified new edge out of a ci.yml script", "R4e",
        mutate=("scripts/format-freeze.sh", "#!/usr/bin/env bash",
                "#!/usr/bin/env bash\n: scripts/check-copy-style.py"))
    # ...and the stale-entry direction, which is what stops the two registers
    # becoming a list of things that used to be true.
    arm("a FOLLOW_EDGES entry whose reference is gone", "R4e",
        mutate=("scripts/cross-check.sh", "scripts/crosscheck-provenance.py",
                "scripts/crosscheck-gone.py"))
    return 0 if ok else 1


def inventory(root: Path) -> int:
    files = tracked_files(root)
    ci = (root / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    readers = reader_set(root, ci, files)
    excluded = [f for f in files if matches_any(f, DOCS_ONLY)]
    print(f"tracked files: {len(files)}")
    print(f"ci.yml reader set: {len(readers)} file(s)")
    for reader in readers:
        if reader.startswith("scripts/"):
            print(f"    {reader}")
    print(f"    ... plus {sum(1 for r in readers if not r.startswith('scripts/'))} under "
          f"{list(WORKSPACE_READER_ROOTS)}")
    print(f"excluded from ci.yml's push trigger: {len(excluded)} file(s)")
    for path in excluded:
        print(f"    {path}")
    return 0


def main(argv: list[str]) -> int:
    if argv and argv not in (["--self-test"], ["--inventory"]):
        print("usage: scripts/check-ci-paths.py [--self-test | --inventory]", file=sys.stderr)
        return 2
    if argv == ["--self-test"]:
        rc = self_test(REPO)
        print("check-ci-paths self-test PASS" if rc == 0 else "check-ci-paths self-test FAIL")
        return rc
    if argv == ["--inventory"]:
        return inventory(REPO)
    failures = check(REPO)
    for rule, message in failures.items:
        print(f"::error::check-ci-paths [{rule}]: {message}")
    if failures:
        return 1
    files = tracked_files(REPO)
    excluded = [f for f in files if matches_any(f, DOCS_ONLY)]
    ci = (REPO / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    readers = reader_set(REPO, ci, files)
    print(
        f"check-ci-paths: {len(excluded)} of {len(files)} tracked file(s) are excluded from "
        f"ci.yml's push trigger by {len(DOCS_ONLY)} pattern(s); none is read by any of the "
        f"{len(readers)} file(s) ci.yml runs, {len(REQUIRED_CONTEXTS)} required contexts are "
        f"each produced exactly once on pull_request, and {len(GREP_SURFACES)} registered grep "
        f"surface(s) still match nothing excluded"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
