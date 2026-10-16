#!/usr/bin/env python3
"""Every `run:` block in ci.yml must be a committed script or an allowlisted line (task Q43).

A `tamper-matrix` guard command was malformed from the day Q8 wrote it —
`--list` passed to *cargo*, which rejects it, where it must reach the test
binary after `--` — and it sat latent through two waves because **the lane
had never executed remotely**. The guard worked exactly as designed: it
refused to report success from a check that produced no evidence. The defect
was that the guard's own command had never been run.

The class, not the instance: **logic that lives only in YAML is logic nobody
runs before a push.** The three lanes that call committed scripts
(`vector-freeze`, `cross-check`, `traceability`) were green on their first
remote run; both CI-logic defects this project has had were in inline shell.

So every `run:` block must now be one of:

  1. a call into a committed script under `scripts/`, which a contributor and
     `scripts/local-gate.sh` can run; or
  2. a line on ALLOWED_INLINE below, each of which records the local lane
     that exercises it.

Anything else fails this check. Unused allowlist entries fail it too — a
stale exemption is how an allowlist stops meaning anything.

RULE [Q111] — NO PIPELINE FEEDS AN EARLY-EXIT grep (tasks/Q.md Q111, D181)
---------------------------------------------------------------------------

Q43's rule moved CI logic into committed scripts; it says nothing about the
shell inside them, and Q111's defect was in a committed script. So this file
also reads every shell file git knows — a shell shebang, a `.sh` suffix, or a
`# shellcheck shell=` directive, over `git ls-files` plus the untracked files
git does not ignore, so a new script is read before its first `git add` — and
forbids one shape in its code, whether or not the file sets `pipefail`:

    writer | grep -q PATTERN     and likewise -m N, -l, -L, --quiet, --silent,
                                 --max-count, --files-with-matches,
                                 --files-without-match, any abbreviation grep
                                 accepts (`--q`, `--sil`, `--max=1`), in any
                                 option cluster, before or after the pattern,
                                 after `|` or `|&`, at any `$( )` depth.

THE MECHANISM. Those options make grep exit at its first match and close the
pipe's read end. GNU grep matches whole lines, so a writer is safe exactly
while it writes nothing after the matched line's newline; its next write(2)
gets SIGPIPE, it exits 141, and under `set -o pipefail` the pipeline reports
that status — "no match" precisely when the match came early. Measured on
bash 5.2.15 and GNU grep 3.8 (wave 37), matching on the first line: a one-line
literal missed 0 of 3 000 runs, a two-line one 37 through `printf` and 53
through `echo -e`; and scripts/devnet/sepolia-preflight's `--self-test`, whose
three probes piped a multi-line `$out` into this shape, failed 38 of 500 runs
at fbcee1e.

THE FIX the message names is no pipe: `grep -q P <<<"$v"` for a value, and
`grep -q P <<<"$(cmd)"` or `grep -q P < <(cmd)` for a command. On bash 5.2.15
a here-string of up to 60 000 B is itself a pipe (a larger one is a temp
file), but the shell writes it in full before grep starts, so no writer is
left to kill. A process substitution's writer can still die of SIGPIPE; its
status is simply not the reader's.

PAYLOAD BLINDNESS, ON PURPOSE (Q111 Accept row 2). The rule forbids the SHAPE.
It never judges whether a writer emits one line — the property that really did
make the eight `ci-lanes.sh` literal sites safe — because that judgement, made
by eye, is what failed before: the census that judged payloads counted 11
sites where there were 16, and 3 of the 5 it missed were live races.

WHAT IT CANNOT SEE. Here-document bodies are data here and are never scanned,
even when they feed a shell (`bash <<'EOF'`); nor is code inside strings
handed to `bash -c`, `sh -c` or `eval`; nor a reader named through a variable
(`$GREP -q`). A file it cannot lex — an unterminated quote, `$(`, `case` or
here-document — is reported `[Q111-lex]` rather than passed unread, because a
lexer that has lost its place sees no pipes at all.

REFUSED, with their measured yields (D181 R5), so neither is re-proposed:
  * a `| head` rule: 35 sites, 0 true positives. 33 discard, mask or never use
    the writer's status; the 2 that consume it were measured safe
    (vector-freeze.sh's sort emits its 1 272 B in one write; e2e-devnet.sh's
    raced 0 of 300).
  * a `grep -c` rule: `-c` reads to end of input (the writer exited 0 in 3 of
    3 runs, against 141 in 3 of 3 for each of -q, -m1, -l and -L). Its hazard
    is exit 1 on a zero count, which is a different class from this one.

Usage:
    scripts/check-ci-shell.py              check (workflow `run:` blocks, then [Q111])
    scripts/check-ci-shell.py --self-test  prove both can go red
Exit: 0 pass, 1 failure.
"""

from __future__ import annotations

import re
import subprocess
import sys
import textwrap
from pathlib import Path
from typing import NamedTuple

REPO = Path(__file__).resolve().parent.parent
WORKFLOWS_DIR = REPO / ".github" / "workflows"
WORKFLOW = WORKFLOWS_DIR / "ci.yml"


def workflows() -> list[Path]:
    """Every committed workflow, not just `ci.yml`.

    Q43's Accept names `ci.yml`, but the class is "logic that lives only in
    YAML". `advisory-cron.yml` carried a second copy of the `cargo deny`
    invocation and `fuzz-nightly.yml` a corpus-size loop; scoping the check to
    one file would have closed the instance again.
    """
    return sorted(p for p in WORKFLOWS_DIR.glob("*.yml") if not p.name.startswith("."))

# Inline `run:` bodies that are NOT logic. Each value names why it is exempt
# and, where it runs a build tool, the local lane that executes the same tool
# over the same tree. Keys are matched after whitespace normalisation.
ALLOWED_INLINE: dict[str, str] = {
    "rustup show active-toolchain || rustup toolchain install\nrustup show":
        "toolchain bootstrap; byte-identical in every job, no branching, no computed value. "
        "Exercised by every local cargo invocation, which resolves the same rust-toolchain.toml.",
    "node --version":
        "version echo for the log; asserts nothing. The node floor is asserted inside "
        "scripts/wasm-test-runner.mjs and scripts/wasm-bitmatch.mjs, which run locally.",
    "cargo fmt --check":
        "single command, no logic. Local lane: scripts/local-gate.sh `fmt`.",
    "cargo clippy --all-targets --locked -- -D warnings":
        "single command, no logic. Local lane: scripts/local-gate.sh `clippy` (which is stricter: "
        "--workspace --all-features).",
    "cargo test --workspace --locked":
        "single command, no logic. Local lane: scripts/local-gate.sh `test` (which is stricter: "
        "--all-features).",
    "cargo build -p antseal-core --target wasm32-unknown-unknown --locked":
        "single command, no logic. Local lane: scripts/local-gate.sh `wasm32-build` "
        "(renamed from `wasm32` at Q125 — it is a build, and the name said otherwise; "
        "the EXECUTING lane is `wasm32-tests`, which shells out to scripts/wasm-tests.sh).",
    "pip install --require-hashes -r requirements-crosscheck.txt":
        "pinned, hash-checked tool install. Local equivalent: scripts/cross-check.sh --setup.",
    "cargo install cargo-fuzz --version 0.13.2 --locked":
        "pinned tool install (docs/dependency-policy.md §5). scripts/fuzz.sh asserts the "
        "installed version matches the pin, locally and in CI.",
    "cargo install cargo-deny --version 0.19.8 --locked":
        "pinned tool install (docs/dependency-policy.md §5). scripts/ci-lanes.sh audit-deny "
        "refuses to run without it and prints the same pinned install line.",
}

SCRIPT_CALL = re.compile(r"(?:^|\s|\|\||&&|;)(?:bash\s+|sh\s+|python3\s+|node\s+|\./)?(scripts/[\w.-]+)")


def normalise(body: str) -> str:
    kept = [line.rstrip() for line in body.splitlines() if line.strip()]
    return textwrap.dedent("\n".join(kept)).strip()


def run_blocks(text: str) -> list[tuple[int, str]]:
    """Every `run:` block with its 1-based line number.

    Hand-rolled rather than via a YAML library: this check must work with no
    third-party dependency (the `traceability` lane it joins needs none).

    That first clause is the real reason and it still holds. **The second
    reason this docstring used to give is false**, and is recorded here rather
    than quietly deleted (D124 §3.2): it said a YAML loader "would normalise
    away the very indentation that tells a single-line `run:` from a block
    one". Measured 2026-08-11 — a loader tells them apart BETTER. A block
    scalar comes back with its trailing newline, and the `defaults: run:
    shell: bash` case this scanner special-cases by hand at :112-117 comes back
    as a `dict` rather than a `str`, which is a type distinction rather than an
    indentation heuristic. The real cost of `safe_load` is LINE NUMBERS: every
    failure message in this file is `workflow.name:lineno` and recovering that
    needs a mark-recording `Loader` subclass. The docstring named the wrong
    cost and omitted the real one.

    **A per-job `cargo` predicate was proposed here (Q182) and REFUSED AS
    VACUOUS, not as expensive** (D124 RULING 2). It is recorded so the shape is
    not re-proposed: the incident that produced the row was the near-miss line
    `./scripts/gate-features.sh --check-partition`, which carries no `cargo`
    token — and neither does any of the five `run:` lines the `traceability`
    job carries today. 0 of 6, measured. Reading one level into the callee is
    worse: `ci-lanes.sh` holds 31 `cargo` occurrences belonging to other lanes
    and `wasm-bitmatch.sh` 4, so a callee-grep reds all five of today's GREEN
    steps. `run:` text is the wrong OBSERVABLE for a property of a process
    tree, and any static instrument reading it inherits the emptiness however
    well it is built. The property is asserted at the job instead, at runtime,
    by `scripts/cargo-free.sh` — whose header states it once.

    **Job attribution itself is cheap and was measured, not guessed**: adding a
    tracked current-job to this function costs NINE LINES and attributes 65 of
    65 `run:` blocks across all four workflows with zero unattributed, a total
    matching the one `main()` already prints (D124 §1.7, measured 2026-08-11 at
    65 blocks; the count is now 68). It is not built because nothing needs it —
    so a future row that genuinely wants a per-job workflow predicate should
    price it at nine lines and not at "the larger half of the work". One trap
    if it is ever built: a naive scan for two-space-indented keys also reports
    `pull_request` and `push` as jobs, since they are children of `on:` at the
    same indent, so the attribution must track the `jobs:` section.
    """
    out: list[tuple[int, str]] = []
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        m = re.match(r"^(\s*)-?\s*run:\s*(\S.*)?$", lines[i])
        if not m:
            i += 1
            continue
        indent, inline = m.group(1), m.group(2)
        start = i + 1
        if inline is None:
            # `defaults:\n  run:\n    shell: bash` — a mapping, not a command.
            # A command is always a scalar: inline, or an explicit block
            # indicator. Anything else is not shell and must not be scanned.
            i += 1
            continue
        if inline not in ("|", ">", "|-", ">-"):
            out.append((start, inline))
            i += 1
            continue
        body, i = [], i + 1
        while i < len(lines):
            line = lines[i]
            if line.strip() and not line.startswith(indent + " "):
                break
            body.append(line)
            i += 1
        out.append((start, "\n".join(body)))
    return out


def check(*targets: Path) -> list[str]:
    failures: list[str] = []
    used: set[str] = set()
    blocks = [(w, n, b) for w in targets for n, b in run_blocks(w.read_text(encoding="utf-8"))]
    if not blocks:
        return [f"{[str(t) for t in targets]}: no `run:` blocks found at all — the parser is broken"]

    for workflow, lineno, raw in blocks:
        body = normalise(raw)
        scripts = SCRIPT_CALL.findall(body)
        if scripts:
            # Every line must be part of the script call, not logic wrapped
            # around one: a script call plus an `if`/`for`/pipeline is still
            # inline logic, and is exactly what Q43 forbids.
            for line in body.splitlines():
                if not any(s in line for s in scripts):
                    failures.append(
                        f"{workflow.name}:{lineno}: calls {scripts[0]} but also carries inline "
                        f"logic: {line.strip()!r} — move it into the script"
                    )
            for s in scripts:
                path = REPO / s
                if not path.is_file():
                    failures.append(f"{workflow.name}:{lineno}: {s} does not exist")
                elif not (path.stat().st_mode & 0o111) and not body.lstrip().startswith(
                    ("bash ", "sh ", "python3 ", "node ")
                ):
                    failures.append(f"{workflow.name}:{lineno}: {s} is not executable")
            continue
        if body in ALLOWED_INLINE:
            used.add(body)
            continue
        failures.append(
            f"{workflow.name}:{lineno}: inline `run:` shell that is neither a committed script "
            f"call nor allowlisted:\n"
            + "\n".join(f"        {line}" for line in body.splitlines())
            + "\n    Move it into a script under scripts/ (the pattern of vector-freeze.sh, "
            "cross-check.sh, fuzz.sh, ci-lanes.sh) so it can be run before a push, or add it to "
            "ALLOWED_INLINE with the local lane that exercises it. A lane that has never run on "
            "the remote is not evidence, no matter how long it has been committed."
        )

    for stale in sorted(set(ALLOWED_INLINE) - used):  # noqa: E501
        failures.append(
            "ALLOWED_INLINE carries an entry no `run:` block uses any more; delete it:\n"
            + "\n".join(f"        {line}" for line in stale.splitlines())
        )
    return failures


# ── Rule [Q111]: no pipeline feeds an early-exit grep ───────────────────────
#
# The module docstring states the rule, its mechanism and its blind spots. What
# follows is the machinery: a lexer exactly deep enough to know whether a `|`
# is a pipe, and grep's own option grammar, so `-eq` (pattern `q`) is not
# mistaken for `-q` and `--sil` is not missed.

Q111_READERS = frozenset({"grep", "egrep", "fgrep"})

# GNU grep's long options — the 3.8 `--help` list plus its two undocumented
# aliases, `--fixed-regexp` and `--unix-byte-offsets` — with each one's argument
# kind and the short option it stands for. getopt_long accepts any unambiguous
# prefix, and two names meaning the same option are not ambiguous (`--col`):
# measured on grep 3.8, `--q`, `--sil`, `--max=1` and `--files-witho` are all
# accepted, and `--files-with` is refused as ambiguous.
_GREP_LONG: dict[str, tuple[str, str]] = {
    "after-context": ("required", "A"), "basic-regexp": ("no", "G"),
    "before-context": ("required", "B"), "binary": ("no", "U"),
    "binary-files": ("required", "binary-files"), "byte-offset": ("no", "b"),
    "color": ("optional", "color"), "colour": ("optional", "color"),
    "context": ("required", "C"), "count": ("no", "c"),
    "dereference-recursive": ("no", "R"), "devices": ("required", "D"),
    "directories": ("required", "d"), "exclude": ("required", "exclude"),
    "exclude-dir": ("required", "exclude-dir"),
    "exclude-from": ("required", "exclude-from"),
    "extended-regexp": ("no", "E"), "file": ("required", "f"),
    "files-with-matches": ("no", "l"), "files-without-match": ("no", "L"),
    "fixed-regexp": ("no", "F"), "fixed-strings": ("no", "F"),
    "group-separator": ("required", "group-separator"), "help": ("no", "help"),
    "ignore-case": ("no", "i"), "include": ("required", "include"),
    "initial-tab": ("no", "T"), "invert-match": ("no", "v"),
    "label": ("required", "label"), "line-buffered": ("no", "line-buffered"),
    "line-number": ("no", "n"), "line-regexp": ("no", "x"),
    "max-count": ("required", "m"), "no-filename": ("no", "h"),
    "no-group-separator": ("no", "no-group-separator"),
    "no-ignore-case": ("no", "no-ignore-case"), "no-messages": ("no", "s"),
    "null": ("no", "Z"), "null-data": ("no", "z"), "only-matching": ("no", "o"),
    "perl-regexp": ("no", "P"), "quiet": ("no", "q"), "recursive": ("no", "r"),
    "regexp": ("required", "e"), "silent": ("no", "q"), "text": ("no", "a"),
    "unix-byte-offsets": ("no", "u"), "version": ("no", "V"),
    "with-filename": ("no", "H"), "word-regexp": ("no", "w"),
}
_GREP_SHORT_WITH_ARG = frozenset("ABCDXdefm")  # grep 3.8's short_options
_GREP_EARLY = frozenset("qmlL")  # -q (--quiet, --silent), -m, -l, -L

_CONTROL_OPS = (";;&", ";;", ";&", ";", "||", "|&", "|", "&&", "&")
_REDIR_OPS = ("&>>", "&>", "<<<", "<<-", "<<", "<>", "<&", ">>", ">|", ">&", "<", ">")
_BEFORE_COMMAND = frozenset({"then", "do", "else", "elif", "if", "while", "until", "!", "{", "time"})
_COMPOUND_ENDS = frozenset({"fi", "done", "esac", "}"})
_ASSIGNMENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(?:\[[^]]*\])?\+?=")
_SHELLS = re.compile(r"(?:ba|da|k|z|a|mk|pdk)?sh")


class _Tok(NamedTuple):
    kind: str  # "w" word, "op" control operator, "nl" newline, "redir" redirection
    text: str
    line: int
    frame: int  # 0 = the file; one number per `$( )`, `<( )`, `>( )` or backtick body


class ShellLexError(Exception):
    def __init__(self, line: int, what: str) -> None:
        super().__init__(f"line {line}: {what}")
        self.line = line
        self.what = what


class _Lexer:
    """Bash, lexed exactly deep enough to know whether a `|` is a pipe.

    It tracks what decides that: single, double and `$'…'` quoting, backslash,
    comments, here-document bodies (skipped), `$( )`, backticks, `<( )`/`>( )`,
    `${ }`, arithmetic, and `case` patterns (where `|` is alternation), at any
    depth and across physical lines. Each nested command list gets its own
    frame number, so "the command after this pipe" is read inside the frame
    the pipe belongs to. Measured over the 31 shell files at fbcee1e: 368
    pipes, 26 here-document bodies, the same 16 sites the planning prototype
    found — which, reading line by line, also counted 31 `case` alternations as
    pipes and missed the real one after wasm-bitmatch.sh's multi-line
    here-string.
    """

    def __init__(self, text: str, toks: list[_Tok], frames: list[int], line: int = 1) -> None:
        self.s, self.n, self.i, self.line = text, len(text), 0, line
        self.toks = toks
        self.frames = frames  # a one-element list: the frame counter, shared with sub-lexers
        self.pending: list[tuple[str, bool, int]] = []  # here-documents awaiting their body
        self.heredocs = 0

    def run(self) -> None:
        self.code(0, None)
        if self.pending:
            raise ShellLexError(self.pending[0][2], f"here-document `{self.pending[0][0]}` has no body")

    def new_frame(self) -> int:
        self.frames[0] += 1
        return self.frames[0]

    def emit(self, kind: str, text: str, line: int, frame: int) -> None:
        self.toks.append(_Tok(kind, text, line, frame))

    def code(self, frame: int, closer: str | None) -> None:
        """One command list, up to `closer` (`)`) or the end of the text."""
        s, opened = self.s, self.line
        depth = 0  # `( )` nesting inside this frame
        case: list[str] = []  # per open `case`: subject -> in -> pat <-> body
        expect_cmd, after_redir = True, False
        while self.i < self.n:
            c = s[self.i]
            if s.startswith("\\\n", self.i):
                self.i += 2
                self.line += 1
                continue
            if c in " \t\r":
                self.i += 1
                continue
            if c == "\n":
                self.emit("nl", c, self.line, frame)
                self.i += 1
                self.line += 1
                self.heredoc_bodies()
                if not case or case[-1] in ("pat", "body"):
                    expect_cmd = True
                continue
            if c == "#":  # at a token boundary, so a comment
                j = s.find("\n", self.i)
                self.i = self.n if j < 0 else j
                continue
            in_pat = bool(case) and case[-1] == "pat"
            if in_pat and c in "()":
                self.i += 1
                if c == ")":
                    case[-1], expect_cmd = "body", True
                continue
            if c == ")":
                self.i += 1
                if depth:
                    depth -= 1
                    self.emit("op", c, self.line, frame)
                    expect_cmd = False
                    continue
                if closer != ")":
                    raise ShellLexError(self.line, "unbalanced `)`")
                if case:
                    raise ShellLexError(self.line, "`case` still open at the `)` closing its frame")
                return
            if c == "(" and expect_cmd and s.startswith("((", self.i):
                self.i += 2
                self.arith()
                expect_cmd = False
                continue
            if c == "(":
                self.i += 1
                depth += 1
                self.emit("op", c, self.line, frame)
                expect_cmd = True
                continue
            if s.startswith(("<(", ">("), self.i):
                self.word(frame)
                expect_cmd = after_redir = False
                continue
            op = next((o for o in _CONTROL_OPS if s.startswith(o, self.i)), None)
            if op is not None and not s.startswith("&>", self.i):
                self.i += len(op)
                if in_pat and op == "|":
                    continue  # pattern alternation, not a pipe
                if case and case[-1] == "body" and op in (";;", ";&", ";;&"):
                    case[-1] = "pat"
                self.emit("op", op, self.line, frame)
                expect_cmd, after_redir = True, False
                continue
            red = next((o for o in _REDIR_OPS if s.startswith(o, self.i)), None)
            if red is not None:
                self.i += len(red)
                self.emit("redir", red, self.line, frame)
                if red in ("<<", "<<-"):
                    self.heredoc_operator(frame, red == "<<-")
                else:
                    after_redir = True
                continue
            line, raw = self.line, self.word(frame)
            if raw is None or after_redir:  # an fd number, or a redirection's target
                after_redir = after_redir and raw is None
                continue
            state = case[-1] if case else None
            if state == "subject":
                case[-1] = "in"
            elif state == "in":
                if raw != "in":
                    raise ShellLexError(line, f"`case` subject followed by `{raw}`, not `in`")
                case[-1] = "pat"
            elif state == "pat":
                if raw == "esac":
                    case.pop()
                    expect_cmd = False
            elif expect_cmd and raw == "case":
                case.append("subject")
            elif expect_cmd and raw == "esac" and state == "body":
                case.pop()
                expect_cmd = False
            elif not (expect_cmd and (raw in _BEFORE_COMMAND or _ASSIGNMENT.match(raw))):
                expect_cmd = False
        if closer is not None:
            raise ShellLexError(opened, "a `$(`, `<(` or `>(` opened here is never closed")
        if depth:
            raise ShellLexError(self.line, f"{depth} `(` never closed")
        if case:
            raise ShellLexError(self.line, "`case` never closed by `esac`")

    def word(self, frame: int) -> str | None:
        """One word, emitted; None for an fd number glued to a redirection."""
        s, begin, line = self.s, self.i, self.line
        while self.i < self.n:
            c = s[self.i]
            if c == "\\":
                self.line += s.startswith("\\\n", self.i)
                self.i += 2
            elif c == "'":
                self.single_quoted()
            elif c == '"':
                self.i += 1
                self.double_quoted(frame)
            elif c == "`":
                self.backtick()
            elif c == "$":
                self.dollar(frame, in_dq=False)
            elif c in "<>" and self.i == begin and s.startswith("(", self.i + 1):
                self.i += 2
                self.code(self.new_frame(), ")")
            elif c in " \t\r\n|&;()<>":
                break
            else:
                self.i += 1
        raw = s[begin:self.i]
        if not raw:
            raise ShellLexError(line, f"unexpected {s[self.i]!r}")
        if raw.isdigit() and self.i < self.n and s[self.i] in "<>":
            return None
        self.emit("w", raw, line, frame)
        return raw

    def dollar(self, frame: int, in_dq: bool) -> None:
        s = self.s
        if s.startswith("$((", self.i):
            self.i += 3
            self.arith()
        elif s.startswith("$(", self.i):
            self.i += 2
            self.code(self.new_frame(), ")")
        elif s.startswith("${", self.i):
            self.i += 2
            self.param(frame, in_dq)
        elif not in_dq and s.startswith("$'", self.i):
            self.i += 1
            self.ansi_c()
        elif not in_dq and s.startswith('$"', self.i):
            self.i += 2
            self.double_quoted(frame)
        else:
            self.i += 1

    def single_quoted(self) -> None:
        j = self.s.find("'", self.i + 1)
        if j < 0:
            raise ShellLexError(self.line, "unterminated single quote")
        self.line += self.s.count("\n", self.i, j)
        self.i = j + 1

    def ansi_c(self) -> None:  # at the quote of `$'…'`
        s, line = self.s, self.line
        self.i += 1
        while self.i < self.n:
            if s[self.i] == "\\":
                self.i += 2
                continue
            self.line += s[self.i] == "\n"
            self.i += 1
            if s[self.i - 1] == "'":
                return
        raise ShellLexError(line, "unterminated $'...' string")

    def double_quoted(self, frame: int) -> None:  # just past the opening quote
        s, line = self.s, self.line
        while self.i < self.n:
            c = s[self.i]
            if c == "\\":
                self.line += s.startswith("\\\n", self.i)
                self.i += 2
            elif c == '"':
                self.i += 1
                return
            elif c == "`":
                self.backtick()
            elif c == "$":
                self.dollar(frame, in_dq=True)
            else:
                self.line += c == "\n"
                self.i += 1
        raise ShellLexError(line, "unterminated double quote")

    def param(self, frame: int, in_dq: bool) -> None:  # just past `${`
        s, line, depth = self.s, self.line, 1
        while self.i < self.n:
            c = s[self.i]
            if c == "\\":
                self.i += 2
            elif c == "'" and not in_dq:
                self.single_quoted()
            elif c == '"':
                self.i += 1
                self.double_quoted(frame)
            elif c == "`":
                self.backtick()
            elif c == "$" and s.startswith("${", self.i):
                self.i += 2
                depth += 1
            elif c == "$":
                self.dollar(frame, in_dq)
            elif c == "}":
                self.i += 1
                depth -= 1
                if not depth:
                    return
            else:
                self.line += c == "\n"
                self.i += 1
        raise ShellLexError(line, "unterminated ${...}")

    def arith(self) -> None:  # just past `((` or `$((`; `|` in here is bitwise OR
        s, line, depth = self.s, self.line, 2
        while self.i < self.n:
            c = s[self.i]
            self.i += 1
            self.line += c == "\n"
            depth += (c == "(") - (c == ")")
            if not depth:
                return
        raise ShellLexError(line, "unterminated (( ))")

    def backtick(self) -> None:  # at the opening backtick
        s, line, j = self.s, self.line, self.i + 1
        while j < self.n and s[j] != "`":
            j += 2 if s[j] == "\\" else 1
        if j >= self.n:
            raise ShellLexError(line, "unterminated backtick")
        body = re.sub(r"\\([\\`$])", r"\1", s[self.i + 1:j])
        sub = _Lexer(body, self.toks, self.frames, line)
        sub.code(self.new_frame(), None)
        if sub.pending:
            raise ShellLexError(line, "here-document inside backticks")
        self.line += s.count("\n", self.i, j)
        self.i = j + 1

    def heredoc_operator(self, frame: int, strip_tabs: bool) -> None:
        while self.i < self.n and self.s[self.i] in " \t":
            self.i += 1
        line, raw = self.line, self.word(frame)
        if raw is None:
            raise ShellLexError(line, "here-document operator with no delimiter")
        delimiter = re.sub(r"""\\(.)|['"]""", lambda m: m.group(1) or "", raw)
        self.pending.append((delimiter, strip_tabs, line))

    def heredoc_bodies(self) -> None:
        """At a newline: skip the body of every here-document opened on that line."""
        s = self.s
        for delimiter, strip_tabs, line in self.pending:
            while True:
                if self.i >= self.n:
                    raise ShellLexError(line, f"here-document `{delimiter}` is never terminated")
                j = s.find("\n", self.i)
                end = self.n if j < 0 else j
                text = s[self.i:end]
                self.i, self.line = end + 1, self.line + 1
                if (text.lstrip("\t") if strip_tabs else text) == delimiter:
                    break
            self.heredocs += 1
        self.pending = []


def _literal(raw: str) -> str | None:
    """Quote removal for a word that expands nothing; None if it expands anything."""
    out, i, n = [], 0, len(raw)
    while i < n:
        c = raw[i]
        if c == "\\":
            out.append(raw[i + 1:i + 2])
            i += 2
        elif c == "'":
            j = raw.find("'", i + 1)
            if j < 0:
                return None
            out.append(raw[i + 1:j])
            i = j + 1
        elif c == '"':
            i += 1
            while i < n and raw[i] != '"':
                if raw[i] in "$`":
                    return None
                if raw[i] == "\\" and raw[i + 1:i + 2] in ('"', "\\", "$", "`"):
                    i += 1
                out.append(raw[i])
                i += 1
            i += 1
        elif c in "$`":
            return None
        else:
            out.append(c)
            i += 1
    return "".join(out)


def _grep_long(name: str) -> tuple[str, str] | None:
    """getopt_long's resolution: the exact name, else an unambiguous prefix."""
    if name in _GREP_LONG:
        return _GREP_LONG[name]
    hits = {spec for full, spec in _GREP_LONG.items() if name and full.startswith(name)}
    return hits.pop() if len(hits) == 1 else None


def grep_early_exit_option(args: list[str]) -> str | None:
    """The option word that makes grep stop reading early, or None.

    GNU argument permutation: options count after operands too, until `--`. A
    short cluster ends at the first option that takes an argument, which is
    the rest of the cluster or else the next word (`-eq` is the pattern `q`).
    """
    i = 0
    while i < len(args):
        a = _literal(args[i])
        i += 1
        if a is None or not a.startswith("-") or a == "-":
            continue
        if a == "--":
            return None
        if a.startswith("--"):
            name, eq, _ = a[2:].partition("=")
            spec = _grep_long(name)
            if spec is not None and spec[1] in _GREP_EARLY:
                return a
            if spec is not None and spec[0] == "required" and not eq:
                i += 1
            continue
        for pos, ch in enumerate(a[1:], 1):
            if ch in _GREP_EARLY:
                return a
            if ch in _GREP_SHORT_WITH_ARG:
                i += pos == len(a) - 1
                break
    return None


def _simple_command(toks: list[_Tok], k: int) -> list[str]:
    """The words of the simple command starting at toks[k], redirections dropped."""
    while k < len(toks) and (toks[k].kind == "nl" or toks[k].text == "("):
        k += 1  # bash allows newlines (and so comments) after `|`; `( grep … )` is a reader too
    words, target = [], False
    for t in toks[k:]:
        if t.kind == "w":
            if not target:
                words.append(t.text)
            target = False
        elif t.kind == "redir":
            target = True
        else:
            break
    return words


def _command_name(words: list[str]) -> tuple[str | None, list[str]]:
    """(the command run, its arguments), through assignments and transparent wrappers."""
    i = 0
    while i < len(words):
        if _ASSIGNMENT.match(words[i]):
            i += 1
            continue
        w = _literal(words[i])
        if w is None:
            return None, []
        i += 1
        if w in ("{", "!", "if", "while", "until", "exec", "nohup"):
            continue
        if w in ("command", "time"):
            if i < len(words) and _literal(words[i]) in ("-v", "-V"):
                return None, []  # `command -v grep` looks grep up; it runs nothing
            while i < len(words) and _literal(words[i]) == "-p":
                i += 1
            continue
        if w in ("env", "nice", "stdbuf", "ionice", "timeout"):
            while i < len(words) and (
                (_literal(words[i]) or "").startswith("-") or _ASSIGNMENT.match(words[i])
            ):
                i += 1 + (_literal(words[i]) in ("-u", "--unset", "-n", "-s", "-k"))
            i += w == "timeout"  # its DURATION
            continue
        return Path(w).name, words[i:]
    return None, []


def _writer_name(toks: list[_Tok], k: int) -> str:
    """What the pipe at toks[k] reads from, for the message."""
    if k and toks[k - 1].kind == "op" and toks[k - 1].text == ")":
        return "( … )"
    if k and toks[k - 1].kind == "w" and toks[k - 1].text in _COMPOUND_ENDS:
        return f"… {toks[k - 1].text}"
    start = k - 1
    while start >= 0 and toks[start].kind in ("w", "redir"):
        start -= 1
    name, _ = _command_name(_simple_command(toks, start + 1))
    return name or "…"


class ShellScan(NamedTuple):
    findings: list[str]
    pipes: int
    heredocs: int


def q111_scan_text(name: str, text: str) -> ShellScan:
    """Rule [Q111] over one shell file's text. Pure: no I/O, so the self-test plants in memory."""
    toks: list[_Tok] = []
    lexer = _Lexer(text, toks, [0])
    try:
        lexer.run()
    except ShellLexError as e:
        return ShellScan(
            [f"{name}:{e.line}: [Q111-lex] cannot lex this file ({e.what}), so rule [Q111] "
             f"cannot see its pipelines — it refuses the file rather than pass it unread"],
            0, lexer.heredocs)
    frames: dict[int, list[_Tok]] = {}
    for t in toks:
        frames.setdefault(t.frame, []).append(t)
    findings: list[tuple[int, str]] = []
    pipes = 0
    for ftoks in frames.values():
        for k, t in enumerate(ftoks):
            if t.kind != "op" or t.text not in ("|", "|&"):
                continue
            pipes += 1
            reader, args = _command_name(_simple_command(ftoks, k + 1))
            flag = grep_early_exit_option(args) if reader in Q111_READERS else None
            if flag is None:
                continue
            findings.append((t.line, (
                f"{name}:{t.line}: [Q111] `{_writer_name(ftoks, k)} {t.text} {reader} {flag}`: "
                f"{reader} {flag} stops reading at its first match, so a writer with more to "
                f"write dies of SIGPIPE (exit 141) after the match, and under `set -o pipefail` "
                f"the pipeline reports that failure — the verdict inverts. Feed it without a "
                f"pipe: `{reader} {flag} P <<<\"$v\"` for a value, `{reader} {flag} P <<<\"$(cmd)\"` "
                f"or `{reader} {flag} P < <(cmd)` for a command (tasks/Q.md Q111)."
            )))
    return ShellScan([m for _, m in sorted(findings)], pipes, lexer.heredocs)


def is_shell_file(path: str, head: str) -> bool:
    """R1's three markers: a shell shebang, a `.sh` suffix, a `# shellcheck shell=` directive."""
    lines = head.split("\n")
    if lines[0].startswith("#!"):
        argv = lines[0][2:].split()
        while argv and Path(argv[0]).name == "env":
            argv = [a for a in argv[1:] if not a.startswith("-") and "=" not in a]
        if argv and _SHELLS.fullmatch(Path(argv[0]).name):
            return True
    if path.endswith(".sh"):
        return True
    for line in lines:  # a directive in the leading comment block (shellcheck's own rule)
        if line.strip() and not line.startswith("#"):
            break
        if re.match(r"#\s*shellcheck\s+shell=", line):
            return True
    return False


def q111_shell_files(root: Path = REPO) -> list[str]:
    """Every shell file git knows of: `git ls-files` plus untracked files it does not ignore."""
    listing = subprocess.run(
        ["git", "-C", str(root), "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
        capture_output=True,
    )
    if listing.returncode != 0:
        raise RuntimeError(listing.stderr.decode(errors="replace").strip() or "git ls-files failed")
    found = []
    for rel in sorted({p for p in listing.stdout.decode(errors="surrogateescape").split("\0") if p}):
        path = root / rel
        if path.is_symlink() or not path.is_file():
            continue  # a link is read through its target; a tracked file deleted here is gone
        with path.open("rb") as fh:
            head = fh.read(4096).decode("utf-8", errors="replace")
        if is_shell_file(rel, head):
            found.append(rel)
    return found


class ShellCheck(NamedTuple):
    findings: list[str]
    files: list[str]
    pipes: int
    heredocs: int


def q111_check(root: Path = REPO) -> ShellCheck:
    try:
        files = q111_shell_files(root)
    except (OSError, RuntimeError) as e:
        return ShellCheck([f"[Q111] cannot enumerate the shell files git knows ({e}); a rule "
                           f"that reads no file must not pass"], [], 0, 0)
    findings: list[str] = []
    pipes = heredocs = 0
    for rel in files:
        text = (root / rel).read_bytes().decode("utf-8", errors="surrogateescape")
        scan = q111_scan_text(rel, text)
        findings += scan.findings
        pipes += scan.pipes
        heredocs += scan.heredocs
    if not files:
        findings.append("[Q111] no shell file found at all — R1's enumeration is broken, and a "
                        "rule over zero files is green for no reason")
    return ShellCheck(findings, files, pipes, heredocs)


# ── [Q111]'s self-test arms: every one planted in memory, judged by message ─
#
# RED arms name each (line, flag) the finding must carry, and every finding must
# also name both fixes (R2), so an unrelated finding cannot satisfy an arm. A1
# is Q111's own Accept row 1 in both directions. A1-A13 and G1-G9 are the
# planning lane's twenty-three cases (P4, wave 37); B, H and L are this lexer's
# own reach: what a line-by-line scanner got wrong, and what it must refuse.
_H = "#!/usr/bin/env bash\nset -uo pipefail\n"
Q111_ARMS: list[tuple[str, str, object]] = [
    ("A1  printf '%s' \"$var\" | grep -q x (Accept row 1)",
     _H + "if printf '%s' \"$var\" | grep -q x; then :; fi\n", [(3, "-q")]),
    ("A2  echo | grep -qF", _H + "echo \"$v\" | grep -qF x && ok=1\n", [(3, "-qF")]),
    ("A3  cat | grep -m1", _H + "cat \"$f\" | grep -m1 x >/dev/null\n", [(3, "-m1")]),
    ("A4  cmd | grep -l", _H + "git ls-files | grep -l x\n", [(3, "-l")]),
    ("A5  cmd | grep --quiet", _H + "cargo tree | grep --quiet x || die\n", [(3, "--quiet")]),
    ("A6  inside \"$( )\"",
     _H + "r=\"$(printf '%s\\n' \"$v\" | grep -qE y && echo ok)\"\n", [(3, "-qE")]),
    ("A7  LC_ALL=C grep -q", _H + "sort f | LC_ALL=C grep -q x\n", [(3, "-q")]),
    ("A8  |& pipe", _H + "cmd |& grep -q x\n", [(3, "-q")]),
    ("A9  -A2 then -q", _H + "cmd | grep -A2 -q x\n", [(3, "-q")]),
    ("A10 after a quoted <<word (e2e-devnet.sh:193)",
     _H + "sed -E \"s/a/\\1<<value withheld>>/g\" f\nprintf '%s' \"$v\" | grep -q x\n", [(4, "-q")]),
    ("A11 backslash-continued pipeline",
     _H + "printf '%s\\n' \"$v\" \\\n  | grep -qF x\n", [(4, "-qF")]),
    ("A12 trailing `|` (wasm-toolchain-audit.sh:77)",
     _H + "if ! cargo metadata --no-deps |\n    grep -q \"x\"; then :; fi\n", [(3, "-q")]),
    ("A13 after a `&&` continuation",
     _H + "true &&\n  printf '%s\\n' \"$v\" | grep -q x\n", [(4, "-q")]),
    ("B1  an abbreviation grep accepts: --qui", _H + "cmd | grep --qui x\n", [(3, "--qui")]),
    ("B2  --max=2", _H + "cmd | grep --max=2 x\n", [(3, "--max=2")]),
    ("B3  -q after the pattern (GNU permutation)", _H + "cmd | grep \"$re\" -q\n", [(3, "-q")]),
    ("B4  inside backticks", _H + "v=`cmd | grep -l x`\n", [(3, "-l")]),
    ("B5  inside a process substitution",
     _H + "while read -r f; do :; done < <(git ls-files | grep -L x)\n", [(3, "-L")]),
    ("B6  after a multi-line here-string (wasm-bitmatch.sh:332)",
     _H + "n=\"$(hits <<<\"a\nb | c\nd\" | grep -q x)\"\n", [(5, "-q")]),
    ("B7  command, \\grep, a path, env + timeout",
     _H + "cmd | command grep -q x\ncmd | \\grep -q x\ncmd | /usr/bin/grep -q x\n"
          "cmd | env LC_ALL=C timeout 5 grep -q x\n",
     [(3, "-q"), (4, "-q"), (5, "-q"), (6, "-q")]),
    ("B8  compound readers: { } and if",
     _H + "cmd | { grep -q x; }\ncmd | if grep -q x; then :; fi\n", [(3, "-q"), (4, "-q")]),
    ("B9  a comment and a newline after the pipe", _H + "cmd | # why\n  grep -q x\n", [(3, "-q")]),
    ("B10 egrep, fgrep and the long spellings",
     _H + "cmd | egrep --silent x\ncmd | fgrep --files-without-match x\n"
          "cmd | grep --max-count=3 x\ncmd | grep --files-with-matches x\n",
     [(3, "--silent"), (4, "--files-without-match"), (5, "--max-count=3"),
      (6, "--files-with-matches")]),
    ("B11 in a case body; a case writing into $( )",
     _H + "case \"$1\" in\n  a|b) cmd | grep -q x ;;\nesac\n"
          "r=\"$(case \"$1\" in a) printf '%s\\n' \"$v\" ;; esac | grep -q y)\"\n",
     [(4, "-q"), (6, "-q")]),
    ("A1g the here-string form (Accept row 1)", _H + "if grep -q x <<<\"$var\"; then :; fi\n", []),
    ("G1  -e -q: the -q is the PATTERN", _H + "cmd | grep -e -q x\n", []),
    ("G2  grep -c and grep -o read to EOF", _H + "n=\"$(cmd | grep -c x)\"\ncmd | grep -o x | sort\n", []),
    ("G3  no pipe; a process substitution", _H + "grep -q x file\ngrep -q x < <(cmd)\n", []),
    ("G4  || is not a pipe", _H + "false || grep -q x file\n", []),
    ("G5  case-pattern alternation", _H + "case \"$x\" in a|grep) : ;; esac\n", []),
    ("G6  [[ ]] alternation", _H + "[[ $x == a || $x == b ]] && :\n", []),
    ("G7  a comment", _H + "# printf x | grep -q y\n", []),
    ("G8  a here-document BODY (stated blindness)", _H + "cat <<'EOF'\nprintf x | grep -q y\nEOF\n", []),
    ("G9  single-quoted text", _H + "echo 'printf x | grep -q y'\n", []),
    ("H1  option arguments consumed: -eq, --, -e -m, --regexp -q",
     _H + "cmd | grep -eq x\ncmd | grep -- -q\ncmd | grep -A 2 -e -m x\ncmd | grep --regexp -q\n", []),
    ("H2  quoted text spanning lines",
     _H + "printf '%s\\n' 'one\nprintf x | grep -q y'\necho \"a\n$(true) | grep -q y\nb\"\n", []),
    ("H3  here-documents: <<\\EOF, <<-\"END\", inside $( )",
     _H + "cat <<\\EOF\ncmd | grep -q x\nEOF\ncat <<-\"END\"\n\tcmd | grep -q x\n\tEND\n"
          "printf '%s\\n' \"$(cat <<EOF\ncmd | grep -q x\nEOF\n)\" | grep -c y\n", []),
    ("H4  a `|` that is no pipe: ${//|/}, $(( | )), (( | ))",
     _H + "y=\"${x//|/-}\"; z=$(( a | b ))\n(( m = a | b ))\n", []),
    ("H5  redirections; plain grep >/dev/null drains (grep 3.8)",
     _H + "cmd 2>&1 | grep -c x\ncmd >/dev/null 2>&1 || grep -q x f\ncmd | grep x >/dev/null\n", []),
    ("L1  an unterminated double quote is refused", _H + "echo \"unterminated\n",
     ("lex", 3, "unterminated double quote")),
    ("L2  an unterminated here-document is refused", _H + "cat <<EOF\nbody\n",
     ("lex", 3, "never terminated")),
    ("L3  an unclosed $( is refused", _H + "x=\"$(printf a\n", ("lex", 3, "never closed")),
]

# R1's scope markers, both directions; the first is the class the census missed.
Q111_SCOPE_ARMS: list[tuple[str, str, bool]] = [
    ("scripts/devnet/run", "#!/usr/bin/env bash\nset -u\n", True),
    ("scripts/x.sh", "echo hi\n", True),
    ("scripts/lib/sourced", "# shellcheck shell=bash\n# sourced, never run\nf() { :; }\n", True),
    (".githooks/hook", "#!/bin/sh\nexec true\n", True),
    ("scripts/x", "#!/usr/bin/env -S bash -eu\n", True),
    ("scripts/tool.py", "#!/usr/bin/env python3\nprint()\n", False),
    ("docs/notes", "prose first\n# shellcheck shell=bash\n", False),
]


def _q111_arm(text: str, want: object) -> tuple[bool, list[str]]:
    got = q111_scan_text("planted.sh", text).findings
    if isinstance(want, tuple):  # ("lex", line, reason): refused by message, not by silence
        _, line, reason = want
        return (len(got) == 1 and got[0].startswith(f"planted.sh:{line}: [Q111-lex] ")
                and reason in got[0]), got
    if not want:
        return not got, got
    return len(got) == len(want) and all(
        any(f.startswith(f"planted.sh:{line}: [Q111] `") and f" {flag}`:" in f
            and '<<<"$v"' in f and "< <(cmd)" in f for f in got)
        for line, flag in want), got


def q111_self_test(root: Path = REPO) -> bool:
    ok = True
    for label, text, want in Q111_ARMS:
        good, got = _q111_arm(text, want)
        kind = "refused" if isinstance(want, tuple) else ("RED" if want else "GREEN")
        print(f"  [Q111] {label:58s} -> {kind if good else 'WRONG'}"
              + (f" ({len(got)})" if good and kind == "RED" else ""))
        if not good:
            ok = False
            print(f"    ::error:: wanted {want!r}; the rule returned:")
            for f in got or ["(no finding)"]:
                print(f"      {f}")
    for path, head, want in Q111_SCOPE_ARMS:
        got = is_shell_file(path, head)
        print(f"  [Q111] scope: {path:44s} -> {'shell' if got else 'not shell'}"
              + ("" if got == want else "  WRONG"))
        if got != want:
            ok = False
            print(f"    ::error:: R1's markers classify {path!r} wrongly (wanted {want})")
    control = q111_check(root)
    bare = [f for f in control.files if not f.endswith(".sh")]
    print(f"  [Q111] control (the tree): {len(control.files)} shell file(s), {len(bare)} without "
          f"a .sh suffix, {control.pipes} pipe(s) -> {'RED' if control.findings else 'GREEN'}")
    if control.findings:
        ok = False
        print("    ::error:: the tree control is red; convert the sites before trusting the arms")
        for f in control.findings:
            print(f"      {f}")
    if not bare:
        ok = False
        print("    ::error:: no shell file without a .sh suffix was found, so the shebang half of "
              "R1's scope read nothing on the real tree — the class that hid "
              "scripts/devnet/sepolia-preflight's three live sites from the census")
    return ok


def self_test() -> int:
    """Plant the two faults this check exists to catch and require red.

    Q149 surveyed every red arm in the repository and found this one
    structurally immune to the class — it judges on the failure list `check()`
    RETURNS, in-process, so a crash propagates and fails the harness instead of
    satisfying an arm the way a bare non-zero exit status would. Its lesser
    weakness, recorded here rather than fixed: the arm below asks only WHETHER
    a failure was raised and never WHICH, so a finding unrelated to the planted
    fault would satisfy it — partly compensated by the control run at the end,
    which requires the unmodified workflow to raise nothing at all. The rule
    and the register of instruments that owe it are in scripts/lib/red-arm.sh.
    """
    original = WORKFLOW.read_text(encoding="utf-8")
    # Dot-prefixed so `workflows()` never picks it up; the siblings are still
    # passed alongside it, so an ALLOWED_INLINE entry used only by one of them
    # cannot make a planted fault look red for the wrong reason.
    scratch = WORKFLOWS_DIR / ".ci-shell-selftest.yml"
    siblings = [w for w in workflows() if w != WORKFLOW]
    # THE ANCHORS ARE ASSERTED, NOT ASSUMED (see the `assert` in the loop
    # below). All three used to plant against the `secret-guard` job, which
    # D138/Q239 MOVED out of ci.yml into ci-always.yml — and this self-test went
    # red on the very next gate run with `self-test fault … did not apply`,
    # which is the assertion working: a planted fault that cannot be planted is
    # reported, never silently skipped. Re-anchored on `golden-vectors`, chosen
    # because it is a plain single-step lane in ci.yml with no matrix, no
    # `defaults:` and no `if:`, so it is the least likely of the fifteen to move
    # again. If it ever does, this comment is the instruction: re-anchor, do not
    # weaken the assert.
    anchor_step = "      - name: Run the golden-vector suite (vector_ reserved-name marker)"
    anchor_run = "        run: ./scripts/ci-lanes.sh golden-vectors"
    faults = [
        (
            "a NEW inline run: block with logic",
            original.replace(
                anchor_step,
                "      - name: planted fault\n"
                "        run: |\n"
                "          matched=\"$(cargo test --locked -- --list | grep -c ': test$')\"\n"
                "          if [ \"$matched\" -eq 0 ]; then exit 1; fi\n"
                + anchor_step,
                1,
            ),
        ),
        (
            "logic wrapped around a script call",
            original.replace(
                anchor_run,
                "        run: |\n"
                "          ./scripts/ci-lanes.sh golden-vectors\n"
                "          echo 'and now some logic' && exit 0",
                1,
            ),
        ),
        (
            "a run: block calling a script that does not exist",
            original.replace(
                anchor_run,
                "        run: ./scripts/does-not-exist.sh golden-vectors",
                1,
            ),
        ),
    ]
    ok = True
    try:
        for label, text in faults:
            assert text != original, f"self-test fault {label!r} did not apply"
            scratch.write_text(text, encoding="utf-8")
            failures = check(scratch, *siblings)
            status = "RED" if failures else "GREEN"
            print(f"  planted fault: {label:45s} -> {status}")
            if not failures:
                print("    ::error:: the check stayed green over a planted fault")
                ok = False
    finally:
        scratch.unlink(missing_ok=True)

    control = check(*workflows())
    print(f"  control (unmodified ci.yml){'':21s} -> {'RED' if control else 'GREEN'}")
    if control:
        print("    ::error:: the control run is red; fix the workflow before trusting the faults")
        for f in control:
            print(f"      {f}")
        ok = False
    if not q111_self_test():
        ok = False
    return 0 if ok else 1


def main() -> int:
    if "--self-test" in sys.argv[1:]:
        rc = self_test()
        if rc == 0:
            print("check-ci-shell self-test PASS")
        return rc
    files = workflows()
    failures = check(*files)
    shell = q111_check()
    for f in failures + shell.findings:
        print(f"::error::check-ci-shell: {f}")
    if failures or shell.findings:
        return 1
    total = sum(len(run_blocks(w.read_text(encoding="utf-8"))) for w in files)
    print(
        f"check-ci-shell: {total} `run:` block(s) across {len(files)} workflow(s) "
        f"({', '.join(w.name for w in files)}) — every one is a committed script call or one of "
        f"{len(ALLOWED_INLINE)} allowlisted lines, each naming the local lane that runs it"
    )
    bare = sum(1 for f in shell.files if not f.endswith(".sh"))
    print(
        f"check-ci-shell [Q111]: {len(shell.files)} shell file(s) read ({bare} without a .sh "
        f"suffix), {shell.pipes} pipe(s), {shell.heredocs} here-document body(ies) skipped — "
        f"no pipeline feeds an early-exit grep"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
