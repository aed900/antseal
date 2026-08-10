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

Usage:
    scripts/check-ci-shell.py              check
    scripts/check-ci-shell.py --self-test  prove the check can go red
Exit: 0 pass, 1 failure.
"""

from __future__ import annotations

import re
import sys
import textwrap
from pathlib import Path

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
    third-party dependency (the `traceability` lane it joins needs none), and
    a YAML loader would also normalise away the very indentation that tells a
    single-line `run:` from a block one.
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
    faults = [
        (
            "a NEW inline run: block with logic",
            original.replace(
                "      - name: Vault-export / wallet-key signature guard (self-test, then scan)",
                "      - name: planted fault\n"
                "        run: |\n"
                "          matched=\"$(cargo test --locked -- --list | grep -c ': test$')\"\n"
                "          if [ \"$matched\" -eq 0 ]; then exit 1; fi\n"
                "      - name: Vault-export / wallet-key signature guard (self-test, then scan)",
                1,
            ),
        ),
        (
            "logic wrapped around a script call",
            original.replace(
                "        run: ./scripts/ci-lanes.sh secret-guard",
                "        run: |\n"
                "          ./scripts/ci-lanes.sh secret-guard\n"
                "          echo 'and now some logic' && exit 0",
                1,
            ),
        ),
        (
            "a run: block calling a script that does not exist",
            original.replace(
                "        run: ./scripts/ci-lanes.sh secret-guard",
                "        run: ./scripts/does-not-exist.sh secret-guard",
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
    return 0 if ok else 1


def main() -> int:
    if "--self-test" in sys.argv[1:]:
        rc = self_test()
        if rc == 0:
            print("check-ci-shell self-test PASS")
        return rc
    files = workflows()
    failures = check(*files)
    for f in failures:
        print(f"::error::check-ci-shell: {f}")
    if failures:
        return 1
    total = sum(len(run_blocks(w.read_text(encoding="utf-8"))) for w in files)
    print(
        f"check-ci-shell: {total} `run:` block(s) across {len(files)} workflow(s) "
        f"({', '.join(w.name for w in files)}) — every one is a committed script call or one of "
        f"{len(ALLOWED_INLINE)} allowlisted lines, each naming the local lane that runs it"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
