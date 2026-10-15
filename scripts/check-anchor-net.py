#!/usr/bin/env python3
"""The no-real-network policies' static half (tasks **Q16** and **S40**).

Two runtime gates enforce the policies. Neither can see the ways it stops
applying, and that is what this script checks:

* **The anchor gate** — `crates/antseal-anchor/src/http/offline.rs` refuses
  any endpoint that is not a loopback IP literal, inside `HttpClient::attempt`
  — the one function in the workspace that hands a URL to `ureq`. Its
  `cfg(test)` arm is armed by the compiler and has no off switch (Q16, D99).
* **The storage gate** — `antseal_net::network::storage_gate` refuses any
  bootstrap peer that is not loopback, as the first fallible step of both
  storage constructors: before the payer's `eth_chainId` call and before
  `Client::connect` (D173 §2 R9, R10). Its `cfg(test)` arm covers
  antseal-net's own unit tests; a build with debug assertions is armed with
  the variable unset; a release build is armed by the variable alone, which
  is why every venue below exports it.

Read those two modules first; this script duplicates neither.

R1 and R4 hold BOTH variables to the same rules through the same code, so the
storage arming can never be checked by a weaker copy (D173 §2 R11). R2, R3
and R5 belong to the anchor gate alone: the storage gate has no HTTP client,
no URL-valued constant and no test-only bypass feature, and its single dial
site is pinned by the shape scan in `crates/antseal-net/tests/` (D173 §2 R10).

  R1  **The arming.** The `cfg(test)` arms cover each crate's own unit
      tests. Every *other* test binary — `antseal-cli/tests/*.rs`, which
      drives the real submission gate and the real storage adapters through
      the real pipeline — links the crates' ordinary builds, where
      `cfg(test)` is false and only the environment arms them. An arming
      that lives in a workflow nobody checks is an arming a reformat
      deletes. So: every committed workflow declares BOTH variables at
      workflow level, and `scripts/local-gate.sh` exports both.

  R2  **One HTTP client.** The anchor gate is inside `antseal-anchor`'s
      substrate. A second HTTP client anywhere in the workspace bypasses it
      completely, and nothing else would notice: `ci-lanes.sh dep-graph`'s
      forbidden-crate scan covers `antseal-core`'s graph only, so `reqwest`
      in `antseal-cli`'s dev-dependencies is invisible to every existing lane.

  R3  **Inventory closure.** The anchor gate's headline test walks the
      product's default endpoint constants by *value*, so a calendar added
      to an existing list is covered for free. A brand-new constant is the
      case a value-walk cannot see. Every URL-valued `pub const` in
      antseal-anchor must therefore be named in the gate's test module.

  R4  **The spawn venue** (D99 R4.3; D173 §2 R11). R1 covers the two venues
      that arm a whole *run* — the workflows and `scripts/local-gate.sh`.
      Neither covers a bare `cargo test -p antseal-cli`, which is what a
      contributor actually types, and which was **measured** on 2026-08-06
      to run with `deny_reason() == None` and to reach `freetsa.org` for
      real. So the harness itself must guarantee the variables rather than
      inherit them: every construction of the `antseal` binary goes through
      `crates/antseal-cli/tests/common/spawn.rs`, that helper sets BOTH
      variables, and no test source calls `main_entry` in-process — a test
      **cannot** arm its own process, because `std::env::set_var` is `unsafe`
      in edition 2024 and `[workspace.lints.rust]` denies `unsafe_code`
      (both confirmed by compiling them). `env_clear()` gets its own arm: it
      is the one call that strips the variables even in CI, and the rule is
      CALL-LEVEL — the statement that clears must itself re-set both. It was
      file-level until D173 §2 R11, and a file-level rule passed a second,
      unarmed `env_clear()` in a file that re-armed once.

  R5  **The `test-util` edge** (D99 R5). `antseal-anchor`'s `test-util`
      feature carries `upgrade_pending_with` and
      `UpgradeTarget::loopback_for_tests` — a resolver seam and a constructor
      that bypasses A42's allowlist. They are safe only because the feature
      cannot reach a shipped binary, and that is true only while every
      workspace manifest keeps `test-util` on a **dev**-dependency edge.
      A normal edge would put the bypass in `cargo build` output silently.
      The house rule is already written at `antseal-core/Cargo.toml`
      ("DEV-DEPENDENCY EDGES ONLY for `test-util`"); this is its enforcement.

Usage:
    scripts/check-anchor-net.py              check
    scripts/check-anchor-net.py --self-test  prove each rule can go red
Exit: 0 pass, 1 failure.
"""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
WORKFLOWS_DIR = REPO / ".github" / "workflows"
LOCAL_GATE = REPO / "scripts" / "local-gate.sh"
ANCHOR_SRC = REPO / "crates" / "antseal-anchor" / "src"
GATE_MODULE = ANCHOR_SRC / "http" / "offline.rs"


@dataclass(frozen=True)
class Gate:
    """One environment-armed runtime gate, and how a test source may name it.

    R1 and R4 iterate over `GATES` and never over one of them, which is the
    mechanism behind D173 §2 R11's "through the same functions": there is no
    second code path for the storage variable to be weaker on.
    """

    env_var: str
    """The variable the gate reads. `"1"` arms; `"0"` is the only off switch."""
    module: str
    """Where the runtime gate lives, for messages."""
    spellings: tuple[str, ...]
    """Identifiers a Rust test source may pass to `.env(` for this variable,
    with or without a path prefix: the spawn helper's constant, and for the
    storage gate also the gate module's own `ENV`."""
    reaches: str
    """What a disarmed gate lets a test reach, for messages."""
    record: str
    """The decision that rules the gate, for messages."""


GATES: tuple[Gate, ...] = (
    Gate(
        env_var="ANTSEAL_NO_REAL_ANCHOR_NETWORK",
        module="crates/antseal-anchor/src/http/offline.rs",
        spellings=("NO_REAL_ANCHOR_NETWORK",),
        reaches="a real TSA or OTS calendar",
        record="Q16 / D99",
    ),
    Gate(
        env_var="ANTSEAL_NO_REAL_STORAGE_NETWORK",
        module="crates/antseal-net/src/network.rs (`storage_gate`)",
        spellings=("NO_REAL_STORAGE_NETWORK", "storage_gate::ENV"),
        reaches="a public Autonomi peer",
        record="D173 §2 R9-R11",
    ),
)

# R4. The single file that may construct the product binary in a test, and
# the cargo-provided path it is the only legitimate reader of.
SPAWN_HELPER = "crates/antseal-cli/tests/common/spawn.rs"
BIN_ENV = "CARGO_BIN_EXE_antseal"
# The *mechanism*, not the name. Matched on the macro expansion that actually
# yields the path, because an assertion message or a rustdoc link may name the
# variable as prose and reading a name is not reaching for the binary — the
# first draft matched the bare identifier and reddened on the very test that
# asserts the helper spawns `CARGO_BIN_EXE_antseal` rather than a PATH lookup.
# `option_env!` is covered too: it is the same read with a softer failure.
BIN_ENV_MACRO = re.compile(rf'(?:option_)?env!\s*\(\s*"{BIN_ENV}"')
# The in-process entry. A test calling this runs the CLI inside the test
# process, which cannot be armed — see the module docs of the spawn helper.
IN_PROCESS_ENTRY = "main_entry"
# The one call that hands a child an empty environment.
ENV_CLEAR = "env_clear()"
# R4 (d). How far past an `env_clear()` line the statement that clears may
# run before the scan stops looking for the re-arm. A bound, not a tuning
# knob: the clean-machine chain in `e2e_restore.rs` is about twenty lines
# with its comments, and a statement the bound cuts short goes RED (loud),
# never green.
STATEMENT_CAP = 60

# R5. The feature whose items bypass A42's allowlist, and the crate that
# declares it. Permitted on `[dev-dependencies]` edges only.
TEST_UTIL_FEATURE = "test-util"

# R2. Names that can open an HTTP(S) connection. `ureq` is on the list
# deliberately: the rule is not "no client" but "exactly one client, in the
# one crate whose substrate carries the gate".
HTTP_CLIENT_CRATES = frozenset(
    {
        "ureq",
        "reqwest",
        "hyper",
        "hyper-util",
        "isahc",
        "curl",
        "attohttpc",
        "surf",
        "minreq",
        "http-req",
        "awc",
        "actix-web",
    }
)
# The single crate whose manifest may declare one, and the single client it
# may declare. `Cargo.toml`'s `[workspace.dependencies]` is where the exact
# pin lives (D90), so the root manifest is a permitted declaration site too.
CLIENT_OWNER = "antseal-anchor"
PERMITTED_CLIENT = "ureq"

# R3. A `pub const` whose value contains a URL literal.
URL_CONST = re.compile(
    r"pub const\s+(?P<name>[A-Z0-9_]+)\s*:[^=]+=\s*(?P<value>.*?);",
    re.DOTALL,
)


def rust_sources() -> list[Path]:
    return sorted(p for p in ANCHOR_SRC.rglob("*.rs"))


def workflows() -> list[Path]:
    return sorted(p for p in WORKFLOWS_DIR.glob("*.yml") if not p.name.startswith("."))


def carries_url_literal(value: str) -> bool:
    """Does a `pub const`'s value text contain a URL string literal?

    Matched on `"http:` / `"https:` — the scheme and its colon, **not** the
    `//` — because the obvious line-based comment stripper mangles exactly
    the thing it is asked to find: `"https://freetsa.org/tsr".split("//")`
    leaves `"https:` and no terminating `;`, so the detector found **zero**
    constants in a tree that has six. R3's own anti-vacuity check caught it
    on the first run; it is recorded here so the shortcut is not retried.

    Comments are not stripped at all, and do not need to be: a doc comment
    cannot match `pub const NAME: ... = ...;`. A commented-out constant would
    be a false positive — the over-strict direction, which fails loudly
    rather than silently passing.
    """
    return '"http:' in value or '"https:' in value


def workflow_level_env(text: str) -> str:
    """The `env:` mapping at column 0, so every job inherits it.

    A job-level arming would leave the next job added unarmed, which is the
    failure R1 exists to prevent — so an indented `env:` does not count.
    """
    top_level = re.search(r"^env:\n((?:[ \t]+.*\n|\n)*)", text, re.MULTILINE)
    return top_level.group(1) if top_level else ""


def check_arming(
    workflow_texts: dict[str, str], local_gate_text: str
) -> list[str]:
    """R1 — every gate's environment arm is actually armed, in both venues."""
    failures: list[str] = []
    for gate in GATES:
        for name, text in sorted(workflow_texts.items()):
            block = workflow_level_env(text)
            if not re.search(
                rf"^[ \t]+{gate.env_var}:\s*[\"']?1[\"']?\s*$", block, re.MULTILINE
            ):
                failures.append(
                    f"R1: .github/workflows/{name} does not set {gate.env_var}: \"1\" in its "
                    f"workflow-level `env:` block. Every workflow arms it, so a job added "
                    f"later inherits the policy instead of quietly opting out of it "
                    f"({gate.record})."
                )
        if not re.search(rf"^export {gate.env_var}=1$", local_gate_text, re.MULTILINE):
            failures.append(
                f"R1: scripts/local-gate.sh does not `export {gate.env_var}=1`. The local "
                f"gate is the venue a contributor actually runs; unarmed, it is the one "
                f"place an integration test can still reach {gate.reaches} "
                f"({gate.record})."
            )
    return failures


def check_single_client(manifests: dict[str, str]) -> list[str]:
    """R2 — exactly one HTTP client, declared by exactly one crate."""
    failures: list[str] = []
    found: list[tuple[str, str]] = []
    for name, text in sorted(manifests.items()):
        body = "\n".join(
            line for line in text.splitlines() if not line.lstrip().startswith("#")
        )
        for crate in sorted(HTTP_CLIENT_CRATES):
            escaped = re.escape(crate)
            # Cargo accepts a dependency in three spellings, and this rule is
            # worth only as much as its weakest one. The self-test plants all
            # three; the table-header form was found by that self-test after
            # the first draft checked only the inline one, which is precisely
            # how `[dev-dependencies.reqwest]` would have walked in.
            #
            #   1. inline           reqwest = "0.12"
            #   2. table header     [dev-dependencies.reqwest]
            #                       (also [target.'cfg(x)'.dependencies.reqwest])
            #   3. renamed edge     httpthing = { package = "reqwest" }
            inline = re.search(rf"^\s*{escaped}\s*=", body, re.MULTILINE)
            header = re.search(
                rf"^\s*\[[^\]]*dependencies\.{escaped}\]", body, re.MULTILINE
            )
            renamed = re.search(rf"package\s*=\s*[\"']{escaped}[\"']", body)
            if inline or header or renamed:
                found.append((name, crate))
    for owner, crate in found:
        manifest_crate = owner.split("/")[1] if "/" in owner else owner
        if crate != PERMITTED_CLIENT:
            failures.append(
                f"R2: {owner} declares the HTTP client `{crate}`. Anchor traffic is gated "
                f"inside antseal-anchor's substrate (http::offline); a second client "
                f"bypasses the gate entirely and no other lane would see it. If this edge "
                f"is genuinely needed, it needs a decision record and this rule needs "
                f"updating in the same commit."
            )
        elif manifest_crate not in (CLIENT_OWNER, "Cargo.toml"):
            failures.append(
                f"R2: {owner} declares `{crate}`, but only {CLIENT_OWNER} (and the root "
                f"[workspace.dependencies] pin) may. D90 makes antseal-anchor the sole "
                f"declaration site precisely so the gate has one chokepoint."
            )
    if not found:
        failures.append(
            "R2: the scan found NO HTTP-client declaration anywhere. antseal-anchor "
            "declares ureq (D90), so the manifest scan is broken, not the tree clean — "
            "and a broken scan is a green verdict that means nothing."
        )
    return failures


def url_constants(sources: dict[str, str]) -> dict[str, str]:
    """Every `pub const` in antseal-anchor whose value carries a URL literal."""
    found: dict[str, str] = {}
    for name, text in sorted(sources.items()):
        for match in URL_CONST.finditer(text):
            if carries_url_literal(match.group("value")):
                found[match.group("name")] = name
    return found


def check_inventory(sources: dict[str, str], gate_text: str) -> list[str]:
    """R3 — every URL-valued constant is named in the gate's test module."""
    failures: list[str] = []
    constants = url_constants(sources)
    if not constants:
        failures.append(
            "R3: no URL-valued `pub const` was found in crates/antseal-anchor/src/. "
            "DEFAULT_TSA_URLS and DEFAULT_OTS_CALENDARS exist, so the detector is broken "
            "rather than the tree empty."
        )
        return failures
    for const, where in sorted(constants.items()):
        if not re.search(rf"\b{re.escape(const)}\b", gate_text):
            failures.append(
                f"R3: `{const}` ({where}) is a URL-valued constant that "
                f"crates/antseal-anchor/src/http/offline.rs never names. Its endpoints are "
                f"therefore outside the walk that proves every default endpoint is refused. "
                f"Add it to `every_default_endpoint()` — or, if it is not dialable, say so "
                f"there in a comment so the next reader does not have to rediscover it."
            )
    return failures


def is_comment(line: str) -> bool:
    """Is the line wholly a Rust line comment (`//`, `///` or `//!`)?"""
    return line.lstrip().startswith("//")


def uncommented(text: str) -> list[str]:
    """Lines that are not wholly a Rust comment.

    Deliberately crude — it only drops lines whose first non-space characters
    are `//`, which covers `//`, `///` and `//!`. That is enough for what R4
    needs and no more: the rules below are about *code*, and a doc comment
    that quotes `main_entry` to explain why nothing calls it must not be the
    thing that fails the build. Block comments are not handled, and a
    `/* … */` hiding a real call would be a false negative — the direction
    that costs a missed catch rather than a bogus failure, and the runtime
    gate is still the thing that fails an actual call.
    """
    return [line for line in text.splitlines() if not is_comment(line)]


def arming_call(gate: Gate) -> re.Pattern[str]:
    """The one shape that counts as arming a gate on a `Command`: an `.env(`
    call whose key is the variable — as the string literal, or as one of the
    gate's identifier spellings with any path prefix — and whose value is the
    literal `"1"`.

    The value is matched on purpose. Both gates fail closed on any value but
    `"0"`, so `"true"` would arm too — but `"1"` is what every venue sets,
    what `anchor_stage.rs`'s runtime assertion reads back, and the single
    spelling a reader has to recognise. A helper that set `"0"` would be a
    disarm dressed as an arm, and this pattern does not accept it.
    """
    names = "|".join(re.escape(s) for s in (f'"{gate.env_var}"', *gate.spellings))
    return re.compile(rf'\.env\(\s*(?:[A-Za-z_][A-Za-z0-9_]*::)*(?:{names})\s*,\s*"1"\s*\)')


def ends_statement(line: str) -> bool:
    """Does this code line end a Rust statement — a `;` followed by nothing
    but whitespace or a trailing line comment?"""
    return re.search(r";\s*(?://.*)?$", line) is not None


def env_clear_statements(text: str) -> list[tuple[int, str]]:
    """Every code-line `env_clear()` call, with the rest of the statement
    that makes it: `(1-based line number, statement text after the clear)`.

    The window starts AFTER the last `env_clear()` on its line — an `.env(`
    chained before the clear is wiped by it and must not count — and runs to
    the first following code line that ends a statement, skipping comment
    lines, bounded by `STATEMENT_CAP`. That window is what "call level"
    means here (D173 §2 R11): the re-arm must be chained on the statement
    that clears, not merely present somewhere in the file.
    """
    lines = text.splitlines()
    found: list[tuple[int, str]] = []
    for index, line in enumerate(lines):
        if is_comment(line) or ENV_CLEAR not in line:
            continue
        tail = line[line.rindex(ENV_CLEAR) + len(ENV_CLEAR):]
        chunk = [tail]
        if not ends_statement(tail):
            for follow in lines[index + 1 : index + STATEMENT_CAP]:
                if is_comment(follow):
                    continue
                chunk.append(follow)
                if ends_statement(follow):
                    break
        found.append((index + 1, "\n".join(chunk)))
    return found


def check_spawn_venue(test_sources: dict[str, str], helper_text: str | None) -> list[str]:
    """R4 — the CLI test harness guarantees the arming, in all four ways it
    can stop doing so, for every gate."""
    failures: list[str] = []
    variables = " and ".join(gate.env_var for gate in GATES)

    if helper_text is None:
        return [
            f"R4: {SPAWN_HELPER} does not exist. It is the ONLY place a test may construct the "
            f"`antseal` binary, and the only thing that arms {variables} for a bare "
            f"`cargo test -p antseal-cli` — measured 2026-08-06 to otherwise run with the "
            f"anchor gate disarmed and to reach freetsa.org for real (D99 §1.3)."
        ]

    # (a) The helper actually arms, for every gate. A helper that constructs
    # the binary without a variable is worse than no helper: it looks like
    # the protection is there.
    helper_code = "\n".join(uncommented(helper_text))
    for gate in GATES:
        if not arming_call(gate).search(helper_code):
            failures.append(
                f"R4: {SPAWN_HELPER} constructs the binary but never sets {gate.env_var}. Every "
                f"spawned-binary suite in antseal-cli is armed by that one line and by nothing "
                f"else; without it a bare `cargo test -p antseal-cli` can reach {gate.reaches} "
                f"and every assertion still passes ({gate.record}). The shape this rule reads "
                f"is `.env(<key>, \"1\")` with <key> the literal \"{gate.env_var}\" or one of "
                f"{list(gate.spellings)}, with or without a path prefix."
            )

    # (b) Nothing else names the cargo-provided path. A flat rule with no
    # exemption list, which is why the helper also exports `antseal_exe()`
    # for the one suite that wants the path rather than a Command.
    for name, text in sorted(test_sources.items()):
        if name == SPAWN_HELPER:
            continue
        if any(BIN_ENV_MACRO.search(line) for line in uncommented(text)):
            failures.append(
                f"R4: {name} reads {BIN_ENV} directly. Construct the binary through "
                f"`spawn::antseal()`, which arms {variables}; if you need the PATH rather "
                f"than a Command, use `spawn::antseal_exe()`. A bare construction is a suite "
                f"that reaches real anchor endpoints and public storage peers on a developer's "
                f"machine."
            )

    # (c) The in-process venue. This one cannot be made safe, only closed:
    # a test cannot arm its own process (`set_var` is unsafe in edition 2024,
    # and `unsafe_code` is denied workspace-wide — both confirmed by
    # compiling them, 2026-08-06).
    for name, text in sorted(test_sources.items()):
        if any(IN_PROCESS_ENTRY in line for line in uncommented(text)):
            failures.append(
                f"R4: {name} calls `{IN_PROCESS_ENTRY}` in-process. A test CANNOT arm "
                f"{variables} for its own process — `std::env::set_var` is `unsafe` in "
                f"edition 2024 and [workspace.lints.rust] denies `unsafe_code` — so an "
                f"in-process CLI entry that dials calendars or peers cannot be made safe. "
                f"Spawn the binary through `spawn::antseal()` instead (D99 R4.2)."
            )

    # (d) The one call that strips the arming even when CI supplied it, held
    # at CALL level: the statement that clears must re-set every gate's
    # variable itself. `env_remove` is deliberately NOT covered:
    # antseal-anchor's own `no_real_network.rs` must remove the variable to
    # prove the disarmed arm reaches the network, which is the workspace's
    # only proof the arm works.
    statements = 0
    for name, text in sorted(test_sources.items()):
        for lineno, statement in env_clear_statements(text):
            statements += 1
            for gate in GATES:
                if not arming_call(gate).search(statement):
                    failures.append(
                        f"R4: {name}:{lineno} calls `env_clear()` and the statement that clears "
                        f"never re-sets {gate.env_var}. `env_clear()` is the one operation that "
                        f"defeats the environment arm even in CI, where the workflow arms it "
                        f"workflow-wide: the parent inherits it and the child is handed an empty "
                        f"environment. Nothing else notices — a disarmed gate reaches "
                        f"{gate.reaches} and every assertion still passes. Chain the re-arm on "
                        f"the SAME statement, after the clear: `.env_clear()….env("
                        f"{gate.spellings[0]}, \"1\")` — a re-arm elsewhere in the file does not "
                        f"count, because a file-level rule passed a second, unarmed "
                        f"`env_clear()` in a file that re-armed once (D173 §2 R11)."
                    )
    # Anti-vacuity for (d): the clean machine in `e2e_restore.rs` is a
    # standing `env_clear()` (D99 R4.1), so a scan that finds no call anywhere
    # has stopped reading, not found a clean tree.
    if statements == 0:
        failures.append(
            "R4: the `env_clear()` scan found NO call under crates/*/tests/. "
            "crates/antseal-cli/tests/e2e_restore.rs's clean machine is one, so the scanner "
            "is broken rather than the tree clean — and if that call was removed on purpose, "
            "retarget this guard in the same commit."
        )

    return failures


def dependency_sections(text: str) -> list[tuple[str, str]]:
    """`(section header, body)` for every dependency table in a manifest.

    Covers all the spellings cargo accepts, because the rule is worth only as
    much as its weakest one:

        [dependencies]                                    normal
        [dependencies.antseal-anchor]                     normal
        [build-dependencies]                              normal (ships in
                                                          no binary, but it is
                                                          not a dev edge)
        [workspace.dependencies]                          normal
        [target.'cfg(unix)'.dependencies]                 normal
        [dev-dependencies]                                dev
        [target.'cfg(…)'.dev-dependencies]                dev
        [features]                                        neither — but see
                                                          the second arm
    """
    sections: list[tuple[str, str]] = []
    header = "(root)"
    body: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("[") and not stripped.startswith("[["):
            sections.append((header, "\n".join(body)))
            header = stripped
            body = []
        elif not stripped.startswith("#"):
            body.append(line)
    sections.append((header, "\n".join(body)))
    return sections


def check_test_util_edges(manifests: dict[str, str]) -> list[str]:
    """R5 — `test-util` never rides a normal-dependency edge."""
    failures: list[str] = []
    seen_any_dev_edge = False
    for name, text in sorted(manifests.items()):
        for header, body in dependency_sections(text):
            is_dependency_table = "dependencies" in header
            is_dev = "dev-dependencies" in header
            if is_dependency_table and is_dev and TEST_UTIL_FEATURE in body:
                seen_any_dev_edge = True
            if is_dependency_table and not is_dev and TEST_UTIL_FEATURE in body:
                failures.append(
                    f"R5: {name} enables `{TEST_UTIL_FEATURE}` on a NORMAL dependency edge, in "
                    f"`{header}`. That feature carries `upgrade_pending_with` and "
                    f"`UpgradeTarget::loopback_for_tests` — a resolver seam and a constructor "
                    f"that bypasses A42's https/bare-host/no-port allowlist entirely. They are "
                    f"safe only because `cargo build` cannot reach them (measured: the product "
                    f"build compiles antseal-anchor with `--cfg feature=\"default\"` alone). A "
                    f"normal edge puts the bypass in shipped output. DEV-DEPENDENCY EDGES ONLY "
                    f"(antseal-core/Cargo.toml; D99 R5)."
                )
            # The transitive spelling: a package feature that switches
            # `test-util` on through a normal edge. `cargo build --features
            # that-one` would then ship the bypass, and no dependency table
            # would look wrong.
            if header == "[features]" and f"/{TEST_UTIL_FEATURE}" in body:
                offenders = [
                    line.strip()
                    for line in body.splitlines()
                    if f"/{TEST_UTIL_FEATURE}" in line
                ]
                failures.append(
                    f"R5: {name} defines a package feature that enables `{TEST_UTIL_FEATURE}` "
                    f"through a dependency edge: {offenders}. `cargo build --features` would "
                    f"then put A42's allowlist bypass in a shipped binary, with every dependency "
                    f"table still looking correct (D99 R5)."
                )
    if not seen_any_dev_edge:
        failures.append(
            f"R5: the manifest scan found NO `{TEST_UTIL_FEATURE}` dev-dependency edge anywhere. "
            f"antseal-cli takes one on antseal-anchor (and two more on core/net), so the section "
            f"parser is broken rather than the tree clean — and a broken scan is a green verdict "
            f"that means nothing."
        )
    return failures


def test_sources() -> list[Path]:
    """Every integration-test source in the workspace.

    R4's venue. These link each crate's ORDINARY build, where the gates'
    `cfg(test)` arms are false — which is the whole reason the environment
    arm has to be guaranteed here rather than assumed.
    """
    return sorted(p for p in (REPO / "crates").glob("*/tests/**/*.rs"))


def read_tree() -> tuple[
    dict[str, str], str, dict[str, str], dict[str, str], str, dict[str, str]
]:
    workflow_texts = {p.name: p.read_text(encoding="utf-8") for p in workflows()}
    local_gate_text = LOCAL_GATE.read_text(encoding="utf-8")
    manifests = {"Cargo.toml": (REPO / "Cargo.toml").read_text(encoding="utf-8")}
    for manifest in sorted((REPO / "crates").glob("*/Cargo.toml")):
        manifests[f"crates/{manifest.parent.name}/Cargo.toml"] = manifest.read_text(
            encoding="utf-8"
        )
    sources = {
        str(p.relative_to(REPO)): p.read_text(encoding="utf-8") for p in rust_sources()
    }
    gate_text = GATE_MODULE.read_text(encoding="utf-8")
    tests = {
        str(p.relative_to(REPO)): p.read_text(encoding="utf-8") for p in test_sources()
    }
    return workflow_texts, local_gate_text, manifests, sources, gate_text, tests


def check(
    workflow_texts: dict[str, str],
    local_gate_text: str,
    manifests: dict[str, str],
    sources: dict[str, str],
    gate_text: str,
    tests: dict[str, str],
) -> list[str]:
    failures = (
        check_arming(workflow_texts, local_gate_text)
        + check_single_client(manifests)
        + check_inventory(sources, gate_text)
        + check_spawn_venue(tests, tests.get(SPAWN_HELPER))
        + check_test_util_edges(manifests)
    )
    # Anti-vacuity for R4: the whole rule set is a walk over test sources, and
    # a glob that stopped matching would report a clean tree rather than a
    # broken scan. R3 learned this the hard way (see `carries_url_literal`).
    if len(tests) < 20:
        failures.append(
            f"R4: the test-source scan found only {len(tests)} file(s) under crates/*/tests/. "
            f"This workspace has well over twenty, so the glob is broken rather than the tree "
            f"empty, and every R4 verdict above is vacuous."
        )
    return failures


# ── self-test plants for R4 (d) ─────────────────────────────────────────────
# Each is appended to a real test source IN MEMORY; the `env_clear()` is on
# the first line, which is the line the failure must name. `spawn::…` need
# not compile — nothing here is compiled.
E2E_RESTORE = "crates/antseal-cli/tests/e2e_restore.rs"
UNARMED_CLEAR = (
    "fn clean(command: &mut std::process::Command, home: &std::path::Path) "
    '{ command.env_clear().env("HOME", home); }'
)
HALF_ARMED_CLEAR = (
    "fn clean_half(command: &mut std::process::Command) "
    '{ command.env_clear().env(spawn::NO_REAL_ANCHOR_NETWORK, "1"); }'
)
REARM_BEFORE_CLEAR = (
    "fn clean_backwards(command: &mut std::process::Command, home: &std::path::Path) "
    '{ command.env(spawn::NO_REAL_ANCHOR_NETWORK, "1")'
    '.env(spawn::NO_REAL_STORAGE_NETWORK, "1").env_clear().env("HOME", home); }'
)
FULLY_ARMED_CLEAR = "\n".join(
    [
        "fn clean_again(mut command: std::process::Command, home: &std::path::Path) "
        "-> std::process::Command {",
        "    command",
        "        .env_clear()",
        "        // re-armed on the statement that clears, both gates",
        '        .env(spawn::NO_REAL_ANCHOR_NETWORK, "1")',
        '        .env(antseal_net::network::storage_gate::ENV, "1")',
        '        .env("HOME", home);',
        "    command",
        "}",
    ]
)


def self_test() -> int:
    """Planted faults, each required to turn this check RED **with the
    failure the fault should produce** — judged on the returned failure list
    and on its text (rule tag plus the names the message must carry), never
    on the fact that something went red (scripts/lib/red-arm.sh). Two
    planted shapes must stay GREEN, so the call-level rule is shown to
    accept the re-arm it asks for and not merely to refuse every second
    `env_clear()`.

    Every fault is applied to an in-memory copy of the real tree, so a
    self-test can never leave damage behind and can never be skipped because
    a scratch directory was not writable.
    """
    workflow_texts, local_gate_text, manifests, sources, gate_text, tests = read_tree()
    control = check(workflow_texts, local_gate_text, manifests, sources, gate_text, tests)
    print(f"  control (unmodified tree){'':50s} -> {'RED' if control else 'GREEN'}")
    if control:
        for failure in control:
            print(f"    ::error:: control run is RED: {failure}")
        return 1

    ok = True
    anchor, storage = GATES

    def copied() -> list:
        return [
            dict(workflow_texts),
            local_gate_text,
            dict(manifests),
            dict(sources),
            gate_text,
            dict(tests),
        ]

    def arm(
        label: str,
        mutate,
        *expects: tuple[str, ...],
        forbid: tuple[str, ...] = (),
    ) -> None:
        """Plant, then require a failure carrying ALL of each `expects` tuple
        (plus whatever the mutation returns, e.g. the planted `file:line`),
        and no failure carrying all of `forbid`."""
        nonlocal ok
        args = copied()
        extra = mutate(args)
        if extra is None:
            print(f"  planted fault: {label:60s} -> NOT APPLIED")
            print("    ::error:: the mutation changed nothing, so the arm proves nothing")
            ok = False
            return
        failures = check(*args)
        unmet = [
            want + extra
            for want in expects
            if not any(all(s in failure for s in want + extra) for failure in failures)
        ]
        forbidden = (
            [f for f in failures if all(s in f for s in forbid + extra)] if forbid else []
        )
        verdict = "RED" if failures else "GREEN"
        print(
            f"  planted fault: {label:60s} -> {verdict}"
            f"{' (NO MATCH)' if unmet else ''}{' (OVER-MATCH)' if forbidden else ''}"
        )
        if not failures:
            print("    ::error:: the check stayed GREEN over a planted fault")
            ok = False
            return
        if unmet or forbidden:
            for want in unmet:
                print(f"    ::error:: no failure carried all of {want!r}")
            for failure in forbidden:
                print(f"    ::error:: a failure carried all of {forbid + extra!r}: {failure}")
            for failure in failures:
                print(f"      got: {failure}")
            ok = False

    def green(label: str, mutate) -> None:
        """Plant a shape the rules must ACCEPT. The control is green, so any
        failure at all is this plant's."""
        nonlocal ok
        args = copied()
        extra = mutate(args)
        if extra is None:
            print(f"  planted green: {label:60s} -> NOT APPLIED")
            print("    ::error:: the mutation changed nothing, so the arm proves nothing")
            ok = False
            return
        failures = check(*args)
        print(f"  planted green: {label:60s} -> {'RED' if failures else 'GREEN'}")
        if failures:
            print("    ::error:: the check went RED over a shape the rule must accept")
            for failure in failures:
                print(f"      got: {failure}")
            ok = False

    # ── R1: the arming, per gate ──────────────────────────────────────────
    def drop_workflow_arming(gate: Gate):
        def mutate(args):
            name = "ci.yml"
            before = args[0][name]
            after = re.sub(
                rf"^[ \t]+{gate.env_var}:.*\n", "", before, count=1, flags=re.MULTILINE
            )
            if after == before:
                return None
            args[0][name] = after
            return ()

        return mutate

    def drop_local_gate_arming(gate: Gate):
        def mutate(args):
            before = args[1]
            after = before.replace(f"export {gate.env_var}=1", "# removed", 1)
            if after == before:
                return None
            args[1] = after
            return ()

        return mutate

    # ── R2 / R3 ───────────────────────────────────────────────────────────
    def add_second_client(args):
        key = "crates/antseal-cli/Cargo.toml"
        args[2][key] = args[2][key] + '\n[dev-dependencies.reqwest]\nversion = "0.12"\n'
        return ()

    def add_renamed_client(args):
        key = "crates/antseal-net/Cargo.toml"
        args[2][key] = args[2][key] + '\nhttpthing = { package = "isahc", version = "1" }\n'
        return ()

    def move_the_client(args):
        key = "crates/antseal-cli/Cargo.toml"
        args[2][key] = args[2][key] + "\nureq = { workspace = true }\n"
        return ()

    def add_unregistered_endpoint_const(args):
        key = "crates/antseal-anchor/src/tsa.rs"
        args[3][key] = (
            args[3][key]
            + '\npub const BACKUP_TSA_URLS: [&str; 1] = ["https://tsa.example.org/tsr"];\n'
        )
        return ()

    # ── R4: the spawn venue ──────────────────────────────────────────────
    def disarm_the_spawn_helper(gate: Gate):
        """D99 R4.3 fault (a): the helper keeps constructing, stops arming
        one gate — the single code line that arms it is deleted."""

        def mutate(args):
            lines = args[5][SPAWN_HELPER].splitlines(keepends=True)
            pattern = arming_call(gate)
            for index, line in enumerate(lines):
                if not is_comment(line) and pattern.search(line):
                    del lines[index]
                    args[5][SPAWN_HELPER] = "".join(lines)
                    return ()
            return None

        return mutate

    def plant_a_bare_spawn(args):
        """D99 R4.3 fault (b): a suite constructs the binary for itself."""
        key = "crates/antseal-cli/tests/list_command.rs"
        args[5][key] = (
            args[5][key]
            + '\nfn spawn() { std::process::Command::new(env!("CARGO_BIN_EXE_antseal")); }\n'
        )
        return ()

    def plant_an_in_process_entry(args):
        """D99 R4.3 fault (c): the venue that cannot be armed at all."""
        key = "crates/antseal-cli/tests/exit_codes.rs"
        args[5][key] = (
            args[5][key]
            + "\nfn drive() { let _ = antseal_cli::main_entry(std::env::args_os()); }\n"
        )
        return ()

    def plant_env_clear(key: str, body: str):
        """D99 R4.3 fault (d), and D173 §3's "call-level re-arm" plant:
        append a function whose first line calls `env_clear()`, and hand back
        the `file:line` the failure must name."""

        def mutate(args):
            before = args[5][key]
            after = before.rstrip("\n") + "\n\n" + body + "\n"
            args[5][key] = after
            lineno = after.splitlines().index(body.splitlines()[0]) + 1
            return (f"{key}:{lineno}",)

        return mutate

    # ── R5: the test-util edge ───────────────────────────────────────────
    def plant_a_normal_test_util_edge(args):
        """D99 R5's fault: the bypass on a shipping edge."""
        key = "crates/antseal-cli/Cargo.toml"
        args[2][key] = args[2][key] + (
            "\n[dependencies.antseal-anchor]\nworkspace = true\n" 'features = ["test-util"]\n'
        )
        return ()

    def plant_a_transitive_test_util_feature(args):
        """The spelling no dependency table would reveal."""
        key = "crates/antseal-cli/Cargo.toml"
        before = args[2][key]
        after = before.replace(
            'ant-backend = ["antseal-net/ant-backend", "dep:tokio"]',
            'ant-backend = ["antseal-net/ant-backend", "dep:tokio"]\n'
            'debug-anchors = ["antseal-anchor/test-util"]',
            1,
        )
        if after == before:
            return None
        args[2][key] = after
        return ()

    clear_named = ("R4:", "env_clear()")
    arm(
        "R1 workflow arming deleted from ci.yml (anchor)",
        drop_workflow_arming(anchor),
        ("R1:", "ci.yml", anchor.env_var),
    )
    arm(
        "R1 workflow arming deleted from ci.yml (storage)",
        drop_workflow_arming(storage),
        ("R1:", "ci.yml", storage.env_var),
    )
    arm(
        "R1 local-gate.sh export deleted (anchor)",
        drop_local_gate_arming(anchor),
        ("R1:", "scripts/local-gate.sh", anchor.env_var),
    )
    arm(
        "R1 local-gate.sh export deleted (storage)",
        drop_local_gate_arming(storage),
        ("R1:", "scripts/local-gate.sh", storage.env_var),
    )
    arm(
        "R2 a second HTTP client (reqwest dev-dep)",
        add_second_client,
        ("R2:", "crates/antseal-cli/Cargo.toml", "`reqwest`"),
    )
    arm(
        "R2 a RENAMED second client (package = isahc)",
        add_renamed_client,
        ("R2:", "crates/antseal-net/Cargo.toml", "`isahc`"),
    )
    arm(
        "R2 ureq declared outside antseal-anchor",
        move_the_client,
        ("R2:", "crates/antseal-cli/Cargo.toml", "only antseal-anchor"),
    )
    arm(
        "R3 a new endpoint const the gate test never names",
        add_unregistered_endpoint_const,
        ("R3:", "BACKUP_TSA_URLS", "never names"),
    )
    arm(
        "R4 (a) the spawn helper stops arming (anchor)",
        disarm_the_spawn_helper(anchor),
        ("R4:", SPAWN_HELPER, "never sets", anchor.env_var),
    )
    arm(
        "R4 (a) the spawn helper stops arming (storage)",
        disarm_the_spawn_helper(storage),
        ("R4:", SPAWN_HELPER, "never sets", storage.env_var),
    )
    arm(
        "R4 (b) a bare CARGO_BIN_EXE_antseal in another suite",
        plant_a_bare_spawn,
        ("R4:", "crates/antseal-cli/tests/list_command.rs", BIN_ENV),
    )
    arm(
        "R4 (c) a test calling main_entry in-process",
        plant_an_in_process_entry,
        ("R4:", "crates/antseal-cli/tests/exit_codes.rs", IN_PROCESS_ENTRY),
    )
    arm(
        "R4 (d) an env_clear() in a file that never re-arms",
        plant_env_clear("crates/antseal-cli/tests/machine_mode.rs", UNARMED_CLEAR),
        clear_named + (anchor.env_var,),
        clear_named + (storage.env_var,),
    )
    # D173 §3 "call-level re-arm": a file with two `env_clear()`, one of them
    # re-armed. The file-level rule passed this; the failure must name the
    # second call's line, for both gates.
    arm(
        "R4 (d) a SECOND env_clear() in a file that re-arms once",
        plant_env_clear(E2E_RESTORE, UNARMED_CLEAR),
        clear_named + (anchor.env_var,),
        clear_named + (storage.env_var,),
    )
    arm(
        "R4 (d) a second env_clear() re-arming the anchor gate only",
        plant_env_clear(E2E_RESTORE, HALF_ARMED_CLEAR),
        clear_named + (storage.env_var,),
        forbid=clear_named + (anchor.env_var,),
    )
    arm(
        "R4 (d) both re-arms chained BEFORE the clear",
        plant_env_clear(E2E_RESTORE, REARM_BEFORE_CLEAR),
        clear_named + (anchor.env_var,),
        clear_named + (storage.env_var,),
    )
    green(
        "R4 (d) a second env_clear() re-arming both on its statement",
        plant_env_clear(E2E_RESTORE, FULLY_ARMED_CLEAR),
    )
    arm(
        "R5 test-util on a NORMAL dependency edge",
        plant_a_normal_test_util_edge,
        ("R5:", "crates/antseal-cli/Cargo.toml", "NORMAL dependency edge"),
    )
    arm(
        "R5 a feature enabling <crate>/test-util",
        plant_a_transitive_test_util_feature,
        ("R5:", "crates/antseal-cli/Cargo.toml", "debug-anchors"),
    )
    return 0 if ok else 1


def main() -> int:
    if "--self-test" in sys.argv[1:]:
        rc = self_test()
        print("check-anchor-net self-test " + ("PASS" if rc == 0 else "FAIL"))
        return rc
    workflow_texts, local_gate_text, manifests, sources, gate_text, tests = read_tree()
    failures = check(workflow_texts, local_gate_text, manifests, sources, gate_text, tests)
    for failure in failures:
        print(f"::error::check-anchor-net: {failure}")
    if failures:
        return 1
    constants = url_constants(sources)
    clears = sum(len(env_clear_statements(text)) for text in tests.values())
    print(
        f"check-anchor-net: {' and '.join(g.env_var for g in GATES)} each armed in "
        f"{len(workflow_texts)} workflow(s) + scripts/local-gate.sh + {SPAWN_HELPER} (the "
        f"third venue: every `antseal` binary construction in {len(tests)} test source(s) "
        f"goes through it, no test drives {IN_PROCESS_ENTRY} in-process, and {clears} "
        f"`env_clear()` call(s) each re-arm both on the statement that clears); one HTTP "
        f"client ({PERMITTED_CLIENT}) declared by {CLIENT_OWNER} alone; {len(constants)} "
        f"URL-valued constant(s) ({', '.join(sorted(constants))}) all named by the gate's "
        f"endpoint walk; `{TEST_UTIL_FEATURE}` on dev-dependency edges only"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
