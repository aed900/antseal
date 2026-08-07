#!/usr/bin/env python3
"""The no-real-anchor-network policy's static half (task **Q16**).

The policy's *enforcement* is a runtime gate:
`crates/antseal-anchor/src/http/offline.rs` refuses any endpoint that is not
a loopback IP literal, inside `HttpClient::attempt` — the one function in the
workspace that hands a URL to `ureq`. Its `cfg(test)` arm is armed by the
compiler and has no off switch. Read that module first; this script does not
duplicate it.

What a runtime gate structurally cannot see is checked here, and it is
exactly the set of ways the gate stops applying without anything going red:

  R1  **The arming.** The `cfg(test)` arm covers antseal-anchor's own unit
      tests. Every *other* test binary — `antseal-cli/tests/*.rs`, which
      drives the real submission gate through the real pipeline — links the
      crate's ordinary build, where `cfg(test)` is false and only
      `ANTSEAL_NO_REAL_ANCHOR_NETWORK` arms it. An arming that lives in a
      workflow nobody checks is an arming a reformat deletes. So: every
      committed workflow declares it at workflow level, and
      `scripts/local-gate.sh` exports it.

  R2  **One HTTP client.** The gate is inside `antseal-anchor`'s substrate. A
      second HTTP client anywhere in the workspace bypasses it completely,
      and nothing else would notice: `ci-lanes.sh dep-graph`'s forbidden-crate
      scan covers `antseal-core`'s graph only, so `reqwest` in
      `antseal-cli`'s dev-dependencies is invisible to every existing lane.

  R3  **Inventory closure.** The gate's headline test walks the product's
      default endpoint constants by *value*, so a calendar added to an
      existing list is covered for free. A brand-new constant is the case a
      value-walk cannot see. Every URL-valued `pub const` in antseal-anchor
      must therefore be named in the gate's test module.

  R4  **The spawn venue** (D99 R4.3). R1 covers the two venues that arm a
      whole *run* — the workflows and `scripts/local-gate.sh`. Neither
      covers a bare `cargo test -p antseal-cli`, which is what a contributor
      actually types, and which was **measured** on 2026-08-06 to run with
      `deny_reason() == None` and to reach `freetsa.org` for real. So the
      harness itself must guarantee the variable rather than inherit it:
      every construction of the `antseal` binary goes through
      `crates/antseal-cli/tests/common/spawn.rs`, that helper sets the
      variable, and no test source calls `main_entry` in-process — a test
      **cannot** arm its own process, because `std::env::set_var` is `unsafe`
      in edition 2024 and `[workspace.lints.rust]` denies `unsafe_code`
      (both confirmed by compiling them). `env_clear()` gets its own arm:
      it is the one call that strips the variable even in CI.

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
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
WORKFLOWS_DIR = REPO / ".github" / "workflows"
LOCAL_GATE = REPO / "scripts" / "local-gate.sh"
ANCHOR_SRC = REPO / "crates" / "antseal-anchor" / "src"
GATE_MODULE = ANCHOR_SRC / "http" / "offline.rs"

ENV_VAR = "ANTSEAL_NO_REAL_ANCHOR_NETWORK"

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


def check_arming(
    workflow_texts: dict[str, str], local_gate_text: str
) -> list[str]:
    """R1 — the environment arm is actually armed, in both venues."""
    failures: list[str] = []
    for name, text in sorted(workflow_texts.items()):
        # Workflow level: the `env:` mapping at column 0, so every job
        # inherits it. A job-level arming would leave the next job added
        # unarmed, which is the failure this rule exists to prevent.
        top_level = re.search(r"^env:\n((?:[ \t]+.*\n|\n)*)", text, re.MULTILINE)
        block = top_level.group(1) if top_level else ""
        if not re.search(rf"^\s+{ENV_VAR}:\s*[\"']?1[\"']?\s*$", block, re.MULTILINE):
            failures.append(
                f"R1: .github/workflows/{name} does not set {ENV_VAR}: \"1\" in its "
                f"workflow-level `env:` block. Every workflow arms it, so a job added "
                f"later inherits the policy instead of quietly opting out of it."
            )
    if not re.search(rf"^export {ENV_VAR}=1$", local_gate_text, re.MULTILINE):
        failures.append(
            f"R1: scripts/local-gate.sh does not `export {ENV_VAR}=1`. The local gate is "
            f"the venue a contributor actually runs; unarmed, it is the one place an "
            f"integration test can still reach a real TSA or OTS calendar."
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
    return [line for line in text.splitlines() if not line.lstrip().startswith("//")]


def check_spawn_venue(test_sources: dict[str, str], helper_text: str | None) -> list[str]:
    """R4 — the CLI test harness guarantees the arming, in all four ways it
    can stop doing so."""
    failures: list[str] = []

    if helper_text is None:
        return [
            f"R4: {SPAWN_HELPER} does not exist. It is the ONLY place a test may construct the "
            f"`antseal` binary, and the only thing that arms {ENV_VAR} for a bare "
            f"`cargo test -p antseal-cli` — measured 2026-08-06 to otherwise run with the gate "
            f"disarmed and to reach freetsa.org for real (D99 §1.3)."
        ]

    # (a) The helper actually arms. A helper that constructs the binary
    # without the variable is worse than no helper: it looks like the
    # protection is there.
    if not re.search(rf"\.env\(\s*(?:{ENV_VAR}|NO_REAL_ANCHOR_NETWORK)", helper_text) and not re.search(
        rf"env\(\s*\"{ENV_VAR}\"", helper_text
    ):
        failures.append(
            f"R4: {SPAWN_HELPER} constructs the binary but never sets {ENV_VAR}. Every "
            f"spawned-binary suite in antseal-cli is armed by that one line and by nothing else; "
            f"without it a bare `cargo test -p antseal-cli` dials live calendars and TSAs and "
            f"every assertion still passes (Q16 §2)."
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
                f"`spawn::antseal()`, which arms {ENV_VAR}; if you need the PATH rather than a "
                f"Command, use `spawn::antseal_exe()`. A bare construction is a suite that "
                f"reaches real anchor endpoints on a developer's machine."
            )

    # (c) The in-process venue. This one cannot be made safe, only closed:
    # a test cannot arm its own process (`set_var` is unsafe in edition 2024,
    # and `unsafe_code` is denied workspace-wide — both confirmed by
    # compiling them, 2026-08-06).
    for name, text in sorted(test_sources.items()):
        if any(IN_PROCESS_ENTRY in line for line in uncommented(text)):
            failures.append(
                f"R4: {name} calls `{IN_PROCESS_ENTRY}` in-process. A test CANNOT arm {ENV_VAR} "
                f"for its own process — `std::env::set_var` is `unsafe` in edition 2024 and "
                f"[workspace.lints.rust] denies `unsafe_code` — so an in-process CLI entry that "
                f"dials calendars cannot be made safe. Spawn the binary through "
                f"`spawn::antseal()` instead (D99 R4.2)."
            )

    # (d) The one call that strips the arming even when CI supplied it.
    # `env_remove` is deliberately NOT covered: antseal-anchor's own
    # `no_real_network.rs` must remove the variable to prove the disarmed arm
    # reaches the network, which is the workspace's only proof the arm works.
    for name, text in sorted(test_sources.items()):
        lines = uncommented(text)
        if not any("env_clear()" in line for line in lines):
            continue
        if not any(ENV_VAR in line or "NO_REAL_ANCHOR_NETWORK" in line for line in lines):
            failures.append(
                f"R4: {name} calls `env_clear()` and never re-sets {ENV_VAR}. `env_clear()` is the "
                f"one operation that defeats the environment arm even in CI, where the workflow "
                f"arms it workflow-wide: the parent inherits it and the child is handed an empty "
                f"environment. Nothing else notices — a disarmed gate reaches the network and "
                f"every assertion still passes."
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

    R4's venue. These link each crate's ORDINARY build, where the gate's
    `cfg(test)` arm is false — which is the whole reason the environment arm
    has to be guaranteed here rather than assumed.
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


def self_test() -> int:
    """One planted fault per rule; each must turn this check RED.

    Every fault is applied to an in-memory copy of the real tree, so a
    self-test can never leave damage behind and can never be skipped because
    a scratch directory was not writable.
    """
    workflow_texts, local_gate_text, manifests, sources, gate_text, tests = read_tree()
    control = check(workflow_texts, local_gate_text, manifests, sources, gate_text, tests)
    print(f"  control (unmodified tree){'':30s} -> {'RED' if control else 'GREEN'}")
    if control:
        for failure in control:
            print(f"    ::error:: control run is RED: {failure}")
        return 1

    ok = True

    def arm(label: str, mutate) -> None:
        nonlocal ok
        args = [
            dict(workflow_texts),
            local_gate_text,
            dict(manifests),
            dict(sources),
            gate_text,
            dict(tests),
        ]
        mutated = mutate(args)
        assert mutated, f"self-test fault {label!r} did not apply"
        failures = check(*args)
        print(f"  planted fault: {label:52s} -> {'RED' if failures else 'GREEN'}")
        if not failures:
            print("    ::error:: the check stayed GREEN over a planted fault")
            ok = False

    def drop_workflow_arming(args) -> bool:
        name = "ci.yml"
        before = args[0][name]
        args[0][name] = re.sub(rf"^\s+{ENV_VAR}:.*\n", "", before, count=1, flags=re.MULTILINE)
        return args[0][name] != before

    def drop_local_gate_arming(args) -> bool:
        before = args[1]
        args[1] = before.replace(f"export {ENV_VAR}=1", "# removed", 1)
        return args[1] != before

    def add_second_client(args) -> bool:
        key = "crates/antseal-cli/Cargo.toml"
        before = args[2][key]
        args[2][key] = before + '\n[dev-dependencies.reqwest]\nversion = "0.12"\n'
        return args[2][key] != before

    def add_renamed_client(args) -> bool:
        key = "crates/antseal-net/Cargo.toml"
        before = args[2][key]
        args[2][key] = before + '\nhttpthing = { package = "isahc", version = "1" }\n'
        return args[2][key] != before

    def move_the_client(args) -> bool:
        key = "crates/antseal-cli/Cargo.toml"
        before = args[2][key]
        args[2][key] = before + '\nureq = { workspace = true }\n'
        return args[2][key] != before

    def add_unregistered_endpoint_const(args) -> bool:
        key = "crates/antseal-anchor/src/tsa.rs"
        before = args[3][key]
        args[3][key] = (
            before
            + '\npub const BACKUP_TSA_URLS: [&str; 1] = ["https://tsa.example.org/tsr"];\n'
        )
        return args[3][key] != before

    # ── R4: the spawn venue ──────────────────────────────────────────────
    def disarm_the_spawn_helper(args) -> bool:
        """D99 R4.3 fault (a): the helper keeps constructing, stops arming."""
        before = args[5][SPAWN_HELPER]
        args[5][SPAWN_HELPER] = re.sub(
            r"^\s*command\.env\(NO_REAL_ANCHOR_NETWORK.*\n",
            "",
            before,
            count=1,
            flags=re.MULTILINE,
        )
        return args[5][SPAWN_HELPER] != before

    def plant_a_bare_spawn(args) -> bool:
        """D99 R4.3 fault (b): a suite constructs the binary for itself."""
        key = "crates/antseal-cli/tests/list_command.rs"
        before = args[5][key]
        args[5][key] = (
            before
            + '\nfn spawn() { std::process::Command::new(env!("CARGO_BIN_EXE_antseal")); }\n'
        )
        return args[5][key] != before

    def plant_an_in_process_entry(args) -> bool:
        """D99 R4.3 fault (c): the venue that cannot be armed at all."""
        key = "crates/antseal-cli/tests/exit_codes.rs"
        before = args[5][key]
        args[5][key] = (
            before + "\nfn drive() { let _ = antseal_cli::main_entry(std::env::args_os()); }\n"
        )
        return args[5][key] != before

    def plant_an_unarmed_env_clear(args) -> bool:
        """The fourth way, found while implementing D99 R4: a child handed an
        empty environment is disarmed even in CI."""
        key = "crates/antseal-cli/tests/machine_mode.rs"
        before = args[5][key]
        args[5][key] = before + "\nfn clean() { command.env_clear().env(\"HOME\", home); }\n"
        return args[5][key] != before

    # ── R5: the test-util edge ───────────────────────────────────────────
    def plant_a_normal_test_util_edge(args) -> bool:
        """D99 R5's fault: the bypass on a shipping edge."""
        key = "crates/antseal-cli/Cargo.toml"
        before = args[2][key]
        args[2][key] = before + (
            '\n[dependencies.antseal-anchor]\nworkspace = true\n'
            'features = ["test-util"]\n'
        )
        return args[2][key] != before

    def plant_a_transitive_test_util_feature(args) -> bool:
        """The spelling no dependency table would reveal."""
        key = "crates/antseal-cli/Cargo.toml"
        before = args[2][key]
        args[2][key] = before.replace(
            'ant-backend = ["antseal-net/ant-backend", "dep:tokio"]',
            'ant-backend = ["antseal-net/ant-backend", "dep:tokio"]\n'
            'debug-anchors = ["antseal-anchor/test-util"]',
            1,
        )
        return args[2][key] != before

    arm("R1 workflow arming deleted from ci.yml", drop_workflow_arming)
    arm("R1 local-gate.sh export deleted", drop_local_gate_arming)
    arm("R2 a second HTTP client (reqwest dev-dep)", add_second_client)
    arm("R2 a RENAMED second client (package = isahc)", add_renamed_client)
    arm("R2 ureq declared outside antseal-anchor", move_the_client)
    arm("R3 a new endpoint const the gate test never names", add_unregistered_endpoint_const)
    arm("R4 (a) the spawn helper stops arming the variable", disarm_the_spawn_helper)
    arm("R4 (b) a bare CARGO_BIN_EXE_antseal in another suite", plant_a_bare_spawn)
    arm("R4 (c) a test calling main_entry in-process", plant_an_in_process_entry)
    arm("R4 (d) an env_clear() that never re-arms", plant_an_unarmed_env_clear)
    arm("R5 test-util on a NORMAL dependency edge", plant_a_normal_test_util_edge)
    arm("R5 a feature enabling <crate>/test-util", plant_a_transitive_test_util_feature)
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
    print(
        f"check-anchor-net: {ENV_VAR} armed in {len(workflow_texts)} workflow(s) "
        f"+ scripts/local-gate.sh + {SPAWN_HELPER} (the third venue: every "
        f"`antseal` binary construction in {len(tests)} test source(s) goes through it, and no "
        f"test drives {IN_PROCESS_ENTRY} in-process); one HTTP client ({PERMITTED_CLIENT}) "
        f"declared by {CLIENT_OWNER} alone; {len(constants)} URL-valued constant(s) "
        f"({', '.join(sorted(constants))}) all named by the gate's endpoint walk; "
        f"`{TEST_UTIL_FEATURE}` on dev-dependency edges only"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
