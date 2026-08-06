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


def read_tree() -> tuple[dict[str, str], str, dict[str, str], dict[str, str], str]:
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
    return workflow_texts, local_gate_text, manifests, sources, gate_text


def check(
    workflow_texts: dict[str, str],
    local_gate_text: str,
    manifests: dict[str, str],
    sources: dict[str, str],
    gate_text: str,
) -> list[str]:
    return (
        check_arming(workflow_texts, local_gate_text)
        + check_single_client(manifests)
        + check_inventory(sources, gate_text)
    )


def self_test() -> int:
    """One planted fault per rule; each must turn this check RED.

    Every fault is applied to an in-memory copy of the real tree, so a
    self-test can never leave damage behind and can never be skipped because
    a scratch directory was not writable.
    """
    workflow_texts, local_gate_text, manifests, sources, gate_text = read_tree()
    control = check(workflow_texts, local_gate_text, manifests, sources, gate_text)
    print(f"  control (unmodified tree){'':30s} -> {'RED' if control else 'GREEN'}")
    if control:
        for failure in control:
            print(f"    ::error:: control run is RED: {failure}")
        return 1

    ok = True

    def arm(label: str, mutate) -> None:
        nonlocal ok
        args = [dict(workflow_texts), local_gate_text, dict(manifests), dict(sources), gate_text]
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

    arm("R1 workflow arming deleted from ci.yml", drop_workflow_arming)
    arm("R1 local-gate.sh export deleted", drop_local_gate_arming)
    arm("R2 a second HTTP client (reqwest dev-dep)", add_second_client)
    arm("R2 a RENAMED second client (package = isahc)", add_renamed_client)
    arm("R2 ureq declared outside antseal-anchor", move_the_client)
    arm("R3 a new endpoint const the gate test never names", add_unregistered_endpoint_const)
    return 0 if ok else 1


def main() -> int:
    if "--self-test" in sys.argv[1:]:
        rc = self_test()
        print("check-anchor-net self-test " + ("PASS" if rc == 0 else "FAIL"))
        return rc
    workflow_texts, local_gate_text, manifests, sources, gate_text = read_tree()
    failures = check(workflow_texts, local_gate_text, manifests, sources, gate_text)
    for failure in failures:
        print(f"::error::check-anchor-net: {failure}")
    if failures:
        return 1
    constants = url_constants(sources)
    print(
        f"check-anchor-net: {ENV_VAR} armed in {len(workflow_texts)} workflow(s) "
        f"+ scripts/local-gate.sh; one HTTP client ({PERMITTED_CLIENT}) declared by "
        f"{CLIENT_OWNER} alone; {len(constants)} URL-valued constant(s) "
        f"({', '.join(sorted(constants))}) all named by the gate's endpoint walk"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
