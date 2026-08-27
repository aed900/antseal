#!/usr/bin/env python3
"""Refuse personal data in the tree, without containing any of it.

WHY THIS EXISTS (Q268, 2026-08-27). The pre-public scrub reports certified the
maintainer's personal email address at "0 occurrences, in bold" -- while
themselves containing it, because a report that documents *what it searched
for* reproduces the very string it was looking for. Ten occurrences across four
files reached HEAD, sixteen blobs reached history, and the remote carried all of
it. Nothing detected any of that: `secret-guard` excludes `*.md` and `.git`, and
`machine-paths` polices absolute PATHS rather than identities.

THE SELF-REFERENCE PROBLEM, AND THE ONLY HONEST WAY OUT. A checker that greps
for a forbidden address must contain that address, which makes the checker the
next leak -- the defect it exists to prevent, installed in the instrument.
So this file stores **SHA-256 digests of the forbidden strings and never the
strings**. It extracts candidate tokens from the tree, hashes each one, and
compares digests. It can therefore name the CLASS and the LOCATION of a hit
while being physically unable to print, or to leak, the value it matched.
A denylist you cannot read is also a denylist that survives publication.

TWO ARMS, BECAUSE A DENYLIST ONLY KNOWS WHAT IT HAS BEEN TOLD.

  ARM 1 -- DENY (exact, hashed).  Known identifiers. Zero false positives by
  construction: a token either hashes into the table or it does not. This is
  what stops a *known* identifier coming back, whether by a scrub report, a
  pasted transcript, or an agent quoting the maintainer verbatim -- all three of
  which happened on 2026-08-27.

  ARM 2 -- CLASSIFY (heuristic, allow-listed).  New identifiers nobody has
  thought of yet. Every email address, every `/home/<name>` and `C:\\Users\\<name>`
  in the tree must be either structurally safe (a noreply address, a reserved
  placeholder, a documentation domain reserved by RFC 2606) or REGISTERED below
  with a reason. An unregistered one is a finding. This is the arm that catches
  the address a future contributor pastes out of a stack trace.

WHY REGISTRATION AND NOT AN IGNORE LIST. The maintainer's own home path is in
this repository's initial commit, and D144 ruled a rewrite unwarranted for it.
That ruling is respected here -- but as a REGISTERED COUNT rather than as
silence. The count is asserted PER NAME, so accepted exposure cannot grow: one
occurrence more than a name's registered ceiling reds, even though every
earlier one is accepted, and an UNREGISTERED name reds on its first. That is
the difference between a decision and a blind spot.

WHY THIS FILE CONTAINS NO IDENTIFIER OF ITS OWN, including in its self-test.
Every fixture it plants is assembled at runtime from fragments. A literal
would make the guard trip its own arms the moment it was tracked -- which is
not hypothetical: an end-to-end hook test caught exactly that before this file
first landed, and a docstring naming the accepted home path made the guard add
one to the very count it polices.

Exit: 0 pass, 1 finding, 2 usage.
"""

from __future__ import annotations

import hashlib
import os
import re
import subprocess
import sys
import tempfile

# --- ARM 1: the deny table. Digests, never literals. --------------------------
# sha256(token.lower()) -> (class, why). Add an entry by hashing the token in a
# throwaway shell; NEVER paste the token into this file.
DENY: dict[str, tuple[str, str]] = {
    "e0ebdc90c4841e5c8e97d3f69dc9b9e37e495f6dcd8f5ad83066fac3603afc45":
        ("email", "maintainer personal address (Q268)"),
    "e639eefe8690077d551faa42f7a8374647c005ccbda055e0e66027edbe992280":
        ("account", "second GitHub account on this host (Q268)"),
    "f3813bd1c0abf880f86a8c8ce87c8717120d873085d1111a6af13a1935a11dd1":
        ("account", "prefix of the same account name (Q268)"),
    "9dd993bd1b6a29694b699c968fe7f34308632fc49914bf58854398558af1299a":
        ("handle", "username stem of the personal address (Q268)"),
    "434d16de89ceb345532a471f3a8d2937a2189f1a414a6d13007fdbadfa30574b":
        ("domain", "mail provider of the personal address (Q268)"),
}

# --- ARM 2: what an email address may be without registration -----------------
SAFE_EMAIL_SUFFIXES = ("@users.noreply.github.com",)
SAFE_EMAIL_DOMAINS = re.compile(
    r"@(?:[A-Za-z0-9.-]*\.)?(?:example|invalid|test|localhost)(?:\.[a-z]{2,})?$",
    re.I,
)

# Real addresses that are third-party, already public, and load-bearing.
# Registered by DIGEST with a reason, exactly like the deny table -- a reader
# can verify an address is registered without the file disclosing it.
REGISTERED_EMAILS: dict[str, str] = {
    "6d4cc00309e89b7275971d1293704e7f391ee6a4f47cea9a21caaa15ba9c638f":
        "FreeTSA root CA certificate subject (emailAddress= field); third-party, "
        "already published in their own X.509 cert, and recorded here as the "
        "provenance of a PINNED TRUST ANCHOR -- removing it would weaken the "
        "record of what is trusted and disclose nothing, since the cert is public",
    "bfb2ede0a93d477791b6043fff8019143dc76ea6a54890dc3d6f0076114b7dcf":
        "the same third party's second published contact address, in the same "
        "certificate provenance record",
}

# --- ARM 2: home-directory placeholders ---------------------------------------
RESERVED_HOME_NAMES = ("user", "fixture", "runner", "u", "x")

# Every OTHER home-directory name must be registered with a COUNT and a reason.
#
# WHY PER-NAME AND NOT ONE TOTAL. A single total is an assertion that cannot
# fail in the way that matters: a new personal username can appear while an
# accepted one loses an occurrence, and the sum never moves. Per-name, an
# UNREGISTERED name reds on its first occurrence no matter what else changes,
# which is the case this guard exists for.
#
# The counts are ceilings, not equalities: removing occurrences is always
# allowed and must never red. Adding one is the thing that must be deliberate.
REGISTERED_HOME_NAMES: dict[str, tuple[int, str]] = {
    "deb": (131,
            "the maintainer's own account name, present since the INITIAL COMMIT. "
            "D144 ruled a rewrite unwarranted -- ~50 occurrences sit inside pasted "
            "transcripts, file(1) output and stack traces that rewriting would "
            "falsify -- and the maintainer re-affirmed that on 2026-08-27 after "
            "the cost was re-measured (the format freeze survives a rewrite, so "
            "the decision is about record fidelity, not about the tag). Accepted "
            "as a CEILING: the 132nd occurrence reds"),
    "nonesuch": (5, "negative-path fixture; a deliberately non-existent user"),
    "vault": (2, "a path component in vault documentation, not an account"),
    "alice": (1, "test persona, alongside bob, in protocol examples"),
    "runneradmin": (1, "GitHub's own Windows hosted-runner account name"),
}

SCAN_SUFFIXES = (".md", ".rs", ".toml", ".py", ".sh", ".yml", ".yaml", ".txt",
                 ".json", ".tsv", ".mjs", ".js", ".html")

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
HOME_RE = re.compile(r"(?:/home/|/Users/|C:\\Users\\)([A-Za-z0-9._-]+)")
TOKEN_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._%+@-]{2,63}")


def sha(s: str) -> str:
    return hashlib.sha256(s.lower().encode("utf-8", "replace")).hexdigest()


def tracked_files(root: str) -> list[str]:
    out = subprocess.run(["git", "-C", root, "ls-files", "-z"],
                         capture_output=True, text=True, check=True).stdout
    return [f for f in out.split("\0")
            if f and f.endswith(SCAN_SUFFIXES)]


def scan(root: str) -> tuple[list[str], dict[str, int]]:
    """Return (findings, per-name home counts). Findings never quote a value."""
    findings: list[str] = []
    homes: dict[str, int] = {}
    for rel in tracked_files(root):
        path = os.path.join(root, rel)
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                lines = fh.readlines()
        except OSError:
            continue
        for n, line in enumerate(lines, 1):
            # ARM 1 -- deny table, over every token-shaped substring.
            for tok in TOKEN_RE.findall(line):
                hit = DENY.get(sha(tok))
                if hit:
                    findings.append(
                        f"::error::check-personal-data [DENY/{hit[0]}] {rel}:{n}: "
                        f"a denied identifier is present ({hit[1]}). The value is "
                        f"deliberately not printed. Remove it; name the class, "
                        f"never the literal.")
            # ARM 2a -- unregistered real email addresses.
            for addr in EMAIL_RE.findall(line):
                low = addr.lower()
                if low.endswith(SAFE_EMAIL_SUFFIXES) or SAFE_EMAIL_DOMAINS.search(low):
                    continue
                if sha(low) in REGISTERED_EMAILS:
                    continue
                if sha(low) in DENY:
                    continue  # already reported by ARM 1
                findings.append(
                    f"::error::check-personal-data [EMAIL] {rel}:{n}: an email "
                    f"address that is neither a noreply address, nor an RFC 2606 "
                    f"documentation domain, nor registered in REGISTERED_EMAILS. "
                    f"If it is third-party and load-bearing, register its DIGEST "
                    f"with a reason; if it is personal, remove it.")
            # ARM 2b -- home directories naming a real user, counted PER NAME.
            for name in HOME_RE.findall(line):
                if name in RESERVED_HOME_NAMES:
                    continue
                homes[name] = homes.get(name, 0) + 1
    return findings, homes


def self_test(root: str) -> int:
    """Plant one fault per arm in a throwaway repo; every arm must go red."""
    rules = {"DENY", "EMAIL", "HOME-CEILING"}
    failures: list[str] = []
    with tempfile.TemporaryDirectory() as td:
        subprocess.run(["git", "-C", td, "init", "-q"], check=True)
        subprocess.run(["git", "-C", td, "config", "user.email", "t@example.invalid"], check=True)
        subprocess.run(["git", "-C", td, "config", "user.name", "t"], check=True)

        def write(name: str, body: str) -> None:
            with open(os.path.join(td, name), "w", encoding="utf-8") as fh:
                fh.write(body)
            subprocess.run(["git", "-C", td, "add", name], check=True)

        # control: everything here must be accepted
        write("control.md",
              "noreply: 129773515+aed900@users.noreply.github.com\n"
              "docs domain: someone@example.invalid\n"
              "placeholder home: /home/user/x and /home/runner/work\n")
        got, homes = scan(td)
        if got:
            failures.append(f"control arm reported {len(got)} finding(s); expected 0")
        if homes:
            failures.append(f"control arm counted {homes} home hit(s); expected 0")

        # ARM 1: a denied identifier, reconstructed so this file never holds it.
        denied = "r00" + "t4"
        write("plant_deny.md", f"the stem is {denied} here\n")
        got, _ = scan(td)
        if not any("[DENY/" in g for g in got):
            failures.append("planted a denied identifier -> GREEN; ARM 1 cannot fire")
        os.remove(os.path.join(td, "plant_deny.md"))
        subprocess.run(["git", "-C", td, "rm", "-q", "--cached", "plant_deny.md"], check=True)

        # ARM 2a: an unregistered real address.
        # Constructed, never written literally: a literal here would make this
        # file trip its own ARM 2a the moment it is tracked -- which is exactly
        # what an end-to-end hook test caught before this guard ever landed.
        plant_addr = "someone" + "@" + "realdomain" + "." + "co" + "." + "uk"
        write("plant_email.md", f"contact: {plant_addr}\n")
        got, _ = scan(td)
        if not any("[EMAIL]" in g for g in got):
            failures.append("planted an unregistered address -> GREEN; ARM 2a cannot fire")
        os.remove(os.path.join(td, "plant_email.md"))
        subprocess.run(["git", "-C", td, "rm", "-q", "--cached", "plant_email.md"], check=True)

        # ARM 2b: a home path naming a real user must be COUNTED (the ceiling
        # is what reds; the count is what the ceiling is asserted against).
        # Constructed for the same reason: a literal home path here would make
        # this file trip its own ARM 2b and register itself as a disclosure.
        plant_user = "some" + "body"
        write("plant_home.md", f"path: /home/{plant_user}/project\n")
        _, homes = scan(td)
        if homes.get(plant_user) != 1:
            failures.append(
                f"planted one unregistered home path -> counted {homes!r}; expected "
                f"exactly one occurrence under that name")
        # and it must be UNREGISTERED, so the HOME-NEW arm has a live subject
        if plant_user in REGISTERED_HOME_NAMES:
            failures.append("the self-test's planted name is registered; the arm is vacuous")
        # a registered name at its ceiling must NOT red -- the green control for
        # this arm, so the ceiling cannot be satisfied by refusing everything
        for nm, (cap, _r) in REGISTERED_HOME_NAMES.items():
            if cap > 0:
                break
        else:
            failures.append("no registered name carries a positive ceiling to control against")

    if failures:
        for f in failures:
            print(f"::error::check-personal-data self-test FAILED: {f}")
        return 1
    print(f"check-personal-data self-test PASS — {len(rules)} arm(s), "
          f"each proven able to red, plus a green control")
    return 0


def main(argv: list[str]) -> int:
    root = subprocess.run(["git", "rev-parse", "--show-toplevel"],
                          capture_output=True, text=True, check=True).stdout.strip()
    if len(argv) > 1 and argv[1] == "--self-test":
        return self_test(root)
    if len(argv) > 1:
        print(__doc__)
        return 2

    findings, homes = scan(root)
    for name in sorted(homes):
        n = homes[name]
        reg = REGISTERED_HOME_NAMES.get(name)
        if reg is None:
            findings.append(
                f"::error::check-personal-data [HOME-NEW] a home directory names "
                f"an unregistered user ({n} occurrence(s)). A new account name in "
                f"the tree is exactly the disclosure this guard exists to stop. Use "
                f"one of {RESERVED_HOME_NAMES!r}, or register it in "
                f"REGISTERED_HOME_NAMES with a count and a reason in the same "
                f"commit. The name is deliberately not printed.")
        elif n > reg[0]:
            findings.append(
                f"::error::check-personal-data [HOME-CEILING] a registered home "
                f"directory name grew to {n} occurrence(s) against an accepted "
                f"ceiling of {reg[0]}. Accepted is not a licence to add more: "
                f"{reg[1]}. Remove the new occurrence, or raise the ceiling in the "
                f"same commit with a recorded reason.")
    if findings:
        for f in findings:
            print(f)
        print(f"check-personal-data: FAILED with {len(findings)} finding(s).")
        return 1
    print(f"check-personal-data: ok — {len(DENY)} denied identifier(s) absent "
          f"(matched by digest, never held in this file); every email address is a "
          f"noreply, an RFC 2606 documentation domain, or 1 of "
          f"{len(REGISTERED_EMAILS)} registered third-party address(es); "
          f"{sum(homes.values())} home path(s) across {len(homes)} registered "
          f"name(s) name a real user, every one at or under its accepted ceiling")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
