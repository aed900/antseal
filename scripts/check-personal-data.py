#!/usr/bin/env python3
"""Refuse personal data in the tree and in the history it publishes, without
containing any of it.

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

FOUR ARMS, BECAUSE A DENYLIST ONLY KNOWS WHAT IT HAS BEEN TOLD.

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

  ARM 3 -- IDENTITY WITH NO PATH ATTACHED (2026-09-12).  ARM 2's home rule
  matches a PATH, so it cannot see an account name disclosed in prose: *"owned
  by `<name>`"*, an `ls -ld` line reading *"drwx------ <name> <name>"*, an
  `id -un` transcript, a `<name>:<name>` chown pair, a sentence that says *"the
  maintainer's Linux username `<name>`"*. Each of those discloses exactly the
  datum the ceiling on ARM 2 exists to bound, while contributing nothing to it,
  so the ceiling mechanism did not protect the prose and new bare-name
  disclosures could be added indefinitely without reddening anything. This is
  the *machine-paths* defect one layer in: that check passed a leaked
  `<name>:<name>` pair because it matched absolute PATHS rather than usernames.
  ARM 3 matches the IDENTITY CONTEXT and takes the name out of it, so the count
  is per name and bounded like ARM 2's.

  ARM 4 -- THE SAME RULES OVER PUBLISHABLE HISTORY (`--history`, 2026-09-12).
  ARMS 1-3 walk `git ls-files`, i.e. HEAD. **A flip publishes history, not a
  tree.** The only other committed instrument that walks the whole object store
  is `scripts/scrub-history.sh`, and all eleven of its rules are
  credential-shaped (PEM, keystore, vault magic, age, minisign, wallet-key
  export, PGP, forge token, AWS, Slack) -- grep its rule patterns for
  `@|home|[Uu]ser|mail` and you get nothing, so its `verdict=CLEAN` is
  structurally incapable of speaking to an identifier. Before ARM 4 nothing in
  this repository scanned history for an email, a home path or a username.
  ARM 4 streams every object reachable from the refs that publish and applies
  ARMS 1-3 to blobs, commit objects and annotated tags ALIKE -- commit objects
  raw, so author and committer headers and commit messages are covered. That
  last point is load-bearing rather than decorative: the account name is in
  **6 commit messages**, which a HEAD-only scan cannot see, and a history mode
  that skipped them would be this file's own defect one layer down.

WHY REGISTRATION AND NOT AN IGNORE LIST. The maintainer's own home path is in
this repository's initial commit, and D144 ruled a rewrite unwarranted for it.
That ruling is respected here -- but as a REGISTERED COUNT rather than as
silence. The count is asserted PER NAME, so accepted exposure cannot grow: one
occurrence more than a name's registered ceiling reds, even though every
earlier one is accepted, and an UNREGISTERED name reds on its first. That is
the difference between a decision and a blind spot.

WHY THE HISTORY CEILINGS COUNT PATHS AND MESSAGE OBJECTS, NOT OCCURRENCES.
History is append-only: an occurrence in it cannot be edited away, so a ceiling
there must bound the DISCLOSURE and not the commit rate. A raw occurrence
ceiling bounds the commit rate and nothing else -- one edit to the heaviest
file adds 38 occurrences by itself -- so it would red within days on routine
work, and a known-red check wired into a ritual is worse than no check. The
quantities ARM 4 asserts instead move only on a deliberate act, and together
they bound occurrence growth anyway, which is why the occurrence total needs no
ceiling of its own. A new occurrence can arrive exactly three ways:

  (a) in a file that already discloses the name -- bounded by the HEAD ceiling,
      because the commit is made from the tree ARMS 2-3 police;
  (b) in a file that does not yet disclose it -- a new PATH, asserted here;
  (c) in a commit message or tag message -- a new MESSAGE OBJECT, asserted here.

WHY THIS FILE CONTAINS NO IDENTIFIER OF ITS OWN, including in its self-test.
Every fixture it plants is assembled at runtime from fragments. A literal
would make the guard trip its own arms the moment it was tracked -- which is
not hypothetical: an end-to-end hook test caught exactly that before this file
first landed, and a docstring naming the accepted home path made the guard add
one to the very count it polices. ARM 3 sharpens the hazard, because it matches
bare names rather than paths, so `REGISTERED_HOME_NAMES` -- whose keys ARE
names -- sits one loose pattern away from being counted by the arm below it.
The self-test therefore asserts that THIS FILE contributes zero names to ARM 3,
as an assertion rather than as a comment, and every new registry below is keyed
by DIGEST so that a reader who already knows a name can verify its
registration while the file discloses none of them.

Usage:
  check-personal-data.py                 ARMS 1-3 over `git ls-files` (HEAD)
  check-personal-data.py --history [ref...]
                                         ARMS 1-3 over every object reachable
                                         from the given refs; default is the
                                         set a flip publishes
  check-personal-data.py --self-test     plant one fault per arm; each must red

Exit: 0 pass, 1 finding, 2 usage.
"""

from __future__ import annotations

import hashlib
import io
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
    "cd29c5ac348a026a3ec5286890908fffb5bf6ab77f20672171be323a70c95026":
        "the no-reply address in the agent attribution trailer that the harness "
        "appends to a commit message. Third-party, published, and a no-reply "
        "mailbox by construction, so it names no person. Registered because it "
        "is a HISTORY-ONLY disclosure -- measured 2026-09-12 in 167 of the 569 "
        "publishable commit objects and in ZERO tracked files, so ARMS 1-3 were "
        "structurally unable to see it and ARM 4 found it on its first run. It "
        "is the worked example of why a HEAD-only identifier scan is not an "
        "answer about what a flip publishes",
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

# --- ARM 3: bare account names, asserted by their identity context ------------
#
# Names that assert no person, and so need no ceiling. ARM 2's placeholders are
# included by construction: `/home/user` and a bare `user` are the same claim
# about nobody. The rest are POSIX system accounts and groups, which every host
# has and which therefore identify no host, plus the role word `maintainer` and
# the two redaction placeholders the wave-31 scrub installed in place of real
# identifiers (`maintainer-handle`, `email-maintainer`) -- a placeholder that
# reds would punish the redaction for having happened, and one of them is in
# the tree 11 times in history and once at HEAD, measured.
RESERVED_IDENTITY_NAMES = RESERVED_HOME_NAMES + (
    "root", "nobody", "nogroup", "daemon", "www-data", "sudo", "adm", "staff",
    "wheel", "maintainer", "maintainer-handle", "email-maintainer",
)

# Debian `adduser`'s NAME_REGEX shape, which is what a real account name on this
# host looks like. Deliberately lowercase-only: allowing capitals re-admits
# every task-row id (`Q265`), constant (`MAX_INTERMEDIATE_COUNT`) and filename
# in the corpus, measured, and the residual -- a mixed-case account name
# disclosed in prose -- is covered by ARM 1 the moment it is a KNOWN name.
IDENT_NAME = r"[a-z_][a-z0-9_-]{0,31}"
# Two characters minimum, for the one context that has no literal anchor of its
# own. MEASURED, not cautious: a same-token colon pair of length ONE is a slice
# expression, not an account -- `oids[i:i + CAT_FILE_BATCH]` in this very file
# was counted as a user:group pair by the first draft of that rule.
IDENT_NAME2 = r"[a-z_][a-z0-9_-]{1,31}"
IDENT_QUOTE = r"[`'\"]"
MODE_STR = r"[-bcdlps][-rwxsStT]{9}"

# A line must actually be about filesystem ownership before a phrase as common
# as "owned by" is read as naming an account. MEASURED, not guessed: without
# this the arm fires 15 times on "owned by a", 10 on "owned by the", and on
# every task row and constant the corpus says something is "owned by".
# `\bowner\b` is deliberately NOT a marker -- in this repository an "owner" is
# the decision row that owns a requirement, and admitting it let exactly one
# false positive through (`MAX_INTERMEDIATE_COUNT`, TODO.md:623).
POSIX_OWNERSHIP_MARKER = re.compile(
    r"\bmode\b|\b0[0-7]{3}\b|\buid\b|\bgid\b|\bch(?:own|grp)\b|\bumask\b"
    r"|\bls[ \t]+-[a-zA-Z]*l|\bstat\b|" + MODE_STR +
    r"|\bid[ \t]+-un\b|\bwhoami\b|\blogname\b|%U\b|\$USER\b|/etc/passwd", re.I)

# Each context is a POSIX identity ASSERTION with no path in it. Every one of
# them is proven able to red, individually, by `--self-test`; several have an
# empty domain at HEAD today, and an arm whose subject is empty is green
# because nothing reachable could redden it, which is this project's dominant
# defect class -- the self-test is what keeps them honest until history or a
# future paste gives them a subject.
#
# `[ \t]` and `[^\n]` throughout, never `\s` or `.`: these run over whole
# objects, and a `\s+` would let a mode string at the end of one line bind to
# names on the next.
IDENTITY_CONTEXTS: dict[str, re.Pattern[str]] = {
    # `ls -l` / `ls -ld` transcript: mode, optional link count, owner, group.
    "LS-L": re.compile(MODE_STR + r"[.+@]?[ \t]+(?:\d+[ \t]+)?(" + IDENT_NAME +
                       r")[ \t]+(" + IDENT_NAME + r")(?![\w./-])"),
    # chown/chgrp, with or without a group half. The TARGET must look like a
    # path, which is what separates a command from prose: without that clause
    # the rule read the phrase "chown pair" in this file's own docstring as an
    # account named `pair`, and would read every sentence about chown the same
    # way.
    "CHOWN": re.compile(r"\bch(?:own|grp)[ \t]+(?:-[\w-]+[ \t]+)*(" + IDENT_NAME +
                        r")(?:[:.](" + IDENT_NAME + r"))?[ \t]+(?=[~/$'\"]|\./)"),
    # A bare user:group pair. The BACKREFERENCE is what makes this safe: it
    # requires both halves to be the same token, which ordinary prose and
    # `key: value` never are, and which is exactly the shape `machine-paths`
    # passed because it was matching paths. `[` is excluded on the left and `]`
    # on the right because a slice expression has the same shape as a
    # user:group pair; so is `$`, for a macro fragment specifier (`$ty:ty`,
    # measured in `manifest/registry.rs`).
    "USERGROUP": re.compile(r"(?<![\w@./:$\[-])(" + IDENT_NAME2 + r"):(\1)(?![\w./:@\]-])"),
    # The output of a command whose whole purpose is to print the account name.
    "IDCMD": re.compile(r"(?:\bid[ \t]+-un\b|\bwhoami\b|\blogname\b|%U\b|\$USER\b"
                        r"|\bUSERNAME\b)[^\n]{0,48}?(?:->|=>|:|=)[ \t]*" +
                        IDENT_QUOTE + r"?(" + IDENT_NAME + r")"),
    # Prose that says a name IS a username. The quoting requirement is measured:
    # admitting `**bold**` as a quote re-admitted one false positive
    # (`match-level`, tasks/Q.md:3492) and bought nothing.
    "NAMEPROSE": re.compile(r"\b(?:user|account|login)[ \t]?names?\b[^\n]{0,72}?" +
                            IDENT_QUOTE + r"(" + IDENT_NAME + r")" + IDENT_QUOTE, re.I),
    # A /etc/passwd or `getent` record.
    "PASSWD": re.compile(r"(?<![\w./-])(" + IDENT_NAME + r"):[x*!]?:(\d{1,6}):(\d{1,6})"),
}
# Handled apart from the table because its marker must be on the SAME LINE:
# whole-object matching would let a mode string anywhere in a 4 000-line
# document license an "owned by" phrase at the other end of it.
OWNED_BY_RE = re.compile(r"\bowned by[ \t]+" + IDENT_QUOTE + r"(" + IDENT_NAME +
                         r")" + IDENT_QUOTE, re.I)

# Cheap prefilter. ARM 4 runs the contexts above over ~245 MB of objects; this
# reduces that to the objects that could match at all, and cost 55 s of the
# first draft's 169 s. It must stay a strict SUPERSET of the ANCHORED contexts'
# anchors, and the self-test asserts the correspondence in BOTH directions:
# every anchored context's own fixture must survive the prefilter, and every
# context listed as unanchored must NOT, so neither a missing anchor nor a
# stale listing can filter a context silently out of its own arm.
IDENTITY_ANCHOR = re.compile(
    r"owned by|ch(?:own|grp)|whoami|logname|id[ \t]+-un|%U|\$USER|USERNAME"
    r"|(?:user|account|login)[ \t]?name|" + MODE_STR + r"|:[x*!]?:\d", re.I)

# One context has NO literal anchor -- a `<name>:<name>` pair is pure shape --
# so it runs over every object unconditionally. Gating it behind the prefilter
# is not a cheap approximation, it is a DISABLED RULE: the first draft did
# exactly that and the rule could never fire on anything, which the self-test
# caught. The split is named here rather than implied, and asserted below.
UNANCHORED_CONTEXTS = ("USERGROUP",)

# Bare account names at HEAD, per name, as a CEILING. Keyed by digest: this
# registry's subject is a name, so holding the key as a literal is the leak the
# whole file is built to avoid.
REGISTERED_IDENTITY_NAMES: dict[str, tuple[int, str]] = {
    "9cfa1468c93fc18652e34a000f0c6614b0fa18f6f4887477ad9b0d36ca6a7eaa": (7,
        "the maintainer's own account name, disclosed with NO PATH ATTACHED and "
        "so invisible to ARM 2's ceiling of 131. Measured at HEAD 2026-09-12: 7 "
        "occurrences in 3 files -- an `ls -ld` line (owner and group, 2), the "
        "`id -un` and `stat -c '%U'` lines of the same transcript (2), one "
        "`owned by` sentence beside a mode (1), and two prose sentences that "
        "call the name a unix/Linux username outright (2). Accepted on D144's "
        "reasoning, which is about record fidelity and transfers exactly: these "
        "are pasted command output and a scrub report naming what it found, and "
        "rewriting them would falsify the record. Accepted as a CEILING: the "
        "8th occurrence reds. Note the third of those files is a scrub report "
        "whose own sentence reads *\"Discloses: the maintainer's Linux "
        "username\"* -- the report that documents a disclosure performs it, "
        "which is the Q268 shape this file was built for"),
}

# --- ARM 4: publishable history -----------------------------------------------
# The refs a flip publishes. `main` is what `git push` sends; the freeze tag is
# pinned by released digests and is pushed with it. Objects reachable only from
# other local refs are NOT published by pushing these, and are excluded by
# design -- the output says how many, because the local store is a superset and
# a reader must not mistake this scan for one over everything on disk.
HISTORY_REFS = ("main", "refs/tags/format-v1-freeze")

# An object whose first 8 KiB contain a NUL is binary: decoding it yields
# replacement characters and every identifier rule becomes noise over it. The
# count of skipped objects is REPORTED, so the exclusion is visible rather than
# silent.
BINARY_SNIFF_BYTES = 8192
CAT_FILE_BATCH = 512

# Identifier-shaped names in publishable history, per name. Keyed by digest, and
# uniformly so: the largest subject here is the maintainer's own account name,
# and a registry with two kinds of key invites the wrong one.
#
# Each value is (path ceiling, message-object ceiling, reason). The path count
# is over BLOBS, whose rev-list path attribution is one path per object; the
# message-object count is over COMMIT and annotated-TAG objects, which have no
# path and carry the forms that cannot be fixed without a rewrite.
REGISTERED_HISTORY_NAMES: dict[str, tuple[int, int, str]] = {
    "9cfa1468c93fc18652e34a000f0c6614b0fa18f6f4887477ad9b0d36ca6a7eaa": (34, 6,
        "the maintainer's own account name. Measured 2026-09-12 over the "
        "publishable set: 631 occurrences (619 via ARM 2's home paths, 12 via "
        "ARM 3's bare forms) across 34 blob paths and 6 COMMIT MESSAGES. The 6 "
        "is the number that matters and the reason ARM 4 reads commit objects "
        "raw: a commit message cannot be edited without a rewrite, so it is the "
        "one form D144's ruling cannot be revisited for cheaply. The occurrence "
        "total carries no ceiling on purpose -- see the header -- and the two "
        "that do move only when a NEW FILE or a NEW COMMIT MESSAGE discloses "
        "the name. An earlier audit measured 20 paths on 2026-08-27; both are "
        "right at their own commit, and the difference is the decision docs "
        "written since, which paste transcripts"),
    "e6f0a1fbb43c89196dcfcbef85908f19ab4c5f7cc4f4c452284697757683d7ef": (2, 1,
        "a path component in vault documentation, not an account -- the same "
        "name ARM 2 registers at a HEAD ceiling of 2. 12 occurrences, 2 blob "
        "paths, 1 commit message"),
    "8e284604842a79ac2ab1bc2c72cf5c8f94d1ee561aa3609d17f0ed807ae7d386": (2, 0,
        "the deliberately non-existent user of the negative-path fixtures -- the "
        "same name ARM 2 registers at a HEAD ceiling of 5. 11 occurrences, 2 "
        "blob paths, no commit message"),
    "6d4dd91a15baa7e03f6dc38c2498085f07ebe367f91e186bd69527e6de3e3e31": (1, 0,
        "GitHub's own Windows hosted-runner account name -- the same name ARM 2 "
        "registers at a HEAD ceiling of 1. 2 occurrences, 1 blob path"),
    "2bd806c97f0e00af1a1fc3328fa763a9269723c8db8fac4f93af71db186d6e90": (1, 0,
        "the protocol-example test persona -- the same name ARM 2 registers at a "
        "HEAD ceiling of 1. 1 occurrence, 1 blob path"),
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


def identity_names(text: str) -> dict[str, int]:
    """ARM 3. Bare account names asserted by an identity context, per name.

    Reserved placeholders are dropped here rather than at judgment time, so a
    caller can never mistake a placeholder for a subject that needs a ceiling.
    """
    names: dict[str, int] = {}

    def bump(nm: str | None) -> None:
        if not nm or nm.isdigit() or nm in RESERVED_IDENTITY_NAMES:
            return
        names[nm] = names.get(nm, 0) + 1

    for rule in UNANCHORED_CONTEXTS:
        for m in IDENTITY_CONTEXTS[rule].finditer(text):
            for g in m.groups():
                bump(g)
    if not IDENTITY_ANCHOR.search(text):
        return names

    for rule, rx in IDENTITY_CONTEXTS.items():
        if rule in UNANCHORED_CONTEXTS:
            continue
        for m in rx.finditer(text):
            for g in m.groups():
                bump(g)
    if "owned by" in text.lower():
        for line in text.splitlines():
            if "owned by" not in line.lower():
                continue
            if not POSIX_OWNERSHIP_MARKER.search(line):
                continue
            for m in OWNED_BY_RE.finditer(line):
                bump(m.group(1))
    return names


def scan(root: str) -> tuple[list[str], dict[str, int], dict[str, int]]:
    """Return (findings, home counts, bare-name counts). Findings never quote
    a value."""
    findings: list[str] = []
    homes: dict[str, int] = {}
    users: dict[str, int] = {}
    for rel in tracked_files(root):
        path = os.path.join(root, rel)
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except OSError:
            continue
        for n, line in enumerate(text.splitlines(), 1):
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
        # ARM 3 -- bare account names, over the whole object: two of the
        # contexts span a phrase rather than a line, and the prefilter is only
        # worth its cost once per file.
        for name, n in identity_names(text).items():
            users[name] = users.get(name, 0) + n
    return findings, homes, users


def judge_homes(homes: dict[str, int]) -> list[str]:
    """ARM 2b's verdict. Factored out of main() so the self-test can prove the
    CEILING branch actually reds -- before, that branch was covered only by a
    control asserting that some registered name carried a positive ceiling,
    which is an assertion about the table and not about the code."""
    findings: list[str] = []
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
    return findings


def judge_identities(users: dict[str, int]) -> list[str]:
    """ARM 3's verdict, in ARM 2b's shape: unregistered reds on the first
    occurrence, registered reds one past its ceiling."""
    findings: list[str] = []
    for name in sorted(users):
        n = users[name]
        reg = REGISTERED_IDENTITY_NAMES.get(sha(name))
        if reg is None:
            findings.append(
                f"::error::check-personal-data [USER-NEW] an identity context "
                f"names an unregistered account ({n} occurrence(s), digest "
                f"{sha(name)[:16]}). This form carries NO PATH, so the home-path "
                f"ceiling cannot see it and cannot bound it. Use one of "
                f"{RESERVED_IDENTITY_NAMES!r}, or register the name's DIGEST in "
                f"REGISTERED_IDENTITY_NAMES with a count and a reason in the same "
                f"commit. The name is deliberately not printed.")
        elif n > reg[0]:
            findings.append(
                f"::error::check-personal-data [USER-CEILING] a registered account "
                f"name grew to {n} bare occurrence(s) against an accepted ceiling "
                f"of {reg[0]}. Accepted is not a licence to add more: {reg[1]}. "
                f"Remove the new occurrence, or raise the ceiling in the same "
                f"commit with a recorded reason.")
    return findings


# --- ARM 4: streaming the object store ----------------------------------------


def read_exact(fh: io.BufferedIOBase, n: int) -> bytes:
    """Read exactly n bytes or raise.

    A single read(n) on a PIPE is permitted to return short. Taking that short
    result as the whole object desynchronises a `cat-file --batch` stream: every
    later header is read out of the middle of a payload, nothing matches, and
    the scan reports a near-zero count -- a FALSE CLEAN, which is the worst
    failure this file can have. This project hit exactly that trap this week.
    """
    buf = bytearray()
    while len(buf) < n:
        chunk = fh.read(n - len(buf))
        if not chunk:
            raise RuntimeError(
                f"cat-file stream ended after {len(buf)} of {n} expected byte(s); "
                f"the scan is incomplete and its result is not a clean")
        buf += chunk
    return bytes(buf)


def read_record(fh: io.BufferedIOBase, want: str) -> tuple[str, int, bytes]:
    """Read one `cat-file --batch` record and prove it is the one we asked for.

    Three assertions, because a comment cannot fail: the header must have three
    fields, the object id it names must be the id we requested (the alignment
    check), and the record must end in exactly one LF (the framing check).
    """
    header = fh.readline().decode("utf-8", "replace").rstrip("\n")
    parts = header.split(" ")
    if len(parts) != 3:
        raise RuntimeError(f"cat-file header is not '<oid> <type> <size>': {header!r}")
    got, typ, size_s = parts
    if got != want:
        raise RuntimeError(
            f"cat-file stream desynchronised: asked for {want}, header names "
            f"{got}. Every object after this point would be read from the middle "
            f"of another one's payload.")
    size = int(size_s)
    payload = read_exact(fh, size)
    term = read_exact(fh, 1)
    if term != b"\n":
        raise RuntimeError(
            f"cat-file record for {want} ended with {term!r}, not LF; the "
            f"declared size of {size} byte(s) did not match the payload")
    return typ, size, payload


def resolve_refs(root: str, refs: list[str]) -> list[tuple[str, str]]:
    """Every named ref must resolve. A history scan that silently covered fewer
    refs than it claimed -- a fresh clone without tags, a renamed branch -- would
    report a clean about a smaller subject than the flip publishes."""
    out: list[tuple[str, str]] = []
    for ref in refs:
        if ref.startswith("-"):
            out.append((ref, "(pseudo-ref, passed to rev-list as given)"))
            continue
        r = subprocess.run(["git", "-C", root, "rev-parse", "--verify", "--quiet",
                            ref + "^{}"], capture_output=True, text=True)
        if r.returncode != 0 or not r.stdout.strip():
            raise RuntimeError(
                f"ref {ref!r} does not resolve in this repository; refusing to "
                f"report a history verdict over a smaller subject than asked for")
        out.append((ref, r.stdout.strip()))
    return out


def scan_history(root: str, refs: list[str]) -> tuple[list[str], dict[str, object]]:
    """ARMS 1-3 over every object reachable from `refs`.

    Blobs, commit objects and annotated tags alike, the last two raw so that
    author and committer headers and messages are covered.
    """
    resolved = resolve_refs(root, refs)
    rl = subprocess.run(["git", "-C", root, "rev-list", "--objects"] + refs,
                        capture_output=True, text=True, check=True).stdout
    oids: list[str] = []
    paths: dict[str, str] = {}
    for line in rl.splitlines():
        if not line:
            continue
        head, _, tail = line.partition(" ")
        oids.append(head)
        paths[head] = tail or "(no path)"

    counts: dict[str, int] = {}
    type_bytes: dict[str, int] = {}
    scanned_bytes = 0
    skipped_binary = 0
    seen = 0
    deny_objs: dict[str, set[str]] = {}
    email_objs: dict[str, set[str]] = {}
    # name -> [occurrences, {blob paths}, {message object ids}, {via}]
    tally: dict[str, list] = {}
    memo: dict[str, object] = {}

    def note(name: str, n: int, oid: str, typ: str, via: str) -> None:
        row = tally.setdefault(name, [0, set(), set(), set()])
        row[0] += n
        if typ == "blob":
            row[1].add(paths.get(oid, "(no path)"))
        else:
            row[2].add(oid)
        row[3].add(via)

    proc = subprocess.Popen(["git", "-C", root, "cat-file", "--batch"],
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE, bufsize=0)
    try:
        assert proc.stdin is not None and proc.stdout is not None
        i = 0
        while i < len(oids):
            batch = oids[i:i + CAT_FILE_BATCH]
            i += CAT_FILE_BATCH
            proc.stdin.write("".join(o + "\n" for o in batch).encode("ascii"))
            proc.stdin.flush()
            for want in batch:
                typ, size, payload = read_record(proc.stdout, want)
                seen += 1
                counts[typ] = counts.get(typ, 0) + 1
                type_bytes[typ] = type_bytes.get(typ, 0) + size
                if typ == "tree":
                    continue
                if b"\0" in payload[:BINARY_SNIFF_BYTES]:
                    skipped_binary += 1
                    continue
                text = payload.decode("utf-8", "replace")
                scanned_bytes += size
                # ARM 1. De-duplicated per object and memoised across objects:
                # the deny table is exact, so one hit per object is the whole
                # finding and 245 MB of near-duplicate revisions is mostly the
                # same tokens over and over.
                for tok in set(TOKEN_RE.findall(text)):
                    hit = memo.get(tok, 0)
                    if hit == 0:
                        hit = DENY.get(sha(tok))
                        memo[tok] = hit
                    if hit:
                        deny_objs.setdefault(hit[0], set()).add(want)
                # ARM 2a.
                for addr in EMAIL_RE.findall(text):
                    low = addr.lower()
                    if low.endswith(SAFE_EMAIL_SUFFIXES) or SAFE_EMAIL_DOMAINS.search(low):
                        continue
                    d = sha(low)
                    if d in DENY:
                        continue  # already reported by ARM 1
                    if d in REGISTERED_EMAILS:
                        continue
                    email_objs.setdefault(d, set()).add(want)
                # ARM 2b.
                for name in HOME_RE.findall(text):
                    if name in RESERVED_HOME_NAMES:
                        continue
                    note(name, 1, want, typ, "home-path")
                # ARM 3.
                for name, n in identity_names(text).items():
                    note(name, n, want, typ, "bare-name")
    finally:
        if proc.stdin is not None:
            proc.stdin.close()
        proc.wait()

    # An assertion, not a comment: rev-list and cat-file must agree on how many
    # objects there were. If the stream had ended early, read_record would have
    # raised -- but a batch loop that skipped a chunk would not, and this is
    # what would catch it.
    if seen != len(oids):
        raise RuntimeError(
            f"read {seen} object(s) but rev-list named {len(oids)}; the scan did "
            f"not cover its own subject")

    findings: list[str] = []
    for cls, objs in sorted(deny_objs.items()):
        findings.append(
            f"::error::check-personal-data [HIST-DENY/{cls}] a denied identifier "
            f"is present in {len(objs)} publishable object(s) ({DENY_CLASS_WHY.get(cls, cls)}). "
            f"The value is deliberately not printed. A flip publishes these "
            f"objects; HEAD being clean does not remove them. Sample object(s): "
            f"{', '.join(sorted(objs)[:3])}")
    for d, objs in sorted(email_objs.items()):
        findings.append(
            f"::error::check-personal-data [HIST-EMAIL] an email address in "
            f"{len(objs)} publishable object(s) is neither a noreply address, nor "
            f"an RFC 2606 documentation domain, nor registered (digest "
            f"{d[:16]}). Register its DIGEST in REGISTERED_EMAILS with a reason, "
            f"or accept that publishing these refs publishes it. Sample "
            f"object(s): {', '.join(sorted(objs)[:3])}")
    for name in sorted(tally):
        occ, blob_paths, msg_objs, via = tally[name]
        reg = REGISTERED_HISTORY_NAMES.get(sha(name))
        if reg is None:
            findings.append(
                f"::error::check-personal-data [HIST-NEW] publishable history "
                f"discloses an unregistered identifier-shaped name (digest "
                f"{sha(name)[:16]}, found via {'+'.join(sorted(via))}): {occ} "
                f"occurrence(s) across {len(blob_paths)} blob path(s) and "
                f"{len(msg_objs)} message object(s). History cannot be edited, so "
                f"this is a REGISTRATION decision, not a removal: record the "
                f"name's DIGEST in REGISTERED_HISTORY_NAMES with its path and "
                f"message-object counts and a reason, or rewrite before the flip. "
                f"Sample path(s): {', '.join(sorted(blob_paths)[:3]) or '(none)'}. "
                f"The name is deliberately not printed.")
            continue
        cap_paths, cap_msgs, why = reg
        if len(blob_paths) > cap_paths:
            findings.append(
                f"::error::check-personal-data [HIST-PATHS] a registered "
                f"historical name now appears at {len(blob_paths)} blob path(s) "
                f"against an accepted ceiling of {cap_paths}. A NEW FILE "
                f"disclosing an accepted name is a deliberate act and must be "
                f"recorded as one: {why}. Remove it from the new path before "
                f"committing, or raise the ceiling in the same commit with a "
                f"reason. Path(s): {', '.join(sorted(blob_paths)[:5])}")
        if len(msg_objs) > cap_msgs:
            findings.append(
                f"::error::check-personal-data [HIST-MSGS] a registered "
                f"historical name now appears in {len(msg_objs)} message "
                f"object(s) against an accepted ceiling of {cap_msgs}. This is "
                f"the form that cannot be fixed without rewriting history, so it "
                f"is the one worth catching while the commit is still the tip: "
                f"{why}. Amend the message, or raise the ceiling in the same "
                f"commit with a reason. Object(s): "
                f"{', '.join(sorted(msg_objs)[:5])}")

    # Three sizes, not one, because conflating them is how a reader (and the
    # author of this function, on its first run) reaches the wrong conclusion:
    # objects ON DISK is a superset of objects REACHABLE FROM ANY LOCAL REF,
    # which is a superset of the scanned set. Only the middle one can ever be
    # pushed -- git sends reachable objects, so the on-disk remainder is
    # unreachable garbage that `git gc` removes and no push can publish.
    on_disk = subprocess.run(
        ["git", "-C", root, "cat-file", "--batch-all-objects", "--batch-check=%(objectname)"],
        capture_output=True, text=True, check=True).stdout.split()
    ref_reachable = subprocess.run(["git", "-C", root, "rev-list", "--objects", "--all"],
                                   capture_output=True, text=True, check=True).stdout.splitlines()
    all_refs = subprocess.run(["git", "-C", root, "for-each-ref", "--format=%(refname)"],
                              capture_output=True, text=True, check=True).stdout.split()
    stats: dict[str, object] = {
        "refs": resolved,
        "objects": len(oids),
        "counts": counts,
        "type_bytes": type_bytes,
        "scanned_bytes": scanned_bytes,
        "skipped_binary": skipped_binary,
        "distinct_tokens": len(memo),
        "on_disk_objects": len(on_disk),
        "ref_reachable_objects": len([x for x in ref_reachable if x]),
        "local_refs": len(all_refs),
        "default_scope": list(refs) == list(HISTORY_REFS),
        "names": {n: (v[0], len(v[1]), len(v[2])) for n, v in tally.items()},
    }
    return findings, stats


DENY_CLASS_WHY = {cls: why for cls, why in DENY.values()}


def self_test(root: str) -> int:
    """Plant one fault per arm in throwaway repos; every arm must go red.

    No fixture is a literal identifier: every planted name and address is
    assembled at runtime from fragments, because a literal in this file would
    make the guard trip its own arms the moment it was tracked.
    """
    # One entry per arm that this function proves ABLE TO RED. Controls are
    # counted separately: a control proves the arm is not red for everything,
    # which is a different claim.
    rules = {"DENY", "EMAIL", "HOME-NEW", "HOME-CEILING", "USER-NEW",
             "USER-CEILING", "HIST-DENY", "HIST-NEW", "HIST-PATHS", "HIST-MSGS",
             "STREAM-SHORT-READ", "STREAM-DESYNC", "STREAM-FRAMING",
             "SELF-LITERAL"}
    rules |= {"CONTEXT/" + name for name in IDENTITY_CONTEXTS}
    rules.add("CONTEXT/OWNED-BY")
    controls = 0
    failures: list[str] = []

    # --- ARM 3, per context. Every context must fire on its own form, must be
    # attributed to ITSELF rather than to a neighbour, and must survive the
    # prefilter -- an arm silently filtered out of its own scan is green
    # because nothing reachable could redden it.
    plant = "some" + "body"                      # never a registered name
    other = "no" + "one"
    # A DENIED identifier, reconstructed from fragments so this file never
    # holds it. Used by the ARM 1 plant and by the self-naming detector's own
    # proof, which needs a literal it knows the digest of.
    denied = "r00" + "t4"
    if sha(plant) in REGISTERED_IDENTITY_NAMES or plant in RESERVED_IDENTITY_NAMES:
        failures.append("the self-test's planted bare name is registered or "
                        "reserved; every ARM 3 arm below would be vacuous")
    if sha(other) in REGISTERED_HISTORY_NAMES or other in RESERVED_IDENTITY_NAMES:
        failures.append("the self-test's planted HISTORY name is registered or "
                        "reserved; the ARM 4 name arms below would be vacuous")
    if plant == other:
        failures.append("the two planted names are the same string; the ARM 4 "
                        "fixtures would inherit ARM 3's registration")
    fixtures = {
        "LS-L": "drwx------ " + plant + " " + plant + "  .minisign",
        "CHOWN": "chown -R " + plant + ":" + plant + " /srv/app",
        "USERGROUP": "the pair printed was " + plant + ":" + plant + " on that host",
        "IDCMD": "whoami -> " + plant,
        "NAMEPROSE": "the login name `" + plant + "` is a distinct datum",
        "PASSWD": "getent: " + plant + ":x:1000:1000:,,,:/srv:/bin/sh",
        "OWNED-BY": "exists at mode `0700`, owned by `" + plant + "`, same uid",
    }
    if set(UNANCHORED_CONTEXTS) - set(IDENTITY_CONTEXTS):
        failures.append(f"UNANCHORED_CONTEXTS names a context that does not "
                        f"exist: {set(UNANCHORED_CONTEXTS) - set(IDENTITY_CONTEXTS)!r}")
    for name, fixture in fixtures.items():
        anchored = name not in UNANCHORED_CONTEXTS
        if anchored and not IDENTITY_ANCHOR.search(fixture):
            failures.append(f"ARM 3 context {name}: the prefilter drops its own "
                            f"fixture, so the context can never run. Either give "
                            f"IDENTITY_ANCHOR its anchor, or name it in "
                            f"UNANCHORED_CONTEXTS")
        if not anchored and IDENTITY_ANCHOR.search(fixture):
            failures.append(f"ARM 3 context {name}: it is listed as unanchored, "
                            f"but its own fixture DOES survive the prefilter, so "
                            f"the listing is untested and may be hiding a real "
                            f"anchor")
        if identity_names(fixture).get(plant, 0) < 1:
            failures.append(f"ARM 3 context {name}: planted its own form -> not "
                            f"counted; that context cannot fire")
        rx = OWNED_BY_RE if name == "OWNED-BY" else IDENTITY_CONTEXTS[name]
        if not rx.search(fixture):
            failures.append(f"ARM 3 context {name}: its fixture is matched by "
                            f"some OTHER context but not by {name} itself, so "
                            f"{name} is proven by nothing")
    # OWNED-BY must NOT fire without an ownership marker on the same line --
    # measured: without that condition the arm fires on 40+ prose phrases and
    # on every task row the corpus says something is "owned by".
    if identity_names("this requirement is owned by `" + plant + "` in the register"):
        failures.append("ARM 3 OWNED-BY fired on a line with no ownership marker; "
                        "the arm is a prose matcher and will red on arrival")
    else:
        controls += 1
    # A reserved placeholder must never be counted.
    if identity_names("drwx------ " + RESERVED_IDENTITY_NAMES[0] + " " +
                      RESERVED_IDENTITY_NAMES[0] + "  x"):
        failures.append("ARM 3 counted a reserved placeholder; the arm would red "
                        "on its own control fixtures")
    else:
        controls += 1
    # THIS FILE must contribute nothing to ARM 3. REGISTERED_HOME_NAMES holds
    # names as literal keys, so one loose context would make the guard count
    # its own registry and police its own text -- see the header.
    own_src = ""
    try:
        with open(os.path.abspath(__file__), encoding="utf-8") as fh:
            own_src = fh.read()
    except OSError as exc:
        failures.append(f"could not read this file to prove it is clean: {exc}")
    own = identity_names(own_src)
    # ...and it must not hold a LITERAL of any identifier it registers. ARM 1
    # reds on a DENIED literal because this file is tracked, but a REGISTERED
    # one -- an address or an account name whose digest sits in a table above --
    # would pass every arm while sitting here in plain text. Asserted as an
    # EQUALITY against the one accepted exception, so that the exception is
    # named rather than silent: REGISTERED_HOME_NAMES is keyed by NAME, a
    # pre-existing shape this file's ARM 3 work deliberately did not change,
    # and its keys are therefore tokens of this file by construction. Any
    # OTHER self-naming token is a new leak and reds.
    registered_digests = (set(DENY) | set(REGISTERED_EMAILS)
                          | set(REGISTERED_IDENTITY_NAMES)
                          | set(REGISTERED_HISTORY_NAMES))

    def self_named(src: str) -> set[str]:
        return {t for t in TOKEN_RE.findall(src) if sha(t) in registered_digests}

    if own_src and self_named(own_src) != set(REGISTERED_HOME_NAMES):
        extra = self_named(own_src) - set(REGISTERED_HOME_NAMES)
        missing = set(REGISTERED_HOME_NAMES) - self_named(own_src)
        failures.append(
            f"this file holds a LITERAL of an identifier it registers by digest: "
            f"{len(extra)} token(s) beyond REGISTERED_HOME_NAMES' keys"
            + (f", and {len(missing)} of those keys are no longer present, so the "
               f"accepted exception should be narrowed in the same commit" if missing else "")
            + ". The names are deliberately not printed; hash the suspect token "
              "in a throwaway shell to find it.")
    elif own_src and not self_named(own_src + " " + denied) - set(REGISTERED_HOME_NAMES):
        failures.append("the self-naming detector does not see a planted denied "
                        "literal; it is an assertion that cannot fail")
    else:
        controls += 1
    if own:
        failures.append(f"this file contributes {sum(own.values())} name(s) to "
                        f"ARM 3 across {len(own)} distinct name(s); the guard is "
                        f"policing its own text and its ceilings include itself")
    else:
        controls += 1

    # --- ARMS 1-3 over a synthetic tree.
    with tempfile.TemporaryDirectory() as td:
        subprocess.run(["git", "-C", td, "init", "-q"], check=True)
        subprocess.run(["git", "-C", td, "config", "user.email", "t@example.invalid"], check=True)
        subprocess.run(["git", "-C", td, "config", "user.name", "t"], check=True)

        def write(name: str, body: str) -> None:
            with open(os.path.join(td, name), "w", encoding="utf-8") as fh:
                fh.write(body)
            subprocess.run(["git", "-C", td, "add", name], check=True)

        def drop(name: str) -> None:
            os.remove(os.path.join(td, name))
            subprocess.run(["git", "-C", td, "rm", "-q", "--cached", name], check=True)

        # control: everything here must be accepted
        write("control.md",
              "noreply: 129773515+aed900@users.noreply.github.com\n"
              "docs domain: someone@example.invalid\n"
              "placeholder home: /home/user/x and /home/runner/work\n")
        got, homes, users = scan(td)
        if got:
            failures.append(f"control arm reported {len(got)} finding(s); expected 0")
        if homes:
            failures.append(f"control arm counted {homes} home hit(s); expected 0")
        if users:
            failures.append(f"control arm counted {len(users)} bare name(s); expected 0")
        if not got and not homes and not users:
            controls += 1

        # ARM 1: the denied identifier reconstructed above.
        write("plant_deny.md", f"the stem is {denied} here\n")
        got, _, _ = scan(td)
        if not any("[DENY/" in g for g in got):
            failures.append("planted a denied identifier -> GREEN; ARM 1 cannot fire")
        drop("plant_deny.md")

        # ARM 2a: an unregistered real address.
        # Constructed, never written literally: a literal here would make this
        # file trip its own ARM 2a the moment it is tracked -- which is exactly
        # what an end-to-end hook test caught before this guard ever landed.
        plant_addr = "someone" + "@" + "realdomain" + "." + "co" + "." + "uk"
        write("plant_email.md", f"contact: {plant_addr}\n")
        got, _, _ = scan(td)
        if not any("[EMAIL]" in g for g in got):
            failures.append("planted an unregistered address -> GREEN; ARM 2a cannot fire")
        drop("plant_email.md")

        # ARM 2b: a home path naming a real user must be COUNTED (the count is
        # what the ceiling is asserted against) and must then be JUDGED.
        # Constructed for the same reason: a literal home path here would make
        # this file trip its own ARM 2b and register itself as a disclosure.
        write("plant_home.md", f"path: /home/{plant}/project\n")
        _, homes, _ = scan(td)
        if homes.get(plant) != 1:
            failures.append(
                f"planted one unregistered home path -> counted {homes!r}; expected "
                f"exactly one occurrence under that name")
        # and it must be UNREGISTERED, so the HOME-NEW arm has a live subject
        if plant in REGISTERED_HOME_NAMES:
            failures.append("the self-test's planted name is registered; the arm is vacuous")
        if not any("[HOME-NEW]" in g for g in judge_homes({plant: 1})):
            failures.append("an unregistered home name -> GREEN; HOME-NEW cannot fire")
        # HOME-CEILING, against a registered name held one over its ceiling.
        for nm, (cap, _r) in REGISTERED_HOME_NAMES.items():
            if not any("[HOME-CEILING]" in g for g in judge_homes({nm: cap + 1})):
                failures.append(f"a registered home name one over its ceiling of "
                                f"{cap} -> GREEN; HOME-CEILING cannot fire")
                break
            if judge_homes({nm: cap}):
                failures.append("a registered home name AT its ceiling reds; the "
                                "ceiling is an equality, not a ceiling")
                break
        else:
            controls += 1
        drop("plant_home.md")

        # ARM 3: the same two branches, over the bare-name counter.
        write("plant_user.md", "ls -ld ~/.config -> drwx------ " + plant + " " +
              plant + "  (created 12:37)\n")
        _, _, users = scan(td)
        if users.get(plant) != 2:
            failures.append(f"planted an `ls -ld` owner/group pair -> counted "
                            f"{users!r}; expected exactly 2 under that name")
        if not any("[USER-NEW]" in g for g in judge_identities({plant: 2})):
            failures.append("an unregistered bare name -> GREEN; USER-NEW cannot fire")
        REGISTERED_IDENTITY_NAMES[sha(plant)] = (1, "self-test fixture")
        try:
            if not any("[USER-CEILING]" in g for g in judge_identities({plant: 2})):
                failures.append("a registered bare name over its ceiling -> GREEN; "
                                "USER-CEILING cannot fire")
            if judge_identities({plant: 1}):
                failures.append("a registered bare name AT its ceiling reds; the "
                                "ceiling is an equality, not a ceiling")
            else:
                controls += 1
        finally:
            del REGISTERED_IDENTITY_NAMES[sha(plant)]
        drop("plant_user.md")

    # --- ARM 4's stream framing. Each assertion in read_record/read_exact must
    # be provably able to fire, or it is a comment wearing an if-statement.
    good = "0" * 40
    if not _raises(lambda: read_exact(io.BytesIO(b"abc"), 8)):
        failures.append("read_exact accepted a short stream; the exact trap that "
                        "yields a near-zero match count and a FALSE CLEAN")
    if not _raises(lambda: read_record(io.BytesIO(b"%s blob 3\nabc\n" % (("1" * 40).encode())), good)):
        failures.append("read_record accepted a header naming a different object; "
                        "a desynchronised stream would report a clean")
    if not _raises(lambda: read_record(io.BytesIO(("%s blob 3\nabcX" % good).encode()), good)):
        failures.append("read_record accepted a record not terminated by LF; a "
                        "size mismatch would go unnoticed")
    if _raises(lambda: read_record(io.BytesIO(("%s blob 3\nabc\n" % good).encode()), good)):
        failures.append("read_record rejected a WELL-FORMED record; the framing "
                        "assertions refuse everything and prove nothing")
    else:
        controls += 1

    # --- ARM 4 over a synthetic repository, including a COMMIT MESSAGE, which
    # is the form a HEAD-only scan structurally cannot see.
    with tempfile.TemporaryDirectory() as td:
        subprocess.run(["git", "-C", td, "init", "-q"], check=True)
        subprocess.run(["git", "-C", td, "config", "user.email", "t@example.invalid"], check=True)
        subprocess.run(["git", "-C", td, "config", "user.name", "t"], check=True)

        def commit(fname: str, body: str, msg: str) -> None:
            with open(os.path.join(td, fname), "w", encoding="utf-8") as fh:
                fh.write(body)
            subprocess.run(["git", "-C", td, "add", fname], check=True)
            subprocess.run(["git", "-C", td, "commit", "-q", "-m", msg], check=True)

        commit("ok.md", "placeholder home: /home/user/x\n", "safe subject line")
        got, stats = scan_history(td, ["HEAD"])
        if got:
            failures.append(f"ARM 4 control reported {len(got)} finding(s) over a "
                            f"clean synthetic history; expected 0")
        elif stats["counts"].get("commit") != 1 or stats["counts"].get("blob") != 1:
            failures.append(f"ARM 4 control saw {stats['counts']!r}; expected one "
                            f"blob and one commit, so the walk is not covering "
                            f"what it claims")
        else:
            controls += 1

        # The name appears ONLY in a commit message. Nothing in git ls-files can
        # see this, which is the whole reason ARM 4 reads commit objects raw.
        commit("also.md", "nothing of interest\n",
               "record the owner: drwx------ " + other + " " + other + "  /srv")
        got, stats = scan_history(td, ["HEAD"])
        hist_new = [g for g in got if "[HIST-NEW]" in g]
        if not hist_new:
            failures.append("planted an unregistered name in a COMMIT MESSAGE -> "
                            "GREEN; ARM 4 is blind to the one form HEAD cannot see")
        elif "1 message object(s)" not in hist_new[0]:
            failures.append(f"ARM 4 found the planted name but not in a message "
                            f"object; it is being attributed to a blob: {hist_new[0]}")
        # ...and with the name registered at zero, both history ceilings must red.
        REGISTERED_HISTORY_NAMES[sha(other)] = (0, 0, "self-test fixture")
        try:
            got, _ = scan_history(td, ["HEAD"])
            if not any("[HIST-MSGS]" in g for g in got):
                failures.append("a registered historical name over its message "
                                "ceiling -> GREEN; HIST-MSGS cannot fire")
            commit("paths.md", "chown -R " + other + ":" + other + " /srv\n",
                   "add a blob that discloses it too")
            got, _ = scan_history(td, ["HEAD"])
            if not any("[HIST-PATHS]" in g for g in got):
                failures.append("a registered historical name over its path "
                                "ceiling -> GREEN; HIST-PATHS cannot fire")
        finally:
            del REGISTERED_HISTORY_NAMES[sha(other)]

        # A denied identifier in history must red even though HEAD is clean of it.
        commit("gone.md", f"stem {denied}\n", "add it")
        subprocess.run(["git", "-C", td, "rm", "-q", "gone.md"], check=True)
        subprocess.run(["git", "-C", td, "commit", "-q", "-m", "remove it from HEAD"],
                       check=True)
        head_findings, _, _ = scan(td)
        got, _ = scan_history(td, ["HEAD"])
        if any("[DENY/" in g for g in head_findings):
            failures.append("the ARM 4 deny fixture is still visible at HEAD, so "
                            "it proves nothing about history")
        if not any("[HIST-DENY/" in g for g in got):
            failures.append("a denied identifier removed from HEAD but live in "
                            "history -> GREEN; HIST-DENY cannot fire, which is "
                            "the Q268 case itself")

        # A ref that does not resolve must refuse, not quietly scan less.
        if not _raises(lambda: scan_history(td, ["refs/heads/no-such-branch"])):
            failures.append("scan_history accepted an unresolvable ref; it would "
                            "report a clean over a smaller subject than asked for")
        else:
            controls += 1

    if failures:
        for f in failures:
            print(f"::error::check-personal-data self-test FAILED: {f}")
        return 1
    print(f"check-personal-data self-test PASS — {len(rules)} arm(s), "
          f"each proven able to red, plus {controls} green control(s)")
    return 0


def _raises(fn) -> bool:
    """True if fn() raised. Used to prove that an assertion can fail."""
    try:
        fn()
    except Exception:
        return True
    return False


def run_head(root: str) -> int:
    findings, homes, users = scan(root)
    findings += judge_homes(homes)
    findings += judge_identities(users)
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
          f"name(s) name a real user, every one at or under its accepted ceiling; "
          f"{sum(users.values())} bare account-name occurrence(s) across "
          f"{len(users)} registered name(s), every one at or under its accepted "
          f"ceiling. This is HEAD only — `--history` is the other half.")
    return 0


def run_history(root: str, refs: list[str]) -> int:
    try:
        findings, stats = scan_history(root, refs)
    except RuntimeError as exc:
        print(f"::error::check-personal-data [HISTORY] {exc}")
        print("check-personal-data --history: FAILED — the scan did not complete, "
              "so its silence is not a clean.")
        return 1
    counts = stats["counts"]
    refs_desc = ", ".join(r if o.startswith("(") else f"{r} -> {o[:12]}"
                          for r, o in stats["refs"])
    scope = (f"scope: {stats['objects']} object(s) reachable from {refs_desc} "
             f"({counts.get('blob', 0)} blob, {counts.get('commit', 0)} commit, "
             f"{counts.get('tree', 0)} tree, {counts.get('tag', 0)} tag); "
             f"{stats['scanned_bytes']} byte(s) of text scanned, "
             f"{stats['skipped_binary']} object(s) skipped as binary")
    superset = (f"this scan is a SUBSET BY DESIGN and covers exactly what pushing "
                f"the refs above publishes: {stats['ref_reachable_objects']} "
                f"object(s) are reachable from one of this repository's "
                f"{stats['local_refs']} local ref(s), and "
                f"{stats['on_disk_objects']} exist on disk — the difference is "
                f"unreachable and no push can send it, while objects reachable "
                f"only from OTHER local refs are a different subject, so "
                f"`git push --all --tags` is a different act with a different "
                f"answer")
    if not stats["default_scope"]:
        superset += (". NOTE: these are not the default refs, and every ceiling "
                     f"in this file is registered against {list(HISTORY_REFS)!r}, "
                     f"so a ceiling finding here is an audit result and not a "
                     f"statement about what a flip publishes")
    if findings:
        for f in findings:
            print(f)
        print(f"check-personal-data --history: FAILED with {len(findings)} "
              f"finding(s). {scope}; {superset}.")
        return 1
    named = stats["names"]
    print(f"check-personal-data --history: ok — {scope}. {len(DENY)} denied "
          f"identifier(s) absent from every one of them (matched by digest, never "
          f"held in this file); every email address is a noreply, an RFC 2606 "
          f"documentation domain, or 1 of {len(REGISTERED_EMAILS)} registered "
          f"third-party address(es); {sum(v[0] for v in named.values())} "
          f"identifier-shaped occurrence(s) across {len(named)} registered "
          f"name(s), every one at or under its accepted path and message-object "
          f"ceilings. {superset}.")
    return 0


def main(argv: list[str]) -> int:
    root = subprocess.run(["git", "rev-parse", "--show-toplevel"],
                          capture_output=True, text=True, check=True).stdout.strip()
    if len(argv) > 1 and argv[1] == "--self-test":
        if len(argv) > 2:
            print(__doc__)
            return 2
        return self_test(root)
    if len(argv) > 1 and argv[1] == "--history":
        refs = argv[2:] or list(HISTORY_REFS)
        return run_history(root, refs)
    if len(argv) > 1:
        print(__doc__)
        return 2
    return run_head(root)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
