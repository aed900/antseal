#!/usr/bin/env python3
"""Positioning-copy conformance over the product's user-facing copy (tasks Q20, U31).

MVP-SPEC.md line 28 is a *product* constraint with a *copy* enforcement:

    never call it a "notary" in legal copy — and never claim "priority"
    unqualified. A seal proves the holder of key X possessed this content by
    time T — not authorship, not exclusive possession … Docs must state both
    limits, plus a compelled-disclosure note

The rules, their spec citations and their surface classes live in
`docs/positioning-copy-style.md`. This file is the executable half; the guide
is normative and this scanner enforces the subset of it that a scanner can
decide. Every rule id below (`P1`…`P9`) is a section of that guide.

WHAT THIS SCANS, AND WHY IT IS NOT "docs/"
------------------------------------------
The guide's Class P — **product copy** — is what a *user* reads: the README,
the verifier page, and the CLI's rendered output. Almost everything under
`docs/` is Class E — **engineering copy** — written for contributors, and
sweeping it would produce findings that are not copy defects and an
exemption list large enough to stop meaning anything. The partition is not
left implicit: rule **P8** requires every `docs/*.md` and every `docs/*/`
subtree to be classified in `DOCS_CLASSIFICATION` below, so a new page that
is nobody's Class cannot land unnoticed. That is D123's lesson applied
forward — a scan blind to the very file a row authors is the failure mode.

CLI copy is scanned through its **rendered golden snapshots**, not through
`crates/antseal-cli/src/**.rs`. Two reasons, both measured (2026-08-15):
`src/` is code, where `ReceiptSinkFault::NotArmed` lowercases to `notarmed`
and a substring ban fires on an identifier; and the snapshots are what the
user actually sees. U31's single catalog module of user-facing strings does
not exist yet — when it lands it becomes a literal entry in `COPY_SCAN`.

Usage:
    scripts/check-copy-style.py              check
    scripts/check-copy-style.py --self-test  plant violations, require red
    scripts/check-copy-style.py --inventory  print every file the scan reads
Exit: 0 pass, 1 failure, 2 usage.
"""

from __future__ import annotations

import re
import shutil
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

GUIDE = "docs/positioning-copy-style.md"
"""The normative guide. Every rule id here is one of its sections."""

R18_TABLE = "crates/antseal-core/tests/verdict_wording.rs"
"""R18's frozen verdict-copy sweep — the source of the Class V ban list (P9)."""

# ---------------------------------------------------------------------------
# scan roots
# ---------------------------------------------------------------------------

# D123's per-entry rule, deliberately reproduced here rather than reinvented:
# a **literal file** entry is read as itself, UNFILTERED — naming it in a
# reviewed constant is the deliberation, and no second gate is owed — while a
# **directory** entry is walked recursively and filtered by COPY_SUFFIXES,
# which is the only job a suffix set has ever had. The guide is a literal
# entry for exactly the reason D123 names: a lint whose own authored document
# is outside its scan is the defect, not the exemption.
#
# A named entry that does not exist is a FAILURE, never a skip (the harness's
# missing-target rule): renaming a surface out from under this list must be
# loud.
COPY_SCAN: tuple[str, ...] = (
    # Class P — product copy.
    "README.md",
    # The disclosure policy (Q242). A LITERAL entry under D123's rule: read as
    # itself, unfiltered. It is product copy in the strictest sense — the one
    # page a stranger reads before deciding how to report a flaw in a verifier
    # that makes cryptographic claims — and its scope section restates what a
    # seal does and does not prove, which is exactly what P1-P3 police.
    "SECURITY.md",
    GUIDE,
    "verifier-web/",
    # Q30's release-signing set (D71). A DIRECTORY entry for the same reason
    # docs/user/ is one: the user-facing check-your-download page is product
    # copy in the strictest sense - a stranger holding only a download follows
    # it - and D71 §2 R11 constrains what the custody and maintainer documents
    # beside it may claim about a signature too, so the whole subtree is
    # scanned rather than one file of it.
    "docs/signing/",
    # The M4 user-facing documentation set (Q23-Q27; Q21's threat model is NOT
    # here - D139 §2 R3). A DIRECTORY entry under D123's rule: walked and
    # suffix-filtered, so every page that lands here is scanned from its first
    # commit with no second register edit. D139 §1.4/§1.5 prices that against
    # one entry per page: identical coverage under --self-test, 2 register
    # edits instead of 12, and no per-page ordering trap in a file six lanes
    # share. What it costs is recorded at D139 §4.2.
    "docs/user/",
    # The CLI's copy as the user reads it: the committed golden renderings.
    "crates/antseal-cli/tests/snapshots/",
    # R18's frozen verdict document (MVP-SPEC.md line 127's "one authoritative
    # wording set"). Scanned so this guide is provably compatible with the
    # wording set it must not break — Q20's Accept row 1.
    "crates/antseal-core/tests/snapshots/",
)

COPY_SUFFIXES = frozenset({".md", ".html", ".htm", ".txt", ".js", ".css"})
"""Directory-walk filter only (D123 R1). Never applied to a literal entry."""


# Rule P8. Every `docs/*.md` at depth 1 and every `docs/*/` subtree carries a
# class and a reason. `PRODUCT` means "scanned by COPY_SCAN above"; `ENG`
# means Class E, engineering copy, out of scope with the reason recorded.
# A path in neither is a FAILURE — that is the whole point of the register.
DOCS_CLASSIFICATION: dict[str, tuple[str, str]] = {
    # --- depth-1 pages ---
    "positioning-copy-style.md": ("PRODUCT", "this guide; scanned as a literal COPY_SCAN entry"),
    "ci-verification.md": ("ENG", "CI runbook for contributors; no product claim"),
    "config.md": ("ENG", "config-file reference; describes keys, makes no claim about a seal"),
    "dependency-policy.md": ("ENG", "supply-chain policy for contributors"),
    "instrument-ledger.md": ("ENG", "register of this repo's own instruments"),
    "security-assumptions.md": (
        "ENG",
        "FROZEN engineering text, byte-identical-asserted by "
        "crates/antseal-core/tests/security_assumptions_drift.rs — a finding inside it is "
        "unfixable without breaking that drift test",
    ),
    "threat-model.md": (
        "ENG",
        "stays Class E after Q21 finalized it 2026-08-17, and the reason is MEASURED (D139 §1.2, "
        "§2 R3): the text between the `<!-- BEGIN frozen-security-assumptions -->` and `<!-- END "
        "frozen-security-assumptions -->` markers is the byte-frozen copy of "
        "security-assumptions.md, asserted by "
        "crates/antseal-core/tests/security_assumptions_drift.rs, and one line inside that block "
        "reads '**What breaks if it is false.** Authorship binding.' - a live P3 with no "
        "disclaimer in its sentence. Promoting this file to PRODUCT therefore reds the lint on "
        "text Q21's own Accept clause ('assumptions block still verbatim') forbids it to touch; "
        "measured, the flip is still RED after every repair Q21 was permitted to make. The block "
        "is pinned by EQUALITY between the two copies, not by a digest - so the blocker is the M0 "
        "sign-off record and Q21's Accept, not the drift test. Q21 fixed the two defects OUTSIDE "
        "the block (the P2 in the Positioning section and the P4 where §2.3 quoted the receipt "
        "class across a line break), leaving exactly the one frozen P3. The user-facing pages "
        "live in docs/user/. LOCATOR NOTE, recorded because it happened inside one wave: D139 §2 "
        "R4 specified this reason with the line numbers 39-408 and :23, and Q21's own mandated "
        "growth moved the block to 51-420 and the sign-off to :30 before the ink dried. The "
        "markers are the stable locator and are what the drift test actually reads",
    ),
    "toolchain.md": ("ENG", "toolchain pinning for contributors"),
    "vault-keyfile.md": ("ENG", "keyfile mechanism reference; Q24 writes the user-facing pages"),
    "wasm-toolchain.md": ("ENG", "WASM build reference for contributors"),
    "zeroization-audit.md": ("ENG", "audit record"),
    # --- subtrees ---
    "anchors/": ("ENG", "operator runbooks"),
    "decisions/": ("ENG", "decision records; a record's job includes proposing work (D109 §3.3)"),
    "devnet/": ("ENG", "developer network setup"),
    "format/": ("ENG", "the wire registry and its freeze"),
    "naming/": ("ENG", "registration/outreach runbooks"),
    "research/": ("ENG", "design-round records"),
    "reviews/": ("ENG", "code-review records"),
    "signing/": (
        "PRODUCT",
        "Q30's release-signing set (D71), scanned as the COPY_SCAN directory entry "
        "docs/signing/. PRODUCT on the merits of its user-facing half: "
        "verifying-a-release.md is followed by a stranger holding only a download, "
        "and D71 §2 R11 forbids the release documentation claiming a legal property, "
        "a withdrawal mechanism that does not exist, or independent verifiability for "
        "a key served from the same origin as the binary - which is P1/P3's rule "
        "reached from a different record. The operational half (key-custody.md, "
        "maintainer-key-procedure.md) is scanned too and costs nothing: measured "
        "2026-08-18, admitting the subtree moved the corpus 20 -> 24 files and "
        "produced ZERO new findings",
    ),
    "testing/": ("ENG", "test-harness contracts"),
    "upstream/": ("ENG", "upstream-tracking records"),
    "user/": (
        "PRODUCT",
        "the M4 user-facing documentation set (Q23-Q27), scanned as the COPY_SCAN "
        "directory entry docs/user/ - D139 §2 R1. CLOSED VENUE: every file here is "
        "Class P by construction. An engineering document does not go in this "
        "directory; nothing mechanical enforces that (D139 §4.2)",
    ),
    "waves/": ("ENG", "wave briefs"),
}


# Rule P7 debts. A required clause that the tree does not yet carry, with the
# task that owes it. Each entry is asserted STILL OWED: satisfy the clause
# without deleting its entry and this check goes RED demanding the deletion —
# the same discipline check-ci-shell.py applies to ALLOWED_INLINE and
# verdict_wording.rs applies to RESIDUE. A debt that cannot go stale is an
# exemption, and exemptions rot.
OWED_PRESENCE: dict[tuple[str, str], str] = {
    ("README.md", "limit-exclusive-possession"): (
        "Q22 (M4) — 'Write README, install guide, and product-limits/disclosure docs', whose Do "
        "names 'possession-not-authorship' and whose Accept reads 'Q20 lint green'. README today "
        "states the authorship limit and not the exclusive-possession one; MVP-SPEC.md line 28 "
        "requires both"
    ),
    ("README.md", "compelled-disclosure"): (
        "Q22 (M4) — same row; its Do names the compelled-disclosure note explicitly. Today the "
        "note exists only in docs/threat-model.md §2.5, which is Class E"
    ),
}


# ---------------------------------------------------------------------------
# the patterns
# ---------------------------------------------------------------------------

# P1. The word and its family, with WORD BOUNDARIES rather than the substring
# `notar`. Measured 2026-08-15: `ReceiptSinkFault::NotArmed` lowercases to
# `notarmed`, so a substring ban fires on an identifier in
# crates/antseal-cli/src/pipeline/receipt_sink.rs. The green control arm in
# self_test() pins that.
NOTARY = re.compile(
    r"\bnotar(y|ies|ial|ially|is(e|es|ed|ing|ation)|iz(e|es|ed|ing|ation))\b", re.I
)

# P2. Line 28 bans the *unqualified* claim, so the noun alone is not the
# violation. `prioritise/prioritize` are deliberately absent: they order work,
# they never claim anything about a seal.
PRIORITY = re.compile(r"\bpriorit(y|ies)\b", re.I)

# The qualification line 28 itself supplies: "an earlier seal by someone who
# received your work outranks yours ('seal before you share')".
PRIORITY_QUALIFIER = re.compile(r"seal before you share|outrank", re.I)

# P3. The two claims a seal never supports.
AUTHORSHIP = re.compile(
    r"\bauthorship\b|\bexclusive\s+possession\b|\bexclusively\s+possess\w*|\bsole\s+possession\b",
    re.I,
)

# A disclaimer in the same sentence is what makes a banned word lawful in
# documentation: line 28 does not merely permit "it is not a legal notary", it
# REQUIRES the limits to be stated, and they cannot be stated without naming
# them. `rejected|banned|forbidden` cover a guide's own rejected specimens.
DISCLAIMER = re.compile(
    r"\b(not|never|no|none|nothing|neither|nor|isn't|cannot|can't|without|rejected|banned"
    r"|forbidden|refused|refuses)\b",
    re.I,
)

# P4/P5. Spec-dictated spellings, em dash included (MVP-SPEC.md lines 110/137).
RECEIPT_CLASS = "supporting evidence — no independently proven time"
RECEIPT_ANCHOR = "no independently proven time"
CLAIMED_TIME_LABEL = "asserted by sealer — NOT verified"
CLAIMED_TIME_ANCHOR = "asserted by sealer"

# P6. D62 §3 R8's canonical value, and the pattern that finds every other
# spelling rather than merely failing to match it.
CANONICAL_URL = "https://antseal.org/"
PRODUCT_URL = re.compile(r"https?://[A-Za-z0-9.-]*antseal\.[a-z]+[^\s)\"'<>\],`*]*")

# P7. The clauses MVP-SPEC.md line 28 requires of a positioning surface.
PRESENCE_SURFACES = ("README.md",)
PRESENCE_CLAUSES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("possession-language", re.compile(r"\bpossess(ion|ed|es)\b", re.I)),
    ("limit-authorship", re.compile(r"\bno(t| )\s*\**\s*(claim of\s+)?authorship\b", re.I)),
    (
        "limit-exclusive-possession",
        re.compile(r"\bnot?\s+\**\s*exclusive(ly)?\s*\**\s*(possession|possess\w*)\b", re.I),
    ),
    ("seal-before-you-share", re.compile(r"seal before you share", re.I)),
    ("compelled-disclosure", re.compile(r"compelled|forced to reveal|coerc(e|ed|ion)", re.I)),
)


class Finding:
    """One violation: rule id, where, and what to do about it."""

    def __init__(self, rule: str, where: str, message: str) -> None:
        self.rule = rule
        self.where = where
        self.message = message

    def __str__(self) -> str:
        return f"[{self.rule}] {self.where}: {self.message}"


# ---------------------------------------------------------------------------
# reading the corpus
# ---------------------------------------------------------------------------


def scan_files(root: Path) -> tuple[list[tuple[str, str]], list[Finding]]:
    """Every (relative path, text) the copy rules apply to, per the D123 rule."""
    out: list[tuple[str, str]] = []
    failures: list[Finding] = []
    seen: set[Path] = set()
    for entry in COPY_SCAN:
        base = root / entry
        literal = not entry.endswith("/")
        if literal and not base.is_file():
            failures.append(
                Finding(
                    "P0",
                    entry,
                    "named in COPY_SCAN but is not a file — a renamed or deleted copy surface "
                    "must be loud, never a silent skip",
                )
            )
            continue
        if not literal and not base.is_dir():
            failures.append(
                Finding("P0", entry, "named in COPY_SCAN but is not a directory")
            )
            continue
        candidates = [base] if literal else sorted(base.rglob("*"))
        found = 0
        for path in candidates:
            if not path.is_file():
                continue
            if not literal and path.suffix not in COPY_SUFFIXES:
                continue
            if path in seen:
                continue
            seen.add(path)
            try:
                text = path.read_text(encoding="utf-8")
            except (UnicodeDecodeError, OSError):
                continue
            out.append((path.relative_to(root).as_posix(), text))
            found += 1
        if not literal and found == 0:
            failures.append(
                Finding(
                    "P0",
                    entry,
                    f"is a scan root that reads NOTHING — no file under it has a suffix in "
                    f"{sorted(COPY_SUFFIXES)}. A root that reads nothing is D123's defect",
                )
            )
    return out, failures


def blocks(text: str) -> list[tuple[int, str]]:
    """(start offset, block) for every blank-line-delimited block."""
    out: list[tuple[int, str]] = []
    offset = 0
    for chunk in re.split(r"\n[ \t]*\n", text):
        out.append((offset, chunk))
        offset += len(chunk) + 2
    return out


def enclosing(spans: list[tuple[int, str]], index: int) -> str:
    """The block or sentence containing `index`, or the empty string."""
    for start, body in spans:
        if start <= index < start + len(body):
            return body
    return ""


def sentences(block_text: str, block_start: int) -> list[tuple[int, str]]:
    """Sentence-ish spans: `.`/`!`/`?` boundaries, plus markdown structure.

    A markdown table row and a list item are each their own claim, so a
    newline that begins one ends the previous sentence. This is an
    approximation and the guide says so (§10): a disclaimer one sentence away
    from its claim is not seen.
    """
    out: list[tuple[int, str]] = []
    cursor = 0
    for piece in re.split(r"(?<=[.!?])[ \t\n]+|\n(?=[ \t]*(?:[|\-*>#]|\d+\.))", block_text):
        idx = block_text.find(piece, cursor)
        if idx < 0:
            idx = cursor
        out.append((block_start + idx, piece))
        cursor = idx + len(piece)
    return out


def line_of(text: str, index: int) -> int:
    return text.count("\n", 0, index) + 1


# ---------------------------------------------------------------------------
# the rules
# ---------------------------------------------------------------------------


def check_banned(rel: str, text: str) -> list[Finding]:
    """P1, P2, P3 — the three bans MVP-SPEC.md line 28 states."""
    found: list[Finding] = []
    block_spans = blocks(text)
    sentence_spans: list[tuple[int, str]] = []
    for start, body in block_spans:
        sentence_spans.extend(sentences(body, start))

    for match in NOTARY.finditer(text):
        sentence = enclosing(sentence_spans, match.start())
        if not DISCLAIMER.search(sentence):
            found.append(
                Finding(
                    "P1",
                    f"{rel}:{line_of(text, match.start())}",
                    f"'{match.group(0)}' with no disclaimer in its sentence — MVP-SPEC.md line "
                    f"28: never call it a 'notary' in legal copy. Product copy may name the word "
                    f"only to deny it ('it is not a legal notary'). Sentence: "
                    f"{sentence.strip()[:120]!r}",
                )
            )

    for match in PRIORITY.finditer(text):
        block = enclosing(block_spans, match.start())
        if not PRIORITY_QUALIFIER.search(block):
            found.append(
                Finding(
                    "P2",
                    f"{rel}:{line_of(text, match.start())}",
                    f"'{match.group(0)}' with no qualification in its block — MVP-SPEC.md line "
                    f"28: never claim 'priority' unqualified. The qualification the spec supplies "
                    f"is that an earlier seal by someone who received your work outranks yours "
                    f"('seal before you share'); say it in the same block",
                )
            )

    for match in AUTHORSHIP.finditer(text):
        sentence = enclosing(sentence_spans, match.start())
        if not DISCLAIMER.search(sentence):
            found.append(
                Finding(
                    "P3",
                    f"{rel}:{line_of(text, match.start())}",
                    f"'{match.group(0)}' with no disclaimer in its sentence — MVP-SPEC.md line "
                    f"28: a seal proves possession, 'not authorship, not exclusive possession'. "
                    f"Sentence: {sentence.strip()[:120]!r}",
                )
            )
    return found


def check_spellings(rel: str, text: str) -> list[Finding]:
    """P4, P5 — the two spec-dictated spellings, exactly as the spec spells them."""
    found: list[Finding] = []
    for anchor, canonical, rule, cite in (
        (RECEIPT_ANCHOR, RECEIPT_CLASS, "P4", "MVP-SPEC.md lines 110 and 137"),
        (CLAIMED_TIME_ANCHOR, CLAIMED_TIME_LABEL, "P5", "MVP-SPEC.md line 137"),
    ):
        start = 0
        while True:
            index = text.find(anchor, start)
            if index < 0:
                break
            start = index + len(anchor)
            window = text[max(0, index - len(canonical)) : index + len(canonical)]
            if canonical not in window:
                found.append(
                    Finding(
                        rule,
                        f"{rel}:{line_of(text, index)}",
                        f"'{anchor}' is not spelled as {cite} dictates. The one lawful spelling "
                        f"is {canonical!r} — em dash included; it is R18's frozen row, not a "
                        f"phrase to paraphrase",
                    )
                )
    return found


def check_url(rel: str, text: str) -> list[Finding]:
    """P6 — one canonical verifier URL (MVP-SPEC.md line 139, D62 §3 R8)."""
    found: list[Finding] = []
    for match in PRODUCT_URL.finditer(text):
        if match.group(0) != CANONICAL_URL:
            found.append(
                Finding(
                    "P6",
                    f"{rel}:{line_of(text, match.start())}",
                    f"{match.group(0)!r} is not the canonical verifier URL. MVP-SPEC.md line 139 "
                    f"requires 'one canonical URL used in all docs and printed by the CLI'; D62 "
                    f"§3 R8 fixes it at {CANONICAL_URL!r} and puts the single Rust definition in "
                    f"crates/antseal-cli/src/brand.rs (VERIFIER_URL)",
                )
            )
    return found


def check_presence(root: Path) -> tuple[list[Finding], list[str]]:
    """P7 — the clauses line 28 requires of a positioning surface, and their debts."""
    found: list[Finding] = []
    notices: list[str] = []
    satisfied: set[tuple[str, str]] = set()
    for rel in PRESENCE_SURFACES:
        path = root / rel
        if not path.is_file():
            found.append(Finding("P7", rel, "positioning surface is missing"))
            continue
        text = path.read_text(encoding="utf-8")
        for clause, pattern in PRESENCE_CLAUSES:
            if pattern.search(text):
                satisfied.add((rel, clause))
                continue
            owner = OWED_PRESENCE.get((rel, clause))
            if owner is None:
                found.append(
                    Finding(
                        "P7",
                        rel,
                        f"does not state the required '{clause}' clause — MVP-SPEC.md line 28 "
                        f"('Docs must state both limits, plus a compelled-disclosure note'). "
                        f"Write it, or register the debt in OWED_PRESENCE with the owning task",
                    )
                )
            else:
                notices.append(f"{rel}: '{clause}' NOT YET STATED — owed by {owner}")

    for (rel, clause), owner in sorted(OWED_PRESENCE.items()):
        if (rel, clause) in satisfied:
            found.append(
                Finding(
                    "P7",
                    rel,
                    f"OWED_PRESENCE still carries '{clause}' but the clause is now STATED. "
                    f"Delete the entry (owed by {owner}) — a debt that outlives its subject is an "
                    f"exemption, and exemptions rot",
                )
            )
    return found, notices


def check_docs_partition(root: Path) -> list[Finding]:
    """P8 — every docs page and subtree has a class and a reason (the D123 guard)."""
    found: list[Finding] = []
    docs = root / "docs"
    if not docs.is_dir():
        return [Finding("P8", "docs/", "does not exist — the partition cannot be checked")]
    seen: set[str] = set()
    for child in sorted(docs.iterdir()):
        if child.is_dir():
            key = child.name + "/"
        elif child.suffix == ".md":
            key = child.name
        else:
            continue
        seen.add(key)
        entry = DOCS_CLASSIFICATION.get(key)
        if entry is None:
            found.append(
                Finding(
                    "P8",
                    f"docs/{key}",
                    "is classified by nothing. Every docs page and subtree is Class P (product "
                    "copy — add it to COPY_SCAN) or Class E (engineering copy — record the "
                    "reason); an unclassified page is a copy surface no lint reads, which is "
                    "D123's defect. See docs/positioning-copy-style.md §2",
                )
            )
            continue
        cls, _reason = entry
        if cls == "PRODUCT" and f"docs/{key}" not in COPY_SCAN:
            found.append(
                Finding(
                    "P8",
                    f"docs/{key}",
                    "is classified PRODUCT but is not a COPY_SCAN entry — it would be scanned by "
                    "nothing",
                )
            )
    for key in sorted(set(DOCS_CLASSIFICATION) - seen):
        found.append(
            Finding(
                "P8",
                f"docs/{key}",
                "is classified in DOCS_CLASSIFICATION but does not exist. Delete the entry — a "
                "register of files that are not there stops being read",
            )
        )
    return found


def r18_banned_tokens(root: Path) -> tuple[list[str], list[Finding]]:
    """The Class V ban list, read out of R18's own table rather than restated."""
    path = root / R18_TABLE
    if not path.is_file():
        return [], [
            Finding("P9", R18_TABLE, "is missing — the Class V ban list cannot be read")
        ]
    text = path.read_text(encoding="utf-8")
    start = text.find("const BANNED_TOKENS")
    if start < 0:
        return [], [
            Finding(
                "P9",
                R18_TABLE,
                "carries no `const BANNED_TOKENS` — the extractor is broken, or R18's table "
                "moved. Fix the extractor; do not delete the rule",
            )
        ]
    end = text.find("];", start)
    body = text[start:end]
    tokens = re.findall(r"\(\s*\"([^\"]+)\"", body)
    if len(tokens) < 10:
        return tokens, [
            Finding(
                "P9",
                R18_TABLE,
                f"extracted only {len(tokens)} banned token(s) from BANNED_TOKENS — the "
                f"extractor is broken, not the table clean. A check that reads nothing must "
                f"never report green",
            )
        ]
    return tokens, []


def check_r18_coverage(root: Path) -> list[Finding]:
    """P9 — the guide names every token R18's frozen sweep bans."""
    tokens, found = r18_banned_tokens(root)
    if found:
        return found
    guide = root / GUIDE
    if not guide.is_file():
        return [Finding("P9", GUIDE, "is missing — the guide is the normative half of this check")]
    lowered = guide.read_text(encoding="utf-8").lower()
    for token in tokens:
        if token.lower() not in lowered:
            found.append(
                Finding(
                    "P9",
                    GUIDE,
                    f"does not name {token!r}, which R18's frozen sweep bans from verdict copy "
                    f"({R18_TABLE}, BANNED_TOKENS). One vocabulary, one place it is written "
                    f"down — two lists held in step by a comment is the defect D116 collapsed "
                    f"five constants to prevent",
                )
            )
    return found


# ---------------------------------------------------------------------------
# the check
# ---------------------------------------------------------------------------


def check(root: Path) -> tuple[list[Finding], list[str], int]:
    """Returns (findings, notices, files scanned)."""
    files, findings = scan_files(root)
    for rel, text in files:
        findings.extend(check_banned(rel, text))
        findings.extend(check_spellings(rel, text))
        findings.extend(check_url(rel, text))
    presence, notices = check_presence(root)
    findings.extend(presence)
    findings.extend(check_docs_partition(root))
    findings.extend(check_r18_coverage(root))
    return findings, notices, len(files)


# ---------------------------------------------------------------------------
# the self-test
# ---------------------------------------------------------------------------

# Every file the staged tree needs: the scan roots, the docs partition's
# subjects, and R18's table. Copied file-by-file rather than by copying the
# repository — `fuzz/corpus` alone is ~922 files (D123 §3.3) and a self-test
# that copies it is a self-test nobody runs.
def stage(root: Path, dest: Path) -> None:
    for entry in COPY_SCAN:
        src = root / entry
        if src.is_file():
            (dest / entry).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dest / entry)
        elif src.is_dir():
            shutil.copytree(src, dest / entry, dirs_exist_ok=True)
    (dest / R18_TABLE).parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(root / R18_TABLE, dest / R18_TABLE)
    docs = dest / "docs"
    docs.mkdir(parents=True, exist_ok=True)
    for key in DOCS_CLASSIFICATION:
        target = docs / key
        if key.endswith("/"):
            target.mkdir(parents=True, exist_ok=True)
        elif not target.exists():
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text("# staged placeholder\n", encoding="utf-8")


def edit(path: Path, old: str, new: str) -> None:
    text = path.read_text(encoding="utf-8")
    if old not in text:
        raise AssertionError(f"self-test fixture is stale: {old!r} not in {path}")
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


def self_test() -> int:
    """Plant each violation this check exists to catch and require red BY RULE.

    Judged on the findings list `check()` RETURNS, in-process, so a crash
    propagates and fails the harness rather than satisfying an arm the way a
    bare non-zero exit status would (Q149). And each arm asserts WHICH rule
    fired, not merely THAT something did — check-ci-shell.py records the
    weaker form as its own known weakness.

    The GREEN arms matter as much: a rule that fires on lawful copy is worse
    than no rule, so `NotArmed`, the X.509 noun "certificate", and a properly
    disclaimed notary sentence each get an arm proving the check stays quiet.
    """
    ok = True
    with tempfile.TemporaryDirectory(prefix="copy-style-selftest-") as tmp:
        base = Path(tmp)
        stage(REPO, base)

        control, _notices, scanned = check(base)
        print(f"  control (staged, unmodified, {scanned} files)".ljust(78) + "-> ", end="")
        if control:
            print("RED")
            print("    ::error:: the control run is red; the staged tree must be clean first")
            for finding in control:
                print(f"      {finding}")
            ok = False
        else:
            print("GREEN")

        guide = base / GUIDE
        readme = base / "README.md"
        verdicts = base / "crates/antseal-core/tests/snapshots/verdict-wording.txt"

        def truncate_r18() -> None:
            """Cut R18's table below the non-vacuity floor.

            The branch under test is the one that matters most in this
            repository: a check whose input went empty must report RED, never
            the green line it would print over a corpus it never read.
            """
            for token in ("notary", "notaris", "notariz", "notarial", "copyright", "patent"):
                edit(base / R18_TABLE, f'("{token}"', "// removed by the self-test")

        # (rule, label, mutation, expect) — `expect` "red" names the rule that
        # must fire; "green" arms require silence.
        faults = [
            (
                "P1",
                "Q20's own Accept: 'legal notary' in a docs file",
                lambda: guide.write_text(
                    guide.read_text(encoding="utf-8")
                    + "\n\nantseal is a legal notary for your documents.\n",
                    encoding="utf-8",
                ),
                "red",
            ),
            (
                "P2",
                "an unqualified priority claim",
                lambda: guide.write_text(
                    guide.read_text(encoding="utf-8")
                    + "\n\nantseal establishes priority over later claimants.\n",
                    encoding="utf-8",
                ),
                "red",
            ),
            (
                "P3",
                "an authorship claim",
                lambda: guide.write_text(
                    guide.read_text(encoding="utf-8")
                    + "\n\nA seal proves authorship of the sealed bytes.\n",
                    encoding="utf-8",
                ),
                "red",
            ),
            (
                "P4",
                "the receipt class respelled with a hyphen",
                lambda: edit(verdicts, RECEIPT_CLASS, "supporting evidence - no independently proven time"),
                "red",
            ),
            (
                "P5",
                "the claimed-time label paraphrased",
                lambda: edit(verdicts, CLAIMED_TIME_LABEL, "asserted by sealer (not verified)"),
                "red",
            ),
            (
                "P6",
                "a www. spelling of the verifier URL",
                lambda: readme.write_text(
                    readme.read_text(encoding="utf-8")
                    + "\n\nVerify at https://www.antseal.org/ instead.\n",
                    encoding="utf-8",
                ),
                "red",
            ),
            (
                "P7",
                "the seal-before-you-share line deleted from README",
                lambda: edit(readme, "Seal before you share.", "Sealing is optional."),
                "red",
            ),
            (
                "P7",
                "a debt satisfied but not deleted from OWED_PRESENCE",
                lambda: readme.write_text(
                    readme.read_text(encoding="utf-8")
                    + "\n\nA seal proves possession, not exclusive possession, and the vault "
                    "holder can always be compelled to reveal.\n",
                    encoding="utf-8",
                ),
                "red",
            ),
            (
                "P8",
                "a new docs page nothing classifies",
                lambda: (base / "docs/brand-new-product-page.md").write_text(
                    "# new page\n", encoding="utf-8"
                ),
                "red",
            ),
            (
                "P9",
                "the guide stops naming a token R18 bans",
                lambda: edit(guide, "affidavit", "afidavit"),
                "red",
            ),
            (
                "P0",
                "a scan root renamed away",
                lambda: (base / "README.md").rename(base / "README.renamed.md"),
                "red",
            ),
            (
                "P0",
                "a directory root left reading NOTHING",
                lambda: [
                    p.unlink()
                    for p in (base / "crates/antseal-cli/tests/snapshots").glob("*.txt")
                ],
                "red",
            ),
            (
                "P8",
                "a docs page classified PRODUCT but in no COPY_SCAN entry",
                lambda: DOCS_CLASSIFICATION.__setitem__(
                    "ci-verification.md", ("PRODUCT", "planted by the self-test")
                ),
                "red",
            ),
            (
                "P9",
                "R18's ban list truncated — the extractor must not read green",
                truncate_r18,
                "red",
            ),
            (
                "P1",
                "GREEN ARM — the identifier ReceiptSinkFault::NotArmed",
                lambda: guide.write_text(
                    guide.read_text(encoding="utf-8")
                    + "\n\nThe sink reports ReceiptSinkFault::NotArmed when it is NotArmed.\n",
                    encoding="utf-8",
                ),
                "green",
            ),
            (
                "P1",
                "GREEN ARM — a disclaimed notary sentence",
                lambda: guide.write_text(
                    guide.read_text(encoding="utf-8")
                    + "\n\nantseal is not a legal notary and never notarises anything.\n",
                    encoding="utf-8",
                ),
                "green",
            ),
            (
                "P3",
                "GREEN ARM — the X.509 noun 'certificate'",
                lambda: guide.write_text(
                    guide.read_text(encoding="utf-8")
                    + "\n\nThe certificate had expired by the time of the check.\n",
                    encoding="utf-8",
                ),
                "green",
            ),
            (
                "P2",
                "GREEN ARM — priority qualified in its block",
                lambda: guide.write_text(
                    guide.read_text(encoding="utf-8")
                    + "\n\nantseal proves priority only relatively: an earlier seal by someone "
                    "who received your work outranks yours. Seal before you share.\n",
                    encoding="utf-8",
                ),
                "green",
            ),
        ]

        for rule, label, mutate, expect in faults:
            snapshot = {
                path: path.read_bytes()
                for path in base.rglob("*")
                if path.is_file()
            }
            # One arm mutates a module-level register rather than a file, so
            # the restore has to cover both or the arms after it run against a
            # tree nobody put back.
            register = dict(DOCS_CLASSIFICATION)
            mutate()
            findings, _notices, _scanned = check(base)
            fired = sorted({f.rule for f in findings})
            if expect == "red":
                hit = rule in fired
                print(f"  {rule} {label:62.62s} -> {'RED' if hit else 'GREEN'}")
                if not hit:
                    print(
                        f"    ::error:: planted {rule} violation did not fire {rule}; "
                        f"rules that fired: {fired or 'none'}"
                    )
                    ok = False
                else:
                    message = next(f for f in findings if f.rule == rule)
                    print(f"      {message}")
            else:
                quiet = rule not in fired
                print(f"  {rule} {label:62.62s} -> {'QUIET' if quiet else 'FIRED'}")
                if not quiet:
                    print(
                        f"    ::error:: {rule} fired on lawful copy — a rule that reddens on "
                        f"legitimate text is worse than no rule"
                    )
                    for finding in findings:
                        if finding.rule == rule:
                            print(f"      {finding}")
                    ok = False
            # restore
            for path in list(base.rglob("*")):
                if path.is_file() and path not in snapshot:
                    path.unlink()
            for path, blob in snapshot.items():
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(blob)
            DOCS_CLASSIFICATION.clear()
            DOCS_CLASSIFICATION.update(register)

        # D123 R6's discipline, applied to every entry rather than to the one
        # that motivated the rule: a scan root is only proven to be read by a
        # fault planted INSIDE it going red. Without this, a suffix filter
        # silently applied to a literal entry — or a directory root whose
        # walk stopped matching — leaves the check green over an unread file
        # and nothing downstream can say so.
        staged_files, _ = scan_files(base)
        if len(staged_files) < 10:
            print(
                f"    ::error:: only {len(staged_files)} file(s) staged — the harness is broken, "
                f"not the corpus small"
            )
            ok = False
        print(f"  --- every one of the {len(staged_files)} scanned files is demonstrably READ ---")
        for rel, _text in staged_files:
            path = base / rel
            original = path.read_bytes()
            path.write_bytes(original + "\n\nantseal is a legal notary.\n".encode("utf-8"))
            findings, _notices, _scanned = check(base)
            read = any(f.rule == "P1" and f.where.startswith(rel + ":") for f in findings)
            print(f"    {rel:64.64s} -> {'READ' if read else 'UNREAD'}")
            if not read:
                print(
                    f"    ::error:: a planted violation in {rel} was NOT reported — the scan "
                    f"names this file and does not read it"
                )
                ok = False
            path.write_bytes(original)

        after, _notices, _scanned = check(base)
        print("  control (staged tree restored)".ljust(78) + "-> ", end="")
        if after:
            print("RED")
            print("    ::error:: the restore left the staged tree dirty; arms above are suspect")
            for finding in after:
                print(f"      {finding}")
            ok = False
        else:
            print("GREEN")
    return 0 if ok else 1


# ---------------------------------------------------------------------------


def inventory() -> int:
    files, failures = scan_files(REPO)
    for rel, text in files:
        print(f"  {rel}  ({len(text)} bytes)")
    print(f"check-copy-style inventory: {len(files)} file(s) across {len(COPY_SCAN)} scan root(s)")
    for failure in failures:
        print(f"::error::check-copy-style: {failure}")
    return 1 if failures else 0


def main(argv: list[str]) -> int:
    flags = [a for a in argv if a.startswith("-")]
    unknown = [f for f in flags if f not in ("--self-test", "--inventory")]
    if unknown or len(argv) != len(flags):
        print(f"usage: {Path(__file__).name} [--self-test | --inventory]", file=sys.stderr)
        return 2
    if "--self-test" in flags:
        rc = self_test()
        print("check-copy-style self-test PASS" if rc == 0 else "check-copy-style self-test FAIL")
        return rc
    if "--inventory" in flags:
        return inventory()

    findings, notices, scanned = check(REPO)
    for finding in findings:
        print(f"::error::check-copy-style {finding}")
    for notice in notices:
        print(f"check-copy-style: registered debt — {notice}")
    if findings:
        return 1
    print(
        f"check-copy-style: ok — {scanned} product-copy file(s) across {len(COPY_SCAN)} scan "
        f"root(s) satisfy MVP-SPEC.md line 28's positioning rules (P1-P3), the spec's dictated "
        f"spellings (P4/P5), the one canonical verifier URL (P6), the required positioning "
        f"clauses (P7, {len(OWED_PRESENCE)} registered debt(s) above), the docs partition "
        f"(P8, {len(DOCS_CLASSIFICATION)} entries) and R18's Class V vocabulary (P9). "
        f"Guide: {GUIDE}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
