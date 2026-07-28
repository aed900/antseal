#!/usr/bin/env python3
"""Q38 — the independent reader for the verification-report byte format.

The report byte format is decision **D29**
(``docs/decisions/D29-report-byte-format.md``): a v1 format that freezes at
the Q14 ``format-v1-freeze`` gate, with every pinned string committed under
``testdata/vectors/v*/report/`` by R9. Until this file existed, **no
implementation outside ``antseal-core`` checked any of it** — the bytes were
produced by ``serde_json`` and compared against themselves.

Why a *syntactic* checker and not a second emitter
--------------------------------------------------
Reproducing a report means reproducing the whole evidence pipeline: bundle
decode, commitment opening, cover reconstruction, signature verification. A
second pipeline would be a second product, not a cross-check, and its
disagreements would be its own bugs far more often than ours. D31 §1 is
explicit that a vehicle which closes no failure mode is worse than none,
because it reads as coverage.

But D29's contract is not the *content* of a report — it is a set of
**syntactic properties of the bytes**, and those are cheap to check with an
independent JSON reader that shares no code with the encoder. That is what
this is: CPython's ``json``, the committed strings, and D29 read from the
decision record.

Tier: **T1 with no T0 anchor.**
------------------------------
D31 §1's tiers: T0 is an external oracle, T1 an independent
re-implementation, T2 two implementations inside one ecosystem. This checker
is T1 — a reader written from the specification, sharing no code with the
Rust — and **there is no T0 anchor available, because the contract is ours**.
No standards body publishes expected antseal report bytes and none ever will.
That is the honest ceiling for this surface, not a shortfall to be closed
later, and ``docs/testing/cross-check.md`` records it as such.

A consequence worth stating plainly: a misreading of D29 shared between the
Rust encoder and this reader would survive this check. What it *does* catch
is the entire class of "the bytes drifted from the contract" — a float
appearing, a key reordering, uppercase hex, a version field that moved — and
after Q14 every one of those is a format incident.

The properties, each traceable to a D29 rule
--------------------------------------------
=====  ==========================================================  =========
 id    property                                                     D29
=====  ==========================================================  =========
 P1    every pinned string is UTF-8 and parses as a JSON object     rule 5
 P2    no object anywhere has a duplicate key                       rule 1
 P3    compact re-serialisation in the received key order           rules 1,5
       reproduces the exact bytes
 P4    no value anywhere is a float (and no NaN/Infinity)           rule 3
 P5    every hex-shaped string is lowercase and even-length         rule 6
 P6    every key is snake_case                                      rule 7
 P7    ``report_version`` is the first key and equals the pinned    rule 8
       constant
 P8    objects sharing a key set share its order                    rule 1
 P9    enum-valued fields are kebab-case                            rule 7
=====  ==========================================================  =========

P3 is the load-bearing one and subsumes several rules at once: compact
separators, integer formatting, and string escaping all have to be right or
the bytes do not come back. The others exist because P3 alone would accept a
*self-consistently wrong* document — one that round-trips perfectly while
carrying uppercase hex or a moved key.

One limit, stated rather than glossed
-------------------------------------
**P3 cannot detect a key reordering, and neither can anything else here.**
P3 re-serialises in the order the bytes carried, so a document whose keys were
all emitted in a different order round-trips just as cleanly. Discovering this
is what P8 is for and what P8 is *not*: P8 catches an **inconsistent** order
(two objects with one key set disagreeing), and P7 catches ``report_version``
leaving the front, but a reordering applied uniformly everywhere would survive
both. It could only be caught by a reader that independently knew the Rust
struct declaration order, and parsing that out of ``report.rs`` is exactly the
kind of brittleness that produces a false red at a freeze gate.

The mitigation is elsewhere and is not a cross-check: reordering a field is a
source edit that moves every pinned string at once, so ``vector-freeze`` and
the native↔WASM bit-match both go red, and D29 rule 1 makes it a format event
by construction. This checker's claim is over the *bytes*, not over the
struct.

Two envelope checks ride along (E1, E2) because they cost nothing and guard
the same freeze: ``report_json`` is itself lowercase even-length hex, and
``report_len`` equals the decoded byte length.

Discovery
---------
``testdata/vectors/v*/report/*.json`` — never a hard-coded ``v1``, so a
future v2 format directory is picked up with no edit here (the promise
``testdata/vectors/README.md`` makes). Pinned strings are collected by
walking each document for any key named ``report_json``, so a v2 envelope
that nests its cases differently still works.

A run that discovers nothing **fails**: a checker that passes vacuously is
the failure mode D31 §11 item 6 exists to prevent.

Exit codes: ``0`` every property held · ``1`` a violation, or a self-test
breach, or discovery found nothing.
"""

from __future__ import annotations

import argparse
import binascii
import json
import pathlib
import re
import sys

# ── D29's syntactic vocabulary ─────────────────────────────────────────────

# D29 rule 7, first clause: "Field names are the Rust snake_case names,
# unrenamed." NOTE for anyone reading tasks/Q.md's Q38 entry: it asked for
# kebab-case *keys*, which is wrong and was corrected here — see Q44. Rule 7
# puts kebab-case on enum wire names (P9), never on field names.
SNAKE_CASE = re.compile(r"^[a-z][a-z0-9]*(_[a-z0-9]+)*$")

# D29 rule 7, second clause: enum wire names are kebab-case.
KEBAB_CASE = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")

# D29 rule 6: binary data is lowercase hex.
LOWER_HEX = re.compile(r"^[0-9a-f]+$")

# What counts as "a hex string" to an independent reader with no schema.
#
# The report carries no type information, so hex has to be recognised by
# shape. The floor is 16 characters: below it, an all-hex-character string is
# indistinguishable from ordinary data — `claimed_time_informational_only` is
# the decimal string "1767225600", ten characters, every one of them a hex
# digit. Sixteen is comfortably above every non-binary field in the format and
# comfortably below the shortest binary one (a 32-byte digest is 64).
#
# The heuristic's honest limit: a 16+ character free-text value that happened
# to use only [0-9a-fA-F] would be flagged. No such value exists today and the
# failure message explains the shape rule, so a human can adjudicate it.
HEX_SHAPED = re.compile(r"^[0-9a-fA-F]{16,}$")
HEX_SHAPE_FLOOR = 16

# P9's registry: the report fields whose values are D29 rule-7 enums, as
# opposed to free text (`title`, `path`) or opaque strings
# (`claimed_time_informational_only`, `fetch_date`, `source`).
#
# This is deliberately a closed list rather than a heuristic. The alternative
# — "any token-shaped string must be kebab-case" — would fire on a legitimate
# single-word `title`, and a false red at the freeze gate is a worse outcome
# than a narrower check. Adding an enum field to the report means adding it
# here; ANTI-ROT below makes forgetting visible, because a registry key that
# matches nothing turns the lane red instead of checking nothing.
ENUM_FIELDS = ("kind", "state", "signature_scheme", "storage_linkage", "supporting_evidence")

REPORT_VERSION_KEY = "report_version"

# Where the Rust constant lives. P7 compares the vectors against the *source*,
# not just against the vector's own declared `expect.report_version`, so a
# constant bumped without re-emitting the vectors turns this red. R32 is the
# precedent: that bump rewrote all 21 pinned strings at once.
RUST_REPORT_VERSION = pathlib.Path("crates/antseal-core/src/verify/report.rs")
RUST_CONST = re.compile(r"^pub const REPORT_VERSION:\s*u32\s*=\s*(\d+)\s*;", re.MULTILINE)


class Violation(Exception):
    """One property failed. Carries the property id for the self-test."""

    def __init__(self, prop: str, where: str, detail: str) -> None:
        super().__init__(f"{prop} {where}: {detail}")
        self.prop = prop
        self.where = where
        self.detail = detail


# ── parsing, with the hooks that make P2 and P4 exact ──────────────────────


def _no_float(_text: str) -> float:
    raise Violation("P4", "<parse>", "a float literal appears in the bytes (D29 rule 3)")


def _no_constant(name: str) -> float:
    raise Violation("P4", "<parse>", f"the non-finite constant {name} appears (D29 rule 3)")


def _pairs(items: list[tuple[str, object]]) -> dict:
    """``object_pairs_hook`` that rejects duplicate keys (P2).

    ``json.loads`` silently keeps the last of a duplicated key, which would
    make P3 fail with an unhelpful byte-length mismatch. Catching it here
    names the key instead.
    """
    seen: set[str] = set()
    for key, _ in items:
        if key in seen:
            raise Violation("P2", "<parse>", f"duplicate key {key!r} in one object")
        seen.add(key)
    return dict(items)


def parse_report(raw: bytes, where: str) -> dict:
    """P1: UTF-8, parses, and is an object at the top level."""
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise Violation("P1", where, f"not valid UTF-8: {exc}") from exc
    try:
        value = json.loads(
            text, object_pairs_hook=_pairs, parse_float=_no_float, parse_constant=_no_constant
        )
    except Violation as exc:  # P2/P4 raised from inside a hook
        raise Violation(exc.prop, where, exc.detail) from None
    except json.JSONDecodeError as exc:
        raise Violation("P1", where, f"does not parse as JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise Violation("P1", where, f"top level is {type(value).__name__}, not an object")
    return value


# ── the property engine ────────────────────────────────────────────────────


def check_bytes(raw: bytes, where: str, expected_version: int, orders: dict) -> dict:
    """Run every byte-level property over one pinned report string.

    ``orders`` accumulates P8's key-set → key-order map across the whole run
    and is mutated here; pass a fresh dict per document.

    Returns the parsed value so the caller can reuse it.
    """
    value = parse_report(raw, where)  # P1, P2, P4-at-parse

    # P3 — the load-bearing one. dicts preserve insertion order in CPython
    # 3.7+, so `json.dumps` writes the keys back in exactly the order the
    # bytes carried them. Compact separators and `ensure_ascii=False` match
    # D29 rule 5's `serde_json::to_vec` and serde_json's non-escaping of
    # non-ASCII; if either the separators, the order, an integer formatting
    # or a string escape differed, the bytes would not come back.
    again = json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    if again != raw:
        raise Violation(
            "P3",
            where,
            "compact re-serialisation in the received key order does not reproduce the "
            f"bytes ({len(again)} bytes vs {len(raw)}); first difference at offset "
            f"{_first_difference(again, raw)}",
        )

    # P7 — `report_version` first, integer, and equal to the pinned constant.
    keys = list(value)
    if not keys or keys[0] != REPORT_VERSION_KEY:
        raise Violation(
            "P7",
            where,
            f"first key is {keys[0]!r} but D29 rule 8 makes it {REPORT_VERSION_KEY!r}"
            if keys
            else "the document is empty",
        )
    version = value[REPORT_VERSION_KEY]
    if isinstance(version, bool) or not isinstance(version, int):
        raise Violation("P7", where, f"{REPORT_VERSION_KEY} is {version!r}, not an integer")
    if version != expected_version:
        raise Violation(
            "P7",
            where,
            f"{REPORT_VERSION_KEY} is {version} but the pinned constant is {expected_version}",
        )

    _walk(value, where, "$", orders)
    return value


def _first_difference(a: bytes, b: bytes) -> int:
    for i, (x, y) in enumerate(zip(a, b)):
        if x != y:
            return i
    return min(len(a), len(b))


def _walk(node: object, where: str, path: str, orders: dict) -> None:
    """P4, P5, P6, P8, P9 over the whole tree."""
    if isinstance(node, dict):
        keys = tuple(node)

        # P6 — every key snake_case (D29 rule 7, first clause).
        for key in keys:
            if not SNAKE_CASE.match(key):
                raise Violation(
                    "P6", where, f"{path}.{key}: key is not snake_case (D29 rule 7)"
                )

        # P8 — declaration order is the wire order (D29 rule 1), so two
        # objects carrying the same key set must carry it in the same order.
        # Checked across every document of a run, which is where a
        # per-case reordering would show up.
        signature = frozenset(keys)
        previous = orders.get(signature)
        if previous is None:
            orders[signature] = (keys, f"{where}{path}")
        elif previous[0] != keys:
            raise Violation(
                "P8",
                where,
                f"{path}: key order {list(keys)} contradicts {list(previous[0])} "
                f"first seen at {previous[1]} — D29 rule 1 makes declaration order "
                "the wire order, so one key set has one order",
            )

        for key, child in node.items():
            _walk(child, where, f"{path}.{key}", orders)

            # P9 — enum wire names are kebab-case (D29 rule 7, second clause).
            if key in ENUM_FIELDS and isinstance(child, str):
                if not KEBAB_CASE.match(child):
                    raise Violation(
                        "P9",
                        where,
                        f"{path}.{key}: enum value {child!r} is not kebab-case (D29 rule 7)",
                    )

    elif isinstance(node, list):
        for index, child in enumerate(node):
            _walk(child, where, f"{path}[{index}]", orders)

    elif isinstance(node, float):
        # Belt and braces: `parse_float` already refuses float literals, so
        # reaching here means a caller synthesised one (the self-test does).
        raise Violation("P4", where, f"{path}: float value {node!r} (D29 rule 3)")

    elif isinstance(node, str):
        # P5 — binary is lowercase hex (D29 rule 6).
        if HEX_SHAPED.match(node):
            if not LOWER_HEX.match(node):
                raise Violation(
                    "P5",
                    where,
                    f"{path}: hex-shaped string is not lowercase (D29 rule 6): {node!r}",
                )
            if len(node) % 2:
                raise Violation(
                    "P5",
                    where,
                    f"{path}: hex-shaped string has odd length {len(node)} — "
                    "half a byte cannot be encoded (D29 rule 6)",
                )


# ── documents ──────────────────────────────────────────────────────────────


def collect_pinned(node: object, path: str = "$") -> list[tuple[str, str]]:
    """Every ``report_json`` string in a vector document, with its path.

    Walks rather than indexing ``expect.cases[]`` so a future envelope layout
    needs no edit here.
    """
    found: list[tuple[str, str]] = []
    if isinstance(node, dict):
        for key, child in node.items():
            if key == "report_json" and isinstance(child, str):
                found.append((f"{path}.{key}", child))
            else:
                found.extend(collect_pinned(child, f"{path}.{key}"))
    elif isinstance(node, list):
        for index, child in enumerate(node):
            found.extend(collect_pinned(child, f"{path}[{index}]"))
    return found


def check_document(document: dict, name: str, rust_version: int) -> tuple[int, int]:
    """Every property over one vector document. Returns (strings, enums seen)."""
    pinned = collect_pinned(document)
    if not pinned:
        raise Violation("P1", name, "no `report_json` strings — the document pins nothing")

    # Anti-vacuity: if the envelope declares a case list, every case must have
    # contributed a pinned string. An emitter that dropped `report_json` from
    # half its cases would otherwise pass with half the coverage.
    cases = document.get("expect", {}).get("cases")
    if isinstance(cases, list) and len(cases) != len(pinned):
        raise Violation(
            "E0",
            name,
            f"{len(cases)} cases declared but {len(pinned)} pinned strings found — "
            "a case lost its `report_json`",
        )

    # P7's pinned constant. The vector's own declaration must agree with the
    # Rust source; both must then equal every document's first field.
    declared = document.get("expect", {}).get(REPORT_VERSION_KEY)
    if declared is None:
        declared = rust_version
    elif isinstance(declared, bool) or not isinstance(declared, int):
        raise Violation("P7", name, f"expect.{REPORT_VERSION_KEY} is {declared!r}, not an integer")
    elif declared != rust_version:
        raise Violation(
            "P7",
            name,
            f"expect.{REPORT_VERSION_KEY} is {declared} but "
            f"{RUST_REPORT_VERSION}'s REPORT_VERSION is {rust_version} — a constant was "
            "bumped without re-emitting the vectors (R32 is the precedent)",
        )

    orders: dict = {}
    enums = 0
    for index, (path, hex_string) in enumerate(pinned):
        where = f"{name}{path}"

        # E1 — the envelope's own hex discipline.
        if not LOWER_HEX.match(hex_string) or len(hex_string) % 2:
            raise Violation(
                "E1", where, "`report_json` is not lowercase, even-length hex"
            )
        raw = binascii.unhexlify(hex_string)

        # E2 — `report_len` agrees with the bytes it describes.
        case = _case_of(document, index)
        if isinstance(case, dict) and isinstance(case.get("report_len"), int):
            if case["report_len"] != len(raw):
                raise Violation(
                    "E2",
                    where,
                    f"report_len is {case['report_len']} but the decoded bytes are {len(raw)}",
                )

        value = check_bytes(raw, where, declared, orders)
        enums += sum(1 for _ in _enum_values(value))

    # ANTI-ROT for P9: a registry entry that matches nothing is a renamed
    # field, and a checker silently checking nothing is the thing D31 §11
    # item 6 forbids.
    if enums == 0 and ENUM_FIELDS:
        raise Violation(
            "P9",
            name,
            f"none of the registered enum fields {list(ENUM_FIELDS)} appears in any "
            "report — the registry is stale and P9 checked nothing",
        )
    return len(pinned), enums


def _case_of(document: dict, index: int) -> object:
    cases = document.get("expect", {}).get("cases")
    if isinstance(cases, list) and index < len(cases):
        return cases[index]
    return None


def _enum_values(node: object):
    if isinstance(node, dict):
        for key, child in node.items():
            if key in ENUM_FIELDS and isinstance(child, str):
                yield child
            yield from _enum_values(child)
    elif isinstance(node, list):
        for child in node:
            yield from _enum_values(child)


# ── discovery ──────────────────────────────────────────────────────────────


def repo_root() -> pathlib.Path:
    return pathlib.Path(__file__).resolve().parent.parent


def discover(root: pathlib.Path) -> list[pathlib.Path]:
    return sorted(root.glob("testdata/vectors/v*/report/*.json"))


def rust_report_version(root: pathlib.Path) -> int:
    path = root / RUST_REPORT_VERSION
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise Violation("P7", str(RUST_REPORT_VERSION), f"cannot read the constant: {exc}") from exc
    match = RUST_CONST.search(text)
    if match is None:
        raise Violation(
            "P7",
            str(RUST_REPORT_VERSION),
            "no `pub const REPORT_VERSION: u32 = …;` found — the declaration moved and "
            "this checker's pin is now unanchored",
        )
    return int(match.group(1))


def rel(root: pathlib.Path, path: pathlib.Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


# ── --check ────────────────────────────────────────────────────────────────


def run_check(root: pathlib.Path) -> int:
    documents = discover(root)
    if not documents:
        print(
            "FAIL  no testdata/vectors/v*/report/*.json found — discovery is broken or the "
            "vectors were deleted, and this checker would pass vacuously.",
            file=sys.stderr,
        )
        return 1

    try:
        version = rust_report_version(root)
    except Violation as exc:
        print(f"FAIL  {exc}", file=sys.stderr)
        return 1

    total = 0
    for path in documents:
        name = rel(root, path)
        try:
            with open(path, "r", encoding="utf-8") as handle:
                document = json.load(handle)
        except (OSError, json.JSONDecodeError) as exc:
            print(f"FAIL  {name}: cannot read the vector document: {exc}", file=sys.stderr)
            return 1
        try:
            strings, enums = check_document(document, name, version)
        except Violation as exc:
            print(
                f"FAIL  {exc}\n"
                "      This is a report-format disagreement between the committed bytes and "
                "D29's contract.\n"
                "      Never re-emit the vectors to make it agree (D31 §11 item 5) — decide "
                "first whether\n"
                "      the contract or the encoder is wrong.",
                file=sys.stderr,
            )
            return 1
        print(f"OK    {name}: {strings} pinned report string(s), {enums} enum value(s)")
        total += strings

    print(
        f"\nreport byte format OK: {total} pinned string(s) across {len(documents)} document(s), "
        f"report_version {version}, 9 properties + 3 envelope checks each (T1, no T0 anchor)"
    )
    return 0


# ── --self-test ────────────────────────────────────────────────────────────
#
# D31 §11 item 6: a checker never observed failing is not evidence. Every
# property gets its own planted fault, and the fault must be caught by *that*
# property and no other — a self-test that accepts any red would pass while
# nine properties collapsed into one.
#
# Faults are planted in memory, on a copy of a real committed document. The
# working tree is never written to.


def _reserialise(value: object) -> bytes:
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _faults(raw: bytes) -> list[tuple[str, str, bytes]]:
    """(property, label, mutated bytes) — one per byte-level property."""
    value = json.loads(raw, object_pairs_hook=_pairs)
    out: list[tuple[str, str, bytes]] = []

    out.append(("P1", "truncated mid-token", raw[: len(raw) // 2]))
    out.append(("P1", "invalid UTF-8 byte", raw[:-1] + b"\xff"))

    # P2 — a duplicate key survives only in raw bytes; no dict can hold it.
    out.append(
        (
            "P2",
            "duplicate key",
            b'{"report_version":1,"report_version":1' + raw[len(b'{"report_version":1') :],
        )
    )

    # P3 — the same document, pretty-printed. Parses, is semantically
    # identical, and is not the pinned bytes.
    out.append(("P3", "non-compact separators", json.dumps(value).encode("utf-8")))
    out.append(("P3", "a space after a colon", raw.replace(b'":', b'" :', 1)))

    # P4 — a float where an integer belongs.
    floated = dict(value)
    floated["report_version"] = 1.0
    out.append(("P4", "float literal", _reserialise(floated)))

    # P5 — one hex digit uppercased.
    upper = _mutate_hex(value)
    if upper is not None:
        out.append(("P5", "uppercase hex digit", _reserialise(upper)))
    odd = _mutate_hex(value, drop_one=True)
    if odd is not None:
        out.append(("P5", "odd-length hex", _reserialise(odd)))

    # P6 — a key renamed to kebab-case, which D29 rule 7 reserves for enum
    # values. This is also the regression guard for Q44's correction.
    kebabbed = {("work-id" if k == "work" else k): v for k, v in value.items()}
    out.append(("P6", "kebab-case key", _reserialise(kebabbed)))

    # P7 — `report_version` no longer first, and `report_version` wrong.
    demoted = {k: v for k, v in value.items() if k != "report_version"}
    demoted["report_version"] = value["report_version"]
    out.append(("P7", "report_version not first", _reserialise(demoted)))
    bumped = dict(value)
    bumped["report_version"] = value["report_version"] + 1
    out.append(("P7", "report_version != the pinned constant", _reserialise(bumped)))

    # P9 — an enum value that is not kebab-case.
    shouted = _mutate_enum(value)
    if shouted is not None:
        out.append(("P9", "enum value not kebab-case", _reserialise(shouted)))

    return out


def _first_multikey(node: object, skip_top: bool = False):
    """Find an object with >= 2 keys, returning (that object, its first key).

    ``skip_top`` refuses the root object. P8's fault needs a *nested* victim:
    reordering the root moves ``report_version`` off the front, and P7 would
    fire first — proving P7 twice and P8 not at all.
    """
    if isinstance(node, dict):
        if len(node) >= 2 and not skip_top:
            return node, next(iter(node))
        for child in node.values():
            found = _first_multikey(child)
            if found is not None:
                return found
    elif isinstance(node, list):
        for child in node:
            found = _first_multikey(child)
            if found is not None:
                return found
    return None


def _replace(node: object, needle: object, replacement: object) -> object:
    if node is needle:
        return replacement
    if isinstance(node, dict):
        return {k: _replace(v, needle, replacement) for k, v in node.items()}
    if isinstance(node, list):
        return [_replace(v, needle, replacement) for v in node]
    return node


def _mutate_hex(node: object, drop_one: bool = False) -> object:
    """Return a copy with the first hex-shaped string corrupted, or None."""
    hit = [False]

    def go(item: object) -> object:
        if hit[0]:
            return item
        if isinstance(item, dict):
            return {k: go(v) for k, v in item.items()}
        if isinstance(item, list):
            return [go(v) for v in item]
        if isinstance(item, str) and HEX_SHAPED.match(item):
            hit[0] = True
            if drop_one:
                return item[:-1]
            # Uppercase the first *letter*, not the first character: a digest
            # ending in a digit would make `.upper()` a silent no-op and the
            # fault would never be planted. That bug was real and this
            # self-test caught it.
            for index, char in enumerate(item):
                if char.isalpha():
                    return item[:index] + char.upper() + item[index + 1 :]
            hit[0] = False
        return item

    out = go(node)
    return out if hit[0] else None


def _mutate_enum(node: object) -> object:
    """Return a copy with the first registered enum value SHOUTED, or None."""
    hit = [False]

    def go(item: object) -> object:
        if isinstance(item, dict):
            out = {}
            for k, v in item.items():
                if not hit[0] and k in ENUM_FIELDS and isinstance(v, str):
                    hit[0] = True
                    out[k] = v.upper()
                else:
                    out[k] = go(v)
            return out
        if isinstance(item, list):
            return [go(v) for v in item]
        return item

    out = go(node)
    return out if hit[0] else None


def run_self_test(root: pathlib.Path) -> int:
    documents = discover(root)
    if not documents:
        print("FAIL  self-test: no report vectors to plant faults in", file=sys.stderr)
        return 1
    with open(documents[0], "r", encoding="utf-8") as handle:
        document = json.load(handle)
    pinned = collect_pinned(document)
    if not pinned:
        print("FAIL  self-test: the first document pins no report strings", file=sys.stderr)
        return 1

    version = rust_report_version(root)
    raw = binascii.unhexlify(pinned[0][1])
    status = 0

    # Control: unmutated bytes must be GREEN, or every red below is noise.
    try:
        check_bytes(raw, "<control>", version, {})
        print("OK    control: the unmutated bytes pass")
    except Violation as exc:
        print(f"FAIL  control: the unmutated bytes already fail — {exc}", file=sys.stderr)
        return 1

    seen: set[str] = set()
    for prop, label, mutated in _faults(raw):
        try:
            check_bytes(mutated, "<self-test>", version, {})
        except Violation as exc:
            if exc.prop == prop:
                print(f"OK    {prop} {label}: caught")
                seen.add(prop)
            else:
                print(
                    f"FAIL  {prop} {label}: caught by {exc.prop} instead — the properties have "
                    f"collapsed into each other ({exc.detail})",
                    file=sys.stderr,
                )
                status = 1
        else:
            print(
                f"FAIL  {prop} {label}: the checker stayed GREEN — that property is not "
                "actually being checked",
                file=sys.stderr,
            )
            status = 1

    # P8 needs two strings' worth of state — the same key set in two orders
    # inside one run — so it is planted against a shared `orders` map rather
    # than through a single `check_bytes` call.
    #
    # The victim must be a NESTED object: reordering the root moves
    # `report_version` off the front and P7 fires first, which would prove P7
    # twice and P8 not at all.
    orders: dict = {}
    swapped = _mutate_order(json.loads(raw, object_pairs_hook=_pairs))
    if swapped is None:
        print("FAIL  P8 setup: no nested reorderable object in the fixture", file=sys.stderr)
        status = 1
    else:
        try:
            check_bytes(raw, "<self-test/a>", version, orders)
            check_bytes(_reserialise(swapped), "<self-test/b>", version, orders)
        except Violation as exc:
            if exc.prop == "P8":
                print("OK    P8 same key set, two orders: caught")
                seen.add("P8")
            else:
                print(f"FAIL  P8 reordered nested object: caught by {exc.prop} instead — "
                      f"{exc.detail}", file=sys.stderr)
                status = 1
        else:
            print("FAIL  P8: the checker stayed GREEN on a reordered object", file=sys.stderr)
            status = 1

    # Document-level faults: E0, E1, E2 and the P7 constant coupling.
    for prop, label, mutate in _document_faults():
        clone = json.loads(json.dumps(document))
        mutate(clone)
        try:
            check_document(clone, "<self-test>", version)
        except Violation as exc:
            if exc.prop == prop:
                print(f"OK    {prop} {label}: caught")
                seen.add(prop)
            else:
                print(f"FAIL  {prop} {label}: caught by {exc.prop} instead", file=sys.stderr)
                status = 1
        else:
            print(f"FAIL  {prop} {label}: the checker stayed GREEN", file=sys.stderr)
            status = 1

    required = {"P1", "P2", "P3", "P4", "P5", "P6", "P7", "P8", "P9", "E0", "E1", "E2"}
    missing = sorted(required - seen)
    if missing:
        print(
            f"FAIL  self-test: no fault was ever planted for {missing} — those properties are "
            "unproven",
            file=sys.stderr,
        )
        status = 1

    if status == 0:
        print(
            f"\nself-test PASSED: {len(required)} properties each observed failing on their own "
            "planted fault, and green without it"
        )
    return status


def _mutate_order(node: object) -> object:
    """Move the first key of the first *nested* multi-key object to the end."""
    found = _first_multikey(node, skip_top=True)
    if found is None:
        return None
    holder, key = found
    moved = {k: v for k, v in holder.items() if k != key}
    moved[key] = holder[key]
    return _replace(node, holder, moved)


def _document_faults() -> list[tuple[str, str, object]]:
    def drop_case(doc: dict) -> None:
        doc["expect"]["cases"][0].pop("report_json")

    def upper_envelope(doc: dict) -> None:
        case = doc["expect"]["cases"][0]
        case["report_json"] = case["report_json"].upper()

    def wrong_len(doc: dict) -> None:
        doc["expect"]["cases"][0]["report_len"] += 1

    def wrong_declared(doc: dict) -> None:
        doc["expect"]["report_version"] += 1

    return [
        ("E0", "a case lost its report_json", drop_case),
        ("E1", "envelope hex uppercased", upper_envelope),
        ("E2", "report_len disagrees with the bytes", wrong_len),
        ("P7", "expect.report_version != the Rust constant", wrong_declared),
    ]


# ── entry point ────────────────────────────────────────────────────────────


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--check", action="store_true", help="check every committed report vector (the default)"
    )
    parser.add_argument(
        "--self-test", action="store_true", dest="self_test", help="prove the checker can go red"
    )
    args = parser.parse_args()

    root = repo_root()
    try:
        if args.self_test:
            return run_self_test(root)
        return run_check(root)
    except Violation as exc:
        print(f"FAIL  {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
