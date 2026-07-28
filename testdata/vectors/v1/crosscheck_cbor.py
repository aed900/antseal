#!/usr/bin/env python3
"""F14 — the independent CBOR cross-check over this version's golden vectors.

The **second implementation** in the pre-freeze cross-check mandate
(MVP-SPEC.md line 5; Definitions & encoding, line 73). Contract:
``docs/testing/cbor-cross-check.md`` (F19). Vehicles and tiers: decision
**D31** (``docs/decisions/D31-cross-check-vehicles.md``), rows 1-3 and 11.

Why this file exists at all
---------------------------
Our own codec round-tripping our own bytes proves nothing about the bytes: an
encoder and a decoder that share a bug agree with each other perfectly. This
checker shares no code with ``antseal-core``. It never runs our encoder, never
links our crate, and takes every expectation from the **committed** files.

The division of labour D31 insists on
-------------------------------------
* **Decoding** is ``cbor2 ==6.1.3`` (D7 §D12) — a genuinely independent
  implementation: different author, different codebase, and *zero shared
  code* (``minicbor 2.3.0`` has no dependencies at all).
* **Encoding is ours** — :func:`encode_canonical`, written here from
  RFC 8949 §4.2.1. D31 §8 rejected cbor2's ``dumps(canonical=True)``: its key
  order is RFC 7049 length-first, which merely *coincides* with §4.2.1 over
  today's unsigned-integer keys. Using it would have imported that caveat as
  a permanent documented exception; writing the encoder retires it, and makes
  the encoding authority ours-vs-minicbor rather than one library's canonical
  mode versus another's.
* **Canonicality judgement is ours too** (:func:`strict_render`), for the same
  reason: neither library's notion of "canonical" is trusted.

This is D31 tier **T1** — an independent re-implementation. T1 cannot catch a
*shared misreading of the spec*, so the RFC 8949 Appendix A worked examples
run first as a **T0 external oracle**: bytes the RFC itself publishes, which
no amount of agreement between our two implementations could manufacture.

Exit codes: ``0`` all checks passed · ``1`` a disagreement · ``2`` cbor2 is
not provisioned (``--require`` turns that into ``1``).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import sys
import urllib.request
import zipfile

# ---------------------------------------------------------------------------
# The rendering table (docs/testing/cbor-cross-check.md §3)
#
# This is the SECOND implementation of the table that
# crates/antseal-core/src/test_util/vectors_cbor_diag.rs implements in Rust.
# The two are deliberately written from the spec, not from each other, and are
# held together by crates/antseal-core/tests/cbor_crosscheck_contract.rs.
#
#   unsigned int (major 0) -> JSON number, non-negative
#   negative int (major 1) -> JSON number, negative
#   byte string  (major 2) -> {"b": "<lowercase hex>"}
#   text string  (major 3) -> JSON string
#   array        (major 4) -> JSON array
#   map          (major 5) -> {"m": [[key, value], ...]}, entries in wire order
#
# The largest integer the sidecar may carry: 2^53 - 1, the last value an
# IEEE-754 double represents exactly. Rendering above it would produce a
# sidecar some conforming JSON readers silently round -- the one thing a
# cross-check artifact must never do. Must equal
# `vectors_cbor_diag::MAX_JSON_SAFE_INT`.
MAX_JSON_SAFE_INT = 9007199254740991

CBOR2_VERSION = "6.1.3"

VERSION_DIR = pathlib.Path(__file__).resolve().parent
REPO_ROOT = VERSION_DIR.parents[2]
REQUIREMENTS = REPO_ROOT / "requirements-crosscheck.txt"
TAMPER_FORMAT = REPO_ROOT / "testdata" / "tamper" / "format"


class CheckFailure(Exception):
    """A disagreement between this implementation and the committed bytes."""


# ---------------------------------------------------------------------------
# OUR OWN RFC 8949 §4.2.1 canonical encoder (D31 row 1).
#
# Deliberately written from the RFC text, not from either codec:
#
#   * "Preferred serialization": the argument uses the shortest of the five
#     head forms that can express it (§4.2.1 -> §4.1).
#   * Definite lengths only.
#   * Map keys sorted by the **bytewise lexicographic order of their encoded
#     form**. Note this is the real §4.2.1 rule, not "sort the integers":
#     implementing it properly is what retires D7 §D12's RFC 7049 caveat
#     instead of documenting it, and it keeps working if a future registry
#     ever admits a non-integer key.
# ---------------------------------------------------------------------------


def _head(major: int, arg: int) -> bytes:
    if arg < 0:
        raise CheckFailure(f"negative argument {arg} in a CBOR head")
    if arg < 24:
        return bytes([(major << 5) | arg])
    for additional, width in ((24, 1), (25, 2), (26, 4), (27, 8)):
        if arg < (1 << (8 * width)):
            return bytes([(major << 5) | additional]) + arg.to_bytes(width, "big")
    raise CheckFailure(f"argument {arg} exceeds the 64-bit CBOR head")


def encode_canonical(item: object) -> bytes:
    """Encode one item per RFC 8949 §4.2.1 Core Deterministic Encoding."""
    if isinstance(item, bool):
        raise CheckFailure("booleans are outside the antseal CBOR profile")
    if isinstance(item, int):
        return _head(0, item) if item >= 0 else _head(1, -1 - item)
    if isinstance(item, (bytes, bytearray)):
        return _head(2, len(item)) + bytes(item)
    if isinstance(item, str):
        raw = item.encode("utf-8")
        return _head(3, len(raw)) + raw
    if isinstance(item, (list, tuple)):
        return _head(4, len(item)) + b"".join(encode_canonical(x) for x in item)
    if isinstance(item, dict):
        entries = sorted((encode_canonical(k), encode_canonical(v)) for k, v in item.items())
        for i in range(1, len(entries)):
            if entries[i][0] == entries[i - 1][0]:
                raise CheckFailure("duplicate map key after canonical encoding")
        return _head(5, len(entries)) + b"".join(k + v for k, v in entries)
    raise CheckFailure(f"{type(item).__name__} is outside the antseal CBOR profile")


# ---------------------------------------------------------------------------
# Our own strict CBOR reader: renderer AND canonicality validator in one pass.
#
# It exists because `cbor2.loads` cannot answer the questions the canonicality
# check asks. A decoded Python object has already lost the evidence: duplicate
# map keys have collapsed into one, a non-shortest integer head reads back as
# the same integer, an indefinite-length string reads back as the same string.
# Those are exactly the non-canonical classes the F3 profile hard-rejects, so
# they must be judged on the WIRE, before any library sees them.
# ---------------------------------------------------------------------------


def _read_head(buf: memoryview, pos: int) -> tuple[int, int, int]:
    """Read one CBOR head. Returns ``(major, argument, next_pos)``.

    Enforces **shortest-form** heads (RFC 8949 §4.2.1) and rejects
    indefinite lengths outright.
    """
    if pos >= len(buf):
        raise CheckFailure(f"truncated: no head byte at offset {pos}")
    ib = buf[pos]
    major, ai = ib >> 5, ib & 0x1F
    pos += 1
    if ai < 24:
        return major, ai, pos
    if ai == 31:
        raise CheckFailure(f"indefinite-length item at offset {pos - 1} (major {major})")
    if ai > 27:
        raise CheckFailure(f"reserved additional-information {ai} at offset {pos - 1}")
    width = 1 << (ai - 24)
    if pos + width > len(buf):
        raise CheckFailure(f"truncated {width}-byte argument at offset {pos}")
    arg = int.from_bytes(buf[pos : pos + width], "big")
    pos += width
    # Shortest form: each width may only carry values the narrower widths
    # cannot. This is the check a decoded object can no longer answer.
    floor = {1: 24, 2: 1 << 8, 4: 1 << 16, 8: 1 << 32}[width]
    if arg < floor:
        raise CheckFailure(
            f"non-shortest head at offset {pos - width - 1}: value {arg} encoded in "
            f"{width} byte(s), minimum for that width is {floor}"
        )
    return major, arg, pos


def _render_int(value: int) -> int:
    """Render an integer, refusing anything a double reader would round."""
    if value > MAX_JSON_SAFE_INT or value < -MAX_JSON_SAFE_INT:
        raise CheckFailure(
            f"integer {value} exceeds the JSON-safe bound {MAX_JSON_SAFE_INT}: a sidecar "
            f"must not carry a number some conforming readers round"
        )
    return value


def _render_item(buf: memoryview, pos: int, depth: int) -> tuple[object, int]:
    if depth > 64:
        raise CheckFailure(f"nesting deeper than 64 at offset {pos}")
    major, arg, pos = _read_head(buf, pos)
    if major == 0:
        return _render_int(arg), pos
    if major == 1:
        return _render_int(-1 - arg), pos
    if major in (2, 3):
        if pos + arg > len(buf):
            raise CheckFailure(f"truncated string of length {arg} at offset {pos}")
        raw = bytes(buf[pos : pos + arg])
        pos += arg
        if major == 2:
            # Embedded CBOR is NEVER recursed into: the layer boundary is what
            # F6/F9's three-layer strict decode is about, so it stays visible.
            return {"b": raw.hex()}, pos
        try:
            return raw.decode("utf-8"), pos
        except UnicodeDecodeError as exc:
            raise CheckFailure(f"invalid UTF-8 text string at offset {pos - arg}: {exc}") from exc
    if major == 4:
        items = []
        for _ in range(arg):
            item, pos = _render_item(buf, pos, depth + 1)
            items.append(item)
        return items, pos
    if major == 5:
        entries: list[list[object]] = []
        previous: int | None = None
        for _ in range(arg):
            kpos = pos
            kmajor, key, pos = _read_head(buf, pos)
            if kmajor != 0:
                raise CheckFailure(
                    f"map key at offset {kpos} has major type {kmajor}; the v1 registry "
                    f"uses unsigned-integer keys only"
                )
            if previous is not None and key <= previous:
                # Strictly ascending. Over uint-only keys, bytewise order
                # (RFC 8949 §4.2.1) and numeric order coincide, so this single
                # test covers both duplicate keys and out-of-order keys.
                relation = "duplicated" if key == previous else "out of order after"
                raise CheckFailure(f"map key {key} at offset {kpos} is {relation} {previous}")
            previous = key
            value, pos = _render_item(buf, pos, depth + 1)
            entries.append([_render_int(key), value])
        return {"m": entries}, pos
    raise CheckFailure(
        f"major type {major} at offset {pos - 1} is outside the profile "
        f"(no tags, floats or simple values)"
    )


def strict_render(data: bytes) -> object:
    """Validate canonicality on the wire and render per the table.

    One item, no trailing bytes -- the same contract as
    ``antseal_core::codec::decode::check_canonical``, and the reason a sidecar
    can never describe more or less than the bytes it accompanies.
    """
    buf = memoryview(data)
    value, pos = _render_item(buf, 0, 0)
    if pos != len(buf):
        raise CheckFailure(f"{len(buf) - pos} trailing byte(s) after the top-level item")
    return value


# ---------------------------------------------------------------------------
# Reconstruction: committed sidecar JSON -> Python objects for re-encoding.
#
# The input is the COMMITTED diagnostic, never this checker's own decode.
# Rebuilding from our own decode would close the loop through one
# implementation and check nothing.
# ---------------------------------------------------------------------------


def reconstruct(item: object, where: str = "$") -> object:
    if isinstance(item, bool):  # bool is a subclass of int in Python -- check first
        raise CheckFailure(f"{where}: booleans are not in the rendering table")
    if isinstance(item, float):
        raise CheckFailure(f"{where}: floats are not in the rendering table")
    if isinstance(item, int):
        return _render_int(item)
    if isinstance(item, str):
        return item
    if isinstance(item, list):
        return [reconstruct(x, f"{where}[{i}]") for i, x in enumerate(item)]
    if isinstance(item, dict):
        keys = set(item)
        if keys == {"b"}:
            hexed = item["b"]
            if not isinstance(hexed, str) or hexed != hexed.lower():
                raise CheckFailure(f"{where}: byte strings render as lowercase hex")
            try:
                return bytes.fromhex(hexed)
            except ValueError as exc:
                raise CheckFailure(f"{where}: malformed hex: {exc}") from exc
        if keys == {"m"}:
            out: dict[int, object] = {}
            previous: int | None = None
            for i, entry in enumerate(item["m"]):
                if not isinstance(entry, list) or len(entry) != 2:
                    raise CheckFailure(f"{where}.m[{i}]: map entries are [key, value] pairs")
                key, value = entry
                if isinstance(key, bool) or not isinstance(key, int):
                    raise CheckFailure(f"{where}.m[{i}]: map keys are unsigned integers")
                if previous is not None and key <= previous:
                    # The encoder below sorts, so without this the re-encode
                    # would silently repair a reordered sidecar and check 2
                    # would wave through the exact mutation F19 names.
                    raise CheckFailure(
                        f"{where}.m[{i}]: key {key} is not strictly greater than {previous} "
                        f"-- the sidecar pins wire order (RFC 8949 §4.2.1)"
                    )
                previous = key
                out[_render_int(key)] = reconstruct(value, f"{where}.m[{i}][1]")
            return out
        raise CheckFailure(
            f"{where}: an object must be exactly {{'b': hex}} or {{'m': pairs}}; "
            f"got keys {sorted(keys)}"
        )
    raise CheckFailure(f"{where}: {type(item).__name__} is not in the rendering table")


def render_loaded(obj: object, where: str = "$") -> object:
    """Render what the independent decoder produced, per the same table."""
    if isinstance(obj, bool):
        raise CheckFailure(f"{where}: booleans are not in the rendering table")
    if isinstance(obj, float):
        raise CheckFailure(f"{where}: floats are not in the rendering table")
    if isinstance(obj, int):
        return _render_int(obj)
    if isinstance(obj, str):
        return obj
    if isinstance(obj, (bytes, bytearray)):
        return {"b": bytes(obj).hex()}
    if isinstance(obj, list):
        return [render_loaded(x, f"{where}[{i}]") for i, x in enumerate(obj)]
    if isinstance(obj, dict):
        entries = []
        for key, value in obj.items():
            if isinstance(key, bool) or not isinstance(key, int):
                raise CheckFailure(f"{where}: map key {key!r} is not an unsigned integer")
            entries.append([_render_int(key), render_loaded(value, f"{where}.{key}")])
        return {"m": entries}
    raise CheckFailure(f"{where}: {type(obj).__name__} is not in the rendering table")


# ---------------------------------------------------------------------------
# T0 EXTERNAL ORACLE — RFC 8949 Appendix A, "Examples of Encoded CBOR Data
# Items". These bytes are published by the RFC itself, so they cannot be
# manufactured by our two implementations agreeing with each other: they are
# the one thing here that catches a SHARED MISREADING of the spec, which is
# precisely what D31 §1 says tier T1 cannot see.
#
# Scope is the profile's own surface -- unsigned/negative integers, byte and
# text strings, arrays, maps. Appendix A rows for floats, tags, simple values
# and indefinite lengths are deliberately absent: the F3 profile rejects them,
# so there is nothing for our encoder to reproduce.
# ---------------------------------------------------------------------------

RFC_8949_APPENDIX_A: list[tuple[object, str]] = [
    (0, "00"),
    (1, "01"),
    (10, "0a"),
    (23, "17"),
    (24, "1818"),
    (25, "1819"),
    (100, "1864"),
    (1000, "1903e8"),
    (1000000, "1a000f4240"),
    (1000000000000, "1b000000e8d4a51000"),
    (18446744073709551615, "1bffffffffffffffff"),
    (-1, "20"),
    (-10, "29"),
    (-100, "3863"),
    (-1000, "3903e7"),
    (b"", "40"),
    (b"\x01\x02\x03\x04", "4401020304"),
    ("", "60"),
    ("a", "6161"),
    ("IETF", "6449455446"),
    ('"\\', "62225c"),
    ("ü", "62c3bc"),
    ("水", "63e6b0b4"),
    ("\U00010151", "64f0908591"),
    ([], "80"),
    ([1, 2, 3], "83010203"),
    ([1, [2, 3], [4, 5]], "8301820203820405"),
    (list(range(1, 26)), "98190102030405060708090a0b0c0d0e0f101112131415161718181819"),
    ({}, "a0"),
    ({1: 2, 3: 4}, "a201020304"),
    ({"a": 1, "b": [2, 3]}, "a26161016162820203"),
    (["a", {"b": "c"}], "826161a161626163"),
    ({"a": "A", "b": "B", "c": "C", "d": "D", "e": "E"}, "a56161614161626142616361436164614461656145"),
]


def rfc_8949_anchor(cbor2, report, table=None) -> int:
    """Both directions against the RFC's own published bytes.

    ``table`` is a seam for the self-test, which plants a wrong expectation and
    requires it to be caught — an oracle never observed failing is decorative.
    """
    table = RFC_8949_APPENDIX_A if table is None else table
    for value, expected in table:
        ours = encode_canonical(value)
        if ours.hex() != expected:
            raise CheckFailure(
                f"RFC 8949 Appendix A: encoding {value!r} gives {ours.hex()}, the RFC says "
                f"{expected}. Our §4.2.1 encoder is wrong"
            )
        theirs = cbor2.loads(bytes.fromhex(expected))
        if theirs != value or type(theirs) is not type(value):
            raise CheckFailure(
                f"RFC 8949 Appendix A: cbor2 decodes {expected} to {theirs!r}, the RFC says "
                f"{value!r}"
            )
    report(f"T0 anchor: {len(table)} RFC 8949 Appendix A examples, both directions")
    return len(table) * 2


# ---------------------------------------------------------------------------
# Preflight: confirm the independent library's behaviour, never assume it.
# ---------------------------------------------------------------------------


def installed_version(cbor2) -> str:
    """The loaded cbor2's version.

    cbor2 6.x exports no ``__version__`` -- its ``__init__.py`` is a pure
    re-export shim over the compiled ``_cbor2`` extension -- so the version
    comes from the distribution metadata beside it on ``sys.path``.
    """
    import importlib.metadata  # noqa: PLC0415

    try:
        return importlib.metadata.version("cbor2")
    except importlib.metadata.PackageNotFoundError as exc:
        raise CheckFailure(
            f"cbor2 loaded from {cbor2.__file__} carries no distribution metadata, so its "
            f"version cannot be confirmed; D12 pins =={CBOR2_VERSION} exactly"
        ) from exc


def preflight(cbor2, report) -> int:
    checks = 0

    version = installed_version(cbor2)
    if version != CBOR2_VERSION:
        raise CheckFailure(f"cbor2 {version} is on the path; D12 pins =={CBOR2_VERSION} exactly")
    checks += 1

    # (1) MAP ORDER ON LOAD -- the load-bearing assumption of the whole lane.
    # The sidecar pins wire order, so a decoder that sorted (or round-tripped
    # through a set) would weaken every map comparison to a set comparison
    # without anything going red. Demonstrated, not cited: a map whose wire
    # order is DESCENDING must come back descending.
    loaded = cbor2.loads(bytes([0xA2, 0x02, 0x00, 0x01, 0x00]))  # {2: 0, 1: 0}
    if list(loaded.keys()) != [2, 1]:
        raise CheckFailure(
            f"cbor2 does not preserve map order on load: {list(loaded.keys())} != [2, 1]. "
            f"Every map comparison in this checker would silently degrade to a set comparison"
        )
    checks += 1

    # (2) The known limitation that makes strict_render mandatory: duplicate
    # keys COLLAPSE on load. If a future cbor2 started rejecting them this
    # assertion goes red, and strict_render's rationale can be revisited.
    collapsed = cbor2.loads(bytes([0xA2, 0x01, 0x00, 0x01, 0x01]))  # {1: 0, 1: 1}
    if collapsed != {1: 1}:
        raise CheckFailure(
            f"cbor2's duplicate-key behaviour changed: {collapsed!r}. strict_render's "
            f"rationale needs revisiting"
        )
    checks += 1

    # (3) D7 §D12's byte-compatibility evidence, replayed against OUR encoder
    # so the decision record cannot rot: sorted uint-key map, 24-boundary head.
    replay = encode_canonical({1: 0, 2: 0, 10: 0, 24: 0})
    if replay.hex() != "a4010002000a00181800":
        raise CheckFailure(
            f"D12's recorded byte-compatibility evidence no longer reproduces: {replay.hex()}"
        )
    checks += 1

    # (4) The MAX_JSON_SAFE_INT refusal is asserted, not assumed (F19 notes).
    for probe in (MAX_JSON_SAFE_INT + 1, -MAX_JSON_SAFE_INT - 1):
        try:
            strict_render(encode_canonical(probe))
        except CheckFailure:
            pass
        else:
            raise CheckFailure(f"the JSON-safe bound is not enforced: {probe} rendered")
    if strict_render(encode_canonical(MAX_JSON_SAFE_INT)) != MAX_JSON_SAFE_INT:
        raise CheckFailure("the value at the JSON-safe bound must render")
    checks += 1

    report(f"preflight: cbor2 {version} ({cbor2.__file__}) -- {checks} checks")
    return checks


# ---------------------------------------------------------------------------
# Vector discovery and checking.
# ---------------------------------------------------------------------------


def discover() -> list[pathlib.Path]:
    """Every committed vector file of THIS format version.

    Mirrors the Q4 runner's discovery rule (``testdata/vectors/README.md``):
    ``*.json`` under ``v<n>/`` is a vector; ``INDEX.json`` is the one
    auxiliary that is also ``.json``. Other versions are covered by their own
    copy of this checker -- ``scripts/cross-check.sh`` iterates ``v*/``.
    """
    return [p for p in sorted(VERSION_DIR.rglob("*.json")) if p.name != "INDEX.json"]


def locate_layers(case: dict, top_bytes: bytes) -> dict[str, bytes]:
    """Find the bytes of every ``diagnostic`` layer, using no layer names.

    The outermost layer is the one whose rendering equals the committed bytes.
    Every other layer is an **embedded** one, so its bytes are already inside a
    layer we have located: we scan the byte strings of each located layer and
    keep the one that renders to that layer's committed diagnostic.

    Deliberately name-free. `envelope`/`body`/`bundle`/`manifest` are F12/F13
    conventions, not wire facts, and a new kind that names its layers
    differently is picked up here with no change.
    """
    wanted: dict[str, object] = dict(case["diagnostic"])
    located: dict[str, bytes] = {}

    top_render = strict_render(top_bytes)
    for name, expected in list(wanted.items()):
        if expected == top_render:
            located[name] = top_bytes
            del wanted[name]
            break
    else:
        # Locating IS the render-and-compare check for the outermost layer, so
        # say so, and point at the layer that came closest rather than leaving
        # a reviewer to guess which side moved.
        closest = max(wanted, key=lambda n: _common_prefix(top_render, wanted[n]))
        raise CheckFailure(
            f"the committed bytes ({len(top_bytes)} bytes) do not render to ANY committed "
            f"diagnostic layer {sorted(wanted)} -- the outermost layer's bytes and its sidecar "
            f"disagree. Closest is {closest!r}:\n  {_diff(top_render, wanted[closest])}"
        )

    progress = True
    while wanted and progress:
        progress = False
        for source in list(located.values()):
            for candidate in _byte_strings(strict_render(source)):
                try:
                    rendered = strict_render(candidate)
                except CheckFailure:
                    continue  # not CBOR: a salt, a hash, a signature
                for name, expected in list(wanted.items()):
                    if rendered == expected:
                        located[name] = candidate
                        del wanted[name]
                        progress = True
    if wanted:
        raise CheckFailure(
            f"layer(s) {sorted(wanted)}: no byte string embedded in the located layer(s) "
            f"{sorted(located)} renders to their committed diagnostic. Either that sidecar is "
            f"wrong (a changed value, or entries in the wrong order -- the sidecar pins WIRE "
            f"order), or the bytes it describes are not embedded where the format says"
        )
    return located


def _common_prefix(ours: object, theirs: object) -> int:
    a, b = json.dumps(ours), json.dumps(theirs)
    for i, (x, y) in enumerate(zip(a, b)):
        if x != y:
            return i
    return min(len(a), len(b))


def _byte_strings(item: object) -> list[bytes]:
    """Every byte string in a rendered item, outermost first."""
    out: list[bytes] = []
    if isinstance(item, dict):
        if "b" in item:
            out.append(bytes.fromhex(item["b"]))
        elif "m" in item:
            for _key, value in item["m"]:
                out.extend(_byte_strings(value))
    elif isinstance(item, list):
        for value in item:
            out.extend(_byte_strings(value))
    return out


def find_envelope(located: dict[str, bytes]) -> tuple[str, bytes, bytes]:
    """Identify the manifest envelope structurally, by no name at all.

    The envelope is the layer that is a map whose **key 0** is a byte string
    holding another located layer -- that nesting *is* the F5/F6 envelope
    (``{0: body, 1: signature container}``). Returns
    ``(layer_name, envelope_bytes, key0_bytes)``.

    For the `manifest` kind the envelope is the outermost layer; for `bundle`
    it is the embedded manifest, which is why `anchor_digest` is a real
    structural claim there and not just a hash of the file's own bytes.
    """
    matches = []
    for name, raw in located.items():
        rendered = strict_render(raw)
        if not (isinstance(rendered, dict) and "m" in rendered):
            continue
        entries = rendered["m"]
        if not entries or entries[0][0] != 0:
            continue
        value = entries[0][1]
        if not (isinstance(value, dict) and "b" in value):
            continue
        key0 = bytes.fromhex(value["b"])
        if any(key0 == other for other in located.values()):
            matches.append((name, raw, key0))
    if len(matches) != 1:
        raise CheckFailure(
            f"expected exactly one layer whose key-0 byte string is another located layer "
            f"(the manifest envelope); found {[m[0] for m in matches]}"
        )
    return matches[0]


def check_case(cbor2, case: dict) -> int:
    checks = 0
    name = case.get("name", "<unnamed>")

    byte_fields = [k for k in case if k.endswith("_bytes")]
    if len(byte_fields) != 1:
        raise CheckFailure(
            f"case {name!r}: expected exactly one committed `*_bytes` field, found {byte_fields}"
        )
    top_bytes = bytes.fromhex(case[byte_fields[0]])

    located = locate_layers(case, top_bytes)

    for layer in sorted(located):
        raw = located[layer]
        expected = case["diagnostic"][layer]

        # CANONICALITY -- on the wire, in our own logic (D31 row 3), plus the
        # rendering that falls out of the same pass.
        try:
            ours = strict_render(raw)
        except CheckFailure as exc:
            raise CheckFailure(f"case {name!r} layer {layer!r}: canonicality: {exc}") from exc
        if ours != expected:
            raise CheckFailure(
                f"case {name!r} layer {layer!r}: strict render disagrees with the committed "
                f"diagnostic\n  {_diff(ours, expected)}"
            )
        checks += 1

        # CHECK 1 (D31 row 2) -- the independent DECODER renders to the same
        # sidecar.
        try:
            theirs = render_loaded(cbor2.loads(raw))
        except CheckFailure:
            raise
        except Exception as exc:  # a library rejection is a disagreement
            raise CheckFailure(
                f"case {name!r} layer {layer!r}: cbor2 could not decode: {exc}"
            ) from exc
        if theirs != expected:
            raise CheckFailure(
                f"case {name!r} layer {layer!r}: cbor2's decode disagrees with the committed "
                f"diagnostic\n  {_diff(theirs, expected)}"
            )
        checks += 1

        # CHECK 2 (D31 row 1) -- re-encode the COMMITTED sidecar with OUR OWN
        # §4.2.1 encoder and compare to the committed bytes.
        rebuilt = encode_canonical(reconstruct(expected, layer))
        if rebuilt != raw:
            raise CheckFailure(
                f"case {name!r} layer {layer!r}: our RFC 8949 §4.2.1 re-encoding of the "
                f"committed diagnostic does not reproduce the committed bytes\n"
                f"  ours      {rebuilt.hex()[:160]}\n  committed {raw.hex()[:160]}"
            )
        checks += 1

    envelope_layer, envelope_bytes, key0 = find_envelope(located)

    # CHECK 3 (D31 row 11) -- work_id hashes the EMBEDDED body bytes (F19 §2).
    work_id = hashlib.sha256(key0).hexdigest()
    if work_id != case["work_id"]:
        raise CheckFailure(
            f"case {name!r}: SHA-256 of layer {envelope_layer!r}'s key-0 byte string is "
            f"{work_id}, committed work_id is {case['work_id']}"
        )
    checks += 1

    # CHECK 4 (D31 row 11) -- anchor_digest hashes the whole manifest envelope.
    anchor = hashlib.sha256(envelope_bytes).hexdigest()
    if anchor != case["anchor_digest"]:
        raise CheckFailure(
            f"case {name!r}: SHA-256 of layer {envelope_layer!r} is {anchor}, committed "
            f"anchor_digest is {case['anchor_digest']}"
        )
    checks += 1

    return checks


def _diff(ours: object, theirs: object) -> str:
    a, b = json.dumps(ours), json.dumps(theirs)
    for i, (x, y) in enumerate(zip(a, b)):
        if x != y:
            lo = max(0, i - 60)
            return (
                f"first difference at char {i}:\n    ours      …{a[lo : i + 60]}"
                f"\n    committed …{b[lo : i + 60]}"
            )
    return f"lengths differ: ours {len(a)}, committed {len(b)}"


# ---------------------------------------------------------------------------
# D31 F14 step 5 — the rejection fixtures really are non-canonical.
#
# F15's tamper fixtures assert that OUR decoder rejects them with a specific
# code. That is a claim about our decoder, not about the bytes. Here a second
# implementation judges the same bytes against RFC 8949 §4.2.1 directly, which
# turns "we reject it" into "it is genuinely non-canonical" -- and, just as
# usefully, confirms the schema-level fixtures are *perfectly good CBOR*, so
# they are testing what they claim to test rather than accidentally being
# encoding faults.
# ---------------------------------------------------------------------------

# What each F15 `cbor-` row must look like ON THE WIRE, in this checker's own
# words. Matching the REASON and not merely "something was rejected" is what
# makes the sweep an independent confirmation rather than a coincidence: a
# random salt that happens to start with a float head would satisfy "rejected"
# while saying nothing about the fixture's actual mutation.
CANONICALITY_REASON = {
    "cbor-duplicate-map-key": "duplicated",
    "cbor-non-shortest-int": "non-shortest",
    "cbor-non-shortest-length": "non-shortest",
    "cbor-indefinite-length": "indefinite-length",
    "cbor-trailing-bytes": "trailing",
    "cbor-unsorted-map-keys": "out of order",
    "cbor-float": "major type 7",
}

# Codes whose fixtures are an antseal RESOURCE CAP, not an RFC 8949 property.
# Nesting depth is F11's limit and bundle size is D10's; arbitrarily deep or
# large CBOR is perfectly canonical, so there is nothing here to confirm.
NOT_A_CANONICALITY_CLAIM = {"cbor-nesting-too-deep", "bundle-too-large"}


def _verdicts(cbor2, data: bytes, depth: int = 0) -> list[str]:
    """Our §4.2.1 rejections for these bytes and for each CBOR layer inside.

    Descent is deliberately unguided — the checker has no schema knowledge and
    will happily try a salt or a signature — which is exactly why the caller
    matches on the *reason* rather than on the mere existence of a rejection.
    """
    try:
        strict_render(data)
    except CheckFailure as exc:
        return [str(exc)]  # a structure we cannot walk cannot be descended
    if depth >= 2:
        return []
    found: list[str] = []
    for candidate in _byte_strings(strict_render(data)):
        try:
            cbor2.loads(candidate)  # lenient: is this a CBOR layer at all?
        except Exception:
            continue
        found.extend(_verdicts(cbor2, candidate, depth + 1))
    return found


def tamper_sweep(cbor2, report) -> int:
    """D31 F14 step 5 — the rejection fixtures really are non-canonical.

    Two assertions, and the second matters as much as the first:

    * a `cbor-` fixture must be non-canonical **for the reason it claims**,
      judged by our §4.2.1 logic rather than by our decoder's error code;
    * a schema-level fixture (`manifest-…`, `bundle-…`) must be **perfectly
      good CBOR** at the outer layer, which proves it exercises the schema
      rather than tripping the codec first and never reaching it.
    """
    manifest = TAMPER_FORMAT / "FIXTURES.json"
    if not manifest.is_file():
        report("  --  no testdata/tamper/format/FIXTURES.json; rejection sweep skipped")
        return 0
    catalogue = json.loads(manifest.read_text(encoding="utf-8"))
    if catalogue.get("format_version") != VERSION_DIR.name:
        report(f"  --  tamper fixtures are {catalogue.get('format_version')}; sweep skipped")
        return 0

    confirmed = canonical = skipped = 0
    for fixture in catalogue["fixtures"]:
        code = fixture["expected"]["code"]
        source = fixture["source"]
        if source["kind"] != "file" or code in NOT_A_CANONICALITY_CLAIM:
            skipped += 1
            continue
        data = (TAMPER_FORMAT / source["file"]).read_bytes()

        if code.startswith("cbor-"):
            wanted = CANONICALITY_REASON.get(code)
            if wanted is None:
                raise CheckFailure(
                    f"tamper fixture {fixture['id']!r} carries the unmapped canonicality code "
                    f"{code}: this sweep must be taught what that looks like on the wire, or it "
                    f"is silently not checking a row"
                )
            verdicts = _verdicts(cbor2, data)
            if not any(wanted in verdict for verdict in verdicts):
                raise CheckFailure(
                    f"tamper fixture {fixture['id']!r} claims {code}, but our own RFC 8949 "
                    f"§4.2.1 logic finds no {wanted!r} fault in it or any layer it embeds "
                    f"(found: {verdicts or 'nothing'}). The fixture is not testing what it claims"
                )
            confirmed += 1
        else:
            try:
                strict_render(data)
            except CheckFailure as exc:
                raise CheckFailure(
                    f"tamper fixture {fixture['id']!r} claims the SCHEMA-level code {code}, but "
                    f"our §4.2.1 logic finds its outer layer non-canonical ({exc}). It would be "
                    f"rejected by the codec before the schema layer ever saw it"
                ) from exc
            canonical += 1

    report(
        f"  OK  tamper/format: {confirmed} fixture(s) independently confirmed non-canonical for "
        f"the claimed reason, {canonical} confirmed canonical-but-schema-invalid, "
        f"{skipped} out of scope"
    )
    return confirmed + canonical


# ---------------------------------------------------------------------------
# The run.
# ---------------------------------------------------------------------------


def run(cbor2, report) -> tuple[int, int, int, int]:
    """Check everything. Returns ``(files, checked, cases, checks)``."""
    checks = preflight(cbor2, report)
    checks += rfc_8949_anchor(cbor2, report)
    files = checked = cases = 0

    for path in discover():
        files += 1
        try:
            vector = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise CheckFailure(f"{path}: unreadable vector file: {exc}") from exc
        if vector.get("schema") != "antseal-golden-vector":
            raise CheckFailure(
                f"{path}: not a golden-vector envelope (schema={vector.get('schema')!r})"
            )

        # A vector is in scope exactly when it commits a diagnostic sidecar.
        # Driving on the sidecar rather than on a kind allow-list means any
        # future CBOR-committing kind is covered the day it lands *provided it
        # commits a sidecar*.
        #
        # KNOWN LIMITATION, stated rather than hidden: a kind that commits
        # format CBOR and NO sidecar is silently out of scope, and this line
        # cannot tell that apart from a kind that commits no CBOR at all. The
        # honest fix is a registry-level flag on the kind, which is a
        # `KNOWN_KINDS` change and not this file's to make -- see
        # docs/testing/cbor-cross-check.md §8.
        subject = [c for c in vector.get("expect", {}).get("cases", []) if "diagnostic" in c]
        if not subject:
            report(
                f"  --  {_rel(path)}: kind {vector['kind']!r}, no diagnostic sidecar "
                f"(out of scope for the CBOR cross-check)"
            )
            continue

        checked += 1
        here = 0
        for case in subject:
            try:
                here += check_case(cbor2, case)
            except CheckFailure as exc:
                raise CheckFailure(f"{_rel(path)} [{vector['kind']}]: {exc}") from exc
        cases += len(subject)
        checks += here
        report(f"  OK  {_rel(path)}: kind {vector['kind']!r}, {len(subject)} case(s), {here} checks")

    if checked == 0:
        raise CheckFailure(
            "zero vectors carrying a diagnostic sidecar were discovered -- the cross-check "
            "would pass vacuously. Discovery is broken, or the format vectors are gone"
        )

    checks += tamper_sweep(cbor2, report)
    return files, checked, cases, checks


def _rel(path: pathlib.Path) -> str:
    return path.relative_to(REPO_ROOT).as_posix()


# ---------------------------------------------------------------------------
# Self-test: a cross-check that has never failed is not evidence of anything.
# ---------------------------------------------------------------------------


def self_test(cbor2, report) -> int:
    """Mutate a real committed case in memory; require each mutation to be caught."""
    path = next(
        p
        for p in discover()
        if any(
            "diagnostic" in c
            for c in json.loads(p.read_text(encoding="utf-8")).get("expect", {}).get("cases", [])
        )
    )
    vector = json.loads(path.read_text(encoding="utf-8"))
    case = next(c for c in vector["expect"]["cases"] if "diagnostic" in c)
    field = next(k for k in case if k.endswith("_bytes"))
    raw = bytes.fromhex(case[field])

    def mutated(fn) -> dict:
        clone = json.loads(json.dumps(case))
        fn(clone)
        return clone

    def flip_a_byte(c):
        b = bytearray(bytes.fromhex(c[field]))
        b[len(b) // 2] ^= 0x01
        c[field] = bytes(b).hex()

    def reorder_a_map(c):
        # F19 accept: a sidecar whose entries are CORRECT but REORDERED must
        # fail. This is the mutation a set comparison would wave through.
        for item in c["diagnostic"].values():
            if isinstance(item, dict) and len(item.get("m", [])) >= 2:
                item["m"][0], item["m"][1] = item["m"][1], item["m"][0]
                return
        raise CheckFailure("self-test: no multi-entry map to reorder")

    def non_shortest_int(c):
        # Rewrite the outermost head to a wider, non-shortest form -- the class
        # a decoded object can no longer see (F15 row `cbor-non-shortest-*`,
        # and D31's named self-test).
        b = bytearray(bytes.fromhex(c[field]))
        major, ai = b[0] >> 5, b[0] & 0x1F
        b[0:1] = bytes([(major << 5) | 24, ai])
        c[field] = bytes(b).hex()

    def truncate(c):
        c[field] = bytes.fromhex(c[field])[:-1].hex()

    def corrupt_work_id(c):
        c["work_id"] = ("0" if c["work_id"][0] != "0" else "1") + c["work_id"][1:]

    def corrupt_anchor_digest(c):
        c["anchor_digest"] = ("0" if c["anchor_digest"][0] != "0" else "1") + c["anchor_digest"][1:]

    def drop_a_layer(c):
        c["diagnostic"].pop(sorted(c["diagnostic"])[0])

    mutations = [
        ("one flipped byte in the committed bytes", flip_a_byte),
        ("map entries correct but REORDERED", reorder_a_map),
        ("non-shortest integer head (non-canonical)", non_shortest_int),
        ("truncated bytes", truncate),
        ("wrong work_id", corrupt_work_id),
        ("wrong anchor_digest", corrupt_anchor_digest),
        ("a diagnostic layer removed", drop_a_layer),
    ]

    report(f"self-test against {_rel(path)} case {case['name']!r} ({len(raw)} bytes):")
    for label, fn in mutations:
        try:
            check_case(cbor2, mutated(fn))
        except CheckFailure as exc:
            report(f"  RED as required  {label}\n                   -> {str(exc).splitlines()[0][:140]}")
        else:
            raise CheckFailure(f"self-test FAILED: the checker accepted a vector with {label}")

    # The T0 oracle must be fallible too. Plant a wrong RFC expectation and
    # require it to be caught: an anchor that would pass whatever our encoder
    # emitted is decorative, and decorative evidence is worse than none.
    planted = [(24, "1819")]  # the RFC says 1818; 1819 is the encoding of 25
    try:
        rfc_8949_anchor(cbor2, lambda _message: None, planted)
    except CheckFailure:
        report("  RED as required  a wrong RFC 8949 Appendix A expectation")
    else:
        raise CheckFailure("self-test FAILED: the T0 anchor accepted a wrong RFC expectation")

    # And the honest control: unmutated, the same case passes.
    check_case(cbor2, case)
    report("  GREEN unmutated  the same case passes untouched")
    return len(mutations) + 2


# ---------------------------------------------------------------------------
# Provisioning cbor2 ==6.1.3 without pip (CI uses pip; not every dev box has
# one). The ONLY step that touches the network.
# ---------------------------------------------------------------------------


def read_bootstrap_table() -> dict[str, tuple[str, str]]:
    """The ``# boot`` rows of requirements-crosscheck.txt (pip ignores them)."""
    files: dict[str, tuple[str, str]] = {}
    for line in REQUIREMENTS.read_text(encoding="utf-8").splitlines():
        parts = line.split()
        if len(parts) == 5 and parts[0] == "#" and parts[1] == "boot":
            _, _, sha, blake, name = parts
            files[name] = (sha, blake)
    if not files:
        raise CheckFailure(f"{REQUIREMENTS} carries no `# boot` rows for the pip-less bootstrap")
    return files


def wheel_candidates() -> list[str]:
    """Wheel filenames this interpreter can load, most-preferred first."""
    tag = f"cp{sys.version_info.major}{sys.version_info.minor}"
    gil = getattr(sys, "_is_gil_enabled", None)
    abis = [f"{tag}-{tag}t"] if (gil is not None and not gil()) else [f"{tag}-{tag}"]
    machine = os.uname().machine if hasattr(os, "uname") else ""
    if sys.platform.startswith("linux"):
        plats = (
            [f"manylinux_2_28_{machine}", f"musllinux_1_2_{machine}"]
            if machine in ("x86_64", "aarch64")
            else []
        )
    elif sys.platform == "darwin":
        plats = ["macosx_11_0_arm64"] if machine == "arm64" else []
    elif sys.platform == "win32":
        plats = ["win_amd64", "win32"]
    else:
        plats = []
    return [f"cbor2-{CBOR2_VERSION}-{abi}-{plat}.whl" for abi in abis for plat in plats]


def setup(home: pathlib.Path, report) -> int:
    """Fetch, verify and unpack the pinned wheel into ``home``.

    cbor2 6.x is a compiled Rust/PyO3 extension with **no pure-Python
    fallback**, so a source install would need a Rust toolchain, Python dev
    headers and a network cargo fetch. A wheel needs none of them -- and a
    wheel is a zip, so this needs no `pip`, no `ensurepip` and no root.
    """
    files = read_bootstrap_table()
    for name in wheel_candidates():
        if name in files:
            break
    else:
        raise CheckFailure(
            f"no wheel in {REQUIREMENTS.name} matches this interpreter "
            f"(tried {wheel_candidates()})"
        )
    sha, blake = files[name]
    url = f"https://files.pythonhosted.org/packages/{blake[:2]}/{blake[2:4]}/{blake[4:]}/{name}"

    report(f"fetching {name}")
    data = urllib.request.urlopen(url, timeout=120).read()  # noqa: S310 -- pinned https URL
    got = hashlib.sha256(data).hexdigest()
    if got != sha:
        raise CheckFailure(f"{name}: SHA-256 {got} does not match the pin's {sha}")
    report(f"  sha256 {got} matches {REQUIREMENTS.name}")

    home.mkdir(parents=True, exist_ok=True)
    archive = home / name
    archive.write_bytes(data)
    with zipfile.ZipFile(archive) as zf:
        zf.extractall(home)
    archive.unlink()
    (home / "PROVENANCE.txt").write_text(
        f"cbor2 {CBOR2_VERSION}\nwheel  {name}\nsha256 {sha}\nurl    {url}\n"
        f"pinned by {REQUIREMENTS.relative_to(REPO_ROOT).as_posix()} (decisions D12, D31)\n",
        encoding="utf-8",
    )
    report(f"  unpacked into {home}")
    return 0


def _default_home() -> pathlib.Path:
    cache = os.environ.get("XDG_CACHE_HOME") or os.path.join(os.path.expanduser("~"), ".cache")
    return pathlib.Path(cache) / "antseal" / f"cbor2-{CBOR2_VERSION}"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true", help="run the cross-check (the default)")
    parser.add_argument("--setup", action="store_true", help="fetch the pinned wheel (network)")
    parser.add_argument("--self-test", action="store_true", help="prove the checker can go red")
    parser.add_argument(
        "--require",
        action="store_true",
        help="treat a missing cbor2 as a failure rather than as UNAVAILABLE",
    )
    parser.add_argument("--home", default=os.environ.get("ANTSEAL_CBOR2_HOME", ""))
    args = parser.parse_args()

    def report(message: str) -> None:
        print(message, flush=True)

    home = pathlib.Path(args.home) if args.home else _default_home()

    try:
        if args.setup:
            return setup(home, report)

        if home.is_dir() and str(home) not in sys.path:
            sys.path.insert(0, str(home))
        try:
            import cbor2  # noqa: PLC0415 -- deliberately lazy: --setup runs without it
        except ImportError as exc:
            message = (
                f"cbor2 =={CBOR2_VERSION} is not provisioned ({exc}).\n"
                f"  CI:    pip install --require-hashes -r requirements-crosscheck.txt\n"
                f"  Local: scripts/cross-check.sh --setup   (no pip needed)\n"
                f"  Home:  {home}"
            )
            if args.require:
                print(f"FAIL  {message}", file=sys.stderr)
                return 1
            print(f"UNAVAILABLE  {message}", file=sys.stderr)
            return 2

        if args.self_test:
            count = self_test(cbor2, report)
            report(
                f"\nself-test PASSED: {count} scenarios — 8 planted faults caught "
                f"(7 vector mutations + a wrong RFC expectation), 1 control green"
            )
            return 0

        files, checked, cases, checks = run(cbor2, report)
        report(
            f"\ncross-check PASSED: {checks} checks over {cases} case(s) in {checked} "
            f"CBOR-committing vector(s) of {files} committed {VERSION_DIR.name} vector file(s)"
        )
        return 0
    except CheckFailure as exc:
        print(f"\nCROSS-CHECK FAILED\n  {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
