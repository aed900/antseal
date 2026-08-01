#!/usr/bin/env python3
"""Regenerate storage-address.json — antseal storage-address golden vectors
(tasks/S.md S4; decisions D32/D35).

Independent reference implementation: BLAKE3 (hash mode, 32-byte output)
built from the Python stdlib alone, written directly from the BLAKE3
specification (https://github.com/BLAKE3-team/BLAKE3-specs) — no Rust code
path shared. Under D32 a blob is exactly one Autonomi chunk and its storage
address is BLAKE3-256 of the blob bytes (`compute_address`,
ant-protocol-2.3.0/src/data_types.rs:10-12), so these vectors double as a
cross-implementation check of `antseal_core::storage::compute_storage_address`
(D31 tier T1: two independently written implementations agreeing on committed
bytes).

Anchoring (what makes this implementation trustworthy):

- the length-0 case IS the first entry of the official BLAKE3 test-vector
  suite (BLAKE3-team test_vectors.json), embedded below as a self-test that
  runs before anything else — a broken compression function cannot reproduce
  it;
- every input is the official test-vector input pattern `byte[i] = i % 251`,
  so any future reader can validate any case against the official suite or
  any third-party BLAKE3 tool;
- the Rust side (`blake3 = "=1.8.5"`, workspace-pinned per D35) was verified
  against the complete official suite at P15 (workspace Cargo.toml, blake3
  pin comment). Agreement between THAT implementation and THIS one over the
  committed cases is the cross-check.

ALL INPUTS ARE NON-SECRET, FIXED TEST FIXTURES (project rule 6): storage
addresses are computed over AEAD ciphertext in production; these public
pattern bytes stand in for ciphertext of the same lengths. No key material
is involved anywhere.

The size ladder (S4 accept; D32 decision 3 for the arithmetic):

    0          empty input (official BLAKE3 vector anchor)
    272        smallest padded-unit ciphertext (256-byte bucket + 16 tag)
    65 552     mid rung (65 536-byte padded plaintext + 16 tag; 65 chunks,
               so the BLAKE3 tree layer is exercised)
    4 194 047  maximum unit PLAINTEXT under D32 (4 MiB − 257)
    4 194 064  maximum plaintext-derived CIPHERTEXT (16 383·256 + 16)
    4 194 304  MAX_CHUNK_SIZE exactly (ant-protocol chunk.rs:19) — accepted
    4 194 305  cap + 1 — COMMITTED REJECTION: no v1 address exists (D32);
               the expected outcome is the typed error, not a hash, so no
               digest is recorded for it (and none is computed here).

Committed vectors are retained forever (dependency-policy/Q6): a byte change
here is a format event, never a silent regeneration. Run only to *verify*:

    python3 gen_vectors.py --check

`--check` is the uniform entry point every reference generator carries (D31
section 6a): it re-derives, diffs against the committed bytes, prints a
per-file verdict, and exits non-zero on any difference. It is the only thing
`scripts/cross-check.sh` calls. Bare (no `--check`) still writes the document
to stdout, so the historical regeneration recipe keeps working.

The tiny `check_committed` helper below is duplicated verbatim in the sibling
generators rather than shared through a common module. That is deliberate:
this file is an *independent* cross-check vehicle (D31 tier T1), and a shared
helper would be shared code between the vehicles it is meant to keep apart.
"""

import argparse
import difflib
import json
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent

# ---------------------------------------------------------------------------
# BLAKE3, hash mode, 32-byte output — written from the specification.
# ---------------------------------------------------------------------------

IV = (
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
)
MSG_PERMUTATION = (2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8)
CHUNK_LEN = 1024
BLOCK_LEN = 64
CHUNK_START = 1
CHUNK_END = 2
PARENT = 4
ROOT = 8
MASK32 = 0xFFFFFFFF


def _compress(cv, block_words, counter, block_len, flags):
    """One BLAKE3 compression; returns the first 8 output words (the
    chaining value / root output words we need — extended output is never
    used for a 32-byte hash)."""
    v = [
        cv[0], cv[1], cv[2], cv[3], cv[4], cv[5], cv[6], cv[7],
        IV[0], IV[1], IV[2], IV[3],
        counter & MASK32, (counter >> 32) & MASK32, block_len, flags,
    ]
    m = list(block_words)
    for round_index in range(7):
        if round_index != 0:
            m = [m[MSG_PERMUTATION[i]] for i in range(16)]
        # Columns then diagonals; g() inlined for CPython speed.
        for (a, b, c, d, x, y) in (
            (0, 4, 8, 12, m[0], m[1]),
            (1, 5, 9, 13, m[2], m[3]),
            (2, 6, 10, 14, m[4], m[5]),
            (3, 7, 11, 15, m[6], m[7]),
            (0, 5, 10, 15, m[8], m[9]),
            (1, 6, 11, 12, m[10], m[11]),
            (2, 7, 8, 13, m[12], m[13]),
            (3, 4, 9, 14, m[14], m[15]),
        ):
            va = (v[a] + v[b] + x) & MASK32
            vd = v[d] ^ va
            vd = ((vd >> 16) | (vd << 16)) & MASK32
            vc = (v[c] + vd) & MASK32
            vb = v[b] ^ vc
            vb = ((vb >> 12) | (vb << 20)) & MASK32
            va = (va + vb + y) & MASK32
            vd = vd ^ va
            vd = ((vd >> 8) | (vd << 24)) & MASK32
            vc = (vc + vd) & MASK32
            vb = vb ^ vc
            vb = ((vb >> 7) | (vb << 25)) & MASK32
            v[a], v[b], v[c], v[d] = va, vb, vc, vd
    return [v[i] ^ v[i + 8] for i in range(8)]


def _block_words(block):
    padded = block + b"\x00" * (BLOCK_LEN - len(block))
    return [int.from_bytes(padded[i : i + 4], "little") for i in range(0, BLOCK_LEN, 4)]


def _chunk_cv(chunk, chunk_counter, root):
    """Chaining value of one ≤1024-byte chunk (`root` only for a
    single-chunk input)."""
    blocks = [chunk[i : i + BLOCK_LEN] for i in range(0, len(chunk), BLOCK_LEN)] or [b""]
    cv = IV
    last = len(blocks) - 1
    for i, block in enumerate(blocks):
        flags = (CHUNK_START if i == 0 else 0) | (CHUNK_END if i == last else 0)
        if root and i == last:
            flags |= ROOT
        cv = _compress(cv, _block_words(block), chunk_counter, len(block), flags)
    return cv


def _subtree_cv(data, chunk_counter, root):
    """Chaining value of the subtree over `data` whose first chunk has index
    `chunk_counter`. Left subtree takes the largest power-of-two chunk count
    strictly below the total (the BLAKE3 tree shape rule)."""
    if len(data) <= CHUNK_LEN:
        return _chunk_cv(data, chunk_counter, root)
    chunks = (len(data) + CHUNK_LEN - 1) // CHUNK_LEN
    left_chunks = 1 << ((chunks - 1).bit_length() - 1)
    split = left_chunks * CHUNK_LEN
    left = _subtree_cv(data[:split], chunk_counter, False)
    right = _subtree_cv(data[split:], chunk_counter + left_chunks, False)
    flags = PARENT | (ROOT if root else 0)
    return _compress(IV, left + right, 0, BLOCK_LEN, flags)


def blake3_hash(data: bytes) -> bytes:
    """BLAKE3 (hash mode) of `data`, 32 bytes."""
    words = _subtree_cv(data, 0, True)
    return b"".join(w.to_bytes(4, "little") for w in words)


# The first entry of the official BLAKE3 test-vector suite (BLAKE3-team
# test_vectors.json: input length 0, hash output truncated to 32 bytes).
OFFICIAL_EMPTY_HASH = "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"


def self_test():
    """Known-answer + structural self-tests; a failure here means the
    reference implementation itself is broken and nothing downstream can be
    trusted."""
    got = blake3_hash(b"").hex()
    if got != OFFICIAL_EMPTY_HASH:
        raise SystemExit(
            "self-test FAILED: BLAKE3(\"\") = "
            f"{got}, official vector says {OFFICIAL_EMPTY_HASH}"
        )
    # Structural: block boundary (64/65) and chunk boundary (1024/1025)
    # inputs must all hash distinctly, and repeated calls must agree.
    seen = set()
    for n in (0, 1, 63, 64, 65, 1023, 1024, 1025, 2048, 2049):
        data = pattern(n)
        first = blake3_hash(data)
        if blake3_hash(data) != first:
            raise SystemExit(f"self-test FAILED: nondeterminism at length {n}")
        if first in seen:
            raise SystemExit(f"self-test FAILED: collision at length {n}")
        seen.add(first)


# ---------------------------------------------------------------------------
# The committed document.
# ---------------------------------------------------------------------------

MAX_CHUNK_SIZE = 4_194_304  # ant-protocol-2.3.0/src/chunk.rs:19 (D32 row 3)

# (name, length) — the S4 ladder; lengths over MAX_CHUNK_SIZE are committed
# REJECTION cases (typed error, no address exists in v1 — D32 decision 5).
CASES = (
    ("empty-0", 0),
    ("smallest-unit-ciphertext-272", 272),
    ("mid-64k-ciphertext-65552", 65_552),
    ("max-unit-plaintext-4194047", 4_194_047),
    ("max-unit-ciphertext-4194064", 4_194_064),
    ("cap-edge-4194304", MAX_CHUNK_SIZE),
    ("over-cap-4194305", MAX_CHUNK_SIZE + 1),
)


def pattern(length: int) -> bytes:
    """The official BLAKE3 test-vector input pattern: byte[i] = i % 251."""
    period = bytes(i % 251 for i in range(251))
    whole, rest = divmod(length, 251)
    return period * whole + period[:rest]


def build_document() -> dict:
    input_cases = [{"name": name, "len": length} for (name, length) in CASES]
    expect_cases = []
    for name, length in CASES:
        if length > MAX_CHUNK_SIZE:
            expect_cases.append(
                {"name": name, "len": length, "rejected": "exceeds-chunk-cap"}
            )
        else:
            expect_cases.append(
                {"name": name, "len": length, "address": blake3_hash(pattern(length)).hex()}
            )
    return {
        "schema": "antseal-golden-vector",
        "schema_version": 1,
        "format_version": "v1",
        "kind": "storage-address",
        "non_secret": (
            "NON-SECRET public fixture bytes: every input is the official BLAKE3 "
            "test-vector pattern byte[i] = i % 251 at the stated length, standing in "
            "for AEAD ciphertext of the same length. No secret material is involved "
            "and nothing derives from the fixed test seed W (addresses hash public "
            "ciphertext, never secrets)."
        ),
        "description": (
            "D32 storage-address rule (S4): address = BLAKE3-256 of the blob bytes, "
            "over the size ladder 0 / 272 (smallest padded-unit ciphertext) / 65552 "
            "(mid) / 4194047 (max unit plaintext) / 4194064 (max plaintext-derived "
            "ciphertext) / 4194304 (MAX_CHUNK_SIZE, cap edge) — plus the committed "
            "cap+1 REJECTION case: over-cap input has no v1 address (typed error)."
        ),
        "inputs": {"pattern": "i-mod-251", "cases": input_cases},
        "expect": {"max_chunk_size": MAX_CHUNK_SIZE, "cases": expect_cases},
    }


def render(document: dict) -> str:
    return json.dumps(document, indent=2, ensure_ascii=False) + "\n"


def check_committed(rendered: str, committed_path: pathlib.Path) -> int:
    """Diff freshly derived output against the committed file (D31 §6a)."""
    name = committed_path.name
    if not committed_path.exists():
        print(f"MISSING   {name}: no committed file to check against")
        return 1
    committed = committed_path.read_text(encoding="utf-8")
    if committed == rendered:
        print(f"OK        {name}: committed bytes match a fresh derivation")
        return 0
    print(f"MISMATCH  {name}: committed file differs from fresh derivation")
    diff = difflib.unified_diff(
        committed.splitlines(keepends=True),
        rendered.splitlines(keepends=True),
        fromfile=f"committed/{name}",
        tofile="derived",
    )
    sys.stdout.writelines(list(diff)[:40])
    return 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="re-derive and diff against the committed vector file (exit 1 on drift)",
    )
    args = parser.parse_args()

    self_test()
    rendered = render(build_document())
    if args.check:
        return check_committed(rendered, HERE / "storage-address.json")
    sys.stdout.write(rendered)
    return 0


if __name__ == "__main__":
    sys.exit(main())
