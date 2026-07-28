#!/usr/bin/env python3
"""Regenerate hkdf-labels.json — antseal HKDF golden vectors (tasks/C.md C3).

Independent reference implementation: RFC 5869 HKDF-SHA256 built from Python
stdlib hmac/hashlib only (no Rust code path shared), so the committed vectors
double as a cross-implementation check of antseal-core's derivation
(MVP-SPEC.md line 77; the full independent cross-check mandate is C16).

ALL INPUTS ARE NON-SECRET, FIXED TEST FIXTURES (project rule 6): the test W
is the documented fixed test seed 00 01 02 .. 1f (testdata/README.md) and
must never be a real secret.

The output is a Q4 golden-vector file (envelope schema documented in
testdata/vectors/README.md), discovered and executed by the native runner
`crates/antseal-core/tests/vector_runner.rs`.

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

History: this file emitted the line-format `hkdf-sha256-v1.txt` until Q2/Q4
migrated the vectors into the envelope schema (pre-Q6, so the move was safe);
the derivation values (info/okm hex) are unchanged, only the container format
changed.
"""

import argparse
import difflib
import hashlib
import hmac
import json
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent

# NON-SECRET fixture master secret W = the documented fixed test seed
# (32 bytes, 0x00..0x1f; testdata/README.md "Secret-material convention").
W = bytes(range(32))
SENTINEL = 0xFFFF_FFFF_FFFF_FFFF

# The frozen label registry (MVP-SPEC.md lines 91, 94-98):
# (label, output length, id domain, vector id).
# Vector ids exercise LE64 visibly: 0, 1, a distinctive 8-byte value, and the
# sentinel for the no-natural-id labels.
REGISTRY = [
    ("unit-key", 32, "unit_id", 0x0),
    ("unit-salt", 16, "unit_id", 0x1),
    ("path-salt", 16, "file_id", 0x0),
    ("file-salt", 16, "file_id", 0x1),
    ("fine-seed", 32, "file_id", 0x0123456789ABCDEF),
    ("sig-ed25519", 32, "sentinel", SENTINEL),
    ("sig-mldsa65", 32, "sentinel", SENTINEL),
    ("manifest-key", 32, "sentinel", SENTINEL),
]


def info_bytes(label: str, ident: int) -> bytes:
    """info = u8(len(label)) || label || LE64(id)  (MVP-SPEC.md line 77)."""
    encoded = label.encode("ascii")
    assert 0 < len(encoded) <= 255
    return bytes([len(encoded)]) + encoded + ident.to_bytes(8, "little")


def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    """RFC 5869 HKDF-SHA256 from raw HMAC (extract, then expand)."""
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    okm = b""
    block = b""
    counter = 1
    while len(okm) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        okm += block
        counter += 1
    return okm[:length]


def check_committed(path: pathlib.Path, produced: str) -> int:
    """Diff freshly derived bytes against a committed vector file (D31 6a).

    Returns 0 on byte equality, 1 otherwise, and prints a bounded unified diff
    so a disagreement is legible without a second command.
    """
    name = path.name
    if not path.exists():
        print(f"FAIL  {name}: committed vector is missing", file=sys.stderr)
        return 1
    committed = path.read_text(encoding="utf-8")
    if committed == produced:
        print(f"OK    {name}")
        return 0
    print(
        f"FAIL  {name}: re-derived bytes differ from the committed vector. "
        "This is a format event or a real disagreement — never regenerate to "
        "make it agree (D31 section 11 item 5).",
        file=sys.stderr,
    )
    diff = difflib.unified_diff(
        committed.splitlines(),
        produced.splitlines(),
        fromfile=f"committed/{name}",
        tofile=f"rederived/{name}",
        lineterm="",
        n=2,
    )
    for line in list(diff)[:60]:
        print(f"  {line}", file=sys.stderr)
    return 1


def build_document() -> dict:
    vectors = []
    for label, out_len, domain, ident in REGISTRY:
        info = info_bytes(label, ident)
        okm = hkdf_sha256(W, b"", info, out_len)
        vectors.append(
            {
                "label": label,
                "id": f"0x{ident:016x}",
                "id_domain": domain,
                "info": info.hex(),
                "okm": okm.hex(),
            }
        )
    return {
        "schema": "antseal-golden-vector",
        "schema_version": 1,
        "format_version": "v1",
        "kind": "hkdf-labels",
        "non_secret": (
            "NON-SECRET test fixture (project rule 6): the master secret W is "
            "the documented fixed test seed, bytes 0x00..0x1f "
            "(testdata/README.md); never real vault or wallet material."
        ),
        "description": (
            "HKDF-SHA256 label-registry golden vectors (C3): "
            "HKDF-SHA256(W, label, id) with salt = empty, IKM = W, "
            "info = u8(len(label)) || label || LE64(id) (MVP-SPEC.md line 77); "
            "one vector per registered label; sentinel id = 0xffffffffffffffff."
        ),
        "inputs": {"w": W.hex()},
        "expect": {"vectors": vectors},
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Regenerate or verify the C3 HKDF label-registry golden vectors."
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="re-derive and byte-compare the committed vector instead of writing it",
    )
    args = parser.parse_args()

    produced = json.dumps(build_document(), indent=2) + "\n"
    if args.check:
        return check_committed(HERE / "hkdf-labels.json", produced)
    sys.stdout.write(produced)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
