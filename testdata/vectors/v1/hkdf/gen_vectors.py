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

    python3 gen_vectors.py > /tmp/check.json && diff /tmp/check.json hkdf-labels.json

History: this file emitted the line-format `hkdf-sha256-v1.txt` until Q2/Q4
migrated the vectors into the envelope schema (pre-Q6, so the move was safe);
the derivation values (info/okm hex) are unchanged, only the container format
changed.
"""

import hashlib
import hmac
import json

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


def main() -> None:
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
    document = {
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
    print(json.dumps(document, indent=2))


if __name__ == "__main__":
    main()
