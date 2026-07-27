#!/usr/bin/env python3
"""Regenerate hkdf-sha256-v1.txt — antseal HKDF golden vectors (tasks/C.md C3).

Independent reference implementation: RFC 5869 HKDF-SHA256 built from Python
stdlib hmac/hashlib only (no Rust code path shared), so the committed vectors
double as a cross-implementation check of antseal-core's derivation
(MVP-SPEC.md line 77; the full independent cross-check mandate is C16).

ALL INPUTS ARE NON-SECRET, FIXED TEST FIXTURES (project rule 6): the test W
is the public byte pattern 00 01 02 .. 1f and must never be a real secret.

Committed vectors are retained forever (dependency-policy/Q6): a byte change
here is a format event, never a silent regeneration. Run only to *verify*:

    python3 gen_vectors.py > /tmp/check.txt && diff /tmp/check.txt hkdf-sha256-v1.txt
"""

import hashlib
import hmac

# NON-SECRET fixture master secret W (32 bytes, 0x00..0x1f).
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
    print("# antseal golden vectors: HKDF-SHA256 label registry (v1)")
    print("#")
    print("# NON-SECRET FIXTURE - the master secret W below is a fixed public")
    print("# test pattern (bytes 0x00..0x1f), never a real secret (project rule 6).")
    print("#")
    print("# Construction (MVP-SPEC.md line 77):")
    print("#   HKDF-SHA256(W, label, id): salt = empty, IKM = W,")
    print("#   info = u8(len(label)) || label || LE64(id)")
    print("# Sentinel id (no-natural-id labels) = 0xffffffffffffffff.")
    print("#")
    print("# Format: '<key> = <value>' header lines, then one 'vector' line per")
    print("# registry entry with whitespace-separated key=value fields; hex is")
    print("# lowercase, ids are 0x-prefixed 16-digit hex (LE64 of the value).")
    print("# Regeneration (verify-only; committed bytes are frozen):")
    print("#   see gen_vectors.py in this directory.")
    print()
    print(f"w = {W.hex()}")
    print()
    for label, out_len, domain, ident in REGISTRY:
        info = info_bytes(label, ident)
        okm = hkdf_sha256(W, b"", info, out_len)
        print(
            f"vector label={label} id=0x{ident:016x} id_domain={domain} "
            f"info={info.hex()} okm={okm.hex()}"
        )


if __name__ == "__main__":
    main()
