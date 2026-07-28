#!/usr/bin/env python3
"""Regenerate the antseal crypto golden vectors (tasks/C.md C16).

Emits the Q4 golden-vector files in this directory from the **independent**
reference implementations in `reference.py` (Python standard library only,
every primitive validated against its published RFC/draft known answers — run
`python3 reference.py`). No code is shared with the Rust path, so a green
`cargo test -p antseal-core vector_` run *is* cross-implementation agreement.

ALL INPUTS ARE NON-SECRET, FIXED TEST FIXTURES (project rule 6): the master
secret W is the documented fixed test seed 00 01 02 .. 1f
(testdata/README.md, "Secret-material convention"); every derived salt, key
and seed below is a deterministic function of it. Never a real secret.

Committed vectors are retained forever (docs/dependency-policy.md section 4;
Q6 freezes them): a byte change here is a **format event**, justified
explicitly, never a silent regeneration. Run only to *verify*:

    python3 gen_vectors.py --check      # all four files, one verdict each

`--check` is the uniform entry point every reference generator carries (D31
section 6a): it re-derives, diffs against the committed bytes, prints a
per-file verdict, and exits non-zero on any difference. It is the only thing
`scripts/cross-check.sh` calls. The per-kind stdout mode still works:

    python3 gen_vectors.py commitments  | diff - commitments.json
    python3 gen_vectors.py unit-aead    | diff - unit-aead.json
    python3 gen_vectors.py manifest-aead| diff - manifest-aead.json
    python3 gen_vectors.py signatures --mldsa mldsa65-fips204.json \
                                        | diff - signatures.json

`--check` covers `signatures.json` too, with one honestly-stated hole: the
`expect.mldsa65.public_key` and `expect.mldsa65.signature` fields cannot be
re-derived here (no Python ML-DSA), so `--check` reads those two values back
from the committed file and re-derives everything else — including
`expect.mldsa65.seed`, which is HKDF and *is* checked. Those two fields are
covered instead by `crates/antseal-core/tests/acvp_ml_dsa.rs` against NIST
ACVP (D31 rows 12/13, tier T0), which is a strictly stronger vehicle than
anything this file could offer. `--check` prints that scope so the coverage
is never silently overread.

The tiny `check_committed` helper below is duplicated verbatim in the sibling
generators rather than shared through a common module. That is deliberate:
this file is an *independent* cross-check vehicle (D31 tier T1), and a shared
helper would be shared code between the vehicles it is meant to keep apart.

The ML-DSA-65 half of `signatures.json` cannot be produced here — there is no
Python ML-DSA implementation in this toolchain. Its independent vehicle is the
`fips204` crate (a separate implementation from the consumed `ml-dsa`), driven
by `probes/sig-probe/tests/c16_mldsa_vector.rs`; see this directory's README.
"""

import argparse
import difflib
import hashlib
import json
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent

# The Q4 runner treats every non-`.json`/non-auxiliary file under
# `testdata/vectors/` as an unclassifiable file and fails loudly — which
# includes a `__pycache__/` directory dropped by the import below. Disable
# bytecode caching before importing so running the generator never leaves
# the vector tree in a state that fails the runner.
sys.dont_write_bytecode = True

import reference as ref  # noqa: E402  (must follow the dont_write_bytecode set)

# NON-SECRET fixture master secret W = the documented fixed test seed
# (32 bytes, 0x00..0x1f; testdata/README.md).
W = bytes(range(32))

# NON-SECRET fixture seal_id (16 bytes; MVP-SPEC.md line 90). A visible
# counting pattern so the AAD layout `seal_id || LE64(unit_id)` is readable
# by eye in the committed hex.
SEAL_ID = bytes.fromhex("a0a1a2a3a4a5a6a7a8a9aaabacadaeaf")

# The frozen signature context (MVP-SPEC.md line 97).
SIG_CONTEXT = b"antseal-manifest-v1"

NON_SECRET = (
    "NON-SECRET test fixture (project rule 6): the master secret W is the "
    "documented fixed test seed, bytes 0x00..0x1f (testdata/README.md); "
    "every key, salt and seed here derives from it. Never real vault or "
    "wallet material."
)


def envelope(kind: str, description: str, inputs: dict, expect: dict) -> dict:
    """Wrap a payload in the Q4 envelope (testdata/vectors/README.md)."""
    return {
        "schema": "antseal-golden-vector",
        "schema_version": 1,
        "format_version": "v1",
        "kind": kind,
        "non_secret": NON_SECRET,
        "description": description,
        "inputs": inputs,
        "expect": expect,
    }


def fixture_nonce(domain: str, ident: int) -> bytes:
    """A deterministic, documented, NON-SECRET 24-byte fixture nonce.

    Committed vectors must not depend on any RNG (testdata/README.md rule 2:
    "fixtures are deterministic"), and antseal's encrypt APIs deliberately
    draw their nonces internally — so vectors pin the *decrypt* direction
    under a nonce chosen here. XChaCha20-Poly1305 encryption is a
    deterministic function of (key, nonce, aad, plaintext), so a ciphertext
    that authenticates back to the pinned plaintext under the pinned
    (key, nonce, aad) is necessarily the ciphertext byte-for-byte.

    Nonces are public data (the manifest unit table is their authoritative
    home, MVP-SPEC.md line 91) — nothing here is secret.
    """
    seed = b"antseal-c16-fixture-nonce/" + domain.encode() + ref.le64(ident)
    return hashlib.sha256(seed).digest()[:24]


# ---------------------------------------------------------------------------
# kind: commitments (C6 — MVP-SPEC.md lines 79, 93-95)
# ---------------------------------------------------------------------------

# (commitment, domain tag, salt label) — the frozen mapping of
# antseal_core::crypto::commit's module table.
COMMITMENT_SPEC = {
    "unit": (ref.TAG_UNIT_COMMIT, "unit-salt"),
    "raw": (ref.TAG_RAW_COMMIT, "file-salt"),
    "canon": (ref.TAG_CANON_COMMIT, "file-salt"),
    "path": (ref.TAG_PATH_COMMIT, "path-salt"),
}

# (name, commitment kind, id, message bytes). Ids exercise LE64 visibly.
COMMITMENT_CASES = [
    ("unit-empty", "unit", 0x0, b""),
    ("unit-short", "unit", 0x1, b"the unit bytes under commitment"),
    ("unit-trailing-zeros", "unit", 0x0123456789ABCDEF, b"ends in zeros\x00\x00\x00"),
    ("unit-256-bytes", "unit", 0x2, bytes(range(256))),
    ("raw-binary", "raw", 0x0, bytes.fromhex("89504e470d0a1a0a0000000d49484452")),
    ("raw-empty-file", "raw", 0x2A, b""),
    ("canon-text", "canon", 0x0, "first line\nsecond line\n".encode()),
    # Same file_id as canon-text: raw_commit and canon_commit share one
    # file_salt by design (MVP-SPEC.md line 95) — this pair pins that.
    ("raw-text-same-file", "raw", 0x0, "first line\r\nsecond line".encode()),
    ("canon-nfc-text", "canon", 0x2A, "é is NFC-composed to é\n".encode()),
    ("path-ascii", "path", 0x0, b"docs/chapter-one.md"),
    ("path-non-ascii", "path", 0x2A, "notes/été/日記.txt".encode()),
    ("path-empty", "path", 0x7, b""),
]


def gen_commitments() -> dict:
    vectors = []
    for name, kind, ident, message in COMMITMENT_CASES:
        tag, salt_label = COMMITMENT_SPEC[kind]
        salt = ref.derive(W, salt_label, ident)
        assert len(salt) == 16
        vectors.append(
            {
                "name": name,
                "commitment": kind,
                "domain_tag": f"{tag:02x}",
                "salt_label": salt_label,
                "id": f"0x{ident:016x}",
                "salt": salt.hex(),
                "message": message.hex(),
                "digest": ref.tagged_sha256(tag, salt, message).hex(),
            }
        )
    return envelope(
        "commitments",
        "Salted-commitment golden vectors (C16/C6): "
        "commit = SHA-256(domain_tag || salt || message) with the salt derived "
        "as HKDF-SHA256(W, salt_label, id) (MVP-SPEC.md lines 79, 93-95); "
        "all four commitment kinds, empty and non-empty messages, non-ASCII "
        "paths, and a raw/canon pair sharing one file_salt.",
        {"w": W.hex()},
        {"vectors": vectors},
    )


# ---------------------------------------------------------------------------
# kind: unit-aead (C8 + C9 — MVP-SPEC.md line 91)
# ---------------------------------------------------------------------------

# (name, unit_id, unit bytes). Covers the C16-mandated boundary set: the
# empty unit (-> 256-B plaintext), a 256-aligned unit (-> 512), and the
# bucket edges either side of them.
UNIT_AEAD_CASES = [
    ("empty-unit", 0x0, b""),
    ("one-byte", 0x1, b"\x00"),
    ("bucket-edge-255", 0x2, bytes(range(255))),
    ("bucket-aligned-256", 0x3, bytes(range(256))),
    ("bucket-edge-257", 0x4, bytes(range(256)) + b"\xff"),
    ("bucket-edge-511", 0x5, bytes((i * 7) % 256 for i in range(511))),
    ("bucket-aligned-512", 0x6, bytes((i * 7) % 256 for i in range(512))),
    ("trailing-zero-content", 0x7, b"genuine trailing zeros follow\x00\x00\x00\x00"),
    # A large unit_id so LE64(unit_id) is visible in the AAD tail.
    ("large-unit-id", 0x0123456789ABCDEF, b"bound to seal and unit"),
]


def unit_aad(seal_id: bytes, unit_id: int) -> bytes:
    """AAD = seal_id || LE64(unit_id), 24 bytes (MVP-SPEC.md line 91)."""
    return seal_id + ref.le64(unit_id)


def gen_unit_aead() -> dict:
    vectors = []
    for name, unit_id, unit_bytes in UNIT_AEAD_CASES:
        k_u = ref.derive(W, "unit-key", unit_id)
        aad = unit_aad(SEAL_ID, unit_id)
        padded = ref.apply_padding(unit_bytes)
        nonce = fixture_nonce("unit", unit_id)
        ciphertext = ref.xchacha20poly1305_encrypt(k_u, nonce, padded, aad)
        assert len(aad) == 24
        assert len(ciphertext) == len(padded) + 16
        vectors.append(
            {
                "name": name,
                "unit_id": f"0x{unit_id:016x}",
                "true_length": len(unit_bytes),
                "unit_bytes": unit_bytes.hex(),
                "k_u": k_u.hex(),
                "aad": aad.hex(),
                "padded_plaintext": padded.hex(),
                "nonce": nonce.hex(),
                "ciphertext": ciphertext.hex(),
            }
        )
    return envelope(
        "unit-aead",
        "Unit AEAD golden vectors (C16/C8/C9): k_u = HKDF(W, \"unit-key\", "
        "unit_id), XChaCha20-Poly1305 with AAD = seal_id || LE64(unit_id) over "
        "the zero-padded plaintext, padded_length(t) = ceil((t+1)/256)*256 "
        "(MVP-SPEC.md line 91); covers the empty unit (256-B plaintext), the "
        "256-aligned unit (512-B plaintext), both bucket edges, and genuine "
        "trailing-zero content.",
        {"w": W.hex(), "seal_id": SEAL_ID.hex()},
        {"vectors": vectors},
    )


# ---------------------------------------------------------------------------
# kind: manifest-aead (C10 — MVP-SPEC.md line 98)
# ---------------------------------------------------------------------------

# (name, plaintext manifest bytes). The frozen AAD is EMPTY.
MANIFEST_AEAD_CASES = [
    ("manifest-blob", 0, bytes.fromhex("a2005820") + b"manifest body bytes (stand-in)" + bytes.fromhex("01a0")),
    ("empty-plaintext", 1, b""),
    ("single-byte", 2, b"\x00"),
]


def gen_manifest_aead() -> dict:
    k_m = ref.derive(W, "manifest-key", ref.SENTINEL_ID)
    vectors = []
    for name, index, manifest_bytes in MANIFEST_AEAD_CASES:
        nonce = fixture_nonce("manifest", index)
        blob = ref.xchacha20poly1305_encrypt(k_m, nonce, manifest_bytes, b"")
        assert len(blob) == len(manifest_bytes) + 16
        vectors.append(
            {
                "name": name,
                "manifest_bytes": manifest_bytes.hex(),
                "aad": "",
                "nonce": nonce.hex(),
                "blob": blob.hex(),
            }
        )
    return envelope(
        "manifest-aead",
        "Manifest AEAD golden vectors (C16/C10): k_m = HKDF(W, "
        "\"manifest-key\", sentinel) with the sentinel id "
        "0xffffffffffffffff, XChaCha20-Poly1305 over the plaintext manifest "
        "bytes with the frozen **empty** AAD (MVP-SPEC.md line 98).",
        {"w": W.hex()},
        {"k_m": k_m.hex(), "vectors": vectors},
    )


# ---------------------------------------------------------------------------
# kind: signatures (C12 + C13 + C14 — MVP-SPEC.md lines 97, 104)
# ---------------------------------------------------------------------------

# NON-SECRET fixture body: a stand-in for F's canonical CBOR manifest body.
SIG_BODY = b"antseal C16 crypto golden-vector manifest body\n"


def gen_signatures(mldsa_path: str) -> dict:
    """Assemble the hybrid signature vector.

    The Ed25519 half comes from `reference.ed25519_*` (the RFC 8032 section 6
    reference formulation, known-answer-checked against RFC 8032 section 7.1);
    the ML-DSA-65 half is read from the `fips204`-produced JSON emitted by
    `probes/sig-probe/tests/c16_mldsa_vector.rs` (see this directory's README —
    there is no Python ML-DSA in this toolchain, so the independent vehicle is
    a second Rust implementation).
    """
    with open(mldsa_path, "r", encoding="utf-8") as handle:
        return gen_signatures_from(json.load(handle), source=mldsa_path)


def gen_signatures_from(mldsa: dict, source: str = "<committed signatures.json>") -> dict:
    """Assemble the hybrid signature vector from an already-loaded ML-DSA half.

    Split out of `gen_signatures` so `--check` can re-derive the document
    without the `fips204` probe output on disk (it is not committed): the two
    un-derivable ML-DSA fields are read back from the committed vector and
    every other field, `mldsa65.seed` included, is derived here.
    """
    ed_seed = ref.derive(W, "sig-ed25519", ref.SENTINEL_ID)
    # Ed25519 has no context parameter, so the frozen ctx is folded into the
    # signed pre-image: ctx || 0x00 || body (MVP-SPEC.md line 97).
    signing_message = SIG_CONTEXT + b"\x00" + SIG_BODY

    mldsa_seed = ref.derive(W, "sig-mldsa65", ref.SENTINEL_ID)
    mldsa_path = source
    if bytes.fromhex(mldsa["seed"]) != mldsa_seed:
        raise SystemExit(
            f"{mldsa_path}: seed {mldsa['seed']} is not "
            f"HKDF(W, 'sig-mldsa65', sentinel) = {mldsa_seed.hex()}"
        )
    if bytes.fromhex(mldsa["body"]) != SIG_BODY:
        raise SystemExit(f"{mldsa_path}: body does not match this script's SIG_BODY")
    if bytes.fromhex(mldsa["context"]) != SIG_CONTEXT:
        raise SystemExit(f"{mldsa_path}: context does not match the frozen SIG_CONTEXT")

    return envelope(
        "signatures",
        "Hybrid author-signature golden vectors (C16/C12/C13/C14): keys "
        "derived from W via HKDF, Ed25519 over the frozen pre-image "
        "ctx || 0x00 || body, ML-DSA-65 with the FIPS 204 ctx parameter and "
        "deterministic signing (rnd = 0^32, decision D15), and the "
        "sig_policy [0, 1] hybrid orchestration over the same body "
        "(MVP-SPEC.md lines 97, 104).",
        {"w": W.hex(), "body": SIG_BODY.hex(), "context": SIG_CONTEXT.hex()},
        {
            "ed25519": {
                "seed": ed_seed.hex(),
                "public_key": ref.ed25519_public_key(ed_seed).hex(),
                "signing_message": signing_message.hex(),
                "signature": ref.ed25519_sign(ed_seed, signing_message).hex(),
            },
            "mldsa65": {
                "seed": mldsa_seed.hex(),
                "public_key": mldsa["public_key"],
                "signature": mldsa["signature"],
            },
            "hybrid": {"policy_ids": [0, 1], "policy_label": "hybrid"},
        },
    )


# ---------------------------------------------------------------------------

GENERATORS = {
    "commitments": gen_commitments,
    "unit-aead": gen_unit_aead,
    "manifest-aead": gen_manifest_aead,
}


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


def check_all() -> int:
    """Re-derive and byte-compare every committed vector in this directory."""
    status = 0
    for kind, generator in sorted(GENERATORS.items()):
        produced = json.dumps(generator(), indent=2) + "\n"
        status |= check_committed(HERE / f"{kind}.json", produced)

    # signatures.json: everything except the two un-derivable ML-DSA fields.
    # `_signature_mldsa_from_committed` re-reads those from the committed file
    # and re-checks the one ML-DSA field that *is* derivable (the HKDF seed),
    # so a tampered seed still fails here.
    signatures_path = HERE / "signatures.json"
    if not signatures_path.exists():
        print("FAIL  signatures.json: committed vector is missing", file=sys.stderr)
        return status | 1
    with open(signatures_path, "r", encoding="utf-8") as handle:
        committed_doc = json.load(handle)
    mldsa = committed_doc.get("expect", {}).get("mldsa65", {})
    borrowed = {
        "seed": mldsa.get("seed", ""),
        "public_key": mldsa.get("public_key", ""),
        "signature": mldsa.get("signature", ""),
        "body": SIG_BODY.hex(),
        "context": SIG_CONTEXT.hex(),
    }
    produced = json.dumps(gen_signatures_from(borrowed), indent=2) + "\n"
    status |= check_committed(signatures_path, produced)
    print(
        "note  signatures.json: expect.mldsa65.public_key and .signature are "
        "read back from the committed file (no Python ML-DSA exists); they are "
        "cross-checked against NIST ACVP by "
        "crates/antseal-core/tests/acvp_ml_dsa.rs (D31 rows 12/13, tier T0). "
        "Every other field above, expect.mldsa65.seed included, was re-derived.",
        file=sys.stderr,
    )
    return status


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "kind", nargs="?", choices=sorted([*GENERATORS, "signatures"]), default=None
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="re-derive and byte-compare every committed vector in this directory",
    )
    parser.add_argument(
        "--mldsa",
        default="mldsa65-fips204.json",
        help="fips204-produced ML-DSA-65 JSON (signatures only)",
    )
    args = parser.parse_args()
    if (args.kind is None) == (not args.check):
        parser.error("give exactly one of a `kind` positional or `--check`")

    # Never emit or trust a vector from an unverified reference implementation.
    ref.selftest()
    print("", file=sys.stderr)

    if args.check:
        return check_all()

    document = gen_signatures(args.mldsa) if args.kind == "signatures" else GENERATORS[args.kind]()
    sys.stdout.write(json.dumps(document, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
