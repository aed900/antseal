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

`--check` covers `signatures.json` too. The `expect.mldsa65.public_key` and
`expect.mldsa65.signature` fields cannot be *fully* re-derived here — there is
no Python ML-DSA in this toolchain — but C27 closed the gap that mattered:
they were once read straight back from the committed file and re-emitted, so
comparing the result against that same file was a tautology and a tamper of
either field left `--check` green.

They are now checked by `check_mldsa_half` below, which is stdlib-only and
gives three independent legs plus a pin (see that function for the FIPS 204
citations). The honest framing, unchanged: ML-DSA-65 is already covered at
tier **T0** by NIST ACVP in `crates/antseal-core/tests/acvp_ml_dsa.rs` (D31
rows 12/13), which is strictly stronger than anything this file can offer.
C27 is completeness of *this checker*, not a soundness hole that was open.
`--check` prints the scope so the coverage is never silently overread.

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

# ── C27: making the ML-DSA half of signatures.json checkable ───────────────
#
# FIPS 204 (August 2024) parameters for ML-DSA-65, Table 2.
MLDSA65_K = 6  # rows of A / polynomials in t1 and h
MLDSA65_L = 5  # columns of A / polynomials in z
MLDSA65_OMEGA = 55  # max hint bits across all k polynomials
MLDSA65_LAMBDA_4 = 48  # |c-tilde| = lambda/4 = 192/4
MLDSA65_GAMMA1_BITS = 20  # bits per z coefficient: gamma1 = 2^19, range 2*gamma1

MLDSA65_PK_LEN = 32 + MLDSA65_K * 32 * 10  # rho || t1, 10 bits per coefficient
MLDSA65_SIG_LEN = (
    MLDSA65_LAMBDA_4 + MLDSA65_L * 32 * MLDSA65_GAMMA1_BITS + MLDSA65_OMEGA + MLDSA65_K
)

# Leg 4 (see check_mldsa_half): SHA-256 over public_key || signature, the
# residue the three derivations above it do not determine.
#
# THIS CONSTANT MOVES WITH THE VECTOR. If the ML-DSA half of signatures.json
# is ever legitimately re-emitted — a new W, a new SIG_BODY, a new frozen
# context — this line moves in the same commit, exactly as that file's entry
# in FROZEN.sha256 does. The failure message prints the observed digest so
# the update is a copy-paste, and it is deliberately NOT auto-updatable:
# "regenerate until it agrees" is the move D31 section 11 item 5 forbids.
MLDSA65_RESIDUE_SHA256 = "f5ff53604e53de13ca2a094752e9b47467485fef25c65a7056f259070c4b926d"


def hint_bit_unpack(tail: bytes) -> int | None:
    """FIPS 204 Algorithm 21 `HintBitUnpack`. Returns the hint count, or None.

    The last `omega + k` bytes of a signature encode the hint polynomials as
    a sorted index list per polynomial plus k cumulative cut points, with the
    unused prefix zero-padded. Most of those bytes are therefore constrained,
    and a malformed hint section is detectable without any lattice arithmetic
    at all — which is the whole reason this leg is affordable in stdlib
    Python.
    """
    if len(tail) != MLDSA65_OMEGA + MLDSA65_K:
        return None
    index = 0
    for i in range(MLDSA65_K):
        cut = tail[MLDSA65_OMEGA + i]
        if cut < index or cut > MLDSA65_OMEGA:
            return None
        first = index
        while index < cut:
            if index > first and tail[index - 1] >= tail[index]:
                return None  # indices within one polynomial must strictly increase
            index += 1
    for i in range(index, MLDSA65_OMEGA):
        if tail[i] != 0:
            return None  # the pad above the last hint must be zero
    return index


def check_mldsa_half(mldsa: dict, expected_seed: bytes, where: str) -> list[str]:
    """C27 — check the two ML-DSA fields `--check` used to take on trust.

    Before C27, `--check` read `public_key` and `signature` back out of the
    committed file and fed them into the document it then compared *against
    that same file*. The two fields cancelled, and a tamper of either left the
    lane green. The claim was recorded honestly ("cannot be re-derived here"),
    but "cannot be re-derived" was doing more work than it should: three
    properties are derivable with nothing but `hashlib`.

    Tier: this is **T1**, and it is completeness rather than soundness. ML-DSA-65
    is covered at **T0** by NIST ACVP (D31 rows 12/13, replayed from Rust in
    `crates/antseal-core/tests/acvp_ml_dsa.rs`), which is strictly stronger
    than anything here. What C27 fixes is that a tamper of *this file* now
    turns *this checker* red.

    The four legs, each returning a message rather than raising, so one run
    reports everything wrong at once:

    1. **Lengths.** FIPS 204 Table 2: pk is 1952 bytes, sig is 3309.
    2. **rho, re-derived from the HKDF seed.** Algorithm 6 `KeyGen_internal`
       computes `(rho, rho', K) = H(xi || IntegerToBytes(k,1) ||
       IntegerToBytes(l,1), 128)` with H = SHAKE-256, and `pkEncode` places
       rho in the first 32 bytes. So the first 32 bytes of the public key are
       a pure SHAKE-256 function of the seed, and the seed is itself HKDF of
       W. This leg ties the committed public key to the master secret through
       two independent derivations and is the strongest of the four.
       (The `k || l` domain separator is the FINAL standard's; the 2023 draft
       omitted it. A crate implementing the draft would fail here, which is a
       feature.)
    3. **Hint-section validity.** Algorithm 21 over the trailing 61 bytes.
    4. **A residue pin.** SHA-256 over `pk || sig`, covering t1 and the
       c-tilde/z sections that legs 2 and 3 cannot reach. This is the leg that
       makes the coverage total: with it, any single-byte change to either
       field turns `--check` red.
    """
    problems: list[str] = []
    try:
        pk = bytes.fromhex(mldsa.get("public_key", ""))
        sig = bytes.fromhex(mldsa.get("signature", ""))
    except ValueError as exc:
        return [f"{where}: mldsa65 public_key/signature is not valid hex ({exc})"]

    # 1. Lengths (FIPS 204 Table 2).
    if len(pk) != MLDSA65_PK_LEN:
        problems.append(
            f"{where}: mldsa65.public_key is {len(pk)} bytes, but ML-DSA-65 encodes "
            f"rho || t1 in {MLDSA65_PK_LEN} (FIPS 204 Table 2)"
        )
    if len(sig) != MLDSA65_SIG_LEN:
        problems.append(
            f"{where}: mldsa65.signature is {len(sig)} bytes, but ML-DSA-65 encodes "
            f"c~ || z || h in {MLDSA65_SIG_LEN} (FIPS 204 Table 2)"
        )

    # 2. rho = H(xi || k || l, 128)[0:32]  (FIPS 204 Algorithm 6 + pkEncode).
    if len(pk) >= 32:
        rho = hashlib.shake_256(
            expected_seed + bytes([MLDSA65_K, MLDSA65_L])
        ).digest(128)[:32]
        if pk[:32] != rho:
            problems.append(
                f"{where}: mldsa65.public_key does not start with rho = "
                f"SHAKE256(seed || {MLDSA65_K:02x} || {MLDSA65_L:02x}, 128)[0:32] = "
                f"{rho.hex()} (FIPS 204 Algorithm 6). The public key does not belong "
                "to the HKDF-derived seed recorded beside it."
            )

    # 3. The hint section decodes (FIPS 204 Algorithm 21).
    if len(sig) == MLDSA65_SIG_LEN:
        hints = hint_bit_unpack(sig[-(MLDSA65_OMEGA + MLDSA65_K) :])
        if hints is None:
            problems.append(
                f"{where}: mldsa65.signature's trailing {MLDSA65_OMEGA + MLDSA65_K} bytes "
                "are not a valid HintBitUnpack encoding (FIPS 204 Algorithm 21) — the hint "
                "indices are unsorted, the cut points are not non-decreasing, or the pad "
                "is non-zero"
            )

    # 4. The residue pin over everything legs 1-3 do not determine.
    residue = hashlib.sha256(pk + sig).hexdigest()
    if residue != MLDSA65_RESIDUE_SHA256:
        problems.append(
            f"{where}: SHA-256(mldsa65.public_key || mldsa65.signature) is\n"
            f"        {residue}\n"
            f"        but MLDSA65_RESIDUE_SHA256 pins\n"
            f"        {MLDSA65_RESIDUE_SHA256}\n"
            "        Either the committed vector was tampered with, or the ML-DSA half was "
            "legitimately\n"
            "        re-emitted — in which case move the constant in gen_vectors.py in the "
            "same commit,\n"
            "        exactly as signatures.json's FROZEN.sha256 entry moves. Never "
            "regenerate to agree\n"
            "        (D31 section 11 item 5)."
        )
    return problems


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

    # C27. The comparison above cannot see these two fields — it was handed
    # them — so they are checked here, against FIPS 204 and a residue pin,
    # never against themselves.
    problems = check_mldsa_half(mldsa, bytes.fromhex(borrowed["seed"]), "signatures.json")
    if problems:
        print("FAIL  signatures.json: the ML-DSA half does not check out", file=sys.stderr)
        for problem in problems:
            print(f"  {problem}", file=sys.stderr)
        status |= 1
    else:
        print(
            "OK    signatures.json: mldsa65.public_key and .signature check out "
            f"(lengths {MLDSA65_PK_LEN}/{MLDSA65_SIG_LEN}, rho re-derived from the HKDF "
            "seed via SHAKE-256, hint section decodes, residue digest pinned)",
            file=sys.stderr,
        )
    print(
        "note  signatures.json: the ML-DSA half is not fully re-derived here (no Python "
        "ML-DSA exists). Its independent vehicle is NIST ACVP at tier T0, replayed by "
        "crates/antseal-core/tests/acvp_ml_dsa.rs (D31 rows 12/13); the four legs above "
        "are C27's completeness check, so that a tamper of THIS file turns THIS checker "
        "red. Every other field, expect.mldsa65.seed included, was re-derived.",
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
