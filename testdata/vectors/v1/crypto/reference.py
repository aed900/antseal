#!/usr/bin/env python3
"""Independent reference implementations for the antseal crypto golden
vectors (tasks/C.md C16).

**Python standard library only** (`hashlib`, `hmac`) — no third-party crates,
no shared code with the Rust path. Every primitive antseal-core's vectors pin
is re-implemented here from its specification, so a green vector run *is*
cross-implementation agreement, not a self-check (the C3/G3 house precedent).

Implemented, with the specification each follows:

- `hkdf_sha256`            — RFC 5869 (extract/expand from raw HMAC-SHA256)
- `info_bytes`             — MVP-SPEC.md line 77
- `tagged_sha256`          — MVP-SPEC.md line 79 (domain-tag prefix)
- `chacha20_block`         — RFC 8439 section 2.3
- `poly1305_mac`           — RFC 8439 section 2.5
- `chacha20poly1305_ietf`  — RFC 8439 section 2.8
- `hchacha20`              — draft-irtf-cfrg-xchacha section 2.2
- `xchacha20poly1305`      — draft-irtf-cfrg-xchacha section 3.1 (= libsodium's
                             `crypto_aead_xchacha20poly1305_ietf_*`)
- `ed25519_*`              — RFC 8032 section 6 reference formulation

ALL INPUTS THESE FUNCTIONS ARE CALLED WITH ARE NON-SECRET, FIXED TEST
FIXTURES (project rule 6): the test master secret W is the documented fixed
test seed 00 01 02 .. 1f (testdata/README.md). Never a real secret.

`selftest()` (run this file directly) checks every primitive against published
known-answer vectors and, when the optional corroborating libraries are
installed, against them too:

    python3 reference.py            # self-test only

## The T0 anchors (D31 rows 4 and 8)

This file is a **T1** vehicle in D31's grading: an independent
re-implementation, which catches transcription and implementation bugs but
never a *shared misreading of the specification*. Only published known
answers close that gap, so D31 §3 requires this file to actually carry them
rather than promise them — "a T1 reference whose T0 anchor is aspirational is
a T1 reference".

Q11 audited that and found the anchors **already present and passing**: RFC
5869 A.1 and A.3, and RFC 8032 §7.1 TEST 2, landed with C16. No C16 agreement
was ever T1-unanchored. Q11 widened them from sampled to complete, since a
partial known-answer set is a quiet way to miss a boundary case:

- **RFC 5869 A.2** added — the long-input case, `L = 82`. A.1 and A.3 both
  stop at 42 octets (two HMAC blocks); A.2 needs three, so it is the only one
  of the three that exercises the third expand iteration.
- **RFC 8032 §7.1 — all five cases** (`RFC8032_7_1` below), up from TEST 2
  alone. TEST 1's empty message and TEST 1024's 1023-byte message bracket the
  SHA-512 block boundary that a single-byte message cannot reach. The table
  was parsed out of the RFC text, not transcribed by hand, and `selftest`
  asserts it still has all five entries so a truncation cannot silently
  weaken the anchor.

`selftest()` is what `scripts/cross-check.sh` runs **first and
unconditionally** (D31 §6b): if the reference's own known answers fail, every
downstream vector agreement is worthless, and running it first makes that
legible instead of surfacing as forty vector diffs.
"""

import hashlib
import hmac
import sys

# ---------------------------------------------------------------------------
# RFC 5869 HKDF-SHA256 and the antseal label encoding (MVP-SPEC.md lines 76-77)
# ---------------------------------------------------------------------------

SENTINEL_ID = 0xFFFF_FFFF_FFFF_FFFF

# The frozen label registry (MVP-SPEC.md lines 91, 94-98): label -> output len.
LABEL_OUTPUT_LEN = {
    "unit-key": 32,
    "unit-salt": 16,
    "path-salt": 16,
    "file-salt": 16,
    "fine-seed": 32,
    "sig-ed25519": 32,
    "sig-mldsa65": 32,
    "manifest-key": 32,
}


def le64(value: int) -> bytes:
    """LE64(id) — the shared id encoding (MVP-SPEC.md line 76)."""
    return value.to_bytes(8, "little")


def info_bytes(label: str, ident: int) -> bytes:
    """info = u8(len(label)) || label || LE64(id)  (MVP-SPEC.md line 77).

    The length prefix is what makes (label, id) -> info injective.
    """
    encoded = label.encode("ascii")
    assert 0 < len(encoded) <= 255
    return bytes([len(encoded)]) + encoded + le64(ident)


def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    """RFC 5869 HKDF-SHA256 built from raw HMAC (extract, then expand)."""
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    okm = b""
    block = b""
    counter = 1
    while len(okm) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        okm += block
        counter += 1
    return okm[:length]


def derive(w: bytes, label: str, ident: int) -> bytes:
    """HKDF-SHA256(W, label, id) at the registry's output length."""
    return hkdf_sha256(w, b"", info_bytes(label, ident), LABEL_OUTPUT_LEN[label])


# ---------------------------------------------------------------------------
# Domain-tagged SHA-256 (MVP-SPEC.md line 79)
# ---------------------------------------------------------------------------

# The frozen tag registry (MVP-SPEC.md line 79).
TAG_FINE_LEAF = 0x00
TAG_FINE_NODE = 0x01
TAG_UNIT_COMMIT = 0x02
TAG_RAW_COMMIT = 0x03
TAG_CANON_COMMIT = 0x04
TAG_PATH_COMMIT = 0x05
TAG_GGM_SALT_CHILD = 0x06


def tagged_sha256(tag: int, *parts: bytes) -> bytes:
    """SHA-256(tag || concat(parts)) — the tag is always the first byte."""
    assert 0x00 <= tag <= 0xFF
    return hashlib.sha256(bytes([tag]) + b"".join(parts)).digest()


# ---------------------------------------------------------------------------
# Unit padding codec (MVP-SPEC.md line 91)
# ---------------------------------------------------------------------------

PAD_BLOCK = 256


def padded_length(true_length: int) -> int:
    """ceil((true_length + 1) / 256) * 256 — always at least one pad byte."""
    return -(-(true_length + 1) // PAD_BLOCK) * PAD_BLOCK


def apply_padding(data: bytes) -> bytes:
    """Zero-fill to `padded_length(len(data))`."""
    return data + bytes(padded_length(len(data)) - len(data))


# ---------------------------------------------------------------------------
# ChaCha20 / Poly1305 / XChaCha20-Poly1305 (RFC 8439; draft-irtf-cfrg-xchacha)
# ---------------------------------------------------------------------------

_MASK32 = 0xFFFF_FFFF
_CHACHA_CONSTANTS = (0x61707865, 0x3320646E, 0x79622D32, 0x6B206574)


def _rotl32(value: int, count: int) -> int:
    value &= _MASK32
    return ((value << count) | (value >> (32 - count))) & _MASK32


def _quarter_round(state: list, a: int, b: int, c: int, d: int) -> None:
    """RFC 8439 section 2.1."""
    state[a] = (state[a] + state[b]) & _MASK32
    state[d] = _rotl32(state[d] ^ state[a], 16)
    state[c] = (state[c] + state[d]) & _MASK32
    state[b] = _rotl32(state[b] ^ state[c], 12)
    state[a] = (state[a] + state[b]) & _MASK32
    state[d] = _rotl32(state[d] ^ state[a], 8)
    state[c] = (state[c] + state[d]) & _MASK32
    state[b] = _rotl32(state[b] ^ state[c], 7)


def _double_rounds(state: list, count: int = 10) -> None:
    """`count` double rounds = 2*count rounds (RFC 8439 section 2.3.1)."""
    for _ in range(count):
        _quarter_round(state, 0, 4, 8, 12)
        _quarter_round(state, 1, 5, 9, 13)
        _quarter_round(state, 2, 6, 10, 14)
        _quarter_round(state, 3, 7, 11, 15)
        _quarter_round(state, 0, 5, 10, 15)
        _quarter_round(state, 1, 6, 11, 12)
        _quarter_round(state, 2, 7, 8, 13)
        _quarter_round(state, 3, 4, 9, 14)


def _words_le(data: bytes) -> list:
    return [int.from_bytes(data[i : i + 4], "little") for i in range(0, len(data), 4)]


def _bytes_le(words) -> bytes:
    return b"".join(word.to_bytes(4, "little") for word in words)


def chacha20_block(key: bytes, counter: int, nonce: bytes) -> bytes:
    """RFC 8439 section 2.3: the 64-byte ChaCha20 block function.

    `nonce` is the 12-byte IETF nonce.
    """
    assert len(key) == 32 and len(nonce) == 12
    state = list(_CHACHA_CONSTANTS) + _words_le(key) + [counter & _MASK32] + _words_le(nonce)
    working = state[:]
    _double_rounds(working)
    return _bytes_le((working[i] + state[i]) & _MASK32 for i in range(16))


def chacha20_xor(key: bytes, counter: int, nonce: bytes, data: bytes) -> bytes:
    """RFC 8439 section 2.4: the ChaCha20 stream cipher."""
    out = bytearray()
    for offset in range(0, len(data), 64):
        block = chacha20_block(key, counter + offset // 64, nonce)
        chunk = data[offset : offset + 64]
        out.extend(byte ^ block[i] for i, byte in enumerate(chunk))
    return bytes(out)


def poly1305_mac(message: bytes, key: bytes) -> bytes:
    """RFC 8439 section 2.5: the Poly1305 one-time authenticator."""
    assert len(key) == 32
    prime = (1 << 130) - 5
    r = int.from_bytes(key[:16], "little") & 0x0FFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF
    s = int.from_bytes(key[16:], "little")
    acc = 0
    for offset in range(0, len(message), 16):
        chunk = message[offset : offset + 16]
        # Append the high 1 bit: one byte past the chunk (RFC 8439 2.5.1).
        n = int.from_bytes(chunk + b"\x01", "little")
        acc = ((acc + n) * r) % prime
    return ((acc + s) & ((1 << 128) - 1)).to_bytes(16, "little")


def _pad16(data: bytes) -> bytes:
    remainder = len(data) % 16
    return b"" if remainder == 0 else bytes(16 - remainder)


def chacha20poly1305_ietf_encrypt(
    key: bytes, nonce12: bytes, plaintext: bytes, aad: bytes
) -> bytes:
    """RFC 8439 section 2.8: AEAD_CHACHA20_POLY1305. Returns ciphertext||tag."""
    otk = chacha20_block(key, 0, nonce12)[:32]
    ciphertext = chacha20_xor(key, 1, nonce12, plaintext)
    mac_data = (
        aad
        + _pad16(aad)
        + ciphertext
        + _pad16(ciphertext)
        + len(aad).to_bytes(8, "little")
        + len(ciphertext).to_bytes(8, "little")
    )
    return ciphertext + poly1305_mac(mac_data, otk)


def hchacha20(key: bytes, nonce16: bytes) -> bytes:
    """draft-irtf-cfrg-xchacha section 2.2: HChaCha20 subkey derivation.

    Unlike the block function there is **no** final addition of the input
    state; the output is words 0..4 and 12..16.
    """
    assert len(key) == 32 and len(nonce16) == 16
    state = list(_CHACHA_CONSTANTS) + _words_le(key) + _words_le(nonce16)
    _double_rounds(state)
    return _bytes_le(state[0:4] + state[12:16])


def xchacha20poly1305_encrypt(
    key: bytes, nonce24: bytes, plaintext: bytes, aad: bytes
) -> bytes:
    """draft-irtf-cfrg-xchacha section 3.1 — libsodium's
    `crypto_aead_xchacha20poly1305_ietf_encrypt`. Returns ciphertext||tag.
    """
    assert len(key) == 32 and len(nonce24) == 24
    subkey = hchacha20(key, nonce24[:16])
    return chacha20poly1305_ietf_encrypt(subkey, b"\x00\x00\x00\x00" + nonce24[16:], plaintext, aad)


# ---------------------------------------------------------------------------
# Ed25519 (RFC 8032 section 6 reference formulation)
# ---------------------------------------------------------------------------

_ED_P = 2**255 - 19
_ED_Q = 2**252 + 27742317777372353535851937790883648493


def _ed_inv(x: int) -> int:
    return pow(x, _ED_P - 2, _ED_P)


_ED_D = -121665 * _ed_inv(121666) % _ED_P
_ED_MODP_SQRT_M1 = pow(2, (_ED_P - 1) // 4, _ED_P)


def _ed_recover_x(y: int, sign: int):
    if y >= _ED_P:
        return None
    x2 = (y * y - 1) * _ed_inv(_ED_D * y * y + 1)
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (_ED_P + 3) // 8, _ED_P)
    if (x * x - x2) % _ED_P != 0:
        x = x * _ED_MODP_SQRT_M1 % _ED_P
    if (x * x - x2) % _ED_P != 0:
        return None
    if (x & 1) != sign:
        x = _ED_P - x
    return x


_ED_G_Y = 4 * _ed_inv(5) % _ED_P
_ED_G_X = _ed_recover_x(_ED_G_Y, 0)
_ED_G = (_ED_G_X, _ED_G_Y, 1, _ED_G_X * _ED_G_Y % _ED_P)


def _ed_add(p, q):
    """Extended-coordinate addition (RFC 8032 section 6)."""
    a, b = (p[1] - p[0]) * (q[1] - q[0]) % _ED_P, (p[1] + p[0]) * (q[1] + q[0]) % _ED_P
    c, d = 2 * p[3] * q[3] * _ED_D % _ED_P, 2 * p[2] * q[2] % _ED_P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % _ED_P, g * h % _ED_P, f * g % _ED_P, e * h % _ED_P)


def _ed_mul(s: int, p):
    q = (0, 1, 1, 0)
    while s > 0:
        if s & 1:
            q = _ed_add(q, p)
        p = _ed_add(p, p)
        s >>= 1
    return q


def _ed_compress(p) -> bytes:
    zinv = _ed_inv(p[2])
    x, y = p[0] * zinv % _ED_P, p[1] * zinv % _ED_P
    return int.to_bytes(y | ((x & 1) << 255), 32, "little")


def _ed_sha512_modq(data: bytes) -> int:
    return int.from_bytes(hashlib.sha512(data).digest(), "little") % _ED_Q


def _ed_secret_expand(secret: bytes):
    assert len(secret) == 32
    h = hashlib.sha512(secret).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return a, h[32:]


def ed25519_public_key(secret: bytes) -> bytes:
    """RFC 8032 section 5.1.5: the public key for a 32-byte seed."""
    a, _ = _ed_secret_expand(secret)
    return _ed_compress(_ed_mul(a, _ED_G))


def ed25519_sign(secret: bytes, message: bytes) -> bytes:
    """RFC 8032 section 5.1.6: PureEdDSA signing (deterministic)."""
    a, prefix = _ed_secret_expand(secret)
    public = _ed_compress(_ed_mul(a, _ED_G))
    r = _ed_sha512_modq(prefix + message)
    big_r = _ed_mul(r, _ED_G)
    rs = _ed_compress(big_r)
    h = _ed_sha512_modq(rs + public + message)
    s = (r + h * a) % _ED_Q
    return rs + int.to_bytes(s, 32, "little")


# ---------------------------------------------------------------------------
# self-test: published known answers, plus optional third-party corroboration
# ---------------------------------------------------------------------------

# RFC 8032 section 7.1 — the complete Ed25519 known-answer set, parsed
# from the RFC text rather than transcribed. Five cases: an empty
# message, 1 byte, 2 bytes, 1023 bytes (multi-block SHA-512), and the
# SHA-512(abc) digest as message. Each is (name, secret, public,
# message, signature), all hex.
RFC8032_7_1 = (
    (
        "TEST 1",
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae"
        "7f60",
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707"
        "511a",
        "",
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e0652249"
        "01555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe2465514143"
        "8e7a100b",
    ),
    (
        "TEST 2",
        "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8"
        "a6fb",
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4"
        "660c",
        "72",
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb"
        "69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d2916"
        "12bb0c00",
    ),
    (
        "TEST 3",
        "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b44"
        "58f7",
        "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb91154890"
        "8025",
        "af82",
        "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5a"
        "c3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027bece"
        "ea1ec40a",
    ),
    (
        "TEST 1024",
        "f5e5767cf153319517630f226876b86c8160cc583bc013744c6bf255f5cc"
        "0ee5",
        "278117fc144c72340f67d0f2316e8386ceffbf2b2428c9c51fef7c597f1d"
        "426e",
        "08b8b2b733424243760fe426a4b54908632110a66c2f6591eabd3345e3e4"
        "eb98fa6e264bf09efe12ee50f8f54e9f77b1e355f6c50544e23fb1433ddf"
        "73be84d879de7c0046dc4996d9e773f4bc9efe5738829adb26c81b37c93a"
        "1b270b20329d658675fc6ea534e0810a4432826bf58c941efb65d57a338b"
        "bd2e26640f89ffbc1a858efcb8550ee3a5e1998bd177e93a7363c344fe6b"
        "199ee5d02e82d522c4feba15452f80288a821a579116ec6dad2b3b310da9"
        "03401aa62100ab5d1a36553e06203b33890cc9b832f79ef80560ccb9a39c"
        "e767967ed628c6ad573cb116dbefefd75499da96bd68a8a97b928a8bbc10"
        "3b6621fcde2beca1231d206be6cd9ec7aff6f6c94fcd7204ed3455c68c83"
        "f4a41da4af2b74ef5c53f1d8ac70bdcb7ed185ce81bd84359d44254d9562"
        "9e9855a94a7c1958d1f8ada5d0532ed8a5aa3fb2d17ba70eb6248e594e1a"
        "2297acbbb39d502f1a8c6eb6f1ce22b3de1a1f40cc24554119a831a9aad6"
        "079cad88425de6bde1a9187ebb6092cf67bf2b13fd65f27088d78b7e883c"
        "8759d2c4f5c65adb7553878ad575f9fad878e80a0c9ba63bcbcc2732e694"
        "85bbc9c90bfbd62481d9089beccf80cfe2df16a2cf65bd92dd597b0707e0"
        "917af48bbb75fed413d238f5555a7a569d80c3414a8d0859dc65a46128ba"
        "b27af87a71314f318c782b23ebfe808b82b0ce26401d2e22f04d83d1255d"
        "c51addd3b75a2b1ae0784504df543af8969be3ea7082ff7fc9888c144da2"
        "af58429ec96031dbcad3dad9af0dcbaaaf268cb8fcffead94f3c7ca495e0"
        "56a9b47acdb751fb73e666c6c655ade8297297d07ad1ba5e43f1bca32301"
        "651339e22904cc8c42f58c30c04aafdb038dda0847dd988dcda6f3bfd15c"
        "4b4c4525004aa06eeff8ca61783aacec57fb3d1f92b0fe2fd1a85f672451"
        "7b65e614ad6808d6f6ee34dff7310fdc82aebfd904b01e1dc54b2927094b"
        "2db68d6f903b68401adebf5a7e08d78ff4ef5d63653a65040cf9bfd4aca7"
        "984a74d37145986780fc0b16ac451649de6188a7dbdf191f64b5fc5e2ab4"
        "7b57f7f7276cd419c17a3ca8e1b939ae49e488acba6b965610b5480109c8"
        "b17b80e1b7b750dfc7598d5d5011fd2dcc5600a32ef5b52a1ecc820e308a"
        "a342721aac0943bf6686b64b2579376504ccc493d97e6aed3fb0f9cd71a4"
        "3dd497f01f17c0e2cb3797aa2a2f256656168e6c496afc5fb93246f6b111"
        "6398a346f1a641f3b041e989f7914f90cc2c7fff357876e506b50d334ba7"
        "7c225bc307ba537152f3f1610e4eafe595f6d9d90d11faa933a15ef13695"
        "46868a7f3a45a96768d40fd9d03412c091c6315cf4fde7cb68606937380d"
        "b2eaaa707b4c4185c32eddcdd306705e4dc1ffc872eeee475a64dfac86ab"
        "a41c0618983f8741c5ef68d3a101e8a3b8cac60c905c15fc910840b94c00"
        "a0b9d0",
        "0aab4c900501b3e24d7cdf4663326a3a87df5e4843b2cbdb67cbf6e460fe"
        "c350aa5371b1508f9f4528ecea23c436d94b5e8fcd4f681e30a6ac00a970"
        "4a188a03",
    ),
    (
        "TEST SHA(abc)",
        "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca"
        "3d42",
        "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467"
        "e2bf",
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55"
        "d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94f"
        "a54ca49f",
        "dc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26"
        "b58909351fc9ac90b3ecfdfbc7c66431e0303dca179c138ac17ad9bef117"
        "7331a704",
    ),
)



def _check(name: str, got, want) -> None:
    if got != want:
        raise AssertionError(f"{name}: got {got!r}, want {want!r}")
    print(f"  ok  {name}", file=sys.stderr)


def selftest() -> None:
    """Known-answer checks for every primitive above."""
    print("known-answer vectors:", file=sys.stderr)

    # RFC 5869 appendix A.1 (HKDF-SHA256, Test Case 1).
    _check(
        "RFC 5869 A.1 HKDF-SHA256",
        hkdf_sha256(bytes.fromhex("0b" * 22), bytes.fromhex("000102030405060708090a0b0c"),
                    bytes.fromhex("f0f1f2f3f4f5f6f7f8f9"), 42).hex(),
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
    )
    # RFC 5869 appendix A.2 (SHA-256 with longer inputs/outputs, L = 82).
    # The multi-block expand loop: A.1 and A.3 both stop at 42 octets, which
    # is two HMAC blocks; A.2 needs three, so it is the only one of the three
    # that would notice a counter or carry-over bug in the third iteration.
    _check(
        "RFC 5869 A.2 HKDF-SHA256 (long inputs, L=82)",
        hkdf_sha256(
            bytes.fromhex("".join(f"{b:02x}" for b in range(0x00, 0x50))),
            bytes.fromhex("".join(f"{b:02x}" for b in range(0x60, 0xB0))),
            bytes.fromhex("".join(f"{b:02x}" for b in range(0xB0, 0x100))),
            82,
        ).hex(),
        "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c"
        "59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71"
        "cc30c58179ec3e87c14c01d5c1f3434f1d87",
    )
    # RFC 5869 appendix A.3 (zero-length salt and info) — the empty-salt
    # semantics antseal's derivation relies on.
    _check(
        "RFC 5869 A.3 HKDF-SHA256 (empty salt)",
        hkdf_sha256(bytes.fromhex("0b" * 22), b"", b"", 42).hex(),
        "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8",
    )

    # RFC 8439 section 2.3.2: the ChaCha20 block-function test vector.
    _check(
        "RFC 8439 2.3.2 ChaCha20 block",
        chacha20_block(bytes(range(32)), 1, bytes.fromhex("000000090000004a00000000")).hex(),
        "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4e"
        "d2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e",
    )
    # RFC 8439 section 2.5.2: the Poly1305 test vector.
    _check(
        "RFC 8439 2.5.2 Poly1305",
        poly1305_mac(b"Cryptographic Forum Research Group",
                     bytes.fromhex("85d6be7857556d337f4452fe42d506a8"
                                   "0103808afb0db2fd4abff6af4149f51b")).hex(),
        "a8061dc1305136c6c22b8baf0c0127a9",
    )
    # RFC 8439 section 2.8.2: AEAD_CHACHA20_POLY1305 (ciphertext || tag).
    aead = chacha20poly1305_ietf_encrypt(
        bytes.fromhex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"),
        bytes.fromhex("070000004041424344454647"),
        b"Ladies and Gentlemen of the class of '99: If I could offer you "
        b"only one tip for the future, sunscreen would be it.",
        bytes.fromhex("50515253c0c1c2c3c4c5c6c7"),
    )
    _check(
        "RFC 8439 2.8.2 AEAD tag",
        aead[-16:].hex(),
        "1ae10b594f09e26a7e902ecbd0600691",
    )
    _check(
        "RFC 8439 2.8.2 AEAD ciphertext head",
        aead[:16].hex(),
        "d31a8d34648e60db7b86afbc53ef7ec2",
    )
    # draft-irtf-cfrg-xchacha section 2.2.1: the HChaCha20 test vector.
    _check(
        "cfrg-xchacha 2.2.1 HChaCha20",
        hchacha20(bytes.fromhex("000102030405060708090a0b0c0d0e0f"
                                "101112131415161718191a1b1c1d1e1f"),
                  bytes.fromhex("000000090000004a0000000031415927")).hex(),
        "82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc",
    )
    # draft-irtf-cfrg-xchacha appendix A.3.1: the full AEAD_XCHACHA20_POLY1305
    # known answer — the exact construction antseal's unit and manifest
    # ciphertexts use (MVP-SPEC.md lines 91, 98).
    xaead = xchacha20poly1305_encrypt(
        bytes.fromhex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"),
        bytes.fromhex("404142434445464748494a4b4c4d4e4f5051525354555657"),
        b"Ladies and Gentlemen of the class of '99: If I could offer you "
        b"only one tip for the future, sunscreen would be it.",
        bytes.fromhex("50515253c0c1c2c3c4c5c6c7"),
    )
    _check(
        "cfrg-xchacha A.3.1 XChaCha20-Poly1305 ciphertext",
        xaead[:-16].hex(),
        "bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb"
        "731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b452"
        "2f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff9"
        "21f9664c97637da9768812f615c68b13b52e",
    )
    _check(
        "cfrg-xchacha A.3.1 XChaCha20-Poly1305 tag",
        xaead[-16:].hex(),
        "c0875924c1c7987947deafd8780acf49",
    )
    # RFC 8032 section 7.1 (Ed25519) — the complete published set, not one
    # case. TEST 1's empty message and TEST 1024's 1023-byte message bracket
    # the SHA-512 block boundary in a way TEST 2's single byte never could.
    if len(RFC8032_7_1) != 5:
        raise AssertionError(
            f"RFC 8032 7.1 table has {len(RFC8032_7_1)} cases, expected all 5 — "
            "a truncated known-answer table silently weakens the anchor"
        )
    for name, secret_hex, public_hex, message_hex, signature_hex in RFC8032_7_1:
        secret = bytes.fromhex(secret_hex)
        _check(
            f"RFC 8032 7.1 {name} public key",
            ed25519_public_key(secret).hex(),
            public_hex,
        )
        _check(
            f"RFC 8032 7.1 {name} signature ({len(message_hex) // 2}-byte message)",
            ed25519_sign(secret, bytes.fromhex(message_hex)).hex(),
            signature_hex,
        )

    # Optional corroboration by independent third-party implementations. Not
    # required (the known answers above are the contract); when the libraries
    # are installed the agreement is asserted, widening the cross-check.
    print("third-party corroboration (optional):", file=sys.stderr)
    try:
        import nacl.bindings as sodium  # libsodium
        import nacl.signing

        key, nonce, msg, aad = bytes(range(32)), bytes(range(24)), b"sunscreen", b"aad"
        _check(
            "libsodium XChaCha20-Poly1305 agrees",
            xchacha20poly1305_encrypt(key, nonce, msg, aad).hex(),
            sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(msg, aad, nonce, key).hex(),
        )
        seed = bytes(range(32))
        signing_key = nacl.signing.SigningKey(seed)
        _check(
            "libsodium Ed25519 public key agrees",
            ed25519_public_key(seed).hex(),
            bytes(signing_key.verify_key).hex(),
        )
        _check(
            "libsodium Ed25519 signature agrees",
            ed25519_sign(seed, b"sunscreen").hex(),
            signing_key.sign(b"sunscreen").signature.hex(),
        )
    except ImportError:
        print("  --  PyNaCl not installed; skipped", file=sys.stderr)

    try:
        from cryptography.hazmat.primitives.asymmetric import ed25519 as openssl_ed

        seed = bytes(range(32))
        private = openssl_ed.Ed25519PrivateKey.from_private_bytes(seed)
        _check(
            "OpenSSL Ed25519 signature agrees",
            ed25519_sign(seed, b"sunscreen").hex(),
            private.sign(b"sunscreen").hex(),
        )
    except ImportError:
        print("  --  cryptography not installed; skipped", file=sys.stderr)

    print("reference.py: all self-tests passed", file=sys.stderr)


if __name__ == "__main__":
    selftest()
