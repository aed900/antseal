#!/usr/bin/env python3
"""Derivation record for anchor.json — the `anchor` golden vectors (A22).

**This is NOT a cross-implementation check, and the difference is the whole
point of reading this file.** For `crypto`, `fine-tree`, `hkdf` and
`storage-address` the sibling `gen_vectors.py` is an independently written
implementation whose *agreement* with Rust is the evidence (D31 tier T1). No
such implementation exists for the `anchor` kind: there is no second RFC 3161
chain validator or `.ots` evaluator here, and writing one in Python would pin
the same judgement twice rather than check it (D101 §7.3, D103 §3.2).

What this script is instead: the committed, executable, network-free statement
of **how the frozen `inputs` were obtained from `testdata/anchors/`**. It emits
`inputs` and the envelope. It emits no verdict, and it computes nothing any
verdict depends on. Every `expect` value comes from the Rust executor's
`build_expect` (`crates/antseal-core/src/test_util/vectors_anchor.rs`), which
is the *only* implementation of the rules.

Three of the seven cases carry an artifact that is not a file on disk: the
three-way merged+upgraded `.ots` over digest A. It is derived here, and the
derivation is a **byte splice with no judgement in it** — `merge_upgrade`'s
entire byte effect is

    out = file[..offset] || 0xff || body || file[offset..]

(`crates/antseal-anchor/src/ots/container.rs:252-268`), at an offset found by
a literal byte search for the pending attestation's wire encoding
(`:211-237`). No hash, no key, no crypto (D103 §2.2). The shipped
`merge_upgrade` is run over the same inputs to the same SHA-256 by
`crates/antseal-anchor/src/ots/upgrade/tests.rs`
(`the_three_way_splice_reaches_the_committed_vector_digest`, D103 RULING 2a) —
two independently written pieces of code, one committed number.

**The splice order is part of the ruling** (D103 RULING 3, §4.2):
`pending_refs`' document order over the *current* stored artifact at each step,
re-located each time, which for `merged-A.ots` is

    alice -> bob -> catallaxy

A different order produces different bytes. Intermediate sizes, measured:
664 -> 1665 -> 2702 -> **3808** B, ending at 244 ops, depth 85, 6 attestations,
sha256 c2bf8b2c22055061f7105c357459969d4bb62d397f95001a70f570fed88e0c68.

ALL INPUTS ARE NON-SECRET (project rule 6): real timestamp tokens, real
calendar responses and real mainnet block headers, every one of them published
data. No key material, no vault material, nothing derived from the fixture
seed W.

Usage:

    python3 gen_vectors.py --check     re-derive and diff against the committed
                                       document; non-zero on any difference
    python3 gen_vectors.py             write the re-derived document to stdout

`--check` is the uniform entry point every generator under
`testdata/vectors/v*/*/` carries (D31 §6a); `scripts/cross-check.sh` discovers
this file by glob and calls it. What it verifies:

  1. the envelope and the whole `inputs` object, re-derived from
     `testdata/anchors/` and diffed against the committed bytes;
  2. the **self-binding** half of `expect` — per case, `artifact_len` and
     `artifact_sha256` against `inputs.cases[].artifact_hex`, the case names
     positionally, and `expect.verify_at_unix` against `inputs.verify_at_unix`.

(2) is arithmetic over the inputs, not a second evaluator: it is D101 §7.2's
"right link", the one that makes truncated, extended or edited hex fail on the
same run that would have produced a wrong verdict. Every *verdict* field is
checked by the Rust executor and by nothing here.

The container walk below is a reader, used to (a) report the pending
attestations in document order so the splice targets are derived rather than
typed, and (b) self-test against the tree's own committed shape measurements
(`crates/antseal-core/src/anchor/ots/tests.rs:243-269`) before it is trusted
for anything: merged-A -> 34 ops / depth 12 / 3 attestations, and
rust-opentimestamps-LARGE_TEST -> 100 / 67 / 4. A walker that cannot reproduce
those is not permitted to place a splice.
"""

from __future__ import annotations

import hashlib
import json
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[3]
BOOTSTRAP = ROOT / "testdata" / "anchors" / "A25-bootstrap"
UPGRADED = BOOTSTRAP / "upgraded"
HEADERS = ROOT / "testdata" / "anchors" / "A25-upgrade-headers"
COMMITTED = HERE / "anchor.json"

# ── the `.ots` container, as antseal-core reads it ─────────────────────────
#
# Constants transcribed from crates/antseal-core/src/anchor/ots/parse.rs and
# exec.rs. They are wire constants of a foreign format, not antseal's.

MAGIC = b"\x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94"
PENDING_TAG = bytes([0x83, 0xDF, 0xE3, 0x0D, 0x2E, 0xF9, 0x0C, 0x8E])
BITCOIN_TAG = bytes([0x05, 0x88, 0x96, 0x0D, 0x73, 0xD7, 0x19, 0x01])
TAG_FORK = 0xFF
TAG_ATTESTATION = 0x00
OP_SHA256, OP_APPEND, OP_PREPEND = 0x08, 0xF0, 0xF1
OP_UNIMPLEMENTED = frozenset({0x02, 0x03, 0x67, 0xF2, 0xF3})

# The committed shapes the walker must reproduce before it is trusted
# (antseal-core/src/anchor/ots/tests.rs:243-269).
WALKER_SELF_TEST = (
    (BOOTSTRAP / "merged-A.ots", 34, 12, 3),
    (UPGRADED / "rust-opentimestamps-LARGE_TEST.ots", 100, 67, 4),
)

# ── the frozen document's fixed values ─────────────────────────────────────

VERIFY_AT_UNIX = 1_786_100_000  # 2026-08-07T10:53:20Z (D103 RULING 4b)

# D103 §9.2: the RECORDED instant, per artifact, from that artifact's own
# capture-log line. Never normalised, never synthetic (D103 RULING 8).
FETCH_DATE_FREETSA = 1_785_698_419  # D60-CAPTURE.log:36, utc=2026-08-02T19:20:19Z
FETCH_DATE_DIGICERT = 1_785_698_426  # D60-CAPTURE.log:37, utc=2026-08-02T19:20:26Z
FETCH_DATE_UPGRADE = 1_786_098_992  # A25-upgrade-headers/CAPTURE.log, utc_start

ATTESTED_HEIGHT = 960_767  # alice's branch; bob 960768 and catallaxy 960771

# The splice, in the order D103 RULING 3 pins. Each entry is
# (calendar URI, upgrade-response body), and the URI is checked against the
# artifact's own pending attestations before it is used.
SPLICE_ORDER = (
    ("https://alice.btc.calendar.opentimestamps.org", "A-alice.upgrade"),
    ("https://bob.btc.calendar.opentimestamps.org", "A-bob.upgrade"),
    ("https://btc.calendar.catallaxy.com", "A-catallaxy.upgrade"),
)


class Reader:
    """A cursor over bytes already in memory (parse.rs `Reader`)."""

    def __init__(self, data: bytes) -> None:
        self.data = data
        self.pos = 0

    def byte(self) -> int:
        if self.pos >= len(self.data):
            raise ValueError("truncated")
        value = self.data[self.pos]
        self.pos += 1
        return value

    def take(self, n: int) -> bytes:
        if self.pos + n > len(self.data):
            raise ValueError("truncated")
        value = self.data[self.pos : self.pos + n]
        self.pos += n
        return value

    def varuint(self) -> int:
        value, shift = 0, 1
        for _ in range(9):  # MAX_VARUINT_BYTES
            byte = self.byte()
            value += (byte & 0x7F) * shift
            if not byte & 0x80:
                return value
            shift *= 128
        raise ValueError("varuint too long")


def varuint_bytes(value: int) -> bytes:
    """Little-endian base-128 varuint, minimally encoded (container.rs)."""
    out = bytearray()
    while True:
        byte = value % 128
        value //= 128
        if value == 0:
            out.append(byte)
            return bytes(out)
        out.append(byte | 0x80)


def pending_attestation_bytes(uri: str) -> bytes:
    """`0x00 || tag(8) || varuint(payload_len) || varuint(uri_len) || uri`.

    `container.rs:pending_attestation_bytes` verbatim — the needle
    `locate_pending` searches for.
    """
    payload = varuint_bytes(len(uri)) + uri.encode("utf-8")
    return (
        bytes([TAG_ATTESTATION])
        + PENDING_TAG
        + varuint_bytes(len(payload))
        + payload
    )


def walk(data: bytes) -> tuple[list[tuple], dict[str, int]]:
    """Walk the op-DAG exactly as `parse.rs::walk` does.

    Returns the attestations in document order and the shape measurements the
    self-test compares. Raises on anything the Rust parser would reject.
    """
    reader = Reader(data)
    if reader.take(len(MAGIC)) != MAGIC:
        raise ValueError("bad magic")
    if reader.varuint() != 1:
        raise ValueError("unsupported version")
    if reader.byte() != 8:
        raise ValueError("unsupported digest type")
    start = reader.take(32)

    attestations: list[tuple] = []
    ops = 0
    max_depth = 0
    # A frame is [value|None, depth, children, closes_parent]. stack[0] is
    # `Walk::root`; stack[1:] is `Walk::rest`.
    stack: list[list] = [[start, 0, 0, False]]

    def complete_top() -> bool:
        while True:
            if len(stack) == 1:
                return True
            if not stack.pop()[3]:
                return False

    while True:
        first = reader.byte()
        is_last_child = first != TAG_FORK
        stack[-1][2] += 1
        child_tag = first if is_last_child else reader.byte()

        if child_tag == TAG_ATTESTATION:
            commitment = stack[-1][0]
            tag = reader.take(8)
            declared = reader.varuint()
            payload = reader.take(declared)
            if tag == PENDING_TAG:
                sub = Reader(payload)
                uri = sub.take(sub.varuint()).decode("utf-8")
                if sub.pos != len(payload):
                    raise ValueError("pending payload not consumed")
                attestations.append(("pending", uri, commitment))
            elif tag == BITCOIN_TAG:
                sub = Reader(payload)
                height = sub.varuint()
                if sub.pos != len(payload):
                    raise ValueError("bitcoin payload not consumed")
                attestations.append(("bitcoin", height, commitment))
            else:
                attestations.append(("unknown", tag.hex(), declared))
            if is_last_child and complete_top():
                break
            continue

        if child_tag not in (OP_SHA256, OP_APPEND, OP_PREPEND) and (
            child_tag not in OP_UNIMPLEMENTED
        ):
            raise ValueError(f"unknown op 0x{child_tag:02x}")

        depth = stack[-1][1] + 1
        max_depth = max(max_depth, depth)
        ops += 1
        operand = b""
        if child_tag in (OP_APPEND, OP_PREPEND):
            operand = reader.take(reader.varuint())

        value = stack[-1][0]
        if value is None:
            new_value = None  # indeterminacy is absorbing (D58 §9.4)
        elif child_tag == OP_SHA256:
            new_value = hashlib.sha256(value).digest()
        elif child_tag == OP_APPEND:
            new_value = value + operand
        elif child_tag == OP_PREPEND:
            new_value = operand + value
        else:
            new_value = None
        stack.append([new_value, depth, 0, is_last_child])

    if reader.pos != len(data):
        raise ValueError(f"{len(data) - reader.pos} trailing bytes")
    return attestations, {
        "ops": ops,
        "depth": max_depth,
        "attestations": len(attestations),
    }


def self_test_walker() -> None:
    """Refuse to place a splice with a walker that cannot reproduce the
    tree's own committed shape measurements."""
    for path, ops, depth, count in WALKER_SELF_TEST:
        _, shape = walk(path.read_bytes())
        got = (shape["ops"], shape["depth"], shape["attestations"])
        if got != (ops, depth, count):
            raise SystemExit(
                f"walker self-test FAILED on {path.name}: measured {got}, "
                f"antseal-core/src/anchor/ots/tests.rs records {(ops, depth, count)}"
            )


def locate_pending(data: bytes, uri: str) -> int:
    """`container.rs::locate_pending` for occurrence 0.

    The byte-search count must equal the parser's count for this URI, which is
    what makes index-matching sound (container.rs module docs).
    """
    expected = sum(1 for a in walk(data)[0] if a[0] == "pending" and a[1] == uri)
    needle = pending_attestation_bytes(uri)
    found = [
        i for i in range(len(data) - len(needle) + 1) if data[i : i + len(needle)] == needle
    ]
    if len(found) != expected:
        raise SystemExit(
            f"locate_pending({uri}): byte search found {len(found)}, parser found "
            f"{expected} — refusing to edit a file this code cannot place"
        )
    if not found:
        raise SystemExit(f"locate_pending({uri}): no occurrence")
    return found[0]


def three_way_splice() -> bytes:
    """`merged-A.ots` + the three committed upgrade bodies, in the pinned
    order (D103 RULING 3)."""
    self_test_walker()
    current = (BOOTSTRAP / "merged-A.ots").read_bytes()
    for uri, body_name in SPLICE_ORDER:
        body = (UPGRADED / body_name).read_bytes()
        offset = locate_pending(current, uri)
        # splice_sibling_before: a pure insertion, never a rewrite.
        current = current[:offset] + bytes([TAG_FORK]) + body + current[offset:]
        # `merge_upgrade` re-parses after every splice (upgrade.rs:372); so
        # does this, for the same reason.
        walk(current)
    return current


def block_header(height: int) -> bytes:
    """The agreed 80-byte mainnet header, from both committed endpoints.

    A16's must-agree rule is byte-identity over the header, so both endpoint
    captures are read and compared here rather than one being picked.
    """
    a = (HEADERS / f"esplora-blockstream-header-{height}.txt").read_text().strip()
    b = (HEADERS / f"esplora-mempool-header-{height}.txt").read_text().strip()
    if a != b:
        raise SystemExit(f"header {height}: the two committed endpoints disagree")
    header = bytes.fromhex(a)
    if len(header) != 80:
        raise SystemExit(f"header {height}: {len(header)} bytes, expected 80")
    # The header the artifact's ops commit to, checked here so a wrong file
    # cannot be quoted silently: double-SHA256 must equal the committed height
    # lookup, in the reversed display form esplora returns.
    claimed = (HEADERS / f"esplora-blockstream-height-{height}.txt").read_text().strip()
    computed = hashlib.sha256(hashlib.sha256(header).digest()).digest()[::-1].hex()
    if computed != claimed:
        raise SystemExit(
            f"header {height}: double-SHA256 is {computed}, the committed height "
            f"lookup claims {claimed}"
        )
    return header


def tsa_case(name: str, filename: str, fetch_date: int) -> dict:
    token = (BOOTSTRAP / filename).read_bytes()
    return {
        "name": name,
        "kind": "tsa",
        "artifact_hex": token.hex(),
        "intermediates_hex": [],
        "fetch_date_unix": fetch_date,
        "upgrade": None,
        "online": [],
        "provenance": f"testdata/anchors/A25-bootstrap/{filename}",
    }


SPLICED_PROVENANCE = (
    "derived (not a file): testdata/anchors/A25-bootstrap/merged-A.ots spliced with "
    "upgraded/A-alice.upgrade, upgraded/A-bob.upgrade, upgraded/A-catallaxy.upgrade in "
    "that order by testdata/vectors/v1/anchor/gen_vectors.py; header from "
    "testdata/anchors/A25-upgrade-headers/esplora-blockstream-header-960767.txt "
    "(byte-identical at esplora-mempool-header-960767.txt)"
)


def build_inputs() -> dict:
    spliced = three_way_splice()
    header = block_header(ATTESTED_HEIGHT)
    upgrade = {
        "block_height": ATTESTED_HEIGHT,
        "block_header_hex": header.hex(),
        "fetch_date_unix": FETCH_DATE_UPGRADE,
    }

    def spliced_case(name: str, online: list) -> dict:
        return {
            "name": name,
            "kind": "ots",
            "artifact_hex": spliced.hex(),
            "intermediates_hex": [],
            "fetch_date_unix": None,
            "upgrade": dict(upgrade),
            "online": online,
            "provenance": SPLICED_PROVENANCE,
        }

    return {
        "verify_at_unix": VERIFY_AT_UNIX,
        "anchor_digest": (BOOTSTRAP / "digest-A.bin").read_bytes().hex(),
        "cases": [
            tsa_case("tsa-freetsa-p384", "D60-tsa-freetsa-resp.tsr", FETCH_DATE_FREETSA),
            tsa_case("tsa-digicert-rsa", "D60-tsa-digicert-resp.tsr", FETCH_DATE_DIGICERT),
            {
                "name": "ots-pending",
                "kind": "ots",
                "artifact_hex": (BOOTSTRAP / "merged-A.ots").read_bytes().hex(),
                "intermediates_hex": [],
                "fetch_date_unix": None,
                "upgrade": None,
                "online": [],
                "provenance": "testdata/anchors/A25-bootstrap/merged-A.ots",
            },
            spliced_case("ots-upgraded-offline", []),
            spliced_case(
                "ots-upgraded-online-proven",
                [
                    {
                        "height": ATTESTED_HEIGHT,
                        "result": "header",
                        "header_hex": header.hex(),
                    }
                ],
            ),
            spliced_case(
                "ots-upgraded-online-block-absent",
                [
                    {
                        "height": ATTESTED_HEIGHT,
                        "result": "no-such-block",
                        "header_hex": None,
                    }
                ],
            ),
            {
                "name": "ots-wrong-seal",
                "kind": "ots",
                "artifact_hex": (BOOTSTRAP / "merged-B.ots").read_bytes().hex(),
                "intermediates_hex": [],
                "fetch_date_unix": None,
                "upgrade": None,
                "online": [],
                "provenance": "testdata/anchors/A25-bootstrap/merged-B.ots",
            },
        ],
    }


NON_SECRET = (
    "NON-SECRET recorded public artifacts: two real RFC 3161 timestamp tokens "
    "(FreeTSA ECDSA P-384, DigiCert RSA), two real OpenTimestamps calendar "
    "artifacts, a three-way merged+upgraded .ots derived from committed calendar "
    "responses, and a real Bitcoin mainnet block header. Every byte was published "
    "by a third party or is a byte splice of bytes that were. No key material, no "
    "vault material, and nothing derived from the fixed test seed W."
)

DESCRIPTION = (
    "anchor kind (A22): the per-anchor verdict object for seven cases over four "
    "recorded artifacts, at a fixed verify_at of 1786100000 (2026-08-07T10:53:20Z) "
    "against TsaRootStore::pinned(). Cases 1-2 are the two D60 tokens; case 3 the "
    "un-upgraded merged-A.ots; cases 4-6 the SAME three-way merged+upgraded .ots "
    "bytes (3808 B, sha256 c2bf8b2c22055061f7105c357459969d4bb62d397f95001a70f570fed88e0c68) "
    "under no online evidence, an agreed matching header, and an agreed no-such-block "
    "respectively; case 7 an .ots for the OTHER seal (merged-B) under this document's "
    "anchor_digest. "
    "CLOCK, measured per artifact and not normalised (D103 RULING 8): cases 1 and 2 "
    "carry the capture host's own clock reading. Measured against each token's "
    "genTime, that clock was 128 s slow for BOTH. The log's headline of 129 s "
    "(D60-CAPTURE.log:17-23) is the largest of three probe offsets (+129/+128/+129) "
    "and is not the figure for these two artifacts. gen_time <= fetch_date is FALSE "
    "for both cases; that is correct and no check may assert otherwise (A32, "
    "D59 section 6(a)). Cases 4-6 carry utc_start of the 2026-08-07 header campaign, "
    "which is the later of the group's two capture instants - the upgrade group is "
    "all-or-nothing (D79) and did not exist until its header did. That campaign "
    "recorded NO clock offset, so this value's skew is unmeasured; it is the recorded "
    "instant and nothing more. No verification rule reads fetch_date. It is pinned "
    "here as a pass-through: the verdict must echo the input unchanged and move "
    "nothing else (R72). "
    "Case 6's online input is HYPOTHETICAL evidence about a block that exists. "
    "OnlineEvidence is data a host supplies, and the case pins what the rule does "
    "with an agreed absence - it does NOT claim block 960767 is absent. It is the "
    "first committed witness for D56 section 4's anti-downgrade rule: a committed "
    "artifact that agreed evidence refutes still renders pending when it has a "
    "pending branch, and the refutation is carried as an A39 suppressed anomaly. "
    "Provenance and the derivation of the spliced artifact: "
    "testdata/vectors/v1/anchor/README.md and gen_vectors.py."
)


def build_document(expect: object) -> dict:
    return {
        "schema": "antseal-golden-vector",
        "schema_version": 1,
        "format_version": "v1",
        "kind": "anchor",
        "non_secret": NON_SECRET,
        "description": DESCRIPTION,
        "inputs": build_inputs(),
        "expect": expect,
    }


def render(document: dict) -> str:
    """Byte-for-byte what the Rust emitter writes (R9's convention, shared by
    `report`): the eight envelope keys in their documented order, every nested
    object in `serde_json`'s own alphabetical ordering.

    The two renderers must agree exactly — `--check` diffs this against the
    committed bytes, and `emit_anchor_vector_document` rewrites them.
    """

    def sub(value: object) -> str:
        return json.dumps(value, indent=2, ensure_ascii=False, sort_keys=True).replace(
            "\n", "\n  "
        )

    def string(value: str) -> str:
        return json.dumps(value, ensure_ascii=False)

    return (
        "{\n"
        '  "schema": "antseal-golden-vector",\n'
        '  "schema_version": 1,\n'
        '  "format_version": "v1",\n'
        f'  "kind": {string(document["kind"])},\n'
        f'  "non_secret": {string(document["non_secret"])},\n'
        f'  "description": {string(document["description"])},\n'
        f'  "inputs": {sub(document["inputs"])},\n'
        f'  "expect": {sub(document["expect"])}\n'
        "}\n"
    )


def check_self_binding(document: dict) -> list[str]:
    """D101 section 7.2's right link: `expect`'s self-binding fields against
    `inputs`. Arithmetic over the inputs — never a second evaluator."""
    problems: list[str] = []
    inputs, expect = document["inputs"], document["expect"]
    if expect.get("verify_at_unix") != inputs["verify_at_unix"]:
        problems.append(
            f"expect.verify_at_unix {expect.get('verify_at_unix')!r} != "
            f"inputs.verify_at_unix {inputs['verify_at_unix']!r}"
        )
    in_cases, out_cases = inputs["cases"], expect.get("cases", [])
    if len(in_cases) != len(out_cases):
        problems.append(f"{len(in_cases)} inputs cases vs {len(out_cases)} expect cases")
        return problems
    for want, got in zip(in_cases, out_cases):
        where = want["name"]
        if got.get("name") != want["name"]:
            problems.append(f"case order: inputs {want['name']!r} vs expect {got.get('name')!r}")
            continue
        artifact = bytes.fromhex(want["artifact_hex"])
        if got.get("artifact_len") != len(artifact):
            problems.append(
                f"{where}: expect.artifact_len {got.get('artifact_len')!r} != "
                f"{len(artifact)} (from inputs.artifact_hex)"
            )
        digest = hashlib.sha256(artifact).hexdigest()
        if got.get("artifact_sha256") != digest:
            problems.append(
                f"{where}: expect.artifact_sha256 {got.get('artifact_sha256')!r} != {digest}"
            )
    return problems


def report_digests() -> None:
    """Per-file SHA-256 for the quoted captures, for the landing commit
    message. D60-CAPTURE.log records no per-file digest (D101 section 7.2's
    left-link gap); these close it for the two tokens A22 quotes."""
    print("# quoted captures, sha256 (D101 section 7.2, left link)", file=sys.stderr)
    for rel in (
        "A25-bootstrap/D60-tsa-freetsa-resp.tsr",
        "A25-bootstrap/D60-tsa-digicert-resp.tsr",
        "A25-bootstrap/merged-A.ots",
        "A25-bootstrap/merged-B.ots",
        "A25-bootstrap/upgraded/A-alice.upgrade",
        "A25-bootstrap/upgraded/A-bob.upgrade",
        "A25-bootstrap/upgraded/A-catallaxy.upgrade",
        "A25-upgrade-headers/esplora-blockstream-header-960767.txt",
    ):
        data = (ROOT / "testdata" / "anchors" / rel).read_bytes()
        print(f"#   {hashlib.sha256(data).hexdigest()}  {len(data):>6} B  {rel}", file=sys.stderr)
    spliced = three_way_splice()
    print(
        f"#   {hashlib.sha256(spliced).hexdigest()}  {len(spliced):>6} B  "
        "(derived) three-way merged+upgraded .ots over digest A",
        file=sys.stderr,
    )


def main() -> int:
    if "--check" not in sys.argv:
        report_digests()
        # The committed `expect` is carried through: this script emits no
        # verdict (D103 section 3.2). Regenerating `expect` is
        # `cargo test -p antseal-core --features test-util --test anchor_vectors
        #  -- --ignored emit_anchor_vector_document`.
        expect = json.loads(COMMITTED.read_text(encoding="utf-8"))["expect"]
        sys.stdout.write(render(build_document(expect)))
        return 0

    if not COMMITTED.is_file():
        print(f"FAIL  {COMMITTED} does not exist", file=sys.stderr)
        return 1
    committed_text = COMMITTED.read_text(encoding="utf-8")
    committed = json.loads(committed_text)
    rederived = render(build_document(committed["expect"]))

    status = 0
    if rederived != committed_text:
        status = 1
        print(
            "FAIL  anchor.json: the re-derived envelope/inputs differ from the "
            "committed bytes",
            file=sys.stderr,
        )
        want = json.loads(rederived)
        for key in ("schema", "schema_version", "format_version", "kind", "non_secret", "description"):
            if want[key] != committed.get(key):
                print(f"      envelope.{key} differs", file=sys.stderr)
        if want["inputs"] != committed.get("inputs"):
            print("      inputs differ (re-derive from testdata/anchors/)", file=sys.stderr)
            wi, ci = want["inputs"], committed.get("inputs", {})
            for key in ("verify_at_unix", "anchor_digest"):
                if wi.get(key) != ci.get(key):
                    print(f"        inputs.{key}: {ci.get(key)!r} != {wi.get(key)!r}", file=sys.stderr)
            for index, wc in enumerate(wi["cases"]):
                cc = ci.get("cases", [])[index] if index < len(ci.get("cases", [])) else None
                if cc != wc:
                    print(f"        inputs.cases[{index}] ({wc['name']}) differs", file=sys.stderr)

    for problem in check_self_binding(committed):
        status = 1
        print(f"FAIL  anchor.json self-binding: {problem}", file=sys.stderr)

    if status == 0:
        cases = len(committed["inputs"]["cases"])
        print(f"OK    anchor.json: envelope + inputs re-derived, {cases} cases self-bound")
    return status


if __name__ == "__main__":
    sys.exit(main())
