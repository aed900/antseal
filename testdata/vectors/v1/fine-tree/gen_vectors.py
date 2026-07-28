#!/usr/bin/env python3
"""Regenerate the antseal fine-tree/GGM golden vectors (tasks/G.md G15).

An **independent** reference implementation of the whole fine-tree stack —
GGM salt derivation, RFC 6962 unbalanced Merkle promotion, the leaf-exact
GGM sub-cover, and the boundary Merkle path — written from MVP-SPEC.md
lines 78/79/96 using the Python standard library only. No code is shared
with the Rust path, so a green `cargo test -p antseal-core vector_` run *is*
cross-implementation agreement on the MSB-first indexing this file exists to
pin.

ALL INPUTS ARE NON-SECRET, FIXED TEST FIXTURES (project rule 6). The master
secret W is the documented fixed test seed 00 01 02 .. 1f
(testdata/README.md, "Secret-material convention"), and the synthetic file
seed is

    s_root = SHA-256("antseal G15 fine-tree s_root" || W)

which is the project's documented `alternate_test_secret` construction: a
genuinely different fixture secret that is still a deterministic function of
the documented seed. Never a real vault seed.

Committed vectors are retained forever (Q6 freezes them): a byte change here
is a **format event**, justified explicitly, never a silent regeneration.
Run only to *verify*:

    python3 gen_vectors.py --check

`--check` is the uniform entry point every reference generator carries (D31
section 6a): it re-derives, diffs against the committed bytes, prints a
per-file verdict, and exits non-zero on any difference. It is the only thing
`scripts/cross-check.sh` calls. Bare (no `--check`) still writes the document
to stdout, so the historical `| diff - fine-tree.json` recipe keeps working.

The tiny `check_committed` helper below is duplicated verbatim in the sibling
generators rather than shared through a common module. That is deliberate:
this file is an *independent* cross-check vehicle (D31 tier T1), and a shared
helper would be shared code between the vehicles it is meant to keep apart.

The Rust side has its own regenerator (`vector_fine_tree_document_regenerates`
in crates/antseal-core/tests/fine_tree_vectors.rs), which rebuilds this
document from antseal-core's public API and diffs it against the committed
file. Two regenerators, one committed artifact.
"""

import argparse
import difflib
import hashlib
import json
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent

# ── fixture inputs (all NON-SECRET) ────────────────────────────────────────

W = bytes(range(32))
S_ROOT_LABEL = b"antseal G15 fine-tree s_root"

# ── the frozen domain tags (MVP-SPEC.md line 79) ───────────────────────────

TAG_FINE_TREE_LEAF = 0x00
TAG_FINE_TREE_NODE = 0x01
TAG_GGM_SALT_CHILD = 0x06

SALT_LEN = 16


def sha256(*parts: bytes) -> bytes:
    digest = hashlib.sha256()
    for part in parts:
        digest.update(part)
    return digest.digest()


# ── GGM salt tree (MVP-SPEC.md line 96) ────────────────────────────────────


def s_root() -> bytes:
    """The synthetic file seed: SHA-256(label || W) (module docstring)."""
    return sha256(S_ROOT_LABEL, W)


def depth_for_leaf_count(n: int) -> "int | None":
    """d = ceil(log2 n); None for n = 0 (an empty file has no tree)."""
    if n == 0:
        return None
    d = 0
    while (1 << d) < n:
        d += 1
    return d


def child_seed(parent: bytes, bit: int) -> bytes:
    """s_{v||b} = SHA-256(0x06 || s_v || b)."""
    return sha256(bytes([TAG_GGM_SALT_CHILD]), parent, bytes([bit]))


def path_bits(index: int, level: int) -> "list[int]":
    """The root-to-node path, **MSB-FIRST**: bit `level - 1` of `index` first.

    This one line is what the whole vector file pins. Reversing it (LSB-first)
    produces a different `salt_i` for every index whose bit pattern is not a
    palindrome, and therefore a different `fine_root`, different cover seeds,
    and different boundary hashes — which is exactly why the committed
    intermediates catch an indexing change rather than only the final root.
    """
    return [(index >> (level - 1 - k)) & 1 for k in range(level)]


def seed_at(root: bytes, level: int, index: int) -> bytes:
    seed = root
    for bit in path_bits(index, level):
        seed = child_seed(seed, bit)
    return seed


def salt_of(root: bytes, depth: int, index: int) -> bytes:
    """salt_i = leaf_seed[..16]; with d = 0 this is s_root[..16]."""
    return seed_at(root, depth, index)[:SALT_LEN]


def first_slot(level: int, index: int, depth: int) -> int:
    return index << (depth - level)


def slot_width(level: int, depth: int) -> int:
    return 1 << (depth - level)


def used_ggm_nodes(n: int, depth: int) -> "list[tuple[int, int]]":
    """Every grid node covering at least one real leaf, in (level, index) order.

    Slots >= n are unused and commit nothing, so no public path derives a node
    lying wholly inside them (MVP-SPEC.md line 96).
    """
    nodes = []
    for level in range(depth + 1):
        for index in range(1 << level):
            if first_slot(level, index, depth) < n:
                nodes.append((level, index))
    return nodes


# ── content Merkle tree (MVP-SPEC.md lines 78, 96) ─────────────────────────


def leaf_hash(salt: bytes, index: int, byte: int) -> bytes:
    """leaf_i = SHA-256(0x00 || salt_i || LE64(i) || byte_i)."""
    return sha256(
        bytes([TAG_FINE_TREE_LEAF]), salt, index.to_bytes(8, "little"), bytes([byte])
    )


def node_hash(left: bytes, right: bytes) -> bytes:
    """node = SHA-256(0x01 || left || right)."""
    return sha256(bytes([TAG_FINE_TREE_NODE]), left, right)


def rfc6962_split(width: int) -> int:
    """The largest power of two STRICTLY below `width` (RFC 6962 promotion)."""
    if width < 2:
        return 1
    split = 1
    while split * 2 < width:
        split *= 2
    return split


def subtree_hash(root: bytes, depth: int, content: bytes, first: int, end: int) -> bytes:
    if end - first <= 1:
        return leaf_hash(salt_of(root, depth, first), first, content[first])
    split = rfc6962_split(end - first)
    return node_hash(
        subtree_hash(root, depth, content, first, first + split),
        subtree_hash(root, depth, content, first + split, end),
    )


def content_nodes(first: int, end: int, out: "list[tuple[int, int]]") -> None:
    out.append((first, end))
    if end - first <= 1:
        return
    split = rfc6962_split(end - first)
    content_nodes(first, first + split, out)
    content_nodes(first + split, end, out)


def canonical_slot(first: int, end: int, n: int, depth: int) -> "tuple[int, int]":
    """The DEEPEST grid slot whose real span equals [first, end).

    Content-tree nodes can span a truncated interval at a ragged right edge,
    so their wire address is this canonical slot (registry-v1 section 5).
    """
    for level in range(depth, -1, -1):
        width = slot_width(level, depth)
        if first % width != 0:
            continue
        if min(first + width, n) != end:
            continue
        return (level, first // width)
    raise AssertionError(f"[{first},{end}) is no content-tree node at n={n}")


# ── leaf-exact GGM sub-cover (MVP-SPEC.md line 96) ─────────────────────────


def minimal_cover(start: int, end: int, n: int, depth: int) -> "list[tuple[int, int]]":
    """The maximal-subtree decomposition whose every node's REAL span is inside
    [start, end). Nodes additionally spanning only unused slots >= n are
    permitted; a node spanning an unrevealed REAL leaf never is.

    Pre-order DFS, left child first, so nodes come out ascending by first leaf.
    """
    out = []

    def visit(level: int, index: int) -> None:
        node_first = first_slot(level, index, depth)
        if node_first >= n:  # wholly unused: commits nothing
            return
        real_end = min(node_first + slot_width(level, depth), n)
        if real_end <= start or node_first >= end:  # disjoint
            return
        if node_first >= start and real_end <= end:  # leaf-exact: emit
            out.append((level, index))
            return
        visit(level + 1, index * 2)
        visit(level + 1, index * 2 + 1)

    visit(0, 0)
    return out


def boundary_path(
    root: bytes, depth: int, content: bytes, n: int, start: int, end: int
) -> "list[tuple[int, int, bytes]]":
    """The maximal content-tree subtrees lying entirely outside [start, end),
    ascending by first leaf, each as (level, index, hash)."""
    out = []

    def record(first: int, node_end: int) -> None:
        if node_end <= start or first >= end:
            level, index = canonical_slot(first, node_end, n, depth)
            out.append((level, index, subtree_hash(root, depth, content, first, node_end)))
            return
        if node_end - first <= 1:
            return
        split = rfc6962_split(node_end - first)
        record(first, first + split)
        record(first + split, node_end)

    record(0, n)
    return out


# ── document assembly ──────────────────────────────────────────────────────

NON_SECRET = (
    "NON-SECRET test fixture (project rule 6): the master secret W is the "
    "documented fixed test seed, bytes 0x00..0x1f (testdata/README.md), and "
    "the synthetic file seed is s_root = SHA-256(s_root_label || W) — the "
    "documented alternate_test_secret construction. Every seed, salt and "
    "hash below is a deterministic function of those two. Never real vault "
    "material."
)

DESCRIPTION = (
    "Fine-tree/GGM golden vectors (G15): the unbalanced n=6 case with every "
    "intermediate pinned — all used GGM node seeds, every salt_i (which is "
    "what pins MSB-FIRST bit order), every RFC 6962 content-tree node under "
    "unbalanced promotion, and fine_root — plus covers, boundary paths and "
    "full range proofs for reveal {2}, [1,3), [4,6) and the full [0,6); and "
    "the edge cases n=1 (root == leaf), n=0 (no tree at all) and n=5 (one "
    "past a power of two, exercising unused GGM slots) "
    "(MVP-SPEC.md lines 78, 96, 153, 169)."
)

# Each case: (name, content bytes, [(opening name, start, length)]).
CASES = [
    (
        "unbalanced-n6",
        bytes.fromhex("00017f80feff"),
        [
            ("reveal-single-leaf-2", 2, 1),
            ("reveal-1-3-two-cover-nodes", 1, 2),
            ("reveal-4-6-node-over-unused-slots", 4, 2),
            ("reveal-full-0-6", 0, 6),
        ],
    ),
    (
        "n1-root-is-leaf",
        bytes.fromhex("2a"),
        [("reveal-full-0-1", 0, 1)],
    ),
    (
        "n0-no-tree",
        b"",
        [],
    ),
    (
        "n5-one-past-a-power-of-two",
        bytes.fromhex("a0b1c2d3e4"),
        [
            ("reveal-4-5-cover-node-spans-three-unused-slots", 4, 1),
            ("reveal-0-4-left-perfect-subtree", 0, 4),
            ("reveal-full-0-5", 0, 5),
        ],
    ),
]


def build_case(root: bytes, name: str, content: bytes, openings) -> dict:
    n = len(content)
    depth = depth_for_leaf_count(n)
    if depth is None:
        # n = 0: there is no tree, so there is nothing to pin but its absence.
        return {
            "name": name,
            "n": 0,
            "depth": None,
            "slot_count": 0,
            "ggm_nodes": [],
            "salts": [],
            "merkle_nodes": [],
            "fine_root": None,
            "openings": [],
        }

    ggm_nodes = [
        {"level": level, "index": index, "seed": seed_at(root, level, index).hex()}
        for (level, index) in used_ggm_nodes(n, depth)
    ]
    salts = [
        {"index": i, "salt": salt_of(root, depth, i).hex()} for i in range(n)
    ]

    nodes: "list[tuple[int, int]]" = []
    content_nodes(0, n, nodes)
    # Ordered by subtree WIDTH then first leaf, i.e. level by level from the
    # leaves up — the reading order of "each Merkle level under RFC 6962
    # unbalanced promotion". The last entry is always the root.
    nodes.sort(key=lambda span: (span[1] - span[0], span[0]))
    merkle_nodes = []
    for first, end in nodes:
        level, index = canonical_slot(first, end, n, depth)
        merkle_nodes.append(
            {
                "first": first,
                "end": end,
                "level": level,
                "index": index,
                "hash": subtree_hash(root, depth, content, first, end).hex(),
            }
        )

    built = []
    for opening_name, start, length in openings:
        end = start + length
        cover = minimal_cover(start, end, n, depth)
        built.append(
            {
                "name": opening_name,
                "start": start,
                "length": length,
                "revealed_bytes": content[start:end].hex(),
                "releases_s_root": cover == [(0, 0)],
                "cover": [
                    {
                        "level": level,
                        "index": index,
                        "seed": seed_at(root, level, index).hex(),
                    }
                    for (level, index) in cover
                ],
                "boundary": [
                    {"level": level, "index": index, "hash": node.hex()}
                    for (level, index, node) in boundary_path(
                        root, depth, content, n, start, end
                    )
                ],
            }
        )

    return {
        "name": name,
        "n": n,
        "depth": depth,
        "slot_count": 1 << depth,
        "ggm_nodes": ggm_nodes,
        "salts": salts,
        "merkle_nodes": merkle_nodes,
        "fine_root": subtree_hash(root, depth, content, 0, n).hex(),
        "openings": built,
    }


def selftest(root: bytes) -> None:
    """Refuse to emit from an unchecked reference (testdata/README.md rule 2).

    The spec's own worked statements, restated as assertions: the MSB-first
    leaf path at n = 6, the n = 1 salt rule, the two normative cover KATs, and
    the leaf-exactness invariant the covers exist to satisfy.
    """
    # MVP-SPEC.md line 96 / tasks/G.md G8: at n = 6 (d = 3) leaf 2's path is
    # bits (0, 1, 0) MSB-first — the single most load-bearing line here.
    assert path_bits(2, 3) == [0, 1, 0], path_bits(2, 3)
    assert path_bits(1, 3) == [0, 0, 1]
    assert path_bits(4, 3) == [1, 0, 0]
    # d = 0 (n = 1): salt_0 = s_root[..16], with zero derivation steps.
    assert salt_of(root, 0, 0) == root[:SALT_LEN]
    # tasks/G.md G11's two normative KATs.
    assert minimal_cover(2, 3, 6, 3) == [(3, 2)]
    assert minimal_cover(4, 6, 6, 3) == [(1, 1)]
    # Full range => exactly the root, i.e. s_root itself.
    assert minimal_cover(0, 6, 6, 3) == [(0, 0)]
    assert minimal_cover(0, 5, 5, 3) == [(0, 0)]
    # RFC 6962 promotion: the left subtree is the largest perfect one.
    assert [rfc6962_split(w) for w in [2, 3, 4, 5, 6, 7, 8, 9]] == [
        1, 2, 2, 4, 4, 4, 4, 8
    ]
    # Leaf-exactness, exhaustively over every range of every case's n: no
    # emitted node may cover a real leaf outside the revealed range.
    for _, content, _ in CASES:
        n = len(content)
        depth = depth_for_leaf_count(n)
        if depth is None:
            continue
        for start in range(n):
            for end in range(start + 1, n + 1):
                covered = set()
                for level, index in minimal_cover(start, end, n, depth):
                    node_first = first_slot(level, index, depth)
                    for leaf in range(node_first, min(node_first + slot_width(level, depth), n)):
                        assert leaf not in covered, "cover nodes overlap"
                        covered.add(leaf)
                assert covered == set(range(start, end)), (n, start, end, covered)
    print("reference self-test: OK", file=sys.stderr)


def build_document() -> dict:
    root = s_root()
    selftest(root)
    return {
        "schema": "antseal-golden-vector",
        "schema_version": 1,
        "format_version": "v1",
        "kind": "fine-tree",
        "non_secret": NON_SECRET,
        "description": DESCRIPTION,
        "inputs": {
            "w": W.hex(),
            "s_root_label": S_ROOT_LABEL.decode("ascii"),
            "cases": [
                {
                    "name": name,
                    "content": content.hex(),
                    "openings": [
                        {"name": opening, "start": start, "length": length}
                        for (opening, start, length) in openings
                    ],
                }
                for (name, content, openings) in CASES
            ],
        },
        "expect": {
            "s_root": root.hex(),
            "cases": [build_case(root, *case) for case in CASES],
        },
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


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Regenerate or verify the G15 GGM/fine-tree golden vectors."
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="re-derive and byte-compare the committed vector instead of writing it",
    )
    args = parser.parse_args()

    produced = json.dumps(build_document(), indent=2) + "\n"
    if args.check:
        return check_committed(HERE / "fine-tree.json", produced)
    sys.stdout.write(produced)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
