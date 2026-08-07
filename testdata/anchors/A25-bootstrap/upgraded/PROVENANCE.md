# The upgraded `.ots` bootstrap fixture — **not an A25 capture**

**NON-SECRET.** Public Bitcoin mainnet timestamp data. No private or secret
material is present or derivable here.

## Read this before citing anything measured against it

`rust-opentimestamps-LARGE_TEST.ots` is **not** a fixture this project
captured. It is the `LARGE_TEST` constant from
`opentimestamps-0.2.0/src/lib.rs:54-113` — a genuine OpenTimestamps proof over
Bitcoin blocks **449397** and **449399** (≈ January 2017), extracted verbatim
from the crate source and written out as the bytes it already was.

It is here because, **when it was written on 2026-08-02, no real upgraded
`.ots` of this project's own existed**. A25's OTS cycle is wall-clock-bound —
a calendar aggregates submissions, commits the aggregate root to Bitcoin, and
only then can a timestamp be upgraded from `pending` to a Bitcoin
attestation. The pending half was captured 2026-08-02T19:16Z
(`../CAPTURE.log`, `../OTS-BOOTSTRAP.md`), and A11 and A12 landed before the
upgraded half could exist, so this stood in.

**Corrected 2026-08-07.** The paragraph above said the upgraded half "cannot
be captured before **2026-08-04**" and that no real upgraded `.ots` existed —
and it stayed on disk saying so for four days after both claims died. **The
six files sitting in this very directory falsify it**: `{A,B}-{alice,bob,
catallaxy}.upgrade`, captured **2026-08-03T09:03Z**, all `200`, each carrying
a real Bitcoin attestation (`UPGRADE-CAPTURE.log`). The wait was **13 h 47 m**,
not the ~48 h this file assumed. Since **2026-08-07** the mainnet headers for
the three attesting blocks — 960767, 960768, 960771 — are captured too
(`../../A25-upgrade-headers/`), which closes the gap §"What it does **not**
establish" below is about. Read that section with this correction in hand: it
is still accurate about *this* file, and no longer accurate about the tree.

**Four rows of the F4 registry (`docs/format/anchor-artifact-limits.md` §5)
are bootstrapped from this file and say so in their `measured against` cell:**
`MAX_OTS_OPS`, `MAX_OTS_DEPTH`, `MAX_OTS_ATTESTATIONS` and
`MAX_OTS_OPERAND_BYTES`/`MAX_OTS_VALUE_BYTES`. They **must be re-measured
against the real fixture and appended.** The values do not change — F4 forbids
lowering and no margin is close — but the provenance cell must stop citing a
third-party crate's test constant.

*Attribution corrected 2026-08-07: this said "**A25** must re-measure them",
as `docs/format/anchor-artifact-limits.md:251,258` still does. The task is
**A48(a)**, which was written for exactly this and lists A25 only as a
dependency. That dependency is discharged — the six real upgraded `.ots` beside
this file have existed since 2026-08-03.*

## What it is, measured

Measured by `antseal_core::anchor::ots::parse_ots_measured`, i.e. by the
parser that enforces the limits, and cross-checked by an independently
written length-respecting scanner:

| quantity | value |
| --- | --- |
| size | 1 768 B |
| start digest | `6fd9c1c4f096b77e6d4457bac1c7f51010d318db483f2868d3795843f098d378` |
| ops | 100 (21 append, 21 prepend, 58 sha256) |
| max depth (op edges, root at 0) | **67** |
| fork nodes / max width | 3 / 2 |
| attestations | 4 — 2 pending + 2 bitcoin |
| max append/prepend operand | 174 B (the coinbase-transaction prefix) |
| max running value | 210 B |
| max attestation payload | 46 B (a pending URI); the Bitcoin payloads are 3 B |

| attestation | value |
| --- | --- |
| pending | `https://bob.btc.calendar.opentimestamps.org` |
| bitcoin, height **449399** | merkle root `1a1da26714e8ef3b140c5f461ee52ea6fb5d8ca8e02d73370b5b416265eb1f5e` |
| pending | `https://alice.btc.calendar.opentimestamps.org` |
| bitcoin, height **449397** | merkle root `7c17a8a0d6bc1da3604ecd442fc38869983290dcbc4876bdf0fcf133791ff218` |

D58 §7.5's table records **depth 69** for this file. Under D58 §9.3's own
normative definition — *"edges from the root step, root at 0 … a chain of `N`
ops terminated by an attestation has maximum depth `N`"* — it is **67**: an
attestation is a leaf hanging off a node, not a node of its own. Recorded
rather than silently applied; the direction is safe (the margin grows) and F4
forbids lowering, so no value moves. Every other number in D58 §7.5's table
reproduced exactly.

## What it does **not** establish

**The merkle-root byte order is not empirically pinned by this file.** The
roots above are the values the ops derive; verifying that they are the
`merkle_root` field of the real blocks 449397/449399, in that byte order,
needs a fetched mainnet header, and A12's `Do` asks for exactly that pin
*"by a real upgraded fixture"*. That is **A25's**, with the rest of the
re-measurement. **Status 2026-08-07: the header half of that pin now exists,
the derivation half does not.** `../../A25-upgrade-headers/` carries the
80-byte headers for 960767/960768/960771 — the blocks the six `.upgrade`
files beside this one attest, not 449397/449399 — each verified offline by
`double-SHA256(header) == claimed block hash`. Comparing the `merkle_root`
those headers carry at bytes `36..68` against the root the `.upgrade` ops
derive is the step that actually pins the byte order, and it has **not** been
performed; it is **A48(b)**'s, and A48(b)'s last missing input was that header
fetch. Until the comparison is made, no file in this tree pins the order
empirically, and the only guard remains the structural one below. What A11/A12 establish offline is structural: each Bitcoin
attestation here is reached through a chain of 32-byte `append`/`prepend`
siblings each followed by `08 08` — double SHA-256 — which is Bitcoin's own
merkle algorithm operating on internal-order hashes, the order the header
stores. The implementation performs **no** reversal, and
`anchor::ots::header::tests::a_byte_reversed_merkle_root_does_not_match`
goes red if one is added.

## Licensing

`opentimestamps` 0.2.0 is `MIT OR Apache-2.0`. What is reproduced here is a
public Bitcoin timestamp proof — protocol and blockchain facts, not authored
expression — and no line of the crate's source is vendored, wrapped or pinned
(`docs/decisions/D58-opentimestamps-viability.md` §8: the crate is adopted in
no form). The extraction is deterministic and repeatable: read the
`LARGE_TEST` byte-string literal from the crate source and write out the bytes
it denotes.

`sha256(rust-opentimestamps-LARGE_TEST.ots)` =
`9b192789b96e8626284401b323e08567306697e17934d3c64eba343371f0e54d`
