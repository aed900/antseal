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

## Re-measured 2026-08-10 (A48(a)) — three rows moved, two did not

Five rows of the F4 registry (`docs/format/anchor-artifact-limits.md` §5) were
bootstrapped from this file. **A48 re-measured all five** against the artifact a
verifier actually parses — the three-way splice recorded below, measured with
`anchor::ots::parse_ots_measured`, the parser that enforces the limits.

| row | bootstrapped here | re-measured | outcome |
| --- | --- | --- | --- |
| `MAX_OTS_OPS` | 100 | **244** | moved off this file; margin 40.96x → 16.79x |
| `MAX_OTS_DEPTH` | 67 | **85** | moved off this file; margin 15.28x → 12.05x |
| `MAX_OTS_ATTESTATIONS` | 4 | **6** | moved off this file; margin 64.00x → 42.67x |
| `MAX_OTS_OPERAND_BYTES` | 174 B | 89 B | **stays here** — this file is larger |
| `MAX_OTS_VALUE_BYTES` | 210 B | 125 B | **stays here** — this file is larger |

**No value changed**, so no §6 limit-change entry is owed; the margins moved,
which §5's Update rule classes as something learned *about* an unchanged limit.

**The last two rows are the finding, and they invert this file's status.** Its
operands are a real fat coinbase-transaction prefix; the antseal artifact's are
32-byte merkle siblings and a 44-byte calendar commitment. So this file measures
**larger** on both byte limits, and re-pointing those cells would have *raised*
the recorded margins — 94.16x → 184.09x and 156.04x → 262.14x — by discarding
the fatter real sample. A margin claims something about the worst real artifact
known, not the most recently captured one. This file is therefore **kept and
demoted to what A48's Accept row 3 offers** — *"a second, independent upgraded
shape"* — still binding for two limits and no longer standing in for anything.

*Attribution corrected 2026-08-07: this said "**A25** must re-measure them", as
`docs/format/anchor-artifact-limits.md` did at `:251,258` until **2026-08-10**,
when **A106** corrected it there. The task was **A48(a)**, which lists A25 only
as a dependency; that dependency was discharged 2026-08-03. For three days the
correction existed in this file and nowhere else, which is the whole reason A106
was a row rather than a footnote.*

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
*"by a real upgraded fixture"*. **Status 2026-08-10: done, and not against this
file.** `../../A25-upgrade-headers/` carries the
80-byte headers for 960767/960768/960771 — the blocks the six `.upgrade`
files beside this one attest, not 449397/449399 — each verified offline by
`double-SHA256(header) == claimed block hash`. **A48(b)** compares the
`merkle_root` those headers carry at bytes `36..68` against the root the
`.upgrade` ops derive, at all three heights, in
`crates/antseal-core/tests/anchor_vectors.rs`'s
`vector_anchor_ops_derive_the_fetched_mainnet_headers_merkle_root`; the same row
asserts the match vanishes under a byte reversal. The sentence this paragraph
carried until 2026-08-10 — *"it has **not** been performed"* — is spent.
**This file still pins nothing empirically**, and its structural guard is the
one below; the empirical pin belongs to the artifact derived from the six
`.upgrade` bodies, not to the borrowed proof.
What A11/A12 establish offline is structural: each Bitcoin
attestation here is reached through a chain of 32-byte `append`/`prepend`
siblings each followed by `08 08` — double SHA-256 — which is Bitcoin's own
merkle algorithm operating on internal-order hashes, the order the header
stores. The implementation performs **no** reversal, and
`anchor::ots::header::tests::a_byte_reversed_merkle_root_does_not_match`
goes red if one is added.

## The three-way splice these bodies derive (A22, D103 RULING 3b)

Written by **A22**, owned by **A25**. The six `*.upgrade` files here are
calendar **response bodies**, not `.ots` containers — no magic, no header, no
digest — so no upgraded `.ots` over this project's own digest exists as a file
anywhere in the tree. `testdata/vectors/v1/anchor/` needs one, and derives it.

**The rule.** `merge_upgrade`'s entire byte effect is a splice
(`crates/antseal-anchor/src/ots/container.rs:252-268`):

```text
out = file[..offset] ‖ 0xff ‖ body ‖ file[offset..]
```

at an `offset` found by a literal byte search for the pending attestation's
wire encoding (`:211-237`), whose occurrence count must equal the parser's.
No hash, no key, no judgement.

**The order is part of the ruling** (D103 §4.2): `pending_refs`' document
order over the **current** stored artifact at each step, re-located each time.
For `merged-A.ots` that is alice → bob → catallaxy. A different order produces
different bytes.

| step | bytes | ops | depth | attestations |
| --- | --- | --- | --- | --- |
| `../merged-A.ots` | 664 | 34 | 12 | 3 |
| `+ A-alice.upgrade` | 1 665 | 101 | 79 | 4 |
| `+ A-bob.upgrade` | 2 702 | 171 | 80 | 5 |
| `+ A-catallaxy.upgrade` | **3 808** | **244** | **85** | **6** |

`sha256 = c2bf8b2c22055061f7105c357459969d4bb62d397f95001a70f570fed88e0c68`

The digest-B walk is the same shape: **3 773 B**, 242 ops, depth 83,
`sha256 = 759adb377136d97099695cd6f727c9c85b8578b97e8c3f31ee61072ec1d156f8`.

**Where the bytes live.** In `testdata/vectors/v1/anchor/anchor.json`, as
cases 4, 5 and 6, and **not** as a file here: it is derived, and D101
RULING 6 already settles authority — the vector copy is authoritative, this
directory is provenance, and a third unfrozen copy of derived bytes would be a
copy with no rule attached to it (D103 RULING 3a).

**Two producers, one number.** `testdata/vectors/v1/anchor/gen_vectors.py`
performs the splice in Python, and
`crates/antseal-anchor/src/ots/upgrade/tests.rs::the_three_way_splice_reaches_the_committed_vector_digest`
runs the *shipped* `merge_upgrade` over the same inputs and asserts the same
SHA-256 and the same four intermediate byte counts (D103 RULING 2a).

**The attested heights are 960767 / 960768 / 960771** — alice, bob and
catallaxy respectively, one artifact carrying three Bitcoin branches at three
heights, which is what three operators on independent aggregation schedules
looks like.

### The byte-order comparison above **has now been performed**

The section before this one reads *"Comparing the `merkle_root` those headers
carry at bytes `36..68` against the root the `.upgrade` ops derive is the step
that actually pins the byte order, and it has **not** been performed"*. As of
2026-08-09 it has, for all three heights, with no byte reversal:

| height | ops-derived root | `header[36..68]` | match |
| --- | --- | --- | --- |
| 960767 | `74ce7464…ab53233a` | `74ce7464…ab53233a` | yes |
| 960768 | `a921c752…14798ae5` | `a921c752…14798ae5` | yes |
| 960771 | `d303b654…92b537a7` | `d303b654…92b537a7` | yes |

Each header was re-verified offline first
(`double-SHA256(header)`, reversed, equals the committed
`../../A25-upgrade-headers/esplora-*-height-<h>.txt`), and both endpoint
captures are byte-identical.

It is now pinned **empirically and in CI**, not merely measured once: the
`anchor` vector's case 4 renders `attested` and case 5 renders `proven`, and
both require `check_embedded_header` to return `Committed`, which is exactly
this comparison. A reversal would move those two verdicts and turn the
`golden-vectors`, `vector-freeze` and `wasm-bitmatch` lanes red together.

**This closed A48(b) on 2026-08-10.** The paragraph above read *"This does not
close A48(b), which owns the pin and its own accept wording"* — true when
written, because the comparison had been *performed* but not *committed as a
named test*, which is what A48(b)'s Accept asks for. It now is:
`crates/antseal-core/tests/anchor_vectors.rs`'s
`vector_anchor_ops_derive_the_fetched_mainnet_headers_merkle_root` re-derives
the roots from the frozen artifact, reads the headers from the two committed
captures, asserts both endpoints agree, and asserts the match vanishes under a
reversal — at all three heights, offline, with no network and no new capture.

**The three ops-derived roots, in full**, so this table is checkable by hand
against `../../A25-upgrade-headers/*.txt` bytes `36..68` (hex offsets 72..136):

| height | ops-derived root = `header[36..68]` |
| --- | --- |
| 960767 | `74ce7464d6ae1ec81e9415300e713a90178ad207e543b717ffe4d929ab53233a` |
| 960768 | `a921c752f258a56865c74fed7e1c01739ce441cb4cc5a17f018de06314798ae5` |
| 960771 | `d303b6540d476819dac860d4785542fcba2c99a385a93dac23e41be192b537a7` |

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
