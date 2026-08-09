# `anchor` vectors (A22) — the per-anchor verdict, pinned byte-identically

**What these pin.** `anchor.json` commits the **whole per-anchor verdict
object** — state, headline eligibility, verified time, source identity, fetch
date, diagnostic code, identity discriminant, the A39 suppressed-anomaly list
and the R12 report slot — for seven cases over four recorded artifacts, at one
fixed `verify_at_unix` against `TsaRootStore::pinned()`. That object is
exactly the surface the Q5 native↔wasm32 bit-match compares, so it is what
A22 Accept row 3 (and through it the M2 exit criterion, MVP-SPEC.md line 169)
certifies as byte-identical across targets.

Executor: `crates/antseal-core/src/test_util/vectors_anchor.rs`. Home,
`expect` field set and coverage assertions: **D101** as amended by **D103**.
Regenerator/emitter: `crates/antseal-core/tests/anchor_vectors.rs`.

## The seven cases

| # | case | artifact | inputs beyond the artifact | `state` | `[H]` | `identity_kind` | `suppressed` |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | `tsa-freetsa-p384` | `D60-tsa-freetsa-resp.tsr` (4 643 B) | `fetch_date_unix` 1 785 698 419 | `proven` | yes | `tsa-signer` | `[]` |
| 2 | `tsa-digicert-rsa` | `D60-tsa-digicert-resp.tsr` (6 007 B) | `fetch_date_unix` 1 785 698 426 | `proven` | yes | `tsa-signer` | `[]` |
| 3 | `ots-pending` | `merged-A.ots` (664 B) | no upgrade, no online | `pending` | no | `null` | `[]` |
| 4 | `ots-upgraded-offline` | spliced (3 808 B) | `upgrade{960767, header, 1 786 098 992}`, no online | `attested` | no | `null` | `[]` |
| 5 | `ots-upgraded-online-proven` | **same bytes** | same `upgrade` + `online[{960767, header}]` | `proven` | yes | `bitcoin-chain` | `[]` |
| 6 | `ots-upgraded-online-block-absent` | **same bytes** | same `upgrade` + `online[{960767, no-such-block}]` | `pending` | no | `null` | `["anchor-ots-online-block-absent"]` |
| 7 | `ots-wrong-seal` | `merged-B.ots` (629 B) | no upgrade, no online | `invalid` | no | `null` | `[]` |

Case 5's `verified_time_unix` is **1 785 701 746** — block 960767's `nTime`,
read from the **agreed** header and never from the embedded one (D56 §5).

Four of them are load-bearing in ways the table does not show.

- **Case 4 vs 5** is the pair D92 recorded as missing: same artifact bytes,
  differing only in `OnlineEvidence`. Case 4's `identity_kind: null` is not an
  absent identity — `AnchorOutcome::new` is *handed*
  `AnchorIdentity::BitcoinChain` and **drops** it because `attested` is not
  headline-eligible. That is A40's filter with its first OTS-side witness.
- **Case 6** is this document's only non-empty `suppressed`, and without it
  the field would be frozen having never carried a code — the "empty vs
  absent" ambiguity A39 exists to prevent, re-created inside the artifact
  meant to settle it (D103 §5.2). Its route: agreed `NoSuchBlock` at 960767
  makes O7 fire, which disqualifies O4; O5 then fires because the merged
  artifact still carries three pending attestations, and the O7 refutation is
  carried as the A39 anomaly. That is **D56 §4's anti-downgrade rule**, and it
  had no committed witness before this file.
- **Case 6's input is hypothetical.** `OnlineEvidence` is data a host
  supplies. The case pins what the rule does with an agreed absence; it does
  **not** claim block 960767 is absent. It is not.
- **Case 7** is the only thing that pins the top-level `anchor_digest`:
  without it every case's artifact matches, and the field would be pinned by
  nothing. It also promotes D56 §9's sharpest defect — *"an `.ots` for
  someone else's seal … would render `proven`"* — from the tamper matrix's
  **same-verdict** wasm32 tier to this file's **byte-identical** one
  (D101 §6.3).

## The one artifact that is not a file

Cases 4, 5 and 6 carry a **three-way merged+upgraded `.ots` over digest A**:
3 808 B, 244 ops, depth 85, 6 attestations, `sha256
c2bf8b2c22055061f7105c357459969d4bb62d397f95001a70f570fed88e0c68`. No such
file exists under `testdata/anchors/` and none is added: it is derived, and
D101 RULING 6 already settles authority — the vector copy is authoritative and
the archive is provenance, so a third unfrozen copy would be a copy with no
rule attached (D103 RULING 3a).

`gen_vectors.py` derives it from `merged-A.ots` plus the three committed
`upgraded/A-*.upgrade` bodies. The `A-*.upgrade` files are **calendar response
bodies, not containers** — no OTS magic, no header, no digest — which is why
D101 §9's rows 4/5 named an artifact that does not exist and D103 §2.1
replaced them.

The derivation is a byte splice with no judgement in it:

```text
out = file[..offset] ‖ 0xff ‖ body ‖ file[offset..]
```

at an offset found by a literal byte search for the pending attestation's wire
encoding (`crates/antseal-anchor/src/ots/container.rs:211-268`). The order is
part of the ruling — `pending_refs`' document order over the *current* stored
artifact at each step, re-located each time: **alice → bob → catallaxy**
(D103 RULING 3, §4.2), through 664 → 1 665 → 2 702 → 3 808 B.

The three Bitcoin branches derive merkle roots that byte-match `header[36..68]`
of the committed mainnet headers for 960767 / 960768 / 960771, each of which
double-SHA256s to its committed height lookup. That is why
`check_embedded_header` returns `Committed`, and why case 4 renders `attested`
rather than `pending`: **O4 precedes O5**, so the surviving pending branches do
not demote it. (The inverse of the trap `tasks/A.md:265` records for the
*forged*-header row, where forging breaks `committed` and O3/O4 fall through.)

## `gen_vectors.py` is a DERIVATION RECORD, not a cross-check

This matters, and a reader who assumes otherwise will look for a cross-check
nobody intended and conclude one was skipped.

For `crypto`, `fine-tree`, `hkdf` and `storage-address` the sibling
`gen_vectors.py` is an **independently written implementation** whose
agreement with Rust is the evidence (D31 tier T1). For `anchor` there is no
such implementation: reproducing `expect` means reproducing RFC 3161 chain
validation and the `.ots` evaluator, and a Python one would pin the same
judgement twice rather than check it (D101 §7.3).

So this generator emits **`inputs` only** — the committed, executable
statement of how the frozen inputs were obtained from `testdata/anchors/`.
Every `expect` value comes from the Rust executor's own `build_expect`, which
is the only implementation of the rules.

What `--check` verifies, on the `cross-check` lane that discovers it by glob:

1. the envelope and the whole `inputs` object, re-derived from
   `testdata/anchors/` and diffed against the committed bytes;
2. the **self-binding** half of `expect` — per case, `artifact_len` and
   `artifact_sha256` against `inputs.cases[].artifact_hex` (D101 §7.2's right
   link), the case names positionally, and `expect.verify_at_unix`.

(2) is arithmetic over the inputs, not a second evaluator. Its value is that
truncated, extended or edited hex fails on the same run that would otherwise
have produced a wrong verdict — including the shared artifact's three copies,
which must agree.

The container walk in the generator **self-tests before it is trusted**:
it must reproduce the tree's own committed shape measurements
(`crates/antseal-core/src/anchor/ots/tests.rs:243-269`) — `merged-A.ots` →
34 ops / depth 12 / 3 attestations, `rust-opentimestamps-LARGE_TEST.ots` →
100 / 67 / 4 — or it refuses to place a splice.

**The cross-check that does exist** is on the splice, and it is A14's:
`crates/antseal-anchor/src/ots/upgrade/tests.rs::the_three_way_splice_reaches_the_committed_vector_digest`
runs the *shipped* `merge_upgrade` three times over the same committed
fixtures and asserts the same SHA-256 this document carries. Two
independently written pieces of code, one committed number (D103 RULING 2a) —
and it is **not** D101 RULING 6b's refused archive-equality lane: it names no
vector file, reads no frozen path, and if the splice rule ever legitimately
changes it is *code* and is edited.

## The clock, measured per artifact and not normalised

Three claims, each true of the artifacts it describes (D103 RULING 8, §9.5):

1. **Cases 1 and 2 carry the capture host's own clock reading.** Measured
   against each token's `genTime`, that clock was **128 s slow for both**
   (freetsa `utc=…19:20:19Z` vs `genTime …19:22:27Z`; digicert `…19:20:26Z`
   vs `…19:22:34Z`). The log's headline of 129 s
   (`D60-CAPTURE.log:17-23`) is the largest of three probe offsets
   (+129/+128/+129) and **is not the figure for these two artifacts**. So
   `gen_time <= fetch_date` is **FALSE** for both cases; that is correct and
   no check may ever assert otherwise (A32, D59 §6(a)). The capture log is a
   record of what was observed at capture time and is **not edited** — the
   correction lives here and in the vector's `description`.
2. **Cases 4-6 carry `utc_start` of the 2026-08-07 header campaign**
   (1 786 098 992), which is the later of the group's two capture instants:
   the bodies were fetched 2026-08-03T09:03Z and the headers
   2026-08-07T10:36Z, and D79 makes the upgrade group all-or-nothing, so the
   group did not exist until its header did. That campaign recorded **no**
   clock offset, so this value's skew is unmeasured; it is the recorded
   instant and nothing more.
3. **No verification rule reads `fetch_date`.** It is pinned here as a
   pass-through: the verdict must echo the input unchanged and move nothing
   else (R72). The executor asserts that as a law over the document —
   `fetch_date` is non-null exactly when `inputs` supply a `fetch_date_unix`
   (TSA) or an `upgrade` group (OTS) — which is what makes the ruling
   checkable rather than merely written down (D103 RULING 5a).

The synthetic `ots_writer::FETCH_DATE` was refused for both cases: it is
eight days *before* the tokens were issued, it lives in a module this executor
may not name (below), and it would make `fetch_date` the only field in a
document of recorded artifacts that records nothing.

## `verify_at_unix = 1 786 100 000`

2026-08-07T10:53:20Z. Four constraints, all checked (D103 RULING 4b):

- after every `genTime` (latest 1 785 698 554);
- after every attesting `nTime` (latest 1 785 704 384);
- after every `fetch_date` (latest 1 786 098 992);
- before every signer certificate's `notAfter` — so cases 1 and 2 are
  `proven` and not `valid-at-stamping-cert-since-expired`.

The field is top-level and one document has one; a second vector file under
`anchor/` is the extension path for a different `verify_at`.

*(D103 §5.5 renders this instant as "2026-08-07T11:33:20Z". The value is the
one D103 rules — 1 786 100 000 — and it satisfies every constraint D103
checks; only the parenthetical rendering is off by 40 minutes. Recorded here
rather than silently corrected, because a decision record is immutable once
ruled.)*

## What this kind may not name, and why it fails as a BUILD

`crate::anchor::testing` is `#[cfg(any(test, feature = "test-util"))]`
(`crates/antseal-core/src/anchor/mod.rs:77`), and `crates/wasm-bitmatch`
takes `antseal-core` with `test-vectors` through a **normal** dependency
edge — the *smaller* feature. So every constant in that module (`MERGED_A`,
`DIGEST_A`, `UPGRADED_LARGE_TEST`, all of `ots_writer`, all of `tamper_rows`)
and `TsaRootStore::from_static` besides are invisible to the parity build.

An executor naming one would compile happily under
`cargo test -p antseal-core`, where `cfg(test)` is on, and **fail to build**
the single crate this kind exists to satisfy. The executor therefore names
none: every byte arrives as hex from this file, and every root comes from
`TsaRootStore::pinned()` (D103 RULING 7).

The same gate is why the untrusted-root, mock-CA and two-store cases are
**not** here and must not be moved here: a vector executor reaches exactly one
root store, and a shipped verifier has exactly one by construction (A6). Those
rows are permanently A21's, as in-module `#[cfg(test)]` tests that run under
`--lib` on wasm32 (D101 RULING 5, §6.3 — two mechanisms of different strength,
one exit criterion).

## Retention and movement

This file is frozen by `../FROZEN.sha256` and retained forever per Q6's
per-version policy. `anchor` is the **second** kind whose pinned bytes are a
function of the *verifier* rather than of the *format* (D94 §2a), and the D94
verdict-event escape in `scripts/vector-freeze.sh` is scoped to `report/`
**by path** — so an `anchor` vector cannot legally move. The three events that
could ever require one are listed in D101 §4.3; each needs its own record,
which is also where `verdict_event_ok` would be extended.

**Everything here is NON-SECRET** (project rule 6): real published timestamp
tokens, real calendar responses, a real mainnet block header, and a byte
splice of bytes that were all published. No key material, no vault material,
nothing derived from the fixed test seed `W`.
