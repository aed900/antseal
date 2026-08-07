# A25 day-3 capture — mainnet block headers for this project's own attestations

Captured **2026-08-07T10:36:32Z–10:37:34Z** (wave 9). Twelve requests, all
`200`. Campaign README per real-smoke-runbook §4.

## Consent

Maintainer authorisation was given in-session on **2026-08-07**: express
confirmation to fetch Bitcoin mainnet block headers for heights
960767/960768/960771 from `blockstream.info` and `mempool.space`. **Reads
only** — no submission, no account, no credentials, and no digest left the
machine in either direction. Public block data both ways. The authorisation
is recorded verbatim at the head of `CAPTURE.log`, which is the form runbook
§1 requires.

## Why this capture existed to be made

The six committed day-2 upgrade responses in `../A25-bootstrap/upgraded/`
carry **real Bitcoin attestations** — `alice` → 960767, `bob` → 960768,
`catallaxy` → 960771 (`UPGRADE-CAPTURE.log`, 2026-08-03T09:03Z). But the only
block headers committed anywhere in the tree were for height **800000**
(`../A16-A17-live/`), captured for A16's endpoint-agreement round and
unrelated to anything this project stamped.

So the project held a genuinely upgraded `.ots` over its own digest and
**could not promote it to `proven`**, because promotion needs the 80 header
bytes of the attesting block. `crates/antseal-anchor/src/ots/engine/tests.rs`
says so in place: *"this lane did not fetch a mainnet header for it (that
half is A48's)"*, and the existing upgrade test synthesises a zeroed header
with the derived root spliced into `36..68`.

These twelve files close that gap. A synthetic header cannot substitute: it
freezes a fabricated "Bitcoin header" forever and cannot exercise the `nTime`
byte-equality A18 found load-bearing.

## Contents

Per height ∈ {960767, 960768, 960771}, per endpoint ∈ {blockstream, mempool}:

| file | bytes | content |
| --- | --- | --- |
| `esplora-<ep>-height-<h>.txt` | 64 | block hash, lowercase hex, no trailing newline |
| `esplora-<ep>-header-<h>.txt` | 160 | the 80-byte header, lowercase hex, no trailing newline |

Paths and hosts were read from `crates/antseal-anchor/src/esplora.rs`
(`DEFAULT_ESPLORA_ENDPOINTS`, `ESPLORA_BLOCK_HEIGHT_PATH`,
`ESPLORA_BLOCK_PATH`, `ESPLORA_HEADER_SUFFIX`), never re-typed from this
document. If the two disagree, the code is right and this is stale.

## What was verified at capture time, offline

1. **Every header is authentic.** `double-SHA256(header)`, byte-reversed,
   equals the block hash the height lookup returned. This is checked per file
   and holds for all three heights — the header bytes are not taken on the
   endpoint's word.
2. **Both endpoints agree byte-for-byte** on all three headers and all three
   hashes. That is A16's must-agree rule exercised against live infrastructure
   for the first time since 2026-08-03, and it passed on the *extracted*
   object rather than on response framing.

## The finding this capture produced

The `nTime` fields date the attesting blocks:

| height | nTime | UTC |
| --- | --- | --- |
| 960767 | 1785701746 | 2026-08-02T20:15:46Z |
| 960768 | 1785702431 | 2026-08-02T20:27:11Z |
| 960771 | 1785704384 | 2026-08-02T20:59:44Z |

The digests were submitted at **2026-08-02T19:16Z**. So Bitcoin confirmed
them **59 to 103 minutes later, the same evening** — while the calendars did
not *serve* the upgraded proof until **2026-08-03T09:03Z, 13 h 47 m** after
submission.

Those are two different latencies and the tree had only measured the second.
`OTS-BOOTSTRAP.md` already corrected its own "~48 h" draft down to 13 h 47 m;
this capture shows even that figure is not Bitcoin's — it is the calendar's
aggregation-and-serving cadence. **The chain was done in about an hour.**
Anything that reasons about how long an OTS anchor takes to become provable
should cite the calendar, not the block interval.

## Retention

These are inputs to A25's `--online` promotion, A48(b)'s empirical
merkle-root byte-order pin, and A12. They are public consensus data over
already-public golden-vector digests: no secret material, nothing
correlatable to a real user's work-id.
