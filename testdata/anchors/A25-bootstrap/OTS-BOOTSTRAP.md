# A25 bootstrap capture — OTS half

**NON-SECRET.** Real public OpenTimestamps calendar responses. No private
or secret material is present or derivable here.

## What this is

A25's real-endpoint smoke requires a **two-day OTS pending → upgraded
cycle**, which is wall-clock-bound: a calendar aggregates submissions,
commits the aggregate root to Bitcoin, and only then can the timestamp be
*upgraded* from `pending` to a Bitcoin attestation. The clock therefore has
to start before the code that will finally consume it exists — so this
capture was taken at the **start** of the M2 wave, and the tasks that
bootstrap from it (A5, A11, A13, A14, A25 — see their Notes in
`../../../tasks/A.md`) are re-run against the final artifacts at A25.

Maintainer authorisation for real-endpoint submission was given in-session
on 2026-08-02 (reads **and** submissions to public TSAs and OTS calendars,
throwaway test digests only).

## What was submitted

Two `anchor_digest` values, both already committed public golden-vector
material — nothing new was disclosed by stamping them:

| tag | digest | source vector |
| --- | --- | --- |
| A | `083f87df00fd5c703d35b883d83535644c686f9e53f1584d7df126abdabd69df` | `testdata/vectors/v1/manifest/manifest.json` |
| B | `3448b9f22d6d4de5b68e0c1ba28d56e8466aa5a01892835411f7c467b52e5e9c` | `testdata/vectors/v1/bundle/bundle.json` |

Both derive from the documented fixed test seed
(`test_util::TEST_MASTER_SECRET_W`), per `../README.md`'s convention.

Submission was a raw `POST <calendar>/digest` with the **32 raw digest
bytes** as the body, `Accept: application/vnd.opentimestamps.v1`. Response
bodies are stored verbatim as `<tag>-<calendar>.timestamp`; they are the
calendar's **serialized timestamp ops**, not complete `.ots` files — the
`.ots` container around them is A11/A13's work.

Per-request HTTP status, byte count, SHA-256 and UTC instant are in
`CAPTURE.log`. Submission window: **2026-08-02T19:16:18Z – 19:16:26Z**.

## Findings at capture time (evidence, not background)

- **`finney.btc.calendar.opentimestamps.org` failed DNS resolution** — one
  of the four calendars in the upstream client's traditional default set.
  It is not merely down; the name did not resolve. D54 owns the default
  calendar set and the rot policy this implies.
- `alice` and `bob` returned 207 B and 170 B respectively for both digests;
  `catallaxy` returned 220 B and 185 B. Three live calendars ≥ the spec's
  minimum of two (MVP-SPEC.md line ~106).
- An earlier attempt in the same session submitted an **empty** body
  (`xxd` is absent on this host, so hex→binary decoding silently produced a
  zero-byte file). Those responses were discarded, not committed, and the
  capture script now hard-fails unless the digest file is exactly 32 bytes.
  Recorded because the failure was silent on the client side and the
  calendars answered `200` — a submit path that does not check its own
  request length can stamp nothing and look successful.

## Day-2 procedure (the pending → upgraded half)

Not before **2026-08-04**. For each `<tag>-<calendar>.timestamp`, ask the
calendar for the upgrade:

    POST/GET <calendar>/timestamp/<commitment-hex>

The commitment is the calendar's own commitment operation output, read out
of the pending timestamp — A11's codec is what determines it, which is why
this half is deliberately left to the A13/A14 implementation rather than
scripted here in advance. Record the upgraded bytes beside the pending
ones, never over them: the **pending** state is itself a required fixture
(the `pending` anchor state, and the same-day-reveal case the spec calls
out at line ~136).
