# A16/A17 live-endpoint capture — the must-agree pairs

Captured **2026-08-03T08:20Z–08:34Z**. Ten response files plus `CAPTURE.log`.
Campaign README per real-smoke-runbook §4, written **2026-08-07**: the
campaign predates the requirement, and §4 applies to it the same way §1 does.

**NON-SECRET.** Public block and transaction data only. Nothing here is
antseal's own material — the transactions are third parties' public
mainnet/testnet transactions taken from head blocks, and block **800000** is a
public Bitcoin block from 2023-07-24T03:17:09Z, unrelated to anything this
project has stamped.

## Consent

**This log carries no §1 consent record, and that is recorded rather than
inferred.** `CAPTURE.log:1-13` states the owning tasks, the endpoint policy
and the secret-material position, but not an authorisation. The run took
place on 2026-08-03 under the M2-wide network permission granted 2026-08-02
that `../A25-bootstrap/D60-CAPTURE.log:3-4` cites — and the runbook's §1 says
in as many words that *"a previous authorisation is **not** consent for a new
run"*. Two campaigns record their authorisation verbatim in their own log
(`../A25-bootstrap/OTS-BOOTSTRAP.md:17-19`,
`../A25-upgrade-headers/CAPTURE.log:3-7`); this one does not.

The run was **reads only** — `GET`s of public block data and `POST`ed
JSON-RPC queries naming third parties' already-public transaction hashes. No
account, no credentials, no submission, and no antseal digest in either
direction. That is what makes the omission recoverable rather than a breach,
and it is not a reason to repeat it: the standard is the log, not the risk.

## Why this capture existed to be made

A16 rules that the two esplora endpoints must agree **byte-for-byte** on a
block header; A17 rules that the two Arbitrum RPCs must agree on a receipt.
Those are different rules, and the reason they are different had been
recorded in D55 §3 without the responses that showed it ever being committed
— so `receipt_facts_ignore_unknown_and_extra_keys`, which D55 §7 specifies in
terms of *"the two real committed Sepolia responses from §3"*, could not be
written as specified. These ten files are what A24's stub servers replay and
what makes that test writable.

## Contents

| file | bytes | content |
| --- | --- | --- |
| `esplora-{blockstream,mempool}-height-800000.txt` | 64 | block hash, lowercase hex, no trailing newline |
| `esplora-{blockstream,mempool}-header-800000.txt` | 160 | the 80-byte header, lowercase hex, no trailing newline |
| `esplora-{blockstream,mempool}-404-body.txt` | 15 | the absent-block body, exactly `Block not found` |
| `arbone-{arb1,drpc}-receipt.json` | 1786 / 1785 | `eth_getTransactionReceipt`, arbitrum-one, tx `0x06a5012d…b0b3` |
| `sepolia-{rollup,drpc}-receipt.json` | 6975 / 6974 | `eth_getTransactionReceipt`, arbitrum-sepolia, tx `0xdeae7e5f…ab21` |

Three further probes are recorded in `CAPTURE.log` but committed as no file:
`eth_chainId` against both endpoint pairs (`0xa4b1` / `0x66eee`), and an
absent-transaction query against both arbitrum-one endpoints (`"result":null`
from each — the `Absent` outcome, which is not `Lagging`).

Hosts and paths were read from `crates/antseal-anchor/src/` — the endpoint
lists are `DEFAULT_ESPLORA_ENDPOINTS` and `ARBITRUM_ONE_VERIFY_RPCS`, never
re-typed from this document. If the two disagree, the code is right and this
is stale.

## What was verified against the committed bytes, offline

Re-checked 2026-08-07 against the files as they sit here, not restated from
the log:

1. **The header is authentic.** `double-SHA256(header)`, byte-reversed, equals
   `00000000000000000002a7c4c1e48d76c5a37902165a270156b7a8d72728a054`, the hash
   the height lookup returned. The header bytes are not taken on the
   endpoint's word.
2. **The two esplora endpoints are byte-identical** on the header (160 B), on
   the height (64 B), and on the `404` body (15 B, no trailing newline).
3. **The two Arbitrum endpoints are not byte-identical, on either network** —
   1786 vs 1785 B and 6975 vs 6974 B, both first differing at the **third
   byte** — while the extracted tuple `(status, blockNumber, blockHash,
   transactionHash)` is **equal** in both pairs, and **no shared key holds a
   differing value** in either pair.

## The findings this capture produced

**Byte comparison is right for esplora and wrong for JSON-RPC, and the reason
is structural rather than a quirk of two vendors.** An esplora header is a
fixed-width 80-byte consensus object with no encoding freedom, so byte
identity is a property two honest endpoints cannot fail. A JSON-RPC response
is a serialization, and two honest endpoints differ in it for **two
independent reasons**, both present here:

- **Envelope key order.** `arb1` and `sepolia-rollup` emit
  `{"jsonrpc",…,"id",…,"result":…}`; both `drpc` endpoints emit
  `{"id",…,"jsonrpc",…,"result":…}`. This is what puts the first difference at
  the third byte of all four files.
- **Result key sets.** On Sepolia, `sepolia-rollup.arbitrum.io` carries
  `timeboosted` and `arbitrum-sepolia.drpc.org` carries `blobGasUsed`;
  neither carries the other's.

`CAPTURE.log:57-64` presents the envelope-order difference as *"a second,
independent reason"* holding on mainnet where D55 §3's key-set reason does
not. Measured against the committed bytes, the sharper statement is that on
**Sepolia both reasons apply at once**, and either alone is sufficient: a byte
comparator would report a lying endpoint for two honest ones on **every one of
these four responses**. Agreement is a property of the extracted tuple (D55
§3, D56).

**The absent cases are three different outcomes, not one.** An agreed `404`
+ `Block not found` from both esplora endpoints is `NoSuchBlock` (D56 rule
O7); `"result":null` from both RPCs is `Absent`; one RPC answering `null`
while the other returns a receipt is `Lagging`. Collapsing them loses the
distinction between "the chain does not have it" and "one endpoint has not
caught up".

**This log does not meet runbook §4's recording bar, and the missing field is
the load-bearing one.** §4 requires URL, HTTP status, byte count, **SHA-256**
and UTC instant *per request*. `CAPTURE.log` carries the URLs, the statuses
and the byte counts, but **no SHA-256 anywhere** and no per-request UTC —
only `utc_start`/`utc_end`. The SHA-256 is what would let a later reader
confirm that the ten files here are the byte strings the endpoints actually
returned; without it, "verbatim" rests on the capturer's word. The three A25
logs (`../A25-bootstrap/CAPTURE.log`, `.../upgraded/UPGRADE-CAPTURE.log`,
`../A25-upgrade-headers/CAPTURE.log`) do carry all four. Recorded here rather
than back-filled: hashing the committed files today would produce digests of
*these* files, which proves nothing about what arrived over the wire, and
would look exactly like the field §4 asks for.

**A clock caveat inherited from the same window.** `CAPTURE.log:12` records
that this host ran ~129 s slow (D90 §6.10). Every figure in that log is
therefore a byte count or an HTTP status and never a wall-clock comparison,
which is the same discipline `../A25-bootstrap/D60-CAPTURE.log:16-28` states
for `genTime`.

## Retention

These are inputs to A16, A17, A24's stub servers and D55 §7's receipt tests.
Unlike the pending `.ots` bodies in `../A25-bootstrap/`, they are
**reproducible** — block 800000 and both transactions are permanent public
records, so a later capture would return the same header and the same receipt
facts. What would *not* reproduce is the pair of serializations: envelope
ordering and result key sets are the endpoints' current behaviour and can
change without notice, which is exactly why the differing bodies are worth
keeping verbatim. Refresh by committing beside, never over (runbook §5).
