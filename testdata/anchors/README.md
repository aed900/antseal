# anchors/ — recorded anchor fixtures

Home for **A**'s recorded anchor material (A24/A25, Q16): real OTS calendar
responses and `.ots` upgrade states (pending → Bitcoin-attested), real TSA
tokens (FreeTSA ECDSA P-384, DigiCert) over fixture digests, the mainnet
block headers those attestations name, and the pinned root-store snapshots
they verify against. CI replays these recordings exclusively — the anchor
tests make **zero real anchor-network calls** (rate-limit/ToS respect, Q16).
Since 2026-08-06 that is **enforced** by
`crates/antseal-anchor/src/http/offline.rs`, which refuses any non-loopback
endpoint from inside the HTTP substrate, and by `scripts/ci-lanes.sh
anchor-net-policy`; the policy is `docs/testing/anchor-ci-policy.md`. The
capture/refresh procedure is `docs/anchors/real-smoke-runbook.md`.

Captures here are **append-only in practice**: a pending `.ots` body can
never be re-taken once its commitment is upgraded, so a refresh commits
beside an old capture, never over it.

## The four campaigns

Each carries a `README.md` or equivalent provenance record (runbook §4). File
counts are as of each campaign's capture date and grow by appending, never by
replacement.

Three of the four record their maintainer authorisation verbatim in their own
log, which is what runbook §1 requires; **`A16-A17-live/` does not**, and
relies on the M2-wide permission granted the previous day, which §1 says in as
many words is not consent for a new run. Its README states the gap rather than
papering over it. `A16-A17-live/CAPTURE.log` also omits the per-request
SHA-256 and per-request UTC that §4 requires. Both campaigns predate the
runbook; neither gap is a licence to repeat it.

| directory | captured | files | what it holds |
| --- | --- | --- | --- |
| `A25-bootstrap/` | 2026-08-02, upgraded 2026-08-03 | 61 | The OTS and TSA half. Six **pending** calendar timestamps over two golden-vector digests at three live calendars, and in `upgraded/` their six **Bitcoin-attested** upgrades plus the hard-error `Not found` bodies; nine live TSA request/response pairs (`D60-*`); five root certificates with provenance (`roots-*`). Prose: `OTS-BOOTSTRAP.md`, `roots-PROVENANCE.md`, `upgraded/PROVENANCE.md`. |
| `A16-A17-live/` | 2026-08-03 | 12 | The must-agree half. The esplora pair over block 800000 plus its agreed-absence `404` bodies, and the Arbitrum RPC pairs on mainnet and Sepolia — the fixtures behind the finding that two honest RPCs differ byte-for-byte and must be compared on the extracted tuple. |
| `A25-upgrade-headers/` | 2026-08-07 | 14 | The promotion half. The 80-byte mainnet headers for **960767 / 960768 / 960771** — the blocks `A25-bootstrap/upgraded/` actually attests — from both esplora endpoints, byte-identical, each verified offline by `double-SHA256(header) == claimed block hash`. Reads only; no digest was sent. |
| `A25-wave16-cycle/` | 2026-08-11 (day-1 submits 12:46Z; day-2 ~17:55Z through `scripts/anchor-smoke`) | 23 | The product's-own-calendars cycle — and the first campaign driven by antseal's own clients. Day-1: eight **pending** submissions — the same two golden-vector digests at the four `DEFAULT_OTS_CALENDARS` pool endpoints (D54's set), which **no earlier campaign had stamped**: the bootstrap's hosts were the `*.btc.calendar` names, and even catallaxy differs (`ots.btc.catallaxy.com` vs `btc.calendar.catallaxy.com`). All eight `200`, by hand. Day-2, under its own fresh consent: six **Bitcoin-attested** upgrades via A14 in `upgraded/` (both eternitywall pendings honestly `not-yet-confirmed`, re-pollable); FreeTSA + DigiCert request/response pairs, both `Proven` against the pinned store via A10 (`TSA-CAPTURE.log`); the agreed esplora header for 960767 and the agreed Arbitrum tuple via A16/A17 (`MUSTAGREE-CAPTURE.log`). Consent recorded verbatim in every log header per runbook §1 (D126). |

The **pending** bodies in `A25-bootstrap/` are the irreplaceable ones: those
six commitments will never serve a pending body again, and a fresh stamp
would be a different and later timestamp.

## Captures quoted by a frozen golden vector (D101 RULING 6c)

Since **A22** (2026-08-09) some files here are quoted verbatim, as hex, inside
`testdata/vectors/v1/anchor/anchor.json`: the two `D60-tsa-{freetsa,digicert}-resp.tsr`
tokens, `merged-A.ots`, `merged-B.ots`, the three `upgraded/A-*.upgrade`
bodies, and `A25-upgrade-headers/esplora-*-header-960767.txt`.

**Those captures are retained.** The vector is the authoritative copy and is
frozen; this directory is its provenance of record. Deleting a quoted capture
does not break CI — deliberately, because a standing equality test between a
frozen file and an unfrozen one is a lane whose red the frozen side is
forbidden to fix (D101 RULING 6b). It breaks the **audit trail**, which is
worse because it is silent.

The vector names each source path verbatim in `inputs.cases[].provenance`, and
`testdata/vectors/v1/anchor/gen_vectors.py --check` re-derives the quoted bytes
from this directory on the `cross-check` lane — so a moved or edited capture is
visible there, as a re-derivation mismatch, rather than as a permanently red
required lane.

Anchor fixtures contain real *public* cryptographic material (certificates,
tokens, calendar proofs, block headers) — permitted; the secret-material
convention (`../README.md`) bars only private/secret material. Every digest
ever anchored from here derives from the documented fixed test seed and was
already committed golden-vector material before it was stamped, so no
submission disclosed anything new.
