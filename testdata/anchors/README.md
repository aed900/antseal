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

## The three campaigns

Each carries a `README.md` or equivalent provenance record (runbook §4). File
counts are as of 2026-08-07 and grow by appending, never by replacement.

Two of the three record their maintainer authorisation verbatim in their own
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

The **pending** bodies in `A25-bootstrap/` are the irreplaceable ones: those
six commitments will never serve a pending body again, and a fresh stamp
would be a different and later timestamp.

Anchor fixtures contain real *public* cryptographic material (certificates,
tokens, calendar proofs, block headers) — permitted; the secret-material
convention (`../README.md`) bars only private/secret material. Every digest
ever anchored from here derives from the documented fixed test seed and was
already committed golden-vector material before it was stamped, so no
submission disclosed anything new.
