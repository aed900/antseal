# anchors/ — recorded anchor fixtures (RESERVED for M2)

Reserved home for **A**'s recorded anchor material (A24/A25, Q16): real OTS
calendar responses and `.ots` upgrade states (pending → Bitcoin-attested),
real TSA tokens (FreeTSA ECDSA P-384, DigiCert) over fixture digests, and
the pinned root-store snapshots they verify against. CI replays these
recordings exclusively — the anchor tests make **zero real anchor-network
calls** (rate-limit/ToS respect, Q16). Since 2026-08-06 that is **enforced**
by `crates/antseal-anchor/src/http/offline.rs`, which refuses any non-loopback
endpoint from inside the HTTP substrate, and by `scripts/ci-lanes.sh
anchor-net-policy`; the policy is `docs/testing/anchor-ci-policy.md`. The
capture/refresh procedure is `docs/anchors/real-smoke-runbook.md`.

Captures here are **append-only in practice**: a pending `.ots` body can
never be re-taken once its commitment is upgraded, so a refresh commits
beside an old capture, never over it.

Empty until M2 by design. Anchor fixtures contain real *public*
cryptographic material (certificates, tokens, calendar proofs) — permitted;
the secret-material convention (`../README.md`) bars only private/secret
material. Fixture digests being anchored derive from the documented fixed
test seed.
