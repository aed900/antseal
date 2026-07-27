# anchors/ — recorded anchor fixtures (RESERVED for M2)

Reserved home for **A**'s recorded anchor material (A24/A25, Q16): real OTS
calendar responses and `.ots` upgrade states (pending → Bitcoin-attested),
real TSA tokens (FreeTSA ECDSA P-384, DigiCert) over fixture digests, and
the pinned root-store snapshots they verify against. CI replays these
recordings exclusively — the anchor lane makes **zero real anchor-network
calls** (rate-limit/ToS respect, Q16); the capture/refresh procedure is the
Q16 runbook.

Empty until M2 by design. Anchor fixtures contain real *public*
cryptographic material (certificates, tokens, calendar proofs) — permitted;
the secret-material convention (`../README.md`) bars only private/secret
material. Fixture digests being anchored derive from the documented fixed
test seed.
