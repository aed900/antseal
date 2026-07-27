# D15 — ML-DSA signing mode: hedged vs deterministic

- **Status: RESOLVED — deterministic (rnd = 0³²)**
- **Date: 2026-07-27**

## Context

FIPS 204 defines two signing variants: hedged (default; fresh randomness
folded into each signature) and deterministic (rnd fixed to 32 zero bytes).
The choice affects golden-vector reproducibility (C16), the independent
cross-check (Q11), and the fips204 fallback story — verification is
unaffected either way (a verifier cannot and need not distinguish the two;
the mode is not encoded in the format). Register entry D15; blocks C13's
signing call and C16's vector shape.

Inputs captured at C11 (docs/research/C11-signature-probe.md):

- `ml-dsa =0.1.1`'s non-RNG signing path is deterministic (rnd = 0³²);
  hedged sits behind a `rand_core` feature.
- Deterministic signatures are cross-implementation byte-identical:
  `fips204 =0.4.6` produced byte-identical keygen **and** deterministic
  signatures from the same ξ during the probe.

## Decision

**All v1 ML-DSA-65 signing uses the deterministic variant** (FIPS 204
`Sign` with rnd = 0³²; the crate's non-RNG signing API). Hedged signing is
not used anywhere in v1. Verification remains strict/canonical per spec
line 97 and accepts any valid, canonical signature regardless of how it
was produced.

## Rationale

1. **Portable vectors**: C16 golden vectors and Q11's ACVP/fips204
   cross-checks are only byte-reproducible under deterministic signing —
   the probe already demonstrated ml-dsa ↔ fips204 byte-identity in this
   mode. Hedged signing would reduce signature vectors to
   verify-only checks.
2. **Fallback invisibility**: if a RUSTSEC advisory ever forces the
   `fips204` swap (D14's pinned-unconsumed fallback), deterministic mode
   makes the swap byte-invisible — a dependency change, not a behavioral
   event.
3. **Consistency**: Ed25519 (RFC 8032) is inherently deterministic; one
   signing discipline across both algorithms simplifies the C18
   round-trip property suite and the C16 vector layout.
4. **No RNG in the signing path**: keygen expands ξ from HKDF(W) and
   signing needs no OS randomness — fewer moving parts on every target.

## Residual risk (recorded)

Hedged mode exists to blunt fault/side-channel attacks on the signing
device. antseal signs in a short-lived CLI process on the sealer's own
machine (not an HSM/embedded signer exposed to induced faults), and the
signing key is per-work (derived from W), bounding blast radius. Accepted
for MVP; record in the threat model (C20/Q12/Q21). Because the mode is
not format-encoded, a future app version may switch to hedged signing
with no format bump and no effect on existing seals.

## Consequences

- C13 signs via the deterministic path and pins the exact call in code
  comments + tests (keygen-from-fixed-ξ and sign-fixed-body KATs).
- C16 commits deterministic signature vectors; Q11 cross-checks them
  against fips204/ACVP deterministic-mode material.
- D30 note: no new error surface (signing mode has none).
