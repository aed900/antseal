# testdata/

Fixture tree for antseal (MVP-SPEC.md, Architecture). This README fixes the
layout (P5); fixture content is owned by the C (crypto), F (formats), G
(canonicalization/units/fine tree) and Q (test infrastructure) domains and
lands with their milestones.

Layout:

- `vectors/` — committed golden vectors for derivation/crypto primitives,
  each subdirectory self-documenting via its README. First resident:
  `vectors/hkdf/` (C3) — HKDF-SHA256 label-registry vectors from a fixed
  NON-SECRET `W`, verified by `crates/antseal-core/tests/hkdf_golden.rs`.
  Committed vectors are retained forever. (C)
- `golden/` — golden vectors: exact canonical bytes (plus digests) for every
  versioned format — manifest, bundle, commitments — cross-checked against an
  independent CBOR implementation. Committed vectors are retained forever.
  (F/Q; intended)
- `utf8-corpus/` — UTF-8 canonicalization corpus: NFC, LF, BOM and other edge
  cases; idempotence and cross-platform stability inputs. (G)
- `tamper-matrix/` — mutated manifests/bundles: every mutation class must
  fail verification with a distinct error. (Q, fed by F/C)
- `fine-tree/` — fine-tree range-proof fixtures for selective disclosure
  (leaf/node domain separation, boundary ranges). (G)

Rules: fixtures are deterministic (seeded RNG only), and no secret material
ever appears here — master secrets, unit keys and salts live only in vaults,
never in test fixtures.
