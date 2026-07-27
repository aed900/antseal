# testdata/

Fixture tree for antseal (MVP-SPEC.md, Architecture). **Nothing is stored
here yet** — this README only fixes the intended layout (P5). Fixture content
is owned by the F (formats), G (canonicalization/units/fine tree) and Q (test
infrastructure) domains and lands with their milestones.

Intended layout:

- `golden/` — golden vectors: exact canonical bytes (plus digests) for every
  versioned format — manifest, bundle, commitments — cross-checked against an
  independent CBOR implementation. Committed vectors are retained forever.
  (F/Q)
- `utf8-corpus/` — UTF-8 canonicalization corpus: NFC, LF, BOM and other edge
  cases; idempotence and cross-platform stability inputs. (G)
- `tamper-matrix/` — mutated manifests/bundles: every mutation class must
  fail verification with a distinct error. (Q, fed by F/C)
- `fine-tree/` — fine-tree range-proof fixtures for selective disclosure
  (leaf/node domain separation, boundary ranges). (G)

Rules: fixtures are deterministic (seeded RNG only), and no secret material
ever appears here — master secrets, unit keys and salts live only in vaults,
never in test fixtures.
