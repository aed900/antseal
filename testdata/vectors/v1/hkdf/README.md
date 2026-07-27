# HKDF-SHA256 golden vectors (C3) — format v1

Golden vectors for antseal's HKDF label registry — the derivation
`HKDF-SHA256(W, label, id)` with salt = empty, IKM = `W`, and
`info = u8(len(label)) ‖ label ‖ LE64(id)` (MVP-SPEC.md lines 76–77), one
vector per registered label (lines 91, 94–98).

**Everything in this directory is a NON-SECRET, fixed, public test fixture**
(project rule 6): the master secret `W` used here is the documented fixed
test seed — the byte pattern `00 01 02 … 1f` (see `testdata/README.md`,
"Secret-material convention") — and must never be a real secret. No real
vault material may ever appear in fixtures.

## Files

- `hkdf-labels.json` — the committed vectors in the Q4 golden-vector
  envelope (schema: `../../README.md`), kind `hkdf-labels`: the fixture `w`
  plus `(label, id, id_domain, info-bytes, output)` tuples for all 8
  registry labels. Discovered and executed by the native runner
  (`crates/antseal-core/tests/vector_runner.rs`); also verified directly by
  `crates/antseal-core/tests/hkdf_golden.rs` (the C3 accept anchor).
- `gen_vectors.py` — the independent reference implementation (Python
  stdlib `hmac`/`hashlib`/`json` only — no shared code with the Rust path)
  that produced the file. Run it only to *verify*; committed vectors are
  frozen at Q6 and retained forever (docs/dependency-policy.md §4). A byte
  change is a format event, justified explicitly, never regenerated
  silently.

## Migration note (Q2/Q4, 2026-07-27 — pre-freeze)

These vectors previously lived at `testdata/vectors/hkdf/hkdf-sha256-v1.txt`
in a bespoke line format. Q2 moved them into the per-format-version layout
(`vectors/v1/`) and Q4 re-containered them as an envelope vector file so the
generic runner executes them. The move happened **before the Q6 freeze**, so
it is not a format event; the derivation values (`w`, ids, `info`, `okm`
hex) are byte-identical to the original file (verified at migration by
field-wise comparison, and re-provable by running `gen_vectors.py`).

## Vector id choices

Ids exercise the LE64 encoding visibly: `0`, `1`, the distinctive
`0x0123456789abcdef` (its little-endian bytes `ef cd ab 89 67 45 23 01` are
the info tail of the `fine-seed` vector), and the sentinel
`0xffffffffffffffff` for the three no-natural-id labels (spec line 77).
`okm` length is the registry output length (16 or 32 bytes); hex is
lowercase throughout.

## WASM bit-match

The native runner verifies these vectors today. Executing the same
verification in the WASM build with a bit-match assertion joins Q5's
native↔WASM harness when it lands (MVP-SPEC.md line 167: the WASM build
must bit-match native verification; committed vectors are the medium — the
parse/execute logic already lives WASM-safe in
`antseal_core::test_util::vectors`, so Q5 only adds byte embedding and the
wasm test driver).
