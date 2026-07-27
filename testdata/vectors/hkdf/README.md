# HKDF-SHA256 golden vectors (C3)

Golden vectors for antseal's HKDF label registry — the derivation
`HKDF-SHA256(W, label, id)` with salt = empty, IKM = `W`, and
`info = u8(len(label)) ‖ label ‖ LE64(id)` (MVP-SPEC.md lines 76–77), one
vector per registered label (lines 91, 94–98).

**Everything in this directory is a NON-SECRET, fixed, public test fixture**
(project rule 6): the master secret `W` used here is the byte pattern
`00 01 02 … 1f` and must never be a real secret. No real vault material may
ever appear in fixtures.

## Files

- `hkdf-sha256-v1.txt` — the committed vectors: `(label, id, id_domain,
  info-bytes, output)` tuples for all 8 registry labels, plus the fixture
  `w`. Verified by `crates/antseal-core/tests/hkdf_golden.rs`.
- `gen_vectors.py` — the independent reference implementation (Python
  stdlib `hmac`/`hashlib` only — no shared code with the Rust path) that
  produced the file. Run it only to *verify*; committed vectors are frozen
  and retained forever (docs/dependency-policy.md §4; Q6). A byte change is
  a format event, justified explicitly, never regenerated silently.

## File format (`hkdf-sha256-v1.txt`)

- `#` lines and blank lines are comments.
- `w = <hex>` — the 32-byte NON-SECRET fixture master secret.
- One `vector` line per registry entry:
  `vector label=<ascii> id=0x<16 hex digits> id_domain=<unit_id|file_id|sentinel> info=<hex> okm=<hex>`
- Hex is lowercase; `id` is the numeric value (its LE64 encoding is the last
  8 bytes of `info`); `okm` length is the registry output length (16 or 32
  bytes). Sentinel id = `0xffffffffffffffff` (spec line 77).

The format is deliberately trivial so an independent implementation can
consume it without a parser dependency.

## Vector id choices

Ids exercise the LE64 encoding visibly: `0`, `1`, the distinctive
`0x0123456789abcdef` (its little-endian bytes `ef cd ab 89 67 45 23 01` are
the info tail of the `fine-seed` vector), and the sentinel for the three
no-natural-id labels.

## WASM bit-match

The native test suite verifies these vectors today. Executing the same
verification in the WASM build with a bit-match assertion joins Q5's
native↔WASM harness when it lands (MVP-SPEC.md line 167: the WASM build
must bit-match native verification; committed vectors are the medium).
