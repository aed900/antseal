# Golden vectors (Q4) — layout, envelope schema, runner contract

Committed golden vectors for every versioned antseal format, organised as
`vectors/<format-version>/…` (MVP-SPEC.md line 57; format-stability policy
line 123: **per-version vectors are retained in CI indefinitely** — Q6 adds
the append-only `FROZEN.sha256` freeze guard per version directory).

Everything here is NON-SECRET fixture material under the secret-material
convention in `../README.md`.

## Directory contract

```
vectors/
  README.md            # this file (aux)
  v1/                  # one directory per format version, name = v<integer>
    <component>/       # free-form grouping (hkdf/, manifest/, …)
      *.json           # vector files (envelope schema below)
      README.md        # aux: what these vectors pin, provenance
      *.py             # aux: independent reference generators (verify-only)
```

The native runner (`crates/antseal-core/tests/vector_runner.rs`, test names
`vector_runner_*`, CI lane `golden-vectors` + the three `cross-os-*` lanes)
discovers vectors by **walking `testdata/vectors/` — no hardcoded file
lists**. The discovery rules are strict so nothing is ever silently
skipped:

- Directly under `vectors/`: only `README.md` and `v<integer>/` directories
  are allowed. Anything else **fails the runner**.
- Under a version directory, every regular file must be either
  - a **vector file**: extension `.json` — parsed, validated, and executed
    (a malformed vector file is a hard test failure, never a skip), or
  - an **auxiliary file**: `README.md`, `*.py` (reference generators), or —
    once Q6 lands — the `FROZEN.sha256` freeze manifest.

  A file of any other kind **fails the runner** as unclassifiable.
- Zero vectors discovered across the whole tree **fails the runner**
  (guards against discovery rot).

## Envelope schema (`schema_version` 1)

Every vector file is a UTF-8 JSON object with **exactly** these fields
(unknown fields are rejected — `deny_unknown_fields`; all fields required):

| Field | Value |
| --- | --- |
| `schema` | the string `"antseal-golden-vector"` |
| `schema_version` | `1` (integer; the envelope's own version, independent of the format version) |
| `format_version` | `"v1"`, … — **must equal the version directory** the file sits in (a mismatch fails the runner: misfiled vectors are caught) |
| `kind` | dispatch key, one of the registered kinds below |
| `non_secret` | free-text fixture provenance; **must contain the marker `NON-SECRET`** and should name the fixed test seed the fixture derives from |
| `description` | human-readable statement of what the vector pins |
| `inputs` | kind-defined object: everything needed to *recompute* the expectations |
| `expect` | kind-defined object: the expected artifacts/digests, byte-exact |

Binary data is **lowercase hex** throughout (matching D29's report-byte
rule); 64-bit ids are `0x`-prefixed 16-digit hex strings (unambiguous in
every JSON implementation, including the Q11 independent cross-check).

Parsing, validation, and execution live WASM-safe (no I/O) in
`antseal_core::test_util::vectors` (feature `test-util`), so the Q5
native↔WASM bit-match lane reuses the exact same execution path; only file
discovery/reading is native and lives in the runner test.

### Registered kinds

| `kind` | Since | `inputs` | `expect` | Executed as |
| --- | --- | --- | --- | --- |
| `hkdf-labels` | M0 (C3) | `w` (32-byte hex; must equal the documented fixed test seed) | `vectors`: one entry per registered HKDF label — `label`, `id` (`0x…` LE64 value), `id_domain` (`unit_id`\|`file_id`\|`sentinel`), `info` (hex), `okm` (hex) | full-registry coverage check, then per label: registry `id_domain`/output-length match, `info` re-encoded and compared, `okm` re-derived through the typed API and byte-compared |

Reserved kind names for the formats that land next (**the envelope needs no
change** — each kind defines its own `inputs`/`expect` objects; adding a
kind = one new dispatch arm + executor in `test_util::vectors`, zero runner
changes):

- `manifest` (F12): `inputs` = test `W`, `seal_id`, per-unit nonces, file
  bytes, canonicalization descriptors; `expect` = manifest bytes (hex,
  deterministic CBOR), `work_id`, `anchor_digest`, commitments,
  `fine_root`.
- `bundle` (F13, M3): as `manifest` plus reveal selection; `expect` adds
  bundle bytes and the redaction structure. Includes the **empty-anchor**
  must-exist vector (MVP-SPEC.md line 153).
- `report` (R/Q5): `inputs` = a bundle (hex or by reference to a sibling
  `bundle` vector id); `expect` = the canonical verification-report bytes
  (hex of the D29 compact-JSON encoding) — the native↔WASM bit-match
  medium.
- `anchor` (A, M2): recorded `.ots`/TSA-token fixtures with expected
  per-anchor verdict states — slots in as a kind with no envelope change
  (an explicit Q4 accept: M2 anchor vectors need no redesign).
- `fine-tree` (G15): range-proof openings incl. the unbalanced n=6
  MSB-first vector.

## Adding a vector (no harness change)

1. Write the JSON file conforming to the envelope + its kind's payload
   (generate `expect` values with an independent reference implementation
   where one exists; commit the generator as `*.py` beside the vectors).
2. Drop it anywhere under the right `vectors/<format-version>/` directory.
3. `cargo test -p antseal-core vector_` — the runner discovers and executes
   it; CI (`golden-vectors` + `cross-os-*` lanes) picks it up with **no
   code change**.

Adding a **new kind** (framework extension, not a per-vector event): add
the payload types + executor arm in
`crates/antseal-core/src/test_util/vectors.rs` and a row to the table
above. The runner test itself never changes.

Adding a **new format version**: create `vectors/v<n>/` — discovery is by
directory walk, so the runner executes all versions forever (Q6 enforces
retention).

## Freeze status

**Pre-freeze**: until Q6 lands the `FROZEN.sha256` guard and Q14 tags
`format-v1-freeze`, vectors here may still be moved or re-containered (as
the Q2/Q4 hkdf migration was). After the freeze, modifying or deleting a
frozen vector is a format event requiring a version bump; additions remain
allowed.
