# Golden vectors (Q4) — layout, envelope schema, runner contract

Committed golden vectors for every versioned antseal format, organised as
`vectors/<format-version>/…` (MVP-SPEC.md line 57; format-stability policy
line 123: **per-version vectors are retained in CI indefinitely** — Q6's
per-version `FROZEN.sha256` is the append-only freeze + must-exist guard,
see "Freeze + indefinite per-version retention" below).

Everything here is NON-SECRET fixture material under the secret-material
convention in `../README.md`.

## Directory contract

```
vectors/
  README.md            # this file (aux)
  v1/                  # one directory per format version, name = v<integer>
    FROZEN.sha256      # aux: Q6 freeze + must-exist manifest (one per version)
    INDEX.json         # aux: F10 per-version roster (one per version)
    <component>/       # free-form grouping (hkdf/, manifest/, …)
      *.json           # vector files (envelope schema below)
      README.md        # aux: what these vectors pin, provenance
      *.py             # aux: independent reference generators (verify-only)
```

**`v<n>/` is a format version's whole record**, and it has three parts that
must not be conflated:

| File | Job | Owner |
| --- | --- | --- |
| the `*.json` vectors | the evidence itself | the landing task |
| `FROZEN.sha256` | **freeze** the bytes + catch deletions | Q6 |
| `INDEX.json` | the **roster**: what exists, who owns it, what it pins, what is still owed | F10 |

`INDEX.json` is an auxiliary and is deliberately **not** frozen: it changes
every time a vector lands, and a roster edit must never read as a format
event. It is held to the tree — and cross-checked against `FROZEN.sha256` —
by `crates/antseal-core/tests/vector_index.rs`.

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
  - an **auxiliary file**: `README.md`, `*.py` (reference generators), the
    `FROZEN.sha256` freeze manifest (Q6), or the `INDEX.json` roster (F10) —
    both described below.

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
`antseal_core::test_util::vectors` (feature **`test-vectors`**, implied by
`test-util`; the tier split is P14's — see `docs/wasm-toolchain.md`), so the
Q5 native↔WASM bit-match lane reuses the exact same execution path; only
file discovery/reading is native and lives in the runner test.

Each execution also returns `VectorSummary::recomputed_digest`: a SHA-256
over **every byte the executor recomputed**, length-prefixed and
domain-separated. It is a *harness* digest — never a format commitment, and
outside the C1 domain-tag registry by construction — and it is the medium
the `wasm-bitmatch` lane byte-compares between native and wasm32
(`crates/wasm-bitmatch/README.md`). Kind executors that recompute values
should feed them into it; the runner and the bit-match then cover the new
kind with no further wiring.

### Registered kinds

| `kind` | Since | `inputs` | `expect` | Executed as |
| --- | --- | --- | --- | --- |
| `hkdf-labels` | M0 (C3) | `w` (32-byte hex; must equal the documented fixed test seed) | `vectors`: one entry per registered HKDF label — `label`, `id` (`0x…` LE64 value), `id_domain` (`unit_id`\|`file_id`\|`sentinel`), `info` (hex), `okm` (hex) | full-registry coverage check, then per label: registry `id_domain`/output-length match, `info` re-encoded and compared, `okm` re-derived through the typed API and byte-compared |
| `commitments` | M0 (C16) | `w` (as above) | `vectors`: `name`, `commitment` (`unit`\|`raw`\|`canon`\|`path`), `domain_tag` (1-byte hex), `salt_label`, `id` (`0x…` LE64), `salt` (hex), `message` (hex), `digest` (hex) | all four commitment kinds covered, then per entry: frozen `(domain_tag, salt_label)` pair checked against the registry, `salt` re-derived through C2's typed API, `digest` recomputed through C6's public API and byte-compared, and the matching `verify_*_commit` accepts the same inputs |
| `unit-aead` | M0 (C16) | `w` (as above), `seal_id` (16-byte hex) | `vectors`: `name`, `unit_id` (`0x…` LE64), `true_length`, `unit_bytes` (hex), `k_u` (hex), `aad` (hex), `padded_plaintext` (hex), `nonce` (hex), `ciphertext` (hex) | boundary coverage enforced (empty unit + a 256-aligned unit), then per entry: `k_u` re-derived, `aad` recomputed, `padded_plaintext` recomputed byte-exact and checked against the `padded_length` formula, ciphertext length checked, and the ciphertext decrypted back to `unit_bytes` through **both** the key-direct and the `W` entry points |
| `manifest-aead` | M0 (C16) | `w` (as above) | `k_m` (hex) plus `vectors`: `name`, `manifest_bytes` (hex), `aad` (must be `""`), `nonce` (hex), `blob` (hex) | `MANIFEST_AAD` asserted empty and every entry's `aad` required empty (the frozen empty-AAD rule), `k_m` re-derived at the sentinel id, blob length checked, and the blob decrypted back to `manifest_bytes` through both entry points |
| `signatures` | M0 (C16) | `w` (as above), `body` (hex), `context` (hex; must equal the frozen `SIG_CONTEXT`) | `ed25519` (`seed`, `public_key`, `signing_message`, `signature`), `mldsa65` (`seed`, `public_key`, `signature`), `hybrid` (`policy_ids`, `policy_label`) | frozen context checked; per algorithm the seed, public key and signature bytes re-derived and byte-compared, then verified; the hybrid leg rebuilds keys and signatures through C14's policy path, requires the identical bytes, and runs `verify_body` under the policy |
| `sig-reject` | M0 (C15) | `w`, `alg` (`ed25519`\|`ml-dsa-65`), `ctx` (must equal the frozen signature context), `body` (hex) | `base` (honest `public_key`/`signature` hex) + `cases`: per case an `id`, a `class`, a `why`, a **source** recipe for the key and the signature bytes, and the `expect`ed outcome (`accept` or a stable `crypto-…` code) | `base` re-derived and byte-compared; per-algorithm class coverage; expected codes checked against the real `CryptoError` code set; every case's bytes rebuilt from its recipe and run through C14's full verification path (`sig_policy::verify_body`). Format doc: `v1/sig-reject/README.md` |

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
4. `./scripts/wasm-bitmatch.sh` — the Q5 harness embeds the new file (its
   `build.rs` walks this tree) and requires the native and wasm32
   transcripts to stay byte-identical. Also **no code change**: the
   `wasm-bitmatch` lane covers every new vector automatically.
5. `./scripts/vector-freeze.sh --update` — appends the vector's digest to
   its version's `FROZEN.sha256`, which freezes its bytes and puts it on
   the must-exist list. A vector outside the manifest has no retention
   guarantee, so the `vector-freeze` lane refuses it. Commit the manifest
   line with the vector.
6. **Register it in `INDEX.json`** — see the next section for the exact
   entry shape. `cargo test -p antseal-core vector_index` refuses a vector
   that is committed but unrostered, and a roster entry with no file.

Adding a **new kind** (framework extension, not a per-vector event): add
the payload types + executor arm in
`crates/antseal-core/src/test_util/vectors.rs`, a row to the table above,
and a `#! kind <name> <task>` directive to the version manifest (the
checker requires the two to agree). The runner test itself never changes.

Adding a **new format version**: create `vectors/v<n>/` with its own
`FROZEN.sha256` **and its own `INDEX.json`** — discovery is by directory
walk, so the runner executes and the freeze guard checks all versions
forever (Q6 enforces retention). The index's `format_version` must name a
version `antseal_core::format::SUPPORTED_VERSIONS` lists, which is what ties
the vector tree to F10's dispatch table: vectors can only exist for a
version this build can actually decode.

## The per-version index (F10)

`v<n>/INDEX.json` is the **roster** of one format version. `FROZEN.sha256`
answers *"have these bytes changed?"*; the index answers *"what is here, who
owns it, what does it pin, and what is still owed?"* — the questions a
reviewer, the Q14 freeze gate, and R28's multi-version suite each need
answered without reading seven JSON payloads.

It is consumed by `crates/antseal-core/tests/vector_index.rs` (test names
carry the reserved `vector_` marker, so it runs on the `cross-os-*` lanes
alongside the Q4 runner).

### Schema

```json
{
  "schema": "antseal-vector-index",
  "schema_version": 1,
  "format_version": "v1",
  "freeze_gate": "Q14",
  "note": "…",
  "vectors": [
    {
      "slug":  "crypto-commitments",
      "path":  "crypto/commitments.json",
      "kind":  "commitments",
      "task":  "C16",
      "pins":  "one sentence: the obligation this vector discharges, citing the spec line"
    }
  ],
  "pending": [
    {
      "slug":  "manifest-encode-decode",
      "kind":  "manifest",
      "task":  "F12",
      "must_exist_before_freeze": true,
      "pins":  "…"
    }
  ]
}
```

Unknown fields are rejected (`deny_unknown_fields`), so a typo is never
silently ignored.

| Field | Rule |
| --- | --- |
| `slug` | permanent handle, unique within the version, kebab-case. Downstream work refers to a vector by slug, so treat it like an error code: **append-only, never renamed** |
| `path` | forward-slashed, relative to `v<n>/`, must exist and must be frozen |
| `kind` | must equal the vector file's own `kind` **and** be in `test_util::vectors::KNOWN_KINDS` |
| `task` | the task that landed (or owes) it — never blank |
| `pins` | ≥ 20 chars; states what the vector pins, ideally citing the MVP-SPEC line |
| `must_exist_before_freeze` | *pending entries only.* `true` ⇒ this is part of Q14's must-exist minimum and has a matching `#! pending` line in `FROZEN.sha256`; `false` ⇒ tracked here only |

### What the test enforces

1. `format_version` equals the directory **and** is in
   `antseal_core::format::SUPPORTED_VERSIONS`.
2. **Roster completeness both ways**: committed vectors ≡ index entries. A
   vector landed without registering fails; so does a stale entry.
3. The index cannot lie: each entry's `kind` is compared against the vector
   file's own `kind`, and the file's `format_version` against the directory.
4. Slugs and paths are unique; a slug is never both landed and pending.
5. **Index ⟷ freeze agreement**: rostered set ≡ frozen set, and
   `{pending | must_exist_before_freeze}` ≡ `FROZEN.sha256`'s `#! pending`
   set, slug and task. The two files are mutually enforcing.
6. `INDEX.json` itself is never in the frozen set.

### Registration contract for downstream vector tasks

**F12** (`manifest`), **F13** (`bundle`), **G15** (`fine-tree`) and **R9**
(`report`) each land a kind that is currently a `pending` entry. The move
from pending → landed is one commit:

1. Commit the vector file(s) under `v1/<component>/`.
2. Add the kind's payload types + executor arm in
   `crates/antseal-core/src/test_util/vectors.rs` and its `KNOWN_KINDS` row,
   plus a row in the registered-kinds table above.
3. Add `#! kind <name> <task>` to `v1/FROZEN.sha256` and run
   `./scripts/vector-freeze.sh --update`.
4. In `INDEX.json`: **delete** the `pending` entry and add one `vectors`
   entry per committed file. Carry the pending entry's `kind` and `task`
   across unchanged; give each file its own `slug` and `pins`.
5. If the entry had `must_exist_before_freeze: true`, delete the matching
   `#! pending` line from `FROZEN.sha256` in the same commit — the test
   compares the two sets exactly, so a half-migration is red.
6. `cargo test -p antseal-core vector_` — runner, freeze and index in one
   go; then `./scripts/wasm-bitmatch.sh`.

Adding a vector to a kind that already exists needs only steps 1, 3 and 4.
Neither the runner nor the bit-match lane needs any change, ever.

## Freeze + indefinite per-version retention (Q6)

Each version directory carries a **`FROZEN.sha256`** manifest. It does two
jobs at once:

1. **Freeze** — one SHA-256 per committed vector file, so any byte change
   turns the `vector-freeze` CI lane red.
2. **Must-exist list** — the hash lines *are* the list. The Q4 runner above
   can only fail on files it finds, so **deleting** a vector silently
   removes its coverage; the manifest is the second layer that catches it.
   It also catches the opposite: a committed `*.json` that is *not* listed
   is an unfrozen vector and fails too.

Only vector files (`*.json`) are frozen. `README.md` and the `*.py`
reference generators are **auxiliaries by design**: the generators are
re-runnable cross-checks, and the JSON they produced is what the format
commits to.

The manifest is `sha256sum -c` compatible (`#` lines are comments), so CI
checks the digests twice — once with coreutils, which shares no code with
antseal, and once with the authoritative checker
`crates/antseal-core/tests/vector_freeze.rs`. Both run from
`./scripts/vector-freeze.sh`; `--self-test` proves the lane goes red on a
mutated and on a deleted vector; `--update` regenerates the digest blocks.

### Directives

`#!` lines carry the machine-readable part (unknown directives fail — a
typo is never silently ignored):

| Directive | Meaning |
| --- | --- |
| `manifest-version` | the manifest's own schema version |
| `format-version` | must equal the version directory it sits in |
| `status` | `pre-freeze` or `frozen` |
| `freeze-gate` | the task that flips `status` (`Q14`) |
| `kind <name> <since>` | a vector **kind** that freezes with this version; the union across versions must equal `test_util::vectors::KNOWN_KINDS` |
| `pending <slug> <task> <what>` | a must-exist vector this version still owes, naming the task that must land it |

**Kinds freeze at Q14** — the kind *name* and its `inputs`/`expect` payload
shape, not the shared envelope (which carries its own `schema_version`).
Six kinds freeze with v1: `hkdf-labels`, `commitments`, `unit-aead`,
`manifest-aead`, `signatures`, `sig-reject`.

### Retention: per version, indefinite

**`v<n>/` is the unit of retention.** A version directory, once created, is
kept and run forever; every future release's CI executes all of them
(MVP-SPEC.md line 123; `../README.md`). Freezing is per version too: a
future `v2/` gets its own `FROZEN.sha256` and neither disturbs nor releases
`v1/`. Discovery is a directory walk, so retention needs no per-version
wiring — but a version directory **without** a manifest is a hard failure,
because its vectors would be unfrozen and deletable in silence.

### What changes at Q14

| | now (`status pre-freeze`) | after Q14 (`status frozen`) |
| --- | --- | --- |
| Add a vector | append its manifest line (`--update`) | same — additions stay legal forever |
| Change a vector's bytes | allowed as a **recorded, justified** regeneration: re-run `--update`, review the digest diff, state why in the commit | **refused.** A byte change is a format event needing a new format version |
| Delete a vector | refused | refused |
| Add a kind | record it as `#! kind` | new kinds land under a new format version |
| `#! pending` entries | may exist; each names its owning task | **must be empty** — that is Q14's gate condition, and the checker refuses `status frozen` while any remain |

Q6 built the mechanism and the current manifest; **Q14 executes the
freeze** by landing the outstanding `#! pending` vectors and setting
`#! status frozen`.
