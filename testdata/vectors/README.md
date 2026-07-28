# Golden vectors (Q4) — layout, envelope schema, runner contract

Committed golden vectors for every versioned antseal format, organised as
`vectors/<format-version>/…` (MVP-SPEC.md line 57; format-stability policy
line 123: **per-version vectors are retained in CI indefinitely** — Q6's
per-version `FROZEN.sha256` is the append-only freeze + must-exist guard,
see "Freeze + indefinite per-version retention" below).

## The test-only-secret convention

Everything here is NON-SECRET fixture material under the secret-material
convention in `../README.md`, and the harness **enforces** it rather than
trusting it:

- every vector file's `non_secret` field must contain the literal marker
  `NON-SECRET` and name the seed it derives from — the envelope check rejects
  the file otherwise;
- every secret-bearing kind requires `inputs.w` to be the documented fixed
  test seed `W = 0x00 0x01 … 0x1f`, and a document derived from any other
  master secret **fails** rather than passing quietly;
- a second fixture secret, where one is genuinely needed (a wrong-key case, a
  synthetic `s_root`), is minted as `SHA-256(label ‖ W)` through
  `test_util::alternate_test_secret`, with the label appearing verbatim in
  the vector — so its provenance is readable and reproducible, never a fresh
  32-byte literal of unknown origin;
- the non-secret fixture constants a format vector needs (`seal_id`,
  `app_version`, `claimed_time`, content addresses) are published constants
  of `test_util::bundle_fixtures`, and the executors require the committed
  values to equal them.

No committed vector contains, or derives from, real vault, wallet or author
material (project rule 6).

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
| `fine-tree` | M0 (G15) | `w`, `s_root_label` (the documented synthetic-seed label) + `cases`: per case a `name`, the file `content` (hex; its length **is** `n`) and the `openings` to prove (`name`, `start`, `length`) | `s_root` (hex) + per case `n`, `depth`, `slot_count`, `ggm_nodes` (every used grid node's seed), `salts` (every `salt_i`), `merkle_nodes` (every RFC 6962 content-tree node with its canonical slot and hash), `fine_root`, and per opening the full range proof — `cover` (leaf-exact, with seeds), `boundary` (with hashes), `revealed_bytes`, `releases_s_root` | the **whole** `expect` object is recomputed from `inputs` through the public API and compared as one value, so a missing/extra/reordered entry fails like a wrong byte; then the assertions a value comparison cannot state: each leaf is *also* derived LSB-first and must differ (the MSB-first pin), every wholly-unused grid slot must be refused by `SaltTree::seed_at`, every opening is run back through `verify_range`, and `n = 0` must be declined by all four entry points. Format doc: `v1/fine-tree/README.md` |
| `content-model` | M0 (G21) | `w` (as above), `fine_seed_label` (the documented synthetic-supplier label) + `cases`: per case a `name`, a `pins` sentence, and the `files` of one whole work (`raw` hex, `force_text`, `split`, `no_fine_tree`) | `cases`: per case `file_count`/`unit_count`, per **file** the descriptor as recorded (`kind`, `fine_tree_present`, `fine_tree_domain`, `unicode_version`), `raw_len`, `size`, `canonical`, `s_root`, `fine_root` and its `unit_ids`, and per **unit** `unit_id`, `file_id`, `kind`, `start`, `length`, `true_length`, `covered`, `unit_commit_required`, `bytes` | the **whole** `expect` is recomputed through `assemble_content_model` and compared as one value; then the **G14 tie** (the `golden-four-file-work` case must equal `content::fixtures::golden_inputs()` *and* recompute to `golden_model()` — both directions), G14's nine-invariant oracle, every covered unit proved through `prove_unit` and verified against its file's own `fine_root`, the verifier's `canonicalize_v` recompute of every text rendition under the *descriptor-recorded* version, and structural shape coverage. Pins **no** proof bytes, so D83's cover encoding cannot move it. Format doc: `v1/content-model/README.md` |
| `manifest` | M0 (F12) | `w`, `seal_id`, `app_version`, `claimed_time` (each required to equal its published fixture constant) + `cases`: per case a `name`, `title`, `policy` (`hybrid`\|`ed25519-only`), `seed`, and `files` (`path`, `kind`, `raw` hex, `fine_tree`, `split` widths) — a declarative work driven through R6's fixture constructor | per case `manifest_bytes` (hex, the canonical envelope), `work_id`, `anchor_digest`, `diagnostic` (`envelope` + `body`, rendered by the [sidecar rules](#the-diagnostic-sidecar-manifest--bundle)) and `decoded` (the schema-layer reading, field by named field; large blobs as `{len, sha256}`) | the **whole** `expect` is recomputed from `inputs` and compared as one value; then, against the **committed** bytes: the F6 envelope round-trip, the F5/F2 body round-trip, both F7 digests, F7's separation property (a mutated signature container moves `anchor_digest` and leaves `work_id`), and the sidecar re-rendered from the committed bytes. Shape coverage is asserted structurally, not by case name. Format doc: `v1/manifest/README.md` |
| `bundle` | M0 (F13) | the `manifest` inputs, plus per case an `anchors` set (`empty`\|`one-ots-two-tsa`\|`every-kind`\|`every-kind-no-receipt`), a `selection` (one of `"untouched"`\|`"full"`\|`"full-no-mirror"`\|`{"units":[…]}` per file) and the `work` | per case `bundle_bytes` (hex, the canonical `.sealproof`), `work_id`, `anchor_digest`, `diagnostic` (`bundle` + `manifest` + `body` — **all three** strict-decode layers) and `decoded` (storage record, anchors, receipt, covered/non-covered reveals with covers and boundary paths, touched files, full reveals) | the whole `expect` recomputed and compared; then, against the **committed** bytes: `SealProof::decode`'s three strict layers, `encode_bundle` round-trip byte-identity, the zero-copy `anchor_digest` pre-image seam, both manifest digests over the *embedded* bytes, the sidecar re-rendered per layer, and **`verify_bundle` accepts it** (F13's R handshake — report *bytes* are R9's kind). Coverage is structural and includes the **empty-anchor** requirement. Format doc: `v1/bundle/README.md` |

## The diagnostic sidecar (`manifest` + `bundle`)

The two format kinds commit **bytes**, and bytes alone cannot be reviewed or
cross-checked: an independent decoder handed only a hex string has nothing to
disagree *with*. Each of their cases therefore also carries a `diagnostic` —
the same CBOR data item written out structurally — which is what **F14**'s
second CBOR implementation (Python `cbor2`, decision D12) compares against.

One canonical CBOR item renders by these rules and no others (renderer:
`test_util::vectors_cbor_diag`; **F14 implements exactly this table**):

| CBOR item | JSON |
| --- | --- |
| unsigned integer (major 0) | a JSON number, non-negative |
| negative integer (major 1) | a JSON number, negative |
| byte string (major 2) | `{"b": "<lowercase hex>"}` |
| text string (major 3) | a JSON string |
| array (major 4) | a JSON array |
| map (major 5) | `{"m": [[key, value], …]}`, entries in wire order |

Unambiguous by construction: the only JSON objects are `{"b": …}` and
`{"m": …}`, told apart by their single key. Map entries are **pairs** rather
than a JSON object because every v1 key is an integer while JSON object keys
are strings — pairs keep the key's type and the wire order visible, and that
order (strictly ascending, RFC 8949 §4.2.1) is itself part of what is pinned.
The renderer refuses any integer above 2^53 − 1 rather than emit a number an
IEEE-double reader would silently round.

**Embedded CBOR is never recursed into.** A manifest's `body`, and a bundle's
embedded manifest, render as byte strings exactly as the wire says; each
inner layer is rendered separately under its own name (`envelope`, `body`,
`manifest`, …). The layer boundary stays explicit because that boundary *is*
F6/F9's three-layer strict decode.

A case commits exactly **one** byte string — the outermost layer
(`manifest_bytes` / `bundle_bytes`). There is deliberately **no**
`body_bytes` field, so an inner layer's bytes must be read out of the
enclosing item; `work_id`'s pre-image comes out of the envelope's key-0 byte
string, which is what demonstrates that `work_id` hashes the *embedded*
bytes and never a re-encoding.

**The full F14 contract — sidecar location, the rendering table, the four
checks, and the two things to confirm rather than assume — is
`docs/testing/cbor-cross-check.md` (F19).** The table above, that document,
and `test_util::vectors_cbor_diag` are three statements of one rule; a drift
test (`crates/antseal-core/tests/cbor_crosscheck_contract.rs`) keeps them
pointing at each other.

The second implementation itself is `v<n>/crosscheck_cbor.py` — one per
format version, each checking its own directory, run by
`scripts/cross-check.sh` (CI lane `cross-check`). It is a `*.py`
**auxiliary** under the directory contract above, so it is never executed as
a vector. Per decision D31 it uses `cbor2` to **decode only**; the RFC 8949
§4.2.1 canonical encoder and the canonicality judgement are its own.

| `report` | M0 (R9) | `w`, `seal_id`, `seed` and `app_version` (R6's fixed fixture constants) + `cases`: per case the R6 `shapes::catalogue()` handle to build (`shape`) and one sentence saying which M0 row it discharges (`pins`) | `report_version` + per case `bundle_len`/`bundle_sha256` (the input bundle R6 builds), `revealed_unit_ids`, `report_len`, **`report_json`** (lowercase hex of `VerificationReport::to_canonical_json()` — the byte-exact D29 encoding and the native↔WASM bit-match medium) and `report` (the same bytes decoded, the order-insensitive review surface) | the **whole** `expect` object is recomputed — each shape rebuilt through R6 and run through `verify_bundle` — and compared as one value; then the assertions a value comparison cannot state: coverage of every M0 shape in `REQUIRED_SHAPES`, structural coverage (some case yields an empty anchor list, some other a populated one, some a committed placeholder), `evidence.passed` with `units_verified` equal to what the bundle revealed, byte-identical re-serialization (D27/D29), and a leak scan re-deriving every `k_u`/`unit_salt`/`path_salt`/`file_salt`/`s_root` of the work and requiring none in the pinned bytes. Format doc: `v1/report/README.md` |

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
(`report`) each land a kind that starts life as a `pending` entry — G15 and
R9 have done so; F12 and F13 are still owed. The move from pending → landed
is one commit:
**R9** (`report`) is the one kind still sitting as a `pending` entry;
**G15** (`fine-tree`), **F12** (`manifest`) and **F13** (`bundle`) have each
made the move already, and with F13 the v1 **must-exist set is empty** — the
Q14 gate condition on `FROZEN.sha256`. It is one commit:

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
**Eleven** kinds freeze with v1: `hkdf-labels`, `commitments`, `unit-aead`,
`manifest-aead`, `signatures`, `sig-reject`, `fine-tree`, `content-model`,
`report`, `manifest`, `bundle`. The manifest's `#! kind` directives are the
authoritative list — the checker requires their union to equal
`test_util::vectors::KNOWN_KINDS`, so this sentence can go stale but the
build cannot.

### Retention: per version, indefinite

**`v<n>/` is the unit of retention.** A version directory, once created, is
kept and run forever; every future release's CI executes all of them
(MVP-SPEC.md line 123; `../README.md`). Freezing is per version too: a
future `v2/` gets its own `FROZEN.sha256` and neither disturbs nor releases
`v1/`. Discovery is a directory walk, so retention needs no per-version
wiring — but a version directory **without** a manifest is a hard failure,
because its vectors would be unfrozen and deletable in silence.

**Budget (D87).** `crates/wasm-bitmatch/build.rs` embeds every vector into
the bit-match artifact and enforces a ceiling of **2 MiB of embedded bytes
per `v<n>/` directory** (`*.json` less `INDEX.json`). It is per version on
purpose — retention is per version, so a new version gets its own budget
and never competes with an older one's. A breach fails the build; the fix
is a reviewed raise in `build.rs` and D87, never deleting or shrinking a
committed vector. Today `v1` uses 590 280 B, 28.15 % of its budget.

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
