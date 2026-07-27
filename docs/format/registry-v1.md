# antseal wire-format registry — v1 (F4)

> **DRAFT — NOT FROZEN. This registry freezes only at the Q14
> `format-v1-freeze` gate (M0 Definitions sign-off).** Until then every row
> is a *proposal*. Three feeding decisions are still open and are marked
> inline wherever they bite:
>
> - **D8** — the registry as a whole (key assignments, reserved ranges,
>   signatures container, time encoding, byte-range representation,
>   explicit `file_id`). Rows carry status `proposed` = pending D8 sign-off.
> - **D9** — GGM node-address representation, co-frozen with G8. Rows
>   carry status `pending-D9`. Both candidates are drafted in §5.
> - **D17** — `sig_policy` algorithm-ID numeric values. Rows carry status
>   `pending-D17`. Proposed values in §6.2.
>
> After Q14, this document is normative and any change is a format-version
> event (MVP-SPEC.md line 123).

- Task: **F4** (tasks/F.md). Date: 2026-07-27.
- Spec basis: MVP-SPEC.md lines 71–79 (Definitions & encoding), 90
  (`seal_id`), 91–98 (unit/body fields), 112–114 (reveal bundle), 121
  (structural invariants), 123 (format stability), 127–137 (anchor states).
- Resolved inputs: D7 (`minicbor =2.3.0`, uint keys, manual impls), D11
  (Autonomi address = 32 B BLAKE3, docs/research/S1-ant-core-api-survey.md
  §1), D25 (`unicode-17.0.0`), D20/D21 (descriptor carries `kind` only — no
  forced-text flag; canonicalization pipeline frozen), D27/D29 (verification
  report is a *separate, non-wire* byte format — context only).
- Machine mirror: [`registry-v1.json`](registry-v1.json) (§14). Draft gate
  test: `crates/antseal-core/tests/format_registry_draft.rs`.

## 0. Scope and reading rules

This registry assigns **every unsigned-integer map key** of the v1 wire
formats: the manifest envelope, the manifest body, file-table entries,
unit-table entries, the `.sealproof` bundle top level, and every bundle
section — plus the CBOR type, presence rule, and exact byte length of every
field, the shared tuple shapes, the wire enums, and the reserved key space.

Column conventions in §7:

- **presence** — `req` (must be present) or `opt: <rule>` (present iff the
  rule holds; the rule is enforced at parse time by F5/F8 unless marked
  `[R]` = semantic, verifier-side per D27 stage order). Absence is always
  key absence — v1 has no `null` (§1).
- **len/shape** — exact byte length for fixed-size `bstr` fields; element
  type for arrays; `var` for variable-length opaque bytes.
- **status** — `proposed` (pending the D8 whole-registry sign-off),
  `pending-D9`, `pending-D17`.

Layer split (recorded so rows do not over-claim): F3 enforces CBOR
canonicality; F5/F8 enforce schema shape — key sets, types, exact lengths,
conditional presence, list ordering; R owns semantic/structural invariants
(tiling, `true_length` = range width, leaf-exact cover, partial-reveal
isolation — MVP-SPEC.md line 121). A row's presence rule names its layer.

The 1:1 assertion that **code constants match this table** arrives with
F5/F8 (schema types) — the current draft test (§14) checks only the
mirror's internal consistency.

## 1. v1 type profile

The encoding is RFC 8949 §4.2.1 Core Deterministic Encoding as restricted
by MVP-SPEC.md line 73, produced and enforced via the pinned
`minicbor = "=2.3.0"` (D7) under F2/F3. On top of that profile, **v1
restricts the type surface to five major types**:

| allowed | CBOR major | use |
| --- | --- | --- |
| `uint` | 0 | ids, sizes, versions, enum values, times, tuple coordinates, **all map keys** |
| `bstr` | 2 | commitments, salts, seeds, keys, nonces, addresses, ciphertexts, opaque anchor artifacts, embedded manifest/body bytes |
| `tstr` | 3 | title, app version, paths, Unicode-version string, TSA source |
| `array` | 4 | tables, sections, tuples (definite length only) |
| `map` | 5 | every keyed structure (definite length, uint keys, strictly ascending) |

Excluded from v1 entirely (decoder hard-rejects, F3): negative integers
(major 1), **all** simple values — including `true`/`false`/`null`/
`undefined` — floats (major 7), tags (major 6), indefinite lengths.
Consequences, recorded as rules:

1. **Booleans encode as `uint` 0/1** (`fine_tree_present`, and any future
   flag). Rationale: one fewer decoder class to harden, and 0/1 uints are
   shortest-form-canonical by construction; a simple-value `true`/`false`
   adds a type class whose only benefit is cosmetic.
2. **Optionality = key absence.** A field is present or its key is absent;
   `null` does not exist. One logical value therefore has exactly one
   encoding (no present-but-null vs absent split).
3. **Map keys are unsigned integers only**, so bytewise key order equals
   ascending numeric order (asserted by F2). Duplicate keys are
   structurally impossible on decode (strict-ascent rejection, F3) — this
   is what makes the integer-keyed containers of §7.1/§7.2 duplicate-free
   *by map semantics*, not by a checked invariant.
4. **All v1 key assignments live in `0..=23`** (single-byte CBOR heads).
   Within `0..=23`, unassigned keys are **reserved**: their presence in v1
   input fails with F10's distinct reserved-slot error naming the key.
   Keys `>= 24` are not reserved-for-v1.x and fail with the plain
   unknown-key error. (Two error bands; F10 mechanics.)
5. **No magic bytes / file header.** A `.sealproof` or manifest is bare
   deterministic CBOR; the version discriminant is map key 0, which sorted
   uint keys place **first** in the encoded bytes (F10 reads it before
   dispatch). A non-CBOR magic prefix would break "everything is one
   canonical CBOR item"; a CBOR tag is banned by the profile. Recorded as
   deliberate.
6. **The manifest envelope shape `{0: body, 1: signatures}` is frozen
   across all future versions** (F10 note): version dispatch for the body
   happens *after* outer-envelope decode, so the envelope itself can never
   gain keys. It has **no** reserved range — any key other than 0/1 is
   unknown-key, forever.
7. No format string on the wire embeds a crate or product name (D7
   consequence); the only registered string values are the Unicode version
   descriptor (`unicode-17.0.0`, D25) and free-form informational text.

## 2. Fixed scalar lengths (parse-enforced)

| bytes | fields | source |
| --- | --- | --- |
| 16 | `seal_id`; `unit_salt`, `path_salt`, `file_salt` | MVP-SPEC.md lines 90, 94–95, 121 |
| 24 | XChaCha20-Poly1305 nonces (unit nonces, manifest-storage nonce) | lines 91, 98 |
| 32 | `path_commit`, `raw_commit`, `canon_commit`, `unit_commit`, `fine_root`; `s_root` + every GGM cover seed; every boundary Merkle node hash; `k_u`, `k_m`; Autonomi ciphertext address (**D11: `XorName = [u8; 32]`, BLAKE3-256**); EVM tx hash (Keccak-256); Ed25519 public key | lines 94–96, 98, 121; S1 §1 |
| 64 | Ed25519 signature (RFC 8032) | line 97 |
| 80 | Bitcoin block header | line 108 |
| 1952 | ML-DSA-65 public key (FIPS 204 Table 2) — *pending-D17 confirm* | line 97 |
| 3309 | ML-DSA-65 signature (FIPS 204 Table 2) — *pending-D17 confirm* | line 97 |

Derived 32-B values that are **not** wire fields (never stored, always
recomputed): `work_id` = SHA-256(body bytes), `anchor_digest` = SHA-256(full
manifest bytes) — line 75; see §12 checklist.

Variable-length `bstr` fields (ciphertexts, `.ots`, DER tokens/certs,
receipt payload, embedded manifest) are bounded by F11's caps (§11).
Unit-ciphertext lengths additionally satisfy a cheap parse-time shape
check: XChaCha20-Poly1305 output = padded plaintext + 16-B tag, and
`padded_length` is a positive multiple of 256 (line 91), so every unit
ciphertext has `len ≡ 16 (mod 256)` and `len ≥ 272`. The exact equality
`len == padded_length(true_length) + 16` is R's semantic check against the
manifest.

## 3. Integer time encoding — status: proposed

**All wire timestamps are `uint` POSIX seconds, UTC** (seconds since
1970-01-01T00:00:00Z, leap seconds smeared/ignored per POSIX). Fields:
body `claimed_time` (§7.2), OTS `fetch_date` (§7.8), TSA `fetch_date`
(§7.9).

Rationale:

- The profile has no floats (line 73) and v1 has no tags (§1), so RFC 8949
  tag-1 epoch times and any fractional form are out by construction. A
  bare shortest-form `uint` is the only representation with exactly one
  encoding per instant.
- Text forms (RFC 3339 `tstr`) admit many encodings of one instant
  (offset, casing, fraction digits) — a canonicalization hazard and a
  parser surface for adversarial bundles, for zero benefit on fields that
  are either informational (`claimed_time`, line 98) or metadata
  (`fetch_date`). The *provable* times live inside the anchor artifacts
  (TSTInfo genTime, Bitcoin header), not in these fields.
- Second granularity suffices for every consumer; milliseconds would be
  false precision costing wire bytes.
- `uint` (not signed): pre-1970 instants cannot legitimately occur in any
  of these fields (the product cannot have sealed before it existed).
  u64 seconds has no 2038/2106 horizon worth naming.
- Report-side note: the verification report (D29, a separate non-wire JSON
  format) carries `i64` Unix seconds; every valid wire value fits — the
  boundary conversion is checked, not assumed.

## 4. Byte-range representation — status: proposed

**`range = [start, length]` — a 2-element definite array of two `uint`s**,
in the unit's byte domain (canonical bytes for text, raw bytes for binary
and raw-mirror units; line 83/92). Covered leaf range = `[start,
start+length)`. The empty unit of an empty file is `[0, 0]`.

Rationale for `[start, length]` over `[start, end)`:

- **Width is the load-bearing quantity.** Every consumer of the range
  consumes its width: the `true_length = byte-range width` invariant (line
  121), the `padded_length` formula input (line 91), the leaf-count of the
  covered range. With `[start, length]` the width is a field, not a
  subtraction; the R invariant is a direct equality.
- No representable degenerate state (`end < start` cannot be written).
  The one residual hazard, `start + length` overflow in u64, must be
  checked with overflow-checked arithmetic wherever the exclusive end is
  formed (R's tiling check; G's cover derivation) — recorded here as a
  registry-level implementation note.
- Deliberate redundancy, kept: `true_length` (§7.5 key 3) always equals
  `range[1]` for every unit (line 121 — raw-mirror included, whose range
  is `[0, raw_size]`-with-length-`raw_size`, line 92). The spec lists
  *both* fields (line 98) and the tamper matrix requires the row
  "`true_length` ≠ byte-range width" (line 168), which needs the two to be
  independently settable on the wire. The equality is R's check, not a
  parse rule.

## 5. GGM sub-cover / boundary-path node addressing — status: pending-D9 (co-freeze with G8)

Both the GGM salt tree and the content Merkle tree of a fine-tree file
live on the **depth-`d` dyadic grid**, `d = ⌈log₂ n⌉` (n = the file's
`size`; `n = 1 → d = 0`), leaf slots `0..2^d`, slots `i ≥ n` unused (line
96). A *node slot* is identified by how it is reached from the root. Two
candidate wire representations, drafted per the D9 open decision:

### Candidate A — `(level, index)` pair of uints

`[level, index]`: `level` = distance from the grid root (root = 0, leaf
slots at `level = d`); `index` = 0-based position within the level,
`index < 2^level`. The slot covers leaf slots
`[index · 2^(d−level), (index+1) · 2^(d−level))`.

Key property: **the path bits from the root to slot `(level, index)` are
exactly the bits of `index`, MSB-first (`level` bits)** — i.e. Candidate A
is the spec's own leaf-addressing rule ("leaf `i` is reached from `s_root`
by the bits of `i` MSB-first", line 96) generalized to interior nodes: a
GGM seed at `(level, index)` sits `level` child-derivation steps below
`s_root`, and deriving leaf `j` under it applies the remaining
`d − level` bits of `j`, MSB-first.

Encoding: 2 uints, shortest-form — canonical with no extra rules; 2–11
bytes per address (2–4 in practice: `level ≤ 64`, and `index` is small at
shallow levels where cover seeds concentrate).

### Candidate B — bit-path

The root-to-node path as an explicit bit string, MSB-first. Two sub-forms:

- **B1, packed `bstr`**: bits packed MSB-first into bytes + an explicit
  bit-length (either a `[len, bstr]` tuple or a length-prefix byte).
  Needs a **pad-bit canonicality rule** (unused trailing bits MUST be
  zero, decoder-checked) — an extra non-shortest-form-style rejection
  class this profile otherwise avoids.
- **B2, one byte per step** (`0x00`/`0x01`, matching the GGM child bytes
  `b`): no packing ambiguity, trivially maps to `SHA-256(0x06 ‖ s ‖ b)`
  steps, but costs `depth` bytes per address — at `n = 10⁸` (`d = 27`) a
  ≤ 2d-node cover pays ~54 × ~29 B of addressing vs ~54 × ~3 B under A,
  materially eroding the spec's ~1.7 KB cover sizing (line 96).

### Comparison and recommendation

| criterion | A `(level, index)` | B1 packed bits | B2 byte-per-bit |
| --- | --- | --- | --- |
| Canonicality | free (shortest-form uints) | needs pad-bit rule + check | free |
| Size per address | 2–11 B (typ. 2–4) | 2–10 B | `depth`+2 B |
| Arithmetic (interval, cover derivation) | shifts on `index` | unpack first | per-byte walk |
| Matches spec's MSB-first leaf rule | identical, generalized | transposed form | transposed form |
| Invalid-state checks | `level ≤ d`, `index < 2^level` | pad bits zero, `len ≤ d` | bytes ∈ {0,1}, `len ≤ d` |

**Recommendation: Candidate A**, encoded as the leading two elements of
the tuples below. It is informationally identical to a bit-path
(`index`'s bits MSB-first *are* the path) but inherits canonicality from
the CBOR profile instead of adding a padding rule, is the cheapest on the
wire, and reads directly as "this seed is `level` GGM steps below
`s_root` via the bits of `index`". **Not frozen until G8 adopts the same
convention (D9).**

### Canonical slot for content-tree (boundary-path) nodes

The GGM salt tree is complete (every slot genuine). The content Merkle
tree is the dyadic grid truncated at `n` with RFC 6962-style unbalanced
promotion (line 78), so a promoted node occupies several slots. The
canonical address is the **deepest slot** — descend while the node's
truncated leaf interval fits entirely within one child slot; equivalently
the slot at which the node is the root of the subtree over exactly its
leaf interval. (Example, `n = 6`, `d = 3`: the node over leaves `[4, 6)`
is canonically `(2, 2)`, not `(1, 1)`.) This matches the spec's
"deepest single-leaf nodes at the range boundaries" rule for leaf-exact
covers (line 96). Validity: a content-tree address must satisfy
`index · 2^(d−level) < n` and the deepest-slot rule; both are R-side
checks (the leaf-exact-cover check subsumes them for covers).

### Tuple shapes (pending-D9)

- **`cover_entry` = `[level, index, seed]`** — `uint, uint, bstr(32)`.
  One disclosed GGM seed of the leaf-exact sub-cover.
- **`path_node` = `[level, index, hash]`** — `uint, uint, bstr(32)`. One
  boundary Merkle sibling node hash.

**Addresses are explicit on the wire** (not implied by position within
the list), a deliberate choice: the verifier MUST recompute the expected
leaf-exact cover / sibling set from `(range, n, d)` and compare **sets**
— which is precisely what gives the tamper rows "over-broad GGM cover
whose node spans an unrevealed real leaf" and "wrong-position node" a
distinct, nameable error (line 168) instead of collapsing them into a
generic root mismatch. Cost: 2–4 bytes per entry. Note the security rule
is unchanged either way: the no-ancestor-seed rule (line 96) constrains
what the *builder* may ship, not how the verifier interprets it.

Ordering (parse-enforced, F8): within `cover` and within `paths`, entries
sorted by **strictly ascending leaf-interval start**
(`index · 2^(d−level)`). Entries of a valid cover/sibling set are
pairwise disjoint, so starts are distinct; strict ascent also rejects
duplicates. Deterministic re-encoding follows for free.

## 6. Enumerations

### 6.1 `anchor_status` — status: proposed

Wire values for the spec's seven-state per-anchor taxonomy, in spec order
(MVP-SPEC.md lines 129–135):

| value | state | headline-eligible |
| --- | --- | --- |
| 0 | `proven` | yes |
| 1 | `valid-at-stamping-cert-since-expired` | yes |
| 2 | `attested` | no (offline) |
| 3 | `pending` | no |
| 4 | `internally-consistent-only` | no |
| 5 | `invalid` | no |
| 6 | `absent` | no |

Values 7–15 reserved (unregistered — reject in v1). The bundle field
(§7.8/§7.9 key 0) records the **sealer-side captured state**; the
verifier always derives its own verdict state and never trusts the
recorded one (sealer-as-adversary, line 121). Which subset is *legal as
recorded* (e.g. OTS: `pending`/`attested`; TSA: whether the sealer
records its own pre-verification) is an A/R semantic rule — flagged to
D8, §13 item 5. `absent` (6) is representable for uniformity but an
artifact entry recording `absent` is self-contradictory; expected to be
rejected by that semantic rule (absence of an anchor is the empty section,
not an entry).

### 6.2 `sig_alg` — status: pending-D17

Registered `sig_policy` algorithm IDs (proposed values; C14 coordinates;
freeze at Q14):

| value | algorithm | pubkey | signature | notes |
| --- | --- | --- | --- | --- |
| 0 | `ed25519` | 32 B | 64 B | RFC 8032, strict/canonical verification (line 97). The always-present baseline: the reserved fallback policy is `[0]`. |
| 1 | `ml-dsa-65` | 1952 B | 3309 B | FIPS 204, `ctx = "antseal-manifest-v1"`, canonical-encoding rejection (line 97). |
| 2–15 | — | — | — | Reserved for future algorithms (e.g. a wider ML-DSA set, SLH-DSA). Unregistered in v1: any appearance — in `sig_policy`, `pubkeys`, or `signatures` — is a parse-time reject (C14 `SigPolicyUnknownAlg` / F5 unknown-key). |

Rationale: 0/1 encode in one byte; `ed25519` takes 0 as the algorithm
every v1 manifest must be able to carry alone (the ML-DSA WASM-probe
fallback ships `sig_policy = [0]` with the format unchanged, line 97).

### 6.3 Small closed enums — status: proposed

| enum | values |
| --- | --- |
| `descriptor_kind` (§7.4 key 0) | 0 = `binary`, 1 = `text` |
| `fine_tree_domain` (§7.4 key 2) | 0 = `raw`, 1 = `canonical` (aligned: a binary file's tree domain is raw = 0, a text file's is canonical = 1; both recorded explicitly per line 83) |
| `unit_kind` (§7.5 key 1) | 0 = `normal`, 1 = `raw-mirror` (line 98: raw-mirror units are ordinary entries distinguished by kind, no link field) |

Unlisted values reject at parse (F5).

## 7. Map key registries

### 7.1 Manifest envelope — `{body, signatures}` (line 74)

Shape frozen across **all** versions (§1 rule 6). No reserved range.

| key | field | type | presence | len/shape | status |
| --- | --- | --- | --- | --- | --- |
| 0 | `body` | bstr | req | var — embedded canonical-CBOR body (§7.2); `work_id` = SHA-256 of exactly these bytes; verifiers never re-encode (line 74) | proposed |
| 1 | `signatures` | map | req | uint keys = `sig_alg` (§6.2) → bstr of that algorithm's exact signature length; non-empty; enumerable; duplicates impossible by map semantics; present-set = policy-set is C14's check | pending-D17 (keys) |

### 7.2 Manifest body (line 98) — inside the `body` bstr

Version discriminant at key 0 (encoded first; F10 dispatch).

| key | field | type | presence | len/shape | status |
| --- | --- | --- | --- | --- | --- |
| 0 | `format_version` | uint | req | = 1 in v1 | proposed |
| 1 | `app_version` | tstr | req | free-form, informational only (producing build; never verdict-bearing) | proposed |
| 2 | `seal_id` | bstr | req | 16 | proposed |
| 3 | `title` | tstr | req | may be empty (no `--title` ⇒ `""` — one shape, §13 item 3) | proposed |
| 4 | `claimed_time` | uint | req | POSIX seconds UTC (§3); informational only (line 98) | proposed |
| 5 | `pubkeys` | map | req | uint keys = `sig_alg` → bstr of that algorithm's exact pubkey length; non-empty; key-set = policy-set is C14's check | pending-D17 (keys) |
| 6 | `sig_policy` | array | req | uint `sig_alg` elements; **order-preserving** (spec: ordered list); non-empty + duplicate-free + registered-only enforced at parse (line 97, C14) | pending-D17 (values) |
| 7 | `files` | array | req | file-table entries (§7.3); non-empty (a work = one or more files, line 83); array index **is** `file_id` (line 76) — no stored per-entry id in the manifest | proposed |
| 8–23 | — | — | — | reserved (§1 rule 4) | proposed |

### 7.3 File-table entry (line 98)

| key | field | type | presence | len/shape | status |
| --- | --- | --- | --- | --- | --- |
| 0 | `path_commit` | bstr | req | 32 | proposed |
| 1 | `raw_commit` | bstr | req | 32 | proposed |
| 2 | `canon_commit` | bstr | opt: `descriptor.kind == text` | 32 | proposed |
| 3 | `size` | uint | req | leaf count / tiling-domain byte count: canonical bytes for text, raw bytes for binary (line 98; a text file's raw byte count travels as its raw-mirror unit's `true_length`) | proposed |
| 4 | `descriptor` | map | req | §7.4 | proposed |
| 5 | `fine_root` | bstr | opt: `descriptor.fine_tree_present == 1` | 32 | proposed |
| 6 | `units` | array | req | unit-table entries (§7.5); non-empty (empty file = one empty unit, line 78) | proposed |
| 7–23 | — | — | — | reserved | proposed |

### 7.4 Canonicalization descriptor (lines 83, 98; G4 field set)

Per D20/D21 the descriptor carries **no** forced-text flag — `kind`
alone selects the total text-mode transform.

| key | field | type | presence | len/shape | status |
| --- | --- | --- | --- | --- | --- |
| 0 | `kind` | uint | req | `descriptor_kind` (§6.3) | proposed |
| 1 | `fine_tree_present` | uint | req | 0/1 (§1 rule 1); 0 for `--no-fine-tree` files and empty files (G4) | proposed |
| 2 | `fine_tree_domain` | uint | opt: `fine_tree_present == 1` | `fine_tree_domain` (§6.3) | proposed |
| 3 | `unicode_version` | tstr | opt: `kind == text` | v1 value set = {`"unicode-17.0.0"`} (D25); parse checks shape only — version-known lookup is G's registry at verify time | proposed |
| 4–23 | — | — | — | reserved | proposed |

Illegal combinations (G4's validation, run inside the decode path):
binary + canonical domain, text without `unicode_version`, version on
binary, present tree without domain.

### 7.5 Unit-table entry (lines 91–92, 98)

| key | field | type | presence | len/shape | status |
| --- | --- | --- | --- | --- | --- |
| 0 | `unit_id` | uint | req | work-global ordinal in manifest order (line 76). Stored explicitly per the line-98 field list *and* parse-checked equal to the derived manifest-order ordinal (concatenating `units` across `files` in order yields `0..N`) — a mismatch is a distinct decode error, so reveals and `--units` ids are self-describing and silent reordering is unrepresentable | proposed |
| 1 | `kind` | uint | req | `unit_kind` (§6.3) | proposed |
| 2 | `range` | array | req | `byte_range` tuple (§4), in the unit's byte domain; raw-mirror units span `[0, raw_size)` (line 92) | proposed |
| 3 | `true_length` | uint | req | pre-padding byte length; `== range[1]` is R's invariant (line 121; deliberate redundancy, §4) | proposed |
| 4 | `unit_commit` | bstr | opt: unit **not** fine-tree-covered, i.e. `kind == raw-mirror` **or** file `fine_tree_present == 0` (line 94: covered units are bound solely by `fine_root`) | 32 | proposed |
| 5 | `nonce` | bstr | req | 24 — the single authoritative copy (line 91); reveal entries never carry nonces (§12) | proposed |
| 6 | `address` | bstr | req | 32 — Autonomi ciphertext address (D11) | proposed |
| 7–23 | — | — | — | reserved | proposed |

Ordering: units appear in manifest order (which defines `unit_id`).
Within a file, non-mirror units must tile `[0, size)` sorted (R, line
121); proposed builder rule: raw-mirror entries follow all non-mirror
entries of their file (§13 item 6).

### 7.6 Bundle top level (lines 112–114)

Version discriminant at key 0 (encoded first).

| key | field | type | presence | len/shape | status |
| --- | --- | --- | --- | --- | --- |
| 0 | `format_version` | uint | req | = 1 in v1 (bundle and manifest version independently, line 123) | proposed |
| 1 | `manifest` | bstr | req | var — the full **plaintext manifest envelope** bytes (§7.1); `anchor_digest` = SHA-256 of exactly these bytes (line 75); nested strict decode per F9 | proposed |
| 2 | `storage_record` | map | req | §7.7 | proposed |
| 3 | `ots_anchors` | array | req, may be empty | OTS artifacts (§7.8); empty-anchor (UNANCHORED) bundle = both anchor arrays empty (one shape only — required-may-be-empty avoids an absent-vs-empty encoding split) | proposed |
| 4 | `tsa_anchors` | array | req, may be empty | TSA artifacts (§7.9) | proposed |
| 5 | `receipt` | map | opt: sealer passed `--include-receipt` (line 110 — genuinely optional data, hence key absence) | §7.10 | proposed |
| 6 | `covered_reveals` | array | req, may be empty | §7.11 entries, strictly ascending `unit_id` | proposed |
| 7 | `noncovered_reveals` | array | req, may be empty | §7.12 entries, strictly ascending `unit_id`; raw-mirror reveals ride here (raw-mirror units are never covered, line 94) | proposed |
| 8 | `touched_files` | array | req, may be empty | §7.13 entries, strictly ascending `file_id` | proposed |
| 9 | `full_reveals` | array | req, may be empty | §7.14 entries, strictly ascending `file_id`; every entry's `file_id` must also appear in `touched_files` [R] | proposed |
| 10 | `range_reveals` | — | **reserved, named** | v1.1 sub-unit arbitrary-byte-range covers + boundary paths (line 114/161); reject-if-present in v1 with the reserved-slot error (F10) | proposed |
| 11–23 | — | — | — | reserved | proposed |

### 7.7 Manifest storage record (line 98)

| key | field | type | presence | len/shape | status |
| --- | --- | --- | --- | --- | --- |
| 0 | `address` | bstr | req | 32 (D11) | proposed |
| 1 | `nonce` | bstr | req | 24 | proposed |
| 2 | `k_m` | bstr | req | 32 (`k_m` discloses nothing beyond the manifest the bundle already embeds, line 98) | proposed |
| 3–23 | — | — | — | reserved | proposed |

### 7.8 OTS anchor artifact (lines 108, 112–114)

| key | field | type | presence | len/shape | status |
| --- | --- | --- | --- | --- | --- |
| 0 | `status` | uint | req | `anchor_status` (§6.1), sealer-recorded (never trusted) | proposed |
| 1 | `ots` | bstr | req | var — the raw `.ots`, opaque at this layer (A parses; A owns DER/`.ots` limits at M2) | proposed |
| 2 | `block_height` | uint | opt: `status == attested` | attested Bitcoin block height | proposed |
| 3 | `block_header` | bstr | opt: `status == attested` | **80** (line 108) | proposed |
| 4 | `fetch_date` | uint | opt: `status == attested` | POSIX seconds (§3) — when the upgrade/header was fetched (semantics flagged to A, §13 item 5) | proposed |
| 5–23 | — | — | — | reserved | proposed |

### 7.9 TSA anchor artifact (lines 109, 112–114)

| key | field | type | presence | len/shape | status |
| --- | --- | --- | --- | --- | --- |
| 0 | `status` | uint | req | `anchor_status` (§6.1), sealer-recorded | proposed |
| 1 | `token` | bstr | req | var — DER TimeStampResp/token, opaque at this layer | proposed |
| 2 | `intermediates` | array | req, may be empty | bstr elements — DER certs, opaque; **intermediates only** (bundle-supplied roots never close a chain, line 109) | proposed |
| 3 | `fetch_date` | uint | req | POSIX seconds (§3) — when the token was obtained (always known at seal) | proposed |
| 4 | `source` | tstr | opt | informational TSA URL/identity; never verdict-bearing (the verdict's source identity comes from the verified cert chain). Added beyond the literal line-112 list because the report model renders a bundle-recorded source — flagged to D8, §13 item 1 | proposed |
| 5–23 | — | — | — | reserved | proposed |

### 7.10 Arbitrum receipt record (line 110) — opt-in

Internals are A/S-owned; this layer fixes only the envelope split:
the two user-visible "supporting evidence" data plus one opaque payload
(quote preimages + `proof_bytes` — the complete v1.1 verification-chain
capture). Shape to be confirmed with A/S — §13 item 4.

| key | field | type | presence | len/shape | status |
| --- | --- | --- | --- | --- | --- |
| 0 | `tx_hashes` | array | req | bstr(32) elements (Keccak-256 EVM tx hashes), non-empty | proposed |
| 1 | `block_number` | uint | req | | proposed |
| 2 | `payload` | bstr | req | var — opaque A/S serialization (quote preimages, `proof_bytes`) | proposed |
| 3–23 | — | — | — | reserved | proposed |

### 7.11 Covered-unit reveal (lines 96, 112–114)

| key | field | type | presence | len/shape | status |
| --- | --- | --- | --- | --- | --- |
| 0 | `unit_id` | uint | req | must resolve into the embedded manifest's unit table [R] | proposed |
| 1 | `k_u` | bstr | req | 32 | proposed |
| 2 | `ciphertext` | bstr | req | var; `≡ 16 (mod 256)`, `≥ 272` at parse (§2) | proposed |
| 3 | `cover` | array | req | `cover_entry` tuples (§5), non-empty (a covered unit has ≥ 1 leaf; the empty unit is never covered — empty files have no fine tree), strictly ascending interval start; leaf-exactness is R's check | pending-D9 |
| 4 | `paths` | array | req, may be empty | `path_node` tuples (§5), strictly ascending interval start; empty when the unit spans `[0, n)` (no boundary siblings) | pending-D9 |
| 5–23 | — | — | — | reserved | proposed |

### 7.12 Non-covered-unit reveal (lines 92, 94, 112–114)

`--no-fine-tree` whole-file units and raw-mirror units. Keys 0–2 aligned
with §7.11 (shared decode prefix).

| key | field | type | presence | len/shape | status |
| --- | --- | --- | --- | --- | --- |
| 0 | `unit_id` | uint | req | | proposed |
| 1 | `k_u` | bstr | req | 32 | proposed |
| 2 | `ciphertext` | bstr | req | var; same §2 shape check | proposed |
| 3 | `unit_salt` | bstr | req | 16 — opens `unit_commit` | proposed |
| 4–23 | — | — | — | reserved | proposed |

### 7.13 Touched-file entry (lines 112–114) — explicit `file_id`: YES (§10)

| key | field | type | presence | len/shape | status |
| --- | --- | --- | --- | --- | --- |
| 0 | `file_id` | uint | req | index into the embedded manifest's file table; in-range [R] | proposed |
| 1 | `path` | tstr | req | the sealed path; UTF-8 by type (native F3 check); opens `path_commit` with `path_salt` | proposed |
| 2 | `path_salt` | bstr | req | 16 | proposed |
| 3–23 | — | — | — | reserved | proposed |

### 7.14 Fully-revealed-file entry (lines 112–114, 121)

| key | field | type | presence | len/shape | status |
| --- | --- | --- | --- | --- | --- |
| 0 | `file_id` | uint | req | | proposed |
| 1 | `file_salt` | bstr | req | 16 — opens `raw_commit`/`canon_commit` (full reveal only, line 95) | proposed |
| 2 | `s_root` | bstr | opt: file's `fine_tree_present == 1` | 32 — the full `[0, n)` cover (line 114); `--no-fine-tree` files have no fine tree, hence no `s_root` | proposed |
| 3–23 | — | — | — | reserved | proposed |

Partial-reveal isolation (line 121) — a partially-revealed file must have
**no** §7.14 entry — is R's semantic check.

## 8. Deterministic list-ordering rules (F9 requirement)

Decoded order is always preserved on re-encode (decode∘encode identity);
the rules below make the *builder's* output unique per logical bundle and
are parse-checked where marked:

| list | order | checked at parse |
| --- | --- | --- |
| body `files` | manifest order (defines `file_id`) | trivially (order is meaning) |
| file `units` | manifest order (defines `unit_id`) | yes — stored `unit_id` must equal the derived ordinal (§7.5) |
| `sig_policy` | sealer's order, preserved (spec: ordered list) | duplicate-free only |
| `pubkeys` / `signatures` maps | ascending `sig_alg` | yes (map-key strict ascent) |
| `covered_reveals`, `noncovered_reveals` | strictly ascending `unit_id` | yes |
| `touched_files`, `full_reveals` | strictly ascending `file_id` | yes |
| `cover`, `paths` | strictly ascending leaf-interval start (§5) | yes |
| `ots_anchors`, `tsa_anchors` | capture order recorded in the seal journal (stable across rebuilds); wire order preserved as-is | no (builder rule; proposed — §13 item 5) |
| `intermediates` | as supplied by the TSA (chain order, leaf-adjacent first) | no (A's semantic domain) |
| `tx_hashes` | capture order | no |

## 9. Reserved key space — summary

- Every map's assigned keys and named-reserved keys live in `0..=23`;
  the per-map remainder of `0..=23` is range-reserved for v1.x additions.
  Reserved-key presence in v1 input → F10's distinct reserved-slot error
  naming the key. Keys `>= 24` → plain unknown-key error. (§1 rule 4.)
- Named reserved slots in v1: **bundle key 10 `range_reveals`** (v1.1
  sub-unit byte-range reveals, line 161) and **`sig_alg` values 2–15**
  (§6.2).
- The manifest envelope (§7.1) has **no** reserved space — shape frozen
  forever (§1 rule 6).
- A reserved key is *assigned* only by a recorded format decision; v1.x
  assignments must be additive (new optional field) — anything else is a
  version bump (line 123).

## 10. Touched-file explicit `file_id` — decision: YES (proposed)

The F4 task note requires this decision here. Bundle per-file sections
(§7.13/§7.14) carry an explicit `file_id` key 0. Rationale:

1. **Bundle sections are subsets.** In the manifest, `file_id` is the
   array index (line 76) — position is total and authoritative, and a
   stored id could only contradict it, so the manifest stores none. A
   bundle's touched-file list is a sparse subset of that table; without an
   explicit id, associating an entry to its file means trial-opening
   `path_commit` against every file entry — O(files) salted hashes per
   entry, and a *conflated* failure mode (a wrong salt and a
   nonexistent file become indistinguishable "no commitment matched").
2. **Distinct tamper errors.** With the id explicit, "file_id out of
   range", "path_commit mismatch", and "duplicate touched entry" are
   three distinct rows (line 168's distinct-error mandate); implicit
   association collapses them.
3. **Deterministic ordering needs a content-independent sort key** (§8):
   ascending `file_id` gives one; path strings do not (paths are
   sealer-chosen and only verifiable *after* association).
4. **Consistency:** unit reveals already carry explicit `unit_id` for the
   same reasons (spec line 114 lists `unit_id` in reveal entries but names
   no id for file entries — the asymmetry reads as unspecified, not
   deliberate; flagged in §13 item 2).

Cost: 1–2 bytes per touched file. `full_reveals` entries reference the
same id (their §7.13 counterpart must exist [R]).

## 11. Parser resource caps (F11 — placeholder)

Concrete cap constants (max bundle/manifest byte size, unit/file/anchor
counts, per-list lengths incl. cover/path/cert lists, CBOR nesting depth)
are F11's open decision and will be recorded **in this registry** when
frozen (F11 accept). Sizing floor already fixed by the spec: cover lists
must comfortably admit `2·⌈log₂ n⌉` entries at `n = 10⁸` (line 96).

## 12. Spec-coverage checklist

Every field named in MVP-SPEC.md lines 74–75, 98, and 112–114, mapped to
its registry row (F4 accept criterion). "—" = deliberately not a wire
field, with the reason.

| spec line | spec item | registry row |
| --- | --- | --- |
| 74 | manifest `{body: bstr, …}` | §7.1 key 0 |
| 74 | manifest `{…, signatures}` | §7.1 key 1 |
| 75 | `work_id` | — derived: SHA-256(§7.1 key 0 contents); never stored (would be redundant/confusable) |
| 75 | `anchor_digest` | — derived: SHA-256(full manifest bytes = §7.6 key 1 contents); never stored |
| 98 | format version | §7.2 key 0 |
| 98 | app version | §7.2 key 1 |
| 98 | `seal_id` | §7.2 key 2 |
| 98 | title | §7.2 key 3 |
| 98 | claimed time | §7.2 key 4 |
| 98 | pubkeys | §7.2 key 5 |
| 98 | `sig_policy` (non-empty) | §7.2 key 6 |
| 98 | file table | §7.2 key 7 |
| 98 | `path_commit` | §7.3 key 0 |
| 98 | `raw_commit` | §7.3 key 1 |
| 98 | `canon_commit`? | §7.3 key 2 |
| 98 | `size` (leaf count / tiling domain) | §7.3 key 3 |
| 98 | canonicalization descriptor | §7.3 key 4 → §7.4 (kind, fine-tree presence, domain, Unicode version — lines 83/98; no forced flag per D20) |
| 98 | `fine_root`? | §7.3 key 5 |
| 98 | unit table | §7.3 key 6 |
| 98 | `unit_id` | §7.5 key 0 |
| 98 | unit `kind` (normal \| raw-mirror) | §7.5 key 1 + §6.3 |
| 98 | byte-range | §7.5 key 2 + §4 |
| 98 | `true_length` | §7.5 key 3 |
| 98 | `unit_commit`? (iff not covered) | §7.5 key 4 |
| 98 | nonce | §7.5 key 5 |
| 98 | ciphertext network address | §7.5 key 6 |
| 98 | manifest storage record `{address, nonce, k_m}` | §7.6 key 2 → §7.7 keys 0–2 |
| 112 | self-contained / offline | — property of the whole §7.6 shape (no field) |
| 112 | plaintext manifest bytes | §7.6 key 1 |
| 112 | manifest storage record | §7.6 key 2 |
| 112 | per-anchor status | §7.8 key 0, §7.9 key 0 + §6.1 |
| 112 | `.ots` | §7.8 key 1 |
| 112 | embedded Bitcoin header (where upgraded) | §7.8 keys 2–3 (height + 80-B header) |
| 112 | TSA tokens | §7.9 key 1 (one artifact per token; ≥ 2 TSAs ⇒ ≥ 2 entries) |
| 112 | intermediate certs | §7.9 key 2 |
| 112 | fetch dates | §7.8 key 4, §7.9 key 3 |
| 112 | receipt (only if opted in) | §7.6 key 5 → §7.10 |
| 114 | covered unit: `unit_id` | §7.11 key 0 |
| 114 | covered unit: `k_u` | §7.11 key 1 |
| 114 | covered unit: embedded ciphertext | §7.11 key 2 |
| 114 | covered unit: leaf-exact GGM sub-cover | §7.11 key 3 + §5 |
| 114 | covered unit: boundary Merkle paths | §7.11 key 4 + §5 |
| 114 | non-covered unit: `unit_id` | §7.12 key 0 |
| 114 | non-covered unit: `unit_salt` | §7.12 key 3 |
| 114 | non-covered unit: `k_u` | §7.12 key 1 |
| 114 | non-covered unit: embedded ciphertext | §7.12 key 2 |
| 114 | touched file: path | §7.13 key 1 |
| 114 | touched file: `path_salt` | §7.13 key 2 |
| 114 | fully-revealed file: `file_salt` | §7.14 key 1 |
| 114 | fully-revealed file: `s_root` | §7.14 key 2 |
| 114 | raw-mirror unit "when proving exact original bytes" | — rides as a §7.12 entry (its manifest `kind` = raw-mirror identifies it); the whole-file-only selection rule is U's CLI gate (line 92), not wire |
| 114 | (v1.1) sub-unit range covers + boundary paths | §7.6 key 10 — reserved, reject-in-v1 |
| 114 | "Nonces come from the manifest (single source of truth)" | — checked absence: §7.11/§7.12 deliberately have **no** nonce key |

## 13. Ambiguities found and D8 feed

Items the spec's field lists leave open; each is proposed above and needs
a D8 (or A/S) confirmation at sign-off:

1. **TSA source identity** (§7.9 key 4): the report model
   (`crates/antseal-core/src/verify/report.rs`, `AnchorResult::source`)
   expects a bundle-recorded source identity, but lines 112–114 do not
   list one. Proposed: optional informational `tstr` on TSA artifacts
   only (the `.ots` is self-describing — calendar URLs live inside its
   attestations; the TSA URL is not reliably recoverable from the token).
2. **Explicit `file_id` in per-file bundle sections** — decided YES here
   (§10); the spec names ids for unit entries but is silent for file
   entries.
3. **`title` / `app_version` optionality**: proposed required-may-be-empty
   `tstr` (one shape; no absent-vs-empty split). If D8 prefers absence for
   "no title", §7.2 key 3 becomes `opt` — decide once.
4. **Receipt record internal split** (§7.10): proposed
   `{tx_hashes, block_number, payload}` with payload opaque; A/S must
   confirm this envelope carries the full S1-surveyed capture (quote
   preimages + `proof_bytes`) for the v1.1 chain.
5. **Recorded anchor-status subset + OTS `fetch_date` semantics + anchor
   list order** (§6.1, §7.8, §8): which of the seven states are legal *as
   recorded*, per kind, and the exact capture-date meaning — A/R rule,
   wire type unaffected.
6. **Raw-mirror position within a file's `units` array**: proposed
   builder rule "after all non-mirror units"; parse accepts any position
   (only the non-mirror tiling order is invariant-bearing).
7. **`unit_id` stored-and-checked** (§7.5 key 0): the spec lists the field
   *and* defines it as derivable; proposed to store + parse-check
   equality. If D8 prefers derived-only, key 0 is removed and keys shift —
   decide before F5.

Open co-freezes tracked elsewhere: D9 (§5, with G8), D17 (§6.2, with
C14), F11 caps (§11).

## 14. Machine-readable mirror and tests

[`registry-v1.json`](registry-v1.json) mirrors this document 1:1 — every
map, key number, type, presence rule, fixed length, enum value, tuple
shape, and reserved range, with per-item `status` markers
(`proposed` / `pending-D9` / `pending-D17`). The draft-stage test
`crates/antseal-core/tests/format_registry_draft.rs` asserts: the JSON
parses; every key/value/index is an unsigned integer; no duplicate key
numbers within any single map (nor values within an enum); reserved
ranges are well-formed, mutually disjoint, and collide with no assigned
key. The 1:1 code-constants ⟷ registry assertion lands with F5/F8, and
the F11 cap constants join the mirror when frozen.
