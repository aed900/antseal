# antseal wire-format registry — v1 (F4)

> **DRAFT — NOT FROZEN. This registry freezes only at the Q14
> `format-v1-freeze` gate (M0 Definitions sign-off).** Until then every row
> is a *proposal*, including every row added by the bundle-slice pass
> below — nothing here is frozen by having been written down. Feeding
> decisions, marked inline wherever they bite:
>
> - **D8** — the registry as a whole (key assignments, reserved ranges,
>   signatures container, time encoding, byte-range representation,
>   explicit `file_id`). **Open.** Rows carry status `proposed` = pending
>   D8 sign-off. The D8 feed is §13.
> - **D9** — GGM node-address representation, co-frozen with G8.
>   **RESOLVED 2026-07-28** (`(level, index)`, Candidate A —
>   docs/decisions/D9-ggm-node-address.md). The former `pending-D9` rows
>   now carry `proposed`: decided, but still riding the D8/Q14 freeze like
>   every other row. The §5 candidate comparison stays as the recorded
>   rationale.
> - **D17** — `sig_policy` algorithm-ID numeric values. **Open**
>   (ratified in code at M0 wave 3; formal flip at Q14). Rows carry status
>   `pending-D17`. Proposed values in §6.2.
>
> After Q14, this document is normative and any change is a format-version
> event (MVP-SPEC.md line 123).

- Task: **F4** (tasks/F.md). Date: 2026-07-27; **bundle slice completed
  2026-07-28** (the D8 `.sealproof` half — §§7.6–7.15, feeding F8/F9).
- Spec basis: MVP-SPEC.md lines 71–79 (Definitions & encoding), 90
  (`seal_id`), 91–98 (unit/body fields), 112–114 (reveal bundle), 121
  (structural invariants), 123 (format stability), 127–137 (anchor states),
  161 (v1.1 parking lot — the reserved slots of §9).
- Resolved inputs: D7 (`minicbor =2.3.0`, uint keys, manual impls), D11
  (Autonomi address = 32 B BLAKE3, docs/research/S1-ant-core-api-survey.md
  §1), D25 (`unicode-17.0.0`), D20/D21 (descriptor carries `kind` only — no
  forced-text flag; canonicalization pipeline frozen), D27/D29 (verification
  report is a *separate, non-wire* byte format — context only), **D9**
  (`NodeAddress = (level, index)` — §5), **D23** (a file's raw mirror is its
  **last** unit — §7.5, §8), **D22/D24** (splitting rules; no bundle-visible
  field), **D28** (full-reveal strictness is **hard-fail**, and reveal shape
  is **derived, never declared** — §7.14, and the fourth checked absence in
  §7.6.1), **D30** (stable error codes: every rejection class named here must
  land on its own code — docs/testing/error-code-contract.md).
- Registered decisions this slice fed and **F8 subsequently resolved**
  (2026-07-28): **D74** — extraneous `s_root` on a fine-tree-absent full
  reveal: **reject** (§7.14); **D75** — a full reveal ships covers *and*
  `s_root`: **both** (§7.11); **D80** — a revealed unit's owning file must
  appear in `touched_files`: **required, tier [R]** (§7.6). Still open and
  **not** resolved here: **D77** (zero-non-mirror-unit file — §7.14's
  anti-vacuity clause makes the predicate safe without it), **D76**
  (splitting `file_salt` — recommended NO for v1).
- Ratified before F8 and binding on it: **D78** (bundle schema validation
  never opens the embedded manifest — §0, §7.6.3), **D79** (the OTS upgrade
  group is free-standing all-or-nothing, never keyed on `status` — §7.8).
- Already-consumed rows: the manifest-side maps §§7.1–7.5 are **implemented**
  (F5/F6 — `crates/antseal-core/src/manifest/`, key constants in
  `manifest/registry.rs`). Their key numbers are consumed; the bundle slice
  composes with them and does not move them.
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
  rule holds). Absence is always key absence — v1 has no `null` (§1).
  Every conditional row carries a **validation tier** (below) saying who
  can decide it.
- **len/shape** — exact byte length for fixed-size `bstr` fields; element
  type for arrays; `var` for variable-length opaque bytes.
- **status** — `proposed` (pending the D8 whole-registry sign-off) or
  `pending-D17`. (`pending-D9` is retired: D9 resolved 2026-07-28. The
  draft-gate vocabulary in §14 still admits it so the marker can never be
  reintroduced unregistered.)

### Validation tiers

Recorded so rows do not over-claim, and so F8 and R cannot both assume the
other checks a rule. F3 enforces CBOR canonicality beneath all three.

| tier | who | decidable from | examples |
| --- | --- | --- | --- |
| **[P]** | F5 (manifest) / F8 (bundle) | the **one entry** being decoded | type, exact byte length, enum membership, non-empty container, `level ≤ 64`, `index < 2^level` |
| **[X]** | F5 / F8, same pass | the **whole container** it is decoding (manifest body, or bundle) | list ordering, `unit_id` = derived ordinal, cross-section id disjointness, descriptor-conditioned presence within one file entry |
| **[R]** | R (verify), post-decode | the **bundle *and* the embedded manifest**, or crypto | `full_reveal.s_root` presence, which reveal array a unit belongs in, tiling, leaf-exact cover, `true_length` = range width, partial-reveal isolation (MVP-SPEC.md line 121) |

**Proposed rule (D8 feed, §13 item 8): bundle schema validation never
consults the embedded manifest.** F8 decodes the bundle from the bundle's
own bytes; the manifest is layer 2 of F9's pipeline and is not available
to — and must not be reached for by — a bundle-schema presence rule. Any
rule needing both sides is therefore **[R]**, not a schema error. This is
what keeps the two error families separate under D30: a bundle that is
*well-formed but inconsistent with its manifest* must report a verify
code, never a schema code, so "malformed bundle" and "lying sealer" never
render alike.

The 1:1 assertion that **code constants match this table** arrives with
F5/F8 (schema types) — the current draft test (§14) checks only the
mirror's internal consistency. §7.15 lists what F8 must register for the
bundle half.

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

## 5. GGM sub-cover / boundary-path node addressing — status: proposed (D9 RESOLVED — Candidate A)

> **D9 resolved 2026-07-28** — `(level, index)`, Candidate A below
> (docs/decisions/D9-ggm-node-address.md). G8 implements the semantic
> counterpart `content::ggm::NodeAddress` with the identical form and
> `MAX_LEVEL = 64`. The candidate comparison is retained as the recorded
> rationale, not as an open choice. Co-frozen with the rest of the
> registry at Q14.

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
`s_root` via the bits of `index`". **Adopted: G8 implemented the same
convention independently, and D9 resolved to it on 2026-07-28.** Frozen
with the registry at Q14, not before.

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

### Tuple shapes (D9-decided)

- **`cover_entry` = `[level, index, seed]`** — `uint, uint, bstr(32)`.
  One disclosed GGM seed of the leaf-exact sub-cover.
- **`path_node` = `[level, index, hash]`** — `uint, uint, bstr(32)`. One
  boundary Merkle sibling node hash.

Both are **3-element definite arrays**; a wrong element count is a shape
error, not a missing-field error (arrays have no key space and therefore
no reserved slots — a future extra element would be a format-version
event, §9).

**Address validity splits across two tiers** (§0), and F8 must implement
only the first:

| check | tier | rationale |
| --- | --- | --- |
| `level ≤ 64` | **[P]** | self-contained; `MAX_LEVEL = 64` because `d = ⌈log₂ n⌉ ≤ 64` for any `n ≤ u64::MAX`. Bounds the `1 << level` below so it cannot overflow — do the level check *first* |
| `index < 2^level` | **[P]** | self-contained once `level ≤ 64` holds |
| `level ≤ d` | **[R]** | needs the file's `size` from the embedded manifest |
| deepest-slot rule; leaf-exactness; no-ancestor-seed | **[R]** | needs the manifest and G13's cover derivation |

G8's `NodeAddress::try_new` already returns the two [P] rejections
(`NodeAddressLevelTooDeep`, `NodeAddressIndexOutOfRange`) and
`NodeAddressLevelExceedsDepth` for the first [R] one, so F8 should
construct through it rather than re-check inline — one implementation of
the bound, one error per class (D30).

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

**Why it is frozen, not merely stable (F10).** The manifest's version
discriminant sits *inside* the `body` bstr (§7.2 key 0), so a verifier must
decode this envelope **before** it can read the version at all. The envelope
is therefore the one map that can never carry a version-specific change:
whatever parses it has to work for every version that will ever exist,
including versions written after that parser shipped. Anything a future
version needs to say goes inside the body, where dispatch can see it.

Consequences, all asserted:

- The envelope has **no reserved band** — reserving space would imply a
  future field, and there can be none. Any key besides 0/1 is
  `manifest-unknown-key`, never `manifest-reserved-key`.
- The envelope has **no discriminant of its own**. Adding one would be
  redundant with key 0 of the body and could disagree with it.
- Dispatch order differs between the two artifacts, deliberately: the
  **bundle**'s discriminant (§7.6 key 0) is a top-level key of the file, so
  an unsupported bundle is rejected from its first bytes; the **manifest
  body**'s is one layer in, so its rejection follows the envelope decode.
  See §9, "Version dispatch order".

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
121). **D23 (resolved 2026-07-27): a file's raw mirror, if present, is
that file's *last* unit** — at most one per file, so within each file the
id order of the tiling set equals its range order and the mirror always
holds the file's highest `unit_id`. This is a **seal-side construction
rule**: parse accepts any position and R exempts mirrors *by `kind`,
never by position* (`verify::structural`), so a hand-built manifest that
violates the placement still verifies or fails on content grounds alone.
Bundle consequence: in `noncovered_reveals` (§7.6 key 7), a file's mirror
reveal sorts after every non-covered reveal of the same file.

### 7.6 Bundle top level (lines 112–114)

Version discriminant at key 0 (encoded first). Every key is `req` except
the opt-in receipt, so a `.sealproof` has exactly **one** shape per
logical content: the "nothing revealed, nothing anchored" bundle is
`{0,1,2, 3:[], 4:[], 6:[], 7:[], 8:[], 9:[]}`, not a bundle with keys
missing. Required-may-be-empty everywhere avoids the absent-vs-empty
encoding split that would give one logical bundle two byte encodings.

| key | field | type | presence | len/shape | status |
| --- | --- | --- | --- | --- | --- |
| 0 | `format_version` | uint | req | = 1 in v1. Versions **independently** of the manifest (line 123): a v1 bundle may embed a v2 manifest and vice versa, so F10 dispatches the two discriminants separately and never infers one from the other | proposed |
| 1 | `manifest` | bstr | req | var — the full **plaintext manifest envelope** bytes (§7.1) exactly as anchored; `anchor_digest` = SHA-256 of exactly these bytes (line 75); nested strict decode per F9 (§7.6.3) | proposed |
| 2 | `storage_record` | map | req | §7.7 | proposed |
| 3 | `ots_anchors` | array | req, may be empty | OTS artifacts (§7.8); an UNANCHORED bundle is **both** anchor arrays empty | proposed |
| 4 | `tsa_anchors` | array | req, may be empty | TSA artifacts (§7.9) | proposed |
| 5 | `receipt` | map | **opt — no parse-decidable condition** [P]: presence *is* the sealer's `--include-receipt` opt-in (line 110). Absence is never an error and presence is never required; a verifier must not read anything into either | §7.10 | proposed |
| 6 | `covered_reveals` | array | req, may be empty | §7.11 entries, strictly ascending `unit_id` [X] | proposed |
| 7 | `noncovered_reveals` | array | req, may be empty | §7.12 entries, strictly ascending `unit_id` [X]; raw-mirror reveals ride here (a raw mirror is never fine-tree-covered, line 94), and by D23 a file's mirror sorts last among its own entries | proposed |
| 8 | `touched_files` | array | req, may be empty | §7.13 entries, strictly ascending `file_id` [X] | proposed |
| 9 | `full_reveals` | array | req, may be empty | §7.14 entries, strictly ascending `file_id` [X]; every entry's `file_id` must also appear in `touched_files` — **[X], not [R]**: both lists are in the bundle, so F8 decides it without the manifest | proposed |
| 10 | `range_reveals` | — | **reserved, named** | v1.1 sub-unit arbitrary-byte-range covers + boundary paths (lines 114/161); reject-if-present in v1 (§9) | proposed |
| 11–23 | — | — | — | reserved | proposed |

**Cross-section rules of the bundle map** (all **[X]** — bundle-only, so
F8 owns them; none needs the manifest):

| rule | why it is not [R] |
| --- | --- |
| `covered_reveals` and `noncovered_reveals` `unit_id` sets are **disjoint** | both lists are present; a unit revealed twice is a malformed bundle regardless of what the manifest says. R's `DuplicateUnitReveal` remains the backstop for the manifest-aware case |
| `full_reveals ⊆ touched_files` by `file_id` | ditto — a full reveal whose path was never disclosed is malformed on its face |
| the two reveal arrays are each strictly ascending | ordering is a bundle property (§8) |

The matching **[R]** rules — the ones that genuinely need both sides —
are: *which* array a unit belongs in (covered iff its file has
`fine_tree_present == 1` and its `kind` is not `raw-mirror`, line 94),
every id resolving into the manifest tables, `full_reveal.s_root`
presence (§7.14), and — **D80, resolved 2026-07-28 with F8** — that
**every revealed unit's owning file has a `touched_files` entry**
(`docs/decisions/D80-revealed-unit-touched-file.md`).

D80 is [R] and not [X] precisely because "a revealed unit's *owning
file*" is a manifest fact: the unit table is nested inside file entries,
so the mapping needs layer 2, which §0's rule forbids the bundle schema
layer from reaching for. It is therefore a verify-pipeline outcome
(recommended `revealed-unit-file-not-touched`; R4/R5 mints the final
spelling), **not** a `bundle-` code — and it does not subsume the
`full_reveals ⊆ touched_files` row above, which stays [X]: a file may be
touched by a unit reveal without being fully revealed.

The evidence, since this one was a genuine open question: line 95 says
`path_salt` "ships whenever any reveal *touches* the file (so the
recipient can verify the path)", and line 121 gives only two rendering
states — revealed content, or "unrevealed files render as committed
placeholders (size only, path withheld)". A permissive reading would
need a third state the spec does not define, and would hide only the
*filename*: the plaintext manifest already exposes file identity, size,
and unit boundaries to every recipient (line 95, stated deliberately).

**Canonical concatenation order.** Where a consumer needs "the revealed
units" as one sequence — e.g. `verify::structural::BundleView`'s
`revealed_unit_ids`, whose first-duplicate report must be deterministic —
it is `covered_reveals` ⧺ `noncovered_reveals`, i.e. **section key
order**. Recorded here so R5's population order is a registry fact rather
than an implementation accident.

#### 7.6.1 Checked absences — what a bundle deliberately does not carry

Three fields are absent **by design**, and F8's checklist test asserts
their absence rather than merely not implementing them (the F8 accept
criterion for nonces generalizes to all three). An absence nobody tests
is an absence that grows back.

| absent | why | consequence if it were added |
| --- | --- | --- |
| **per-unit `nonce`** in §7.11/§7.12 | "Nonces come from the manifest (single source of truth)" (line 114) | a bundle-side nonce would be a second, sealer-controlled AEAD input the verifier could be steered onto; `verify::unit_stages::RevealedUnitInput` deliberately exposes no parameter to smuggle one through |
| **any signature container** at bundle level | the bundle is **unsigned**. Its authority is the embedded *signed* manifest (§7.1 key 1) plus the anchor artifacts; nothing about a `.sealproof` is authenticated as a whole | a bundle signature would invite the verifier to trust the *assembler* — but the assembler is the sealer, i.e. the adversary (line 121). There is deliberately no `sig_alg` map here and no §7.1-style envelope |
| **`work_id` / `anchor_digest` / `seal_id`** at bundle level | all three are *derived*: `work_id` = SHA-256(manifest body bytes), `anchor_digest` = SHA-256(key 1 bytes), `seal_id` is a manifest body field | a stored copy could disagree with the bytes it claims to summarize, creating a "which one is authoritative" question with no good answer (§12) |
| **any reveal-shape discriminant** (`is_full_reveal`, `reveal_mode`, …) at any level | **D28 rider 1**: reveal shape is *derived* from the signed unit table and the revealed set, never declared | a declared shape is sealer-forgeable: declaring "partial" while revealing every unit would smuggle back the permissive full-reveal option D28 rejected — through the format rather than through the verifier (§7.14) |

#### 7.6.2 Anchor kind is positional, not a field

An anchor artifact carries **no `kind`/`type` key**; whether it is an OTS
or a TSA anchor is fixed by *which array* it rides in (key 3 vs key 4).
F8's task text lists "anchor type" among the per-anchor fields — that item
is satisfied by the array split, and this row records why the field does
not exist:

1. **The illegal state is unrepresentable.** With a `kind` field, a TSA
   token sitting in the OTS array is a *representable* state needing a
   checked rule and a tamper row. With the split, it cannot be written.
2. **The two shapes genuinely differ** (§7.8 has `.ots` + block height +
   header; §7.9 has a DER token + an intermediates list), so a single
   union map would need presence rules keyed on `kind` — reintroducing
   exactly the coupling item 1 removes.
3. **Verdict aggregation is per-kind anyway** (R17/A18): OTS is
   online-gated for `proven`, TSA is offline-verifiable, so no consumer
   wants a kind-agnostic anchor list.

Cost: a future third anchor kind is a new top-level key, not a new enum
value. That is the intended shape — a new anchor kind arrives with a new
artifact schema regardless, so it was never going to be a one-value
change (§9).

#### 7.6.3 Nested decode layers (F9) and the manifest seam

A `.sealproof` decodes in **three strict layers**, each with its own
error class so a tamper row can name which one a mutation broke:

| layer | input | decoder | strictness |
| --- | --- | --- | --- |
| 1 | the whole file | F8/F9 bundle decode | canonical CBOR (F3) + bundle schema; trailing bytes rejected |
| 2 | key 1's `bstr` contents | `manifest::Manifest::decode` | canonical CBOR + envelope schema |
| 3 | the envelope's `body` `bstr` | `manifest::body::ManifestBodyV1::decode` | canonical CBOR + body schema, after F10 reads the body's own key 0 |

Composition requirements this puts on F8/F9, from the shape F6 already
shipped:

- `Manifest<'b>` **borrows** its input. The bundle decoder must hand
  layer 2 a **sub-slice of the bundle input**, not a copy: `Manifest`'s
  zero-copy guarantee — that the bytes fed to `work_id` and to signature
  verification are the received ones *by construction* — only holds if
  the slice really is the bundle's own bytes. A decode-into-`Vec` step
  would silently downgrade that guarantee to a convention.
- The same slice is the `anchor_digest` pre-image. `Manifest::encoded_bytes()`
  returns it, so the digest is taken from the decoded object rather than
  re-derived by the caller.
- Layers 2 and 3 already report as `ManifestError::Envelope` /
  `ManifestError::Body`; layer 1 needs its own bundle-schema error class
  that can never be confused with either (F9 accept).
- **Nesting depth for F11**: the deepest v1 chain is bundle map →
  `covered_reveals` array → reveal map → `cover` array → `cover_entry`
  array = **5** container levels, plus layers 2–3 contributing manifest
  map → `files` array → file entry map → `units` array → unit entry map →
  `range` array = **6**. The two do not nest (layer 2 starts from a fresh
  decoder over the `bstr` contents), so the cap is `max(5, 6)`, not
  `5 + 6` — recorded so F11 does not budget a depth that permits absurd
  bundle nesting.

### 7.7 Manifest storage record (line 98)

The **manifest's own** storage triple, not a per-unit one: each unit's
address and nonce live in the manifest unit table (§7.5 keys 5–6). It
exists so the storage-linkage layer can re-fetch and decrypt the uploaded
*encrypted* manifest copy — "bytes anchored ≠ bytes stored" (line 98).

| key | field | type | presence | len/shape | status |
| --- | --- | --- | --- | --- | --- |
| 0 | `address` | bstr | req | 32 (D11) — Autonomi address of the **encrypted** manifest copy | proposed |
| 1 | `nonce` | bstr | req | 24 — the XChaCha20-Poly1305 nonce of that copy. Manifest AEAD uses **empty AAD** (line 98), so no further binding field is carried | proposed |
| 2 | `k_m` | bstr | req | 32 — `k_m = HKDF(W, "manifest-key")`. Disclosing it costs nothing: the bundle already embeds the plaintext manifest (line 98) | proposed |
| 3–23 | — | — | — | reserved | proposed |

Required, not optional, even though nothing in the **evidence** layer
consumes it: an absent record would be a second bundle shape for the same
logical content, and the layer that does consume it (storage linkage /
`--live`) must be able to say "this bundle claims persistence and the
claim fails" rather than "this bundle said nothing". The evidence verdict
never depends on it (line 112) — that separation is R's, and no wire flag
encodes it.

### 7.8 OTS anchor artifact (lines 108, 112–114)

**Artifact internals stay opaque at this layer.** `.ots` bytes are a
`bstr` F8 never parses; the attestation/ops model, the calendar
semantics, and the `.ots` size limits are **A's, at M2**. This registry
reserves the *shape* only.

| key | field | type | presence | len/shape | status |
| --- | --- | --- | --- | --- | --- |
| 0 | `status` | uint | req | `anchor_status` (§6.1), sealer-recorded (**never trusted** — the verifier derives its own state) | proposed |
| 1 | `ots` | bstr | req | var — the raw `.ots`, opaque (A parses; A owns `.ots` limits at M2) | proposed |
| 2 | `block_height` | uint | opt: **upgrade group** (below) | attested Bitcoin block height | proposed |
| 3 | `block_header` | bstr | opt: **upgrade group** | **exactly 80** [P] (line 108) — a wrong length is its own error, never a "malformed header" | proposed |
| 4 | `fetch_date` | uint | opt: **upgrade group** | POSIX seconds (§3) — when the upgrade/header was fetched (semantics flagged to A, §13 item 5) | proposed |
| 5–23 | — | — | — | reserved | proposed |

**The upgrade group (keys 2–4) is all-or-nothing** [X]: an upgraded OTS
anchor carries height + header + fetch date together, and a
not-yet-upgraded one carries none of them. Two of the three present is a
malformed artifact, not a partially-known one. Stating it as a *group*
(rather than three independent `opt` rows) is what makes "header without
height" a single distinct rejection instead of a rule that has to be
rediscovered per key.

Whether the group's presence is additionally **tied to `status ==
attested`** is a genuinely open, format-permanent question and is
**flagged to D8 as §13 item 9** — it is the one place in this registry
where a parse rule would depend on a field the design elsewhere says the
verifier must never trust. Both readings are drafted there; the group
rule above holds either way.

### 7.9 TSA anchor artifact (lines 109, 112–114)

Same discipline: the DER token and the certificates are opaque `bstr`s
here. CMS/X.509 parsing, chain validation against the pinned root store,
and the "valid at stamping" evaluation are **A's, at M2**.

| key | field | type | presence | len/shape | status |
| --- | --- | --- | --- | --- | --- |
| 0 | `status` | uint | req | `anchor_status` (§6.1), sealer-recorded (never trusted) | proposed |
| 1 | `token` | bstr | req | var — DER TimeStampResp/token, opaque | proposed |
| 2 | `intermediates` | array | req, may be empty | bstr elements — DER certs, opaque; **intermediates only**: a bundle-supplied chain can never close against a bundle-supplied root (line 109), so no root slot exists here to be tempted by | proposed |
| 3 | `fetch_date` | uint | req | POSIX seconds (§3) — when the token was obtained; always known at seal, hence required where the OTS counterpart is optional | proposed |
| 4 | `source` | tstr | **opt — no parse-decidable condition** [P] | informational TSA URL/identity; **never verdict-bearing** (the verdict's source identity comes from the verified cert chain, not from this string). Beyond the literal line-112 list because the report model renders a bundle-recorded source — flagged to D8, §13 item 1 | proposed |
| 5–23 | — | — | — | reserved | proposed |

One artifact per token: "≥ 2 TSAs" (line 103) means ≥ 2 entries in key 4
of §7.6, not a multi-token artifact. Nothing in the schema requires two —
an under-anchored bundle is a *verdict*, not a parse error.

### 7.10 Arbitrum receipt record (line 110) — opt-in

Internals are A/S-owned; this layer fixes only the envelope split:
the two user-visible "supporting evidence" data plus one opaque payload
(quote preimages + `proof_bytes` — the complete v1.1 verification-chain
capture). Shape to be confirmed with A/S — §13 item 4.

| key | field | type | presence | len/shape | status |
| --- | --- | --- | --- | --- | --- |
| 0 | `tx_hashes` | array | req | bstr(32) elements (Keccak-256 EVM tx hashes), non-empty; capture order (§8) | proposed |
| 1 | `block_number` | uint | req | the payment's Arbitrum One block number | proposed |
| 2 | `payload` | bstr | req | var — opaque A/S serialization (quote preimages, `proof_bytes`). **Opaque to this registry**: its internal layout is A/S's and is *not* a v1 wire format, so changing it is not a format-version event | proposed |
| 3 | `chain_inputs` | — | **reserved, named** | v1.1 Arbitrum-receipt **verification chain** (line 161: address recomputation ↔ quote preimages ↔ tx calldata) — the slot into which v1.1 may promote registry-visible, version-stable structure out of the opaque `payload`. Reject-if-present in v1 (§9). Shape deliberately **not designed here** — A/S own it | proposed |
| 4–23 | — | — | — | reserved | proposed |

**Why a named slot when capture is already complete.** The MVP obligation
is only that the v1.1 chain stay *possible with no reseal* (TODO parking
lot), and key 2 satisfies it: every input the chain needs is captured at
payment time. But key 2 is **opaque** — deliberately outside this
registry — so anything the v1.1 verifier must read in a *version-stable,
cross-implementation* way (the WASM page and the CLI agreeing on a
structure, per the line-123 stability contract) cannot live there. That
needs a registry key, and a frozen v1 map can only gain one from a
**reserved** slot (§9). Naming it now costs nothing and is the difference
between "v1.1 adds a field" and "v1.1 is a format-version event".

MVP verdict is unchanged and unchangeable by this slot: the receipt
renders as **supporting evidence — no independently proven time** (line
110), because no on-chain datum contains `anchor_digest`. No reserved
slot can promote it, and none should be read as promising to.

### 7.11 Covered-unit reveal (lines 96, 112–114)

| key | field | type | presence | len/shape | status |
| --- | --- | --- | --- | --- | --- |
| 0 | `unit_id` | uint | req | must resolve into the embedded manifest's unit table **[R]** | proposed |
| 1 | `k_u` | bstr | req | 32 **[P]** — the unit key, disclosed per reveal so the verifier decrypts without ever holding `W` (line 114) | proposed |
| 2 | `ciphertext` | bstr | req | var; `len ≡ 16 (mod 256)` and `len ≥ 272` **[P]** (§2). The exact `len == padded_length(true_length) + 16` is **[R]** — it needs the manifest's `true_length` | proposed |
| 3 | `cover` | array | req **(D75 RESOLVED — "both"; see below)** | `cover_entry` tuples (§5), **non-empty [P]** (a covered unit has ≥ 1 leaf; the empty unit is never covered — empty files have no fine tree, §7.4), strictly ascending interval start **[X]**; leaf-exactness and the no-ancestor-seed rule are **[R]** | proposed |
| 4 | `paths` | array | req, may be empty | `path_node` tuples (§5), strictly ascending interval start **[X]**; empty exactly when the unit spans `[0, n)` (no boundary siblings) — the *exactly* is **[R]** | proposed |
| 5–23 | — | — | — | reserved | proposed |

The nonce is **not** here: it comes from the manifest unit table (§7.6.1).
`AAD = seal_id ‖ LE64(unit_id)` (line 91) is likewise reconstructed from
the manifest and this entry's `unit_id`, never carried.

Because `cover`/`paths` are **nested inside** the reveal they belong to,
a proof can only speak about the unit whose entry encloses it — the
"proof reaches outside the revealed set" state
(`VerifyError::UnknownUnitRef` via `BundleView::proof_unit_refs`) is
therefore **unrepresentable in v1** and that check idles. It stops idling
the moment bundle key 10 (`range_reveals`) is assigned in v1.1, where a
range proof may well name units by id from a separate section — recorded
so the check is not deleted as dead code.

#### D75 — does a full reveal ship per-unit covers *and* `s_root`?

> **RESOLVED 2026-07-28 with F8: "both"** — key 3 is unconditionally
> `req` at tier [P]
> (`docs/decisions/D75-full-reveal-cover-shape.md`). The draft's lean
> below is retained as the recorded rationale, not as an open choice.
> The decision's rider is binding: because two independent routes to
> `fine_root` now coexist, **they must be required to agree** — leaf
> salts derived from `s_root` and from the per-unit covers are the same
> values, and a disagreement is an equivocation attempt. That is an
> **open tamper row for R4/Q8**, without which the redundancy buys
> nothing.

**The original registered framing (D75, resolve with F8):**
On a *full* reveal of a fine-tree file the bundle would, as drafted,
carry both this entry's per-unit `cover`/`paths` for every unit **and**
the file's `s_root` (§7.14 key 2) — two independent routes to the same
`fine_root`. D75 asks whether the covers should instead be omitted in
that case.

**The key assignment is answer-neutral, and deliberately so.** Nothing
about D75 moves a key, a type, or a reserved slot: key 3 keeps its number
either way. Only its *presence rule* differs —

- **"both"** (as drafted): `req`, **[P]** — a covered reveal is
  self-contained and F8 validates it without the manifest;
- **"`s_root` only"**: `opt: ¬full(F)`, which is **[R]** — key 3's
  presence would then depend on the derived full-reveal predicate
  (§7.14), so F8 could no longer validate a covered reveal in isolation
  and the rule would cross the §0 tier boundary.

**Which way the draft leans, and why: "both".** Three reasons, offered as
D75 input rather than as a decision: (1) it keeps key 3 at tier [P], so
bundle schema validation stays decidable from the bundle alone (§0);
(2) it costs bytes but leaks nothing — on a full reveal every leaf is
disclosed anyway, which is exactly why line 114 says `s_root` "discloses
nothing" there; (3) it keeps one decode shape for `covered_reveal`
instead of two. The cost is real: ~2·⌈log₂ n⌉ cover entries per unit are
redundant once `s_root` is present.

**The consequence D75 actually decides** is what R4's `s_root` tree
rebuild *is*: under "both" it is defence-in-depth (each unit is already
bound to `fine_root` through its own cover, and the rebuild additionally
proves no extra leaves), while under "`s_root` only" it becomes the sole
binding and is load-bearing. Note the rebuild is spec-mandated by line
121 either way — D75 changes its weight, not whether it runs. Under
"both", the two routes must be required to *agree*: leaf salts derived
from `s_root` and from the per-unit covers are the same values, and a
disagreement is a distinct tamper row someone must own.

### 7.12 Non-covered-unit reveal (lines 92, 94, 112–114)

`--no-fine-tree` whole-file units and raw-mirror units — the two cases
bound by `unit_commit` rather than by `fine_root` (line 94). Keys 0–2 are
**deliberately key-aligned with §7.11** so both reveal kinds share one
decode prefix: same key numbers, same types, same [P] checks, one
implementation. The divergence starts at key 3, where §7.11 needs a
cover and this needs the salt that opens the commitment.

| key | field | type | presence | len/shape | status |
| --- | --- | --- | --- | --- | --- |
| 0 | `unit_id` | uint | req | resolves into the manifest unit table **[R]** | proposed |
| 1 | `k_u` | bstr | req | 32 **[P]** | proposed |
| 2 | `ciphertext` | bstr | req | var; same §2 shape check **[P]** | proposed |
| 3 | `unit_salt` | bstr | req | 16 **[P]** — opens `unit_commit = SHA-256(0x02 ‖ unit_salt ‖ bytes)` (line 94) | proposed |
| 4–23 | — | — | — | reserved | proposed |

A raw-mirror reveal is an ordinary entry here — no mirror flag, no link
field: the manifest's `kind` already identifies it (line 98), and by D23
it is its file's last unit, so it sorts after that file's other
non-covered entries. Whether a unit legitimately belongs in *this* array
rather than §7.11 is **[R]** (it depends on the file's
`fine_tree_present` and the unit's `kind`).

### 7.13 Touched-file entry (lines 112–114) — explicit `file_id`: YES (§10)

| key | field | type | presence | len/shape | status |
| --- | --- | --- | --- | --- | --- |
| 0 | `file_id` | uint | req | index into the embedded manifest's file table; in-range **[R]** | proposed |
| 1 | `path` | tstr | req | the sealed path. UTF-8 by type (native F3 check); **the tstr's bytes as received are the commitment pre-image** — `path_commit = SHA-256(0x05 ‖ path_salt ‖ path_utf8)` (line 95). No NFC, no separator rewriting, no case folding is applied to a path: the text canonicalization pipeline (D20/D21) governs *file content*, never this field | proposed |
| 2 | `path_salt` | bstr | req | 16 **[P]** | proposed |
| 3–23 | — | — | — | reserved | proposed |

Path disclosure is per **touched** file, and `path_salt` is the
*path-only* salt — independent of `file_salt` precisely so that naming a
file never weakens its content commitments (line 95). The two must never
be merged into one salt field in a future version.

### 7.14 Fully-revealed-file entry (lines 112–114, 121) — D28 strict

| key | field | type | presence | len/shape | status |
| --- | --- | --- | --- | --- | --- |
| 0 | `file_id` | uint | req | in-range **[R]**; must also appear in `touched_files` **[X]** (§7.6) | proposed |
| 1 | `file_salt` | bstr | req | 16 **[P]** — opens `raw_commit`/`canon_commit`; disclosed **only** on a full reveal (line 95) | proposed |
| 2 | `s_root` | bstr | **opt — biconditional, [R]: present iff `full(F) ∧ fine_tree = Present`** | 32 — the full `[0, n)` cover (line 114); a `--no-fine-tree` or empty file has no fine tree, hence no `s_root` | proposed |
| 3–23 | — | — | — | reserved | proposed |

#### The entry's own presence is derived, never declared (D28)

**D28 (resolved 2026-07-28) made full-reveal strictness hard-fail**, and
the presence rule of this whole *section* is therefore a **biconditional
over a derived predicate**, not an option the sealer exercises:

```text
N(F)     = { unit_id : unit ∈ manifest.units, unit.file_id = F, kind = Normal }
R(F)     = N(F) ∩ bundle.revealed
full(F) ⟺ N(F) ≠ ∅ ∧ R(F) = N(F)

a §7.14 entry for F exists  ⟺  full(F)
its key 2 is present        ⟺  full(F) ∧ F.fine_tree = Present
```

Both directions are errors, and both are **[R]** — every input is either
signed manifest data or bundle field presence, but the predicate needs
*both* sides:

| violation | error (D28's frozen order) |
| --- | --- |
| entry present, `¬full(F)` | `partial-reveal-salt-leak-file-salt` |
| key 2 present, `¬full(F)` | `partial-reveal-salt-leak-s-root` |
| `full(F)`, no entry | `full-reveal-material-missing-file-salt` |
| `full(F) ∧ fine_tree = Present`, key 2 absent | `full-reveal-material-missing-s-root` |
| `full(F) ∧ fine_tree = Absent`, key 2 present | `full-reveal-s-root-without-fine-tree` — **D74 RESOLVED 2026-07-28 with F8: reject** (`docs/decisions/D74-extraneous-full-reveal-s-root.md`). A single code: the `FileSalt` counterpart would be unreachable, because key 1 is `req` at schema level and F8 rejects a key-1-less entry as `bundle-missing-key` before R4 runs |

Two shape consequences worth stating, because they are easy to get
subtly wrong:

1. **"Missing `file_salt`" is realized as a missing *entry*, not as an
   entry with a missing key.** Key 1 is `req` at schema level, so F8
   rejects an entry without it as a schema error long before R4 runs.
   D28's rule 3 therefore fires on section absence. Key 2 is genuinely
   optional at schema level, so its arm *is* an entry-with-key-absent.
2. **`kind = Normal` only, and `N(F) ≠ ∅`.** A file is fully revealed
   when its canonical-domain units are all revealed whether or not its
   raw mirror is (mirrors are exempt by `kind`, never by position —
   D23). The non-emptiness clause exists so a hand-built zero-unit file
   is not *vacuously* full for every bundle, including one revealing
   nothing (D77).

#### There is no reveal-shape field, and there must never be one

The bundle carries **no** `is_full_reveal` / `reveal_mode` /
`reveal_shape` discriminant, at any level. This is a **binding
constraint from D28 rider 1**, not an omission: shape is computed from
the signed unit table and the revealed set, so a declared shape would be
a second, *sealer-forgeable* source of truth — and a bundle declaring
"partial" while revealing every unit would reintroduce exactly the
permissive option D28 rejected, through the wire format instead of
through the verifier. A future editor who notices that the verifier
"already knows" the shape and thinks it cheap to record it on the wire
is re-opening a closed decision. Do not add the field (§7.6.1).

The presence of a §7.14 entry is therefore **material, not a claim**: it
does not assert that the file is fully revealed, it supplies openings
whose presence must *agree* with the independently derived predicate.

#### Why both salts live here rather than in §7.13

Touching a file (naming it) and fully revealing it are separate
disclosures with separate salts — `path_salt` opens only `path_commit`,
`file_salt` only the content commitments (line 95). Keeping them in
separate sections means a builder cannot leak one while intending the
other, and it is why partial-reveal isolation is expressible as "this
file has no §7.14 entry" rather than as a per-field rule.

### 7.15 Bundle-side code composition — the F8 seam

What the bundle half must register to match the manifest half already
shipped in `crates/antseal-core/src/manifest/registry.rs`. This is the
1:1 code ⟷ registry contract of §14, spelled out so F8 does not have to
reverse-engineer it from F5.

**Map identities.** F8 registers nine more maps. Their registry names —
the strings a `MapId::registry_name()` must return, identical to
`maps[].name` in the JSON mirror, which is how the 1:1 test pairs code to
table — are:

| §  | registry name | §  | registry name |
| --- | --- | --- | --- |
| 7.6 | `bundle` | 7.11 | `covered_reveal` |
| 7.7 | `storage_record` | 7.12 | `noncovered_reveal` |
| 7.8 | `ots_anchor` | 7.13 | `touched_file` |
| 7.9 | `tsa_anchor` | 7.14 | `full_reveal` |
| 7.10 | `receipt_record` | | |

**Reserved bands abut and fill.** Every bundle map's band runs from
`last_assigned + 1` to `23` — the shape F5's `key_spaces_are_well_formed`
already asserts for the manifest maps. Concretely: `bundle` → `10..=23`,
`storage_record` → `3..=23`, `ots_anchor` → `5..=23`, `tsa_anchor` →
`5..=23`, `receipt_record` → `3..=23`, `covered_reveal` → `5..=23`,
`noncovered_reveal` → `4..=23`, `touched_file` → `3..=23`, `full_reveal`
→ `3..=23`. Unlike the manifest envelope, **no bundle map is
shape-frozen**: all nine reserve.

**A named reserved slot is documentation, not a new error class.** Bundle
key 10 (`range_reveals`) and receipt key 3 (`chain_inputs`) classify as
plain `Reserved` and raise F10's one reserved-slot error with the key
number in the message. Giving a named slot its own error variant would
mean v1.1 changes an error code when it assigns the key — exactly what
D30's stable-code contract forbids. The name exists so a human reading
the rejection knows what the sender was trying to send.

**Exact lengths: two layers, different jobs.** R already registers
`verify::error::LengthField` for the six disclosed fixed-length classes
of line 121 (`unit_salt`, `path_salt`, `file_salt`, `s_root`, GGM
covering seed, boundary node hash). F8's parse-time checks and R's
`check_disclosed_lengths` overlap on purpose:

- F8's is the **wire gate** — a bundle that came through F8's decoder can
  never reach R with a wrong-length salt, so R's group idles on that
  path;
- R's is the **view gate** — `BundleView` is populated by R5 and by
  fixtures, not only by F8, so the invariant must not rest on the
  decoder alone. Do not delete it as dead code.
- `k_u` (32) and `k_m` (32) are **F8-only**: line 121's list is
  "every disclosed salt/seed/node hash", and keys are neither. There is
  no `LengthField` class for them and none should be added — R binds keys
  by whether they *decrypt*, not by their length.

**What F8 must not do.** Consult the embedded manifest during bundle
schema validation (§0); re-home or renumber any of the five manifest-side
`MapId` variants; or introduce a second `sig_alg`/`SigAlgMap` surface —
the bundle carries no signature material at all (§7.6.1).

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
| `covered_reveals`, `noncovered_reveals` | strictly ascending `unit_id` | yes — **[X]**, each array independently; cross-array disjointness too (§7.6) |
| `touched_files`, `full_reveals` | strictly ascending `file_id` | yes — **[X]** |
| `cover`, `paths` | strictly ascending leaf-interval start `index · 2^(d−level)` (§5) | yes — **[X]**, and **`d` is not needed to decide it**: rescaling every start by the same positive factor preserves strict order, so comparing `index · 2^(D−level)` for any common `D ≥ max(level)` in the list gives the identical verdict. Compute it in `u128` (`index < 2^level` bounds the product by `2^D ≤ 2^64`, which is *not* a `u64`). The manifest-derived `d` enters only at R's leaf-exactness check |
| `ots_anchors`, `tsa_anchors` | capture order recorded in the seal journal (stable across rebuilds); wire order preserved as-is | no (builder rule; proposed — §13 item 5) |
| `intermediates` | as supplied by the TSA (chain order, leaf-adjacent first) | no (A's semantic domain) |
| `tx_hashes` | capture order | no |

**Why the anchor arrays are the one unsorted bundle list.** Every other
list has a content-independent sort key (an id, an interval start). An
anchor artifact has none: sorting by `status` would reorder on
re-verification, by `fetch_date` would collide, and by artifact bytes
would be meaningless. So their order is a *builder* rule backed by the
seal journal rather than a parse rule — which is why "the same logical
bundle always produces identical bytes" (F9 accept) holds **per builder
state**, not per logical content. A bundle rebuilt from a journal is
byte-identical; a bundle rebuilt from a different anchor capture order is
not, and neither is wrong. Recorded so F9's determinism test fixes the
anchor order in its fixtures rather than asserting a sort.

D23 rider: because a file's raw mirror is its last unit, ascending
`unit_id` in `noncovered_reveals` also puts each file's mirror after that
file's other non-covered reveals — an ordering property that comes free
and must not be separately enforced (it would double-report the same
violation).

## 9. Reserved key space — summary

- Every map's assigned keys and named-reserved keys live in `0..=23`;
  the per-map remainder of `0..=23` is range-reserved for v1.x additions.
  Reserved-key presence in v1 input → F10's distinct reserved-slot error
  naming the key. Keys `>= 24` → plain unknown-key error. (§1 rule 4.)
- **Named reserved slots in v1** — one per committed v1.1 item, so each
  can ship as an additive v1.x field rather than a format-version event:

  | slot | reserved for | owner of the eventual shape |
  | --- | --- | --- |
  | bundle key **10** `range_reveals` (§7.6) | v1.1 arbitrary sub-unit byte-range reveal tooling — the covers + boundary paths of a `reveal --range` selection (lines 114/161) | G/R (the proof format itself already ships in MVP via G12/G13; only *selection* + rendering are deferred) |
  | receipt key **3** `chain_inputs` (§7.10) | v1.1 Arbitrum-receipt verification chain (line 161) — registry-visible structure promoted out of the opaque `payload` | A/S |
  | `sig_alg` values **2–15** (§6.2) | future signature algorithms | C |

  Reserving is *not* designing: none of the three shapes is specified
  here, and specifying one is a later decision, not an editorial pass.

- All three reject-if-present in v1 with F10's reserved-slot error — the
  same error a *nameless* reserved key raises (§7.15), so assigning a
  named slot in v1.1 never changes an existing error code (D30).
- The manifest envelope (§7.1) has **no** reserved space — shape frozen
  forever (§1 rule 6). Every other map, manifest- and bundle-side,
  reserves the remainder of its band (§7.15).
- **Arrays have no reserved space.** `byte_range` (2 elements),
  `cover_entry` and `path_node` (3 each) are positional, so a future
  element cannot be "reserved" — extending one is a version bump. This is
  why per-entry extensibility lives in the enclosing *map*, not in the
  tuples.
- A reserved key is *assigned* only by a recorded format decision; v1.x
  assignments must be additive (new optional field) — anything else is a
  version bump (line 123).

### Version dispatch order (F10) — status: proposed

Two independent discriminants, read at two different depths:

| artifact | discriminant | read after | unsupported ⇒ |
| --- | --- | --- | --- |
| `.sealproof` bundle | §7.6 key 0 | nothing — first key of the file | `bundle-unsupported-format-version` |
| manifest body | §7.2 key 0 | the §7.1 envelope decode | `manifest-unsupported-format-version` |

Frozen facts:

1. **The discriminant is key 0 in both maps.** Canonical maps ascend
   (§1 rule 3), so key 0 is first on the wire whenever present, and reading
   the version is a constant-cost peek regardless of artifact size. A
   hostile oversized artifact declaring an unknown version is rejected
   before any section is walked — earlier than F11's caps apply.
2. **The two discriminants are independent.** A v1 bundle may one day carry
   a v2 manifest; the two rejections are separate codes in separate families
   (D78) and must stay separable.
3. **The §7.1 envelope shape is frozen across all versions**, because it is
   what you must parse in order to find the manifest's version (§7.1).
4. **Unsupported ≠ malformed.** An artifact declaring a version with no
   decoder yields the version error and *nothing else* — never a
   canonicality error, never an unknown/reserved-key error, even when the
   rest of the artifact would also fail v1 validation. Conversely a
   *missing* discriminant is `*-missing-key` and a non-canonical one is the
   `cbor-*` class: "too new" and "corrupt" are different claims about the
   sender and never merge.
5. **A released version is decodable forever** (line 123). Support is added
   by appending a row to the dispatch table, never by widening an older
   version's decoder. Code side: `antseal_core::format`
   (`SUPPORTED_VERSIONS`, `VersionDispatch`, the `V1` admission witness).

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

## 11. Parser resource caps (D10 — frozen)

Frozen by decision D10 (`docs/decisions/D10-parser-caps.md`, 2026-07-28);
implemented in `antseal_core::codec::caps`; a test asserts code == this
table. All values are `u64` except depth (`u16`). Sizing rationale per
row is in the decision record.

| constant | value | applies to | error code |
| --- | --- | --- | --- |
| `MAX_BUNDLE_BYTES` | 268435456 | layer-1 `.sealproof` input | `bundle-too-large` |
| `MAX_MANIFEST_BYTES` | 16777216 | layer-2 input (§7.6 key 1 contents) | `manifest-too-large` |
| `MAX_CBOR_DEPTH` | 8 | enclosing containers, generic walker (§7.6.3: v1 max is 6) | `cbor-nesting-too-deep` |
| `MAX_FILE_COUNT` | 16384 | §7.2 key 7 `files` | `manifest-too-many-files` |
| `MAX_UNIT_COUNT` | 65536 | §7.3 key 6 `units`, **work-global running budget** | `manifest-too-many-units` |
| `MAX_OTS_ANCHOR_COUNT` | 256 | §7.6 key 3 | `bundle-too-many-ots-anchors` |
| `MAX_TSA_ANCHOR_COUNT` | 256 | §7.6 key 4 | `bundle-too-many-tsa-anchors` |
| `MAX_INTERMEDIATE_COUNT` | 16 | §7.9 key 2 | `bundle-too-many-intermediates` |
| `MAX_TX_HASH_COUNT` | 256 | §7.10 key 0 | `bundle-too-many-tx-hashes` |
| `MAX_COVERED_REVEAL_COUNT` | 65536 | §7.6 key 6 | `bundle-too-many-covered-reveals` |
| `MAX_NONCOVERED_REVEAL_COUNT` | 65536 | §7.6 key 7 | `bundle-too-many-noncovered-reveals` |
| `MAX_COVER_ENTRIES` | 256 | §7.11 key 3 (2·⌈log₂ n⌉ ≤ 128 for any `uint` size) | `bundle-too-many-cover-entries` |
| `MAX_PATH_NODES` | 256 | §7.11 key 4 | `bundle-too-many-path-nodes` |
| `MAX_TOUCHED_FILE_COUNT` | 16384 | §7.6 key 8 | `bundle-too-many-touched-files` |
| `MAX_FULL_REVEAL_COUNT` | 16384 | §7.6 key 9 | `bundle-too-many-full-reveals` |
| `MAX_OTS_BYTES` | 1048576 | §7.8 key 1 | `bundle-ots-too-large` |
| `MAX_TSA_TOKEN_BYTES` | 1048576 | §7.9 key 1 | `bundle-tsa-token-too-large` |
| `MAX_CERT_BYTES` | 65536 | §7.9 key 2 elements | `bundle-cert-too-large` |
| `MAX_RECEIPT_PAYLOAD_BYTES` | 16777216 | §7.10 key 2 | `bundle-receipt-payload-too-large` |

**Clamp rule (normative).** Every pre-allocation in the decode path is
clamped to `min(claimed_length, remaining_input)`, including lists with no
cap (`sig_policy`, `pubkeys`, `signatures` — bounded instead by the
16-value `sig_alg` universe of §6.2). Order at every array head: head
canonicality → cap → clamped allocation → elements. `bstr`/`tstr`
payloads are already bounds-checked before consumption (F3) and read
zero-copy, so no string length can drive an allocation.

**Recorded non-caps**: `sig_policy`/`pubkeys`/`signatures` (bounded by the
registered-alg universe and by duplicate-freedom); `range`/`cover_entry`/
`path_node` (fixed arity, §4/§5); `title`/`app_version`/`path`/`source`
(free-form `tstr`s, transitively bounded); revealed-unit `ciphertext`
(shape-checked; an upper bound would equal `MAX_BUNDLE_BYTES`).

**Not F11's**: internal structural limits of the opaque artifacts (`.ots`
op counts, DER nesting, signed-attribute counts) are A's at M2 (§7.8,
§7.9; MVP-SPEC.md line 153) — their freeze status is **D83**.

## 12. Spec-coverage checklist

Every field named in MVP-SPEC.md lines 74–75, 98, and 112–114, mapped to
its registry row (F4 accept criterion), plus the bundle-slice additions
drawn from lines 91, 110, 121 and 161. "—" = deliberately not a wire
field, with the reason. Rows whose registry cell begins "— checked
absence" are the ones F8 must *test* the absence of, not merely omit
(§7.6.1).

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
| 161 | (v1.1) Arbitrum-receipt verification chain | §7.10 key 3 — reserved, reject-in-v1 |
| 114 | "Nonces come from the manifest (single source of truth)" | — checked absence: §7.11/§7.12 deliberately have **no** nonce key (§7.6.1) |
| 112 | anchor *kind* (OTS vs TSA) | — positional, not a field: §7.6 key 3 vs key 4 (§7.6.2). Satisfies the "anchor type" item of the F8 task field list |
| 91 | per-unit AAD `seal_id ‖ LE64(unit_id)` | — reconstructed from the manifest `seal_id` + the reveal's `unit_id`; never carried (§7.11) |
| 121 | exact length of every disclosed salt / seed / node hash | §7.11 key 3 (seed 32) · §7.12 key 3 (16) · §7.13 key 2 (16) · §7.14 keys 1–2 (16, 32) · §5 `path_node` element 2 (32) — all **[P]** |
| 112 | bundle authority comes from the embedded *signed* manifest | — checked absence: the bundle has no signature container of its own (§7.6.1) |
| 75 | `work_id` / `anchor_digest` at bundle level | — checked absence: both derived from §7.6 key 1's bytes; storing either would create a second authority (§7.6.1) |
| 110 | receipt is opt-in | §7.6 key 5 — the *only* optional top-level key; absence carries no meaning |
| 121 | full-reveal material (`file_salt`, `s_root`) mandatory when a file is fully revealed | §7.14 — biconditional over the **derived** predicate (D28); entry absence *is* the missing-`file_salt` case |
| 121 | reveal shape (partial vs full) | — checked absence: **no** shape discriminant anywhere in the bundle; derived from the signed unit table + revealed set (D28 rider 1; §7.6.1, §7.14) |

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
6. ~~**Raw-mirror position within a file's `units` array**~~ —
   **CLOSED by D23** (2026-07-27): the mirror is its file's last unit;
   parse still accepts any position and R exempts mirrors by `kind`, not
   by position (§7.5).
7. ~~**`unit_id` stored-and-checked**~~ — **settled in code by F5**
   (2026-07-28): key 0 is stored *and* parse-checked equal to the derived
   manifest-order ordinal (`manifest/body.rs`). Recorded here as a D8
   ratification item only; changing it now would move consumed keys.

Added by the bundle-slice pass (2026-07-28) — each is format-permanent
and **none is decided here**:

8. **May bundle schema validation open the embedded manifest?** (§0.)
   Proposed **no**: F8 decides the bundle from the bundle's own bytes,
   and any rule needing both sides is [R]. This is not merely a layering
   preference — it fixes *which error family* each rejection lands in,
   and D30 makes error codes permanent. Under "no", an `s_root` present
   for a tree-less file (§7.14) is a **verify** failure; under "yes" it is
   a **schema** failure, and the two render differently to users. Decide
   once, before F8 writes its error enum. Owner: D8 with F8/F9/R.
9. **Is the OTS upgrade group (§7.8 keys 2–4) tied to `status ==
   attested`, or free-standing?** The registry's rule that keys 2–4 are
   all-or-nothing is not in question; the coupling is. Tying presence to
   `status` makes the artifact self-consistent and gives a crisp early
   rejection — but it is the only place where a **parse** rule depends on
   a field the design says the verifier must **never trust** (§6.1), so a
   sealer's lie about `status` becomes a parse outcome. Free-standing
   presence keeps parse ignorant of semantics and leaves the whole
   judgement to A/R, at the cost of admitting artifacts like
   `status = pending` + header. Owner: D8 with A. Format-permanent either
   way, and cheap to get wrong quietly.
10. **Must a revealed unit's owning file have a `touched_files` entry?**
    I.e. may a bundle disclose bytes while withholding *which file* they
    came from? Line 114 says paths ship "per **touched** file" without
    defining touched; line 121's anti-out-of-context guardrail argues the
    recipient should always know what they are looking at, while path
    privacy argues the opposite. If mandatory it is an **[X]** rule F8
    enforces (both lists are in the bundle); if optional it is nothing at
    all. `full_reveals ⊆ touched_files` is already settled as mandatory
    (§7.6) — this is the weaker per-unit case. Owner: D8 with R (and U for
    the `reveal` surface).

Open co-freezes tracked elsewhere: D17 (§6.2, with C14). The F11 caps
(§11) are frozen by D10 and no longer open.
**D9 closed 2026-07-28** (§5) — no longer a co-freeze, only a co-freeze
*date* (Q14, with everything else here).

Registered decisions the bundle slice **feeds and must not resolve** —
each is already an entry in the TODO decision register, so it is *not*
re-raised as a D8 item here:

| decision | where it bites in this registry | this slice's contribution |
| --- | --- | --- |
| **D74** — extraneous `s_root` on a fine-tree-absent full reveal | §7.14 key 2, the fifth violation row | the row is left **unassigned**, and the permissive reading is explicitly not encoded |
| **D75** — does a full reveal ship covers *and* `s_root`? | §7.11 key 3 presence | shown to be **key-neutral** (only the presence rule and its tier move); the draft leans "both", with reasons, as D75 input |
| **D77** — zero-non-mirror-unit file | §7.14's `N(F) ≠ ∅` clause | recorded as the reason the clause exists; no registry change either way |

## 14. Machine-readable mirror and tests

[`registry-v1.json`](registry-v1.json) mirrors this document 1:1 — every
map, key number, type, presence rule, fixed length, enum value, tuple
shape, and reserved range, with per-item `status` markers. The
draft-stage test `crates/antseal-core/tests/format_registry_draft.rs`
asserts: the JSON parses; every key/value/index is an unsigned integer;
no duplicate key numbers within any single map (nor values within an
enum); reserved ranges are well-formed, mutually disjoint, and collide
with no assigned key; every assigned key and reserved bound sits in the
`0..=23` band; and every item carries a **registered** status marker.

The registered vocabulary stays `proposed` / `pending-D9` /
`pending-D17` even though **no item carries `pending-D9` any more** (D9
resolved 2026-07-28). Keeping the retired marker registered is
deliberate: an item that reacquires it fails no test today, but the
marker cannot be *silently reintroduced* under a different spelling
either — and dropping it from the allow-list would only mean a future
re-open has to edit the test as well as the registry. Both readings are
defensible; the cheap one is kept.

The bundle slice adds three non-`maps` sections the walker does not
status-check, because they record rules rather than assignments:
`decode_layers`, `checked_absences`, and `validation_tiers`. They are
mirrors of §7.6.3, §7.6.1, and §0 respectively and exist so F8 can
consume them without parsing prose.

The 1:1 code-constants ⟷ registry assertion lands with F5/F8 (§7.15
lists what the bundle half must register), and the F11 cap constants join
the mirror when frozen.
