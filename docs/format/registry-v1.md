# antseal wire-format registry — v1 (F4)

> **FROZEN — v1. This document is normative.** It froze at the Q14
> `format-v1-freeze` gate (M0 Definitions sign-off) and is signed off by
> **D8** (`docs/decisions/D8-wire-registry-final.md`). Every key
> assignment, type, presence rule, byte length, enum value, tuple shape and
> reserved range below is **format-permanent**: changing one is a
> format-version event, not an edit (MVP-SPEC.md line 123; the procedure is
> Q27's).
>
> Two directions, not one. A later release may **relax** a v1 rule (a
> bundle that used to be rejected starts being accepted) but may never
> **tighten** one (a bundle that used to be accepted starts being
> rejected) — line 123 promises every released format version stays
> verifiable forever. Additive v1.x fields come from the reserved bands of
> §9 and from nowhere else.
>
> The freeze covers the machine mirror too: `registry-v1.json` carries
> `"status": "frozen-v1"` on the document and on every item, and the three
> pre-freeze markers (`proposed`, `pending-D9`, `pending-D17`) are illegal
> anywhere in it. `crates/antseal-core/tests/format_registry_freeze.rs`
> asserts that, the code ⟷ mirror correspondence, and this document
> ⟷ mirror correspondence (§14). The bytes of both files are pinned by
> `docs/format/FROZEN.sha256` (Q50).
>
> Decisions this document records rather than proposes: **D8** (the
> registry as a whole), **D9** (`(level, index)` node addressing, §5),
> **D10** (parser caps, §11), **D17** (`sig_alg` values, §6.2), **D28**,
> **D74**, **D75**, **D76**, **D77**, **D78**, **D79**, **D80**, **D82**,
> **D83**. §13 is the closed record.

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
- Registered decisions this document records as **settled law**, all
  resolved 2026-07-28: **D74** — extraneous `s_root` on a fine-tree-absent
  full reveal: **reject**, code `full-reveal-s-root-without-fine-tree`
  (§7.14; `docs/decisions/D74-extraneous-full-reveal-s-root.md`);
  **D75** — a full reveal ships covers *and* `s_root`: **both**, key 3
  unconditionally `req` at tier [P] (§7.11;
  `docs/decisions/D75-full-reveal-cover-shape.md`); **D76** — splitting
  `file_salt`: **NO for v1**, one salt for both content commitments (§7.14
  key 1; `docs/decisions/D76-file-salt-split.md`); **D77** — a
  zero-non-mirror-unit (mirror-only) file: **reject at F5**, code
  `manifest-empty-normal-units` (§7.3 key 6;
  `docs/decisions/D77-zero-unit-file.md`); **D80** — a revealed unit's
  owning file must appear in `touched_files`: **required, tier [R]**, code
  `revealed-unit-file-not-touched` (§7.6;
  `docs/decisions/D80-revealed-unit-touched-file.md`); **D82** — the
  converse: a `touched_files` entry whose file has no revealed unit:
  **reject**, tier [R], code `touched-file-without-revealed-unit` (§7.6;
  `docs/decisions/D82-touched-file-without-reveal.md`).
- Ratified 2026-07-28 and binding on F8: **D78** (bundle schema validation
  never opens the embedded manifest — §0, §7.6.3), **D79** (the OTS upgrade
  group is free-standing all-or-nothing, never keyed on `status` — §7.8).
- Already-consumed rows: the manifest-side maps §§7.1–7.5 are **implemented**
  (F5/F6 — `crates/antseal-core/src/manifest/`, key constants in
  `manifest/registry.rs`). Their key numbers are consumed; the bundle slice
  composes with them and does not move them.
- Machine mirror: [`registry-v1.json`](registry-v1.json) (§14). Freeze gate
  test: `crates/antseal-core/tests/format_registry_freeze.rs`. Byte pin:
  `docs/format/FROZEN.sha256`.

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

There is deliberately **no status column**. Every v1 row carries the same
state — `frozen-v1` — so a column with one value in every cell would be
noise and a copy-paste hazard across 84 cells. The document-level state is
the FROZEN banner above; the per-item `frozen-v1` markers live in the JSON
mirror, which is where the freeze test reads them and where a future v1.x
addition can be told apart from a frozen v1 item (§12, §14). The pre-freeze
markers `proposed`, `pending-D9` and `pending-D17` are illegal for v1 items
and must not appear anywhere in either file.

### Validation tiers

Recorded so rows do not over-claim, and so F8 and R cannot both assume the
other checks a rule. F3 enforces CBOR canonicality beneath all three.

| tier | who | decidable from | examples |
| --- | --- | --- | --- |
| **[P]** | F5 (manifest) / F8 (bundle) | the **one entry** being decoded | type, exact byte length, enum membership, non-empty container, `level ≤ 64`, `index < 2^level` |
| **[X]** | F5 / F8, same pass | the **whole container** it is decoding (manifest body, or bundle) | list ordering, `unit_id` = derived ordinal, cross-section id disjointness, descriptor-conditioned presence within one file entry |
| **[R]** | R (verify), post-decode | the **bundle *and* the embedded manifest**, or crypto | `full_reveal.s_root` presence, which reveal array a unit belongs in, tiling, leaf-exact cover, `true_length` = range width, partial-reveal isolation (MVP-SPEC.md line 121) |

**Ratified rule (D78, 2026-07-28): bundle schema validation never
consults the embedded manifest.** F8 decodes the bundle from the bundle's
own bytes; the manifest is layer 2 of F9's pipeline and is not available
to — and must not be reached for by — a bundle-schema presence rule. Any
rule needing both sides is therefore **[R]**, not a schema error. This is
what keeps the two error families separate under D30: a bundle that is
*well-formed but inconsistent with its manifest* must report a verify
code, never a schema code, so "malformed bundle" and "lying sealer" never
render alike.

The 1:1 assertion that **code constants match this table** has landed:
`tests/format_registry_freeze.rs` drives map keys, reserved bands, closed
enums, `sig_alg` (both code copies), fixed scalar lengths, tuple arities,
version dispatch, error→map attribution, all nineteen D10 caps, and the
field **names** against the mirror, in both directions — and parses this
document's own mechanical tables against it. §14 names the whole assertion
set; §7.15 lists what the bundle half registers.

## 1. v1 type profile

The encoding is RFC 8949 §4.2.1 Core Deterministic Encoding as restricted
by MVP-SPEC.md line 73, produced and enforced via the pinned
`minicbor = "=2.3.0"` (D7) under F2/F3. On top of that profile, **v1
restricts the type surface to five major types**:

| allowed | CBOR major | use |
| --- | --- | --- |
| `uint` | 0 | ids, sizes, versions, enum values, times, tuple coordinates, **all map keys** |
| `bstr` | 2 | commitments, salts, seeds, keys, nonces, addresses, ciphertexts, opaque anchor artifacts, embedded manifest/body bytes |
| `tstr` | 3 | title, app version, paths, Unicode-version string |
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
   unknown-key error. (Two error bands; F10 mechanics.) The band size is
   itself load-bearing — see §9's headroom table and the ruling that an
   **exhausted band is a format-version event, never a key ≥ 24**.
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
| 1952 | ML-DSA-65 public key (FIPS 204 Table 2) | line 97 |
| 3309 | ML-DSA-65 signature (FIPS 204 Table 2) | line 97 |

**Canonical leaf-level GGM payload (D83).** The 32-byte length above is
unconditional, but at the grid's leaf level only half of it is read. A
disclosed GGM value for a node at **`level == d`** (`d = ⌈log₂ n⌉`) is
`salt_i ‖ 0x00·16`: the verifier takes `salt_i = payload[..16]` with no
descent (MVP-SPEC.md line 96), so bytes `16..32` are significant only as a
canonicality rule. **A non-zero upper half is a rejection**
(`fine-root-leaf-seed-tail-not-zero`), tier **[R]** — it needs `n` from the
embedded manifest. This binds `cover_entry` (§5, §7.11 key 3) at
`level == d` and `full_reveal.s_root` (§7.14 key 2) at `n == 1`, the one
case where the grid root is itself a leaf.

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

## 3. Integer time encoding

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

## 4. Byte-range representation

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

## 5. GGM sub-cover / boundary-path node addressing (D9 — `(level, index)`)

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

### Canonical leaf-level payload (D83 — option B)

A cover node at `level == d` covers exactly one leaf slot, so a verifier
descends `d − level = 0` levels and reads `salt_i = payload[..16]`
directly (MVP-SPEC.md line 96). Bytes `16..32` are therefore never an input
to any hash. v1 fixes them at **zero** and requires the verifier to check
them, so that one proof has exactly one encoding.

Incidence, for sizing and for test design: a cover for `[a, b)` contains a
`level == d` node **iff `d == 0 ∨ a odd ∨ (b odd ∧ b < n)`** — about ¾ of
all ranges. A whole-file cover `[0, n)` is always the single root node and
so carries one only at `n == 1`; under D75 a *split* file's full reveal
ships one cover per unit and is governed by unit-boundary parity, not by
file size. At most **2** such nodes occur in any one cover.

The same rule governs `full_reveal.s_root` (§7.14 key 2) at `n == 1`,
where `d == 0` makes the grid root a leaf and MVP-SPEC.md line 96 states
`salt_0 = s_root[..16]` outright. At that size the two fields are
byte-identical by rule, which is how D75's "the two routes must agree"
rider is discharged.

Rejected alternatives are recorded in
`docs/decisions/D83-leaf-cover-seed-tail-malleability.md`: a 16-byte
payload at `level == d` would contradict MVP-SPEC.md lines 96/121 and drop
two exact byte lengths from tier [P] to [R] for a ≤ 0.95 % wire saving.

### Tuple shapes (D9-decided)

- **`cover_entry` = `[level, index, seed]`** — `uint, uint, bstr(32)`.
  One disclosed GGM seed of the leaf-exact sub-cover. At `level == d` the
  third element is **not** the raw seed but the canonical leaf-level
  payload `salt_i ‖ 0x00·16` (D83); at `level < d` it is the seed itself.
  The length is 32 either way and stays a **[P]** check.
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

### 6.1 `anchor_status`

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

Values 7–15 reserved (unregistered — reject in v1).

**The non-consumption rule (D8 §4a — format-permanent).** `anchor_status`
(§7.8 key 0, §7.9 key 0) is the sealer's **capture-time record**. Its wire
domain is the seven registered values `0..=6`; `7..=15` are reserved and
rejected. Within `0..=6` **every value is legal on every artifact of either
kind**, including `absent`, which is representable and meaningless rather
than illegal. **There is no per-kind legal-value subset, in v1 or ever.**
**No v1 parse rule and no v1 verdict may read this field.** A verifier
derives its own per-anchor state (sealer-as-adversary, line 121) and MAY
display the recorded value only as a *sealer-asserted claim*, with the
discipline MVP-SPEC.md line 137 already prescribes for `claimed_time` —
"asserted by sealer — NOT verified", never entering the headline.

Why no subset, stated so it is not re-opened:

1. **It is D79's rule one level down.** D79 fixed that the OTS upgrade
   group's *presence* may not be conditioned on `status`, because `status`
   is sealer-written and the design requires a verifier not to trust it;
   conditioning parse on it would let a sealer choose which shapes decode.
   A per-kind legal-value subset is the same construction applied to the
   field itself — it makes *decodability* depend on a value whose whole
   design property is that nothing depends on it.
2. **It would file a sealer's lie in the wrong error family.** A sealer
   writing `proven` on a pending OTS is lying, not malforming; under a
   subset rule that lie becomes a **schema** rejection, and D30 makes the
   family permanent (`docs/testing/error-code-contract.md` §2, D78).
3. **The evidence to choose a subset does not exist.** Which states a
   sealer can legitimately observe at capture time is A-domain semantics,
   decided at M2 against A25's real artifacts; a subset frozen now against
   zero artifacts could only be *relaxed* later, which would make
   M2-produced bundles fail in M0/M1-era verifiers — the illegal direction
   under line 123.

### 6.2 `sig_alg` (D17)

Registered `sig_policy` algorithm IDs. **D17 is closed here** — the values
were ratified in code at M0 wave 3 (C14/F5) and freeze with this document:

| value | algorithm | pubkey | signature | notes |
| --- | --- | --- | --- | --- |
| 0 | `ed25519` | 32 B | 64 B | RFC 8032, strict/canonical verification (line 97). The always-present baseline: the reserved fallback policy is `[0]`. |
| 1 | `ml-dsa-65` | 1952 B | 3309 B | FIPS 204, `ctx = "antseal-manifest-v1"`, canonical-encoding rejection (line 97). |
| 2–15 | — | — | — | Reserved for future algorithms (e.g. a wider ML-DSA set, SLH-DSA). Unregistered in v1: any appearance — in `sig_policy`, `pubkeys`, or `signatures` — is a parse-time reject (C14 `SigPolicyUnknownAlg` / F5 unknown-key). |

Rationale: 0/1 encode in one byte; `ed25519` takes 0 as the algorithm
every v1 manifest must be able to carry alone (the ML-DSA WASM-probe
fallback ships `sig_policy = [0]` with the format unchanged, line 97).
The 1952/3309 lengths are FIPS 204 Table 2, verified against the pinned
crate's own source (`docs/research/C11-signature-probe.md:46`) rather than
from memory, pinned in code at `crypto/sig_mldsa.rs`, and asserted by
§2's scalar rows.

**The 16-value universe freezes twice over — D10 depends on it.** §11's
recorded non-caps justify the *absence* of caps on
`sig_policy`/`pubkeys`/`signatures` by "bounded instead by the 16-value
`sig_alg` universe of §6.2". So widening the reserved band beyond 15 would
require minting caps for three lists that currently have none: the universe
is fixed by D10 as well as by this section, and neither can move alone.

The mapping is duplicated in code — `crypto::sig_policy` (C's) and
`manifest::registry` (F's, the one the codec uses) — and the duplication is
deliberate: this table is the single **normative** source of the numbers,
and how many `match` arms the crate has is a code-organisation matter the
registry does not own. Re-homing changes no value and is therefore a free
refactor at any time. What the freeze test does own is that **both** copies
are asserted against the mirror directly (§14 assertion C5), not through
each other.

### 6.3 Small closed enums

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

| key | field | type | presence | len/shape |
| --- | --- | --- | --- | --- |
| 0 | `body` | bstr | req | var — embedded canonical-CBOR body (§7.2); `work_id` = SHA-256 of exactly these bytes; verifiers never re-encode (line 74) |
| 1 | `signatures` | map | req | uint keys = `sig_alg` (§6.2) → bstr of that algorithm's exact signature length; non-empty; enumerable; duplicates impossible by map semantics; present-set = policy-set is C14's check |

### 7.2 Manifest body (line 98) — inside the `body` bstr

Version discriminant at key 0 (encoded first; F10 dispatch).

| key | field | type | presence | len/shape |
| --- | --- | --- | --- | --- |
| 0 | `format_version` | uint | req | = 1 in v1 |
| 1 | `app_version` | tstr | req | free-form, informational only (producing build; never verdict-bearing); **may be empty**, and a non-empty check is permanently foreclosed (below) |
| 2 | `seal_id` | bstr | req | 16 |
| 3 | `title` | tstr | req | **may be empty** (no `--title` ⇒ `""` — one shape); never verdict-bearing; a **disclosure to every bundle recipient** (below) |
| 4 | `claimed_time` | uint | req | POSIX seconds UTC (§3); informational only (line 98) |
| 5 | `pubkeys` | map | req | uint keys = `sig_alg` → bstr of that algorithm's exact pubkey length; non-empty; key-set = policy-set is C14's check |
| 6 | `sig_policy` | array | req | uint `sig_alg` elements; **order-preserving** (spec: ordered list); non-empty + duplicate-free + registered-only enforced at parse (line 97, C14) |
| 7 | `files` | array | req | file-table entries (§7.3); non-empty (a work = one or more files, line 83); array index **is** `file_id` (line 76) — no stored per-entry id in the manifest |
| 8–23 | — | — | — | reserved (§1 rule 4) |

**Keys 1 and 3 are `req`, may be empty, and no non-empty check may ever be
added.** Adding one would reject a bundle a released verifier accepted —
the illegal direction under line 123 — so the rule is format-permanent in
the *permissive* sense rather than merely current. `""` is the single
encoding of "no title"; the absent-vs-empty split does not exist because
the profile has no `null` (§1 rule 2), and the alternative shape (`opt`,
non-empty when present) was rejected on three grounds: `app_version` has no
absent state to model (a manifest always has a producing build), the
alternative costs one or two permanent D30 codes to save two bytes, and
`req`-may-be-empty is the rule §7.6 already adopts for the bundle.

**Recorded privacy note.** `title` is user text in a **plaintext** manifest
embedded in **every** bundle, so every bundle recipient reads it whether or
not the file it names is revealed. (The *uploaded* copy is encrypted —
line 98 — so the network never sees it.) The leak is recorded, not
eliminated; U's CLI surface is where a user is told.

### 7.3 File-table entry (line 98)

| key | field | type | presence | len/shape |
| --- | --- | --- | --- | --- |
| 0 | `path_commit` | bstr | req | 32 |
| 1 | `raw_commit` | bstr | req | 32 |
| 2 | `canon_commit` | bstr | opt: `descriptor.kind == text` | 32 |
| 3 | `size` | uint | req | leaf count / tiling-domain byte count: canonical bytes for text, raw bytes for binary (line 98; a text file's raw byte count travels as its raw-mirror unit's `true_length`) |
| 4 | `descriptor` | map | req | §7.4 |
| 5 | `fine_root` | bstr | opt: `descriptor.fine_tree_present == 1` | 32 |
| 6 | `units` | array | req | unit-table entries (§7.5); non-empty (empty file = one empty unit, line 78); **at least one `kind = normal` unit [P]** — a mirror-only file has no tiling domain, so it is rejected at F5 with `manifest-empty-normal-units` (**D77**, `docs/decisions/D77-zero-unit-file.md`) |
| 7–23 | — | — | — | reserved |

### 7.4 Canonicalization descriptor (lines 83, 98; G4 field set)

Per D20/D21 the descriptor carries **no** forced-text flag — `kind`
alone selects the total text-mode transform.

| key | field | type | presence | len/shape |
| --- | --- | --- | --- | --- |
| 0 | `kind` | uint | req | `descriptor_kind` (§6.3) |
| 1 | `fine_tree_present` | uint | req | 0/1 (§1 rule 1); 0 for `--no-fine-tree` files and empty files (G4) |
| 2 | `fine_tree_domain` | uint | opt: `fine_tree_present == 1` | `fine_tree_domain` (§6.3) |
| 3 | `unicode_version` | tstr | opt: `kind == text` | v1 value set = {`"unicode-17.0.0"`} (D25); parse checks shape only — version-known lookup is G's registry at verify time |
| 4–23 | — | — | — | reserved |

Illegal combinations (G4's validation, run inside the decode path):
binary + canonical domain, text without `unicode_version`, version on
binary, present tree without domain.

### 7.5 Unit-table entry (lines 91–92, 98)

| key | field | type | presence | len/shape |
| --- | --- | --- | --- | --- |
| 0 | `unit_id` | uint | req | work-global ordinal in manifest order (line 76). Stored explicitly per the line-98 field list *and* parse-checked equal to the derived manifest-order ordinal (concatenating `units` across `files` in order yields `0..N`) — a mismatch is a distinct decode error, so reveals and `--units` ids are self-describing and silent reordering is unrepresentable |
| 1 | `kind` | uint | req | `unit_kind` (§6.3) |
| 2 | `range` | array | req | `byte_range` tuple (§4), in the unit's byte domain; raw-mirror units span `[0, raw_size)` (line 92) |
| 3 | `true_length` | uint | req | pre-padding byte length; `== range[1]` is R's invariant (line 121; deliberate redundancy, §4) |
| 4 | `unit_commit` | bstr | opt: unit **not** fine-tree-covered, i.e. `kind == raw-mirror` **or** file `fine_tree_present == 0` (line 94: covered units are bound solely by `fine_root`) | 32 |
| 5 | `nonce` | bstr | req | 24 — the single authoritative copy (line 91); reveal entries never carry nonces (§12) |
| 6 | `address` | bstr | req | 32 — Autonomi ciphertext address (D11) |
| 7–23 | — | — | — | reserved |

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

| key | field | type | presence | len/shape |
| --- | --- | --- | --- | --- |
| 0 | `format_version` | uint | req | = 1 in v1. Versions **independently** of the manifest (line 123): a v1 bundle may embed a v2 manifest and vice versa, so F10 dispatches the two discriminants separately and never infers one from the other |
| 1 | `manifest` | bstr | req | var — the full **plaintext manifest envelope** bytes (§7.1) exactly as anchored; `anchor_digest` = SHA-256 of exactly these bytes (line 75); nested strict decode per F9 (§7.6.3) |
| 2 | `storage_record` | map | req | §7.7 |
| 3 | `ots_anchors` | array | req, may be empty | OTS artifacts (§7.8); an UNANCHORED bundle is **both** anchor arrays empty |
| 4 | `tsa_anchors` | array | req, may be empty | TSA artifacts (§7.9) |
| 5 | `receipt` | map | **opt — no parse-decidable condition** [P]: presence *is* the sealer's `--include-receipt` opt-in (line 110). Absence is never an error and presence is never required; a verifier must not read anything into either | §7.10 |
| 6 | `covered_reveals` | array | req, may be empty | §7.11 entries, strictly ascending `unit_id` [X] |
| 7 | `noncovered_reveals` | array | req, may be empty | §7.12 entries, strictly ascending `unit_id` [X]; raw-mirror reveals ride here (a raw mirror is never fine-tree-covered, line 94), and by D23 a file's mirror sorts last among its own entries |
| 8 | `touched_files` | array | req, may be empty | §7.13 entries, strictly ascending `file_id` [X] |
| 9 | `full_reveals` | array | req, may be empty | §7.14 entries, strictly ascending `file_id` [X]; every entry's `file_id` must also appear in `touched_files` — **[X], not [R]**: both lists are in the bundle, so F8 decides it without the manifest |
| 10 | `range_reveals` | — | **reserved, named** | v1.1 sub-unit arbitrary-byte-range covers + boundary paths (lines 114/161); reject-if-present in v1 (§9) |
| 11–23 | — | — | — | reserved |

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
presence (§7.14), and the **`touched_files` equality** below.

**`touched_files` names exactly the files with a revealed unit** — both
directions, both tier **[R]**, both resolved 2026-07-28:

| direction | rule | decision | code |
| --- | --- | --- | --- |
| ⊇ | every revealed unit's owning file has a `touched_files` entry | **D80** (`docs/decisions/D80-revealed-unit-touched-file.md`) | `revealed-unit-file-not-touched` |
| ⊆ | every `touched_files` entry belongs to a file with a revealed unit | **D82** (`docs/decisions/D82-touched-file-without-reveal.md`) | `touched-file-without-revealed-unit` |

Both are [R] and not [X] for the same reason: "a revealed unit's *owning
file*" is a manifest fact — the unit table is nested inside file entries —
so the mapping needs layer 2, which §0's rule forbids the bundle schema
layer from reaching for. Both are therefore verify-pipeline outcomes, never
`bundle-` codes. Neither subsumes the `full_reveals ⊆ touched_files` row
above, which stays **[X]**: a file may be touched by a unit reveal without
being fully revealed.

The evidence, since D80 was a genuine open question: line 95 says
`path_salt` "ships whenever any reveal *touches* the file (so the
recipient can verify the path)", and line 121 gives only two rendering
states — revealed content, or "unrevealed files render as committed
placeholders (size only, path withheld)". A permissive reading would
need a third state the spec does not define, and would hide only the
*filename*: the plaintext manifest already exposes file identity, size,
and unit boundaries to every recipient (line 95, stated deliberately).
D82 adds the converse observation that line 121 does not merely omit
"unrevealed file, path disclosed" — it states the opposite.

**Recorded v1.1 coupling.** Both rules, and D28's `full(F)` predicate
(§7.14), quantify over *revealed units*. A range reveal reveals part of a
unit, so **assigning bundle key 10 (`range_reveals`) requires widening
"revealed" in all three**. That widening is *permissive* — bundles
previously rejected start being accepted — hence legal under line 123, and
an old v1 verifier rejects a key-10 bundle cleanly at the reserved-slot
error rather than mis-verifying it. So the v1.1 path stays open, but it is
a coupling rather than a free addition (§9, §13a).

**Canonical concatenation order.** Where a consumer needs "the revealed
units" as one sequence — e.g. `verify::structural::BundleView`'s
`revealed_unit_ids`, whose first-duplicate report must be deterministic —
it is `covered_reveals` ⧺ `noncovered_reveals`, i.e. **section key
order**. Recorded here so R5's population order is a registry fact rather
than an implementation accident.

#### 7.6.1 Checked absences — what a bundle deliberately does not carry

**Six** fields are absent **by design**, and F8's checklist test asserts
their absence rather than merely not implementing them (the F8 accept
criterion for nonces generalizes to all six). An absence nobody tests
is an absence that grows back.

| absent | why | consequence if it were added |
| --- | --- | --- |
| **per-unit `nonce`** in §7.11/§7.12 | "Nonces come from the manifest (single source of truth)" (line 114) | a bundle-side nonce would be a second, sealer-controlled AEAD input the verifier could be steered onto; `verify::unit_stages::RevealedUnitInput` deliberately exposes no parameter to smuggle one through |
| **any signature container** at bundle level | the bundle is **unsigned**. Its authority is the embedded *signed* manifest (§7.1 key 1) plus the anchor artifacts; nothing about a `.sealproof` is authenticated as a whole | a bundle signature would invite the verifier to trust the *assembler* — but the assembler is the sealer, i.e. the adversary (line 121). There is deliberately no `sig_alg` map here and no §7.1-style envelope |
| **`work_id` / `anchor_digest` / `seal_id`** at bundle level | all three are *derived*: `work_id` = SHA-256(manifest body bytes), `anchor_digest` = SHA-256(key 1 bytes), `seal_id` is a manifest body field | a stored copy could disagree with the bytes it claims to summarize, creating a "which one is authoritative" question with no good answer (§12) |
| **any reveal-shape discriminant** (`is_full_reveal`, `reveal_mode`, …) at any level | **D28 rider 1**: reveal shape is *derived* from the signed unit table and the revealed set, never declared | a declared shape is sealer-forgeable: declaring "partial" while revealing every unit would smuggle back the permissive full-reveal option D28 rejected — through the format rather than through the verifier (§7.14) |
| **a TSA `source` string** on §7.9 (removed from v1 by D8 §1) | a sealer's claim about an anchor's *provenance*, bound by nothing — the bundle is unsigned, so any relay can rewrite it undetectably — and consumed by nothing: the report pipeline refuses to copy it in writing (`verify/pipeline.rs`), and a verdict's source identity comes from the **verified certificate chain** (line 109's pinned root store) or the `.ots` attestations | a free-text provenance label rendered beside a verdict whose headline is literally "Existed no later than \<time\> (source)" (line 137) — the fifth instance of "do not carry a sealer's claim next to the thing it claims about", which the four rows above already exclude |
| **any chain identifier** (`chain_id`, network name) in §7.10 | the chain is **pinned by the verifier** (line 137: two public Arbitrum RPCs, user-overridable), never named by the artifact under inspection | a sealer-written `chain_id` would *steer the verifier's RPC choice* — the same hazard as a bundle-side nonce or a bundle-supplied trust root (line 109: "bundle-embedded chains supply intermediates only"). A receipt captured on Sepolia or a devnet simply fails to resolve against Arbitrum One at v1.1, which is the correct outcome and stronger than trusting the bundle to admit it |

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

| key | field | type | presence | len/shape |
| --- | --- | --- | --- | --- |
| 0 | `address` | bstr | req | 32 (D11) — Autonomi address of the **encrypted** manifest copy |
| 1 | `nonce` | bstr | req | 24 — the XChaCha20-Poly1305 nonce of that copy. Manifest AEAD uses **empty AAD** (line 98), so no further binding field is carried |
| 2 | `k_m` | bstr | req | 32 — `k_m = HKDF(W, "manifest-key")`. Disclosing it costs nothing: the bundle already embeds the plaintext manifest (line 98) |
| 3–23 | — | — | — | reserved |

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

| key | field | type | presence | len/shape |
| --- | --- | --- | --- | --- |
| 0 | `status` | uint | req | `anchor_status` (§6.1), sealer-recorded (**never trusted** — the verifier derives its own state) |
| 1 | `ots` | bstr | req | var — the raw `.ots`, opaque (A parses; A owns `.ots` limits at M2) |
| 2 | `block_height` | uint | opt: **upgrade group** (below) | attested Bitcoin block height |
| 3 | `block_header` | bstr | opt: **upgrade group** | **exactly 80** [P] (line 108) — a wrong length is its own error, never a "malformed header" |
| 4 | `fetch_date` | uint | opt: **upgrade group** | POSIX seconds (§3) — the instant the sealer **completed the upgrade capture** (below) |
| 5–23 | — | — | — | reserved |

**The upgrade group (keys 2–4) is all-or-nothing** [X]: an upgraded OTS
anchor carries height + header + fetch date together, and a
not-yet-upgraded one carries none of them. Two of the three present is a
malformed artifact, not a partially-known one. Stating it as a *group*
(rather than three independent `opt` rows) is what makes "header without
height" a single distinct rejection instead of a rule that has to be
rediscovered per key.

**The group is free-standing (D79, ratified 2026-07-28): its presence is
never conditioned on `status`.** `status` is sealer-written and the design
requires a verifier not to trust it; conditioning a *parse* rule on it
would let a sealer choose which shapes decode — the same
derived-not-declared principle D28 rider 1 applies to reveal shape. The
consequence is accepted deliberately: an artifact recording
`status = pending` while carrying height + header is well-formed v1, and
what its status values *mean* is A-domain semantics at M2 (§6.1).

**What key 4 means, exactly.** The instant the sealer **completed the
upgrade capture** — obtained the attested block height *and* the 80-byte
header and wrote them to the journal. It is **not** the `.ots` submission
time (not carried anywhere), and **not** the Bitcoin block timestamp, which
lives inside the embedded header and is the datum `--online` confirmation
promotes to `proven` (line 108). Its membership in the upgrade group is
what makes this the only coherent reading: a not-yet-upgraded anchor has no
upgrade to have fetched, which is precisely why the field is absent for
one.

**Three non-rules, recorded so nobody adds them.** None of these is a v1
rule and none may become one after the freeze — each would reject honest
bundles, and both sides of every comparison are sealer-authored, so none is
verifiable:

- no ordering relation between `fetch_date` and the header's own timestamp,
  or between it and `claimed_time`;
- no lower or upper bound (zero is a legal `uint`);
- no monotonicity across the anchor list.

**Recorded privacy note.** An OTS `fetch_date` reveals, to the second, when
the sealer last ran the CLI — activity metadata about the *sealer*, not
about the work. Line 114 lists "fetch dates" as bundle content, so the
field stays; the leak is recorded, not eliminated.

### 7.9 TSA anchor artifact (lines 109, 112–114)

Same discipline: the DER token and the certificates are opaque `bstr`s
here. CMS/X.509 parsing, chain validation against the pinned root store,
and the "valid at stamping" evaluation are **A's, at M2**.

| key | field | type | presence | len/shape |
| --- | --- | --- | --- | --- |
| 0 | `status` | uint | req | `anchor_status` (§6.1), sealer-recorded (never trusted) |
| 1 | `token` | bstr | req | var — DER TimeStampResp/token, opaque |
| 2 | `intermediates` | array | req, may be empty | bstr elements — DER certs, opaque; **intermediates only**: a bundle-supplied chain can never close against a bundle-supplied root (line 109), so no root slot exists here to be tempted by |
| 3 | `fetch_date` | uint | req | POSIX seconds (§3) — the instant the sealer **received the `TimeStampResp`** (below); always known at seal, hence required where the OTS counterpart is optional |
| 4–23 | — | — | — | reserved |

**Key 4 is plain reserved, and its absence is checked (D8 §1).** The draft
assigned key 4 to an informational `source` string; **v1 does not carry
one** (§7.6.1). It is not a *named* reserved slot: §9's named slots mean "a
committed v1.1 item", and a TSA source string is committed to nothing. The
option is preserved by the band, not by a name — assigning key 4 in a later
v1.x release is the ordinary additive path (§9) and needs only a recorded
format decision. Present in v1 input, key 4 raises F10's ordinary
reserved-slot error; no code was minted for its removal.

**What key 3 means, exactly.** The instant the sealer **received the
`TimeStampResp`** from the TSA. It is **not** the token's `genTime`:
`genTime` is inside the DER and is the *provable* time (line 109); this
field is metadata about the sealer's own clock and network. Required
because a TSA artifact exists only if a response was received, so the value
is always known — which is the asymmetry with §7.8 key 4. The three
non-rules recorded under §7.8 (no ordering relation, no bounds, no
monotonicity) bind this field identically. Privacy: for a TSA anchor the
date adds nothing, being within seconds of the token's own `genTime`, which
ships anyway.

One artifact per token: "≥ 2 TSAs" (line 103) means ≥ 2 entries in key 4
of §7.6, not a multi-token artifact. Nothing in the schema requires two —
an under-anchored bundle is a *verdict*, not a parse error.

### 7.10 Arbitrum receipt record (line 110) — opt-in

Internals are A/S-owned; this layer fixes only the envelope split:
the two user-visible "supporting evidence" data plus one opaque payload
(quote preimages + `proof_bytes` — the v1.1 verification-chain capture).

| key | field | type | presence | len/shape |
| --- | --- | --- | --- | --- |
| 0 | `tx_hashes` | array | req | bstr(32) elements (Keccak-256 EVM tx hashes), non-empty; capture order (§8) |
| 1 | `block_number` | uint | req | the Arbitrum One block number of the **earliest-confirmed** transaction in key 0 — i.e. the **minimum** block number over the receipt's transactions. A payment may span several transactions (S1 §12: ≤ 256 transfers per tx, one `TxHash` per sub-batch), each confirmed in its own block, so "the payment's block" is **defined, not observed**. Display-only: unverified in v1, never verdict-bearing, re-derivable from any transaction hash over RPC. A per-transaction structure, if a consumer ever needs one, takes a reserved key additively — and must then be **per tx**, never a second scalar |
| 2 | `payload` | bstr | req | var — opaque A/S serialization (quote preimages, `proof_bytes`). **Opaque to this registry**: its internal layout is A/S's and is *not* a v1 wire format, so changing it is not a format-version event |
| 3 | `chain_inputs` | — | **reserved, named** | v1.1 Arbitrum-receipt **verification chain** (line 161: address recomputation ↔ quote preimages ↔ tx calldata) — the slot into which v1.1 may promote registry-visible, version-stable structure out of the opaque `payload`. Reject-if-present in v1 (§9). Shape deliberately **not designed here** — A/S own it |
| 4–23 | — | — | — | reserved |

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

**What freezes about key 2, and what deliberately does not.** The payload
is an opaque `bstr` whose internal layout is **not v1 wire format**. Its
contents may change in any release without a format-version event and
without a reseal. Nothing in a v1 verdict may depend on its internal
structure. The **completeness** of the capture — whether it carries every
input the v1.1 chain will need — is an **S-domain obligation (S7)** with no
freeze deadline, because the vault, not the bundle, is what a reseal would
have to rebuild from; anything v1.1 must read in a version-stable,
cross-implementation way is promoted out of the payload into reserved
key 3 (`chain_inputs`), which is what that slot exists for. This is D84's
move: freeze the placement and the failure shape, let the domain that will
hold the evidence choose the contents.

**And there is no chain identifier, deliberately** — a checked absence
(§7.6.1), because a sealer-written `chain_id` would steer the verifier's
RPC choice.

`tx_hashes` (key 0) is non-empty because a receipt with no transaction
records no payment; its 256-element cap is `MAX_TX_HASH_COUNT` (§11), which
S1 §12's `MAX_TRANSFERS_PER_TRANSACTION` makes the natural ceiling.

### 7.11 Covered-unit reveal (lines 96, 112–114)

| key | field | type | presence | len/shape |
| --- | --- | --- | --- | --- |
| 0 | `unit_id` | uint | req | must resolve into the embedded manifest's unit table **[R]** |
| 1 | `k_u` | bstr | req | 32 **[P]** — the unit key, disclosed per reveal so the verifier decrypts without ever holding `W` (line 114) |
| 2 | `ciphertext` | bstr | req | var; `len ≡ 16 (mod 256)` and `len ≥ 272` **[P]** (§2). The exact `len == padded_length(true_length) + 16` is **[R]** — it needs the manifest's `true_length` |
| 3 | `cover` | array | req | `cover_entry` tuples (§5), **non-empty [P]** (a covered unit has ≥ 1 leaf; the empty unit is never covered — empty files have no fine tree, §7.4), strictly ascending interval start **[X]**; leaf-exactness, the no-ancestor-seed rule and the **canonical leaf-level payload (D83: an entry at `level == d` must carry `salt_i ‖ 0x00·16`)** are **[R]** |
| 4 | `paths` | array | req, may be empty | `path_node` tuples (§5), strictly ascending interval start **[X]**; empty exactly when the unit spans `[0, n)` (no boundary siblings) — the *exactly* is **[R]** |
| 5–23 | — | — | — | reserved |

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

#### D75 — why key 3 is `req` even on a full reveal (recorded rationale)

> **Settled law: "both"** (D75, resolved 2026-07-28 —
> `docs/decisions/D75-full-reveal-cover-shape.md`). Key 3 is
> unconditionally `req` at tier [P]. The material below is the recorded
> rationale for that outcome, not an open choice. The decision's rider is
> binding: because two independent routes to `fine_root` coexist, **they
> must be required to agree** — leaf salts derived from `s_root` and from
> the per-unit covers are the same values, and a disagreement is an
> equivocation attempt.

**The framing D75 answered:**
On a *full* reveal of a fine-tree file the bundle carries both this
entry's per-unit `cover`/`paths` for every unit **and** the file's
`s_root` (§7.14 key 2) — two independent routes to the same `fine_root`.
D75 asked whether the covers should instead be omitted in that case.

**The key assignment is answer-neutral, and deliberately so.** Nothing
about D75 moves a key, a type, or a reserved slot: key 3 keeps its number
either way. Only its *presence rule* differs —

- **"both"** (as drafted): `req`, **[P]** — a covered reveal is
  self-contained and F8 validates it without the manifest;
- **"`s_root` only"**: `opt: ¬full(F)`, which is **[R]** — key 3's
  presence would then depend on the derived full-reveal predicate
  (§7.14), so F8 could no longer validate a covered reveal in isolation
  and the rule would cross the §0 tier boundary.

**Why "both" won.** Three reasons: (1) it keeps key 3 at tier [P], so
bundle schema validation stays decidable from the bundle alone (§0, D78);
(2) it costs bytes but leaks nothing — on a full reveal every leaf is
disclosed anyway, which is exactly why line 114 says `s_root` "discloses
nothing" there; (3) it keeps one decode shape for `covered_reveal`
instead of two. The cost is real: ~2·⌈log₂ n⌉ cover entries per unit are
redundant once `s_root` is present.

**What D75 settles about R4's `s_root` tree rebuild.** The rebuild is
**defence-in-depth for the file's content binding** — every unit is
already bound to `fine_root` through its own cover — and simultaneously
**load-bearing and sole for the disclosed `s_root` itself**:
`check_fine_root_rebuild` is the only consumer of a full reveal's `s_root`
anywhere in the pipeline, so deleting it would turn §7.14 key 2 into
precisely what D74 mints a permanent code to prevent — a bundle-side field
the verifier reads, does not check, and does not report. The rebuild is
spec-mandated by line 121 either way; D75 changes its weight, not whether
it runs.

> **Correction, applied per D75 Correction 1**
> (`docs/decisions/D75-full-reveal-cover-shape.md` §Corrections). Earlier
> drafts of this section said the rebuild "additionally proves no extra
> leaves". **It proves nothing of the kind**, because both routes take the
> leaf count from the same place and neither can admit a leaf the other
> excludes. The claim is deleted rather than weakened.

### 7.12 Non-covered-unit reveal (lines 92, 94, 112–114)

`--no-fine-tree` whole-file units and raw-mirror units — the two cases
bound by `unit_commit` rather than by `fine_root` (line 94). Keys 0–2 are
**deliberately key-aligned with §7.11** so both reveal kinds share one
decode prefix: same key numbers, same types, same [P] checks, one
implementation. The divergence starts at key 3, where §7.11 needs a
cover and this needs the salt that opens the commitment.

| key | field | type | presence | len/shape |
| --- | --- | --- | --- | --- |
| 0 | `unit_id` | uint | req | resolves into the manifest unit table **[R]** |
| 1 | `k_u` | bstr | req | 32 **[P]** |
| 2 | `ciphertext` | bstr | req | var; same §2 shape check **[P]** |
| 3 | `unit_salt` | bstr | req | 16 **[P]** — opens `unit_commit = SHA-256(0x02 ‖ unit_salt ‖ bytes)` (line 94) |
| 4–23 | — | — | — | reserved |

A raw-mirror reveal is an ordinary entry here — no mirror flag, no link
field: the manifest's `kind` already identifies it (line 98), and by D23
it is its file's last unit, so it sorts after that file's other
non-covered entries. Whether a unit legitimately belongs in *this* array
rather than §7.11 is **[R]** (it depends on the file's
`fine_tree_present` and the unit's `kind`).

### 7.13 Touched-file entry (lines 112–114) — explicit `file_id`, ratified (§10)

| key | field | type | presence | len/shape |
| --- | --- | --- | --- | --- |
| 0 | `file_id` | uint | req | index into the embedded manifest's file table; in-range **[R]** |
| 1 | `path` | tstr | req | the sealed path. UTF-8 by type (native F3 check); **the tstr's bytes as received are the commitment pre-image** — `path_commit = SHA-256(0x05 ‖ path_salt ‖ path_utf8)` (line 95). No NFC, no separator rewriting, no case folding is applied to a path: the text canonicalization pipeline (D20/D21) governs *file content*, never this field |
| 2 | `path_salt` | bstr | req | 16 **[P]** |
| 3–23 | — | — | — | reserved |

Path disclosure is per **touched** file, and `path_salt` is the
*path-only* salt — independent of `file_salt` precisely so that naming a
file never weakens its content commitments (line 95). The two must never
be merged into one salt field in a future version.

### 7.14 Fully-revealed-file entry (lines 112–114, 121) — D28 strict

| key | field | type | presence | len/shape |
| --- | --- | --- | --- | --- |
| 0 | `file_id` | uint | req | in-range **[R]**; must also appear in `touched_files` **[X]** (§7.6) |
| 1 | `file_salt` | bstr | req | 16 **[P]** — opens `raw_commit`/`canon_commit`; disclosed **only** on a full reveal (line 95). **One salt for both content commitments (D76: no split in v1)** — a future `raw_salt` would take a reserved slot of this map, never displace key 1 |
| 2 | `s_root` | bstr | **opt — biconditional, [R]: present iff `full(F) ∧ fine_tree = Present`** | 32 — the full `[0, n)` cover (line 114); a `--no-fine-tree` or empty file has no fine tree, hence no `s_root`. At **`n == 1`** the grid root is a leaf, so this field is the canonical leaf-level payload `salt_0 ‖ 0x00·16` and a non-zero upper half is rejected **[R]** (D83) |
| 3–23 | — | — | — | reserved |

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
| `full(F) ∧ fine_tree = Absent`, key 2 present | `full-reveal-s-root-without-fine-tree` (**D74**, `docs/decisions/D74-extraneous-full-reveal-s-root.md`). A single code: the `FileSalt` counterpart is unreachable, because key 1 is `req` at schema level and F8 rejects a key-1-less entry as `bundle-missing-key` before R4 runs |

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
`4..=23`, `receipt_record` → `3..=23`, `covered_reveal` → `5..=23`,
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
| `ots_anchors`, `tsa_anchors` | capture order recorded in the seal journal (stable across rebuilds); wire order preserved as-is | no (builder rule) |
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

**Order carries no meaning.** A verifier must not read "first" as
"primary". The headline is "Existed no later than \<earliest
headline-eligible time\>" (line 137), computed from **verified** times,
never from position. Recorded so the M3 page cannot acquire a positional
convention by accident.

**Duplicate anchor artifacts are legal v1, deliberately.** A
byte-identical duplicate `.ots` or TSA token in one array is not rejected.
Rejecting it was considered and declined for three reasons: it catches only
the laziest inflation (a sealer wanting two "independent" TSA anchors from
one TSA simply requests two tokens — different bytes, same TSA, passes any
byte-distinctness check); the check it would substitute for is a
*verdict*-level one that needs no format support — **anchor independence
must be evaluated from verified identities, never from array length**, an
obligation on A18/R17; and it would put up to 256 × 1 MiB of hashing into
verify stage 1, which D10 §6 designs to be cheap and to run ahead of every
AEAD, hash and signature. The price is stated plainly: this is the
**irreversible** direction — permissive now cannot be tightened after the
freeze — and it is accepted because the check that actually matters lives
where the evidence is, and a weaker proxy in the format would create
exactly the false assurance the real check must not compete with.

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

### Headroom at freeze

Recorded at the freeze so exhaustion is visible before it is reached. Free
slots = the map's share of `0..=23` that is neither assigned nor named:

| map | assigned | named-reserved | free slots in `0..=23` |
| --- | --- | --- | --- |
| `manifest_envelope` | 0–1 | — | **0 — frozen shape, no band, forever** (§1 rule 6) |
| `manifest_body` | 0–7 | — | 16 |
| `file_entry` | 0–6 | — | 17 |
| `canon_descriptor` | 0–3 | — | 20 |
| `unit_entry` | 0–6 | — | 17 |
| `bundle` | 0–9 | 10 `range_reveals` | **13** |
| `storage_record` | 0–2 | — | 21 |
| `ots_anchor` | 0–4 | — | 19 |
| `tsa_anchor` | 0–3 | — | 20 |
| `receipt_record` | 0–2 | 3 `chain_inputs` | 20 |
| `covered_reveal` | 0–4 | — | 19 |
| `noncovered_reveal` | 0–3 | — | 20 |
| `touched_file` | 0–2 | — | 21 |
| `full_reveal` | 0–2 | — | 21 |

**Why `0..=23` and not a wider band.** The band's *size* is what makes
F10's reserved-slot error honest. That error means "this is a v1.x field
your verifier is too old for" — a credible claim for a small, deliberately
reserved band of 24, and a lie for, say, `0..=255`, where most keys will
never be assigned and "upgrade your verifier" would be the wrong advice for
what is simply garbage. Widening the band is therefore not free even though
it costs no bytes: it degrades a permanent error code's meaning, and D30
freezes which code fires for which input. The tightest map, `bundle` at 13
free, is also the one whose additions are largest — a new top-level section
is a new schema, not a field (§7.6.2) — so thirteen is generous.

**Band exhaustion is a format-version event, not a defect to patch.** If a
map's `0..=23` band is ever exhausted, the next addition is **not** a key
≥ 24. Keys ≥ 24 are unknown-key forever (§1 rule 4) and carry no
"too-old verifier" meaning, so a v1.x field there would be rejected by the
wrong code. An exhausted band means the format has run out of additive
room, and the correct response is a **format-version event** — which this
section already requires for anything non-additive.

### The v1.1 sub-unit range-reveal path, and its couplings

A v1.1 range reveal needs, per lines 96/114: the file (or unit) it speaks
about, the byte range, the revealed bytes, the leaf-exact GGM sub-cover of
exactly those leaves, and the boundary Merkle paths. That is **one new
bundle section** — an array under bundle key 10, whose elements are a new
map with its own fresh `0..=23` band. Nothing in v1 has to move. Three
couplings, recorded now because they are cheap to record and expensive to
discover:

1. **"Revealed" widens.** D80, D82 (§7.6) and D28's `full(F)` predicate
   (§7.14) all quantify over *revealed units*; a range reveal reveals part
   of a unit, so assigning key 10 requires widening all three. The widening
   is permissive, hence legal (line 123), and an old v1 verifier rejects a
   key-10 bundle cleanly at the reserved-slot error.
2. **`UnknownUnitRef` stops idling.** §7.11 records that "proof reaches
   outside the revealed set" is unrepresentable in v1 because `cover`/
   `paths` are nested inside their reveal. That check must survive the
   freeze rather than be tidied away as dead code.
3. **The proof format itself is already frozen.** `cover_entry` and
   `path_node` (§5) are what a range proof carries, and they ship in MVP
   (line 161). So v1.1 adds *selection and rendering*, not cryptography —
   which is why one reserved key suffices. Boundary paths need nothing
   further: a range's boundary siblings are `path_node` tuples in the same
   encoding, addressed by the same `(level, index)` convention D9 froze.

### Version dispatch order (F10)

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

## 10. Touched-file explicit `file_id` — RESOLVED: YES

The F4 task note requires this decision here; D8 §5 ratified it. Bundle
per-file sections (§7.13/§7.14) carry an explicit `file_id` key 0.

**The binding reason is structural rather than preferential: without an
explicit `file_id` the tier-[X] rule `full_reveals ⊆ touched_files` (§7.6)
is undecidable at F8.** An [X] rule is decided from the bundle alone.
Associating a `full_reveal` entry to a `touched_file` entry without a
shared id means opening `path_commit` — which needs the manifest — so the
rule would drop to tier [R], which D78 forbids the bundle schema layer from
reaching for. The same applies to §8's "strictly ascending `file_id`"
ordering rule on both lists, and to D80's and D82's rules, neither of which
is even expressible without the id. So the id is *forced* by the tier
system §0 adopts, not merely preferred.

Four supporting reasons, all of which hold:

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
   deliberate; §13 item 2).

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
`path_node` (fixed arity, §4/§5); `title`/`app_version`/`path`
(free-form `tstr`s, transitively bounded); revealed-unit `ciphertext`
(shape-checked; an upper bound would equal `MAX_BUNDLE_BYTES`).

**Not F11's**: internal structural limits of the opaque artifacts (`.ots`
op counts, DER nesting, signed-attribute counts) are A's at M2 (§7.8,
§7.9; MVP-SPEC.md line 153) — their freeze status is **D84**
(`docs/decisions/D84-anchor-artifact-limits-permanence.md`): not v1 format
surface, so they do **not** freeze at Q14. The anchor *envelope* above, and
D10's rows over it, do.

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
| 112 | fetch dates | §7.8 key 4, §7.9 key 3 — and line 112's enumeration for a TSA artifact ("TSA tokens + intermediate certs, fetch dates") is **exhaustive**: §7.9 assigns keys 0–3 and nothing more |
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
| 109/137 | a TSA anchor's **source identity** | — checked absence: no `source` string on the wire (D8 §1). The identity a verdict reports comes from the verified certificate chain against the pinned root store (line 109) for TSA, and from the `.ots` attestations for OTS — never from a bundle field (§7.6.1, §7.9) |
| 110/137 | the receipt's **chain** | — checked absence: no `chain_id` or network name. The chain is pinned by the verifier ("two public Arbitrum RPCs", line 137), never named by the artifact under inspection (§7.6.1, §7.10) |

## 13. Closed record — every question this registry raised, and what settled it

D8 (`docs/decisions/D8-wire-registry-final.md`, RESOLVED 2026-07-28) signed
the registry off. This section is the closed record of the ten items the
draft raised. **No item here is open.**

| # | question | outcome | where |
| --- | --- | --- | --- |
| 1 | TSA source identity as an informational `tstr` | **NO — removed from v1.** `tsa_anchor` key 4 becomes plain reserved (band `4..=23`) and its absence is asserted. The field was bound by nothing (the bundle is unsigned) and consumed by nothing (the report pipeline refuses it in writing); a verdict's source identity comes from the verified cert chain or the `.ots` attestations. **D8 §1** | §7.6.1, §7.9, §12 |
| 2 | explicit `file_id` in per-file bundle sections | **YES, ratified** — and forced, not merely preferred: without it the [X] rule `full_reveals ⊆ touched_files` is undecidable at F8 (D78). **D8 §5** | §7.13, §7.14, §10 |
| 3 | `title` / `app_version` optionality | **required-may-be-empty `tstr`, both keys.** The draft's shape confirmed on replaced grounds — the alternative is equally canonical, so canonicality does not decide it; `app_version` has no absent state, the alternative costs permanent D30 codes, and `req`-may-be-empty is the rule §7.6 already adopts. A non-empty check is permanently foreclosed. **D8 §2** | §7.2 |
| 4 | receipt record internal split | **`{tx_hashes, block_number, payload}` confirmed**, with key 1 given a *total* definition (the minimum block number over key 0's transactions) because the drafted wording is under-determined under S1's verified multi-transaction payment path. Payload completeness is **scoped out of the freeze**: the payload is opaque, not v1 wire format, and capture completeness is S7's obligation with no freeze deadline. A chain identifier is a checked absence. **D8 §3** | §7.10, §7.6.1 |
| 5 | recorded `anchor_status` subset · `fetch_date` semantics · anchor list order | **(a)** all seven values legal as recorded on both kinds — **no per-kind subset, ever** — with the non-consumption rule frozen in its place; **(b)** TSA `fetch_date` = the instant the `TimeStampResp` was received, OTS `fetch_date` = the instant the upgrade capture completed, neither being the provable time, plus three recorded non-rules; **(c)** capture order, unchecked, positionally meaningless, duplicates legal — anchor independence is A18/R17's verified-identity check. **D8 §4** | §6.1, §7.8, §7.9, §8 |
| 6 | ~~raw-mirror position within a file's `units` array~~ | **closed by D23** (2026-07-27): the mirror is its file's last unit; parse accepts any position and R exempts mirrors by `kind` | §7.5 |
| 7 | ~~`unit_id` stored-and-checked~~ | **ratified.** Storing it is spec-mandated (line 98); *checking* it is what stops the stored copy from becoming a second authority (§7.6.1's rule). Landed at F5 as `manifest-unit-id-mismatch`. **D8 §6** | §7.5 |
| 8 | may bundle schema validation open the embedded manifest? | **NO — D78** (ratified 2026-07-28). Enforced structurally: `BundleError` has no arm that can carry a `ManifestError`. Fixes which error family every cross-side rejection lands in, permanently under D30 | §0, §7.6.3 |
| 9 | is the OTS upgrade group tied to `status == attested`? | **NO — free-standing (D79**, ratified 2026-07-28). Conditioning a parse rule on a sealer-written field would let a sealer choose which shapes decode | §7.8 |
| 10 | must a revealed unit's owning file have a `touched_files` entry? | **YES — D80**, tier [R], `revealed-unit-file-not-touched`. **D82** subsequently closed the converse, so the two together state an *equality*: `touched_files` names exactly the files with a revealed unit | §7.6 |

**Decisions this registry records as settled rather than feeds** — the
draft's closing table listed D74, D75 and D77 as "fed but not resolved
here". All three, plus D76, resolved on 2026-07-28 and are stated as law in
the body: D74 (§7.14's fifth violation row,
`full-reveal-s-root-without-fine-tree`), D75 (§7.11 key 3 `req`, tier [P],
with its "proves no extra leaves" claim deleted per D75 Correction 1),
D76 (§7.14 key 1, one `file_salt` for both content commitments), D77
(§7.3 key 6, `manifest-empty-normal-units`). D82 was absent from the
registry entirely until this freeze and is now in §7.6.

**Co-freezes, all closed.** D9 (§5, 2026-07-28), D10 (§11, 2026-07-28),
D17 (§6.2 — ratified in code at M0 wave 3, formally closed here), D83
(§2, §5, §7.11 key 3, §7.14 key 2). Nothing in this registry is open.


## 14. Machine-readable mirror and tests

[`registry-v1.json`](registry-v1.json) mirrors this document 1:1 — every
map, key number, field name, type, presence rule, fixed length, enum value,
tuple shape, cap and reserved range, with per-item `status` markers. The
freeze-gate test is
`crates/antseal-core/tests/format_registry_freeze.rs`.

### The status vocabulary

| | before Q14 | at and after Q14 |
| --- | --- | --- |
| document-level `status` | `draft-until-Q14` | **`frozen-v1`** |
| item-level `status` | `proposed` \| `pending-D9` \| `pending-D17` | **`frozen-v1`**, and nothing else |

`proposed` is **not** a legal value for any v1 item, and neither is any
`pending-*` marker. This is not a stylistic rule: an item that still says
`proposed` in a frozen registry is either a genuine unresolved question
that escaped the gate or a lie about the document's own state, and both
are worse than a failing test. `pending-D9` and `pending-D17` are retired
outright rather than kept on an allow-list — after the freeze the stronger
property is that these strings **must not appear at all**, which is a
prohibition, not an allow-list entry. The moment a v1.1 item is drafted
into a reserved slot the equality assertion fails, forcing the v1.1 author
to extend the vocabulary consciously at their own gate rather than sliding
a proposal into a frozen document.

### The assertion set

Named so it cannot be under-delivered. **A + B + C1–C10 + D**, with **E**
the recorded non-assertions.

**A — mirror internal consistency.** The JSON parses; `registry_version
== 1`; every key / enum value / tuple index is an unsigned integer; no
duplicate key numbers within a map, no duplicate values within an enum;
reserved ranges well-formed, mutually disjoint, colliding with no assigned
key, and abutting where a map declares several; every assigned key and
reserved bound within `profile.v1_key_band_max`; the `maps[]` set is
exactly the fourteen registered names.

**B — freeze state.** Document status is `frozen-v1`; every item's status
**equals** `frozen-v1` (equality, not membership: an item added with no
status, with `proposed`, or with a novel spelling all fail identically);
and none of `proposed`, `pending-D9`, `pending-D17`, `draft-until-Q14`
occurs anywhere in the JSON at any depth, in any field — which catches the
case an allow-list cannot, a `notes` string that still says "proposed".

**C — code ⟷ mirror.**

| | assertion |
| --- | --- |
| C1 | map identity — `{MapId::ALL} ∪ {BundleMapId::ALL}` by `registry_name()` equals `{maps[].name}`, both directions |
| C2 | key numbers — per map, `assigned_keys()` equals `{maps[].fields[].key}` |
| C3 | reserved bands — per map, `reserved_band()` equals `maps[].reserved`, including `None` for the envelope and the two named slots pinned by their code constants |
| C4 | closed enums — `(value, registry_value_name)` pairs for `DescriptorKind`, `FineTreeDomain`, `UnitKind`, `AnchorStatus`; every value in every declared reserved range is rejected by code |
| C5 | `sig_alg`, **both** code copies — `manifest::registry::sig_alg_from_wire`/`to_wire` *and* `crypto::sig_policy::sig_alg_from_id`/`to_id`, each against the JSON directly over the full registered set and the full reserved band |
| C6 | field **names** — per map, the ordered `(key, name)` pairs equal `maps[].fields[].{key,name}` exactly. Without this, "1:1" would mean only "the numbers line up", and §7.6.1's name-based absence ban would be evadable by a rename |
| C7 | scalar lengths — the thirteen `scalars[]` rows against their code constants, plus the bundle-side aliases (`TX_HASH_LEN`, `STORAGE_NONCE_LEN`, `STORAGE_ADDRESS_LEN`, `MIN_CIPHERTEXT_LEN`) |
| C8 | tuple arities — `byte_range` 2, `cover_entry` 3, `path_node` 3 |
| C9 | caps — all 19 `caps.entries[]` names, values **and error codes** against `codec::caps` and the emitting variants' `.code()`, both directions |
| C10 | report `AnchorState` ⟷ wire `AnchorStatus` — two independent seven-variant enums with byte-identical kebab-case spellings and no other binding. Report v1 freezes at Q14 alongside the wire (D84 §7), so the ordered spellings are pinned to each other |

**D — document ⟷ mirror.** The freeze test reads *this file* and asserts,
for the mechanical tables only: every `### 7.x` map section's rows
`| N | name | …` match that map's `maps[].fields[].{key,name}` exactly,
both directions, including the reserved-band row; §6's enum tables match
`enums[]`; §2's fixed-length table matches `scalars[]` **by length, both
directions** — a recorded narrowing, because §2 groups fields by byte length
and names them in prose while `scalars[]` names them by role with synthetic
keys (`salt16`, `commit32`, `hash32`), so the two are not row-comparable and
a substring match on the prose would pin editorial wording rather than format
facts; §11's cap table matches `caps.entries[]` by name, value and code.
Brittleness to formatting
is a feature after the freeze: the normative document should not be
reformatted silently. Without D, "mirrors this document 1:1" is an unbacked
claim — which is how the JSON drifted from its own doc before the freeze.

**E — recorded non-assertions**, named so they are deliberate rather than
forgotten:

- **presence rules** (`required` / `optional` / conditional) are expressed
  in code by Rust types (`Option<T>`, enum arms), which cannot be reflected
  without a macro; the mirror carries them for humans and for F8/R, and the
  schema tests enforce them;
- **validation tiers** ([P]/[X]/[R]) have no code representation at all —
  they are a layering contract between F8 and R, enforced by which module
  holds each check;
- **§12's spec-coverage checklist** cannot be machine-checked (spec lines
  are prose) and remains a reviewed artifact;
- **the receipt `payload`'s internal layout** is deliberately outside this
  registry (§7.10) and has nothing to assert.

### Non-`maps` sections

Three sections record rules rather than assignments and are not
status-walked as key spaces: `decode_layers`, `checked_absences`, and
`validation_tiers` — mirrors of §7.6.3, §7.6.1 and §0 respectively, so F8
can consume them without parsing prose. They still carry the frozen marker
where they carry a status at all.

### Byte pinning

Both files are digest-pinned by `docs/format/FROZEN.sha256` under the same
append-only, refuse-on-change semantics `scripts/vector-freeze.sh` applies
to golden vectors (Q50). The code ⟷ mirror assertions above are
*consistency* checks: they would pass a coordinated edit of both sides in
one commit. The digest is what makes a post-freeze change to either file a
visible, deliberate act.

