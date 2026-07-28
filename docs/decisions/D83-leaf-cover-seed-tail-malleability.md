# D83 — A leaf-level cover seed's upper 16 bytes are inert: accept the malleability, canonicalize it, or shorten the wire form?

- **Status: RESOLVED — option B, the canonical zero tail. A disclosed GGM
  payload at `level == d` is `salt_i ‖ 0x00·16`: still exactly 32 bytes,
  of which only the low 16 carry meaning, and the upper 16 MUST be zero or
  the proof is rejected. One new error code, no change to any CBOR type or
  length, no change to F's decoder, no tier change.**
- **Date: 2026-07-28** (planning; G23 implements, R4 carries the second
  call site, F4 records the registry rows)
- **Owner: G (semantics + both checks) + F (registry wording); gate Q14**

---

# RESOLVED — 2026-07-28

## 0. The decision, in one rule

> **Canonical leaf-level payload (v1, normative).** Let `d = ⌈log₂ n⌉` be
> the GGM grid depth of a fine-tree file of `n` leaves. The 32-byte value a
> bundle discloses for a GGM node at **`level == d`** is
>
> ```text
> payload = salt_i ‖ 0x00 0x00 … 0x00        (16 salt bytes ‖ 16 zero bytes)
> ```
>
> A verifier MUST reject a bundle in which any `level == d` disclosed GGM
> payload has a non-zero upper half. The rule binds at **both** sites where
> a `level == d` GGM value is disclosed:
>
> 1. `cover_entry`'s third element (registry §5 tuple; §7.11 key 3
>    `cover[]`) — whenever that entry's `level` equals `d`;
> 2. `full_reveal.s_root` (§7.14 key 2) — whenever `n == 1`, because then
>    `d == 0` and the grid root **is** the single leaf.

Nothing else changes. `cover_entry` stays `[uint, uint, bstr(32)]`;
`full_reveal.s_root` stays `bstr(32)`; both keep their exact-length checks
at tier **[P]**; F's decoder is untouched. The new rule is a *value*
constraint at tier **[R]**, enforced where `n` is already in hand.

## 1. Exposure, corrected and measured

The record above ("leaf-level nodes appear in most partial reveals") and the
orchestrator's hand-off ("the `[0,n)` cover decomposition contains a size-1
block iff `n` is odd") are **both wrong**, in opposite directions. The true
rule was measured exhaustively against `content::minimal_cover` rather than
reasoned about:

**Fact 1 — the whole-file cover never decomposes.** `minimal_cover([0,n), n)`
is the single root node `(0, 0)` for **every** `n`, because the root's *real*
span (its slot interval truncated at `n`) is exactly `[0, n)` and is
therefore leaf-exact on its own. Verified for `n = 1..=40`; already pinned by
`cover::tests::full_range_is_exactly_the_root`. A whole-file cover carries a
`level == d` node **only at `n == 1`**, where `d == 0` and the root is the
leaf. File-size parity is irrelevant.

**Fact 2 — the exact incidence rule.** A cover for leaves `[a, b)` of an
`n`-leaf file contains a `level == d` node **iff**

```text
d == 0   ∨   a is odd   ∨   (b is odd ∧ b < n)
```

Verified exhaustively for every `n ≤ 24` and every sub-range `[a, b)`
(zero mismatches). The `b < n` clause is the ragged-right-edge allowance:
a right boundary that coincides with the end of the file is absorbed by the
unused slots, so it never forces a deepest single-leaf node.

**Fact 3 — the incidence is ~75 %, not "most".** Over all `n(n+1)/2` leaf
ranges of a file:

| `n` | ranges carrying ≥ 1 `level == d` node |
| --- | --- |
| 6 | 15 / 21 (71.4 %) |
| 30 | 345 / 465 (74.2 %) |
| 34 | 442 / 595 (74.3 %) |
| 35 | 459 / 630 (72.9 %) |
| 100 | 3775 / 5050 (74.8 %) |
| 101 | 3825 / 5151 (74.3 %) |
| 1000 | 375 250 / 500 500 (75.0 %) |

The asymptote is exactly ¾ — `P(a odd) + P(a even ∧ b odd ∧ b < n) = ½ + ¼`.

**Fact 4 — at most two per cover.** No cover of any range of any `n ≤ 200`
contains more than **2** `level == d` nodes (one per range boundary). This
is the number every wire-cost argument below is built on.

**Fact 5 — what D75-BOTH actually adds.** The orchestrator is right that
full reveals are exposed, but through **unit-boundary parity**, not file
parity: under D75 a full reveal ships one cover *per unit*, and each unit
`[a, b)` is scored by Fact 2. Measured, on realistic shapes:

| file | units | `level == d` nodes across the full reveal |
| --- | --- | --- |
| `n = 34`, split 12/12/10 | `[0,12) [12,24) [24,34)` | **0** |
| `n = 30`, split 10/10/10 | `[0,10) [10,20) [20,30)` | **0** |
| `n = 35`, split 11/11/13 | `[0,11) [11,22) [22,35)` | **2** |
| `n = 100`, split 33/34/33 | `[0,33) [33,67) [67,100)` | **4** |
| `n = 6`, split 2/2/2 | `[0,2) [2,4) [4,6)` | **0** |
| `n = 1`, single unit | `[0,1)` | **1** |

An **unsplit** file's full reveal is one unit spanning `[0, n)`, so by Fact 1
it contributes a `level == d` node only at `n == 1`. `--split blank-lines`
puts boundaries at paragraph offsets, which are odd about half the time —
hence the 0-vs-4 spread above. The exposure is real and common, and it is
governed by unit boundaries.

## 2. The degenerate case the decision must name: `n == 1`

For a one-byte fine-tree file `d = 0`, so:

- the file's single unit is `[0, 1)`, its cover is the single node `(0, 0)`,
  and that node's seed **is** `s_root`;
- under D75-BOTH the same 32 bytes therefore appear **twice** in one bundle —
  §7.11 key 3's `cover[0][2]` and §7.14 key 2 `s_root` — and today both
  upper halves are independently unconstrained;
- MVP-SPEC.md line 96 states this case explicitly: "`d = 0`, `n = 1`:
  `salt_0 = s_root[..16]`". So the inertness of `full_reveal.s_root`'s tail
  at `n == 1` is **spec-visible**, not an implementation accident — and the
  original D83 record missed it entirely by scoping the finding to
  `cover_entry`.

**What option B does about the duplication.** Both fields are `level == d`
disclosures, so both take the canonical tail. The consequence is that at
`n == 1` the two fields become **byte-identical by rule**, which is what
makes D75's outstanding "the two routes must agree" rider (registry §7.11,
D75 rider) implementable as a plain 32-byte equality rather than a
first-16-bytes comparison with a written-down exception. A second consequence
worth stating: at `n == 1` the true `s_root`'s upper 16 bytes now **never
leave the vault**, because nothing needs them. That is a small but real
reduction in disclosed key material, in the direction MVP-SPEC.md line 96
already argues for ("no seed that is an ancestor of any unrevealed leaf ever
leaves the vault").

## 3. Why B, and what the losing options cost

### Option C (16-byte payload at `level == d`) — rejected

1. **It contradicts the spec in two places.** MVP-SPEC.md line 121:
   "`s_root` and every GGM covering seed = 32 B"; line 96: "Every disclosed
   32-B seed (`s_root`, GGM covering seeds) … is length-checked by the
   verifier". C is a **spec amendment**, not a registry change. The original
   record cited line 121 only as the source of `BadSeedLength` and never
   noticed that it *fixes the number*.
2. **It drops an exact byte length from tier [P] to tier [R] — twice.**
   Registry §0's tier table names "exact byte length" as the archetypal [P]
   check, and §7.11 key 3 / §7.14 key 2 are [P] today. Under C the length
   depends on `d`, which needs the manifest's `size`, which D78 forbids the
   bundle schema layer from reading. F8 could only assert `len ∈ {16, 32}`,
   with the real rule deferred to R. **This is precisely the argument that
   decided D76** ("both salts' presence would become tier [R], making a
   §7.14 entry undecidable at F8") — and here it lands on two fields instead
   of one.
3. **It forks §2's parse-enforced fixed-length table**, whose entire purpose
   is that a length is decidable from the field alone, and it makes
   `FineTreeError::BadSeedLength`'s `expected` field level-dependent —
   breaking the committed assertion `BadSeedLength { expected: 32, got: 31 }`
   and its exact `Display` string, both of which are pinned.
4. **It creates a bundle carrying one secret at two different lengths.** At
   `n == 1` the cover payload would be 16 bytes while §7.14 key 2 stayed 32
   (or would have to shrink too, dragging a *second* field's length into
   [R]). Either way the "two routes must agree" check becomes an asymmetric
   prefix comparison.
5. **It makes `WireNode.bytes` polymorphic** (seed at `level < d`, salt at
   `level == d`), so `seed_of()` stops applying uniformly and `CoverSalts`
   needs a second construction path — in the one function whose defensive
   uniformity is load-bearing.
6. **The wire saving it buys is under 1 %.** By Fact 4 a cover has at most 2
   `level == d` nodes, so C saves **≤ 32 bytes per covered reveal**. The
   smallest legal covered reveal is ≈ 352 B (map head 1 + `k_u` 34 +
   ciphertext ≥ 274 + cover ≥ 42 + empty `paths` 1), so the saving is ≤ 9 %
   of the *smallest possible* entry and far less in practice. At D10's
   `MAX_COVERED_REVEAL_COUNT = 65 536` it is ≤ 2 MiB against D10's 219 MiB
   worst-case bundle: **≤ 0.95 %**. The register's third stated harm
   ("16 bytes per node are wasted") does not survive being quantified.

### Option A (accept and document) — rejected

1. **It is the irreversible direction.** MVP-SPEC.md line 123 makes every
   released version verifiable forever, so a v1 that accepts arbitrary tails
   must accept them forever; B can be relaxed later, A can never be
   tightened. The project's stated tie-break (strict → permissive is a legal
   future relaxation; the reverse is not) points at B.
2. **It permanently degrades an assertion the project already built.**
   `crates/antseal-core/tests/verify_fuzz.rs:176`
   (`the_unauthenticated_region_at_m0_is_exactly_the_storage_record`) asserts
   as an **equality**, over an exhaustive 7891-byte sweep, that the only
   unauthenticated bytes in a `.sealproof` are the 88-byte storage record,
   and `byte_changing_mutations_outside_the_inert_regions_are_rejected`
   encodes the same boundary as the constant `88 + 67`. Both hold today only
   because every R6 fixture has even unit boundaries (`CRLF_TEXT` → 34,
   `blob.bin` 30 split 10/10/10, `split.md` 34 split 12/12/10), so no fixture
   produces a `level == d` cover node — a corpus-dependent fact that currently
   reads as universal. Under **A**, adding the odd-length fixtures R36/R37
   already register would force the boundary to become
   `88 + 67 + 16·k(bundle)` — a per-bundle, shape-dependent quantity, which
   is not an equality anybody can assert. Under **B** the constant stays
   **exactly 88** (plus 67 until R12), because the tail becomes
   authenticated. B does not merely avoid damaging that test; it is what
   allows R36/R37 to land without weakening it.
3. **It requires documenting two inert regions, not one** — the record only
   knew about `cover_entry` (§2 above).
4. The register's first stated harm — "bundle bytes are not a canonical
   identifier" — is **already true for other reasons and stays true under
   every option**: the 88-byte storage record is unauthenticated *by design*
   (spec line 119's evidence/storage separation), so a `.sealproof`'s bytes
   were never a canonical identifier for its proof. A is not rejected on that
   argument, and B is not adopted for it. What B actually buys is the
   *second* harm — a landable tamper row and an assertable authentication
   boundary — plus reversibility.

### Option H (make `salt_i` the full 32-byte leaf seed) — considered, rejected

Not on the register's list, and it deserves recording because it is the only
option that makes the malleability **unrepresentable without any length or
value rule**: if `salt_i` were the whole leaf seed rather than
`leaf_seed[..16]`, every byte of a `level == d` payload would be read by
`leaf_hash`, and there would be no new code, no new check, no tier question,
and no canonical-form rule at all.

Rejected on blast radius, not on elegance:

- it edits **MVP-SPEC.md line 96**, the authoritative spec, changing a stated
  cryptographic parameter (16-byte salts) — a maintainer decision, not a
  planning-round one;
- it changes `leaf_hash`'s preimage from 26 B to 42 B and therefore **every
  `fine_root` that exists**, re-emitting the fine-tree, manifest, bundle and
  content-model vectors and every derived digest — against option B's three
  changed hex strings in one file;
- it makes the fine-tree leaf salt the only 16 → 32 B outlier against
  `unit_salt`/`path_salt`/`file_salt` (registry §2), for no security gain
  (128-bit salts are already ample against the confirmation attack line 96
  describes).

Recorded so a future v2 that revisits the fine tree knows this is the clean
way to retire the rule B introduces.

### Why zero, specifically

The canonical filler is `0x00`, matching the format's existing filler
discipline: unit padding is zero beyond `true_length` **and the verifier
checks it** (MVP-SPEC.md line 121). Repeating the salt or any other pattern
would add a second thing to compute and check for no gain. Zero also has the
property that the discarded bytes are the *only* ones that never leave the
vault (§2).

## 4. Exact implementation

### 4.1 The error code (append-only; D30 §3)

| | |
| --- | --- |
| variant | `FineTreeError::LeafSeedTailNotZero { level: u8, index: u64 }` |
| code | **`fine-root-leaf-seed-tail-not-zero`** |
| `#[error(...)]` | `"leaf-level GGM seed tail at (level {level}, index {index}) is not zero"` |
| file | `crates/antseal-core/src/content/fine_tree/error.rs` |

It joins the `fine-root-` family by the standing exception recorded in
`docs/testing/error-code-contract.md` §2 — G's fine-tree errors carry
`fine-root-`, not `content-`. The payload is `level`/`index` only: both are
public wire structure, so project rules 4/6 hold, and the existing
`display_renders_structural_metadata_only` /
`payload_variants_render_their_numbers` tests extend without exception.

`all_code_exemplars()` gains
`E::LeafSeedTailNotZero { level: 3, index: 2 }`, and the count assertions in
`codes_are_pairwise_distinct` and
`every_class_surfaces_distinctly_through_verify_error` go **7 → 8**.

**Exactly one code is minted for the whole decision.** R's second call site
(§4.4) surfaces the same string through a delegating wrapper arm, which is
the pattern F15 established and the error-code contract §2 mandates: a code
names a rejection class, never a site. The two sites are separated by
`(code, layer)` in the fixture table, exactly as the twenty format fixtures
are.

### 4.2 The shared predicate (G owns it)

In `crates/antseal-core/src/content/fine_tree/verify.rs`, public so R can
call it:

```rust
/// Significant bytes of a disclosed GGM payload at `level == d` (D83).
pub const LEAF_PAYLOAD_SIGNIFICANT_LEN: usize = Salt16::LEN; // 16

/// Enforce D83's canonical tail on one disclosed, length-checked GGM payload.
///
/// A no-op for `address.level() != depth`: only a node at the grid's leaf
/// level has a tail the verifier never reads.
///
/// # Errors
///
/// [`FineTreeError::LeafSeedTailNotZero`] when the node sits at `level == d`
/// and any of bytes `16..32` is non-zero.
pub fn check_leaf_level_payload(
    payload: &[u8; DISCLOSED_LEN],
    address: NodeAddress,
    depth: u8,
) -> Result<(), FineTreeError>
```

The comparison is a plain `!=` — the payload is disclosed public material, so
no constant-time requirement applies; say so in the doc comment, because the
next reader will ask.

### 4.3 Where the check fires in the frozen precedence (G13)

`verify_range`'s order is frozen and asserted by
`error_precedence_is_deterministic`. The new check becomes **step 7**, and
`RootMismatch` becomes step 8:

```text
1. RangeOutOfBounds
2. ByteLenMismatch
3. BadSeedLength          (cover payloads are exactly 32 B)
4. BadNodeHashLength
5. OverBroadCover
6. WrongCoverShape
7. LeafSeedTailNotZero    ← NEW
8. RootMismatch
```

Concretely, in `verify_range`: insert `check_leaf_level_payload` for every
cover entry **immediately after `check_cover(...)?` and before
`if expected.releases_s_root()`**. Two reasons, both binding:

- **after `check_cover`** — the security-bearing `OverBroadCover` and the
  structural `WrongCoverShape` must never be masked by a cheaper check
  (`error_precedence_is_deterministic` already pins that principle for the
  over-broad case), and a `level == d` node *can* be over-broad: at `d = 3`
  the node `(3, 5)` is a level-`d` node outside a reveal of leaf 2, which is
  exactly the third case in `adversarial_over_broad_cover`. After
  `check_cover` succeeds, the offered addresses are known equal to the
  recomputed ones, so `node.level == depth` is a trustworthy predicate;
- **before the `releases_s_root()` branch** — so it also governs the
  `n == 1` full-reveal cover, whose single node is at `level 0 == d`. After
  the check, `seed_of()` yields `salt ‖ 0¹⁶`, and `rebuild_fine_root` on a
  1-byte file derives `salt_0 = payload[..16] = salt`, i.e. the correct root.
  That path must get its own test.

`RangeProof::verify` reaches this automatically — it is the same entry point.

### 4.4 The second call site: `full_reveal.s_root` at `n == 1` (R owns it)

In `crates/antseal-core/src/verify/file_stages.rs`, where the disclosed
`s_root` bytes become a `Seed32` (currently the
`Seed32::try_from(bytes).map_err(|_| VerifyError::WrongLength { … })` at
≈ line 811), add **immediately after** that conversion — i.e. after R4's
row-6 length checks and before the row-8 rebuild:

```rust
check_leaf_level_payload(
    s_root.as_bytes(),
    NodeAddress::root(),
    depth_for_leaf_count(file.size).unwrap_or(0),
)
```

`depth_for_leaf_count(1) == 0 == NodeAddress::root().level()`, so the check
is a no-op for every `n > 1` and fires only in the degenerate case. Wrap it
in a new `VerifyError` arm whose `code()` **delegates** to the inner
`FineTreeError::code()` — no second code string:

```rust
/// A fully revealed file's disclosed `s_root` violates D83's canonical
/// leaf-level payload rule (only reachable at `n == 1`, where `d == 0`).
FineRootSeedTailNotCanonical { file_id: u64, source: FineTreeError },
```

D75's outstanding agreement rider (registry §7.11) then becomes a plain
32-byte equality between §7.14 key 2 and the whole-file unit's cover payload;
record that in the rider's wording when D75's registry corrections land.
The direct check above is the **normative** one and must not be replaced by
the agreement check — the agreement check's scope may later change, the
format rule may not.

### 4.5 The prover side (G12)

`CoverEntry` (in `content/fine_tree/cover.rs`) gains a second stored value
rather than mutating `seed()`:

```rust
pub struct CoverEntry {
    node: CoverNode,
    seed: Seed32,       // the true derived GGM seed — UNCHANGED
    payload: Seed32,    // what the bundle discloses (D83)
}

impl CoverEntry {
    /// The node's GGM seed. Equal to `SaltTree::seed_at(address)`.
    pub const fn seed(&self) -> &Seed32 { … }

    /// The bytes a bundle discloses for this node: the seed for
    /// `level < d`, and `salt_i ‖ 0x00·16` for `level == d` (D83).
    pub const fn payload(&self) -> &Seed32 { … }
}
```

`cover_seeds(s_root, cover)` fills both — it already has `cover.depth()`.
`RangeProof::wire_cover()` switches to `bytes: entry.payload().as_bytes()`.

Three constraints on this shape, each of which a naive implementation breaks:

1. **`seed()` must keep meaning "the GGM seed"**, or
   `cover_seeds_agree_with_the_salt_tree` becomes a statement about the wire
   instead of about the GGM tree and stops proving what it claims.
2. **The payload must be a `Seed32`, not a `[u8; 32]`.** `Seed32` redacts its
   `Debug` and zeroizes on drop; a bare array inside `RangeProof` (which
   derives `Debug`) would print salt bytes in a panic message and break
   `cover_entry_debug_redacts_the_seed` and project rule 6.
3. `wire_cover()` must keep returning borrowed `WireNode<'_>`s, which is why
   the payload is *stored* rather than computed on demand.

`prove_unit` needs no change — it is `prove_range`.

## 5. Verbatim registry rows

### 5.1 `docs/format/registry-v1.md` §2 — append after the fixed-length table

> **Canonical leaf-level GGM payload (D83).** The 32-byte length above is
> unconditional, but at the grid's leaf level only half of it is read. A
> disclosed GGM value for a node at **`level == d`** (`d = ⌈log₂ n⌉`) is
> `salt_i ‖ 0x00·16`: the verifier takes `salt_i = payload[..16]` with no
> descent (MVP-SPEC.md line 96), so bytes `16..32` are significant only as a
> canonicality rule. **A non-zero upper half is a rejection**
> (`fine-root-leaf-seed-tail-not-zero`), tier **[R]** — it needs `n` from the
> embedded manifest. This binds `cover_entry` (§5, §7.11 key 3) at
> `level == d` and `full_reveal.s_root` (§7.14 key 2) at `n == 1`, the one
> case where the grid root is itself a leaf.

### 5.2 §5 — replace the `cover_entry` bullet under "Tuple shapes (D9-decided)"

> - **`cover_entry` = `[level, index, seed]`** — `uint, uint, bstr(32)`.
>   One disclosed GGM seed of the leaf-exact sub-cover. At `level == d` the
>   third element is **not** the raw seed but the canonical leaf-level
>   payload `salt_i ‖ 0x00·16` (D83); at `level < d` it is the seed itself.
>   The length is 32 either way and stays a **[P]** check.

### 5.3 §5 — new subsection after "Canonical slot for content-tree (boundary-path) nodes"

> #### Canonical leaf-level payload — status: proposed (D83 RESOLVED — option B)
>
> A cover node at `level == d` covers exactly one leaf slot, so a verifier
> descends `d − level = 0` levels and reads `salt_i = payload[..16]`
> directly (MVP-SPEC.md line 96). Bytes `16..32` are therefore never an input
> to any hash. v1 fixes them at **zero** and requires the verifier to check
> them, so that one proof has exactly one encoding.
>
> Incidence, for sizing and for test design: a cover for `[a, b)` contains a
> `level == d` node **iff `d == 0 ∨ a odd ∨ (b odd ∧ b < n)`** — about ¾ of
> all ranges. A whole-file cover `[0, n)` is always the single root node and
> so carries one only at `n == 1`; under D75 a *split* file's full reveal
> ships one cover per unit and is governed by unit-boundary parity, not by
> file size. At most **2** such nodes occur in any one cover.
>
> The same rule governs `full_reveal.s_root` (§7.14 key 2) at `n == 1`,
> where `d == 0` makes the grid root a leaf and MVP-SPEC.md line 96 states
> `salt_0 = s_root[..16]` outright. At that size the two fields are
> byte-identical by rule, which is how D75's "the two routes must agree"
> rider is discharged.
>
> Rejected alternatives are recorded in
> `docs/decisions/D83-leaf-cover-seed-tail-malleability.md`: a 16-byte
> payload at `level == d` would contradict MVP-SPEC.md lines 96/121 and drop
> two exact byte lengths from tier [P] to [R] for a ≤ 0.95 % wire saving.

### 5.4 §7.11 key 3 — replace the `len/shape` cell

> `cover_entry` tuples (§5), **non-empty [P]** (a covered unit has ≥ 1 leaf;
> the empty unit is never covered — empty files have no fine tree, §7.4),
> strictly ascending interval start **[X]**; leaf-exactness, the
> no-ancestor-seed rule and the **canonical leaf-level payload (D83: an
> entry at `level == d` must carry `salt_i ‖ 0x00·16`)** are **[R]**

### 5.5 §7.14 key 2 — replace the `len/shape` cell

> 32 — the full `[0, n)` cover (line 114); a `--no-fine-tree` or empty file
> has no fine tree, hence no `s_root`. At **`n == 1`** the grid root is a
> leaf, so this field is the canonical leaf-level payload
> `salt_0 ‖ 0x00·16` and a non-zero upper half is rejected **[R]** (D83)

### 5.6 `docs/format/registry-v1.json` — the mirror

Three edits, all additive:

1. `resolved_decisions` gains

```json
"D83": {
  "topic": "canonical leaf-level GGM payload",
  "resolved": "2026-07-28",
  "outcome": "option B — a disclosed GGM payload at level == d is salt_i || 0x00*16; length stays 32 and stays [P]; the zero tail is a [R] value rule",
  "binds": ["cover_entry element 2 at level == d", "full_reveal key 2 at n == 1"],
  "code": "fine-root-leaf-seed-tail-not-zero",
  "doc": "docs/decisions/D83-leaf-cover-seed-tail-malleability.md"
}
```

2. `tuples[] where name == "cover_entry"` — `elements[2]` gains, and the
   tuple gains a `canonical_form` note:

```json
{
  "index": 2,
  "name": "seed",
  "type": "bstr",
  "length": 32,
  "canonical_leaf_payload": "at level == d the value is salt_i || 0x00*16 (D83); at level < d it is the raw GGM seed. Length 32 either way, tier P; the zero tail is tier R."
}
```

3. `maps[] where name == "full_reveal"` — key 2's entry gains

```json
"canonical_leaf_payload": "at n == 1 (d == 0) the grid root is a leaf, so this field is salt_0 || 0x00*16 and a non-zero upper half is rejected (D83, tier R)"
```

Whatever the mirror's exact key names turn out to be, the **1:1 doc ⟷ JSON
test in §14 is the acceptance criterion**: if it passes and the prose above
is present verbatim, the mirror is right.

## 6. Artifacts that must be re-emitted — and the ones that must NOT move

### Must change

| artifact | change |
| --- | --- |
| `testdata/vectors/v1/fine-tree/fine-tree.json` | **3 openings, 4 seed strings** (below) |
| `testdata/vectors/v1/fine-tree/gen_vectors.py` | the independent generator must implement the same rule, or Q11's cross-check diverges |
| `testdata/vectors/v1/FROZEN.sha256` | the `fine-tree/fine-tree.json` digest line — regenerate with `scripts/vector-freeze.sh --update` |
| `testdata/vectors/v1/INDEX.json` | the `fine-tree` roster entry's `pins` prose (auxiliary, not frozen) |
| `testdata/tamper/MATRIX.json` | one `project_added` entry (§7) |
| `crates/antseal-core/tests/content_properties.rs` | `significant()` collapses to the identity projection; `d83_…_committed_counterexample` inverts |

**The four seed strings, exactly.** Only `expect.cases[].openings[].cover[].seed`
changes; `expect.s_root` and every `ggm_nodes[].seed` are the GGM *tree* and
must stay byte-identical — a diff that touches them is wrong.

| case / opening | node | before | after |
| --- | --- | --- | --- |
| `unbalanced-n6` / `reveal-single-leaf-2` | `(3, 2)` | `73387341bf77a56d2ded9a012a3662bb0eb574c8cc071ebc77a9bd182334c16a` | `73387341bf77a56d2ded9a012a3662bb00000000000000000000000000000000` |
| `unbalanced-n6` / `reveal-1-3-two-cover-nodes` | `(3, 1)` | `9c24e08a2f6d02a94d489000e2d135894bc843ff3497fbb3e39b8b6820d9efe2` | `9c24e08a2f6d02a94d489000e2d1358900000000000000000000000000000000` |
| `unbalanced-n6` / `reveal-1-3-two-cover-nodes` | `(3, 2)` | as row 1 | as row 1 |
| `n1-root-is-leaf` / `reveal-full-0-1` | `(0, 0)` | `b723077eaee0fbb58430d9932cb173e5e3935b0fcab3203e51f53625a86ee9b5` | `b723077eaee0fbb58430d9932cb173e500000000000000000000000000000000` |

The other five openings (`reveal-4-6-node-over-unused-slots` `(1,1)`,
`reveal-full-0-6` `(0,0)` at `d = 3`, and all three `n5` openings) are at
`level < d` and **must not change**.

A changed vector digest is a format event and must read as one: the commit
that moves `FROZEN.sha256` names D83 in its message and touches nothing else.

### Must NOT change — checked, not assumed

| artifact | why it is safe |
| --- | --- |
| `testdata/vectors/v1/bundle/bundle.json` | every committed case's covers are at `level < d`: case 0/4/5/6 cover `(0,0)` on `n = 64`/`n = 34` files (`d = 6`); case 1's covers are levels 2–4 on `n = 30` (`d = 5`); case 2's is `(2,1)` on `n = 6` (`d = 3`). All unit boundaries are even. **Digest unchanged.** |
| `testdata/tamper/format/base/bundle.cbor` + all 20 fixtures | the base is bundle case `empty-anchor-unanchored`, whose only cover is `(0,0)` on a 64-byte file. **All 22 digests in `FIXTURES.json` unchanged.** |
| `testdata/vectors/v1/manifest/manifest.json`, `crypto/*`, `hkdf/*`, `sig-reject/*`, `report/*` | no GGM payload appears in any of them; `fine_root` is unaffected because B changes only what is *disclosed*, never what is *hashed* |
| every signature, `work_id`, `anchor_digest` | the bundle is not signed; D83 touches no manifest byte |
| `crates/antseal-core/proptest-regressions/content_properties.txt` | keep the persisted counterexample — it now proves the *rejection* instead of the malleability. Deleting it discards the evidence that produced the decision |

**This "must not change" table is a standing obligation, not a one-off.**
It holds only because no committed bundle fixture has an odd unit boundary.
The moment R36/R37 add one — which they should — that bundle's digests move
for D83 reasons and the mover must say so.

## 7. Tamper matrix

One new row, owned by G (G19's family), added to the Rust registry and
recorded in `testdata/tamper/MATRIX.json` under `project_added`:

```json
{
  "row_id": "fine-root-leaf-seed-tail-not-zero",
  "owner": "G",
  "why": "D83: a level == d cover payload's upper 16 bytes are never read as key material, so v1 fixes them at zero and checks them. Before D83 this mutation had NO observable effect — the row was unlandable as written, which is what forced the decision. The fixture flips one bit of byte 16..32 of a leaf-level cover entry in an odd-boundary reveal (n = 6, reveal {2}, node (3,2))."
}
```

The fixture's base must be a reveal that **has** a `level == d` node —
`n = 6`, reveal `{2}`, cover `(3, 2)` is G11's own normative KAT and the
shape the committed counterexample already uses.

A **second fixture** (same code, different site) covers §7.14 key 2 at
`n == 1`; per §4.1 it is a fixture, not a second row, separated by
`(code, layer)` exactly as F15's twenty format fixtures are.

## 8. What a bundle carrying the OLD shape does, and whether v1 can express the change

**A bundle whose `level == d` payload carries the true seed tail is
REJECTED** with `fine-root-leaf-seed-tail-not-zero`. There is no grace mode
and no version discriminant for it.

That is safe **only because it is happening now**: no real seal exists, Q14
has not run, `FROZEN.sha256` still reads `status pre-freeze`, and the only
old-shape artifacts in existence are the four hex strings in §6 and the
tests that generate them. After Q14 the same change would be a format-version
bump, because a receiver rejecting a bundle a sealer produced is exactly the
compatibility break MVP-SPEC.md line 123 forbids.

**The wire change needs no new code beyond the one minted here, and no
format-version bump**, because it changes neither a CBOR type, nor a length,
nor a key assignment, nor a reserved slot — only the admissible *value set* of
an existing 32-byte field. `format_version` stays 1. This is the property
that separates B from C: C would change a length, and a length is what F's
decoder branches on.

## 9. What the implementer must report back

Amend **this file** with a dated entry — do not bury findings in a task
report — if any of the following turns out differently:

1. **The precedence position.** If placing the check at step 7 makes
   `error_precedence_is_deterministic` awkward, or if a real proof can be
   simultaneously `LeafSeedTailNotZero` and something later in a way the
   order gets wrong, report the case before moving the step.
2. **The `n == 1` full-reveal path.** Confirm, with a test, that
   `verify_range` accepts a 1-byte full reveal whose single cover node is
   `(0,0)` carrying `salt_0 ‖ 0¹⁶` and that `rebuild_fine_root` yields the
   correct `fine_root` from it. If the branch order needs changing, say so.
3. **`CoverEntry`'s two-value shape.** If storing both `seed` and `payload`
   turns out to break a borrow or a `Debug` redaction test, report the actual
   shape adopted — the three constraints in §4.5 are the requirements, the
   struct layout is not.
4. **The "must not change" table (§6).** Re-run it. If any digest outside
   `fine-tree/fine-tree.json` moves, **stop** — either a fixture gained an
   odd boundary (fine, say so explicitly in the commit) or the change is
   wider than this decision authorises.
5. **The R call site.** If `VerifyError` cannot take a delegating arm without
   disturbing D27's fail-fast ordering or D29's pinned report bytes, report
   it rather than minting a second code.
6. **Any level-`d` case the incidence rule (§1 Fact 2) gets wrong.** It was
   verified exhaustively only to `n ≤ 24`; a proptest to `n ≤ 2^12` is cheap
   and should be added. A counterexample invalidates the sizing in §3 and
   must be recorded here.

---

# IMPLEMENTATION AMENDMENT — 2026-07-28 (G23)

Landed as decided: option B, one code, no length or tier change,
`format_version` still 1. §9 asks the implementer to amend **this file**
where the prose proved wrong; six places did.

## A1. §4.3 — `WrongCoverShape` has two precedence positions, not one

The numbered order reads as though the class occupied one slot. It does not:

- the **cover** half is `check_cover`'s (wrong count, wrong order, an address
  off the grid, a node over only unused slots) and precedes step 7;
- the **boundary** half — a missing, extra or misplaced sibling — is
  diagnosed during the fold, and therefore **follows** step 7.

So a proof carrying both a short boundary path and a dirty leaf tail reports
`LeafSeedTailNotZero`. The pre-existing `error_precedence_is_deterministic`
caught this on its `shape_and_root` case. The step was **not** moved: every
security-bearing classification still wins, and what is reordered is only the
residual structural mismatch this document itself describes as disclosing
nothing. Both halves are now pinned by that test.

## A2. §4.4 — `unwrap_or(0)` is wrong; skip `n == 0` instead

`depth_for_leaf_count(file.size).unwrap_or(0)` returns `None` only for
`size == 0`, an empty file with **no GGM grid at all**, where the rule is
vacuous. Defaulting to depth 0 makes the check fire there and reclassifies
the hand-built "fine tree declared on an empty file" bundle from row 8's
`fine-root-rebuild-mismatch` to this code — and makes *which* code it gets
depend on an irrelevant byte of a seed nothing derives from. Landed as
`if let Some(depth) = depth_for_leaf_count(file.size)`. Row 8 still rejects
that shape (`rebuild_fine_root` refuses empty content).

## A3. §4.5 — the prover side is not only `CoverEntry`

`full_reveal.s_root` is disclosed straight from the vault and never passes
through `cover_seeds`, so scoping the prover change to `CoverEntry` left the
`n == 1` case with **no** prover-side implementation of the rule — and R6's
fixture constructor duly emitted a raw `s_root`, which the new check then
rejected. Fixed by making the transformation public as
`content::fine_tree::canonical_leaf_level_payload` — the prover-side dual of
`check_leaf_level_payload` — and routing both disclosure paths through it.
**A real sealer must do the same** when it writes §7.14 key 2.

## A4. §6 — the "must NOT change" table missed the report vectors

`report/verification-reports.json` moved. Its row in the table
(`report/*` … "no GGM payload appears in any of them") is wrong: R9's report
corpus carries whole `.sealproof` bundles, and one of its 21 M0 shapes is a
**one-byte file** — exactly the `n == 1` case §2 adds to this decision's
scope. Exactly one field of one case moved,
`expect.cases[12].bundle_sha256`; `bundle_len`, `report` and `report_json`
are unchanged. This is inside what the decision authorises, so §9.4's "stop"
clause does not apply — the omission is in the table, not in the rule.

Everything else the table predicted held, verified rather than assumed:
`bundle/bundle.json` regenerates byte-for-byte, and all 22
`testdata/tamper/format` digests are unchanged.

**The verbatim hex in §6 reproduced exactly** — all four "before" strings
matched the committed vector and all four "after" strings matched the
regenerated one, in the three named openings and nowhere else.

## A5. §7 — the row id must carry a domain prefix

`MATRIX.json`'s `row_id` must equal the implemented `TamperRow.id` (the
completeness checker keys on it). G's two existing rows are `content-`
prefixed by the convention `tamper_rows_fine_tree` documents, and all 29
existing `project_added` ids carry a domain prefix, so the bare
`fine-root-leaf-seed-tail-not-zero` would have been the only unprefixed id in
the registry. Landed as **`content-fine-root-leaf-seed-tail-not-zero`**; the
`why` text is verbatim and no *code* string changed.

## A6. Count assertions and mirror shape

- §4.1 names two count assertions (both in `error.rs`). There is a **third**,
  `row_codes_are_distinct_across_the_whole_fine_tree_enum` in
  `tests/tamper_fine_tree.rs`, and a **fourth** on R's side,
  `DISTINCT_CODES` 85 → 86 in `verify/error.rs`. All four moved.
- §5.6's `resolved_decisions` entry is written as an object; every existing
  entry in `registry-v1.json` is a **string**. Landed as a string carrying
  the same facts, per §5.6's own "whatever the mirror's key names turn out to
  be, the 1:1 test is the acceptance criterion". Edits 2 and 3 landed as
  written.
- §5.3's new subsection is given as `####`; §5's other children are `###`,
  and at `####` it would nest under "Canonical slot for content-tree
  (boundary-path) nodes", which is a different subject. Landed as `###`.

---

# ORIGINAL RECORD (2026-07-28) — retained as the analysis that framed the decision

The material below is the record as written when G20 surfaced the finding. It
is preserved verbatim. Where it and the resolution above disagree — notably
its scoping of the finding to `cover_entry` alone, its "most partial reveals"
exposure estimate, and its recommendation of option C — **the resolution
governs**, and §1/§3 above say why.

## Context

A `.sealproof` range proof ships its GGM sub-cover as `(level, index,
seed)` triples with `seed` **exactly 32 bytes** (MVP-SPEC.md line 121's
length rule, enforced by `FineTreeError::BadSeedLength`).

A verifier turns each cover node's seed into the salts of the leaves that
node covers by descending `sub_depth = d − level` levels
(`fine_tree::verify::CoverSalts` → `ggm_walk::GgmWalker`). At the bottom,

> `salt_i = leaf_seed[..16]` (MVP-SPEC.md line 96)

When the cover node **is** a leaf — `level == d`, so `sub_depth == 0` —
there is no descent at all: the walker returns `seed[..16]` directly and
**bytes 16..32 of the disclosed seed are never read by anything**.

That case is not exotic. Every boundary-decomposed reveal ends in
deepest-single-leaf nodes: it is exactly G11's first normative KAT (`n = 6`,
reveal `{2}` → node `(3,2)`), and it occurs in most partial reveals.

## How it was found

G20's `mutated_proofs_never_panic_and_never_verify` asserted the natural
property "any change to the wire form must be rejected", and proptest
produced a counterexample at 1024 cases (persisted at
`crates/antseal-core/proptest-regressions/content_properties.txt`, shrunk
to `n = 101`, a single-leaf cover node `(7, 73)`, one bit flipped in the
seed's upper half). The proof still verified — correctly, by the rule
above.

## What is and is not at stake

**Not a soundness or confidentiality break.** The inert bytes convey
nothing about unrevealed leaves (they are the tail of a seed whose whole
subtree is a single revealed leaf), and no substitution of them can make a
different byte or a different `fine_root` verify. `salt_i` is unchanged, so
the leaf hash, the fold, and the root are unchanged.

**It is a canonical-form / malleability issue**, and antseal cares about
canonical forms:

1. **Bundle uniqueness.** Two byte-distinct `.sealproof` files can carry
   the same proof and both verify. Anything that treats bundle bytes as
   identifying — a content address, a de-duplication key, a "same bundle"
   comparison, a digest quoted in a report — inherits 2^128 equally valid
   spellings per leaf-level cover node.
2. **Tamper-matrix completeness.** The project's discipline is "every
   mutation fails with a distinct error" (working principles;
   `testdata/tamper/`). This mutation class fails with *no* error, so a
   future `bundle-cover-seed-bitflip` row would be unlandable as written
   and must be scoped to the significant bytes.
3. **Wire cost.** 16 wasted bytes per leaf-level cover node, on a format
   that is otherwise carefully minimal.

## Options

**A. Accept and document.** Record in `docs/format/registry-v1.md` §5 that
the upper 16 bytes of a `level == d` cover seed are not covered by
verification, and that bundle bytes are therefore not a canonical
identifier for a proof. Cheapest; leaves the malleability in the format
forever (line 123 makes v1 verifiable forever).

**B. Canonical padding.** Keep 32 bytes on the wire but require the
prover to emit the true derived seed and the verifier to reject a
`level == d` cover node whose tail is not… — the verifier *cannot* check
it against the truth (it has no way to derive the real seed), so the only
checkable rule is a **fixed** tail, e.g. all zeros. That restores
uniqueness and is a one-line verifier check, but it makes the wire value
no longer "the seed" for the leaf case, which is a semantic wrinkle worth
weighing.

**C. Shorten the wire form.** Encode a `level == d` cover node's payload
as **16 bytes** — which is what it actually is, a `salt_i` — and keep 32
bytes for every `level < d` node. Removes the malleability entirely,
shrinks bundles, and matches the semantics exactly. Costs a
length-by-level rule in F's decoder (`BadSeedLength` becomes
level-dependent) and a registry §5 change.

## Recommendation (not a decision)

**C**, with **A** as the fallback if F judges the level-dependent length
rule too sharp an edge for a strict decoder. C is the only option under
which the wire value and its meaning coincide, and it is the one that
makes the malleability *unrepresentable* rather than merely illegal.

## Consequences either way

- Whichever lands, `docs/format/registry-v1.md` §5 gains an explicit
  statement of the leaf-level cover node's payload length and its
  significant bytes; D9's node-address contract is untouched.
- G20's property is currently written against the **present** behaviour: it
  compares an *effective* projection of the wire (a `level == d` cover
  node's first 16 bytes only) and asserts that a change inside the inert
  tail still verifies. Resolving this as B or C flips that assertion, which
  is intentional — the test is the executable statement of whichever rule
  is chosen, and the committed regression case is the counterexample that
  forced the question.
- If B or C lands, R7/G19 gain a real tamper row for the previously-inert
  bytes.

## Status of any implementation

**None.** Only the test and this record; no format constant, no code path,
no length rule has been minted (project rule: an unresolved decision that
would freeze a format rule is registered, not implemented).

> *(End of the original record. Superseded 2026-07-28 by the RESOLVED
> section at the top of this file: option **B**, the canonical zero tail —
> one new code `fine-root-leaf-seed-tail-not-zero`, no length change, no
> tier change, implemented by **G23** with a second call site in R4.)*
