# D10 — Parser resource caps (frozen constants)

- **Status: RESOLVED — 19 frozen caps, 18 new error codes, one universal
  clamp rule. Every cap is enforced inside verify stage 1 (`decode`), so a
  hostile bundle dies before any AEAD, hash, or signature work.**
- **Date: 2026-07-28** (planning; F11 implements, F15 encodes two of the
  caps in fixtures, F4 records the rows)

## Context

MVP-SPEC.md line 153 requires "hard caps on bundle size/unit count/depth/
allocations" and line 187 names hostile bundles — adversary-authored CBOR
parsed in a counterparty's browser — as a standing risk. tasks/F.md F11
turns that into "define frozen cap constants in one module"; F15's
oversized/over-deep tamper fixtures encode the numbers, and
`testdata/tamper/MATRIX.json` already carries a **pending** row
(`oversized-or-deep-cbor` → `oversized`) with a deliberately null expected
code, waiting on this decision.

The values are format-permanent for the reason recorded in §11: a receiver
that rejects a bundle a sealer produced is a compatibility break, and
line 123 makes every released format version verifiable by every future
release. So the numbers freeze at Q14 alongside the rest of format v1.

Three facts from the real code shape everything below:

1. `codec::decode` is **zero-copy**. `bytes()`/`str()` borrow from the
   input slice, and `check_payload_bounds` already refuses a claimed
   string length larger than the remaining input (`decode.rs`, precedence
   step 6). So no `bstr`/`tstr` length can drive an allocation today. The
   allocation surface is **arrays**, and only arrays.
2. F9 left a standing marker: `bundle::schema::decode_section` carries no
   `Vec::with_capacity` and names F11 as its replacement. The same
   deliberate omission exists at five other sites (`manifest/body.rs`
   units / sig_policy / files, `bundle/schema.rs` intermediates /
   tx_hashes / cover / paths, `manifest/sigmap.rs` entries).
3. The typed schema decoders recurse a **schema-fixed** number of levels.
   Depth is therefore not input-driven in the typed path — which has a
   consequence for F15 that §7 records, because it contradicts the task
   description in tasks/F.md.

## 1. The frozen cap table

All values are `u64` (depth excepted, §8). Names are the exact constant
identifiers F11 must use.

| # | constant | value | applies to | error code |
| --- | --- | --- | --- | --- |
| 1 | `MAX_BUNDLE_BYTES` | `268_435_456` (256 MiB) | layer-1 `.sealproof` input slice | `bundle-too-large` |
| 2 | `MAX_MANIFEST_BYTES` | `16_777_216` (16 MiB) | layer-2 input = bundle key 1 `bstr` contents (manifest envelope bytes) | `manifest-too-large` |
| 3 | `MAX_CBOR_DEPTH` | `8` (`u16`) | enclosing containers of any item, generic walker | `cbor-nesting-too-deep` *(existing)* |
| 4 | `MAX_FILE_COUNT` | `16_384` (2¹⁴) | body key 7 `files` array | `manifest-too-many-files` |
| 5 | `MAX_UNIT_COUNT` | `65_536` (2¹⁶) | **work-global** running budget over every file's key 6 `units` array | `manifest-too-many-units` |
| 6 | `MAX_OTS_ANCHOR_COUNT` | `256` | bundle key 3 | `bundle-too-many-ots-anchors` |
| 7 | `MAX_TSA_ANCHOR_COUNT` | `256` | bundle key 4 | `bundle-too-many-tsa-anchors` |
| 8 | `MAX_INTERMEDIATE_COUNT` | `16` | TSA anchor key 2 `intermediates` | `bundle-too-many-intermediates` |
| 9 | `MAX_TX_HASH_COUNT` | `256` | receipt key 0 `tx_hashes` | `bundle-too-many-tx-hashes` |
| 10 | `MAX_COVERED_REVEAL_COUNT` | `= MAX_UNIT_COUNT` | bundle key 6 | `bundle-too-many-covered-reveals` |
| 11 | `MAX_NONCOVERED_REVEAL_COUNT` | `= MAX_UNIT_COUNT` | bundle key 7 | `bundle-too-many-noncovered-reveals` |
| 12 | `MAX_COVER_ENTRIES` | `256` | covered reveal key 3 `cover` | `bundle-too-many-cover-entries` |
| 13 | `MAX_PATH_NODES` | `256` | covered reveal key 4 `paths` | `bundle-too-many-path-nodes` |
| 14 | `MAX_TOUCHED_FILE_COUNT` | `= MAX_FILE_COUNT` | bundle key 8 | `bundle-too-many-touched-files` |
| 15 | `MAX_FULL_REVEAL_COUNT` | `= MAX_FILE_COUNT` | bundle key 9 | `bundle-too-many-full-reveals` |
| 16 | `MAX_OTS_BYTES` | `1_048_576` (1 MiB) | OTS anchor key 1 `ots` | `bundle-ots-too-large` |
| 17 | `MAX_TSA_TOKEN_BYTES` | `1_048_576` (1 MiB) | TSA anchor key 1 `token` | `bundle-tsa-token-too-large` |
| 18 | `MAX_CERT_BYTES` | `65_536` (64 KiB) | each `intermediates` element | `bundle-cert-too-large` |
| 19 | `MAX_RECEIPT_PAYLOAD_BYTES` | `16_777_216` (16 MiB) | receipt key 2 `payload` | `bundle-receipt-payload-too-large` |

Rows 10/11 and 14/15 are **separately named constants defined as the
manifest-side value** (`pub const MAX_COVERED_REVEAL_COUNT: u64 =
MAX_UNIT_COUNT;`). Naming them separately is not decoration: D78 forbids
the bundle schema layer from consulting the manifest, so the bundle's
bound on "how many units may be revealed" has to be a bundle-side
constant. Defining it *as* the manifest constant is what keeps the two
from drifting apart.

**The caps are independent upper bounds, not a partition of a budget.**
`MAX_OTS_ANCHOR_COUNT × MAX_OTS_BYTES` alone exceeds `MAX_BUNDLE_BYTES`;
that combination is simply unreachable, and `MAX_BUNDLE_BYTES` is the
single global backstop that binds first. Each per-item cap still earns its
keep because it fires **cheaply and specifically**: a 2 MiB `.ots` inside a
3 MiB bundle is rejected as `bundle-ots-too-large`, not as a generic
size failure and not after the whole bundle has been walked.

## 2. Sizing math

Assumptions are stated per row. Wire sizes are worst-case
shortest-form CBOR: a `bstr(32)` costs 33 B, a `bstr(24)` costs 25 B, a
map/array head 1–3 B, a `uint` 1–9 B depending on magnitude.

### `MAX_UNIT_COUNT = 65_536` and `MAX_FILE_COUNT = 16_384`

*Assumption*: a work is a human-curated set of files, and units are reveal
granularity (default one per file; `--split blank-lines` splits text on
paragraph boundaries).

Legitimate maxima: a 1 000-page book splits into roughly 20 000
paragraphs; 65 536 admits three such books, or 16 384 files at four units
each. 16 384 files covers a full source tree or a dataset directory with
wide margin. A work larger than that is a filesystem archive, which is not
what "seal your work" targets.

Manifest cost at cap. Worst-case unit entry (all seven keys, offsets in a
256 MiB file, `unit_id < 2¹⁶`):

```
map head 1 + unit_id 4 + kind 2 + range 12 + true_length 6
         + unit_commit 34 + nonce 26 + address 34        = 119 B  (round 120)
```

Worst-case file entry, excluding its units:

```
map head 1 + path_commit 34 + raw_commit 34 + canon_commit 34
         + size 6 + descriptor 24 + fine_root 34 + units head 4 = 171 B (round 175)
```

At both caps simultaneously: `65 536 × 120 + 16 384 × 175 ≈ 7.5 + 2.7 =
10.2 MiB`, plus ~3.4 KB of body header (`pubkeys` carries a 1952-B ML-DSA
key; `signatures` a 3309-B ML-DSA signature). **Both count caps are
therefore reachable inside `MAX_MANIFEST_BYTES`** — neither is vacuous,
and each has a legal at-cap input, which F11's "at-cap passes" test needs.

### `MAX_MANIFEST_BYTES = 16 MiB`

*Assumption*: the manifest must admit both count caps at once (above:
10.2 MiB) with headroom for title/app-version text and future v1.x
additive fields. 16 MiB is 1.57×. It also bounds the SHA-256 work behind
`work_id` and `anchor_digest` (~16 MiB hashed, twice) and the size of the
encrypted manifest blob every seal uploads.

The **body** gets no separate constant: it is a `bstr` inside the
envelope, so `len(body) < len(envelope) ≤ MAX_MANIFEST_BYTES` by
construction. A second constant would buy a tighter bound nobody needs and
a permanent code (D30 §3) for a check the envelope cap already makes.

### `MAX_BUNDLE_BYTES = 256 MiB`

*Assumption*: the binding case is a **whole-work reveal**, where every
unit's ciphertext is embedded.

The spec's own worked case is `n = 10⁸` (line 96) — a ~95.4 MiB file. Its
worst reveal shape is *text, split, with a raw mirror*, because a text
file's raw bytes ship as an extra unit (line 92) and padding overhead
scales with unit count (`padded_length = ⌈(true_length+1)/256⌉·256`, plus
a 16-B tag per unit):

```
canonical ciphertext            95.4 MiB
per-unit padding + tag          65 536 × 271 B      = 17.0 MiB
raw-mirror ciphertext           95.4 MiB
manifest (units at cap)                             ≈ 10.2 MiB
covers/paths, anchors, entries                      <  1   MiB
                                                    ─────────
                                                    ≈ 219 MiB
```

219 MiB < 256 MiB, ~14 % headroom. That the *padding* term is 17 MiB — as
large as the whole manifest — is the non-obvious interaction; it is why
the cap is 256 MiB and not 128 MiB.

**What the cap implies for the largest supportable work.** Sealing is not
capped by D10 at all; only *bundles* are. Under `MAX_BUNDLE_BYTES`:

- largest **fully revealable** binary work ≈ 239 MiB of content;
- largest **fully revealable** text work ≈ 119 MiB (content appears twice:
  canonical + raw mirror);
- a **partial** reveal of an arbitrarily large work is always
  representable, bounded only by the bytes actually disclosed.

wasm32 sanity: a browser verifier holds the input (≤256 MiB) plus
decrypted plaintexts plus the recomputed canonical rendition for the
raw-mirror check — peak on the order of 0.8–1.0 GiB, inside a 32-bit
4 GiB address space by ~4×. That is a desktop-browser figure; the M3 page
should warn before attempting a bundle that large rather than OOM. A
practical page-side warning threshold is a **UX** matter, not a format
one — see §11 on why there is no local override.

### `MAX_COVER_ENTRIES = 256` and `MAX_PATH_NODES = 256`

*Assumption*: derived from the **type width of the manifest's `size`
field**, not from a guess.

A file's leaf count `n` is a `uint`, so `d = ⌈log₂ n⌉ ≤ 64`. Spec line 96
bounds a leaf-exact minimal GGM cover at `2·⌈log₂ n⌉` seeds; the boundary
Merkle paths are at most one path of `d` nodes per range boundary, i.e.
`2·d`. So for **any representable file**:

```
cover ≤ 2·64 = 128        paths ≤ 2·64 = 128
```

256 is exactly 2× the theoretical maximum for any file `size` the format
can express. It cannot be exceeded by an honest cover, ever, for any
future file size — which is the property that makes it safe to freeze.

The spec's worked case: `⌈log₂ 10⁸⌉ = 27` (2²⁶ = 67 108 864 < 10⁸ ≤ 2²⁷),
so `2·27 = 54` seeds ≈ 1.7 KB of seed material, matching line 96. On the
wire a `cover_entry` is `[level, index, bstr(32)]` (D9), costing
`1 + 1 + 5 + 33 = 40 B` at that scale, so 54 entries ≈ 2.1 KB per revealed
unit. At cap: `256 × 44 = 11 KB`. Margin over the spec's own case: **4.7×**.

### `MAX_OTS_ANCHOR_COUNT = MAX_TSA_ANCHOR_COUNT = 256`

*Assumption*: the minimum-anchor policy wants ≥2 OTS calendars and ≥2 TSA
tokens (spec lines 108–109); an honest bundle today has single digits of
each. 256 admits two decades of monthly re-anchoring (the re-anchoring
*service* is parked to v1.1, but verifier-side expiry semantics are v1, so
anchor sets are expected to grow, not to be fixed at seal time).

### `MAX_INTERMEDIATE_COUNT = 16`

*Assumption*: real TSA chains are leaf + 1–3 intermediates; cross-certified
chains reach 5–6. 16 is ~4× the realistic maximum.

**This is the weakest-evidence cap in the table.** Every other row is
derived from a type width, a spec sizing statement, or an arithmetic
worst case; this one is derived from what public CAs do. A25's recorded
FreeTSA (ECDSA P-384) and DigiCert fixtures are the first real evidence
the project will have — **A must confirm 16 against them before Q14**, when
raising it is still free. Recorded as an open action below.

### `MAX_TX_HASH_COUNT = 256`

*Assumption*: one batch-payment tx per seal (spec's `pay` is "one
Merkle-batch EVM tx"), with room for a batch split across many txs.
`256 × 33 B = 8.4 KB`, negligible.

### Opaque artifact byte caps (16–19)

*Assumption*: all four are ≥30× the largest real artifact, because
guessing high is free and guessing low is a compatibility break.

| field | real size | cap | margin |
| --- | --- | --- | --- |
| `.ots` | ~0.5 KB pending, 1–4 KB upgraded | 1 MiB | ~250× |
| TSA DER token | 2–10 KB with certs | 1 MiB | ~100× |
| X.509 intermediate | 1–2 KB | 64 KiB | ~32× |
| receipt `payload` | quote preimages + `proof_bytes`, ~256 chunks × ~1 KB | 16 MiB | ~60× |

These are **byte-length caps on v1 wire fields**, which is why F11 owns
them even though the artifacts' *internals* are A's at M2 (registry §7.8,
§7.9; MVP-SPEC.md line 153 puts DER/`.ots` limits in M2). A byte-length
cap on a `bstr` field decides whether a given `.sealproof` is valid v1, so
it must freeze with format v1. The internal structural limits A5/A11 will
add — max ops, max attestations, max signed attributes, DER nesting — are
a different question, raised as **D83** below.

### `MAX_CBOR_DEPTH = 8`

*Assumption*: registry §7.6.3 already computed the v1 structural maximum —
bundle chain 5 containers, manifest chain 6 (`manifest map → files array →
file entry map → units array → unit entry map → range array`), and the two
**do not nest** because layer 2 starts a fresh decoder over the `bstr`
contents. So the requirement is `≥ 6`.

8 = 6 + 2, leaving room for one v1.x additive field nested one level
deeper without permitting absurd nesting. It replaces F3's provisional
`MAX_NESTING_DEPTH = 64`, whose doc comment already names F11 as the task
that may "re-home or retune this value, keyed by the same
`DecodeError::NestingTooDeep` error".

Semantics, stated so F11 cannot land an off-by-one: **an item with
`MAX_CBOR_DEPTH` enclosing containers is accepted; one with
`MAX_CBOR_DEPTH + 1` is rejected.** That is exactly `walk_item`'s existing
`if depth > MAX_..` guard with `depth` = number of enclosing containers, so
no logic changes — only the constant.

## 3. Recorded non-caps

Each of these is an unbounded-looking list that gets **no cap and no new
code**, with the reason. Minting a code for a check that cannot fire is
the failure mode D75's record already warned about.

| list | why no cap |
| --- | --- |
| body key 6 `sig_policy` | duplicate-free **and** registered-only are already enforced (`manifest-duplicate-alg-sig-policy`, `manifest-unregistered-alg-sig-policy`). The registered universe is `sig_alg 0..=15` (registry §6.2), so length ≤ 16 forever and ≤ 2 in v1; element 3 of a hostile array fails on an existing code before any cap could. |
| body key 5 `pubkeys`, envelope key 1 `signatures` | maps with strictly-ascending `uint` keys drawn from the same 16-value universe: ≤16 entries **by map semantics**, and unregistered-alg fires first. |
| unit key 2 `range`, `cover_entry`, `path_node` | fixed arity, already checked (`manifest-wrong-range-arity`, `bundle-wrong-cover-entry-arity`, `bundle-wrong-path-node-arity`). |
| `title`, `app_version`, touched-file `path`, TSA `source` | free-form `tstr`s with no natural maximum. Transitively bounded by caps 1–2. A per-field byte cap would mint a permanent code and would have to answer "how long is a legitimate title?" — a question with no principled answer, and the wrong side to be wrong on. |
| revealed-unit `ciphertext` | already shape-checked (`len ≡ 16 mod 256`, `len ≥ 272`). An upper bound would have to be ≈ `MAX_BUNDLE_BYTES` anyway, since a whole-file unit's ciphertext is the file: a redundant cap dressed as a policy on work size. |

**The clamp rule still applies to every one of these** (§4). A cap and a
clamp are different mechanisms: `sig_policy` needs no cap, but it must
still never call `Vec::with_capacity(claimed)`.

## 4. The clamp rule

> **Every pre-allocation is clamped to `min(claimed_length,
> remaining_input)`.** No exceptions, including lists with no cap.

Justification: every element of a definite-length array costs **at least
one wire byte**, so the count of bytes remaining after the array head is
an upper bound on the element count. The clamp turns "a length header can
drive an allocation" into "a length header can drive an allocation no
larger than the attacker's own input", which is the property F17's fuzz
invariant ("no allocation beyond the F11 budget") needs to be statable.

Frozen order at every array head — this fixes tamper-row precedence, so
F15's fixtures are deterministic:

1. `d.array()` — head canonicality (a non-shortest length head therefore
   beats every cap code with `cbor-non-shortest-length`);
2. **cap check on the claimed count**, before a single element is read.
   Cheap by construction: the rejecting fixture is an array head and
   nothing else;
3. `Vec::with_capacity(clamped_capacity(claimed, d.remaining()))` — by
   this point `claimed ≤ cap`, so the allocation is bounded by
   `min(cap, remaining_input)`;
4. decode elements.

Where it applies, exhaustively (the six sites F9 left marked plus the two
already-safe classes):

| site | list |
| --- | --- |
| `bundle::schema::decode_section` | ots/tsa anchors, covered/noncovered reveals, touched files, full reveals |
| `bundle::schema::TsaAnchor::decode` | `intermediates` |
| `bundle::schema::ReceiptRecord::decode` | `tx_hashes` |
| `bundle::schema::CoveredReveal::decode` | `cover`, `paths` |
| `manifest::body::FileEntry::decode` | `units` |
| `manifest::body::ManifestBodyV1::decode` | `sig_policy`, `files` |
| `manifest::sigmap::SigAlgMap::decode` | map entries |

Two classes need **no** change and F11 must not "fix" them:

- **`bstr`/`tstr` payloads** — `check_payload_bounds` already refuses a
  claimed length exceeding the remaining input, in `u64`, before any
  `usize` conversion (`decode.rs` step 6). Reads borrow; the only copies
  (`title.to_owned()`, `OpaqueBytes::from_vec`) copy exactly the validated
  borrowed length, which *is* the clamp.
- **Element loops** — `for _ in 0..count { list.push(..) }` already
  terminates on truncation, because each element consumes ≥1 byte or
  errors. The clamp bounds the *capacity hint*, not the loop.

## 5. Where caps run relative to crypto

`verify::pipeline`'s frozen stage order is `decode → structural → units →
files → sigs → anchors`, and stage 1 is exactly `SealProof::decode(input)`.
Every cap in this decision fires inside that call. **F11 adds no stage and
changes no stage boundary**; it tightens stage 1.

The consequence is the property line 187 asks for: the first crypto in the
pipeline is stage 3's AEAD decrypt and GGM/Merkle work, and stage 5's
signature verification; both are unreachable while any cap is violated.
`work_id`/`anchor_digest` hashing likewise sits behind stage 1.

Ordering inside stage 1, frozen:

| order | check | cost | code |
| --- | --- | --- | --- |
| 1 | `input.len() > MAX_BUNDLE_BYTES` — the **first statement** of `BundleV1::decode`, before the decoder is constructed | O(1) | `bundle-too-large` |
| 2 | layer-1 CBOR canonicality + bundle schema, with count/artifact caps at each head | O(input) | `cbor-*`, `bundle-*` |
| 3 | `manifest_bytes().len() > MAX_MANIFEST_BYTES` — the **first statement** of `Manifest::decode` | O(1) | `manifest-too-large` |
| 4 | layer-2/3 CBOR canonicality + manifest schema, with the unit/file caps | O(manifest) | `cbor-*`, `manifest-*` |

So an oversized bundle that *also* has a bad signature reports
`bundle-too-large`, consistent with R5's "earlier stage wins" tests; and an
oversized bundle that also has non-canonical CBOR reports
`bundle-too-large`, because the size check precedes the walk. Both are
deliberate and must be pinned by F11 tests.

`SealProof::decode` already runs layer 1 to completion before layer 2
starts, so no reordering is needed to get this — it falls out of D78.

## 6. Finding: the over-deep row cannot be a pipeline row

tasks/F.md F15 lists "over-deep CBOR" as a tamper fixture alongside
oversized. **Over-deep is structurally unreachable through
`SealProof::decode`**, and F11/F15 must handle it as a direct-call row.

Reason: every field in the v1 schema has a fixed type, so the typed
decoders never read a *generic* item. Nesting an array where the schema
expects a `uint` yields `cbor-unexpected-type` at the first level, not
`cbor-nesting-too-deep` at the ninth. There is no schema position that
admits arbitrary nesting, so no input can walk the typed path deeper than
the registry's 6. The depth guard lives — and can only live — in
`codec::decode::walk_item`, i.e. behind the public `check_canonical`
entry point.

This is the same class of finding the error-code contract already records
for R3's `wrong-length-ggm-covering-seed` ("not reachable through
`verify_bundle` … should either bind the `bundle-` code or be a direct-call
row"). **Decision: F15's over-deep fixture is a direct-call row on
`check_canonical`**, keeping `cbor-nesting-too-deep` a `cbor-` code owned by
the walker. `MATRIX.json`'s pending `deep` case already expects that code,
so nothing in the registry changes — only how the row is executed.

The `oversized` case is unaffected: `bundle-too-large` fires in
`BundleV1::decode` and *is* pipeline-reachable. Its pending row currently
carries `row_id: "cbor-oversized"` and `expected: null`; F15 binds
`expected: "bundle-too-large"`. The row **id** may keep its `cbor-`
spelling or be renamed to `bundle-oversized` — nothing has bound to a
pending row id, and ids and codes are separate namespaces — but the code
is `bundle-too-large`, in the `bundle-` family, because the mutation is
detected on the bundle's own bytes (D78).

## 7. Error taxonomy — 18 new codes

Checked against `docs/testing/error-code-contract.md` §2 (domain prefixes)
and against every code already minted, by sweeping every `=> "kebab-case"`
return in `crates/antseal-core/src/` — 215 distinct literals, a *superset*
of the code universe since the same pattern also returns enum display
names and HKDF labels — plus every `expected` in
`testdata/tamper/MATRIX.json`. **Nothing in that superset contains
`-too-large`, `-too-many-`, or `-oversized`**; the only near neighbours are
`bundle-ciphertext-too-short`, `cbor-nesting-too-deep`, and
`content-node-address-level-too-deep`, none of which collides. All 18 are
new, therefore **format-permanent, therefore they must land before Q14**
(contract §3: before Q14 a code may still be corrected as a recorded
change; after Q14 the code set is permanent).

Prefix assignment follows §2 without exception. F11 spans three surfaces
and the codes split accordingly rather than pooling under one family:

- **`bundle-`** (14) — every cap detected on the bundle's own bytes.
- **`manifest-`** (3) — every cap detected on the embedded manifest's
  bytes. D78 makes this split normative, not stylistic: a `manifest-` code
  always means "the embedded manifest is malformed".
- **`cbor-`** (0 new) — depth reuses the existing
  `cbor-nesting-too-deep`.

Codes are **variant-level with a kind discriminator**, the pattern §1 of
the contract prescribes and F8 already used for its four
`bundle-unsorted-*` codes over the same four lists:

```
bundle-too-large                        BundleError::InputTooLarge
bundle-too-many-ots-anchors             BundleError::ListTooLong { list: OtsAnchors, .. }
bundle-too-many-tsa-anchors                                        TsaAnchors
bundle-too-many-intermediates                                      Intermediates
bundle-too-many-tx-hashes                                          TxHashes
bundle-too-many-covered-reveals                                    CoveredReveals
bundle-too-many-noncovered-reveals                                 NonCoveredReveals
bundle-too-many-cover-entries                                      Cover
bundle-too-many-path-nodes                                         Paths
bundle-too-many-touched-files                                      TouchedFiles
bundle-too-many-full-reveals                                       FullReveals
bundle-ots-too-large                    BundleError::ArtifactTooLarge { field: Ots, .. }
bundle-tsa-token-too-large                                                  TsaToken
bundle-cert-too-large                                                       Certificate
bundle-receipt-payload-too-large                                            ReceiptPayload
manifest-too-large                      ManifestError::InputTooLarge
manifest-too-many-files                 ManifestError::ListTooLong { list: Files, .. }
manifest-too-many-units                                              Units
```

Error payloads carry `len`/`claimed` and `cap` as `u64` — lengths and
constants, never input byte content, per `decode.rs`'s module policy and
matching the existing `got`/`expected` payloads on `bundle-wrong-length-*`.
Project rule 6 is satisfied by construction: no salt, key, or plaintext
can reach a cap error.

R's `VerifyError::Decode` wrapper surfaces all 18 unchanged (contract §2),
so R's universe grows by 18 without R minting anything.

## 8. wasm32 parity

The repo's existing convention is stated in `codec.rs`: *"output and error
values are platform-independent (positions are `u64`, never `usize`) so
native and wasm32 behavior bit-match."* D10 extends it verbatim to caps.

Rules F11 must follow:

1. **Every byte/count cap is `u64`.** Comparisons happen in `u64`. Widen
   `input.len()` **up** (`as u64`, lossless on 32- and 64-bit); never
   narrow a cap **down** to `usize` for comparison — on wasm32 that would
   silently truncate a cap above `u32::MAX` and make a bundle valid on one
   target and invalid on the other.
2. **Every cap is ≤ `u32::MAX`.** The largest is `MAX_BUNDLE_BYTES` =
   2²⁸, sixteen-fold under 2³². This is what guarantees each cap is
   *reachable* on wasm32 as well as native, so at-cap and cap+1 tests mean
   the same thing on both.
3. **The one `usize` conversion is the clamped capacity**, and it is
   lossless by an invariant worth writing into the function's docs:
   `clamped_capacity(claimed, remaining) ≤ remaining ≤ input.len() ≤
   usize::MAX`.
4. **`MAX_CBOR_DEPTH` is `u16`** — the deliberate exception. Depth is a
   container count compared against `walk_item`'s existing `u16` counter;
   it never touches a wire length or a `usize`, so the widening rule does
   not apply and a narrow type makes the confusion impossible.
5. F11's cap tests run under Q's wasm32 lane (`scripts/wasm-test-runner.mjs`)
   and must produce byte-identical error codes there.

## 9. Exact Rust surface for F11

Frozen. F11 has no design freedom on names, module path, or shapes below.

**Module**: `crates/antseal-core/src/codec/caps.rs`, declared `pub mod
caps;` in `codec.rs` and re-exported alongside the existing `pub use
decode::{…}`. One module for all 19 constants, per F11's own wording.
`decode::MAX_NESTING_DEPTH` is **removed** (not aliased — two names for one
value is worse than a rename in a pre-1.0 internal crate) and every use
becomes `caps::MAX_CBOR_DEPTH`; `codec.rs`'s `pub use` list is updated.

```rust
// codec/caps.rs — frozen v1 parser resource caps (decision D10).
pub const MAX_BUNDLE_BYTES: u64 = 268_435_456;
pub const MAX_MANIFEST_BYTES: u64 = 16_777_216;
pub const MAX_CBOR_DEPTH: u16 = 8;
pub const MAX_FILE_COUNT: u64 = 16_384;
pub const MAX_UNIT_COUNT: u64 = 65_536;
pub const MAX_OTS_ANCHOR_COUNT: u64 = 256;
pub const MAX_TSA_ANCHOR_COUNT: u64 = 256;
pub const MAX_INTERMEDIATE_COUNT: u64 = 16;
pub const MAX_TX_HASH_COUNT: u64 = 256;
pub const MAX_COVERED_REVEAL_COUNT: u64 = MAX_UNIT_COUNT;
pub const MAX_NONCOVERED_REVEAL_COUNT: u64 = MAX_UNIT_COUNT;
pub const MAX_COVER_ENTRIES: u64 = 256;
pub const MAX_PATH_NODES: u64 = 256;
pub const MAX_TOUCHED_FILE_COUNT: u64 = MAX_FILE_COUNT;
pub const MAX_FULL_REVEAL_COUNT: u64 = MAX_FILE_COUNT;
pub const MAX_OTS_BYTES: u64 = 1_048_576;
pub const MAX_TSA_TOKEN_BYTES: u64 = 1_048_576;
pub const MAX_CERT_BYTES: u64 = 65_536;
pub const MAX_RECEIPT_PAYLOAD_BYTES: u64 = 16_777_216;

/// Clamp a pre-allocation to what the remaining input could hold.
///
/// Every element of a definite-length array costs at least one wire byte,
/// so `remaining` bounds the element count. The result is `<= remaining
/// <= input.len() <= usize::MAX`, which is why the `as usize` is lossless
/// on wasm32 as well as native.
#[must_use]
pub fn clamped_capacity(claimed: u64, remaining: u64) -> usize;

/// Work-global decode budget threaded through the manifest body decode.
///
/// Not a wire field. It exists so that "one file claiming 2^20 units" and
/// "2^20 files claiming one unit each" hit the same cap with the same code.
#[derive(Debug)]
pub struct DecodeBudget { units_remaining: u64 }

impl DecodeBudget {
    #[must_use] pub const fn new() -> Self;
    /// Charge `claimed` units against the work-global budget.
    /// `Err(())` when `claimed` exceeds what is left; the caller raises
    /// `ManifestError::ListTooLong { list: Units, claimed, cap: MAX_UNIT_COUNT }`.
    pub fn take_units(&mut self, claimed: u64) -> Result<(), ()>;
}
```

**One new decoder accessor** (`codec/decode.rs`):

```rust
impl<'b> CanonicalDecoder<'b> {
    /// Bytes remaining after the cursor. `u64`, never `usize`, so the
    /// clamp behaves identically on wasm32 and native.
    #[must_use]
    pub fn remaining(&self) -> u64;
}
```

**Error additions.** `bundle/error.rs`:

```rust
pub enum BundleListKind {
    OtsAnchors, TsaAnchors, Intermediates, TxHashes,
    CoveredReveals, NonCoveredReveals, Cover, Paths,
    TouchedFiles, FullReveals,
}
impl BundleListKind { pub const fn cap(self) -> u64; }   // the table, next to the codes

pub enum OpaqueField { Ots, TsaToken, Certificate, ReceiptPayload }
impl OpaqueField { pub const fn cap(self) -> u64; }

BundleError::InputTooLarge   { len: u64, cap: u64 }
BundleError::ListTooLong     { list: BundleListKind, claimed: u64, cap: u64 }
BundleError::ArtifactTooLarge{ field: OpaqueField, len: u64, cap: u64 }
```

`manifest/error.rs`:

```rust
pub enum ManifestListKind { Files, Units }
impl ManifestListKind { pub const fn cap(self) -> u64; }

ManifestError::InputTooLarge { len: u64, cap: u64 }
ManifestError::ListTooLong   { list: ManifestListKind, claimed: u64, cap: u64 }
```

Both enums extend their domain's existing `code()` match and their
layer-1 pairwise-distinctness meta-test exemplar lists.

**The section reader** (`bundle/schema.rs`), replacing F9's marked
`decode_section` — the order is §4's, and it is the shape every other
allocation site copies:

```rust
fn decode_section<T>(
    d: &mut CanonicalDecoder<'_>,
    list: BundleListKind,
    mut decode_one: impl FnMut(&mut CanonicalDecoder<'_>) -> Result<T, BundleError>,
) -> Result<Vec<T>, BundleError> {
    let claimed = d.array().map_err(cbor)?;              // 1. head canonicality
    let cap = list.cap();
    if claimed > cap {                                   // 2. cap, before any element
        return Err(BundleError::ListTooLong { list, claimed, cap });
    }
    let mut out = Vec::with_capacity(clamped_capacity(claimed, d.remaining()));  // 3. clamp
    for _ in 0..claimed {                                // 4. elements
        out.push(decode_one(d)?);
    }
    Ok(out)
}
```

**Depth**: no logic change. `walk_item`'s guard becomes `if depth >
MAX_CBOR_DEPTH`; the existing
`nesting_depth_guard_accepts_limit_rejects_beyond` test keeps its shape
with new numbers. **No depth tracking is added to the typed path** — §6
explains why it would be unreachable code.

**Tests F11 owes** (beyond its own accept list):

- per cap: at-cap passes / cap+1 fails with that cap's code — 19 pairs;
- a `#[test]` asserting `BundleListKind::cap()` / `OpaqueField::cap()` /
  `ManifestListKind::cap()` equal the `docs/format/registry-v1.json`
  `caps` table (F11 accept: "code == registry table");
- allocation test: a small input claiming a huge array length is rejected
  without a large allocation, asserted by a counting test allocator;
- a test pinning §5's stage-1 precedence: oversized-and-non-canonical
  reports `bundle-too-large`;
- a test pinning that the v1 registry's deepest legal chain (6 containers)
  passes at `MAX_CBOR_DEPTH`, so the cap can never be lowered below the
  schema by accident.

## 10. Registry rows F4 must record

**F11's implementer lands these; this decision does not edit the
registry.** Replace `docs/format/registry-v1.md` §11 (currently a
placeholder) with:

```markdown
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
```

And in `docs/format/registry-v1.json`, a new top-level key mirroring it
(the doc↔JSON consistency tests in
`crates/antseal-core/tests/format_registry_draft.rs` consume the mirror,
and every item needs a `status` marker per
`every_draft_item_carries_a_registered_status_marker`):

```json
"caps": {
  "doc_section": "registry-v1.md section 11",
  "decision": "D10",
  "status": "proposed",
  "clamp_rule": "every pre-allocation clamped to min(claimed_length, remaining_input); order at an array head is head canonicality -> cap -> clamped allocation -> elements",
  "entries": [
    { "name": "MAX_BUNDLE_BYTES", "value": 268435456, "unit": "bytes",
      "applies_to": "layer-1 .sealproof input", "code": "bundle-too-large",
      "status": "proposed" }
  ]
}
```

…one `entries` object per row of the table above, `unit` being `"bytes"`,
`"count"`, or `"containers"`.

Also update `decode_layers.max_container_depth` to record `"cap": 8` next
to its existing `bundle_chain: 5` / `manifest_chain: 6`.

## 11. Permanence

**All 19 are format-permanent and freeze at Q14**, for the reason the task
statement gives and this record adopts: a receiver that rejects a bundle a
sealer produced is a compatibility break, and line 123 binds every future
release to every released version. F15's oversized and over-deep fixtures
additionally encode two of them as committed bytes.

They are not all permanent in the same *direction*, and the distinction is
worth recording because it says which mistakes are recoverable:

- **Honest-reachable caps** (1, 2, 4, 5, 10–19): an honest sealer's output
  can approach them. **Both directions break.** Lowering rejects bundles
  already sealed; raising mints bundles that shipped verifiers reject.
  These are frozen hard.
- **Hardening-only caps** (3, 6–9): the v1 schema's own maximum sits far
  below the value (depth 6 vs 8; ~4 anchors vs 256; ~3 intermediates vs
  16), so no honest artifact approaches them. **Raising is
  backward-compatible for receivers; lowering below the schema maximum is
  the break.** If evidence arrives before Q14 that one is too tight — the
  `MAX_INTERMEDIATE_COUNT` risk in §2 is the live example — raising it is
  cheap. After Q14 it is a format-version event either way.

**No local override exists, and none should be added.** A per-verifier cap
knob would let the CLI and the WASM page disagree on whether a bundle is
valid, which is precisely the divergence MVP-SPEC.md line 73 exists to
prevent ("the CLI and the zero-install WASM page must never diverge on a
'valid' bundle"). The only locally tunable thing in this area is a *UX*
threshold — the M3 page warning before it attempts a 200 MiB bundle — which
never changes a verdict.

The genuinely non-permanent parts of F11 are the ones that are not
constants at all: `clamped_capacity`'s implementation, `DecodeBudget`'s
internals, and the choice to hint capacity at all (an amortizing
`Vec::new()` is equally memory-safe; the clamp exists so the budget is
*statable* for F17's fuzz invariant). Those are free to change forever.

## Consequences and open actions

1. **18 new codes must land before Q14** (contract §3). They are F11's to
   mint; F15 binds two of them in fixtures.
2. **`MATRIX.json`'s `oversized` pending row gets `expected:
   "bundle-too-large"`**; its `deep` row keeps `cbor-nesting-too-deep` but
   becomes a **direct-call row on `check_canonical`**, not a pipeline row
   (§6). Q8's `EXPECTED_M0_PENDING` shrinks by two when F15 lands.
3. **A must validate `MAX_INTERMEDIATE_COUNT = 16` against the A25
   recorded FreeTSA/DigiCert chains before Q14** (§2). It is the only cap
   in the table whose basis is empirical rather than derived, and raising
   it is free until the freeze.
4. **New decision registered — D83: are A's M2 internal `.ots`/DER
   structural limits format-permanent?** A5 ("hard caps … max response
   size, max certificate count/size, max signed-attribute count, max
   nesting depth") and A11 ("`.ots` codec wrapper: strict limits") will
   add limits at M2 that decide accept/reject on a **v1-frozen** bundle,
   after Q14 has closed. D10 takes the byte-length caps on v1 `bstr`
   fields (16–19) into M0 precisely because they are wire-format
   constraints; the *internal* limits are constraints on foreign formats
   and were left to A. But the same argument that froze rows 16–19 applies
   to them: a limit that decides validity must be identical in the CLI and
   the page, forever. D83 must answer whether they freeze at Q14 (which
   means placeholder values must be chosen at M0, on no evidence) or are
   explicitly scoped as post-freeze and versioned separately. **Blocks:
   A5, A11, and Q14's freeze scope.** Recommendation: scope them
   explicitly as post-freeze, and record in the format-stability policy
   that artifact-internal limits are a named, documented exception to
   line 123 — the alternative is guessing DER limits at M0 with no
   recorded real token to check against.
5. F16's proptest strategies generate "bounded by F11 caps" — generating
   at 65 536 units or 256 MiB is not viable in a property corpus. F16
   should generate against a **test-only reduced-cap profile** and cover
   the real caps with F11's dedicated at-cap/cap+1 tests. Flagged to F16
   so it does not discover this at implementation time.

## Outcome

**RESOLVED, 2026-07-28.** Nineteen frozen caps as tabled in §1; one
universal clamp rule (`min(claimed_length, remaining_input)`, applied at
every pre-allocation whether or not a cap covers it); eighteen new
`bundle-`/`manifest-` codes plus the existing `cbor-nesting-too-deep`; all
enforcement inside verify stage 1, ahead of every AEAD, hash, and
signature operation; `u64` everywhere so wasm32 and native cannot diverge.
F11 implements and lands the registry rows of §10; F15 encodes the
oversized and over-deep fixtures; the residual M2 artifact-internal
limits are registered as their own decision (see the register in
`TODO.md` — the number this doc originally proposed was taken by an
unrelated finding landed the same day).

## Amendments from F11's implementation (2026-07-28)

F11 implemented every value, name, module path and clamp order in this
document verbatim. Three items in the *prose* were wrong or underspecified
and are corrected here rather than left to rot in a task report. None
changes a frozen value.

1. **§9's `take_units(&mut self, claimed: u64) -> Result<(), ()>` trips a
   default-on clippy lint** (`result_unit_err`), which the workspace denies
   under `-D warnings`. The signature is kept — `codec` sits below
   `manifest` and cannot name `ManifestError`, and a bespoke error type
   would duplicate the caller's `claimed`/`cap` pair — with a targeted
   `#[allow]` and that justification at the site. §9 should be read as
   including the allow.

2. **§5 orders the size cap ahead of F10's version dispatch, which this
   document never says out loud.** The consequence is a real semantic
   choice: a >256 MiB **v2** bundle now reports `bundle-too-large`, a *v1*
   cap that does not bind it. **Ruling: keep it.** The cheapest rejection
   wins, and a v1 verifier has no business reading 300 MiB of untrusted
   bytes to discover it cannot parse them anyway; the alternative lets a
   hostile artifact walk a verifier arbitrarily far in before any bound
   applies. The claim in `format.rs` that a hostile oversized bundle
   declaring version 7 is rejected "before F11's caps even matter" was
   false and has been corrected in place.

3. **§9's "at-cap input passes" is not literally achievable for the count
   caps.** A count cap is checked *before* its elements are read, so an
   at-cap fixture that supplies no elements necessarily fails later on
   something else. The honest form of the property — and what F11's rows
   assert — is that at-cap yields **a different code** and cap+1 yields
   **the cap's own code**. Same discrimination, accurate statement.
