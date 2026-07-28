# `bundle` vectors (F13) — the `.sealproof` format, frozen byte for byte

`bundle.json` is the v1 reveal-bundle format's committed evidence: the
canonical deterministic-CBOR bytes of ten `.sealproof` bundles, the
identity of the manifest each embeds, a **three-layer diagnostic sidecar**,
and the reveal structure each one discloses (MVP-SPEC.md lines 57, 73,
112–114, 153, 167).

## The empty-anchor bundle

> `empty-anchor-unanchored` is the **M0 milestone artifact** — MVP-SPEC.md
> line 153's *"manifest/bundle encode–decode incl. empty-anchor vectors"*, and
> the obligation Q6 registered under the permanent slug `bundle-empty-anchor`.

A bundle with **no OTS artifact, no TSA artifact and no receipt** is a
perfectly valid `.sealproof`: it proves existence, integrity and authorship,
and simply carries no independently proven time. Nothing about the format may
require an anchor, so the UNANCHORED bundle has to decode, round-trip and
verify exactly like any other — and this case asserts precisely that, plus
that it is not vacuous (it does reveal a unit).

## What one case pins

| field | freezes |
| --- | --- |
| `bundle_bytes` | the canonical `.sealproof` bytes — the whole format, byte for byte |
| `work_id`, `anchor_digest` | the embedded manifest's identity, recomputed from the **embedded** bytes |
| `diagnostic.bundle`, `.manifest`, `.body` | **all three** strict-decode layers (F9), rendered structurally |
| `decoded` | the schema-layer reading: storage record, anchors, receipt, reveals, covers, boundary paths, touched files, full reveals |

The three diagnostic layers are the point. To the outer pass, the embedded
manifest is just a byte string — its canonicality is only established by
running the strict decoder on the inner bytes themselves, and that is exactly
what the sidecar mirrors: each layer under its own name, nesting explicit,
never flattened. The sidecar rendering rules are documented once, in
`../../README.md` § "The diagnostic sidecar", and are what F14's independent
CBOR implementation implements.

In `decoded`, the material a verifier actually *uses* — `k_u`, `unit_salt`,
`path_salt`, `file_salt`, `s_root`, cover seeds, boundary hashes, transaction
hashes — is written out in full (32 bytes at most, and NON-SECRET fixture
material by construction). Opaque artifact blobs and unit ciphertexts are
summarised as `{len, sha256}`: their bytes are already frozen by
`bundle_bytes` and by the diagnostic, and a third copy of a 272-byte
ciphertext pins nothing new.

`revealed_unit_ids` is in the registry's canonical concatenation order —
`covered_reveals` ⧺ `noncovered_reveals` — which is duplicate-free but
deliberately **not** globally sorted (registry §7.6). It looks unsorted
because it is.

## Cases

| case | reveals | anchors |
| --- | --- | --- |
| `empty-anchor-unanchored` | a single binary file, fully | **none** — the milestone artifact |
| `whole-work-reveal` | all three files of a multi-file work, under the default **hybrid** policy | 1 OTS + 2 TSA |
| `covered-unit-partial-reveal` | one covered unit of the unbalanced `n = 6` file — leaves `[2,4)`, so the cover is the leaf-exact interior node `(2,1)` and the boundary path is genuinely non-empty | none |
| `noncovered-unit-reveal` | only the `--no-fine-tree` file, so its unit arrives with `unit_salt` in place of a cover | none |
| `full-file-reveal-with-mirror` | a mirrored text file in full: the covered canonical unit, the non-covered raw mirror, and `file_salt` + `s_root` | none |
| `every-anchor-kind-with-receipt` | a mixed selection (full / one unit / untouched) | **every kind and optional slot**: an OTS artifact with the D79 upgrade group and one without, a TSA artifact with intermediates and a `source` and one with neither, and the Arbitrum receipt |
| `every-anchor-kind-no-receipt` | identical | the same, receipt **excluded** |
| `nothing-revealed` | nothing at all — proves the work exists and shows none of it | none |
| `leaf-level-cover-partial-reveal` | one covered unit of the **odd-boundary** `n = 6` file (retiled 2 / 1 / 3) — the lone leaf `[2,3)`, whose minimal cover is the single node `(3,2)` at the grid's **leaf level**, so its payload is D83's `salt₂ ‖ 0x00·16` | none |
| `one-byte-fine-tree-full-reveal` | the `n = 1` file in full. `d = 0`, so the grid root *is* the leaf: `cover[0][2]` and `s_root` are the **same 32 bytes**, both in canonical leaf-level form | none |

The last two cases are the ones D83 exists for. Every other case here has
**even** unit boundaries, and by D83 §1 Fact 2 a cover of leaves `[a, b)`
contains a `level == d` node iff `d == 0 ∨ a odd ∨ (b odd ∧ b < n)` — so
before G24 the canonical leaf-level payload was pinned only in the
`fine-tree` vector and never in a whole `.sealproof`. `bundle.json`'s digest
moved when they landed, for exactly that reason (D83 §6's standing
obligation).

The receipt pair is a **one-section diff**: identical works, identical
selections, differing only in the receipt. Receipt presence *is* the sealer's
`--include-receipt` choice and carries no verdict (registry §7.10), which is
exactly why both shapes need a committed vector.

Only `whole-work-reveal` uses the hybrid policy — ML-DSA-65 costs 5.3 kB per
bundle and the bundle layer is policy-independent, so one realistic
full-strength example is kept as the reference artifact and the rest spend
their bytes on reveal structure. The manifest-side policy pair is F12's.

## Anchor artifact bytes are placeholders — a note for A

`.ots` blobs, DER tokens, intermediate certificates, the 80-byte Bitcoin
header and the receipt payload are **opaque `bstr`s at the format layer** by
design: F enforces lengths and structure, A parses contents at M2 (F8; F13
notes; A25). Every artifact byte here is therefore a self-labelling synthetic
placeholder — the header, for instance, is the ASCII
`antseal M0 placeholder - NOT a real Bitcoin header`, zero-padded to the
schema's exact 80 bytes, so anyone who hexdumps a fixture reads what it is
instead of mistaking a synthetic ramp for a recorded attestation.

**A swaps in recorded real fixtures at M2 with no schema change.** Doing so is
a recorded, justified regeneration of this file (re-bless, re-freeze, justify
the digest diff) and touches neither the `bundle` kind's payload shape nor the
wire registry. That is the whole reason these bytes stay opaque now.

## What the executor checks

Beyond recomputing the entire document from `inputs` and comparing it as one
value, the executor runs, against the **committed** bytes:

1. `SealProof::decode` — all three strict layers over one buffer (F9);
2. `encode_bundle` of the decoded bundle — byte-identical (F9 accept);
3. the zero-copy seam: the `anchor_digest` pre-image **is** the bundle's
   embedded manifest byte string, not a re-derivation;
4. both manifest digests, recomputed from those embedded bytes;
5. the sidecar, re-rendered from the committed bytes at every layer;
6. **`verify_bundle` accepts it.** F13's accept clause is *"R's M3
   verification tests can consume these vectors unmodified"*, and a bundle the
   verifier rejects would not be consumable however well it decodes. Only
   acceptance is asserted here — the canonical **report bytes** over the same
   shapes are R9's `report` vectors, and duplicating them would create two
   artifacts that must agree.

Shape coverage is asserted **structurally** rather than by case name, so a
renamed case still counts and a silently dropped shape does not — including
the empty-anchor requirement, which fails loudly if no case has all three
anchor sections empty.

## Provenance and regenerating

Every secret derives from the documented fixed test seed
`W = 0x00 0x01 … 0x1f` (`testdata/README.md`) through R6's deterministic
fixture constructor (`test_util::bundle_fixtures`) — this repository's single
definition of a valid work and a valid reveal, so the vector cannot drift from
the substrate R7–R10 mutate (R29).

```sh
ANTSEAL_BLESS_VECTORS=1 cargo test -p antseal-core vector_bundle
```

Without the environment variable the same suite only **compares**.
`crates/antseal-core/tests/bundle_vectors.rs` additionally asserts that each
declarative case really is its `bundle_fixtures::shapes` counterpart under the
stated selection, that the empty-anchor case is what its slug promises, and
that the receipt pair differs in nothing but the receipt.
