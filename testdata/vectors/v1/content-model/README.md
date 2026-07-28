# `content-model` vectors (G21) — the composition above the tree

`content-model.json` pins the **seal-side content model's derived values**:
what `assemble_content_model` produces from a work's files and flags, before
any key material, any CBOR, and any proof. G15's `fine-tree` vectors pin the
tree primitives; this pins the composition above them.

## Why it exists — the hole G14 left

G14's golden end-to-end fixture is committed as **Rust constants**
(`crates/antseal-core/src/content/fixtures.rs`, `test-vectors` tier). The
wasm32 `--lib` lane executes it, so a native/wasm32 divergence inside the
assembly fails a unit test there.

But the Q5 bit-match lane (`crates/wasm-bitmatch`, `scripts/wasm-bitmatch.sh`)
compares committed vector **files** byte-for-byte between the two targets, and
a Rust constant is not a file. The assembly's derived values — per-file
`fine_root`, unit ranges and work-global ids, `size`, descriptor fields — were
therefore outside that lane entirely. This vector puts them in it, and the
coverage is automatic: the bit-match harness's `build.rs` walks this tree, so
no per-vector wiring exists to forget.

## What is pinned

Per case (one whole *work*):

| pinned | why |
| --- | --- |
| per file: `kind`, `fine_tree_present`, `fine_tree_domain`, `unicode_version` | the descriptor exactly as recorded (MVP-SPEC.md line 83) |
| per file: `raw_len` **and** `size` | the two are different numbers for text: `size` is stated in the file's own domain (line 98) |
| per file: `canonical` | the rendition the fine tree's leaves and every text offset live in (line 85) |
| per file: `s_root`, `fine_root` | the synthetic seed the model was handed and the root it derived — `null` where no tree exists |
| per unit: `unit_id`, `file_id`, `kind` | work-global ids in manifest order, never restarting per file (line 76) |
| per unit: `start`, `length`, `true_length`, `bytes` | the tiling itself, and the mirror's exemption from it (line 92) |
| per unit: `covered`, `unit_commit_required` | the sole-commitment rule, as the exact negation it is (line 94) |

## What is deliberately **not** pinned: proof bytes

No cover seed, boundary node, or proof byte appears in this document.
Openings are *executed* — every covered unit is proved through `prove_unit`
and verified against its file's own `fine_root`, so "covered" is demonstrated
rather than declared — but nothing about the proof's **encoding** is
committed here.

That is a deliberate separation of concerns, and it has a live consequence:
decision **D83** may change a leaf-level cover node's payload from 32 bytes to
16. G15's `fine-tree` vectors own proof bytes and move with that decision;
these do not. The executor asserts the independence mechanically
(`the_document_pins_no_proof_bytes`) rather than trusting the comment.

## Cases

| case | files | what it exercises |
| --- | --- | --- |
| `golden-four-file-work` | 4 | **byte-identical to `content::fixtures::golden_inputs()`** — CRLF text under `--split blank-lines` with a raw mirror, a binary file, a `--no-fine-tree` file, and an empty file. Seven work-global units across four files. |
| `force-text-invalid-utf8` | 1 | the `--force-text` branch the golden four leave untouched: bytes that fail strict UTF-8 detection are sealed as text, so the rendition is D20's lossy U+FFFD transform and the mirror is the only carrier of the originals |

The second case's file is `EF BB "head" CR LF FF FE "tail" CR LF`, chosen so
three corners land at once: `EF BB` is a **truncated BOM** and decodes to one
U+FFFD which stage 2 must *not* strip (U+FFFD is not U+FEFF); `FF FE` can
never begin a UTF-8 sequence, so it becomes two separate U+FFFDs rather than
one; and both line endings are `CR LF`, so raw and canonical differ for a
second, independent reason.

## The G14 tie

The executor does something no other kind does: it compares the committed
`golden-four-file-work` case against G14's Rust fixture **in both
directions** —

1. the case's file bytes and flags must equal `golden_inputs()`, and
2. the model recomputed from the case must equal `golden_model()`'s rendering.

Without (1) the file could pin a *different* work and stay perfectly
self-consistent; without (2) the Rust fixture could change meaning while the
file kept the old values. Both run on native and on wasm32, since both are
in-memory comparisons.

## Coverage is structural, not by name

`check_shape_coverage` asserts what the case set *contains* — both
`FileKind`s, both `UnitKind`s, both `fine_root` presence states, a multi-unit
split, an empty file, a text file whose raw ≠ canonical, and a `--force-text`
file that is not valid UTF-8 — never that a case with a particular name
exists. Renaming a case keeps passing; quietly dropping a branch does not.

## No independent generator, and why

Unlike G15's kind there is no `gen_vectors.py`. A second implementation of
this document would have to reimplement NFC under a pinned Unicode version,
the D21 canonicalization pipeline, D22's split, D23's mirror rule, and the
whole GGM/Merkle tree — i.e. the product, which is a second product rather
than a cross-check (the same reason R9's `report` kind has none).

What stands behind the values instead is decomposition. The tree layer is
cross-checked against Python by `../fine-tree/gen_vectors.py`; the
canonicalization layer by G3's UTF-8 corpus
(`crates/antseal-core/tests/utf8_corpus.rs`); the HKDF and commitment layers
by `../crypto/reference.py`. What this kind adds — the composition — is held
by whole-document regeneration
(`crates/antseal-core/tests/content_model_vectors.rs`), by the tie to G14's
independently written constants, and by the native↔WASM byte comparison.

## Fixture material

Every value derives from the documented fixed test seed
`W = 0x00 0x01 … 0x1f` (`testdata/README.md`) through
`content::fixtures::SyntheticFineSeeds`:

```text
s_root(file_id) = SHA-256(SYNTHETIC_FINE_SEED_LABEL ‖ W ‖ le64(file_id))
```

Deliberately **not** C's `HKDF(W, "fine-seed", file_id)`, so a fixture seed
can never collide with a real vault derivation and no committed value here is
reachable from any production key schedule (project rule 6). The label
appears verbatim in `inputs.fine_seed_label` and the executor rejects any
other.

One consequence worth stating: `file_id` is positional *within a work*, so
the two cases' file 0 share an `s_root`. That is harmless for a fixture — the
files differ, so the roots differ — and it is the price of pinning the
documented supplier rather than inventing a per-case one.

## Regenerating

```text
cargo test -p antseal-core --features test-util --test content_model_vectors \
    -- --ignored emit_content_model_vector_document
./scripts/vector-freeze.sh --update
```

A digest change here is a **format event**: state in the commit which values
moved and why.
