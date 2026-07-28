# `manifest` vectors (F12) — the manifest format, frozen byte for byte

`manifest.json` is the v1 manifest format's committed evidence: the canonical
deterministic-CBOR envelope bytes of six works, the `work_id` and
`anchor_digest` each one hashes to, and a **diagnostic sidecar** that says
what those bytes structurally *are* (MVP-SPEC.md lines 57, 73, 75, 98, 153,
167).

It also discharges a debt: **F7 deferred its committed digest artifact to
here.** F7 built `work_id` and `anchor_digest` as two distinct named
functions, but its accept clause — *"fixed manifest fixture → expected
`work_id` and `anchor_digest` hex committed to testdata"* — needed a manifest
whose own bytes were frozen, which is F12. Every case below commits the
envelope bytes *and* both digests, and the executor recomputes both through
the public API.

## What one case pins

| field | freezes |
| --- | --- |
| `manifest_bytes` | the canonical envelope bytes — the whole format, byte for byte |
| `work_id` | `SHA-256(body)`, over the embedded `body` byte string **as received** |
| `anchor_digest` | `SHA-256(envelope)`, signatures included |
| `diagnostic.envelope`, `diagnostic.body` | the two CBOR layers, rendered structurally (below) |
| `decoded` | the same manifest read back through the **schema** layer, field by named field |

`diagnostic` and `decoded` are not two renderings of one thing. The
diagnostic is schema-blind — it says *"key 3 of the body map holds this text
string"*. The decoded view says *"the title is `empty file`"*. Only holding
both catches a schema layer that reads the registry **consistently but
wrongly**: a swapped pair of key numbers encodes and decodes cleanly and
would sail past a bytes-only vector.

### Where the `work_id` pre-image is

There is deliberately no separate `body_bytes` field. The pre-image is
exactly the envelope's key-0 byte string:

```
expect.cases[i].diagnostic.envelope.m[0][1].b     # hex; SHA-256 of it is work_id
```

Two fields that must agree are a place for them to disagree — and making a
checker *reach into the envelope* for the pre-image is the more honest
exercise, because it demonstrates that `work_id` hashes the embedded bytes
and never a re-encoding (F6/F7: verifiers never re-encode).

## The diagnostic sidecar format

One canonical CBOR item, rendered as JSON by these rules and no others
(the renderer is `test_util::vectors_cbor_diag`; **F14's independent
implementation implements exactly this table**):

| CBOR item | JSON |
| --- | --- |
| unsigned integer (major 0) | a JSON number, non-negative |
| negative integer (major 1) | a JSON number, negative |
| byte string (major 2) | `{"b": "<lowercase hex>"}` |
| text string (major 3) | a JSON string |
| array (major 4) | a JSON array |
| map (major 5) | `{"m": [[key, value], …]}`, entries in wire order |

Unambiguous by construction: the only JSON objects are `{"b": …}` and
`{"m": …}`, told apart by their single key. Map entries are **pairs**, not a
JSON object, because every v1 key is an integer while JSON object keys are
strings — pairs keep the key's type and the wire order visible, and the wire
order (strictly ascending, RFC 8949 §4.2.1) is itself part of what is pinned.

Integers render as JSON numbers, exact for any reader with 64-bit or
arbitrary-precision integers. The renderer refuses to emit a value above
2^53 − 1 rather than write a number an IEEE-double reader would silently
round.

**Embedded CBOR is not recursed into.** A manifest's `body` is a byte string
whose contents are themselves CBOR; the envelope diagnostic renders it as a
byte string, exactly as the wire says, and `diagnostic.body` renders those
inner bytes as their own item. The layer boundary stays explicit because that
boundary *is* F6's three-layer strict decode.

### What F14 does with it

1. `cbor2.loads(manifest_bytes)` → render by the table above → must equal
   `diagnostic.envelope` exactly;
2. the key-0 byte string, loaded and rendered → must equal `diagnostic.body`;
3. re-encode each rendered item per RFC 8949 §4.2.1 → must equal the bytes it
   came from;
4. `SHA-256` of the key-0 byte string → must equal `work_id`; of the whole
   envelope → `anchor_digest`.

Step 1 catches "our encoder and our decoder agree with each other and are
both wrong". Step 3 catches a non-canonical encoding our own strict decoder
somehow admits.

The integer keys are named in `docs/format/registry-v1.json` (maps
`manifest_envelope`, `manifest_body`, `file_entry`, `canon_descriptor`,
`unit_entry`).

## Cases

| case | shape | policy |
| --- | --- | --- |
| `minimal-binary-hybrid` | one binary file, one fine-tree-covered unit — the reference manifest | hybrid |
| `minimal-binary-ed25519-only` | the **identical work** under the Ed25519-only fallback (spec line 97) | ed25519-only |
| `text-with-raw-mirror` | a CRLF source: `canon_commit` present, raw mirror emitted as the file's **last** unit (G7, D23) | ed25519-only |
| `no-fine-tree-unit-commit` | `--no-fine-tree`: no `fine_root`, the unit carries `unit_commit` instead (spec lines 84, 94) | ed25519-only |
| `empty-file-unit` | `size` 0, `true_length` 0, exactly one unit, and no fine tree — G4's rule, reached by *asking* for a tree and having the constructor decline | ed25519-only |
| `multi-file-multi-unit` | three files: a mirrored text file, a `--split` 10/10/10 binary, and a `--no-fine-tree` file | hybrid |

The first two cases are a **one-field diff**: same files, same seed, same
nonces, differing only in `sig_policy`, `pubkeys` and `signatures`.

### Why most cases are Ed25519-only

ML-DSA-65 costs 1952 B of public key plus 3309 B of signature — 10.5 kB of
hex per case, appearing twice (bytes and sidecar), and the two hybrid cases
are 90 % of this file. The signature map is a *sibling* of the body, not
interleaved with it, so a hybrid case pins nothing about the file/unit table
that an Ed25519-only case does not. The suite therefore spends the hybrid
budget where it buys something — the smallest work (so the ML-DSA bytes sit
in the smallest possible surround) and the richest one (the default policy on
the most structured shape) — and pairs the smallest work with its
Ed25519-only twin so the two policies are directly diffable.

## Provenance and the test-only-secret convention

Every case is **fully crypto-consistent**: real salted commitments, real
fine-tree roots, real signatures over the real body bytes. Every one of those
secrets derives from the documented fixed test seed
`W = 0x00 0x01 … 0x1f` (`testdata/README.md`), through R6's deterministic
fixture constructor (`test_util::bundle_fixtures`) — which is this
repository's single definition of "a valid antseal work", so the vector
cannot drift from the substrate R7–R10 mutate and R9's report vectors pin.

The other fixture constants — `seal_id`, `app_version`, `claimed_time`, the
per-unit content addresses — are published placeholders, and the executor
*requires* `inputs.w`, `inputs.seal_id`, `inputs.app_version` and
`inputs.claimed_time` to equal them. A vector derived from any other material
fails rather than passing quietly (project rule 6).

No value in this file is, or is derived from, real vault, wallet or author
material.

## Regenerating

Generation is in-repo and reproducible; the committed file is the output of

```sh
ANTSEAL_BLESS_VECTORS=1 cargo test -p antseal-core vector_manifest
```

Without the environment variable the same suite only **compares**, so drift
fails CI with the offending field named. Regenerating a frozen vector is a
reviewed event (`../../README.md`, "What changes at Q14"): re-run
`scripts/vector-freeze.sh --update`, review the digest diff, and justify it
in the commit.

`crates/antseal-core/tests/manifest_vectors.rs` additionally asserts that each
declarative case really is its `bundle_fixtures::shapes` counterpart, and that
a manifest is a function of the **work** and not of what a reveal shows.
