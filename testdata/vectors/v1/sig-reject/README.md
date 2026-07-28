# `sig-reject` — author-signature reject vectors (C15)

Committed reject-vector suites, one per author-signature algorithm, pinning
the **strict/canonical verification** semantics MVP-SPEC.md line 97 makes a
conformance requirement:

> Verification MUST be strict/canonical and is a conformance requirement for
> every verifier (CLI, WASM page, third parties) so they cannot diverge on
> the same frozen bundle.

| file | algorithm | cases |
| --- | --- | --- |
| `ed25519.json` | Ed25519 (RFC 8032 `verify_strict` + C12's D16 pre-validation layer) | 21 |
| `ml-dsa-65.json` | ML-DSA-65 (FIPS 204 Algorithm 27 `sigDecode`) | 15 |

Everything here is **NON-SECRET** fixture material: every key derives from
the documented fixed test seed `W = 00 01 02 … 1f` (`../../../README.md`,
secret-material convention).

Executed by the Q4 runner through
`antseal_core::test_util::vectors_sig_reject`, which routes **every case
through C14's full verification path** (`crypto::sig_policy::verify_body`
with a one-algorithm policy) rather than the per-algorithm entry point — so
the suites cover the policy layer's own length and present-set checks as
well as the algorithm's canonicality rules. Execution is WASM-safe and I/O
free, so the Q5 native↔WASM bit-match lane runs the identical code path.

> **Layout note.** tasks/C.md C15 sketched `testdata/sig-reject/`. Reject
> vectors *are* golden vectors — their `expect` is an error code instead of
> an output — so they live in the Q4 envelope under
> `vectors/<format-version>/` instead of opening a new top-level fixture
> category (`../../../README.md`, contribution rule 5). Nothing about the
> envelope needed changing; only a kind was added.

## Envelope

Standard Q4 envelope (`../../README.md`) with `kind: "sig-reject"`.

### `inputs`

| field | value |
| --- | --- |
| `w` | 32-byte hex; **must** equal the documented fixed test seed |
| `alg` | `"ed25519"` or `"ml-dsa-65"` (the `SigAlg` wire names) |
| `ctx` | **must** equal the frozen context string `antseal-manifest-v1` |
| `body` | hex of the manifest body bytes being signed |

### `expect`

```jsonc
"expect": {
  "base": { "public_key": "<hex>", "signature": "<hex>" },
  "cases": [ /* … */ ]
}
```

`base` is the honest material: the public key derived from `W` and the
signature over `body` under the frozen context. The executor **re-derives
both and byte-compares**, so the base doubles as a keygen +
deterministic-signing golden and no case can be built on stale bytes.

Each case:

| field | value |
| --- | --- |
| `id` | stable, unique within the suite |
| `class` | which rejection family it exercises (table below) |
| `why` | the rule being violated, in prose — required, non-empty |
| `public_key` | a **source** (below) producing this case's key bytes |
| `signature` | a **source** producing this case's signature bytes |
| `expect` | `"accept"`, or the stable `crypto-…` error code the verifier must emit |
| `public_key_hex`, `signature_hex` | *optional* expanded bytes; when present the executor byte-compares them against the source's output. The Ed25519 suite carries them (32/64 bytes each); the ML-DSA suite omits them (1952/3309 bytes per case) and is reproduced from the recipes. |

## Sources — how to rebuild a case's bytes

A source is an object. `from` selects the starting material; the remaining
fields mutate it, **in this order**: `edits`, then `truncate_to`, then
`append_hex`.

| `from` | meaning |
| --- | --- |
| `"base"` | the corresponding `expect.base` value |
| `"alternate-signer"` | the same derivation, but under `W' = SHA-256("antseal C15 alternate signer" ‖ W)` — a genuinely different signer that is still derived from the documented test seed |
| `"context"` | *signature only.* Sign `body` under the context named by the sibling `ctx` field: Ed25519 signs `ctx ‖ 0x00 ‖ body`; ML-DSA-65 passes it as the FIPS 204 `ctx` parameter |
| `"raw-body"` | *Ed25519 signature only.* Sign the bare `body` with **no** context prefix at all |

| field | meaning |
| --- | --- |
| `edits` | ordered splices. Each is either `{"offset": n, "hex": "…"}` (write these literal bytes at `n`) or `{"offset": n, "fill": "ff", "repeat": k}` (write `k` copies of the single byte). An edit that would run past the end of the buffer is a malformed vector, not a truncation. |
| `truncate_to` | keep the first `n` bytes |
| `append_hex` | append these bytes |

Edit recipes are **derived from the mutated bytes** by the generator (a
single splice covering the differing span), so a file's recipe and its
`*_hex` fields can never disagree.

## Case classes

| class | applies to | what it exercises |
| --- | --- | --- |
| `accept` | both | positive control: the honest material verifies |
| `s-out-of-range` | Ed25519 | RFC 8032 §5.1 `0 ≤ S < L`, with values straddling `L` |
| `small-order-point` | Ed25519 | small-order `R` or `A` (identity, order-2) |
| `non-canonical-point` | Ed25519 | non-canonical `y` encodings (`y ≥ p`, "negative zero") and off-curve points — including the **ZIP-215 gap** the pinned `ed25519-dalek` leaves open on `A` (decision D16) |
| `hint-rule` | ML-DSA-65 | FIPS 204 Algorithm 21: strict index ordering, count ≤ ω = 55, non-decreasing cuts, zero padding past the last cut |
| `z-out-of-range` | ML-DSA-65 | the `‖z‖∞ < γ₁ − β` norm bound, which the pinned crate enforces eagerly at decode |
| `wrong-key` | both | well-formed signature by the alternate signer |
| `wrong-context` | both | signature made under a different (or empty) context |
| `wrong-length` | both | wrong-length signature or public key |
| `bit-flip` | both | a mutation that still **decodes**, so it must fail as *invalid*, not *non-canonical* |
| `canonical-but-invalid` | both | an impeccable encoding that does not verify — the other side of the same distinction |
| `degenerate` | both | all-zero / all-`0xFF` blobs: adversarial input must reject cleanly, never panic |

The executor requires, per algorithm, the classes C15 enumerates
(`accept`, plus Ed25519: `s-out-of-range`, `small-order-point`,
`non-canonical-point`, `wrong-key`, `wrong-context`, `wrong-length`;
ML-DSA-65: `hint-rule`, `z-out-of-range`, `wrong-length`, `bit-flip`,
`wrong-key`, `wrong-context`), and rejects a class that does not apply to
the suite's algorithm — a suite cannot silently lose a family.

## Expected codes

Reject cases name a stable `CryptoError` code from the D30 contract
(`docs/testing/error-code-contract.md`). The executor checks the code is
`crypto-`-prefixed **and** that some `CryptoError` variant actually emits
it, so a typo in a committed file fails loudly instead of vacuously
passing. The two codes these suites use per algorithm are:

- `crypto-non-canonical-signature-{ed25519,ml-dsa-65}` — the *encoding* is
  not canonical;
- `crypto-signature-invalid-{ed25519,ml-dsa-65}` — the encoding is
  impeccable but the signature does not verify over these bytes under this
  key.

Keeping those two distinct is exactly what the tamper matrix (MVP-SPEC.md
line 168) requires, and these suites are where the boundary between them is
pinned case by case.

## Provenance and regeneration

The generator is committed beside its output as
`crates/antseal-core/tests/sig_reject_suite.rs` and is run to **verify**:
`sig_reject_committed_suites_match_the_generator` rebuilds both documents
and asserts the committed bytes are byte-identical. Regeneration is
deliberately opt-in:

```
cargo test -p antseal-core --all-features -- --ignored sig_reject_regenerate
```

A byte change to a committed suite is a reviewed event, not a drive-by
regeneration (`../../../README.md`, contribution rule 3).
