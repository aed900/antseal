# D81 — `unit-decrypt-failed` has no cause discriminator

- **Status: RESOLVED — option (b). No discriminator is minted. One registry
  row (`verify-flipped-ciphertext-byte`) claims the outcome; *swapped unit*
  and *wrong `k_u`* become recorded non-rows plus named tests and an R10
  property**
- **Date: 2026-07-28**
- **Owning task: R8** (consumed by Q8's registry + checker, R10's property
  suite, C19/C20's assumption regression set)
- Surfaced 2026-07-28 by Q8's completeness registry applying distinctness to
  **pending** rows — before either row was written.

## The question

MVP-SPEC.md line 168 names *flipped ciphertext byte* and *swapped unit* as
two separate M0 tamper rows. Both fail at R2's stage 1 with
`VerifyError::UnitDecryptFailed`, which carries no cause, so both bind the
code `unit-decrypt-failed` and `check_registry` will refuse the pair. Either
a cause discriminator is minted — a change to the frozen code set, hence
before Q14 — or one mutation stops being a row.

The register leaned toward minting, on the argument that "a verifier that
cannot tell 'someone flipped a byte' from 'someone swapped a unit' is weaker
evidence". That argument is wrong, and the rest of this record is why.

## What the code does today

Stage 1 of the per-unit pipeline
(`crates/antseal-core/src/verify/unit_stages.rs:241`) calls the single AEAD
implementation with bundle-side `k_u` and ciphertext, manifest-side
`seal_id`, `unit_id`, `nonce` and `true_length`:

- `crates/antseal-core/src/crypto/unit_aead.rs:282` opens
  XChaCha20-Poly1305 and, at **line 290**, collapses every failure with
  `.map_err(|_| CryptoError::AeadDecryptFailed)`. The `chacha20poly1305`
  crate's `aead::Error` is a unit struct — there is nothing to map *from*.
- `crates/antseal-core/src/verify/unit_stages.rs:249-252` maps that to
  `VerifyError::UnitDecryptFailed { unit_id }`, with the comment "The AEAD
  cannot (and must not) distinguish wrong key / wrong nonce / wrong AAD /
  tampering."
- `crates/antseal-core/src/verify/error.rs:646` returns
  `"unit-decrypt-failed"` for that variant; the variant
  (`error.rs:276-280`) carries only `unit_id`.
- `crates/antseal-core/src/crypto/unit_aead.rs:58-65` already states the
  rule as C9's frozen failure ordering.

Both mutations are stage-1 failures because nothing earlier looks at the
ciphertext. R3's length group
(`crates/antseal-core/src/verify/pipeline.rs:501`) enumerates `unit_salt`,
`path_salt`, `file_salt`, `s_root`, GGM covering seeds and boundary node
hashes — every field with a *spec-fixed* length. A ciphertext has no fixed
length, so it is not in that group and no structural stage sees it.

## The cryptographic question, answered

An AEAD authentication failure is **one bit by construction**: one Poly1305
tag comparison covers the key, the nonce, the AAD, the ciphertext and the
lengths. Reporting *which* input was wrong would mean reporting the result of
a sub-comparison that does not exist. So the only honest question is: **what
does the verifier hold, outside the AEAD, that separates a swapped unit from
a flipped byte?** Taken one at a time:

**1. Per-unit key derivation — nothing.** `k_u = HKDF(W, "unit-key",
unit_id)` (`crates/antseal-core/src/crypto/hkdf.rs:247`) is a *sealer-side*
property. The verifier never holds `W` (spec line 114;
`unit_stages.rs:130-134` marks `k_u` bundle-side) and the manifest commits to
nothing about `k_u`, so the verifier cannot even establish that entry B's
supplied key *is* `k_B`. It therefore cannot separate "right key, wrong
ciphertext" from "wrong key, right ciphertext" either — the same one bit.

**2. The AAD's `unit_id` binding — an input, not an output.** `AAD =
seal_id ‖ LE64(unit_id)` (`unit_aead.rs:134-139`) is what makes a swap
*fail*. It contributes nothing to *why* it failed. R8's own task text
("test documents that AAD, not a commitment, catches this first") is a claim
about a mechanism; a code is not a mechanism, and no code can carry it. A
test can, which is the whole shape of this decision.

**3. The manifest's per-unit `nonce` — nothing.** The nonce is not
recoverable from a ciphertext without the key, and supplying the donor unit's
nonce with the recipient unit's key still fails.

**4. `true_length` / `padded_length` — a length test, and a length test is
not a swap test.** This is the only genuine structural datum. After a swap,
entry B's ciphertext is `padded_length(true_length_A) + 16` bytes while the
manifest says `padded_length(true_length_B) + 16`. But spec line 91 pads
into **256-byte buckets on purpose**, so any two units in the same bucket
are length-identical, and a `--split` work is mostly sub-256-B units in
bucket 1. The check would fire for *some* swaps and not others, making the
row's expected code a function of which two units the fixture happened to
pick — precisely the design freedom this record exists to remove, and it
would force R10's property to assert a disjunction of codes.

It also has a concrete cost. `encrypt_unit_overpadded`
(`unit_aead.rs:339`) produces a ciphertext exactly 256 B too long, so a
pre-AEAD ciphertext-length check would preempt the implemented
`over-padded-unit` row and convert it from a post-authentication verdict
into an unauthenticated one. Spec line 121 binds `true_length` to "its
**AEAD-plaintext length** after padding strip" — an authenticated quantity.
Trading an authenticated check for an unauthenticated one to obtain a nicer
error string is the wrong direction.

**5. The content commitments — stage 4, and blind to the difference
anyway.** `unit_commit` / `fine_root` need plaintext that does not exist. Had
the AEAD been absent entirely, *both* mutations would still be caught there:
garbage plaintext fails `unit_commit`, and unit A's bytes fail unit B's leaf
range under `fine_root`. That is spec line 103 working exactly as written —
"no verdict-bearing check relies on a ciphertext decrypting to a unique
plaintext". The AEAD is not the binding mechanism for either mutation; it
merely gets there first because it is stage 1.

**6. The manifest's `address` field — the strongest candidate, and it
loses.** Each unit entry carries the ciphertext's Autonomi address, which is
BLAKE3-256 of the stored chunk (`crates/antseal-core/src/manifest/body.rs:122`,
decision D11) and is covered by the signature. Recomputing it over the
embedded ciphertext *would* be a genuine, key-free, non-heuristic
discriminator: a swap yields exactly the address the signed manifest assigns
to unit A, positively identifying the donor. It is rejected on four counts,
any one sufficient:

  - it makes an **M3 storage-linkage** computation verdict-bearing at M0,
    inverting spec line 119 ("storage is the product's bonus, not its
    proof") and the pipeline's own "must never gate the evidence verdict"
    (`pipeline.rs:66-69`);
  - `body.rs:126-128` holds the address deliberately **opaque** — "this
    crate must stay WASM-safe and network-free, so nothing here interprets
    the address" — so implementing it means teaching the frozen verifier
    Autonomi's chunk-addressing scheme and adding BLAKE3 to the WASM verdict
    path, against a weekly-moving upstream;
  - it must run *before* the AEAD to preempt `unit-decrypt-failed`, i.e. an
    unauthenticated check displacing an authenticated one, and it would have
    to be phrased as "if these bytes hash to some *other* unit's address" —
    a check whose only purpose is to produce a better error string;
  - it is trivially evaded: swap **and** flip one byte, or splice bytes from
    a non-revealed unit, and it reports the flip code.

**7. Speculative re-decryption under other units' keys — unsound.** Trying
entry B's ciphertext against every other revealed unit's `(k_u, nonce,
AAD)` costs O(n²) AEAD opens over adversary-chosen input (a bundle with
10⁴ corrupted reveals forces 10⁸ opens in a browser), and it detects only
swaps whose *donor is also revealed*. Splice in a non-revealed unit's
ciphertext, another work's ciphertext, or random bytes of the right length
and it is silent. Worst of all, the reported code for one entry's mutation
would depend on which **other** units the bundle happens to reveal: the same
mutation on the same entry yields different codes in two bundles. A tamper
row binds a code to a mutation; this makes the code a function of unrelated
bundle contents. And building a "try keys against ciphertexts" loop into a
verifier whose AEAD is documented as non-committing is the partitioning-oracle
shape line 103 warns about.

### Why the indistinguishability is inherent

It is the same non-committing-AEAD property C20's security-assumptions block
is about (tasks/C.md C20: "AEAD confidentiality-only and non-committing
(invisible-salamanders class), acceptable because no verdict-bearing check
relies on unique decryption"). The AEAD's entire contribution to a verdict is
one bit — *these bytes were not produced under this (key, nonce, AAD)* — and
the design deliberately puts all identity and content binding in the salted
SHA-256 commitments and the signatures. A cause discriminator would be a
claim to information the construction is built not to have. The only way to
obtain it would be to bind ciphertexts outside the AEAD (item 6), which
inverts the evidence/storage separation.

**The register's premise was backwards.** The verifier's strength here is the
commitment, not the AEAD, and the code names the stage that fired, not the
attacker's intent. No verifier can attribute intent from a MAC failure;
pretending to would be the actual weakening.

## Options

**A — mint a cause discriminator.** Requires one of items 4/6/7. Each is
either fixture-dependent, layering-inverting, or adversary-evadable. Cost: a
permanent code plus a new pre-AEAD stage in a frozen order.

**B — one row, and demote the rest to tests + a property.** Cost: one spec
case discharged without a row, which today's Q8 checker cannot express (see
below).

## Decision

**Option B.**

- **`verify-flipped-ciphertext-byte` is the row**, binding
  `unit-decrypt-failed`. It keeps the row id already reserved in
  `MATRIX.json` and pinned in `EXPECTED_M0_PENDING`.
- **Swapped unit is a recorded non-row**, asserted instead as a named R8
  pipeline test, an AAD-isolating C-level test, and an R10 property.
- **No new `VerifyError` variant, no new code.** R's universe stays at 84
  codes over 26 variants.

The tie-break between the two candidate rows, stated honestly. The
counter-argument is real: a flipped ciphertext byte is *already* asserted
end-to-end by R5 (`pipeline.rs:1664-1670`,
`each_stage_order_mutation_is_observable_alone`), whereas the swap has no
coverage anywhere — so on marginal value the swap is the better row. It
loses on three grounds. The flip is the archetype line 168 lists first and
the mutation a third-party verifier implementer replicates first; its
outcome is fixture-independent in the strongest sense (any byte of any
ciphertext of any fixture shape), whereas a swap needs two suitable revealed
units; and the swap's entire content is the *mechanism* claim, which a row
cannot express and a test can. After the demotion the swap gets exactly the
kind of coverage the flip already has, so the asymmetry closes.

**Precedent inside this project.** C already made this collapse at its own
layer: wrong key, wrong nonce, wrong AAD and a flipped byte are one
observable failure, and `crypto-unit-aead-wrong-key` is the single row kept
for it (`MATRIX.json`, family `wrong-key`). D81 is the same collapse one
layer up.

## The three-way collision R8 must know about

R8's task text names **three** mutations that all land on
`unit-decrypt-failed`: flipped ciphertext, wrong `k_u`, swapped unit. Only
two are registered as spec cases — the spec's `wrong key` family is already
discharged by C's row. So:

> **`wrong k_u` through `verify_bundle` must not become a row either.** It
> would be a `project_added` entry claiming an outcome
> `verify-flipped-ciphertext-byte` already owns, and `check_registry` would
> refuse it. It is a named test, and a second recorded non-row.

## Implementation instruction for R8

### 1. The row

Add exactly one row to R's registry slice, base fixture: any R6 bundle with
at least one revealed unit; mutation: flip one byte of one revealed unit's
embedded ciphertext (body **or** tag — both are the same outcome, and the
fixture should note it).

```text
id:       "verify-flipped-ciphertext-byte"
expected: ExpectedOutcome::ErrorCode("unit-decrypt-failed")
```

Then, in the **same commit**, replace that case's `pending` block with
`"rows": ["verify-flipped-ciphertext-byte"]` and delete its
`EXPECTED_M0_PENDING` entry
(`crates/antseal-core/tests/tamper_completeness/mod.rs:76-80`).

### 2. `testdata/tamper/MATRIX.json` — verbatim

Replace the `swapped-unit` family's single case with (note the new `non_row`
key, and that `pending` is gone):

```json
{
  "id": "swapped-unit",
  "what": "present unit A's ciphertext under unit B's entry; the AAD's `unit_id` binding — not a commitment — is what catches it first",
  "non_row": "swapped-unit-ciphertext"
}
```

Append these two entries to `non_rows[]`, in this order:

```json
{
  "id": "swapped-unit-ciphertext",
  "milestone": "M0",
  "owner": "R",
  "mutation": "present unit A's ciphertext under unit B's entry in the bundle (MVP-SPEC.md line 168, family `swapped-unit`)",
  "collides_with": "verify-flipped-ciphertext-byte",
  "why": "An AEAD authentication failure is one bit by construction: a single Poly1305 tag comparison covers key, nonce, AAD, ciphertext and lengths, so `decrypt_unit_with_key` can only report `AeadDecryptFailed` and R2 can only report `unit-decrypt-failed` — the same outcome the flipped-ciphertext row claims. Outside the AEAD the verifier holds nothing that separates the two: it never holds `W`, so a bundle-supplied `k_u` is unverifiable; the AAD's `unit_id` binding is an input to the failing check, not an output of it; ciphertext length distinguishes only swaps between different 256-B padding buckets, so it is fixture-dependent rather than a discriminator; and the content commitments that would tell the two apart need a plaintext that does not exist. Decision D81 evaluated and rejected the address-recompute and speculative-re-decryption discriminators.",
  "instead": "Three assertions, none of them a row: (1) the named R8 pipeline test `r8_swapped_unit_ciphertext_is_rejected` in `crates/antseal-core/src/verify/pipeline.rs`, asserting `unit-decrypt-failed`; (2) the AAD-isolating C-level test `aad_unit_id_binding_rejects_a_foreign_unit_id` in `crates/antseal-core/src/crypto/unit_aead.rs`, which calls `decrypt_unit_with_key` with unit A's key, nonce and ciphertext but unit B's `unit_id` — the one call shape that varies the AAD alone — proving the AAD, not the key, is what rejects a swap; (3) the R10 property: for every ordered pair of distinct revealed units of a valid bundle, moving A's ciphertext into B's entry never verifies.",
  "record": "docs/decisions/D81-unit-decrypt-cause.md",
  "warning": "Adding this as a row will break Q7's distinctness assertion against `verify-flipped-ciphertext-byte`. That is the harness working, not a bug to route around; the fix is never an edited expected code (error-code contract §3)."
},
{
  "id": "pipeline-level-wrong-unit-key",
  "milestone": "M0",
  "owner": "R",
  "mutation": "replace a revealed unit's bundle-supplied `k_u` with another key and verify through `verify_bundle` (tasks/R.md R8's `wrong k_u` mutation)",
  "collides_with": "verify-flipped-ciphertext-byte",
  "why": "Same collapse as `swapped-unit-ciphertext`, and the spec's `wrong key` family is already discharged by C's primitive-level row `crypto-unit-aead-wrong-key`, which binds the distinct C code `crypto-aead-decrypt-failed`. A pipeline-level wrong-key row would be a project addition claiming `unit-decrypt-failed`, already owned.",
  "instead": "The named R5 pipeline test `wrong_key_fails_before_padding_checks` already exercises the wrong-key path at the stage boundary (`crates/antseal-core/src/verify/unit_stages.rs`), and R10's property covers it: no substitution of a revealed unit's `k_u` ever verifies.",
  "record": "docs/decisions/D81-unit-decrypt-cause.md",
  "warning": "Adding this as a row will break Q7's distinctness assertion against `verify-flipped-ciphertext-byte`."
}
```

Also update the registry's `_readme` and `testdata/tamper/README.md`: the
sentence "There is no third state" becomes three states — `rows`, `pending`,
or `non_row` — with the constraint that a `non_row` case names an entry in
`non_rows[]` whose `collides_with` names a row that actually claims the
outcome.

### 3. `tests/tamper_completeness/mod.rs` — the checker must gain the third state

This is not optional. **Q14's gate is `m0_pending.is_empty()`**
(`mod.rs:190`). A spec case that can never have a row and can only be
expressed as `pending` would keep the gate red forever, so the checker has to
be able to discharge it. Required edits, all in one commit:

1. `only_keys(case, &["id", "what", "rows", "pending", "non_row"], …)`
   (`mod.rs:428`).
2. The `(has_rows, has_pending)` match (`mod.rs:449-478`) becomes a 3-way
   over `(rows, pending, non_row)`: **exactly one** must be present; zero and
   any two are both failures, with the existing messages extended.
3. A `check_case_non_row` that fails unless the named id appears in the
   registry's `non_rows[]`. Because a non-row's `collides_with` is already
   required to name a live-or-reserved row (`mod.rs:568-577`), discharging a
   case this way transitively names a row that claims the outcome — the same
   strength `pending` has, not prose.
4. `Registry` gains `m0_non_row_cases: usize`, and
   `assert_registry_is_consistent` (`mod.rs:877-881`) becomes
   `m0_implemented_cases + m0_pending.len() + m0_non_row_cases == m0_cases`,
   with its "there is no third state" message updated.
5. A new pinned constant, next to `EXPECTED_M0_PENDING`, so a case cannot be
   silently discharged:
   ```rust
   const EXPECTED_M0_NON_ROW_CASES: &[(&str, &str)] =
       &[("swapped-unit/swapped-unit", "swapped-unit-ciphertext")];
   ```
   asserted the same way the pending set is.
6. `EXPECTED_NON_ROWS` (`mod.rs:148`) gains `"swapped-unit-ciphertext"` and
   `"pipeline-level-wrong-unit-key"` **appended in registry order** — the
   assertion is `Vec` equality, so order matters.
7. Delete the `("swapped-unit/swapped-unit", "R8", "verify-swapped-unit")`
   entry from `EXPECTED_M0_PENDING` (`mod.rs:96`).
8. Add a tests-of-the-test case (the block at `mod.rs:969+`): a case whose
   `non_row` names an id absent from `non_rows[]` must turn the check red.

`EXPECTED_M0_FAMILIES` stays 17 — the family is not deleted, only its case's
discharge changes.

### 4. What replaces the demoted rows

- `r8_swapped_unit_ciphertext_is_rejected` — R5's pipeline fixture has two
  revealed units of file 0 plus one of file 1; move one's ciphertext into
  another's entry and assert `unit-decrypt-failed`. Document in the test
  that the AAD's `unit_id`, not a commitment, is what rejects it, and point
  at the C-level test that proves it.
- `aad_unit_id_binding_rejects_a_foreign_unit_id` — the AAD-isolating test.
  `decrypt_unit_with_key(k_A, seal_id, UnitId(B), nonce_A, ct_A, len_A)`
  varies **only** the AAD, because the key is passed explicitly on that entry
  point. The existing `decrypt_failure_classes_are_distinct`
  (`unit_aead.rs:474`) isolates the `seal_id` component this way but not the
  `unit_id` component, since its wrong-`unit_id` case goes through
  `decrypt_unit` and changes `k_u` too.
- R10 property — the pair-swap quantifier above, plus the `k_u`-substitution
  one. R10's task text already names "section swaps of valid R6 bundles" as
  a fuzz input, so this is the property's natural home.

## Permanence

Format-permanent in the direction that matters: **no code is minted**, so the
frozen code set is unchanged and nothing here is a Q14 blocker on the code
side. What *is* permanent is the shape of the argument — a future contributor
who adds a `unit-decrypt-*` cause code is not making a local improvement,
they are asserting the verifier holds information this record shows it does
not. Adding codes stays routine (error-code contract §3); adding *this* code
needs a new decision that first defeats items 4, 6 and 7 above.

The Q8 checker change is the permanent surface: after it, a spec case may be
discharged by a recorded non-row. That is a deliberate widening, constrained
so it names a real row and is pinned twice.

## Cost, stated honestly

Two of the spec's line-168 mutations lose their registry row, and the 1:1
mapping now has a case discharged by argument rather than by a row. The
argument is checked (the non-row's `collides_with` must name a row that
claims the outcome, and both the non-row set and the discharged-case set are
pinned outside the registry), but it is still weaker than a row. The
alternative buys a row by minting a permanent code for information the
construction does not have, and by putting a pre-AEAD unauthenticated check
in front of an authenticated one.
