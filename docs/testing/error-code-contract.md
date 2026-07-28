# Stable error-code contract (Q7; decision D30)

Normative for every component domain (F/C/G/S/A/R). Spec basis: the tamper
matrix — "every mutation fails with a **distinct** error" (MVP-SPEC.md
line 168) — and the working principle *parse defensively*. This document is
the formalization D30 called for; it is enforced by per-domain distinctness
meta-tests plus the cross-domain sweep in the Q7 harness
(`antseal_core::test_util::tamper`).

## 1. What a code is

Every error type a verifier can surface exposes

```rust
pub const fn code(&self) -> &'static str
```

returning a **lowercase kebab-case** identifier. The code is the
machine-readable name of the failure: tamper rows bind to it, `--json`
output carries it, and third-party verifiers compare against it. The
`Display` text may be reworded freely; the code may not.

Codes are **variant-level, not type-level**: where a variant carries a kind
discriminator that a tamper row must distinguish — a salt kind, a signature
algorithm, a tiling-violation class — each value gets its own code
(`crypto-unit-salt-length` vs `crypto-path-salt-length`; `tiling-gap` vs
`tiling-overlap`). One code per *outcome a mutation can be pinned to*.

## 2. Domain prefixes

| Prefix | Owner | Surface |
|---|---|---|
| `cbor-` | F | canonical-CBOR decode (F3) |
| `manifest-` | F | manifest schema validation (F5–F7) |
| `bundle-` | F | `.sealproof` bundle schema validation (F8–F9) |
| `crypto-` | C | HKDF, commitments, padding, AEAD, signatures (C2–C14) |
| `content-` | G | canonicalization, unit model, fine tree (G2–G13) |
| *(unprefixed)* | R | verification-pipeline outcomes (R1–R5) |

`manifest-` and `bundle-` are **separate families, and that separation is
normative** (decision D78, ratified 2026-07-28). Bundle schema validation
never consults the embedded manifest, so a `bundle-` code always means
"malformed on the bundle's own bytes" and a `manifest-` code always means
"the embedded manifest is malformed". A bundle that is *well-formed but
inconsistent with its manifest* is neither: it is a verify-pipeline
outcome in R's unprefixed namespace. Since this section is what makes
families permanent, the split had to exist before F8's error enum was
written — and it is enforced structurally: `BundleError` has no arm that
can carry a `ManifestError`.

R's codes are deliberately unprefixed: they name pipeline-level outcomes
(`tiling-gap`, `path-commit-mismatch`, `unknown-unit-ref`) that appear in
user-facing verdicts, where a `verify-` prefix would be noise. The
distinctness rule is global regardless of prefix, so an unprefixed R code
must not collide with any domain code — the Q7 registry sweep is what
proves it.

A domain never mints a code under another domain's prefix. Wrapper arms are
the exception in the other direction: when R wraps a C or F error
(`VerifyError::Crypto`, `VerifyError::Codec`), the **inner** code is
surfaced unchanged, so the wrapped failure keeps its owning domain's
identity rather than acquiring a second one.

### Consequence: a code names a rejection class, never a layer (recorded at F15)

Wrapper arms delegating unchanged has a consequence worth stating outright,
because it is the thing a contributor will otherwise try to "fix". The
`.sealproof` pipeline has three strict layers (registry §7.6.3), and the
**same** canonicality fault at each of them produces the **same code**:

| where the duplicate map key is | code | layer |
|---|---|---|
| the manifest body | `cbor-duplicate-map-key` | manifest body |
| the manifest envelope | `cbor-duplicate-map-key` | manifest envelope |
| the bundle map | `cbor-duplicate-map-key` | bundle |
| the embedded manifest inside a canonical bundle | `cbor-duplicate-map-key` | manifest envelope |

So **four distinguishable mutations cannot be four tamper rows** — §4 layer 2
correctly refuses the set. That is not a coverage gap and the fix is *not*
`cbor-duplicate-map-key-in-body` and friends: minting per-layer codes would
fork one taxonomy into four and make "which layer" a permanent part of every
code name, which §3 then freezes forever.

What separates them is `ManifestError::layer` / `SealProofError::layer` —
pipeline context, not a rejection class. F15's fixture table
(`testdata/tamper/format/FIXTURES.json`) is therefore the finer instrument:
it pins every fixture on the **`(code, layer)` pair**, which *is* pairwise
informative, while a tamper row is registered only where the code is not
already claimed. Twenty fixtures, seven rows, and the difference is checked
in both directions rather than asserted.

Caveat a reader hits immediately, and F26 owns: the two accessors disagree
about what a missing layer means. A bundle **schema** rejection still
reports `Some(Bundle)` — a layer-1 failure is layer 1 by construction — while
a manifest schema rejection reports `None`, because it names its own map,
which is more precise. So `layer == null` means "schema rejection *inside the
manifest*", not "schema rejection".

### Recorded exception: the `fine-root-` family (ratified 2026-07-28)

The fine-tree errors live in G (`content/fine_tree/error.rs`) but carry
**`fine-root-`**, not `content-`. This is deliberate and is the only
standing exception.

R2 minted `fine-root-binding-failed` and `fine-root-over-broad-cover` before
G9–G13 existed, to declare the seam the fine tree would later fill. §3 makes
codes append-only — *a failing test is never fixed by editing a code* — so
those two cannot be renamed. When G13 added five more classes to the same
family, the choice was between extending `fine-root-` or splitting one
taxonomy across two prefixes with the older half misnamed. Extending it is
the lesser evil: the family stays contiguous and searchable, and the
identity of already-shipped codes is preserved.

The global distinctness rule is unaffected — `fine-root-` collides with no
other prefix, and the Q7 registry sweep proves it. R's exemplar list
*sources* the fine-tree rows from G's rather than restating them, so the two
cannot drift.

## 3. Append-only

Codes are permanent from the moment a tamper row, a golden vector, or a
released verifier binds to one:

- **Never rename** a code. A renamed code silently breaks every third-party
  verifier comparing against it and invalidates committed rows.
- **Never reuse** a retired code for a different meaning.
- **Never renumber or re-scope** an existing code to make a failing test
  pass. If a test disagrees with a code, either the implementation regressed
  or the row is wrong — changing the code is a third option that destroys
  the contract.
- **Adding** codes is routine and unrestricted: new variants, new kind
  discriminators, and new domains all append.

Before the Q14 freeze a code may still be corrected, but only as a recorded,
justified change (the same discipline as a fixture byte change). After Q14
the code set of frozen surfaces is permanent.

## 4. Distinctness enforcement, in three layers

1. **Per-domain meta-tests** — each domain asserts its own codes are
   pairwise distinct over an exemplar of every variant (F's `DecodeError`,
   C's `CryptoError`, G's content errors, R's `VerifyError`). These catch
   copy-paste collisions inside a domain.
2. **The Q7 registry sweep** — `check_registry` refuses two tamper rows that
   expect the same outcome, across domains. This is where a genuine
   cross-domain collision surfaces, because rows from F, C, and R sit in one
   registry.
3. **Q8 completeness** — `testdata/tamper/MATRIX.json` maps the spec's
   M0/M2 enumeration 1:1 onto implemented rows, and the check refuses a spec
   case that has neither a row nor an owned `pending` marker. It also
   applies the distinctness rule **ahead of implementation**: a pending
   row whose expected code is already claimed — by an implemented row or by
   another pending row — fails the registry unless the entry records the
   collision explicitly. That surfaces "these two mutations are one
   observable failure" while it is still cheap to fix, instead of at the
   moment `check_registry` refuses the pair.

A collision found at layer 2 is **not** fixed by editing the registry: it
means two mutations are genuinely indistinguishable to a verifier, and the
fix is a new error variant with its own code in the owning domain.

## 5. Outcomes that are not errors

Some tamper rows — chiefly M2 anchor rows — must pin a **verdict state**
rather than an error: an anchor signed by an untrusted root does not error,
it lands in a specific non-headline state. The harness models these as
`ExpectedOutcome::VerdictState(name)`, in a namespace separate from error
codes, and applies the same distinctness rule. A18/R17 own the state names;
the harness only compares them.

## 6. Adding a row

The procedure lives with the harness
(`crates/antseal-core/src/test_util/tamper.rs`, module docs) so it cannot
drift from the code that enforces it. In short: pick the distinct code (or
mint one), write an `fn() -> ActualOutcome` that applies exactly one
mutation to a valid base fixture, append a `TamperRow` with a permanent
kebab-case id, and never edit an existing row's expected code.

## 7. Status

- **2026-07-27** — contract formalized at Q7; harness + seeded registry
  landed (17 rows across F, C, and R, all outcomes pairwise distinct).
  Domain code inventories at that date: F `cbor-` 15, C `crypto-` 25+, R
  unprefixed 30+ (the running total recorded in the TODO decision register
  as D30). Wave-3 work adds `manifest-` (F5–F7) and `content-` (G4/G5/G8)
  codes; the cross-domain sweep runs over the merged set at integration.
- **2026-07-28** — C17 landed C's registry slice
  (`antseal_core::test_util::tamper_rows_crypto`): **17 crypto rows**, merged
  with the Q7 seed rows in `tests/tamper_matrix.rs` so the layer-2
  cross-domain sweep runs over **34 rows**. C15 added a fourth enforcement
  surface for the same code set: committed reject vectors validate their
  expected code against the real `CryptoError` code universe
  (`all_code_exemplars`), so a code that no variant emits cannot be pinned
  by a committed artifact either. First genuine cross-domain near-miss
  recorded and kept separable: R's pipeline-level `path-commit-mismatch` vs
  C's primitive-level `crypto-path-commit-mismatch`.
- **2026-07-28 (M0 wave 4, F8)** — `bundle-` registered as a sixth family
  with **32** codes, asserted pairwise distinct *and* disjoint from
  `manifest-` (`bundle::error`'s meta-tests) and exercised from real bytes
  by `tests/bundle_schema.rs`'s 32-row reject matrix. R gained one code,
  `full-reveal-s-root-without-fine-tree`, when **D74** resolved to reject
  — completing D28's five-arm violation table (R total 71 → 72).
  **D80** fixes a further rule whose code R4/R5 still owes:
  `revealed-unit-file-not-touched` (recommended spelling).
- **2026-07-28** — Q8 landed the completeness registry
  (`testdata/tamper/MATRIX.json`, checker
  `crates/antseal-core/tests/tamper_completeness/mod.rs`, CI lane
  `tamper-matrix`): **37 M0 spec cases across 17 families** — 24
  implemented, **13 pending** with named owners (F15 ×2, G19 ×2, R7 ×6, R8
  ×3) — plus 9 declared project-added rows, 2 recorded non-rows, and 7 M2
  anchor cases pre-registered for Q18. Two collisions surfaced by the
  ahead-of-implementation distinctness check and recorded rather than
  resolved by Q8: (a) `flipped ciphertext byte` and `swapped unit` both
  surface as `unit-decrypt-failed`, because `VerifyError::UnitDecryptFailed`
  carries no cause discriminator — R8 must mint a discriminator or make one
  of the two an R10 property; (b) a C-level GGM-covering-seed length row
  would claim `crypto-seed-length`, already held by the `s_root` row,
  because `CryptoError::SeedLength` has no kind discriminator — the R-level
  code set *does* discriminate, so that sub-variant is owned by R7 and the
  C-level row is a recorded non-row. Two further hazards are noted on
  pending cases: a G19 row and an R8/R7 row would collide on
  `fine-root-binding-failed` and on `fine-root-over-broad-cover`
  respectively, because R's wrapper arms surface the inner code unchanged
  (§2).
- **2026-07-28** — R4 appended four codes across two domains. R (unprefixed):
  `full-reveal-s-root-without-fine-tree` (decision D74 — the *unexpected
  material* direction, completing D28's present-set-==-required-set rule).
  G (`content-`): `content-unknown-unicode-version` and
  `content-canonicalize-invalid-utf8`, a **new family** on
  `crate::canon::{CanonicalizeError, UnicodeVersionError}` with its own
  layer-1 meta-test (`canon::tests`), which additionally asserts
  disjointness from `ContentError`'s codes — two families now share the
  `content-` prefix, so within-prefix distinctness needs proving, not
  assuming. Both reach the pipeline through R's new
  `VerifyError::Canon` wrapper arm with the inner code surfaced unchanged
  (§2). R's `VerifyError` universe: **79** distinct codes over 23 variants.
  Worth recording as a §2 illustration: `content-unknown-unicode-version`
  ("this verifier is too old") and R's `raw-mirror-canonicalization-mismatch`
  ("these bytes do not canonicalize to that content") are outcomes of the
  *same check* on the *same field* and must never merge — a second genuine
  near-miss of the `path-commit-mismatch` kind, kept separable.
- **2026-07-28 (M0 wave 4, R5)** — the orchestration appended three codes,
  all in R's unprefixed namespace and all of the *same* class: bundle and
  manifest each well formed, the two inconsistent with each other. §2 already
  assigns that class to R, and R5 is the first task with both layers decoded
  at once, so it is the first task that can observe one.
  - `revealed-unit-file-not-touched` — **D80**, exactly the spelling the
    decision record recommended. Not a `bundle-` code: mapping `unit_id →
    file_id` needs the signed unit table, which D78 keeps out of layer 1.
    Distinct from, and not redundant with, F8's tier-`[X]`
    `bundle-full-reveal-without-touched-file`.
  - `covered-unit-revealed-as-non-covered` /
    `non-covered-unit-revealed-as-covered` — a unit shipped in the reveal
    section its manifest binding forbids. Named from the **bundle's**
    mistake, since that is what a tamper row mutates.

  R also gained the `Decode` wrapper arm over F9's `SealProofError`, which
  surfaces `bundle-`, `manifest-` and delegated `cbor-` codes unchanged (§2).
  R's `VerifyError` universe: **84** distinct codes over 26 variants.

  Two records worth keeping from wiring the exemplar list:

  1. `ManifestError::SigPolicyEmpty` and `CryptoError::SigPolicyEmpty` have
     word-for-word identical `Display` text. Their *codes* differ, which is
     the contract's point, but R's exemplar list has to avoid pairing them
     because the Display-distinctness meta-test sees only the text. A third
     near-miss of the `path-commit-mismatch` kind, kept separable.
  2. **R3's `wrong-length-ggm-covering-seed` is not reachable through
     `verify_bundle`.** F8 decodes every disclosed salt, seed, key and node
     hash into a fixed-size type, so a wrong-length one is rejected at
     layer 1 as `bundle-wrong-length-cover-seed` and never reaches R's
     length group — which R5 still runs, as a backstop, over the decoded
     values. R7's pending row `verify-wrong-length-ggm-covering-seed` should
     therefore either bind the `bundle-` code or be a direct-call row on
     `check_field_length`; it cannot be a pipeline row as written. The same
     applies to the other five `wrong-length-*` classes.

- **2026-07-28 (M0 wave 5, F10)** — **zero codes minted, zero renamed.** F10
  re-homed `bundle-unsupported-format-version` (F9 raised it inline) and
  `manifest-unsupported-format-version` behind the version-dispatch table in
  `antseal_core::format`, and drove the two reserved-slot codes
  (`manifest-reserved-key`, `bundle-reserved-key`) from every reserved key of
  every v1 map. All four strings are unchanged, which is the contract working
  as intended: the *implementation* of a rejection may move, and its payload
  and wording may change, but its identity may not.

  Two records:

  1. Both `UnsupportedFormatVersion` variants gained a
     `supported: &'static [u64]` field and were reworded ("…; this build
     decodes v1"). §1 permits both — `Display` is free, the code is not — and
     the payload is carried as *data* rather than pre-rendered so a
     third-party verifier can render its own actionable message.
  2. F10 makes a **precedence** rule part of the contract: an artifact
     declaring an unsupported version reports the version code and *nothing
     else*, even when it would also fail v1 validation on a reserved key, an
     unknown key, a missing field or canonicality. The converse also holds —
     a *missing* discriminant is `*-missing-key` and a non-canonical one is
     the `cbor-*` class. "Too new" and "corrupt" are different claims about
     the sender and must never merge; the pairing is asserted mutation by
     mutation with a v1 control for each.

  Gap recorded, not closed: none of these four codes has a tamper row —
  `MATRIX.json` has no version or reserved-slot case, and Q8 does not catch it
  because they are project-added rather than spec-enumerated. Owned by **F18**.
- **2026-07-28 (M0 wave 5, R6/R7)** — R7 landed R's structural registry slice
  (`antseal_core::test_util::tamper_rows_structural`): **24 rows**, merged
  into `tests/tamper_matrix.rs` so the layer-2 cross-domain sweep now runs
  over **58 rows**. **No code was minted.** Every row binds a code R1–R5 had
  already shipped, which is the outcome the contract is meant to produce: a
  task whose whole job is writing rows should find the taxonomy already
  adequate, and a row that could not find a distinct code would have been a
  finding about the taxonomy rather than a licence to extend it.

  Three records worth keeping:

  1. **A second pipeline-unreachable R code, same cause as the first.**
     R5's rider recorded that `wrong-length-ggm-covering-seed` cannot be
     reached through `verify_bundle` because F8 decodes every disclosed
     salt/seed into a fixed-size type. R7 found the same effect in a
     different field: `partial-reveal-salt-leak-s-root` is unreachable
     because `FullReveal` makes `file_salt` **mandatory**, so a bundle can
     never present `s_root` alone and D28 row 1 always claims the verdict
     first. Both are direct-call rows (on `check_structural` and
     `classify_file_reveal` respectively), and neither code was weakened to
     fit — the R-level rules are right, and R4 must keep adjudicating the two
     materials independently. The unreachability is itself pinned by a test,
     so the day F8 gains an `s_root`-only shape the row becomes a pipeline
     row rather than silently continuing to test a different layer.
  2. **All six `wrong-length-*` classes now have R-level rows**, alongside
     C's primitive-level ones (the `s-root-32` two-row precedent, extended to
     five of the six cases; `ggm-seed-32` stays R-only per the recorded
     `crypto-level-ggm-seed-length` non-row). They keep R's length group
     reachable and pinned for the day a field is relaxed to a variable-length
     byte string.
  3. **The reverse coverage direction is now enforced.** Q8's registry maps
     the *spec's* enumeration onto rows; R7 added
     `every_unprefixed_verify_code_has_a_row_or_a_named_owner`, which maps
     the *error enum* onto rows. Every code in R's unprefixed namespace must
     be claimed by a row, by a Q7 seed row, or by an entry naming the task
     that owes it (**two** codes, both R8's). Adding a structural invariant
     without one of the three now fails CI — the direction Q8 structurally
     cannot check, because it catches an invariant nobody wrote a spec case
     for. It immediately earned itself: it surfaced that R's *pipeline-level*
     `padded-length-mismatch` and `non-zero-padding` had no row and no owner
     — C's seed rows pin the `strip_padding` primitive under different codes,
     and no task's text named the pipeline pair — so R7 added them.

- **2026-07-28 (M0 wave 5, F11 + D77)** — nineteen new codes across two
  existing families, all **format-permanent** and all landed before Q14 (§3).
  - **D10's eighteen resource-cap codes.** F's `bundle-` family grows 32 → 47
    exemplars (+15: `bundle-too-large`, ten `bundle-too-many-*`, four
    `bundle-*-too-large`); `manifest-` grows 44 → 48 exemplars (+4:
    `manifest-too-large`, `manifest-too-many-files`,
    `manifest-too-many-units`, and D77's below). The split across two families
    is **D78 applied, not stylistic**: a cap detected on the bundle's own
    bytes is `bundle-`, a cap detected on the embedded manifest's bytes is
    `manifest-`. Depth mints nothing — it reuses the existing
    `cbor-nesting-too-deep`, whose constant merely moved from F3's provisional
    `MAX_NESTING_DEPTH = 64` to `caps::MAX_CBOR_DEPTH = 8`.
    - Verified new before minting: no `-too-large`, `-too-many-` or
      `-oversized` literal existed anywhere in the tree; the only near
      neighbours are `bundle-ciphertext-too-short`, `cbor-nesting-too-deep`
      and `content-node-address-level-too-deep`, none of which collides.
    - **Recorded non-codes** (D10 §3), for the reason D75's record warned
      about — minting a code for a check that cannot fire: `sig_policy`,
      `pubkeys` and `signatures` get *no* cap and *no* code, because the
      registered `sig_alg` universe is 16 values and duplicate-freedom is
      already enforced, so an existing code always fires first. They are still
      allocation-clamped: a cap and a clamp are different mechanisms.
    - **`bundle-too-large` beats every other bundle code**, including the
      `cbor-` canonicality classes and `bundle-unsupported-format-version`,
      because D10 §5 puts the O(1) size check as the first statement of the
      decode. Pinned by `tests/parser_caps.rs`. See the F19 note below on the
      version interaction.
  - **D77's `manifest-empty-normal-units`** (`ContainerField::NormalUnits`) —
    a file whose entire unit table is raw mirrors. Distinct from the four
    existing `manifest-empty-*` codes and reachable only through
    `FileEntry::new`, positioned **after** `units.is_empty()` (so a genuinely
    unit-less file keeps reporting `manifest-empty-units` — one code per
    outcome, §1) and **before** the coverage loop (so the shape error wins
    over a per-unit `unit_commit` error). Owed tamper row: F15.
  - R's `VerifyError::Decode` wrapper surfaces all nineteen unchanged (§2), so
    R's universe grows by nineteen without R minting anything.
- **2026-07-28 (M0 wave 5, D82)** — R appended one code in its unprefixed
  namespace, in the **same class as the 2026-07-28 R5 entry above** (bundle
  and manifest each well formed, the two inconsistent):
  `touched-file-without-revealed-unit`, on the new variant
  `VerifyError::TouchedFileWithoutRevealedUnit { file_id }`. R's universe:
  **85** distinct codes over **27** variants.

  It is the converse of D80's `revealed-unit-file-not-touched`, and the pair
  is why it is a second code rather than a widened first: a verdict must say
  which direction the bundle got `touched_files` wrong, and the two
  mutations are separately reachable (drop an entry vs. splice one in).
  With both in force `touched_files` is exactly determined by the revealed
  set, so any deviation in either direction is a named error.

  Two contract points worth recording:

  1. **The check is additive to a frozen order.** It runs at R5's coherence
     group 1b, after D80's group 1 and before the reveal-section rule. No
     previously-rejected input changes its reported code — group 1 still
     wins where both fire, and the inputs 1b newly rejects were previously
     *accepted*, so they had no code to change. Both precedences are pinned
     by tests rather than asserted in prose
     (`d82_group_order_*` in `verify::coherence`).
  2. **A stage-ordering trap the row had to be built around, recorded
     because it generalises.** `check_path_commits` runs earlier, in stage
     2's structural groups, and iterates the *bundle's* touched list. A
     fixture that splices an entry with an invented path or a junk salt
     therefore reports `path-commit-mismatch` and silently pins a
     **different, already-owned** outcome. The mutation only reaches 1b
     when the spliced `{path, path_salt}` pair is genuine — which is also
     the security point, since `path_salt = HKDF(W, "path-salt", file_id)`
     is a per-work constant and needs no forgery to copy. Both codes are
     pinned from the same fixture knob
     (`d82_a_junk_salt_is_claimed_by_the_earlier_path_commit_stage`), so
     the row cannot drift onto the wrong one.

- **2026-07-28 (M0 wave 5, R8 / D81)** — **no code minted.** R8's three
  pipeline mutations that all land on `unit-decrypt-failed` — flipped
  ciphertext byte, swapped unit, wrong `k_u` — were resolved by **D81** in
  favour of one row and two recorded non-rows, not a cause discriminator.
  An AEAD authentication failure is one bit by construction (a single
  Poly1305 tag comparison over key, nonce, AAD, ciphertext and lengths), so
  a cause code would be a claim to information the construction is built not
  to have; D81 evaluates and rejects the four candidate discriminators
  (ciphertext length, chunk-address recompute, speculative re-decryption,
  AAD introspection). The precedent it follows is C's own collapse one layer
  down, where `crypto-unit-aead-wrong-key` is the single row for the whole
  wrong-key/nonce/AAD/flip family.

  The contract consequence is §3-shaped and worth stating: **adding a
  `unit-decrypt-*` cause code later is not a routine append.** Appending
  codes stays routine; appending *this* one requires a decision that first
  defeats D81's four items, because the verifier would have to obtain the
  information from outside the AEAD — which in every candidate means an
  unauthenticated check displacing an authenticated one.

  D81 also forced a **checker** change rather than a code change, recorded
  here because it widens what "discharged" means: a Q8 spec case may now be
  discharged by a recorded non-row (`non_row`), not only by a row or a
  `pending` marker. It is constrained so the discharge still names a real
  row — the non-row's `collides_with` must resolve to a live or reserved row
  id — and both the non-row set and the discharged-case set are pinned
  outside the registry.

  **A third collision, found while implementing R8, of the same shape one
  commitment layer up.** R8's task text also names `wrong unit_salt →
  unit_commit mismatch`, which lands on `unit-commit-mismatch` — the code
  R8's own `altered manifest field, non-covered unit` row claims. It is the
  same argument as D81's, and it is worth stating because it generalises
  past the AEAD: **a salted commitment opening is one bit too.** The
  verifier recomputes `SHA-256(0x02 ‖ unit_salt ‖ bytes)` and compares it
  with the manifest's stored value; a mismatch says the *triple* is
  inconsistent and cannot attribute itself to a substituted bundle salt
  rather than to an altered manifest commit, because both are inputs to the
  one comparison. `VerifyError::UnitCommitMismatch` carries only `unit_id`,
  and a cause field would be reporting a sub-comparison that does not
  exist. The spec's `wrong-salt/unit-commit` case is in any event already
  discharged by C's primitive-level row, so a pipeline-level salt row would
  be a project addition claiming an owned outcome. Recorded as the non-row
  `pipeline-level-wrong-unit-salt` with a named test.

  The generalisation worth carrying forward: **the codes in R's namespace
  name the check that failed, not the field that was wrong.** Wherever a
  check is a single comparison over several inputs — an AEAD tag, a
  commitment opening, a Merkle root — asking for a cause discriminator is
  asking the verifier for information the comparison does not produce.

  R8 also brought R's unprefixed namespace to **full row coverage**: R7's
  `every_unprefixed_verify_code_has_a_row_or_a_named_owner` had two codes
  standing on `OWED_BY_ANOTHER_TASK` (`unit-decrypt-failed`,
  `unit-commit-mismatch`) and both are now rows, so that list is empty. It
  is kept rather than deleted, so the "named owner" escape stays available
  and deliberate the next time a code lands ahead of its row.

- **2026-07-28 (M0 wave 5, F15)** — **no code minted**, and the **M0 tamper
  matrix is COMPLETE (0 pending)** — Q14's gate condition, printed by the
  lane every run. F landed its registry slice
  (`antseal_core::test_util::tamper_rows_format`): **twenty fixtures, seven
  rows**, merged into `tests/tamper_matrix.rs`. Every row binds a code that
  already existed — `bundle-too-large` (D10 §1 tabled it for exactly this
  row), `cbor-nesting-too-deep`, `cbor-non-shortest-length`, and the two
  key-band pairs — which is the outcome §3 is meant to produce for a task
  whose whole job is writing rows.

  Four records:

  1. **Twenty fixtures, seven rows, and the ratio is the contract's own
     doing.** See the new §2 subsection above: one canonicality fault at four
     layers is four fixtures and one code, because wrapper arms delegate
     unchanged. F15's mapping table pins the `(code, layer)` pair, which is
     the finer instrument a per-layer code family would have been — without
     freezing "which layer" into fifteen permanent names.
  2. **The `cbor-` family has no reverse-coverage check, and six of its
     fifteen codes have neither a row nor a named owner** (`cbor-malformed`,
     `cbor-simple-value`, `cbor-tag`, `cbor-invalid-utf8`,
     `cbor-unexpected-type`, `cbor-int-out-of-range`). R7's check covers R's
     namespace and F23 will cover `bundle-`/`manifest-`; the `cbor-` family
     falls between them precisely *because* both merely delegate to it, so it
     belongs to neither exemplar sweep while being reachable through every
     schema surface. Owned by **F24**.
  3. **A length-valued mutation is now expressible as data.** The oversized
     row needed "an input of size *n*" without storing *n* bytes;
     `FIXTURES.json` distinguishes `source.kind = "file"` from
     `"synthesized"`, the latter carrying a recipe plus the length it
     produces. Any future cap row is a data row rather than a special case,
     and a test asserts no committed format fixture exceeds 64 KiB so the
     recipe cannot quietly become a file.
  4. **The two `layer()` accessors disagree about what "no layer" means**
     — recorded in §2 above, owned by **F26**. It only surfaced because F15
     asserts the layer on every fixture rather than the code alone.

  One obligation deliberately left open and re-homed: **D77 §6's mirror-only
  row** (`manifest-empty-normal-units`), which the decision names F15 for. It
  needs a byte mutation of a *nested* unit's `kind` — `FileEntry::new` refuses
  to construct the shape — and therefore the span primitive **F25** records.
  It is a project-added row with no `pending` marker, so it never bore on the
  gate; **F22** owns it by title.

- **Formal freeze**: Q7/Q8, with C14 ratifying the per-algorithm signature
  codes. Frozen for good at Q14 along with the rest of format v1.
