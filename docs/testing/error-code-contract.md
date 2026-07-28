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
| `manifest-` | F | manifest/bundle schema validation (F5–F9) |
| `crypto-` | C | HKDF, commitments, padding, AEAD, signatures (C2–C14) |
| `content-` | G | canonicalization, unit model, fine tree (G2–G13) |
| *(unprefixed)* | R | verification-pipeline outcomes (R1–R5) |

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
- **Formal freeze**: Q7/Q8, with C14 ratifying the per-algorithm signature
  codes. Frozen for good at Q14 along with the rest of format v1.
