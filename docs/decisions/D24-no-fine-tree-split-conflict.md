# D24 — `--no-fine-tree` × `--split` on the same file

- **Status: RESOLVED — hard CLI error (no silent single-unit override); model is single-unit by construction either way**
- **Date: 2026-07-27**

## Context

`--no-fine-tree <glob>` files are permanently whole-file-reveal-only
(spec line 85) ⇒ exactly one whole-file unit (G5 model rule).
`--split blank-lines` requests sub-file reveal granularity for text
files (spec line 84). A text file matched by both asks for two
incompatible granularities. Register entry D24 ("silently force
single-unit vs. hard CLI error; model must be single-unit either way");
blocks G5, G6, G14, and U's flag validation.

## Decision

Two independent layers:

1. **CLI: hard error.** If `--split blank-lines` is active and any
   **text** file selected for splitting also matches a
   `--no-fine-tree` glob, `seal` aborts during argument/plan validation
   — before the consent gate, before any derivation or payment — with a
   distinct error naming the file and both flags, and suggesting the
   workaround (seal that file as a separate work, or drop one flag).
   Binary files matched by `--no-fine-tree` are **not** an error under
   `--split`: splitting never applies to binary files (G6), so no
   contradiction exists.
2. **Model: single-unit by construction.** G5/G14 expose no code path
   that splits a `--no-fine-tree` file — the model cannot represent the
   contradiction regardless of CLI bugs (defense in depth; G14 asserts
   the invariant).

## Rationale

1. **Permanence asymmetry**: unit boundaries are frozen forever at
   seal time. Silent single-unit would permanently discard the user's
   requested reveal granularity — a surprising, irreversible loss
   discovered only at first reveal. Re-running a failed command costs
   seconds.
2. **House style is loud**: the spec already mandates a warning for
   `--no-fine-tree` alone (line 85); the project's consent-first
   posture (U14 permanence gate, U17 loud safety aborts) treats
   ambiguous permanent choices as errors, not defaults.
3. **Clean `--json`/scripting contract**: a deterministic pre-flight
   error beats a silently divergent seal shape in automation (aligns
   with D51's hard-abort direction).

## Consequences

- G5/G14: no split path for `--no-fine-tree` files; G14 asserts.
- G6: documents that splitting applies only to fine-tree-covered text
  files.
- U13's flag validation (M1) implements the error with a distinct CLI
  error variant/exit code (U2 taxonomy); the error text names file +
  both flags. Until U13 lands, the rule lives in G14's assembly
  contract.
- No format impact (pure CLI semantics; nothing frozen at Q14 beyond
  what G5 already freezes).
