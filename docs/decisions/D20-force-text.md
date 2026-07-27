# D20 — `--force-text` semantics on invalid UTF-8

- **Status: RESOLVED**
- **Date: 2026-07-27**

## Context

Text detection is strict UTF-8 validity; `--force-text` forces text-mode
canonicalization onto files that fail it (spec lines 83, 149). The open
decision: deterministic lossy U+FFFD replacement (making text-mode
canonicalization **total** over arbitrary bytes) vs recording a forced-mode
flag in the descriptor. The verifier's raw-mirror check (spec line 121)
must be able to recompute `canonicalize_v(raw_mirror_bytes)` for any
sealed text file, forever.

## Decision

**Deterministic lossy U+FFFD replacement; text-mode canonicalization is
total. No forced-mode descriptor flag.**

1. Text-mode decoding is lossy UTF-8: every maximal invalid subpart is
   replaced with one U+FFFD, per Unicode §3.9 "U+FFFD Substitution of
   Maximal Subparts" — the policy implemented by Rust
   `String::from_utf8_lossy`. This is the single, frozen text-mode
   transform; it is exactly identity-on-decode for valid UTF-8.
2. Because lossy ≡ strict on valid UTF-8, the descriptor's existing
   `kind = Text` alone fully determines recompute semantics — a verifier
   applies text-mode canonicalization whenever the descriptor says text,
   with no second flag to consult. `--force-text` is purely a **seal-time
   gate** deciding whether invalid-UTF-8 input may enter text mode at all
   (without it, invalid UTF-8 classifies as binary).
3. G3 golden corpus fixtures MUST include invalid-UTF-8 inputs whose
   canonical outputs pin the maximal-subparts replacement byte-exactly
   (guarding against any alternative U+FFFD-count policy), and the
   independent cross-check (Q11) must reproduce them.

## Rationale

- Totality is required: R's `canonicalize(raw) == canonical` recompute must
  always run (G2's Do states this), and a text file forced from invalid
  UTF-8 always has a raw mirror whose bytes are invalid UTF-8.
- A descriptor flag adds a second wire field that changes nothing: the
  transform must be total and deterministic either way, and `kind = Text`
  already selects it. Fewer frozen fields, same information.
- Determinism/reproducibility: the maximal-subparts policy is standardized,
  stable in Rust std, and pinned forever by golden vectors regardless of
  any future std change (a change would fail G3's fixtures and force a
  deliberate format-version decision).

## Consequences

- G2 implements one total text-mode `canonicalize_v`; `--force-text`
  surfaces in U's CLI as an input-classification override only.
- The canonical rendition of a forced-text file contains U+FFFD where the
  original had invalid sequences; the raw mirror preserves the exact
  original bytes (uploaded per spec line 92), so no information is lost.
- G4's descriptor gains no new field.
