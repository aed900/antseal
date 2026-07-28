# Changelog

Notable changes to antseal, newest first.

This file starts at the **format-v1 freeze**. Before it there were no releases
and no external consumers, so there was nothing a changelog could promise; the
per-wave record of how the project got here lives in `TODO.md`'s change log
and in `docs/decisions/`.

**Format versions are the load-bearing entries.** A format version, once
frozen, is verifiable forever (MVP-SPEC.md line 123). Entries under a
`[format-vN]` heading state exactly what became permanent, because that is
what a third-party verifier implements against and what a later release may
not silently change.

## [format-v1] — 2026-07-28

The M0 format freeze (task **Q14**). Everything listed here is **permanent**:
a v1 `.sealproof` bundle produced today must verify against every future
release, so these definitions can be extended under a new version but never
changed under v1.

### Frozen

- **Deterministic CBOR profile** — RFC 8949 §4.2.1 canonical form, encoder
  pinned `minicbor =2.3.0` (D7/P10), with 15 distinct strict-decode rejection
  classes (F3) and 19 parser cap constants (D10).
- **The v1 wire registry** — `docs/format/registry-v1.md` and its machine
  mirror `registry-v1.json`: every map key, CBOR type, presence rule, exact
  byte length, tuple shape, enum value and reserved range (F4/D8). Both files
  are now under an append-only freeze digest (`docs/format/FROZEN.sha256`,
  Q50).
- **Hash domain tags** `0x00`–`0x06`, one registry, one `tagged_sha256` helper
  (C1).
- **HKDF-SHA256 derivation** — the length-prefixed injective info encoding and
  the full 8-label registry, with the sentinel id (C2/C3).
- **Signature context string** `antseal-manifest-v1`, framed `ctx ‖ 0x00 ‖
  body` (C12).
- **`sig_policy` algorithm ids** — `0 = ed25519`, `1 = ml-dsa-65`, `2..=15`
  reserved and rejected (D17), pinned in both directions across C's semantic
  registry and F's wire registry.
- **Unicode version** `unicode-17.0.0` via `unicode-normalization =0.1.25`,
  with the canonicalization pipeline decode → BOM strip → EOL → NFC
  (D20/D21/D25). Shipped tables are retained forever.
- **The GGM fine tree** — `(level, index)` node addressing (D9), MSB-first
  indexing, 16-byte leaf salts, and the leaf-level cover payload
  `salt_i ‖ 0x00·16` (D83).
- **The stable error-code universe** — 191 codes across seven families,
  append-only, snapshotted at `testdata/error-codes/v1/CODES.txt` (D30/Q52).
- **The verification-report byte format**, report **v1**
  (`REPORT_VERSION = 1`) — byte-deterministic compact JSON, declaration-order
  fields, no floats, lowercase hex (D29/R32).
- **The golden-vector set** — 12 files, 11 kinds, pinned by
  `testdata/vectors/v1/FROZEN.sha256` and retained indefinitely (Q6).

### Explicitly NOT frozen

- **Anchor-artifact internals** — DER nesting depth, certificate counts within
  a validated chain, `.ots` op counts. These are verifier policy over foreign
  formats and are set at M2 against real captured artifacts (**D84**). What
  *is* frozen is the envelope: that each is an opaque CBOR `bstr` in its
  registered key, D10's byte and count caps over those fields, and rules
  F1–F4. This is **not** an exception to line 123 — M0 and M1 render every
  anchor `absent`, so no released verifier's verdict depends on artifact
  internals.
- **Report versions after v1.** The freeze fixes report v1. M2's anchor stage
  will carry states v1 does not and will ship report v2; line 123 promises
  that v1 reports stay verifiable, not that v1 is the last version.
- **`--split blank-lines` boundary semantics** (D22) — seal-time CLI
  behaviour, not verification law. Each seal's resulting ranges are permanent;
  the rule that produced them is not.
- **ML-DSA signing mode** (deterministic, `rnd = 0³²`, D15) — not encoded in
  the format, so a future version may switch without a format bump.

### Known limitations recorded at the freeze

- The independent cross-check reaches **T1 with no external oracle** for
  salted commitments, unit padding and the GGM tree, and no oracle can exist —
  those constructions are this project's own. ML-DSA-65 is the best-covered
  surface, at **T0** against NIST ACVP.
- 65 `manifest-`/`bundle-` schema-shape codes carry a named owner rather than
  a tamper row (**F39**); the row policy is per family and is deliberately not
  decided here.
- Nothing in this repository has been pushed to a remote as part of this
  freeze, and 7 of the 18 CI contexts have not run their present content
  remotely. Local evidence only.
