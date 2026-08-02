# D47 — `vault export` format: re-encrypted single file, not a verbatim archive

- **Status: RESOLVED — `vault export` produces ONE file: the Q2-reserved
  magic `ANTSEAL VAULT EXPORT` + a versioned deterministic-CBOR header
  (own KDF block, fresh salt, AAD-bound) + a single AEAD over the full
  serialized logical vault state (cache excluded per D43). Same vault
  passphrase, proven by the unlock export performs; keyfile factor
  preserved; mandatory post-write self-verify; import validates
  everything before touching `~/.antseal/`. The register carried no lean
  ("verbatim archive vs re-encrypted single file"); decided for
  re-encrypted on two decisive properties the archive cannot have —
  whole-backup authentication and a deliberate interchange format that
  does not freeze U5's on-disk layout — with the archive's genuine
  advantages weighed and priced.**
- **Date: 2026-08-01** (M1 planning wave; blocks U12; register
  TODO.md:527, U-domain open decision 9, tasks/U.md:396)
- **Owning tasks: U12 (implement), U5 (layout independence), U2 (error
  classes), Q2 secret-guard (exclusion event when the literal lands)**

## Context

`vault export` must produce "a single encrypted backup file … capturing
everything needed to reveal/restore every work", and `vault import` must
reconstruct `~/.antseal/` on a clean machine; incomplete works must
survive the round trip so a resumable seal stays resumable
(tasks/U.md:149–154). This pair is what S19's M1 clean-tree E2E and the
M4 disk-loss drill exercise (tasks/S.md:241–251; MVP-SPEC.md:37,175).
Q2 reserved the magic string `ANTSEAL VAULT EXPORT` for exactly this
format, wired into the `secret-guard` CI lane (TODO.md:245;
testdata/README.md:103–113; CONTRIBUTING.md:45).

The options as registered (tasks/U.md:396):

- **A — verbatim archive**: pack the on-disk vault (header + encrypted
  store + config) into one container, unchanged, under the existing
  passphrase.
- **B — re-encrypted single file**: unlock, serialize the logical state,
  re-encrypt the whole payload under one fresh AEAD.

A third shape surfaced during analysis and is named so it stays rejected:

- **C — outer AEAD over the raw store bytes without unlocking** (KDF a
  passphrase, wrap the on-disk bytes): gets whole-file authentication
  without an unlock.

## Decision — Option B, with these normative properties

### Format (schema details are U12's; these properties are D47's)

```
file := MAGIC ("ANTSEAL VAULT EXPORT", exact bytes)
      ‖ header (deterministic CBOR: format_version, kdf block
                 {alg id, full params, fresh 16-B salt}, 24-B AEAD nonce)
      ‖ AEAD ciphertext (XChaCha20-Poly1305, workspace pin
                 chacha20poly1305 =0.11.0, Cargo.toml:173)
AAD  := MAGIC ‖ encoded header        // U6's construction, transplanted
```

- **Payload** = deterministic-CBOR serialization (project rule 5) of the
  full logical vault state: format/app versions, the vault's settings
  (wrap mode per U8/D50), the wallet record, every work record — journal
  state including **staged bytes for every incomplete work** (U12's
  resumability Accept, tasks/U.md:154) — anchors, receipts, paths, costs,
  bookkeeping (U18's export flag), **and a copy of `config.toml`**.
  Config sits beside the vault AEAD on disk (D42) but belongs inside the
  backup: import must reconstruct the whole directory, and encrypting it
  here is free. **Complete-work cache bytes are excluded** (D43 §3).
- **Passphrase**: the vault passphrase. Export performs a full unlock
  first, which *proves* the passphrase opens the data before it becomes
  the backup's only key. A separate export passphrase is NOT offered at
  MVP: the canonical surface gives `vault export|import` no flags
  (tasks/U.md:13), and a second — likely weaker, likely improvised —
  passphrase over the same `W` is a footgun with no requirement behind
  it. Fresh random 16-B salt, KDF algorithm + params copied from the
  vault header (they already satisfy D40's floors); never the vault's
  salt, never the vault's derived key (a distinct AEAD domain gets a
  distinct key).
- **Keyfile factor preserved**: the exported wrap-mode record is carried
  as-is, so an export of a keyfile-wrapped vault requires the same
  keyfile at import — U12's Accept verbatim ("unreadable without the
  passphrase (and wrap factor if configured)", tasks/U.md:152). The
  keyfile is a portable file by design (D50); nothing machine-bound
  exists at M1 (D50 defers the OS keystore precisely so this holds —
  when a keystore wrap lands, its export MUST re-wrap to portable
  factors; recorded there as a binding constraint).
- **Write discipline**: temp + fsync + rename (U5, tasks/U.md:62), then a
  **mandatory self-verify before success is reported**: re-open the
  written file from disk, KDF + decrypt, and compare a digest of the
  decoded payload against the in-memory serialization. This is R13's
  build-then-`verify_bundle` house pattern (tasks/R.md:158) applied to
  the one artifact whose failure is discovered at disaster time. It
  closes the entire encrypted-wrong class that re-encryption uniquely
  risks over a verbatim copy.
- **Import**: parse the header under **D40 §3's KDF caps** (the header is
  attacker-suppliable input and the KDF runs pre-authentication — same
  resource-bomb, same rule, second call site), KDF, decrypt, and validate
  the complete payload in memory (or a temp dir) **before** touching
  `~/.antseal/`; then install atomically. Refuses an existing vault
  without explicit confirmation (tasks/U.md:149); a `format_version`
  above the supported range fails with the "created by newer antseal"
  error, mirroring U5's header rule (tasks/U.md:64). A failed import
  leaves the existing directory byte-identical.
- **Versioning**: `format_version` is the export schema's own, decoupled
  from U5's on-disk layout version. Identification is by magic, not file
  extension (extension advisory only; naming is U12's).

### Why the verbatim archive (A) loses

1. **It freezes U5's on-disk layout as an interchange format.** An
   archive's "schema" is whatever the vault happens to look like on disk
   — filenames, per-record framing, incidental structure. Import must
   then accept every historical layout forever, so every future layout
   migration (the thing U5's versioned header exists to permit,
   tasks/U.md:64) grows an import shim. Option B's import maps a
   deliberate, versioned schema into the *current* layout; the layout
   stays an implementation detail.
2. **No whole-backup authentication.** Per-record AEADs (D42's rider)
   detect tamper and splice — but not **absence**. A verbatim archive
   with one work record dropped in transit or by bit-rot imports
   "successfully" minus a work, silently. A backup format that cannot
   detect a missing record fails its one job. Option B's single AEAD
   makes any deletion, truncation, or flip an authentication failure.
   (Fixing this inside A means an authenticated manifest-of-contents —
   i.e. building B's machinery and keeping A's costs.)
3. **It cannot exclude the D43 cache without ceasing to be verbatim** —
   selective packing of an encrypted store means understanding and
   re-framing records, which is again B's machinery.

Priced honestly, A's real advantages: it needs **no unlock** (a locked
vault can be backed up, croned, by copying bytes), and it has **no
re-encryption bug class** (a copy cannot be encrypted wrong). The second
is neutralized by the mandatory self-verify; the first is genuinely
surrendered — see residual risks. (Nothing stops a user rsyncing
`~/.antseal/` as a *bonus* raw copy; that is disk hygiene, not the
supported interchange format, and it inherits none of U12's guarantees.)

### Why C loses

C gets A's no-unlock property with B's whole-file AEAD — but the export
passphrase is then **unverifiable at export time**: nothing proves the
typed passphrase matches the vault's, and a typo produces a backup that
opens to garbage, discovered at disaster time. Verifying it means
decrypting the inner store — which is the unlock C exists to avoid.
Collapses into B.

## Error classes (names advisory; U2 owns codes, tasks/U.md:26)

`export-self-verify-failed` (distinct, loud — the written file was bad);
`import-auth-failed` (wrong passphrase / tampered or truncated file — one
class, deliberately, like U6's vault-auth); `import-newer-version`;
`import-refused-existing-vault`; D40's `vault-kdf-params-out-of-range` at
the import header.

## Tests (house checklist: new format ⇒ vectors + tamper cases)

- Round trip: export → wipe → import → `restore` byte-identical
  (tasks/U.md:151); incomplete-work resumability round trip
  (tasks/U.md:154); kill-during-export leaves no partial file at the
  target path; failed import leaves the existing vault untouched.
- Tamper set: flip any ciphertext byte → auth failure; truncate → auth
  failure; edit magic / version / KDF params in the header → distinct
  errors (header edits break the AAD; version/magic break parse); D40 cap
  bomb (huge `m_cost`) → rejected before the KDF runs.
- **No committed fixtures, ever**: exports are exactly what the
  `secret-guard` lane hunts (testdata/README.md:103–113). All test
  artifacts are generated at runtime in temp dirs from the documented
  non-secret test seed. The `ANTSEAL VAULT EXPORT` literal entering
  source at U12 is the anticipated guard-exclusion event — extend the
  guard's exclusions in the same PR, as the convention requires
  (testdata/README.md:110–113).

## Spec conformance

MVP-SPEC.md:143 says only "`vault export`/`import` for encrypted backup";
lines 172/175 demand the clean-tree restore and disk-loss drill work.
Option B satisfies all three; no divergence. Nothing here enters the Q14
freeze — the export format is vault surface, versioned by its own header,
outside the v1 bundle/manifest universe.

## Consequences and integration updates

1. **tasks/U.md U12 (line 149)** — "format per open decision 9" → per
   D47; add the self-verify, the in-memory-validate-then-install import
   rule, and the D40 cap inheritance to Do/Accept.
2. **tasks/U.md open decision 9 (line 396)** — mark resolved by D47.
3. **U2** — the error classes above.
4. **D41 note** (sibling decision, non-interactive passphrase): whatever
   channel D41 picks is what makes scripted/automated exports possible,
   since export now requires an unlock. Recorded here as a consumer of
   D41's outcome, not a constraint on it.
5. **S19** — no change needed: lean exports make its no-staged-bytes
   restore proof automatic (D43 §3).

## Residual risks (for the register)

- **Export requires an unlock** — no locked-vault backup via the
  supported format, and automated backup needs D41's non-interactive
  channel. Accepted: a backup whose passphrase was never proven is worse
  than an inconvenient one.
- **Export is a full-state snapshot under one key**: a stolen export ≡ a
  stolen vault (same passphrase, same wrap factor). Already the U18/U29
  nag posture — "treat the passphrase and any export as a long-term
  high-value key" (MVP-SPEC.md:184) — no new exposure, but worth naming.
- Memory footprint: import validates the payload in memory; with D43's
  cache excluded the payload is record-scale, so this is fine at MVP and
  a streaming import is a v1.1 concern only if an everything-included
  export option ever lands.

## Discovered-work candidates

- **Q2/CI:** the secret-guard exclusion event for the source literal
  (same-PR, reviewed — already anticipated by the convention; this is a
  reminder, not new machinery).
- **v1.1 register (shared with D43):** everything-included export option;
  if taken, revisit streaming import.

## Amendment (2026-08-02, S29): the payload's journal rule, restated at the entry-key level

This record inherited D43 §3's exclusion as a whole-work property —
"**Complete-work cache bytes are excluded** (D43 §3)" in the Payload
bullet, and Consequences item 5's "lean exports make [S19's]
no-staged-bytes restore proof automatic". D43's amendment of the same date
corrects the underlying rule; the export format is where it is enforced,
so it is restated here in the terms the format actually speaks.

**Corrected payload rule.** The `journal` key of a work (payload map key
1) carries **every** journal entry when the work's state is not
`complete`, and for a `complete` work carries **only the entries below
`UNIT_ENTRY_BASE`** — 0 `STATE_ENTRY`, 1 `PLAN_ENTRY`, 2
`MANIFEST_BLOB_ENTRY`. The entries at 3 and above are the staged unit
ciphertexts (the D43 cache) and are never exported. Import validates the
same predicate and rejects a `complete` work carrying any entry
`>= UNIT_ENTRY_BASE`.

Without entry 2 an imported complete work has no address for its
encrypted manifest and therefore cannot be restored on a content-addressed
network at all (S29; D43's amendment carries the full diagnosis). That
made this format lossy in the one direction a backup format may never be
lossy: it round-tripped everything except the thing that makes a work
recoverable, and only after the vault was gone.

**No version bump.** `EXPORT_FORMAT_VERSION` stays 1. The schema is
unchanged — same keys, same types, same ordering — and only the writer's
*selection* of entries widens. Both directions of compatibility hold: a
pre-amendment reader accepts nothing this writer emits that it would have
rejected except a complete work's entries 0–2, which it rejects with the
D43 validator message; and this reader accepts every pre-amendment file,
since "no journal entries at all" still satisfies the new predicate
vacuously. Old backups therefore import cleanly and stay unrestorable for
their complete works — the data was never written, so no reader can
recover it. That is the residual risk below.

The three §Rejected-alternatives arguments are untouched: this is still a
single authenticated CBOR payload, still not a verbatim directory copy
(the rejection reasoning at Consequences "It cannot exclude the D43 cache
without ceasing to be verbatim" now reads *staged unit blobs* for
*cache*), and the memory-footprint note still holds — a complete work
contributes record-scale bytes plus one manifest ciphertext, not content.

Consequences item 5 is superseded: S19's drill gets its no-staged-bytes
property from the unit exclusion, which is intact, and no longer gets a
manifest-fetch from it. See D43's amendment for why that trade is the
right one.

## Residual risk added by the amendment

- **Backups written before 2026-08-02 cannot restore their complete
  works.** The locator was never in the file. They import without error —
  correctly, since the format allows the entries to be absent — and fail
  at restore with `ManifestUnavailable`. Nothing in the format can repair
  this after the fact; the remedy is to re-export from a live vault, which
  still holds the journal. No shipped release predates the fix, so the
  exposure is limited to development-tree backups.
