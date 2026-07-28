# D76 — Split `file_salt` into separate raw/canonical salts? **No, for v1**

- **Status: RESOLVED — NO for v1. One `file_salt` continues to salt both
  `raw_commit` and `canon_commit` (MVP-SPEC.md line 95). The recorded lean
  is confirmed; its *stated reason* is overturned.**
- **Date: 2026-07-28**
- **Owning tasks: C6/C2** (would have consumed F4/F8 §7.14, C7, R4)
- Surfaced 2026-07-28 by D28's residual-risk analysis (candidate 2,
  `docs/decisions/D28-full-reveal-strictness.md` lines 489–494).

## Context

Spec line 95 uses **one** 16-byte per-file salt for two commitments:

```text
raw_commit   = SHA-256(0x03 ‖ file_salt ‖ raw_bytes)
canon_commit = SHA-256(0x04 ‖ file_salt ‖ canonical_bytes)
```

both implemented from the single opaque `FileSalt`
(`crates/antseal-core/src/crypto/commit.rs:66` and `:75`; `canon_commit`'s
doc comment already says "Shares `file_salt` with `raw_commit` **by
design**"), derived from the one `"file-salt"` registry label
(`crates/antseal-core/src/crypto/hkdf.rs:26`, `:274`).

D28 made a full reveal strict, which makes `file_salt` disclosure
unconditional on that shape rather than avoidable by omission, and named the
consequence as its own residual: a recipient who is shown the canonical bytes
and handed `file_salt` also holds an offline oracle over `raw_commit`.

D76 asks whether v1 should split the salt in two — `canon_salt` for
`canon_commit`, `raw_salt` for `raw_commit` — so that a canonical-only full
reveal never opens the raw commitment.

## What the code does today

**Disclosure is gated to exactly one shape.** `derive_file_salt` returns the
opaque `FileSalt`, which has no byte accessor
(`crypto/hkdf.rs:266–276`). The only public byte path in the crate is
`FullFileRevealDisclosure::file_salt_bytes`
(`crypto/disclosure.rs:341–343`), reachable only with a
`FullFileRevealContext` witness that refuses anything but exact non-mirror
coverage (`crypto/disclosure.rs:248–268`). `PartialRevealDisclosure` has no
slot for one, proved by a `compile_fail` doc-test
(`crypto/disclosure.rs:166–177`). Verifier-side, D28's rows 1–2 reject a
`file_salt` on any `¬full(F)` file
(`crates/antseal-core/src/verify/file_stages.rs:58–59`).

**A raw mirror exists iff raw ≠ canonical.** `needs_mirror` is byte
inequality and nothing else (`crates/antseal-core/src/content/mirror.rs:104`;
property-tested at `mirror.rs:566`). Binary files never have one — they have
no canonical rendition, so their units *are* the raw bytes.

**The manifest already publishes the raw byte count.** A text file's raw size
reaches the manifest **only** as its mirror unit's `true_length` and range
`[0, raw_size)` (`content/mirror.rs:20–24`;
`crates/antseal-core/src/manifest/body.rs:736–742`: "A text file's *raw* byte
count travels as its raw-mirror unit's `true_length`"). Both are plaintext
manifest fields, present in **every** bundle including a zero-unit partial
reveal.

**`raw_commit` is unconditional; `canon_commit` is text-only.**
`FileEntry` stores `raw_commit` as a plain field (`manifest/body.rs:655`)
while `canon_commit` lives inside `CanonMode::Text`
(`manifest/body.rs:213–223`), so `Binary` cannot hold one.

**Wire shape.** §7.14 key 1 `file_salt` is `req`, tier **[P]** —
decidable from the one entry being decoded, with no reference to the manifest
(`docs/format/registry-v1.md` §7.14 key 1, tier table at §0).

## The exposure, quantified

`file_salt` is disclosed **iff** `full(F)`. Walk every case where that holds
and ask what the recipient learns about bytes they were not shown.

| file shape | does `file_salt` open anything unshown? |
|---|---|
| **Binary** | No. `raw_commit` is the whole-file commitment the full-reveal concat opens directly (row 7, `verify/file_stages.rs:64`). The bytes are shown. |
| **Text, raw == canonical** (no mirror) | No. `raw_commit` commits the same bytes as `canon_commit` under a different tag, and those bytes are shown. The recipient can *check* `raw_commit` — a check R4 deliberately declines to run (`verify/file_stages.rs:142–149`) — which is a gain, not a leak. |
| **Text, raw ≠ canonical, mirror revealed** | No. The raw bytes are disclosed outright; rows 9–10 open `raw_commit` and re-derive the canonicalization (`verify/file_stages.rs:66–67`). |
| **Text, raw ≠ canonical, mirror withheld** | **Yes — this is the whole residual.** |

So the exposure is a single shape: a fully revealed **text** file that
**needs** a mirror and whose bundle does **not** carry it.

### Is that shape reachable honestly? Yes.

`RevealSelection::WholeFile` and `::All` both include the mirror; only
`::UnitIds` is constrained, and it *rejects* a named mirror id
(`content/mirror.rs:187–192`, `RawMirrorNotUnitSelectable`). Therefore
`--units <every normal id>` is the one CLI path that reaches `full(F)`
without the mirror — and D28 explicitly blesses it with two positive
fixtures, `full-reveal-via-enumerated-units` and `full-reveal-without-mirror`
(`docs/decisions/D28-full-reveal-strictness.md` lines 276–277). This is not
an adversary-only shape. It is "show my whole document, not my CRLFs".

### What the oracle actually yields

The recipient holds canonical bytes `C`, raw size `R` (from the mirror's
`true_length`), the fact `raw ≠ canonical` (from the mirror's mere
existence), `file_salt`, and `raw_commit`. They enumerate raw pre-images of
length `R` that canonicalize to `C` under D21's frozen pipeline (decode →
strip all leading U+FEFF → CRLF→LF then lone CR→LF → NFC) and hash each
against `raw_commit`.

The marginal yield is **smaller than D28's write-up implies**, because the
size delta `d = R − |C|` already partitions that space before a single hash
is computed: `k` leading BOMs contribute `3k`, each CRLF contributes `+1` per
LF in `C`, a lone CR contributes `0`, an NFD sequence a per-character amount.
For the overwhelmingly common uniform-convention file, `d` alone identifies
the convention. The oracle resolves only the **residual ambiguity among
same-length pre-images** — chiefly lone-CR versus a compensating
normalization difference, or which mixture of BOM/EOL/NFD sums to the same
`d`.

Content is not at stake in either direction: `C` is disclosed by
construction in this shape. What leaks is authoring-platform metadata —
line-ending convention, leading-BOM count, normalization form.

## Options

### Option A — keep one salt (v1 as specified)

### Option B — split into `canon_salt` and `raw_salt`

A ninth HKDF label; §7.14 grows a key; C6's two commitment functions take
different salt types; C7 grows a second witness.

## Decision

**Option A.** One `file_salt`, unchanged. Recorded so v1.1 revisits this
deliberately rather than by omission.

## Rationale

### 1. The recorded lean's stated reason does not survive scrutiny — say so

TODO.md registered this as "**NO for v1** — it needs a new HKDF label against
C2's frozen 8-label registry". That is the **weakest** argument available and
should not be the one anyone relies on.

C2's info encoding is `u8(len(label)) ‖ label ‖ LE64(id)`
(`crypto/hkdf.rs:190–197`), and its own module docs state the point of the
length prefix explicitly: the map is injective "**by construction** — not by
the accident that the current labels happen to be prefix-free — so **any
future label can be added safely**" (`crypto/hkdf.rs:12–16`). There is no
cryptographic obstacle whatsoever. "Frozen" (`crypto/hkdf.rs:33`) means
*adding a label is a format event*, and pre-Q14, with nothing sealed, a
format event costs: widening `Label::ALL: [Self; 8]`
(`crypto/hkdf.rs:123–132`), updating two assertions
(`crypto/hkdf.rs:431`, `:441–450`), and regenerating
`testdata/vectors/v1/crypto/` plus `FROZEN.sha256`. That is an afternoon of
bookkeeping, not a reason to decline.

The decision stands on the three arguments below instead.

### 2. It would push §7.14 off tier [P] and make the entry undecidable at F8

Today `file_salt` is `req` [P] (`docs/format/registry-v1.md` §7.14 key 1): F8
validates a full-reveal entry from the entry's own bytes. Under a split,
neither salt can be unconditionally required —

```text
canon_salt present ⟺ full(F) ∧ F.canon = Text
raw_salt   present ⟺ full(F) ∧ (F.canon = Binary ∨ F's mirror ∈ revealed)
```

— because a binary file has no `canon_commit` to open
(`manifest/body.rs:213–223`) and a mirror-less text full reveal has no raw
bytes to bind. Both conditions read the **manifest**: `CanonMode` for the
first, and `CanonMode` *plus* the intersection of the revealed set with the
manifest's mirror unit for the second. Both are tier **[R]** by the registry's
own definition (`docs/format/registry-v1.md` §0, validation tiers), and **D78** forbids bundle
schema validation from opening the embedded manifest at all. F8 would no
longer be able to decide whether a §7.14 entry is well formed — the exact
failure mode D75 rejected in its rationale 1
(`docs/decisions/D75-full-reveal-cover-shape.md` lines 33–40).

There is a second-order casualty. §7.14's shape consequence 1
(`docs/format/registry-v1.md` §7.12, non-covered-unit reveal) records that "missing `file_salt`" is
realized as a **missing entry**, not an entry with a missing key —
*precisely because* key 1 is `req` at schema level, so F8 rejects a
key-1-less entry as `bundle-missing-key` before R4 runs. Split the salt and
that stops being true: D28's rule 3 would have to become a per-key rule,
changing the realized error shape of an already-resolved decision. D74's
single-code argument depends on the same fact
(`docs/decisions/D74-extraneous-full-reveal-s-root.md` lines 159–164). A
salt split silently re-opens both.

### 3. It roughly doubles a permanent code surface, for a metadata delta

D28 froze four reveal-shape codes and D74 a fifth
(`crates/antseal-core/src/verify/error.rs`). `FullRevealMaterial` is a
two-valued discriminator; splitting makes it three-valued, so the missing arm
becomes `...-canon-salt` / `...-raw-salt` / `...-s-root` and the leak arm
likewise — plus a D74-shaped *extraneous* arm ("`raw_salt` present on a full
reveal whose mirror is not revealed"), which the D74 precedent obliges us to
reject rather than ignore. Five permanent codes become eight or nine. D30 §3
makes each append-only and permanent at Q14
(`docs/testing/error-code-contract.md:84–101`), with matching tamper rows and
Q8 registry entries for each.

### 4. The split does not eliminate the leak — it removes one confirmation step

This is the decisive measurement. After a split, a recipient of a
mirror-less text full reveal still holds `C`, still holds `R` (the mirror
unit's `true_length`, plaintext manifest data — `manifest/body.rs:736–742`),
and still knows raw ≠ canonical from the mirror's existence
(`content/mirror.rs:104`). The candidate partition by `d = R − |C|` is
untouched. What disappears is only the ability to *confirm* which of the
same-length candidates is true.

Buying that, at the cost of items 2 and 3, is the wrong trade. Eliminating
the metadata leak properly would require withholding raw size — i.e. changing
what the plaintext manifest discloses, which is a spec-level redesign of line
95/98, far outside a salt split.

### 5. The hiding claim C19 guards is untouched

C19's executable attacks are against the **partial**-reveal oracle
(`crypto/confirmation_attack.rs:140–243`): a one-unit recipient must not be
able to confirm the whole document. That is unaffected by D76 in either
direction — no `file_salt` of any spelling is disclosed on a partial reveal
(`crypto/disclosure.rs:24–39`, `:166–177`). The D76 residual lives strictly
*inside* the full-reveal shape, where the canonical content is shown anyway.
So the security-assumptions block C20 cites is not weakened by choosing
Option A, and C19 needs no new variant.

## Cost, stated honestly

v1 has **no** shape that shows a text file's whole canonical content while
withholding its raw-form fingerprint. A sealer who wants the fingerprint
withheld has exactly two options, both real losses:

1. issue a whole-file reveal *including* the mirror — which discloses the raw
   bytes outright, so there is nothing left to fingerprint; or
2. withhold one unit, making it a partial reveal — no `file_salt`, no
   whole-file openings, and a sized blackout in the redaction view (R19).

That is the price of Option A, and it is charged only on text files that
needed a mirror.

## Residual risk (the v1.1 reader's brief)

**Exact shape.** A `.sealproof` bundle that fully reveals a file `F` where
`F.canon = Text` and `F` has a raw-mirror unit that the bundle does **not**
reveal.

**What the recipient can determine.** Which raw pre-image, among those of
length `R = mirror.true_length` that canonicalize to the disclosed canonical
bytes under the descriptor's recorded Unicode version, is the true one. In
practice: the original's line-ending convention, its leading-BOM count, and
its normalization form.

**What they cannot.** Any content byte not already disclosed (the canonical
bytes are shown in this shape by definition); anything about any other file
(`file_salt` is per-`file_id`, `crypto/hkdf.rs:274`); anything at all from a
partial reveal (no `file_salt` is disclosed, and rows 1–2 reject one that
appears).

**Magnitude.** Bounded by the pre-image space of length `R` — for a uniform
file typically a single candidate already implied by `d = R − |C|`, so the
oracle's marginal yield is often zero.

### What triggers revisiting — name these, do not rediscover them

1. **Any new reveal shape that discloses `file_salt` without disclosing the
   canonical bytes.** Today the two are inseparable (C7's witness requires
   exact non-mirror coverage). Break that coupling and the oracle stops being
   a metadata oracle and becomes a *content* oracle — the C19 attack, back.
   **This is the trigger that matters; it converts D76 from a preference into
   a bug.**
2. **`raw_commit` gaining a meaning not derivable from the canonical form** —
   e.g. a v1.1 notion of "original with attachments", or a raw-domain fine
   tree. Then `raw_salt` is needed for binding reasons regardless of privacy,
   and the split comes free with a change already being made.
3. **A CLI default that withholds the mirror on a whole-file reveal.** Today
   `WholeFile` and `All` include it (`content/mirror.rs:159–170`), so the
   exposed shape requires deliberate `--units` enumeration. If that ever
   inverts, the residual goes from opt-in to default and the calculus changes.
4. **Any format-version bump for another reason.** Item 2 of the rationale is
   a *pre-Q14 layering* cost, not a permanent one; at a v2 where §7.14 is
   being reshaped anyway, re-run this analysis rather than inheriting the
   answer.

### Of the rejected option (B), stated plainly

Had we split for v1: F8 could not validate a full-reveal entry without the
manifest, contradicting D78; D28's rule-3 error shape and D74's single-code
argument would both need reworking; and the reveal-shape code surface would
roughly double — all to remove a confirmation step for a metadata fact whose
structural half the plaintext manifest publishes unconditionally anyway.

## Consequences — what this freezes

- **C2**: the HKDF registry stays at **8 labels** for v1; `"file-salt"` keeps
  both consumers (`crypto/hkdf.rs:26`).
- **C6**: `raw_commit`/`canon_commit` keep the shared `FileSalt` parameter
  (`crypto/commit.rs:66`, `:75`). The "shares `file_salt` by design" comment
  is now a decision reference, not an observation.
- **C7**: one witness, one accessor. `FullFileRevealContext` /
  `FullFileRevealDisclosure::file_salt_bytes` are unchanged.
- **F4/F8**: §7.14 key 1 stays `req` tier **[P]**
  (`docs/format/registry-v1.md` §7.14 key 1). Key 3–23 stay reserved; a future
  `raw_salt` would take a reserved slot, not displace key 1.
- **R4**: rows 1–5 and the `FullRevealMaterial` two-valued discriminator are
  unchanged; no new codes.
- **No format impact**: no new HKDF label, no new wire key, no new domain
  tag, no new error code.

## Spec conformance

Consistent with the spec, and does not extend it. Line 95 specifies one
`file_salt` covering both content commitments; Option A is that text
unchanged. The residual documented above is a property of the spec's own
construction, not of an implementation choice, which is why eliminating it
would be a spec-level change (D28 said as much — line 416).

## Recorded outcome

**2026-07-28 — RESOLVED: NO for v1.** One `file_salt` continues to salt both
`raw_commit` and `canon_commit`. The recorded lean is **confirmed**; its
stated reason (the frozen HKDF registry) is **overturned** as near-costless
pre-Q14 and replaced by the layering, code-surface, and
leak-is-not-eliminated arguments above. Residual risk and its four revisit
triggers are recorded for v1.1.
