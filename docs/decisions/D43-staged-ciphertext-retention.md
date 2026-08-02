# D43 — Staged-ciphertext retention after successful finalize

- **Status: RESOLVED — RETAIN. On `finalize_batch` success the staged
  bytes are reclassified journal → cache in place (same bytes, state
  tag), stay inside the AEAD boundary, and are excluded from `vault
  export`. The journal/cache split is the load-bearing line: journal
  bytes (work not complete) are resume-critical, never prunable, always
  exported; cache bytes (work complete) are integrity-rechecked on every
  use, fall back to `get_data` on any mismatch, and their loss is never
  an error. The register carried no hard lean; the task texts (R16, U27,
  spec line 36) were already written local-copy-first — CONFIRMED and
  completed with the export rule and the prune consequence neither had
  stated.**
- **Date: 2026-08-01** (M1 planning wave; blocks U9 now, feeds U27/U28 and
  R15/R16 at M3; register TODO.md:523, U-domain open decision 5,
  tasks/U.md:392)
- **Owning tasks: U9 (record store + retention), U12/D47 (export
  content), S10/S11 (journal states), R16/U27 (M3 consumers), S14 (restore
  fallback — proposed amendment)**

## Context

Before payment, the journal persists "the staged ciphertext bytes of
every unit (plus each unit's nonce and target address)" (MVP-SPEC.md:145;
S10, tasks/S.md:131). Resume re-uploads those exact bytes and abandons the
work if they are unavailable — the `(k_u, nonce)` single-use guard (S11,
tasks/S.md:144–148). All of that is settled. The open question
(tasks/U.md:392) is only what happens to the bytes **after**
`finalize_batch` succeeds: "keep as local cache (serves `show` snippets,
reveal/restore without network) vs prune (lean vault)". U9's Accept defers
to this record (tasks/U.md:117).

## What reveal actually needs (the decisive evidence)

A `.sealproof` bundle **embeds the revealed units' ciphertexts**
(MVP-SPEC.md:112–114 "embedded ciphertext"; the storage-linkage layer
verifies those embedded bytes against the manifest addresses,
MVP-SPEC.md:119). So bundle *construction* must hold ciphertext bytes, and
R16 already specifies where they come from:

> "Gather ciphertexts for **all** units of every touched file (boundary
> Merkle paths need the whole file's leaves): **prefer byte-identical
> staged journal bytes, else fetch from Autonomi via S** using manifest
> addresses" (tasks/R.md:194)

with the Note: fetching all touched-file units "is unavoidable for
boundary-path computation without a persisted tree cache"
(tasks/R.md:200). Two consequences:

1. Reveal-time sourcing is **cache-first with network fallback** — the
   spec's own sentence has the same shape: "Fetches ciphertext from
   Autonomi **when no local copy exists**" (MVP-SPEC.md:36). The fetch is
   the fallback, not the design center.
2. Pruning is not "reveal pays one unit's fetch": revealing one unit of an
   n-unit fine-tree file requires **the whole file's ciphertexts** (every
   leaf feeds the tree rebuild). Prune converts every partial reveal into
   a full-file network round-trip against a young network
   (MVP-SPEC.md:180) — for a command whose UX moment is an interactive
   consent prompt (U29).

U27's `show` snippets have the same dependency: "decrypted staged
ciphertext for exact sealed bytes, else current local file marked 'may
differ' …, else omitted" (tasks/U.md:323). Only the cache gives the
exact-sealed-bytes row.

## Decision

### 1. Retain, as a state transition, not a copy

On the S10 state machine's `finalizing → complete` transition the staged
bytes are **reclassified in place** as cache. Nothing moves; the record
store tags the class. Both classes sit inside the AEAD boundary (D42;
MVP-SPEC.md:143 lists the seal journal in the encrypted set — the bytes
are already public-destined AEAD ciphertext, so this is uniformity and
integrity, not confidentiality).

### 2. The two classes have different contracts

| | **journal** (state ≠ complete) | **cache** (state = complete) |
| --- | --- | --- |
| role | resume substrate (S11); byte-identical re-upload | serve U27 snippets, R16 gathering, restore fallback |
| integrity | S10's address recompute; failure ⇒ staged-bytes-unavailable ⇒ **abandon** (tasks/S.md:134,148) | recheck on every use (S4 address recompute vs manifest address); mismatch ⇒ warn + silently refetch via `get_data`; never an error, never abandon |
| prunable | **never** — deletion *is* abandonment, which is S11's deliberate act, not housekeeping | in principle yes; **no prune surface exists at MVP** (see §4) |
| in `vault export` | **always** — U12's Accept requires "a resumable seal stays resumable" across the round trip (tasks/U.md:154) | **excluded** (see §3) |

The cache integrity recheck is not optional politeness: a bit-rotted
cached ciphertext embedded into a bundle would fail the recipient's
storage-linkage and AEAD checks — the builder's self-verify (R13,
tasks/R.md:158) would abort the reveal with an error where a recheck
turns the same rot into a silent heal.

### 3. Export excludes the cache (feeds D47)

U12's own enumeration is "everything **needed** to reveal/restore every
work (all records, journal, anchors, wallet, config)" (tasks/U.md:149) —
and the cache is, by definition of `complete`, re-fetchable from the
network that S19's clean-tree E2E already assumes present ("everything
must come from the vault backup **plus the network**", tasks/S.md:246).
Excluding it keeps exports at record scale (KBs) instead of content scale
(the cache is ≈ 1–2× sealed content: padded unit ciphertexts
(MVP-SPEC.md:91) + raw mirrors + encrypted manifest), which matters for a
file users are nagged to create early and store safely (U18).

A pleasant proof obligation falls out for free: because imports carry no
cache, **S19's restore-from-backup E2E exercises the pure network path
with zero test contrivance** — the "restore must NOT need staged bytes"
property is enforced by the export format rather than by harness surgery.

### 4. No prune surface at MVP — the consequence stated plainly

The canonical CLI surface is closed (tasks/U.md:13,15) and contains no
`vault prune`/`gc`. Choosing RETAIN therefore means: **vault disk grows by
≈ 1–2× of every sealed work's size and cannot be slimmed from within the
MVP surface** (the records sit inside the AEAD; manual file deletion is
corruption, not pruning). Accepted deliberately at MVP scale
(technical-ish creators sealing documents, MVP-SPEC.md:26); a `vault gc`
command is recorded as a v1.1 candidate, and it will be a *cache*-only
operation by the §2 table (journal bytes of incomplete works are never
its to touch).

### 5. Restore stays network-normative; cache becomes its fallback

S14 as written always fetches ("fetch every unit ciphertext via
`get_data`", tasks/S.md:183) and must keep that as the normative path —
it is what the M4 disk-loss drill proves. Proposed S14 amendment
(S-domain, at integration): when a `get_data` fetch fails and a cache
copy exists, use it — commitment verification (which S14 performs on
every unit regardless of source) is unchanged, so the fallback costs no
trust. This is the one place retention buys disaster resilience: after an
Autonomi data loss (the 1.0→2.0 reset was total, MVP-SPEC.md:180), the
live vault's cache is the only remaining copy of the ciphertexts, and a
restore that refuses to read it would be purism at the worst moment.

### Why prune loses (adversarially, not just on points)

- Every argument for prune is "lean vault" — real, bounded, and priced in
  §4. Against it: reveal degrades to whole-file network fetches (§ above),
  `show` loses exact-bytes snippets, and restore loses its only
  network-independent copy.
- Prune is not even the simpler implementation: deletion must be strictly
  ordered **after** the durable `complete` marker (delete-then-crash
  before the marker lands ⇒ resume finds staged bytes missing ⇒ S11
  abandons a work whose payment landed — the exact catastrophe-by-
  housekeeping S11's guard exists to make deliberate). Retention has no
  crash-ordering obligation at all: the transition writes a tag.
- Privacy delta of retention: none. The bytes are AEAD ciphertexts that
  are public on Autonomi from finalize onward, and they sit inside the
  vault AEAD besides.

## Spec conformance

MVP-SPEC.md is silent on post-finalize disposition (line 145 covers the
journal's pre-finalize life; line 36's "when no local copy exists" implies
local copies persist). No divergence; this record completes the spec's
implied model. Nothing here is v1 wire format; nothing freezes at Q14.

## Consequences and integration updates

1. **tasks/U.md U9 (line 117)** — Accept bullet "retention policy … per
   open decision 5" → "per D43: reclassify journal → cache at complete;
   cache excluded from export; integrity-recheck-or-refetch on use".
2. **tasks/U.md open decision 5 (line 392)** — mark resolved by D43.
3. **tasks/U.md U27 (line 323)** — snippet sourcing confirmed cache-first;
   strike the "per open decisions 5/14" hedge (D50 is irrelevant to
   snippet sourcing — the dangling "/14" reference should go).
4. **tasks/R.md R16 (line 194)** — add the cache-integrity recheck: cached
   bytes are embedded only after S4 address recomputation matches the
   manifest address; mismatch ⇒ refetch. (R16's sourcing order itself is
   already correct.)
5. **tasks/S.md S14 (line 183)** — proposed amendment per §5 (network
   first, verified-cache fallback on fetch failure). S-domain owner
   ratifies; if declined, §5's doomsday note moves to the threat model
   instead.
6. **tasks/S.md S10** — the state machine gains the explicit
   `complete`-transition reclassification write (tag only, no byte move).
7. **D47** — export content rule (§3) is an input to the export format
   record.

## Residual risks (for the register)

- **Unbounded vault growth until a v1.1 `vault gc`** (§4) — accepted,
  sized ≈ 1–2× sealed content.
- **Cache-in-export is deliberately absent**: a vault backup alone cannot
  survive an Autonomi data loss for complete works (the live vault can,
  via §5). Matches the spec's risk posture — "storage permanence is the
  product's bonus, not its proof" (MVP-SPEC.md:180) — and an
  everything-included export flag is a v1.1 candidate alongside `gc`, not
  MVP surface (the canonical CLI is closed).
- The §5 S14 amendment is proposed across a domain boundary; until
  ratified, restore remains network-only and the doomsday copy exists but
  is unreachable by the restore path.

## Discovered-work candidates

- **v1.1 register:** `vault gc` (cache-only prune) and an
  everything-included export option — both CLI-surface events, so v1.1 by
  construction.
- **S:** the S14 verified-cache fallback amendment (§5) — small, testable
  on MockBackend (fetch-failure injection is S3's bread and butter,
  tasks/S.md:38).
- **Q (M4):** disk-growth note in the vault docs (what the vault stores,
  why it is content-sized, and that backups are not).

## Amendment (2026-08-02, S29): §3 excluded the manifest locator, and an imported complete work could not be restored at all

§3 named the export exclusion as a property of the **work** — state =
`complete` ⇒ the journal is cache ⇒ nothing exported — and U12
implemented it exactly that way (`export.rs`: `state == Complete ⇒
journal = []`, with the import validator rejecting a complete work that
carried *any* journal bytes). That is one category too coarse. The S10
journal's entry-key namespace has two halves, and only the second one is
what this record's size reasoning is about:

| entries | content | scale |
| --- | --- | --- |
| 0 `STATE_ENTRY`, 1 `PLAN_ENTRY`, 2 `MANIFEST_BLOB_ENTRY` | fine state tag; seal plan + plaintext manifest; the encrypted manifest's `{address, nonce}` (+ its own ciphertext) | record (KBs) |
| ≥ 3 `UNIT_ENTRY_BASE` | one staged unit ciphertext each, raw mirrors included | content (≈ 1–2× sealed content) |

§3's own justification is entirely about the second row — "record scale
(KBs)" versus "content scale" — so the exclusion was over-broad by
accident rather than by decision. The tell is in §3's parenthetical
itself, which lists "+ encrypted manifest" as part of the cache: the
encrypted **manifest** is record-scale metadata, and its journal record is
the only thing that says *where on Autonomi the manifest is*.

**The consequence, found by S14 (lane ε) and recorded as S29.** Dropping
entry 2 dropped that address, which is not derivable from `W`, `seal_id`
or `work_id` — an encrypted manifest is unfindable on a content-addressed
network without it. Dropping entry 1 dropped the plaintext copy in the
same stroke. S14 implements both manifest sources and is proven on each;
after a `vault import` **neither had a source**, so a restored-from-backup
complete work stopped on `ManifestUnavailable` and S19's clean-tree drill
— the M1 gate clause — could not pass. M3's `reveal`-after-import (R16
needs the manifest too) had the identical hole. Note the shape of the
failure: it was silent at export time and irreversible by the time it
mattered, since the backup is what exists after the vault is gone.

**Corrected rule.** *The cache is the staged unit blobs, not the journal
area.* On `vault export` a complete work carries its record-scale journal
head — entries 0 (`STATE_ENTRY`), 1 (`PLAN_ENTRY`) and 2
(`MANIFEST_BLOB_ENTRY`) — and drops every entry from 3 (`UNIT_ENTRY_BASE`)
upward. Incomplete works are unchanged: every entry is exported, as §2's
table already required. `vault import` enforces the same line from the
other side, rejecting a complete work that carries any entry
`>= UNIT_ENTRY_BASE`. §2's table row "in `vault export`" should be read as
**journal: always; cache (= staged unit blobs): excluded**.

Entry 2 is exported whole, ciphertext included, rather than reduced to the
`{address, nonce}` pair it is needed for: a `StagedBlob` record's address
is BLAKE3 of its own ciphertext (S4), so a stripped record fails the
integrity recompute every consumer performs, and splitting it would be a
new record type rather than a scoping fix. The cost is bounded and stays
inside §3's own budget — the manifest ciphertext scales with the *unit
count*, not with content, and remains KBs where the excluded unit blobs
are megabytes.

**One §3 claim narrows, and it should be said plainly.** §3 credited the
lean export with making "S19's restore-from-backup E2E exercise the pure
network path with zero test contrivance". That remains true of every
**unit** — the bulk, and the part the disk-loss drill exists to prove —
but it is no longer true of the manifest, which an imported work now finds
in its vault copy first (`ManifestSource::VaultCopy`). This is the right
trade: a drill that proves the network path by making restore *impossible*
proved nothing. The locator path is exercised directly instead, by
deleting the plaintext copy from an imported work and restoring again —
`an_imported_complete_work_restores_from_the_network`
(`crates/antseal-cli/tests/restore_engine.rs`), which asserts both halves
at once: every unit came from the network (`from_cache == 0`) and the
journal head is exactly `[0, 1, 2]`.

Since **S29** the rule lives in one place per side —
`gather_payload` and `validate_payload` in
`crates/antseal-cli/src/vault/export.rs`, both keyed on `UNIT_ENTRY_BASE`
rather than on a state tag. D47 carries the matching amendment.
