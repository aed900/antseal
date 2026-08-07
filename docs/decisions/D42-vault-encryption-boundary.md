# D42 — Vault encryption-boundary partition (and the hook-without-unlock consequence)

- **Status: RESOLVED — anchor artifacts (`.ots`, TSA tokens, fetch dates)
  and every other per-work record live INSIDE the passphrase AEAD; exactly
  three things live beside it: `config.toml`, the vault header, and the
  lockfile. Consequently the U24 opportunistic-upgrade hook is defined as
  running iff the host command already holds an unlocked vault handle —
  on a locked or absent vault it is a silent no-op, never a prompt. The
  register's lean (U5's encrypted-at-rest mandate for records, U4's
  plaintext config) is CONFIRMED, with the consequence sharpened from
  "skip when locked" to a positive rule about which commands upgrade.**
- **Date: 2026-08-01** (M1 planning wave; blocks U5 now, U24 at M2;
  register TODO.md:522, U-domain open decision 4, tasks/U.md:391)
- **Owning tasks: U5 (layout + boundary), U4 (config), U24 (hook, M2),
  U9 (record store)**

## Context

MVP-SPEC.md:143 defines the vault: "`~/.antseal/`: config + per-work
records (`W`, seal journal, receipts, `.ots`, TSA tokens, addresses,
paths, costs), encrypted at rest with a passphrase." U5 must "decide and
document the encryption-boundary partition (what lives inside the
passphrase AEAD vs beside it …) without weakening the mandate that
per-work records … are encrypted at rest" (tasks/U.md:62). U4
independently describes `config.toml` as a "plaintext-readable location
inside the vault dir; see open decision 4" (tasks/U.md:50).

The tension is U24 (M2): "**every** CLI invocation opportunistically
attempts pending OTS upgrades … and never fail[s] or delay[s] the primary
command … the hook must never trigger a passphrase prompt the command
didn't already need" (tasks/U.md:291; MVP-SPEC.md:35,108). If the pending
`.ots` files sit inside the AEAD, a hook running without an unlock can
neither read them nor persist an upgraded attestation. That is the
"hook-without-unlock consequence" this record must own.

## Options

- **A — records inside, config beside** (the register's lean): the AEAD
  covers everything enumerated by line 143; config is plaintext; the hook
  runs only when the host command unlocked anyway.
- **B — anchor artifacts beside the AEAD** (plaintext or under some
  stored-beside key), so the hook can run on every invocation including
  locked/vault-less ones.
- **C — a cached "hook key"**: artifacts inside a second AEAD whose key is
  persisted beside the store after first unlock, so the hook can operate
  without a passphrase.

## Decision

**Option A.** The partition, exhaustively:

**Beside the AEAD** (readable/writable with no passphrase — and nothing
may ever be added to this list that is secret or per-work):

1. **`config.toml`** (U4) — default network, per-network contracts/RPC
   endpoints, reserved TSA-list and online-endpoint override slots
   (tasks/U.md:50). Binding constraint on all future config slots: config
   carries operator *preferences*, never secrets and never per-work data.
2. **The vault header** — format version, KDF block (D40), wrap-mode
   record (U8/D50). Necessarily pre-unlock; tamper is caught at unlock by
   U6's AAD binding (tasks/U.md:74), parameter bombs by D40 §3's caps.
3. **The single-writer lockfile** (tasks/U.md:62) — contains no data.

Transient atomic-write temp files (U5's temp+fsync+rename discipline) may
exist beside momentarily but only ever contain the above classes or AEAD
ciphertext.

**Inside the AEAD** — everything else, i.e. the entire line-143
enumeration and its descendants: `W`, the wallet record (own sub-key,
U10), per-work records, titles, file paths, costs, completion state, the
seal journal including staged ciphertext bytes and their D43 cache
reclassification, `PaymentReceipt`s, **all anchor artifacts** (pending and
upgraded `.ots`, TSA tokens, fetch dates), record indexes, and vault
bookkeeping such as U18's "export performed" flag.

### The hook rule (binding on U24 at M2)

> The opportunistic OTS upgrade hook runs **iff the dispatching command
> already holds an unlocked vault handle**. It performs its bounded-time
> calendar polling and persists upgraded `.ots` through that handle. When
> the vault is locked, absent, or the command is vault-less, the hook is a
> silent no-op (debug-level trace only). It never unlocks, never prompts,
> and never creates `~/.antseal`.

**The consequence, quantified rather than hand-waved:** the only canonical
command that never unlocks is `verify` (mandated vault-less and
prompt-free — tasks/U.md:357, and U24's own Accept asserts "vault-less
`verify` performs no vault access and no prompt", tasks/U.md:295). Every
other command a vault owner runs — `init`, `seal`, `list`, `show`,
`status`, `restore`, `reveal`, `vault export|import` (tasks/U.md:13) —
unlocks by need.

> **Corrected 2026-08-07 (D99 §6), and this paragraph over-counted by two.**
> The **rule** above — the hook runs iff the host command already holds an
> unlocked vault handle — is untouched and was implemented exactly as
> written. What is wrong is this enumeration: `verify` is **not** the only
> command that never arms the hook. `init` **creates** a vault rather than
> unlocking one, and `vault import` **writes** one; measured at U24's
> landing, neither holds an `UnlockedVault` at the dispatch layer, so
> neither arms. Three commands are therefore documented non-armers, not one.
>
> This matters because the paragraph reads as a coverage argument — *"only
> one case degrades"* — and a coverage argument built on a miscount invites
> the next lane to treat an unarmed command as a bug. U24's rewritten
> Accept row 4 asserts the real partition per subcommand over the binary's
> own debug trace, in **both** directions, which is what the original row
> (factually unsatisfiable — no point that sees every subcommand holds a
> vault) could never have done. So "every CLI invocation attempts upgrades"
(MVP-SPEC.md:35) degrades in exactly one case: an owner running bare
`verify` on their own machine gets no upgrade pass. That user's pending
anchors still advance on their next `list`/`show`/`status`/`seal`, and
`list` nags while any strong anchor is pending (U25). A verifier-only
machine has no vault and no pending `.ots` — nothing to upgrade. This is
the whole cost of Option A, and it is paid where it does not matter.

### Why B and C lose

- **B (artifacts beside, plaintext)** directly contradicts the U5 mandate
  and MVP-SPEC.md:143, which enumerate `.ots` and TSA tokens in the
  encrypted set — and the leak is real, not cosmetic: a pending `.ots`
  carries `anchor_digest` and calendar URLs; a TSA token carries
  `anchor_digest`, genTime, and the TSA identity. A lifted vault directory
  would reveal how many works exist, when each was sealed, and digests
  that link the vault to any bundle or anchor seen elsewhere — precisely
  the work-count/timing metadata the encrypted store denies an attacker
  who has the files but not the passphrase. Buying back that leak would
  purchase only the bare-`verify` upgrade case dismissed above.
- **B′ (beside, encrypted under a beside-stored key)** is obfuscation:
  key and ciphertext in the same stolen directory.
- **C (cached hook key)** converts "encrypted at rest" into "encrypted
  until first use": the cached key rides in every theft of the directory,
  so the artifacts are effectively plaintext to the threat model that
  matters, while adding a second key-management surface, a second AAD
  domain, and a consistency protocol between the two stores. All cost, no
  property.

### Rider: AAD discipline for whatever segmentation U5 chooses

U6 binds the KDF header into "the vault AEAD" (tasks/U.md:74). U5/U9 may
implement the inside region as one blob or as independently-AEAD'd records
under the vault key (the latter is strongly indicated once D43's retained
ciphertext cache exists — decrypting gigabytes to read a work list is not
a plan). D42 fixes the boundary's integrity semantics either way:

1. **Every** AEAD encryption under the vault key binds the full serialized
   KDF header (or an HKDF-derived key that includes it — equivalent) as
   AAD, so U6's downgrade-detection property holds for every record, not
   just a monolith.
2. Every per-record AEAD additionally binds the record's identity (work
   id + record class) in its AAD, so records cannot be transplanted
   between slots of one vault undetected (splice resistance).
3. Honest limit, recorded: **whole-vault rollback is out of scope.** An
   attacker who can copy the directory can restore an older copy; no
   offline scheme detects that. In-scope is per-record splice/downgrade,
   which the AADs close.

## Spec conformance

Line 143's grammar can be read as putting *config* under "encrypted at
rest" too. That reading is rejected, and not on convenience: `verify
--online` reads U4's endpoint overrides (tasks/U.md:357) and MUST run
vault-less and prompt-free — config-inside-AEAD would force it to either
prompt (forbidden) or silently ignore the owner's configured overrides
(divergence). U4's own text already assumes plaintext config
(tasks/U.md:50), and config contains no secrets by the rule above. Flagged
per the code-vs-spec rule as an interpretation, not a divergence: the
enumerated *per-work records* — the load-bearing list — are all inside.

## Consequences and integration updates

1. **tasks/U.md U5 (line 62)** — replace "see open decision 4" with the
   D42 partition table + the AAD rider; U5's layout doc cites D42.
2. **tasks/U.md U4 (line 50)** — strike "see open decision 4"; config is
   confirmed beside, with the no-secrets rule stated.
3. **tasks/U.md U24 (line 291)** — replace "per open decision 4: skip
   silently" with the positive hook rule above (runs iff unlocked handle;
   persists through it; silent no-op otherwise). U24's Accept gains: "a
   command that unlocked the vault runs the hook through the same handle
   with no second unlock".
4. **tasks/U.md open decision 4 (line 391)** — mark resolved by D42.
5. **U9** — record-identity AAD (rider 2) lands with the record store.

## Residual risks (for the register)

- **Plaintext config is tamperable by a local file-writer**: a redirected
  RPC endpoint or TSA list is an evidence-downgrade vector (attacker TSAs
  yield tokens that fail the pinned-root chain at verify →
  `internally-consistent-only`, never `proven`; pinned roots are compiled
  into antseal-core, MVP-SPEC.md:109, so config cannot forge `proven`).
  A local writer is largely outside the threat model, but a cheap
  hardening exists: witness a config digest inside the vault and warn on
  unlock when it changed. Recorded as an optional discovered-work
  candidate, not mandated.
- Whole-vault rollback undetectable offline (rider 3) — inherent.
- The bare-`verify` no-upgrade case: an owner who *only* ever verifies
  never advances pending OTS. Bounded by U25's `list` nag and
  `status --upgrade`; accepted.

## Discovered-work candidates

- **U (optional hardening):** config-tamper witness — digest of
  `config.toml` stored inside the vault, checked at unlock, warn-only.
  Proposed for the U domain backlog at M2 alongside U24/U26 (config's
  consumers), not on the M1 critical path.
- **Q (M4):** threat-model §2.1 (docs/threat-model.md:419) should state
  the partition and what a stolen-but-locked vault directory does and does
  not reveal (config preferences and header parameters — yes; work count,
  timings, digests, artifacts — no).
