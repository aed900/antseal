# D50 — OS-keystore platform scope for the `W` wrap: none at M1

- **Status: RESOLVED — M1 ships the keyfile wrap only. The OS-keystore
  wrap is format-reserved (wrap-mode id 2 in U8's AAD-bound header
  registry) and implemented by a post-D72 follow-up; its platform scope
  is NOT chosen now, because the register's own question — "Linux Secret
  Service / macOS Keychain / Windows at MVP?" (tasks/U.md:401) — is
  unanswerable before D72 (release target set, open, due M4) without
  pre-committing D72, which this record's mandate forbids. The framing is
  therefore overturned: the correct M1 answer to "which platforms?" is
  "no platforms yet, and the header makes later ones additive."**
- **Date: 2026-08-01** (M1 planning wave; blocks U8; register
  TODO.md:530, U-domain open decision 14, tasks/U.md:401; D72 explicitly
  left open)
- **Owning tasks: U8 (wrap implementation + header), U11 (init offer),
  post-D72 follow-up (keystore scope + implementation)**

## Context

Spec: `init` "offers a high-entropy keyfile / OS-keystore wrap for `W`"
(MVP-SPEC.md:143). U8 implements the offer, records the chosen wrap mode
in the vault header bound via U6's AAD, and defers platform scope to this
decision (tasks/U.md:95–105). U8's own notes already say it is "not on
the M1 E2E critical path — may land late-M1" and that "OS-keystore CI
coverage on headless Linux needs a mock keystore" (tasks/U.md:105).
CI today runs three OS lanes — linux, macos, windows, fail-fast off
(.github/workflows/ci.yml:216–230) — but D72 (TODO.md, Due M4) has not
decided which of those are release targets.

## Evidence

### The crate landscape (crates.io API, retrieved 2026-08-01)

`keyring 4.1.6` — updated **2026-08-01, the day of this record** (active
churn) — is now a facade over `keyring-core` plus per-platform store
crates, each an optional target-gated dependency:
`zbus-secret-service-keyring-store` / `dbus-secret-service-keyring-store`
(Linux/BSD DBus Secret Service), `linux-keyutils-keyring-store` (kernel
keyring), `apple-native-keyring-store`, `windows-native-keyring-store`,
plus `db-keystore`. Choosing platform scope is literally choosing which
of those subtrees enters the audited dependency graph — under a policy
where every dependency is a deliberate, justified event
(docs/dependency-policy.md §1/§4; P7) and the vault format row is
security surface.

### Two technical facts that reshape the question

1. **Linux has no universally-durable keystore.** The Secret Service
   path (GNOME Keyring / KWallet over DBus) is durable but assumes a
   desktop environment and an unlocked login keyring — absent on the
   headless boxes a CLI audience runs (hence U8's mock-keystore note).
   The `linux-keyutils` path needs no DBus but is a **kernel keyring:
   memory-resident, not persistent across reboot**. A reboot-volatile
   store holding the *sole* copy of a wrap factor for a vault whose theft
   model is "no rotation, ever" (docs/threat-model.md:419–431) is not a
   wrap, it is a time bomb: first reboot ⇒ vault permanently unopenable.
   Any future Linux keystore scope must be Secret-Service-class or
   nothing, with keyutils at most a session convenience — this paragraph
   is recorded for the follow-up decision so it is not re-derived.
2. **A machine-bound factor breaks the backup story unless export
   converts it.** D47's export preserves wrap factors; that is only sound
   because the M1 keyfile is portable. An OS-keystore entry does not
   travel in a `vault export` file, so the clean-machine drill
   (tasks/S.md:241–251; MVP-SPEC.md:175) would import a vault whose
   second factor died with the old machine. **Binding constraint on the
   future keystore task, recorded now:** when the keystore wrap lands,
   `vault export` MUST re-wrap `W`'s protection to portable factors
   (passphrase, or passphrase + keyfile) with a loud, explicit statement
   at export time — or refuse. D47 §keyfile cites this record for why it
   has no such branch at M1.

### What the keyfile already buys

The security content of the wrap is a second factor: vault theft then
requires the vault files *and* the factor. A 32-byte OS-CSPRNG keyfile,
AEAD/HKDF-mixed into the unlock path with the existing pinned primitives
(chacha20poly1305/hkdf/sha2, Cargo.toml:105–112,173; zeroizing carriage
via C5's types, crates/antseal-core/src/crypto/secrets.rs:195), delivers
that with **zero new dependencies**, works identically on all three CI
OSes today, is testable headless with no mock keystore, and is portable
across machines (the user carries the file; U8 stores it "wherever the
user directs", tasks/U.md:100). What the OS keystore adds over it is
convenience (no file to carry; OS login unlocks it) minus portability —
a trade users can only be offered honestly once the platform set is a
decided fact rather than a guess.

## Decision

1. **M1 ships: passphrase-only, and passphrase + keyfile.** No `keyring`
   (or platform-store) dependency enters the workspace at M1 — the
   tasks/U.md:405 cross-domain note listing keyring among P's pins is
   corrected at integration.
2. **The wrap-mode registry in U8's header is fixed now**:
   `0 = none`, `1 = keyfile`, `2 = os-keystore` — **reserved,
   unimplemented**. The mode byte is inside U6's AAD-bound header, so
   mode 2 is format-reserved the same way `sig_policy` reserved the
   Ed25519-only fallback (MVP-SPEC.md:97): adding the keystore later is
   additive, never a header break. An M1 binary opening a vault with mode
   2 fails with a distinct "wrap mode not supported by this antseal"
   error (same family as U5's newer-version error, tasks/U.md:64), never
   a generic auth failure.
3. **Platform scope is decided by a follow-up decision AFTER D72
   resolves** (register it when D72 lands; owner U8's successor task).
   Inputs recorded for it: the Linux durability finding, the export
   re-wrap constraint, the keyring-4.x facade shape (re-verified then —
   the crate moved the day this record was written), and the P7 cost of
   each platform subtree. This record deliberately constrains that
   decision's *inputs*, not its outcome.
4. **Spec narrowing, flagged not silent**: line 143's offer is satisfied
   at M1 by the keyfile half only. Recorded here as a deliberate,
   reversible narrowing (the reserved mode is the reversal mechanism);
   the M4 threat-model doc (docs/threat-model.md:419–431 §2.1 must-cover
   list names "keyfile / OS-keystore wrapping") states the actual shipped
   state rather than the spec's disjunction.

### Why not "just add keyring for Linux now" (the tempting middle)

- It pre-commits half of D72 (a Linux keystore lane implies Linux-first
  release posture) — the mandate this record operates under forbids it.
- The M1 payment is real and immediate: a platform subtree in the audited
  graph, a mock-keystore CI fixture, and a D47 conversion branch — for a
  feature U8 already marks off the critical path, on the one platform
  where the durable backend assumes a desktop the target audience often
  lacks.
- The keystore's value is convenience; the keyfile already delivers the
  security property. Deferral loses no protection, only polish, and the
  reserved mode makes the polish additive later.

## Spec conformance

MVP-SPEC.md:143's "keyfile / OS-keystore wrap" is shipped as
keyfile-at-M1 with the keystore format-reserved — a recorded narrowing
per the code-vs-spec rule, not a divergence hidden in implementation.
U8's Accept ("round-trip tests for each wrap mode", tasks/U.md:102) reads
over the *shipped* modes {none, keyfile}; the mode-2 reserved error gets
its own test. Nothing here enters the Q14 freeze (vault surface).

## Consequences and integration updates

1. **tasks/U.md U8 (lines 95–105)** — Do: platform scope "per open
   decision 14" → "M1 keyfile-only per D50; wrap-mode 2 reserved in the
   header; keystore is a post-D72 follow-up". Accept: add the mode-2
   distinct-error test; drop the mock-keystore note to the follow-up.
2. **tasks/U.md open decision 14 (line 401)** — mark resolved by D50
   (keyfile-only M1; scope decision deferred post-D72 by design).
3. **tasks/U.md:405 (cross-domain P line)** — remove `keyring` from the
   M1 pin list (argon2/scrypt stay, per D40).
4. **tasks/U.md U27 (line 321)** — the "/14" in "per open decisions 5/14"
   is a dangling reference (keystore scope never affected snippet
   sourcing); strike it (D43 already notes this from the /5 side).
5. **TODO.md register** — the post-D72 keystore-scope decision is a new
   register entry when D72 resolves (discovered work below).
6. **docs/threat-model.md §2.1 (M4, Q21)** — state keyfile-shipped /
   keystore-reserved.

## Residual risks (for the register)

- Users wanting an OS-integrated, no-file-to-carry unlock wait past MVP;
  until then the keyfile's safety depends on where the user puts it
  (guidance belongs in U8's help text and the M4 docs: not beside the
  vault, not in the same cloud folder as the export).
- The reserved mode byte is a promise: the follow-up must honor id 2's
  semantics or formally retire it — either way through the register,
  never by reuse.
- `keyring`'s 4.x facade is churn-active (updated the day of this
  record); the follow-up decision must re-survey rather than trust this
  snapshot.

## Discovered-work candidates

- **U (post-D72):** "OS-keystore wrap: platform scope + implementation"
  — a new U-task + register decision pair, created when D72 lands, with
  this record's §Evidence as its brief (durability rule, export re-wrap
  constraint, per-platform dep cost).
- **Q (M4):** keyfile-handling guidance in the vault docs (placement,
  what happens if lost — distinct from passphrase loss).
