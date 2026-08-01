# D40 — Vault KDF selection mechanism and low-RAM behavior

- **Status: RESOLVED — Argon2id (m = 262144 KiB, t = 3, p = 1) is the sole
  default; scrypt (N = 2²⁰, r = 8, p = 1) exists only as an explicit
  init-time selection, never an automatic one; a machine that cannot
  allocate the KDF's memory gets a typed hard error at create *and* unlock,
  and there is NO fallback prompt. U6's own note leaned toward "a documented
  fallback prompt" — overturned: the fallback it imagines does not exist,
  because scrypt at its spec floor needs 1 GiB, four times Argon2id's
  256 MiB.**
- **Date: 2026-08-01** (M1 planning wave; blocks U6, U11; register
  TODO.md:520, U-domain open decision 2, tasks/U.md:389)
- **Owning tasks: U6 (KDF + header + AAD), U11 (init flow), U2 (error
  classes), P (crate pins per docs/dependency-policy.md §1)**

## Context

MVP-SPEC.md line 143 fixes the vault KDF parameters and the anti-downgrade
mechanism: Argon2id "m ≥ 256 MiB, t = 3, p = 1 (default), random 16-B
salt — with `scrypt N ≥ 2²⁰` as an alternative", algorithm id + full
parameters in the vault header, and "the entire KDF header is bound into
the vault AEAD as AAD so a parameter downgrade … is a detected
authentication failure". U6 (tasks/U.md:69–80) implements exactly that and
its Accept already rejects below-floor creation (tasks/U.md:78).

What the register left open (tasks/U.md:389) is the *selection mechanism* —
who chooses scrypt, when — and the behavior "on machines that cannot
allocate Argon2id's 256 MiB". U6's note (tasks/U.md:80) carried the only
lean: "may need a documented fallback prompt".

## The arithmetic that decides the low-RAM half

The fallback-prompt idea silently assumes scrypt is the low-RAM escape.
It is the opposite. RFC 7914 scrypt memory is ≈ `128 · r · N` bytes for
the V array; the spec floors N at 2²⁰ (MVP-SPEC.md:143) and the standard
interactive-to-storage parameterization is r = 8, p = 1, so:

```
scrypt  floor:  128 · 8 · 2^20  =  2^30 B  =  1 GiB
Argon2id floor: m = 262144 KiB  =  256 MiB
```

A machine that cannot allocate 256 MiB cannot allocate 1 GiB. **There is no
spec-conformant weaker KDF to fall back to**, and U6's Accept
(tasks/U.md:78) forbids creating below the floors. A "fallback prompt"
could therefore only ever offer a below-floor vault, i.e. exactly the
silent weakening the AAD binding exists to make impossible for existing
vaults — offered interactively at creation instead. The threat this floor
defends is not hypothetical inconvenience: a stolen vault "retroactively
and permanently decrypts public, undeletable ciphertexts with no possible
rotation" (MVP-SPEC.md:143; docs/threat-model.md:419–431 §2.1), and a
creation-time downgrade is permanent for that vault's lifetime.

## Decision

### 1. Selection mechanism

- **Default: Argon2id, m = 262144 KiB (256 MiB), t = 3, p = 1,** random
  16-B salt. Creation writes exactly these values (not merely "≥ floor") —
  v1 has no surface for user-tuned parameters, and a benchmark-driven
  auto-tuner is explicitly rejected: it would mint machine-dependent
  parameters and let a slow machine argue itself into a weak vault.
- **scrypt N = 2²⁰, r = 8, p = 1** is selectable **only by an explicit
  user choice at `init`**. How that choice is surfaced (wizard step vs
  flag) is D39's to decide — this record deliberately does not pre-commit
  the interaction model, only the rule: *no automatic selection, no
  environment probing, no fallback path selects scrypt.* Its use case is
  operator policy (preferring the older, longer-scrutinized construction),
  **not** resource constraints — `init` help/docs must say it needs *more*
  memory (1 GiB), so nobody reaches for it as an escape hatch.
- The header records algorithm id + full parameters + salt and is AAD-bound
  per U6 (tasks/U.md:74). D40 adds nothing to the wire; the D40 rule is
  about which values the writer ever emits.

### 2. Low-RAM behavior: typed refusal, no prompt, no fallback

- Creation attempts the allocation; on failure it fails with a **distinct,
  actionable vault-domain error** (working name `vault-kdf-memory`; code
  and exit-code assignment are U2's, tasks/U.md:21–31): the machine cannot
  meet the vault's memory-hardness floor; use a machine with ≥ ~300 MiB
  (≥ ~1.1 GiB for scrypt) allocatable; the floor is a security parameter
  and antseal will not create a weaker vault.
- **Unlock has the same behavior.** The header's recorded parameters are
  what the KDF must run with, on every invocation, forever — a vault
  created on a capable machine is not openable on one that cannot allocate
  its `m`. This is stated in docs rather than "solved": any solve is a
  downgrade.
- Allocation failure MUST surface as the typed error, not an abort or an
  OOM kill: the implementation uses fallible allocation for the KDF arena
  where the crate API permits it. Honest limit, recorded: under Linux
  overcommit the allocation can "succeed" and the OOM killer strike during
  the fill; detection is best-effort by construction.

### 3. Pre-auth header caps (defensive parsing carried to the vault)

The KDF runs *before* the AEAD can authenticate anything — the key does
not exist yet. So the KDF parameters are the one attacker-suppliable input
that is acted on pre-authentication: a substituted vault file (or a
malicious `vault export` file handed to `vault import` — same header
construction, D47) demanding `m = 1 TiB` is a resource bomb that no AAD
check can catch, because the AAD check runs after the KDF. Per the
D10-caps precedent, header parsing MUST enforce ceilings before invoking
the KDF, with a distinct error (working name
`vault-kdf-params-out-of-range`):

| parameter | floor (reject below) | cap (reject above) |
| --- | --- | --- |
| Argon2id `m_cost` | 262144 KiB | 4194304 KiB (4 GiB) |
| Argon2id `t_cost` | 3 | 64 |
| Argon2id `p` | 1 | 1 (exactly) |
| scrypt `log₂ N` | 20 | 24 |
| scrypt `r` | 8 | 8 (exactly) |
| scrypt `p` | 1 | 1 (exactly) |

Constants are U6's to land and version with the header; the normative part
of D40 is that caps exist, sit before the KDF call, and are distinct from
auth failure. (Below-floor is unreachable from our own writer but the
check is kept: the header is adversary-suppliable input.) A future
parameter raise is a header-version event and revisits the caps with it.

## Crate selection (recorded for the implementation lane; pins land per P7)

Workspace generation: `sha2 = "=0.11.0"` (+ load-bearing `zeroize`
feature, D88), `hkdf =0.13.0`, `hmac =0.13.0`, `chacha20poly1305 =0.11.0`
(Cargo.toml:105–112,173; docs/dependency-policy.md:27,35–52). The
dependency-policy §1 table already reserves the row "Argon2/scrypt (vault
KDF) | vault format | U/C" (docs/dependency-policy.md:29). Verified against
crates.io 2026-08-01 (API retrievals, this planning pass):

- **`scrypt = "=0.12.0"`** (stable, 2026-04-22): depends on `sha2 ^0.11`,
  `pbkdf2 ^0.13`, `salsa20 ^0.11` — it resolves onto **our exact
  `sha2 =0.11.0` pin including the D88 `zeroize` drop-glue**, adding no
  second digest generation. Optional `password-hash`/`kdf`/`mcf` features
  stay OFF (parameters live in our AAD-bound header, not PHC strings).
- **`argon2 = "=0.6.0-rc.8"`** (2026-04-21): depends on
  `blake2 ^0.11.0-rc.5` (digest-0.11 generation) with an optional `zeroize`
  feature — enable it. **The stable alternative `argon2 0.5.3` is
  REJECTED**: it depends on `blake2 ^0.10.6`, dragging a second
  `digest 0.10`/`block-buffer 0.10` stack into the audited graph — one the
  D88 analysis never covered, whose buffers would hold the passphrase with
  no wiping story, and a duplicate-generation tree besides
  (deny.toml:64 `multiple-versions = "warn"` would flag it, correctly).
  Accepting an rc for a security-relevant primitive has direct precedent:
  `ml-dsa =0.1.1` is pre-1.0 and unaudited and was pinned exactly with
  advisory tracking (docs/dependency-policy.md:23). Conditions: exact pin,
  RUSTSEC/GHSA watch, and if `argon2 0.6.0` final is out at pin time, take
  it instead — the lane re-verifies current versions at pin time per §4.
- **Pin-time obligation (D88-style):** run the residue probe over a
  dropped Argon2id computation — blake2 0.11-rc uses the same
  `buffer_fixed!`/`block-buffer 0.12` machinery whose `ZeroizeOnDrop` arm
  D88 proved is a marker with no `Drop`; verify `blake2/zeroize` actually
  gates a wiping `Drop` on the BLAKE2b core state before believing it.
  Passphrase buffers themselves ride in C5's zeroizing types
  (`SecretBuf`, crates/antseal-core/src/crypto/secrets.rs:195;
  `MasterSecretRef`, crates/antseal-core/src/crypto/material.rs:66).
- Both crates join the exact-pin class in the PR that introduces them
  (docs/dependency-policy.md:54–58); RFC 9106 (Argon2) and RFC 7914
  (scrypt) known-answer vectors are committed as tests so a crate swap or
  bump that changes output bytes is loud. KDF output bytes are vault-format
  bytes: silently different output = every existing vault stops opening.

## What this costs, stated honestly

- **~1 s of KDF on every invocation.** Argon2id at 256 MiB / t = 3 /
  single-lane is on the order of a second on current desktops (U6's Accept
  requires measuring and documenting the real number, tasks/U.md:79).
  Every vault-touching command pays it (only `verify` is vault-less,
  tasks/U.md:357). No unlocked-key caching mechanism is added to soften
  it — a cached key is a second copy of the thing the KDF exists to
  protect. This is the designed price of the no-rotation threat model.
- **scrypt-at-floor costs 1 GiB and ~3–5 s.** Documented at the selection
  point so the choice is informed.
- Machines under ~300 MiB free simply cannot host an antseal vault. MVP
  users (MVP-SPEC.md:26) are not in that class; embedded/containerized
  edge cases are excluded deliberately rather than accommodated weakly.

## Spec conformance

- Parameters, floors, salt size, AAD binding: exactly MVP-SPEC.md:143 and
  U6 (tasks/U.md:74–79). No deviation.
- The spec names no scrypt r/p. **D40 fixes r = 8, p = 1** as the creation
  values (the RFC 7914 conventional pairing its N-floor implies); the
  header records them explicitly either way, so this is a writer-side
  completion of an under-specified line, not a format change. Flagged here
  per the code-vs-spec rule; a one-word spec amendment ("N ≥ 2²⁰, r = 8,
  p = 1") is recommended at the next spec-touching pass.
- Risks line MVP-SPEC.md:184 says "pinned scrypt params with header
  agility" where the default is Argon2id — pre-existing loose wording,
  noted, not load-bearing.
- Nothing here enters the v1 bundle/manifest freeze: vault formats are
  outside Q14's scope, versioned by U5's header instead (tasks/U.md:64).

## Consequences and integration updates

1. **tasks/U.md U6 Notes (line 80)** — replace "may need a documented
   fallback prompt — decision folded into open decision 2" with a pointer
   to D40: typed refusal, no fallback; add the header-cap requirement to
   U6's Do/Accept (caps before KDF, distinct error, cap constants
   documented).
2. **tasks/U.md U11 (line 135)** — "KDF choice per open decision 2" → per
   D40 (explicit scrypt selection, surfaced per D39).
3. **tasks/U.md U2 (line 26)** — error taxonomy gains the two D40 classes
   (`vault-kdf-memory`, `vault-kdf-params-out-of-range`), distinct from
   vault-auth failure.
4. **tasks/U.md open decision 2 (line 389)** — mark resolved by D40.
5. **docs/dependency-policy.md §1 row (line 29)** — completed with the
   actual pins + deciding-task note when the implementation lane lands
   them (the D88-style blake2 probe recorded alongside).
6. **U12/D47** — `vault import` header parsing inherits §3's caps
   verbatim (same pre-auth KDF bomb; one rule, two call sites).

## Residual risks (for the register)

- Linux overcommit can defeat allocation-failure detection (OOM kill
  instead of typed error) — best-effort, documented.
- `argon2` rides an rc pin until 0.6.0 final: pre-1.0 discipline as for
  ml-dsa (exact pin + advisory sweep), plus the blake2-zeroize probe as a
  pin-PR gate.
- The per-invocation ~1 s unlock is a UX tax that will generate user
  pressure for a weaker mode or key caching; this record is the place that
  says no, so future pressure is a reopen-with-evidence event, not a
  drive-by.

## Discovered-work candidates

- **U:** U6 header-cap constants + tests (caps-before-KDF; reused by U12
  import) — folds into U6's implementation, no new task needed unless the
  lane prefers one.
- **P/C:** pin PR for `argon2`/`scrypt` with the RFC KAT vectors and the
  blake2 residue probe (D88 §2 methodology) as acceptance items.
- **Q (M4):** threat-model §2.1 (docs/threat-model.md:419) gains the
  "why there is no low-RAM fallback" paragraph — the scrypt 1-GiB
  arithmetic belongs in the user-facing story.
