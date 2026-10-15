# D175 — In the feature build `reveal` fetches uncached ciphertext through the D170 reader, connected **at most once and only from a needed fetch**; **nothing about the network may fail a reveal that needs no fetch**; the default build keeps `U72` byte for byte; and the zero-call property is a library counter plus two process witnesses

- **Status: RESOLVED. The row's direction survived; "a lazy connect" is one of five
  things that must be lazy or reshaped, and one `Accept` clause is unbuildable in the venue
  it implies.**
  - **The premise that holds**: the reveal engine's only backend method is `get_data`, at
    two sites, and both consult the vault cache — integrity-rechecked — first
    (`crates/antseal-cli/src/pipeline/reveal.rs`, `resolve_manifest_bytes` and
    `gather_unit`). A backend that connects on its first `get_data` makes zero dials for a
    fully cached work. The seam's futures carry no `Send` bound and take `&self`, so a
    std-only lazy type suffices and can be tested in the default build like D170's other
    policy types; D170's 60 s hang guard composes unchanged if the deferred future *is*
    `connect_read_only`.
  - **Four defects a lazy wrapper alone leaves**: (1) the handler drives the engine with
    `block_on_vault_local`, which polls once and returns an internal error on the first
    real fetch; (2) copying `restore`'s **eager** order — recorded network, flag check,
    `select_network` — would refuse a **fully cached** reveal of any devnet work with usage 2
    whenever no devnet export is present, a regression of `U72` in the release build;
    (3) `U71`'s consent scan requires exactly one production `run_reveal(` passing
    `gate.gate()` and matches text regardless of `#[cfg]`, so a two-arm handler goes red in
    default CI; (4) a connected reader must be built and dropped inside the runtime.
  - **"A fully cached reveal makes zero backend calls, asserted by a call counter"** cannot be
    read through a spawned binary — a spawned binary holds no mock and in-process
    `main_entry` is refused. The counter is library-level; the binary carries two process
    witnesses that already have a template (`tests/restore_output.rs`'s per-build cached
    restore). §2 R8.
  - **Found, not asked**: after this lands, `BackendArm::Compiled`'s refusal sentence has
    **no production emitter in either build** — its last is `reveal`'s
    `VaultLocalBackend` — so the sentence and its arm name are routed to a row (`U95`).
- **Date: 2026-09-15**
- Owner rows: **`U91`**; **`U95`** (minted with this record: the `Compiled` arm's sentence
  and name have no subject); **`U72`** (its cached path is preserved by §2 R1–R2);
  **`U93`**/D174 (`reveal` gains `result.network` first).
- Related: **D43** (cache retention; no write-back rule), **D69** §5 (exit groups), **D170**
  (the reader; §2 R9 and §4's *"reveal's wiring"* are discharged here), **D173** §2 R7
  (`resolve_peers`, called lazily by `reveal`), **`U71`**, **`U36`**.

## 0. What was measured against

`HEAD` `3473ab2`. Planning lane P3 read the reveal handler, the engine, the backend seam and
its policy types, `vault import`'s payload, D43, D170, `U71`'s scan, the machine-mode tables
and the devnet suites; no cargo run. The orchestrator re-read the handler's
`VaultLocalBackend::new("reveal")` with no `#[cfg]` and `restore`'s `connect_read_only`
before this record was written.

## 1. What was measured

- **Order inside `prepare`**: record state → manifest (the plan entry's plaintext copy if
  present, else the staged encrypted manifest, else a fetch) → identity binding → selection
  (typed errors before any fetch) → anchors → **every unit, normal and raw mirror, of every
  touched file**, sequentially, each `?` → preview → summary counting
  `units_from_cache`/`units_from_network`.
- **All-or-nothing**: every gather aborts the reveal on error, before the consent gate, with
  `Unfetchable` → network-failure (23); a reveal has no per-file rows.
- **Fetched bytes are verified before use**: BLAKE3 address recompute against the manifest's
  address, AEAD open for every normal unit and riding mirror, then the bundle builder's
  mandatory self-verify. **Fetched units are never written to the cache.**
- **After `vault import`** a complete work carries journal entries 0–2 (D43's amendment): the
  plaintext manifest is in the vault, so a clean-home reveal fetches **only unit
  ciphertexts** — every unit of every touched file, raw mirrors included whether or not they
  ride.
- **Today `reveal` ignores `--network` in both builds** and takes no vault lock
  (`reveal_out.rs` documents why: it writes nothing).
- **The process-level dial witness exists**: `connect_read_only` emits one trace,
  *"connecting the read-only reader"*, only when a connection is attempted, and
  `tests/restore_output.rs` already asserts its presence and absence per build.
- **The `NotFound` mapping** (*"the network has no data at this address"* → 23) becomes
  reachable by a production reveal for the first time.

## 2. RULING

### §2 R1 — One backend per build; the feature build dials only through `connect_read_only`, once, from a fetch

Default build: `reveal` keeps `VaultLocalBackend::new("reveal")` driven by
`block_on_vault_local`, and reads no flag, definition or export — `U72` byte for byte.
Feature build: `reveal` holds a lazily connecting read-only backend whose deferred future is
`connect_read_only(command, &config)` — reusing D170's trace, hang guard and degrade —
awaited **at most once**, and only from inside the first `get_data`.

### §2 R2 — Nothing network-shaped may fail before the first needed fetch

The recorded network's read and parse, the explicit-`--network` comparison,
`select_network`/`read_only_network` and D173's `resolve_peers` all run **inside the deferred
future**. A fully cached reveal completes, with the default build's output, when
`ANTSEAL_DEVNET_ENV` is unset, names a missing file, or names a dead export, and whatever
`--network` says.

### §2 R3 — The recorded network, enforced lazily; each failure keeps its own class

When a fetch is needed the network is the work record's; `config.toml`'s default is never
consulted. Then: an explicit `--network` naming another network is **usage (2)**, naming both;
an unparseable recorded network is **reveal-inputs-unusable (36)**, reveal's own class; a
missing or unusable definition, or no peers, is **usage (2)** with the resolver's text. All three
surface at the first needed fetch, before the consent gate, with nothing written. Mechanism: the
lazy backend records the refusal and the handler replaces the engine's resulting network failure
with it — exact, because every `get_data` error aborts a reveal. A refusal recorded but never
reached is dropped. *Refused*: reporting a lazily reached definition failure as 23 — it tells
scripts to retry a failure only an environment fix cures.

### §2 R4 — Transient failures keep their group and their true words

With a usable definition, a failed connect, a hang-guard timeout or a failed fetch ends the whole
reveal at that unit with **network-failure (23)**, before the gate, nothing written, in the
engine's `Unfetchable` sentence carrying the reader's reason — never `BackendArm`'s *"does not
construct one yet"* and never absence for an unreachable network (D170 §2 R2, §2 R12). An
authoritative `NotFound` keeps its existing 23 mapping (see §4). No new class, exit code or
document version.

### §2 R5 — Runtime and lifetime

The feature build drives the reveal with `backend::runtime()`; the lazy backend and any connected
reader are constructed, used and dropped inside that runtime's `block_on` — `restore`'s shape.
`block_on_vault_local` is never used over a backend that can fetch. The consent prompt inside
`block_on` is `seal`'s existing shape.

### §2 R6 — `U71`'s closed list is not edited for production

`commands.rs` keeps exactly one production `run_reveal(` call, passing `gate.gate()`, and exactly
one `DisclosureConsent::new(`. Suggested shape (the lane may choose another that passes the scan):
a per-build driver in `backend.rs` taking an async closure over `&B`, called once from the handler.
New tests drive `RevealEngine::prepare`, not `run_reveal`, to stay off the list.

### §2 R7 — Read-only, no lock, no write-back

The lazy type delegates `get_data` only; `quote_batch`, `pay`, `finalize_batch` and `balances`
refuse in the lazy type itself without attempting a connection, with `ReadOnlyBackend`'s
refusal — so nothing wrapped by mistake can pay (`U36`'s restated `Accept`). No U5 lock; no
fetched unit written to the cache; the raw reader type stays nameable only in `backend.rs`.

### §2 R8 — `Accept` row 2, restated: a library counter and two process witnesses

*"A fully cached reveal makes zero backend calls in both builds"* is met by **(a)** the default
build's `VaultLocalBackend::refusals() == 0` (the existing `reveal_vault_local.rs` test,
unchanged); **(b)** in the feature build, the production lazy type from the gated constructor,
with a definition that could only dial a dead or empty network, reporting **zero connection
attempts and zero calls** after `RevealEngine::prepare` on a fully cached fixture, beside
`units_from_cache > 0` (heavy tier, no devnet); **(c)** in both builds through the spawned binary:
exit 0, `units.from_network == 0`, `units.from_cache > 0`, and **no** *"connecting the read-only
reader"* trace — under no export **and** under a dead export. (No export catches an eager
definition, which would exit 2; a dead export catches an eager connect, which on the pinned stack
does not fail and would otherwise exit 0 after seconds.)

### §2 R9 — `Accept` row 1's test lives in suite S19

In `crates/antseal-cli/tests/e2e_restore.rs`: seal on a sealing home, export, wipe; spawned
`vault import` on a clean home with no export; spawned `--json reveal <work> --units <strict
subset> --yes -o subset.sealproof` with the live export and the backend trace enabled. Pass: exit
0, `units.from_cache == 0`, `units.from_network` equal to the touched files' unit count,
`revealed_unit_ids` equal to the strict subset, exactly one connect trace, and the bundle verifying
through a spawned vault-less `verify --json`. On the same clean home a dead-export control exits 23
per §2 R4, writes no bundle, and its message carries neither *"does not construct one yet"* nor
*"has no data at this address"*. T-D3's assertion text *"(U72; U91 wires the rest)"* is corrected.

### §2 R10 — The `[reveal]` refusal document is retired, not replaced

In the same act: the `json-envelopes.txt` document `[reveal] error [arm:
backend-compiled-in-command-unwired]`, its producer, its registration and its equality row are
retired, the snapshot re-blessed through the real producer, and one assertion added that the
committed snapshot carries no `BackendArm::Compiled` header — so a document of text no build emits
cannot come back. No replacement: the feature build's uncached text is the adapter's per-fetch
reason (upstream churn) or the resolver's sentence (`U92` rewrites it). `reveal`'s machine-mode
class stays passphrase-unavailable (11) in both builds.

### §2 R11 — The orphaned sentence is routed, not deleted here

After this lands `BackendArm::Compiled.message` has zero production emitters in either build. This
record does not delete or reword it — R82 requires that retraction to be argued, and several tests
cite it as a property — and `BackendArm` survives as a build discriminator. **`U95`** owns the
sentence's retirement or rewording and the arm name `backend-compiled-in-command-unwired`, which is
now false for every command.

### §2 R12 — Documents in the same act; the spec untouched

`docs/drills/vault-restore-drill.md` names `reveal` among the steps that need network on a clean
machine; the `commands::reveal` rustdoc, `backend.rs`'s module documentation and the machine-mode
prose are updated; D170 takes a dated addendum. `MVP-SPEC.md` is not edited — the divergence closes
in the product (`Accept` row 3), evidenced by row 1's green and an empty diff of the spec at the
implementing commit. `U91`'s Notes record that this row reaches no public network until `S40`'s
peers are resolvable.

### §2 R13 — The scope word is "backend calls"

`U91`'s `Do` says *zero network calls*; D42's post-output upgrade hook may contact timestamp
calendars, which is anchor I/O outside the storage seam. The record and the row say *zero backend
calls*.

## 3. Fault plants

Owed by the implementing lane, judged by message, `touch` after each restore: the feature handler
driven by `block_on_vault_local` (an uncached reveal dies at the hang guard's tokio timer — `there is no reactor running, must be called from the context of a Tokio 1.x runtime`, exit 101; **corrected in place 2026-10-15 by the registrar on RC2b's measurement — as first written this read "exits 1", and the single no-op poll never reaches a parked future** — the S19 row reds); `read_only_network`
called eagerly in the handler (the no-export cached witness exits 2); `connect_read_only` awaited at
construction (the dead-export witness sees the connect trace; the library counter reads 1 attempt);
a disagreeing `--network` checked eagerly (a cached reveal with `--network arbitrum-one` exits 2);
an unparseable recorded network mapped to 23 (expected 36); the lazy type's `pay` forwarding (its
refusal test goes green-when-wrong — must red); a second production `run_reveal(` (`U71`'s scan);
the retired `[reveal]` document restored (the no-`Compiled`-header assertion). Green baselines first.

## 4. What this record does NOT decide

- **An authoritative `NotFound` during a reveal is exit 23 (*retry later*), though on a permanent
  network it means the data is gone** — a D69 question, flagged to its owner; not changed here.
- Write-back of fetched units to the cache — not ruled; it would make `reveal` a vault writer.
- Upstream network-stack `Drop` behaviour outside a runtime — avoided by §2 R5, not established.

## 5. Edit list — per write scope, with the lane named before this record was written

### RC2b (the reveal lane) — after RC2a (D174's envelope lane) lands
- `crates/antseal-cli/src/backend.rs`: the lazy type (ungated policy half, gated constructor next
  to `connect_read_only`), the per-build driver, module documentation (§2 R1, R5, R7).
- `crates/antseal-cli/src/commands.rs`: `fn reveal` only (§2 R2, R3, R5, R6).
- A new test file for §2 R8 (b) (must not call `run_reveal(`); `tests/restore_output.rs` or a
  sibling for §2 R8 (c); `tests/e2e_restore.rs` (§2 R9); `tests/machine_mode.rs` and
  `tests/snapshots/json-envelopes.txt` (§2 R10).

### RD (the devnet-and-user documentation lane)
- `docs/drills/vault-restore-drill.md` (§2 R12).

### Registrar
- Mint `U95` (§2 R11); `U91` Notes; a dated addendum on D170; index row and register row.

## Closing — this record is not consent

It authorises no network act beyond the local devnet.
