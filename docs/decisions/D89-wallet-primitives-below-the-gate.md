# D89 — The wallet and balance primitives below the `ant-backend` gate

- **Status: RESOLVED — the light half moves into the DEFAULT graph, over a
  direct exact-pinned `k256` (no `ecdsa` feature) plus `sha3` for
  Keccak-256; `BalanceReport`/`PreflightReport` and the shortfall rule move
  with it at zero dependency cost, and `balances()` joins the
  `StorageBackend` trait. Measured: 120 → 129 packages in the default
  `--workspace` graph, **zero** added to the `ant-backend` (447) and devnet
  (475) graphs, **zero** new entries in `Cargo.lock`. Both of the register's
  option framings are overturned: (a) rests on a product statement that was
  already decided elsewhere and fails on a measurable *coverage* regression,
  not on taste; (b)'s "k256/alloy-primitives-scale" is wrong by measurement —
  the `alloy-signer-local` route costs +71 packages, six times the k256
  route. D44 is not weakened: acceptance stays the pinned stack's *by
  construction*, because alloy's own parse bottoms out in exactly the
  `k256` call the light half will make, on exactly the version the lock
  already pins.**
- **Date: 2026-08-02** (M1 execution wave; blocks U11 and U14 now, U13
  transitively; register TODO.md:353 (U37), TODO.md:354 (U38))
- **Owner: U37; executed in `antseal-net` (new ungated wallet module), U11
  (`init`), U14 (consent gate), and one added `dep-graph` rule**
- **Blocks: U11, U14, U13 (via U11/U14); §7 unblocks U11's wizard half**

## Context

`crates/antseal-net/src/evm.rs` is gated in its entirety
(`crates/antseal-net/src/lib.rs:82-83`), and the same feature gates the
adapter (`lib.rs:72-73`) and its re-exports (`lib.rs:99-100`). That module
is the only home of the wallet primitives `init` needs — `WalletKey::generate`
(evm.rs:158-175), `WalletKey::import` (evm.rs:191-245), `address()`
(evm.rs:254-267), `checksummed()` (evm.rs:101-104) — and `ant_backend.rs` is
the only home of `BalanceReport`/`PreflightReport` (ant_backend.rs:149-178),
which U14 renders.

The feature is non-default by decision, and the containment around it is
real work: S23's manifest-owner rule, S6's use-confinement allowlist, P20's
four rules, S22's three-tier gate policy. U37 therefore posed the question as
a product-identity choice — gate `init` too, or pay the default graph an
"secp256k1+keccak edge … exactly the 120-package measurement dep-graph rule 1
pins".

Three of that framing's load-bearing claims are false, and correcting them
changes which option wins. They are corrected first, because two of the three
would otherwise decide the outcome by themselves.

## The register's framing, corrected

### Correction 1 — dep-graph rule 1 does not pin 120; it pins five names

Rule 1's assertion is a name scan: the default `--workspace` tree must
contain no line matching `^(ant-node|ant-core|ant-protocol|evmlib|alloy) v`
(`scripts/ci-lanes.sh:340-346`). The package count is computed *after* the
verdict and printed into the OK message, under a comment that says what it is
in terms: "Evidence, not decoration: the two package counts are the size of
what the feature gate is holding back, and a collapse toward each other is
visible in the log before it is a violation" (`scripts/ci-lanes.sh:348-354`).
`docs/dependency-policy.md:87-96` states rule 1 the same way and records the
figure as "Measured at P20: 120 packages by default, 475 with
`devnet-launcher/devnet`".

Reproduced today with the lane's own command and counting method
(`sed 's/ .*//' | sort -u | grep -c .`): **120** default, **475** with
`devnet-launcher/devnet`, **447** with `antseal-net/ant-backend`.

So no assertion in any lane pins the number. `k256`, `sha3`,
`elliptic-curve` and friends match none of the five forbidden names, so under
every option in this record **rule 1's verdict is unchanged**. What changes is
a printed evidence number and one recorded sentence in the dependency policy.
That is a documentation consequence, not a containment breach — and it must
still be written down, which §6 does.

### Correction 2 — the balance half is not a dependency question at all

`BalanceReport` is `EvmAddress20` + two `u128` (ant_backend.rs:152-161);
`PreflightReport` is four `u128` (ant_backend.rs:167-178). `EvmAddress20` is
defined in `network.rs:106` — the pure half, already in the default graph.
Neither type names one upstream type. They are gated **only because they were
written inside a gated file**. Moving them costs exactly zero packages, and
the option space (a)/(b)/(c) does not apply to them.

Under the same correction the *real* U14 blocker becomes visible, and it is
not the feature gate: `balances()` and `preflight()` are inherent methods on
the concrete `AntCoreBackend` (ant_backend.rs:388, 415), while the
`StorageBackend` trait carries only `quote_batch`/`pay`/`finalize_batch`/
`get_data` (`crates/antseal-net/src/backend.rs:65-131`). A consent gate
written against them would hold a concrete backend — violating project rule 1
("all network access goes through `seal-net::StorageBackend`") and D34's
injected-interface design, and making U14 Accept row 4 (tasks/U.md:235)
untestable against `MockBackend` **even with the feature on**. U37's note
that "the pipeline never calls `preflight`/`balances` today" is the same
finding seen from the other side: there is no seam to call through yet.

### Correction 3 — a default build already cannot seal, and already says so

`antseal-cli`'s own `ant-backend` feature forwards the net feature and the
tokio runtime (`crates/antseal-cli/Cargo.toml:47-49`); `AntCoreBackend`, the
`SealBackend` seam and the vault→`WalletKey` bridge are all behind it
(`crates/antseal-cli/src/backend.rs:63, 110-201`); and U36 already wrote the
typed refusal a default build emits: "`{command}` needs a live Autonomi
connection, and this build has no storage backend compiled in (the
`ant-backend` feature is off by default). The command itself is complete —
rebuild with `--features ant-backend` to reach the network"
(`crates/antseal-cli/src/backend.rs:86-92`).

So "a default build of antseal is an inspect-and-verify build" is **already
true and already shipped**, decided by S12/S22/U36, not by this record. U37's
"it changes what a default build of antseal *is*" is not what is at stake.
The only open question is whether `init` joins the network commands on the
gated side — and, because release binaries must be built with the feature on
to seal at all (D72 open, and untouched here), that question does not reach
any shipped binary. It reaches exactly two things: whether a contributor's
default build can make a wallet, and **where U11/U14's Accept rows can be
asserted**. The second is decisive, and is measured in Evidence 3.

## Evidence

### 1. What each option costs, measured

Method: for each candidate dependency set, a scratch crate outside the
workspace, resolved offline against the same registry, `cargo tree -e normal
--prefix none`; package **names** deduplicated and differenced against the
default `--workspace` name set (the lane's own metric). Every figure below is
executed, not estimated.

| candidate light-half dependency | closure | new names | default graph |
| --- | --- | --- | --- |
| `alloy-signer-local =1.8.3`, `default-features = false` | 114 | **+71** | 191 |
| `alloy-signer-local =1.8.3`, default features | 114 | +71 | 191 |
| `alloy-primitives =1.6.1` alone | 25 | +11 | 131 |
| `k256 =0.13.4` (`ecdsa`,`arithmetic`) + `sha3 =0.11.0` | 26 | +11 | 131 |
| **`k256 =0.13.4` (`arithmetic` only) + `sha3 =0.11.0`** | **21** | **+9** | **129** |

The nine: `base16ct`, `const-oid`, `crypto-bigint`, `der`, `elliptic-curve`,
`ff`, `group`, `k256`, `sec1`. `sha3` costs zero *names* (the name is already
in the default set via the dev-side fips204 stack) and one package in the
normal graph; its entire closure — `block-buffer 0.12.1`, `crypto-common
0.2.2`, `digest 0.11.3`, `hybrid-array`, `keccak 0.2.0`, `typenum`, `cfg-if` —
is already in the default **normal** graph, because sha3 0.11 sits on the same
RustCrypto 0.11 generation the project already pins for `sha2`/`ml-dsa`.

Three consequences of the table:

- **Option (b) as framed is refuted.** The register calls the light half
  "k256/alloy-primitives-scale", but the D44 gate crate is
  `alloy-signer-local`, and taking it costs **+71** — `alloy-sol-macro`,
  `syn-solidity`, `darling`, `ruint`, `http`, `bytes`, `serde_with`, `crc`
  and the rest — a 59 % increase in the default graph to obtain four
  functions. `alloy-primitives` alone (+11) buys only `Address` and its
  EIP-55 `Display`, which is twenty lines over a hash the light half needs
  anyway.
- **Dropping k256's `ecdsa` feature is free and strictly better.** It removes
  `ecdsa`, `rfc6979` — and, though they do not move the *name* count,
  `signature 2.2.0` and `hmac 0.12.1`, which would otherwise sit beside the
  project's `signature 3.0.0` and `hmac 0.13.0` as duplicate generations. The
  acceptance predicate is unaffected: see Evidence 4.
- **The heavy graphs do not move at all.** `k256 0.13.4`,
  `elliptic-curve 0.13.8`, `crypto-bigint 0.5.5` and `sha3 0.11.0` are already
  in the `ant-backend` tree, and all nine new names are already in
  `Cargo.lock`. The lockfile delta is dependency-list lines only — the U36
  tokio precedent, where "the lockfile delta is one line".

### 2. `precomputed-tables` and the one performance note

`k256`'s default `precomputed-tables` feature is off in the measured
configuration, which makes the single scalar multiplication per `init`
slower. Should it ever matter, turning it on adds `once_cell` — already one
of the 120. Recorded so the choice is visible, not so it is revisited.

### 3. The coverage cliff behind option (a) — the decisive evidence

Under option (a), U11's wallet-touching code is `#[cfg]`-inactive in a
default build, and inactive code is not compiled, not type-checked, not
linted. Where would it then be checked?

- **Required CI: nowhere.** The required contexts are default-feature:
  `cargo clippy --all-targets --locked` (`.github/workflows/ci.yml:122`) and
  `cargo test --workspace --locked` (`ci.yml:148`). No `--features` anywhere.
  This is exactly what S30 records as an open problem in its own words: "No
  CI lane compiles the heavy feature paths at all … the only remote compile of
  `ant-backend`/`devnet` is the **weekly, non-required** `devnet-e2e-cron`"
  (TODO.md:319).
- **Local tier 2: not triggered.** S22's heavy tier fires from a path list —
  `crates/antseal-net/`, `crates/antseal-cli/src/pipeline/`,
  `crates/antseal-cli/src/vault/wallet.rs`, `crates/devnet-launcher/`,
  `scripts/devnet/`, `scripts/e2e-devnet.sh`, `Cargo.toml`, `Cargo.lock`
  (`scripts/gate-features.sh:88-95`). `init`'s handler and its copy are in
  none of them, so a change to the wizard would be classified light and
  compiled by no tier that runs.

So option (a) does not merely move four of U11's six Accept rows
(tasks/U.md:181, 182, 183, 184) to a slower lane. It moves them to a lane no
required gate runs and no local trigger selects, for a file set whose changes
that trigger cannot see. The wizard-order snapshot, the three-network funding
copy, the U31 possession-language catalog entries and the `--json` fixture
would be, in the ordinary course of work, **unbuilt**. That is a measurable
regression against the project's own gate topology, and it is what defeats
(a) — not any argument about what a default build ought to be.

(Option (a) also leaves U11 Accept row 3 — the wizard-order snapshot —
unassertable anywhere cheap, because the wizard cannot run to completion in a
build with no wallet source.)

### 4. D44 survives by construction, and it is executed, not argued

The pinned acceptance chain, read in the vendored sources rather than
inferred:

1. `evmlib::Wallet::new_from_private_key` → alloy `PrivateKeySigner: FromStr`;
2. `impl FromStr for LocalSigner<SigningKey>` is
   `hex::decode_to_array::<_, 32>(src)?` then `Self::from_slice(&array)?`
   (`alloy-signer-local-1.8.3/src/private_key.rs:224-230`);
3. `LocalSigner::from_slice` is `SigningKey::from_slice(bytes)`
   (`private_key.rs:52-54`);
4. `ecdsa::SigningKey::from_slice` is `SecretKey::<C>::from_slice(bytes)`
   (`ecdsa-0.16.9/src/signing.rs:99-103`).

The acceptance gate is therefore **`k256`'s `SecretKey::from_slice` and a hex
decoder**, and nothing else. The light half calls the identical function on
the identical version — `Cargo.lock` records `alloy-signer-local`'s dependency
as a **bare** `"k256"` entry, which is the lock's own statement that exactly
one k256 exists (the same encoding P20 rule 3 already reads for alloy), and it
is 0.13.4. The hex layer is *already ours* today: evm.rs:223-232 does length,
prefix and digit checking before upstream is consulted, and evm.rs:16-30
records that the pre-checks exist only to name the failure class.

So option (c) does not introduce a second acceptance implementation. It
deletes one indirection from an existing two-layer arrangement and keeps the
same bottom layer.

Executed against the project's own committed known answers, on
`k256 =0.13.4` (`arithmetic` only) + `sha3 =0.11.0`, offline:

```
scalar1   = 0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf   (evm.rs:722-727 expects exactly this)
zero     accepted = false        order n  accepted = false
n-1      accepted = true         all-ff   accepted = false
eip55 roundtrip 0xa78d8321B20c4Ef90eCd72f2588AA985A4BDb684 = true
eip55 roundtrip 0x9A3EcAc693b699Fc0B2B6A50B5549e50c2320A26 = true
eip55 roundtrip 0x4bc1aCE0E66170375462cB4E6Af42Ad4D5EC689C = true
```

Row 1 reproduces `known_scalar_derives_the_known_address` (evm.rs:716-728)
byte-for-byte. Rows 2–3 reproduce the whole scalar-boundary set the current
feature-path test asserts (evm.rs:613-628, constants at evm.rs:409-413). Rows
4–6 are the three committed EIP-55 contract constants
(`crates/antseal-net/src/network.rs:65, 70, 80`) round-tripped through a
hand-written EIP-55 renderer — which means the ungated renderer inherits three
known-answer vectors in the **default** lane for free, and they are the same
constants evm.rs:464-465 and 480-484 already check against alloy's `Display`
on the feature path.

### 5. The lane-δ agreement test survives intact, and becomes load-bearing

`import_acceptance_equals_the_pinned_stack_acceptance` (evm.rs:646-682) —
S5's (lane δ) agreement test — asserts, for a valid set and an invalid set,
that our verdict equals `Wallet::new_from_private_key`'s. It compares a
now-ungated `WalletKey::import` against a still-gated upstream parse, so it
**stays exactly where it is**, in evm.rs's gated test module, with its body
unchanged. It survives this decision without a line of edit.

Its status changes, though: today it pins our structural pre-checks against a
call we then make anyway; afterwards it is the only executable statement that
two independently-reached implementations agree. It must therefore be treated
as a guard, not a nicety — §5 of the Decision says how.

## Decision

### 1. The wallet light half moves to the default graph, in its own ungated module

A new **ungated** `crates/antseal-net/src/wallet.rs` owns `WalletKey` and
`generate` / `import` / `address` / `as_hex` / `into_hex` / redacted `Debug`,
plus `checksummed()`, `WalletImportError` and the non-config arms of
`WalletOpsError`. `evm.rs` stays gated and keeps `to_evm_network`, the
`Wallet`/`EvmNetwork` re-exports, and an `impl WalletKey` block carrying
`evm_wallet()` — an inherent impl for the same type from a second module in
the same crate, which is ordinary Rust and keeps `WalletKey` one type across
the gate.

**`wallet.rs` is deliberately NOT added to the S6 allowlist**
(`scripts/ci-lanes.sh:234-240`). Keeping it off the list is what makes
"the light half names no upstream crate" a machine-checked fact rather than a
comment: the moment an `ant_core::`/`ant_protocol::` code line appears there,
`dep-graph` fails (`ci-lanes.sh:260-266`).

### 2. Dependencies: `k256` without `ecdsa`, `sha3`, and the existing `getrandom`

- `k256 = "=0.13.4"`, `default-features = false`, `features = ["arithmetic"]`.
  Exact-pinned into dependency-policy §1's class, with **lockstep to alloy /
  evmlib, not to the project's crypto stack**: D44 defines acceptance as what
  the pinned payment stack accepts, so this pin follows whatever k256 the
  ant-core graph locks and moves only inside an ant-core bump review (§4).
- `sha3 = "=0.11.0"`, `default-features = false` — Keccak-256 for address
  derivation and EIP-55. Not lockstep with anything: Keccak-256 is a fixed
  function and the known-answer vectors are the authority (the `blake3` row's
  reasoning, `docs/dependency-policy.md`).
- Keygen draws from the **already-pinned `getrandom =0.4.3`**, not the
  `getrandom03` (0.3.4) alias the gated module uses. The 0.3 alias exists to
  match the ant-core graph; in the default graph the project's own pinned
  0.4.3 is already a normal dependency of `antseal-cli`, so this adds nothing
  and keeps one fewer getrandom generation in the product graph.

Both new edges are declared by `antseal-net` only. Neither name is in S23's
guarded set, and `antseal-net` is an allowed owner regardless
(`ci-lanes.sh:141-186`) — so rule 4's verdict is unchanged.

### 3. `BalanceReport` and `PreflightReport` move to the default graph, and `balances()` joins the trait

- Both structs move verbatim into the default graph (`backend.rs` beside the
  trait, or `network.rs`; placement is the implementer's, the gate is not).
  Zero packages.
- `StorageBackend` gains `async fn balances(&self) -> Result<BalanceReport,
  StorageError>` — a network call, so by project rule 1 it belongs on the
  seam. `MockBackend` gains a settable canned report; `AntCoreBackend`'s
  existing body (ant_backend.rs:388-395) becomes the impl.
- The **shortfall rule** becomes a pure default-graph function
  `preflight(&BalanceReport, &CostQuote) -> Result<PreflightReport,
  StorageError>`, lifted verbatim from ant_backend.rs:417-435 — including
  the documented ANT-first order. `AntCoreBackend::preflight` becomes
  `preflight(&self.balances().await?, quote)`, so `pay()`'s internal re-check
  (S8's guarantee) keeps calling exactly one implementation, and U14 Accept
  row 4's insufficient-token/insufficient-gas split becomes a default-lane
  unit test over a pure function.

`preflight` does **not** go on the trait: it is arithmetic, not I/O, and
putting it there would let an implementation disagree about which shortfall
fires.

### 4. `dep-graph` gains a fifth rule: one k256, and it is alloy's

Modelled exactly on P20 rule 3 (`ci-lanes.sh:370-405`), whose mechanism is
already proven and self-tested:

1. `Cargo.lock` resolves exactly one `k256` version;
2. the recorded `=` pin literal in the workspace manifest equals it;
3. when `alloy-signer-local` is in the lock, its dependency entry for `k256`
   is **bare** (unqualified) — the lock's own statement that there is one
   k256 and both of us are on it;
4. self-test first, on a planted version-qualified entry, in the shape
   `Cargo.lock` emits — the house pattern every rule in this lane already
   follows.

This is an **addition**. No existing assertion is relaxed, removed or
re-scoped by this decision.

### 5. Verification obligations that land with the code

- **Default lane, new**: the scalar-1 → `0x7E5F…Bdf` known answer (moved out
  of evm.rs, which keeps its own copy on the feature path); the scalar
  boundary set (0, n, n−1, all-FF); the three EIP-55 contract constants; the
  D44 rejection classes (wrong length / non-hex / whitespace / mnemonic /
  invalid scalar) that U11 Accept row 2 enumerates.
- **Feature path, unchanged**: `import_acceptance_equals_the_pinned_stack_acceptance`
  (evm.rs:646-682) stays byte-for-byte, and is now the drift guard between
  two implementations rather than a tautology. It is joined by an EIP-55
  agreement assertion — the existing `checksummed(...) == ARBITRUM_…`
  comparisons (evm.rs:464-465, 480-484) already are one, and now compare our
  renderer against alloy's `Display` rather than alloy against itself.
- Because `crates/antseal-net/` is already a tier-2 trigger path
  (`gate-features.sh:88`), any change to the light half automatically runs
  the feature-path agreement test locally. The coupling this decision relies
  on already exists; it needs no new trigger.
- Fixture discipline unchanged: keys derive via `alternate_test_secret`, never
  committed literals (project rule 6); the secret-guard lane needs no new
  exclusion, since no new magic literal is introduced.

## Rationale

**Why (a) loses.** Not on product taste — its product statement is already
true and already shipped (Correction 3). It loses because it puts U11's
entire UX surface behind a feature that **no required CI context compiles**
(ci.yml:122, 148) and **no local tier trigger selects for the files involved**
(gate-features.sh:88-95), a gap the project has already recorded against
itself as S30 (TODO.md:319). Choosing (a) would mean choosing to leave four
of six Accept rows unbuilt in ordinary work, in exchange for nine packages.

**Why (b) loses.** By measurement: the D44 gate crate is
`alloy-signer-local`, and it costs +71 packages — a 59 % default-graph
increase, including a proc-macro subtree (`alloy-sol-macro`, `syn-solidity`,
`darling`) and `bytes`/`http`, for four functions. The register's own
description of (b) as "an secp256k1+keccak edge" describes the k256 route,
which is (c).

**Why (c) wins, and why it is not the compromise it looks like.** The usual
objection to (c) — "a reimplementation can drift from the pinned stack" —
does not apply, because the light half is not a reimplementation of the
acceptance predicate. Evidence 4 traces alloy's parse to `k256`'s
`SecretKey::from_slice`; calling that function directly, on the single k256
the lock already pins, is the *same* predicate, and the hex layer around it
was already ours. What is genuinely new is (i) address derivation performed
by us rather than by alloy — pinned by an executed known answer the project
already committed — and (ii) EIP-55 rendering performed by us — pinned by
three already-committed checksummed constants. Both are total functions with
known answers, which is the cheapest possible verification situation.

**Why the balance half is not any of the three.** Correction 2: the types
carry no upstream type, so their gating is an accident of file placement, and
the thing actually blocking U14 is a missing trait method that would block it
with the feature on as much as with it off.

**On the 120.** The number is evidence the lane prints so a collapse is
visible early (ci-lanes.sh:348-354). Moving it to 129 for a measured,
enumerated, already-locked set of nine pure-Rust RustCrypto crates is the
number doing its job — it is recorded, argued and dated, which is exactly
what would *not* happen if an edge drifted in unnoticed. The 355-package
cliff rule 1 exists to guard sits untouched at 475.

## Consequences for the blocked tasks

- **U11 (`init`) — unblocked.** Accept rows 2, 3, 4 and 5 (tasks/U.md:181-184)
  become default-lane rows: import classes, wizard-order snapshot, address +
  three-network funding copy, `--json` fixture. Row 1 (E2E, tasks/U.md:180)
  is unchanged — it was always a devnet row on the feature path. `init` needs
  no refusal branch and no build-conditional copy: in a default build it
  creates a real, fundable wallet whose address is real, and the vault it
  writes is the same vault a payment-capable build opens. **U31 consequence**:
  no new "this build cannot …" copy is introduced by this decision; U36's
  existing two-armed refusal (backend.rs:86-92) remains the only place that
  speaks about builds.
- **U14 (consent gate) — unblocked, and its shape fixed.** The gate takes a
  `BalanceReport` and a `PreflightReport` as data, never a backend; row 1's
  "both balances" renders from the moved struct, row 4's shortfall split
  tests against the lifted pure function. `MockBackend` supplies balances, so
  both rows run in the default lane with no network and no feature.
- **U13 (`seal` orchestration) — dependency chain clears**, and the "new wire"
  U37 named now has a defined shape: the pipeline calls
  `backend.balances()` through the trait before rendering consent, and hands
  the pair to the gate. Nothing else in U13 changes; the payment path stays
  gated.
- **U38 — see §7**; it is `init`'s other blocker and is resolved here.
- **Containment lanes — which assertions change: none.** Rule 1's five-name
  scan, rule 2 (self_encryption, both halves), rule 3 (alloy lockstep), rule 4
  (S23 owners), the `antseal-core` I/O/RNG-free scan (ci-lanes.sh:188-206,
  scoped to `-p antseal-core`, which gains nothing), and the S6 allowlist all
  keep their current verdicts. Two things move and both are additive: the
  **printed** default count 120 → 129, and a **new** rule 5 (Decision 4).
- **`docs/dependency-policy.md` — two edits, both required.** A §1 exact-pin
  row for `k256` (with the alloy/evmlib lockstep clause, §4 bump procedure)
  and one for `sha3` (no lockstep, vector-authoritative); and a dated
  amendment to the rule-1 paragraph at :87-96 restating the measurement as
  "120 → 129 (D89, 2026-08-02); 475 with `devnet-launcher/devnet`,
  unchanged". The policy sentence is the only place the old number is
  recorded as a claim rather than printed as evidence.
- **S20's ant-core bump procedure** gains one line: when the bump moves
  `alloy`/`evmlib`, check whether it moves `k256`, and move our pin with it.
  Rule 5 makes forgetting it a red lane rather than a silent fork of the
  accepted set.

## 7. U38 — `value_source` threading (the sibling)

**Confirmed, with the mechanism and the landing site fixed.**

The defect is exactly as recorded: `InitArgs::wallet`, `kdf` and `wrap` carry
`default_value_t` (`crates/antseal-cli/src/cli.rs:192, 204, 209`), and
`parse_checked` is `Self::try_parse_from(itr)?` followed by `cross_validate`
(cli.rs:367-375) — `try_parse_from` consumes and discards the `ArgMatches`, so
"the user typed `--wallet generate`" and "the user said nothing" arrive as the
same value. D39 Decision 1's "a value already supplied by flag/fd is not asked
again" (tasks/U.md:178) and U11 Accept row 3 (tasks/U.md:182) both turn on the
distinction. `clap::ArgMatches::value_source` has it.

**The fix, exactly:**

1. In `parse_checked`, replace `Self::try_parse_from(itr)?` with the two steps
   the derive performs internally. `Parser::try_parse_from` is exactly
   `command().try_get_matches_from(itr)` then
   `from_arg_matches_mut(&mut matches).map_err(format_error::<Self>)`
   (`clap_builder-4.6.5/src/derive.rs:71-78`), and `format_error` is
   `let mut cmd = I::command(); err.format(&mut cmd)` (derive.rs:387-390) over
   the **public** `Error::format` (`clap_builder-4.6.5/src/error/mod.rs:94`).
   So the behaviour-preserving replacement is:

   ```rust
   let matches = Self::command().try_get_matches_from(itr)?;
   let mut cli = Self::from_arg_matches(&matches)
       .map_err(|e| e.format(&mut Self::command()))?;
   ```

   The non-`_mut` form leaves `matches` intact to query (it works on an
   internal clone), and the `map_err` line is not optional decoration: drop it
   and a `from_arg_matches` failure would render without usage context, which
   is the one observable difference between the two spellings. Same error
   type, same error kinds, same exit codes, same `--help`/`--version` paths.
2. Add `#[arg(skip)] pub provided: InitProvided` to `InitArgs`, a
   `Copy` struct of three bools. `parse_checked` fills it from
   `matches.subcommand_matches("init")` with
   `value_source(..) == Some(ValueSource::CommandLine)` before
   `cross_validate()` runs.
3. `init`'s wizard asks a question iff its bool is false.

**Why it lands there and not in `init`'s handler**: `parse_checked` documents
itself as "the single entry every driver (binary, tests) uses, so no path can
skip validation" (cli.rs:483-485). A second entry point returning sources
would let a caller take the source-less one and silently lose the
distinction; changing the single entry preserves the property. Carrying the
bools **inside `InitArgs`** rather than in the return type keeps all six
existing `parse_checked` call sites unchanged (`src/lib.rs:63`,
`src/machine.rs:271`, `src/machine.rs:318`, `tests/cli_surface.rs:122`,
`tests/vault_export.rs:551`, `tests/vault_export.rs:559`) — the return type
stays `Result<Self, clap::Error>`. `#[arg(skip)]` is supported by the pinned
derive (`clap_derive-4.6.4/src/item.rs:403-405`, `MagicAttrName::Skip`).

**Frozen-surface confirmation, as asked**: no flag is added, removed,
renamed, or has its help text, value name, default or `ValueEnum` variants
touched. `#[arg(skip)]` fields are invisible to clap's builder, so
`crates/antseal-cli/tests/snapshots/cli-surface.help.txt` is unchanged and
must be asserted unchanged (its existing snapshot test is the check — it
should go green without re-blessing; a re-blessed snapshot in this change is a
defect signal).

**Semantics this fixes without changing machine mode**: unsupplied + TTY →
ask (wizard pre-selects the clap default); unsupplied + machine mode → take
the documented default silently (Argon2id per D40, `generate` per D39,
`none` per D50) — *not* an abort, because these three have defaults and are
not "missing required inputs" under D51. Supplied → never asked, in either
mode. `ValueSource::EnvVariable` is unreachable by construction: D41 rejected
env-var channels, and no argument declares one.

**Default direction of the new field**: `InitProvided::default()` is all
`false` = "nothing was flag-supplied", which makes a hand-constructed
`InitArgs` (tests) ask rather than assume — the safe direction.

**Landing discipline** per the U38 entry: its own red-then-green test — a
parse of `["antseal","init"]` versus `["antseal","init","--wallet","generate"]`
must disagree on `provided.wallet` while agreeing on `wallet`, which fails
before the change and passes after. Order: U38 lands **before** U11's wizard
half, and is independent of everything else in this record.

## Residual risks

1. **Two namers of secp256k1.** We and `alloy-signer-local` both name k256.
   Rule 5 (Decision 4) makes a split visible immediately, and the failure mode
   is a red lane during an ant-core bump review — the moment it should be
   noticed. Accepted; it is the same structure D44/P20 rule 3 already accepted
   for alloy, for the same reason.
2. **k256 0.13.x is the older RustCrypto generation** (elliptic-curve 0.13 /
   digest 0.10) and will not track the project's 0.11-generation crypto pins.
   That is correct rather than unfortunate: this pin's partner is the payment
   stack, not our hash stack. Dropping the `ecdsa` feature keeps the
   duplication down to the crates the predicate genuinely needs.
3. **EIP-55 is now our twenty lines.** Guarded by three committed
   known-answer constants in the default lane plus alloy agreement on the
   feature path. Residual: an address shape none of the four vectors covers.
   Cheap closure if wanted — a feature-path property test over random 20-byte
   addresses against alloy's `Display`; recorded, not mandated.
4. **A default build can now create a wallet it cannot spend from.** The key
   and address are real and the vault is portable, so nothing is lost or
   misleading; `seal` still refuses with U36's typed message. No new copy is
   introduced. If field feedback shows users funding a wallet from an
   inspect-only build and then being surprised, the fix is one sentence in
   `init`'s funding copy under U31 — additive, and deliberately not
   pre-committed here.
5. **The default graph is now 129 and the next request will cite this
   record.** Stated plainly: this decision spends nine packages on a
   coverage property, and does not license a tenth without the same
   measurement, the same enumeration, and the same argument.
6. **D72 is untouched.** Release targets and the release build's feature set
   are not pre-committed by anything here; the observation that a sealing
   binary must carry `ant-backend` is a statement about the feature, not about
   D72's answer.

## Discovered-work candidates

- **S-domain** — `StorageBackend::balances()` + the lifted pure `preflight`
  (Decision 3) is real S work sitting inside a U-blocking decision; it may
  warrant its own id rather than riding U14, since `pay()`'s internal re-check
  and `MockBackend` both change.
- **Q-domain** — `dep-graph` rule 5 (Decision 4) plus the dependency-policy
  §1 rows and the rule-1 amendment: gate-script and policy work, Q-owned by
  S22's recorded ownership conclusion.
- **Q-domain** — S30 is the general form of Evidence 3 and is still open; this
  record supplies a concrete, dated instance of the cost (four Accept rows
  nearly landing in an uncompiled lane) as input to whichever branch S30 takes.

## Revisit triggers

- An ant-core bump that moves `alloy`/`evmlib` onto a different `k256` — rule
  5 goes red; move the pin inside the bump review, never alone.
- `alloy` gaining a genuinely light re-export of address/EIP-55 (today it does
  not: the +71 measurement is the whole reason it lost) — would allow
  retiring our EIP-55 lines, not the k256 edge.
- D72 resolving in a way that puts an inspect-only binary on a release
  channel — this record's Consequence for U11 (no build-conditional copy)
  should be re-read at that point, and U31 consulted about the funding copy.
