# D44 — Wallet import formats: raw hex only vs +mnemonic

- **Status: RESOLVED — raw hex private key only in v1 (64 hex digits,
  optional `0x`, case-insensitive, k256 scalar-validated), accepted-set
  defined as "whatever the pinned evmlib/alloy parse accepts" so import
  validation and the payment path cannot drift. Mnemonic import is
  rejected for v1: the pinned upstream stack does not compile it in, it
  pulls two new payment-path crates into the exact-pin class, and its
  derivation-path ambiguity creates a silent wrong-wallet failure mode.
  Revisit trigger recorded.**
- **Date: 2026-08-01** (planning; S5 implements validation, U11 the flow)
- **Owning tasks:** S5 (import validation, tasks/S.md:65 "formats per
  D44"), U11 (init import path), U10 (storage), D39/D41 (the key-material
  channel `--wallet-key-fd`).

## Context

Register entry D44 / U open decision 6 (tasks/U.md:393): `init` offers
wallet **generate or import** (MVP-SPEC.md line 149); the import format
set is open. The wallet key signs real Arbitrum payments, lives inside
the vault under its own sub-key (MVP-SPEC.md line 143), and S5 must
validate imports "over the same pinned evmlib/alloy stack ant-core uses,
so generated/imported keys are valid for the payment path"
(tasks/S.md:65).

## What the pinned upstream actually supports (read from source)

- `evmlib-0.9.0/src/wallet.rs:72-75` —
  `Wallet::new_from_private_key(network, private_key: &str)`; fails with
  `Error::PrivateKeyInvalid` (wallet.rs:38). This is the **only** import
  constructor evmlib exposes (the rest are `new` from a prebuilt signer,
  `new_with_random_wallet`, `random_private_key`; no mnemonic API
  exists anywhere in the crate).
- The parse chain: wallet.rs:242-243 → alloy
  `PrivateKeySigner: FromStr` →
  `alloy-signer-local-1.4.3/src/private_key.rs:224-230`:
  `hex::decode_to_array::<_, 32>(src)` (const-hex: optional `0x`,
  case-insensitive, exactly 64 hex digits) then
  `SigningKey::from_slice` (k256: rejects 0 and ≥ group order). So the
  stack already gives exact-length, prefix-tolerant, scalar-validated
  hex import for free.
- Mnemonics are a **compiled-out feature**: evmlib's alloy dependency
  enables `["contract", "json-rpc", "network", "node-bindings",
  "provider-http", "reqwest-rustls-tls", "rpc-client", "rpc-types",
  "signer-local", "std"]` (`evmlib-0.9.0/Cargo.toml:56-70`) — no
  `mnemonic`. Enabling it means alloy-signer-local's `mnemonic` feature,
  which activates `dep:coins-bip32` + `dep:coins-bip39`
  (`alloy-signer-local-1.4.3/Cargo.toml:50-52`).

## Decision

**Raw hex only for v1.**

1. Accepted input (arriving via `--wallet-key-fd`, D39/D41, or no-echo
   interactive paste — never argv/env): after D41-style fd read
   (one trailing LF/CRLF stripped, no interior control bytes, non-empty),
   the string must parse through the *same pinned stack the payment path
   uses* — i.e. acceptance is defined extensionally as
   `Wallet::new_from_private_key` succeeding. That yields: optional `0x`,
   64 hex digits either case, valid secp256k1 scalar. S5 wraps the
   upstream error into its typed rejection (tasks/S.md:67) without
   echoing any part of the input (project rule 6).
2. **No mnemonic (BIP-39) import in v1.** Also explicitly out: keystore
   V3 JSON files (alloy's `keystore` feature — same additive-later
   status, weaker demand).
3. Both are legal *additive* extensions later: a new accepted format
   widens `init`'s input set without touching vault format, payment
   path, or any frozen surface. The reversible direction is to start
   narrow.

## Rationale — why mnemonic loses on three independent grounds

1. **Pin governance** (`docs/dependency-policy.md` §1): "Any new
   dependency whose output bytes end up hashed, signed, stored, or paid
   for joins the class." A mnemonic-derived key signs payments, so
   `coins-bip39` + `coins-bip32` (wordlists, PBKDF2 path, BIP-32
   derivation) would enter the exact-pin class and the weekly advisory
   watch — permanent maintenance for an input convenience. Today they
   are not in the graph at all (deny.toml scans would gain two crates
   plus their trees; `bans.multiple-versions = "warn"` would likely
   light up on their hmac/sha2 generations).
2. **The silent wrong-wallet failure mode.** A mnemonic does not name a
   key; a *(mnemonic, passphrase, derivation path, index)* tuple does.
   Wallet vendors disagree on paths (`m/44'/60'/0'/0/i` vs legacy and
   Ledger variants), so an import that derives a different path than the
   user's original wallet silently produces a *valid but different,
   empty* address — the user funds/holds ANT at one address and antseal
   pays from another. Raw hex has no derivation step and therefore no
   such failure mode: the imported key **is** the wallet. For a payment
   tool this asymmetry matters more than entry ergonomics.
3. **Hygiene positioning.** The spec's wallet-linkability mitigation is
   *fresh, disposable* funding keys (MVP-SPEC.md line 185: wallet-hygiene
   docs, fresh address per work/client), and vault theft includes wallet
   theft (line 143). Mnemonic import invites pointing an HD *root* —
   a user's whole wallet hierarchy — at a hot operational vault. Hex-only
   nudges toward exporting one purpose-made key, which is the
   documented posture. (The M1 E2E imports Anvil's pre-funded dev keys —
   raw hex is also exactly what the devnet hands us.)

Confirmation of fit: the fallback flow S1 §9 keeps viable is literally
`Wallet::new_from_private_key(vault_key)`
(`docs/research/S1-ant-core-api-survey.md` §2, §9), and the primary
external-signer flow signs with the same k256 key material — one format
covers both flows with zero conversion code.

## Consequences — task integration

- **S5**: implements validation as Decision 1 (parse-through-pinned-
  stack; typed error; zeroizing buffers end-to-end). Unit tests: valid
  key with/without `0x`; uppercase; 63/65 digits; non-hex; zero scalar;
  ≥-order scalar; trailing-newline tolerance from the fd read.
- **U11**: import wizard prompt says "raw hex private key (64 hex
  digits)"; docs show how to export one from common wallets and how to
  make a fresh one. Error copy must not claim mnemonics are unsupported
  *forever* — say "not supported in this version".
- **U1/D39**: no new surface beyond D39's `--wallet-key-fd`.
- **Q (docs)**: wallet-hygiene page states the disposable-key posture as
  the reason there is no mnemonic path (turns the limitation into the
  recommendation it actually is).

## Residual risk / revisit trigger

- Real users with mnemonic-only wallets must run one external derivation
  step (any standard tool) — friction, accepted and documented.
- **Revisit trigger:** recurring user requests plus willingness to
  decide, in one package: fixed derivation-path policy (which paths,
  index scanning or not, 25th-word support), the coins-bip39/bip32 pins
  joining §1, and UI copy that shows the derived address for
  confirmation *before* storing anything. Until someone will decide all
  of that deliberately, the format set stays hex-only.
