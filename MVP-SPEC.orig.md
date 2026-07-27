# MVP Spec — Notary / Proof-of-Existence Service on Autonomi 2.0

Working name: **`antseal`** (placeholder — rename freely; used for the CLI binary and crate prefix below).

## Context

Research in this conversation established:

- Autonomi 2.0 (the WithAutonomi/Saorsa upstream) is live and usable **today for immutable, pay-once-forever storage** (chunks/files via `ant-core` 0.5.x on crates.io, payments on Arbitrum One). Mutable data types don't exist yet — irrelevant here, since notarization only needs immutability.
- The timestamping market is commoditized (OpenTimestamps is free; WIPO PROOF died of low demand). The defensible product is the **bundle**: private-until-revealed permanent vault + **granular, provable selective disclosure** + zero-install third-party verification. Nobody ships Merkle-level partial reveal as a product.
- Two hard design constraints from the research: (1) Autonomi itself provides no trusted clock — timestamps must come from independent anchors (OTS/RFC 3161/Arbitrum payment receipt) so evidence survives even if the young network resets again; (2) Autonomi's native self-encryption is convergent — secret work must be wrapped in randomized AEAD before upload or it's vulnerable to confirmation attacks.

MVP scope decisions (user-confirmed):

1. **Form factor**: Rust CLI (non-custodial, user's own wallet) + static web verifier page (same core via WASM). No backend.
2. **Reveal depth**: manifests commit the salted fine-grained byte-tree **from day one** (every seal is forever byte-range-revealable); MVP reveal tooling is whole-work + per-section; byte-range reveal commands land in v1.1.
3. **Anchors**: OpenTimestamps (Bitcoin) + ≥2 free RFC 3161 TSAs + captured Arbitrum payment receipt, on every seal. eIDAS-qualified stamps = later paid tier.
4. **Network**: develop and test on local devnet / Sepolia; **release defaults to Arbitrum One mainnet**, with `--network devnet|sepolia` as the development flag. Maintainer accepts tracking upstream breaking changes (weekly release cadence upstream; pin + adapter layer below).

## Product definition

**One-liner**: Seal your work into permanent encrypted public storage with independently verifiable timestamps; later, reveal all of it — or any part of it — to anyone, with proof it belongs to what you sealed.

**MVP user**: technical-ish creators, researchers, inventors, small legal/IP practices comfortable with a CLI. **Counterparties/verifiers need zero install** (drag a proof file onto a web page).

**Positioning constraint**: never call it a "notary" in legal copy — it is proof of existence/integrity/priority, not identity attestation. Docs must state this.

**Explicitly OUT of MVP scope** (parking lot, v1.1+): byte-range reveal *tooling* (commitment ships now), eIDAS-qualified stamps, hosted SaaS/org gateway, GUI/desktop app, C2PA manifest export, Arweave mirror tier, ZK position-blinded reveals, key escrow/social recovery, re-anchoring service, public anchor-bundle uploads.

## Core user flows

1. **Seal**: `antseal seal thesis/ --title "..."` → canonicalize → encrypt units → upload ciphertexts + manifest to Autonomi (paid, permanent) → anchor manifest hash (OTS pending + RFC 3161 tokens + Arbitrum receipt) → print work-id + cost. Nothing readable ever leaves the machine.
2. **Status/upgrade**: `antseal status <work-id> --upgrade` → completes pending OTS attestation (Bitcoin confirmation lag), shows each anchor's state.
3. **Reveal**: `antseal reveal <work-id> --units 3,5` (or `--all`) `-o pitch.sealproof` → self-contained proof bundle (embeds ciphertext + keys/salts for revealed units only + manifest + all anchors).
4. **Verify** (third party): drag `pitch.sealproof` onto the static verifier page (or `antseal verify pitch.sealproof`) → offline verdict: what content is proven, its position in the sealed whole (blackout redaction view), and the earliest provable time per anchor. Optional online mode confirms the Bitcoin block, TSA cert chains, and Arbitrum tx via public APIs; optional `--live` (CLI) re-fetches ciphertext from Autonomi to prove persistence.

## Architecture

Cargo workspace, greenfield in `/home/deb/Documents/code0`:

```
antseal/
  crates/
    seal-core/       # pure logic, WASM-safe (no I/O): canonicalization, crypto,
                     # manifest + bundle formats, full verification
    seal-anchor/     # OTS client (submit/upgrade/verify), RFC 3161 client (DER req/resp),
                     # Arbitrum receipt capture/check
    seal-net/        # Autonomi storage behind a `StorageBackend` trait; ant-core impl + mock
    seal-cli/        # binary `antseal` (clap, tokio)
  verifier-web/      # static page: plain HTML/JS + seal-core compiled via wasm-bindgen
  testdata/          # golden vectors, UTF-8 edge-case corpus, tamper matrix fixtures
```

**Key external dependency**: `ant-core = "=0.5.0"` (pin exactly; upstream is pre-1.0 with weekly releases). All network use goes through `seal-net::StorageBackend` (`put_data`, `get_data`, `put_chunk`, `get_chunk`, `cost_quote`, `payment_receipts`) so upstream churn is contained in one impl file and tests run on `MockBackend`. Reuse upstream as-is: `Client::connect`, `with_wallet`, `data_upload`/`data_download` (public mode), `chunk_put`/`chunk_get`, and the local devnet example (`start-local-devnet`, 25 nodes + Anvil) from the ant-client repo.

### Canonicalization (v1 — frozen at seal time, recorded in manifest)

- A **work** = one or more files + metadata. Each file commits its **raw bytes** always; text files (valid UTF-8, or `--force-text`) additionally commit a **canonical rendition**: UTF-8, NFC-normalized, LF line endings, no BOM. All offsets/indices = **byte offsets into the canonical rendition** (unambiguous; UI later maps graphemes→bytes).
- **Units** (= reveal granularity in MVP): default one unit per file; `--split blank-lines` splits text files on blank-line paragraph boundaries. Binary files are always single-unit and get no fine tree.

### Cryptography (v1)

- Per-work master secret `W` (32 B, OS CSPRNG) in the local vault. Everything else derives from `W` via HKDF-SHA256 with distinct labels — vault stores only `W` + metadata.
- **Unit encryption**: `k_u = HKDF(W, "unit-key"‖unit_id)`; XChaCha20-Poly1305, random nonce, AAD = `work_id‖unit_id`. Ciphertexts are what Autonomi stores (uploaded "public" — they're opaque; randomized AEAD defeats convergent-encryption confirmation attacks by construction).
- **Salted commitments** (hiding + binding, revealed piecemeal):
  - per-unit: `unit_commit = SHA-256(unit_salt ‖ canonical_unit_bytes)`, `unit_salt = HKDF(W, "unit-salt"‖unit_id)` (16 B). Salting is mandatory — short units are guessable.
  - per-file fine tree (text only): `salt_i = HMAC-SHA256(HKDF(W,"fine-seed"‖file_id), LE64(i))[..16]`; `leaf_i = SHA-256(0x00 ‖ salt_i ‖ LE64(i) ‖ byte_i)`; binary SHA-256 Merkle with `0x01` node prefix (domain separation). Only the root enters the manifest; tree recomputed on demand. This is the v1-committed, v1.1-revealed layer.
- **Author signature**: hybrid **Ed25519 + ML-DSA-65** over the manifest body (RustCrypto `ed25519-dalek` + `ml-dsa`/`fips204`). Verifier requires both. Fallback if ML-DSA proves WASM-hostile during M0: ship Ed25519-only, manifest format already reserves the second sig slot (format change not required later).
- **Manifest** (canonical deterministic CBOR, versioned): work metadata (title, claimed time — informational only, pubkeys), file table {path, raw hash, size, canonicalization descriptor, fine_root?, unit table {unit_id, canonical byte-range, unit_commit, nonce, ciphertext network address}}, format version, app version, signatures. `work_id = SHA-256(manifest body)`. Manifest itself is uploaded to Autonomi; **anchors bind `SHA-256(manifest bytes)`**, which transitively binds every commitment.

### Anchoring (`seal-anchor`)

- **OTS**: stamp manifest hash against ≥2 public calendars; store pending `.ots`; `status --upgrade` completes to a Bitcoin attestation. Evaluate `rust-opentimestamps`; if unmaintained, implement the minimal client (the wire format is small) — decide in M2.
- **RFC 3161**: build DER `TimeStampReq` (SHA-256, nonce, certReq), POST to a configurable TSA list (default: FreeTSA + one other free TSA), verify/parse `TimeStampResp`, store DER tokens + TSA cert chains in the vault and in every bundle.
- **Arbitrum receipt**: persist whatever `ant-core` exposes per upload — tx hash(es), block number, quoted chunk addresses, Merkle batch proof if surfaced. Exact shape TBD against the pinned API in M1; treated as the third (bonus) anchor, not the primary one.

### Reveal bundle (`.sealproof`, versioned CBOR)

Self-contained by design — verification must not require Autonomi access:
manifest bytes + all anchor artifacts (+ their fetch dates) + for each revealed unit: `unit_salt`, `k_u`, nonce, **embedded ciphertext**. Verifier: decrypt → canonicalize → recompute `unit_commit` → match manifest → check sigs → check anchors bind the manifest hash → render verdict + redaction view (revealed units in place, unrevealed as sized blackout blocks). Every reveal displays position + total size (anti-out-of-context guardrail).

### Verifier web page

Plain HTML/JS + `seal-core` WASM. Offline-first: full cryptographic verification locally; shows Bitcoin block height/hash and TSA identities with "confirm online" buttons (esplora-style public API for the Bitcoin header; public Arbitrum RPC for the tx). No framework, no build beyond `wasm-pack`; hostable on any static host.

### Vault

`~/.antseal/`: config + per-work records (`W`, receipts, `.ots`, TSA tokens, addresses), encrypted at rest with a passphrase (scrypt → XChaCha20-Poly1305). `vault export`/`import` for encrypted backup. **Docs and CLI must nag: lose the vault (and backup) = lose reveal ability forever; the sealed data itself stays safely unreadable.**

### CLI surface (MVP)

`init` (vault, wallet key import, network config) · `seal` (`--title`, `--split`, `--dry-run` cost quote) · `list` · `status [--upgrade]` · `reveal --all | --units … -o file` · `verify [--online] [--live]` · `vault export|import`. Global: `--network arbitrum-one(default)|sepolia|devnet`, `--json`.

## Milestones

- **M0 — Core formats & crypto** (`seal-core` + `testdata/`): canonicalization, commitments, manifest/bundle encode-decode, full verify logic, hybrid sigs. Golden test vectors + property tests + tamper matrix. WASM build proven here (decides the ML-DSA fallback question early).
- **M1 — Storage** (`seal-net`): pinned ant-core behind `StorageBackend` + mock; end-to-end seal→fetch→verify on the local devnet; payment-receipt capture nailed down against the real API.
- **M2 — Anchors** (`seal-anchor`): OTS submit/upgrade/verify, RFC 3161 request/verify, receipts folded into bundles; `status`.
- **M3 — Reveal + verifier**: bundle builder, `verify` CLI, WASM verifier page with redaction view, offline/online modes.
- **M4 — Hardening & release**: threat-model doc, vault-loss + "not a legal notary" docs, Sepolia then one real mainnet smoke seal, cross-platform binaries, CI (fmt/clippy/test/wasm), **release with mainnet default**. Post-release chore: weekly upstream-bump check (user-accepted).
- **v1.1 parking lot**: byte-range reveal tooling (`reveal --range`, range proofs in bundles — format already supports it), qualified eIDAS tier, anchor-bundle public upload, C2PA export, grapheme-selection UX.
  *Why byte-range tooling is v1.1 (user-confirmed twice):* the fine-tree **commitment** ships in every MVP manifest, so no seal is ever locked out of later byte-range reveal; the deferred half is only proof serialization + the selection/rendering UX (canonical-offset mapping, mid-grapheme slicing policy, partial-text redaction view), which is the widest, most trust-sensitive part of M3 and doesn't need to be on the MVP critical path.

## Verification (how we know it works)

- **Unit/property tests** per crate; committed golden vectors so the WASM build must bit-match native verification.
- **Tamper matrix** (every mutation must fail with a distinct error): flipped ciphertext byte, altered manifest field, wrong salt, wrong key, swapped unit, forged sig, `.ots`/TSA token for a different hash, bundle claiming a different byte-range.
- **UTF-8 corpus**: CRLF, NFD vs NFC, BOM, emoji/ZWJ, mixed scripts — canonicalization must be idempotent and cross-platform stable.
- **E2E on devnet** (scripted): start 25-node devnet + Anvil (upstream example), seal multi-file work with `--split`, reveal subset, verify bundle offline via CLI **and** via the WASM page in a headless browser (playwright); `--live` re-fetch passes.
- **Anchor smoke tests**: real OTS calendars (pending → upgraded next day), real FreeTSA token verified against its cert; CI uses a mock TSA + recorded OTS fixtures.
- **Adversarial doc-test**: demonstrate the confirmation attack against an unsalted variant in a test, proving why salts are non-optional (regression guard for future refactors).
- **M4 gate**: one real Sepolia seal + one small real mainnet seal, verified end-to-end from a clean machine using only the released binary + the hosted verifier page.

## Risks & mitigations

- **ant-core 0.5.x churn / weekly upstream releases** → exact pin + `StorageBackend` isolation + mock-first tests; user commits to tracking bumps.
- **Autonomi network youth (one reset already)** → evidence validity never depends on Autonomi: bundles are self-contained, anchors are Bitcoin/TSA. Storage permanence is the product's bonus, not its proof.
- **`rust-opentimestamps` maturity unknown** → evaluated in M2 with a budgeted fallback (minimal vendored client).
- **ML-DSA in WASM unknown** → probed in M0; reserved manifest slot makes the fallback non-breaking.
- **Free TSA availability** → ≥2 TSAs, configurable, failures downgrade the seal report rather than abort (OTS + Arbitrum still anchor).
- **Vault loss = product-level footgun** → export nag on first seal, loud docs.
