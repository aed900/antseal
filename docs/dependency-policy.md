# Dependency pin governance (P7)

Normative policy for every dependency of the antseal workspace. Rationale:
antseal produces permanent, versioned formats (manifests, bundles, `.ots`
material, ciphertext addresses) whose bytes must stay verifiable forever,
while several upstream crates release weekly-to-biweekly (ant-core) or are
pre-1.0 and unaudited (ml-dsa). A silently moved dependency version is a
format or consensus incident, not a chore. (MVP-SPEC.md: Key external
dependency; Risks — ant-core churn, PQC crate maturity.)

## 1. The exact-pin class

Every **format-, crypto-, or network-consensus-affecting** dependency MUST
be pinned with an exact `=x.y.z` requirement. Known members (each lands in
the workspace with its owning task; the pin rule binds from the moment it
lands):

| Dependency | Why exact-pinned | Deciding task |
| --- | --- | --- |
| `ant-core` (spec pin `=0.5.0`, re-verified at M0 start) | storage/payment surface; network consensus | P9 |
| `ant-node` — **pinned `=0.15.0` 2026-08-01 (P16; memo docs/research/P16-devnet-feasibility.md §5)**: the in-process devnet node stack behind ant-core's `devnet` feature. ant-core 0.5.0's own caret `0.15.0` requirement is deterministic today only by accident (no other 0.15.x published; 0.16.0 is outside the caret) — the exact pin closes the 0.15.1 window before it opens. Consumed ONLY by the never-published `devnet-launcher` behind its non-default `devnet` feature, never by a product crate; must stay inside ant-core's own requirement, so it moves only within an ant-core bump review (§4) | network consensus: node-side storage/replication/payment-verification behavior defines what the devnet accepts — the S17–S19 E2E evidence runs on exactly this stack | P16 — landed |
| `ant-protocol` — **pinned `=2.3.0` 2026-08-01 (S6)**: the wire-protocol crate ant-core itself depends on, taken as a direct edge because the S6 adapter needs surfaces ant-core does not re-export — `QuoteHash`/`TxHash`/`Amount`, `payment::deserialize_single_node_proof` (the S7 capture-consistency parse of the receipt's `proof_bytes`), `evm::contract::payment_vault` (per-sub-batch `payForQuotes` calldata + `MAX_TRANSFERS_PER_TRANSACTION = 256`, the D37 cap), `CLOSE_GROUP_MAJORITY`. Its own header names it "the single version-pin point" and prohibits a downstream evmlib dep (lib.rs:75-92) — honored: no evmlib line exists. =2.3.0 is exactly what ant-core 0.5.0 resolves in Cargo.lock (2.3.1 exists and is deliberately not taken). **Lockstep: moves ONLY inside an ant-core bump review (§4), never alone.** Consumed by antseal-net behind the non-default `ant-backend` feature | storage/payment wire surface; the receipt's `proof_bytes` encoding (tag + rmp) is this crate's format | S6 — landed |
| `alloy` — **pinned `=1.8.3` 2026-08-01 (S6; D33 Decision 4)**: the EVM `Provider` trait + Ethereum tx/receipt types for the external-signer flow `pay()` drives itself — each ≤256-transfer sub-batch tx submitted and its receipt awaited in-band (the D33 block-number capture source). evmlib exposes its concrete provider (`Wallet::to_provider()`) but re-exports no trait, so the trait import is unavoidably direct. =1.8.3 is what evmlib 0.9.0's caret `1.0.32` resolves in Cargo.lock; the declared features are a strict subset of evmlib's activation set, so the line adds zero packages/features to the resolved graph. **Lockstep: moves only with an evmlib move inside an ant-core bump review (§4)** | payment-tx submission + receipt capture (tx hashes/block numbers journaled into the permanent vault record) | S6 (D33) — landed |
| `bytes` — **pinned `=1.12.1` 2026-08-01 (S6)**: `prepare_chunk_payment` consumes and `DataChunk.content` carries `bytes::Bytes`; the adapter must construct the type. Exact-pinned to the version the ant-core graph already locks (zero packages added); moves only within an ant-core bump review (§4). Not format-affecting by itself — pinned for lockstep hygiene with the storage surface it feeds | storage-payload container type of the pinned upstream API | S6 — landed |
| `k256` — **pinned `=0.13.4` 2026-08-02 (U37; decision [D89](decisions/D89-wallet-primitives-below-the-gate.md))**, `default-features = false`, `features = ["arithmetic"]` — **NOT `ecdsa`**. The secp256k1 half of the wallet **light half** (`crates/antseal-net/src/wallet.rs`), which D89 moved into the **default** graph so `init`/consent are compiled and asserted by required CI rather than by a feature no required context builds. It is not a second acceptance implementation: D44 defines the accepted key set as what the pinned evmlib/alloy parse accepts, and that parse bottoms out in exactly `k256::SecretKey::from_slice` (traced in vendored source: `alloy-signer-local-1.8.3/src/private_key.rs:224-230` → `:52-54` → `ecdsa-0.16.9/src/signing.rs:99-103`), on exactly the version `Cargo.lock` already pins. Dropping `ecdsa` costs nothing and keeps `signature 2.2.0`/`hmac 0.12.1` out of the graph beside the project's `signature 3`/`hmac 0.13`; `precomputed-tables` stays off (one slower scalar multiplication per `init`; enabling it would add `once_cell`). **Lockstep: with alloy/evmlib, NOT with the project's crypto stack** — this pin's partner is the payment stack, so it follows whatever k256 the ant-core graph locks and moves only inside an ant-core bump review (§4). Enforced by `dep-graph` **rule 5** (one k256; the `=` pin literal equals it; `alloy-signer-local`'s lock entry stays bare) | wallet-key acceptance predicate (D44) + address derivation — a key accepted here must be a key the payment path accepts | U37 (D89) — landed |
| `sha3` — **pinned `=0.11.0` 2026-08-02 (U37; decision [D89](decisions/D89-wallet-primitives-below-the-gate.md))**, `default-features = false` (drops `alloc` and `oid`). Keccak-256 for EVM address derivation (`keccak256(uncompressed pubkey[1..])`, last 20 bytes) and EIP-55 checksum rendering. **No lockstep with anything** — the `blake3` row's reasoning exactly: Keccak-256 is a fixed function, and the committed known-answer vectors are the determinism authority, not the crate version. Guards: the scalar-1 ⇒ `0x7E5F…Bdf` generator address and the three checksummed contract constants (`network.rs:65,70,80`) in the **default** lane, plus the feature-path assertion that our renderer equals alloy's own `Display` (`evm.rs`). Adds one package to the normal graph and **zero names**: sha3 0.11 sits on the same RustCrypto 0.11 generation the project already pins for `sha2`/`ml-dsa`, so its whole closure is already there | address bytes shown to users and written into the vault; EIP-55 rendering | U37 (D89) — landed |
| `minicbor` (pinned `=2.3.0`, decision D7) | every hashed/signed byte flows through it | P10 (joint with F) — landed |
| `ed25519-dalek` — **pinned `=3.0.0` 2026-07-27 ([D13](decisions/D13-ed25519-dalek-pin.md); C11 probe)**: verify_strict semantics probe-proven identical to 2.2.0 (byte-identical keys/sigs), chosen for the unified signature-3/sha2-0.11/getrandom-0.4 stack shared with `ml-dsa`; ZIP-215 pubkey-parse gap closed by C12's pre-validation layer | signature format + strict-verification semantics | P11 (C sign-off) — landed (declaration-only until C12) |
| `ml-dsa` — **pinned `=0.1.1` 2026-07-27 ([D14](decisions/D14-mldsa-crate.md); C11 probe)**: primary ML-DSA-65; pre-1.0, unaudited; all three 2026 advisories patched in 0.1.1 (only CVE-2026-22705 has a RUSTSEC ID — P13 must watch GHSA/osv.dev, not RUSTSEC alone); wasm32 probe passed with executed native↔wasm bit-match | PQC signature format | P12 — landed (declaration-only until C13) |
| `fips204` — **pinned `=0.4.6` 2026-07-27 ([D14](decisions/D14-mldsa-crate.md))**: fallback impl, dormant since 2024-12 (accepted for a fallback); probe-proven byte-identical keygen + deterministic sign vs `ml-dsa`, so activation needs no re-derivation; normally consumed by no crate | PQC signature fallback | P12 — landed (declaration-only) |
| `opentimestamps` (spec pin `=0.2.0`) | `.ots` wire format. **Scope: wire-format codec only** — the calendar HTTP client is in-house (antseal-anchor); no networking surface of the crate may be used | P18 (A) |
| `blake3` — **pinned `=1.8.5` 2026-08-01 (P15; decision [D35](decisions/D35-self-encryption-dependency-mode.md))**: current stable on crates.io, and the same version ant-core 0.5.0's packaged lock records — matching is tidy, **not** load-bearing: BLAKE3 is a fixed function, and the golden vectors, not the crate version, are the determinism authority, so this pin has **no lockstep semantics** with ant-core bumps. `default-features = false` (drops `std`, the only default feature): the normal graph is pure no_std Rust (arrayref/arrayvec/cfg-if/constant_time_eq — no getrandom, no rand, no I/O, no threads); `rayon` (nondeterministic thread pool), `mmap` (I/O) and `wasm32_simd` deliberately OFF. P15 probe 2026-08-01: wasm32-unknown-unknown build passes on the pinned toolchain, and the official BLAKE3-team spec vectors match on both the x86 asm path and `pure`. Declaration-only until S4 consumes it | storage-address recomputation: S4's `compute_storage_address` and the M3 storage-linkage layer recompute ant-protocol's `compute_address` = BLAKE3-256 of the blob bytes (network consensus) | P15 (D35) — landed (declaration-only until S4) |
| AEAD/HKDF/SHA-2 stack — **HKDF/SHA-2 part nominated 2026-07-27 (C1–C4): `sha2 = "=0.11.0"`, `hkdf = "=0.13.0"`, `hmac = "=0.13.0"`** (current stable verified on crates.io; RUSTSEC clean — sha2's only advisory RUSTSEC-2021-0100 affects 0.9.7 only, hkdf/hmac have none; `hmac` is hkdf's HMAC layer, also the tests' RFC 5869 reference). **XChaCha20-Poly1305 part nominated 2026-07-27 (C9): `chacha20poly1305 = "=0.11.0"`** (current stable, same RustCrypto generation as the sha2 0.11/hkdf 0.13 pins; RUSTSEC — no advisories on record). Every permanent unit/manifest ciphertext byte comes out of it. Features `alloc` + `zeroize` only; **default features OFF so `getrandom` never enters antseal-core** (injected-RNG-only policy, C5/C9; wasm recipe is P14's). Underlying `aead`/`chacha20`/`poly1305`/`cipher` versions frozen by Cargo.lock (§3) | ciphertext format + key derivation | C |
| Unicode/NFC data crate — **nominated 2026-07-27 (G1): `unicode-normalization = "=0.1.25"`, shipping Unicode data 17.0.0 behind the frozen descriptor string `unicode-17.0.0`** ([D25](decisions/D25-unicode-normalization.md)); the data version is frozen into manifests, and every shipped table is retained forever | canonicalization output bytes | G |
| Argon2/scrypt (vault KDF) — **pinned 2026-08-01 (U6; decision [D40](decisions/D40-vault-kdf-selection.md)): `argon2 = "=0.6.0-rc.8"` (default-features off — no `alloc`, we allocate the arena fallibly ourselves per D40 §2; no `getrandom`/`password-hash` — parameters live in the AAD-bound vault header, never PHC strings; `zeroize` ON), `blake2 = "=0.11.0-rc.6"` (argon2's hash core, declared directly SOLELY to force its `zeroize` feature — argon2's own `zeroize` does not forward it, and blake2's wiping `Drop` on the BLAKE2b chaining state is gated on blake2's own feature: without this line every Argon2id H0 leaves 65 bytes of passphrase-derived state in dropped hashers, measured; the hmac-declaration precedent), `scrypt = "=0.12.0"` (default-features off; resolves onto the exact `sha2 =0.11.0` pin incl. the D88 zeroize drop-glue — no second digest generation; honest limit recorded: scrypt's internal 1 GiB B/V buffers have no wiping story, password-derived only).** Re-verified current at pin time per D40's clause: argon2 0.6.0 final is NOT out, rc.8 is newest — rc discipline as for ml-dsa (exact pin + RUSTSEC/GHSA watch). RUSTSEC check 2026-08-01: no advisories on record for argon2/blake2/scrypt at these versions. Guards: RFC 9106 §5.3 + RFC 7914 §12 known-answer vectors (`crates/antseal-cli/tests/vault_encryption.rs` — KDF output bytes are vault-format bytes) and the D88-style blake2 residue probe + manifest-declaration check (`crates/antseal-cli/tests/kdf_residue.rs`, red-direction proven 2026-08-01). The blake2 `zeroize` feature is **load-bearing** exactly like sha2's (treat removal as a §4 version bump) | vault format + passphrase-residue hygiene | U6 (D40) — landed |
| `getrandom` — **pinned `=0.4.3` 2026-08-01 (U6)**: the CLI's OS-CSPRNG backend — vault KDF salts and record nonces are drawn from it (antseal-core stays injected-RNG-only by construction, C5; the CLI is the sanctioned production caller). 0.4.3 = the version the locked graph already records (the ed25519-dalek/ml-dsa getrandom-0.4 line — no second generation added to the product graph). RUSTSEC 2026-08-01: no advisories on record for 0.4.x | secret-generation surface (same family as the rand_core row) | U6 — landed |
| `rpassword` — **pinned `=7.5.4` 2026-08-01 (U7; channel decision [D41](decisions/D41-noninteractive-passphrase-channel.md))**: the no-echo terminal prompt — the rawest secret-path input surface in the product (the passphrase transits its buffers before any type of ours can wrap it), exact-pinned on the `zeroize`-row precedent though it affects no format byte. Mechanism argued at U7: no-echo needs termios, which std does not expose; the alternatives were this small vetted crate (+`rtoolbox`; libc already in the graph via getrandom, rtoolbox's serde/serde_json resolve onto the existing exact pins) or first-party libc `unsafe` under the workspace deny. Reviewed at pin: SafeString line-buffer wiping, termios restored on drop (panic included), prompt writes to `/dev/tty` never stdout; the returned String is moved straight into C5's `SecretBuf`. Machine mode never reaches it (D51). RUSTSEC 2026-08-01: no advisories on record | secret-path input surface | U7 (D41) — landed |
| `ureq` — **pinned `=3.3.0` 2026-08-02 (P29; decision [D90](decisions/D90-anchor-http-substrate.md))**, `default-features = false`, `features = ["rustls"]`. The anchor HTTP substrate's client (`crates/antseal-anchor/src/http.rs`) — OTS calendars, RFC 3161 TSA POSTs, esplora, Arbitrum RPC. Declared by `antseal-anchor` **alone** and **ungated**: required CI passes no `--features` (`ci.yml:122`, `:148`), so a gated network half would leave every Accept row of A3/A10/A13/A16/A17 — all of them local-stub unit tests — compiled by nothing, which is D89's coverage cliff one milestone later. Exact-pinned on the **`rpassword` row's precedent**, not the format one: no byte it produces is hashed, signed, stored or paid for as an output format (the DER `TimeStampReq` is built in antseal-core, `.ots` and token bytes are opaque payloads), but it is the sole path by which adversary-controlled bytes enter the process before any parser of ours sees them, and **three of its behaviours are load-bearing contracts it does not publish** — `.limit(N)` accepts N−1 bytes, `max_redirects(0)` *returns* the 3xx instead of erroring, and `Config::default()` reads `HTTP_PROXY`/`ALL_PROXY` from the environment. All three are emergent from its implementation, all three are pinned by named tests in `antseal-anchor`, and a minor bump could move any of them silently. **No lockstep with anything.** Bump procedure (§4) additionally **MUST state which `webpki-roots` the bump moves to**: that Mozilla root snapshot is a TLS trust input that arrives *transitively* (never declared by us) and is frozen only by `Cargo.lock` §3, so a `cargo update` can move it with no lane commenting. Measured 2026-08-02: +15 names on the default graph (129 → 144), 25-package closure, four names new to the lock (`ureq`, `ureq-proto`, `utf8-zero`, `webpki-roots`); every other closure member resolves to the version the lock already carried — including the project's own `subtle 2.6.1` and `zeroize 1.9.0` pins — and it brings no `digest`/`sha2`, so no second RustCrypto generation enters (rustls hashes through `ring`). `default-features = false` drops `gzip`, and with it the decompression-bomb path under a streaming byte ceiling. RUSTSEC + GHSA/osv.dev 2026-08-02: zero advisories on record for `ureq`, `ureq-proto`, `utf8-zero`, `webpki-roots`; `rustls 0.23.43`, `ring 0.17.14`, `rustls-webpki 0.103.13` are each past every advisory on record. Licence MIT OR Apache-2.0; `rust-version 1.85` ≤ the 1.92.0 pin | **not** format-affecting — the rawest adversary-facing input surface in the product, plus three undocumented behavioural contracts the substrate is built on | P29 (D90) — landed |
| `zeroize` — **pinned `=1.9.0` 2026-07-27 (C5)** (current stable on crates.io; RUSTSEC — no advisories on record). Wiping semantics for `W`, unit/manifest keys, salts, seeds, and passphrase buffers (`MasterSecret`/`SecretBuf`/material newtypes; C5/C21). Features: `alloc` only (Vec-backed `SecretBuf`); the `derive` feature is deliberately NOT enabled — impls are manual, keeping syn/proc-macro out of antseal-core's graph | secret-hygiene behavior | C (C5) |
| `der` — **pinned `=0.8.1` 2026-08-02 (A5; decision [D60](decisions/D60-der-cms-x509-pins.md))**: the DER reader every RFC 3161 artifact passes through. Strictness is the product requirement, not a preference — A5's Accept demands BER constructs be rejected with a distinct error class, and D60 §7.4 records which rejections this crate gives for free and which antseal adds. Two of its behaviours are load-bearing and unpublished: `ErrorKind` is `#[non_exhaustive]` (so no match over it can be exhaustive — D60 §7.2's claim to the contrary is corrected there), and `resume_nested` does not restore the position, so unread inner bytes are re-offered to the outer decoder and top-level `finish()` still demands exact consumption — a lane's "trailing content is not rejected" finding was falsified by that. **Lockstep: with `x509-cert`/`cms`/`const-oid`/`spki`, which share this generation.** | strict-DER decode is the anchor stage's parse-rejection semantics | A5 (D60) — landed |
| `const-oid` — **pinned `=0.10.2` 2026-08-02 (A5/A8; decision [D60](decisions/D60-der-cms-x509-pins.md))**, feature `db`. Object-identifier constants for every algorithm, attribute and extension the token verifier names. The `db` feature is **ours, not inherited** — D60 found the nominee list incomplete without it. An OID mismatch is a silent accept-or-reject of the wrong algorithm, which is why the identifiers are pinned rather than typed out locally. **Lockstep with the `der` generation.** | algorithm/attribute identity in a verdict-bearing path | A5/A8 (D60) — landed |
| `x509-cert` — **pinned `=0.3.0` 2026-08-02 (A5/A9; decision [D60](decisions/D60-der-cms-x509-pins.md))**: certificate *parsing* only — it has no path validation, which A9 writes by hand against the pinned root store (spec line 108 budgets exactly that). **Lockstep with the `der` generation**; D60 measured that `cms 0.2.3` would fork it, giving **two non-interconvertible `Certificate` types in the crate that decides which certificate signed a timestamp**. | certificate structure in a verdict-bearing path | A5/A9 (D60) — landed |
| `cms` — **pinned `=0.3.0-pre.2` 2026-08-02 (A8; decision [D60](decisions/D60-der-cms-x509-pins.md))**: RFC 5652 `SignedData` parsing. **PRE-RELEASE, deliberately** — the stable `0.2.3` forks the DER stack (above), which is worse than a pre-release on a crate whose parse output antseal re-checks in full. Every semantic check (signed attributes, `messageImprint`, nonce, ESSCertID, critical EKU, signature verification) is antseal's own; this crate supplies structure only. **P23 owns the stabilisation watch** and must re-verify at each rc. **Lockstep with the `der` generation.** | CMS structure under the anchor verdict | A8 (D60) — landed |
| `p384` — **pinned `=0.14.0` 2026-08-02 (A8/A9; decision [D60](decisions/D60-der-cms-x509-pins.md))**: ECDSA P-384 verification for TSA signatures. Normative per spec line 108 (FreeTSA's 2026 cert), and **the digest is SHA-512, not the SHA-384 the pairing suggests** — FreeTSA signs `ecdsa-with-SHA512`, measured. **P-256 is out of v1**: of nine live TSAs captured, exactly one uses ECDSA and it is P-384; zero serve P-256. | TSA signature verification — decides whether a timestamp is genuine | A8/A9 (D60) — landed |
| `rsa` — **pinned `=0.10.0-rc.18` 2026-08-02 (A8/A9; decision [D60](decisions/D60-der-cms-x509-pins.md))**: RSA PKCS#1 v1.5 verification, including the **bare `rsaEncryption`** signature AlgorithmIdentifier that 5 of 9 live TSAs emit, DigiCert included. **PRE-RELEASE by necessity, not preference**: `rsa 0.9.10` is *structurally impossible* here — it pulls `rand`/`rand_chacha` into `antseal-core`'s normal graph via `num-bigint-dig`, which the `dep-graph` lane's own rule fails red on, plus 8 duplicate pairs including a second `signature`, `digest`, `der`. Carries the one mandatory `deny.toml` ignore, **RUSTSEC-2023-0071** (Marvin timing side channel on the **private**-key path): antseal-core holds no RSA private key and performs no RSA private-key operation — the only API it calls is `pkcs1v15::VerifyingKey::verify` over a TSA's public key — so there is no secret in the computation for the channel to leak. The advisory's range is `introduced: 0.0.0-0` with no fixed version, so **no `rsa` release escapes it**; this is not waiting on an upgrade. **P23 owns the stabilisation watch.** | TSA signature verification — decides whether a timestamp is genuine | A8/A9 (D60) — landed |
| `sha1` — **pinned `=0.11.0` 2026-08-02 (A8; decision [D60](decisions/D60-der-cms-x509-pins.md))**: **required, and forbidden as a signature digest.** ESSCertID **v1**'s `certHash` is SHA-1 *by definition* (RFC 5035), and FreeTSA emits v1 — verified identical across two independent captures — so binding the signer certificate is impossible without it. It is used **only** for that certificate-identity binding, never to validate a signature: a SHA-1 signature digest is refused with its own code (Apple's real token is refused on exactly this ground). Absent from D60's original nominee list; the gap was found by dissecting a real token, not by reading a spec. | certificate-identity binding only — never signature validation | A8 (D60) — landed |
| `subtle` — **pinned `=2.6.1` 2026-07-27 (C6)** (current stable; 2.6.0 yanked; RUSTSEC — no advisories on record). Constant-time equality for every verdict-bearing commitment-digest comparison over adversarial bundles (MVP-SPEC.md line 121/168 checks); comparison semantics are consensus-relevant. `default-features = false` (drops `std`/`i128`; wasm-lean) | verdict-bearing comparison semantics | C (C6) |
| `rand_core` — **pinned `=0.10.1` 2026-07-27 (C5)** (current stable; RUSTSEC-2019-0035 and RUSTSEC-2021-0023 affect only <0.4.2 / 0.6.0–0.6.1). The injected-CSPRNG **trait contract** of every generation/nonce path (`MasterSecret`/`SealId` generation, C9 nonce drawing): trait-surface changes alter the public API and test determinism, hence exact-pinned. 0.10 is a pure trait crate — zero deps, zero features — so it structurally cannot pull `getrandom` into antseal-core (0.10 renamed 0.6's `CryptoRngCore` to `CryptoRng`/`TryCryptoRng`; we bound on `TryCryptoRng` and map failures to `CryptoError::RngFailure`) | injected-RNG API contract | C (C5/C9) |
| `serde` + `serde_json` (pinned `=1.0.229` / `=1.0.151` at R1) | the serialized `VerificationReport` is the R9/Q4/Q5 native↔WASM bit-match vector byte format, retained forever — serializer output drift is a silent vector break ([D29](decisions/D29-report-byte-format.md)) | R1 |
| `wasm-bindgen` — **pinned `=0.2.126` 2026-08-12 (R22; decision [D18](decisions/D18-wasm-bindgen-surface-location.md))**: the verifier page's JS boundary, declared by `antseal-wasm` alone and only under a wasm32 target table, with default features off and `std` on (equal to the crate's own default set, and immune to a future default-set change). **Not a free choice**: this is the version the committed `Cargo.lock` already resolves through the ant-core subtree (chrono, getrandom, js-sys, reqwest, uuid, wasm-bindgen-futures, wasm-streams, wasmtimer, web-sys, web-time), so the pin is **coupled to the upstream payment stack** — an ant-core bump that raises the floor above it fails the resolve rather than silently duplicating, and **S20's bump procedure must name `wasm-bindgen` as a coupled pin** (the alloy/evmlib lockstep shape). Two mechanical properties ride on the literal: §5 requires the installed `wasm-bindgen-cli` to equal it (glue generated by a mismatched CLI is a silent breakage), and `scripts/wasm-toolchain-audit.sh`'s extractor is a **line grep**, so the declaration must stay a SINGLE LINE. `serde-serialize` is a **decided prohibition** (D18 §5 R5): the module hands JS the bytes `to_canonical_json()` produced, never a structured value, so one serialization path serves the CLI and the page alike | **not** format-affecting by itself — it is the codegen that produces the shipped `.wasm` whose SHA-256 the page publishes about itself (D63 §5 R2), so a version move changes the artifact bytes and the digest the footer displays | R22 (D18) — landed |

**Note on the AEAD/HKDF/SHA-2 stack row.** `sha2`'s **`zeroize` feature is
load-bearing** (D88): dropping it silently restores recoverable `W` and
GGM-seed residue in dropped hashers. Treat feature removal as a version bump
under §4, and note that the compile-time `ZeroizeOnDrop` assertions in
`crypto.rs::zeroization_sweep` do **not** catch it — the wipe is drop glue,
not a trait bound.

Three separate guards exist instead (C24), and none is redundant:

| guard | file | catches |
| --- | --- | --- |
| compile-time | `crates/antseal-core/tests/digest_zeroize_link.rs` | `digest/zeroize` off ⇒ `sha2::digest::zeroize` does not resolve ⇒ build fails. Proves `BlockBuffer`'s wiping `Drop` exists — the buffer holding `W` and the GGM parent seed. **Blind to** `sha2`'s own feature: `hmac/zeroize` forwards `digest/zeroize` too. |
| declaration | `crates/antseal-core/tests/feature_pins.rs` | the pin line itself losing `features = ["zeroize"]` — exactly the case above is blind to, i.e. `Sha256VarCore`'s chaining-state `Drop` silently vanishing. |
| behaviour | `crates/antseal-core/tests/zeroization_residue.rs` | bytes actually surviving a drop. The only layer that would outlive an upstream change of mechanism. |

The stack's other feature selections are ordinary consumption shape; this one
is a security property whose failure mode is silent, which is why it is
called out here rather than left in the row.

**`self_encryption` is prohibited, not pinned (P15, decision
[D35](decisions/D35-self-encryption-dependency-mode.md)).** Until 2026-08-01
this table carried a `self_encryption` row ("must equal the exact version
ant-core's graph locks"). D35 dissolved the need: under D32's
blob-=-one-chunk model the storage address is BLAKE3-256 of the ciphertext
bytes, so no antseal crate uses `self_encryption` for anything — and three
independent grounds (GPL-3.0 with no linking exception; mandatory
tokio/tempfile/rayon/rand deps; wasm32-hostile) disqualify it from ever
becoming a dependency. The rule is therefore a **prohibition**:
`self_encryption` must never be a *direct* dependency of any antseal crate —
it remains a transitive, never-invoked-by-us dependency inside ant-core's
graph, linked only into net/cli binaries (D6's distribution note stands).
Enforced on every run by `scripts/ci-lanes.sh dep-graph` (declared-manifest
scan plus, once the crate is in the locked graph, a resolved-graph
immediate-parent check). The old move-only-in-lockstep clause is **retired**:
the transitive version simply follows ant-core's lock and is *recorded*,
never pinned by us, at every ant-core bump (§4 checklist; S20's survey).
The `blake3` row above is D35's replacement primitive and deliberately has
no lockstep semantics of its own.

**The devnet era's containment is asserted, not conventional (P20,
2026-08-02).** P16's lockfile event resolved `ant-node` and the whole EVM
stack into `Cargo.lock`, and a lock entry is not a compile — locks cover
every member feature. `scripts/ci-lanes.sh dep-graph` therefore carries
**one containment story in four rules**, all in that single lane so a
reviewer sees them together:

1. **The default `--workspace` graph reaches none of `ant-node`,
   `ant-core`, `ant-protocol`, `evmlib`, `alloy`.** Every edge to them is
   behind `devnet-launcher/devnet` or `antseal-net/ant-backend`, both
   non-default by decision (D33, D35, D52). Measured at P20: 120 packages
   by default, 475 with `devnet-launcher/devnet` — a single non-optional
   edge added in review would move ~355 packages into every contributor's
   build and every CI lane, and nothing else would notice.
   **Amended 2026-08-02 (D89): the default figure is now 129**; 475 with
   `devnet-launcher/devnet` and 447 with `antseal-net/ant-backend`, both
   **unchanged**. The nine are `base16ct`, `const-oid`, `crypto-bigint`,
   `der`, `elliptic-curve`, `ff`, `group`, `k256`, `sec1` — the enumerated,
   already-locked closure of the `k256`/`sha3` rows above, spent on a
   measured *coverage* property (D89 Evidence 3: without them, four of
   U11's six Accept rows would be compiled by no gate that runs). Note what
   the rule actually asserts and what it does not: **the verdict is a scan
   for those five names**, and the package count is computed *after* it and
   printed as evidence, so this amendment changes a recorded number and no
   assertion. The 355-package cliff the rule exists to guard is untouched.
   This record also sets the bar for the next request: nine packages bought
   an argued, measured, enumerated coverage property, and that does not
   license a tenth without the same three things.
   **Amended again 2026-08-02 (D90, P29): the default figure is now 144**;
   **479** with `devnet-launcher/devnet` and **451** with
   `antseal-net/ant-backend`. The fifteen are the `ureq` row's enumerated
   closure — the anchor HTTP client, taken *ungated* because required CI is
   default-features-only, so a gated network half would leave every Accept
   row of A3/A10/A13/A16/A17 (all local-stub unit tests) compiled by
   nothing. Same note as D89's: the **verdict is still the five-name scan**,
   which none of ureq's 25 closure packages matches, so this amendment moves
   a printed number and no assertion, and the 355-package cliff is still
   untouched. Same bar, too: fifteen packages bought a *functional*
   capability (without them the product cannot anchor, cannot poll upgrades
   and cannot verify online) plus the coverage property, with the closure
   enumerated and every version shown to be one the lock already carried.
   It licenses no sixteenth without the same measurement.
2. **`self_encryption` is a direct dependency of nothing of ours** — the
   prohibition above, declared-manifest scan plus resolved-parent check,
   both halves now with their own planted-fake self-test.
3. **`alloy` moves only with the `evmlib` that ant-core's graph locks.**
   D44 defines the accepted wallet/payment set as "what the pinned
   evmlib/alloy parse accepts", and `antseal-net` holds a direct `alloy`
   edge (evmlib re-exports no `Provider` trait), so two independent things
   name `alloy` and independent drift would silently fork that set.
   `Cargo.lock` already encodes the property: a dependency entry is
   version-**qualified** (`"alloy 1.7.0"`) if and only if the package
   resolves to more than one version, so `evmlib` listing a bare `"alloy"`
   is the lock's own statement that there is one alloy and both of us are
   on it. The lane checks that, the whole `alloy-*` family being
   single-versioned, and that the recorded `=` pin literal equals what is
   resolved.

4. **Only `antseal-net` and `devnet-launcher` may *declare* `ant-core`,
   `ant-protocol`, `alloy` or `bytes`** (S23, completing S2's accept row).
   `antseal-net` is the churn-isolation boundary MVP-SPEC.md lines 60–69
   describe, and S20's bump procedure relies on an ant-core move being
   bounded to it. The check reads `cargo metadata --no-deps`, so it sees
   normal, dev, build, target-gated, optional and **renamed** edges alike —
   the level S2 is phrased at, and one the lane's source-token check
   structurally cannot reach: a consumer writing a fully qualified
   `::ant_core::Client`, or aliasing the crate, spells `ant_core::`
   nowhere. Proven red by both a `bytes.workspace = true` edge (the house
   declaration style, which a name-based grep of the manifest would miss)
   and a `upstream = { package = "bytes" }` renamed edge, which no
   name-based grep could find at all.
5. **`k256` is single-versioned, exact-pinned, and it is the one
   `alloy-signer-local` resolves** (added 2026-08-02, D89 Decision 4 —
   rule 3's mechanism, applied to the second thing that now names a curve
   implementation). D89 put the wallet light half in the default graph on
   the argument that D44's acceptance predicate *is*
   `k256::SecretKey::from_slice`; that argument survives only while one
   k256 exists. A fork would silently split the accepted wallet-key set
   with nothing failing — so the lane reads the same lock encoding rule 3
   does (a bare dependency entry ⇔ one resolved version), plus the `=` pin
   literal, and its self-test asserts the detector in **both** directions.
   Failure mode by design: a red lane during an ant-core bump review, which
   is the moment it should be noticed. (S20's bump procedure gains the
   matching line: when a bump moves `alloy`/`evmlib`, check whether it
   moves `k256`, and move our pin with it — never alone.)


Each rule runs its detector against a planted violation **before** the
verdict, the pattern the `secret-guard` lane established; rule 1's
self-test uses the real graph with the feature flipped on rather than a
planted string, and rule 4's plants both a forbidden edge and an allowed
one, so the extractor is pinned in both directions — as does rule 5's,
which asserts its split detector matches a planted version-qualified entry
**and** does not match the bare entry that is the green case. Rules 2 and 4 also
carry an anti-vacuity assertion — a scan that silently stops matching is
green for the worst possible reason.

**This list grows — it is a floor, not a ceiling.** G nominates the
Unicode/NFC crate (with its exact Unicode data version) at M0, and C
nominates the concrete AEAD/HKDF/SHA-2 crates at M0. Any new dependency
whose output bytes end up hashed, signed, stored, or paid for joins the
class in the same PR that introduces it.

Dependencies outside the class (e.g. `thiserror`, `clap`, `tracing`) may use
caret requirements, but their *resolved* versions are still frozen by the
committed `Cargo.lock` (§3).

**`tokio` stays outside the class, deliberately — recorded 2026-08-02
(U36).** U36 gave `antseal-cli` an async runtime edge (`optional = true`,
activated only by the non-default `ant-backend` feature) so
`crate::backend` can drive `ant-core`'s reactor-parked futures; that is a
new *product* edge and so is recorded here rather than left in a manifest
comment. It is **not** an exact pin, and the reasoning is the same one the
workspace entry has carried since P16: nothing tokio produces is hashed,
signed, stored or paid for — it schedules, it does not encode — so it fails
§1's own membership test; and the property actually worth protecting is
"one tokio in the tree, the same version the `ant-core`/`ant-node` graph
resolves", which a competing `=x.y.z` requirement on this edge is precisely
what would break. Caret plus the committed lockfile is the stronger
guarantee here, not the weaker one. What the new edge must keep true is a
*containment* claim, not a pin: `dep-graph` rule 1 measures the default
`--workspace` graph, and every tokio edge in the tree (devnet-launcher's
`devnet`, antseal-net's dev-only, antseal-cli's `ant-backend`) is gated
such that the default graph resolves none. A future edge that is *not*
feature-gated is the event that needs review, not a version bump.

## 2. Single declaration point

ALL version requirements live in **`[workspace.dependencies]`** in the root
`Cargo.toml` and nowhere else. Member crates reference dependencies
exclusively via `<dep>.workspace = true` — a member `Cargo.toml` never
carries a version string. The whole pin surface is reviewable in one place,
and an off-policy version cannot hide in a crate manifest.

## 3. Lockfile discipline

`Cargo.lock` is committed. Every CI lane that resolves dependencies runs
with `--locked`, so lockfile drift — or a manifest change without its
lockfile update — fails CI loudly. Local builds behave the same: if cargo
wants to touch the lockfile unprompted, a manifest and the lock are out of
sync; fix the commit rather than letting resolution float.

## 4. Version bumps are deliberate, reviewed events

Upstream cadence is weekly-to-biweekly; ours is not. **No drive-by bumps.**
`cargo update` sweeps, auto-bump bots, and bumping "while in the area" are
all off-policy (the weekly upstream check, P19, produces a *report*, never a
bump). A bump is its own PR containing only the bump and its direct
fallout, with this checklist completed in the PR description:

- [ ] Upstream changelog / release notes / commit delta reviewed; behavior
      and format changes written up
- [ ] RUSTSEC check for the new version (advisory lane must be green; new
      advisories get a written applicability assessment)
- [ ] Golden-vector re-run: every committed vector still verifies
      byte-exact (M0 onward). A vector change is a format event — it is
      justified explicitly, never regenerated silently
- [ ] For `ant-core`: devnet E2E green (local devnet, P16; Sepolia-mode
      where payment surfaces changed, P17), and the `self_encryption`
      version its graph locks re-recorded — recorded, never pinned: no
      antseal crate may depend on it directly (D35 prohibition, P15; the
      old move-only-in-lockstep clause is retired)
- [ ] For `ant-core` bumps that move `alloy`/`evmlib`: **check whether they
      move `k256`, and move our `=` pin with it — never alone** (D89; the
      wallet light half's acceptance predicate is that k256's
      `SecretKey::from_slice`, so a fork splits the accepted wallet-key
      set). `dep-graph` rule 5 makes forgetting this a red lane rather
      than a silent fork, which is the point: it fires inside the bump
      review, where the decision belongs
- [ ] For toolchain bumps: [toolchain.md](toolchain.md) procedure —
      `rust-toolchain.toml`, `rust-version`, `clippy.toml` move together in
      one commit

## 5. Toolchain and dev-tools under the same rules

- The Rust toolchain is pinned exactly in `rust-toolchain.toml`
  ([toolchain.md](toolchain.md)); MSRV = the pin; bumps follow §4.
- Dev-tools whose output or verdict the project depends on are exact-pinned
  wherever they are installed (CI workflows, scripts, docs):
  **wasm-pack**, **wasm-bindgen-cli** (must equal the `wasm-bindgen` crate
  pin — a mismatch breaks the build. **[D18, 2026-08-12]** The deliberate
  no-pin state ends with R22: the crate pin is **`=0.2.126`**, which is the
  version the committed `Cargo.lock` already resolves through the ant-core
  subtree, so it is **coupled to the upstream stack** — an ant-core bump that
  raises the floor above it fails the resolve, and **S20's bump procedure must
  name `wasm-bindgen` as a coupled pin** (the alloy↔evmlib lockstep shape).
  The crate pin must be a **single-line** `[workspace.dependencies]` entry
  containing `"=0.2.126"`, because `scripts/wasm-toolchain-audit.sh`'s
  extractor is a line grep; and the crate pin and the CLI install line must
  land in the **same commit**, because the audit is green only while both are
  absent. **[2026-08-12, maintainer]** Both tools are now installed on this
  machine at exact versions — `wasm-bindgen-cli` **`=0.2.126`** (not the newer
  0.2.127: the CLI equals the crate pin, and the lock carries 0.2.126) and
  **`wasm-pack 0.15.0`**, each `cargo install … --locked` — so this section's
  *"exact-pinned wherever they are installed"* rule is **satisfied here**;
  what remains is the committed half, which lands with R22. The equality rule
  is enforced from the moment either pin appears by
  `scripts/wasm-toolchain-audit.sh`, CI lane `wasm32-core-tests`; rationale in
  [wasm-toolchain.md](wasm-toolchain.md) §4), **cargo-deny `=0.19.8`** (its verdict
  gates merges; pinned at P13 per [D19](decisions/D19-advisory-lane.md) —
  installed with `cargo install cargo-deny --version 0.19.8 --locked` in
  both the per-PR `audit-deny` job and the weekly `advisory-cron`
  workflow, and the same version is what "run cargo-deny locally" means),
  **Python `cbor2` `==6.1.3`** (the D12 independent CBOR cross-check the
  M0 golden-vector freeze gate depends on — never enters any Rust
  dependency tree; the `the_cbor2_pin_is_exact_and_dev_tool_only` test
  refuses to let its name appear in a manifest). F14 landed the pin as
  `requirements-crosscheck.txt` (pip `--require-hashes`, D31): a SHA-256 per
  artifact PyPI publishes for 6.1.3, from which — on a machine with no pip —
  `scripts/cross-check.sh --setup` fetches and verifies a wheel into a cache
  **outside the repo**
  (`${XDG_CACHE_HOME:-~/.cache}/antseal/cbor2-6.1.3`). Two facts that
  shaped that: cbor2 6.x is a compiled **Rust/PyO3** extension with no
  pure-Python fallback (so a source install would want a Rust toolchain and
  dev headers), and a wheel is a zip — so the setup step needs no `pip`,
  no `ensurepip` and no root, **cargo-fuzz `=0.13.2`** (its verdict
  gates merges via the `fuzz-smoke` lane; pinned at Q9 — installed with
  `cargo install cargo-fuzz --version 0.13.2 --locked` in both the per-PR
  `fuzz-smoke` job and the scheduled `fuzz-nightly` workflow, and
  `scripts/fuzz.sh` **refuses to run** on any other version rather than
  silently producing a verdict from an unreviewed tool).
  The M3 reproducible wasm build makes the
  wasm-pack/wasm-bindgen versions format-provenance-relevant, exactly like
  the toolchain itself.
- **A second, dated toolchain pin exists for fuzzing only**:
  `fuzz/rust-toolchain.toml` (`nightly-2026-01-26` at Q9). cargo-fuzz needs
  nightly for `-Z sanitizer` and libFuzzer instrumentation, and the
  workspace pin — which is the MSRV — must not move for that. rustup
  resolves toolchain files from the invocation directory upward and
  `scripts/fuzz.sh` runs cargo from `fuzz/`, so the nightly governs fuzzing
  and nothing else (`fuzz/` is not an ancestor of `crates/`). It is a
  **date**, not a floating `nightly`, for the reason this whole section
  exists: a floating channel would make "the fuzzer found nothing" a
  statement about whatever compiler CI downloaded that morning. Bumps
  follow §4.

## Enforcement & cross-references

- CI (P8): `--locked` in every resolving lane; the `core-dep-graph` lane
  guards antseal-core's dependency purity.
- CI (P14): the `wasm32-core-tests` lane runs
  `scripts/wasm-toolchain-audit.sh`, which enforces the getrandom recipe on
  every wasm32 build graph and the wasm-bindgen crate↔CLI pin equality of §5
  ([wasm-toolchain.md](wasm-toolchain.md)).
- cargo-deny advisory lane, per-PR + weekly schedule (P13, M0).
- CI (Q9): the `fuzz-smoke` lane installs cargo-fuzz at the §5 pin and the
  fuzzing nightly from `fuzz/rust-toolchain.toml`; neither version literal
  is hardcoded in a workflow. `fuzz/Cargo.lock` is committed and separate
  from the workspace lockfile — the fuzz crate carries an empty
  `[workspace]` table, so `libfuzzer-sys`/`arbitrary`/`cc` structurally
  cannot reach the audited graph (`docs/testing/fuzzing.md`).
- Weekly upstream-bump check: report-only, human-reviewed PR required for
  any pin change (P19).
- PR process: [../CONTRIBUTING.md](../CONTRIBUTING.md) — its checklist
  routes every version-touching PR through §4.
- [toolchain.md](toolchain.md) — the toolchain pin governed by §5.
