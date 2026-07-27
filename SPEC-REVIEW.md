# MVP-SPEC.md — Multi-Agent Review (2026-07-27)

> **Status**: all fixes below were applied in the Revision-2 rewrite of `MVP-SPEC.md` (same date).
> Line references throughout this review refer to the *reviewed* original, preserved as
> `MVP-SPEC.orig.md`.

**Method**: six parallel specialist reviewers (cryptographic design, threat model/privacy, external
fact-checking against live sources, Rust/ecosystem feasibility, product/UX, internal consistency)
produced 61 findings; after dedup, the load-bearing/contested claims went through a second adversarial
verification pass (7 verifiers instructed to *refute* each claim, checking the spec text, upstream
source code, and live registries/docs). Everything below marked **[verified]** survived that pass;
one finding was refuted and is listed under "Considered and rejected". External facts were checked
against crates.io, docs.rs, the WithAutonomi/ant-client source, docs.autonomi.com, and the services
themselves on 2026-07-27.

**Verdict**: The spec's factual foundation is unusually solid — nearly every claim about the outside
world checks out (see "What checked out" at the end). The architecture is buildable roughly as drawn.
But the manifest definition (line 69) was evidently written after the promises and flows and never
reconciled against them: as written the spec contains **one construction that cannot be implemented at
all, two defects that falsify its central privacy promise, a forgeable offline verifier, a missing
product core (restore), and a false headline promise for binary files**. All of the critical items are
**format-affecting and must be resolved before M0 freezes the manifest/bundle formats and golden
vectors** — after the first real mainnet seal they become permanent.

---

## Critical — the spec is wrong as written

### C1. `work_id`/AAD circular dependency — `seal` is unimplementable [verified]
`MVP-SPEC.md:64` sets AAD = `work_id‖unit_id`; `MVP-SPEC.md:69` defines `work_id = SHA-256(manifest
body)` and puts each unit's **ciphertext network address** inside the manifest's unit table. Autonomi
addresses are content-derived (chunk address = hash of chunk content — confirmed against
docs.autonomi.com and the self_encryption crate). So: ciphertext ← AAD ← work_id ← manifest body ←
ciphertext address ← ciphertext — a dependency cycle. The verification pass attacked five escape
readings (body excludes the unit table; addresses knowable in advance; AAD not bound into stored
bytes; a two-pass ordering; placeholder fields) and all fail against the spec text. Producing a valid
seal would require a SHA-256 fixed point; the spec'd verifier (line 80), which reconstructs the AAD
from the manifest, could never accept one. The cycle runs *only* through the address field — nonce,
`unit_commit`, and byte-range are all computable pre-encryption.

**Fix**: make the AAD independent of the finished manifest. Either AAD = `seal_id ‖ LE64(unit_id)`
where `seal_id` is a random 16–32 B value generated at seal start and recorded in the manifest body,
or AAD = `unit_commit ‖ LE64(unit_id)` (computable pre-upload). Transplant resistance is preserved;
manifest→ciphertext binding already exists via the address and `unit_commit` fields. Update line 80's
verifier steps to match.

### C2. Manifest uploaded in plaintext — title, file paths, sizes, pubkeys published forever
`MVP-SPEC.md:32` encrypts only units ("encrypt units → upload ciphertexts + manifest");
`MVP-SPEC.md:69` says "Manifest itself is uploaded to Autonomi" with no encryption step anywhere. The
manifest contains title, per-file paths, sizes, unit byte-ranges, claimed time, and signing pubkeys —
readable CBOR for any node operator or crawler, on a permanent network where nothing can ever be
deleted. This directly falsifies "Nothing readable ever leaves the machine" (line 32) and
"private-until-revealed" (line 10) for exactly the target users (`patentable-widget-v3.docx` as a
plaintext path is itself a disclosure; the pubkeys also link all of one author's works). Three of six
reviewers found this independently.

**Fix**: encrypt the uploaded manifest copy: `k_m = HKDF(W, "manifest-key")`, random nonce, same AEAD.
Bundles already embed the plaintext manifest bytes (line 80), so verification is unchanged; anchors
continue to bind SHA-256 of the *plaintext* manifest bytes — state explicitly that "bytes anchored" ≠
"bytes stored". Consider also padding/packing per-unit ciphertexts (the per-paragraph size profile
alone can fingerprint a known document), and a seal-time notice that title/paths are visible to
*bundle recipients*.

### C3. Unsalted per-file "raw hash" re-enables the confirmation attack the design exists to prevent [verified]
`MVP-SPEC.md:58` ("Each file commits its raw bytes always") + `MVP-SPEC.md:69` put a plain, unsalted
SHA-256 of each complete file into the manifest — while line 66 says "Salting is mandatory — short
units are guessable" and line 59 makes the *default unit a whole file*, i.e. the spec itself concedes
whole files are guessable. Two leak channels: (a) the publicly uploaded manifest (C2), and (b) **every
`.sealproof` bundle**, which embeds full manifest bytes — so a counterparty receiving a partial reveal
gets the paths, sizes, and unsalted raw hashes of **all unrevealed files** and can confirm any
candidate document (leaked draft, known prior art) by hashing it. It also links identical files across
works. This breaks the hiding property of selective disclosure even after C2 is fixed, because bundles
must carry the manifest. The verification pass found no escape reading: the raw hash is definitionally
unsalted (the spec's naming convention reserves "commit" for salted constructs), and it cannot be
redacted from bundles without breaking anchor/work_id verification.

**Fix**: replace with a salted commitment: `raw_commit = SHA-256(file_salt ‖ raw_bytes)`,
`file_salt = HKDF(W, "file-salt"‖file_id)` (16 B), disclosed only when that file is revealed. Decide
explicitly what bundle recipients may learn about unrevealed files (consider aliasing paths in the
redaction view). Extend the line 111 adversarial doc-test to the file level.

### C4. Offline verification has no trust roots — wholesale-forged bundles verify green
Bundles embed "all anchor artifacts" including TSA cert chains (`MVP-SPEC.md:74,80`), and the page
promises "full cryptographic verification locally" (line 84) with an offline "earliest provable time
per anchor" (line 35). But an RFC 3161 token proves nothing against a chain *supplied in the same
attacker-authored bundle* — no TSA trust store is defined anywhere — and an OTS attestation stores
only a Bitcoin block *height*: without a header source, "block time" is unknowable offline, and the
bundle contents list (line 80) omits the header. Concrete failure: a forger mints their own "TSA",
fabricates an OTS attestation naming a 2019 block, and the drag-and-drop verifier renders "proven:
2019". The tamper matrix (line 107) only tests tokens "for a different hash" — a well-formed token
from an untrusted root passes every listed check. (Ecosystem reality, verified: no turnkey pure-Rust
CMS/X.509-path validation exists — RustCrypto `cms` parses but does not verify SignedData, `x509-cert`
has no chain validation — so this is also 2–4 weeks of hidden M2 effort, and per M6 below it must run
in WASM.)

**Fix**: (a) compile a versioned pinned trust store of the default TSAs' roots into seal-core (bundle
chains supply intermediates only); (b) embed the attested Bitcoin block height **and 80-byte header**
in bundles, verified against a compiled-in checkpoint chain — or explicitly downgrade the offline OTS
verdict to "commitment chain valid — time unconfirmed until online check"; (c) verdicts must
distinguish "verified against pinned roots" from "internally consistent only"; (d) chain validity is
evaluated at the token's genTime, never wall-clock (see M12); (e) extend the tamper matrix: valid
token from untrusted root, fabricated Bitcoin attestation, expired/substituted chains.

### C5. The "permanent vault" has no door — no command restores the author's own work
The one-liner sells a permanent encrypted vault (`MVP-SPEC.md:22,10`), but the CLI surface
(`MVP-SPEC.md:92`) has no command that fetches ciphertext from Autonomi and decrypts it back to files.
`reveal` builds third-party proof bundles; `verify` renders a verdict. Concrete failure: laptop dies,
user `vault import`s their backup on a new machine — no specced sequence returns `thesis/` to disk.
The spec also never says where `reveal` gets ciphertext (local cache vs network), so even
`reveal --all` is undefined after disk loss.

**Fix**: add `antseal restore <work-id> [-o dir]` (fetch via `StorageBackend`, decrypt with
vault-derived keys, verify against manifest, write files); spec that `reveal` fetches from the network
when no local copy exists; add a disk-loss recovery E2E (clean machine + vault backup only) to the M4
gate.

### C6. "Every seal is forever byte-range-revealable" is false for binary files
`MVP-SPEC.md:16` ("every seal is forever byte-range-revealable"), line 22 ("reveal all of it — or any
part of it"), and line 102 ("no seal is ever locked out") vs line 59 ("Binary files are always
single-unit and get no fine tree") and line 67 ("text only"). A thesis sealed as a **PDF** — the most
common legal/creative artifact — is permanently whole-file-reveal-only, and since commitments freeze
at seal time this can never be upgraded for existing seals. Also undefined: what the unit table's
"canonical byte-range" holds for binary units (binaries have no canonical rendition, line 58).

**Fix**: either commit a fine tree over raw bytes for binary files too (cheap once M1's GGM fix
lands), or scope the promise honestly in all three places + product copy ("byte-range-revealable for
text files; binary files reveal whole-file") and have `seal` warn per binary file.

---

## Major — should change before implementation starts

### M1. Fine tree: freeze a range-friendly salt derivation now, or the flagship feature is crippled forever [verified, sharpened]
The per-byte tree (`MVP-SPEC.md:67`) with flat per-index salts `salt_i = HMAC(seed, LE64(i))[..16]`
locks in, permanently (lines 16/56/102), the following verified arithmetic:
- **Seal cost**: ~7 SHA-256 compressions per byte (~5 with HMAC midstate caching). 1 MB ≈ sub-second —
  fine; 100 MB ≈ 7×10⁸ compressions ≈ tens of seconds on SHA-NI CPUs, **3–6 minutes measured on an
  older non-SHA-NI CPU**, repaid on every "recompute on demand"; a materialized leaf level is 32 B per
  input byte (3.2 GB at 100 MB).
- **Reveal cost (v1.1, but format frozen now)**: the only hiding-preserving range proof ships every
  in-range salt — **16 bytes per revealed byte (~17× the disclosed data)** + ≤2·32·log₂(n) boundary
  path bytes.
- **The tempting "optimization" is catastrophic**: shipping the per-file fine-seed instead lets anyone
  derive all salts, and then — the verification pass sharpened this — **`fine_root` itself (present in
  every manifest and bundle) becomes an unsalted-equivalent commitment to the whole file**: one tree
  computation confirms any guessed document, no proof needed. Boundary sibling leaves additionally
  fall to ≤256 guesses each, and co-path interior nodes partition the remainder into
  brute-forceable small subtrees. File-wide hiding collapse, under the spec's own primary threat model.

**Fix (adjudicated between the two competing proposals)**: keep per-byte leaves (block leaves would
over-reveal boundary bytes and contradict the byte-range promise), but derive salts via a **GGM binary
PRF tree** keyed by the fine-seed (children = HMAC(parent, 0x00/0x01) — or SHA-256(parent‖bit), which
is ~2 compressions/byte, cheaper than the current flat derivation): any contiguous range's salts are
then conveyed by ≤2·log₂(n) inner seeds (**~1.7 KB even at n=10⁸**) while out-of-range salts stay
pseudorandom (puncturable-PRF hiding). Standard construction, ~50 lines. Additionally: (a) add the
normative sentence "range proofs MUST carry per-leaf salts / subtree seeds covering revealed leaves
only; the fine-seed never leaves the vault"; (b) mandate streaming tree construction (O(log n)
memory) and a documented size ceiling for fine-tree files; (c) **M0 must actually build a fine tree,
extract a byte-range proof, and verify it against `fine_root`** — currently no MVP test ever
exercises the format being permanently embedded in paid manifests (that omission was the entire
justification gap in line 102's defense).

### M2. Signature acceptance rule is self-contradictory; downgrade surface undefined
`MVP-SPEC.md:68`: "Verifier requires both" + "Fallback …: ship Ed25519-only" in the same line. If the
fallback triggers, every seal fails every spec-faithful verifier; if verifiers instead "verify
whatever is present", that unstated weaker rule means a future Ed25519 break lets forged manifests
simply present as fallback-profile. Line 80 also never states that zero valid anchors is a hard fail,
so a sig-stripped, unanchored bundle's verdict is undefined; the "forged sig" tamper row (line 107) is
unspecifiable without the rule.

**Fix**: an explicit `sig_policy` field (ordered required-algorithm list) inside the signed body;
verifier MUST validate every listed signature (hybrid never passes with one), MUST require ≥1 valid
anchor binding the manifest bytes, and MUST label verdicts "hybrid (PQ)" vs "Ed25519-only"; state the
anti-downgrade policy for accepting old Ed25519-only manifests. Freeze in M0.

### M3. Encodings unpinned — golden vectors are currently unwritable
Line 106 demands bit-exact WASM/native golden vectors, but (all [verified] against the RFCs/crates):
- **"Canonical deterministic CBOR" names no profile or crate** — RFC 8949 §4.2.1 and RFC 7049 §3.9
  sort map keys *differently*; ciborium has no canonical mode, serde_cbor is unmaintained, dcbor
  implements a third profile (numeric reduction). Same logical manifest → different `work_id`.
- **"Manifest body" is never defined as a byte string** (which fields, re-encoded how), yet it is what
  signatures cover and `work_id` hashes; lines 32/73/80 say just "manifest hash" without saying
  *which* of the two digests (body vs full bytes) — an engineer implementing line 73 in isolation
  could stamp `work_id` and produce tokens no verifier can match.
- **`unit_id`/`file_id` have no encoding or scope** despite feeding HKDF and the AAD; the manifest
  nests units *inside* the file table (suggesting per-file numbering) while `--units 3,5` is global.
  Per-file numbering would silently derive **identical `k_u` and `unit_salt` for unit 0 of every
  file**.
- **HKDF salt-vs-info placement unstated** (RFC 5869 has both); **Merkle odd-node rule unstated**;
  label concatenations have no length/width discipline.

**Fix**: add a Definitions section: RFC 8949 §4.2.1 core deterministic encoding, definite lengths, no
floats, pinned crate+version; **make re-encoding unnecessary** by structuring the manifest as
`{body: bstr, signatures}` so signatures/work_id cover the exact embedded bytes; name the two digests
(`work_id` vs `anchor_digest`) and replace every bare "manifest hash"; `unit_id` = work-global LE64,
`file_id` = LE64 file-table index, used identically in labels/AAD/leaves; HKDF: salt = empty, info =
label‖LE64(id); RFC 6962-style odd-node rule; define empty/1-byte-file behavior.

### M4. Arbitrum receipt: the named APIs can't capture it, and as specced it isn't verifiable — but both are fixable [verified, modified]
Verified against ant-core 0.5.0 source and docs.rs: `data_upload` returns
`{data_map, chunks_stored, payment_mode_used}` (it internally *discards* cost) and `chunk_put` returns
a bare address — **the "reuse upstream as-is" plan (line 54) cannot produce the tx hashes line 75
wants**. No upstream changes are needed though: the public, documented prepare→pay→finalize surface
exposes them (`prepare_chunk_payment`, `SingleNodeQuotePayment::pay → Vec<TxHash>`,
`batch_pay → PaidChunk.proof_bytes` embedding tx_hashes + quote preimages, and the external-signer
`PaymentIntent`/`finalize_upload(tx_hash_map)` flow where antseal submits the tx itself); block
numbers come from one `eth_getTransactionReceipt`. Separately: **no on-chain datum contains
SHA-256(manifest bytes)** — `payForQuotes` calldata carries quote hashes whose preimages commit BLAKE3
chunk addresses — so line 69's "anchors bind SHA-256(manifest bytes)" is false for this anchor and
line 80's bind-check is unimplementable from the specced bundle contents (addresses alone don't link
to calldata; quote *preimages* are needed and never persisted). The chain **is** constructible:
self_encryption is deterministic and standalone, so a verifier holding manifest bytes can recompute
chunk addresses → match persisted quote preimages → confirm quote hashes in the tx via RPC; or store
the manifest via `chunk_put` so the paid quote commits BLAKE3(manifest bytes) directly.

**Fix**: rewrite line 54 (seal path uses the payment APIs; keep `data_download` for reads) and line 75
(persist tx hashes + **quote preimages** + proof_bytes); either spec the full verification chain
(with address recomputation in seal-core, WASM-safe) or demote the receipt in every user-facing
verdict to "supporting evidence — no independently proven time" until it exists. Scope line 69's
"anchors bind…" claim to OTS/RFC 3161.

### M5. `StorageBackend` trait shape fights ant-core's batch payment model
Per-blob `put_data` + detached `payment_receipts` (line 54) can't express upstream's
quote→pay(Merkle batch)→finalize flow; a `--split` seal of ~100 paragraphs becomes ~101 sequential
quote+pay cycles and up to ~101 Arbitrum txs where Merkle mode does ~1 — direct gas/latency cost and a
fragmented receipt anchor. `put_chunk`/`get_chunk` appear in no product flow (dead adapter surface
re-verified on every upstream bump).

**Fix**: batch-first trait: `quote_batch(&[Blob]) → CostQuote`,
`put_batch(&[Blob]) → (Vec<Address>, PaymentReceipt)` over PaymentMode::Merkle; drop the chunk
methods; derive the receipt shape from `MerkleBatchPaymentResult`.

### M6. Anchor *verification* must live in seal-core, or the WASM page can't deliver the offline verdict
Lines 46/74 put OTS and RFC 3161 verify in `seal-anchor`; lines 50/84 build the page from `seal-core`
only; lines 35/80 require the page to render per-anchor offline verdicts. As drawn, M3 either breaks
the central promise or forces an unplanned mid-M3 code migration.

**Fix**: seal-core (WASM-safe, no I/O) owns all anchor *parsing/verification* (TimeStampResp/TSTInfo +
sig check, .ots deserialization + op execution, receipt binding); seal-anchor shrinks to the network
side (submit, upgrade polling, capture). Add anchor-verify golden vectors + wasm32 build to M2's exit
criteria.

### M7. What exactly is encrypted? Raw vs canonical bytes is ambiguous — and raw bytes may never be stored
`unit_commit` covers canonical bytes (line 66) and units are canonical byte-ranges (line 58), yet the
verifier "decrypt → **canonicalize** → recompute unit_commit" (line 80) implies ciphertexts hold
non-canonical bytes. If ciphertexts hold canonical bytes: for any file where raw ≠ canonical
(CRLF/BOM/NFD), the original raw bytes are **never stored on Autonomi** — the manifest's raw-hash
commitment can never be opened from storage, and after vault+original loss the exact original file is
unrecoverable despite the "permanent storage" framing. If they hold raw bytes: canonical ranges don't
delimit raw bytes and per-unit encryption of `--split` files is ill-defined.

**Fix**: specify ciphertext = the unit's canonical bytes; verify chain becomes decrypt → recompute
commit → idempotence check. Where raw ≠ canonical, additionally encrypt+upload the raw file as one
extra whole-file unit (own key/commit/address) so the raw commitment stays openable; record the
linkage in the file table.

### M8. The sealer is an adversary too: no structural invariants, no canonical-rendition hash
Line 80 never checks that unit ranges are sorted, non-overlapping, in-bounds, and exactly tile the
file — the "position + total size" guardrail renders numbers the sealer chose. And since
canonicalization is lossy and the only file-level commitment is the raw hash, even a full `--all`
reveal of a text file can't be cross-checked against any file-level commitment. A sealer can place a
revealed paragraph at a false position or inflate the file size to bury a quote; everything passes.

**Fix**: add `canon_hash` (hash of the full canonical rendition) per text file to the manifest;
verifier invariants: ranges sorted/non-overlapping/exactly partition [0, canonical_size); on full
reveal, concatenated units must hash to `canon_hash`. Tamper fixtures: overlapping/out-of-bounds/
non-tiling ranges, size mismatch.

### M9. Tamper matrix covers honest bit-flips only — no hostile-structure or resource-exhaustion cases
`.sealproof`, DER, and `.ots` are adversary-authored inputs parsed in the CLI and in the
counterparty's browser tab, yet line 107 lists only mutations of honest artifacts. Unaddressed: CBOR
nesting/allocation bombs, absurd unit counts, multi-GB embedded ciphertexts, BER-vs-DER laxity in
TimeStampResp (historically bug-rich), unbounded .ots op-chains.

**Fix (M0 requirements)**: strict definite-length canonical CBOR (reject otherwise); hard caps (bundle
size, unit count, depth, allocations bounded by remaining input); strict DER; .ots op/length limits;
cargo-fuzz targets for bundle/manifest/TimeStampResp/.ots parsers wired into CI; a
"malicious structure" tamper-matrix family.

### M10. Verifier-page trust: any host can serve lying JS
"Zero-install" verification (line 24) + "hostable on any static host" (line 84) with no reproducible
build, published artifact hash, canonical URL, or in-page provenance = a verifier that always prints
VERIFIED defeats the product for its stated audience with no cryptography broken. Online mode's
unpinned endpoints are manipulation points.

**Fix**: reproducible wasm build with published SHA-256 + signed releases; one canonical URL printed
by the CLI and used in docs; page footer shows its own build hash + "for high-stakes verification run
`antseal verify`"; online mode pins ≥2 independent endpoints, requires agreement, renders results as
an advisory overlay distinct from the offline verdict.

### M11. Wallet linkability: every bundle doxes the sealer's entire sealing history
The receipt (tx hash → payer wallet) is embedded in every bundle: on-chain, one wallet links every
seal a user makes (count, timing, cost ≈ size) and typically traces to a KYC'd exchange; any bundle
recipient can enumerate the sealer's full history. Material for IP firms and inventors; absent from
the risk list.

**Fix**: make receipt inclusion opt-in (`reveal --include-receipt` — line 75 already calls it a
"bonus" anchor); wallet-hygiene guidance in `init` and docs (fresh address per work/client); add a
linkability section to the threat-model doc.

### M12. Anchor lifecycle policy missing at every stage: seal-time minimums, upgrade automation, verdict semantics, long-term validation
Compound gap across four findings: (a) line 120 lets a seal proceed with all TSAs down while OTS is
only a *pending* promise and upgrade is manual-only (`status --upgrade`) — a user who never returns
can hold a seal with **no strong timestamp at all** if the calendars later die; (b) verdict semantics
for pending/missing/degraded anchors are unspecified — the same-day reveal (every demo) carries an
unprovable OTS and the page's rendering choice decides whether counterparties trust it; (c) no policy
for **expired/dead TSA certificates years later** — fail-closed silently kills aging bundles exactly
when disputes surface; (d) sealer-chosen "claimed time" has no display rules and will be read as
proven.

**Fix**: seal fails without ≥1 successful RFC 3161 token unless `--force-degraded`; attempt pending
OTS upgrades opportunistically on *every* CLI invocation and nag from `list`; spec a per-anchor status
taxonomy (proven / pending / invalid / absent) with exact wording and one headline line ("Existed no
later than \<earliest fully-proven time\>"); RFC 3161 validity evaluated at genTime (render "valid at
stamping; cert since expired" distinctly); claimed time rendered subordinate and labeled "asserted by
sealer — NOT verified"; flag >48 h divergence between verified anchors.

### M13. Vault: parameters, theft model, wallet-key location, memory hygiene all unspecified
"scrypt → XChaCha20-Poly1305" (line 88) with no N/r/p, no salt, no params-in-header (a later default
change bricks old vaults). The vault concentrates every work's `W` against **permanently public**
ciphertexts — theft = retroactive decryption forever, and `vault export` backups are scattered by
design; the risk list covers only *loss*. Whether the Arbitrum private key sits inside the encrypted
vault is unstated. No zeroization requirements.

**Fix**: pin scrypt N≥2¹⁷, r=8, p=1 (or Argon2id) + random 16 B salt + params stored in the vault
header; wallet key lives inside the encrypted vault (or external signer support); `zeroize` on W/k_u/
passphrase buffers; add vault-theft to the threat-model doc.

### M14. Wallet funding UX is the first wall every user hits, and it's blank
`init` presumes an existing Arbitrum One wallet holding ANT + ETH for gas. For researchers/inventors/
small legal practices that's the hardest step in the journey: no key generation, no balance display,
no required-amount guidance, no distinct insufficient-ANT vs insufficient-gas errors, no post-hoc cost
record.

**Fix**: `init` generates or imports a key and prints the address + funding instructions; balances
shown beside every quote; preflight fails early with actionable errors; per-work cost stored and shown
by `list`; a "funding your wallet" doc in M4.

### M15. Mid-seal failure: naive retry pays twice, by design
Seal is a multi-payment pipeline on a young network; there is no persisted in-progress state, no
resume, no idempotency — and because nonces are random (correctly), a re-run re-encrypts to
*different* ciphertexts at *different* addresses: the user pays again and orphans paid ciphertext
forever. The E2E plan tests only the happy path.

**Fix**: a seal journal in the vault (per-unit nonce, ciphertext hash, target address, receipts as
they land) written *before* payment; re-running `seal` resumes with recorded nonces/ciphertexts;
`list` shows `incomplete`; add kill-mid-seal → resume → verify to the devnet E2E.

### M16. Units are opaque: no ids scheme, no preview, irreversible mistakes
`reveal --units 3,5` — numbered how, across files? No command enumerates units; with `--split` a
thesis is hundreds of anonymous paragraph numbers, and a mistyped id irreversibly ships the wrong
secret to a counterparty.

**Fix**: define unit addressing (work-global LE64, ties into M3); add `antseal show <work-id>` listing
units with file/range/size/snippet; `reveal` prints exactly what will be disclosed and requires
confirmation (`--yes` for scripts); heading-aware splitting noted for v1.1.

### M17. "Priority" overclaims: seals prove possession, not authorship — and the docs never say so
Anyone can seal content they merely received; a recipient's earlier seal will out-rank the true
author's in this system's own verdicts. The signature binds a self-generated key, not an identity.
The M4 docs list covers "not a legal notary" but not authorship limits or compelled disclosure (the
vault holder *can* be forced to reveal; vault destruction is the only opt-out).

**Fix**: verdict text: "proves the holder of key X possessed this content by time T; does not prove
authorship"; qualify/drop "priority" in the one-liner and legal copy; add authorship-limits
("seal before you share") and coercion notes to the M4 docs mandate.

---

## Minor — worth fixing, lower stakes

1. **"Sepolia" stage needs one clarifying sentence** [verified, corrected]: no *public* Autonomi 2.0
   testnet exists (ant-node roadmap: "Testnet deployment — In Progress"), but the spec's path is
   executable as written via upstream's **self-hosted** Sepolia mode (`start-devnet-sepolia` example:
   25 local nodes verifying payments against the real deployed Arbitrum Sepolia contracts). State
   that this is what "Sepolia" means; rename the flag value `sepolia` → `arbitrum-sepolia` (chain
   421614 — not Ethereum Sepolia) to match upstream; note that the single M4 mainnet smoke seal is
   the *only* pre-release exposure to the real public storage network.
2. **M1 E2E precedes anchors (M2)**: zero-anchor seals aren't representable in format or CLI. Specify
   anchor cardinality 0..n + per-anchor status enum, an empty-anchor golden vector in M0, and a
   dev-only `--no-anchor` flag.
3. **OTS crate reality** [verified]: the crate is `opentimestamps` (repo *name* is
   rust-opentimestamps), last release 0.2.0 (2023-04-12), repo dormant since; it contains **no
   calendar HTTP client** — only .ots parse/serialize/op-evaluation. The M2 "evaluate; fallback if
   unmaintained" decision is already answerable today: the calendar layer (submit, upgrade polling,
   attestation merge) is in-house work on every branch. Pre-decide it and size M2 accordingly.
4. **PQC crate decisions** [verified]: RustCrypto `ml-dsa` 0.1.1 (stable since 2026-05, FIPS 204
   final, ~1.5M downloads, pure Rust) — but **unaudited, with two Jan 2026 advisories** (a
   verification-soundness bug patched in 0.1.0-rc.4; a timing side-channel) — pin exactly;
   `fips204` dormant since 2024-12-22. Both pure-Rust/no_std, so "ML-DSA proves WASM-hostile" (line
   119) is overweighted — the real WASM gotcha is **getrandom**: 0.3/0.4 need the `wasm_js` feature
   + `RUSTFLAGS='--cfg getrandom_backend="wasm_js"'`, while 0.2 (via ed25519-dalek 2.x) needs
   feature `js`; a mixed workspace needs both. Also decide ed25519-dalek 2.x vs the fresh 3.0.0
   (2026-07-06). Write the wasm32 build recipe into the spec and run it in CI from M0.
5. **Name the second TSA now** [verified]: it ships in the binary, so it's a release decision.
   Verified candidates + caveats: DigiCert `timestamp.digicert.com` (free, code-signing-positioned),
   zeitstempel.dfn.de (operational, non-commercial terms), Sectigo (~15 s spacing), SwissSign
   (~10/day). Record terms/rate limits. Also: FreeTSA's 2026 cert is **ECC P-384** — the verifier
   must handle ECDSA tokens, not just RSA. Pin a default esplora endpoint too (line 84).
6. **Permanence consent moment**: seal goes straight to paid irrevocable upload; only vault loss gets
   a mandated nag. Require a pre-upload summary (files, bytes, cost, "permanent and irreversible")
   with `--yes` for scripts.
7. **Format-stability promise missing**: nothing guarantees a 2026 `.sealproof` verifies on the 2031
   verifier. Add: every released format version verifies forever; per-version golden vectors retained
   in CI; the hosted page supports all released versions.
8. **Missing non-code deliverables**: license (verifier must be open/auditable; "hostable on any
   static host" presumes redistribution rights), verifier domain/hosting (the M4 gate needs a hosted
   page no milestone ships), binary signing/checksums (unsigned crypto tooling on macOS/Windows is
   blocked or scare-screened for exactly the zero-install audience), an MVP success metric.
9. **Crate naming heads-up** [verified, corrected]: `seal-core`/`seal-cli` are taken on crates.io by
   an unrelated active project; `antseal`, `seal-anchor`, `seal-net` are free. Only matters if
   publishing (workspace-internal crates don't need registry names) — but renaming is cheap now and
   impossible-ish after M4; also line 3's "crate prefix" claim is false as written (crates are
   `seal-*`, not `antseal-*`). The `ant-` prefix reads as official Autonomi tooling (their binaries
   are `ant`/`antnode`) — get a blessing or pick a non-ant name; add a pre-M0 naming task.
10. **CLI surface inconsistencies**: line 92 omits every positional the flows show
    (`status <work-id>`, `reveal <work-id>`, `verify <bundle>`, `seal <path>…`); `--force-text`
    (line 58) missing from the surface; `--network` enumerated differently at lines 18 vs 92. Make
    line 92 canonical and complete.
11. **Two divergent parking lots**: line 28 ("v1.1+", 10 items) vs line 101 ("v1.1", 5 items) with
    drifting names and a misplaced heading level (a non-milestone bullet inside `## Milestones`).
    Keep one canonical list; tag items "v1.1 (committed)" vs "later".
12. **Verification bullets lack milestone owners**: the L109 E2E mixes M1 and M3 deliverables; the
    adversarial doc-test (L111) maps to no milestone; the threat-model doc is written in M4 though
    its claims justify M0 design. Annotate owners; skeleton threat model in M0.
13. **Tamper-matrix row "bundle claiming a different byte-range"** has no corresponding MVP bundle
    field (range proofs are v1.1). Re-specify as a manifest-field mutation with a distinct error, or
    move to the v1.1 plan.
14. **Commitment opening hygiene**: verifier must enforce |unit_salt| = 16 and revealed length =
    manifest range length (shift-malleability otherwise); give `unit_commit` its own domain tag
    (e.g. 0x02 prefix) so a 49-byte unit's preimage can't be shaped like an interior node.
15. **Signing keys contradict "everything derives from W"**: they have no HKDF labels and are absent
    from the vault inventory (line 88). Derive them: Ed25519 seed = HKDF(W, "sig-ed25519"), ML-DSA ξ
    = HKDF(W, "sig-mldsa65") (FIPS 204 keygen expands a 32-byte seed) — and state that keys are
    per-work.
16. **Cadence wording**: upstream releases are weekly-to-biweekly (verified gaps of 5–15 days), not
    strictly weekly; ant-core 0.5.0 was 4 days old at review time — re-verify the pin at M0 start.
17. **Editorial**: title says "Notary", the word line 26 bans — retitle to "Proof-of-Existence &
    Selective-Disclosure Service"; "binary" used in two senses (files vs two-child tree — say
    "two-child Merkle tree" at line 67); "(title, claimed time — informational only, pubkeys)" —
    scope the parenthetical to claimed time only; reword line 102's "the widest, most trust-sensitive
    part of M3" (it is, by that same sentence, not in M3).

---

## Considered and rejected by the verification pass

- **"Bundles shouldn't embed `k_u`/ciphertext; a plaintext+salt opening proves the same verdict"** —
  REFUTED. `k_u` is HKDF-scoped to the one unit whose plaintext ships in the same bundle (zero
  marginal disclosure; a salt-only bundle is equally copyable and irrevocable), and the AEAD layer is
  load-bearing: without it, a seal whose uploaded ciphertext was garbage would verify clean in every
  mode — the embedded ciphertext + key is what binds the revealed content to the network copy for
  `--live` and the tamper matrix. Residual nit worth taking: line 80 could state the layering
  explicitly (commitment+anchors = the evidence; AEAD = the storage linkage) and add an offline check
  that the embedded ciphertext derives the manifest's network address.
- **"The Sepolia milestone plan is wrong as written"** — REFUTED as a conclusion (see Minor #1: the
  documented self-hosted Sepolia mode satisfies every spec mention; only clarity fixes remain).

## What checked out (verified against live sources, 2026-07-27)

Autonomi 2.0 live since ~2026-04-17 with pay-once immutable storage on Arbitrum One; mutable types
absent; the 1.0→2.0 transition was an explicit full data reset (strongly validating the
anchors-over-Autonomi design); WithAutonomi is the legitimate upstream (maidsafe/autonomi redirects to
it); `ant-core` 0.5.0 exists with *all six* named client APIs by exact name; the `start-local-devnet`
example (25 nodes + Anvil) exists; self-encryption is documented convergent (justifying the AEAD
wrap); OTS has 4 free public calendars; FreeTSA operational; WIPO PROOF discontinued 2022 for low
demand; eIDAS qualified timestamps cost money via QTSPs; esplora APIs live; `antseal` is free on
crates.io; Autonomi 2.0 itself uses ML-DSA-65 (nice alignment with the hybrid choice). Design calls
verified sound: the work_id (body) vs anchored-hash (full bytes) split is deliberate and
cryptographically right (anchoring signature-bearing bytes binds sigs into the timestamp); HKDF labels
are mutually prefix-free; XChaCha20-Poly1305 with random 192-bit nonces is safe here (each `k_u`
encrypts exactly one message); 0x00/0x01 + LE64(i) leaf/node separation is sound; the ML-DSA-day-one
hedge (M0 probe + reserved slot) and the free-OTS-vs-paid-bundle positioning are honest and
well-constructed.

---

*Generated by a six-lens multi-agent review + seven-verifier adversarial pass (13 agents, ~700k
tokens, ~170 tool calls). Full per-finding detail: the six finder reports and seven verification
verdicts are preserved in the session transcript directories.*

---

# Cryptographic Audit (pre-M0-freeze, 2026-07-27)

**Method**: six specialist cryptographers (GGM/puncturable-PRF, selective-disclosure, AEAD, commitments, signatures/encoding, KDF/key-management), each doing reduction-level analysis with a "confirmed sound" list; then four adversarial verifiers on the load-bearing findings, pinning the *minimal correct* fix and rejecting over-heavy or insufficient ones. All confirmed findings are applied in the Revision-2 spec.

## Confirmed & fixed

- **[CRITICAL-of-the-crypto-round] Cross-mode equivocation** (found independently by the GGM and selective-disclosure lenses; verified real, high confidence). Each fine-tree file carried *two* independent salted commitments over the same bytes — per-unit `unit_commit` and per-file `fine_root` — cross-checked only on a full reveal the sealer may never issue. Once v1.1 range reveals ship against the now-frozen `fine_root`, a malicious sealer opens byte *i* to X (via `unit_commit`) for one counterparty and to Y≠X (via a range proof) for another, under one anchored `work_id`, undetectably. Verified frozen-unfixable-later. **Fix (verified minimal, option (a); options (b) redefine-unit_commit and (c) document-only both proven insufficient):** `fine_root` is the *sole* content commitment for covered bytes; per-unit reveals become leaf-aligned range openings against `fine_root` using the already-M0-tested machinery; `unit_commit` is dropped for covered units and kept only for `--no-fine-tree` and raw-mirror units.
- **Resume `(k_u,nonce)` reuse** (major, verified — narrower: bites in the kill-mid-upload case). The journal recorded a ciphertext *hash*, and resume re-encryption under the recorded nonce with a changed source = catastrophic AEAD nonce reuse. **Fix:** journal stages ciphertext *bytes*; resume re-uploads byte-identical and never re-encrypts; abandon (fresh `seal_id`+nonces) if bytes are lost. Format-invisible.
- **Reject non-canonical CBOR on decode** (major, verified). Without it, a self-signing sealer ships a duplicate-key body that first-wins vs last-wins decoders read differently → `work_id` binds bytes but not meaning; the CLI and WASM page could diverge on a "valid" bundle. **Fix:** decoder hard-rejects duplicate keys, non-shortest ints, indefinite lengths, unsorted/unknown keys, trailing bytes.
- **Strict/canonical signature verification** (major, verified). Ed25519 malleability + non-canonical ML-DSA encodings let a lenient and a strict verifier disagree on the same frozen bundle. **Fix:** RFC 8032 `verify_strict` + canonical ML-DSA, as a conformance requirement; plus a frozen signature context string `"antseal-manifest-v1"` bound into both signatures.
- **HKDF info injectivity** (major, verified — current 8-label registry is injective, but only by length-coincidence; a demonstrated LE64 collision shows how a future label breaks it). **Fix:** `info = u8(len(label)) ‖ label ‖ LE64(id)` with a reserved sentinel id — injective by construction.
- **Raw-mirror ↔ canonical binding** (minor, verified real). A sealer could co-timestamp an "original" that doesn't canonicalize to the sealed content. **Fix:** verifier recomputes `canonicalize_v(raw)` (descriptor-pinned Unicode version) and matches the canonical bytes.
- **Padding over-claim** (downgraded major→minor on verification: the defect is the *claim*, not the 256-B formula; and it's format-version-scoped, so changeable later). **Fix:** honest re-scoping of the anti-fingerprinting sentence + threat-model residual note; formula unchanged.
- **Hardening applied:** leaf-exact GGM cover (normative + M0 test); length-checks on all disclosed 32-B seeds/nodes; vault KDF raised to Argon2id (m≥256 MiB) with the parameter header authenticated into the vault AEAD; wallet key under its own sub-key.
- **Security-assumptions block** added (several lenses: sound-but-must-be-documented-before-a-permanent-freeze): binding = standard-model SHA-256 CR (~128-bit, no agility); hiding = RO-model secret-prefix salted SHA-256 (not implied by CR); GGM = SHA-256-as-RO / XMSS-style message-keyed PRG, length-extension inapplicable; AEAD confidentiality-only and non-committing, with all binding on the SHA-256 commitments (a future refactor must not drop a commitment to trust the AEAD); multi-target hiding ~2^128/K.

## Confirmed sound (positive evidence for the freeze)

GGM puncturing / out-of-range salt pseudorandomness (co-path argument, RO/PRG model); MSB-first dyadic cover is exact (no over-coverage, verified for power-of-two and unbalanced n incl. n=1); 16-B salt truncation; boundary sibling leaf-hashes hide out-of-range bytes; domain-tag disjointness (0x00–0x06 vs CBOR heads); no length-extension leverage anywhere; the path_salt/file_salt split closes the partial-reveal confirmation oracle; per-unit AEAD key disclosure leaks nothing about W or other units; hybrid non-separability / anti-downgrade; DSKS / exclusive-ownership resistance; two-layer separation (evidence verdict never depends on storage/`--live`); no nonce reuse in normal operation; XChaCha 192-bit random-nonce collision bound; no padding-oracle exposure. The AEAD-non-committing property was specifically checked against storage-linkage, `--live`, restore, and manifest persistence and found not to be relied upon by any verdict-bearing check.

## Residual (accepted, documented — not blockers, but the freeze rests on them)

- All **hiding** claims are random-oracle-model, not standard-model — they would not survive a SHA-256 that is collision-resistant but not a PRF.
- **Binding** is permanently pinned to ~128-bit SHA-256 collision-resistance (a version hook is reserved but there is no in-format agility).
- Per-unit **size fingerprinting** is an inherent residual of per-unit selective disclosure (bounded by the difficulty of grouping content-addressed chunks whose manifest is encrypted).
- These constructions have had **adversarial-agent review, not a human cryptographer's audit or a machine-checked proof**. Before M0 freeze the golden vectors must be cross-checked against an independent implementation (which the spec mandates), and the novel pieces (GGM salt tree, two-layer reveal, hybrid-sig binding) warrant a professional review.
