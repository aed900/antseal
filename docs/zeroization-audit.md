# Zeroization coverage audit (task C21)

**Date: 2026-07-28. Reviewed by: `aed900`.** Scope:
`crates/antseal-core/src/crypto/` — every secret-bearing type and buffer, its
zeroization disposition, and where none is possible, why.

MVP-SPEC.md line 143 requires `zeroize` on `W`, unit keys and passphrase
buffers, "documented caveat: the WASM verifier cannot guarantee this for
bundle-supplied keys in browser memory". This is that documentation, plus the
sweep that found the gaps the spec line does not anticipate.

**Machine-checked part.** The `ZeroizeOnDrop` claims in tables A and D are
compile-time `const` assertions in
`crates/antseal-core/src/crypto.rs::zeroization_sweep`, evaluated whenever the
crate's test target compiles — on native *and* on
`wasm32-unknown-unknown`. A dependency bump that silently dropped a `zeroize`
feature fails the build; it cannot pass a green test suite. Per-module
assertions also exist (C5/C9/C10/C13); the roll-up is what answers "is
anything missing?".

**Honest part.** Five residual risks (R1–R5) are recorded below. R1 is a
genuine gap in a third-party crate with no available fix. None of the five is
papered over.

---

## A. Owning secret types defined by this crate

All are `ZeroizeOnDrop`, none is `Clone` or `Copy`, none implements
`Display`, and every one redacts its `Debug`.

| Type | Module | Holds | Wiped by | Notes |
| --- | --- | --- | --- | --- |
| `MasterSecret` | `secrets` | `W` (32 B) | manual `Drop` | The root secret. A stolen `W` retroactively decrypts permanently public ciphertexts with no rotation, so this is the highest-value 32 bytes in the system. |
| `SecretBuf` | `secrets` | passphrase-class bytes (`Vec<u8>`) | `Drop` → `Vec::zeroize` | Wipes **spare capacity** too. Deliberately **no growth API** — see R2 for why that matters. `Debug` withholds even the length (passphrase length is guessing-relevant). |
| `Key32` | `material` | any derived 32-B key | macro-generated `Drop` | The concrete type behind both AEAD key aliases below. |
| `Seed32` | `material` | `s_root`, Ed25519 seed, ML-DSA ξ, bundle-supplied GGM covering seeds | macro-generated `Drop` | |
| `Salt16` | `material` | `unit_salt`, `path_salt`, bundle-supplied disclosed salts | macro-generated `Drop` | |
| `FileSalt` | `material` | `file_salt` (opaque — no public byte accessor) | inner `Salt16`'s `Drop` | Marker impl states the contract the inner field upholds. |
| `UnitKey` (= `Key32`) | `unit_aead` | `k_u` | as `Key32` | Asserted under its public alias so a future de-aliasing cannot lose the property. |
| `ManifestKey` (= `Key32`) | `manifest_aead` | `k_m` | as `Key32` | |
| `ManifestStorageRecord` | `manifest_aead` | `{nonce (public), k_m}` | explicit `Drop` + `Zeroize` | Not `Clone`: uncontrolled key copies defeat zeroization. |
| `NonCoveredUnitDisclosure` | `disclosure` | `{unit_id (public), unit_salt}` | field drop glue | Marker impl **added by C21**. `derive(Debug)` is safe: the only secret field is a `Salt16`, whose own `Debug` redacts. |
| `FullFileRevealDisclosure` | `disclosure` | `{file_id (public), path_salt, file_salt}` | field drop glue | Marker impl **added by C21**. Same `Debug` argument. |
| `PartialRevealDisclosure` | `disclosure` | `{file_id, path_salt, Vec<NonCoveredUnitDisclosure>}` | field drop glue, **partially** | **No marker impl — see R2.** The claim would be false. |

## B. Borrowed views — deliberately *not* wiping

| Type | Why no zeroization |
| --- | --- |
| `MasterSecretRef<'a>` (`material`) | It is a `Copy` **borrow** of `W`, owning nothing. A wiping `Drop` would either be a lie (nothing to wipe) or would wipe *through a shared reference*, destroying the owner's data at an arbitrary point. The owning `MasterSecret` is what wipes. A live test (`the_master_secret_view_is_a_borrow_not_an_owner`) pins that the borrow/own split is still the shape it claims to be. |

## C. Public values — deliberately *not* secret

Not zeroized, and correctly so; listed to close the sweep rather than leave
them unexplained. All ship in the manifest or the bundle in the clear.

`SealId`, `Nonce24`, `NodeHash32`, `CommitmentDigest`, `FineRoot`,
`Ed25519PublicKey`, `MlDsa65PublicKey`, `Ed25519Signature`,
`MlDsa65Signature`, `WorkId`, `AnchorDigest`, `UnitId`/`FileId`,
`SigPolicy`/`PolicyLabel`. These render hex in `Debug` on purpose — verifier
diagnostics need them, and there is nothing to withhold.

## D. Third-party key state

Held but not defined here. Each is `ZeroizeOnDrop` only because a
**non-default** `zeroize` feature is enabled in the workspace pin; that is
exactly what a routine version bump loses silently, so all four are asserted.

| Type | Holds | Feature that provides it |
| --- | --- | --- |
| `ed25519_dalek::SigningKey` | dalek's copy of the `W`-derived seed plus the expanded scalar | `ed25519-dalek` feature `zeroize` (D13 consumption shape) |
| `ml_dsa::SigningKey<MlDsa65>` | ξ | `ml-dsa` feature `zeroize` (non-default; D14) |
| `ml_dsa::ExpandedSigningKey<MlDsa65>` | `rho`, `K`, `tr`, `s1`, `s2`, `t0` | same |
| `chacha20poly1305::XChaCha20Poly1305` | the cipher's internal key copy | `chacha20poly1305` feature `zeroize` |
| `hkdf::Hkdf<Sha256>` (internal `Hmac<Sha256>`) | the PRK-keyed HMAC state | **none available — see R1** |

## E. Intermediate buffers

| Buffer | Where | Disposition |
| --- | --- | --- |
| HKDF OKM (`[u8; 16]` / `[u8; 32]`) | `hkdf::derive_key32` / `derive_seed32` / `derive_salt16` | **Wiped** — explicit `okm.zeroize()` immediately after the value is moved into its newtype. |
| Padded plaintext (`Vec<u8>`) | `unit_aead::encrypt_unit` | **Wiped** — `padded.zeroize()` after encryption, on both success and failure. |
| Padded plaintext (`Vec<u8>`) | `unit_aead::decrypt_unit_with_key`, error path | **Wiped** — authenticated-but-malformed plaintext is still the sealer's secret content, so it is wiped before being discarded. |
| Padded plaintext (`Vec<u8>`) | `unit_aead::decrypt_unit_with_key`, success path | **No residue** — `truncate(true_length)` leaves the tail in the allocation, but the strip has already *validated* every byte beyond `true_length` to be zero, so there is no secret past the new length. Correct as written; not a gap. |
| Decrypted unit plaintext (returned `Vec<u8>`) | `decrypt_unit` / `decrypt_unit_with_key` return value | **Caller-owned — see R3.** |
| `into_bytes()` results | `Key32` / `Seed32` / `Salt16` | **Caller-owned — see R4.** |
| Ed25519 seed → dalek | `sig_ed25519::signing_key` | **No transient copy** — the derived `Seed32` wipes on return; dalek's own copy wipes on its drop. |
| ML-DSA ξ → crate | `sig_mldsa::signing_key` | **No transient copy** — a zero-copy borrowed view is handed to `from_seed`; no intermediate array exists to forget about. |
| `signing_message(body)` (`Vec<u8>`) | `sig_ed25519` | Not wiped, **deliberately**: it is `ctx ‖ 0x00 ‖ manifest body`, and the plaintext manifest body ships in the clear inside every `.sealproof`. Nothing vault-secret is in it. |
| Ciphertexts, public keys, signatures | throughout | Public by construction. |
| `FileSalt::expose_bytes_for_test_vectors` | `material` | Gated behind the `test-vectors` feature, which no shipped build enables. |

---

## Residual risks

### R1 — HKDF/HMAC internal key state is never wiped, and no available feature fixes it

**Severity: the highest in this document.** Every `derive_*` call builds an
`hkdf::Hkdf<Sha256>` from `W`. That value holds an `Hmac<Sha256>` keyed with
the HKDF **PRK**, and `Hkdf::extract` additionally materialises the raw
32-byte PRK and discards it. Both are `W`-equivalent *for that work*: anyone
holding either can produce every unit key, every salt, the fine seed and both
signing seeds. Neither is zeroized.

Why it cannot currently be fixed:

- `hkdf = "=0.13.0"` exposes **no** `zeroize` feature, and its
  `GenericHkdf<H>` derives `Clone, Debug` with no `Drop` and no `Zeroize`.
- `hmac = "=0.13.0"` *does* have `zeroize = ["digest/zeroize"]`, and it is not
  enabled in our pin — but enabling it **would not help**. `Hmac<D>` is
  generated by `digest::buffer_fixed!(… impl: MacTraits KeyInit)`, and
  `MacTraits` expands to `BaseFixedTraits MacMarker`. `digest`'s macro only
  emits `impl ZeroizeOnDrop` for types whose trait list names `ZeroizeOnDrop`
  explicitly, which this one does not. The feature forwards zeroization to
  `digest`/`block-buffer` internals, not to the HMAC key state.

So this is precisely the case C21's acceptance criterion anticipates: *"the
documented reason none is possible, e.g. crate-internal key state inside a
third-party crate."*

Scope and mitigation: the exposure is one stack-resident `Hkdf` per
derivation call, living only for the duration of `hkdf_expand`, plus one
discarded PRK array. It is never heap-allocated by us, never logged, never
serialized, and never crosses an API boundary. The realistic threat is a core
dump or a swapped page during a `seal`/`reveal`, which is the same class as
`W` itself being resident — and `W` *is* resident for the same window.

Follow-up: **task C22** (appended to `tasks/C.md`) — decide between (a)
accepting this permanently with the reasoning above, (b) upstreaming a
`ZeroizeOnDrop` trait-name addition to `hmac`'s `buffer_fixed!` invocation,
or (c) replacing the `hkdf` call with an in-house extract/expand over a
zeroizing HMAC. Option (c) is ~40 lines and already has an independent RFC
5869 reference implementation in this crate's tests, so it is cheaper than it
sounds — but it moves a **frozen derivation** into our own code, which is a
deliberate decision, not a drive-by.

### R2 — `PartialRevealDisclosure`'s `Vec` growth strands un-wiped salts

`add_revealed_unit` pushes into a `Vec<NonCoveredUnitDisclosure>`. On
reallocation the elements are moved bitwise into the new buffer and the old
allocation is freed **without** running their `Drop`, so every `unit_salt`
pushed before the growth remains in freed heap memory.

This is the same `Vec` hazard `SecretBuf` avoids by having no growth API at
all — the caveat is documented there and then reintroduced here.

Severity is low **today**: a `unit_salt` in this collection belongs to a unit
the bundle reveals anyway, so the stranded bytes are already-disclosed
material. The reason it is recorded rather than waved off is the *shape*: any
future field on this type holding undisclosed material would inherit the same
leak silently. Claiming `ZeroizeOnDrop` for the type would be false, so the
impl is deliberately absent.

Fix if it ever matters: pre-size with `Vec::with_capacity(unit_count)` at
construction (the count is known from the manifest), or take the complete
unit list in the constructor as `SecretBuf` does.

### R3 — decrypted unit plaintext is returned to the caller un-wrapped

`decrypt_unit` / `decrypt_unit_with_key` return a plain `Vec<u8>` holding the
sealer's secret content. It is not self-wiping, and it cannot be: the callers
are `restore` (writes it to a file), reveal previews (renders it), and the
verifier (recomputes commitments over it). Wrapping the return in a zeroizing
type would only relocate the problem, because every one of those callers must
hand the bytes onward.

Disposition: **accepted, caller-owned**, documented at the API. The vault
layer (U) owns hygiene for anything it persists.

### R4 — `into_bytes()` extractors hand out non-wiping copies

`Key32::into_bytes`, `Seed32::into_bytes` and `Salt16::into_bytes` return a
raw `[u8; N]`. The original still wipes on its own drop, but the returned copy
is an ordinary array with no `Drop`.

Disposition: **accepted, caller-owned**, already documented on the extractors
and in the `material` module docs. These exist for the encode paths (a salt
that ships in a bundle must become bytes eventually). The alternative —
removing them — would push the same raw copy into every call site with less
visibility.

### R5 — the WASM verifier cannot guarantee zeroization

The normative caveat of MVP-SPEC.md line 143, carried as a doc comment on the
crypto module root and delivered into `docs/threat-model.md` §2.10:

> **The WASM verifier cannot guarantee zeroization for bundle-supplied keys
> (`k_u`, `k_m`, salts) in browser memory.**

The types still call `zeroize` under `wasm32` and the writes are still
volatile and unreorderable — but that is a promise about one linear-memory
allocation, not about the machine. A JavaScript engine may have copied the
bundle bytes into engine-owned buffers before they ever reached linear memory
(`fetch`/`File` results, the source `ArrayBuffer`, string intermediates); the
whole WebAssembly memory may be relocated by `memory.grow`; the browser may
swap or snapshot the tab. None of that is reachable from Rust.

Bounded, not catastrophic: those keys open exactly the content the bundle
already contains in the clear, and **`W` never reaches a browser at all** —
the verifier holds bundle-supplied keys, never the master secret. Recorded as
residual risk rather than mitigated, because no mitigation exists at this
layer.

---

## Grep sweep — no secret material in any log, error or fixture path

Run 2026-07-28 at the C21 commit, from the workspace root. This ties to C4's
redaction tests, which assert the same properties dynamically.

| # | Check | Command | Result |
| --- | --- | --- | --- |
| 1 | No logging facility exists in `antseal-core` at all — secrets cannot leak through one that is not there | `grep -rnE "tracing::\|log::(trace\|debug\|info\|warn\|error)\|println!\|eprintln!\|dbg!\|print!" crates/antseal-core/src/` | **0 matches** |
| 2 | `CryptoError` cannot carry byte payloads: it derives `Copy`, so it holds no heap data, and no variant has a byte-array field | `grep -n "derive(Debug, Error" …/crypto/error.rs` → `#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]`; `grep -cE "Vec<u8>\|&\[u8\]\|\[u8; ?[0-9]+\]" …/crypto/error.rs` | **`Copy`; 0 byte-typed fields.** Variants carry only kinds, lengths, offsets and ids. |
| 3 | No secret type implements `Display` | `grep -rn "impl fmt::Display\|impl core::fmt::Display" crates/antseal-core/src/crypto/` | **6 matches, all benign**: `CommitmentKind`, `SaltKind`, `SigAlg` (non-secret enums, used in error text) and three test-local RNG-failure stubs. |
| 4 | No secret-material newtype uses a derived `Debug` | `grep -rn "derive(.*Debug.*)" …/crypto/material.rs …/crypto/secrets.rs` | **1 match**, a test-local error stub. Every secret type has a hand-written redacting `Debug`. |
| 5 | Composite structs that *do* derive `Debug` expose nothing | manual review of `disclosure.rs` (`NonCoveredUnitDisclosure`, `PartialRevealDisclosure`, `FullFileRevealDisclosure`) | **Safe** — their only secret fields are `Salt16`/`FileSalt`, whose own `Debug` prints `<redacted>`. |
| 6 | Owning secret types are not `Clone`/`Copy` | `grep -rnE "derive\(Clone" …/crypto/material.rs …/crypto/secrets.rs` | **3 matches, all correct**: `MasterSecretRef` (a borrow — `Copy` is the point), `NodeHash32` and `SealId` (public values). |
| 7 | Fixtures hold no real secrets | `grep -rli "NON-SECRET" testdata/` plus the fixture conventions in `testdata/README.md` | Fixture inputs are fixed and explicitly marked NON-SECRET; test `W` values are constants like `[0x11u8; 32]`. |

Dynamic counterparts (already in the suite, not re-derived here):
`debug_is_redacted` and `node_hash_debug_renders_hex` (`material`),
`debug_redaction` (`secrets`), `cover_entry_debug_redacts_the_seed`
(`content::fine_tree::cover`), and the C4 error-taxonomy message tests.

---

## Related records

- `docs/security-assumptions.md` — C20, the frozen assumptions (this audit is
  an operational property, not a format assumption, so it sits outside that
  freeze).
- `docs/threat-model.md` §2.1 (vault theft), §2.10 (this caveat).
- `docs/dependency-policy.md` — the pin-governance rules R1's follow-up must
  respect.
- `tasks/C.md` C22 — the R1 follow-up.
