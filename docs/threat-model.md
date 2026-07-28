# antseal threat model

**Status: SKELETON (M0, task Q12).** One part of this document is finished
and frozen — the security assumptions the permanent format rests on. The
rest is a numbered set of stubs to be written at **M4** (Q21), listed here
now so the freeze happens against a known map rather than a blank page, and
so nothing on the list can be quietly forgotten between M0 and M4.

Read section 1 as normative. Read section 2 as a table of contents for work
that has not been done.

## Positioning

antseal proves **existence, integrity and priority** of data you possessed.
It is **not** a legal notary, and it does not prove authorship — only that
the sealed bytes existed, unaltered, before a provable time. Every threat
below is scoped to that claim.

## Sign-off record

| What | Status | Signed off by | Date |
| --- | --- | --- | --- |
| Frozen security assumptions (section 1) | **FROZEN** — the five assumption classes the `.sealproof` format permanently rests on, authored by C20 against the implemented `antseal-core::crypto` tree | `aed900` | 2026-07-28 |
| Threat sections (section 2) | **NOT WRITTEN** — stubs only; due at M4 (Q21) | — | — |

The frozen block below is reproduced **verbatim** from
`docs/security-assumptions.md`, which is its source of truth and carries the
change header for it. The two copies are asserted byte-identical by
`crates/antseal-core/tests/security_assumptions_drift.rs`: edit one without
the other and the test suite fails. Do not "fix" a drift failure by editing
this copy — copy C20's block. If an assumption itself changed, that is a
format event, and it starts with a dated row in C20's change header.

---

# 1. Frozen security assumptions

<!-- BEGIN frozen-security-assumptions -->
## Frozen security assumptions (M0, 2026-07-28)

Five classes. Each names the assumption, what breaks if it is false, and the
code that implements or executes it. Spec references are MVP-SPEC.md line
numbers; code references are paths under `crates/antseal-core/`.

### 1. Binding — standard-model SHA-256 collision resistance (~128-bit)

**Assumption.** SHA-256 is collision-resistant. Nothing stronger, nothing
weaker, and no random-oracle behaviour is assumed for binding.

**What it binds.** Every commitment and every identity digest in the format:

| value | preimage | code |
| --- | --- | --- |
| `unit_commit` | `SHA-256(0x02 ‖ unit_salt ‖ unit_bytes)` | `src/crypto/commit.rs::unit_commit` |
| `raw_commit` | `SHA-256(0x03 ‖ file_salt ‖ raw_bytes)` | `src/crypto/commit.rs::raw_commit` |
| `canon_commit` | `SHA-256(0x04 ‖ file_salt ‖ canonical_bytes)` | `src/crypto/commit.rs::canon_commit` |
| `path_commit` | `SHA-256(0x05 ‖ path_salt ‖ path_utf8)` | `src/crypto/commit.rs::path_commit` |
| `fine_root` | root of the SHA-256 Merkle tree over `leaf_i = SHA-256(0x00 ‖ salt_i ‖ LE64(i) ‖ byte_i)` and `node = SHA-256(0x01 ‖ left ‖ right)`, RFC-6962 promotion | `src/content/fine_tree/build.rs` (`FineRoot`, `leaf_hash`, `node_hash`, `rfc6962_split`) |
| `work_id` | `SHA-256(manifest body bytes)` — bare, no tag | `src/manifest/ids.rs::work_id` |
| `anchor_digest` | `SHA-256(full plaintext manifest envelope bytes, signatures included)` — bare, no tag | `src/manifest/ids.rs::anchor_digest` |

Every *tagged* preimage routes through the single helper
`src/crypto/domain.rs::tagged_sha256`, so the domain tag is structurally the
first preimage byte; no other module may hard-code a tag byte, and a
grep-enforced test in that module (`no_other_module_hardcodes_domain_tag_bytes`)
keeps it honest. `work_id` and `anchor_digest` carry **no** tag: they hash raw
deterministic-CBOR bytes and are domain-separated by construction, because a
top-level CBOR map/bstr header is always `> MAX_DOMAIN_TAG` (`0x06`) — F
asserts that disjointness on every encoded manifest/body golden vector.
`work_id` and `anchor_digest` are also kept lexically distinct by the
repo-wide identifier ban on `manifest_hash`
(`crates/antseal-core/tests/identifier_bans.rs`), because collapsing the two
would unbind anchors from the bytes they were computed over (spec line 75);
they are separate non-inter-convertible newtypes (`WorkId`, `AnchorDigest`)
for the same reason, and `digests_are_bare_sha256_of_their_input` in
`src/manifest/ids.rs` pins that neither grows a prefix.

**What breaks if it is false.** The permanent sealer-equivocation bound.
A collision lets a sealer open one anchored commitment to two different
contents — the single failure that no downstream check can catch, because
both openings are honest-looking. This is why `fine_root` is the *sole*
content commitment for fine-tree-covered bytes (spec line 96): one
authoritative value per byte, so a per-unit reveal and a v1.1 byte-range
reveal of the same `work_id` cannot disagree.

**No hash agility.** There is exactly one hash function in the format. No
algorithm identifier accompanies any commitment, and none is parsed. This
is deliberate: an agility field is a downgrade surface, and a v1 verifier
that must interpret it is a v1 verifier that can be told to accept less.
The escape hatch is the **format-version hook**: the manifest body carries
`format_version` (`FORMAT_VERSION_V1`, `src/manifest/registry.rs`) and the
decoder hard-rejects any other value at parse time. A wider hash therefore
arrives as a new format version verified by new code, never as a negotiated
parameter inside v1.

### 2. Hiding — random-oracle-model salted SHA-256 with a 128-bit secret salt

**Assumption.** SHA-256 behaves as a random oracle for the secret-prefix
construction `H(tag ‖ salt ‖ message)` with a secret, uniformly random,
128-bit `salt`.

This is **not** implied by collision resistance, and it is the one place the
design leaves the standard model. A SHA-256 that were collision-resistant
but not a PRF would keep every binding claim in class 1 intact and break
every hiding claim here. Stated separately for exactly that reason.

**What it hides.** Confirmation-attack resistance for all committed content
an adversary can *guess*: paragraphs of prose, contract clauses, filenames,
and — the extreme case — the single-byte leaves of the fine tree, whose
message space is 256 values. A bare `H(m)` is binding but not hiding
whenever `m` is guessable; the adversary computes `H(m*)` for the candidate
they already had in mind and compares. Nothing is brute-forced. Salting
raises the cost to guessing the salt as well: 2^128 work per candidate
message.

Salts are per-unit and per-file and derive from the vault-held `W` through
label-separated HKDF (`src/crypto/hkdf.rs`): `unit_salt = HKDF(W,
"unit-salt", unit_id)`, `path_salt = HKDF(W, "path-salt", file_id)`,
`file_salt = HKDF(W, "file-salt", file_id)`. The two per-file salts are
independent by label so that disclosing a file's *path* never compromises
its *content* commitments (spec line 95).

**This claim is executable, not prose.** `src/crypto/confirmation_attack.rs`
(C19) contains no code — it contains two attacks, and both run as doc-tests
on every `cargo test`:

1. the **unsalted-unit** variant, where the attacker holds only the manifest
   and confirms an unrevealed unit's exact contents against a deliberately
   unsalted toy `SHA-256(0x02 ‖ unit_bytes)` at the cost of four hashes —
   and fails against the production `unit_commit`;
2. the **unsalted-file-hash** variant, the sharper one, where the attacker is
   a legitimate recipient of a *one-unit partial reveal*: because
   `canon_commit`/`raw_commit` sit in the manifest embedded in **every**
   bundle, an unsalted `canon_commit` is an offline whole-document
   confirmation oracle. Against the production construction it is inert,
   because `file_salt` is structurally unobtainable on a partial reveal.

Those doc-tests are the executable form of this section. If the hiding
claim ever stops holding for the shipped constructions, they fail loudly.
The disclosure-side counterpart is enforced by the type system rather than
by a test (C7, `src/crypto/disclosure.rs`): `FileSalt` has no public byte
accessor, `PartialRevealDisclosure` has no `file_salt` field, and the only
public byte path is `FullFileRevealDisclosure::file_salt_bytes`, reachable
only through a `FullFileRevealContext` that has attested full coverage of
the file's non-mirror units — where the content is shown anyway, so the salt
discloses nothing.

**Multi-target erosion.** Hiding degrades to roughly `2^128 / K` against an
adversary attacking `K` exposed commitments simultaneously (one salt search
amortised across all targets). With 128-bit salts this is a comfortable
margin at every realistic `K`: even `K = 2^40` exposed commitments leaves
2^88. **128-bit salts are the intended margin**, chosen with this erosion
in mind, and `Salt16::LEN * 8 == 128` is asserted inside the C19 doc-test so
the margin cannot be silently narrowed.

**What breaks if it is false.** Selective disclosure. Every partial reveal
becomes a full disclosure of the guessable parts of the work, which is the
one property the product exists to provide.

### 3. GGM range/leaf hiding — SHA-256 as a length-doubling PRG

**Assumption.** SHA-256 is a secure length-doubling PRG on the fixed 34-byte
single-block input `0x06 ‖ seed ‖ b`, where `seed` is 32 secret bytes and
`b ∈ {0x00, 0x01}` selects the child. Equivalently: SHA-256 as a random
oracle. This is the same message-keyed-PRF assumption class that XMSS and
SPHINCS+ make of their tweakable hashes.

The GGM salt tree is a complete binary tree of depth `d = ⌈log₂ n⌉` over the
file's `n` leaves, rooted at `s_root = HKDF(W, "fine-seed", file_id)`, with
children `s_{v‖b} = SHA-256(0x06 ‖ s_v ‖ b)` and leaf `i` reached from the
root by the bits of `i` MSB-first. `salt_i` is the leaf seed truncated to
16 bytes; content leaves are `leaf_i = SHA-256(0x00 ‖ salt_i ‖ LE64(i) ‖
byte_i)`. The tag `0x06` is `TAG_GGM_SALT_CHILD` in
`src/crypto/domain.rs`; the trailing `b` is preimage *data*, not a second
tag — only the first preimage byte carries domain meaning. The whole
assumption is loaded onto **one function**,
`src/content/ggm.rs::child_seed`, which is the module's single hash
primitive and the only place a child seed is ever derived.

**Length extension is inapplicable.** SHA-256's Merkle–Damgård length-extension
weakness lets an attacker who knows `H(x)` and `len(x)` compute `H(x ‖ pad ‖
y)`. No construction in this format is vulnerable, because no SHA-256 output
here is used as a keyed-prefix MAC over attacker-extendable data:

- the GGM child preimage is **fixed-length** (34 bytes, one compression-function
  block including padding) with the variable part in the middle, not at the end;
- fine-tree leaf and node preimages are fixed-length (`0x00 ‖ 16 ‖ 8 ‖ 1` and
  `0x01 ‖ 32 ‖ 32`);
- the four commitment preimages end in attacker-relevant data, but their
  outputs are only ever **equality-compared** against a signed, anchored
  value — never used as a secret prefix whose extension would be accepted.

An extension of `unit_commit` is not a valid `unit_commit` of anything the
verifier will check.

**Puncturing soundness rests on the leaf-exact-cover / no-ancestor-seed
rule.** A GGM cover is sound as a *puncturable* PRF only if the seeds that
leave the vault span exactly the revealed leaves. A merely-valid dyadic
cover whose node spans an unrevealed real leaf `j < n` would disclose
`salt_j` and reopen the per-byte confirmation attack of class 2 — against a
single byte, whose message space is 256 values, i.e. total disclosure of
that byte. So the normative rule is:

> The cover MUST be leaf-exact (deepest single-leaf nodes at the range
> boundaries), and **no seed that is an ancestor of any unrevealed leaf ever
> leaves the vault**.

That includes `s_root` itself, which is the ancestor of every leaf: it is
conveyed only on a **full-file** reveal, where every leaf is revealed and the
verifier recomputes `fine_root` from the revealed bytes outright.

**The rule is enforced twice, in opposite directions.**

*By construction, on the prover side (G11).* It is a property of the type
system, not of a runtime check. In
`src/content/fine_tree/cover.rs`: `LeafExactCover` has **no public
constructor**; `minimal_cover(range, leaf_count)` is its only producer and
emits a node only when that node's *real*-leaf span lies wholly inside the
revealed range; and `cover_seeds(&s_root, &cover)` — **the only function in
the crate that turns cover nodes into disclosable seeds** — accepts a
`&LeafExactCover` and nothing else. "Ask the vault for an ancestor seed" is
therefore not a call anybody can write. Cover depth is *derived* from
`leaf_count` rather than passed in, so an inconsistent `(n, d)` pair is
unrepresentable too. The `s_root`-iff-full-reveal rule is not a separate
check but a consequence of the same construction:
`LeafExactCover::releases_s_root()` is true exactly when the cover is the
single root node, which happens exactly when the range is `[0, n)`.
The companion witness on the other axis is `CoveredUnit::of`
(`src/content/fine_tree/proof.rs`), which makes `prove_unit` uncallable for
a raw-mirror or `--no-fine-tree` unit.

*By rejection, on the verifier side (G13).* A bundle is adversarial input,
so unrepresentability at the prover buys nothing there.
`verify_range` / `check_cover` in `src/content/fine_tree/verify.rs`
**recompute** the canonical cover from `(range, n)` and require equality with
the offered one, rather than validating what was offered; a node whose real
span exceeds the revealed range is `FineTreeError::OverBroadCover`, which
carries its own permanent error code `fine-root-over-broad-cover` and its own
tamper row, and is marked in the source as having to stay distinct forever.
Over-broadness is classified **before** structural faults in the frozen error
precedence, precisely so that the disclosure-bearing failure can never be
masked by a cheaper one. Executed by `adversarial_over_broad_cover`,
`s_root_never_opens_a_partial_range` and
`ancestors_of_cover_nodes_are_always_over_broad` (every strict ancestor
substitution rejected), with `a_valid_but_non_canonical_cover_is_still_refused`
guarding the anti-relaxation direction: even a leaf-exact cover that
discloses *less* than the canonical one is refused, because "sound" is not
the acceptance criterion — "canonical" is. The n=6-reveal-{2} case the spec
names (line 153) is pinned at unit level by
`n6_reveal_leaf_2_is_a_single_deepest_node`, and the general soundness
property — the derivable real-leaf closure of a cover equals the revealed
range exactly — by the proptest
`cover_is_bounded_complete_sound_and_root_iff_full`.

*And once more at bundle level (R).* `src/verify/file_stages.rs` rejects a
bundled `s_root` for a file that is not fully revealed
(`VerifyError::PartialRevealSaltLeak { material: FullRevealMaterial::SRoot }`),
so the rule holds even against a bundle assembled by hand rather than by the
sealer.

Two decisions complete the shape. **D75** requires a full reveal to carry
*both* per-unit covers and `s_root`, with the two routes required to agree,
so `s_root` is defence-in-depth rather than a second, softer path. **D74**
rejects an *extraneous* `s_root` on a file with no fine tree, closing the
rule in the unexpected-material direction — adding material fires too, not
only removing it.

**What breaks if it is false.** Per-byte hiding of unrevealed bytes inside a
file that has any revealed range — i.e. range reveals stop being selective.
Binding is unaffected: `fine_root` is still a SHA-256 Merkle root and class 1
still holds.

### 4. AEAD is confidentiality-only and non-committing

**Assumption.** XChaCha20-Poly1305 provides confidentiality and ciphertext
integrity under a fresh key/nonce pair. It is **not** key-committing: it is
computationally feasible to construct a single ciphertext that decrypts
successfully under two different keys to two different plaintexts
(invisible-salamanders / partitioning class). We assume nothing to the
contrary and rely on nothing to the contrary.

**Why that is acceptable here.** **No verdict-bearing check relies on a
ciphertext decrypting to a unique plaintext.** All content and identity
binding is carried by the salted SHA-256 commitments (class 1) and the
author signatures (class 5):

- a revealed unit's content is bound by `unit_commit` or by `fine_root`,
  recomputed from the *decrypted bytes* and compared against the signed,
  anchored manifest — a successful decryption that produced different bytes
  fails that comparison;
- the manifest's identity is bound by `work_id`/`anchor_digest` over its
  **plaintext** bytes and by the signatures, never by the fact that the
  network blob decrypted;
- storage-linkage and `--live` bind **ciphertext** bytes (address
  recomputation and byte comparison), not decryption outcomes.

The AEAD's job is to keep the network copy opaque — Autonomi storage is
public, permanent and content-addressed, and the randomized AEAD wrapper is
also what stops upstream's *convergent* self-encryption from turning an
upload into a confirmation oracle (two sealers with identical bytes upload
different ciphertexts).

Corollary on error attribution: `CryptoError::AeadDecryptFailed` is raised
on any authentication failure — wrong key, wrong `W`, wrong nonce, wrong AAD
component, or tampered ciphertext. The AEAD cannot distinguish these and
**must not be asked to**; a check that tried to attribute a decrypt failure
to a specific cause would be relying on properties Poly1305 does not offer.
Attribution is the commitments' job, and it happens after a successful
decryption, not instead of one. The C8 padding rejections
(`PaddingLengthMismatch`, `NonZeroPadding`) run strictly after successful
AEAD verification, which is what keeps those failure classes structurally
distinct in the tamper matrix.

**The frozen rule.**

> **A future refactor MUST NOT drop a content commitment in favor of
> trusting the AEAD.**

That sentence is not only recorded here. It is embedded verbatim as a module
doc comment in both AEAD modules — `src/crypto/unit_aead.rs` and
`src/crypto/manifest_aead.rs` — where a developer contemplating exactly that
refactor will read it, and its presence in both is machine-checked by
`crates/antseal-core/tests/security_assumptions_drift.rs`.

**What breaks if it is false — that is, if the rule is ignored.** A sealer
could produce one stored ciphertext and two bundles opening it to two
different "revealed" contents, both verifying. The commitments are what make
that impossible; the AEAD never was.

### 5. Signature unforgeability — strict Ed25519 + ML-DSA-65, hybrid, non-downgradable

**Assumption.** Ed25519 with *strict* verification is SUF-CMA
(strong existential unforgeability under chosen-message attack), and
ML-DSA-65 is unforgeable at its FIPS 204 category-3 level. The hybrid
requires **both**: an adversary must break both to forge an author
signature.

Plain Ed25519 is only EUF-CMA, not SUF-CMA — it is malleable, and a
non-strict verifier accepts multiple distinct signature encodings on one
message. That is why strictness is a **conformance requirement for every
verifier** (CLI, WASM page, third parties), not an implementation
preference: two verifiers that disagree about the same frozen bundle are a
worse failure than either verdict alone. Implemented in
`src/crypto/sig_ed25519.rs` as RFC 8032 `verify_strict` *plus* an explicit
pre-validation layer (decision **D16**): `scalar_is_canonical` rejects
`S ≥ L`, and `point_encoding_is_canonical` closes the ZIP-215 pubkey gap by
decompress-recompress-compare on both `A` and `R`. The pre-validation exists
because the pinned `ed25519-dalek` reports those rejections only from inside
`verify` behind an opaque error, and the tamper matrix requires
`NonCanonicalSignature` to be distinguishable from `SignatureInvalid`.
`src/crypto/sig_mldsa.rs` needs no such layer: FIPS 204 Algorithm 27
`sigDecode` enforces the complete canonical-encoding rule (hint
count/ordering/padding, `z` range), so a decode failure *is* the
non-canonical verdict.

Both halves bind the same frozen context string
`"antseal-manifest-v1"` (`SIG_CONTEXT`, `src/crypto.rs`), each the way its
own standard prescribes: Ed25519 folds it into the pre-image as
`ctx ‖ 0x00 ‖ body`, ML-DSA-65 passes it as the FIPS 204 `ctx` parameter.
A signature therefore cannot be lifted into another context. Signing keys
derive from `W` under independent HKDF labels (`"sig-ed25519"`,
`"sig-mldsa65"`) and are per-work by construction.

**Hybrid means both, enforced as a set equality.** `sig_policy` is an
ordered list of registered algorithm ids living **inside the signed body**.
It must be non-empty, duplicate-free and registered-only (rejected at parse
time otherwise, so a signature-less manifest can never verify vacuously),
and at verify time the **present signature set MUST equal the policy set**:
every listed signature is validated, and a missing, invalid, *or
present-but-unlisted* signature is a hard failure. A hybrid manifest
therefore never passes on one good signature. Registered ids (decision
**D17**, ratified by C14): `0 = ed25519`, `1 = ml-dsa-65`, `2–15` reserved.
Ed25519 is id 0 because the reserved fallback policy is `[0]`.
`src/crypto/sig_policy.rs` owns the semantic registry and
`src/manifest/registry.rs` the wire registry; the test
`crypto_and_manifest_registries_agree` pins the two together so they cannot
drift.

**Non-downgradability.** Because the policy sits inside the signed body, and
the body is what `work_id` and `anchor_digest` are computed over, stripping
ML-DSA from an existing hybrid manifest changes the body bytes and breaks
*both* signatures — and, once anchored, the anchors too. A fresh
Ed25519-only forgery is therefore a *different* body, hence a different
`work_id` with its own, necessarily later, timestamps: a new work, never a
downgrade of the original. This is executed by the test
`downgrading_a_hybrid_policy_breaks_both_signatures` in
`src/crypto/sig_policy.rs`, which strips ML-DSA from a policy embedded in
its own signed body and asserts that the retained Ed25519 signature fails.
The verification result carries `PolicyLabel` (`Hybrid` / `Ed25519Only` /
`Other`) so the verdict wording "hybrid (PQ)" versus "Ed25519-only" is
derived from what was actually verified, never declared.

**What breaks if it is false.** Authorship binding. Note the asymmetry the
hybrid buys: a future break of Ed25519 alone does not forge an antseal
manifest, and a break of ML-DSA-65 alone does not either. Both must fall.

### What is deliberately *not* assumed

- **Autonomi availability or honesty.** `.sealproof` bundles are
  self-contained; verification succeeds fully offline. Evidence validity
  never depends on the network being reachable, and the network is never
  trusted for time.
- **Timestamp-authority honesty, singly.** Time comes from independent
  anchors (OpenTimestamps → Bitcoin, ≥2 RFC 3161 TSAs, plus the Arbitrum
  receipt as supporting evidence only). No single anchor is load-bearing.
- **Anything about the verifier's host.** The WASM verifier is a static
  page; see the threat-model section on a malicious verifier host, and the
  zeroization caveat in C21's appendix.
<!-- END frozen-security-assumptions -->

---

# 2. Threat sections (M4 — stubs)

Each section below is **not yet written**. The scope line says what belongs
in it, so a later author is filling a defined hole rather than inventing the
shape. Numbering is stable: cite these as `threat-model §2.N`.

## 2.1 Vault theft

*Scope.* The `~/.antseal/` vault holds `W`, from which every key, salt and
seed for every work derives. A stolen vault plus a broken passphrase
retroactively and permanently decrypts ciphertexts that are public and
undeletable, with **no possible rotation**. Must cover: the Argon2id
parameter floor and why the whole KDF header is bound in as AEAD AAD (a
parameter downgrade must be an authentication failure, not a silent
weakening); the separate sub-key for the Arbitrum wallet key; keyfile /
OS-keystore wrapping; what the attacker gets per work and across works; and
the honest statement that there is no recovery once this happens.

*Status:* not written — M4 (Q21).

## 2.2 Vault loss

*Scope.* The mirror-image failure, and the one users will actually hit. Lose
the vault and its backup and you permanently lose the ability to reveal or
restore — while the sealed data itself stays safely unreadable *forever*.
Must cover: `vault export`/`import`, the disk-loss restore drill, and why
the CLI and docs nag on both loss and theft rather than only theft.

*Status:* not written — M4 (Q21).

## 2.3 Wallet linkability

*Scope.* Payment happens from an Arbitrum wallet, and the receipt names it.
Including a receipt in a bundle (`reveal --include-receipt`, opt-in) exposes
the paying wallet and thereby links every seal that wallet ever paid for.
Must cover: what an observer learns from the chain without any bundle at
all; what the opt-in adds; funding hygiene; and whether "supporting evidence
— no independently proven time" is worth that linkage to a given user.

*Status:* not written — M4 (Q21).

## 2.4 Malicious verifier host

*Scope.* The WASM verifier is a static page served from a host that could
serve something else. A hostile page can render any verdict it likes for any
bundle. Must cover: the reproducible build plus published hash plus canonical
URL as the mitigation; why an independent CLI verify is always available and
is the real answer; and the limits of what a page can promise about itself.

*Status:* not written — M4 (Q21).

## 2.5 Coercion / compelled disclosure

*Scope.* An adversary who can compel the holder. Must cover: what a
compelled passphrase yields (everything, retroactively — see §2.1); the fact
that selective disclosure protects against *recipients*, not against
*compulsion*; the absence of any deniability feature and why none is claimed;
and the interaction with §2.2 (a destroyed vault is unrecoverable, which cuts
both ways).

*Status:* not written — M4 (Q21).

## 2.6 Hostile bundles

*Scope.* A `.sealproof` is wholly attacker-controlled input, and the verifier
is the one component that must never panic, hang or over-allocate on it.
Must cover: the strict CBOR profile and parser caps; the tamper matrix as the
evidence that every mutation fails with a *distinct* error; the fuzz targets;
the over-broad-cover and partial-reveal-salt-leak rejections; and the
"internally consistent only" verdict class for a bundle whose chain closes
only against material the bundle itself supplied.

*Status:* not written — M4 (Q21).

## 2.7 Sealer as adversary

*Scope.* The bundle recipient's threat model. A sealer chooses what to
reveal, and the interesting attacks are equivocation (opening one anchored
commitment two ways — see §1 class 1) and out-of-context partial reveal
(showing a true fragment that misleads). Must cover: single-authoritative-
commitment (`fine_root` as the sole content commitment for covered bytes);
the anti-downgrade property of the signed policy; and the rendering
guardrails — every reveal displays position and total size, unrevealed units
render as sized blackout blocks, unrevealed files as committed placeholders.

*Status:* not written — M4 (Q21).

## 2.8 Size fingerprint

*Scope.* What structure metadata leaks even when content does not. Bundle
recipients see file count, sizes and unit boundaries; the network sees
padded ciphertext lengths. Must cover: the 256-byte padding bucket and what
it does and does not blur; what a size histogram identifies (a known
document, a known template); and the deliberate decision that structure is
visible, which docs must state plainly.

*Status:* not written — M4 (Q21).

## 2.9 Evidence independence

*Scope.* Why no single anchor is load-bearing. Must cover: OTS→Bitcoin
(offline `attested`, online-gated to `proven`, and why a lone embedded
header proves nothing offline); ≥2 RFC 3161 TSAs verified against a pinned
root store with genTime-evaluated chain validity; the Arbitrum receipt as
supporting evidence only; and the standing rule that **Autonomi is never
trusted for time** and evidence validity never depends on Autonomi being
reachable.

*Status:* not written — M4 (Q21).

## 2.10 WASM zeroization caveat

**Delivered by C21 (2026-07-28) — this section is written.** The full
per-buffer audit behind it is `docs/zeroization-audit.md`.

### The caveat

> **The WASM verifier cannot guarantee zeroization for bundle-supplied keys
> (`k_u`, `k_m`, salts) in browser memory.**

This is normative (MVP-SPEC.md line 143) and is also carried as a doc comment
on the crypto module root, `crates/antseal-core/src/crypto.rs`.

### Why not

Every secret-bearing type this crate *defines* is `ZeroizeOnDrop`, and those
impls run under `wasm32` exactly as they do natively: the writes are volatile
and cannot be optimised away. Third-party hasher state is wiped too, but by a
different mechanism — ordinary drop glue gated on `sha2`'s non-default
`zeroize` feature, **not** a `ZeroizeOnDrop` bound ([D88](decisions/D88-hkdf-hmac-zeroization.md);
`docs/zeroization-audit.md` R1). Two documented exceptions remain by design:
`PartialRevealDisclosure`'s growing `Vec` (audit R2) and a handful of
`Drop`-less stack temporaries inside `hkdf`/`hmac` (audit R1's narrowed
residue).

None of that is the point of this section, because all of it is a promise
about **one linear-memory allocation**, not about the machine underneath it.
Outside that allocation the runtime does things Rust cannot see or undo:

- the bundle bytes were almost certainly copied into engine-owned buffers
  before they ever reached linear memory — a `fetch` response, a `File` read,
  the source `ArrayBuffer`, string intermediates — and those copies are
  garbage-collected, not wiped;
- `memory.grow` may relocate the entire WebAssembly memory, leaving the old
  region intact and unreachable;
- the browser may swap the tab's pages, snapshot them for session restore, or
  hand them to a crash reporter.

None of this is reachable from the Rust side, so no amount of care inside
`antseal-core` closes it.

### Why it is bounded

- The keys in question open **exactly the content the bundle already contains
  in the clear**. A verifier that has been given `k_u` for a revealed unit has
  also been given that unit's plaintext; retaining the key discloses nothing
  the page was not shown.
- **`W` never reaches a browser at all.** The verifier holds bundle-supplied
  keys only — never the master secret — so the retroactive, unrotatable
  compromise of §2.1 cannot originate here.

### Practical guidance (for the docs at M4)

Treat a browser that has verified a bundle as having **retained that bundle's
`k_u`/`k_m`/salts until the tab is closed**. For a reveal whose contents are
sensitive to the point that the receiving machine matters, use the CLI
verifier, which runs in a process whose memory the OS reclaims on exit and
whose zeroization is real.

*Status:* written (C21). Cross-check at M4 (Q21) once the verifier page
exists, in case the shipped page adds handling that widens the exposure.

---

## Related records

- `docs/security-assumptions.md` — C20, the source of truth for section 1.
- `docs/decisions/` — the decision register (D74/D75 GGM cover shape,
  D13/D14/D15 signature pins and signing mode, D16/D17 signature policy).
- `docs/format/registry-v1.md` — the wire format these assumptions apply to.
- `docs/testing/error-code-contract.md` — the permanent error codes the
  tamper matrix binds to.
