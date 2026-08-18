# antseal threat model

**Status: FINALIZED (M4, task Q21, 2026-08-17).** The document was created at
M0 (Q12) as a frozen assumptions block plus a numbered set of stubs, so that
the freeze happened against a known map rather than a blank page and nothing
on the list could be quietly forgotten between M0 and M4. Section 2 is now
written: §2.10 by C21 at M0, §2.1–§2.9 by Q21 at M4, each to the scope line
its M0 stub declared. Section 3 maps every row of MVP-SPEC.md's *Risks &
mitigations* onto a section here or onto the user-facing page that owns it.

Read section 1 as normative and section 2 as analysis. Section 2 is **not**
frozen: it may be corrected without a format event, which is exactly what
distinguishes it from section 1.

**This is an engineering document.** The user-facing prose lives under
`docs/user/`; where a topic belongs to a reader rather than to a maintainer,
the section here says so and names the page (D139 §2 R2/R10). Positioning
discipline binds both: possession, never authorship, and the limits stated
rather than implied.

## Positioning

antseal proves **existence, integrity and priority** of data you possessed.
It is **not** a legal notary, and it does not prove authorship — only that
the sealed bytes existed, unaltered, before a provable time. The priority
claim is qualified, and the qualification is the spec's own (MVP-SPEC.md line
28): an earlier seal by someone who received your work **outranks** yours, so
**seal before you share**. Every threat below is scoped to that claim.

## Sign-off record

| What | Status | Signed off by | Date |
| --- | --- | --- | --- |
| Frozen security assumptions (section 1) | **FROZEN** — the five assumption classes the `.sealproof` format permanently rests on, authored by C20 against the implemented `antseal-core::crypto` tree | `aed900` | 2026-07-28 |
| Threat section §2.10 (WASM zeroization) | **WRITTEN** — C21, against `docs/zeroization-audit.md`; re-checked against the shipped verifier page at M4 (§2.10, closing note) | — | 2026-07-28 |
| Threat sections §2.1–§2.9 | **WRITTEN** — Q21, each to its M0 scope line; section 2 carries no sign-off and is **not** frozen | — | 2026-08-17 |

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

# 2. Threat sections

Numbering is stable: cite these as `threat-model §2.N`. The ten headings are
enumerated by `every_m4_threat_section_is_enumerated`
(`crates/antseal-core/tests/security_assumptions_drift.rs:272-315`), so a
section cannot be deleted quietly.

**Each section keeps its `*Scope.*` paragraph, which is the M0 contract it
was written against.** Q12 wrote those lines before the work existed, so that
a later author would fill a defined hole rather than invent a shape; keeping
them lets a reader check the delivery against the brief instead of taking the
delivery's word for it. Where the shipped tree turned out to differ from a
scope line, the section says so under a heading that begins **"Correction to
this section's M0 scope line"** rather than departing silently. There are
three such corrections, in §2.1 (twice) and §2.9 (once).

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

**Why this is the worst failure in the product.** Autonomi storage is
pay-once and permanent, so every ciphertext antseal has uploaded is still
there and always will be. Confidentiality rests entirely on the passphrase,
forever and in retrospect: an attacker who takes the vault today and breaks
the passphrase in five years decrypts everything sealed before today. There
is no expiry, no re-key, nothing to revoke. The code states it in the same
words the docs do, where a maintainer will meet it —
`crates/antseal-cli/src/vault/bookkeeping.rs:76` (*"The ciphertexts are
public and undeletable, and there is no key rotation."*) and
`crates/antseal-core/src/crypto/secrets.rs:48-49`.

**What the attacker gets.** `W` is **per work**, not per vault
(`crates/antseal-cli/src/vault/store.rs:201`, the `WorkRecord`), so the unit
of loss is the vault and the blast radius is *every* work in it:

| taken | what it opens |
| --- | --- |
| one work's `W` | every `k_u` and `k_m`, every `unit_salt`/`path_salt`/`file_salt`, every `s_root` — i.e. every uploaded ciphertext of that work, plus both signing seeds, so new manifests can be forged under that work's identity (label registry: `crates/antseal-core/src/crypto/hkdf.rs:137-146`) |
| the vault | the above for **every** work, plus `config.toml`, the seal journal, receipts, `.ots` and TSA tokens, addresses, paths and costs (`crates/antseal-cli/src/vault/mod.rs:36-44`) |
| a `vault export` file | the same payload again — `crates/antseal-cli/src/vault/export.rs:100`: *"The payload plaintext contains `W` for every work"*. An export is a second copy of the whole blast radius and is protected by the passphrase alone |

The wallet secret is stored beside all of this and is discussed in §2.3.

**The passphrase floor and the KDF.** Argon2id is the default; scrypt is
selectable only by explicit choice at `init`. The parameters are frozen
constants, and the same constants are used to *create* a vault and to
*validate* one on open — `crates/antseal-cli/src/vault/kdf.rs:111`: *"Frozen
Argon2id creation values (D40 §1; also the decode floors)."*

| parameter | value | constant |
| --- | --- | --- |
| Argon2id `m` | 262 144 KiB (256 MiB) | `kdf.rs:112` `ARGON2ID_M_COST_KIB` |
| Argon2id `t` | 3 | `kdf.rs:114` `ARGON2ID_T_COST` |
| Argon2id `p` | 1 (exact match, not a floor) | `kdf.rs:116`, checked at `:300` |
| scrypt `log2 N` | 20 (N = 2²⁰) | `kdf.rs:119` `SCRYPT_LOG2_N` |
| KDF salt | 16 random bytes | `kdf.rs:104` `KDF_SALT_LEN` |

Ceilings exist too (`kdf.rs:126-130`), because an *inflated* parameter in an
adversary-supplied header is a memory bomb rather than a weakening.

**Correction to this section's M0 scope line — the shipped behaviour is
stronger than the scope line describes, and it matters.** The scope line
says a parameter downgrade *"must be an authentication failure, not a silent
weakening"*. It is neither silent nor an authentication failure: a header
whose parameters fall below the floor is rejected **before authentication
and before any allocation**, by `KdfParams::check_ranges`
(`kdf.rs:280`, floor test at `:288`) called from `decode` at `:438`, which
`crates/antseal-cli/src/vault/session.rs:423-427` runs one line ahead of the
key derivation — *"D40 §3: caps inside this decode run before any KDF
allocation."* It carries its own error class, `vault-kdf-params-out-of-range`
(`crates/antseal-cli/src/error.rs:445`, exit 14), so the failure names its
cause instead of collapsing into a generic auth error. The deviation is
recorded at the test that proves it, not only here:
`crates/antseal-cli/tests/vault_encryption.rs:502-503` — *"strictly stronger
than the auth-failure the task text imagined (recorded deviation,
tasks/U.md U6). No path opens a vault with weakened parameters."*
`downgraded_params_are_rejected_pre_auth` (`:505`) rewrites a real vault's
on-disk header with halved `m` and scrypt N = 2¹⁹ and asserts class and exit
code (`:526-527`).

**The AAD binding is still load-bearing, in the direction the caps cannot
reach.** The exact bytes of the vault header — algorithm id, parameters,
salt, wrap mode — are the AEAD's associated data for every vault record:
`RecordIdentity::aad` (`crates/antseal-cli/src/vault/cipher.rs:181`,
consumed at `:254` and `:297`), over the bytes `VaultHeader::encode` returns
(`crates/antseal-cli/src/vault/header.rs:260`, contract at `:46-49`). So a
header edit that stays *inside* the caps — raising `t` from 3 to 4, or
swapping the salt — changes the derived key or the AAD and fails
authentication rather than opening a vault under parameters its owner never
chose. Both directions are executed:
`raised_params_within_caps_fail_authentication`
(`vault_encryption.rs:537-568`, keeps the real salt, raises `t_cost` only,
asserts `VaultAuthFailure`/exit 12) and `flipped_salt_fails_authentication`
(`:574-586`). The pure-AAD axis — KDF inputs held fixed, header bytes edited
— is pinned at the cipher layer by `identity_and_header_axes_all_bind`
(`cipher.rs:352`), which asserts the edited-header open fails at `:392` and
that the untouched slot still opens at `:397`, so the assertion cannot pass
over a vault that opens for nothing.

**Header agility, and what a future format does *not* get to do.** The
vault header carries `VAULT_FORMAT_VERSION = 1` (`header.rs:65`); a *newer*
version is refused before its body is parsed at all (`header.rs:309-311`,
exit 16), which is the same discipline the manifest's `format_version` hook
uses in §1 class 1. The wrap-mode registry is `0 = none`, `1 = keyfile`,
`2 = os-keystore (reserved)` (`header.rs:78-85`); an unregistered id is
refused at `header.rs:346`.

**Correction to this section's M0 scope line, second item: only the keyfile
half of *"keyfile / OS-keystore wrapping"* ships.** D50
(`decisions/D50-os-keystore-scope.md:3`) resolved that M1 ships the keyfile
wrap only, and mode 2 is registered-but-unimplemented — refused distinctly
at unlock with `VaultWrapModeUnsupported`, exit 19
(`session.rs:398-403`; test `crates/antseal-cli/tests/vault_keyfile.rs:217-232`
asserts the class, the exit code, and that the message says the vault is
*intact*). The keyfile is a second factor combined by HKDF, never XOR
(`crates/antseal-cli/src/vault/keyfile.rs:14-16`), it is 32 bytes
(`keyfile.rs:67`), `ANTSEAL_KEYFILE` names a *path* and never a secret
(`keyfile.rs:70`), and a keyfile-wrapped vault is refused by both `vault
export` and `vault import` (`export.rs:745`, `:520`) so that the second
factor cannot be silently dropped by a backup. D50 also gives the reason a
keystore is not treated as a wrap here: a reboot-volatile store holding the
sole copy of a wrap factor, for a vault whose theft model is *no rotation,
ever*, is a time bomb (`D50-os-keystore-scope.md:54-56`).

**The wallet sub-key decouples record compromise, and does not decouple
passphrase compromise.** `MVP-SPEC.md` line 143 requires the Arbitrum wallet
key to live inside the vault *"under its own sub-key"*, and it does:
`wallet_subkey = HKDF-SHA256(salt = "", ikm = vault key, info = "antseal-cli
vault v1: wallet record sub-key")`
(`crates/antseal-cli/src/vault/wallet.rs:9-12`, label at `:56`, derivation at
`session.rs:154-163`). Two precisions the phrase *"sub-key"* invites a reader
to get wrong:

- the wallet secret is **not derived from `W`** and is not derived from
  anything. It is a fresh 32-byte CSPRNG key, or a raw hex key the user
  imported (`crates/antseal-cli/src/init.rs:497-513`);
- the sub-key is a sub-key of the **vault key**, so it protects the wallet
  record against a compromise of *another* record's key, not against the
  passphrase. A thief who breaks the passphrase derives the vault key and
  therefore the sub-key. `wallet_record_opens_only_under_the_sub_key`
  (`wallet.rs:202-222`) proves the first half by forging a blob under the
  main vault key with the same identity and asserting it fails to open.

**There is no recovery, and there is no rotation. Both were measured, not
assumed.** Searched: `rotat` across `crates/**/*.rs` returns 26 hits and not
one of them is a rotation mechanism — they are the anchor-poll candidate
rotation, TSA signing-key rotation as a *verifier's* concern, test-fixture
bookkeeping, and prose asserting this absence. `re-encrypt|rekey|rewrap` and
their spellings return test harnesses, verifier prose, and explicit refusals
(`crates/antseal-core/src/crypto/unit_aead.rs:28`,
`crates/antseal-cli/src/seal_resume.rs:108`). The frozen CLI surface has nine
commands and none of them is `rotate`, `passwd` or `change-passphrase`
(`crates/antseal-cli/tests/snapshots/cli-surface.help.txt:7-15`). The one
re-encryption that exists is `vault import`, which builds a **new** vault
with a fresh salt and re-encrypts every *local* record (`export.rs:130-131`);
it does not touch `W`, and nothing can touch what is already uploaded.

**What the product does about it.** It nags, loudly, on first seal, and the
nag is the only mitigation available at this layer: `export_nag`
(`crates/antseal-cli/src/seal_run.rs:110`, computed at `:498`, rendered at
`:142-144`), whose copy opens *"NO BACKUP YET — this vault has never been
exported."* (`crates/antseal-cli/src/vault/bookkeeping.rs:257-259`) and
carries both the loss and the theft warning (`:68`, `:74`).
`the_first_seal_nags_about_the_missing_backup_and_a_recorded_export_stops_it`
(`crates/antseal-cli/tests/seal_command.rs:950-1027`) asserts the nag fires,
asserts the exact strings, then records an export and asserts the nag stops —
both directions, so a nag that could never fire would fail the test.

**Delegated.** The user-facing page is `docs/user/vault-theft.md` (Q24): what
a strong passphrase means here, why an export is a long-term high-value key,
and what to do if a laptop is stolen. This section is the engineering
account; that page is the one a user reads.

## 2.2 Vault loss

*Scope.* The mirror-image failure, and the one users will actually hit. Lose
the vault and its backup and you permanently lose the ability to reveal or
restore — while the sealed data itself stays safely unreadable *forever*.
Must cover: `vault export`/`import`, the disk-loss restore drill, and why
the CLI and docs nag on both loss and theft rather than only theft.

**Loss is not the inverse of theft; it is a different loss.** Theft costs
confidentiality forever. Loss costs *capability* forever and costs
confidentiality nothing — the uploaded ciphertexts stay exactly as opaque as
they were, because the keys that would open them are gone with the vault.
A user who loses everything has an unreadable permanent archive, which is
strictly better than the alternative and is worth saying out loud.

**What survives a lost vault, and this is the part users do not expect.**
Every `.sealproof` bundle already produced still verifies, forever, offline,
by anybody. Bundles are self-contained by construction — §1's *"What is
deliberately not assumed"* states it, and it is why evidence validity never
depended on the vault or on Autonomi. Losing the vault destroys the ability
to make *new* reveals; it destroys no evidence already handed to a
counterparty, and it does not weaken a verdict anyone has already been shown.

**What is lost.** Reveal and restore, both, permanently:

- **reveal** needs `W` for the unit keys, the per-unit and per-file salts and
  the GGM seeds. Without them a partial reveal cannot be assembled at all;
- **restore** needs `W` to decrypt the uploaded units and the manifest. The
  manifest is itself uploaded encrypted (spec line 91), so the index of a
  work's own chunks is unreadable too — there is nothing to enumerate;
- both signing seeds derive from `W` (`crates/antseal-core/src/crypto/hkdf.rs:137-146`),
  so the work's identity cannot be re-signed either.

**The backup mechanism, precisely.** Two commands, no flags at all —
`antseal vault export [FILE]` and `antseal vault import <FILE>`
(`crates/antseal-cli/src/cli.rs:454`, `:462`; the frozen surface snapshot
`crates/antseal-cli/tests/snapshots/cli-surface.help.txt:357` and `:384`
carries only the three global options). The design note at `cli.rs:449` is
the whole product decision: *"single re-encrypted file, no flags (D47)"*.

- **The export is encrypted, under its own fresh salt.** One AEAD over the
  whole payload, key derived from the passphrase against a KDF block with a
  **new** salt rather than the vault's (`crates/antseal-cli/src/vault/export.rs:15-17`,
  fresh salt at `:866`), magic `ANTSEAL VAULT EXPORT` (`:177`), format
  version 1 (`:182`), extension `.sealvault` (`:185`), 1 GiB read cap
  (`:192`).
- **It contains `W` for every work** (`export.rs:64-95`, stated at `:100`) —
  which is exactly why §2.1 treats an export as a second copy of the vault's
  entire blast radius rather than as a mere backup.
- **The export self-verifies before it is named.** The engine decodes and
  opens what it just wrote and only then renames it into place
  (`export.rs:104-118`, `export_vault` at `:838`) — an export that would not
  have imported is not left on disk looking like a backup.
- **The import builds a new vault**, fresh salt, fresh vault key, every local
  record re-encrypted (`export.rs:130-131`, `import_vault` at `:1015`).
- **A keyfile-wrapped vault is refused in both directions** (`export.rs:745`
  and `:520`, both `CliError::Usage`, message *"nothing was written"*), so a
  backup can never silently discard the second factor. Verified end to end by
  `a_wrapped_vault_is_refused_by_export_and_a_wrapped_payload_by_import`
  (`crates/antseal-cli/tests/vault_keyfile.rs:328-357`), which asserts the
  error class **and** that no output file exists afterwards.

**The nag, and why it nags on both failure modes.** The first-seal nag
(§2.1) carries `LOSS_WARNING` *and* `THEFT_WARNING`
(`crates/antseal-cli/src/vault/bookkeeping.rs:68`, `:74`), and it is
recorded as satisfied only after an export has been written *and*
self-verified (`crates/antseal-cli/src/commands.rs:806-810`). The reason to
nag on both is that the two mitigations pull in opposite directions: the
answer to loss is *make more copies*, and the answer to theft is *make
fewer*. A user told only about theft keeps no backup and loses everything to
a dead disk; a user told only about loss scatters copies of a file that
retroactively decrypts a permanent public archive. Only stating both makes
the trade visible, which is why `MVP-SPEC.md` line 143 requires the CLI and
the docs to carry both and not one.

**The drill is a gate item, not a claim made here.** The disk-loss restore
drill is executed at the M4 gate (spec line 157; Q34's `Do` and its
evidence-bundle Accept row). This section records that the mechanism exists
and is tested at unit level; the end-to-end proof that a restore works from
an export alone, on a machine that has never seen the original vault, is
Q34's to produce and to record.

**Delegated.** The user-facing page is `docs/user/vault-loss.md` (Q24): the
export procedure, where to keep the file, how many copies, and the restore
drill written as steps rather than as a mechanism.

## 2.3 Wallet linkability

*Scope.* Payment happens from an Arbitrum wallet, and the receipt names it.
Including a receipt in a bundle (`reveal --include-receipt`, opt-in) exposes
the paying wallet and thereby links every seal that wallet ever paid for.
Must cover: what an observer learns from the chain without any bundle at
all; what the opt-in adds; funding hygiene; and whether
"supporting evidence — no independently proven time" is worth that linkage
to a given user.

### What a chain-only observer learns

A seal's entire public on-chain footprint is one ERC-20 `approve` followed by
`1..n` `payForQuotes(DataPayment[])` calls — one tx in the common case, since
the cap is 256 transfers per tx and one non-zero transfer per blob
(`crates/antseal-net/src/ant_backend.rs:36-40`, `:675-691`).

**Nothing in that calldata says "antseal".** The transfer struct is
upstream's own three fields — `rewardsAddress`, `amount`, `quoteHash`. There
is no memo field, no tag, and antseal deploys no contract on any network
(D73 §3.5.1, `decisions/D73-external-completions-without-telemetry.md:310-312`).
An observer watching `payForQuotes` sees an Autonomi payer, not an antseal
payer.

**The allowance is a different story, and it is an open question this
section records rather than settles.** antseal approves the **exact quoted
total**; upstream approves `U256::MAX`:

| | antseal | upstream |
| --- | --- | --- |
| amount approved | the exact quoted total | `U256::MAX` (unlimited) |
| where | `crates/antseal-net/src/ant_backend.rs:437-455` (`ensure_allowance`), doc comment at `:433-436` — *"never `U256::MAX`"* | `evmlib-0.9.0/src/wallet.rs:421`; `ant-core-0.5.0/src/data/client/payment.rs:130` documents *"Approves `U256::MAX` (unlimited) spending."* |
| how often | before essentially **every** seal | once per address, **ever** |

The frequency difference is the mechanism, and it follows from the amount.
`ensure_allowance` short-circuits when the standing allowance already covers
the total (`ant_backend.rs:446-448`), but an *exact* allowance is consumed by
the very payment it was raised for, so the short-circuit almost never fires.
Both the calldata and the ERC-20 `Approval` event log are public and
permanent. **An address that emits a fresh, non-round `approve` before
essentially every payment is therefore separable from the general Autonomi
payer population** — so the honest answer to this section's own scope
question is: an observer with no bundle at all learns *that this address is
running antseal, or a tool with identical hygiene*.

**This is deliberately left open here.** The behaviour was chosen **for**
wallet hygiene — it leaves no unlimited standing allowance against the
payment vault — and it is defensible on that ground. It also reduces the
anonymity set. D73 established the fingerprint and **explicitly refused to
rule on it** (§6 item 6, `D73-external-completions-without-telemetry.md:743-750`):
the three arms are *unlimited* (costs a standing allowance), *exact* (costs
anonymity) and *rounded-up* (might cost neither, and **nobody has priced
it**). Row **Q240** owns the choice, jointly with Q25. Nothing in this
section chooses, and a reader should not take the description above as an
endorsement of any arm.

**What is missing is a pin, not a description.** Measured: `grep` over
`crates/` for `approve_to_spend_tokens|token_allowance|U256::MAX` returns
four hits, all inside `ant_backend.rs` itself (`:50`, `:435`, `:441`,
`:451`) — **zero test assertions**. A refactor toward upstream's shape, which
is the obvious simplification, would silently destroy a deliberate trade and
no lane would notice. That test is Q240's, against `MockBackend`; no mainnet
spend is needed to prove it.

*(One correction, because the record it comes from is stale about itself:
D73 §3.5.4 says the fingerprint is "documented nowhere as an observability
property". D73 **is** that documentation, and as of this section so is the
threat model. What remains true is that nothing pins it.)*

### What including the receipt adds

The receipt is **excluded from bundles by default**, and the default is
`bool`'s `false` with no `default_value` anywhere — there is no line to get
wrong (`crates/antseal-cli/src/cli.rs:375-377`; the shipped help snapshot
`crates/antseal-cli/tests/snapshots/cli-surface.help.txt:285-286` carries the
same warning to the user). The include branch is a single `if`
(`crates/antseal-cli/src/pipeline/reveal.rs:653-657`), and at format level
*presence is the opt-in*: there is no parse-decidable condition on the
section, its presence **is** the sealer's choice
(`crates/antseal-core/src/bundle/schema.rs:730-733`).

Opting in ships the **whole journaled receipt**, not a summary: the wire
record is `tx_hashes`, `block_number` and an opaque `payload`
(`schema.rs:738-741`) whose payload is the entire `PaymentReceipt`
JSON-encoded (`crates/antseal-cli/src/pipeline/receipt_sink.rs:79-82`).

**No field of it names the payer.** The linkage runs through `tx_hashes`: a
tx hash resolves on any public explorer to the sending address, and from
there to every other seal that address ever paid for. The code says so where
a maintainer would otherwise log one — *"no field of this type may appear in
logs or error messages — receipts are wallet-linkable on a public chain"*
(`crates/antseal-net/src/receipt.rs:156-157`) — and the reveal consent screen
says so to the user before they opt in
(`crates/antseal-cli/src/reveal_consent.rs:131-135`). Secondary linkage
inside the payload: which storage nodes were paid (`rewards_address`), which
peers quoted, and the exact amounts.

Two absences worth stating, because both are checked rather than incidental:

- **No chain identifier rides in the bundle.** The chain is pinned by the
  verifier and is never named by the artifact under inspection
  (`docs/format/registry-v1.md:746`).
- **No time of any kind.** Not the block as a time, not a transaction
  timestamp (`crates/antseal-cli/src/status.rs:217-219`).

The default is proven against produced bundles rather than against the flag:
`include_receipt_embeds_the_recorded_receipt_and_default_omits_it`
(`crates/antseal-cli/tests/reveal_flow.rs:585-628`) seals over `MockBackend`,
reveals with no flag, **decodes the resulting bundle bytes** and asserts
`receipt().is_none()`, then flips the flag and asserts the embedded
`tx_hashes`/`block_number` equal the journaled ones — so the test would fail
if the section were present-but-empty as readily as if the flag were ignored.
`include_receipt_toggles_the_embedded_receipt`
(`crates/antseal-cli/tests/reveal_output.rs:438-479`) repeats it at CLI level
and additionally asserts the default reveal's human output contains no
mention of a wallet at all.

### Funding hygiene, and the affordance that does not exist

**One vault pays with one address, by construction.** The wallet record is a
singleton — `RecordIdentity::Wallet` carries no discriminant, where
`Receipt { seal_id }` does (`crates/antseal-cli/src/vault/cipher.rs:100-118`)
— so every seal in a vault is paid by the same address. The key itself is a
fresh CSPRNG secret or an imported raw hex key
(`crates/antseal-cli/src/init.rs:497-513`), never derived, and the address is
its EIP-55 rendering (`init.rs:523`).

`MVP-SPEC.md` line 185 makes three commitments against this risk. **Two are
implemented and one is not**, and this document should not imply otherwise:

| commitment | state |
| --- | --- |
| receipt excluded from bundles by default | **implemented**, proven above |
| `--include-receipt` to opt in | **implemented** (`cli.rs:375-377`) |
| wallet-hygiene docs (fresh address per work/client) | **docs-only, and there is no CLI affordance behind it** |

Measured: no `seal`-time wallet or address flag exists on the frozen CLI
surface (the only wallet flags are `init`'s `--wallet` and
`--wallet-key-fd`), no config key names a wallet
(`crates/antseal-cli/src/config.rs:8` — preferences only, *"never secrets,
never per-work"*), and there is no rotate/new-wallet command. The only way to
pay a work from a different address today is a **separate vault** via
`ANTSEAL_DIR` (`crates/antseal-cli/src/vault/layout.rs:75-86`), which is a
vault-per-work workaround rather than per-work address support. A user
following the fresh-address advice is running one vault per address, with
one export to look after per vault (§2.2).

**Delegated.** `docs/user/wallet-hygiene.md` (Q25) owns the linkability chain
written for a reader — receipt → wallet → funding route → identity — and the
fresh-address recommendation with the vault-per-address cost stated.
`docs/user/funding-your-wallet.md` (Q23) owns how the address gets ETH and
ANT in the first place, which is where the chain to an identity usually
starts.

### Is the linkage worth what it buys?

For most users, no, and the asymmetry is stark. What the linkage buys is one
display line. The receipt is never headline-eligible and is never an anchor;
its result type carries **no time field and no state field — not a null one,
none** — so the class it renders in is a property of the shape rather than of
a renderer remembering it
(`crates/antseal-core/src/verify/report.rs:743-757`). It renders as
"supporting evidence — no independently proven time"
(`crates/antseal-core/src/verify/wording.rs:392`) over a detail line that
says what it proves and what it does not: *"recorded on Arbitrum block
{block_number} across {transaction_count} transaction(s) — this proves
payment and existence-by-block, never this work's time"* (`wording.rs:403-409`).
What it costs is permanent, public linkage of this work to a wallet and of
that wallet to every seal it ever paid for, to everyone the bundle is ever
shown to.

The case where opting in is defensible is narrow and forward-looking: the
full receipt chain is specced for v1.1 (spec line 110), capture is complete
from day one, and a counterparty who will one day verify that chain needs the
receipt to have been in the bundle. That is a considered choice for a
specific counterparty, and it is the reason the flag exists rather than being
removed.

**The project asks no one for a receipt-bearing bundle, ever.** D73 R10
clause 7 forbids it (`D73-external-completions-without-telemetry.md:664-672`),
and D73 §3.7 gives the reason: asking a participant to include the receipt is
asking them to hand the project a KYC-linkable identifier in exchange for
helping it hit a number. A receipt group that arrives anyway is not read, not
recorded and never quoted (D73 R6.2).

## 2.4 Malicious verifier host

*Scope.* The WASM verifier is a static page served from a host that could
serve something else. A hostile page can render any verdict it likes for any
bundle. Must cover: the reproducible build plus published hash plus canonical
URL as the mitigation; why an independent CLI verify is always available and
is the real answer; and the limits of what a page can promise about itself.

**The threat is total and cannot be closed by the page.** A verifier page is
JavaScript and WebAssembly served by a host. A host that serves something
else can render "VERIFIED" over a bundle that fails, or "TAMPERED" over one
that passes, and no amount of care inside `antseal-core` reaches that. Every
mitigation below reduces the chance that a *substituted* page goes unnoticed;
none of them makes the page trustworthy on its own authority.

**What the page is, and why that is small on purpose.** The shipped page is
**one file** — `verifier-web/index.template.html` — and
`crates/antseal-wasm/tests/page_template.rs:63` asserts the directory holds
nothing else. The deploy closure is `index.html` plus `SHA256SUMS` and
nothing else, enforced twice: `scripts/verifier-page-pack.mjs:133` fails if
the output directory holds another file, and `scripts/pages-publish.sh:91`
re-checks set equality before staging. A single artifact with a single digest
is the only shape a reader can check by hand.

**The three provenance mitigations spec line 139 requires, and where each
lives.**

| mitigation | where |
| --- | --- |
| reproducible `wasm-pack` build with a published SHA-256 | `SHA256SUMS` written over the **served** `index.html` (`scripts/verifier-page-pack.mjs:120-121`); `scripts/pages-publish.sh:132-136` re-fetches the canonical URL after publishing and compares |
| one canonical URL in all docs and printed by the CLI | `https://antseal.org/` (D62 §3 R8; single Rust definition `crates/antseal-cli/src/brand.rs`, `VERIFIER_URL`) |
| footer build hash | `verifier-web/index.template.html:146` renders `module build <digest>`, substituted from `sha256Hex(wasm)` at `scripts/verifier-page-pack.mjs:80` and injected at `:87`; the module's own `build_info()` fills a second element at `:131` with core version, supported format versions and source commit |

**The limit of what a page can promise about itself, stated exactly.**
`crates/antseal-wasm/src/build_info.rs:12-17` puts it in one sentence: *a
digest of a file cannot live inside that file*. So the footer digest is the
**module's**, not the page's, and the page's own digest necessarily lives
somewhere else — in `SHA256SUMS`, fetched over the same connection from the
same host. A visitor who trusts the host has learned nothing new; a visitor
who does not trust the host cannot be helped by a value the host serves. This
is structural, not an implementation gap, and the label is guarded against
quietly drifting into a stronger claim: `page_template.rs:244` asserts the
element is `page-build`, that the label contains *module*, that it does
**not** read *page build*, and that the label carries no hex run of eight
characters or more — so a future edit cannot turn a module digest into an
implied page digest. The packer holds the two ends together: it fails if the
injected footer digest is not the digest of the module the page carries, and
it re-reads its own `SHA256SUMS` and checks that each recorded digest is that
file's own bytes (`scripts/verifier-page-pack.mjs:129-158`, with a
planted-fault self-test at `:286`). **The footer proves page-carries-module;
`SHA256SUMS` proves you-fetched-that-page.** Neither proves the other.

**Where the reproducible build actually runs, stated precisely, because a
mitigation cited in the wrong venue is worse than one cited honestly.**
`scripts/reproducible-build.sh --compare` builds the module twice under two
different checkout paths and two different `CARGO_HOME`s, so the published
digests describe bytes a reader on another machine can reproduce. It is a
**deploy-gated step, not a CI job**: it is invoked from
`scripts/pages-publish.sh:77`, which `.github/workflows/pages.yml:79` calls
*before* anything is staged, and `pages.yml` is `workflow_dispatch:`-only
(`:41`) — a deploy is a manual act. There is **no push/PR/scheduled job
anywhere in `.github/workflows/` that performs the two-build byte-identity
comparison**; the correction is recorded in-tree at
`docs/instrument-ledger.md:121`. The same is true of the browser assertions
(`.github/workflows/verifier-page.yml:52`, dispatch-only). What *does* run on
every push and PR is `wasm-bitmatch` (`.github/workflows/ci.yml:590-605`),
which executes every committed golden vector on native **and** `wasm32` and
requires the transcripts — report bytes plus recomputed digests — to be
byte-identical, self-test first; its comparator additionally refuses to pass
over an empty vector set or a vector that was skipped on either side
(`scripts/wasm-bitmatch.mjs:104-131`). That is the guard against the CLI and
the page disagreeing; it is not a guard against a substituted host.

**Which is why the real answer is the CLI.** `antseal verify` runs the same
`antseal-core` verification in a process on the user's own machine, from a
binary whose signature they checked once, against a bundle that is
self-contained. It needs no host, no network and no trust in a page. The page
says so itself, in the page's own voice, at
`verifier-web/index.template.html:135`: *"for high-stakes verification, run
`antseal verify` and compare verdicts"* — and that sentence is not merely
present, it is **drift-tested against the spec at run time**:
`scripts/verifier-page-browser.mjs` extracts the sentence from `MVP-SPEC.md`
line 139 during the run (`:520-528`, failing if the spec no longer carries
it), reads the rendered element's text out of the live DOM after CSP and
after JS (`:675`), and asserts equality (`:731-737`). Two verifiers
disagreeing about one frozen bundle is the signal, it is available to anybody
at any time, and it is the property that makes a hostile host survivable
rather than merely unlikely.

**What the honest page does *not* do, measured rather than asserted.** These
are properties of the shipped template, and each one is a thing a hostile
replacement could of course do — they are listed because a reader comparing a
suspect page against this description has something concrete to compare:

- **no persistence of any kind** — no `localStorage`, `sessionStorage`,
  `indexedDB`, Cache API, cookies, and **no service worker anywhere in the
  repository**. `scripts/wasm-imports.mjs:97-108` refuses a wasm module that
  even *imports* `localStorage`/`sessionStorage`/`indexedDB`/`fetch`/
  `XMLHttpRequest`/`WebSocket`/`crypto`, and its self-test plants an
  `env.fetch` import at `:177` so the check is not blind;
- **no telemetry, no analytics, no error reporting, no external resource of
  any kind** — no `src=`/`href=` attributes at all, a system font stack, and
  zero `console.*` calls (the panic hook throws rather than logging,
  `crates/antseal-wasm/src/boundary.rs:44`);
- **nothing fetched on load.** `scripts/verifier-page-browser.mjs:696`
  asserts the offline run fetches nothing but the page itself, measured with
  CDP `Network.requestWillBeSent`, which fires even for requests the CSP
  blocks — *"A page that asked and was refused has still asked"* (`:23-26`) —
  and the instrument's own anti-blindness arm (`:1455-1472`) plants a page
  that fetches `https://example.invalid/probe` and fails the run if no
  request is recorded;
- **CSP `default-src 'none'`** (`verifier-web/index.template.html:6`), with
  `connect-src https:` deliberately scheme-only rather than host-pinned —
  `page_template.rs:116-120` asserts the absence of a host allowlist, because
  the spec mandates user-overridable endpoints and a page cannot diagnose a
  CSP refusal.

**Online mode discloses something, and it is not the bundle.** The advisory
overlay is user-triggered and never automatic
(`verifier-web/index.template.html:830-831`). When triggered it queries four
pinned third parties — `blockstream.info`, `mempool.space`, `arb1.arbitrum.io`
and `arbitrum.drpc.org` (`:337-340`) — with `credentials: "omit"`, sending
**bundle-derived anchor metadata only**: a Bitcoin block height, a block
hash, and one Arbitrum transaction hash. No bundle bytes and no content
digest leave the machine. The residual is correlation: the verifier's IP
address becomes linkable, at four named third parties, to a specific anchored
work. That is a real disclosure, it is the user's to accept, and it is the
reason the overlay is a button rather than a default.

**Delegated.** Nothing. This section is engineering copy end to end; the
user-facing half is the README's verify instructions and the CLI's own
`reveal` output, which prints the canonical URL (Q22, Q30).

## 2.5 Coercion / compelled disclosure

*Scope.* An adversary who can compel the holder. Must cover: what a
compelled passphrase yields (everything, retroactively — see §2.1); the fact
that selective disclosure protects against *recipients*, not against
*compulsion*; the absence of any deniability feature and why none is claimed;
and the interaction with §2.2 (a destroyed vault is unrecoverable, which cuts
both ways).

**The note the spec requires, in as many words.** `MVP-SPEC.md` line 28
makes this a documentation obligation rather than an optional section: *"the
vault holder can always be forced to reveal; vault destruction is the only,
irreversible, opt-out."* Everything below elaborates that sentence; nothing
below softens it.

**A compelled passphrase yields everything, retroactively.** It is §2.1 with
the passphrase handed over instead of guessed, so it arrives at the same
place by a shorter road: every `W` in the vault, therefore every unit key and
every salt and every seed, therefore every uploaded ciphertext of every work
in that vault, therefore the plaintext of everything ever sealed from it —
not just the work the compulsion was about. The blast-radius table in §2.1
applies unchanged. An export file is the same disclosure in a form that can
be handed over without the machine.

**Selective disclosure protects against recipients. It does nothing against
compulsion, and the distinction is not a nuance.** Every mechanism in this
product — leaf-exact covers, the salt separation of §1 class 2, the type
system that makes an ancestor seed unaskable-for — constrains what a
*recipient of a bundle* can learn beyond what the sealer chose to show. All
of it presumes the sealer is the one aiming it. A party who can compel the
holder is not a recipient: they take the vault's capability, and then the
reveal machinery works for them exactly as well as it worked for its owner.
There is no cryptographic construction in the design that resists this, and
none is intended to.

**There is no deniability feature, and none is claimed.** Measured: no
hidden-volume, decoy-vault or duress-passphrase mechanism exists anywhere in
the tree — `deniab`, `duress` and `decoy` appear in no decision record and in
no code path as a feature, and `MVP-SPEC.md` does not park one. The vault has
one header, one KDF block and one wrap mode (§2.1), and it enumerates the
works it holds.

The reason none is claimed is worth stating rather than leaving as an
omission. Deniability against a compelling adversary is a property of what
that adversary knows and how long they are willing to keep asking — not a
property of a file format. A vault-shaped file on a machine that has the
antseal binary installed is evidence that a vault exists; a second passphrase
that opens a smaller set is a defence only until someone asks whether there
is a third. A product cannot test that promise, so this one does not make it.
Running a separate vault per context (`ANTSEAL_DIR`,
`crates/antseal-cli/src/vault/layout.rs:75-86`) genuinely limits what any one
compulsion reaches, and it is a practice a user may adopt — it is **not** a
deniability feature and this document does not present it as one.

**The interaction with §2.2 cuts both ways, which is the whole point.** The
only irreversible opt-out is destroying the vault and every backup of it —
and that is §2.2's catastrophe, deliberately performed. What it costs and
what it buys are both permanent:

| after destroying the vault | |
| --- | --- |
| the ability to reveal or restore | **gone**, for every work, forever (§2.2) |
| the uploaded ciphertexts | still there, still permanent, now unreadable by anyone including their owner |
| bundles already issued | **unaffected** — self-contained, they verify offline forever |
| what compulsion can still extract | only what those already-issued bundles already show |

Two consequences follow, and they point in opposite directions:

- **Destruction is not concealment.** Sealing is an act that leaves public
  traces — chunks on Autonomi, an anchor with a calendar or a TSA, a payment
  on Arbitrum (§2.3). Destroying the vault removes the *key*, not the
  *record that something was sealed*. Anyone already holding a bundle keeps a
  verifiable statement about bytes they were shown.
- **Compulsion cannot un-prove existence.** The evidence a seal produces is
  the one thing coercion cannot reach backwards into: a counterparty who
  verified a bundle last year has a verdict that does not depend on the
  sealer's continued cooperation, on the vault, or on Autonomi. That property
  is the product; it is also the reason a coerced holder has less to gain
  from destruction than they might assume.

**Delegated.** The user-facing compelled-disclosure note is owed on
`README.md` by **Q22**, and the copy lint currently carries it as a named
debt whose text points at this section as the only place it exists today
(`scripts/check-copy-style.py`, `OWED_PRESENCE`). This section is that note's
engineering source; it is not a substitute for stating it where a user will
meet it.

## 2.6 Hostile bundles

*Scope.* A `.sealproof` is wholly attacker-controlled input, and the verifier
is the one component that must never panic, hang or over-allocate on it.
Must cover: the strict CBOR profile and parser caps; the tamper matrix as the
evidence that every mutation fails with a *distinct* error; the fuzz targets;
the over-broad-cover and partial-reveal-salt-leak rejections; and the
"internally consistent only" verdict class for a bundle whose chain closes
only against material the bundle itself supplied.

**The setting.** A counterparty is handed a file by the person asking to be
believed, and drops it onto a page in their own browser. Every byte of it is
adversary-authored: CBOR, DER, `.ots`, all of it. The verifier must reach a
typed verdict on any input at all, and must never panic, hang or
over-allocate reaching it.

**Layer 1 — the strict CBOR profile.** `check_canonical`
(`crates/antseal-core/src/codec/decode.rs:887`) enforces RFC 8949 §4.2.1
rather than accepting anything a decoder happens to understand. Fifteen
distinct rejections, each with its own permanent code, matched wildcard-free
so a new variant cannot inherit an old code
(`crates/antseal-core/src/codec/decode.rs:317-341`):

| rejected | code | enforced at |
| --- | --- | --- |
| trailing bytes after the top-level item | `cbor-trailing-bytes` | `decode.rs:731-741` |
| indefinite-length items | `cbor-indefinite-length` | `decode.rs:539`, `:706-718` |
| non-shortest integers / lengths | `cbor-non-shortest-int`, `cbor-non-shortest-length` | `decode.rs:231`, `:239` |
| a duplicate map key | `cbor-duplicate-map-key` | `decode.rs:816`, `:867` |
| unsorted map keys | `cbor-unsorted-map-keys` | `decode.rs:821`, `:870` |
| nesting past the cap | `cbor-nesting-too-deep` | `decode.rs:754-757` |
| floats, simple values, tags | `cbor-float`, `cbor-simple-value`, `cbor-tag` | `decode.rs:154-161` |
| invalid UTF-8, truncation, malformed heads, type and range faults | `cbor-invalid-utf8`, `cbor-truncated`, `cbor-malformed`, `cbor-unexpected-type`, `cbor-int-out-of-range` | `decode.rs:200-302` |

Duplicate and unsorted keys are **two variants and not one**, and the module
says why: disorder and duplication are different attacks and a verifier that
collapses them tells the operator less than it knows (`decode.rs:244`).
Unknown and reserved keys are rejected one layer up, by the schema rather
than by the CBOR reader — `manifest-unknown-key`
(`crates/antseal-core/src/manifest/error.rs:393`, `:768`),
`bundle-unknown-key` and `bundle-reserved-key`
(`crates/antseal-core/src/bundle/error.rs:470`, `:691-692`).

**Layer 2 — caps, in one place, frozen.** Nineteen parser caps live in
`crates/antseal-core/src/codec/caps.rs` and nowhere else — the module says so
of itself (`caps.rs:6-7`) and states the reason there is **no local override**
(`caps.rs:92-94`): *"a per-verifier cap knob would let the CLI and the WASM
page disagree on whether a bundle is valid."* Two verifiers disagreeing about
one frozen bundle is the failure this product cannot afford, so the caps are
format-permanent (`caps.rs:87-88`).

| cap | value | where |
| --- | --- | --- |
| `MAX_BUNDLE_BYTES` | 256 MiB | `caps.rs:108`, checked as the **first statement** of decode (`crates/antseal-core/src/bundle/schema.rs:1759-1779`) |
| `MAX_MANIFEST_BYTES` | 16 MiB | `caps.rs:118`, `crates/antseal-core/src/manifest/envelope.rs:94-97` |
| `MAX_CBOR_DEPTH` | 8 | `caps.rs:138` |
| `MAX_FILE_COUNT` / `MAX_UNIT_COUNT` | 16 384 / 65 536 (unit budget is **work-global**) | `caps.rs:145`, `:155` |
| `MAX_OTS_BYTES` / `MAX_TSA_TOKEN_BYTES` / `MAX_CERT_BYTES` | 1 MiB / 1 MiB / 64 KiB | `caps.rs:229-235` |

The rule that makes the caps hold against a *lying length* is separate and
normative (`caps.rs:34-36`): **every pre-allocation is clamped to
`min(claimed_length, remaining_input)`, with no exceptions, including lists
that have no cap of their own.** `clamped_capacity` is generic in the element
type and divides by its width, which is what makes the byte bound literally
true rather than element-count-shaped. The stage order is frozen too
(`caps.rs:11-25`), so a hostile artifact dies at a length check before any
AEAD, GGM, hashing or signature work is done on it.

Anchor artifacts have their own second home, because they are a different
parser family reached later: `crates/antseal-core/src/anchor/ots/limits.rs`
(op count 4 096, depth 1 024, branch width 64, attestation and operand byte
caps) and `crates/antseal-core/src/anchor/caps.rs` (chain certificates 8, per-
certificate bytes 16 KiB — the latter distinguished from `MAX_CERT_BYTES`
because *"nothing else stops a hostile token carrying a 900 KiB
'certificate'"*, `anchor/caps.rs:79-84`). The registry with dates, fixtures
and margins is `docs/format/anchor-artifact-limits.md` §5. One limit is
**not** ours and is pinned behaviourally instead: DER nesting depth 63 is
`der 0.8.1`'s own private constant, and `der_nesting_depth_limit_is_63`
(`crates/antseal-core/tests/der_pin_eval.rs:137-160`) fails if a crate bump
moves it **in either direction** — a loosened limit is as much a regression
as a tightened one.

**Allocation is measured, not reasoned about.** A counting global allocator
(`fuzz/src/lib.rs:63-90`) enforces the property that gives the clamp rule its
teeth — `the_reservation_never_exceeds_the_input_that_drove_it` — with an
in-suite twin at `crates/antseal-core/tests/parser_caps_alloc.rs`, so the
budget is checked in ordinary `cargo test` and not only under fuzzing.

**Layer 3 — the tamper matrix, and the property that makes it worth having.**
**97 rows**, assembled by `all_rows()`
(`crates/antseal-core/tests/tamper_matrix.rs:426-440`) and cross-registered
against the spec in `testdata/tamper/MATRIX.json`, which also records **six
mutations that are deliberately not rows** and why.

The matrix's claim is not "every mutation is rejected" — it is that **every
mutation is rejected *distinguishably***, and that is an executed assertion
rather than a convention. `check_registry`
(`crates/antseal-core/src/test_util/tamper.rs:165-179`) scans every earlier
row for one already claiming the same expected outcome and fails with:

> *"expected outcome `{}` is already claimed by row `{}` — the tamper matrix
> requires every mutation to fail distinguishably, so one of these two
> mutations needs its own error variant + code"*

It runs over the whole live registry (`tamper_matrix.rs:444-451`, asserting
the checked count equals `rows.len()` so it cannot pass over a short list),
and **the check itself is fault-planted**:
`two_rows_with_the_same_expected_code_fail_distinctness`
(`tamper.rs:286-301`) registers two rows expecting the same code and asserts
exactly one failure naming the earlier row. The contract states what a
collision means, so nobody edits the registry to make one go away
(`docs/testing/error-code-contract.md:485-487`): *"it means two mutations are
genuinely indistinguishable to a verifier, and the fix is a new error variant
with its own code in the owning domain."* Cross-domain reach is exercised
rather than assumed — `seeded_rows_span_multiple_domains`
(`tamper_matrix.rs:457-487`) requires live rows binding `cbor-`, `crypto-`
and the unprefixed structural codes. CI lane: `tamper-matrix`
(`.github/workflows/ci.yml:633-636`), self-test first.

**The two disclosure-bearing rejections this section owes by name.**

- **Over-broad cover.** A cover node whose real-leaf span exceeds the
  revealed range would disclose an unrevealed byte's salt and reopen the
  per-byte confirmation attack of §1 class 3. It is
  `fine-root-over-broad-cover`
  (`crates/antseal-core/src/content/fine_tree/error.rs:208`), it has its own
  tamper row (`crates/antseal-core/src/test_util/tamper_rows_fine_tree.rs:507-514`,
  which substitutes the honest node with its parent), and the test asserts
  the *class* as well as the code and that it differs from `RootMismatch`
  (`crates/antseal-core/tests/tamper_fine_tree.rs:241-256`) — two classes,
  not two spellings of one. §1 class 3 records that over-broadness is
  classified **before** structural faults in the frozen error precedence, so
  the disclosure-bearing failure can never be masked by a cheaper one.
- **Partial-reveal salt leak — two codes, one per material.**
  `partial-reveal-salt-leak-file-salt` and `partial-reveal-salt-leak-s-root`
  (`crates/antseal-core/src/verify/error.rs:750-753`), each with its own
  tamper row (`tamper_rows_structural.rs:567-579`). The property is also
  exercised independently by a proptest that forces the leak at build time
  and asserts the self-check refuses it, with the success arm failing loudly
  (`crates/antseal-core/tests/builder_properties.rs:993-1004`) — so it cannot
  pass by never building anything. **One honesty note carried from the
  registry rather than hidden:** the `-s-root` code is currently unreachable
  through the pipeline, because a full reveal always carries a `file_salt`
  and the file-salt row fires first (`tamper_rows_structural.rs:42`;
  `docs/testing/error-code-contract.md:649-652`). It is reached by calling
  the classifier directly, and it is recorded as unreachable rather than
  presented as a live guard.

**Layer 4 — the no-panic property, from three independent directions.**

1. **Per row, in the tamper harness.** A row that panics is a failure with
   its own message — *"PANICKED while exercising … adversarial input must
   error, never crash"* (`tamper.rs:183-191`) — and the harness's own
   fault-plant registers a deliberately panicking row and asserts the harness
   catches it (`tamper.rs:320-330`). A row whose surface *accepts* a tampered
   artifact fails with `ACCEPTED`, a different message again
   (`tamper.rs:333-338`).
2. **Property tests in the ordinary suite.**
   `crates/antseal-core/tests/verify_fuzz.rs:82-135` runs four properties
   over arbitrary bytes, structure-aware mutations, every mutation of every
   seed, and **every truncation of a valid bundle** (`cut in 0..100_000`).
   Each asserts the outcome is a *typed* `Rejected` or `Verified`, so an
   untyped return fails even when nothing panics; a panic fails the case and
   a hang fails the run.
3. **Fuzz targets, which cover the half a proptest structurally cannot.**
   Six targets — `manifest_decode`, `bundle_decode`, `codec_round_trip`,
   `verify_bundle`, `anchor_token`, `anchor_ots` (`scripts/fuzz.sh:39`) —
   assert no panic **and no abort**, the latter being uncatchable and a trap
   on wasm32. They deliberately install no `catch_unwind`, *"because
   swallowing the panic would defeat the property"*
   (`fuzz/fuzz_targets/manifest_decode.rs:16-17`).

**Where fuzzing runs, stated precisely rather than generously.** `fuzz-smoke`
is a real per-push/PR CI job (`.github/workflows/ci.yml:662-698`): lint,
build, a **self-test that arms a tripwire so each target panics on its first
input and the lane fails unless the crash is caught and a reproducer is
written** (`:689`), then 90 seconds per target over the committed seed
corpora (`:691`). Two qualifications the tree records about itself and this
document repeats: `docs/testing/fuzzing.md:310-318` marks `fuzz-smoke`
*intended-required* — required by convention, not yet a branch-protection
context — and `fuzz-nightly` is **not nightly**: it is cron `41 3 * * 1,4`,
twice weekly, 600 s per target, with a corpus cached across runs
(`.github/workflows/fuzz-nightly.yml:44`, `:138`, `:120-126`). The name is
kept deliberately and the schedule is a budget decision, recorded in the
workflow itself.

**Layer 5 — "internally consistent only", the verdict class for a bundle that
vouches for itself.** An adversary's cheapest move is not a malformed
artifact but a **well-formed** one that closes against material the bundle
itself supplied — a token whose own self-signed root travels inside it. The
verdict for that is `AnchorState::InternallyConsistentOnly`
(`crates/antseal-core/src/verify/report.rs:622`, wire name
`internally-consistent-only` at `:662`), which renders as:

> `internally-consistent-only — cryptographically well-formed but not
> independently anchored — it chains to no pinned root (TSA) and matched
> nothing online (OTS)`

(`crates/antseal-core/src/verify/wording.rs:253-256`). It is **never**
headline-eligible: eligibility is decided in one wildcard-free place
(`crates/antseal-core/src/verify/aggregate.rs:48-57`) and only `proven` and
`valid-at-stamping-cert-since-expired` are true there. The state is produced
where no pinned root is named by any candidate path
(`crates/antseal-core/src/anchor/chain.rs:505-520`), *"including the case
where the chain closes cleanly on a root the bundle itself supplied"*.

Three tests carry it, and each is built so that it cannot pass for the wrong
reason:

- `self_signed_root_in_the_token_is_not_a_trust_anchor`
  (`chain.rs:1318-1351`) runs one real token twice, differing **only** in the
  store: withheld root gives `InternallyConsistentOnly` with no verified time
  and no anchor label; the same root injected into the store gives `Proven`.
  Without the second half the negative would be vacuous.
- `a_bundle_copy_of_a_pinned_root_is_ignored_not_trusted`
  (`chain.rs:1360-1373`) pushes a **byte-identical** copy of a pinned root
  into the bundle-supplied bag against an empty store and requires
  `InternallyConsistentOnly` — catching an implementation that matches trust
  anchors by subject name or by pool membership rather than by store
  membership.
- `an_untrusted_root_expired_before_gentime_is_internally_consistent_only`
  (`chain.rs:1950-1965`) covers the overlapping case, and its comment names
  the bug it exists to catch: *"Any implementation that checks time before
  checking reachability returns `invalid`, and the natural check order does
  exactly that."*

One deliberate boundary, so the class is not over-read: an artifact that
**exceeded a limit** renders `invalid`, explicitly not
`internally-consistent-only`, because *"that state means
well-formed-but-unanchored; an artifact we refused to finish reading is not
known to be well-formed"* (`docs/format/anchor-artifact-limits.md:47-50`).

**What is *not* claimed.** The workspace lints are
`unsafe_code = "deny"`, `dbg_macro = "deny"`, `todo = "deny"` and
`unwrap_used = "warn"`, the last hardened in practice by
`cargo clippy -- -D warnings` (`.github/workflows/ci.yml:171`). There is **no**
`clippy::panic`, `expect_used` or `indexing_slicing` lint anywhere in the
workspace. The no-panic property rests on the three executed mechanisms above
and not on a lint that would deny the construct outright.

**Delegated.** Nothing. This section is the verifier's own account of itself.

## 2.7 Sealer as adversary

*Scope.* The bundle recipient's threat model. A sealer chooses what to
reveal, and the interesting attacks are equivocation (opening one anchored
commitment two ways — see §1 class 1) and out-of-context partial reveal
(showing a true fragment that misleads). Must cover: single-authoritative-
commitment (`fine_root` as the sole content commitment for covered bytes);
the anti-downgrade property of the signed policy; and the rendering
guardrails — every reveal displays position and total size, unrevealed units
render as sized blackout blocks, unrevealed files as committed placeholders.

**Whose threat model this is.** Every other section protects the sealer.
This one protects the person the bundle is handed to, and it is the section a
counterparty should read first. The sealer chose the content, the unit
boundaries, the title, the claimed time and which parts to reveal — the
verifier's job is to make sure none of those choices can turn into a lie
about the anchored bytes, and to make what was *withheld* impossible to
overlook.

**Equivocation — opening one anchored commitment two ways.** §1 class 1
names this as the single failure no downstream check can catch, because both
openings look honest. The format closes it by never having two authorities
for one byte:

- **`fine_root` is the sole content commitment for covered bytes, and that is
  a property of the type rather than a rule someone remembered.**
  `UnitBinding::FineTreeCovered` has **no field**
  (`crates/antseal-core/src/crypto/disclosure.rs:79-94`), so a covered unit
  has nowhere to put a second commitment. A `compile_fail,E0559` doctest at
  `:71-78` asserts that writing one does not compile.
- **The agreement is checked in both directions at construction and at
  decode.** `FileEntry::new`
  (`crates/antseal-core/src/manifest/body.rs:764-779`) rejects a covered unit
  that carries a `unit_commit` (`manifest-unexpected-unit-commit`) *and* a
  non-covered unit that lacks one (`manifest-missing-unit-commit`,
  `crates/antseal-core/src/manifest/error.rs:794`, `:801`); every decoded
  entry funnels through it (`body.rs:614-626`). The wire-level test
  `reject_unit_commit_present_on_a_covered_unit`
  (`crates/antseal-core/tests/manifest_schema.rs:126-140`) injects the key
  into encoded bytes rather than calling the constructor, and states the
  threat in its own comment: *"a second commitment over the same bytes would
  let a sealer open byte i two ways under one anchored `work_id`."*
- **The golden work is swept per unit**, not sampled:
  `no_covered_unit_carries_a_unit_commit`
  (`crates/antseal-core/src/content/openings_e2e.rs:245-287`) asserts, for
  every unit, that carrying a `unit_commit` is exactly the negation of being
  covered, then pins the carrying set to `[3, 5, 6]` — the raw mirror, the
  `--no-fine-tree` file and the empty file — so the property cannot pass by
  the set being empty.
- **At most one raw mirror per file** (`body.rs:755-763`), because a second
  mirror would be *"a second, contradictory 'original', signed and anchored
  inside a clean-verifying bundle"* (`body.rs:728-735`).
- **A full reveal rebuilds the whole tree** from `s_root` through the same
  builder the sealer ran and requires the rebuilt root to equal `fine_root`
  (`crates/antseal-core/src/verify/file_stages.rs:1034-1063`; both a
  substituted `s_root` and an altered `fine_root` land on
  `fine-root-rebuild-mismatch`, `:2035-2061`).

**The `canon_commit`/`raw_commit` cross-check, and why it is not optional.**
Row 7 opens the whole-file content commitment — `canon_commit` for text,
`raw_commit` for binary (`file_stages.rs:1008-1024`). The module states the
consequence of ever making it conditional (`:124-130`): these two fields have
**no other verification path**, so *"making that check optional would not
weaken it — it would delete it, leaving two signed, anchored, permanently
stored fields a sealer may fill with anything."* Rows 9 and 10 close the
co-timestamped-"original" move: row 9 opens `raw_commit` over the mirror
bytes, row 10 recomputes `canonicalize(raw)` under the descriptor-recorded
Unicode version and requires byte-equality with the canonical bytes row 7
already validated (`:1147-1177`). The order is frozen and taken as a typed
witness, so *"forgetting a cross-check is a compile error, not a silent
acceptance"* (`:1181-1211`). The row-10 test substitutes a wholly different
mirror **and recomputes `raw_commit` over it**, so row 9 passes and row 10 is
genuinely the failing check (`:2117-2132`) — the test cannot pass on the
earlier row's back.

**The anti-downgrade property of the signed policy.** §1 class 5 has this in
full: `sig_policy` lives *inside* the signed body, the body is what `work_id`
and `anchor_digest` are computed over, and the verifier requires the present
signature set to **equal** the policy set. So stripping ML-DSA from an
anchored hybrid manifest changes the body, breaks both signatures and breaks
the anchors; a fresh Ed25519-only forgery is a different body, hence a
different `work_id` with its own necessarily later timestamps — a new work,
never a downgrade of the original. Executed by
`downgrading_a_hybrid_policy_breaks_both_signatures`
(`crates/antseal-core/src/crypto/sig_policy.rs`).

**Claimed time is the sealer's, and it is subordinate by absence rather than
by a filter.** The value is injected once, at the one place a clock is
trusted (`crates/antseal-cli/src/seal_run.rs:577-579`), and lands in the
manifest body as informational only (`body.rs:1204-1209`). In the verifier it
lives in a field named for its status —
`claimed_time_informational_only` (`crates/antseal-core/src/verify/report.rs:278`)
— and renders as
"claimed time: {t} (asserted by sealer — NOT verified)"
(`crates/antseal-core/src/verify/wording.rs:344`, `:353-355`). The reason it
can never reach the headline is that the headline computation's input set has
no field it could arrive in (`crates/antseal-core/src/verify/verdict.rs:26-35`):
*"there is no parameter to smuggle it through and no code to delete to let it
in."* `a_claimed_time_earlier_than_every_anchor_cannot_move_the_headline`
(`crates/antseal-core/src/verify/verdict/tests.rs:382-419`) sets a claimed
time of 100 against anchors at 500 and 300 and asserts the headline is 300 —
and that the serialized headline contains `300` and not `"100"`.

**Out-of-context partial reveal is the residual, and its answer is rendering
rather than cryptography.** A sealer who reveals a true sentence out of a
document has revealed something true. No commitment scheme can object. What
the verifier can do is refuse to let the fragment *look* like the whole, and
that guardrail has exactly one rendering path, so a position cannot be
dropped on some route
(`crates/antseal-core/src/verify/redaction.rs:51-60`). Both arms of
`block_line` (`:505-511`) take the same three figures by construction:

| what the recipient sees | frozen wording |
| --- | --- |
| a revealed unit | `unit {id} revealed: {size} byte(s) at offset {start} of {total} declared` (`wording.rs:549-551`) |
| an unrevealed unit | `unit {id} blacked out: {size} byte(s) at offset {start} of {total} declared — sealed, and not revealed by this bundle` (`wording.rs:560-565`) |
| an unrevealed file | `file #{id} — {size} declared byte(s), path withheld: this bundle reveals nothing of this file and names it only by ordinal` (`wording.rs:577-582`) |

Every size on that view is labelled as the sealer's own figure, not a
measurement: *"every size below is the sealer's declared figure, not a
measurement by this run"* (`wording.rs:512-513`).

Two tests carry this, and both are built so they could fail:

- `every_unit_row_of_every_shape_states_position_and_total_size`
  (`crates/antseal-cli/tests/redaction_view.rs:186-208`) walks five real
  `.sealproof` fixtures and requires every `unit ` row to contain
  `" byte(s) at offset "`, `" of "` and `" declared"`, with a `checked >= 9`
  floor so a broken fixture walk cannot pass over nothing. Its negative
  control (`:213-236`) plants three rows that drop a figure — size only, no
  denominator, a percentage — and asserts the predicate rejects each.
- `a_withheld_files_rendering_depends_on_nothing_but_its_ordinal_and_size`
  (`:254-311`) is a real differential: it renames a withheld file to
  `sensitive/merger-with-acme-corp.txt`, replaces its bytes with same-length
  decoys, and asserts the two rendered documents are **byte-identical** and
  that none of those words appears.

**One honest gap in that guardrail's evidence.** The WASM page renders the
same strings from the same assembly — `RenderedRedaction`
(`crates/antseal-wasm/src/api.rs:175`) — and composes nothing itself; it
prints the pre-composed lines (`verifier-web/index.template.html:207-229`).
So the property holds structurally on both surfaces. But **no browser-level
test asserts that the page's rendered rows carry position and total size**;
the sweep above is CLI-side. The guarantee on the page is by shared
construction, which is strong, and it is not separately pinned. Recorded here
rather than left for a reader to assume.

**What a sealer legitimately controls, and the recipient should know it.**
The title is user text in a **plaintext** manifest embedded in every bundle,
so every recipient reads it whether or not the file it names is revealed
(`docs/format/registry-v1.md:589-593`; the CLI warns the sealer at
`crates/antseal-cli/src/seal_warnings.rs:114-120`). Unit boundaries, file
selection, `--no-fine-tree` and the claimed time are all the sealer's
choices, and §2.8 covers what those choices leak.

**Delegated.** Nothing. This is the counterparty's section and it belongs
here in full.

## 2.8 Size fingerprint

*Scope.* What structure metadata leaks even when content does not. Bundle
recipients see file count, sizes and unit boundaries; the network sees
padded ciphertext lengths. Must cover: the 256-byte padding bucket and what
it does and does not blur; what a size histogram identifies (a known
document, a known template); and the deliberate decision that structure is
visible, which docs must state plainly.

**The decision, stated plainly, because it is a decision and not an
oversight.** Structure metadata — file count, file sizes, unit boundaries,
unit sizes — **is visible to every bundle recipient, by design**
(`MVP-SPEC.md` line 95). Per-unit selective disclosure cannot be built any
other way: a recipient who is to be convinced that unit 7 sits at offset
1 024 of a 40 KB file has been told the offsets and the sizes. The product's
answer is to make that visible rather than to imply otherwise, and this
section is where the extent of it is written down.

**Two observers, two different views.**

| observer | sees |
| --- | --- |
| a **bundle recipient** | the whole plaintext manifest, therefore exact unpadded sizes |
| the **network** | one chunk per unit plus one for the manifest, each unit's length bucketed to 256 bytes, the manifest's length **unbucketed**, and the payment transactions |

**What a bundle recipient reads without anything being revealed.** The bundle
embeds the plaintext manifest envelope verbatim
(`crates/antseal-core/src/bundle/schema.rs:1658-1665`), so every field below
is readable by anyone holding any `.sealproof`, whatever was revealed:

- work level (`crates/antseal-core/src/manifest/body.rs:1065-1073`):
  `app_version`, `seal_id`, **`title` — user text**, `claimed_time`,
  `pubkeys`, `sig_policy`, the file list. The title is read by every
  recipient whether or not the file it names is revealed
  (`docs/format/registry-v1.md:589-593`);
- per file (`body.rs:657-664`): `path_commit`, `raw_commit`, the canonical
  mode with `canon_commit`, **`size`**, the fine-tree presence and its
  `fine_root`, and the unit list. File **count** is the list length, and the
  index *is* the `file_id` (`body.rs:652-655`). Paths themselves live in the
  vault, never here (`body.rs:791`);
- per unit (`body.rs:480-488`): `unit_id`, kind, **`range` (start, length) —
  the unit boundary**, **`true_length` — the exact unpadded size**, the
  binding, the AEAD nonce, and **the Autonomi address of that unit's
  ciphertext**.

That last item is worth pausing on: a bundle hands its recipient the storage
addresses of every unit of the work, including the ones it did not reveal.
The ciphertexts are opaque (§1 class 4) and no key is disclosed, so this
reveals no content — but it does let a recipient confirm those chunks exist,
and it **groups** them, which is precisely what the network-only observer
below cannot otherwise do.

**The padding bucket, and exactly what it blurs.** Unit plaintext is
zero-padded to `padded_length = ⌈(true_length + 1) / 256⌉ · 256`
(`crates/antseal-core/src/crypto/padding.rs:43`, `:53-55`; the same value is
the wire constant `PADDING_BLOCK` and the two are pinned equal by
`crates/antseal-net/tests/storage_constants.rs:108-115`). Always at least one
pad byte, so a unit that already ends on a boundary is unambiguous and the
empty unit pads to 256. Stripping is length-first, driven by the manifest's
`true_length` rather than by scanning, so genuine trailing `0x00` content
survives (`padding.rs:82-85`).

What it blurs: a passive storage-layer size peek, to a 256-byte bucket. What
it does **not** blur, in the module's own words (`padding.rs:21-30`): *an
observer still learns `⌊true_length / 256⌋`*. It is *"cheap defense-in-depth
… not a full fingerprint defense — per-unit selective disclosure inherently
exposes per-unit size, so the vector of bucketed sizes (especially under
`--split`) remains a partial fingerprint. Bundle recipients see true lengths
by design."*

**Three things the padding does not cover at all, and the first is an
asymmetry worth naming.**

1. **The manifest ciphertext is not padded.** `encrypt_manifest` goes
   straight to the AEAD with no padding step
   (`crates/antseal-core/src/crypto/manifest_aead.rs:209-242`), so the
   network sees `manifest_plaintext_len + 16` exactly. That length varies
   with file count, unit count and title length, so it is a finer signal
   than any individual unit's bucket.
2. **Chunk count is not blurred.** One blob per unit plus one for the
   manifest (`crates/antseal-cli/src/pipeline/seal.rs:299-347`), each blob
   exactly one Autonomi chunk capped at 4 MiB
   (`crates/antseal-net/src/blob.rs:38`).
3. **Payment-transaction count is not blurred**, and it is public and
   permanent. Payment is one EVM transaction per sub-batch of at most 256
   transfers (`crates/antseal-net/src/ant_backend.rs:38`, `:687`), so the
   on-chain transaction count is about `⌈(units + 1) / 256⌉` — a lower-bound
   signal on unit count that never expires. §2.3 covers the wallet those
   transactions name.

**`--split` is what turns a size into a histogram.** The default is one
whole-file unit (`crates/antseal-core/src/content/unit.rs:5-7`, asserted at
`:635-641`), and the only splitting mode admitted in v1 is
`--split blank-lines` (`crates/antseal-cli/src/cli.rs:298-300`, `:333-339`).
Under it the manifest publishes **the paragraph-length histogram of every
split text file, in the clear** — `range` and `true_length` per unit, kept as
two fields deliberately (`docs/format/registry-v1.md:631-632`). There is no
byte-size granularity knob, so the histogram is the document's own paragraph
structure rather than an arbitrary tiling.

**What a size histogram identifies.** Against an adversary holding a
*candidate* — a published document, a contract template, a filing form — a
paragraph-length vector is close to unique. It is far more identifying than a
single file size, and the 256-byte bucket does not soften it at all for a
bundle recipient, who reads the true lengths anyway. The two realistic
attacks are *"is this that document?"* (a template match) and *"is this the
same document as the one in that other bundle?"* (a cross-bundle join on
structure alone).

**Why the content behind those sizes stays hidden, and where that is
executed.** Two mechanisms, neither of them size-based:

- **Randomized AEAD, not convergent encryption.** Autonomi's native
  self-encryption is convergent, which would make an upload a confirmation
  oracle on its own. Wrapping in a randomized AEAD before upload is what
  stops it: *"two sealers with the same manifest bytes upload different
  ciphertexts"* (`crates/antseal-core/src/crypto/manifest_aead.rs:19-21`).
- **Salted commitments — and the attack is executable, not asserted.** §1
  class 2 is the claim; `crates/antseal-core/src/crypto/confirmation_attack.rs`
  (C19) is its executable form and the standing regression guard for this
  section. The module contains no code: it contains two attacks that run as
  **doc-tests on every `cargo test`** — the **unsalted-unit** variant
  (`:61-138`), which confirms an unrevealed unit's exact contents against a
  deliberately unsalted toy commitment at the cost of four hashes and fails
  against the production `unit_commit`; and the **unsalted-file-hash**
  variant (`:140-243`), the sharper one, where the attacker is a legitimate
  recipient of a one-unit partial reveal and an unsalted `canon_commit`
  would be an offline whole-document confirmation oracle. The 128-bit salt
  margin is asserted inside the same doc-test (`:125`,
  `Salt16::LEN * 8 == 128`), so it cannot be narrowed silently. The module is
  wired into the crate at `crates/antseal-core/src/crypto.rs:112`, which is
  what makes these doc-tests *run* rather than merely exist.

**Grouping difficulty is the primary defence against the network observer,
and its exceptions are named.** `MVP-SPEC.md` line 91 is explicit that the
confirmation attack is defeated primarily by the randomized AEAD *and* by the
difficulty of grouping a work's chunks at all: Autonomi addresses are
content-derived, and the only artifact enumerating a work's unit addresses —
the manifest — is itself uploaded encrypted, so a network-only observer
cannot tell which chunks belong to one work. The spec names the four routes
that **do** group them, and this document does not soften the list: the
encrypted manifest (to anyone who can decrypt it), **a bundle** (which
publishes every unit address in the clear), **the batch-payment
transaction**, and **upload-time traffic correlation**. So the residual
fingerprint is exploitable by an adversary who can both group a work's
ciphertexts by one of those routes *and* hold a candidate document — a
narrower adversary than "anyone watching the network", and a wider one than
"nobody".

**Nothing blurs upload timing, ordering or batching, and that was measured
rather than assumed.** Blobs upload in canonical order — units by `unit_id`,
manifest last (`crates/antseal-cli/src/pipeline/seal.rs:361-369`) — with no
shuffle, no jitter and no cover traffic anywhere in `crates/antseal-net`. A
crash-resume re-uploads byte-identical staged ciphertexts
(`crates/antseal-cli/src/pipeline/resume.rs:6`), producing a second
correlated burst with the same size vector. **No traffic-analysis
countermeasure exists in the codebase**, and none is claimed.

**`--no-fine-tree` is the one structural choice that is permanent.** A file
excluded from the fine tree becomes exactly one whole-file unit bound by
`unit_commit`, and is whole-file-revealable only, forever
(`crates/antseal-cli/src/cli.rs:306-309`; structurally at
`crates/antseal-core/src/manifest/body.rs:274-286` and
`crates/antseal-core/src/content/unit.rs:664-674`). The CLI says so before
the seal, in those terms: *"PERMANENTLY whole-file-reveal only … the opt-out
is recorded in the manifest and can never be changed for this work — the only
remedy is to seal the file again later, as a different work with a different
date"* (`crates/antseal-cli/src/seal_warnings.rs:136-144`). For this section
the trade is simple: it removes the paragraph histogram, and it removes
partial reveal along with it.

**The escape hatch is a format version, never a parameter.** The padding
formula is format-version-scoped (`padding.rs:32-38`; `MVP-SPEC.md` line 91),
so a future version may adopt a coarser scheme — Padmé's `O(log log n)` leak
is the named candidate — without breaking v1 seals, if real fingerprinting
data ever justifies its permanent storage cost. It is deliberately **not** a
negotiable parameter inside v1, for the reason §1 class 1 refuses hash
agility: a knob a verifier must interpret is a knob a verifier can be told to
set low. Format evolution is `docs/user/format-stability.md`'s subject (Q27).

**Delegated.** Nothing structural. The user-facing statement that a bundle
recipient sees file count, sizes and unit boundaries is owed on `README.md`
by **Q22**, whose `Do` names it; this section is its engineering source.

## 2.9 Evidence independence

*Scope.* Why no single anchor is load-bearing. Must cover: OTS→Bitcoin
(offline `attested`, online-gated to `proven`, and why a lone embedded
header proves nothing offline); ≥2 RFC 3161 TSAs verified against a pinned
root store with genTime-evaluated chain validity; the Arbitrum receipt as
supporting evidence only; and the standing rule that **Autonomi is never
trusted for time** and evidence validity never depends on Autonomi being
reachable.

**The design rule.** No single anchor is load-bearing, and no anchor source
is trusted to be honest on its own. A verdict's headline is the **earliest
headline-eligible** time, and eligibility is decided in exactly one
wildcard-free place (`crates/antseal-core/src/verify/aggregate.rs:48-57`), so
a new anchor state must decide explicitly rather than inherit.

### OTS → Bitcoin: `pending`, `attested`, `proven`

The three states are constructed differently, and the difference is that
`attested` has **no time parameter at all**:
`AnchorVerdict::attested(kind, source, fetch_date)` sets
`verified_time_unix: None` (`crates/antseal-core/src/anchor/model.rs:791-796`),
where `proven(kind, verified_time_unix, …)` is the only constructor that can
set it (`model.rs:739-749`). So `attested` cannot carry a time by
construction, not by a filter someone remembered.

**Why a lone embedded header proves nothing offline.** An upgraded `.ots`
carries a Bitcoin block header. On its own that header's proof-of-work is
**self-referential** — an attacker picks its own `nBits`, so a
minimal-difficulty forged header mines in seconds
(`crates/antseal-core/src/anchor/ots/header.rs:11`; `MVP-SPEC.md` line 108).
The header is therefore evidence of a *claim about* a block, never of a
block. Promotion to `proven` requires the header to be confirmed against the
real chain: rule O3
(`crates/antseal-core/src/anchor/verdicts.rs:789-811`) fires only when an
**agreed** header from two independent endpoints equals the embedded one, and
the time it records is the *agreed* header's `nTime` — never the embedded
one's. Two must-agree esplora endpoints, `blockstream.info` and
`mempool.space`, are the default (`crates/antseal-anchor/src/esplora.rs:83-84`),
and the whole path is behind `--online`
(`crates/antseal-cli/src/verify_host.rs:148`).

`a_minted_single_branch_committed_ots_answers_all_three_online_cases`
(`crates/antseal-core/tests/anchor_ots_writer.rs:48-88`) walks one minted
`.ots` through four outcomes from one fixture: no evidence → `attested` with
no verified time; agreed header equal to the embedded one → `proven` at the
header's `nTime`; a *different* agreed header → `invalid` with the
header-mismatch code; no such block → `invalid` with the block-absent code.
`attested_is_never_headline_eligible` (`anchor/ots/header.rs:365`) pins the
consequence.

### RFC 3161 TSAs

**Correction to this section's M0 scope line.** The scope line reads *"≥2 RFC
3161 TSAs verified against a pinned root store"*, which conflates two
different numbers. Measured:

- the **default endpoint list is two** — `https://freetsa.org/tsr` and
  `http://timestamp.digicert.com`
  (`crates/antseal-anchor/src/tsa.rs:102-103`, asserted by
  `the_default_tsa_list_is_the_specs_two`, `tsa/tests.rs:579`);
- the **seal gate requires one verified token**, not two:
  `MIN_VERIFIED_TSA_TOKENS = 1`
  (`crates/antseal-anchor/src/submit.rs:292`), and the constant's own doc at
  `:284-291` says *"**One**, and A31 does not change it."*

The distinction is load-bearing in the other direction too: two configured
endpoints can be **one** TSA behind two names — `timestamp.entrust.net` and
`timestamp.sectigo.com` share a signer certificate
(`docs/anchors/real-smoke-runbook.md:80-85`) — which is why `distinct_tsas()`
(`submit.rs:124`) exists, so a report never says "two anchors" when two
endpoints collapsed into one authority. A section that promised "≥2 verified
TSAs" would be describing a policy the code does not implement and a
robustness the collapse case does not deliver.

**The minimum-anchor policy, and the escape.** `evaluate_seal_gate`
(`submit.rs:252-276`) aborts a seal that produced zero verified tokens unless
`--force-degraded` is passed (`crates/antseal-cli/src/cli.rs:322-324`), and
the abort is loud about what did *not* happen: *"the minimum-anchor policy
was not met: 0 of {attempted} TSA endpoint(s) produced a verified token, so
nothing was paid for"* (`crates/antseal-anchor/src/gate.rs:184-189`).
`--force-degraded` cannot buy everything: it cannot authorise a `--no-anchor`
seal on a permanent network, and the test loops both flag combinations to
prove it (`submit/tests.rs:251`).

**The pinned root store is compiled in, not fetched and not configurable.**
Four DER roots — FreeTSA, DigiCert Trusted Root G4, DFN-Verein Community Root
CA 2022, Sectigo Public Time Stamping Root R46 — are `include_bytes!`d into
`antseal-core` (`crates/antseal-core/src/anchor/roots/mod.rs:263-307`), at
store version 1 with build date 2026-08-03 (`:114-117`), and
`pinned_store_is_exactly_four_roots_at_version_1` (`:360`) pins the version,
the date, the four labels **in order**, and the total byte count. A fifth
candidate is quarantined with its reason recorded
(`crates/antseal-core/src/anchor/roots/PROVENANCE.md:251-258`). Cite the test
rather than the comment at `roots/mod.rs:259`, which still says *"Three
roots"* and is stale.

**Chain validity is evaluated at `genTime`, and "expired" is not "invalid".**
`temporal_grade` (`crates/antseal-core/src/anchor/chain.rs:851-869`) asks
three questions in order: was the certificate valid *when the token was
stamped* (back-dated → `NotYetValid`; expired-at-`genTime` → `Expired`, both
fatal), and has it expired *since* (→ `ValidAtGenTimeButExpired`, which keeps
`verified_time_unix` and stays headline-eligible, `chain.rs:530-546`, *"Aging
bundles must not silently rot."*). The `verify_at` comparison is one-sided by
construction and can never itself produce a failure. `antseal-core` reads no
clock at all — `verify_at_unix` is a parameter (`chain.rs:69`).

Three tests fix the behaviour in all three directions, from one real DigiCert
token: `one_fixture_two_verify_times_flips_proven_and_since_expired`
(`chain.rs:1749`) verifies the same token at two times and gets `proven` then
`valid-at-stamping-cert-since-expired`, still headline-eligible, same
verified time; `an_expired_at_gentime_chain_is_invalid_with_the_temporal_code`
(`:1788`) pushes `genTime` past the certificate and gets `invalid` with
`anchor-cert-not-valid-at-gentime` and no eligibility;
`verify_at_before_gentime_is_still_proven` (`:1772`) loops three
verify-times before `genTime` and requires `proven` each time.

### The Arbitrum receipt is supporting evidence, structurally

It renders as
"supporting evidence — no independently proven time"
(`crates/antseal-core/src/verify/wording.rs:392`), over a detail line saying
what it does and does not prove. It can never be an anchor and never reach a
headline, and neither is a check: `ReceiptEvidence::is_headline_eligible`
is `const fn … { false }` with the reasoning beside it — *"Never
headline-eligible, and not because anyone remembered to check … there is no
code path that could make it return `true`"*
(`crates/antseal-core/src/anchor/verdicts.rs:365-372`) — and the report's
receipt arm carries **no time field and no state field, not a null one,
none** (`crates/antseal-core/src/verify/report.rs:756-759`). Even a
successful two-RPC online confirmation leaves it ineligible
(`anchor/verdicts/tests.rs:2269`), and every online-confirmation string ends
`— supporting evidence only` (`wording.rs:968-998`). §2.3 covers what
including it costs.

### The claimed time never competes with an anchor

The sealer's own timestamp renders as
"claimed time: {t} (asserted by sealer — NOT verified)"
(`wording.rs:344`, `:353-355`) and is excluded from the headline by absence
rather than by a filter (§2.7; `crates/antseal-core/src/verify/verdict.rs:26-35`).

### The upgrade path, so `pending` does not become permanent

A `pending` OTS is a debt, and the product chases it without being asked: the
opportunistic upgrade hook runs at the end of **every** invocation
(`crates/antseal-cli/src/upgrade_hook.rs:1-3`, single call site
`crates/antseal-cli/src/lib.rs:185`), inside a deliberately small budget — 3
seconds and 4 polls (`upgrade_hook.rs:55-57`) — so it can never delay a
command meaningfully. `list` nags while any work is in that state, and only
then: the classifier is wildcard-free and `OnlyPendingOts` is the single
nagging state (`crates/antseal-anchor/src/ots/engine.rs:619-700`), rendering
*"ANCHORS PENDING: {n} calendar attestation(s) not yet confirmed by Bitcoin,
and nothing else here proves a time independently"* plus the exact command to
run (`crates/antseal-cli/src/listing.rs:760-769`). A genuinely unanchored
work is **labelled, never nagged** — the nag exists for a state that will
resolve itself, not for one that will not
(`crates/antseal-cli/tests/list_command.rs:875-921`).

### Autonomi is never trusted for time, and evidence never depends on it

**Verification is offline, and that is proven with a host that panics on
contact rather than with a mock that could quietly answer.**
`offline_mode_never_consults_the_host`
(`crates/antseal-core/src/verify/orchestration/tests.rs:206-221`) runs
verification against a `PanickingHost` whose every method panics — *"the host
seam is the only route to a network, so a host that panics on contact is the
strongest available statement that no call was made"* (`:127-135`) — and it
repeats the run over an `attested` bundle *"so the row is not passing because
there was nothing to fetch about"*. Its anti-vacuity twin
(`the_host_seam_is_live_when_a_mode_asks_for_it`, `:229-253`) uses a counting
host and asserts `(0, 0)` calls offline and `(1, 1)` with online and live
enabled, so the panicking row cannot be passing over an orchestration that
never consults a host at all. And `verify_offline`, the entry point third
parties call, is asserted equal to that same offline configuration (`:260`).
The CLI half is proven at the binary: `verify` runs on a machine with no
vault at all, with stdin closed, without prompting
(`crates/antseal-cli/tests/verify_command.rs:773`).

**Structurally, an Autonomi-derived time has no route into a verdict.**
`antseal-core` owns all verification and does not depend on `antseal-net` at
all (`crates/antseal-core/Cargo.toml`); `verified_time_unix` is settable only
through `proven` and `valid_at_stamping_cert_since_expired`
(`anchor/model.rs:739`, `:763`), every other constructor hard-coding `None`;
and `headline_eligible` is wildcard-free. `crates/antseal-net/src/lib.rs:45-47`
states the crate's own scope: *"**Evidence validity never depends on Autonomi
availability**: this crate stores and fetches ciphertext; it plays no part in
offline bundle verification."*

**A gap this section names rather than papers over.** *"Autonomi is never
trusted for time"* is **project rule 3, prose and structure — there is no
test that asserts it.** Grepped: no test in the tree names the rule, and the
three structural obstacles above would not redden on a rename; they would
redden only if someone routed an Autonomi-derived time through a new type or
a new state. The rule holds today because there is nothing to delete that
would let it in, which is a good position and is not the same as a guard.

### The accepted one-time mainnet exposure

`MVP-SPEC.md` lines 157 and 180 accept exactly one pre-release exposure to
the public network: a single small real mainnet smoke seal at the M4 gate,
performed to prove the released binary works end to end against the network
it defaults to. It is accepted deliberately and it is bounded — one seal, one
work, before release — and it changes nothing about evidence validity, since
a bundle's verification never touches Autonomi.

> **Slot for Q34.** The concrete exposure — **work-id and date** — is
> recorded here by Q34 after the gate runs, alongside the release notes
> (Q34's `Do` and its third Accept row). Until then this paragraph records
> the accepted policy; it does not record an event that has happened.

**Delegated.** TSA selection, the alternates with their recorded caveats
(`zeitstempel.dfn.de`'s non-commercial terms, Sectigo's ~15 s spacing,
SwissSign's ~10/day), configuring a custom list, and what `--force-degraded`
means for a user are `docs/user/timestamp-authorities.md`'s (Q26). Today that
material lives at `docs/anchors/real-smoke-runbook.md:71-85` and
`docs/config.md:101-110`, which are operator documents rather than user ones.

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

### The M4 cross-check (Q21, 2026-08-17) — the shipped page **widens** this, narrowly

C21 left a standing obligation here: *cross-check once the verifier page
exists, in case the shipped page adds handling that widens the exposure.* The
page exists. The cross-check was performed against
`verifier-web/index.template.html`, which
`crates/antseal-wasm/tests/page_template.rs:63` asserts is the whole of the
shipped page. **The result is one widening, one smaller one, and everything
else narrower or unchanged.**

**The widening, and it is by design rather than by accident.** The page holds
the entire bundle in a module-scope variable for the life of the tab:

```js
394:  let sessionBundle = null;      // set at :418, cleared only at :427
296:  bytes = new Uint8Array(await file.arrayBuffer());
```

It exists so that pressing *confirm online* need not re-read the file
(`verifier-web/index.template.html:305-309`), and the page's own comment
describes the lifetime plainly: *"In memory, which is the whole of a session
on a page that never navigates"* (`:390-393`). `disarmOnline()` nulls the
reference (`:427`) and is called from exactly one place — the top of the next
drop (`:291`). There is no `beforeunload`, `pagehide` or timeout handler, and
no `.fill(0)` anywhere in the file.

This matters because C21's audit assumed the browser-side copies were
*accidental and unreachable* — engine buffers awaiting garbage collection.
This copy is **neither**: it is strongly reachable and therefore ineligible
for collection, and because the retained object is the **whole bundle**
rather than the derived keys, everything §2.10 scopes (`k_u`, `k_m`, salts)
stays fully re-derivable from browser memory for the tab's lifetime. Pressing
*confirm online* re-derives it all at an arbitrary later moment (`:778`
re-passes the bundle for a full re-verification), which extends the window
rather than closing it. A second, smaller widening: the entire canonical
report crosses into immutable JS strings at `:303` and `:778` — C21 named
input-side string intermediates but not output-side ones.

**What that second copy does *not* contain, verified rather than assumed.**
No key material: `crates/antseal-core/src/verify/report.rs:52-56` is
normative that no field of the report model may carry `W`, `k_u`, `k_m`, any
salt or any GGM seed, and `no_secret_material_in_display_debug_or_json`
(`crates/antseal-core/src/verify/mod.rs:568-651`) builds three fully
populated reports plus the whole error-exemplar set and asserts nine surfaces
contain none of five planted secret patterns — then asserts the wire forms do
not even contain the substrings `salt`, `seed`, `k_u`, `k_m`, `secret` or
`nonce`. No revealed plaintext either: the redaction block is offsets and
sizes only (`crates/antseal-core/src/verify/wording.rs:550`, §2.7), and no
export returns unit content. What *does* cross is public statement data plus
the sealer's title and the revealed file paths.

**Everything else narrows or matches**, and each was checked by name rather
than inferred: no `localStorage`, `sessionStorage`, `indexedDB`, Cache API or
cookies; **no service worker anywhere in the repository**; no `console.*`
call in the page or in `crates/antseal-wasm/src` (the panic hook throws
rather than logging, `crates/antseal-wasm/src/boundary.rs:44`); no analytics,
telemetry or error reporting; no external resource of any kind; CSP
`default-src 'none'` (`:6`); and a runtime-proven zero-request offline path
(§2.4). `scripts/wasm-imports.mjs:97-108` refuses a module that so much as
*imports* a storage or network name, with a planted fault at `:177`.

**The practical guidance below is therefore unchanged and, if anything,
firmer.** Where C21 wrote *treat a browser that has verified a bundle as
having retained that bundle's keys until the tab is closed* as a pessimistic
assumption about garbage collection, the shipped page makes it a structural
property of the design. The advice is the same; its status has moved from
prudent to certain.

**What this cross-check could not determine, stated plainly.** The
wasm-bindgen glue is generated at build time and is not committed, so whether
the per-call copy of the bundle into linear memory is freed or wiped after
`verify_rendered`/`verify_online` return was **not** established; the audit
read the template and the packer rather than the built bytes; and
browser-level behaviours — bfcache, session restore, the retained
`<input type="file">` handle at `:59`, crash-reporter snapshots — remain
exactly as unobservable from source as C21 said they were.

*Status:* written (C21, 2026-07-28); cross-checked against the shipped page
(Q21, 2026-08-17) with the finding above.

---

# 3. Risk coverage map — `MVP-SPEC.md` lines 177–189

Every row of the spec's *Risks & mitigations* section, and where it is
answered. A row is either **addressed here**, in a named section, or
**delegated** to a named document that owns it. Nothing on the spec's list is
left without a home, and nothing is answered by two owners.

| spec line | risk | owner |
| --- | --- | --- |
| **179** | ant-core churn (weekly-to-biweekly) → exact pin, `StorageBackend` isolation, mock-first tests | **Delegated** — `docs/dependency-policy.md`, which names this row as its own subject at `:9` (*"Risks — ant-core churn, PQC crate maturity"*). It is a dependency-governance risk, not a threat to a seal: no attacker is involved and no evidence property depends on it. |
| **180** | Autonomi network youth → evidence validity never depends on Autonomi; one accepted pre-release mainnet exposure | **§2.9** — the offline-verification proof, the structural absence of an Autonomi-derived time, and the accepted one-time exposure with the slot Q34 fills. |
| **181** | receipt anchor not independently verifiable in MVP → demoted to supporting evidence | **§2.9** (why it can never be an anchor, structurally) and **§2.3** (what including it costs). |
| **182** | OTS pending window / calendar death; TSA churn and cert expiry → minimum-anchor policy, opportunistic upgrades, pinned roots, genTime LTV | **§2.9** — all four, including the correction that the *gate* is one verified token while the *default list* is two endpoints. TSA selection and the alternates are **delegated** to `docs/user/timestamp-authorities.md` (Q26). |
| **183** | PQC crate maturity (`ml-dsa` pre-1.0 and unaudited; `fips204` dormant) → exact pins, RUSTSEC tracking, WASM probe, reserved-slot fallback | **Delegated** — `docs/dependency-policy.md:9` and its `ml-dsa`/`fips204` rows. The *cryptographic* half — what a break of either half of the hybrid would and would not forge — is **§1 class 5**, which is frozen. |
| **184** | vault loss **and** vault theft → export nag, loud docs for both, hardened KDF with header agility, wallet key inside the vault, `zeroize` | **§2.1** (theft) and **§2.2** (loss), with the user-facing pages **delegated** to `docs/user/vault-theft.md` and `docs/user/vault-loss.md` (Q24). |
| **185** | wallet linkability → receipt excluded by default, wallet-hygiene docs, threat-model section | **§2.3**, which is the section this row names — including the measured finding that of the row's three commitments two are implemented and the third has no CLI affordance behind it. Hygiene and funding are **delegated** to `docs/user/wallet-hygiene.md` (Q25) and `docs/user/funding-your-wallet.md` (Q23). |
| **186** | malicious verifier host → reproducible build, published hash, canonical URL, footer build-hash, CLI cross-check advice | **§2.4**, including where each mitigation actually runs and the structural limit on what a page can promise about itself. |
| **187** | hostile bundles → parser hardening, caps, strict encodings, fuzzing in CI | **§2.6**, with the fuzzing venue stated precisely rather than generously. |
| **188** | sealer-as-adversary → structural invariants, `canon_commit`/`raw_commit` cross-checks, subordinate claimed-time rendering | **§2.7**, all three, plus the rendering guardrails and one honestly recorded evidence gap on the page side. |
| **189** | free-TSA terms and rate limits → defaults with recorded caveats, configurable list, failures downgrade the seal report | **Delegated** — `docs/user/timestamp-authorities.md` (Q26), whose `Do` names each caveat. **§2.9** carries the mechanism the downgrade rides on (the minimum-anchor policy and `--force-degraded`); the per-endpoint terms are the user page's. |

Two rows of the eleven — 179 and 183 — are engineering-process risks rather
than threats to a seal, and both are delegated to the document that already
names them. The other nine are answered in this file, five of them with a
user-facing counterpart named beside them.

The threat sections also carry three topics the Risks list does not enumerate
separately: **coercion and compelled disclosure** (§2.5, required instead by
spec line 28), the **residual size fingerprint** (§2.8, required by spec
line 91), and the **WASM zeroization caveat** (§2.10, required by spec
line 143).

---

## Related records

- `docs/security-assumptions.md` — C20, the source of truth for section 1.
- `docs/user/` — the M4 user-facing documentation set (D139 §2 R1/R2):
  `vault-theft.md`, `vault-loss.md`, `wallet-hygiene.md`,
  `funding-your-wallet.md`, `timestamp-authorities.md`, `format-stability.md`.
  This file stays engineering copy and is not part of that set (D139 §2 R3).
- `docs/dependency-policy.md` — the owner of spec rows 179 and 183.
- `docs/zeroization-audit.md` — C21, the per-buffer audit behind §2.10.
- `docs/testing/fuzzing.md` — the fuzz lanes §2.6 cites, and their venue.
- `docs/decisions/` — the decision register (D74/D75 GGM cover shape,
  D13/D14/D15 signature pins and signing mode, D16/D17 signature policy).
- `docs/format/registry-v1.md` — the wire format these assumptions apply to.
- `docs/testing/error-code-contract.md` — the permanent error codes the
  tamper matrix binds to.
