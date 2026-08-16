# D134 — Paper-key locked bundles: the transform pair, the header that shrinks, and what U32 actually has to reserve

- **Status: RESOLVED on all four chartered surfaces. The round's architecture
  survives; three of its surface leans do not, and the reason D134 was placed
  before U32 turns out to be a different reason than the one the register
  recorded.** The register's clause — *"must resolve before U32 or the CLI
  release freeze prices a reopen"* — assumes the lock/unlock surface collides
  with the frozen CLI. **Measured, it barely does.** `antseal verify` on a
  locked file today exits **40** with
  `bundle: expected map, found byte string at byte 0 [cbor-unexpected-type]`,
  and `machine.rs:56` puts `message` in the **freely rewordable** half of the
  D65 tier table, so the honest refusal this feature wants from `verify` is
  **not a frozen-surface event at all**. What U32 genuinely owes is **three
  policy reservations** (§2 R3), not a surface. That is the headline: the
  deadline is real, its content is smaller than the register feared, and it
  sits in the release *promises* rather than in the command tree.
- **Three leans overturned, each on a measurement in this tree.** (a) The
  round's `reveal --lock` becomes a **vault-free transform pair**: `reveal`
  opens the vault at `commands.rs:665-667`, so a lock mode inherits a vault
  requirement the operation does not need, and it mutates reveal's frozen
  default-output line at `cli-surface.help.txt:280`. (b) The wrapper's `label`
  stops being a free-text `tstr` defaulting to `"card 1"` and becomes a
  **bounded `uint` card number**, which makes the round's own red-team finding
  #1 — *"plaintext label leaks recipient identity if mirrored"* —
  **unrepresentable** instead of mitigated by a rubric. (c) **Both probes the
  round's addendum pinned as D134's resolution evidence are mis-specified**:
  probe 2's observable cannot discriminate its two arms (D132 measured an
  entire sixth export at **146 B** against a wordlist payload of **~13 kB**),
  and probe 3's kilobyte-bundle benchmark would have licensed a page promise
  that is false at scale, because the repair scan costs **Θ(192 × |file|)** —
  ~2 ms for the largest golden vector and **~19–64 s for a 100 MB reveal**.
- **A premise carried in this lane's brief is false and is corrected here.**
  The verifier page does **not** run with zero network access. Its CSP is
  `connect-src https:` — scheme-only, **deliberately not** the six pinned hosts
  (`verifier-web/index.template.html:6`; ruled at D129 §5 R6,
  `D129…:705-718`, on the §1 (m) measurement at `:352-368`), and the page holds
  two live `fetch()` call sites at `index.template.html:534` and `:574` for
  D66's opt-in overlay. Zero-network is a **test-lane assertion about the
  offline path**, not a property of the shipped document. This inverts surface
  3's analysis: a paper key typed into that page is **the first secret the page
  would ever hold**, inside a document that may address any `https:` origin.
- **BIP39-24 is ratified on arithmetic recomputed here, not recalled.**
  24 words = 264 bits = **256 entropy + 8 checksum**, and the wrap's key is
  **exactly 256 bits** (`Key32::LEN == 32`, asserted at `material.rs:409`) —
  an exact fit with **no derivation step**, which is the whole argument. The
  round's worked example reproduces byte for byte on this machine. What does
  **not** reproduce here is the *word rendering*: no BIP39 wordlist exists in
  this repository or its 772-package lock file, so every claim about which
  English word an index names — and the wordlist's pinned SHA-256 — remains
  the round's measurement, not this record's. §2 R10 names the gate.
- **Date: 2026-08-16**
- **Owning task: U32.**
- Related: `docs/research/paper-key-transport-design-round.md` (the OBOL round
  that minted this decision, 2026-08-15, and its maintainer addendum of the
  same day), D50 (the `--wrap` registry — the word "wrap" is already taken),
  D51/D65/D69 (the machine-mode, JSON-tier and exit-code contracts this record
  prices against), D68 (reveal's default filename), D18 §5 R4 as amended by
  D130 and tested by D132 (the closed page boundary), D129 §5 R6 and D66 (the
  page's real network posture), R18 (the verdict-wording freeze), U1 (the
  frozen CLI surface), U32 (the freeze this record feeds), Q21/Q24 (custody and
  size-fingerprint prose), Q29 (wordlist provenance).

---

## 1. What was measured

Every file:line below was read in this working tree at HEAD `3352fbe`
(2026-08-16). Where a number contradicts the round doc it is flagged; where it
confirms it, that is said too, because the round's cites were re-checked rather
than trusted.

### 1.1 The frozen CLI, and what a lock mode would actually move

| surface | where it is frozen | measured |
|---|---|---|
| help text | `crates/antseal-cli/tests/snapshots/cli-surface.help.txt` | **407** lines, 18 120 bytes, newline-terminated (the round records 408 — off by one, not load-bearing) |
| `verify` never prompts | snapshot `:14` and `:295` | both exact, verbatim *"needs no vault and never prompts"* |
| reveal's default output | snapshot `:280` | *"(default `./antseal-reveal-<work-id>.sealproof`; an existing file is never overwritten)"* — U68's amendment (ii) has **landed**; `tasks/U.md:19` still describes it as pending |
| secrets never in argv | snapshot `:30`, `:77`, `:125` | *"Secrets never transit argv or the environment"* |
| exit-code table | `src/error.rs:327` (`ALL: [ErrorClass; 33]`), `:365` (`exit_code`); `tests/exit_codes.rs:36` (`TABLE: [(ErrorClass,u8,&str); 33]`), `:121`, `:135` | 33 classes; **44–49 reserved** with a reddening assertion; `(40..=43)` additionally asserted to be `verify-`-named |
| command set | `src/machine.rs:161-172` | `ALL_COMMAND_NAMES: [&str; 10]` — *"exactly the ten of the frozen surface"* |
| prompt classes | `src/machine.rs:195-226` | a **closed four-variant enum** with four declarations, ridden by an exhaustive `match` so a new subcommand *"fails to compile until it is both named and registered"* (`:136-141`) |
| JSON promises | `src/machine.rs:61-65` | tier A frozen report bytes · tier B wrapper, **`message` freely rewordable** (`:56`, `:64`) · tier C *"unstable until U32"* |

**`verify` cannot prompt, and the guard that says so is weaker than the
property.** Traced through `run.rs:77-93` → `commands.rs:720`: the handler
resolves no layout, collects no passphrase and takes an unused `_slot`; its doc
at `:701-704` states it. `reveal`, by contrast, opens the vault at
`commands.rs:665-667` before it does anything else. The only behavioural guard
on verify's silence is `tests/verify_command.rs:772`, which nulls stdin and
asserts the output never contains the string **"passphrase"** — a prompt reading
*"Enter word 1 of 24:"* would pass it. That gap is priced in §4.

**What `verify` does with a locked file today — measured, not inferred.** A
file beginning with the proposed 20-byte magic was handed to the built binary
(`target/debug/antseal`, built 2026-08-16 11:25, i.e. **~3 h older than HEAD** —
stated because a stale artifact is a wrong-medium risk, though nothing in the
decode path moved):

```
$ antseal verify fake.sealproof.locked
error: this bundle did not verify: bundle: expected map, found byte string at byte 0 [cbor-unexpected-type]
exit=40
```

This is **deterministic for this magic, not an artefact of the fixture**:
`'A'` is `0x41`, CBOR major type 2 with additional info 1, so *every* file
starting `ANTSEAL …` decodes as a one-byte byte string where a map was
required. The message is also **actively wrong for the primary user story** —
the recipient of a perfectly good sealed proof is told *"this bundle did not
verify"*.

### 1.2 The page boundary, and the page's real network posture

- `crates/antseal-wasm/src/boundary.rs` holds **six `pub fn`s** — `start` `:42`
  (attribute `:41`), `verify` `:59`, `verify_online` `:74`, `verify_rendered`
  `:91`, `verdict_class` `:102`, `build_info` `:116` — i.e. **five callables
  plus the panic hook**, matching the round's stated convention.
- D18 §5 R4 closes that list. D130 opened it four→five on a measurement and
  **closed it again in the same act**: *"additions beyond five remain a
  decision, not a code change"* (`D18…:1144-1151`). D132 then **built and
  refused a sixth export at 146 B and 0.0199 ms**, routing its datum to a fifth
  *member* of the returned document instead (`D18…:1155-1158`).
- **The guard that enforces the closed list checks names only.**
  `scripts/wasm-boundary.mjs:86-103` filters `Object.keys(module_)` for
  functions and compares against a name array. **Arity and signature are
  invisible to it.** Widening `verify(bundle_bytes)` to `verify(bundle_bytes,
  key)` would change the boundary and leave the guard green — the one boundary
  change the rule cannot see.
- Per-export cost is measured twice in this repository: D130 §(d) `:207-211`
  prices the module at **1 841 981 B** with four exports, **+3 678 B (+0.200 %)**
  for an export carrying new content, **+31 772 B (+1.725 %)** for two, gzip
  586 027 → 597 055, **import table unmoved at 3 shims**; D132's pure-glue
  sixth export cost **146 B**.
- **Network posture, corrected.** `verifier-web/index.template.html:6` sets
  `default-src 'none'; script-src <two sha256 hashes> 'wasm-unsafe-eval';
  style-src <hash>; img-src 'none'; connect-src https:; base-uri 'none';
  form-action 'none'`. D129 §5 R6 (`:705-718`) rules `connect-src https:`
  **scheme-only and deliberately not a host allowlist**, because §1 (m)
  (`:352-368`) measured that an allowlist breaks spec line 137's
  user-overridable endpoints **undiagnosably** — the page sees an identical
  `TypeError` either way and D66 §3 R4 forbids it naming a cause. D66's status
  line records all six pinned endpoints as browser-usable. The page therefore
  **can** address any `https:` origin; it happens not to on the offline path,
  which is what D129's zero-request assertion measures.
- R18 (`tasks/R.md:217-229`) freezes the **verdict wording set** and asserts at
  `:227` that *"CLI and page sources contain no verdict-wording literals outside
  the table"*. Unlock copy — box labels, wrong-card text, escalation prose — is
  **not verdict wording**, so it neither moves an R18 string nor violates R18's
  grep test. The page's real copy freeze is mechanical, not editorial: any
  inline-script edit changes a CSP `script-src` hash and forces the R25
  recompute.

### 1.3 The crypto the wrap would actually use

- **AEAD**: XChaCha20-Poly1305, 24-byte nonce (`unit_aead.rs:103`), 32-byte key
  (`UnitKey = Key32`, `:92`; `Key32` declared `material.rs:151`, `Key32::LEN ==
  32` asserted `material.rs:409`). *"No public API accepts a caller-supplied
  encryption nonce"* (`:23-26`).
- **Not key-committing, and the rule is frozen**: `unit_aead.rs:50-56` —
  *"no verdict-bearing check relies on a ciphertext decrypting to a unique
  plaintext … A future refactor MUST NOT drop a content commitment in favor of
  trusting the AEAD"* — machine-checked by `security_assumptions_drift.rs`
  (`:58-63`). And `:67-72`: on authentication failure the AEAD *"cannot and
  must not distinguish which"* of wrong key / wrong nonce / wrong AAD /
  tampered ciphertext occurred.
- **No derivation path is free**: `hkdf.rs:21-30` lists exactly eight labels;
  `:32` *"The registry is **frozen**: adding a label is a format event"*;
  `:41-42` *"No public API accepts a label string; the registry is the only
  path"*. `blake3::derive_key` and `blake3::keyed_hash` are used **nowhere** in
  the workspace (0 hits). A fresh random K used **directly** as the AEAD key is
  the only construction that touches neither W nor the registry.
- **The container precedent** is `crates/antseal-cli/src/vault/export.rs:7-17`:
  `MAGIC (20 B) ‖ canonical CBOR array(2) [format_version, body: bstr] ‖
  XChaCha ct, AAD = MAGIC ‖ header`.
- **The decoder refuses trailing bytes**: `codec/decode.rs:269-274`
  (`TrailingBytes`), `:331` (`cbor-trailing-bytes`), `:730-738` (the
  fully-consumed assertion), test `:1088`. A padded plaintext handed to the v1
  parser fails; padding needs explicit framing.
- **Padding already has a ruled home**: `crypto/padding.rs` — the C8 formula
  `padded_length(n) = ⌈(n+1)/256⌉·256`, `PAD_BLOCK = 256` (`:41`), stripping
  **length-first, never by scanning**, with `PaddingLengthMismatch` and
  `NonZeroPadding` rejections. Its own §*What padding does and does not hide*
  (`:21-30`) calls the result *"cheap defense-in-depth … not a full fingerprint
  defense"* and states plainly *"Bundle recipients see true lengths by
  design"*; `:33-38` scopes the formula to the format version and names Padmé
  as the successor if fingerprinting data ever justifies the cost.
- **Zero encoding crates**, re-measured at recording: `Cargo.lock` holds 772
  packages and **0** each of `bech32`, `bip39`, `base32`, `slip39`, `mnemonic`,
  `qrcode`. Ruling 5 of the round confirmed.

### 1.4 The encodings, recomputed here

From the round's fixed example entropy
`000102…1e1f` (a published test-vector pattern, never a production key), using
Python's `hashlib` — nothing imported from the round:

```
SHA-256(entropy) = 630dcd2966c4336691125448bbb25b4ff412a49c732db2c8abc1b8581bd710dd
first byte       = 0x63                       ← round doc: 0x63 ✓
CS = ENT/32 = 256/32 = 8 bits;  256 + 8 = 264 = 24 × 11 exactly
indices = [0,64,1030,64,643,28,257,266,88,771,540,241,
           8,1096,610,1045,176,1478,50,417,1422,116,963,1891]   ← identical to the round's ✓
max index 1891 < 2048 ✓ ; the duplicate at positions 2 and 4 is index 64 in both ✓
128-bit alternative: CS = 4, 128 + 4 = 132 = 12 × 11 exactly
```

**What could not be verified here, and why it matters:** the *words*. There is
no `english.txt`, no wordlist of any kind, and no BIP39 crate anywhere in this
repository (`find` + `Cargo.lock`, both negative). Index → word is therefore
still the round's measurement against a wordlist fetched into a scratchpad that
no longer exists. Under the round's own wrong-medium rule — the one that barred
SLIP-39 because two from-memory implementations disagreed at list index 16 —
**this record states no word string and no wordlist hash as verified.** §2 R10
names the gate that closes it.

### 1.5 Real bundle sizes

Extracted from `testdata/vectors/v1/bundle/bundle.json`
(`expect.cases[].bundle_bytes`, hex, ten cases):

| case | bytes |
|---|---:|
| one-byte-fine-tree-full-reveal | 932 |
| empty-anchor-unanchored | 936 |
| covered-unit-partial-reveal | 1 095 |
| leaf-level-cover-partial-reveal | 1 146 |
| nothing-revealed | 1 228 |
| full-file-reveal-with-mirror | 1 440 |
| noncovered-unit-reveal | 1 619 |
| every-anchor-kind-no-receipt | 2 911 |
| every-anchor-kind-with-receipt | 3 033 |
| whole-work-reveal | 9 397 |
| **total** | **23 737** |

Confirms the round's 932–9 397 span. The wrapper adds a **constant**: 20 B
magic + a small CBOR header + a 16 B Poly1305 tag, so a locked file's size is
its bundle's size plus a publicly known offset.

---

## 2. The ruling

### §2 R1 — The unlock primitive is a pure transform on both surfaces, and `verify` stays the single verdict authority

Unlock takes `(locked bytes, key)` and yields **the inner v1 bundle bytes**.
It does not verify. Verification remains `verify`'s, unchanged, on both
surfaces: on the CLI the recipient's second step is the existing `verify`; on
the page the JS feeds the returned bytes into the existing `verify_rendered`.

Three measured reasons, not one:

1. **It keeps the verdict band intact.** `tests/exit_codes.rs:135-168` asserts
   that any class in `40..=43` is `verify-`-named. An unlock command that also
   produced a verdict would have to mint verdict-bearing codes outside that
   band or take `verify-` names it does not own. The pure transform's failures
   (not a locked file, wrong key, bad words) are disjoint from verdicts.
2. **It keeps one authority per fact.** `verify_out.rs:120` is documented as
   *"the only expression in the CLI that turns a verdict into a code"*. A
   verifying unlock would be a second.
3. **It makes the CLI and the page the same design.** The same
   bytes-in-bytes-out primitive serves both, so the card's two routes cannot
   diverge in what they mean.

The cost is one extra step for the recipient. The mitigation is copy, not
architecture: the card already names one route ("drag the file onto
antseal.org — or the offline copy"), and on that route the two steps are one
gesture.

### §2 R2 — The CLI amendment is a **vault-free transform pair**, not a mode on `reveal`

**Overturns the round's `reveal --lock` lean.** Two new top-level commands: one
that takes a finished `.sealproof` and emits a `.sealproof.locked` plus the
card material, one that takes a `.sealproof.locked` plus a key and emits the
bundle. Neither opens the vault; both join `verify` in the third-party,
no-vault family.

| | `reveal --lock` | transform pair |
|---|---|---|
| vault required to lock | **yes** — `commands.rs:665-667` opens it before anything | no |
| can lock a bundle produced earlier / by someone else | **no** — requires re-running an irreversible-disclosure command with the vault | yes |
| frozen lines mutated | reveal's `-o` default (`snapshot:280`) becomes flag-conditional; reveal's `Commands:` summary and prompt matrix both grow | **none** — reveal's block is untouched |
| new blocks appended | one command block + one flag | two command blocks |
| MORTSAFE fit | kit-builder must hold the vault | a kit-builder who is not the sealer can lock (memo L37's 1-of-1 outer, as intended) |

**The one property `reveal --lock` would buy, examined and found not to be
required**: with a lock mode the plaintext bundle need never touch disk. But
the sealer's machine already holds W, the vault and the source files — strictly
more sensitive material — so a plaintext copy of a disclosure the sealer chose
to make adds no meaningful exposure *there*. The locked file exists to protect
the bundle **elsewhere**. The residual is documentation-level: the lock
command's output copy should say the plaintext copy still exists.

**Naming is constrained, and the round's own spelling fails one constraint.**
`--wrap` is taken by D50's W-wrap registry (`snapshot:79-84`), so `wrap`/
`unwrap` are refused outright. `unlock` already means **the vault unlock** in
three places of the frozen help (`:84`, `:333`, `:355`), so a command spelled
`unlock` would be the product's only command whose name contradicts its own
help text. The v1.1 round picks the spellings **within these constraints**;
this record refuses to mint names it cannot test against a written help page.

### §2 R3 — What U32 must freeze is a policy, not a surface. These are the three reservations.

The v1.1 planning round runs **after** U32 (U32 is M4; implementation is v1.1),
so U32 cannot freeze a surface that does not exist yet. It can, and must,
freeze promises that make the later addition **purely additive**:

1. **The exit-code table is append-only.** New classes take unused codes; no
   assigned code is renumbered, reused or repurposed. **Do not take 44–49** —
   `tests/exit_codes.rs` reserves that band for D69 §3 R9's named verdict
   futures, and the assertion reddens on misuse. The lock/unlock classes are
   ordinary process outcomes and belong outside the verdict band.
2. **Tier C is promised as stable-additive, not exact.** `machine.rs:65` today
   promises tier C nothing *"until U32"*. If U32 freezes it as an exact
   document, every later member is a break. If U32 promises it under D65 tier
   B's own words — no key renamed, removed, retyped or moved without an
   `ENVELOPE_VERSION` bump, new keys addable without one — then v1.1 adds
   members legally.
3. **The release docs state that the command set may grow additively in a minor
   release.** U1's *"Nothing else joins the surface"* (`tasks/U.md:13`) is a
   statement about MVP scope; without an explicit growth sentence a reader takes
   the U32 snapshot as a closed set and v1.1's two commands read as a break.

**Declaring the commands early is refused.** U1's idiom — later-milestone
handlers returning *"not implemented until M<x>"* so the surface never drifts —
was designed for milestones *inside* MVP. Shipping the **release** binary with
two commands that refuse to work advertises a feature the product does not have,
and U32's own Accept row demands *"the release binary's `--help` snapshot
matches the frozen canonical surface exactly"*. Reservations cost nothing and
mislead nobody.

### §2 R4 — `verify` gains detection, never interaction — and it needs no frozen surface to move

The round ruled out verify-auto-detect-**with-prompt**. This record rules in
verify-auto-detect-**with-refusal**, which is a different thing and is
compatible with the frozen contract: refusing is not prompting.

On a file whose first 20 bytes are the locked magic, `verify` should say so and
stop. Measured, the cost of that is **zero frozen surface**:

- the **exit code does not move** — it is 40 `verify-bundle-rejected` today and
  stays 40; D69's own idiom is *"the specific `VerifyError::code()` rides in the
  message, never in the integer"* (`tasks/U.md:31`);
- the **message is explicitly rewordable** — `machine.rs:56` and the tier-B row
  at `:64` place `message` outside the compatibility promise;
- the **error-code string universe is append-only** —
  `docs/testing/error-code-contract.md` §3, so a new identifier for
  *"this is a locked proof, not a broken one"* is a legal addition rather than a
  format event.

So the sentence a recipient reads can be fixed in v1.1 without reopening
anything U32 froze. **This is the specific finding that shrinks the register's
pre-U32 collision**, and it is the reason §2 R3 is a policy rather than a
redesign.

### §2 R5 — The key never transits argv. Both commands declare an fd channel; the typed-back guards hand transcription only

`cli-surface.help.txt:30` states the house rule as a frozen promise:
*"Secrets never transit argv or the environment."* A 24-word key is secret
material, so `--words "abandon amount …"` is **refused now**, before anyone
proposes it. The declared non-interactive channels are file descriptors, on
D41's precedent, and both inherit U33/D72's Windows non-stdin-fd wrinkle.

**The round's mandatory full 24-word typed-back is a guard on *hand
transcription*, and it applies exactly where hand transcription happens.** When
K is written to or read from a file descriptor there is no hand copy to
mis-copy, and requiring a typed-back there would be ceremony rather than
safety. Stated explicitly so that a future implementer neither weakens the
interactive path nor invents a hollow re-entry for the machine path.

### §2 R6 — D51's prompt-class partition does not fit, and pretending it does would mis-name an abort

`machine.rs:195-209` closes prompt classes at four, and the enum's own doc
binds `Authentication` to *"the vault passphrase"* with the abort class
`passphrase-unavailable`. A recipient opening a locked file **has no vault**;
aborting their run with `passphrase-unavailable` would name a thing that does
not exist in their world. Neither `Consent`, `Configuration` nor
`DestructiveConfirm` fits either.

**Ruling: a fifth prompt class is required, and minting it is an amendment to
D51 that lands with its subject at v1.1** — not a stretch of an existing class.
Recorded now because the registry rides an exhaustive `match` (`machine.rs:136-141`)
and the abort-not-hang harness enumerates commands × machine-mode flags: the
class, its channel and its abort code move together or the harness fails, and
the abort code is a row in the append-only table §2 R3 R1 governs.

### §2 R7 — `label` is a bounded `uint` card number, not free text

**Overturns the round's `tstr` field defaulting to `"card 1"`.** The header
carries a card **number** (a small unsigned integer, default 1), authenticated
by the AAD like every other header byte, and the page renders it as *"this file
opens with card N"*.

The round's own red team found the defect — *"plaintext label leaks recipient
identity if mirrored"* — and the round answered it with a non-identifying
default plus a rubric warning on the card. **That is a documentation control
over a permanent, immutable, potentially public artefact.** Users will type
`for Alice` and `mum's will` into a free-text field, and no gate in this
project can see it. A `uint` makes the leak **unrepresentable**, which is the
same move the codebase makes everywhere else it can (`Nonce24` has no slice
constructor; HKDF has no label-string API).

It loses nothing the design needs. The wrong-card triage the label exists for
works identically on a number. Free text belongs on the **card**, which is
paper, private, and the one artefact in this design that is never published.
Two secondary gains: a `uint` encodes in one or two bytes regardless of content,
so it cannot vary the file's length; and it removes a UTF-8/normalisation
surface from an adversarially-parsed header.

### §2 R8 — No padding in locked-v1. The size relationship is stated instead.

The ciphertext length equals the bundle length; the locked file's length equals
that plus a publicly known constant. An observer therefore learns the bundle's
size, which correlates with **how much was disclosed**. Priced against the ten
real bundles of §1.5:

| scheme | total cost | distinct size classes for the 10 vectors |
|---|---:|---:|
| none (ruled) | — | 10 |
| C8's own formula (⌈(n+1)/256⌉·256) | **+1 095 B (+4.6 %)** | 6 |
| power-of-two buckets | **+13 127 B (+55.3 %)** | 4 |
| 16 KiB floor | **+140 103 B (+590.2 %)** | 1 |

**Every row buys less than it appears to.** The informative content of a
bundle's size is its *magnitude* — "one unit revealed" versus "the whole work" —
and the cheap scheme hides only the low 8 bits of it, while the scheme that
collapses this corpus to one class costs nearly 6×. Worse, none of them
generalises: bundle size is dominated by revealed unit ciphertexts and is
therefore **unbounded**, so no bucket scheme with tolerable overhead hides a
100 MB reveal beside a 1 kB one. Size privacy for a variable-length payload is
a property of a transport, not of a file format.

Padding would also buy a new parse surface. `decode.rs:269-274` refuses trailing
bytes, so a padded plaintext needs explicit framing: either a cleartext length
(self-defeating — it republishes the very number the padding hides) or a
strip step that reads the CBOR item's own end offset and then validates the
remainder. That is implementable, and C8's two rejection classes would carry
over, but it is a new adversarially-reachable step bought for a leak it does
not close.

**Growth path**: not a reserved key. `format.rs:115` and its append-only
contract, and `padding.rs:33-38`'s own precedent (*"a future format version may
adopt a coarser scheme (e.g. Padmé)"*), say the same thing — a later
`locked-v2` adopts padding wholesale if fingerprinting evidence ever justifies
it. **The leak is routed to Q21's threat model as a named, documented property**
and to Q24's custody prose, not hidden.

### §2 R9 — No key-commitment field in locked-v1, on its own argument

The round left kc *"weighed-not-adopted"*. This record refuses it on grounds
argued here rather than inherited:

1. **There is no sanctioned way to derive it.** The HKDF registry is frozen at
   eight labels with no label-string API (`hkdf.rs:32`, `:41-42`), so a
   registered derivation costs a **format event**; and `blake3::derive_key` is
   used nowhere in the workspace, so an ad-hoc hash of a raw AEAD key would be
   this project's first unlabelled derivation — precisely the
   domain-separation smell it designs against.
2. **The threat it defends gains an attacker nothing here.** Key commitment
   defeats a ciphertext crafted to open validly under two keys. In this format
   the plaintext must be a **fully verifying v1 bundle** carrying its own
   commitments and signatures, and `unit_aead.rs:50-56` already forbids any
   verdict resting on AEAD uniqueness. A two-key ciphertext therefore yields
   two independently valid bundles — which the sealer could simply have sent as
   two files.
3. **Accidental wrong keys are already caught.** A random wrong key fails
   Poly1305 with overwhelming probability, and the triage kc would add
   (wrong card versus wrong file) is already served **outside** the ciphertext
   by the card's echoed card number and the file-check line.

**What refusing kc costs, stated because it is not nothing** (§2 R11): the
tag-guided repair scan must run a tag check per candidate, so its cost scales
with the file. If a future round decides that is unacceptable, the two
mechanisms to weigh are (a) a registered-label commitment, paying the frozen
registry's format event, and (b) an **empty-plaintext AEAD check block under a
second nonce** — ~40 bytes, no new primitive, no registry event, a wrong-key
*detector* rather than a binding commitment. (b) was not on the round's list and
dominates (a) on cost; neither is analysed in depth here.

**Rider that must survive**: whatever happens, the verdict never rests on the
unwrap succeeding. Unwrapping is transport; the verdict is v1 verification.

### §2 R10 — BIP39-24 is ratified, and 256 bits is argued rather than inherited

Ratified on §1.4's recomputation: **24 words = 256 entropy + 8 checksum = 264
bits = 24 × 11 exactly**, and the wrap's key is **exactly 32 bytes**
(`material.rs:409`). The fit is exact in both directions — no truncation, no
expansion, **no derivation step at all**, which is what lets K be used directly
as the AEAD key and touch neither W nor the frozen label registry.

**The recorded 128-bit challenge (codex32-48, or 12 words) is answered, not
inherited.** Two reasons:

1. **It is not free.** 128 bits of paper secret must be expanded to a 32-byte
   AEAD key. The only sanctioned expansion is HKDF, whose registry is frozen at
   eight labels — so 12 words costs a **format event** and converts a design
   with zero crypto machinery into one with a derivation step. The saving is
   ~65 hand-written letters (12 words at the round's measured 5.404 mean).
2. **It is the wrong side of this project's own posture.** A permanent,
   deliberately-public ciphertext on a decades horizon, in a product that pays
   for hybrid ML-DSA-65 signatures precisely because it takes that horizon
   seriously, should not carry a symmetric key whose margin under the standard
   quadratic search speedup is 64 bits. 256 bits keeps the effective margin at
   128.

**The gate this ratification does not clear, named exactly.** Every word string
and the wordlist's pinned SHA-256 remain the round's measurement. The blocking
step is mechanical and belongs to the v1.1 codec row: **commit `english.txt` as
repo data, hash the committed file, and reproduce the round's 24 words and its
199/49 128 substitution-miss enumeration against the committed copy** (with the
Q29 provenance/licence note). Until that file is in the tree, no record in this
repository may state a BIP39 word or wordlist hash as verified.

**English-only in v1 — probe 5 answered analytically, as the addendum
anticipated.** The decisive point is structural: multiple wordlists force the
unlocker to know *which* list a card uses, and putting a language tag in the
header would place a **demographic identifier in cleartext on a public-forever
file** — reintroducing precisely the leak §2 R7 removes. The growth path
therefore is not a header field: the **card** names its list (it already names
its standard), and the CLI/page offer a selector. Non-English support stays
additive and leak-free, and the decimal check-digit fallback stays recorded,
unscheduled, and with its premise named — an audience that cannot handle
English words but can handle an English-language product is a thin population.

### §2 R11 — Page key entry: the shape is a sixth boundary entry, both pinned probes are re-specified, and the authorising question is not page size

**The shape, decided on evidence already in the tree.** Between the round's two
arms — a new export versus widening an existing one — **widening is refused**:

- it is **invisible to the guard** that exists to police the boundary
  (`wasm-boundary.mjs:86-103` compares names, never signatures), so the one
  change the closed-list rule cannot see would be the one chosen;
- it makes `verify` **key-aware**, which is the page-side form of exactly what
  the round ruled out on the CLI (ruling 7). `verify` is the key-free
  third-party entry point on both surfaces or on neither.

So unlock is a **sixth entry**, returning the inner bundle bytes (§2 R1). Two
consequences are recorded rather than glossed: it is the first entry that does
**not** return the report's canonical bytes, so D18 §5 R4's wording must be
amended, not merely extended; and D132 has already refused a sixth export once.
That refusal does **not** bind here, and the reason is structural: D132's datum
could ride as a **member of a returned document**, whereas unlock needs a new
**input** — the key — which no existing export accepts and no return-shape
change can provide. **The D18 amendment lands with its subject at v1.1**, on
D130's precedent of amending in the same commit as the code; this record rules
the shape, not the amendment.

**Probe 2 is re-specified.** As written it measures page-size delta and
CSP-hash churn *between the two arms*. Both arms compile the same unlock code
and the same ~13 kB wordlist (2 048 words at the round's measured 5.404 mean,
plus separators); the arms differ by roughly one export's glue, **measured at
146 B by D132** — about 0.008 % of a 1.84 MB module — and both edit the inline
script, so both produce exactly **one** recomputed CSP hash. The observable
cannot discriminate the arms it was specified to decide. What it should measure
is the **absolute** cost of adding unlock at all (module delta, gzip delta,
import table unmoved at 3 shims) plus `verifier-page-browser.sh` green in
Chromium and Firefox — the D129/D136 file:// parity gate.

**Probe 3 is answered structurally and its benchmark re-specified.** A failed
tag check does not decrypt: it MACs the ciphertext. So the repair scan is
**24 × 2 048 = 49 152 checksum evaluations** (free) yielding ~**192**
checksum-passing candidates, each costing one Poly1305 pass over the whole
file — i.e. **Θ(192 × |file|)**:

| ciphertext | MAC work | ~at 300 MB/s | ~at 1 GB/s |
|---|---:|---:|---:|
| 932 B (smallest vector) | 179 kB | <1 ms | <1 ms |
| 9 397 B (largest vector) | 1.8 MB | ~6 ms | ~2 ms |
| 1 MB reveal | 192 MB | ~0.64 s | ~0.19 s |
| 100 MB reveal | 19.2 GB | **~64 s** | **~19 s** |

The probe as specified — *"over kilobyte bundles"* — would have measured the
top two rows, concluded "trivial", and licensed page copy promising repair that
becomes a minutes-long freeze on a large reveal. **Ruling: no page or CLI copy
may promise repair timing or guaranteed repair; the copy must stay true at
every file size, and the benchmark must sweep sizes rather than sample one.**
(These are structural byte counts and throughput arithmetic, not an in-browser
measurement; the sweep still owes real numbers.)

**The authorising question is none of the above, and it is deferred.** The page
that would receive the key is a document whose CSP permits `connect-src https:`
to **any** origin (§1.2, D129 §5 R6), holding two live `fetch()` sites for D66's
opt-in overlay. Everything the page has ever handled is **already-disclosed**
material: a bundle is built to be given away. **A paper key is the first secret
this page would ever hold**, and it would hold it in a network-capable
document. Nothing in the round weighed that, because the round believed — as
this lane's brief did — that the page could not reach the network.

**Blocking question, and the medium that resolves it:** may the unlock flow run
in the same document as the overlay's `connect-src https:`, and if not, what
separates them? The candidate arms are (a) accept it, resting on the CSP's
script-hash pinning, with the card's co-equal offline copy as the real
mitigation; (b) a stricter CSP for the unlock context — measured, not assumed,
since `connect-src` cannot be tightened per-flow within one document and D129
§5 R6 refuses to narrow it globally; (c) a separate document, which collides
with D129/D131's one-committed-source, one-published-file shape. **Medium: a
CSP/isolation experiment run in both engines through
`verifier-page-browser.sh`, plus a threat-model sentence from Q21 — not a
page-size benchmark.** This is a **new** probe the round did not have. Until it
resolves, this record rules the export *shape* and withholds authorisation to
build page key entry.

---

## 3. What this record does NOT decide

- **Any implementation.** The F/C/U/R/Q rows mint at the v1.1 planning round
  with centrally-assigned IDs, per the register. Nothing here schedules code,
  and nothing enters M3 or M4 implementation.
- **The exact command spellings and flag names.** §2 R2 fixes the shape and the
  constraints (`wrap` refused, bare `unlock` refused, no secrets in argv); the
  words are minted at v1.1 against a written help page.
- **Whether page key entry is built at all.** §2 R11 rules the shape and defers
  the authorisation to a named CSP/isolation question. If that question resolves
  against the page, unlock is CLI-only in v1.1 and the round's page-scope
  hostage risk is realised — that consequence is recorded, not hidden.
- **The wordlist itself.** No word string and no wordlist hash is ratified here
  (§2 R10). Provenance and licence stay Q29's.
- **The DMS 2-of-3 share encoding and the KEM lockbox** — reserved to the DMS
  round (memo L102); only the card protocol converges.
- **Public mirroring of locked bundles** — its own consent-gated round. This
  record assumes public exposure defensively and authorises no upload.
- **The v1 bundle format.** `SUPPORTED_VERSIONS` stays `[1]`; the v1 vector tree
  and its `FROZEN.sha256` are untouched. Everything ruled here lives strictly
  above them.

---

## 4. What this ruling owes

1. **A verify-never-prompts guard that can actually fail.** The only behavioural
   check (`tests/verify_command.rs:772`) asserts the absence of the string
   *"passphrase"*. Once a key-entry vocabulary exists in the product, a prompt
   reading *"Enter word 1 of 24"* passes it. `reveal` already has the stronger
   idiom — a source-shape assertion over its caller set and gate argument
   (`tests/reveal_consent.rs:655-660`, `:841-846`). **New
   row candidate (U domain, S):** give `verify`'s handler the same source-shape
   assertion, before any word-prompt vocabulary exists to slip past it.
2. **A boundary guard that pins signatures, not just names.**
   `scripts/wasm-boundary.mjs:86-103` cannot see arity or type changes, so the
   closed-list rule that D18/D130/D132 spent three records enforcing has a hole
   exactly where §2 R11's refused arm sits. **New row candidate (R or Q domain,
   S):** assert each export's arity, with a planted fault per rule.
3. **The three U32 reservations of §2 R3**, which are U32's own edit set:
   append-only exit codes, tier C promised stable-additive, and a
   surface-may-grow sentence in the release docs.
4. **Q21/Q24 custody prose** must gain the §2 R8 sentence: a locked file's size
   is its bundle's size plus a constant, and that discloses roughly how much
   was revealed.
5. **The CSP/secret-context probe of §2 R11** — a new probe, owned by the v1.1
   round, blocking page key entry and nothing else.
6. **A correction to the round doc's `tasks/U.md:19` reading** (informational):
   U68's amendment (ii) has landed — reveal's `-o` line names its default at
   `cli-surface.help.txt:280` — and the frozen snapshot measures 407 lines here
   against the round's 408.
