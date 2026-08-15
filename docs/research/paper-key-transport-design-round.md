# Paper-key locked bundles — OBOL design-round verdict (recorded 2026-08-15)

- **Date:** 2026-08-15. **Kind: design note / research memo — not a decision record.**
  No task row exists for this; the registrar's two same-day edits (a dated paragraph in the
  Committed-v1.1 parking-lot tier, a NEXT-D row under `### Due M4`) point here for the full
  ruling. Every implementation stage still gets its own planning round and decision records
  first, and the round's own decision row is briefed — per house rule — to try to overturn
  this ruling's lean.
- **Provenance:** maintainer-requested adversarial workflow, run 2026-08-15: three
  ground-truth reader reports (the DMS memo · the tracker/register · the code and frozen
  surfaces), three independent designers (LAST WORDS human-factors / EPITAPH crypto-format /
  PALLBEARERS integration-roadmap — "the paper is for hands and phones, not parsers" /
  "the encoding carries its own repair, carved to outlast its tools" / "one format family
  for every paper secret the project will ever hold"), one red team per design, one
  synthesis judge, and this recording writer. The dossier reached the writer as structured
  JSON and lived otherwise only in session-local storage; the round's computation scripts
  (`codex32_encode.py`, `verify_codex32_adversarial.py`, `slip39_calc.py`, the fetched
  `bip-0093.mediawiki` and BIP39 `english.txt`) sit in the session scratchpad and die with
  it. **This document is the round's sole durable record**; a resume recipe for the
  measurements is included below.
- **Vet status:** vetted at recording, same day. The judge's ruling in the numbered
  sections below is rendered with its claims and wording preserved — quoted phrases are
  verbatim from the dossier — and is NOT corrected in-line; every correction lives in the
  appended "Vet findings" section, whose load-bearing numbers were **re-measured by the
  writer's own independent implementation**, not transcribed.
- **Consent boundaries, restated at recording:** nothing external was touched — no upload,
  no publish, no registration, no firm contact, no funds. Network activity was limited to
  fetching two public specification documents read-only (BIP-93 mediawiki source; the
  canonical BIP39 English wordlist) for verification. The only repository writes are this
  file (writer lane) and TODO.md (registrar lane, single-writer, separately briefed).
  **REQUIRES MAINTAINER ACTION:** committing this file — and the still-untracked
  `docs/research/dms-mortsafe-design-round.md` beside it (hygiene debt the ground-truth
  read re-flagged). Public mirroring of locked bundles remains consent-gated and untouched.
- **Evidence labels:** **(M)** measured this round (command/computation ran, output
  captured), **(D)** documentation/register claim with a cite, **(I)** inference. Planted
  faults are recorded with whether they *fail for the right reason*.

---

## The question, and the lean under trial

The user's words, verbatim, are the round's binding axes: *"my main priority is that it's
an option to share decryption methods on hand-written paper (so presumably some sort of
key)"* and *"not all our users will be technical enough for a CLI unlock."* Hard
constraints: the paper artifact is HAND-WRITTEN and must stand alone (a printed-QR sibling
may exist later); the v1 `.sealproof` format is frozen (changes go above it); the CLI
surface is frozen under U1 (any change is a decision); the verifier page is one
self-contained file (D129) and its scope growth is a decision; `W` is never shared; the
horizon is decades — paper in a drawer for years must stay decodable.

**The register's prior lean**, which this round was briefed to overturn: a "locked-bundle
wrap" — `reveal` gains a mode that AEAD-wraps the finished `.sealproof` under a fresh
random 32-byte key K; K is printed in a checksummed human-carriable encoding, *lean:
bech32m, ~60–66 chars*; the locked file travels any channel; K travels by paper/phone.
Claimed to double as the MORTSAFE outer lock at Shamir 1-of-1. An earlier round had
already rejected a "capability string" arm (k_m + address + per-unit keys; recipient
fetches from Autonomi).

**Outcome in one line:** the wrap half of the lean is CONFIRMED unanimously; the bech32m
half is OVERTURNED — the ruling is twenty-four numbered BIP39 words on a hand-written
card, with every surviving red-team organ grafted on. Both rival red teams independently
conceded the word medium; the judge's grade for the winning arm's worked example is (M),
re-verified a fourth time at this recording.

## Ground truth measured this round

### The frozen surfaces the design must live above

- **(M)** v1 bundles are self-contained: the plaintext manifest envelope, the
  `storage_record {address, nonce, k_m}`, both anchor arrays, and per-reveal `k_u` **plus
  the ciphertext itself** ride inside the bundle; offline verify fetches nothing. The k_m
  disclosure rationale is explicit: *"Disclosing it costs nothing: the bundle already
  embeds the plaintext manifest"* (docs/format/registry-v1.md:818); *"the unit key,
  disclosed per reveal so the verifier decrypts without ever holding `W`"* (:981). Golden
  vectors span 932–9,397 B; D129 measured a real 7,981 B bundle. One chunk, ~400×
  headroom under the 4 MiB cap.
- **(M)** v1 has no ASCII magic — the file IS a canonical CBOR map read at key 0
  (`VERSION_KEY = 0`, format.rs:124); `SUPPORTED_VERSIONS: &[1]` (format.rs:115);
  released versions never change, futures append. Unknown version = named refusal
  (format.rs:239).
- **(M)** CLI freeze: `cli-surface.help.txt` (408 lines) pinned by `tests/cli_surface.rs`;
  *"Nothing else joins the surface; the snapshot enumerates exactly this … the surface is
  frozen from day one"* (tasks/U.md:13). `reveal` has **no** lock mode (reveal_out.rs:298
  is a vault-lock comment; the snapshot's three "lock" hits are keyfile/vault-export
  prose). `verify` is *"third-party; needs no vault and never prompts"* — frozen snapshot
  text at :14 and :295 — and D51 widened it: *"machine mode never prompts for anything"*
  (tasks/U.md:694). Sanctioned amendment path with precedent: a decision doc amends U1 and
  the snapshot is re-frozen in the same act (D39/D41; D68 — tasks/U.md:13,19).
- **(M)** Page: one committed source, `verifier-web/index.template.html` (D131);
  one published file whose CSP `script-src` is locked to the two inline-script SHA-256
  hashes + `'wasm-unsafe-eval'` (template:6) — a one-byte payload edit makes the browser
  refuse to run the page (D129 §1k). file:// parity measured in Chromium+Firefox, report
  byte-identical to native, exactly one network request (D129 §1g,i). Today's UI is a
  `.sealproof` drop zone + file picker only (template:57-59); footer digest =
  `__ANTSEAL_MODULE_SHA256__` (template:136).
- **(M)** WASM already contains the cipher: the shipped module compiles core's
  XChaCha20-Poly1305 decrypt — `pub fn decrypt_unit_with_key` (unit_aead.rs:278), the
  verifier-side seam where keys arrive **explicit and bundle-supplied, never W** — reached
  from the verify exports via api.rs:85-87. The export surface is a closed list of six
  `pub fn`s: `start` :42 (the `#[wasm_bindgen(start)]` init hook, attribute at :41),
  `verify` :59, `verify_online` :74, `verify_rendered` :91, `verdict_class` :102,
  `build_info` :116. Growth is a D18 §5 R4 event; D130 added one export; D132 refused one.
- **(M)** AEAD/keys: XChaCha20-Poly1305, 32-B key, 24-B nonce (`Nonce24::LEN = 24`,
  unit_aead.rs:103), `chacha20poly1305` =0.11.0 default-features off (injected-RNG only).
  *"No public API accepts a caller-supplied encryption nonce"* — structural single-use
  rule (unit_aead.rs:23-26). The cipher is **not key-committing** and the rule is frozen:
  *"no verdict-bearing check relies on a ciphertext decrypting to a unique plaintext …
  A future refactor MUST NOT drop a content commitment in favor of trusting the AEAD"*
  (unit_aead.rs:48-56). The HKDF-SHA256 label registry is **frozen at 8 labels**:
  *"The registry is frozen: adding a label is a format event"* (hkdf.rs:32-33) and
  *"No public API accepts a label string; the registry is the only path"* (hkdf.rs:41-42)
  — so a fresh random K used **directly** as an AEAD key touches neither W nor the
  registry, and matches the explicit-key verifier pattern. Zeroizing key types exist
  (`Key32`, `SecretBuf`). Genuinely secret material per reveal is ~100–200 B order
  (k_u 32, unit_salt 16, file_salt 16, s_root 32, k_m 32 — registry §2; (I) on per-case
  sums).
- **(M)** Outer-wrapper precedent — the vault export (crates/antseal-cli/src/vault/
  export.rs:7-17): `MAGIC ("ANTSEAL VAULT EXPORT", 20 bytes — the Q2-reserved literal;
  its ONE sanctioned source occurrence is this module, recorded in the secret-guard lane's
  exclusion) ‖ header: canonical CBOR array(2) [format_version: uint, body: bstr]` where
  body v1 = `map {0: kdf_block, 1: nonce (24 B)}`, `‖ ciphertext … AAD = MAGIC ‖ header`.
- **(M)** Secret-guard interaction: the Q2 guard hard-fails on registered file signatures
  — *"No real secret material may ever be committed"* (scripts/ci-lanes.sh:1139; guard
  block :1042-1142, planted-fake self-test at :1115). A new magic naively joining that
  fail-list turns the gate red on its own committed vectors. Found independently by two
  red teams.
- **(M)** Encoding dependencies: the 772-package Cargo.lock has **zero**
  bech32/bip39/base32/slip39/mnemonic/qrcode packages (re-grepped at recording: 0 hits);
  no antseal Cargo.toml declares an encoding crate; hex rendering is in-house. In
  antseal-core/Cargo.toml: `blake3` :53, `chacha20poly1305` :54, `hkdf` :60, `sha2` :81
  are **normal** deps; `hmac` :95 sits under `[dev-dependencies]` :91. A new crate is a
  P7 vetting event; the recorded precedent refuses one where in-house suffices
  (testdata/tamper/README.md).
- **(M)** Upload plumbing is content-agnostic (`StorageBackend`, antseal-net
  backend.rs:163; BLAKE3 single-chunk addressing, storage.rs:100, D32) but no command
  uploads an arbitrary blob today, and the real backend is behind the non-default
  `ant-backend` feature. *Public anchor-bundle uploads* is a parked Later item
  (TODO.md:1004) — the entropy tension's premise.

### Three brief corrections (the round's readers vs its brief)

1. *"No self_encryption dependency anywhere"* — **FALSE at the lock**: self_encryption
   0.36.0 is present via ant-core 0.5.0, compiling only in the non-default ant-backend
   graph. True only as "antseal's own addressing never uses it" (D32/D35).
2. *"The verifier surface is five exports (D129)"* — **stale**: boundary.rs holds six
   `pub fn`s (D130 added `verify_rendered`). Cite boundary.rs, not D129, and state the
   counting convention (six pub fns incl. the start hook; five callables in D132's
   vocabulary).
3. *"The blessed additive-outer-wrapper pattern"* — **not a recorded rule anywhere**. What
   exists is the format.rs append-only contract plus the shipped vault-export precedent
   above. Designs cite those, not a nonexistent blessing.

### The DMS memo's bearing (docs/research/dms-mortsafe-design-round.md, fresh read)

- **(D)** Hand-written-priority is continuous with MORTSAFE, not novel: *"Shares are
  hand-copied or written to smartcard, never rendered through a printer pipeline (spool
  files and printer flash leak)"* (L38, generalized by probe 5).
- **(D)** The memo's own gate for exactly this round's concern: *"Recipient-kit cold
  usability: hand kits to non-technical subjects and measure unaided claim success.
  Failure redesigns S_R"* (L81). Its release path names only *"the offline tool"* (L54)
  and its vet says recipient-side opening tooling *does not exist* (L102).
- **(M — negative)** **Total encoding vacuum**: zero occurrences of
  bech32/base32/BIP39/word-list/mnemonic/transcription-checksum in the memo's 206 lines;
  "hand-copied" is the only transcription verb; no medium is ever named for the lockbox
  private key. The lean's bech32m appears nowhere — any encoding is fresh ground this
  sibling doc must argue, and does.
- **(D)** The MORTSAFE outer lock is *"AEAD-wrapped … under a fresh random key R, never
  derived from W. R is Shamir-split 2-of-3"* (L37) — this round's wrap is textually that
  construction at 1-of-1. The inner KEM lockbox is explicitly **not** inherited: *"no
  existing convention covers a KEM, and adopting one is its own decision round"* (L102);
  *"all confidentiality is symmetric AEAD under W-derived keys, and bundles today reach
  recipients in plaintext"* (ibid.).

### The register (TODO.md, measured at recording)

Parking lot :996-1006 — Committed v1.1 tier :998, 2026-08-01 tier :1000, the DMS Later
paragraph :1002 (the registration template this round follows), the Later list :1004
(incl. *public anchor-bundle uploads*), scope discipline :1006. Decision register's
`### Due M4` :962 holds D71/D72/D73 (:963-965) — the file's only three open D rows.
Q237's M3 blocker set is enumerated and closed. Next free IDs: **D134 · F56 · C30 · U73 ·
R87 · Q238** (A135 is a recorded hole; P21/P27/P28 dead — never reuse). Register rule:
an unresolved decision past its due milestone is a blocker — the mechanism the staged
path uses to make the pre-U32 deadline enforceable.

### The encodings, computed — the round's own measurements

All from the fixed example entropy `000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f`
(a published test vector pattern — **never a production key**; production K is drawn
fresh from the CSPRNG per lock).

- **(M, ×4)** BIP39-24: checksum byte = first byte of SHA-256(entropy) = `0x63`; the 24
  indices `[0, 64, 1030, 64, 643, 28, 257, 266, 88, 771, 540, 241, 8, 1096, 610, 1045,
  176, 1478, 50, 417, 1422, 116, 963, 1891]`; words `abandon amount liar amount expire
  adjust cage candy arch gather drum bullet absurd math era live bid rhythm alien crouch
  range attend journey unaware`; the duplicate "amount" at positions 2 and 4 is genuine;
  126 secret letters, a–z only; decode roundtrips byte-identical. Computed by the
  designer, independently recomputed by its red team, re-verified by the judge, and
  **recomputed a fourth time by this writer's own implementation at recording — all four
  agree on every value.**
- **(M, ×3)** Wordlist: the canonical BIP39 `english.txt`, 2048 words, SHA-256
  `2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda` (the widely-pinned
  canonical value; hashed independently by red team and writer). 4-letter prefixes are
  unique across the full list (measured). List mean word length 5.404 → ~130 expected
  secret letters for a random K (the example's 126 is its draw).
- **(M, ×2)** The 8-bit checksum catches 48,929/49,128 single valid-word substitutions;
  **199/49,128 (0.41%) pass it** — exhaustively enumerated by the red team and
  independently re-enumerated by the writer, exact match. Planted faults `bid→bicycle`
  and `bid→bike` both caught — *fails for the right reason*.
- **(M, ×2)** codex32 (BIP-93): the same key encodes to the 74-char string
  `ms10sealsqqqsyqcyq5rqwzqfpg9scrgwpugpzysnzs23v9ccrydpk8qarc0sy57ykxfd6t9jl`
  (threshold "0", ident "seal", index "s"). The designer's encoder exact-matches BIP-93's
  canonical 256-bit vector 4 and validates vector 1; the red team wrote an independent
  **decode**-side implementation: payload decodes to the exact 32-B key; exhaustive
  1-substitution (2,201 mutants) and 2-substitution: zero false accepts; 8-erasure
  recovery exact (one valid fill in 32^8); 200k random garbles rejected. Spec guarantees:
  correct ≤4 substitutions / ≤8 erasures / ≤13 consecutive (BIP-93 L135, L371-373);
  charset has no b/i/o and "1" only in the `ms1` prefix (L166, re-checked at recording);
  uppercase-SHOULD for handwriting (L83).
- **(I — barred as adoption evidence)** SLIP-39: the 33-word structure (20+20+260+30
  bits) and rs1024 arithmetic self-verify (6000/6000 random 1–3-word corruptions
  detected), but the word indices came from memory in **both** independent
  implementations, and they **disagree on the word at list index 16 ("agency" vs
  "again")** — no SLIP-39 wordlist exists on this offline machine. Under the register's
  wrong-medium rule this bars adopting SLIP-39 on this round's evidence; official test
  vectors are the mandatory gate if it returns.
- **(M length / I characters)** The lean's own encoding for the same key:
  `antseal1qqqsyqcyq5rqwzqfpg9scrgwpugpzysnzs23v9ccrydpk8qarc0sgkt827` — 66 dense
  bech32m chars (from-memory BIP-350 constants for the exact characters; the length and
  charset arithmetic are structural). One glyph slip = checksum failure with no specified
  localization. That string is the overturn argument in one line.

**Resume recipe** (scripts are session-local; this rebuilds the measurements in minutes):
BIP39: bits = entropy ‖ first-8-bits-of-SHA-256(entropy), split into 24×11-bit indices
into the pinned english.txt; re-derive the values above. Substitution sweep: for each of
24 positions × 2047 alternative words, recompute the checksum over the mutated entropy
and count passes (expect 199/49,128 for this entropy). codex32: constants from BIP-93
L95-111; verify vectors 1 and 4; decode the 74-char string above. The wordlist must hash
to `2f5eed53…dbda` before use.

## The arms

| Arm | Codename | Origin | Fate |
|---|---|---|---|
| Locked-bundle AEAD wrap above frozen v1 | — (the MORTSAFE outer at 1-of-1) | register's lean, architecture half | **CONFIRMED** unanimously — all three designs and all three red teams |
| bech32m 66-char string | SHROUD | register's lean, encoding half | **OVERTURNED** by all three designs independently |
| BIP39, 24 numbered words | LAST WORDS | design 0 (human-factors) | **WINNER** — grafted final (OBOL) |
| codex32, 74 chars | EPITAPH | design 1 (crypto-format) | runner-up; organs grafted (file-check line, erasure honesty); recorded DMS-share candidate |
| SLIP-39, 33 words | PALLBEARERS | design 2 (integration-roadmap) | runner-up; adoption barred this round by evidence medium; organs grafted (full typed-back, never-prompting CLI, sequencing); recorded DMS-share candidate |
| Capability string (k_m + address + unit keys) | WILL-O'-THE-WISP | earlier-rejected; re-examined per brief | **STAYS REJECTED** — see ruling 1 |
| Passphrase wrap | SHALLOW GRAVE | weighed by all three | **REJECTED** — offline-crackable once a locked file is ever public (:1004); random K is immune |
| SLIP-39 1-of-1 everywhere | — | design 0's red team (no brief listed it) | weighed; loses 33-vs-24 ink, dead-weight group metadata, and BIP39's wider 2046 ubiquity |
| codex32-48 @128-bit | — | design 1's red team (no brief listed it) | recorded challenge: NEXT-D must argue 256-bit explicitly, not inherit it |
| Tag-guided single-word auto-repair | — | surfaced independently by two red teams | **ABSORBED** into the graft |
| Decimal check-digit groups | — | design 0's fallback | recorded fallback if English words fail the audience (probe 5) |
| PGP wordlist · Crockford base32 · diceware · hex+hand-CRC · do-nothing/channel-privacy | — | design 2's sweep | dominated; recorded |

---

# Paper-key transport — synthesis judge's verdict (2026-08-15)

Rendered from the judge's structured dossier with claims and wording preserved (quoted
phrases verbatim); corrections live only in the Vet findings at the end of this file.

---

# 1. EXECUTIVE VERDICT

The winner is **LAST WORDS**, grafted into the final design **OBOL** (an obol is the
small coin set with the dead to pay the ferryman — one hand-carried token that buys the
crossing). The user's own words fix the binding axes: hand-written paper and
non-technical unlock. **Words beat character strings on both, and both rival red teams
independently concede it** — PALLBEARERS' attacker rejects codex32 on exactly the
non-technical-typing constraint, and LAST WORDS' own attacker finds no defeating arm and
calls BIP39 the better decades bet. Among word arms: 24 < 33 words on the priority path,
and LAST WORDS is the only design whose end-to-end example survived at **MEASURED** grade
(the judge recomputed checksum byte `0x63`, all 24 indices, the live duplicate, the 126
a-z letters; its attacker independently confirmed the wordlist pin `2f5eed53…dbda` and
full-list prefix uniqueness), while PALLBEARERS' indices are from-memory with two
implementations disagreeing at index 16 — **the register's wrong-medium rule disqualifies
adopting it this round**. BIP39 is the simplest codec and the widest 2046 recovery bet.

Runners-up on their own red teams: **PALLBEARERS** fell on its own attacker's findings —
its `verify` auto-detect-and-prompt contradicts frozen snapshot text (:14/:295 plus
D51's matrix), and its own worked example could not be verified on this machine.
**EPITAPH** survived its red team technically intact — the best-verified math of the
round — and lost at synthesis on the axis the user's words make binding: 74 dense
uppercase characters with residual 2/Z 5/S U/V ambiguity is the wrong artifact for
non-technical hands. Its genuine advantages (guaranteed correction, erasures, native
Shamir, DMS unity) are partially recovered by grafting tag-guided single-word auto-repair
— which converts the 8-bit checksum's measured 0.41% miss and the localization gap into
tag-arbitrated correction — and its DMS-unity case survives as a recorded candidate in
the round that actually owns share encoding (L102). **SHROUD** (the lean's bech32m) is
overturned: detection-only with no specified correction, a charset that hand-writes
badly, and it optimizes exactly what the AEAD tag already provides free.
**WILL-O'-THE-WISP** stays rejected — see ruling 1. All three designs were fatal-free;
every survivable finding from all three attacks is resolved in the graft (§ Attack
findings).

# 2. THE ARCHITECTURE

**Cryptographic layering:**

1. **Inner — untouched v1.** The finished `.sealproof`, byte-identical inside the wrap
   (format.rs:115/:124; SUPPORTED_VERSIONS stays `[1]`). Zero frozen bytes move; the v1
   vector tree and FROZEN.sha256 are untouched.
2. **Outer — the lock.** New file class `.sealproof.locked` :=
   `MAGIC "ANTSEAL LOCKED PROOF" (20 B) ‖ canonical CBOR header, array(2)
   [format_version = 1, body: map{1: label tstr, 2: nonce bstr(24)}] ‖
   XChaCha20-Poly1305(K, nonce, AAD = MAGIC‖header, plaintext = whole v1 bundle)` —
   the vault-export pattern (export.rs:7-17). **K is a fresh random 32-byte key used
   directly as the AEAD key — no KDF, no HKDF label, never W-derived, never stored**
   (hkdf.rs:32-42: no label-string API exists; the frozen registry is untouched). Fresh
   random 24-B nonce per lock (unit_aead.rs:24-26 no-caller-nonce rule). **No passphrase
   arm**: parked public mirroring (TODO.md:1004) makes low-entropy keys
   offline-crackable; random K is immune. The non-committing cipher rule is honored:
   the verdict is **tag-ok-then-full-v1-verify, never AEAD uniqueness**
   (unit_aead.rs:48-56); no kc commitment field in wrapper v1 — EPITAPH's kc is recorded
   weighed-not-adopted (triage served by label echo + auto-repair; the D-round may
   revisit), and an optional pad-to-bucket field is a D-round question with the
   size-fingerprint note routed to Q21. `label` defaults to non-identifying ("card 1");
   the card rubric warns against personal names (public-mirror identity leak). Unknown
   version = named refusal; decrypted plaintext must parse as CBOR with key 0 = 1. The
   magic joins the Q2 signature registry as **reserved-but-NON-SECRET**
   (publishable-ciphertext class) with an explicit secret-guard exclusion plus a
   planted-fault self-test — naive fail-list membership reddens the gate on committed
   vectors (ci-lanes.sh:1054-1139; found independently by two red teams). Vectors get
   their own root `testdata/vectors/locked-v1/` + FROZEN.sha256 (v1 tree untouched);
   tamper MATRIX rows stay **byte-level** (magic/version/nonce/ct/tag/truncation);
   word/checksum cases are codec golden vectors, not MATRIX rows.
3. **Carrier — the words.** K → BIP39 English, 24 words (256-bit entropy + 8-bit SHA-256
   checksum → 24×11-bit indices). Wordlist = canonical `english.txt` **committed as repo
   data**, pinned SHA-256 `2f5eed53…dbda`, with a license/provenance note (Q29); **zero
   new crates** (Cargo.lock measured clean; the checksum needs only `sha2`, already a
   normal core dep). Concentric checks: **(a)** list membership — a non-word reddens ITS
   box; 4-letter prefixes unique, autocomplete after 4 keystrokes; **(b)** the 8-bit
   checksum — catches ~99.6% of single valid-word substitutions (measured 199/49,128
   misses); **(c)** the AEAD tag — a 128-bit key-vs-file arbiter. **Tag-guided
   single-word auto-repair:** on checksum or tag failure, scan 24 positions × 2048
   words, tag-test the checksum-passing candidates (~200 AEAD trials on a kilobyte
   file); a found repair is SHOWN for confirmation against the card, **never silently
   applied**. This closes both the localization gap and the 1/256 miss. A fully
   unreadable word is the same scan at one position — single-erasure recovery
   guaranteed; multi-word failure escalates honestly ("read each word aloud with its
   number to the sender") with no impossible multi-error localization promises. Scan
   wall-clock is measured in-browser before the page copy promises it (open probe).

**Lock flow (sealer).** `reveal --lock` (exact surface = the D-round) generates K, writes
the `.locked` file, displays the words on an **alternate screen** (no scrollback/tmux
history; cleared after; P5-style no-leak probe with planted fault), and **REQUIRES full
24-word typed-back re-entry validated by checksum+tag before the file is emitted and K is
forgotten** — grafted from PALLBEARERS' red team: a 3-position spot check guarding an
unrecoverable miscopied-card failure is the assertions-that-cannot-fail smell. Re-lock
anytime: fresh K, new card.

**Card flow (paper).** Hand-written ~A6 card, copied from the TTY, never a printer
(DMS L38): "ANTSEAL KEY CARD" header; card-label line (echoed from the wrapper header so
the page can say "wrong card" and name the right one); locked filename (D68 default +
".locked"); optional **file-check line** — first 4 chars of BLAKE3(locked file) in an a-z
rendering, shown by the page on file load so wrong-file is caught BEFORE any typing
(grafted from EPITAPH; blake3 already in core); "open at antseal.org — or the offline
copy beside the file (USB/M-DISC)" with the offline copy **co-equal** (decades/DNS-hijack
hedge); one CLI line; THE KEY: 24 numbered words in a 4×6 grid, **numbering mandatory**
(disarms genuine duplicates — the example's positions 2/4); rubric: lowercase print, only
the FIRST 4 LETTERS must be readable, duplicates are correct, phone read-back WITH
numbers; standard line "24-word BIP39 key — any conforming tool recovers it"
(locked-v1.md gains a recovery-without-antseal section); closing line reworded per red
team: **"this card is the only key to the locked file — anyone holding both can read;
keep the card safe and apart from the file."**

The worked example (fixed test entropy above — never a production key):

```
ANTSEAL KEY CARD
card label:  card 1                    (the file knows this name)
opens file:  antseal-reveal-<work-id>.sealproof.locked
file check:  <4 letters the page shows when you choose the file>
how:         drag the file onto  antseal.org — or the offline copy beside the file
             (or, terminal: one CLI line — exact command is the D-round's)

KEY — 24 words. Small printed letters. Number every word.

 1 abandon    2 amount    3 liar      4 amount    5 expire    6 adjust
 7 cage       8 candy     9 arch     10 gather   11 drum     12 bullet
13 absurd    14 math     15 era      16 live     17 bid      18 rhythm
19 alien     20 crouch   21 range    22 attend   23 journey  24 unaware

* only the FIRST 4 LETTERS of each word must be readable
* yes — words 2 and 4 are both "amount"; that is correct
* checking by phone: read each word WITH its number
* 24-word BIP39 key — any conforming tool recovers it
* this card is the only key to the locked file — anyone holding
  both can read; keep the card safe and apart from the file
```

**Unlock flow (recipient, page).** The file travels any channel (email/USB/M-DISC/
mirror); the card by hand. Page (antseal.org or the offline copy; file:// parity already
measured, D129): drop file → magic sniffed → label + file-check echoed → 24 numbered
boxes mirroring the card; autocomplete; per-box redden; auto-repair with confirm; honest
escalation; success flows into the **unchanged** verify report. Page entry is a D18
closed-list boundary event (six pub fns today, boundary.rs:42-116 — state the counting
convention: `start()` is the init hook, five callables in D132's vocabulary); packaging
re-runs mechanically (R25 CSP recompute, footer digest moves); the R27/Q19 corpus gains
locked cases. Page-side AEAD unwrap needs **no new crypto dependency** — the cipher is
already in the module.

**Unlock flow (CLI).** A separate never-surprising unlock surface (name/shape = D-round);
**verify-auto-detect-with-prompt RULED OUT** — "needs no vault and never prompts" is
frozen snapshot text (:14/:295) plus D51's matrix (U.md:694), and any revisit must amend
that clause explicitly. Key via fd/args with the U33/D72 Windows-fd wrinkle named. All
CLI changes ride **one U1-amendment decision with cli-surface.help.txt re-frozen in the
same act** (D39/D41/D68 precedent, U.md:13,19); the registrar may split the decision into
2–3 D-ids per house precedent.

**DMS convergence.** The card protocol (numbered words, full typed-back at creation,
phone read-back with numbers, page grid, offline copy co-equal) becomes the house pattern
DMS kits inherit, filling the memo's measured encoding vacuum **at the protocol layer**;
the 2-of-3 share ENCODING is NOT pre-ruled — SLIP-39 and codex32 are the recorded
candidates for that round (codex32's native GF(32) Shamir + pencil verifiability vs
SLIP-39's word medium), decided with a P7-style drill. This wrap IS the MORTSAFE outer
construction at Shamir 1-of-1 (L37: fresh random symmetric key, AEAD, never-W) and
deliberately sidesteps the KEM lockbox, which remains its own round (L102). The gift
path does not wait on either.

# 3. SCORECARD

1. **LAST WORDS (BIP39-24, winner):** handwrite BEST (126 a-z letters in the example, no
   ambiguous glyphs, 4-letter sufficiency) · unlock BEST (numbered grid, autocomplete,
   localization; repair graftable) · security equal (random-256 K, tag-arbitrated) ·
   freeze discipline strong (its auto-detect wrinkle caught by its red team) · DMS
   partial (protocol-layer converge, share encoding deferred) · cost LOWEST (table
   lookup + pinned data) · decades BEST (most ubiquitous standard; the example
   re-verified MEASURED) · sequencing strong (D-before-U32 argument). *Weaker spots:*
   the 8-bit checksum passes 0.41% of single valid-word substitutions (closed by the
   auto-repair graft + tag), and raw glyph count is higher than EPITAPH's (~130 letters
   + 24 numerals vs 74 chars) — bought back by per-glyph forgiveness and the 4-letter
   rule; the cold drill arbitrates.
2. **EPITAPH (codex32-74):** handwrite WEAKEST for this audience (74 dense uppercase
   chars, residual 2/Z 5/S U/V) · unlock good but char-typing burden + a 5–8-substitution
   message overclaim (its red team's find) · security equal + the kc triage idea ·
   discipline BEST (never-prompts rigor, counting conventions) · DMS BEST (one format,
   native GF(32) Shamir, pencil-verifiable) · cost mid (in-house BCH corrector) ·
   decades mixed (niche standard; **best-verified math of the round**) · sequencing
   strong (kits-consume-encoding ordering). *Weaker spot:* the audience is the user's
   binding constraint, and both rival red teams reject character strings on it.
3. **PALLBEARERS (SLIP-39-33):** handwrite good (words, but +38% ink vs 24) · unlock
   good (grid + correction assist) · security equal · discipline WEAKEST
   (verify-prompts contradicts frozen :14/:295 text; hmac dev-dep miss) · DMS strong
   (native k-of-n unity) · cost mid+ (dead-weight Feistel/PBKDF2 at 1-of-1, hmac
   promotion edge) · decades good-minus (extendable-fork wrinkle; indices INFERRED —
   two from-memory implementations disagreed) · sequencing BEST (Committed-tier
   promotion, run-before-DMS, U32 analysis). *Weaker spot:* its worked example is
   unverifiable on this machine — the round's own wrong-medium disqualifier.

# 4. CHOSEN TRADE-OFFS

- **An 8-bit checksum instead of codex32's 13-char BCH.** Accepted: the checksum is a UX
  layer, not the security — the AEAD tag arbitrates key-vs-file at 128 bits, and
  tag-guided auto-repair converts the measured 0.41% miss and the localization gap into
  shown-for-confirm correction. Bought: the simplest codec and the widest 2046 recovery.
- **~130 hand-written letters + 24 numerals, more raw ink than EPITAPH's 74 glyphs.**
  Accepted: per-glyph forgiveness (a-z words, unique 4-letter prefixes, list-membership
  localization, phone-friendly) is what the audience axis buys; only ~96 letters are
  load-bearing under the 4-letter rule. The cold drill measures the trade.
- **No in-format correction guarantee** (codex32's ≤4-sub/≤8-erasure lost). Accepted:
  any single-word error or single erasure is recovered by the tag-guided scan; multi-word
  failure escalates honestly to numbered read-back — no impossible promises.
- **No kc commitment field in wrapper v1.** Accepted: the frozen rule already forbids
  verdicts on AEAD uniqueness; wrong-card/wrong-file triage is served by the label echo +
  file-check line + repair scan. The D-round may revisit (recorded).
- **English-only v1 wordlist.** Accepted: the non-English probe is owed; official
  non-English BIP39 lists and the decimal check-digit fallback are the recorded arms.
- **Possibly two paper-encoding families project-wide** if the DMS round picks codex32 or
  SLIP-39 for shares. Accepted: the card protocol converges regardless; L102 owns that
  choice and this round refuses to pre-empt it on wrong-medium evidence.
- **Every `.locked` file is treated as public forever** (random-K only, non-identifying
  label default, no passphrase arm ever). Accepted: conservative against the parked
  public-mirror path (:1004); costs nothing today.
- **Nothing ships in MVP.** Accepted: registration-only now (:1006 scope discipline);
  the user's priority is honored by Committed-v1.1 tier placement and the
  run-before-DMS-implementation ordering, not by breaking the M3/M4 gates.

# 5. WHAT ANALYSIS CANNOT SETTLE

1. **Cold-usability drill:** ≥3 non-technical subjects, real hand-written card + locked
   file, unaided open from the file:// page in Chromium AND Firefox, observer-scored
   success/time/error loci — MEDIUM: human drill against the built page (DMS L81
   pattern). **Licensed to redesign the card/grid AND, on gross failure, to reopen the
   encoding class at the D-round** (fallbacks recorded: decimal check-digit groups,
   SLIP-39). *(→ WAIVED by the maintainer, same day — see Addendum 2026-08-15 at the
   end of this file; the license lapses.)*
2. **Page entry surface:** seventh wasm export vs widened existing verify export —
   MEDIUM: two spike builds through the packaging script; measured page-size delta,
   CSP-hash churn, and verifier-page-browser.sh pass in both browsers (D129 medium rule:
   a probe from the wrong client can invert the answer).
3. **Auto-repair wall-clock:** 24×2048 checksum scan + ~200 tag trials over kilobyte
   bundles — MEDIUM: in-browser wasm benchmark, Chromium+Firefox, before the page copy
   promises repair; INFERRED-trivial today, not measured.
4. **`reveal --lock` no-leak:** words never reach scrollback/tmux history/spool/temp;
   alternate-screen clear verified — MEDIUM: instrumented local run with a planted fault
   (P5 pattern; local-only, no consent needed).
5. **Non-English audiences:** official non-English BIP39 lists vs the decimal
   check-digit fallback — MEDIUM: phone read-back trial with a native-speaker pair;
   decides wordlist-set vs digits at the D-round.
6. **DMS 2-of-3 share encoding (SLIP-39 vs codex32)** — MEDIUM: the DMS KEM/tooling
   round's P7-style timed drill, hand-copied shares recombined in the offline tool; if
   SLIP-39 returns, its official test vectors are the mandatory gate (two from-memory
   implementations already disagreed at index 16).
7. **Public mirroring of locked bundles** — its own consent-gated round (:1004; money
   moves, D36/D49); nothing in this design blocks on it — MEDIUM: that round's design
   docs + express consent gates.

# 6. STAGED PATH

- **Now, this round:** this document, plus two registrar edits — a dated paragraph in
  the **Committed-v1.1** parking-lot tier (promoted from Later per the user's stated
  main priority, cross-referencing :1002 whose recipient-leg encoding vacuum it fills at
  the protocol layer), and a **NEXT-D register row under `### Due M4`**, because the
  U1-amendment half must resolve before U32's CLI release freeze or price a reopen —
  Due-M4 placement makes the deadline enforceable by the register's own
  unresolved-past-due-milestone rule and sidesteps inventing a post-M4 bucket. Nothing
  enters M3 (Q237's blocker set is enumerated and closed) or M4 implementation (:1006
  scope discipline; MVP ships without it).
- **At v1.1 kickoff:** THIS feature's planning round runs FIRST, before DMS
  implementation rows, so DMS kits inherit the card protocol; it resolves NEXT-D
  (briefed, per house rule, to overturn this round's lean) and mints the
  centrally-assigned F/C/U/R/Q implementation rows below.
- **M4 otherwise** gains only the Q21/Q24 custody sentences :1002 already owes.
- **Later:** public mirroring (own consent-gated round), the DMS share-encoding and KEM
  rounds (L102), each with its own records.
- **Coordination:** TODO.md is currently Modified in git status — single-writer
  registrar coordinates; this round doc and the untracked DMS memo both need committing
  (**REQUIRES MAINTAINER ACTION** — no lane runs git).

**Registration rows, verbatim** (NEXT-* placeholders are deliberate — IDs are centrally
assigned by the registrar at write time; next-free at recording: D134 · F56 · C30 · U73 ·
R87 · Q238. The registrar verifies cites rather than transcribing — Vet finding 3 pins
the measured lines):

```
NOW — parking lot, Committed-v1.1 tier (insert as a new dated paragraph after the :998
Committed list, before the 2026-08-01 paragraph): **Registered 2026-08-15 (user
priority, Committed v1.1): paper-key locked bundles — hand-written sharing of decryption
capability.** reveal gains a lock mode: the finished v1 .sealproof, byte-identical
inside, AEAD-wrapped (XChaCha20-Poly1305, fresh random 32-byte K used directly — no KDF,
no HKDF label, never W) into `.sealproof.locked` := MAGIC "ANTSEAL LOCKED PROOF" ||
canonical-CBOR header [version, {label, nonce}] || ct, AAD=MAGIC||header (vault-export
pattern, export.rs:7-17). K travels ONLY as a hand-written card: BIP39 English, 24
numbered words (canonical english.txt committed as pinned data sha256 2f5eed53…dbda;
zero new crates — Cargo.lock measured clean 2026-08-15). Unlock for non-technical
recipients on the PAGE (24-box numbered grid, 4-letter autocomplete, tag-guided
single-word auto-repair shown-for-confirm; a D18 closed-list boundary event) and a
separate never-surprising CLI surface (one U1 amendment + snapshot re-freeze; verify
stays never-prompting — frozen text :14/:295). No passphrase arm: the parked public
anchor-bundle uploads item makes low-entropy keys offline-crackable. Sealer-side:
alternate-screen word display and MANDATORY full 24-word typed-back before the file is
emitted. Card protocol (numbering, phone read-back with numbers, offline page copy
co-equal, card names its standard) becomes the house pattern DMS kits inherit; this is
the MORTSAFE outer lock at 1-of-1 (memo L37); the 2-of-3 share encoding stays that
round's decision (candidates recorded: SLIP-39, codex32). The magic joins Q2 as
reserved-but-NON-SECRET with an explicit secret-guard exclusion + planted-fault
self-test (naive registration reddens the gate on committed vectors,
ci-lanes.sh:1054-1139). Decision minted under Due M4 (must resolve before U32);
implementation rows mint at the v1.1 planning round, which runs BEFORE DMS
implementation. Full record: docs/research/paper-key-transport-design-round.md
(2026-08-15, 3-design adversarial round, judge-grafted). Evidence covers computed
encodings (indices/checksum/duplicate/126-letter burden recomputed three ways), planted
faults, and file-cited freeze mechanics; it does NOT cover unaided non-technical humans
(cold drill owed, L81 pattern, licensed to redesign the grid or reopen encoding), the
wasm auto-repair wall-clock, the export-vs-widened-verify page surface (spike builds
owed), or non-English audiences.
```

```
NOW — Decision register, under '### Due M4' (:962), after D73: - [ ] **NEXT-D**
Paper-key locked-bundle surfaces: U1 amendment shape (reveal --lock + separate unlock
surface; verify stays never-prompting), wrapper header final fields (label default,
pad-to-bucket, kc-or-not), page-entry export shape, BIP39-24 encoding ratification (U32;
implementation rows minted at the v1.1 planning round) *(minted 2026-08-15, up-front —
paper-key transport design round, docs/research/paper-key-transport-design-round.md;
deliberately placed Due M4: must resolve BEFORE U32 or the CLI release freeze prices a
reopen; implementation itself is v1.1 — see the Committed-v1.1 parking-lot paragraph of
the same date; registrar may split into 2-3 D-ids per D68/D130 precedent)*
```

```
AT v1.1 PLANNING ROUND (after NEXT-D resolves; central IDs assigned then) — Formats
domain: - [ ] **NEXT-F** (M) locked-v1 outer wrapper: docs/format/locked-v1.md (MAGIC ||
CBOR array(2) [version,{label,nonce}] || XChaCha ct, AAD=MAGIC||header;
recovery-without-antseal section), golden vectors under NEW root
testdata/vectors/locked-v1/ + FROZEN.sha256, byte-level tamper MATRIX rows
(magic/version/nonce/ct/tag/truncation) — after NEXT-D. Notes: design
docs/research/paper-key-transport-design-round.md 2026-08-15; vault-export schema-exact
(export.rs:7-17); v1 tree and FROZEN.sha256 untouched (format.rs:110-124); evidence does
NOT cover the pad-to-bucket option (NEXT-D scope) or any human trial.
```

```
AT v1.1 PLANNING ROUND — Crypto domain: - [ ] **NEXT-C** (M) BIP39-24 codec in
core/wasm: committed english.txt (sha256 2f5eed53…dbda + license/provenance note per
Q29), encode/decode, checksum, tag-guided single-word auto-repair, zeroizing key types;
codec golden vectors incl. planted-fault cases (word-substitution, checksum-miss,
erasure) — after NEXT-D. Notes: design doc 2026-08-15; zero new crates (Cargo.lock
measured clean); prefix-uniqueness and 199/49,128 checksum-miss measurements recorded
there; evidence does NOT cover in-browser scan wall-clock (probe before page copy
promises repair).
```

```
AT v1.1 PLANNING ROUND — CLI domain: - [ ] **NEXT-U** (M) reveal --lock + unlock
surface: alternate-screen word display cleared after read-back, MANDATORY full 24-word
typed-back (checksum+tag) before emit, never-overwrite (D68), key-fd option naming the
U33/D72 Windows wrinkle, cli-surface.help.txt re-frozen in the same act — after NEXT-D,
NEXT-C, NEXT-F. Notes: design doc 2026-08-15; D39/D41/D68 amendment precedent
(U.md:13,19); verify's frozen never-prompts contract untouched; tick gated on the
P5-style no-leak instrumented run with planted fault — evidence does NOT yet cover that
leak surface.
```

```
AT v1.1 PLANNING ROUND — Reveal&page domain: - [ ] **NEXT-R** (L) page unlock: magic
sniff on drop, label + file-check echo BEFORE typing, 24-box numbered grid with
autocomplete and per-box redden, auto-repair shown-for-confirm, honest escalation copy;
boundary event per NEXT-D (six pub fns today, boundary.rs:42-116 — state the counting
convention); repack (R25 CSP recompute, footer digest moves); R27/Q19 corpus gains
locked cases; file:// parity Chromium+Firefox — after NEXT-D, NEXT-C, NEXT-F. Notes:
design doc 2026-08-15; tick gated on the cold-usability drill (>=3 non-technical
subjects, unaided, file://) which is LICENSED to redesign the grid or reopen encoding
(L81 pattern); export-vs-widened-verify decided by two spike builds measuring page-size
delta + CSP churn — evidence does NOT yet cover either measurement.
```

*(The cold-drill half of NEXT-R's tick gate is struck by the Addendum 2026-08-15 at the
end of this file — maintainer waiver; the corpus, file:// parity, and spike-build gates
stand.)*

```
AT v1.1 PLANNING ROUND — CI&copy/docs domain: - [ ] **NEXT-Q** (S) paper-key docs +
guard: recipient card instructions and card-text copy under Q28 audit (card must name
the offline disc/USB copy as co-equal and its BIP39 standard), english.txt provenance
under Q29, locked-v1 joins Q27 format-stability policy, secret-guard exclusion +
planted-fault self-test for the non-secret magic, Q21/Q24 custody sentences
(card-metadata linkage, size fingerprinting, card-is-the-sole-secret once the file is
public) — after NEXT-F, NEXT-U, NEXT-R. Notes: design doc 2026-08-15; :1002 already
names Q21/Q24 for custody defects; evidence does NOT cover non-English audiences
(read-back trial owed) or the public-mirror consent gate (own round, :1004).
```

## What this round rules — ten rulings, each with its evidence medium

1. **Locked-bundle wrap confirmed; the capability-string arm stays rejected** — MEDIUM:
   doc quotes (registry-v1.md:818's k_m-discloses-nothing rationale inverts without the
   bundle in hand — a network copy would hold title/commitments/pubkeys; delivery would
   chain to Autonomi; it grants reading without proof and grows linearly with units).
2. **Fresh random 32-B K used directly; no passphrase arm; no KDF; no HKDF label;
   never-W by construction** — MEDIUM: file cites re-verified by the judge (hkdf.rs:41-42
   "No public API accepts a label string"; unit_aead.rs:278 explicit-key precedent) +
   register quote (:1004 parked public anchor-bundle uploads makes low-entropy keys
   offline-crackable on a decades horizon).
3. **Container = MAGIC "ANTSEAL LOCKED PROOF" ‖ CBOR array(2) header ‖ XChaCha ct,
   AAD=MAGIC‖header, fresh 24-B nonce; verdict = tag-then-full-v1-verify, never AEAD
   uniqueness; v1 bundle byte-identical inside** — MEDIUM: file cites (export.rs:7-17
   judge-verified; unit_aead.rs:24-26, 48-56; format.rs:110-124).
4. **Encoding class = numbered English words, BIP39-24; the lean's bech32m half
   OVERTURNED; codex32 and SLIP-39 weighed and not adopted for the gift path** — MEDIUM:
   computed encodings, independently recomputed three times within the round (judge:
   checksum byte 0x63, all 24 indices, the live duplicate, 126 a-z letters; red team:
   wordlist pin, full-list prefix uniqueness, planted faults caught, the 199/49,128
   checksum-miss enumeration; SLIP-39's indices were from-memory grade with two
   implementations disagreeing — the wrong-medium rule bars adopting it on this round's
   evidence) — and a fourth recomputation by the writer at recording, all values matching.
5. **Wordlist ships as committed pinned repo data, zero new crates** — MEDIUM:
   Cargo.lock grep measured clean of bech32/base32/bip39/wordlist crates;
   tamper/README dep-refusal precedent quote.
6. **The new magic is reserved-but-NON-SECRET (publishable-ciphertext class) with an
   explicit secret-guard exclusion + planted-fault self-test** — MEDIUM: script read
   (ci-lanes.sh:1042-1142 fail-list hard-fails on registered signatures, judge-verified)
   found independently by two red teams: naive Q2 registration reddens the gate on
   committed vectors.
7. **verify-auto-detect-with-prompt ruled OUT; unlock is a separate surface; changes
   ride one U1-amendment decision with snapshot re-freeze plus a D18 closed-list page
   event** — MEDIUM: frozen snapshot text judge-verified (cli-surface.help.txt:14,295
   "needs no vault and never prompts"), D51 matrix (U.md:694), boundary.rs:42-116
   six-pub-fn count, D39/D41/D68 precedent (U.md:13,19).
8. **Mandatory full 24-word typed-back re-entry (checksum+tag validated) before the
   locked file is emitted and K forgotten** — MEDIUM: failure-mode analysis over
   file-cited facts (K deliberately unsaved + the DMS staged-kit sealer-unreachable
   scenario L50/L53; the house assertions-that-cannot-fail rule); the no-leak property
   itself still gets its P5-style probe.
9. **DMS 2-of-3 share encoding NOT ruled here — reserved to the DMS round with SLIP-39
   and codex32 as recorded candidates; the card PROTOCOL (numbering, read-back, grid,
   offline copy) converges now** — MEDIUM: doc quotes (L102 "its own decision round";
   L81 probe-licensing philosophy; L38 hand-copy rule with the measured encoding vacuum).
10. **Registration path: dated paragraph in the Committed-v1.1 tier now + decision row
    under Due M4 now; implementation rows at the v1.1 planning round, run before DMS
    implementation** — MEDIUM: register cites judge-verified (:996-1006 tier structure
    and the :1002 template; Q237's closed blocker set; :1006 scope discipline; the
    register's unresolved-past-due-milestone rule enforcing the pre-U32 deadline
    structurally).

## What this round does NOT decide

- **Anything at decision grade.** This file is a research memo (see Kind). The actual
  decision record(s) — NEXT-D, possibly split 2–3 ways — are where the lock/unlock
  surface shape and names, the wrapper's final header fields (label default text,
  pad-to-bucket, kc-or-not, bstr-wrapped vs inline body — Vet finding 2), the
  page-entry export shape, and the BIP39-24 ratification (including the recorded 128-bit
  codex32-48 length challenge, which must be argued rather than inherited) actually get
  ruled. The D-round is briefed to overturn this round's lean, per house rule.
- **No implementation rows exist.** F/C/U/R/Q rows mint at the v1.1 planning round with
  centrally-assigned IDs; nothing enters M3 or M4 implementation.
- **The DMS 2-of-3 share encoding** (SLIP-39 vs codex32) — reserved to the DMS
  KEM/tooling round (L102); only the card protocol converges now.
- **KEM lockbox adoption** — untouched; its combiner, pins, vectors, and tooling remain
  that round's (L102).
- **Non-English wordlists vs the decimal fallback** — probe 5's read-back trial decides.
- **Public mirroring of locked bundles** — its own consent-gated round (:1004; money
  moves, D36/D49). This design assumes public exposure defensively but neither builds
  nor authorizes any upload.
- **Whether the page may promise repair timing** — blocked on probe 3's in-browser
  benchmark.
- **The win itself is probe-gated, not final:** the cold-usability drill is licensed to
  redesign the grid or reopen the encoding class (L81 pattern); a probe from the right
  medium has overturned this register's leans before. *(→ superseded same day: the
  drill is waived by maintainer ruling — Addendum 2026-08-15 below.)*

## Attack findings and their dispositions

All three designs survived their red teams — **zero fatal findings** round-wide; every
survivable finding is resolved in the graft or routed to a named owner.

**Red team on LAST WORDS** (9 survivable): plaintext label leaks recipient identity if
mirrored → non-identifying default + rubric warning + Q21 hook (grafted). No at-creation
read-back; sealer's own miscopy discovered possibly after the sealer is unreachable →
mandatory full typed-back (grafted, strengthened by PALLBEARERS' red team). "Works
without internet" false without a saved page; bare antseal.org is a decades DNS-hijack
surface → offline copy named co-equal on the card; Q28 audit (grafted). Localization
overclaim — measured 199/49,128 substitutions pass the checksum; valid-word slips get
global detection only, and the tag-failure copy then misdiagnoses → tag-guided
auto-repair + honest copy (grafted). Q2-guard collision, verified in ci-lanes.sh —
committed vectors would redden a naive registration → non-secret class + explicit
exclusion + planted-fault self-test (grafted). verify auto-detect collides with the
frozen never-prompts contract → ruled OUT (ruling 7). No post-M4 register bucket; weigh
Committed-tier per the user's priority → Due-M4 placement + Committed-v1.1 tier
(adopted). Format hygiene: match the export's array(2) schema or record why not; give
the container its own vector root; wordlist license note → array(2) adopted,
`vectors/locked-v1/` root, Q29 note (all grafted). Fact-check dings (example's 5.2
avg vs 5.4 list mean; "schema-exact" phrasing; bech32m "corrects zero" nuance;
"declared un-hand-copyable" overclaim) → Vet findings 1, 2, 8. Its counterproposal —
SLIP-39-1-of-1-everywhere — weighed and beaten on 24-vs-33 and 2046 ubiquity; its two
strengthen-not-replace additions (auto-repair; typed-back) are IN the graft.

**Red team on EPITAPH** (10 survivable, mostly codex32-specific; those that traveled):
5–8-substitution localization is mathematically impossible — the copy must escalate to
erasure marking instead → the graft's honest-escalation copy carries the lesson
(erasures ARE locatable; substitutions beyond repair are not). Probe pre-commitment
("failure redesigns the card, not the encoding") pre-limits the probe against house
philosophy → probe 1 is licensed to reopen the encoding (grafted). Page-scope hostage
risk (if the boundary event is refused, unlock collapses to CLI-only, failing the
user's priority) → briefed into probe 2 with D132's actual refusal reasoning; the real
arms are new-export vs widened-export (in-page decode cannot do XChaCha). Share-string
triage (a valid share typed into the unlock field must branch, not fail) →
encoding-specific; recorded for the DMS round's tooling. kc triage table underspecified
→ kc not adopted in v1; recorded for NEXT-D. Card title/filename cleartext is a
theft-observation surface → optional title; Q21/Q24 custody sentences (routed).
bech32m comparison phrasing ("corrects zero" → "no safe/specified correction"; 66-not-74
chars only at short HRPs) → Vet finding 8. --key-fd inherits the U33/D72 Windows
question → named in NEXT-U (grafted). Cite drifts (format.rs :115 vs :116;
boundary :41 vs :42; export-counting convention) → Vet finding 3. Its counterproposal —
codex32-48 at 128 bits — recorded as the length challenge NEXT-D must argue.

**Red team on PALLBEARERS** (11 survivable; those that traveled): verify-prompts
contradicts frozen text + D51 → never-prompting CLI (ruling 7, grafted). "hmac already a
direct dep" is false — it is dev-only → moot in the graft (BIP39 needs no
PBKDF2/Feistel; sha2 is a normal dep) — Vet finding 5. Q2-guard collision (independent
second find) → grafted as above. 3-of-33 spot check is an assertion that cannot fail →
full typed-back (grafted). Terminal scrollback leak → alternate-screen display + clear +
P5-style probe (grafted). "Card opens nothing without the file" false under the
public-mirror premise → closing line reworded (grafted). Card never names its standard;
2046 opacity → standard line + recovery-without-antseal section (grafted).
Extendable-vs-original SLIP-39 fork wrinkle → recorded for the DMS round. Candor gap
(codex32 explored but unlisted) → cured here: every arm is on the record. "ONE decision"
undercount → registrar may split 2–3 D-ids (grafted into NEXT-D's mint note). Tamper
taxonomy — word/checksum cases are codec vectors, not byte-tamper MATRIX rows →
grafted. Card metadata + size fingerprinting → optional pad-to-bucket at NEXT-D; Q21
note (routed). Its counterproposal's page-side correction assist is the same auto-repair
graft, independently surfaced.

---

## Vet findings (2026-08-15 — writer's same-day check; the judge's text above is as issued)

Method: every load-bearing number was **re-computed by the writer's own independent
implementation** (BIP39 from its definition; nothing imported from the designers'
scripts), and every file:line cite used by the ruling was re-grepped/re-read in the tree
at recording. Outcomes, including clean passes:

1. **Scorecard's "handwrite BEST (126 a-z letters …)" — PARTIALLY.** 126 is the worked
   example's draw; the measured list mean is 5.404 letters/word, so a random K expects
   ~130 secret letters (+24 numerals + labels). And raw glyph count alone would favor
   EPITAPH (74 < ~130): the ranking's real basis is per-glyph forgiveness (a-z only,
   unique 4-letter prefixes ⇒ ~96 load-bearing letters, list-membership localization,
   word familiarity) — which both rival red teams independently conceded, and which
   probe 1's drill, not this memo, ultimately arbitrates. Direction survives; the bare
   number as stated is example-specific.
2. **"Vault-export-schema-exact array(2) [version, body: map{…}]" — OVERCLAIM at one
   level, measured.** The shipped export header is `array(2) [format_version: uint,
   body: bstr]` with the nonce inside a **bstr-wrapped** map keyed {0: kdf_block,
   1: nonce} (export.rs:10-14). The graft's sketch is an **inline** map keyed {1: label,
   2: nonce} with no kdf block. Pattern-exact — MAGIC ‖ array(2) header ‖ AEAD with
   AAD = MAGIC‖header — yes; field-schema-exact — no. NEXT-F/locked-v1.md must state
   the body encoding (bstr-wrapped for byte-level convention match vs inline for
   simplicity) as a deliberate choice. Not conclusion-bearing.
3. **Cite drift, pinned by measurement — PASS after correction.** `SUPPORTED_VERSIONS`
   is format.rs:**115** (the ":116" variant circulating in one attack is the drift);
   `VERSION_KEY` :124. The six wasm exports: attribute `#[wasm_bindgen(start)]` at
   boundary.rs:**41**, fns at :42/:59/:74/:91/:102/:116 — ":41-116" and ":42-116"
   bracket the same closed list. `decrypt_unit_with_key` at unit_aead.rs:**278** exact.
   Never-prompts at snapshot :**14**/:**295** exact. The Q2 guard block spans
   ci-lanes.sh:**1042-1142** (planted-fake self-test :1115, fail message :1139); the
   judge's ":1054-1139" lands inside it. Registrars carry THESE lines, not the drifted
   ones.
4. **"Six exports" counting convention — PASS.** Six `pub fn`s including the `start()`
   init hook; D132's vocabulary counts five callables. NEXT-R's mandate to state the
   convention is the right fix — an unstated convention is a future register red.
5. **Zero-new-crates — PASS, and stronger than one design claimed.** Cargo.lock has
   zero encoding-crate packages (re-grepped at recording). The graft needs only `sha2`
   (normal dep, Cargo.toml:81) for the checksum and `blake3` (:53) for the file-check
   line. PALLBEARERS' hmac problem (hmac at :95 under `[dev-dependencies]` :91) does
   not touch the graft: BIP39 raw-entropy encoding uses no PBKDF2/Feistel/HMAC.
6. **SLIP-39's evidence grade — PASS as the judge used it.** Structure arithmetic
   self-verifies; the word indices were from-memory in both independent implementations
   and disagreed on the word at list index 16 ("agency" vs "again"). The wrong-medium
   disqualification is the register's own medium-decides-it lesson operating inside the
   round; official vectors are the mandatory gate on any return.
7. **Auto-repair cost "~200 AEAD trials" — PASS as (I).** 24×2048 = 49,152 checksum
   evaluations; expected checksum-passing candidates ≈ 49,152/256 ≈ 192, each a
   kilobyte-scale AEAD. INFERRED-trivial; probe 3 measures in-browser wall-clock before
   the page copy promises anything.
8. **bech32m "detection-only / corrects zero" — PARTIALLY as phrasing.** BIP-173/350
   specify guaranteed detection (≤4 substitutions) and bless no correction; the BCH
   distance admits limited correction in practice. The defensible form — "no safe,
   specified correction" — is the one this record carries. The comparative conclusion
   and the measured 66-char string are untouched.
9. **The encoding numbers — PASS, re-measured.** Writer's independent implementation at
   recording: wordlist hash `2f5eed53…dbda`, 2048 words, checksum byte `0x63`, all 24
   indices, words, the position-2/4 duplicate, 126 letters all a-z, byte-identical
   roundtrip, full-list prefix uniqueness, list mean 5.404, **exactly 199/49,128**
   substitution misses, and both planted faults (`bid→bicycle`, `bid→bike`) caught —
   *fails for the right reason*. Every value matches the round's three earlier
   computations.
10. **Registration mechanics — PASS.** `### Due M4` measured at TODO.md:962 with D73 at
    :965 (NEXT-D's stated anchor); parking-lot lines :996/:998/:1000/:1002/:1004/:1006
    all as cited; next-free IDs D134/F56/C30/U73/R87/Q238 confirmed against the register
    lane's recount (A135 hole and dead P-ids respected). The NEXT-* placeholders are
    correct house practice — lanes never number their own discoveries.
11. **"Parked public mirroring makes low-entropy keys offline-crackable" — PASS as a
    ruling, with its premise labeled.** Public mirroring is a *parked possibility*
    (:1004), not a shipped path (upload plumbing content-agnostic but caller-less,
    behind the non-default ant-backend feature). Designing every `.locked` file as
    potentially-public-forever is the conservative side of an (I) — right on a decades
    horizon; recorded here so nobody reads "public mirroring exists" out of it.

Net: nothing found moves the verdict, any ruling, or any registration row; two phrasings
are corrected (pattern-exact, not schema-exact; example letter count vs list-mean
expectation), the cite drift is pinned to measured lines, and every load-bearing
encoding number was independently recomputed at recording and matched. The judge's
`register_now` and all seven rows pass to the registrar unamended.

---

## Addendum — maintainer ruling, 2026-08-15 (later the same day)

**The ruling, maintainer's words verbatim** (given in direct reply to this round's probe
list): *"we don't need the cold-usability drill (and I can't get it done anyway) because
it's a similar process to Bitcoin etc."*

**Effect: probe 1 (cold-usability drill) is WAIVED.** The rationale on the record:
hand-copying a 24-word BIP39 recovery phrase is the Bitcoin ecosystem's standard
practice, exercised at population scale for over a decade by non-expert users, and the
card's own conventions (numbered grid, first-4-letters sufficiency, phone read-back
caution) are drawn from that ecosystem's accumulated practice. The evidence grade is
stated honestly: this is **(D) precedent, not (M) measurement** — it covers the
*transcription medium* (24 English words, hand-copied, recovered later) and it does NOT
measure THIS page's 24-box grid, the unaided `file://` open, or this project's recipient
demographic (wallet users self-select; gift and DMS recipients do not). That residual is
**accepted by the ruling**; the drill was also infeasible for this maintainer to run.

Consequences, applied in the same act:

1. **The win is no longer probe-gated on probe 1**, and the drill's license to redesign
   the card/grid or reopen the encoding class **lapses**. The recorded fallbacks
   (decimal check-digit groups, SLIP-39) remain recorded; nothing schedules them.
2. **NEXT-R's preserved row text is amended for the registrar who mints it at v1.1:**
   strike the clause "tick gated on the cold-usability drill (>=3 non-technical
   subjects, unaided, file://) which is LICENSED to redesign the grid or reopen encoding
   (L81 pattern)". Its tick gate becomes what already stands in the row: the locked
   cases in the R27/Q19 corpus, file:// parity in Chromium+Firefox, and the
   export-vs-widened-verify shape resolved by then at the D-round.
3. **Probes 2, 3 and 5 are pinned as D134's named resolution evidence** (D134's row in
   TODO.md was amended in the same act): the two export-shape spike builds (page-size
   delta, CSP-hash churn, verifier-page-browser.sh in Chromium+Firefox), the in-browser
   auto-repair wall-clock benchmark before any page copy promises repair, and the
   non-English wordlist-vs-decimal question, decidable analytically at that round.
4. **Probe 4 (`reveal --lock` no-leak) is unchanged** — it stays NEXT-U's v1.1 tick
   gate.
5. **Probes 6 and 7 are unchanged** — they belong to other rounds (DMS share encoding;
   consent-gated public mirroring) and were never this round's to waive.
6. **D134's overturn brief stands unchanged**: the resolving round is still briefed to
   try to overturn this round's lean, and it may order any measurement it wants — the
   waiver removes an obligation, not a permission.

**Editorial note for auditability:** the judge's sections above remain as issued; three
dated pointer annotations were inserted at this ruling (at §5 probe 1, at the NEXT-R
preserved row, and at the "win itself is probe-gated" bullet of What this round does NOT
decide) so no reader of those sections carries away a gate that no longer exists.
Register edits performed with this addendum, single-writer: the D134 row and the
Committed-v1.1 paragraph both carry the waiver dated 2026-08-15, and the full
traceability gate was re-run green after the edits.
