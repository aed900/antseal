# D67 — Disclosure-preview snippet: window length, form judgment, binary format, and the unavailable arm

- **Status: RESOLVED — text = the first 64 post-padding-strip plaintext bytes,
  cut backed off to a UTF-8 code-point boundary; binary and raw-mirror = the
  first 16 bytes as `hex:` + ungrouped lowercase pairs; truncation marker `…`
  rendered outside the closing quote so content cannot forge it; form judged
  from the manifest's committed domain (`CanonMode` × `UnitKind`), never by
  re-sniffing content.** Both overturn arms the brief supplied — **no snippet
  in v1** and **length-only preview** — are **refused on measurement**: spec
  lines 36 and 149 make the snippet normative on both surfaces, it is the only
  preview field that binds consent to *content* rather than to coordinates,
  and terminal/scrollback exposure is not a class this decision could close,
  because `show` prints the same vault-local bytes gate-free by the spec's own
  canonical CLI list. The register's lean — "a small presentational choice" —
  **survives as to freeze-weight** (zero wire impact, presentational until
  M3 snapshots) **and is corrected as to content**: the choice carries a
  consent-display-integrity component the "small" framing missed, so the
  ruling includes a closed control/bidi escape set that stops a crafted file
  repainting the very screen that asks for irreversible-disclosure consent.
- **Date: 2026-08-11** (wave 16, D67 planning lane; briefed to overturn the
  presentational lean. The two supplied arms are refused on measurement, one
  arm nobody supplied — whole-unit preview — is refused too, and the lean
  keeps its freeze-weight verdict while losing its "nothing security-shaped
  here" implication.)
- **Owning tasks: R15** (computes the data; its Notes named this the open
  decision), **U27** (renders it in `show`), **U29** (renders it in the
  consent gate), **R16** (carries the data through the reveal flow).
- **Amends**: `tasks/R.md` R15 `Notes` and `tasks/U.md` U27 (notes quoted in
  §8; the registrar's to apply). **Supersedes**: nothing. **Corrects**:
  nothing.

---

## 1. What was measured

**(a) The spec mandates the snippet on both surfaces, by name.**
`MVP-SPEC.md` line 36: *"prints exactly which units (file, byte-range, size,
snippet) will be **irreversibly disclosed** and requires confirmation"*.
Line 149 (*"this list is canonical"*): `show <work-id>` *"(every unit: file,
byte-range, size, local snippet when available — the preview for
`reveal --units`)"*. A no-snippet ruling is therefore not a free choice
inside R15's Notes — it is a spec divergence, and this project flags those
rather than ruling them in by a side door.

**(b) Line 121's position + total size guardrail is the verifier's floor,
not the consent ceiling.** *"Every reveal displays position + total size
(anti-out-of-context guardrail)"* governs what a **verifier** shows a
third party about what is *around* the disclosure. The consent preview's job
is the inverse: confirm to the **sealer** what is *inside* the selection
before it becomes permanent. The two surfaces share the row fields; they do
not share a purpose, and a ruling that collapsed the second into the first
would be reasoning from the wrong reader.

**(c) The binary/text judgment already exists and is committed.** At seal
time G classifies with `canon::pipeline::is_text`
(`crates/antseal-core/src/canon/pipeline.rs:269` —
`str::from_utf8(raw_bytes).is_ok()`), the user can override with
`--force-text` (D20), and the result is **committed per file** in the signed
manifest as `CanonMode::{Binary, Text}`
(`crates/antseal-core/src/manifest/body.rs:217`), whose own doc records the
domain consequence: binary offsets are raw-byte offsets, text offsets are
canonical-byte offsets (spec line 83). Units carry
`UnitKind::{Normal, RawMirror}` (`manifest/registry.rs:409`). **There is
nothing left to classify at preview time** — the preview's only honest move
is to mirror the committed domain of the bytes being disclosed.

**(d) The house already has a truncation pattern for exactly this job.**
`canon/unicode.rs:196` `truncate_for_echo`: bound a string echoed to a
terminal at `MAX_ECHO_BYTES` (**64 bytes**, `unicode.rs:50`), backing the
cut **down** to a `char` boundary (≤ 3 bytes), with an explicit marker. The
job class — "user-controlled text is about to hit a terminal; bound it,
never split a code point, say so when cut" — is this decision's job class.

**(e) Every hex surface in the product is ungrouped lowercase, unprefixed
by `0x`.** `Digest32` renders 64 lowercase hex chars
(`verify/report.rs`, pinned by
`digest32_is_lowercase_hex_in_display_debug_and_json`); the CLI's
`hex_seal`/`hex32` render `{byte:02x}` ungrouped
(`crates/antseal-cli/src/listing.rs:1157` et al.). A grouped or
`0x`-prefixed snippet would mint a second hex spelling for zero measured
gain.

**(f) Canonical text is UTF-8 by construction and unit starts are code-point
boundaries.** Canonicalization emits UTF-8/NFC/LF/no-BOM (pipeline stages,
`canon/pipeline.rs`); `--split` cuts at blank lines
(`content/split.rs`, D22), i.e. after an ASCII LF, so a Normal unit of a
Text file starts on a boundary and its full plaintext is valid UTF-8 for
all honest data. The defensive arm in §3 R2 exists for adversarial or
corrupt inputs, not for any shape the sealer can produce.

**(g) Raw mirrors exist to prove *exact original bytes*, and text rendering
can silently misrepresent exactly those.** A mirror is present when raw ≠
canonical (spec line 92); the difference is BOM/CRLF-class material. A BOM
(`U+FEFF`) is valid UTF-8 and renders **invisibly** — a text-rendered
mirror snippet would look identical to the canonical unit while the bytes
differ, which is a misrepresentation on the one unit kind whose entire
purpose is byte-exactness. Hex shows the `efbbbf`.

**(h) The snippet's freeze-weight is already recorded in the tree.**
The snippet never enters any CBOR: the bundle's key registry
(`docs/format/registry-v1.md` **§7.6, Bundle top level**) has no slot for
it, and **§7.6.1 (checked absences)** records the governing house principle
— derived values are not carried. The verifier side is prohibited from ever
growing one: `UnrevealedFilePlaceholder` *"must never gain a path, snippet,
or any content-derived field"* (`verify/report.rs:825`). On the machine
side, `listing.rs`'s module doc records the current contract state: **D65
is not in force; the in-force machine contract is `ENVELOPE_VERSION`**
(`crates/antseal-cli/src/machine.rs:66`). And `tasks/U.md` U32 says what
eventually hardens presentation: at M4, *"snapshot baselines become
compatibility promises."* So the corridor is: presentational now →
snapshot-frozen at M3 (U29/U27/R18) → promised at U32.

**(i) Grapheme handling is deliberately parked, twice.** Spec line 96: per-
unit reveals need *"no mid-grapheme handling, which is the part genuinely
deferred to v1.1"*; line 161 and `TODO.md`'s parking lot defer
*"mid-grapheme slicing policy"* and *"grapheme-selection UX"*. A
grapheme-aware truncation rule here would import the parked machinery
through a display detail.

**(j) In the consent gate, the unavailable arm is near-unreachable.**
R16's own Do gathers ciphertexts for **all** units of every touched file
and *"decrypt[s] for preview and tree rebuild"* — the builder cannot
produce a bundle without the plaintext the snippet is cut from. So under
`reveal`, a row without a snippet means the build was about to fail anyway.
The arm is real on `show` (U27 has **no S dependency** — it never fetches;
cache-first per D43, then current-file-marked-may-differ, then absent) and
in defensive totality.

---

## 2. The overturn arms, refused on measurement

### 2.1 "No snippet in v1" — refused

- **It is a spec divergence, not a parameter choice** (§1 a). Both surfaces
  name the snippet in normative text; this lane has no warrant to edit the
  spec, and the arm cannot be adopted without doing so.
- **The snippet is the only field that binds consent to content.** The other
  row fields — file, byte-range, size — are coordinates. `--units 3,5` is
  typed from memory or scrollback of an earlier `show`; unit ids are bare
  work-global ordinals; a `4`-for-`5` slip discloses the **wrong unit,
  irreversibly** ("irreversibly disclosed" is the gate's own headline). The
  snippet is the last surface on which that error is visible before it is
  permanent. The failure it prevents (wrong content disclosed forever)
  strictly dominates the cost it incurs (≤ 64 bytes of about-to-be-disclosed
  plaintext echoed to the sealer's own terminal).
- **The scrollback objection dissolves under the spec's own `show`.** The
  arm's strongest form: *a snippet is itself a disclosure — to terminal,
  scrollback, screen-share — before the user consents.* Measured against the
  boundary: the plaintext is already local and the user's own — `reveal`
  requires the vault, the vault decrypts every unit at will, and the source
  file is ordinarily still on disk. The project's confidentiality boundary
  is the **network and the bundle recipient** (spec: nothing readable ever
  leaves the machine; rule 6's secret class is `W`, unit keys, salts — and
  R15's Accept already carves out *"the plaintext being deliberately
  disclosed"*). And decisively: `show` prints the same snippet **with no
  gate at all**, by canonical spec text (line 149). Refusing R15's snippet
  would not close the terminal-exposure class; it would only remove the
  copy of it that does consent work. A hostile-terminal user's mitigation
  is not to run `show`/`reveal` interactively on that terminal — not a
  degraded consent gate for everyone else.

### 2.2 "Length-only preview" — refused

Length-only is the row minus its one content-bearing field, so every
measurement in §2.1 applies. Two additions:

- It promotes line 121's pair (position + total size) from the verifier's
  anti-out-of-context **floor** into the consent gate's **ceiling** —
  backwards per §1 (b).
- The mis-selection channel it leaves open is exactly the one the gate
  exists for: coordinates confirm that *a* unit of *that* file will be
  disclosed, never that it is the unit the user believes it is. A consent
  gate that cannot surface the user's own error before permanence is
  ceremony.

### 2.3 The arm nobody supplied — whole-unit preview — also refused

If a snippet strengthens consent, print everything? No: units are unbounded
(MB-scale), and a consent prompt that scrolls its own confirmation line off
the screen has destroyed the gate it serves — the user confirms against
whatever is left visible. Identification is the job; reading is `restore`'s.
64 bytes identifies (§3 R1's rationale).

---

## 3. The ruling

Eight rules. "Window" = the bytes selected; "rendering" = the terminal form.
All constants are named constants beside R15's computation, pinned by the
unit tests R15's Accept already requires.

**R1 — Window selection.** The snippet window is a **prefix**: the first
`min(CAP, true_length)` bytes of the unit's **post-padding-strip plaintext**
(never the padded AEAD plaintext — padding is all-zero filler beyond
`true_length`, spec line 121). `CAP` = **64 bytes** for the text form,
**16 bytes** for the hex form. `truncated ⟺ window length < true_length`.
The unit of account is **bytes**, not chars: every neighbouring figure in
the row (`byte-range`, `size`, `true_length`) is byte-denominated, and 64
is the house's existing measured bound for text echoed to a terminal
(§1 d). 64 bytes ≈ ten words of ASCII prose, ≈ 21 CJK chars — enough to
recognise one's own paragraph, which is the job. 16 bytes = one classic
hexdump row and covers the leading file magics that make binary bytes
recognisable at all (PNG 8, PDF 5, ZIP 4, gzip 3, ELF `e_ident` exactly
16); 32 rendered chars is half a `Digest32`. (Offset-257-class magics such
as tar are not covered; the row's path and size carry identification
there.)

**R2 — Form judgment: the manifest's committed domain, no sniffing.**

```text
form(unit) = Text  iff  unit.kind = Normal
                     ∧  file.canon = CanonMode::Text
                     ∧  the R1 text window survives R3's boundary cut
                        as valid UTF-8
           = Hex   otherwise
```

Consequences, each deliberate:

- **Raw-mirror units are always Hex**, including mirrors of text files —
  §1 (g): the mirror's purpose is byte-exactness, and text rendering makes
  precisely the mirror-relevant bytes (BOM, CRLF) invisible or ambiguous.
- **Normal units of a Binary file are always Hex**, even when their bytes
  happen to decode as UTF-8 — the preview mirrors the **committed domain
  being disclosed** (raw offsets, `raw_commit`), and the classification
  moment was seal time (`is_text` + D20's `--force-text`), not display
  time. Content re-sniffing at preview time would be the new classifier
  the code does not have and this decision refuses to mint.
- **The defensive arm**: a text-domain window that fails UTF-8 validation
  (impossible for honest data per §1 f; reachable via corrupt cache before
  S4's recheck, or a hand-built vault) drops to **Hex** — never to
  `from_utf8_lossy`. U+FFFD substitution *shows characters that are not
  the bytes* in the one surface whose job is to show the bytes; the hex
  arm degrades honestly. (The pipeline's internal lossy stage is seal-time
  decode semantics with its own KATs — it is not a display policy, and the
  preview never re-canonicalizes sealed bytes.)

**R3 — Text rendering.**

```text
"<escaped window>"      when not truncated
"<escaped window>"…     when truncated
```

- **Boundary cut**: when `true_length > 64`, the cut backs off from byte 64
  to the previous UTF-8 code-point boundary — 0–3 bytes, the
  `truncate_for_echo` pattern (§1 d). When `true_length ≤ 64` the window is
  the whole plaintext and no cut exists. **Code-point boundary, not
  grapheme boundary**: grapheme machinery is parked (§1 i); a cut may
  sever a combining sequence or ZWJ cluster, which is a display-only
  artifact in a display-only value, accepted and recorded here.
- **Escaping — a closed, frozen set, applied per code point:** `\\` for
  backslash, `\"` for the quotation mark, `\n` / `\r` / `\t` for LF / CR /
  TAB, and `\u{…}` (Rust syntax, minimal-length lowercase hex) for the
  remaining members of: **C0** `U+0000–U+001F`, **DEL** `U+007F`, **C1**
  `U+0080–U+009F`, and the **bidirectional format controls**
  `U+061C`, `U+200E`, `U+200F`, `U+202A–U+202E`, `U+2066–U+2069` (the
  CVE-2021-42574 "Trojan Source" set). **Every other code point passes
  through unmodified** — the user's prose renders as prose. Why the set is
  not smaller: a consent screen that echoes raw C0/C1 lets a crafted file
  move the cursor and repaint the totals it is asking the user to confirm,
  and NFC removes none of the bidi controls, which can visually reorder a
  snippet so it *reads* as different content than its bytes. Why it is not
  larger (`escape_debug`, printability tables): those track Unicode data
  across toolchains; this set is closed and version-independent, so the
  snapshot the rendering freezes into (§R7) cannot rot under a pin bump.
  Escaping LF also makes the snippet **exactly one line**, and makes a
  whitespace-only unit *visible* (`"\n\n"`), which is a small consent win
  the raw form would lose.
- **The marker sits outside the closing quote.** Inside the quotes, `…`
  (U+2026) is an ordinary passthrough code point a file can contain, so an
  inside marker is forgeable by content; with `\"` escaped, nothing can
  render after the honest closing quote, so the outside position cannot be
  forged. Same glyph as `truncate_for_echo`'s; the bracketed byte total is
  **not** carried over, because the row already prints `size` — it would
  restate a neighbouring column.
- **Empty unit** (`true_length = 0`): `""`, no marker — the complete
  representation of zero bytes.

**R4 — Hex rendering.**

```text
hex:<lowercase pairs, ungrouped>      when not truncated
hex:<lowercase pairs, ungrouped>…     when truncated
```

Lowercase, unprefixed-by-`0x`, ungrouped — the product's only hex spelling
(§1 e). The `hex:` label is the form discriminant a human needs (a text
file containing `deadbeef` renders quoted, so the two forms cannot
collide), and quoting is reserved for text. Zero-length hex windows
(unreachable for honest data — an empty file is `is_text`-true and gets
the Text arm) render as bare `hex:` for totality.

**R5 — The unavailable arm.** The row's snippet slot is `Option`-shaped
with **no reason carried**; when absent, the rendering is the literal
`(snippet unavailable)` — reason-free because the causes differ by surface
(no cache and no readable current file in `show`; hypothetical in `reveal`,
§1 j) and a reasoned string would lie on one of them. The row still renders
in full — file, byte-range, size — and consent may proceed on those
invariants; that this is acceptable is anchored by §1 (b): position + size
are the fields the spec itself treats as the always-present pair.
Provenance labeling (*sealed bytes* vs *current file — may differ if
modified since sealing*) stays U27's copy per its own Do and is
snapshot-frozen there, not here; the **data** carries the provenance
discriminant so the label is never re-derived at render time. U27's
current-file fallback must slice **in the unit's commitment domain** — for
a Text file that means re-canonicalizing the current bytes before applying
the canonical byte-range (offsets are canonical per spec line 83 /
`CanonMode` docs); when the current file cannot produce the range
in-domain, the snippet is absent, not approximated.

**R6 — Machine surfaces carry values, not renderings.** Wherever a snippet
appears in `--json` output, the field carries the **raw window value**
(the text window as a JSON string — serde's escaping, not R3's; the hex
window as the bare pair string without `hex:`), plus the form
discriminant, the `truncated` flag, and provenance. Quotes, `hex:`, and
`…` are terminal rendering only and never appear inside machine values, so
no consumer ever parses a marker out of data. **Schema shape and stability
are not ruled here** — see §5.

**R7 — Contract status: presentational free space, in the recorded
corridor.** The snippet is derived at display time and enters **no wire
format**: no bundle or manifest key (registry **§7.6** has no slot and
this decision requests none — consistent with **§7.6.1**'s
derived-values-are-not-carried principle), no new error codes, no HKDF
labels or domain tags, nothing freeze-permanent, nothing for Q14/F4. Spec
line 123's format-stability promise covers manifest/bundle versions and is
untouched. The rules above are **library semantics pinned by R15's unit
tests**; the renderings freeze as **snapshots** at M3 (U29's preview
snapshot, U27's fixtures, R18's wording discipline for its own domain) and
become **compatibility promises only at U32** (that row's own text). Until
U32, changing a cap or the escape set is an ordinary code change plus a
snapshot re-freeze — which is exactly why the values were measured here
rather than guessed: nothing should need to move.

**R8 — Home: zero `antseal-core` footprint.** Every consumer of the
snippet is CLI-side (R15/R16/U27/U29); the verifier page never renders one
and the report types are prohibited from growing one (§1 h). Per the D34
placement R16's Notes already record (S/U-typed reveal orchestration lives
in the `antseal_cli` `[lib]` target), the window/escape/hex helpers and
both constants live beside R15's computation in `antseal-cli`. `seal-core`
WASM safety is untouched because `seal-core` is untouched.

---

## 4. Refused shapes

| shape | refused on |
| --- | --- |
| no snippet in v1 | spec lines 36 + 149 name it normatively on both surfaces (§1 a); only content-binding field in the gate; scrollback class not closable while `show` prints the same bytes gate-free (§2.1) |
| length-only preview | same measurements; inverts line 121's floor into a ceiling (§2.2) |
| whole-unit preview | units are MB-scale; a prompt that scrolls its own confirmation off-screen destroys the gate (§2.3) |
| content sniffing at preview time (`is_text` re-run per unit) | mints the classifier the code does not have; the committed `CanonMode`/`UnitKind` is the domain being disclosed, and sniffing can render a forced-binary unit as text, misstating the disclosure's domain (§3 R2) |
| text rendering for raw mirrors | BOM renders invisibly; misrepresents the one unit kind whose purpose is byte-exactness (§1 g) |
| `from_utf8_lossy` fallback | U+FFFD shows characters that are not the bytes, in a consent surface (§3 R2) |
| grapheme-aware truncation | parked in v1.1 twice over (spec lines 96/161, TODO parking lot); house pattern is code-point backoff (§1 d, i) |
| `escape_debug` / printability-table escaping | Unicode-version-dependent output rots snapshots under a pin bump; the closed set is version-independent (§3 R3) |
| grouped / `0x`-prefixed hex | would mint a second hex spelling against every existing surface (§1 e) |
| 80/128-byte text cap, 32-byte hex cap | no identification gain measured over the house 64 / one hexdump row; width cost is real (§3 R1) |
| marker inside the quotes | U+2026 is passthrough content; inside position is forgeable, outside is not once `\"` is escaped (§3 R3) |
| a `--no-snippet` flag | mints CLI surface no task owns to serve a threat (§2.1's hostile terminal) whose user already holds the mitigation; recordable at v1.1 if a real user asks |

---

## 5. The D67/D65 edge, drawn explicitly

**D67 owns the snippet *value*** — which bytes are selected (R1), how the
form is judged (R2), how each form and the absent arm render (R3–R5), and
the value-vs-rendering split on machine surfaces (R6) — on **every**
surface where a snippet appears. **D67 rules nothing about any `--json`
schema**: field names, envelope shape, and any stability commitment stay
with the D65/U50 family exactly as `listing.rs`'s recorded state has it
(D65 not in force; `ENVELOPE_VERSION` is the machine contract in force).
**D65, conversely, can never collide with D67**: its subject is the
verdict report (R21/U30), and verdict/report types carry no snippet by
standing prohibition (`verify/report.rs:825`). If a future decision
freezes `show`'s JSON schema, it freezes the *shape around* R6's values;
the values remain D67's.

Adjacent and deliberately untouched: **D28**'s promotion consequence
(revealing a file's last unit promotes to a full reveal and opens the
whole-file commitments — R15/U28 must surface it) is a *row annotation*
obligation, already ruled there and not re-opened here.

---

## 6. Consumed rows and inputs

- **R15** (`tasks/R.md`) — the Notes line *"Snippet length/format is an
  open decision (small)"* is discharged by this record.
- **U27, U29** (`tasks/U.md`) — the rendering surfaces; U29's snapshot
  Accept is the M3 freeze vehicle (§3 R7).
- **MVP-SPEC.md** lines 36, 149, 121 (and 83/92/96/161 as measured).
- **D28** (promotion + derived-shape precedent), **D43** (cache-first
  snippet provenance), **D34** via R16's Notes (home), **D20/D22/D25**
  (classification and canonical-form facts), **D51** (machine-mode matrix
  U29 inherits — unchanged here), the v1.1 parking lot (grapheme deferral),
  and `docs/format/registry-v1.md` **§7.6 / §7.6.1** (cited by section;
  no registry change requested).

---

## 7. Edit set

**This lane wrote one file: this one.** Everything below is instruction for
the registrar/implementing lanes.

1. `TODO.md` decision register, D67 line (Due M3 block) — replace with the
   resolved line quoted in the lane's closing report (§9-equivalent
   deliverable; D43's line is the model).
2. `docs/decisions/README.md` — one index row for this record, in id order,
   status/date from this record's own lines (D119 conventions).
3. `tasks/R.md` R15 — replace the Notes line with the quoted note in §8.1.
4. `tasks/U.md` U27 — append the quoted note in §8.2.
5. `tasks/U.md` U29 — optional one-liner in §8.3; U29 needs no behavioural
   change (it renders R15's data and snapshot-freezes the result).
6. **No edits** to `MVP-SPEC.md`, the frozen registry, any code, or any
   fixture are requested by this ruling.

---

## 8. Quoted entry notes (registrar's to apply)

### 8.1 `tasks/R.md` R15 — replace the `Notes` line

> - Notes: Snippet length/format ruled 2026-08-11 by **D67**
>   (docs/decisions/D67-disclosure-preview-snippet-format.md): text = first
>   **64** post-padding-strip plaintext bytes, cut backed off to a UTF-8
>   code-point boundary (never a split code point; grapheme handling stays
>   parked); binary and raw-mirror = `hex:` + first **16** bytes as
>   ungrouped lowercase pairs; marker `…` outside the closing quote iff
>   truncated; form = the manifest's committed domain (`CanonMode` ×
>   `UnitKind` — mirrors always hex, no content sniffing; UTF-8 failure on
>   a text-domain window → hex arm, never `from_utf8_lossy`); text windows
>   render through D67 §3 R3's closed escape set (C0/C1/DEL + bidi
>   controls); absent arm renders `(snippet unavailable)` with the row's
>   file/range/size intact. Caps are named constants beside this function,
>   pinned by the unit tests above; presentational (no wire field, no
>   codes) until U29/R18 snapshots freeze the rendering (U32 makes it a
>   promise).

### 8.2 `tasks/U.md` U27 — append a `Notes` line

> - Notes: **[D67, 2026-08-11]** Snippet value + form are D67's
>   (docs/decisions/D67-disclosure-preview-snippet-format.md): 64-byte text
>   window to a code-point boundary / `hex:` + 16-byte lowercase-pair
>   window; form from the manifest's committed domain (raw mirrors always
>   hex — a BOM must not render invisibly beside the not-selectable mark);
>   escaping per D67 §3 R3; marker `…` outside the quotes; absent arm
>   renders `(snippet unavailable)`. The current-file fallback slices in
>   the unit's commitment domain (re-canonicalize a Text file before
>   applying the canonical range, spec line 83) or degrades to absent —
>   never an approximate raw-offset slice. In `--json`, snippet fields
>   carry the raw window value + form + truncated + provenance; quotes,
>   `hex:` and `…` are terminal rendering only. Schema shape/stability
>   stays with the D65/U50 family.

### 8.3 `tasks/U.md` U29 — optional one-liner

> - Notes: **[D67, 2026-08-11]** The preview's snippet rows render per D67
>   (64-byte text / 16-byte `hex:` windows, closed escape set, `(snippet
>   unavailable)` arm); this row's snapshot is the M3 freeze vehicle for
>   that rendering. Under this gate the absent arm is near-unreachable:
>   R16 already holds every revealed unit's plaintext or the build itself
>   fails.

---

## 9. Discovered work — described, not registered

No ids are minted here.

**(i) R15's Do still says "local staged bytes"** for the snippet source,
predating D43's journal→cache reclassification for completed works; R16's
Notes carry the bracketed D43 correction and R15's prose was never
updated. Doc-prose staleness only — §8.1's note supersedes it in practice
— ledger material for the registrar.

**(ii) The escape discipline minted here has no counterpart on existing
consent surfaces.** The seal-consent report prints titles and file paths
with no control-character handling anywhere in `antseal-cli` (measured by
grep across `seal_consent.rs`/`seal_warnings.rs`/`listing.rs`). Exposure
is self-injection only (the values are the user's own args), so this is an
observation, not a defect row; U31's copy-catalog lane is the natural
owner if it is ever promoted.

---

## Outcome

The register filed this as a small presentational choice and, on
freeze-weight, it is one: no wire field, no codes, snapshots at M3, a
promise only at U32. What the framing missed is that the field in question
is the one piece of *content* on an irreversible-consent screen, which
makes its rendering a display-integrity surface: the bytes must be the
bytes (no lossy substitution, mirrors in hex), the cut must be honest
(code-point boundary, unforgeable marker), and the screen must not be
repaintable by the thing it is previewing (closed control/bidi escape
set). The two refusal arms would have removed that surface entirely and
were refused on the spec's own text and on what the gate is for. The
numbers themselves — 64 and 16 — are the house's existing echo bound and
one hexdump row, chosen so that nothing here is a new convention: the
snippet renders in the product's only hex spelling, truncates by the
house's only truncation pattern, and freezes on the same corridor as every
other M3 presentation.
