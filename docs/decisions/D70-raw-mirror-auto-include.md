# D70 — Raw-mirror auto-include on whole-file reveals: always automatic vs future opt-out

- **Status: RESOLVED — automatic, and the lean survives on measurement, not
  confirmation: the spec does not mandate automatic inclusion (line 114's own
  parenthetical makes the mirror conditional, and the mirror-less full reveal
  is a frozen REQUIRED golden vector that verifies), but it kills every
  alternative the MVP surface could express — a v1 opt-out flag is dead
  against line 149's canonical CLI list, and never-include makes line 92's
  selection rule vacuous and the M0-frozen rows 9–10 permanently dormant.
  NOTHING is reserved for the future opt-out, because the reservation already
  exists: a mirror-less full reveal verifies today, fixture- and
  frozen-vector-pinned, so a v1.1 `--no-mirror`-class flag is a pure
  builder/CLI addition with zero format cost. The converse invariant — full
  reveal ⇒ mirror present — is a BUILDER guarantee in both directions; the
  verifier enforces neither direction, and must not start.**
- **Date: 2026-08-11** (wave 16, D70 lane, briefed to overturn the automatic
  lean — the opt-out and verifier-must-not-care arms were taken to
  measurement; one is absorbed as load-bearing, the others die on frozen
  bytes and the frozen spec.)
- **Owning tasks: R13/R16** (consumed by R14 property suite, R15/U27
  disclosure preview, U28/U29 CLI + consent, R18 wording policy for mirror
  states; builds on D23 placement, D28 full-reveal strictness, G7 predicates)

---

## 1. What was measured

**(a) The spec's four sentences, and what each one decides.**

MVP-SPEC.md line 92 (raw mirror — the selection rule):

> Selection rule: **includable only via a whole-file reveal (or `--all`); a
> bare `--units <mirror-id>` is rejected** so a raw file is never disclosed
> by a mistyped id.

This is a **ceiling**, not a mandate: it names the only paths by which the
mirror *may* enter a bundle. It does not say those paths *must* include it.
The same line's verify path is explicitly conditional — *"`unit_commit`
opening always, plus the `file_salt`-keyed `raw_commit` opening **when
proving exact original bytes**"*.

Line 114 (reveal bundle contents):

> \+ per **fully revealed** file {`file_salt`, **`s_root`** (…)} **(and its
> raw-mirror unit when proving exact original bytes)**

The parenthetical conditions the mirror's presence. A fully revealed file's
`{file_salt, s_root}` entry is unconditional (D28 made it hard-fail); the
mirror clause is not written that way. **A mirror-less full reveal is
therefore a legal v1 bundle shape by the spec's own contents list** — the
sentence that decides question 1's "spec-mandated or project-chosen": the
inclusion policy is **project-chosen**; the spec fixes only where inclusion
is permitted.

Line 121 (the binding check) is conditional on the same fact: *"whenever a
reveal discloses **both** a file's raw-mirror bytes and its canonical
content (every full reveal carrying a raw mirror), the verifier MUST
recompute `canonicalize_v(raw_mirror_bytes)` …"*. The check's trigger is
presence, not full-reveal-ness.

Line 149 (CLI surface): *"**MVP — this list is canonical; the flows above
are examples of it**"* — and the canonical `reveal` is
`reveal <work-id> (--all | --units …) [-o file] [--include-receipt]
[--yes]`. **No mirror flag exists.** A v1 opt-out flag is a spec change to a
frozen spec; the arm is dead on this sentence alone.

**(b) The verifier enforces neither direction of "mirrors ⟷ full reveals" —
and both tolerances are frozen.**

- **Full reveal without the mirror verifies.** D28's positive-fixture table
  row `full-reveal-without-mirror` (*"the mirror is not part of the
  predicate"*) is implemented and green:
  `full_reveal_without_the_mirror_is_still_full`
  (`crates/antseal-core/src/verify/file_stages.rs:1720-1732`) — a BOM-source
  text file, its one canonical unit revealed, the mirror withheld,
  classifies `Full` and verifies; rows 9–10 simply do not run. **Stronger:
  the shape is a frozen end-to-end golden vector.**
  `REQUIRED_SHAPES` (`crates/antseal-core/src/test_util/vectors_report.rs:91`)
  pairs `single-text-with-mirror/full-no-mirror` with the R9 milestone row
  **"full text reveal"** — the canonical full-text-reveal vector in
  `testdata/vectors/v1/report/verification-reports.json` (pinned by
  `FROZEN.sha256`) is the *mirror-less* one. Any arm that makes the verifier
  demand the mirror on a full reveal flips a committed accept to a reject
  and regenerates frozen vectors. Dead.
- **Mirror alongside a partial reveal also verifies.** The module doc's
  *"What R4 deliberately does not check"* section
  (`crates/antseal-core/src/verify/file_stages.rs:163-172`) records it as a
  deliberate non-check: the spec's selection rule is *"a **builder** guard
  against a mistyped id"*; a bundle shipping a mirror with a partial reveal
  discloses only the sealer's own raw file, the mirror stays `unit_commit`-
  bound at R2, no `file_salt` exists for it to open, and *"turning it into a
  bundle-validity invariant would mint a permanent code and is not in line
  121's enumeration — it needs its own decision first."* **This record is
  that decision, and it refuses the invariant** (§4). R53 settled the
  report half: the mirror is verified-but-unreported —
  `FileReveal::raw_mirror` is `Some` only with a full reveal
  (`crates/antseal-core/src/verify/report.rs:786-798`; presenting a
  partial's mirror as "the original file" would promote unbound bytes,
  2026-07-31 review finding 8).

So R13's Accept line *"mirrors appear only with full-file reveals"*
describes **builder output**, not verifier law — measured, in both
directions.

**(c) The content model: not every file has a mirror, and at most one.**

- `needs_mirror(raw, canonical) ⟺ raw_bytes != canonical.as_bytes()` —
  byte inequality is the whole rule
  (`crates/antseal-core/src/content/mirror.rs:104-107`, G7). Binary files
  never have one (no canonical rendition); already-canonical text has none;
  the empty file has none (empty raw = empty canonical).
- At most one per file, the file's **last** unit (D23; clause 3 makes a
  second mirror unrepresentable in any decoded manifest —
  `manifest-multiple-raw-mirrors` fires at decode,
  `crates/antseal-core/src/manifest/error.rs:604`, tamper row committed).
- A mirror-**only** file is unrepresentable: registry §7.4 requires at
  least one `kind = normal` unit per file (reject at F5).
- The one resolution of "this file's mirror" is by kind, never position:
  `resolve_raw_mirror` (`crates/antseal-core/src/verify/file_stages.rs:752-783`),
  first-wins over the concat-exemption predicate.
- `--no-fine-tree` is **orthogonal**: G7's rule has no fine-tree condition,
  so a `--no-fine-tree` CRLF/BOM text file still carries a mirror; the
  mirror is never fine-tree-covered regardless (G7 truth test), and rows
  9–10 run for such a file's full reveal like any other (row 10 always in
  `TextMode::Forced`, D20).

**(d) R6's constructor already implements the ruling — and the overturn
shapes as fixture-only counterfactuals.**
`FileSelection::Full` pushes the mirror iff the file has one
(`crates/antseal-core/src/test_util/bundle_fixtures.rs:846-854` — `if
*chosen == FileSelection::Full && let Some(mirror) = file.mirror_unit`);
`WorkSelection::All` = every file full, mirrors included (`:413`);
`FullNoMirror` and `UnitsWithMirror` exist as deliberately dishonest
fixture-only shapes (*"a bundle no honest CLI emits"*, `:386-405`) that
exercise the two verifier tolerances above. The mirror-less arm is a no-op
by construction for a file with no mirror — no error path exists.

**(e) The wire has no mirror surface to reserve, and the named-reserved
list contains no mirror slot.** A revealed mirror is an **ordinary**
non-covered reveal entry `{unit_id, unit_salt, k_u, ciphertext}` (registry
§7.12 — *"no mirror flag, no link"*) inside `noncovered_reveals` (§7.6
key 7, strictly ascending `unit_id`). The fully-revealed-file entry (§7.14)
carries keys 0–2 only; no mirror field. The named reserved slots (§9) are
bundle key 10 `range_reveals`, receipt key 3 `chain_inputs`, and `sig_alg`
values 2–15 — reserved by recorded decision, and **no mirror-opt-out slot
exists among them**. None is needed: the mirror's opt-out *is its absence*,
which is D28 rider 1 (*"reveal shape is derived, never declared"*) applied
to one more piece of optional evidence.

**(f) R13 does not exist yet.** No `build_bundle` in
`crates/antseal-core/src`; R13/R14/R16 unchecked (TODO.md rows). This
ruling lands before the code, as intended.

---

## 2. The v1 arms

Three behaviors were expressible; two die on the frozen spec.

**Arm N — never include (mirror stays vault-side in MVP).** Refused. Under
N, no MVP path ever includes a mirror: line 92's carve-out names the only
two inclusion routes, and N takes neither — a spec sentence enumerating the
sole paths by which a thing may be included is made vacuous by a build that
never takes them. Line 114's contents clause goes equally dead. Worse, the
M0-frozen verify machinery built for the mirror — rows 9–10
(`RawCommitMismatch`, `RawMirrorCanonicalizationMismatch`), their tamper
rows, and the REQUIRED frozen shape `single-text-with-mirror/full` (**"raw-mirror
full reveal"**, `vectors_report.rs:110`) — would describe bundles the
product never emits, and a text file's `raw_commit` would be openable by no
bundle ever: precisely the *"permanently unfalsifiable commitment"* defect
D28 refused for `canon_commit`, reproduced for `raw_commit`. The mirror was
also paid for and permanently stored (line 92: it exists so *"the original
bytes reach storage and `raw_commit` is openable from the network"*) —
dead weight under N.

**Arm F — a v1 opt-out flag.** Refused on line 149 (§1a): the MVP CLI list
is canonical and has no such flag. A wire-declared opt-out is refused
independently by D28 rider 1 — shape is carried by absence, never by a
declared discriminant — and by the frozen registry: assigning a reserved
key is a recorded format decision this record declines to make (§1e).

**Arm A — automatic.** Adopted. What survives of the overturn brief against
it, stated honestly:

1. *Default-minimal disclosure* (bundles are irreversible; automatic
   discloses more per bundle). True, and answered by the project's own
   pattern for irreversible acts: **informed consent, not silent
   narrowing**. The mirror is a listed, sized unit row in the R15 preview
   (its Do already includes *"whether a raw mirror will ride along"*) and
   inside U29's irreversible-disclosure confirmation; line 36 requires the
   reveal to print *exactly which units* will be disclosed. And the
   marginal disclosure is small where it exists at all: for CRLF/BOM/NFD
   sources, a full-reveal recipient already holds `file_salt`,
   `raw_commit`, and the complete canonical bytes — D28's recorded residual
   is that the raw form is brute-forceable from ~a dozen candidates, so
   withholding the mirror there protects a fingerprint the recipient can
   recover anyway. The honest exception is `--force-text` (§9).
2. *Bundle size* — the mirror roughly doubles that file's embedded
   ciphertext. Real, consented (the preview shows the mirror's `raw_size`),
   and exactly what the free v1.1 opt-out can save (§3).
3. *"The verifier must not care."* Correct — and **absorbed as the ruling's
   load-bearing half** rather than refused: the verifier's measured
   neutrality (§1b) is what makes the future opt-out free, and §4 forbids
   tightening it in either direction.

What automatic buys, in D28's own currency: `raw_commit` and the line-121
anti-co-timestamping binding are **conditionally guaranteed** — *if an
honest builder issues a full reveal of a mirror-bearing file, the mirror
rides, `raw_commit` is opened, and `canonicalize_v(raw) == canonical` is
checked*. A sealer who sealed a bogus "original" is caught by the first
full reveal, not never. (A malicious sealer can still hand-build a
mirror-less bundle — the verifier accepts the shape — but the manifest in
every bundle shows the mirror unit exists, `kind` and sizes being public
structure metadata, so a counterparty can demand it; see §10 (iv) for the
report-surface gap.)

---

## 3. The future opt-out: nothing to reserve, because the reservation already exists

The brief's question — must v1 reserve a format slot, CLI surface, or
verifier tolerance for a later opt-out — dissolves on §1b + §1e:

- **Verifier tolerance: already exists, already frozen.** The mirror-less
  full reveal verifies today, pinned twice — the D28 positive fixture and
  the frozen `single-text-with-mirror/full-no-mirror` golden vector. It is
  not something v1 must *add*; it is something v1 must *not remove* (§4).
- **Format slot: none needed, and none may be minted.** The opt-out's wire
  encoding is the absence of one `noncovered_reveals` entry — a shape the
  registry already admits. The format is frozen; this record assigns no
  reserved key and adds nothing to §9's named-reserved list.
- **CLI surface: deferred whole.** A v1.1 `reveal --no-mirror`-class flag
  is a builder-input + preview-wording + consent-copy change: R16 gains a
  selection parameter, R13 gains a knob (v1 deliberately has none — §7),
  R14's converse property becomes conditional on the knob, U28/U29 gain
  the flag and its preview line. **Zero format bytes move, zero golden
  vectors move, zero verifier changes.** Measured cost of the deferral:
  nothing is foreclosed.

This is the reversibility D28 rationale 4 asked for, in a cheaper form:
there, strict→permissive was a legal *format* relaxation; here both
directions are builder policy and the wire is untouched either way. The
v1.1 parking lot's scope discipline (*"the MVP obligation is only that
these remain **possible**"*) is satisfied by the frozen tolerance itself.

One boundary for the future lane, recorded now so it is not re-derived: a
v1.1 opt-out flag governs the **builder's emission only**. It must not
grow a wire discriminant ("mirror withheld by choice") — that would be the
declared-shape defect D28 rider 1 exists to prevent — and it must not
change what the verifier accepts.

---

## 4. The converse invariant: both directions are builder guarantees, and the verifier gains nothing

R13's Accept asserts *"mirrors appear only with full-file reveals"* (the
forward direction). The brief asks about the converse: full-file reveal ⇒
mirror present. Ruled, from §1b's measurements:

| direction | verifier today | after D70 |
| --- | --- | --- |
| mirror revealed ⇒ file fully revealed | **not enforced** (deliberate non-check, `file_stages.rs:163-172`; R53: verified-but-unreported) | unchanged — builder guarantee only |
| file fully revealed ∧ manifest has a mirror ⇒ mirror revealed | **not enforced** (`full-reveal-without-mirror` is a frozen positive vector) | unchanged — builder guarantee only |

**The verifier is assigned no new duty, permanently for v1.** Either
tightening flips a frozen accept to a reject: the converse direction
regenerates the `single-text-with-mirror/full-no-mirror` golden vector
(and its R30 digest row); the forward direction rejects the R53 shape whose
tolerance is pinned by committed stage tests and the report producer's
documented rule — and both would break line 123's format-stability promise
for any v1 bundle already issued. The module doc's *"needs its own decision
first"* is hereby answered: **refused**.

Consequently:

- **R13** must assert *both* directions structurally over its own output —
  and cannot delegate either to the mandatory `verify_bundle` self-check,
  which (measured) accepts violations of both. The forward direction is
  additionally enforced upstream by R16's selection resolution
  (`mirror_selectable` / `unit_selectable`,
  `crates/antseal-core/src/content/mirror.rs:187-210`, already shipped:
  bare mirror id → `ContentError::RawMirrorNotUnitSelectable`).
- **R14** property (c) (*"includes mirrors only alongside full-file
  reveals"*) gains its converse arm: for every fully revealed file whose
  manifest carries a `kind = raw-mirror` unit, that unit's `unit_id` is in
  the built bundle's revealed set and its §7.12 entry is present. Like the
  ancestor-seed checker, derive "has a mirror" independently (scan the
  fixture's unit table by kind), not through R13's own resolution.

---

## 5. Files with no mirror, and `--no-fine-tree`

R13's Do reads *"per fully revealed file {`file_salt`, `s_root`} plus its
raw-mirror unit"*. All three items are conditional, each on its own
measured predicate, and none of the three absences is an error:

| item | present iff | absent for |
| --- | --- | --- |
| `file_salt` | `full(F)` (D28 — unconditional on a full reveal) | — |
| `s_root` | `full(F) ∧ FineTree::Present` (D28) | `--no-fine-tree` files, empty files |
| mirror unit | `full(F) ∧` manifest has a `kind = raw-mirror` unit for `F` | binary files, already-canonical text, empty files |

*"Plus its raw-mirror unit"* for a file with none is a **no-op, never an
error** — exactly R6's implemented shape (§1d). A `--no-fine-tree` text
file with a mirror emits **two** non-covered reveals on a full reveal (its
whole-file unit and its mirror, each `{unit_id, unit_salt, k_u,
ciphertext}`), no `s_root`, and still runs rows 7, 9, 10.

---

## 6. The ruling

1. **v1 behavior: automatic.** A whole-file reveal (per-file full,
   `--all`, or a `--units` subset that completes the file) includes the
   file's raw-mirror unit whenever the manifest records one. This is
   **project-chosen within a spec-narrowed space**: the spec's own
   contents line (114) leaves the mirror-less full reveal legal, but the
   canonical CLI surface (149) admits no v1 selector, and never-include is
   refuted by lines 92/114 and the M0-frozen mirror machinery (§2).
2. **No reservation is minted for the future opt-out — deliberately.** The
   opt-out remains possible at zero format cost because the mirror-less
   full-reveal shape already verifies, frozen-vector-pinned. No reserved
   key, no CLI stub, no new verifier tolerance. A v1.1 flag is builder/CLI
   surface only and must never become a wire discriminant (§3).
3. **Both mirror ⟷ full-reveal directions are builder guarantees.** The
   verifier enforces neither today and is assigned neither — assigning
   either would move frozen accepts (§4). R13 asserts both internally;
   R14 tests both; R16's selection rejection covers the forward direction
   at the API boundary.
4. **Mirror emission is conditional on existence** (`full(F)` ∧
   manifest-has-mirror, kind-resolved), a no-op for the mirror-less file;
   `--no-fine-tree` is orthogonal and its mirror-bearing files behave per
   §5.
5. **Zero frozen bytes.** Nothing here regenerates a committed golden
   vector, moves registry bytes, mints an error code, or changes any
   verifier verdict.

---

## 7. What R13 must implement (verbatim for the implementation lane)

1. **No mirror knob in v1.** `build_bundle`'s inputs stay exactly as
   R13's Do lists them; mirror inclusion is **derived inside the builder**
   from the resolved per-file selection: for each file classified full,
   locate the file's mirror by `kind` (the `resolve_raw_mirror` semantics —
   kind-based, never position; at most one exists, D23 clause 3) and, if
   present, add its `unit_id` to the revealed set and emit its non-covered
   reveal entry `{unit_id, unit_salt, k_u, ciphertext}` (registry §7.12)
   into `noncovered_reveals` (§7.6 key 7; F9's global
   strictly-ascending-`unit_id` ordering handles placement — no
   special-casing). A file with no mirror contributes nothing — no error,
   no log. Type-level: because no input can express "full without mirror"
   or "partial with mirror", R6's `FullNoMirror` / `UnitsWithMirror`
   remain fixture-only shapes **R13's API is unable to produce** — assert
   that in the parity test rather than merely not producing them.
2. **Emit no mirror-specific material beyond the §7.12 entry.** The
   `raw_commit` opening reuses the `file_salt` already emitted in the
   file's §7.14 entry; nonces stay manifest-only; nothing new touches the
   wire.
3. **Structural self-assertions, both directions** (§4): before returning,
   assert (a) every emitted mirror entry belongs to a file classified
   full; (b) every full-classified file with a manifest mirror has its
   mirror entry emitted. These are internal assertions in the same family
   as the isolation checks — the mandatory `verify_bundle` self-check
   **cannot** catch either (measured, §1b), so their absence is not
   covered by it. `verify_bundle` remains mandatory regardless: with the
   mirror present it runs rows 9–10, so wrong mirror *bytes* still abort
   the build.
4. **Partial and untouched files: never a mirror entry**, even though the
   verifier would accept one. R16's `unit_selectable` rejection is the
   API-boundary guard; R13's assertion (3a) is the belt.
5. **Ciphertext availability**: R16's gathering step already fetches all
   units of every touched file — that includes the mirror. R13 receives
   the mirror ciphertext through the same per-unit ciphertext input as
   every other unit.
6. **Preview parity** (R15/R16/U29): the "raw mirror will ride along"
   annotation and the mirror's preview row (file, byte-range
   `[0, raw_size)` in the raw domain, size) must be derived from the same
   `full(F) ∧ has-mirror` predicate the builder uses, so R16's Accept
   ("the preview data matches the final bundle contents") holds by
   construction — including on **promotion**, where a `--units` subset
   completing a file pulls in `file_salt`, `s_root`, *and* the mirror, and
   the consent gate must say all three (D28 consequence; R16 Accept
   "subset completing a file (mirror rides)").
7. **R14 additions**: property (c) gains the converse arm (§4), with
   mirror-presence re-derived independently of R13's resolution; the
   negative control ("forcing the builder to emit a forbidden item makes
   the self-check fail") does **not** transfer to the mirror rules —
   forcing a mirror omission or a partial-mirror emission passes
   `verify_bundle` (measured), which is exactly why (3)'s assertions are
   the enforcement and must have their own negative controls.

---

## 8. Spec conformance

- **Consistent with the spec, on its quoted text**: line 92's ceiling is
  honored (mirror enters only via whole-file/`--all` paths — R16 rejects
  bare ids); line 114's contents clause is realized with "when proving
  exact original bytes" resolved to "on every whole-file reveal", the only
  resolution the canonical CLI surface (line 149) can express; line 121's
  binding check fires on every honest full reveal of a mirror-bearing
  file, which is the strongest conditional guarantee available (§2 Arm A).
- **One recorded narrowing, stated plainly**: MVP users cannot issue a
  full-content reveal that withholds the original bytes. That shape exists
  in the format (frozen vector) but not in the product until v1.1 chooses
  to surface it. This is scope discipline, not format law.

---

## 9. Residual risk (of the decision taken)

- **`--force-text` mirrors carry real marginal disclosure.** For
  CRLF/BOM/NFD sources the mirror's content is brute-force-recoverable by
  any full-reveal recipient anyway (D28's residual), so automatic costs
  ~nothing. A `--force-text` file's mirror bytes are invalid UTF-8 whose
  canonical rendition is lossy — the raw bytes are *not* recoverable from
  the canonical form, so for these files the mirror is a genuine
  additional disclosure. It is consented (preview row + U29 gate), it is
  usually the point (for a `--force-text` file the raw bytes *are* the
  work), and the free v1.1 opt-out is the relief valve — but until v1.1, a
  user who wants to fully reveal such a file's canonical form without its
  original cannot. Documented, accepted.
- **Bundle growth**: a full reveal of a mirror-bearing file embeds the
  file's ciphertext roughly twice (canonical units + raw mirror). Docs
  note alongside R16's fetch-all note.
- **The guarantee is conditional, as all of D28's are**: a sealer who
  never fully reveals never opens `raw_commit`; a hand-built mirror-less
  bundle still verifies. The manifest's public structure metadata (the
  mirror unit's existence and size) is the counterparty's lever; §10 (iv)
  records the report-surface gap.

---

## 10. Discovered work — described, not registered

No ids are minted here.

**(i) R13's Notes and the tasks/R.md open-decisions row use executed-past
phrasing for unstarted work.** tasks/R.md R13's Notes read *"Raw-mirror
inclusion on full-file reveal **implemented** as automatic"* and the
open-decisions row *"always automatic **(implemented default)**"* — R13 is
unchecked and `build_bundle` does not exist (§1f). The accurate referent
is R6's fixture constructor (§1d). Instrument prose finding; the D70
entry notes replace the pointers.

**(ii) A verifier-side decision candidate lives only in a module doc, and
the freeze has overtaken it.**
`crates/antseal-core/src/verify/file_stages.rs:173-181` records
*"`raw_commit` on a text full reveal with no mirror in the manifest"* —
i.e. when no mirror exists, `raw_commit` should open to the canonical
bytes, one SHA-256 — as *"a decision candidate rather than implemented"*.
No register row carries it, and post-Q14 it is foreclosed for v1: adding
the rejection would fail v1 bundles that verify today (line 123). The
restore path already performs the equivalent check vault-side (tasks/S.md
S14 execution note 5). Ledger material.

**(iii) R18's mirror-wording policy now has its third state.** R18's R53
note demands a stated policy for a *partial* reveal's mirror bytes. Under
D70 the wording set must also cover the full reveal **with** mirror (rows
9–10 bound — the only state entitled to "the original file" phrasing, per
the R53 note) and the full reveal **without** mirror (legal, frozen-vector
shape: `raw_commit` unopened, binding unchecked — must never render as if
original bytes were proven). Feeds the existing R18 obligation; no new row
needed beyond what R18 already owes.

**(iv) The report does not surface a withheld mirror.** On a full reveal
of a mirror-bearing file with the mirror absent, the report shows
`raw_mirror: None` and `unrevealed_spans` lists only non-mirror units
(`crates/antseal-core/src/verify/report.rs:780-798`) — nothing says "the
manifest records a mirror this bundle did not open"; the only trace is the
manifest unit table. Honest R13 bundles never have this shape under D70,
but D28-amendment consistent narrowings and hand-built bundles do. A
rendering-completeness candidate for R18/R19 (verdict-neutral — the
accept is frozen; this is about what the redaction view *says*), sitting
naturally beside (iii).

---

## Edit set

**This lane wrote one file: this one.** Everything else is instruction for
the registrar:

- `TODO.md` D70 register row → resolved form (text supplied in the lane
  report).
- `docs/decisions/README.md` → this decision's index row (supplied).
- `tasks/R.md` R13 Notes and R16 entry → dated D70 notes (supplied); the
  open-decisions row for the mirror gains its resolution pointer.
- No code, no testdata, no `docs/format/` bytes. Zero frozen bytes.
