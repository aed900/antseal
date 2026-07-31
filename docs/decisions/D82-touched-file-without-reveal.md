# D82 — Is a `touched_files` entry for a file with **no** revealed unit legitimate?

- **Status: RESOLVED — NO, reject. `touched_files` must equal the set of
  files with a revealed unit; the converse half D80 left open is now
  closed. New code `touched-file-without-revealed-unit`, R5 coherence
  group 1b**
- **Date: 2026-07-28**
- **Owning task: R5 coherence** (consumed by R7's fixture list, R6/R13's
  builders, R19's redaction view, Q8's registry)
- Surfaced 2026-07-28 at R5, which deliberately declined to decide it
  (`crates/antseal-core/src/verify/coherence.rs:59-66`).

## The question

D80 settled one direction: every revealed unit's owning file **must** have a
`touched_files` entry. The converse — a `touched_files` entry for a file the
bundle reveals nothing from — is currently allowed. It is a real disclosure
shape on its face ("a file by this path was part of the work, and here is
nothing else"), so the permissive reading might be right. Either answer is
format-permanent.

## What the code does today

- **F8 (tier `[X]`)** enforces `full_reveals ⊆ touched_files`
  (`crates/antseal-core/src/bundle/error.rs:457-461`) and nothing in the
  other direction. It could not: mapping a reveal to its owning file needs
  the signed unit table, which D78 keeps out of layer 1.
- **R3 verifies the entry.** `check_path_commits`
  (`crates/antseal-core/src/verify/structural.rs:357-387`) recomputes
  `path_commit = SHA-256(0x05 ‖ path_salt ‖ path_utf8)` for **every** touched
  entry, revealed-from or not, and rejects an unknown `file_id`
  (`unknown-file-ref`) or a bad opening (`path-commit-mismatch`). It iterates
  the *bundle's* list, so these fire before any coherence check.
- **R5 coherence permits it, in writing.**
  `crates/antseal-core/src/verify/coherence.rs:59-66` argues the permissive
  case; `coherence.rs:314-324`
  (`a_touched_file_with_no_revealed_unit_is_allowed`) pins it.
- **The report throws the path away.** `reveal_set`
  (`crates/antseal-core/src/verify/pipeline.rs:906-991`) sets `touched` from
  `is_revealed` alone (line 926); a file with no revealed unit takes the
  `if !touched` branch at line 951 and is emitted as
  `UnrevealedFilePlaceholder { file_id, size }` — **size only, path
  withheld**. The verified path is discarded. The doc comment at
  `pipeline.rs:900-903` says so explicitly.

So today the format accepts a disclosure it verifies and then refuses to
render.

## Evidence

**1. Line 121's rendering taxonomy is closed in *both* directions.**

> Every reveal displays position + total size (anti-out-of-context
> guardrail); unrevealed units render as sized blackout blocks;
> **unrevealed files render as committed placeholders (size only, path
> withheld)**.

D80 read this to mean there is no state for "revealed content, path
withheld". The mirror reading is stronger, because the spec does not merely
omit the state — it names the opposite: a file with no revealed unit **is**
an unrevealed file, and its path **is withheld**. The permissive reading asks
the verifier to render "unrevealed file, path disclosed", which line 121
forecloses rather than merely fails to mention. Using one reading of one
sentence in D80 and the opposite reading here is not available.

**2. Line 95 says "only".**

> File paths live in the vault, not the manifest: disclosed (with
> `path_salt`) per touched file at reveal time; bundle recipients see
> **unrevealed files only as committed placeholders** ("file #3, 48 KB").

"Only as committed placeholders" is a universal over unrevealed files. A
disclosed path is more than a placeholder.

**3. Line 95 also defines when `path_salt` ships**: "ships whenever any
reveal *touches* the file (so the recipient can verify the path)". D80 fixed
the meaning of `touches` at that italicised defining use: a reveal touches a
file when it discloses a unit of it. A file with no revealed unit is touched
by no reveal, so its `path_salt` does not ship. D80 + D82 together make the
sentence a biconditional:

```text
touched_files  ==  { file_id(u) : u ∈ bundle.revealed }
```

**4. Line 114's bundle enumeration is a closed list**: "… + per **touched**
file {path, `path_salt`} + per **fully revealed** file {…}". `touched` is
line 95's term. An entry for an untouched file is not a disclosure the format
defines — the same closure D74 applied to a stray `s_root` ("Rejecting an
undefined disclosure is the reading in which the verifier's field set is
closed").

**5. It is exactly the D74 hole, in the same unsigned bundle.** The manifest
is signed and anchored; the bundle is not. Today: strip a `touched_files`
entry for a revealed unit's file → D80 fires. **Add** one → nothing fires.
D74 rationale 3 closed precisely this shape for `s_root`, and its argument
transfers without adjustment.

The attack is not a forgery, which is why it matters. A relay cannot invent a
`(path, path_salt)` pair — that needs a preimage of a signed `path_commit`
under a 16-byte secret salt. It does not have to. **`path_salt = HKDF(W,
"path-salt", file_id)` is a per-work constant** (`crypto/hkdf.rs:262`), so
any party who has ever seen a bundle of this work that touches file F holds
that pair verbatim, and can splice it into a second bundle of the same work
that the sealer chose not to disclose F in. It passes R3's `path_commit`
check because it is genuine. The sealer's per-bundle disclosure decision —
the one the CLI consent gate names file by file (line 36) — is silently
overridden by a third party. Under the strict rule that splice is a named
error.

**6. The permissive reading buys the honest sealer nothing today, and
buying it something is a report-format change.** The path is discarded
(`pipeline.rs:951`). To deliver "prove a file by this path was part of the
work" the report would need a third reveal state, and the obvious home is
forbidden in terms:

> This type must never gain a path, snippet, or any content-derived field
> (MVP-SPEC.md line 121; R19 asserts placeholders leak nothing).
> — `crates/antseal-core/src/verify/report.rs:349-360`

So the permissive branch is not "keep the current behaviour". It is: mint a
new `RevealSet` state, decide how R18/R19 render it, and commit Q4/Q9 golden
report vectors for it — under D29 a report-format change, permanent at Q14 —
in order to define a disclosure line 121 says does not exist. The strict
branch changes no report bytes for any bundle an honest builder emits.

## Options

**A — allow.** Requires the report state above, a rendering decision, and
golden vectors; leaves the append hole open permanently.

**B — reject.** One permanent code, one new check in R5's coherence stage.
Forecloses filename-only disclosure until a format version defines it.

## Decision

**Option B — reject.**

- `VerifyError::TouchedFileWithoutRevealedUnit { file_id: u64 }` →
  **`touched-file-without-revealed-unit`**, in R's unprefixed namespace
  (bundle and manifest each well formed, the two inconsistent — error-code
  contract §2, and the same class as D80's own code).
- Display: `file {file_id}: touched_files entry for a file with no revealed
  unit`.
- One code, not two: there is no material-kind discriminator here, and the
  `full_reveals` variant of the same mistake is unreachable — a full reveal
  reveals every non-mirror unit and F5 refuses a file with none
  (`ManifestError::EmptyContainer`, `manifest/error.rs:201`: "an empty file
  still has one empty unit"), so a fully revealed file always has a revealed
  unit.

## Rationale

1. **The spec answers it, in the same sentence D80 used** (evidence 1–3).
   D80 had to argue from an absent rendering state; D82 has a present one
   that says the opposite.
2. **Strictness is the reversible direction** (D74 rationale 5; line 123
   makes format stability normative). Reject → tolerate is a legal later
   relaxation: bundles built strict keep verifying. Tolerate → reject is
   not. Note this is the **opposite** asymmetry to D80's, where the
   reversible branch was to *require*; both times the reversible branch is
   the one taken, which is the consistency, not a coincidence.
3. **It completes the totality property for `touched_files`.** With D80 and
   D82 the set is exactly determined by the revealed set, so *any* deviation
   in either direction is a named error, and the relay-splice of evidence 5
   stops being silent. Same shape as D74's 2×2 over (fine-tree state,
   `s_root` presence). [Scope note, 2026-07-31 — adversarial review,
   finding 7: total over *disagreement between the two sets*, in both
   directions. A consistent whole-file narrowing (a file's reveal entries,
   `touched_files` entry and `full_reveals` entry removed together)
   shrinks both sets in step, keeps them equal, and correctly fires
   nothing — by design and harmlessly, because the unsigned bundle claims
   only what it discloses. See D28's 2026-07-31 amendment.]
4. **Derived, never declared.** The bundle does not get to assert what was
   disclosed; it is computed from the signed unit table and the revealed set
   (D28 rider 1, `file_stages.rs:11-25`). A touched entry with no reveal is
   the bundle asserting a disclosure the manifest-plus-reveal-set does not
   support.
5. **It costs the honest sealer nothing.** R6/R13 emit a touched entry per
   revealed file because that is the only reason to emit one; the CLI's
   consent gate is file-scoped (line 36). No honest builder can reach the
   rejected shape.

## Cost, stated honestly

One permanent code, and filename-only disclosure is foreclosed for format
v1. That second cost is real: there is no substitute shape at v1 — a sealer
who wants to name a file without showing content has to reveal a unit of it.
The reopening path is deliberate rather than inherited: a future version adds
a `disclosed_paths` section with its own rendering state and its own
decision, instead of the capability arriving by silence in a section whose
verified value the verifier currently discards.

## Implementation instruction

### R5 coherence — where it fires

New **group 1b** in `check_coherence`
(`crates/antseal-core/src/verify/coherence.rs:159-165`), between group 1
(D80) and group 2 (reveal-section agreement):

| # | rule | error |
|---|---|---|
| 1 | every revealed unit's owning file has a `touched_files` entry | `RevealedUnitFileNotTouched` (D80) |
| **1b** | **every `touched_files` entry's file has a revealed unit** | **`TouchedFileWithoutRevealedUnit` (D82)** |
| 2 | every revealed unit sits in the section its manifest binding requires | `RevealModeMismatch` |

`fn check_touched_exactness(units: &[CoherenceUnit], bundle:
&CoherenceBundleView<'_>) -> Result<(), VerifyError>`, called from
`check_coherence` between the two existing calls.

**Effect on the frozen order: additive only.** Every input that violates an
existing rule reports the same code as before, because 1b sits after D80 and
before group 2 and no implemented or pending row binds the (1b, 2)
precedence. The one deliberate new precedence is 1b before group 2.

**Subject order — visit the manifest, not the bundle.** Report the lowest
offending `file_id` in **manifest file-table order**, never `touched_files`
order, for the reason R5 already gives for D80 ("visiting the manifest unit
table so 'first error' cannot depend on bundle layout"). No new view type is
needed: every file has at least one unit (F5's `EmptyContainer`), so the
`file_id`s in `units` — already in manifest order — enumerate the manifest
file table by first occurrence. Iterate that, and for each `file_id` present
in `bundle.touched_file_ids` with no revealed unit, return the error. Keep
`CoherenceUnit` at its three scalars.

Every touched `file_id` is known to exist in the manifest by then: R3's
group 3 already rejected a dangling one as `unknown-file-ref`.

### Code-surface edits

- `verify/error.rs`: new variant in the coherence block next to
  `RevealedUnitFileNotTouched`; a `code()` arm; one entry in
  `all_error_exemplars`; `DISTINCT_CODES` **84 → 85**; the variant tally
  `assert_eq!(tally.len(), 26)` → **27**; the doc comment's "15 single-code
  variants" → 16, naming D82's as the 16th.
- `verify/coherence.rs`: **rewrite the module-doc paragraph at lines 59-66**
  — it currently argues *for* the permissive reading and is now wrong; it
  must cite this record instead. Add the row to the frozen-order table
  (lines 24-28). Invert the test
  `a_touched_file_with_no_revealed_unit_is_allowed` (lines 314-324) into
  `d82_a_touched_file_with_no_revealed_unit_is_rejected`, and add a
  group-order test pinning 1b before group 2 (a bundle violating both).
- `verify/pipeline.rs`: stage table line 20 becomes "… (D80 touched-file
  coverage → D82 touched-set exactness → reveal-section agreement)"; delete
  the now-unreachable clause "including a file whose path the bundle
  disclosed without revealing any of its bytes" from `reveal_set`'s doc
  (lines 900-903). The `if !touched` branch itself is unchanged — it now
  handles only genuinely untouched files. Add a pipeline test
  `d82_touched_file_without_a_revealed_unit_is_rejected` via a new `Tweak`
  knob (e.g. `add_touched_file: Option<u64>`) that splices a **valid**
  `(path, path_salt)` entry for file 2.
- `docs/testing/error-code-contract.md` §7: append the code under the
  2026-07-28 R5 entry's class ("bundle and manifest each well formed, the two
  inconsistent"), with R's universe at **85** codes over **27** variants.

### R7 — the tamper row, and the fixture trap

Add one **project-added** row (line 168 names no family for it, exactly like
D74's):

```json
{
  "row_id": "verify-touched-file-without-revealed-unit",
  "owner": "R",
  "why": "Decision D82 closes the converse of D80: `touched_files` must equal the set of files with a revealed unit. Not named at MVP-SPEC.md line 168, whose list illustrates rather than exhausts; kept because the bundle is unsigned and `path_salt` is a per-work constant, so without this rule any relay holding another bundle of the same work can splice a genuine `{path, path_salt}` entry into a bundle whose sealer chose not to disclose that file — the D74 add-material hole, in the touched-file section."
}
```

Row: base = a multi-file R6 bundle with at least one file revealed from and
one not; mutation = **add** a `touched_files` entry for the unrevealed file;
expected `touched-file-without-revealed-unit`.

**The trap, spelled out because a lazily built fixture will bind the wrong
code:** the spliced entry must carry the file's *correct* `path` and
`path_salt`. R3's `check_path_commits` runs in stage 2 **before** coherence
and iterates the bundle's list, so an entry with a junk salt or a made-up
path fires `path-commit-mismatch` — a different, already-owned outcome, and
the row would silently be testing the wrong thing. R6's constructor must
therefore be able to emit a valid touched entry for a file it reveals
nothing from, even though no honest bundle contains one.

**Audit the positive fixtures.** Every R6/R7 fixture must satisfy
`touched_files == revealed files` or it stops verifying. R5's own fixture
already does (files 0 and 1 touched and revealed from, file 2 neither —
`pipeline.rs:1394`), and none of R7's listed rows disturbs it: stripping
full-reveal material or leaking a salt leaves the revealed set intact. Check
the rest against this rule when writing them.

**One knock-on to check, not to fix blindly.** The recorded non-row
`full-reveal-unit-strip-downgrade` says its mutation's observable outcome is
`partial-reveal-salt-leak-file-salt`. That holds only while the stripped
file still has another revealed unit. On a **single-unit** file, stripping
its one reveal now leaves a touched entry with no revealed unit, so
D82's stage-2 code fires before R4's stage-4 leak arm. The entry stays a
non-row either way (it now collides for two possible reasons) and the R10
property it points at — "no single-unit deletion from a full-reveal bundle
verifies" — is unaffected. Its `why` prose is what goes stale; amend it or
pin the fixture at ≥2 units, R7's call.

### R6 / R13 / R14

The builder invariant is now
`touched_files == { file_id(u) : u ∈ revealed }` — equality, not inclusion.
R14's builder property test should assert both directions, the same note D74
left for `s_root`.

### R19 / M3

The redaction view inherits a **two-state** model, unchanged from line 121:
`FileReveal` (path + total size + spans) for files with a revealed unit,
`UnrevealedFilePlaceholder` (size only) for everything else. There is no
third state to design, and `UnrevealedFilePlaceholder` keeps its
never-gain-a-path rule.

## Permanence

Format-permanent both ways, which is why it could not stay open past Q14:
allowing it would have frozen a disclosure shape with no defined rendering,
and rejecting it freezes a code and forecloses filename-only disclosure for
v1. The code is append-only from the moment R7's row binds it (error-code
contract §3).
