# D85 — `unit-commit-mismatch` has no cause discriminator, and no salted commitment opening ever will

- **Status: RESOLVED — no code is minted. `pipeline-level-wrong-unit-salt`
  is ratified as a recorded non-row, and the rule is generalised to every
  salted-commitment opening in R's pipeline, not just this one**
- **Date: 2026-07-28**
- **Owning task: R33** (consumed by Q8's registry, R8's slice docs, the
  error-code contract §7, and Q14's freeze checklist)
- Surfaced 2026-07-28 at R8, which found a **third** collision of D81's
  exact shape one commitment layer up and discharged it on the module docs'
  authority alone. R33 exists because a discharge with no decision record
  is not a decision, and the code set freezes at Q14.

## The question

R8's task text names `wrong unit_salt → unit_commit mismatch` as a
mutation. It lands on `unit-commit-mismatch` — the code R8's own
`verify-non-covered-unit-commit-mismatch` row already claims for the
*altered manifest field* mutation — so `check_registry` would refuse the
pair. R8 recorded it as the non-row `pipeline-level-wrong-unit-salt` on
D81's argument: a salted commitment opening is one bit, because the
verifier recomputes `SHA-256(0x02 ‖ unit_salt ‖ bytes)` and compares, and
both the salt and the stored commit are inputs to the single comparison.

That argument is not obviously transferable, and R33 says so plainly. D81's
subject was an AEAD tag, where the indistinguishability is a property of
the primitive. Here it is not:

> Unlike the AEAD, both inputs are **structurally** attributable — the salt
> is bundle-side, the commit is manifest-side, and the manifest is
> **signed**. A verifier that ran the signature stage first could say which
> side was altered.

So the honest question is not "is a commitment opening one bit?" (it is)
but **"does the signature give the verifier attribution the comparison
itself cannot produce?"** If it does, the analogy to D81 fails and a code
must be minted before Q14. This record answers that question directly
rather than by analogy.

## What the code does today

- `crates/antseal-core/src/verify/unit_stages.rs:288` — stage 4's
  non-covered arm calls
  `verify_unit_commit(unit_salt, &bytes, unit_commit)` and maps
  `CryptoError::CommitmentMismatch` to
  `VerifyError::UnitCommitMismatch { unit_id }`
  (`unit_stages.rs:291-293`).
- `crates/antseal-core/src/verify/error.rs:346` — the variant carries
  **only** `unit_id`; `error.rs:684` returns `"unit-commit-mismatch"`.
- The three inputs to that one comparison have three different
  provenances: `unit_salt` is bundle-side (§7.12), `bytes` is the AEAD
  plaintext of a bundle-side ciphertext opened under a bundle-side `k_u`,
  and `unit_commit` is manifest-side and inside the signed body.
- R5's frozen stage order is `decode → structural → units → files → sigs
  → anchors`. Stage 4 (files/units content) therefore runs **before** the
  signature stage, and
  `the_unit_commit_row_beats_the_signature_stage`
  (`crates/antseal-core/src/test_util/tamper_rows_pipeline.rs`) pins that
  the content verdict wins.
- `the_wrong_unit_salt_route_reaches_the_same_code` (same file) pins the
  collision as a fact. Both tests pass at `aa169ac`.

## The asymmetry, taken seriously and defeated

Assume, for the sake of the argument, a verifier that runs signatures
first and then reports a cause on `unit-commit-mismatch`. Ask what it can
actually say.

**1. "Signature valid" does not narrow the fault to the salt — there are
two bundle-side candidates, not one.** If the signature verifies, the
manifest is the one that key signed, so `unit_commit` is not a third
party's edit. But the mismatch then has **two** possible bundle-side
causes: a substituted `unit_salt`, or substituted *plaintext*. The second
is not hypothetical. The verifier never holds `W`; the bundle supplies
`k_u` (spec line 114), and the nonce and AAD are public manifest data. So
anyone holding the bundle can re-encrypt **arbitrary bytes** under the same
`(k_u, nonce, AAD)` and produce a ciphertext that authenticates at stage 1.
That is not a defect — it is spec line 103 working as designed ("no
verdict-bearing check relies on a ciphertext decrypting to a unique
plaintext"), and it is exactly why `unit_commit` and not the AEAD is the
content binding. A code spelled `unit-commit-wrong-salt` would therefore
be **unsound**: it would assert an attribution the verifier cannot justify,
on inputs it cannot separate. The only sound cause here is "something
bundle-side", which is not a cause.

**2. "Signature invalid" does not narrow the fault to `unit_commit`
either.** The signature covers the whole manifest body. A flipped
`unit_commit`, a flipped `size`, a flipped `nonce` and a flipped `address`
all break it identically. So the signature-first split is
manifest-side-vs-bundle-side at best, and *neither half names a field*. It
is one bit about *provenance*, not a discriminator over the failing
comparison's inputs.

**3. Even that one bit answers the wrong question, because the sealer is an
adversary.** "The signature verifies" means "this manifest is the one this
key signed" — it does **not** mean "this manifest is honest". MVP-SPEC.md
line 121 makes the sealer adversarial; D28's whole rationale is that a
sealer may fill signed, anchored fields with anything. A sealer can sign a
manifest whose `unit_commit` is wrong, and then the signature verifies and
the content check fails — the same observable as a third party editing an
honest manifest. So the manifest-side/bundle-side split does not even
partition the *attacks*; it partitions "was this altered after signing",
which is a different question from the one a tamper verdict answers.

**4. Obtaining the split would cost the frozen stage order, and that is a
trade the project has already refused.** A cause on `unit-commit-mismatch`
requires the signature result at stage 4, i.e. signatures before files.
Two consequences, either one disqualifying:

  - Every *manifest-field* mutation that also breaks the signature — which
    is all of them — would begin reporting a signature code instead of its
    content code. That re-binds the expected code of existing rows
    (`verify-non-covered-unit-commit-mismatch`,
    `verify-concat-commit-mismatch-canon`/`-raw`,
    `verify-raw-commit-mismatch`, and every `wrong-length-*` row on a
    manifest field). Error-code contract §3 forbids editing an expected
    code to make the suite agree; this would edit a dozen at once.
  - It substitutes the less useful verdict. "The content of this bundle
    contradicts its manifest" is what a recipient needs; "the signature
    over this manifest is broken" is a strictly weaker statement about the
    same bytes. R8 pinned that preference in a named test precisely so it
    could not be traded away silently.

**5. There is no fifth candidate.** D81 had to evaluate ciphertext length,
chunk-address recompute and speculative re-decryption because the AEAD had
adjacent structural data. A salted commitment has none: the digest is
32 bytes with no internal structure, the salt is 16 bytes of uniform
random with nothing to check it against (its only opening is this
comparison), and the plaintext's only other binding — `fine_root` — is
mutually exclusive with `unit_commit` by the single-authoritative-
commitment rule (spec line 94; `UnitBinding` makes it type-enforced). A
non-covered unit has exactly one content binding, and it is the one that
just failed.

## The generalisation this record actually makes

R33's own note asks for the rule to be written down rather than inferred.
It is broader than `unit_commit`, and stating it once is what stops the
question being re-litigated per site after the freeze:

> **Every salted-commitment opening in R's pipeline is a single comparison
> over ≥ 3 inputs of mixed provenance, and none of them can carry a cause.**

| check | recomputation | inputs (B = bundle-side, M = manifest-side) | code |
|---|---|---|---|
| unit content | `SHA-256(0x02 ‖ unit_salt ‖ bytes)` | `unit_salt` B, `bytes` B, `unit_commit` M | `unit-commit-mismatch` |
| touched path | `SHA-256(0x05 ‖ path_salt ‖ path_utf8)` | `path_salt` B, `path` B, `path_commit` M | `path-commit-mismatch` |
| whole-file canonical | `SHA-256(0x04 ‖ file_salt ‖ concat)` | `file_salt` B, concat B, `canon_commit` M | `concat-commit-mismatch-canon` |
| whole-file raw | `SHA-256(0x03 ‖ file_salt ‖ bytes)` | `file_salt` B, bytes B, `raw_commit` M | `concat-commit-mismatch-raw`, `raw-commit-mismatch` |

Note that **`path_commit` is the sharper case, not `unit_commit`**: both
the salt *and* the committed value (`path`) are bundle-side, so it has two
bundle-side inputs by construction rather than by the re-encryption
argument of item 1 — and for it, even a signature-first verifier gets
*nothing at all*, since a valid signature excludes neither input.

Two coverage facts about that site, verified at `aa169ac` and recorded here
because D85 is what makes them acceptable rather than accidental:

- The single row is Q7's seed row
  (`crates/antseal-core/tests/tamper_matrix.rs:382`), base `two-unit-file`,
  mutation **"substitute the disclosed path, keeping the salt"** — the
  *path* route.
- The **salt route** (substitute `path_salt`, keep the path) is exercised
  by no row and by no named test at R's layer. Under D85 it correctly
  cannot be a row — it would claim `path-commit-mismatch`, which the seed
  row owns — but "cannot be a row" is not "should be unasserted". D81's
  own pattern is a recorded non-row **plus a named test**, and this site
  has neither.
- The same holds for `canon_commit`/`raw_commit`: their rows
  (`verify-concat-commit-mismatch-canon`/`-raw`,
  `verify-raw-commit-mismatch`) all mutate the **manifest** side, so the
  `file_salt` route is likewise unasserted at R's layer.

D85 does not leave those gaps open. Because the generalisation is what this
record adds, the record also owes the assertions that make it checkable —
see §5 of the verbatim artifacts below. Without them the general rule would
be prose about three sites and a test about one.

The rule that follows, and the one Q14 freezes:

> **A code in R's namespace names the check that failed, not the field that
> was wrong.** Wherever a check is a single comparison over several inputs
> — an AEAD tag (D81), a salted commitment opening (D85), a Merkle root —
> asking for a cause discriminator is asking the verifier for information
> the comparison does not produce. Adding such a code later is not a
> routine §3 append: it requires a decision that first says what the
> verifier holds, *outside* the comparison, that separates the inputs — and
> for the four sites above the answer is nothing, because the signature
> only ever separates manifest-side from bundle-side and each site has at
> least two bundle-side inputs.

## Options

**A — mint a cause discriminator** (e.g. `UnitCommitMismatch { unit_id,
cause }` → `unit-commit-mismatch-wrong-salt` / `-altered-commit`).
Requires the signature result at stage 4. Costs: one or two permanent
codes; an inverted stage order; the re-binding of every manifest-field
row's expected code (§3 violation); and the resulting attribution would
still be unsound, because "signature valid" leaves two bundle-side
candidates.

**B — no code; ratify the non-row and record the general rule.** Costs: one
spec-adjacent mutation keeps being asserted by a named test rather than a
row, and the `path_commit`/`concat_commit` merges stay implicit in their
rows rather than explicit in a code.

## Decision

**Option B.** No `VerifyError` variant is added, no code is minted, no
payload field is added to `VerifyError::UnitCommitMismatch`, and the frozen
stage order is unchanged. **R's universe stays at 85 distinct codes over 27
variants.** `pipeline-level-wrong-unit-salt` remains a recorded non-row and
this record becomes its authority.

**Nothing about the frozen check order changes.** No new check is added at
any position; the `unit_commit` comparison stays where it is —
`crates/antseal-core/src/verify/unit_stages.rs`, per-unit stage 4,
non-covered arm, inside the *units* stage of R5's `decode → structural →
units → files → sigs → anchors`. This decision is **not additive** to the
frozen order.

## Where a cause could legitimately live, if anyone ever wants it

Not in a code — in **rendering**. D27 already separates the normative
fail-fast typed first error (which the tamper matrix binds to) from
`VerifyFailures`, the rendering-only collection. `VerifyFailures`
(`crates/antseal-core/src/verify/error.rs:754`) exists as a type but has no
producer in the pipeline today; when one lands at M3, a report that shows
"content check failed **and** the manifest signature does not verify" gives
a human the manifest-side/bundle-side split *without* minting a code,
without reordering stages, and without asserting an attribution the
cryptography does not support. That is the correct home for the
information, and recording it here means a future contributor reaches for
the renderer instead of the code set.

## Consequences — what this freezes

- **The code set is unchanged**, so D85 is not a Q14 blocker on the code
  side. What Q14 freezes is the *argument*: after the freeze, adding a
  `unit-commit-*`, `path-commit-*`, `concat-commit-*` or `raw-commit-*`
  cause code requires a new decision that first defeats items 1–5 above.
- **The stage order gains a second reason to be what it is.** Until now
  "Files before Signatures" was justified as "a content failure should
  report as a content failure". D85 adds: the alternative would not even
  buy sound attribution, so the ordering costs nothing it was suspected of
  costing.
- **Three of the four commitment sites now have a recorded reason for
  merging their salt route and their committed-value route into one row.**
  Previously only `unit_commit` had one (in module docs), and it had no
  decision record.
- **No format impact**: no wire fields, no HKDF labels, no domain tags, no
  registry keys, no tier changes.

## Verbatim artifacts

### 1. `testdata/tamper/MATRIX.json` — `non_rows[]`, entry `pipeline-level-wrong-unit-salt`

Exactly **one** field changes: `record`. R33's Accept bullet requires it to
point at the ratifying record rather than at the registry. Replace the
existing `"record"` string with, verbatim:

```json
      "record": "docs/decisions/D85-unit-commit-cause.md",
```

Everything else in that entry — `id`, `milestone`, `owner`, `mutation`,
`collides_with`, `why`, `instead`, `warning` — is **unchanged**. In
particular do **not** edit `why`: it is correct as written, and D85
supplements rather than replaces it.

Append this sentence to that entry's existing `why` string, inside the same
JSON string (no new key):

```text
 Ratified by decision D85, which additionally establishes that the signature stage cannot supply a cause: `signature valid` still leaves two bundle-side candidates, because a bundle holder can re-encrypt arbitrary plaintext under the supplied `k_u`, and `signature invalid` does not name a manifest field.
```

**No other MATRIX.json change.** This is not a new row and not a new
non-row: `EXPECTED_NON_ROWS`, `EXPECTED_M0_NON_ROW_CASES`,
`EXPECTED_M0_PENDING`, `EXPECTED_M0_FAMILIES`, the family/case counts and
`m0_is_complete()` are all untouched. The M0 matrix stays complete with
zero pending.

### 2. `docs/format/registry-v1.md` + `registry-v1.json`

**No change.** D85 mints no code, moves no key, and changes no tier or
presence rule. Recorded explicitly so the implementer does not go looking.

### 3. `docs/testing/error-code-contract.md` §7 — append this dated entry

Place it **after** the `2026-07-28 (M0 wave 5, F15)` entry and **before**
the `**Formal freeze**` line:

```markdown
- **2026-07-28 (M0 wave 6, D85/R33)** — **no code minted**; R's universe
  stays at **85** distinct codes over **27** variants. R33 ratified the
  non-row `pipeline-level-wrong-unit-salt` and, in doing so, generalised
  the R8 note above from `unit_commit` to **every salted-commitment
  opening in R's pipeline** (`unit_commit`, `path_commit`, `canon_commit`,
  `raw_commit`).

  The generalisation needed more than D81's analogy, because the
  asymmetry R33 names is real: unlike an AEAD tag's inputs, a commitment
  opening's inputs are structurally attributable — the salt is
  bundle-side, the commit is manifest-side, and the manifest is signed.
  D85 shows the attribution still does not exist. `Signature valid`
  leaves **two** bundle-side candidates, not one, because the verifier
  never holds `W` and a bundle holder can re-encrypt arbitrary plaintext
  under the supplied `k_u` (spec line 103); `signature invalid` names no
  manifest field, since one signature covers the whole body; and neither
  half distinguishes a third-party edit from an adversarial sealer, which
  is the threat model (line 121). Obtaining even that coarse split would
  require signatures before files, re-binding the expected code of every
  manifest-field row at once — which §3 forbids.

  `path_commit` is the sharper case and is covered by the same rule:
  **both** its salt and its committed value (`path`) are bundle-side, so
  R7's single `verify-path-commit-mismatch` row legitimately claims both
  the wrong-salt and the substituted-path routes. That merge had no
  recorded justification before D85.

  §3 consequence, the same shape as D81's: **adding a
  `unit-commit-*`/`path-commit-*`/`concat-commit-*`/`raw-commit-*` cause
  code later is not a routine append.** It requires a decision that first
  says what the verifier holds outside the comparison that separates its
  inputs. Where a cause is genuinely wanted it belongs in **rendering**,
  not in the code set: D27's `VerifyFailures` lane can show "content
  check failed *and* the signature does not verify" without minting a
  code or reordering stages.
```

### 4. `crates/antseal-core/src/test_util/tamper_rows_pipeline.rs` — module docs

In the `## The commitment collapse (found at R8, same shape one layer up)`
subsection, the sentence ending "…plus
[`the_wrong_unit_salt_route_reaches_the_same_code`]." gains one sentence:

```text
//! Ratified as **decision D85**
//! (`docs/decisions/D85-unit-commit-cause.md`), which also answers the
//! objection this collapse invites and D81's did not: the manifest is
//! signed, so a signature-first verifier *looks* able to attribute the
//! fault to a side. It cannot — "signature valid" leaves two bundle-side
//! candidates (the salt and the plaintext, since a bundle holder can
//! re-encrypt under the supplied `k_u`), and "signature invalid" names no
//! field. D85 extends the rule to `path_commit`, `canon_commit` and
//! `raw_commit`.
```

The table row for `wrong `unit_salt`` changes its final cell from
``found at R8; see below`` to ``found at R8; decision **D85**``.

No expected code is touched and no existing assertion changes.

### 5. The three named tests that make the generalisation checkable

D81's shape was "one row, plus a named test for each demoted route". D85
extends the rule to four commitment sites but only two of them
(`unit_commit`'s two routes) currently have that pairing. Add the missing
salt-route tests, in
`crates/antseal-core/src/test_util/tamper_rows_pipeline.rs`'s `tests`
module, next to `the_wrong_unit_salt_route_reaches_the_same_code` and
modelled on it exactly (build a tweaked fixture, assert the code, document
why it is not a row):

| test name | mutation | asserted code |
|---|---|---|
| `d85_the_wrong_path_salt_route_reaches_the_same_code` | substitute a touched file's `path_salt` with another touched file's genuine 16-byte salt, keeping the path | `path-commit-mismatch` |
| `d85_the_wrong_file_salt_route_reaches_the_concat_code` | substitute a fully revealed file's `file_salt` with another fully revealed file's genuine 16-byte salt | `concat-commit-mismatch-canon` (text file) |
| `d85_the_wrong_file_salt_route_on_a_binary_file` | the same substitution on a fully revealed **binary** file | `concat-commit-mismatch-raw` |

Rules for all three, so they cannot drift into rows:

- **Use a genuine, correctly sized salt from elsewhere in the same work**,
  never random bytes and never a wrong length — a wrong length is caught
  earlier by R3's group 1 (`wrong-length-file-salt` /
  `wrong-length-path-salt`) and would assert nothing about the commitment.
- **None of them may be added to any registry slice.** Each would claim an
  outcome an existing row already owns, and `check_registry` would
  correctly refuse the pair. Each test's doc comment must say so and cite
  this record.
- If R6's `Tweak` has no knob for substituting `path_salt` or `file_salt`,
  add one alongside the existing `wrong_unit_salt` knob
  (`test_util/bundle_fixtures.rs:504`); do **not** hand-edit encoded bytes.

If any of the three turns out to reach a *different* code from the one
tabled, stop and report it: that would mean the site is not the collapse
D85 claims, and D85's generalisation would need amending before Q14 rather
than after.

## Committed artifacts to re-emit

**None.** No code is minted, no error string changes, no report field
changes, and no fixture bytes change — §5's tests build their fixtures at
runtime from R6's builder, exactly as the existing non-row tests do. So no
golden vector, no `vector-freeze` digest, and no committed `.sealproof`
fixture is affected. If any committed digest moves as a result of this
work, something outside D85's scope was changed and the change is wrong.

## What the implementer must report back

1. That `cargo test -p antseal-core --features test-util` passes with the
   MATRIX.json edit in place, **and specifically** that
   `tests/tamper_matrix.rs` still reports the M0 matrix complete with zero
   pending and `EXPECTED_NON_ROWS` unchanged at six entries in order.
2. That `scripts/vector-freeze.sh` reports **zero** changed digests. A
   changed digest means the edit escaped its scope.
3. The exact code/variant count printed by R's meta-test after the change,
   confirming **85 / 27**. If it is not 85/27 the tree was not at `aa169ac`
   or another wave-6 task minted a code — say which.
4. **The result of each of §5's three tests, individually.** They are the
   only part of this decision that can falsify it. If all three land on
   the tabled codes, the generalisation is checked at all four commitment
   sites and D85 is complete. If any lands elsewhere, say which and stop —
   that site is not the collapse this record claims, and the correct
   response is amending D85 before Q14, never editing the test's expected
   code (§3).
5. Confirmation that no `VerifyError` variant gained a field and no
   `code()` arm changed.

## Post-freeze correction — 2026-07-31

Item 3's "confirming **85 / 27**" was true of the lane that implemented
R33 and stale on the merged tree: G23 (D83) had minted
`fine-root-leaf-seed-tail-not-zero` hours earlier the same day, so the R
universe at the freeze is **86 distinct codes over 28 variants** (27 of
them exemplar-represented; `FineRootSeedTailNotCanonical` deliberately
delegates). `verify/error.rs`'s `DISTINCT_CODES = 86` is the source of
truth. The claim this record exists for — **D85 minted nothing** — is
unaffected; `aa169ac` simply was not the merged freeze tree. The same
stale count had propagated to TODO.md's register entry,
`docs/decisions/README.md` and `docs/testing/error-code-contract.md` §7,
all corrected 2026-07-31.
