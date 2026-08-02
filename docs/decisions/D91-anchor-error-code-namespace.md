# D91 — The A-domain error-code namespace

- **Status: RESOLVED — one prefix, `anchor-`. The `ots-`/`tsa-` split is
  rejected, and the register's framing of this as "one prefix vs per-surface
  prefixes" is overturned: measured against the code sets four resolved
  decisions have already minted, the split's honest prefix count is **four**,
  not two. D58 §10.4's own prediction — *"A5 will want a sibling `tsa-` on the
  same grounds"* — was **tested and failed the same day**: D60 §7.2/§7.3 is A5's
  decision, and it independently ruled `anchor-`. The F precedent does not
  license the split, because `manifest-`/`bundle-` encodes an
  information-flow guarantee that D78 enforces *in the type system*, whereas
  `ots-`/`tsa-` encodes `AnchorKind` — a discriminator that already exists as
  a typed field on `AnchorVerdict` **and** on frozen report v1's
  `AnchorResult`. Putting it in the code name too is exactly the move
  error-contract §2 already refuses for the decode layer. The digest-commitment
  check is **`anchor-ots-digest-mismatch`**; `ots-ops-do-not-commit-anchor-digest`
  is never minted. And a substantive finding beyond the naming: as the two
  documents stand, **D56 rule O2 is unreachable and reads a field D58's
  `OtsArtifact` does not have** — the two decisions disagree about where the
  check lives, not only about what it is called.**
- **Date: 2026-08-02** (M2 planning round)
- **Owning tasks: A38/Q80** (the §2 registration), **A11** (D58's 16 codes),
  **A5** (D60's eight), **Q76** (the four held `MATRIX.json` cells),
  **Q77** (the machine enforcement, §8)
- **Blocks: A5, A8, A9, A10, A11, A12, A21/Q18** — every A task that owes a
  code, which is all of them

---

## Context — what the mint claimed, and what survived

D91 has no register line in `TODO.md`; it was minted from the collision
itself, and the fullest statement of it in the tree is the beta lane's own
working copy of `docs/testing/error-code-contract.md`, whose §2 table cell for
A currently reads:

> `| **UNRESOLVED — D91** | A | anchor-artifact verification (A5–A18) and
> capture-path outcomes (A10). **Two decisions resolved on the same day
> disagree on the spelling** … **No A code may be minted until D91 rules** |`

Three things about the framing did not survive contact with the tree.

1. **The question is not two-way.** D58 §10.4 registers `ots-` for the `.ots`
   **codec** — all sixteen of its codes are `parse_ots` errors — and predicts
   one sibling. §3 below counts the already-ruled A codes that fall outside
   both: the online-header and block-absent checks (A18's state machine over
   `antseal-anchor` evidence), the chain rules (A9), and the capture-path
   nonce comparison (A10, in `antseal-anchor`, not in core at all). The split
   needs **four** prefixes for codes that exist today, not two.
2. **The prediction that carried the split is already falsified.** D58 §10.4
   says *"A5 will want a sibling `tsa-` on the same grounds"*. A5's decision
   is **D60**, resolved the same day, and §7.2 opens *"New error-code prefix
   **`anchor-`**, owner **A**"* — then mints eight codes under it (§7.3). The
   forecast was not merely disputed; it was run.
3. **"Q80 is blocked" is stale in one direction and true in the other.**
   Q80 **landed** on `m2w1-beta` at `061fa80` (2026-08-02 21:49:20 +0100),
   registering `anchor-` unilaterally with a recorded deviation; the lane then
   **backed it out in its working tree** to `**UNRESOLVED — D91**` rather than
   decide a permanent namespace by accident. That is the right call and this
   document exists to release it. What Q80 could not do in either state is
   rule on D58's sixteen codes or on the digest-code collision, and — measured
   from `git show --stat 061fa80`, **one file changed, 154 insertions, all
   prose** — it landed **no test**. §8 supplies the one it was missing.

The lean, such as it is, survives. Its stated reason does not: "one domain,
one prefix" is *not* this project's rule (F has three) and cannot be the
ground. §2 supplies the ground that is.

---

## 1. Why F's three prefixes do not license a fourth split

This is the argument the ruling has to defeat, and it deserves the strong
form: F owns `cbor-`, `manifest-` and `bundle-`, so the project has already
decided that one domain may hold several namespaces. If F may, why not A?

Because of **what F's split encodes**. `docs/testing/error-code-contract.md`
§2, on D78:

> Bundle schema validation never consults the embedded manifest, so a
> `bundle-` code always means "malformed on the bundle's own bytes" and a
> `manifest-` code always means "the embedded manifest is malformed". … it is
> enforced structurally: `BundleError` has no arm that can carry a
> `ManifestError`.

The prefix is a claim about **information flow**, and the type system makes
the claim true. Reading `bundle-` on a verdict tells a third party something
it could not otherwise know: the manifest was not consulted. That is worth a
permanent namespace.

Now apply the same test to `ots-`/`tsa-`. Does `ots-` guarantee the TSA
artifact was not consulted?

**Yes — and at artifact level the guarantee is vacuous**, because no
per-artifact anchor check consults the other kind under *any* naming. D53's
rules `T0–T3`/`C1–C6` take one TSA artifact plus `anchor_digest` plus the
pinned root store; D56's `O0–O9` take one `.ots` artifact plus `anchor_digest`
plus the D79 upgrade group plus online evidence. Every rule in both documents
is already scoped to one artifact by its own signature, so a prefix excludes
nothing that was reachable. D78's separation is informative precisely because
the *natural* implementation goes the other way — the two artifacts are
nested, and F9 decodes both — so "did not consult" is a real restraint.
Nothing about `.ots` op execution tempts anyone to open a TSA token.

**And the one genuinely cross-kind check in the A domain cuts the same way.**
D53 §10's **A40** carries `docs/format/registry-v1.md` §8's obligation —
*"anchor independence must be evaluated from verified identities, never from
array length"* — which quantifies over the whole anchor set of both kinds, as
does A20's minimum-anchor policy. So the A domain has exactly one check a
kind-prefix could say something about, and what it would have to say is
"consults both". A split cannot classify its code at all; a single family
carries it without comment. The prefix that would be informative here is the
one the split does not have.

**What `ots-`/`tsa-` actually encodes is `AnchorKind`** — and `AnchorKind` is
already a typed field, in two places, one of them frozen:

- `crates/antseal-core/src/anchor/model.rs` — `AnchorVerdict { kind:
  AnchorKind, state, verified_time_unix, source, fetch_date, diagnostic }`.
  The kind sits in the **same struct as the diagnostic code**.
- `crates/antseal-core/src/verify/report.rs` — `AnchorResult`'s `kind` field,
  frozen at report v1 (D29/R32; Q14).

So the split would spend a permanent string on a discriminator the datum
already carries as data, immediately adjacent to the code. That is the exact
move §2 already refuses, under the heading *"a code names a rejection class,
never a layer"*:

> minting per-layer codes would fork one taxonomy into four and make "which
> layer" a permanent part of every code name, which §3 then freezes forever.

and its resolution — `ManifestError::layer()` / `SealProofError::layer()` as
*"pipeline context, not a rejection class"*, the finer instrument that pins
the `(code, layer)` pair without freezing fifteen names. `AnchorKind` is the
anchor domain's `layer()`, and it is already better than that: `layer()` had
to be *added* at F26/D86 to make the pair informative, whereas `kind` shipped
with A2.

The same rule is recorded twice more, in the form D91 is applying:

- **D85/R33**: *"the codes … name the check that failed, not the field that
  was wrong."*
- **C28**: *"the duplicated algorithm is payload, not a code discriminant …
  The asymmetry with the neighbouring per-algorithm signature codes is
  principled: there the **check itself** is per-algorithm."*

C28's clause is the one honest opening for the split, so take it seriously:
*is* the check per-kind? Partly — `.ots` op execution and X.509 path
validation are genuinely different checks. But §3 shows the boundary does not
fall where the split puts it, and §2 shows the taxonomy it would produce is
not two-valued.

**Conclusion.** `manifest-`/`bundle-` encodes a structural fact enforced by a
type. `ots-`/`tsa-` encodes a topic that is already a field. The F precedent
argues *against* the split, not for it, because it shows what a second prefix
has to earn.

---

## 2. The evidence from four independent applications of the rule

Not an appeal to majority — an observation about what the rule produces when
four planners with no contact apply it to four different A surfaces.

| decision | surface | prefix chosen | codes |
| --- | --- | --- | --- |
| **D53 §7** | A9 — X.509 path validation | `anchor-` | 3 |
| **D56 §7** | A11/A12/A18 — OTS state machine | `anchor-` | 4 |
| **D59 §5** | A10 — TSA capture path | `anchor-` (*"`anchor-` is hereby the A domain's prefix"*) | 1 |
| **D60 §7.2/§7.3** | **A5** — strict DER/CMS/X.509 | `anchor-` (*"New error-code prefix **`anchor-`**, owner **A**"*) | 8 |
| **D58 §10.4** | A11 — the `.ots` codec | `ots-`, *"A5 will want a sibling `tsa-`"* | 16 |

Measured: **16 `anchor-*` codes across four resolved decisions, against 16
`ots-*` codes in one.** All five documents are `RESOLVED`, all dated
2026-08-02.

The D60 row is the decisive one and it is not a tie-break. D58 named a
specific future task — A5 — and predicted the prefix it would want. That task
got its own decision on the same day, reached the code-naming question from
the DER/CMS end with no sight of D53, and wrote `anchor-`. D58 §10.4's
supporting argument is therefore not merely outvoted; it is the one claim in
this collision that was independently tested.

*(D53's set is measured from `docs/decisions/D53-…md:468-472`, D56's from
`D56-…md:449-454`, D59's from `D59-…md:427-431`, D60's from `D60-…md:976-983`,
D58's from `D58-…md:970-985`; the union, `sort -u`, is 16 and 16.)*

---

## 3. Where the split's homeless codes would go — priced on codes that exist

D58 §10.4 scopes `ots-` to the `.ots` codec: every one of its sixteen codes
is raised by `parse_ots` (§10.3's two check tables). Take that scope at its
word and sort the already-ruled A codes into it.

| code (as resolved) | fires in | `ots-` (codec)? | `tsa-` (A5 strict DER/CMS)? |
| --- | --- | --- | --- |
| `anchor-ots-online-header-mismatch` (D56 O6) | A18 state machine, over `antseal-anchor` evidence | no | no |
| `anchor-ots-online-block-absent` (D56 O7) | same | no | no |
| `anchor-ots-header-uncommitted` (D56 O8) | same, over the D79 upgrade group | no | no |
| `anchor-cert-not-valid-at-gentime` (D53 C3) | A9 chain validation | no | no |
| `anchor-chain-constraint-violation` (D53 C4) | A9 | no | no |
| `anchor-chain-signature-invalid` (D53 C5) | A9 | no | no |
| `anchor-tsa-nonce-mismatch` (D59, A10) | **`antseal-anchor`**, capture path — not in core | no | no |

Seven of the sixteen `anchor-*` codes belong to neither of the split's two
namespaces. The honest prefix count for today's set is **four** — codec,
DER/CMS parse, chain, capture — and a fifth is already visible in **A40**'s
cross-kind independence obligation (§1), which no kind-prefix can classify
because its whole content is that it reads both.

The tree already shows the pressure. Q80's landed row had to **widen D53
§7's surface column** to reach D59's code — *"; and capture-path outcomes in
`antseal-anchor` (A10)"* — and recorded the deviation. Widening a surface
column is free. Under a per-surface prefix scheme it is not available: the
equivalent move is minting a prefix, and §3 makes that permanent.

**And the boundary is not clean even inside the split's own two members.**
D60 §7.3's eight codes are owned by two tasks and surface at three: `anchor-der-*`
are A5's parse; `anchor-chain-cert-count`/`anchor-chain-cert-size` are A5-owned
but bound A9's chain; `anchor-digest-alg-unsupported` and
`anchor-signature-alg-unsupported` are **A8's**, and the second of the two
also fires on a **certificate**'s `signatureAlgorithm` — root-store territory,
A6's. A rule that assigns prefixes by surface has to adjudicate each of those,
per code, forever. That is precisely the *"we'll work it out per code"* the
brief names, and it is what one prefix removes.

---

## 4. The sweep count, measured

Three sweeps exist and F37 exists to merge them, so the cost is real. But the
tree records **why** there are three, and it is not "three prefixes".

**Measured, at HEAD (`06d5b4c`):**

- `crates/antseal-core/src/test_util/tamper_coverage.rs:93` —
  `pub const DOMAINS: &[&CoverageDomain] = &[&BUNDLE, &MANIFEST];`, with the
  doc comment *"**F24 appends its `cbor-` domain here**; nothing else needs to
  change for it."* The mechanism is **data**: a prefix costs one
  `CoverageDomain` const plus one `DOMAINS` entry, carrying two hand-kept
  accounting lists (`claimed_in_integration_target`, `owed`), each pinned in
  both directions.
- `crates/antseal-core/src/test_util/tamper_rows_cbor.rs:70-76` — F24 **did
  not** append. It built a sibling, and recorded the reason: *"F23 was authored
  in a concurrent lane, so this is its **sibling** rather than an extension."*
- `crates/antseal-core/src/test_util/tamper_rows_structural.rs:875-882` —
  R7's `owned_prefixes` is a **six-element hardcoded literal** with
  **default-deny** semantics: any code not matching a listed prefix is treated
  as R's own and must have a row.
- `crates/antseal-core/src/error_universe.rs:192-199` — `census`'s `PREFIXES`
  is the same six-element literal.

So the arithmetic is: **1 vs 4** in `DOMAINS`, **2 vs 8** hand-kept accounting
lists, **1 vs 4** in R7's default-deny skip list (live the moment any
`VerifyError::Anchor` wrapper arm appears, which is the obvious M2/M3 shape
given §2's wrapper rule), **1 vs 4** in `census`.

That is the small argument. The large one is the F24 record: **the cause of
three sweeps was three tasks in parallel lanes, not three prefixes** — and
the split maximises exposure to exactly that failure, because its two
prefixes are owned by **A11** (`ots-`) and **A5** (`tsa-`), different tasks
that this project runs in different lanes on a 2-core box, and D58 and D60
already demonstrated the two lanes cannot see each other. One family
registered once by A38, ahead of both, is the structural fix; two families
minted by two concurrent lanes is the F23/F24 shape reproduced with a
permanent artifact instead of a mergeable test.

---

## 5. The one argument recorded in the split's favour, and why it fails

Q80 handed D91 a genuine input rather than a rhetorical one, and it must be
answered rather than skipped. `docs/testing/error-code-contract.md` (beta
working tree, the S ruling):

> **U2's `ErrorClass::AnchorGateAbort` already renders as the string
> `anchor-gate-abort`** (exit 22 …). It is *not* a collision — different
> field, different document, different consumer — but a same-string *stem*
> shared between the two is indistinguishable from one to a reader.
> … **This is evidence for D91, not a ruling.** If A's prefix is `anchor-`,
> the A namespace and U2's exit-code namespace share a stem … If it is
> `ots-`/`tsa-`, they do not.

The premise is right and the conclusion is wrong, because **the split does not
avoid the problem — it makes it larger.** Measured at HEAD:

```
$ grep -rn '"ots-pending"\|"tsa-0.der"\|"tsa-0"' --include="*.rs" crates/ | wc -l
9
$ grep -rln '"ots-pending"\|"tsa-0.der"\|"tsa-0"' --include="*.rs" crates/
crates/antseal-cli/src/vault/store.rs
crates/antseal-cli/src/vault/cipher.rs
crates/antseal-cli/tests/work_store.rs
crates/antseal-cli/tests/vault_export.rs

$ grep -rn '"anchor-gate-abort"' --include="*.rs" crates/ | wc -l
3
```

`ots-pending` and `tsa-0.der` are the vault's **anchor slot names** (U9's
store, live in `antseal-cli` today). Under `ots-`/`tsa-`, the A code namespace
would share a stem with the vault-slot namespace at *every single code*, and
`ots-pending` reads far more like an error code than `anchor-gate-abort` does
— it is lowercase kebab-case, it names an anchor condition, and "pending" is
one of the seven frozen `AnchorState` spellings. **9 occurrences against 3,
and the confusable string is a better error-code impostor.**

Under `anchor-`, exactly one stem is shared, it is already reserved by Q80,
and §8's cross-namespace check makes the reservation machine-enforced. Under
the split, the shared stems are the prefixes themselves and no reservation is
possible, because you cannot reserve a spelling you are simultaneously
minting under.

---

## 6. The ruling

### 6.1 The prefix

**One prefix, `anchor-`, owner A.** `ots-` and `tsa-` are not registered, in
this wave or any later one; D58 §10.4's `ots-` and its predicted `tsa-` are
closed as not-taken.

The verbatim `docs/testing/error-code-contract.md` §2 table row, ready to
paste — this is **Q80's landed text at `061fa80`**, ratified rather than
rewritten, because its extension of D53 §7 is the correct one (§3: D53's
"A5–A18" wording does not reach D59's code):

```markdown
| `anchor-` | A | anchor-artifact verification: strict DER/CMS, X.509 path validation, `.ots` op execution, embedded-header and online-header checks (A5–A18); and capture-path outcomes in `antseal-anchor` (A10) |
```

It **replaces**, in the beta working tree, the held cell:

```markdown
| **UNRESOLVED — D91** | A | anchor-artifact verification (A5–A18) and capture-path outcomes (A10). **Two decisions resolved on the same day disagree on the spelling** — see below. **No A code may be minted until D91 rules**, and §3 makes whichever is written permanent from the first code that binds to it. |
```

Row order is unchanged: between `content-` (G) and *(unprefixed)* (R).
**Q80's second row — `| *(none — S mints no codes)* | S | ruled below, not
omitted |` — is not touched by D91** and stands as landed.

The §2 prose block *"The A domain's prefix is UNRESOLVED and blocking —
D91 (raised 2026-08-02)"* is replaced by Q80's original
*"### The `anchor-` family (A), registered 2026-08-02 at Q80"* section, with
its two spelling-independent records (the owner-backed nonce code, the
two-directional temporal code) unchanged — both were written to survive this
ruling and do — plus a sentence recording D91 as the ratification and §7's
sub-namespace convention.

### 6.2 The canonical code for the digest-commitment check

**`anchor-ots-digest-mismatch`.** `ots-ops-do-not-commit-anchor-digest` is
**never minted** and never enters `testdata/error-codes/v1/CODES.txt`.

Three grounds, in the order that decides it.

1. **It is the only one of the two with a binding.** §3 makes a code permanent
   *"from the moment a tamper row, a golden vector, or a released verifier
   binds to one"*. D53 §8 binds M2 tamper row 1 to it; the row id in
   `testdata/tamper/MATRIX.json` **is** `anchor-ots-digest-mismatch` (beta,
   Q76 at `1eb87ae`), and row ids are permanent handles. Nothing anywhere
   binds the D58 spelling — §6.3 lists every occurrence, and all three are
   inside D58 itself.
2. **§6.1 disqualifies the D58 spelling regardless**, since it is unprefixed
   relative to the registered family.
3. **It is the more accurate name**, on §2's own rule that a code names the
   check. D58 §10.3 concedes this in the act of arguing for its own name:
   *"every attestation in the file descends from `start_digest`, so the
   equality on that one header field **is** the commitment check"*. The check
   is a 32-byte comparison of a header field; "the ops do not commit" is the
   consequence, not the comparison. `anchor-ots-digest-mismatch` names the
   comparison and matches D56 §7's own gloss, *"The `.ots` stamped digest is
   not this seal's `anchor_digest`."*

### 6.3 Every place the losing name appears today

Grepped across all four worktrees (`code0`, `code0-m2-alpha`, `code0-m2-beta`,
`code0-m2-gamma`), excluding `.git` and `target`. **Six occurrences, in three
files, and not one of them is code.**

The three inside D58 are **not edited in place.** The register's own
convention (`docs/decisions/README.md`: *"A decision is changed by editing its
file with a new dated entry, never by silently rewriting history"*) means the
losing spelling stays where it was written and §9.4's dated amendment says
what it now means. The other three are working artifacts, not records, and are
rewritten.

| file | line | what it is | orchestrator action |
| --- | --- | --- | --- |
| `/home/deb/Documents/code0/docs/decisions/D58-opentimestamps-viability.md` | 909 | §10.3 check-order table, step 5 | governed by §9.4's amendment |
| `/home/deb/Documents/code0/docs/decisions/D58-opentimestamps-viability.md` | 976 | §10.4 code list, line 7 of 16 | governed by §9.4's amendment |
| `/home/deb/Documents/code0/docs/decisions/D58-opentimestamps-viability.md` | 1027 | §11 test row `ots_stamping_a_different_digest_is_rejected` | governed by §9.4's amendment |
| `/home/deb/Documents/code0-m2-beta/testdata/tamper/MATRIX.json` | 466 | the `why` of the held cell `anchor-token-for-a-different-digest/ots-digest-mismatch` | rewrite per §9.1; set `"expected": "anchor-ots-digest-mismatch"` |
| `/home/deb/Documents/code0-m2-beta/crates/antseal-core/tests/tamper_completeness/mod.rs` | 187 | `EXPECTED_M2_UNMINTED` entry 1's reason string | **delete the entry** (§9.2) |
| `/home/deb/Documents/code0-m2-beta/docs/testing/error-code-contract.md` | 156 | the D91 hold paragraph | superseded by §6.1's replacement |

`code0-m2-alpha` and `code0-m2-gamma`: **zero occurrences.** The same sweep for
the other fifteen bare `ots-*` names found them **only** in
`docs/decisions/D58-opentimestamps-viability.md` (lines 786, 789–790, 905–933,
945, 970–985, 1027–1032, 1091, 1177). **No Rust source, no committed fixture,
no JSON, in any worktree, carries any `ots-*` or `tsa-*` error code.** The
ruling costs zero renames of anything that exists — which is the whole reason
D91 had to run before A11 rather than after.

### 6.4 The finding under the naming collision — D56 O2 is unreachable as written

The two decisions disagree about **where** the check lives, and nobody has
recorded it. D58 §10.2 makes `anchor_digest` a **required parameter**:

```rust
pub fn parse_ots(bytes: &[u8], anchor_digest: &[u8; 32]) -> Result<OtsArtifact, OtsError>;

pub struct OtsArtifact {
    pub attestations: Vec<OtsAttestation>,
}
```

so the comparison happens **inside the parser**, at §10.3 step 5, and returns
an `OtsError`. But D56's rules read:

```text
O1.  A11's anchor-stage limits exceeded, or the `.ots`
     codec rejects the bytes                           ->  AnchorState::Invalid
                                                           code: A11's limit / codec code (F1-F3)
O2.  artifact.stamped_digest != *anchor_digest         ->  AnchorState::Invalid
                                                           code "anchor-ots-digest-mismatch"
```

with D56 §5's overlap table giving *"O1 and any of O2–O9 → **O1**"*. Two
consequences, neither recorded in either document:

1. **`OtsArtifact` has no `stamped_digest` field** — the struct above is its
   whole definition. O2's predicate is unspellable against D58's type.
2. Even given the field, **O2 could never fire**: under D58's signature the
   parser has already returned `Err` for every input O2 would reject, so O1
   claims it first. O2 is dead as a rule.

**Ruling: one check, in one place — D58 §10.3 step 5, inside `parse_ots`.**
D58's placement argument is sound and is kept verbatim (*"a wrong-digest
`.ots` costs one 32-byte comparison and can never be used as a work
amplifier"*), and it is the reason not to take the obvious repair of adding
`stamped_digest` to `OtsArtifact` — that would require parsing the whole file
before checking the digest, reinstating the amplifier.

**D56 rule O2 is retained, and is re-read as naming an outcome rather than
adding a check**: it is the name of the `OtsError` variant O1 delegates for
this one input. No rule is renumbered, no ordering moves, and the observable
outcome is unchanged in both documents — `AnchorState::Invalid` with code
`anchor-ots-digest-mismatch` — so `MATRIX.json` row 1 is satisfied under
either reading and the ruling costs no test. What it prevents is an
implementer "fixing" O2 by giving `OtsArtifact` the field.

*(This also removes the only reason D56 §9's test
`a_wrong_digest_ots_is_invalid_regardless_of_its_attestations` — *"the worst
reachable defect in the file"* — could have been written against a
post-parse check. It is now a test that the parser's step 5 precedes the
walk, which is exactly D58 §11's `ots_stamping_a_different_digest_is_rejected`.
The two tests are the same test in two documents; §9.4 records the merge.)*

---

## 7. The complete A-domain code set after this ruling

Thirty-two codes, from five resolved decisions. All pairwise distinct, all
lowercase kebab-case, all under `anchor-`, none colliding with the 194 in
`testdata/error-codes/v1/CODES.txt` — measured:

```
$ for p in anchor ots tsa; do printf "%-8s %s\n" "$p-" \
    "$(grep -c "^$p-" testdata/error-codes/v1/CODES.txt)"; done
anchor-  0
ots-     0
tsa-     0
```

### 7.1 The renaming map for D58's sixteen — complete, for A11

**Fifteen mechanical renames and one merge.** Nothing else about D58 changes:
every limit value, every derivation, every witness, the check order, and the
iterative-parser requirement are untouched.

| D58 §10.4 name | A11 implements | note |
| --- | --- | --- |
| `ots-bad-magic` | `anchor-ots-bad-magic` | |
| `ots-unsupported-version` | `anchor-ots-unsupported-version` | |
| `ots-unsupported-digest-type` | `anchor-ots-unsupported-digest-type` | |
| `ots-truncated` | `anchor-ots-truncated` | |
| `ots-trailing-bytes` | `anchor-ots-trailing-bytes` | |
| `ots-varint-too-long` | `anchor-ots-varint-too-long` | |
| `ots-ops-do-not-commit-anchor-digest` | **`anchor-ots-digest-mismatch`** | **the merge — §6.2. Not a mechanical rename: the D56 name wins outright, and D58's spelling is never minted.** |
| `ots-too-many-ops` | `anchor-ots-too-many-ops` | |
| `ots-too-deep` | `anchor-ots-too-deep` | |
| `ots-branch-too-wide` | `anchor-ots-branch-too-wide` | |
| `ots-too-many-attestations` | `anchor-ots-too-many-attestations` | |
| `ots-operand-too-long` | `anchor-ots-operand-too-long` | |
| `ots-value-too-long` | `anchor-ots-value-too-long` | |
| `ots-attestation-payload-too-long` | `anchor-ots-attestation-payload-too-long` | |
| `ots-attestation-payload-not-consumed` | `anchor-ots-attestation-payload-not-consumed` | longest in the tree at **43** bytes; measured longest committed today is **41** (`manifest-wrong-length-signature-ml-dsa-65`). +2, recorded rather than treated as an objection. |
| `ots-unknown-op` | `anchor-ots-unknown-op` | |

**Net: A11 mints fifteen new codes** (not sixteen), because the sixteenth is
D56's and A11 raises it. D58 §10.3's two check tables take the renames
literally in both columns.

### 7.2 The full set, and three near-misses kept separable

| owner | codes |
| --- | --- |
| A5 (D60) | `anchor-der-not-strict`, `anchor-der-malformed`, `anchor-der-nesting-depth`, `anchor-chain-cert-count`, `anchor-chain-cert-size`, `anchor-signed-attr-count` |
| A8 (D60, D53 §8) | `anchor-digest-alg-unsupported`, `anchor-signature-alg-unsupported`, `anchor-tsa-imprint-mismatch` |
| A9 (D53 §7) | `anchor-cert-not-valid-at-gentime`, `anchor-chain-constraint-violation`, `anchor-chain-signature-invalid` |
| A10 (D59 §5) | `anchor-tsa-nonce-mismatch` — **owner-backed, not row-backed** (Q80's record stands verbatim) |
| A11 (D58 §10.4, renamed) | the fifteen `anchor-ots-*` of §7.1 |
| A11/A12/A18 (D56 §7) | `anchor-ots-digest-mismatch`, `anchor-ots-online-header-mismatch`, `anchor-ots-online-block-absent`, `anchor-ots-header-uncommitted` |

Three near-misses, recorded in the house tradition of `path-commit-mismatch`
vs `crypto-path-commit-mismatch` — **three codes in one family contain
"digest" and name three different objects**, and merging any pair would be a
re-scope §3 forbids:

1. `anchor-ots-digest-mismatch` — the `.ots` header's **start digest value**
   is not this seal's `anchor_digest` (D56 O2 / D58 step 5).
2. `anchor-ots-unsupported-digest-type` — the `.ots` header's **digest-type
   tag** is not `0x08` (D58 step 3). Same header, one field earlier, a type
   rather than a value.
3. `anchor-digest-alg-unsupported` — a **CMS digest OID** outside D60 §3.3's
   table. Different artifact kind, different encoding, different check.

A fourth, weaker: `anchor-ots-truncated` (a read past the end of input) vs
`anchor-ots-trailing-bytes` (input not fully consumed) are the two directions
of one boundary and stay two codes, because D58 §10.3 fires them at different
steps (`j` inside the walk vs step 7 after it) and both are reachable.

### 7.3 The sub-namespace convention — advisory, not enforced

The already-ruled set mixes kind-qualified names (`anchor-ots-*`,
`anchor-tsa-*`) with unqualified ones (`anchor-chain-*`, `anchor-der-*`), so
the convention is written down here or it becomes the next collision:

> **The segment after `anchor-` names the check. A kind segment (`ots`/`tsa`)
> appears only where the same check name would otherwise be ambiguous across
> the two artifact kinds.**

That is why `anchor-ots-digest-mismatch` and `anchor-tsa-imprint-mismatch`
both carry one — both are "this artifact stamps a different digest", and both
exist — while `anchor-chain-signature-invalid` does not, there being no OTS
chain. It reproduces the existing set exactly.

**This is a review guideline and is deliberately not machine-enforced.** §3
makes codes permanent, so a *naming-style* test would turn a judgement call
into a red build and its only available fix would be the rename §3 forbids.
The one machine-enforced rule is the prefix (§8).

---

## 8. The test that makes this machine-enforced — and what makes it fail

The ruling is currently a table row in a Markdown file. Nothing in the tree
can see a violation: `census()` sorts any unrecognised code into its
`"(unprefixed)"` bucket and **prints** it, so `ots-bad-magic` would be counted
as one of R's, added to the snapshot by the additions-only path, and pass
every existing check. §2's headline rule — *"A domain never mints a code under
another domain's prefix"* — has **no enforcement anywhere in the tree today**,
which is why D58 could mint sixteen codes under a namespace nobody had
registered and nothing went red.

Task **Q77** (§10). Location: `crates/antseal-core/src/error_universe.rs`,
beside the existing snapshot gate. Native-only, for the same reason the rest
of the module is (P14: `wasm32-unknown-unknown` has no filesystem).

### 8.1 The mechanism

One committed table pairing each enumerator in `by_enumerator()` with the
prefix registered to its domain in §2:

```rust
/// The §2 prefix table, transcribed. One row per enumerator in
/// `by_enumerator()`; the `verify::error` row is deliberately permissive
/// because §2's wrapper rule makes R's exemplar list a superset of every
/// other family's.
const ENUMERATOR_PREFIXES: &[(&str, Allowed)] = &[
    ("codec::decode::all_code_exemplars",              Allowed::Only("cbor-")),
    ("manifest::error::all_code_exemplars",            Allowed::Only("manifest-")),
    ("bundle::error::all_code_exemplars",              Allowed::Only("bundle-")),
    ("crypto::error::all_code_exemplars",              Allowed::Only("crypto-")),
    ("content::error::all_code_exemplars",             Allowed::Only("content-")),
    ("canon::canon_code_exemplars",                    Allowed::Only("content-")),
    ("content::fine_tree::error::all_code_exemplars",  Allowed::Only("fine-root-")),
    ("anchor::error::all_code_exemplars",              Allowed::Only("anchor-")),   // A38
    ("verify::error::all_error_exemplars",             Allowed::AnyRegisteredOrUnprefixed),
];

/// §2's table, first column, backticked cells only.
const REGISTERED_PREFIXES: &[&str] = &[
    "cbor-", "manifest-", "bundle-", "crypto-", "content-", "fine-root-", "anchor-",
];
```

`REGISTERED_PREFIXES` also replaces `census`'s private `PREFIXES`
(`error_universe.rs:192-199`), so the census and the gate cannot drift.

Two pure functions and three tests:

| test | claim | **what makes it fail** |
| --- | --- | --- |
| `every_code_carries_the_prefix_registered_to_its_domain` | §2's headline rule, for the first time | **A11 minting `ots-bad-magic`, or A5 minting `tsa-nonce-mismatch`** — red, naming the `(enumerator, code)` pair. Also red if C mints `bundle-…`, or if anyone introduces a *new* prefix without a §2 row, since it is not in `REGISTERED_PREFIXES`. This is the exact mutation D91 forbids and the reason the task exists. |
| `the_prefix_check_goes_red_on_a_foreign_prefix` | test-of-the-test | The comparator is a pure function over a synthetic roster; passing `[("anchor::error::all_code_exemplars", {"ots-bad-magic"})]` must return that pair. Fails if the comparator is weakened to a warning, to a `starts_with(anything)`, or to skipping unknown enumerators. Planted-fault shape, matching `the_comparison_catches_a_rename`. |
| `section_2_prefix_table_matches_registered_prefixes` | the const **is** the doc | Parses the first column of §2's table from `docs/testing/error-code-contract.md`, backticked cells only (so the `*(unprefixed)*` and `*(none — S mints no codes)*` rows are skipped by construction), and asserts set equality plus `len() == REGISTERED_PREFIXES.len()` and `>= 7`. Red when a prefix is added to the table and not the const, or the reverse. Precedent: `format_registry_freeze.rs`, and D58 §11's `ots_limits_match_the_f4_registry` is the same shape. The length assertion is what stops it passing vacuously on a parse that finds nothing. |

### 8.2 The two anti-vacuity obligations, and they are the load-bearing half

The brief's own warning applies hardest here, because the natural
implementation of this check passes vacuously in the one situation that
matters.

1. **An enumerator with no `ENUMERATOR_PREFIXES` row must be a failure, not a
   skip.** If A38 adds `anchor::error::all_code_exemplars` to
   `by_enumerator()` but forgets the table row, a `filter_map` lookup would
   silently exempt the entire A family — the check would go green over
   *exactly* the domain D91 exists to constrain. The lookup is therefore
   total: an unknown enumerator is reported by name.
2. **`the_universe_is_exactly_the_eight_enumerators` must move 8 → 9 when
   A38 lands**, and that is a second, independent guard rather than
   bookkeeping. Its existing failure message already states the stake: *"the
   enumerator roster changed size; a ninth domain must be added to
   `by_enumerator` or its codes freeze under nothing."* An `AnchorError` with
   `code()` but no enumerator entry is a family outside Q52's snapshot **and**
   outside this check, which is the pre-Q52 state restored for one domain.

### 8.3 Second leg — the cross-namespace disjointness Q80 measured but could not assert

Q80 recorded U2's `ErrorClass::AnchorGateAbort` → `"anchor-gate-abort"` as a
reserved spelling and measured the disjointness by hand (*"28 class names,
zero intersection"*), noting it *"is not yet machine-checked — Q77"*. §5 makes
that reservation load-bearing under this ruling, so it lands in the same task
and the same mechanism rather than as a fourth sweep — the F23/F24 lesson
applied at the moment it would otherwise repeat:

| test | **what makes it fail** |
| --- | --- |
| `error_codes_and_exit_class_names_are_disjoint` (`crates/antseal-cli/tests/`, which can see both) | Any A code minted as `anchor-gate-abort`, or any new `ErrorClass` name that collides with a code. Cannot pass vacuously: asserts both sets are non-empty and that the class set has the pinned size Q80 measured. It lives in the CLI test target because `antseal-core` cannot see `CliError` — stated so nobody moves it into `error_universe.rs` and weakens it to a hardcoded list. |

---

## 9. The edits this decision authorises

### 9.1 `testdata/tamper/MATRIX.json` — three held cells filled (Q76)

The three `"expected": null` cells held for D91 are filled; **no row id
changes**, since a prefix ruling renames no row. Verbatim:

```json
            "row_id": "anchor-ots-digest-mismatch",
            "outcome_kind": "error",
            "expected": "anchor-ots-digest-mismatch",
            "why": "D56 rule O2, named by D91. The check is ONE check in ONE place — D58 section 10.3 step 5, inside `parse_ots`, before the walk, so a wrong-digest `.ots` costs one 32-byte comparison and is never a work amplifier. D91 section 6.2 rules that `anchor-ots-digest-mismatch` is its code and D58's `ots-ops-do-not-commit-anchor-digest` is never minted. Split from the TSA half at D53 section 8: line 168's clause is compound, and the two checks live in different stages on different artifact kinds (`.ots` stamped digest at A11; `TSTInfo.messageImprint` at A8), so they cannot share an outcome key."
```

```json
            "row_id": "anchor-tsa-imprint-mismatch",
            "outcome_kind": "error",
            "expected": "anchor-tsa-imprint-mismatch",
            "why": "D53 section 8 row 2; the A-domain prefix is `anchor-` per D91. A8 owns the check and the code; D53 fixes that it fires at stage T2, before any chain rule, so a token for a different digest is never classified by its chain."
```

```json
            "row_id": "anchor-expired-at-gentime",
            "outcome_kind": "error",
            "expected": "anchor-cert-not-valid-at-gentime",
            "why": "D53 rule C3, spelling ruled by D91. One code covers both temporal directions (D85: a cause belongs in rendering, not the code set); this row exercises the expired direction and the not-yet-valid direction is D53's named test `a_certificate_not_yet_valid_at_gentime_is_the_same_code`."
```

The **fourth** held cell — `ber-where-der-required/ber-where-der-required` —
is *not* D91's, but its stated reason (*"A5's strict-DER code, owed by D60"*)
is stale: D60 §7.3 has named it. With the prefix ruled it becomes fillable as
`anchor-der-not-strict`. **D60/A5 owns that call, not D91**; recorded as a
finding (§11.4) rather than applied here.

### 9.2 `crates/antseal-core/tests/tamper_completeness/mod.rs`

`EXPECTED_M2_UNMINTED` loses its **first three** entries (the D91 holds).
It keeps the fourth pending §11.4. Its doc comment's paragraph beginning
*"**Four entries, and three of them are one defect.**"* is replaced by a
sentence recording that D91 ruled and the three were released — the list must
never silently empty, since the arming assertion reads it in both directions.

### 9.3 `docs/testing/error-code-contract.md`

§2 per §6.1. §7's status log gains a dated entry:

> - **2026-08-02 (M2 planning round, D91)** — **the `anchor-` family is
>   registered and no code is minted, renamed or removed; the universe stays
>   194.** Two decisions resolved the same day proposed different namespaces
>   for A — D53 §7 (with D56 §7, D59 §5 and D60 §7.2) `anchor-`, D58 §10.4
>   `ots-` with a predicted sibling `tsa-` — and §3 makes whichever binds
>   first permanent. D91 rules **one prefix, `anchor-`**. The F precedent does
>   not license the split: `manifest-`/`bundle-` encodes an information-flow
>   guarantee D78 enforces in the type system, while `ots-`/`tsa-` encodes
>   `AnchorKind`, already a typed field on `AnchorVerdict` **and** on frozen
>   report v1's `AnchorResult` — the same duplication §2 refuses for the
>   decode layer. Measured: seven of the sixteen already-ruled `anchor-*`
>   codes belong to neither of the split's namespaces, so its honest count is
>   four prefixes, not two; and D58's own prediction was falsified the same
>   day by **D60**, A5's decision, which chose `anchor-`. D58's sixteen
>   `ots-*` codes become `anchor-ots-*` (D91 §7.1), fifteen mechanically and
>   one by merge: the digest-commitment check is
>   **`anchor-ots-digest-mismatch`** (D56 §7), and
>   `ots-ops-do-not-commit-anchor-digest` is never minted. Also found, and
>   larger than the naming: **D56 rule O2 is unreachable and reads a field
>   `OtsArtifact` does not have** — D58 puts the comparison inside
>   `parse_ots`, so O1 always claims it first (D91 §6.4). §2's headline rule
>   *"a domain never mints a code under another domain's prefix"* is enforced
>   by **nothing** today — `census` sorts an unregistered prefix into R's
>   bucket and prints it — which is how sixteen codes came to be minted under
>   an unregistered namespace with a green suite. → **Q77**.

### 9.4 `docs/decisions/D58-opentimestamps-viability.md` — the amendment

D58 is a RESOLVED record; it is amended, not overridden. **Paste verbatim,
immediately after the §10.4 heading, before the paragraph beginning "New
domain prefix":**

```markdown
> **Amended 2026-08-02 by [D91](D91-anchor-error-code-namespace.md).** This
> section originally opened *"New domain prefix **`ots-`**, owner **A**,
> appended to `docs/testing/error-code-contract.md` §2's table. It borrows no
> other family's prefix; A5 will want a sibling `tsa-` on the same grounds."*
> **`ots-` is not registered and never will be. The A domain has one prefix,
> `anchor-`.** The sibling this section predicted was decided the same day and
> went the other way: **D60 §7.2** — A5's own decision — opens *"New
> error-code prefix **`anchor-`**, owner **A**"* and mints eight codes under
> it, as do D53 §7, D56 §7 and D59 §5. The sixteen codes listed below are
> therefore read as `anchor-ots-*` throughout: fifteen take the prefix
> mechanically (D91 §7.1's map), and the seventh,
> `ots-ops-do-not-commit-anchor-digest`, is **not minted at all** — the
> digest-commitment check is D56 §7's `anchor-ots-digest-mismatch`, which
> §10.3 step 5 raises and to which D53 §8 already binds M2 tamper row 1.
> Every other clause of §10.4 stands, and so does the whole of §§9–11: the
> seven limits, their derivations and F4 rows, the frozen check order, the
> iterative-parser requirement and the named tests are untouched by the
> renaming. One further correction §10.2 needs, from D91 §6.4: `OtsArtifact`
> has no `stamped_digest` field, and this is correct — the comparison belongs
> in the parser for §10.3's work-amplifier reason — so **D56 rule O2 names an
> outcome rather than adding a second check**, and D58 §11's
> `ots_stamping_a_different_digest_is_rejected` and D56 §9's
> `a_wrong_digest_ots_is_invalid_regardless_of_its_attestations` are one test.
```

### 9.5 `docs/decisions/D56-ots-internally-consistent-trigger.md`

D56 wins on both points and needs no amendment paragraph. One clarification
belongs on rule O2 so §6.4's finding does not have to be rediscovered:

```markdown
> **Clarified 2026-08-02 by [D91](D91-anchor-error-code-namespace.md) §6.4.**
> O2 names an outcome, not a second check. D58 §10.2 makes `anchor_digest` a
> required parameter of `parse_ots`, so the comparison happens at §10.3 step 5
> inside the parser — deliberately, since a post-parse check would let a
> wrong-digest `.ots` amplify work — and `OtsArtifact` therefore has no
> `stamped_digest` field to read. O1 always claims this input; its code for it
> is `anchor-ots-digest-mismatch`, which is what O2 says. Do **not** add a
> `stamped_digest` field to make O2 literally executable.
```

### 9.6 Not authorised

- **No code in the frozen 194 is renamed, removed or re-scoped**, and the
  snapshot does not move: D91 mints nothing. A11's and A5's first appends take
  it up through §4a's additions-only path.
- **No `AnchorState`, no wire `AnchorStatus`, no report field.** Report v1
  stays frozen; D53 §6's and D56 §6's constraint — diagnostic codes never
  enter `VerificationReport` — is untouched and is the reason a prefix ruling
  is not a format event.
- **No `AnchorDiagnostic` prefix validation.** `anchor/model.rs:660-666`
  deliberately validates none, recording this collision as the reason. D91
  does *not* license baking `anchor-` into the constructor: the enforcement
  belongs in Q77's enumerator sweep, which sees the whole family at once,
  not in a constructor that sees one code and would reject the wrapper cases
  §2's rule permits.

---

## 10. Discovered work

ID block **A45, Q77**, allocated from the low end. **A45 is unused and
returned.** This document uses **Q77** — and uses it for the task Q80's own
commit message already named it for, merged with §8's prefix sweep, because
they are one mechanism and splitting them would be the F23/F24 sibling
failure committed knowingly. Full entry in the planner's task file.

- **Q77 (S)** — make §2's namespace rules machine-enforced: the
  prefix-conformance sweep of §8.1–§8.2, plus the code/`ErrorClass`
  disjointness Q80 measured by hand. **Blocks nothing** (A5 and A11 may
  proceed on the ruling), but must land in the same wave, since it is the only
  thing that would catch the next D58.

No other task is minted. A38/Q80's scope is unchanged and now unblocked; A11
consumes §7.1; Q76 applies §9.1–§9.2; the D58 and D56 amendments are the
orchestrator's.

---

## 11. Corrections to existing prose (orchestrator applies at source)

1. **`docs/decisions/D58-opentimestamps-viability.md` §10.4** — *"New domain
   prefix **`ots-`**, owner **A** … A5 will want a sibling `tsa-` on the same
   grounds"* and *"Sixteen codes"*. Amended per §9.4; the count becomes
   fifteen minted plus one of D56's.
2. **`docs/decisions/D56-ots-internally-consistent-trigger.md` §5, rule O2** —
   the predicate `artifact.stamped_digest != *anchor_digest` reads a field
   `OtsArtifact` does not have, and the rule is unreachable behind O1.
   Clarified per §9.5.
3. **`docs/testing/error-code-contract.md`, beta working tree, §2** — the
   `**UNRESOLVED — D91**` cell and the *"The A domain's prefix is UNRESOLVED
   and blocking"* block. Replaced per §6.1.
4. **`crates/antseal-core/tests/tamper_completeness/mod.rs`,
   `EXPECTED_M2_UNMINTED` entry 4** — the reason *"A5's strict-DER code, owed
   by D60 (D53 §8 row 8)"* is stale: **D60 §7.3 named it**
   (`anchor-der-not-strict`, for `ErrorKind::IndefiniteLength`, which is what
   BER-where-DER-required produces). With the prefix ruled, either fill the
   cell or restate the reason as "owed by A5's implementation", but it is no
   longer owed by a decision. **Not applied here — D60/A5's call.**
5. **`docs/decisions/D53-chain-invalid-at-gentime.md` §10 and §11 item 1** —
   the missing-prefix work is attributed to **A38**; D59 §7 and Q80 call the
   same work **Q80**, and D60 §7.2/§11 item 8 calls it **Q72**. Three ids for
   one task, in four resolved decisions. The tree's landed commit is `Q80`
   (`061fa80`). Reconcile to one id and record the aliases, or the next reader
   counts three tasks.
6. **`crates/antseal-core/src/error_universe.rs:192-199`** — `census`'s
   `PREFIXES` is a private six-element literal whose `"(unprefixed)"` bucket
   silently absorbs any unregistered prefix. It is presented as a census, but
   it is the closest thing the tree has to a prefix registry and it is wrong
   by omission the moment `anchor-` lands. Fold into Q77's
   `REGISTERED_PREFIXES` (§8.1) rather than adding a seventh literal beside it.
7. **`docs/decisions/D58-opentimestamps-viability.md` §11**, test row
   `ots_stamping_a_different_digest_is_rejected`, and **D56 §9**, test row
   `a_wrong_digest_ots_is_invalid_regardless_of_its_attestations` — these are
   the same test in two documents (§6.4). Keep one name; D56's is the stronger
   statement (it asserts the check beats a genuine online-confirmable Bitcoin
   attestation) and D58's is the one that pins the *position* (before the
   walk). They should be one test asserting both, or two tests with the
   overlap recorded — as written, an implementer writes both and neither
   document says they are the same input.

---

## 12. Residual risks and revisit triggers

- **The convention of §7.3 is unenforced by design.** A future A task may mint
  `anchor-tsa-chain-signature-invalid` beside `anchor-chain-signature-invalid`
  and nothing will go red, because §3 makes the fix unavailable. Trigger: the
  first A code whose name a reviewer has to argue about; the answer is a
  recorded note in §2, never a rename.
- **`anchor-ots-*` is eleven characters of prefix.** Nothing in the tree
  depends on code length, and the longest name grows from 41 to 43 bytes
  (measured, §7.1), but a JSON verdict carrying several anchor codes is
  wordier under this ruling than under the split. Accepted: the split's cost
  is permanent structure, this one is bytes.
- **Q77 is the only thing standing between this ruling and a convention.**
  Until it lands, §2's headline rule is enforced by review, which is the
  regime that produced this collision. Trigger: A5 or A11 landing a code
  before Q77 — acceptable once, not twice.
- **`AnchorKind` carries the burden the prefix would have carried.** If a
  future report version ever drops the `kind` field from `AnchorResult`, the
  argument of §1 loses its second leg (the first, `AnchorVerdict::kind`,
  survives). Trigger: any `REPORT_VERSION` bump that touches `AnchorResult`.
- **The alias tangle of §11.5 is a live merge hazard, not a tidiness item.**
  Four resolved decisions instruct three different tasks to write one table
  row. If two lanes act on two of the ids, two lanes edit §2's table
  concurrently. Trigger: immediate — reconcile before the next A wave starts.

## Index row (orchestrator applies at merge)

| [D91](D91-anchor-error-code-namespace.md) | The A-domain error-code namespace — **one prefix, `anchor-`; `ots-`/`tsa-` rejected**, and the register's two-way framing overturned: measured against the codes four resolved decisions already mint, the split's honest count is **four** prefixes (codec, DER/CMS parse, chain, capture), because **seven of the sixteen `anchor-*` codes belong to neither of its namespaces** — the online-header and block-absent checks, the three chain rules, and D59's capture-path code, which lives in `antseal-anchor` and which Q80 could only reach by *widening a surface column*, a move a prefix scheme does not have. D58 §10.4's own prediction (*"A5 will want a sibling `tsa-`"*) was **tested and failed the same day**: A5's decision is **D60**, which independently opens *"New error-code prefix `anchor-`"*. The F precedent argues against the split, not for it: `manifest-`/`bundle-` encodes an information-flow guarantee **D78 enforces in the type system** (`BundleError` has no arm carrying a `ManifestError`), whereas `ots-`/`tsa-` encodes `AnchorKind` — already a typed field on `AnchorVerdict` *and* on frozen report v1's `AnchorResult` — which is the duplication §2 already refuses for the decode layer (*"a code names a rejection class, never a layer"*). The one recorded argument for the split (Q80's `anchor-gate-abort` stem) **inverts on measurement**: the split shares a stem with the vault's live anchor slot names at *every* code (9 occurrences of `ots-pending`/`tsa-0.der` vs 3 of `anchor-gate-abort`, and `ots-pending` is the better impostor). Digest-commitment check ruled **`anchor-ots-digest-mismatch`**; `ots-ops-do-not-commit-anchor-digest` never minted (6 occurrences, all prose, none in code, in any worktree). D58's 16 → `anchor-ots-*`, fifteen mechanically and one by merge. Also found, larger than the naming: **D56 rule O2 is unreachable and reads a field `OtsArtifact` does not have** — D58 puts the comparison inside `parse_ots`, so O1 always claims it — and §2's headline rule *"a domain never mints a code under another domain's prefix"* is enforced by **nothing**, `census` sorting an unregistered prefix into R's bucket and printing it, which is how 16 codes were minted under an unregistered namespace with a green suite → **Q77**. Zero codes minted, zero renamed; universe stays 194 | RESOLVED | 2026-08-02 |

## Register entry for `TODO.md` (orchestrator pastes; do not edit `TODO.md`)

- [x] **D91** The A-domain error-code namespace: one `anchor-` prefix vs per-surface `ots-`/`tsa-`, and the canonical code for the `.ots` digest-commitment check (A38/Q80, A5, A11 — blocking) — **Resolved 2026-08-02** (docs/decisions/D91-anchor-error-code-namespace.md): **one prefix, `anchor-`**, and the two-way framing overturned — the split's honest count is **four** prefixes, since seven of the sixteen already-ruled `anchor-*` codes (the two online checks, `anchor-ots-header-uncommitted`, the three chain rules, and D59's `antseal-anchor` capture-path code) belong to neither of its namespaces. D58 §10.4's prediction that *"A5 will want a sibling `tsa-`"* was **falsified the same day by D60**, A5's own decision, which independently registered `anchor-`; four resolved decisions choose `anchor-` (16 codes) against D58's one (16 codes). The F precedent **cuts against** the split: D78 makes `manifest-`/`bundle-` a structural guarantee enforced in the type system, while `ots-`/`tsa-` merely re-encodes `AnchorKind`, already a typed field on `AnchorVerdict` and on frozen report v1's `AnchorResult` — the exact duplication §2 refuses for the decode layer. Q80's `anchor-gate-abort` stem argument **inverts on measurement** (9 live `ots-pending`/`tsa-0.der` vault slot names vs 3). Digest check ruled **`anchor-ots-digest-mismatch`**; `ots-ops-do-not-commit-anchor-digest` never minted — 6 occurrences, all prose, none in code, in any worktree. D58's 16 codes → `anchor-ots-*` (15 mechanical + 1 merge); D58 amended, D56 clarified. Found: **D56 rule O2 is unreachable and reads a field `OtsArtifact` lacks**, and §2's own "never another domain's prefix" rule is **enforced by nothing** → **Q77**. Releases three of `EXPECTED_M2_UNMINTED`'s four held cells. Zero codes minted or renamed; universe stays 194
