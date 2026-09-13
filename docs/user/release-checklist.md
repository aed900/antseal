# The release checklist

This is the gate a release passes before it reaches you. It is published rather
than kept internal for the same reason the freeze ceremony is published
(`format-stability.md` §9): a promise you cannot check is worth less than one
you can.

Every row below states **what must be true** and **the command that reads the
answer back**. A row is never ticked from memory, from a task row, or from a
previous release — the figures in this repository have gone stale inside two
days before now, and the instruction that follows from that is the one Q254's
runbook already gives: *"Re-run every command; quote no figure from a row."*

## Status of this checklist, stated first

**No release has happened, and not one row below has been executed.** Every row
is tagged `[UNEXECUTED]`. That tag is the honest state, not a placeholder: this
document was written before the release pipeline exists, so it is a
specification of the gate rather than a record of one being passed.

Measured 2026-08-22:

- `grep -rn -- '--release' .github/workflows/` returns **0** hits across the
  **8** workflow files present. **No job in this repository builds a release
  binary.** Section G explains what that costs.
- `git tag --list` returns `format-v1-freeze` and `pre-trailer-strip-949dd9d`.
  There is no `v*` release tag.
- Every crate in the workspace is `version = "0.0.0"`, asserted for the core
  crate at `crates/antseal-core/src/lib.rs:54`.

## What this checklist is not — it is not the publish-flip runbook

There are two ordered procedures in this project and they gate two different
acts. Confusing them is easy and expensive, so the boundary is written twice,
once from each side.

| | **the publish flip** | **this checklist** |
| --- | --- | --- |
| the act | making the source repository public | shipping a release to users |
| owner | Q254, executing Q65's decision | Q31, gating Q34's publication |
| venue | `docs/ci-verification.md`, chapter *"Q254/Q65 — the publish flip, as an ordered procedure"* | this page |
| shape | Phase A (before), Phase B (at the flip), Phase C (after) | sections A–I below, all before |

The flip runbook says so itself, in its own *"What this checklist does NOT
cover"* section:

> **It does not cover releases, packages, or `crates.io`.** Release assets
> inherit repository visibility (D72 §2 R6) and change status at B1, but the
> release process itself is Q31/Q34's and the publication scope of the crates
> is D72's.

The handoff is therefore explicit from both ends and neither procedure is a
prerequisite of the other in general. One real ordering does exist and is
recorded at **F** below.

---

## A. Gate evidence

The M4 gate is task **Q34**, and its evidence is the precondition this
checklist exists to enforce. No release ships on a gate that was run but not
recorded.

- [ ] `[UNEXECUTED]` **The gate evidence bundle is committed** — gate logs, the
      page-verdict capture, the restore byte-compare and the disk-loss drill
      results. This is Q34's first `Accept` row and it is the one that makes
      every other row here checkable by someone who was not present.
- [ ] `[UNEXECUTED]` **The Sepolia end-to-end run is green**, and it ran
      **before** any mainnet action. Q32's `Accept` row 1 states that ordering;
      it is a deadline on the mainnet act, not a precondition of writing the
      scripts.
- [ ] `[UNEXECUTED]` **The clean-machine procedure used zero repo-checkout
      resources** — released artifacts and the hosted page only. If the machine
      needed a credential to fetch anything, it was not the clean third-party
      machine the gate tests.
- [ ] `[UNEXECUTED]` **The disk-loss drill recovered byte-identical originals**
      from nothing but the encrypted vault backup.
- [ ] `[UNEXECUTED]` **The traceability matrix is green for every milestone,
      including its line-143 section** — `docs/testing/verification-matrix.md`,
      rows `L143.1`–`L143.15`. Read the `notes` cell of every row: in that
      section `covered` means *the divergence is recorded and disposed*, which
      is wider than its meaning elsewhere in the matrix.

      ```bash
      python3 scripts/check-traceability.py
      ```

## B. The page hash, in the only form that can be true

The verifier page publishes its own build digest so a reader can rebuild and
compare. **The comparison is against the commit the page was deployed from, and
against no other commit** — including a later commit that changed nothing.

That is not a defect and not a debt. The page module stamps its source commit
at compile time (`crates/antseal-wasm/build.rs:22-40`), so the commit string is
itself a compile input; `docs/ci-verification.md:2641-2647` measured two commits
whose every other compile input was identical producing modules of identical
size and different digests. The sentence that follows it at `:2651-2652` is the
rule this row enforces:

> The honest claim is "reproducible at the commit it was deployed from", never
> "reproducible from HEAD".

A row demanding a match against HEAD would be a row that can never go green.

- [ ] `[UNEXECUTED]` **The deployed commit is recorded** — the 40-character
      `head_sha` of the deploying run, not "the latest commit".
- [ ] `[UNEXECUTED]` **A local build at that commit reproduces the served
      bytes.**

      ```bash
      ANTSEAL_SOURCE_COMMIT=<deployed 40-hex> ./scripts/pages-publish.sh --build
      ./scripts/pages-publish.sh --verify
      ```

      The byte comparison is at `scripts/pages-publish.sh:132-145`; it compares
      the served body against the `SHA256SUMS` the local `--build` produced, and
      prints `the served bytes are NOT the built artifact` with both digests
      when they differ. Note the same function checks two further properties in
      the same run: that the page is served as `text/html`, and that the
      identity and gzip fetches decode to identical bytes.
- [ ] `[UNEXECUTED]` **The published digest in the release notes is the one just
      reproduced**, and it is labelled with its commit. A digest published
      without its commit is not checkable by anyone.

**Read this before citing any previously published number.** The page's
standing-debt history is recorded in three places that do not agree, and the
disagreement is live as of 2026-08-22:

| surface | says |
| --- | --- |
| `tasks/R.md:357` | the debt is **discharged** — the redeploy ran 2026-08-15, run `31873422229`, `head_sha 9317a35b3adaef56b03eaa22a80a2b76e232a7d9` |
| `docs/ci-verification.md:2633` section | the same, plus the reasoning correction quoted above |
| `TODO.md`, the `R26` row | still carries **`STANDING DEBT: a redeploy is owed`** |

The retraction landed in two surfaces and not the third. Until that is
reconciled by whoever owns the row, **measure the live page rather than quoting
any of the three.**

## C. Signatures

The mechanism is `docs/decisions/D71-binary-signing-mechanism-and-key-custody.md`:
one long-lived Ed25519 keypair held by the maintainer, used with minisign,
**signing performed locally**. The reader-facing half of this section is
`../signing/verifying-a-release.md`.

- [ ] `[UNEXECUTED]` **`SHA256SUMS` covers every released artifact**, and every
      artifact plus the sums file carries a `.minisig`.
- [ ] `[UNEXECUTED]` **Every trusted comment is the structured form**, carrying
      this artifact's own basename:

      ```
      antseal <version> <artifact-basename> commit:<40-hex> <RFC3339 UTC timestamp>
      ```

      Built at `scripts/sign-release.sh:250`. The per-artifact basename is what
      defeats presenting one artifact's signature for another, which is why the
      passphrase prompt cannot be batched away — `scripts/sign-release.sh:90-93`
      states that in the script's own help.
- [ ] `[UNEXECUTED]` **The untrusted comment carries nothing.** It is freely
      rewritable after signing while the artifact still fully verifies, so D71
      §2 R4 forbids putting a version, a filename or any other meaningful value
      there.
- [ ] `[UNEXECUTED]` **The signing key was never on a runner.** The secret key
      belongs on no CI runner, in no repository secret and in no KMS. Note what
      enforces this and what does not: the prohibition is stated in the script's
      help text at `scripts/sign-release.sh:97`, and the *mechanical* refusal in
      the script is a different one — an unencrypted (`-W`) key is refused by
      reading the KDF field out of the key struct. There is no automated check
      that the host is not a runner, so this row is a human attestation.
- [ ] `[UNEXECUTED]` **The verifier was run against the finished directory, and
      its self-test was run too.**

      ```bash
      ./scripts/verify-release.sh --version <v> --commit <40-hex> --dir dist/
      ./scripts/verify-release.sh --self-test
      ```

      The self-test plants every mutation D71 §1.3 measured and requires each to
      be caught by its own distinct failure.

## D. Versioning

- [ ] `[UNEXECUTED]` **The release tag is `v<major>.<minor>.<patch>`** and its
      SemVer level was chosen against the **CLI surface**, never against the
      format. See `versioning.md` §4.
- [ ] `[UNEXECUTED]` **The format version did not move unless a change in
      `format-stability.md` §8's first table forced it.** If it did move, section
      E applies and a `format-v<n>-freeze` tag is cut.
- [ ] `[UNEXECUTED]` **The release notes state both numbers separately**, and do
      not present either as implying the other.

## E. Format vectors — never ship a version without them

Adopted from `format-stability.md` §9 step 7, which names this checklist as the
place the rule is enforced.

- [ ] `[UNEXECUTED]` **Every released format version has its golden vectors in
      the tree**, and CI runs them on the CLI, on `wasm32`, and on the page
      path. A released version whose vectors are missing, altered, or failing on
      any of those three is not shippable.
- [ ] `[UNEXECUTED]` **The vector index and the decoder agree.**
      `SUPPORTED_VERSIONS` (`crates/antseal-core/src/format.rs:115`) is the code
      side, `testdata/vectors/v<n>/INDEX.json` is the data side, and
      `crates/antseal-core/tests/vector_index.rs` asserts they match.
- [ ] `[UNEXECUTED]` **The freeze boundary has not drifted.**

      ```bash
      python3 scripts/check-traceability.py --freeze-boundary
      ```

## F. Timestamp-authority root store

These four rows are adopted from `../anchors/root-store-update.md` §6, which
wrote them in quotable form for this checklist to take over. That section's own
note says the reference was one-directional until this page existed; it now
points both ways. The wording is that section's, unchanged, except that its
`docs/anchors/…` link is rewritten relative to this directory.

- [ ] `[UNEXECUTED]` **Root-store expiry horizon.**
      `roots_within_expiry_horizon(now, 365 d)` is empty for the release build.
      If not, append the successor root (`../anchors/root-store-update.md` §4) —
      never swap, never drop.
- [ ] `[UNEXECUTED]` **Root-store provenance.** Every root in `ROOTS_V1` has a
      `PROVENANCE.md` section whose recorded fingerprints match the compiled
      bytes, and every `- QUARANTINED:` root is absent from the store.
      (Mechanised by `the_store_matches_the_provenance_record`; the human half is
      confirming the *channels* were really executed, not merely written down.)
- [ ] `[UNEXECUTED]` **Store version in the release notes.**
      `TSA_ROOT_STORE_VERSION`, `TSA_ROOT_STORE_BUILD_DATE`, the root count,
      and — if either changed since the last release — which root was appended
      and which organisation that admits.
- [ ] `[UNEXECUTED]` **Quarantine disclosure.** Any documented TSA alternate
      whose root is quarantined is named in the release notes together with the
      consequence: configuring it produces a pre-payment seal abort, not a weaker
      bundle.

**The one real ordering against the publish flip lives here.** A root-store
append changes what a released binary trusts, so it belongs to a release and not
to a visibility change; nothing in section F waits on the flip, and nothing in
the flip waits on section F.

## G. The build, and the supply chain around it

- [ ] `[UNEXECUTED]` **The release job pins its runner image and asserts the
      artifact's glibc floor.** `ubuntu-latest` is forbidden for the artifact
      build: it is a moving alias re-pointed on its own schedule, so a binary
      built there has a floor nobody measured and that can rise without a
      commit. The floor is asserted in the job, not assumed.
- [ ] `[UNEXECUTED]` **Every `uses:` in the release job is pinned to a 40-hex
      commit.** Measured 2026-08-22 across the 8 workflows present: **57**
      `uses:` invocations, **57** pinned, **0** unpinned.

      ```bash
      grep -rhoE '^[[:space:]]*(-[[:space:]]*)?uses:[[:space:]]*\S+' .github/workflows/ \
        | grep -vcE '@[0-9a-f]{40}'
      ```

      Use a pattern that admits leading whitespace **and** an optional list
      dash. A pattern anchored at `^uses:` misses every `- uses:` step; a pattern
      anchored at `(^|- )uses:` misses every indented `uses:` that has no dash,
      of which there are **11** here. Both mistakes produce a smaller corpus and
      a green result, which is the failure that looks like success.
- [ ] `[UNEXECUTED]` **The pin ledger moved with the pins.**
      `.github/action-pins.tsv` is the authority for
      `scripts/check-action-pins.py`; a ledger row that moves without its
      residual being re-taken reddens rule P7 by design.

### The `sha_pinning_required` row, and why it is recorded rather than ticked

**The repository setting is NOT armed, and the blocker is `Q255`.**

This is the escape branch of Q31's own `Accept` row — *"the release job's
actions are SHA-pinned and `sha_pinning_required` is ARMED, or the reason it is
not is recorded here with its blocker named."* This is that record.

- **Reason, measured.** `actions/upload-pages-artifact@v3.0.1` is a *composite*
  action whose own `action.yml:77` carries a bare `actions/upload-artifact@v4` —
  a moving major tag one level below anything this repository can pin. GitHub's
  pinning policy traverses composites, so arming `sha_pinning_required: true`
  today refuses `pages.yml` outright, and `pages.yml` is the only job in the
  tree with write scope. Turning the enforcement on before `Q255` resolves would
  block the very change that fixes it.
  (`docs/decisions/D143-third-party-action-pinning-and-renewal.md` §2 R5.)
- **What `Q255` does.** Upgrades and re-pins all three Pages actions —
  `configure-pages` to v6.0.0, `upload-pages-artifact` to v5.0.0, `deploy-pages`
  to v5.0.0 — each to its resolved commit, and deletes the `residual` ledger line
  only after confirming v5's nested `uses:` is itself SHA-pinned.
- **How to verify the state — by reading it back, never by having set it.**

  ```bash
  gh api repos/aed900/antseal/actions/permissions
  ```

  Last observed 2026-08-19 by Q254's step B6:
  `{"enabled":true,"allowed_actions":"all","sha_pinning_required":false}`.
  That is a **recorded exposure, not a step to execute** — and it is weaker than
  the files, which are fully pinned. Do not tick anything on the strength of
  reading it.

- [ ] `[BLOCKED — Q255]` `sha_pinning_required` is `true`, read back from the
      API. Until `Q255` lands, this row stays unticked with the reason above,
      and the release notes say so rather than staying silent.

## H. crates.io — the decision, and what executing it means

**No `antseal*` crate is published to crates.io as part of this release.** The
decision is `docs/decisions/D72-release-targets-distribution-and-crates-io-scope.md`
§2 R8, on four independent grounds, any one sufficient: it is not currently
possible (the packaging step fails on a structural self-dev-dep); a publish is a
permanent public source disclosure that routes around the visibility decision;
it would put a permanent licence assertion on an immutable index that is correct
for an empty placeholder and wrong for the real crate; and the distribution
channel is already decided and is not crates.io — `cargo install` would also be
an **unsigned** acquisition path, defeating section C for anyone who used it.

*Executing* that decision is a recording act with **zero public steps**, which
is what makes it doable at all — see D141 §1.5's clause-by-clause walk of this
row.

- [ ] `[UNEXECUTED]` **The five reserved names are recorded in the release
      documentation** with owner, publish date and status, so the reservation is
      a known project asset with a stated purpose rather than five orphans.
      Retrieved by D72 §1.5 on 2026-08-16, and to be re-read at release rather
      than quoted from here:

      | name | version | published | owner | licence | yanked |
      | --- | --- | --- | --- | --- | --- |
      | `antseal` | 0.0.0 | 2026-08-11 | `aed900` | `MIT OR Apache-2.0` | false |
      | `antseal-core` | 0.0.0 | 2026-08-11 | `aed900` | `MIT OR Apache-2.0` | false |
      | `antseal-anchor` | 0.0.0 | 2026-08-11 | `aed900` | `MIT OR Apache-2.0` | false |
      | `antseal-net` | 0.0.0 | 2026-08-11 | `aed900` | `MIT OR Apache-2.0` | false |
      | `antseal-cli` | 0.0.0 | 2026-08-11 | `aed900` | `MIT OR Apache-2.0` | false |

      `antseal-wasm` is **not** among them: it is `publish = false`
      (`crates/antseal-wasm/Cargo.toml:49`) and was never reserved.
- [ ] `[UNEXECUTED]` **The review date is set: the first release after M4.** At
      that point either a real version ships, or the reservations are
      re-justified deliberately. What D72 §2 R8 refuses is letting them sit
      indefinitely with nobody owning the question. They are not yanked: a yank
      hides a version from resolution, frees no name and deletes no code.
- [ ] `[UNEXECUTED]` **The release notes do not imply a crates.io route
      exists.** A second source of binaries contradicts the single-authoritative-
      source rule, and an unsigned one contradicts section C.

## I. Rows this checklist carries but cannot yet close

Recorded here rather than omitted, because a checklist that silently drops its
hard rows is worse than one that names them.

| row | state | why |
| --- | --- | --- |
| a dry-run tag produces a complete signed draft release | **not attempted** | no release workflow exists (0 hits for `--release` across the 8 workflows), and signing is a local maintainer act by D71 §2 R1 |
| the WASM hash is identical across two independent builds | **not attempted** | needs the release pipeline above; the deploy-gated reproducibility step has executed zero times on a hosted runner. **[2026-09-13]** D168 §2 R1 adds the push-tier enforcement: the required status context `reproducible-build` (`.github/workflows/reproducible-build.yml`) runs the same two-environment comparison on every push to `main` and every pull request. It is built locally and NOT YET WITNESSED, so it too has executed zero times on a hosted runner; and because it compares two environments on one runner at one commit, it does not by itself close this row |
| licence text reaches the **deployed page artifact** | **open** | `verifier-web/` cannot hold a licence file — a test asserts that directory holds exactly `index.template.html` — so the obligation moves to the published artifact. **VENUE DECIDED 2026-09-03 (wave 33): a sibling file the deploy writes** — one `pages.yml` step copies root `LICENSE-MIT`/`LICENSE-APACHE`/`COPYRIGHT` into `target/verifier-web/` before `upload-pages-artifact`. Footer REFUSED (the template is a tracked page input: STALE-ARTIFACT cascade and a double gate for a delta unverifiable behind the billing gate); release archive REFUSED (the clause's subject is the page artifact a static-host copier takes — an archive never reaches it). Mechanism deliberately UNWRITTEN until witnessable: owner = the first CI-capable lane after Maintainer action (11); timing = with the first green hosted Pages run; closes on licence CONTENT served at the sibling URLs, never a status code alone. Full record: `tasks/Q.md` Q31 Accept row 6. **[2026-09-13]** Maintainer action (11), the billing act that owner clause waited on, is dissolved: the refusal it named was the private repository's Actions allowance, which the public flip retired (see the note below this table). The owner is `Q31` `Accept` row 6 itself. And the decided venue collides with `scripts/pages-publish.sh`'s own guard that the deploy directory holds exactly what `SHA256SUMS` lists (`scripts/pages-publish.sh:85-95`): wave 35's planning round measured that copying the three licence files in reds with *the deploy directory and SHA256SUMS disagree*, exit 1, against exit 0 without them. The mechanism needs a ruling before it is written |
| `sha_pinning_required` armed | **blocked** | `Q255`, section G |

A further constraint applies to all four and to any row here that needs a
hosted run: **the hosted CI provider has refused every job since 2026-08-15** —
runs complete in seconds with `steps: 0` and no runner assigned, which
`docs/ci-verification.md` diagnoses as an exhausted minute allowance rather than
a verdict on the code. No row above may be ticked on a run with that signature.

**[2026-09-13] Corrected: hosted jobs execute again.** Read back from the API:
`ci` run `34719132556` at `4a7f524` — 15 of 15 jobs `success`, 8 to 15 steps
each, a runner assigned to every job — and `ci-always` run `34720769800` at
`ef5f6d9` — 2 of 2 jobs `success`, 5 and 18 steps, both with a runner assigned —
each triggered by a push on 2026-09-12. The refusal above was the private
repository's Actions allowance; standard hosted runners are not billed on a
public repository, so the public flip of 2026-09-12 retired it. The rule in the
paragraph above stands: a job with `steps: 0` or an empty `runner_name` was
refused, not run, and no row is ever ticked on such a run.

## What this checklist does not cover

- **It does not authorise anything.** Publishing a release is an external action
  requiring express, in-the-moment consent naming the action, the destination
  and the account. Nothing on this page is that consent, and no earlier consent
  carries forward to it.
- **It does not sequence the visibility flip.** That is
  `docs/ci-verification.md`'s Q254/Q65 chapter, and it is a different act with a
  different owner.
- **It does not decide the artifact set.** Which target triples are built is
  D72's, not this page's.
- **It has no rollback.** A published release cannot be recalled: a downloaded
  artifact stays downloaded, and a crates.io version can never be deleted. Every
  row above is a gate precisely because there is nothing after it.
- **It has never been run.** Every row is `[UNEXECUTED]` or `[BLOCKED]`, and a
  pre-state is not a result.

## Evidence

| Claim on this page | Where it is enforced or measured |
| --- | --- |
| no job builds a release binary | `grep -rn -- '--release' .github/workflows/` → 0 hits, 8 files, 2026-08-22 |
| 57 `uses:`, all pinned; 11 invisible to a `(^\|- )uses:` pattern | `.github/workflows/`, measured 2026-08-22; ledger `.github/action-pins.tsv`; checker `scripts/check-action-pins.py` |
| the page reproduces only at its deployed commit | `crates/antseal-wasm/build.rs:22-40`; `docs/ci-verification.md:2641-2652` |
| the served bytes are compared against a local build | `scripts/pages-publish.sh:132-145` |
| the trusted comment's structured form | `scripts/sign-release.sh:250`; D71 §2 R4 |
| the untrusted comment carries nothing | D71 §2 R4 |
| an unencrypted key is refused mechanically | `scripts/sign-release.sh`, the `-W` refusal reading the key struct's KDF field |
| the signing prohibition on runners is text, not a check | `scripts/sign-release.sh:97` |
| the release-verifier self-test plants every measured mutation | `scripts/verify-release.sh --self-test`; D71 §1.3 |
| vectors gate a version bump | `format-stability.md` §9 step 7; `crates/antseal-core/tests/vector_index.rs` |
| the supported-version list is append-only | `crates/antseal-core/src/format.rs:115` and its doc comment at `:112-114` |
| the four root-store rows, verbatim | `../anchors/root-store-update.md` §6 |
| `sha_pinning_required` is blocked by `Q255` | D143 §2 R5; last read-back recorded at `docs/ci-verification.md:3427` |
| no crates.io publish at M4, on four grounds | D72 §2 R8 |
| executing that decision is a recording act with zero public steps | D141 §1.5 |
| the five reserved names and their metadata | D72 §1.5, retrieved 2026-08-16 |
| `antseal-wasm` was never reserved | `crates/antseal-wasm/Cargo.toml:49` |
| the flip runbook hands the release process to Q31/Q34 | `docs/ci-verification.md`, the Q254/Q65 chapter's *"does NOT cover"* section |
| the gate itself | task **Q34**; `docs/testing/verification-matrix.md` |
