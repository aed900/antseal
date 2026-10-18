# D192 — SwissSign is **flagged, not promoted**: `MVP-SPEC.md:109`'s documented alternate ships **documented, configurable and never counting** while store v1 quarantines its root, the disposition is **named for `Q34`**, and the places a user configures TSAs say **which authorities count**

- **Status: RESOLVED. H11's direction — flag now, refuse promotion — survived. Two of its
  premises fell (b), and it missed two facts.**
  - **H11 — *flag arm now (record the divergence, disposition at `Q34`) plus fix
    `roots/mod.rs`'s rustdoc counts; promotion of SwissSign refused (needs `A56`)*.**
    - **The rustdoc half had already dissolved.** `A138` fixed the store's two false rustdoc
      claims on 2026-10-16 (`TODO.md:699`, `[x]`). `A136`'s own register line still tells a
      lane to do it (`TODO.md:697`: *"fix `roots/mod.rs:259` (*"Three roots"* against a
      four-element array) and `:260-261` … in the same act"*), so the orchestrator strikes that
      clause (§2 R4).
    - **The "which TSAs count" statement already existed.** Q26's page says it in §1, in its
      store table and in §3's *"root in store v1"* column, so `A136`'s Accept rows 2 and 4 were
      met there. The act is a **second** statement where a user configures the list, plus the
      runbook's alternates table — not new content.
    - **Missed: beside a pinned TSA, a quarantined one marks every seal degraded.** The page
      says only that such an endpoint *"buys you extra HTTP requests and no extra evidence"*
      (`docs/user/timestamp-authorities.md:190-191`).
    - **Missed: at the abort, the CLI discards which endpoint failed and why.** A
      SwissSign-only user is told *"re-run when a TSA is reachable"*, advice that cannot work
      because SwissSign answered. That is D194's `U97`.
  - **"SwissSign alone is a guaranteed pre-payment abort" holds, with one qualifier the row
    omitted:** `--force-degraded` turns it into a paid seal that carries zero TSA tokens.
- **Date: 2026-10-17**
- Owner rows: **`A136`** (§2 R1–R4); **`Q34`** (a Notes line naming the flag and its
  disposition, §2 R4).
- Related:
  - **D57** §5 and §6 (the quarantine and the channel rule that keeps a root out ahead of its
    provenance; §5 takes an optional dated addendum);
  - **`A56`** (promotion's prerequisite), **`A26`** (the append procedure), **`A138`** (the
    rustdoc fix), **`Q26`** (the page);
  - **D194** / **`U97`** (the abort's per-endpoint lines: the seal-time surface of "which TSAs
    count");
  - **D188** §2 R8 (`L-CFG`'s `docs/config.md` edit carries §2 R3's sentence);
  - **`Q31`** (the release notes that carry the disclosure).

## 0. What was measured against

`HEAD` `23f3093` (local `main`; `origin/main` `cfd5868`), tree clean, 2026-10-17.

Planning lane P4 (wave 38) worked read-only and built nothing; every claim it made comes from
reading code, tests and records. It made no network request, so whether `www.swisssign.com`
still refuses this host is **not established** (last measured 403 on 2026-08-03). The
availability survey (PS) found `A136` available (every `after` term `[x]`) and partly met: its
Accept rows 2 and 4 on the page, row 1 nowhere.

Before this record was written, the records lane re-read the load-bearing lines through
`git show 23f3093:<path>`, because round-1 lanes were already editing the tree. Every figure
below held.

## 1. What was measured

### 1.1 The divergence

- **The spec lists SwissSign.** `MVP-SPEC.md:109`: *"documented alternates with recorded
  caveats: zeitstempel.dfn.de (non-commercial terms), Sectigo (~15 s spacing), SwissSign
  (~10/day)"*, with chains validated to *"a **pinned TSA root store compiled into
  `antseal-core`**"*.
- **Store v1 does not hold its root.** `crates/antseal-core/src/anchor/roots/mod.rs:263`
  (`static ROOTS_V1`) holds four `PinnedRoot` entries — FreeTSA, DigiCert G4, DFN-Verein 2022,
  Sectigo R46 — and `pinned_store_is_exactly_four_roots_at_version_1` (`:360`) pins them.
- **The quarantine is recorded.** `crates/antseal-core/src/anchor/roots/PROVENANCE.md:258`:
  *"- QUARANTINED: swisssign-signature-services-root-2020-2"*; `:262-267`: *"a user who
  configures only quarantined TSAs gets a **hard pre-payment seal abort**, not a weaker bundle
  ... Promotion is an A26 append: one `PinnedRoot` block, one version bump, one section moved
  out of this list."*
- **Why.** D57 §5's correction (2026-08-03): `www.swisssign.com` returned 403 to this host for
  every request, so C1 could not run, and *"Promoting C3 to stand in for a blocked C1
  substitutes one channel *class* for another ... Left to **A56**."*

### 1.2 What a SwissSign token does at seal time

- **It is captured as a failure.** `crates/antseal-anchor/src/tsa.rs:499-506`: a token whose
  chain is not headline-eligible becomes `TsaFailure::Untrusted`, class `untrusted-chain`
  (`:215`). SwissSign's real token reaches `InternallyConsistentOnly` against the pinned store
  (`crates/antseal-core/src/anchor/chain.rs:1478`,
  `swisssign_rsa3072_leaf_without_basic_constraints_chains`, which asserts `Proven` against an
  injected store and `InternallyConsistentOnly` against the pinned one).
- **Alone, it aborts before payment — unless `--force-degraded`.** `evaluate_seal_gate`
  (`crates/antseal-anchor/src/submit.rs:252`) proceeds only at `MIN_VERIFIED_TSA_TOKENS`
  (`:292`, `1`), else proceeds degraded under `--force-degraded` (`:273`), else aborts. The gate
  runs before payment (`crates/antseal-cli/src/pipeline/resume.rs:476` against `:488`). With
  `--force-degraded` the seal is paid and carries **zero** TSA tokens: an untrusted token is
  never a capture, so nothing of it is stored.
- **Beside a pinned TSA, it marks every seal degraded.** `TsaCaptureStage::degradation_report`
  (`tsa.rs:333-348`) lists every failed attempt, `untrusted-chain` included;
  `AnchorSubmission::is_degraded` (`submit.rs:132-133`) is true when that report is non-empty;
  `pipeline/resume.rs:403` then calls `mark_degraded`.
- **At the abort, the reason is thrown away.** `crates/antseal-cli/src/pipeline/error.rs:273`
  maps `SealError::AnchorGate(_)` to a unit variant, and the user reads only
  `crates/antseal-cli/src/error.rs:678-681`: *"… re-run when a TSA is reachable, or pass
  --force-degraded …"*. D194 rules this.

### 1.3 What the surfaces say today

- **The page already says which count.** `docs/user/timestamp-authorities.md` §1 (`:28`, the
  rule: a token counts only when its chain validates against the root store compiled into
  antseal), the store table, §3's table (`:112`; SwissSign at `:124`, *"**NO — quarantined**
  ... count for nothing"*), and §3's four further endpoints (Apple *"**REFUSED.**"* at `:172`;
  GlobalSign and Certum verify and count zero; *"**None of the four is recommended today.**"*
  at `:189`). It understates the mixed case at `:190-191`.
- **Where a user configures says nothing about it.** `init` writes no `[anchors]` section; the
  configuring reference is `docs/config.md:72-77`, which says the gate *"aborts the seal before
  any payment rather than sealing without a timestamp"* and neither names the authorities that
  count nor points at the page.
- **That sentence is not linted.** `scripts/check-copy-style.py:136` classifies `config.md` as
  `ENG` (*"config-file reference; describes keys, makes no claim about a seal"*), a reason the
  quoted sentence already falsifies (the planning lane's instrument finding, for the ledger).
- **The runbook lists SwissSign plainly.** `docs/anchors/real-smoke-runbook.md:75`: *"|
  SwissSign | alternate | **~10 requests/day** | published |"* — no quarantine note, and P4's
  `grep -c -i` for Apple, GlobalSign, Certum or *"quarantin"* there returned 0.
- **The release-notes row is written, and narrower than the facts.**
  `docs/anchors/root-store-update.md:166-169`: *"**Quarantine disclosure.** Any documented TSA
  alternate whose root is quarantined is named in the release notes together with the
  consequence: configuring it produces a pre-payment seal abort, not a weaker bundle."* That
  consequence holds only when quarantined authorities are configured **alone** (§1.2).
- **`Q34` has no line-109 venue.** The verification matrix's basis is *"MVP-SPEC.md lines
  165–175 ... plus one declared extension: MVP-SPEC.md line 143"*
  (`docs/testing/verification-matrix.md:5-7`), so a line-109 flag needs its own home: this
  record plus a `Q34` Notes pointer.

### 1.4 What promotion would cost

- **`A56` first.** `tasks/A.md:898-909` admits two routes and only two: *"(a) execute D57's
  channel **C1** (the vendor's own URL) from a host SwissSign does not block"*, an outward
  fetch; or *"(b) carry an **amendment to D57** as a reviewed decision that lets a C3 archive
  snapshot of the C1 URL stand in for C1"* — the move A7 declined because the gated task would
  have rewritten its own admission rule.
- **Then a store event and a redeploy.** `A26`'s append (store v2, a test rename, a wasm
  build), and, because the hosted verifier compiles `antseal-core`, a consented Pages redeploy;
  otherwise the CLI and the page disagree about SwissSign tokens.
- **D57's price for any root** (`D57:77-79`): *"**each root is an organisation that can sign a
  false, earlier time.**"*
- **What it buys:** an alternate with a published ~10/day quota (`MVP-SPEC.md:109`). `A56`'s
  own Notes: *"SwissSign is capability, not a blocker"* (`tasks/A.md:909`).

## 2. RULING

### §2 R1 — The choice, stated: FLAG (`A136` Accept 1)

`MVP-SPEC.md:109` lists SwissSign as a documented alternate; store v1 quarantines its root
(D57 §5 and §6; `roots/PROVENANCE.md:258`). This record takes the **flag** arm. The spec is
frozen, so the divergence is recorded as a flag with a disposition, never as a spec edit, and
`A136`'s Accept 1 asks for exactly that: *"the choice is stated, not implied by which one
happened"*.

### §2 R2 — The disposition named for `Q34`; promotion refused with its price

**Accepted for this release as documented, configurable and never counting:**
- configuring **only** SwissSign aborts the seal before payment (exit 22);
- configuring it **beside a pinned TSA** marks **every** seal degraded;
- the release notes carry `docs/anchors/root-store-update.md` §6's *Quarantine disclosure*
  row;
- promotion stays `A56`'s — C1 from an unblocked host, or a D57 amendment — followed by an
  `A26` append to store v2 and a page redeploy.

**Promotion is refused**, priced: two outward acts (`A56`'s fetch or a reviewed amendment, and
a consented Pages dispatch), one store-version event, and one more organisation able to sign a
false, earlier time (D57), for an authority with a published quota of about ten requests a day.

### §2 R3 — The surfaces say which authorities count (`A136` Accept 2 and 3)

- **`docs/config.md`'s `[anchors]` comment** (written by `L-CFG` in its D188 edit of the same
  block) gains: *"only authorities whose root is compiled into antseal count toward the anchor
  gate: FreeTSA, DigiCert, zeitstempel.dfn.de and Sectigo (Entrust is Sectigo); SwissSign,
  GlobalSign and Certum return tokens that verify but never count, and Apple is refused — see
  docs/user/timestamp-authorities.md §1 and §3"*.
- **`docs/user/timestamp-authorities.md`**: §3 (around `:190-191`) says that adding an
  unpinned or quarantined authority beside a pinned one marks **every** seal degraded; §4
  (around `:248-251`) cross-references `docs/config.md`, so the two agree.
- **`docs/anchors/real-smoke-runbook.md:75`**: SwissSign becomes *"alternate — root
  quarantined, counts zero"*, plus one sentence that names Apple, GlobalSign and Certum and
  points at the page's §3.
- The store and the spec are untouched.

### §2 R4 — The orchestrator's acts

Strike `TODO.md:697`'s stale rustdoc clause (`A138` did that work on 2026-10-16); add a `Q34`
Notes line naming the flag and its disposition; tick `A136`.

## 3. Fault plants

This record's acts are documents only, and **no red plant is available for their content.**
P4 measured that no checker reads a *"which TSAs count"* sentence: `scripts/check-copy-style.py`
mentions none of TSA, pinned, SwissSign or root store in any rule (its one match, `:156`, is
unrelated), and `docs/config.md` and `docs/anchors/` are classified `ENG`, outside the product
scan. So the evidence for each new sentence is the sentence itself, **grepped back by text
into the row**, never a lint verdict.

**Green.**
- `scripts/check-copy-style.py` exits 0, read back from a file, after the page edit
  (`docs/user/` is a product scan root).
- `cargo test -p antseal-core --lib anchor::roots`:
  `pinned_store_is_exactly_four_roots_at_version_1` (`roots/mod.rs:360`) and
  `the_store_matches_the_provenance_record` (`:597`) stay green — the store did not move.

**The seal-time witness lives in D194.** `U97`'s test drives a stub TSA serving a real unpinned
token through an all-failing seal and asserts the endpoint is printed with `[untrusted-chain]`
and `internally-consistent-only`. That is the red-capable surface for "which TSAs count" at the
moment it bites.

## 4. What this record does NOT decide

- **Promotion itself.** It stays `A56`'s. Only the maintainer can run C1 from a host
  SwissSign does not block, and only the maintainer can consent to the Pages redeploy that a
  store-v2 append requires.
- **Whether the release-notes row is widened.** `root-store-update.md:166-169` states only the
  alone case (§1.3); §2 R2 names both consequences, and the release notes owe both, whichever
  text carries them. The row's wording is `Q31`'s to settle.
- **`config.md`'s copy-lint classification** (`ENG`, with a reason the file already
  falsifies): a ledger finding, not ruled here.
- **A capture-level SwissSign twin** in `crates/antseal-anchor/src/tsa/tests.rs`. Today only
  GlobalSign's real token is driven through `capture_one`
  (`a_verifying_token_that_reaches_no_pinned_root_is_not_a_capture`, `tsa/tests.rs:275`). A
  SwissSign twin needs its request nonce read from the token's own `TSTInfo`, which P4 did not
  establish. Optional, not ruled.
- **`MVP-SPEC.md`**, which is frozen and is not edited.

## 5. Edit list — per write scope, with the lane named before this record was written

### L-ANCHOR (round 1) — the page and the runbook

- `docs/user/timestamp-authorities.md` §3 (around `:190-191`) and §4 (around `:248-251`), per
  §2 R3. The same lane owns the whole page this round (D193 also edits §3 and §4; `L-ERR2`
  edits §5 and §6 in round 2, per D194).
- `docs/anchors/real-smoke-runbook.md:75` and the one added sentence.

### L-CFG (round 1) — `docs/config.md`

- §2 R3's sentence in the `[anchors]` comment, inside the same edit that adds D188's
  `ots_calendars` documentation (D188 §2 R8).

### RECORDS-B — an optional dated addendum on D57 §5 naming this disposition

### Orchestrator — `TODO.md`, `tasks/Q.md`, `docs/decisions/README.md`

- `TODO.md:697`: the stale clause struck; `A136` ticked.
- `tasks/Q.md`: a `Q34` Notes line naming the flag and its disposition (§2 R2).
- The index row and the register row.

### Not touched

`crates/antseal-core/src/anchor/roots/` (the store), `MVP-SPEC.md`.

## 6. As built — wave 38, lanes L-ANCHOR and L-CFG and the orchestrator (recorded in place before this record was first committed)

No code moved: the store and the spec are untouched. Every surface below was read back by grep. Neither
`docs/config.md` nor `docs/anchors/` is read by any copy or citation check (`docs/instrument-ledger.md`).

- **§2 R3, `docs/config.md` (L-CFG).** The `[anchors]` comment carries the ruled sentence verbatim,
  capitalised: *"Only authorities whose root is compiled into antseal count toward the anchor gate:
  FreeTSA, DigiCert, zeitstempel.dfn.de and Sectigo (Entrust is Sectigo); SwissSign, GlobalSign and
  Certum return tokens that verify but never count, and Apple is refused — see
  docs/user/timestamp-authorities.md §1 and §3."* The page's §1 and §3 exist. The store's four
  labels are `freetsa`, `digicert`, `dfn-verein` and `sectigo`.
- **§2 R3, the page (L-ANCHOR).**
  - §3's SwissSign paragraph says that beside a pinned authority it still counts for nothing and
    its failure marks every seal degraded.
  - The *"None of the four"* paragraph says that an unpinned or quarantined authority beside a
    pinned one fails as `untrusted-chain` on every run, so every seal is recorded degraded
    (`submit.rs:128-136`, `is_degraded`), and that with no pinned authority the seal aborts before
    payment (§5).
  - §4 names which authorities count and points at `docs/config.md`'s `[anchors]` section. The two
    surfaces state the same three lists.
- **§2 R3, the runbook (L-ANCHOR).** `real-smoke-runbook.md:75` reads *"alternate — root
  **quarantined**, counts zero"*. A new sentence after `:86`, keeping lines 1–86 still because
  the threat model cites them, names Apple, GlobalSign and Certum and points at the page's §3.
- **The release-note row (L-ANCHOR, at the orchestrator's request).** `root-store-update.md:166-169`
  now states both consequences in the same four lines: alone, the seal aborts before payment;
  beside a pinned authority, the token counts zero and every seal is degraded. The file stays 184
  lines, so this record's citation holds.
- **§2 R4 (the orchestrator).**
  - `TODO.md`'s A136 clause is struck with its date (`A138` made that fix on 2026-10-16).
  - `Q34` gains a Notes line naming the flag and its disposition.
  - `A136` is ticked.

## Closing — this record is not consent

It changes documents in the tree. Nothing in it authorises a push, a dispatch, a deploy, a
network fetch or any other outward act; the promotion it refuses would need two of them, each
with its own consent.
