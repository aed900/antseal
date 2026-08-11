# D93 — Online-refutation precedence, and the M2 anchor tamper matrix A21 must build

- **Status: RESOLVED — the registry is right, the code is wrong, and D56 is
  wrong in the one place the code copied faithfully.** `MATRIX.json` row
  `anchor-forged-header` keeps `"outcome_kind": "verdict", "expected":
  "invalid"`; nothing in the M2 half of the registry changes except one `why`
  string and the BER cell Q75 owns. What must change is **D56 §5's rule
  order**: it puts **O4 above O6 and O7**, which makes both online refutations
  unreachable on exactly the artifacts they were written for. A forged header
  the ops commit renders `attested` no matter what the agreed endpoints
  return, and an `.ots` claiming a height beyond the chain tip renders
  `attested` for ever — **the defect D56 §3 states in those words as the
  reason O7 exists**. `evaluate_ots_artifact` implements D56 §5 exactly, so it
  inherits the defect; A18's own suite records the O6 half as intended
  behaviour and its O7 test exercises a corner where the rule cannot be seen.
  The fix is one guard: **O4 fires only when no agreed online evidence refutes
  the recorded height**. O5 stays above O6/O7, so D56 §4's anti-downgrade
  ruling is untouched, and the A21 single-branch trap stays real and becomes
  doubly load-bearing. Zero frozen report bytes change, zero error codes are
  minted, and **no non-null `expected` cell moves** — the only `expected` edit
  in the whole M2 half is the BER null Q75 fills.**
- **Date: 2026-08-06** (M2 wave-5 planning round; blocks **A21**, and **A80**
  must land before it)
- **Owning tasks: A80** (the precedence fix and its two anti-vacuity twins),
  **A21** (the eight rows), **Q75** (the BER cell), **A82** (the `.ots` builder
  A21 cannot reach), **A81/Q92** (the O7 project-added row), **A83** (the
  wrong-corner audit). Amends **D56 §5, §9, §1** and **D53 §8**.

---

## 1. What the brief claimed, and what the tree says

Every premise was checked against the tree before anything was built on it.
Three of the brief's load-bearing claims are false, and one of the false ones
is the whole question.

| Brief's claim | Verdict | Measured where |
| --- | --- | --- |
| The eight cases "live under **five** family entries" | **False — six.** | `tamper_completeness/mod.rs:131` pins `EXPECTED_M2_FAMILIES = 6`; the six are `anchor-token-for-a-different-digest`, `untrusted-tsa-root`, `forged-bitcoin-header`, `attested-ots-withheld-from-headline`, `tsa-chain-expiry`, `ber-where-der-required`. Two are compound (cases 2 + 2), giving `EXPECTED_M2_CASES = 8` at `:149` |
| "D56 rule O6 is narrower than D56 states — O4 precedes it, so a self-consistent forgery refuted online is `attested`" | **True**, and pinned by a committed test | `verdicts.rs:680-692` (O4's guard does not read `agreed`); `verdicts/tests.rs:661` `a_self_consistent_forgery_refuted_online_is_attested_with_the_refutation_recorded` |
| "So the specified row appears unsatisfiable as written" | **False.** The row is satisfiable today — via an **uncommitted** forgery plus online evidence, which reaches O6 at `verdicts.rs:709-720`. It is not *unbuildable*; it is **vacuous**, because that same fixture renders `invalid` offline through O8 and the row can never see the online gate | `verdicts/tests.rs:681-697` builds exactly that shape and gets `invalid` |
| "the matrix's distinctness argument (invalid claimed exactly once) depends on it" | **False.** D53 §8's argument runs the other way: *because* rows 2, 6 and 8 also render `Invalid`, at most one row may pin the bare state, so the others mint codes. "Claimed exactly once" is the consequence, not the premise | `D53-chain-invalid-at-gentime.md:553-559` |
| "D56 §9's `nTime` row is unsatisfiable" | **True**, and already corrected in the tree | `D56-…:515-525`; `verdicts/tests.rs:576-638` |
| A21's single-branch trap (O5 fires first on a merged base) | **True** | `D56-…:252-258`; O5 at `verdicts.rs:700-706` |
| Q75 is still valid | **Half.** The `expected` value is right; "drop the pending block" is **wrong** and would turn the registry red | §10 below |

The one the brief got backwards is the third row, and reversing it changes the
ruling: the question is not *"can this row be built?"* but *"can this row ever
report red?"*

---

## 2. What the shipped code produces for each of the eight cases

All eight expected outcomes exist in the tree today. Nothing in this column is
inferred from prose.

| # | `row_id` | Registry `expected` | Shipped code, correct fixture | Registry cell |
| --- | --- | --- | --- | --- |
| 1 | `anchor-ots-digest-mismatch` | `error:anchor-ots-digest-mismatch` | `Invalid` + that code (O1/O2 inside `parse_ots`; `ots/error.rs:260`) | **right** |
| 2 | `anchor-tsa-imprint-mismatch` | `error:anchor-tsa-imprint-mismatch` | `Invalid` + that code (T2 in `verify_token`, `verdicts.rs:868-882`; `error.rs:447`) | **right** |
| 3 | `anchor-untrusted-root` | `verdict:internally-consistent-only` | `InternallyConsistentOnly` (C6 fallthrough, `verdicts.rs:959-966`) | **right** |
| 4 | `anchor-forged-header` | `verdict:invalid` | **`Attested`** for the forgery that matters; `Invalid` only for a forgery already refutable offline | **right — the code is wrong** |
| 5 | `anchor-attested-not-headline` | `verdict:attested` | `Attested` (O4, `verdicts.rs:680-692`) | **right** |
| 6 | `anchor-expired-at-gentime` | `error:anchor-cert-not-valid-at-gentime` | `Invalid` + that code (C3; `chain.rs:168`) | **right** |
| 7 | `anchor-expired-after-gentime` | `verdict:valid-at-stamping-cert-since-expired` | that state (`verdicts.rs:934-941`) | **right** |
| 8 | `anchor-ber-not-der` | `null` | `Invalid` + `anchor-der-not-strict` (`error.rs:417`) | **stale — Q75, §10** |

Seven of eight cells are correct and buildable as written. **One cell is
correct and unbuildable-as-intended**, and the reason is in the code.

---

## 3. The decisive finding: O4 above O6/O7 kills both online refutations

`evaluate_ots_artifact` returns at O4 on `upgrade.is_some() && committed`,
and `agreed` appears nowhere in that guard (`verdicts.rs:680-692`). The
refutation block at `:709-720` is reached only after O3, O4 and O5 have all
fallen through. Therefore:

> **O6 and O7 can only ever produce a verdict when `committed` is false** —
> that is, when the artifact is *already* refuted offline by O8.

Two consequences, and the second is not a matter of taste.

**(a) The online gate cannot refute the forgery it exists to catch.** Line 108
spends a paragraph on why a lone embedded header proves nothing: *"an attacker
picks its own `nBits`, so a minimal-difficulty forged header mines in
seconds"*. Forging a header the ops commit needs no mining at all — the
attacker chooses the ops, reads the root they derive, and writes it into bytes
36..68 of 80 bytes of its choosing. That artifact is `committed`. Under the
shipped order it renders `attested` whether the agreed endpoints return the
real block H, a different block, or nothing at all. The *sloppy* forgery — one
whose merkle-root field the ops do not derive — is the only one O6 ever sees,
and O8 already convicts it offline. The online gate refutes nothing it did not
already have.

**(b) O7 reinstates, verbatim, the defect D56 §3 says it prevents.** D56 §3:

> *"two endpoints agreeing that height H does not exist is agreed evidence
> refuting the artifact's claim, and it must be `Invalid` (rule O7) … .
> Collapsing it into 'no evidence' would let an `.ots` claiming a block beyond
> the chain tip render `attested` for ever."*

Under the shipped order an `.ots` claiming height 99 999 999, with a
self-consistent embedded header, renders **`attested` for ever**. `NoSuchBlock`
is not collapsed into "no evidence" — it is simply never reached. The rule was
written, minted a code, and cannot fire.

**The test that should have caught (b) cannot.** `verdicts/tests.rs:736`
`agreed_absence_of_the_block_is_invalid` carries the doc comment *"What makes
it fail: collapsing `NoSuchBlock` into 'no entry'. An `.ots` claiming a height
beyond the chain tip would then render `attested` for ever."* Its fixture is
`container(&synthetic_digest(0x21), &fork(&[bitcoin(449399), bitcoin(449400)]))`
with zero ops, so every branch commitment is `[0x21; 32]` while
`committing_upgrade()`'s header carries the real derived root `1a1da267…`
(`upgraded/PROVENANCE.md`). `committed` is **false**, so the test exercises
O7 in the one corner where O7 is not the rule under test — O8 would have
convicted the same bytes. This is the wave's own dominant finding recurring:
**an instrument that names its defect in prose and cannot see it.**

---

## 4. Which is wrong — code, registry, or D56

All three were live. The evidence is one-sided.

**D56 §5's rule order is wrong, and the code is a faithful copy of it.**

Against the shipped order stand five independent statements, four of them
inside D56 itself:

1. **MVP-SPEC.md:108** — *"A header that fails the online match … is the
   `forged Bitcoin attestation/header` tamper case (`invalid`)"*.
2. **MVP-SPEC.md:168** — *"**forged Bitcoin header that fails the `--online`
   block match** (→ `invalid`)"*.
3. **D56 §1** ruled, at length and on four grounds, that 108/168 **win** over
   line 133 on this exact input. The shipped order makes that ruling
   inoperative for the input it was about.
4. **D56 §5's own summary table**, row *"upgraded with header, `--online`
   mismatch → `Invalid` (`anchor-ots-online-header-mismatch`), rule O6"*.
   *"Upgraded with header"* is `committed` — which is precisely the case the
   listed order sends to O4. **The rule list and the table contradict each
   other**, and the table agrees with the spec.
5. **D56 §3**, quoted in §3(b) above, and **A18's own Accept row 2** in
   `tasks/A.md`: *"matching online evidence promotes to `proven` with the
   block-header timestamp; **mismatch → `invalid`**"*. That clause was
   discharged by the uncommitted corner and is vacuous as it stands.

For the shipped order, exactly one argument was ever offered: D56 §4's
**best-evidence-wins**. It does not reach here, for two reasons:

- **§4 is a per-branch rule.** Its subject is *"a refuted branch never demotes
  a confirmed or pending one"*, and its threat is a relay appending a branch to
  an **unsigned** bundle. The embedded header is not a branch: the D79 upgrade
  group is **singular** (`registry-v1.md` §7.8, and D56 §5 relies on that
  singularity to key `online` by `u.block_height()`). There is nothing to
  out-vote.
- **The anti-downgrade argument is already conceded on this field.** A relay
  that *replaces* the embedded header of an honest, fully-upgraded,
  no-pending-branches `.ots` gets `invalid` today, offline, via O8 — no online
  evidence needed. O4-above-O6 buys no censorship resistance that O8 does not
  already give away. What §4 genuinely protects is the *pending* case, and
  that protection lives in **O5**, which this decision does not move.

The remaining argument for the shipped order is the reorg case: an honest
sealer's block H is orphaned, the fetch returns the new H, and `invalid` reads
as an accusation. It is real and it is the price. It is also the price D53's
partition principle already sets — *`invalid` iff the artifact makes a claim
the verifier can refute from material it already trusts* — the OTS attestation
itself is void after a reorg, the honest recovery is `status --upgrade`, and
the alternative is a verifier that has been handed a refutation and reports a
clean `attested`. Recorded in §12 with a revisit trigger.

**Ruling: the registry cell stands, D56 §5's order is amended, and A80 changes
the code.**

---

## 5. The amended rule order

The three precedences the tree needs cannot be written as one linear
first-match list — O4 must beat O5 (the partially-upgraded merge is `attested`),
O5 must beat O6/O7 (a pending branch is not demoted), and O6/O7 must beat O4.
That is a cycle, which is why D56 §5 broke it in the wrong place. It is broken
correctly by **conditioning O4**, not by reordering:

```text
let refuted_online = match agreed {                    // O6/O7 only. NOT O8.
    Some(Header(h)) => h != *u.block_header(),
    Some(NoSuchBlock) => true,
    None => false,
};

O3.  upgrade && committed
       && agreed == Some(Header(h)) && h == embedded  ->  Proven   [H]
                                                          time = nTime(h)

O4.  upgrade && committed && !refuted_online          ->  Attested
                                                          time = None

O5.  !pending.is_empty()                              ->  Pending

O6.  upgrade && agreed == Some(Header(h))
       && h != embedded                               ->  Invalid
                                                          "anchor-ots-online-header-mismatch"
O7.  upgrade && agreed == Some(NoSuchBlock)           ->  Invalid
                                                          "anchor-ots-online-block-absent"
O8.  upgrade && !committed                            ->  Invalid
                                                          "anchor-ots-header-uncommitted"
O9.  otherwise                                        ->  InternallyConsistentOnly
```

O0, O1 and O2 are unchanged. `refutation` is already computed once at
`verdicts.rs:625`; O4's new guard is the same value, so the change is one
condition and no new traversal.

**Every behaviour the amended order changes**, exhaustively — nothing else in
the machine moves, because `refuted_online` is false whenever `agreed` is
`None`, which is every offline evaluation:

| Artifact | Before | After | Right? |
| --- | --- | --- | --- |
| committed, online header differs, **no** pending branch | `Attested` | **`Invalid`** (`…online-header-mismatch`) | spec 108/168, D56 §5 table |
| committed, `NoSuchBlock`, **no** pending branch | `Attested` | **`Invalid`** (`…online-block-absent`) | D56 §3, verbatim |
| committed, online refuted, **with** a pending branch | `Attested` | **`Pending`** | best-evidence-wins: the pending branch is the strongest unrefuted claim; §4's anti-downgrade property is preserved exactly |
| committed, online agrees | `Proven` | `Proven` | unchanged |
| committed, no online evidence | `Attested` | `Attested` | D56 §3's network-weather rule, unchanged |
| everything with `!committed` | as before | as before | O5/O6/O7/O8/O9 untouched |

**A39 consequence, stated so it is not discovered as a surprise:** under the
amendment O4 can no longer carry a suppressed O6/O7 anomaly (its guard
excludes them) and cannot carry an O8 one (`committed` contradicts it), so
O4's `suppressed` list is **always empty**. A39's Accept rows are unaffected:
its OTS row is *"a merged `.ots` with one pending branch and one forged
Bitcoin branch renders `pending` and carries one suppressed entry"*, which is
O5 over O6/O8 and still fires. The change removes the only case where a
*genuine online refutation* was recorded-and-ignored rather than acted on.

> **Corrected 2026-08-06 by the implementing lane (A80), which ran it.**
> §7 below says to invert `a_self_consistent_forgery_refuted_online_is_attested…`,
> and that reads as though the artifact moves to `Invalid`. **It does not.**
> Its fixture is the real `LARGE_TEST` capture, which carries evaluable
> **pending** branches, so under the amended order it lands on the *third* row
> of the table above — `committed, online refuted, with a pending branch →
> Pending` — not the first. §5's table is right; §7's phrasing is misleading
> about which cell it reaches. The claims were therefore split: a new
> single-branch fixture carries the `Invalid` claim, and the real capture
> carries the `Pending` claim. Measured: applying the guard alone, before any
> test was touched, turned **exactly one** committed test red (`left: Pending,
> right: Attested`) and left all eight "must stay green" rows green.

**Committed tests that must change** (measured by reading; not run — see §11):

- `verdicts/tests.rs:661`
  `a_self_consistent_forgery_refuted_online_is_attested_with_the_refutation_recorded`
  — **inverted and renamed**. It is the test that pins the defect, and its doc
  comment is where the wrong reading was written down.
- `verdicts/tests.rs:736` `agreed_absence_of_the_block_is_invalid` — **gains
  the committed twin**; keep the existing `!committed` case as the O7-over-O8
  ordering assertion.

**Committed tests that must stay green, and are the regression proof:**
`an_upgraded_ots_is_attested_offline_and_carries_no_time` (:538),
`matching_online_evidence_promotes_attested_to_proven` (:553),
`the_proven_time_is_read_from_the_agreed_header` (:598 — asserts only
`state != Proven` and `time == None`, both of which survive),
`online_evidence_that_does_not_commit_the_ops_root_does_not_promote` (:709),
`an_upgrade_group_over_a_pending_only_ots_is_pending_not_invalid` (:776),
`a_pending_branch_is_not_demoted_by_a_forged_bitcoin_branch` (:888),
`a_partially_upgraded_merge_is_attested_not_pending` (:920),
`absent_online_evidence_leaves_the_state_at_attested` (:818).

---

## 6. `verdict:invalid`, and D53's C3/C4/C5 rationale

Row 4 keeps `verdict:invalid`, so the key is still claimed exactly once and
nothing in D53 §8 moves. Recorded anyway, because the brief asked and the
answer is not the one the registry's `why` implies:

**If row 4 had moved to an error key, C3/C4/C5's rationale would have been
strengthened, not broken.** D53 §8's argument is that rows 2, 6 and 8 all
*render* `Invalid`, so at most one row may pin the bare state and the rest
must mint codes. Zero rows pinning it satisfies that constraint a fortiori,
and the checker enforces **distinctness, not coverage**
(`tamper_completeness/mod.rs:906` `check_pending_cross_distinctness` compares
claimed keys; an unclaimed key is not a failure). The reason to keep
`verdict:invalid` is different and simpler: line 168 states the outcome as the
state, the matrix maps line 168 1:1, and the cell was never wrong — only the
fixture and the code were.

The cost of keeping it is that `verdict:invalid` does not distinguish O6 from
O8, so a lane that builds the wrong fixture gets a green row. §9 closes that
inside the row itself rather than by changing the key.

---

## 7. The `MATRIX.json` edits this decision authorises

Two, and only two. **No `expected` value changes.**

**7.1 — row `anchor-forged-header`, `why` only.** The current text asserts a
distinctness property as the row's *reason*, and states rule O6 without the
precondition that makes O6 reachable. Replace the `pending` block of
`families[] → forged-bitcoin-header → cases[0]`:

```json
          "pending": {
            "task": "A21",
            "row_id": "anchor-forged-header",
            "outcome_kind": "verdict",
            "expected": "invalid",
            "why": "D56 rule O6 as amended by D93; spec-stated outcome (MVP-SPEC.md line 168, -> `invalid`). `verdict:invalid` is claimed exactly ONCE across the eight M2 cases, by this row, which is why rows 2, 6 and 8 pin codes instead (D53 section 8). FIXTURE IS LOAD-BEARING (D93 section 9 row 4): the `.ots` must be SINGLE-BRANCH, because a pending sibling makes rule O5 fire first and the row renders `pending` (D56 section 4); and its ops must COMMIT the embedded header, because the uncommitted forgery is already `invalid` offline through O8 and a row built that way passes without the online gate ever running. The mutation is the embedded header's `nTime`, the merkle-root field untouched. D93 section 3 measured that the committed shape rendered `attested` before A80 lifted the online refutations above O4."
          }
```

**7.2 — row `anchor-ber-not-der`, Q75's cell.** See §10.

Nothing else in the M2 half is touched. In particular **the compound families
stay compound and the counts stay 6/8**, so `EXPECTED_M2_FAMILIES` and
`EXPECTED_M2_CASES` do not move.

---

## 8. D56 §9's `nTime` row — retired, replaced, and now recorded as an amendment

The brief's second known conflict is real and the tree already handles it
correctly; what is missing is the record, and this project amends the decision
rather than leaving the correction in a task report.

D56 §9 asks for `the_proven_time_is_the_online_headers_ntime_not_the_embedded_ones`
over *"a fixture whose two headers differ in `nTime` alone while both commit
the ops root"*. O3's guard is `h == *u.block_header()` — a byte equality over
all 80 bytes — so such a fixture never reaches `Proven`, and whenever O3 does
fire the two headers are identical and `nTime` read from either is the same
integer. A18 recorded this inline at `D56-…:515-525` and shipped
`the_proven_time_is_read_from_the_agreed_header` (`verdicts/tests.rs:598`),
which pins the two claims that *are* observable: the guard is a whole-header
equality (an implementation comparing only merkle roots promotes a header
differing in `nTime` and goes red), and the promoted time is that header's
`nTime`.

**Ruling: retire-and-replace, which is what happened; D56 gains a formal
amendment (§13 below) so the correction is reachable from the top of the
document and not only from the middle of §9.** Two things the inline
correction does not say and the amendment must:

1. **O3's whole-header equality is a ruling, not an accident.** It could have
   been a merkle-root comparison; that is the natural way to "fix" the
   untestable rule and it is a real promotion hole (a header agreeing on the
   root but not on `nTime` is not block H). D56 §5 should state the equality
   is deliberate — which is what makes the `nTime` rule moot rather than
   unenforced.
2. **Under the amended order the rule acquires a second observable
   consequence.** A header differing in `nTime` alone now renders `Invalid`
   (O6) rather than `Attested`, on a single-branch artifact — which is exactly
   A21's row 4, so **row 4 is the reachable form of the test D56 §9 could not
   write.** A weakened O3 makes row 4 render `proven` and the row goes red.

---

## 9. A21's row-by-row brief

Eight rows, six families. For each: the base, the single mutation, the surface
call, the expected outcome, and **the planted fault that proves the row can
report red** — the last is not optional, per the wave's seven-blind-instruments
finding.

Two structural prerequisites before any row is written:

- **A80 lands first.** Row 4 cannot be built to specification against the
  current machine.
- **A82 lands first.** The synthetic `.ots` writer rows 4 and 5 need
  (`container`/`fork`/`bitcoin`/`pending`/`unknown`/`varuint`, `header_with`,
  `derived_root`) lives in `crates/antseal-core/src/anchor/verdicts/tests.rs`
  under `#[cfg(test)]`, invisible to both `test_util` (not `cfg(test)`) and
  `crates/antseal-core/tests/` (a separate crate). It must be promoted to
  `anchor::testing`, beside `MockTsa`.

| # | Row | Base | Mutation | Surface → outcome |
| --- | --- | --- | --- | --- |
| 1 | `anchor-ots-digest-mismatch` | real merged pending `.ots` `testdata/anchors/A25-bootstrap/merged-A.ots` with `digest-A.bin` | verify it against **`digest-B.bin`** — the other committed golden digest; no byte is patched | `evaluate_ots_artifact(view, &DIGEST_B, &BlockEvidence::new())` → `Invalid`, diagnostic `anchor-ots-digest-mismatch` → `ErrorCode` |
| 2 | `anchor-tsa-imprint-mismatch` | real `D60-tsa-freetsa-resp.tsr` (stamped over `D60_STAMPED`) | verify against a different `anchor_digest`, **with an empty root store** | `evaluate_tsa_artifact(view, &other, &empty_store(), AFTER_CAPTURE)` → `Invalid`, `anchor-tsa-imprint-mismatch` |
| 3 | `anchor-untrusted-root` | `MockTsa::granted()` token (`anchor::testing`), CA cert in the bag | evaluate against `empty_store()` instead of `mock.root_store()` | → `InternallyConsistentOnly` |
| 4 | `anchor-forged-header` | **single-branch** upgraded `.ots`: `container(&d, &bitcoin(H))` with `d` also the header's merkle root, so the ops commit it; `OtsUpgrade::new(H, header_with(&d, T), fetch)`; agreed evidence = that same header. This base renders **`proven`** | the **embedded** header's `nTime` becomes `T + 3600`; bytes 36..68 untouched, so the ops still commit it; the agreed header is unchanged | `evaluate_ots_artifact(view, &d, evidence)` → `Invalid`, diagnostic `anchor-ots-online-header-mismatch` → `VerdictState("invalid")` |
| 5 | `anchor-attested-not-headline` | real `upgraded/rust-opentimestamps-LARGE_TEST.ots` + `committing_upgrade()` | the online evidence is **withheld** (the artifact is honest — this is the positive control) | `evaluate_ots_artifact(view, &DIGEST_UPGRADED, &BlockEvidence::new())` → `Attested`, and `VerdictState("attested")` **only if `!is_headline_eligible()`** |
| 6 | `anchor-expired-at-gentime` | `MockTsa` with `signer_validity: (G-200_000, G-100_000)`, `gen_time_unix: G` | — (the window itself is the case) | `evaluate_tsa_artifact(…, mock.root_store(), G-150_000)` → `Invalid`, `anchor-cert-not-valid-at-gentime` |
| 7 | `anchor-expired-after-gentime` | the same mock with `signer_validity: (G-100_000, G+100_000)` | verified at `G + 200_000` | → `ValidAtStampingCertSinceExpired` |
| 8 | `anchor-ber-not-der` | real `D60-tsa-freetsa-resp.tsr` | substitute the committed BER twin `D60-ber-indefinite-freetsa.tsr` | `evaluate_tsa_artifact(…)` → `Invalid`, `anchor-der-not-strict` |

**Planted faults — one per row, each must turn that row red:**

1. **Row 1** — make `parse_ots` ignore its `anchor_digest` argument (D58 §10.3
   step 5). The row renders `pending` (the base has three live calendars) and
   goes red. Second fault, cheaper to plant: point the row at `digest-A.bin`;
   the mutation vanishes and the row renders `pending`.
2. **Row 2** — swap T2 and T3 (`verify_token` after `validate_token_chain`).
   With the **empty** store the row then renders `internally-consistent-only`
   and goes red. *This is why the empty store is mandatory:* against a pinned
   store both orders give the same answer and the row would be blind to
   D53's T2-before-T3 ruling, which is the only thing it exists to pin.
3. **Row 3** — treat a token-supplied self-signed certificate as a trust
   anchor (D57 P2); the row renders `proven`. **Positive twin required**
   (A21 Accept; D57 §8 item 4): at row level, the same mock token against
   `mock.root_store()` must render `proven`, which catches the opposite fault
   — rejecting any chain containing a self-signed certificate — and neither
   direction passes vacuously because both run over one artifact. D57's twin
   over the **real** FreeTSA/DFN/SwissSign tokens (each shipping its own
   self-signed root and still reaching `proven`) is **A43's**, not a ninth
   matrix row; A21 cites it rather than rebuilding it.
4. **Row 4** — three faults, all of which must redden it. **(i) Restore D56
   §5's shipped order** (O4 above O6): renders `attested`. This is the fault
   the row exists for. **(ii) Drop the online evidence** from the exercise:
   renders `attested` — proves the online gate is threaded and not decoration.
   **(iii) Weaken O3's guard to a merkle-root comparison**: renders `proven`,
   which is the promotion hole D56 §9's retired `nTime` row was reaching for.
   Additionally the row carries its own **vacuity latch**: the exercise
   evaluates the artifact *offline* first and returns
   `ActualOutcome::VerdictState("attested-offline-precondition-failed")`
   unless that evaluation is `Attested`, so a lane that rebuilds the row with
   the uncommitted forgery — the shape that satisfies it today — gets a red
   row naming the reason instead of a green one.
5. **Row 5** — promote on the embedded header alone (drop O3's online
   conjunct): renders `proven`, red. Note honestly: **adding `Attested` to
   `headline_eligible` does not move the state**, so a plain
   `VerdictState(state_name)` row is blind to the rule the row is named after.
   That is why the exercise must return `VerdictState("attested")` only when
   `!is_headline_eligible()` and a distinguishable string otherwise —
   `verdict:attested` stays the registry key and the instrument gains the
   eye it was missing. The crate-level guard
   `exactly_the_two_spec_h_states_are_headline_eligible` stays as the
   independent second surface.
6. **Row 6** — validate the chain at `verify_at` instead of at `genTime` (the
   whole of D53 C3). Because `verify_at = G-150_000` sits **inside** the
   signer window, the row then renders `proven` and goes red. A `verify_at`
   chosen outside the window would make the row blind to the ruling.
7. **Row 7** — the same fault in the other direction: validating at
   `verify_at = G+200_000` renders `Invalid` with
   `anchor-cert-not-valid-at-gentime`, red. Rows 6 and 7 are one differential
   over one mock — same signer, two windows — which is what makes "expired ≠
   invalid" a measured claim rather than two independent green rows.
8. **Row 8** — parse with `from_ber` instead of the strict-DER pin: the token
   verifies and the row renders `proven` or `internally-consistent-only`, red.
   The fixture is **proven to be valid BER** (`from_ber` accepts it, Q75's
   evidence), so the row cannot pass by the artifact merely being malformed.
   **One BER row only**: all four rejecting fixtures produce the same code, so
   the other three stay named tests in `tests/der_pin_eval.rs`, and
   `D60-ber-unsorted-setof-freetsa.tsr` is **not** a candidate at all —
   `der_pin_setof_ordering_is_canonicalised_not_rejected` records that SET-OF
   ordering is canonicalised rather than refused.

**Cross-row obligations.** All eight rows run native **and**
`wasm32-unknown-unknown` (A21 Accept; every fixture arrives by
`include_bytes!` or is minted in-process, so none needs a filesystem). No row
returns `ActualOutcome::Accepted` — D56 §8 is explicit that row 5's positive
shape returns `VerdictState`, because `Accepted` is *"always a failure"* by
the harness's own doc comment.

---

## 10. Q75 — valid in substance, wrong in two of its three instructions

**Still valid:** `anchor-der-not-strict` exists (`anchor/error.rs:417`),
`tests/der_pin_eval.rs::der_pin_rejects_indefinite_length` and
`::der_pin_rejects_nonminimal_length` drive it over the four committed BER
fixtures, and two of those are proven to be valid BER by `from_ber` accepting
them. The `expected` value Q75 names is right.

**Wrong, and it would turn the `tamper-matrix` lane red:**

1. *"drop the pending block"* — the case would then have none of `rows`,
   `pending` or `non_row`, which the checker refuses outright with *"A spec
   case is never silently absent"* (`tamper_completeness/mod.rs:551-556`); and
   giving it a `rows` array instead is worse, because `check_case_rows` is
   handed `live_ids` (`:563-570`) and **A21 has not built the row yet** — the
   same rule the `project_added` check states in words at `:624-628`, *"a row
   that does not EXIST is a `pending` case instead"*. **The pending block
   stays; only `expected` and `why` change.**
2. Q75 does not mention `EXPECTED_M2_UNMINTED`
   (`tamper_completeness/mod.rs:187-193`). Its assertion reads the list in
   **both** directions — *"a case whose code has since been minted must be
   removed here in the same commit"* (`:1152-1158`). Filling the cell without
   emptying the list is a red lane.

**Exact change, both files, one commit.** `MATRIX.json`,
`families[] → ber-where-der-required → cases[0].pending`:

```json
          "pending": {
            "task": "A21",
            "row_id": "anchor-ber-not-der",
            "outcome_kind": "error",
            "expected": "anchor-der-not-strict",
            "why": "D53 section 8 row 8; the code is A5's, named by D60 section 7.3 and minted at `anchor/error.rs`. Filled at Q75 (ruled by D93 section 10): the last null in the M2 half, so `EXPECTED_M2_UNMINTED` empties in the same commit and layer 3 now compares all eight M2 outcome keys. The row's fixture is ONE of the four rejecting BER captures (`D60-ber-indefinite-freetsa.tsr`); the other three produce the same code and stay named tests in `tests/der_pin_eval.rs`, and `D60-ber-unsorted-setof-freetsa.tsr` is not a candidate because SET-OF ordering is canonicalised rather than refused. Strict-DER limits and their fuzz targets are A5/A23/Q17."
          }
```

and in `crates/antseal-core/tests/tamper_completeness/mod.rs`:

```rust
const EXPECTED_M2_UNMINTED: &[(&str, &str)] = &[];
```

with its doc comment updated — the mechanism stays, the list empties, and the
comment's own rule (*"The list must never silently empty"*) is honoured by
this being a recorded edit rather than a deletion.

**Measured consequence, and it is the point of Q75:** with the last null gone,
layer 3 compares **eight** M2 outcome keys instead of seven, and the
`assert_m2_anchor_set_is_armed` print names all eight. Q76's arming argument
is only fully discharged here.

---

## 11. Measured vs. assumed

**Measured** — read from the tree at `323adb8`, file and line cited above:
O4's guard and its position ahead of the refutation block; the refutation
helper's O6→O7→O8 order; the committed test that pins `attested` for a
self-consistent forgery refuted online; the `!committed` fixture inside
`agreed_absence_of_the_block_is_invalid`; six families / eight cases and both
checker constants; the one `EXPECTED_M2_UNMINTED` entry and its two-direction
assertion; the existence of all eight expected codes and states; the checker's
refusal of a case with no `rows`/`pending`/`non_row` and of a `rows` entry
naming a row that does not exist; `ActualOutcome::ErrorCode` being
constructible by any exercise function, not only from a `Result`; the SET-OF
fixture being canonicalised rather than rejected; the `#[cfg(test)]` scope of
the `.ots` builder.

**Assumed, and flagged as such:** that A80's one-line guard compiles and that
the eight tests listed in §5 as "must stay green" do. **No `cargo` command was
run** — the machine is 2 cores with a second planner running, and the ruling
does not rest on a build. The blast radius in §5 is derived by reading each
test's fixture against the amended predicate; A80's lane must confirm it, and
if any test in the "must stay green" list moves, that is a finding about this
decision, not a fixture to adjust.

---

## 12. Residual risks and revisit triggers

- **A reorg now renders `invalid`** where it rendered `attested` (§4). The
  bound is narrow — it needs a single-branch, fully-upgraded, no-pending
  `.ots` plus an `--online` run against a reorged height — and the honest
  recovery is `status --upgrade`. Trigger: any report of a false `invalid`
  from a live bundle, or any change to A14's re-upgrade policy.
- **`invalid` reaches the page with no reason.** D56 §6 forbids the four
  `anchor-ots-*` codes from entering `VerificationReport`, and report v1 is
  frozen. Before this decision an online refutation was an invisible A39
  anomaly on an `attested` anchor; after it, it is a visible `invalid` whose
  diagnostic the page still cannot render. That is strictly better and still
  incomplete. **R61** owns the CLI/page asymmetry. Trigger: any
  `report_version` bump — carry the diagnostic with it.
- **Row 4's vacuity latch is bespoke.** It is the only row in the matrix that
  checks its own precondition. If a second row needs one, promote the pattern
  into the harness rather than copying it. Trigger: a second row with a
  fixture-shape precondition.
- **O7 still has no matrix row** (§13's A81/Q92). Until it does, the rule's
  only instrument is a unit test — the same posture that produced the blind
  test §3 found.

---

## 13. Amendments and corrections (orchestrator applies at source)

1. **`docs/decisions/D56-ots-internally-consistent-trigger.md` §5 — the rule
   order.** Replace the O3–O9 block with §5 of this document, and add above
   it: *"**Amended 2026-08-06 by [D93](D93-online-refutation-precedence.md)
   §4/§5.** As first written this list placed O4 above O6 and O7, which made
   both online refutations unreachable whenever the ops commit the embedded
   header — the case they were written for. §3's stated defect (*'an `.ots`
   claiming a block beyond the chain tip would render `attested` for ever'*)
   was live, and §5's own summary table row (*'upgraded with header,
   `--online` mismatch → Invalid, O6'*) contradicted the list. O4 now carries
   a guard rather than a position; O5 keeps its precedence over O6/O7, so §4's
   best-evidence ruling is unchanged."*
2. **D56 §5 — O3's guard.** Add: *"the byte equality over all 80 bytes is
   deliberate, not incidental: a merkle-root comparison would promote a header
   agreeing on the root and disagreeing on `nTime`, which is not block H. It
   is also what makes the `nTime` rule below unobservable (§9)."*
3. **D56 §1, ground 3 — delete it.** It reads *"The tamper matrix is already
   committed to it … Changing it would be a row edit, and row expected
   outcomes are never edited"*. `anchor-forged-header` is a **`pending`
   marker, not a row**; contract §6 governs implemented rows, and Q76's own
   Accept says so (*"this task touches `pending` entries only"*). The ruling
   survives on grounds 1, 2 and 4; the third was never available.
4. **D56 §9 — the `nTime` row.** Promote A18's inline correction to a numbered
   amendment carrying §8 of this document, including that row 4 of the tamper
   matrix is now the reachable form of the claim.
5. **D53 §8 — the distinctness sentence.** Append: *"The dependency runs one
   way. `verdict:invalid` being claimed exactly once is a **consequence** of
   rows 2, 6 and 8 minting codes, not a premise of it: the checker enforces
   distinctness, not coverage, so zero claimants would satisfy the same
   constraint (D93 §6)."*
6. **`tasks/A.md` A18 `Accept` row 2** — *"mismatch → `invalid`"* was
   discharged by the `!committed` corner only. Append: *"— and the fixture
   must be one whose ops **commit** the embedded header; the uncommitted
   shape is already `invalid` offline through O8, so it discharges this clause
   vacuously (D93 §3)."*
7. **`tasks/A.md` A21** — the amendment in §14.3 below.
8. **`tasks/Q.md` Q75** — the amendment in §14.4 below.
9. **`crates/antseal-core/src/test_util/tamper_coverage.rs`** — `ANCHOR_ONLINE`'s
   owner note for `anchor-ots-online-block-absent` says *"a named test drives
   it"*. After A80 that test is the committed twin; after A81/Q92 it is a row.
   A80 updates the string.
10. `docs/decisions/README.md` — this decision's index row. **Applied 2026-08-11**, executing [D119](D119-decision-index-identity-and-the-index-row-sections.md) §5 step 4; the former `## Index row` section is demoted to this line under D119 RULING 4, and RULING 6 puts the row in the act that commits the record.

---

## 14. Discovered work

Ids from this planner's allocated block only: **A80–A87**, **Q92–Q95**. Five
used.

### A80 — Lift the online refutations above O4 in `evaluate_ots_artifact`
- Milestone: M2 — **blocks A21**
- Size: S
- Deps: A18 (the machine); D93
- Discovered by: **D93 §3** (2026-08-06)
- Problem: `verdicts.rs:680-692` returns `Attested` on `upgrade.is_some() && committed` without consulting `agreed`, so rules O6 and O7 can only ever produce a verdict when the artifact is *already* refutable offline through O8. A forged header the ops commit is unrefutable by the online gate, and an `.ots` claiming a height beyond the chain tip renders `attested` for ever — the defect D56 §3 states in those words as the reason O7 exists. A18's Accept row 2 (*"mismatch → `invalid`"*) and MVP-SPEC.md lines 108/168 are discharged vacuously.
- Do: Give O4 the guard in D93 §5 (`committed && !refuted_online`, where `refuted_online` covers O6 and O7 and **not** O8). Leave O0–O3, O5, O8, O9 and every offline path untouched. Invert and rename `a_self_consistent_forgery_refuted_online_is_attested_with_the_refutation_recorded`, and give `agreed_absence_of_the_block_is_invalid` a **committed** twin, keeping the existing `!committed` case as the O7-over-O8 ordering assertion. Update `ANCHOR_ONLINE`'s owner note in `test_util/tamper_coverage.rs`.
- Accept:
  - A single-branch committed `.ots` whose embedded header the agreed pair refutes renders `Invalid`/`anchor-ots-online-header-mismatch`; the **same artifact with the evidence removed** renders `Attested` — both directions, or the rule is untested.
  - A committed `.ots` at a height the agreed pair says does not exist renders `Invalid`/`anchor-ots-online-block-absent`.
  - A committed, online-refuted `.ots` **with** a pending branch renders `Pending` and carries the refutation as an A39 suppressed entry (D56 §4 preserved).
  - The eight tests D93 §5 lists as "must stay green" are green, unchanged.
  - `O4`'s `suppressed` list is asserted empty by construction.
  - Native and wasm32.

### A81 — Build the O7 tamper row (`anchor-ots-online-block-absent`)
- Milestone: M2
- Size: S
- Deps: A80, A21, A82, Q92
- Discovered by: **D93 §12** (2026-08-06)
- Problem: O7 is the one online refutation the spec never named, so D56 §8 gave it no row and its only instrument is a unit test — and D93 §3 measured that this test exercised the one corner where its own stated defect is invisible. A rule whose sole instrument was blind for a whole wave is the shape this project puts in the matrix.
- Do: Add the row as a `project_added[]` entry (the mechanism D56 §8 names) with `outcome_kind: "error"`, `expected: "anchor-ots-online-block-absent"` — distinct from every other claimed key. Fixture: A21's row-4 base with `OnlineBlockResult::NoSuchBlock` at the recorded height instead of a refuting header.
- Accept: the row is red when O7 is folded into "no evidence", and red when O4's D93 guard is reverted; native and wasm32.

### A82 — Promote the synthetic `.ots` writer into `anchor::testing`
- Milestone: M2 — **blocks A21**
- Size: S
- Deps: A11 (the container format), A24/A59 (`anchor::testing`)
- Discovered by: **D93 §9** (2026-08-06)
- Problem: `container`, `fork`, `bitcoin`, `pending`, `unknown`, `varuint`, `header_with` and `derived_root` live in `crates/antseal-core/src/anchor/verdicts/tests.rs` behind `#[cfg(test)]`. A21's rows cannot reach them from either home the matrix uses — `test_util` is not `cfg(test)`, and `crates/antseal-core/tests/` is a separate crate. The shapes no capture contains (a single-branch committed upgrade, an unknown attestation, a Bitcoin branch with no upgrade group) are exactly the ones A21 needs.
- Do: Move them to `anchor::testing` beside `MockTsa`, keeping every format constant imported by name from the parser so a format change breaks the build rather than silently minting bytes the parser rejects for the wrong reason. Re-point `verdicts/tests.rs` and `anchor::ots::tests`' private twin at the one copy.
- Accept: an integration target under `crates/antseal-core/tests/` mints a single-branch committed upgraded `.ots` and evaluates it; the builder is not reachable from non-test builds (feature- or `cfg`-gated as `MockTsa` is); no duplicate writer remains.

### A83 — Audit the A18 suite for rules asserted in the wrong corner
- Milestone: M2
- Size: M
- Deps: A80
- Discovered by: **D93 §3** (2026-08-06)
- Problem: `agreed_absence_of_the_block_is_invalid` names its defect in prose and cannot see it, because its fixture reaches the asserted state through O8 rather than through O7. It is the same defect class as the root-store lane's 25/25-green suite and the seven blind instruments of wave 4, and D56 §9 specifies ~22 such tests — two of which have now been found wrong by hand.
- Do: For every D56 §9 and D53 §9 test now committed, check that the fixture reaches the asserted outcome **through the rule the test names** and not through an earlier one. Where it does not, add the shape that does. Where a rule genuinely cannot be isolated, record why in the test's doc comment instead of implying it is.
- Accept: every such test either exercises its named rule in isolation or states why it cannot; at least one further planted fault per corrected test; no test's assertion is weakened to make it pass.

### Q92 — Register the O7 row in `MATRIX.json`'s `project_added[]`
- Milestone: M2
- Size: XS
- Deps: D93; **before A81**
- Do: Add the `project_added[]` entry for `anchor-ots-online-block-absent` with the D93 §12 justification (line 168 names it nowhere; its only instrument was measured blind). Re-run the combined distinctness sweep.
- Accept: the sweep is green with the new key; a planted duplicate of an existing key goes red naming both rows.
- Notes: registry-side only — A81 builds the fixture. Ordered before A81 for the same reason Q76 was ordered before A21.
