# The positioning-copy style guide (Q20)

**Status: NORMATIVE for product copy.** Every rule below cites the
`MVP-SPEC.md` line it comes from. The machine-checkable subset is enforced by
`scripts/check-copy-style.py`, whose rule ids (`P0`…`P9`) are the section
numbers of this document; U31 shares that one lint rather than growing a
second one.

This product is **proof of existence, integrity and possession-by-time**. It
is not a legal instrument and it never says it is. The rules exist because
the temptation runs one way: every sentence that overclaims here is a
sentence a counterparty may rely on.

---

## 1. The source text

`MVP-SPEC.md` **line 28**, in full, is the constraint the whole guide serves:

> **Positioning constraints**: never call it a "notary" in legal copy — and
> never claim "priority" unqualified. A seal proves **the holder of key X
> possessed this content by time T** — not authorship, not exclusive
> possession; an earlier seal by someone who received your work outranks
> yours ("**seal before you share**"). Docs must state both limits, plus a
> compelled-disclosure note: the vault holder can always be forced to reveal;
> vault destruction is the only, irreversible, opt-out. All verdict copy uses
> possession language.

Four more lines are cited by name below: **line 110** and **line 137** (the
receipt's class and the claimed-time label), **line 127** (one authoritative
verdict-wording set), **line 139** (one canonical verifier URL) and **line
143** (the vault's two loud failure modes).

---

## 2. Three surface classes, because one rule set does not fit them

A rule that is right for a verdict line is wrong for a documentation page,
and pretending otherwise produces either a lint nobody can satisfy or an
exemption list that swallows the corpus.

| Class | What it is | Where it lives | Enforced by |
| --- | --- | --- | --- |
| **V — verdict copy** | The sentences the verifier prints about a bundle | `crates/antseal-core/src/verify/wording.rs`, snapshotted to `crates/antseal-core/tests/snapshots/verdict-wording.txt` | `crates/antseal-core/tests/verdict_wording.rs` (R18), plus §3–§6 here |
| **P — product copy** | What a user or counterparty reads: the README, the verifier page, the CLI's rendered output, the M4 product docs | `README.md`, `verifier-web/`, `crates/antseal-cli/tests/snapshots/`, this guide | `scripts/check-copy-style.py` |
| **E — engineering copy** | Contributor-facing text: decision records, runbooks, test contracts, this repository's own registers | most of `docs/`, `tasks/`, `TODO.md`, Rust sources | review; **not** scanned |

**Class V is the strictest and it is already enforced.** R18's sweep bans its
vocabulary outright, on the stated ground that a verdict line has no room for
the qualifying paragraph a lawful use would need. Nothing in this guide
loosens that; §3–§6 are the Class P rules, which are looser *because
documentation is required to state the limits, and a limit cannot be stated
without naming the thing it limits*.

**The partition is checked, not assumed.** Rule **P8** requires every
`docs/*.md` page and every `docs/*/` subtree to carry a class and a reason in
the lint's `DOCS_CLASSIFICATION` register. A page classified by nothing is a
failure. This is D123's lesson applied forward: that decision found a scan
that was blind to the very file its own row authored, and the guard against
repeating it is a register that reddens on an unclassified page rather than a
scan root list nobody re-derives. For the same reason this document is a
**literal** entry in the lint's `COPY_SCAN` — the guide is inside its own
scan, and §13 records the run that proves it.

---

## 3. Banned — the "notary" family (rule **P1**, spec line 28)

**The word and its family are banned from product copy except to deny it** —
`notary`, `notaries`, `notarial`, `notarise`/`notarize` and their
inflections, every one of them, never as a claim.

- **Lawful**: *"antseal is not a legal notary."* — the disclaimer line 28
  requires; `README.md` and `docs/threat-model.md` both carry it today.
- **Rejected**: any sentence naming the word without a disclaimer in it.

The lint's test is mechanical: the **sentence** containing the word must also
contain a negation (`not`, `never`, `no`, `nothing`, `cannot`, `without`) or
a rejection marker (`rejected`, `banned`, `forbidden`, `refused`). That is
the smallest test that lets the required disclaimer through and stops the
claim.

**The pattern is a word family, never the substring `notar`.** Measured
2026-08-15: `ReceiptSinkFault::NotArmed` in
`crates/antseal-cli/src/pipeline/receipt_sink.rs` lowercases to `notarmed`,
so a substring ban fires on an identifier that has nothing to do with
positioning. A green self-test arm pins that behaviour.

---

## 4. Banned — "priority" in a block that never says an earlier seal outranks yours (rule **P2**, spec line 28)

Line 28 bans the **unqualified** claim, not the noun, and it supplies its own
qualification in the same breath: an earlier seal by someone who received
your work outranks yours — **seal before you share**. So the rule is:

> Wherever product copy uses the word, the same block must carry the
> qualification: the phrase *seal before you share*, or an explicit statement
> that an earlier seal outranks a later one.

- **Lawful** (this is `README.md`'s shipped positioning block, and it passes):
  *"a seal proves possession by time T — NOT authorship. "Seal before you
  share." antseal is proof of existence, integrity and priority; it is not a
  legal notary."*
- **Rejected**: the word standing alone in a block that never says an earlier
  seal outranks a later one.

**Scope is the block, not the sentence, and that is a deliberate loosening.**
Measured on the tree today: at sentence scope the README's own reviewed
paragraph goes red, because the qualification sits one sentence away from the
claim — which is how a person actually writes it, and how a reader actually
meets it. Sentence scope buys nothing a reader would notice and costs the
one shipped example of the copy the spec's own words produce. What it costs:
a block long enough to hold an unrelated *seal before you share* would let a
second, unqualified use through. §10 records that as a known limit rather
than pretending it away.

`prioritise`/`prioritize` are **not** covered. They order work; they never
claim anything about a seal.

---

## 5. Banned — authorship and exclusive possession (rule **P3**, spec line 28)

A seal proves possession by a time. It does not prove who wrote the bytes,
and it does not prove that nobody else holds them. So `authorship`,
`exclusive possession`, `exclusively possessed` and `sole possession` are
banned in product copy unless disclaimed in their own sentence — the same
test as §3.

R18's frozen row is the model, and it passes this rule as written:

> a seal proves the holder of the sealing key possessed this content by the
> proven time — not authorship, and not exclusive possession

---

## 6. Required — possession language, and both limits (rule **P7**, spec line 28)

Line 28 does not only forbid; it **requires**. Every positioning surface —
today `README.md`; at M4 the product-limits and disclosure pages Q22–Q25
write — must state, in its own words:

| Clause | What it must say | Spec |
| --- | --- | --- |
| `possession-language` | what a seal proves, in possession terms — *the holder of key X possessed this content by time T* | line 28 |
| `limit-authorship` | that it is **not** authorship | line 28 |
| `limit-exclusive-possession` | that it is **not** exclusive possession | line 28 |
| `seal-before-you-share` | that an earlier seal by a recipient outranks yours — *seal before you share* | line 28 |
| `compelled-disclosure` | that the vault holder can always be forced to reveal, and that vault destruction is the only, irreversible opt-out | line 28 |

A clause the tree does not yet carry is registered in the lint's
`OWED_PRESENCE` with the **task that owes it**, and each entry is asserted
*still owed*: satisfy the clause without deleting its entry and the lint goes
red demanding the deletion. A debt that cannot go stale is an exemption, and
exemptions rot — the discipline `check-ci-shell.py` applies to
`ALLOWED_INLINE` and `verdict_wording.rs` applies to `RESIDUE`.

Two debts are registered today; both are **genuine gaps in the tree, not
exemptions written to make a lint green**, and both are owed by Q22, whose
own `Accept` already reads *"Q20 lint green"*. See §11.

---

## 7. Required — the spec's own spellings (rules **P4**, **P5**)

Two phrases are dictated by the spec outright and are R18 rows. Wherever
copy spells the concept, it spells it **exactly** — em dash included:

| Concept | The one spelling | Spec |
| --- | --- | --- |
| the Arbitrum receipt's class | `supporting evidence — no independently proven time` | lines 110, 137 |
| the sealer's claimed time | `asserted by sealer — NOT verified` | line 137 |

The receipt is **not an anchor** and is never headline-eligible; the claimed
time is subordinate and never enters the headline (line 137). Copy that
paraphrases either has, in practice, softened it.

---

## 8. Required — one canonical verifier URL (rule **P6**, spec line 139)

Line 139 requires *"one canonical URL used in all docs and printed by the CLI
in `reveal` output"*. D62 §3 R8 fixes the value at `https://antseal.org/` —
apex, `https`, trailing slash, no `www`, no subdomain, no path — and puts the
single Rust definition in `crates/antseal-cli/src/brand.rs` as
`VERIFIER_URL`. Markdown cannot import a Rust `const`, so the rule is: **one
definition, and every other occurrence byte-equal to it.**

The lint enforces the negative half over its own scan roots: any
`https?://…antseal.<tld>…` spelling that is not byte-equal to the canonical
value fails. The **tree-wide** value-identity scan is explicitly R26/Q28's,
as `brand.rs`'s own module docs record; this guide does not duplicate it.

---

## 9. The Class V vocabulary, incorporated by reference (rule **P9**)

Verdict copy carries a wider ban, because a verdict line has no room to
qualify anything. R18's table is the single source of that vocabulary and it
is **read** by the lint out of `crates/antseal-core/tests/verdict_wording.rs`
rather than restated here — two lists held in step by a comment is the defect
D116 collapsed five constants to prevent. This section exists so the guide
cannot fall silently behind it: rule **P9** fails if any token below stops
being named here.

| Token banned from verdict copy | Why it is banned |
| --- | --- |
| `notary` | banned: spec line 28 |
| `notaris` | banned: the same, British spelling of the verb |
| `notariz` | banned: the same, American spelling of the verb |
| `notarial` | banned: the same, adjectival form |
| `priority` | banned unqualified (spec line 28); a verdict line has no room for the qualification, which is that an earlier seal outranks yours — seal before you share |
| `legally binding` | banned: a verdict is evidence, never an instrument |
| `copyright` | banned: a seal says nothing about rights |
| `patent` | banned: a seal says nothing about rights |
| `affidavit` | banned: legal-instrument vocabulary |
| `witness` | banned: legal-instrument vocabulary |
| `certify` | banned: the product certifies nothing about the work |
| `certified` | banned: the same verb form |

The noun **`certificate`** survives — it is the X.509 object in the
`valid-at-stamping-cert-since-expired` state. The ban is on the verb forms.
A green self-test arm pins that too.

These tokens are **not** Class P bans. Documentation must be able to say that
a seal is not legally binding and certifies nothing, and a threat model must
be able to use the word *witness* about a test.

---

## 10. What this lint does not do

Stated plainly, because a checker whose limits are unwritten gets trusted for
things it never did.

1. **It does not read intent.** *"antseal is not just a legal notary — it is
   better"* carries a negation and passes §3. A disclaimer that reads as a
   boast still needs a human.
2. **Sentence and block detection are approximations.** Sentences split on
   `.`/`!`/`?` and on markdown structure; blocks split on blank lines. A
   disclaimer one sentence too far away is not seen, and a block long enough
   to hold an unrelated qualification can shelter a second claim (§4).
3. **It scans rendered copy, not Rust sources.** CLI strings reach it through
   `crates/antseal-cli/tests/snapshots/`. A user-facing string that reaches no
   snapshot is invisible to it. U31's single catalog module of user-facing
   strings **does not exist yet** (measured 2026-08-15); when it lands it
   becomes a literal `COPY_SCAN` entry and this limit narrows.
4. **It does not check that a required clause is *well written*** — only that
   the surface states it.
5. **It does not do the tree-wide URL value-identity scan** (§8); that is
   R26/Q28's.
6. **It is not a substitute for review.** Every rule here is a floor.

---

## 11. Findings on the tree as it stands (measured 2026-08-15)

Recorded rather than exempted, with the task that owns each.

1. **`README.md` states one of line 28's two limits.** It says *NOT
   authorship*; it does not say *not exclusive possession*. Registered as an
   `OWED_PRESENCE` debt owed by **Q22**.
2. **`README.md` carries no compelled-disclosure note.** Line 28 requires it
   of docs; today it exists only in `docs/threat-model.md` §2.5, which is
   Class E. Registered as an `OWED_PRESENCE` debt owed by **Q22**.
3. **`docs/threat-model.md`'s Positioning section claims priority
   unqualified.** Line 14 reads *"antseal proves **existence, integrity and
   priority** of data you possessed"*, and its block never says an earlier
   seal outranks a later one — no *seal before you share*. The file is Class
   E today for two reasons recorded in `DOCS_CLASSIFICATION`: it is an M0
   skeleton whose product-copy sections are **Q21**'s at M4 (and Q21's
   `Accept` already reads *"Q20 lint passes"*), and roughly 370 of its lines
   are a verbatim frozen copy of `docs/security-assumptions.md` asserted
   byte-identical by `crates/antseal-core/tests/security_assumptions_drift.rs`
   — a finding inside that block cannot be fixed in this file at all. **This
   is a real defect in shipped text, not a rule that is wrong.** Q21 owns it.
4. **`docs/anchors/root-store-update.md` line 9 claims priority unqualified**
   in the same shape (*"antseal's whole claim is priority"*). Class E,
   operator runbook, no product surface — recorded so the Q28 widening does
   not meet it as a surprise.

Nothing else in the scanned corpus violates any rule: the CLI's ten golden
snapshots, R18's verdict document and the verifier page template are clean on
every rule, measured, not assumed.

---

## 12. What Q20 enforces, and what Q28 inherits

Q20's own `Notes` say full-corpus enforcement completes in **Q28**. The
boundary, so that neither row silently enforces everything nor nothing:

**Enforced now (Q20).** Rules P0–P9 over the product-copy roots that exist
today: `README.md`, this guide, `verifier-web/`, the CLI's rendered golden
snapshots and R18's verdict document. The `docs/` partition (P8) over every
page and subtree. The two dictated spellings and the canonical-URL negative
half over those roots. Two registered presence debts with named owners.

**Q28 inherits.**

1. **Widening `COPY_SCAN` to the M4 product docs** — Q22's README rewrite,
   install guide and product-limits pages, Q23's funding doc, Q24's
   vault-loss/theft pages, Q25's wallet-hygiene page. None exists today, and
   a scan root that names a missing file fails by design (P0), so they join
   as they land. P8 makes that unmissable: each lands unclassified and red.
2. **The tree-wide canonical-URL value-identity scan** (§8), which
   `brand.rs` already assigns to R26/Q28.
3. **`docs/threat-model.md`'s promotion to Class P** once Q21 has written it
   (finding 3 above).
4. **U31's catalog module**, when it exists, as a literal `COPY_SCAN` entry —
   at which point "CLI strings" stops meaning "the strings that reached a
   snapshot".
5. **Cross-surface identity**: that the CLI, the page and the docs spell one
   concept one way. R18 and D64 own that inside the verdict set; nothing
   checks it across docs today.

---

## 13. Running it

```
scripts/check-copy-style.py              # the check; exit 0 pass, 1 fail
scripts/check-copy-style.py --self-test  # plant every violation, require red
scripts/check-copy-style.py --inventory  # print every file the scan reads
```

`--self-test` stages a copy of the scan roots in a temp directory and runs
three families of arm, judging on the findings list the check returns — in
process, so a crash fails the harness instead of satisfying an arm:

1. **Fourteen red arms**, at least one per rule, each asserting **which** rule
   fired rather than merely that something did. The first is Q20's own
   `Accept` case: a *legal notary* claim with no disclaimer, planted in a
   docs file.
2. **Four green arms** over lawful copy — `ReceiptSinkFault::NotArmed`, the
   X.509 noun `certificate`, a sentence saying antseal is not a legal notary,
   and a priority block that says an earlier seal outranks yours. A rule that
   reddens on legitimate text is worse than no rule, so silence is asserted
   too.
3. **One arm per scanned file**: a violation is planted in every file the
   inventory names and each must be reported *against that path*. This is
   D123 R6's discipline generalised — a scan root is proven read only by a
   fault inside it going red, and a scan that misses its own target is this
   repository's dominant defect class.

The harness is itself fallible, and that was measured rather than assumed:
breaking §3's pattern to `notarZZZ` makes `--self-test` exit 1 with
`::error:: planted P1 violation did not fire P1; rules that fired: none`.

A green run of the check without a green self-test proves nothing; CI runs
the self-test first, as two steps of the `traceability` job.
