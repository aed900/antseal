# Q28 — full-corpus copy audit: positioning and the single canonical URL

- **Date: 2026-08-22** (wave 29)
- Owner row: **Q28** (`Accept` row 3 — *"signed-off audit checklist committed;
  violations fixed before Q34 release"*)
- Subject: `MVP-SPEC.md` line 28's positioning rules, lines 110/137's dictated
  spellings, and line 139's single canonical URL, over the **whole** corpus —
  not only the partition a lint reaches.

**What this document is.** The sign-off for one pass, with its measurements
attached and its blind spots named. It is a **dated record**, not a live guard:
the live guard is `scripts/check-copy-style.py`, and where this audit reaches
further than that script, it reaches by hand and will go stale. Every figure
below was measured on 2026-08-22 at the wave-29 registration.

---

## 1. The mechanical half — what the lint already proves

```bash
{ python3 scripts/check-copy-style.py > cs.out 2>&1; echo "REAL_EXIT=$?" > cs.exit; }
```

**[OBSERVED 2026-08-22]** — `REAL_EXIT=0`, read back from a file and not from a
harness's exit report:

> `check-copy-style: ok — 29 product-copy file(s) across 8 scan root(s) satisfy
> MVP-SPEC.md line 28's positioning rules (P1-P3), the spec's dictated spellings
> (P4/P5), the one canonical verifier URL (P6), the required positioning clauses
> (P7, 0 registered debt(s) above), the docs partition (P8, 23 entries) and R18's
> Class V vocabulary (P9).`

**Read the numbers, not the word `ok`.** 29 files over 8 roots; a root that
silently stopped matching would still print `ok`, which is why P0 fails loudly
on a `COPY_SCAN` entry that is not a file or reads nothing.

D150 §2 R6's anchored predicate, the one that gates the flip:

```bash
python3 scripts/check-copy-style.py | grep -c '^check-copy-style: registered debt'
```

**[OBSERVED 2026-08-22]** — **`0`**. `0` is the value that permits the flip. The
register being empty is the healthy state and it **strengthens** the check: with
no entry available to excuse it, an unstated required clause is now a finding
rather than a notice.

---

## 2. `Accept` row 2 — exactly one canonical URL value, measured tree-wide

`Accept` row 2 is the **ruled** predicate (D62 adopts it verbatim over R26's
looser phrasing). The value is `https://antseal.org/`. `check_url` enforces it
mechanically over the 29-file Class P partition; this audit ran the same
D62 §3 R8 pattern over the **whole tree** — every `.md`, `.rs`, `.html`, `.js`,
`.mjs`, `.py`, `.sh`, `.txt` and `.yml` — to see what the lint's partition
leaves out.

| spelling | occurrences | where |
| --- | ---: | --- |
| `https://antseal.org/` | **99** | the canonical value |
| `https://antseal.org` *(no trailing slash)* | 8 | ENG records |
| `http://antseal.org/` | 5 | D62, D139, `docs/naming/P3-domain-registration.md` |
| `https://www.antseal.org/` | 3 | D139; `scripts/check-copy-style.py`'s own fixtures |
| `https://antseal.org/docs/` | 2 | D139 |
| `https://antseal.org/.` `https://antseal.org/…` `http://antseal.org/…` `https://antseal.org/#verify` | 1 each | D139; sentence-final punctuation and ellipsis captured by the pattern |
| `https://antseal.io/help` | 1 | D155 |
| `https://antseal.example` | 1 | D55 |

**Verdict: row 2 HOLDS.** Every non-canonical spelling resolves to an
**ENG-class record that legitimately discusses other names** — the decision
that chose the host (D62), the venue ruling that enumerated rejected forms
(D139), the domain-registration runbook (P3), a refusal record quoting a
specimen (D155/D55), and the checker's own planted fixtures. **Zero
non-canonical spellings appear on any Class P product surface.** This is
D62 §3 R8's named-allow-list working as designed, and the measurement is what
distinguishes it from the same table produced by a lint that simply never
looked.

---

## 3. The manual half — three live paraphrases of the dictated receipt class, FIXED

This is `Q28`'s **handed finding** (2026-08-17, wave 23), and it was still live
five waves later. The dictated spelling is
**`supporting evidence — no independently proven time`** — em dash, no comma
(`scripts/check-copy-style.py`'s `RECEIPT_CLASS`, from MVP-SPEC.md line 110).

**The load-bearing part is that the scan is whitespace-normalised.** Two of the
three occurrences **wrap across source lines**, so a line-oriented `grep` for
the dictated string finds neither — which is exactly why three paraphrases
survived every audit to date.

| site | shape | fixed |
| --- | --- | --- |
| `crates/antseal-core/src/bundle/schema.rs` | wrapped between *supporting* and *evidence* | ✅ |
| `crates/antseal-core/src/verify/orchestration.rs` | single line | ✅ |
| `crates/antseal-core/src/verify/report.rs` | wrapped after *no* | ✅ |

`report.rs` carried **both** spellings twelve lines apart — the correct em-dash
form in the type's own doc header, the comma paraphrase below it — which is the
sharpest form of the defect: the file that states the rule correctly restates it
wrongly a dozen lines later.

**Why it mattered where it was.** Two of the three files are precisely the ones
`docs/threat-model.md` §2.3 cites as its authority for the receipt's class, so a
maintainer following either citation landed on the softened wording. All three
are **rustdoc prose**, not string literals and not test assertions — no rendered
output moved, and `cargo check -p antseal-core --lib` is **`REAL_EXIT=0`** after
the change.

**Post-fix measurement**, same whitespace-normalised scan over `crates/**`, all
root and `docs/` Markdown, and `verifier-web/`:

- comma paraphrases: **0** on every product and source surface.
- **One occurrence deliberately left standing**: `docs/instrument-ledger.md:168`,
  the dated ledger entry that *records* this finding. A record of a defect must
  quote the defect; editing it would destroy the record (D117).
- dictated em-dash occurrences: **25**.

---

## 4. Running the copy rules where the lint does not go — and what that measures

`docs/threat-model.md` is deliberately **not** in `COPY_SCAN` (D139 §2 R3), and
Rust sources are recorded as unscanned (guide §10.3). This audit ran the lint's
own `check_banned`, `check_spellings` and `check_url` over those surfaces anyway,
to find out what the exclusions cost. **13 raw hits. All 13 are false positives,
and each has a distinct cause** — which is the measurement that justifies the
exclusions rather than merely asserting them:

1. **`docs/threat-model.md:405` and `docs/security-assumptions.md:387` — P3
   `Authorship`.** The text is *"**What breaks if it is false.** Authorship
   binding."* — a two-word sentence naming what the hybrid signature scheme
   **cryptographically binds**, a term of art. P3's target is the marketing
   claim *"a seal proves authorship"*; the rule fires only because its
   disclaimer must sit in the same **sentence**, and this sentence is two words
   long. Not a violation. (The two files carry identical text by design — they
   are byte-identity drift-tested against each other.)
2. **`crates/antseal-core/src/verify/wording.rs:20` — P5 `asserted by sealer`.**
   A **false positive caused by a line wrap**: the dictated
   `asserted by sealer — NOT verified` is split across `//!` lines 20–21.
   Normalised, the file carries the dictated spelling exactly, and the constant
   itself is correct on one line. This is §3's wrap-blindness **in the opposite
   direction** — there it hid three real defects, here it would manufacture one.
3. **`crates/antseal-core/tests/verdict_wording.rs` — 10 hits (P1×2, P2×6,
   P3×2).** The test file for the wording rules, whose fixtures are
   **deliberately rejected specimens**. A corpus of banned strings is what this
   file is for.

**Conclusion, and it is a finding about the instrument rather than the copy:**
the Class P rules do **not** transfer to Class E documents or to Rust sources
without producing false positives at a rate of 13-for-0. That is the reason
D139 §2 R3 excluded the threat model, now **measured** instead of assumed, and
it is the argument against widening `COPY_SCAN` to `crates/**` on the strength
of §3's three real defects. The right instrument for §3's class is a
**whitespace-normalised scan for the dictated spellings specifically**, not the
whole P1–P9 battery.

---

## 5. What this audit does NOT cover

- **It is not a guard.** It is one dated pass. The live guard is
  `check-copy-style.py` over 29 files; everything in §3 and §4 was reached by
  hand and **nothing prevents §3's class from recurring in Rust sources**. No
  checker is minted here: §4 measures that the obvious one (widen `COPY_SCAN`)
  would cost 13 false positives, and a narrower one is a decision this row was
  not given.
- **Release-note templates**, named in `Q28`'s `Do`, do not exist yet — there is
  no release. They are `Q31`'s, and they inherit this audit rather than being
  covered by it.
- **`Accept` row 3's second clause** — *"violations fixed **before** Q34
  release"* — is a deadline this lane cannot close. §3's violations are fixed
  **now**; the clause stays live for anything found between here and `Q34`.
- **The CLI's runtime output** is covered only through the committed golden
  snapshots (13 files, all inside `COPY_SCAN`). Output paths with no snapshot
  are not audited by this pass and are not enumerated.
- It says nothing about the page's **rendered** copy, only about
  `verifier-web/index.template.html` as a file.
